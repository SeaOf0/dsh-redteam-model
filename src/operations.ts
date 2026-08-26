/**
 * Serial operation queue for the management RPC.
 *
 * Operations run one at a time. Cancellation only removes queued work; a
 * running pnpm/child process is intentionally never killed by cancel.
 */

import { randomUUID } from 'node:crypto'
import { lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import type { OperationKind, OperationRecord, OperationState } from './types.ts'

export type OperationUpdate = Partial<Pick<OperationRecord, 'percent' | 'detail' | 'state' | 'error'>>
export interface OperationOutcome {
  readonly state: 'done' | 'warned'
  readonly detail: string
}
export type OperationRunner = (update: (patch: OperationUpdate) => void) => Promise<string | OperationOutcome>

const OPERATION_KINDS = new Set<OperationKind>(['deploy-modes', 'install', 'update', 'uninstall', 'repair'])
const OPERATION_STATES = new Set<OperationState>(['queued', 'running', 'done', 'warned', 'failed', 'cancelled'])
const INTERRUPTED_DETAIL = 'interrupted by previous dsh web restart'

interface PersistedOperations {
  readonly schemaVersion: 1
  readonly writerId: string
  readonly nextId: number
  readonly records: readonly OperationRecord[]
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isSettled(state: OperationState): boolean {
  return state === 'done' || state === 'warned' || state === 'failed' || state === 'cancelled'
}

function parseOperationRecord(value: unknown): OperationRecord | undefined {
  if (!isRecord(value)) return undefined
  if (typeof value.id !== 'string' || !/^op-[0-9]+$/.test(value.id)) return undefined
  const numericId = Number.parseInt(value.id.slice(3), 10)
  if (!Number.isSafeInteger(numericId) || numericId < 1) return undefined
  if (typeof value.kind !== 'string' || !OPERATION_KINDS.has(value.kind as OperationKind)) return undefined
  if (typeof value.target !== 'string') return undefined
  if (typeof value.state !== 'string' || !OPERATION_STATES.has(value.state as OperationState)) return undefined
  if (value.percent !== undefined && value.percent !== null
    && (typeof value.percent !== 'number' || !Number.isFinite(value.percent))) return undefined
  if (value.detail !== undefined && typeof value.detail !== 'string') return undefined
  if (value.error !== undefined && typeof value.error !== 'string') return undefined

  return {
    id: value.id,
    kind: value.kind as OperationKind,
    target: value.target,
    state: value.state as OperationState,
    ...(value.percent === undefined ? {} : { percent: value.percent as number | null }),
    ...(value.detail === undefined ? {} : { detail: value.detail }),
    ...(value.error === undefined ? {} : { error: value.error }),
  }
}

export class OperationQueue {
  private readonly records: OperationRecord[] = []
  private readonly maxRecords = 50
  private nextId = 1
  private tail: Promise<void> = Promise.resolve()
  private closed = false
  private writeSequence = 0
  private readonly writerId = randomUUID()
  private persistenceOwnership: 'unclaimed' | 'owned' | 'lost' = 'unclaimed'

  constructor(private readonly persistenceFile?: string) {
    this.load()
    this.persist()
  }

  enqueue(kind: OperationKind, target: string, runner: OperationRunner): string {
    if (this.closed) throw new Error('operation queue is closed')
    this.ensureCapacity(1)
    if (!Number.isSafeInteger(this.nextId)) throw new Error('operation id space exhausted')
    const id = `op-${String(this.nextId).padStart(4, '0')}`
    this.nextId += 1
    const record: OperationRecord = {
      id,
      kind,
      target,
      state: 'queued',
      percent: 0,
      detail: 'queued',
    }
    this.records.push(record)
    this.persist()
    this.tail = this.tail.then(() => this.run(record, runner)).catch(() => {})
    return id
  }

  cancel(id: string): boolean {
    const record = this.records.find(candidate => candidate.id === id && candidate.state === 'queued')
    if (record === undefined) return false
    this.update(record, { state: 'cancelled', percent: 100, detail: 'cancelled' })
    this.persist()
    return true
  }

  clearSettled(): void {
    let changed = false
    for (let index = this.records.length - 1; index >= 0; index -= 1) {
      const state = this.records[index]?.state
      if (state !== undefined && isSettled(state)) {
        this.records.splice(index, 1)
        changed = true
      }
    }
    if (changed) this.persist()
  }

  list(): readonly OperationRecord[] {
    return this.records.slice()
  }

  whenIdle(): Promise<void> {
    return this.tail
  }

  /** Make a multi-record RPC enqueue atomic with respect to the bounded queue. */
  ensureCapacity(count: number): void {
    if (this.closed) throw new Error('operation queue is closed')
    if (!Number.isSafeInteger(count) || count < 0) throw new Error('operation count must be a non-negative integer')
    const active = this.records.filter(record => !isSettled(record.state)).length
    if (active + count > this.maxRecords) {
      throw new Error(`operation queue capacity exceeded (maximum ${String(this.maxRecords)} active operations)`)
    }

    const requiredRemoval = Math.max(0, this.records.length + count - this.maxRecords)
    let remove = requiredRemoval
    for (let index = 0; index < this.records.length && remove > 0;) {
      if (isSettled(this.records[index]!.state)) {
        this.records.splice(index, 1)
        remove -= 1
      } else {
        index += 1
      }
    }
    if (remove !== 0) throw new Error('operation queue capacity invariant violated')
    if (requiredRemoval > 0) this.persist()
  }

  /** Host lifecycle cleanup: cancel queued work; running work is left to settle. */
  dispose(): void {
    this.closed = true
    let changed = false
    for (const record of this.records) {
      if (record.state === 'queued') {
        this.update(record, { state: 'cancelled', percent: 100, detail: 'cancelled on shutdown' })
        changed = true
      }
    }
    if (changed) {
      this.persist()
    }
  }

  private update(record: OperationRecord, patch: OperationUpdate): void {
    const mutable = record as {
      state: OperationState
      percent?: number
      detail?: string
      error?: string
    }
    if (patch.percent !== undefined && patch.percent !== null) {
      mutable.percent = Math.min(100, Math.max(0, Math.round(patch.percent)))
    }
    if (patch.detail !== undefined) mutable.detail = patch.detail
    if (patch.state !== undefined) mutable.state = patch.state
    if (patch.error !== undefined) mutable.error = patch.error
  }

  private async run(record: OperationRecord, runner: OperationRunner): Promise<void> {
    if (this.closed || record.state !== 'queued') return
    this.update(record, { state: 'running', percent: 1, detail: 'started' })
    this.persist()
    try {
      const outcome = await runner(patch => this.update(record, patch))
      if (typeof outcome === 'string') {
        this.update(record, { state: 'done', percent: 100, detail: outcome })
      } else {
        this.update(record, { state: outcome.state, percent: 100, detail: outcome.detail })
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.update(record, {
        state: 'failed',
        percent: 100,
        detail: message,
        error: message,
      })
    } finally {
      this.persist()
    }
  }

  private load(): void {
    if (this.persistenceFile === undefined) return
    try {
      if (!lstatSync(this.persistenceFile).isFile()) return
      const parsed: unknown = JSON.parse(readFileSync(this.persistenceFile, 'utf8'))
      if (!isRecord(parsed) || parsed.schemaVersion !== 1 || !Array.isArray(parsed.records)) return

      const seen = new Set<string>()
      const loaded: OperationRecord[] = []
      let maxId = 0
      for (const candidate of parsed.records) {
        const record = parseOperationRecord(candidate)
        if (record === undefined || seen.has(record.id)) return
        seen.add(record.id)
        maxId = Math.max(maxId, Number.parseInt(record.id.slice(3), 10))
        if (record.state === 'queued' || record.state === 'running') {
          loaded.push({
            ...record,
            state: 'failed',
            percent: 100,
            detail: INTERRUPTED_DETAIL,
            error: INTERRUPTED_DETAIL,
          })
        } else {
          loaded.push(record)
        }
      }

      const persistedNextId = parsed.nextId
      if (persistedNextId !== undefined
        && (!Number.isSafeInteger(persistedNextId) || (persistedNextId as number) < 1)) return
      this.records.push(...loaded.slice(-this.maxRecords))
      this.nextId = Math.max(maxId + 1, persistedNextId as number | undefined ?? 1)
    } catch {
      // Missing or malformed history must never block management operations.
    }
  }

  private persist(): void {
    if (this.persistenceFile === undefined || this.persistenceOwnership === 'lost') return
    let temporaryFile: string | undefined
    try {
      try {
        if (!lstatSync(this.persistenceFile).isFile()) return
        if (this.persistenceOwnership === 'owned') {
          const current: unknown = JSON.parse(readFileSync(this.persistenceFile, 'utf8'))
          if (!isRecord(current) || current.writerId !== this.writerId) {
            this.persistenceOwnership = 'lost'
            return
          }
        }
      } catch (error) {
        if (!isRecord(error) || error.code !== 'ENOENT') return
      }

      const directory = path.dirname(this.persistenceFile)
      mkdirSync(directory, { recursive: true })
      this.writeSequence += 1
      temporaryFile = path.join(
        directory,
        `.${path.basename(this.persistenceFile)}.${process.pid}.${this.writeSequence}.tmp`,
      )
      const payload: PersistedOperations = {
        schemaVersion: 1,
        writerId: this.writerId,
        nextId: this.nextId,
        records: this.records,
      }
      writeFileSync(temporaryFile, `${JSON.stringify(payload, null, 2)}\n`, { flag: 'wx', mode: 0o600 })
      renameSync(temporaryFile, this.persistenceFile)
      temporaryFile = undefined
      this.persistenceOwnership = 'owned'
    } catch {
      // History persistence is best effort and cannot change operation results.
    } finally {
      if (temporaryFile !== undefined) {
        try { rmSync(temporaryFile, { force: true }) } catch { /* Ignore cleanup errors. */ }
      }
    }
  }

}
