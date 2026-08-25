/**
 * Serial operation queue for the management RPC.
 *
 * Operations run one at a time. Cancellation only removes queued work; a
 * running pnpm/child process is intentionally never killed by cancel.
 */

import type { OperationKind, OperationRecord, OperationState } from './types.ts'

export type OperationUpdate = Partial<Pick<OperationRecord, 'percent' | 'detail' | 'state' | 'error'>>
export type OperationRunner = (update: (patch: OperationUpdate) => void) => Promise<string>

export class OperationQueue {
  private readonly records: OperationRecord[] = []
  private readonly maxRecords = 50
  private nextId = 1
  private tail: Promise<void> = Promise.resolve()
  private closed = false

  enqueue(kind: OperationKind, target: string, runner: OperationRunner): string {
    if (this.closed) throw new Error('operation queue is closed')
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
    this.trim()
    this.tail = this.tail.then(() => this.run(record, runner)).catch(() => {})
    return id
  }

  cancel(id: string): boolean {
    const record = this.records.find(candidate => candidate.id === id && candidate.state === 'queued')
    if (record === undefined) return false
    this.update(record, { state: 'cancelled', percent: 100, detail: 'cancelled' })
    return true
  }

  clearSettled(): void {
    for (let index = this.records.length - 1; index >= 0; index -= 1) {
      const state = this.records[index]?.state
      if (state === 'done' || state === 'warned' || state === 'failed' || state === 'cancelled') {
        this.records.splice(index, 1)
      }
    }
  }

  list(): readonly OperationRecord[] {
    return this.records.slice()
  }

  /** Host lifecycle cleanup: cancel queued work; running work is left to settle. */
  dispose(): void {
    this.closed = true
    for (const record of this.records) {
      if (record.state === 'queued') {
        this.update(record, { state: 'cancelled', percent: 100, detail: 'cancelled on shutdown' })
      }
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
    try {
      const detail = await runner(patch => this.update(record, patch))
      this.update(record, { state: 'done', percent: 100, detail })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.update(record, {
        state: 'failed',
        percent: 100,
        detail: message,
        error: message,
      })
    }
  }

  private trim(): void {
    if (this.records.length <= this.maxRecords) return
    let remove = this.records.length - this.maxRecords
    // Never evict queued/running records: they are still live work and the
    // UI relies on them for the busy state. Only settled history is trimmed.
    for (let index = 0; index < this.records.length && remove > 0;) {
      const state = this.records[index]?.state
      if (state === 'done' || state === 'warned' || state === 'failed' || state === 'cancelled') {
        this.records.splice(index, 1)
        remove -= 1
      } else {
        index += 1
      }
    }
  }
}
