/**
 * Loopback RPC registration for the dsh-redteam-model management console.
 *
 * The channel is served with `authority: 'loopback'` only, and every mutating
 * endpoint validates its payload against the known mode/plugin allowlists.
 */

import {
  deployModes,
  getStatus,
  installOne,
  repairMode,
  requireMode,
  requirePlugin,
  scanModes,
  scanPlugins,
  uninstallOne,
  updateOne,
} from './manager.ts'
import type { OperationOutcome, OperationQueue } from './operations.ts'
import {
  RPC_CHANNEL,
  type HostConnectionHandle,
  type OperationKind,
  type OperationStartPayload,
  type RpcResult,
} from './types.ts'

const ENDPOINTS = new Set(['status', 'operation/start', 'operation/cancel', 'operations/clear'])
const OPERATION_KINDS = new Set<OperationKind>(['deploy-modes', 'install', 'update', 'uninstall', 'repair'])
const MAX_TARGETS = 15
/** Sentinel `target` values used by the client for batch operations. */
const BATCH_TARGETS: Record<'install' | 'update' | 'uninstall', string> = {
  install: 'missing',
  update: 'updates',
  uninstall: 'installed',
}

function ok(value: unknown): RpcResult {
  return { ok: true, value }
}

function asObject(payload: unknown): Record<string, unknown> {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('payload must be an object')
  }
  return payload as Record<string, unknown>
}

function knownPluginNames(): string[] {
  return scanPlugins().map(plugin => plugin.name)
}

function knownModeNames(): string[] {
  return scanModes().map(mode => mode.id)
}

function validateTargets(kind: OperationKind, target: string, targets: readonly unknown[] | undefined): string[] {
  if (kind === 'deploy-modes') {
    const allowed = new Set([...knownModeNames(), 'modes'])
    if (!allowed.has(target)) throw new Error(`unknown deploy-modes target: ${target}`)
    if (targets !== undefined && targets.length > 0) throw new Error('deploy-modes does not accept targets')
    return [target]
  }
  if (kind === 'repair') {
    if (targets !== undefined && targets.length > 0) throw new Error('repair does not accept targets')
    const modes = new Set(knownModeNames())
    const plugins = new Set(knownPluginNames())
    if (modes.has(target) || plugins.has(target)) return [target]
    throw new Error(`unknown repair target: ${target}`)
  }

  // install / update / uninstall
  const plugins = new Set(knownPluginNames())
  const names: string[] = []
  if (targets !== undefined) {
    if (!Array.isArray(targets)) throw new Error('targets must be an array')
    if (targets.length === 0 || targets.length > MAX_TARGETS) {
      throw new Error(`targets must contain 1..${MAX_TARGETS} entries`)
    }
    if (target !== BATCH_TARGETS[kind] && !plugins.has(target)) {
      throw new Error(`unknown plugin: ${target}`)
    }
    for (const raw of targets) {
      if (typeof raw !== 'string' || raw === '') throw new Error('targets entries must be non-empty strings')
      if (!plugins.has(raw)) throw new Error(`unknown plugin in targets: ${raw}`)
      if (!names.includes(raw)) names.push(raw)
    }
  } else {
    if (!plugins.has(target)) throw new Error(`unknown plugin: ${target}`)
    names.push(target)
  }
  return names
}

function operationRunner(kind: OperationKind, target: string) {
  return async (update: (patch: { detail?: string; percent?: number }) => void): Promise<string | OperationOutcome> => {
    const onProgress = (phase: string, percent?: number): void => {
      update({ detail: phase, ...(percent === undefined ? {} : { percent }) })
    }
    const modeResult = (detail: string): string | OperationOutcome => {
      return detail.includes('skipped existing entries:')
        ? { state: 'warned', detail }
        : detail
    }
    if (kind === 'deploy-modes') {
      return modeResult(target === 'modes' ? deployModes(undefined, onProgress) : repairMode(target, undefined, onProgress))
    }
    if (kind === 'repair') {
      if (knownModeNames().includes(target)) return modeResult(repairMode(target, undefined, onProgress))
      // Plugin repair re-points the link and reinstalls the package.
      return installOne(target, { onProgress }, undefined)
    }
    if (kind === 'install') return installOne(target, { onProgress }, undefined)
    if (kind === 'update') return updateOne(target, { onProgress }, undefined)
    if (kind === 'uninstall') return uninstallOne(target, { onProgress }, undefined)
    throw new Error(`unsupported operation kind: ${kind}`)
  }
}

function handleStart(payload: Record<string, unknown>, queue: OperationQueue): RpcResult {
  const kind = payload.kind
  if (typeof kind !== 'string' || !OPERATION_KINDS.has(kind as OperationKind)) {
    throw new Error('kind must be one of deploy-modes|install|update|uninstall|repair')
  }
  const target = payload.target
  if (typeof target !== 'string' || target === '') throw new Error('target must be a non-empty string')

  const rawTargets = payload.targets
  if (rawTargets !== undefined && !Array.isArray(rawTargets)) throw new Error('targets must be an array')
  const names = validateTargets(kind as OperationKind, target, rawTargets)
  for (const name of names) {
    // validateTargets already checked allowlists; require* re-checks cheaply.
    if (kind === 'install' || kind === 'update' || kind === 'uninstall') requirePlugin(name)
    if (kind === 'repair') {
      if (knownModeNames().includes(name)) requireMode(name)
      else requirePlugin(name)
    }
  }

  // Reject an oversized batch before enqueueing any of it.
  queue.ensureCapacity(names.length)
  let firstId: string | undefined
  for (const name of names) {
    const id = queue.enqueue(kind as OperationKind, name, operationRunner(kind as OperationKind, name))
    if (firstId === undefined) firstId = id
  }
  return ok({ id: firstId })
}

function handleEndpoint(endpoint: string, rawPayload: unknown, queue: OperationQueue): RpcResult {
  if (!ENDPOINTS.has(endpoint)) throw new Error(`unknown endpoint: ${endpoint}`)

  if (endpoint === 'status') {
    return ok(getStatus(queue.list()))
  }

  if (endpoint === 'operations/clear') {
    queue.clearSettled()
    return ok({ cleared: true })
  }

  if (endpoint === 'operation/cancel') {
    const payload = asObject(rawPayload)
    const id = payload.id
    if (typeof id !== 'string' || id === '') throw new Error('id must be a non-empty string')
    return ok({ cancelled: queue.cancel(id) })
  }

  if (endpoint === 'operation/start') {
    return handleStart(asObject(rawPayload), queue)
  }

  throw new Error(`unknown endpoint: ${endpoint}`)
}

export function registerModelRpc(connection: HostConnectionHandle, queue: OperationQueue): void {
  connection.rpc.handle(RPC_CHANNEL, async (endpoint, rawPayload): Promise<RpcResult> => {
    try {
      return handleEndpoint(endpoint, rawPayload, queue)
    } catch (error) {
      return { ok: false, error: { message: error instanceof Error ? error.message : String(error) } }
    }
  }, { authority: 'loopback' })
}

export type { OperationStartPayload }
