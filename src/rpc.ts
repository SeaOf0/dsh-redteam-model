/**
 * Loopback RPC registration for the dsh-redteam-model management console.
 *
 * The channel is served with `authority: 'loopback'` only, and every mutating
 * endpoint validates its payload against the known mode/plugin allowlists.
 */

import {
  deployGlobalAgents,
  deployModes,
  getStatus,
  installOne,
  repairMode,
  requireMode,
  requirePlugin,
  scanModes,
  scanPlugins,
  uninstallModes,
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
const OPERATION_KINDS = new Set<OperationKind>(['deploy-modes', 'remove-modes', 'install', 'update', 'uninstall', 'repair'])
/** Upper bound for one batch; must cover a full first-run install of every delivered plugin. */
const MAX_TARGETS = 32
/**
 * Channel spellings: modern Hosts (0.1.2+) serve plugin RPC over exact Fetch
 * routes under /api (`connection.fetch.register`), because the legacy
 * `rpc.handle` channel registration silently stops working there. Legacy
 * Hosts (0.1.1 and older) only know the bare channel, so both are registered.
 */
const API_CHANNEL = '/api/dsh-redteam-model'
/** Sentinel `target` values used by the client for batch operations. */
const BATCH_TARGETS: Record<'install' | 'update' | 'uninstall', string> = {
  install: 'missing',
  update: 'updates',
  uninstall: 'installed',
}
/** Sentinel `target` naming the whole mode plane for deploy and removal. */
const MODES_BATCH_TARGET = 'modes'

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
  if (kind === 'deploy-modes' || kind === 'remove-modes') {
    const allowed = new Set([...knownModeNames(), MODES_BATCH_TARGET])
    if (!allowed.has(target)) throw new Error(`unknown ${kind} target: ${target}`)
    if (targets !== undefined && targets.length > 0) throw new Error(`${kind} does not accept targets`)
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
      return detail.includes('skipped existing entries:') || detail.includes('skipped foreign entries:')
        ? { state: 'warned', detail }
        : detail
    }
    if (kind === 'deploy-modes') {
      // The batch deploy also seeds the security-preset instruction file
      // ($DSH_HOME/AGENTS.security.md, package-owned namespace refreshed on
      // change) and retires the legacy user-global AGENTS.md this package
      // used to install, so security context reaches the ten presets only.
      if (target === MODES_BATCH_TARGET) {
        const agentsNotice = deployGlobalAgents(undefined, onProgress)
        const detail = deployModes(undefined, onProgress)
        return modeResult(`${agentsNotice}\n${detail}`)
      }
      return modeResult(repairMode(target, undefined, onProgress))
    }
    if (kind === 'remove-modes') {
      return modeResult(uninstallModes(undefined, onProgress, target === MODES_BATCH_TARGET ? undefined : [target]))
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
    throw new Error('kind must be one of deploy-modes|remove-modes|install|update|uninstall|repair')
  }
  const target = payload.target
  if (typeof target !== 'string' || target === '') throw new Error('target must be a non-empty string')

  const rawTargets = payload.targets
  if (rawTargets !== undefined && !Array.isArray(rawTargets)) throw new Error('targets must be an array')
  const names = validateTargets(kind as OperationKind, target, rawTargets)
  for (const name of names) {
    // validateTargets already checked allowlists; require* re-checks cheaply.
    if (kind === 'install' || kind === 'update' || kind === 'uninstall') requirePlugin(name)
    if (kind === 'remove-modes' && name !== MODES_BATCH_TARGET) requireMode(name)
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

/** Invoke the endpoint handler with the host rpcErrorSchema failure contract. */
async function invokeEndpoint(endpoint: string, payload: unknown, queue: OperationQueue): Promise<RpcResult> {
  try {
    return handleEndpoint(endpoint, payload, queue)
  } catch (error) {
    return { ok: false, error: { code: 'internal' as const, message: error instanceof Error ? error.message : String(error), details: {} } }
  }
}

/** Wrap one endpoint handler as a Fetch-route handler speaking the host RPC envelope. */
function fetchHandlerFor(endpoint: string, queue: OperationQueue) {
  return async (request: Request): Promise<Response> => {
    const respond = (rpcId: string, result: unknown): Response =>
      Response.json({ type: 'server-response', rpcId, result })
    if (request.method !== 'POST') return new Response('method not allowed', { status: 405 })
    const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
    if (contentType !== 'application/json') return new Response('content type must be application/json', { status: 415 })
    let body: { type?: unknown; rpcId?: unknown; method?: unknown; payload?: unknown }
    try {
      body = await request.json() as typeof body
    } catch {
      return new Response('body is not JSON', { status: 400 })
    }
    const rpcId = typeof body.rpcId === 'string' ? body.rpcId : 'invalid-request'
    if (body.type !== 'client-request' || body.method !== endpoint) {
      return respond(rpcId, { ok: false, error: { code: 'internal', message: 'invalid client-request envelope', details: {} } })
    }
    return respond(rpcId, await invokeEndpoint(endpoint, body.payload, queue))
  }
}

export function registerModelRpc(connection: HostConnectionHandle, queue: OperationQueue): void {
  // Modern Hosts (0.1.2+): exact Fetch routes under /api keep the channel alive.
  if (typeof connection.fetch?.register === 'function') {
    for (const endpoint of ENDPOINTS) {
      connection.fetch.register({
        path: `${API_CHANNEL}/${endpoint}`,
        methods: ['POST'],
        requestBody: 'buffered',
        fetch: fetchHandlerFor(endpoint, queue),
      })
    }
  }
  // Legacy Hosts (0.1.1 and older): bare rpc channel. On modern Hosts this
  // registration silently fails, which is harmless — the Fetch routes above
  // are the transport there.
  // Legacy Hosts (0.1.1 and older): bare rpc channel. On modern Hosts this
  // registration throws ("cannot get property webServer without inject") and
  // must not escape — the throw also aborts sibling registrations in the
  // same inject callback, so guard it.
  try {
    connection.rpc.handle(RPC_CHANNEL, async (endpoint, rawPayload): Promise<RpcResult> => {
      return invokeEndpoint(endpoint, rawPayload, queue)
    }, { authority: 'loopback' })
  } catch {
    // Modern Host: the Fetch routes above are the transport.
  }
}

export type { OperationStartPayload }
