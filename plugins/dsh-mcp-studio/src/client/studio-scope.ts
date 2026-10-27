/** Client-side studio scope: settings read/write, live-status polling, diagnostics — all through the plugin's loopback channel. */
import type { DiagnoseReport, HubRpcResult, SettingsScope, StudioConnectionHandle, StudioLive, StudioScopeSnapshot } from './contracts.js'
import { STUDIO_CHANNEL } from '../settings-rpc.js'

type Mutation = { op: 'set'; path: string[]; value: unknown } | { op: 'unset'; path: string[] }

/** Exact Fetch routes registered by Host 0.1.2+ under the reserved /api prefix. */
const API_CHANNEL = `/api${STUDIO_CHANNEL}`
/** Bare RPC channel registered by older Hosts through connection.rpc.handle. */
const LEGACY_CHANNEL = STUDIO_CHANNEL

/** The modern route is absent (old Host or static fallback), so the legacy channel may answer. */
class RouteUnavailableError extends Error {}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

interface DescriptorShape {
  status?: unknown
  value?: unknown
  base?: unknown
  user?: unknown
  revision?: unknown
  writable?: unknown
}

export class StudioScope implements SettingsScope {
  private snapshot: StudioScopeSnapshot = { status: 'loading', value: undefined, base: undefined, user: undefined, revision: undefined, writable: false, mode: 'host' }
  private readonly listeners = new Set<() => void>()
  private tail: Promise<unknown> = Promise.resolve()
  private channel: 'api' | 'legacy' = 'api'
  private rpcId = 0
  /** Resolves once the first settings read settled (ready or unavailable). */
  readonly ready: Promise<void>

  constructor(private readonly connection: StudioConnectionHandle) {
    this.ready = this.load()
  }

  getSnapshot = (): StudioScopeSnapshot => this.snapshot

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  set(field: string, value: unknown): Promise<void> {
    return this.write({ op: 'set', path: [field], value })
  }

  unset(field: string): Promise<void> {
    return this.write({ op: 'unset', path: [field] })
  }

  async status(): Promise<StudioLive | { error: string }> {
    try {
      const response = await this.call('status', {})
      if (!response.ok) return { error: response.error.message }
      const value = response.value as Partial<StudioLive>
      if (!Array.isArray(value.servers) || typeof value.summary !== 'object' || value.summary === null) {
        return { error: 'host returned no status payload' }
      }
      return value as StudioLive
    } catch (error) {
      return { error: messageOf(error) }
    }
  }

  async clearExecutions(): Promise<{ cleared: boolean } | { error: string }> {
    try {
      const response = await this.call('executions/clear', {})
      if (!response.ok) return { error: response.error.message }
      return { cleared: true }
    } catch (error) {
      return { error: messageOf(error) }
    }
  }

  async diagnose(id: string): Promise<DiagnoseReport | { error: string }> {
    try {
      const response = await this.call('diagnose', { id })
      if (!response.ok) return { error: response.error.message }
      return response.value as DiagnoseReport
    } catch (error) {
      return { error: messageOf(error) }
    }
  }

  private async load(): Promise<void> {
    try {
      const response = await this.call('settings/get', {})
      if (!response.ok) {
        this.publish({ ...this.snapshot, status: 'unavailable' })
        return
      }
      const view = (typeof response.value === 'object' && response.value !== null ? response.value : {}) as DescriptorShape
      this.publish({
        status: 'ready',
        value: view.value,
        base: view.base,
        user: view.user,
        revision: typeof view.revision === 'number' ? view.revision : undefined,
        writable: view.writable === true,
        mode: 'host',
      })
    } catch {
      this.publish({ ...this.snapshot, status: 'unavailable' })
    }
  }

  /**
   * Modern Hosts (0.1.2+) expose exact Fetch routes under /api, which cannot
   * travel through connection.rpc.call. Legacy Hosts only serve the bare
   * channel, so probe /api first and stick with whichever transport answered.
   */
  private async call(endpoint: string, payload: unknown): Promise<HubRpcResult> {
    if (this.channel === 'api') {
      try {
        return await this.invokeApi(endpoint, payload)
      } catch (error) {
        if (!(error instanceof RouteUnavailableError)) throw error
        this.channel = 'legacy'
      }
    }
    return this.connection.rpc.call(LEGACY_CHANNEL, endpoint, payload)
  }

  private async invokeApi(endpoint: string, payload: unknown): Promise<HubRpcResult> {
    const rpcId = `studio-${++this.rpcId}`
    const response = await fetch(`${API_CHANNEL}/${endpoint}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'client-request', rpcId, method: endpoint, payload }),
    })
    if (!response.ok) {
      const message = `transport failure for ${API_CHANNEL}/${endpoint}: HTTP ${response.status}`
      if (response.status === 404 || response.status === 405) throw new RouteUnavailableError(message)
      throw new Error(message)
    }
    let envelope: { type?: unknown; rpcId?: unknown; result?: HubRpcResult }
    try {
      envelope = await response.json() as typeof envelope
    } catch {
      throw new RouteUnavailableError(`transport failure for ${API_CHANNEL}/${endpoint}: response is not JSON`)
    }
    if (envelope.type !== 'server-response' || envelope.rpcId !== rpcId || envelope.result === undefined) {
      throw new Error(`transport failure for ${API_CHANNEL}/${endpoint}: malformed envelope`)
    }
    return envelope.result
  }

  private write(op: Mutation): Promise<void> {
    const task = this.tail.then(async () => {
      const response = await this.call('settings/mutate', {
        ops: [op],
        ...(this.snapshot.revision === undefined ? {} : { expectedRevision: this.snapshot.revision }),
      })
      if (!response.ok) throw new Error(response.error.message)
      const view = (typeof response.value === 'object' && response.value !== null ? response.value : {}) as DescriptorShape
      this.publish({
        status: 'ready',
        value: view.value,
        base: view.base,
        user: view.user,
        revision: typeof view.revision === 'number' ? view.revision : undefined,
        writable: view.writable === true,
        mode: 'host',
      })
    })
    this.tail = task.catch(() => {})
    return task
  }

  private publish(snapshot: StudioScopeSnapshot): void {
    this.snapshot = snapshot
    for (const listener of this.listeners) listener()
  }
}

export function createStudioScope(connection: StudioConnectionHandle): SettingsScope {
  return new StudioScope(connection)
}
