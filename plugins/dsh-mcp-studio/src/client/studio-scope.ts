/** Client-side studio scope: settings read/write, live-status polling, diagnostics — all through the plugin's loopback channel. */
import type { DiagnoseReport, SettingsScope, StudioLive, StudioScopeSnapshot } from './contracts.js'
import { STUDIO_CHANNEL } from '../settings-rpc.js'

type Mutation = { op: 'set'; path: string[]; value: unknown } | { op: 'unset'; path: string[] }

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

  constructor(private readonly call: (endpoint: string, payload: unknown) => Promise<{ ok: true; value: unknown } | { ok: false; error: { message: string } }>) {
    void this.load()
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
    const response = await this.call('status', {})
    if (!response.ok) return { error: response.error.message }
    const value = response.value as Partial<StudioLive>
    if (!Array.isArray(value.servers) || typeof value.summary !== 'object' || value.summary === null) {
      return { error: 'host returned no status payload' }
    }
    return value as StudioLive
  }

  async clearExecutions(): Promise<{ cleared: boolean } | { error: string }> {
    const response = await this.call('executions/clear', {})
    if (!response.ok) return { error: response.error.message }
    return { cleared: true }
  }

  async diagnose(id: string): Promise<DiagnoseReport | { error: string }> {
    const response = await this.call('diagnose', { id })
    if (!response.ok) return { error: response.error.message }
    return response.value as DiagnoseReport
  }

  private async load(): Promise<void> {
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

export function createStudioScope(connection: { rpc: { call(channel: string, endpoint: string, payload: unknown): Promise<{ ok: true; value: unknown } | { ok: false; error: { message: string } }> } }): SettingsScope {
  return new StudioScope((endpoint, payload) => connection.rpc.call(STUDIO_CHANNEL, endpoint, payload))
}
