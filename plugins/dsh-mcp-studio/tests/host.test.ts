/** Integration test: mount engine lifecycle, settings seam wiring, loopback RPC registration. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context, Service } from '@deepseek-ai/cordis'
import {
  apply as studioApply,
  inject as studioInject,
  name as studioName,
} from '../src/index.ts'
import type { StudioSection } from '../src/types.ts'
import type { RpcResult } from '../src/settings-rpc.ts'

interface ScopeLike {
  get(): StudioSection
  watch(cb: () => void): () => void
  update(patch: object): Promise<void>
  replace(section: object): Promise<void>
}

class StubTools extends Service {
  readonly registered: string[] = []
  constructor(ctx: Context) {
    super(ctx, 'tools')
  }
  register(definition: { name: string }): () => void {
    this.registered.push(definition.name)
    return () => {
      this.registered = this.registered.filter(name => name !== definition.name)
    }
  }
  view(): unknown {
    const visible = new Map(this.registered.map(name => [name, { name, description: `desc of ${name}` }]))
    return { visible }
  }
}

class StubSettings extends Service {
  private readonly registrations = new Map<string, { scope: ScopeLike }>()
  constructor(ctx: Context) {
    super(ctx, 'settings')
  }
  register(ns: string, _schema: unknown, options: { base?: unknown }): ScopeLike {
    let user: Record<string, unknown> = {}
    let watcher: (() => void) | undefined
    const resolve = (): StudioSection => ({ ...(options.base as StudioSection), ...user }) as StudioSection
    const scope: ScopeLike = {
      get: () => resolve(),
      watch: cb => {
        watcher = cb
        return () => {
          watcher = undefined
        }
      },
      update: async patch => {
        user = { ...user, ...patch }
        watcher?.()
      },
      replace: async section => {
        user = section as Record<string, unknown>
        watcher?.()
      },
    }
    this.registrations.set(ns, { scope })
    return scope
  }
  commit(ns: string, patch: object): void {
    this.registrations.get(ns)?.scope.update(patch)
  }
  get writable(): boolean {
    return true
  }
  describe(): Array<{ ns: string; value: unknown; revision: number; applies: string }> {
    return [...this.registrations.entries()].map(([ns, { scope }]) => ({ ns, value: scope.get(), revision: 1, applies: 'live' }))
  }
  async mutate(): Promise<void> {}
}

class StubConnection extends Service {
  handler: ((endpoint: string, payload: unknown) => Promise<RpcResult>) | undefined
  constructor(ctx: Context) {
    super(ctx, 'connection')
  }
  readonly rpc = {
    handle: (_channel: string, handler: (endpoint: string, payload: unknown) => Promise<RpcResult>) => {
      this.handler = handler
      return () => {
        this.handler = undefined
      }
    },
  }
}

test('studio host: mounts per enabled row, hot-swaps on change, serves status RPC', async () => {
  const root = new Context()
  const tools = new StubTools(root)
  void tools
  const settings = new StubSettings(root)
  void settings
  const connection = new StubConnection(root)
  void connection

  const section: StudioSection = { servers: [] }
  const fiber = root.plugin({ name: studioName, inject: studioInject, apply: studioApply }, section)
  await fiber
  assert.ok(settings.describe().some(entry => entry.ns === 'mcp-studio'), 'namespace should register')
  assert.ok(connection.handler !== undefined, 'loopback RPC should register')

  const status = async (): Promise<{ servers: Array<{ name: string; state: string }>; summary: Record<string, number> }> => {
    const result = await connection.handler!('status', {})
    assert.ok(result.ok)
    return result.value as { servers: Array<{ name: string; state: string }>; summary: Record<string, number> }
  }

  let initial = await status()
  assert.deepEqual(initial.summary, { total: 0, enabled: 0, connected: 0, tools: 0 })

  // A mounted row contributing no tools reads as unreachable, not error.
  settings.commit('mcp-studio', { servers: [{
    id: 's1', enabled: true, name: 'demo', transport: 'stdio', command: 'false',
    argsLine: '', env: {}, cwd: '', url: '', headers: {}, toolCallTimeoutMs: 60_000, failOnStartupError: false,
  }] })
  await new Promise(resolve => setTimeout(resolve, 30))
  let after = await status()
  assert.equal(after.servers[0]!.name, 'demo')
  assert.equal(after.summary.enabled, 1)

  // Disabling every server unmounts and clears state.
  settings.commit('mcp-studio', { servers: [] })
  await new Promise(resolve => setTimeout(resolve, 30))
  after = await status()
  assert.deepEqual(after.summary, { total: 0, enabled: 0, connected: 0, tools: 0 })

  fiber.dispose()
  await new Promise(resolve => setTimeout(resolve, 20))
})
