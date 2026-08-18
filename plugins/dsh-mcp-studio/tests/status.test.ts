import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createExecutionRing, createStatusHandler, type MountTracker } from '../src/settings-rpc.ts'
import type { StudioSection } from '../src/types.ts'

function fakeView(tools: Record<string, string>): unknown {
  const visible = new Map(Object.entries(tools).map(([name, description]) => [name, { name, description }]))
  return { visible }
}

const section = (servers: Array<Partial<{ id: string; enabled: boolean; name: string; transport: string }>>): StudioSection =>
  ({
    servers: servers.map((server, index) => ({
      id: server.id ?? `s${index}`,
      enabled: server.enabled ?? true,
      name: server.name ?? `srv${index}`,
      transport: (server.transport ?? 'stdio') as 'stdio',
      command: 'x', argsLine: '', env: {}, cwd: '', url: '', headers: {},
      toolCallTimeoutMs: 60_000, failOnStartupError: false,
    })),
  })

test('status handler: aggregates registry tools per enabled server', async () => {
  const tracker: MountTracker = { states: new Map([['s2', { state: 'error', error: 'boom' }]]) }
  const handler = createStatusHandler(
    () => section([
      { id: 's1', name: 'alpha' },
      { id: 's2', name: 'beta' },
      { id: 's3', name: 'gamma', enabled: false },
    ]),
    () => fakeView({
      'mcp__alpha__list': 'lists things',
      'mcp__alpha__get': 'gets a thing',
      'mcp__other__tool': 'not ours',
    }),
    tracker,
  )
  const result = await handler()
  assert.ok(result.ok)
  const value = result.value as { servers: Array<{ name: string; state: string; toolCount: number; tools: Array<{ name: string }> }>; summary: Record<string, number> }
  const byName = new Map(value.servers.map(server => [server.name, server]))
  assert.equal(byName.get('alpha')!.state, 'connected')
  assert.equal(byName.get('alpha')!.toolCount, 2)
  assert.deepEqual(byName.get('alpha')!.tools.map(tool => tool.name), ['get', 'list'])
  assert.equal(byName.get('beta')!.state, 'error')
  assert.match(byName.get('beta')!.error ?? '', /boom/)
  assert.equal(byName.get('gamma')!.state, 'disabled')
  assert.deepEqual(value.summary, { total: 3, enabled: 2, connected: 1, tools: 2 })
})

test('status handler: mounting and unreachable states', async () => {
  const tracker: MountTracker = { states: new Map([['s0', { state: 'mounting' }]]) }
  const handler = createStatusHandler(
    () => section([{ id: 's0', name: 'slow' }, { id: 's1', name: 'flat' }]),
    () => fakeView({}),
    tracker,
  )
  const result = await handler()
  assert.ok(result.ok)
  const value = result.value as { servers: Array<{ name: string; state: string }> }
  const byName = new Map(value.servers.map(server => [server.name, server]))
  assert.equal(byName.get('slow')!.state, 'mounting')
  assert.equal(byName.get('flat')!.state, 'unreachable')
})

test('execution ring: trims to capacity, clears, reports capacity in status', async () => {
  const ring = createExecutionRing(3)
  for (let i = 0; i < 5; i += 1) {
    ring.push({ at: i, server: 's', tool: `t${i}`, durationMs: 1, ok: true })
  }
  // Newest three survive, newest first.
  assert.deepEqual(ring.recent(10).map(record => record.tool), ['t4', 't3', 't2'])
  const handler = createStatusHandler(() => ({ servers: [] }), () => undefined, { states: new Map() }, ring)
  const result = await handler()
  assert.ok(result.ok)
  const value = result.value as { executions: Array<{ tool: string }>; execCapacity: number }
  assert.equal(value.execCapacity, 3)
  assert.equal(value.executions.length, 3)
  ring.clear()
  assert.deepEqual(ring.recent(10), [])
  assert.equal(ring.max, 3)
})
