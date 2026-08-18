import { test } from 'node:test'
import assert from 'node:assert/strict'

import { StudioController } from '../src/client/controller.ts'
import type { ServerDraft, SettingsScope, StudioScopeSnapshot } from '../src/client/contracts.ts'

const draft = (id: string): ServerDraft => ({
  id, enabled: true, name: id, transport: 'stdio', command: 'x', argsLine: '',
  env: [], cwd: '', url: '', headers: [], toolCallTimeoutMs: 60_000, failOnStartupError: false,
})

function fakeScope(servers: ServerDraft[]): SettingsScope {
  let snapshot: StudioScopeSnapshot = {
    status: 'ready', value: { servers }, base: undefined, user: undefined,
    revision: 1, writable: true, mode: 'host',
  }
  return {
    getSnapshot: () => snapshot,
    subscribe: () => () => {},
    set: async (field, value) => {
      if (field !== 'servers') return
      snapshot = { ...snapshot, value: { servers: value as ServerDraft[] }, revision: (snapshot.revision ?? 0) + 1 }
    },
    unset: async () => {},
    status: async () => ({ servers: [], summary: { total: 0, enabled: 0, connected: 0, tools: 0 } }),
    diagnose: async () => ({ ok: true, elapsedMs: 1, toolCount: 0 }),
  }
}

test('controller: moveServer reorders and save persists the order', async () => {
  const scope = fakeScope([draft('a'), draft('b'), draft('c')])
  const controller = new StudioController(scope)
  const face = controller.inject()

  face.moveServer('c', 'a')
  let state = controller.getStore().getSnapshot()
  assert.deepEqual(state.view.servers.map(server => server.id), ['c', 'a', 'b'])
  assert.equal(state.dirty, true)

  await face.save()
  state = controller.getStore().getSnapshot()
  assert.equal(state.dirty, false)
  const persisted = (scope.getSnapshot().value as { servers: ServerDraft[] }).servers
  assert.deepEqual(persisted.map(server => server.id), ['c', 'a', 'b'], 'saved order must match staged order')

  // No-ops stay clean.
  face.moveServer('a', 'a')
  assert.equal(controller.getStore().getSnapshot().dirty, false)
  face.moveServer('missing', 'a')
  assert.equal(controller.getStore().getSnapshot().dirty, false)
})
