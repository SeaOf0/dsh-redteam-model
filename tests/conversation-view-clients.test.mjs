import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'
import * as React from 'react'

const CASES = [
  ['plugins/dsh-campaign-memory/lib/client.js', '@dsh-external/dsh-campaign-memory', 'campaign-memory', 'showCampaignMemory', true],
  ['plugins/dsh-attack-atlas/lib/client.js', '@dsh-external/dsh-attack-atlas', 'attack-atlas', 'showAttackAtlas', true],
  ['plugins/dsh-redteam-results/lib/client.js', '@dsh-external/dsh-redteam-results', 'redteam-results', 'showRedteamResults', false],
  ['plugins/dsh-hunter/lib/client.js', '@dsh-external/dsh-hunter', 'hunter', 'showHunter', false],
  ['plugins/dsh-webshell-mgr/lib/client.js', '@dsh-external/dsh-webshell-mgr', 'webshell-mgr', 'showWebshellManager', false],
]

function loadBundle(file, packageId) {
  let definition
  vm.runInNewContext(readFileSync(file, 'utf8'), {
    window: { __ModuleLoader__: { load(value) { definition = value } } },
  })
  assert.equal(definition.id, packageId)
  return definition.factory(name => {
    if (name === 'react') return React
    throw new Error(`unexpected browser import: ${name}`)
  })
}

function harness(bundle, field, needsSessions) {
  let snapshot = {
    status: 'ready',
    value: { [field]: true },
    writable: true,
    mode: 'host',
  }
  const listeners = new Set()
  const registered = []
  const lifecycle = []
  let disposed = 0
  let cleanup = () => undefined

  const ctx = {
    effect() {},
    inject(services, callback) {
      assert.equal(needsSessions, services.includes('sessions'))
      return callback({ sessions: {} })
    },
    settingsScope: {
      bind(spec) {
        assert.equal(spec.namespace, 'redteam-manager-ui')
        return {
          getSnapshot: () => snapshot,
          subscribe(listener) {
            lifecycle.push('subscribe')
            listeners.add(listener)
            return () => listeners.delete(listener)
          },
        }
      },
    },
    slots: {
      inject(name, callback) {
        assert.equal(name, 'conversation.view')
        cleanup = callback()
        return cleanup
      },
      register(options) {
        lifecycle.push('register')
        registered.push(options.id)
        let alive = true
        return () => {
          if (!alive) throw new Error('view disposer called twice')
          alive = false
          disposed += 1
        }
      },
    },
  }

  bundle.apply(ctx)
  return {
    registered,
    lifecycle,
    disposed: () => disposed,
    publish(next) {
      snapshot = next
      for (const listener of listeners) listener()
    },
    cleanup: () => cleanup(),
  }
}

for (const [file, packageId, slotId, field, needsSessions] of CASES) {
  test(`${slotId} owns an idempotent fail-open visibility lifecycle`, () => {
    const bundle = loadBundle(file, packageId)
    assert.deepEqual(Array.from(bundle.inject), ['slots', 'settingsScope'])
    const view = harness(bundle, field, needsSessions)
    assert.deepEqual(view.lifecycle.slice(0, 2), ['subscribe', 'register'])
    assert.deepEqual(view.registered, [slotId])

    view.publish({ status: 'loading', value: undefined, writable: false, mode: 'memory' })
    view.publish({ status: 'ready', value: {}, writable: true, mode: 'host' })
    view.publish({ status: 'ready', value: { [field]: 'false' }, writable: true, mode: 'host' })
    assert.deepEqual(view.registered, [slotId])
    assert.equal(view.disposed(), 0)

    view.publish({ status: 'ready', value: { [field]: false }, writable: true, mode: 'host' })
    assert.equal(view.disposed(), 1)
    view.publish({ status: 'ready', value: { [field]: false }, writable: true, mode: 'host' })
    assert.equal(view.disposed(), 1)

    view.publish({ status: 'unavailable', value: { [field]: false }, writable: false, mode: 'memory' })
    assert.deepEqual(view.registered, [slotId, slotId])

    view.publish({ status: 'ready', value: { [field]: true }, writable: true, mode: 'host' })
    assert.deepEqual(view.registered, [slotId, slotId])

    view.cleanup()
    assert.equal(view.disposed(), 2)
    view.publish({ status: 'ready', value: { [field]: false }, writable: true, mode: 'host' })
    assert.deepEqual(view.registered, [slotId, slotId])
    assert.equal(view.disposed(), 2)
  })
}
