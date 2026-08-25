import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'
import * as React from 'react'
import * as JsxRuntime from 'react/jsx-runtime'
import TestRenderer, { act } from 'react-test-renderer'

const DEFAULT_VISIBILITY = {
  showCampaignMemory: true,
  showAttackAtlas: true,
  showRedteamResults: true,
  showHunter: true,
  showWebshellManager: true,
}

const STATUS = {
  summary: {
    modesTotal: 0,
    modesReady: 0,
    pluginsTotal: 1,
    pluginsInstalled: 1,
    updatesAvailable: 0,
    busy: false,
  },
  modes: [],
  plugins: [{
    name: 'dsh-attack-atlas',
    title: 'Attack Atlas',
    description: 'Attack Atlas test fixture',
    installState: 'installed',
    installedVersion: '1.1.1',
    mountPlane: 'host',
  }],
  operations: [],
}

function stripProps(props, names) {
  const next = { ...props }
  for (const name of names) delete next[name]
  return next
}

const primitives = {
  Button({ children, icon, ...props }) {
    return React.createElement('button', stripProps(props, ['size', 'variant']), icon, children)
  },
  DisclosureRow({ children, ...props }) {
    return React.createElement('div', stripProps(props, ['open', 'onOpenChange']), children)
  },
  Modal({ open, title, description, children, footer }) {
    if (!open) return null
    return React.createElement('section', { role: 'dialog', 'aria-label': title },
      React.createElement('h2', null, title),
      React.createElement('p', null, description),
      children,
      footer,
    )
  },
  StateDot() {
    return React.createElement('span')
  },
  IconAgentPresetOutline16() {
    return React.createElement('span')
  },
  IconCordisPluginOutline14() {
    return React.createElement('span')
  },
  IconRefreshOutline16() {
    return React.createElement('span')
  },
}

function loadClientBundle() {
  let definition
  const browserWindow = {
    __ModuleLoader__: {
      load(value) {
        definition = value
      },
    },
    setTimeout,
    clearTimeout,
  }
  vm.runInNewContext(readFileSync('lib/client.js', 'utf8'), { window: browserWindow })
  assert.equal(definition.id, '@dsh-external/dsh-redteam-model')
  return definition.factory(name => {
    if (name === 'react') return React
    if (name === 'react/jsx-runtime') return JsxRuntime
    if (name === '@deepseek-ai/dsh-client-ui-primitives') return primitives
    throw new Error(`unexpected browser import: ${name}`)
  })
}

async function renderManager(initialSnapshot) {
  const client = loadClientBundle()
  let snapshot = initialSnapshot
  let pageComponent
  let dictionary = {}
  const listeners = new Set()
  const setCalls = []
  const rpcCalls = []

  const ctx = {
    effect(factory, label) {
      if (label?.endsWith(': locale')) factory()
    },
    connection: {
      rpc: {
        async call(_channel, endpoint) {
          rpcCalls.push(endpoint)
          assert.equal(endpoint, 'status')
          return { ok: true, value: STATUS }
        },
      },
    },
    settingsScope: {
      bind(spec) {
        assert.equal(spec.namespace, 'redteam-manager-ui')
        return {
          getSnapshot: () => snapshot,
          subscribe(listener) {
            listeners.add(listener)
            return () => listeners.delete(listener)
          },
          async set(field, value) {
            setCalls.push({ field, value })
          },
        }
      },
    },
    locale: {
      register(_namespace, dictionaries) {
        dictionary = dictionaries.en
        return () => undefined
      },
      bind() {
        return key => dictionary[key] ?? key
      },
    },
    slots: {
      inject(name, register) {
        assert.equal(name, 'settings.section')
        register()
      },
      register(options, component) {
        assert.equal(options.id, 'redteam-manager')
        pageComponent = component
        return () => undefined
      },
    },
  }

  client.apply(ctx)
  assert.equal(typeof pageComponent, 'function')

  let renderer
  await act(async () => {
    renderer = TestRenderer.create(React.createElement(pageComponent))
    await Promise.resolve()
    await Promise.resolve()
  })

  const openPlugins = () => {
    const button = renderer.root.findAllByType('button').find(node => node.children.includes('Plugins'))
    assert.ok(button, 'Plugins page button must render')
    act(() => button.props.onClick())
  }

  return {
    renderer,
    rpcCalls,
    setCalls,
    openPlugins,
    setSnapshot(next) {
      snapshot = next
      for (const listener of listeners) listener()
    },
    async cleanup() {
      await act(async () => renderer.unmount())
    },
  }
}

test('Manager fails open when an unavailable settings snapshot retains false', async () => {
  const manager = await renderManager({
    status: 'unavailable',
    value: { ...DEFAULT_VISIBILITY, showAttackAtlas: false },
    writable: false,
    mode: 'host',
  })
  try {
    manager.openPlugins()
    const toggle = manager.renderer.root.findByProps({
      role: 'switch',
      'aria-label': 'Attack Atlas: Show conversation tab',
    })
    assert.equal(toggle.props.checked, true)
    assert.equal(toggle.props.disabled, true)
  } finally {
    await manager.cleanup()
  }
})

test('Manager reports a resolved settings write that did not persist', async () => {
  const manager = await renderManager({
    status: 'ready',
    value: { ...DEFAULT_VISIBILITY },
    writable: true,
    mode: 'host',
  })
  try {
    manager.openPlugins()
    const findToggle = () => manager.renderer.root.findByProps({
      role: 'switch',
      'aria-label': 'Attack Atlas: Show conversation tab',
    })

    await act(async () => {
      findToggle().props.onChange({ target: { checked: false } })
      await Promise.resolve()
      await Promise.resolve()
    })

    assert.deepEqual(manager.setCalls, [{ field: 'showAttackAtlas', value: false }])
    assert.equal(findToggle().props.checked, true)
    const alert = manager.renderer.root.findByProps({ role: 'alert' })
    const text = alert.findAllByType('span').flatMap(node => node.children).join(' ')
    assert.match(text, /preference was not saved/i)
    assert.equal(manager.rpcCalls.includes('operation/start'), false)
  } finally {
    await manager.cleanup()
  }
})
