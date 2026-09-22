import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { OperationQueue, registerModelRpc } from '../lib/index.js'

function rpcFixture() {
  const previousHome = process.env.DSH_HOME
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-redteam-rpc-test-'))
  const queue = new OperationQueue()
  let handler
  let authority
  const fetchRoutes = new Map()
  const connection = {
    rpc: {
      handle(channel, registered, options) {
        assert.equal(channel, '/dsh-redteam-model')
        handler = registered
        authority = options.authority
      },
    },
    fetch: {
      register(route) {
        assert.match(route.path, /^\/api\/dsh-redteam-model\//)
        assert.deepEqual(route.methods, ['POST'])
        fetchRoutes.set(route.path, route)
      },
    },
  }
  process.env.DSH_HOME = home
  registerModelRpc(connection, queue)
  return {
    home,
    queue,
    fetchRoutes,
    authority: () => authority,
    call(endpoint, payload = {}) {
      return handler(endpoint, payload)
    },
    /** Round-trip one envelope through the registered Fetch route. */
    async callFetch(endpoint, payload = {}) {
      const route = fetchRoutes.get(`/api/dsh-redteam-model/${endpoint}`)
      if (route === undefined) throw new Error(`no fetch route for ${endpoint}`)
      const request = new Request(`http://host/api/dsh-redteam-model/${endpoint}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'client-request', rpcId: 't-1', method: endpoint, payload }),
      })
      const response = await route.fetch(request)
      assert.equal(response.status, 200)
      const envelope = await response.json()
      assert.equal(envelope.type, 'server-response')
      assert.equal(envelope.rpcId, 't-1')
      return envelope.result
    },
    cleanup() {
      queue.dispose()
      if (previousHome === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = previousHome
      rmSync(home, { recursive: true, force: true })
    },
  }
}

test('RPC registers as loopback and rejects unknown input', async () => {
  const fixture = rpcFixture()
  try {
    assert.equal(fixture.authority(), 'loopback')
    const unknown = await fixture.call('unknown')
    assert.equal(unknown.ok, false)
    // Failure envelopes must satisfy the host client-connection rpcErrorSchema
    // (code/message/details) or the browser SDK hides the real cause (#10).
    assert.equal(unknown.error.code, 'internal')
    assert.equal(typeof unknown.error.message, 'string')
    assert.deepEqual(unknown.error.details, {})
    assert.equal((await fixture.call('operation/start', { kind: 'shell', target: 'x' })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'repair', target: '../../outside' })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'repair', target: 'redteam', targets: {} })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'deploy-modes', target: 'redteam', targets: 'redteam' })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'install', target: 'missing-plugin' })).ok, false)
    const overflow = Array.from({ length: 33 }, () => 'dsh-hunter')
    assert.equal((await fixture.call('operation/start', { kind: 'install', target: 'missing', targets: overflow })).ok, false)
  } finally {
    fixture.cleanup()
  }
})

test('Fetch routes under /api carry the RPC envelope end to end (#11 follow-up)', async () => {
  const fixture = rpcFixture()
  try {
    assert.equal(fixture.fetchRoutes.size, 4)
    const status = await fixture.callFetch('status', {})
    assert.equal(status.ok, true)
    assert.equal(typeof status.value.summary.pluginsTotal, 'number')
    const bad = await fixture.callFetch('status', {})
    assert.equal(bad.ok, true)
    const envelopeMismatch = await (async () => {
      const route = fixture.fetchRoutes.get('/api/dsh-redteam-model/status')
      const request = new Request('http://host/api/dsh-redteam-model/status', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'client-request', rpcId: 't-2', method: 'other/endpoint', payload: {} }),
      })
      const response = await route.fetch(request)
      const envelope = await response.json()
      return envelope.result
    })()
    assert.equal(envelopeMismatch.ok, false)
    assert.equal(envelopeMismatch.error.code, 'internal')
    const started = await fixture.callFetch('operation/start', { kind: 'deploy-modes', target: 'redteam' })
    assert.equal(started.ok, true)
    await fixture.queue.whenIdle()
  } finally {
    fixture.cleanup()
  }
})

test('mode row repair touches only the named mode and warns on a preserved conflict', async () => {
  const fixture = rpcFixture()
  try {
    const presets = path.join(fixture.home, '.agent-presets')
    const foreign = path.join(presets, 'redteam')
    mkdirSync(foreign, { recursive: true })
    writeFileSync(path.join(foreign, 'foreign.txt'), 'keep\n', 'utf8')

    const result = await fixture.call('operation/start', { kind: 'repair', target: 'redteam' })
    assert.equal(result.ok, true)
    await fixture.queue.whenIdle()

    const record = fixture.queue.list()[0]
    assert.equal(record?.state, 'warned')
    assert.match(record?.detail ?? '', /skipped existing entries: redteam/)
    assert.equal(existsSync(path.join(presets, 'pentest')), false)
    assert.equal(existsSync(path.join(foreign, 'foreign.txt')), true)
  } finally {
    fixture.cleanup()
  }
})

test('mode row repair copies one missing mode into a real presets directory', async () => {
  const fixture = rpcFixture()
  try {
    const presets = path.join(fixture.home, '.agent-presets')
    mkdirSync(presets, { recursive: true })
    const result = await fixture.call('operation/start', { kind: 'repair', target: 'redteam' })
    assert.equal(result.ok, true)
    await fixture.queue.whenIdle()
    assert.equal(fixture.queue.list()[0]?.state, 'done')
    assert.equal(existsSync(path.join(presets, 'redteam', 'preset.yml')), true)
    assert.equal(existsSync(path.join(presets, 'pentest')), false)
  } finally {
    fixture.cleanup()
  }
})

test('remove-modes takes the whole deployment back through the queue', async () => {
  const fixture = rpcFixture()
  try {
    const presets = path.join(fixture.home, '.agent-presets')
    assert.equal((await fixture.call('operation/start', { kind: 'deploy-modes', target: 'modes' })).ok, true)
    await fixture.queue.whenIdle()
    assert.equal(existsSync(presets), true)

    assert.equal((await fixture.call('operation/start', { kind: 'remove-modes', target: 'nope' })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'remove-modes', target: 'modes', targets: ['redteam'] })).ok, false)

    const result = await fixture.call('operation/start', { kind: 'remove-modes', target: 'modes' })
    assert.equal(result.ok, true)
    await fixture.queue.whenIdle()
    const record = fixture.queue.list().find(op => op.kind === 'remove-modes')
    assert.equal(record?.state, 'done')
    assert.match(record?.detail ?? '', /removed agent presets link/)
    assert.equal(existsSync(presets), false)
    assert.equal((await fixture.call('status', {})).value.summary.modesReady, 0)
  } finally {
    fixture.cleanup()
  }
})

test('RPC rejects an over-capacity operation before enqueueing any records', async () => {
  const fixture = rpcFixture()
  let releaseFirst
  const firstGate = new Promise(resolve => {
    releaseFirst = resolve
  })
  try {
    fixture.queue.enqueue('install', 'busy-1', async () => {
      await firstGate
      return 'done'
    })
    for (let index = 2; index <= 50; index += 1) {
      fixture.queue.enqueue('install', `busy-${index}`, async () => 'done')
    }

    const result = await fixture.call('operation/start', { kind: 'install', target: 'dsh-hunter' })
    assert.equal(result.ok, false)
    assert.match(result.error.message, /operation queue capacity exceeded/)
    assert.equal(fixture.queue.list().length, 50)
    assert.equal(fixture.queue.list().some(record => record.target === 'dsh-hunter'), false)

    releaseFirst()
    await fixture.queue.whenIdle()
  } finally {
    releaseFirst?.()
    fixture.cleanup()
  }
})
