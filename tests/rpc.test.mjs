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
  const connection = {
    rpc: {
      handle(channel, registered, options) {
        assert.equal(channel, '/dsh-redteam-model')
        handler = registered
        authority = options.authority
      },
    },
  }
  process.env.DSH_HOME = home
  registerModelRpc(connection, queue)
  return {
    home,
    queue,
    authority: () => authority,
    call(endpoint, payload = {}) {
      return handler(endpoint, payload)
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
    assert.equal((await fixture.call('unknown')).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'shell', target: 'x' })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'repair', target: '../../outside' })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'repair', target: 'redteam', targets: {} })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'deploy-modes', target: 'redteam', targets: 'redteam' })).ok, false)
    assert.equal((await fixture.call('operation/start', { kind: 'install', target: 'missing-plugin' })).ok, false)
    const overflow = Array.from({ length: 16 }, () => 'dsh-hunter')
    assert.equal((await fixture.call('operation/start', { kind: 'install', target: 'missing', targets: overflow })).ok, false)
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
