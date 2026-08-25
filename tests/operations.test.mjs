import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { OperationQueue } from '../lib/index.js'

function historyFixture(t) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'dsh-redteam-operations-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  return path.join(directory, 'operations.json')
}

test('queued operation can be cancelled and is not executed', async () => {
  const queue = new OperationQueue()
  const order = []

  queue.enqueue('install', 'first', async update => {
    update({ percent: 10, detail: 'started first' })
    order.push('first-start')
    await new Promise(resolve => setTimeout(resolve, 40))
    order.push('first-end')
    return 'installed first'
  })

  const secondId = queue.enqueue('install', 'second', async () => {
    order.push('second-run')
    return 'installed second'
  })

  assert.equal(queue.cancel(secondId), true)
  assert.equal(queue.cancel(secondId), false)

  await new Promise(resolve => setTimeout(resolve, 80))
  assert.deepEqual(order, ['first-start', 'first-end'])

  const records = queue.list()
  assert.equal(records.length, 2)
  assert.equal(records[0]?.state, 'done')
  assert.equal(records[1]?.state, 'cancelled')
  assert.equal(records[1]?.detail, 'cancelled')
})

test('cancel returns false for running and settled operations', async () => {
  const queue = new OperationQueue()
  let releaseRunning
  const runningStarted = new Promise(resolve => {
    releaseRunning = resolve
  })

  const runningId = queue.enqueue('install', 'running', async update => {
    releaseRunning()
    await new Promise(resolve => setTimeout(resolve, 40))
    return 'done'
  })

  await runningStarted
  assert.equal(queue.cancel(runningId), false)

  await new Promise(resolve => setTimeout(resolve, 60))
  assert.equal(queue.cancel(runningId), false)
  assert.equal(queue.list()[0]?.state, 'done')
})

test('clearSettled keeps running and queued records, clears only settled history', async () => {
  const queue = new OperationQueue()
  let releaseFirst
  const firstGate = new Promise(resolve => {
    releaseFirst = resolve
  })

  queue.enqueue('install', 'first', async () => {
    await firstGate
    return 'ok'
  })
  const secondId = queue.enqueue('update', 'second', async () => 'ok')
  const thirdId = queue.enqueue('uninstall', 'third', async () => 'ok')

  // Let the first operation start and become running.
  await new Promise(resolve => setTimeout(resolve, 5))
  queue.clearSettled()
  assert.deepEqual(queue.list().map(record => record.id).sort(), [secondId, thirdId, 'op-0001'].sort())

  releaseFirst()
  await new Promise(resolve => setTimeout(resolve, 20))
  queue.clearSettled()
  assert.deepEqual(queue.list(), [])
})

test('runner can settle an operation as warned', async () => {
  const queue = new OperationQueue()
  queue.enqueue('deploy-modes', 'redteam', async () => ({
    state: 'warned',
    detail: 'preserved existing preset',
  }))
  await queue.whenIdle()
  assert.equal(queue.list()[0]?.state, 'warned')
  assert.equal(queue.list()[0]?.detail, 'preserved existing preset')
})

test('settled operation history survives queue restart and ids keep increasing', async t => {
  const historyFile = historyFixture(t)
  const firstQueue = new OperationQueue(historyFile)
  firstQueue.enqueue('install', 'scanner-toolkit', async () => 'installed scanner-toolkit')
  await firstQueue.whenIdle()

  const restartedQueue = new OperationQueue(historyFile)
  assert.deepEqual(restartedQueue.list(), [{
    id: 'op-0001',
    kind: 'install',
    target: 'scanner-toolkit',
    state: 'done',
    percent: 100,
    detail: 'installed scanner-toolkit',
  }])

  const nextId = restartedQueue.enqueue('uninstall', 'scanner-toolkit', async () => 'uninstalled')
  assert.equal(nextId, 'op-0002')
  await restartedQueue.whenIdle()
})

test('restart marks queued and running history as interrupted', t => {
  const historyFile = historyFixture(t)
  writeFileSync(historyFile, `${JSON.stringify({
    schemaVersion: 1,
    records: [
      { id: 'op-0007', kind: 'install', target: 'queued-plugin', state: 'queued', percent: 0 },
      { id: 'op-0008', kind: 'update', target: 'running-plugin', state: 'running', percent: 45 },
      { id: 'op-0009', kind: 'repair', target: 'redteam', state: 'done', percent: 100, detail: 'repaired' },
    ],
  }, null, 2)}\n`)

  const queue = new OperationQueue(historyFile)
  const records = queue.list()
  assert.deepEqual(records.map(record => record.state), ['failed', 'failed', 'done'])
  assert.equal(records[0]?.percent, 100)
  assert.equal(records[0]?.detail, 'interrupted by previous dsh web restart')
  assert.equal(records[1]?.error, 'interrupted by previous dsh web restart')

  const persisted = JSON.parse(readFileSync(historyFile, 'utf8'))
  assert.deepEqual(persisted.records.map(record => record.state), ['failed', 'failed', 'done'])
})

test('clearSettled persists the cleared history', async t => {
  const historyFile = historyFixture(t)
  const queue = new OperationQueue(historyFile)
  queue.enqueue('repair', 'redteam', async () => 'repaired')
  await queue.whenIdle()
  queue.clearSettled()

  const restartedQueue = new OperationQueue(historyFile)
  assert.deepEqual(restartedQueue.list(), [])
  assert.equal(restartedQueue.enqueue('repair', 'pentest', async () => 'repaired'), 'op-0002')
  await restartedQueue.whenIdle()
})

test('malformed history is ignored and safely replaced', async t => {
  const historyFile = historyFixture(t)
  writeFileSync(historyFile, '{not-json')

  const queue = new OperationQueue(historyFile)
  assert.deepEqual(queue.list(), [])
  queue.enqueue('deploy-modes', 'redteam', async () => 'deployed')
  await queue.whenIdle()

  const persisted = JSON.parse(readFileSync(historyFile, 'utf8'))
  assert.equal(persisted.schemaVersion, 1)
  assert.equal(persisted.records[0]?.state, 'done')
})

test('unwritable history target does not change the operation result', async t => {
  const historyFile = historyFixture(t)
  const queue = new OperationQueue(path.dirname(historyFile))
  queue.enqueue('repair', 'redteam', async () => 'repaired without history')
  await queue.whenIdle()

  assert.equal(queue.list()[0]?.state, 'done')
  assert.equal(queue.list()[0]?.detail, 'repaired without history')
})

test('only the most recent 50 persisted history records are loaded', t => {
  const historyFile = historyFixture(t)
  writeFileSync(historyFile, `${JSON.stringify({
    schemaVersion: 1,
    records: Array.from({ length: 55 }, (_, index) => ({
      id: `op-${String(index + 1).padStart(4, '0')}`,
      kind: 'repair',
      target: `mode-${index + 1}`,
      state: 'done',
      percent: 100,
    })),
  })}\n`)

  const queue = new OperationQueue(historyFile)
  assert.equal(queue.list().length, 50)
  assert.equal(queue.list()[0]?.id, 'op-0006')
  assert.equal(queue.list()[49]?.id, 'op-0055')
  assert.equal(JSON.parse(readFileSync(historyFile, 'utf8')).records.length, 50)
})

test('queue capacity never exceeds 50 active or persisted records', async t => {
  const historyFile = historyFixture(t)
  let releaseFirst
  const firstGate = new Promise(resolve => {
    releaseFirst = resolve
  })
  const queue = new OperationQueue(historyFile)
  queue.enqueue('install', 'plugin-1', async () => {
    await firstGate
    return 'installed'
  })
  for (let index = 2; index <= 50; index += 1) {
    queue.enqueue('install', `plugin-${index}`, async () => 'installed')
  }

  assert.equal(queue.list().length, 50)
  assert.equal(JSON.parse(readFileSync(historyFile, 'utf8')).records.length, 50)
  assert.throws(
    () => queue.enqueue('install', 'plugin-51', async () => 'installed'),
    /operation queue capacity exceeded/,
  )
  assert.equal(queue.list().length, 50)

  releaseFirst()
  await queue.whenIdle()

  assert.equal(queue.enqueue('install', 'plugin-51', async () => 'installed'), 'op-0051')
  await queue.whenIdle()
  assert.equal(queue.list().length, 50)
  assert.equal(queue.list()[0]?.id, 'op-0002')
  assert.equal(JSON.parse(readFileSync(historyFile, 'utf8')).records.length, 50)
})

test('settling an old disposed writer cannot overwrite a replacement queue', async t => {
  const historyFile = historyFixture(t)
  let releaseFirst
  let markStarted
  const firstGate = new Promise(resolve => {
    releaseFirst = resolve
  })
  const started = new Promise(resolve => {
    markStarted = resolve
  })

  const firstQueue = new OperationQueue(historyFile)
  firstQueue.enqueue('install', 'old-writer', async () => {
    markStarted()
    await firstGate
    return 'old writer finished late'
  })
  await started
  firstQueue.dispose()

  const replacementQueue = new OperationQueue(historyFile)
  assert.equal(replacementQueue.list()[0]?.state, 'failed')
  assert.equal(replacementQueue.enqueue('repair', 'redteam', async () => 'replacement completed'), 'op-0002')
  await replacementQueue.whenIdle()

  releaseFirst()
  await firstQueue.whenIdle()

  const finalQueue = new OperationQueue(historyFile)
  assert.deepEqual(finalQueue.list().map(record => [record.id, record.state, record.detail]), [
    ['op-0001', 'failed', 'interrupted by previous dsh web restart'],
    ['op-0002', 'done', 'replacement completed'],
  ])
})
