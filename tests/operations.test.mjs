import test from 'node:test'
import assert from 'node:assert/strict'
import { OperationQueue } from '../lib/index.js'

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
