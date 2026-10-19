import { test } from 'node:test'
import assert from 'node:assert/strict'

import { StudioScope } from '../src/client/studio-scope.ts'

const originalFetch = globalThis.fetch

function envelope(rpcId: string, result: unknown): Response {
  return new Response(JSON.stringify({ type: 'server-response', rpcId, result }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

test('studio scope reads settings through the modern /api fetch route', async (t) => {
  t.after(() => { globalThis.fetch = originalFetch })
  const legacyCalls: unknown[] = []
  let request: { url: string; init: RequestInit | undefined } | undefined

  globalThis.fetch = async (input, init) => {
    request = { url: String(input), init }
    const body: unknown = JSON.parse(String(init?.body))
    assert.ok(typeof body === 'object' && body !== null && 'rpcId' in body && typeof body.rpcId === 'string')
    return envelope(body.rpcId, {
      ok: true,
      value: { status: 'ready', value: { servers: [{ id: 'one' }] }, revision: 4, writable: true },
    })
  }

  const scope = new StudioScope({
    rpc: {
      call: async (...args: unknown[]) => {
        legacyCalls.push(args)
        return { ok: false, error: { message: 'unexpected legacy call' } }
      },
    },
  })
  await scope.ready

  assert.equal(request?.url, '/api/dsh-mcp-studio/settings/get')
  assert.equal(request?.init?.method, 'POST')
  assert.equal(request?.init?.credentials, 'include')
  assert.deepEqual(legacyCalls, [])
  assert.equal(scope.getSnapshot().status, 'ready')
  const value = scope.getSnapshot().value
  assert.ok(typeof value === 'object' && value !== null && 'servers' in value)
  assert.deepEqual(value.servers, [{ id: 'one' }])
})

test('studio scope falls back once to the legacy channel when /api is absent', async (t) => {
  t.after(() => { globalThis.fetch = originalFetch })
  const legacyCalls: Array<{ channel: string; endpoint: string }> = []
  let fetchCalls = 0

  globalThis.fetch = async () => {
    fetchCalls += 1
    return new Response('not found', { status: 404 })
  }

  const scope = new StudioScope({
    rpc: {
      call: async (channel: string, endpoint: string) => {
        legacyCalls.push({ channel, endpoint })
        return endpoint === 'status'
          ? { ok: true, value: { servers: [], summary: { total: 0, enabled: 0, connected: 0, tools: 0 } } }
          : { ok: true, value: { status: 'ready', value: { servers: [] }, revision: 1, writable: true } }
      },
    },
  })
  await scope.ready

  assert.equal(scope.getSnapshot().status, 'ready')
  assert.deepEqual(legacyCalls, [{ channel: '/dsh-mcp-studio', endpoint: 'settings/get' }])

  const status = await scope.status()
  assert.equal('error' in status, false)
  assert.deepEqual(legacyCalls, [
    { channel: '/dsh-mcp-studio', endpoint: 'settings/get' },
    { channel: '/dsh-mcp-studio', endpoint: 'status' },
  ])
  assert.equal(fetchCalls, 1, 'the legacy decision must stick')
})

test('studio scope writes settings through the modern /api fetch route', async (t) => {
  t.after(() => { globalThis.fetch = originalFetch })
  const requests: Array<{ url: string; body: unknown }> = []

  globalThis.fetch = async (input, init) => {
    const body: unknown = JSON.parse(String(init?.body))
    assert.ok(typeof body === 'object' && body !== null && 'rpcId' in body && typeof body.rpcId === 'string')
    requests.push({ url: String(input), body })
    const revision = String(input).endsWith('/settings/mutate') ? 5 : 4
    return envelope(body.rpcId, {
      ok: true,
      value: { status: 'ready', value: { servers: [{ id: 'saved' }] }, revision, writable: true },
    })
  }

  const scope = new StudioScope({
    rpc: {
      call: async () => {
        throw new Error('unexpected legacy call')
      },
    },
  })
  await scope.ready
  await scope.set('servers', [{ id: 'saved' }])

  assert.deepEqual(requests.map(request => request.url), [
    '/api/dsh-mcp-studio/settings/get',
    '/api/dsh-mcp-studio/settings/mutate',
  ])
  const mutate = requests[1]?.body
  assert.ok(typeof mutate === 'object' && mutate !== null && 'payload' in mutate)
  const payload = mutate.payload
  assert.ok(typeof payload === 'object' && payload !== null && 'ops' in payload && 'expectedRevision' in payload)
  assert.deepEqual(payload.ops, [{ op: 'set', path: ['servers'], value: [{ id: 'saved' }] }])
  assert.equal(payload.expectedRevision, 4)
  assert.equal(scope.getSnapshot().revision, 5)
})

test('studio scope keeps the /api channel after a server error', async (t) => {
  t.after(() => { globalThis.fetch = originalFetch })
  let legacyCalls = 0

  globalThis.fetch = async () => new Response('boom', { status: 500 })

  const scope = new StudioScope({
    rpc: {
      call: async () => {
        legacyCalls += 1
        return { ok: true, value: {} }
      },
    },
  })
  await scope.ready

  assert.equal(scope.getSnapshot().status, 'unavailable')
  assert.equal(legacyCalls, 0)
  const status = await scope.status()
  assert.deepEqual(status, { error: 'transport failure for /api/dsh-mcp-studio/status: HTTP 500' })
})

test('studio scope reports unavailable when no transport answers', async (t) => {
  t.after(() => { globalThis.fetch = originalFetch })
  globalThis.fetch = async () => new Response('not found', { status: 404 })

  const scope = new StudioScope({
    rpc: {
      call: async () => { throw new Error('legacy channel unavailable') },
    },
  })
  await scope.ready

  assert.equal(scope.getSnapshot().status, 'unavailable')
  const status = await scope.status()
  assert.deepEqual(status, { error: 'legacy channel unavailable' })
})
