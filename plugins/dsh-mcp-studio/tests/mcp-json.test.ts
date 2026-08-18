import { test } from 'node:test'
import assert from 'node:assert/strict'

import { MCP_JSON_TEMPLATE, argsToLine, formatMcpJson, lineToArgs, parseMcpJson, serversToMcpJson } from '../src/client/mcp-json.ts'

test('mcp-json: Claude Desktop mcpServers format', () => {
  const result = parseMcpJson(JSON.stringify({
    mcpServers: {
      github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_TOKEN: 'x' }, cwd: '/tmp' },
    },
  }))
  assert.ok(!('error' in result))
  const server = result.servers[0]!
  assert.equal(server.name, 'github')
  assert.equal(server.transport, 'stdio')
  assert.equal(server.argsLine, '-y @modelcontextprotocol/server-github')
  assert.deepEqual(server.env, [{ key: 'GITHUB_TOKEN', value: 'x' }])
})

test('mcp-json: VS Code servers format with http type', () => {
  const result = parseMcpJson(JSON.stringify({
    servers: {
      remote: { type: 'http', url: 'http://localhost:3000/mcp', headers: { Authorization: 'Bearer t' } },
    },
    inputs: [{ type: 'prompt' }],
  }))
  assert.ok(!('error' in result))
  assert.equal(result.servers[0]!.transport, 'streamable-http')
  assert.deepEqual(result.servers[0]!.headers, [{ key: 'Authorization', value: 'Bearer t' }])
})

test('mcp-json: bare map and single object paste', () => {
  const bare = parseMcpJson('{"a": {"command": "node"}, "b": {"url": "https://x/mcp"}}')
  assert.ok(!('error' in bare))
  assert.equal(bare.servers.length, 2)
  const single = parseMcpJson('{"type":"stdio","command":"uvx","args":["mcp-server-fetch"]}')
  assert.ok(!('error' in single))
  assert.equal(single.servers[0]!.command, 'uvx')
})

test('mcp-json: metadata keys, disabled flag, and wrapper descent', () => {
  const result = parseMcpJson(JSON.stringify({
    mcpServers: { off: { command: 'x', disabled: true, autoApprove: ['t'] } },
    inputs: [], _meta: { x: 1 },
  }))
  assert.ok(!('error' in result))
  assert.equal(result.servers[0]!.enabled, false)
  const wrapped = parseMcpJson('{"config":{"mcpServers":{"deep":{"url":"https://x/mcp"}}}}')
  assert.ok(!('error' in wrapped))
  assert.equal(wrapped.servers[0]!.name, 'deep')
})

test('mcp-json: error paths and name dedup', () => {
  assert.ok('error' in parseMcpJson(''))
  assert.ok('error' in parseMcpJson('not json'))
  assert.ok('error' in parseMcpJson('{"foo": "bar"}'))
  const dup = parseMcpJson('{"a": {"command": "x"}, "a ": {"command": "y"}}', ['a'])
  assert.ok(!('error' in dup))
  const names = dup.servers.map(server => server.name)
  assert.equal(new Set(names).size, names.length)
  assert.equal(argsToLine(['two words', 'plain']), '"two words" plain')
})

test('mcp-json: format, template, and export round-trip', () => {
  const formatted = formatMcpJson('{"mcpServers":{"a":{"command":"x"}}}')
  assert.ok(!('error' in formatted))
  assert.equal((formatted as { text: string }).text, '{\n  "mcpServers": {\n    "a": {\n      "command": "x"\n    }\n  }\n}\n')
  assert.ok('error' in formatMcpJson('nope'))
  assert.match(MCP_JSON_TEMPLATE, /"mcpServers"/)

  const exported = serversToMcpJson([{
    name: 'demo', transport: 'stdio', command: 'npx', argsLine: '-y pkg "two words"',
    env: [{ key: 'T', value: '1' }], cwd: '', url: '', headers: [],
  }])
  const back = parseMcpJson(exported)
  assert.ok(!('error' in back), 'error' in back ? back.error : '')
  const server = back.servers[0]!
  assert.equal(server.name, 'demo')
  assert.equal(server.command, 'npx')
  assert.equal(server.argsLine, '-y pkg "two words"')
  assert.deepEqual(server.env, [{ key: 'T', value: '1' }])

  const httpExported = serversToMcpJson([{
    name: 'r', transport: 'streamable-http', command: '', argsLine: '', env: [], cwd: '',
    url: 'http://x/mcp', headers: [{ key: 'Authorization', value: 'Bearer t' }],
  }])
  const backHttp = parseMcpJson(httpExported)
  assert.ok(!('error' in backHttp))
  assert.equal(backHttp.servers[0]!.transport, 'streamable-http')
  assert.deepEqual(backHttp.servers[0]!.headers, [{ key: 'Authorization', value: 'Bearer t' }])
})

test('mcp-json: lineToArgs quoting inverse', () => {
  assert.deepEqual(lineToArgs('-y pkg "two words"'), ['-y', 'pkg', 'two words'])
  assert.deepEqual(lineToArgs(''), [])
})
