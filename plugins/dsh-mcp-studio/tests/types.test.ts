import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  DEFAULT_TOOL_CALL_TIMEOUT_MS,
  splitArgs,
  toMcpClientConfig,
  validateSection,
  type ServerEntry,
} from '../src/types.ts'

const server = (overrides: Partial<ServerEntry>): ServerEntry => ({
  id: 's1',
  enabled: true,
  name: 'demo',
  transport: 'stdio',
  command: 'npx',
  argsLine: '',
  env: {},
  cwd: '',
  url: '',
  headers: {},
  toolCallTimeoutMs: DEFAULT_TOOL_CALL_TIMEOUT_MS,
  failOnStartupError: false,
  ...overrides,
})

test('splitArgs: whitespace, quotes, escapes', () => {
  assert.deepEqual(splitArgs(''), [])
  assert.deepEqual(splitArgs('a b  c'), ['a', 'b', 'c'])
  assert.deepEqual(splitArgs('-y @scope/pkg "two words"'), ['-y', '@scope/pkg', 'two words'])
  assert.deepEqual(splitArgs("--token='x y' --flag"), ['--token=x y', '--flag'])
  assert.deepEqual(splitArgs(String.raw`--escaped=\"q\" plain`), ['--escaped="q"', 'plain'])
})

test('toMcpClientConfig: stdio and http projections', () => {
  assert.deepEqual(toMcpClientConfig(server({ argsLine: 'x --y' })), {
    serverName: 'demo',
    toolCallTimeoutMs: DEFAULT_TOOL_CALL_TIMEOUT_MS,
    failOnStartupError: false,
    transport: 'stdio',
    command: 'npx',
    args: ['x', '--y'],
    env: {},
    cwd: '',
  })
  assert.deepEqual(toMcpClientConfig(server({ transport: 'streamable-http', url: 'http://x/mcp', headers: { A: 'b' } })), {
    serverName: 'demo',
    toolCallTimeoutMs: DEFAULT_TOOL_CALL_TIMEOUT_MS,
    failOnStartupError: false,
    transport: 'streamable-http',
    url: 'http://x/mcp',
    headers: { A: 'b' },
  })
})

test('validateSection: rejects duplicates and incomplete rows', () => {
  assert.throws(() => validateSection({ servers: [server({}), server({ id: 's2', name: 'demo' })] }), /unique/)
  assert.throws(() => validateSection({ servers: [server({ command: '  ' })] }), /no command/)
  assert.throws(() => validateSection({ servers: [server({ transport: 'streamable-http', url: '' })] }), /no url/)
  assert.throws(() => validateSection({ servers: [server({ transport: 'streamable-http', url: 'ftp://x' })] }), /http or https/)
  assert.throws(() => validateSection({ servers: [server({ name: '' })] }), /no name/)
  // Disabled rows may be incomplete.
  validateSection({ servers: [server({ enabled: false, command: '' })] })
})
