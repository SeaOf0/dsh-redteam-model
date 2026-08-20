import test from 'node:test'
import assert from 'node:assert/strict'
import { SERVER_PRESETS } from '../src/client/presets.js'
import { parseMcpJson } from '../src/client/mcp-json.js'

test('presets: ids unique and json parses to staged rows', () => {
  const ids = new Set(SERVER_PRESETS.map(preset => preset.id))
  assert.equal(ids.size, SERVER_PRESETS.length, 'preset ids must be unique')
  for (const preset of SERVER_PRESETS) {
    const parsed = parseMcpJson(preset.json)
    assert.ok(!('error' in parsed), `${preset.id}: ${'error' in parsed ? parsed.error : ''}`)
    assert.equal(parsed.servers.length, 1, `${preset.id} stages exactly one row`)
  }
})

test('presets: chrome-devtools and kali import disabled (manual connect)', () => {
  for (const id of ['chrome-devtools', 'kali']) {
    const preset = SERVER_PRESETS.find(row => row.id === id)
    assert.ok(preset, `preset ${id} exists`)
    const parsed = parseMcpJson(preset.json)
    assert.equal(parsed.servers[0].enabled, false, `${id} must import disabled`)
  }
})

test('presets: kali is streamable-http with placeholder url', () => {
  const preset = SERVER_PRESETS.find(row => row.id === 'kali')
  const parsed = parseMcpJson(preset.json)
  const row = parsed.servers[0]
  assert.equal(row.transport, 'streamable-http')
  assert.match(row.url, /^http:\/\/<kali-ip>:8765\/mcp$/)
})
