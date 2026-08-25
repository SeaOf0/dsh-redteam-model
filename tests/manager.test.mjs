import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { getStatus, scanModes, scanPlugins } from '../lib/index.js'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

test('scanPlugins discovers all 15 sub-plugins with correct planes', () => {
  const plugins = scanPlugins(repoRoot)
  assert.equal(plugins.length, 15)
  assert.equal(plugins.filter(plugin => plugin.mountPlane === 'preset').map(plugin => plugin.name).sort().join(','), 'dsh-scanner-tools,dsh-semgrep-audit')
  for (const plugin of plugins) {
    assert.match(plugin.name, /^dsh-[a-z0-9-]+$/)
    assert.notEqual(plugin.version, '0.0.0')
  }
})

test('scanModes discovers the nine security modes', () => {
  const modes = scanModes(repoRoot)
  assert.equal(modes.length, 9)
  const ids = new Set(modes.map(mode => mode.id))
  for (const expected of ['redteam', 'pentest', 'code-audit', 'binary-analysis', 'attack-defense', 'av-evasion', 'incident-response', 'cloud-security', 'ctf-solver']) {
    assert.equal(ids.has(expected), true, `missing mode: ${expected}`)
  }
})

test('getStatus reports an untouched profile as all not-installed without profileError', () => {
  const previousHome = process.env.DSH_HOME
  const isolatedHome = mkdtempSync(path.join(tmpdir(), 'dsh-redteam-model-test-'))
  process.env.DSH_HOME = isolatedHome
  try {
    const status = getStatus([], repoRoot)
    assert.equal(status.summary.modesTotal, 9)
    assert.equal(status.summary.pluginsTotal, 15)
    assert.equal(status.summary.pluginsInstalled, 0)
    assert.equal(status.summary.profileError, undefined)
    assert.equal(status.plugins.every(plugin => plugin.installState === 'not-installed'), true)
  } finally {
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    rmSync(isolatedHome, { recursive: true, force: true })
  }
})
