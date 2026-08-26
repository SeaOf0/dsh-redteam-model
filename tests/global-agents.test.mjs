import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { deployGlobalAgents } from '../lib/index.js'

const ORIGINAL_HOME = process.env.DSH_HOME

function makeRoot() {
  const root = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-root-'))
  writeFileSync(path.join(root, 'AGENTS.md'), '# package global instructions\nline two\n', 'utf8')
  return root
}

test('deployGlobalAgents installs the packaged file when no global AGENTS.md exists', () => {
  const root = makeRoot()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-home-'))
  process.env.DSH_HOME = home
  try {
    const detail = deployGlobalAgents(root)
    const dst = path.join(home, 'AGENTS.md')
    assert.match(detail, /global instructions installed/)
    assert.ok(existsSync(dst), 'global file created')
    assert.equal(readFileSync(dst, 'utf8'), readFileSync(path.join(root, 'AGENTS.md'), 'utf8'))
  } finally {
    process.env.DSH_HOME = ORIGINAL_HOME
    rmSync(root, { recursive: true, force: true })
    rmSync(home, { recursive: true, force: true })
  }
})

test('deployGlobalAgents never overwrites an existing different global file', () => {
  const root = makeRoot()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-home-'))
  process.env.DSH_HOME = home
  const dst = path.join(home, 'AGENTS.md')
  writeFileSync(dst, '# my own global rules\n', 'utf8')
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /left untouched/)
    assert.match(detail, /copy .* over it manually/)
    assert.equal(readFileSync(dst, 'utf8'), '# my own global rules\n', 'existing content preserved byte-exact')
  } finally {
    process.env.DSH_HOME = ORIGINAL_HOME
    rmSync(root, { recursive: true, force: true })
    rmSync(home, { recursive: true, force: true })
  }
})

test('deployGlobalAgents is a no-op when the global file already matches the package', () => {
  const root = makeRoot()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-home-'))
  process.env.DSH_HOME = home
  const dst = path.join(home, 'AGENTS.md')
  writeFileSync(dst, readFileSync(path.join(root, 'AGENTS.md'), 'utf8'), 'utf8')
  const before = readFileSync(dst, 'utf8')
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /already matches/)
    assert.equal(readFileSync(dst, 'utf8'), before)
  } finally {
    process.env.DSH_HOME = ORIGINAL_HOME
    rmSync(root, { recursive: true, force: true })
    rmSync(home, { recursive: true, force: true })
  }
})

test('deployGlobalAgents skips gracefully when the package ships no AGENTS.md', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-root-'))
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-home-'))
  process.env.DSH_HOME = home
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /skipped/)
    assert.equal(existsSync(path.join(home, 'AGENTS.md')), false, 'nothing created')
  } finally {
    process.env.DSH_HOME = ORIGINAL_HOME
    rmSync(root, { recursive: true, force: true })
    rmSync(home, { recursive: true, force: true })
  }
})
