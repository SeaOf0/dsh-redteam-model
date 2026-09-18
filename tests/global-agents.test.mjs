import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { deployGlobalAgents } from '../lib/index.js'

const ORIGINAL_HOME = process.env.DSH_HOME

// A stand-in for the packaged security-preset instruction document: the retire
// check matches it by its title line plus ecosystem markers, so the fixture
// carries both.
const PACKAGE_DOC = [
  '# Security Testing Collaboration Support Specification',
  '',
  'Workspace support layer referencing dsh-route-boost and dsh-refusal-guard.',
  ''
].join('\n')

function makeRoot(doc = PACKAGE_DOC) {
  const root = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-root-'))
  writeFileSync(path.join(root, 'AGENTS.security.md'), doc, 'utf8')
  return root
}

function makeHome() {
  return mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-home-'))
}

function cleanup(root, home) {
  process.env.DSH_HOME = ORIGINAL_HOME
  rmSync(root, { recursive: true, force: true })
  rmSync(home, { recursive: true, force: true })
}

test('deployGlobalAgents installs AGENTS.security.md when absent', () => {
  const root = makeRoot()
  const home = makeHome()
  process.env.DSH_HOME = home
  try {
    const detail = deployGlobalAgents(root)
    const dst = path.join(home, 'AGENTS.security.md')
    assert.match(detail, /security-preset instructions installed/)
    assert.ok(existsSync(dst), 'namespaced file created')
    assert.equal(readFileSync(dst, 'utf8'), PACKAGE_DOC)
    assert.equal(existsSync(path.join(home, 'AGENTS.md')), false, 'host user-global layer untouched')
  } finally {
    cleanup(root, home)
  }
})

test('deployGlobalAgents is a no-op when the namespaced file already matches', () => {
  const root = makeRoot()
  const home = makeHome()
  process.env.DSH_HOME = home
  writeFileSync(path.join(home, 'AGENTS.security.md'), PACKAGE_DOC, 'utf8')
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /already match/)
    assert.equal(readFileSync(path.join(home, 'AGENTS.security.md'), 'utf8'), PACKAGE_DOC)
  } finally {
    cleanup(root, home)
  }
})

test('deployGlobalAgents refreshes a stale namespaced copy (package-owned namespace)', () => {
  const root = makeRoot()
  const home = makeHome()
  process.env.DSH_HOME = home
  writeFileSync(path.join(home, 'AGENTS.security.md'), '# older release content\n', 'utf8')
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /security-preset instructions updated/)
    assert.equal(readFileSync(path.join(home, 'AGENTS.security.md'), 'utf8'), PACKAGE_DOC)
  } finally {
    cleanup(root, home)
  }
})

test('deployGlobalAgents retires a legacy user-global AGENTS.md deployed by an earlier release', () => {
  const root = makeRoot()
  const home = makeHome()
  process.env.DSH_HOME = home
  const legacy = path.join(home, 'AGENTS.md')
  const legacyBody = PACKAGE_DOC.replace('referencing', 'older release referencing')
  writeFileSync(legacy, legacyBody, 'utf8')
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /retired/)
    assert.equal(existsSync(legacy), false, 'legacy user-global file no longer active')
    const backup = path.join(home, 'AGENTS.md.bak-dsh-redteam-model')
    assert.ok(existsSync(backup), 'legacy content preserved in a recoverable backup')
    assert.equal(readFileSync(backup, 'utf8'), legacyBody)
    assert.ok(existsSync(path.join(home, 'AGENTS.security.md')), 'namespaced file installed')
  } finally {
    cleanup(root, home)
  }
})

test('deployGlobalAgents keeps timestamped backups when a previous backup already exists', () => {
  const root = makeRoot()
  const home = makeHome()
  process.env.DSH_HOME = home
  writeFileSync(path.join(home, 'AGENTS.md'), PACKAGE_DOC, 'utf8')
  writeFileSync(path.join(home, 'AGENTS.md.bak-dsh-redteam-model'), 'earlier backup\n', 'utf8')
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /retired/)
    const baks = readdirSync(home).filter((name) => name.startsWith('AGENTS.md.bak-'))
    assert.equal(baks.length, 2, 'earlier backup kept, new backup added')
  } finally {
    cleanup(root, home)
  }
})

test('deployGlobalAgents never touches a user-owned global AGENTS.md', () => {
  const root = makeRoot()
  const home = makeHome()
  process.env.DSH_HOME = home
  const legacy = path.join(home, 'AGENTS.md')
  writeFileSync(legacy, '# my own global rules\nnothing matching the package markers\n', 'utf8')
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /not from this package/)
    assert.equal(readFileSync(legacy, 'utf8'), '# my own global rules\nnothing matching the package markers\n', 'user content preserved byte-exact')
    assert.ok(existsSync(path.join(home, 'AGENTS.security.md')), 'namespaced file still installed')
  } finally {
    cleanup(root, home)
  }
})

test('deployGlobalAgents skips gracefully when the package ships no AGENTS.security.md', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dsh-rtm-agents-root-'))
  const home = makeHome()
  process.env.DSH_HOME = home
  try {
    const detail = deployGlobalAgents(root)
    assert.match(detail, /skipped/)
    assert.equal(existsSync(path.join(home, 'AGENTS.security.md')), false, 'nothing created')
    assert.equal(existsSync(path.join(home, 'AGENTS.md')), false, 'user-global layer untouched')
  } finally {
    cleanup(root, home)
  }
})
