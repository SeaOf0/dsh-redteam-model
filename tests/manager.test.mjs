import test from 'node:test'
import assert from 'node:assert/strict'
import fs, { cpSync, mkdtempSync, mkdirSync, existsSync, lstatSync, readFileSync, readlinkSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { homedir, tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { deployModes, dshHome, getStatus, installOne, repairMode, scanModes, scanPlugins, uninstallOne } from '../lib/index.js'
import { createManagerFixture } from './helpers/fixture.mjs'

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

test('deployModes copies modes into an existing real .agent-presets directory without touching it', () => {
  const previousHome = process.env.DSH_HOME
  const isolatedHome = mkdtempSync(path.join(tmpdir(), 'dsh-redteam-model-test-'))
  const presetsDir = path.join(isolatedHome, '.agent-presets')
  mkdirSync(presetsDir, { recursive: true })
  mkdirSync(path.join(presetsDir, 'router-standard'))
  process.env.DSH_HOME = isolatedHome
  try {
    const detail = deployModes(repoRoot)
    assert.match(detail, /copied 9 modes/)
    assert.equal(existsSync(path.join(presetsDir, 'router-standard')), true)
    const status = getStatus([], repoRoot)
    assert.equal(status.summary.modesReady, 9)
    const marker = JSON.parse(readFileSync(path.join(presetsDir, '.dsh-redteam-model.json'), 'utf8'))
    assert.equal(marker.schemaVersion, 2)
    assert.equal(marker.owner, '@dsh-external/dsh-redteam-model')
    for (const mode of status.modes) {
      assert.equal(mode.linkState, 'ok')
      const destination = path.join(presetsDir, mode.id)
      assert.equal(lstatSync(destination).isDirectory(), true, `${mode.id} must be a real directory`)
      assert.match(marker.modes[mode.id]?.digest ?? '', /^sha256:[0-9a-f]{64}$/)
    }
  } finally {
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    rmSync(isolatedHome, { recursive: true, force: true })
  }
})

test('deployModes refuses a symlink marker without changing its target', { skip: process.platform === 'win32' }, () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  try {
    const victim = path.join(fixture.home, 'victim.json')
    writeFileSync(victim, '{"keep":true}\n', 'utf8')
    symlinkSync(victim, path.join(fixture.presets, '.dsh-redteam-model.json'))
    assert.throws(() => deployModes(fixture.root), /unsafe mode marker/i)
    assert.equal(readFileSync(victim, 'utf8'), '{"keep":true}\n')
  } finally {
    fixture.cleanup()
  }
})

test('a changed packaged digest makes a copied mode stale and repair refreshes only that mode', () => {
  const fixture = createManagerFixture({ modes: ['redteam', 'pentest'], realPresetsDirectory: true })
  try {
    deployModes(fixture.root)
    fixture.setModeDigest('redteam', 'v2')
    let status = getStatus([], fixture.root)
    assert.equal(status.modes.find(mode => mode.id === 'redteam')?.linkState, 'stale')
    assert.equal(status.modes.find(mode => mode.id === 'pentest')?.linkState, 'ok')
    repairMode('redteam', fixture.root)
    status = getStatus([], fixture.root)
    assert.equal(status.modes.every(mode => mode.linkState === 'ok'), true)
    assert.equal(fixture.backupsFor('redteam').length, 1)
    assert.equal(fixture.backupsFor('pentest').length, 0)
  } finally {
    fixture.cleanup()
  }
})

test('an unchanged repeated deployment is idempotent and creates no backups', () => {
  const fixture = createManagerFixture({ modes: ['redteam', 'pentest'], realPresetsDirectory: true })
  try {
    deployModes(fixture.root)
    const detail = deployModes(fixture.root)
    assert.match(detail, /copied 0 modes/)
    assert.equal(fixture.backupsFor('redteam').length, 0)
    assert.equal(fixture.backupsFor('pentest').length, 0)
  } finally {
    fixture.cleanup()
  }
})

test('a malformed primary marker recovers from the regular backup', () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  try {
    deployModes(fixture.root)
    writeFileSync(path.join(fixture.presets, '.dsh-redteam-model.json'), '{broken', 'utf8')
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'ok')
    deployModes(fixture.root)
    const marker = JSON.parse(readFileSync(path.join(fixture.presets, '.dsh-redteam-model.json'), 'utf8'))
    assert.equal(marker.schemaVersion, 2)
  } finally {
    fixture.cleanup()
  }
})

test('a legacy absolute-source marker is treated as stale and migrated on repair', () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  try {
    deployModes(fixture.root)
    writeFileSync(path.join(fixture.presets, '.dsh-redteam-model.json'), `${JSON.stringify({
      redteam: { source: path.join(fixture.root, 'modes', 'redteam'), deployedAt: 1 },
    })}\n`, 'utf8')
    rmSync(path.join(fixture.presets, '.dsh-redteam-model.backup.json'))
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'stale')
    repairMode('redteam', fixture.root)
    const marker = JSON.parse(readFileSync(path.join(fixture.presets, '.dsh-redteam-model.json'), 'utf8'))
    assert.equal(marker.schemaVersion, 2)
    assert.equal(typeof marker.modes.redteam.digest, 'string')
  } finally {
    fixture.cleanup()
  }
})

test('foreign preset conflicts are preserved and reported', () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  try {
    const foreign = path.join(fixture.presets, 'redteam')
    mkdirSync(foreign)
    writeFileSync(path.join(foreign, 'foreign.txt'), 'keep\n', 'utf8')
    const detail = deployModes(fixture.root)
    assert.match(detail, /skipped existing entries: redteam/)
    assert.equal(readFileSync(path.join(foreign, 'foreign.txt'), 'utf8'), 'keep\n')
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'error')
  } finally {
    fixture.cleanup()
  }
})

test('dshHome handles blank, tilde, relative and absolute values', () => {
  const previous = process.env.DSH_HOME
  try {
    process.env.DSH_HOME = ''
    assert.equal(dshHome(), path.join(homedir(), '.dsh'))
    process.env.DSH_HOME = '   '
    assert.equal(dshHome(), path.join(homedir(), '.dsh'))
    process.env.DSH_HOME = '~/redteam-home'
    assert.equal(dshHome(), path.join(homedir(), 'redteam-home'))
    process.env.DSH_HOME = 'relative-home'
    assert.equal(dshHome(), path.resolve('relative-home'))
    process.env.DSH_HOME = path.resolve('absolute-home')
    assert.equal(dshHome(), path.resolve('absolute-home'))
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
})

test('preset-plane bundle pollution is broken and repair removes every occurrence', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-scanner-tools'] })
  try {
    const pkg = '@dsh-external/dsh-scanner-tools'
    const manifest = JSON.parse(readFileSync(fixture.profilePackage, 'utf8'))
    manifest.dependencies[pkg] = `link:${path.join(fixture.root, 'plugins', 'dsh-scanner-tools')}`
    manifest.dsh.profile.bundles.push(pkg, pkg)
    writeFileSync(fixture.profilePackage, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    const installed = path.join(fixture.profile, 'node_modules', '@dsh-external', 'dsh-scanner-tools')
    mkdirSync(installed, { recursive: true })
    writeFileSync(path.join(installed, 'package.json'), '{"version":"1.0.0"}\n', 'utf8')
    assert.equal(getStatus([], fixture.root).plugins[0]?.installState, 'broken')
    await installOne('dsh-scanner-tools', {}, fixture.root)
    assert.equal(fixture.bundles().includes(pkg), false)
  } finally {
    fixture.cleanup()
  }
})

test('failed install removes a profile and lockfile that did not exist before', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'], profileExists: false, npx: 'generic-failure', mutateLock: true })
  try {
    await assert.rejects(installOne('dsh-hunter', {}, fixture.root), /pnpm install failed/)
    assert.equal(existsSync(fixture.profilePackage), false)
    assert.equal(existsSync(fixture.lockfile), false)
    assert.equal(existsSync(fixture.profile), false)
  } finally {
    fixture.cleanup()
  }
})

test('failed install restores exact package and lockfile bytes', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'], npx: 'generic-failure', mutateLock: true })
  try {
    const packageBefore = readFileSync(fixture.profilePackage)
    const lockBefore = readFileSync(fixture.lockfile)
    await assert.rejects(installOne('dsh-hunter', {}, fixture.root), /pnpm install failed/)
    assert.deepEqual(readFileSync(fixture.profilePackage), packageBefore)
    assert.deepEqual(readFileSync(fixture.lockfile), lockBefore)
  } finally {
    fixture.cleanup()
  }
})

test('release-age recovery requires an existing lockfile and an exact pnpm error code', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'], npx: 'release-age-failure-then-success' })
  try {
    await installOne('dsh-hunter', {}, fixture.root)
    const calls = fixture.npxCalls()
    assert.equal(calls.length, 2)
    assert.equal(calls[1].includes('--config.minimumReleaseAge=0'), true)
  } finally {
    fixture.cleanup()
  }
})

test('plain minimumReleaseAge text does not trigger a safety bypass', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'], npx: 'generic-failure', stderr: 'minimumReleaseAge advice' })
  try {
    await assert.rejects(installOne('dsh-hunter', {}, fixture.root), /minimumReleaseAge advice/)
    assert.equal(fixture.npxCalls().length, 1)
  } finally {
    fixture.cleanup()
  }
})

test('lookalike release-age error codes do not trigger a safety bypass', async () => {
  const fixture = createManagerFixture({
    plugins: ['dsh-hunter'],
    npx: 'generic-failure',
    stderr: 'ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION_FAKE',
  })
  try {
    await assert.rejects(installOne('dsh-hunter', {}, fixture.root), /VIOLATION_FAKE/)
    assert.equal(fixture.npxCalls().length, 1)
  } finally {
    fixture.cleanup()
  }
})

test('prefixed release-age lookalikes do not trigger a safety bypass', async () => {
  const fixture = createManagerFixture({
    plugins: ['dsh-hunter'],
    npx: 'generic-failure',
    stderr: 'fakeERR_PNPM_NO_MATURE_MATCHING_VERSION',
  })
  try {
    await assert.rejects(installOne('dsh-hunter', {}, fixture.root), /fakeERR/)
    assert.equal(fixture.npxCalls().length, 1)
  } finally {
    fixture.cleanup()
  }
})

test('missing presets root keeps the existing whole-directory symlink deployment', () => {
  const fixture = createManagerFixture({ modes: ['redteam'] })
  try {
    const detail = deployModes(fixture.root)
    assert.match(detail, /agent presets link ready/)
    assert.equal(lstatSync(fixture.presets).isSymbolicLink(), true)
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'ok')
  } finally {
    fixture.cleanup()
  }
})

test('deployModes refuses an unsafe backup marker without changing its target', { skip: process.platform === 'win32' }, () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  try {
    deployModes(fixture.root)
    const backup = path.join(fixture.presets, '.dsh-redteam-model.backup.json')
    const victim = path.join(fixture.home, 'backup-victim.json')
    writeFileSync(victim, '{"keep":true}\n', 'utf8')
    rmSync(backup)
    symlinkSync(victim, backup)
    assert.throws(() => deployModes(fixture.root), /unsafe mode marker/i)
    assert.equal(readFileSync(victim, 'utf8'), '{"keep":true}\n')
  } finally {
    fixture.cleanup()
  }
})

test('stable marker ownership survives a changed package root', () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  try {
    deployModes(fixture.root)
    const movedRoot = path.join(fixture.base, 'model-v2')
    cpSync(fixture.root, movedRoot, { recursive: true })
    const digestFile = path.join(movedRoot, 'lib', 'mode-digests.json')
    const digestManifest = JSON.parse(readFileSync(digestFile, 'utf8'))
    digestManifest.modes.redteam = `sha256:${'f'.repeat(64)}`
    writeFileSync(digestFile, `${JSON.stringify(digestManifest, null, 2)}\n`, 'utf8')
    assert.equal(getStatus([], movedRoot).modes[0]?.linkState, 'stale')
    repairMode('redteam', movedRoot)
    assert.equal(getStatus([], movedRoot).modes[0]?.linkState, 'ok')
  } finally {
    fixture.cleanup()
  }
})

test('host-plane repair reduces duplicate bundle entries to exactly one', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'] })
  try {
    const pkg = '@dsh-external/dsh-hunter'
    const manifest = JSON.parse(readFileSync(fixture.profilePackage, 'utf8'))
    manifest.dependencies[pkg] = `link:${path.join(fixture.root, 'plugins', 'dsh-hunter')}`
    manifest.dsh.profile.bundles.push(pkg, pkg)
    writeFileSync(fixture.profilePackage, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    const installed = path.join(fixture.profile, 'node_modules', '@dsh-external', 'dsh-hunter')
    mkdirSync(installed, { recursive: true })
    writeFileSync(path.join(installed, 'package.json'), '{"version":"1.0.0"}\n', 'utf8')
    assert.equal(getStatus([], fixture.root).plugins[0]?.installState, 'broken')
    await installOne('dsh-hunter', {}, fixture.root)
    assert.equal(fixture.bundles().filter(name => name === pkg).length, 1)
  } finally {
    fixture.cleanup()
  }
})

test('uninstall removes every duplicate bundle declaration', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'] })
  try {
    const pkg = '@dsh-external/dsh-hunter'
    const manifest = JSON.parse(readFileSync(fixture.profilePackage, 'utf8'))
    manifest.dependencies[pkg] = `link:${path.join(fixture.root, 'plugins', 'dsh-hunter')}`
    manifest.dsh.profile.bundles.push(pkg, pkg)
    writeFileSync(fixture.profilePackage, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    await uninstallOne('dsh-hunter', {}, fixture.root)
    assert.equal(fixture.bundles().includes(pkg), false)
  } finally {
    fixture.cleanup()
  }
})

test('peer-link failure restores the exact profile and lockfile state', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'] })
  try {
    const packageBefore = readFileSync(fixture.profilePackage)
    const lockBefore = readFileSync(fixture.lockfile)
    const peerRoot = path.join(fixture.root, 'plugins', 'node_modules')
    mkdirSync(peerRoot, { recursive: true })
    writeFileSync(path.join(peerRoot, '@dsh-external'), 'blocks external peer directory\n', 'utf8')
    await assert.rejects(installOne('dsh-hunter', {}, fixture.root))
    assert.deepEqual(readFileSync(fixture.profilePackage), packageBefore)
    assert.deepEqual(readFileSync(fixture.lockfile), lockBefore)
    const deepseek = path.join(peerRoot, '@deepseek-ai')
    assert.deepEqual(existsSync(deepseek) ? readdirSync(deepseek) : [], [])
  } finally {
    fixture.cleanup()
  }
})

test('release-age failure without a pre-existing lockfile does not retry', async () => {
  const fixture = createManagerFixture({ plugins: ['dsh-hunter'], profileExists: false, npx: 'release-age-failure-then-success' })
  try {
    await assert.rejects(installOne('dsh-hunter', {}, fixture.root), /MINIMUM_RELEASE_AGE_VIOLATION/)
    assert.equal(fixture.npxCalls().length, 1)
  } finally {
    fixture.cleanup()
  }
})

test('missing digest metadata fails closed for real-directory deployment', () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  try {
    rmSync(path.join(fixture.root, 'lib', 'mode-digests.json'))
    assert.throws(() => deployModes(fixture.root), /mode digest missing: redteam/)
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'error')
  } finally {
    fixture.cleanup()
  }
})

test('missing digest metadata fails before creating the whole presets link', () => {
  const fixture = createManagerFixture({ modes: ['redteam'] })
  try {
    rmSync(path.join(fixture.root, 'lib', 'mode-digests.json'))
    assert.throws(() => deployModes(fixture.root), /mode digest missing: redteam/)
    assert.equal(existsSync(fixture.presets), false)
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'error')
  } finally {
    fixture.cleanup()
  }
})

test('missing digest metadata fails closed without replacing an existing whole presets link', () => {
  const fixture = createManagerFixture({ modes: ['redteam'] })
  try {
    deployModes(fixture.root)
    const target = readlinkSync(fixture.presets)
    rmSync(path.join(fixture.root, 'lib', 'mode-digests.json'))
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'error')
    assert.throws(() => deployModes(fixture.root), /mode digest missing: redteam/)
    assert.equal(lstatSync(fixture.presets).isSymbolicLink(), true)
    assert.equal(readlinkSync(fixture.presets), target)
  } finally {
    fixture.cleanup()
  }
})

test('a failed final staging rename restores the previous managed copy', () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  const originalRename = fs.renameSync
  try {
    deployModes(fixture.root)
    const destination = path.join(fixture.presets, 'redteam')
    const deployed = path.join(destination, 'content.txt')
    assert.equal(readFileSync(deployed, 'utf8'), 'fixture redteam v1\n')
    writeFileSync(path.join(fixture.root, 'modes', 'redteam', 'content.txt'), 'fixture redteam v2\n', 'utf8')
    fixture.setModeDigest('redteam', 'v2')

    fs.renameSync = (source, target) => {
      if (path.basename(String(source)).startsWith('.redteam.dsh-redteam-model.tmp-') && target === destination) {
        throw new Error('injected final rename failure')
      }
      return originalRename(source, target)
    }
    syncBuiltinESMExports()
    assert.throws(() => repairMode('redteam', fixture.root), /injected final rename failure/)
    assert.equal(readFileSync(deployed, 'utf8'), 'fixture redteam v1\n')
    assert.equal(fixture.backupsFor('redteam').length, 0)
    assert.equal(readdirSync(fixture.presets).some(name => name.includes('.dsh-redteam-model.tmp-')), false)
    assert.equal(getStatus([], fixture.root).modes[0]?.linkState, 'stale')
  } finally {
    fs.renameSync = originalRename
    syncBuiltinESMExports()
    fixture.cleanup()
  }
})

test('a later mode copy failure leaves earlier copied modes owned and retryable', () => {
  const fixture = createManagerFixture({ modes: ['redteam', 'pentest'], realPresetsDirectory: true })
  const originalCopy = fs.cpSync
  try {
    const failingSource = path.join(fixture.root, 'modes', 'pentest')
    fs.cpSync = (source, target, options) => {
      if (source === failingSource) throw new Error('injected second copy failure')
      return originalCopy(source, target, options)
    }
    syncBuiltinESMExports()
    assert.throws(() => deployModes(fixture.root), /injected second copy failure/)
    const partial = getStatus([], fixture.root)
    assert.equal(partial.modes.find(mode => mode.id === 'redteam')?.linkState, 'ok')
    assert.equal(partial.modes.find(mode => mode.id === 'pentest')?.linkState, 'missing')

    fs.cpSync = originalCopy
    syncBuiltinESMExports()
    deployModes(fixture.root)
    assert.equal(getStatus([], fixture.root).modes.every(mode => mode.linkState === 'ok'), true)
    assert.equal(fixture.backupsFor('redteam').length, 0)
  } finally {
    fs.cpSync = originalCopy
    syncBuiltinESMExports()
    fixture.cleanup()
  }
})

test('a marker write failure removes a new copy and restores marker pre-state', () => {
  const fixture = createManagerFixture({ modes: ['redteam'], realPresetsDirectory: true })
  const originalRename = fs.renameSync
  try {
    const primary = path.join(fixture.presets, '.dsh-redteam-model.json')
    const backup = path.join(fixture.presets, '.dsh-redteam-model.backup.json')
    fs.renameSync = (source, target) => {
      if (path.basename(String(source)).startsWith('..dsh-redteam-model.json.tmp-') && target === primary) {
        throw new Error('injected marker rename failure')
      }
      return originalRename(source, target)
    }
    syncBuiltinESMExports()
    assert.throws(() => deployModes(fixture.root), /injected marker rename failure/)
    assert.equal(existsSync(path.join(fixture.presets, 'redteam')), false)
    assert.equal(existsSync(primary), false)
    assert.equal(existsSync(backup), false)
  } finally {
    fs.renameSync = originalRename
    syncBuiltinESMExports()
    fixture.cleanup()
  }
})

test('targeted repair preserves ownership of other legacy-managed modes', () => {
  const fixture = createManagerFixture({ modes: ['redteam', 'pentest'], realPresetsDirectory: true })
  try {
    deployModes(fixture.root)
    writeFileSync(path.join(fixture.presets, '.dsh-redteam-model.json'), `${JSON.stringify({
      redteam: { source: path.join(fixture.root, 'modes', 'redteam'), deployedAt: 1 },
      pentest: { source: path.join(fixture.root, 'modes', 'pentest'), deployedAt: 1 },
    })}\n`, 'utf8')
    rmSync(path.join(fixture.presets, '.dsh-redteam-model.backup.json'))

    repairMode('redteam', fixture.root)
    let status = getStatus([], fixture.root)
    assert.equal(status.modes.find(mode => mode.id === 'redteam')?.linkState, 'ok')
    assert.equal(status.modes.find(mode => mode.id === 'pentest')?.linkState, 'stale')
    assert.equal(fixture.backupsFor('pentest').length, 0)

    repairMode('pentest', fixture.root)
    status = getStatus([], fixture.root)
    assert.equal(status.modes.every(mode => mode.linkState === 'ok'), true)
  } finally {
    fixture.cleanup()
  }
})
