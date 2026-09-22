import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import test from 'node:test'

import {
  ENGINE_PACKAGES,
  NORMALIZER_VERSION,
  rewriteCompositionText,
} from '../lib/index.js'
import { deployModes, detectEngineFlavor, normalizePresetComposition } from '../lib/index.js'
import { createManagerFixture } from './helpers/fixture.mjs'

const SAMPLE = [
  'entries:',
  '    - id: tool-workflow',
  "      name: '@deepseek-ai/dsh-tool-workflow'",
  '',
  '    # 工作流执行引擎行：源树默认按新宿主声明；部署副本由安装器按运行宿主',
  '    # 实际提供的引擎包改写（新宿主 dsh-workflow-ptc / 旧宿主 dsh-workflow-worker-thread，config 兼容）。',
  '    - id: workflow-ptc',
  "      name: '@deepseek-ai/dsh-workflow-ptc'",
  '      config:',
  '        provider: spawn',
  '',
  '    - id: tool-scanner',
  "      name: '@dsh-external/dsh-scanner-tools'",
  '',
  '    - id: tool-keepme',
  "      name: '@deepseek-ai/dsh-tool-keepme'",
  ''].join('\n')

test('rewriteCompositionText swaps the engine row to the detected flavor', () => {
  const result = rewriteCompositionText(SAMPLE, {
    engine: ENGINE_PACKAGES.worker,
    entries: {},
  })
  assert.equal(result.changed, true)
  assert.match(result.text, /- id: workflow-worker-thread/)
  assert.match(result.text, /name: '@deepseek-ai\/dsh-workflow-worker-thread'/)
  assert.doesNotMatch(result.text, /- id: workflow-ptc/)
  assert.match(result.notes.join('\n'), /engine row rewritten/)
  // The engine config block below the row is untouched.
  assert.match(result.text, /provider: spawn/)
})

test('rewriteCompositionText is idempotent', () => {
  const once = rewriteCompositionText(SAMPLE, { engine: ENGINE_PACKAGES.ptc, entries: {} })
  const twice = rewriteCompositionText(once.text, { engine: ENGINE_PACKAGES.ptc, entries: {} })
  assert.equal(twice.changed, false)
  assert.equal(twice.text, once.text)
})

test('rewriteCompositionText turns known @dsh-external rows into file: rows', () => {
  const result = rewriteCompositionText(SAMPLE, {
    entries: { 'dsh-scanner-tools': 'file:///opt/profile/node_modules/@dsh-external/dsh-scanner-tools/lib/index.js' },
  })
  assert.match(result.text, /name: 'file:\/\/\/opt\/profile\/node_modules\/@dsh-external\/dsh-scanner-tools\/lib\/index\.js'/)
  assert.match(result.notes.join('\n'), /dsh-scanner-tools rewritten to file: row/)
})

test('rewriteCompositionText leaves unknown @dsh-external rows and other rows alone', () => {
  const result = rewriteCompositionText(SAMPLE, { entries: {} })
  // No engine decision and no entry for the external row: nothing changes,
  // but the unresolved package is reported so the deploy log stays honest.
  assert.equal(result.changed, false)
  assert.match(result.text, /name: '@dsh-external\/dsh-scanner-tools'/)
  assert.match(result.notes.join('\n'), /dsh-scanner-tools not present/)
  assert.match(result.text, /name: '@deepseek-ai\/dsh-tool-keepme'/)
})

test('rewriteCompositionText with no decisions at all changes nothing', () => {
  const result = rewriteCompositionText(SAMPLE, {})
  assert.equal(result.changed, false)
  assert.equal(result.text, SAMPLE)
})

test('detectEngineFlavor probes bases in order', () => {
  // No base here names an engine package, so detection stays undefined.
  assert.equal(detectEngineFlavor(['/definitely/not/anywhere']), undefined)
})

test('deployModesIntoDirectory rewrites deployed copies and keeps the source untouched', () => {
  const fixture = createManagerFixture({ modes: ['probe-mode'], realPresetsDirectory: true })
  try {
    const modeDir = `${fixture.root}/modes/probe-mode`
    writeFileSync(`${modeDir}/agent.cordis.yml`, SAMPLE, 'utf8')
    const fakePluginDir = `${fixture.profile}/node_modules/@dsh-external/dsh-scanner-tools`
    mkdirSync(`${fakePluginDir}/lib`, { recursive: true })
    writeFileSync(`${fakePluginDir}/package.json`, '{"name":"@dsh-external/dsh-scanner-tools","main":"lib/index.js"}' + '\n', 'utf8')
    writeFileSync(`${fakePluginDir}/lib/index.js`, 'export default {}\n', 'utf8')

    deployModes(fixture.root)
    const deployed = readFileSync(`${fixture.presets}/probe-mode/agent.cordis.yml`, 'utf8')
    assert.match(deployed, /name: 'file:\/\/.*@dsh-external\/dsh-scanner-tools\/lib\/index\.js'/)
    assert.equal(readFileSync(`${modeDir}/agent.cordis.yml`, 'utf8'), SAMPLE)

    // Re-running deploy with the current normaliser keeps the copy byte-stable.
    const before = readFileSync(`${fixture.presets}/probe-mode/agent.cordis.yml`, 'utf8')
    deployModes(fixture.root)
    assert.equal(readFileSync(`${fixture.presets}/probe-mode/agent.cordis.yml`, 'utf8'), before)
  } finally {
    fixture.cleanup()
  }
})

test('normalizePresetComposition tolerates a mode without agent.cordis.yml', () => {
  const fixture = createManagerFixture({ modes: ['bare-mode'] })
  try {
    const result = normalizePresetComposition(`${fixture.root}/modes/bare-mode`)
    assert.equal(result.changed, false)
    assert.equal(existsSync(`${fixture.root}/modes/bare-mode/agent.cordis.yml`), false)
  } finally {
    fixture.cleanup()
  }
})

test('marker replay: an old-normaliser copy is re-deployed even with a matching digest', () => {
  const fixture = createManagerFixture({ modes: ['replay-mode'], realPresetsDirectory: true })
  try {
    const modeDir = `${fixture.root}/modes/replay-mode`
    writeFileSync(`${modeDir}/agent.cordis.yml`, SAMPLE, 'utf8')
    const fakePluginDir = `${fixture.profile}/node_modules/@dsh-external/dsh-scanner-tools`
    mkdirSync(`${fakePluginDir}/lib`, { recursive: true })
    writeFileSync(`${fakePluginDir}/package.json`, '{"name":"@dsh-external/dsh-scanner-tools","main":"lib/index.js"}' + '\n', 'utf8')
    writeFileSync(`${fakePluginDir}/lib/index.js`, 'export default {}\n', 'utf8')
    deployModes(fixture.root)
    const first = readFileSync(`${fixture.presets}/replay-mode/agent.cordis.yml`, 'utf8')

    // Simulate a copy deployed by an older normaliser revision: same digest,
    // stale rows, marker missing the revision field.
    writeFileSync(`${fixture.presets}/replay-mode/agent.cordis.yml`, SAMPLE, 'utf8')
    const markerFile = `${fixture.presets}/.dsh-redteam-model.json`
    const marker = JSON.parse(readFileSync(markerFile, 'utf8'))
    delete marker.normalizer
    writeFileSync(markerFile, `${JSON.stringify(marker, null, 2)}\n`, 'utf8')

    deployModes(fixture.root)
    assert.notEqual(readFileSync(`${fixture.presets}/replay-mode/agent.cordis.yml`, 'utf8'), SAMPLE)
    assert.equal(readFileSync(`${fixture.presets}/replay-mode/agent.cordis.yml`, 'utf8'), first)
    const replayed = JSON.parse(readFileSync(markerFile, 'utf8'))
    assert.equal(replayed.normalizer, NORMALIZER_VERSION)
  } finally {
    fixture.cleanup()
  }
})

test('deployModes rewrites @dsh-external rows from the packaged plugins, not the profile links', () => {
  // The install path returns before pnpm has created the profile's
  // @dsh-external links, so a deploy that only read the profile tree left
  // every row bare — unresolvable on a packaged desktop host. The dependency
  // row exists by then, and the collection's own plugins/ tree with it.
  const fixture = createManagerFixture({ modes: ['race-mode'], plugins: ['dsh-scanner-tools'], realPresetsDirectory: true })
  try {
    const modeDir = `${fixture.root}/modes/race-mode`
    writeFileSync(`${modeDir}/agent.cordis.yml`, SAMPLE, 'utf8')
    mkdirSync(`${fixture.root}/plugins/dsh-scanner-tools/lib`, { recursive: true })
    writeFileSync(`${fixture.root}/plugins/dsh-scanner-tools/lib/index.js`, 'export default {}\n', 'utf8')
    const manifest = JSON.parse(readFileSync(fixture.profilePackage, 'utf8'))
    manifest.dependencies['@dsh-external/dsh-scanner-tools'] = `link:${fixture.root}/plugins/dsh-scanner-tools`
    writeFileSync(fixture.profilePackage, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    assert.equal(existsSync(`${fixture.profile}/node_modules/@dsh-external`), false)

    deployModes(fixture.root)
    const deployed = readFileSync(`${fixture.presets}/race-mode/agent.cordis.yml`, 'utf8')
    assert.match(deployed, /name: 'file:\/\/.*\/plugins\/dsh-scanner-tools\/lib\/index\.js'/)
    assert.doesNotMatch(deployed, /name: '@dsh-external\/dsh-scanner-tools'/)
  } finally {
    fixture.cleanup()
  }
})

test('a copy left with bare rows is re-normalised even when digest and normaliser match', () => {
  const fixture = createManagerFixture({ modes: ['reheal-mode'], plugins: ['dsh-scanner-tools'], realPresetsDirectory: true })
  try {
    const modeDir = `${fixture.root}/modes/reheal-mode`
    writeFileSync(`${modeDir}/agent.cordis.yml`, SAMPLE, 'utf8')
    mkdirSync(`${fixture.root}/plugins/dsh-scanner-tools/lib`, { recursive: true })
    writeFileSync(`${fixture.root}/plugins/dsh-scanner-tools/lib/index.js`, 'export default {}\n', 'utf8')
    const manifest = JSON.parse(readFileSync(fixture.profilePackage, 'utf8'))
    manifest.dependencies['@dsh-external/dsh-scanner-tools'] = `link:${fixture.root}/plugins/dsh-scanner-tools`
    writeFileSync(fixture.profilePackage, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    deployModes(fixture.root)
    const markerFile = `${fixture.presets}/.dsh-redteam-model.json`
    assert.equal(JSON.parse(readFileSync(markerFile, 'utf8')).normalizer, NORMALIZER_VERSION)

    // A copy the digest still matches but the normaliser would change: the row
    // is bare again (what a pre-link deploy wrote) with the revision current.
    const healed = readFileSync(`${fixture.presets}/reheal-mode/agent.cordis.yml`, 'utf8')
    writeFileSync(`${fixture.presets}/reheal-mode/agent.cordis.yml`, SAMPLE, 'utf8')
    deployModes(fixture.root)

    const redeployed = readFileSync(`${fixture.presets}/reheal-mode/agent.cordis.yml`, 'utf8')
    assert.equal(redeployed, healed)
    assert.doesNotMatch(redeployed, /name: '@dsh-external\/dsh-scanner-tools'/)
  } finally {
    fixture.cleanup()
  }
})
