import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { mkdtempSync } from 'node:fs'

const ORIGINAL_PATH = process.env.PATH
const ORIGINAL_HOME = process.env.DSH_HOME

function digestFor(seed) {
  const code = seed.charCodeAt(0).toString(16).padStart(2, '0')
  return `sha256:${code.repeat(32).slice(0, 64)}`
}

function writeJson(file, value) {
  mkdirSync(path.dirname(file), { recursive: true })
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

function fakeNpxSource() {
  return `#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync, writeFileSync, writeSync } from 'node:fs'
import path from 'node:path'
const log = process.env.FAKE_NPX_LOG
if (log) appendFileSync(log, JSON.stringify(process.argv.slice(2)) + '\\n')
const outcome = process.env.FAKE_NPX_OUTCOME || 'success'
if (process.env.FAKE_NPX_MUTATE_LOCK === '1') writeFileSync(path.join(process.cwd(), 'pnpm-lock.yaml'), 'mutated-by-fake\\n')
if (outcome === 'generic-failure') {
  writeSync(2, process.env.FAKE_NPX_STDERR || 'generic install failure')
  process.exit(1)
}
if (outcome === 'release-age-failure-then-success') {
  const countFile = process.env.FAKE_NPX_COUNT
  const count = countFile && existsSync(countFile) ? Number(readFileSync(countFile, 'utf8')) : 0
  if (countFile) writeFileSync(countFile, String(count + 1))
  if (count === 0) {
    writeSync(2, 'ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION locked package')
    process.exit(1)
  }
}
process.exit(0)
`
}

export function createManagerFixture(options = {}) {
  const base = mkdtempSync(path.join(tmpdir(), 'dsh-redteam-manager-test-'))
  const root = path.join(base, 'model')
  const home = path.join(base, 'home')
  const profile = path.join(home, 'profiles', 'web')
  const presets = path.join(home, '.agent-presets')
  const bin = path.join(base, 'bin')
  const npxLog = path.join(base, 'npx-calls.jsonl')
  const npxCount = path.join(base, 'npx-count')
  const modes = options.modes ?? ['redteam']
  const plugins = options.plugins ?? []
  const digests = {}

  mkdirSync(path.join(root, 'lib'), { recursive: true })
  for (const [index, id] of modes.entries()) {
    const directory = path.join(root, 'modes', id)
    mkdirSync(directory, { recursive: true })
    writeFileSync(path.join(directory, 'preset.yml'), `name: ${id}\ndescription: ${id} fixture\norder: ${index + 1}\n`, 'utf8')
    writeFileSync(path.join(directory, 'content.txt'), `fixture ${id} v1\n`, 'utf8')
    digests[id] = digestFor(String.fromCharCode(97 + index))
  }
  writeJson(path.join(root, 'lib', 'mode-digests.json'), { schemaVersion: 1, modes: digests })

  for (const name of plugins) {
    writeJson(path.join(root, 'plugins', name, 'package.json'), {
      name: `@dsh-external/${name}`,
      version: '1.0.0',
      description: `${name} fixture`,
    })
  }

  if (options.realPresetsDirectory === true) mkdirSync(presets, { recursive: true })
  if (options.profileExists !== false) {
    writeJson(path.join(profile, 'package.json'), {
      name: 'dsh-profile-web',
      private: true,
      dependencies: {},
      dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'] } },
    })
    writeFileSync(path.join(profile, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n', 'utf8')
  }

  mkdirSync(bin, { recursive: true })
  const fakeSource = path.join(bin, 'fake-npx.mjs')
  writeFileSync(fakeSource, fakeNpxSource(), 'utf8')
  const unixNpx = path.join(bin, 'npx')
  writeFileSync(unixNpx, fakeNpxSource(), 'utf8')
  chmodSync(unixNpx, 0o755)
  writeFileSync(path.join(bin, 'npx.cmd'), '@echo off\r\nnode "%~dp0fake-npx.mjs" %*\r\n', 'utf8')

  process.env.DSH_HOME = home
  process.env.PATH = `${bin}${path.delimiter}${ORIGINAL_PATH ?? ''}`
  process.env.FAKE_NPX_LOG = npxLog
  process.env.FAKE_NPX_COUNT = npxCount
  process.env.FAKE_NPX_OUTCOME = options.npx ?? 'success'
  if (options.stderr !== undefined) process.env.FAKE_NPX_STDERR = options.stderr
  if (options.mutateLock === true) process.env.FAKE_NPX_MUTATE_LOCK = '1'

  return {
    base,
    root,
    home,
    profile,
    presets,
    profilePackage: path.join(profile, 'package.json'),
    lockfile: path.join(profile, 'pnpm-lock.yaml'),
    setModeDigest(id, digest) {
      digests[id] = digest.startsWith('sha256:') ? digest : digestFor(digest)
      writeJson(path.join(root, 'lib', 'mode-digests.json'), { schemaVersion: 1, modes: digests })
    },
    setBundles(bundles) {
      const manifest = JSON.parse(readFileSync(path.join(profile, 'package.json'), 'utf8'))
      manifest.dsh.profile.bundles = bundles
      writeJson(path.join(profile, 'package.json'), manifest)
    },
    bundles() {
      return JSON.parse(readFileSync(path.join(profile, 'package.json'), 'utf8')).dsh.profile.bundles
    },
    backupsFor(id) {
      if (!existsSync(presets)) return []
      return readdirSync(presets).filter(name => name.startsWith(`${id}.bak-`))
    },
    npxCalls() {
      if (!existsSync(npxLog)) return []
      return readFileSync(npxLog, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
    },
    cleanup() {
      if (ORIGINAL_HOME === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = ORIGINAL_HOME
      if (ORIGINAL_PATH === undefined) delete process.env.PATH
      else process.env.PATH = ORIGINAL_PATH
      for (const name of ['FAKE_NPX_LOG', 'FAKE_NPX_COUNT', 'FAKE_NPX_OUTCOME', 'FAKE_NPX_STDERR', 'FAKE_NPX_MUTATE_LOCK']) {
        delete process.env[name]
      }
      rmSync(base, { recursive: true, force: true })
    },
  }
}
