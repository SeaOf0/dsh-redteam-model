/**
 * Installation engine for the dsh-redteam-model management host.
 *
 * This module is intentionally runtime-free: it depends only on Node built-ins
 * and on the types in `types.ts`, so the same code can be unit-tested without a
 * DSH host. Every mutating file operation is preceded by a timestamped backup;
 * no operation deletes user data.
 */

import { spawn } from 'node:child_process'
import {
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  renameSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  AdminStatus,
  ModeStatus,
  OperationRecord,
  PluginStatus,
} from './types.ts'

const IS_WIN = process.platform === 'win32'
const MIN_PROFILE = {
  name: 'dsh-profile-web',
  private: true,
  dependencies: {},
  dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'] } },
}

export interface PluginDescriptor {
  readonly name: string
  readonly title: string
  readonly description: string
  readonly version: string
  readonly mountPlane: 'host' | 'preset'
  readonly dir: string
}

export interface ModeDescriptor {
  readonly id: string
  readonly name: string
  readonly summary: string
  readonly dir: string
  readonly digest?: string
  readonly order?: number
}

interface ProfilePackage {
  dependencies?: Record<string, string>
  dsh?: { profile?: { bundles?: string[] } }
}

export type ProgressCallback = (phase: string, percent?: number) => void
export interface InstallOptions {
  readonly onProgress?: ProgressCallback
}

interface SpawnResult {
  readonly code: number | null
  readonly stdout: string
  readonly stderr: string
}

/** Locate the model package root from this module's own location. */
export function locateRoot(): string {
  return path.dirname(path.dirname(fileURLToPath(import.meta.url)))
}

export function dshHome(): string {
  const configured = process.env.DSH_HOME?.trim()
  if (configured === undefined || configured === '') return path.join(homedir(), '.dsh')
  if (configured === '~') return homedir()
  if (configured.startsWith('~/') || configured.startsWith('~\\')) {
    return path.resolve(homedir(), configured.slice(2))
  }
  return path.resolve(configured)
}

/** The profile this host process actually booted (`--profile <name>`), default web. */
export function activeProfile(): string {
  const argv = process.argv
  const flag = argv.indexOf('--profile')
  const next = flag !== -1 ? argv[flag + 1] : undefined
  if (next !== undefined && !next.startsWith('-')) {
    return next
  }
  return 'web'
}

export function profileWebDir(): string {
  return path.join(dshHome(), 'profiles', activeProfile())
}

export function profilePackageFile(): string {
  return path.join(profileWebDir(), 'package.json')
}

export function presetsLinkPath(): string {
  return path.join(dshHome(), '.agent-presets')
}

function existsAny(target: string): boolean {
  try {
    lstatSync(target)
    return true
  } catch {
    return false
  }
}

function titleFromDir(name: string): string {
  const base = name.replace(/^dsh-/, '')
  return base
    .split('-')
    .filter(part => part !== '')
    .map(part => part.length <= 3 ? part.toUpperCase() : part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

/** Scan each <root>/plugins subdirectory's package.json. Returns descriptors sorted by name. */
export function scanPlugins(root = locateRoot()): PluginDescriptor[] {
  const pluginsRoot = path.join(root, 'plugins')
  if (!existsSync(pluginsRoot)) return []
  const names = readdirSync(pluginsRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .filter(name => existsSync(path.join(pluginsRoot, name, 'package.json')))
    .sort()
  return names.map((name) => {
    const dir = path.join(pluginsRoot, name)
    const raw = readJsonFile(path.join(dir, 'package.json')) as Record<string, unknown> | null
    const pkg = raw ?? {}
    const mountPlane = name === 'dsh-scanner-tools' || name === 'dsh-semgrep-audit' ? 'preset' : 'host'
    return {
      name,
      title: titleFromDir(name),
      description: typeof pkg.description === 'string' ? pkg.description : '',
      version: typeof pkg.version === 'string' ? pkg.version : '0.0.0',
      mountPlane,
      dir,
    }
  })
}

/** Scan <root>/modes/*. Modes are plain directories with preset.yml. */
export function scanModes(root = locateRoot()): ModeDescriptor[] {
  const modesRoot = path.join(root, 'modes')
  if (!existsSync(modesRoot)) return []
  const digests = readModeDigests(root)
  const ids = readdirSync(modesRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .filter(id => existsSync(path.join(modesRoot, id, 'preset.yml')))
  const modes = ids.map((id): ModeDescriptor | null => {
    const dir = path.join(modesRoot, id)
    const text = readFileSync(path.join(dir, 'preset.yml'), 'utf8')
    const name = /^name:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? id
    const summary = /^description:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? ''
    const orderRaw = /^order:\s*(\d+)$/m.exec(text)?.[1]
    const order = orderRaw === undefined ? undefined : Number(orderRaw)
    const digest = digests[id]
    return { id, name, summary, dir, ...(digest === undefined ? {} : { digest }), ...(order === undefined ? {} : { order }) }
  }).filter((mode): mode is ModeDescriptor => mode !== null)
  return modes.sort((left, right) => {
    const lo = left.order ?? 99
    const ro = right.order ?? 99
    if (lo !== ro) return lo - ro
    return left.id.localeCompare(right.id)
  })
}

function readModeDigests(root: string): Record<string, string> {
  const raw = readJsonFile(path.join(root, 'lib', 'mode-digests.json'))
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return {}
  const manifest = raw as { schemaVersion?: unknown; modes?: unknown }
  if (manifest.schemaVersion !== 1 || typeof manifest.modes !== 'object' || manifest.modes === null || Array.isArray(manifest.modes)) {
    return {}
  }
  const digests: Record<string, string> = {}
  for (const [id, digest] of Object.entries(manifest.modes)) {
    if (typeof digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(digest)) digests[id] = digest
  }
  return digests
}

export function requirePlugin(name: string, root = locateRoot()): PluginDescriptor {
  const plugin = scanPlugins(root).find(candidate => candidate.name === name)
  if (plugin === undefined) throw new Error(`unknown plugin: ${name}`)
  return plugin
}

export function requireMode(id: string, root = locateRoot()): ModeDescriptor {
  const mode = scanModes(root).find(candidate => candidate.id === id)
  if (mode === undefined) throw new Error(`unknown mode: ${id}`)
  return mode
}

function readJsonFile(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function emptyProfile(): ProfilePackage {
  return { dependencies: {}, dsh: { profile: { bundles: [] } } }
}

function isValidProfile(raw: unknown): raw is ProfilePackage {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return false
  const profile = raw as ProfilePackage
  if (profile.dependencies !== undefined && (typeof profile.dependencies !== 'object' || profile.dependencies === null || Array.isArray(profile.dependencies))) {
    return false
  }
  const bundles = profile.dsh?.profile?.bundles
  if (bundles !== undefined && !Array.isArray(bundles)) return false
  return true
}

function readProfile(): ProfilePackage | null {
  const file = profilePackageFile()
  if (!existsSync(file)) return null
  const raw = readJsonFile(file)
  return isValidProfile(raw) ? raw : null
}

function profileErrorDetail(): string | undefined {
  const file = profilePackageFile()
  if (!existsSync(file)) return undefined
  const raw = readJsonFile(file)
  return isValidProfile(raw) ? undefined : `profile package.json is invalid: ${file}`
}

function ensureProfile(): ProfilePackage {
  const file = profilePackageFile()
  if (!existsSync(file)) {
    mkdirSync(path.dirname(file), { recursive: true })
    const profile = structuredClone(MIN_PROFILE) as unknown as ProfilePackage
    atomicWriteJson(file, profile)
    return profile
  }
  const profile = readProfile()
  if (profile === null) throw new Error(`profile package.json is invalid: ${file}`)
  profile.dependencies ??= {}
  profile.dsh ??= {}
  profile.dsh.profile ??= {}
  profile.dsh.profile.bundles ??= []
  return profile
}

function backupFile(file: string): string | undefined {
  if (!existsSync(file)) return undefined
  const backup = `${file}.bak-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  copyFileSync(file, backup)
  return backup
}

function atomicWriteJson(file: string, value: unknown): void {
  const dir = path.dirname(file)
  mkdirSync(dir, { recursive: true })
  const temp = `${file}.tmp-${process.pid}-${Date.now()}`
  const body = `${JSON.stringify(value, null, 2)}\n`
  writeFileSync(temp, body, 'utf8')
  try {
    renameSync(temp, file)
  } catch (error) {
    rmSync(temp, { force: true })
    throw error
  }
}

function writeProfileWithBackup(profile: ProfilePackage): string | undefined {
  const file = profilePackageFile()
  const backup = backupFile(file)
  atomicWriteJson(file, profile)
  return backup
}

interface FileSnapshot {
  readonly file: string
  readonly existed: boolean
  readonly body?: Buffer
}

function snapshotFile(file: string): FileSnapshot {
  return existsSync(file)
    ? { file, existed: true, body: readFileSync(file) }
    : { file, existed: false }
}

function restoreFileSnapshot(snapshot: FileSnapshot): void {
  if (!snapshot.existed) {
    rmSync(snapshot.file, { force: true })
    return
  }
  if (snapshot.body === undefined) throw new Error(`snapshot body missing: ${snapshot.file}`)
  const temp = `${snapshot.file}.restore-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  try {
    writeFileSync(temp, snapshot.body, { flag: 'wx' })
    renameSync(temp, snapshot.file)
  } catch (error) {
    rmSync(temp, { force: true })
    throw error
  }
}

function profileMutationSnapshots(): readonly [FileSnapshot, FileSnapshot] {
  return [
    snapshotFile(profilePackageFile()),
    snapshotFile(path.join(profileWebDir(), 'pnpm-lock.yaml')),
  ]
}

function restoreFileSnapshots(snapshots: readonly FileSnapshot[]): void {
  for (const snapshot of snapshots) restoreFileSnapshot(snapshot)
}

function addBundle(profile: ProfilePackage, pkg: string): void {
  profile.dsh ??= {}
  profile.dsh.profile ??= {}
  profile.dsh.profile.bundles ??= []
  if (!profile.dsh.profile.bundles.includes(pkg)) profile.dsh.profile.bundles.push(pkg)
}

function removeBundle(profile: ProfilePackage, pkg: string): void {
  const bundles = profile.dsh?.profile?.bundles
  if (bundles === undefined) return
  profile.dsh!.profile!.bundles = bundles.filter(candidate => candidate !== pkg)
}

function normalizeBundle(profile: ProfilePackage, plugin: PluginDescriptor): void {
  const pkg = pluginDependencyName(plugin)
  removeBundle(profile, pkg)
  if (plugin.mountPlane === 'host') addBundle(profile, pkg)
}

function pluginDependencyName(plugin: PluginDescriptor): string {
  return `@dsh-external/${plugin.name}`
}

function readInstalledVersion(plugin: PluginDescriptor): string | undefined {
  const file = path.join(profileWebDir(), 'node_modules', '@dsh-external', plugin.name, 'package.json')
  if (!existsSync(file)) return undefined
  const raw = readJsonFile(file) as Record<string, unknown> | null
  return typeof raw?.version === 'string' ? raw.version : undefined
}

function compareVersions(left: string, right: string): number {
  const leftParts = left.split('.').map(part => Number.parseInt(part, 10) || 0)
  const rightParts = right.split('.').map(part => Number.parseInt(part, 10) || 0)
  const length = Math.max(leftParts.length, rightParts.length)
  for (let index = 0; index < length; index += 1) {
    const a = leftParts[index] ?? 0
    const b = rightParts[index] ?? 0
    if (a !== b) return a - b
  }
  return 0
}

function modeStatus(mode: ModeDescriptor, root: string): ModeStatus {
  const link = presetsLinkPath()
  const modesRoot = path.join(root, 'modes')
  const modeDir = mode.dir
  if (mode.digest === undefined) {
    return {
      id: mode.id,
      name: mode.name,
      summary: mode.summary,
      linkState: 'error',
      linkPath: path.join(link, mode.id),
      ready: false,
    }
  }
  let linkState: ModeStatus['linkState'] = 'missing'
  let linkPath: string | undefined

  try {
    // Whole-directory deployment: ~/.dsh/.agent-presets is a symlink to
    // <package>/modes and every mode inside it is live.
    const current = readlinkSync(link)
    linkPath = path.join(link, mode.id)
    linkState = path.resolve(current) === path.resolve(modesRoot) ? 'ok' : 'stale'
  } catch {
    if (existsSync(link)) {
      // Existing real directory: DSH's preset discovery skips symlinked
      // children (`child.isDirectory()` is false for them), so the manager
      // copies each packaged mode in as a real directory and records it in a
      // marker file. Judge that managed copy instead.
      linkPath = path.join(link, mode.id)
      let stat: ReturnType<typeof lstatSync> | null = null
      try {
        stat = lstatSync(linkPath)
      } catch {
        stat = null
      }
      try {
        const marker = readModeMarker(link)
        const entry = marker.marker.modes[mode.id]
        const legacyOwned = marker.legacyOwned.has(mode.id)
        if (entry?.digest === mode.digest && stat !== null && stat.isDirectory()) {
          linkState = 'ok'
        } else if ((entry !== undefined || legacyOwned) && stat !== null && stat.isDirectory()) {
          linkState = 'stale'
        } else if (stat !== null && stat.isSymbolicLink()) {
          try {
            const current = readlinkSync(linkPath)
            linkState = path.resolve(current) === path.resolve(modeDir) ? 'stale' : 'error'
          } catch {
            linkState = 'error'
          }
        } else if (stat !== null) {
          linkState = 'error'
        } else {
          linkState = 'missing'
        }
      } catch {
        linkState = 'error'
      }
    } else {
      linkState = 'missing'
    }
  }

  const ready = linkState === 'ok' && existsSync(modeDir)
  return {
    id: mode.id,
    name: mode.name,
    summary: mode.summary,
    linkState,
    ...(linkPath === undefined ? {} : { linkPath }),
    ready,
  }
}

function pluginStatus(plugin: PluginDescriptor): PluginStatus {
  const profile = readProfile() ?? emptyProfile()
  const pkg = pluginDependencyName(plugin)
  const dependency = profile.dependencies?.[pkg]
  const installedVersion = readInstalledVersion(plugin)
  const latestVersion = plugin.version

  let installState: PluginStatus['installState']
  if (dependency === undefined) {
    installState = 'not-installed'
  } else if (!existsSync(plugin.dir)) {
    installState = 'broken'
  } else {
    const expectedLink = `link:${plugin.dir}`
    const linked = dependency === expectedLink
    const bundleCount = profile.dsh?.profile?.bundles?.filter(candidate => candidate === pkg).length ?? 0
    const bundled = plugin.mountPlane === 'host' ? bundleCount === 1 : bundleCount === 0
    if (!linked) {
      installState = installedVersion === undefined ? 'broken' : 'update-available'
    } else if (!bundled || installedVersion === undefined) {
      installState = 'broken'
    } else if (compareVersions(installedVersion, latestVersion) < 0) {
      installState = 'update-available'
    } else {
      installState = 'installed'
    }
  }

  return {
    name: plugin.name,
    title: plugin.title,
    description: plugin.description,
    installState,
    ...(installedVersion === undefined ? {} : { installedVersion }),
    latestVersion,
    mountPlane: plugin.mountPlane,
  }
}

/** Read the live admin status. `operations` is supplied by the host queue. */
export function getStatus(operations: readonly OperationRecord[] = [], root = locateRoot()): AdminStatus {
  return buildStatus(operations, root)
}

/** Alias matching the manager API name used in the design notes. */
export function status(operations: readonly OperationRecord[] = [], root = locateRoot()): AdminStatus {
  return buildStatus(operations, root)
}

function buildStatus(operations: readonly OperationRecord[] = [], root = locateRoot()): AdminStatus {
  const modes = scanModes(root).map(mode => modeStatus(mode, root))
  const plugins = scanPlugins(root).map(plugin => pluginStatus(plugin))
  const modesReady = modes.filter(mode => mode.ready).length
  const pluginsInstalled = plugins.filter(plugin => plugin.installState === 'installed').length
  const updatesAvailable = plugins.filter(plugin => plugin.installState === 'update-available').length
  const profileError = profileErrorDetail()
  return {
    summary: {
      modesTotal: modes.length,
      modesReady,
      pluginsTotal: plugins.length,
      pluginsInstalled,
      updatesAvailable,
      busy: operations.some(operation => operation.state === 'queued' || operation.state === 'running'),
      ...(profileError === undefined ? {} : { profileError }),
    },
    modes,
    plugins,
    operations: [...operations],
  }
}

/* ------------------------------------------------------------------ */
/* Process layer: pnpm installs through argv-based spawns.            */
/* ------------------------------------------------------------------ */

const CMD_METACHARS = /[\s"&|<>^()%!]/

function quoteCmdArg(arg: string): string {
  if (!CMD_METACHARS.test(arg)) return arg
  return `"${arg.replace(/"/g, '""')}"`
}

function spawnShim(file: string, args: readonly string[], options: Record<string, unknown>): ReturnType<typeof spawn> {
  if (!IS_WIN) return spawn(file, [...args], { ...options, shell: false })
  const commandLine = [file, ...args].map(quoteCmdArg).join(' ')
  return spawn(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', `"${commandLine}"`], {
    ...options,
    shell: false,
    windowsVerbatimArguments: true,
  })
}

function spawnEnv(): Record<string, string | undefined> {
  const separator = IS_WIN ? ';' : ':'
  const parts = (process.env.PATH ?? '').split(separator).filter(part => part !== '')
  const candidates = IS_WIN
    ? [path.dirname(process.execPath)]
    : ['/opt/homebrew/bin', '/usr/local/bin', path.join(homedir(), '.local', 'bin'), path.dirname(process.execPath)]
  for (const bin of candidates) {
    if (bin !== '' && !parts.includes(bin)) parts.push(bin)
  }
  return { ...process.env, CI: 'true', PATH: parts.join(separator) }
}

function spawnCollect(
  file: string,
  args: readonly string[],
  cwd: string,
  onOutput?: (line: string) => void,
): Promise<SpawnResult> {
  return new Promise((resolve) => {
    const child = spawnShim(file, args, {
      cwd,
      env: spawnEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    const feed = (chunk: Buffer, into: 'out' | 'err'): void => {
      const text = chunk.toString()
      if (into === 'out') stdout = (stdout + text).slice(-64 * 1024)
      else stderr = (stderr + text).slice(-64 * 1024)
      onOutput?.(text.trim())
    }
    child.stdout?.on('data', (chunk: Buffer) => feed(chunk, 'out'))
    child.stderr?.on('data', (chunk: Buffer) => feed(chunk, 'err'))
    child.on('error', (error: Error) => {
      resolve({ code: 127, stdout, stderr: `${stderr}\n${error.message}` })
    })
    child.on('close', (code: number | null) => {
      resolve({ code, stdout, stderr })
    })
  })
}

async function runPnpmInstall(cwd: string, onProgress?: ProgressCallback): Promise<void> {
  onProgress?.('running pnpm install', 50)
  const runArgs = ['-y', 'pnpm', 'install', '--prefer-offline', '--no-frozen-lockfile']
  const hadLockfile = existsSync(path.join(cwd, 'pnpm-lock.yaml'))
  let result = await spawnCollect('npx', runArgs, cwd, line => {
    if (line !== '') onProgress?.(line.slice(0, 200))
  })
  // pnpm 11 can reject every later mutation when an existing lockfile already
  // contains a release inside its minimumReleaseAge window. Match only pnpm's
  // two known error codes, require a pre-existing lock, and retry once.
  const output = `${result.stdout}\n${result.stderr}`
  const releaseAgeError = /(?:^|[^A-Za-z0-9_])ERR_PNPM_(?:MINIMUM_RELEASE_AGE_VIOLATION|NO_MATURE_MATCHING_VERSION)(?![A-Za-z0-9_])/m
  if (result.code !== 0 && hadLockfile && releaseAgeError.test(output)) {
    onProgress?.('retrying locked profile after release-age verification failure', 55)
    result = await spawnCollect('npx', [...runArgs, '--config.minimumReleaseAge=0'], cwd, line => {
      if (line !== '') onProgress?.(line.slice(0, 200))
    })
  }
  if (result.code !== 0) {
    const tail = result.stderr.trim() || result.stdout.trim() || `exit code ${String(result.code)}`
    throw new Error(`pnpm install failed: ${tail.slice(-1000)}`)
  }
}

/* ------------------------------------------------------------------ */
/* Mutating operations.                                               */
/* ------------------------------------------------------------------ */

function ensureLinkType(): 'junction' | 'dir' {
  return IS_WIN ? 'junction' : 'dir'
}

function makeDirLink(src: string, dst: string): boolean {
  // On Windows, junctions need no admin rights but cannot point at a target
  // that does not exist yet; dangling peer bridges are left for a later run.
  if (IS_WIN && !existsAny(src)) return false
  symlinkSync(src, dst, ensureLinkType())
  return true
}

interface PeerLinkChange {
  readonly source: string
  readonly destination: string
  readonly backup?: string
}

function replacePeerLink(source: string, destination: string, changes: PeerLinkChange[]): boolean {
  if (IS_WIN && !existsAny(source)) return false
  let current: string | null = null
  try {
    current = readlinkSync(destination)
  } catch {
    // Not a symlink or missing.
  }
  if (current !== null && path.resolve(current) === path.resolve(source)) return false

  let backup: string | undefined
  if (existsAny(destination)) {
    backup = `${destination}.bak-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    renameSync(destination, backup)
  }
  try {
    if (!makeDirLink(source, destination)) {
      if (backup !== undefined) renameSync(backup, destination)
      return false
    }
    changes.push({ source, destination, ...(backup === undefined ? {} : { backup }) })
    return true
  } catch (error) {
    if (backup !== undefined && !existsAny(destination) && existsAny(backup)) renameSync(backup, destination)
    throw error
  }
}

function rollbackPeerLinks(changes: readonly PeerLinkChange[]): void {
  for (const change of [...changes].reverse()) {
    if (isOurSymlink(change.destination, change.source)) unlinkSync(change.destination)
    if (change.backup !== undefined && !existsAny(change.destination) && existsAny(change.backup)) {
      renameSync(change.backup, change.destination)
    }
  }
}

/** Replicate deploy.mjs: bridge @deepseek-ai/* and @dsh-external/* into plugins/node_modules. */
export function linkPluginPeers(root = locateRoot()): { deepseek: number; external: number } {
  const runtime = path.join(dshHome(), 'profiles', 'node_modules', '@deepseek-ai')
  const localDeepseek = path.join(root, 'plugins', 'node_modules', '@deepseek-ai')
  mkdirSync(localDeepseek, { recursive: true })

  let names: string[] = []
  try {
    names = readdirSync(runtime).filter(name => !name.startsWith('.'))
  } catch {
    // Runtime not installed yet; fall through with the known candidates so
    // dangling links are created now and become live after the first boot.
  }
  for (const extra of ['dsh-tools', 'schemastery', 'dsh-settings', 'dsh-system-prompt', 'dsh-mcp-client', 'dsh-llm']) {
    if (!names.includes(extra)) names.push(extra)
  }

  const changes: PeerLinkChange[] = []
  try {
    let deepseek = 0
    for (const pkg of names) {
      const src = path.join(runtime, pkg)
      const dst = path.join(localDeepseek, pkg)
      if (replacePeerLink(src, dst, changes)) deepseek += 1
    }

    const localExternal = path.join(root, 'plugins', 'node_modules', '@dsh-external')
    mkdirSync(localExternal, { recursive: true })
    let external = 0
    for (const plugin of scanPlugins(root)) {
      const src = plugin.dir
      const dst = path.join(localExternal, plugin.name)
      if (replacePeerLink(src, dst, changes)) external += 1
    }
    return { deepseek, external }
  } catch (error) {
    try {
      rollbackPeerLinks(changes)
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], 'plugin peer linking failed and rollback was incomplete')
    }
    throw error
  }
}

/** Deploy (or repair) the nine modes into ~/.dsh/.agent-presets. */
export function deployModes(root = locateRoot(), onProgress?: ProgressCallback, ids?: readonly string[]): string {
  const target = path.join(root, 'modes')
  const requested = ids === undefined ? undefined : new Set(ids)
  for (const mode of scanModes(root)) {
    if ((requested === undefined || requested.has(mode.id)) && mode.digest === undefined) {
      throw new Error(`mode digest missing: ${mode.id}`)
    }
  }
  const link = presetsLinkPath()
  mkdirSync(dshHome(), { recursive: true })
  onProgress?.('checking agent presets link', 20)

  let previousLinkBackup: string | undefined
  if (existsAny(link)) {
    let current: string | null = null
    try {
      current = readlinkSync(link)
    } catch {
      // Existing real directory: never replace the user's presets. DSH's
      // preset discovery skips symlinked children, so copy each packaged mode
      // in as a real directory and record the managed copies in a marker.
      return deployModesIntoDirectory(link, root, onProgress, ids)
    }
    if (current !== null && path.resolve(current) === path.resolve(target)) {
      onProgress?.('agent presets link ok', 100)
      return `agent presets link ok: ${link} -> ${target}`
    }
    // Existing symlink to something else: a link can be moved aside safely.
    previousLinkBackup = `${link}.bak-${Date.now()}`
    renameSync(link, previousLinkBackup)
    onProgress?.(`backed up existing agent presets link to ${previousLinkBackup}`, 50)
  }

  try {
    symlinkSync(target, link, ensureLinkType())
  } catch (error) {
    if (previousLinkBackup !== undefined && !existsAny(link) && existsAny(previousLinkBackup)) {
      renameSync(previousLinkBackup, link)
    }
    throw error
  }
  onProgress?.('agent presets link ready', 100)
  return `agent presets link ready: ${link} -> ${target}`
}

/**
 * Copy each packaged mode into an existing real `.agent-presets` directory.
 * A hidden marker records which entries this manager owns; only those owned
 * copies are ever replaced. Foreign or conflicting presets are left as-is.
 */

const MODE_MARKER_FILE = '.dsh-redteam-model.json'
const MODE_MARKER_BACKUP_FILE = '.dsh-redteam-model.backup.json'
const MODE_MARKER_OWNER = '@dsh-external/dsh-redteam-model'
const LEGACY_STALE_DIGEST = `sha256:${'0'.repeat(64)}`

interface ModeMarkerEntry {
  readonly digest: string
  readonly deployedAt: number
}

interface ModeMarker {
  readonly schemaVersion: 2
  readonly owner: typeof MODE_MARKER_OWNER
  readonly modes: Record<string, ModeMarkerEntry>
}

interface ModeMarkerRead {
  readonly marker: ModeMarker
  readonly legacyOwned: ReadonlySet<string>
  readonly recoveredFromBackup: boolean
}

function emptyModeMarker(): ModeMarker {
  return { schemaVersion: 2, owner: MODE_MARKER_OWNER, modes: {} }
}

function modeMarkerFile(directory: string): string {
  return path.join(directory, MODE_MARKER_FILE)
}

function modeMarkerBackupFile(directory: string): string {
  return path.join(directory, MODE_MARKER_BACKUP_FILE)
}

function readMarkerJson(file: string): unknown | undefined {
  if (!existsAny(file)) return undefined
  const info = lstatSync(file)
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`unsafe mode marker: ${file}`)
  return JSON.parse(readFileSync(file, 'utf8')) as unknown
}

function assertSafeModeMarkerPaths(directory: string): void {
  for (const file of [modeMarkerFile(directory), modeMarkerBackupFile(directory)]) {
    if (!existsAny(file)) continue
    const info = lstatSync(file)
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`unsafe mode marker: ${file}`)
  }
}

function parseModeMarker(raw: unknown): Omit<ModeMarkerRead, 'recoveredFromBackup'> | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  const candidate = raw as { schemaVersion?: unknown; owner?: unknown; modes?: unknown }
  if (candidate.schemaVersion === 2) {
    if (candidate.owner !== MODE_MARKER_OWNER || typeof candidate.modes !== 'object' || candidate.modes === null || Array.isArray(candidate.modes)) {
      return null
    }
    const modes: Record<string, ModeMarkerEntry> = {}
    for (const [id, value] of Object.entries(candidate.modes)) {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
      const entry = value as { digest?: unknown; deployedAt?: unknown }
      if (typeof entry.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(entry.digest)) return null
      modes[id] = { digest: entry.digest, deployedAt: typeof entry.deployedAt === 'number' ? entry.deployedAt : 0 }
    }
    return { marker: { schemaVersion: 2, owner: MODE_MARKER_OWNER, modes }, legacyOwned: new Set() }
  }

  const legacyOwned = new Set<string>()
  for (const [id, value] of Object.entries(raw)) {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
    const entry = value as { source?: unknown }
    if (typeof entry.source !== 'string') return null
    legacyOwned.add(id)
  }
  return { marker: emptyModeMarker(), legacyOwned }
}

function readModeMarker(directory: string): ModeMarkerRead {
  assertSafeModeMarkerPaths(directory)
  const primary = modeMarkerFile(directory)
  const backup = modeMarkerBackupFile(directory)
  let primaryError: unknown
  try {
    const raw = readMarkerJson(primary)
    if (raw === undefined) {
      const backupRaw = readMarkerJson(backup)
      if (backupRaw === undefined) return { marker: emptyModeMarker(), legacyOwned: new Set(), recoveredFromBackup: false }
      const backupParsed = parseModeMarker(backupRaw)
      if (backupParsed !== null) return { ...backupParsed, recoveredFromBackup: true }
      throw new Error(`invalid mode marker backup: ${backup}`)
    }
    const parsed = parseModeMarker(raw)
    if (parsed !== null) return { ...parsed, recoveredFromBackup: false }
    primaryError = new Error(`invalid mode marker: ${primary}`)
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('unsafe mode marker:')) throw error
    primaryError = error
  }

  try {
    const raw = readMarkerJson(backup)
    const parsed = raw === undefined ? null : parseModeMarker(raw)
    if (parsed !== null) return { ...parsed, recoveredFromBackup: true }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('unsafe mode marker:')) throw error
  }
  const detail = primaryError instanceof Error ? primaryError.message : String(primaryError)
  throw new Error(`invalid mode marker: ${primary}: ${detail}`)
}

function atomicWriteRegularFile(file: string, body: string): void {
  if (existsAny(file)) {
    const info = lstatSync(file)
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`unsafe mode marker: ${file}`)
  }
  const directory = path.dirname(file)
  const temp = path.join(directory, `.${path.basename(file)}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  try {
    writeFileSync(temp, body, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
    renameSync(temp, file)
  } catch (error) {
    rmSync(temp, { force: true })
    throw error
  }
}

function writeModeMarker(directory: string, marker: ModeMarker): void {
  const body = `${JSON.stringify(marker, null, 2)}\n`
  const backup = modeMarkerBackupFile(directory)
  const primary = modeMarkerFile(directory)
  assertSafeModeMarkerPaths(directory)
  atomicWriteRegularFile(backup, body)
  atomicWriteRegularFile(primary, body)
}

function isOurSymlink(destination: string, source: string): boolean {
  try {
    return lstatSync(destination).isSymbolicLink() && path.resolve(readlinkSync(destination)) === path.resolve(source)
  } catch {
    return false
  }
}

function deployModesIntoDirectory(
  directory: string,
  root: string,
  onProgress?: ProgressCallback,
  ids?: readonly string[],
): string {
  const requested = ids === undefined ? undefined : new Set(ids)
  const allModes = scanModes(root)
  const modes = allModes.filter(mode => requested === undefined || requested.has(mode.id))
  const current = readModeMarker(directory)
  const marker: ModeMarker = {
    schemaVersion: 2,
    owner: MODE_MARKER_OWNER,
    modes: { ...current.marker.modes },
  }
  const knownModes = new Set(allModes.map(mode => mode.id))
  for (const id of current.legacyOwned) {
    if (knownModes.has(id) && marker.modes[id] === undefined) {
      marker.modes[id] = { digest: LEGACY_STALE_DIGEST, deployedAt: 0 }
    }
  }
  let copied = 0
  let unchanged = 0
  const skipped: string[] = []

  for (const mode of modes) {
    if (mode.digest === undefined) throw new Error(`mode digest missing: ${mode.id}`)
    const destination = path.join(directory, mode.id)
    const entry = marker.modes[mode.id]
    const owned = entry !== undefined
    const destinationExists = existsAny(destination)
    const legacySymlink = destinationExists && isOurSymlink(destination, mode.dir)

    if (destinationExists) {
      if (!legacySymlink && (!owned || !lstatSync(destination).isDirectory())) {
        skipped.push(`${mode.id} (existing entry)`)
        continue
      }
    }

    if (!legacySymlink && owned && entry?.digest === mode.digest && destinationExists && lstatSync(destination).isDirectory()) {
      unchanged += 1
      continue
    }

    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const staging = path.join(directory, `.${mode.id}.dsh-redteam-model.tmp-${suffix}`)
    const backup = `${destination}.bak-${suffix}`
    const markerSnapshots = [
      snapshotFile(modeMarkerFile(directory)),
      snapshotFile(modeMarkerBackupFile(directory)),
    ]
    let backedUp = false
    let promoted = false
    let markerWriteAttempted = false
    try {
      cpSync(mode.dir, staging, { recursive: true })
      if ((owned || legacySymlink) && existsAny(destination)) {
        renameSync(destination, backup)
        backedUp = true
      }
      renameSync(staging, destination)
      promoted = true
      marker.modes[mode.id] = { digest: mode.digest, deployedAt: Date.now() }
      markerWriteAttempted = true
      writeModeMarker(directory, marker)
    } catch (error) {
      const rollbackErrors: unknown[] = []
      try { rmSync(staging, { recursive: true, force: true }) } catch (rollbackError) { rollbackErrors.push(rollbackError) }
      if (promoted) {
        try { rmSync(destination, { recursive: true, force: true }) } catch (rollbackError) { rollbackErrors.push(rollbackError) }
      }
      if (backedUp && !existsAny(destination) && existsAny(backup)) {
        try { renameSync(backup, destination) } catch (rollbackError) { rollbackErrors.push(rollbackError) }
      }
      if (markerWriteAttempted) {
        try { restoreFileSnapshots(markerSnapshots) } catch (rollbackError) { rollbackErrors.push(rollbackError) }
      }
      if (rollbackErrors.length > 0) {
        throw new AggregateError([error, ...rollbackErrors], `mode deployment failed and rollback was incomplete: ${mode.id}`)
      }
      throw error
    }
    copied += 1
  }

  if (copied === 0 && (current.recoveredFromBackup || current.legacyOwned.size > 0
    || !existsAny(modeMarkerFile(directory)) || !existsAny(modeMarkerBackupFile(directory)))) {
    writeModeMarker(directory, marker)
  }
  const suffix = skipped.length > 0 ? `; skipped existing entries: ${skipped.join(', ')}` : ''
  const detail = `copied ${copied} modes into existing agent presets directory; ${unchanged} already current${suffix}`
  onProgress?.(detail, 100)
  return detail
}

/** Validate/rebuild the .agent-presets link for one named mode. */
export function repairMode(id: string, root = locateRoot(), onProgress?: ProgressCallback): string {
  const mode = requireMode(id, root)
  if (!existsSync(mode.dir)) throw new Error(`mode directory missing: ${mode.dir}`)
  onProgress?.(`repairing agent presets link for ${id}`, 10)
  const detail = deployModes(root, onProgress, [id])
  return `${mode.id}: ${detail}`
}

/** Install one plugin into the web profile and run pnpm install. */
export async function installOne(name: string, options: InstallOptions = {}, root = locateRoot()): Promise<string> {
  const plugin = requirePlugin(name, root)
  const profileDirectoryExisted = existsAny(profileWebDir())
  const snapshots = profileMutationSnapshots()
  try {
    const profile = ensureProfile()
    options.onProgress?.('writing profile', 10)
    const pkg = pluginDependencyName(plugin)
    profile.dependencies ??= {}
    profile.dependencies[pkg] = `link:${plugin.dir}`
    normalizeBundle(profile, plugin)
    if (snapshots[0].existed) writeProfileWithBackup(profile)
    else atomicWriteJson(profilePackageFile(), profile)
    await runPnpmInstall(profileWebDir(), options.onProgress)
    options.onProgress?.('linking plugin peers', 90)
    linkPluginPeers(root)
    options.onProgress?.('done', 100)
    return `installed ${name}@${plugin.version}`
  } catch (error) {
    restoreFileSnapshots(snapshots)
    if (!profileDirectoryExisted) {
      try { rmdirSync(profileWebDir()) } catch { /* Keep a non-empty directory created by pnpm. */ }
    }
    throw error
  }
}

/** Uninstall one plugin from the web profile and run pnpm install. */
export async function uninstallOne(name: string, options: InstallOptions = {}, root = locateRoot()): Promise<string> {
  const plugin = requirePlugin(name, root)
  const snapshots = profileMutationSnapshots()
  const profile = readProfile()
  const pkg = pluginDependencyName(plugin)
  if (profile === null || profile.dependencies?.[pkg] === undefined) {
    options.onProgress?.('not installed', 100)
    return `${name} is not installed`
  }

  try {
    options.onProgress?.('writing profile', 10)
    delete profile.dependencies?.[pkg]
    removeBundle(profile, pkg)
    writeProfileWithBackup(profile)
    await runPnpmInstall(profileWebDir(), options.onProgress)
    options.onProgress?.('linking plugin peers', 90)
    linkPluginPeers(root)
    options.onProgress?.('done', 100)
    return `uninstalled ${name}`
  } catch (error) {
    restoreFileSnapshots(snapshots)
    throw error
  }
}

/** Update one plugin: if it is not installed this behaves like install. */
export async function updateOne(name: string, options: InstallOptions = {}, root = locateRoot()): Promise<string> {
  const plugin = requirePlugin(name, root)
  const profile = readProfile()
  const pkg = pluginDependencyName(plugin)
  if (profile === null || profile.dependencies?.[pkg] === undefined) {
    return installOne(name, options, root)
  }

  // Re-point the dependency to the current plugin directory and reinstall.
  return installOne(name, options, root)
}

/** Update every installed plugin. */
export async function updateAll(options: InstallOptions = {}, root = locateRoot()): Promise<string[]> {
  const plugins = scanPlugins(root)
  const profile = readProfile()
  const installed = plugins.filter(plugin => profile?.dependencies?.[pluginDependencyName(plugin)] !== undefined)
  const results: string[] = []
  for (const plugin of installed) {
    results.push(await updateOne(plugin.name, options, root))
  }
  return results
}
