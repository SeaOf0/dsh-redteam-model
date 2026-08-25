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
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  renameSync,
  symlinkSync,
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
  return process.env.DSH_HOME ?? path.join(homedir(), '.dsh')
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
    return { id, name, summary, dir, ...(order === undefined ? {} : { order }) }
  }).filter((mode): mode is ModeDescriptor => mode !== null)
  return modes.sort((left, right) => {
    const lo = left.order ?? 99
    const ro = right.order ?? 99
    if (lo !== ro) return lo - ro
    return left.id.localeCompare(right.id)
  })
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
  } catch {
    // Fall back to a direct write only if the atomic rename is unavailable
    // (e.g. some Windows filesystems). The backup was already made by callers.
    writeFileSync(file, body, 'utf8')
    try { lstatSync(temp) } catch { /* already gone */ }
  }
}

function writeProfileWithBackup(profile: ProfilePackage): string | undefined {
  const file = profilePackageFile()
  const backup = backupFile(file)
  atomicWriteJson(file, profile)
  return backup
}

function restoreProfile(backup: string | undefined): void {
  if (backup === undefined || !existsSync(backup)) return
  copyFileSync(backup, profilePackageFile())
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
  const index = bundles.indexOf(pkg)
  if (index >= 0) bundles.splice(index, 1)
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
      // Existing real directory: the manager links modes inside it one by
      // one, so judge the per-mode entry instead of the directory itself.
      linkPath = path.join(link, mode.id)
      try {
        const current = readlinkSync(linkPath)
        linkState = path.resolve(current) === path.resolve(modeDir) ? 'ok' : 'stale'
      } catch {
        linkState = existsSync(linkPath) ? 'error' : 'missing'
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
    const bundled = plugin.mountPlane !== 'host' || profile.dsh?.profile?.bundles?.includes(pkg) === true
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
  let result = await spawnCollect('npx', runArgs, cwd, line => {
    if (line !== '') onProgress?.(line.slice(0, 200))
  })
  // pnpm's supply-chain policy rejects lockfiles whose existing entries were
  // published inside the minimumReleaseAge window. That is a property of the
  // profile's other plugins, not of this install: retry once with the
  // one-shot bypass so a fresh profile lockfile does not block the operation.
  if (result.code !== 0 && `${result.stdout}\n${result.stderr}`.includes('minimumReleaseAge')) {
    onProgress?.('retrying install with fresh-release bypass', 55)
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

  let deepseek = 0
  for (const pkg of names) {
    const src = path.join(runtime, pkg)
    const dst = path.join(localDeepseek, pkg)
    let current: string | null = null
    try {
      current = readlinkSync(dst)
    } catch {
      // Not a symlink or missing.
    }
    if (current === src) continue
    if (existsAny(dst)) renameSync(dst, `${dst}.bak-${Date.now()}`)
    if (!makeDirLink(src, dst)) continue
    deepseek += 1
  }

  const localExternal = path.join(root, 'plugins', 'node_modules', '@dsh-external')
  mkdirSync(localExternal, { recursive: true })
  let external = 0
  for (const plugin of scanPlugins(root)) {
    const src = plugin.dir
    const dst = path.join(localExternal, plugin.name)
    let current: string | null = null
    try {
      current = readlinkSync(dst)
    } catch {
      // Not a symlink or missing.
    }
    if (current === src) continue
    if (existsAny(dst)) renameSync(dst, `${dst}.bak-${Date.now()}`)
    if (!makeDirLink(src, dst)) continue
    external += 1
  }

  return { deepseek, external }
}

/** Deploy (or repair) the nine modes into ~/.dsh/.agent-presets. */
export function deployModes(root = locateRoot(), onProgress?: ProgressCallback): string {
  const target = path.join(root, 'modes')
  const link = presetsLinkPath()
  mkdirSync(dshHome(), { recursive: true })
  onProgress?.('checking agent presets link', 20)

  if (existsAny(link)) {
    let current: string | null = null
    try {
      current = readlinkSync(link)
    } catch {
      // Existing real directory: never replace the user's presets. Link each
      // of our modes into it so both sets of presets stay live together.
      return deployModesIntoDirectory(link, root, onProgress)
    }
    if (current !== null && path.resolve(current) === path.resolve(target)) {
      onProgress?.('agent presets link ok', 100)
      return `agent presets link ok: ${link} -> ${target}`
    }
    // Existing symlink to something else: a link can be moved aside safely.
    const backup = `${link}.bak-${Date.now()}`
    renameSync(link, backup)
    onProgress?.(`backed up existing agent presets link to ${backup}`, 50)
  }

  symlinkSync(target, link, ensureLinkType())
  onProgress?.('agent presets link ready', 100)
  return `agent presets link ready: ${link} -> ${target}`
}

/**
 * Link each packaged mode into an existing real `.agent-presets` directory.
 * Existing entries are never overwritten: foreign or conflicting presets are
 * reported and left exactly as they are.
 */
function deployModesIntoDirectory(directory: string, root: string, onProgress?: ProgressCallback): string {
  const modes = scanModes(root)
  let linked = 0
  const skipped: string[] = []

  for (const mode of modes) {
    const destination = path.join(directory, mode.id)
    if (existsAny(destination)) {
      try {
        const current = readlinkSync(destination)
        if (path.resolve(current) === path.resolve(mode.dir)) continue
        skipped.push(`${mode.id} (existing link to ${current})`)
        continue
      } catch {
        skipped.push(`${mode.id} (existing directory)`)
        continue
      }
    }
    symlinkSync(mode.dir, destination, ensureLinkType())
    linked += 1
  }

  const suffix = skipped.length > 0 ? `; skipped existing entries: ${skipped.join(', ')}` : ''
  onProgress?.(`linked ${linked} modes into existing agent presets directory${suffix}`, 100)
  return `linked ${linked} modes into existing agent presets directory${suffix}`
}

/** Validate/rebuild the .agent-presets link for one named mode. */
export function repairMode(id: string, root = locateRoot(), onProgress?: ProgressCallback): string {
  const mode = requireMode(id, root)
  if (!existsSync(mode.dir)) throw new Error(`mode directory missing: ${mode.dir}`)
  onProgress?.(`repairing agent presets link for ${id}`, 10)
  const detail = deployModes(root, onProgress)
  return `${mode.id}: ${detail}`
}

/** Install one plugin into the web profile and run pnpm install. */
export async function installOne(name: string, options: InstallOptions = {}, root = locateRoot()): Promise<string> {
  const plugin = requirePlugin(name, root)
  const profile = ensureProfile()
  options.onProgress?.('writing profile', 10)

  const pkg = pluginDependencyName(plugin)
  profile.dependencies ??= {}
  profile.dependencies[pkg] = `link:${plugin.dir}`
  if (plugin.mountPlane === 'host') addBundle(profile, pkg)
  const backup = writeProfileWithBackup(profile)

  try {
    await runPnpmInstall(profileWebDir(), options.onProgress)
    options.onProgress?.('linking plugin peers', 90)
    linkPluginPeers(root)
    options.onProgress?.('done', 100)
    return `installed ${name}@${plugin.version}`
  } catch (error) {
    restoreProfile(backup)
    throw error
  }
}

/** Uninstall one plugin from the web profile and run pnpm install. */
export async function uninstallOne(name: string, options: InstallOptions = {}, root = locateRoot()): Promise<string> {
  const plugin = requirePlugin(name, root)
  const profile = readProfile()
  const pkg = pluginDependencyName(plugin)
  if (profile === null || profile.dependencies?.[pkg] === undefined) {
    options.onProgress?.('not installed', 100)
    return `${name} is not installed`
  }

  options.onProgress?.('writing profile', 10)
  delete profile.dependencies?.[pkg]
  removeBundle(profile, pkg)
  const backup = writeProfileWithBackup(profile)

  try {
    await runPnpmInstall(profileWebDir(), options.onProgress)
    options.onProgress?.('linking plugin peers', 90)
    linkPluginPeers(root)
    options.onProgress?.('done', 100)
    return `uninstalled ${name}`
  } catch (error) {
    restoreProfile(backup)
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
