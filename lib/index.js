// src/operations.ts
var OperationQueue = class {
  records = [];
  maxRecords = 50;
  nextId = 1;
  tail = Promise.resolve();
  closed = false;
  enqueue(kind, target, runner) {
    if (this.closed) throw new Error("operation queue is closed");
    const id = `op-${String(this.nextId).padStart(4, "0")}`;
    this.nextId += 1;
    const record = {
      id,
      kind,
      target,
      state: "queued",
      percent: 0,
      detail: "queued"
    };
    this.records.push(record);
    this.trim();
    this.tail = this.tail.then(() => this.run(record, runner)).catch(() => {
    });
    return id;
  }
  cancel(id) {
    const record = this.records.find((candidate) => candidate.id === id && candidate.state === "queued");
    if (record === void 0) return false;
    this.update(record, { state: "cancelled", percent: 100, detail: "cancelled" });
    return true;
  }
  clearSettled() {
    for (let index = this.records.length - 1; index >= 0; index -= 1) {
      const state = this.records[index]?.state;
      if (state === "done" || state === "warned" || state === "failed" || state === "cancelled") {
        this.records.splice(index, 1);
      }
    }
  }
  list() {
    return this.records.slice();
  }
  /** Host lifecycle cleanup: cancel queued work; running work is left to settle. */
  dispose() {
    this.closed = true;
    for (const record of this.records) {
      if (record.state === "queued") {
        this.update(record, { state: "cancelled", percent: 100, detail: "cancelled on shutdown" });
      }
    }
  }
  update(record, patch) {
    const mutable = record;
    if (patch.percent !== void 0 && patch.percent !== null) {
      mutable.percent = Math.min(100, Math.max(0, Math.round(patch.percent)));
    }
    if (patch.detail !== void 0) mutable.detail = patch.detail;
    if (patch.state !== void 0) mutable.state = patch.state;
    if (patch.error !== void 0) mutable.error = patch.error;
  }
  async run(record, runner) {
    if (this.closed || record.state !== "queued") return;
    this.update(record, { state: "running", percent: 1, detail: "started" });
    try {
      const detail = await runner((patch) => this.update(record, patch));
      this.update(record, { state: "done", percent: 100, detail });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.update(record, {
        state: "failed",
        percent: 100,
        detail: message,
        error: message
      });
    }
  }
  trim() {
    if (this.records.length <= this.maxRecords) return;
    let remove = this.records.length - this.maxRecords;
    for (let index = 0; index < this.records.length && remove > 0; ) {
      const state = this.records[index]?.state;
      if (state === "done" || state === "warned" || state === "failed" || state === "cancelled") {
        this.records.splice(index, 1);
        remove -= 1;
      } else {
        index += 1;
      }
    }
  }
};

// src/manager.ts
import { spawn } from "node:child_process";
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
  writeFileSync
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
var IS_WIN = process.platform === "win32";
var MIN_PROFILE = {
  name: "dsh-profile-web",
  private: true,
  dependencies: {},
  dsh: { profile: { bundles: ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"] } }
};
function locateRoot() {
  return path.dirname(path.dirname(fileURLToPath(import.meta.url)));
}
function dshHome() {
  return process.env.DSH_HOME ?? path.join(homedir(), ".dsh");
}
function activeProfile() {
  const argv = process.argv;
  const flag = argv.indexOf("--profile");
  const next = flag !== -1 ? argv[flag + 1] : void 0;
  if (next !== void 0 && !next.startsWith("-")) {
    return next;
  }
  return "web";
}
function profileWebDir() {
  return path.join(dshHome(), "profiles", activeProfile());
}
function profilePackageFile() {
  return path.join(profileWebDir(), "package.json");
}
function presetsLinkPath() {
  return path.join(dshHome(), ".agent-presets");
}
function existsAny(target) {
  try {
    lstatSync(target);
    return true;
  } catch {
    return false;
  }
}
function titleFromDir(name2) {
  const base = name2.replace(/^dsh-/, "");
  return base.split("-").filter((part) => part !== "").map((part) => part.length <= 3 ? part.toUpperCase() : part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}
function scanPlugins(root = locateRoot()) {
  const pluginsRoot = path.join(root, "plugins");
  if (!existsSync(pluginsRoot)) return [];
  const names = readdirSync(pluginsRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).filter((name2) => existsSync(path.join(pluginsRoot, name2, "package.json"))).sort();
  return names.map((name2) => {
    const dir = path.join(pluginsRoot, name2);
    const raw = readJsonFile(path.join(dir, "package.json"));
    const pkg = raw ?? {};
    const mountPlane = name2 === "dsh-scanner-tools" || name2 === "dsh-semgrep-audit" ? "preset" : "host";
    return {
      name: name2,
      title: titleFromDir(name2),
      description: typeof pkg.description === "string" ? pkg.description : "",
      version: typeof pkg.version === "string" ? pkg.version : "0.0.0",
      mountPlane,
      dir
    };
  });
}
function scanModes(root = locateRoot()) {
  const modesRoot = path.join(root, "modes");
  if (!existsSync(modesRoot)) return [];
  const ids = readdirSync(modesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).filter((id) => existsSync(path.join(modesRoot, id, "preset.yml")));
  const modes = ids.map((id) => {
    const dir = path.join(modesRoot, id);
    const text = readFileSync(path.join(dir, "preset.yml"), "utf8");
    const name2 = /^name:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? id;
    const summary = /^description:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? "";
    const orderRaw = /^order:\s*(\d+)$/m.exec(text)?.[1];
    const order = orderRaw === void 0 ? void 0 : Number(orderRaw);
    return { id, name: name2, summary, dir, ...order === void 0 ? {} : { order } };
  }).filter((mode) => mode !== null);
  return modes.sort((left, right) => {
    const lo = left.order ?? 99;
    const ro = right.order ?? 99;
    if (lo !== ro) return lo - ro;
    return left.id.localeCompare(right.id);
  });
}
function requirePlugin(name2, root = locateRoot()) {
  const plugin = scanPlugins(root).find((candidate) => candidate.name === name2);
  if (plugin === void 0) throw new Error(`unknown plugin: ${name2}`);
  return plugin;
}
function requireMode(id, root = locateRoot()) {
  const mode = scanModes(root).find((candidate) => candidate.id === id);
  if (mode === void 0) throw new Error(`unknown mode: ${id}`);
  return mode;
}
function readJsonFile(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}
function emptyProfile() {
  return { dependencies: {}, dsh: { profile: { bundles: [] } } };
}
function isValidProfile(raw) {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return false;
  const profile = raw;
  if (profile.dependencies !== void 0 && (typeof profile.dependencies !== "object" || profile.dependencies === null || Array.isArray(profile.dependencies))) {
    return false;
  }
  const bundles = profile.dsh?.profile?.bundles;
  if (bundles !== void 0 && !Array.isArray(bundles)) return false;
  return true;
}
function readProfile() {
  const file = profilePackageFile();
  if (!existsSync(file)) return null;
  const raw = readJsonFile(file);
  return isValidProfile(raw) ? raw : null;
}
function profileErrorDetail() {
  const file = profilePackageFile();
  if (!existsSync(file)) return void 0;
  const raw = readJsonFile(file);
  return isValidProfile(raw) ? void 0 : `profile package.json is invalid: ${file}`;
}
function ensureProfile() {
  const file = profilePackageFile();
  if (!existsSync(file)) {
    mkdirSync(path.dirname(file), { recursive: true });
    const profile2 = structuredClone(MIN_PROFILE);
    atomicWriteJson(file, profile2);
    return profile2;
  }
  const profile = readProfile();
  if (profile === null) throw new Error(`profile package.json is invalid: ${file}`);
  profile.dependencies ??= {};
  profile.dsh ??= {};
  profile.dsh.profile ??= {};
  profile.dsh.profile.bundles ??= [];
  return profile;
}
function backupFile(file) {
  if (!existsSync(file)) return void 0;
  const backup = `${file}.bak-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  copyFileSync(file, backup);
  return backup;
}
function atomicWriteJson(file, value) {
  const dir = path.dirname(file);
  mkdirSync(dir, { recursive: true });
  const temp = `${file}.tmp-${process.pid}-${Date.now()}`;
  const body = `${JSON.stringify(value, null, 2)}
`;
  writeFileSync(temp, body, "utf8");
  try {
    renameSync(temp, file);
  } catch {
    writeFileSync(file, body, "utf8");
    try {
      lstatSync(temp);
    } catch {
    }
  }
}
function writeProfileWithBackup(profile) {
  const file = profilePackageFile();
  const backup = backupFile(file);
  atomicWriteJson(file, profile);
  return backup;
}
function restoreProfile(backup) {
  if (backup === void 0 || !existsSync(backup)) return;
  copyFileSync(backup, profilePackageFile());
}
function addBundle(profile, pkg) {
  profile.dsh ??= {};
  profile.dsh.profile ??= {};
  profile.dsh.profile.bundles ??= [];
  if (!profile.dsh.profile.bundles.includes(pkg)) profile.dsh.profile.bundles.push(pkg);
}
function removeBundle(profile, pkg) {
  const bundles = profile.dsh?.profile?.bundles;
  if (bundles === void 0) return;
  const index = bundles.indexOf(pkg);
  if (index >= 0) bundles.splice(index, 1);
}
function pluginDependencyName(plugin) {
  return `@dsh-external/${plugin.name}`;
}
function readInstalledVersion(plugin) {
  const file = path.join(profileWebDir(), "node_modules", "@dsh-external", plugin.name, "package.json");
  if (!existsSync(file)) return void 0;
  const raw = readJsonFile(file);
  return typeof raw?.version === "string" ? raw.version : void 0;
}
function compareVersions(left, right) {
  const leftParts = left.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const rightParts = right.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const a = leftParts[index] ?? 0;
    const b = rightParts[index] ?? 0;
    if (a !== b) return a - b;
  }
  return 0;
}
function modeStatus(mode, root) {
  const link = presetsLinkPath();
  const modesRoot = path.join(root, "modes");
  let linkState = "missing";
  let current = null;
  try {
    current = readlinkSync(link);
    linkState = path.resolve(current) === path.resolve(modesRoot) ? "ok" : "stale";
  } catch {
    linkState = existsSync(link) ? "error" : "missing";
  }
  const linkPath = path.join(link, mode.id);
  const ready = linkState === "ok" && existsSync(path.join(modesRoot, mode.id));
  return {
    id: mode.id,
    name: mode.name,
    summary: mode.summary,
    linkState,
    ...linkState === "missing" ? {} : { linkPath },
    ready
  };
}
function pluginStatus(plugin) {
  const profile = readProfile() ?? emptyProfile();
  const pkg = pluginDependencyName(plugin);
  const dependency = profile.dependencies?.[pkg];
  const installedVersion = readInstalledVersion(plugin);
  const latestVersion = plugin.version;
  let installState;
  if (dependency === void 0) {
    installState = "not-installed";
  } else if (!existsSync(plugin.dir)) {
    installState = "broken";
  } else {
    const expectedLink = `link:${plugin.dir}`;
    const linked = dependency === expectedLink;
    const bundled = plugin.mountPlane !== "host" || profile.dsh?.profile?.bundles?.includes(pkg) === true;
    if (!linked) {
      installState = installedVersion === void 0 ? "broken" : "update-available";
    } else if (!bundled || installedVersion === void 0) {
      installState = "broken";
    } else if (compareVersions(installedVersion, latestVersion) < 0) {
      installState = "update-available";
    } else {
      installState = "installed";
    }
  }
  return {
    name: plugin.name,
    title: plugin.title,
    description: plugin.description,
    installState,
    ...installedVersion === void 0 ? {} : { installedVersion },
    latestVersion,
    mountPlane: plugin.mountPlane
  };
}
function getStatus(operations = [], root = locateRoot()) {
  return buildStatus(operations, root);
}
function buildStatus(operations = [], root = locateRoot()) {
  const modes = scanModes(root).map((mode) => modeStatus(mode, root));
  const plugins = scanPlugins(root).map((plugin) => pluginStatus(plugin));
  const modesReady = modes.filter((mode) => mode.ready).length;
  const pluginsInstalled = plugins.filter((plugin) => plugin.installState === "installed").length;
  const updatesAvailable = plugins.filter((plugin) => plugin.installState === "update-available").length;
  const profileError = profileErrorDetail();
  return {
    summary: {
      modesTotal: modes.length,
      modesReady,
      pluginsTotal: plugins.length,
      pluginsInstalled,
      updatesAvailable,
      busy: operations.some((operation) => operation.state === "queued" || operation.state === "running"),
      ...profileError === void 0 ? {} : { profileError }
    },
    modes,
    plugins,
    operations: [...operations]
  };
}
var CMD_METACHARS = /[\s"&|<>^()%!]/;
function quoteCmdArg(arg) {
  if (!CMD_METACHARS.test(arg)) return arg;
  return `"${arg.replace(/"/g, '""')}"`;
}
function spawnShim(file, args, options) {
  if (!IS_WIN) return spawn(file, [...args], { ...options, shell: false });
  const commandLine = [file, ...args].map(quoteCmdArg).join(" ");
  return spawn(process.env.ComSpec ?? "cmd.exe", ["/d", "/s", "/c", `"${commandLine}"`], {
    ...options,
    shell: false,
    windowsVerbatimArguments: true
  });
}
function spawnEnv() {
  const separator = IS_WIN ? ";" : ":";
  const parts = (process.env.PATH ?? "").split(separator).filter((part) => part !== "");
  const candidates = IS_WIN ? [path.dirname(process.execPath)] : ["/opt/homebrew/bin", "/usr/local/bin", path.join(homedir(), ".local", "bin"), path.dirname(process.execPath)];
  for (const bin of candidates) {
    if (bin !== "" && !parts.includes(bin)) parts.push(bin);
  }
  return { ...process.env, CI: "true", PATH: parts.join(separator) };
}
function spawnCollect(file, args, cwd, onOutput) {
  return new Promise((resolve) => {
    const child = spawnShim(file, args, {
      cwd,
      env: spawnEnv(),
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    const feed = (chunk, into) => {
      const text = chunk.toString();
      if (into === "out") stdout = (stdout + text).slice(-64 * 1024);
      else stderr = (stderr + text).slice(-64 * 1024);
      onOutput?.(text.trim());
    };
    child.stdout?.on("data", (chunk) => feed(chunk, "out"));
    child.stderr?.on("data", (chunk) => feed(chunk, "err"));
    child.on("error", (error) => {
      resolve({ code: 127, stdout, stderr: `${stderr}
${error.message}` });
    });
    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}
async function runPnpmInstall(cwd, onProgress) {
  onProgress?.("running pnpm install", 50);
  const result = await spawnCollect("npx", ["-y", "pnpm", "install", "--prefer-offline", "--no-frozen-lockfile"], cwd, (line) => {
    if (line !== "") onProgress?.(line.slice(0, 200));
  });
  if (result.code !== 0) {
    const tail = result.stderr.trim() || result.stdout.trim() || `exit code ${String(result.code)}`;
    throw new Error(`pnpm install failed: ${tail.slice(-1e3)}`);
  }
}
function ensureLinkType() {
  return IS_WIN ? "junction" : "dir";
}
function makeDirLink(src, dst) {
  if (IS_WIN && !existsAny(src)) return false;
  symlinkSync(src, dst, ensureLinkType());
  return true;
}
function linkPluginPeers(root = locateRoot()) {
  const runtime = path.join(dshHome(), "profiles", "node_modules", "@deepseek-ai");
  const localDeepseek = path.join(root, "plugins", "node_modules", "@deepseek-ai");
  mkdirSync(localDeepseek, { recursive: true });
  let names = [];
  try {
    names = readdirSync(runtime).filter((name2) => !name2.startsWith("."));
  } catch {
  }
  for (const extra of ["dsh-tools", "schemastery", "dsh-settings", "dsh-system-prompt", "dsh-mcp-client", "dsh-llm"]) {
    if (!names.includes(extra)) names.push(extra);
  }
  let deepseek = 0;
  for (const pkg of names) {
    const src = path.join(runtime, pkg);
    const dst = path.join(localDeepseek, pkg);
    let current = null;
    try {
      current = readlinkSync(dst);
    } catch {
    }
    if (current === src) continue;
    if (existsAny(dst)) renameSync(dst, `${dst}.bak-${Date.now()}`);
    if (!makeDirLink(src, dst)) continue;
    deepseek += 1;
  }
  const localExternal = path.join(root, "plugins", "node_modules", "@dsh-external");
  mkdirSync(localExternal, { recursive: true });
  let external = 0;
  for (const plugin of scanPlugins(root)) {
    const src = plugin.dir;
    const dst = path.join(localExternal, plugin.name);
    let current = null;
    try {
      current = readlinkSync(dst);
    } catch {
    }
    if (current === src) continue;
    if (existsAny(dst)) renameSync(dst, `${dst}.bak-${Date.now()}`);
    if (!makeDirLink(src, dst)) continue;
    external += 1;
  }
  return { deepseek, external };
}
function deployModes(root = locateRoot(), onProgress) {
  const target = path.join(root, "modes");
  const link = presetsLinkPath();
  mkdirSync(dshHome(), { recursive: true });
  onProgress?.("checking agent presets link", 20);
  if (existsAny(link)) {
    let current = null;
    try {
      current = readlinkSync(link);
    } catch {
      throw new Error(
        `refusing to replace ${link}: it is a real directory, not a symlink. Move it away manually (or keep it and manage modes through the CLI deploy script), then retry.`
      );
    }
    if (current !== null && path.resolve(current) === path.resolve(target)) {
      onProgress?.("agent presets link ok", 100);
      return `agent presets link ok: ${link} -> ${target}`;
    }
    const backup = `${link}.bak-${Date.now()}`;
    renameSync(link, backup);
    onProgress?.(`backed up existing agent presets link to ${backup}`, 50);
  }
  symlinkSync(target, link, ensureLinkType());
  onProgress?.("agent presets link ready", 100);
  return `agent presets link ready: ${link} -> ${target}`;
}
function repairMode(id, root = locateRoot(), onProgress) {
  const mode = requireMode(id, root);
  if (!existsSync(mode.dir)) throw new Error(`mode directory missing: ${mode.dir}`);
  onProgress?.(`repairing agent presets link for ${id}`, 10);
  const detail = deployModes(root, onProgress);
  return `${mode.id}: ${detail}`;
}
async function installOne(name2, options = {}, root = locateRoot()) {
  const plugin = requirePlugin(name2, root);
  const profile = ensureProfile();
  options.onProgress?.("writing profile", 10);
  const pkg = pluginDependencyName(plugin);
  profile.dependencies ??= {};
  profile.dependencies[pkg] = `link:${plugin.dir}`;
  if (plugin.mountPlane === "host") addBundle(profile, pkg);
  const backup = writeProfileWithBackup(profile);
  try {
    await runPnpmInstall(profileWebDir(), options.onProgress);
    options.onProgress?.("linking plugin peers", 90);
    linkPluginPeers(root);
    options.onProgress?.("done", 100);
    return `installed ${name2}@${plugin.version}`;
  } catch (error) {
    restoreProfile(backup);
    throw error;
  }
}
async function uninstallOne(name2, options = {}, root = locateRoot()) {
  const plugin = requirePlugin(name2, root);
  const profile = readProfile();
  const pkg = pluginDependencyName(plugin);
  if (profile === null || profile.dependencies?.[pkg] === void 0) {
    options.onProgress?.("not installed", 100);
    return `${name2} is not installed`;
  }
  options.onProgress?.("writing profile", 10);
  delete profile.dependencies?.[pkg];
  removeBundle(profile, pkg);
  const backup = writeProfileWithBackup(profile);
  try {
    await runPnpmInstall(profileWebDir(), options.onProgress);
    options.onProgress?.("linking plugin peers", 90);
    linkPluginPeers(root);
    options.onProgress?.("done", 100);
    return `uninstalled ${name2}`;
  } catch (error) {
    restoreProfile(backup);
    throw error;
  }
}
async function updateOne(name2, options = {}, root = locateRoot()) {
  const plugin = requirePlugin(name2, root);
  const profile = readProfile();
  const pkg = pluginDependencyName(plugin);
  if (profile === null || profile.dependencies?.[pkg] === void 0) {
    return installOne(name2, options, root);
  }
  return installOne(name2, options, root);
}

// src/types.ts
var RPC_CHANNEL = "/dsh-redteam-model";

// src/rpc.ts
var ENDPOINTS = /* @__PURE__ */ new Set(["status", "operation/start", "operation/cancel", "operations/clear"]);
var OPERATION_KINDS = /* @__PURE__ */ new Set(["deploy-modes", "install", "update", "uninstall", "repair"]);
var MAX_TARGETS = 15;
var BATCH_TARGETS = {
  install: "missing",
  update: "updates",
  uninstall: "installed"
};
function ok(value) {
  return { ok: true, value };
}
function asObject(payload) {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("payload must be an object");
  }
  return payload;
}
function knownPluginNames() {
  return scanPlugins().map((plugin) => plugin.name);
}
function knownModeNames() {
  return scanModes().map((mode) => mode.id);
}
function validateTargets(kind, target, targets) {
  if (kind === "deploy-modes") {
    const allowed = /* @__PURE__ */ new Set([...knownModeNames(), "modes"]);
    if (!allowed.has(target)) throw new Error(`unknown deploy-modes target: ${target}`);
    if (targets !== void 0 && targets.length > 0) throw new Error("deploy-modes does not accept targets");
    return [target];
  }
  if (kind === "repair") {
    if (targets !== void 0 && targets.length > 0) throw new Error("repair does not accept targets");
    const modes = new Set(knownModeNames());
    const plugins2 = new Set(knownPluginNames());
    if (modes.has(target) || plugins2.has(target)) return [target];
    throw new Error(`unknown repair target: ${target}`);
  }
  const plugins = new Set(knownPluginNames());
  const names = [];
  if (targets !== void 0) {
    if (!Array.isArray(targets)) throw new Error("targets must be an array");
    if (targets.length === 0 || targets.length > MAX_TARGETS) {
      throw new Error(`targets must contain 1..${MAX_TARGETS} entries`);
    }
    if (target !== BATCH_TARGETS[kind] && !plugins.has(target)) {
      throw new Error(`unknown plugin: ${target}`);
    }
    for (const raw of targets) {
      if (typeof raw !== "string" || raw === "") throw new Error("targets entries must be non-empty strings");
      if (!plugins.has(raw)) throw new Error(`unknown plugin in targets: ${raw}`);
      if (!names.includes(raw)) names.push(raw);
    }
  } else {
    if (!plugins.has(target)) throw new Error(`unknown plugin: ${target}`);
    names.push(target);
  }
  return names;
}
function operationRunner(kind, target) {
  return async (update) => {
    const onProgress = (phase, percent) => {
      update({ detail: phase, ...percent === void 0 ? {} : { percent } });
    };
    if (kind === "deploy-modes") return deployModes(void 0, onProgress);
    if (kind === "repair") {
      if (knownModeNames().includes(target)) return repairMode(target, void 0, onProgress);
      return installOne(target, { onProgress }, void 0);
    }
    if (kind === "install") return installOne(target, { onProgress }, void 0);
    if (kind === "update") return updateOne(target, { onProgress }, void 0);
    if (kind === "uninstall") return uninstallOne(target, { onProgress }, void 0);
    throw new Error(`unsupported operation kind: ${kind}`);
  };
}
function handleStart(payload, queue) {
  const kind = payload.kind;
  if (typeof kind !== "string" || !OPERATION_KINDS.has(kind)) {
    throw new Error("kind must be one of deploy-modes|install|update|uninstall|repair");
  }
  const target = payload.target;
  if (typeof target !== "string" || target === "") throw new Error("target must be a non-empty string");
  const names = validateTargets(kind, target, payload.targets);
  let firstId;
  for (const name2 of names) {
    if (kind === "install" || kind === "update" || kind === "uninstall") requirePlugin(name2);
    if (kind === "repair") {
      if (knownModeNames().includes(name2)) requireMode(name2);
      else requirePlugin(name2);
    }
    const id = queue.enqueue(kind, name2, operationRunner(kind, name2));
    if (firstId === void 0) firstId = id;
  }
  return ok({ id: firstId });
}
function handleEndpoint(endpoint, rawPayload, queue) {
  if (!ENDPOINTS.has(endpoint)) throw new Error(`unknown endpoint: ${endpoint}`);
  if (endpoint === "status") {
    return ok(getStatus(queue.list()));
  }
  if (endpoint === "operations/clear") {
    queue.clearSettled();
    return ok({ cleared: true });
  }
  if (endpoint === "operation/cancel") {
    const payload = asObject(rawPayload);
    const id = payload.id;
    if (typeof id !== "string" || id === "") throw new Error("id must be a non-empty string");
    return ok({ cancelled: queue.cancel(id) });
  }
  if (endpoint === "operation/start") {
    return handleStart(asObject(rawPayload), queue);
  }
  throw new Error(`unknown endpoint: ${endpoint}`);
}
function registerModelRpc(connection, queue) {
  connection.rpc.handle(RPC_CHANNEL, async (endpoint, rawPayload) => {
    try {
      return handleEndpoint(endpoint, rawPayload, queue);
    } catch (error) {
      return { ok: false, error: { message: error instanceof Error ? error.message : String(error) } };
    }
  }, { authority: "loopback" });
}

// src/index.ts
var name = "dsh-redteam-model";
var inject = ["connection"];
function apply(ctx) {
  const queue = new OperationQueue();
  ctx.inject(["connection"], (web) => {
    const { connection } = web;
    registerModelRpc(connection, queue);
  });
  ctx.effect(() => () => {
    queue.dispose();
  }, "dsh-redteam-model: queue");
}
export {
  OperationQueue,
  apply,
  getStatus,
  inject,
  name,
  scanModes,
  scanPlugins
};
