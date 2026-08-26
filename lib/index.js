// src/index.ts
import path3 from "node:path";

// src/conversationViewSettings.ts
import { settingsNamespace } from "@deepseek-ai/dsh-settings";
import z from "@deepseek-ai/schemastery";

// src/conversationViewState.ts
var DEFAULT_CONVERSATION_VIEW_SETTINGS = Object.freeze({
  showCampaignMemory: true,
  showAttackAtlas: true,
  showRedteamResults: true,
  showHunter: true,
  showWebshellManager: true
});
function effectiveConversationViewSettings(snapshot) {
  return snapshot.status === "ready" && snapshot.value !== void 0 ? snapshot.value : DEFAULT_CONVERSATION_VIEW_SETTINGS;
}
function conversationViewWriteApplied(snapshot, field, expected) {
  return snapshot.status === "ready" && snapshot.value?.[field] === expected;
}

// src/conversationViewSettings.ts
var CONVERSATION_VIEW_SETTINGS_NAMESPACE = settingsNamespace("redteam-manager-ui");
var ConversationViewSettingsSchema = z.object({
  showCampaignMemory: z.boolean().default(true),
  showAttackAtlas: z.boolean().default(true),
  showRedteamResults: z.boolean().default(true),
  showHunter: z.boolean().default(true),
  showWebshellManager: z.boolean().default(true)
});
function registerConversationViewSettings(ctx) {
  ctx.inject(["settings"], (services) => {
    const { settings } = services;
    settings.register(CONVERSATION_VIEW_SETTINGS_NAMESPACE, ConversationViewSettingsSchema, { applies: "live" });
  });
}

// src/manager.ts
import { spawn } from "node:child_process";
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
  const configured = process.env.DSH_HOME?.trim();
  if (configured === void 0 || configured === "") return path.join(homedir(), ".dsh");
  if (configured === "~") return homedir();
  if (configured.startsWith("~/") || configured.startsWith("~\\")) {
    return path.resolve(homedir(), configured.slice(2));
  }
  return path.resolve(configured);
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
  const digests = readModeDigests(root);
  const ids = readdirSync(modesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).filter((id) => existsSync(path.join(modesRoot, id, "preset.yml")));
  const modes = ids.map((id) => {
    const dir = path.join(modesRoot, id);
    const text = readFileSync(path.join(dir, "preset.yml"), "utf8");
    const name2 = /^name:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? id;
    const summary = /^description:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? "";
    const orderRaw = /^order:\s*(\d+)$/m.exec(text)?.[1];
    const order = orderRaw === void 0 ? void 0 : Number(orderRaw);
    const digest = digests[id];
    return { id, name: name2, summary, dir, ...digest === void 0 ? {} : { digest }, ...order === void 0 ? {} : { order } };
  }).filter((mode) => mode !== null);
  return modes.sort((left, right) => {
    const lo = left.order ?? 99;
    const ro = right.order ?? 99;
    if (lo !== ro) return lo - ro;
    return left.id.localeCompare(right.id);
  });
}
function readModeDigests(root) {
  const raw = readJsonFile(path.join(root, "lib", "mode-digests.json"));
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
  const manifest = raw;
  if (manifest.schemaVersion !== 1 || typeof manifest.modes !== "object" || manifest.modes === null || Array.isArray(manifest.modes)) {
    return {};
  }
  const digests = {};
  for (const [id, digest] of Object.entries(manifest.modes)) {
    if (typeof digest === "string" && /^sha256:[0-9a-f]{64}$/.test(digest)) digests[id] = digest;
  }
  return digests;
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
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
}
function writeProfileWithBackup(profile) {
  const file = profilePackageFile();
  const backup = backupFile(file);
  atomicWriteJson(file, profile);
  return backup;
}
function snapshotFile(file) {
  return existsSync(file) ? { file, existed: true, body: readFileSync(file) } : { file, existed: false };
}
function restoreFileSnapshot(snapshot) {
  if (!snapshot.existed) {
    rmSync(snapshot.file, { force: true });
    return;
  }
  if (snapshot.body === void 0) throw new Error(`snapshot body missing: ${snapshot.file}`);
  const temp = `${snapshot.file}.restore-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  try {
    writeFileSync(temp, snapshot.body, { flag: "wx" });
    renameSync(temp, snapshot.file);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
}
function profileMutationSnapshots() {
  return [
    snapshotFile(profilePackageFile()),
    snapshotFile(path.join(profileWebDir(), "pnpm-lock.yaml"))
  ];
}
function restoreFileSnapshots(snapshots) {
  for (const snapshot of snapshots) restoreFileSnapshot(snapshot);
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
  profile.dsh.profile.bundles = bundles.filter((candidate) => candidate !== pkg);
}
function normalizeBundle(profile, plugin) {
  const pkg = pluginDependencyName(plugin);
  removeBundle(profile, pkg);
  if (plugin.mountPlane === "host") addBundle(profile, pkg);
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
  const modeDir = mode.dir;
  if (mode.digest === void 0) {
    return {
      id: mode.id,
      name: mode.name,
      summary: mode.summary,
      linkState: "error",
      linkPath: path.join(link, mode.id),
      ready: false
    };
  }
  let linkState = "missing";
  let linkPath;
  try {
    const current = readlinkSync(link);
    linkPath = path.join(link, mode.id);
    linkState = path.resolve(current) === path.resolve(modesRoot) ? "ok" : "stale";
  } catch {
    if (existsSync(link)) {
      linkPath = path.join(link, mode.id);
      let stat = null;
      try {
        stat = lstatSync(linkPath);
      } catch {
        stat = null;
      }
      try {
        const marker = readModeMarker(link);
        const entry = marker.marker.modes[mode.id];
        const legacyOwned = marker.legacyOwned.has(mode.id);
        if (entry?.digest === mode.digest && stat !== null && stat.isDirectory()) {
          linkState = "ok";
        } else if ((entry !== void 0 || legacyOwned) && stat !== null && stat.isDirectory()) {
          linkState = "stale";
        } else if (stat !== null && stat.isSymbolicLink()) {
          try {
            const current = readlinkSync(linkPath);
            linkState = path.resolve(current) === path.resolve(modeDir) ? "stale" : "error";
          } catch {
            linkState = "error";
          }
        } else if (stat !== null) {
          linkState = "error";
        } else {
          linkState = "missing";
        }
      } catch {
        linkState = "error";
      }
    } else {
      linkState = "missing";
    }
  }
  const ready = linkState === "ok" && existsSync(modeDir);
  return {
    id: mode.id,
    name: mode.name,
    summary: mode.summary,
    linkState,
    ...linkPath === void 0 ? {} : { linkPath },
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
    const bundleCount = profile.dsh?.profile?.bundles?.filter((candidate) => candidate === pkg).length ?? 0;
    const bundled = plugin.mountPlane === "host" ? bundleCount === 1 : bundleCount === 0;
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
  const runArgs = ["-y", "pnpm", "install", "--prefer-offline", "--no-frozen-lockfile"];
  const hadLockfile = existsSync(path.join(cwd, "pnpm-lock.yaml"));
  let result = await spawnCollect("npx", runArgs, cwd, (line) => {
    if (line !== "") onProgress?.(line.slice(0, 200));
  });
  const output = `${result.stdout}
${result.stderr}`;
  const releaseAgeError = /(?:^|[^A-Za-z0-9_])ERR_PNPM_(?:MINIMUM_RELEASE_AGE_VIOLATION|NO_MATURE_MATCHING_VERSION)(?![A-Za-z0-9_])/m;
  if (result.code !== 0 && hadLockfile && releaseAgeError.test(output)) {
    onProgress?.("retrying locked profile after release-age verification failure", 55);
    result = await spawnCollect("npx", [...runArgs, "--config.minimumReleaseAge=0"], cwd, (line) => {
      if (line !== "") onProgress?.(line.slice(0, 200));
    });
  }
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
function replacePeerLink(source, destination, changes) {
  if (IS_WIN && !existsAny(source)) return false;
  let current = null;
  try {
    current = readlinkSync(destination);
  } catch {
  }
  if (current !== null && path.resolve(current) === path.resolve(source)) return false;
  let backup;
  if (existsAny(destination)) {
    backup = `${destination}.bak-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    renameSync(destination, backup);
  }
  try {
    if (!makeDirLink(source, destination)) {
      if (backup !== void 0) renameSync(backup, destination);
      return false;
    }
    changes.push({ source, destination, ...backup === void 0 ? {} : { backup } });
    return true;
  } catch (error) {
    if (backup !== void 0 && !existsAny(destination) && existsAny(backup)) renameSync(backup, destination);
    throw error;
  }
}
function rollbackPeerLinks(changes) {
  for (const change of [...changes].reverse()) {
    if (isOurSymlink(change.destination, change.source)) unlinkSync(change.destination);
    if (change.backup !== void 0 && !existsAny(change.destination) && existsAny(change.backup)) {
      renameSync(change.backup, change.destination);
    }
  }
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
  const changes = [];
  try {
    let deepseek = 0;
    for (const pkg of names) {
      const src = path.join(runtime, pkg);
      const dst = path.join(localDeepseek, pkg);
      if (replacePeerLink(src, dst, changes)) deepseek += 1;
    }
    const localExternal = path.join(root, "plugins", "node_modules", "@dsh-external");
    mkdirSync(localExternal, { recursive: true });
    let external = 0;
    for (const plugin of scanPlugins(root)) {
      const src = plugin.dir;
      const dst = path.join(localExternal, plugin.name);
      if (replacePeerLink(src, dst, changes)) external += 1;
    }
    return { deepseek, external };
  } catch (error) {
    try {
      rollbackPeerLinks(changes);
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], "plugin peer linking failed and rollback was incomplete");
    }
    throw error;
  }
}
function deployModes(root = locateRoot(), onProgress, ids) {
  const target = path.join(root, "modes");
  const requested = ids === void 0 ? void 0 : new Set(ids);
  for (const mode of scanModes(root)) {
    if ((requested === void 0 || requested.has(mode.id)) && mode.digest === void 0) {
      throw new Error(`mode digest missing: ${mode.id}`);
    }
  }
  const link = presetsLinkPath();
  mkdirSync(dshHome(), { recursive: true });
  onProgress?.("checking agent presets link", 20);
  let previousLinkBackup;
  if (existsAny(link)) {
    let current = null;
    try {
      current = readlinkSync(link);
    } catch {
      return deployModesIntoDirectory(link, root, onProgress, ids);
    }
    if (current !== null && path.resolve(current) === path.resolve(target)) {
      onProgress?.("agent presets link ok", 100);
      return `agent presets link ok: ${link} -> ${target}`;
    }
    previousLinkBackup = `${link}.bak-${Date.now()}`;
    renameSync(link, previousLinkBackup);
    onProgress?.(`backed up existing agent presets link to ${previousLinkBackup}`, 50);
  }
  try {
    symlinkSync(target, link, ensureLinkType());
  } catch (error) {
    if (previousLinkBackup !== void 0 && !existsAny(link) && existsAny(previousLinkBackup)) {
      renameSync(previousLinkBackup, link);
    }
    throw error;
  }
  onProgress?.("agent presets link ready", 100);
  return `agent presets link ready: ${link} -> ${target}`;
}
var MODE_MARKER_FILE = ".dsh-redteam-model.json";
var MODE_MARKER_BACKUP_FILE = ".dsh-redteam-model.backup.json";
var MODE_MARKER_OWNER = "@dsh-external/dsh-redteam-model";
var LEGACY_STALE_DIGEST = `sha256:${"0".repeat(64)}`;
function emptyModeMarker() {
  return { schemaVersion: 2, owner: MODE_MARKER_OWNER, modes: {} };
}
function modeMarkerFile(directory) {
  return path.join(directory, MODE_MARKER_FILE);
}
function modeMarkerBackupFile(directory) {
  return path.join(directory, MODE_MARKER_BACKUP_FILE);
}
function readMarkerJson(file) {
  if (!existsAny(file)) return void 0;
  const info = lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`unsafe mode marker: ${file}`);
  return JSON.parse(readFileSync(file, "utf8"));
}
function assertSafeModeMarkerPaths(directory) {
  for (const file of [modeMarkerFile(directory), modeMarkerBackupFile(directory)]) {
    if (!existsAny(file)) continue;
    const info = lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`unsafe mode marker: ${file}`);
  }
}
function parseModeMarker(raw) {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const candidate = raw;
  if (candidate.schemaVersion === 2) {
    if (candidate.owner !== MODE_MARKER_OWNER || typeof candidate.modes !== "object" || candidate.modes === null || Array.isArray(candidate.modes)) {
      return null;
    }
    const modes = {};
    for (const [id, value] of Object.entries(candidate.modes)) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
      const entry = value;
      if (typeof entry.digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(entry.digest)) return null;
      modes[id] = { digest: entry.digest, deployedAt: typeof entry.deployedAt === "number" ? entry.deployedAt : 0 };
    }
    return { marker: { schemaVersion: 2, owner: MODE_MARKER_OWNER, modes }, legacyOwned: /* @__PURE__ */ new Set() };
  }
  const legacyOwned = /* @__PURE__ */ new Set();
  for (const [id, value] of Object.entries(raw)) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const entry = value;
    if (typeof entry.source !== "string") return null;
    legacyOwned.add(id);
  }
  return { marker: emptyModeMarker(), legacyOwned };
}
function readModeMarker(directory) {
  assertSafeModeMarkerPaths(directory);
  const primary = modeMarkerFile(directory);
  const backup = modeMarkerBackupFile(directory);
  let primaryError;
  try {
    const raw = readMarkerJson(primary);
    if (raw === void 0) {
      const backupRaw = readMarkerJson(backup);
      if (backupRaw === void 0) return { marker: emptyModeMarker(), legacyOwned: /* @__PURE__ */ new Set(), recoveredFromBackup: false };
      const backupParsed = parseModeMarker(backupRaw);
      if (backupParsed !== null) return { ...backupParsed, recoveredFromBackup: true };
      throw new Error(`invalid mode marker backup: ${backup}`);
    }
    const parsed = parseModeMarker(raw);
    if (parsed !== null) return { ...parsed, recoveredFromBackup: false };
    primaryError = new Error(`invalid mode marker: ${primary}`);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("unsafe mode marker:")) throw error;
    primaryError = error;
  }
  try {
    const raw = readMarkerJson(backup);
    const parsed = raw === void 0 ? null : parseModeMarker(raw);
    if (parsed !== null) return { ...parsed, recoveredFromBackup: true };
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("unsafe mode marker:")) throw error;
  }
  const detail = primaryError instanceof Error ? primaryError.message : String(primaryError);
  throw new Error(`invalid mode marker: ${primary}: ${detail}`);
}
function atomicWriteRegularFile(file, body) {
  if (existsAny(file)) {
    const info = lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`unsafe mode marker: ${file}`);
  }
  const directory = path.dirname(file);
  const temp = path.join(directory, `.${path.basename(file)}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  try {
    writeFileSync(temp, body, { encoding: "utf8", flag: "wx", mode: 384 });
    renameSync(temp, file);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
}
function writeModeMarker(directory, marker) {
  const body = `${JSON.stringify(marker, null, 2)}
`;
  const backup = modeMarkerBackupFile(directory);
  const primary = modeMarkerFile(directory);
  assertSafeModeMarkerPaths(directory);
  atomicWriteRegularFile(backup, body);
  atomicWriteRegularFile(primary, body);
}
function isOurSymlink(destination, source) {
  try {
    return lstatSync(destination).isSymbolicLink() && path.resolve(readlinkSync(destination)) === path.resolve(source);
  } catch {
    return false;
  }
}
function deployModesIntoDirectory(directory, root, onProgress, ids) {
  const requested = ids === void 0 ? void 0 : new Set(ids);
  const allModes = scanModes(root);
  const modes = allModes.filter((mode) => requested === void 0 || requested.has(mode.id));
  const current = readModeMarker(directory);
  const marker = {
    schemaVersion: 2,
    owner: MODE_MARKER_OWNER,
    modes: { ...current.marker.modes }
  };
  const knownModes = new Set(allModes.map((mode) => mode.id));
  for (const id of current.legacyOwned) {
    if (knownModes.has(id) && marker.modes[id] === void 0) {
      marker.modes[id] = { digest: LEGACY_STALE_DIGEST, deployedAt: 0 };
    }
  }
  let copied = 0;
  let unchanged = 0;
  const skipped = [];
  for (const mode of modes) {
    if (mode.digest === void 0) throw new Error(`mode digest missing: ${mode.id}`);
    const destination = path.join(directory, mode.id);
    const entry = marker.modes[mode.id];
    const owned = entry !== void 0;
    const destinationExists = existsAny(destination);
    const legacySymlink = destinationExists && isOurSymlink(destination, mode.dir);
    if (destinationExists) {
      if (!legacySymlink && (!owned || !lstatSync(destination).isDirectory())) {
        skipped.push(`${mode.id} (existing entry)`);
        continue;
      }
    }
    if (!legacySymlink && owned && entry?.digest === mode.digest && destinationExists && lstatSync(destination).isDirectory()) {
      unchanged += 1;
      continue;
    }
    const suffix2 = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const staging = path.join(directory, `.${mode.id}.dsh-redteam-model.tmp-${suffix2}`);
    const backup = `${destination}.bak-${suffix2}`;
    const markerSnapshots = [
      snapshotFile(modeMarkerFile(directory)),
      snapshotFile(modeMarkerBackupFile(directory))
    ];
    let backedUp = false;
    let promoted = false;
    let markerWriteAttempted = false;
    try {
      cpSync(mode.dir, staging, { recursive: true });
      if ((owned || legacySymlink) && existsAny(destination)) {
        renameSync(destination, backup);
        backedUp = true;
      }
      renameSync(staging, destination);
      promoted = true;
      marker.modes[mode.id] = { digest: mode.digest, deployedAt: Date.now() };
      markerWriteAttempted = true;
      writeModeMarker(directory, marker);
    } catch (error) {
      const rollbackErrors = [];
      try {
        rmSync(staging, { recursive: true, force: true });
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
      if (promoted) {
        try {
          rmSync(destination, { recursive: true, force: true });
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      }
      if (backedUp && !existsAny(destination) && existsAny(backup)) {
        try {
          renameSync(backup, destination);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      }
      if (markerWriteAttempted) {
        try {
          restoreFileSnapshots(markerSnapshots);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      }
      if (rollbackErrors.length > 0) {
        throw new AggregateError([error, ...rollbackErrors], `mode deployment failed and rollback was incomplete: ${mode.id}`);
      }
      throw error;
    }
    copied += 1;
  }
  if (copied === 0 && (current.recoveredFromBackup || current.legacyOwned.size > 0 || !existsAny(modeMarkerFile(directory)) || !existsAny(modeMarkerBackupFile(directory)))) {
    writeModeMarker(directory, marker);
  }
  const suffix = skipped.length > 0 ? `; skipped existing entries: ${skipped.join(", ")}` : "";
  const detail = `copied ${copied} modes into existing agent presets directory; ${unchanged} already current${suffix}`;
  onProgress?.(detail, 100);
  return detail;
}
function repairMode(id, root = locateRoot(), onProgress) {
  const mode = requireMode(id, root);
  if (!existsSync(mode.dir)) throw new Error(`mode directory missing: ${mode.dir}`);
  onProgress?.(`repairing agent presets link for ${id}`, 10);
  const detail = deployModes(root, onProgress, [id]);
  return `${mode.id}: ${detail}`;
}
function deployGlobalAgents(root = locateRoot(), onProgress) {
  const src = path.join(root, "AGENTS.md");
  if (!existsSync(src)) return "global AGENTS.md source missing from package: skipped";
  const dst = path.join(dshHome(), "AGENTS.md");
  onProgress?.("checking global AGENTS.md");
  if (!existsAny(dst)) {
    mkdirSync(dshHome(), { recursive: true });
    copyFileSync(src, dst);
    const detail = `global instructions installed: ${dst} (effective on new sessions)`;
    onProgress?.(detail);
    return detail;
  }
  let identical = false;
  try {
    identical = readFileSync(src).equals(readFileSync(dst));
  } catch {
  }
  if (identical) return `global AGENTS.md already matches this package: ${dst}`;
  return `existing global AGENTS.md left untouched: ${dst} \u2014 to adopt this package version, back it up and copy ${src} over it manually`;
}
async function installOne(name2, options = {}, root = locateRoot()) {
  const plugin = requirePlugin(name2, root);
  const profileDirectoryExisted = existsAny(profileWebDir());
  const snapshots = profileMutationSnapshots();
  try {
    const profile = ensureProfile();
    options.onProgress?.("writing profile", 10);
    const pkg = pluginDependencyName(plugin);
    profile.dependencies ??= {};
    profile.dependencies[pkg] = `link:${plugin.dir}`;
    normalizeBundle(profile, plugin);
    if (snapshots[0].existed) writeProfileWithBackup(profile);
    else atomicWriteJson(profilePackageFile(), profile);
    await runPnpmInstall(profileWebDir(), options.onProgress);
    options.onProgress?.("linking plugin peers", 90);
    linkPluginPeers(root);
    options.onProgress?.("done", 100);
    return `installed ${name2}@${plugin.version}`;
  } catch (error) {
    restoreFileSnapshots(snapshots);
    if (!profileDirectoryExisted) {
      try {
        rmdirSync(profileWebDir());
      } catch {
      }
    }
    throw error;
  }
}
async function uninstallOne(name2, options = {}, root = locateRoot()) {
  const plugin = requirePlugin(name2, root);
  const snapshots = profileMutationSnapshots();
  const profile = readProfile();
  const pkg = pluginDependencyName(plugin);
  if (profile === null || profile.dependencies?.[pkg] === void 0) {
    options.onProgress?.("not installed", 100);
    return `${name2} is not installed`;
  }
  try {
    options.onProgress?.("writing profile", 10);
    delete profile.dependencies?.[pkg];
    removeBundle(profile, pkg);
    writeProfileWithBackup(profile);
    await runPnpmInstall(profileWebDir(), options.onProgress);
    options.onProgress?.("linking plugin peers", 90);
    linkPluginPeers(root);
    options.onProgress?.("done", 100);
    return `uninstalled ${name2}`;
  } catch (error) {
    restoreFileSnapshots(snapshots);
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

// src/operations.ts
import { randomUUID } from "node:crypto";
import { lstatSync as lstatSync2, mkdirSync as mkdirSync2, readFileSync as readFileSync2, renameSync as renameSync2, rmSync as rmSync2, writeFileSync as writeFileSync2 } from "node:fs";
import path2 from "node:path";
var OPERATION_KINDS = /* @__PURE__ */ new Set(["deploy-modes", "install", "update", "uninstall", "repair"]);
var OPERATION_STATES = /* @__PURE__ */ new Set(["queued", "running", "done", "warned", "failed", "cancelled"]);
var INTERRUPTED_DETAIL = "interrupted by previous dsh web restart";
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isSettled(state) {
  return state === "done" || state === "warned" || state === "failed" || state === "cancelled";
}
function parseOperationRecord(value) {
  if (!isRecord(value)) return void 0;
  if (typeof value.id !== "string" || !/^op-[0-9]+$/.test(value.id)) return void 0;
  const numericId = Number.parseInt(value.id.slice(3), 10);
  if (!Number.isSafeInteger(numericId) || numericId < 1) return void 0;
  if (typeof value.kind !== "string" || !OPERATION_KINDS.has(value.kind)) return void 0;
  if (typeof value.target !== "string") return void 0;
  if (typeof value.state !== "string" || !OPERATION_STATES.has(value.state)) return void 0;
  if (value.percent !== void 0 && value.percent !== null && (typeof value.percent !== "number" || !Number.isFinite(value.percent))) return void 0;
  if (value.detail !== void 0 && typeof value.detail !== "string") return void 0;
  if (value.error !== void 0 && typeof value.error !== "string") return void 0;
  return {
    id: value.id,
    kind: value.kind,
    target: value.target,
    state: value.state,
    ...value.percent === void 0 ? {} : { percent: value.percent },
    ...value.detail === void 0 ? {} : { detail: value.detail },
    ...value.error === void 0 ? {} : { error: value.error }
  };
}
var OperationQueue = class {
  constructor(persistenceFile) {
    this.persistenceFile = persistenceFile;
    this.load();
    this.persist();
  }
  records = [];
  maxRecords = 50;
  nextId = 1;
  tail = Promise.resolve();
  closed = false;
  writeSequence = 0;
  writerId = randomUUID();
  persistenceOwnership = "unclaimed";
  enqueue(kind, target, runner) {
    if (this.closed) throw new Error("operation queue is closed");
    this.ensureCapacity(1);
    if (!Number.isSafeInteger(this.nextId)) throw new Error("operation id space exhausted");
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
    this.persist();
    this.tail = this.tail.then(() => this.run(record, runner)).catch(() => {
    });
    return id;
  }
  cancel(id) {
    const record = this.records.find((candidate) => candidate.id === id && candidate.state === "queued");
    if (record === void 0) return false;
    this.update(record, { state: "cancelled", percent: 100, detail: "cancelled" });
    this.persist();
    return true;
  }
  clearSettled() {
    let changed = false;
    for (let index = this.records.length - 1; index >= 0; index -= 1) {
      const state = this.records[index]?.state;
      if (state !== void 0 && isSettled(state)) {
        this.records.splice(index, 1);
        changed = true;
      }
    }
    if (changed) this.persist();
  }
  list() {
    return this.records.slice();
  }
  whenIdle() {
    return this.tail;
  }
  /** Make a multi-record RPC enqueue atomic with respect to the bounded queue. */
  ensureCapacity(count) {
    if (this.closed) throw new Error("operation queue is closed");
    if (!Number.isSafeInteger(count) || count < 0) throw new Error("operation count must be a non-negative integer");
    const active = this.records.filter((record) => !isSettled(record.state)).length;
    if (active + count > this.maxRecords) {
      throw new Error(`operation queue capacity exceeded (maximum ${String(this.maxRecords)} active operations)`);
    }
    const requiredRemoval = Math.max(0, this.records.length + count - this.maxRecords);
    let remove = requiredRemoval;
    for (let index = 0; index < this.records.length && remove > 0; ) {
      if (isSettled(this.records[index].state)) {
        this.records.splice(index, 1);
        remove -= 1;
      } else {
        index += 1;
      }
    }
    if (remove !== 0) throw new Error("operation queue capacity invariant violated");
    if (requiredRemoval > 0) this.persist();
  }
  /** Host lifecycle cleanup: cancel queued work; running work is left to settle. */
  dispose() {
    this.closed = true;
    let changed = false;
    for (const record of this.records) {
      if (record.state === "queued") {
        this.update(record, { state: "cancelled", percent: 100, detail: "cancelled on shutdown" });
        changed = true;
      }
    }
    if (changed) {
      this.persist();
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
    this.persist();
    try {
      const outcome = await runner((patch) => this.update(record, patch));
      if (typeof outcome === "string") {
        this.update(record, { state: "done", percent: 100, detail: outcome });
      } else {
        this.update(record, { state: outcome.state, percent: 100, detail: outcome.detail });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.update(record, {
        state: "failed",
        percent: 100,
        detail: message,
        error: message
      });
    } finally {
      this.persist();
    }
  }
  load() {
    if (this.persistenceFile === void 0) return;
    try {
      if (!lstatSync2(this.persistenceFile).isFile()) return;
      const parsed = JSON.parse(readFileSync2(this.persistenceFile, "utf8"));
      if (!isRecord(parsed) || parsed.schemaVersion !== 1 || !Array.isArray(parsed.records)) return;
      const seen = /* @__PURE__ */ new Set();
      const loaded = [];
      let maxId = 0;
      for (const candidate of parsed.records) {
        const record = parseOperationRecord(candidate);
        if (record === void 0 || seen.has(record.id)) return;
        seen.add(record.id);
        maxId = Math.max(maxId, Number.parseInt(record.id.slice(3), 10));
        if (record.state === "queued" || record.state === "running") {
          loaded.push({
            ...record,
            state: "failed",
            percent: 100,
            detail: INTERRUPTED_DETAIL,
            error: INTERRUPTED_DETAIL
          });
        } else {
          loaded.push(record);
        }
      }
      const persistedNextId = parsed.nextId;
      if (persistedNextId !== void 0 && (!Number.isSafeInteger(persistedNextId) || persistedNextId < 1)) return;
      this.records.push(...loaded.slice(-this.maxRecords));
      this.nextId = Math.max(maxId + 1, persistedNextId ?? 1);
    } catch {
    }
  }
  persist() {
    if (this.persistenceFile === void 0 || this.persistenceOwnership === "lost") return;
    let temporaryFile;
    try {
      try {
        if (!lstatSync2(this.persistenceFile).isFile()) return;
        if (this.persistenceOwnership === "owned") {
          const current = JSON.parse(readFileSync2(this.persistenceFile, "utf8"));
          if (!isRecord(current) || current.writerId !== this.writerId) {
            this.persistenceOwnership = "lost";
            return;
          }
        }
      } catch (error) {
        if (!isRecord(error) || error.code !== "ENOENT") return;
      }
      const directory = path2.dirname(this.persistenceFile);
      mkdirSync2(directory, { recursive: true });
      this.writeSequence += 1;
      temporaryFile = path2.join(
        directory,
        `.${path2.basename(this.persistenceFile)}.${process.pid}.${this.writeSequence}.tmp`
      );
      const payload = {
        schemaVersion: 1,
        writerId: this.writerId,
        nextId: this.nextId,
        records: this.records
      };
      writeFileSync2(temporaryFile, `${JSON.stringify(payload, null, 2)}
`, { flag: "wx", mode: 384 });
      renameSync2(temporaryFile, this.persistenceFile);
      temporaryFile = void 0;
      this.persistenceOwnership = "owned";
    } catch {
    } finally {
      if (temporaryFile !== void 0) {
        try {
          rmSync2(temporaryFile, { force: true });
        } catch {
        }
      }
    }
  }
};

// src/types.ts
var RPC_CHANNEL = "/dsh-redteam-model";

// src/rpc.ts
var ENDPOINTS = /* @__PURE__ */ new Set(["status", "operation/start", "operation/cancel", "operations/clear"]);
var OPERATION_KINDS2 = /* @__PURE__ */ new Set(["deploy-modes", "install", "update", "uninstall", "repair"]);
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
    const modeResult = (detail) => {
      return detail.includes("skipped existing entries:") ? { state: "warned", detail } : detail;
    };
    if (kind === "deploy-modes") {
      if (target === "modes") {
        const agentsNotice = deployGlobalAgents(void 0, onProgress);
        const detail = deployModes(void 0, onProgress);
        return modeResult(`${agentsNotice}
${detail}`);
      }
      return modeResult(repairMode(target, void 0, onProgress));
    }
    if (kind === "repair") {
      if (knownModeNames().includes(target)) return modeResult(repairMode(target, void 0, onProgress));
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
  if (typeof kind !== "string" || !OPERATION_KINDS2.has(kind)) {
    throw new Error("kind must be one of deploy-modes|install|update|uninstall|repair");
  }
  const target = payload.target;
  if (typeof target !== "string" || target === "") throw new Error("target must be a non-empty string");
  const rawTargets = payload.targets;
  if (rawTargets !== void 0 && !Array.isArray(rawTargets)) throw new Error("targets must be an array");
  const names = validateTargets(kind, target, rawTargets);
  for (const name2 of names) {
    if (kind === "install" || kind === "update" || kind === "uninstall") requirePlugin(name2);
    if (kind === "repair") {
      if (knownModeNames().includes(name2)) requireMode(name2);
      else requirePlugin(name2);
    }
  }
  queue.ensureCapacity(names.length);
  let firstId;
  for (const name2 of names) {
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
  registerConversationViewSettings(ctx);
  const queue = new OperationQueue(path3.join(profileWebDir(), ".dsh-redteam-model-operations.json"));
  ctx.inject(["connection"], (web) => {
    const { connection } = web;
    registerModelRpc(connection, queue);
  });
  ctx.effect(() => () => {
    queue.dispose();
  }, "dsh-redteam-model: queue");
}
export {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  OperationQueue,
  apply,
  conversationViewWriteApplied,
  deployGlobalAgents,
  deployModes,
  dshHome,
  effectiveConversationViewSettings,
  getStatus,
  inject,
  installOne,
  name,
  registerConversationViewSettings,
  registerModelRpc,
  repairMode,
  scanModes,
  scanPlugins,
  uninstallOne
};
