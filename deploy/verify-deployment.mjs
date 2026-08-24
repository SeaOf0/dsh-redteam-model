// Offline deployment verification for the seven-preset bundle (six modes + redteam controller).
// Boots a minimal cordis host (same seam set as the real one), then:
//   1. mounts all nine presets via agentPresets.standingKeyFor (composition files load);
//   2. loads every deployed plugin's bundle row through the REAL loader path
//      (loader.create with the profile's baseUrl — bare specifiers resolve exactly as at boot);
//   3. reads each preset's preset.yml metadata (roster display parses).
// Exits non-zero on any failure. Run after deploy.sh (requires ~/.dsh/profiles runtime packages,
// i.e. dsh web has been started at least once, and pnpm install in profiles/web for link deps).

import { pathToFileURL } from "node:url";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";

const DSH_HOME = process.env.DSH_HOME ?? path.join(os.homedir(), ".dsh");
const RUNTIME = path.join(DSH_HOME, "profiles", "node_modules"); // @deepseek-ai runtime pkgs
const PROFILE_WEB = path.join(DSH_HOME, "profiles", "web");
const BUNDLE_DIR = path.join(path.resolve(import.meta.dirname, ".."), "plugins"); // dsh-redteam-model/plugins

const at = (name) => pathToFileURL(path.join(RUNTIME, "@deepseek-ai", name, "lib", "index.js")).href;

const load = async (name) => {
	try { return await import(at(name)); } catch (e) {
		console.error(`FAIL 无法导入 @deepseek-ai/${name}（${e.message}）——若首次部署，先 ./deploy.sh --start 跑一次 dsh web 安装运行时，再回来 --check`);
		process.exit(1);
	}
};

const { Context } = await load("cordis");
const LoaderMod = await load("cordis-plugin-loader");
const Loader = LoaderMod.default;
const Group = LoaderMod.Group;
const providers = {};
for (const p of ["dsh-system-prompt", "dsh-tools", "dsh-skill", "dsh-commands", "dsh-token-meter",
	"dsh-subagent", "dsh-user-questions", "dsh-shell", "dsh-compaction", "dsh-goal", "dsh-web",
	"dsh-llm", "dsh-session", "dsh-fs-local", "dsh-subprocess", "dsh-jobs-local", "dsh-agent"]) {
	const mod = await load(p);
	providers[p] = mod.default ?? mod;
}
const ShellEnv = await import(pathToFileURL(path.join(RUNTIME, "@deepseek-ai", "dsh-shell-env", "lib", "index.js")).href);
const AgentPresets = (await load("dsh-agent-presets")).default;

const app = new Context();
app.baseUrl = pathToFileURL(PROFILE_WEB + path.sep).href;
await app.plugin(Loader);
app.loader.builtins.group = Group;
for (const p of Object.values(providers)) await app.plugin(p, {});
await app.plugin(ShellEnv, {});
await app.plugin(AgentPresets, { default: "pentest" });

let failed = 0;

// 1) nine presets mount (eight modes + redteam controller)
const ids = ["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "redteam", "incident-response", "cloud-security", "ctf-solver"];
for (const id of ids) {
	try {
		await app.agentPresets.standingKeyFor(id);
		const meta = await import(at("dsh-agent-presets")).then((m) =>
			m.readPresetMetadata(path.join(DSH_HOME, ".agent-presets", id)));
		console.log(`OK   preset ${id}（${meta.name}）`);
	} catch (e) { failed++; console.log(`FAIL preset ${id}: ${e.message}`); }
}

// 2) deployed plugin rows load through the real loader path (with each row's real patch config)
const Yaml = await import(pathToFileURL(path.join(RUNTIME, "yaml", "dist", "index.js")).href);
const pj = JSON.parse(fs.readFileSync(path.join(PROFILE_WEB, "package.json"), "utf8"));
const bundles = pj.dsh?.profile?.bundles ?? [];
// 本机 profile 可能还挂着用户自装的非交付插件（automation/easm/sidechain 等）——它们不在
// dsh-redteam-model/plugins/ 内，按其 link 目标存在性单独放行说明，不算交付校验失败。
const DELIVERED = new Set(["dsh-stage-gate", "dsh-attack-atlas", "dsh-session-pulse", "dsh-mcp-studio", "dsh-product-subagents", "dsh-route-boost", "dsh-campaign-memory", "dsh-refusal-guard", "dsh-sec-enforce", "dsh-redteam-results", "dsh-hunter", "dsh-mode-group", "dsh-scanner-tools", "dsh-webshell-mgr", "dsh-semgrep-audit"]);
for (const name of bundles) {
	if (!name.startsWith("@dsh-external/")) continue; // 官方 bundle 由真实启动校验
	const dir = name.replace("@dsh-external/", "");
	if (!DELIVERED.has(dir)) {
		const link = pj.dependencies?.[name];
		if (link?.startsWith("link:") && fs.existsSync(link.slice(5))) console.log(`SKIP plugin ${name}（宿主自装，非交付件，link 存在）`);
		else console.log(`WARN plugin ${name}（宿主自装且 link 失效——与本交付无关，提示而已）`);
		continue;
	}
	// boot 前置检查：bundle 清单成员必须在 package.json 声明 dsh.bundle（真实启动会硬性校验）
	try {
		const pkg = JSON.parse(fs.readFileSync(path.join(BUNDLE_DIR, dir, "package.json"), "utf8"));
		if (!pkg.dsh?.bundle) throw new Error("package.json 缺 dsh.bundle 声明（boot 会拒绝）");
	} catch (e) { failed++; console.log(`FAIL plugin ${name}: ${e.message}`); continue; }
	const patch = path.join(BUNDLE_DIR, dir, "cordis.patch.yml");
	let config = {};
	try {
		const doc = Yaml.parse(fs.readFileSync(patch, "utf8"));
		config = doc?.[0]?.insert?.[0]?.config ?? {};
	} catch { /* 无 patch 或解析失败按空配置 */ }
	try {
		await app.loader.create({ name, config });
		console.log(`OK   plugin ${name}`);
	} catch (e) { failed++; console.log(`FAIL plugin ${name}: ${e.message}`); }
}

// preset 平面交付件不进 web bundles（由预设行挂载）——按依赖 link + dsh.bundle 声明校验，
// 保证任何环境（含全新安装）九个交付插件都被覆盖到。
for (const dir of DELIVERED) {
	const name = `@dsh-external/${dir}`;
	if (bundles.includes(name)) continue;
	const link = pj.dependencies?.[name];
	try {
		if (!link?.startsWith("link:") || !fs.existsSync(link.slice(5))) throw new Error("依赖 link 缺失或失效");
		const pkg = JSON.parse(fs.readFileSync(path.join(BUNDLE_DIR, dir, "package.json"), "utf8"));
		if (!pkg.dsh?.bundle) throw new Error("package.json 缺 dsh.bundle 声明");
		console.log(`OK   plugin ${name}（preset 平面）`);
	} catch (e) { failed++; console.log(`FAIL plugin ${name}: ${e.message}`); }
}

// 3) stage-gate tool sanity (pure validators, no runtime state)
const gateLib = await import(pathToFileURL(path.join(BUNDLE_DIR, "dsh-stage-gate", "lib", "index.js")).href);
const modes = Object.keys(gateLib.GATES);
console.log(`OK   stage-gate schemas: ${modes.length} modes, ${modes.reduce((n, m) => n + Object.keys(gateLib.GATES[m]).length, 0)} gates`);

process.exit(failed ? 1 : 0);
