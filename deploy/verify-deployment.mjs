// Offline deployment verification for the ten-preset bundle (nine modes + redteam controller).
// Boots a minimal cordis host (same seam set as the real one), then:
//   1. mounts all ten presets — composition file readable + row structure valid
//      (registry.entryListProblem) + every plugin row through the REAL loader path,
//      the same per-row strength a standing mount performs (host 0.1.7 adaptation:
//      dsh-agent-presets split into preset + registry; see mountComposition below);
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

const { Context, Service } = await load("cordis");
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
// 0.1.7 适配：dsh-agent-presets（提供 standingKeyFor 离线挂载）在 0.1.7 拆分为
// dsh-agent-preset + dsh-agent-preset-registry，挂载模型改为 agent scope 运行时解析——
// 离线桩无法复刻完整 session 链。等价验证面（强度与 standingKeyFor 一致）：
// 组合文件可读（= compositionStamp 前置）+ 行结构合法（registry.entryListProblem）+
// 每个插件行经真实 loader.create 加载（standingKeyFor 挂载时同样逐行走 loader）。
const Yaml = await import(pathToFileURL(path.join(RUNTIME, "yaml", "dist", "index.js")).href);
const { entryListProblem } = await load("dsh-agent-preset-registry");

async function mountComposition(app, dir) {
	const raw = fs.readFileSync(path.join(dir, "agent.cordis.yml"), "utf8");
	const rows = Yaml.parse(raw);
	const problem = entryListProblem(rows);
	if (problem) throw new Error(problem);
	const flat = [];
	const walk = (rs) => { for (const r of rs ?? []) r?.group === true ? walk(r.config) : flat.push(r); };
	walk(rows);
	for (const row of flat) await app.loader.create({ name: row.name, config: row.config ?? {} });
}

const app = new Context();
app.baseUrl = pathToFileURL(PROFILE_WEB + path.sep).href;
await app.plugin(Loader);
app.loader.builtins.group = Group;
for (const p of Object.values(providers)) await app.plugin(p, {});
await app.plugin(ShellEnv, {});
// 环境适配：preset 体系 inject sessionProjections（真实宿主由会话插件提供，
// 离线校验只需服务满足激活期检查——no-op 桩即可，不影响真实宿主路径）。
const SessionProjectionsStub = class extends Service {
	constructor(ctx) { super(ctx, "sessionProjections"); }
	register() {}
	stateOf() { return undefined; }
};
await app.plugin(SessionProjectionsStub, {});
// 环境适配：宿主 0.1.6-alpha.2 起 preset 行引用的 dsh-tool-workflow / dsh-workflow-ptc /
// dsh-tool-ralph 分别 inject workflowEngine / ptcRuntime+sandboxPolicy / workflowEngine
// （真实宿主由宿主自家包提供；离线校验只需服务满足激活期检查——workflow-ptc 的构造器
// 读 ctx.ptcRuntime.language === "typescript"，桩带该字段即可，工作流不会被离线校验执行。
// 实测缺桩时十模式 mount 全 FAIL 为误报，真实运行时 roster 全 healthy）。
const WorkflowEngineStub = class extends Service {
	constructor(ctx) { super(ctx, "workflowEngine"); }
};
const PtcRuntimeStub = class extends Service {
	language = "typescript";
	constructor(ctx) { super(ctx, "ptcRuntime"); }
};
const SandboxPolicyStub = class extends Service {
	constructor(ctx) { super(ctx, "sandboxPolicy"); }
};
for (const stub of [WorkflowEngineStub, PtcRuntimeStub, SandboxPolicyStub]) {
	await app.plugin(stub, {});
}

let failed = 0;

// 1) ten presets mount (nine modes + redteam controller)
const ids = ["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "redteam", "incident-response", "cloud-security", "ctf-solver", "asset-mapping"];
for (const id of ids) {
	try {
		const dir = path.join(DSH_HOME, ".agent-presets", id);
		await mountComposition(app, dir);
		const meta = Yaml.parse(fs.readFileSync(path.join(dir, "preset.yml"), "utf8")) ?? {};
		console.log(`OK   preset ${id}（${meta.name}）`);
	} catch (e) { failed++; console.log(`FAIL preset ${id}: ${e.message}`); }
}

// 2) deployed plugin rows load through the real loader path (with each row's real patch config)
const pj = JSON.parse(fs.readFileSync(path.join(PROFILE_WEB, "package.json"), "utf8"));
const bundles = pj.dsh?.profile?.bundles ?? [];
// 本机 profile 可能还挂着用户自装的非交付插件（automation/easm/sidechain 等）——它们不在
// dsh-redteam-model/plugins/ 内，按其 link 目标存在性单独放行说明，不算交付校验失败。
const DELIVERED = new Set(["dsh-stage-gate", "dsh-attack-atlas", "dsh-session-pulse", "dsh-mcp-studio", "dsh-product-subagents", "dsh-route-boost", "dsh-campaign-memory", "dsh-refusal-guard", "dsh-sec-enforce", "dsh-redteam-results", "dsh-hunter", "dsh-mode-group", "dsh-scanner-tools", "dsh-webshell-mgr", "dsh-semgrep-audit", "dsh-auto-advance", "dsh-trace-vault"]);
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

// preset 平面交付件不进 web bundles（由预设 agent.cordis.yml 的挂载行加载）——按依赖
// link + 预设挂载行校验。注意：这类插件【故意不声明】dsh.bundle——一旦声明，宿主 CLI 的
// bundle reconcile 会把它写进 dsh.profile.bundles，管理台随即判平面错配（cordis.patch.yml
// 头注释有完整说明）。挂载行存在（至少一个模式的 agent.cordis.yml 引用）才是它的生效证明。
const MODES_DIR = path.join(path.resolve(import.meta.dirname, ".."), "modes");
for (const dir of DELIVERED) {
	const name = `@dsh-external/${dir}`;
	if (bundles.includes(name)) continue;
	const link = pj.dependencies?.[name];
	try {
		if (!link?.startsWith("link:") || !fs.existsSync(link.slice(5))) throw new Error("依赖 link 缺失或失效");
		const mounted = fs.readdirSync(MODES_DIR).some((m) => {
			try { return fs.readFileSync(path.join(MODES_DIR, m, "agent.cordis.yml"), "utf8").includes(name); } catch { return false; }
		});
		if (!mounted) throw new Error("无任何模式的 agent.cordis.yml 挂载行引用");
		console.log(`OK   plugin ${name}（preset 平面）`);
	} catch (e) { failed++; console.log(`FAIL plugin ${name}: ${e.message}`); }
}

// 3) stage-gate tool sanity (pure validators, no runtime state)
const gateLib = await import(pathToFileURL(path.join(BUNDLE_DIR, "dsh-stage-gate", "lib", "index.js")).href);
const modes = Object.keys(gateLib.GATES);
console.log(`OK   stage-gate schemas: ${modes.length} modes, ${modes.reduce((n, m) => n + Object.keys(gateLib.GATES[m]).length, 0)} gates`);

// 4) foreign-base pass: normalised copies must mount from a base that cannot
//    walk up into the profile tree — the exact resolution face a packaged
//    desktop host presents. `~/.dsh/profiles` can see the runtime engine
//    packages but not `@dsh-external/*`, so the engine row staying a package
//    name and the external rows becoming `file:` is precisely what this pass
//    proves loadable.
{
	const Manager = await import(pathToFileURL(path.join(import.meta.dirname, "..", "lib", "index.js")).href);
	const MODES_SRC = path.join(import.meta.dirname, "..", "modes");
	const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "dsh-verify-foreign-"));
	try {
		for (const id of ids) {
			fs.cpSync(path.join(MODES_SRC, id), path.join(tmpRoot, id), { recursive: true });
			const result = Manager.normalizePresetComposition(path.join(tmpRoot, id));
			if (!result.changed) console.log(`WARN foreign-copy ${id}: normaliser made no change (engine undetected and no @dsh-external rows?)`);
		}
		const rewritten = fs.readFileSync(path.join(tmpRoot, "pentest", "agent.cordis.yml"), "utf8");
		const externalRows = rewritten.split("\n").filter((line) => /name: '@dsh-external\//.test(line));
		if (externalRows.length > 0) {
			failed++;
			console.log(`FAIL foreign-copy pentest: ${externalRows.length} bare @dsh-external row(s) survived normalisation`);
		} else {
			console.log(`OK   foreign-copy pentest: @dsh-external rows rewritten to file: URLs`);
		}
		const flavor = Manager.detectEngineFlavor();
		const engineRow = rewritten.split("\n").find((line) => /- id: workflow-(ptc|worker-thread)/.test(line));
		console.log(`OK   foreign-copy engine row: ${engineRow?.trim() ?? "(absent)"} (detected flavor: ${flavor ?? "none"})`);

		const app2 = new Context();
		// Base with the packaged-desktop property: runtime engine packages
		// visible, profile @dsh-external links unreachable.
		app2.baseUrl = pathToFileURL(path.join(DSH_HOME, "profiles") + path.sep).href;
		await app2.plugin(Loader);
		app2.loader.builtins.group = Group;
		for (const p of Object.values(providers)) await app2.plugin(p, {});
		await app2.plugin(ShellEnv, {});
		await app2.plugin(SessionProjectionsStub, {});
		for (const stub of [WorkflowEngineStub, PtcRuntimeStub, SandboxPolicyStub]) await app2.plugin(stub, {});
		for (const id of ids) {
			try {
				await mountComposition(app2, path.join(tmpRoot, id));
				console.log(`OK   foreign-base preset ${id}`);
			} catch (e) { failed++; console.log(`FAIL foreign-base preset ${id}: ${e.message}`); }
		}
	} finally {
		fs.rmSync(tmpRoot, { recursive: true, force: true });
	}
}

process.exit(failed ? 1 : 0);
