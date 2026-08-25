#!/usr/bin/env node
// 六模式 + redteam 主模式 presets 自包含一键部署 CLI（win/mac/linux，零新增依赖：node>=22 + 网络）。
//
// dsh-redteam-model/ 即完整交付物：modes/（九预设：八专业模式 + redteam 主模式）+ shared/ +
// plugins/（十五插件）+ deploy/（本工具）。发现链接指向 modes/，只扫九个干净预设；
// 其余目录在链接之外不会入 roster。
// 移交方式：打包 dsh-redteam-model（--bundle 产出 dsh-redteam-model-bundle-<date>.tar.gz），
// 目标机解压后一条命令完成部署。
//
//   node deploy.mjs            # 安装：预设链接(备份不删) + 插件 link/bundle 登记 + pnpm install
//   node deploy.mjs --check    # 离线校验：九预设挂载 + 插件真实 loader 路径 + dsh.bundle 声明
//   node deploy.mjs --start    # 后台启动 dsh web (:3080)
//   node deploy.mjs --bundle   # 打包 presets 根为 tar.gz（系统 tar：mac/linux 及 Win10+ bsdtar）
//
//   npx ./deploy               # 同上（deploy/ 含 package.json bin）
//
// Windows 说明：预设链接用 junction（免管理员/免开发者模式）；npx/pnpm 调用走 shell。

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync, spawn } from "node:child_process";

const IS_WIN = process.platform === "win32";
// 布局：dsh-redteam-model/{ modes/<九预设>, shared/, plugins/<十五插件>, deploy/ }。
// 预设发现链接指向 modes/（发现器只扫其直接子目录=九个干净预设；shared/plugins/deploy
// 平铺在 modes 之外，避免被当成缺 agent.cordis.yml 的损坏预设行）。
const MODEL_ROOT = path.resolve(import.meta.dirname, ".."); // dsh-redteam-model/ 本身
const PRESETS_ROOT = path.join(MODEL_ROOT, "modes");
const PLUGINS_ROOT = path.join(MODEL_ROOT, "plugins");
const DSH_HOME = process.env.DSH_HOME ?? path.join(os.homedir(), ".dsh");
const PRESET_LINK = path.join(DSH_HOME, ".agent-presets");
const PROFILE_WEB = path.join(DSH_HOME, "profiles", "web");
// hostPlane: true = 进 bundles（宿主平面、全模式可见）；false = 仅 link 依赖（preset 平面，
// 由预设行挂载——scanner 允许 pentest/attack-defense/cloud-security/ctf-solver 可见，宿主不挂是设计而非遗漏）。
const PLUGINS = [
	{ name: "dsh-stage-gate", hostPlane: true },
	{ name: "dsh-attack-atlas", hostPlane: true },
	{ name: "dsh-session-pulse", hostPlane: true },
	{ name: "dsh-mcp-studio", hostPlane: true },
	{ name: "dsh-product-subagents", hostPlane: true },
	{ name: "dsh-route-boost", hostPlane: true },
	{ name: "dsh-campaign-memory", hostPlane: true },
	{ name: "dsh-refusal-guard", hostPlane: true },
	{ name: "dsh-sec-enforce", hostPlane: true },
	{ name: "dsh-redteam-results", hostPlane: true },
	{ name: "dsh-hunter", hostPlane: true },
	{ name: "dsh-mode-group", hostPlane: true },
	{ name: "dsh-scanner-tools", hostPlane: false },
	{ name: "dsh-semgrep-audit", hostPlane: false },
	{ name: "dsh-webshell-mgr", hostPlane: true }
];
const MODE = process.argv[2] ?? "";

const log = (m) => console.log(`\x1b[1;32m[deploy]\x1b[0m ${m}`);
const warn = (m) => console.log(`\x1b[1;33m[deploy]\x1b[0m ${m}`);
const die = (m) => { console.error(`\x1b[1;31m[deploy]\x1b[0m ${m}`); process.exit(1); };

function run(cmd, args, opts = {}) {
	const r = IS_WIN
		? spawnSync(cmd.join(" "), args, { shell: true, stdio: "inherit", ...opts })
		: spawnSync(cmd[0], [...cmd.slice(1), ...args], { stdio: "inherit", ...opts });
	if (r.status !== 0) die(`命令失败：${cmd.join(" ")} ${args.join(" ")}`);
	return r;
}

function existsAny(p) { try { fs.lstatSync(p); return true; } catch { return false; } }

// 插件 bare 导入的 peer 包（@deepseek-ai/dsh-tools / schemastery）在新环境无法从
// bundle 物理位置向上解析——链接到运行时安装的 profiles/node_modules 桥接。
function linkPluginPeers() {
	// 把运行时全部 @deepseek-ai/* 桥接进 plugins/node_modules——插件的 bare 导入
	// （dsh-tools / schemastery / dsh-settings / dsh-mcp-client …）在新环境无法从
	// bundle 物理位置向上解析；链接到 boot 安装的 profiles/node_modules 后即生效。
	// 首次部署时运行时尚未安装，悬挂链接照建（boot 装完即活），幂等可重跑。
	const runtime = path.join(DSH_HOME, "profiles", "node_modules", "@deepseek-ai");
	const local = path.join(PLUGINS_ROOT, "node_modules", "@deepseek-ai");
	fs.mkdirSync(local, { recursive: true });
	let n = 0;
	let names = [];
	try { names = fs.readdirSync(runtime); } catch { /* 运行时未装：按候选悬挂 */ }
	names = names.filter((x) => !x.startsWith("."));
	for (const extra of ["dsh-tools", "schemastery", "dsh-settings", "dsh-system-prompt", "dsh-mcp-client", "dsh-llm"]) {
		if (!names.includes(extra)) names.push(extra);
	}
	for (const pkg of names) {
		const src = path.join(runtime, pkg);
		const dst = path.join(local, pkg);
		let current = null;
		try { current = fs.readlinkSync(dst); } catch { /* 非链接或不存在 */ }
		if (current === src) continue;
		if (existsAny(dst)) { fs.renameSync(dst, `${dst}.bak-${Date.now()}`); }
		fs.symlinkSync(src, dst);
		n++;
	}
	log(`插件 peer 桥接完成（${n} 个 @deepseek-ai/* → 运行时；首次部署为悬挂链接，boot 后生效）`);
	// 插件互依赖桥接：@dsh-external/<name> → plugins/<name>（如 dsh-hunter 依赖
	// dsh-redteam-results/store）。自链接幂等，boot 后生效。
	const extLocal = path.join(PLUGINS_ROOT, "node_modules", "@dsh-external");
	fs.mkdirSync(extLocal, { recursive: true });
	let m = 0;
	for (const { name: pn } of PLUGINS) {
		const srcDir = path.join(PLUGINS_ROOT, pn);
		const dst = path.join(extLocal, pn);
		let cur = null;
		try { cur = fs.readlinkSync(dst); } catch { /* 非链接 */ }
		if (cur === srcDir) continue;
		if (existsAny(dst)) { fs.renameSync(dst, `${dst}.bak-${Date.now()}`); }
		fs.symlinkSync(srcDir, dst);
		m++;
	}
	log(`插件互依赖桥接完成（${m} 个 @dsh-external/* → plugins/）`);
}

function linkPresets() {
	fs.mkdirSync(DSH_HOME, { recursive: true });
	const target = PRESETS_ROOT;
	if (existsAny(PRESET_LINK)) {
		let current = null;
		try { current = fs.readlinkSync(PRESET_LINK); } catch { /* 实体目录而非链接 */ }
		if (current === target) { log("预设链接已就绪"); return; }
		const bak = `${PRESET_LINK}.bak-${Date.now()}`;
		fs.renameSync(PRESET_LINK, bak);
		warn(`已有 .agent-presets 已备份至 ${bak}（绝不删除）`);
	}
	// Windows 用 junction：目录联接免管理员/免开发者模式；unix 用 dir 符号链接
	fs.symlinkSync(target, PRESET_LINK, IS_WIN ? "junction" : "dir");
	log(`预设链接已建立：${PRESET_LINK} -> ${target}${IS_WIN ? "（junction）" : ""}`);
}

function patchProfile() {
	const pj = path.join(PROFILE_WEB, "package.json");
	if (!fs.existsSync(pj)) {
		fs.mkdirSync(PROFILE_WEB, { recursive: true });
		fs.writeFileSync(pj, JSON.stringify({
			name: "dsh-profile-web",
			private: true,
			dependencies: {},
			dsh: { profile: { bundles: ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"] } }
		}, null, 2));
		log(`已创建最小 profile：${pj}`);
	}
	const d = JSON.parse(fs.readFileSync(pj, "utf8"));
	d.dependencies ??= {};
	d.dsh ??= {}; d.dsh.profile ??= {}; d.dsh.profile.bundles ??= [];
	let changed = 0;
	for (const { name, hostPlane } of PLUGINS) {
		const pluginDir = path.join(PLUGINS_ROOT, name);
		if (!fs.existsSync(path.join(pluginDir, "cordis.patch.yml"))) { warn(`跳过 ${name}（无 cordis.patch.yml，骨架或未实现）`); continue; }
		const pkg = `@dsh-external/${name}`;
		const link = `link:${pluginDir}`;
		if (d.dependencies[pkg] !== link) { d.dependencies[pkg] = link; changed++; }
		if (hostPlane && !d.dsh.profile.bundles.includes(pkg)) { d.dsh.profile.bundles.push(pkg); changed++; }
	}
	fs.writeFileSync(pj, JSON.stringify(d, null, 2));
	log(`package.json 完成（${changed} 项变更${changed ? "" : "，已是最新"}）`);
}

function install() {
	log("pnpm install（经 npx，无需预装）");
	run(["npx", "-y", "pnpm", "install", "--prefer-offline"], [], { cwd: PROFILE_WEB });
	linkPluginPeers();
	log("安装完成");
}

function start() {
	const logFile = path.join(DSH_HOME, "deploy-web.log");
	const out = fs.openSync(logFile, "a");
	const child = IS_WIN
		? spawn("npx -y @deepseek-ai/dsh web", { shell: true, detached: true, stdio: ["ignore", out, out] })
		: spawn("npx", ["-y", "@deepseek-ai/dsh", "web"], { detached: true, stdio: ["ignore", out, out] });
	child.unref();
	log(`dsh web 已后台启动（日志 ${logFile}），稍候访问 http://127.0.0.1:3080`);
}

function bundle() {
	const outDir = MODEL_ROOT;
	const out = path.join(outDir, `dsh-redteam-model-bundle-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}.tar.gz`);
	// 交付包纯净性：管理文档（设计/进度/测试记录——含本机实测记录与本地路径）不随包分发，
	// 仅留在源目录供维护者交接；如目标机维护者需要，另行手动拷贝。
	const args = ["-czf", out,
		"--exclude", "node_modules", "--exclude", ".git", "--exclude", ".zcode", "--exclude", ".DS_Store",
		"--exclude", "*-bundle-*.tar.gz",
		"--exclude", "dsh-redteam-model/DESIGN.md", "--exclude", "dsh-redteam-model/PROGRESS.md", "--exclude", "dsh-redteam-model/测试.md", "--exclude", "dsh-redteam-model/SOURCES.md", "--exclude", "dsh-redteam-model/token节省方案.md",
		"--exclude", ".github", "--exclude", ".cursorrules",
		"dsh-redteam-model"];
	// 从 dsh-redteam-model 的上级目录打包，使 tar 内含顶层 dsh-redteam-model/ 目录
	run(["tar"], args, { cwd: path.dirname(MODEL_ROOT) });
	log(`${out} 打包完成（打包源：${MODEL_ROOT}；交付净量：modes 九预设 + shared + plugins + deploy；管理文档不随包）`);
	log(`目标机：tar -xzf ${path.basename(out)} && cd dsh-redteam-model/deploy && node deploy.mjs（或 npx ./deploy）`);
}

if (MODE === "--check") {
	const verify = path.join(import.meta.dirname, "verify-deployment.mjs");
	const r = spawnSync(process.execPath, [verify], { stdio: "inherit" });
	process.exit(r.status ?? 1);
} else if (MODE === "--bundle") {
	bundle();
} else {
	log(`model root: ${MODEL_ROOT}（modes: ${PRESETS_ROOT}）`);
	log(`dsh home: ${DSH_HOME}（${IS_WIN ? "Windows" : process.platform}）`);
	linkPresets();
	patchProfile();
	install();
	if (MODE === "--start") start();
	else log("完成。启动：--start；校验：--check（新环境须先跑本脚本 install 建立桥接后再 --check）；打包：--bundle");
}
