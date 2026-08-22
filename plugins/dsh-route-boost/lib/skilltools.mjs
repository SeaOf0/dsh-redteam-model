// dsh-route-boost skilltools —— 技能依赖声明扫描 + 装配期工具面检测。
// SKILL.md frontmatter 约定：tools: nmap, nuclei, httpx（逗号/空白分隔的命令名）。
// 扫描与检测均带 TTL 缓存：command -v 毫秒级，装配期同步调用不阻塞；
// 结果供信封 tools 行消费——缺件在开战前显形，按三级兜底（已装同类 → MCP → 批准后安装）补位。
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const MODES_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../modes");
const SCAN_TTL = 60_000;
const CHECK_TTL = 600_000;
const TOOL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const scanCache = new Map(); // presetId → { at, deps: Set<string> }
const checkCache = new Map(); // tool → { at, ok: boolean }

/** 扫描模式技能目录全部 SKILL.md 的 tools: 声明（去重集合）。 */
export function scanSkillDeps(presetId, now = Date.now()) {
	const hit = scanCache.get(presetId);
	if (hit && now - hit.at < SCAN_TTL) return hit.deps;
	const deps = new Set();
	const root = path.join(MODES_ROOT, presetId, "skills");
	try {
		for (const dir of fs.readdirSync(root, { withFileTypes: true })) {
			if (!dir.isDirectory()) continue;
			try {
				const text = fs.readFileSync(path.join(root, dir.name, "SKILL.md"), "utf8");
				const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
				if (!fm) continue;
				const tm = /^tools:\s*(.+)$/m.exec(fm[1]);
				if (tm) for (const t of tm[1].split(/[,，、\s]+/)) {
					const n = t.trim();
					if (TOOL_NAME_RE.test(n)) deps.add(n);
				}
			} catch { /* 单文件读取失败忽略 */ }
		}
	} catch { /* 模式无技能目录 */ }
	scanCache.set(presetId, { at: now, deps });
	return deps;
}

/** command -v 探测（/bin/sh 内建；名非法直接判缺）。 */
export function checkTool(name, now = Date.now()) {
	if (!TOOL_NAME_RE.test(name)) return false;
	const hit = checkCache.get(name);
	if (hit && now - hit.at < CHECK_TTL) return hit.ok;
	let ok = false;
	try {
		ok = spawnSync("/bin/sh", ["-c", `command -v -- ${name} >/dev/null 2>&1`]).status === 0;
	} catch { /* 探测失败按缺件处理 */ }
	checkCache.set(name, { at: now, ok });
	return ok;
}

/** 装配期工具面：模式技能依赖的就绪概况；无声明依赖的模式返回 undefined（不占信封）。 */
export function toolsStatus(presetId, now = Date.now()) {
	const deps = [...scanSkillDeps(presetId, now)].sort();
	if (deps.length === 0) return undefined;
	const missing = deps.filter((n) => !checkTool(n, now));
	return { total: deps.length, ok: deps.length - missing.length, missing };
}
