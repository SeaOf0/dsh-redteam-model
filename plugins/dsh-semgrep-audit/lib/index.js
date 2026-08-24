// dsh-semgrep-audit — code-audit 扫描对账闭环的运行时化（D5 收口）：本机 semgrep
// 封装为模型工具，纪律内置（同 scanner-tools 范式）：
//   1) 检测制：本机未装 semgrep 拒绝执行——三级兜底提示（MCP/安装请求批准制），绝不自动装；
//   2) 规则集随预设：本地三层规则集（java 402 自建/php 1/oss 1080）自动定位，离线主通道；
//   3) 产物落证据：JSON 写 <workspace>/artifacts/scans/semgrep-<ts>.json 并回 evidence-index.md；
//   4) 命中进对账：命中自动双写 scan-reconcile.md（人读）+ scan-reconcile.csv（机读，
//      表头对齐 audit-playbook A3 契约）待处置行——命中 ≠ 漏洞，复核后经
//      redteam_finding_register(sourceOrigin=scan-confirmed/scan-false-positive) 升格；
//   5) 只读：静态扫描不写目标仓、不联网（--metrics=off），产物只落工作区。
// 挂载：preset 平面（code-audit 的 agent.cordis.yml 一行）。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { defineTool } from "@deepseek-ai/dsh-tools";

const BIN_HINT = "本机未装 semgrep——三级兜底：①已连接 MCP（如 kali MCP 的 semgrep_scan，只替引擎不替规则集，命中面收窄如实标注）；②征得用户批准后安装（pip install semgrep——安装请求制，本工具绝不自动装）；③规则降级章通用模式+脚本。";

/** which-style binary check without shell. */
export function hasBin(bin) {
	const probe = process.platform === "win32" ? spawnSync("where", [bin]) : spawnSync("/usr/bin/which", [bin]);
	return probe.status === 0;
}

/** 定位 code-audit refs/（三层规则集随预设分发）。候选按序探测，供测试注入。 */
export function findRefsDir(candidates) {
	const list = candidates ?? [
		path.resolve(import.meta.dirname, "../../../modes/code-audit/refs"), // 开发树/整包部署（plugins 同级有 modes/）
		path.join(os.homedir(), ".dsh", "profiles", "web", "modes", "code-audit", "refs") // profile 部署布局
	];
	for (const dir of list) {
		try {
			if (fs.existsSync(path.join(dir, "lang", "java-audit", "semgrep-rules")) || fs.existsSync(path.join(dir, "semgrep-oss"))) return dir;
		} catch { /* 探测失败换下一个 */ }
	}
	return "";
}

/** 规则层 → --config 路径（相对 refs/）。custom 层由 rulesPath 直供。 */
export const RULE_LAYERS = {
	"builtin-java": ["lang/java-audit/semgrep-rules"],
	"builtin-php": ["lang/php-audit/semgrep-rules"],
	oss: ["semgrep-oss"]
};

export function buildArgs(layer, target, rulesPath, refsDir) {
	const configs = layer === "custom"
		? [String(rulesPath ?? "")]
		: (RULE_LAYERS[layer] ?? []).map((rel) => path.join(refsDir, rel));
	const args = ["scan", "--json", "--metrics=off", "--quiet"];
	for (const c of configs) args.push("--config", c);
	args.push(String(target));
	return { args, configs };
}

/** 解析 semgrep --json 输出：摘要 + 对账行（rule+path+line 去重，展示截断）。纯函数。 */
export function parseSemgrepJson(raw, cap = 200) {
	let j;
	try { j = JSON.parse(raw); } catch { return { ok: false, error: "semgrep 输出非 JSON（引擎异常或缺装降级输出）" }; }
	const results = Array.isArray(j.results) ? j.results : [];
	const bySeverity = {};
	const byRule = {};
	const seen = new Set();
	const hits = [];
	for (const r of results) {
		const rule = String(r.check_id ?? "?");
		const sev = String(r.extra?.severity ?? "?");
		const file = String(r.path ?? "?");
		const line = r.start?.line ?? 0;
		const k = `${rule}|${file}|${line}`;
		bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
		byRule[rule] = (byRule[rule] ?? 0) + 1;
		if (seen.has(k)) continue;
		seen.add(k);
		if (hits.length < cap) hits.push({ rule, file, line, severity: sev, message: String(r.extra?.message ?? "").slice(0, 160) });
	}
	const topRules = Object.entries(byRule).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([rule, n]) => `${rule}×${n}`).join("、");
	return {
		ok: true,
		total: results.length,
		unique: seen.size,
		bySeverity, hits,
		errors: Array.isArray(j.errors) ? j.errors.length : 0,
		summaryText: `semgrep 命中 ${results.length} 条（去重 ${seen.size}${hits.length < seen.size ? `，展示前 ${hits.length}` : ""}）${topRules ? "；Top 规则：" + topRules : ""}——已写对账待处置（命中≠漏洞，复核后经 redteam_finding_register 升格 scan-confirmed/scan-false-positive）`
	};
}

function ensureDirs(workspace) {
	fs.mkdirSync(path.join(workspace, "artifacts", "scans"), { recursive: true });
}

function appendEvidence(fsMod, workspace, evidenceId, cmd, file) {
	const p = path.join(workspace, "evidence-index.md");
	let head = "";
	try { head = fsMod.readFileSync(p, "utf8"); } catch {
		head = "# 证据索引\n\n| 编号 | 时间 | 证据 | 产生方式 | 交接/消费 |\n|---|---|---|---|---|\n";
	}
	fsMod.writeFileSync(p, head + `| ${evidenceId} | ${new Date().toISOString()} | ${file} | ${cmd} | 扫描产物 |\n`);
}

function nextEvidenceId(fsMod, workspace) {
	let n = 0;
	try {
		const text = fsMod.readFileSync(path.join(workspace, "evidence-index.md"), "utf8");
		for (const m of text.matchAll(/\| E(\d+) \|/g)) n = Math.max(n, Number(m[1]));
	} catch { /* 尚无索引 */ }
	return `E${n + 1}`;
}

/** 对账双写：md（人读，同 scanner-tools 格式）+ csv（机读，表头对齐 audit-playbook A3 契约）。 */
export function appendReconcile(fsMod, workspace, rows) {
	if (!rows || rows.length === 0) return 0;
	const mdPath = path.join(workspace, "scan-reconcile.md");
	let head = "";
	try { head = fsMod.readFileSync(mdPath, "utf8"); } catch {
		head = "# 扫描命中对账（scan-reconcile）\n\n| 来源 | 命中 | 终态 |\n|---|---|---|\n";
	}
	fsMod.writeFileSync(mdPath, head + rows.map((r) => `| semgrep | ${r.rule} @ ${r.file}:${r.line} [${r.severity}] | 待处置（命中≠漏洞，须复核+补真实调用链） |`).join("\n") + "\n");
	const csvPath = path.join(workspace, "scan-reconcile.csv");
	let csv = "";
	try { csv = fsMod.readFileSync(csvPath, "utf8"); } catch { csv = "scanner,rule,file,line,verdict,reason\n"; }
	const esc = (s) => /[",\n]/.test(s) ? `"${String(s).replace(/"/g, '""')}"` : String(s);
	fsMod.writeFileSync(csvPath, csv + rows.map((r) => ["semgrep", r.rule, r.file, r.line, "待处置", "命中≠漏洞，复核后经 register 升格"].map(esc).join(",")).join("\n") + "\n");
	return rows.length;
}

/** 运行核心（spawn/fs/二进制检测均可注入供测试）。 */
export function runSemgrep({ workspace, target, layer = "builtin-java", rulesPath, extraArgs, spawnFn, fsMod, refsCandidates, cap, hasBinFn }) {
	const fsx = fsMod ?? fs;
	if (!(hasBinFn ?? hasBin)("semgrep")) return { ok: false, error: BIN_HINT };
	const refsDir = findRefsDir(refsCandidates);
	if (layer !== "custom" && !refsDir) return { ok: false, error: "未定位到 code-audit refs/（三层规则集随预设分发）——请用 layer=custom + rules_path 指定规则路径，或检查预设部署布局" };
	if (layer === "custom" && !rulesPath) return { ok: false, error: "layer=custom 必填 rules_path（规则文件或目录）" };
	const { args, configs } = buildArgs(layer, target, rulesPath, refsDir);
	if (layer === "custom" && !fsx.existsSync(String(rulesPath))) return { ok: false, error: `规则路径不存在：${rulesPath}` };
	if (!fsx.existsSync(String(target))) return { ok: false, error: `扫描目标不存在：${target}` };
	const full = [...args, ...(extraArgs ?? [])];
	const cmdStr = `semgrep ${full.join(" ")}`;
	ensureDirs(workspace);
	const ts = new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
	const outFile = path.join(workspace, "artifacts", "scans", `semgrep-${ts}.json`);
	const proc = (spawnFn ?? ((bin, a) => spawnSync(bin, a, { timeout: 600_000, maxBuffer: 64 * 1024 * 1024 })))("semgrep", full);
	if (proc.error) return { ok: false, error: `执行失败：${proc.error.message}` };
	const parsed = parseSemgrepJson(proc.stdout ? proc.stdout.toString() : "", cap);
	if (!parsed.ok) return { ok: false, error: parsed.error };
	fsx.writeFileSync(outFile, proc.stdout.toString());
	const evidenceId = nextEvidenceId(fsx, workspace);
	appendEvidence(fsx, workspace, evidenceId, `${cmdStr}（规则层 ${layer}：${configs.join("、")}）`, path.relative(workspace, outFile));
	const reconciled = appendReconcile(fsx, workspace, parsed.hits);
	return { ok: true, evidenceId, file: path.relative(workspace, outFile), layer, total: parsed.total, unique: parsed.unique, bySeverity: parsed.bySeverity, reconciled, summaryText: parsed.summaryText };
}

const name = "semgrep-audit";
const inject = ["tools"];

function apply(ctx) {
	ctx.tools.register(defineTool({
		name: "semgrep_scan",
		description: "Local semgrep scan with the preset's offline rule sets (code-audit 三层规则集自动定位；离线主通道). Hits dual-write scan-reconcile.md/.csv as 待处置 — hit ≠ vuln: 复核+补真实调用链后经 redteam_finding_register(sourceOrigin=scan-confirmed/scan-false-positive) 升格, A3 数量守恒. Local binary only — never auto-installs.",
		parameters: {
			target: { type: "string", required: true, description: "扫描目标（仓库/目录根，绝对或相对工作区）" },
			workspace: { type: "string", required: true, description: "任务工作区根（产物与对账落此）" },
			layer: { type: "string", enum: ["builtin-java", "builtin-php", "oss", "custom"], required: true, description: "规则层：builtin-java=402 条自建/builtin-php=php 规则/oss=1080 条开源规则集/custom=自定路径" },
			rules_path: { type: "string", description: "layer=custom 时的规则文件/目录路径（必填）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `semgrep：${v.summaryText ?? ""}（证据 ${v.evidenceId}）` : `semgrep 拒绝/失败：${v.error}` }]
		},
		execute(args) {
			return Promise.resolve(runSemgrep({ workspace: path.resolve(args.workspace), target: path.resolve(args.target), layer: args.layer, rulesPath: args.rules_path }));
		}
	}));
}

export { apply, inject, name };
