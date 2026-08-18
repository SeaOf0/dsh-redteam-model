// dsh-scanner-tools — pentest 三级兜底第一级的运行时化：本机扫描器（nuclei/httpx/ffuf）
// 封装为模型工具，纪律内置：
//   1) 速率纪律参数化：保守默认（nuclei -rl 15 / httpx -rl 25 / ffuf -rate 50），
//      显式提速会记录在扫描审计里（默认值来自 pentest-playbook 速率纪律，用户已确认）；
//   2) 产物落证据：JSON/JSONL 写 <workspace>/artifacts/scans/<tool>-<ts>.json 并回
//      evidence-index.md 一行；
//   3) 命中进对账：nuclei 命中自动写 scan-reconcile.md 待处置行（命中 ≠ 漏洞，复核后终态）；
//   4) 防盲打：主动扫描（nuclei/ffuf）要求目标已登记 assets.md；轻探测（httpx）允许未登记
//      但产出登记建议；MCP/安装请求兜底提示内置。
// 挂载：preset 平面（pentest / attack-defense 各自 agent.cordis.yml 一行）。

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { defineTool } from "@deepseek-ai/dsh-tools";

const RATE_DEFAULTS = { nuclei: 15, httpx: 25, ffuf: 50 }; // 保守默认；显式覆盖会留痕
const BIN_HINT = "三级兜底：本机未装该工具——先查已连接 MCP（如 kali MCP），仍无则按 pentest-playbook 安装请求流程征得用户批准后安装；本工具绝不自动安装。";

/** which-style binary check without shell. */
export function hasBin(bin) {
	const probe = process.platform === "win32" ? spawnSync("where", [bin]) : spawnSync("/usr/bin/which", [bin]);
	return probe.status === 0;
}

/** target host must appear in assets.md (active scans only). Returns {ok, hint}. */
export function checkRegistered(fsMod, workspace, target) {
	const text = (() => { try { return fsMod.readFileSync(path.join(workspace, "assets.md"), "utf8"); } catch { return ""; } })();
	if (!text) return { ok: false, hint: "工作区无 assets.md——先完成侦察阶段（Gate P1 资产基线）再主动扫描" };
	const host = String(target).replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
	return text.includes(host)
		? { ok: true, hint: "" }
		: { ok: false, hint: `目标 ${host} 未登记在 assets.md——防盲打：先登记资产（侦察组回填）再主动扫描` };
}

function ensureDirs(workspace) {
	fs.mkdirSync(path.join(workspace, "artifacts", "scans"), { recursive: true });
}

function appendEvidence(workspace, evidenceId, cmd, file) {
	const p = path.join(workspace, "evidence-index.md");
	let head = "";
	try { head = fs.readFileSync(p, "utf8"); } catch {
		head = "# 证据索引\n\n| 编号 | 时间 | 证据 | 产生方式 | 交接/消费 |\n|---|---|---|---|---|\n";
	}
	fs.writeFileSync(p, head + `| ${evidenceId} | ${new Date().toISOString()} | ${file} | ${cmd} | 扫描产物 |\n`);
}

function appendReconcile(workspace, rows) {
	if (!rows || rows.length === 0) return 0;
	const p = path.join(workspace, "scan-reconcile.md");
	let head = "";
	try { head = fs.readFileSync(p, "utf8"); } catch {
		head = "# 扫描命中对账（scan-reconcile）\n\n| 来源 | 命中 | 终态 |\n|---|---|---|\n";
	}
	const lines = rows.map((r) => `| ${r.source} | ${r.hit} | 待处置（命中≠漏洞，须复核+对照三件套） |`).join("\n");
	fs.writeFileSync(p, head + lines + "\n");
	return rows.length;
}

function nextEvidenceId(workspace) {
	let n = 0;
	try {
		const text = fs.readFileSync(path.join(workspace, "evidence-index.md"), "utf8");
		for (const m of text.matchAll(/\| E(\d+) \|/g)) n = Math.max(n, Number(m[1]));
	} catch { /* 尚无索引 */ }
	return `E${n + 1}`;
}

/** Run one scanner with rate discipline + evidence + reconcile. Pure-ish core (fs injectable in tests). */
export function runScan({ bin, args, workspace, tool, rate, defaultRate, active, target, parse, outFile: outFileOverride }) {
	if (!hasBin(bin)) return { ok: false, error: BIN_HINT, bin };
	if (active) {
		const reg = checkRegistered(fs, workspace, target);
		if (!reg.ok) return { ok: false, error: reg.hint, bin };
	}
	ensureDirs(workspace);
	const nucleiTemplateDirs = [
		path.join(process.env.HOME ?? "", "nuclei-templates"),
		path.join(process.env.HOME ?? "", "Library", "Application Support", "nuclei", "templates"),
		path.join(process.env.HOME ?? "", ".config", "nuclei", "templates")
	];
	if (bin === "nuclei" && !nucleiTemplateDirs.some((d) => fs.existsSync(d))) {
		return { ok: false, error: "nuclei 模板库不存在——首次使用需一次性下载（nuclei -update-templates，数据非工具安装）。按用户基准需批准：请在 DSH 会话外自行执行，或明确批准后由模型执行。", bin };
	}
	const ts = new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
	const outFile = outFileOverride ?? path.join(workspace, "artifacts", "scans", `${tool}-${ts}.json`);
	const full = [...args];
	if (rate && rate !== defaultRate) full.push(...(tool === "nuclei" ? ["-rl", String(rate)] : tool === "httpx" ? ["-rl", String(rate)] : ["-rate", String(rate)]));
	else full.push(...(tool === "ffuf" ? ["-rate", String(defaultRate)] : ["-rl", String(defaultRate)]));
	const cmdStr = `${bin} ${full.join(" ")}`;
	const timeoutMs = bin === "nuclei" ? 900_000 : 300_000;
	const proc = spawnSync(bin, full, { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
	if (proc.error) return { ok: false, error: `执行失败：${proc.error.message}${proc.error.code === "ETIMEDOUT" ? `（超时 ${timeoutMs / 1000}s${bin === "nuclei" ? "——模板库缺失时首次会尝试拉取导致超时" : ""}）` : ""}`, bin };

	const raw = proc.stdout ? proc.stdout.toString() : "";
	const parsed = parse ? parse(raw, proc) : { raw: raw };
	if (parsed.__writeRaw !== null && parsed.__writeRaw !== undefined) fs.writeFileSync(outFile, parsed.__writeRaw);
	else fs.writeFileSync(outFile, JSON.stringify({ raw: raw.slice(0, 100000) }, null, 2));
	const evidenceId = nextEvidenceId(workspace);
	appendEvidence(workspace, evidenceId, cmdStr + (rate && rate !== defaultRate ? `（速率显式覆盖：默认 ${defaultRate} → ${rate}，留痕）` : `（保守默认速率 ${defaultRate}）`), path.relative(workspace, outFile));
	const reconciled = appendReconcile(workspace, parsed.__hits || []);
	return { ok: proc.status === 0, evidenceId, file: path.relative(workspace, outFile), summary: parsed.__summary ?? {}, hits: (parsed.__hits || []).length, reconciled, stdout: parsed.__summaryText ?? "" };
}

//#region parsers

const nucleiParse = (raw) => {
	const hits = [];
	const out = [];
	for (const line of raw.split("\n")) {
		if (!line.trim().startsWith("{")) continue;
		try {
			const j = JSON.parse(line);
			hits.push({ source: "nuclei", hit: `${j.templateID ?? j["template-id"]} @ ${j.host ?? j.url} [${j.info?.severity ?? "?"}]` });
			out.push(j);
		} catch { /* 非 JSONL 行忽略 */ }
	}
	return { __writeRaw: JSON.stringify(out, null, 2), __hits: hits, __summary: { total: out.length }, __summaryText: `nuclei 命中 ${out.length} 条（已写对账待处置）` };
};

const httpxParse = (raw) => {
	const out = [];
	for (const line of raw.split("\n")) {
		if (!line.trim().startsWith("{")) continue;
		try { out.push(JSON.parse(line)); } catch { /* 忽略 */ }
	}
	return { __writeRaw: JSON.stringify(out, null, 2), __hits: [], __summary: { alive: out.length }, __summaryText: `存活 ${out.length}；探测未登记资产属侦察行为，结果请回填 assets.md` };
};

const ffufParse = (_raw, proc) => {
	// ffuf -o 已直接写 JSON 到 -o 文件；这里只汇总额外信息
	return { __writeRaw: null, __hits: [], __summary: { note: "结果见 -o 输出文件（已由 ffuf 写入）" }, __summaryText: `ffuf 完成（exit ${proc.status}），结果见产物文件` };
};

//#endregion

const name = "scanner-tools";
const inject = ["tools"];

function apply(ctx) {
	ctx.tools.register(defineTool({
		name: "nuclei_scan",
		description: "Template-based vuln scan (local nuclei). Conservative rate by default (-rl 15); explicit `rate` override is audit-logged. Requires the target registered in the workspace assets.md (防盲打). Hits append to scan-reconcile.md as 待处置 (hit ≠ vuln — verify with 对照三件套 before reporting).",
		parameters: {
			target: { type: "string", required: true, description: "Target URL/host (must be registered in assets.md)" },
			workspace: { type: "string", required: true, description: "Task workspace root" },
			severity: { type: "string", description: "e.g. medium,high,critical (default high,critical)" },
			rate: { type: "integer", description: "requests/sec override (default 15; override is audit-logged)" }
		},
		output: { schema: { type: "object", additionalProperties: true }, render: (_a, v) => [{ type: "text", text: v.ok ? `nuclei: ${v.__summaryText ?? ""}${v.stdout ? " — " + v.stdout : ""}（证据 ${v.evidenceId}）` : `nuclei 拒绝/失败：${v.error}` }] },
		execute(args) {
			const severity = args.severity ?? "high,critical";
			const args2 = ["-u", args.target, "-severity", severity, "-jsonl", "-silent", "-nc"];
			return Promise.resolve(runScan({ bin: "nuclei", args: args2, workspace: path.resolve(args.workspace), tool: "nuclei", rate: args.rate, defaultRate: RATE_DEFAULTS.nuclei, active: true, target: args.target, parse: nucleiParse }));
		}
	}));
	ctx.tools.register(defineTool({
		name: "httpx_probe",
		description: "Alive/tech-fingerprint probe (local httpx). Light recon: unregistered targets allowed, but backfill assets.md with the results. Conservative rate by default (-rl 25).",
		parameters: {
			targets: { type: "string", required: true, description: "One URL/host, or comma-separated list" },
			workspace: { type: "string", required: true, description: "Task workspace root" },
			rate: { type: "integer", description: "requests/sec override (default 25; audit-logged)" }
		},
		output: { schema: { type: "object", additionalProperties: true }, render: (_a, v) => [{ type: "text", text: v.ok ? `httpx: ${v.stdout ?? ""}（证据 ${v.evidenceId}）` : `httpx 失败：${v.error}` }] },
		execute(args) {
			const args2 = ["-u", args.targets, "-json", "-silent", "-title", "-tech-detect", "-status-code"];
			return Promise.resolve(runScan({ bin: "httpx", args: args2, workspace: path.resolve(args.workspace), tool: "httpx", rate: args.rate, defaultRate: RATE_DEFAULTS.httpx, active: false, target: args.targets, parse: httpxParse }));
		}
	}));
	ctx.tools.register(defineTool({
		name: "ffuf_fuzz",
		description: "Dir/param fuzz (local ffuf). Conservative rate by default (-rate 50). Requires target registered in assets.md (防盲打). Use mode=dir for path fuzzing, mode=param for parameter discovery.",
		parameters: {
			url: { type: "string", required: true, description: "URL containing FUZZ keyword, e.g. https://host/FUZZ" },
			workspace: { type: "string", required: true, description: "Task workspace root" },
			mode: { type: "string", enum: ["dir", "param"], required: true, description: "dir = path fuzz; param = parameter discovery (?FUZZ=1)" },
			wordlist: { type: "string", description: "Path to wordlist (default: common.txt via -w common if available)" },
			rate: { type: "integer", description: "requests/sec override (default 50; audit-logged)" }
		},
		output: { schema: { type: "object", additionalProperties: true }, render: (_a, v) => [{ type: "text", text: v.ok ? `ffuf: ${v.stdout ?? ""}（证据 ${v.evidenceId}）` : `ffuf 拒绝/失败：${v.error}` }] },
		execute(args) {
			const wl = args.wordlist ?? "common.txt";
			if (!fs.existsSync(path.resolve(wl))) return Promise.resolve({ ok: false, error: `字典不存在：${wl}——请给 wordlist 参数（绝对路径或 SecLists）；本工具不代装字典。` });
			const u = args.mode === "param" ? (args.url.includes("FUZZ=") ? args.url : args.url + (args.url.includes("?") ? "&" : "?") + "FUZZ=1") : args.url;
			ensureDirs(path.resolve(args.workspace));
			const ts = new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
			const outFile = path.join(path.resolve(args.workspace), "artifacts", "scans", `ffuf-${ts}.json`);
			const args2 = ["-u", u, "-w", wl, "-mc", "200,204,301,302,307,401,403", "-o", outFile, "-of", "json", "-s"];
			return Promise.resolve(runScan({ bin: "ffuf", args: args2, workspace: path.resolve(args.workspace), tool: "ffuf", rate: args.rate, defaultRate: RATE_DEFAULTS.ffuf, active: true, target: args.url, parse: ffufParse, outFile }));
		}
	}));
}

export { apply, inject, name, RATE_DEFAULTS };
