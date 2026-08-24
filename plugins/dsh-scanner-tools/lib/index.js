// dsh-scanner-tools — 本机扫描器封装为模型工具（nuclei/httpx/ffuf/nmap/subfinder/whatweb），
// 纪律内置：
//   1) 速率纪律参数化：保守默认（nuclei -rl 15 / httpx -rl 25 / ffuf -rate 50 / nmap --max-rate 1000 /
//      whatweb -a 1 / hydra -t 4），显式提速会记录在扫描审计里（默认值与 pentest-playbook 速率纪律一致）；
//   2) 产物落证据：JSON/JSONL 写 <workspace>/artifacts/scans/；注册表工具全文输出写
//      artifacts/tool-output/（超限返回封顶预览 + 落盘路径供按需读取）；均回 evidence-index.md 一行；
//   3) 命中进对账：nuclei 命中自动写 scan-reconcile.md 待处置行（命中 ≠ 漏洞，复核后终态）；
//   4) 防盲打：主动扫描（nuclei/ffuf/nmap）要求目标已登记 assets.md / cloud-assets.md；轻探测
//      （httpx/whatweb/被动枚举 subfinder）允许未登记但产出登记建议；
//   5) 输出治理：返回模型的预览封顶（头尾拼接+全文指针），全文永落盘不丢；每工具连续失败
//      3 次熔断 60s（防死磕——提示改走阶梯下级通道）；
//   6) 工具调用阶梯（六节点）：本机 → MCP → 已装替代 → MCP 备选 → 询问安装 → 不批准走脚本编写
//      （registry.js 每个 def.tiers 落到工具描述与缺装提示；绝不自动安装）。
// 挂载：preset 平面（pentest / attack-defense / cloud-security / ctf-solver 各自 agent.cordis.yml 一行）。

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { TOOL_DEFS, buildArgs, tiersLine } from "./registry.js";

const RATE_DEFAULTS = { nuclei: 15, httpx: 25, ffuf: 50 }; // 保守默认；显式覆盖会留痕
const BIN_HINT = "三级兜底：本机未装该工具——先查已连接 MCP（如 kali MCP），仍无则按 pentest-playbook 安装请求流程征得用户批准后安装；本工具绝不自动安装。";

/** which-style binary check without shell. */
export function hasBin(bin) {
	const probe = process.platform === "win32" ? spawnSync("where", [bin]) : spawnSync("/usr/bin/which", [bin]);
	return probe.status === 0;
}

/** target host must appear in the baseline file (active scans only). Returns {ok, hint, baseline}.
 *  基线文件按预设双候选探测：assets.md（pentest/攻防）或 cloud-assets.md（cloud-security C1）——
 *  任一存在即按其校验；两个都无才拒绝。 */
export function checkRegistered(fsMod, workspace, target) {
	const baselines = ["cloud-assets.md", "assets.md"]; // cloud 前置：云会话的基线是 cloud-assets.md
	let text = "", used = "";
	for (const f of baselines) {
		try { text = fsMod.readFileSync(path.join(workspace, f), "utf8"); } catch { text = ""; }
		if (text) { used = f; break; }
	}
	if (!text) return { ok: false, hint: "工作区无 assets.md / cloud-assets.md 资产基线——先完成测绘阶段（pentest Gate P1 / cloud Gate C1）再主动扫描" };
	const host = String(target).replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
	return text.includes(host)
		? { ok: true, hint: "" }
		: { ok: false, hint: `目标 ${host} 未登记在 ${used}——防盲打：先登记资产（测绘组回填基线文件）再主动扫描` };
}

function ensureDirs(workspace) {
	fs.mkdirSync(path.join(workspace, "artifacts", "scans"), { recursive: true });
}

//#region 输出治理：返回模型的预览封顶 + 全文永落盘可回读 + 每工具连续失败熔断

const PREVIEW_HEAD = 3600, PREVIEW_TAIL = 2000;

/** 预览封顶（纯函数）：短输出原样返回；长输出头尾拼接 + 中间省略量标注。 */
export function governPreview(raw) {
	const s = String(raw ?? "");
	if (s.length <= PREVIEW_HEAD + PREVIEW_TAIL + 200) return { preview: s, truncated: false, bytes: s.length };
	const mid = s.length - PREVIEW_HEAD - PREVIEW_TAIL;
	return { preview: s.slice(0, PREVIEW_HEAD) + `\n…（中间省略 ${mid} 字符——全文已落盘，按需读取）…\n` + s.slice(-PREVIEW_TAIL), truncated: true, bytes: s.length };
}

/** 全文落盘（证据原件）：artifacts/tool-output/<tool>-<ts>.txt，返回工作区相对路径。 */
export function spillOutput(fsMod, workspace, tool, raw) {
	const dir = path.join(workspace, "artifacts", "tool-output");
	fsMod.mkdirSync(dir, { recursive: true });
	const ts = new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
	const file = path.join(dir, `${tool}-${ts}.txt`);
	fsMod.writeFileSync(file, String(raw ?? ""));
	return path.relative(workspace, file);
}

const BREAKER_THRESHOLD = 3, BREAKER_COOLDOWN_MS = 60_000;
const breakerMap = new Map(); // tool → { fails, until }（进程级；重启自然重置）

/** 熔断查询：冷却中返回剩余秒数，放行返回 0。 */
export function breakerCheck(tool, nowMs = Date.now()) {
	const b = breakerMap.get(tool);
	return b && b.until > nowMs ? Math.ceil((b.until - nowMs) / 1000) : 0;
}

/** 熔断记账：成功清零；连续失败达阈值进入冷却（防死磕同一工具——提示改走阶梯下级通道）。 */
export function breakerRecord(tool, ok, nowMs = Date.now()) {
	const b = breakerMap.get(tool) ?? { fails: 0, until: 0 };
	if (ok) { b.fails = 0; b.until = 0; }
	else { b.fails += 1; if (b.fails >= BREAKER_THRESHOLD) { b.until = nowMs + BREAKER_COOLDOWN_MS; b.fails = 0; } }
	breakerMap.set(tool, b);
}

//#endregion

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
	const cooldown = breakerCheck(tool);
	if (cooldown > 0) return { ok: false, error: `熔断中：${tool} 连续失败 3 次进入 60s 冷却（剩 ${cooldown}s）——改走工具调用阶梯下级通道（MCP/替代/脚本）或稍后重试`, bin };
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
	if (proc.error) { breakerRecord(tool, false); return { ok: false, error: `执行失败：${proc.error.message}${proc.error.code === "ETIMEDOUT" ? `（超时 ${timeoutMs / 1000}s${bin === "nuclei" ? "——模板库缺失时首次会尝试拉取导致超时" : ""}）` : ""}`, bin }; }
	breakerRecord(tool, proc.status === 0);

	const raw = proc.stdout ? proc.stdout.toString() : "";
	const parsed = parse ? parse(raw, proc) : { raw: raw };
	if (parsed.__writeRaw !== null && parsed.__writeRaw !== undefined) fs.writeFileSync(outFile, parsed.__writeRaw);
	else fs.writeFileSync(outFile, JSON.stringify({ raw: raw }, null, 2)); // 全文落盘不截断（模型侧预览另由注册表工具治理）
	const evidenceId = nextEvidenceId(workspace);
	appendEvidence(workspace, evidenceId, cmdStr + (rate && rate !== defaultRate ? `（速率显式覆盖：默认 ${defaultRate} → ${rate}，留痕）` : `（保守默认速率 ${defaultRate}）`), path.relative(workspace, outFile));
	const reconciled = appendReconcile(workspace, parsed.__hits || []);
	return { ok: proc.status === 0, evidenceId, file: path.relative(workspace, outFile), summary: parsed.__summary ?? {}, hits: (parsed.__hits || []).length, reconciled, stdout: parsed.__summaryText ?? "" };
}

//#region 注册表工具执行器：声明式 def → 构参 → 治理执行（预览封顶 + 全文落盘 + 熔断 + 阶梯提示）

/** 按注册表 def 执行一个工具。输出治理：全文永落盘（证据原件 + 回读指针），返回模型的是封顶预览。 */
export function runGoverned({ def, params, workspace, fsMod = fs }) {
	const ws = path.resolve(workspace);
	const cooldown = breakerCheck(def.id);
	if (cooldown > 0) return { ok: false, error: `熔断中：${def.id} 连续失败 3 次进入 60s 冷却（剩 ${cooldown}s）——改走工具调用阶梯下级通道（MCP/替代/脚本）或稍后重试` };
	if (def.guard?.active) {
		const tp = def.guard.targetParam ?? "target";
		const reg = checkRegistered(fsMod, ws, params[tp] ?? params.target ?? params.domain ?? "");
		if (!reg.ok) return { ok: false, error: reg.hint, bin: def.bin };
	}
	// 二进制候选解析：def.bins 按序探测（支持 {module} 占位——impacket 的 impacket-<m>/<m>.py 双安装名）
	const binCandidates = (def.bins ?? [def.bin]).map((c) => c.replace("{module}", String(params.module ?? def.bin)));
	let bin = null;
	for (const cand of binCandidates) if (hasBin(cand)) { bin = cand; break; }
	if (!bin) return { ok: false, error: `${BIN_HINT}\n${tiersLine(def)}`, bin: def.bin, tiers: tiersLine(def) };
	let built;
	try { built = buildArgs(def, params); } catch (e) { return { ok: false, error: `参数拒绝：${e.message}` }; }
	const cmdStr = `${bin} ${built.argv.join(" ")}`;
	const proc = spawnSync(bin, built.argv, { timeout: def.limits.timeoutMs, maxBuffer: 32 * 1024 * 1024 });
	if (proc.error) {
		breakerRecord(def.id, false);
		return { ok: false, error: `执行失败：${proc.error.message}${proc.error.code === "ETIMEDOUT" ? `（超时 ${def.limits.timeoutMs / 1000}s）` : ""}\n${tiersLine(def)}`, tiers: tiersLine(def) };
	}
	breakerRecord(def.id, proc.status === 0);
	const raw = (proc.stdout ? proc.stdout.toString() : "") + (proc.stderr && proc.stderr.toString().trim() ? `\n[stderr]\n${proc.stderr.toString()}` : "");
	const gov = governPreview(raw);
	const persisted = spillOutput(fsMod, ws, def.id, raw);
	const evidenceId = nextEvidenceId(ws);
	appendEvidence(ws, evidenceId, cmdStr + (built.audit.length ? `（${built.audit.join("；")}）` : "（保守默认参数）"), persisted);
	return {
		ok: proc.status === 0, evidenceId, persisted, bytes: gov.bytes, truncated: gov.truncated,
		preview: gov.preview,
		summaryText: `${def.id} 完成（exit ${proc.status}，输出 ${gov.bytes} 字符${gov.truncated ? "，预览已封顶" : ""}；全文 ${persisted}；证据 ${evidenceId}）`,
		tiers: tiersLine(def)
	};
}

//#endregion

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
	return { __writeRaw: JSON.stringify(out, null, 2), __hits: [], __summary: { alive: out.length }, __summaryText: `存活 ${out.length}；探测未登记资产属测绘行为，结果请回填资产基线（assets.md / cloud-assets.md）` };
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
	// 注册表工具统一注册：def 带全部工具面元数据（名称/摘要/参数 schema/阶梯/守卫），新增工具只改 registry.js
	for (const def of Object.values(TOOL_DEFS)) {
		ctx.tools.register(defineTool({
			name: def.name,
			description: `${def.summary} Full output always persisted to artifacts/tool-output/ with a capped preview returned. ${def.hint}。${tiersLine(def)}`,
			parameters: Object.assign({
				workspace: { type: "string", required: true, description: "Task workspace root" },
				extra: { type: "string", description: "Explicit extra args (audit-logged escape hatch; shell metacharacters rejected)" }
			}, def.params),
			output: { schema: { type: "object", additionalProperties: true }, render: (_a, v) => [{ type: "text", text: v.ok ? `${v.summaryText}\n${v.preview}` : `${def.id} 拒绝/失败：${v.error}` }] },
			execute(args) {
				return Promise.resolve(runGoverned({ def, params: args, workspace: args.workspace }));
			}
		}));
	}
}

export { apply, inject, name, RATE_DEFAULTS };
