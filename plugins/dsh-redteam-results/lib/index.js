// dsh-redteam-results — 会话隔离的 redteam 成果登记（七模式）宿主插件。
//
// 三件事：
//   1) 模型侧工具：redteam_finding_register / update / delete——执行时从 exec.agent
//      自动取 sessionId 与 agentPreset，成果严格按「会话 × 模式」隔离；
//   2) 存储：node:sqlite 单库 ~/.dsh/redteam-results/results.db（行级持久——删除某条
//      成果即删除对应行，除非删库，数据永远在）；
//   3) Web 通道：不走 connection.rpc（其在部分 fiber 上注册 webServer 路由会静默失败），
//      而是 better-sidebar 同款配方——静态注入 webServer/webRuntime，自己注册
//      /dsh-redteam-results 前缀路由 + 同源信任栅栏，会话标签页直接 POST JSON 读写。
//
// 「验证」按钮：取 agents 注册表把复核请求作为一条用户消息 followup 进当前会话，
// 模型按模式验证纪律复核后用 redteam_finding_update 回写状态。

import path from "node:path";
import os from "node:os";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { openStore, registerFinding, updateFinding, removeFinding, getFinding, listFindings, listFindingsAll, groupByTarget, groupByTargetAll, computeStats, computeStatsAll, modeCounts, modeCountsAll, ledgerOverview, ledgerOverviewAll, getMeta, setMeta, SEVERITIES, STATUSES, EVIDENCE_LEVELS, SOURCE_ORIGINS } from "./store.js";

const name = "dsh-redteam-results";
const inject = ["tools", "webServer", "webRuntime", "agentPresets"];

const ROUTE_PATH = "/dsh-redteam-results";
const MODES = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];
const MODE_LABELS = {
	redteam: "研究员模式",
	pentest: "渗透测试模式",
	"code-audit": "代码审计模式",
	"binary-analysis": "二进制分析模式",
	"attack-defense": "攻防评估模式",
	"av-evasion": "免杀对抗模式",
	"incident-response": "应急溯源模式",
	"cloud-security": "云安全攻防模式",
	"ctf-solver": "CTF 解题模式"
};
const DB_PATH = path.join(os.homedir(), ".dsh", "redteam-results", "results.db");
const MAX_BODY = 5 * 1024 * 1024;

let store; // 进程级单句柄（DatabaseSync 同步 API，SQLite 自带串行化）
function theStore() {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}

//#region 通道与工具共用的业务逻辑

/** 一键验证的注入文案（用户消息；进入会话后由模型按模式验证纪律复核并回写状态）。 */
export function verifyMessage(finding) {
	const lines = [
		`[成果验证请求] 复核「redteam 成果」页 finding #${finding.seq}：${finding.title}`,
		`等级 ${finding.severity} ｜ 目标 ${finding.target || "（未填）"} ｜ 当前状态 ${finding.status} ｜ 证据等级 ${finding.evidenceLevel}`
	];
	if (finding.poc) lines.push(`复现材料：\n${finding.poc}`);
	if (finding.baseline || finding.diffEvidence || finding.markerEcho) lines.push(`对照三件套：基线=${finding.baseline || "缺"} ｜ 差分=${finding.diffEvidence || "缺"} ｜ marker=${finding.markerEcho || "缺"}`);
	if (finding.impact) lines.push(`影响证明：${finding.impact}`);
	if (finding.chain) lines.push(`工人链：${finding.chain}`);
	if (finding.chainTracer) lines.push(`追踪员链：${finding.chainTracer}`);
	if (finding.evidence) lines.push(`证据引用：${finding.evidence}`);
	if (finding.timelineAt) lines.push(`攻击时间：${finding.timelineAt}`);
	if (finding.entry || finding.identity || finding.permission || finding.resource) lines.push(`攻击路径四要素：入口=${finding.entry || "缺"} ｜ 身份=${finding.identity || "缺"} ｜ 权限=${finding.permission || "缺"} ｜ 资源=${finding.resource || "缺"}`);
	lines.push("请按本模式验证纪律复核（渗透模式=对照三件套：基线/差分/marker 逐字回显），复核后调 redteam_finding_update 回写 status（verified/false-positive）与 verifyNote。");
	return lines.join("\n");
}

function sessionOf(ctx, exec) {
	const agent = exec?.agent;
	const id = agent?.session?.id;
	if (!id) return undefined;
	let preset;
	try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
	if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
	return { id: String(id), mode: MODES.includes(preset) ? preset : "redteam" };
}

function resolveAgents(ctx) {
	try { return ctx.get("agents"); } catch { /* 该 fiber 未声明 agents */ }
	try { return ctx.agents; } catch { /* 同上 */ }
	return undefined;
}

//#endregion

//#region HTTP 通道（自注册路由 + 同源信任栅栏）

function hostOf(headers) {
	const h = headers?.host;
	return typeof h === "string" ? h : "";
}

function isLoopbackHostname(hostname) {
	if (hostname === "localhost" || hostname === "[::1]") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/** 同源信任栅栏：Host 是本机/受信授权，且 Origin（浏览器跨站标记）与 Host 同源。 */
export function isTrustedRequest(req, trustedHosts) {
	const host = hostOf(req.headers);
	if (host === "") return false;
	let hostUrl;
	try { hostUrl = new URL(`http://${host}`); } catch { return false; }
	const okHost = isLoopbackHostname(hostUrl.hostname) || (trustedHosts ?? []).some((t) => {
		try { return new URL(`http://${t}`).hostname === hostUrl.hostname; } catch { return false; }
	});
	if (!okHost) return false;
	const origin = req.headers?.origin;
	if (typeof origin === "string" && origin !== "null") {
		try {
			const originUrl = new URL(origin);
			if (originUrl.hostname !== hostUrl.hostname) return false;
		} catch { return false; }
	}
	return true;
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let size = 0;
		const chunks = [];
		req.on("data", (c) => {
			size += c.length;
			if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); return; }
			chunks.push(c);
		});
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

/** 通道端点分发（纯逻辑，供路由与测试复用）。 */
export async function dispatch(ctx, st, endpoint, payload) {
	const p = payload ?? {};
	if (endpoint === "findings.list") {
		const mode = String(p.mode ?? "redteam");
		if (p.scope === "all") {
			// 跨会话模式页：该模式全表 + created_at 范围过滤；counts=全时域侧栏计数；行带 sessionId
			const range = { from: String(p.from ?? ""), to: String(p.to ?? "") };
			return { list: listFindingsAll(st, mode, { ...p, ...range }), stats: computeStatsAll(st, mode, range), counts: modeCountsAll(st) };
		}
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { list: listFindings(st, sessionId, mode, p), stats: computeStats(st, sessionId, mode), counts: modeCounts(st, sessionId), meta: getMeta(st, sessionId) };
	}
	if (endpoint === "findings.groups") {
		const mode = String(p.mode ?? "redteam");
		if (p.scope === "all") {
			const range = { from: String(p.from ?? ""), to: String(p.to ?? "") };
			return { groups: groupByTargetAll(st, mode, { ...p, ...range }) };
		}
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { groups: groupByTarget(st, sessionId, mode, p) };
	}
	if (endpoint === "counts.all") {
		return { counts: modeCountsAll(st) };
	}
	if (endpoint === "ledger.overview") {
		if (p.scope === "all") {
			// 跨会话全局大屏：按登记时间（created_at）过滤，from/to 为 ISO 字符串（可空）
			return { overview: ledgerOverviewAll(theStore(), { from: String(p.from ?? ""), to: String(p.to ?? "") }) };
		}
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { overview: ledgerOverview(theStore(), sessionId), meta: getMeta(theStore(), sessionId) };
	}
	if (endpoint === "meta.set") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, meta: setMeta(st, sessionId, p) };
	}
	if (endpoint === "finding.delete") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		removeFinding(st, sessionId, String(p.id ?? ""));
		return { ok: true, counts: modeCounts(st, sessionId) };
	}
	if (endpoint === "finding.verify") {
		const sessionId = String(p.sessionId ?? "");
		const finding = getFinding(st, sessionId, String(p.id ?? ""));
		if (!finding) return { ok: false, error: "finding 不存在" };
		const agents = resolveAgents(ctx);
		const agent = agents?.get?.(sessionId);
		if (!agent || typeof agent.followup !== "function") return { ok: false, error: "会话不可达（代理未运行）" };
		agent.followup({ id: `rtr-${Date.now()}-${finding.seq}`, content: [{ type: "text", text: verifyMessage(finding) }], source: { kind: "user" } });
		return { ok: true };
	}
	throw new Error(`unknown endpoint ${endpoint}`);
}

//#endregion

//#region host wiring

function apply(ctx) {
	//#region 模型工具（宿主平面，七模式可见）
	ctx.tools.register(defineTool({
		name: "redteam_finding_register",
		description: "Register one finding into this session's「redteam 成果」tab — session- and mode-scoped automatically from the CURRENT session (you cannot and must not specify another mode). Call it for every finding entering a report; keep status honest (pending until verified). Common fields: title/target/severity/description/poc/evidence/summary/status. Mode-native fields are defined in the CURRENT preset's persona「成果登记」条款 — follow that, do not invent fields. Register from the main session; subagent registrations land in the subagent's own session store.",
		parameters: {
			title: { type: "string", required: true, description: "漏洞/问题名称（简短）" },
			severity: { type: "string", required: true, enum: SEVERITIES, description: "critical/high/medium/low（严重/高危/中危/低危）" },
			target: { type: "string", required: true, description: "漏洞地址/目标（URL、主机、对象路径）" },
			summary: { type: "string", required: true, description: "核心简介一句话（列表展示用）" },
			type: { type: "string", description: "漏洞类型（如 SQLi/XSS/未授权；可含 CWE）" },
			description: { type: "string", description: "漏洞描述（影响与成因）" },
			poc: { type: "string", description: "测试过程/复现 EXP（完整可复现步骤或脚本）；代码审计填复现条件或利用前提" },
			chain: { type: "string", description: "调用链 entry→sink（代码审计：审计工人链，双链格式每行一链，如 Controller.x() → Service.y() → Dao.z(sql)）" },
			chainTracer: { type: "string", description: "追踪员链（审计双链第二侧，独立重追的 entry→sink；与 chain 对照）" },
			chainVerdict: { type: "string", description: "双链一致性结论（一致/不一致+差异说明；不一致=疑似不进 confirmed）" },
			snippetEntry: { type: "string", description: "入口代码片段（审计：entry 处关键代码）" },
			snippetSink: { type: "string", description: "sink 代码片段（审计：危险点实际代码）" },
			cwe: { type: "string", description: "CWE 编号（如 CWE-89）" },
			patch: { type: "string", description: "修复 diff 建议（审计可选，diff 格式）" },
			sourceOrigin: { type: "string", enum: SOURCE_ORIGINS, description: "来源：manual=人工深审 / scan-confirmed=扫描命中复核确认 / scan-false-positive=扫描误报复核（审计对账用）" },
			sampleHash: { type: "string", description: "样本 SHA256（二进制分析：样本唯一标识，页面按样本分组）" },
			family: { type: "string", description: "家族/变种归属（二进制分析，如 AgentTesla、CobaltStrike）" },
			packer: { type: "string", description: "壳/保护（二进制分析，如 UPX、VMProtect、无壳）" },
			iocs: { type: "string", description: "IOC 清单（二进制分析：C2/URL/IP/互斥量/注册表/持久化位置，每行一条）" },
			detectionRule: { type: "string", description: "检测规则（二进制分析：YARA/Sigma 原文）" },
			baseline: { type: "string", description: "对照三件套①基线（渗透：正常请求的行数/内容基线）" },
			diffEvidence: { type: "string", description: "对照三件套②差分（渗透：注入后真实翻转证据）" },
			markerEcho: { type: "string", description: "对照三件套③marker 逐字回显" },
			impact: { type: "string", description: "影响证明（渗透：拿到什么数据/执行到什么程度，如 whoami 输出、脱库行数）" },
			cvss: { type: "string", description: "CVSS 向量与评分（如 CVSS:3.1/AV:N/... (8.6)）" },
			requestPkt: { type: "string", description: "完整请求包（渗透：决定性请求原文）" },
			responsePkt: { type: "string", description: "关键响应（渗透：证明影响的响应原文/片段）" },
			evidence: { type: "string", description: "证据引用（evidence-index 编号/产物路径；审计=双链比对文件 artifacts/<id>-chains.md）" },
			fix: { type: "string", description: "修复建议" },
			timelineAt: { type: "string", description: "攻击时间节点（时间线排序：ISO 或 YYYY-MM-DD HH:MM；未知填 unknown）" },
			entry: { type: "string", description: "入口凭证或身份（云安全：AK/SK、实例身份、公开入口）" },
			identity: { type: "string", description: "利用身份（云安全：IAM 用户/角色/服务身份）" },
			permission: { type: "string", description: "权限（云安全：策略名/权限清单）" },
			resource: { type: "string", description: "目标资源（云安全：ARN/桶名/实例 ID）" },
			status: { type: "string", enum: STATUSES, description: "默认 pending；已复核才填 verified/false-positive" },
			evidenceLevel: { type: "string", enum: EVIDENCE_LEVELS, description: "证据等级，默认 unknown" }
		},
		output: {
			schema: {
				type: "object",
				additionalProperties: true,
				properties: {
					ok: { type: "boolean", required: true },
					id: { type: "string", required: true }
				}
			},
			render: (_a, v) => [{ type: "text", text: v.ok ? `已登记成果 #${v.seq} ${v.title}（${v.mode}，${v.severity}）——本会话「redteam 成果」页可见` : `登记失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session) return Promise.resolve({ ok: false, id: "", error: "无法解析当前会话（工具需在会话内调用）" });
			const finding = registerFinding(theStore(), session.id, session.mode, args);
			return Promise.resolve({ ok: true, id: finding.id, seq: finding.seq, title: finding.title, mode: finding.mode, severity: finding.severity });
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_finding_update",
		description: "Update one finding in this session's「redteam 成果」tab by id (from redteam_finding_register's result): status transitions after verification (verified/false-positive/fixed), severity/字段修订，verifyNote 记录复核结论。",
		parameters: {
			id: { type: "string", required: true, description: "finding id（如 pentest-3）" },
			status: { type: "string", enum: STATUSES, description: "新状态" },
			verifyNote: { type: "string", description: "复核注记（结论+依据，简短）" },
			severity: { type: "string", enum: SEVERITIES },
			title: { type: "string" },
			type: { type: "string" },
			target: { type: "string" },
			summary: { type: "string" },
			description: { type: "string" },
			poc: { type: "string" },
			chain: { type: "string" },
			chainTracer: { type: "string" },
			chainVerdict: { type: "string" },
			snippetEntry: { type: "string" },
			snippetSink: { type: "string" },
			cwe: { type: "string" },
			patch: { type: "string" },
			sourceOrigin: { type: "string", enum: SOURCE_ORIGINS },
			sampleHash: { type: "string" },
			family: { type: "string" },
			packer: { type: "string" },
			iocs: { type: "string" },
			detectionRule: { type: "string" },
			baseline: { type: "string" },
			diffEvidence: { type: "string" },
			markerEcho: { type: "string" },
			impact: { type: "string" },
			cvss: { type: "string" },
			requestPkt: { type: "string" },
			responsePkt: { type: "string" },
			retestNote: { type: "string", description: "复测注记（修复后复测结论：已修复/部分/未修复+依据）" },
			evidence: { type: "string" },
			fix: { type: "string" },
			timelineAt: { type: "string", description: "攻击时间节点（时间线排序：ISO 或 YYYY-MM-DD HH:MM；未知填 unknown）" },
			entry: { type: "string" },
			identity: { type: "string" },
			permission: { type: "string" },
			resource: { type: "string" },
			evidenceLevel: { type: "string", enum: EVIDENCE_LEVELS }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `成果已更新：${v.id} → ${v.status ?? "字段修订"}${v.verifyNote ? `（${v.verifyNote}）` : ""}` : `更新失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session) return Promise.resolve({ ok: false, error: "无法解析当前会话" });
			const finding = updateFinding(theStore(), session.id, session.mode, args.id, args);
			if (finding === undefined) return Promise.resolve({ ok: false, error: `finding ${args.id} 不存在（本会话 ${session.mode} 页）` });
			return Promise.resolve({ ok: true, id: finding.id, status: finding.status, verifyNote: finding.verifyNote });
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_finding_delete",
		description: "Remove one finding from this session's「redteam 成果」tab by id（页面删除按钮同源；删除即删数据库行，统计同步更新）。",
		parameters: { id: { type: "string", required: true, description: "finding id" } },
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `已删除成果 ${v.id}` : `删除失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session) return Promise.resolve({ ok: false, error: "无法解析当前会话" });
			removeFinding(theStore(), session.id, args.id);
			return Promise.resolve({ ok: true, id: args.id });
		}
	}));
	//#endregion

	//#region Web 通道路由（better-sidebar 同款：webServer 自注册 + 同源栅栏）
	const trustedHosts = () => {
		try { return ctx.webRuntime?.trustedHosts ?? []; } catch { return []; }
	};
	ctx.effect(() => ctx.webServer.register({
		kind: "prefix",
		path: ROUTE_PATH,
		handler: async (req, res) => {
			const send = (code, body) => {
				const text = JSON.stringify(body);
				res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
				res.end(text);
			};
			if (!isTrustedRequest(req, trustedHosts())) { res.writeHead(403); res.end("forbidden"); return; }
			if (req.method !== "POST") { res.writeHead(405); res.end("method not allowed"); return; }
			let endpoint = "";
			try { endpoint = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname.slice(ROUTE_PATH.length)).replace(/^\/+/, ""); } catch { endpoint = ""; }
			if (endpoint === "") { res.writeHead(404); res.end("not found"); return; }
			try {
				const raw = await readBody(req);
				const payload = raw === "" ? {} : JSON.parse(raw);
				const result = await dispatch(ctx, theStore(), endpoint, payload);
				send(200, result);
			} catch (e) {
				send(400, { ok: false, error: e?.message ?? String(e) });
			}
		}
	}), "dsh-redteam-results: web route");
	//#endregion
}

export { MODES, MODE_LABELS, SEVERITIES, STATUSES, EVIDENCE_LEVELS, ROUTE_PATH, apply, inject, name, openStore };

//#endregion
