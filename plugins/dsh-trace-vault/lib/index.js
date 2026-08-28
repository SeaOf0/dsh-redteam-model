// dsh-trace-vault — 过程库宿主插件（九模式）。
//
// 自动留痕：监听 session/event 的 tool/call + tool/result（callId 配对），把九个安全
// 模式会话的每一次工具调用落 SQLite——调用参数、结果文本、出局分类（ok/blocked/error）、
// 耗时。零行为改变：不拦截、不改写、不注入提示；模型与用户无感。
//
// 价值三连：
//   1) 跨 compaction 过程记忆——压缩后模型仍能 trace_search 检索历史轮次的调用与
//      响应片段（某个报错、WAF 拦截页、回显、响应头），不依赖「记得」；
//   2) 过程级信息交换——子会话/多轮之间「谁在哪个调用里见过 X」可检索；
//   3) 失败归因数据面——blocked 计数（WAF/403/429）是「换路径/降速」信号的程序来源
//      （信封渲染在后续批次接入，本批只落数据）。
//
// 边界：定位是索引不是归档——args/result 落库即截断（8K/32K），全文在会话
// transcript；仅安全模式会话入库（其余会话零捕获）；本地库不做脱敏（与战役记忆
// 同纪律：内网地址/指纹细节是过程证据的价值所在）。

import path from "node:path";
import os from "node:os";
import z from "@deepseek-ai/schemastery";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { openStore, insertTrace, searchTraces, getTrace, listRecent, statsTraces, sessionStats, classifyOutcome, argsTextOf, resultTextOf } from "./store.js";

const name = "dsh-trace-vault";
const inject = ["tools", "agentPresets", "systemPrompt"];

export const MODE_IDS = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];

const Config = z.object({
	capture: z.boolean().default(true),
	tools: z.boolean().default(true),
	envelope: z.boolean().default(true),
	retentionDays: z.natural().default(14),
	maxRows: z.natural().default(50000)
});

/** 失败归因信封（纯函数，供测试）：blocked 聚集时一行提示，否则空串。
 *  变化才投由 RuntimeContextProjection 保证（与 route-boost 同机制）——
 *  无信号/信号未变时零 token 成本。 */
export const ENVELOPE_TAG = "dsh-trace-vault";
export function buildOutcomeHint(stats, { windowMinutes = 30, threshold = 2 } = {}) {
	if (!stats || Number(stats.blocked) < threshold) return "";
	return `<${ENVELOPE_TAG}>拦截信号：近 ${windowMinutes} 分钟 blocked ${stats.blocked} 次（403/WAF/429/验证码类）——连续受阻先换路径/降速/换 UA 再硬撞；trace_search 可检索拦截响应原文。</${ENVELOPE_TAG}>`;
}

const DB_PATH = path.join(os.homedir(), ".dsh", "trace-vault", "traces.db");
/** 在途配对表上限：超过即整表清空（防事件风暴下内存无界；丢的是未完成调用的配对，非落库数据）。 */
const INFLIGHT_CAP = 4096;
/** 插件自注入 followup 的 id 前缀（这些"用户消息"不是真人介入，画像统计须排除）。 */
const PLUGIN_MSG_PREFIX = ["auto-kickoff-", "auto-advance-", "atlas-nudge-", "hunter-", "rtr-", "refusal-guard-", "t2-task-"];

let store;
function theStore() {
	if (store === undefined) store = openStore(process.env.DSH_TRACE_VAULT_DB || DB_PATH);
	return store;
}

/** 会话真实模式的权威源（与 attack-atlas 同法）：agents 注册表 → composedPreset，
 *  回落 header.agentPreset。任一源解析失败返回 ""（不入库）。 */
function modeOfSession(ctx, sessionId) {
	const agents = (() => {
		try { return ctx.get("agents"); } catch { /* 该 fiber 未声明 agents */ }
		try { return ctx.agents; } catch { /* 同上 */ }
		return undefined;
	})();
	const agent = agents?.get?.(sessionId);
	let mode = "";
	try { mode = String(ctx.agentPresets?.composedPreset?.(agent?.ctx) ?? ""); } catch { /* 组合未就绪 */ }
	if (!MODE_IDS.includes(mode)) {
		const header = agent?.session?.header?.agentPreset;
		mode = MODE_IDS.includes(header) ? header : "";
	}
	return mode;
}

/** 从 tool/result 事件提取 callId（两形态：message.source.callId 或 content 块的 toolCallId）。 */
export function callIdOfResult(event) {
	const message = event?.data?.message ?? {};
	if (message.source?.kind === "tool" && typeof message.source.callId === "string") return message.source.callId;
	if (Array.isArray(message.content)) {
		const block = message.content.find((b) => typeof b?.toolCallId === "string");
		if (block) return block.toolCallId;
	}
	return undefined;
}

/** 从 tool/result 事件提取错误位：显式 error 字段或任一 content 块 isError。 */
export function isErrorResult(event) {
	if (event?.data?.error !== undefined) return true;
	const content = event?.data?.message?.content;
	return Array.isArray(content) && content.some((b) => b?.isError === true);
}

/** 事件层装配（导出供测试）：返回 {onCall, onResult} 两个喂入口，配对后落库。 */
export function createCapture(ctx, st, modeResolver = modeOfSession) {
	const inflight = new Map();
	const onCall = (sessionId, event) => {
		const callId = event?.data?.callId;
		const tool = event?.data?.name;
		if (typeof callId !== "string" || typeof tool !== "string") return;
		if (inflight.size >= INFLIGHT_CAP) inflight.clear();
		inflight.set(`${sessionId}:${callId}`, { tool, args: argsTextOf(event.data.arguments), t0: Date.now() });
	};
	const onResult = (sessionId, event) => {
		const callId = callIdOfResult(event);
		if (typeof callId !== "string") return;
		const key = `${sessionId}:${callId}`;
		const entry = inflight.get(key);
		if (!entry) return;
		inflight.delete(key);
		const mode = modeResolver(ctx, sessionId);
		if (!MODE_IDS.includes(mode)) return; // 仅安全模式入库
		const result = resultTextOf(event?.data?.message?.content);
		insertTrace(st, {
			id: key,
			sessionId: String(sessionId ?? ""),
			mode,
			tool: entry.tool,
			args: entry.args,
			result,
			isError: isErrorResult(event),
			durMs: Date.now() - entry.t0
		});
	};
	// 人工介入画像：真人用户消息落 '(intervention)' 行（插件注入的 followup 按 id 前缀排除）
	const onHuman = (sessionId, event) => {
		const msg = event?.data;
		if (msg?.source?.kind !== "user") return;
		const id = String(msg?.id ?? "");
		if (!id || PLUGIN_MSG_PREFIX.some((p) => id.startsWith(p))) return;
		const mode = modeResolver(ctx, sessionId);
		if (!MODE_IDS.includes(mode)) return;
		const text = Array.isArray(msg.content) ? msg.content.map((b) => (b?.type === "text" ? String(b.text ?? "") : "")).join("") : String(msg.content ?? "");
		insertTrace(st, { id: `${sessionId}:human:${id}`, sessionId: String(sessionId ?? ""), mode, tool: "(intervention)", args: text.slice(0, 2000), result: "", isError: false });
	};
	return { onCall, onResult, onHuman, inflight };
}

function sessionKey(subject) {
	return String(subject?.id ?? subject?.header?.id ?? "?");
}

function sessionOfExec(ctx, exec) {
	const agent = exec?.agent;
	const id = agent?.session?.id;
	if (!id) return undefined;
	let preset;
	try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
	if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
	return { id: String(id), mode: MODE_IDS.includes(preset) ? preset : undefined };
}

function apply(ctx, config) {
	const cfg = { capture: true, tools: true, envelope: true, retentionDays: 14, maxRows: 50000, ...config };
	let capture;
	if (cfg.capture) {
		capture = createCapture(ctx, theStore());
		ctx.on("session/event", (subject, event) => {
			if (event?.type === "tool/call") {
				capture.onCall(sessionKey(subject), event);
			} else if (event?.type === "tool/result") {
				capture.onResult(sessionKey(subject), event);
			} else if (event?.type === "user/message") {
				capture.onHuman(sessionKey(subject), event);
			}
		});
	}
	// 失败归因信封节：每轮装配重渲染本会话近窗口的 blocked 聚集，变化才投递
	if (cfg.envelope) {
		ctx.systemPrompt.context({
			name: "trace-vault",
			order: 560,
			text: (assembly) => {
				const agent = assembly?.agent;
				if (!agent) return "";
				let preset;
				try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
				if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
				if (!MODE_IDS.includes(preset)) return "";
				const sessionId = agent?.session?.id;
				if (!sessionId) return "";
				try {
					const since = new Date(Date.now() - 30 * 60_000).toISOString().replace("T", " ").slice(0, 19);
					return buildOutcomeHint(statsTraces(theStore(), { sessionId: String(sessionId), since }));
				} catch { return ""; }
			}
		});
	}
	if (!cfg.tools) return;

	ctx.tools.register(defineTool({
		name: "trace_search",
		description: "过程检索：按关键词在历史工具调用的参数与响应文本里找命中（子串匹配，新到旧）。用途——上下文被压缩/轮次久远后找回「曾经出现过」的过程观察：某次报错原文、WAF/拦截响应片段、回显、响应头、某工具当时怎么调的。返回命中行（工具/时间/出局分类/长度），全文用 trace_get 按 id 取。可加 tool/session 过滤。仅安全模式会话可用；本地过程库（自动留痕，未成形观察的检索面——结构化成果用战役记忆）。",
		parameters: {
			query: { type: "string", required: true, description: "关键词（子串命中调用参数或响应文本；大小写不敏感由库保证一致行为）" },
			tool: { type: "string", description: "按工具名过滤（如 bash / fetch）" },
			session_id: { type: "string", description: "限定会话（省略=全部本地会话）" },
			limit: { type: "number", description: "返回行数（默认 10，上限 50）" },
			offset: { type: "number", description: "翻页偏移" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? renderHits(v.rows, v.total ?? v.rows.length) : `检索失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOfExec(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				const rows = searchTraces(theStore(), { q: args.query, tool: args.tool, sessionId: args.session_id, limit: args.limit, offset: args.offset });
				return Promise.resolve({ ok: true, rows, total: rows.length });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "trace_get",
		description: "取一条历史工具调用的完整过程（调用参数全文 + 响应文本全文，落库上限内）。id 来自 trace_search / trace_recent 的命中行。",
		parameters: {
			id: { type: "string", required: true, description: "调用 id（trace_search/trace_recent 返回的 id）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? renderFull(v.row) : `取回失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOfExec(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				const row = getTrace(theStore(), args.id);
				if (!row) return Promise.resolve({ ok: false, error: `无此调用：${args.id}` });
				return Promise.resolve({ ok: true, row });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "trace_recent",
		description: "最近工具调用一览（新到旧）：某工具/某会话最近都调了什么、出局分类（ok/blocked/error）如何。blocked 聚集=WAF/限速拦截信号（换路径/降速）；error 聚集=环境或命令问题。",
		parameters: {
			tool: { type: "string", description: "按工具名过滤" },
			session_id: { type: "string", description: "限定会话（默认=当前会话）" },
			limit: { type: "number", description: "返回行数（默认 20，上限 100）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? renderHits(v.rows, v.total ?? v.rows.length, v.stats) : `取回失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOfExec(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				const sessionId = args.session_id || session.id;
				const rows = listRecent(theStore(), { sessionId, tool: args.tool, limit: args.limit });
				const stats = statsTraces(theStore(), { sessionId });
				return Promise.resolve({ ok: true, rows, total: rows.length, stats });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "trace_stats",
		description: "会话画像统计（评估指标最小集）：本会话工具调用成败分布与成功率、自救信号（blocked 之后是否推进到 ok）、人工介入次数、受阻工具 top。收口自评与运营复盘用；成功率低于 85% 提示工具面工程化问题，blocked 高且无自救=路径僵持信号。",
		parameters: {
			session_id: { type: "string", description: "限定会话（默认=当前会话）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `会话画像：调用 ${v.stats.calls} 次（ok ${v.stats.ok} / blocked ${v.stats.blocked} / error ${v.stats.error}，成功率 ${v.stats.successRate ?? "-"}%）｜自救信号 ${v.stats.selfRecovered ? "有（blocked 后推进到 ok）" : "无"}｜人工介入 ${v.stats.interventions} 次${v.stats.blockedTools.length ? `｜受阻工具 top：${v.stats.blockedTools.join("、")}` : ""}` : `统计失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOfExec(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				const sessionId = args.session_id || session.id;
				return Promise.resolve({ ok: true, stats: sessionStats(theStore(), { sessionId }) });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));
}

function renderHits(rows, total, stats) {
	if (!rows || rows.length === 0) return "无命中。";
	const lines = rows.map((r) => `[${r.id}] ${r.createdAt} ${r.tool} → ${r.outcome}${r.isError ? "（错误）" : ""}${r.durMs != null ? ` ${r.durMs}ms` : ""}（args ${r.argsLen ?? "?"} / result ${r.resultLen ?? "?"} 字符）`);
	const head = total > rows.length ? `命中 ${total} 行，显示前 ${rows.length} 行（翻页用 offset）：` : `${total} 行：`;
	const tail = stats ? `\n出局统计：ok ${stats.ok} / blocked ${stats.blocked} / error ${stats.error}${stats.blocked > 0 ? "——blocked 聚集为拦截信号，建议换路径/降速" : ""}` : "";
	return head + "\n" + lines.join("\n") + tail;
}

function renderFull(row) {
	return [
		`调用 ${row.id}`,
		`模式 ${row.mode} · 会话 ${row.sessionId} · ${row.createdAt}${row.durMs != null ? ` · ${row.durMs}ms` : ""} · 出局 ${row.outcome}${row.isError ? "（错误）" : ""}`,
		"—— 参数 ——",
		row.args || "(空)",
		"—— 结果 ——",
		row.result || "(空)"
	].join("\n");
}

export { Config, apply, inject, name, classifyOutcome, DB_PATH };
