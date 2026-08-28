// dsh-trace-vault store — 过程库 SQLite 数据层（node:sqlite DatabaseSync）。
//
// 单库 ~/.dsh/trace-vault/traces.db：traces 表按「一次工具调用」一行存过程证据
// （调用参数 + 结果文本 + 出局分类），callId 配对由 index.js 的事件层完成后落库。
// 定位是索引不是归档：args/result 落库即截断（ARGS_CAP/RESULT_CAP），全文在会话
// transcript 里；这里存的是「哪个调用、什么参数、回了什么片段」——供跨 compaction
// 检索与失败归因统计。与 campaign-memory 的分工：记忆库存成果（结构化打法），
// 过程库存原始调用流（未成形的观察）。
//
// 检索用 LIKE（子串语义、跨机器行为一致）：本库量级为单工作站数千行级，
// 量上来后再升级 FTS5 trigram（外部内容表 + 触发器同步），接口不变。

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

/** 调用参数落库上限（字符）。 */
export const ARGS_CAP = 8 * 1024;
/** 结果文本落库上限（字符）。超出截断并带标记。 */
export const RESULT_CAP = 32 * 1024;
/** 出局分类：ok 正常 / blocked 被拦（WAF/403/429/限速/验证码/拒绝）/ error 工具报错。 */
export const OUTCOMES = ["ok", "blocked", "error"];

const BLOCKED_RE = /\b(403|forbidden|waf|blocked|rate.?limit|429|too many requests|captcha|denied)\b/i;

/** 出局分类（纯函数）：工具报错优先；文本命中拦截特征归 blocked（blocked 之于
 *  规划者是「换路径/降速」信号，不是死路）；其余 ok。isError 未知时按文本判定。 */
export function classifyOutcome(isError, text) {
	if (isError === true) return "error";
	return BLOCKED_RE.test(String(text ?? "")) ? "blocked" : "ok";
}

/** 从 tool/result 的 message.content 块提取文本并截断。真实管线为嵌套结构
 *  （[{type:"tool-result", content:[{type:"text",...}], isError}]），合成/回放事件
 *  可能为平铺 text 块——两种形态都取。 */
export function resultTextOf(content, cap = RESULT_CAP) {
	const texts = [];
	const walk = (blocks) => {
		if (typeof blocks === "string") { texts.push(blocks); return; }
		if (!Array.isArray(blocks)) return;
		for (const b of blocks) {
			if (!b || typeof b !== "object") continue;
			if (b.type === "text" && typeof b.text === "string") texts.push(b.text);
			else if (Array.isArray(b.content) || typeof b.content === "string") walk(b.content); // tool-result 嵌套
		}
	};
	walk(content);
	return capText(texts.join("\n"), cap);
}

/** 调用参数归一：JSON 字符串美化后截断；非 JSON 原样截断。 */
export function argsTextOf(raw, cap = ARGS_CAP) {
	const s = String(raw ?? "");
	let pretty = s;
	try {
		const parsed = JSON.parse(s);
		if (parsed && typeof parsed === "object") pretty = JSON.stringify(parsed, null, 1);
	} catch { /* 非 JSON 原样 */ }
	return capText(pretty, cap);
}

function capText(s, cap) {
	const text = String(s ?? "");
	if (text.length <= cap) return text;
	return `${text.slice(0, cap)}\n…[trace-vault 截断：原 ${text.length} 字符，仅存前 ${cap}]`;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS traces (
	id         TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	mode       TEXT NOT NULL,
	tool       TEXT NOT NULL,
	args       TEXT NOT NULL DEFAULT '',
	result     TEXT NOT NULL DEFAULT '',
	is_error   INTEGER NOT NULL DEFAULT 0,
	outcome    TEXT NOT NULL DEFAULT 'ok',
	dur_ms     INTEGER,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS traces_session ON traces(session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS traces_tool ON traces(tool);
CREATE INDEX IF NOT EXISTS traces_created ON traces(created_at DESC);
`;

function now() {
	return new Date().toISOString().replace("T", " ").slice(0, 19);
}

export function openStore(dbPath, { retentionDays = 14, maxRows = 50000 } = {}) {
	if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true });
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL");
	db.exec("PRAGMA busy_timeout = 5000"); // 多进程（两个 dsh 实例）并发写不直接抛 SQLITE_BUSY
	db.exec(SCHEMA);
	const st = { db, retentionDays, maxRows, insertCount: 0, close() { db.close(); } };
	purgeOld(st);
	capRows(st);
	return st;
}

/** 落一条完整调用（callId 已配对）。id 冲突时覆盖（同 callId 重放以最新为准）。 */
export function insertTrace(st, { id, sessionId, mode, tool, args = "", result = "", isError = false, outcome, durMs }) {
	const cls = outcome ?? classifyOutcome(isError, result);
	st.db
		.prepare(
			`INSERT OR REPLACE INTO traces (id, session_id, mode, tool, args, result, is_error, outcome, dur_ms, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		)
		.run(String(id), String(sessionId ?? ""), String(mode ?? ""), String(tool ?? ""), String(args ?? ""), String(result ?? ""), isError ? 1 : 0, cls, Number.isFinite(durMs) ? Math.max(0, Math.round(durMs)) : null, now());
	st.insertCount += 1;
	if (st.insertCount % 200 === 0) { purgeOld(st); capRows(st); }
	return { id: String(id), outcome: cls };
}

/** LIKE 转义：q 中的 % _ \ 按字面匹配。 */
export function escapeLike(q) {
	return String(q ?? "").replace(/[\\%_]/g, (c) => `\\${c}`);
}

/** 关键词检索（子串命中 args/result），新行在前。返回轻量行（不含全文）。 */
export function searchTraces(st, { q = "", tool = "", sessionId = "", mode = "", limit = 10, offset = 0 } = {}) {
	const lim = Math.min(Math.max(Number(limit) || 10, 1), 50);
	const off = Math.max(Number(offset) || 0, 0);
	const where = [];
	const params = [];
	if (q) { where.push("(args LIKE ? ESCAPE '\\' OR result LIKE ? ESCAPE '\\')"); const p = `%${escapeLike(q)}%`; params.push(p, p); }
	if (tool) { where.push("tool = ?"); params.push(String(tool)); }
	if (sessionId) { where.push("session_id = ?"); params.push(String(sessionId)); }
	if (mode) { where.push("mode = ?"); params.push(String(mode)); }
	const sql = `SELECT id, session_id, mode, tool, is_error, outcome, dur_ms, created_at, length(args) AS args_len, length(result) AS result_len
		FROM traces ${where.length ? "WHERE " + where.join(" AND ") : ""}
		ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`;
	return st.db.prepare(sql).all(...params, lim, off).map(rowOf);
}

/** 按 id 取完整行（含 args/result 全文——落库上限内）。 */
export function getTrace(st, id) {
	const row = st.db.prepare("SELECT * FROM traces WHERE id = ?").get(String(id ?? ""));
	return row ? rowOf(row) : undefined;
}

/** 最近调用（新行在前），可按会话/工具过滤。 */
export function listRecent(st, { sessionId = "", tool = "", limit = 20 } = {}) {
	const lim = Math.min(Math.max(Number(limit) || 20, 1), 100);
	const where = [];
	const params = [];
	if (sessionId) { where.push("session_id = ?"); params.push(String(sessionId)); }
	if (tool) { where.push("tool = ?"); params.push(String(tool)); }
	const sql = `SELECT id, session_id, mode, tool, is_error, outcome, dur_ms, created_at, length(args) AS args_len, length(result) AS result_len
		FROM traces ${where.length ? "WHERE " + where.join(" AND ") : ""}
		ORDER BY created_at DESC, id DESC LIMIT ?`;
	return st.db.prepare(sql).all(...params, lim).map(rowOf);
}

/** 出局统计（失败归因的聚合面：blocked 计数是「换路径」信号）。since 传 ISO 时刻
 *  （如 30 分钟前）只统计其后；省略=全部。 */
export function statsTraces(st, { sessionId = "", since = "" } = {}) {
	const where = [];
	const params = [];
	if (sessionId) { where.push("session_id = ?"); params.push(String(sessionId)); }
	if (since) { where.push("created_at >= ?"); params.push(String(since)); }
	const cond = where.length ? "WHERE " + where.join(" AND ") : "";
	const rows = st.db.prepare(`SELECT outcome, COUNT(*) AS n FROM traces ${cond} GROUP BY outcome`).all(...params);
	const out = { total: 0, ok: 0, blocked: 0, error: 0 };
	for (const r of rows) { out.total += r.n; if (OUTCOMES.includes(r.outcome)) out[r.outcome] = r.n; }
	return out;
}

/** 会话画像（评估指标最小集）：调用成败分布/成功率/自救信号/人工介入数。
 *  自救信号（SRR 雏形）= 出现过 blocked 之后再出现 ok（时间序按 created_at+rowid）；
 *  人工介入 = tool='(intervention)' 行（真人用户消息，插件注入已排除）。 */
export function sessionStats(st, { sessionId = "" } = {}) {
	const rows = sessionId
		? st.db.prepare("SELECT tool, outcome FROM traces WHERE session_id = ? ORDER BY created_at, rowid").all(String(sessionId))
		: st.db.prepare("SELECT tool, outcome FROM traces ORDER BY created_at, rowid").all();
	let ok = 0, blocked = 0, error = 0, interventions = 0, sawBlocked = false, selfRecovered = false;
	const blockedTools = new Map();
	for (const r of rows) {
		if (r.tool === "(intervention)") { interventions++; continue; }
		if (r.outcome === "ok") { ok++; if (sawBlocked) selfRecovered = true; }
		else if (r.outcome === "blocked") { blocked++; sawBlocked = true; blockedTools.set(r.tool, (blockedTools.get(r.tool) ?? 0) + 1); }
		else if (r.outcome === "error") { error++; }
	}
	const calls = ok + blocked + error;
	return {
		sessionId: String(sessionId || ""),
		calls, ok, blocked, error, interventions,
		successRate: calls > 0 ? Math.round((ok / calls) * 1000) / 10 : null,
		selfRecovered,
		blockedTools: [...blockedTools.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([t, n]) => `${t}×${n}`)
	};
}

/** 按保留天数清理（开库与每 200 次写入触发）。返回删除行数。 */
export function purgeOld(st) {
	const days = Number(st.retentionDays);
	if (!Number.isFinite(days) || days <= 0) return 0;
	const info = st.db.prepare("DELETE FROM traces WHERE created_at < datetime('now', ?)").run(`-${Math.round(days)} days`);
	return Number(info.changes) || 0;
}

/** 总量上限：超限按 created_at 最旧淘汰。返回删除行数。 */
export function capRows(st) {
	const max = Number(st.maxRows);
	if (!Number.isFinite(max) || max <= 0) return 0;
	const n = st.db.prepare("SELECT COUNT(*) AS n FROM traces").get().n;
	if (n <= max) return 0;
	const info = st.db.prepare(
		`DELETE FROM traces WHERE id IN (SELECT id FROM traces ORDER BY created_at ASC, id ASC LIMIT ?)`
	).run(n - max);
	return Number(info.changes) || 0;
}

function rowOf(row) {
	return {
		id: row.id,
		sessionId: row.session_id,
		mode: row.mode,
		tool: row.tool,
		args: row.args ?? "",
		result: row.result ?? "",
		isError: row.is_error === 1,
		outcome: row.outcome,
		durMs: row.dur_ms,
		createdAt: row.created_at,
		argsLen: row.args_len ?? undefined,
		resultLen: row.result_len ?? undefined
	};
}
