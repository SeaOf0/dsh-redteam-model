// dsh-campaign-memory store — 战役记忆 SQLite 数据层（node:sqlite DatabaseSync）。
//
// 单库 ~/.dsh/campaign-memory/memory.db：memories 表按模式作用域（跨会话长期资产）。
// 存原文不脱敏：内网地址/指纹细节是打法价值所在；凭据不入记忆是纪律而非转换——
// 凭据类单独存本地凭据库（hunter key 库 / webshell 连接库等），记忆只写指位，需要时从库读。
// 检索即记账：usage_count / last_used_at 随检索自增，驱动「按使用频次+新近度」的召回排序与淘汰。
// detect（检测指纹）类默认 30 天过期——免杀情报有半衰期；其余类别默认永久。

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

export const MEMORY_KINDS = ["tactic", "fingerprint", "tooling", "lesson", "detect"];
const KIND_LABELS = { tactic: "战术打法", fingerprint: "目标指纹", tooling: "工具可用性", lesson: "教训", detect: "检测指纹" };
export function kindLabel(kind) { return KIND_LABELS[kind] || "战术打法"; }

const DETECT_DEFAULT_DAYS = 30;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS memories (
	id           TEXT PRIMARY KEY,
	mode         TEXT NOT NULL,
	kind         TEXT NOT NULL,
	title        TEXT NOT NULL,
	content      TEXT NOT NULL,
	tags         TEXT NOT NULL DEFAULT '',
	target_kind  TEXT NOT NULL DEFAULT '',
	workspace    TEXT NOT NULL DEFAULT '',
	usage_count  INTEGER NOT NULL DEFAULT 0,
	last_used_at TEXT DEFAULT '',
	source_session TEXT NOT NULL DEFAULT '',
	expires_at   TEXT,
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS memories_mode ON memories(mode);
`;

function now() {
	return new Date().toISOString().replace("T", " ").slice(0, 19);
}
function clean(s, max) {
	return String(s ?? "").trim().slice(0, max);
}

export function openStore(dbPath) {
	if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true });
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL");
	db.exec(SCHEMA);
	try { db.exec("ALTER TABLE memories ADD COLUMN workspace TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移 */ }
	purgeExpired({ db }); // 开库即清过期：免杀指纹等时效记忆不滞留
	return { db, close() { db.close(); } };
}

function expiry(kind, days) {
	const d = Number(days);
	if (Number.isFinite(d) && d > 0) {
		const t = new Date(Date.now() + d * 86400_000);
		return t.toISOString().replace("T", " ").slice(0, 19);
	}
	if (kind === "detect") return expiry(null, DETECT_DEFAULT_DAYS);
	return null;
}

/** 写入一条战役记忆（自动脱敏；id 服务端生成）。 */
export function writeMemory(st, { mode, kind, title, content, tags = "", target_kind = "", expires_days, source_session = "", workspace = "" }) {
	const m = clean(mode, 40), k = MEMORY_KINDS.includes(kind) ? kind : "tactic";
	const t = clean(title, 80);
	if (!m || !t) throw new Error("mode/title 必填");
	const c = clean(content, 4000);
	if (!c) throw new Error("content 必填");
	const id = "cm-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
	const exp = expiry(k, expires_days);
	st.db.prepare("INSERT INTO memories (id, mode, kind, title, content, tags, target_kind, workspace, usage_count, last_used_at, source_session, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?)")
		.run(id, m, k, t, c, clean(tags, 200), clean(target_kind, 40), clean(workspace, 60), clean(source_session, 80), exp, now(), now());
	return { id, mode: m, kind: k, workspace: clean(workspace, 60), expires_at: exp };
}

function rowOut(r) {
	return { ...r, usageCount: r.usage_count, lastUsedAt: r.last_used_at, sourceSession: r.source_session, targetKind: r.target_kind };
}

const SELECT = "SELECT id, mode, kind, title, content, tags, target_kind, workspace, usage_count, last_used_at, source_session, expires_at, created_at, updated_at FROM memories";

function notExpired(expr = "") {
	return ` expires_at IS NULL OR expires_at > datetime('now') ${expr ? "AND " + expr : ""}`;
}

/** 检索（LIKE 关键词 × 类别/目标形态过滤），按 usage→last_used→新近排序；命中即记账。 */
export function searchMemories(st, { mode, query = "", kind = "", target_kind = "", limit = 8 }) {
	const m = clean(mode, 40);
	if (!m) throw new Error("mode required");
	const q = clean(query, 120);
	const conds = ["mode = ?", "(" + notExpired() + ")"];
	const args = [m];
	if (q) { conds.push("(title LIKE ? OR content LIKE ? OR tags LIKE ?)"); args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
	if (kind && MEMORY_KINDS.includes(kind)) { conds.push("kind = ?"); args.push(kind); }
	if (target_kind) { conds.push("target_kind = ?"); args.push(clean(target_kind, 40)); }
	const rows = st.db.prepare(`${SELECT} WHERE ${conds.join(" AND ")} ORDER BY usage_count DESC, last_used_at DESC, created_at DESC LIMIT ?`).all(...args, Math.min(Math.max(Number(limit) || 8, 1), 20));
	const ts = now();
	if (rows.length) {
		const ids = rows.map((r) => r.id);
		st.db.prepare(`UPDATE memories SET usage_count = usage_count + 1, last_used_at = ? WHERE id IN (${ids.map(() => "?").join(",")})`).run(ts, ...ids);
	}
	return rows.map((r) => rowOut({ ...r, content: preview(r.content, 600), usage_count: r.usage_count + 1, last_used_at: ts }));
}

/** 正文预览：超上限截断加省略号（检索/list 行级 token 收敛；全文走 getMemory 按需取）。 */
function preview(text, max) {
	const t = String(text ?? "");
	return t.length > max ? t.slice(0, max) + "…（全文经 campaign_memory_get 按需读取）" : t;
}

/** 召回注入候选（纯读、不记账——保证装配渲染确定性）：仅本工作区（新工作区=干净开局，
 *  不跨客户/项目串场）；usage→last_used→新近排序，取前 N 条。 */
export function topForInjection(st, mode, workspace, n = 3) {
	const rows = st.db.prepare(`${SELECT} WHERE mode = ? AND workspace = ? AND (${notExpired()}) ORDER BY usage_count DESC, last_used_at DESC, created_at DESC LIMIT ?`).all(clean(mode, 40), clean(workspace, 60), n);
	return rows.map(rowOut);
}

export function listMemories(st, { mode, kind = "", includeExpired = false }) {
	const m = clean(mode, 40);
	if (!m) throw new Error("mode required");
	const conds = ["mode = ?"];
	const args = [m];
	if (!includeExpired) conds.push("(" + notExpired() + ")");
	if (kind && MEMORY_KINDS.includes(kind)) { conds.push("kind = ?"); args.push(kind); }
	return st.db.prepare(`${SELECT} WHERE ${conds.join(" AND ")} ORDER BY usage_count DESC, last_used_at DESC, created_at DESC`).all(...args).map((r) => rowOut({ ...r, content: preview(r.content, 200) }));
}

export function getMemory(st, id) {
	const r = st.db.prepare(`${SELECT} WHERE id = ?`).get(String(id ?? ""));
	return r ? rowOut(r) : undefined;
}

export function removeMemory(st, id) {
	const r = st.db.prepare("DELETE FROM memories WHERE id = ?").run(String(id ?? ""));
	if (r.changes === 0) throw new Error(`记忆不存在：${id}`);
	return { removed: String(id) };
}

export function statsMemories(st, mode) {
	const m = clean(mode, 40);
	if (!m) throw new Error("mode required");
	const rows = st.db.prepare("SELECT kind, expires_at FROM memories WHERE mode = ?").all(m);
	const byKind = {};
	for (const k of MEMORY_KINDS) byKind[k] = 0;
	let expired = 0;
	for (const r of rows) {
		byKind[r.kind] = (byKind[r.kind] ?? 0) + 1;
		if (r.expires_at && r.expires_at <= now()) expired += 1;
	}
	return { total: rows.length, byKind, expired };
}

export function purgeExpired(st) {
	const r = st.db.prepare("DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')").run();
	return { purged: r.changes };
}
