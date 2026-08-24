// dsh-campaign-memory store — 战役记忆 SQLite 数据层（node:sqlite DatabaseSync）。
//
// 单库 ~/.dsh/campaign-memory/memory.db：memories 表按模式作用域（跨会话长期资产）。
// 存原文不脱敏：内网地址/指纹细节是打法价值所在，凭据同样原样入库（记忆库是本地库）；
// 已有独立凭据库（hunter key 库 / webshell 连接库等）时也可只写指位，需要时从库读。
// 检索即记账已改为读全文记账：usage_count / last_used_at 只在 getMemory 时自增——
// 预览命中不算真实使用，避免无关 LIKE 命中污染热度。排序=热度×时间半衰（30 天），
// 久未读取的记忆自然让位、读取即复活——早期记忆不再永久霸占召回位。
// detect（检测指纹）默认 30 天过期并自动清理——免杀情报有半衰期；fingerprint（目标指纹）
// 默认 180 天——到期退出自动召回但保留资产（检索仍可命中带过期标记，同题重写即刷新时效）；
// 其余类别默认永久。同模式同工作区同题同目标形态（target_kind）写入=刷新既有记忆而非新增重复
// ——CTF 同名题（signin/pwn1 等）跨平台/赛事以 target_kind=平台名区分，不静默互覆。

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

export const MEMORY_KINDS = ["tactic", "fingerprint", "tooling", "lesson", "detect"];
const KIND_LABELS = { tactic: "战术打法", fingerprint: "目标指纹", tooling: "工具可用性", lesson: "教训", detect: "检测指纹" };
export function kindLabel(kind) { return KIND_LABELS[kind] || "战术打法"; }

const DETECT_DEFAULT_DAYS = 30;
const FINGERPRINT_DEFAULT_DAYS = 180;
const HALF_LIFE_DAYS = 30;
/** 单工作区（mode × workspace 名）记忆总量上限：写入查重的全表扫描因此有界；超限按热度×半衰最冷淘汰。 */
export const MAX_ROWS_PER_WORKSPACE = 400;
const COLD_ORDER = `ORDER BY (usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(last_used_at, ''), created_at))) / ${HALF_LIFE_DAYS}.0) ASC, updated_at ASC, created_at ASC`;

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
	workspace_key TEXT NOT NULL DEFAULT '',
	usage_count  INTEGER NOT NULL DEFAULT 0,
	last_used_at TEXT DEFAULT '',
	source_session TEXT NOT NULL DEFAULT '',
	expires_at   TEXT,
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS memories_mode ON memories(mode);
CREATE INDEX IF NOT EXISTS memories_ws ON memories(mode, workspace_key);
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
	db.exec("PRAGMA busy_timeout = 5000"); // 多进程（两个 dsh 实例）并发写不直接抛 SQLITE_BUSY
	db.exec(SCHEMA);
	try { db.exec("ALTER TABLE memories ADD COLUMN workspace TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移 */ }
	try { db.exec("ALTER TABLE memories ADD COLUMN workspace_key TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移 */ }
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
	if (kind === "fingerprint") return expiry(null, FINGERPRINT_DEFAULT_DAYS);
	return null;
}

/** 标题归一（去空白+小写）：同题判定的比较基准。 */
function normTitle(t) {
	return String(t ?? "").trim().toLowerCase().replace(/\s+/g, "");
}

/** 写入一条战役记忆（存储原文不脱敏；id 服务端生成）。同模式同工作区同题=刷新既有行
 *  （正文/类别/时效更新、热度保留、created_at 保留），跨工作区同题各自独立。
 *  隔离键 workspace_key=basename@路径哈希：同名目录不串场、移动目录=新 key；缺省 "" 走旧 basename 语义。 */
export function writeMemory(st, { mode, kind, title, content, tags = "", target_kind = "", expires_days, source_session = "", workspace = "", workspace_key = "" }) {
	const m = clean(mode, 40), k = MEMORY_KINDS.includes(kind) ? kind : "tactic";
	const t = clean(title, 80);
	if (!m || !t) throw new Error("mode/title 必填");
	const c = clean(content, 4000);
	if (!c) throw new Error("content 必填");
	const ws = clean(workspace, 60);
	const wk = clean(workspace_key, 80);
	const exp = expiry(k, expires_days);
	const nt = normTitle(t);
	const tk = clean(target_kind, 40);
	// 同题判定带 target_kind 维度：同题同目标形态才刷新——跨平台同名题不互覆
	const rows = st.db.prepare("SELECT id, title, workspace_key, target_kind FROM memories WHERE mode = ? AND workspace = ?").all(m, ws);
	const prev = rows.find((r) => normTitle(r.title) === nt && (r.target_kind || "") === tk && (wk ? r.workspace_key === wk : r.workspace_key === ""));
	if (prev) {
		st.db.prepare("UPDATE memories SET kind = ?, title = ?, content = ?, tags = ?, target_kind = ?, expires_at = ?, source_session = ?, workspace_key = ?, updated_at = ? WHERE id = ?")
			.run(k, t, c, clean(tags, 200), clean(target_kind, 40), exp, clean(source_session, 80), wk, now(), prev.id);
		return { id: prev.id, mode: m, kind: k, workspace: ws, expires_at: exp, refreshed: true, evicted: 0 };
	}
	const id = "cm-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
	st.db.prepare("INSERT INTO memories (id, mode, kind, title, content, tags, target_kind, workspace, workspace_key, usage_count, last_used_at, source_session, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?)")
		.run(id, m, k, t, c, clean(tags, 200), clean(target_kind, 40), ws, wk, clean(source_session, 80), exp, now(), now());
	// 总量上限：同模式同工作区（含新旧键位行）超限冷淘汰——只淘汰本键位行，新写行永不让位。
	let evicted = 0;
	const total = st.db.prepare("SELECT COUNT(*) AS n FROM memories WHERE mode = ? AND workspace = ?").get(m, ws).n;
	if (total > MAX_ROWS_PER_WORKSPACE) {
		const keyCond = wk ? "workspace_key = ?" : "workspace_key = ''";
		const coldArgs = wk ? [m, ws, wk, id, total - MAX_ROWS_PER_WORKSPACE] : [m, ws, id, total - MAX_ROWS_PER_WORKSPACE];
		const cold = st.db.prepare(`SELECT id FROM memories WHERE mode = ? AND workspace = ? AND ${keyCond} AND id != ? ${COLD_ORDER} LIMIT ?`).all(...coldArgs);
		for (const row of cold) { st.db.prepare("DELETE FROM memories WHERE id = ?").run(row.id); evicted += 1; }
	}
	return { id, mode: m, kind: k, workspace: ws, expires_at: exp, refreshed: false, evicted };
}

function rowOut(r) {
	const expired = !!(r.expires_at && r.expires_at <= now());
	return { ...r, usageCount: r.usage_count, lastUsedAt: r.last_used_at, sourceSession: r.source_session, targetKind: r.target_kind, expired };
}

const SELECT = "SELECT id, mode, kind, title, content, tags, target_kind, workspace, usage_count, last_used_at, source_session, expires_at, created_at, updated_at FROM memories";

function notExpired(expr = "") {
	return ` expires_at IS NULL OR expires_at > datetime('now') ${expr ? "AND " + expr : ""}`;
}

/** 热度评分（排序用）：usage+1 为基数，按最后使用距今 ${HALF_LIFE_DAYS} 天半衰——
 *  早期高频记忆久未读取自然让位，新鲜记忆可入召回位；读取（get）刷新 last_used 即复活。 */
const HOTNESS_ORDER = `ORDER BY (usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(last_used_at, ''), created_at))) / ${HALF_LIFE_DAYS}.0) DESC, last_used_at DESC, created_at DESC`;

/** 检索（LIKE 关键词 × 类别/目标形态过滤），按热度×半衰排序；不记账——读全文（getMemory）才计。
 *  过期记忆不召回，唯一例外 fingerprint：目标指纹到期只是变陈旧不是失效，仍可命中（带 expired 标记）。 */
export function searchMemories(st, { mode, query = "", kind = "", target_kind = "", limit = 8 }) {
	const m = clean(mode, 40);
	if (!m) throw new Error("mode required");
	const q = clean(query, 120);
	const conds = ["mode = ?", "(expires_at IS NULL OR expires_at > datetime('now') OR kind = 'fingerprint')"];
	const args = [m];
	if (q) { conds.push("(title LIKE ? OR content LIKE ? OR tags LIKE ?)"); args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
	if (kind && MEMORY_KINDS.includes(kind)) { conds.push("kind = ?"); args.push(kind); }
	if (target_kind) { conds.push("target_kind = ?"); args.push(clean(target_kind, 40)); }
	const rows = st.db.prepare(`${SELECT} WHERE ${conds.join(" AND ")} ${HOTNESS_ORDER} LIMIT ?`).all(...args, Math.min(Math.max(Number(limit) || 8, 1), 20));
	return rows.map((r) => {
		const out = rowOut({ ...r, content: preview(r.content, 600) });
		if (out.expired) out.content = "[已过期——适用性自判；重新验证后同题 campaign_memory_write 刷新] " + out.content;
		return out;
	});
}

/** 正文预览：超上限截断加省略号（检索/list 行级 token 收敛；全文走 getMemory 按需取）。
 *  截点不劈代理对（emoji 等 4 字节字符）。 */
function preview(text, max) {
	const t = String(text ?? "");
	if (t.length <= max) return t;
	let cut = t.slice(0, max);
	if (/[\uD800-\uDBFF]$/.test(cut)) cut = cut.slice(0, -1);
	return cut + "…（全文经 campaign_memory_get 按需读取）";
}

/** 召回注入候选（纯读、不记账——保证装配渲染确定性）：仅本工作区（新工作区=干净开局，
 *  不跨客户/项目串场）、未过期，按热度×半衰排序取前 N 条。
 *  wk=隔离键（basename@路径哈希）：按键精确隔离；缺省走旧 basename 语义（仅匹配无键行）。 */
export function topForInjection(st, mode, workspace, n = 3, wk = "") {
	const rows = wk
		? st.db.prepare(`${SELECT} WHERE mode = ? AND workspace_key = ? AND (${notExpired()}) ${HOTNESS_ORDER} LIMIT ?`).all(clean(mode, 40), clean(wk, 80), n)
		: st.db.prepare(`${SELECT} WHERE mode = ? AND workspace = ? AND workspace_key = '' AND (${notExpired()}) ${HOTNESS_ORDER} LIMIT ?`).all(clean(mode, 40), clean(workspace, 60), n);
	return rows.map(rowOut);
}

/** 清单（收口复盘/治理用）：与 search 同受行数钳制（token 收敛——list 不做全量倾倒），默认 50、上限 200。 */
export function listMemories(st, { mode, kind = "", includeExpired = false, limit = 50 }) {
	const m = clean(mode, 40);
	if (!m) throw new Error("mode required");
	const conds = ["mode = ?"];
	const args = [m];
	if (!includeExpired) conds.push("(" + notExpired() + ")");
	if (kind && MEMORY_KINDS.includes(kind)) { conds.push("kind = ?"); args.push(kind); }
	return st.db.prepare(`${SELECT} WHERE ${conds.join(" AND ")} ${HOTNESS_ORDER} LIMIT ?`).all(...args, Math.min(Math.max(Number(limit) || 50, 1), 200)).map((r) => rowOut({ ...r, content: preview(r.content, 200) }));
}

/** 读取全文=真实使用：记账（usage+1 / last_used 刷新）——热度与半衰排序的唯一驱动。
 *  account:false 供纯浏览（Web 标签页展开全文）——查看不是采用，不推高召回排名。 */
export function getMemory(st, id, { account = true } = {}) {
	const i = String(id ?? "");
	if (account) st.db.prepare("UPDATE memories SET usage_count = usage_count + 1, last_used_at = ? WHERE id = ?").run(now(), i);
	const r = st.db.prepare(`${SELECT} WHERE id = ?`).get(i);
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

/** 清理只删过期的检测指纹（情报半衰期已过即无保留价值）；fingerprint 等其余到期行
 *  退出召回但保留资产——经 includeExpired 可查、可同题重写复活、可手动删除。 */
export function purgeExpired(st) {
	const r = st.db.prepare("DELETE FROM memories WHERE kind = 'detect' AND expires_at IS NOT NULL AND expires_at <= datetime('now')").run();
	return { purged: r.changes };
}
