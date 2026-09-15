// dsh-campaign-memory store — 战役记忆 SQLite 数据层（node:sqlite DatabaseSync）。
//
// 单库 ~/.dsh/campaign-memory/memory.db：memories 表按模式作用域（跨会话长期资产）。
// 存原文不脱敏：内网地址/指纹细节是打法价值所在，凭据同样原样入库（记忆库是本地库）；
// 已有独立凭据库（hunter key 库 / webshell 连接库等）时也可只写指位，需要时从库读。
// 检索即记账已改为读全文记账：usage_count / last_used_at 只在 getMemory 时自增——
// 预览命中不算真实使用，避免无关命中污染热度。排序=热度×时间半衰（30 天），
// 久未读取的记忆自然让位、读取即复活——早期记忆不再永久霸占召回位。
// 检索走 FTS5 trigram（分词 OR 召回——多词分离可命中，CJK 三字及以上子串可查；
// bm25×热度混排、命中窗摘录）；FTS 不可用或全短词时回落整串 LIKE。
// 正文超 4000 字符显式截断（返回 truncated 提示，不静默腰斩）；同题刷新带回执
// （原正文字数+预览，误合并可察觉）；工作区超限冷淘汰先归档 memories_archive 再删（可恢复）。
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
CREATE TABLE IF NOT EXISTS memories_archive (
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
	updated_at   TEXT NOT NULL,
	archived_at  TEXT NOT NULL
);
`;

/** FTS5 trigram 外容表 + 触发器同步；PRAGMA user_version 标记索引代际——旧库（无标记）开库
 *  全量重建一次并置标记（外容表的 COUNT(*)/integrity-check 都探不出「内容有行、索引为空」，
 *  只能版本标记）。trigram 对 CJK 友好：三字及以上子串可查（默认 unicode61 分词器会把连续
 *  汉字串成一个 token，子串召回全靠运气）；不可用（构建缺 FTS5）返回 false，检索回落整串 LIKE。 */
const FTS_GENERATION = 1;
function setupFts(db) {
	db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
	title, content, tags, content='memories', content_rowid='rowid', tokenize='trigram')`);
	db.exec(`CREATE TRIGGER IF NOT EXISTS memories_fts_ai AFTER INSERT ON memories BEGIN
	INSERT INTO memories_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags); END`);
	db.exec(`CREATE TRIGGER IF NOT EXISTS memories_fts_ad AFTER DELETE ON memories BEGIN
	INSERT INTO memories_fts(memories_fts, rowid, title, content, tags) VALUES ('delete', old.rowid, old.title, old.content, old.tags); END`);
	db.exec(`CREATE TRIGGER IF NOT EXISTS memories_fts_au AFTER UPDATE ON memories BEGIN
	INSERT INTO memories_fts(memories_fts, rowid, title, content, tags) VALUES ('delete', old.rowid, old.title, old.content, old.tags);
	INSERT INTO memories_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags); END`);
	const v = db.prepare("PRAGMA user_version").get();
	if (v?.user_version !== FTS_GENERATION) {
		db.exec("INSERT INTO memories_fts(memories_fts) VALUES ('rebuild')");
		db.exec(`PRAGMA user_version = ${FTS_GENERATION}`);
	}
	return true;
}

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
	let fts = false;
	try { fts = setupFts(db); } catch { /* 构建缺 FTS5：检索回落 LIKE */ }
	purgeExpired({ db }); // 开库即清过期：免杀指纹等时效记忆不滞留
	return { db, fts, close() { db.close(); } };
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
 *  （正文/类别/时效更新、热度保留、created_at 保留），跨工作区同题各自独立；刷新带回执
 *  （原正文字数+预览——误合并可察觉）。正文超上限显式截断（返回 truncated=true，不静默腰斩）。
 *  隔离键 workspace_key=basename@路径哈希：同名目录不串场、移动目录=新 key；缺省 "" 走旧 basename 语义。 */
export function writeMemory(st, { mode, kind, title, content, tags = "", target_kind = "", expires_days, source_session = "", workspace = "", workspace_key = "" }) {
	const m = clean(mode, 40), k = MEMORY_KINDS.includes(kind) ? kind : "tactic";
	const t = clean(title, 80);
	if (!m || !t) throw new Error("mode/title 必填");
	const raw = String(content ?? "").trim();
	const c = raw.slice(0, 4000);
	if (!c) throw new Error("content 必填");
	const truncated = raw.length > 4000;
	const ws = clean(workspace, 60);
	const wk = clean(workspace_key, 80);
	const exp = expiry(k, expires_days);
	const nt = normTitle(t);
	const tk = clean(target_kind, 40);
	// 同题判定带 target_kind 维度：同题同目标形态才刷新——跨平台同名题不互覆
	const rows = st.db.prepare("SELECT id, title, content, workspace_key, target_kind FROM memories WHERE mode = ? AND workspace = ?").all(m, ws);
	const prev = rows.find((r) => normTitle(r.title) === nt && (r.target_kind || "") === tk && (wk ? r.workspace_key === wk : r.workspace_key === ""));
	if (prev) {
		st.db.prepare("UPDATE memories SET kind = ?, title = ?, content = ?, tags = ?, target_kind = ?, expires_at = ?, source_session = ?, workspace_key = ?, updated_at = ? WHERE id = ?")
			.run(k, t, c, clean(tags, 200), clean(target_kind, 40), exp, clean(source_session, 80), wk, now(), prev.id);
		return { id: prev.id, mode: m, kind: k, workspace: ws, expires_at: exp, refreshed: true, evicted: 0, truncated, chars: c.length, prev: { chars: String(prev.content ?? "").length, preview: String(prev.content ?? "").slice(0, 60) } };
	}
	const id = "cm-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
	st.db.prepare("INSERT INTO memories (id, mode, kind, title, content, tags, target_kind, workspace, workspace_key, usage_count, last_used_at, source_session, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?)")
		.run(id, m, k, t, c, clean(tags, 200), clean(target_kind, 40), ws, wk, clean(source_session, 80), exp, now(), now());
	// 总量上限：同模式同工作区（含新旧键位行）超限冷淘汰——只淘汰本键位行，新写行永不让位；
	// 淘汰先归档 memories_archive（可恢复）再删。
	let evicted = 0;
	const total = st.db.prepare("SELECT COUNT(*) AS n FROM memories WHERE mode = ? AND workspace = ?").get(m, ws).n;
	if (total > MAX_ROWS_PER_WORKSPACE) {
		const keyCond = wk ? "workspace_key = ?" : "workspace_key = ''";
		const coldArgs = wk ? [m, ws, wk, id, total - MAX_ROWS_PER_WORKSPACE] : [m, ws, id, total - MAX_ROWS_PER_WORKSPACE];
		const cold = st.db.prepare(`SELECT id FROM memories WHERE mode = ? AND workspace = ? AND ${keyCond} AND id != ? ${COLD_ORDER} LIMIT ?`).all(...coldArgs);
		for (const row of cold) {
			st.db.prepare(`INSERT OR REPLACE INTO memories_archive (id, mode, kind, title, content, tags, target_kind, workspace, workspace_key, usage_count, last_used_at, source_session, expires_at, created_at, updated_at, archived_at)
				SELECT id, mode, kind, title, content, tags, target_kind, workspace, workspace_key, usage_count, last_used_at, source_session, expires_at, created_at, updated_at, ? FROM memories WHERE id = ?`).run(now(), row.id);
			st.db.prepare("DELETE FROM memories WHERE id = ?").run(row.id);
			evicted += 1;
		}
	}
	return { id, mode: m, kind: k, workspace: ws, expires_at: exp, refreshed: false, evicted, truncated, chars: c.length };
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

/** 检索（FTS5 trigram 主路 + LIKE 回落），不记账——读全文（getMemory）才计。
 *  FTS 路：≥3 字符词走 MATCH（多词分离可命中，OR 召回）；<3 字符词另跑 LIKE 补位合并
 *  （MATCH 不能出现在 OR 表达式里——SQLite 限制，故两段查询在 JS 归并去重，FTS 命中排前）。
 *  bm25×热度混排（词法更贴者排前），命中窗摘录（snippet 环绕最佳命中，token 收敛）。
 *  过期记忆不召回，唯一例外 fingerprint：目标指纹到期只是变旧不是失效，仍可命中（带 expired 标记）。
 *  FTS 不可用或全短词时回落整串 LIKE（与历史行为一致）。 */
export function searchMemories(st, { mode, query = "", kind = "", target_kind = "", limit = 8 }) {
	const m = clean(mode, 40);
	if (!m) throw new Error("mode required");
	const q = clean(query, 120);
	const lim = Math.min(Math.max(Number(limit) || 8, 1), 20);
	const toks = q ? q.split(/\s+/).map((t) => t.replace(/"/g, "").trim()).filter(Boolean) : [];
	const ftsToks = toks.filter((t) => t.length >= 3);
	const shortToks = toks.filter((t) => t.length < 3);
	const kindCond = kind && MEMORY_KINDS.includes(kind);
	const tk = clean(target_kind, 40);
	let rows;
	if (st.fts && ftsToks.length > 0) {
		const match = ftsToks.map((t) => `"${t}"`).join(" OR ");
		const conds = ["m.mode = ?", "(m.expires_at IS NULL OR m.expires_at > datetime('now') OR m.kind = 'fingerprint')", "memories_fts MATCH ?"];
		const args = [m, match];
		if (kindCond) { conds.push("m.kind = ?"); args.push(kind); }
		if (tk) { conds.push("m.target_kind = ?"); args.push(tk); }
		rows = st.db.prepare(`SELECT m.id, m.mode, m.kind, m.title, m.content, m.tags, m.target_kind, m.workspace, m.usage_count, m.last_used_at, m.source_session, m.expires_at, m.created_at, m.updated_at,
			snippet(memories_fts, 1, '»', '«', '…', 120) AS snip, bm25(memories_fts) AS rel
			FROM memories m JOIN memories_fts ON memories_fts.rowid = m.rowid
			WHERE ${conds.join(" AND ")}
			ORDER BY ((m.usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(m.last_used_at, ''), m.created_at))) / ${HALF_LIFE_DAYS}.0)) / (1.0 + COALESCE(bm25(memories_fts), 12.0)) DESC, m.last_used_at DESC, m.created_at DESC
			LIMIT ?`).all(...args, lim);
		if (shortToks.length) {
			const likeConds = shortToks.map(() => "(title LIKE ? OR content LIKE ? OR tags LIKE ?)").join(" OR ");
			const likeArgs = shortToks.flatMap((t) => [`%${t}%`, `%${t}%`, `%${t}%`]);
			const c2 = ["mode = ?", "(expires_at IS NULL OR expires_at > datetime('now') OR kind = 'fingerprint')", `(${likeConds})`];
			const a2 = [m, ...likeArgs];
			if (kindCond) { c2.push("kind = ?"); a2.push(kind); }
			if (tk) { c2.push("target_kind = ?"); a2.push(tk); }
			const likeRows = st.db.prepare(`${SELECT} WHERE ${c2.join(" AND ")} ${HOTNESS_ORDER} LIMIT ?`).all(...a2, lim);
			const seen = new Set(rows.map((r) => r.id));
			for (const r of likeRows) if (!seen.has(r.id)) rows.push(r);
			rows = rows.slice(0, lim);
		}
	} else {
		const conds = ["mode = ?", "(expires_at IS NULL OR expires_at > datetime('now') OR kind = 'fingerprint')"];
		const args = [m];
		if (q) { conds.push("(title LIKE ? OR content LIKE ? OR tags LIKE ?)"); args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
		if (kindCond) { conds.push("kind = ?"); args.push(kind); }
		if (tk) { conds.push("target_kind = ?"); args.push(tk); }
		rows = st.db.prepare(`${SELECT} WHERE ${conds.join(" AND ")} ${HOTNESS_ORDER} LIMIT ?`).all(...args, lim);
	}
	return rows.map(({ snip: _snip, rel: _rel, ...r }) => {
		const body = (typeof _snip === "string" && _snip !== "") ? _snip : r.content;
		const out = rowOut({ ...r, content: preview(body, 600) });
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
