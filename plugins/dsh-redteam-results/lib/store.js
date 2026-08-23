// dsh-redteam-results store — SQLite 数据层（node:sqlite DatabaseSync，同步 API）。
//
// 单库 ~/.dsh/redteam-results/results.db：
//   findings 表以 (session_id, id) 为主键，所有读写恒带 session_id + mode 双键——
//   模式隔离由存储层强制（渗透成果物理上进不了代审的行，反之亦然）；
//   session_meta 表存会话级任务元数据（审计对象/渗透范围、版本、scope）。
// 测试注入 ":memory:"。

import { DatabaseSync } from "node:sqlite";

const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = ["pending", "code-reviewed", "verified", "false-positive", "fixed"];
/** 分模式状态子集：漏洞生命周期五态=发现型（渗透/代审/攻防/应急/云）；
 *  产物型模式用各自本体词——免杀=在验/过检/被检出、CTF=未解/卡点/已解、二进制=分析中/疑似/已定论。
 *  verified 语义通用（各模式的"验证类终态"），verifiedAt 落库逻辑不变。 */
const MODE_STATUSES = {
	default: STATUSES,
	"av-evasion": ["pending", "verified", "detected"],
	"ctf-solver": ["pending", "stuck", "verified"],
	"binary-analysis": ["pending", "suspect", "verified"]
};
const ALL_STATUSES = Array.from(new Set([].concat(...Object.values(MODE_STATUSES))));
const statusesOf = (mode) => MODE_STATUSES[mode] ?? STATUSES;
const EVIDENCE_LEVELS = ["confirmed", "partial", "unknown"];
const SOURCE_ORIGINS = ["manual", "scan-confirmed", "scan-false-positive"];
const DEFAULT_PAGE_SIZE = 10;
const MODES = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];

const SCHEMA = `
CREATE TABLE IF NOT EXISTS findings (
	session_id TEXT NOT NULL,
	id         TEXT NOT NULL,
	seq        INTEGER NOT NULL,
	mode       TEXT NOT NULL,
	title      TEXT NOT NULL,
	severity   TEXT NOT NULL,
	status     TEXT NOT NULL,
	evidence_level TEXT NOT NULL,
	type       TEXT NOT NULL DEFAULT '',
	target     TEXT NOT NULL DEFAULT '',
	summary    TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	poc        TEXT NOT NULL DEFAULT '',
	chain      TEXT NOT NULL DEFAULT '',
	evidence   TEXT NOT NULL DEFAULT '',
	fix        TEXT NOT NULL DEFAULT '',
	verify_note TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	verified_at TEXT NOT NULL DEFAULT '',
	baseline   TEXT NOT NULL DEFAULT '',
	diff_evidence TEXT NOT NULL DEFAULT '',
	marker_echo TEXT NOT NULL DEFAULT '',
	impact     TEXT NOT NULL DEFAULT '',
	cvss       TEXT NOT NULL DEFAULT '',
	retest_note TEXT NOT NULL DEFAULT '',
	retest_at  TEXT NOT NULL DEFAULT '',
	request_pkt TEXT NOT NULL DEFAULT '',
	response_pkt TEXT NOT NULL DEFAULT '',
	snippet_entry TEXT NOT NULL DEFAULT '',
	snippet_sink TEXT NOT NULL DEFAULT '',
	chain_tracer TEXT NOT NULL DEFAULT '',
	chain_verdict TEXT NOT NULL DEFAULT '',
	cwe        TEXT NOT NULL DEFAULT '',
	patch      TEXT NOT NULL DEFAULT '',
	source_origin TEXT NOT NULL DEFAULT '',
	sample_hash TEXT NOT NULL DEFAULT '',
	family    TEXT NOT NULL DEFAULT '',
	packer    TEXT NOT NULL DEFAULT '',
	iocs      TEXT NOT NULL DEFAULT '',
	detection_rule TEXT NOT NULL DEFAULT '',
	timeline_at  TEXT NOT NULL DEFAULT '',
	entry       TEXT NOT NULL DEFAULT '',
	identity    TEXT NOT NULL DEFAULT '',
	permission  TEXT NOT NULL DEFAULT '',
	resource    TEXT NOT NULL DEFAULT '',
	audit_mode  TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (session_id, id)
);
CREATE INDEX IF NOT EXISTS idx_findings_session_mode ON findings(session_id, mode, seq);
CREATE TABLE IF NOT EXISTS session_meta (
	session_id TEXT NOT NULL PRIMARY KEY,
	target_label TEXT NOT NULL DEFAULT '',
	version    TEXT NOT NULL DEFAULT '',
	scope      TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL
);
`;

const COLS = "session_id,id,seq,mode,title,severity,status,evidence_level,type,target,summary,description,poc,chain,evidence,fix,verify_note,created_at,updated_at,verified_at,baseline,diff_evidence,marker_echo,impact,cvss,retest_note,retest_at,request_pkt,response_pkt,snippet_entry,snippet_sink,chain_tracer,chain_verdict,cwe,patch,source_origin,sample_hash,family,packer,iocs,detection_rule,timeline_at,entry,identity,permission,resource,audit_mode";
const N_COLS = COLS.split(",").length;

/** 存量库新列（逐列 ALTER，已存在则忽略）。 */
const MIGRATION_COLUMNS = [
	"baseline", "diff_evidence", "marker_echo", "impact", "cvss", "retest_note", "retest_at",
	"request_pkt", "response_pkt", "snippet_entry", "snippet_sink", "chain_tracer", "chain_verdict",
	"cwe", "patch", "source_origin", "chain", "sample_hash", "family", "packer", "iocs", "detection_rule", "timeline_at",
	"entry", "identity", "permission", "resource"

	, "audit_mode"
];;

/** 打开（或创建）库并预编译语句。dbPath 传 ":memory:" 供测试。 */
export function openStore(dbPath) {
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL;");
	db.exec(SCHEMA);
	for (const col of MIGRATION_COLUMNS) {
		try { db.exec(`ALTER TABLE findings ADD COLUMN ${col} TEXT NOT NULL DEFAULT ''`); } catch { /* 列已存在 */ }
	}
	return {
		dbPath,
		db,
		insert: db.prepare(`INSERT INTO findings (${COLS}) VALUES (${"?,".repeat(N_COLS - 1)}?)`),
		get: db.prepare(`SELECT ${COLS} FROM findings WHERE session_id = ? AND id = ?`),
		nextSeq: db.prepare("SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM findings WHERE session_id = ? AND mode = ?"),
		update: db.prepare(`UPDATE findings SET title=?, severity=?, status=?, evidence_level=?, type=?, target=?, summary=?, description=?, poc=?, chain=?, evidence=?, fix=?, verify_note=?, updated_at=?, verified_at=?, baseline=?, diff_evidence=?, marker_echo=?, impact=?, cvss=?, retest_note=?, retest_at=?, request_pkt=?, response_pkt=?, snippet_entry=?, snippet_sink=?, chain_tracer=?, chain_verdict=?, cwe=?, patch=?, source_origin=?, sample_hash=?, family=?, packer=?, iocs=?, detection_rule=?, timeline_at=?, entry=?, identity=?, permission=?, resource=?, audit_mode=? WHERE session_id=? AND id=?`),
		remove: db.prepare("DELETE FROM findings WHERE session_id = ? AND id = ?"),
		listAll: db.prepare(`SELECT ${COLS} FROM findings WHERE session_id = ? AND mode = ? ORDER BY seq DESC`),
		listAllAll: db.prepare(`SELECT ${COLS} FROM findings WHERE session_id = ? ORDER BY updated_at DESC, seq DESC`),
		listGlobal: db.prepare(`SELECT ${COLS} FROM findings ORDER BY updated_at DESC, seq DESC`),
		listGlobalMode: db.prepare(`SELECT ${COLS} FROM findings WHERE mode = ? ORDER BY updated_at DESC, seq DESC`),
		countsAll: db.prepare("SELECT mode, COUNT(*) AS n FROM findings GROUP BY mode"),
		counts: db.prepare("SELECT mode, COUNT(*) AS n FROM findings WHERE session_id = ? GROUP BY mode"),
		metaGet: db.prepare("SELECT target_label, version, scope, updated_at FROM session_meta WHERE session_id = ?"),
		metaSet: db.prepare("INSERT INTO session_meta (session_id, target_label, version, scope, updated_at) VALUES (?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET target_label=excluded.target_label, version=excluded.version, scope=excluded.scope, updated_at=excluded.updated_at"),
		close: () => { try { db.close(); } catch { /* 已关闭 */ } }
	};
}

const nowIso = () => new Date().toISOString();
const cleanEnum = (v, allowed, fallback) => (allowed.includes(v) ? v : fallback);
const cleanText = (v, max = 20000) => {
	const s = typeof v === "string" ? v.trim() : "";
	return s.length > max ? s.slice(0, max) : s;
};

/** 追加的可选富字段（camelCase → 列名映射）。 */
const EXTRA_FIELDS = ["baseline", "diffEvidence", "markerEcho", "impact", "cvss", "retestNote", "retestAt", "requestPkt", "responsePkt", "snippetEntry", "snippetSink", "chainTracer", "chainVerdict", "cwe", "patch", "sampleHash", "family", "packer", "iocs", "detectionRule", "timelineAt", "entry", "identity", "permission", "resource", "auditMode"];
const COL_OF = {
	baseline: "baseline", diffEvidence: "diff_evidence", markerEcho: "marker_echo", impact: "impact",
	cvss: "cvss", retestNote: "retest_note", retestAt: "retest_at", requestPkt: "request_pkt",
	responsePkt: "response_pkt", snippetEntry: "snippet_entry", snippetSink: "snippet_sink",
	chainTracer: "chain_tracer", chainVerdict: "chain_verdict", cwe: "cwe", patch: "patch",
	sampleHash: "sample_hash", family: "family", packer: "packer", iocs: "iocs", detectionRule: "detection_rule",
	timelineAt: "timeline_at", entry: "entry", identity: "identity", permission: "permission", resource: "resource", auditMode: "audit_mode"
};

function rowToFinding(row) {
	const f = {
		id: row.id, seq: row.seq, mode: row.mode,
		title: row.title, severity: row.severity, status: row.status, evidenceLevel: row.evidence_level,
		type: row.type, target: row.target, summary: row.summary, description: row.description,
		poc: row.poc, chain: row.chain, evidence: row.evidence, fix: row.fix, verifyNote: row.verify_note,
		createdAt: row.created_at, updatedAt: row.updated_at, verifiedAt: row.verified_at,
		sourceOrigin: row.source_origin || "manual"
	};
	for (const k of EXTRA_FIELDS) f[k] = row[COL_OF[k]] ?? "";
	return f;
}

/** 登记一条 finding（会话内 mode 维度自增序号；mode 由宿主从会话推导，调用方不可指定他模式）。 */
export function registerFinding(store, sessionId, mode, input) {
	const seq = store.nextSeq.get(sessionId, mode).n;
	const id = `${mode}-${seq}`;
	const now = nowIso();
	const f = {
		id, seq, mode,
		title: cleanText(input.title, 200) || "未命名发现",
		severity: cleanEnum(input.severity, SEVERITIES, "medium"),
		status: cleanEnum(input.status, STATUSES, "pending"),
		evidenceLevel: cleanEnum(input.evidenceLevel, EVIDENCE_LEVELS, "unknown"),
		type: cleanText(input.type, 60),
		target: cleanText(input.target, 500),
		summary: cleanText(input.summary, 300),
		description: cleanText(input.description),
		poc: cleanText(input.poc),
		chain: cleanText(input.chain),
		evidence: cleanText(input.evidence),
		fix: cleanText(input.fix),
		verifyNote: "",
		createdAt: now, updatedAt: now, verifiedAt: "",
		sourceOrigin: cleanEnum(input.sourceOrigin, SOURCE_ORIGINS, "manual")
	};
	for (const k of EXTRA_FIELDS) f[k] = cleanText(input[k]);
	store.insert.run(
		sessionId, f.id, f.seq, mode, f.title, f.severity, f.status, f.evidenceLevel, f.type, f.target, f.summary,
		f.description, f.poc, f.chain, f.evidence, f.fix, f.verifyNote, f.createdAt, f.updatedAt, f.verifiedAt,
		f.baseline, f.diffEvidence, f.markerEcho, f.impact, f.cvss, f.retestNote, f.retestAt, f.requestPkt,
		f.responsePkt, f.snippetEntry, f.snippetSink, f.chainTracer, f.chainVerdict, f.cwe, f.patch, f.sourceOrigin,
		f.sampleHash, f.family, f.packer, f.iocs, f.detectionRule, f.timelineAt, f.entry, f.identity, f.permission, f.resource, f.auditMode
	);
	return f;
}

/** 按 (sessionId, mode, id) 更新——跨模式 id 一律 undefined（隔离由存储层强制）。 */
export function updateFinding(store, sessionId, mode, id, patch = {}) {
	const row = store.get.get(sessionId, id);
	if (row === undefined || row.mode !== mode) return undefined;
	const prev = rowToFinding(row);
	const statusSet = statusesOf(mode);
	// fixed 只接受"此前已验证真实存在"的流转：先 verified、修复后复测不成功才可标记（仅含 fixed 的模式适用）。
	if (statusSet.includes("fixed") && cleanEnum(patch.status, statusSet, prev.status) === "fixed" && prev.status !== "verified") {
		throw new Error("已修复 仅可用于此前已验证（verified）真实存在的 finding——先验证成立，用户修复后复测不成功再标记 fixed");
	}
	const next = {
		title: cleanText(patch.title, 200) || prev.title,
		severity: cleanEnum(patch.severity, SEVERITIES, prev.severity),
		status: cleanEnum(patch.status, statusSet, prev.status),
		evidenceLevel: cleanEnum(patch.evidenceLevel, EVIDENCE_LEVELS, prev.evidenceLevel),
		type: patch.type !== undefined ? cleanText(patch.type, 60) : prev.type,
		target: patch.target !== undefined ? cleanText(patch.target, 500) : prev.target,
		summary: patch.summary !== undefined ? cleanText(patch.summary, 300) : prev.summary,
		description: patch.description !== undefined ? cleanText(patch.description) : prev.description,
		poc: patch.poc !== undefined ? cleanText(patch.poc) : prev.poc,
		chain: patch.chain !== undefined ? cleanText(patch.chain) : prev.chain,
		evidence: patch.evidence !== undefined ? cleanText(patch.evidence) : prev.evidence,
		fix: patch.fix !== undefined ? cleanText(patch.fix) : prev.fix,
		verifyNote: patch.verifyNote !== undefined ? cleanText(patch.verifyNote) : prev.verifyNote,
		updatedAt: nowIso(),
		verifiedAt: prev.status !== "verified" && cleanEnum(patch.status, statusSet, prev.status) === "verified" ? nowIso() : prev.verifiedAt,
		sourceOrigin: cleanEnum(patch.sourceOrigin, SOURCE_ORIGINS, prev.sourceOrigin)
	};
	for (const k of EXTRA_FIELDS) next[k] = patch[k] !== undefined ? cleanText(patch[k]) : prev[k];
	store.update.run(
		next.title, next.severity, next.status, next.evidenceLevel, next.type, next.target, next.summary,
		next.description, next.poc, next.chain, next.evidence, next.fix, next.verifyNote, next.updatedAt, next.verifiedAt,
		next.baseline, next.diffEvidence, next.markerEcho, next.impact, next.cvss, next.retestNote, next.retestAt,
		next.requestPkt, next.responsePkt, next.snippetEntry, next.snippetSink, next.chainTracer, next.chainVerdict,
		next.cwe, next.patch, next.sourceOrigin, next.sampleHash, next.family, next.packer, next.iocs, next.detectionRule, next.timelineAt,
		next.entry, next.identity, next.permission, next.resource, next.auditMode, sessionId, id
	);
	return { ...prev, ...next };
}

/** 按 (sessionId, id) 删除（行不存在则无操作）。 */
export function removeFinding(store, sessionId, id) {
	store.remove.run(sessionId, id);
}

export function getFinding(store, sessionId, id) {
	const row = store.get.get(sessionId, id);
	return row === undefined ? undefined : rowToFinding(row);
}

export function allFindings(store, sessionId, mode) {
	return store.listAll.all(sessionId, mode).map(rowToFinding);
}

export function listFindings(store, sessionId, mode, { page = 1, pageSize = DEFAULT_PAGE_SIZE, severity = "", status = "", q = "" } = {}) {
	const needle = String(q ?? "").trim().toLowerCase();
	const rows = allFindings(store, sessionId, mode)
		.filter((f) => (severity ? f.severity === severity : true))
		.filter((f) => (status ? f.status === status : true))
		.filter((f) => (needle ? `${f.title} ${f.summary} ${f.target} ${f.type} ${f.cwe}`.toLowerCase().includes(needle) : true));
	const size = Math.max(1, Math.min(100, Number(pageSize) || DEFAULT_PAGE_SIZE));
	const total = rows.length;
	const pages = Math.max(1, Math.ceil(total / size));
	const current = Math.min(pages, Math.max(1, Number(page) || 1));
	return { rows: rows.slice((current - 1) * size, current * size), total, page: current, pageSize: size, pages };
}

/** 按目标/位置分组（渗透=资产分组，代审=文件分组共用）。 */
export function groupByTarget(store, sessionId, mode, { severity = "", status = "", q = "" } = {}) {
	const needle = String(q ?? "").trim().toLowerCase();
	const rows = allFindings(store, sessionId, mode)
		.filter((f) => (severity ? f.severity === severity : true))
		.filter((f) => (status ? f.status === status : true))
		.filter((f) => (needle ? `${f.title} ${f.summary} ${f.target} ${f.type} ${f.cwe}`.toLowerCase().includes(needle) : true));
	const groups = new Map();
	for (const f of rows) {
		const key = f.target || "（未填）";
		if (!groups.has(key)) groups.set(key, []);
		groups.get(key).push(f);
	}
	return [...groups.entries()].map(([target, items]) => ({ target, count: items.length, items }));
}

/** 统计内核（会话版与全局版共用）：四档严重度、状态分布、类型 top、CWE/来源/目标/家族/壳分布。 */
function statsOf(all) {
	const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
	const byStatus = Object.fromEntries(STATUSES.map((s) => [s, 0]));
	const byEvidence = Object.fromEntries(EVIDENCE_LEVELS.map((s) => [s, 0]));
	const typeMap = new Map();
	const cweMap = new Map();
	const sourceMap = new Map();
	const auditModeMap = new Map();
	const familyMap = new Map();
	const packerMap = new Map();
	const targetMap = new Map();
	let lastAt = "";
	for (const f of all) {
		bySeverity[f.severity] += 1;
		byStatus[f.status] += 1;
		byEvidence[f.evidenceLevel] += 1;
		typeMap.set(f.type || "未分类", (typeMap.get(f.type || "未分类") ?? 0) + 1);
		if (f.cwe) cweMap.set(f.cwe, (cweMap.get(f.cwe) ?? 0) + 1);
		if (f.family) familyMap.set(f.family, (familyMap.get(f.family) ?? 0) + 1);
		if (f.packer) packerMap.set(f.packer, (packerMap.get(f.packer) ?? 0) + 1);
		sourceMap.set(f.sourceOrigin || "manual", (sourceMap.get(f.sourceOrigin || "manual") ?? 0) + 1);
		if (f.auditMode) auditModeMap.set(f.auditMode, (auditModeMap.get(f.auditMode) ?? 0) + 1);
		targetMap.set(f.target || "（未填）", (targetMap.get(f.target || "（未填）") ?? 0) + 1);
		if (f.updatedAt > lastAt) lastAt = f.updatedAt;
	}
	const top = (m, n) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, count]) => ({ key, count }));
	return {
		total: all.length,
		bySeverity,
		byStatus,
		byEvidence,
		byType: top(typeMap, 8).map(({ key, count }) => ({ type: key, count })),
		byCwe: top(cweMap, 8).map(({ key, count }) => ({ cwe: key, count })),
		bySource: top(sourceMap, 4).map(({ key, count }) => ({ source: key, count })),
		byAuditMode: top(auditModeMap, 2).map(({ key, count }) => ({ auditMode: key, count })),
		byTarget: top(targetMap, 8).map(({ key, count }) => ({ target: key, count })),
		byFamily: top(familyMap, 8).map(({ key, count }) => ({ family: key, count })),
		byPacker: top(packerMap, 6).map(({ key, count }) => ({ packer: key, count })),
		lastAt
	};
}

/** 会话内统计（原语义保留）。 */
export function computeStats(store, sessionId, mode) {
	return statsOf(allFindings(store, sessionId, mode));
}

/** 跨会话统计：按登记时间（created_at）范围过滤后的全模式数据聚合。 */
export function computeStatsAll(store, mode, { from = "", to = "" } = {}) {
	const rows = store.listGlobalMode.all(mode)
		.filter((row) => (from === "" || row.created_at >= from) && (to === "" || row.created_at <= to));
	return statsOf(rows);
}

/** 跨会话模式计数（侧栏总数，全时域）。 */
export function modeCountsAll(store) {
	const out = Object.fromEntries(MODES.map((m) => [m, 0]));
	for (const row of store.countsAll.all()) if (out[row.mode] !== undefined) out[row.mode] = row.n;
	return out;
}

/** 跨会话清单：按 mode 全表 + 筛选（severity/status/q）+ created_at 范围 + 分页；行带 sessionId。 */
export function listFindingsAll(store, mode, { page = 1, pageSize = DEFAULT_PAGE_SIZE, severity = "", status = "", q = "", from = "", to = "" } = {}) {
	const needle = String(q ?? "").trim().toLowerCase();
	const rows = store.listGlobalMode.all(mode)
		.map((row) => ({ ...rowToFinding(row), sessionId: row.session_id }))
		.filter((f) => (severity ? f.severity === severity : true))
		.filter((f) => (status ? f.status === status : true))
		.filter((f) => (from === "" || f.createdAt >= from))
		.filter((f) => (to === "" || f.createdAt <= to))
		.filter((f) => (needle ? `${f.title} ${f.summary} ${f.target} ${f.type} ${f.cwe}`.toLowerCase().includes(needle) : true));
	const size = Math.max(1, Math.min(100, Number(pageSize) || DEFAULT_PAGE_SIZE));
	const total = rows.length;
	const pages = Math.max(1, Math.ceil(total / size));
	const current = Math.min(pages, Math.max(1, Number(page) || 1));
	return { rows: rows.slice((current - 1) * size, current * size), total, page: current, pageSize: size, pages };
}

/** 跨会话按目标分组（平铺分组视图共享）。 */
export function groupByTargetAll(store, mode, { severity = "", status = "", q = "", from = "", to = "" } = {}) {
	const list = listFindingsAll(store, mode, { severity, status, q, from, to, page: 1, pageSize: 100000 });
	const groups = new Map();
	for (const f of list.rows) {
		const key = f.target || "（未填）";
		if (!groups.has(key)) groups.set(key, []);
		groups.get(key).push(f);
	}
	return [...groups.entries()].map(([target, items]) => ({ target, count: items.length, items }));
}


/** 大屏聚合：全会话跨模式——模式/状态/等级/证据分布 + 最近流水（全部模式倒序）。 */
export function ledgerOverview(store, sessionId) {
	const rows = store.listAllAll ? store.listAllAll.all(sessionId) : [];
	const byMode = Object.fromEntries(MODES.map((m) => [m, 0]));
	const byStatus = { pending: 0, verified: 0, "false-positive": 0, fixed: 0 };
	const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
	const byEvidence = Object.fromEntries(EVIDENCE_LEVELS.map((s) => [s, 0]));
	let lastAt = "";
	for (const row of rows) {
		if (byMode[row.mode] !== undefined) byMode[row.mode] += 1;
		if (byStatus[row.status] !== undefined) byStatus[row.status] += 1;
		if (bySeverity[row.severity] !== undefined) bySeverity[row.severity] += 1;
		if (byEvidence[row.evidence_level] !== undefined) byEvidence[row.evidence_level] += 1;
		if (row.updated_at > lastAt) lastAt = row.updated_at;
	}
	const recent = rows.slice(0, 120).map(rowToFinding);
	return { total: rows.length, byMode, byStatus, bySeverity, byEvidence, recent, lastAt };
}

/** 全局作战大屏聚合：跨会话（全部安全模式），按登记时间（created_at）过滤范围。
 * from/to 为 ISO 字符串（闭区间，空串=该侧不限）；recent 每条带 sessionId 供跨会话定位。 */
export function ledgerOverviewAll(store, { from = "", to = "" } = {}) {
	const rows = store.listGlobal.all();
	const inRange = (row) => (from === "" || row.created_at >= from) && (to === "" || row.created_at <= to);
	const byMode = Object.fromEntries(MODES.map((m) => [m, 0]));
	const byStatus = { pending: 0, verified: 0, "false-positive": 0, fixed: 0 };
	const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
	const byEvidence = Object.fromEntries(EVIDENCE_LEVELS.map((s) => [s, 0]));
	const sessions = new Set();
	let lastAt = "";
	let total = 0;
	for (const row of rows) {
		if (!inRange(row)) continue;
		total += 1;
		sessions.add(row.session_id);
		if (byMode[row.mode] !== undefined) byMode[row.mode] += 1;
		if (byStatus[row.status] !== undefined) byStatus[row.status] += 1;
		if (bySeverity[row.severity] !== undefined) bySeverity[row.severity] += 1;
		if (byEvidence[row.evidence_level] !== undefined) byEvidence[row.evidence_level] += 1;
		if (row.updated_at > lastAt) lastAt = row.updated_at;
	}
	const recent = rows.filter(inRange).slice(0, 120).map((row) => ({ ...rowToFinding(row), sessionId: row.session_id }));
	return { total, sessions: sessions.size, byMode, byStatus, bySeverity, byEvidence, recent, lastAt, range: { from, to } };
}

export function modeCounts(store, sessionId) {
	const out = Object.fromEntries(MODES.map((m) => [m, 0]));
	for (const row of store.counts.all(sessionId)) if (out[row.mode] !== undefined) out[row.mode] = row.n;
	return out;
}

/** 会话任务元数据（审计对象/渗透范围、版本/commit、scope）。 */
export function getMeta(store, sessionId) {
	const row = store.metaGet.get(sessionId);
	return row === undefined ? { targetLabel: "", version: "", scope: "" } : { targetLabel: row.target_label, version: row.version, scope: row.scope };
}

export function setMeta(store, sessionId, { targetLabel = "", version = "", scope = "" } = {}) {
	store.metaSet.run(sessionId, cleanText(targetLabel, 200), cleanText(version, 120), cleanText(scope, 500), nowIso());
	return getMeta(store, sessionId);
}

export { SEVERITIES, STATUSES, MODE_STATUSES, ALL_STATUSES, EVIDENCE_LEVELS, SOURCE_ORIGINS, MODES, statusesOf };
