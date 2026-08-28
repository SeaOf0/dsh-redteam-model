// dsh-attack-atlas store — SQLite 覆盖态数据层（node:sqlite DatabaseSync）。
//
// 单库 ~/.dsh/attack-atlas/atlas.db：
//   coverage 表以 (session_id, mode, key) 为主键——key 为格子（cat/item）或主类（cat）；
//   stages 表记作战流程阶段推进（active/done）。
// 语义对齐 playbook 矩阵覆盖规则：N-A 与预算耗尽必附原因；未测 = 无记录（不落 todo 行）。

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

const CELL_STATES = ["tested-found", "tested-clear", "na", "budget-stop"];
const STAGE_STATES = ["active", "done"];

const SCHEMA = `
CREATE TABLE IF NOT EXISTS coverage (
	session_id  TEXT NOT NULL,
	mode        TEXT NOT NULL,
	key         TEXT NOT NULL,
	state       TEXT NOT NULL,
	reason      TEXT NOT NULL DEFAULT '',
	finding_refs TEXT NOT NULL DEFAULT '',
	target      TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (session_id, mode, key)
);
CREATE TABLE IF NOT EXISTS stages (
	session_id TEXT NOT NULL,
	mode       TEXT NOT NULL,
	stage      TEXT NOT NULL,
	state      TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (session_id, mode, stage)
);
CREATE TABLE IF NOT EXISTS chain_nodes (
	session_id TEXT NOT NULL,
	mode       TEXT NOT NULL,
	id         TEXT NOT NULL,
	label      TEXT NOT NULL,
	kind       TEXT NOT NULL DEFAULT "host",
	seg        TEXT NOT NULL DEFAULT "",
	note       TEXT NOT NULL DEFAULT "",
	major      INTEGER NOT NULL DEFAULT 0,
	finding_ref TEXT NOT NULL DEFAULT "",
	created_at TEXT NOT NULL,
	PRIMARY KEY (session_id, mode, id)
);
CREATE TABLE IF NOT EXISTS chain_edges (
	session_id TEXT NOT NULL,
	mode       TEXT NOT NULL,
	src        TEXT NOT NULL,
	dst        TEXT NOT NULL,
	label      TEXT NOT NULL DEFAULT "",
	edge_type  TEXT NOT NULL DEFAULT "",
	created_at TEXT NOT NULL,
	PRIMARY KEY (session_id, mode, src, dst, label)
);
CREATE TABLE IF NOT EXISTS targets (
	session_id TEXT NOT NULL,
	mode       TEXT NOT NULL,
	seq        INTEGER NOT NULL,
	label      TEXT NOT NULL,
	kind       TEXT NOT NULL DEFAULT 'other',
	note       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	PRIMARY KEY (session_id, mode, seq)
);
CREATE TABLE IF NOT EXISTS methods (
	id         TEXT NOT NULL,
	mode       TEXT NOT NULL,
	name       TEXT NOT NULL,
	target     TEXT NOT NULL DEFAULT '',
	notes      TEXT NOT NULL DEFAULT '',
	graph      TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS methods_mode ON methods(mode);
CREATE TABLE IF NOT EXISTS capabilities (
	id         TEXT NOT NULL,
	mode       TEXT NOT NULL,
	kind       TEXT NOT NULL,
	cat        TEXT NOT NULL,
	item       TEXT NOT NULL DEFAULT '',
	label      TEXT NOT NULL,
	descr      TEXT NOT NULL DEFAULT '',
	template   TEXT NOT NULL DEFAULT '',
	ref        TEXT NOT NULL DEFAULT '',
	pb         TEXT NOT NULL DEFAULT '',
	forms      TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS caps_mode ON capabilities(mode);
CREATE TABLE IF NOT EXISTS misses (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	mode       TEXT NOT NULL,
	kind       TEXT NOT NULL,
	query      TEXT NOT NULL,
	error      TEXT NOT NULL DEFAULT '',
	session_id TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS misses_mode ON misses(mode, query);
`;

export const TARGET_KINDS = ["domain", "web", "ip", "api", "miniprogram", "android", "ios", "desktop", "component", "cloud", "ai", "repo", "sample", "payload", "webshell", "loader", "memshell", "c2", "host", "case", "challenge", "account", "tenant", "cluster", "other"];
const TARGET_KIND_LABELS = { domain: "域名", web: "Web 站点", ip: "IP/主机", api: "API 服务", miniprogram: "小程序", android: "Android", ios: "iOS", desktop: "桌面客户端", component: "组件/中间件", cloud: "云资产", ai: "AI 服务", repo: "源码仓库", sample: "样本", payload: "载荷", webshell: "WebShell", loader: "加载器", memshell: "内存马", c2: "C2 通道", host: "主机", case: "案件", challenge: "题目", account: "云账号", tenant: "租户", cluster: "集群", other: "其他" };

export function targetKindLabel(kind) {
	return TARGET_KIND_LABELS[kind] || "其他";
}

export function openStore(dbPath) {
	if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true }); // node:sqlite 不建父目录
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL");
	db.exec(SCHEMA);
	try { db.exec("ALTER TABLE coverage ADD COLUMN target TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移（列已存在） */ }
	try { db.exec("ALTER TABLE chain_nodes ADD COLUMN finding_ref TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移（列已存在） */ }
	try { db.exec("ALTER TABLE chain_edges ADD COLUMN edge_type TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移（列已存在） */ }
	return {
		db,
		close() { db.close(); }
	};
}

function now() {
	return new Date().toISOString().replace("T", " ").slice(0, 19);
}

function clean(s, max) {
	return String(s ?? "").trim().slice(0, max);
}

/** 格子终态落库（upsert）。na/budget-stop 必附原因——覆盖规则的硬约束在存储层强制。
 *  target：终态所属目标（多目标会话溯源用；单目标未填时自动归属唯一登记目标）。 */
export function markCell(st, sessionId, mode, key, { state, reason = "", findingRefs = "", target = "" }) {
	const k = clean(key, 120);
	if (!k.includes("/")) {
		if (!/^[a-z0-9-]+$/.test(k)) throw new Error(`非法主类 key：${k}`);
	} else if (!/^[a-z0-9-]+\/[a-z0-9-]+$/.test(k)) {
		throw new Error(`非法格子 key：${k}`);
	}
	if (!CELL_STATES.includes(state)) throw new Error(`state 必须是 ${CELL_STATES.join("/")}`);
	const r = clean(reason, 500);
	if ((state === "na" || state === "budget-stop") && !r) throw new Error(`${state === "na" ? "N-A" : "预算耗尽"}必须附原因（reason）`);
	const refs = clean(findingRefs, 300);
	let tgt = clean(target, 120);
	if (!tgt) {
		const registered = listTargets(st, sessionId, mode);
		if (registered.length === 1) tgt = registered[0].label; // 单目标自动归属
	}
	st.db.prepare(
		"INSERT INTO coverage (session_id, mode, key, state, reason, finding_refs, target, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)\n" +
		"ON CONFLICT (session_id, mode, key) DO UPDATE SET state = excluded.state, reason = excluded.reason, finding_refs = excluded.finding_refs, target = excluded.target, updated_at = excluded.updated_at"
	).run(String(sessionId), String(mode), k, state, r, refs, tgt, now());
	return { key: k, state, reason: r, findingRefs: refs, target: tgt };
}

/** 阶段推进（active=进行中 / done=完成）。 */
export function markStage(st, sessionId, mode, stage, state) {
	const s = clean(stage, 40);
	if (!/^[a-z0-9-]+$/.test(s)) throw new Error(`非法阶段 id：${s}`);
	if (!STAGE_STATES.includes(state)) throw new Error(`state 必须是 ${STAGE_STATES.join("/")}`);
	st.db.prepare(
		"INSERT INTO stages (session_id, mode, stage, state, updated_at) VALUES (?, ?, ?, ?, ?)\n" +
		"ON CONFLICT (session_id, mode, stage) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at"
	).run(String(sessionId), String(mode), s, state, now());
	return { stage: s, state };
}

/** 全量读取（会话 × 模式）：格子 + 阶段 + 目标。 */
export function getCoverage(st, sessionId, mode) {
	const cells = st.db.prepare("SELECT key, state, reason, finding_refs AS findingRefs, target, updated_at AS updatedAt FROM coverage WHERE session_id = ? AND mode = ?")
		.all(String(sessionId), String(mode));
	const stages = st.db.prepare("SELECT stage, state, updated_at AS updatedAt FROM stages WHERE session_id = ? AND mode = ?")
		.all(String(sessionId), String(mode));
	const targets = listTargets(st, sessionId, mode);
	return { cells, stages, targets };
}

/** 目标登记（与资产清单基线同步维护；一个会话可多目标）。 */
export function addTarget(st, sessionId, mode, { label, kind = "other", note = "" }) {
	const l = clean(label, 120);
	if (!l) throw new Error("label required");
	const k = TARGET_KINDS.includes(kind) ? kind : "other";
	const row = st.db.prepare("SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM targets WHERE session_id = ? AND mode = ?").get(String(sessionId), String(mode));
	const seq = row.n;
	st.db.prepare("INSERT INTO targets (session_id, mode, seq, label, kind, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
		.run(String(sessionId), String(mode), seq, l, k, clean(note, 300), now());
	return { seq, label: l, kind: k, note: clean(note, 300) };
}

export function listTargets(st, sessionId, mode) {
	return st.db.prepare("SELECT seq, label, kind, note, created_at AS createdAt FROM targets WHERE session_id = ? AND mode = ? ORDER BY seq")
		.all(String(sessionId), String(mode));
}

export const CHAIN_NODE_KINDS = ["entry", "host", "segment", "bastion", "dc", "cred", "attacker", "infra", "pivot", "exfil", "identity", "secret", "resource", "orgroot", "other"];
const CHAIN_KIND_LABELS = { entry: "入口", host: "主机", segment: "网段关口", bastion: "堡垒机", dc: "域控", cred: "凭据", attacker: "攻击者", infra: "C2/基础设施", pivot: "跳板/横向", exfil: "外传/扩散", identity: "身份/角色", secret: "密钥面", resource: "云资源", orgroot: "组织根/KMS", other: "资产" };
export function chainKindLabel(kind) { return CHAIN_KIND_LABELS[kind] || "资产"; }

export function addChainNode(st, sessionId, mode, { id, label, kind = "host", seg = "", note = "", major = false, findingRef = "" }) {
	const nid = clean(id, 60);
	if (!/^[a-z0-9][a-z0-9._-]*$/i.test(nid)) throw new Error(`节点 id 非法（字母数字与 ._-）：${nid}`);
	const l = clean(label, 80);
	if (!l) throw new Error("label required");
	const k = CHAIN_NODE_KINDS.includes(kind) ? kind : "other";
	const fr = clean(findingRef, 60); // 关联成果 finding id（与「redteam 成果」页互链；空=无关联）
	st.db.prepare("INSERT INTO chain_nodes (session_id, mode, id, label, kind, seg, note, major, finding_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n" +
		"ON CONFLICT (session_id, mode, id) DO UPDATE SET label = excluded.label, kind = excluded.kind, seg = excluded.seg, note = excluded.note, major = excluded.major, finding_ref = excluded.finding_ref")
		.run(String(sessionId), String(mode), nid, l, k, clean(seg, 60), clean(note, 300), major ? 1 : 0, fr, now());
	return { id: nid, label: l, kind: k, major: !!major, findingRef: fr };
}

/** 链路边类型学（黑板关系边五型）：类型化边让拓扑可按边语义聚合检索，label 仍是自由补充细节。
 *  空串=未分类（旧数据兼容）。 */
export const CHAIN_EDGE_TYPES = {
	"discovered_on": "在…发现",
	"exploits": "利用",
	"enables": "使可行",
	"depends_on": "前置依赖",
	"leads_to": "导致"
};

export function addChainEdge(st, sessionId, mode, { src, dst, label = "", edgeType = "" }) {
	const a = clean(src, 60), b = clean(dst, 60), l = clean(label, 80);
	if (!a || !b) throw new Error("src/dst required");
	const et = Object.hasOwn(CHAIN_EDGE_TYPES, String(edgeType ?? "")) ? String(edgeType) : "";
	for (const n of [a, b]) {
		const hit = st.db.prepare("SELECT id FROM chain_nodes WHERE session_id = ? AND mode = ? AND id = ?").get(String(sessionId), String(mode), n);
		if (!hit) throw new Error(`边引用未登记节点：${n}（先 add-node）`);
	}
	st.db.prepare("INSERT INTO chain_edges (session_id, mode, src, dst, label, edge_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)\n" +
		"ON CONFLICT (session_id, mode, src, dst, label) DO UPDATE SET label = excluded.label, edge_type = excluded.edge_type")
		.run(String(sessionId), String(mode), a, b, l, et, now());
	return { src: a, dst: b, label: l, edgeType: et };
}

export function listChain(st, sessionId, mode) {
	const nodes = st.db.prepare("SELECT id, label, kind, seg, note, major, finding_ref AS findingRef, created_at AS createdAt FROM chain_nodes WHERE session_id = ? AND mode = ? ORDER BY created_at, id").all(String(sessionId), String(mode));
	const edges = st.db.prepare("SELECT src, dst, label, edge_type AS edgeType FROM chain_edges WHERE session_id = ? AND mode = ? ORDER BY created_at").all(String(sessionId), String(mode));
	return { nodes, edges };
}

/** 反查互链：该模式下各 finding 被哪些链路节点引用（键=`${sessionId}:${findingRef}`——
 *  「redteam 成果」页跨会话模式页 Detail 的「链路节点」行用）。 */
export function chainRefIndex(st, mode) {
	const rows = st.db.prepare("SELECT session_id AS sessionId, id AS nodeId, label, kind, major, finding_ref AS findingRef FROM chain_nodes WHERE mode = ? AND finding_ref != ''").all(String(mode));
	const idx = {};
	for (const r of rows) (idx[`${r.sessionId}:${r.findingRef}`] ||= []).push(r);
	return idx;
}

export function clearChain(st, sessionId, mode) {
	st.db.prepare("DELETE FROM chain_nodes WHERE session_id = ? AND mode = ?").run(String(sessionId), String(mode));
	st.db.prepare("DELETE FROM chain_edges WHERE session_id = ? AND mode = ?").run(String(sessionId), String(mode));
	return { cleared: "chain" };
}

export function removeTarget(st, sessionId, mode, seq) {
	const owner = st.db.prepare("SELECT label FROM targets WHERE session_id = ? AND mode = ? AND seq = ?").get(String(sessionId), String(mode), Number(seq));
	if (owner) st.db.prepare("UPDATE coverage SET target = '' WHERE session_id = ? AND mode = ? AND target = ?").run(String(sessionId), String(mode), owner.label);
	st.db.prepare("DELETE FROM targets WHERE session_id = ? AND mode = ? AND seq = ?").run(String(sessionId), String(mode), Number(seq));
	return { removed: Number(seq) };
}

/** 清除一条格子记录（回退到未测）；key 缺省 = 清空该会话该模式全部覆盖态。 */
export function clearCoverage(st, sessionId, mode, key) {
	if (key === undefined || key === "") {
		st.db.prepare("DELETE FROM coverage WHERE session_id = ? AND mode = ?").run(String(sessionId), String(mode));
		st.db.prepare("DELETE FROM stages WHERE session_id = ? AND mode = ?").run(String(sessionId), String(mode));
		return { cleared: "all" };
	}
	st.db.prepare("DELETE FROM coverage WHERE session_id = ? AND mode = ? AND key = ?").run(String(sessionId), String(mode), clean(key, 120));
	return { cleared: clean(key, 120) };
}

export { CELL_STATES, STAGE_STATES };

//#region 自定义工作方法论模板（跨会话长期资产，模式作用域）

const METHOD_ID_RE = /^m-[a-z0-9]+$/;
const METHOD_PER_MODE = 50;

function newMethodId() {
	return `m-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

/** 模板保存（upsert）。graph 为对象；体积/数量硬上限在存储层兜底强制。 */
export function saveMethod(st, { id, mode, name, target = "", notes = "", graph }) {
	const m = String(mode ?? "");
	const nm = clean(name, 40);
	if (!m) throw new Error("mode required");
	if (!nm) throw new Error("name required");
	const gObj = typeof graph === "string" ? JSON.parse(graph) : graph;
	const text = JSON.stringify(gObj);
	if (text.length > 64 * 1024) throw new Error("图数据超体积上限");
	let nodeId = clean(id, 40);
	if (nodeId && !METHOD_ID_RE.test(nodeId)) throw new Error(`非法模板 id：${nodeId}`);
	const existing = nodeId ? st.db.prepare("SELECT id, mode FROM methods WHERE id = ?").get(nodeId) : undefined;
	if (existing && existing.mode !== m) throw new Error(`模板属于 ${existing.mode}，不得跨模式覆盖`);
	if (!existing) nodeId = newMethodId();
	st.db.prepare(
		"INSERT INTO methods (id, mode, name, target, notes, graph, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)\n" +
		"ON CONFLICT(id) DO UPDATE SET name = excluded.name, target = excluded.target, notes = excluded.notes, graph = excluded.graph, updated_at = excluded.updated_at"
	).run(nodeId, m, nm, clean(target, 120), clean(notes, 2000), text, now(), now());
	return { id: nodeId, created: !existing };
}

function parseGraphSafe(text) {
	try {
		const g = JSON.parse(text);
		return { nodes: Array.isArray(g.nodes) ? g.nodes.length : 0 };
	} catch { return { nodes: 0, broken: true }; }
}

export function listMethods(st, mode) {
	const rows = st.db.prepare("SELECT id, mode, name, target, notes, graph, updated_at AS updatedAt FROM methods WHERE mode = ? ORDER BY updated_at DESC").all(String(mode));
	return rows.map((r) => ({ id: r.id, mode: r.mode, name: r.name, target: r.target, notes: r.notes, graph: (() => { try { return JSON.parse(r.graph); } catch { return { nodes: [], edges: [] }; } })(), updatedAt: r.updatedAt, nodeCount: parseGraphSafe(r.graph).nodes }));
}

export function getMethod(st, id) {
	const r = st.db.prepare("SELECT id, mode, name, target, notes, graph, updated_at AS updatedAt FROM methods WHERE id = ?").get(String(id ?? ""));
	if (!r) return undefined;
	return { id: r.id, mode: r.mode, name: r.name, target: r.target, notes: r.notes, graph: (() => { try { return JSON.parse(r.graph); } catch { return { nodes: [], edges: [] }; } })(), updatedAt: r.updatedAt };
}

export function removeMethod(st, id) {
	const r = st.db.prepare("DELETE FROM methods WHERE id = ?").run(String(id ?? ""));
	if (r.changes === 0) throw new Error(`模板不存在：${id}`);
	return { removed: String(id) };
}

export function copyMethod(st, id) {
	const src = getMethod(st, id);
	if (!src) throw new Error(`模板不存在：${id}`);
	return saveMethod(st, { mode: src.mode, name: `${src.name} 副本`, target: src.target, notes: src.notes, graph: src.graph });
}

/** 导出（可按模式）：不含 id/时间戳，graph 展开为对象——跨机器通用格式。 */
export function exportMethods(st, mode) {
	const rows = mode
		? st.db.prepare("SELECT mode, name, target, notes, graph FROM methods WHERE mode = ? ORDER BY updated_at").all(String(mode))
		: st.db.prepare("SELECT mode, name, target, notes, graph FROM methods ORDER BY mode, updated_at").all();
	return rows.map((r) => ({ mode: r.mode, name: r.name, target: r.target, notes: r.notes, graph: (() => { try { return JSON.parse(r.graph); } catch { return { nodes: [], edges: [] }; } })() }));
}

/** 导入：逐行校验（mode 白名单/graph 形状/数量上限），坏行跳过并说明原因；id 一律重新生成。 */
export function importMethods(st, rows, validModes) {
	const imported = [];
	const skipped = [];
	const list = Array.isArray(rows) ? rows.slice(0, 100) : [];
	for (const row of list) {
		const nm = clean(row?.name, 40);
		const m = clean(row?.mode, 40);
		if (!nm || !m) { skipped.push({ name: nm || "(无名)", reason: "缺名称或模式" }); continue; }
		if (!validModes.includes(m)) { skipped.push({ name: nm, reason: `未知模式 ${m}` }); continue; }
		let g = row?.graph ?? { nodes: [], edges: [] };
		if (typeof g === "string") { try { g = JSON.parse(g); } catch { g = null; } }
		if (!g || !Array.isArray(g.nodes) || g.nodes.length === 0) { skipped.push({ name: nm, reason: "图数据缺失或为空" }); continue; }
		if (g.nodes.length > 60) { skipped.push({ name: nm, reason: "模块数超上限" }); continue; }
		const count = st.db.prepare("SELECT COUNT(*) AS n FROM methods WHERE mode = ?").get(m).n;
		if (count >= METHOD_PER_MODE) { skipped.push({ name: nm, reason: `模式 ${m} 模板数已达上限 ${METHOD_PER_MODE}` }); continue; }
		const saved = saveMethod(st, { mode: m, name: nm, target: clean(row?.target, 120), notes: clean(row?.notes, 2000), graph: g });
		imported.push({ id: saved.id, name: nm, mode: m });
	}
	return { imported, skipped };
}

//#endregion

//#region 能力库（自定义主类/子类，跨会话长期资产，模式作用域；key 与覆盖格子同构）

const CAP_KINDS = ["category", "item"];
const CAP_KEY_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const CAPS_LIMIT = { categories: 20, items: 100 };

function capKey() {
	return "u-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

/** 保存能力（upsert）。category 行：cat=自身体系 key（新建自动 u- 前缀）；item 行：cat=所属主类 key、item=子类短 key。 */
export function saveCap(st, { id, mode, kind, cat, item, label, desc = "", template = "", ref = "", pb = "", forms = "" }) {
	const m = String(mode ?? "");
	const k = String(kind ?? "");
	if (!m) throw new Error("mode required");
	if (!CAP_KINDS.includes(k)) throw new Error(`kind 必须是 ${CAP_KINDS.join("/")}`);
	const l = clean(label, 60);
	if (!l) throw new Error("label required");
	const rowId = clean(id, 40);
	const existing = rowId ? st.db.prepare("SELECT id, kind FROM capabilities WHERE id = ?").get(rowId) : undefined;
	if (rowId && !existing) throw new Error(`能力不存在：${rowId}`);
	let catKey = "", itemKey = "";
	if (k === "category") {
		if (existing) {
			if (existing.kind !== "category") throw new Error("类型不可变更");
			catKey = st.db.prepare("SELECT cat FROM capabilities WHERE id = ?").get(rowId).cat;
		} else {
			const n = st.db.prepare("SELECT COUNT(*) AS n FROM capabilities WHERE mode = ? AND kind = 'category'").get(m).n;
			if (n >= CAPS_LIMIT.categories) throw new Error(`自定义主类已达上限 ${CAPS_LIMIT.categories}`);
			catKey = capKey();
		}
	} else {
		const c = clean(cat, 60);
		if (!CAP_KEY_RE.test(c)) throw new Error(`所属主类 key 非法：${c || "(空)"}`);
		let oldCat = "";
		if (existing) {
			if (existing.kind !== "item") throw new Error("类型不可变更");
			const prevRow = st.db.prepare("SELECT cat, item FROM capabilities WHERE id = ?").get(rowId);
			itemKey = prevRow.item;
			oldCat = prevRow.cat;
		} else {
			const n = st.db.prepare("SELECT COUNT(*) AS n FROM capabilities WHERE mode = ? AND kind = 'item'").get(m).n;
			if (n >= CAPS_LIMIT.items) throw new Error(`自定义子类已达上限 ${CAPS_LIMIT.items}`);
			itemKey = capKey();
		}
		catKey = c;
		// 换主类：既有终态行随迁（旧 cat/item → 新 cat/item），矩阵不留幽灵行；
		// 新 key 已有终态时（UPDATE OR IGNORE 落空）删旧行去重——状态以新格子现存为准。
		if (oldCat && oldCat !== catKey) {
			const oldKey = `${oldCat}/${itemKey}`, newKey = `${catKey}/${itemKey}`;
			st.db.prepare("UPDATE OR IGNORE coverage SET key = ? WHERE mode = ? AND key = ?").run(newKey, m, oldKey);
			st.db.prepare("DELETE FROM coverage WHERE mode = ? AND key = ?").run(m, oldKey);
		}
	}
	const rid = rowId || ("c-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8));
	st.db.prepare(
		"INSERT INTO capabilities (id, mode, kind, cat, item, label, descr, template, ref, pb, forms, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n" +
		"ON CONFLICT(id) DO UPDATE SET cat = excluded.cat, label = excluded.label, descr = excluded.descr, template = excluded.template, ref = excluded.ref, pb = excluded.pb, forms = excluded.forms, updated_at = excluded.updated_at"
	).run(rid, m, k, catKey, itemKey, l, clean(desc, 300), clean(template, 2000), clean(ref, 120), clean(pb, 120), clean(forms, 120), now(), now());
	return { id: rid, kind: k, cat: catKey, item: itemKey };
}

export function listCaps(st, mode) {
	return st.db.prepare(
		"SELECT id, mode, kind, cat, item, label, descr, template, ref, pb, forms, updated_at AS updatedAt FROM capabilities WHERE mode = ? " +
		"ORDER BY CASE kind WHEN 'category' THEN 0 ELSE 1 END, created_at, id"
	).all(String(mode));
}

/** 删除：自定义主类级联删除其全部自定义子类，并清理对应覆盖终态孤儿行；返回级联数。 */
export function removeCap(st, id) {
	const row = st.db.prepare("SELECT id, mode, kind, cat, item FROM capabilities WHERE id = ?").get(String(id ?? ""));
	if (!row) throw new Error(`能力不存在：${id}`);
	let cascaded = 0;
	if (row.kind === "category") {
		const r = st.db.prepare("DELETE FROM capabilities WHERE mode = ? AND kind = 'item' AND cat = ?").run(row.mode, row.cat);
		cascaded = r.changes;
		// 主类与其全部子类格子（cat 及 cat/*）的终态行跨会话清理——矩阵本就不渲染自定义主类
		st.db.prepare("DELETE FROM coverage WHERE mode = ? AND (key = ? OR key LIKE ? || '/%')").run(row.mode, row.cat, row.cat);
	} else if (row.item) {
		st.db.prepare("DELETE FROM coverage WHERE mode = ? AND key = ?").run(row.mode, row.cat + "/" + row.item);
	}
	st.db.prepare("DELETE FROM capabilities WHERE id = ?").run(row.id);
	return { removed: row.id, cascaded };
}

/** 导出（可按模式）：保留 cat/item 体系 key（跨机器方法论模板引用可续）；行 id/时间戳不入包。 */
export function exportCaps(st, mode) {
	const rows = mode
		? st.db.prepare("SELECT mode, kind, cat, item, label, descr, template, ref, pb, forms FROM capabilities WHERE mode = ? ORDER BY kind, created_at").all(String(mode))
		: st.db.prepare("SELECT mode, kind, cat, item, label, descr, template, ref, pb, forms FROM capabilities ORDER BY mode, kind, created_at").all();
	return rows.map((r) => ({ mode: r.mode, kind: r.kind, cat: r.cat, item: r.item, label: r.label, desc: r.descr, template: r.template, ref: r.ref, pb: r.pb, forms: r.forms }));
}

/** 导入：格式/数量/同 key 去重检查，坏行跳过说明原因；体系 key 尽量保留，非法时新生成。 */
export function importCaps(st, rows, validModes) {
	const imported = [];
	const skipped = [];
	const list = Array.isArray(rows) ? rows.slice(0, 200) : [];
	for (const row of list) {
		const m = clean(row?.mode, 40), k = clean(row?.kind, 10), l = clean(row?.label, 60);
		if (!l) { skipped.push({ name: "(无名)", reason: "缺名称" }); continue; }
		if (!m || !validModes.includes(m)) { skipped.push({ name: l, reason: `未知模式 ${m || "(空)"}` }); continue; }
		if (!CAP_KINDS.includes(k)) { skipped.push({ name: l, reason: "kind 非法" }); continue; }
		if (k === "category") {
			const key = CAP_KEY_RE.test(clean(row?.cat, 60)) ? clean(row?.cat, 60) : capKey();
			if (st.db.prepare("SELECT id FROM capabilities WHERE mode = ? AND kind = 'category' AND cat = ?").get(m, key)) { skipped.push({ name: l, reason: "同名主类标识已存在（重复导入）" }); continue; }
			const n = st.db.prepare("SELECT COUNT(*) AS n FROM capabilities WHERE mode = ? AND kind = 'category'").get(m).n;
			if (n >= CAPS_LIMIT.categories) { skipped.push({ name: l, reason: `模式 ${m} 自定义主类已达上限` }); continue; }
			const rid = "c-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
			st.db.prepare("INSERT INTO capabilities (id, mode, kind, cat, item, label, descr, template, ref, pb, forms, created_at, updated_at) VALUES (?, ?, 'category', ?, '', ?, ?, ?, ?, ?, ?, ?, ?)")
				.run(rid, m, key, l, clean(row?.desc, 300), clean(row?.template, 2000), clean(row?.ref, 120), clean(row?.pb, 120), clean(row?.forms, 120), now(), now());
			imported.push({ id: rid, name: l, mode: m });
		} else {
			const ck = clean(row?.cat, 60), ik = clean(row?.item, 60);
			if (!CAP_KEY_RE.test(ck) || !CAP_KEY_RE.test(ik)) { skipped.push({ name: l, reason: "所属主类或子类 key 非法" }); continue; }
			if (st.db.prepare("SELECT id FROM capabilities WHERE mode = ? AND kind = 'item' AND cat = ? AND item = ?").get(m, ck, ik)) { skipped.push({ name: l, reason: "同 key 子类已存在（重复导入）" }); continue; }
			const n = st.db.prepare("SELECT COUNT(*) AS n FROM capabilities WHERE mode = ? AND kind = 'item'").get(m).n;
			if (n >= CAPS_LIMIT.items) { skipped.push({ name: l, reason: `模式 ${m} 自定义子类已达上限` }); continue; }
			const rid = "c-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
			st.db.prepare("INSERT INTO capabilities (id, mode, kind, cat, item, label, descr, template, ref, pb, forms, created_at, updated_at) VALUES (?, ?, 'item', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
				.run(rid, m, ck, ik, l, clean(row?.desc, 300), clean(row?.template, 2000), clean(row?.ref, 120), clean(row?.pb, 120), clean(row?.forms, 120), now(), now());
			imported.push({ id: rid, name: l, mode: m });
		}
	}
	return { imported, skipped };
}

//#endregion

//#region MISS 缺口台账：模型想点亮但体系里不存在的 key——数据驱动的能力库补缺依据

/** 未命中落库（best-effort：任何失败静默——统计面不阻塞业务路径）。kind: cell/stage。 */
export function recordMiss(st, { mode, kind, query, error = "", sessionId = "" }) {
	try {
		st.db.prepare("INSERT INTO misses (mode, kind, query, error, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?)")
			.run(clean(mode, 40), clean(kind, 20), clean(query, 120), clean(error, 500), clean(sessionId, 80), now());
	} catch { /* 统计面尽力而为 */ }
}

/** 聚合视图：按 (mode, kind, query) 计数 + 最近出现，频次降序——高频未命中即「值得建自定义模块」清单。 */
export function missSummary(st, { limit = 50 } = {}) {
	const rows = st.db.prepare(
		`SELECT mode, kind, query, COUNT(*) AS n, MAX(created_at) AS last_at
		 FROM misses GROUP BY mode, kind, query ORDER BY n DESC, last_at DESC LIMIT ?`
	).all(Math.min(Math.max(Number(limit) || 50, 1), 200));
	const total = st.db.prepare("SELECT COUNT(*) AS n FROM misses").get().n;
	return { total, rows };
}

//#endregion
