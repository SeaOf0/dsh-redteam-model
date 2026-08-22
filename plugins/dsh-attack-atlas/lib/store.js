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
	created_at TEXT NOT NULL,
	PRIMARY KEY (session_id, mode, id)
);
CREATE TABLE IF NOT EXISTS chain_edges (
	session_id TEXT NOT NULL,
	mode       TEXT NOT NULL,
	src        TEXT NOT NULL,
	dst        TEXT NOT NULL,
	label      TEXT NOT NULL DEFAULT "",
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
`;

export const TARGET_KINDS = ["domain", "web", "ip", "api", "miniprogram", "android", "ios", "desktop", "component", "cloud", "ai", "other"];
const TARGET_KIND_LABELS = { domain: "域名", web: "Web 站点", ip: "IP/主机", api: "API 服务", miniprogram: "小程序", android: "Android", ios: "iOS", desktop: "桌面客户端", component: "组件/中间件", cloud: "云资产", ai: "AI 服务", other: "其他" };

export function targetKindLabel(kind) {
	return TARGET_KIND_LABELS[kind] || "其他";
}

export function openStore(dbPath) {
	if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true }); // node:sqlite 不建父目录
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL");
	db.exec(SCHEMA);
	try { db.exec("ALTER TABLE coverage ADD COLUMN target TEXT NOT NULL DEFAULT ''"); } catch { /* 旧库已迁移（列已存在） */ }
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

export function addChainNode(st, sessionId, mode, { id, label, kind = "host", seg = "", note = "", major = false }) {
	const nid = clean(id, 60);
	if (!/^[a-z0-9][a-z0-9._-]*$/i.test(nid)) throw new Error(`节点 id 非法（字母数字与 ._-）：${nid}`);
	const l = clean(label, 80);
	if (!l) throw new Error("label required");
	const k = CHAIN_NODE_KINDS.includes(kind) ? kind : "other";
	st.db.prepare("INSERT INTO chain_nodes (session_id, mode, id, label, kind, seg, note, major, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n" +
		"ON CONFLICT (session_id, mode, id) DO UPDATE SET label = excluded.label, kind = excluded.kind, seg = excluded.seg, note = excluded.note, major = excluded.major")
		.run(String(sessionId), String(mode), nid, l, k, clean(seg, 60), clean(note, 300), major ? 1 : 0, now());
	return { id: nid, label: l, kind: k, major: !!major };
}

export function addChainEdge(st, sessionId, mode, { src, dst, label = "" }) {
	const a = clean(src, 60), b = clean(dst, 60), l = clean(label, 80);
	if (!a || !b) throw new Error("src/dst required");
	for (const n of [a, b]) {
		const hit = st.db.prepare("SELECT id FROM chain_nodes WHERE session_id = ? AND mode = ? AND id = ?").get(String(sessionId), String(mode), n);
		if (!hit) throw new Error(`边引用未登记节点：${n}（先 add-node）`);
	}
	st.db.prepare("INSERT INTO chain_edges (session_id, mode, src, dst, label, created_at) VALUES (?, ?, ?, ?, ?, ?)\n" +
		"ON CONFLICT (session_id, mode, src, dst, label) DO UPDATE SET label = excluded.label")
		.run(String(sessionId), String(mode), a, b, l, now());
	return { src: a, dst: b, label: l };
}

export function listChain(st, sessionId, mode) {
	const nodes = st.db.prepare("SELECT id, label, kind, seg, note, major, created_at AS createdAt FROM chain_nodes WHERE session_id = ? AND mode = ? ORDER BY created_at, id").all(String(sessionId), String(mode));
	const edges = st.db.prepare("SELECT src, dst, label FROM chain_edges WHERE session_id = ? AND mode = ? ORDER BY created_at").all(String(sessionId), String(mode));
	return { nodes, edges };
}

export function clearChain(st, sessionId, mode) {
	st.db.prepare("DELETE FROM chain_nodes WHERE session_id = ? AND mode = ?").run(String(sessionId), String(mode));
	st.db.prepare("DELETE FROM chain_edges WHERE session_id = ? AND mode = ?").run(String(sessionId), String(mode));
	return { cleared: "chain" };
}

export function removeTarget(st, sessionId, mode, seq) {
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
