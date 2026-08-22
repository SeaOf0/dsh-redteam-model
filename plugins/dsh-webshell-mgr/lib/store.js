// dsh-webshell-mgr store：独立 SQLite（~/.dsh/webshell-mgr/webshell.db）
//   - connections：webshell 连接注册表（协议/语言/执行模式/凭据/编码/探活状态）
//   - conn_states：每连接工作区状态（终端历史、上次路径等，UI 落盘）
//   - db_profiles：每连接多套数据库连接档案
//   - generations：生成器产物登记（文件落 ~/.dsh/webshell-mgr/generated/）
//   - op_log：操作台账（报告门/清痕对账用——每次 exec/file/db/plugin 操作记一行）
// 凭据为明文存储：webshell 口令属一次性作战凭据，不采用加密落盘；删除连接不自动清
// 凭据明文落盘——彻底清除时删库文件并 VACUUM。

import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS connections (
  id TEXT NOT NULL PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'cmd-system',
  shell_lang TEXT NOT NULL DEFAULT 'php',
  exec_mode TEXT NOT NULL DEFAULT 'system',
  pass_param TEXT NOT NULL DEFAULT 'pass',
  cmd_param TEXT NOT NULL DEFAULT 'cmd',
  password TEXT NOT NULL DEFAULT '',
  secret_key TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT 'post',
  encoding TEXT NOT NULL DEFAULT 'auto',
  db_encoding TEXT NOT NULL DEFAULT 'auto',
  os TEXT NOT NULL DEFAULT 'auto',
  headers_json TEXT NOT NULL DEFAULT '{}',
  timeout_ms INTEGER NOT NULL DEFAULT 20000,
  remark TEXT NOT NULL DEFAULT '',
  basic_info TEXT NOT NULL DEFAULT '',
  last_probe_at TEXT NOT NULL DEFAULT '',
  last_status TEXT NOT NULL DEFAULT 'unknown',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS conn_states (
  conn_id TEXT NOT NULL PRIMARY KEY,
  state_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS db_profiles (
  id TEXT NOT NULL PRIMARY KEY,
  conn_id TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'mysql',
  host TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  database TEXT NOT NULL DEFAULT '',
  remark TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS generations (
  id TEXT NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  lang TEXT NOT NULL,
  kind TEXT NOT NULL,
  file_path TEXT NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS op_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conn_id TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_op_log_conn ON op_log (conn_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_db_profiles_conn ON db_profiles (conn_id);
`;

const nowIso = () => new Date().toISOString();
const newId = (prefix) => prefix + "_" + randomBytes(6).toString("hex");

const CONN_FIELDS = ["name", "url", "protocol", "shell_lang", "exec_mode", "pass_param", "cmd_param", "password", "secret_key", "method", "encoding", "db_encoding", "os", "kind", "headers_json", "profile_json", "timeout_ms", "remark"];

/** 连接行 → 业务对象：headers 解析 + 数值规整。 */
export function rowToConn(row) {
	if (!row) return null;
	const conn = { ...row };
	try { conn.headers = JSON.parse(row.headers_json || "{}") ?? {}; } catch { conn.headers = {}; }
	try { conn.basicInfo = row.basic_info ? JSON.parse(row.basic_info) : null; } catch { conn.basicInfo = null; }
	conn.timeoutMs = Number(row.timeout_ms) || 20000;
	delete conn.headers_json;
	delete conn.basic_info;
	return conn;
}

export function openStore(dbPath) {
	if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL;");
	db.exec(SCHEMA);
	// 存量库迁移：连接形态列（file=文件马 / mem=内存马——内存马注入管理为二期，字段先预留）
	try { db.exec("ALTER TABLE connections ADD COLUMN kind TEXT NOT NULL DEFAULT 'file'"); } catch { /* 已有列 */ }
	try { db.exec("ALTER TABLE connections ADD COLUMN profile_json TEXT NOT NULL DEFAULT ''"); } catch { /* 已有列 */ }
	const stmts = {
		insertConn: db.prepare(`INSERT INTO connections (id, ${CONN_FIELDS.join(", ")}, basic_info, last_probe_at, last_status, created_at, updated_at)
			VALUES (:id, :name, :url, :protocol, :shell_lang, :exec_mode, :pass_param, :cmd_param, :password, :secret_key, :method, :encoding, :db_encoding, :os, :kind, :headers_json, :profile_json, :timeout_ms, :remark, '', '', 'unknown', :now, :now)`),
		updateConn: db.prepare(`UPDATE connections SET ${CONN_FIELDS.map((f) => `${f} = :${f}`).join(", ")}, updated_at = :now WHERE id = :id`),
		getConn: db.prepare("SELECT * FROM connections WHERE id = ?"),
		listConns: db.prepare("SELECT * FROM connections ORDER BY created_at DESC"),
		deleteConn: db.prepare("DELETE FROM connections WHERE id = ?"),
		setProbe: db.prepare("UPDATE connections SET basic_info = ?, last_probe_at = ?, last_status = ?, os = CASE WHEN ? = 'auto' THEN os ELSE ? END, updated_at = ? WHERE id = ?"),
		getState: db.prepare("SELECT state_json FROM conn_states WHERE conn_id = ?"),
		setState: db.prepare("INSERT INTO conn_states (conn_id, state_json) VALUES (?, ?) ON CONFLICT(conn_id) DO UPDATE SET state_json = excluded.state_json"),
		clearState: db.prepare("DELETE FROM conn_states WHERE conn_id = ?"),
		insertDbProfile: db.prepare("INSERT INTO db_profiles (id, conn_id, type, host, port, username, password, database, remark, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)"),
		updateDbProfile: db.prepare("UPDATE db_profiles SET type=?, host=?, port=?, username=?, password=?, database=?, remark=? WHERE id=? AND conn_id=?"),
		deleteDbProfile: db.prepare("DELETE FROM db_profiles WHERE id = ? AND conn_id = ?"),
		listDbProfiles: db.prepare("SELECT * FROM db_profiles WHERE conn_id = ? ORDER BY created_at"),
		insertGeneration: db.prepare("INSERT INTO generations (id, name, lang, kind, file_path, meta_json, created_at) VALUES (?,?,?,?,?,?,?)"),
		listGenerations: db.prepare("SELECT * FROM generations ORDER BY created_at DESC"),
		deleteGeneration: db.prepare("DELETE FROM generations WHERE id = ?"),
		insertOp: db.prepare("INSERT INTO op_log (conn_id, action, detail, created_at) VALUES (?,?,?,?)"),
		listOps: db.prepare("SELECT * FROM op_log WHERE conn_id = ? ORDER BY id DESC LIMIT ?")
	};
	return {
		dbPath,
		db,
		...stmts,
		close: () => { try { db.close(); } catch { /* 已关闭 */ } }
	};
}

/** 新建/更新连接（fields 为 CONN_FIELDS 子集 + id）。 */
export function saveConn(st, fields) {
	const id = String(fields.id ?? "") || newId("ws");
	const row = {
		id,
		name: String(fields.name ?? ""),
		url: String(fields.url ?? "").trim(),
		protocol: String(fields.protocol ?? "cmd-system"),
		shell_lang: String(fields.shell_lang ?? "php"),
		exec_mode: String(fields.exec_mode ?? "system"),
		pass_param: String(fields.pass_param ?? "pass"),
		cmd_param: String(fields.cmd_param ?? "cmd"),
		password: String(fields.password ?? ""),
		secret_key: String(fields.secret_key ?? ""),
		method: fields.method === "get" ? "get" : "post",
		encoding: String(fields.encoding ?? "auto"),
		db_encoding: String(fields.db_encoding ?? "auto"),
		os: String(fields.os ?? "auto"),
		kind: String(fields.kind ?? "file") === "mem" ? "mem" : "file",
		headers_json: JSON.stringify(fields.headers && typeof fields.headers === "object" ? fields.headers : {}),
		profile_json: String(fields.profile_json ?? ""),
		timeout_ms: Math.min(Math.max(Number(fields.timeout_ms) || 20000, 3000), 120000),
		remark: String(fields.remark ?? ""),
		now: nowIso()
	};
	const existing = st.getConn.get(id);
	if (existing) {
		// 更新：未提供的字段沿用现值（凭据留空 = 保持不变语义在 UI 层处理，这里字段级覆盖）
		for (const f of CONN_FIELDS) if (fields[f] === undefined) row[f] = existing[f];
		row.headers_json = fields.headers === undefined ? existing.headers_json : row.headers_json;
		row.timeout_ms = fields.timeout_ms === undefined ? existing.timeout_ms : row.timeout_ms;
	}
	if (!row.url) throw new Error("url 不能为空");
	if (existing) st.updateConn.run(row);
	else st.insertConn.run(row);
	return rowToConn(st.getConn.get(id));
}

export function listConns(st) {
	return st.listConns.all().map(rowToConn);
}

export function getConn(st, id) {
	return rowToConn(st.getConn.get(String(id ?? "")));
}

export function deleteConn(st, id) {
	st.deleteConn.run(String(id ?? ""));
	st.clearState.run(String(id ?? ""));
	st.db.prepare("DELETE FROM db_profiles WHERE conn_id = ?").run(String(id ?? ""));
}

export function recordProbe(st, id, { status, basicInfo, os }) {
	st.setProbe.run(
		basicInfo ? JSON.stringify(basicInfo) : "",
		nowIso(),
		status,
		os ?? "auto",
		os ?? "auto",
		nowIso(),
		String(id ?? "")
	);
}

export function getState(st, connId) {
	const row = st.getState.get(String(connId ?? ""));
	if (!row) return {};
	try { return JSON.parse(row.state_json) ?? {}; } catch { return {}; }
}

export function setState(st, connId, state) {
	st.setState.run(String(connId ?? ""), JSON.stringify(state ?? {}));
}

export function listDbProfiles(st, connId) {
	return st.listDbProfiles.all(String(connId ?? ""));
}

export function saveDbProfile(st, connId, fields) {
	const id = String(fields.id ?? "") || newId("db");
	const existing = st.getConn.get(String(connId ?? ""));
	if (!existing) throw new Error("连接不存在");
	const row = st.listDbProfiles.all(String(connId)).find((r) => r.id === id);
	if (row) {
		// 更新语义：密码缺省或空串都保持原值（UI 编辑不回显不重填；新档案才允许空密码）
		let pw = fields.password === undefined || String(fields.password) === "" ? row.password : String(fields.password);
		st.updateDbProfile.run(
			String(fields.type ?? row.type), String(fields.host ?? row.host), Number(fields.port ?? row.port) || 0,
			fields.username === undefined ? row.username : String(fields.username),
			pw,
			String(fields.database ?? row.database), String(fields.remark ?? row.remark), id, String(connId)
		);
	} else {
		st.insertDbProfile.run(id, String(connId), String(fields.type ?? "mysql"), String(fields.host ?? ""), Number(fields.port) || 0,
			String(fields.username ?? ""), String(fields.password ?? ""), String(fields.database ?? ""), String(fields.remark ?? ""), nowIso());
	}
	return st.listDbProfiles.all(String(connId)).find((r) => r.id === id);
}

export function deleteDbProfile(st, connId, id) {
	st.deleteDbProfile.run(String(id ?? ""), String(connId ?? ""));
}

export function recordGeneration(st, { name, lang, kind, filePath, meta }) {
	const id = newId("gen");
	st.insertGeneration.run(id, String(name ?? ""), String(lang ?? ""), String(kind ?? ""), String(filePath ?? ""), JSON.stringify(meta ?? {}), nowIso());
	return st.listGenerations.all().find((r) => r.id === id);
}

export function listGenerations(st) {
	return st.listGenerations.all();
}

export function logOp(st, connId, action, detail) {
	try { st.insertOp.run(String(connId ?? ""), String(action ?? ""), String(detail ?? "").slice(0, 4000), nowIso()); } catch { /* 日志不阻塞主流程 */ }
}

export function listOps(st, connId, limit = 50) {
	return st.listOps.all(String(connId ?? ""), Math.min(Number(limit) || 50, 500));
}

export { nowIso };
