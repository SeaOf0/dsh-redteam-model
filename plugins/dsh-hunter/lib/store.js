// dsh-hunter store：独立 SQLite（~/.dsh/hunter/hunter.db）
//   - configs：三平台 API key（只存密文值，UI 回显末 4 位）
//   - history：实测流水线历史（可审计）
//   - authorized：用户标记授权的资产白名单（L1 验证只对这些资产执行）
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS configs (
  platform TEXT NOT NULL PRIMARY KEY,
  key_value TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  finding_id TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT 'code-audit',
  query TEXT NOT NULL DEFAULT '',
  platforms TEXT NOT NULL DEFAULT '',
  verdict TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS authorized (
  key TEXT NOT NULL PRIMARY KEY,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
`;

const PLATFORMS = ["fofa", "hunter", "quake"];
const nowIso = () => new Date().toISOString();

export function openHunterStore(dbPath) {
	if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
	const db = new DatabaseSync(dbPath);
	db.exec("PRAGMA journal_mode = WAL;");
	db.exec(SCHEMA);
	return {
		dbPath,
		db,
		setKey: db.prepare("INSERT INTO configs (platform, key_value, updated_at) VALUES (?,?,?) ON CONFLICT(platform) DO UPDATE SET key_value=excluded.key_value, updated_at=excluded.updated_at"),
		getKeys: db.prepare("SELECT platform, key_value, updated_at FROM configs"),
		insertHistory: db.prepare("INSERT INTO history (created_at, finding_id, mode, query, platforms, verdict, details) VALUES (?,?,?,?,?,?,?)"),
		listHistory: db.prepare("SELECT * FROM history ORDER BY id DESC LIMIT ?"),
		authorize: db.prepare("INSERT INTO authorized (key, note, created_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET note=excluded.note, created_at=excluded.created_at"),
		unauthorize: db.prepare("DELETE FROM authorized WHERE key = ?"),
		listAuthorized: db.prepare("SELECT key, note, created_at FROM authorized ORDER BY created_at DESC"),
		close: () => { try { db.close(); } catch { /* 已关闭 */ } }
	};
}

/** 配置视图：只返回「是否已配置 + 末 4 位」，绝不回传完整 key。 */
export function configView(store) {
	const rows = store.getKeys.all();
	const out = {};
	for (const p of PLATFORMS) out[p] = { configured: false, tail: "" };
	for (const row of rows) {
		const key = String(row.key_value ?? "");
		out[row.platform] = { configured: key.length > 0, tail: key.length > 4 ? "…" + key.slice(-4) : key };
	}
	return out;
}

export function getKey(store, platform) {
	const row = store.getKeys.all().find((r) => r.platform === platform);
	return row ? String(row.key_value ?? "") : "";
}

export { PLATFORMS, nowIso };
