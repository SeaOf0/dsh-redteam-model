// dsh-webshell-mgr「webshell 管理」宿主插件：
//   1) Web 通道：/dsh-webshell-mgr 前缀路由（同源信任栅栏）——连接/执行/文件/数据库/
//      生成器/插件/台账 RPC；
//   2) 模型工具面：webshell_generate / connect / list / exec / file / db /
//      plugin_list / plugin_run 八件——执行时解析 composedPreset，仅五安全模式放行
//      （redteam / pentest / attack-defense / av-evasion / ctf-solver）；
//   3) 存储：独立 SQLite ~/.dsh/webshell-mgr/webshell.db + generated/ 产物目录 +
//      plugins/ 用户载荷插件目录；
//   4) MCP：同核 stdio 服务在 mcp/server.mjs（外部 harness 用，dsh 会话内走本工具面）。
//
// 授权边界：仅授权测试环境使用；所有操作入 op_log 台账（清痕对账用）。
// 不走 connection.rpc（部分 fiber 上注册 webServer 路由会静默 405——hunter/results 同款结论）。

import path from "node:path";
import os from "node:os";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { openStore, saveConn, listConns, getConn, deleteConn, recordProbe, getState, setState, listDbProfiles, saveDbProfile, deleteDbProfile, recordGeneration, listGenerations, logOp, listOps } from "./store.js";
import { protocolMeta, detectProtocol, probeConnection } from "./protocol/registry.js";
import * as cap from "./protocol/capabilities.js";
import { GEN_KINDS, makeAndSave, importFromFile } from "./generators.js";
import { listPlugins, getPlugin, runPlugin, checkRunnable } from "./plugins-registry.js";
import { readFileSync } from "node:fs";

const name = "dsh-webshell-mgr";
const inject = ["tools", "webServer", "webRuntime", "agentPresets"];

const ROUTE_PATH = "/dsh-webshell-mgr";
const BASE_DIR = path.join(os.homedir(), ".dsh", "webshell-mgr");
const DB_PATH = path.join(BASE_DIR, "webshell.db");
const MAX_BODY = 8 * 1024 * 1024;
const MAX_READ = 4 * 1024 * 1024;
const ALLOWED_MODES = ["redteam", "pentest", "attack-defense", "av-evasion", "ctf-solver"];
const MODE_LABEL = { redteam: "研究员模式", pentest: "渗透测试模式", "attack-defense": "攻防评估模式", "av-evasion": "免杀对抗模式", "ctf-solver": "CTF 解题模式" };

let store;
function theStore() {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}

//#region 通用逻辑（路由与工具共用）

function connOrThrow(id) {
	const conn = getConn(theStore(), id);
	if (!conn) throw new Error(`连接 ${id} 不存在`);
	return conn;
}

/** 连接（自动识别 + 登记或刷新既有）。 */
async function connectCore(p) {
	const spec = {
		url: String(p.url ?? "").trim(),
		password: String(p.password ?? ""),
		secretKey: String(p.secretKey ?? ""),
		passParam: String(p.passParam ?? "pass"),
		cmdParam: String(p.cmdParam ?? "cmd"),
		method: p.method === "get" ? "get" : "post",
		timeoutMs: Number(p.timeoutMs) || 8000
	};
	if (!spec.url) throw new Error("url 不能为空");
	const result = await detectProtocol(spec);
	if (!result.hit) {
		const attempted = result.attempts.map((a) => `${a.protocol}(${a.error})`).join("；");
		throw new Error(`${result.error}。已试：${attempted}`);
	}
	// 登记或刷新（同 URL 复用既有连接）
	const existing = listConns(theStore()).find((c) => c.url === spec.url);
	const saved = saveConn(theStore(), {
		id: existing?.id,
		name: String(p.name ?? "") || existing?.name || new URL(spec.url).hostname,
		url: spec.url,
		protocol: result.protocol,
		shell_lang: result.shellLang,
		exec_mode: result.execMode || (existing?.exec_mode ?? "system"),
		pass_param: result.protocol.startsWith("cmd") ? spec.passParam : (existing?.pass_param ?? spec.passParam),
		cmd_param: result.protocol === "cmd-system" ? spec.cmdParam : (existing?.cmd_param ?? spec.cmdParam),
		password: spec.password,
		secret_key: spec.secretKey,
		method: spec.method,
		os: result.os,
		headers: existing?.headers ?? {}
	});
	recordProbe(theStore(), saved.id, { status: "ok", basicInfo: result.basicInfo, os: result.os });
	logOp(theStore(), saved.id, "connect", `${result.protocol}/${result.shellLang}/os=${result.os}`);
	cap.invalidateConn(saved.id);
	return { conn: publicConn(saved), detection: result };
}

/** 对外连接视图（凭据不回传明文，只带尾 4 位）。 */
function publicConn(c) {
	const { password, secret_key, ...rest } = c;
	return {
		...rest,
		secretKey: secret_key,
		passwordSet: Boolean(password),
		passwordTail: password.length > 4 ? "…" + password.slice(-4) : (password ? "…" : "")
	};
}

async function execCore(connId, command) {
	const conn = connOrThrow(connId);
	const cmd = String(command ?? "").trim();
	if (!cmd) throw new Error("命令为空");
	const output = await cap.runCommand(conn, cmd);
	logOp(theStore(), conn.id, "exec", String(command ?? "").slice(0, 500));
	return { output };
}

async function fileCore(connId, action, a = {}) {
	const conn = connOrThrow(connId);
	switch (action) {
		case "ls": {
			const r = await cap.listDir(conn, String(a.path ?? ""));
			logOp(theStore(), conn.id, "file.ls", String(a.path ?? ""));
			return { entries: r };
		}
		case "read": {
			const buf = await cap.readFile(conn, String(a.path ?? ""));
			if (buf.length > MAX_READ) throw new Error(`文件过大（${buf.length} > ${MAX_READ} 字节）——用下载分段`);
			logOp(theStore(), conn.id, "file.read", String(a.path ?? ""));
			return { b64: buf.toString("base64"), size: buf.length };
		}
		case "write": {
			const buf = Buffer.from(String(a.b64 ?? ""), "base64");
			const r = await cap.writeFile(conn, String(a.path ?? ""), buf);
			logOp(theStore(), conn.id, "file.write", `${a.path} (${buf.length}B)`);
			return r;
		}
		case "mkdir": case "delete": case "delete-dir": case "mv": case "copy": case "chmod": case "touch": case "stat": case "wget": case "hash": case "roots": {
			const r = await cap.fileAction(conn, action, a);
			logOp(theStore(), conn.id, "file." + action, JSON.stringify(a).slice(0, 300));
			return r;
		}
		default: throw new Error(`未知文件操作 ${action}`);
	}
}

async function dbCore(connId, action, a = {}) {
	const conn = connOrThrow(connId);
	if (action === "profiles") {
		// 凭据不回传明文——只给 passwordSet 标志（与连接视图同口径）
		return { profiles: listDbProfiles(theStore(), connId).map(({ password, ...rest }) => ({ ...rest, passwordSet: Boolean(password) })) };
	}
	if (action === "profile.save") return { profile: saveDbProfile(theStore(), connId, a) };
	if (action === "profile.delete") { deleteDbProfile(theStore(), connId, String(a.id ?? "")); return { ok: true }; }
	const profile = listDbProfiles(theStore(), connId).find((x) => x.id === String(a.profileId ?? ""));
	if (!profile) throw new Error("数据库档案不存在——先 profile.save");
	const conn2 = conn;
	switch (action) {
		case "dbs": {
			const dbs = await cap.dbDatabases(conn2, profile);
			logOp(theStore(), conn.id, "db.dbs", profile.type);
			return { databases: dbs };
		}
		case "tables": {
			const tables = await cap.dbTables(conn2, profile, String(a.database ?? ""));
			logOp(theStore(), conn.id, "db.tables", `${a.database ?? profile.database}`);
			return { tables };
		}
		case "tableinfo": {
			const r = await cap.dbTableInfo(conn2, profile, String(a.database ?? ""), String(a.table ?? ""));
			return r;
		}
		case "exec": {
			const r = await cap.dbQuery(conn2, profile, String(a.sql ?? ""));
			logOp(theStore(), conn.id, "db.exec", String(a.sql ?? "").slice(0, 300));
			return r;
		}
		default: throw new Error(`未知数据库操作 ${action}`);
	}
}

function genCore(action, a = {}) {
	switch (action) {
		case "kinds": return { kinds: GEN_KINDS, protocols: protocolMeta() };
		case "list": return { generations: listGenerations(theStore()) };
		case "make": {
			const item = makeAndSave(BASE_DIR, String(a.kind ?? ""), a);
			const rec = recordGeneration(theStore(), { name: item.name, lang: item.lang, kind: item.kind, filePath: item.filePath, meta: { password: item.password, passParam: item.passParam, cmdParam: item.cmdParam, connHint: item.connHint } });
			logOp(theStore(), "", "gen.make", `${item.kind} → ${item.filePath}`);
			return { generation: rec, password: item.password, connHint: item.connHint, content: item.content };
		}
		case "import": {
			const item = importFromFile(BASE_DIR, String(a.path ?? ""), a);
			const rec = recordGeneration(theStore(), { name: item.name, lang: item.lang, kind: "import", filePath: item.filePath, meta: {} });
			return { generation: rec, content: item.content };
		}
		case "read": {
			const rec = listGenerations(theStore()).find((g) => g.id === String(a.id ?? ""));
			if (!rec) throw new Error("产物不存在");
			return { generation: rec, content: readFileSync(rec.file_path, "utf8") };
		}
		case "delete": {
			const id = String(a.id ?? "");
			const rec = listGenerations(theStore()).find((g) => g.id === id);
			if (!rec) throw new Error("产物不存在");
			st.db.prepare("DELETE FROM generations WHERE id = ?").run(id);
			return { ok: true };
		}
		default: throw new Error(`未知生成操作 ${action}`);
	}
}

async function pluginsCore(action, a = {}) {
	switch (action) {
		case "list": {
			const plugins = listPlugins(path.join(BASE_DIR, "plugins")).map((p) => ({ name: p.name, version: p.version, type: p.type, langs: p.langs, protocols: p.protocols, params: p.params, origin: p.origin }));
			return { plugins, dir: path.join(BASE_DIR, "plugins") };
		}
		case "check": {
			const plugin = getPlugin(path.join(BASE_DIR, "plugins"), String(a.name ?? ""));
			if (!plugin) throw new Error("插件不存在");
			const conn = connOrThrow(String(a.connId ?? ""));
			return { blocker: await checkRunnable(conn, plugin) };
		}
		case "run": {
			const plugin = getPlugin(path.join(BASE_DIR, "plugins"), String(a.name ?? ""));
			if (!plugin) throw new Error("插件不存在");
			const conn = connOrThrow(String(a.connId ?? ""));
			const params = typeof a.params === "object" && a.params ? a.params : {};
			const r = await runPlugin(conn, plugin, params);
			logOp(theStore(), conn.id, "plugin.run", `${plugin.name} ${JSON.stringify(params).slice(0, 200)}`);
			return { result: r };
		}
		default: throw new Error(`未知插件操作 ${action}`);
	}
}

//#endregion

//#region 模式门禁（工具面）

function sessionModeOf(ctx, exec) {
	const agent = exec?.agent;
	const id = agent?.session?.id;
	if (!id) return undefined;
	let preset;
	try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
	if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
	return { id: String(id), mode: typeof preset === "string" ? preset : "" };
}

function modeGuard(ctx, exec) {
	const session = sessionModeOf(ctx, exec);
	if (!session) return { ok: false, error: "无法解析当前会话（工具需在会话内调用）" };
	if (!ALLOWED_MODES.includes(session.mode)) {
		return { ok: false, error: `webshell 工具面仅限${ALLOWED_MODES.map((m) => MODE_LABEL[m]).join("/")}调用（当前：${session.mode || "未识别模式"}）` };
	}
	return { ok: true };
}

//#endregion

//#region HTTP 通道

function hostOf(headers) {
	const h = headers?.host;
	return typeof h === "string" ? h : "";
}

function isLoopbackHostname(hostname) {
	if (hostname === "localhost" || hostname === "[::1]") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isTrustedRequest(req, trustedHosts) {
	const host = hostOf(req.headers);
	if (host === "") return false;
	let hostUrl;
	try { hostUrl = new URL(`http://${host}`); } catch { return false; }
	const okHost = isLoopbackHostname(hostUrl.hostname) || (trustedHosts ?? []).some((t) => {
		try { return new URL(`http://${t}`).hostname === hostUrl.hostname; } catch { return false; }
	});
	if (!okHost) return false;
	const origin = req.headers?.origin;
	if (typeof origin === "string" && origin !== "null") {
		try {
			const originUrl = new URL(origin);
			if (originUrl.hostname !== hostUrl.hostname) return false;
		} catch { return false; }
	}
	return true;
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let size = 0;
		const chunks = [];
		req.on("data", (c) => {
			size += c.length;
			if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); return; }
			chunks.push(c);
		});
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

export async function dispatch(ctx, st, endpoint, payload) {
	const p = payload ?? {};
	switch (endpoint) {
		case "meta": return { protocols: protocolMeta(), allowedModes: ALLOWED_MODES };
		case "conn.list": return { connections: listConns(st).map(publicConn) };
		case "conn.save": {
			const saved = saveConn(st, p);
			cap.invalidateConn(saved.id);
			return { conn: publicConn(saved) };
		}
		case "conn.delete": {
			const id = String(p.id ?? "");
			deleteConn(st, id);
			cap.invalidateConn(id);
			return { ok: true };
		}
		case "conn.detect": return detectProtocol({ url: p.url, password: p.password, secretKey: p.secretKey, passParam: p.passParam, cmdParam: p.cmdParam, method: p.method, timeoutMs: p.timeoutMs });
		case "conn.connect": return connectCore(p);
		case "conn.probe": {
			const conn = connOrThrow(String(p.id ?? ""));
			const r = await probeConnection(conn);
			recordProbe(st, conn.id, { status: r.status, basicInfo: r.basicInfo, os: r.os });
			cap.invalidateConn(conn.id);
			logOp(st, conn.id, "probe", r.os);
			return r;
		}
		case "conn.state.get": return { state: getState(st, String(p.id ?? "")) };
		case "conn.state.set": setState(st, String(p.id ?? ""), p.state ?? {}); return { ok: true };
		case "exec.run": return execCore(String(p.connId ?? ""), p.command);
		case "file.ls": case "file.read": case "file.write": case "file.action": {
			const action = endpoint === "file.action" ? String(p.action ?? "") : endpoint.split(".")[1];
			return fileCore(String(p.connId ?? ""), action, p);
		}
		case "db.action": return dbCore(String(p.connId ?? ""), String(p.action ?? ""), p);
		case "gen.action": return genCore(String(p.action ?? ""), p);
		case "plugins.action": return pluginsCore(String(p.action ?? ""), p);
		case "ops.recent": return { ops: listOps(st, String(p.connId ?? ""), Number(p.limit) || 50) };
		default: throw new Error(`unknown endpoint ${endpoint}`);
	}
}

//#endregion

//#region 模型工具注册

function registerTools(ctx) {
	ctx.tools.register(defineTool({
		name: "webshell_generate",
		description: "生成基础/自研加密 webshell 源码（仅授权测试）。php-oneliner（eval 通道一句话）/ php-basic（口令门+命令通道）/ php-aes1|php-aes2（自研加密马 v1=c/u/d、v2=+eval 结构化能力）/ jsp-basic / jsp-aes1 / aspx-basic / aspx-aes1。返回源码+落盘路径+连接提示；免杀变体请走免杀对抗模式。",
		parameters: {
			kind: { type: "string", required: true, enum: Object.keys(GEN_KINDS), description: "生成类型" },
			name: { type: "string", description: "产物名（默认 kind+时间戳）" },
			password: { type: "string", description: "口令（basic/oneliner 用；缺省随机生成并在结果返回）" },
			pass_param: { type: "string", description: "口令参数名（默认 pass）" },
			cmd_param: { type: "string", description: "命令参数名（basic 用，默认 cmd）" }
		},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.ok ? `已生成 ${v.generation.kind} → ${v.generation.file_path}\n连接提示：${v.connHint}` : `生成失败：${v.error}` }] },
		execute(args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, error: g.error });
			const r = genCore("make", args);
			return Promise.resolve({ ok: true, ...r });
		}
	}));

	ctx.tools.register(defineTool({
		name: "webshell_connect",
		description: "登记并连接一个 webshell（仅授权测试）：给定 URL+口令(+盐)自动识别协议（自研加密/一句话 eval/命令通道/魔改冰蝎/魔改哥斯拉），探测 OS 与基本信息，登记进「webshell 管理」页。返回连接 id 供 exec/file/db/plugin 工具使用。",
		parameters: {
			url: { type: "string", required: true, description: "webshell 地址（含协议 http(s)://）" },
			password: { type: "string", description: "口令 / X-T / X-G 值（按协议）" },
			secret_key: { type: "string", description: "盐（魔改通道用，默认 demo 盐）" },
			name: { type: "string", description: "连接备注名（默认 hostname）" },
			pass_param: { type: "string", description: "POST 参数名（一句话通道，默认 pass）" },
			cmd_param: { type: "string", description: "命令参数名（命令通道，默认 cmd）" }
		},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true }, id: { type: "string" } } }, render: (_a, v) => [{ type: "text", text: v.ok ? `已连接 ${v.conn.name}（${v.detection.protocol}/${v.detection.shellLang}，OS=${v.detection.os}，id=${v.conn.id}）` : `连接失败：${v.error}` }] },
		execute(args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, id: "", error: g.error });
			return connectCore(args).then((r) => ({ ok: true, id: r.conn.id, conn: r.conn, detection: r.detection })).catch((e) => ({ ok: false, id: "", error: e?.message ?? String(e) }));
		}
	}));

	ctx.tools.register(defineTool({
		name: "webshell_list",
		description: "列出已登记的 webshell 连接（协议/语言/OS/最近探活状态/基本信息）。",
		parameters: {},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.ok ? v.connections.map((c) => `${c.id} ${c.name} [${c.protocol}/${c.shell_lang}] os=${c.os} ${c.last_status}`).join("\n") || "（无连接）" : `查询失败：${v.error}` }] },
		execute(_args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, error: g.error });
			return Promise.resolve({ ok: true, connections: listConns(theStore()).map(publicConn) });
		}
	}));

	ctx.tools.register(defineTool({
		name: "webshell_exec",
		description: "在指定 webshell 连接上执行 OS 命令（仅授权测试）。行缓冲语义：交互式命令换非交互等价（ad 纪律：长任务拆短命令、输出落文件分段读）。",
		parameters: {
			conn_id: { type: "string", required: true, description: "连接 id（webshell_connect 返回）" },
			command: { type: "string", required: true, description: "OS 命令" }
		},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.ok ? String(v.output ?? "").slice(0, 8000) || "（无输出）" : `执行失败：${v.error}` }] },
		execute(args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, error: g.error });
			return execCore(args.conn_id, args.command).then((r) => ({ ok: true, output: r.output })).catch((e) => ({ ok: false, error: e?.message ?? String(e) }));
		}
	}));

	ctx.tools.register(defineTool({
		name: "webshell_file",
		description: "webshell 文件操作（仅授权测试）。action=ls/read/write/delete/delete-dir/mkdir/mv/chmod/touch/stat/wget/roots。read 返回 base64；write 传 base64（自动分块）；touch 伪造时间戳（epoch 秒）；wget 从 URL 拉文件到目标机。工具上传属环境改动——进操作痕迹台账（本工具每次操作已记 op_log）。",
		parameters: {
			conn_id: { type: "string", required: true, description: "连接 id" },
			action: { type: "string", required: true, enum: ["ls", "read", "write", "delete", "delete-dir", "mkdir", "mv", "copy", "chmod", "touch", "stat", "wget", "roots"], description: "操作" },
			path: { type: "string", description: "目标路径（ls/read/write/delete/mkdir/chmod/touch/stat 用）" },
			b64: { type: "string", description: "write 内容（base64）" },
			from: { type: "string", description: "mv 源路径" },
			to: { type: "string", description: "mv 目标路径 / wget 保存路径" },
			url: { type: "string", description: "wget 远程地址" },
			mode: { type: "string", description: "chmod 八进制（如 755）" },
			epoch: { type: "integer", description: "touch 时间戳（秒）" }
		},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.ok ? (Array.isArray(v.entries) ? `共 ${v.entries.length} 项` : v.b64 ? `读回 ${v.size} 字节（base64 已截断展示省略）` : JSON.stringify(v).slice(0, 4000)) : `操作失败：${v.error}` }] },
		execute(args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, error: g.error });
			return fileCore(args.conn_id, args.action, args).then((r) => ({ ok: true, ...r })).catch((e) => ({ ok: false, error: e?.message ?? String(e) }));
		}
	}));

	ctx.tools.register(defineTool({
		name: "webshell_db",
		description: "webshell 数据库操作（仅授权测试，需 eval 能力通道=PHP eval 马或自研加密马 v2）。action=profile.save/dbs/tables/tableinfo/exec。先 profile.save 存连接档案（type=mysql/pgsql/sqlite/mssql + host/port/username/password/database），再 dbs→tables→exec。",
		parameters: {
			conn_id: { type: "string", required: true, description: "连接 id" },
			action: { type: "string", required: true, enum: ["profile.save", "dbs", "tables", "tableinfo", "exec"], description: "操作" },
			profile_id: { type: "string", description: "数据库档案 id（save 之外必填）" },
			type: { type: "string", enum: ["mysql", "pgsql", "sqlite", "mssql"], description: "引擎类型（save 用）" },
			host: { type: "string", description: "主机（save 用；sqlite 传文件路径到 database）" },
			port: { type: "integer", description: "端口（save 用）" },
			username: { type: "string", description: "用户名（save 用）" },
			password: { type: "string", description: "密码（save 用）" },
			database: { type: "string", description: "库名（save/tables 用）" },
			table: { type: "string", description: "表名（tableinfo 用）" },
			sql: { type: "string", description: "SQL 语句（exec 用；SELECT 回前 200 行）" }
		},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.ok ? JSON.stringify(v).slice(0, 6000) : `数据库操作失败：${v.error}` }] },
		execute(args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, error: g.error });
			return dbCore(args.conn_id, args.action, args).then((r) => ({ ok: true, ...r })).catch((e) => ({ ok: false, error: e?.message ?? String(e) }));
		}
	}));

	ctx.tools.register(defineTool({
		name: "webshell_plugin_list",
		description: "列出已安装的 webshell 载荷插件（声明式清单：名称/语言/通道/参数表单）。用户可用自然语言要求运行某个插件——先看本清单确认参数。",
		parameters: {},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.ok ? v.plugins.map((p) => `${p.name} v${p.version} [${p.type}] ${p.langs.join("/")} 参数：${p.params.map((x) => x.key).join(",") || "无"}`).join("\n") || "（无插件）" : `查询失败：${v.error}` }] },
		execute(_args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, error: g.error });
			return Promise.resolve({ ok: true, ...pluginsCore("list") });
		}
	}));

	ctx.tools.register(defineTool({
		name: "webshell_plugin_run",
		description: "在指定 webshell 连接上运行一个载荷插件（仅授权测试；需 eval 能力通道）。参数表见 webshell_plugin_list。",
		parameters: {
			conn_id: { type: "string", required: true, description: "连接 id" },
			plugin: { type: "string", required: true, description: "插件名" },
			params_json: { type: "string", description: '插件参数 JSON 字符串（如 {"host":"10.0.0.1"}）' }
		},
		output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.ok ? JSON.stringify(v.result).slice(0, 8000) : `插件运行失败：${v.error}` }] },
		execute(args, exec) {
			const g = modeGuard(ctx, exec);
			if (!g.ok) return Promise.resolve({ ok: false, error: g.error });
			let params = {};
			try { params = args.params_json ? JSON.parse(args.params_json) : {}; } catch { return Promise.resolve({ ok: false, error: "params_json 不是合法 JSON" }); }
			return pluginsCore("run", { name: args.plugin, connId: args.conn_id, params }).then((r) => ({ ok: true, result: r.result })).catch((e) => ({ ok: false, error: e?.message ?? String(e) }));
		}
	}));
}

//#endregion

function apply(ctx) {
	const trustedHosts = () => {
		try { return ctx.webRuntime?.trustedHosts ?? []; } catch { return []; }
	};
	ctx.effect(() => ctx.webServer.register({
		kind: "prefix",
		path: ROUTE_PATH,
		handler: async (req, res) => {
			const send = (code, body) => {
				const text = typeof body === "string" ? body : JSON.stringify(body);
				res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
				res.end(text);
			};
			if (!isTrustedRequest(req, trustedHosts())) { res.writeHead(403); res.end("forbidden"); return; }
			if (req.method !== "POST") { res.writeHead(405); res.end("method not allowed"); return; }
			let endpoint = "";
			try { endpoint = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname.slice(ROUTE_PATH.length)).replace(/^\/+/, ""); } catch { endpoint = ""; }
			if (endpoint === "") { res.writeHead(404); res.end("not found"); return; }
			try {
				const raw = await readBody(req);
				const payload = raw === "" ? {} : JSON.parse(raw);
				const result = await dispatch(ctx, theStore(), endpoint, payload);
				send(200, result);
			} catch (e) {
				send(400, { ok: false, error: e?.message ?? String(e) });
			}
		}
	}), "dsh-webshell-mgr: web route");
	registerTools(ctx);
}

export { apply, inject, name, ROUTE_PATH, DB_PATH, BASE_DIR, ALLOWED_MODES };
