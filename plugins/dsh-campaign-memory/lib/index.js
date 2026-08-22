// dsh-campaign-memory — 战役记忆宿主插件（九模式）。
//
// 三件事：
//   1) 沉淀：模型侧 campaign_memory_write 随战随记（写入即脱敏：凭据/令牌替换、内网 IP 掩末位）；
//   2) 召回：campaign_memory_search 检索即记账（usage 排序）；装配期把该模式高频记忆注入
//      上下文（<dsh-campaign-memory> 标记块，与 route-boost 信封同款的压缩存活标记）；
//   3) 治理：检测指纹类默认 30 天过期（免杀情报半衰期），过期自动退出召回；Web 标签页
//      「战役记忆」浏览/检索/删除，loopback RPC 同源栅栏。
//
// 记忆是模式作用域的跨会话资产：渗透的目标指纹打法、攻防的环境突破序、代审的框架 sink、
// 免杀的过检指纹、IR 的家族模式、云的账号提权路径、CTF 的题型解法、二进制的家族特征。

import path from "node:path";
import os from "node:os";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { openStore, writeMemory, searchMemories, topForInjection, listMemories, getMemory, removeMemory, statsMemories, purgeExpired, kindLabel, MEMORY_KINDS } from "./store.js";

const name = "dsh-campaign-memory";
const inject = ["tools", "webServer", "webRuntime", "agentPresets", "systemPrompt"];

export const MODE_IDS = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];
const MODE_LABELS = {
	redteam: "安全研究员", pentest: "渗透测试", "code-audit": "代码审计", "binary-analysis": "二进制分析",
	"attack-defense": "攻防评估", "av-evasion": "免杀对抗", "incident-response": "应急溯源", "cloud-security": "云安全攻防", "ctf-solver": "CTF 解题"
};
const DB_PATH = path.join(os.homedir(), ".dsh", "campaign-memory", "memory.db");
const ROUTE_PATH = "/dsh-campaign-memory";
const MAX_BODY = 1024 * 1024;

let store;
function theStore() {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}

//#region 召回注入块（纯函数，供测试）

const INJECT_TAG = "dsh-campaign-memory";
const INJECT_BUDGET = 700;

/** 装配期召回块：标记化（压缩后可识别）、预算内（超限截到整行）。确定性：同库状态同文。 */
export function buildMemoryBlock(mode, workspace, rows) {
	if (!rows || rows.length === 0) return "";
	const lines = [`<${INJECT_TAG} mode="${mode}" workspace="${workspace}" n="${rows.length}">`, `本工作区战役记忆（历史战役沉淀；适用性自判——目标环境可能已变化）：`];
	rows.forEach((r, i) => {
		const brief = String(r.content).split("\n")[0].slice(0, 90);
		lines.push(`${i + 1}. [${kindLabel(r.kind)}${r.targetKind ? "·" + r.targetKind : ""}] ${r.title}——${brief}`);
	});
	lines.push("沉淀/检索：有效打法即时 campaign_memory_write 记忆（凭据不入记忆——存本地凭据库，记忆只写指位）；开战或换目标类型先 campaign_memory_search 检索。");
	lines.push(`</${INJECT_TAG}>`);
	let text = lines.join("\n");
	if (text.length > INJECT_BUDGET) {
		while (lines.length > 3 && text.length > INJECT_BUDGET) {
			lines.splice(lines.length - 2, 1);
			text = lines.join("\n");
		}
		text = text.slice(0, INJECT_BUDGET - 1) + "…\n</" + INJECT_TAG + ">";
	}
	return text;
}

//#endregion

function workspaceOf(agent) {
	const cwd = agent?.session?.header?.cwd;
	const base = typeof cwd === "string" && cwd ? path.basename(cwd) : "";
	return base.slice(0, 60);
}

function sessionOf(ctx, exec) {
	const agent = exec?.agent;
	const id = agent?.session?.id;
	if (!id) return undefined;
	let preset;
	try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
	if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
	return { id: String(id), mode: MODE_IDS.includes(preset) ? preset : undefined };
}

//#region HTTP 通道（自注册路由 + 同源信任栅栏）

function hostOf(headers) {
	const h = headers?.host;
	return typeof h === "string" ? h : "";
}
function isLoopbackHostname(hostname) {
	if (hostname === "localhost" || hostname === "[::1]") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}
export function isTrustedRequest(req, trustedHosts) {
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

/** 通道端点分发（纯逻辑，供路由与测试复用）。 */
export async function dispatch(ctx, st, endpoint, payload) {
	const p = payload ?? {};
	if (endpoint === "memory.list") {
		const mode = String(p.mode ?? "");
		if (!mode) throw new Error("mode required");
		return { memories: listMemories(st, { mode, kind: p.kind ? String(p.kind) : "", includeExpired: !!p.includeExpired }) };
	}
	if (endpoint === "memory.search") {
		const mode = String(p.mode ?? "");
		if (!mode) throw new Error("mode required");
		return { memories: searchMemories(st, { mode, query: p.query, kind: p.kind, target_kind: p.target_kind, limit: p.limit }) };
	}
	if (endpoint === "memory.get") {
		const m = getMemory(st, String(p.id ?? ""));
		if (!m) throw new Error(`记忆不存在：${p.id}`);
		return { memory: m };
	}
	if (endpoint === "memory.write") {
		const m = writeMemory(st, { mode: p.mode, kind: p.kind, title: p.title, content: p.content, tags: p.tags, target_kind: p.target_kind, expires_days: p.expires_days, source_session: p.sessionId, workspace: p.workspace });
		return { ok: true, ...m };
	}
	if (endpoint === "memory.remove") {
		return { ok: true, ...removeMemory(st, String(p.id ?? "")) };
	}
	if (endpoint === "memory.stats") {
		const mode = String(p.mode ?? "");
		if (!mode) throw new Error("mode required");
		return { stats: statsMemories(st, mode) };
	}
	if (endpoint === "memory.purge") {
		return { ok: true, ...purgeExpired(st) };
	}
	throw new Error(`unknown endpoint ${endpoint}`);
}

//#endregion

function apply(ctx) {
	//#region 装配期召回块（systemPrompt 动态上下文：记忆集变化才重新快照）
	ctx.systemPrompt.context({
		name: "campaign-memory",
		order: 600,
		text: (assembly) => {
			const agent = assembly?.agent;
			if (!agent) return "";
			let presetId = "";
			try { presetId = String(ctx.agentPresets.composedPreset(agent.ctx) ?? ""); } catch { /* 组合未就绪 */ }
			if (!MODE_IDS.includes(presetId)) return "";
			try {
				return buildMemoryBlock(presetId, workspaceOf(agent), topForInjection(theStore(), presetId, workspaceOf(agent), 3));
			} catch { return ""; }
		}
	});
	//#endregion

	//#region 模型工具（宿主平面；九模式会话内可用）
	ctx.tools.register(defineTool({
		name: "campaign_memory_write",
		description: "把本次战役中验证有效的打法/目标指纹/工具可用性/教训/检测指纹沉淀为战役记忆（跨会话长期复用）。存储原文不做脱敏——凭据/密钥不入记忆：凭据单独存本地凭据库（hunter key 库/webshell 连接库等），记忆只写指位（存哪、叫什么），需要时从库读。kind：tactic 战术打法 / fingerprint 目标指纹 / tooling 工具可用性 / lesson 教训 / detect 检测指纹（默认 30 天过期，可 expires_days 覆盖）。有效即可记，不必等收口。",
		parameters: {
			title: { type: "string", required: true, description: "一句话标题（如：XX 框架后台默认凭据直连）" },
			content: { type: "string", required: true, description: "打法/事实正文（怎么做的、命中条件、关键参数；凭据类会被脱敏）" },
			kind: { type: "string", required: true, enum: MEMORY_KINDS, description: "记忆类别" },
			tags: { type: "string", description: "检索标签（逗号分隔，如：java,后台,弱口令）" },
			target_kind: { type: "string", description: "适用目标形态（web/api/域环境/家族名等，召回过滤用）" },
			expires_days: { type: "number", description: "有效期天数（省略时 detect=30 天，其余永久）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `记忆已沉淀：${v.id}${v.expires_at ? "（" + v.expires_at + " 过期）" : ""}` : `沉淀失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				const m = writeMemory(theStore(), { mode: session.mode, kind: args.kind, title: args.title, content: args.content, tags: args.tags, target_kind: args.target_kind, expires_days: args.expires_days, source_session: session.id, workspace: workspaceOf(exec?.agent) });
				return Promise.resolve({ ok: true, id: m.id, expires_at: m.expires_at });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "campaign_memory_search",
		description: "检索本模式战役记忆（开战或换目标类型时先查——历史打法可能直接给出可复用路径）。跨工作区检索：全部工作区的同模式记忆都可命中，每行带 workspace 来源标注——跨客户/项目经验复用是显式动作。按使用频次+新近排序，命中自动记账；行内为正文预览，全文经 campaign_memory_get 按需读取。返回为空说明该方向没有历史沉淀。",
		parameters: {
			query: { type: "string", required: true, description: "关键词（标题/正文/标签匹配，如：XX 云台 弱口令）" },
			kind: { type: "string", enum: MEMORY_KINDS, description: "限定类别（可选）" },
			target_kind: { type: "string", description: "限定目标形态（可选）" },
			limit: { type: "number", description: "返回条数（默认 8，上限 20）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `命中 ${v.memories.length} 条战役记忆` : `检索失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				return Promise.resolve({ ok: true, memories: searchMemories(theStore(), { mode: session.mode, query: args.query, kind: args.kind, target_kind: args.target_kind, limit: args.limit }) });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "campaign_memory_get",
		description: "读取一条战役记忆全文（检索/list 返回的是正文预览，需要完整打法细节时按 id 取全文）。",
		parameters: {
			id: { type: "string", required: true, description: "记忆 id（cm- 开头）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `记忆全文：${v.memory.title}` : `读取失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			const m = getMemory(theStore(), args.id);
			return Promise.resolve(m ? { ok: true, memory: m } : { ok: false, error: `记忆不存在：${args.id}` });
		}
	}));

	ctx.tools.register(defineTool({
		name: "campaign_memory_list",
		description: "列出本模式当前有效战役记忆（收口复盘与记忆治理用）。",
		parameters: { kind: { type: "string", enum: MEMORY_KINDS, description: "限定类别（可选）" } },
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `本模式战役记忆 ${v.memories.length} 条` : `读取失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			return Promise.resolve({ ok: true, memories: listMemories(theStore(), { mode: session.mode, kind: args.kind }) });
		}
	}));

	ctx.tools.register(defineTool({
		name: "campaign_memory_remove",
		description: "删除一条战役记忆（过时/失效/错误的记忆及时清除，保持记忆库可信）。",
		parameters: { id: { type: "string", required: true, description: "记忆 id（cm- 开头）" } },
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `记忆已删除：${v.removed}` : `删除失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				return Promise.resolve({ ok: true, ...removeMemory(theStore(), args.id) });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));
	//#endregion

	//#region Web 通道路由（自注册 + 同源栅栏）
	const trustedHosts = () => {
		try { return ctx.webRuntime?.trustedHosts ?? []; } catch { return []; }
	};
	ctx.effect(() => ctx.webServer.register({
		kind: "prefix",
		path: ROUTE_PATH,
		handler: async (req, res) => {
			const send = (code, body) => {
				const text = JSON.stringify(body);
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
	}), "dsh-campaign-memory: web route");
	//#endregion
}

export { MODE_LABELS, MEMORY_KINDS, kindLabel, ROUTE_PATH, apply, inject, name, openStore };

//#endregion
