// dsh-campaign-memory — 战役记忆宿主插件（九模式）。
//
// 三件事：
//   1) 沉淀：模型侧 campaign_memory_write 随战随记（存储原文不脱敏——内网地址/指纹细节是打法价值所在，凭据同样原样入库）；
//   2) 召回：campaign_memory_search 检索预览不记账，campaign_memory_get 读全文即记账
//      （usage/last_used 是热度排序的唯一驱动——排序=热度×30 天半衰，久未读取自然让位）；
//      装配期把该模式本工作区高频记忆注入上下文（<dsh-campaign-memory> 标记块）；
//   3) 治理：detect 默认 30 天过期并自动清理；fingerprint 默认 180 天——到期退出自动召回、
//      检索仍可命中带过期标记、同题重写即刷新；同模式同工作区同题写入=刷新不重复；
//      Web 标签页「战役记忆」浏览/检索/删除，loopback RPC 同源栅栏。
//
// 记忆是模式作用域的跨会话资产：渗透的目标指纹打法、攻防的环境突破序、代审的框架 sink、
// 免杀的过检指纹、IR 的家族模式、云的账号提权路径、CTF 的题型解法、二进制的家族特征。

import path from "node:path";
import crypto from "node:crypto";
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
/** 进程级 CSRF token：GET <route>/csrf 由同源页取走（跨源响应不可读），POST 须回带 x-dsh-csrf 头。 */
const CSRF_TOKEN = crypto.randomBytes(24).toString("hex");
export function checkCsrf(req, token) {
	return String(req?.headers?.["x-dsh-csrf"] ?? "") === String(token ?? "");
}
const MAX_BODY = 1024 * 1024;

let store;
function theStore() {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}

//#region 召回注入块（纯函数，供测试）

const INJECT_TAG = "dsh-campaign-memory";
const INJECT_BUDGET = 700;

/** 装配期召回块：标记化（压缩后可识别）、预算内（超限先减记忆行——数据让位，指引行最后丢；
 *  n 属性随实留行数重建）。确定性：同库状态同文。 */
export function buildMemoryBlock(mode, workspace, rows) {
	if (!rows || rows.length === 0) return "";
	const close = `</${INJECT_TAG}>`;
	const guide = "沉淀/检索：有效打法即时 campaign_memory_write 记忆（正文原样入库不脱敏——凭据可入库或只写指位指向本地凭据库）；开战/接案或换目标类型先 campaign_memory_search 检索。";
	const build = (kept) => {
		const kinds = [...new Set(kept.map((r) => r.targetKind).filter(Boolean))];
		const topicLine = kinds.length > 1 ? `本工作区记忆含多目标（${kinds.slice(0, 4).join("/")}${kinds.length > 4 ? " 等" : ""}）——适用性按目标自判，检索可加 target_kind 过滤。` : "";
		return [
			`<${INJECT_TAG} mode="${mode}" workspace="${workspace}" n="${kept.length}">`,
			"本工作区战役记忆（历史战役沉淀；适用性自判——目标环境可能已变化）：",
			...kept.map((r, i) => `${i + 1}. [${kindLabel(r.kind)}${r.targetKind ? "·" + r.targetKind : ""}] ${r.title}——${String(r.content).split("\n")[0].slice(0, 160)}`),
			...(topicLine ? [topicLine] : []),
			guide
		].join("\n") + "\n" + close;
	};
	let kept = rows.slice();
	let text = build(kept);
	while (kept.length > 0 && text.length > INJECT_BUDGET) {
		kept = kept.slice(0, -1);
		text = build(kept);
	}
	if (text.length > INJECT_BUDGET) {
		const tail = "…\n" + close; // 兜底（固定行极端超限）：硬截到预算内，截点在闭合标签前
		text = text.slice(0, INJECT_BUDGET - tail.length) + tail;
	}
	return text;
}

//#endregion

/** 工作区标识：name=目录 basename（展示与旧库兼容），key=basename@全路径哈希 8 位（隔离键——
 *  同名目录不串场、移动/改名目录=新 key 干净开局，旧记忆仍可跨工作区检索找回）。cwd 缺失时
 *  key=""（回落 basename 旧语义，注入只匹配无键行）。 */
function workspaceOf(agent) {
	const cwd = agent?.session?.header?.cwd;
	if (typeof cwd !== "string" || !cwd) return { name: "", key: "" };
	const base = path.basename(cwd).slice(0, 60);
	return { name: base, key: base + "@" + crypto.createHash("sha256").update(cwd).digest("hex").slice(0, 8) };
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
			if (originUrl.host !== hostUrl.host) return false; // 含端口：本机他端口页面的 Origin 不放行
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
		return { memories: listMemories(st, { mode, kind: p.kind ? String(p.kind) : "", includeExpired: !!p.includeExpired, limit: p.limit }) };
	}
	if (endpoint === "memory.search") {
		const mode = String(p.mode ?? "");
		if (!mode) throw new Error("mode required");
		return { memories: searchMemories(st, { mode, query: p.query, kind: p.kind, target_kind: p.target_kind, limit: p.limit }) };
	}
	if (endpoint === "memory.get") {
		const m = getMemory(st, String(p.id ?? ""), { account: !p.peek }); // peek=纯浏览不记账（Web 标签页展开全文）
		if (!m) throw new Error(`记忆不存在：${p.id}`);
		return { memory: m };
	}
	if (endpoint === "memory.write") {
		const m = writeMemory(st, { mode: p.mode, kind: p.kind, title: p.title, content: p.content, tags: p.tags, target_kind: p.target_kind, expires_days: p.expires_days, source_session: p.sessionId, workspace: p.workspace, workspace_key: p.workspaceKey });
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
				const ws = workspaceOf(agent);
				return buildMemoryBlock(presetId, ws.name, topForInjection(theStore(), presetId, ws.name, 3, ws.key));
			} catch { return ""; }
		}
	});
	//#endregion

	//#region 模型工具（宿主平面；九模式会话内可用）
	ctx.tools.register(defineTool({
		name: "campaign_memory_write",
		description: "把本次战役中验证有效的打法/目标指纹/工具可用性/教训/检测指纹沉淀为战役记忆（跨会话长期复用）。存储原文不做脱敏——内网地址/指纹细节/凭据均原样入库（记忆库是本地库）；已有独立凭据库（hunter key 库/webshell 连接库等）时也可只写指位（存哪、叫什么）。同模式同工作区同题写入=刷新既有记忆（正文与时效更新、热度保留，不产生重复——复用标题即可更新）。kind：tactic 战术打法 / fingerprint 目标指纹（默认 180 天时效，到期退出自动召回、检索仍可命中带过期标记，同题重写即刷新；代审的框架 sink 特征归此档）/ tooling 工具可用性（代审的 semgrep 规则集调优结论归此档）/ lesson 教训 / detect 检测指纹（默认 30 天过期并清理，可 expires_days 覆盖）。本模式作战记忆以本工具为准沉淀；用户偏好/环境事实等通用记忆（如有其他记忆工具）不在此沉淀。有效即可记，不必等收口。同模式同工作区上限 400 条，超限自动冷淘汰（热度×半衰最旧让位）；同目录多目标（多云厂商/多样本/多题）时 target_kind 填目标标识（厂商名/样本哈希前 8 位/平台名）——召回注入按目标标注，适用性按目标自判。CTF：题解套路与非预期解→tactic、工具配方（完整命令行/参数）→tooling、卡点教训→lesson；开赛/换题型先检索；同名题跨平台/赛事以 target_kind=平台名区分（同题同平台才刷新，不互覆）。应急溯源：排查配方与处置手法→tactic、家族/威胁指纹→fingerprint、取证工具可用性→tooling、检测规则时效情报→detect、复盘教训→lesson；接案/换案件先检索；多案件同目录以 target_kind=案件号区分。",
		parameters: {
			title: { type: "string", required: true, description: "一句话标题（如：XX 框架后台默认凭据直连）；同题同 target_kind 即刷新而非新增（跨平台同名题不互覆）" },
			content: { type: "string", required: true, description: "打法/事实正文（怎么做的、命中条件、关键参数；原样入库不做脱敏——凭据/密钥也原样存储）" },
			kind: { type: "string", required: true, enum: MEMORY_KINDS, description: "记忆类别" },
			tags: { type: "string", description: "检索标签（逗号分隔，如：java,后台,弱口令）" },
				target_kind: { type: "string", description: "适用目标形态（web/api/域环境/家族名/案件号等，召回过滤用）" },
			expires_days: { type: "number", description: "有效期天数（省略时 detect=30 天、fingerprint=180 天，其余永久）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `记忆已${v.refreshed ? "刷新" : "沉淀"}：${v.id}${v.expires_at ? "（" + v.expires_at + " 过期）" : ""}${v.evicted ? `（本工作区超上限，冷淘汰 ${v.evicted} 条）` : ""}` : `沉淀失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				const ws = workspaceOf(exec?.agent);
				const m = writeMemory(theStore(), { mode: session.mode, kind: args.kind, title: args.title, content: args.content, tags: args.tags, target_kind: args.target_kind, expires_days: args.expires_days, source_session: session.id, workspace: ws.name, workspace_key: ws.key });
				return Promise.resolve({ ok: true, id: m.id, expires_at: m.expires_at, refreshed: m.refreshed, evicted: m.evicted });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "campaign_memory_search",
		description: "检索本模式战役记忆（开战或换目标类型时先查——历史打法可能直接给出可复用路径；本模式作战记忆以本工具为准，通用记忆检索不作前置）。跨工作区检索：全部工作区的同模式记忆都可命中，每行带 workspace 来源标注——跨客户/项目经验复用是显式动作。按热度排序（使用频次×30 天时间衰减，久未读取自然让位）；命中不记账，campaign_memory_get 读全文即记账并复活热度；已过期目标指纹仍可命中（带过期标记）。行内为正文预览，全文经 campaign_memory_get 按需读取。返回为空说明该方向没有历史沉淀。",
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
		description: "读取一条战役记忆全文（检索/list 返回的是正文预览，需要完整打法细节时按 id 取全文）。读取即计入热度（usage/last_used 刷新）——驱动自动召回排序，被采用的历史打法读完即复活。",
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
			try {
				const m = getMemory(theStore(), args.id);
				return Promise.resolve(m ? { ok: true, memory: m } : { ok: false, error: `记忆不存在：${args.id}` });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "campaign_memory_list",
		description: "列出本模式当前有效战役记忆（收口复盘与记忆治理用；按热度排序取前列——默认 50 条、上限 200，需要更多用检索收窄）。",
		parameters: { kind: { type: "string", enum: MEMORY_KINDS, description: "限定类别（可选）" }, limit: { type: "number", description: "返回条数（默认 50，上限 200）" } },
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `本模式战役记忆 ${v.memories.length} 条` : `读取失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅安全模式会话内可用" });
			try {
				return Promise.resolve({ ok: true, memories: listMemories(theStore(), { mode: session.mode, kind: args.kind, limit: args.limit }) });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
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
			let csrfPath = "";
			try { csrfPath = new URL(req.url ?? "/", "http://x").pathname; } catch { csrfPath = ""; }
			if (req.method === "GET" && csrfPath === ROUTE_PATH + "/csrf") { send(200, { token: CSRF_TOKEN }); return; }
			if (req.method !== "POST") { res.writeHead(405); res.end("method not allowed"); return; }
			if (!checkCsrf(req, CSRF_TOKEN)) { res.writeHead(403); res.end("csrf token missing or invalid"); return; }
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
