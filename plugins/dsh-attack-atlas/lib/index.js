// dsh-attack-atlas — 攻击面图谱宿主插件。
//
// 三件事：
//   1) 类目体系：lib/taxonomy.js 纯数据（八专业模式全量，结构=战场分区×战术列×形态×阶段）；
//   2) 覆盖态：模型侧 redteam_coverage_mark / redteam_coverage_stage / redteam_coverage_list
//      回写终态（会话 × 模式隔离），SQLite 落 ~/.dsh/attack-atlas/atlas.db；
//   3) Web 通道：webServer 自注册 /dsh-attack-atlas 前缀路由 + 同源信任栅栏；
//      会话标签页「攻击面图谱」读体系/读覆盖态/双击派单（followup 进当前会话）。
//
// 派单语义：双击格子/主类/阶段 = 把一条用户消息注入当前会话，模型按 playbook
// 对应章节开测，完成后经 redteam_coverage_mark 回写点亮——图谱即覆盖度参考标准。

import path from "node:path";
import os from "node:os";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { openStore, markCell, markStage, getCoverage, clearCoverage, addTarget, listTargets, removeTarget, addChainNode, addChainEdge, listChain, clearChain, CHAIN_NODE_KINDS, chainKindLabel, CELL_STATES, STAGE_STATES, TARGET_KINDS, targetKindLabel } from "./store.js";
import { TAXONOMIES, ATLAS_MODES, locate } from "./taxonomy.js";

const name = "dsh-attack-atlas";
const inject = ["tools", "webServer", "webRuntime", "agentPresets"];

const ROUTE_PATH = "/dsh-attack-atlas";
const MODE_LABELS = {
	pentest: "渗透测试模式",
	"code-audit": "代码审计模式",
	"binary-analysis": "二进制分析模式",
	"attack-defense": "攻防评估模式",
	"av-evasion": "免杀对抗模式",
	"incident-response": "应急溯源模式",
	"cloud-security": "云安全攻防模式",
	"ctf-solver": "CTF 解题模式"
};
const DB_PATH = path.join(os.homedir(), ".dsh", "attack-atlas", "atlas.db");
const MAX_BODY = 1024 * 1024;

let store;
function theStore() {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}

//#region 通道与工具共用逻辑

/** 双击派单的注入文案（用户消息；模型按 playbook 对应章节执行并回写点亮）。 */
function anchorLines(targets) {
	if (!targets || targets.length === 0) {
		return "目标锚定：本会话尚未登记目标——开测前先确认授权目标并调 redteam_atlas_target 登记（与资产清单基线 assets.md 同步），严格不超出授权范围。";
	}
	const list = targets.map((t, i) => `「${t.label}」${targetKindLabel(t.kind)}`).join("、");
	return `目标锚定：${list}（资产明细见 assets.md/入口面盘点表；多目标时终态回写须带 target 参数注明所属目标，N-A 须注明对哪个目标不具备）。`;
}
export function triggerMessage(taxonomy, payload) {
	const formLabel = payload.formId && payload.formId !== "all"
		? `｜形态「${(taxonomy.forms.find((f) => f.id === payload.formId) || {}).label || payload.formId}」` : "";
	if (payload.level === "chain-gen") {
		return [
			"[AttackAtlas·链路拓扑生成] 请依据本会话整体上下文（evidence-index 攻击图 links、已获权限/凭据、突破路径）登记攻击链拓扑：",
			`① redteam_atlas_chain add-node 逐个登记节点（kind：${Object.entries(taxonomy.chainKinds || {}).map(([id, m]) => id + " " + m.label).join("/") || "entry 入口/host 主机/segment 网段关口/bastion 堡垒机/dc 域控/cred 凭据"}；重大成果节点 major=true；seg 填网段如 10.1.1.x）`,
			"② add-edge 登记边（label：获取权限/凭据复用/隔离突破/密码抓取/域控获取…）；多入口/无拓扑按实际登记，不虚构。",
			"登记即自动成图（「链路拓扑图」弹窗实时刷新）。"
		].join("\n");
	}
	if (payload.level === "stage") {
		const stage = taxonomy.stages.find((s) => s.id === payload.stageId);
		return [
			`[AttackAtlas·阶段推进] 进入阶段「${stage ? stage.label : payload.stageId}」（${taxonomy.label}模式作战流程）。`,
			`按 playbook 该阶段章节执行；完成后调用 redteam_coverage_stage(stage="${payload.stageId}", state="done") 回写点亮。`,
			anchorLines(payload.targets)
		].join("\n");
	}
	if (payload.level === "category") {
		const category = taxonomy.categories.find((c) => c.id === payload.categoryId);
		return [
			`[AttackAtlas·主类派单] 对主类「${category ? category.label : payload.categoryId}」整组开测（${taxonomy.label}模式${formLabel}）。`,
			"要求：子项逐格推进，每格终态三选一（已测·未命中 / 已测·有发现 / N-A 附原因），逐格调用 redteam_coverage_mark 回写；发现即 redteam_finding_register 登记；速率与红线照 playbook 执行。",
			anchorLines(payload.targets)
		].join("\n");
	}
	const loc = locate(taxonomy, `${payload.categoryId}/${payload.itemId}`);
	const category = loc?.category;
	const item = loc?.item;
	let refHint = "";
	if (item?.ref) refHint = item.ref.startsWith("pentest:") ? `\n知识手册：pentest refs/${item.ref.slice(8)}（开测前先读对应验证姿势）` : `\n知识手册：refs/${item.ref}（开测前先读对应验证姿势）`;
	else if (item?.pb) refHint = `\n打法出处：本模式 playbook ${item.pb}`;
	return [
		`[AttackAtlas·格子派单] 对以下格子开测（${taxonomy.label}模式${formLabel}）：`,
		`主类「${category ? category.label : payload.categoryId}」｜子项「${item ? item.label : payload.itemId}」${refHint}`,
		"按 playbook 验证姿势执行（最小影响、非破坏性）；终态三选一（已测·未命中 / 已测·有发现 / N-A 附原因），完成后调用 redteam_coverage_mark 回写点亮；有发现即 redteam_finding_register 登记。",
		anchorLines(payload.targets)
	].join("\n");
}

function sessionOf(ctx, exec) {
	const agent = exec?.agent;
	const id = agent?.session?.id;
	if (!id) return undefined;
	let preset;
	try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
	if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
	return { id: String(id), mode: ATLAS_MODES.includes(preset) ? preset : undefined };
}

function resolveAgents(ctx) {
	try { return ctx.get("agents"); } catch { /* 该 fiber 未声明 agents */ }
	try { return ctx.agents; } catch { /* 同上 */ }
	return undefined;
}

//#endregion

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
	if (endpoint === "taxonomy.get") {
		return {
			modes: ATLAS_MODES.map((m) => ({ id: m, label: MODE_LABELS[m], pending: !!TAXONOMIES[m]?.pending })),
			taxonomies: TAXONOMIES
		};
	}
	if (endpoint === "session.mode") {
		// 会话真实模式的权威源：agents 注册表 → composedPreset（列表源重启后可能退化为组合名）。
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const agents = resolveAgents(ctx);
		const agent = agents?.get?.(sessionId);
		let mode = "";
		try { mode = String(ctx.agentPresets?.composedPreset?.(agent.ctx) ?? ""); } catch { /* 组合未就绪 */ }
		if (!ATLAS_MODES.includes(mode)) {
			const header = agent?.session?.header?.agentPreset;
			mode = ATLAS_MODES.includes(header) ? header : "";
		}
		return { mode };
	}
	if (endpoint === "coverage.get") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return getCoverage(st, sessionId, String(p.mode ?? "pentest"));
	}
	if (endpoint === "coverage.mark") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const cell = markCell(st, sessionId, String(p.mode ?? "pentest"), String(p.key ?? ""), {
			state: String(p.state ?? ""), reason: p.reason, findingRefs: p.findingRefs, target: p.target
		});
		return { ok: true, cell };
	}
	if (endpoint === "stage.mark") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, stage: markStage(st, sessionId, String(p.mode ?? "pentest"), String(p.stage ?? ""), String(p.state ?? "")) };
	}
	if (endpoint === "coverage.clear") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, ...clearCoverage(st, sessionId, String(p.mode ?? "pentest"), p.key ? String(p.key) : "") };
	}
	if (endpoint === "targets.add") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, target: addTarget(st, sessionId, String(p.mode ?? "pentest"), { label: String(p.label ?? ""), kind: String(p.kind ?? "other"), note: p.note }) };
	}
	if (endpoint === "targets.list") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { targets: listTargets(st, sessionId, String(p.mode ?? "pentest")) };
	}
	if (endpoint === "targets.remove") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, ...removeTarget(st, sessionId, String(p.mode ?? "pentest"), p.seq) };
	}
	if (endpoint === "chain.node") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, node: addChainNode(st, sessionId, String(p.mode ?? "pentest"), { id: p.id, label: p.label, kind: p.kind, seg: p.seg, note: p.note, major: !!p.major }) };
	}
	if (endpoint === "chain.edge") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, edge: addChainEdge(st, sessionId, String(p.mode ?? "pentest"), { src: p.src, dst: p.dst, label: p.label }) };
	}
	if (endpoint === "chain.list") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return listChain(st, sessionId, String(p.mode ?? "pentest"));
	}
	if (endpoint === "chain.clear") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, ...clearChain(st, sessionId, String(p.mode ?? "pentest")) };
	}
	if (endpoint === "atlas.trigger") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const mode = String(p.mode ?? "pentest");
		const taxonomy = TAXONOMIES[mode];
		if (!taxonomy || taxonomy.pending) return { ok: false, error: `模式 ${mode} 的体系编排中，暂不可派单` };
		const agents = resolveAgents(ctx);
		const agent = agents?.get?.(sessionId);
		if (!agent || typeof agent.followup !== "function") return { ok: false, unreachable: true, error: "会话不可达（会话可能已删除或代理未运行）" };
		agent.followup({
			id: `atlas-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
			content: [{ type: "text", text: triggerMessage(taxonomy, { ...p, targets: listTargets(st, sessionId, mode) }) }],
			source: { kind: "user" }
		});
		return { ok: true };
	}
	throw new Error(`unknown endpoint ${endpoint}`);
}

//#endregion

//#region host wiring

function apply(ctx) {
	//#region 模型工具（宿主平面；九模式会话内可用）
	ctx.tools.register(defineTool({
		name: "redteam_coverage_mark",
		description: "把攻击面图谱（「攻击面图谱」标签页）里的一个格子或主类标为终态。每个格子终态三选一：已测·有发现(tested-found) / 已测·未命中(tested-clear) / N-A附原因(na)；预算耗尽用 budget-stop（附原因）。key 形如 injection/sqli（格子）或 injection（主类整组 N-A）。tested-clear 时 reason 建议写未排除面；tested-found 时 findingRefs 填关联 finding id。逐格回写，图谱实时点亮。",
		parameters: {
			key: { type: "string", required: true, description: "cat/item 格子 key 或 cat 主类 key" },
			state: { type: "string", required: true, enum: CELL_STATES, description: "终态" },
			reason: { type: "string", description: "原因（na/budget-stop 必填；tested-clear 建议写未排除面）" },
			findingRefs: { type: "string", description: "关联 finding id（逗号分隔）" },
			target: { type: "string", description: "该终态所属目标（多目标会话必须注明；单目标可不填自动归属）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `图谱已点亮：${v.key} → ${v.state}` : `点亮失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用（当前会话未挂专业模式）" });
			try {
				const cell = markCell(theStore(), session.id, session.mode, args.key, { state: args.state, reason: args.reason, findingRefs: args.findingRefs, target: args.target });
				return Promise.resolve({ ok: true, key: cell.key, state: cell.state });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_coverage_stage",
		description: "推进攻击面图谱顶部的作战流程带：进入某阶段标 active、完成标 done。stage 取当前模式体系的阶段 id（渗透模式为 s0-s6：防护画像/被动收集/入口面盘点/登陆口专线/逐面挖掘/验证与影响证明/收口）。",
		parameters: {
			stage: { type: "string", required: true, description: "阶段 id" },
			state: { type: "string", required: true, enum: STAGE_STATES, description: "active=进行中 done=完成" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `阶段已点亮：${v.stage} → ${v.state}` : `阶段点亮失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			try {
				const stage = markStage(theStore(), session.id, session.mode, args.stage, args.state);
				return Promise.resolve({ ok: true, stage: stage.stage, state: stage.state });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_coverage_list",
		description: "读取本会话攻击面图谱的全部覆盖终态（格子+阶段），复核员抽查与收口核对用。",
		parameters: {},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `本会话图谱终态：${v.cells.length} 格 / ${v.stages.length} 阶段` : `读取失败：${v.error}` }]
		},
		execute(_args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			const cov = getCoverage(theStore(), session.id, session.mode);
			return Promise.resolve({ ok: true, cells: cov.cells, stages: cov.stages });
		}
	}));
	ctx.tools.register(defineTool({
		name: "redteam_atlas_target",
		description: "登记/查看本会话 AttackAtlas 的作战目标（与资产清单基线 assets.md 同步维护；入口面盘点发现的每个资产均登记）。目标登记后：图谱头部目标带展示、双击派单自动带目标锚定、覆盖终态回写可逐目标溯源——这是防目标漂移的锚。kind 取 domain/web/ip/api/miniprogram/android/ios/desktop/component/cloud/ai/other。",
		parameters: {
			action: { type: "string", required: true, enum: ["add", "list", "remove"], description: "add=登记 list=列出 remove=删除" },
			label: { type: "string", description: "目标标识（域名/ip:port/应用名），action=add 必填" },
			kind: { type: "string", enum: TARGET_KINDS, description: "目标形态" },
			note: { type: "string", description: "备注（入口/授权范围片段）" },
			seq: { type: "number", description: "action=remove 时的序号" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? (v.targets ? `本会话目标 ${v.targets.length} 个：${v.targets.map((t) => t.label).join("、")}` : `目标已登记：${v.label}（${v.kindLabel}）`) : `目标操作失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			try {
				if (args.action === "list") return Promise.resolve({ ok: true, targets: listTargets(theStore(), session.id, session.mode) });
				if (args.action === "remove") { removeTarget(theStore(), session.id, session.mode, args.seq); return Promise.resolve({ ok: true, removed: args.seq }); }
				const t = addTarget(theStore(), session.id, session.mode, { label: args.label, kind: args.kind, note: args.note });
				return Promise.resolve({ ok: true, label: t.label, kind: t.kind, kindLabel: targetKindLabel(t.kind), seq: t.seq });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_atlas_chain",
		description: "登记/查看本会话 AttackAtlas 的攻击链拓扑（链路拓扑图弹窗实时成图）。节点：entry 入口/host 主机/segment 网段关口/bastion 堡垒机/dc 域控/cred 凭据，重大成果节点 major=true，seg 填网段（如 10.1.1.x）；边 label 写动作（获取权限/凭据复用/隔离突破/域控获取…）。多入口/暂无链路按实际登记，不虚构。突破成立、拿下一台主机、跨段、拿到关键凭据时即登记——链路拓扑随战役推进实时生长。",
		parameters: {
			action: { type: "string", required: true, enum: ["add-node", "add-edge", "list", "clear"], description: "add-node=登记节点 add-edge=登记边 list=查看 clear=清空" },
			id: { type: "string", description: "节点 id（字母数字与 ._-，如 h-192-168-1-2；action=add-node 必填）" },
			label: { type: "string", description: "节点显示名（域名/ip/凭据名）" },
			kind: { type: "string", enum: CHAIN_NODE_KINDS, description: "节点类型" },
			seg: { type: "string", description: "所属网段（如 10.1.1.x）" },
			note: { type: "string", description: "备注（拿到什么权限/凭据名）" },
			major: { type: "boolean", description: "重大成果节点（堡垒机/域控/全域权限等）" },
			src: { type: "string", description: "边起点节点 id（action=add-edge 必填）" },
			dst: { type: "string", description: "边终点节点 id" },
			edgeLabel: { type: "string", description: "边动作标签（获取权限/凭据复用/隔离突破…）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? (v.chain ? `链路拓扑：${v.chain.nodes.length} 节点 / ${v.chain.edges.length} 边` : `已登记：${v.what}`) : `链路登记失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			try {
				if (args.action === "list") return Promise.resolve({ ok: true, chain: listChain(theStore(), session.id, session.mode) });
				if (args.action === "clear") { clearChain(theStore(), session.id, session.mode); return Promise.resolve({ ok: true, what: "链路已清空" }); }
				if (args.action === "add-node") { const n = addChainNode(theStore(), session.id, session.mode, { id: args.id, label: args.label, kind: args.kind, seg: args.seg, note: args.note, major: args.major }); return Promise.resolve({ ok: true, what: `节点 ${n.label}（${chainKindLabel(n.kind)}${n.major ? "·重大" : ""}）` }); }
				const e = addChainEdge(theStore(), session.id, session.mode, { src: args.src, dst: args.dst, label: args.edgeLabel });
				return Promise.resolve({ ok: true, what: `边 ${e.src} → ${e.dst}${e.label ? "（" + e.label + "）" : ""}` });
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
	}), "dsh-attack-atlas: web route");
	//#endregion
}

export { ATLAS_MODES, MODE_LABELS, CELL_STATES, STAGE_STATES, ROUTE_PATH, apply, inject, name, openStore };

//#endregion
