// dsh-attack-atlas method — 自定义工作方法论纯逻辑层。
//
// 方法论模板 = 命名有向图：节点 = 主类/子项模块（ref 与覆盖格子 key 同构：cat 或 cat/item），
// 边 = 衔接（执行先后约束）。三层职责：
//   1) validateMethod —— 结构错误（拒绝保存）与闭环警告（询问用户）分离；
//   2) layerMethod —— 拓扑分层（同层可并行，上层未完成不进下层）；环内节点归「循环段」按序执行一轮；
//   3) methodRunMessage —— 运行信封：目标锚定 + 辅助需求 + 分层步骤序列 + 知识手册锚点。
// 体系演进兼容：模板引用的 ref 运行时失配 → 降级为纯标签步骤（不崩、不静默丢失）。

import { locate } from "./taxonomy.js";

export const METHOD_LIMITS = {
	name: 40,
	label: 60,
	note: 200,
	notes: 2000,
	target: 120,
	nodes: 60,
	edges: 120,
	graphBytes: 64 * 1024,
	perMode: 50,
	importBatch: 100
};

const NODE_ID_RE = /^[a-z0-9][a-z0-9-]{0,19}$/;
const REF_RE = /^[a-z0-9-]+(\/[a-z0-9-]+)?$/;
const TOOL_RE = /^[\w][\w@/.:-]{0,49}$/;
export const NODE_TYPES = ["tax", "tool", "mcp", "custom"];

function cleanStr(v, max) {
	return String(v ?? "").trim().slice(0, max);
}

/** 规范化图数据（容错解析；非法形状交由校验报告，不在此抛错）。 */
export function normalizeGraph(raw) {
	const r = raw ?? {};
	const nodes = Array.isArray(r.nodes) ? r.nodes.map((n) => ({
		id: cleanStr(n?.id, 24),
		ref: cleanStr(n?.ref, 120),
		nt: cleanStr(n?.nt, 10) || "tax",
		tool: cleanStr(n?.tool, 50),
		spec: cleanStr(n?.spec, 200),
		label: cleanStr(n?.label, METHOD_LIMITS.label),
		note: cleanStr(n?.note, METHOD_LIMITS.note),
		x: Number.isFinite(Number(n?.x)) ? Number(n.x) : 0,
		y: Number.isFinite(Number(n?.y)) ? Number(n.y) : 0
	})) : [];
	const edges = Array.isArray(r.edges) ? r.edges.map((e) => ({
		src: cleanStr(e?.src, 24),
		dst: cleanStr(e?.dst, 24)
	})) : [];
	return { nodes, edges };
}

/**
 * 校验方法论：errors = 结构问题（服务端拒绝保存）；warnings = 闭环问题（询问用户，可按现状继续）；
 * hints = 覆盖建议（仅提示）。返回规范化后的 graph 一并带回。
 */
export function validateMethod(name, rawGraph, taxonomy) {
	const errors = [];
	const warnings = [];
	const hints = [];
	const graph = normalizeGraph(rawGraph);
	const nodes = graph.nodes;
	const edges = graph.edges;

	const n = cleanStr(name, METHOD_LIMITS.name);
	if (!n) errors.push("方法论名称必填");
	if (!Array.isArray(rawGraph?.nodes) || nodes.length === 0) errors.push("画布为空——请先从左侧模块库加入至少一个模块");
	if (nodes.length > METHOD_LIMITS.nodes) errors.push(`模块数超上限（${nodes.length} > ${METHOD_LIMITS.nodes}）`);
	if (edges.length > METHOD_LIMITS.edges) errors.push(`衔接数超上限（${edges.length} > ${METHOD_LIMITS.edges}）`);

	const idSet = new Set();
	const labelOf = {};
	const NT_LABEL = { tool: "工具", mcp: "MCP", custom: "自定义工具" };
	for (const node of nodes) {
		if (!NODE_ID_RE.test(node.id)) { errors.push(`模块 id 非法：${node.id || "(空)"}`); continue; }
		if (idSet.has(node.id)) errors.push(`模块 id 重复：${node.id}`);
		idSet.add(node.id);
		labelOf[node.id] = node.label || node.tool || node.ref || node.id;
		if (!NODE_TYPES.includes(node.nt)) errors.push(`非法模块类型：${node.nt || "(空)"}`);
		else if (node.nt === "tax") {
			if (!REF_RE.test(node.ref)) errors.push(`模块引用格式非法：${node.ref || "(空)"}（应为 cat 或 cat/item）`);
		} else if (!TOOL_RE.test(node.tool)) {
			errors.push(`${NT_LABEL[node.nt]}名非法：${node.tool || "(空)"}（字母数字与 @/.:- 组合）`);
		}
	}
	const seenEdge = new Set();
	for (const e of edges) {
		if (!idSet.has(e.src) || !idSet.has(e.dst)) { errors.push(`衔接引用了不存在的模块：${e.src} → ${e.dst}`); continue; }
		if (e.src === e.dst) { errors.push(`衔接指向自身：${labelOf[e.src]}`); continue; }
		const k = e.src + "→" + e.dst;
		if (seenEdge.has(k)) { errors.push(`衔接重复：${labelOf[e.src]} → ${labelOf[e.dst]}`); continue; }
		seenEdge.add(k);
	}
	if (JSON.stringify(graph).length > METHOD_LIMITS.graphBytes) errors.push("图数据超体积上限");

	if (errors.length === 0) {
		// —— 闭环五查（警告级：询问用户，可按现状继续）——
		const hasIn = new Set(edges.map((e) => e.dst));
		const hasOut = new Set(edges.map((e) => e.src));
		const isolated = nodes.filter((node) => !hasIn.has(node.id) && !hasOut.has(node.id));
		if (isolated.length) warnings.push({ kind: "isolated", ids: isolated.map((x) => x.id), msg: `${isolated.length} 个模块未与任何步骤衔接（孤立）：${isolated.map((x) => labelOf[x.id]).join("、")}` });
		if (edges.length > 0) {
			if (nodes.every((node) => hasIn.has(node.id))) warnings.push({ kind: "nostart", ids: [], msg: "全部步骤都有入边——缺少起点（必含循环衔接）" });
			if (nodes.every((node) => hasOut.has(node.id))) warnings.push({ kind: "noend", ids: [], msg: "全部步骤都有出边——缺少收口终点" });
		}
		const layered = layerMethod(graph);
		if (layered.cycle.length) warnings.push({ kind: "cycle", ids: layered.cycle, msg: `存在循环衔接：${layered.cycle.map((id) => labelOf[id]).join("、")}——运行时将按「循环段」顺序执行一轮` });
		const hasAnyStart = nodes.some((node) => !hasIn.has(node.id));
		if (hasAnyStart) {
			const reachable = new Set(layered.layers.flat());
			const unreachable = nodes.filter((node) => !reachable.has(node.id) && !isolated.some((x) => x.id === node.id));
			if (unreachable.length) warnings.push({ kind: "unreachable", ids: unreachable.map((x) => x.id), msg: `从起点不可达（链路断裂）：${unreachable.map((x) => labelOf[x.id]).join("、")}` });
		}

		// —— 覆盖建议（提示级）——
		if (taxonomy?.zones?.length && nodes.length > 1) {
			const covered = new Set();
			for (const node of nodes) {
				if (node.nt !== "tax") continue;
				const loc = locate(taxonomy, node.ref);
				if (loc?.category?.zone) covered.add(loc.category.zone);
			}
			const missed = taxonomy.zones.filter((z) => !covered.has(z.id));
			if (missed.length && covered.size > 0) hints.push(`未覆盖战场：${missed.map((z) => z.label).join("、")}（仅提示，不影响保存与运行）`);
		}
	}
	return { errors, warnings, hints, graph, name: n };
}

/** 拓扑分层：Kahn 逐层取零入度；无法归层的（环内节点）留作 cycle，按出现序执行一轮。 */
export function layerMethod(rawGraph) {
	const graph = normalizeGraph(rawGraph);
	const nodes = graph.nodes;
	const edges = graph.edges.filter((e) => nodes.some((n) => n.id === e.src) && nodes.some((n) => n.id === e.dst));
	const indeg = {};
	const adj = {};
	for (const n of nodes) { indeg[n.id] = 0; adj[n.id] = []; }
	for (const e of edges) { indeg[e.dst] += 1; adj[e.src].push(e.dst); }
	const order = nodes.map((n) => n.id);
	const remaining = new Set(order);
	const layers = [];
	for (;;) {
		const layer = order.filter((id) => remaining.has(id) && indeg[id] === 0);
		if (layer.length === 0) break;
		layers.push(layer);
		for (const id of layer) {
			remaining.delete(id);
			for (const d of adj[id]) if (indeg[d] > 0) indeg[d] -= 1;
		}
	}
	return { layers, cycle: order.filter((id) => remaining.has(id)) };
}

function stepLine(taxonomy, node) {
	const note = node.note ? `｜重点：${node.note}` : "";
	if (node.nt === "tool") return `▸ 工具「${node.tool}」${node.spec ? `｜用途：${node.spec}` : ""}${note}（不可用时降级：同类已有工具优先，其次写脚本等效实现）`;
	if (node.nt === "mcp") return `▸ MCP「${node.tool}」${node.spec ? `｜用途：${node.spec}` : ""}${note}（会话未加载时先询问用户是否启用；拒绝则降级同类工具/脚本）`;
	if (node.nt === "custom") return `▸ 自定义工具「${node.tool}」${node.spec ? `｜要求：${node.spec}` : ""}${note}（不存在时先询问用户是否安装：说明安装方式与影响，批准后才安装；拒绝则降级：同类已有工具优先，其次写脚本等效实现并注明降级）`;
	const loc = locate(taxonomy, node.ref);
	if (!loc) return `▸ 「${node.label || node.ref}」（该步骤在当前图谱体系中已不存在，按标签意图执行）${note}`;
	if (loc.item) {
		let hint = "";
		if (loc.item.ref) {
			const p = loc.item.ref.startsWith("pentest:") ? `pentest refs/${loc.item.ref.slice(8)}` : `refs/${loc.item.ref}`;
			hint = ` —— 知识手册：${p}（开测前先读对应验证姿势）`;
		} else if (loc.item.pb) hint = ` —— 打法出处：本模式 playbook ${loc.item.pb}`;
		else if (loc.item._cap?.template) hint = ` —— 用户自定义打法模板：\n    ${loc.item._cap.template.split("\n").join("\n    ")}`;
		else if (loc.item._cap) hint = " —— 用户自定义步骤（未附模板，按标签意图与会话上下文执行）";
		return `▸ 子项「${loc.item.label}」｜key: ${node.ref}${loc.item._cap ? "（用户自定义）" : ""}${hint}${note}`;
	}
	return `▸ 主类「${loc.category.label}」整组开测｜key: ${node.ref}（${loc.category._cap ? "用户自定义主类·" : ""}子项逐格终态三选一）${note}`;
}

/** 运行信封（用户消息注入当前会话；模型按分层执行并逐项回写点亮）。 */
export function methodRunMessage(taxonomy, method, opts) {
	const layered = layerMethod(method.graph);
	const byId = {};
	for (const n of normalizeGraph(method.graph).nodes) byId[n.id] = n;
	const lines = [
		`[AttackAtlas·自定义方法论运行] 按用户自定义方法论推进本战役（替代默认全流程；速率与红线仍照 playbook 执行）。`,
		`方法论：「${method.name}」（${taxonomy.label}模式）`,
		opts.anchor,
		`辅助需求：${opts.notes ? opts.notes : "（无）"}`,
		"执行纪律：",
		"- 分层执行：同层步骤可并行或自选序，上层未完成不进入下层；",
		`- 每完成一项调 redteam_coverage_mark(key, 终态) 点亮（主类=整组逐格终态三选一（${(taxonomy.stateLabels || {})["tested-found"] || "已测·有发现"} / ${(taxonomy.stateLabels || {})["tested-clear"] || "已测·未命中"} / ${(taxonomy.stateLabels || {}).na || "N-A 附原因"}），子项=单格；自定义模块不进矩阵、终态照记可经 redteam_coverage_list 查）；有发现即 redteam_finding_register 登记；`,
		"- 步骤与目标/形态不适用时按 N-A 附原因回写，不硬凑" + (taxonomy.chain ? "；突破/拿权/跨段等链路事实按 redteam_atlas_chain 登记" : "") + "。",
		"步骤序列："
	];
	if (Object.values(byId).some((n) => n.nt && n.nt !== "tax")) {
		lines.push("- 工具/MCP/自定义工具模块：执行到该步先确认可用（命令存在/MCP 已加载）；不可用时按该步标注的协议处理——自定义工具必须先询问用户是否安装（说明安装方式与影响），得到批准才安装，拒绝则降级（同类已有工具优先，其次写脚本等效实现并在过程注明降级）；严禁未经用户批准自行安装任何东西。");
	}
	layered.layers.forEach((layer, i) => {
		lines.push(`第 ${i + 1} 层${i === 0 ? "（起点）" : ""}：`);
		for (const id of layer) if (byId[id]) lines.push("  " + stepLine(taxonomy, byId[id]));
	});
	if (layered.cycle.length) {
		lines.push("循环段（存在循环衔接，按列出顺序执行一轮）：");
		for (const id of layered.cycle) if (byId[id]) lines.push("  " + stepLine(taxonomy, byId[id]));
	}
	return lines.join("\n");
}

/** 运行弹层输入的目标在会话无登记目标时自动补登记——kind 轻量推断。 */
export function inferTargetKind(label) {
	const s = String(label ?? "").trim();
	if (/^https?:\/\//i.test(s)) return "web";
	if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(s)) return "ip";
	if (/^[\w-]+(\.[\w-]+)+/.test(s)) return "domain";
	return "other";
}
