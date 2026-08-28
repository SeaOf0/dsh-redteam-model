// dsh-route-boost — the per-turn governance envelope for the security presets
// (eight professional modes + redteam controller).
//
// The envelope pushes a route envelope + discipline reminders into every
// user turn via a UserPromptSubmit hook. DSH's native equivalent is the dynamic
// systemPrompt CONTEXT contribution: agent-loop re-renders contexts at every
// assembly and RuntimeContextProjection delivers a snapshot user message ONLY
// when the rendered text changed — steady phases cost nothing, changed phases
// re-anchor the model onto its mode's rails (gate checklist / review duty /
// boundary line / refs pointers).
//
// Feedback safety: phase inference reads only human user messages
// (source.kind !== "plugin"), so the plugin's own snapshots can never
// re-trigger it. Unknown presets (non-security modes) render empty text.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import z from "@deepseek-ai/schemastery";
import { MODES, FALLBACK_GATES, NEGATION_TOKENS } from "./routes.mjs";
import { toolsStatus } from "./skilltools.mjs";
import { detectScope } from "./scope.mjs";
export { detectScope };

const name = "dsh-route-boost";
const inject = ["tools", "systemPrompt", "agentPresets"];

const Config = z.object({
	maxChars: z.natural().default(1200),
	includeRefs: z.boolean().default(true),
	phaseSurface: z.boolean().default(true),
	wrapDeny: z.array(z.string()).default(["subagent", "subagent_fork", "subagent_claude_code", "subagent_codex", "workflow"])
});

/** 收尾相位（八模式报告相位 id 实测集）：report / summary / review。 */
export const WRAP_PHASE_IDS = new Set(["report", "summary", "review"]);
export function isWrapPhase(phaseId) {
	return WRAP_PHASE_IDS.has(String(phaseId ?? ""));
}

/** 相位工具面 guard（纯函数，供测试与装配复用）：收尾相位收起派单类工具——
 *  收尾优先级最高（停止开新方向/新扇出），先收口台账与报告；新方向须用户明示。
 *  phaseLookup(agentId) → 当前粘滞相位 id（装配期维护，guard 执行期读取）。 */
export function buildSurfaceGuard({ config, phaseLookup, resolveMode }) {
	const cfg = { phaseSurface: true, wrapDeny: ["subagent", "subagent_fork", "subagent_claude_code", "subagent_codex", "workflow"], ...config };
	const denySet = new Set(cfg.wrapDeny);
	return function surfaceGuard(exec) {
		if (!cfg.phaseSurface) return undefined;
		const agent = exec?.agent;
		if (!agent || !denySet.has(exec.name)) return undefined;
		const mode = resolveMode(agent);
		if (mode === undefined || !Object.prototype.hasOwnProperty.call(MODES, mode)) return undefined;
		const phaseId = phaseLookup(agent.id);
		if (!isWrapPhase(phaseId)) return undefined;
		return `收尾相位工具面：「${exec.name}」已收起——收尾优先级最高（停止开新方向/新扇出）：先收口台账（operation_progress：准则 met / 意图收口 / 覆盖声明）再写报告；确需新派单，请用户明示或等用户消息把相位切回执行。`;
	};
}

/** Only genuine human input steers routing: web-submitted prompts carry
 * source.kind === "user" (the apiproxy's lastPromptAt uses the same test).
 * Machine user-messages (plugin snapshots, skill catalogs) must not. */
export function isHumanUser(message) {
	return message?.source?.kind === "user";
}

/** Latest HUMAN user text per agent/session id. Two feeds:
 *  - agent/inbox/inserted: fires the moment a human message is queued
 *    (followup), BEFORE the turn's prompt assembly — this kills the
 *    one-turn lag a session-events-only feed would have (user/message is
 *    appended to the session AFTER the first assemble of the turn).
 *  - session/user/message: fallback for hosts/drivers that bypass the inbox. */
function latestUserTracker(ctx, store) {
	const record = (id, text) => {
		const state = store.get(id) ?? {};
		state.text = text;
		store.set(id, state);
	};
	ctx.on("agent/inbox/inserted", (info) => {
		const message = info?.message;
		if (!isHumanUser(message)) return;
		const text = textOf(message);
		if (text) record(info.agent.id, text);
	});
	ctx.on("session/event", (subject, event) => {
		if (event?.type !== "user/message" || !isHumanUser(event.data)) return;
		const text = textOf(event.data);
		if (text) record(sessionIdOf(subject), text);
	});
	ctx.on("agent/disposed", (agent) => store.delete(agent.id));
}

function textOf(message) {
	const content = message?.content ?? message;
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content.filter((b) => b?.type === "text").map((b) => b.text).join(" ");
}

function sessionIdOf(subject) {
	return subject?.id ?? subject?.header?.id ?? "?";
}

/** Keyword match with ASCII word boundaries: a pure [a-z0-9] keyword matches
 * only as a standalone token ("ad" must not fire inside "read"/"admin";
 * "exp" must not fire inside "example"). CJK keywords substring-match as
 * before — Chinese has no word boundaries to exploit. */
const ASCII_TOKEN = /^[a-z0-9]+$/;
const boundaryCache = new Map();
export function matchKeyword(lowerText, keyword) {
	if (!ASCII_TOKEN.test(keyword)) return lowerText.includes(keyword);
	let re = boundaryCache.get(keyword);
	if (re === undefined) {
		re = new RegExp(`(?:^|[^a-z0-9])${keyword}(?:$|[^a-z0-9])`);
		boundaryCache.set(keyword, re);
	}
	return re.test(lowerText);
}

/** 否定语境检测：学习/防御/加固语境抑制
 * execution 相位路由。只匹配否定词表；「检测/排查」等防守动作不在表内。 */
export function hasNegation(text) {
	const lower = String(text ?? "").toLowerCase();
	return NEGATION_TOKENS.some((k) => matchKeyword(lower, k.toLowerCase()));
}

/** First matching phase for `text` (lowercased). Negation context (学习/防御)
 * skips execution phases so a knowledge-seeking prompt never routes into an
 * attack-execution phase. No keyword hit falls back to the agent's STICKY
 * phase (phase memory — a bare "继续" must not reset the mode to its default
 * phase), then the mode default — EXCEPT under negation: a negated prompt with
 * no keyword hit is a knowledge question and must not inherit a sticky
 * execution phase, so it falls to the mode default. */
export function inferPhase(mode, text, stickyPhaseId) {
	const lower = String(text ?? "").toLowerCase();
	const negated = hasNegation(lower);
	for (const phase of mode.phases) {
		if (negated && phase.execution === true) continue;
		if (phase.keywords.some((k) => matchKeyword(lower, k.toLowerCase()))) return phase;
	}
	if (!negated) {
		const sticky = stickyPhaseId === undefined ? undefined : mode.phases.find((p) => p.id === stickyPhaseId);
		if (sticky !== undefined) return sticky;
	}
	return mode.phases.find((p) => p.id === mode.defaultPhase) ?? mode.phases[0];
}

/** Machine pre-judgment of what evidence quality the user's text carries
 * (evidence-level inference, preset flavours). */
const STRONG_EVIDENCE_TOKENS = ["raw request", "原始请求", "完整请求", "请求包", "burp", "pcap", "wireshark", "tcpdump", "nmap", "fscan", "source code", "源码", "sha256", "复现", "poc", "回显", "stack trace", "traceback", "反汇编", "调用链", "样本"];
const PARTIAL_EVIDENCE_TOKENS = ["request", "response", "响应", "报错", "错误信息", "截图", "url", "接口", "日志", "log", "token", "session", "review"];
export function inferEvidence(text) {
	const lower = String(text ?? "").toLowerCase();
	if (STRONG_EVIDENCE_TOKENS.some((k) => lower.includes(k))) return "confirmed";
	if (PARTIAL_EVIDENCE_TOKENS.some((k) => lower.includes(k))) return "partial";
	return "unknown";
}

/** refs categories whose keyword list hits the text, order-preserving unique.
 * Category labels are lookup keys into the preset's TOP-LEVEL refs/README.md
 * quick-route (subdirectories carry no READMEs of their own). */
export function inferRefs(mode, text) {
	const lower = String(text ?? "").toLowerCase();
	const hits = [];
	for (const entry of mode.refs) {
		if (entry.keywords.some((k) => matchKeyword(lower, k.toLowerCase())) && !hits.includes(entry.dir)) hits.push(entry.dir);
	}
	return hits;
}

/** The host interpolates every `{{name}}` group in a rendered context and
 * throws on empty/unknown names. The envelope embeds gate titles and refs
 * names from preset data, so neutralize any `{{` before the text reaches the
 * interpolator (WORD JOINER U+2060; the model still reads `{{`). */
export function escapePromptBraces(text) {
	return text.includes("{{") ? text.replace(/\{(?=\{)/gu, "{\u2060") : text;
}

/** Render the envelope. Deterministic in (mode, phase, refsHits, operation, tools) — identical
 *  inputs must produce deterministic text or RuntimeContextProjection re-snapshots.
 *  预算控制：超长时 refs/知识提示行最先丢，其次语境行，再次 tools 行，然后从尾部整行丢
 *  （mode 行与 operation 恢复行在顶部受保护）；单行仍超才截断加省略号——整行粒度保证
 *  每一行的语义完整性。
 *  buildEnvelopeDetailed 额外带回 dropped 记账（供注入量审计）；buildEnvelope 保持纯文本返回。 */
/** 目标锚定行只挂三作战模式（目标漂移是作战大忌；其余模式无目标概念）。 */
const TARGET_ANCHOR_MODES = new Set(["pentest", "attack-defense", "cloud-security"]);

/** 目的原文单行化+裁剪（粘滞随轮携带，防长会话目的漂移）。 */
export function purposeLine(text, max = 120) {
	const oneLine = String(text ?? "").replace(/\s+/g, " ").trim();
	if (!oneLine) return "";
	return oneLine.length > max ? oneLine.slice(0, max) + "…" : oneLine;
}

export function buildEnvelopeDetailed({ presetId, mode, phase, refsHits, evidence = "unknown", gates, operation, maxChars = 1200, includeRefs = true, negated = false, tools, scope, purpose, surface = "" }) {
	const gateTable = gates?.[presetId] ?? {};
	const gateLines = phase.gates
		.map((id) => gateTable[id] ? `${id} ${gateTable[id].title}` : `${id}`)
		.join(" | ");
	const lines = [
		`[route-boost] mode=${presetId}（${mode.label}） phase=${phase.id} ${phase.label}（推断，不符以实际为准）`,
		gateLines
			? `gates: ${gateLines} —— 结构校验调 stage_gate；语义门禁归复核员（independent-review）`
			: "gates: 本模式无自建门——总控只消费专业模式 gate-pass 落盘产物；台账终态见 router-playbook",
		`boundary: ${mode.boundary}`,
		...(surface === "wrap" ? ["工具面: 收尾相位——subagent/workflow 派单已收起（收口台账与报告优先，新方向须用户明示）"] : []),
		`review: ${mode.review ?? "关键 finding 双签 = DSH 独立复核 + subagent_claude_code 复核一致；仅确认/挑战二选一"}`,
		`evidence: ${evidence}（confirmed=按已验证引用；partial/unknown=下结论前先补证据）`
	];
	if (scope) {
		const mark = presetId === "redteam" ? "台账终态登记" : "redteam_coverage_mark 点亮";
		const line = scope.directed
			? `scope: 定向——用户指定优先${scope.hits && scope.hits.length > 0 ? `：${scope.hits.slice(0, 5).join("、")}` : ""}；只执行用户指定项，完成即逐项 ${mark}，未指定项不补测不欠账；转全流程须用户明示`
			: `scope: 未指定具体项——${presetId === "redteam" ? "按路由手册受理（多任务走台账）" : "按本模式全流程矩阵推进"}`;
		lines.splice(1, 0, line);
	}
	if (TARGET_ANCHOR_MODES.has(presetId)) {
		lines.splice(scope ? 2 : 1, 0, "target: 开战先 redteam_atlas_target 登记目标；每阶段/每次派单开头重读图谱目标带与 assets.md 核对当前作业对象——对未登记对象作业或超出授权=漂移，立即停手回锚");
	}
	if (purpose) {
		lines.splice(scope ? 3 : 2, 0, `目的: ${purpose}`);
	}
	if (phase.channel) {
		lines.splice(2, 0, `channel: ${phase.channel}（本阶段默认通道；缺失按工具手册·通道完整阶梯降级）`);
	}
	if (tools && tools.total > 0) {
		lines.splice(2, 0, `tools: 技能依赖 ${tools.ok}/${tools.total} 就绪${tools.missing.length > 0 ? `——缺 ${tools.missing.join("、")}（先走兜底：已装同类 → MCP → 询问批准后安装）` : ""}`);
	}
	if (operation) {
		const op = operation;
		const gateKeys = Object.keys(op.gates ?? {});
		const lastGate = gateKeys.length > 0 ? `${gateKeys[gateKeys.length - 1]} ${op.gates[gateKeys[gateKeys.length - 1]]?.pass ? "pass" : "fail"}` : "无";
		const cov = op.coverage ? `｜覆盖 ${op.coverage.tested}/${op.coverage.scope}${(op.coverage.untestedIds ?? []).length ? `（未测 ${op.coverage.untestedIds.slice(0, 5).join(",")}${op.coverage.untestedIds.length > 5 ? " 等" : ""}——operation_progress tested 补记）` : ""}` : "";
		const intents = (op.openIntents ?? []).length ? `｜意图 ${op.openIntents.length} 未收口（${op.openIntents.slice(0, 5).join(",")}${op.openIntents.length > 5 ? " 等" : ""}——operation_progress intent_done/blocked/dropped 收口）` : "";
		if ((op.constraints ?? []).length) {
			lines.splice(2, 0, `约束红线: ${op.constraints.join("；")}${op.constraintsNote ?? ""}`);
		}
		lines.splice(1, 0, `operation 恢复: goal=${String(op.goal ?? "").slice(0, 80) || "（未登记）"}｜准则 ${op.met ?? 0}/${op.total ?? 0} met${(op.openIds ?? []).length ? `（未收口 ${op.openIds.join(",")}）` : ""}${cov}${intents}｜待办 ${(op.pending ?? []).length}｜最近门 ${lastGate}——先读 operation-state.json 对齐；准则全 met+报告门过才可写 reports/（scope 已登记时报告须声明一致「覆盖：M/N」）；压缩续接先读四件套（WORKSPACE.md/gate-log 尾/evidence-index 认知节/findings）再动门禁`);
	}
	if (negated) {
		lines.push("语境: 学习/防御语境——攻击执行相位已抑制，按讲解/防御口径作答");
	}
	if (includeRefs) {
		if (refsHits.length > 0) {
			lines.push(`refs: 读 refs/README.md 快速路由 → ${refsHits.join("、")}`);
		} else if ((mode.refs ?? []).length > 0) {
			lines.push("refs: 本轮无命中——需外部知识先 web_search 或读 refs/README.md，勿凭记忆自答");
		} else {
			lines.push("知识: 无 refs 命中——浅做按 router-playbook；深度知识加载对应专业 playbook，勿凭记忆自答");
		}
	}
	const dropped = [];
	let text = lines.join("\n");
	if (text.length > maxChars) {
		const drop = (pred, tag) => { const i = lines.findIndex(pred); if (i >= 0) { lines.splice(i, 1); dropped.push(tag); } };
		drop((l) => l.startsWith("refs:") || l.startsWith("知识:"), "refs");
		text = lines.join("\n");
	}
	if (text.length > maxChars) {
		const i = lines.findIndex((l) => l.startsWith("语境:"));
		if (i >= 0) { lines.splice(i, 1); dropped.push("语境"); text = lines.join("\n"); }
	}
	if (text.length > maxChars) {
		const i = lines.findIndex((l) => l.startsWith("tools:"));
		if (i > 0) { lines.splice(i, 1); dropped.push("tools"); text = lines.join("\n"); }
	}
	while (text.length > maxChars && lines.length > 1) {
		lines.pop();
		dropped.push("tail");
		text = lines.join("\n");
	}
	return { text: text.length > maxChars ? text.slice(0, maxChars - 1) + "…" : text, dropped };
}

export function buildEnvelope(opts) {
	return buildEnvelopeDetailed(opts).text;
}

/** 信封块标记：结构化起止标签让历史快照在上下文压缩后仍可被识别（多块共存以 rev 最大者为准），
 *  也让压缩/抽取等下游消费方能定位治理注入块。 */
export const ENVELOPE_TAG = "dsh-route-boost";
export function wrapEnvelope(body, { rev, presetId, phaseId }) {
	return `<${ENVELOPE_TAG} rev="${rev}" mode="${presetId}" phase="${phaseId}">\n${body}\n</${ENVELOPE_TAG}>`;
}
export function isEnvelopeText(text) {
	const t = String(text ?? "").trim();
	return t.startsWith(`<${ENVELOPE_TAG} `) && t.endsWith(`</${ENVELOPE_TAG}>`);
}
export function envelopeRev(text) {
	const m = /rev="(\d+)"/.exec(String(text ?? ""));
	return m ? Number(m[1]) : undefined;
}

/** 注入量记账（JSONL，一行一次快照投递）：模式/相位/rev/字符数/被丢节/refs 命中——
 *  refs 按节读取与信封预算调参的数据面。路径固定在 ~/.dsh/route-boost/。 */
export function accountingPath(home = os.homedir()) {
	return path.join(home, ".dsh", "route-boost", "injections.jsonl");
}
export function appendAccounting(file, record) {
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.appendFileSync(file, JSON.stringify(record) + "\n");
		return true;
	} catch { /* 记账失败不阻塞装配 */ }
	return false;
}

/** 路由决策审计行：相位变化时落一行
 * markdown 表格行——与 gate-log/enforce-log 同构，让「每轮把模型拉回轨道」的
 * 推送层可复盘。触发词截断 80 字符、换行折叠，防日志膨胀。 */
export function buildAuditRow(nowIso, modeId, phaseId, trigger) {
	const t = String(trigger ?? "").replace(/\s+/g, " ").slice(0, 80);
	return `| ${nowIso} | ${modeId} | ${phaseId} | ${t.replace(/\|/g, "/")} |`;
}

/** 读工作区 operation-state.json 的恢复盘摘要（无契约/读取失败返回 undefined——信封不投递该行）。
 * 仅在有「未收口准则、待办、覆盖度未测项、或未收口意图」时投递：全收口的终态契约不占信封预算。 */
function readOperationSummary(cwd) {
	if (!cwd) return undefined;
	try {
		const st = JSON.parse(fs.readFileSync(path.join(cwd, "operation-state.json"), "utf8"));
		if (!st || !Array.isArray(st.criteria) || st.criteria.length === 0) return undefined;
		const openIds = st.criteria.filter((c) => c && c.status !== "met").map((c) => c.id);
		const pending = Array.isArray(st.pending) ? st.pending : [];
		// 覆盖度台账（scope/tested）：登记即纳入摘要——有未测项时即使准则全 met 也投递
		const scope = Array.isArray(st.scope) ? st.scope.filter((s) => s && typeof s.id === "string") : [];
		const testedIds = new Set((Array.isArray(st.tested) ? st.tested : []).map((t) => t?.id));
		const untestedIds = scope.filter((s) => !testedIds.has(s.id)).map((s) => s.id);
		// 意图台账：open 意图存在时投递
		const openIntents = (Array.isArray(st.intents) ? st.intents : []).filter((i) => i && i.status === "open").map((i) => i.id);
		// 约束台账：登记即投递独立行（防压缩丢失——用户红线必须每轮可见）
		const constraints = Array.isArray(st.constraints) ? st.constraints.filter((c) => c && (c.kind === "deny" || c.kind === "allow") && typeof c.text === "string" && c.text.trim()) : [];
		if (openIds.length === 0 && pending.length === 0 && openIntents.length === 0 && constraints.length === 0 && (scope.length === 0 || untestedIds.length === 0)) return undefined;
		return { goal: st.goal, total: st.criteria.length, met: st.criteria.length - openIds.length, openIds, pending, gates: st.gates, coverage: scope.length > 0 ? { scope: scope.length, tested: scope.length - untestedIds.length, untestedIds } : undefined, openIntents, constraints: constraints.slice(0, 6).map((c) => `${c.kind === "deny" ? "禁" : "允"}：${String(c.text).slice(0, 60)}`) };
	} catch { /* 无状态或损坏：不投递 */ }
	return undefined;
}

async function apply(ctx, config) {
	let gates = FALLBACK_GATES;
	try {
		// Bundle layout guarantees the sibling plugin; the try keeps a partial
		// hand-install degradeable instead of bricking the host.
		({ GATES: gates } = await import("../../dsh-stage-gate/lib/index.js"));
	} catch {}
	// Per-agent routing state: latest human text + last inferred phase (sticky).
	const agentState = new Map();
	latestUserTracker(ctx, agentState);
	// 相位工具面：guard 在执行期读装配期维护的粘滞相位，收尾相位收起派单类工具
	ctx.tools.guard(buildSurfaceGuard({
		config,
		phaseLookup: (agentId) => agentState.get(agentId)?.phaseId,
		resolveMode: (agent) => {
			try { return ctx.agentPresets.composedPreset(agent.ctx); } catch { return undefined; }
		}
	}));
	/** 相位变化审计（设计点③）：写 <workspace>/route-audit.md；失败静默（审计
	 * 不得阻塞装配）。只在相位真正变化时落一行，稳态零写入。 */
	const auditRoute = (agent, modeId, phaseId, trigger) => {
		try {
			const cwd = agent?.session?.header?.cwd;
			if (!cwd) return;
			const file = path.join(cwd, "route-audit.md");
			const row = buildAuditRow(new Date().toISOString(), modeId, phaseId, trigger);
			if (!fs.existsSync(file)) {
				fs.writeFileSync(file, `# 路由决策审计（route-boost 自动留痕）\n\n| 时间 | 模式 | 相位 | 触发输入 |\n|---|---|---|---|\n${row}\n`);
			} else {
				fs.appendFileSync(file, `${row}\n`);
			}
		} catch { /* 审计失败不阻塞 */ }
	};
	const logFile = accountingPath();
	ctx.systemPrompt.context({
		name: "route-boost",
		order: 500,
		text: (assembly) => {
			const agent = assembly?.agent;
			if (!agent) return "";
			const presetId = ctx.agentPresets.composedPreset(agent.ctx);
			const mode = MODES[presetId];
			if (mode === undefined) return "";
			const state = agentState.get(agent.id);
			const text = state?.text ?? "";
			const negated = hasNegation(text);
			const phase = inferPhase(mode, text, state?.phaseId);
			const refsHits = inferRefs(mode, text);
			const evidence = inferEvidence(text);
			const operation = readOperationSummary(agent?.session?.header?.cwd);
			if (state?.phaseId !== phase.id) auditRoute(agent, presetId, phase.id, text);
			const tools = toolsStatus(presetId);
			const scope = detectScope(presetId, text);
			// 目的锚定粘滞：定向消息=最新用户指定（覆盖更新）；全流程下首条任务消息快照后粘滞
			let purpose = state?.purpose ?? "";
			if (scope.directed && text) purpose = purposeLine(text);
			else if (!purpose && text && state?.rev === undefined) purpose = purposeLine(text);
			const detailed = buildEnvelopeDetailed({ presetId, mode, phase, refsHits, evidence, gates, operation, maxChars: config.maxChars, includeRefs: config.includeRefs, negated, tools, scope, purpose, surface: config.phaseSurface !== false && isWrapPhase(phase.id) ? "wrap" : "" });
			let rev = state?.rev ?? 0;
			if (state?.lastBody !== detailed.text) {
				rev += 1;
				agentState.set(agent.id, { text, phaseId: phase.id, rev, lastBody: detailed.text, purpose });
				appendAccounting(logFile, { ts: new Date().toISOString(), agent: agent.id, mode: presetId, phase: phase.id, rev, chars: detailed.text.length, dropped: detailed.dropped, refs: refsHits, evidence, scope: scope.directed ? "directed" : "full", scopeHits: scope.hits.slice(0, 5), tools: tools ? { ok: tools.ok, total: tools.total, missing: tools.missing } : undefined });
			} else {
				agentState.set(agent.id, { text, phaseId: phase.id, rev, lastBody: detailed.text, purpose });
			}
			return wrapEnvelope(escapePromptBraces(detailed.text), { rev, presetId, phaseId: phase.id });
		}
	});
}

export { Config, MODES, apply, inject, name };
