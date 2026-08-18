// dsh-route-boost — the per-turn governance envelope for the security presets
// (six professional modes + redteam controller).
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
import path from "node:path";
import z from "@deepseek-ai/schemastery";
import { MODES, FALLBACK_GATES, NEGATION_TOKENS } from "./routes.mjs";

const name = "dsh-route-boost";
const inject = ["systemPrompt", "agentPresets"];

const Config = z.object({
	maxChars: z.natural().default(1600),
	includeRefs: z.boolean().default(true)
});

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

/** Render the envelope. Deterministic in (mode, phase, refsHits, operation) — identical
 * inputs must produce deterministic text or RuntimeContextProjection re-snapshots. */
export function buildEnvelope({ presetId, mode, phase, refsHits, evidence = "unknown", gates, operation, maxChars = 1600, includeRefs = true, negated = false }) {
	const gateTable = gates?.[presetId] ?? {};
	const gateLines = phase.gates
		.map((id) => gateTable[id] ? `${id} ${gateTable[id].title}` : `${id}`)
		.join(" | ");
	const lines = [
		`[route-boost] mode=${presetId}（${mode.label}） phase=${phase.id} ${phase.label}（推断——若与实际任务不符，以实际为准继续）`,
		gateLines
			? `gates: ${gateLines} —— 结构校验调 stage_gate，语义门禁归复核员（independent-review）`
			: "gates: 本模式无自建门——总控只消费专业模式 gate-pass 落盘产物（不越权判定）；台账终态与全局总结模板见 router-playbook",
		`review: ${mode.review ?? "关键 finding 双签 = DSH 独立复核 + subagent_claude_code 复核一致；仅确认/挑战二选一，禁止骑墙"}`,
		`boundary: ${mode.boundary}`,
		`evidence: ${evidence}（confirmed=用户已附原始证据材料，按已验证引用；partial/unknown=下结论前先补证据）`
	];
	if (operation) {
		const op = operation;
		const gateKeys = Object.keys(op.gates ?? {});
		const lastGate = gateKeys.length > 0 ? `${gateKeys[gateKeys.length - 1]} ${op.gates[gateKeys[gateKeys.length - 1]]?.pass ? "pass" : "fail"}` : "无";
		lines.splice(1, 0, `operation 恢复: goal=${String(op.goal ?? "").slice(0, 80) || "（未登记）"}｜准则 ${op.met ?? 0}/${op.total ?? 0} met${(op.openIds ?? []).length ? `（未收口 ${op.openIds.join(",")}）` : ""}｜待办 ${(op.pending ?? []).length} 项｜最近门 ${lastGate}——先读 operation-state.json 对齐进度再继续；准则全 met + 报告门通过才可写 reports/`);
	}
	if (negated) {
		lines.push("语境: 检测到学习/防御语境——攻击执行相位路由已抑制，按知识讲解/防御口径作答");
	}
	if (includeRefs) {
		if (refsHits.length > 0) {
			lines.push(`refs: 读 refs/README.md 快速路由 → ${refsHits.join("、")}`);
		} else if ((mode.refs ?? []).length > 0) {
			lines.push("refs: 本轮无命中——需要外部知识时先 web_search 或读本模式 refs/README.md 快速路由，勿凭记忆自答");
		} else {
			lines.push("知识: 本轮无 refs 命中——浅做按 router-playbook（路由表/概览探测纪律/台账/总结模板）；需要深度知识时加载对应专业 playbook，勿凭记忆自答");
		}
	}
	const text = lines.join("\n");
	return text.length > maxChars ? text.slice(0, maxChars - 1) + "…" : text;
}

/** 路由决策审计行：相位变化时落一行
 * markdown 表格行——与 gate-log/enforce-log 同构，让「每轮把模型拉回轨道」的
 * 推送层可复盘。触发词截断 80 字符、换行折叠，防日志膨胀。 */
export function buildAuditRow(nowIso, modeId, phaseId, trigger) {
	const t = String(trigger ?? "").replace(/\s+/g, " ").slice(0, 80);
	return `| ${nowIso} | ${modeId} | ${phaseId} | ${t.replace(/\|/g, "/")} |`;
}

/** 读工作区 operation-state.json 的恢复盘摘要（无契约/读取失败返回 undefined——信封不投递该行）。
 * 仅在有「未收口准则或待办」时投递：全 met 的终态契约不再占信封预算。 */
function readOperationSummary(cwd) {
	if (!cwd) return undefined;
	try {
		const st = JSON.parse(fs.readFileSync(path.join(cwd, "operation-state.json"), "utf8"));
		if (!st || !Array.isArray(st.criteria) || st.criteria.length === 0) return undefined;
		const openIds = st.criteria.filter((c) => c && c.status !== "met").map((c) => c.id);
		const pending = Array.isArray(st.pending) ? st.pending : [];
		if (openIds.length === 0 && pending.length === 0) return undefined;
		return { goal: st.goal, total: st.criteria.length, met: st.criteria.length - openIds.length, openIds, pending, gates: st.gates };
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
			agentState.set(agent.id, { text, phaseId: phase.id });
			return escapePromptBraces(buildEnvelope({ presetId, mode, phase, refsHits, evidence, gates, operation, maxChars: config.maxChars, includeRefs: config.includeRefs, negated }));
		}
	});
}

export { Config, MODES, apply, inject, name };
