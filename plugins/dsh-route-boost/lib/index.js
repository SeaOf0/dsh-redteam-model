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
import os from "node:os";
import path from "node:path";
import z from "@deepseek-ai/schemastery";
import { MODES, FALLBACK_GATES, NEGATION_TOKENS } from "./routes.mjs";
import { toolsStatus } from "./skilltools.mjs";
import { detectScope } from "./scope.mjs";
export { detectScope };

const name = "dsh-route-boost";
const inject = ["systemPrompt", "agentPresets"];

const Config = z.object({
	maxChars: z.natural().default(1200),
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

/** Render the envelope. Deterministic in (mode, phase, refsHits, operation, tools) — identical
 *  inputs must produce deterministic text or RuntimeContextProjection re-snapshots.
 *  预算控制：超长时 refs/知识提示行最先丢，其次语境行，再次 tools 行，然后从尾部整行丢
 *  （mode 行与 operation 恢复行在顶部受保护）；单行仍超才截断加省略号——整行粒度保证
 *  每一行的语义完整性。
 *  buildEnvelopeDetailed 额外带回 dropped 记账（供注入量审计）；buildEnvelope 保持纯文本返回。 */
export function buildEnvelopeDetailed({ presetId, mode, phase, refsHits, evidence = "unknown", gates, operation, maxChars = 1200, includeRefs = true, negated = false, tools, scope }) {
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
		lines.splice(1, 0, `operation 恢复: goal=${String(op.goal ?? "").slice(0, 80) || "（未登记）"}｜准则 ${op.met ?? 0}/${op.total ?? 0} met${(op.openIds ?? []).length ? `（未收口 ${op.openIds.join(",")}）` : ""}｜待办 ${(op.pending ?? []).length}｜最近门 ${lastGate}——先读 operation-state.json 对齐；准则全 met+报告门过才可写 reports/；压缩续接先读四件套（WORKSPACE.md/gate-log 尾/evidence-index 认知节/findings）再动门禁`);
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
			const detailed = buildEnvelopeDetailed({ presetId, mode, phase, refsHits, evidence, gates, operation, maxChars: config.maxChars, includeRefs: config.includeRefs, negated, tools, scope });
			let rev = state?.rev ?? 0;
			if (state?.lastBody !== detailed.text) {
				rev += 1;
				agentState.set(agent.id, { text, phaseId: phase.id, rev, lastBody: detailed.text });
				appendAccounting(logFile, { ts: new Date().toISOString(), agent: agent.id, mode: presetId, phase: phase.id, rev, chars: detailed.text.length, dropped: detailed.dropped, refs: refsHits, evidence, scope: scope.directed ? "directed" : "full", scopeHits: scope.hits.slice(0, 5), tools: tools ? { ok: tools.ok, total: tools.total, missing: tools.missing } : undefined });
			} else {
				agentState.set(agent.id, { text, phaseId: phase.id, rev, lastBody: detailed.text });
			}
			return wrapEnvelope(escapePromptBraces(detailed.text), { rev, presetId, phaseId: phase.id });
		}
	});
}

export { Config, MODES, apply, inject, name };
