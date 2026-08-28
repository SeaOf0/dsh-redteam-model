// dsh-auto-advance — 自动推进器（八专业模式）。
//
// 把「模型停下等用户输入」的断点焊上：subagent 类执行体返回（tool/result）时，
// 若意图台账有未收口方向，主动 followup 注入一条推进提醒——按台账收口本次执行
// 对应的意图（done 附产出指位 / blocked 附原因），再依锚派下一步（operation_intent）
// 或收工。事件驱动闭环的最后一环。
//
// 三护栏（自主不失控）：
//   1) 轮数上限——连续自动推进 maxAutoTurns 轮封顶，真人消息（含其他插件注入）重置计数；
//   2) opt-in——仅意图台账存在且有 open 意图时激活（与 scope 同纪律：登记即激活）；
//   3) 注入自带台账态势——收口什么/还剩什么/第几轮，人工可审计、随时接管。
// 另有冷却窗（默认 30s）：并行执行体齐返回只并作一次推进，不刷屏。
//
// 不改写不拦截，只注入；非八专业模式/无台账会话零干扰。
// 推进语态按模式注入（MODE_VOICE）：收口产出与下一步方向用本模式自己的语义，
// 台账机制原子（operation_progress/operation_intent/轮次护栏）全模式统一。

import fs from "node:fs";
import path from "node:path";
import z from "@deepseek-ai/schemastery";

const name = "dsh-auto-advance";
const inject = ["agentPresets"];

export const MODE_IDS = ["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];

const Config = z.object({
	enable: z.boolean().default(true),
	maxAutoTurns: z.natural().default(5),
	cooldownMs: z.natural().default(30000),
	kickoff: z.boolean().default(true)
});

/** 执行体工具面：subagent 家族（原生 subagent/subagent_fork + 产品 CLI 派生工具）。 */
export function isAdvanceTool(toolName) {
	return /^subagent/.test(String(toolName ?? ""));
}

/** 台账读取：open 意图清单（无文件/无意图返回 null）。 */
export function readOpenIntents(cwd) {
	try {
		const st = JSON.parse(fs.readFileSync(path.join(cwd, "operation-state.json"), "utf8"));
		if (!st || !Array.isArray(st.intents)) return null;
		const open = st.intents.filter((i) => i && i.status === "open");
		return { total: st.intents.length, openIds: open.map((i) => i.id), summaries: open.map((i) => `${i.id}:${String(i.summary ?? "").slice(0, 60)}`) };
	} catch { return null; }
}

/** 从执行体调用参数中提取意图 id 提示（模型派单 prompt 里写了 i1/i2 时点名，没写则空）。 */
export function intentHintOf(argsRaw, ledger) {
	const ids = new Set();
	for (const m of String(argsRaw ?? "").matchAll(/\bi([0-9]{1,3})\b/g)) ids.add(`i${Number(m[1])}`);
	const known = new Set((ledger?.openIds ?? []).concat(ledger ? [] : []));
	// 提示 id 限定在台账 open 意图内（点名已收口的没有意义）
	return [...ids].filter((id) => (ledger?.openIds ?? []).includes(id)).slice(0, 5);
}

/** 各模式推进语态：收口时"产出"在本模式指什么、下一步在本模式是什么方向——
 *  台账机制原子（operation_progress 收口/operation_intent 派单/轮次护栏）全模式统一，语态按模式注入。 */
export const MODE_VOICE = {
	pentest: { done: "漏洞发现或验证证据（finding id 或证据落盘路径）", next: "下一攻击面或入口方向" },
	"code-audit": { done: "finding（附 sink 指位与复现链，双链命中对账）", next: "下一模块或 sink 面" },
	"binary-analysis": { done: "能力结论或 IOC 假设（同步假设台账）", next: "下一假设或分析视角" },
	"attack-defense": { done: "阶段战果（op-traces 或 gate 产物指位）", next: "下一阶段动作或战果扩大方向" },
	"av-evasion": { done: "判定结果（过检或被检出，附判定环境）", next: "下一配对实验" },
	"incident-response": { done: "证据指位与时间线位置", next: "下一排查项" },
	"cloud-security": { done: "战果与攻击路径四要素位置", next: "下一身份或资源路径" },
	"ctf-solver": { done: "flag 与解题路径", next: "下一题或下一模块" }
};

/** 推进决策（纯函数，供测试）：返回 {nudge:false,reason} 或 {nudge:true,text}。
 *  voice={done,next} 为模式语态（MODE_VOICE），缺省时退通用文案。 */
export function decideAdvance({ toolName, ledger, usedTurns, maxAutoTurns, cooldownMs, lastNudgeAt, now, hint = [], voice = {} }) {
	if (!isAdvanceTool(toolName)) return { nudge: false, reason: "tool" };
	if (ledger === null || ledger.openIds.length === 0) return { nudge: false, reason: "no-open-intents" };
	if (usedTurns >= maxAutoTurns) return { nudge: false, reason: "turn-cap" };
	if (now - lastNudgeAt < cooldownMs) return { nudge: false, reason: "cooldown" };
	const openList = ledger.summaries.slice(0, 5).map((s) => s.split(":")[0]).join(",");
	const more = ledger.openIds.length > 5 ? " 等" : "";
	const hintLine = hint.length > 0 ? `本次执行疑似对应 ${hint.join(", ")}（以派单 prompt 提及为准）。` : "";
	return {
		nudge: true,
		text: `[auto-advance] 执行体已返回（${toolName}）。台账：意图 ${ledger.openIds.length}/${ledger.total} 未收口（${openList}${more}）——${hintLine}先 operation_progress 收口本次执行对应的意图（intent_done 附产出指位${voice.done ? `：${voice.done}` : ""} / intent_blocked 附原因），再依锚 operation_intent 派下一步${voice.next ? `（${voice.next}）` : ""}或收工（无下一步即静默收尾，不硬造方向）。本条为自动推进（第 ${usedTurns + 1}/${maxAutoTurns} 轮），人工输入随时接管。`
	};
}

function isHumanUser(message) {
	return message?.source?.kind === "user";
}
function textOf(message) {
	const content = message?.content ?? message;
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content.filter((b) => b?.type === "text").map((b) => b.text).join(" ");
}

async function apply(ctx, config) {
	const cfg = { enable: true, maxAutoTurns: 5, cooldownMs: 30000, kickoff: true, ...config };
	if (!cfg.enable) return;
	let decompositionMap = null;
	// 模式化拆分理论：兄弟插件 dsh-stage-gate 的 DECOMPOSITION（不可达降级通用文案）
	try {
		({ DECOMPOSITION: decompositionMap } = await import("../../dsh-stage-gate/lib/index.js"));
	} catch { /* 手工局部安装降级 */ }
	const inflight = new Map(); // `${sid}:${callId}` → toolName（只记执行体）
	const inflightArgs = new Map(); // 同键 → 调用参数原文（意图提示用，同生命周期）
	const state = new Map(); // sid → { used, lastAt }
	const myIds = new Set(); // 本插件注入的 followup id（真人判定排除自身）
	const kickoffDone = new Set(); // sid → 开工提醒已发（每会话一次）

	const agentsOf = () => {
		try { return ctx.get("agents"); } catch { return undefined; }
	};
	const agentOf = (sid) => agentsOf()?.get?.(sid);

/** 真人接管重置：只清轮次计数（连续自主上限），冷却窗保留（防连发与谁说话无关）。 */
	const reset = (sid) => {
		const st = state.get(sid);
		if (st) state.set(sid, { used: 0, lastAt: st.lastAt });
	};

	/** 模式化拆分理论（DECOMPOSITION 已在 apply 顶部导入；不可达降级通用文案）。 */
	const theoryOf = (mode) => {
		if (decompositionMap && decompositionMap[mode]) return decompositionMap[mode];
		return null;
	};

	/** 开工提醒文案：模式化（本模式拆分理论+准则结构+分母语义）优先，降级通用三登记。 */
	const kickoffText = (mode) => {
		const d = theoryOf(mode);
		if (d) {
			return `[auto-advance] 开工提醒（${mode}）：深度任务先做开工三登记——① operation_goal（目标+可判定准则；本模式拆分理论：${d.theory}——准则结构：${d.criteriaGuide}）→ ② operation_constraints（用户口头约束 deny/allow 结构化，防压缩丢失+可拦${d.constraintHints ? `；本模式约束面：${d.constraintHints}` : ""}）→ ③ operation_scope（范围分母${d.scopeSemantics ? `：${d.scopeSemantics}` : ""}，报告门对账依据）。登记后对账/推进/门禁体系激活；快任务/问答可忽略（不登记零干扰，出口有兜底）。`;
		}
		return "[auto-advance] 开工提醒：深度任务先做开工三登记——operation_goal（目标+可判定准则）→ operation_constraints（用户口头约束 deny/allow 结构化，防压缩丢失+可拦）→ operation_scope（范围分母，报告门对账依据）。登记后对账/推进/门禁体系激活；快任务/问答可忽略（不登记零干扰，出口有兜底）。";
	};

	ctx.on("agent/inbox/inserted", (info) => {
		const message = info?.message;
		if (!isHumanUser(message) || myIds.has(message?.id)) return;
		const sid = info?.agent?.session?.id ?? info?.agent?.id;
		reset(sid);
		// 开工提醒（第 0 轮推进）：专业模式会话首条人类消息后，工作区无台账则一次性提醒
		// 开工三登记——不硬拦（快任务可忽略），出口对账兜底。
		if (cfg.kickoff && sid && !kickoffDone.has(sid)) {
			kickoffDone.add(sid);
			const agent = info?.agent;
			const cwd = agent?.session?.header?.cwd;
			if (typeof cwd === "string" && cwd && !fs.existsSync(path.join(cwd, "operation-state.json")) && typeof agent.followup === "function") {
				let mode = "";
				try { mode = String(ctx.agentPresets?.composedPreset?.(agent?.ctx) ?? ""); } catch { /* 组合未就绪 */ }
				if (MODE_IDS.includes(mode)) {
					const id = `auto-kickoff-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
					myIds.add(id);
					try {
						agent.followup({ id, role: "user", content: [{ type: "text", text: kickoffText(mode) }], source: { kind: "user" } });
					} catch { /* 提醒失败不重试 */ }
				}
			}
		}
	});
	ctx.on("session/event", (subject, event) => {
		if (event?.type === "user/message" && isHumanUser(event.data) && !myIds.has(event.data?.id)) {
			reset(subject?.id ?? subject?.header?.id);
			return;
		}
		const sid = String(subject?.id ?? subject?.header?.id ?? "");
		if (!sid) return;
		if (event?.type === "tool/call") {
			const toolName = event.data?.name;
			if (!isAdvanceTool(toolName)) return;
			if (inflight.size > 1024) { inflight.clear(); inflightArgs.clear(); }
			const key = `${sid}:${event.data.callId}`;
			inflight.set(key, toolName);
			inflightArgs.set(key, String(event.data.arguments ?? ""));
			return;
		}
		if (event?.type !== "tool/result") return;
		const message = event.data?.message ?? {};
		const callId = typeof message.source?.callId === "string" && message.source?.kind === "tool" ? message.source.callId : (Array.isArray(message.content) ? message.content.find((b) => typeof b?.toolCallId === "string")?.toolCallId : undefined);
		if (typeof callId !== "string") return;
		const key = `${sid}:${callId}`;
		const toolName = inflight.get(key);
		if (toolName === undefined) return;
		const argsRaw = inflightArgs.get(key) ?? "";
		inflight.delete(key);
		inflightArgs.delete(key);
		// 会话/模式/工作区三重门槛
		const agent = agentOf(sid);
		if (!agent || typeof agent.followup !== "function") return;
		let mode = "";
		try { mode = String(ctx.agentPresets?.composedPreset?.(agent.ctx) ?? ""); } catch { /* 组合未就绪 */ }
		if (!MODE_IDS.includes(mode)) return;
		const cwd = agent.session?.header?.cwd;
		if (typeof cwd !== "string" || !cwd) return;
		const ledger = readOpenIntents(cwd);
		const hint = intentHintOf(argsRaw, ledger);
		const st = state.get(sid) ?? { used: 0, lastAt: 0 };
		const decision = decideAdvance({ toolName, ledger, usedTurns: st.used, maxAutoTurns: cfg.maxAutoTurns, cooldownMs: cfg.cooldownMs, lastNudgeAt: st.lastAt, now: Date.now(), hint, voice: MODE_VOICE[mode] ?? {} });
		if (!decision.nudge) return;
		const id = `auto-advance-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		myIds.add(id);
		state.set(sid, { used: st.used + 1, lastAt: Date.now() });
		try {
			agent.followup({ id, role: "user", content: [{ type: "text", text: decision.text }], source: { kind: "user" } });
		} catch { /* 注入失败不重试（下一执行体返回自然再试） */ }
	});
	ctx.on("agent/disposed", (agent) => {
		const sid = agent?.session?.id ?? agent?.id;
		state.delete(sid);
		kickoffDone.delete(sid);
	});
}

export { Config, apply, inject, name };
