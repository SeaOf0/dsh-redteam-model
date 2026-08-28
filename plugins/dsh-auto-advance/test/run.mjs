// dsh-auto-advance 离线单测：决策纯函数（工具过滤/无台账/轮数上限/冷却/文案）
// + 装配接线（事件→followup）/三护栏/真人重置/意图点名/非专业模式静默。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isAdvanceTool, readOpenIntents, intentHintOf, decideAdvance, MODE_IDS, MODE_VOICE, Config } from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

const LEDGER = { total: 3, openIds: ["i1", "i2", "i3"], summaries: ["i1:追注入点", "i2:横向试探", "i3:提权验证"] };
const BASE = { toolName: "subagent", ledger: LEDGER, usedTurns: 0, maxAutoTurns: 5, cooldownMs: 30000, lastNudgeAt: 0, now: 100000 };

// 1. 工具面
ok("subagent 前缀命中", isAdvanceTool("subagent") && isAdvanceTool("subagent_fork") && isAdvanceTool("subagent_claude_code") && isAdvanceTool("subagent_codex"));
ok("非执行体不命中", !isAdvanceTool("bash") && !isAdvanceTool("fetch") && !isAdvanceTool("subagentX") === false && !isAdvanceTool(""));

// 2. 决策纯函数
{
	let d = decideAdvance({ ...BASE, toolName: "bash" });
	ok("非执行体不推进", d.nudge === false && d.reason === "tool");
	d = decideAdvance({ ...BASE, toolName: "subagent", ledger: null });
	ok("无台账不推进", d.nudge === false && d.reason === "no-open-intents");
	d = decideAdvance({ ...BASE, toolName: "subagent", ledger: { total: 3, openIds: [], summaries: [] } });
	ok("无 open 意图不推进", d.nudge === false && d.reason === "no-open-intents");
	d = decideAdvance({ ...BASE, toolName: "subagent", usedTurns: 5 });
	ok("轮数上限封顶", d.nudge === false && d.reason === "turn-cap");
	d = decideAdvance({ ...BASE, toolName: "subagent", lastNudgeAt: 90000, now: 100000 });
	ok("冷却窗内不推进", d.nudge === false && d.reason === "cooldown");
	d = decideAdvance({ ...BASE, toolName: "subagent", lastNudgeAt: 90000, now: 130000 });
	ok("冷却窗外推进", d.nudge === true);
	d = decideAdvance(BASE);
	ok("常规推进", d.nudge === true && d.text.includes("[auto-advance]") && d.text.includes("3/3 未收口") && d.text.includes("i1,i2,i3"));
	ok("文案含收口指路与轮次", d.text.includes("intent_done") && d.text.includes("第 1/5 轮") && d.text.includes("人工输入随时接管"));
	ok("文案含不硬造方向", d.text.includes("不硬造方向"));
	d = decideAdvance({ ...BASE, hint: ["i1", "i2"] });
	ok("意图点名进文案", d.text.includes("本次执行疑似对应 i1, i2"));
}

// 2b. 模式语态注入
{
	ok("八模式语态全覆盖", Object.keys(MODE_VOICE).length === 8 && MODE_IDS.every((m) => MODE_VOICE[m]?.done && MODE_VOICE[m]?.next));
	const ir = decideAdvance({ ...BASE, voice: MODE_VOICE["incident-response"] });
	ok("IR 推进语态：产出=证据指位与时间线/下一步=排查项", ir.text.includes("证据指位与时间线位置") && ir.text.includes("（下一排查项）"));
	ok("机制原子不随语态变", ir.text.includes("operation_progress") && ir.text.includes("operation_intent") && ir.text.includes("第 1/5 轮") && ir.text.includes("不硬造方向") && ir.text.includes("人工输入随时接管"));
	const au = decideAdvance({ ...BASE, voice: MODE_VOICE["code-audit"] });
	ok("代审推进语态：产出=finding 复现链/下一步=sink 面", au.text.includes("双链命中对账") && au.text.includes("下一模块或 sink 面"));
	const av = decideAdvance({ ...BASE, voice: MODE_VOICE["av-evasion"] });
	ok("免杀推进语态：产出=判定结果/下一步=配对实验", av.text.includes("过检或被检出") && av.text.includes("（下一配对实验）"));
	const plain = decideAdvance(BASE);
	ok("无 voice 退通用文案（向后兼容）", plain.text.includes("intent_done 附产出指位 / intent_blocked 附原因") && plain.text.includes("派下一步或收工"));
}

// 3. 台账读取与意图提示（真实文件）
{
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aa-"));
	fs.writeFileSync(path.join(tmp, "operation-state.json"), JSON.stringify({ criteria: [{ id: "g1", status: "met" }], intents: [{ id: "i1", summary: "追注入", status: "open" }, { id: "i2", summary: "横向", status: "done" }] }));
	const ledger = readOpenIntents(tmp);
	ok("readOpenIntents 只列 open", ledger.openIds.join() === "i1" && ledger.total === 2);
	ok("readOpenIntents 无文件返回 null", readOpenIntents(path.join(tmp, "nope")) === null);
	fs.writeFileSync(path.join(tmp, "operation-state.json"), JSON.stringify({ criteria: [] }));
	ok("无 intents 键返回 null", readOpenIntents(tmp) === null);
	const hint = intentHintOf('{"prompt":"执行 i1 的注入点验证（意图 i1）+ 参考 i9"}', { openIds: ["i1"], summaries: ["i1:x"] });
	ok("意图提示限定 open 集", hint.join() === "i1");
	ok("无提及返回空", intentHintOf("{}", ledger).length === 0);
	fs.rmSync(tmp, { recursive: true, force: true });
}

// 4. 装配接线：fake ctx 全链路（事件→followup）+ 三护栏 + 真人重置
{
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aa-wire-"));
	fs.writeFileSync(path.join(tmp, "operation-state.json"), JSON.stringify({ criteria: [{ id: "g1", status: "met" }], intents: [{ id: "i1", summary: "追注入", status: "open" }] }));
	const mod = await import("../lib/index.js");
	const handlers = {};
	const followups = [];
	const fakeAgent = {
		ctx: {}, session: { id: "sx", header: { cwd: tmp, agentPreset: "pentest" } },
		followup: (m) => followups.push(m)
	};
	const agentsMap = new Map([["sx", fakeAgent]]);
	const fakeCtx = {
		on: (ev, fn) => { handlers[ev] = fn; },
		get: (svc) => (svc === "agents" ? { get: (id) => (id === "sx" ? fakeAgent : undefined) } : undefined),
		agentPresets: { composedPreset: () => "pentest" }
	};
	let threw = null;
	try { await mod.apply(fakeCtx, { cooldownMs: 20 }); } catch (e) { threw = e; }
	ok("apply 不抛", threw === null);
	ok("session/event 已接线", typeof handlers["session/event"] === "function");
	const call = (name, callId, args = "{}") => handlers["session/event"]({ id: "sx" }, { type: "tool/call", data: { name, callId, arguments: args } });
	const result = (callId) => handlers["session/event"]({ id: "sx" }, { type: "tool/result", data: { message: { source: { kind: "tool", callId }, content: [{ type: "text", text: "done" }] } } });
	call("subagent_claude_code", "c1", '{"prompt":"执行 i1 验证"}');
	result("c1");
	ok("执行体返回注入推进", followups.length === 1 && followups[0].content[0].text.includes("[auto-advance]") && followups[0].content[0].text.includes("i1"));
	ok("followup 形态（role/source/id）", followups[0].role === "user" && followups[0].source.kind === "user" && typeof followups[0].id === "string");
	// 冷却窗：立即第二次返回不注入
	call("subagent", "c2");
	result("c2");
	ok("冷却窗抑制第二连发", followups.length === 1);
	// 非执行体不注入
	call("bash", "c3");
	result("c3");
	ok("非执行体返回不注入", followups.length === 1);
	// 真人消息重置计数；再推一轮成功
	handlers["agent/inbox/inserted"]({ agent: { id: "a", session: { id: "sx" } }, message: { id: "human-1", source: { kind: "user" }, content: "继续" } });
	call("subagent", "c4");
	result("c4");
	ok("真人重置后冷却仍生效（同窗）", followups.length === 1);
	// 冷却窗外：推进成功
	await new Promise((r) => setTimeout(r, 30));
	const t0 = Date.now();
	handlers["session/event"]({ id: "sx" }, { type: "user/message", data: { id: "human-2", source: { kind: "user" }, content: "好" } });
	call("subagent", "c5");
	result("c5");
	ok("冷却窗外第二次推进", followups.length === 2);
	// 自注入不重置（伪造我的 id）
	handlers["agent/inbox/inserted"]({ agent: { id: "a", session: { id: "sx" } }, message: { id: followups[1].id, source: { kind: "user" }, content: "自动" } });
	ok("config 默认值", Config({}).enable === true && Config({}).maxAutoTurns === 5 && Config({}).cooldownMs === 30000);
	fs.rmSync(tmp, { recursive: true, force: true });
}

// 5. 开工提醒（v0.2.0）：专业模式首条人类消息+无台账→一次性三登记提醒
{
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aa-kick-"));
	const mod = await import("../lib/index.js");
	const handlers = {};
	const followups = [];
	const fakeAgent = { ctx: {}, session: { id: "sk", header: { cwd: tmp, agentPreset: "pentest" } }, followup: (m) => followups.push(m) };
	const fakeCtx = {
		on: (ev, fn) => { handlers[ev] = fn; },
		get: () => ({ get: (id) => (id === "sk" ? fakeAgent : undefined) }),
		agentPresets: { composedPreset: () => "pentest" }
	};
	await mod.apply(fakeCtx, {});
	const human = (id) => handlers["agent/inbox/inserted"]({ agent: fakeAgent, message: { id, source: { kind: "user" }, content: "测一下这个站" } });
	human("h1");
	ok("无台账时注入开工提醒", followups.length === 1 && followups[0].content[0].text.includes("开工三登记") && followups[0].content[0].text.includes("operation_constraints"));
	human("h2");
	ok("每会话只提醒一次", followups.length === 1);
	// 已有台账：不提醒
	const followups2 = [];
	const fakeAgent2 = { ctx: {}, session: { id: "sk2", header: { cwd: tmp, agentPreset: "pentest" } }, followup: (m) => followups2.push(m) };
	const fakeCtx2 = { on: (ev, fn) => { handlers[ev] = fn; }, get: () => ({ get: (id) => (id === "sk2" ? fakeAgent2 : undefined) }), agentPresets: { composedPreset: () => "pentest" } };
	fs.writeFileSync(path.join(tmp, "operation-state.json"), JSON.stringify({ criteria: [{ id: "g1", status: "met" }] }));
	await mod.apply(fakeCtx2, {});
	handlers["agent/inbox/inserted"]({ agent: fakeAgent2, message: { id: "h3", source: { kind: "user" }, content: "继续" } });
	ok("已有台账不提醒", followups2.length === 0);
	// kickoff 关闭
	const followups3 = [];
	const fakeCtx3 = { on: (ev, fn) => { handlers[ev] = fn; }, get: () => ({ get: () => undefined }), agentPresets: { composedPreset: () => "pentest" } };
	const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), "aa-kick2-"));
	const fakeAgent3 = { ctx: {}, session: { id: "sk3", header: { cwd: tmp2 } }, followup: (m) => followups3.push(m) };
	fakeCtx3.get = () => ({ get: (id) => (id === "sk3" ? fakeAgent3 : undefined) });
	await mod.apply(fakeCtx3, { kickoff: false });
	handlers["agent/inbox/inserted"]({ agent: fakeAgent3, message: { id: "h4", source: { kind: "user" }, content: "x" } });
	ok("kickoff=false 关闭", followups3.length === 0);
	fs.rmSync(tmp, { recursive: true, force: true });
	fs.rmSync(tmp2, { recursive: true, force: true });
}

// 4b. kickoff 模式化（v0.3.0）：文案含本模式拆分理论
{
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aa-kickm-"));
	const mod = await import("../lib/index.js");
	const handlers = {};
	for (const mode of ["pentest", "code-audit", "ctf-solver"]) {
		const followups = [];
		const fakeAgent = { ctx: {}, session: { id: "sk-" + mode, header: { cwd: tmp, agentPreset: mode } }, followup: (m) => followups.push(m) };
		const fakeCtx = { on: (ev, fn) => { handlers[ev] = fn; }, get: () => ({ get: (id) => (id === "sk-" + mode ? fakeAgent : undefined) }), agentPresets: { composedPreset: () => mode } };
		await mod.apply(fakeCtx, {});
		handlers["agent/inbox/inserted"]({ agent: fakeAgent, message: { id: "h-" + mode, source: { kind: "user" }, content: "x" } });
		if (mode === "pentest") {
			ok("kickoff 含 pentest 拆分理论", followups.length === 1 && followups[0].content[0].text.includes("作战流程×资产×漏洞类矩阵") && followups[0].content[0].text.includes("准则按"));
			ok("kickoff 含分母语义", followups[0].content[0].text.includes("入口资产面"));
		}
		if (mode === "code-audit") ok("kickoff 含 audit 理论", followups.length === 1 && followups[0].content[0].text.includes("模块×sink"));
		if (mode === "ctf-solver") ok("kickoff 含 ctf 理论", followups.length === 1 && followups[0].content[0].text.includes("题面登记"));
	}
	fs.rmSync(tmp, { recursive: true, force: true });
}

// 5. 模式清单：八专业、不含 redteam
ok("八专业模式清单", MODE_IDS.length === 8 && !MODE_IDS.includes("redteam") && MODE_IDS.includes("ctf-solver"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
