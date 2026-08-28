// dsh-trace-vault 离线单测：出局分类/截断标记/事件配对落库（含安全模式门与
// callId 双形态）/检索命中与 LIKE 转义/最近一览与统计/保留清理/总量上限。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openStore, insertTrace, searchTraces, getTrace, listRecent, statsTraces, sessionStats, purgeOld, capRows, classifyOutcome, argsTextOf, resultTextOf, escapeLike, ARGS_CAP, RESULT_CAP } from "../lib/store.js";
import { createCapture, callIdOfResult, isErrorResult, MODE_IDS } from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

// 1. 出局分类：error 优先；blocked 特征（403/WAF/429/验证码/拒绝）；其余 ok
{
	ok("error 分类优先", classifyOutcome(true, "一切正常") === "error");
	ok("403 归 blocked", classifyOutcome(false, "HTTP/1.1 403 Forbidden") === "blocked");
	ok("waf 归 blocked", classifyOutcome(false, "request blocked by WAF") === "blocked");
	ok("429/限速归 blocked", classifyOutcome(false, "429 Too Many Requests") === "blocked");
	ok("验证码归 blocked", classifyOutcome(false, "please complete the captcha") === "blocked");
	ok("正常文本归 ok", classifyOutcome(false, "200 OK，返回登录页") === "ok");
	ok("中文响应归 ok", classifyOutcome(false, "操作成功") === "ok");
}

// 1b. 嵌套 tool-result 形态（真实管线实证 v0.2.1）：文本在内层 content
{
	const nested = [{ type: "tool-result", toolCallId: "call_x", content: [{ type: "text", text: "【pentest 拆分理论】作战流程×资产×漏洞类矩阵——目标契约已登记" }], isError: false }];
	ok("嵌套 tool-result 文本提取", resultTextOf(nested).includes("拆分理论") && resultTextOf(nested).includes("目标契约"));
	const flat = [{ type: "text", text: "平铺形态" }];
	ok("平铺形态仍提取", resultTextOf(flat) === "平铺形态");
	const deep = [{ type: "tool-result", content: [{ type: "tool-result", content: [{ type: "text", text: "两层嵌套" }] }] }];
	ok("多层嵌套递归提取", resultTextOf(deep) === "两层嵌套");
	ok("混合块取全部 text", resultTextOf([{ type: "text", text: "a" }, { type: "tool-result", content: [{ type: "text", text: "b" }] }]) === "a\nb");
}

// 2. 截断标记与参数归一
{
	const long = "x".repeat(RESULT_CAP + 100);
	const capped = resultTextOf([{ type: "text", text: long }]);
	ok("result 截断到上限并带标记", capped.length < long.length && capped.includes("[trace-vault 截断"));
	const args = argsTextOf(JSON.stringify({ url: "http://a", deep: { k: "v" } }));
	ok("args JSON 美化", args.includes("\n"));
	const nonJson = argsTextOf("裸字符串参数");
	ok("非 JSON args 原样", nonJson === "裸字符串参数");
}

// 3. 事件配对落库：tool/call + tool/result 按 callId 配对；仅安全模式入库；
//    结果 callId 双形态（source.callId / content[].toolCallId）均可配对
{
	const st = openStore(":memory:");
	const modes = new Map([["s1", "pentest"], ["s2", "plain-chat"]]);
	const modeResolver = (_ctx, sid) => modes.get(sid) ?? "";
	const cap = createCapture(null, st, modeResolver);
	cap.onCall("s1", { type: "tool/call", data: { name: "bash", callId: "c1", arguments: "{\"command\":\"curl -s http://t/login\"}" } });
	cap.onResult("s1", { type: "tool/result", data: { message: { source: { kind: "tool", callId: "c1" }, content: [{ type: "text", text: "HTTP/1.1 403 Forbidden\nblocked by waf" }] } } });
	const hit = searchTraces(st, { q: "waf" });
	ok("配对落库并按内容命中", hit.length === 1 && hit[0].tool === "bash" && hit[0].outcome === "blocked");
	const full = getTrace(st, hit[0].id);
	ok("全文含调用参数与响应", full.args.includes("curl -s") && full.result.includes("403 Forbidden"));
	// 非安全模式：不入库
	cap.onCall("s2", { type: "tool/call", data: { name: "bash", callId: "c9", arguments: "{}" } });
	cap.onResult("s2", { type: "tool/result", data: { message: { content: [{ toolCallId: "c9", type: "text", text: "ok" }] } } });
	ok("非安全模式不入库", searchTraces(st, { sessionId: "s2" }).length === 0);
	// content 块 toolCallId 形态（当前会话 s1）
	cap.onCall("s1", { type: "tool/call", data: { name: "fetch", callId: "c2", arguments: "{\"url\":\"http://t/api\"}" } });
	cap.onResult("s1", { type: "tool/result", data: { message: { content: [{ toolCallId: "c2", type: "text", text: "{\"code\":0}" }] } } });
	const hit2 = searchTraces(st, { q: "api" });
	ok("content 块 toolCallId 形态配对", hit2.length === 1 && hit2[0].tool === "fetch");
	// isError 事件（guard 拒绝的调用：data.error 显式存在，message.source.callId 仍在）
	cap.onCall("s1", { type: "tool/call", data: { name: "bash", callId: "c3", arguments: "{}" } });
	cap.onResult("s1", { type: "tool/result", data: { error: { message: "denied by guard" }, message: { source: { kind: "tool", callId: "c3" }, content: [{ type: "text", text: "Error: denied by guard", isError: true }] } } });
	const errs = searchTraces(st, { tool: "bash" });
	ok("显式 error 字段归 error 出局", errs.length === 2 && errs.some((r) => r.outcome === "error"));
	// 无 tool/call 前置的结果（事件流中途接入）：不落不炸
	cap.onResult("s1", { type: "tool/result", data: { message: { source: { kind: "tool", callId: "ghost" }, content: [{ type: "text", text: "x" }] } } });
	ok("未配对结果安全跳过", searchTraces(st, { q: "x" }).every((r) => r.id !== "s1:ghost"));
	// callId 提取器与错误位（纯函数）
	ok("callId 提取：source 形态", callIdOfResult({ data: { message: { source: { kind: "tool", callId: "a" } } } }) === "a");
	ok("callId 提取：content 块形态", callIdOfResult({ data: { message: { content: [{ toolCallId: "b" }] } } }) === "b");
	ok("错误位：块 isError", isErrorResult({ data: { message: { content: [{ isError: true }] } } }) === true);
	st.close();
}

// 4. 检索：LIKE 转义（% 按字面）、工具过滤、分页
{
	const st = openStore(":memory:");
	insertTrace(st, { id: "t1", sessionId: "s1", mode: "pentest", tool: "bash", args: "nmap -p 80 t", result: "100% complete" });
	insertTrace(st, { id: "t2", sessionId: "s1", mode: "pentest", tool: "fetch", args: "GET /api/v2", result: "code 0" });
	ok("% 按字面命中", searchTraces(st, { q: "100%" }).length === 1);
	ok("下划线按字面命中", insertTrace(st, { id: "t3", sessionId: "s1", mode: "pentest", tool: "bash", args: "x_y", result: "" }) && searchTraces(st, { q: "x_" }).length === 1);
	ok("工具过滤", searchTraces(st, { tool: "fetch" }).length === 1);
	ok("多关键词不命中时不误报", searchTraces(st, { q: "不存在的关键词" }).length === 0);
	const page1 = searchTraces(st, { limit: 2 });
	ok("limit 生效", page1.length === 2);
	st.close();
}

// 5. 最近一览与出局统计
{
	const st = openStore(":memory:");
	insertTrace(st, { id: "a", sessionId: "s1", mode: "pentest", tool: "bash", args: "", result: "ok", isError: false, durMs: 12 });
	insertTrace(st, { id: "b", sessionId: "s1", mode: "pentest", tool: "bash", args: "", result: "403 denied", isError: false });
	insertTrace(st, { id: "c", sessionId: "s1", mode: "pentest", tool: "fetch", args: "", result: "boom", isError: true });
	const stats = statsTraces(st, { sessionId: "s1" });
	ok("统计三分支计数", stats.total === 3 && stats.ok === 1 && stats.blocked === 1 && stats.error === 1);
	const recent = listRecent(st, { sessionId: "s1", limit: 2 });
	ok("最近一览新到旧", recent.length === 2 && recent[0].id === "s1:c".split(":")[1] ? recent[0].tool === "fetch" : false);
	ok("durMs 落库", getTrace(st, "a").durMs === 12);
	st.close();
}

// 6. 保留清理与总量上限
{
	const st = openStore(":memory:", { retentionDays: 14, maxRows: 3 });
	for (let i = 0; i < 5; i++) insertTrace(st, { id: `old${i}`, sessionId: "s", mode: "pentest", tool: "bash", args: "", result: `r${i}` });
	ok("总量上限淘汰最旧", capRows(st) === 2 && statsTraces(st).total === 3 && getTrace(st, "old0") === undefined && getTrace(st, "old4") !== undefined);
	st.db.prepare("UPDATE traces SET created_at = '2020-01-01 00:00:00' WHERE id = 'old4'").run();
	ok("过期清理", purgeOld(st) === 1 && getTrace(st, "old4") === undefined);
	st.close();
}

// 7. 模式清单完整性（九模式）
ok("九模式清单", Array.isArray(MODE_IDS) && MODE_IDS.length === 9);

// 8. apply 装配：defineTool 方言冒烟（真 dsh-tools）+ 事件接线 + 模式门禁
//    库走 DSH_TRACE_VAULT_DB 临时文件，不碰真实过程库。
{	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "trace-vault-"));
	process.env.DSH_TRACE_VAULT_DB = path.join(tmp, "t.db");
	const mod = await import("../lib/index.js");
	const { openStore, searchTraces } = await import("../lib/store.js");
	const registered = [];
	const handlers = {};
	const contexts = [];
	const fakeCtx = {
		on: (ev, fn) => { handlers[ev] = fn; },
		tools: { register: (tool) => registered.push(tool) },
		systemPrompt: { context: (c) => contexts.push(c) },
		agentPresets: { composedPreset: (agentCtx) => agentCtx?.preset ?? "pentest" },
		get: () => undefined
	};
	let threw = null;
	try { mod.apply(fakeCtx, {}); } catch (e) { threw = e; }
	ok("apply 不抛（defineTool 方言过检）", threw === null);
	const names = registered.map((t) => t?.name);
	ok("三工具注册", names.includes("trace_search") && names.includes("trace_get") && names.includes("trace_recent"));
	// 事件接线：tool/call + tool/result → 落库
	ok("session/event 已接线", typeof handlers["session/event"] === "function");
	handlers["session/event"]({ id: "sx" }, { type: "tool/call", data: { name: "bash", callId: "k1", arguments: "{\"command\":\"id\"}" } });
	handlers["session/event"]({ id: "sx" }, { type: "tool/result", data: { message: { source: { kind: "tool", callId: "k1" }, content: [{ type: "text", text: "uid=0(root)" }] } } });
	const st = openStore(process.env.DSH_TRACE_VAULT_DB);
	ok("apply 接线后事件落库", searchTraces(st, { q: "uid=0" }).length === 1);
	// 模式门禁：非安全模式 exec 拒用工具（composedPreset 依 agent.ctx.preset）
	const tool = registered.find((t) => t?.name === "trace_search");
	const denied = await tool.execute({ query: "x" }, { agent: { session: { id: "sx", header: {} }, ctx: { preset: "plain-chat" } } });
	ok("非安全模式工具拒绝", denied.ok === false && denied.error.includes("安全模式"));
	const allowed = await tool.execute({ query: "uid=0" }, { agent: { session: { id: "sx", header: {} }, ctx: {} } });
	ok("安全模式工具可用", allowed.ok === true && allowed.rows.length === 1);
	const renderText = tool.output.render(null, allowed)[0].text;
	ok("render 含命中行与 id", renderText.includes("sx:k1") && renderText.includes("bash"));
	st.close();
	delete process.env.DSH_TRACE_VAULT_DB;
	fs.rmSync(tmp, { recursive: true, force: true });
}

// 9. 失败归因信封（v0.2.0）：阈值/空信号/装配接线/窗口过滤
{
	const { buildOutcomeHint, ENVELOPE_TAG } = await import("../lib/index.js");
	const { openStore, insertTrace, statsTraces } = await import("../lib/store.js");
	ok("无 blocked 空串", buildOutcomeHint({ blocked: 0, ok: 5, error: 1 }) === "");
	ok("1 次不达阈值空串", buildOutcomeHint({ blocked: 1 }) === "");
	ok("2 次触发提示", (() => { const t = buildOutcomeHint({ blocked: 2 }); return typeof t === "string" && t.includes(ENVELOPE_TAG) && t.includes("blocked 2 次") && t.includes("trace_search"); })());
	ok("阈值可调", buildOutcomeHint({ blocked: 2 }, { threshold: 3 }) === "");
	// since 窗口过滤
	const st = openStore(":memory:");
	insertTrace(st, { id: "w1", sessionId: "s1", mode: "pentest", tool: "bash", args: "", result: "403 forbidden" });
	st.db.prepare("UPDATE traces SET created_at = '2020-01-01 00:00:00' WHERE id = 'w1'").run();
	insertTrace(st, { id: "w2", sessionId: "s1", mode: "pentest", tool: "bash", args: "", result: "waf blocked" });
	const recent = statsTraces(st, { sessionId: "s1", since: "2026-01-01 00:00:00" });
	ok("since 只统计窗口内", recent.blocked === 1);
	ok("无 since 统计全部", statsTraces(st, { sessionId: "s1" }).blocked === 2);
	st.close();
	// 装配接线：fakeCtx 捕获 systemPrompt.context 注册并渲染（含 blocked 事件后触发）
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "trace-vault-env-"));
	process.env.DSH_TRACE_VAULT_DB = path.join(tmp, "t.db");
	const mod = await import("../lib/index.js");
	const contexts = [];
	const handlers = {};
	const fakeCtx = {
		on: (ev, fn) => { handlers[ev] = fn; },
		tools: { register: () => {} },
		systemPrompt: { context: (c) => contexts.push(c) },
		agentPresets: { composedPreset: (agentCtx) => agentCtx?.preset ?? "pentest" },
		get: () => undefined
	};
	mod.apply(fakeCtx, {});
	ok("信封节已注册", contexts.length === 1 && contexts[0].name === "trace-vault");
	handlers["session/event"]({ id: "sx" }, { type: "tool/call", data: { name: "bash", callId: "b1", arguments: "{}" } });
	handlers["session/event"]({ id: "sx" }, { type: "tool/result", data: { message: { source: { kind: "tool", callId: "b1" }, content: [{ type: "text", text: "403 waf" }] } } });
	handlers["session/event"]({ id: "sx" }, { type: "tool/call", data: { name: "bash", callId: "b2", arguments: "{}" } });
	handlers["session/event"]({ id: "sx" }, { type: "tool/result", data: { message: { source: { kind: "tool", callId: "b2" }, content: [{ type: "text", text: "429 Too Many Requests" }] } } });
	const text = contexts[0].text({ agent: { ctx: {}, session: { id: "sx", header: {} } } });
	ok("blocked 聚集触发信封", text.includes("blocked 2 次") && text.includes("拦截信号"));
	ok("非安全模式渲染空", contexts[0].text({ agent: { ctx: { preset: "plain" }, session: { id: "sx", header: {} } } }) === "");
	ok("无 agent 渲染空", contexts[0].text({}) === "");
	delete process.env.DSH_TRACE_VAULT_DB;
	fs.rmSync(tmp, { recursive: true, force: true });
}


// 18. 人工介入画像 + 会话画像统计（评估指标最小集）
{
	const st = openStore(":memory:");
	const modes = new Map([["sx", "pentest"]]);
	const modeResolver = (_ctx, sid) => modes.get(sid) ?? "";
	const cap = createCapture(null, st, modeResolver);
	// blocked → ok 序列（自救信号应置位）
	cap.onCall("sx", { type: "tool/call", data: { name: "bash", callId: "b1", arguments: "{}" } });
	cap.onResult("sx", { type: "tool/result", data: { message: { source: { kind: "tool", callId: "b1" }, content: [{ type: "text", text: "403 forbidden by waf" }] } } });
	cap.onCall("sx", { type: "tool/call", data: { name: "fetch", callId: "b2", arguments: "{}" } });
	cap.onResult("sx", { type: "tool/result", data: { message: { source: { kind: "tool", callId: "b2" }, content: [{ type: "text", text: "ok" }] } } });
	// 真人消息入库为 (intervention)；插件注入前缀排除
	cap.onHuman("sx", { type: "user/message", data: { id: "human-1", source: { kind: "user" }, content: [{ type: "text", text: "换个路径试试" }] } });
	cap.onHuman("sx", { type: "user/message", data: { id: "auto-advance-x1", source: { kind: "user" }, content: [{ type: "text", text: "[auto-advance] 注入" }] } });
	cap.onHuman("sx", { type: "user/message", data: { id: "human-2", source: { kind: "plugin" }, content: [{ type: "text", text: "插件消息" }] } });
	const stats = sessionStats(st, { sessionId: "sx" });
	ok("介入画像：真人消息计 1 次（插件前缀与 plugin 源排除）", stats.interventions === 1);
	ok("自救信号：blocked 后推进到 ok", stats.selfRecovered === true && stats.blocked === 1 && stats.ok === 1);
	ok("成功率计算", stats.calls === 2 && stats.successRate === 50);
	ok("受阻工具 top 记账", stats.blockedTools.length === 1 && stats.blockedTools[0].startsWith("bash"));
	const empty = sessionStats(st, { sessionId: "nope" });
	ok("空会话画像不炸", empty.calls === 0 && empty.successRate === null && empty.selfRecovered === false);
	st.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
