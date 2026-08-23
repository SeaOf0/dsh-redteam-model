// dsh-session-pulse 离线单测：纯逻辑（进度/子代理分组/提示词提取/模式门控）+ session.mode 端点 + 信任栅栏。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { PULSE_MODES, MODE_LABELS, modeOk, progressOf, groupSubagents, SUB_STATUS_LABELS, promptEntries, textOf, clip, titleLine, parseTranscript } from "../lib/pulse.js";
import { dispatch, isTrustedRequest, subagentTranscript, ROUTE_PATH, checkCsrf } from "../lib/index.js";

let pass = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { console.log(`FAIL ${label}`); process.exitCode = 1; } };

// 1. 模式门控：九模式名单 + 判定（含服务端兜底）
ok("九模式名单齐（redteam + 八专业）", PULSE_MODES.length === 9 && PULSE_MODES.includes("redteam") && PULSE_MODES.includes("ctf-solver") && Object.keys(MODE_LABELS).length === 9);
ok("modeOk：直判/服务端兜底/组合名拒绝", modeOk("pentest", "") === true && modeOk("cordis", "incident-response") === true && modeOk("cordis", "") === false && modeOk("", "") === false);

// 2. 任务进度：todos 投影 → 汇总
ok("progressOf：null/空清单返回 null", progressOf(null) === null && progressOf([]) === null);
{
	const p = progressOf([{ status: "completed", content: "a" }, { status: "in_progress", content: "b" }, { status: "pending", content: "c" }, { status: "completed", content: "d" }]);
	ok("progressOf：计数与百分比", p.total === 4 && p.done === 2 && p.active === 1 && p.pending === 1 && p.pct === 50 && p.allDone === false);
	ok("progressOf：全完成态", progressOf([{ status: "completed" }, { status: "completed" }]).allDone === true);
}

// 3. 子代理目录分组：目录行 → 运行/已结束（one-shot=已完成、continuable=已结束）
{
	const g = groupSubagents({ entries: [
		{ id: "session-a", label: "Side: New thread", mode: "continuable", activity: "running", hasChildren: false },
		{ id: "b", label: "Mnemon idle checkpoint review", mode: "one-shot", activity: "inactive", hasChildren: false },
		{ id: "c", label: "并行复核", mode: "one-shot", activity: "running", hasChildren: true },
		{ id: "d", label: "旧线程", mode: "continuable", activity: "inactive", hasChildren: true }
	] });
	ok("分组：2 运行 / 2 已结束", g.running.length === 2 && g.finished.length === 2);
	ok("运行判定按 activity", g.running[0].id === "session-a" && g.running[1].id === "c" && g.running[1].hasChildren === true);
	ok("已结束状态语义（one-shot=已完成 / continuable=已结束）", g.finished[0].status === "completed" && g.finished[1].status === "ended" && SUB_STATUS_LABELS.completed === "已完成");
	ok("目录缺失/空目录返回空组", groupSubagents(null).running.length === 0 && groupSubagents({ entries: [] }).finished.length === 0);
	ok("坏行（无 id）跳过", groupSubagents({ entries: [null, { label: "x" }, { id: "ok", activity: "running" }] }).running.length === 1);
}

// 4. 提示词提取：chat 快照（order + nodes）→ user 节点清单
{
	const mk = (key, kind, data) => ({ key, kind, data });
	const nodes = new Map([
		["u1", mk("u1", "user", { kind: "user", seq: 2, time: 1787450000000, content: [{ type: "text", text: " 帮我测试 SQL 注入 " }, { type: "image", data: "…" }] })],
		["a1", mk("a1", "assistant-step", { content: [{ type: "text", text: "x" }] })],
		["u2", mk("u2", "user", { kind: "user", seq: 5, time: 1787450100000, content: [{ type: "text", text: "第一行\n第二行" }] })],
		["u5", mk("u5", "user", { kind: "user", seq: 8, time: 1787450400000, content: [{ type: "text", text: "长".repeat(60) }] })],
		["u3", mk("u3", "user", { kind: "user", seq: 6, time: 1787450200000, content: [{ type: "image" }] })],
		["u4", mk("u4", "user", { kind: "user", seq: 7, time: 1787450300000, content: [] })]
	]);
	const chat = { order: ["u1", "a1", "u2", "u3", "u4", "u5"], nodes };
	const list = promptEntries(chat, 40);
	ok("只收 user 节点且按 order 序", list.length === 3 && list[0].key === "u1" && list[1].key === "u2" && list[2].key === "u5");
	ok("文本提取（trim/多部件/跳过图片；纯图/空内容剔除）", list[0].text === "帮我测试 SQL 注入" && list[1].text === "第一行\n第二行");
	ok("预览裁剪带省略号", list[2].preview.length === 41 && list[2].preview.endsWith("…") && list[1].preview === "第一行\n第二行");
	ok("空快照/缺 nodes 安全", promptEntries(null).length === 0 && promptEntries({ order: ["x"], nodes: undefined }).length === 0);
	ok("textOf 跳过非 text 部件", textOf({ content: [{ type: "text", text: "a" }, { type: "tool", x: 1 }] }) === "a" && textOf({}) === "");
	ok("clip 裁剪边界", clip("abc", 5) === "abc" && clip("abcdef", 5) === "abcde…");
	ok("titleLine 首个非空行为卡标题（裁剪/全空回退）", titleLine("  \n帮我测试注入\n第二行") === "帮我测试注入" && titleLine("x".repeat(50), 42).endsWith("…") && titleLine(" \n \n") === "");
}

// 5. 子代理转写：事件流提取（user/assistant 文本、reasoning 跳过、tool 行、上限）
{
	const ev = (type, seq, data) => JSON.stringify({ type, seq, time: 1787450000000 + seq, data });
	const jsonl = [
		ev("session", 1, { id: "x" }),
		ev("user/message", 9, { content: [{ type: "text", text: " 你是复核子代理。目标：X " }, { type: "image" }] }),
		ev("assistant/message", 20, { message: { content: [{ type: "reasoning", text: "思考（不进转写）" }, { type: "text", text: "开始复核" }] } }),
		ev("tool/call", 21, { callId: "c1", name: "skill", arguments: '{"name": "code-audit"}' }),
		ev("assistant/message", 30, { message: { content: [{ type: "reasoning", text: "..." }] } }),
		ev("assistant/message", 31, { message: { content: [{ type: "text", text: "结论：未发现" }] } }),
		"不是 json 的一行",
		ev("tool/result", 40, { message: { source: { callId: "c1" } } })
	].join("\n");
	const tr = parseTranscript(jsonl);
	ok("转写：user/assistant 文本 + tool 行按序、reasoning 与坏行剔除", JSON.stringify(tr.map((e) => e.kind)) === JSON.stringify(["user", "assistant", "tool", "assistant"]) && tr[0].text === "你是复核子代理。目标：X" && tr[2].name === "skill" && tr[2].brief.includes("code-audit"));
	ok("转写：纯 reasoning 的 assistant 步骤不产生空条目", !tr.some((e) => e.kind === "assistant" && e.text === ""));
	const capped = parseTranscript(ev("user/message", 1, { content: [{ type: "text", text: "长".repeat(2000) }] }), { text: 100 });
	ok("转写：单条文本截断", capped[0].text.length === 101 && capped[0].text.endsWith("…"));
	ok("转写：空/非字符串输入安全", parseTranscript("").length === 0 && parseTranscript(null).length === 0);
}

// 5b. 子代理转写端点：多帧 zstd 日志定位与解压（临时目录造真实多帧文件）
{
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sp-"));
	const sid = "01234567-abcd-ef01-2345-6789abcdef01";
	const ws = path.join(dir, "--workspace-a--", sid);
	fs.mkdirSync(ws, { recursive: true });
	const lines = [
		JSON.stringify({ type: "session", seq: 1, data: { id: sid } }),
		JSON.stringify({ type: "user/message", seq: 2, time: 1787450000000, data: { content: [{ type: "text", text: "任务：复核" }] } }),
		JSON.stringify({ type: "assistant/message", seq: 3, time: 1787450000001, data: { message: { content: [{ type: "text", text: "已复核" }] } } }),
		JSON.stringify({ type: "tool/call", seq: 4, time: 1787450000002, data: { callId: "c1", name: "grep", arguments: "pattern" } })
	];
	// 宿主落盘形态：每次一行一个独立 zstd 帧，直接拼接
	const blob = Buffer.concat(lines.map((l) => zlib.zstdCompressSync(Buffer.from(l + "\n"))));
	fs.writeFileSync(path.join(ws, "session.jsonl.zstd"), blob);
	const tr = subagentTranscript(sid, dir);
	ok("多帧 zstd 定位+全量解压+转写", tr.sessionId === sid && JSON.stringify(tr.entries.map((e) => e.kind)) === JSON.stringify(["user", "assistant", "tool"]) && tr.entries[0].text === "任务：复核");
	await assert.rejects(async () => subagentTranscript("not-exist-0123456789", dir), /不存在/);
	await assert.rejects(async () => subagentTranscript("../evil", dir), /非法/);
	fs.rmSync(dir, { recursive: true, force: true });
}

// 6. session.mode 端点：composedPreset 权威源 → header 兜底 → 未知为空
{
	const fakeCtx = (preset, headerPreset) => ({
		agentPresets: { composedPreset: () => preset },
		get: () => ({ get: (id) => ({ id, ctx: {}, session: { header: { agentPreset: headerPreset } } }) })
	});
	const mkAgents = (headerPreset) => ({ get: (id) => ({ id, ctx: { __x: 1 }, session: { header: { agentPreset: headerPreset } } }) });
	const r1 = await dispatch({ agentPresets: { composedPreset: () => "pentest" }, get: () => mkAgents("cordis") }, "session.mode", { sessionId: "s1" });
	ok("session.mode：composedPreset 直判", r1.mode === "pentest");
	const r2 = await dispatch({ agentPresets: { composedPreset: () => "cordis" }, get: () => mkAgents("cloud-security") }, "session.mode", { sessionId: "s2" });
	ok("session.mode：组合名退化走 header 兜底", r2.mode === "cloud-security");
	const r3 = await dispatch({ agentPresets: { composedPreset: () => "cordis" }, get: () => mkAgents("cordis") }, "session.mode", { sessionId: "s3" });
	ok("session.mode：非九模式返回空串", r3.mode === "");
	const r4 = await dispatch({ agentPresets: { composedPreset: () => "redteam" }, get: () => mkAgents("") }, "session.mode", { sessionId: "s4" });
	ok("session.mode：redteam 总控在名单内", r4.mode === "redteam");
	await assert.rejects(() => dispatch(null, "session.mode", {}), /sessionId required/);
	await assert.rejects(() => dispatch(null, "unknown.x", {}), /unknown endpoint/);
}

// 6. 信任栅栏：loopback 放行、外域拒、跨源 Origin 拒
ok("栅栏四态",
	isTrustedRequest({ headers: { host: "127.0.0.1:3080" } }, []) === true &&
	isTrustedRequest({ headers: { host: "evil.com:3080" } }, []) === false &&
	isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://evil.com" } }, []) === false &&
	isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://127.0.0.1:9999" } }, []) === false &&
	isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://127.0.0.1:3080" } }, []) === true &&
	isTrustedRequest({}, []) === false);
ok("路由前缀", ROUTE_PATH === "/dsh-session-pulse");

ok("CSRF 头校验：匹配放行/缺失或错值拒",
	checkCsrf({ headers: { "x-dsh-csrf": "T" } }, "T") === true &&
	checkCsrf({ headers: { "x-dsh-csrf": "X" } }, "T") === false &&
	checkCsrf({ headers: {} }, "T") === false && checkCsrf({}, "T") === false);

console.log(`\n${pass} passed`);
