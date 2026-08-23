window.__ModuleLoader__.load({ id: "@dsh-external/dsh-session-pulse", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-session-pulse client — 会话状态面板（九模式）：
//   1) 对话栏右上角：任务进度 chip（todos 投影）→ 点击展开任务面板（逐条勾选）；
//      子代理 chip → 右侧「子智能体目录」抽屉（锚定对话列右侧）；
//   2) 抽屉内点名子代理 → 就地展开其运行内容（服务端转写：任务/文本/工具行），返回不离开主会话；
//   3) 对话栏内左侧居中「提示词」栏（锚定对话列，非全局视口）：悬停预览、点击定位消息锚点。
// 纯逻辑镜像 lib/pulse.js（双侧同步的事实源在那里，test 以它为准）。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useRef = React.useRef, useCallback = React.useCallback, useSyncExternalStore = React.useSyncExternalStore;

//#region 纯逻辑镜像（与 lib/pulse.js 保持逐行为等价）

var PULSE_MODES = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];
var MODE_LABELS = { redteam: "安全研究员", pentest: "渗透测试", "code-audit": "代码审计", "binary-analysis": "二进制分析", "attack-defense": "攻防评估", "av-evasion": "免杀对抗", "incident-response": "应急溯源", "cloud-security": "云安全攻防", "ctf-solver": "CTF 解题" };

function modeOk(agentPreset, serverMode) {
	if (PULSE_MODES.includes(agentPreset)) return true;
	if (serverMode && PULSE_MODES.includes(serverMode)) return true;
	return false;
}
function progressOf(todos) {
	if (!Array.isArray(todos) || todos.length === 0) return null;
	var done = 0, active = 0;
	for (var i = 0; i < todos.length; i++) {
		var t = todos[i];
		if (t && t.status === "completed") done++;
		else if (t && t.status === "in_progress") active++;
	}
	var total = todos.length;
	return { total: total, done: done, active: active, pending: total - done - active, pct: Math.round((done / total) * 100), allDone: done === total };
}
function groupSubagents(catalog) {
	var entries = catalog && Array.isArray(catalog.entries) ? catalog.entries : [];
	var running = [], finished = [];
	for (var i = 0; i < entries.length; i++) {
		var e = entries[i];
		if (!e || typeof e.id !== "string") continue;
		var row = {
			id: e.id,
			label: String(e.label || e.id).slice(0, 80),
			mode: e.mode === "continuable" ? "continuable" : "one-shot",
			running: e.activity === "running",
			hasChildren: !!e.hasChildren,
			status: e.activity === "running" ? "running" : (e.mode === "continuable" ? "ended" : "completed")
		};
		(row.running ? running : finished).push(row);
	}
	return { running: running, finished: finished };
}
var SUB_STATUS_LABELS = { running: "运行中", completed: "已完成", ended: "已结束" };
function textOf(data) {
	var parts = data && data.content;
	if (!Array.isArray(parts)) return "";
	var out = [];
	for (var i = 0; i < parts.length; i++) {
		var p = parts[i];
		if (p && p.type === "text" && typeof p.text === "string" && p.text.trim()) out.push(p.text.trim());
	}
	return out.join("\n");
}
function clip(text, max) {
	var t = String(text == null ? "" : text);
	return t.length > max ? t.slice(0, max) + "…" : t;
}
function promptEntries(chat, previewMax) {
	var max = previewMax || 160;
	var order = chat && chat.order ? chat.order : [];
	var nodes = chat && chat.nodes;
	if (!nodes || typeof nodes.get !== "function") return [];
	var out = [];
	for (var i = 0; i < order.length; i++) {
		var node = nodes.get(order[i]);
		var data = (node && node.data) || node;
		var kind = node && node.kind != null ? node.kind : data.kind;
		if (kind !== "user") continue;
		var text = textOf(data);
		if (!text) continue;
		out.push({ key: order[i], seq: Number(data.seq) || 0, time: Number(data.time) || 0, text: text, preview: clip(text, max) });
	}
	return out;
}
function fmtTime(ms) {
	if (!ms) return "";
	var d = new Date(ms);
	var p = function (n) { return (n < 10 ? "0" : "") + n; };
	return p(d.getHours()) + ":" + p(d.getMinutes());
}
function titleLine(text, max) {
	var m = max || 42;
	var lines = String(text == null ? "" : text).split("\n");
	for (var i = 0; i < lines.length; i++) {
		var t = lines[i].trim();
		if (t) return t.length > m ? t.slice(0, m) + "…" : t;
	}
	return "";
}
var SEARCH_ICON = React.createElement("svg", { width: 11, height: 11, viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", strokeWidth: 1.6 },
	React.createElement("circle", { cx: 6.8, cy: 6.8, r: 4.6 }),
	React.createElement("line", { x1: 10.4, y1: 10.4, x2: 14.2, y2: 14.2, strokeLinecap: "round" }));

//#endregion

//#region 样式

var CSS = [
	".dsh-sp-chips{display:flex;gap:6px;align-items:center;flex:none}",
	".dsh-sp-chip{display:inline-flex;gap:6px;align-items:center;border:1px solid rgba(58,157,255,.42);border-radius:999px;background:rgba(58,157,255,.08);color:#cfe6ff;padding:2px 10px;font-size:11px;line-height:18px;white-space:nowrap}",
	".dsh-sp-chip b{font-weight:600;color:#e8f3ff}",
	".dsh-sp-chip.is-btn{cursor:pointer}",
	".dsh-sp-chip.is-btn:hover{background:rgba(58,157,255,.22)}",
	".dsh-sp-bar{width:54px;height:4px;border-radius:2px;background:rgba(58,157,255,.25);overflow:hidden;flex:none}",
	".dsh-sp-bar i{display:block;height:100%;background:linear-gradient(90deg,#3f8ef7,#38d4ff)}",
	".dsh-sp-chip.is-done{border-color:rgba(124,227,176,.55);background:rgba(124,227,176,.10);color:#9fe8c5}",
	".dsh-sp-chip.is-done .dsh-sp-bar i{background:linear-gradient(90deg,#3fce9a,#7ce3b0)}",
	".dsh-sp-chip.is-live .dsh-sp-dot{background:#38d4ff;box-shadow:0 0 6px rgba(56,212,255,.8);animation:dsh-sp-blink 1.2s ease-in-out infinite}",
	".dsh-sp-dot{width:6px;height:6px;border-radius:50%;background:rgba(124,200,255,.5);flex:none}",
	"@keyframes dsh-sp-blink{50%{opacity:.35}}",
	".dsh-sp-tasks{position:fixed;z-index:82;width:300px;max-height:60vh;overflow-y:auto;border:1px solid rgba(58,157,255,.5);border-radius:10px;background:rgba(8,24,46,.97);backdrop-filter:blur(12px);box-shadow:0 10px 36px rgba(2,8,20,.55);padding:10px 12px}",
	".dsh-sp-tasks-head{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:700;color:#e8f3ff;letter-spacing:1px;margin-bottom:8px}",
	".dsh-sp-tasks-head span{flex:1}",
	".dsh-sp-task{display:flex;gap:8px;align-items:flex-start;font-size:12px;line-height:1.6;color:#b9d2ee;padding:3px 0}",
	".dsh-sp-task i{width:13px;height:13px;border-radius:50%;border:1.5px solid rgba(124,200,255,.55);flex:none;margin-top:2px;box-sizing:border-box}",
	".dsh-sp-task.is-done{color:#7d97b8;text-decoration:line-through}",
	".dsh-sp-task.is-done i{border-color:#3fce9a;background:#3fce9a;box-shadow:inset 0 0 0 2.5px rgba(8,24,46,.97)}",
	".dsh-sp-task.is-active i{border-color:#38d4ff;animation:dsh-sp-blink 1.2s ease-in-out infinite}",
	".dsh-sp-rail{position:fixed;z-index:60;display:flex;flex-direction:column;gap:5px;max-height:62vh;width:132px;overflow-y:auto;overscroll-behavior:contain;padding:2px;scrollbar-width:thin}",
	".dsh-sp-rail-head{display:flex;align-items:center;gap:5px;font-size:10px;color:#7d97b8;letter-spacing:1px;padding:0 4px 2px;flex:none}",
	".dsh-sp-rail-head svg{flex:none;opacity:.7}",
	".dsh-sp-pitem{position:relative;border:1px solid rgba(255,255,255,.10);border-radius:7px;background:rgba(255,255,255,.05);color:#9db3cd;font-size:10.5px;line-height:15px;padding:2px 8px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:none;transition:background .15s,color .15s,border-color .15s}",
	".dsh-sp-pitem:hover{color:#dbe8f6;border-color:rgba(140,170,210,.3)}",
	".dsh-sp-pitem.is-open{background:#17191d;border-color:#3c4149;color:#f2f4f8}",
	".dsh-sp-pexpand{position:fixed;z-index:62;width:344px;border-radius:9px 7px 7px 9px;background:#17191d;border:1px solid #3c4149;box-shadow:0 10px 34px rgba(2,8,20,.55);color:#f2f4f8;cursor:pointer;overflow:hidden}",
	".dsh-sp-pexpand-title{font-size:11.5px;font-weight:700;color:#ffffff;padding:8px 12px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
	".dsh-sp-pexpand-body{font-size:10.5px;line-height:1.65;color:#c3ccd9;padding:5px 12px 6px;white-space:pre-wrap;word-break:break-word;display:-webkit-box;-webkit-line-clamp:6;-webkit-box-orient:vertical;overflow:hidden}",
	".dsh-sp-pexpand-foot{display:flex;align-items:center;gap:8px;padding:5px 12px 7px;border-top:1px solid rgba(255,255,255,.08);font-size:10px;color:#8a94a3}",
	".dsh-sp-pexpand-jump{margin-left:auto;border:1px solid #4a5568;border-radius:6px;background:rgba(255,255,255,.06);color:#e2e8f0;font-size:10.5px;cursor:pointer;padding:1px 9px;flex:none}",
	".dsh-sp-pexpand-jump:hover{background:rgba(255,255,255,.14)}",
	".dsh-sp-drawer{position:fixed;z-index:80;width:300px;display:flex;flex-direction:column;border-left:1px solid rgba(58,157,255,.45);background:rgba(8,24,46,.97);backdrop-filter:blur(14px);box-shadow:-12px 0 36px rgba(2,8,20,.5)}",
	".dsh-sp-drawer-head{display:flex;align-items:center;gap:8px;padding:12px 14px;border-bottom:1px solid rgba(58,157,255,.3);flex:none}",
	".dsh-sp-drawer-title{font-size:13px;font-weight:700;letter-spacing:2px;color:#e8f3ff;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
	".dsh-sp-drawer-x{border:1px solid rgba(58,157,255,.45);border-radius:6px;background:rgba(58,157,255,.1);color:#cfe6ff;font-size:11px;cursor:pointer;padding:2px 9px;flex:none}",
	".dsh-sp-drawer-x:hover{background:rgba(58,157,255,.25)}",
	".dsh-sp-back{border:1px solid rgba(58,157,255,.45);border-radius:6px;background:rgba(58,157,255,.1);color:#cfe6ff;font-size:11px;cursor:pointer;padding:2px 9px;flex:none}",
	".dsh-sp-back:hover{background:rgba(58,157,255,.25)}",
	".dsh-sp-drawer-body{flex:1;overflow-y:auto;padding:10px 12px;display:flex;flex-direction:column;gap:12px}",
	".dsh-sp-group-head{font-size:11px;color:#8fb4d9;letter-spacing:1px;flex:none}",
	".dsh-sp-empty{font-size:11.5px;color:#7d97b8;line-height:1.8;padding:4px 2px}",
	".dsh-sp-sub{border:1px solid rgba(58,157,255,.3);border-radius:8px;padding:7px 10px;background:rgba(12,32,62,.6);cursor:pointer}",
	".dsh-sp-sub:hover{border-color:rgba(56,212,255,.6);background:rgba(58,157,255,.14)}",
	".dsh-sp-sub-label{font-size:12px;color:#e8f3ff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
	".dsh-sp-sub-meta{display:flex;align-items:center;gap:6px;margin-top:3px;font-size:10.5px;color:#7d97b8}",
	".dsh-sp-tag{border:1px solid rgba(58,157,255,.4);border-radius:4px;padding:0 5px;font-size:9.5px;color:#7cc8ff;flex:none}",
	".dsh-sp-tag.is-run{border-color:rgba(56,212,255,.7);color:#38d4ff}",
	".dsh-sp-tag.is-done{border-color:rgba(124,227,176,.5);color:#9fe8c5}",
	".dsh-sp-tr-meta{display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:10.5px;color:#7d97b8}",
	".dsh-sp-tr{font-size:11.5px;line-height:1.7;color:#b9d2ee;white-space:pre-wrap;word-break:break-word;border-radius:6px;padding:6px 9px;margin-bottom:6px}",
	".dsh-sp-tr.is-user{background:rgba(56,212,255,.09);border-left:3px solid rgba(56,212,255,.65);color:#d8ecff}",
	".dsh-sp-tr.is-asst{border-left:3px solid rgba(124,200,255,.35);padding-left:9px}",
	".dsh-sp-toolrow{display:flex;gap:6px;align-items:baseline;font-size:11px;color:#8fb4d9;padding:2px 0 2px 12px}",
	".dsh-sp-toolname{color:#7cc8ff;flex:none;font-weight:600}",
	".dsh-sp-toolbrief{min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#7d97b8}",
	".dsh-sp-loading{font-size:11.5px;color:#7d97b8;padding:16px 4px;text-align:center}",
	".dsh-sp-toast{position:fixed;right:18px;bottom:18px;z-index:90;max-width:360px;padding:9px 13px;border-radius:8px;border:1px solid rgba(58,157,255,.5);background:rgba(8,24,46,.94);backdrop-filter:blur(12px);color:#d8ecff;font-size:12px;box-shadow:0 6px 24px rgba(2,8,20,.55)}",
	".dsh-sp-toast.is-err{border-color:rgba(255,120,120,.55);color:#ffd6d6}",
	".dsh-sp-flash{animation:dsh-sp-flash 1.6s ease-out 1}",
	"@keyframes dsh-sp-flash{0%{background:rgba(56,212,255,.28);box-shadow:0 0 0 3px rgba(56,212,255,.25)}100%{background:transparent;box-shadow:0 0 0 3px transparent}}"
].join("\n");
function installStyles() {
	var style = document.createElement("style");
	style.id = "dsh-sp-style";
	style.textContent = CSS;
	document.head.appendChild(style);
	return function () { style.remove(); };
}

//#endregion

/** 会话消息流是否在视口内（其他标签页时锚点不在 DOM——提示词栏随之隐藏）。 */
function chatAnchorsVisible() {
	return !!document.querySelector("[data-conversation-scroll] [data-chat-anchor-key]");
}
function anchorEl(key) {
	try {
		var k = typeof CSS !== "undefined" && CSS.escape ? CSS.escape(key) : key.replace(/"/g, '\\"');
		return document.querySelector('[data-chat-anchor-key="' + k + '"]');
	} catch { return null; }
}
/** 对话列元素（含头部与滚动区的整列——rail/抽屉/任务面板全部锚定其内，非全局视口）。 */
function conversationColumnEl() {
	var scroller = document.querySelector("[data-conversation-scroll]");
	return scroller ? scroller.parentElement : null;
}

function PulseRoot(props) {
	var sessionsStore = props.pulseSessions;
	var sessionId = props.sessionId != null ? String(props.sessionId) : "";
	var useSession = props.useSession;
	var useProjection = props.useProjection;

	var tasksOpen = useState(false); var setTasksOpen = tasksOpen[1];
	var drawerOpen = useState(false); var setDrawerOpen = drawerOpen[1];
	var detailId = useState(""); var setDetailId = detailId[1];
	var hoverKey = useState(""); var setHoverKey = hoverKey[1];
	var hoverRect = useState(null); var setHoverRect = hoverRect[1];
	var toast = useState(null); var setToast = toast[1];
	var toastTimer = useRef(0);
	var serverMode = useState(""); var setServerMode = serverMode[1];
	var serverAsked = useRef("");
	var catalogAsked = useRef("");
	var chatVis = useState(false); var setChatVis = chatVis[1];
	var colRect = useState(null); var setColRect = colRect[1];
	var leaveTimer = useRef(0);

	var list = useSyncExternalStore(sessionsStore.list.subscribe, sessionsStore.list.getSnapshot);
	var summary = sessionId ? list.byId[sessionId] : undefined;
	var agentPreset = summary && summary.agentPreset ? String(summary.agentPreset) : "";

	// 服务端兜底：列表源 agentPreset 退化（宿主重启后组合名）时问一次真相
	useEffect(function () {
		if (PULSE_MODES.includes(agentPreset)) { serverAsked.current = ""; if (serverMode[0]) setServerMode(""); return; }
		if (!sessionId || serverAsked.current === sessionId) return;
		serverAsked.current = sessionId;
		postCsrf(ROUTE_BASE + "/session.mode", { sessionId: sessionId })
			.then(function (r) { return r.json(); })
			.then(function (r) { if (r && r.mode) setServerMode(r.mode); })
			.catch(function () { });
	}, [sessionId, agentPreset]);

	// 目录预取（chip 计数可见即可，不必等抽屉打开）
	useEffect(function () {
		if (!sessionId || catalogAsked.current === sessionId) return;
		catalogAsked.current = sessionId;
		try { if (typeof sessionsStore.refreshSubagents === "function") sessionsStore.refreshSubagents(sessionId); } catch { /* 目录服务不可用 */ }
	}, [sessionId]);

	// 抽屉打开期间订阅目录成员实时更新
	useEffect(function () {
		if (!drawerOpen[0] || !sessionId) return;
		try {
			if (typeof sessionsStore.refreshSubagents === "function") sessionsStore.refreshSubagents(sessionId);
			if (typeof sessionsStore.setSubagentCatalogOpen === "function") sessionsStore.setSubagentCatalogOpen(sessionId, true);
		} catch { /* 同上 */ }
		return function () {
			try { if (typeof sessionsStore.setSubagentCatalogOpen === "function") sessionsStore.setSubagentCatalogOpen(sessionId, false); } catch { /* 同上 */ }
		};
	}, [drawerOpen[0], sessionId]);

	// 提示词栏可见性：消息流锚点在 DOM 才显示（切到图谱等标签页自动隐藏）
	useEffect(function () {
		var t = 0;
		var check = function () {
			window.clearTimeout(t);
			t = window.setTimeout(function () { setChatVis(chatAnchorsVisible()); }, 120);
		};
		setChatVis(chatAnchorsVisible());
		var mo = new MutationObserver(check);
		mo.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["aria-selected"] });
		return function () { window.clearTimeout(t); mo.disconnect(); };
	}, []);

	// 对话列矩形跟踪：rail/抽屉/任务面板锚定对话列内（列尺寸或位置变化即重算）
	useEffect(function () {
		var measure = function () {
			var el = conversationColumnEl();
			if (!el) { setColRect(null); return; }
			var r = el.getBoundingClientRect();
			setColRect({ left: r.left, top: r.top, width: r.width, height: r.height });
		};
		measure();
		var ro = null;
		var mo = new MutationObserver(function () {
			// 对话列可能随标签页切换重建——重建后重新挂 ResizeObserver
			var el = conversationColumnEl();
			if (el && ro && ro.__el !== el) { ro.disconnect(); ro.__el = el; ro.observe(el); }
			measure();
		});
		mo.observe(document.body, { childList: true, subtree: true });
		try {
			ro = new ResizeObserver(measure);
			var el0 = conversationColumnEl();
			if (el0) { ro.__el = el0; ro.observe(el0); }
		} catch { ro = null; }
		window.addEventListener("resize", measure);
		return function () {
			mo.disconnect();
			if (ro) ro.disconnect();
			window.removeEventListener("resize", measure);
		};
	}, []);

	var progress = useProjection ? useProjection("todos") : null;
	var chat = useSession ? useSession(function (s) { return s.chat; }) : null;
	var running = useSession ? useSession(function (s) { return s.running; }) : false;

	// 门控在全部 hooks 之后（九模式之外不渲染）
	if (!modeOk(agentPreset, serverMode[0])) return null;

	function say(text, err) {
		setToast({ text: text, err: !!err });
		window.clearTimeout(toastTimer.current);
		toastTimer.current = window.setTimeout(function () { setToast(null); }, 2600);
	}

	var prog = progressOf(progress);
	var groups = groupSubagents(list.subagentsByParent ? list.subagentsByParent[sessionId] : null);
	var prompts = promptEntries(chat);
	var modeId = PULSE_MODES.includes(agentPreset) ? agentPreset : serverMode[0];
	var subTotal = groups.running.length + groups.finished.length;
	var col = colRect[0];

	function locate(key) {
		var el = anchorEl(key);
		if (!el) { say("该提示词不在当前已加载区间——先在消息流里向上滚动加载更早消息", true); return; }
		try { el.scrollIntoView({ behavior: "smooth", block: "center" }); } catch { el.scrollIntoView(); }
		el.classList.remove("dsh-sp-flash");
		void el.offsetWidth;
		el.classList.add("dsh-sp-flash");
		window.setTimeout(function () { el.classList.remove("dsh-sp-flash"); }, 1700);
	}
	function openDetail(id) {
		setDetailId(id);
	}


	return React.createElement(React.Fragment, null,
		React.createElement("span", { className: "dsh-sp-chips" },
			prog ? React.createElement("button", {
				type: "button",
				className: "dsh-sp-chip is-btn" + (prog.allDone ? " is-done" : (running ? " is-live" : "")),
				onClick: function () { setTasksOpen(!tasksOpen[0]); setDrawerOpen(false); },
				title: "任务进度（点击展开任务面板）：" + prog.done + "/" + prog.total + " 已完成" + (prog.active ? "，" + prog.active + " 进行中" : "")
			},
			React.createElement("i", { className: "dsh-sp-dot" }),
			"任务 ", React.createElement("b", null, prog.done + "/" + prog.total),
			React.createElement("span", { className: "dsh-sp-bar" }, React.createElement("i", { style: { width: prog.pct + "%" } }))) : null,
			React.createElement("button", {
				type: "button",
				className: "dsh-sp-chip is-btn",
				onClick: function () { setDrawerOpen(!drawerOpen[0]); setTasksOpen(false); setDetailId(""); },
				title: "子智能体目录（共 " + subTotal + " 个）"
			},
			"子代理 ", React.createElement("b", null, String(subTotal)),
			groups.running.length ? React.createElement("span", null, " · " + groups.running.length + " 运行中") : null)),
		tasksOpen[0] && prog && col ? React.createElement(TaskPanel, {
			prog: prog, todos: progress, col: col, onClose: function () { setTasksOpen(false); }
		}) : null,
		drawerOpen[0] && col ? React.createElement(SubagentDrawer, {
			groups: groups, modeLabel: MODE_LABELS[modeId] || "", detailId: detailId[0],
			onClose: function () { setDrawerOpen(false); setDetailId(""); },
			onBack: function () { setDetailId(""); },
			openDetail: openDetail, say: say, col: col
		}) : null,
		chatVis[0] && prompts.length && col ? React.createElement(PromptRail, {
			prompts: prompts, hoverKey: hoverKey[0], hoverRect: hoverRect[0], col: col,
			onHover: function (key, rect) {
				window.clearTimeout(leaveTimer.current);
				setHoverKey(key);
				setHoverRect(rect);
			},
			onLeave: function () {
				window.clearTimeout(leaveTimer.current);
				leaveTimer.current = window.setTimeout(function () { setHoverKey(""); setHoverRect(null); }, 140);
			},
			locate: locate
		}) : null,
		toast[0] ? React.createElement("div", { className: "dsh-sp-toast" + (toast[0].err ? " is-err" : "") }, toast[0].text) : null);
}

/** 任务面板：右上角对话列内下弹，逐条任务勾选（完成绿实心、进行中呼吸、待办空心）。 */
function TaskPanel(props) {
	var todos = Array.isArray(props.todos) ? props.todos : [];
	useEffect(function () {
		var onKey = function (e) { if (e.key === "Escape") props.onClose(); };
		window.addEventListener("keydown", onKey);
		return function () { window.removeEventListener("keydown", onKey); };
	}, []);
	var c = props.col;
	return React.createElement("div", {
		className: "dsh-sp-tasks",
		style: { left: Math.max(8, c.left + c.width - 312), top: c.top + 44 }
	},
	React.createElement("div", { className: "dsh-sp-tasks-head" },
		React.createElement("span", null, "任务 " + props.prog.done + "/" + props.prog.total + (props.prog.allDone ? " · 全部完成" : "")),
		React.createElement("button", { type: "button", className: "dsh-sp-drawer-x", onClick: props.onClose }, "关闭")),
	todos.map(function (t, i) {
		var st = t && t.status === "completed" ? "is-done" : (t && t.status === "in_progress" ? "is-active" : "");
		return React.createElement("div", { key: i, className: "dsh-sp-task " + st, title: t && t.content ? t.content : "" },
			React.createElement("i", null),
			React.createElement("span", null, t && t.content ? t.content : "（空）"));
	}));
}

/**
 * 子智能体目录抽屉（锚定对话列右侧）。两层视图：
 * 目录（正在运行/已结束分组）↔ 详情（点名子代理的就地转写——任务/文本/工具行；不离开主会话）。
 */
function SubagentDrawer(props) {
	var groups = props.groups;
	var col = props.col;
	useEffect(function () {
		var onKey = function (e) { if (e.key === "Escape") { if (props.detailId) props.onBack(); else props.onClose(); } };
		window.addEventListener("keydown", onKey);
		return function () { window.removeEventListener("keydown", onKey); };
	}, [props.detailId]);
	var c = col;
	return React.createElement("div", {
		className: "dsh-sp-drawer",
		style: { left: c.left + c.width - 300, top: c.top, height: c.height }
	},
	React.createElement("div", { className: "dsh-sp-drawer-head" },
		props.detailId ? React.createElement("button", { type: "button", className: "dsh-sp-back", onClick: props.onBack }, "返回目录") : null,
		React.createElement("span", { className: "dsh-sp-drawer-title" }, props.detailId ? "子代理运行内容" : "子智能体目录"),
		!props.detailId && props.modeLabel ? React.createElement("span", { className: "dsh-sp-tag" }, props.modeLabel) : null,
		React.createElement("button", { type: "button", className: "dsh-sp-drawer-x", onClick: props.onClose }, "关闭")),
	React.createElement("div", { className: "dsh-sp-drawer-body" },
		props.detailId
			? React.createElement(SubagentDetail, { id: props.detailId, groups: groups, say: props.say })
			: React.createElement(React.Fragment, null,
				React.createElement("div", { className: "dsh-sp-group-head" }, "正在运行 · " + groups.running.length),
				groups.running.length === 0
					? React.createElement("div", { className: "dsh-sp-empty" }, "没有正在运行的子智能体")
					: groups.running.map(function (s) { return subRow(props, s); }),
				React.createElement("div", { className: "dsh-sp-group-head" }, "已结束 · " + groups.finished.length),
				groups.finished.map(function (s) { return subRow(props, s); }))));
}
function subRow(props, s) {
	return React.createElement("div", {
		key: s.id, className: "dsh-sp-sub", onClick: function () { props.openDetail(s.id); },
		title: (s.mode === "continuable" ? "可持续子代理" : "单次子代理") + "——点击查看运行内容"
	},
	React.createElement("div", { className: "dsh-sp-sub-label" }, s.label),
	React.createElement("div", { className: "dsh-sp-sub-meta" },
		React.createElement("span", { className: "dsh-sp-tag" + (s.running ? " is-run" : " is-done") }, SUB_STATUS_LABELS[s.status] || s.status),
		s.mode === "continuable" ? React.createElement("span", null, "可持续") : React.createElement("span", null, "单次"),
		s.hasChildren ? React.createElement("span", null, "有下级") : null));
}

/** 单个子代理的运行内容（服务端转写懒加载；目录行标签为标题）。 */
function SubagentDetail(props) {
	var data = useState(null); var setData = data[1];
	var err = useState(""); var setErr = err[1];
	var asked = useRef("");
	useEffect(function () {
		if (asked.current === props.id) return;
		asked.current = props.id;
		setData(null); setErr("");
		postCsrf(ROUTE_BASE + "/subagent.transcript", { sessionId: props.id })
			.then(function (r) { return r.json(); })
			.then(function (r) {
				if (r && r.entries) setData(r.entries);
				else setErr(r && r.error ? r.error : "读取失败");
			})
			.catch(function (e) { setErr("通道不可达：" + (e && e.message ? e.message : e)); });
	}, [props.id]);
	var row = [].concat(props.groups.running, props.groups.finished).find(function (x) { return x.id === props.id; });
	return React.createElement(React.Fragment, null,
		React.createElement("div", { className: "dsh-sp-tr-meta" },
			row ? React.createElement("b", { style: { color: "#e8f3ff", fontSize: 12 } }, row.label) : null,
			row ? React.createElement("span", { className: "dsh-sp-tag" + (row.running ? " is-run" : " is-done") }, SUB_STATUS_LABELS[row.status] || row.status) : null),
		err[0] ? React.createElement("div", { className: "dsh-sp-empty" }, err[0]) : null,
		!err[0] && !data[0] ? React.createElement("div", { className: "dsh-sp-loading" }, "读取运行内容…") : null,
		data[0] && data[0].length === 0 ? React.createElement("div", { className: "dsh-sp-empty" }, "该子代理会话没有可显示的内容") : null,
		(data[0] || []).map(function (e, i) {
			if (e.kind === "tool") {
				return React.createElement("div", { key: "t" + i, className: "dsh-sp-toolrow" },
					React.createElement("span", { className: "dsh-sp-toolname" }, e.name),
					React.createElement("span", { className: "dsh-sp-toolbrief", title: e.brief }, e.brief));
			}
			return React.createElement("div", { key: "t" + i, className: "dsh-sp-tr " + (e.kind === "user" ? "is-user" : "is-asst") }, e.text);
		}));
}

/**
 * 提示词栏（对话列内左侧居中）：条目=单行窄条；悬停/选中的那一条就地变长（向右展开黑卡）——
 * 展开即预览（标题/正文六行/时间），点击条目或展开卡定位到消息锚点。
 */
function PromptRail(props) {
	var col = props.col;
	var openEntry = props.hoverKey ? props.prompts.find(function (p) { return p.key === props.hoverKey; }) : null;
	var openIdx = openEntry ? props.prompts.indexOf(openEntry) + 1 : 0;
	return React.createElement(React.Fragment, null,
		React.createElement("div", {
			className: "dsh-sp-rail",
			style: { left: col.left + 10, top: col.top + col.height / 2, transform: "translateY(-50%)" }
		},
		React.createElement("div", { className: "dsh-sp-rail-head" }, SEARCH_ICON, "提示词 · " + props.prompts.length),
		props.prompts.map(function (p) {
			return React.createElement("div", {
				key: p.key,
				className: "dsh-sp-pitem" + (props.hoverKey === p.key ? " is-open" : ""),
				onClick: function () { props.locate(p.key); },
				onMouseEnter: function (e) { props.onHover(p.key, e.currentTarget.getBoundingClientRect()); },
				onMouseLeave: props.onLeave,
				title: "点击定位到该消息"
			}, p.preview.replace(/\n/g, " "));
		})),
		openEntry && props.hoverRect ? React.createElement("div", {
			className: "dsh-sp-pexpand",
			style: { left: props.hoverRect.left, top: props.hoverRect.top - 1, minHeight: props.hoverRect.height + 2 },
			onMouseEnter: function () { props.onHover(openEntry.key, props.hoverRect); },
			onMouseLeave: props.onLeave,
			onClick: function () { props.locate(openEntry.key); }
		},
		React.createElement("div", { className: "dsh-sp-pexpand-title" }, titleLine(openEntry.text, 56) || "（无标题）"),
		React.createElement("div", { className: "dsh-sp-pexpand-body" }, clip(openEntry.text, 600)),
		React.createElement("div", { className: "dsh-sp-pexpand-foot" },
			"第 " + openIdx + " 条 · " + fmtTime(openEntry.time),
			React.createElement("button", {
				type: "button", className: "dsh-sp-pexpand-jump",
				onClick: function (e) { e.stopPropagation(); props.locate(openEntry.key); }
			}, "定位"))) : null);
}

var dshCsrf = {};
/** CSRF token 懒加载（同源 GET /csrf）；POST 回带 x-dsh-csrf 头。 */
function csrfOf(base) {
	if (!dshCsrf[base]) dshCsrf[base] = fetch(base + "/csrf").then(function (r) { return r.json(); }).then(function (r) { return r && r.token ? r.token : ""; }).catch(function () { return ""; });
	return dshCsrf[base];
}
function postCsrf(url, body) {
	return csrfOf("/dsh-session-pulse").then(function (tok) {
		return fetch(url, { method: "POST", headers: tok ? { "content-type": "application/json", "x-dsh-csrf": tok } : { "content-type": "application/json" }, body: JSON.stringify(body) });
	});
}
var ROUTE_BASE = "/dsh-session-pulse";

function apply(ctx) {
	ctx.effect(function () { return installStyles(); }, "dsh-session-pulse: styles");
	ctx.inject(["sessions"], function (scope) {
		var sessionsStore = scope.sessions;
		ctx.slots.inject("conversation.session.header.actions", function () {
			return ctx.slots.register({
				name: "conversation.session.header.actions",
				id: "session-pulse",
				order: 10,
				registrant: "dsh-session-pulse",
				inject: function (sid) { return { pulseSessions: sessionsStore }; }
			}, function (slotProps) {
				return React.createElement(PulseRoot, Object.assign({}, slotProps));
			});
		});
		return function () {};
	});
}

module.exports = { name: "dsh-session-pulse-client", inject: ["slots"], apply: apply };
return module.exports; } });
