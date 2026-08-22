window.__ModuleLoader__.load({ id: "@dsh-external/dsh-campaign-memory", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-campaign-memory client — 会话标签页「战役记忆」：九模式战役记忆的浏览 / 检索 / 删除。
// 记忆为模式作用域跨会话资产：默认定位当前会话模式，可切换九模式查看；检测指纹类到期自动退出召回。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useRef = React.useRef;

function api(endpoint, payload) {
	return fetch("/dsh-campaign-memory/" + endpoint, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(payload || {})
	}).then(function (r) { return r.json(); });
}

var MODES = [
	{ id: "redteam", label: "安全研究员" },
	{ id: "pentest", label: "渗透测试" },
	{ id: "attack-defense", label: "攻防评估" },
	{ id: "code-audit", label: "代码审计" },
	{ id: "binary-analysis", label: "二进制分析" },
	{ id: "av-evasion", label: "免杀对抗" },
	{ id: "incident-response", label: "应急溯源" },
	{ id: "cloud-security", label: "云安全攻防" },
	{ id: "ctf-solver", label: "CTF 解题" }
];
var KIND_LABEL = { tactic: "战术打法", fingerprint: "目标指纹", tooling: "工具可用性", lesson: "教训", detect: "检测指纹" };
var KINDS = ["", "tactic", "fingerprint", "tooling", "lesson", "detect"];

var CSS = [
	".dsh-cm-root{position:relative;display:flex;flex-direction:column;min-height:100%;height:100%;overflow:hidden;color:#dbe8f6;background:radial-gradient(1200px 500px at 70% -10%,rgba(35,90,160,.35),transparent 60%),radial-gradient(900px 420px at 0% 110%,rgba(20,60,120,.3),transparent 55%),linear-gradient(180deg,#081b33 0%,#061225 100%);font-size:13px}",
	".dsh-cm-root::before{content:\"\";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(rgba(58,157,255,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(58,157,255,.06) 1px,transparent 1px);background-size:40px 40px}",
	".dsh-cm-wrap{position:relative;display:flex;flex-direction:column;gap:10px;padding:12px 14px;min-height:100%;box-sizing:border-box;flex:1;min-height:0}",
	".dsh-cm-panel{border:1px solid rgba(58,157,255,.35);border-radius:10px;background:rgba(10,30,60,.45);backdrop-filter:blur(10px);box-shadow:0 0 15px rgba(58,157,255,.1)}",
	".dsh-cm-head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px 14px;padding:8px 14px}",
	".dsh-cm-title{font-size:18px;font-weight:700;letter-spacing:2px;background:linear-gradient(90deg,#7cc8ff,#ffffff,#7cc8ff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}",
	".dsh-cm-sub{font-size:11px;color:#8fb4d9;letter-spacing:1px}",
	".dsh-cm-modes{display:flex;gap:6px;flex-wrap:wrap;padding:8px 14px}",
	".dsh-cm-mode{border:1px solid rgba(58,157,255,.4);border-radius:999px;background:rgba(58,157,255,.08);color:#bfe3ff;padding:3px 12px;font-size:12px;cursor:pointer;transition:all .2s;user-select:none}",
	".dsh-cm-mode:hover{background:rgba(58,157,255,.2)}",
	".dsh-cm-mode.is-on{background:linear-gradient(90deg,#3f8ef7,#38d4ff);color:#04101f;font-weight:700;border-color:#38d4ff;box-shadow:0 0 10px rgba(56,212,255,.4)}",
	".dsh-cm-stats{display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:4px 14px 8px}",
	".dsh-cm-stat{border:1px solid rgba(58,157,255,.35);border-radius:8px;padding:3px 9px;background:rgba(58,157,255,.08);text-align:center;min-width:54px}",
	".dsh-cm-stat b{display:block;font-size:14px;line-height:1.2;color:#7cc8ff}",
	".dsh-cm-stat span{font-size:10px;color:#9db9d8}",
	".dsh-cm-tools{display:flex;gap:8px;align-items:center;padding:8px 14px;flex-wrap:wrap}",
	".dsh-cm-in{flex:1;min-width:160px;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:5px 9px;font-size:12px;outline:none}",
	".dsh-cm-sel{border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:5px 9px;font-size:12px;outline:none}",
	".dsh-cm-btn{border:1px solid rgba(58,157,255,.45);border-radius:8px;padding:4px 12px;font-size:12px;color:#cfe6ff;background:rgba(58,157,255,.1);cursor:pointer}",
	".dsh-cm-btn:hover{background:rgba(58,157,255,.25)}",
	".dsh-cm-list{flex:1;overflow:auto;padding:4px 14px 14px;display:flex;flex-direction:column;gap:8px}",
	".dsh-cm-card{border:1px solid rgba(58,157,255,.3);border-radius:9px;padding:9px 12px;background:rgba(12,32,62,.6)}",
	".dsh-cm-card b{font-size:13px;color:#e8f3ff}",
	".dsh-cm-card .meta{font-size:10.5px;color:#7d97b8;margin-top:2px}",
	".dsh-cm-card .body{font-size:11.5px;color:#b9d2ee;margin-top:5px;white-space:pre-wrap;word-break:break-word;line-height:1.6}",
	".dsh-cm-kbadge{display:inline-block;margin-left:6px;font-size:9px;border-radius:4px;padding:0 5px;border:1px solid rgba(124,200,255,.4);color:#7cc8ff;vertical-align:1px}",
	".dsh-cm-kbadge.k-detect{border-color:rgba(245,197,66,.55);color:#ffe9ad}",
	".dsh-cm-acts{display:flex;gap:5px;margin-top:6px;flex-wrap:wrap}",
	".dsh-cm-acts button{border:1px solid rgba(58,157,255,.45);border-radius:5px;background:rgba(58,157,255,.1);color:#cfe6ff;font-size:11px;cursor:pointer;padding:2px 8px}",
	".dsh-cm-acts button.is-danger{border-color:rgba(255,120,120,.5);color:#ffc9c9}",
	".dsh-cm-empty{color:#9db9d8;font-size:12px;line-height:2.2;padding:36px 16px;text-align:center}",
	".dsh-cm-toast{position:fixed;right:18px;bottom:18px;z-index:70;max-width:380px;padding:10px 14px;border-radius:8px;border:1px solid rgba(58,157,255,.5);background:rgba(8,24,46,.94);backdrop-filter:blur(12px);color:#d8ecff;font-size:12px;box-shadow:0 6px 24px rgba(2,8,20,.55)}",
	".dsh-cm-toast.is-err{border-color:rgba(255,120,120,.55);color:#ffd6d6}"
].join("\n");
function installStyles() {
	var style = document.createElement("style");
	style.id = "dsh-cm-style";
	style.textContent = CSS;
	document.head.appendChild(style);
	return function () { style.remove(); };
}

function fmtTime(s) { return s ? String(s).replace("T", " ").slice(0, 16) : ""; }

function MemoryView(props) {
	var sessionsStore = props.sessionsStore;
	var sessionId = props.sessionId != null ? String(props.sessionId) : "";
	var force = useState(0)[1];
	var mode = useState(""); var setMode = mode[1];
	var kind = useState(""); var setKind = kind[1];
	var query = useState(""); var setQuery = query[1];
	var rows = useState([]); var setRows = rows[1];
	var stats = useState({ total: 0, byKind: {}, expired: 0 }); var setStats = stats[1];
	var expanded = useState(""); var setExpanded = expanded[1];
	var delConfirm = useState(""); var setDelConfirm = delConfirm[1];
	var fullOf = useState({}); var setFull = fullOf[1];
	var toast = useState(null); var setToast = toast[1];
	var toastTimer = useRef(0);

	var preset = "";
	try {
		var snap = sessionsStore && sessionsStore.list.getSnapshot();
		var s = snap && (sessionId ? snap.byId[sessionId] : snap.byId[snap.current]);
		preset = s && s.agentPreset ? String(s.agentPreset) : "";
	} catch { /* 快照不可用时默认渗透 */ }
	var resolved = mode[0] || (MODES.some(function (m) { return m.id === preset; }) ? preset : "pentest");

	useEffect(function () {
		if (!sessionsStore || !sessionsStore.list) return;
		try { return sessionsStore.list.subscribe(function () { force(function (n) { return n + 1; }); }); } catch { return; }
	}, [sessionsStore]);

	function say(text, err) {
		setToast({ text: text, err: !!err });
		window.clearTimeout(toastTimer.current);
		toastTimer.current = window.setTimeout(function () { setToast(null); }, 3200);
	}
	function load(m, k) {
		api("memory.list", { mode: m, kind: k || "" }).then(function (r) {
			if (r && r.memories) setRows(r.memories);
		}).catch(function () {});
		api("memory.stats", { mode: m }).then(function (r) {
			if (r && r.stats) setStats(r.stats);
		}).catch(function () {});
	}
	useEffect(function () { load(resolved, kind[0]); setDelConfirm(""); setExpanded(""); }, [resolved, kind[0]]);

	function runSearch() {
		if (!query[0].trim()) { load(resolved, kind[0]); return; }
		api("memory.search", { mode: resolved, query: query[0], kind: kind[0] || undefined, limit: 20 }).then(function (r) {
			if (r && r.memories) { setRows(r.memories); say("检索命中 " + r.memories.length + " 条（已计入使用热度）"); }
			else say((r && r.error) || "检索失败", true);
		}).catch(function () { say("检索失败（通道不可达）", true); });
	}
	function purge() {
		api("memory.purge", {}).then(function (r) {
			if (r && r.ok) { load(resolved, kind[0]); say("已清理过期记忆 " + r.purged + " 条"); }
		}).catch(function () {});
	}

	var st = stats[0];
	return React.createElement("div", { className: "dsh-cm-root" },
		React.createElement("div", { className: "dsh-cm-wrap" },
			React.createElement("div", { className: "dsh-cm-panel dsh-cm-head" },
				React.createElement("div", null,
					React.createElement("div", { className: "dsh-cm-title" }, "战役记忆"),
					React.createElement("div", { className: "dsh-cm-sub" }, "跨会话打法沉淀 —— 检索即记账 · 指纹类到期自动退场 · 凭据走独立凭据库")),
				React.createElement("div", { className: "dsh-cm-acts" },
					React.createElement("button", { type: "button", className: "dsh-cm-btn", onClick: purge }, "清理过期"))),
			React.createElement("div", { className: "dsh-cm-panel" },
				React.createElement("div", { className: "dsh-cm-modes" },
					MODES.map(function (m) {
						return React.createElement("span", {
							key: m.id, className: "dsh-cm-mode" + (resolved === m.id ? " is-on" : ""),
							onClick: function () { setMode(m.id); }
						}, m.label);
					})),
				React.createElement("div", { className: "dsh-cm-stats" },
					React.createElement("div", { className: "dsh-cm-stat" }, React.createElement("b", null, String(st.total)), React.createElement("span", null, "总记忆")),
					["tactic", "fingerprint", "tooling", "lesson", "detect"].map(function (k) {
						return React.createElement("div", { className: "dsh-cm-stat", key: k }, React.createElement("b", null, String(st.byKind[k] || 0)), React.createElement("span", null, KIND_LABEL[k]));
					}),
					React.createElement("div", { className: "dsh-cm-stat" }, React.createElement("b", null, String(st.expired)), React.createElement("span", null, "已过期")))),
			React.createElement("div", { className: "dsh-cm-panel", style: { display: "flex", flexDirection: "column", flex: 1, minHeight: 0 } },
				React.createElement("div", { className: "dsh-cm-tools" },
					React.createElement("input", { className: "dsh-cm-in", placeholder: "检索标题 / 正文 / 标签…（回车检索，计入使用热度）", value: query[0], onChange: function (e) { setQuery(e.target.value); }, onKeyDown: function (e) { if (e.key === "Enter") runSearch(); } }),
					React.createElement("select", { className: "dsh-cm-sel", value: kind[0], onChange: function (e) { setKind(e.target.value); } },
						KINDS.map(function (k) { return React.createElement("option", { key: k, value: k }, k ? KIND_LABEL[k] : "全部类别"); })),
					React.createElement("button", { type: "button", className: "dsh-cm-btn", onClick: runSearch }, "检索")),
				React.createElement("div", { className: "dsh-cm-list" },
					rows[0].length === 0
						? React.createElement("div", { className: "dsh-cm-empty" },
							"本模式还没有战役记忆。", React.createElement("br", null),
							"会话内模型经 campaign_memory_write 沉淀有效打法（凭据不入记忆，走独立凭据库）；", React.createElement("br", null),
							"开战时装配上下文自动携带高频记忆，检索 campaign_memory_search 命中即计入热度。")
						: rows[0].map(function (m) {
							return React.createElement("div", { key: m.id, className: "dsh-cm-card" },
								React.createElement("b", { onClick: function () { setExpanded(expanded[0] === m.id ? "" : m.id); }, style: { cursor: "pointer" } }, m.title,
									React.createElement("span", { className: "dsh-cm-kbadge" + (m.kind === "detect" ? " k-detect" : "") }, KIND_LABEL[m.kind] || m.kind)),
								React.createElement("div", { className: "meta" },
									(m.workspace ? "@" + m.workspace + " · " : "") + (m.tags ? m.tags + " · " : "") + (m.targetKind ? "目标：" + m.targetKind + " · " : "") + "热度 " + m.usageCount + " · " + (m.lastUsedAt ? "近用 " + fmtTime(m.lastUsedAt) : "未用过") + (m.expiresAt ? " · " + fmtTime(m.expiresAt) + " 过期" : "") ),
								expanded[0] === m.id ? React.createElement("div", { className: "body" }, fullOf[0][m.id] || m.content) : null,
								React.createElement("div", { className: "dsh-cm-acts" },
									React.createElement("button", { type: "button", onClick: function () {
									if (expanded[0] === m.id) { setExpanded(""); return; }
									setExpanded(m.id);
									if (!fullOf[0][m.id] && String(m.content).includes("…")) {
										api("memory.get", { id: m.id }).then(function (r) {
											if (r && r.memory) { var nx = Object.assign({}, fullOf[0]); nx[m.id] = r.memory.content; setFull(nx); }
										}).catch(function () {});
									}
								} }, expanded[0] === m.id ? "收起" : "全文"),
									React.createElement("button", {
										type: "button", className: delConfirm[0] === m.id ? "is-danger" : "",
										onClick: function () {
											if (delConfirm[0] === m.id) {
												api("memory.remove", { id: m.id }).then(function (r) {
													if (r && r.ok) { setDelConfirm(""); load(resolved, kind[0]); say("记忆已删除"); }
													else say((r && r.error) || "删除失败", true);
												}).catch(function () { say("删除失败", true); });
											} else setDelConfirm(m.id);
										}
									}, delConfirm[0] === m.id ? "确认删除？" : "删除")));
						})))),
		toast[0] ? React.createElement("div", { className: "dsh-cm-toast" + (toast[0].err ? " is-err" : "") }, toast[0].text) : null);
}

function apply(ctx) {
	ctx.effect(function () { return installStyles(); }, "dsh-campaign-memory: styles");
	ctx.inject(["sessions"], function (scope) {
		var sessionsStore = scope.sessions;
		ctx.slots.inject("conversation.view", function () {
			return ctx.slots.register({
				name: "conversation.view",
				id: "campaign-memory",
				order: 53,
				label: function () { return "战役记忆"; }
			}, function (props) {
				return React.createElement(MemoryView, Object.assign({}, props, { sessionsStore: sessionsStore }));
			});
		});
		return function () {};
	});
}

module.exports = { name: "dsh-campaign-memory-client", inject: ["slots"], apply: apply };
return module.exports; } });
