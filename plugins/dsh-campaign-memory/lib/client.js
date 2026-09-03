window.__ModuleLoader__.load({ id: "@dsh-external/dsh-campaign-memory", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-campaign-memory client — 会话标签页「战役记忆」：九模式战役记忆的浏览 / 检索 / 删除。
// 记忆为模式作用域跨会话资产：默认定位当前会话模式，可切换九模式查看；检测指纹到期自动清理，
// 目标指纹到期退出召回（可切「含已过期」查看/取舍）。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useRef = React.useRef;

var dshCsrf = {};
/** CSRF token 懒加载（同源 GET /csrf，跨源页面读不到）；POST 回带 x-dsh-csrf 头。
 *  token 缓存遇 403 即失效重取一次——宿主重启轮换 token 后已开标签页自愈，不再永久 403。 */
function csrfOf(base) {
	if (!dshCsrf[base]) dshCsrf[base] = fetch(base + "/csrf").then(function (r) { return r.json(); }).then(function (r) { return r && r.token ? r.token : ""; }).catch(function () { return ""; });
	return dshCsrf[base];
}
function postJson(tok, endpoint, payload) {
	return fetch("/dsh-campaign-memory/" + endpoint, {
		method: "POST",
		headers: tok ? { "content-type": "application/json", "x-dsh-csrf": tok } : { "content-type": "application/json" },
		body: JSON.stringify(payload || {})
	});
}
function api(endpoint, payload) {
	return csrfOf("/dsh-campaign-memory").then(function (tok) {
		return postJson(tok, endpoint, payload).then(function (r) {
			if (r.status === 403) {
				delete dshCsrf["/dsh-campaign-memory"];
				return csrfOf("/dsh-campaign-memory").then(function (tok2) { return postJson(tok2, endpoint, payload); }).then(function (r2) { return r2.json(); });
			}
			return r.json();
		});
	});
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
	"body{--cm-line:#4176e6;--cm-ink:#14263e;--cm-ink-2:#2c3f58;--cm-ink-3:#3d5273;--cm-ink-4:#5b6f8a;--cm-ink-5:#6e8098;--cm-ink-6:#7d8ea3;--cm-ink-7:#8a97a8;--cm-cyan-note:#2f6fe4;--cm-grad-a:#2f6fe4;--cm-grad-b:#38a4f7;--cm-on-grad:#ffffff;--cm-gold:#b07800;--cm-gold-ink:#7a5800;--cm-danger:#e03131;--cm-danger-ink:#c92a2a;--cm-root-bg:radial-gradient(1200px 500px at 70% -10%,color-mix(in srgb,var(--cm-line) 7%,transparent),transparent 60%),radial-gradient(900px 420px at 0% 110%,color-mix(in srgb,var(--cm-line) 5%,transparent),transparent 55%),linear-gradient(180deg,#f8fbff 0%,#eef4fc 100%);--cm-panel:rgba(255,255,255,.78);--cm-card:rgba(255,255,255,.66);--cm-input:#ffffff;--cm-float:rgba(255,255,255,.97);--cm-title-grad:linear-gradient(90deg,#2f6fe4,#14263e,#2f6fe4);--cm-glow:0 4px 14px rgba(20,40,80,.07);--cm-shadow:0 6px 24px rgba(20,40,80,.18);--cm-chip-hover:color-mix(in srgb,var(--cm-line) 18%,transparent);--cm-btn-hover:color-mix(in srgb,var(--cm-line) 18%,transparent)}",
	"body[data-ds-dark-theme]{--cm-line:#3a9dff;--cm-ink:#e8f3ff;--cm-ink-2:#dbe8f6;--cm-ink-3:#cfe6ff;--cm-ink-4:#b9d2ee;--cm-ink-5:#9db9d8;--cm-ink-6:#8fb4d9;--cm-ink-7:#7d97b8;--cm-cyan-note:#7cc8ff;--cm-grad-a:#3f8ef7;--cm-grad-b:#38d4ff;--cm-on-grad:#04101f;--cm-gold:#f5c542;--cm-gold-ink:#ffe9ad;--cm-danger:#ff7878;--cm-danger-ink:#ffc9c9;--cm-root-bg:radial-gradient(1200px 500px at 70% -10%,rgba(35,90,160,.35),transparent 60%),radial-gradient(900px 420px at 0% 110%,rgba(20,60,120,.3),transparent 55%),linear-gradient(180deg,#081b33 0%,#061225 100%);--cm-panel:rgba(10,30,60,.45);--cm-card:rgba(12,32,62,.6);--cm-input:rgba(10,30,60,.6);--cm-float:rgba(8,24,46,.94);--cm-title-grad:linear-gradient(90deg,#7cc8ff,#ffffff,#7cc8ff);--cm-glow:0 0 15px rgba(58,157,255,.1);--cm-shadow:0 6px 24px rgba(2,8,20,.55);--cm-chip-hover:rgba(58,157,255,.2);--cm-btn-hover:rgba(58,157,255,.25)}",
	".dsh-cm-root{position:relative;display:flex;flex-direction:column;min-height:100%;height:100%;overflow:hidden;color:var(--cm-ink-2);background:var(--cm-root-bg);font-size:13px}",
	".dsh-cm-root::before{content:\"\";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(color-mix(in srgb,var(--cm-line) 6%,transparent) 1px,transparent 1px),linear-gradient(90deg,color-mix(in srgb,var(--cm-line) 6%,transparent) 1px,transparent 1px);background-size:40px 40px}",
	".dsh-cm-wrap{position:relative;display:flex;flex-direction:column;gap:10px;padding:12px 14px;min-height:100%;box-sizing:border-box;flex:1;min-height:0}",
	".dsh-cm-panel{border:1px solid color-mix(in srgb,var(--cm-line) 35%,transparent);border-radius:10px;background:var(--cm-panel);backdrop-filter:blur(10px);box-shadow:var(--cm-glow)}",
	".dsh-cm-head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px 14px;padding:8px 14px}",
	".dsh-cm-title{font-size:18px;font-weight:700;letter-spacing:2px;background:var(--cm-title-grad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}",
	".dsh-cm-sub{font-size:11px;color:var(--cm-ink-6);letter-spacing:1px}",
	".dsh-cm-modes{display:flex;gap:6px;flex-wrap:wrap;padding:8px 14px}",
	".dsh-cm-mode{border:1px solid color-mix(in srgb,var(--cm-line) 40%,transparent);border-radius:999px;background:color-mix(in srgb,var(--cm-line) 8%,transparent);color:var(--cm-ink-3);padding:3px 12px;font-size:12px;cursor:pointer;transition:all .2s;user-select:none}",
	".dsh-cm-mode:hover{background:var(--cm-chip-hover)}",
	".dsh-cm-mode.is-on{background:linear-gradient(90deg,var(--cm-grad-a),var(--cm-grad-b));color:var(--cm-on-grad);font-weight:700;border-color:var(--cm-grad-b);box-shadow:0 0 10px color-mix(in srgb,var(--cm-grad-b) 40%,transparent)}",
	".dsh-cm-stats{display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:4px 14px 8px}",
	".dsh-cm-stat{border:1px solid color-mix(in srgb,var(--cm-line) 35%,transparent);border-radius:8px;padding:3px 9px;background:color-mix(in srgb,var(--cm-line) 8%,transparent);text-align:center;min-width:54px}",
	".dsh-cm-stat b{display:block;font-size:14px;line-height:1.2;color:var(--cm-cyan-note)}",
	".dsh-cm-stat span{font-size:10px;color:var(--cm-ink-5)}",
	".dsh-cm-tools{display:flex;gap:8px;align-items:center;padding:8px 14px;flex-wrap:wrap}",
	".dsh-cm-in{flex:1;min-width:160px;border:1px solid color-mix(in srgb,var(--cm-line) 40%,transparent);border-radius:6px;background:var(--cm-input);color:var(--cm-ink-2);padding:5px 9px;font-size:12px;outline:none}",
	".dsh-cm-sel{border:1px solid color-mix(in srgb,var(--cm-line) 40%,transparent);border-radius:6px;background:var(--cm-input);color:var(--cm-ink-2);padding:5px 9px;font-size:12px;outline:none}",
	".dsh-cm-btn{border:1px solid color-mix(in srgb,var(--cm-line) 45%,transparent);border-radius:8px;padding:4px 12px;font-size:12px;color:var(--cm-ink-3);background:color-mix(in srgb,var(--cm-line) 10%,transparent);cursor:pointer}",
	".dsh-cm-btn:hover{background:var(--cm-btn-hover)}",
	".dsh-cm-btn.is-on{background:linear-gradient(90deg,var(--cm-grad-a),var(--cm-grad-b));color:var(--cm-on-grad);font-weight:700;border-color:var(--cm-grad-b)}",
	".dsh-cm-list{flex:1;overflow:auto;padding:4px 14px 14px;display:flex;flex-direction:column;gap:8px}",
	".dsh-cm-card{border:1px solid color-mix(in srgb,var(--cm-line) 30%,transparent);border-radius:9px;padding:9px 12px;background:var(--cm-card)}",
	".dsh-cm-card b{font-size:13px;color:var(--cm-ink)}",
	".dsh-cm-card .meta{font-size:10.5px;color:var(--cm-ink-7);margin-top:2px}",
	".dsh-cm-card .body{font-size:11.5px;color:var(--cm-ink-4);margin-top:5px;white-space:pre-wrap;word-break:break-word;line-height:1.6}",
	".dsh-cm-kbadge{display:inline-block;margin-left:6px;font-size:9px;border-radius:4px;padding:0 5px;border:1px solid color-mix(in srgb,var(--cm-cyan-note) 40%,transparent);color:var(--cm-cyan-note);vertical-align:1px}",
	".dsh-cm-kbadge.k-detect{border-color:color-mix(in srgb,var(--cm-gold) 55%,transparent);color:var(--cm-gold-ink)}",
	".dsh-cm-kbadge.k-expired{border-color:color-mix(in srgb,var(--cm-danger) 55%,transparent);color:var(--cm-danger-ink)}",
	".dsh-cm-acts{display:flex;gap:5px;margin-top:6px;flex-wrap:wrap}",
	".dsh-cm-acts button{border:1px solid color-mix(in srgb,var(--cm-line) 45%,transparent);border-radius:5px;background:color-mix(in srgb,var(--cm-line) 10%,transparent);color:var(--cm-ink-3);font-size:11px;cursor:pointer;padding:2px 8px}",
	".dsh-cm-acts button.is-danger{border-color:color-mix(in srgb,var(--cm-danger) 50%,transparent);color:var(--cm-danger-ink)}",
	".dsh-cm-empty{color:var(--cm-ink-5);font-size:12px;line-height:2.2;padding:36px 16px;text-align:center}",
	".dsh-cm-toast{position:fixed;right:18px;bottom:18px;z-index:70;max-width:380px;padding:10px 14px;border-radius:8px;border:1px solid color-mix(in srgb,var(--cm-line) 50%,transparent);background:var(--cm-float);backdrop-filter:blur(12px);color:var(--cm-ink-3);font-size:12px;box-shadow:var(--cm-shadow)}",
	".dsh-cm-toast.is-err{border-color:color-mix(in srgb,var(--cm-danger) 55%,transparent);color:var(--cm-danger-ink)}"
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
	var showExpired = useState(false); var setShowExpired = showExpired[1];
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
	function load(m, k, incl) {
		api("memory.list", { mode: m, kind: k || "", includeExpired: !!incl }).then(function (r) {
			if (r && r.memories) setRows(r.memories);
		}).catch(function () {});
		api("memory.stats", { mode: m }).then(function (r) {
			if (r && r.stats) setStats(r.stats);
		}).catch(function () {});
	}
	useEffect(function () { load(resolved, kind[0], showExpired[0]); setDelConfirm(""); setExpanded(""); }, [resolved, kind[0], showExpired[0]]);

	function runSearch() {
		if (!query[0].trim()) { load(resolved, kind[0], showExpired[0]); return; }
		api("memory.search", { mode: resolved, query: query[0], kind: kind[0] || undefined, limit: 20 }).then(function (r) {
			if (r && r.memories) { setRows(r.memories); say("检索命中 " + r.memories.length + " 条"); }
			else say((r && r.error) || "检索失败", true);
		}).catch(function () { say("检索失败（通道不可达）", true); });
	}
	function purge() {
		api("memory.purge", {}).then(function (r) {
			if (r && r.ok) { load(resolved, kind[0], showExpired[0]); say("已清理过期检测指纹 " + r.purged + " 条"); }
		}).catch(function () {});
	}

	var st = stats[0];
	return React.createElement("div", { className: "dsh-cm-root" },
		React.createElement("div", { className: "dsh-cm-wrap" },
			React.createElement("div", { className: "dsh-cm-panel dsh-cm-head" },
				React.createElement("div", null,
					React.createElement("div", { className: "dsh-cm-title" }, "战役记忆"),
					React.createElement("div", { className: "dsh-cm-sub" }, "跨会话打法沉淀 —— 读全文计热度 · 检测指纹到期清理 / 目标指纹到期退场可召回 · 原文入库不脱敏")),
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
					React.createElement("input", { className: "dsh-cm-in", placeholder: "检索标题 / 正文 / 标签…（回车检索）", value: query[0], onChange: function (e) { setQuery(e.target.value); }, onKeyDown: function (e) { if (e.key === "Enter") runSearch(); } }),
					React.createElement("select", { className: "dsh-cm-sel", value: kind[0], onChange: function (e) { setKind(e.target.value); } },
						KINDS.map(function (k) { return React.createElement("option", { key: k, value: k }, k ? KIND_LABEL[k] : "全部类别"); })),
					React.createElement("button", { type: "button", className: "dsh-cm-btn" + (showExpired[0] ? " is-on" : ""), onClick: function () { setShowExpired(!showExpired[0]); } }, "含已过期"),
					React.createElement("button", { type: "button", className: "dsh-cm-btn", onClick: runSearch }, "检索")),
				React.createElement("div", { className: "dsh-cm-list" },
					rows[0].length === 0
						? React.createElement("div", { className: "dsh-cm-empty" },
							"本模式还没有战役记忆。", React.createElement("br", null),
							"会话内模型经 campaign_memory_write 沉淀有效打法（正文原样入库不脱敏——凭据可入库或只写指位）；", React.createElement("br", null),
							"开战时装配上下文自动携带高频记忆，读全文（campaign_memory_get）计入热度并驱动召回。")
						: rows[0].map(function (m) {
							return React.createElement("div", { key: m.id, className: "dsh-cm-card" },
								React.createElement("b", { onClick: function () { setExpanded(expanded[0] === m.id ? "" : m.id); }, style: { cursor: "pointer" } }, m.title,
									React.createElement("span", { className: "dsh-cm-kbadge" + (m.kind === "detect" ? " k-detect" : "") }, KIND_LABEL[m.kind] || m.kind),
								m.expired ? React.createElement("span", { className: "dsh-cm-kbadge k-expired" }, "已过期") : null),
								React.createElement("div", { className: "meta" },
									(m.workspace ? "@" + m.workspace + " · " : "") + (m.tags ? m.tags + " · " : "") + (m.targetKind ? "目标：" + m.targetKind + " · " : "") + "热度 " + m.usageCount + " · " + (m.lastUsedAt ? "近用 " + fmtTime(m.lastUsedAt) : "未用过") + (m.expiresAt ? " · " + fmtTime(m.expiresAt) + " 过期" : "") ),
								expanded[0] === m.id ? React.createElement("div", { className: "body" }, fullOf[0][m.id] || m.content) : null,
								React.createElement("div", { className: "dsh-cm-acts" },
									React.createElement("button", { type: "button", onClick: function () {
									if (expanded[0] === m.id) { setExpanded(""); return; }
									setExpanded(m.id);
									if (!fullOf[0][m.id] && String(m.content).includes("…")) {
										api("memory.get", { id: m.id, peek: true }).then(function (r) { // peek=纯浏览不记账（查看不是采用）
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

var REDTEAM_MANAGER_UI_NAMESPACE = "redteam-manager-ui";

function injectVisibleConversationView(ctx, field, register) {
	var settings = ctx.settingsScope.bind({ namespace: REDTEAM_MANAGER_UI_NAMESPACE });
	ctx.slots.inject("conversation.view", function () {
		var disposeView;
		function isVisible() {
			var snapshot = settings.getSnapshot();
			return snapshot.status !== "ready" || !snapshot.value || snapshot.value[field] !== false;
		}
		function reconcile() {
			if (isVisible()) {
				if (!disposeView) disposeView = register();
				return;
			}
			if (disposeView) {
				disposeView();
				disposeView = undefined;
			}
		}
		var unsubscribe = settings.subscribe(reconcile);
		reconcile();
		return function () {
			unsubscribe();
			if (disposeView) {
				disposeView();
				disposeView = undefined;
			}
		};
	});
}

function apply(ctx) {
	ctx.effect(function () { return installStyles(); }, "dsh-campaign-memory: styles");
	ctx.inject(["sessions"], function (scope) {
		var sessionsStore = scope.sessions;
		injectVisibleConversationView(ctx, "showCampaignMemory", function () {
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

module.exports = { name: "dsh-campaign-memory-client", inject: ["slots", "settingsScope"], apply: apply };
return module.exports; } });
