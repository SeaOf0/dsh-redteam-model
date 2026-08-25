// dsh-mode-group 客户端：新建会话屏模式选择 chip 两级化。
// 内置模式与研究员模式留顶层；八个专业模式折叠进「专业安全模式」子菜单（悬停预览+
// 点击固定，视口自适应翻转）。数据与动作走 connection.api.agentPresets，语义与原生
// seat 一致：选择=暂存+空白会话即应用；会话列表变化时补投。
window.__ModuleLoader__.load({ id: "@dsh-external/dsh-mode-group", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useRef = React.useRef, useCallback = React.useCallback;

var PRO_IDS = ["attack-defense", "pentest", "code-audit", "av-evasion", "incident-response", "binary-analysis", "cloud-security", "ctf-solver"];
var RESEARCHER = "redteam";
var L10N = {
	zh: { group: "专业安全模式", groupDesc: "八个专业安全模式", researcher: "研究员模式" },
	en: { group: "Professional security", groupDesc: "Eight specialist modes", researcher: "Researcher" }
};
function t() {
	return /^zh/.test(navigator.language || "") ? L10N.zh : L10N.en;
}
function msgOf(e) {
	return String((e && e.message) || e);
}

// —— 控制器（暂存与应用语义对齐原生 seat）——
function createController(api, currentSession, onApplied) {
	var state = { options: [], current: "", error: null, busy: false };
	var fallback = "";
	var staged;
	var subs = [];
	function snap() { return state; }
	function set(patch) { state = Object.assign({}, state, patch); subs.forEach(function (fn) { fn(state); }); }
	function subscribe(fn) { subs.push(fn); return function () { subs = subs.filter(function (x) { return x !== fn; }); }; }
	function load() {
		return api.agentPresets.list({}).then(function (res) {
			if (!res.result.ok) { set({ error: res.result.error.message }); return; }
			var presets = res.result.value.presets || [];
			fallback = (presets.find(function (p) { return p.isDefault; }) || presets[0] || {}).id || "";
			var s = currentSession();
			set({ options: presets.map(function (p) { return { id: p.id, name: p.name || p.id, description: p.description || "", isDefault: !!p.isDefault, trust: p.trust }; }),
				current: staged || (s && s.agentPreset) || fallback, error: null });
		}).catch(function (e) { set({ error: msgOf(e) }); });
	}
	function applyStaged() {
		var s = currentSession();
		if (staged === undefined || s === undefined) return Promise.resolve();
		if (!s.blank || s.agentPreset === staged) { staged = undefined; return Promise.resolve(); }
		set({ busy: true, error: null });
		return api.agentPresets.select({ sessionId: s.id, agentPreset: staged }).then(function (res) {
			staged = undefined;
			if (!res.result.ok) { set({ busy: false, error: res.result.error.message, current: fallback }); return; }
			set({ busy: false, current: res.result.value.agentPreset });
			onApplied && onApplied(s.id, res.result.value.agentPreset);
		}).catch(function (e) { staged = undefined; set({ busy: false, error: msgOf(e), current: fallback }); });
	}
	function select(id) {
		staged = id;
		set({ current: id, error: null });
		return applyStaged();
	}
	return { snap: snap, subscribe: subscribe, load: load, select: select, applyStaged: applyStaged };
}

// —— 视口自适应弹层定位 ——
function place(el, anchor, side) {
	el.style.visibility = "hidden";
	el.style.display = "block";
	el.style.maxHeight = "";
	var r = anchor.getBoundingClientRect();
	var vw = window.innerWidth, vh = window.innerHeight;
	var w = Math.min(el.offsetWidth, vw - 16);
	var below = vh - r.bottom - 8, above = r.top - 8;
	var y = r.bottom + 4;
	var avail = below;
	if (below < Math.min(h0(el), 220) && above > below) { y = Math.max(8, r.top - el.offsetHeight - 4); avail = above; }  // 下方放不下且上方更宽→完整翻上
	if (y < 8) y = 8;
	el.style.maxHeight = Math.max(160, avail) + "px";                     // 按可用空间动态滚动
	var x = side === "sub" ? r.right + 4 : r.left;
	if (x + w > vw - 8) x = Math.max(8, (side === "sub" ? r.left : r.left) - w - 4);  // 贴右翻左
	if (x < 8) x = 8;
	el.style.left = x + "px";
	el.style.top = y + "px";
	el.style.visibility = "visible";
}
function h0(el) { var m = el.style.maxHeight; el.style.maxHeight = ""; var h = el.offsetHeight; el.style.maxHeight = m; return h; }

function Chip(props) {
	var ctl = props.ctl;
	var snap = props.useCtl();
	var l = t();
	useEffect(function () { ctl.load(); }, []);   // 挂载即拉取 roster
	var st = useState(false), menuOpen = st[0], setMenuOpen = st[1];
	var sub = useState(false), subOpen = sub[0], setSubOpen = sub[1];
	var pinned = useRef(false);
	var btnRef = useRef(null), menuRef = useRef(null), subRef = useRef(null), groupRef = useRef(null);
	var hoverTimer = useRef(0), closeTimer = useRef(0);

	var options = snap.options || [];
	var pro = options.filter(function (o) { return PRO_IDS.indexOf(o.id) >= 0; })
		.sort(function (a, b) { return PRO_IDS.indexOf(a.id) - PRO_IDS.indexOf(b.id); });
	var builtin = options.filter(function (o) { return PRO_IDS.indexOf(o.id) < 0 && o.id !== RESEARCHER; });
	var researcher = options.find(function (o) { return o.id === RESEARCHER; });
	var groupable = pro.length >= 2;                       // 专业模式不足两个时退化为平铺
	var chosen = options.find(function (o) { return o.id === snap.current; });
	var label = chosen ? chosen.name : (snap.current || "…");

	var closeAll = useCallback(function () {
		setMenuOpen(false); setSubOpen(false); pinned.current = false;
	}, [setMenuOpen, setSubOpen]);

	useEffect(function () {
		if (!menuOpen) return;
		var onDown = function (e) {
			if (btnRef.current && btnRef.current.contains(e.target)) return;
			if (menuRef.current && menuRef.current.contains(e.target)) return;
			if (subRef.current && subRef.current.contains(e.target)) return;
			closeAll();
		};
		var onKey = function (e) { if (e.key === "Escape") closeAll(); };
		var onResize = function () { if (menuRef.current && btnRef.current) place(menuRef.current, btnRef.current, "root"); };
		window.addEventListener("mousedown", onDown);
		window.addEventListener("keydown", onKey);
		window.addEventListener("resize", onResize);
		return function () {
			window.removeEventListener("mousedown", onDown);
			window.removeEventListener("keydown", onKey);
			window.removeEventListener("resize", onResize);
		};
	}, [menuOpen, closeAll]);

	useEffect(function () {
		if (menuOpen && menuRef.current && btnRef.current) place(menuRef.current, btnRef.current, "root");
		if (subOpen && subRef.current && groupRef.current) place(subRef.current, groupRef.current, "sub");
	});

	function pick(id) {
		closeAll();
		ctl.select(id);
	}
	function item(o) {
		return React.createElement("button", { key: o.id, type: "button", role: "menuitem", className: "dsh-mg-item" + (o.id === snap.current ? " is-cur" : ""), onClick: function () { pick(o.id); } },
			React.createElement("span", { className: "dsh-mg-name" }, o.name),
			o.description ? React.createElement("span", { className: "dsh-mg-desc" }, o.description) : null);
	}

	if (!options.length) return null;
	return React.createElement(React.Fragment, null,
		React.createElement("button", { ref: btnRef, type: "button", className: "dsh-mg-chip", title: snap.error || label, disabled: !!snap.busy,
			onClick: function () { setMenuOpen(function (v) { var n = !v; if (!n) { setSubOpen(false); pinned.current = false; } return n; }); } },
			label,
			React.createElement("span", { className: "dsh-mg-caret" }, "▾")),
		menuOpen ? React.createElement("div", { ref: menuRef, className: "dsh-mg-menu", role: "menu" },
			builtin.map(item),
			researcher ? item(researcher) : null,
			groupable ? React.createElement("div", { ref: groupRef, key: "__group", role: "menuitem", tabIndex: 0,
				"aria-haspopup": "menu", "aria-expanded": subOpen,
				className: "dsh-mg-item dsh-mg-group" + (subOpen ? " is-open" : ""),
				onMouseEnter: function () {
					window.clearTimeout(closeTimer.current);
					window.clearTimeout(hoverTimer.current);
					hoverTimer.current = window.setTimeout(function () { setSubOpen(true); }, 120);   // 悬停预览
				},
				onMouseLeave: function () {
					window.clearTimeout(hoverTimer.current);
					if (pinned.current) return;
					closeTimer.current = window.setTimeout(function () { setSubOpen(false); }, 160);   // 离开缓冲
				},
				onClick: function () { pinned.current = !pinned.current; setSubOpen(true); } },       // 点击固定
				React.createElement("span", { className: "dsh-mg-name" }, l.group),
				React.createElement("span", { className: "dsh-mg-desc" }, l.groupDesc),
				React.createElement("span", { className: "dsh-mg-caret is-sub" }, "▸")) : null,
			!groupable ? pro.map(item) : null)
		: null,
		(menuOpen && subOpen && groupable) ? React.createElement("div", { ref: subRef, role: "menu", className: "dsh-mg-menu dsh-mg-sub",
			onMouseEnter: function () { window.clearTimeout(closeTimer.current); },
			onMouseLeave: function () {
				if (pinned.current) return;
				closeTimer.current = window.setTimeout(function () { setSubOpen(false); }, 160);
			} },
			pro.map(item)) : null);
}

function installStyles() {
	if (document.getElementById("dsh-mg-style")) return function () {};
	var css = [
		".dsh-mg-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--dsw-alias-border-l1,#e9e9ec);background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);border-radius:8px;padding:5px 10px;font-size:13px;cursor:pointer;max-width:min(260px,60vw);overflow:hidden;white-space:nowrap;text-overflow:ellipsis;transition:background .12s ease}",
		".dsh-mg-chip:hover{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-mg-chip:disabled{opacity:.5;cursor:default}",
		".dsh-mg-chip:focus-visible,.dsh-mg-item:focus-visible{outline:2px solid var(--dsw-alias-accent,#4c6ef5);outline-offset:1px}",
		".dsh-mg-caret{font-size:10px;color:var(--dsw-alias-label-tertiary,#8a8a8f);flex:none}",
		".dsh-mg-menu{position:fixed;z-index:300;width:min(max-content,92vw);min-width:min(300px,92vw);max-width:min(440px,92vw);overflow:auto;overscroll-behavior:contain;background:var(--dsw-specific-menu,var(--dsw-alias-bg-layer-3,var(--dsw-alias-bg-base,#fff)));border:1px solid var(--dsw-alias-border-l2,#e4e4e7);border-radius:10px;box-shadow:0 10px 32px rgba(0,0,0,.14);padding:6px;display:none;animation:dsh-mg-in .1s ease}",
		"@keyframes dsh-mg-in{from{opacity:0;transform:translateY(2px)}to{opacity:1;transform:none}}",
		".dsh-mg-sub{min-width:min(320px,92vw)}",
		".dsh-mg-item{display:flex;flex-direction:column;gap:2px;width:100%;text-align:left;border:none;background:none;border-radius:7px;padding:7px 10px;cursor:pointer;font-size:13px;color:var(--dsw-alias-label-primary,#1a1a1a)}",
		".dsh-mg-item:hover{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-mg-item.is-cur{outline:1px solid color-mix(in srgb,var(--dsw-alias-accent,#4c6ef5) 45%,transparent)}",
		".dsh-mg-group{position:relative;align-items:baseline;flex-direction:row;justify-content:space-between;gap:8px}",
		".dsh-mg-group .dsh-mg-desc{flex:1}",
		".dsh-mg-name{font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}",
		".dsh-mg-desc{font-size:11.5px;color:var(--dsw-alias-label-tertiary,#8a8a8f);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}",
		".dsh-mg-group.is-open{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		"@media (pointer:coarse){.dsh-mg-item{padding:11px 12px}.dsh-mg-chip{padding:8px 12px}}",
		"@media (prefers-reduced-motion:reduce){.dsh-mg-menu{animation:none}}"
	].join("\n");
	var style = document.createElement("style");
	style.id = "dsh-mg-style";
	style.textContent = css;
	document.head.appendChild(style);
	return function () { style.remove(); };
}

function apply(ctx) {
	ctx.effect(function () { return installStyles(); }, "dsh-mode-group: styles");
	ctx.inject(["slots", "conversation", "sessions", "workspaces", "connection", "remote"], function (scope) {
		var active = true;
		var stops = [];
		function addStop(f) { stops.push(f); }
		var api = scope.get("connection").api;
		var ctl = createController(api, function () {
			if (!active) return undefined;
			try {
				var state = scope.sessions.list.getSnapshot();
				var s = state.current === undefined ? undefined : state.byId[state.current];
				return s === undefined ? undefined : { id: s.id, blank: s.blank, agentPreset: s.agentPreset };
			} catch { return undefined; }
		}, function (sessionId, agentPreset) {
			try { scope.sessions.noteAgentPreset(sessionId, agentPreset); } catch { /* 列表不在时静默 */ }
		});
		addStop(scope.sessions.list.subscribe(function () {
			if (!active) return;
			try { ctl.applyStaged(); } catch { /* 失活窗口静默 */ }
		}));
		addStop(scope.remote.$on("agent-preset/selected", function (sessionId, agentPreset) {
			try { scope.sessions.noteAgentPreset(sessionId, agentPreset); } catch { /* 同上 */ }
		}));
		scope.slots.inject("conversation.hero.agentPreset", function () {
			var make = function (priority) {
				return scope.slots.register({ name: "conversation.hero.agentPreset", priority: priority }, function () {
				var useCtl = function (sel) {
					var st = useState(ctl.snap());
					useEffect(function () { return ctl.subscribe(function (s) { st[1](s); }); }, []);
					return sel === undefined ? st[0] : sel(st[0]);
				};
				return React.createElement(Chip, { ctl: ctl, useCtl: useCtl, key: "dsh-mg" });
				});
			};
			try {
				return make(-1);
			} catch (e1) {
				// 同优先级已有占用（另一插件也接管了此槽）——降一档继续遮蔽并留痕
				console.warn("[dsh-mode-group] priority -1 已被占用，回退 -2：", e1 && e1.message);
				try { return make(-2); } catch (e2) { console.warn("[dsh-mode-group] 注册放弃（槽竞争失败），官方选择器保持：", e2 && e2.message); return function () { return null; }; }
			}
		});
		return function () {
			active = false;
			stops.forEach(function (f) { try { f(); } catch { /* 已失效静默 */ } });
		};
	});
}

module.exports = { name: "dsh-mode-group-client", inject: ["slots", "locale", "connection", "remote"], apply: apply };
return module.exports; } });
