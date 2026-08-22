window.__ModuleLoader__.load({ id: "@dsh-external/dsh-attack-atlas", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-attack-atlas client — 会话标签页「AttackAtlas」：未选模式=引导页；
// 进入配套模式=该模式的架构体系矩阵（作战流程带 + 主类×子项 + 四态点亮 + 图例统计）。
// 双击格子/主类/阶段 = 派单进当前会话；单键=详情浮层（含人工回退标态）。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useCallback = React.useCallback, useRef = React.useRef;

function api(endpoint, payload) {
	return fetch("/dsh-attack-atlas/" + endpoint, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(payload || {})
	}).then(function (r) { return r.json(); });
}

var ATLAS_MODES = [
	{ id: "attack-defense", label: "攻防评估模式" },
	{ id: "pentest", label: "渗透测试模式" },
	{ id: "code-audit", label: "代码审计模式" },
	{ id: "av-evasion", label: "免杀对抗模式" },
	{ id: "incident-response", label: "应急溯源模式" },
	{ id: "binary-analysis", label: "二进制分析模式" },
	{ id: "cloud-security", label: "云安全攻防模式" },
	{ id: "ctf-solver", label: "CTF 解题模式" }
];
var STATE_META = {
	todo: { label: "未测", cls: "is-todo" },
	"tested-found": { label: "已测·有发现", cls: "is-found" },
	"tested-clear": { label: "已测·未命中", cls: "is-clear" },
	na: { label: "不具备", cls: "is-na" },
	"budget-stop": { label: "预算耗尽", cls: "is-budget" }
};
var STAGE_META = { active: { label: "进行中", cls: "is-active" }, done: { label: "完成", cls: "is-done" } };
var KIND_LABEL = { domain: "域名", web: "Web 站点", ip: "IP/主机", api: "API 服务", miniprogram: "小程序", android: "Android", ios: "iOS", desktop: "桌面客户端", component: "组件/中间件", cloud: "云资产", ai: "AI 服务", other: "其他" };

function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function fmtTime(s) { return s ? String(s).replace("T", " ").slice(0, 16) : ""; }

//#region 样式（磨砂深蓝 · 与成果页 UI 同风）
var CSS = [
	".dsh-ata-root{position:relative;display:flex;flex-direction:column;min-height:100%;height:100%;overflow:hidden;color:#dbe8f6;background:radial-gradient(1200px 500px at 70% -10%,rgba(35,90,160,.35),transparent 60%),radial-gradient(900px 420px at 0% 110%,rgba(20,60,120,.3),transparent 55%),linear-gradient(180deg,#081b33 0%,#061225 100%);font-size:13px}",
	".dsh-ata-root::before{content:\"\";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(rgba(58,157,255,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(58,157,255,.06) 1px,transparent 1px);background-size:40px 40px}",
	".dsh-ata-wrap{position:relative;display:flex;flex-direction:column;gap:10px;padding:12px 14px;min-height:100%;box-sizing:border-box;flex:1;min-height:0}",
	".dsh-ata-panel{position:relative;border:1px solid rgba(58,157,255,.35);border-radius:10px;background:rgba(10,30,60,.45);backdrop-filter:blur(10px);box-shadow:0 0 15px rgba(58,157,255,.1)}",
	".dsh-ata-head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px 14px;padding:8px 14px;flex:none}",
	".dsh-ata-title{font-size:18px;font-weight:700;letter-spacing:2px;background:linear-gradient(90deg,#7cc8ff,#ffffff,#7cc8ff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}",
	".dsh-ata-sub{font-size:11px;color:#8fb4d9;letter-spacing:1px}",
	".dsh-ata-stats{display:flex;gap:6px;flex-wrap:wrap;align-items:center}",
	".dsh-ata-stat{border:1px solid rgba(58,157,255,.35);border-radius:8px;padding:3px 9px;background:rgba(58,157,255,.08);text-align:center;min-width:54px}",
	".dsh-ata-stat b{display:block;font-size:14px;line-height:1.2}",
	".dsh-ata-stat span{font-size:10px;color:#9db9d8}",
	".dsh-ata-stat.s-found b{color:#f5c542}.dsh-ata-stat.s-clear b{color:#38d4ff}.dsh-ata-stat.s-na b{color:#8d99ab}.dsh-ata-stat.s-budget b{color:#ff9f43}.dsh-ata-stat.s-pct b{color:#7cc8ff}",
	".dsh-ata-legend{display:flex;gap:10px;flex-wrap:wrap;align-items:center;font-size:11px;color:#9db9d8}",
	".dsh-ata-dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px;vertical-align:-1px}",
	".dsh-ata-dot.d-found{background:#f5c542;box-shadow:0 0 6px rgba(245,197,66,.7)}",
	".dsh-ata-dot.d-clear{background:#38d4ff;box-shadow:0 0 6px rgba(56,212,255,.7)}",
	".dsh-ata-dot.d-na{background:#59657a}",
	".dsh-ata-dot.d-budget{background:#ff9f43}",
	".dsh-ata-dot.d-todo{background:transparent;border:1px dashed #55688a}",
	".dsh-ata-hint{font-size:11px;color:#7d97b8}",
	".dsh-ata-targets{display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:6px 14px 9px;flex:none;border-top:1px solid rgba(58,157,255,.2)}",
	".dsh-ata-tgt-label{font-size:11px;color:#8fb4d9;letter-spacing:1px}",
	".dsh-ata-tgt{display:inline-flex;align-items:center;gap:5px;border:1px solid rgba(58,157,255,.45);border-radius:6px;padding:2px 9px;font-size:11px;color:#d8ecff;background:rgba(58,157,255,.1);backdrop-filter:blur(6px)}",
	".dsh-ata-tgt i{font-style:normal;font-size:10px;color:#7cc8ff}",
	".dsh-ata-stages{display:flex;align-items:stretch;gap:0;padding:10px 14px;overflow-x:auto;flex:none}",
	".dsh-ata-stage{position:relative;flex:1;min-width:86px;display:flex;flex-direction:column;align-items:center;gap:5px;padding:5px 4px;cursor:default;user-select:none}",
	".dsh-ata-stage::before{content:\"\";position:absolute;top:50%;left:-50%;width:100%;height:1px;background:linear-gradient(90deg,transparent,rgba(58,157,255,.5),transparent)}",
	".dsh-ata-stage:first-child::before{display:none}",
	".dsh-ata-node{width:24px;height:24px;border-radius:50%;border:1px solid rgba(58,157,255,.5);background:rgba(10,30,60,.7);display:flex;align-items:center;justify-content:center;font-size:11px;color:#7d97b8;transition:all .25s}",
	".dsh-ata-stage.is-done .dsh-ata-node{background:linear-gradient(135deg,#3f8ef7,#38d4ff);border-color:#38d4ff;color:#04101f;box-shadow:0 0 10px rgba(56,212,255,.55);font-weight:700}",
	".dsh-ata-stage.is-active .dsh-ata-node{border-color:#f5c542;color:#f5c542;box-shadow:0 0 0 4px rgba(245,197,66,.15),0 0 12px rgba(245,197,66,.4);animation:dsh-ata-pulse 1.6s ease-in-out infinite}",
	"@keyframes dsh-ata-pulse{0%,100%{box-shadow:0 0 0 3px rgba(245,197,66,.12),0 0 8px rgba(245,197,66,.35)}50%{box-shadow:0 0 0 6px rgba(245,197,66,.18),0 0 16px rgba(245,197,66,.55)}}",
	".dsh-ata-stage span{font-size:11px;color:#9db9d8;text-align:center;white-space:nowrap}",
	".dsh-ata-stage.is-done span{color:#bfe3ff}",
	".dsh-ata-stage.is-active span{color:#f5c542}",
	".dsh-ata-forms{display:flex;gap:6px;flex-wrap:wrap;padding:8px 14px 0;flex:none}",
	".dsh-ata-form{border:1px solid rgba(58,157,255,.4);border-radius:999px;background:rgba(58,157,255,.08);color:#bfe3ff;padding:3px 12px;font-size:12px;cursor:pointer;transition:all .2s;user-select:none}",
	".dsh-ata-form:hover{background:rgba(58,157,255,.2)}",
	".dsh-ata-form.is-on{background:linear-gradient(90deg,#3f8ef7,#38d4ff);color:#04101f;font-weight:700;border-color:#38d4ff;box-shadow:0 0 10px rgba(56,212,255,.4)}",
	".dsh-ata-matrix{display:flex;gap:10px;overflow:auto;padding:10px 2px 2px;align-items:flex-start;flex:1;min-height:0}",
	".dsh-ata-zone{display:flex;gap:10px;align-items:stretch}",
	".dsh-ata-zone-cats{display:flex;gap:10px;align-items:flex-start}",
	".dsh-ata-zone-rail{flex:none;writing-mode:vertical-rl;text-align:center;font-size:11px;letter-spacing:4px;color:#7cc8ff;border:1px solid rgba(58,157,255,.3);border-radius:8px;padding:10px 5px;background:rgba(10,30,60,.4);backdrop-filter:blur(8px);user-select:none}",
	".dsh-ata-cat{flex:1 1 190px;min-width:178px;max-width:264px;display:flex;flex-direction:column;border:1px solid rgba(58,157,255,.35);border-radius:10px;background:rgba(10,30,60,.45);backdrop-filter:blur(10px);box-shadow:0 0 15px rgba(58,157,255,.1)}",
	".dsh-ata-cat-head{position:sticky;top:0;z-index:5;display:flex;flex-direction:column;gap:5px;padding:9px 12px 7px;cursor:default;user-select:none;border-radius:10px 10px 0 0;border-bottom:1px solid rgba(58,157,255,.25);background:linear-gradient(180deg,rgba(13,36,70,.97),rgba(10,30,60,.92));backdrop-filter:blur(10px)}",
	".dsh-ata-cat-name{font-size:13px;font-weight:700;color:#e8f3ff;letter-spacing:1px;line-height:1.3}",
	".dsh-ata-cat-desc{font-size:10px;color:#7d97b8;font-weight:400;letter-spacing:0}",
	".dsh-ata-cat-meter{display:flex;align-items:center;gap:6px}",
	".dsh-ata-cat-bar{flex:1;height:5px;border-radius:3px;background:rgba(58,157,255,.14);overflow:hidden}",
	".dsh-ata-cat-bar i{display:block;height:100%;background:linear-gradient(90deg,#3f8ef7,#38d4ff);transition:width .4s}",
	".dsh-ata-cat-count{font-size:10px;color:#9db9d8;flex:none;white-space:nowrap}",
	".dsh-ata-items{display:flex;flex-direction:column;gap:5px;padding:8px 10px 10px}",
	".dsh-ata-item{display:block;width:100%;border-radius:6px;padding:5px 9px;font-size:12px;line-height:1.35;text-align:left;cursor:default;user-select:none;transition:all .2s;word-break:break-word;white-space:normal;box-sizing:border-box}",
	".dsh-ata-item.is-todo{border:1px dashed #4a5f80;color:#8ba3c2;background:rgba(14,34,64,.4)}",
	".dsh-ata-item.is-todo:hover{border-color:#6f8fc0;color:#b9d2ee}",
	".dsh-ata-item.is-found{border:1px solid rgba(245,197,66,.75);color:#ffe9ad;background:linear-gradient(135deg,rgba(245,197,66,.28),rgba(245,197,66,.1));box-shadow:0 0 10px rgba(245,197,66,.28)}",
	".dsh-ata-item.is-clear{border:1px solid rgba(56,212,255,.6);color:#d8f4ff;background:linear-gradient(135deg,rgba(56,212,255,.22),rgba(56,212,255,.08));box-shadow:0 0 8px rgba(56,212,255,.22)}",
	".dsh-ata-item.is-na{border:1px solid rgba(93,107,128,.55);color:#8d99ab;background:rgba(93,107,128,.12);text-decoration:line-through;text-decoration-color:rgba(141,153,171,.6)}",
	".dsh-ata-item.is-budget{border:1px solid rgba(255,159,67,.65);color:#ffd9ae;background:rgba(255,159,67,.12)}",
	".dsh-ata-item .dsh-ata-badge{display:inline-block;margin-left:5px;font-size:10px;font-weight:700;color:#f5c542}",
	".dsh-ata-pop{position:fixed;z-index:60;width:264px;padding:12px 13px;border:1px solid rgba(58,157,255,.5);border-radius:10px;background:rgba(8,24,46,.92);backdrop-filter:blur(14px);box-shadow:0 8px 30px rgba(2,8,20,.6)}",
	".dsh-ata-pop h5{margin:0 0 6px;font-size:13px;color:#eaf4ff}",
	".dsh-ata-pop .dsh-ata-pop-row{font-size:11px;color:#9db9d8;line-height:1.7;word-break:break-all}",
	".dsh-ata-pop .dsh-ata-markrow{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}",
	".dsh-ata-mark{border:1px solid rgba(58,157,255,.45);background:rgba(58,157,255,.1);color:#cfe6ff;border-radius:6px;padding:3px 8px;font-size:11px;cursor:pointer}",
	".dsh-ata-mark:hover{background:rgba(58,157,255,.25)}",
	".dsh-ata-mark.is-danger{border-color:rgba(255,120,120,.5);color:#ffc9c9}",
	".dsh-ata-reason{width:100%;margin-top:6px;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:5px 8px;font-size:11px;box-sizing:border-box;outline:none}",
	".dsh-ata-toast{position:fixed;right:18px;bottom:18px;z-index:70;max-width:380px;padding:10px 14px;border-radius:8px;border:1px solid rgba(58,157,255,.5);background:rgba(8,24,46,.94);backdrop-filter:blur(12px);color:#d8ecff;font-size:12px;box-shadow:0 6px 24px rgba(2,8,20,.55)}",
	".dsh-ata-toast.is-err{border-color:rgba(255,120,120,.55);color:#ffd6d6}",
	".dsh-ata-guide{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px;flex:1;padding:48px 20px;text-align:center}",
	".dsh-ata-guide-title{font-size:22px;font-weight:700;letter-spacing:4px;background:linear-gradient(90deg,#7cc8ff,#ffffff,#7cc8ff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}",
	".dsh-ata-guide-text{color:#9db9d8;font-size:13px;line-height:2;max-width:520px}",
	".dsh-ata-guide-modes{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;max-width:640px}",
	".dsh-ata-guide-mode{border:1px solid rgba(58,157,255,.4);border-radius:999px;padding:6px 16px;font-size:13px;color:#bfe3ff;background:rgba(58,157,255,.08)}",
	".dsh-ata-pending{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;flex:1;padding:48px 20px;text-align:center;color:#9db9d8}",
	".dsh-ata-chainbtn{border:1px solid rgba(245,197,66,.55);border-radius:8px;padding:4px 12px;font-size:12px;color:#ffe9ad;background:rgba(245,197,66,.12);cursor:pointer;transition:all .2s;user-select:none}",
	".dsh-ata-chainbtn:hover{background:rgba(245,197,66,.25);box-shadow:0 0 10px rgba(245,197,66,.3)}",
	".dsh-ata-modal{position:fixed;inset:0;z-index:80;display:flex;align-items:center;justify-content:center;background:rgba(4,12,24,.74);backdrop-filter:blur(9px)}",
	".dsh-ata-chainpanel{width:min(1180px,95vw);height:min(760px,90vh);display:flex;flex-direction:column;border:1px solid rgba(58,157,255,.45);border-radius:12px;background:linear-gradient(180deg,rgba(9,26,50,.97),rgba(6,17,36,.97));box-shadow:0 20px 70px rgba(0,0,0,.55)}",
	".dsh-ata-chaintoolbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 18px;border-bottom:1px solid rgba(58,157,255,.3);flex:none}",
	".dsh-ata-chaintitle{font-size:15px;font-weight:700;letter-spacing:2px;color:#e8f3ff}",
	".dsh-ata-chainstats{display:flex;gap:6px;font-size:11px;color:#9db9d8;align-items:center}",
	".dsh-ata-chainwrap{flex:1;overflow:auto;padding:14px;min-height:0}",
	".dsh-ata-chainlegend{display:flex;gap:12px;flex-wrap:wrap;padding:6px 18px 10px;border-top:1px solid rgba(58,157,255,.3);font-size:11px;color:#9db9d8;flex:none}"
].join("\n");
function installStyles() {
	var style = document.createElement("style");
	style.id = "dsh-ata-style";
	style.textContent = CSS;
	document.head.appendChild(style);
	return function () { style.remove(); };
}
//#endregion

//#region 视图

function AtlasView(props) {
	var sessionId = props.sessionId != null ? String(props.sessionId) : "";
	var sessionsStore = props.sessionsStore;
	var version = useState(0);
	var force = version[1];
	var tax = useState(null); var setTax = tax[1];
	var cov = useState({ cells: [], stages: [] }); var setCov = cov[1];
	var form = useState("all"); var setForm = form[1];
	var pop = useState(null); var setPop = pop[1];
	var chainOpen = useState(false); var setChainOpen = chainOpen[1];
	var toast = useState(null); var setToast = toast[1];
	var toastTimer = useRef(0);

	var preset = "";
	try {
		var snap = sessionsStore && sessionsStore.list.getSnapshot();
		var s = snap && (sessionId ? snap.byId[sessionId] : snap.byId[snap.current]);
		preset = s && s.agentPreset ? String(s.agentPreset) : "";
	} catch { /* 快照不可用时按未选模式处理 */ }

	useEffect(function () {
		if (!sessionsStore || !sessionsStore.list) return;
		try { return sessionsStore.list.subscribe(function () { force(function (n) { return n + 1; }); }); } catch { return; }
	}, [sessionsStore]);

	var mode = ATLAS_MODES.some(function (m) { return m.id === preset; }) ? preset : "";
	// 列表源退化兜底（宿主重启后既有会话的 agentPreset 可能退化为组合名）：
	// 会话存在但 mode 解析不出时，问服务端一次真相（agents 注册表 → composedPreset）。
	var serverMode = useState(""); var setServerMode = serverMode[1];
	var serverAsked = useRef("");
	useEffect(function () {
		if (!sessionId || mode) { serverAsked.current = ""; if (serverMode[0]) setServerMode(""); return; }
		if (serverAsked.current === sessionId) return;
		serverAsked.current = sessionId;
		api("session.mode", { sessionId: sessionId }).then(function (r) {
			if (r && r.mode) setServerMode(r.mode);
		}).catch(function () {});
	}, [sessionId, mode]);
	var resolvedMode = mode || (ATLAS_MODES.some(function (m) { return m.id === serverMode[0]; }) ? serverMode[0] : "");
	var taxData = tax[0];
	var taxonomy = resolvedMode && taxData ? (taxData.taxonomies[resolvedMode] || null) : null;

	var loadCov = useCallback(function () {
		if (!sessionId || !resolvedMode) return;
		api("coverage.get", { sessionId: sessionId, mode: resolvedMode }).then(function (r) {
			if (r && r.cells) setCov({ cells: r.cells, stages: r.stages || [] });
		}).catch(function () {});
	}, [sessionId, resolvedMode]);

	useEffect(function () {
		if (taxData === null) api("taxonomy.get", {}).then(setTax).catch(function () { setTax({ taxonomies: {} }); });
	}, []);
	useEffect(function () { loadCov(); }, [loadCov]);
	useEffect(function () {  // 运行时点亮：矩阵可见期间轻量轮询
		if (!resolvedMode || !taxonomy || taxonomy.pending) return;
		var h = window.setInterval(loadCov, 5000);
		return function () { window.clearInterval(h); };
	}, [resolvedMode, taxonomy, loadCov]);
	useEffect(function () { setForm("all"); setPop(null); }, [resolvedMode]);

	function say(text, err) {
		setToast({ text: text, err: !!err });
		window.clearTimeout(toastTimer.current);
		toastTimer.current = window.setTimeout(function () { setToast(null); }, 3600);
	}

	function trigger(payload) {
		if (!sessionId) return;
		api("atlas.trigger", Object.assign({ sessionId: sessionId, mode: resolvedMode }, payload)).then(function (r) {
			if (r && r.ok) say("已派单进当前会话，完成后按终态自动点亮");
			else say((r && r.error) || "派单失败", true);
		}).catch(function () { say("派单失败（通道不可达）", true); });
	}

	function manualMark(key, state, reason) {
		if (state === "__clear__") {
			api("coverage.clear", { sessionId: sessionId, mode: resolvedMode, key: key })
				.then(function (r) {
					if (r && r.ok) { loadCov(); setPop(null); say("已清除，格子回到未测"); }
					else say((r && r.error) || "清除失败", true);
				}).catch(function () { say("清除失败", true); });
			return;
		}
		api("coverage.mark", { sessionId: sessionId, mode: resolvedMode, key: key, state: state, reason: reason || "" })
			.then(function (r) {
				if (r && r.ok) { loadCov(); setPop(null); say("已人工回写：" + (STATE_META[state] || { label: state }).label); }
				else say((r && r.error) || "回写失败", true);
			}).catch(function () { say("回写失败", true); });
	}

	if (!sessionId) {
		return React.createElement("div", { className: "dsh-ata-root" },
			React.createElement("div", { className: "dsh-ata-guide" },
				React.createElement("div", { className: "dsh-ata-guide-title" }, "AttackAtlas"),
				React.createElement("div", { className: "dsh-ata-guide-text" }, "等待会话上下文——新建会话后本页自动绑定。")));
	}
	if (!resolvedMode) {
		return React.createElement("div", { className: "dsh-ata-root" },
			React.createElement("div", { className: "dsh-ata-guide" },
				React.createElement("div", { className: "dsh-ata-guide-title" }, "AttackAtlas"),
				React.createElement("div", { className: "dsh-ata-guide-text" },
					"当前会话未选择专业安全模式。图谱与模式体系一一对应——", React.createElement("br", null),
					"请先在会话中进入以下任一模式，进入后本页自动展示该模式的架构体系："),
				React.createElement("div", { className: "dsh-ata-guide-modes" },
					ATLAS_MODES.map(function (m) { return React.createElement("span", { key: m.id, className: "dsh-ata-guide-mode" }, m.label); }))),
			toastNode(toast[0]));
	}
	if (!taxonomy || taxonomy.pending) {
		var mLabel = (ATLAS_MODES.find(function (m) { return m.id === resolvedMode; }) || {}).label || resolvedMode;
		return React.createElement("div", { className: "dsh-ata-root" },
			React.createElement("div", { className: "dsh-ata-pending" },
				React.createElement("div", { className: "dsh-ata-guide-title" }, "AttackAtlas"),
				React.createElement("div", null, mLabel + " 的架构体系编排中"),
				React.createElement("div", { className: "dsh-ata-guide-text" }, "渗透测试模式体系已就绪；其余模式体系按同一矩阵范式逐步纳入。")),
			toastNode(toast[0]));
	}
	return React.createElement("div", { className: "dsh-ata-root" },
		React.createElement(MatrixView, {
			mode: resolvedMode, taxonomy: taxonomy, cov: cov[0],
			openChain: function () { setChainOpen(true); }, targets: (cov[0].targets || []).map(function (t) { return { seq: t.seq, label: t.label, kindLabel: KIND_LABEL[t.kind] || t.kind, note: t.note }; }), form: form[0], setForm: setForm,
			pop: pop[0], setPop: setPop, trigger: trigger, manualMark: manualMark, openChain: function () { setChainOpen(true); }
		}),
		chainOpen[0] ? React.createElement(ChainModal, {
			sessionId: sessionId, mode: resolvedMode, taxonomy: taxonomy, trigger: trigger, onClose: function () { setChainOpen(false); }
		}) : null,
		toastNode(toast[0]));
}

function toastNode(toast) {
	if (!toast) return null;
	return React.createElement("div", { className: "dsh-ata-toast" + (toast.err ? " is-err" : "") }, toast.text);
}

function MatrixView(props) {
	var taxonomy = props.taxonomy, cov = props.cov, form = props.form;
	var S_META = STATE_META;
	if (taxonomy.stateLabels) {
		S_META = {};
		for (var sk in STATE_META) S_META[sk] = STATE_META[sk];
		for (var lk in taxonomy.stateLabels) if (S_META[lk]) S_META[lk] = { label: taxonomy.stateLabels[lk], cls: S_META[lk].cls };
	}
	var S_SHORT = { found: "有发现", clear: "未命中", na: "不具备", budget: "预算停" };
	if (taxonomy.stateShort) for (var sk2 in taxonomy.stateShort) S_SHORT[sk2] = taxonomy.stateShort[sk2];
	var cells = {};
	(cov.cells || []).forEach(function (c) { cells[c.key] = c; });
	var stageMap = {};
	(cov.stages || []).forEach(function (s) { stageMap[s.stage] = s; });

	var visibleCats = (taxonomy.categories || []).filter(function (c) {
		if (!form || form === "all") return true;
		var allow = (taxonomy.formCategories || {})[form] || [];
		return allow.indexOf(c.id) >= 0;
	});

	var stat = { total: 0, found: 0, clear: 0, na: 0, budget: 0, todo: 0 };
	var STAT_KEY = { "tested-found": "found", "tested-clear": "clear", "na": "na", "budget-stop": "budget", "todo": "todo" };
	var catRows = visibleCats.map(function (c) {
		var items = c.items.filter(function (i) {
			return !i.forms || !form || form === "all" || i.forms.indexOf(form) >= 0;
		}).map(function (i) {
			var rec = cells[c.id + "/" + i.id] || cells[c.id];
			var state = rec ? rec.state : "todo";
			stat.total++; stat[STAT_KEY[state] || "todo"]++;
			return { cat: c, item: i, key: c.id + "/" + i.id, state: state, rec: rec };
		});
		return { cat: c, items: items };
	}).filter(function (r) { return r.items.length > 0; });

	var lit = stat.found + stat.clear + stat.na + stat.budget;
	var pct = stat.total ? Math.round((lit / stat.total) * 100) : 0;

	return React.createElement("div", { className: "dsh-ata-wrap" },
		React.createElement("div", { className: "dsh-ata-panel dsh-ata-head" },
			React.createElement("div", null,
				React.createElement("div", { className: "dsh-ata-title" }, "AttackAtlas · " + taxonomy.label),
				React.createElement("div", { className: "dsh-ata-sub" }, "覆盖面参考标准 —— 双击派单 · 单键详情 · 运转终态实时点亮")),
			React.createElement("div", { className: "dsh-ata-stats" },
				statCard("s-found", stat.found, S_SHORT.found),
				statCard("s-clear", stat.clear, S_SHORT.clear),
				statCard("s-na", stat.na, S_SHORT.na),
				statCard("s-budget", stat.budget, S_SHORT.budget),
				statCard("", stat.total - lit, "未测"),
				statCard("s-pct", pct + "%", "覆盖率"),
				taxonomy.chain ? React.createElement("button", {
					type: "button", className: "dsh-ata-chainbtn", onClick: props.openChain || function () {}
				}, "链路拓扑图") : null)),
		React.createElement(TargetStrip, { targets: props.targets || [] }),
		React.createElement("div", { className: "dsh-ata-panel" },
			React.createElement("div", { className: "dsh-ata-stages" },
				(taxonomy.stages || []).map(function (s) {
					var rec = stageMap[s.id];
					var cls = rec ? (STAGE_META[rec.state] || {}).cls || "" : "";
					return React.createElement("div", {
						key: s.id, className: "dsh-ata-stage" + (cls ? " " + cls : ""),
						onDoubleClick: function () { props.trigger({ level: "stage", stageId: s.id }); },
						title: "双击派单：推进该阶段"
					},
					React.createElement("div", { className: "dsh-ata-node" }, rec && rec.state === "done" ? "✓" : ""),
					React.createElement("span", null, s.label));
				})),
			React.createElement("div", { className: "dsh-ata-legend", style: { padding: "0 16px 10px" } },
				React.createElement("span", null, React.createElement("i", { className: "dsh-ata-dot d-found" }), S_META["tested-found"].label),
				React.createElement("span", null, React.createElement("i", { className: "dsh-ata-dot d-clear" }), S_META["tested-clear"].label),
				React.createElement("span", null, React.createElement("i", { className: "dsh-ata-dot d-na" }), S_META.na.label),
				React.createElement("span", null, React.createElement("i", { className: "dsh-ata-dot d-budget" }), S_META["budget-stop"].label),
				React.createElement("span", null, React.createElement("i", { className: "dsh-ata-dot d-todo" }), "未测"),
				React.createElement("span", { className: "dsh-ata-hint" }, "双击阶段推进 · 双击主类整组开测 · 双击子项单格开测")),
			React.createElement("div", { className: "dsh-ata-forms" },
				React.createElement("span", {
					key: "all", className: "dsh-ata-form" + (form === "all" ? " is-on" : ""),
					onClick: function () { props.setForm("all"); }
				}, "全部"),
				(taxonomy.forms || []).map(function (f) {
					return React.createElement("span", {
						key: f.id, className: "dsh-ata-form" + (form === f.id ? " is-on" : ""),
						onClick: function () { props.setForm(f.id); }
					}, f.label);
				})),
			React.createElement("div", { style: { height: 10 } })),
		React.createElement("div", { className: "dsh-ata-matrix" },
			zoneGroups(taxonomy, catRows).map(function (g) {
				return React.createElement("div", { key: g.key, className: "dsh-ata-zone" },
					g.rail ? React.createElement("div", { className: "dsh-ata-zone-rail" }, g.rail) : null,
					React.createElement("div", { className: "dsh-ata-zone-cats" },
						catRows.filter(function (row) { return g.keys.has(row.cat.id); }).map(function (row) {
				var litN = row.items.filter(function (i) { return i.state !== "todo"; }).length;
				var foundN = row.items.filter(function (i) { return i.state === "tested-found"; }).length;
				var p = row.items.length ? Math.round((litN / row.items.length) * 100) : 0;
				return React.createElement("div", { key: row.cat.id, className: "dsh-ata-cat" },
					React.createElement("div", {
						className: "dsh-ata-cat-head",
						onDoubleClick: function () { props.trigger({ level: "category", categoryId: row.cat.id, formId: form }); },
						title: "双击派单：整组开测"
					},
						React.createElement("span", { className: "dsh-ata-cat-name" }, row.cat.label),
						row.cat.desc ? React.createElement("span", { className: "dsh-ata-cat-desc" }, row.cat.desc) : null,
						React.createElement("span", { className: "dsh-ata-cat-meter" },
							React.createElement("span", { className: "dsh-ata-cat-bar" }, React.createElement("i", { style: { width: p + "%" } })),
							React.createElement("span", { className: "dsh-ata-cat-count" }, litN + "/" + row.items.length + (foundN ? " · 发现" + foundN : "")))),
					React.createElement("div", { className: "dsh-ata-items" },
						row.items.map(function (it) {
							return React.createElement(ItemChip, {
								key: it.key, data: it, pop: props.pop, setPop: props.setPop,
								trigger: props.trigger, manualMark: props.manualMark, form: form
							});
						})));
						})));
			})),
		props.pop ? React.createElement(Popover, {
			pop: props.pop, setPop: props.setPop, manualMark: props.manualMark, stateMeta: S_META, shortLabels: S_SHORT
		}) : null);
}

/** 战场分组：有 zones 的模式按 zone 连续分组（rail=战场名）；无 zones 单组无 rail。 */
function zoneGroups(taxonomy, catRows) {
	var zones = taxonomy.zones;
	if (!zones || zones.length === 0) return [{ key: "__all__", rail: "", keys: new Set(catRows.map(function (r) { return r.cat.id; })) }];
	return zones.map(function (z) {
		return {
			key: z.id, rail: z.label,
			keys: new Set(catRows.filter(function (r) { return r.cat.zone === z.id; }).map(function (r) { return r.cat.id; }))
		};
	}).filter(function (g) { return g.keys.size > 0; });
}

var CHAIN_KIND_META = {
	entry: { label: "入口", fill: "rgba(56,212,255,.16)", stroke: "#38d4ff" },
	host: { label: "主机", fill: "rgba(58,157,255,.13)", stroke: "rgba(58,157,255,.65)" },
	segment: { label: "网段关口", fill: "rgba(124,200,255,.10)", stroke: "#7cc8ff", dash: "5 3" },
	bastion: { label: "堡垒机", fill: "rgba(245,197,66,.16)", stroke: "#f5c542" },
	dc: { label: "域控", fill: "rgba(255,143,95,.16)", stroke: "#ff8f5f" },
	cred: { label: "凭据", fill: "rgba(180,140,255,.15)", stroke: "#b48cff" },
	other: { label: "资产", fill: "rgba(93,107,128,.14)", stroke: "rgba(141,153,171,.6)" }
};

/** 拓扑分层布局：无入边（或多入口）为第 0 层，其余 = 前驱最大层 +1（环路由访问序兜底）。 */
function layoutChain(chain) {
	var nodes = chain.nodes || [], edges = chain.edges || [];
	var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });
	var preds = {}; nodes.forEach(function (n) { preds[n.id] = []; });
	edges.forEach(function (e) { if (byId[e.src] && byId[e.dst]) preds[e.dst].push(e.src); });
	var level = {}; nodes.forEach(function (n) { level[n.id] = preds[n.id].length ? -1 : 0; });
	for (var round = 0; round < nodes.length + 2; round++) {
		var changed = false;
		nodes.forEach(function (n) {
			if (level[n.id] >= 0) return;
			var ready = preds[n.id].every(function (p) { return level[p] >= 0; });
			if (ready) { level[n.id] = 1 + Math.max.apply(null, preds[n.id].map(function (p) { return level[p]; })); changed = true; }
		});
		if (!changed) break;
	}
	nodes.forEach(function (n) { if (level[n.id] < 0) level[n.id] = 0; }); // 环路兜底：提至入口层侧写为 0
	var byLevel = {};
	nodes.forEach(function (n) { (byLevel[level[n.id]] = byLevel[level[n.id]] || []).push(n); });
	var COL = 230, ROW = 84, X0 = 30, Y0 = 34, W = 172, H = 56;
	var pos = {}, maxLevel = 0, maxRows = 1;
	Object.keys(byLevel).map(Number).sort(function (a, b) { return a - b; }).forEach(function (lv) {
		maxLevel = Math.max(maxLevel, lv); maxRows = Math.max(maxRows, byLevel[lv].length);
		byLevel[lv].forEach(function (n, i) { pos[n.id] = { x: X0 + lv * COL, y: Y0 + i * ROW, lv: lv }; });
	});
	return { pos: pos, byLevel: byLevel, width: X0 + (maxLevel + 1) * COL - (COL - W) + 30, height: Y0 + maxRows * ROW + 20, W: W, H: H, nodes: nodes, edges: edges, byId: byId };
}

function ChainModal(props) {
	var chain = useState({ nodes: [], edges: [] }); var setChain = chain[1];
	var KINDS = (props.taxonomy && props.taxonomy.chainKinds) || CHAIN_KIND_META;
	useEffect(function () {
		var load = function () {
			if (!props.sessionId || !props.mode) return;
			api("chain.list", { sessionId: props.sessionId, mode: props.mode }).then(function (r) {
				if (r && r.nodes) setChain({ nodes: r.nodes, edges: r.edges || [] });
			}).catch(function () {});
		};
		load();
		var h = window.setInterval(load, 3000);
		return function () { window.clearInterval(h); };
	}, [props.sessionId, props.mode]);
	var g = layoutChain(chain[0]);
	var majorN = g.nodes.filter(function (n) { return n.major; }).length;
	return React.createElement("div", { className: "dsh-ata-modal", onClick: function (e) { if (e.target === e.currentTarget) props.onClose(); } },
		React.createElement("div", { className: "dsh-ata-chainpanel" },
			React.createElement("div", { className: "dsh-ata-chaintoolbar" },
				React.createElement("span", { className: "dsh-ata-chaintitle" }, "链路拓扑图"),
				React.createElement("span", { className: "dsh-ata-chainstats" },
					"节点 ", React.createElement("b", { style: { color: "#d8ecff" } }, g.nodes.length),
					" · 边 ", React.createElement("b", { style: { color: "#d8ecff" } }, g.edges.length),
					" · 重大成果 ", React.createElement("b", { style: { color: "#f5c542" } }, majorN)),
				React.createElement("span", { style: { flex: 1 } }),
				React.createElement("button", { type: "button", className: "dsh-ata-chainbtn", onClick: function () { props.trigger({ level: "chain-gen" }); } }, "从会话生成（模型登记）"),
				React.createElement("button", { type: "button", className: "dsh-ata-mark", onClick: props.onClose }, "关闭")),
			React.createElement("div", { className: "dsh-ata-chainwrap" },
				g.nodes.length === 0
					? React.createElement("div", { style: { color: "#9db9d8", textAlign: "center", padding: "70px 20px", lineHeight: 2.2 } },
						"暂无链路数据——两条路成图：", React.createElement("br", null),
						"① 模型侧在突破/拿权/跨段时调 redteam_atlas_chain 登记节点与边（随战役实时生长）；", React.createElement("br", null),
						"② 点右上「从会话生成」派单，模型按会话上下文一次性登记；多入口/无拓扑按实际画。")
					: React.createElement("svg", { width: g.width, height: g.height, style: { minWidth: "100%" } },
						React.createElement("defs", null, React.createElement("marker", { id: "dsh-ata-arrow", markerWidth: "8", markerHeight: "8", refX: "7", refY: "3", orient: "auto" },
							React.createElement("path", { d: "M0,0 L7,3 L0,6 Z", fill: "rgba(120,170,220,.8)" })),
							React.createElement("marker", { id: "dsh-ata-arrow-gold", markerWidth: "8", markerHeight: "8", refX: "7", refY: "3", orient: "auto" },
								React.createElement("path", { d: "M0,0 L7,3 L0,6 Z", fill: "#f5c542" }))),
						g.edges.map(function (e, i) {
							var a = g.pos[e.src], b = g.pos[e.dst];
							if (!a || !b) return null;
							var gold = (g.byId[e.dst] || {}).major;
							var x1 = a.x + g.W, y1 = a.y + g.H / 2, x2 = b.x, y2 = b.y + g.H / 2;
							var mx = (x1 + x2) / 2;
							var d = "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2;
							return React.createElement("g", { key: "e" + i },
								React.createElement("path", { d: d, fill: "none", stroke: gold ? "#f5c542" : "rgba(120,170,220,.55)", strokeWidth: gold ? 1.8 : 1.3, markerEnd: "url(#" + (gold ? "dsh-ata-arrow-gold" : "dsh-ata-arrow") + ")" }),
								e.label ? React.createElement("text", { x: mx, y: (y1 + y2) / 2 - 6, textAnchor: "middle", fontSize: 10, fill: gold ? "#ffe9ad" : "#8fb4d9", stroke: "rgba(6,17,36,.9)", strokeWidth: 3, paintOrder: "stroke" }, e.label) : null);
						}),
						g.nodes.map(function (n) {
							var p = g.pos[n.id];
							var meta = KINDS[n.kind] || KINDS.other || CHAIN_KIND_META.other;
							var stroke = n.major ? "#f5c542" : meta.stroke;
							return React.createElement("g", { key: n.id, transform: "translate(" + p.x + "," + p.y + ")" },
								React.createElement("rect", { width: g.W, height: g.H, rx: 10, fill: meta.fill, stroke: stroke, strokeWidth: n.major ? 2 : 1.2, strokeDasharray: meta.dash || null, filter: n.major ? "drop-shadow(0 0 6px rgba(245,197,66,.45))" : null }),
								React.createElement("text", { x: 12, y: 23, fontSize: 13, fontWeight: 700, fill: "#eaf4ff" }, String(n.label).slice(0, 16)),
								React.createElement("text", { x: 12, y: 42, fontSize: 10.5, fill: "#9db9d8" }, meta.label + (n.seg ? " · " + n.seg : "") + (n.note ? " · " + String(n.note).slice(0, 12) : "")),
								n.major ? React.createElement("g", null,
									React.createElement("rect", { x: g.W - 44, y: 8, width: 36, height: 17, rx: 8, fill: "rgba(245,197,66,.2)", stroke: "#f5c542", strokeWidth: 1 }),
									React.createElement("text", { x: g.W - 26, y: 20, textAnchor: "middle", fontSize: 10, fill: "#ffe9ad", fontWeight: 700 }, "重大")) : null);
						}))),
			React.createElement("div", { className: "dsh-ata-chainlegend" },
				Object.keys(KINDS).map(function (k) {
					return React.createElement("span", { key: k }, React.createElement("i", { style: { display: "inline-block", width: 10, height: 10, borderRadius: 2, marginRight: 4, background: KINDS[k].fill, border: "1px solid " + KINDS[k].stroke, verticalAlign: "-1px" } }), KINDS[k].label);
				}),
				React.createElement("span", { style: { color: "#f5c542" } }, "金框=重大成果 · 金边=通向重大成果"))));
}

function TargetStrip(props) {
	var targets = props.targets || [];
	return React.createElement("div", { className: "dsh-ata-panel dsh-ata-targets" },
		React.createElement("span", { className: "dsh-ata-tgt-label" }, "目标锚定"),
		targets.length === 0
			? React.createElement("span", { className: "dsh-ata-hint" }, "未登记目标——模型侧 redteam_atlas_target 登记（与资产清单基线同步）后，双击派单自动带目标上下文")
			: targets.map(function (t) {
				return React.createElement("span", { key: t.seq, className: "dsh-ata-tgt", title: t.note || "" }, t.label, React.createElement("i", null, t.kindLabel || ""));
			}));
}
function statCard(cls, value, label) {
	return React.createElement("div", { className: "dsh-ata-stat " + cls },
		React.createElement("b", null, String(value)), React.createElement("span", null, label));
}

function ItemChip(props) {
	var d = props.data;
	var meta = STATE_META[d.state] || STATE_META.todo;
	var rec = d.rec;
	return React.createElement("span", {
		className: "dsh-ata-item " + meta.cls,
		onClick: function (e) {
			e.stopPropagation();
			props.setPop({ key: d.key, title: d.item.label, cat: d.cat.label, state: d.state, rec: rec, ref: d.item.ref || "", pb: d.item.pb || "", x: e.clientX, y: e.clientY });
		},
		onDoubleClick: function (e) {
			e.stopPropagation();
			props.setPop(null);
			props.trigger({ level: "item", categoryId: d.cat.id, itemId: d.item.id, formId: props.form });
		},
		title: d.item.label + "（双击开测）"
	}, d.item.label, rec && rec.state === "tested-found" && rec.findingRefs
		? React.createElement("span", { className: "dsh-ata-badge" }, rec.findingRefs.split(/[,,]/).filter(Boolean).length)
		: null);
}

function Popover(props) {
	var pop = props.pop;
	var ref = useRef(null);
	var pos = useState({ left: -9999, top: -9999 }); var setPos = pos[1];
	var reason = useState(""); var setReason = reason[1];
	var needReason = useState(null); var setNeedReason = needReason[1];

	useEffect(function () {
		var el = ref.current;
		if (!el) return;
		var w = el.offsetWidth || 264, h = el.offsetHeight || 180;
		var left = Math.max(8, Math.min(pop.x + 10, window.innerWidth - w - 8));
		var top = pop.y + 10 + h > window.innerHeight - 8 ? Math.max(8, pop.y - h - 10) : pop.y + 10;
		setPos({ left: left, top: top });
		var onDown = function (e) { if (el && !el.contains(e.target)) props.setPop(null); };
		window.addEventListener("mousedown", onDown);
		return function () { window.removeEventListener("mousedown", onDown); };
	}, []);

	var rec = pop.rec || {};
	function mark(state) {
		if (state === "na" || state === "budget-stop") { setNeedReason(state); setReason(rec.reason || ""); return; }
		props.manualMark(pop.key, state, "");
	}
	return React.createElement("div", { className: "dsh-ata-pop", ref: ref, style: { left: pos[0].left, top: pos[0].top } },
		React.createElement("h5", null, pop.cat, " / ", pop.title),
		React.createElement("div", { className: "dsh-ata-pop-row" }, "状态：", ((props.stateMeta || STATE_META)[pop.state] || { label: pop.state }).label),
		rec.target ? React.createElement("div", { className: "dsh-ata-pop-row" }, "目标：", esc(rec.target)) : null,
		rec.reason ? React.createElement("div", { className: "dsh-ata-pop-row" }, "原因：", esc(rec.reason)) : null,
		rec.findingRefs ? React.createElement("div", { className: "dsh-ata-pop-row" }, "关联 finding：", esc(rec.findingRefs)) : null,
		rec.updatedAt ? React.createElement("div", { className: "dsh-ata-pop-row" }, "更新：", fmtTime(rec.updatedAt)) : null,
		pop.ref ? React.createElement("div", { className: "dsh-ata-pop-row" }, pop.ref.indexOf("pentest:") === 0 ? "知识手册：pentest refs/" + esc(pop.ref.slice(8)) : "知识手册：refs/" + esc(pop.ref)) : (pop.pb ? React.createElement("div", { className: "dsh-ata-pop-row" }, "打法出处：playbook ", esc(pop.pb)) : null),
		React.createElement("div", { className: "dsh-ata-markrow" },
			React.createElement("button", { type: "button", className: "dsh-ata-mark", onClick: function () { mark("tested-found"); } }, (props.shortLabels || {}).found || "有发现"),
			React.createElement("button", { type: "button", className: "dsh-ata-mark", onClick: function () { mark("tested-clear"); } }, (props.shortLabels || {}).clear || "未命中"),
			React.createElement("button", { type: "button", className: "dsh-ata-mark", onClick: function () { mark("na"); } }, "不具备"),
			React.createElement("button", { type: "button", className: "dsh-ata-mark", onClick: function () { mark("budget-stop"); } }, "预算停"),
			React.createElement("button", { type: "button", className: "dsh-ata-mark is-danger", onClick: function () { props.manualMark(pop.key, "__clear__", ""); } }, "清除")),
		needReason[0] ? React.createElement("div", null,
			React.createElement("input", {
				className: "dsh-ata-reason", placeholder: "原因（必填）：资产无此面 / 超出授权 / 环境不具备…",
				value: reason[0], onChange: function (e) { setReason(e.target.value); }
			}),
			React.createElement("div", { className: "dsh-ata-markrow", style: { marginTop: 6 } },
				React.createElement("button", {
					type: "button", className: "dsh-ata-mark",
					onClick: function () { if (reason[0].trim()) props.manualMark(pop.key, needReason[0], reason[0]); }
				}, "确认回写"),
				React.createElement("button", {
					type: "button", className: "dsh-ata-mark",
					onClick: function () { setNeedReason(null); }
				}, "取消"))) : null);
}

//#endregion

function apply(ctx) {
	ctx.effect(function () { return installStyles(); }, "dsh-attack-atlas: styles");
	ctx.inject(["sessions"], function (scope) {
		var sessionsStore = scope.sessions;
		ctx.slots.inject("conversation.view", function () {
			return ctx.slots.register({
				name: "conversation.view",
				id: "attack-atlas",
				order: 54,
				label: function () { return "AttackAtlas"; }
			}, function (props) {
				return React.createElement(AtlasView, Object.assign({}, props, { sessionsStore: sessionsStore }));
			});
		});
		return function () {};
	});
}

module.exports = { name: "dsh-attack-atlas-client", inject: ["slots"], apply: apply };
return module.exports; } });
