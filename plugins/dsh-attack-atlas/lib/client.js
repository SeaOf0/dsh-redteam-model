window.__ModuleLoader__.load({ id: "@dsh-external/dsh-attack-atlas", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-attack-atlas client — 会话标签页「AttackAtlas」：未选模式=引导页；
// 进入配套模式=该模式的架构体系矩阵（作战流程带 + 主类×子项 + 四态点亮 + 图例统计）。
// 双击格子/主类/阶段 = 派单进当前会话；单键=详情浮层（含人工回退标态）。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useCallback = React.useCallback, useRef = React.useRef;

var dshCsrf = {};
/** CSRF token 懒加载（同源 GET /csrf，跨源页面读不到）；POST 回带 x-dsh-csrf 头。 */
function csrfOf(base) {
	if (!dshCsrf[base]) dshCsrf[base] = fetch(base + "/csrf").then(function (r) { return r.json(); }).then(function (r) { return r && r.token ? r.token : ""; }).catch(function () { return ""; });
	return dshCsrf[base];
}
function api(endpoint, payload) {
	return csrfOf("/dsh-attack-atlas").then(function (tok) {
		return fetch("/dsh-attack-atlas/" + endpoint, {
			method: "POST",
			headers: tok ? { "content-type": "application/json", "x-dsh-csrf": tok } : { "content-type": "application/json" },
			body: JSON.stringify(payload || {})
		}).then(function (r) {
			return r.text().then(function (t) {
				try { return JSON.parse(t); } catch { throw new Error("HTTP " + r.status + (t ? "\uff1a" + String(t).slice(0, 60) : "")); }
			});
		});
	});
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
	".dsh-ata-chainlegend{display:flex;gap:12px;flex-wrap:wrap;padding:6px 18px 10px;border-top:1px solid rgba(58,157,255,.3);font-size:11px;color:#9db9d8;flex:none}",
	".dsh-ata-mbtn{border:1px solid rgba(58,157,255,.55);border-radius:8px;padding:4px 12px;font-size:12px;color:#cfe6ff;background:rgba(58,157,255,.12);cursor:pointer;transition:all .2s;user-select:none}",
	".dsh-ata-mbtn:hover{background:rgba(58,157,255,.25);box-shadow:0 0 10px rgba(58,157,255,.3)}",
	".dsh-ata-mpanel{width:min(1280px,96vw);height:min(820px,92vh);display:flex;flex-direction:column;border:1px solid rgba(58,157,255,.45);border-radius:12px;background:linear-gradient(180deg,rgba(9,26,50,.98),rgba(6,17,36,.98));box-shadow:0 20px 70px rgba(0,0,0,.55)}",
	".dsh-ata-mhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 18px;border-bottom:1px solid rgba(58,157,255,.3);flex:none}",
	".dsh-ata-mtitle{font-size:15px;font-weight:700;letter-spacing:2px;color:#e8f3ff}",
	".dsh-ata-mdirty{font-size:10px;color:#f5c542;border:1px solid rgba(245,197,66,.45);border-radius:6px;padding:1px 7px}",
	".dsh-ata-mheadbtn{border:1px solid rgba(58,157,255,.45);border-radius:8px;padding:4px 12px;font-size:12px;color:#cfe6ff;background:rgba(58,157,255,.1);cursor:pointer}",
	".dsh-ata-mheadbtn:hover{background:rgba(58,157,255,.25)}",
	".dsh-ata-mheadbtn.is-run{border-color:rgba(245,197,66,.55);color:#ffe9ad;background:rgba(245,197,66,.12)}",
	".dsh-ata-mheadwrap{position:relative}",
	".dsh-ata-mbody{display:flex;flex:1;min-height:0}",
	".dsh-ata-mpal{width:236px;flex:none;border-right:1px solid rgba(58,157,255,.3);display:flex;flex-direction:column;min-height:0}",
	".dsh-ata-mpal-search{margin:8px 10px;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:5px 9px;font-size:12px;outline:none}",
	".dsh-ata-mpal-in{flex:1;overflow:auto;padding:4px 10px 10px}",
	".dsh-ata-mpal-cat{display:flex;align-items:center;gap:6px;padding:6px 2px;cursor:pointer;user-select:none}",
	".dsh-ata-mpal-cat b{font-size:12px;color:#e8f3ff;font-weight:600;flex:1}",
	".dsh-ata-mpal-cat span{font-size:10px;color:#7d97b8}",
	".dsh-ata-madd{border:1px solid rgba(58,157,255,.45);border-radius:5px;background:rgba(58,157,255,.12);color:#9fd0ff;font-size:12px;cursor:pointer;line-height:1.2;padding:1px 7px}",
	".dsh-ata-madd:hover{background:rgba(58,157,255,.3)}",
	".dsh-ata-mpal-item{display:flex;align-items:center;gap:6px;padding:3px 2px 3px 14px;cursor:pointer;user-select:none}",
	".dsh-ata-mpal-item span{font-size:11px;color:#b9d2ee;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
	".dsh-ata-mpal-item i{font-style:normal;font-size:9px;color:#7cc8ff;flex:none}",
	".dsh-ata-mcanvaswrap{position:relative;flex:1;min-width:0;display:flex}",
	".dsh-ata-mcanvas{flex:1;overflow:auto;position:relative;background-image:linear-gradient(rgba(58,157,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(58,157,255,.05) 1px,transparent 1px);background-size:28px 28px}",
	".dsh-ata-mnode{position:absolute;border-radius:9px;padding:7px 10px;font-size:12px;line-height:1.35;box-sizing:border-box;cursor:grab;user-select:none;word-break:break-word;background:rgba(12,32,62,.94);border:1.2px solid rgba(56,212,255,.65);color:#d8f4ff;box-shadow:0 2px 10px rgba(2,8,20,.4)}",
	".dsh-ata-mnode.is-cat{border-color:rgba(58,157,255,.7);background:rgba(16,42,80,.94);color:#cfe6ff}",
	".dsh-ata-mnode.is-sel{border-color:#f5c542;box-shadow:0 0 0 3px rgba(245,197,66,.18),0 0 14px rgba(245,197,66,.35)}",
	".dsh-ata-mnode.is-warn{animation:dsh-ata-mblink 1s ease-in-out infinite}",
	"@keyframes dsh-ata-mblink{0%,100%{box-shadow:0 0 4px rgba(255,143,95,.35)}50%{box-shadow:0 0 16px rgba(255,143,95,.75)}}",
	".dsh-ata-mnode-k{display:inline-block;font-size:9px;border:1px solid rgba(124,200,255,.4);border-radius:4px;padding:0 4px;color:#7cc8ff;margin-right:5px;vertical-align:1px}",
	".dsh-ata-mnode-note{position:absolute;right:6px;top:3px;font-size:10px;color:#f5c542}",
	".dsh-ata-mport{position:absolute;right:-8px;top:50%;margin-top:-6px;width:12px;height:12px;border-radius:50%;background:#0a1e3c;border:1.5px solid #38d4ff;cursor:crosshair}",
	".dsh-ata-mport:hover{background:#38d4ff;box-shadow:0 0 8px rgba(56,212,255,.8)}",
	".dsh-ata-mbar{position:absolute;display:flex;gap:5px;align-items:center;z-index:6}",
	".dsh-ata-mbar-in{flex:1;min-width:0;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(8,24,46,.96);color:#dbe8f6;padding:3px 8px;font-size:11px;outline:none}",
	".dsh-ata-mbar-b{border:1px solid rgba(58,157,255,.45);border-radius:6px;background:rgba(58,157,255,.15);color:#cfe6ff;font-size:11px;cursor:pointer;padding:2px 8px;flex:none}",
	".dsh-ata-mbar-b.is-danger{border-color:rgba(255,120,120,.5);color:#ffc9c9}",
	".dsh-ata-mfoot{display:flex;gap:10px;align-items:center;padding:10px 16px;border-top:1px solid rgba(58,157,255,.3);flex:none;flex-wrap:wrap}",
	".dsh-ata-mfoot label{font-size:11px;color:#8fb4d9;flex:none}",
	".dsh-ata-mfoot input{border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:5px 9px;font-size:12px;outline:none}",
	".dsh-ata-mcheck{position:absolute;right:14px;top:12px;z-index:7;width:300px;max-height:70%;overflow:auto;padding:10px 12px;border:1px solid rgba(58,157,255,.5);border-radius:10px;background:rgba(8,24,46,.96);backdrop-filter:blur(12px);font-size:11px;line-height:1.7}",
	".dsh-ata-mcheck h6{margin:0 0 4px;font-size:12px;color:#eaf4ff}",
	".dsh-ata-mcheck .is-err{color:#ff9f9f}",
	".dsh-ata-mcheck .is-warn{color:#ffd9ae}",
	".dsh-ata-mcheck .is-hint{color:#7d97b8}",
	".dsh-ata-mcard{position:relative;width:min(560px,92vw);max-height:82vh;overflow:auto;padding:18px 20px;border:1px solid rgba(245,197,66,.5);border-radius:12px;background:linear-gradient(180deg,rgba(9,26,50,.98),rgba(6,17,36,.98));box-shadow:0 20px 70px rgba(0,0,0,.55)}",
	".dsh-ata-mcard h5{margin:0 0 8px;font-size:14px;color:#eaf4ff}",
	".dsh-ata-mrow{display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap}",
	".dsh-ata-mrow input{flex:1;min-width:180px;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:6px 9px;font-size:12px;outline:none;box-sizing:border-box}",
	".dsh-ata-mrow textarea{width:100%;box-sizing:border-box;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:6px 9px;font-size:12px;outline:none;resize:vertical}",
	".dsh-ata-mtpl{position:absolute;top:46px;left:0;z-index:9;width:340px;max-height:60vh;overflow:auto;padding:10px;border:1px solid rgba(58,157,255,.5);border-radius:10px;background:rgba(8,24,46,.97);backdrop-filter:blur(12px)}",
	".dsh-ata-mtpl-item{border:1px solid rgba(58,157,255,.3);border-radius:8px;padding:7px 9px;margin-bottom:7px}",
	".dsh-ata-mtpl-item b{font-size:12px;color:#e8f3ff}",
	".dsh-ata-mtpl-item .meta{font-size:10px;color:#7d97b8;margin:2px 0 5px}",
	".dsh-ata-mtpl-acts{display:flex;gap:5px;flex-wrap:wrap}",
	".dsh-ata-mtpl-acts button{border:1px solid rgba(58,157,255,.45);border-radius:5px;background:rgba(58,157,255,.1);color:#cfe6ff;font-size:11px;cursor:pointer;padding:2px 8px}",
	".dsh-ata-mtpl-acts button.is-danger{border-color:rgba(255,120,120,.5);color:#ffc9c9}",
	".dsh-ata-mhelp{position:fixed;right:26px;bottom:64px;z-index:95;width:min(480px,90vw);max-height:74vh;overflow:auto;padding:16px 18px;border:1px solid rgba(124,200,255,.5);border-radius:12px;background:rgba(8,24,46,.97);backdrop-filter:blur(14px);box-shadow:0 16px 50px rgba(2,8,20,.6);font-size:12px;line-height:1.9;color:#b9d2ee}",
	".dsh-ata-mhelp h5{margin:0 0 6px;font-size:14px;color:#eaf4ff}",
	".dsh-ata-mhelp h6{margin:10px 0 2px;font-size:12px;color:#7cc8ff}",
	".dsh-ata-mfab{position:absolute;right:16px;bottom:14px;z-index:8;width:30px;height:30px;border-radius:50%;border:1px solid rgba(124,200,255,.5);background:rgba(10,30,60,.85);color:#7cc8ff;font-size:15px;cursor:pointer;user-select:none}",
	".dsh-ata-mfab:hover{background:rgba(58,157,255,.25)}",
	".dsh-ata-mnode.is-tool{border-color:rgba(124,227,176,.75);color:#d9fff0;background:rgba(10,42,36,.94)}",
	".dsh-ata-mnode.is-mcp{border-color:rgba(180,140,255,.75);color:#eee4ff;background:rgba(26,14,52,.94)}",
	".dsh-ata-mnode.is-custom{border-color:rgba(255,159,67,.75);color:#ffe6c9;background:rgba(44,24,8,.94)}",
	".dsh-ata-mtoolsec{margin-top:10px;border-top:1px dashed rgba(58,157,255,.35);padding-top:8px}",
	".dsh-ata-mtoolsec h6{margin:0 0 6px;font-size:11px;color:#7cc8ff;letter-spacing:1px}",
	".dsh-ata-mtool-kinds{display:flex;gap:5px;margin-bottom:6px}",
	".dsh-ata-mtool-kind{border:1px solid rgba(58,157,255,.4);border-radius:999px;padding:2px 10px;font-size:11px;color:#b9d2ee;cursor:pointer;user-select:none}",
	".dsh-ata-mtool-kind.is-on{background:linear-gradient(90deg,#3f8ef7,#38d4ff);color:#04101f;font-weight:700;border-color:#38d4ff}",
	".dsh-ata-mtool-in{width:100%;box-sizing:border-box;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:4px 8px;font-size:11px;outline:none;margin-bottom:5px}",
	".dsh-ata-mtool-chips{display:flex;gap:4px;flex-wrap:wrap}",
	".dsh-ata-mtool-chip{border:1px dashed rgba(124,200,255,.35);border-radius:5px;padding:1px 7px;font-size:10px;color:#7cc8ff;cursor:pointer}",
	".dsh-ata-mtool-chip:hover{border-style:solid;color:#bfe3ff}",
	".dsh-ata-capmodes{width:148px;flex:none;border-right:1px solid rgba(58,157,255,.3);overflow:auto;padding:10px 8px;display:flex;flex-direction:column;gap:6px}",
	".dsh-ata-capmode{border:1px solid rgba(58,157,255,.35);border-radius:8px;padding:6px 10px;font-size:12px;color:#b9d2ee;cursor:pointer;user-select:none;text-align:left}",
	".dsh-ata-capmode.is-on{background:linear-gradient(90deg,#3f8ef7,#38d4ff);color:#04101f;font-weight:700;border-color:#38d4ff}",
	".dsh-ata-capgrid{flex:1;overflow:auto;padding:12px;display:flex;flex-direction:column;gap:8px;min-width:0}",
	".dsh-ata-capcard{border:1px solid rgba(58,157,255,.3);border-radius:9px;padding:9px 12px;background:rgba(12,32,62,.6)}",
	".dsh-ata-capcard b{font-size:13px;color:#e8f3ff}",
	".dsh-ata-capcard .meta{font-size:10.5px;color:#7d97b8;margin-top:2px}",
	".dsh-ata-capbadge{display:inline-block;margin-left:6px;font-size:9px;border-radius:4px;padding:0 5px;vertical-align:1px}",
	".dsh-ata-capbadge.b-user{border:1px solid rgba(124,227,176,.55);color:#9fe8c5}",
	".dsh-ata-capbadge.b-mine{border:1px solid rgba(245,197,66,.55);color:#ffe9ad}",
	".dsh-ata-capbadge.b-builtin{border:1px solid rgba(124,200,255,.4);color:#7cc8ff}",
	".dsh-ata-captoggle{display:flex;border:1px solid rgba(58,157,255,.4);border-radius:8px;overflow:hidden;user-select:none}",
	".dsh-ata-captoggle span{padding:4px 12px;font-size:12px;color:#b9d2ee;cursor:pointer}",
	".dsh-ata-captoggle span.is-on{background:linear-gradient(90deg,#3f8ef7,#38d4ff);color:#04101f;font-weight:700}",
	".dsh-ata-capform label{font-size:11px;color:#8fb4d9;display:block;margin:10px 0 3px}",
	".dsh-ata-capform input,.dsh-ata-capform select,.dsh-ata-capform textarea{width:100%;box-sizing:border-box;border:1px solid rgba(58,157,255,.4);border-radius:6px;background:rgba(10,30,60,.6);color:#dbe8f6;padding:6px 9px;font-size:12px;outline:none}",
	".dsh-ata-capform textarea{resize:vertical;font-family:inherit}"
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
	var methodOpen = useState(false); var setMethodOpen = methodOpen[1];
	var capsOpen = useState(false); var setCapsOpen = capsOpen[1];
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
			if (r && r.cells) setCov({ cells: r.cells, stages: r.stages || [], targets: r.targets || [] });
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
				React.createElement("div", { className: "dsh-ata-guide-text" }, "该模式的架构体系按同一矩阵范式编排中，就绪后本页自动展示。")),
			toastNode(toast[0]));
	}
	return React.createElement("div", { className: "dsh-ata-root" },
		React.createElement(MatrixView, {
			mode: resolvedMode, taxonomy: taxonomy, cov: cov[0],
			openChain: function () { setChainOpen(true); }, targets: (cov[0].targets || []).map(function (t) { return { seq: t.seq, label: t.label, kindLabel: KIND_LABEL[t.kind] || t.kind, note: t.note }; }), form: form[0], setForm: setForm,
			pop: pop[0], setPop: setPop, trigger: trigger, manualMark: manualMark,
			openMethod: function () { setMethodOpen(true); },
			openCaps: function () { setCapsOpen(true); }
		}),
		chainOpen[0] ? React.createElement(ChainModal, {
			sessionId: sessionId, mode: resolvedMode, taxonomy: taxonomy, trigger: trigger, onClose: function () { setChainOpen(false); }
		}) : null,
		methodOpen[0] ? React.createElement(MethodModal, {
			sessionId: sessionId, mode: resolvedMode, taxonomy: taxonomy,
			targets: (cov[0].targets || []).map(function (t) { return { label: t.label, kindLabel: KIND_LABEL[t.kind] || t.kind }; }),
			say: say, onClose: function () { setMethodOpen(false); }
		}) : null,
		capsOpen[0] ? React.createElement(CapabilityModal, {
			mode: resolvedMode, taxonomies: (taxData && taxData.taxonomies) || {},
			say: say, onClose: function () { setCapsOpen(false); }
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
				React.createElement("button", {
					type: "button", className: "dsh-ata-mbtn", onClick: props.openMethod || function () {}
				}, "自定义工作方法论"),
				React.createElement("button", {
					type: "button", className: "dsh-ata-mbtn", onClick: props.openCaps || function () {}
				}, "能力库"),
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
					React.createElement("span", { className: "dsh-ata-hint" }, "双击阶段推进 · 双击主类整组开测 · 双击子项单格开测 · 右上「自定义工作方法论」自由编排")),
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

//#region 自定义工作方法论（MethodModal）

var METHOD_W = 180, METHOD_H = 54;
var TOOL_KIND_META = { tool: "工具", mcp: "MCP", custom: "自定义" };
var TOOL_QUICK = ["nmap", "httpx", "nuclei", "sqlmap", "ffuf", "subfinder"];

function methodMaxSeq(ns) {
	var m = 0;
	(ns || []).forEach(function (n) { var v = Number(String(n.id).replace(/^n/, "")); if (v > m) m = v; });
	return m;
}

/** 与服务端 layerMethod 同款分层：分层对齐；环 → 循环列；孤立 → 右侧独立列。 */
function methodFormatLayout(nodes, edges) {
	var connected = {};
	edges.forEach(function (e) { connected[e.src] = 1; connected[e.dst] = 1; });
	var core = nodes.filter(function (n) { return connected[n.id]; });
	var isolated = nodes.filter(function (n) { return !connected[n.id]; });
	var indeg = {}, adj = {};
	core.forEach(function (n) { indeg[n.id] = 0; adj[n.id] = []; });
	edges.forEach(function (e) { if (indeg[e.dst] !== undefined) { indeg[e.dst]++; adj[e.src].push(e.dst); } });
	var remaining = core.map(function (n) { return n.id; });
	var layers = [];
	for (;;) {
		var layer = remaining.filter(function (id) { return indeg[id] === 0; });
		if (!layer.length) break;
		layers.push(layer);
		var gone = {}; layer.forEach(function (id) { gone[id] = 1; });
		remaining = remaining.filter(function (id) { return !gone[id]; });
		layer.forEach(function (id) { (adj[id] || []).forEach(function (d) { if (indeg[d] > 0) indeg[d]--; }); });
	}
	var COL = 230, ROW = 82, X0 = 30, Y0 = 26, pos = {}, lv = -1;
	layers.forEach(function (lay, i) { lv = i; lay.forEach(function (id, j) { pos[id] = { x: X0 + i * COL, y: Y0 + j * ROW }; }); });
	var cx = X0 + (lv + 1) * COL;
	remaining.forEach(function (id, j) { pos[id] = { x: cx, y: Y0 + j * ROW }; });
	isolated.forEach(function (n, j) { pos[n.id] = { x: cx + COL, y: Y0 + j * ROW }; });
	return pos;
}

function MethodModal(props) {
	var taxonomy = props.taxonomy, mode = props.mode, say = props.say;
	var DRAFT_KEY = "dsh-atlas-method-draft-" + mode;

	var nodes = useState([]); var setNodes = nodes[1];
	var edges = useState([]); var setEdges = edges[1];
	var stName = useState(""); var setName = stName[1];
	var stTarget = useState(""); var setTarget = stTarget[1];
	var stNotes = useState(""); var setNotes = stNotes[1];
	var currentId = useState(""); var setCurrentId = currentId[1];
	var dirty = useState(false); var setDirty = dirty[1];
	var templates = useState([]); var setTemplates = templates[1];
	var tplOpen = useState(false); var setTplOpen = tplOpen[1];
	var delConfirm = useState(""); var setDelConfirm = delConfirm[1];
	var openCat = useState(""); var setOpenCat = openCat[1];
	var search = useState(""); var setSearch = search[1];
	var toolKind = useState("tool"); var setToolKind = toolKind[1];
	var toolName = useState(""); var setToolName = toolName[1];
	var toolSpec = useState(""); var setToolSpec = toolSpec[1];
	var caps = useState([]); var setCaps = caps[1];
	var selId = useState(""); var setSel = selId[1];
	var selNote = useState(""); var setSelNote = selNote[1];
	var warnIds = useState([]); var setWarnIds = warnIds[1];
	var check = useState(null); var setCheck = check[1];
	var inquiry = useState(null); var setInquiry = inquiry[1];
	var runDlg = useState(null); var setRunDlg = runDlg[1];
	var helpOpen = useState(false); var setHelpOpen = helpOpen[1];
	var connPos = useState(null); var setConnPos = connPos[1];
	var connSrc = useRef(""), hoverId = useRef(""), dragMoved = useRef(false), seq = useRef(0), justSaved = useRef(false);
	var canvasRef = useRef(null), fileRef = useRef(null);

	function firstTarget() { var t = (props.targets || [])[0]; return t ? t.label : ""; }
	function touch() { setDirty(true); setWarnIds([]); }

	function loadTemplates() {
		api("methods.list", { mode: mode }).then(function (r) {
			if (r && r.methods) setTemplates(r.methods);
		}).catch(function () {});
	}

	useEffect(function () {
		loadTemplates();
		api("caps.list", { mode: mode }).then(function (r) { if (r && r.caps) setCaps(r.caps); }).catch(function () {});
		try {
			var raw = window.localStorage.getItem(DRAFT_KEY);
			if (raw) {
				var d = JSON.parse(raw);
				if (d && (d.nodes || []).length) {
					setName(d.name || ""); setTarget(d.target || ""); setNotes(d.notes || "");
					setNodes(d.nodes || []); setEdges(d.edges || []); setCurrentId(d.currentId || "");
					seq.current = methodMaxSeq(d.nodes);
					say("已恢复上次未保存的编排草稿");
				}
			}
		} catch { /* 坏草稿弃用 */ }
	}, []);
	useEffect(function () {
		if (justSaved.current) { justSaved.current = false; return; } // 保存成功后的状态回写不再重建草稿
		if (!nodes[0].length && !edges[0].length && !stName[0]) return;
		try { window.localStorage.setItem(DRAFT_KEY, JSON.stringify({ name: stName[0], target: stTarget[0], notes: stNotes[0], nodes: nodes[0], edges: edges[0], currentId: currentId[0] })); } catch { /* 存不进就算了 */ }
	}, [nodes[0], edges[0], stName[0], stTarget[0], stNotes[0], currentId[0]]);

	function addBlock(ref, label) {
		seq.current += 1;
		var i = seq.current - 1;
		setNodes(function (ns) { return ns.concat([{ id: "n" + seq.current, ref: ref, label: label, note: "", x: 30 + (i % 4) * 230, y: 26 + Math.floor(i / 4) * 82 }]); });
		touch();
		say("已加入模块：" + label);
	}
	function delNode(id) {
		setNodes(function (ns) { return ns.filter(function (n) { return n.id !== id; }); });
		setEdges(function (es) { return es.filter(function (e) { return e.src !== id && e.dst !== id; }); });
		if (selId[0] === id) setSel("");
		touch();
	}
	function addToolBlock() {
		var t = toolName[0].trim();
		if (!t) { say("请先填写工具/MCP 名称", true); return; }
		seq.current += 1;
		var i = seq.current - 1;
		var kindLabel = toolKind[0] === "tool" ? "工具" : toolKind[0] === "mcp" ? "MCP" : "自定义工具";
		setNodes(function (ns) { return ns.concat([{ id: "n" + seq.current, ref: "", nt: toolKind[0], tool: t, spec: toolSpec[0].trim(), label: t, note: "", x: 30 + (i % 4) * 230, y: 26 + Math.floor(i / 4) * 82 }]); });
		touch();
		say("已加入" + kindLabel + "模块：" + t);
		setToolName("");
	}
	function applyNote() {
		var id = selId[0], v = selNote[0];
		setNodes(function (ns) { return ns.map(function (n) { return n.id === id ? Object.assign({}, n, { note: v }) : n; }); });
		touch();
		say("备注已写入模块");
	}

	function startDrag(e, n) {
		if (e.button !== 0) return;
		var t = e.target;
		if (t && String(t.className || "").indexOf("dsh-ata-mport") >= 0) return;
		e.preventDefault();
		var sx = e.clientX, sy = e.clientY, ox = n.x, oy = n.y, moved = false;
		var onMove = function (ev) {
			var dx = ev.clientX - sx, dy = ev.clientY - sy;
			if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
			setNodes(function (ns) { return ns.map(function (m) { return m.id === n.id ? Object.assign({}, m, { x: Math.max(0, ox + dx), y: Math.max(0, oy + dy) }) : m; }); });
		};
		var onUp = function () {
			window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp);
			dragMoved.current = moved;
			if (moved) touch();
		};
		window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
	}

	function startConn(e, id) {
		e.stopPropagation(); e.preventDefault();
		connSrc.current = id;
		var el = canvasRef.current;
		var toXY = function (ev) {
			if (!el) return { x: 0, y: 0 };
			var r = el.getBoundingClientRect();
			return { x: ev.clientX - r.left + el.scrollLeft, y: ev.clientY - r.top + el.scrollTop };
		};
		var onMove = function (ev) { setConnPos(toXY(ev)); };
		var onUp = function () {
			window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp);
			setConnPos(null);
			var src = connSrc.current, dst = hoverId.current;
			connSrc.current = "";
			if (!src || !dst || dst === src) return;
			if (edges[0].some(function (ed) { return ed.src === src && ed.dst === dst; })) { say("该衔接已存在"); return; }
			setEdges(function (es) { return es.concat([{ src: src, dst: dst }]); });
			touch();
			say("已建立衔接");
		};
		window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
	}

	function doValidate(cb) {
		api("methods.validate", { mode: mode, name: stName[0], graph: { nodes: nodes[0], edges: edges[0] } }).then(function (v) {
			if (!v || v.error) { say((v && v.error) || "校验失败", true); return; }
			setCheck(v);
			var ids = [];
			(v.warnings || []).forEach(function (w) { ids = ids.concat(w.ids || []); });
			setWarnIds(ids);
			cb(v);
		}).catch(function () { say("校验失败（通道不可达）", true); });
	}
	function reallySave(after) {
		api("methods.save", { id: currentId[0] || undefined, mode: mode, name: stName[0], target: stTarget[0], notes: stNotes[0], graph: { nodes: nodes[0], edges: edges[0] } }).then(function (r) {
			if (!r || !r.ok) { say((r && r.error) || "保存失败", true); return; }
			justSaved.current = true;
			setCurrentId(r.id); setDirty(false);
			try { window.localStorage.removeItem(DRAFT_KEY); } catch { /* 无草稿可清 */ }
			loadTemplates();
			say("模板已保存：「" + stName[0] + "」");
			if (after === "run") setRunDlg({ id: r.id, name: stName[0], target: stTarget[0] || firstTarget(), notes: stNotes[0] });
		}).catch(function () { say("保存失败（通道不可达）", true); });
	}
	function doSave(after) {
		if (!stName[0].trim()) { say("请先填写方法论名称", true); return; }
		if (after === "run" && !dirty[0] && currentId[0]) {
			setRunDlg({ id: currentId[0], name: stName[0], target: stTarget[0] || firstTarget(), notes: stNotes[0] });
			return; // 闭环已确认过的存档直接运行
		}
		doValidate(function (v) {
			if (v.errors && v.errors.length) { say("存在结构问题，已在校验面板列出", true); return; }
			if (v.warnings && v.warnings.length) { setInquiry({ warnings: v.warnings, hints: v.hints || [], after: after }); return; }
			reallySave(after);
		});
	}
	function confirmRun() {
		var d = runDlg[0];
		api("methods.run", { id: d.id, sessionId: props.sessionId, mode: mode, target: d.target, notes: d.notes }).then(function (r) {
			if (r && r.ok) {
				setRunDlg(null); props.onClose();
				say("已按自定义方法论派单——内置模块进度实时点亮矩阵（自定义模块终态照记可查）");
			} else say((r && r.error) || "运行失败", true);
		}).catch(function () { say("运行失败（通道不可达）", true); });
	}

	function loadTemplate(t) {
		api("methods.get", { id: t.id }).then(function (r) {
			if (!r || !r.method) { say("读取模板失败", true); return; }
			var m = r.method, g = m.graph || { nodes: [], edges: [] };
			setName(m.name); setTarget(m.target || ""); setNotes(m.notes || "");
			setNodes(g.nodes || []); setEdges(g.edges || []);
			seq.current = methodMaxSeq(g.nodes);
			setCurrentId(m.id); setDirty(false); setWarnIds([]); setCheck(null); setSel("");
			setTplOpen(false);
			say("已载入模板：「" + m.name + "」");
		}).catch(function () { say("读取模板失败（通道不可达）", true); });
	}
	function newTemplate() {
		setName(""); setTarget(firstTarget()); setNotes(""); setNodes([]); setEdges([]);
		setCurrentId(""); setDirty(false); setWarnIds([]); setCheck(null); setSel("");
		setTplOpen(false);
	}
	function copyTemplate(id) {
		api("methods.copy", { id: id }).then(function (r) {
			if (r && r.ok) { loadTemplates(); say("已复制为副本"); } else say((r && r.error) || "复制失败", true);
		}).catch(function () { say("复制失败", true); });
	}
	function removeTemplate(id) {
		api("methods.remove", { id: id }).then(function (r) {
			if (r && r.ok) {
				loadTemplates();
				if (currentId[0] === id) { setCurrentId(""); setDirty(true); }
				setDelConfirm("");
				say("模板已删除");
			} else say((r && r.error) || "删除失败", true);
		}).catch(function () { say("删除失败", true); });
	}
	function exportTemplates() {
		api("methods.export", { mode: mode }).then(function (r) {
			var data = JSON.stringify({ format: "attack-atlas-methods", version: 1, methods: (r && r.methods) || [] }, null, 2);
			var blob = new Blob([data], { type: "application/json" });
			var a = document.createElement("a");
			a.href = URL.createObjectURL(blob);
			a.download = "attack-atlas-methods-" + mode + ".json";
			a.click();
			URL.revokeObjectURL(a.href);
			say("已导出本模式模板文件");
		}).catch(function () { say("导出失败", true); });
	}
	function importFile(f) {
		if (!f) return;
		var reader = new FileReader();
		reader.onload = function () {
			var data;
			try { data = JSON.parse(reader.result); } catch { say("文件不是合法 JSON", true); return; }
			var rows = Array.isArray(data) ? data : data.methods;
			if (!Array.isArray(rows)) { say("文件里没有模板数据", true); return; }
			api("methods.import", { methods: rows }).then(function (r) {
				if (!r || !r.ok) { say((r && r.error) || "导入失败", true); return; }
				loadTemplates();
				var sk = (r.skipped || []).map(function (s) { return s.name + "：" + s.reason; }).join("；");
				say("导入成功 " + r.imported.length + " 个" + (sk ? "；跳过 " + r.skipped.length + " 个（" + sk + "）" : ""));
			}).catch(function () { say("导入失败", true); });
		};
		reader.readAsText(f);
	}

	// —— 画布几何 ——
	var byId = {};
	nodes[0].forEach(function (n) { byId[n.id] = n; });
	var cw = 640, chh = 420;
	nodes[0].forEach(function (n) { cw = Math.max(cw, n.x + METHOD_W + 80); chh = Math.max(chh, n.y + METHOD_H + 80); });
	var connFrom = connSrc.current && byId[connSrc.current]
		? { x: byId[connSrc.current].x + METHOD_W, y: byId[connSrc.current].y + METHOD_H / 2 } : null;

	var q = search[0].toLowerCase();
	// 合并体系：内置主类（含挂在其下的自定义子类「用」）+ 自定义主类（「自」）——保存即共享进编排器
	var capCatsSrc = caps[0].filter(function (c) { return c.kind === "category"; });
	var capItemsByCat = {};
	caps[0].forEach(function (c) { if (c.kind === "item") (capItemsByCat[c.cat] = capItemsByCat[c.cat] || []).push(c); });
	var palTaxCats = (taxonomy.categories || []).map(function (c) {
		var extra = (capItemsByCat[c.id] || []).map(function (i) { return { id: i.item, label: i.label, ref: i.ref || "", pb: i.pb || "", _cap: true }; });
		return extra.length ? Object.assign({}, c, { items: c.items.concat(extra) }) : c;
	});
	capCatsSrc.forEach(function (cc) {
		palTaxCats.push({ id: cc.cat, label: cc.label, desc: cc.descr, _cap: true, items: (capItemsByCat[cc.cat] || []).map(function (i) { return { id: i.item, label: i.label, ref: i.ref || "", pb: i.pb || "", _cap: true }; }) });
	});
	var palCats = palTaxCats.filter(function (c) {
		if (!q) return true;
		if (c.label.toLowerCase().indexOf(q) >= 0) return true;
		return c.items.some(function (i) { return i.label.toLowerCase().indexOf(q) >= 0; });
	});

	var chk = check[0];
	var inq = inquiry[0];
	var run = runDlg[0];

	return React.createElement("div", { className: "dsh-ata-modal", onClick: function (e) { if (e.target === e.currentTarget) props.onClose(); } },
		React.createElement("div", { className: "dsh-ata-mpanel" },
			React.createElement("div", { className: "dsh-ata-mhead" },
				React.createElement("span", { className: "dsh-ata-mtitle" }, "自定义工作方法论 · " + taxonomy.label),
				dirty[0] ? React.createElement("span", { className: "dsh-ata-mdirty" }, "未保存") : null,
				React.createElement("span", { style: { flex: 1 } }),
				React.createElement("div", { className: "dsh-ata-mheadwrap" },
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { setTplOpen(!tplOpen[0]); setDelConfirm(""); } }, "模板"),
					tplOpen[0] ? React.createElement("div", { className: "dsh-ata-mtpl", onClick: function (e) { e.stopPropagation(); } },
						React.createElement("div", { className: "dsh-ata-mtpl-acts", style: { marginBottom: 8 } },
							React.createElement("button", { type: "button", onClick: newTemplate }, "新建"),
							React.createElement("button", { type: "button", onClick: function () { fileRef.current && fileRef.current.click(); } }, "导入"),
							React.createElement("button", { type: "button", onClick: exportTemplates }, "导出本模式"),
							React.createElement("input", { ref: fileRef, type: "file", accept: ".json,application/json", style: { display: "none" }, onChange: function (e) { importFile(e.target.files && e.target.files[0]); e.target.value = ""; } })),
						templates[0].length === 0
							? React.createElement("div", { style: { color: "#7d97b8", fontSize: 11, padding: "6px 2px" } }, "暂无保存的模板——编排后点「保存」即可长期使用")
							: templates[0].map(function (t) {
								return React.createElement("div", { key: t.id, className: "dsh-ata-mtpl-item" },
									React.createElement("b", null, t.name),
									React.createElement("div", { className: "meta" }, t.updatedAt + " · " + t.nodeCount + " 模块" + (currentId[0] === t.id ? " · 编辑中" : "")),
									React.createElement("div", { className: "dsh-ata-mtpl-acts" },
										React.createElement("button", { type: "button", onClick: function () { loadTemplate(t); } }, "编辑"),
										React.createElement("button", { type: "button", onClick: function () { setTplOpen(false); setRunDlg({ id: t.id, name: t.name, target: t.target || firstTarget(), notes: t.notes || "" }); } }, "运行"),
										React.createElement("button", { type: "button", onClick: function () { copyTemplate(t.id); } }, "复制"),
										React.createElement("button", {
											type: "button", className: delConfirm[0] === t.id ? "is-danger" : "",
											onClick: function () { if (delConfirm[0] === t.id) removeTemplate(t.id); else setDelConfirm(t.id); }
										}, delConfirm[0] === t.id ? "确认删除？" : "删除")));
							})) : null),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { if (!nodes[0].length) { say("画布为空，先从左侧加入模块", true); return; } var pos = methodFormatLayout(nodes[0], edges[0]); setNodes(function (ns) { return ns.map(function (n) { return pos[n.id] ? Object.assign({}, n, pos[n.id]) : n; }); }); touch(); say("已格式化排版（分层对齐；孤立模块靠右独立列）"); } }, "格式化排版"),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { doValidate(function () { say("校验完成——结果见画布右上面板"); }); } }, "校验"),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { doSave(""); } }, "保存"),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn is-run", onClick: function () { doSave("run"); } }, "运行"),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: props.onClose }, "关闭")),
			React.createElement("div", { className: "dsh-ata-mbody" },
				React.createElement("div", { className: "dsh-ata-mpal" },
					React.createElement("input", { className: "dsh-ata-mpal-search", placeholder: "搜索主类 / 子项…", value: search[0], onChange: function (e) { setSearch(e.target.value); } }),
					React.createElement("div", { className: "dsh-ata-mpal-in" },
						palCats.map(function (c) {
							var open = openCat[0] === c.id || !!q;
							return React.createElement("div", { key: c.id },
								React.createElement("div", { className: "dsh-ata-mpal-cat", onClick: function () { setOpenCat(openCat[0] === c.id ? "" : c.id); } },
										React.createElement("b", null, (openCat[0] === c.id && !q ? "▾ " : "▸ ") + c.label, c._cap ? React.createElement("i", { style: { fontStyle: "normal", fontSize: 9, color: "#ffe9ad", marginLeft: 5 } }, "自") : null),
									React.createElement("span", null, c.items.length + " 项"),
									React.createElement("button", {
										type: "button", className: "dsh-ata-madd",
										onClick: function (e) { e.stopPropagation(); addBlock(c.id, c.label); },
										title: "加入主类模块（整组开测）"
									}, "＋")),
								open ? c.items.filter(function (i) { return !q || i.label.toLowerCase().indexOf(q) >= 0 || c.label.toLowerCase().indexOf(q) >= 0; }).map(function (i) {
									return React.createElement("div", {
										key: i.id, className: "dsh-ata-mpal-item",
										title: (i.ref ? "知识手册：refs/" + i.ref : "打法出处：playbook " + (i.pb || "")) + "（点＋加入画布）"
									},
										React.createElement("span", null, i.label),
										i._cap ? React.createElement("i", { style: { color: "#9fe8c5" } }, "用") : (i.ref ? React.createElement("i", null, "册") : (i.pb ? React.createElement("i", null, "法") : null)),
									React.createElement("button", {
										type: "button", className: "dsh-ata-madd",
										onClick: function (e) { e.stopPropagation(); addBlock(c.id + "/" + i.id, i.label); }
									}, "＋"));
									}) : null);
							}),
							React.createElement("div", { className: "dsh-ata-mtoolsec" },
								React.createElement("h6", null, "工具模块 · 工具 / MCP / 自定义"),
								React.createElement("div", { className: "dsh-ata-mtool-kinds" },
									["tool", "mcp", "custom"].map(function (k) {
										return React.createElement("span", {
											key: k, className: "dsh-ata-mtool-kind" + (toolKind[0] === k ? " is-on" : ""),
											onClick: function () { setToolKind(k); }
										}, TOOL_KIND_META[k]);
									})),
								React.createElement("input", { className: "dsh-ata-mtool-in", placeholder: "名称（如 nmap / chrome-devtools / ja3-eye）", value: toolName[0], onChange: function (e) { setToolName(e.target.value); } }),
								React.createElement("input", { className: "dsh-ata-mtool-in", placeholder: toolKind[0] === "custom" ? "要求描述（做什么、怎么算可用）" : "用途（随运行信封带给模型）", value: toolSpec[0], onChange: function (e) { setToolSpec(e.target.value); } }),
								React.createElement("button", { type: "button", className: "dsh-ata-madd", style: { width: "100%", padding: "4px 0", boxSizing: "border-box" }, onClick: addToolBlock }, "＋ 加入画布"),
								toolKind[0] === "tool"
									? React.createElement("div", { className: "dsh-ata-mtool-chips", style: { marginTop: 5 } },
										TOOL_QUICK.map(function (t) {
											return React.createElement("span", { key: t, className: "dsh-ata-mtool-chip", onClick: function () { setToolName(t); } }, t);
										}))
									: React.createElement("div", { style: { fontSize: 10, color: "#7d97b8", lineHeight: 1.7, marginTop: 5 } }, toolKind[0] === "mcp" ? "MCP 未加载时：运行中先询问是否启用，拒绝则降级同类/脚本" : "自定义工具不存在时：先询问是否安装，批准才装；拒绝则降级同类/写脚本")))),
					React.createElement("div", { className: "dsh-ata-mcanvaswrap" },
					React.createElement("div", {
						className: "dsh-ata-mcanvas", ref: canvasRef,
						onMouseDown: function (e) { if (e.target === e.currentTarget || e.target.className === "dsh-ata-msizer") { setSel(""); } }
					},
						React.createElement("div", { className: "dsh-ata-msizer", style: { position: "relative", width: cw, height: chh } },
							React.createElement("svg", { width: cw, height: chh, style: { position: "absolute", left: 0, top: 0, pointerEvents: "none" } },
								edges[0].map(function (e, i) {
									var a = byId[e.src], b = byId[e.dst];
									if (!a || !b) return null;
									var x1 = a.x + METHOD_W, y1 = a.y + METHOD_H / 2, x2 = b.x, y2 = b.y + METHOD_H / 2;
									var mx = (x1 + x2) / 2;
									var d = "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2;
									return React.createElement("g", { key: "e" + i },
										React.createElement("path", { d: d, fill: "none", stroke: "transparent", strokeWidth: 12, style: { pointerEvents: "stroke", cursor: "pointer" }, onClick: function () { setEdges(function (es) { return es.filter(function (x, j) { return j !== i; }); }); touch(); say("已删除衔接"); } }),
										React.createElement("path", { d: d, fill: "none", stroke: "rgba(120,170,220,.6)", strokeWidth: 1.4, markerEnd: "url(#dsh-ata-marrow)" }));
								}),
								connFrom && connPos[0] ? React.createElement("path", {
									d: "M" + connFrom.x + "," + connFrom.y + " L" + connPos[0].x + "," + connPos[0].y,
									fill: "none", stroke: "#f5c542", strokeWidth: 1.4, strokeDasharray: "5 4"
								}) : null,
								React.createElement("defs", null, React.createElement("marker", { id: "dsh-ata-marrow", markerWidth: "8", markerHeight: "8", refX: "7", refY: "3", orient: "auto" },
									React.createElement("path", { d: "M0,0 L7,3 L0,6 Z", fill: "rgba(120,170,220,.8)" })))),
							nodes[0].length === 0
								? React.createElement("div", { style: { position: "absolute", left: 24, top: 20, color: "#7d97b8", fontSize: 12, lineHeight: 2.2 } },
									"空画布——左侧模块库点「＋」放入模块：", React.createElement("br", null),
									"· 主类模块（蓝框）= 运行时整组开测、逐格点亮", React.createElement("br", null),
									"· 子项模块（青框）= 单点开测，带知识手册锚（册/法）", React.createElement("br", null),
									"· 拖模块摆放；从右侧圆点拖出连线建立衔接；点连线删除；点模块加备注")
								: null,
							nodes[0].map(function (n) {
								var isTax = !n.nt || n.nt === "tax";
								var isCat = isTax && n.ref.indexOf("/") < 0;
								var tag = !isTax ? TOOL_KIND_META[n.nt] || "工具" : (isCat ? "主类" : "子项");
								var hot = connSrc.current && hoverId.current === n.id;
								var cls = "dsh-ata-mnode" + (isTax ? (isCat ? " is-cat" : "") : " is-" + n.nt) + (selId[0] === n.id || hot ? " is-sel" : "") + (warnIds[0].indexOf(n.id) >= 0 ? " is-warn" : "");
								var tip = isTax
									? (isCat ? "主类模块（整组开测）" : "子项模块（单点开测）") + "\n" + n.ref
									: tag + "模块：" + n.tool + (n.spec ? "\n用途：" + n.spec : "") + "\n不可用时按协议处理（询问/降级）";
								return React.createElement("div", {
									key: n.id, className: cls,
									style: { left: n.x, top: n.y, width: METHOD_W, minHeight: METHOD_H },
									title: tip + (n.note ? "\n重点：" + n.note : ""),
									onMouseDown: function (e) { startDrag(e, n); },
									onClick: function () {
										if (dragMoved.current) { dragMoved.current = false; return; }
										setSel(n.id); setSelNote(n.note || "");
									},
									onMouseEnter: function () { hoverId.current = n.id; },
									onMouseLeave: function () { if (hoverId.current === n.id) hoverId.current = ""; }
								},
								React.createElement("span", { className: "dsh-ata-mnode-k" }, tag),
								String(n.label || n.tool || n.ref).slice(0, 14),
								n.note ? React.createElement("span", { className: "dsh-ata-mnode-note", title: n.note }, "※") : null,
								React.createElement("span", { className: "dsh-ata-mport", title: "拖出连线建立衔接", onMouseDown: function (e) { startConn(e, n.id); } }),
								selId[0] === n.id ? React.createElement("div", { className: "dsh-ata-mbar", style: { left: 0, top: -42, width: METHOD_W + 70 }, onMouseDown: function (e) { e.stopPropagation(); } },
									React.createElement("input", {
										className: "dsh-ata-mbar-in", placeholder: "备注/重点（随运行信封带给模型）",
										value: selNote[0], onChange: function (e) { setSelNote(e.target.value); },
										onKeyDown: function (e) { if (e.key === "Enter") applyNote(); }
									}),
									React.createElement("button", { type: "button", className: "dsh-ata-mbar-b", onClick: applyNote }, "存"),
									React.createElement("button", { type: "button", className: "dsh-ata-mbar-b is-danger", onClick: function () { delNode(n.id); } }, "删")) : null);
							}))),
				chk ? React.createElement("div", { className: "dsh-ata-mcheck" },
					React.createElement("h6", null, "校验结果"),
					(chk.errors || []).map(function (e2, i) { return React.createElement("div", { key: "ce" + i, className: "is-err" }, "✗ " + e2); }),
					(chk.warnings || []).map(function (w, i) { return React.createElement("div", { key: "cw" + i, className: "is-warn" }, "△ " + w.msg); }),
					(chk.hints || []).map(function (h, i) { return React.createElement("div", { key: "ch" + i, className: "is-hint" }, "◇ " + h); }),
					!(chk.errors || []).length && !(chk.warnings || []).length ? React.createElement("div", { style: { color: "#7ce3b0" } }, "✓ 结构与闭环全部通过") : null,
					React.createElement("div", { className: "dsh-ata-mtpl-acts", style: { marginTop: 8 } },
						(chk.warnings || []).length ? React.createElement("button", { type: "button", onClick: function () { var ids = []; (chk.warnings || []).forEach(function (w) { ids = ids.concat(w.ids || []); }); setWarnIds(ids); say("已在画布高亮问题模块"); } }, "定位高亮") : null,
						React.createElement("button", { type: "button", onClick: function () { setCheck(null); } }, "关闭"))) : null,
				React.createElement("button", { type: "button", className: "dsh-ata-mfab", title: "如何自定义方法论（帮助）", onClick: function () { setHelpOpen(!helpOpen[0]); } }, "?"))),
			React.createElement("div", { className: "dsh-ata-mfoot" },
				React.createElement("label", null, "名称"),
				React.createElement("input", { style: { width: 170 }, placeholder: "方法论模板名（必填）", value: stName[0], onChange: function (e) { setName(e.target.value); setDirty(true); } }),
				React.createElement("label", null, "目标"),
				React.createElement("input", { style: { flex: "1 1 160px", minWidth: 140 }, placeholder: "域名/ip:port/应用名（运行时可改）", value: stTarget[0], onChange: function (e) { setTarget(e.target.value); setDirty(true); } }),
				React.createElement("label", null, "辅助需求"),
				React.createElement("input", { style: { flex: "2 1 220px", minWidth: 180 }, placeholder: "其他要求（只打 Web 面 / 重点关注登录口 / 出报告…）", value: stNotes[0], onChange: function (e) { setNotes(e.target.value); setDirty(true); } }))),
		inq ? React.createElement("div", { className: "dsh-ata-modal", onClick: function (e) { if (e.target === e.currentTarget) setInquiry(null); } },
			React.createElement("div", { className: "dsh-ata-mcard" },
				React.createElement("h5", null, "闭环询问 —— 您的回复即定案"),
				React.createElement("div", { style: { fontSize: 12, color: "#b9d2ee", lineHeight: 1.9 } }, "您的自定义方法论存在以下闭环问题："),
				(inq.warnings || []).map(function (w, i) { return React.createElement("div", { key: "iw" + i, className: "is-warn", style: { color: "#ffd9ae", fontSize: 12, lineHeight: 1.8 } }, "△ " + w.msg); }),
				(inq.hints || []).map(function (h, i) { return React.createElement("div", { key: "ih" + i, style: { color: "#7d97b8", fontSize: 11 } }, "◇ " + h); }),
				React.createElement("div", { className: "dsh-ata-mrow" },
					React.createElement("button", {
						type: "button", className: "dsh-ata-mheadbtn",
						onClick: function () {
							var ids = [];
							(inq.warnings || []).forEach(function (w) { ids = ids.concat(w.ids || []); });
							setWarnIds(ids); setInquiry(null);
							say("已在画布高亮问题模块——修复后重新保存/运行");
						}
					}, "去修复（画布高亮）"),
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn is-run", onClick: function () { var after = inq.after; setInquiry(null); reallySave(after); } }, "按现状继续"),
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { setInquiry(null); } }, "取消")))) : null,
		run ? React.createElement("div", { className: "dsh-ata-modal", onClick: function (e) { if (e.target === e.currentTarget) setRunDlg(null); } },
			React.createElement("div", { className: "dsh-ata-mcard" },
				React.createElement("h5", null, "运行自定义方法论"),
					React.createElement("div", { style: { fontSize: 12, color: "#9db9d8" } }, "模板：", React.createElement("b", { style: { color: "#e8f3ff" } }, run.name), "（派单进当前会话，按分层执行；内置模块逐项点亮矩阵）"),
				React.createElement("div", { className: "dsh-ata-mrow" },
					React.createElement("label", { style: { fontSize: 11, color: "#8fb4d9", flex: "none" } }, "目标"),
					React.createElement("input", { placeholder: "域名/ip:port/应用名", value: run.target, onChange: function (e) { setRunDlg(Object.assign({}, run, { target: e.target.value })); } })),
				React.createElement("div", { className: "dsh-ata-mrow" },
					React.createElement("textarea", { rows: 3, placeholder: "辅助需求（可改，随信封带给模型）", value: run.notes, onChange: function (e) { setRunDlg(Object.assign({}, run, { notes: e.target.value })); } })),
				React.createElement("div", { style: { fontSize: 11, color: "#7d97b8", marginTop: 6 } }, "会话尚未登记目标时将自动登记该目标；同层步骤模型可并行或自选序，上层未完成不进下层。"),
				React.createElement("div", { className: "dsh-ata-mrow" },
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn is-run", onClick: confirmRun }, "确认运行"),
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { setRunDlg(null); } }, "取消")))) : null,
		helpOpen[0] ? React.createElement("div", { className: "dsh-ata-mhelp" },
			React.createElement("div", { style: { display: "flex", alignItems: "center" } },
				React.createElement("h5", { style: { flex: 1, margin: 0 } }, "如何自定义方法论"),
				React.createElement("button", { type: "button", className: "dsh-ata-mbar-b", onClick: function () { setHelpOpen(false); } }, "关闭")),
			React.createElement("h6", null, "模块"),
			React.createElement("div", null, "左侧模块库点「＋」放入画布。主类模块（蓝框）= 整组开测、子项逐格点亮；子项模块（青框）= 单点开测。标「册」的带知识手册锚、「法」的带 playbook 打法出处，运行信封会自动附上。"),
			React.createElement("h6", null, "工具模块"),
			React.createElement("div", null, "工具（绿框）/ MCP（紫框）/ 自定义工具（橙框）模块可混入链路任意位置。运行到该步先确认可用：自定义工具不存在时先询问您是否安装（说明方式与影响），批准才装，拒绝则降级——同类已有工具优先，其次写脚本等效实现并注明降级；MCP 未加载先询问是否启用，拒绝则降级同类/脚本。严禁未经批准自行安装。"),
			React.createElement("h6", null, "摆放与衔接"),
			React.createElement("div", null, "拖动模块自由摆放；从模块右侧圆点拖出连线到目标模块即建立衔接（先后约束）；点连线删除；点模块可在上方加备注/重点、或删除模块。"),
			React.createElement("h6", null, "自定义能力"),
			React.createElement("div", null, "头部「能力库」里添加的自定义主类（标「自」）与子类（挂内置主类下标「用」）会即时出现在本模块库，与内置模块同样可编排；子类的打法模板会在运行信封里内联带给模型。"),
			React.createElement("h6", null, "格式化排版"),
			React.createElement("div", null, "一键按衔接关系分层对齐；孤立的模块自动排到右侧独立列。"),
			React.createElement("h6", null, "闭环五查"),
			React.createElement("div", null, "① 孤立：没和任何步骤衔接；② 无起点：全部有入边；③ 无终点：全部有出边；④ 断裂：从起点走不到；⑤ 循环：成环。保存/运行时若有闭环问题会来询问您——去修复（画布高亮）或按现状继续，您的回复就是定论，直接继续。"),
			React.createElement("h6", null, "保存与模板"),
			React.createElement("div", null, "命名后保存即长期模板（本模式内），可编辑、复制、删除、导入、导出。编排过程中自动存本地草稿，误关弹层不丢。"),
			React.createElement("h6", null, "运行"),
			React.createElement("div", null, "输入目标与辅助需求后派单进当前会话：模型按分层执行（同层可并行，上层未完成不进下层），每完成一项点亮矩阵对应格子（自定义模块不进矩阵，终态照记、可经 redteam_coverage_list 查）；主类模块运行时展开为子项逐格推进。不点运行则一切照默认全流程。同一模板可在多个会话反复运行。")) : null);
}

//#endregion

//#region 能力库（CapabilityModal）

var CAP_TPL = {
	item: "# 适用场景\n（什么目标/什么面用这招）\n# 验证姿势\n1. \n2. \n# 判定标准\n- 有发现：\n- 未命中：",
	category: "# 覆盖范围\n（这个主类管哪些面）\n# 方法论要点\n- \n# 与其他主类的边界\n"
};

function capBadge(cls, text) {
	return React.createElement("span", { className: "dsh-ata-capbadge " + cls }, text);
}

function CapabilityModal(props) {
	var say = props.say;
	var selMode = useState(props.mode); var setSelMode = selMode[1];
	var source = useState("custom"); var setSource = source[1];
	var view = useState("category"); var setView = view[1];
	var caps = useState([]); var setCaps = caps[1];
	var form = useState(null); var setForm = form[1];
	var detail = useState(null); var setDetail = detail[1];
	var delConfirm = useState(""); var setDelConfirm = delConfirm[1];
	var fileRef = useRef(null);

	var tax = props.taxonomies[selMode[0]] || null;
	var capCats = caps[0].filter(function (c) { return c.kind === "category"; });
	var capItems = caps[0].filter(function (c) { return c.kind === "item"; });
	var catLabelOf = {};
	(tax ? tax.categories : []).forEach(function (c) { catLabelOf[c.id] = c.label; });
	capCats.forEach(function (c) { catLabelOf[c.cat] = c.label; });
	var customUnder = {}; // 内置主类 id → 自定义子类行（「用」标记数据源）
	capItems.forEach(function (c) { if (catLabelOf[c.cat] && tax && tax.categories.some(function (x) { return x.id === c.cat; })) (customUnder[c.cat] = customUnder[c.cat] || []).push(c); });

	function loadCaps() {
		api("caps.list", { mode: selMode[0] }).then(function (r) { setCaps((r && r.caps) || []); }).catch(function () {});
	}
	useEffect(function () { loadCaps(); setForm(null); setDetail(null); setDelConfirm(""); }, [selMode[0]]);

	function openAdd(kind) {
		setDetail(null); setDelConfirm("");
		setForm({ kind: kind, id: "", cat: kind === "item" ? ((tax && tax.categories[0]) || {}).id || "" : "", label: "", desc: "", template: "", ref: "", pb: "", forms: "" });
	}
	function openEdit(cap) {
		setDetail(null); setDelConfirm("");
		setForm({ kind: cap.kind, id: cap.id, cat: cap.cat, label: cap.label, desc: cap.descr, template: cap.template, ref: cap.ref, pb: cap.pb, forms: cap.forms });
	}
	function saveForm() {
		if (!form[0].label.trim()) { say("请填写名称", true); return; }
		api("caps.save", Object.assign({ mode: selMode[0] }, form[0])).then(function (r) {
			if (r && r.ok) { loadCaps(); setForm(null); say("能力已保存：" + form[0].label.trim() + "（编排器模块库即时可用）"); }
			else say((r && r.error) || "保存失败", true);
		}).catch(function () { say("保存失败（通道不可达）", true); });
	}
	function removeCapUI(cap) {
		api("caps.remove", { id: cap.id }).then(function (r) {
			if (r && r.ok) { loadCaps(); setDelConfirm(""); say("已删除" + (r.cascaded ? "（级联删除 " + r.cascaded + " 个子类）" : "")); }
			else say((r && r.error) || "删除失败", true);
		}).catch(function () { say("删除失败", true); });
	}
	function exportUI() {
		api("caps.export", { mode: selMode[0] }).then(function (r) {
			var data = JSON.stringify({ format: "attack-atlas-caps", version: 1, capabilities: (r && r.capabilities) || [] }, null, 2);
			var blob = new Blob([data], { type: "application/json" });
			var a = document.createElement("a");
			a.href = URL.createObjectURL(blob);
			a.download = "attack-atlas-caps-" + selMode[0] + ".json";
			a.click();
			URL.revokeObjectURL(a.href);
			say("已导出本模式自定义能力");
		}).catch(function () { say("导出失败", true); });
	}
	function importFile(f) {
		if (!f) return;
		var reader = new FileReader();
		reader.onload = function () {
			var data;
			try { data = JSON.parse(reader.result); } catch { say("文件不是合法 JSON", true); return; }
			var rows = Array.isArray(data) ? data : data.capabilities;
			if (!Array.isArray(rows)) { say("文件里没有能力数据", true); return; }
			api("caps.import", { capabilities: rows }).then(function (r) {
				if (!r || !r.ok) { say((r && r.error) || "导入失败", true); return; }
				loadCaps();
				var sk = (r.skipped || []).map(function (s) { return s.name + "：" + s.reason; }).join("；");
				say("导入成功 " + r.imported.length + " 条" + (sk ? "；跳过 " + r.skipped.length + " 条（" + sk + "）" : ""));
			}).catch(function () { say("导入失败", true); });
		};
		reader.readAsText(f);
	}
	function switchSource(s) { setSource(s); setDelConfirm(""); setDetail(null); }
	function switchView(v) { setView(v); setDelConfirm(""); setDetail(null); }

	var f = form[0];
	var d = detail[0];
	var cards = [];
	if (source[0] === "custom" && view[0] === "category") {
		cards = capCats.map(function (c) {
			var n = capItems.filter(function (i) { return i.cat === c.cat; }).length;
			return { key: c.id, b: [c.label, capBadge("b-mine", "自")], meta: (c.descr ? c.descr + " · " : "") + n + " 个自定义子类 · " + c.updatedAt, cap: c };
		});
	} else if (source[0] === "custom" && view[0] === "item") {
		cards = capItems.map(function (c) {
			var underBuiltin = tax && tax.categories.some(function (x) { return x.id === c.cat; });
			return { key: c.id, b: [c.label, underBuiltin ? capBadge("b-user", "用") : capBadge("b-mine", "自")], meta: "所属主类：" + (catLabelOf[c.cat] || c.cat) + (c.descr ? " · " + c.descr : "") + " · " + c.updatedAt, cap: c };
		});
	} else if (source[0] === "builtin" && view[0] === "category" && tax) {
		cards = tax.categories.map(function (c) {
			var n = c.items.length + ((customUnder[c.id] || []).length ? "＋" + customUnder[c.id].length + "用" : "");
			return { key: c.id, b: [c.label, capBadge("b-builtin", "内置")], meta: (c.desc || "") + " · " + n + " 项", builtin: { kind: "category", cat: c } };
		});
	} else if (source[0] === "builtin" && view[0] === "item" && tax) {
		tax.categories.forEach(function (c) {
			c.items.forEach(function (i) {
				cards.push({ key: c.id + "/" + i.id, b: [i.label, capBadge("b-builtin", "内置")], meta: "所属主类：" + c.label + (i.ref ? " · 知识手册：" + i.ref : (i.pb ? " · 打法出处：playbook " + i.pb : "")), builtin: { kind: "item", cat: c, item: i } });
			});
		});
		capItems.forEach(function (ci) {
			if (!tax.categories.some(function (x) { return x.id === ci.cat; })) return; // 仅列挂在内置主类下的（「用」）
			cards.push({ key: "uc-" + ci.id, b: [ci.label, capBadge("b-user", "用")], meta: "所属主类：" + catLabelOf[ci.cat] + (ci.descr ? " · " + ci.descr : "") + " · 用户添加，可编辑/删除", cap: ci });
		});
	}

	return React.createElement("div", { className: "dsh-ata-modal", onClick: function (e) { if (e.target === e.currentTarget) props.onClose(); } },
		React.createElement("div", { className: "dsh-ata-mpanel" },
			React.createElement("div", { className: "dsh-ata-mhead" },
				React.createElement("span", { className: "dsh-ata-mtitle" }, "能力库 · 主类/子类体系"),
				React.createElement("span", { style: { flex: 1 } }),
				React.createElement("div", { className: "dsh-ata-captoggle" },
					React.createElement("span", { className: source[0] === "custom" ? "is-on" : "", onClick: function () { switchSource("custom"); } }, "自定义"),
					React.createElement("span", { className: source[0] === "builtin" ? "is-on" : "", onClick: function () { switchSource("builtin"); } }, "内置")),
				React.createElement("div", { className: "dsh-ata-captoggle" },
					React.createElement("span", { className: view[0] === "category" ? "is-on" : "", onClick: function () { switchView("category"); } }, "主类"),
					React.createElement("span", { className: view[0] === "item" ? "is-on" : "", onClick: function () { switchView("item"); } }, "子类")),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn is-run", onClick: function () { openAdd("item"); } }, "＋添加子类"),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { openAdd("category"); } }, "＋添加主类"),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { fileRef.current && fileRef.current.click(); } }, "导入"),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: exportUI }, "导出"),
				React.createElement("input", { ref: fileRef, type: "file", accept: ".json,application/json", style: { display: "none" }, onChange: function (e) { importFile(e.target.files && e.target.files[0]); e.target.value = ""; } }),
				React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: props.onClose }, "关闭")),
			React.createElement("div", { className: "dsh-ata-mbody" },
				React.createElement("div", { className: "dsh-ata-capmodes" },
					ATLAS_MODES.map(function (m) {
						return React.createElement("div", {
							key: m.id, className: "dsh-ata-capmode" + (selMode[0] === m.id ? " is-on" : ""),
							onClick: function () { setSelMode(m.id); }
						}, m.label);
					})),
				React.createElement("div", { className: "dsh-ata-capgrid" },
					source[0] === "custom" && caps[0].length === 0
						? React.createElement("div", { style: { color: "#9db9d8", fontSize: 12, lineHeight: 2.2, padding: "30px 10px", textAlign: "center" } },
							"本模式还没有自定义能力（初始为空）。", React.createElement("br", null),
							"点右上「＋添加子类」（优先）挂在内置主类下——标记「用」；", React.createElement("br", null),
							"或「＋添加主类」建自己的类目（标记「自」），子类即可挂进去。", React.createElement("br", null),
							"保存后自动出现在「自定义工作方法论」模块库，可编排进链路运行。")
						: null,
					cards.length === 0 && !(source[0] === "custom" && caps[0].length === 0)
						? React.createElement("div", { style: { color: "#7d97b8", fontSize: 12, padding: "20px 8px" } }, "没有匹配的内容")
						: null,
					cards.map(function (card) {
						return React.createElement("div", { key: card.key, className: "dsh-ata-capcard" },
							React.createElement("b", null, card.b[0], card.b[1] || null),
							React.createElement("div", { className: "meta" }, card.meta),
							React.createElement("div", { className: "dsh-ata-mtpl-acts", style: { marginTop: 6 } },
								React.createElement("button", {
									type: "button",
									onClick: function () {
										if (card.builtin) setDetail(card.builtin);
										else setDetail({ kind: "cap", cap: card.cap, catLabel: catLabelOf[card.cap.cat] });
									}
								}, "详情"),
								card.cap ? React.createElement("button", { type: "button", onClick: function () { openEdit(card.cap); } }, "编辑") : null,
								card.cap ? React.createElement("button", {
									type: "button", className: delConfirm[0] === card.cap.id ? "is-danger" : "",
									onClick: function () {
										if (delConfirm[0] === card.cap.id) removeCapUI(card.cap);
										else setDelConfirm(card.cap.id);
									}
								}, delConfirm[0] === card.cap.id
									? (card.cap.kind === "category" && capItems.filter(function (i) { return i.cat === card.cap.cat; }).length
										? "确认删除？（含 " + capItems.filter(function (i) { return i.cat === card.cap.cat; }).length + " 个子类）" : "确认删除？")
									: "删除") : null));
					})))),
		f ? React.createElement("div", { className: "dsh-ata-modal", onClick: function (e) { if (e.target === e.currentTarget) setForm(null); } },
			React.createElement("div", { className: "dsh-ata-mcard dsh-ata-capform" },
				React.createElement("h5", null, (f.id ? "编辑" : "添加") + (f.kind === "category" ? "主类" : "子类")),
				f.kind === "item" ? React.createElement("div", null,
					React.createElement("label", null, "所属主类（没建过自定义主类时只有内置可选）"),
					React.createElement("select", {
						value: f.cat, onChange: function (e) { setForm(Object.assign({}, f, { cat: e.target.value })); }
					},
						tax ? React.createElement("optgroup", { key: "b", label: "内置主类" }, tax.categories.map(function (c) {
							return React.createElement("option", { key: c.id, value: c.id }, c.label);
						})) : null,
						capCats.length ? React.createElement("optgroup", { key: "u", label: "自定义主类" }, capCats.map(function (c) {
							return React.createElement("option", { key: c.cat, value: c.cat }, c.label);
						})) : null)) : null,
				React.createElement("label", null, "名称（必填）"),
				React.createElement("input", { value: f.label, onChange: function (e) { setForm(Object.assign({}, f, { label: e.target.value })); }, placeholder: f.kind === "category" ? "如：业务专属面" : "如：积分系统双花" }),
				React.createElement("label", null, "一句话描述"),
				React.createElement("input", { value: f.desc, onChange: function (e) { setForm(Object.assign({}, f, { desc: e.target.value })); }, placeholder: "做什么/管什么面" }),
				React.createElement("label", null, f.kind === "category" ? "方法论要点模板（运行信封会带给模型）" : "打法/验证模板（运行信封会内联带给模型）"),
				React.createElement("textarea", { rows: 8, value: f.template, onChange: function (e) { setForm(Object.assign({}, f, { template: e.target.value })); }, placeholder: "可点下方「填入模板」按骨架写" }),
				React.createElement("div", { className: "dsh-ata-mtpl-acts", style: { marginTop: 6 } },
					React.createElement("button", { type: "button", onClick: function () { setForm(Object.assign({}, f, { template: CAP_TPL[f.kind] })); } }, "填入模板"),
					f.kind === "item" ? React.createElement("span", { style: { fontSize: 10, color: "#7d97b8", alignSelf: "center" } }, "可选字段：知识手册路径 / 打法出处 / 适用形态") : null),
				f.kind === "item" ? React.createElement("div", { style: { display: "flex", gap: 8 } },
					React.createElement("input", { style: { flex: 1 }, value: f.ref, onChange: function (e) { setForm(Object.assign({}, f, { ref: e.target.value })); }, placeholder: "知识手册 refs/ 路径（可选）" }),
					React.createElement("input", { style: { flex: 1 }, value: f.pb, onChange: function (e) { setForm(Object.assign({}, f, { pb: e.target.value })); }, placeholder: "打法出处 playbook 章节（可选）" }),
					React.createElement("input", { style: { width: 120 }, value: f.forms, onChange: function (e) { setForm(Object.assign({}, f, { forms: e.target.value })); }, placeholder: "适用形态（可选）" })) : null,
				React.createElement("div", { className: "dsh-ata-mrow" },
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn is-run", onClick: saveForm }, "保存"),
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { setForm(null); } }, "取消")))) : null,
		d ? React.createElement("div", { className: "dsh-ata-modal", onClick: function (e) { if (e.target === e.currentTarget) setDetail(null); } },
			React.createElement("div", { className: "dsh-ata-mcard" },
				React.createElement("h5", null, "详情", d.kind === "cap" ? capBadge("b-mine", "自定义") : capBadge("b-builtin", "内置")),
				d.kind === "cap" ? React.createElement("div", { style: { fontSize: 12, color: "#b9d2ee", lineHeight: 2 } },
					React.createElement("div", null, "名称：", React.createElement("b", { style: { color: "#e8f3ff" } }, d.cap.label), "（", d.cap.kind === "category" ? "主类" : "子类", "）"),
					d.cap.kind === "item" ? React.createElement("div", null, "所属主类：", d.catLabel || d.cap.cat) : null,
					d.cap.descr ? React.createElement("div", null, "描述：", d.cap.descr) : null,
					d.cap.ref ? React.createElement("div", null, "知识手册：", d.cap.ref) : null,
					d.cap.pb ? React.createElement("div", null, "打法出处：playbook ", d.cap.pb) : null,
					d.cap.forms ? React.createElement("div", null, "适用形态：", d.cap.forms) : null,
					React.createElement("div", { style: { whiteSpace: "pre-wrap", background: "rgba(10,30,60,.55)", borderRadius: 8, padding: "8px 10px", marginTop: 6, color: "#d8ecff" } }, d.cap.template || "（未附模板）"))
					: d.kind === "category" ? React.createElement("div", { style: { fontSize: 12, color: "#b9d2ee", lineHeight: 2 } },
						React.createElement("div", null, "主类：", React.createElement("b", { style: { color: "#e8f3ff" } }, d.cat.label), "（内置·只读）"),
						d.cat.desc ? React.createElement("div", null, "描述：", d.cat.desc) : null,
						React.createElement("div", { style: { marginTop: 4 } }, "子项（", d.cat.items.length + (customUnder[d.cat.id] || []).length, " 项）："),
						d.cat.items.map(function (i) { return React.createElement("div", { key: i.id, style: { paddingLeft: 12 } }, "· ", i.label, i.ref ? "（册）" : (i.pb ? "（法）" : "")); }),
						(customUnder[d.cat.id] || []).map(function (c) { return React.createElement("div", { key: c.id, style: { paddingLeft: 12, color: "#9fe8c5" } }, "· ", c.label, capBadge("b-user", "用")); }))
					: React.createElement("div", { style: { fontSize: 12, color: "#b9d2ee", lineHeight: 2 } },
						React.createElement("div", null, "子项：", React.createElement("b", { style: { color: "#e8f3ff" } }, d.item.label), "（内置·只读）"),
						React.createElement("div", null, "所属主类：", d.cat.label),
						d.item.ref ? React.createElement("div", null, "知识手册：refs/", d.item.ref) : null,
						d.item.pb ? React.createElement("div", null, "打法出处：playbook ", d.item.pb) : null,
						d.item.forms && d.item.forms.length ? React.createElement("div", null, "适用形态：", d.item.forms.join("/")) : null),
				React.createElement("div", { className: "dsh-ata-mrow" },
					React.createElement("button", { type: "button", className: "dsh-ata-mheadbtn", onClick: function () { setDetail(null); } }, "关闭")))) : null);
}

//#endregion

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
	}, [needReason[0]]); // 原因输入框展开后重算位置——防下缘溢出视口

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
