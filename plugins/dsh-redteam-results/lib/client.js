window.__ModuleLoader__.load({ id: "@dsh-external/dsh-redteam-results", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-redteam-results client — 会话标签页「redteam 成果」：七模式侧栏 + 渗透/代审成果页。
// 会话隔离：数据按 sessionId 读写；模式隔离由服务端 (session_id, mode) 双键强制。
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
	return csrfOf("/dsh-redteam-results").then(function (tok) {
		return fetch("/dsh-redteam-results/" + endpoint, {
			method: "POST",
			headers: tok ? { "content-type": "application/json", "x-dsh-csrf": tok } : { "content-type": "application/json" },
			body: JSON.stringify(payload || {})
		}).then(function (r) { return r.json(); });
	});
}

var MODES = [
	{ id: "redteam", label: "研究员模式" },
	{ id: "attack-defense", label: "攻防评估模式" },
	{ id: "pentest", label: "渗透测试模式" },
	{ id: "code-audit", label: "代码审计模式" },
	{ id: "av-evasion", label: "免杀对抗模式" },
	{ id: "incident-response", label: "应急溯源模式" },
	{ id: "binary-analysis", label: "二进制分析模式" },
	{ id: "cloud-security", label: "云安全攻防模式" },
	{ id: "ctf-solver", label: "CTF 解题模式" }
];
var SEVERITY_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危" };
var SEVERITY_ORDER = ["critical", "high", "medium", "low"];
var STATUS_LABEL = { pending: "待验证", "code-reviewed": "代码侧已复核", verified: "已验证", "false-positive": "误报", fixed: "已修复" };
var EVIDENCE_LABEL = { confirmed: "已证实", partial: "部分证据", unknown: "未知" };
var SOURCE_LABEL = { manual: "人工深审", "scan-confirmed": "扫描确认", "scan-false-positive": "扫描误报" };
var AUDIT_MODE_LABEL = { static: "静态审计", dynamic: "动态·验证成功" };
// 板式二分：findings=漏洞报告型（渗透/代审）；assets=产物/战果清单型（二进制/攻防/免杀）。
var MODE_META = {
	pentest: {
		archetype: "findings", label: "渗透测试", pocTitle: "测试过程 / 复现 EXP", groupLabel: "按目标分组",
		empty: "本会话暂无渗透测试成果。", allName: "pentest-findings-", reportName: "pentest-report-",
		tableTitle: "渗透测试成果清单", typeLabel: "类型分布", metaLabels: ["渗透范围", "版本/环境", "授权范围"]
	},
	"code-audit": {
		archetype: "findings", label: "代码审计", pocTitle: "复现条件 / 利用前提", groupLabel: "按文件/sink 分组",
		empty: "本会话暂无代码审计成果。", allName: "audit-findings-", reportName: "audit-report-",
		tableTitle: "代码审计成果清单", typeLabel: "RCE 主线分布", metaLabels: ["审计对象", "版本/commit", "审计范围"]
	},
	"binary-analysis": {
		archetype: "assets", label: "二进制分析", kindLabel: "产物类型", locLabel: "产物位置（路径）",
		descLabel: "内容 / 说明", chainLabel: "来源链路（怎么产出）", pocTitle: "使用 / 复现方法",
		groupLabel: "按样本分组", empty: "本会话暂无二进制分析产物。",
		allName: "binary-artifacts-", reportName: "binary-artifact-", tableTitle: "二进制分析产物清单",
		typeLabel: "产物类型分布", metaLabels: ["样本来源/任务", "环境与工具", "分析范围"],
		kinds: "脱壳还原二进制 / 反编译源码 / 提取配置 / 提取密钥(Key) / C2 配置 / 提取载荷 / 修复样本 / 脚本工具 / IOC 集 / YARA 规则"
	},
	"attack-defense": {
		archetype: "assets", label: "攻防评估", kindLabel: "战果类型", locLabel: "目标 / 位置",
		descLabel: "内容摘要（凭据 / 数据 / 权限）", chainLabel: "获取路径（怎么拿到的）", pocTitle: "利用 / 使用方法",
		groupLabel: "按阶段分组", empty: "本会话暂无攻防评估战果。",
		allName: "ad-loot-", reportName: "ad-loot-", tableTitle: "攻防评估战果清单",
		typeLabel: "战果类型分布", metaLabels: ["评估范围", "环境", "授权"],
		kinds: "入口点 / 数据读取成果 / 凭据·密码本 / 哈希集(hash map) / 横向立足点 / 域控成果 / Webshell 部署 / 持久化项 / 内网资产 / 检测gap"
	},
	redteam: {
		archetype: "ledger", label: "研究员模式", kindLabel: "任务形态", locLabel: "任务对象 / 范围",
		descLabel: "结论摘要", chainLabel: "处理路径（怎么做 / 路由到哪）", pocTitle: "下一步行动",
		groupLabel: "按形态分组", empty: "本会话任务台账为空——研究员模式的产物就是台账（任务×状态×结论×证据等级×下一步）。",
		allName: "redteam-ledger-", reportName: "redteam-task-", tableTitle: "研究员任务台账",
		typeLabel: "任务形态分布", metaLabels: ["任务范围", "环境", "授权"],
		kinds: "A 浅层直做 / B 专业路由 / C 多任务协同"
	},
	"av-evasion": {
		archetype: "assets", label: "免杀对抗", kindLabel: "交付物类型", locLabel: "产物路径",
		descLabel: "说明（构建 / 效果）", chainLabel: "构建 / 改造链路", pocTitle: "使用方法与效果",
		groupLabel: "按技术分组", empty: "本会话暂无免杀交付物。",
		allName: "av-deliverables-", reportName: "av-deliverable-", tableTitle: "免杀对抗交付物清单",
		typeLabel: "交付物类型分布", metaLabels: ["实验课题", "测试环境", "边界"],
		kinds: "Webshell（可用） / 免杀二进制 / 加载器 / C2 二开 / 变形脚本 / 测试效果记录 / 检测规则（配对）"
	},
	"incident-response": {
		archetype: "timeline", label: "应急溯源", kindLabel: "节点类型", locLabel: "主机 / 路径",
		descLabel: "节点描述", chainLabel: "取证过程（怎么证实）", pocTitle: "取证过程 / 检测命令",
		groupLabel: "按节点类型分组", empty: "本会话暂无攻击链节点——应急模式的产物是时间线（时间节点×可疑IP×事件×证据）。",
		allName: "ir-timeline-", reportName: "ir-node-", tableTitle: "攻击链时间线",
		typeLabel: "节点类型分布", metaLabels: ["调查对象", "环境", "范围"],
		kinds: "入口点 / 执行 / 持久化 / 横向 / 数据外传 / 影响 / 处置清理 / 其他"
	},
	"cloud-security": {
		archetype: "cloudpath", label: "云安全攻防", kindLabel: "路径类型", locLabel: "目标资源",
		descLabel: "影响证明（拿到什么）", chainLabel: "路径链（入口→身份→权限→资源）", pocTitle: "复现过程",
		groupLabel: "按路径类型分组", empty: "本会话暂无攻击路径——云安全模式的产物是攻击路径（入口凭证→身份→权限→资源→影响证明）。",
		allName: "cloud-paths-", reportName: "cloud-path-", tableTitle: "云攻击路径清单",
		typeLabel: "路径类型分布", metaLabels: ["目标", "环境", "范围"],
		kinds: "凭证泄露利用 / 元数据服务 / 对象存储 / 云数据库 / 权限提升 / 容器逃逸 / K8s 集群 / Serverless / CI-CD / 横向 / 持久化 / 其他"
	},
	"ctf-solver": {
		archetype: "ledger", label: "CTF 解题", kindLabel: "题目模块", locLabel: "题目 URL / 附件",
		descLabel: "解题结论（已解+分值 / 未解+卡点）", chainLabel: "解题路径（怎么解的）", pocTitle: "下一步行动",
		groupLabel: "按模块分组", empty: "本会话暂无赛题——CTF 模式的产物是解题台账（题×模块×状态×flag 验证证据×下一步）。",
		allName: "ctf-ledger-", reportName: "ctf-challenge-", tableTitle: "CTF 解题台账",
		typeLabel: "模块分布", metaLabels: ["赛名", "环境", "范围"],
		kinds: "web / pwn / reverse / crypto / misc / forensics / mobile / cloud / AI / AD / 供应链 / 其他"
	}
};
var ASSET_STATUS_LABEL = { pending: "待验证", verified: "有效·已验证", "false-positive": "已失效", fixed: "已交付" };
var AV_STATUS_LABEL = { pending: "在验", verified: "过检", detected: "被检出", "false-positive": "已失效", fixed: "已交付" };
var BIN_STATUS_LABEL = { pending: "分析中", suspect: "疑似", verified: "已定论", "false-positive": "已失效", fixed: "已归档" };
var STATUS_OPTIONS_OF = {
	"av-evasion": ["pending", "verified", "detected"],
	"ctf-solver": ["pending", "stuck", "verified"],
	"binary-analysis": ["pending", "suspect", "verified"]
};
var LEDGER_STATUS_LABEL = { pending: "进行中", verified: "已收口", "false-positive": "挂起", fixed: "已路由" };
var CTF_STATUS_LABEL = { pending: "未解", stuck: "卡点", verified: "已解·flag 验证", "false-positive": "放弃/排除", fixed: "已复盘" };
var TIMELINE_STATUS_LABEL = { pending: "待复核", "code-reviewed": "复核通过", verified: "已证实", "false-positive": "排除", fixed: "已处置" };
var CLOUDPATH_STATUS_LABEL = { pending: "待验证", verified: "已证实", "false-positive": "排除", fixed: "已修复" };
var BINARY_TYPE_VOCAB = "结论类型词表：恶意定性 / 家族识别 / 脱壳还原 / 算法破解 / Key恢复 / 加壳识别 / C2提取 / 后门确认 / 行为能力 / 诱饵排除 / 固件后门";

function fmtTime(iso) {
	if (!iso) return "";
	var d = new Date(iso);
	if (isNaN(d.getTime())) return String(iso).replace("T", " ").slice(0, 16);
	var p = function (n) { return (n < 10 ? "0" : "") + n; };
	return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}
function localDate() { var d = new Date(); var p = function (n) { return (n < 10 ? "0" : "") + n; }; return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()); }
function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function fmtTimelineAt(v) {
	var s = String(v == null ? "" : v).trim();
	if (!s || s === "unknown" || s === "Unknown") return "时间未知";
	return s.indexOf("T") >= 0 ? fmtTime(s) : s;
}
function timelineKey(v) {
	var s = String(v == null ? "" : v).trim();
	if (!s || s === "unknown" || s === "Unknown") return null;
	var n = Date.parse(s);
	return isNaN(n) ? s : n;
}
function cmpTimeline(a, b) {
	var av = timelineKey(a.timelineAt), bv = timelineKey(b.timelineAt);
	if (av === null && bv === null) return b.seq - a.seq;
	if (av === null) return 1;
	if (bv === null) return -1;
	if (typeof av === "number" && typeof bv === "number") return av - bv;
	if (typeof av === "number") return -1;
	if (typeof bv === "number") return 1;
	return av < bv ? -1 : av > bv ? 1 : b.seq - a.seq;
}
function statusLabelSetFor(archetype, mode) {
	if (mode === "ctf-solver") return CTF_STATUS_LABEL;
	if (mode === "av-evasion") return AV_STATUS_LABEL;
	if (mode === "binary-analysis") return BIN_STATUS_LABEL;
	return archetype === "assets" ? ASSET_STATUS_LABEL : archetype === "ledger" ? LEDGER_STATUS_LABEL : archetype === "timeline" ? TIMELINE_STATUS_LABEL : archetype === "cloudpath" ? CLOUDPATH_STATUS_LABEL : STATUS_LABEL;
}
function statusTextFor(f, mode, labelSet) {
	if (mode === "code-audit" && f.status === "pending" && f.auditMode !== "dynamic") return "待动态验证";
	return labelSet[f.status] || f.status;
}

function download(name, text, mime) {
	var blob = new Blob([text], { type: (mime || "text/markdown") + ";charset=utf-8" });
	var url = URL.createObjectURL(blob);
	var a = document.createElement("a");
	a.href = url; a.download = name;
	document.body.appendChild(a); a.click(); a.remove();
	setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}

//#region 导出生成器（MD 报告 / MD 总览 / MD 表格 / HTML 报告包）

function mdReport(f, mode) {
	var M = MODE_META[mode];
	if (M && M.archetype === "ledger") {
		return [
			"# 任务卡：" + f.title,
			"",
			"- 任务：" + f.title,
			"- " + M.kindLabel + "：" + (f.type || "未分类"),
			"- " + M.locLabel + "：" + (f.target || "（未填写）"),
			"- 状态：" + ((mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[f.status] || f.status) + (mode === "ctf-solver" ? " ｜ 难度：" + (f.type || "-") : " ｜ 优先级：" + (SEVERITY_LABEL[f.severity] || f.severity)) + " ｜ 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel),
			"- 登记时间：" + fmtTime(f.createdAt) + (f.verifiedAt ? " ｜ 收口时间：" + fmtTime(f.verifiedAt) : ""),
			"",
			"## " + M.descLabel,
			"",
			f.description || f.summary || "（未填写）",
			"",
			"## " + M.chainLabel,
			"",
			f.chain || "（未填写）",
			"",
			"## " + M.pocTitle,
			"",
			f.poc || "（未填写——收尾必给下一步）",
			f.evidence ? "\n## 任务书 / 材料路径\n\n" + f.evidence + "\n" : "",
			"",
			"## 复核记录",
			"",
			f.verifyNote || "（未复核）",
			""
		].join("\n");
	}
	if (M && M.archetype === "timeline") {
		return [
			"# 攻击链节点：" + f.title,
			"",
			"- 节点名：" + f.title,
			"- 攻击时间：" + (f.timelineAt || "unknown"),
			"- 节点类型：" + (f.type || "未分类"),
			"- 主机/路径：" + (f.target || "（未填写）"),
			"- 严重度：" + (SEVERITY_LABEL[f.severity] || f.severity),
			"- 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel) + " ｜ 状态：" + (TIMELINE_STATUS_LABEL[f.status] || f.status),
			"- 证据引用：" + (f.evidence || "（未填写）"),
			"",
			"## 取证过程 / 检测命令",
			"",
			f.poc || "（未填写）",
			"",
			"## 节点描述",
			"",
			f.description || "（未填写）",
			"",
			"## 结论",
			"",
			f.summary || f.description || "（未填写）",
			""
		].join("\n");
	}
	if (M && M.archetype === "cloudpath") {
		return [
			"# 云攻击路径：" + f.title,
			"",
			"- 路径名：" + f.title,
			"- 路径类型：" + (f.type || "未分类"),
			"- 目标资源：" + (f.target || f.resource || "（未填写）"),
			"- 严重度：" + (SEVERITY_LABEL[f.severity] || f.severity),
			"- 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel) + " ｜ 状态：" + (CLOUDPATH_STATUS_LABEL[f.status] || f.status),
			"",
			"## 攻击路径链（四要素）",
			"",
			"1. 入口凭证/身份：" + (f.entry || "（未填写）"),
			"2. 利用身份：" + (f.identity || "（未填写）"),
			"3. 权限：" + (f.permission || "（未填写）"),
			"4. 目标资源：" + (f.resource || f.target || "（未填写）"),
			"",
			"## 影响证明（拿到什么）",
			"",
			f.impact || f.description || "（未填写）",
			"",
			"## 复现过程",
			"",
			f.poc || "（未填写）",
			f.evidence ? "\n## 证据引用\n\n" + f.evidence + "\n" : "",
			"",
			"## 结论与复核",
			"",
			f.summary || f.description || "（未填写）",
			"- 复核注记：" + (f.verifyNote || "（未复核）"),
			""
		].join("\n");
	}
	if (M && M.archetype === "assets") {
		return [
			"# " + M.label + "资产卡片：" + f.title,
			"",
			"- 名称：" + f.title,
			"- " + M.kindLabel + "：" + (f.type || "未分类"),
			"- " + M.locLabel + "：" + (f.target || "（未填写）") + (f.sampleHash ? "（关联样本 " + f.sampleHash.slice(0, 12) + "…）" : ""),
			f.family ? "- 家族/变种：" + f.family : "",
			f.packer ? "- 壳/保护：" + f.packer : "",
			"- 状态：" + ((mode === "av-evasion" ? AV_STATUS_LABEL : mode === "binary-analysis" ? BIN_STATUS_LABEL : ASSET_STATUS_LABEL)[f.status] || f.status) + " ｜ 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel),
			"- 登记时间：" + fmtTime(f.createdAt) + (f.verifiedAt ? " ｜ 验证时间：" + fmtTime(f.verifiedAt) : ""),
			"",
			"## " + M.descLabel,
			"",
			f.description || f.summary || "（未填写）",
			"",
			"## " + M.chainLabel,
			"",
			f.chain || "（未填写）",
			"",
			"## " + M.pocTitle,
			"",
			f.poc || "（未填写）",
			f.iocs ? "\n## IOC / 环境结果清单\n\n" + f.iocs + "\n" : "",
			f.detectionRule ? "\n## 检测规则（YARA/Sigma）\n\n```yara\n" + f.detectionRule + "\n```\n" : "",
			"",
			"## 验证记录",
			"",
			"- 证据引用：" + (f.evidence || "（未填写）"),
			"- 复核注记：" + (f.verifyNote || "（未复核）"),
			""
		].filter(function (s) { return s !== ""; }).join("\n");
	}
	if (mode === "binary-analysis") {
		return [
			"# 二进制分析报告：" + f.title,
			"",
			"- 结论标题：" + f.title,
			"- 结论类型：" + (f.type || "未分类"),
			"- 样本：" + (f.target || "（未填写）") + (f.sampleHash ? "（SHA256: " + f.sampleHash + "）" : ""),
			"- 家族/变种：" + (f.family || "未知/未定"),
			"- 壳/保护：" + (f.packer || "未识别"),
			"- 判定/形态：" + (f.type || "未标注") + " ｜ 分析结论：" + (BIN_STATUS_LABEL[f.status] || f.status),
			"- 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel) + " ｜ 状态：" + (STATUS_LABEL[f.status] || f.status),
			"",
			"## 定性依据（结论摘要）",
			"",
			f.description || f.summary || "（未填写）",
			"",
			"## 执行链 / 还原链路",
			"",
			f.chain || "（未填写——如 loader → 解密 → OEP → dump、或 APK 壳 → dex 还原路径）",
			"",
			"## 能力与危害",
			"",
			f.impact || "（未填写——窃取/持久化/横向/破坏能力与影响范围）",
			"",
			"## IOC 清单",
			"",
			f.iocs || "（未提取）",
			"",
			"## 检测规则（YARA/Sigma）",
			"",
			f.detectionRule ? "```yara\n" + f.detectionRule + "\n```" : "（未产出）",
			"",
			"## 复现 / 验证步骤",
			"",
			f.poc || "（未填写——动态复现步骤或破解复现脚本）",
			"",
			"## 处置建议",
			"",
			f.fix || "（未填写）",
			"",
			"## 证据与复核",
			"",
			"- 证据引用：" + (f.evidence || "（未填写；含 provenance 登记）"),
			"- 复核注记：" + (f.verifyNote || "（未复核）") + (f.verifiedAt ? "（验证时间 " + fmtTime(f.verifiedAt) + "）" : ""),
			""
		].join("\n");
	}
	if (mode === "code-audit") {
		return [
			"# 代码审计问题报告：" + f.title,
			"",
			"- 问题名称：" + f.title,
			"- 问题描述（成因与影响）：" + (f.description || f.summary || "（未填写）"),
			"- 问题等级：" + (SEVERITY_LABEL[f.severity] || f.severity) + (f.cvss ? "（" + f.cvss + "）" : ""),
			"- 问题类型 / RCE 主线归类：" + (f.type || "未分类") + (f.cwe ? " / " + f.cwe : ""),
			"- 问题所在代码位置（sink 点）：" + (f.target || "（未填写）"),
			"- 审计形态：" + (AUDIT_MODE_LABEL[f.auditMode] || "未标注（默认静态语义）"),
			"- 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel) + " ｜ 状态：" + (STATUS_LABEL[f.status] || f.status) + " ｜ 来源：" + (SOURCE_LABEL[f.sourceOrigin] || f.sourceOrigin),
			"",
			"## 审计链路（entry → sink）",
			"",
			f.chain || "（未填写——组合/复杂漏洞应给出完整链路，每行一链）",
			"",
			"## 双链对照",
			"",
			"### 审计工人链",
			"",
			f.chain || "（未填写）",
			"",
			"### 追踪员链（独立重追）",
			"",
			f.chainTracer || "（未填写）",
			"",
			"### 一致性结论",
			"",
			f.chainVerdict || "（未对照）",
			"",
			"## 关键代码",
			"",
			f.snippetEntry ? "入口（entry）：" : "",
			f.snippetEntry || "",
			f.snippetEntry ? "\n" : "",
			f.snippetSink ? "危险点（sink）：" : "",
			f.snippetSink || "",
			"",
			"## 复现条件 / 利用前提",
			"",
			f.poc || "（未填写）",
			"",
			"## 修复建议",
			"",
			f.fix || "（未填写）",
			f.patch ? "\n### 修复 diff 建议\n\n```diff\n" + f.patch + "\n```\n" : "",
			"",
			"## 证据与复核",
			"",
			"- 双链比对记录：" + (f.evidence || "（未填写）"),
			"- 复核注记：" + (f.verifyNote || "（未复核）") + (f.verifiedAt ? "（验证时间 " + fmtTime(f.verifiedAt) + "）" : ""),
			""
		].join("\n");
	}
	return [
		"# 渗透测试漏洞报告：" + f.title,
		"",
		"- 漏洞/问题 名称：" + f.title,
		"- 漏洞/问题 描述：" + (f.description || f.summary || "（未填写）"),
		"- 漏洞/问题 等级：" + (SEVERITY_LABEL[f.severity] || f.severity) + (f.type ? "（" + f.type + "）" : "") + (f.cvss ? " ｜ " + f.cvss : ""),
		"- 漏洞/问题 地址：" + (f.target || "（未填写）"),
		"- 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel) + " ｜ 状态：" + (STATUS_LABEL[f.status] || f.status),
		"",
		"## 影响证明",
		"",
		f.impact || "（未填写——发现+验证=真实有效：拿到什么数据/执行到什么程度）",
		"",
		"## 对照三件套",
		"",
		"- 基线（正常请求）：" + (f.baseline || "（未填写）"),
		"- 差分（注入后翻转）：" + (f.diffEvidence || "（未填写）"),
		"- marker 逐字回显：" + (f.markerEcho || "（未填写）"),
		"",
		"## 测试过程",
		"",
		f.poc || f.description || "（未填写）",
		"",
		f.requestPkt ? "### 完整请求包\n\n```\n" + f.requestPkt + "\n```\n" : "",
		f.responsePkt ? "### 关键响应\n\n```\n" + f.responsePkt + "\n```\n" : "",
		"## 修复建议",
		"",
		f.fix || "（未填写）",
		f.retestNote ? "\n## 复测记录\n\n" + f.retestNote + (f.retestAt ? "（" + fmtTime(f.retestAt) + "）" : "") + "\n" : "",
		""
	].join("\n");
}

function mdOverview(meta, stats, rows, mode) {
	if (MODE_META[mode] && MODE_META[mode].archetype === "timeline") {
		var chrono = rows.slice().sort(cmpTimeline);
		var typeLines = (stats.byType || []).map(function (t) { return "- " + t.type + " × " + t.count; });
		var hostLines = (stats.byTarget || []).map(function (t) { return "- " + t.target + " × " + t.count; });
		var sevLine = SEVERITY_ORDER.map(function (s) { return SEVERITY_LABEL[s] + " " + (stats.bySeverity[s] || 0); }).join(" / ");
		var lines = [
			"# 攻击链还原总览（应急溯源）",
			"",
			"- 调查对象：" + (meta.targetLabel || "（未填写）"),
			"- 环境：" + (meta.version || "（未填写）") + " ｜ 范围：" + (meta.scope || "（未填写）"),
			"- 节点总数：" + stats.total,
			"- 严重度统计：" + sevLine,
			"",
			"## 节点类型分布",
			""
		].concat(typeLines.length ? typeLines : ["（无）"]);
		lines.push("", "## 主机分布", "");
		lines = lines.concat(hostLines.length ? hostLines : ["（无）"]);
		lines.push("", "## 攻击时间线（按时间排序）", "");
		if (chrono.length === 0) lines.push("（无）");
		lines = lines.concat(chrono.map(function (f, i) {
			return (i + 1) + ". [" + (f.timelineAt || "unknown") + "] " + (f.type || "未分类") + " · " + f.title + "（" + (f.target || "无主机") + "，严重度 " + (SEVERITY_LABEL[f.severity] || f.severity) + "）";
		}));
		lines.push("", "## 处置建议", "", "按时间线逐节点复核取证过程与证据引用，还原入口点→执行→持久化→横向→数据外传的完整攻击链；未证实（待复核）节点优先补证据，已排除/已处置节点标注收口。", "");
		return lines.join("\n");
	}
	if (MODE_META[mode] && MODE_META[mode].archetype === "cloudpath") {
		var sorted2 = rows.slice().sort(function (a, b) { return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity); });
		var typeLines2 = (stats.byType || []).map(function (t) { return "- " + t.type + " × " + t.count; });
		var resLines = (stats.byTarget || []).map(function (t) { return "- " + t.target + " × " + t.count; });
		var sevLine2 = SEVERITY_ORDER.map(function (s) { return SEVERITY_LABEL[s] + " " + (stats.bySeverity[s] || 0); }).join(" / ");
		var lines2 = [
			"# 云攻击路径总览（云安全攻防）",
			"",
			"- 目标：" + (meta.targetLabel || "（未填写）"),
			"- 环境：" + (meta.version || "（未填写）") + " ｜ 范围：" + (meta.scope || "（未填写）"),
			"- 路径总数：" + stats.total,
			"- 严重度统计：" + sevLine2,
			"",
			"## 路径类型分布",
			""
		].concat(typeLines2.length ? typeLines2 : ["（无）"]);
		lines2.push("", "## 目标资源分布", "");
		lines2 = lines2.concat(resLines.length ? resLines : ["（无）"]);
		lines2.push("", "## 攻击路径清单（按严重度排序）", "");
		if (sorted2.length === 0) lines2.push("（无）");
		lines2 = lines2.concat(sorted2.map(function (f, i) {
			return (i + 1) + ". [" + (SEVERITY_LABEL[f.severity] || f.severity) + "] " + f.title + "（" + (f.type || "未分类") + "，资源 " + (f.resource || f.target || "无") + "）" + (f.summary ? " — " + f.summary : "");
		}));
		lines2.push("", "## 收口建议", "", "逐路径复核四要素证据（入口/身份/权限/资源）与影响证明，未验证路径优先补证据；已排除/已修复路径标注收口。", "");
		return lines2.join("\n");
	}
	var label = MODE_META[mode] ? MODE_META[mode].label : mode;
	var sorted = rows.slice().sort(function (a, b) { return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity); });
	var top3 = sorted.slice(0, 3);
	var lines = [
		"# " + label + "总览报告",
		"",
		"- 对象/范围：" + (meta.targetLabel || "（未填写）"),
		"- 版本：" + (meta.version || "（未填写）") + " ｜ scope：" + (meta.scope || "（未填写）"),
		LABEL_BY_TYPE_MODES[mode] ? "- 成果总数：" + stats.total : "- 成果总数：" + stats.total + "（严重 " + (stats.bySeverity.critical || 0) + " / 高危 " + (stats.bySeverity.high || 0) + " / 中危 " + (stats.bySeverity.medium || 0) + " / 低危 " + (stats.bySeverity.low || 0) + "）",
		"- 状态分布：" + Object.keys(LABEL_BY_TYPE_MODES[mode] ? (mode === "av-evasion" ? AV_STATUS_LABEL : mode === "binary-analysis" ? BIN_STATUS_LABEL : CTF_STATUS_LABEL) : STATUS_LABEL).map(function (s) { var set = LABEL_BY_TYPE_MODES[mode] ? (mode === "av-evasion" ? AV_STATUS_LABEL : mode === "binary-analysis" ? BIN_STATUS_LABEL : CTF_STATUS_LABEL) : STATUS_LABEL; return (set[s] || s) + " " + (stats.byStatus[s] || 0); }).join(" / "),
		"",
		"## 总体结论",
		"",
		stats.total === 0 ? "本会话未登记成果。" : "共 " + stats.total + " 项成果，其中待验证 " + (stats.byStatus.pending || 0) + " 项（结论以验证状态为准，未验证项按疑似处理）。",
		"",
		"## Top-3 风险",
		""
	];
	if (top3.length === 0) lines.push("（无）");
	top3.forEach(function (f) { lines.push("- [" + (LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : (SEVERITY_LABEL[f.severity] || f.severity)) + "] " + f.title + "（" + (f.target || "无地址") + "）" + (f.summary ? "—" + f.summary : "")); });
	lines.push("");
	lines.push("## 修复路线图（优先级从高到低）");
	lines.push("");
	if (rows.length === 0) lines.push("（无）");
	sorted.forEach(function (f, i) {
		lines.push((i + 1) + ". [" + (LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : (SEVERITY_LABEL[f.severity] || f.severity)) + "] " + f.title + (f.fix ? "——" + f.fix.slice(0, 80) : ""));
	});
	lines.push("");
	return lines.join("\n");
}

function mdTable(rows, title, mode) {
	var audit = mode === "code-audit";
	var M = MODE_META[mode];
	var isAsset = M && M.archetype === "assets";
	var isLedger = M && M.archetype === "ledger";
	var isTimeline = M && M.archetype === "timeline";
	var isCloudpath = M && M.archetype === "cloudpath";
	var head = isCloudpath
		? "| # | 路径 | 类型 | 入口 | 身份 | 权限 | 资源 | 严重度 | 影响证明 |"
		: isTimeline
		? "| # | 攻击时间 | 节点 | 类型 | 主机 | 严重度 | 证据 | 结论 |"
		: isLedger
		? "| # | 任务 | 形态 | 对象/范围 | 状态 | 优先级 | 证据等级 | 结论摘要 | 下一步 |"
		: isAsset
		? "| 序号 | 名称 | " + M.kindLabel + " | " + M.locLabel + " | 状态 | 说明 |"
		: audit
		? "| 序号 | 名称 | 等级 | 主线类型 | CWE | sink 位置 | 状态 | 来源 | 简介 |"
		: "| 序号 | 名称 | 等级 | 类型 | CVSS | 地址 | 状态 | 简介 |";
	var sep = isCloudpath ? "|---|---|---|---|---|---|---|---|---|" : isTimeline ? "|---|---|---|---|---|---|---|---|" : isLedger ? "|---|---|---|---|---|---|---|---|---|" : (audit || (isAsset && MODE_META[mode] && MODE_META[mode].kinds && false)) ? "|---|---|---|---|---|---|---|---|---|" : isAsset ? "|---|---|---|---|---|---|" : "|---|---|---|---|---|---|---|---|";
	var body = rows.map(function (f) {
		var cells = isCloudpath
			? [f.seq, f.title, f.type || "-", (f.entry || "-").replace(/\|/g, "/").slice(0, 30), (f.identity || "-").replace(/\|/g, "/").slice(0, 30), (f.permission || "-").replace(/\|/g, "/").slice(0, 30), (f.resource || f.target || "-").replace(/\|/g, "/").slice(0, 40), SEVERITY_LABEL[f.severity] || f.severity, (f.impact || f.summary || "-").replace(/\|/g, "/").slice(0, 50)]
			: isTimeline
			? [f.seq, f.timelineAt || "unknown", f.title, f.type || "-", f.target || "-", SEVERITY_LABEL[f.severity] || f.severity, (f.evidence || "-").replace(/\|/g, "/").slice(0, 40), (f.summary || "-").replace(/\|/g, "/").slice(0, 50)]
			: isLedger
			? [f.seq, f.title, f.type || "-", f.target || "-", (mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[f.status] || f.status, mode === "ctf-solver" ? (f.type || "-") : (SEVERITY_LABEL[f.severity] || f.severity), EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel, (f.summary || "-").replace(/\|/g, "/").slice(0, 50), (f.poc || "-").replace(/\|/g, "/").slice(0, 50)]
			: isAsset
			? [f.seq, f.title, f.type || "-", (f.target || "-") + (f.sampleHash ? " (" + f.sampleHash.slice(0, 8) + ")" : ""), ASSET_STATUS_LABEL[f.status] || f.status, (f.summary || f.description || "-").replace(/\|/g, "/").slice(0, 60)]
			: audit
			? [f.seq, f.title, SEVERITY_LABEL[f.severity] || f.severity, f.type || "-", f.cwe || "-", f.target || "-", STATUS_LABEL[f.status] || f.status, SOURCE_LABEL[f.sourceOrigin] || f.sourceOrigin, (f.summary || "-").replace(/\|/g, "/")]
			: [f.seq, f.title, SEVERITY_LABEL[f.severity] || f.severity, f.type || "-", f.cvss || "-", f.target || "-", STATUS_LABEL[f.status] || f.status, (f.summary || "-").replace(/\|/g, "/")];
		return "| " + cells.join(" | ") + " |";
	});
	return ["# " + (title || "成果清单"), "", head, sep].concat(body).concat([""]).join("\n");
}

/** 极简 MD→HTML：标题/列表/代码块（导出内联渲染足够）。 */
function toSimpleHtml(md) {
	var out = [];
	var inCode = false, inList = false;
	md.split("\n").forEach(function (line) {
		if (line.trim().slice(0, 3) === "```") {
			if (inList) { out.push("</ul>"); inList = false; }
			out.push(inCode ? "</pre>" : "<pre>");
			inCode = !inCode;
			return;
		}
		if (inCode) { out.push(esc(line)); return; }
		if (line.slice(0, 3) === "###") { if (inList) { out.push("</ul>"); inList = false; } out.push("<h3>" + esc(line.replace(/^#+\s*/, "")) + "</h3>"); return; }
		if (line.slice(0, 2) === "##") { if (inList) { out.push("</ul>"); inList = false; } out.push("<h2>" + esc(line.replace(/^#+\s*/, "")) + "</h2>"); return; }
		if (line.slice(0, 1) === "#") { if (inList) { out.push("</ul>"); inList = false; } out.push("<h2>" + esc(line.replace(/^#+\s*/, "")) + "</h2>"); return; }
		if (line.slice(0, 2) === "- ") { if (!inList) { out.push("<ul>"); inList = true; } out.push("<li>" + esc(line.slice(2)) + "</li>"); return; }
		if (/^\d+\.\s/.test(line)) { if (!inList) { out.push("<ul>"); inList = true; } out.push("<li>" + esc(line.replace(/^\d+\.\s*/, "")) + "</li>"); return; }
		if (line.trim() === "") { if (inList) { out.push("</ul>"); inList = false; } return; }
		if (inList) { out.push("</ul>"); inList = false; }
		out.push("<p>" + esc(line) + "</p>");
	});
	if (inList) out.push("</ul>");
	if (inCode) out.push("</pre>");
	return out.join("\n");
}

function htmlReport(meta, stats, rows, mode) {
	var label = MODE_META[mode] ? MODE_META[mode].label : mode;
	var sevColor = { critical: "#e5484d", high: "#e87d2e", medium: "#b58a00", low: "#3b7dd8" };
	var h = ['<!doctype html><html><head><meta charset="utf-8"><title>' + esc(label) + '报告</title><style>'];
	h.push('body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;background:#f6f7f9;color:#1a1a1a;line-height:1.65}');
	h.push('.page{max-width:880px;margin:0 auto;padding:40px 44px;background:#fff;min-height:100vh}');
	h.push('h1{font-size:24px;border-bottom:2px solid #1a1a1a;padding-bottom:10px}h2{font-size:17px;margin-top:34px;border-left:4px solid #4c6ef5;padding-left:10px}h3{font-size:14px;margin:18px 0 6px;color:#555}');
	h.push('.meta{color:#666;font-size:13px;margin:6px 0 2px}.card{border:1px solid #e5e5ea;border-radius:10px;padding:18px 20px;margin:18px 0;background:#fff}');
	h.push('.sev{display:inline-block;font-size:12px;font-weight:600;padding:2px 10px;border-radius:10px;color:#fff;margin-right:8px}');
	h.push('pre{background:#f4f4f6;border:1px solid #e9e9ec;border-radius:8px;padding:12px;white-space:pre-wrap;word-break:break-word;font-size:12.5px;overflow-x:auto}');
	h.push('table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #e5e5ea;padding:6px 10px;text-align:left}th{background:#f6f7f9}');
	h.push('</style></head><body><div class="page">');
	h.push('<h1>' + esc(label) + '报告</h1>');
	h.push('<p class="meta">' + esc(MODE_META[mode] ? MODE_META[mode].metaLabels[0] : "对象") + '：' + esc(meta.targetLabel || "—") + ' ｜ ' + esc(MODE_META[mode] ? MODE_META[mode].metaLabels[1] : "版本") + '：' + esc(meta.version || "—") + ' ｜ scope：' + esc(meta.scope || "—") + '</p>');
	h.push('<p class="meta">总数 ' + stats.total + '（严重 ' + (stats.bySeverity.critical || 0) + ' / 高危 ' + (stats.bySeverity.high || 0) + ' / 中危 ' + (stats.bySeverity.medium || 0) + ' / 低危 ' + (stats.bySeverity.low || 0) + '）｜ 生成时间 ' + new Date().toLocaleString() + '</p>');
	h.push('<h2>成果清单</h2><table><tr>' + (mode === "code-audit" ? "<th>#</th><th>名称</th><th>等级</th><th>主线</th><th>CWE</th><th>sink</th><th>状态</th>" : "<th>#</th><th>名称</th><th>等级</th><th>类型</th><th>地址</th><th>状态</th>") + '</tr>');
	rows.forEach(function (f) {
		h.push('<tr><td>' + f.seq + '</td><td>' + esc(f.title) + '</td><td><span class="sev" style="background:' + (sevColor[f.severity] || "#888") + '">' + esc(SEVERITY_LABEL[f.severity] || f.severity) + '</span></td><td>' + esc(f.type || "-") + '</td>' + (mode === "code-audit" ? '<td>' + esc(f.cwe || "-") + '</td>' : '') + '<td>' + esc(f.target || "-") + '</td><td>' + esc(STATUS_LABEL[f.status] || f.status) + '</td></tr>');
	});
	h.push('</table>');
	rows.forEach(function (f) {
		h.push('<div class="card"><h2>#' + f.seq + ' ' + esc(f.title) + ' <span class="sev" style="background:' + (sevColor[f.severity] || "#888") + '">' + esc(SEVERITY_LABEL[f.severity] || f.severity) + '</span></h2>');
		h.push('<div class="md">' + toSimpleHtml(mdReport(f, mode)) + '</div></div>');
	});
	h.push('</div></body></html>');
	return h.join("\n");
}

//#endregion

//#region 样式


"".length; // noop
var CSS_SCREEN = [
	".dsh-rtr-screen{position:relative;height:100%;overflow:auto;width:100%;min-width:0;box-sizing:border-box;background:radial-gradient(900px 480px at 50% -10%,rgba(58,157,255,.10),transparent 60%),#050f1f;color:#e6f2ff;font-size:13px}",
	".dsh-rtr-screen::before{content:\"\";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(rgba(58,157,255,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(58,157,255,.08) 1px,transparent 1px);background-size:40px 40px}",
	".dsh-rtr-screen::after{content:\"\"}",
	".dsh-scr-inner{position:relative;z-index:2;display:flex;flex-direction:column;gap:14px;container-type:inline-size;container-name:scrinner;padding:clamp(10px,1.6vw,20px) clamp(12px,1.8vw,24px) 26px;min-height:100%;box-sizing:border-box;max-width:1680px;margin:0 auto;width:100%}",
	".dsh-rtr-screen:fullscreen{width:100%;height:100%}",
	".dsh-rtr-screen:fullscreen .dsh-scr-inner{max-width:none;height:100%;min-height:0;gap:18px;padding:clamp(14px,2vh,26px) clamp(18px,2.4vw,36px) clamp(16px,2.6vh,30px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-header{padding:clamp(12px,1.8vh,20px) 26px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-title{font-size:clamp(22px,2vw,30px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-clock{font-size:clamp(20px,1.6vw,26px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-hero{padding:clamp(8px,1.6vh,18px) 6px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-num{padding:clamp(14px,2vh,22px) 14px 12px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-num b{font-size:clamp(36px,3.2vw,52px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-num span{font-size:clamp(11px,1vw,14px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-globewrap{transform:scale(1.24)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-grid{flex:1;min-height:0;grid-template-columns:minmax(260px,1.05fr) minmax(380px,2.3fr) minmax(280px,1.05fr)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-grid>div{min-height:0;overflow-y:auto}",
	".dsh-rtr-screen:fullscreen .dsh-scr-grid>div>.dsh-scr-panel{min-height:0;overflow:auto}",
	".dsh-rtr-screen:fullscreen .dsh-scr-grid>div>.dsh-scr-panel:last-child{flex:1 1 auto}",
	".dsh-rtr-screen:fullscreen .dsh-scr-panel{padding:clamp(14px,1.8vh,20px) clamp(16px,1.4vw,22px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-panel h4{font-size:clamp(13px,1.05vw,16px);margin-bottom:clamp(8px,1vh,12px);padding-bottom:8px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-bar{font-size:clamp(12px,1vw,14px);margin:clamp(3px,.6vh,7px) 0}",
	".dsh-rtr-screen:fullscreen .dsh-scr-bar .lbl{width:84px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-bar .track{height:12px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-bar .val{width:40px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-b3d{font-size:clamp(10px,1.05vw,14px);height:clamp(170px,26vh,260px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-legend{font-size:clamp(11px,.95vw,13px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-table{font-size:clamp(12px,1vw,14px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-table th{padding:clamp(6px,1vh,10px) 10px;font-size:clamp(11px,.9vw,13px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-table td{padding:clamp(6px,1vh,11px) 10px}",
	".dsh-rtr-screen:fullscreen .dsh-scr-sev{font-size:clamp(11px,.9vw,13px)}",
	".dsh-rtr-screen:fullscreen .dsh-scr-empty{display:flex;align-items:center;justify-content:center;flex:1}",
	".dsh-scr-hleft{display:flex;align-items:center;gap:14px;min-width:0}",
	".dsh-scr-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px 16px;min-width:0;padding:12px 24px;border:1px solid rgba(58,157,255,.45);border-radius:10px;background:rgba(10,30,60,.45);backdrop-filter:blur(10px);box-shadow:0 0 20px rgba(58,157,255,.15)}",
	".dsh-scr-title{font-size:22px;font-weight:700;letter-spacing:3px;background:linear-gradient(90deg,#7cc8ff,#ffffff,#7cc8ff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:#7cc8ff}",
	".dsh-scr-title small{display:block;font-size:12px;letter-spacing:4px;color:#8fb4d9;font-weight:600;margin-top:2px;-webkit-text-fill-color:#8fb4d9}",
	".dsh-scr-live{display:flex;align-items:center;gap:8px;font-size:14px;color:#36f1b0;letter-spacing:1px}",
	".dsh-scr-dot{width:10px;height:10px;border-radius:50%;background:#36f1b0;box-shadow:0 0 8px #36f1b0;animation:dshPulse 2s ease-in-out infinite}",
	"@keyframes dshPulse{0%,100%{opacity:1}50%{opacity:.5}}",
	".dsh-scr-clock{font-family:monospace;font-size:22px;color:#3a9dff;letter-spacing:.08em}",
	".dsh-scr-grid{display:grid;grid-template-columns:minmax(180px,240px) minmax(260px,1fr) minmax(200px,250px);gap:14px;align-items:stretch;flex:1}",
	".dsh-scr-grid>div>.dsh-scr-panel:last-child{flex:1}",
	".dsh-scr-center,.dsh-scr-grid>div{min-width:0}",
	".dsh-scr-nums{grid-template-columns:repeat(auto-fit,minmax(110px,1fr))}",
	".dsh-scr-tablewrap{overflow:auto}",
	".dsh-scr-table{table-layout:fixed;width:100%}",
	".dsh-scr-table td,.dsh-scr-table th{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
	"@container scrinner (max-width:700px){.dsh-scr-grid{grid-template-columns:1fr}}",
	"@container scrinner (max-width:620px){.dsh-scr-nums{grid-template-columns:repeat(2,minmax(84px,1fr))}.dsh-scr-title{font-size:15px}.dsh-scr-clock{font-size:15px}}",
	"@container scrinner (max-width:460px){.dsh-scr-nums{grid-template-columns:repeat(auto-fit,minmax(72px,1fr))}.dsh-scr-bar .lbl{width:56px;font-size:11px}.dsh-scr-num b{font-size:24px}}",
	"@media (max-width:980px){.dsh-scr-grid{grid-template-columns:1fr}}",
	"@media (max-width:640px){.dsh-scr-nums{grid-template-columns:repeat(2,1fr)}.dsh-scr-title{font-size:15px}}",
	".dsh-scr-panel{position:relative;min-width:0;overflow:hidden;border:1px solid rgba(58,157,255,.45);border-radius:10px;background:rgba(10,30,60,.45);padding:16px 20px;backdrop-filter:blur(10px);box-shadow:0 0 15px rgba(58,157,255,.1)}",
	".dsh-scr-panel::before{content:\"\"}",
	".dsh-scr-panel::after{content:\"\"}",
	".dsh-scr-panel:hover{border-color:rgba(100,190,255,.65)}",
	".dsh-scr-num{transition:transform .3s,box-shadow .3s}",
	".dsh-scr-num:hover{transform:translateY(-2px);box-shadow:0 0 25px rgba(58,157,255,.25)}",
	".dsh-scr-num b{animation:none}",
	".dsh-scr-table tbody tr{transition:background .2s}",
	".dsh-scr-table tbody tr:hover td{background:rgba(56,190,255,.09)}",
	".dsh-scr-bar .track span{transition:width .6s ease}",
	".dsh-scr-hero{position:relative}",
	".dsh-scr-hero::after{content:\"\";position:absolute;left:6%;right:6%;bottom:-4px;height:1px;background:linear-gradient(90deg,transparent,rgba(70,190,255,.55),transparent)}",
	".dsh-scr-globewrap::before{content:\"\";position:absolute;left:-8%;right:-8%;top:33%;height:34%;border:1px solid rgba(150,225,255,.26);border-radius:50%}",
	".dsh-scr-donut{box-shadow:0 0 18px rgba(58,157,255,.2)}",
	"@keyframes dshShimmer{from{background-position:200% 0}to{background-position:-200% 0}}",
	"@keyframes dshNumGlow{0%,100%{text-shadow:0 0 12px rgba(64,196,255,.35)}50%{text-shadow:0 0 28px rgba(64,196,255,.8)}}",
	".dsh-scr-clockwrap{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}",
	".dsh-scr-range,.dsh-scr-date{background:rgba(58,157,255,.15);color:#fff;border:1px solid rgba(58,157,255,.45);border-radius:6px;padding:6px 12px;font-size:12px;outline:none;color-scheme:dark;backdrop-filter:blur(8px);transition:border-color .2s,box-shadow .2s}",
	".dsh-scr-range:hover,.dsh-scr-date:hover{border-color:rgba(120,200,255,.75)}",
	".dsh-scr-range:focus,.dsh-scr-date:focus{border-color:rgba(140,220,255,.9);box-shadow:0 0 0 3px rgba(58,157,255,.18)}",
	".dsh-rtr-screen .dsh-rtr-btn{background:rgba(58,157,255,.15);color:#e6f2ff;border-color:rgba(58,157,255,.45);backdrop-filter:blur(8px);transition:background .2s,border-color .2s,color .2s}",
	".dsh-rtr-screen .dsh-rtr-btn:hover{background:rgba(58,157,255,.3);border-color:rgba(120,200,255,.75);color:#fff}",
	".dsh-rtr-screen .dsh-rtr-btn:active{background:rgba(58,157,255,.4);color:#fff}",
	".dsh-rtr-screen .dsh-rtr-btn:disabled{opacity:.45}",
	".dsh-scr-hero{display:flex;align-items:center;justify-content:center;gap:clamp(110px,13cqw,300px);padding:10px 6px 2px;flex-wrap:wrap}",
	".dsh-scr-heronums{display:grid;grid-template-columns:repeat(2,minmax(108px,1fr));gap:12px;min-width:0}",
	".dsh-scr-globewrap{position:relative;width:200px;height:200px;display:flex;align-items:center;justify-content:center;flex:none;perspective:900px;transform-style:preserve-3d}",
	".dsh-scr-globe{position:relative;width:130px;height:130px;border-radius:50%;flex:none;background:url(\"data:image/jpeg;base64,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\") 0 0/auto 100% repeat-x;box-shadow:0 0 20px rgba(255,255,255,.2),-3px 0 4px #c3f4ff inset,8px 1px 13px #000 inset,-12px -1px 18px rgba(195,244,255,.6) inset,130px 0 23px rgba(0,0,0,.4) inset,78px 0 20px rgba(0,0,0,.67) inset;animation:dshEarthTex 30s linear infinite,dshGlobeFloat 7s ease-in-out infinite}",
	".dsh-scr-grat{display:none}",
	".dsh-scr-sweep{display:none}",
	".dsh-scr-star{position:absolute;width:4px;height:4px;border-radius:50%;background:#fff;box-shadow:0 0 6px #fff,0 0 12px rgba(255,255,255,.5);animation:dshTwinkle 3s ease-in-out infinite;pointer-events:none}",
	".dsh-scr-orbitstage{position:absolute;inset:0;transform-style:preserve-3d;transform:rotateX(-16deg)}",
	".dsh-scr-orbittrack{position:absolute;left:50%;top:50%;width:calc(var(--r,150px)*2);height:calc(var(--r,150px)*2);margin:calc(var(--r,150px)*-1) 0 0 calc(var(--r,150px)*-1);border-radius:50%;border:1px solid rgba(255,255,255,.28);box-shadow:0 0 7px rgba(255,255,255,.14);transform:rotateX(90deg)}",
	".dsh-scr-orbiter{position:absolute;left:50%;top:50%;transform-style:preserve-3d;animation:dshOrbit3d 16s linear infinite}",
	".dsh-scr-planet{position:absolute;border-radius:50%;border:1px solid currentColor;background:radial-gradient(circle,transparent 58%,currentColor 100%);box-shadow:0 0 9px currentColor;transform-style:preserve-3d;animation:dshPlanetSpin 10s linear infinite}",
	".dsh-scr-planet::before{content:\"\";position:absolute;inset:-1px;border-radius:50%;border:1px solid currentColor;transform:rotateY(90deg)}",
	".dsh-scr-planet::after{content:\"\";position:absolute;inset:-1px;border-radius:50%;border:1px solid currentColor;transform:rotateX(90deg)}",
	"@keyframes dshOrbit3d{from{transform:rotateY(0deg) translateZ(var(--r,150px))}to{transform:rotateY(360deg) translateZ(var(--r,150px))}}",
	"@keyframes dshPlanetSpin{from{transform:rotateY(0deg) rotateX(0deg)}to{transform:rotateY(360deg) rotateX(360deg)}}",
	"@keyframes dshEarthTex{from{background-position:0 0}to{background-position:-207.7px 0}}",
	"@keyframes dshTwinkle{0%,100%{opacity:.1}50%{opacity:1}}",
	".dsh-scr-herotag{position:absolute;bottom:-4px;left:50%;transform:translateX(-50%);font-size:11px;letter-spacing:.2em;color:#8fb4d9;white-space:nowrap}",
	"@keyframes dshGrat{from{background-position:0 0,0 0}to{background-position:190px 0,0 0}}",
	"@keyframes dshSweep{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",
	"@keyframes dshOrbitSpin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",
	"@keyframes dshGlobeFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}",
	"@container scrinner (max-width:980px){.dsh-scr-hero{gap:16px}.dsh-scr-globewrap{transform:scale(.85);order:-1;flex-basis:100%}}",
	"@container scrinner (max-width:760px){.dsh-scr-hero{gap:10px}.dsh-scr-globewrap{transform:scale(.62)}}",
	".dsh-rtr-distsec{display:flex;flex-direction:column;gap:5px;min-width:0;flex:1 1 220px}",
	".dsh-rtr-disthead{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0}",
	".dsh-rtr-distlegend{display:flex;gap:6px 10px;flex-wrap:wrap;min-width:0}",
	".dsh-rtr-distleg{font-size:10px;color:var(--dsw-alias-label-secondary,#666);display:inline-flex;align-items:center;gap:3px;max-width:160px;overflow:hidden;white-space:nowrap}",
	".dsh-rtr-distleg i{width:7px;height:7px;border-radius:2px;flex:none}",
	".dsh-rtr-segbar{display:flex;height:14px;border-radius:7px;overflow:hidden;gap:1px;background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 4%,var(--dsw-alias-bg-base,#fff))}",
	".dsh-rtr-segbar span{display:block;min-width:3px;transition:width .5s ease}",
	".dsh-rtr-distdetails summary{font-size:10px;color:var(--dsw-alias-label-tertiary,#8a8a8f);cursor:pointer;user-select:none;width:max-content}",
	".dsh-rtr-distdetails[open] summary{margin-bottom:2px;color:var(--dsw-alias-state-business-primary,#4c6ef5)}",
	".dsh-rtr-disttitle{font-size:11px;letter-spacing:.05em;color:var(--dsw-alias-label-tertiary,#8a8a8f)}",
	".dsh-rtr-dist{display:flex;flex-direction:column;gap:3px;max-height:138px;overflow-y:auto;min-width:0}",
	".dsh-rtr-distrow{display:grid;grid-template-columns:minmax(60px,110px) 1fr 26px;align-items:center;gap:6px;min-width:0}",
	".dsh-rtr-distlbl{font-size:11px;color:var(--dsw-alias-label-secondary,#666);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
	".dsh-rtr-disttrack{height:8px;border-radius:4px;background:rgba(120,150,190,.16);overflow:hidden}",
	".dsh-rtr-disttrack span{display:block;height:100%;border-radius:4px;background:linear-gradient(90deg,#3f8ef7,#38d4ff);transition:width .4s ease}",
	".dsh-rtr-distrow.is-click{cursor:pointer}",
	".dsh-rtr-distrow.is-click .dsh-rtr-disttrack span{background:linear-gradient(90deg,#7a5cf5,#b48cff)}",
	".dsh-rtr-distrow.is-click:hover .dsh-rtr-distlbl{color:var(--dsw-alias-state-business-primary,#4c6ef5)}",
	".dsh-rtr-distval{font-size:11px;font-family:monospace;color:var(--dsw-alias-label-primary,#333);text-align:right}",
	".dsh-scr-panel h4{margin:0 0 14px;font-size:15px;font-weight:600;letter-spacing:.04em;color:#fff;padding-bottom:10px;border-bottom:1px solid rgba(58,157,255,.2)}",
	".dsh-scr-panel h4::before{content:\"\"}",
	".dsh-scr-center{display:flex;flex-direction:column;gap:14px}",
	".dsh-scr-nums{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}",
	".dsh-scr-num{border:1px solid rgba(58,157,255,.45);border-radius:10px;padding:16px 12px 12px;text-align:center;background:rgba(10,30,60,.45);backdrop-filter:blur(10px);box-shadow:0 0 15px rgba(58,157,255,.12)}",
	".dsh-scr-num b{display:block;font-size:36px;font-weight:700;color:#fff;font-family:monospace;line-height:1.1}",
	".dsh-scr-num span{font-size:13px;letter-spacing:.1em;color:#8fb4d9}",
	".dsh-scr-num.is-good b{color:#36f1b0;text-shadow:0 0 10px rgba(54,241,176,.5)}",
	".dsh-scr-num.is-warn b{color:#ffc93c;text-shadow:0 0 10px rgba(255,201,60,.5)}",
	".dsh-scr-num.is-bad b{color:#ff6b8a;text-shadow:0 0 10px rgba(255,107,138,.5)}",
	".dsh-scr-bar{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:12px}",
	".dsh-scr-bar .lbl{width:80px;color:#8fb4d9;flex:none;text-align:right}",
	".dsh-scr-bar .track{flex:1;height:8px;border-radius:4px;background:rgba(58,157,255,.15);overflow:hidden}",
	".dsh-scr-bar .fill{height:100%;border-radius:4px;background:#3a9dff;box-shadow:0 0 6px rgba(58,157,255,.6)}",
	".dsh-scr-bar .fill.is-alt{background:#3a9dff;box-shadow:0 0 6px rgba(58,157,255,.6)}",
	".dsh-scr-bar .val{width:34px;color:#fff;font-family:monospace;flex:none}",
	".dsh-scr-donut{width:132px;height:132px;border-radius:50%;margin:14px auto 24px;position:relative;isolation:isolate;transform:scaleY(.62);background:conic-gradient(#ff4d6d 0 25%,#ffaa00 25% 50%,#ffdd33 50% 75%,#3a9dff 75% 100%);box-shadow:0 0 18px rgba(58,157,255,.2)}",
	".dsh-scr-donut::before{content:\"\";position:absolute;left:2px;right:2px;top:0;bottom:-26px;border-radius:50%;background:linear-gradient(180deg,#0e2a52,#0a1c3a);z-index:-1;box-shadow:0 18px 28px rgba(2,8,20,.65)}",
	".dsh-scr-donut::after{content:attr(data-total);position:absolute;inset:27px;border-radius:50%;background:#050f1f;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#fff;font-family:monospace;transform:scaleY(1.62)}",
	".dsh-scr-b3d{position:relative;height:clamp(150px,20vh,210px);font-size:10px;perspective:56em;perspective-origin:50% calc(50% - 11em)}",
	".dsh-scr-b3stage{position:absolute;top:72%;left:50%;transform-style:preserve-3d;transform:rotateY(-38deg)}",
	".dsh-scr-b3floor{position:absolute;left:-14em;top:-7em;width:28em;height:14em;transform:translateY(6.5em) rotateX(90deg);background:radial-gradient(rgba(5,15,31,0) 40%,#050f1f 78%),linear-gradient(rgba(58,157,255,.16) 1px,transparent 1px),linear-gradient(90deg,rgba(58,157,255,.16) 1px,transparent 1px);background-size:100%,2em 2em,2em 2em}",
	".dsh-scr-b3slot{position:absolute;left:0;top:0;transform-style:preserve-3d;margin-left:var(--x)}",
	".dsh-scr-b3bar{position:absolute;left:0;top:0;transform-style:preserve-3d;transform-origin:0 6.5em 0;transform:scaleY(var(--v,.04));transition:transform .6s ease}",
	".dsh-scr-b3bar>i{position:absolute;margin:-1.3em;width:2.6em;height:2.6em;backface-visibility:hidden;box-shadow:0 0 1px currentColor;background:currentColor}",
	".dsh-scr-b3bar>i:nth-child(n+2){margin-top:-6.5em;height:13em}",
	".dsh-scr-b3bar>i:nth-child(1){transform:rotate3d(1,0,0,90deg) translateZ(6.5em);filter:brightness(1.25)}",
	".dsh-scr-b3bar>i:nth-child(2){transform:rotate3d(0,1,0,-90deg) translateZ(1.3em);filter:brightness(.55)}",
	".dsh-scr-b3bar>i:nth-child(3){transform:rotate3d(0,1,0,0deg) translateZ(1.3em);filter:brightness(.8)}",
	".dsh-scr-b3bar>i:nth-child(4){transform:rotate3d(0,1,0,90deg) translateZ(1.3em);filter:brightness(.4)}",
	".dsh-scr-b3num{position:absolute;left:-1.3em;width:2.6em;text-align:center;font-size:1.35em;font-weight:700;color:#fff;font-family:monospace;text-shadow:0 1px 5px rgba(0,0,0,.85);transform:rotateY(38deg) translateZ(1.6em) translateY(calc(max(1em,5em - 13em*var(--v,.04))))}",
	".dsh-scr-legend{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;font-size:12px;color:#8fb4d9}",
	".dsh-scr-legend i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:5px;vertical-align:-1px}",
	".dsh-scr-table{width:100%;border-collapse:collapse;font-size:13px}",
	".dsh-scr-table th{position:sticky;top:0;z-index:1;color:#3a9dff;font-weight:500;text-align:left;padding:10px 8px;border-bottom:1px solid rgba(58,157,255,.2);letter-spacing:.04em;font-size:12px;background:rgba(10,40,80,.85)}",
	".dsh-scr-table td{padding:10px 8px;border-bottom:1px solid rgba(58,157,255,.08);color:#e6f2ff}",
	".dsh-scr-table tr:hover td{background:rgba(58,157,255,.1)}",
	".dsh-scr-sev{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600}",
	".dsh-scr-sev-critical{color:#ff8fa0;background:rgba(194,24,47,.30);border:1px solid rgba(255,90,110,.45)}",
	".dsh-scr-sev-high{color:#ffb0b0;background:rgba(255,77,77,.20);border:1px solid rgba(255,90,90,.45)}",
	".dsh-scr-sev-medium{color:#ffe98a;background:rgba(255,221,51,.12);border:1px solid rgba(255,221,51,.45)}",
	".dsh-scr-sev-low{color:#7cc0ff;background:rgba(58,157,255,.16);border:1px solid rgba(58,157,255,.45)}",
	".dsh-scr-mode{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px;color:#e6f2ff}",
	".dsh-scr-mode .tag{width:104px;flex:none;color:#8fb4d9}",
	".dsh-scr-mode .n{margin-left:auto;font-family:monospace;color:#fff}",
	".dsh-scr-empty{padding:60px 20px;text-align:center;color:#8fb4d9;letter-spacing:.12em;font-size:15px}"
].join("\n");

var CSS = [
	".dsh-rtr-root{height:100%;display:flex;min-height:0;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);font-size:13px}",
	".dsh-rtr-side{width:168px;flex:none;border-right:1px solid rgba(148,170,200,.35);padding:14px 10px;display:flex;flex-direction:column;gap:2px;background:linear-gradient(180deg,rgba(238,243,250,.88),rgba(226,235,247,.78));backdrop-filter:blur(12px) saturate(1.1)}",
	".dsh-rtr-side-title{font-size:12px;letter-spacing:.12em;color:#5c7392;padding:0 8px 10px;font-weight:600}",
	".dsh-rtr-side-item{display:flex;align-items:center;justify-content:space-between;gap:6px;padding:7px 10px;border:none;background:none;border-radius:8px;cursor:pointer;color:var(--dsw-alias-label-secondary,#5b5b60);font-size:13px;text-align:left;transition:background .18s,color .18s,box-shadow .18s}",
	".dsh-rtr-side-item:hover{background:rgba(255,255,255,.6);color:var(--dsw-alias-label-primary,#1a1a1a)}",
	".dsh-rtr-side-item.is-active{background:rgba(63,127,232,.10);color:#1f4fb8;font-weight:600;box-shadow:inset 3px 0 0 0 #3f7fe8,inset 0 0 0 1px rgba(63,127,232,.10)}",
	".dsh-rtr-count{font-size:11px;min-width:22px;text-align:center;border-radius:999px;padding:1px 8px;background:rgba(63,127,232,.10);border:1px solid rgba(63,127,232,.28);color:#33549e;font-variant-numeric:tabular-nums}",
	".dsh-rtr-main{flex:1;min-width:0;display:flex;flex-direction:column;overflow:auto;padding:14px 18px 18px;gap:12px}",
	".dsh-rtr-meta{display:flex;align-items:center;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--dsw-alias-label-secondary,#5b5b60);border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:9px;padding:7px 12px;background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 4%,var(--dsw-alias-bg-base,#fff))}",
	".dsh-rtr-meta b{color:var(--dsw-alias-label-primary,#1a1a1a);font-weight:600;margin-left:4px}",
	".dsh-rtr-meta.is-ghost{border-style:dashed;background:transparent;color:var(--dsw-alias-label-tertiary,#8a8a8f);padding:4px 12px}",
	".dsh-rtr-metalink{font:inherit;font-size:12px;color:var(--dsw-alias-state-business-primary,#4c6ef5);background:none;border:none;cursor:pointer;padding:0}",
	".dsh-rtr-metalink:hover{text-decoration:underline}",
	".dsh-rtr-meta input{font:inherit;font-size:12px;padding:3px 8px;border:1px solid var(--dsw-alias-border-l2,#d4d4d8);border-radius:6px;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a)}",
	".dsh-rtr-stats{display:flex;flex-direction:column;gap:10px}",
	".dsh-rtr-cardsrow{display:flex;gap:12px;flex-wrap:wrap}",
	".dsh-rtr-statcard{flex:1;min-width:110px;border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:10px;padding:9px 13px;background:var(--dsw-alias-bg-base,#fff);cursor:pointer}",
	".dsh-rtr-statcard:hover{border-color:var(--dsw-alias-border-l2,#d4d4d8)}",
	".dsh-rtr-statcard.is-dim{opacity:.55}",
	".dsh-rtr-statnum{font-size:21px;font-weight:700;line-height:1.2;margin-top:2px}",
	".dsh-rtr-statlabel{font-size:11px;color:var(--dsw-alias-label-tertiary,#8a8a8f);letter-spacing:.05em}",
	".dsh-rtr-statextra{display:flex;flex-direction:row;flex-wrap:wrap;gap:8px 16px;width:100%;align-items:flex-start}",
	".dsh-rtr-bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 4%,var(--dsw-alias-bg-base,#fff));flex:1 1 100%}",
	".dsh-rtr-chiprow{display:flex;gap:6px;flex-wrap:wrap;flex:1 1 100%}",
	".dsh-rtr-types{display:flex;gap:6px;flex-wrap:wrap}",
	".dsh-rtr-typechip{font-size:11px;padding:2px 8px;border-radius:9px;background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 4%,var(--dsw-alias-bg-base,#fff));color:var(--dsw-alias-label-secondary,#5b5b60);border:1px solid var(--dsw-alias-border-l1,#e9e9ec);cursor:pointer}",
	".dsh-rtr-typechip.is-static{cursor:default;opacity:.78}",
	".dsh-rtr-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}",
	".dsh-rtr-toolbar .dsh-rtr-spacer{flex:1}",
	".dsh-rtr-select,.dsh-rtr-search{font:inherit;font-size:12px;padding:5px 8px;border:1px solid var(--dsw-alias-border-l2,#d4d4d8);border-radius:7px;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a)}",
	".dsh-rtr-search{width:170px}",
	".dsh-rtr-btn{font:inherit;font-size:12px;padding:5px 11px;border-radius:7px;border:1px solid var(--dsw-alias-border-l2,#d4d4d8);background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);cursor:pointer;white-space:nowrap}",
	".dsh-rtr-btn:hover{background:var(--dsw-alias-interactive-bg-hover,color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 7%,transparent))}",
	".dsh-rtr-btn.is-primary{border-color:transparent;background:var(--dsw-alias-state-business-primary,#4c6ef5);color:#fff}",
	".dsh-rtr-btn.is-primary:hover{filter:brightness(1.05)}",
	".dsh-rtr-btn.is-danger{color:#d5333c;border-color:#f1b8bf}",
	".dsh-rtr-btn:active{background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 13%,transparent)}",
	".dsh-rtr-btn:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary,#4c6ef5);outline-offset:1px}",
	".dsh-rtr-btn:disabled{opacity:.5;cursor:default}",
	".dsh-rtr-grouphead{display:flex;align-items:center;gap:10px;padding:10px 12px 4px;font-weight:600;font-size:12.5px;color:var(--dsw-alias-label-secondary,#5b5b60)}",
	".dsh-rtr-grouphead .dsh-rtr-count{font-weight:400}",
	".dsh-rtr-row{border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:10px;overflow:hidden;background:var(--dsw-alias-bg-base,#fff)}",
	".dsh-rtr-row + .dsh-rtr-row{margin-top:8px}",
	".dsh-rtr-rowhead{display:flex;align-items:center;gap:10px;padding:9px 12px;cursor:pointer}",
	".dsh-rtr-rowhead:hover{background:var(--dsw-alias-interactive-bg-hover,color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 5%,transparent))}",
	".dsh-rtr-seq{font-size:11px;color:var(--dsw-alias-label-tertiary,#8a8a8f);width:28px;flex:none;text-align:right}",
	".dsh-rtr-title{font-weight:600;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
	".dsh-rtr-summ{flex:1;min-width:0;color:var(--dsw-alias-label-tertiary,#8a8a8f);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
	".dsh-rtr-time{font-size:11px;color:var(--dsw-alias-label-tertiary,#8a8a8f);flex:none}",
	".dsh-rtr-sev{flex:none;font-size:11px;font-weight:600;padding:2px 8px;border-radius:9px;border:1px solid}",
	".dsh-rtr-sev-critical{color:#c2182f;border-color:rgba(194,24,47,.35);background:rgba(194,24,47,.08)}",
	".dsh-rtr-sev-high{color:#ff4d4d;border-color:rgba(255,77,77,.35);background:rgba(255,77,77,.08)}",
	".dsh-rtr-sev-medium{color:#b58a00;border-color:rgba(181,138,0,.35);background:rgba(181,138,0,.08)}",
	".dsh-rtr-sev-low{color:#3b7dd8;border-color:rgba(59,125,216,.35);background:rgba(59,125,216,.08)}",
	".dsh-rtr-st{flex:none;font-size:11px;padding:2px 8px;border-radius:9px;border:1px solid var(--dsw-alias-border-l2,#d4d4d8);color:var(--dsw-alias-label-secondary,#5b5b60)}",
	".dsh-rtr-st-verified{color:#2f9e63;border-color:rgba(47,158,99,.35);background:rgba(47,158,99,.08)}",
		".dsh-rtr-st-code-reviewed{color:#0b7285;border-color:rgba(11,114,133,.35);background:rgba(11,114,133,.08)}",
	".dsh-rtr-st-false-positive{color:#8a8a8f;text-decoration:line-through}",
	".dsh-rtr-am{flex:none;font-size:11px;padding:2px 8px;border-radius:9px;border:1px solid}",
	".dsh-rtr-am-static{color:var(--dsw-alias-label-secondary,#5b5b60);border-color:rgba(91,91,96,.35);background:rgba(91,91,96,.07)}",
	".dsh-rtr-am-dynamic{color:#2f9e63;border-color:rgba(47,158,99,.35);background:rgba(47,158,99,.1);font-weight:600}",
	".dsh-rtr-detail{border-top:1px solid var(--dsw-alias-border-l1,#e9e9ec);padding:12px 16px;display:flex;flex-direction:column;gap:10px;background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 4%,var(--dsw-alias-bg-base,#fff))}",
	".dsh-rtr-fields{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--dsw-alias-label-secondary,#5b5b60)}",
	".dsh-rtr-fields b{color:var(--dsw-alias-label-primary,#1a1a1a);font-weight:600;margin-left:4px}",
	".dsh-rtr-block h4{margin:0 0 4px;font-size:12px;color:var(--dsw-alias-label-tertiary,#8a8a8f);letter-spacing:.04em}",
	".dsh-rtr-block pre{margin:0;padding:10px 12px;border-radius:8px;background:var(--dsw-alias-bg-base,#fff);border:1px solid var(--dsw-alias-border-l1,#e9e9ec);white-space:pre-wrap;word-break:break-word;font-size:12px;max-height:280px;overflow:auto}",
	".dsh-rtr-duo{display:flex;gap:10px;flex-wrap:wrap}",
	".dsh-rtr-duo>div{flex:1;min-width:280px}",
	".dsh-rtr-duo pre{margin:0;padding:10px 12px;border-radius:8px;background:var(--dsw-alias-bg-base,#fff);border:1px solid var(--dsw-alias-border-l1,#e9e9ec);white-space:pre-wrap;word-break:break-word;font-size:12px;max-height:280px;overflow:auto}",
	".dsh-rtr-verdict{font-size:12px;padding:6px 12px;border-radius:8px;border:1px solid var(--dsw-alias-border-l2,#d4d4d8);background:var(--dsw-alias-bg-base,#fff)}",
	".dsh-rtr-rowactions{display:flex;gap:6px;flex:none}",
	".dsh-rtr-check{accent-color:var(--dsw-alias-state-business-primary,#4c6ef5)}",
	".dsh-rtr-pager{display:flex;align-items:center;justify-content:center;gap:12px;padding:4px 0;font-size:12px;color:var(--dsw-alias-label-secondary,#5b5b60)}",
	".dsh-rtr-empty{border:1px dashed var(--dsw-alias-border-l2,#d4d4d8);border-radius:10px;padding:36px 20px;text-align:center;color:var(--dsw-alias-label-tertiary,#8a8a8f);font-size:12px;line-height:1.9}",
	".dsh-rtr-notice{position:sticky;top:0;z-index:2;font-size:12px;padding:6px 12px;border-radius:8px;background:rgba(76,110,245,.08);border:1px solid rgba(76,110,245,.25);color:var(--dsw-alias-label-primary,#1a1a1a)}",
	".dsh-rtr-skel{color:var(--dsw-alias-label-tertiary,#8a8a8f);padding:28px;text-align:center;font-size:12px}",
	".dsh-rtr-tl{display:flex;flex-direction:column}",
	".dsh-rtr-tl-item{display:flex;gap:12px;align-items:stretch;min-width:0}",
	".dsh-rtr-tl-rail{display:flex;flex-direction:column;align-items:center;width:18px;flex:none}",
	".dsh-rtr-tl-dot{width:10px;height:10px;border-radius:50%;background:var(--dsw-alias-state-business-primary,#4c6ef5);border:2px solid var(--dsw-alias-bg-base,#fff);flex:none;margin-top:22px;z-index:1}",
	".dsh-rtr-tl-line{flex:1;width:2px;background:var(--dsw-alias-border-l2,#d4d4d8);margin-top:4px}",
	".dsh-rtr-tl-item:last-child .dsh-rtr-tl-line{display:none}",
	".dsh-rtr-tl-body{flex:1;min-width:0;display:flex;flex-direction:column;gap:5px;padding-bottom:12px}",
	".dsh-rtr-tl-time{font-family:monospace;font-size:11px;color:var(--dsw-alias-label-secondary,#5b5b60);letter-spacing:.04em}",
	".dsh-rtr-tl-card{border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:10px;background:var(--dsw-alias-bg-base,#fff);overflow:hidden}",
	".dsh-rtr-tl-meta{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--dsw-alias-label-secondary,#5b5b60);padding:0 12px 9px;cursor:pointer}",
	".dsh-rtr-tl-meta b{color:var(--dsw-alias-label-primary,#1a1a1a);font-weight:600;margin-left:4px}",
	".dsh-rtr-tl-concl{flex:1;min-width:0;color:var(--dsw-alias-label-tertiary,#8a8a8f);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
	"@media (max-width:720px){.dsh-rtr-tl-item{gap:8px}.dsh-rtr-tl-meta{gap:8px}}",
	".dsh-rtr-cp{display:flex;flex-direction:column;gap:10px}",
	".dsh-rtr-cp-item{display:flex;flex-direction:column;gap:0;min-width:0}",
	".dsh-rtr-cp-card{border:1px solid var(--dsw-alias-border-l1,#e9e9ec);border-radius:10px;background:var(--dsw-alias-bg-base,#fff);overflow:hidden}",
	".dsh-rtr-cp-chain{display:flex;gap:0;flex-wrap:wrap;align-items:stretch;padding:9px 12px;cursor:pointer;row-gap:6px}",
	".dsh-rtr-cp-hop{display:flex;align-items:baseline;gap:6px;font-size:12px;max-width:100%}",
	".dsh-rtr-cp-hop:not(:last-child):after{content:'→';color:var(--dsw-alias-label-tertiary,#8a8a8f);margin:0 6px}",
	".dsh-rtr-cp-hop i{font-style:normal;color:var(--dsw-alias-label-tertiary,#8a8a8f);white-space:nowrap}",
	".dsh-rtr-cp-hop b{font-weight:600;color:var(--dsw-alias-label-primary,#1a1a1a);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px}",
	".dsh-rtr-cp-hoplabel{font-size:11px;color:var(--dsw-alias-label-tertiary,#8a8a8f);white-space:nowrap}",
	".dsh-rtr-cp-hopval{color:var(--dsw-alias-label-primary,#1a1a1a);font-size:12px}",
	".dsh-rtr-cp-impact{flex:1 1 100%;border-top:1px dashed var(--dsw-alias-border-l1,#e9e9ec);padding-top:6px}",
	"@media (max-width:720px){.dsh-rtr-cp-hop{flex-basis:100%}.dsh-rtr-cp-hop:not(:last-child):after{display:none}}",
	"@media (max-width:720px){.dsh-rtr-root{flex-direction:column}.dsh-rtr-side{width:auto;flex-direction:row;overflow-x:auto;padding:8px}.dsh-rtr-side-title{display:none}.dsh-rtr-side-item{white-space:nowrap}}"
].join("\n");

function installStyles() {
	if (document.getElementById("dsh-rtr-style")) return function () {};
	var el = document.createElement("style");
	el.id = "dsh-rtr-style";
	el.textContent = CSS + CSS_SCREEN;
	document.head.appendChild(el);
	return function () { el.remove(); };
}

//#endregion

var LABEL_BY_TYPE_MODES = { "av-evasion": 1, "ctf-solver": 1, "binary-analysis": 1 };
function Chip(props) {
	if (props.typeLabel) return React.createElement("span", { className: "dsh-rtr-typechip is-static" }, props.typeLabel);
	return React.createElement("span", { className: "dsh-rtr-sev dsh-rtr-sev-" + props.severity }, SEVERITY_LABEL[props.severity] || props.severity);
}
function StatusChip(props) { return React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + props.status }, (props.binary ? ASSET_STATUS_LABEL : STATUS_LABEL)[props.status] || props.status); }
function Btn(props) {
	return React.createElement("button", {
		className: "dsh-rtr-btn" + (props.primary ? " is-primary" : "") + (props.danger ? " is-danger" : ""),
		onClick: props.onClick, disabled: props.disabled, type: "button"
	}, props.children);
}
function Block(props, value) {
	return React.createElement("div", { className: "dsh-rtr-block" },
		React.createElement("h4", null, props.title),
		React.createElement("pre", null, props.children !== undefined ? props.children : value));
}

/** 紧凑分布条形图：多类型不换行堆叠，固定高度可滚动，行可点击（点击=触发筛选）。 */
function DistBars(props) {
	var items = props.items || [];
	if (items.length === 0) return null;
	var mx = Math.max.apply(null, items.map(function (i) { return i.count; }).concat([1]));
	return React.createElement("div", { className: "dsh-rtr-dist" },
		items.map(function (it) {
			return React.createElement("div", { key: it.key, className: "dsh-rtr-distrow" + (it.onClick ? " is-click" : ""), onClick: it.onClick || undefined, title: it.onClick ? "点击筛选 " + it.label : it.label },
				React.createElement("span", { className: "dsh-rtr-distlbl" }, it.label),
				React.createElement("span", { className: "dsh-rtr-disttrack" }, React.createElement("span", { style: { width: (it.count / mx * 100) + "%" } })),
				React.createElement("b", { className: "dsh-rtr-distval" }, it.count));
		}));
}

var DIST_PALETTE = ["#3f8ef7", "#38d4ff", "#7a5cf5", "#b48cff", "#2f9d63", "#e8a13a", "#e5484d", "#8a99ad"];

/** 时间范围 → [from,to] ISO（空串=不限）：today=本地今日零点；Nd=近 N 天；custom=日期闭区间。 */
function rangeIso(sel, cf, ct) {
	var now = new Date();
	if (sel === "today") return [new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString(), ""];
	if (sel === "3d" || sel === "7d" || sel === "30d") return [new Date(now.getTime() - Number(sel.slice(0, -1)) * 86400000).toISOString(), ""];
	if (sel === "custom") return [cf ? new Date(cf + "T00:00:00").toISOString() : "", ct ? new Date(ct + "T23:59:59").toISOString() : ""];
	return ["", ""];
}
var RANGE_OPTIONS = [["today", "今日"], ["3d", "近3天"], ["7d", "近7天"], ["30d", "近30天"], ["all", "全部"], ["custom", "自定义"]];
/** 空态时间范围提示：当前范围可能滤掉了历史成果。 */
function rangeHint(sel) {
	var names = { today: "今日", "3d": "近3天", "7d": "近7天", "30d": "近30天", all: "全部", custom: "自定义" };
	return "当前时间范围：" + (names[sel] || sel) + "——历史成果请切换上方时间范围";
}
/** 时间范围选择器（大屏与模式页共用）。props: range/customFrom/customTo/onChange(sel,cf,ct) */
function RangePicker(props) {
	return React.createElement("span", { className: "dsh-rtr-rangepicker" },
		React.createElement("select", { className: "dsh-scr-range", value: props.range, onChange: function (e) { props.onChange(e.target.value, props.customFrom, props.customTo); } },
			RANGE_OPTIONS.map(function (r) { return React.createElement("option", { key: r[0], value: r[0] }, r[1]); })),
		props.range === "custom" ? React.createElement("input", { type: "date", className: "dsh-scr-date", value: props.customFrom, onChange: function (e) { props.onChange("custom", e.target.value, props.customTo); } }) : null,
		props.range === "custom" ? React.createElement("input", { type: "date", className: "dsh-scr-date", value: props.customTo, onChange: function (e) { props.onChange("custom", props.customFrom, e.target.value); } }) : null);
}

/** 分布节 v2（紧凑）：标题+色点图例一行 · 分段占比条 · <details> 可折叠明细条形。
 * 默认收起——零占高，统计卡片永不被分布内容拉长；明细展开才显示 DistBars。 */
function distSection(title, items) {
	if (!items || items.length === 0) return null;
	var top = items.slice(0, 8);
	var tot = top.reduce(function (n, i) { return n + i.count; }, 0) || 1;
	return React.createElement("div", { className: "dsh-rtr-distsec" },
		React.createElement("div", { className: "dsh-rtr-disthead" },
			React.createElement("span", { className: "dsh-rtr-disttitle" }, title),
			React.createElement("span", { className: "dsh-rtr-distlegend" }, top.map(function (it, i) {
				return React.createElement("span", { key: it.key, className: "dsh-rtr-distleg", title: it.label + " × " + it.count },
					React.createElement("i", { style: { background: DIST_PALETTE[i % DIST_PALETTE.length] } }), it.label, "·", it.count);
			}))),
		React.createElement("div", { className: "dsh-rtr-segbar" }, top.map(function (it, i) {
			return React.createElement("span", { key: it.key, style: { width: (it.count / tot * 100) + "%", background: DIST_PALETTE[i % DIST_PALETTE.length] }, title: it.label + " × " + it.count });
		})),
		React.createElement("details", { className: "dsh-rtr-distdetails" },
			React.createElement("summary", null, "分布明细"),
			DistBars({ items: items })));
}

var SEV_COLORS = { critical: "#c2182f", high: "#ff4d4d", medium: "#d9b00c", low: "#3b7dd8" };

function StatsPanel(props) {
	var stats = props.stats, total = stats.total || 0;
	if (props.archetype === "ledger") {
		var lk = ["pending", "verified", "fixed", "false-positive"];
		var cards = [{ key: "", label: "任务总数", color: null }].concat(lk.map(function (s) {
			return { key: s, label: (props.mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[s], color: s === "verified" ? "#2f9e63" : s === "fixed" ? "#3b7dd8" : s === "false-positive" ? "#8a8a8f" : "#b58a00" };
		}));
		return React.createElement("div", { className: "dsh-rtr-stats" },
			React.createElement("div", { className: "dsh-rtr-cardsrow" }, cards.map(function (c) {
				var value = c.key === "" ? total : (stats.byStatus[c.key] || 0);
				var active = props.statusFilter === c.key || (c.key === "" && !props.statusFilter);
				return React.createElement("div", { key: c.key || "all", className: "dsh-rtr-statcard" + (active ? "" : " is-dim"), onClick: function () { props.onStatus(c.key); } },
				React.createElement("div", { className: "dsh-rtr-statlabel" }, c.label),
				React.createElement("div", { className: "dsh-rtr-statnum", style: c.color ? { color: c.color } : null }, value));
			})),
			React.createElement("div", { className: "dsh-rtr-statextra" },
				distSection("任务形态分布", (stats.byType || []).map(function (x) { return { key: x.type, label: x.type, count: x.count }; })),
				distSection("证据等级分布", ["confirmed", "partial", "unknown"].map(function (e) { return { key: e, label: EVIDENCE_LABEL[e] || e, count: (stats.byEvidence ? stats.byEvidence[e] : 0) || 0 }; }).filter(function (i) { return i.count > 0; }))));
	}
	if (props.archetype === "assets") {
		var stKeys = ["pending", "verified", "false-positive", "fixed"];
		var cards = [{ key: "", label: "总数", color: null }].concat(stKeys.map(function (s) {
			return { key: s, label: ASSET_STATUS_LABEL[s], color: s === "verified" ? "#2f9e63" : s === "false-positive" ? "#8a8a8f" : s === "fixed" ? "#3b7dd8" : "#b58a00" };
		}));
		return React.createElement("div", { className: "dsh-rtr-stats" },
			React.createElement("div", { className: "dsh-rtr-cardsrow" }, cards.map(function (c) {
				var value = c.key === "" ? total : (stats.byStatus[c.key] || 0);
				var active = props.statusFilter === c.key || (c.key === "" && !props.statusFilter);
				return React.createElement("div", { key: c.key || "all", className: "dsh-rtr-statcard" + (active ? "" : " is-dim"), onClick: function () { props.onStatus(c.key); } },
				React.createElement("div", { className: "dsh-rtr-statlabel" }, c.label),
				React.createElement("div", { className: "dsh-rtr-statnum", style: c.color ? { color: c.color } : null }, value));
			})),
			React.createElement("div", { className: "dsh-rtr-statextra" },
				distSection(props.typeLabel, (stats.byType || []).map(function (x) { return { key: x.type, label: x.type, count: x.count }; })),
				props.mode === "binary-analysis" ? distSection("家族分布", (stats.byFamily || []).map(function (c) { return { key: c.family, label: c.family, count: c.count }; })) : null,
				props.mode === "binary-analysis" ? distSection("壳/保护分布", (stats.byPacker || []).map(function (c) { return { key: c.packer, label: c.packer, count: c.count }; })) : null,
				props.mode !== "binary-analysis" ? distSection(props.mode === "attack-defense" ? "目标分布" : "分布", (stats.byTarget || []).filter(function (x) { return x.target !== "（未填）"; }).map(function (x) { return { key: x.target, label: x.target, count: x.count, onClick: function () { props.onTarget(x.target); } }; })) : null));
	}
	if (props.archetype === "timeline") {
		var stKeys = ["pending", "verified", "false-positive", "fixed"];
		var cards = [{ key: "", label: "节点总数", color: null }].concat(stKeys.map(function (s) {
			return { key: s, label: TIMELINE_STATUS_LABEL[s], color: s === "verified" ? "#2f9e63" : s === "false-positive" ? "#8a8a8f" : s === "fixed" ? "#3b7dd8" : "#b58a00" };
		}));
		return React.createElement("div", { className: "dsh-rtr-stats" },
			React.createElement("div", { className: "dsh-rtr-cardsrow" }, cards.map(function (c) {
				var value = c.key === "" ? total : (stats.byStatus[c.key] || 0);
				var active = props.statusFilter === c.key || (c.key === "" && !props.statusFilter);
				return React.createElement("div", { key: c.key || "all", className: "dsh-rtr-statcard" + (active ? "" : " is-dim"), onClick: function () { props.onStatus(c.key); } },
				React.createElement("div", { className: "dsh-rtr-statlabel" }, c.label),
				React.createElement("div", { className: "dsh-rtr-statnum", style: c.color ? { color: c.color } : null }, value));
			})),
			React.createElement("div", { className: "dsh-rtr-statextra" },
				distSection(props.typeLabel, (stats.byType || []).map(function (x) { return { key: x.type, label: x.type, count: x.count }; })),
				distSection("主机分布", (stats.byTarget || []).filter(function (x) { return x.target !== "（未填）"; }).map(function (x) { return { key: x.target, label: x.target, count: x.count, onClick: function () { props.onTarget(x.target); } }; }))));
	}
	if (props.archetype === "cloudpath") {
		var stKeys = ["pending", "verified", "false-positive", "fixed"];
		var cards = [{ key: "", label: "路径总数", color: null }].concat(stKeys.map(function (s) {
			return { key: s, label: CLOUDPATH_STATUS_LABEL[s], color: s === "verified" ? "#2f9e63" : s === "false-positive" ? "#8a8a8f" : s === "fixed" ? "#3b7dd8" : "#b58a00" };
		}));
		return React.createElement("div", { className: "dsh-rtr-stats" },
			React.createElement("div", { className: "dsh-rtr-cardsrow" }, cards.map(function (c) {
				var value = c.key === "" ? total : (stats.byStatus[c.key] || 0);
				var active = props.statusFilter === c.key || (c.key === "" && !props.statusFilter);
				return React.createElement("div", { key: c.key || "all", className: "dsh-rtr-statcard" + (active ? "" : " is-dim"), onClick: function () { props.onStatus(c.key); } },
				React.createElement("div", { className: "dsh-rtr-statlabel" }, c.label),
				React.createElement("div", { className: "dsh-rtr-statnum", style: c.color ? { color: c.color } : null }, value));
			})),
			React.createElement("div", { className: "dsh-rtr-statextra" },
				distSection(props.typeLabel, (stats.byType || []).map(function (x) { return { key: x.type, label: x.type, count: x.count }; })),
				distSection("目标资源分布", (stats.byTarget || []).filter(function (x) { return x.target !== "（未填）"; }).map(function (x) { return { key: x.target, label: x.target, count: x.count, onClick: function () { props.onTarget(x.target); } }; }))));
	}
	var bars = SEVERITY_ORDER.map(function (s) {
		return React.createElement("div", { key: s, title: SEVERITY_LABEL[s] + " " + (stats.bySeverity[s] || 0), style: { width: total > 0 ? ((stats.bySeverity[s] || 0) / total * 100) + "%" : 0, background: SEV_COLORS[s] } });
	});
	var cards = [{ key: "", label: "总数", color: null }].concat(SEVERITY_ORDER.map(function (s) { return { key: s, label: SEVERITY_LABEL[s], color: SEV_COLORS[s] }; }));
	return React.createElement("div", { className: "dsh-rtr-stats" },
		React.createElement("div", { className: "dsh-rtr-cardsrow" }, cards.map(function (c) {
			var value = c.key === "" ? total : (stats.bySeverity[c.key] || 0);
			var active = props.severityFilter === c.key || (c.key === "" && !props.severityFilter);
			return React.createElement("div", { key: c.key || "all", className: "dsh-rtr-statcard" + (active ? "" : " is-dim"), onClick: function () { props.onSeverity(c.key); } },
			React.createElement("div", { className: "dsh-rtr-statlabel" }, c.label),
			React.createElement("div", { className: "dsh-rtr-statnum", style: c.color ? { color: c.color } : null }, value));
		})),
		React.createElement("div", { className: "dsh-rtr-statextra" },
			React.createElement("div", { className: "dsh-rtr-bar" }, bars),
			React.createElement("div", { className: "dsh-rtr-chiprow" },
				Object.keys(STATUS_LABEL).map(function (st) {
					return React.createElement("span", {
						key: st, className: "dsh-rtr-typechip",
						style: props.statusFilter === st ? { borderColor: "var(--dsw-alias-state-business-primary,#4c6ef5)", color: "var(--dsw-alias-state-business-primary,#4c6ef5)" } : null,
						onClick: function () { props.onStatus(props.statusFilter === st ? "" : st); }
					}, STATUS_LABEL[st] + " " + (stats.byStatus[st] || 0));
				})),
			distSection(props.typeLabel, (stats.byType || []).map(function (t) { return { key: t.type, label: t.type, count: t.count }; })),
			props.mode === "code-audit" ? distSection("CWE 分布", (stats.byCwe || []).map(function (c) { return { key: c.cwe, label: c.cwe, count: c.count }; })) : null,
			props.mode === "code-audit" ? distSection("来源", (stats.bySource || []).map(function (c) { return { key: c.source, label: SOURCE_LABEL[c.source] || c.source, count: c.count }; })) : null,
			props.mode === "code-audit" ? distSection("审计形态", (stats.byAuditMode || []).map(function (c) { return { key: c.auditMode, label: AUDIT_MODE_LABEL[c.auditMode] || c.auditMode, count: c.count }; })) : null,
			props.mode === "binary-analysis" ? distSection("家族分布", (stats.byFamily || []).map(function (c) { return { key: c.family, label: c.family, count: c.count }; })) : null,
			props.mode === "binary-analysis" ? distSection("壳/保护分布", (stats.byPacker || []).map(function (c) { return { key: c.packer, label: c.packer, count: c.count }; })) : null,
			props.mode === "pentest" ? distSection("目标分布", (stats.byTarget || []).filter(function (t) { return t.target !== "（未填）"; }).map(function (t) { return { key: t.target, label: t.target, count: t.count, onClick: function () { props.onTarget(t.target); } }; })) : null));
}

function MetaBar(props) {
	var meta = props.meta || { targetLabel: "", version: "", scope: "" };
	var labels = props.labels;
	if (!props.editing) {
		var empty = !meta.targetLabel && !meta.version && !meta.scope;
		if (empty) {
			return React.createElement("div", { className: "dsh-rtr-meta is-ghost" },
				React.createElement("span", null, labels[0] + "未设置（导出报告将标注为未填写）"),
				React.createElement("span", { style: { flex: 1 } }),
				React.createElement("button", { type: "button", className: "dsh-rtr-metalink", onClick: props.onEdit }, "设置"));
		}
		return React.createElement("div", { className: "dsh-rtr-meta" },
			React.createElement("span", null, labels[0], React.createElement("b", null, meta.targetLabel || "未填写")),
			React.createElement("span", null, labels[1], React.createElement("b", null, meta.version || "未填写")),
			React.createElement("span", null, "范围", React.createElement("b", null, meta.scope || "未填写")),
			React.createElement("span", { style: { flex: 1 } }),
			React.createElement(Btn, { onClick: props.onEdit }, "编辑"));
	}
	return React.createElement("div", { className: "dsh-rtr-meta" },
		React.createElement("span", null, labels[0], React.createElement("input", { value: props.draft.targetLabel, onChange: function (e) { props.onDraft("targetLabel", e.target.value); }, placeholder: "对象/范围" })),
		React.createElement("span", null, labels[1], React.createElement("input", { value: props.draft.version, onChange: function (e) { props.onDraft("version", e.target.value); }, placeholder: "版本/commit" })),
		React.createElement("span", null, "范围", React.createElement("input", { value: props.draft.scope, onChange: function (e) { props.onDraft("scope", e.target.value); }, placeholder: "scope" })),
		React.createElement(Btn, { primary: true, onClick: props.onSave }, "保存"),
		React.createElement(Btn, { onClick: props.onCancel }, "取消"));
}

function Detail(props) {
	var f = props.f, mode = props.mode;
	var meta = props.meta || MODE_META.pentest;
	var audit = mode === "code-audit";
	var binary = mode === "binary-analysis";
	if (meta.archetype === "ledger") {
		return React.createElement("div", { className: "dsh-rtr-detail" },
			React.createElement("div", { className: "dsh-rtr-fields" },
				React.createElement("span", null, meta.kindLabel, React.createElement("b", null, f.type || "未分类")),
				React.createElement("span", null, meta.locLabel, React.createElement("b", null, f.target || "未填写")),
				React.createElement("span", null, "状态", React.createElement("b", null, (mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[f.status] || f.status)),
				React.createElement("span", null, "优先级", React.createElement("b", null, SEVERITY_LABEL[f.severity] || f.severity)),
				React.createElement("span", null, "证据等级", React.createElement("b", null, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel)),
				React.createElement("span", null, "登记时间", React.createElement("b", null, fmtTime(f.createdAt))),
				f.verifiedAt ? React.createElement("span", null, "收口时间", React.createElement("b", null, fmtTime(f.verifiedAt))) : null),
			f.description || f.summary ? Block({ title: meta.descLabel }, f.description || f.summary) : null,
			f.chain ? Block({ title: meta.chainLabel }, f.chain) : null,
			f.poc ? Block({ title: meta.pocTitle }, f.poc) : null,
			f.evidence ? Block({ title: "任务书 / 材料路径" }, f.evidence) : null,
			f.fix ? Block({ title: "备注 / 风险提示" }, f.fix) : null,
			f.verifyNote ? Block({ title: "复核记录" }, f.verifyNote) : null,
			React.createElement("div", { className: "dsh-rtr-rowactions" },
				React.createElement(Btn, { onClick: function () { props.onVerify(f); } }, "发送到会话复核"),
				React.createElement(Btn, { onClick: function () { props.onExportOne(f); } }, "导出任务卡（MD）")));
	}
	if (meta.archetype === "assets") {
		return React.createElement("div", { className: "dsh-rtr-detail" },
			React.createElement("div", { className: "dsh-rtr-fields" },
				React.createElement("span", null, meta.kindLabel, React.createElement("b", null, f.type || "未分类")),
				React.createElement("span", null, meta.locLabel, React.createElement("b", { style: { fontFamily: "monospace" } }, f.target || "未填写")),
				React.createElement("span", null, "状态", React.createElement("b", null, ASSET_STATUS_LABEL[f.status] || f.status)),
				React.createElement("span", null, "证据等级", React.createElement("b", null, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel)),
				f.sampleHash ? React.createElement("span", null, "关联样本", React.createElement("b", { style: { fontFamily: "monospace" } }, f.sampleHash.slice(0, 16) + "…")) : null,
				f.family ? React.createElement("span", null, "家族", React.createElement("b", null, f.family)) : null,
				f.packer ? React.createElement("span", null, "壳", React.createElement("b", null, f.packer)) : null,
				React.createElement("span", null, "登记时间", React.createElement("b", null, fmtTime(f.createdAt))),
				f.verifiedAt ? React.createElement("span", null, "验证时间", React.createElement("b", null, fmtTime(f.verifiedAt))) : null),
			f.description || f.summary ? Block({ title: meta.descLabel }, f.description || f.summary) : null,
			f.chain ? Block({ title: meta.chainLabel }, f.chain) : null,
			f.poc ? Block({ title: meta.pocTitle }, f.poc) : null,
			f.iocs ? Block({ title: mode === "av-evasion" ? "环境 / 引擎效果清单" : "IOC 清单" }, f.iocs) : null,
			f.detectionRule ? Block({ title: "检测规则（YARA/Sigma）" }, f.detectionRule) : null,
			f.evidence ? Block({ title: "证据引用" }, f.evidence) : null,
			f.fix ? Block({ title: mode === "binary-analysis" ? "处置建议" : "备注" }, f.fix) : null,
			f.verifyNote ? Block({ title: "验证记录" }, f.verifyNote) : null,
			React.createElement("div", { className: "dsh-rtr-rowactions" },
				React.createElement(Btn, { onClick: function () { props.onVerify(f); } }, "发送到会话验证"),
				React.createElement(Btn, { onClick: function () { props.onExportOne(f); } }, "导出资产卡片（MD）")));
	}
	if (meta.archetype === "timeline") {
		return React.createElement("div", { className: "dsh-rtr-detail" },
			React.createElement("div", { className: "dsh-rtr-fields" },
				React.createElement("span", null, "攻击时间", React.createElement("b", { style: { fontFamily: "monospace" } }, fmtTimelineAt(f.timelineAt))),
				React.createElement("span", null, meta.kindLabel, React.createElement("b", null, f.type || "未分类")),
				React.createElement("span", null, meta.locLabel, React.createElement("b", { style: { fontFamily: "monospace" } }, f.target || "未填写")),
				React.createElement("span", null, "严重度", React.createElement("b", null, SEVERITY_LABEL[f.severity] || f.severity)),
				React.createElement("span", null, "状态", React.createElement("b", null, TIMELINE_STATUS_LABEL[f.status] || f.status)),
				React.createElement("span", null, "证据等级", React.createElement("b", null, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel)),
				React.createElement("span", null, "登记时间", React.createElement("b", null, fmtTime(f.createdAt))),
				f.verifiedAt ? React.createElement("span", null, "验证时间", React.createElement("b", null, fmtTime(f.verifiedAt))) : null),
			f.description ? Block({ title: meta.descLabel }, f.description) : null,
			f.poc ? Block({ title: meta.pocTitle }, f.poc) : null,
			f.summary ? Block({ title: "结论" }, f.summary) : null,
			f.chain ? Block({ title: meta.chainLabel }, f.chain) : null,
			f.evidence ? Block({ title: "证据引用" }, f.evidence) : null,
			f.fix ? Block({ title: "处置建议" }, f.fix) : null,
			f.verifyNote ? Block({ title: "复核注记" }, f.verifyNote) : null,
			React.createElement("div", { className: "dsh-rtr-rowactions" },
				React.createElement(Btn, { onClick: function () { props.onVerify(f); } }, "发送到会话复核"),
				React.createElement(Btn, { onClick: function () { props.onExportOne(f); } }, "导出节点卡（MD）")));
	}
	if (meta.archetype === "cloudpath") {
		var hop = function (label, value) {
			return React.createElement("div", { className: "dsh-rtr-cp-hop" },
				React.createElement("span", { className: "dsh-rtr-cp-hoplabel" }, label),
				React.createElement("span", { className: "dsh-rtr-cp-hopval" }, value || "（未填写）"));
		};
		return React.createElement("div", { className: "dsh-rtr-detail" },
			React.createElement("div", { className: "dsh-rtr-fields" },
				React.createElement("span", null, meta.kindLabel, React.createElement("b", null, f.type || "未分类")),
				React.createElement("span", null, meta.locLabel, React.createElement("b", { style: { fontFamily: "monospace" } }, f.resource || f.target || "未填写")),
				React.createElement("span", null, "严重度", React.createElement("b", null, SEVERITY_LABEL[f.severity] || f.severity)),
				React.createElement("span", null, "状态", React.createElement("b", null, CLOUDPATH_STATUS_LABEL[f.status] || f.status)),
				React.createElement("span", null, "证据等级", React.createElement("b", null, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel)),
				React.createElement("span", null, "登记时间", React.createElement("b", null, fmtTime(f.createdAt))),
				f.verifiedAt ? React.createElement("span", null, "验证时间", React.createElement("b", null, fmtTime(f.verifiedAt))) : null),
			(f.entry || f.identity || f.permission || f.resource) ? React.createElement("div", { className: "dsh-rtr-block" },
				React.createElement("h4", null, "攻击路径链（身份→权限→资源→影响）"),
				React.createElement("div", { className: "dsh-rtr-cp-chain" },
					hop("① 入口凭证/身份", f.entry),
					hop("② 利用身份", f.identity),
					hop("③ 权限", f.permission),
					hop("④ 目标资源", f.resource || f.target),
					React.createElement("div", { className: "dsh-rtr-cp-hop dsh-rtr-cp-impact" },
						React.createElement("span", { className: "dsh-rtr-cp-hoplabel" }, "⑤ 影响证明"),
						React.createElement("span", { className: "dsh-rtr-cp-hopval" }, f.impact || f.summary || "（未填写）")))) : null,
			f.description ? Block({ title: meta.descLabel }, f.description) : null,
			f.poc ? Block({ title: meta.pocTitle }, f.poc) : null,
			f.summary ? Block({ title: "结论" }, f.summary) : null,
			f.chain ? Block({ title: meta.chainLabel }, f.chain) : null,
			f.evidence ? Block({ title: "证据引用" }, f.evidence) : null,
			f.fix ? Block({ title: "修复建议" }, f.fix) : null,
			f.verifyNote ? Block({ title: "复核注记" }, f.verifyNote) : null,
			React.createElement("div", { className: "dsh-rtr-rowactions" },
				React.createElement(Btn, { onClick: function () { props.onVerify(f); } }, "发送到会话验证"),
				React.createElement(Btn, { onClick: function () { props.onExportOne(f); } }, "导出路径卡（MD）")));
	}
	return React.createElement("div", { className: "dsh-rtr-detail" },
		React.createElement("div", { className: "dsh-rtr-fields" },
			React.createElement("span", null, audit ? "主线类型" : binary ? "结论类型" : "类型", React.createElement("b", null, f.type || "未分类")),
			binary && f.family ? React.createElement("span", null, "家族", React.createElement("b", null, f.family)) : null,
			binary && f.packer ? React.createElement("span", null, "壳", React.createElement("b", null, f.packer)) : null,
			binary && f.sampleHash ? React.createElement("span", null, "SHA256", React.createElement("b", null, f.sampleHash.slice(0, 16) + "…")) : null,
			audit && f.cwe ? React.createElement("span", null, "CWE", React.createElement("b", null, f.cwe)) : null,
			!audit && f.cvss ? React.createElement("span", null, "CVSS", React.createElement("b", null, f.cvss.slice(0, 40))) : null,
			React.createElement("span", null, "证据等级", React.createElement("b", null, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel)),
			React.createElement("span", null, audit ? "sink 位置" : "地址", React.createElement("b", null, f.target || "未填写")),
			React.createElement("span", null, "发现时间", React.createElement("b", null, fmtTime(f.createdAt))),
			f.verifiedAt ? React.createElement("span", null, "验证时间", React.createElement("b", null, fmtTime(f.verifiedAt))) : null,
			audit ? React.createElement("span", null, "来源", React.createElement("b", null, SOURCE_LABEL[f.sourceOrigin] || f.sourceOrigin)) : null,
			audit && f.auditMode ? React.createElement("span", null, "审计形态", React.createElement("b", { style: f.auditMode === "dynamic" ? { color: "#2f9e63" } : null }, AUDIT_MODE_LABEL[f.auditMode] || f.auditMode)) : null),
		f.description ? Block({ title: binary ? "定性依据（结论摘要）" : "描述" }, f.description) : null,
		!audit && f.impact ? Block({ title: binary ? "能力与危害" : "影响证明" }, f.impact) : null,
		mode === "pentest" && (f.baseline || f.diffEvidence || f.markerEcho) ? React.createElement("div", { className: "dsh-rtr-duo" },
			React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 12, color: "#8a8a8f" } }, "对照三件套 · 基线"), React.createElement("pre", null, f.baseline || "（未填）")),
			React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 12, color: "#8a8a8f" } }, "差分（翻转）"), React.createElement("pre", null, f.diffEvidence || "（未填）"))) : null,
		mode === "pentest" && f.markerEcho ? Block({ title: "marker 逐字回显" }, f.markerEcho) : null,
		audit && (f.chain || f.chainTracer) ? React.createElement("div", { className: "dsh-rtr-block" },
			React.createElement("h4", null, "双链对照（entry → sink）"),
			React.createElement("div", { className: "dsh-rtr-duo" },
				React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 11, color: "#8a8a8f" } }, "审计工人链"), React.createElement("pre", null, f.chain || "（未填）")),
				React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 11, color: "#8a8a8f" } }, "追踪员链（独立重追）"), React.createElement("pre", null, f.chainTracer || "（未填）"))),
			f.chainVerdict ? React.createElement("div", { className: "dsh-rtr-verdict", style: { marginTop: 8 } }, "一致性结论：" + f.chainVerdict) : null) : null,
		!audit && f.chain ? Block({ title: binary ? "执行链 / 还原链路" : "调用链（entry → sink）" }, f.chain) : null,
		audit && (f.snippetEntry || f.snippetSink) ? React.createElement("div", { className: "dsh-rtr-block" },
			React.createElement("h4", null, "关键代码"),
			React.createElement("div", { className: "dsh-rtr-duo" },
				React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 11, color: "#8a8a8f" } }, "入口 entry"), React.createElement("pre", null, f.snippetEntry || "（未填）")),
				React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 11, color: "#8a8a8f" } }, "危险点 sink"), React.createElement("pre", null, f.snippetSink || "（未填）")))) : null,
		f.poc ? Block({ title: meta.pocTitle }, f.poc) : null,
		binary && f.iocs ? Block({ title: "IOC 清单" }, f.iocs) : null,
		binary && f.detectionRule ? Block({ title: "检测规则（YARA/Sigma）" }, f.detectionRule) : null,
		mode === "pentest" && f.requestPkt ? Block({ title: "完整请求包" }, f.requestPkt) : null,
		mode === "pentest" && f.responsePkt ? Block({ title: "关键响应" }, f.responsePkt) : null,
		f.evidence ? Block({ title: "证据引用" }, f.evidence) : null,
		f.fix ? Block({ title: binary ? "处置建议" : "修复建议" }, f.fix) : null,
		audit && f.patch ? Block({ title: "修复 diff 建议" }, f.patch) : null,
		f.verifyNote ? Block({ title: "复核注记" }, f.verifyNote) : null,
		mode === "pentest" && f.retestNote ? Block({ title: "复测记录" }, f.retestNote + (f.retestAt ? "（" + fmtTime(f.retestAt) + "）" : "")) : null,
		React.createElement("div", { className: "dsh-rtr-rowactions" },
			mode === "code-audit" ? React.createElement(Btn, { primary: true, onClick: function () { props.onLiveVerify ? props.onLiveVerify(f) : null; } }, "实测") : null,
			React.createElement(Btn, { onClick: function () { props.onVerify(f); } }, "发送到会话验证"),
			React.createElement(Btn, { onClick: function () { props.onExportOne(f); } }, "导出报告（MD）")));
}

function ModePage(props) {
	var mode = props.mode;
	var meta = MODE_META[mode] || MODE_META.pentest;
	var sessionId = props.sessionId;
	var stale = useRef(0);
	var data = useState({ rows: [], total: 0, page: 1, pages: 1, stats: null, counts: {}, meta: null, groups: null });
	var setData = data[1];
	var loading = useState(true); var setLoading = loading[1];
	var notice = useState(""); var setNotice = notice[1];
	var page = useState(1); var setPage = page[1];
	var severity = useState(""); var setSeverity = severity[1];
	var status = useState(""); var setStatus = status[1];
	var q = useState(""); var setQ = q[1];
	var grouped = useState(false); var setGrouped = grouped[1];
	var expanded = useState(""); var setExpanded = expanded[1];
	var selected = useState({}); var setSelected = selected[1];
	var confirmDel = useState(""); var setConfirmDel = confirmDel[1];
	var editingMeta = useState(false); var setEditingMeta = editingMeta[1];
	var range = useState("all"); var setRange = range[1];
	var customFrom = useState(""); var setCustomFrom = customFrom[1];
	var customTo = useState(""); var setCustomTo = customTo[1];
	var rt = rangeIso(range[0], customFrom[0], customTo[0]);
	var metaDraft = useState({ targetLabel: "", version: "", scope: "" }); var setMetaDraft = metaDraft[1];

	var fetchList = useCallback(function (opts) {
		var o = opts || {};
		var token = ++stale.current;
		setLoading(true);
		api("findings.list", {
			scope: "all", sessionId: sessionId, mode: mode,
			page: o.page !== undefined ? o.page : page[0], pageSize: 10,
			severity: o.severity !== undefined ? o.severity : severity[0],
			status: o.status !== undefined ? o.status : status[0],
			q: o.q !== undefined ? o.q : q[0],
			from: rangeIso(range[0], customFrom[0], customTo[0])[0], to: rangeIso(range[0], customFrom[0], customTo[0])[1]
		}).then(function (res) {
			if (token !== stale.current) return;
			var list = (res || {}).list || {};
			setData({
				rows: list.rows || [], total: list.total || 0, page: list.page || 1, pages: list.pages || 1,
				stats: res.stats, counts: res.counts || {}, meta: res.meta, groups: null
			});
			if ((o.page || page[0]) > (list.pages || 1)) setPage(list.pages || 1);
		}).catch(function (e) {
			if (token === stale.current) setNotice("读取失败：" + (e && e.message ? e.message : e));
		}).finally(function () {
			if (token === stale.current) setLoading(false);
		});
	}, [sessionId, mode, page[0], severity[0], status[0], q[0], range[0], customFrom[0], customTo[0]]);

	var fetchGroups = useCallback(function () {
		var token = ++stale.current;
		setLoading(true);
		api("findings.groups", { scope: "all", sessionId: sessionId, mode: mode, severity: severity[0], status: status[0], q: q[0], from: rangeIso(range[0], customFrom[0], customTo[0])[0], to: rangeIso(range[0], customFrom[0], customTo[0])[1] })
			.then(function (res) {
				if (token !== stale.current) return;
				var groups = (res || {}).groups || [];
				setData({
					rows: [], total: groups.reduce(function (n, g) { return n + g.count; }, 0), page: 1, pages: 1,
					stats: null, counts: {}, meta: null, groups: groups
				});
			})
			.catch(function (e) { if (token === stale.current) setNotice("分组读取失败：" + (e && e.message ? e.message : e)); })
			.finally(function () { if (token === stale.current) setLoading(false); });
	}, [sessionId, mode, severity[0], status[0], q[0], range[0], customFrom[0], customTo[0]]);

	useEffect(function () {
		setPage(1); setExpanded(""); setSelected({}); setConfirmDel("");
		if (grouped[0]) fetchGroups(); else fetchList({ page: 1 });
	}, [sessionId, mode, severity[0], status[0], q[0], grouped[0], range[0], customFrom[0], customTo[0]]);

	useEffect(function () {
		if (!notice) return;
		var t = setTimeout(function () { setNotice(""); }, 4000);
		return function () { clearTimeout(t); };
	}, [notice]);

	var view = data[0] || {};
	var rows = view.rows || [];
	var stats = view.stats || { total: view.total || 0, bySeverity: {}, byStatus: {}, byType: [], byCwe: [], bySource: [], byTarget: [] };
	var sesMeta = view.meta || { targetLabel: "", version: "", scope: "" };
	var selectedIds = Object.keys(selected[0]).filter(function (k) { return selected[0][k]; });

	function toggle(f) { setConfirmDel(""); setExpanded(expanded[0] === f.id ? "" : f.id); }
	function onVerify(f) {
		api("finding.verify", { sessionId: f.sessionId || sessionId, mode: mode, id: f.id })
			.then(function (r) {
				if (r && r.ok) { setNotice("验证请求已发送到原会话（# " + f.seq + " " + f.title + "），复核后状态由会话回写"); return; }
				if (r && r.unreachable) {
					// 原会话已删/不可达：人工复核兜底——用户确认后直接回写状态与注记
					var ok = window.confirm(r.error + "\n\n是否人工复核后直接标记？\n确定=标记「已验证」，取消=改标「已失效」，关闭对话框=不做标记");
					if (!ok && !window.confirm("标记为「已失效（误报）」？")) { setNotice("已取消标记——成果保持原状态"); return; }
					var status = ok ? "verified" : "false-positive";
					var note = window.prompt("人工复核结论（写入验证记录）：", "原会话不可达，人工复核" + (ok ? "通过" : "判伪")) || "";
					api("finding.mark", { sessionId: f.sessionId || sessionId, id: f.id, status: status, verifyNote: note })
						.then(function (m) { setNotice(m && m.ok ? "已人工标记 #" + f.seq + " → " + (status === "verified" ? "已验证" : "已失效") : "标记失败：" + ((m && m.error) || "未知")); if (grouped[0]) fetchGroups(); else fetchList({}); })
						.catch(function (e) { setNotice("标记失败：" + (e && e.message ? e.message : e)); });
					return;
				}
				setNotice("验证请求失败：" + ((r && r.error) || "未知错误"));
			})
			.catch(function (e) { setNotice("验证请求失败：" + (e && e.message ? e.message : e)); });
	}
	function onLiveVerify(f) {
		// 一键实测：调 dsh-hunter 验证流水线（L0 指纹判定/L1 仅授权资产），结果回写 finding。
		if (mode !== "code-audit") { setNotice("实测仅支持代码审计模式 finding"); return; }
		setNotice("实测进行中：搜索资产 → 存活探测 → 指纹校验 →" + (f.auditMode === "dynamic" ? "影响面评估…" : "EXP 验证（L1 仅授权资产）…"));
		csrfOf("/dsh-hunter").then(function (hTok) {
			return fetch("/dsh-hunter/verify.live", {
				method: "POST",
				headers: hTok ? { "content-type": "application/json", "x-dsh-csrf": hTok } : { "content-type": "application/json" },
				body: JSON.stringify({ sessionId: f.sessionId || sessionId, findingId: f.id, allMode: false })
			});
		}).then(function (r) { return r.json(); }).then(function (r) {
			if (r && r.ok) {
				setNotice("实测完成（#" + f.seq + "）：" + r.summary
					+ (r.suggestions && r.suggestions.length ? "｜下一步：" + r.suggestions.join("；") : "")
					+ (r.notified ? "" : "（原会话不可达，未注入通知）"));
				if (grouped[0]) fetchGroups(); else fetchList({});
				return;
			}
			setNotice("实测失败：" + ((r && r.error) || "未知错误"));
		}).catch(function (e) { setNotice("实测失败：" + (e && e.message ? e.message : e)); });
	}
	function onDelete(f) {
		if (confirmDel[0] !== f.id) { setConfirmDel(f.id); return; }
		api("finding.delete", { sessionId: f.sessionId || sessionId, id: f.id })
			.then(function () { setConfirmDel(""); setNotice("已删除 #" + f.seq + "（统计已同步）"); if (grouped[0]) fetchGroups(); else fetchList({}); })
			.catch(function (e) { setNotice("删除失败：" + (e && e.message ? e.message : e)); });
	}
	function fetchAllForExport() {
		var rtx = rangeIso(range[0], customFrom[0], customTo[0]);
		return api("findings.list", { scope: "all", sessionId: sessionId, mode: mode, page: 1, pageSize: 100, severity: severity[0], status: status[0], q: q[0], from: rtx[0], to: rtx[1] })
			.then(function (raw) { return (((raw || {}).list || {}).rows) || []; });
	}
	function exportAll() {
		fetchAllForExport().then(function (all) {
			download(meta.allName + localDate() + ".md", mdTable(all, meta.tableTitle, mode));
			setNotice("已导出 " + all.length + " 条（当前筛选范围）");
		});
	}
	function exportSelected() {
		var picked = rows.filter(function (f) { return selected[0][f.id]; });
		if (picked.length === 0) { setNotice("先勾选要导出的成果"); return; }
		var text = picked.map(function (f) { return mdReport(f, mode); }).join("\n---\n\n");
		download(meta.reportName + localDate() + ".md", text);
		setNotice("已导出 " + picked.length + " 份报告（MD）");
	}
	function exportOne(f) {
		download("finding-" + mode + "-" + f.seq + "-" + localDate() + ".md", mdReport(f, mode));
	}
	function exportOverview() {
		fetchAllForExport().then(function (all) {
			download((mode === "code-audit" ? "audit" : "pentest") + "-overview-" + localDate() + ".md", mdOverview(sesMeta, stats, all, mode));
			setNotice("总览报告已导出（MD）");
		});
	}
	function exportHtml() {
		fetchAllForExport().then(function (all) {
			download((mode === "code-audit" ? "audit" : "pentest") + "-report-" + localDate() + ".html", htmlReport(sesMeta, stats, all, mode), "text/html");
			setNotice("报告包已导出（HTML，可浏览器打印成 PDF）");
		});
	}
	function saveMeta() {
		api("meta.set", { sessionId: sessionId, targetLabel: metaDraft[0].targetLabel, version: metaDraft[0].version, scope: metaDraft[0].scope })
			.then(function () { setEditingMeta(false); setNotice("任务元数据已保存"); if (grouped[0]) fetchGroups(); else fetchList({}); })
			.catch(function (e) { setNotice("保存失败：" + (e && e.message ? e.message : e)); });
	}

	var rowEl = function (f) {
		var meta2 = meta;
		var stLabelSet = statusLabelSetFor(meta2.archetype, mode);
		return React.createElement("div", { key: f.id, className: "dsh-rtr-row" },
			React.createElement("div", { className: "dsh-rtr-rowhead", onClick: function () { toggle(f); } },
				React.createElement("input", {
					type: "checkbox", className: "dsh-rtr-check", checked: !!selected[0][f.id],
					onClick: function (e) { e.stopPropagation(); },
					onChange: function (e) { var next = Object.assign({}, selected[0]); next[f.id] = e.target.checked; setSelected(next); }
				}),
				React.createElement("span", { className: "dsh-rtr-seq" }, "#" + f.seq),
				React.createElement(Chip, { severity: f.severity, typeLabel: LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : null }),
				React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + f.status }, statusTextFor(f, mode, stLabelSet)),
				mode === "code-audit" && f.auditMode ? React.createElement("span", { className: "dsh-rtr-am dsh-rtr-am-" + f.auditMode }, AUDIT_MODE_LABEL[f.auditMode] || f.auditMode) : null,
				React.createElement("span", { className: "dsh-rtr-title" }, f.title),
				React.createElement("span", { className: "dsh-rtr-summ" }, f.summary || ""),
				React.createElement("span", { className: "dsh-rtr-time" }, fmtTime(f.updatedAt)),
				React.createElement("span", { className: "dsh-rtr-rowactions", onClick: function (e) { e.stopPropagation(); } },
					mode === "code-audit" ? React.createElement(Btn, { primary: true, onClick: function () { onLiveVerify(f); } }, "实测") : null,
					React.createElement(Btn, { onClick: function () { onVerify(f); } }, "验证"),
					React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === f.id ? "确认删除" : "删除"))),
			expanded[0] === f.id ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onLiveVerify: onLiveVerify, onExportOne: exportOne }) : null);
	};

	var tlItem = function (f) {
		var stSet = statusLabelSetFor(meta.archetype, mode);
		var open = expanded[0] === f.id;
		return React.createElement("div", { key: f.id, className: "dsh-rtr-tl-item" },
			React.createElement("div", { className: "dsh-rtr-tl-rail" },
				React.createElement("span", { className: "dsh-rtr-tl-dot" }),
				React.createElement("span", { className: "dsh-rtr-tl-line" })),
			React.createElement("div", { className: "dsh-rtr-tl-body" },
				React.createElement("div", { className: "dsh-rtr-tl-time" }, fmtTimelineAt(f.timelineAt)),
				React.createElement("div", { className: "dsh-rtr-tl-card" },
					React.createElement("div", { className: "dsh-rtr-rowhead", onClick: function () { toggle(f); } },
						React.createElement("input", {
							type: "checkbox", className: "dsh-rtr-check", checked: !!selected[0][f.id],
							onClick: function (e) { e.stopPropagation(); },
							onChange: function (e) { var next = Object.assign({}, selected[0]); next[f.id] = e.target.checked; setSelected(next); }
						}),
						React.createElement("span", { className: "dsh-rtr-seq" }, "#" + f.seq),
						React.createElement("span", { className: "dsh-rtr-typechip is-static" }, f.type || "未分类"),
						React.createElement(Chip, { severity: f.severity, typeLabel: LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : null }),
						React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + f.status }, stSet[f.status] || f.status),
						React.createElement("span", { className: "dsh-rtr-title" }, f.title),
						React.createElement("span", { className: "dsh-rtr-rowactions", onClick: function (e) { e.stopPropagation(); } },
							React.createElement(Btn, { onClick: function () { onVerify(f); } }, "验证"),
							React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === f.id ? "确认删除" : "删除"))),
					React.createElement("div", { className: "dsh-rtr-tl-meta", onClick: function () { toggle(f); } },
						React.createElement("span", null, "主机 ", React.createElement("b", null, f.target || "（未填）")),
						React.createElement("span", null, "证据 ", React.createElement("b", null, f.evidence || "（未填）")),
						React.createElement("span", { className: "dsh-rtr-tl-concl" }, f.summary || "")),
					open ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onLiveVerify: onLiveVerify, onExportOne: exportOne }) : null)));
	};

	var cpItem = function (f) {
		var stSet = statusLabelSetFor(meta.archetype, mode);
		var open = expanded[0] === f.id;
		var hop = function (label, value) {
			return React.createElement("span", { className: "dsh-rtr-cp-hop", title: value || "" },
				React.createElement("i", null, label),
				React.createElement("b", null, (value || "（未填）").slice(0, 120)));
		};
		return React.createElement("div", { key: f.id, className: "dsh-rtr-cp-item" },
			React.createElement("div", { className: "dsh-rtr-cp-card" },
				React.createElement("div", { className: "dsh-rtr-rowhead", onClick: function () { toggle(f); } },
					React.createElement("input", {
						type: "checkbox", className: "dsh-rtr-check", checked: !!selected[0][f.id],
						onClick: function (e) { e.stopPropagation(); },
						onChange: function (e) { var next = Object.assign({}, selected[0]); next[f.id] = e.target.checked; setSelected(next); }
					}),
					React.createElement("span", { className: "dsh-rtr-seq" }, "#" + f.seq),
					React.createElement("span", { className: "dsh-rtr-typechip is-static" }, f.type || "未分类"),
					React.createElement(Chip, { severity: f.severity, typeLabel: LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : null }),
					React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + f.status }, stSet[f.status] || f.status),
					React.createElement("span", { className: "dsh-rtr-title" }, f.title),
					React.createElement("span", { className: "dsh-rtr-rowactions", onClick: function (e) { e.stopPropagation(); } },
						React.createElement(Btn, { onClick: function () { onVerify(f); } }, "验证"),
						React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === f.id ? "确认删除" : "删除"))),
				React.createElement("div", { className: "dsh-rtr-cp-chain", onClick: function () { toggle(f); } },
					hop("入口", f.entry),
					hop("身份", f.identity),
					hop("权限", f.permission),
					hop("资源", f.resource || f.target),
					hop("影响", f.impact || f.summary)),
				open ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onLiveVerify: onLiveVerify, onExportOne: exportOne }) : null));
	};

	var listBody;
	if (loading[0]) {
		listBody = React.createElement("div", { className: "dsh-rtr-skel" }, "读取成果数据…");
	} else if (meta.archetype === "cloudpath") {
		var cpRows = rows.slice().sort(function (a, b) { return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity); });
		listBody = cpRows.length === 0
			? React.createElement("div", { className: "dsh-rtr-empty" },
				meta.empty, React.createElement("br", null),
				rangeHint(range[0]), React.createElement("br", null),
				"会话内模型会把攻击路径通过 redteam_finding_register 登记到这里（也可让模型补登记：\"把攻击路径登记到成果页\"）。")
			: React.createElement("div", { className: "dsh-rtr-cp" }, cpRows.map(cpItem));
	} else if (meta.archetype === "timeline") {
		var chronoRows = rows.slice().sort(cmpTimeline);
		listBody = chronoRows.length === 0
			? React.createElement("div", { className: "dsh-rtr-empty" },
				meta.empty, React.createElement("br", null),
				rangeHint(range[0]), React.createElement("br", null),
				"会话内模型会把攻击链节点通过 redteam_finding_register 登记到这里（也可让模型补登记：\"把攻击链节点登记到成果页\"）。")
			: React.createElement("div", { className: "dsh-rtr-tl" }, chronoRows.map(tlItem));
	} else if (grouped[0]) {
		var groups = view.groups || [];
		listBody = groups.length === 0
			? React.createElement("div", { className: "dsh-rtr-empty" }, meta.empty, React.createElement("br", null), rangeHint(range[0]))
			: groups.map(function (g) {
				return React.createElement("div", { key: g.target },
					React.createElement("div", { className: "dsh-rtr-grouphead" }, g.target, React.createElement("span", { className: "dsh-rtr-count" }, g.count + " 项")),
					g.items.map(rowEl));
			});
	} else {
		listBody = rows.length === 0
			? React.createElement("div", { className: "dsh-rtr-empty" },
				meta.empty, React.createElement("br", null),
				"会话内模型会把进入报告的 finding 通过 redteam_finding_register 登记到这里（也可让模型补登记：\"把已发现的成果登记到成果页\"）。")
			: rows.map(rowEl);
	}

	return React.createElement(React.Fragment, null,
		notice ? React.createElement("div", { className: "dsh-rtr-notice" }, notice) : null,
		React.createElement(MetaBar, {
			meta: sesMeta, labels: meta.metaLabels, editing: editingMeta[0], draft: metaDraft[0],
			onEdit: function () { setMetaDraft({ targetLabel: sesMeta.targetLabel, version: sesMeta.version, scope: sesMeta.scope }); setEditingMeta(true); },
			onDraft: function (k, v) { var next = Object.assign({}, metaDraft[0]); next[k] = v; setMetaDraft(next); },
			onSave: saveMeta, onCancel: function () { setEditingMeta(false); }
		}),
		React.createElement(StatsPanel, {
			stats: stats, mode: mode, archetype: meta.archetype, typeLabel: meta.typeLabel,
			severityFilter: severity[0], statusFilter: status[0],
			onSeverity: function (s) { setSeverity(s); },
			onStatus: function (s) { setStatus(s); },
			onTarget: function (t) { setQ(t); }
		}),
		React.createElement("div", { className: "dsh-rtr-toolbar" },
			React.createElement(RangePicker, { range: range[0], customFrom: customFrom[0], customTo: customTo[0], onChange: function (sel, cf, ct) { setRange(sel); setCustomFrom(cf); setCustomTo(ct); } }),
			meta.archetype !== "assets" && mode !== "av-evasion" && mode !== "ctf-solver" && mode !== "binary-analysis" ? React.createElement("select", { className: "dsh-rtr-select", value: severity[0], onChange: function (e) { setSeverity(e.target.value); } },
				React.createElement("option", { value: "" }, meta.archetype === "ledger" ? "全部优先级" : "全部等级"),
				SEVERITY_ORDER.map(function (s) { return React.createElement("option", { key: s, value: s }, SEVERITY_LABEL[s]); })) : null,
			React.createElement("select", { className: "dsh-rtr-select", value: status[0], onChange: function (e) { setStatus(e.target.value); } },
				React.createElement("option", { value: "" }, "全部状态"),
				(STATUS_OPTIONS_OF[mode] || Object.keys(STATUS_LABEL)).map(function (s) { return React.createElement("option", { key: s, value: s }, statusLabelSetFor(meta.archetype, mode)[s] || STATUS_LABEL[s] || s); })),
			React.createElement("input", { className: "dsh-rtr-search", placeholder: "搜索名称/简介/地址/CWE", value: q[0], onChange: function (e) { setQ(e.target.value); } }),
			meta.archetype !== "timeline" ? React.createElement(Btn, { onClick: function () { setGrouped(!grouped[0]); } }, grouped[0] ? "平铺视图" : meta.groupLabel) : null,
			React.createElement("span", { className: "dsh-rtr-spacer" }),
			React.createElement(Btn, { onClick: exportOverview }, "导出总览（MD）"),
			React.createElement(Btn, { onClick: exportHtml }, "导出报告包（HTML）"),
			React.createElement(Btn, { onClick: exportAll }, meta.archetype === "assets" ? "导出清单（表格）" : "导出全部（表格）"),
			React.createElement(Btn, { primary: true, disabled: selectedIds.length === 0, onClick: exportSelected }, selectedIds.length > 0 ? (meta.archetype === "assets" ? "导出选中卡片（" : "导出选中报告（") + selectedIds.length + "）" : (meta.archetype === "assets" ? "导出选中卡片" : "导出选中报告"))),
		listBody,
		!grouped[0] && (view.pages > 1 || view.total > 10) ? React.createElement("div", { className: "dsh-rtr-pager" },
			React.createElement(Btn, { disabled: view.page <= 1, onClick: function () { setPage(view.page - 1); fetchList({ page: view.page - 1 }); } }, "上一页"),
			"第 " + view.page + " / " + view.pages + " 页 · 共 " + view.total + " 条",
			React.createElement(Btn, { disabled: view.page >= view.pages, onClick: function () { setPage(view.page + 1); fetchList({ page: view.page + 1 }); } }, "下一页")) : null);
}


//#region 任务台账大屏（跨会话作战视图：聚合九模式数据）

var SCR_MODE_LABEL = { redteam: "研究员·台账", pentest: "渗透测试", "code-audit": "代码审计", "binary-analysis": "二进制分析", "attack-defense": "攻防评估", "av-evasion": "免杀对抗", "incident-response": "应急溯源", "cloud-security": "云安全", "ctf-solver": "CTF 解题" };
var SCR_MODE_VOCAB = ["redteam", "attack-defense", "pentest", "code-audit", "av-evasion", "incident-response", "binary-analysis", "cloud-security", "ctf-solver"];

function BigScreen(props) {
	var data = useState(null); var setData = data[1];
	var clock = useState(""); var setClock = clock[1];
	var range = useState("today"); var setRange = range[1];
	var customFrom = useState(""); var setCustomFrom = customFrom[1];
	var customTo = useState(""); var setCustomTo = customTo[1];
	var scrPg = useState(0); var setScrPg = scrPg[1];
	var scrRef = useRef(null);
	var fsOn = useState(false); var setFsOn = fsOn[1];

	var load = useCallback(function () {
		var rt = rangeIso(range[0], customFrom[0], customTo[0]);
		api("ledger.overview", { scope: "all", from: rt[0], to: rt[1] })
			.then(function (res) { setData((res || {}).overview || null); })
			.catch(function () { setData(null); });
	}, [range[0], customFrom[0], customTo[0]]);
	useEffect(function () {
		load();
		var t1 = setInterval(load, 15000);
		var t2 = setInterval(function () {
			var d = new Date();
			setClock(d.toLocaleTimeString("zh-CN", { hour12: false }));
		}, 1000);
		return function () { clearInterval(t1); clearInterval(t2); };
	}, [load]);
	useEffect(function () {
		var sync = function () { setFsOn(document.fullscreenElement === scrRef.current); };
		document.addEventListener("fullscreenchange", sync);
		sync();
		return function () { document.removeEventListener("fullscreenchange", sync); };
	}, []);
	var toggleFs = function () {
		var el = scrRef.current;
		if (!el || !el.requestFullscreen) return;
		if (document.fullscreenElement === el) {
			var p = document.exitFullscreen(); if (p && p.catch) p.catch(function () {});
		} else {
			var q = el.requestFullscreen(); if (q && q.catch) q.catch(function () {});
		}
	};

	var ov = data[0];
	if (ov === null) {
		return React.createElement("div", { className: "dsh-rtr-screen", ref: scrRef },
			React.createElement("div", { className: "dsh-scr-inner" },
				React.createElement("div", { className: "dsh-scr-empty" }, "正在接入全局数据…")));
	}
	var numCard = function (v, label, cls) { return React.createElement("div", { className: "dsh-scr-num " + (cls || "") }, React.createElement("b", null, v), React.createElement("span", null, label)); };
	var total = ov.total || 0;
	var maxMode = Math.max(1, ...SCR_MODE_VOCAB.map(function (m) { return (ov.byMode[m] || 0); }));
	var sevOrder = ["critical", "high", "medium", "low"];
	var sevColors = { critical: "#c2182f", high: "#ff4d4d", medium: "#ffdd33", low: "#3a9dff" };
	var sevTotal = sevOrder.reduce(function (n, s) { return n + (ov.bySeverity[s] || 0); }, 0) || 1;
	var sevMax = Math.max.apply(null, sevOrder.map(function (s) { return ov.bySeverity[s] || 0; })) || 1;
	var acc = 0;
	var donutStops = sevOrder.map(function (s) {
		var from = acc / sevTotal * 100;
		acc += ov.bySeverity[s] || 0;
		return sevColors[s] + " " + from.toFixed(1) + "% " + (acc / sevTotal * 100).toFixed(1) + "%";
	}).join(",");
	var stRows = ov.recent || [];
	var PG_SIZE = 12;
	var pgMax = Math.max(0, Math.ceil(stRows.length / PG_SIZE) - 1);
	var pgCur = Math.min(scrPg[0], pgMax);
	var pgRows = stRows.slice(pgCur * PG_SIZE, pgCur * PG_SIZE + PG_SIZE);
	var modeOf = function (m) { return SCR_MODE_LABEL[m] || m; };
	var satSpecs = [
		{ key: "verified", color: "#36f1b0", r: 150, dur: 16, size: 10, spin: 10 },
		{ key: "pending", color: "#ffc93c", r: 172, dur: 22, size: 12, spin: 12 },
		{ key: "risk", color: "#ff6b8a", r: 194, dur: 28, size: 14, spin: 14 }
	];
	var orbitParts = [];
	satSpecs.forEach(function (t, ti) {
		var n = Math.min(6, t.key === "risk" ? (ov.bySeverity.critical || 0) + (ov.bySeverity.high || 0) : (ov.byStatus[t.key] || 0));
		orbitParts.push(React.createElement("div", { key: "track-" + t.key, className: "dsh-scr-orbittrack", style: { "--r": t.r + "px" } }));
		for (var i = 0; i < n; i++) {
			orbitParts.push(React.createElement("div", {
				key: t.key + "-" + i, className: "dsh-scr-orbiter",
				style: { "--r": t.r + "px", color: t.color, animationDuration: t.dur + "s", animationDelay: (-(i / n) * t.dur - ti * 3).toFixed(2) + "s" }
			}, React.createElement("div", { className: "dsh-scr-planet", style: { width: t.size + "px", height: t.size + "px", margin: (t.size / -2) + "px 0 0 " + (t.size / -2) + "px", animationDuration: t.spin + "s" } })));
		}
	});
	var orbitStage = React.createElement("div", { className: "dsh-scr-orbitstage" }, orbitParts);
	var starPos = [[-30, 20, 3], [240, 60, 2], [-15, 150, 4], [215, 175, 3], [40, -30, 1.5], [160, -25, 4], [230, 110, 2]];
	var stars = starPos.map(function (s, i) {
		return React.createElement("div", { key: "star-" + i, className: "dsh-scr-star", style: { left: s[0] + "px", top: s[1] + "px", animationDuration: s[2] + "s" } });
	});
	return React.createElement("div", { className: "dsh-rtr-screen", ref: scrRef },
		React.createElement("div", { className: "dsh-scr-inner" },
			React.createElement("div", { className: "dsh-scr-header" },
				React.createElement("div", { className: "dsh-scr-hleft" },
					React.createElement(Btn, { onClick: toggleFs }, fsOn[0] ? "退出全屏" : "全屏"),
					React.createElement("div", { className: "dsh-scr-live" }, React.createElement("span", { className: "dsh-scr-dot" }), "LIVE · 跨会话全局")),
				React.createElement("div", { className: "dsh-scr-title" }, "REDTEAM 任务台账作战大屏", React.createElement("small", null, "GLOBAL LEDGER · 九模式跨会话聚合")),
				React.createElement("div", { className: "dsh-scr-clockwrap" },
					React.createElement("select", { className: "dsh-scr-range", value: range[0], onChange: function (e) { setRange(e.target.value); setScrPg(0); } },
						[["today", "今日"], ["3d", "近3天"], ["7d", "近7天"], ["30d", "近30天"], ["all", "全部"], ["custom", "自定义"]].map(function (r) { return React.createElement("option", { key: r[0], value: r[0] }, r[1]); })),
					range[0] === "custom" ? React.createElement("input", { type: "date", className: "dsh-scr-date", value: customFrom[0], onChange: function (e) { setCustomFrom(e.target.value); setScrPg(0); } }) : null,
					range[0] === "custom" ? React.createElement("input", { type: "date", className: "dsh-scr-date", value: customTo[0], onChange: function (e) { setCustomTo(e.target.value); setScrPg(0); } }) : null,
					React.createElement("span", { className: "dsh-scr-clock" }, clock[0] || "--:--:--"))),
			React.createElement("div", { className: "dsh-scr-hero" },
				React.createElement("div", { className: "dsh-scr-heronums" },
					numCard(total, "成果总数"),
					numCard(ov.byStatus.verified || 0, "已验证·有效", "is-good")),
					React.createElement("div", { className: "dsh-scr-globewrap" },
						stars,
						React.createElement("div", { className: "dsh-scr-globe" },
							React.createElement("div", { className: "dsh-scr-grat" }),
							React.createElement("div", { className: "dsh-scr-sweep" })),
						orbitStage,
						React.createElement("div", { className: "dsh-scr-herotag" }, "GLOBAL OPS · " + (ov.sessions || 0) + " 会话")),
				React.createElement("div", { className: "dsh-scr-heronums" },
					numCard(ov.byStatus.pending || 0, "进行中·待验证", "is-warn"),
					numCard((ov.bySeverity.critical || 0) + (ov.bySeverity.high || 0), "严重+高危", "is-bad"))),
			React.createElement("div", { className: "dsh-scr-grid" },
				React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 14 } },
					React.createElement("div", { className: "dsh-scr-panel" },
						React.createElement("h4", null, "模式成果分布"),
						SCR_MODE_VOCAB.map(function (m, i) {
							return React.createElement("div", { key: m, className: "dsh-scr-bar" },
								React.createElement("span", { className: "lbl" }, modeOf(m).slice(0, 6)),
								React.createElement("span", { className: "track" }, React.createElement("span", { className: "dsh-fill " + (i % 2 ? "is-alt" : ""), style: { display: "block", width: ((ov.byMode[m] || 0) / maxMode * 100) + "%", height: "100%", borderRadius: 4, background: (i === 2 || i === 3 || i === 4) ? "#ffc93c" : "#3a9dff", boxShadow: (i === 2 || i === 3 || i === 4) ? "0 0 6px rgba(255,201,60,.55)" : "0 0 6px rgba(58,157,255,.55)" } })),
								React.createElement("span", { className: "val" }, ov.byMode[m] || 0));
						})),
					React.createElement("div", { className: "dsh-scr-panel" },
						React.createElement("h4", null, "状态分布"),
						["pending", "verified", "false-positive", "fixed"].map(function (s, i) {
							var names = { pending: "待验证·进行中", verified: "已验证·有效", "false-positive": "证伪·失效", fixed: "已交付·路由" };
							return React.createElement("div", { key: s, className: "dsh-scr-bar" },
								React.createElement("span", { className: "lbl" }, names[s].slice(0, 7)),
								React.createElement("span", { className: "track" }, React.createElement("span", { style: { display: "block", width: ((ov.byStatus[s] || 0) / Math.max(1, total) * 100) + "%", height: "100%", borderRadius: 4, background: i === 1 ? "#36f1b0" : i === 2 ? "#8fb4d9" : i === 3 ? "#3a9dff" : "#ffc93c" } })),
								React.createElement("span", { className: "val" }, ov.byStatus[s] || 0));
						}))),
				React.createElement("div", { className: "dsh-scr-center" },
					React.createElement("div", { className: "dsh-scr-panel", style: { flex: 1 } },
						React.createElement("h4", null, "任务流水 · 最新登记"),
						stRows.length === 0
							? React.createElement("div", { className: "dsh-scr-empty" }, "该时间范围内暂无登记数据")
							: React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 8, minHeight: 0, flex: 1 } },
								React.createElement("div", { className: "dsh-scr-tablewrap", style: { flex: 1, minHeight: 0 } }, React.createElement("table", { className: "dsh-scr-table" },
									React.createElement("thead", null, React.createElement("tr", null, React.createElement("th", null, "时间"), React.createElement("th", null, "模式"), React.createElement("th", null, "名称"), React.createElement("th", null, "类型"), React.createElement("th", null, "会话"), React.createElement("th", null, "状态"))),
									React.createElement("tbody", null, pgRows.map(function (f) {
										return React.createElement("tr", { key: f.sessionId + "-" + f.mode + "-" + f.id },
											React.createElement("td", null, fmtTime(f.updatedAt).slice(5)),
											React.createElement("td", null, modeOf(f.mode)),
											React.createElement("td", null, f.title),
											React.createElement("td", null, f.type || "-"),
											React.createElement("td", { title: f.sessionId }, f.sessionId ? String(f.sessionId).replace(/^session-/, "").slice(0, 8) : "-"),
											React.createElement("td", null, LABEL_BY_TYPE_MODES[f.mode] ? React.createElement("span", { className: "dsh-scr-sev" }, f.type || "未标注") : React.createElement("span", { className: "dsh-scr-sev dsh-scr-sev-" + f.severity }, SEVERITY_LABEL[f.severity] || f.severity)));
									}))),
								pgMax > 0 ? React.createElement("div", { className: "dsh-rtr-pager", style: { justifyContent: "center" } },
									React.createElement(Btn, { disabled: pgCur <= 0, onClick: function () { setScrPg(pgCur - 1); } }, "上一页"),
									"第 " + (pgCur + 1) + " / " + (pgMax + 1) + " 页 · 共 " + stRows.length + " 条",
									React.createElement(Btn, { disabled: pgCur >= pgMax, onClick: function () { setScrPg(pgCur + 1); } }, "下一页")) : null)))), 
				React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 14 } },
					React.createElement("div", { className: "dsh-scr-panel" },
						React.createElement("h4", null, "风险等级占比"),
						React.createElement("div", { className: "dsh-scr-b3d" },
							React.createElement("div", { className: "dsh-scr-b3stage" },
								React.createElement("div", { className: "dsh-scr-b3floor" }),
								sevOrder.map(function (s, si) {
									var v = Math.max(0.04, (ov.bySeverity[s] || 0) / sevMax);
									return React.createElement("div", { key: "b3-" + s, className: "dsh-scr-b3slot", style: { "--x": (si * 3.2 - 4.8) + "em", color: sevColors[s], "--v": v.toFixed(3) } },
										React.createElement("div", { className: "dsh-scr-b3bar" },
											React.createElement("i"), React.createElement("i"), React.createElement("i"), React.createElement("i")),
										React.createElement("div", { className: "dsh-scr-b3num" }, String(ov.bySeverity[s] || 0)));
								}))),
						React.createElement("div", { className: "dsh-scr-legend" }, sevOrder.map(function (s) {
							return React.createElement("span", { key: s }, React.createElement("i", { style: { background: sevColors[s] } }), SEVERITY_LABEL[s] + " " + (ov.bySeverity[s] || 0));
						}))),
					React.createElement("div", { className: "dsh-scr-panel", style: { flex: 1 } },
						React.createElement("h4", null, "证据等级分布"),
						["confirmed", "partial", "unknown"].map(function (e, i) {
							var names = { confirmed: "已证实", partial: "部分证据", unknown: "未知" };
							var v = ov.byEvidence[e] || 0;
							return React.createElement("div", { key: e, className: "dsh-scr-bar" },
								React.createElement("span", { className: "lbl" }, names[e]),
								React.createElement("span", { className: "track" }, React.createElement("span", { style: { display: "block", width: (v / Math.max(1, total) * 100) + "%", height: "100%", borderRadius: 4, background: i === 0 ? "#36f1b0" : i === 1 ? "#ffc93c" : "#8fb4d9" } })),
								React.createElement("span", { className: "val" }, v));
						}))))));
}

function ComingSoon(props) {
	return React.createElement("div", { className: "dsh-rtr-empty" },
		React.createElement("b", null, props.label + "成果视图将在下一迭代提供"), React.createElement("br", null),
		"当前该模式会话内登记的数据已按「会话 × 模式」隔离保存，不会丢失；",
		React.createElement("br", null),
		"可先在会话中使用 redteam_finding_register 登记成果。");
}

function ResultsView(props) {
	var sessionId = props.sessionId != null ? String(props.sessionId) : "";
	var mode = useState(props.defaultMode || "__ledger__"); var setMode = mode[1];
	var counts = useState({}); var setCounts = counts[1];

	useEffect(function () {
		if (!sessionId) return;
		api("counts.all", {})
			.then(function (raw) { setCounts(((raw || {}).counts) || {}); })
			.catch(function () {});
	}, [sessionId]);

	if (!sessionId) {
		return React.createElement("div", { className: "dsh-rtr-skel" }, "等待会话上下文…（新建会话后本页自动绑定该会话的成果数据）");
	}
	return React.createElement("div", { className: "dsh-rtr-root" },
		React.createElement("aside", { className: "dsh-rtr-side" },
			React.createElement("div", { className: "dsh-rtr-side-title" }, "REDTEAM 成果"),
			React.createElement("button", {
				key: "__ledger__", type: "button",
				className: "dsh-rtr-side-item" + (mode[0] === "__ledger__" ? " is-active" : ""),
				style: { borderColor: "var(--dsw-alias-state-business-primary,#4c6ef5)", marginBottom: 6 },
				onClick: function () { setMode("__ledger__"); }
			}, "任务台账视图", React.createElement("span", { className: "dsh-rtr-count" }, Object.values(counts[0] || {}).reduce(function (a, b) { return a + b; }, 0))),
			MODES.map(function (m) {
				return React.createElement("button", {
					key: m.id, type: "button",
					className: "dsh-rtr-side-item" + (mode[0] === m.id ? " is-active" : ""),
					onClick: function () { setMode(m.id); }
				}, m.label, React.createElement("span", { className: "dsh-rtr-count" }, (counts[0] || {})[m.id] || 0));
			})),
		React.createElement("div", { className: "dsh-rtr-main" },
			mode[0] === "__ledger__"
				? React.createElement(BigScreen, { sessionId: sessionId })
				: React.createElement(ModePage, { sessionId: sessionId, mode: mode[0] })));
}

function apply(ctx) {
	ctx.effect(function () { return installStyles(); }, "dsh-redteam-results: styles");
	ctx.slots.inject("conversation.view", function () {
		return ctx.slots.register({
			name: "conversation.view",
			id: "redteam-results",
			order: 55,
			label: function () { return "redteam 成果"; }
		}, function (props) {
			return React.createElement(ResultsView, props);
		});
	});
}

module.exports = { name: "dsh-redteam-results-client", inject: ["slots"], apply: apply };
return module.exports; } });
