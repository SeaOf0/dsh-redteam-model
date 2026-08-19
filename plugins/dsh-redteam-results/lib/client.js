window.__ModuleLoader__.load({ id: "@dsh-external/dsh-redteam-results", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-redteam-results client — 会话标签页「redteam 成果」：七模式侧栏 + 渗透/代审成果页。
// 会话隔离：数据按 sessionId 读写；模式隔离由服务端 (session_id, mode) 双键强制。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useCallback = React.useCallback, useRef = React.useRef;

function api(endpoint, payload) {
	return fetch("/dsh-redteam-results/" + endpoint, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(payload || {})
	}).then(function (r) { return r.json(); });
}

var MODES = [
	{ id: "redteam", label: "研究员模式" },
	{ id: "pentest", label: "渗透测试模式" },
	{ id: "code-audit", label: "代码审计模式" },
	{ id: "binary-analysis", label: "二进制分析模式" },
	{ id: "attack-defense", label: "攻防评估模式" },
	{ id: "av-evasion", label: "免杀对抗模式" },
	{ id: "incident-response", label: "应急溯源模式" },
	{ id: "cloud-security", label: "云安全攻防模式" },
	{ id: "ctf-solver", label: "CTF 解题模式" }
];
var SEVERITY_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危" };
var SEVERITY_ORDER = ["critical", "high", "medium", "low"];
var STATUS_LABEL = { pending: "待验证", verified: "已验证", "false-positive": "误报", fixed: "已修复" };
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
var LEDGER_STATUS_LABEL = { pending: "进行中", verified: "已收口", "false-positive": "挂起", fixed: "已路由" };
var CTF_STATUS_LABEL = { pending: "进行中", verified: "已解出", "false-positive": "放弃/排除", fixed: "已复盘" };
var TIMELINE_STATUS_LABEL = { pending: "待复核", verified: "已证实", "false-positive": "排除", fixed: "已处置" };
var CLOUDPATH_STATUS_LABEL = { pending: "待验证", verified: "已证实", "false-positive": "排除", fixed: "已修复" };
var BINARY_TYPE_VOCAB = "结论类型词表：恶意定性 / 家族识别 / 脱壳还原 / 算法破解 / Key恢复 / 加壳识别 / C2提取 / 后门确认 / 行为能力 / 诱饵排除 / 固件后门";

function fmtTime(iso) { return iso ? String(iso).replace("T", " ").slice(0, 16) : ""; }
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
	return archetype === "assets" ? ASSET_STATUS_LABEL : archetype === "ledger" ? LEDGER_STATUS_LABEL : archetype === "timeline" ? TIMELINE_STATUS_LABEL : archetype === "cloudpath" ? CLOUDPATH_STATUS_LABEL : STATUS_LABEL;
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
			"- 状态：" + ((mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[f.status] || f.status) + " ｜ 优先级：" + (SEVERITY_LABEL[f.severity] || f.severity) + " ｜ 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel),
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
			"- 状态：" + (ASSET_STATUS_LABEL[f.status] || f.status) + " ｜ 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel),
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
			"- 风险等级：" + (SEVERITY_LABEL[f.severity] || f.severity),
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
		"- 成果总数：" + stats.total + "（严重 " + (stats.bySeverity.critical || 0) + " / 高危 " + (stats.bySeverity.high || 0) + " / 中危 " + (stats.bySeverity.medium || 0) + " / 低危 " + (stats.bySeverity.low || 0) + "）",
		"- 状态分布：" + Object.keys(STATUS_LABEL).map(function (s) { return STATUS_LABEL[s] + " " + (stats.byStatus[s] || 0); }).join(" / "),
		"",
		"## 总体结论",
		"",
		stats.total === 0 ? "本会话未登记成果。" : "共 " + stats.total + " 项成果，其中待验证 " + (stats.byStatus.pending || 0) + " 项（结论以验证状态为准，未验证项按疑似处理）。",
		"",
		"## Top-3 风险",
		""
	];
	if (top3.length === 0) lines.push("（无）");
	top3.forEach(function (f) { lines.push("- [" + (SEVERITY_LABEL[f.severity] || f.severity) + "] " + f.title + "（" + (f.target || "无地址") + "）" + (f.summary ? "—" + f.summary : "")); });
	lines.push("");
	lines.push("## 修复路线图（优先级从高到低）");
	lines.push("");
	if (rows.length === 0) lines.push("（无）");
	sorted.forEach(function (f, i) {
		lines.push((i + 1) + ". [" + (SEVERITY_LABEL[f.severity] || f.severity) + "] " + f.title + (f.fix ? "——" + f.fix.slice(0, 80) : ""));
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
			? [f.seq, f.title, f.type || "-", f.target || "-", (mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[f.status] || f.status, SEVERITY_LABEL[f.severity] || f.severity, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel, (f.summary || "-").replace(/\|/g, "/").slice(0, 50), (f.poc || "-").replace(/\|/g, "/").slice(0, 50)]
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
	".dsh-rtr-screen{position:relative;height:100%;overflow:auto;width:100%;min-width:0;box-sizing:border-box;background:radial-gradient(1200px 600px at 20% -10%,rgba(28,80,160,.28),transparent 60%),radial-gradient(900px 500px at 90% 110%,rgba(150,30,120,.18),transparent 55%),linear-gradient(180deg,#060b18 0%,#0a1426 55%,#060b18 100%);color:#cfe3ff;font-size:13px}",
	".dsh-rtr-screen::before{content:\"\";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(rgba(60,160,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(60,160,255,.05) 1px,transparent 1px);background-size:34px 34px}",
	".dsh-rtr-screen::after{content:\"\";position:absolute;inset:0;pointer-events:none;background:repeating-linear-gradient(180deg,transparent 0 3px,rgba(0,0,0,.06) 3px 4px)}",
	".dsh-scr-inner{position:relative;z-index:2;display:flex;flex-direction:column;gap:14px;container-type:inline-size;padding:clamp(10px,1.6vw,20px) clamp(12px,1.8vw,24px) 26px;min-height:100%;box-sizing:border-box;max-width:1680px;margin:0 auto;width:100%}",
	".dsh-scr-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px 16px;min-width:0;padding:10px 18px;border:1px solid rgba(64,196,255,.25);border-radius:12px;background:linear-gradient(90deg,rgba(16,48,90,.55),rgba(10,20,40,.4));box-shadow:0 0 24px rgba(30,140,255,.12) inset}",
	".dsh-scr-title{font-size:20px;font-weight:800;letter-spacing:.14em;color:#eaf6ff;text-shadow:0 0 18px rgba(64,196,255,.65)}",
	".dsh-scr-title small{display:block;font-size:10px;letter-spacing:.32em;color:#5f8fc0;font-weight:600;margin-top:2px}",
	".dsh-scr-live{display:flex;align-items:center;gap:8px;font-size:12px;color:#7fe3b0;letter-spacing:.1em}",
	".dsh-scr-dot{width:8px;height:8px;border-radius:50%;background:#3dfca0;box-shadow:0 0 10px #3dfca0;animation:dshPulse 1.6s infinite}",
	"@keyframes dshPulse{0%,100%{opacity:1}50%{opacity:.25}}",
	".dsh-scr-clock{font-family:monospace;font-size:20px;color:#9fdcff;text-shadow:0 0 12px rgba(80,200,255,.5);letter-spacing:.08em}",
	".dsh-scr-grid{display:grid;grid-template-columns:minmax(180px,240px) minmax(260px,1fr) minmax(200px,250px);gap:14px;align-items:stretch}",
	".dsh-scr-center,.dsh-scr-grid>div{min-width:0}",
	".dsh-scr-nums{grid-template-columns:repeat(auto-fit,minmax(110px,1fr))}",
	".dsh-scr-tablewrap{overflow-x:auto}",
	".dsh-scr-table{table-layout:fixed;width:100%}",
	".dsh-scr-table td,.dsh-scr-table th{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
	"@container (max-width:700px){.dsh-scr-grid{grid-template-columns:1fr}}",
	"@container (max-width:620px){.dsh-scr-nums{grid-template-columns:repeat(2,minmax(84px,1fr))}.dsh-scr-title{font-size:15px}.dsh-scr-clock{font-size:15px}}",
	"@container (max-width:460px){.dsh-scr-nums{grid-template-columns:repeat(auto-fit,minmax(72px,1fr))}.dsh-scr-bar .lbl{width:56px;font-size:11px}.dsh-scr-num b{font-size:24px}}",
	"@media (max-width:980px){.dsh-scr-grid{grid-template-columns:1fr}}",
	"@media (max-width:640px){.dsh-scr-nums{grid-template-columns:repeat(2,1fr)}.dsh-scr-title{font-size:15px}}",
	".dsh-scr-panel{position:relative;min-width:0;overflow:hidden;border:1px solid rgba(64,196,255,.22);border-radius:12px;background:linear-gradient(180deg,rgba(12,28,52,.72),rgba(8,18,36,.6));padding:14px 16px;backdrop-filter:blur(2px)}",
	".dsh-scr-panel::before{content:\"\";position:absolute;top:-1px;left:14px;right:14px;height:2px;background:linear-gradient(90deg,transparent 0%,#38c6ff 50%,transparent 100%);background-size:200% 100%;opacity:.8;animation:dshShimmer 5s linear infinite}",
	".dsh-scr-panel::after{content:\"\";position:absolute;right:7px;bottom:7px;width:13px;height:13px;border-right:1px solid rgba(64,196,255,.55);border-bottom:1px solid rgba(64,196,255,.55);pointer-events:none}",
	".dsh-scr-panel:hover{border-color:rgba(90,200,255,.45)}",
	".dsh-scr-num b{animation:dshNumGlow 3.6s ease-in-out infinite}",
	".dsh-scr-table tbody tr{transition:background .2s}",
	".dsh-scr-table tbody tr:hover td{background:rgba(56,190,255,.09)}",
	".dsh-scr-bar .track span{transition:width .6s ease}",
	".dsh-scr-hero{position:relative}",
	".dsh-scr-hero::after{content:\"\";position:absolute;left:6%;right:6%;bottom:-4px;height:1px;background:linear-gradient(90deg,transparent,rgba(56,190,255,.65),transparent)}",
	".dsh-scr-globewrap::before{content:\"\";position:absolute;left:-8%;right:-8%;top:33%;height:34%;border:1px solid rgba(150,225,255,.3);border-radius:50%}",
	".dsh-scr-donut{box-shadow:0 0 0 6px rgba(10,20,40,.55),0 0 26px rgba(60,180,255,.4)}",
	"@keyframes dshShimmer{from{background-position:200% 0}to{background-position:-200% 0}}",
	"@keyframes dshNumGlow{0%,100%{text-shadow:0 0 12px rgba(64,196,255,.35)}50%{text-shadow:0 0 28px rgba(64,196,255,.8)}}",
	".dsh-scr-clockwrap{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}",
	".dsh-scr-range,.dsh-scr-date{background:rgba(10,26,48,.85);color:#bfe6ff;border:1px solid rgba(80,180,255,.4);border-radius:7px;padding:3px 8px;font-size:12px;outline:none;color-scheme:dark}",
	".dsh-scr-range:hover,.dsh-scr-date:hover{border-color:rgba(120,210,255,.7)}",
	".dsh-rtr-screen .dsh-rtr-btn{background:rgba(10,26,48,.85);color:#bfe6ff;border-color:rgba(80,180,255,.4)}",
	".dsh-rtr-screen .dsh-rtr-btn:hover{background:rgba(28,58,100,.92);border-color:rgba(120,210,255,.7);color:#eaf6ff}",
	".dsh-rtr-screen .dsh-rtr-btn:active{background:rgba(36,70,118,.95);color:#eaf6ff}",
	".dsh-rtr-screen .dsh-rtr-btn:disabled{opacity:.45}",
	".dsh-scr-hero{display:flex;align-items:center;justify-content:center;gap:clamp(14px,4vw,56px);padding:10px 6px 2px;flex-wrap:wrap}",
	".dsh-scr-heronums{display:grid;grid-template-columns:repeat(2,minmax(108px,1fr));gap:12px;min-width:0}",
	".dsh-scr-globewrap{position:relative;width:176px;height:176px;display:flex;align-items:center;justify-content:center;flex:none}",
	".dsh-scr-globe{position:relative;width:116px;height:116px;border-radius:50%;background:radial-gradient(circle at 35% 32%,#5ec8ff 0%,#0f63bd 36%,#062f6e 68%,#021a3d 100%);box-shadow:0 0 36px rgba(56,190,255,.5),inset -16px -14px 36px rgba(0,0,0,.6);overflow:hidden;animation:dshGlobeFloat 6s ease-in-out infinite}",
	".dsh-scr-grat{position:absolute;inset:0;background:repeating-linear-gradient(90deg,rgba(150,225,255,.30) 0 1px,transparent 1px 19px),repeating-linear-gradient(0deg,rgba(150,225,255,.15) 0 1px,transparent 1px 17px);animation:dshGrat 8s linear infinite}",
	".dsh-scr-sweep{position:absolute;inset:0;background:linear-gradient(100deg,transparent 40%,rgba(170,235,255,.38) 50%,transparent 60%);animation:dshSweep 3.4s linear infinite}",
	".dsh-scr-orbit{position:absolute;left:50%;top:50%;border:1px solid rgba(90,190,255,.35);border-radius:50%}",
	".dsh-scr-orbit::after{content:\"\";position:absolute;top:-3.5px;left:50%;width:7px;height:7px;border-radius:50%;background:#7fe9ff;box-shadow:0 0 12px #7fe9ff}",
	".dsh-scr-orbit.o1{width:148px;height:148px;margin:-74px 0 0 -74px;animation:dshOrbitSpin 13s linear infinite}",
	".dsh-scr-orbit.o2{width:170px;height:170px;margin:-85px 0 0 -85px;border-style:dashed;border-color:rgba(255,130,225,.32);animation:dshOrbitSpin 23s linear infinite reverse}",
	".dsh-scr-orbit.o2::after{background:#ff8ce5;box-shadow:0 0 12px #ff8ce5}",
	".dsh-scr-herotag{position:absolute;bottom:-4px;left:50%;transform:translateX(-50%);font-size:10px;letter-spacing:.26em;color:#7fd4ff;white-space:nowrap;text-shadow:0 0 8px rgba(80,200,255,.65)}",
	"@keyframes dshGrat{from{background-position:0 0,0 0}to{background-position:190px 0,0 0}}",
	"@keyframes dshSweep{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",
	"@keyframes dshOrbitSpin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",
	"@keyframes dshGlobeFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}",
	"@container (max-width:760px){.dsh-scr-hero{gap:10px}.dsh-scr-globewrap{width:130px;height:130px}.dsh-scr-globe{width:84px;height:84px}.dsh-scr-orbit.o1{width:106px;height:106px;margin:-53px 0 0 -53px}.dsh-scr-orbit.o2{width:124px;height:124px;margin:-62px 0 0 -62px}}",
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
	".dsh-scr-panel h4{margin:0 0 12px;font-size:12px;letter-spacing:.22em;color:#7fc4ff;font-weight:700}",
	".dsh-scr-center{display:flex;flex-direction:column;gap:14px}",
	".dsh-scr-nums{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}",
	".dsh-scr-num{border:1px solid rgba(64,196,255,.22);border-radius:12px;padding:14px 12px 10px;text-align:center;background:linear-gradient(180deg,rgba(14,34,64,.8),rgba(8,18,36,.55))}",
	".dsh-scr-num b{display:block;font-size:34px;font-weight:800;color:#eaf6ff;text-shadow:0 0 22px rgba(64,196,255,.55);font-family:monospace}",
	".dsh-scr-num span{font-size:11px;letter-spacing:.18em;color:#6f9ecf}",
	".dsh-scr-num.is-good b{color:#7fe3b0;text-shadow:0 0 22px rgba(60,230,150,.5)}",
	".dsh-scr-num.is-warn b{color:#ffd166;text-shadow:0 0 22px rgba(255,200,80,.5)}",
	".dsh-scr-num.is-bad b{color:#ff7a90;text-shadow:0 0 22px rgba(255,110,140,.5)}",
	".dsh-scr-bar{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:12px}",
	".dsh-scr-bar .lbl{width:76px;color:#8fb8e6;flex:none;text-align:right}",
	".dsh-scr-bar .track{flex:1;height:9px;border-radius:5px;background:rgba(30,60,100,.5);overflow:hidden;border:1px solid rgba(64,196,255,.14)}",
	".dsh-scr-bar .fill{height:100%;border-radius:5px;background:linear-gradient(90deg,#1c7dd8,#38e0ff);box-shadow:0 0 10px rgba(56,224,255,.5)}",
	".dsh-scr-bar .fill.is-alt{background:linear-gradient(90deg,#a13bd8,#ff5ec4);box-shadow:0 0 10px rgba(255,94,196,.5)}",
	".dsh-scr-bar .val{width:34px;color:#cfe3ff;font-family:monospace;flex:none}",
	".dsh-scr-donut{width:120px;height:120px;border-radius:50%;margin:6px auto;position:relative;background:conic-gradient(#e5484d 0 25%,#e87d2e 25% 50%,#d9b00c 50% 75%,#3b7dd8 75% 100%);box-shadow:0 0 18px rgba(60,180,255,.2)}",
	".dsh-scr-donut::after{content:attr(data-total);position:absolute;inset:26px;border-radius:50%;background:#0a1426;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#eaf6ff;font-family:monospace;text-shadow:0 0 12px rgba(64,196,255,.5)}",
	".dsh-scr-legend{display:flex;flex-wrap:wrap;gap:8px 12px;justify-content:center;font-size:11px;color:#9fc2ea}",
	".dsh-scr-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:-1px}",
	".dsh-scr-table{width:100%;border-collapse:collapse;font-size:12px}",
	".dsh-scr-table th{color:#6f9ecf;font-weight:600;text-align:left;padding:5px 8px;border-bottom:1px solid rgba(64,196,255,.18);letter-spacing:.06em;font-size:11px}",
	".dsh-scr-table td{padding:6px 8px;border-bottom:1px solid rgba(40,70,110,.25);color:#d7e8ff}",
	".dsh-scr-table tr:hover td{background:rgba(40,120,220,.1)}",
	".dsh-scr-sev{display:inline-block;padding:1px 8px;border-radius:8px;font-size:11px;font-weight:600}",
	".dsh-scr-sev-critical{color:#ff8ea0;background:rgba(229,72,77,.16);border:1px solid rgba(229,72,77,.4)}",
	".dsh-scr-sev-high{color:#ffb37a;background:rgba(232,125,46,.14);border:1px solid rgba(232,125,46,.4)}",
	".dsh-scr-sev-medium{color:#ffe08a;background:rgba(217,176,12,.12);border:1px solid rgba(217,176,12,.4)}",
	".dsh-scr-sev-low{color:#8ec4ff;background:rgba(59,125,216,.14);border:1px solid rgba(59,125,216,.4)}",
	".dsh-scr-mode{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:12px;color:#a9cdf5}",
	".dsh-scr-mode .tag{width:104px;flex:none;color:#8fb8e6}",
	".dsh-scr-mode .n{margin-left:auto;font-family:monospace;color:#eaf6ff}",
	".dsh-scr-empty{padding:60px 20px;text-align:center;color:#5f8fc0;letter-spacing:.2em;font-size:13px}"
].join("\n");

var CSS = [
	".dsh-rtr-root{height:100%;display:flex;min-height:0;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);font-size:13px}",
	".dsh-rtr-side{width:168px;flex:none;border-right:1px solid var(--dsw-alias-border-l2,#e4e4e7);padding:14px 10px;display:flex;flex-direction:column;gap:2px;background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 4%,var(--dsw-alias-bg-base,#fff))}",
	".dsh-rtr-side-title{font-size:12px;letter-spacing:.08em;color:var(--dsw-alias-label-tertiary,#8a8a8f);padding:0 8px 10px;font-weight:600}",
	".dsh-rtr-side-item{display:flex;align-items:center;justify-content:space-between;gap:6px;padding:7px 10px;border:none;background:none;border-radius:7px;cursor:pointer;color:var(--dsw-alias-label-secondary,#5b5b60);font-size:13px;text-align:left}",
	".dsh-rtr-side-item:hover{background:var(--dsw-alias-interactive-bg-hover,color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 7%,transparent));color:var(--dsw-alias-label-primary,#1a1a1a)}",
	".dsh-rtr-side-item.is-active{background:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 12%,transparent);color:var(--dsw-alias-label-primary,#1a1a1a);font-weight:600}",
	".dsh-rtr-count{font-size:11px;min-width:20px;text-align:center;border-radius:9px;padding:1px 5px;background:var(--dsw-alias-bg-base,#fff);border:1px solid var(--dsw-alias-border-l2,#e4e4e7);color:var(--dsw-alias-label-secondary,#5b5b60)}",
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
	".dsh-rtr-sev-critical{color:#e5484d;border-color:rgba(229,72,77,.35);background:rgba(229,72,77,.08)}",
	".dsh-rtr-sev-high{color:#e87d2e;border-color:rgba(232,125,46,.35);background:rgba(232,125,46,.08)}",
	".dsh-rtr-sev-medium{color:#b58a00;border-color:rgba(181,138,0,.35);background:rgba(181,138,0,.08)}",
	".dsh-rtr-sev-low{color:#3b7dd8;border-color:rgba(59,125,216,.35);background:rgba(59,125,216,.08)}",
	".dsh-rtr-st{flex:none;font-size:11px;padding:2px 8px;border-radius:9px;border:1px solid var(--dsw-alias-border-l2,#d4d4d8);color:var(--dsw-alias-label-secondary,#5b5b60)}",
	".dsh-rtr-st-verified{color:#2f9e63;border-color:rgba(47,158,99,.35);background:rgba(47,158,99,.08)}",
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

function Chip(props) { return React.createElement("span", { className: "dsh-rtr-sev dsh-rtr-sev-" + props.severity }, SEVERITY_LABEL[props.severity] || props.severity); }
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

var SEV_COLORS = { critical: "#e5484d", high: "#e87d2e", medium: "#d9b00c", low: "#3b7dd8" };

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
	}, [sessionId, mode, page[0], severity[0], status[0], q[0]]);

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
	}, [sessionId, mode, severity[0], status[0], q[0]]);

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
			download(meta.allName + new Date().toISOString().slice(0, 10) + ".md", mdTable(all, meta.tableTitle, mode));
			setNotice("已导出 " + all.length + " 条（当前筛选范围）");
		});
	}
	function exportSelected() {
		var picked = rows.filter(function (f) { return selected[0][f.id]; });
		if (picked.length === 0) { setNotice("先勾选要导出的成果"); return; }
		var text = picked.map(function (f) { return mdReport(f, mode); }).join("\n---\n\n");
		download(meta.reportName + new Date().toISOString().slice(0, 10) + ".md", text);
		setNotice("已导出 " + picked.length + " 份报告（MD）");
	}
	function exportOne(f) {
		download("finding-" + mode + "-" + f.seq + "-" + new Date().toISOString().slice(0, 10) + ".md", mdReport(f, mode));
	}
	function exportOverview() {
		fetchAllForExport().then(function (all) {
			download((mode === "code-audit" ? "audit" : "pentest") + "-overview-" + new Date().toISOString().slice(0, 10) + ".md", mdOverview(sesMeta, stats, all, mode));
			setNotice("总览报告已导出（MD）");
		});
	}
	function exportHtml() {
		fetchAllForExport().then(function (all) {
			download((mode === "code-audit" ? "audit" : "pentest") + "-report-" + new Date().toISOString().slice(0, 10) + ".html", htmlReport(sesMeta, stats, all, mode), "text/html");
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
				React.createElement(Chip, { severity: f.severity }),
				React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + f.status }, (stLabelSet[f.status] || f.status)),
				mode === "code-audit" && f.auditMode ? React.createElement("span", { className: "dsh-rtr-am dsh-rtr-am-" + f.auditMode }, AUDIT_MODE_LABEL[f.auditMode] || f.auditMode) : null,
				React.createElement("span", { className: "dsh-rtr-title" }, f.title),
				React.createElement("span", { className: "dsh-rtr-summ" }, f.summary || ""),
				React.createElement("span", { className: "dsh-rtr-time" }, fmtTime(f.updatedAt)),
				React.createElement("span", { className: "dsh-rtr-rowactions", onClick: function (e) { e.stopPropagation(); } },
					React.createElement(Btn, { onClick: function () { onVerify(f); } }, "验证"),
					React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === f.id ? "确认删除" : "删除"))),
			expanded[0] === f.id ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onExportOne: exportOne }) : null);
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
						React.createElement(Chip, { severity: f.severity }),
						React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + f.status }, stSet[f.status] || f.status),
						React.createElement("span", { className: "dsh-rtr-title" }, f.title),
						React.createElement("span", { className: "dsh-rtr-rowactions", onClick: function (e) { e.stopPropagation(); } },
							React.createElement(Btn, { onClick: function () { onVerify(f); } }, "验证"),
							React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === f.id ? "确认删除" : "删除"))),
					React.createElement("div", { className: "dsh-rtr-tl-meta", onClick: function () { toggle(f); } },
						React.createElement("span", null, "主机 ", React.createElement("b", null, f.target || "（未填）")),
						React.createElement("span", null, "证据 ", React.createElement("b", null, f.evidence || "（未填）")),
						React.createElement("span", { className: "dsh-rtr-tl-concl" }, f.summary || "")),
					open ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onExportOne: exportOne }) : null)));
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
					React.createElement(Chip, { severity: f.severity }),
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
				open ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onExportOne: exportOne }) : null));
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
			meta.archetype !== "assets" ? React.createElement("select", { className: "dsh-rtr-select", value: severity[0], onChange: function (e) { setSeverity(e.target.value); } },
				React.createElement("option", { value: "" }, meta.archetype === "ledger" ? "全部优先级" : "全部等级"),
				SEVERITY_ORDER.map(function (s) { return React.createElement("option", { key: s, value: s }, SEVERITY_LABEL[s]); })) : null,
			React.createElement("select", { className: "dsh-rtr-select", value: status[0], onChange: function (e) { setStatus(e.target.value); } },
				React.createElement("option", { value: "" }, "全部状态"),
				Object.keys(STATUS_LABEL).map(function (s) { return React.createElement("option", { key: s, value: s }, statusLabelSetFor(meta.archetype)[s] || STATUS_LABEL[s]); })),
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
var SCR_MODE_VOCAB = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];

function BigScreen(props) {
	var data = useState(null); var setData = data[1];
	var clock = useState(""); var setClock = clock[1];
	var range = useState("today"); var setRange = range[1];
	var customFrom = useState(""); var setCustomFrom = customFrom[1];
	var customTo = useState(""); var setCustomTo = customTo[1];
	var scrPg = useState(0); var setScrPg = scrPg[1];

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

	var ov = data[0];
	if (ov === null) {
		return React.createElement("div", { className: "dsh-rtr-screen" },
			React.createElement("div", { className: "dsh-scr-inner" },
				React.createElement("div", { className: "dsh-scr-empty" }, "正在接入全局数据…")));
	}
	var numCard = function (v, label, cls) { return React.createElement("div", { className: "dsh-scr-num " + (cls || "") }, React.createElement("b", null, v), React.createElement("span", null, label)); };
	var total = ov.total || 0;
	var maxMode = Math.max(1, ...SCR_MODE_VOCAB.map(function (m) { return (ov.byMode[m] || 0); }));
	var sevOrder = ["critical", "high", "medium", "low"];
	var sevColors = { critical: "#e5484d", high: "#e87d2e", medium: "#d9b00c", low: "#3b7dd8" };
	var sevTotal = sevOrder.reduce(function (n, s) { return n + (ov.bySeverity[s] || 0); }, 0) || 1;
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
	return React.createElement("div", { className: "dsh-rtr-screen" },
		React.createElement("div", { className: "dsh-scr-inner" },
			React.createElement("div", { className: "dsh-scr-header" },
				React.createElement("div", { className: "dsh-scr-live" }, React.createElement("span", { className: "dsh-scr-dot" }), "LIVE · 跨会话全局"),
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
					React.createElement("div", { className: "dsh-scr-orbit o1" }),
					React.createElement("div", { className: "dsh-scr-orbit o2" }),
					React.createElement("div", { className: "dsh-scr-globe" },
						React.createElement("div", { className: "dsh-scr-grat" }),
						React.createElement("div", { className: "dsh-scr-sweep" })),
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
								React.createElement("span", { className: "track" }, React.createElement("span", { className: "dsh-fill " + (i % 2 ? "is-alt" : ""), style: { display: "block", width: ((ov.byMode[m] || 0) / maxMode * 100) + "%", height: "100%", borderRadius: 5, background: i % 2 ? "linear-gradient(90deg,#a13bd8,#ff5ec4)" : "linear-gradient(90deg,#1c7dd8,#38e0ff)", boxShadow: i % 2 ? "0 0 10px rgba(255,94,196,.5)" : "0 0 10px rgba(56,224,255,.5)" } })),
								React.createElement("span", { className: "val" }, ov.byMode[m] || 0));
						})),
					React.createElement("div", { className: "dsh-scr-panel" },
						React.createElement("h4", null, "状态分布"),
						["pending", "verified", "false-positive", "fixed"].map(function (s, i) {
							var names = { pending: "待验证·进行中", verified: "已验证·有效", "false-positive": "证伪·失效", fixed: "已交付·路由" };
							return React.createElement("div", { key: s, className: "dsh-scr-bar" },
								React.createElement("span", { className: "lbl" }, names[s].slice(0, 7)),
								React.createElement("span", { className: "track" }, React.createElement("span", { style: { display: "block", width: ((ov.byStatus[s] || 0) / Math.max(1, total) * 100) + "%", height: "100%", borderRadius: 5, background: i === 1 ? "linear-gradient(90deg,#1f9d63,#41e3a0)" : i === 2 ? "linear-gradient(90deg,#4a5a70,#8a99ad)" : i === 3 ? "linear-gradient(90deg,#2f6fd8,#5aa0ff)" : "linear-gradient(90deg,#b58a00,#ffd166)" } })),
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
											React.createElement("td", null, React.createElement("span", { className: "dsh-scr-sev dsh-scr-sev-" + f.severity }, SEVERITY_LABEL[f.severity] || f.severity)));
									}))),
								pgMax > 0 ? React.createElement("div", { className: "dsh-rtr-pager", style: { justifyContent: "center" } },
									React.createElement(Btn, { disabled: pgCur <= 0, onClick: function () { setScrPg(pgCur - 1); } }, "上一页"),
									"第 " + (pgCur + 1) + " / " + (pgMax + 1) + " 页 · 共 " + stRows.length + " 条",
									React.createElement(Btn, { disabled: pgCur >= pgMax, onClick: function () { setScrPg(pgCur + 1); } }, "下一页")) : null)))), 
				React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 14 } },
					React.createElement("div", { className: "dsh-scr-panel" },
						React.createElement("h4", null, "风险等级占比"),
						React.createElement("div", { className: "dsh-scr-donut", style: { background: "conic-gradient(" + (donutStops || "#1c2d4a 0 100%") + ")", "data-total": total }, "data-total": String(total) }),
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
								React.createElement("span", { className: "track" }, React.createElement("span", { style: { display: "block", width: (v / Math.max(1, total) * 100) + "%", height: "100%", borderRadius: 5, background: i === 0 ? "linear-gradient(90deg,#1f9d63,#41e3a0)" : i === 1 ? "linear-gradient(90deg,#b58a00,#ffd166)" : "linear-gradient(90deg,#4a5a70,#8a99ad)" } })),
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
