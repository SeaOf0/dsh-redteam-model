window.__ModuleLoader__.load({ id: "@dsh-external/dsh-redteam-results", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
// dsh-redteam-results client — 会话标签页「redteam 成果」：九模式侧栏 + 各模式成果页（板式按模式分型）。
// 会话隔离：数据按 sessionId 读写；模式隔离由服务端 (session_id, mode) 双键强制；模式页为跨会话聚合视图。
"use strict";
var React = require("react");
var useState = React.useState, useEffect = React.useEffect, useCallback = React.useCallback, useRef = React.useRef;

var dshCsrf = {};
/** CSRF token 懒加载（同源 GET /csrf，跨源页面读不到）；POST 回带 x-dsh-csrf 头。
 *  token 缓存遇 403 即失效重取一次——宿主重启轮换 token 后已开标签页自愈，不再永久 403。 */
function csrfOf(base) {
	if (!dshCsrf[base]) dshCsrf[base] = fetch(base + "/csrf").then(function (r) { return r.json(); }).then(function (r) { return r && r.token ? r.token : ""; }).catch(function () { return ""; });
	return dshCsrf[base];
}
function postJson(tok, endpoint, payload) {
	return fetch("/dsh-redteam-results/" + endpoint, {
		method: "POST",
		headers: tok ? { "content-type": "application/json", "x-dsh-csrf": tok } : { "content-type": "application/json" },
		body: JSON.stringify(payload || {})
	});
}
function api(endpoint, payload) {
	return csrfOf("/dsh-redteam-results").then(function (tok) {
		return postJson(tok, endpoint, payload).then(function (r) {
			if (r.status === 403) {
				delete dshCsrf["/dsh-redteam-results"];
				return csrfOf("/dsh-redteam-results").then(function (tok2) { return postJson(tok2, endpoint, payload); }).then(function (r2) { return r2.json(); });
			}
			return r.json();
		});
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
var EVIDENCE_LABEL = { impact: "影响已证", confirmed: "已证实", partial: "部分证据", unknown: "未知" };
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
		groupLabel: "按目标分组", empty: "本会话暂无攻防评估战果。",
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
	"binary-analysis": ["pending", "suspect", "verified"],
	"attack-defense": ["pending", "verified", "false-positive", "fixed"],
	"cloud-security": ["pending", "verified", "false-positive", "fixed"]
};
var LEDGER_STATUS_LABEL = { pending: "进行中", verified: "已收口", "false-positive": "挂起", fixed: "已路由" };
var CTF_STATUS_LABEL = { pending: "未解", stuck: "卡点", verified: "已解·flag 验证", "false-positive": "放弃/排除", fixed: "已复盘" };
var TIMELINE_STATUS_LABEL = { pending: "待复核", "code-reviewed": "复核通过", verified: "已证实", "false-positive": "排除", fixed: "已处置" };
var CLOUDPATH_STATUS_LABEL = { pending: "待验证", verified: "已证实", "false-positive": "排除", fixed: "已修复" };

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
			"- 状态：" + ((mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[f.status] || f.status) + (mode === "ctf-solver" ? " ｜ 模块：" + (f.type || "-") : " ｜ 优先级：" + (SEVERITY_LABEL[f.severity] || f.severity)) + " ｜ 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel),
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
	if (mode === "binary-analysis") { // 二进制专属报告分支——须在 assets 通用分支之前（binary 的 archetype=assets，否则被遮蔽成死代码）
		return [
			"# 二进制分析报告：" + f.title,
			"",
			"- 结论标题：" + f.title,
			"- 产物类型：" + (f.type || "未分类"),
			"- 样本：" + (f.target || "（未填写）") + (f.sampleHash ? "（SHA256: " + f.sampleHash + "）" : ""),
			"- 家族/变种：" + (f.family || "未知/未定"),
			"- 壳/保护：" + (f.packer || "未识别"),
			"- 分析结论：" + (BIN_STATUS_LABEL[f.status] || f.status) + " ｜ 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel),
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
			f.retestNote ? "\n## 复测记录\n\n" + f.retestNote + (f.retestAt ? "（" + fmtTime(f.retestAt) + "）" : "") + "\n" : "",
			"",
			"## 证据与复核",
			"",
			"- 证据引用：" + (f.evidence || "（未填写；含 provenance 登记）"),
			"- 复核注记：" + (f.verifyNote || "（未复核）") + (f.verifiedAt ? "（验证时间 " + fmtTime(f.verifiedAt) + "）" : ""),
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
			mode === "attack-defense" && f.impact ? "- 影响证明：" + f.impact : "",
			mode === "attack-defense" && (f.baseline || f.diffEvidence || f.markerEcho) ? "\n## 对照三件套\n\n- 基线：" + (f.baseline || "（未填）") + "\n- 差分（翻转）：" + (f.diffEvidence || "（未填）") + "\n- marker 回显：" + (f.markerEcho || "（未填）") + "\n" : "",
			mode === "attack-defense" && f.requestPkt ? "\n## 完整请求包\n\n```\n" + f.requestPkt + "\n```\n" : "",
			mode === "attack-defense" && f.responsePkt ? "\n## 关键响应\n\n```\n" + f.responsePkt + "\n```\n" : "",
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
			"- 证据等级：" + (EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel) + " ｜ 状态：" + statusTextForExport(f, mode) + " ｜ 来源：" + (SOURCE_LABEL[f.sourceOrigin] || f.sourceOrigin),
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
	var assetView = MODE_META[mode] && MODE_META[mode].archetype === "assets";
	var isCtf = mode === "ctf-solver";
	var sorted = isCtf
		? rows.slice().sort(function (a, b) { return ["stuck", "pending", "verified"].indexOf(a.status) - ["stuck", "pending", "verified"].indexOf(b.status); })
		: rows.slice().sort(function (a, b) { return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity); });
	var top3 = sorted.slice(0, 3);
	var lines = [
		"# " + label + "总览报告",
		"",
		"- 对象/范围：" + (meta.targetLabel || "（未填写）"),
		"- 版本：" + (meta.version || "（未填写）") + " ｜ scope：" + (meta.scope || "（未填写）"),
		LABEL_BY_TYPE_MODES[mode] ? "- 成果总数：" + stats.total : "- 成果总数：" + stats.total + "（严重 " + (stats.bySeverity.critical || 0) + " / 高危 " + (stats.bySeverity.high || 0) + " / 中危 " + (stats.bySeverity.medium || 0) + " / 低危 " + (stats.bySeverity.low || 0) + "）",
		"- 状态分布：" + Object.keys(LABEL_BY_TYPE_MODES[mode] ? (mode === "av-evasion" ? AV_STATUS_LABEL : mode === "binary-analysis" ? BIN_STATUS_LABEL : mode === "attack-defense" ? ASSET_STATUS_LABEL : CTF_STATUS_LABEL) : STATUS_LABEL).map(function (s) { var set = LABEL_BY_TYPE_MODES[mode] ? (mode === "av-evasion" ? AV_STATUS_LABEL : mode === "binary-analysis" ? BIN_STATUS_LABEL : mode === "attack-defense" ? ASSET_STATUS_LABEL : CTF_STATUS_LABEL) : STATUS_LABEL; return (set[s] || s) + " " + (stats.byStatus[s] || 0); }).join(" / "),
		"",
		"## 总体结论",
		"",
		stats.total === 0 ? "本会话未登记成果。" : isCtf
			? "共 " + stats.total + " 道题，其中未解 " + (stats.byStatus.pending || 0) + " 项、卡点 " + (stats.byStatus.stuck || 0) + " 项（结论以 flag 验证状态为准）。"
			: "共 " + stats.total + " 项成果，其中待验证 " + (stats.byStatus.pending || 0) + " 项（结论以验证状态为准，未验证项按疑似处理）。",
		"",
		"## " + (assetView ? "Top-3 成果" : isCtf ? "Top-3 题目（未解/卡点优先）" : "Top-3 风险"),
		""
	];
	if (top3.length === 0) lines.push("（无）");
	top3.forEach(function (f) { lines.push("- [" + (LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : (SEVERITY_LABEL[f.severity] || f.severity)) + "] " + f.title + "（" + (f.target || "无地址") + "）" + (f.summary ? "—" + f.summary : "")); });
	lines.push("");
	lines.push("## " + (assetView ? "战果清单（交付/复测优先）" : isCtf ? "解题路线图（未解/卡点优先）" : "修复路线图（优先级从高到低）"));
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
	var isCtf = mode === "ctf-solver";
	var head = isCloudpath
		? "| # | 路径 | 类型 | 入口 | 身份 | 权限 | 资源 | 严重度 | 影响证明 |"
		: isCtf
		? "| # | 任务 | 模块 | 题目地址 | 状态 | 证据等级 | 结论摘要 | 解题材料 |"
		: isTimeline
		? "| # | 攻击时间 | 节点 | 类型 | 主机 | 严重度 | 证据 | 结论 |"
		: isLedger
		? "| # | 任务 | 形态 | 对象/范围 | 状态 | 优先级 | 证据等级 | 结论摘要 | 下一步 |"
		: isAsset
		? "| 序号 | 名称 | " + M.kindLabel + " | " + M.locLabel + " | 状态 | 说明 |"
		: audit
		? "| 序号 | 名称 | 等级 | 主线类型 | CWE | sink 位置 | 状态 | 来源 | 简介 |"
		: "| 序号 | 名称 | 等级 | 类型 | CVSS | 地址 | 状态 | 简介 |";
	var sep = isCloudpath ? "|---|---|---|---|---|---|---|---|---|" : isCtf ? "|---|---|---|---|---|---|---|---|" : isTimeline ? "|---|---|---|---|---|---|---|---|" : isLedger ? "|---|---|---|---|---|---|---|---|---|" : audit ? "|---|---|---|---|---|---|---|---|---|" : isAsset ? "|---|---|---|---|---|---|" : "|---|---|---|---|---|---|---|---|";
	var body = rows.map(function (f) {
		var cells = isCloudpath
			? [f.seq, f.title, f.type || "-", (f.entry || "-").replace(/\|/g, "/").slice(0, 30), (f.identity || "-").replace(/\|/g, "/").slice(0, 30), (f.permission || "-").replace(/\|/g, "/").slice(0, 30), (f.resource || f.target || "-").replace(/\|/g, "/").slice(0, 40), SEVERITY_LABEL[f.severity] || f.severity, (f.impact || f.summary || "-").replace(/\|/g, "/").slice(0, 50)]
			: isCtf
			? [f.seq, f.title, f.type || "-", f.target || "-", CTF_STATUS_LABEL[f.status] || f.status, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel, (f.summary || "-").replace(/\|/g, "/").slice(0, 50), (f.poc || "-").replace(/\|/g, "/").slice(0, 50)]
			: isTimeline
			? [f.seq, f.timelineAt || "unknown", f.title, f.type || "-", f.target || "-", SEVERITY_LABEL[f.severity] || f.severity, (f.evidence || "-").replace(/\|/g, "/").slice(0, 40), (f.summary || "-").replace(/\|/g, "/").slice(0, 50)]
			: isLedger
			? [f.seq, f.title, f.type || "-", f.target || "-", (mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL)[f.status] || f.status, mode === "ctf-solver" ? (f.type || "-") : (SEVERITY_LABEL[f.severity] || f.severity), EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel, (f.summary || "-").replace(/\|/g, "/").slice(0, 50), (f.poc || "-").replace(/\|/g, "/").slice(0, 50)]
			: isAsset
			? [f.seq, f.title, f.type || "-", (f.target || "-") + (f.sampleHash ? " (" + f.sampleHash.slice(0, 8) + ")" : ""), (mode === "av-evasion" ? AV_STATUS_LABEL : mode === "binary-analysis" ? BIN_STATUS_LABEL : ASSET_STATUS_LABEL)[f.status] || f.status, (f.summary || f.description || "-").replace(/\|/g, "/").slice(0, 60)]
			: audit
			? [f.seq, f.title, SEVERITY_LABEL[f.severity] || f.severity, f.type || "-", f.cwe || "-", f.target || "-", statusTextForExport(f, mode), SOURCE_LABEL[f.sourceOrigin] || f.sourceOrigin, (f.summary || "-").replace(/\|/g, "/")]
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
	var assetView = MODE_META[mode] && MODE_META[mode].archetype === "assets";
	var stSet = assetView ? (mode === "av-evasion" ? AV_STATUS_LABEL : mode === "binary-analysis" ? BIN_STATUS_LABEL : ASSET_STATUS_LABEL) : STATUS_LABEL;
	h.push(assetView
		? '<p class="meta">成果总数 ' + stats.total + '｜ 生成时间 ' + new Date().toLocaleString() + '</p>'
		: mode === "ctf-solver"
		? '<p class="meta">题目总数 ' + stats.total + '（未解 ' + (stats.byStatus.pending || 0) + ' / 卡点 ' + (stats.byStatus.stuck || 0) + ' / 已解 ' + (stats.byStatus.verified || 0) + '）｜ 生成时间 ' + new Date().toLocaleString() + '</p>'
		: '<p class="meta">总数 ' + stats.total + '（严重 ' + (stats.bySeverity.critical || 0) + ' / 高危 ' + (stats.bySeverity.high || 0) + ' / 中危 ' + (stats.bySeverity.medium || 0) + ' / 低危 ' + (stats.bySeverity.low || 0) + '）｜ 生成时间 ' + new Date().toLocaleString() + '</p>');
	h.push('<h2>成果清单</h2><table><tr>' + (mode === "code-audit" ? "<th>#</th><th>名称</th><th>等级</th><th>主线</th><th>CWE</th><th>sink</th><th>状态</th><th>来源</th>" : mode === "cloud-security" ? "<th>#</th><th>名称</th><th>等级</th><th>路径类型</th><th>目标资源</th><th>状态</th>" : mode === "ctf-solver" ? "<th>#</th><th>题目</th><th>模块</th><th>题目地址</th><th>状态</th>" : mode === "incident-response" ? "<th>#</th><th>节点</th><th>类型</th><th>主机</th><th>攻击时间</th><th>状态</th>" : assetView ? "<th>#</th><th>名称</th><th>类型</th><th>位置</th><th>状态</th>" : "<th>#</th><th>名称</th><th>等级</th><th>类型</th><th>地址</th><th>状态</th>") + '</tr>');
	rows.forEach(function (f) {
		h.push(mode === "cloud-security"
			? '<tr><td>' + f.seq + '</td><td>' + esc(f.title) + '</td><td><span class="sev" style="background:' + (sevColor[f.severity] || "#888") + '">' + esc(SEVERITY_LABEL[f.severity] || f.severity) + '</span></td><td>' + esc(f.type || "-") + '</td><td>' + esc(f.resource || f.target || "-") + '</td><td>' + esc(statusTextForExport(f, mode)) + '</td></tr>'
			: mode === "ctf-solver"
			? '<tr><td>' + f.seq + '</td><td>' + esc(f.title) + '</td><td>' + esc(f.type || "-") + '</td><td>' + esc(f.target || "-") + '</td><td>' + esc(statusTextForExport(f, mode)) + '</td></tr>'
			: mode === "incident-response"
			? '<tr><td>' + f.seq + '</td><td>' + esc(f.title) + '</td><td>' + esc(f.type || "-") + '</td><td>' + esc(f.target || "-") + '</td><td>' + esc(f.timelineAt || "-") + '</td><td>' + esc(statusTextForExport(f, mode)) + '</td></tr>'
			: assetView
			? '<tr><td>' + f.seq + '</td><td>' + esc(f.title) + '</td><td>' + esc(f.type || "-") + '</td><td>' + esc(f.target || "-") + '</td><td>' + esc(stSet[f.status] || f.status) + '</td></tr>'
			: '<tr><td>' + f.seq + '</td><td>' + esc(f.title) + '</td><td><span class="sev" style="background:' + (sevColor[f.severity] || "#888") + '">' + esc(SEVERITY_LABEL[f.severity] || f.severity) + '</span></td><td>' + esc(f.type || "-") + '</td>' + (mode === "code-audit" ? '<td>' + esc(f.cwe || "-") + '</td>' : '') + '<td>' + esc(f.target || "-") + '</td><td>' + esc(statusTextForExport(f, mode)) + '</td>' + (mode === "code-audit" ? '<td>' + esc(SOURCE_LABEL[f.sourceOrigin] || f.sourceOrigin || "manual") + '</td>' : '') + '</tr>');
	});
	h.push('</table>');
	rows.forEach(function (f) {
		h.push(assetView
			? '<div class="card"><h2>#' + f.seq + ' ' + esc(f.title) + ' <span class="sev" style="background:#3a7d5f">' + esc(f.type || (mode === "binary-analysis" ? "产物" : "战果")) + '</span></h2>'
			: mode === "ctf-solver"
			? '<div class="card"><h2>#' + f.seq + ' ' + esc(f.title) + ' <span class="sev" style="background:' + (f.status === "verified" ? "#3a7d5f" : f.status === "stuck" ? "#c2182f" : "#b58a00") + '">' + esc(CTF_STATUS_LABEL[f.status] || f.status) + '</span></h2>'
			: mode === "incident-response"
			? '<div class="card"><h2>#' + f.seq + ' ' + esc(f.title) + ' <span class="sev" style="background:' + (f.status === "verified" ? "#3a7d5f" : f.status === "fixed" ? "#3b7dd8" : f.status === "false-positive" ? "#8a8a8f" : "#b58a00") + '">' + esc(TIMELINE_STATUS_LABEL[f.status] || f.status) + '</span></h2>'
			: '<div class="card"><h2>#' + f.seq + ' ' + esc(f.title) + ' <span class="sev" style="background:' + (sevColor[f.severity] || "#888") + '">' + esc(SEVERITY_LABEL[f.severity] || f.severity) + '</span></h2>');
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
	".dsh-scr-globe{position:relative;width:130px;height:130px;border-radius:50%;flex:none;background:url(\"data:image/jpeg;base64,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xojhY9gI+QhpeBySSTV/5+6tRgs3BxLbH+i3GLQFsJ9fotQ5jmOIIPy91nafI98wYXAOdyS99Nry5SUb3HyS120gWBfK2+p6nhOgdkx6RHjkRim47nbS4dzRugeSf2XL42XHGHF0rQDRI9T9lObqjHY5hgcS4kgurjaR5edrmy4byZTwv3SRXka5lTMe1jI4g6xYskD05/zWtCttKuBevwcWHHNYxzVKIi2BERAREQEREBERAREQEREBERAREQEREBERAREQX8PLyMR+/HkLDxY8jXawsrK1rUcguvIMbXfyxgNAWuRZ5cPHll3XGbTuzwutyJ2kls0gsUfmPIVtxLjuc4uce5JtQivMZPUQIiKQREQEREBERAREQEREBERAREQEREBERAREQEKIggqhxVblbd6qmVTFtytuNlVuKtuXJyVeKURFzrA4NhVbrI3XXsqUQFNmvooRAREQEREE7qIIFELMy58V8WL+Gx3RyxxgTOe/f4j7JLqrgVQr291hKWkAgkWPRBcBc7c0jgmyK81diY5wJYGkXwSP2VsOZyQ6r5qrpbOObRHaNPHNHmjUt7Pw8jHjwWss72uaRZJ4III5sV5q2xhsDWOYyQEEm3bSDTSR2+1+avs1KfT4M7E07Jmigy2+DNtcWGWMOB2vANEEhpI5FhYU7omuIie94HZzm7f25Vpzi6r8lNs1oUoiKgIiICIiAqmgE0TXuqVXEx8kgYwFznGgB5oKXCiRdqFsM3J/Gl2Rlue/JIaHPNWa4HH0ACwXClOroUoiKAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBVxECRpPYG1QpaSDwpnsZD9pEpJHHDeLB58irLjucXUBfk0cBSfyHi78/RW1NFTK7G686KqY9rdx5vyA7JC5rHFzmb+DwragSCrjSrYVbStMKirzSrgKstKuNK68Kzq4igKVsgREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAKHgIoJSilxVtxVTirbisM6tFDyqD3VTiqFyZ1eCIizSIiICIiAiIgIiICIiAq4mNcfmdtHmaulQpBoqYLk0QjAIka8H08laVySXfG1m1o23yByb9T5q2l19AiIoBERARFLQXGh3QB3VxjeCfEDHA8ApGNp707tz2CSmHwmCMSeJzvLiKPpQ8uFPoXch8cRj/AA829waCZA0tokCx9uRfmsVEUAiIgIiICIiAiIgIiICIiAiIgIiICIiAiIgIiICIiAiIgIiICIiAiIgIiICIiArkDA94bde5VtZGE1jpBuG7vwrY+xMzWhl/l9ODyqY5IQGBzOQSXXyHeg8qV3NsgCuBzfqsYN8zwP3U5TVRESHc5zg2hfYdgqURUSq3Dw9tc3ZKAqlSFbGi60q40qy0q408rpwqlXQVUFbaVcBXTjVKlERWBERAREQEREBERAREQEREBFNKEBERARFNIIREQEREBFNJSCERTSCFPl3UIgIppQgIiICIiAiIgIiICLa6Uzp9+mZP955GfDnCRv4fwImvjLKO4OsijdURfmtWas128k2IREQEREBEQoIJVDlUVQSqZVMUuKtuKqcrbja5s8l5FJUKSoXNVhERQCIiAiIgIiICIiAiIgIiICIiAiIgIiICriLQ4FxcB/291QiC6Zba4Vy7zJ5CtIiAiIgIiICIiAiIgIiICIiAiIgIiICIiAiIgIiICIiAiIgIiICIiAiIgIiICIiAiIgKuFxY8FqoRIMgGXdUd7mgkkHmq5/ZV+C2TCMge3ew8tvkj6eysCS+Hjd91WyZsfLN7T3FEd1bwLCKVCqCmxQ459VCIKgVW0q2FUDytsckWLzSqwVZBVxpXThkpV0KVQ0qoHhbS7VSOUWXpec3BmMj8DBzWEUY8qMuafoQQR9io1SXCnzpJdPxH4eO6i2B0xk2GuQHEAkXdXzXe+6lDFRERIiIgIiICIiAiIgIiICIpP0pBCIiAiIgIiICIiAiIglCoRAREQFKhEBERAREQEREBERBVIx8byx4pw7i1SiICIiAVSSpJVDiotEEqhxUuKoJWGeS0UuKpJQlQVzZVeIREWSRERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQEREBERAREQFUCqVIVpRcBVTSrQKuRltncSPoPNbY5KrgKrBVoH0VQK6MclbF0FSqAVUCtZVUonuikVAEscbHy0qVJJIAvgKEBERAREQEREBERARFPkghERARTz3TlBCKVCAinlO6CEUpyghERAREQEU2oQ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\") 0 0/auto 100% repeat-x;box-shadow:0 0 20px rgba(255,255,255,.2),-3px 0 4px #c3f4ff inset,8px 1px 13px #000 inset,-12px -1px 18px rgba(195,244,255,.6) inset,130px 0 23px rgba(0,0,0,.4) inset,78px 0 20px rgba(0,0,0,.67) inset;animation:dshEarthTex 30s linear infinite,dshGlobeFloat 7s ease-in-out infinite}",
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
	"@keyframes dshEarthTex{from{background-position:0 0}to{background-position:-260px 0}}",
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
	".dsh-scr-num.is-good b{color:var(--rt-ok-bright,#36f1b0);text-shadow:0 0 10px rgba(54,241,176,.5)}",
	".dsh-scr-num.is-warn b{color:var(--rt-sev-medium-bright,#ffd43b);text-shadow:0 0 10px rgba(255,212,59,.5)}",
	".dsh-scr-num.is-bad b{color:var(--rt-sev-high-bright,#ff6b8a);text-shadow:0 0 10px rgba(255,107,138,.5)}",
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
	".dsh-scr-sev-critical{color:var(--rt-sev-critical-bright,#ff8fa0);background:rgba(194,24,47,.30);border:1px solid rgba(255,90,110,.45)}",
	".dsh-scr-sev-high{color:var(--rt-sev-high-bright,#ffb0b0);background:rgba(255,77,77,.20);border:1px solid rgba(255,90,90,.45)}",
	".dsh-scr-sev-medium{color:var(--rt-sev-medium-bright,#ffe98a);background:rgba(255,221,51,.12);border:1px solid rgba(255,221,51,.45)}",
	".dsh-scr-sev-low{color:var(--rt-sev-low-bright,#7cc0ff);background:rgba(58,157,255,.16);border:1px solid rgba(58,157,255,.45)}",
	".dsh-scr-mode{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px;color:#e6f2ff}",
	".dsh-scr-mode .tag{width:104px;flex:none;color:#8fb4d9}",
	".dsh-scr-mode .n{margin-left:auto;font-family:monospace;color:#fff}",
	".dsh-scr-empty{padding:60px 20px;text-align:center;color:#8fb4d9;letter-spacing:.12em;font-size:15px}"
].join("\n");

var CSS = [
	".dsh-rtr-root{height:100%;display:flex;min-height:0;background:var(--dsw-alias-bg-base,#fff);color:var(--dsw-alias-label-primary,#1a1a1a);font-size:13px}",
	".dsh-rtr-side{width:168px;flex:none;border-right:1px solid var(--dsw-alias-border-l1,#e9e9ec);padding:14px 10px;display:flex;flex-direction:column;gap:2px;background:linear-gradient(180deg,color-mix(in srgb,var(--rt-accent,#4c6ef5) 3%,var(--dsw-alias-bg-base,#fff)),color-mix(in srgb,var(--rt-accent,#4c6ef5) 6%,var(--dsw-alias-bg-base,#fff)));backdrop-filter:blur(12px) saturate(1.1)}",
	".dsh-rtr-side-title{font-size:12px;letter-spacing:.12em;color:var(--dsw-alias-label-tertiary,#8a8a8f);padding:0 8px 10px;font-weight:600}",
	".dsh-rtr-side-item{display:flex;align-items:center;justify-content:space-between;gap:6px;padding:7px 10px;border:none;background:none;border-radius:8px;cursor:pointer;color:var(--dsw-alias-label-secondary,#5b5b60);font-size:13px;text-align:left;transition:background .18s,color .18s,box-shadow .18s}",
	".dsh-rtr-side-item:hover{background:var(--dsw-alias-interactive-bg-hover,color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 6%,transparent));color:var(--dsw-alias-label-primary,#1a1a1a)}",
	".dsh-rtr-side-item.is-active{background:color-mix(in srgb,var(--rt-accent,#4c6ef5) 10%,transparent);color:var(--rt-accent,#4c6ef5);font-weight:600;box-shadow:inset 3px 0 0 0 var(--rt-accent,#4c6ef5),inset 0 0 0 1px color-mix(in srgb,var(--rt-accent,#4c6ef5) 10%,transparent)}",
	".dsh-rtr-count{font-size:11px;min-width:22px;text-align:center;border-radius:999px;padding:1px 8px;background:color-mix(in srgb,var(--rt-accent,#4c6ef5) 10%,transparent);border:1px solid color-mix(in srgb,var(--rt-accent,#4c6ef5) 28%,transparent);color:var(--rt-accent,#4c6ef5);font-variant-numeric:tabular-nums}",
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
	".dsh-rtr-btn.is-danger{color:var(--dsw-alias-state-error-primary,#d5333c);border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary,#d5333c) 35%,transparent)}",
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
	"@media (max-width:720px){.dsh-rtr-root{flex-direction:column}.dsh-rtr-side{width:auto;flex-direction:row;overflow-x:auto;padding:8px}.dsh-rtr-side-title{display:none}.dsh-rtr-side-item{white-space:nowrap}}",
	".dsh-rtr-exportpop{position:fixed;z-index:300;visibility:hidden;background:var(--rt-surface-card,#fff);border:1px solid var(--rt-border,#e9e9ec);border-radius:10px;box-shadow:0 10px 34px rgba(9,20,40,.18);padding:6px;min-width:180px;display:flex;flex-direction:column}",
	".dsh-rtr-exportitem{border:none;background:none;text-align:left;padding:8px 12px;font-size:12.5px;border-radius:7px;cursor:pointer;color:var(--dsw-alias-label-primary,#1a1a1a)}",
	".dsh-rtr-exportitem:hover{background:var(--rt-surface-tint,#f7f7f8)}"
].join("\n");

function installStyles() {
	if (document.getElementById("dsh-rtr-style")) return function () {};
	// 红队四插件共享设计令牌（幂等注入，同 id 先到先得；与 pulse/hunter/webshell 同一份内容）
	if (!document.getElementById("dsh-rt-tokens")) {
		var tok = document.createElement("style");
		tok.id = "dsh-rt-tokens";
		tok.textContent = "body{--rt-sev-critical:#c2182f;--rt-sev-high:#ff4d4d;--rt-sev-medium:#d9b00c;--rt-sev-low:#3b7dd8;--rt-sev-critical-bright:#ff8fa0;--rt-sev-high-bright:#ff6b8a;--rt-sev-medium-bright:#ffd43b;--rt-sev-low-bright:#4dabf7;--rt-ok:#2f9e44;--rt-dead:#c92a2a;--rt-ok-bright:#36f1b0;--rt-dead-bright:#ff8787;--rt-accent:var(--dsw-alias-state-business-primary,#4c6ef5);--rt-surface-card:var(--dsw-alias-bg-base,#fff);--rt-surface-tint:color-mix(in srgb,var(--dsw-alias-label-primary,#1a1a1a) 4%,var(--dsw-alias-bg-base,#fff));--rt-border:var(--dsw-alias-border-l1,#e9e9ec);--rt-mono:ui-monospace,\"SF Mono\",SFMono-Regular,Menlo,Consolas,monospace;--rt-navy-bg:rgba(8,24,46,.96);--rt-navy-bg-soft:rgba(12,32,62,.6);--rt-navy-line:rgba(58,157,255,.45);--rt-navy-line-soft:rgba(58,157,255,.28);--rt-navy-text:#e8f3ff;--rt-navy-text-2:#cfe6ff;--rt-navy-body:#b9d2ee;--rt-navy-dim:#7d97b8;--rt-navy-dim-2:#8fb4d9;--rt-navy-accent:#38d4ff;--rt-navy-accent-2:#3a9dff}";
		document.head.appendChild(tok);
	}
	var el = document.createElement("style");
	el.id = "dsh-rtr-style";
	el.textContent = CSS + CSS_SCREEN;
	document.head.appendChild(el);
	return function () { el.remove(); };
}

//#endregion

var LABEL_BY_TYPE_MODES = { "av-evasion": 1, "ctf-solver": 1, "binary-analysis": 1, "attack-defense": 1 };
function Chip(props) {
	if (props.typeLabel) return React.createElement("span", { className: "dsh-rtr-typechip is-static" }, props.typeLabel);
	return React.createElement("span", { className: "dsh-rtr-sev dsh-rtr-sev-" + props.severity }, SEVERITY_LABEL[props.severity] || props.severity);
}
function statusTextForExport(f, mode) {
	if (mode === "code-audit" && f.status === "pending" && f.auditMode !== "dynamic") return "待动态验证";
	if (mode === "cloud-security") return CLOUDPATH_STATUS_LABEL[f.status] || f.status;
	if (mode === "ctf-solver") return CTF_STATUS_LABEL[f.status] || f.status;
	if (mode === "incident-response") return TIMELINE_STATUS_LABEL[f.status] || f.status;
	return STATUS_LABEL[f.status] || f.status;
}
function Btn(props) {
	return React.createElement("button", {
		className: "dsh-rtr-btn" + (props.primary ? " is-primary" : "") + (props.danger ? " is-danger" : ""),
		onClick: props.onClick, disabled: props.disabled, type: "button"
	}, props.children);
}
/** 视口自适应 popover（手动触发打开，外点/ESC 关闭，位置钳制）——导出菜单等目录收纳用。 */
function PopMenu(props) {
	var ref = useRef(null);
	useEffect(function () {
		var el = ref.current;
		if (!el) return;
		var rect = el.getBoundingClientRect();
		var vw = window.innerWidth, vh = window.innerHeight;
		var w = el.offsetWidth || 200;
		var left = props.anchor.left, top = props.anchor.bottom + 6;
		if (left + w > vw - 8) left = Math.max(8, vw - w - 8);
		if (top + rect.height > vh - 8) top = Math.max(8, props.anchor.top - rect.height - 6);
		el.style.left = left + "px";
		el.style.top = top + "px";
		el.style.visibility = "visible";
	}, []);
	useEffect(function () {
		var onDown = function (e) { if (ref.current && !ref.current.contains(e.target)) props.onClose(); };
		var onKey = function (e) { if (e.key === "Escape") props.onClose(); };
		document.addEventListener("mousedown", onDown);
		document.addEventListener("keydown", onKey);
		return function () {
			document.removeEventListener("mousedown", onDown);
			document.removeEventListener("keydown", onKey);
		};
	}, []);
	return React.createElement("div", { ref: ref, className: "dsh-rtr-exportpop", style: { left: "0px", top: "0px", visibility: "hidden" } },
		(props.items || []).map(function (it) {
			return React.createElement("button", { key: it.label, type: "button", className: "dsh-rtr-exportitem", title: it.title || "", onClick: function () { props.onClose(); it.onClick(); } }, it.label);
		}));
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
		// 状态卡按模式词表出（redteam 台账四态、ctf 三态——不出永远为 0 的幽灵卡，卡点可一键过滤）
		var stLabel = props.mode === "ctf-solver" ? CTF_STATUS_LABEL : LEDGER_STATUS_LABEL;
		var lk = props.mode === "ctf-solver" ? ["pending", "stuck", "verified"] : ["pending", "verified", "fixed", "false-positive"];
		var cards = [{ key: "", label: "任务总数", color: null }].concat(lk.map(function (s) {
			return { key: s, label: stLabel[s], color: s === "verified" ? "#2f9e63" : s === "stuck" ? "#c2182f" : s === "fixed" ? "#3b7dd8" : s === "false-positive" ? "#8a8a8f" : "#b58a00" };
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
				distSection(props.mode === "ctf-solver" ? "模块分布" : "任务形态分布", (stats.byType || []).map(function (x) { return { key: x.type, label: x.type, count: x.count }; })),
				distSection("证据等级分布", ["impact", "confirmed", "partial", "unknown"].map(function (e) { return { key: e, label: EVIDENCE_LABEL[e] || e, count: (stats.byEvidence ? stats.byEvidence[e] : 0) || 0 }; }).filter(function (i) { return i.count > 0; }))));
	}
	if (props.archetype === "assets") {
		// 状态卡按模式词表出（binary=suspect 三态、av=detected 三态——不再出永远为 0 的幽灵卡）
		var stSet = props.mode === "binary-analysis" ? BIN_STATUS_LABEL : props.mode === "av-evasion" ? AV_STATUS_LABEL : ASSET_STATUS_LABEL;
		var stKeys = props.mode === "binary-analysis" ? ["pending", "suspect", "verified"] : props.mode === "av-evasion" ? ["pending", "verified", "detected"] : ["pending", "verified", "false-positive", "fixed"];
		var cards = [{ key: "", label: "总数", color: null }].concat(stKeys.map(function (s) {
			return { key: s, label: stSet[s], color: s === "verified" ? "#2f9e63" : s === "suspect" ? "#b58a00" : s === "false-positive" ? "#8a8a8f" : s === "fixed" ? "#3b7dd8" : "#b58a00" };
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
		// 状态卡按模式词表出（IR 默认五态全出——code-reviewed=复核通过有语义，补全五卡不缺过滤面）
		var stKeys = ["pending", "code-reviewed", "verified", "false-positive", "fixed"];
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
				distSection("严重度分布", SEVERITY_ORDER.map(function (s) { return { key: s, label: SEVERITY_LABEL[s], count: (stats.bySeverity ? stats.bySeverity[s] : 0) || 0, onClick: function () { props.onSeverity(s); } }; }).filter(function (i) { return i.count > 0; })),
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
			(props.mode === "code-audit" || props.mode === "pentest") ? distSection("来源", (stats.bySource || []).map(function (c) { return { key: c.source, label: SOURCE_LABEL[c.source] || c.source, count: c.count }; })) : null,
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
				mode === "ctf-solver" ? null : React.createElement("span", null, "优先级", React.createElement("b", null, SEVERITY_LABEL[f.severity] || f.severity)),
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
				React.createElement("span", null, "状态", React.createElement("b", null, statusLabelSetFor("assets", mode)[f.status] || f.status)),
				React.createElement("span", null, "证据等级", React.createElement("b", null, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel)),
				f.sampleHash ? React.createElement("span", null, "关联样本", React.createElement("b", { style: { fontFamily: "monospace" } }, f.sampleHash.slice(0, 16) + "…")) : null,
				f.family ? React.createElement("span", null, "家族", React.createElement("b", null, f.family)) : null,
				f.packer ? React.createElement("span", null, "壳", React.createElement("b", null, f.packer)) : null,
				React.createElement("span", null, "登记时间", React.createElement("b", null, fmtTime(f.createdAt))),
				f.verifiedAt ? React.createElement("span", null, "验证时间", React.createElement("b", null, fmtTime(f.verifiedAt))) : null),
			mode === "binary-analysis" && f.impact ? Block({ title: "能力与危害" }, f.impact) : null,
			f.description || f.summary ? Block({ title: meta.descLabel }, f.description || f.summary) : null,
			f.chain ? Block({ title: meta.chainLabel }, f.chain) : null,
			f.poc ? Block({ title: meta.pocTitle }, f.poc) : null,
			mode === "attack-defense" && (f.baseline || f.diffEvidence) ? React.createElement("div", { className: "dsh-rtr-duo" },
				React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 12, color: "#8a8a8f" } }, "对照三件套 · 基线"), React.createElement("pre", null, f.baseline || "（未填）")),
				React.createElement("div", null, React.createElement("h4", { style: { margin: "0 0 4px", fontSize: 12, color: "#8a8a8f" } }, "差分（翻转）"), React.createElement("pre", null, f.diffEvidence || "（未填）"))) : null,
			mode === "attack-defense" && f.markerEcho ? Block({ title: "marker 逐字回显" }, f.markerEcho) : null,
			mode === "attack-defense" && f.requestPkt ? Block({ title: "完整请求包" }, f.requestPkt) : null,
			mode === "attack-defense" && f.responsePkt ? Block({ title: "关键响应" }, f.responsePkt) : null,
			f.iocs ? Block({ title: mode === "av-evasion" ? "环境 / 引擎效果清单" : "IOC 清单" }, f.iocs) : null,
			f.detectionRule ? Block({ title: "检测规则（YARA/Sigma）" }, f.detectionRule) : null,
			f.evidence ? Block({ title: "证据引用" }, f.evidence) : null,
			f.chainNodes && f.chainNodes.length ? Block({ title: "链路节点（AttackAtlas 互链）" }, f.chainNodes.map(function (n) { return n.label + "（" + n.kind + (n.major ? "·重大成果" : "") + "）"; }).join("\n")) : null,
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
				React.createElement("h4", null, "攻击路径链（入口→身份→权限→资源→影响）"),
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
			f.cvss ? React.createElement("span", null, "CVSS", React.createElement("b", null, f.cvss.slice(0, 40))) : null,
			React.createElement("span", null, "证据等级", React.createElement("b", null, EVIDENCE_LABEL[f.evidenceLevel] || f.evidenceLevel)),
			React.createElement("span", null, audit ? "sink 位置" : "地址", React.createElement("b", null, f.target || "未填写")),
			React.createElement("span", null, "发现时间", React.createElement("b", null, fmtTime(f.createdAt))),
			f.verifiedAt ? React.createElement("span", null, "验证时间", React.createElement("b", null, fmtTime(f.verifiedAt))) : null,
			(audit || mode === "pentest") ? React.createElement("span", null, "来源", React.createElement("b", null, SOURCE_LABEL[f.sourceOrigin] || f.sourceOrigin)) : null,
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
		f.chainNodes && f.chainNodes.length ? Block({ title: "链路节点（AttackAtlas 互链）" }, f.chainNodes.map(function (n) { return n.label + "（" + n.kind + (n.major ? "·重大成果" : "") + "）"; }).join("\n")) : null,
		f.verifyNote ? Block({ title: "复核注记" }, f.verifyNote) : null,
		f.retestNote ? Block({ title: "复测记录" }, f.retestNote + (f.retestAt ? "（" + fmtTime(f.retestAt) + "）" : "")) : null,
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
	var exportMenu = useState(null); var setExportMenu = exportMenu[1];
	var page = useState(1); var setPage = page[1];
	var severity = useState(""); var setSeverity = severity[1];
	var status = useState(""); var setStatus = status[1];
	var q = useState(""); var setQ = q[1];
	var qDraft = useState(""); var setQDraft = qDraft[1];
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
						stats: res.stats || null, counts: {}, meta: res.meta, groups: groups
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

	// 搜索防抖：停键 300ms 才触发查询（不再每键一 POST 打全模式表）
	useEffect(function () {
		var t = setTimeout(function () { setQ(qDraft[0]); }, 300);
		return function () { clearTimeout(t); };
	}, [qDraft[0]]);

	var view = data[0] || {};
	var rows = view.rows || [];
	var stats = view.stats || { total: view.total || 0, bySeverity: {}, byStatus: {}, byType: [], byCwe: [], bySource: [], byTarget: [] };
	var sesMeta = view.meta || { targetLabel: "", version: "", scope: "" };
	var selectedIds = Object.keys(selected[0]).filter(function (k) { return selected[0][k]; });

	// 行唯一键：跨会话视图里 id 只在会话内唯一（每个会话都有一条 pentest-1）——sessionId+id 复合，防 React 重复 key 与勾选/展开串行。
	function uidOf(f) { return (f.sessionId || sessionId) + ":" + f.id; }
	function toggle(f) { var u = uidOf(f); setConfirmDel(""); setExpanded(expanded[0] === u ? "" : u); }
	function onVerify(f) {
		api("finding.verify", { sessionId: f.sessionId || sessionId, mode: mode, id: f.id })
			.then(function (r) {
				if (r && r.ok) { setNotice("验证请求已发送到原会话（# " + f.seq + " " + f.title + "），复核后状态由会话回写"); return; }
				if (r && r.unreachable) {
					// 原会话已删/不可达：人工复核兜底——两段确认三出口（确定=verified / 第二段确定=模式词表内的判伪或重置项 / 取消=不标记）；
					// 确定项与判伪词均按模式词表取（binary=已定论/疑似、av=过检/被检出、其余=已验证/误报或已失效）。
					var okSet = statusLabelSetFor(meta.archetype, mode) || STATUS_LABEL;
					var opts = (STATUS_OPTIONS_OF[mode] || Object.keys(STATUS_LABEL)).filter(function (s) { return s !== "pending"; });
					var neg = opts.indexOf("false-positive") !== -1 ? "false-positive" : (opts.indexOf("suspect") !== -1 ? "suspect" : (opts.indexOf("stuck") !== -1 ? "stuck" : "pending"));
					var negText = (okSet[neg] || neg) + "（" + neg + "）";
					var posText = (okSet.verified || "已验证") + "（verified）";
					var ok = window.confirm(r.error + "\n\n人工复核后直接标记？\n确定=标记「" + posText + "」，取消=选择其他标记");
					if (!ok && !window.confirm("标记为「" + negText + "」？\n确定=标记，取消=不做标记")) { setNotice("已取消标记——成果保持原状态"); return; }
					var status = ok ? "verified" : neg;
					var statusText = ok ? posText : negText;
					var note = window.prompt("人工复核结论（写入验证记录）：", "原会话不可达，人工复核" + (ok ? "通过" : (neg === "false-positive" ? "判伪" : neg === "suspect" ? "定疑似" : neg === "stuck" ? "记卡点" : "重置"))) || "";
					api("finding.mark", { sessionId: f.sessionId || sessionId, id: f.id, status: status, verifyNote: note })
						.then(function (m) { setNotice(m && m.ok ? "已人工标记 #" + f.seq + " → " + statusText : "标记失败：" + ((m && m.error) || "未知")); if (props.onRefreshCounts) props.onRefreshCounts(); if (grouped[0]) fetchGroups(); else fetchList({}); })
						.catch(function (e) { setNotice("标记失败：" + (e && e.message ? e.message : e)); });
					return;
				}
				setNotice("验证请求失败：" + ((r && r.error) || "未知错误"));
			})
			.catch(function (e) { setNotice("验证请求失败：" + (e && e.message ? e.message : e)); });
	}
	var LIVE_BUSY = {}; // 实测 in-flight 防重（key=sessionId:id——流水线含搜索+探测，连点会并发跑多条并重复扣平台配额）
	function onLiveVerify(f) {
		// 一键实测：调 dsh-hunter 验证流水线（L0 指纹判定/L1 仅授权资产），结果回写 finding。
		if (mode !== "code-audit") { setNotice("实测仅支持代码审计模式 finding"); return; }
		var busyKey = (f.sessionId || sessionId) + ":" + f.id;
		if (LIVE_BUSY[busyKey]) { setNotice("实测进行中——请等待本轮完成（搜索+探测为秒级到分钟级）"); return; }
		LIVE_BUSY[busyKey] = true;
		setNotice("实测进行中：搜索资产 → 存活探测 → 指纹校验 →" + (f.auditMode === "dynamic" ? "影响面评估…" : "EXP 验证（L1 仅授权资产）…"));
		var send = function (tok) {
			return fetch("/dsh-hunter/verify.live", {
				method: "POST",
				headers: tok ? { "content-type": "application/json", "x-dsh-csrf": tok } : { "content-type": "application/json" },
				body: JSON.stringify({ sessionId: f.sessionId || sessionId, findingId: f.id, allMode: false })
			});
		};
		var parse = function (r) {
			return r.text().then(function (t) {
				try { return JSON.parse(t); } catch { throw new Error("HTTP " + r.status + (t ? "：" + String(t).slice(0, 80) : "")); }
			});
		};
		csrfOf("/dsh-hunter").then(function (hTok) {
			return send(hTok).then(function (r) {
				if (r.status === 403) {
					delete dshCsrf["/dsh-hunter"]; // token 失效（宿主重启轮换）——重取一次再发
					return csrfOf("/dsh-hunter").then(function (t2) { return send(t2); }).then(parse);
				}
				return parse(r);
			});
		}).then(function (r) {
			if (r && r.ok) {
				setNotice("实测完成（#" + f.seq + "）：" + r.summary
					+ (r.suggestions && r.suggestions.length ? "｜下一步：" + r.suggestions.join("；") : "")
					+ (r.notified ? "" : "（原会话不可达，未注入通知）"));
				if (grouped[0]) fetchGroups(); else fetchList({});
				return;
			}
			setNotice("实测失败：" + ((r && r.error) || "未知错误"));
		}).catch(function (e) { setNotice("实测失败：" + (e && e.message ? e.message : e)); })
			.finally(function () { LIVE_BUSY[busyKey] = false; });
	}
	function onDelete(f) {
		var u = uidOf(f);
		if (confirmDel[0] !== u) { setConfirmDel(u); return; }
		api("finding.delete", { sessionId: f.sessionId || sessionId, id: f.id })
			.then(function () { setConfirmDel(""); setNotice("已删除 #" + f.seq + "（统计已同步）"); if (props.onRefreshCounts) props.onRefreshCounts(); if (grouped[0]) fetchGroups(); else fetchList({}); })
			.catch(function (e) { setNotice("删除失败：" + (e && e.message ? e.message : e)); });
	}
	function fetchAllForExport() {
		var rtx = rangeIso(range[0], customFrom[0], customTo[0]);
		var acc = [];
		function pageOf(n) {
			return api("findings.list", { scope: "all", sessionId: sessionId, mode: mode, page: n, pageSize: 100, severity: severity[0], status: status[0], q: q[0], from: rtx[0], to: rtx[1] })
				.then(function (raw) {
					var l = ((raw || {}).list) || {};
					acc = acc.concat(l.rows || []);
					if (n < (l.pages || 1)) return pageOf(n + 1); // 翻页取全——导出不受单页 100 条截断
					return acc;
				});
		}
		return pageOf(1);
	}
	function exportAll() {
		fetchAllForExport().then(function (all) {
			download(meta.allName + localDate() + ".md", mdTable(all, meta.tableTitle, mode));
			setNotice("已导出 " + all.length + " 条（当前筛选范围）");
		});
	}
	function exportSelected() {
		// 分组态从分组条目取行（分组视图 rows 为空——勾选导出不再永远提示先勾选）
		var pool = grouped[0] ? (view.groups || []).reduce(function (a, g) { return a.concat(g.items); }, []) : rows;
		var picked = pool.filter(function (f) { return selected[0][uidOf(f)]; });
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
			download(mode + "-overview-" + localDate() + ".md", mdOverview(sesMeta, stats, all, mode));
			setNotice("总览报告已导出（MD）");
		});
	}
	function exportHtml() {
		fetchAllForExport().then(function (all) {
			download(mode + "-report-" + localDate() + ".html", htmlReport(sesMeta, stats, all, mode), "text/html");
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
		var uid = uidOf(f);
		var stLabelSet = statusLabelSetFor(meta2.archetype, mode);
		return React.createElement("div", { key: uid, className: "dsh-rtr-row" },
			React.createElement("div", { className: "dsh-rtr-rowhead", onClick: function () { toggle(f); } },
				React.createElement("input", {
					type: "checkbox", className: "dsh-rtr-check", checked: !!selected[0][uid],
					onClick: function (e) { e.stopPropagation(); },
					onChange: function (e) { var next = Object.assign({}, selected[0]); next[uid] = e.target.checked; setSelected(next); }
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
					React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === uid ? "确认删除" : "删除"))),
				expanded[0] === uid ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onLiveVerify: onLiveVerify, onExportOne: exportOne }) : null);
	};

	var tlItem = function (f) {
		var stSet = statusLabelSetFor(meta.archetype, mode);
		var uid = uidOf(f);
		var open = expanded[0] === uid;
		return React.createElement("div", { key: uid, className: "dsh-rtr-tl-item" },
			React.createElement("div", { className: "dsh-rtr-tl-rail" },
				React.createElement("span", { className: "dsh-rtr-tl-dot" }),
				React.createElement("span", { className: "dsh-rtr-tl-line" })),
			React.createElement("div", { className: "dsh-rtr-tl-body" },
				React.createElement("div", { className: "dsh-rtr-tl-time" }, fmtTimelineAt(f.timelineAt)),
				React.createElement("div", { className: "dsh-rtr-tl-card" },
					React.createElement("div", { className: "dsh-rtr-rowhead", onClick: function () { toggle(f); } },
						React.createElement("input", {
							type: "checkbox", className: "dsh-rtr-check", checked: !!selected[0][uid],
							onClick: function (e) { e.stopPropagation(); },
							onChange: function (e) { var next = Object.assign({}, selected[0]); next[uid] = e.target.checked; setSelected(next); }
						}),
						React.createElement("span", { className: "dsh-rtr-seq" }, "#" + f.seq),
						React.createElement("span", { className: "dsh-rtr-typechip is-static" }, f.type || "未分类"),
						React.createElement(Chip, { severity: f.severity, typeLabel: LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : null }),
						React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + f.status }, stSet[f.status] || f.status),
						React.createElement("span", { className: "dsh-rtr-title" }, f.title),
						React.createElement("span", { className: "dsh-rtr-rowactions", onClick: function (e) { e.stopPropagation(); } },
							React.createElement(Btn, { onClick: function () { onVerify(f); } }, "验证"),
							React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === uid ? "确认删除" : "删除"))),
					React.createElement("div", { className: "dsh-rtr-tl-meta", onClick: function () { toggle(f); } },
						React.createElement("span", null, "主机 ", React.createElement("b", null, f.target || "（未填）")),
						React.createElement("span", null, "证据 ", React.createElement("b", null, f.evidence || "（未填）")),
						React.createElement("span", { className: "dsh-rtr-tl-concl" }, f.summary || "")),
					open ? React.createElement(Detail, { f: f, mode: mode, meta: meta, onVerify: onVerify, onLiveVerify: onLiveVerify, onExportOne: exportOne }) : null)));
	};

	var cpItem = function (f) {
		var stSet = statusLabelSetFor(meta.archetype, mode);
		var uid = uidOf(f);
		var open = expanded[0] === uid;
		var hop = function (label, value) {
			return React.createElement("span", { className: "dsh-rtr-cp-hop", title: value || "" },
				React.createElement("i", null, label),
				React.createElement("b", null, (value || "（未填）").slice(0, 120)));
		};
		return React.createElement("div", { key: uid, className: "dsh-rtr-cp-item" },
			React.createElement("div", { className: "dsh-rtr-cp-card" },
				React.createElement("div", { className: "dsh-rtr-rowhead", onClick: function () { toggle(f); } },
					React.createElement("input", {
						type: "checkbox", className: "dsh-rtr-check", checked: !!selected[0][uid],
						onClick: function (e) { e.stopPropagation(); },
						onChange: function (e) { var next = Object.assign({}, selected[0]); next[uid] = e.target.checked; setSelected(next); }
					}),
					React.createElement("span", { className: "dsh-rtr-seq" }, "#" + f.seq),
					React.createElement("span", { className: "dsh-rtr-typechip is-static" }, f.type || "未分类"),
					React.createElement(Chip, { severity: f.severity, typeLabel: LABEL_BY_TYPE_MODES[mode] ? (f.type || "未标注") : null }),
					React.createElement("span", { className: "dsh-rtr-st dsh-rtr-st-" + f.status }, stSet[f.status] || f.status),
					React.createElement("span", { className: "dsh-rtr-title" }, f.title),
					React.createElement("span", { className: "dsh-rtr-rowactions", onClick: function (e) { e.stopPropagation(); } },
						React.createElement(Btn, { onClick: function () { onVerify(f); } }, "验证"),
						React.createElement(Btn, { danger: true, onClick: function () { onDelete(f); } }, confirmDel[0] === uid ? "确认删除" : "删除"))),
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
		// 分组态：按路径类型分组渲染（此前 cloudpath 分支不消费 groups——点分组必现假空态）
		if (grouped[0]) {
			var cpGroups = view.groups || [];
			listBody = cpGroups.length === 0
				? React.createElement("div", { className: "dsh-rtr-empty" }, meta.empty, React.createElement("br", null), rangeHint(range[0]))
				: cpGroups.map(function (g) {
					return React.createElement("div", { key: g.target },
						React.createElement("div", { className: "dsh-rtr-grouphead" }, g.target, React.createElement("span", { className: "dsh-rtr-count" }, g.count + " 条")),
						React.createElement("div", { className: "dsh-rtr-cp" }, g.items.map(cpItem)));
				});
		} else {
			var cpRows = rows.slice().sort(function (a, b) { return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity); });
			listBody = cpRows.length === 0
				? React.createElement("div", { className: "dsh-rtr-empty" },
					meta.empty, React.createElement("br", null),
					rangeHint(range[0]), React.createElement("br", null),
					"会话内模型会把攻击路径通过 redteam_finding_register 登记到这里（也可让模型补登记：\"把攻击路径登记到成果页\"）。")
				: React.createElement("div", { className: "dsh-rtr-cp" }, cpRows.map(cpItem));
		}
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
		(notice[0] && String(notice[0]).trim()) ? React.createElement("div", { className: "dsh-rtr-notice" }, notice[0]) : null,
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
			React.createElement("input", { className: "dsh-rtr-search", placeholder: "搜索名称/简介/地址/CWE", value: qDraft[0], onChange: function (e) { setQDraft(e.target.value); } }),
			meta.archetype !== "timeline" ? React.createElement(Btn, { onClick: function () { setGrouped(!grouped[0]); } }, grouped[0] ? "平铺视图" : meta.groupLabel) : null,
			React.createElement("span", { className: "dsh-rtr-spacer" }),
			React.createElement("span", { style: { position: "relative" } },
				React.createElement(Btn, { onClick: function (e) {
					var r = e.currentTarget.getBoundingClientRect();
					setExportMenu(exportMenu[0] ? null : { left: r.left, top: r.top, bottom: r.bottom });
				} }, exportMenu[0] ? "导出 ▴" : "导出 ▾"),
				exportMenu[0] ? React.createElement(PopMenu, { anchor: exportMenu[0], onClose: function () { setExportMenu(null); }, items: [
					{ label: "总览（MD）", title: "当前筛选范围导出 MD 总览", onClick: exportOverview },
					{ label: meta.archetype === "assets" ? "清单（表格）" : "全部（表格）", title: "翻页取全后导出表格", onClick: exportAll },
					{ label: "报告包（HTML）", title: "HTML 报告包，可浏览器打印成 PDF", onClick: exportHtml }
				] }) : null),
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
	var err = useState(""); var setErr = err[1];
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
			.then(function (res) { setErr(""); setData((res || {}).overview || null); })
			.catch(function (e) { setData(null); setErr(e && e.message ? e.message : String(e)); });
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
				React.createElement("div", { className: "dsh-scr-empty" }, err[0] ? "全局数据读取失败：" + err[0] + "（15 秒后自动重试）" : "正在接入全局数据…")));
	}
	var numCard = function (v, label, cls) { return React.createElement("div", { className: "dsh-scr-num " + (cls || "") }, React.createElement("b", null, v), React.createElement("span", null, label)); };
	var total = ov.total || 0;
	var maxMode = Math.max(1, ...SCR_MODE_VOCAB.map(function (m) { return (ov.byMode[m] || 0); }));
	var sevOrder = ["critical", "high", "medium", "low"];
	var sevColors = { critical: "#c2182f", high: "#ff4d4d", medium: "#ffdd33", low: "#3a9dff" };
	// 风险口径：严重度统计只计漏洞型四模式（渗透/代审/应急/云）——binary/av 等产物型的默认 medium 不混入漏洞等级口径
	var SEV_SCOPE_MODES = { "pentest": 1, "code-audit": 1, "incident-response": 1, "cloud-security": 1 };
	var sevScoped = { critical: 0, high: 0, medium: 0, low: 0 };
	for (const f of (ov.recent || [])) if (SEV_SCOPE_MODES[f.mode] && sevScoped[f.severity] !== undefined) sevScoped[f.severity] += 1;
	var sevSource = (ov.recent || []).some(function (f) { return SEV_SCOPE_MODES[f.mode]; }) ? sevScoped : ov.bySeverity;
	var sevTotal = sevOrder.reduce(function (n, s) { return n + (sevSource[s] || 0); }, 0) || 1;
	var sevMax = Math.max.apply(null, sevOrder.map(function (s) { return sevSource[s] || 0; })) || 1;
	var acc = 0;
	var donutStops = sevOrder.map(function (s) {
		var from = acc / sevTotal * 100;
		acc += sevSource[s] || 0;
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
		var n = Math.min(6, t.key === "risk" ? (sevSource.critical || 0) + (sevSource.high || 0) : (ov.byStatus[t.key] || 0));
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
					numCard((function () { // 严重+高危只计漏洞型模式（渗透/代审/应急/云）——ad 权限价值级/av 检出等不混入漏洞等级口径
						var FM = { "pentest": 1, "code-audit": 1, "incident-response": 1, "cloud-security": 1 };
						return (ov.recent || []).reduce(function (n, f) { return n + (FM[f.mode] && (f.severity === "critical" || f.severity === "high") ? 1 : 0); }, 0);
					})(), "严重+高危（漏洞型）", "is-bad"))),
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
						["pending", "suspect", "verified", "detected", "stuck", "false-positive", "fixed"].map(function (s, i) {
							var names = { pending: "待验证·进行中", suspect: "疑似·未定论", verified: "已验证·有效", detected: "被检出", stuck: "卡点", "false-positive": "证伪·失效", fixed: "已交付·路由" };
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
									var v = Math.max(0.04, (sevSource[s] || 0) / sevMax);
									return React.createElement("div", { key: "b3-" + s, className: "dsh-scr-b3slot", style: { "--x": (si * 3.2 - 4.8) + "em", color: sevColors[s], "--v": v.toFixed(3) } },
										React.createElement("div", { className: "dsh-scr-b3bar" },
											React.createElement("i"), React.createElement("i"), React.createElement("i"), React.createElement("i")),
										React.createElement("div", { className: "dsh-scr-b3num" }, String(sevSource[s] || 0)));
								}))),
						React.createElement("div", { className: "dsh-scr-legend" }, sevOrder.map(function (s) {
							return React.createElement("span", { key: s }, React.createElement("i", { style: { background: sevColors[s] } }), SEVERITY_LABEL[s] + " " + (sevSource[s] || 0));
						}))),
					React.createElement("div", { className: "dsh-scr-panel", style: { flex: 1 } },
						React.createElement("h4", null, "证据等级分布"),
						["impact", "confirmed", "partial", "unknown"].map(function (e, i) {
							var names = { impact: "影响已证", confirmed: "已证实", partial: "部分证据", unknown: "未知" };
							var v = ov.byEvidence[e] || 0;
							return React.createElement("div", { key: e, className: "dsh-scr-bar" },
								React.createElement("span", { className: "lbl" }, names[e]),
								React.createElement("span", { className: "track" }, React.createElement("span", { style: { display: "block", width: (v / Math.max(1, total) * 100) + "%", height: "100%", borderRadius: 4, background: ["#36f1b0", "#7ce8ff", "#ffc93c", "#8fb4d9"][i] } })),
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

	var refreshCounts = useCallback(function () {
		if (!sessionId) return;
		api("counts.all", {}).then(function (raw) { setCounts(((raw || {}).counts) || {}); }).catch(function () {});
	}, [sessionId]);
	useEffect(function () { refreshCounts(); }, [refreshCounts]);

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
					: React.createElement(ModePage, { sessionId: sessionId, mode: mode[0], onRefreshCounts: refreshCounts })));
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
	ctx.effect(function () { return installStyles(); }, "dsh-redteam-results: styles");
	injectVisibleConversationView(ctx, "showRedteamResults", function () {
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

module.exports = { name: "dsh-redteam-results-client", inject: ["slots", "settingsScope"], apply: apply };
return module.exports; } });
