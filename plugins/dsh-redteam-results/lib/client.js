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
	".dsh-scr-globewrap{position:relative;width:176px;height:176px;display:flex;align-items:center;justify-content:center;flex:none}",
	".dsh-scr-globe{position:relative;width:116px;height:116px;border-radius:50%;background:radial-gradient(circle at 35% 32%,#5ec8ff 0%,#0f63bd 36%,#062f6e 68%,#021a3d 100%);box-shadow:0 0 36px rgba(56,190,255,.5),inset -16px -14px 36px rgba(0,0,0,.6);overflow:hidden;animation:dshGlobeFloat 6s ease-in-out infinite}",
	".dsh-scr-grat{position:absolute;inset:0;background:repeating-linear-gradient(90deg,rgba(150,225,255,.30) 0 1px,transparent 1px 19px),repeating-linear-gradient(0deg,rgba(150,225,255,.15) 0 1px,transparent 1px 17px);animation:dshGrat 8s linear infinite}",
	".dsh-scr-sweep{position:absolute;inset:0;background:linear-gradient(100deg,transparent 40%,rgba(170,235,255,.38) 50%,transparent 60%);animation:dshSweep 3.4s linear infinite}",
	".dsh-scr-orbit{position:absolute;left:50%;top:50%;border:1px solid rgba(90,190,255,.35);border-radius:50%}",
	".dsh-scr-orbit::after{content:\"\";position:absolute;top:-3.5px;left:50%;width:7px;height:7px;border-radius:50%;background:#7fe9ff;box-shadow:0 0 12px #7fe9ff}",
	".dsh-scr-orbit.o1{width:148px;height:148px;margin:-74px 0 0 -74px;animation:dshOrbitSpin 13s linear infinite}",
	".dsh-scr-orbit.o2{width:170px;height:170px;margin:-85px 0 0 -85px;border-style:dashed;border-color:rgba(255,130,225,.32);animation:dshOrbitSpin 23s linear infinite reverse}",
	".dsh-scr-orbit.o2::after{background:#ff8ce5;box-shadow:0 0 12px #ff8ce5}",
	".dsh-scr-planet{position:absolute;border-radius:50%;border:1px solid currentColor;background:radial-gradient(circle,transparent 58%,currentColor 100%);box-shadow:0 0 9px currentColor;transform-style:preserve-3d;animation:dshPlanetSpin 10s linear infinite}",
	".dsh-scr-planet::before{content:\"\";position:absolute;inset:-1px;border-radius:50%;border:1px solid currentColor;transform:rotateY(90deg)}",
	".dsh-scr-planet::after{content:\"\";position:absolute;inset:-1px;border-radius:50%;border:1px solid currentColor;transform:rotateX(90deg)}",
	".dsh-scr-herotag{position:absolute;bottom:-4px;left:50%;transform:translateX(-50%);font-size:11px;letter-spacing:.2em;color:#8fb4d9;white-space:nowrap}",
	"@keyframes dshGrat{from{background-position:0 0,0 0}to{background-position:190px 0,0 0}}",
	"@keyframes dshSweep{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",
	"@keyframes dshOrbitSpin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",
	"@keyframes dshGlobeFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}",
	"@container scrinner (max-width:980px){.dsh-scr-hero{gap:clamp(40px,6cqw,110px)}}",
	"@container scrinner (max-width:760px){.dsh-scr-hero{gap:10px}.dsh-scr-globewrap{width:130px;height:130px}.dsh-scr-globe{width:84px;height:84px}.dsh-scr-orbit.o1{width:106px;height:106px;margin:-53px 0 0 -53px}.dsh-scr-orbit.o2{width:124px;height:124px;margin:-62px 0 0 -62px}}",
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
						React.createElement("div", { className: "dsh-scr-orbit o1" }),
						React.createElement("div", { className: "dsh-scr-orbit o2" }),
						React.createElement("div", { className: "dsh-scr-globe" },
							React.createElement("div", { className: "dsh-scr-grat" }),
							React.createElement("div", { className: "dsh-scr-sweep" })),
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
