// dsh-redteam-results — 会话隔离的 redteam 成果登记（九模式）宿主插件。
//
// 三件事：
//   1) 模型侧工具：redteam_finding_register / update / delete——执行时从 exec.agent
//      自动取 sessionId 与 agentPreset，成果严格按「会话 × 模式」隔离；
//   2) 存储：node:sqlite 单库 ~/.dsh/redteam-results/results.db（行级持久——删除某条
//      成果即删除对应行，除非删库，数据永远在）；
//   3) Web 通道：不走 connection.rpc（其在部分 fiber 上注册 webServer 路由会静默失败），
//      而是 better-sidebar 同款配方——静态注入 webServer/webRuntime，自己注册
//      /dsh-redteam-results 前缀路由 + 同源信任栅栏，会话标签页直接 POST JSON 读写。
//
// 「验证」按钮：取 agents 注册表把复核请求作为一条用户消息 followup 进当前会话，
// 模型按模式验证纪律复核后用 redteam_finding_update 回写状态。

import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { openStore, registerFinding, updateFinding, removeFinding, getFinding, listFindings, listFindingsAll, groupByTarget, groupByTargetAll, computeStats, computeStatsAll, modeCounts, modeCountsAll, ledgerOverview, ledgerOverviewAll, getMeta, setMeta, SEVERITIES, STATUSES, MODE_STATUSES, ALL_STATUSES, EVIDENCE_LEVELS, SOURCE_ORIGINS, statusesOf } from "./store.js";

const name = "dsh-redteam-results";
const inject = ["tools", "webServer", "webRuntime", "agentPresets"];

const ROUTE_PATH = "/dsh-redteam-results";
/** 进程级 CSRF token：GET <route>/csrf 由同源页取走（跨源响应不可读），POST 须回带 x-dsh-csrf 头。 */
const CSRF_TOKEN = crypto.randomBytes(24).toString("hex");
export function checkCsrf(req, token) {
	return String(req?.headers?.["x-dsh-csrf"] ?? "") === String(token ?? "");
}
/** 验证按钮防重：sessionId:id → 最近注入时间（10 分钟窗口内不重复 followup，防连点灌多条复核消息）。 */
const VERIFY_SENT = new Map();
const VERIFY_WINDOW_MS = 10 * 60 * 1000;

/** 链路互链（chain 三模式）：反查 AttackAtlas 链路节点对各 finding 的引用——行带 chainNodes
 *  供 Detail 互链显示。atlas 包/库不可用时静默缺省（不阻塞成果读取）。 */
let atlasStoreCache;
async function joinChainRefs(rows, mode) {
	if (!Array.isArray(rows) || rows.length === 0) return;
	try {
		const mod = await import("@dsh-external/dsh-attack-atlas/store");
		const dbPath = process.env.DSH_ATLAS_DB || path.join(os.homedir(), ".dsh", "attack-atlas", "atlas.db");
		if (!atlasStoreCache || atlasStoreCache.dbPath !== dbPath) atlasStoreCache = mod.openStore(dbPath);
		const refIdx = mod.chainRefIndex(atlasStoreCache, mode);
		for (const f of rows) {
			const refs = refIdx[`${f.sessionId ?? ""}:${f.id}`];
			if (refs) f.chainNodes = refs.map((r) => ({ id: r.nodeId, label: r.label, kind: r.kind, major: !!r.major }));
		}
	} catch { /* atlas 不可用或无链路数据——互链缺省 */ }
}
const MODES = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];
const MODE_LABELS = {
	redteam: "研究员模式",
	pentest: "渗透测试模式",
	"code-audit": "代码审计模式",
	"binary-analysis": "二进制分析模式",
	"attack-defense": "攻防评估模式",
	"av-evasion": "免杀对抗模式",
	"incident-response": "应急溯源模式",
	"cloud-security": "云安全攻防模式",
	"ctf-solver": "CTF 解题模式"
};
const DB_PATH = path.join(os.homedir(), ".dsh", "redteam-results", "results.db");
const MAX_BODY = 5 * 1024 * 1024;

let store; // 进程级单句柄（DatabaseSync 同步 API，SQLite 自带串行化）
function theStore() {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}

//#region 通道与工具共用的业务逻辑

/** 一键验证的注入文案（用户消息；进入会话后由模型按模式验证纪律复核并回写状态）。 */
export function verifyMessage(finding) {
	const lines = [
		`[成果验证请求] 复核「redteam 成果」页 finding #${finding.seq}：${finding.title}`,
		finding.mode === "ctf-solver"
			? `模块 ${finding.type || "（未填）"} ｜ 题目地址 ${finding.target || "（未填）"} ｜ 当前状态 ${finding.status} ｜ 证据等级 ${finding.evidenceLevel}`
			: finding.mode === "incident-response"
			? `等级 ${finding.severity} ｜ 主机 ${finding.target || "（未填）"} ｜ 当前状态 ${finding.status} ｜ 证据等级 ${finding.evidenceLevel}`
			: `等级 ${finding.severity} ｜ 目标 ${finding.target || "（未填）"} ｜ 当前状态 ${finding.status} ｜ 证据等级 ${finding.evidenceLevel}`
	];
	if (finding.poc) lines.push(`${finding.mode === "ctf-solver" ? "解题材料（脚本/过程）" : finding.mode === "incident-response" ? "取证过程 / 检测命令" : "复现材料"}：\n${finding.poc}`);
	if (finding.requestPkt) lines.push(`完整请求包：\n${finding.requestPkt}`);
	if (finding.responsePkt) lines.push(`关键响应：\n${finding.responsePkt}`);
	if (finding.baseline || finding.diffEvidence || finding.markerEcho) lines.push(`对照三件套：基线=${finding.baseline || "缺"} ｜ 差分=${finding.diffEvidence || "缺"} ｜ marker=${finding.markerEcho || "缺"}`);
	if (finding.impact) lines.push(`${finding.mode === "binary-analysis" ? "能力与危害" : "影响证明"}：${finding.impact}`);
	if (finding.chain) lines.push(`${finding.mode === "code-audit" ? "工人链" : finding.mode === "attack-defense" ? "获取路径（L<级>: 链级前缀照录）" : finding.mode === "binary-analysis" ? "还原/产出链" : finding.mode === "cloud-security" ? "路径链（入口→身份→权限→资源）" : finding.mode === "ctf-solver" ? "解题路径（怎么解的）" : finding.mode === "incident-response" ? "取证过程（怎么证实）" : "调用链（entry → sink）"}：${finding.chain}`);
	if (finding.mode === "code-audit" && finding.chainTracer) lines.push(`追踪员链：${finding.chainTracer}`);
	if (finding.evidence) lines.push(`证据引用：${finding.evidence}`);
	if (finding.timelineAt) lines.push(`攻击时间：${finding.timelineAt}`);
	if (finding.entry || finding.identity || finding.permission || finding.resource) lines.push(`攻击路径四要素：入口=${finding.entry || "缺"} ｜ 身份=${finding.identity || "缺"} ｜ 权限=${finding.permission || "缺"} ｜ 资源=${finding.resource || "缺"}`);
	const statusGuide = finding.mode === "code-audit"
		? ["请按代审验证纪律复核（双链一致/扫描对账），复核后调 redteam_finding_update 回写 status 与 verifyNote：",
			"- 静态审计：复核通过只能回写 code-reviewed（代码侧已复核）——代码级推理不得标 verified；",
			"- verified 仅限动态验证成功：EXP 本地复现真实生效，或在线授权环境实测 L1 通过；",
			"- 动态审计复现不成立 → false-positive；验证未完成/环境性失败保持 pending。"].join("\n")
		: finding.mode === "attack-defense"
		? ["请按攻防评估验证纪律复核（确定性信号按战果类型择一：对照文件字节一致 / victim 侧标记数据被读到 / OOB 回调命中；入口/注入类战果仍用对照三件套：基线/差分/marker 逐字回显），复核后调 redteam_finding_update 回写 status 与 verifyNote：",
			"- verified=战果真实有效（上述信号至少其一成立，L 链级如实）；",
			"- 验证未完成或环境性失败（目标不可达/WAF 拦截/超时）→ 保持 pending，不得因此判 false-positive；",
			"- false-positive=复核后确认战果不成立或误记；",
			"- fixed=已交付（仅当此前已 verified）。"].join("\n")
		: finding.mode === "binary-analysis"
		? ["请按二进制分析验证纪律复核（静态优先：独立重读关键反汇编段/重跑分析脚本比对一致性；多视角结论一致=更高可信、分歧=对比结论如实写；动态验证仅在必要时建议用户指定干净隔离 VM——本次复核默认静态），复核后调 redteam_finding_update 回写 status 与 verifyNote：",
			"- verified=已定论（字节/指令级证据支撑，结论可独立复核复现）；",
			"- suspect=疑似（静态线索成立但未到定论强度，或还原三验未全过）——合法中间态，不强行升格；",
			"- pending=分析中（复核未完成或需补充证据）；",
			"- 复核推翻原结论 → 更新 description/chain 如实记录矛盾证据，不删行。"].join("\n")
		: finding.mode === "cloud-security"
		? ["请按云安全攻防验证纪律复核（三重证据：云 API 响应+策略文档+权限清单至少其二；只读 Describe/Get/List 验证优先、限速、账单意识；四要素闭环核对：入口/身份/权限/资源逐项对证据），复核后调 redteam_finding_update 回写 status 与 verifyNote：",
			"- verified=已证实（路径可到达性有真实云证据支撑，四要素无悬空）；",
			"- 验证未完成或环境性失败（API 不可达/权限不足/限速）→ 保持 pending，不得因此判 false-positive；",
			"- false-positive=复核后确认路径不成立或误判；",
			"- fixed=已修复（仅当此前已 verified、修复后复测不成功才可标记）。"].join("\n")
		: finding.mode === "ctf-solver"
		? ["请按 CTF 解题验证纪律复核（flag 真实性主线：flag 原文+平台回执/得分变动+解题脚本可重放，至少其二可追溯；web 题可附请求-响应对），复核后调 redteam_finding_update 回写 status 与 verifyNote：",
			"- verified=已解（flag 已提交且平台确认得分，证据可追溯）；",
			"- stuck=卡点（思路断/技术堵点/环境问题）——写明卡在哪一步、已试过什么；",
			"- pending=未解（尚未出 flag 或验证未完成）；",
			"- 复核推翻原结论（flag 无效/非本题 flag）→ 如实更新 description 与验证记录，不删行。"].join("\n")
		: finding.mode === "incident-response"
		? ["请按应急溯源验证纪律复核（证据链交叉：日志/样本/时间戳/网络记录多源一致，时间线逐节点闭合；单条日志不构成结论），复核后调 redteam_finding_update 回写 status 与 verifyNote：",
			"- verified=已证实（多源证据交叉确凿，证据编号可追溯）；",
			"- code-reviewed=复核通过（证据链形式复核完成，未到已证实强度不升格）；",
			"- 复核未完成或证据不足（日志缺失/时间窗未定）→ 保持 pending；",
			"- false-positive=排除（误报或与失陷无关的正常业务现象）；",
			"- fixed=已处置（处置清单执行完成并复测无再生即标——与渗透「修复后复测不成功」语义不同）；",
			"- 复核推翻原结论 → 如实更新 description 与验证记录，不删行。"].join("\n")
		: ["请按本模式验证纪律复核（渗透模式=对照三件套：基线/差分/marker 逐字回显），复核后调 redteam_finding_update 回写 status 与 verifyNote：",
			"- verified=验证完成且真实可再复现；",
			"- 验证未完成或环境性失败（WAF 拦截/目标不可达/超时）→ 保持 pending，不得因此判 false-positive；",
			"- false-positive=验证后确认漏洞不存在或误判；",
			"- fixed=仅当此前已 verified 真实存在、用户修复后本次复测不成功才可标记（须有本次复测记录）。"].join("\n");
	lines.push(statusGuide);
	return lines.join("\n");
}

function sessionOf(ctx, exec) {
	const agent = exec?.agent;
	const id = agent?.session?.id;
	if (!id) return undefined;
	let preset;
	try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
	if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
	return { id: String(id), mode: MODES.includes(preset) ? preset : "redteam" };
}

function resolveAgents(ctx) {
	try { return ctx.get("agents"); } catch { /* 该 fiber 未声明 agents */ }
	try { return ctx.agents; } catch { /* 同上 */ }
	return undefined;
}

//#endregion

//#region HTTP 通道（自注册路由 + 同源信任栅栏）

function hostOf(headers) {
	const h = headers?.host;
	return typeof h === "string" ? h : "";
}

function isLoopbackHostname(hostname) {
	if (hostname === "localhost" || hostname === "[::1]") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/** 同源信任栅栏：Host 是本机/受信授权，且 Origin（浏览器跨站标记）与 Host 同源。 */
export function isTrustedRequest(req, trustedHosts) {
	const host = hostOf(req.headers);
	if (host === "") return false;
	let hostUrl;
	try { hostUrl = new URL(`http://${host}`); } catch { return false; }
	const okHost = isLoopbackHostname(hostUrl.hostname) || (trustedHosts ?? []).some((t) => {
		try { return new URL(`http://${t}`).hostname === hostUrl.hostname; } catch { return false; }
	});
	if (!okHost) return false;
	const origin = req.headers?.origin;
	if (typeof origin === "string" && origin !== "null") {
		try {
			const originUrl = new URL(origin);
			if (originUrl.host !== hostUrl.host) return false; // 含端口：本机他端口页面的 Origin 不放行
		} catch { return false; }
	}
	return true;
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let size = 0;
		const chunks = [];
		req.on("data", (c) => {
			size += c.length;
			if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); return; }
			chunks.push(c);
		});
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

/** 通道端点分发（纯逻辑，供路由与测试复用）。 */
export async function dispatch(ctx, st, endpoint, payload) {
	const p = payload ?? {};
	if (endpoint === "findings.list") {
		const mode = String(p.mode ?? "redteam");
		if (p.scope === "all") {
			// 跨会话模式页：该模式全表 + created_at 范围过滤；counts=全时域侧栏计数；行带 sessionId；
			// meta 取请求会话（标签页所属会话）——模式页元数据栏不为空。
			const range = { from: String(p.from ?? ""), to: String(p.to ?? "") };
			const out = { list: listFindingsAll(st, mode, { ...p, ...range }), stats: computeStatsAll(st, mode, range), counts: modeCountsAll(st), meta: p.sessionId ? getMeta(st, String(p.sessionId)) : undefined };
			await joinChainRefs(out.list.rows, mode);
			return out;
		}
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { list: listFindings(st, sessionId, mode, p), stats: computeStats(st, sessionId, mode), counts: modeCounts(st, sessionId), meta: getMeta(st, sessionId) };
	}
	if (endpoint === "findings.groups") {
		const mode = String(p.mode ?? "redteam");
		if (p.scope === "all") {
			const range = { from: String(p.from ?? ""), to: String(p.to ?? "") };
			// 分组视图带统计（四档卡/状态 chips 在分组态不再全零）+ 请求会话 meta
			const out = { groups: groupByTargetAll(st, mode, { ...p, ...range }), stats: computeStatsAll(st, mode, range), meta: p.sessionId ? getMeta(st, String(p.sessionId)) : undefined };
			await joinChainRefs(out.groups.flatMap((g) => g.items), mode);
			return out;
		}
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { groups: groupByTarget(st, sessionId, mode, p) };
	}
	if (endpoint === "counts.all") {
		return { counts: modeCountsAll(st) };
	}
	if (endpoint === "ledger.overview") {
		if (p.scope === "all") {
			// 跨会话全局大屏：按登记时间（created_at）过滤，from/to 为 ISO 字符串（可空）
			return { overview: ledgerOverviewAll(st, { from: String(p.from ?? ""), to: String(p.to ?? "") }) };
		}
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { overview: ledgerOverview(st, sessionId), meta: getMeta(st, sessionId) };
	}
	if (endpoint === "meta.set") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, meta: setMeta(st, sessionId, p) };
	}
	if (endpoint === "finding.delete") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		removeFinding(st, sessionId, String(p.id ?? ""));
		return { ok: true, counts: modeCounts(st, sessionId) };
	}
	if (endpoint === "finding.verify") {
		const sessionId = String(p.sessionId ?? "");
		const finding = getFinding(st, sessionId, String(p.id ?? ""));
		if (!finding) return { ok: false, error: "finding 不存在" };
		// 防重：同条 finding 10 分钟窗口内不重复注入复核消息（连点保护）。
		const vkey = `${sessionId}:${finding.id}`;
		const last = VERIFY_SENT.get(vkey) ?? 0;
		if (Date.now() - last < VERIFY_WINDOW_MS) return { ok: false, error: "复核请求已在此前 10 分钟内发送——请到原会话查看处理进展；确需重发请稍后再试" };
		const agents = resolveAgents(ctx);
		const agent = agents?.get?.(sessionId);
		if (!agent || typeof agent.followup !== "function") return { ok: false, unreachable: true, error: "原会话不可达（会话可能已删除或代理未运行）——可人工复核后使用「标记验证结果」兜底" };
		agent.followup({ id: `rtr-${Date.now()}-${finding.seq}`, role: "user", content: [{ type: "text", text: verifyMessage(finding) }], source: { kind: "user" } });
		VERIFY_SENT.set(vkey, Date.now());
		if (VERIFY_SENT.size > 500) for (const [k, t] of VERIFY_SENT) if (Date.now() - t >= VERIFY_WINDOW_MS) VERIFY_SENT.delete(k);
		return { ok: true };
	}
	if (endpoint === "finding.mark") {
		// 原会话已删/不可达时的人工复核兜底：直接回写状态与复核注记（UI 动作，不经模型工具）。
		const sessionId = String(p.sessionId ?? "");
		const id = String(p.id ?? "");
		const finding = getFinding(st, sessionId, id);
		if (!finding) return { ok: false, error: "finding 不存在" };
		// 状态词表按 finding 的模式取（产物型=各自本体词、redteam=台账词表）——与 register/update 同源。
		const allowed = statusesOf(finding.mode);
		if (!allowed.includes(p.status)) return { ok: false, error: `status 必须是 ${allowed.join("/")}` };
		const updated = updateFinding(st, sessionId, finding.mode, id, { status: p.status, verifyNote: String(p.verifyNote ?? "") || undefined });
		return { ok: true, id: updated.id, status: updated.status, verifyNote: updated.verifyNote };
	}
	throw new Error(`unknown endpoint ${endpoint}`);
}

//#endregion

//#region host wiring

function apply(ctx) {
	//#region 模型工具（宿主平面，九模式可见）
	ctx.tools.register(defineTool({
		name: "redteam_finding_register",
		description: "登记一条 finding 到本会话「redteam 成果」页（会话×模式自动隔离，不可指定他模式）。每条进报告的 finding 必登；status 复核前一律 pending；字段语义全集见 shared/refs/finding-fields.md。子代理登记落入其自身会话库。",
		parameters: {
			title: { type: "string", required: true, description: "名称（简短）" },
			severity: { type: "string", enum: SEVERITIES, description: "等级（漏洞型模式必填；免杀/CTF/二进制等产物型模式不展示等级，可省略默认 medium，分类标签走 type）" },
			target: { type: "string", required: true, description: "地址/目标/位置" },
			summary: { type: "string", required: true, description: "一句话简介" },
			type: { type: "string", description: "分类标签（按模式本体词表：渗透=漏洞类可含 CWE；代审=RCE 主线（任意上传RCE/未授权RCE/组合RCE/硬编码前端绕过/zip自解压RCE/深度反序列化/溢出RCE/其他）或漏洞类可含 CWE；攻防=战果类型：入口点/数据读取成果/凭据·密码本/哈希集(hash map)/横向立足点/域控成果/Webshell 部署/持久化项/内网资产/检测gap；免杀=交付物语言/形态如 jsp/aspx/powershell/nim/加载器/内存马；CTF=题目模块（web/pwn/reverse/crypto/misc/forensics/ai-ml/osint/malware/mobile/ad-domain/cloud/supply——与图谱自动点亮对齐；难度写入标题或 summary）；应急=链节点类型（入口点/执行/持久化/横向/数据外传/影响/处置清理/其他——与图谱自动点亮对齐；自然事件词如 webshell/勒索病毒/横向移动亦可点亮）；二进制=产物类型（脱壳还原二进制/反编译源码/提取配置/提取密钥(Key)/C2 配置/提取载荷/修复样本/脚本工具/IOC 集/YARA 规则——type 与图谱自动点亮对齐）；云安全=路径类型（凭证泄露利用/元数据服务/对象存储/云数据库/权限提升/容器逃逸/K8s 集群/Serverless/CI-CD/横向/持久化/其他——与图谱自动点亮对齐）；其余=各模式类型词表）" },
			description: { type: "string", description: "描述（影响与成因）" },
			poc: { type: "string", description: "测试过程+完整EXP：复杂=exp/<id>.py 脚本；简单=可直接复现的请求/命令" },
			chain: { type: "string", description: "调用链 entry→sink（审计双链之一，每行一链）" },
			chainTracer: { type: "string", description: "追踪员独立重追链（审计双链另一侧）" },
			chainVerdict: { type: "string", description: "双链结论：一致 / 不一致+差异（不一致=疑似）" },
			snippetEntry: { type: "string", description: "entry 关键代码片段" },
			snippetSink: { type: "string", description: "sink 关键代码片段" },
			cwe: { type: "string", description: "CWE 编号" },
			patch: { type: "string", description: "修复 diff 建议（可选）" },
			sourceOrigin: { type: "string", enum: SOURCE_ORIGINS, description: "来源：manual=纯人工；scan-confirmed=扫描器命中经人工确证后登记（代审/渗透挂扫描器时）；scan-false-positive=扫描命中人工复核判伪" },
			sampleHash: { type: "string", description: "样本 SHA256（二进制）" },
			family: { type: "string", description: "家族/变种（二进制）" },
			packer: { type: "string", description: "壳/保护（二进制）" },
			iocs: { type: "string", description: "IOC 清单（二进制）" },
			detectionRule: { type: "string", description: "检测规则（二进制）" },
			baseline: { type: "string", description: "三件套①基线（渗透）" },
			diffEvidence: { type: "string", description: "三件套②差分（渗透）" },
			markerEcho: { type: "string", description: "三件套③marker 回显" },
			impact: { type: "string", description: "影响证明（渗透）" },
			cvss: { type: "string", description: "CVSS 向量+评分" },
			requestPkt: { type: "string", description: "完整请求包（渗透）" },
			responsePkt: { type: "string", description: "关键响应（渗透）" },
			evidence: { type: "string", description: "证据引用（evidence-index 编号/产物路径）" },
			fix: { type: "string", description: "修复建议（每条 finding 必填）" },
			timelineAt: { type: "string", description: "时间节点（应急）" },
			entry: { type: "string", description: "入口身份（云）" },
			identity: { type: "string", description: "利用身份（云）" },
			permission: { type: "string", description: "权限（云）" },
			resource: { type: "string", description: "目标资源（云）" },
			status: { type: "string", enum: STATUSES, description: "默认 pending" },
			evidenceLevel: { type: "string", enum: EVIDENCE_LEVELS, description: "证据等级四档（自高到低）：impact 影响已证（数据实际获取/业务动作达成）＞ confirmed 可复现（渗透/攻防=对照三件套齐；应急=多源证据交叉一致）＞ partial 部分证据（工具输出/间接推断）＞ unknown 未知" },
			auditMode: { type: "string", enum: ["static", "dynamic"], description: "审计形态（代审必填）：static=静态（无本地复现环境/未复现生效）；dynamic=动态（本地环境真实复现生效）" }
		},
		output: {
			schema: {
				type: "object",
				additionalProperties: true,
				properties: {
					ok: { type: "boolean", required: true },
					id: { type: "string", required: true }
				}
			},
			render: (_a, v) => [{ type: "text", text: v.ok ? `已登记成果 #${v.seq} ${v.title}（${v.mode}，${v.severity}）——本会话「redteam 成果」页可见` : `登记失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session) return Promise.resolve({ ok: false, id: "", error: "无法解析当前会话（工具需在会话内调用）" });
			const finding = registerFinding(theStore(), session.id, session.mode, args);
			return Promise.resolve({ ok: true, id: finding.id, seq: finding.seq, title: finding.title, mode: finding.mode, severity: finding.severity });
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_finding_update",
		description: "按 id 更新一条 finding：状态流转（verified/false-positive/fixed）、字段修订、verifyNote 记复核结论、retestNote 记复测结论。语义全集见 shared/refs/finding-fields.md。",
		parameters: {
			id: { type: "string", required: true, description: "finding id（如 pentest-3）" },
			status: { type: "string", enum: ALL_STATUSES, description: "新状态（按模式子集：漏洞型=pending/code-reviewed/verified/false-positive/fixed，verified=验证成功且可再复现，fixed=仅限此前已验证后修复复测不成功；免杀=pending 在验/verified 过检/detected 被检出；CTF=pending 未解/stuck 卡点/verified 已解；二进制=pending 分析中/suspect 疑似/verified 已定论）" },
			verifyNote: { type: "string", description: "复核注记（结论+依据，简短）" },
			severity: { type: "string", enum: SEVERITIES },
			title: { type: "string" },
			type: { type: "string" },
			target: { type: "string" },
			summary: { type: "string" },
			description: { type: "string" },
			poc: { type: "string" },
			chain: { type: "string" },
			chainTracer: { type: "string" },
			chainVerdict: { type: "string" },
			snippetEntry: { type: "string" },
			snippetSink: { type: "string" },
			cwe: { type: "string" },
			patch: { type: "string" },
			sourceOrigin: { type: "string", enum: SOURCE_ORIGINS },
			sampleHash: { type: "string" },
			family: { type: "string" },
			packer: { type: "string" },
			iocs: { type: "string" },
			detectionRule: { type: "string" },
			baseline: { type: "string" },
			diffEvidence: { type: "string" },
			markerEcho: { type: "string" },
			impact: { type: "string" },
			cvss: { type: "string" },
			requestPkt: { type: "string" },
			responsePkt: { type: "string" },
			retestNote: { type: "string", description: "复测注记（修复后复测结论：已修复/部分/未修复+依据）" },
			evidence: { type: "string" },
			fix: { type: "string" },
			timelineAt: { type: "string", description: "攻击时间节点（时间线排序：ISO 或 YYYY-MM-DD HH:MM；未知填 unknown）" },
			entry: { type: "string" },
			identity: { type: "string" },
			permission: { type: "string" },
			resource: { type: "string" },
			evidenceLevel: { type: "string", enum: EVIDENCE_LEVELS },
			auditMode: { type: "string", enum: ["static", "dynamic"] }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `成果已更新：${v.id} → ${v.status ?? "字段修订"}${v.verifyNote ? `（${v.verifyNote}）` : ""}` : `更新失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session) return Promise.resolve({ ok: false, error: "无法解析当前会话" });
			const finding = updateFinding(theStore(), session.id, session.mode, args.id, args);
			if (finding === undefined) return Promise.resolve({ ok: false, error: `finding ${args.id} 不存在（本会话 ${session.mode} 页）` });
			return Promise.resolve({ ok: true, id: finding.id, status: finding.status, verifyNote: finding.verifyNote });
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_finding_delete",
		description: "Remove one finding from this session's「redteam 成果」tab by id（页面删除按钮同源；删除即删数据库行，统计同步更新）。",
		parameters: { id: { type: "string", required: true, description: "finding id" } },
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `已删除成果 ${v.id}` : `删除失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session) return Promise.resolve({ ok: false, error: "无法解析当前会话" });
			removeFinding(theStore(), session.id, args.id);
			return Promise.resolve({ ok: true, id: args.id });
		}
	}));
	//#endregion

	//#region Web 通道路由（better-sidebar 同款：webServer 自注册 + 同源栅栏）
	const trustedHosts = () => {
		try { return ctx.webRuntime?.trustedHosts ?? []; } catch { return []; }
	};
	ctx.effect(() => ctx.webServer.register({
		kind: "prefix",
		path: ROUTE_PATH,
		handler: async (req, res) => {
			const send = (code, body) => {
				const text = JSON.stringify(body);
				res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
				res.end(text);
			};
			if (!isTrustedRequest(req, trustedHosts())) { res.writeHead(403); res.end("forbidden"); return; }
			let csrfPath = "";
			try { csrfPath = new URL(req.url ?? "/", "http://x").pathname; } catch { csrfPath = ""; }
			if (req.method === "GET" && csrfPath === ROUTE_PATH + "/csrf") { send(200, { token: CSRF_TOKEN }); return; }
			if (req.method !== "POST") { res.writeHead(405); res.end("method not allowed"); return; }
			if (!checkCsrf(req, CSRF_TOKEN)) { res.writeHead(403); res.end("csrf token missing or invalid"); return; }
			let endpoint = "";
			try { endpoint = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname.slice(ROUTE_PATH.length)).replace(/^\/+/, ""); } catch { endpoint = ""; }
			if (endpoint === "") { res.writeHead(404); res.end("not found"); return; }
			try {
				const raw = await readBody(req);
				const payload = raw === "" ? {} : JSON.parse(raw);
				const result = await dispatch(ctx, theStore(), endpoint, payload);
				send(200, result);
			} catch (e) {
				send(400, { ok: false, error: e?.message ?? String(e) });
			}
		}
	}), "dsh-redteam-results: web route");
	//#endregion
}

export { MODES, MODE_LABELS, SEVERITIES, STATUSES, EVIDENCE_LEVELS, ROUTE_PATH, apply, inject, name, openStore };

//#endregion
