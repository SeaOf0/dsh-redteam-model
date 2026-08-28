// dsh-sec-enforce — deterministic tool-call enforcement for the security presets.
//
// 确定性拦截的落地：所有 Gate 此前是模型自查（stage_gate
// 是模型自愿调用的工具），本插件用 dsh-tools 的原生 guard 缝（ctx.tools.guard()，
// pre-execute、同步、可拒绝、全局注册宿主平面）把四条纪律变成机器强制：
//
//   reportGate      write/edit 落 reports/ 前，gate-log.md 必须已有本模式「报告门」PASS
//                   （pentest P3 / audit A3 / binary B2 / ad report / av V4 —— 与
//                   dsh-stage-gate 的 GATES 对齐，报错文本指名该调哪道门）
//   writeBoundary   五模式的写操作限制在任务工作区内（工具级最小权限的最小可行版：
//                   审计只读对象、av 产物限实验室目录，统一为「不出工作区」）
//   dangerousOps    保守高危 bash 特征（大范围 rm / 裸 DROP / 停机重启 / 资金类 POST）
//                   拒绝并指路「呈报计划 → ask_user_question 批准」
//   rateDiscipline  裸奔全端口扫描（nmap -p- 无速率控制 / masscan --rate>1000 /
//                   裸 ffuf 无 -rate）拒绝并给出修法
//
// askGate（v1.1.0，tools/pre-execute waterfall）：破坏分级——不可逆/资金类仍走 guard
// 硬拦；「变更性但可逆」的中间类（账号与权限体系变更 / 防火墙规则修改 / flood 类压测）
// 升级为宿主原生人工审批（approval 服务，allowed-once 放行、拒绝/超时/无审批通道即拒）。
// 监听形态与宿主插件同款：async (exec, next) —— 先取下游决策，仅当下游 allow 时以 ask
// 覆盖（不打断其他插件的更强决策）。
//
// 误报优先于漏报：特征集刻意保守（宁可放过，不误伤正常工作流）；四次全部可配置关闭；
// 非五安全预设的会话零干扰；每次拒绝在 <workspace>/enforce-log.md 落一行审计留痕。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import z from "@deepseek-ai/schemastery";

const name = "dsh-sec-enforce";
const inject = ["tools", "agentPresets"];

const Config = z.object({
	reportGate: z.boolean().default(true),
	writeBoundary: z.boolean().default(true),
	dangerousOps: z.boolean().default(true),
	rateDiscipline: z.boolean().default(true),
	askGate: z.boolean().default(true),
	intentGate: z.boolean().default(true),
	constraintGate: z.boolean().default(true),
	killSwitch: z.boolean().default(true),
	allowDirs: z.array(z.string()).default([])
});

/** 全局熔断（跨模式事实层）：标记文件存在即拦全部工具执行，移除即恢复（无需重启）。
 *  一键停止 = `touch ~/.dsh/sec-enforce/KILL`；恢复 = 删除该标记文件。 */
const KILL_MARKER = () => process.env.DSH_KILL_SWITCH_FILE ?? path.join(os.homedir(), ".dsh", "sec-enforce", "KILL");
const KILL_REASON = () => `全局熔断已触发：所有工具执行暂停（一键停止）。恢复方法：移除标记文件 ${KILL_MARKER()}。熔断期间仅回答问题，不执行任何操作。`;
const killTripped = () => { try { return fs.existsSync(KILL_MARKER()); } catch { return false; } };

const SECURITY_MODES = new Set(["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "redteam", "incident-response", "cloud-security", "ctf-solver"]);
/** 每模式的「报告门」——报告落盘前的最后一道覆盖度/完整性门（与 stage-gate GATES 对齐）。
 * redteam 刻意不在表内：主模式总控只消费专业模式报告（gate-pass 产物），不写 reports/——
 * 其全局总结落工作区根目录（summary.md + task-ledger.md）。命中 reports/ 时走专门的
 * 无门拦截文案（见 buildGuard），不生成误导性的「undefined 门」提示。 */
const REPORT_GATE = {
	pentest: "P3",
	"code-audit": "A3",
	"binary-analysis": "B2",
	"attack-defense": "report",
	"av-evasion": "V4",
	"incident-response": "I5",
	"cloud-security": "C7",
	"ctf-solver": "flag"
};
const WRITE_TOOLS = new Set(["write", "edit"]);

/** gate-log.md 的表格行格式：`| iso | mode/stage | pass | ... |`（dsh-stage-gate appendGateLog）。 */
export function gateLogHasPass(logText, mode, gateId) {
	const needle = `${mode}/${gateId}`;
	for (const line of String(logText ?? "").split("\n")) {
		if (!line.includes("|")) continue;
		const cells = line.split("|").map((c) => c.trim());
		if (cells.includes(needle) && cells.includes("pass")) return true;
	}
	return false;
}

/** 目标路径是否是报告文件（工作区 reports/ 目录下）。 */
export function isReportPath(target, workspace) {
	const norm = path.resolve(target);
	const ws = path.resolve(workspace);
	const rel = path.relative(ws, norm);
	return !rel.startsWith("..") && rel.split(path.sep)[0] === "reports";
}

/** 目标路径是否在允许写入的范围内（工作区内，或任一豁免目录内）。 */
export function isWritable(target, workspace, allowDirs = []) {
	const candidates = [workspace, ...allowDirs];
	return candidates.some((dir) => {
		if (!dir) return false;
		const rel = path.relative(path.resolve(dir), path.resolve(target));
		return !rel.startsWith("..") && !path.isAbsolute(rel);
	});
}

/** 目标路径是否是 redteam 总控的任务书（task-briefs/*.md）。 */
export function isTaskBriefPath(target, workspace) {
	const rel = path.relative(path.resolve(workspace), path.resolve(target));
	return !rel.startsWith("..") && rel.split(path.sep)[0] === "task-briefs" && /\.md$/i.test(rel);
}

/** 任务书锚点行：依据/锚点 开头（含列表前缀容忍）。 */
export const TASK_BRIEF_ANCHOR_RE = /^[ \t]*(?:[-*][ \t]*)?(?:依据|锚点)[：:]/m;

/** 保守高危命令特征（B2 最小集）——命中返回拒绝理由，未命中返回 undefined。
 * 每条拒绝附「降级替代」行——拦截不是终点，
 * 主动给出低风险等价路径（对应对方 DOWNGRADE 语义；对方该级未真正落地，我们
 * 以文案形式落地并保留确定性拦截）。 */
export function scanDangerous(command) {
	const cmd = String(command ?? "");
	const compact = cmd.replace(/\\\n/g, " ").replace(/\s+/g, " ");
	if (/(^|[;&|]\s*)rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(\/|~|\$HOME)(\/|\s|$)/.test(compact)) {
		return "大范围删除（rm 涉及 / 或 ~ 根级路径）被确定性门禁拦截：删除范围必须限定在任务工作区内；确需删除请先列出清单征得用户批准（ask_user_question），再逐项执行。降级替代：cd 到工作区后限定路径逐项删除，或只生成删除清单交由用户手动执行。";
	}
	if (/\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b/i.test(compact) && !/^\s*#/.test(compact)) {
		return "破坏数据完整性操作（DROP/TRUNCATE）被拦截：负面清单禁止破坏数据完整性；验证类需求请用 SELECT 复现影响或在对靶场快照说明并获用户批准后进行。降级替代：SELECT 只读查询复现影响；或靶场快照上验证并注明环境。";
	}
	if (/\b(shutdown\b|reboot\b|systemctl\s+(stop|restart|disable)\b|service\s+\w+\s+(stop|restart)\b|kill\s+-9\s+1\b)/i.test(compact)) {
		return "停机/重启/杀服务属变更性操作，被拦截：需先询问用户（ask_user_question 呈报影响与理由），获批准后执行。降级替代：systemctl status/日志只读收集根因，处置步骤列入建议清单由用户执行。";
	}
	// 资金类接口：向支付/退款/提现/下单路径发写请求（curl/wget POST 或 -d）
	const fundsUrl = /(pay|refund|withdraw|order|recharge|transfer)[a-z]*\/|[?&](out_trade_no|trade_no|order_id)=/i;
	const isPost = /(\bcurl\b[^|;&]*(-X\s*(POST|PUT)|--data(-raw|-binary)?\s|\s-d\s))|(\bwget\b[^|;&]*--post-data)/i.test(compact);
	if (isPost && fundsUrl.test(compact)) {
		return "资金类接口写请求（支付/退款/提现/下单）被拦截：persona 硬规则——只生成重放计划呈报用户（ask_user_question），获明确批准后才执行。降级替代：生成只读重放计划（curl 命令+预期响应比对）呈报用户，不实际发送。";
	}
	return undefined;
}

/** ask 中间档特征（v1.1.0）——「变更性但可逆」类：不走 guard 硬拦，走宿主原生人工审批。
 *  语义分级取自账号/权限体系、服务配置、DoS 三类不可轻动的对象面；特征刻意保守，
 *  宁可放过不误伤（工作区内的 chmod/chown 不命中——限定系统目录与账号面）。
 *  命中返回 { reason }（呈报给审批 UI 的理由），未命中返回 undefined。 */
export function scanAsk(command) {
	const cmd = String(command ?? "");
	const compact = cmd.replace(/\\\n/g, " ").replace(/\s+/g, " ");
	// 账号与权限体系变更：新建/改密/删账号、SQL 授权面。
	// passwd/chpasswd 只在命令位命中（行首/管道后/sudo 后）——裸子串会误伤 /etc/passwd
	// 读取（LFI 验证正路）与代码里的字符串字面量。
	if (/\b(useradd|usermod|userdel|adduser|deluser)\b/.test(compact)
		|| /(^|[|;&]|sudo )\s*(passwd|chpasswd)\b/.test(compact)
		|| /\b(mysql|mariadb|psql|sqlplus|sqlite3)\b[^|;&]*\b(GRANT\s+|REVOKE\s+|CREATE\s+USER|DROP\s+USER|ALTER\s+USER)\b/i.test(compact)) {
		return { reason: "账号/权限体系变更类命令需人工审批：改的是目标环境的身份与授权面（不可轻动、影响所有后续访问）——批准即执行，拒绝则换只读方案（如 SELECT 验证权限现状）。" };
	}
	// 防火墙/安全规则修改：清空或增删规则（影响目标的网络暴露面）
	if (/\biptables\s+(-F\b|--flush)|\bnft\s+(add|delete|flush)\b|\bufw\s+(enable|disable|allow|deny|insert|delete)\b/.test(compact)) {
		return { reason: "防火墙/安全规则修改需人工审批：直接改变目标网络暴露面（可能自断回连或放大暴露）——批准即执行，拒绝则先 iptables -L/nft list ruleset 只读核对再呈报变更清单。" };
	}
	// flood 类压测：明确的高并发洪水语义（与授权扫描的速率纪律不同档）
	if (/\b(hping3|hping)\b[^|;&]*\b--flood\b|--flood\b|\bslowloris\b|\bsynflood\b/i.test(compact)) {
		return { reason: "flood 类压测命令需人工审批：显式洪水语义（--flood/slowloris/synflood）可能构成对目标的服务压力——批准即执行（确在授权范围），拒绝则改用带速率上限的常规验证。" };
	}
	return undefined;
}

/** 组装 ask 监听器（导出供单测直接调用，不依赖宿主）。
 *  形态与宿主插件同款 waterfall 礼仪：无候选直接 next()；有候选先取下游决策，
 *  仅当下游 allow 时以 ask 覆盖（其他插件更强的 deny/ask 决策不被打断）。 */
export function buildAskListener({ config, appendLog, resolveMode }) {
	const cfg = { askGate: true, ...config };
	return async function askListener(exec, next) {
		if (!cfg.askGate) return next();
		const agent = exec?.agent;
		if (!agent || exec.name !== "bash" || typeof exec.arguments?.command !== "string") return next();
		const mode = resolveMode(agent);
		if (mode === undefined || !SECURITY_MODES.has(mode)) return next();
		const ask = scanAsk(exec.arguments.command);
		if (ask === undefined) return next();
		const downstream = await next();
		if (downstream?.kind !== "allow") return downstream;
		const workspace = agent.session?.header?.cwd;
		if (workspace) {
			try {
				appendLog(workspace, `| ${new Date().toISOString()} | ${mode} | ask | ${exec.name} | ${ask.reason.split("：")[0]} |\n`);
			} catch {}
		}
		return { kind: "ask", reason: ask.reason };
	};
}

/** 裸奔扫描特征（B1 最小集）——命中返回带修法的拒绝理由（修法即降级替代）。 */
export function scanRate(command) {
	const cmd = String(command ?? "");
	const compact = cmd.replace(/\\\n/g, " ").replace(/\s+/g, " ");
	if (/\bnmap\b/.test(compact) && /(-p-\s|--?p\s*1-65535|-p\s*1-65535)/.test(compact) && !/(--max-rate|-T[0-3]\b|--min-rate)/.test(compact)) {
		return "全端口 nmap 未带速率控制被拦截（速率纪律）：加 --max-rate（如 --max-rate 300）或 -T2/-T3 后重试；WAF/生产目标从严。降级替代：--top-ports 100 常见端口概览；或先被动侦察（子域/DNS/公开情报）再定向验证。";
	}
	const massRate = compact.match(/--rate\s+(\d+)/);
	if (/\bmasscan\b/.test(compact) && massRate && Number(massRate[1]) > 1000) {
		return `masscan --rate ${massRate[1]} 超保守上限（1000）被拦截：下调 --rate（500 起步）后重试。降级替代：--rate 500 并缩小到授权网段；或改 nmap -sS --max-rate 300 定向扫描。`;
	}
	if (/(^|\s|\/)ffuf\b/.test(compact) && /-u\s/.test(compact) && !/-rate\b/.test(compact)) {
		return "裸 ffuf 未带 -rate 被拦截：加 -rate 50（保守默认）重试，或改用已封装的 ffuf_fuzz 工具（速率纪律/防盲打/证据留痕内置）。降级替代：-rate 50 重试，或改 ffuf_fuzz 封装工具（防盲打/证据落盘内置）。";
	}
	return undefined;
}

/** 组装 guard（导出供单测直接调用，不依赖宿主）。 */
export function buildGuard({ config, readGateLog, readOperationState, appendLog, resolveMode }) {
	const cfg = { reportGate: true, writeBoundary: true, dangerousOps: true, rateDiscipline: true, askGate: true, intentGate: true, constraintGate: true, killSwitch: true, allowDirs: [], ...config };
	return function guard(exec) {
		const agent = exec?.agent;
		if (!agent) return undefined;
		if (cfg.killSwitch && killTripped()) return { reason: KILL_REASON() };
		const mode = resolveMode(agent);
		if (mode === undefined || !SECURITY_MODES.has(mode)) return undefined;
		const workspace = agent.session?.header?.cwd;
		let reason;
		if (WRITE_TOOLS.has(exec.name)) {
			const target = exec.arguments?.file_path ?? exec.arguments?.path;
			if (typeof target === "string" && target && workspace) {
				if (cfg.writeBoundary && !isWritable(target, workspace, cfg.allowDirs)) {
					reason = `写入目标在任务工作区之外（${path.resolve(workspace)}）被拦截：安全预设写操作限工作区内（工具级最小权限）；确需写外部路径，先征得用户批准并在会话中说明。`;
				} else if (mode === "redteam" && typeof exec.arguments?.content === "string" && isTaskBriefPath(target, workspace) && !TASK_BRIEF_ANCHOR_RE.test(exec.arguments.content)) {
					// 总控任务书锚点（轻量锚的 dsh 落点）：任务书是总控唯一自产的派单物，
					// 必须带「依据：」行——凭什么开这单（用户目标原句/材料路径/成果 id）。
					reason = "任务书缺「依据：」锚点行被拦截：写明凭什么开这单——用户目标原句引用 / 已收集材料落盘路径 / 关联成果 id（顶层任务=用户目标即锚）。在任务书末尾补一行「依据：…」后重写。";
				} else if (cfg.reportGate && isReportPath(target, workspace)) {
					const gateId = REPORT_GATE[mode];
					if (gateId === undefined) {
						reason = `报告落盘被拦截：redteam 主模式总控只消费专业模式报告（gate-pass 产物），不写 reports/——全局总结落工作区根目录（summary.md + task-ledger.md 台账），深度任务的报告由对应专业模式会话产出。`;
					} else {
						const log = readGateLog(workspace);
						if (!gateLogHasPass(log, mode, gateId)) {
							reason = `报告落盘被确定性门禁拦截：先调 stage_gate 过 ${mode} 的 ${gateId} 门（覆盖度/完整性），gate-log.md 出现 "${mode}/${gateId} | pass" 后才能写 reports/。`;
						} else {
							const state = typeof readOperationState === "function" ? readOperationState(workspace) : null;
							const openIds = openCriteriaIds(state);
							if (openIds !== null && openIds.length > 0) {
								reason = `报告落盘被目标契约拦截：operation-state.json 尚有未收口准则（${openIds.join(", ")}）——先 operation_progress 逐条 met（带证据），或与用户确认修订目标后再产出 reports/。`;
							} else if (cfg.intentGate) {
								const openIntentIds = openIntentsOf(state);
								if (openIntentIds.length > 0) {
									reason = `报告落盘被意图台账拦截：尚有未收口方向（${openIntentIds.join(", ")}）——operation_progress intent_done/intent_blocked/intent_dropped 逐条收口（blocked/dropped 须 note 原因），或与用户确认放弃后再产出 reports/。`;
								}
							}
						}
					}
				}
			}
		} else if (exec.name === "bash" && typeof exec.arguments?.command === "string") {
			const command = exec.arguments.command;
			const danger = cfg.dangerousOps ? scanDangerous(command) : undefined;
			const rate = cfg.rateDiscipline ? scanRate(command) : undefined;
			reason = danger ?? rate ?? constraintReason(cfg, workspace, command, readOperationState);
		} else if (exec.name === "fetch" && typeof exec.arguments?.url === "string") {
			reason = constraintReason(cfg, workspace, exec.arguments.url, readOperationState);
		}
		if (reason !== undefined && workspace) {
			try {
				appendLog(workspace, `| ${new Date().toISOString()} | ${mode} | ${exec.name} | ${reason.split("：")[0]} |\n`);
			} catch {}
		}
		return reason;
	};
}

/** operation-state 的未收口准则 id；无契约/无准则返回 null（不拦截）。 */
function openCriteriaIds(state) {
	if (state === null || state === undefined || !Array.isArray(state.criteria) || state.criteria.length === 0) return null;
	const open = state.criteria.filter((c) => c && c.status !== "met").map((c) => c.id);
	return open;
}

/** operation-state 的未收口意图 id（open 状态）；无台账返回 []（不拦截）。 */
function openIntentsOf(state) {
	if (state === null || state === undefined || !Array.isArray(state.intents)) return [];
	return state.intents.filter((i) => i && i.status === "open").map((i) => i.id);
}

/** 任务约束命中（deny 且带匹配词的条目）：bash 命令/fetch URL 含任一匹配词即命中。
 *  返回命中的约束（含原文），空数组=放行。无约束/无匹配词条目不参与（提示层归信封）。 */
export function constraintHits(commandOrUrl, state) {
	if (state === null || state === undefined || !Array.isArray(state.constraints)) return [];
	const subject = String(commandOrUrl ?? "");
	if (!subject) return [];
	const out = [];
	for (const c of state.constraints) {
		if (!c || c.kind !== "deny" || !Array.isArray(c.keywords)) continue;
		if (c.keywords.some((k) => typeof k === "string" && k && subject.toLowerCase().includes(k.toLowerCase()))) out.push(c);
	}
	return out;
}

/** 约束拒绝理由组装（constraintGate 关时返回 undefined）。 */
function constraintReason(cfg, workspace, subject, readOperationState) {
	if (!cfg.constraintGate || !workspace) return undefined;
	const hits = constraintHits(subject, typeof readOperationState === "function" ? readOperationState(workspace) : null);
	if (hits.length === 0) return undefined;
	return `任务约束拦截（${hits.map((h) => h.id ?? "?").join(",")}）：${hits.map((h) => h.text).join("；")}——该约束为开工时登记的用户红线（operation_constraints，命中匹配词即拦）；确需此项操作，先与用户确认并修订约束台账。`;
}

function apply(ctx, config) {
	const appendLog = (workspace, line) => {
		fs.appendFileSync(path.join(workspace, "enforce-log.md"), line);
	};
	const resolveMode = (agent) => {
		try { return ctx.agentPresets.composedPreset(agent.ctx); } catch { return undefined; }
	};
	const guard = buildGuard({
		config,
		readGateLog: (workspace) => {
			try { return fs.readFileSync(path.join(workspace, "gate-log.md"), "utf8"); } catch { return ""; }
		},
		readOperationState: (workspace) => {
			try { return JSON.parse(fs.readFileSync(path.join(workspace, "operation-state.json"), "utf8")); } catch { return null; }
		},
		appendLog,
		resolveMode
	});
	ctx.tools.guard(guard);
	// ask 中间档：tools/pre-execute waterfall（礼貌式——尊重下游更强决策）
	ctx.on("tools/pre-execute", buildAskListener({ config, appendLog, resolveMode }));
}

export { Config, REPORT_GATE, SECURITY_MODES, apply, inject, name };
