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
// 误报优先于漏报：特征集刻意保守（宁可放过，不误伤正常工作流）；四次全部可配置关闭；
// 非五安全预设的会话零干扰；每次拒绝在 <workspace>/enforce-log.md 落一行审计留痕。

import fs from "node:fs";
import path from "node:path";
import z from "@deepseek-ai/schemastery";

const name = "dsh-sec-enforce";
const inject = ["tools", "agentPresets"];

const Config = z.object({
	reportGate: z.boolean().default(true),
	writeBoundary: z.boolean().default(true),
	dangerousOps: z.boolean().default(true),
	rateDiscipline: z.boolean().default(true),
	allowDirs: z.array(z.string()).default([])
});

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
	const cfg = { reportGate: true, writeBoundary: true, dangerousOps: true, rateDiscipline: true, allowDirs: [], ...config };
	return function guard(exec) {
		const agent = exec?.agent;
		if (!agent) return undefined;
		const mode = resolveMode(agent);
		if (mode === undefined || !SECURITY_MODES.has(mode)) return undefined;
		const workspace = agent.session?.header?.cwd;
		let reason;
		if (WRITE_TOOLS.has(exec.name)) {
			const target = exec.arguments?.file_path ?? exec.arguments?.path;
			if (typeof target === "string" && target && workspace) {
				if (cfg.writeBoundary && !isWritable(target, workspace, cfg.allowDirs)) {
					reason = `写入目标在任务工作区之外（${path.resolve(workspace)}）被拦截：安全预设写操作限工作区内（工具级最小权限）；确需写外部路径，先征得用户批准并在会话中说明。`;
				} else if (cfg.reportGate && isReportPath(target, workspace)) {
					const gateId = REPORT_GATE[mode];
					if (gateId === undefined) {
						reason = `报告落盘被拦截：redteam 主模式总控只消费专业模式报告（gate-pass 产物），不写 reports/——全局总结落工作区根目录（summary.md + task-ledger.md 台账），深度任务的报告由对应专业模式会话产出。`;
					} else {
						const log = readGateLog(workspace);
						if (!gateLogHasPass(log, mode, gateId)) {
							reason = `报告落盘被确定性门禁拦截：先调 stage_gate 过 ${mode} 的 ${gateId} 门（覆盖度/完整性），gate-log.md 出现 "${mode}/${gateId} | pass" 后才能写 reports/。`;
						} else {
							const openIds = openCriteriaIds(typeof readOperationState === "function" ? readOperationState(workspace) : null);
							if (openIds !== null && openIds.length > 0) {
								reason = `报告落盘被目标契约拦截：operation-state.json 尚有未收口准则（${openIds.join(", ")}）——先 operation_progress 逐条 met（带证据），或与用户确认修订目标后再产出 reports/。`;
							}
						}
					}
				}
			}
		} else if (exec.name === "bash" && typeof exec.arguments?.command === "string") {
			const command = exec.arguments.command;
			const danger = cfg.dangerousOps ? scanDangerous(command) : undefined;
			const rate = cfg.rateDiscipline ? scanRate(command) : undefined;
			reason = danger ?? rate;
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

function apply(ctx, config) {
	const guard = buildGuard({
		config,
		readGateLog: (workspace) => {
			try { return fs.readFileSync(path.join(workspace, "gate-log.md"), "utf8"); } catch { return ""; }
		},
		readOperationState: (workspace) => {
			try { return JSON.parse(fs.readFileSync(path.join(workspace, "operation-state.json"), "utf8")); } catch { return null; }
		},
		appendLog: (workspace, line) => {
			fs.appendFileSync(path.join(workspace, "enforce-log.md"), line);
		},
		resolveMode: (agent) => {
			try { return ctx.agentPresets.composedPreset(agent.ctx); } catch { return undefined; }
		}
	});
	ctx.tools.guard(guard);
}

export { Config, REPORT_GATE, SECURITY_MODES, apply, inject, name };
