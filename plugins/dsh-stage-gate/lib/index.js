// dsh-stage-gate — the runtime half of the security presets' stage-gate discipline.
//
// The playbooks define gates as text contracts (ad-playbook 子代理编排, pentest/audit/re/av
// 编排章); this plugin turns the STRUCTURAL subset of those contracts into a tool the model
// must call and cannot self-grade: files present, non-empty, required markers present, table
// rows complete, artifact provenance hashed. Semantic gates (call-chain agreement, reviewer
// confirm-or-challenge, boundary judgment) stay in the reviewers' hands and are surfaced as
// `manual` entries so the model cannot mistake a structural pass for a full pass.
//
// Verdicts append to <workspace>/gate-log.md — the audit trail the report chapter consumes.
//
// 目标契约与运行状态（operation-state.json）：operation_goal 把任务目标登记为带成功准则的
// 可判定契约；stage_gate 每次判定自动同步 gates 进度；operation_progress 逐条收口准则。
// route-boost 读同一文件在中断后投递恢复盘，sec-enforce 的报告门在准则未全 met 时拦截
// reports/ 落盘——「目标可判定、进度可恢复、终态有门槛」共用这一份文件契约。

import fs from "node:fs";
import path from "node:path";
import { defineTool } from "@deepseek-ai/dsh-tools";

//#region gate schema

/**
 * Check kinds (v1, structural only):
 *  - file        : file exists and is non-empty
 *  - markers     : file contains every marker string
 *  - hexHash     : file contains a 64-hex hash (sha256)
 *  - table       : file holds >= minRows table rows, each with >= minCells non-empty cells
 *  - provenance  : artifacts/ has >=1 <sub>/provenance.md carrying a 64-hex hash
 */
const GATES = {
	pentest: {
		"P1": {
			title: "资产与环境基线",
			checks: [
				{ kind: "file", file: "assets.md" },
				{ kind: "markers", file: "assets.md", markers: ["WAF", "速率"] },
				{ kind: "table", file: "assets.md", minRows: 2, minCells: 2 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 }
			],
			manual: []
		},
		"P2": {
			title: "finding 对照三件套 + 复核记录",
			requiresFile: true,
			fileHint: "该 finding 的六字段报告文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["基线", "差分", "marker", "复核"] }
			],
			manual: ["对照三件套的语义成立（差分真实翻转、marker 逐字回显）与复核员确认/双签记录由复核员判定"]
		},
		"P3": {
			title: "覆盖度（资产×漏洞类全集）",
			checks: [
				{ kind: "file", file: "coverage-matrix.md" },
				{ kind: "table", file: "coverage-matrix.md", minRows: 3, minCells: 3 }
			],
			manual: ["N-A 格理由是否成立由复核员抽查"]
		}
	},
	"code-audit": {
		"A1": {
			title: "前置识别 + 面映射",
			checks: [
				{ kind: "file", file: "surface-map.md" },
				{ kind: "markers", file: "surface-map.md", markers: ["入口", "sink", "深度"] },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] }
			],
			manual: ["已知漏洞核对结论与深度分级合理性"]
		},
		"A2": {
			title: "双链一致（审计工人链 vs 追踪员链）",
			requiresFile: true,
			fileHint: "该 finding 的调用链记录文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["entry", "sink"] }
			],
			manual: ["两条链语义一致由复核员判定；不一致退回重追或降疑似"]
		},
		"A3": {
			title: "覆盖度（模块×sink 全集）+ 扫描命中对账",
			checks: [
				{ kind: "file", file: "audit-coverage-matrix.md" },
				{ kind: "table", file: "audit-coverage-matrix.md", minRows: 3, minCells: 3 },
				{ kind: "file", file: "scan-reconcile.md" },
				{ kind: "markers", file: "scan-reconcile.md", markers: ["确认", "误报"] }
			],
			manual: ["命中数量守恒（扫描器报告数=终态数）由复核员核对"]
		}
	},
	"binary-analysis": {
		"B0": {
			title: "样本登记门",
			checks: [
				{ kind: "provenance", dir: "artifacts" }
			],
			manual: ["来源与日期的真实性"]
		},
		"B1": {
			title: "还原完整性三验",
			requiresFile: true,
			fileHint: "该还原产物的验证记录文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["dex", "IAT", "可运行"] },
				{ kind: "hexHash", file: "$file" }
			],
			manual: ["三项验证的语义结论（通过/不通过）由复核员判定；不过=疑似"]
		},
		"B2": {
			title: "分析维度覆盖 + 假设台账终态",
			checks: [
				{ kind: "file", file: "analysis-coverage.md" },
				{ kind: "table", file: "analysis-coverage.md", minRows: 3, minCells: 3 },
				{ kind: "file", file: "hypothesis-ledger.md" },
				{ kind: "markers", file: "hypothesis-ledger.md", markers: ["确认", "证伪"] }
			],
			manual: ["未决假设不得写成事实"]
		}
	},
	"attack-defense": {
		"recon": {
			title: "阶段①侦察产物",
			checks: [
				{ kind: "file", file: "assets.md" },
				{ kind: "table", file: "assets.md", minRows: 2, minCells: 2 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 }
			],
			manual: []
		},
		"breach": {
			title: "阶段②突破产物（路径台账）",
			checks: [
				{ kind: "file", file: "paths-ledger.md" },
				{ kind: "markers", file: "paths-ledger.md", markers: ["candidate", "chosen"] },
				{ kind: "table", file: "paths-ledger.md", minRows: 1, minCells: 3 }
			],
			manual: ["已验证 finding 的证据由复核员 gate-pass 判定"]
		},
		"lateral": {
			title: "阶段③横向（前置=已验证突破）",
			requiresFile: true,
			fileHint: "横向证据记录文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["授权"] }
			],
			manual: ["前置突破已验证、范围合规由复核员判定"]
		},
		"persistence": {
			title: "阶段④持久化登记",
			checks: [
				{ kind: "file", file: "persistence-registry.md" },
				{ kind: "markers", file: "persistence-registry.md", markers: ["手动排除"] },
				{ kind: "table", file: "persistence-registry.md", minRows: 1, minCells: 4 }
			],
			manual: ["登记即满足；排除步骤可执行性由用户验收"]
		},
		"report": {
			title: "阶段⑤报告完整性",
			requiresFile: true,
			fileHint: "总评估报告文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["漏洞名称", "ATT&CK", "detection gap", "持久化清单", "路径台账", "阶段终态"] },
				{ kind: "file", file: "op-traces.md" },
				{ kind: "markers", file: "op-traces.md", markers: ["shell 地址", "ssh 密钥", "创建的用户"] },
				{ kind: "table", file: "op-traces.md", minRows: 1, minCells: 4 }
			],
			manual: ["每个 finding 带复核 gate-pass 签名由报告员保证", "操作痕迹台账须覆盖全部已登记 webshell/ssh 密钥/新建用户（无则填「无」行）"]
		}
	},
	"av-evasion": {
		"V1": {
			title: "实验计划门（三声明）",
			checks: [
				{ kind: "file", file: "experiment-plan.md" },
				{ kind: "markers", file: "experiment-plan.md", markers: ["测试环境", "产物去向", "持久化预案"] }
			],
			manual: ["三声明语义成立由总控判定：测试环境为本地或任务授权目标；产物去向（实验室目录或任务工作区）如实；涉及持久化则预案与登记制（persistence-registry，含手动排除步骤）一致"]
		},
		"V3": {
			title: "配对完整（技术↔检测双向镜像）",
			requiresFile: true,
			fileHint: "该轮实验报告文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["技术侧", "检测侧"] }
			],
			manual: ["镜像两侧语义对称（同一技术同一实现）由复核员判定"]
		},
		"V2": {
			title: "证据三件",
			requiresFile: true,
			fileHint: "判定日志文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["构建", "判定"] },
				{ kind: "hexHash", file: "$file" }
			],
			manual: ["哈希一致、时间戳合理由复核员核对"]
		},
		"V4": {
			title: "结论外推检查",
			requiresFile: true,
			fileHint: "实验结论文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["已测环境"] }
			],
			manual: ["结论范围 ≤ 已测环境范围——语义判断由总控/复核员执行"]
		}
	},
	"incident-response": {
		"I1": {
			title: "证据保全登记",
			checks: [
				{ kind: "file", file: "evidence-preservation.md" },
				{ kind: "markers", file: "evidence-preservation.md", markers: ["保全项", "取证命令"] },
				{ kind: "table", file: "evidence-preservation.md", minRows: 1, minCells: 4 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 }
			],
			manual: ["保全动作可追溯、取证只读优先由复核员判定"]
		},
		"I2": {
			title: "时间线与攻击链还原",
			checks: [
				{ kind: "file", file: "attack-timeline.md" },
				{ kind: "markers", file: "attack-timeline.md", markers: ["时间节点", "可疑IP", "证据"] },
				{ kind: "table", file: "attack-timeline.md", minRows: 3, minCells: 4 }
			],
			manual: ["链上断点如实标注「未知」；节点证据编号可追溯由复核员判定"]
		},
		"I3": {
			title: "失陷定性收口",
			checks: [
				{ kind: "file", file: "compromise-verdict.md" },
				{ kind: "markers", file: "compromise-verdict.md", markers: ["定性", "证据"] },
				{ kind: "table", file: "compromise-verdict.md", minRows: 1, minCells: 4 }
			],
			manual: ["confirmed/疑似/排除三态语义由复核员判定；疑似不得进 confirmed"]
		},
		"I4": {
			title: "处置建议（清理清单完整性）",
			checks: [
				{ kind: "file", file: "remediation-checklist.md" },
				{ kind: "markers", file: "remediation-checklist.md", markers: ["处置步骤", "验证方式", "用户确认"] },
				{ kind: "table", file: "remediation-checklist.md", minRows: 1, minCells: 4 }
			],
			manual: ["删除类操作标注「用户确认后执行」；步骤可执行性由用户验收"]
		},
		"I5": {
			title: "报告完整性",
			requiresFile: true,
			fileHint: "应急溯源报告文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["时间线", "失陷原因", "ATT&CK", "处置建议", "证据索引"] }
			],
			manual: ["每个 finding 带复核 gate-pass 签名由报告员保证"]
		}
	},
	"cloud-security": {
		"C1": {
			title: "云资产与暴露面测绘",
			checks: [
				{ kind: "file", file: "cloud-assets.md" },
				{ kind: "markers", file: "cloud-assets.md", markers: ["资产", "暴露面", "凭证", "基线快照"] },
				{ kind: "table", file: "cloud-assets.md", minRows: 2, minCells: 4 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 }
			],
			manual: ["暴露面完整、凭证来源可追溯、基线快照可还原由复核员判定"]
		},
		"C2": {
			title: "攻击路径验证",
			checks: [
				{ kind: "file", file: "attack-paths.md" },
				{ kind: "markers", file: "attack-paths.md", markers: ["入口", "身份", "权限", "资源", "影响", "证据"] },
				{ kind: "table", file: "attack-paths.md", minRows: 1, minCells: 6 }
			],
			manual: ["每条路径影响证明级证据、四要素闭环无悬空由复核员判定"]
		},
		"C3": {
			title: "横向与持久化",
			checks: [
				{ kind: "file", file: "lateral-persistence.md" },
				{ kind: "markers", file: "lateral-persistence.md", markers: ["授权", "验证状态", "证据", "排除步骤"] },
				{ kind: "table", file: "lateral-persistence.md", minRows: 1, minCells: 5 }
			],
			manual: ["超范围项标「未执行」零虚构；授权内持久化已登记手动排除步骤"]
		},
		"C4": {
			title: "权限链收口",
			checks: [
				{ kind: "file", file: "privilege-chains.md" },
				{ kind: "markers", file: "privilege-chains.md", markers: ["起点", "权限", "终点", "证据"] },
				{ kind: "table", file: "privilege-chains.md", minRows: 1, minCells: 4 }
			],
			manual: ["每链独立证据、无悬空链、疑似不得进 confirmed 由复核员判定"]
		},
		"C5": {
			title: "检测缺口评估",
			checks: [
				{ kind: "file", file: "detection-gap.md" },
				{ kind: "markers", file: "detection-gap.md", markers: ["审计", "检测", "终态"] },
				{ kind: "table", file: "detection-gap.md", minRows: 1, minCells: 3 }
			],
			manual: ["每关键路径配检测侧结论、终态三选一禁留空由复核员判定"]
		},
		"C6": {
			title: "环境还原",
			checks: [
				{ kind: "file", file: "environment-restore.md" },
				{ kind: "markers", file: "environment-restore.md", markers: ["对象", "还原方式", "验证状态"] },
				{ kind: "table", file: "environment-restore.md", minRows: 1, minCells: 3 }
			],
			manual: ["测试改动全登记、还原可验证、删除类标「用户确认后执行」"]
		},
		"C7": {
			title: "报告完整性",
			requiresFile: true,
			fileHint: "云安全评估报告文件路径",
			checks: [
				{ kind: "markers", file: "$file", markers: ["攻击路径", "配置缺陷", "权限链", "检测缺口", "环境还原", "证据索引", "阶段终态"] }
			],
			manual: ["每条攻击路径带复核 gate-pass 签名由报告员保证"]
		}
	},
	"ctf-solver": {
		board: {
			title: "题面登记",
			checks: [
				{ kind: "file", file: "challenge-board.md" },
				{ kind: "markers", file: "challenge-board.md", markers: ["题名", "模块", "线索"] },
				{ kind: "table", file: "challenge-board.md", minRows: 1, minCells: 3 },
				{ kind: "file", file: "evidence-index.md" },
				{ kind: "markers", file: "evidence-index.md", markers: ["tool-plane", "MCP"] },
				{ kind: "table", file: "evidence-index.md", minRows: 1, minCells: 2 }
			],
			manual: ["每行线索已梳理、模块判定合理由总控判定"]
		},
		flag: {
			title: "flag 台账收口",
			checks: [
				{ kind: "file", file: "flag-ledger.md" },
				{ kind: "markers", file: "flag-ledger.md", markers: ["flag", "验证", "状态"] },
				{ kind: "table", file: "flag-ledger.md", minRows: 1, minCells: 4 }
			],
			manual: ["每个「已解」flag 带验证证据；未解标卡点——不猜不撞不伪造由复核员判定"]
		}
	}
};

//#endregion

//#region pure validators (exported for tests)

const HEX64 = /[a-f0-9]{64}/i;

function readSafe(fsm, p) {
	try { return fsm.readFileSync(p, "utf8"); } catch { return undefined; }
}

/** Parse markdown table rows; separator rows (|---|) excluded. Returns per-row non-empty cell counts. */
export function tableRows(text) {
	const rows = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i].trim();
		if (!line.startsWith("|")) continue;
		const cells = line.split("|").slice(1, line.endsWith("|") ? -1 : undefined).map((c) => c.trim());
		if (cells.length > 0 && cells.every((c) => /^:?-{2,}:?$/.test(c))) continue;
		rows.push({ line: i + 1, nonEmpty: cells.filter((c) => c.length > 0).length });
	}
	return rows;
}

function runCheck(fsm, check, resolve) {
	const file = check.file === "$file" ? resolve.file : check.file && resolve.workspace(check.file);
	switch (check.kind) {
		case "file": {
			const text = file && readSafe(fsm, file);
			return { ok: !!text && text.trim().length > 0, detail: file ?? "(missing $file)" };
		}
		case "markers": {
			const text = file && readSafe(fsm, file);
			if (!text) return { ok: false, detail: `${file ?? "(missing $file)"} 不存在` };
			const missing = check.markers.filter((m) => !text.includes(m));
			return { ok: missing.length === 0, detail: missing.length ? `${file} 缺标记: ${missing.join(", ")}` : file };
		}
		case "hexHash": {
			const text = file && readSafe(fsm, file);
			return { ok: !!text && HEX64.test(text), detail: file ?? "(missing $file)" };
		}
		case "table": {
			const text = file && readSafe(fsm, file);
			if (!text) return { ok: false, detail: `${file ?? "(missing $file)"} 不存在` };
			const rows = tableRows(text);
			const incomplete = rows.filter((r) => r.nonEmpty < (check.minCells ?? 1)).map((r) => `L${r.line}`);
			const ok = rows.length >= (check.minRows ?? 1) && incomplete.length === 0;
			return { ok, detail: `${file}: ${rows.length} 行（要求 ≥${check.minRows}），未填满行: ${incomplete.join(",") || "无"}` };
		}
		case "provenance": {
			const dir = resolve.workspace(check.dir ?? "artifacts");
			let entries = [];
			try { entries = fsm.readdirSync(dir, { withFileTypes: true }); } catch { return { ok: false, detail: `${dir} 不存在` }; }
			for (const e of entries) {
				if (!e.isDirectory()) continue;
				const p = path.join(dir, e.name, "provenance.md");
				const text = readSafe(fsm, p);
				if (text && HEX64.test(text)) return { ok: true, detail: p };
			}
			return { ok: false, detail: `${dir}/*/provenance.md 无带哈希登记` };
		}
		default:
			return { ok: false, detail: `unknown check kind ${check.kind}` };
	}
}

/**
 * Validate one gate. Pure apart from `fsm` (inject node:fs in production, fixtures in tests).
 * @returns {{ mode: string, stage: string, title: string, pass: boolean, checks: object[],
 *             manual: string[], missing: string[] }}
 */
export function runGate(fsm, { mode, stage, workspace, file }) {
	const gate = GATES[mode]?.[stage];
	if (!gate) throw new Error(`unknown gate ${mode}/${stage}; valid stages: ${Object.keys(GATES[mode] ?? {}).join(", ") || "(unknown mode)"}`);
	const resolve = {
		workspace: (f) => path.resolve(workspace, f),
		file: file ? (path.isAbsolute(file) ? path.resolve(file) : path.resolve(workspace, file)) : undefined
	};
	if (gate.requiresFile && !file) throw new Error(`gate ${mode}/${stage} 需要 file 参数（${gate.fileHint}）`);
	const results = gate.checks.map((check) => ({ id: `${check.kind}:${check.file ?? check.dir}`, ...runCheck(fsm, check, resolve) }));
	return {
		mode,
		stage,
		title: gate.title,
		pass: results.every((r) => r.ok),
		checks: results,
		manual: gate.manual,
		missing: results.filter((r) => !r.ok).map((r) => `${r.id} — ${r.detail}`)
	};
}

/** Schema summary for gates_list. */
export function listGates(mode) {
	if (mode && !GATES[mode]) throw new Error(`unknown mode ${mode}; valid: ${Object.keys(GATES).join(", ")}`);
	const modes = mode ? { [mode]: GATES[mode] } : GATES;
	return Object.fromEntries(Object.entries(modes).map(([m, stages]) => [
		m,
		Object.fromEntries(Object.entries(stages).map(([s, g]) => [s, {
			title: g.title,
			files: [...new Set(g.checks.filter((c) => c.file && c.file !== "$file").map((c) => c.file))],
			requiresFile: !!g.requiresFile,
			manual: g.manual
		}]))
	]));
}

//#endregion

//#region plugin

const name = "stage-gate";
const inject = ["tools"];

/** Append the verdict line to <workspace>/gate-log.md (audit trail); write failure never flips the verdict. */
function appendGateLog(workspace, verdict) {
	const line = `| ${new Date().toISOString()} | ${verdict.mode}/${verdict.stage} | ${verdict.pass ? "pass" : "fail"} | ${verdict.missing.join(" ; ") || "-"} |\n`;
	const log = path.join(workspace, "gate-log.md");
	let head = "";
	try { head = fs.readFileSync(log, "utf8"); } catch { head = "# gate-log（阶段门禁判定审计 trail）\n\n| 时间 | 门 | 结果 | 缺项 |\n|---|---|---|---|\n"; }
	fs.mkdirSync(workspace, { recursive: true });
	fs.writeFileSync(log, head + line);
}

//#region operation state（目标契约 / 中断恢复的文件契约）

const STATE_FILE = "operation-state.json";

/** 读工作区运行状态；不存在返回 null（纯函数，导出供 route-boost/sec-enforce/测试复用）。 */
export function readOperationState(fsys, workspace) {
	try {
		const raw = fsys.readFileSync(path.join(workspace, STATE_FILE), "utf8");
		const st = JSON.parse(raw);
		if (st && typeof st === "object" && Array.isArray(st.criteria)) return st;
	} catch { /* 缺失或损坏都按无状态处理 */ }
	return null;
}

/** stage_gate 判定后同步 gates 进度（无契约时也落骨架——恢复盘先于契约也能工作）；失败静默。 */
function syncOperationState(workspace, verdict) {
	try {
		const file = path.join(workspace, STATE_FILE);
		let st = readOperationState(fs, workspace);
		if (st === null) st = { version: 1, mode: verdict.mode, goal: "", criteria: [], gates: {}, pending: [], created_at: new Date().toISOString() };
		st.mode = verdict.mode;
		st.gates = st.gates && typeof st.gates === "object" ? st.gates : {};
		st.gates[verdict.stage] = { pass: verdict.pass, at: new Date().toISOString() };
		st.updated_at = new Date().toISOString();
		fs.mkdirSync(workspace, { recursive: true });
		fs.writeFileSync(file, JSON.stringify(st, null, 2) + "\n");
	} catch { /* 状态同步失败不影响门禁判定 */ }
}

const cleanLine = (s, max) => String(s ?? "").trim().slice(0, max);
const parseIds = (s) => String(s ?? "").split(/[,，;\s]+/).map((x) => x.trim()).filter(Boolean);

/** 登记目标契约：criteria 为多行文本，每行一条成功准则（可判定表述）。 */
function setGoal(workspace, goal, criteriaText) {
	const lines = String(criteriaText ?? "").split(/\r?\n/).map((l) => cleanLine(l, 200)).filter(Boolean);
	if (!cleanLine(goal, 500)) throw new Error("goal required（目标一句话）");
	if (lines.length === 0) throw new Error("criteria required（至少一条成功准则，每行一条）");
	if (lines.length > 20) throw new Error("criteria 最多 20 条");
	const prev = readOperationState(fs, workspace);
	const st = prev ?? { version: 1, mode: "", gates: {}, pending: [], created_at: new Date().toISOString() };
	st.goal = cleanLine(goal, 500);
	st.criteria = lines.map((text, i) => ({ id: `g${i + 1}`, text, status: "open", evidence: "" }));
	st.updated_at = new Date().toISOString();
	fs.mkdirSync(workspace, { recursive: true });
	fs.writeFileSync(path.join(workspace, STATE_FILE), JSON.stringify(st, null, 2) + "\n");
	return st;
}

/** 收口准则 / 维护待办；返回摘要（verdict=all-met 表示目标契约已全部达成）。 */
function updateProgress(workspace, { met = "", failed = "", reopened = "", pending = "", note = "" }) {
	const st = readOperationState(fs, workspace);
	if (st === null) throw new Error("operation-state.json 不存在——先 operation_goal 登记目标契约");
	const byId = new Map(st.criteria.map((c) => [c.id, c]));
	const unknown = [];
	for (const [list, status] of [[met, "met"], [failed, "failed"], [reopened, "open"]]) {
		for (const id of parseIds(list)) {
			const c = byId.get(id);
			if (c === undefined) unknown.push(id);
			else c.status = status;
		}
	}
	if (unknown.length) throw new Error(`未知准则 id：${unknown.join(", ")}（有效：${[...byId.keys()].join(", ") || "无"}）`);
	if (pending !== "") st.pending = pending.split(/\r?\n/).map((l) => cleanLine(l, 200)).filter(Boolean);
	if (note) st.note = cleanLine(note, 500);
	st.updated_at = new Date().toISOString();
	fs.writeFileSync(path.join(workspace, STATE_FILE), JSON.stringify(st, null, 2) + "\n");
	const openIds = st.criteria.filter((c) => c.status !== "met").map((c) => c.id);
	return { goal: st.goal, total: st.criteria.length, met: st.criteria.length - openIds.length, open: openIds.length, openIds, pending: st.pending, verdict: openIds.length === 0 ? "all-met" : "open-remaining" };
}

//#endregion

function apply(ctx) {
	ctx.tools.register(defineTool({
		name: "stage_gate",
		description: "Validate a task-workspace stage artifact against the security presets' gate schemas (structural checks: files present/non-empty, required markers, complete table rows, hashed provenance). Call it BEFORE advancing a stage or accepting a finding/report into the final report; the verdict appends to <workspace>/gate-log.md. Structural pass ≠ full pass — the `manual` entries list what reviewers must still judge.",
		parameters: {
			mode: { type: "string", required: true, enum: Object.keys(GATES), description: "Preset mode" },
			stage: { type: "string", required: true, description: "Gate id: pentest P1/P2/P3 · code-audit A1/A2/A3 · binary-analysis B0/B1/B2 · attack-defense recon/breach/lateral/persistence/report · av-evasion V1..V4 · incident-response I1..I5 · cloud-security C1..C7 · ctf-solver board/flag" },
			workspace: { type: "string", required: true, description: "Task workspace root (absolute, or relative to cwd)" },
			file: { type: "string", description: "Gate-scoped file path (report / chain / verdict log / plan) — required by per-finding gates; a relative path resolves against the workspace" }
		},
		output: {
			schema: {
				type: "object",
				additionalProperties: true,
				properties: {
					pass: { type: "boolean", required: true },
					missing: { type: "array", required: true },
					manual: { type: "array", required: true }
				}
			},
			render: (_args, value) => [{ type: "text", text: `stage_gate ${value.mode}/${value.stage}: ${value.pass ? "PASS" : "FAIL"}${value.missing.length ? ` — missing: ${value.missing.join(" ; ")}` : ""}${value.manual.length ? ` — manual review still required: ${value.manual.join(" ; ")}` : ""}` }]
		},
		execute(args) {
			const workspace = path.resolve(args.workspace);
			const verdict = runGate(fs, { ...args, workspace });
			try { appendGateLog(workspace, verdict); } catch { /* audit-write failure never flips the verdict */ }
			try { syncOperationState(workspace, verdict); } catch { /* state-sync failure never flips the verdict */ }
			return Promise.resolve(verdict);
		}
	}));
	ctx.tools.register(defineTool({
		name: "operation_goal",
		description: "Register the task's goal as a decidable contract into <workspace>/operation-state.json: one-line goal + success criteria (one per line, each independently verifiable). Do this at task start (before the first stage_gate). Criteria close one by one via operation_progress; reports/ output additionally requires every criterion met. The same file powers interruption recovery — a fresh session resumes from it.",
		parameters: {
			workspace: { type: "string", required: true, description: "Task workspace root (absolute, or relative to cwd)" },
			goal: { type: "string", required: true, description: "目标一句话（≤500 字符）" },
			criteria: { type: "string", required: true, description: "成功准则，每行一条（可判定表述，如「getshell 证据：whoami 输出与 evidence 编号」「全量 12 条路由均给出终态」），≤20 条" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_args, v) => [{ type: "text", text: v.ok ? `目标契约已登记：${v.total} 条准则（${v.ids.join(", ")}）。逐条 met 用 operation_progress；全部 met + 报告门通过后才可写 reports/。` : `登记失败：${v.error}` }]
		},
		execute(args) {
			try {
				const st = setGoal(path.resolve(args.workspace), args.goal, args.criteria);
				return Promise.resolve({ ok: true, total: st.criteria.length, ids: st.criteria.map((c) => c.id) });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));
	ctx.tools.register(defineTool({
		name: "operation_progress",
		description: "Close or reopen goal-contract criteria in <workspace>/operation-state.json (registered via operation_goal), and maintain the pending-actions list. `met` ids should carry their evidence reference in the workspace evidence-index. Returns the open/remaining summary; verdict=all-met means the contract is fully satisfied.",
		parameters: {
			workspace: { type: "string", required: true, description: "Task workspace root" },
			met: { type: "string", description: "已达成准则 id（逗号/空格分隔，如 g1 g3）" },
			failed: { type: "string", description: "证伪准则 id（该准则按失败收口）" },
			reopened: { type: "string", description: "重开准则 id（回 open）" },
			pending: { type: "string", description: "待办动作清单（整表替换，每行一条；空串=清空）" },
			note: { type: "string", description: "进度注记（≤500 字符）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { verdict: { type: "string", required: true } } },
			render: (_args, v) => [{ type: "text", text: `operation 进度：met ${v.met}/${v.total}${v.openIds?.length ? `，未收口 ${v.openIds.join(", ")}` : ""}${v.pending?.length ? `，待办 ${v.pending.length} 项` : ""}——${v.verdict === "all-met" ? "目标契约已全部达成" : "收口后才可产出 reports/"}` }]
		},
		execute(args) {
			try {
				return Promise.resolve(updateProgress(path.resolve(args.workspace), args));
			} catch (e) {
				return Promise.resolve({ verdict: "error", error: e?.message ?? String(e) });
			}
		}
	}));
	ctx.tools.register(defineTool({
		name: "gates_list",
		description: "List the stage-gate schemas: each mode's gates, their canonical workspace files, whether a gate-scoped `file` argument is required, and the manual (reviewer-judged) items. Read this first when a workspace is created or before calling stage_gate.",
		parameters: {
			mode: { type: "string", enum: Object.keys(GATES), description: "Omit to list every mode" }
		},
		output: {
			schema: { type: "object", additionalProperties: true },
			render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }]
		},
		execute(args) {
			return Promise.resolve(listGates(args.mode));
		}
	}));
}

export { GATES, apply, inject, name, setGoal, updateProgress, syncOperationState, STATE_FILE };

//#endregion
