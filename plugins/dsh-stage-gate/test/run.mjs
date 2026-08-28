// Standalone tests for dsh-stage-gate pure validators (no DSH runtime needed).
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import { runGate, listGates, tableRows, setGoal, updateProgress, setScope, markTested, coverageCheck, syncOperationState, registerIntent, intentSummary, validateAnchor, setConstraints, constraintSummary, deriveScopeDraft, DECOMPOSITION, readOperationState as ros } from "../lib/index.js";

const F = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "fixture");
let failed = 0;
function expect(name, cond, detail) {
	if (cond) console.log(`ok   ${name}`);
	else { failed++; console.log(`FAIL ${name} ${detail ?? ""}`); }
}

// tableRows: separator excluded, cells counted
const t = tableRows("| a | b |\n|---|---|\n| c |  |\nplain");
expect("tableRows counts 2 rows", t.length === 2, JSON.stringify(t));
expect("tableRows counts non-empty cells", t[1].nonEmpty === 1, JSON.stringify(t));

// pentest P1 pass
let v = runGate(fs, { mode: "pentest", stage: "P1", workspace: F });
expect("pentest/P1 pass", v.pass === true, JSON.stringify(v.missing));

// pentest P1 fail on empty workspace
v = runGate(fs, { mode: "pentest", stage: "P1", workspace: path.join(F, "nowhere") });
expect("pentest/P1 fails on missing workspace", v.pass === false);

// pentest P1 fail when evidence-index lacks tool-plane/MCP markers
{
	const tmp = fs.mkdtempSync(path.join(path.dirname(F), "p1-nomcp-"));
	for (const name of fs.readdirSync(F)) {
		if (fs.statSync(path.join(F, name)).isFile()) fs.copyFileSync(path.join(F, name), path.join(tmp, name));
	}
	const ev = path.join(tmp, "evidence-index.md");
	fs.writeFileSync(ev, fs.readFileSync(ev, "utf8").replace(/## tool-plane[\s\S]*$/, ""));
	v = runGate(fs, { mode: "pentest", stage: "P1", workspace: tmp });
	expect("pentest/P1 fails without tool-plane/MCP markers", v.pass === false);
	v = runGate(fs, { mode: "attack-defense", stage: "recon", workspace: tmp });
	expect("ad/recon fails without tool-plane/MCP markers", v.pass === false);
	v = runGate(fs, { mode: "code-audit", stage: "A1", workspace: tmp });
	expect("audit/A1 fails without tool-plane/MCP markers", v.pass === false);
	for (const [mode, stage] of [["incident-response", "I1"], ["cloud-security", "C1"], ["binary-analysis", "B0"], ["ctf-solver", "board"]]) {
		v = runGate(fs, { mode, stage, workspace: tmp });
		expect(`${mode}/${stage} fails without tool-plane/MCP markers`, v.pass === false);
	}
	fs.rmSync(tmp, { recursive: true, force: true });
}

// pentest P2 requires file
let threw = false;
try { runGate(fs, { mode: "pentest", stage: "P2", workspace: F }); } catch { threw = true; }
expect("P2 without file throws", threw);

// pentest P2 markers check against a report file
const report = path.join(F, "report-tmp.md");
fs.writeFileSync(report, "# 测试过程\n基线…差分…marker…复核记录…\n");
v = runGate(fs, { mode: "pentest", stage: "P2", workspace: F, file: report });
expect("P2 pass with markers file", v.pass === true, JSON.stringify(v.missing));
expect("P2 lists manual items", v.manual.length >= 1);

// P2 relative file resolves against the workspace (baseline-self-test)
const relReport = path.join(F, "reports", "rel-report.md");
fs.mkdirSync(path.join(F, "reports"), { recursive: true });
fs.writeFileSync(relReport, "# 测试过程\n基线…差分…marker…复核…\n");
v = runGate(fs, { mode: "pentest", stage: "P2", workspace: F, file: "reports/rel-report.md" });
expect("P2 relative file resolves against workspace", v.pass === true, JSON.stringify(v.missing));
fs.rmSync(relReport, { force: true });

// pentest P3 pass (3 rows, 3 cells + 复核汇总账)
v = runGate(fs, { mode: "pentest", stage: "P3", workspace: F });
expect("pentest/P3 pass", v.pass === true, JSON.stringify(v.missing));

// pentest P3 缺复核汇总账 = 不过（报告门双签前置）
{
	const ws2 = fs.mkdtempSync(path.join(os.tmpdir(), "p3-no-review-"));
	for (const name of fs.readdirSync(F)) {
		if (fs.statSync(path.join(F, name)).isFile() && name !== "review-log.md") fs.copyFileSync(path.join(F, name), path.join(ws2, name));
	}
	const v2 = runGate(fs, { mode: "pentest", stage: "P3", workspace: ws2 });
	expect("P3 missing review-log fails", v2.pass === false && v2.missing.some((m) => m.includes("review-log")), JSON.stringify(v2.missing));
	fs.rmSync(ws2, { recursive: true, force: true });
}

// code-audit A1 fail (no surface-map.md)
v = runGate(fs, { mode: "code-audit", stage: "A1", workspace: F });
expect("audit/A1 fails without surface-map", v.pass === false);

// binary B0 provenance pass
v = runGate(fs, { mode: "binary-analysis", stage: "B0", workspace: F });
expect("binary/B0 provenance pass", v.pass === true, JSON.stringify(v.missing));

// binary B1 requires file + markers + hex
const verify = path.join(F, "unpack-verify-tmp.md");
fs.writeFileSync(verify, "# 三验\ndex 校验通过；IAT 重建有效；可运行性 OK\n产物 sha256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n");
v = runGate(fs, { mode: "binary-analysis", stage: "B1", workspace: F, file: verify });
expect("binary/B1 pass", v.pass === true, JSON.stringify(v.missing));

// attack-defense persistence fail (no registry)
v = runGate(fs, { mode: "attack-defense", stage: "persistence", workspace: F });
expect("ad/persistence fails without registry", v.pass === false);

// attack-defense report: 操作痕迹台账门禁（缺→不过；全→过）
const adws = fs.mkdtempSync(path.join(path.dirname(F), "ad-report-"));
const adreport = path.join(adws, "report.md");
fs.writeFileSync(adreport, "# 报告\n漏洞名称…ATT&CK…detection gap…持久化清单…路径台账…阶段终态…\n");
v = runGate(fs, { mode: "attack-defense", stage: "report", workspace: adws, file: adreport });
expect("ad/report fails without op-traces", v.pass === false);
fs.writeFileSync(path.join(adws, "op-traces.md"), "# 操作痕迹台账\n| 时间 | shell 地址 | ssh 密钥 | 创建的用户 | 位置 |\n|---|---|---|---|---|\n| 2026-01-01 | 无 | 无 | 无 | 无 |\n");
v = runGate(fs, { mode: "attack-defense", stage: "report", workspace: adws, file: adreport });
expect("ad/report passes with op-traces", v.pass === true, JSON.stringify(v.missing));
fs.rmSync(adws, { recursive: true, force: true });

// av V1 fail (no plan)
v = runGate(fs, { mode: "av-evasion", stage: "V1", workspace: F });
expect("av/V1 fails without plan", v.pass === false);

// av V1 pass with the three declarations (攻击视角重订口径)
const plan = path.join(F, "experiment-plan-tmp.md");
fs.writeFileSync(plan, "# 实验计划\n测试环境：本地默认（授权目标按任务）。\n产物去向：实验室目录或任务工作区。\n持久化预案：不涉及；涉及则登记 persistence-registry（含手动排除步骤）。\n");
v = runGate(fs, { mode: "av-evasion", stage: "V1", workspace: F, file: path.join(F, "experiment-plan.md") });
expect("av/V1 fails while plan only exists under another name", v.pass === false);
fs.copyFileSync(plan, path.join(F, "experiment-plan.md"));
v = runGate(fs, { mode: "av-evasion", stage: "V1", workspace: F });
expect("av/V1 pass with new-declaration markers", v.pass === true, JSON.stringify(v.missing));
expect("av/V1 manual carries registry-system wording", v.manual.length >= 1 && v.manual[0].includes("登记制"));
fs.rmSync(plan, { force: true });
fs.rmSync(path.join(F, "experiment-plan.md"), { force: true });

// incident-response I1 fail (no evidence-preservation.md)
v = runGate(fs, { mode: "incident-response", stage: "I1", workspace: F });
expect("ir/I1 fails without preservation list", v.pass === false);

// incident-response I2 pass with a timeline table (3 rows, 4 cells, required markers)
const timeline = path.join(F, "attack-timeline-tmp.md");
fs.writeFileSync(timeline, "| 时间节点 | 可疑IP | 事件 | 证据 |\n|---|---|---|---|\n| 2026-08-01 02:11 | 203.0.113.5 | SSH 爆破成功登录 | E1 |\n| 2026-08-01 02:17 | 203.0.113.5 | 恶意样本落盘 /tmp/.x | E2 |\n| 2026-08-01 02:20 | 203.0.113.5 | crontab 持久化 | E3 |\n");
fs.copyFileSync(timeline, path.join(F, "attack-timeline.md"));
v = runGate(fs, { mode: "incident-response", stage: "I2", workspace: F });
expect("ir/I2 pass with timeline table", v.pass === true, JSON.stringify(v.missing));
fs.rmSync(timeline, { force: true });
fs.rmSync(path.join(F, "attack-timeline.md"), { force: true });

// incident-response I5 requires file
threw = false;
try { runGate(fs, { mode: "incident-response", stage: "I5", workspace: F }); } catch { threw = true; }
expect("ir/I5 without file throws", threw);

// cloud-security C1 fail (no cloud-assets.md)
v = runGate(fs, { mode: "cloud-security", stage: "C1", workspace: F });
expect("cloud/C1 fails without cloud-assets.md", v.pass === false);

// cloud-security C2 pass with an attack-paths table (1 row, 6 cells, required markers)
const paths = path.join(F, "attack-paths-tmp.md");
fs.writeFileSync(paths, "| 入口 | 身份 | 权限 | 资源 | 影响 | 证据 |\n|---|---|---|---|---|---|\n| 泄露的 AK/SK | 阿里云 RAM 用户 | AdministratorAccess | OSS 桶 prod-backup | 列出并下载全部对象 | E1 |\n");
fs.copyFileSync(paths, path.join(F, "attack-paths.md"));
v = runGate(fs, { mode: "cloud-security", stage: "C2", workspace: F });
expect("cloud/C2 pass with attack-paths table", v.pass === true, JSON.stringify(v.missing));
fs.rmSync(paths, { force: true });
fs.rmSync(path.join(F, "attack-paths.md"), { force: true });

// cloud-security C7 requires file
threw = false;
try { runGate(fs, { mode: "cloud-security", stage: "C7", workspace: F }); } catch { threw = true; }
expect("cloud/C7 without file throws", threw);

// ctf-solver board fail (no challenge-board.md)
v = runGate(fs, { mode: "ctf-solver", stage: "board", workspace: F });
expect("ctf/board fails without challenge-board.md", v.pass === false);

// ctf-solver flag pass with a ledger table (1 row, 4 cells, required markers)
const ledger = path.join(F, "flag-ledger-tmp.md");
fs.writeFileSync(ledger, "| 题名 | 模块 | flag | 验证证据 | 状态 |\n|---|---|---|---|---|\n| warmup | web | flag{test} | 平台回显 Accepted | 已解 |\n");
fs.copyFileSync(ledger, path.join(F, "flag-ledger.md"));
v = runGate(fs, { mode: "ctf-solver", stage: "flag", workspace: F });
expect("ctf/flag pass with ledger table", v.pass === true, JSON.stringify(v.missing));
fs.rmSync(ledger, { force: true });
fs.rmSync(path.join(F, "flag-ledger.md"), { force: true });

// unknown gate throws with valid list
threw = false;
try { runGate(fs, { mode: "pentest", stage: "P9", workspace: F }); } catch (e) { threw = e.message.includes("P1"); }
expect("unknown gate throws listing valid stages", threw);

// gates_list covers eight gated modes
const list = listGates();
expect("gates_list covers 8 modes", Object.keys(list).length === 8);
expect("gates_list single mode", Object.keys(listGates("pentest")).length === 1);

// cleanup tmp files (gate-log handled below)
fs.rmSync(report, { force: true });
fs.rmSync(verify, { force: true });
fs.rmSync(path.join(F, "gate-log.md"), { force: true });

// ── operation-state：目标契约 / 进度收口 / 门禁自动同步 ──────────────────────
import os from "node:os";
{
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "opstate-"));
	const ws = path.join(tmp, "ws");
	// 登记：准则解析与 id 分配
	let st = setGoal(ws, "对 demo 靶站完成授权渗透并出报告", "P1 基线资产登记完成\nSQL 注入拿到 whoami 证据\n覆盖矩阵每格有终态");
	const parsed = ros(fs, ws);
	expect("operation_goal writes criteria with ids", parsed.criteria.length === 3 && parsed.criteria[0].id === "g1" && parsed.criteria.every((c) => c.status === "open"), JSON.stringify(parsed.criteria));
	expect("operation_goal keeps goal text", parsed.goal === "对 demo 靶站完成授权渗透并出报告");
	// 校验失败路径
	let threw = false;
	try { setGoal(path.join(tmp, "ws2"), "", "x"); } catch { threw = true; }
	expect("operation_goal rejects empty goal", threw);
	threw = false;
	try { setGoal(path.join(tmp, "ws3"), "g", "  \n"); } catch { threw = true; }
	expect("operation_goal rejects empty criteria", threw);
	// 进度：met/unknown/all-met
	let s = updateProgress(ws, { met: "g1 g2" });
	expect("operation_progress met two", s.met === 2 && s.open === 1 && s.openIds.join() === "g3", JSON.stringify(s));
	threw = false;
	try { updateProgress(ws, { met: "g9" }); } catch { threw = true; }
	expect("operation_progress rejects unknown id", threw);
	s = updateProgress(ws, { met: "g3", pending: "复测 g2\n导出报告" });
	expect("operation_progress all-met verdict", s.verdict === "all-met" && s.pending.length === 2, JSON.stringify(s));
	// 门禁自动同步：无契约时落骨架，已有契约保留 criteria
	syncOperationState(ws, { mode: "pentest", stage: "P1", pass: true });
	st = ros(fs, ws);
	expect("stage_gate sync records gate without touching criteria", st.gates.P1.pass === true && st.criteria.length === 3 && st.goal.length > 0, JSON.stringify({ g: st.gates, c: st.criteria.length }));
	const ws4 = path.join(tmp, "ws4");
	syncOperationState(ws4, { mode: "pentest", stage: "P1", pass: false });
	const skel = ros(fs, ws4);
	expect("stage_gate sync creates skeleton state", skel !== null && Array.isArray(skel.criteria) && skel.criteria.length === 0 && skel.gates.P1.pass === false);
	fs.rmSync(tmp, { recursive: true, force: true });
}

// ── 覆盖度台账（v1.1.0）：scope 登记 / tested 标记 / 报告门算术对账 ─────────────
{
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scope-"));
	const ws = path.join(tmp, "ws");
	fs.mkdirSync(ws, { recursive: true });
	setGoal(ws, "目标", "g1 准则");
	// scope 登记：自动 id / 显式 id / 重复 id 拒绝 / 先登记契约才可 scope
	let s = setScope(ws, "10.0.0.5 Web 前台\nweb-api: API 网关\ndb: 数据库面");
	const parsed = ros(fs, ws);
	expect("operation_scope auto+explicit ids", parsed.scope.length === 3 && parsed.scope[0].id === "s1" && parsed.scope[1].id === "web-api" && parsed.scope[2].id === "db", JSON.stringify(parsed.scope));
	expect("operation_scope summary starts untested", s.scope === 3 && s.tested === 0 && s.untested === 3);
	let threw = false;
	try { setScope(ws, "a: x\na: y"); } catch { threw = true; }
	expect("operation_scope rejects duplicate ids", threw);
	threw = false;
	try { setScope(path.join(tmp, "bare"), "x"); } catch { threw = true; }
	expect("operation_scope requires prior operation_goal", threw);
	// tested 标记：evidence 必填 / 未知 id 拒 / 幂等刷新 / 越界行剔除
	threw = false;
	try { markTested(ws, "s1", ""); } catch { threw = true; }
	expect("markTested requires evidence", threw);
	threw = false;
	try { markTested(ws, "g1", "ev-1"); } catch { threw = true; }
	expect("markTested rejects non-scope id", threw);
	s = markTested(ws, "s1 web-api", "evidence-index #12 与矩阵行 3");
	expect("markTested counts numerator", s.tested === 2 && s.untestedIds.join() === "db", JSON.stringify(s));
	s = markTested(ws, "s1", "evidence-index #13（刷新）");
	expect("markTested idempotent refresh", s.tested === 2 && ros(fs, ws).tested.find((t) => t.id === "s1").evidence.includes("#13"));
	setScope(ws, "web-api: API 网关");
	expect("re-scope drops out-of-scope tested rows", ros(fs, ws).tested.length === 1 && ros(fs, ws).tested[0].id === "web-api");
	// 对账：scope 未登记 → null（零影响）；scope 重建完整场景
	setScope(ws, "10.0.0.5 Web 前台\nweb-api: API 网关\ndb: 数据库面");
	markTested(ws, "s1 web-api", "evidence-index #12");
	const matrix = path.join(ws, "coverage-matrix.md");
	fs.writeFileSync(matrix, "| 资产 | 终态 |\n|---|---|\n| 10.0.0.5 | RCE |\n| api | 未测 |\n\n覆盖：2/3（db 未测列入未覆盖清单）\n");
	let c = coverageCheck(fs, ws, matrix);
	expect("coverageCheck passes honest partial", c.ok === true && c.detail.includes("2/3"), JSON.stringify(c));
	fs.writeFileSync(matrix, "| 资产 | 终态 |\n|---|---|\n| a | b |\n\n覆盖：3/3\n");
	c = coverageCheck(fs, ws, matrix);
	expect("coverageCheck fails inflated declaration", c.ok === false && c.detail.includes("2 / 共 3"), JSON.stringify(c));
	fs.writeFileSync(matrix, "| 资产 | 终态 |\n|---|---|\n| a | b |\n（无覆盖声明）\n");
	c = coverageCheck(fs, ws, matrix);
	expect("coverageCheck fails missing declaration", c.ok === false && c.detail.includes("须声明"), JSON.stringify(c));
	fs.writeFileSync(matrix, "coverage: 2/3\n");
	c = coverageCheck(fs, ws, matrix);
	expect("coverageCheck accepts english form", c.ok === true);
	c = coverageCheck(fs, ws, path.join(ws, "ghost.md"));
	expect("coverageCheck fails unreadable report", c.ok === false && c.detail.includes("不可读"));
	const bareWs = path.join(tmp, "bare2");
	fs.mkdirSync(bareWs, { recursive: true });
	expect("coverageCheck null without scope", coverageCheck(fs, bareWs, matrix) === null);
	// runGate 集成：报告门（pentest/P3 固定文件 coverage-matrix.md）追加对账检查
	//   构造一个 P3 其余检查全过的最小工作区代价高；此处验证对账行出现在 checks 且能翻 fail
	const gateWs = fs.mkdtempSync(path.join(os.tmpdir(), "p3-"));
	for (const name of fs.readdirSync(F)) {
		if (fs.statSync(path.join(F, name)).isFile()) fs.copyFileSync(path.join(F, name), path.join(gateWs, name));
	}
	setGoal(gateWs, "目标", "g1 准则");
	setScope(gateWs, "10.0.0.5 Web 前台\nweb-api: API 网关\ndb: 数据库面");
	markTested(gateWs, "s1", "evidence-index #1");
	const v3 = runGate(fs, { mode: "pentest", stage: "P3", workspace: gateWs });
	const covRow = v3.checks.find((r) => r.id === "coverage:report");
	expect("P3 gate carries coverage check row", covRow !== undefined && covRow.ok === false && covRow.detail.includes("已测 1") && covRow.detail.includes("须声明"), JSON.stringify(covRow));
	// 非报告门不挂对账
	const v1gate = runGate(fs, { mode: "pentest", stage: "P1", workspace: gateWs });
	expect("non-report gate carries no coverage row", v1gate.checks.every((r) => r.id !== "coverage:report"));
	fs.rmSync(tmp, { recursive: true, force: true });
	fs.rmSync(gateWs, { recursive: true, force: true });
}


// ── 意图台账（v1.2.0）：锚点校验 / 登记 / 收口 / 跨库解析器降级 ─────────────
{
	const tmp = fs.mkdtempSync(path.join(path.dirname(F), "intent-"));
	const ws = tmp;
	setGoal(ws, "目标", "g1 准则");
	setScope(ws, "10.0.0.5 Web 前台\ndb: 数据库面");
	// 锚校验（纯函数）
	expect("boot 豁免通过", validateAnchor(ros(fs, ws), { kind: "boot" }) === "");
	expect("criterion 锚命中", validateAnchor(ros(fs, ws), { kind: "criterion", ref: "g1" }) === "");
	expect("criterion 锚不存在拒", validateAnchor(ros(fs, ws), { kind: "criterion", ref: "g9" }).includes("不存在"));
	expect("scope 锚命中", validateAnchor(ros(fs, ws), { kind: "scope", ref: "db" }) === "");
	expect("非 boot 锚缺 ref 拒", validateAnchor(ros(fs, ws), { kind: "scope" }).includes("必填"));
	expect("anchor_kind 非法拒", validateAnchor(ros(fs, ws), { kind: "magic", ref: "x" }).includes("非法"));
	// finding 锚：解析器注入命中/未命中；无解析器走格式降级
	const resolvers = { findingExists: (sid, id) => id === "pentest-3" };
	expect("finding 锚解析器命中", validateAnchor(null, { kind: "finding", ref: "pentest-3" }, resolvers, "s1", "pentest") === "");
	expect("finding 锚解析器未命中拒", validateAnchor(null, { kind: "finding", ref: "pentest-9" }, resolvers, "s1", "pentest").includes("不存在"));
	expect("finding 锚格式降级通过", validateAnchor(null, { kind: "finding", ref: "audit-12" }) === "");
	expect("finding 锚格式降级拒坏格式", validateAnchor(null, { kind: "finding", ref: "不是id" }).includes("格式"));
	// chain 锚：解析器注入
	const chainResolvers = { chainExists: (sid, mode, id) => id === "n1" };
	expect("chain 锚解析器命中", validateAnchor(null, { kind: "chain", ref: "n1" }, chainResolvers, "s1", "attack-defense") === "");
	expect("chain 锚解析器未命中拒", validateAnchor(null, { kind: "chain", ref: "n9" }, chainResolvers, "s1", "attack-defense").includes("链路节点不存在"));
	// 登记：正常/重复收口编号
	let s = registerIntent(ws, { summary: "追注入点到凭据", anchorKind: "finding", anchorRef: "pentest-3" }, resolvers);
	expect("registerIntent 登记并计数", s.total === 1 && s.open === 1);
	s = registerIntent(ws, { summary: "开局资产盘点", anchorKind: "boot" });
	expect("第二条 boot 登记", s.total === 2 && s.open === 2);
	const st = ros(fs, ws);
	expect("intents 落盘带锚", st.intents[0].anchor.kind === "finding" && st.intents[0].id === "i1");
	let threw = false;
	try { registerIntent(ws, { summary: "坏锚", anchorKind: "criterion", anchorRef: "g9" }); } catch { threw = true; }
	expect("registerIntent 坏锚拒绝", threw);
	threw = false;
	try { registerIntent(ws, { summary: "", anchorKind: "boot" }); } catch { threw = true; }
	expect("registerIntent 空 summary 拒", threw);
	threw = false;
	try { registerIntent(path.join(tmp, "bare-ws"), { summary: "x", anchorKind: "boot" }); } catch { threw = true; }
	expect("registerIntent 无契约拒", threw);
	// 收口：intent_done / blocked 须 note / 未知 id 拒 / 摘要联动
	let p = updateProgress(ws, { intent_done: "i1" });
	expect("intent_done 收口", p.intents.total === 2 && p.intents.open === 1 && p.intents.openIds.join() === "i2");
	threw = false;
	try { updateProgress(ws, { intent_blocked: "i2" }); } catch { threw = true; }
	expect("blocked 无 note 拒", threw);
	p = updateProgress(ws, { intent_blocked: "i2", note: "WAF 全拦+无旁路（证据 ev-7）" });
	expect("blocked 带 note 收口", p.intents.open === 0);
	threw = false;
	try { updateProgress(ws, { intent_done: "i9" }); } catch { threw = true; }
	expect("未知意图 id 拒", threw);
	expect("intentSummary 全收口", intentSummary(ros(fs, ws)).open === 0);
	fs.rmSync(tmp, { recursive: true, force: true });
}


// ── 派生器模式分支（v1.4.0）：每模式正例+误伤例 ────────────────────────────
{
	expect("audit 提取文件与路由", JSON.stringify(deriveScopeDraft(["审计 src/app/router.js 与 /api/user 路由"], "code-audit")) === JSON.stringify(["/api/user", "src/app/router.js"]));
	expect("audit 误伤：版本号不提取", deriveScopeDraft(["Spring Boot 3.2.1 与 Node v22.19.0"], "code-audit").length === 0);
	expect("binary 提取哈希与样本名", JSON.stringify(deriveScopeDraft(["样本 d41d8cd98f00b204e9800998ecf8427e 与 backdoor.exe"], "binary-analysis")) === JSON.stringify(["backdoor.exe", "d41d8cd98f00b204e9800998ecf8427e"]));
	expect("binary 误伤：短十六进制串不提取", deriveScopeDraft(["颜色 #ff0000 与 id abc123"], "binary-analysis").length === 0);
	expect("cloud 提取账号/区域/ARN", (() => { const d = deriveScopeDraft(["账号 123456789012 us-east-1", "arn:aws:iam::111122223333:role/svc"], "cloud-security"); return d.includes("account:123456789012") && d.includes("us-east-1") && d.some((x) => x.startsWith("arn:")); })());
	expect("cloud 误伤：普通长数字不单独提取", !deriveScopeDraft(["订单号 12345678901234567 无账号词"], "cloud-security").some((x) => x.startsWith("account:")));
	expect("ad 提取 CIDR 且去裸 IP", JSON.stringify(deriveScopeDraft(["网段 192.168.10.0/24 与 10.0.0.5"], "attack-defense")) === JSON.stringify(["10.0.0.5", "192.168.10.0/24"]));
	expect("av/ctf/redteam 登记制不派生", deriveScopeDraft(["载荷 x 引擎 360", "题 web1", "路由任务"], "av-evasion").length === 0 && deriveScopeDraft(["题 web1"], "ctf-solver").length === 0 && deriveScopeDraft(["任务"], "redteam").length === 0);
	expect("无模式走统一提取器", JSON.stringify(deriveScopeDraft(["对 https://a.example.com 与 1.2.3.4"])) === JSON.stringify(["1.2.3.4", "a.example.com"]));
}

// ── 模式化拆分（v1.4.0）：DECOMPOSITION 映射 + 三工具 render 注入 ──────────
{
	// 映射完整性
	expect("DECOMPOSITION 九模式齐全", Object.keys(DECOMPOSITION).length === 9 && ["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver", "redteam"].every((m) => DECOMPOSITION[m]?.theory && DECOMPOSITION[m]?.criteriaGuide));
	expect("每模式五字段完整", Object.values(DECOMPOSITION).every((d) => d.theory && d.criteriaGuide && d.scopeSemantics && d.constraintHints && d.example));
	// 装配层：operation_goal render 按模式注入理论（fake ctx 捕获工具定义）
	const registered = [];
	const fakeCtx = { tools: { register: (tool) => registered.push(tool) }, agentPresets: { composedPreset: (c) => c?.preset } };
	const mod = await import("../lib/index.js");
	mod.apply(fakeCtx, {});
	const goal = registered.find((x) => x?.name === "operation_goal");
	const scope = registered.find((x) => x?.name === "operation_scope");
	const cons = registered.find((x) => x?.name === "operation_constraints");
	const tmp = fs.mkdtempSync(path.join(path.dirname(F), "dec-"));
	const g1 = await goal.execute({ workspace: tmp, goal: "测 https://a.example.com", criteria: "g1 x" }, { agent: { ctx: { preset: "pentest" }, session: { id: "s1", header: {} } } });
	const goalText = goal.output.render(null, g1)[0].text;
	expect("goal render 含 pentest 理论", goalText.includes("pentest 拆分理论") && goalText.includes("作战流程×资产×漏洞类矩阵") && goalText.includes("准则按"));
	const g2 = await goal.execute({ workspace: tmp, goal: "审计 x 服务", criteria: "g1 x" }, { agent: { ctx: { preset: "code-audit" }, session: { id: "s1", header: {} } } });
	expect("goal render 含 audit 理论", goal.output.render(null, g2)[0].text.includes("模块×sink"));
	const g3 = await goal.execute({ workspace: tmp, goal: "x", criteria: "g1 x" }, { agent: { ctx: { preset: "plain" }, session: { id: "s1", header: {} } } });
	expect("未知模式不带理论段", !goal.output.render(null, g3)[0].text.includes("拆分理论"));
	const s1 = await scope.execute({ workspace: tmp, items: "a\nb" }, { agent: { ctx: { preset: "cloud-security" }, session: { id: "s1", header: {} } } });
	expect("scope render 含分母语义", scope.output.render(null, s1)[0].text.includes("cloud-security 分母语义") && scope.output.render(null, s1)[0].text.includes("账号/区域/服务面"));
	const c1 = await cons.execute({ workspace: tmp, items: "deny: x" }, { agent: { ctx: { preset: "ctf-solver" }, session: { id: "s1", header: {} } } });
	expect("constraints render 含约束面提示", cons.output.render(null, c1)[0].text.includes("ctf-solver 约束面提示") && cons.output.render(null, c1)[0].text.includes("不猜不撞"));
	fs.rmSync(tmp, { recursive: true, force: true });
}

// ── 约束层 + scope 保守派生（v1.3.0）─────────────────────────────────────
{
	const tmp = fs.mkdtempSync(path.join(path.dirname(F), "cons-"));
	const ws = tmp;
	setGoal(ws, "对 demo 站授权渗透", "g1 准则");
	// 约束登记：格式/匹配词/非法行/重登记替换
	let s = setConstraints(ws, "deny: 不碰支付接口 :: pay,payment,refund\nallow: 仅测 x.example.com 子域\ndeny: 禁止爆破（提示层）");
	expect("约束登记计数", s.total === 3 && s.deny === 2 && s.allow === 1 && s.denyGuarded === 1, JSON.stringify(s));
	const st = ros(fs, ws);
	expect("约束落盘带匹配词", st.constraints[0].id === "c1" && st.constraints[0].keywords.join() === "pay,payment,refund" && st.constraints[2].keywords.length === 0);
	expect("摘要行渲染", constraintSummary(st).lines[0].includes("禁：不碰支付接口") && constraintSummary(st).lines[0].includes("pay"));
	let threw = false;
	try { setConstraints(ws, "随便一行"); } catch { threw = true; }
	expect("非法行拒绝（须 deny:/allow: 开头）", threw);
	threw = false;
	try { setConstraints(path.join(tmp, "bare"), "deny: x"); } catch { threw = true; }
	expect("无契约拒绝", threw);
	s = setConstraints(ws, "deny: 新约束 :: newkw");
	expect("重登记整表替换", s.total === 1 && ros(fs, ws).constraints[0].text === "新约束");
	// scope 保守派生：URL/裸域/IP；不放大到根域；排除版本号
	const draft = deriveScopeDraft(["对 https://app.demo.example.com/login 与 10.0.0.5 授权测试", "覆盖 api.example.com 全部路由（v1.2.3 不算）"]);
	expect("URL 主机提取", draft.includes("app.demo.example.com"));
	expect("IPv4 提取", draft.includes("10.0.0.5"));
	expect("裸域名全名提取（不缩根域）", draft.includes("api.example.com") && !draft.includes("example.com"));
	expect("版本号不提取", !draft.includes("1.2.3"));
	expect("空输入空草稿", deriveScopeDraft("").length === 0);
	expect("无点串不提取", deriveScopeDraft("看看 abc 和 def").length === 0);
	// operation_goal 集成：返回 scopeDraft；已有 scope 不再派生
	const fresh = fs.mkdtempSync(path.join(path.dirname(F), "draft-"));
	const g1 = setGoal(fresh, "测 https://a.example.com", "g1 x");
	const parsed = ros(fs, fresh);
	fs.rmSync(fresh, { recursive: true, force: true });
	fs.rmSync(tmp, { recursive: true, force: true });
}

process.exit(failed ? 1 : 0);
