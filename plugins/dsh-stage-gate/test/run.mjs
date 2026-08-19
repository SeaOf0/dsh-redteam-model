// Standalone tests for dsh-stage-gate pure validators (no DSH runtime needed).
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import { runGate, listGates, tableRows, setGoal, updateProgress, syncOperationState, readOperationState as ros } from "../lib/index.js";

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

// pentest P3 pass (3 rows, 3 cells)
v = runGate(fs, { mode: "pentest", stage: "P3", workspace: F });
expect("pentest/P3 pass", v.pass === true, JSON.stringify(v.missing));

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

process.exit(failed ? 1 : 0);
