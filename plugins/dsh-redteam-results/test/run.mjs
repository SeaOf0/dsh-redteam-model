// dsh-redteam-results 离线单测：SQLite 数据层（:memory:）+ 通道纯逻辑
// （登记/更新/删除/分页筛选/统计/计数/验证文案/信任栅栏/端点分发）。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openStore as atlasOpen, addChainNode as atlasAddNode } from "@dsh-external/dsh-attack-atlas/store";
import { openStore, registerFinding, updateFinding, removeFinding, getFinding, listFindings, listFindingsAll, computeStats, computeStatsAll, modeCounts, modeCountsAll, groupByTarget, groupByTargetAll, setMeta, getMeta, ledgerOverviewAll } from "../lib/store.js";
import { verifyMessage, isTrustedRequest, dispatch, checkCsrf } from "../lib/index.js";

let passed = 0;
const ok = (name, fn) => { fn(); passed++; console.log(`ok   ${name}`); };
const SID = "session-test-1";

ok("register 自增序号且默认值齐备（pending/medium/unknown），行落 SQLite", () => {
	const st = openStore(":memory:");
	const r1 = registerFinding(st, SID, "pentest", { title: "SQL注入", severity: "critical", target: "http://a/?id=1", summary: "布尔盲注" });
	const r2 = registerFinding(st, SID, "pentest", { title: "XSS", target: "http://a/q", summary: "反射" });
	assert.equal(r1.seq, 1);
	assert.equal(r2.id, "pentest-2");
	assert.equal(r2.status, "pending");
	assert.equal(r2.severity, "medium");
	assert.equal(r2.evidenceLevel, "unknown");
	assert.deepEqual(getFinding(st, SID, "pentest-1").title, "SQL注入");
});

ok("状态语义：code-reviewed 可用、不记 verifiedAt；fixed 需先 verified", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "code-audit", { title: "fastjson 反序列化", auditMode: "static" });
	const u = updateFinding(st, SID, "code-audit", "code-audit-1", { status: "code-reviewed" });
	assert.equal(u.status, "code-reviewed");
	assert.ok(!u.verifiedAt, "code-reviewed 不记 verifiedAt");
	let threw = false;
	try { updateFinding(st, SID, "code-audit", "code-audit-1", { status: "fixed" }); } catch { threw = true; }
	assert.ok(threw, "未 verified 直接 fixed 应抛错");
	updateFinding(st, SID, "code-audit", "code-audit-1", { status: "verified", verifyNote: "本地复现 EXP 生效" });
	const f2 = updateFinding(st, SID, "code-audit", "code-audit-1", { status: "fixed", retestNote: "修复后复测不成功" });
	assert.equal(f2.status, "fixed");
	st.close();
});

ok("register 越权值回落（severity/status/evidenceLevel 白名单）+ 长文本截断", () => {
	const st = openStore(":memory:");
	const long = "x".repeat(500);
	const r = registerFinding(st, SID, "pentest", { title: `  ${long}  `, severity: "超高", status: "hacked", evidenceLevel: "maybe" });
	assert.equal(r.severity, "medium");
	assert.equal(r.status, "pending");
	assert.equal(r.title.length, 200);
});

ok("evidenceLevel 四档：impact 最高档可登记入统计，回落语义不变", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "数据实际拖取", evidenceLevel: "impact" });
	registerFinding(st, SID, "pentest", { title: "三件套齐", evidenceLevel: "confirmed" });
	registerFinding(st, SID, "pentest", { title: "仅工具输出", evidenceLevel: "maybe" });
	const stats = computeStats(st, SID, "pentest");
	assert.equal(stats.byEvidence.impact, 1);
	assert.equal(stats.byEvidence.confirmed, 1);
	assert.equal(stats.byEvidence.unknown, 1, "越权值照旧回落 unknown");
	assert.ok(!("maybe" in stats.byEvidence));
});

ok("update 状态翻转落 verifiedAt，字段白名单修订，模式/会话隔离", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "x" });
	registerFinding(st, "session-other", "pentest", { title: "y" });
	const u = updateFinding(st, SID, "pentest", "pentest-1", { status: "verified", verifyNote: "差分翻转+marker 回显", severity: "high" });
	assert.equal(u.status, "verified");
	assert.ok(u.verifiedAt.length > 0);
	assert.equal(u.severity, "high");
	assert.equal(updateFinding(st, SID, "code-audit", "pentest-1", {}), undefined, "模式隔离");
	updateFinding(st, "session-other", "pentest", "pentest-1", { severity: "low" });
	assert.equal(updateFinding(st, "session-other", "pentest", "pentest-2", {}), undefined, "会话隔离（pentest-2 不存在于 session-other）");
	assert.notEqual(getFinding(st, SID, "pentest-1").severity, "low", "他会话更新不影响本会话行");
});

ok("remove 删行（库中不再存在），统计同步", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "a" });
	registerFinding(st, SID, "redteam", { title: "b" });
	removeFinding(st, SID, "pentest-1");
	assert.equal(getFinding(st, SID, "pentest-1"), undefined);
	assert.equal(computeStats(st, SID, "pentest").total, 0);
	assert.equal(computeStats(st, SID, "redteam").total, 1);
});

ok("list 倒序 + 等级/状态/关键词筛选 + 分页钳制", () => {
	const st = openStore(":memory:");
	for (let i = 1; i <= 14; i++) registerFinding(st, SID, "pentest", { title: `漏洞${i}`, severity: i % 2 ? "high" : "low", target: `http://t/${i}` });
	const p1 = listFindings(st, SID, "pentest", {});
	assert.equal(p1.total, 14);
	assert.equal(p1.pages, 2);
	assert.equal(p1.rows.length, 10);
	assert.equal(p1.rows[0].seq, 14, "最新在前");
	assert.equal(listFindings(st, SID, "pentest", { severity: "high" }).total, 7);
	assert.equal(listFindings(st, SID, "pentest", { q: "t/3" }).total, 1, "t/3 不是 t/13 的子串");
	assert.equal(listFindings(st, SID, "pentest", { page: 99 }).page, 2);
});

ok("stats 四档/状态/类型分布与最近时间", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "a", severity: "critical", type: "SQLi", status: "verified" });
	registerFinding(st, SID, "pentest", { title: "b", severity: "critical", type: "SQLi" });
	registerFinding(st, SID, "pentest", { title: "c", severity: "low", type: "XSS" });
	const s = computeStats(st, SID, "pentest");
	assert.equal(s.total, 3);
	assert.equal(s.bySeverity.critical, 2);
	assert.equal(s.byStatus.verified, 1);
	assert.equal(s.byType[0].type, "SQLi");
	assert.equal(s.byType[0].count, 2);
});

ok("modeCounts 七模式计数（会话内隔离）", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "a" });
	registerFinding(st, SID, "redteam", { title: "b" });
	registerFinding(st, SID, "redteam", { title: "c" });
	const c = modeCounts(st, SID);
	assert.equal(c.pentest, 1);
	assert.equal(c.redteam, 2);
	assert.equal(c["av-evasion"], 0);
	assert.equal(c["incident-response"], 0);
});

ok("verifyMessage 携带序号/等级/目标/复现材料与回写指引", () => {
	const st = openStore(":memory:");
	const r = registerFinding(st, SID, "pentest", { title: "SQL注入", severity: "critical", target: "http://a/?id=1", poc: "id=1' and 1=1--" });
	const msg = verifyMessage(r);
	assert.ok(msg.includes("#1") && msg.includes("SQL注入") && msg.includes("critical"));
	assert.ok(msg.includes("id=1' and 1=1--"));
	assert.ok(msg.includes("redteam_finding_update"));
});

ok("信任栅栏：回环 Host 放行、跨站 Origin 拒绝、伪造 Host 拒绝", () => {
	const mk = (headers) => ({ headers });
	assert.equal(isTrustedRequest(mk({ host: "127.0.0.1:3080" }), []), true);
	assert.equal(isTrustedRequest(mk({ host: "localhost:3080" }), []), true);
	assert.equal(isTrustedRequest(mk({ host: "127.0.0.1:3080", origin: "http://evil.com" }), []), false, "跨站 Origin");
	assert.equal(isTrustedRequest(mk({ host: "evil.com:3080" }), []), false, "非回环 Host");
	assert.equal(isTrustedRequest(mk({ host: "127.0.0.1:3080", origin: "http://127.0.0.1:3080" }), []), true, "同源 Origin");
	assert.equal(isTrustedRequest(mk({ host: "127.0.0.1:3080", origin: "http://127.0.0.1:9999" }), []), false, "本机他端口 Origin");
});

ok("dispatch 端点分发：list/delete 正常、未知端点抛错、缺 sessionId 拒绝", async () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "x", severity: "high" });
	const ctxNone = {}; // 无 agents 的 ctx——verify 端点应可判定 finding 不存在
	const listed = await dispatch(ctxNone, st, "findings.list", { sessionId: SID, mode: "pentest" });
	assert.equal(listed.list.total, 1);
	assert.equal(listed.stats.bySeverity.high, 1);
	const del = await dispatch(ctxNone, st, "finding.delete", { sessionId: SID, id: "pentest-1" });
	assert.equal(del.ok, true);
	const badId = await dispatch(ctxNone, st, "finding.verify", { sessionId: SID, id: "pentest-99" });
	assert.equal(badId.ok, false);
	await assert.rejects(() => dispatch(ctxNone, st, "bogus.endpoint", {}), /unknown endpoint/);
	await assert.rejects(() => dispatch(ctxNone, st, "findings.list", {}), /sessionId required/);
});


ok("模式隔离铁律：渗透登记不落代审（用户担忧的反向保证）", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "渗透A", severity: "critical" });
	assert.equal(listFindings(st, SID, "code-audit", {}).total, 0, "代审页看不到渗透成果");
	assert.equal(modeCounts(st, SID)["code-audit"], 0);
	assert.equal(listFindings(st, SID, "pentest", {}).total, 1);
	assert.equal(computeStats(st, SID, "pentest").bySeverity.critical, 1);
	assert.equal(computeStats(st, SID, "code-audit").total, 0);
});

ok("模式隔离：同 id 跨模式更新/删除被拒（findings 表双键强制）", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "X" });
	assert.equal(updateFinding(st, SID, "code-audit", "pentest-1", { status: "verified" }), undefined, "代审侧改不动渗透行");
	const before = getFinding(st, SID, "pentest-1");
	assert.equal(before.status, "pending", "原行未被跨模式篡改");
	removeFinding(st, SID, "pentest-1"); // 删除走 (session,id) 行键——行本身删除
	assert.equal(getFinding(st, SID, "pentest-1"), undefined);
});

ok("渗透富字段往返：三件套/影响/CVSS/请求包/复测", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, SID, "pentest", {
		title: "SQLi", baseline: "正常 12 行", diffEvidence: "注入后 3 行", markerEcho: "r9t2k1",
		impact: "脱库 users 5 行", cvss: "CVSS:3.1/AV:N (8.6)", requestPkt: "GET /?id=1'", responsePkt: "HTTP/1.1 200"
	});
	updateFinding(st, SID, "pentest", f.id, { status: "verified", verifyNote: "差分翻转+marker 回显" });
	const u = updateFinding(st, SID, "pentest", f.id, { status: "fixed", retestNote: "复测已修复", retestAt: "2026-08-18T00:00:00Z" });
	assert.equal(u.baseline, "正常 12 行");
	assert.equal(u.markerEcho, "r9t2k1");
	assert.ok(u.cvss.startsWith("CVSS:3.1"));
	assert.equal(u.retestNote, "复测已修复");
});

ok("代审富字段往返：双链/代码片段/CWE/patch/来源", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, SID, "code-audit", {
		title: "组合RCE", chain: "A() → B() → C()", chainTracer: "A() → B() → C()（重追一致）",
		chainVerdict: "一致", snippetEntry: "req.getParameter(\"p\")", snippetSink: "new File(p)",
		cwe: "CWE-22", patch: "- old\n+ new", sourceOrigin: "scan-confirmed"
	});
	const got = getFinding(st, SID, f.id);
	assert.equal(got.chainVerdict, "一致");
	assert.equal(got.cwe, "CWE-22");
	assert.equal(got.sourceOrigin, "scan-confirmed");
	assert.ok(got.snippetSink.includes("new File"));
	const s = computeStats(st, SID, "code-audit");
	assert.equal(s.byCwe[0].cwe, "CWE-22");
	assert.equal(s.bySource[0].source, "scan-confirmed");
});

ok("按目标分组与元数据", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "pentest", { title: "a", target: "http://x/" });
	registerFinding(st, SID, "pentest", { title: "b", target: "http://x/" });
	registerFinding(st, SID, "pentest", { title: "c", target: "http://y/" });
	const groups = groupByTarget(st, SID, "pentest");
	assert.equal(groups.length, 2);
	const xGroup = groups.find(function (g) { return g.target === "http://x/"; });
	assert.equal(xGroup.count, 2);
	setMeta(st, SID, { targetLabel: "DVWA", version: "v2.1", scope: "全站" });
	const m = getMeta(st, SID);
	assert.equal(m.targetLabel, "DVWA");
	assert.equal(m.version, "v2.1");
});


ok("二进制分析字段往返：样本/家族/壳/IOC/检测规则 + 家族壳分布", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, SID, "binary-analysis", {
		title: "样本定性：Agent Tesla 变种", type: "恶意定性", severity: "high",
		target: "invoice.exe", sampleHash: "a1b2c3d4e5f67890",
		family: "AgentTesla", packer: ".NET Confuser",
		chain: "Loader → AES 解密 → 反射加载 payload",
		impact: "键盘记录 + 凭据窃取（浏览器/邮箱）",
		iocs: "C2: x.evil.com\nMutex: {A1B2}", detectionRule: "rule a1 { condition: true }",
		poc: "dnSpy 反编译 → 解密例程复现", evidence: "artifacts/B0-a1b2/provenance.md"
	});
	const got = getFinding(st, SID, f.id);
	assert.equal(got.family, "AgentTesla");
	assert.equal(got.packer, ".NET Confuser");
	assert.ok(got.iocs.includes("Mutex"));
	const s = computeStats(st, SID, "binary-analysis");
	assert.equal(s.byFamily[0].family, "AgentTesla");
	assert.equal(s.byPacker[0].packer, ".NET Confuser");
	// 隔离：binary 成果不落渗透/代审
	assert.equal(computeStats(st, SID, "pentest").total, 0);
	assert.equal(computeStats(st, SID, "code-audit").total, 0);
});

ok("incident-response 登记：timelineAt 读回正确，缺省为空串", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, SID, "incident-response", {
		title: "SSH 爆破成功登录", type: "入口点", severity: "high", target: "10.0.0.7",
		summary: "弱口令爆破进入", timelineAt: "2026-08-18 09:12", poc: "grep auth.log", evidence: "IR-001"
	});
	assert.equal(f.id, "incident-response-1");
	assert.equal(f.timelineAt, "2026-08-18 09:12");
	const got = getFinding(st, SID, f.id);
	assert.equal(got.timelineAt, "2026-08-18 09:12");
	const f2 = registerFinding(st, SID, "incident-response", { title: "恶意样本落盘", type: "持久化" });
	assert.equal(getFinding(st, SID, f2.id).timelineAt, "", "不带 timelineAt 默认空字符串");
});

ok("隔离：incident-response 行不落 pentest 页", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "incident-response", { title: "数据外传", timelineAt: "2026-08-18 10:00" });
	assert.equal(listFindings(st, SID, "pentest", {}).total, 0, "渗透页看不到应急节点");
	assert.equal(modeCounts(st, SID)["pentest"], 0);
	assert.equal(modeCounts(st, SID)["incident-response"], 1);
	assert.equal(listFindings(st, SID, "incident-response", {}).total, 1);
});

ok("cloud-security 登记：攻击路径四要素读回正确，缺省为空串", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, SID, "cloud-security", {
		title: "AK/SK 泄露 → OSS 对象读取", type: "凭证泄露利用", severity: "high", target: "oss://prod-backup",
		entry: "前端 JS 泄露的 AK/SK", identity: "阿里云 RAM 用户 prod-deploy", permission: "AliyunOSSFullAccess",
		resource: "OSS 桶 prod-backup", impact: "列出并下载全部对象", summary: "前端泄露密钥直接读桶", evidence: "C-001"
	});
	assert.equal(f.id, "cloud-security-1");
	assert.equal(f.entry, "前端 JS 泄露的 AK/SK");
	assert.equal(f.identity, "阿里云 RAM 用户 prod-deploy");
	assert.equal(f.permission, "AliyunOSSFullAccess");
	assert.equal(f.resource, "OSS 桶 prod-backup");
	assert.equal(f.impact, "列出并下载全部对象");
	const got = getFinding(st, SID, f.id);
	assert.equal(got.permission, "AliyunOSSFullAccess");
	const f2 = registerFinding(st, SID, "cloud-security", { title: "元数据 SSRF" });
	assert.equal(getFinding(st, SID, f2.id).entry, "", "不带 entry 默认空字符串");
	assert.equal(getFinding(st, SID, f2.id).resource, "");
});

ok("updateFinding 可回写云路径四要素", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, SID, "cloud-security", { title: "路径一", entry: "e0" });
	const up = updateFinding(st, SID, "cloud-security", f.id, { entry: "e1", permission: "AdministratorAccess", status: "verified", verifyNote: "API 响应证据确凿" });
	assert.equal(up.entry, "e1");
	assert.equal(up.permission, "AdministratorAccess");
	assert.equal(up.status, "verified");
	const got = getFinding(st, SID, f.id);
	assert.equal(got.entry, "e1");
	assert.equal(got.permission, "AdministratorAccess");
});

ok("ctf-solver 登记：ledger 语义字段读回，模式隔离", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, SID, "ctf-solver", {
		title: "warmup-web", type: "web", severity: "high", target: "http://ctf.local:8000/",
		summary: "已解出（500 分）", poc: "写 writeup 复盘", evidence: "平台回显 Accepted"
	});
	assert.equal(f.id, "ctf-solver-1");
	assert.equal(f.type, "web");
	assert.equal(f.evidence, "平台回显 Accepted");
	const f2 = registerFinding(st, SID, "ctf-solver", { title: "heap-pwn", type: "pwn", summary: "未解：栈布局未稳定" });
	assert.equal(getFinding(st, SID, f2.id).type, "pwn");
	assert.equal(listFindings(st, SID, "pentest", {}).total, 0, "CTF 题不落渗透页");
	assert.equal(modeCounts(st, SID)["ctf-solver"], 2);
});

ok("隔离：cloud-security 行不落 pentest 页", () => {
	const st = openStore(":memory:");
	registerFinding(st, SID, "cloud-security", { title: "权限提升链", entry: "ak/sk" });
	assert.equal(listFindings(st, SID, "pentest", {}).total, 0);
	assert.equal(modeCounts(st, SID)["cloud-security"], 1);
});

// ── ledgerOverviewAll：跨会话聚合 + created_at 时间范围过滤 ──
ok("ledgerOverviewAll 跨会话聚合（total/sessions/byMode/recent 带 sessionId）", () => {
	const st = openStore(":memory:");
	registerFinding(st, "session-aaa", "pentest", { title: "a", severity: "high", target: "t", summary: "s" });
	registerFinding(st, "session-bbb", "cloud-security", { title: "b", severity: "low", target: "t2", summary: "s" });
	registerFinding(st, "session-aaa", "binary-analysis", { title: "c", severity: "medium", target: "t3", summary: "s" });
	const all = ledgerOverviewAll(st, {});
	assert.equal(all.total, 3);
	assert.equal(all.sessions, 2);
	assert.equal(all.byMode.pentest + all.byMode["cloud-security"] + all.byMode["binary-analysis"], 3);
	assert.ok(all.recent[0].sessionId !== undefined);
	st.close();
});
ok("ledgerOverviewAll 时间范围过滤（from 未来=空 / to 过去=空 / 宽区间=全量）", () => {
	const st = openStore(":memory:");
	registerFinding(st, "session-aaa", "pentest", { title: "a", severity: "high", target: "t", summary: "s" });
	registerFinding(st, "session-bbb", "av-evasion", { title: "b", severity: "low", target: "t2", summary: "s" });
	assert.equal(ledgerOverviewAll(st, { from: "2999-01-01T00:00:00.000Z" }).total, 0);
	assert.equal(ledgerOverviewAll(st, { to: "2000-01-01T00:00:00.000Z" }).total, 0);
	assert.equal(ledgerOverviewAll(st, { from: "2000-01-01T00:00:00.000Z", to: "2999-01-01T00:00:00.000Z" }).total, 2);
	st.close();
});

// ── 跨会话模式页：listFindingsAll / computeStatsAll / modeCountsAll / groupByTargetAll ──
ok("listFindingsAll 跨会话按模式聚合（行带 sessionId，范围过滤生效）", () => {
	const st = openStore(":memory:");
	registerFinding(st, "session-x1", "av-evasion", { title: "a", severity: "high", target: "t", summary: "s" });
	registerFinding(st, "session-x2", "av-evasion", { title: "b", severity: "low", target: "t2", summary: "s" });
	registerFinding(st, "session-x1", "pentest", { title: "c", severity: "low", target: "t3", summary: "s" });
	const all = listFindingsAll(st, "av-evasion", {});
	assert.equal(all.total, 2);
	assert.ok(all.rows.every((r) => typeof r.sessionId === "string" && r.sessionId.startsWith("session-")));
	assert.equal(listFindingsAll(st, "av-evasion", { from: "2999-01-01T00:00:00.000Z" }).total, 0);
	assert.equal(listFindingsAll(st, "av-evasion", { severity: "high" }).total, 1);
	assert.equal(listFindingsAll(st, "pentest", {}).total, 1);
	const stats = computeStatsAll(st, "av-evasion", {});
	assert.equal(stats.total, 2);
	const counts = modeCountsAll(st);
	assert.equal(counts["av-evasion"], 2);
	assert.equal(counts.pentest, 1);
	const groups = groupByTargetAll(st, "av-evasion", {});
	assert.equal(groups.length, 2);
	st.close();
});

// ===== 分模式状态子集（产物型本体词 / 漏洞型五态不变）=====
{
	const st = openStore(":memory:");
	ok("分模式状态：av=在验/过检/被检出（detected 合法、fixed 回落不变）+ severity 可省默认", () => {
		const r = registerFinding(st, "s-av", "av-evasion", { title: "jsp 冰蝎马", target: "exp/1.jsp", summary: "交付物", type: "jsp" });
		assert.equal(r.severity, "medium", "severity 省略走默认（产物型不展示）");
		assert.equal(r.type, "jsp");
		const u1 = updateFinding(st, "s-av", "av-evasion", r.id, { status: "detected" });
		assert.equal(u1.status, "detected", "被检出 合法");
		const u2 = updateFinding(st, "s-av", "av-evasion", r.id, { status: "fixed" });
		assert.equal(u2.status, "detected", "fixed 不在 av 子集——回落保持原状态");
	});
	ok("分模式状态：ctf=未解/卡点/已解（stuck 合法、verified 落 verifiedAt）", () => {
		const r = registerFinding(st, "s-ctf", "ctf-solver", { title: "web1", target: "board#1", summary: "题", type: "hard" });
		assert.equal(updateFinding(st, "s-ctf", "ctf-solver", r.id, { status: "stuck" }).status, "stuck");
		const u2 = updateFinding(st, "s-ctf", "ctf-solver", r.id, { status: "verified" });
		assert.equal(u2.status, "verified");
		assert.ok(u2.verifiedAt, "已解（verified）落 verifiedAt");
	});
	ok("分模式状态：binary=分析中/疑似/已定论；漏洞型 fixed 前置规则不变", () => {
		const r = registerFinding(st, "s-bin", "binary-analysis", { title: "样本A", target: "sha256:ab", summary: "家族分析" });
		assert.equal(updateFinding(st, "s-bin", "binary-analysis", r.id, { status: "suspect" }).status, "suspect");
		assert.equal(updateFinding(st, "s-bin", "binary-analysis", r.id, { status: "verified" }).status, "verified");
		const v = registerFinding(st, "s-v", "code-audit", { title: "X", target: "t", summary: "s" });
		assert.throws(() => updateFinding(st, "s-v", "code-audit", v.id, { status: "fixed" }), /此前已验证/, "漏洞型 fixed 需先 verified 的旧规则保留");
	});
	st.close();
}

ok("CSRF 头校验：匹配放行/缺失或错值拒", () => {
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "T" } }, "T"), true);
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "X" } }, "T"), false);
	assert.equal(checkCsrf({}, "T"), false);
});

// ===== 台账状态机对齐 + 状态词贯穿回归（register/mark/stats/分组/meta）=====
{
	const st = openStore(":memory:");
	ok("redteam 台账状态机：pending→已路由(fixed) update 不再被守卫拦截、登记即已路由合法", () => {
		const r0 = registerFinding(st, "s-rt", "redteam", { title: "任务A", type: "A", target: "范围", summary: "浅做" });
		assert.equal(r0.status, "pending");
		const r1 = registerFinding(st, "s-rt", "redteam", { title: "任务B（登记即已路由）", status: "fixed", poc: "任务书路径" });
		assert.equal(r1.status, "fixed", "台账 fixed=已路由，登记可直接写");
		assert.equal(updateFinding(st, "s-rt", "redteam", r0.id, { status: "fixed" }).status, "fixed", "无 verified 前置");
	});
	ok("register 状态词表按模式取：av detected 登记保留、漏洞型 fixed 登记即拒", () => {
		assert.equal(registerFinding(st, "s-av2", "av-evasion", { title: "载荷X", status: "detected" }).status, "detected");
		assert.throws(() => registerFinding(st, "s-v2", "pentest", { title: "X", status: "fixed" }), /不可在登记时直接写入/);
	});
	ok("stats 状态分布按模式词表：detected 计数不再丢失", () => {
		registerFinding(st, "s-av3", "av-evasion", { title: "a", status: "detected" });
		registerFinding(st, "s-av3", "av-evasion", { title: "b", status: "detected" });
		const s = computeStats(st, "s-av3", "av-evasion");
		assert.equal(s.byStatus.detected, 2);
		assert.equal(Object.values(s.byStatus).reduce((a, b) => a + b, 0), s.total);
	});
	ok("大屏 byStatus 词表取并集：detected 计入", () => {
		const ov = ledgerOverviewAll(st, {});
		assert.ok((ov.byStatus.detected ?? 0) >= 3);
	});
	ok("groupByTargetAll 全量分组——不再被分页钳到 100", () => {
		const st2 = openStore(":memory:");
		for (let i = 0; i < 105; i++) registerFinding(st2, "s-big", "pentest", { title: "f" + i, target: "同一目标", summary: "s" });
		const groups = groupByTargetAll(st2, "pentest", {});
		assert.equal(groups.length, 1);
		assert.equal(groups[0].count, 105);
		st2.close();
	});
	const av = registerFinding(st, "s-m", "av-evasion", { title: "载荷", status: "detected" });
	const pen = registerFinding(st, "s-m", "pentest", { title: "注入" });
	const m1 = await dispatch(null, st, "finding.mark", { sessionId: "s-m", id: av.id, status: "verified" });
	ok("mark 按模式词表：av verified 合法", () => { assert.equal(m1.ok, true); assert.equal(m1.status, "verified"); });
	const m2 = await dispatch(null, st, "finding.mark", { sessionId: "s-m", id: av.id, status: "false-positive" });
	ok("mark 按模式词表：av 无 false-positive 词——拒绝（不再静默回落报成功）", () => { assert.equal(m2.ok, false); assert.match(m2.error, /status 必须/); });
	const m3 = await dispatch(null, st, "finding.mark", { sessionId: "s-m", id: pen.id, status: "false-positive" });
	ok("mark 漏洞型 false-positive 合法", () => { assert.equal(m3.ok, true); assert.equal(m3.status, "false-positive"); });
	const m4 = await dispatch(null, st, "finding.mark", { sessionId: "s-m", id: av.id, status: "detected" });
	ok("mark 产物型本体词（detected）可标——旧白名单根本不含", () => { assert.equal(m4.ok, true); assert.equal(m4.status, "detected"); });
	const res = await dispatch(null, st, "findings.list", { scope: "all", mode: "pentest", sessionId: "s-m" });
	ok("scope:all 返回请求会话 meta（模式页元数据栏不再永远未设置）", () => { assert.notEqual(res.meta, undefined); assert.equal(res.list.total, 1); });
	const resG = await dispatch(null, st, "findings.groups", { scope: "all", mode: "pentest", sessionId: "s-m" });
	ok("scope:all 分组同样返回 meta", () => { assert.notEqual(resG.meta, undefined); assert.equal(resG.groups.length, 1); });
	ok("scope:all 分组返回 stats（分组态统计卡不再全零）", () => { assert.notEqual(resG.stats, undefined); assert.ok(resG.stats.total >= 1); });
	ok("verify 复核消息携带完整请求包与关键响应（包级复核可见）", () => {
		const r = registerFinding(st, "s-pkt", "pentest", { title: "注入", target: "http://a", summary: "s", requestPkt: "POST /api HTTP/1.1\nHost: a", responsePkt: "200 OK uid=0" });
		const msg = verifyMessage(getFinding(st, "s-pkt", r.id));
		assert.ok(msg.includes("POST /api HTTP/1.1") && msg.includes("200 OK uid=0"), "请求包/响应包进复核消息");
	});
	ok("序号计数器：删除末尾行后 id 不复用（报告引用 id 不漂移）", () => {
		registerFinding(st, "s-seq", "pentest", { title: "a", target: "t", summary: "s" });
		registerFinding(st, "s-seq", "pentest", { title: "b", target: "t", summary: "s" });
		registerFinding(st, "s-seq", "pentest", { title: "c", target: "t", summary: "s" });
		removeFinding(st, "s-seq", "pentest-3");
		assert.equal(registerFinding(st, "s-seq", "pentest", { title: "d", target: "t", summary: "s" }).id, "pentest-4");
	});
	st.close();
}

// ===== attack-defense 批：ad 战果状态集 / verify 分支 / 链路互联 =====
{
	const st = openStore(":memory:");
	ok("ad 状态集：code-reviewed 回落 pending、fixed=已交付（登记即拒+须先 verified）", () => {
		const r = registerFinding(st, "s-ad", "attack-defense", { title: "域控成果", type: "域控成果", target: "DC01", summary: "s", status: "code-reviewed" });
		assert.equal(r.status, "pending", "code-reviewed 不在战果词表——回落 pending");
		assert.throws(() => registerFinding(st, "s-ad", "attack-defense", { title: "X", status: "fixed" }), /攻防=已交付/);
		assert.throws(() => updateFinding(st, "s-ad", "attack-defense", r.id, { status: "fixed" }), /已交付/);
		updateFinding(st, "s-ad", "attack-defense", r.id, { status: "verified" });
		assert.equal(updateFinding(st, "s-ad", "attack-defense", r.id, { status: "fixed" }).status, "fixed", "verified→已交付");
	});
	ok("verifyMessage ad 分支：确定性信号菜单+获取路径标签（不再用代审『工人链』）", () => {
		const f = registerFinding(st, "s-ad2", "attack-defense", { title: "密码本", type: "凭据·密码本", target: "10.1.1.5", summary: "s", chain: "L3: XSS窃会话→密码本" });
		const msg = verifyMessage(getFinding(st, "s-ad2", f.id));
		assert.match(msg, /获取路径（L<级>/);
		assert.match(msg, /确定性信号按战果类型择一/);
		assert.doesNotMatch(msg, /工人链/);
	});
	st.close();
}
{
	// 链路互联回填：临时 atlas 库（DSH_ATLAS_DB 注入）+ chainRefIndex 反查
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rtr-chain-"));
	const adb = atlasOpen(path.join(dir, "atlas.db"));
	atlasAddNode(adb, "s-adl", "attack-defense", { id: "dc-01", label: "DC01", kind: "dc", major: true, findingRef: "attack-defense-1" });
	adb.close();
	process.env.DSH_ATLAS_DB = path.join(dir, "atlas.db");
	try {
		const st = openStore(":memory:");
		registerFinding(st, "s-adl", "attack-defense", { title: "域控成果", type: "域控成果", target: "DC01", summary: "s" });
		const res = await dispatch(null, st, "findings.list", { scope: "all", mode: "attack-defense", sessionId: "s-adl" });
		ok("链路互链：scope:all 行带 chainNodes（atlas finding_ref 反查，含 major）", () => {
			assert.ok(res.list.rows[0].chainNodes && res.list.rows[0].chainNodes[0].id === "dc-01" && res.list.rows[0].chainNodes[0].major === true, "互链行回填");
		});
		st.close();
	} finally {
		delete process.env.DSH_ATLAS_DB;
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

// ===== code-audit 批：auditMode 枚举清洗 / verifyMessage 代审分支直测 =====
{
	const st = openStore(":memory:");
	ok("auditMode 枚举清洗：错值清空不回显（Web 通道无 schema 闸）", () => {
		const r = registerFinding(st, "s-am", "code-audit", { title: "SQL注入", target: "Foo.java:88", summary: "s", auditMode: "dynamicc" });
		assert.equal(r.auditMode, "", "错值清空");
		const r2 = registerFinding(st, "s-am", "code-audit", { title: "XXE", target: "Bar.java:9", summary: "s", auditMode: "dynamic" });
		assert.equal(r2.auditMode, "dynamic");
		const u = updateFinding(st, "s-am", "code-audit", r2.id, { auditMode: "hacked" });
		assert.equal(u.auditMode, "", "update 错值同样清空");
	});
	ok("verifyMessage 代审分支：静态只可 code-reviewed、verified 仅动态成功", () => {
		const f = registerFinding(st, "s-vm", "code-audit", { title: "反序列化", target: "Baz.java:3", summary: "s", poc: "指纹:framework=fastjson,title=\"x\"" });
		const msg = verifyMessage(getFinding(st, "s-vm", f.id));
		assert.match(msg, /静态审计：复核通过只能回写 code-reviewed/);
		assert.match(msg, /verified 仅限动态验证成功/);
	});
	ok("verifyMessage binary 分支：三态词表+静态优先纪律+正确标签", () => {		const f = registerFinding(st, "s-vb", "binary-analysis", { title: "脱壳产物", type: "脱壳还原二进制", target: "artifacts/x/", summary: "s", sampleHash: "ab".repeat(32), chain: "UPX→OEP→dump", impact: "窃取浏览器凭据" });
		const msg = verifyMessage(getFinding(st, "s-vb", f.id));
		assert.match(msg, /还原\/产出链/, "chain 标签");
		assert.match(msg, /能力与危害/, "impact 标签");
		assert.match(msg, /suspect=疑似/);
		assert.match(msg, /静态优先/);
	});
	ok("binary 分组键=sampleHash：同样本产物归一组、漏填回落 target", () => {		const h = "cd".repeat(32);
		registerFinding(st, "s-grp", "binary-analysis", { title: "脱壳产物", type: "脱壳还原二进制", target: "artifacts/a/", summary: "s", sampleHash: h });
		registerFinding(st, "s-grp", "binary-analysis", { title: "YARA", type: "YARA 规则", target: "rules/x.yar", summary: "s", sampleHash: h });
		registerFinding(st, "s-grp", "binary-analysis", { title: "无哈希产物", type: "脚本工具", target: "scripts/t.py", summary: "s" });
		const g = groupByTarget(st, "s-grp", "binary-analysis", {});
		assert.equal(g.length, 2, "同哈希两条归一组+无哈希回落 target 一组");
		assert.equal(g.find((x) => x.target === h.slice(0, 16)).count, 2);
		assert.equal(g.find((x) => x.target === "scripts/t.py").count, 1);
		const pent = groupByTarget(st, "s-grp", "pentest", {});
		assert.ok(Array.isArray(pent), "非 binary 模式分组不回归");
	});
	st.close();
}

// ===== cloud-security：状态四态 / 分组键 type / verifyMessage 分支 =====
{
	const st = openStore(":memory:");
	ok("cloud 状态集：code-reviewed 回落 pending（板式四态）、fixed=已修复须先 verified", () => {
		const r = registerFinding(st, "s-cl", "cloud-security", { title: "AK 泄露接管", type: "权限提升", target: "arn:aws:iam::x", summary: "s", status: "code-reviewed" });
		assert.equal(r.status, "pending", "code-reviewed 不在路径词表——回落 pending");
		assert.throws(() => registerFinding(st, "s-cl", "cloud-security", { title: "X", status: "fixed" }), /fixed/);
		assert.throws(() => updateFinding(st, "s-cl", "cloud-security", r.id, { status: "fixed" }), /已修复|verified/);
		updateFinding(st, "s-cl", "cloud-security", r.id, { status: "verified" });
		assert.equal(updateFinding(st, "s-cl", "cloud-security", r.id, { status: "fixed" }).status, "fixed", "verified→已修复");
	});
	ok("cloud 分组键=type 路径类型：同类型路径归一组（分组标签名实相符）", () => {
		registerFinding(st, "s-cg", "cloud-security", { title: "a", type: "对象存储", target: "oss://b1", summary: "s" });
		registerFinding(st, "s-cg", "cloud-security", { title: "b", type: "对象存储", target: "oss://b2", summary: "s" });
		registerFinding(st, "s-cg", "cloud-security", { title: "c", type: "权限提升", target: "arn:x", summary: "s" });
		const g = groupByTarget(st, "s-cg", "cloud-security", {});
		assert.equal(g.length, 2, "按 type 两类");
		assert.equal(g.find((x) => x.target === "对象存储").count, 2);
	});
	ok("verifyMessage cloud 分支：三重证据+四要素复核+路径链标签", () => {
		const f = registerFinding(st, "s-cv", "cloud-security", { title: "路径", type: "权限提升", target: "arn:x", summary: "s", chain: "前端AK→子账号→AdministratorAccess" });
		const msg = verifyMessage(getFinding(st, "s-cv", f.id));
		assert.match(msg, /路径链（入口→身份→权限→资源）/);
		assert.match(msg, /三重证据/);
		assert.match(msg, /四要素闭环核对/);
	});
	st.close();
}

// ── CTF verifyMessage 分支 + 分组键=模块 ──
ok("verifyMessage CTF 分支：flag 语义+stuck 入口，无渗透语境与非法状态", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, "s-ctf", "ctf-solver", { title: "pwn1", type: "pwn", target: "https://ctf.example/pwn1", poc: "exp.py 栈溢出→ROP", chain: "栈溢出→ROP→shell" });
	const msg = verifyMessage(f);
	assert.match(msg, /模块 pwn /);
	assert.match(msg, /解题材料（脚本\/过程）/);
	assert.match(msg, /解题路径（怎么解的）/);
	assert.match(msg, /stuck=卡点/);
	assert.match(msg, /verified=已解（flag 已提交且平台确认得分/);
	assert.ok(!msg.includes("false-positive="), "不再推荐 CTF 非法状态（cleanEnum 静默吞根源）");
	assert.ok(!msg.includes("渗透模式=对照三件套"), "不再落渗透默认分支");
	st.close();
});
ok("ctf 分组键=模块（type）：按模块归并不按题址", () => {
	const st = openStore(":memory:");
	registerFinding(st, "s-cg", "ctf-solver", { title: "a", type: "web", target: "u1", summary: "s" });
	registerFinding(st, "s-cg", "ctf-solver", { title: "b", type: "pwn", target: "u2", summary: "s" });
	registerFinding(st, "s-cg", "ctf-solver", { title: "c", type: "web", target: "u3", summary: "s" });
	const groups = groupByTargetAll(st, "ctf-solver", {});
	assert.equal(groups.length, 2);
	assert.equal(groups.find((g) => g.target === "web").count, 2);
	st.close();
});

// ── IR verifyMessage 分支（防御语义） ──
ok("verifyMessage IR 分支：取证复核纪律+fixed=已处置，不再落渗透默认分支", () => {
	const st = openStore(":memory:");
	const f = registerFinding(st, "s-ir", "incident-response", { title: "主机A 发现 Webshell", type: "持久化", target: "web-01", timelineAt: "2026-08-24 10:00", poc: "webshell-detection 全盘扫描", chain: "上传→访问→命令执行" });
	const msg = verifyMessage(f);
	assert.match(msg, /｜ 主机 web-01 /);
	assert.match(msg, /取证过程 \/ 检测命令/);
	assert.match(msg, /取证过程（怎么证实）/);
	assert.match(msg, /证据链交叉/);
	assert.match(msg, /fixed=已处置/);
	assert.match(msg, /code-reviewed=复核通过/);
	assert.ok(!msg.includes("渗透模式=对照三件套"), "不再落渗透默认分支");
	assert.ok(!msg.includes("复测不成功才可标记"), "fixed 不再教渗透修复语义");
	st.close();
});

console.log(`\nall ${passed} tests passed`);
