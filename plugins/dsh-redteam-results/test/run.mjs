// dsh-redteam-results 离线单测：SQLite 数据层（:memory:）+ 通道纯逻辑
// （登记/更新/删除/分页筛选/统计/计数/验证文案/信任栅栏/端点分发）。
import assert from "node:assert/strict";
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

console.log(`\nall ${passed} tests passed`);

ok("CSRF 头校验：匹配放行/缺失或错值拒", () => {
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "T" } }, "T"), true);
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "X" } }, "T"), false);
	assert.equal(checkCsrf({}, "T"), false);
});
