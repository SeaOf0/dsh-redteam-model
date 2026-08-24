import assert from "node:assert/strict";
// Offline unit tests for dsh-route-boost. No host, no session — pure data and
// rendering, plus contract checks against dsh-stage-gate's real GATES and the
// presets' top-level refs README indexes.
import { MODES, inferPhase, inferRefs, inferEvidence, buildEnvelope, buildEnvelopeDetailed, purposeLine, wrapEnvelope, isEnvelopeText, envelopeRev, appendAccounting, isHumanUser, matchKeyword, escapePromptBraces, hasNegation, buildAuditRow, Config } from "../lib/index.js";
import { scanSkillDeps, checkTool } from "../lib/skilltools.mjs";
import { detectScope } from "../lib/scope.mjs";
import { TAXONOMIES } from "../../dsh-attack-atlas/lib/taxonomy.js";
import os from "node:os";
import { FALLBACK_GATES } from "../lib/routes.mjs";
import { GATES } from "../../dsh-stage-gate/lib/index.js";
import fs from "node:fs";
import path from "node:path";
import url from "node:url";

const PRESETS_DIR = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "../../../modes");

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

// 1. every gate id referenced by route tables exists in stage-gate GATES
{
	let missing = [];
	for (const [presetId, mode] of Object.entries(MODES)) {
		for (const phase of mode.phases) {
			for (const gateId of phase.gates) {
				if (!(gateId in (GATES[presetId] ?? {}))) missing.push(`${presetId}/${phase.id}:${gateId}`);
			}
		}
	}
	ok("all referenced gate ids exist in stage-gate GATES", missing.length === 0);
	if (missing.length) console.log("  missing:", missing.join(", "));
}

// 2. five modes covered, each with phases/default/boundary/refs
{
	ok("five security modes in route tables",
		["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion"].every((id) => MODES[id] && MODES[id].phases.length >= 4 && MODES[id].boundary.length > 0 && MODES[id].refs.length >= 4));
	ok("defaultPhase names an existing phase",
		Object.values(MODES).every((m) => m.phases.some((p) => p.id === m.defaultPhase)));
}

// 3. phase inference: keyword hit, case-insensitive, sticky fallback, default
{
	const m = MODES.pentest;
	ok("keyword hit routes to verify", inferPhase(m, "验证这个 SQL 注入").id === "verify");
	ok("case-insensitive match", inferPhase(m, "run RECON on target.com").id === "recon");
	ok("no hit falls back to default", inferPhase(m, "随便聊聊").id === m.defaultPhase);
	ok("empty text falls back to default", inferPhase(m, "").id === m.defaultPhase);
	ok("earlier phase wins on multi-hit (ordered table)", inferPhase(m, "先侦察再验证漏洞").id === "recon");
	ok("ad persistence phase routes", inferPhase(MODES["attack-defense"], "做持久化驻留").id === "persistence");
	ok("av pair phase routes", inferPhase(MODES["av-evasion"], "写 yara 检测规则配对").id === "pair");
	ok("sticky phase survives a bare continuation", inferPhase(m, "继续", "verify").id === "verify");
	ok("sticky survives unrelated text", inferPhase(m, "嗯然后呢", "mobile").id === "mobile");
	ok("unknown sticky id falls back to default", inferPhase(m, "继续", "no-such-phase").id === m.defaultPhase);
	ok("explicit keyword overrides sticky", inferPhase(m, "开始侦察", "verify").id === "recon");
}

// 3b. ASCII word-boundary matching (substring misfire regression, 2026-08-17)
{
	ok("matchKeyword: ascii token matches standalone", matchKeyword("用 ad 域渗透", "ad") && matchKeyword("check the ad domain", "ad"));
	ok("matchKeyword: substring does NOT match (read/admin)", !matchKeyword("read the admin panel", "ad") && !matchKeyword("audit the load", "ad"));
	ok("matchKeyword: cjk substring still matches", matchKeyword("横向域控", "域控"));
	const m = MODES.pentest, bin = MODES["binary-analysis"], ad = MODES["attack-defense"];
	ok("pentest: example.com does not misroute to verify", inferPhase(m, "看看 example.com 这个资产").id === "recon");
	ok("pentest: standalone exp still routes to verify", inferPhase(m, "给个 exp 验证").id === "verify");
	ok("binary: idea does not misroute to analyze", inferPhase(bin, "我有个 idea，先登记样本").id === "triage");
	ok("binary: ida pro routes to analyze", inferPhase(bin, "用 ida pro 看反汇编").id === "analyze");
	ok("ad: admin/read do not misroute to lateral", inferPhase(ad, "admin panel 弱口令先突破").id !== "lateral");
	ok("ad: standalone AD routes to lateral", inferPhase(ad, "打 AD 拿域控").id === "lateral");
}

// 3c. code-audit diff phase (增量审计分支)
{
	ok("diff phase routes on patch keywords", inferPhase(MODES["code-audit"], "审这个 patch 的增量变更").id === "diff");
	ok("diff phase routes on code review", inferPhase(MODES["code-audit"], "code review 这个 commit").id === "diff");
	ok("plain audit still routes to audit", inferPhase(MODES["code-audit"], "深审这个模块的调用链").id === "audit");
}

// 4. refs inference
{
	const hits = inferRefs(MODES.pentest, "测 api 接口和 jwt");
	ok("refs keyword hits", hits.includes("api"));
	ok("refs unique dirs", new Set(hits).size === hits.length);
	ok("refs empty on no hit", inferRefs(MODES.pentest, "你好").length === 0);
}

// 5. envelope rendering: structure + gate titles from real GATES + cap
{
	const m = MODES.pentest;
	const phase = inferPhase(m, "验证 sqli");
	const env = buildEnvelope({ presetId: "pentest", mode: m, phase, refsHits: ["web"], gates: GATES });
	ok("envelope has mode/phase/gates/review/boundary lines", env.includes("mode=pentest") && env.includes("gates:") && env.includes("review:") && env.includes("boundary:"));
	ok("gate titles pulled from real GATES", env.includes("资产与环境基线"));
	ok("refs pointer renders top-level README + labels", env.includes("读 refs/README.md 快速路由") && env.includes("web"));
	ok("inferred disclaimer present", env.includes("推断"));
	ok("phase channel line present when defined", env.includes("channel:"));
	ok("channel line omitted for phases without channel", !buildEnvelope({ presetId: "pentest", mode: m, phase: m.phases.find((p) => p.id === "report"), refsHits: [], gates: GATES }).includes("channel:"));
	const capped = buildEnvelope({ presetId: "pentest", mode: m, phase, refsHits: ["web"], gates: GATES, maxChars: 50 });
	ok("maxChars cap applies", capped.length <= 50 && capped.endsWith("…"));
	ok("includeRefs=false drops refs line", !buildEnvelope({ presetId: "pentest", mode: m, phase, refsHits: ["web"], gates: GATES, includeRefs: false }).includes("refs/"));
}

// 6. evidence inference (confirmed / partial / unknown)
{
	ok("strong tokens → confirmed", inferEvidence("这是 burp 抓的原始请求包") === "confirmed");
	ok("source code → confirmed", inferEvidence("附上相关源码片段") === "confirmed");
	ok("partial tokens → partial", inferEvidence("接口返回了报错") === "partial");
	ok("no tokens → unknown", inferEvidence("帮我看看这个站") === "unknown");
}

// 7. envelope v0.2 lines: evidence + no-hit search nudge
{
	const m = MODES.pentest;
	const phase = inferPhase(m, "测 api 接口和 jwt");
	const env = buildEnvelope({ presetId: "pentest", mode: m, phase, refsHits: inferRefs(m, "测 api 接口和 jwt"), evidence: inferEvidence("测 api 接口和 jwt"), gates: GATES });
	ok("evidence line rendered", env.includes("evidence: partial"));
	const noHit = buildEnvelope({ presetId: "pentest", mode: m, phase: inferPhase(m, "看看这个"), refsHits: [], evidence: "unknown", gates: GATES });
	ok("no-hit nudge rendered", noHit.includes("勿凭记忆自答") && noHit.includes("web_search"));
	ok("hit case has no nudge", !env.includes("勿凭记忆自答"));
}

// 8. determinism: same inputs → identical text (RuntimeContextProjection dedupe relies on it)
{
	const m = MODES["code-audit"];
	const phase = inferPhase(m, "semgrep 扫描命中复核");
	const a = buildEnvelope({ presetId: "code-audit", mode: m, phase, refsHits: inferRefs(m, "semgrep 扫描命中复核"), gates: GATES });
	const b = buildEnvelope({ presetId: "code-audit", mode: m, phase, refsHits: inferRefs(m, "semgrep 扫描命中复核"), gates: GATES });
	ok("identical inputs → identical envelope", a === b);
	ok("different phase → different envelope", a !== buildEnvelope({ presetId: "code-audit", mode: m, phase: inferPhase(m, "报告"), refsHits: [], gates: GATES }));
}

// 9. human-input filter: only source.kind === "user" steers routing
{
	ok("human user message accepted", isHumanUser({ source: { kind: "user" }, content: [] }));
	ok("plugin snapshot rejected", !isHumanUser({ source: { kind: "plugin", form: "snapshot" }, content: [] }));
	ok("skill-catalog message rejected", !isHumanUser({ source: { kind: "skill-catalog" }, content: [] }));
	ok("missing source rejected", !isHumanUser({ content: [] }));
}

// 10. config schema defaults
{
	const c = Config({});
	ok("config defaults (maxChars 1200, includeRefs true)", c.maxChars === 1200 && c.includeRefs === true);
}

// 11. av boundary 新口径 + V1 新门 + refs 标签可查
{
	const av = MODES["av-evasion"];
	ok("av boundary policy (授权目标按任务/登记制)", av.boundary.includes("授权目标按任务") && av.boundary.includes("登记") && !av.boundary.includes("不产第三方"));
	const env = buildEnvelope({ presetId: "av-evasion", mode: av, phase: av.phases[0], refsHits: [], gates: GATES });
	ok("av envelope carries new policy and V1 new title", env.includes("授权目标按任务") && env.includes("实验计划门"));
	ok("V1 gate in real GATES uses new-declaration markers", JSON.stringify(GATES["av-evasion"].V1.checks[1].markers) === JSON.stringify(["测试环境", "产物去向", "持久化预案"]));
	let unindexed = [];
	for (const [id, mode] of Object.entries(MODES)) {
		if (mode.refs.length === 0) continue; // redteam 无 refs 库（知识靠五 playbook，信封走技能指针文案）
		const readme = fs.readFileSync(path.join(PRESETS_DIR, id, "refs", "README.md"), "utf8");
		for (const r of mode.refs) if (!readme.includes(r.dir)) unindexed.push(`${id}:${r.dir}`);
	}
	ok("every refs label is indexed in the preset's top-level refs README", unindexed.length === 0);
	if (unindexed.length) console.log("  unindexed:", unindexed.join(", "));
}

// 13. redteam 主模式：无自建门/无 refs 库的路由语义
{
	const rt = MODES.redteam;
	ok("redteam in route tables with phases/boundary", rt !== undefined && rt.phases.length >= 4 && rt.boundary.length > 0);
	ok("redteam has no own gates (controller consumes, not judges)", rt.phases.every((p) => p.gates.length === 0));
	ok("redteam has no refs library (knowledge via five playbooks)", rt.refs.length === 0);
	ok("redteam default phase is intake", rt.defaultPhase === "intake" && rt.phases.some((p) => p.id === "intake"));
	ok("route keywords hit route phase", inferPhase(rt, "帮我脱这个壳并分析样本").id === "route");
	ok("cooperate keywords hit cooperate phase", inferPhase(rt, "三个任务并行处理，最后给我全局总结").id === "cooperate");
	ok("shallow keywords hit shallow phase", inferPhase(rt, "查一下这个域名的 whois 和 dns 解析").id === "shallow");
	ok("no hit falls back to intake", inferPhase(rt, "随便聊聊").id === "intake");
	const env = buildEnvelope({ presetId: "redteam", mode: rt, phase: rt.phases[0], refsHits: [], gates: GATES });
	ok("redteam envelope renders no-gate controller line", env.includes("本模式无自建门") && env.includes("router-playbook"));
	ok("redteam envelope renders skill-pointer knowledge line", env.includes("知识:") && env.includes("加载对应专业 playbook"));
	ok("redteam envelope carries boundary discipline", env.includes("总控三边界") && env.includes("概览探测纪律"));
	ok("redteam envelope renders light-review line (单次复核/关键结论才双签)", env.includes("单次独立复核") && env.includes("关键结论定稿"));
	ok("redteam refs inference always empty", inferRefs(rt, "渗透 逆向 样本").length === 0);
}

// 12. envelope text can never form a host prompt-variable group ({{...}})
{
	const nasty = { title: "gate 标题含裸{{}}与{{{x}}}" };
	const escaped = escapePromptBraces("裸{{}} 与 {{{x}}} 与 {{user}}");
	ok("escapePromptBraces kills every {{ pair", !escaped.includes("{{"));
	ok("escapePromptBraces keeps brace-free and single-brace text", escapePromptBraces("a { b } 无花括号") === "a { b } 无花括号");
	const av = MODES["av-evasion"];
	const wrapped = escapePromptBraces(buildEnvelope({ presetId: "av-evasion", mode: av, phase: av.phases[0], refsHits: [], gates: { "av-evasion": { V1: nasty, A2: nasty } } }));
	ok("escaped envelope with brace-laden gate titles renders without {{", !wrapped.includes("{{") && wrapped.includes("裸"));
}

// 14. incident-response 应急溯源：六相位五门 + 调查边界
{
	const ir = MODES["incident-response"];
	ok("ir in route tables with six phases", ir !== undefined && ir.phases.length === 6);
	ok("ir default phase is preserve", ir.defaultPhase === "preserve");
	ok("ir phase gates map I1-I5 onto the five gates", JSON.stringify(ir.phases.map((p) => p.gates.join(","))) === JSON.stringify(["I1", "I1", "I2", "I3", "I4", "I5"]));
	ok("ir boundary carries investigation stance", ir.boundary.includes("先留证后处置") && ir.boundary.includes("多源互证") && ir.boundary.includes("路由 pentest"));
	ok("preserve keywords hit preserve phase", inferPhase(ir, "先固定证据，做只读取证快照").id === "preserve");
	ok("investigate keywords hit investigate phase", inferPhase(ir, "排查这个 webshell 和可疑 crontab 后门").id === "investigate");
	ok("trace keywords hit trace phase", inferPhase(ir, "按日志还原攻击链时间线，找可疑 ip 入口").id === "trace");
	ok("report keywords hit report phase", inferPhase(ir, "写报告收口").id === "report");
	ok("ir refs inference hits linux on ld.so.preload", inferRefs(ir, "检查 ld.so.preload 的 so 后门").includes("linux"));
	ok("ir refs inference hits windows/webshell on 内存马", inferRefs(ir, "分析这个内存马").includes("windows/webshell"));
	const env = buildEnvelope({ presetId: "incident-response", mode: ir, phase: ir.phases[0], refsHits: [], gates: GATES });
	ok("ir envelope renders I1 gate line and boundary", env.includes("I1") && env.includes("证据保全登记") && env.includes("先留证后处置"));
	ok("ir fallback gates carry I1-I5", Object.keys(FALLBACK_GATES["incident-response"]).length === 5);
}

// 14b. cloud-security 云安全攻防：七相位七门 + 攻击路径主线边界
{
	const cloud = MODES["cloud-security"];
	ok("cloud in route tables with seven phases", cloud !== undefined && cloud.phases.length === 7);
	ok("cloud default phase is map", cloud.defaultPhase === "map");
	ok("cloud phase gates map C1-C7 onto the seven gates", JSON.stringify(cloud.phases.map((p) => p.gates.join(","))) === JSON.stringify(["C1", "C2", "C3", "C4", "C5", "C6", "C7"]));
	ok("cloud boundary carries attack-path stance", cloud.boundary.includes("四要素") && cloud.boundary.includes("只读 API") && cloud.boundary.includes("不碰"));
	ok("map keywords hit map phase", inferPhase(cloud, "测绘这个阿里云资产的暴露面").id === "map");
	ok("path keywords hit path phase", inferPhase(cloud, "利用这个 SSRF 打元数据拿实例角色").id === "path");
	ok("detect keywords hit detect phase", inferPhase(cloud, "评估这个路径的 cloudtrail 检测缺口").id === "detect");
	ok("restore keywords hit restore phase", inferPhase(cloud, "环境还原，清理测试资源").id === "restore");
	ok("report keywords hit report phase", inferPhase(cloud, "写云安全报告收口").id === "report");
	ok("cloud refs inference hits vendors on 阿里云 oss", inferRefs(cloud, "检查阿里云 OSS 桶公开访问").includes("vendors"));
	ok("cloud refs inference hits native on k8s 逃逸", inferRefs(cloud, "分析这个 k8s 容器逃逸路径").includes("native"));
	const env = buildEnvelope({ presetId: "cloud-security", mode: cloud, phase: cloud.phases[0], refsHits: [], gates: GATES });
	ok("cloud envelope renders C1 gate line and boundary", env.includes("C1") && env.includes("云资产与暴露面测绘") && env.includes("四要素"));
	ok("cloud fallback gates carry C1-C7", Object.keys(FALLBACK_GATES["cloud-security"]).length === 7);
}

// 14c. ctf-solver CTF 解题台：四相位两门 + flag 真实性边界
{
	const ctf = MODES["ctf-solver"];
	ok("ctf in route tables with four phases", ctf !== undefined && ctf.phases.length === 4);
	ok("ctf default phase is board", ctf.defaultPhase === "board");
	ok("ctf phase gates map board/flag onto the two gates", JSON.stringify(ctf.phases.map((p) => p.gates.join(","))) === JSON.stringify(["board", "board", "flag", "flag"]));
	ok("ctf boundary carries flag-authenticity stance", ctf.boundary.includes("不猜不撞不伪造") && ctf.boundary.includes("沙盒内") && ctf.boundary.includes("题面"));
	ok("board keywords hit board phase", inferPhase(ctf, "先把这几道赛题的题面登记一下").id === "board");
	ok("solve keywords hit solve phase", inferPhase(ctf, "这道 pwn 题帮我解出 flag").id === "solve");
	ok("verify keywords hit verify phase", inferPhase(ctf, "提交这个 flag 看回显并更新台账").id === "verify");
	ok("review keywords hit review phase", inferPhase(ctf, "写 writeup 复盘收口").id === "review");
	ok("学习语境不再路由到解题执行相位", inferPhase(ctf, "学习一下堆溢出的原理").id !== "solve");
	ok("ctf fallback gates carry board/flag", Object.keys(FALLBACK_GATES["ctf-solver"]).length === 2);
}

// 15. 否定语境过滤：学习/防御语境抑制
// execution 相位，防守相位（IR/检测）不受影响。
{
	ok("negation detected on 学习语境", hasNegation("学习一下 SQL 注入的原理"));
	ok("negation detected on 防御语境", hasNegation("如何防御横向移动"));
	ok("negation not fired on plain pentest ask", !hasNegation("帮我验证这个站的 SQL 注入漏洞"));
	ok("negation not fired on IR forensics ask", !hasNegation("排查这个 webshell 后门并还原攻击链"));
	const pentest = MODES.pentest;
	ok("学习语境不再路由到 verify 相位", inferPhase(pentest, "学习一下 SQL 注入的原理").id !== "verify");
	ok("无否定语境仍路由 verify", inferPhase(pentest, "验证这个 SQL 注入").id === "verify");
	const ad = MODES["attack-defense"];
	ok("防御语境不再路由到横向相位", inferPhase(ad, "如何防御横向移动和 kerberos 攻击").id !== "lateral");
	ok("攻击语境仍路由横向", inferPhase(ad, "往域控横向移动拿 kerberos 票据").id === "lateral");
	const av = MODES["av-evasion"];
	ok("学习语境不再路由到构建相位", inferPhase(av, "学习一下 ollvm 混淆编译原理").id !== "build");
	const ir = MODES["incident-response"];
	ok("IR 防守相位不受否定语境影响", inferPhase(ir, "学习一下怎么排查 crontab 后门").id === "investigate");
	ok("否定语境+无命中不继承粘滞执行相位", inferPhase(pentest, "这个漏洞的修复方案给我讲讲", "verify").id === "recon");
	ok("裸继续仍粘滞（无否定词）", inferPhase(pentest, "继续", "verify").id === "verify");
	const negEnv = buildEnvelope({ presetId: "pentest", mode: pentest, phase: pentest.phases[0], refsHits: [], gates: GATES, negated: true });
	ok("negated envelope carries knowledge-mode hint", negEnv.includes("攻击执行相位已抑制"));
	const plainEnv = buildEnvelope({ presetId: "pentest", mode: pentest, phase: pentest.phases[0], refsHits: [], gates: GATES });
	ok("plain envelope has no negation hint", !plainEnv.includes("攻击执行相位路由已抑制"));
}

// 16. 路由决策审计行（设计点③）：格式稳定、触发词截断、管道转义。
{
	const row = buildAuditRow("2026-08-18T00:00:00.000Z", "pentest", "verify", "验证这个 sql 注入 | 很长".repeat(10));
	ok("audit row carries iso/mode/phase", row.startsWith("| 2026-08-18T00:00:00.000Z | pentest | verify |"));
	ok("audit row truncates trigger and escapes pipes", !row.includes("| 很长 |") && row.length < 200);
	const row2 = buildAuditRow("t", "ir", "trace", "多行\n输入");
	ok("audit row collapses newlines", !row2.includes("\n", row2.indexOf("| t |")));
}

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
// ── operation 恢复盘：有未收口准则时信封注入恢复行，全 met/无状态不注入 ──
{
	const mode = MODES.pentest;
	const phase = mode.phases[0];
	const op = { goal: "对 demo 靶站完成授权渗透", total: 3, met: 1, openIds: ["g2", "g3"], pending: ["复测注入点"], gates: { P1: { pass: true } } };
	const withOp = buildEnvelope({ presetId: "pentest", mode, phase, refsHits: [], evidence: "unknown", gates: FALLBACK_GATES, operation: op });
	ok("envelope includes operation recovery line", withOp.includes("operation 恢复") && withOp.includes("1/3 met") && withOp.includes("g2,g3") && withOp.includes("P1 pass"), withOp.slice(0, 120));
	const without = buildEnvelope({ presetId: "pentest", mode, phase, refsHits: [], evidence: "unknown", gates: FALLBACK_GATES });
	ok("envelope omits recovery line without operation", !without.includes("operation 恢复"));
	ok("recovery line truncates long goal", buildEnvelope({ presetId: "pentest", mode, phase, refsHits: [], gates: FALLBACK_GATES, operation: { ...op, goal: "x".repeat(200) } }).includes("x".repeat(80)));
}

// 17. 信封标记化（压缩存活性）+ 注入量记账 + 装配期工具面
{
	const m = MODES.pentest;
	const phase = inferPhase(m, "验证 sqli");
	const body = buildEnvelope({ presetId: "pentest", mode: m, phase, refsHits: ["web"], gates: GATES });
	const wrapped = wrapEnvelope(body, { rev: 3, presetId: "pentest", phaseId: phase.id });
	ok("wrapEnvelope tags well-formed with attrs", wrapped.startsWith(`<dsh-route-boost rev="3" mode="pentest" phase="${phase.id}">`) && wrapped.endsWith("</dsh-route-boost>"));
	ok("isEnvelopeText recognizes wrapped block only", isEnvelopeText(wrapped) && !isEnvelopeText(body) && !isEnvelopeText("random text"));
	ok("envelopeRev parses rev attr", envelopeRev(wrapped) === 3 && envelopeRev(body) === undefined);
	ok("wrapped body preserved verbatim", wrapped.includes("mode=pentest") && wrapped.includes(body.slice(0, 40)));
	const tight = wrapEnvelope(buildEnvelope({ presetId: "pentest", mode: m, phase, refsHits: ["web"], gates: GATES, maxChars: 50 }), { rev: 1, presetId: "pentest", phaseId: phase.id });
	ok("truncated body still wrapped recognizably", isEnvelopeText(tight));
	const det = buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase, refsHits: ["web"], gates: GATES, maxChars: 50 });
	ok("detailed reports dropped sections (refs first)", det.dropped.includes("refs") && det.text.length <= 50);
	const detTools = buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase, refsHits: [], gates: GATES, tools: { total: 5, ok: 3, missing: ["ffuf", "sqlmap"] } });
	ok("tools line renders missing + fallback chain", detTools.text.includes("tools: 技能依赖 3/5 就绪") && detTools.text.includes("缺 ffuf、sqlmap") && detTools.text.includes("已装同类 → MCP"));
	ok("full-ready tools line carries no missing list", buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase, refsHits: [], gates: GATES, tools: { total: 5, ok: 5, missing: [] } }).text.includes("tools: 技能依赖 5/5 就绪"));
	ok("no tools line when status undefined", !buildEnvelope({ presetId: "redteam", mode: MODES.redteam, phase: MODES.redteam.phases[0], refsHits: [], gates: GATES }).includes("tools:"));
	const overTools = buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase, refsHits: ["web"], gates: GATES, maxChars: 200, negated: true, tools: { total: 5, ok: 3, missing: ["a", "b"] } });
	ok("budget drops tools line before tail lines when tight", overTools.dropped.includes("tools") && overTools.text.length <= 200);
	const deps = scanSkillDeps("pentest");
	ok("scanSkillDeps reads playbook tools frontmatter", deps.has("nmap") && deps.has("sqlmap") && deps.has("masscan") && deps.has("hydra") && !deps.has("impacket") && deps.size === 13);
	ok("checkTool: universal binary true, bogus false", checkTool("ls") === true && checkTool("definitely-not-a-real-tool-xyz") === false);
	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rb-acc-"));
	const tmp = path.join(tmpDir, "injections.jsonl");
	ok("appendAccounting writes JSONL line", appendAccounting(tmp, { ts: "t", mode: "pentest", rev: 1, dropped: ["refs"] }) === true && JSON.parse(fs.readFileSync(tmp, "utf8").trim()).rev === 1);
}

// 18. 任务口径：用户指定优先（定向只做指定项并点亮），未指定走全流程
{
	const targeted = detectScope("pentest", "帮我测试这个目标的SQL注入漏洞、XSS漏洞");
	ok("定向判定：图谱类目命中 SQL 注入与 xss", targeted.directed === true && targeted.hits.some((h) => h.includes("SQL")) && targeted.hits.some((h) => h.toLowerCase().includes("xss")));
	ok("全流程委托不误判", detectScope("pentest", "对 example.com 做全面渗透测试，其他你看着办").directed === false);
	ok("显式定向措辞命中", detectScope("pentest", "只测上传漏洞就好").directed === true);
	ok("泛类词+动作词命中", detectScope("pentest", "查一下这个站的越权").directed === true);
	ok("空文本不定向", detectScope("pentest", "").directed === false);
	ok("判定确定性", JSON.stringify(detectScope("pentest", "测 SQL 注入")) === JSON.stringify(detectScope("pentest", "测 SQL 注入")));
	const m = MODES.pentest, phase = inferPhase(m, "帮我测试这个目标的SQL注入漏洞、XSS漏洞");
	const dEnv = buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase, refsHits: [], gates: GATES, scope: detectScope("pentest", "帮我测试这个目标的SQL注入漏洞、XSS漏洞") });
	ok("定向信封：用户指定优先+只做指定项+点亮+不欠账", dEnv.text.includes("scope: 定向——用户指定优先") && dEnv.text.includes("SQL 注入") && dEnv.text.includes("只执行用户指定项") && dEnv.text.includes("redteam_coverage_mark 点亮") && dEnv.text.includes("不补测不欠账"));
	const fEnv = buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase: m.phases[0], refsHits: [], gates: GATES, scope: { directed: false, hits: [] } });
	ok("全流程信封：按矩阵推进", fEnv.text.includes("scope: 未指定具体项——按本模式全流程矩阵推进"));
	ok("目的行：粘滞携带原文（定向）", buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase, refsHits: [], gates: GATES, scope: { directed: true, hits: ["SQL 注入"] }, purpose: "拿到 getshell 并证明可执行" }).text.includes("目的: 拿到 getshell 并证明可执行"));
	ok("目的行：无 purpose 不出行", !buildEnvelopeDetailed({ presetId: "pentest", mode: m, phase, refsHits: [], gates: GATES }).text.includes("目的:"));
	ok("目的行：多行原文单行化+超长裁剪", purposeLine("第一行\n第二行   空格") === "第一行 第二行 空格" && purposeLine("x".repeat(200)).length === 121 && purposeLine("x".repeat(200)).endsWith("…") && purposeLine("  ") === "");
	ok("target 行：三作战模式注入", ["pentest", "attack-defense", "cloud-security"].every((pid) => buildEnvelopeDetailed({ presetId: pid, mode: MODES[pid], phase: MODES[pid].phases[0], refsHits: [], gates: GATES }).text.includes("target: 开战先 redteam_atlas_target")));
	ok("target 行：其余模式不注入", !buildEnvelopeDetailed({ presetId: "code-audit", mode: MODES["code-audit"], phase: MODES["code-audit"].phases[0], refsHits: [], gates: GATES }).text.includes("target: 开战先") && !buildEnvelopeDetailed({ presetId: "redteam", mode: MODES.redteam, phase: MODES.redteam.phases[0], refsHits: [], gates: GATES }).text.includes("target: 开战先"));
	const rtEnv = buildEnvelopeDetailed({ presetId: "redteam", mode: MODES.redteam, phase: MODES.redteam.phases[0], refsHits: [], gates: GATES, scope: { directed: false, hits: [] } });
	ok("redteam 口径走路由/台账措辞", rtEnv.text.includes("按路由手册受理") && !rtEnv.text.includes("redteam_coverage_mark"));
	const rtDir = buildEnvelopeDetailed({ presetId: "redteam", mode: MODES.redteam, phase: MODES.redteam.phases[0], refsHits: [], gates: GATES, scope: { directed: true, hits: [] } });
	ok("redteam 定向走台账终态措辞", rtDir.text.includes("台账终态登记") && rtDir.text.includes("转全流程须用户明示"));
}

// 19. 任务口径全局矩阵：八专业模式用本模式真实类目构造定向样本必命中；全流程委托不误判
{
	const norm = (x) => String(x).toLowerCase().replace(/[\s　]/g, "");
	for (const [presetId, fullText] of [
		["pentest", "这个渗透任务整体交给你了，全面执行，最后出报告"],
		["attack-defense", "攻防演练全链路整体推进，全面执行到底，出报告收口"],
		["code-audit", "整份源码全面审计一遍，出报告"],
		["binary-analysis", "这个样本整体分析到底，全面执行，出报告"],
		["av-evasion", "整套载荷研究交给你全面执行，出对照报告"],
		["incident-response", "这台主机应急响应全流程走完，出报告"],
		["cloud-security", "这个云环境整体评估一遍，全面执行，出报告"],
		["ctf-solver", "这场比赛全部题目整体推进，出复盘"]
	]) {
		const tax = TAXONOMIES[presetId];
		assert.ok(tax, presetId);
		const labels = tax.categories.flatMap((c) => c.items).slice(0, 6).map((i) => i.label);
		const head = labels.map((l) => l.split(/（|\(|·|\/|、/)[0]).find((h) => norm(h).length >= 3) || labels[0];
		const dir = detectScope(presetId, `帮我测试一下「${head}」这个点，其他不用动`);
		ok(`${presetId}: 定向命中本模式类目（${head}）`, dir.directed === true && dir.hits.length > 0);
		const full = detectScope(presetId, fullText);
		ok(`${presetId}: 全流程委托不误判`, full.directed === false, JSON.stringify(full));
	}
	ok("redteam 定向走显式措辞（无矩阵类目）", detectScope("redteam", "只测这个站的注入，其他不路由").directed === true);
	ok("redteam 全流程委托不误判", detectScope("redteam", "三个任务并行处理，最后全局总结").directed === false);
}

process.exit(fail ? 1 : 0);
