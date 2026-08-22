// dsh-attack-atlas 离线单测：类目体系完整性（key 唯一/形态合法）+ SQLite 覆盖态
// （终态白名单/N-A 必附原因/会话×模式隔离/清除）+ 通道纯逻辑（端点分发/派单文案/信任栅栏）。
import assert from "node:assert/strict";
import { openStore, markCell, markStage, getCoverage, clearCoverage, addTarget, listTargets, addChainNode, addChainEdge, listChain, clearChain, CHAIN_NODE_KINDS } from "../lib/store.js";
import { TAXONOMIES, ATLAS_MODES, locate, itemsInForm, validateTaxonomy, refPaths } from "../lib/taxonomy.js";
import fs2 from "node:fs";
import path2 from "node:path";
import { triggerMessage, isTrustedRequest, dispatch } from "../lib/index.js";

let passed = 0;
const ok = async (name, fn) => { await fn(); passed++; console.log(`ok   ${name}`); };
const SID = "session-atlas-1";

//#region 类目体系

await ok("体系完整性：渗透 13 主类、格子 key 全局唯一、形态引用全部合法", () => {
	const problems = validateTaxonomy();
	assert.deepEqual(problems, []);
	const tax = TAXONOMIES.pentest;
	assert.equal(tax.categories.length, 13);
	assert.equal(tax.stages.length, 7);
	assert.equal(tax.forms.length, 9);
	const total = tax.categories.reduce((a, c) => a + c.items.length, 0);
	assert.ok(total >= 120, `子项总数应≥120，实际 ${total}`);
});

await ok("知识关联：渗透全量子项 ref 指向的 refs 文件逐个存在（关联完整性）", () => {
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/pentest/refs");
	const paths = refPaths(TAXONOMIES.pentest);
	assert.ok(paths.length >= 40, `ref 关联应≥40 个文件，实际 ${paths.length}`);
	const missing = paths.filter((p) => !fs2.existsSync(path2.join(refsRoot, p)));
	assert.deepEqual(missing, [], `refs 缺文件: ${missing.join("、")}`);
});

await ok("攻防体系：19 主类×3 战场×5 阶段×4 形态，zone 全合法，ref 全存在（ad refs 根）", () => {
	const t = TAXONOMIES["attack-defense"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 20);
	assert.equal(t.zones.length, 3);
	assert.equal(t.stages.length, 5);
	assert.equal(t.forms.length, 4);
	assert.deepEqual(validateTaxonomy(), []);
	const zoneIds = new Set(t.zones.map((z) => z.id));
	for (const c of t.categories) assert.ok(zoneIds.has(c.zone), `${c.id} zone 非法`);
	// 外网打点序 = 入口面提级序前 10 项次序不变
	const ev = t.categories.find((c) => c.id === "entry-vec");
	assert.deepEqual(ev.items.map((i) => i.id), ["weak-pass", "unauth", "login-bypass", "upload", "file-read", "cmdi", "deser", "nday", "sqli", "ssrf", "edge-nday"]);
	// 收尾区含登记三件套
	assert.ok(t.categories.find((c) => c.id === "phishing").items.length === 5, "社工钓鱼五项");
	assert.ok(t.categories.find((c) => c.id === "entry-vec").items.some((i) => i.id === "edge-nday"), "提级序补边界设备项");
	const wrapIds = t.categories.filter((c) => c.zone === "wrapup").map((c) => c.id);
	assert.deepEqual(wrapIds, ["persistence", "trace-mgmt", "defense-verify"]);
	// ref 存在性（ad refs 根；pentest: 前缀解析到 pentest refs 根）
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/attack-defense/refs");
	const ptRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/pentest/refs");
	const resolve = (p) => p.startsWith("pentest:") ? [path2.join(ptRoot, p.slice(8)), true] : [path2.join(refsRoot, p), false];
	const missing = refPaths(t).filter((p) => !fs2.existsSync(resolve(p)[0]));
	assert.deepEqual(missing, [], `ad refs 缺文件: ${missing.join("、")}`);
	assert.ok(refPaths(t).some((p) => p.startsWith("pentest:")), "入口提级序应存在跨模式 pentest: ref");
	assert.ok(t.chain === true, "ad 应开启链路拓扑特性位");
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "ad 92 子项 ref/pb 全关联");
	// 终态语义本地化齐备
	for (const k of ["tested-found", "tested-clear", "na", "budget-stop"]) assert.ok(t.stateLabels[k], `stateLabels 缺 ${k}`);
});

await ok("八专业模式全覆盖：全部已就绪，研究员=总控不建图谱（不在名单）", () => {
	assert.equal(ATLAS_MODES.length, 8);
	assert.ok(!ATLAS_MODES.includes("redteam"), "研究员不进图谱名单");
	assert.ok(!TAXONOMIES.redteam, "taxonomy 无研究员条目");
	for (const m of ATLAS_MODES) assert.equal(TAXONOMIES[m].pending, undefined, `模式 ${m} 应已就绪`);
});

await ok("应急体系：22 主类×5 分区×6 阶段×3 形态，chainKinds 全在服务端词表，ref 全存在（ir refs 根）", () => {
	const t = TAXONOMIES["incident-response"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 22);
	assert.equal(t.zones.length, 5);
	assert.equal(t.stages.length, 6);
	assert.equal(t.forms.length, 3);
	assert.equal(t.chain, true);
	assert.deepEqual(validateTaxonomy(), []);
	for (const k of Object.keys(t.chainKinds)) assert.ok(CHAIN_NODE_KINDS.includes(k), `chainKind ${k} 不在服务端词表`);
	const zoneIds = new Set(t.zones.map((z) => z.id));
	for (const c of t.categories) assert.ok(zoneIds.has(c.zone), `${c.id} zone 非法`);
	// 七张场景作战卡齐
	const cards = t.categories.filter((c) => c.zone === "cards").map((c) => c.id);
	assert.deepEqual(cards, ["card-live", "card-webshell", "card-memshell", "card-worm", "card-ransom", "card-vuln", "card-forensics"]);
	// 蠕虫卡含感染链拓扑项、勒索卡含双重勒索
	assert.ok(t.categories.find((c) => c.id === "card-worm").items.some((i) => i.id === "spread-topo"));
	assert.ok(t.categories.find((c) => c.id === "card-ransom").items.some((i) => i.id === "double-ext"));
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/incident-response/refs");
	const missing = refPaths(t).filter((p) => !p.startsWith("pentest:") && !fs2.existsSync(path2.join(refsRoot, p)));
	assert.deepEqual(missing, [], `ir refs 缺文件: ${missing.join("、")}`);
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "ir 95 子项 ref/pb 全关联");
});

await ok("locate/itemsInForm：格子定位与形态过滤", () => {
	const tax = TAXONOMIES.pentest;
	assert.equal(locate(tax, "injection/sqli").item.label, "SQL 注入");
	assert.equal(locate(tax, "injection").category.id, "injection");
	assert.equal(locate(tax, "injection/nope"), undefined);
	assert.equal(locate(tax, "nope/x"), undefined);
	// API 形态出现 API 专属子项；Web 形态不出现
	assert.ok(itemsInForm(tax, "config", "api").some((i) => i.id === "grpc"));
	assert.ok(!itemsInForm(tax, "config", "web").some((i) => i.id === "grpc"));
	// 小程序形态加载小程序主类；Web 形态不加载
	assert.ok(tax.formCategories.miniprogram.includes("mini"));
	assert.ok(!tax.formCategories.web.includes("mini"));
	// 移动主类内 Android/iOS 专属子项按形态过滤
	assert.ok(itemsInForm(tax, "mobile", "android").some((i) => i.id === "binder"));
	assert.ok(!itemsInForm(tax, "mobile", "ios").some((i) => i.id === "binder"));
	assert.ok(itemsInForm(tax, "mobile", "ios").some((i) => i.id === "keychain"));
});

//#endregion

//#region 存储层

await ok("markCell：正常四态落库 + upsert 覆盖更新", () => {
	const st = openStore(":memory:");
	markCell(st, SID, "pentest", "injection/sqli", { state: "tested-found", findingRefs: "pentest-1,pentest-2" });
	markCell(st, SID, "pentest", "injection/sqli", { state: "tested-found", findingRefs: "pentest-1" });
	const cov = getCoverage(st, SID, "pentest");
	assert.equal(cov.cells.length, 1);
	assert.equal(cov.cells[0].findingRefs, "pentest-1");
	markCell(st, SID, "pentest", "mini", { state: "na", reason: "资产无小程序形态" });
	assert.equal(getCoverage(st, SID, "pentest").cells.length, 2);
	st.close();
});

await ok("markCell：白名单外 state 抛错；N-A/预算耗尽无原因抛错；非法 key 抛错", () => {
	const st = openStore(":memory:");
	assert.throws(() => markCell(st, SID, "pentest", "injection/sqli", { state: "hacked" }));
	assert.throws(() => markCell(st, SID, "pentest", "injection/sqli", { state: "na" }));
	assert.throws(() => markCell(st, SID, "pentest", "injection/sqli", { state: "budget-stop", reason: "" }));
	assert.throws(() => markCell(st, SID, "pentest", "bad key/x", { state: "na", reason: "r" }));
	st.close();
});

await ok("会话×模式隔离：他会话/他模式读不到", () => {
	const st = openStore(":memory:");
	markCell(st, SID, "pentest", "auth/jwt", { state: "tested-clear", reason: "仅测签名弱钥，算法混淆未排除" });
	assert.equal(getCoverage(st, SID, "pentest").cells.length, 1);
	assert.equal(getCoverage(st, "session-other", "pentest").cells.length, 0);
	assert.equal(getCoverage(st, SID, "code-audit").cells.length, 0);
	st.close();
});

await ok("markStage + clearCoverage：阶段推进与按格/全量清除", () => {
	const st = openStore(":memory:");
	markStage(st, SID, "pentest", "s0", "done");
	markStage(st, SID, "pentest", "s1", "active");
	markCell(st, SID, "pentest", "file/upload", { state: "tested-found" });
	let cov = getCoverage(st, SID, "pentest");
	assert.equal(cov.stages.length, 2);
	assert.equal(cov.cells.length, 1);
	clearCoverage(st, SID, "pentest", "file/upload");
	cov = getCoverage(st, SID, "pentest");
	assert.equal(cov.cells.length, 0);
	assert.equal(cov.stages.length, 2, "清格子不动阶段");
	clearCoverage(st, SID, "pentest");
	assert.equal(getCoverage(st, SID, "pentest").stages.length, 0);
	assert.throws(() => markStage(st, SID, "pentest", "s0", "finished"));
	st.close();
});

//#endregion

//#region 通道纯逻辑

await ok("dispatch：taxonomy.get 拿到八模式与渗透全量；coverage.get 必须带 sessionId", async () => {
	const st = openStore(":memory:");
	const r = await dispatch(null, st, "taxonomy.get", {});
	assert.equal(r.modes.length, 8);
	assert.ok(r.taxonomies.pentest.categories);
	await assert.rejects(() => dispatch(null, st, "coverage.get", { mode: "pentest" }), /sessionId required/);
	st.close();
});

await ok("dispatch：coverage.mark 走存储校验；coverage.clear 清格", async () => {
	const st = openStore(":memory:");
	const r = await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "logic/race", state: "tested-clear", reason: "限速内并发重放，双花未复现" });
	assert.equal(r.ok, true);
	await assert.rejects(() => dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "logic/race", state: "na" }));
	const c = await dispatch(null, st, "coverage.clear", { sessionId: SID, mode: "pentest", key: "logic/race" });
	assert.equal(c.ok, true);
	st.close();
});

await ok("atlas.trigger：无 agents 注册表时如实报不可达；文案含主类/子项/回写指令", async () => {
	const st = openStore(":memory:");
	const r = await dispatch(null, st, "atlas.trigger", { sessionId: SID, mode: "pentest", level: "item", categoryId: "injection", itemId: "sqli", formId: "web" });
	assert.equal(r.ok, false);
	assert.equal(r.unreachable, true);
	const msg = triggerMessage(TAXONOMIES.pentest, { level: "item", categoryId: "injection", itemId: "sqli", formId: "web" });
	assert.ok(msg.includes("注入") && msg.includes("SQL 注入") && msg.includes("redteam_coverage_mark"));
	const cat = triggerMessage(TAXONOMIES.pentest, { level: "category", categoryId: "deser" });
	assert.ok(cat.includes("反序列化") && cat.includes("逐格"));
	const stage = triggerMessage(TAXONOMIES.pentest, { level: "stage", stageId: "s3" });
	assert.ok(stage.includes("登陆口专线") && stage.includes("redteam_coverage_stage"));
	st.close();
});

await ok("followup 派单：agents 注册表可达时注入一条用户消息", async () => {
	const st = openStore(":memory:");
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	const r = await dispatch(fakeCtx, st, "atlas.trigger", { sessionId: SID, mode: "pentest", level: "category", categoryId: "hardcoded" });
	assert.equal(r.ok, true);
	assert.equal(sent.length, 1);
	assert.ok(sent[0].content[0].text.includes("硬编码"));
	assert.equal(sent[0].source.kind, "user");
	st.close();
});

await ok("信任栅栏：loopback 放行、外域 Host 拒、跨源 Origin 拒", () => {
	assert.equal(isTrustedRequest({ headers: { host: "127.0.0.1:3080" } }, []), true);
	assert.equal(isTrustedRequest({ headers: { host: "localhost:3080" } }, []), true);
	assert.equal(isTrustedRequest({ headers: { host: "evil.com:3080" } }, []), false);
	assert.equal(isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://evil.com" } }, []), false);
	assert.equal(isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://127.0.0.1:3080" } }, []), true);
	assert.equal(isTrustedRequest({}, []), false);
});


//#region 目标锚定层

await ok("目标登记：addTarget/listTargets 逐会话隔离、kind 白名单回落", () => {
	const st = openStore(":memory:");
	const t1 = addTarget(st, SID, "pentest", { label: "example.com", kind: "domain", note: "主站" });
	addTarget(st, SID, "pentest", { label: "10.0.0.5:8080", kind: "ip" });
	addTarget(st, SID, "pentest", { label: "怪kind", kind: "alien" });
	const list = listTargets(st, SID, "pentest");
	assert.equal(list.length, 3);
	assert.equal(t1.seq, 1);
	assert.equal(list[2].kind, "other", "未知 kind 回落 other");
	assert.equal(listTargets(st, "session-other", "pentest").length, 0);
	st.close();
});

await ok("终态溯源：单目标自动归属；多目标显式 target 落库", () => {
	const st1 = openStore(":memory:");
	addTarget(st1, SID, "pentest", { label: "only-target.com", kind: "domain" });
	const c1 = markCell(st1, SID, "pentest", "injection/sqli", { state: "tested-found" });
	assert.equal(c1.target, "only-target.com", "单目标未填自动归属");
	st1.close();
	const st2 = openStore(":memory:");
	addTarget(st2, SID, "pentest", { label: "a.com", kind: "domain" });
	addTarget(st2, SID, "pentest", { label: "b.com", kind: "domain" });
	const c2 = markCell(st2, SID, "pentest", "injection/sqli", { state: "na", reason: "a.com 为纯静态站", target: "a.com" });
	assert.equal(c2.target, "a.com");
	const cov = getCoverage(st2, SID, "pentest");
	assert.equal(cov.targets.length, 2);
	assert.equal(cov.cells[0].target, "a.com");
	st2.close();
});

await ok("派单锚定：无目标时提示先登记；有目标时列清单+N-A 溯源要求", () => {
	const noT = triggerMessage(TAXONOMIES.pentest, { level: "item", categoryId: "injection", itemId: "sqli", formId: "web" });
	assert.ok(noT.includes("尚未登记目标") && noT.includes("redteam_atlas_target"));
	const withT = triggerMessage(TAXONOMIES.pentest, { level: "category", categoryId: "deser", targets: [{ label: "example.com", kind: "domain" }, { label: "10.0.0.5:8080", kind: "ip" }] });
	assert.ok(withT.includes("「example.com」域名") && withT.includes("「10.0.0.5:8080」IP/主机") && withT.includes("target 参数"));
});

await ok("targets.* 端点 + atlas.trigger 注入目标上下文", async () => {
	const st = openStore(":memory:");
	await dispatch(null, st, "targets.add", { sessionId: SID, mode: "pentest", label: "example.com", kind: "domain" });
	const lst = await dispatch(null, st, "targets.list", { sessionId: SID, mode: "pentest" });
	assert.equal(lst.targets.length, 1);
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	await dispatch(fakeCtx, st, "atlas.trigger", { sessionId: SID, mode: "pentest", level: "item", categoryId: "access", itemId: "unauth", formId: "web" });
	assert.equal(sent.length, 1);
	assert.ok(sent[0].content[0].text.includes("「example.com」域名"), "派单文案须含登记目标");
	st.close();
});


//#region 云体系

await ok("云体系：18 主类×4 分区×7 阶段×6 形态，chainKinds 在词表，ref 全存在（cloud refs 根）", () => {
	const t = TAXONOMIES["cloud-security"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 18);
	assert.equal(t.zones.length, 4);
	assert.equal(t.stages.length, 7);
	assert.equal(t.forms.length, 6);
	assert.equal(t.chain, true);
	assert.deepEqual(validateTaxonomy(), []);
	for (const k of Object.keys(t.chainKinds)) assert.ok(CHAIN_NODE_KINDS.includes(k), `chainKind ${k} 不在服务端词表`);
	// 提级序四面与高价值五项
	const loot = t.categories.find((c) => c.id === "loot-order");
	assert.deepEqual(loot.items.map((i) => i.id), ["identity-face", "ctrl-face", "secret-face", "data-face"]);
	assert.equal(t.categories.find((c) => c.id === "hv-cloud").items.length, 5);
	// 六源齐
	const six = t.categories.find((c) => c.id === "entry-disc").items.map((i) => i.id);
	for (const src of ["git-repo", "cicd-env", "imds", "fe-bundle", "client-cfg", "bucket-backup"]) assert.ok(six.includes(src), `六源缺 ${src}`);
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/cloud-security/refs");
	const missing = refPaths(t).filter((p) => !p.startsWith("pentest:") && !fs2.existsSync(path2.join(refsRoot, p)));
	assert.deepEqual(missing, [], `cloud refs 缺文件: ${missing.join("、")}`);
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "cloud 72 子项 ref/pb 全关联");
	const genCloud = triggerMessage(t, { level: "chain-gen" });
	assert.ok(genCloud.includes("identity 身份/角色") && genCloud.includes("orgroot 组织根/KMS"), "云 chain-gen 须按 chainKinds 出清单");
});

//#region 二进制体系

await ok("二进制体系：18 主类×5 分区×6 阶段×5 形态，不设链路拓扑，ref 全存在（binary refs 根）", () => {
	const t = TAXONOMIES["binary-analysis"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 18);
	assert.equal(t.zones.length, 5);
	assert.equal(t.stages.length, 6);
	assert.equal(t.forms.length, 5);
	assert.notEqual(t.chain, true, "分析型模式不设链路拓扑");
	assert.deepEqual(validateTaxonomy(), []);
	// 覆盖规则四维度齐：静态三视角/动态行为面/内存/对抗性构造
	const dims = t.categories.filter((c) => c.zone === "dims").map((c) => c.id);
	assert.deepEqual(dims, ["static-view", "dyn-behavior", "mem-line", "adversarial"]);
	// B0/B1/B2 三门在列
	for (const k of ["reg", "verify", "coverage"]) assert.ok(t.categories.some((c) => c.items.some((i) => i.id === k)), `门禁锚点缺 ${k}`);
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/binary-analysis/refs");
	const missing = refPaths(t).filter((p) => !p.startsWith("pentest:") && !fs2.existsSync(path2.join(refsRoot, p)));
	assert.deepEqual(missing, [], `binary refs 缺文件: ${missing.join("、")}`);
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "binary 66 子项 ref/pb 全关联");
});

//#region 代审体系

await ok("代审体系：15 主类×5 分区×6 阶段×5 形态，不设链路拓扑，ref 全存在（code-audit refs 根）", () => {
	const t = TAXONOMIES["code-audit"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 15);
	assert.equal(t.zones.length, 5);
	assert.equal(t.stages.length, 6);
	assert.equal(t.forms.length, 5);
	assert.notEqual(t.chain, true, "审计型模式不设链路拓扑");
	assert.deepEqual(validateTaxonomy(), []);
	// RCE 主线七类+CVE 模式对齐
	const rce = t.categories.find((c) => c.id === "rce-main").items.map((i) => i.id);
	for (const k of ["upload-rce", "unauth-rce", "combo-rce", "hardcoded-rce", "zipslip-rce", "deep-deser", "overflow-rce", "cve-patterns"]) assert.ok(rce.includes(k), `RCE 主线缺 ${k}`);
	// sink 全集 12 项 + 业务逻辑三行
	assert.equal(t.categories.find((c) => c.id === "sink-core").items.length, 12);
	assert.deepEqual(t.categories.find((c) => c.id === "biz-logic").items.map((i) => i.id), ["state-row", "race-row", "client-ctrl"]);
	// A1/A2/A3 锚点在列
	for (const k of ["surface-map", "dual-chain", "count-conserv"]) assert.ok(t.categories.some((c) => c.items.some((i) => i.id === k)), `门禁锚点缺 ${k}`);
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/code-audit/refs");
	const missing = refPaths(t).filter((p) => !p.startsWith("pentest:") && !fs2.existsSync(path2.join(refsRoot, p)));
	assert.deepEqual(missing, [], `code-audit refs 缺文件: ${missing.join("、")}`);
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "code-audit 58 子项 ref/pb 全关联");
});

//#region 免杀体系

await ok("免杀体系：14 主类×5 分区×6 阶段×4 形态，不设链路拓扑，判定终态语义翻转，ref 全存在（av refs 根）", () => {
	const t = TAXONOMIES["av-evasion"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 14);
	assert.equal(t.zones.length, 5);
	assert.equal(t.stages.length, 6);
	assert.equal(t.forms.length, 4);
	assert.notEqual(t.chain, true, "实验循环型模式不设链路拓扑");
	assert.deepEqual(validateTaxonomy(), []);
	// 决策表八行 + lab 十二组
	const mech = t.categories.find((c) => c.id === "counter-table").items.map((i) => i.id);
	assert.equal(mech.length, 8);
	assert.equal(t.categories.find((c) => c.id === "lab-suites").items.length, 12);
	// 四类载荷时序齐
	for (const k of ["payload-webshell", "payload-bin", "payload-c2", "payload-retool"]) assert.ok(t.categories.some((c) => c.id === k), `载荷时序缺 ${k}`);
	// 判定语义翻转：tested-found=过检
	assert.equal(t.stateLabels["tested-found"], "已测·过检");
	assert.equal(t.stateLabels["tested-clear"], "已测·被检出");
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/av-evasion/refs");
	const missing = refPaths(t).filter((p) => !p.startsWith("pentest:") && !fs2.existsSync(path2.join(refsRoot, p)));
	assert.deepEqual(missing, [], `av refs 缺文件: ${missing.join("、")}`);
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "av 66 子项 ref/pb 全关联");
});

//#region CTF 体系

await ok("CTF 体系：9 主类×3 分区×4 阶段×3 赛制，轻量·不设链路拓扑，ref 全存在（ctf refs 根）", () => {
	const t = TAXONOMIES["ctf-solver"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 9);
	assert.equal(t.zones.length, 3);
	assert.equal(t.stages.length, 4);
	assert.equal(t.forms.length, 3);
	assert.notEqual(t.chain, true, "解题台账型不设链路拓扑");
	assert.deepEqual(validateTaxonomy(), []);
	// 九核心模块 + 生态四模块
	const core = t.categories.find((c) => c.id === "mod-core").items.map((i) => i.id);
	assert.equal(core.length, 9);
	assert.equal(t.categories.find((c) => c.id === "mod-eco").items.length, 4);
	// AWD 三线
	assert.deepEqual(t.categories.find((c) => c.id === "card-awd").items.map((i) => i.id), ["atk-line", "patch-line", "counter-line"]);
	assert.equal(t.stateLabels["tested-found"], "已解·flag 验证");
	const refsRoot = path2.resolve(new URL(".", import.meta.url).pathname, "../../../modes/ctf-solver/refs");
	const missing = refPaths(t).filter((p) => !p.startsWith("pentest:") && !fs2.existsSync(path2.join(refsRoot, p)));
	assert.deepEqual(missing, [], `ctf refs 缺文件: ${missing.join("、")}`);
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "ctf 34 子项 ref/pb 全关联");
});

//#region 链路拓扑

await ok("链路节点：id 规则/kind 白名单/major/upsert；边引用未登记节点拒写", () => {
	const st = openStore(":memory:");
	const n1 = addChainNode(st, SID, "attack-defense", { id: "entry-domain-com", label: "domain.com", kind: "entry", major: true });
	addChainNode(st, SID, "attack-defense", { id: "h-192-168-1-2", label: "192.168.1.2", kind: "host", seg: "192.168.1.x" });
	assert.equal(n1.kind, "entry");
	assert.throws(() => addChainNode(st, SID, "attack-defense", { id: "bad id!", label: "x" }));
	addChainNode(st, SID, "attack-defense", { id: "k-alien", label: "x", kind: "alien" });
	assert.equal(listChain(st, SID, "attack-defense").nodes.find((n) => n.id === "k-alien").kind, "other");
	assert.throws(() => addChainEdge(st, SID, "attack-defense", { src: "entry-domain-com", dst: "nope" }), /未登记节点/);
	const e = addChainEdge(st, SID, "attack-defense", { src: "entry-domain-com", dst: "h-192-168-1-2", label: "获取权限" });
	assert.equal(e.label, "获取权限");
	st.close();
});

await ok("链路会话×模式隔离 + clearChain", () => {
	const st = openStore(":memory:");
	addChainNode(st, SID, "attack-defense", { id: "n1", label: "a" });
	addChainNode(st, "session-other", "attack-defense", { id: "n1", label: "b" });
	assert.equal(listChain(st, SID, "attack-defense").nodes.length, 1);
	assert.equal(listChain(st, SID, "pentest").nodes.length, 0);
	clearChain(st, SID, "attack-defense");
	assert.equal(listChain(st, SID, "attack-defense").nodes.length, 0);
	st.close();
});

await ok("chain.* 端点往返 + chain-gen 派单文案", async () => {
	const st = openStore(":memory:");
	await dispatch(null, st, "chain.node", { sessionId: SID, mode: "attack-defense", id: "entry-1", label: "domain.com", kind: "entry", major: true });
	await dispatch(null, st, "chain.node", { sessionId: SID, mode: "attack-defense", id: "dc-1", label: "10.3.3.3", kind: "dc", major: true, seg: "10.3.3.x" });
	await dispatch(null, st, "chain.edge", { sessionId: SID, mode: "attack-defense", src: "entry-1", dst: "dc-1", label: "域控获取" });
	const c = await dispatch(null, st, "chain.list", { sessionId: SID, mode: "attack-defense" });
	assert.equal(c.nodes.length, 2);
	assert.equal(c.edges[0].label, "域控获取");
	await assert.rejects(() => dispatch(null, st, "chain.edge", { sessionId: SID, mode: "attack-defense", src: "entry-1", dst: "ghost" }));
	const gen = triggerMessage(TAXONOMIES["attack-defense"], { level: "chain-gen" });
	assert.ok(gen.includes("redteam_atlas_chain") && gen.includes("add-node") && gen.includes("不虚构"), "chain-gen 文案须含登记指引与不虚构纪律");
	const genIR = triggerMessage(TAXONOMIES["incident-response"], { level: "chain-gen" });
	assert.ok(genIR.includes("attacker 攻击者") && genIR.includes("host 失陷主机") && genIR.includes("exfil 外传/扩散"), "IR chain-gen 须按 chainKinds 出节点型清单");
	st.close();
});

await ok("派单 refHint：pentest: 前缀与 pb 章节两条路径", () => {
	const cross = triggerMessage(TAXONOMIES["attack-defense"], { level: "item", categoryId: "entry-vec", itemId: "sqli", formId: "external" });
	assert.ok(cross.includes("pentest refs/web/web-injection-sqli.md"), "跨模式 ref 应展开为 pentest refs/");
	const pbItem = triggerMessage(TAXONOMIES["attack-defense"], { level: "item", categoryId: "foothold", itemId: "memshell", formId: "external" });
	assert.ok(pbItem.includes("打法出处：本模式 playbook"), "无 ref 项应走 pb 章节提示");
});

//#endregion

console.log(`\n${passed} passed`);
