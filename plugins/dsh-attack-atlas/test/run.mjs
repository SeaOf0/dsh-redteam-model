// dsh-attack-atlas 离线单测：类目体系完整性（key 唯一/形态合法）+ SQLite 覆盖态
// （终态白名单/N-A 必附原因/会话×模式隔离/清除）+ 通道纯逻辑（端点分发/派单文案/信任栅栏）。
import assert from "node:assert/strict";
import { openStore, markCell, markStage, getCoverage, clearCoverage, addTarget, listTargets, addChainNode, addChainEdge, listChain, clearChain, CHAIN_NODE_KINDS, saveMethod, listMethods, getMethod, removeMethod, copyMethod, exportMethods, importMethods } from "../lib/store.js";
import { TAXONOMIES, ATLAS_MODES, locate, itemsInForm, validateTaxonomy, refPaths } from "../lib/taxonomy.js";
import fs2 from "node:fs";
import path2 from "node:path";
import { triggerMessage, isTrustedRequest, dispatch, checkCsrf } from "../lib/index.js";

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
	assert.equal(isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://127.0.0.1:9999" } }, []), false); // 本机他端口 Origin 拒（端口比对）
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

//#region 自定义工作方法论

import { validateMethod, layerMethod, methodRunMessage, inferTargetKind } from "../lib/method.js";

const G = (nodes, edges) => ({ nodes, edges });
const N = (id, ref, extra = {}) => Object.assign({ id, ref, label: ref, note: "", x: 0, y: 0 }, extra);

await ok("validateMethod：结构错误拒绝（缺名/空画布/坏边/自环/重复边/坏引用）", () => {
	const tax = TAXONOMIES.pentest;
	assert.ok(validateMethod("", G([N("n1", "injection")], []), tax).errors.some((e) => e.includes("名称")));
	assert.ok(validateMethod("x", G([], []), tax).errors.some((e) => e.includes("画布为空")));
	assert.ok(validateMethod("x", G([N("n1", "injection")], [{ src: "n1", dst: "ghost" }]), tax).errors.some((e) => e.includes("不存在")));
	assert.ok(validateMethod("x", G([N("n1", "injection")], [{ src: "n1", dst: "n1" }]), tax).errors.some((e) => e.includes("自身")));
	assert.ok(validateMethod("x", G([N("n1", "injection"), N("n2", "access")], [{ src: "n1", dst: "n2" }, { src: "n1", dst: "n2" }]), tax).errors.some((e) => e.includes("重复")));
	assert.ok(validateMethod("x", G([N("n1", "Bad Ref")], []), tax).errors.some((e) => e.includes("格式非法")));
});

await ok("validateMethod：闭环五查 + 战区覆盖建议（无起点时不重复报断裂）", () => {
	const tax = TAXONOMIES.pentest;
	const wkind = (g) => validateMethod("x", g, tax).warnings.map((w) => w.kind).sort();
	assert.deepEqual(wkind(G([N("n1", "injection"), N("n2", "access"), N("n3", "auth")], [{ src: "n1", dst: "n2" }])), ["isolated"]);
	assert.deepEqual(wkind(G([N("a", "injection"), N("b", "access")], [{ src: "a", dst: "b" }, { src: "b", dst: "a" }])), ["cycle", "noend", "nostart"]);
	assert.deepEqual(wkind(G([N("a", "injection"), N("b", "access"), N("c", "auth"), N("d", "config")], [{ src: "a", dst: "b" }, { src: "c", dst: "d" }, { src: "d", dst: "c" }])), ["cycle", "unreachable"]);
	// 攻防模式：只选外网+内网战场 → 收尾战场提示
	const vad = validateMethod("x", G([N("n1", "recon"), N("n2", "host-collect")], [{ src: "n1", dst: "n2" }]), TAXONOMIES["attack-defense"]);
	assert.deepEqual(vad.errors, []);
	assert.deepEqual(vad.warnings, []);
	assert.ok(vad.hints.some((h) => h.includes("未覆盖战场")), vad.hints.join(";"));
});

await ok("layerMethod：菱形分层正确；环归循环段", () => {
	const lg = layerMethod(G([N("a", "injection"), N("b", "access"), N("c", "auth"), N("d", "config")], [{ src: "a", dst: "b" }, { src: "a", dst: "c" }, { src: "b", dst: "d" }, { src: "c", dst: "d" }]));
	assert.deepEqual(lg.layers, [["a"], ["b", "c"], ["d"]]);
	assert.deepEqual(lg.cycle, []);
	const lc = layerMethod(G([N("a", "injection"), N("b", "access")], [{ src: "a", dst: "b" }, { src: "b", dst: "a" }]));
	assert.deepEqual(lc.layers, []);
	assert.deepEqual(lc.cycle, ["a", "b"]);
});

await ok("methodRunMessage：主类展开/子项知识锚/失配降级/备注/层级序/循环段", () => {
	const m = { name: "凭据优先速攻", graph: G(
		[N("n1", "hardcoded/cloud-creds", { note: "先扫前端与仓库" }), N("n2", "injection"), N("n3", "ghost/ghost"), N("n4", "access/unauth")],
		[{ src: "n1", dst: "n2" }, { src: "n1", dst: "n4" }]
	) };
	const msg = methodRunMessage(TAXONOMIES.pentest, m, { anchor: "目标锚定：无", notes: "只打 Web 面" });
	assert.ok(msg.includes("自定义方法论运行"));
	assert.ok(msg.includes("「凭据优先速攻」（渗透测试模式）"));
	assert.ok(msg.includes("辅助需求：只打 Web 面"));
	assert.ok(msg.includes("子项「云凭据（AK/SK）泄露」｜key: hardcoded/cloud-creds"));
	assert.ok(msg.includes("知识手册：refs/components/cloud-postexploitation.md"));
	assert.ok(msg.includes("重点：先扫前端与仓库"));
	assert.ok(msg.includes("主类「注入」整组开测｜key: injection"));
	assert.ok(msg.includes("已不存在，按标签意图执行"));
	assert.ok(msg.includes("第 1 层（起点）"));
	assert.ok(msg.includes("第 2 层"));
	assert.ok(!msg.includes("循环段"));
	const msgc = methodRunMessage(TAXONOMIES.pentest, { name: "环", graph: G([N("a", "injection"), N("b", "access")], [{ src: "a", dst: "b" }, { src: "b", dst: "a" }]) }, { anchor: "x", notes: "" });
	assert.ok(msgc.includes("循环段（存在循环衔接，按列出顺序执行一轮）"));
	assert.ok(msgc.includes("辅助需求：（无）"));
	assert.equal(inferTargetKind("https://a.com"), "web");
	assert.equal(inferTargetKind("10.0.0.5:8080"), "ip");
	assert.equal(inferTargetKind("example.com"), "domain");
	assert.equal(inferTargetKind("内部oa系统"), "other");
});

await ok("模板存储：保存/列表/读取/复制/删除；upsert 保 id 不增行", () => {
	const st = openStore(":memory:");
	const g = G([N("n1", "injection"), N("n2", "access")], [{ src: "n1", dst: "n2" }]);
	const s1 = saveMethod(st, { mode: "pentest", name: "速攻", target: "a.com", notes: "n", graph: g });
	assert.ok(s1.created);
	saveMethod(st, { id: s1.id, mode: "pentest", name: "速攻2", target: "a.com", notes: "n", graph: g });
	const list = listMethods(st, "pentest");
	assert.equal(list.length, 1);
	assert.equal(list[0].name, "速攻2");
	assert.equal(list[0].nodeCount, 2);
	assert.equal(getMethod(st, s1.id).graph.nodes.length, 2);
	const c = copyMethod(st, s1.id);
	assert.equal(listMethods(st, "pentest").length, 2);
	assert.equal(getMethod(st, c.id).name, "速攻2 副本");
	removeMethod(st, s1.id);
	assert.equal(listMethods(st, "pentest").length, 1);
	assert.throws(() => removeMethod(st, s1.id), /不存在/);
	assert.equal(listMethods(st, "code-audit").length, 0);
	st.close();
});

await ok("methods.* 端点：validate/save/list/get/copy/remove 往返；结构错误拒绝保存", async () => {
	const st = openStore(":memory:");
	const graph = G([N("n1", "injection"), N("n2", "access/unauth")], [{ src: "n1", dst: "n2" }]);
	const bad = await dispatch(null, st, "methods.save", { mode: "pentest", name: "坏", graph: { nodes: [], edges: [] } });
	assert.equal(bad.ok, false);
	assert.ok(bad.error.includes("画布为空"));
	const v = await dispatch(null, st, "methods.validate", { mode: "pentest", name: "速攻", graph });
	assert.deepEqual(v.errors, []);
	assert.deepEqual(v.warnings, []);
	const s = await dispatch(null, st, "methods.save", { mode: "pentest", name: "速攻", target: "a.com", notes: "只打 Web", graph });
	assert.equal(s.ok, true);
	assert.deepEqual(s.warnings, []);
	assert.equal((await dispatch(null, st, "methods.list", { mode: "pentest" })).methods.length, 1);
	const got = await dispatch(null, st, "methods.get", { id: s.id });
	assert.equal(got.method.graph.nodes.length, 2);
	const cp = await dispatch(null, st, "methods.copy", { id: s.id });
	assert.equal((await dispatch(null, st, "methods.list", { mode: "pentest" })).methods.length, 2);
	await dispatch(null, st, "methods.remove", { id: cp.id });
	assert.equal((await dispatch(null, st, "methods.list", { mode: "pentest" })).methods.length, 1);
	await assert.rejects(() => dispatch(null, st, "methods.list", {}), /mode required/);
	st.close();
});

await ok("methods.run：信封注入 + 目标自动登记不重复 + 模式不符拒绝 + 环模板循环段", async () => {
	const st = openStore(":memory:");
	const graph = G([N("n1", "hardcoded/cloud-creds"), N("n2", "injection"), N("n3", "auth/jwt")], [{ src: "n1", dst: "n2" }, { src: "n2", dst: "n3" }]);
	const s = await dispatch(null, st, "methods.save", { mode: "pentest", name: "凭据链", graph });
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	const badMode = await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: SID, mode: "code-audit" });
	assert.equal(badMode.ok, false);
	assert.ok(badMode.error.includes("不符"));
	await assert.rejects(() => dispatch(null, st, "methods.run", { id: "m-nope", sessionId: SID, mode: "pentest" }), /模板不存在/);
	const r = await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: SID, mode: "pentest", target: "example.com", notes: "重点登录口" });
	assert.equal(r.ok, true);
	assert.equal(sent.length, 1);
	const text = sent[0].content[0].text;
	assert.ok(text.includes("「凭据链」"));
	assert.ok(text.includes("第 1 层（起点）"));
	assert.ok(text.includes("「example.com」域名"), "会话无目标时按运行输入自动登记");
	assert.ok(text.includes("重点登录口"));
	assert.equal((await dispatch(null, st, "targets.list", { sessionId: SID, mode: "pentest" })).targets.length, 1);
	await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: SID, mode: "pentest" });
	assert.equal(sent.length, 2);
	assert.ok(sent[1].content[0].text.includes("「example.com」域名"));
	assert.equal((await dispatch(null, st, "targets.list", { sessionId: SID, mode: "pentest" })).targets.length, 1, "已有目标不重复登记");
	const cyc = G([N("a", "injection"), N("b", "access")], [{ src: "a", dst: "b" }, { src: "b", dst: "a" }]);
	const s2 = await dispatch(null, st, "methods.save", { mode: "pentest", name: "环", graph: cyc });
	assert.ok(s2.warnings.some((w) => w.kind === "cycle"), "存环模板允许但带警告");
	await dispatch(fakeCtx, st, "methods.run", { id: s2.id, sessionId: SID, mode: "pentest" });
	assert.equal(sent.length, 3);
	assert.ok(sent[2].content[0].text.includes("循环段"));
	st.close();
});

await ok("模板导入导出：导出→删除→导入复原；坏行跳过并说明原因", async () => {
	const st = openStore(":memory:");
	const graph = G([N("n1", "injection")], []);
	await dispatch(null, st, "methods.save", { mode: "pentest", name: "A", graph });
	await dispatch(null, st, "methods.save", { mode: "code-audit", name: "B", graph: G([N("n1", "rce-main")], []) });
	const ex = await dispatch(null, st, "methods.export", {});
	assert.equal(ex.format, "attack-atlas-methods");
	assert.equal(ex.methods.length, 2);
	assert.equal((await dispatch(null, st, "methods.export", { mode: "pentest" })).methods.length, 1);
	for (const t of (await dispatch(null, st, "methods.list", { mode: "pentest" })).methods) await dispatch(null, st, "methods.remove", { id: t.id });
	const imp = await dispatch(null, st, "methods.import", { methods: ex.methods.concat([{ mode: "redteam", name: "X", graph }], [{ mode: "pentest", name: "空图", graph: { nodes: [], edges: [] } }]) });
	assert.equal(imp.imported.length, 2);
	assert.equal(imp.skipped.length, 2);
	assert.ok(imp.skipped.some((x) => x.reason.includes("未知模式")));
	assert.ok(imp.skipped.some((x) => x.reason.includes("画布为空")), "空图行经结构校验跳过");
	assert.equal((await dispatch(null, st, "methods.list", { mode: "pentest" })).methods.length, 1);
	st.close();
});

//#endregion

await ok("自定义方法论全模式矩阵：八模式 校验/存/取/信封/复制/删 全通；zones 模式出覆盖建议", async () => {
	const st = openStore(":memory:");
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	for (const mode of ATLAS_MODES) {
		const tax = TAXONOMIES[mode];
		const cat = tax.categories[0];
		const item = cat.items[0];
		const cat2 = tax.categories[tax.categories.length - 1];
		const graph = { nodes: [
			{ id: "n1", ref: cat.id, label: cat.label, note: "", x: 0, y: 0 },
			{ id: "n2", ref: cat.id + "/" + item.id, label: item.label, note: "重点", x: 230, y: 0 },
			{ id: "n3", ref: cat2.id, label: cat2.label, note: "", x: 460, y: 0 }
		], edges: [{ src: "n1", dst: "n2" }, { src: "n2", dst: "n3" }] };
		const v = await dispatch(null, st, "methods.validate", { mode, name: "全模式-" + mode, graph });
		assert.deepEqual(v.errors, [], `${mode} 应零结构错：${v.errors.join("/")}`);
		assert.deepEqual(v.warnings, [], `${mode} 应零闭环警告：${v.warnings.map((w) => w.kind).join("/")}`);
		const s = await dispatch(null, st, "methods.save", { mode, name: "全模式-" + mode, graph });
		assert.equal(s.ok, true, mode);
		const g = await dispatch(null, st, "methods.get", { id: s.id });
		assert.equal(g.method.graph.nodes.length, 3, mode);
		const r = await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: "s-" + mode, mode });
		assert.equal(r.ok, true, mode);
		const text = sent[sent.length - 1].content[0].text;
		assert.ok(text.includes("（" + tax.label + "模式）"), `${mode} 信封应带模式名`);
		assert.ok(text.includes("key: " + cat.id + "/" + item.id), `${mode} 信封应带格子 key`);
		assert.ok(text.includes("第 1 层（起点）") && text.includes("第 3 层"), `${mode} 信封应分层`);
		assert.ok(text.includes("redteam_coverage_mark"), `${mode} 信封应带回写指令`);
		if (tax.chain) assert.ok(text.includes("redteam_atlas_chain"), `${mode} 链路模式应带链路登记`);
		else assert.ok(!text.includes("redteam_atlas_chain"), `${mode} 无链路模式不应提链路登记`);
		const cp = await dispatch(null, st, "methods.copy", { id: s.id });
		assert.equal(cp.ok, true, mode);
		await dispatch(null, st, "methods.remove", { id: cp.id });
		await dispatch(null, st, "methods.remove", { id: s.id });
		assert.equal((await dispatch(null, st, "methods.list", { mode })).methods.length, 0, `${mode} 删后应空`);
	}
	// ad 跨模式 pentest: 前缀 ref 在运行信封中展开
	const ad = TAXONOMIES["attack-defense"];
	const crossCat = ad.categories.find((c) => c.items.some((i) => i.ref && i.ref.startsWith("pentest:")));
	const crossItem = crossCat.items.find((i) => i.ref && i.ref.startsWith("pentest:"));
	const sc = await dispatch(null, st, "methods.save", { mode: "attack-defense", name: "跨模式ref", graph: { nodes: [{ id: "n1", ref: crossCat.id + "/" + crossItem.id, label: crossItem.label, note: "", x: 0, y: 0 }], edges: [] } });
	await dispatch(fakeCtx, st, "methods.run", { id: sc.id, sessionId: "s-ad", mode: "attack-defense" });
	assert.ok(sent[sent.length - 1].content[0].text.includes("pentest refs/"), "信封应展开 pentest: 前缀");
	// zones 模式：部分战场覆盖 → 覆盖建议；渗透无 zones 不触发放分支
	for (const mode of ATLAS_MODES) {
		const tax = TAXONOMIES[mode];
		if (!tax.zones) continue;
		const z0 = tax.zones[0].id;
		const cats = tax.categories.filter((c) => c.zone === z0).slice(0, 2);
		if (cats.length < 2) continue;
		const v = validateMethod("x", { nodes: [{ id: "a", ref: cats[0].id, label: cats[0].label, note: "", x: 0, y: 0 }, { id: "b", ref: cats[1].id, label: cats[1].label, note: "", x: 0, y: 0 }], edges: [{ src: "a", dst: "b" }] }, tax);
		assert.deepEqual(v.warnings, [], `${mode} 单战场链应零警告`);
		assert.ok(v.hints.some((h) => h.includes("未覆盖战场")), `${mode} 应给战场覆盖建议`);
	}
	st.close();
});

await ok("工具/MCP/自定义模块：类型校验 + 信封安装批准协议 + 混合链端到端", async () => {
	const st = openStore(":memory:");
	const tax = TAXONOMIES.pentest;
	let v = validateMethod("x", { nodes: [{ id: "n1", nt: "alien", tool: "t" }], edges: [] }, tax);
	assert.ok(v.errors.some((e) => e.includes("非法模块类型")));
	v = validateMethod("x", { nodes: [{ id: "n1", nt: "custom", tool: "" }], edges: [] }, tax);
	assert.ok(v.errors.some((e) => e.includes("自定义工具名非法")));
	v = validateMethod("x", { nodes: [{ id: "n1", nt: "tool", tool: "bad name!" }], edges: [] }, tax);
	assert.ok(v.errors.some((e) => e.includes("工具名非法")));
	const graph = { nodes: [
		{ id: "n1", ref: "hardcoded/cloud-creds", label: "云凭据（AK/SK）泄露", note: "", x: 0, y: 0 },
		{ id: "n2", nt: "tool", tool: "nmap", spec: "端口与服务探测", label: "", note: "", x: 0, y: 0 },
		{ id: "n3", nt: "mcp", tool: "kali", spec: "Kali 工具面", label: "", note: "", x: 0, y: 0 },
		{ id: "n4", nt: "custom", tool: "ja3-eye", spec: "JA3 指纹查询", label: "", note: "", x: 0, y: 0 }
	], edges: [{ src: "n1", dst: "n2" }, { src: "n2", dst: "n3" }, { src: "n3", dst: "n4" }] };
	v = validateMethod("混合链", graph, tax);
	assert.deepEqual(v.errors, [], v.errors.join("/"));
	assert.deepEqual(v.warnings, []);
	const msg = methodRunMessage(tax, { name: "混合链", graph }, { anchor: "目标锚定：无", notes: "" });
	assert.ok(msg.includes("工具「nmap」｜用途：端口与服务探测"));
	assert.ok(msg.includes("MCP「kali」｜用途：Kali 工具面"));
	assert.ok(msg.includes("自定义工具「ja3-eye」｜要求：JA3 指纹查询"));
	assert.ok(msg.includes("先询问用户是否安装"), "信封须含安装询问协议");
	assert.ok(msg.includes("严禁未经用户批准自行安装"), "信封须含禁自装铁则");
	assert.ok(msg.includes("写脚本等效实现"), "信封须含脚本降级路径");
	assert.ok(msg.includes("第 1 层（起点）") && msg.includes("第 4 层"), "混合链分层正确");
	const pure = methodRunMessage(tax, { name: "纯链", graph: { nodes: [{ id: "n1", ref: "injection" }], edges: [] } }, { anchor: "a", notes: "" });
	assert.ok(!pure.includes("严禁未经用户批准"), "无工具模块不出协议行");
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	const s = await dispatch(null, st, "methods.save", { mode: "pentest", name: "混合链", graph });
	assert.equal(s.ok, true);
	await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: SID, mode: "pentest" });
	assert.ok(sent[0].content[0].text.includes("自定义工具「ja3-eye」"));
	await dispatch(null, st, "methods.remove", { id: s.id });
	assert.equal((await dispatch(null, st, "methods.list", { mode: "pentest" })).methods.length, 0);
	st.close();
});

await ok("能力库：自定义主类/子类 CRUD+级联删；并入方法论（校验/信封模板内联/删后降级）+导入导出", async () => {
	const st = openStore(":memory:");
	const c1 = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "category", label: "业务专属面", desc: "行业特有" });
	assert.equal(c1.ok, true);
	assert.ok(c1.cat.startsWith("u-"), "自定义主类 key 应 u- 前缀");
	const i1 = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "item", cat: c1.cat, label: "积分系统双花", template: "# 验证姿势\n1. 并发下单观察余额" });
	assert.ok(i1.item.startsWith("u-"));
	const i2 = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "item", cat: "injection", label: "Mongo 注入", desc: "NoSQL" });
	assert.equal(i2.ok, true);
	await assert.rejects(() => dispatch(null, st, "caps.save", { mode: "pentest", kind: "item", cat: "ghost-cat", label: "x" }), /所属主类不存在/);
	const lst = await dispatch(null, st, "caps.list", { mode: "pentest" });
	assert.equal(lst.caps.length, 3);
	// 方法论引用自定义模块：合并类目后校验干净
	const graph = { nodes: [
		{ id: "n1", ref: "injection", label: "注入" },
		{ id: "n2", ref: "injection/" + i2.item, label: "Mongo 注入" },
		{ id: "n3", ref: c1.cat, label: "业务专属面" },
		{ id: "n4", ref: c1.cat + "/" + i1.item, label: "积分系统双花" }
	], edges: [{ src: "n1", dst: "n2" }, { src: "n2", dst: "n3" }, { src: "n3", dst: "n4" }] };
	const v = await dispatch(null, st, "methods.validate", { mode: "pentest", name: "自定义能力链", graph });
	assert.deepEqual(v.errors, [], v.errors.join("/"));
	assert.deepEqual(v.warnings, []);
	const s = await dispatch(null, st, "methods.save", { mode: "pentest", name: "自定义能力链", graph });
	assert.equal(s.ok, true);
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: SID, mode: "pentest" });
	const text = sent[0].content[0].text;
	assert.ok(text.includes("key: injection/" + i2.item + "（用户自定义）"), "内置主类下自定义子类带标记");
	assert.ok(text.includes("Mongo 注入"));
	assert.ok(text.includes("未附模板"), "无模板子类走回退提示");
	assert.ok(text.includes("用户自定义主类"), "自定义主类整组带标记");
	assert.ok(text.includes("业务专属面"));
	assert.ok(text.includes("积分系统双花"));
	assert.ok(text.includes("并发下单观察余额"), "子类模板内联进信封");
	// 删除自定义主类 → 级联；方法论引用降级
	const rm = await dispatch(null, st, "caps.remove", { id: c1.id });
	assert.equal(rm.cascaded, 1);
	assert.equal((await dispatch(null, st, "caps.list", { mode: "pentest" })).caps.length, 1);
	await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: SID, mode: "pentest" });
	assert.ok(sent[1].content[0].text.includes("已不存在，按标签意图执行"), "能力删除后方法论步骤降级");
	// 导入导出往返 + 悬挂检查 + 重复去重
	const ex = await dispatch(null, st, "caps.export", { mode: "pentest" });
	assert.equal(ex.capabilities.length, 1);
	assert.equal(ex.capabilities[0].cat, "injection", "导出保留体系 key");
	await dispatch(null, st, "caps.remove", { id: i2.id });
	assert.equal((await dispatch(null, st, "caps.list", { mode: "pentest" })).caps.length, 0);
	const imp = await dispatch(null, st, "caps.import", { capabilities: ex.capabilities.concat([{ mode: "pentest", kind: "item", cat: "ghost", item: "u-x", label: "悬挂" }]) });
	assert.equal(imp.imported.length, 1);
	assert.equal(imp.skipped.length, 1);
	assert.ok(imp.skipped[0].reason.includes("所属主类不存在"));
	const imp2 = await dispatch(null, st, "caps.import", { capabilities: ex.capabilities });
	assert.equal(imp2.imported.length, 0);
	assert.equal(imp2.skipped.length, 1, "重复导入同 key 去重");
	// 导回的子类在方法论里依旧可用（key 保留）
	const back = (await dispatch(null, st, "caps.list", { mode: "pentest" })).caps[0];
	assert.equal(back.cat, "injection");
	st.close();
});

await ok("caps.import：撞内置主类/子类标识的行被拒（同 key 遮蔽防护）", async () => {
	const st = openStore(":memory:");
	const r = await dispatch(null, st, "caps.import", { capabilities: [
		{ mode: "pentest", kind: "category", cat: "injection", label: "撞车主类", desc: "x" },
		{ mode: "pentest", kind: "item", cat: "injection", item: "sqli", label: "撞车子类" },
		{ mode: "pentest", kind: "item", cat: "injection", item: "u-mine", label: "合法自定义子类" }
	] });
	assert.equal(r.imported.length, 1, "仅合法行入库");
	assert.equal(r.skipped.length, 2);
	assert.ok(r.skipped.every((s) => s.reason.includes("内置")), r.skipped.map((s) => s.reason).join("/"));
	const caps = await dispatch(null, st, "caps.list", { mode: "pentest" });
	assert.equal(caps.caps.length, 1);
	assert.equal(caps.caps[0].cat, "injection");
	assert.equal(caps.caps[0].item, "u-mine");
	st.close();
});

await ok("saveMethod：跨模式覆盖拒绝、同模式更新不受影响", async () => {
	const st = openStore(":memory:");
	const g1 = { nodes: [{ id: "n1", ref: "injection", nt: "tax" }], edges: [] };
	const a = saveMethod(st, { mode: "pentest", name: "渗透模板", graph: g1 });
	await assert.rejects(async () => saveMethod(st, { id: a.id, mode: "ctf-solver", name: "越权覆盖", graph: { nodes: [{ id: "n1", ref: "ctf-web", nt: "tax" }], edges: [] } }), /属于.*不得跨模式覆盖/);
	const b = saveMethod(st, { id: a.id, mode: "pentest", name: "渗透模板改", graph: g1 });
	assert.equal(b.id, a.id, "同模式 upsert 仍可用");
	assert.equal((await dispatch(null, st, "methods.list", { mode: "pentest" })).methods.length, 1);
	st.close();
});


await ok("体系校验：拼错格子/阶段 key 即拒（mark 不再静默丢失）", async () => {
	const st = openStore(":memory:");
	await assert.rejects(() => dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqll", state: "tested-clear" }), /子项不存在/);
	await assert.rejects(() => dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "ghost-cat", state: "na", reason: "x" }), /主类不存在/);
	await assert.rejects(() => dispatch(null, st, "stage.mark", { sessionId: SID, mode: "pentest", stage: "s7", state: "done" }), /阶段不存在/);
	const okMark = await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqli", state: "tested-clear" });
	assert.equal(okMark.ok, true);
	st.close();
});

await ok("methods.import 走结构校验：坏模板跳过并说明原因", async () => {
	const st = openStore(":memory:");
	const bad = { mode: "pentest", name: "坏模板", graph: { nodes: [{ id: "n1", ref: "injection" }, { id: "n1", ref: "injection" }], edges: [] } };
	const good = { mode: "pentest", name: "好模板", graph: { nodes: [{ id: "n1", ref: "injection", nt: "tax" }], edges: [] } };
	const r = await dispatch(null, st, "methods.import", { methods: [bad, good] });
	assert.equal(r.imported.length, 1);
	assert.equal(r.skipped.length, 1);
	assert.ok(r.skipped[0].reason.includes("结构问题"), r.skipped[0].reason);
	st.close();
});

await ok("孤儿清理：删自定义主类/子类清终态行、删目标清归属", async () => {
	const st = openStore(":memory:");
	const cat = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "category", label: "业务面" });
	const item = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "item", cat: cat.cat, label: "积分双花" });
	await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: cat.cat + "/" + item.item, state: "tested-found" });
	await dispatch(null, st, "targets.add", { sessionId: SID, mode: "pentest", label: "目标A", kind: "web" });
	await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqli", state: "tested-clear", target: "目标A" });
	// 删子类 → 其格子终态行清理
	await dispatch(null, st, "caps.remove", { id: item.id });
	assert.equal((await dispatch(null, st, "coverage.get", { sessionId: SID, mode: "pentest" })).cells.filter((c) => c.key.startsWith(cat.cat)).length, 0, "子类格子已清");
	// 删目标 → 归属清空但终态保留
	const tl = await dispatch(null, st, "targets.list", { sessionId: SID, mode: "pentest" });
	await dispatch(null, st, "targets.remove", { sessionId: SID, mode: "pentest", seq: tl.targets[0].seq });
	const after = (await dispatch(null, st, "coverage.get", { sessionId: SID, mode: "pentest" })).cells;
	assert.equal(after.some((c) => c.key === "injection/sqli"), true, "终态保留");
	assert.equal(after.every((c) => !c.target), true, "目标归属已清");
	st.close();
});

await ok("CSRF 头校验：匹配放行/缺失或错值拒", () => {
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "T" } }, "T"), true);
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "X" } }, "T"), false);
	assert.equal(checkCsrf({ headers: {} }, "T"), false);
	assert.equal(checkCsrf({}, "T"), false);
});

console.log(`\n${passed} passed`);
