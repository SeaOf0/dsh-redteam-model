// dsh-attack-atlas 离线单测：类目体系完整性（key 唯一/形态合法）+ SQLite 覆盖态
// （终态白名单/N-A 必附原因/会话×模式隔离/清除）+ 通道纯逻辑（端点分发/派单文案/信任栅栏）。
import assert from "node:assert/strict";
import { openStore, markCell, markStage, getCoverage, clearCoverage, addTarget, listTargets, removeTarget, addChainNode, addChainEdge, listChain, clearChain, chainRefIndex, CHAIN_NODE_KINDS, saveMethod, listMethods, getMethod, removeMethod, copyMethod, exportMethods, importMethods, saveCap, listCaps, recordMiss, missSummary } from "../lib/store.js";
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
	assert.equal(tax.categories.length, 14);
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
	assert.equal(t.categories.length, 21);
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
	assert.ok(t.categories.find((c) => c.id === "phishing").items.length === 9, "社工钓鱼九项（独立作战线全生命周期）");
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
	assert.ok(t.categories.flatMap((c) => c.items).every((i) => i.ref || i.pb), "ad 128 子项 ref/pb 全关联");
	// 终态语义本地化齐备
	for (const k of ["tested-found", "tested-clear", "na", "budget-stop"]) assert.ok(t.stateLabels[k], `stateLabels 缺 ${k}`);
});

await ok("八专业模式全覆盖：全部已就绪，研究员=总控不建图谱（不在名单）", () => {
	assert.equal(ATLAS_MODES.length, 8);
	assert.ok(!ATLAS_MODES.includes("redteam"), "研究员不进图谱名单");
	assert.ok(!TAXONOMIES.redteam, "taxonomy 无研究员条目");
	for (const m of ATLAS_MODES) assert.equal(TAXONOMIES[m].pending, undefined, `模式 ${m} 应已就绪`);
});

await ok("应急体系：24 主类×5 分区×6 阶段×3 形态，chainKinds 全在服务端词表，ref 全存在（ir refs 根）", () => {
	const t = TAXONOMIES["incident-response"];
	assert.equal(t.pending, undefined);
	assert.equal(t.categories.length, 24);
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
	assert.deepEqual(cards, ["card-live", "card-webshell", "card-memshell", "card-worm", "card-ransom", "card-vuln", "card-forensics", "card-mining", "card-phish"]);
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

//#endregion

//#region 按目标分账（v1.2.0：target 为覆盖态第一维度 + 激活指针）

import { switchTarget, getActiveTarget } from "../lib/store.js";
import { DatabaseSync } from "node:sqlite";
import os from "node:os";

await ok("分账核心：双目标同格双终态并存互不覆盖", () => {
	const st = openStore(":memory:");
	addTarget(st, SID, "pentest", { label: "a.com", kind: "domain" });
	addTarget(st, SID, "pentest", { label: "b.com", kind: "domain" });
	markCell(st, SID, "pentest", "injection/sqli", { state: "tested-found", target: "a.com" });
	markCell(st, SID, "pentest", "injection/sqli", { state: "tested-clear", reason: "b.com 参数化查询", target: "b.com" });
	const cov = getCoverage(st, SID, "pentest");
	assert.equal(cov.cells.length, 2, "同格两行并存（旧共享平面会被顶掉，分账后互不蚕食）");
	assert.ok(cov.cells.some((c) => c.target === "a.com" && c.state === "tested-found"));
	assert.ok(cov.cells.some((c) => c.target === "b.com" && c.state === "tested-clear"));
	st.close();
});

await ok("激活指针：首登自动激活；缺省归当前锚定；switch 后归新锚", () => {
	const st = openStore(":memory:");
	addTarget(st, SID, "pentest", { label: "a.com", kind: "domain" });
	addTarget(st, SID, "pentest", { label: "b.com", kind: "domain" });
	assert.equal(getActiveTarget(st, SID, "pentest")?.label, "a.com", "首登自动激活，第二目标不抢");
	assert.equal(markCell(st, SID, "pentest", "auth/jwt", { state: "tested-clear", reason: "r" }).target, "a.com", "缺省归当前锚定");
	switchTarget(st, SID, "pentest", "b.com");
	assert.equal(getActiveTarget(st, SID, "pentest")?.label, "b.com");
	assert.equal(markCell(st, SID, "pentest", "file/upload", { state: "tested-found" }).target, "b.com", "切锚后缺省随新锚");
	assert.equal(markStage(st, SID, "pentest", "s0", "done").target, "b.com", "阶段缺省同归当前锚定");
	assert.throws(() => switchTarget(st, SID, "pentest", "ghost.com"), /目标不存在/);
	st.close();
});

await ok("归属校验：显式 target 未登记即拒并带已登记清单", () => {
	const st = openStore(":memory:");
	addTarget(st, SID, "pentest", { label: "a.com", kind: "domain" });
	assert.throws(() => markCell(st, SID, "pentest", "auth/jwt", { state: "na", reason: "x", target: "自由文本地址" }), /目标未登记：自由文本地址（已登记：a.com/);
	assert.throws(() => markStage(st, SID, "pentest", "s0", "done", "ghost"), /目标未登记/);
	st.close();
});

await ok("首登扫公共：无目标期回写随首个目标归位；第二目标不扫", () => {
	const st = openStore(":memory:");
	markCell(st, SID, "pentest", "injection/sqli", { state: "tested-found" });
	markStage(st, SID, "pentest", "s0", "done");
	addChainNode(st, SID, "attack-defense", { id: "n1", label: "web" });
	addTarget(st, SID, "pentest", { label: "first.com", kind: "domain" });
	addTarget(st, SID, "attack-defense", { label: "ad-first.com", kind: "domain" });
	const cov = getCoverage(st, SID, "pentest");
	assert.equal(cov.cells[0].target, "first.com", "公共格随首登扫入");
	assert.equal(cov.stages[0].target, "first.com", "公共阶段随首登扫入");
	assert.equal(listChain(st, SID, "attack-defense").nodes[0].target, "ad-first.com", "公共链路随本模式首登扫入（模式隔离）");
	addTarget(st, SID, "pentest", { label: "second.com", kind: "domain" });
	assert.equal(getCoverage(st, SID, "pentest").cells.length, 1, "第二目标不扫不产生歧义归属");
	assert.equal(markCell(st, SID, "pentest", "injection/sqli", { state: "tested-clear", reason: "r", target: "second.com" }).target, "second.com");
	assert.equal(getCoverage(st, SID, "pentest").cells.length, 2);
	st.close();
});

await ok("阶段/门联动分账：autoStageFromGate 点亮当时激活目标的阶段带", () => {
	const st = openStore(":memory:");
	const taxCA = TAXONOMIES["code-audit"];
	addTarget(st, SID, "code-audit", { label: "仓库A" });
	addTarget(st, SID, "code-audit", { label: "仓库B" });
	switchTarget(st, SID, "code-audit", "仓库B");
	autoStageFromGate(st, taxCA, SID, "code-audit", "A2");
	let cov = getCoverage(st, SID, "code-audit");
	assert.equal(cov.stages.length, 2);
	assert.ok(cov.stages.every((s) => s.target === "仓库B"), "级联落在当时激活目标（仓库B）的阶段带");
	switchTarget(st, SID, "code-audit", "仓库A");
	autoStageFromGate(st, taxCA, SID, "code-audit", "A1");
	cov = getCoverage(st, SID, "code-audit");
	assert.ok(cov.stages.some((s) => s.target === "仓库A" && s.stage === "s1"), "切锚后门级联落仓库A");
	assert.ok(cov.stages.filter((s) => s.target === "仓库B").length === 2, "仓库B 阶段带不受仓库A 过门影响");
	st.close();
});

await ok("链路分账：listChain 缺省并集（消费方兼容）、显式 scope 过滤、跨 scope 边拒写", () => {
	const st = openStore(":memory:");
	addTarget(st, SID, "attack-defense", { label: "单位1" });
	addTarget(st, SID, "attack-defense", { label: "单位2" });
	switchTarget(st, SID, "attack-defense", "单位2");
	addChainNode(st, SID, "attack-defense", { id: "web1", label: "边界Web", kind: "entry" }); // 归激活=单位2
	addChainNode(st, SID, "attack-defense", { id: "host2", label: "内网机", kind: "host" }); // 归激活=单位2
	addChainNode(st, SID, "attack-defense", { id: "dc1", label: "域控", kind: "dc", major: true, target: "单位1" });
	addChainEdge(st, SID, "attack-defense", { src: "web1", dst: "host2", label: "获取权限", edgeType: "exploits" }); // 同为缺省=单位2 面
	const uni = listChain(st, SID, "attack-defense");
	assert.equal(uni.nodes.length, 3, "缺省=全目标并集（stage-gate chainExists 兼容）");
	assert.ok(uni.nodes.every((n) => typeof n.target === "string"), "并集带 target 字段");
	assert.equal(listChain(st, SID, "attack-defense", "单位1").nodes.length, 1, "显式 scope 过滤");
	assert.throws(() => addChainEdge(st, SID, "attack-defense", { src: "web1", dst: "dc1", label: "跨单位", target: "单位1" }), /未登记节点/, "跨 scope 悬挂边拒写（web1 不在单位1 面）");
	clearChain(st, SID, "attack-defense", "单位1");
	assert.equal(listChain(st, SID, "attack-defense").nodes.length, 2, "scope 级清链不动他目标");
	st.close();
});

await ok("级联删除：removeTarget 清该目标三表行并自动锚定剩余最小 seq", () => {
	const st = openStore(":memory:");
	addTarget(st, SID, "attack-defense", { label: "单位1" });
	addTarget(st, SID, "attack-defense", { label: "单位2" });
	markCell(st, SID, "attack-defense", "entry-vec/sqli", { state: "tested-found", target: "单位1" });
	markCell(st, SID, "attack-defense", "entry-vec/sqli", { state: "tested-clear", reason: "r", target: "单位2" });
	markStage(st, SID, "attack-defense", "recon", "done", "单位1");
	addChainNode(st, SID, "attack-defense", { id: "n1", label: "x", target: "单位1" });
	removeTarget(st, SID, "attack-defense", 1);
	const cov = getCoverage(st, SID, "attack-defense");
	assert.equal(cov.cells.length, 1);
	assert.equal(cov.cells[0].target, "单位2", "他目标行不动");
	assert.equal(cov.stages.length, 0, "单位1 阶段行级联清");
	assert.equal(listChain(st, SID, "attack-defense").nodes.length, 0, "单位1 链路行级联清");
	assert.equal(getActiveTarget(st, SID, "attack-defense")?.label, "单位2", "删激活目标后自动锚定剩余");
	st.close();
});

await ok("autoLight 归属：finding target 精确匹配归该目标；不匹配归当前激活", async () => {
	const st = openStore(":memory:");
	addTarget(st, "al-t", "code-audit", { label: "oa.xxx", kind: "web" });
	addTarget(st, "al-t", "code-audit", { label: "api.xxx", kind: "api" });
	switchTarget(st, "al-t", "code-audit", "api.xxx");
	const deps = { mode: "code-audit", findFindingId: async () => "code-audit-9", followup: () => {} };
	const r1 = await autoLightFromFinding(null, st, "al-t", { title: "F1", type: "任意文件上传", target: "oa.xxx" }, deps);
	assert.equal(r1.marked.length, 1);
	assert.equal(getCoverage(st, "al-t", "code-audit").cells[0].target, "oa.xxx", "精确匹配登记 label → 归该目标");
	const r2 = await autoLightFromFinding(null, st, "al-t", { title: "F2", type: "未授权 RCE", target: "https://free-text-path" }, deps);
	assert.equal(r2.marked.length, 1);
	const c2 = getCoverage(st, "al-t", "code-audit").cells.find((c) => c.key === "rce-main/unauth-rce");
	assert.equal(c2.target, "api.xxx", "自由文本地址不硬塞 → 归当前激活");
	assert.match(c2.reason, /原报目标 https:\/\/free-text-path 未登记/);
	st.close();
});

await ok("targets.switch 端点 + coverage.get 带 active + 派单锚定行当前锚突出", async () => {
	const st = openStore(":memory:");
	await dispatch(null, st, "targets.add", { sessionId: SID, mode: "pentest", label: "a.com", kind: "domain" });
	await dispatch(null, st, "targets.add", { sessionId: SID, mode: "pentest", label: "b.com", kind: "ip" });
	const sw = await dispatch(null, st, "targets.switch", { sessionId: SID, mode: "pentest", label: "b.com" });
	assert.equal(sw.ok, true);
	assert.equal(sw.target.label, "b.com");
	const got = await dispatch(null, st, "coverage.get", { sessionId: SID, mode: "pentest" });
	assert.equal(got.targets.filter((t) => t.active).length, 1, "至多一个激活");
	assert.equal(got.targets.find((t) => t.active)?.label, "b.com");
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	await dispatch(fakeCtx, st, "atlas.trigger", { sessionId: SID, mode: "pentest", level: "category", categoryId: "injection" });
	const text = sent[0].content[0].text;
	assert.match(text, /当前锚定 「b\.com」IP\/主机/, "锚定行当前锚突出");
	assert.match(text, /其余已登记：「a\.com」域名/, "其余已登记降级列出");
	assert.match(text, /redteam_atlas_target switch/, "带切锚指引");
	await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqli", state: "tested-found", target: "b.com" });
	// 切锚后不带 target 的回写归新锚
	await dispatch(null, st, "targets.switch", { sessionId: SID, mode: "pentest", seq: 1 });
	const r = await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqli", state: "tested-clear", reason: "参数化" });
	assert.equal(r.cell.target, "a.com");
	await assert.rejects(() => dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqli", state: "na", reason: "x", target: "ghost" }), /目标未登记：ghost（已登记：a\.com、b\.com/);
	st.close();
});

await ok("迁移：旧 schema 库 openStore 后单目标归属到位、多目标留公共、旧表保留、幂等", () => {
	const p = path2.join(os.tmpdir(), `atlas-mig-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.db`);
	fs2.rmSync(p, { force: true });
	const old = new DatabaseSync(p);
	old.exec(`
	CREATE TABLE coverage (session_id TEXT NOT NULL, mode TEXT NOT NULL, key TEXT NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', finding_refs TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL, PRIMARY KEY (session_id, mode, key));
	CREATE TABLE stages (session_id TEXT NOT NULL, mode TEXT NOT NULL, stage TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (session_id, mode, stage));
	CREATE TABLE chain_nodes (session_id TEXT NOT NULL, mode TEXT NOT NULL, id TEXT NOT NULL, label TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'host', seg TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', major INTEGER NOT NULL DEFAULT 0, finding_ref TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, PRIMARY KEY (session_id, mode, id));
	CREATE TABLE chain_edges (session_id TEXT NOT NULL, mode TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', edge_type TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, PRIMARY KEY (session_id, mode, src, dst, label));
	CREATE TABLE targets (session_id TEXT NOT NULL, mode TEXT NOT NULL, seq INTEGER NOT NULL, label TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'other', note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, PRIMARY KEY (session_id, mode, seq));
	`);
	old.prepare("INSERT INTO coverage VALUES (?,?,?,?,?,?,?,?)").run("s1", "pentest", "injection/sqli", "tested-found", "", "pentest-1", "", "2026-01-01 00:00:00");
	old.prepare("INSERT INTO stages VALUES (?,?,?,?,?)").run("s1", "pentest", "s0", "done", "2026-01-01 00:00:00");
	old.prepare("INSERT INTO targets VALUES (?,?,?,?,?,?,?)").run("s1", "pentest", 1, "only.com", "domain", "", "2026-01-01 00:00:00");
	old.prepare("INSERT INTO coverage VALUES (?,?,?,?,?,?,?,?)").run("s2", "pentest", "auth/jwt", "tested-clear", "r", "", "b.com", "2026-01-01 00:00:00");
	old.prepare("INSERT INTO coverage VALUES (?,?,?,?,?,?,?,?)").run("s2", "pentest", "file/upload", "na", "无上传面", "", "", "2026-01-01 00:00:00");
	old.prepare("INSERT INTO targets VALUES (?,?,?,?,?,?,?)").run("s2", "pentest", 1, "a.com", "domain", "", "2026-01-01 00:00:00");
	old.prepare("INSERT INTO targets VALUES (?,?,?,?,?,?,?)").run("s2", "pentest", 2, "b.com", "domain", "", "2026-01-01 00:00:00");
	old.close();
	const st = openStore(p);
	const c1 = getCoverage(st, "s1", "pentest");
	assert.equal(c1.cells[0].target, "only.com", "单目标会话：未归属行归它");
	assert.equal(c1.stages[0].target, "only.com");
	assert.equal(getActiveTarget(st, "s1", "pentest")?.label, "only.com", "迁移回填激活");
	const c2 = getCoverage(st, "s2", "pentest");
	assert.deepEqual(c2.cells.map((c) => [c.key, c.target]).sort(), [["auth/jwt", "b.com"], ["file/upload", ""]], "多目标会话：显式归属保留、未归属留公共 scope");
	assert.equal(getActiveTarget(st, "s2", "pentest")?.label, "a.com");
	const legacy = st.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_legacy'").all().map((r) => r.name).sort();
	assert.deepEqual(legacy, ["chain_edges_legacy", "chain_nodes_legacy", "coverage_legacy", "stages_legacy"], "旧表 rename 保留不删");
	st.close();
	const st2 = openStore(p); // 幂等：重开不重复拷贝
	assert.equal(getCoverage(st2, "s1", "pentest").cells.length, 1);
	assert.equal(getCoverage(st2, "s2", "pentest").cells.length, 2);
	st2.close();
	fs2.rmSync(p, { force: true });
	fs2.rmSync(p + "-wal", { force: true });
	fs2.rmSync(p + "-shm", { force: true });
});

await ok("methods.run 运行即切锚：对哪个目标跑方法论当前锚就指向它", async () => {
	const st = openStore(":memory:");
	const graph = { nodes: [{ id: "n1", ref: "injection", label: "注入", note: "", x: 0, y: 0 }], edges: [] };
	const s = await dispatch(null, st, "methods.save", { mode: "pentest", name: "速攻", target: "a.com", graph });
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: "mr-1", mode: "pentest" });
	assert.equal(getActiveTarget(st, "mr-1", "pentest")?.label, "a.com", "方法论的 target 运行即切锚（并自动登记）");
	await dispatch(fakeCtx, st, "methods.run", { id: s.id, sessionId: "mr-1", mode: "pentest", target: "b.com" });
	assert.equal(getActiveTarget(st, "mr-1", "pentest")?.label, "b.com", "运行入参目标优先切锚");
	assert.equal((await dispatch(null, st, "targets.list", { sessionId: "mr-1", mode: "pentest" })).targets.length, 2, "两个目标都登记在案");
	st.close();
});

await ok("激活自愈：组内全无激活时重开库锚定最小 seq（旧版并发写残留兜底）", () => {
	const p = path2.join(os.tmpdir(), `atlas-heal-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.db`);
	const st = openStore(p);
	addTarget(st, "h1", "pentest", { label: "a.com" });
	addTarget(st, "h1", "pentest", { label: "b.com" });
	switchTarget(st, "h1", "pentest", "b.com");
	// 模拟旧版本进程并发写残留：全组 active 清零
	st.db.exec("UPDATE targets SET active = 0");
	st.close();
	const st2 = openStore(p); // 重开自愈
	assert.equal(getActiveTarget(st2, "h1", "pentest")?.label, "a.com", "无激活组重开锚定最小 seq");
	switchTarget(st2, "h1", "pentest", "b.com");
	st2.close();
	const st3 = openStore(p);
	assert.equal(getActiveTarget(st3, "h1", "pentest")?.label, "b.com", "已有激活组不被自愈扰动");
	st3.close();
	fs2.rmSync(p, { force: true }); fs2.rmSync(p + "-wal", { force: true }); fs2.rmSync(p + "-shm", { force: true });
});

await ok("org 形态：组织/单位 kind 可登记并进锚定词", async () => {
	const st = openStore(":memory:");
	const t = addTarget(st, SID, "attack-defense", { label: "某某集团公司", kind: "org" });
	assert.equal(t.kind, "org");
	const sent = [];
	const fakeCtx = { get: () => ({ get: () => ({ followup: (m) => sent.push(m) }) }) };
	await dispatch(fakeCtx, st, "atlas.trigger", { sessionId: SID, mode: "attack-defense", level: "category", categoryId: "recon" });
	assert.match(sent[0].content[0].text, /「某某集团公司」组织\/单位/, "组织目标进锚定行");
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
	// 提级序五面（含 exfil 数据外传）与高价值五项
	const loot = t.categories.find((c) => c.id === "loot-order");
	assert.deepEqual(loot.items.map((i) => i.id), ["identity-face", "ctrl-face", "secret-face", "data-face", "exfil"]);
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
	assert.equal(t.categories.length, 10);
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


await ok("体系校验：拼错格子/阶段 key 即拒（mark 不再静默丢失）+ typo 模糊自愈", async () => {
	const st = openStore(":memory:");
	const healed = await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqll", state: "tested-clear" });
	assert.equal(healed.ok, true);
	assert.equal(healed.cell.key, "injection/sqli", "高置信 typo 归一到 canonical key");
	await assert.rejects(() => dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/zzzz", state: "tested-clear" }), /子项不存在/);
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

await ok("孤儿清理：删自定义主类/子类清终态行、删目标级联清其作战数据", async () => {
	const st = openStore(":memory:");
	const cat = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "category", label: "业务面" });
	const item = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "item", cat: cat.cat, label: "积分双花" });
	await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: cat.cat + "/" + item.item, state: "tested-found" });
	await dispatch(null, st, "targets.add", { sessionId: SID, mode: "pentest", label: "目标A", kind: "web" });
	await dispatch(null, st, "coverage.mark", { sessionId: SID, mode: "pentest", key: "injection/sqli", state: "tested-clear", target: "目标A" });
	// 删子类 → 其格子终态行清理（全目标 scope）
	await dispatch(null, st, "caps.remove", { id: item.id });
	assert.equal((await dispatch(null, st, "coverage.get", { sessionId: SID, mode: "pentest" })).cells.filter((c) => c.key.startsWith(cat.cat)).length, 0, "子类格子已清");
	// 删目标 → 该目标的覆盖/阶段/链路行级联清理（错登清理语义；归档用 switch 切走勿删）
	const tl = await dispatch(null, st, "targets.list", { sessionId: SID, mode: "pentest" });
	await dispatch(null, st, "targets.remove", { sessionId: SID, mode: "pentest", seq: tl.targets[0].seq });
	const after = (await dispatch(null, st, "coverage.get", { sessionId: SID, mode: "pentest" })).cells;
	assert.equal(after.length, 0, "目标作战数据级联清理（首登扫入的公共行随目标删）");
	st.close();
});

await ok("CSRF 头校验：匹配放行/缺失或错值拒", () => {
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "T" } }, "T"), true);
	assert.equal(checkCsrf({ headers: { "x-dsh-csrf": "X" } }, "T"), false);
	assert.equal(checkCsrf({ headers: {} }, "T"), false);
	assert.equal(checkCsrf({}, "T"), false);
});

// ===== 词典治理（R2 报错带候选 / R3 标签等价）=====
import { resolveKey, canonicalKey, resolveStageId, resolveStateLabel, parseCoverageTable, applyCoverageRows, autoLightFromFinding, validateCoverageRef, validateStageRef } from "../lib/index.js";
const CA = TAXONOMIES["code-audit"];

await ok("R3·昨日七连拒实测标签全部自愈（code-audit）", () => {
	// 中文标签曾被全部拒绝——归一化后应全部命中
	const cases = {
		"任意上传RCE": "rce-main/upload-rce", "未授权RCE": "rce-main/unauth-rce", "组合RCE": "rce-main/combo-rce",
		"深度反序列化": "rce-main/deep-deser", "溢出RCE": "rce-main/overflow-rce", "zip自解压RCE": "rce-main/zipslip-rce",
		"SQL 注入": "sink-core/sqli", "RCE 主线": "rce-main", "rce-main/任意上传RCE": "rce-main/upload-rce"
	};
	for (const [label, key] of Object.entries(cases)) assert.equal(resolveKey(CA, label)?.key, key, `${label} 应归一到 ${key}`);
});

await ok("R3·八模式标签直查抽查 + 同长歧义保守拒", () => {
	for (const mode of ["pentest", "binary-analysis", "av-evasion", "cloud-security", "ctf-solver", "incident-response", "attack-defense"]) {
		const t = TAXONOMIES[mode];
		if (!t || t.pending) continue;
		const item = t.categories[0].items[0];
		assert.equal(resolveKey(t, item.label)?.key, `${t.categories[0].id}/${item.id}`, `${mode} 首格标签应全等归一`);
	}
	const fake = { label: "测试体系", stages: [], categories: [{ id: "c1", label: "甲", items: [{ id: "a", label: "苹果派" }, { id: "b", label: "苹果酱" }] }] };
	assert.ok(resolveKey(fake, "苹果")?.ambiguous, "同长双命中须判歧义而非硬选");
});

await ok("R2·错值报错必带合法候选清单", () => {
	const e1 = validateCoverageRef(CA, "不存在的主类");
	assert.match(e1, /合法主类：/, "主类清单在场");
	assert.match(e1, /审计形态判定\(audit-shape\)/, "清单含 id 对");
	const e2 = validateCoverageRef(CA, "rce-main/zzz");
	assert.match(e2, /子项不存在/, "主类对子项错给子项清单");
	assert.match(e2, /任意文件上传 RCE\(rce-main\/upload-rce\)/, "子项清单含 id 对");
	const e3 = validateStageRef(CA, "乱写");
	assert.match(e3, /合法阶段：s1 /, "阶段清单在场");
});

await ok("R3·阶段中文标签归一 + 垃圾串拒收（ghost-cat 假阳性防回归）", () => {
	assert.equal(resolveStageId(CA, "静态审计"), "s2");
	assert.equal(resolveStageId(CA, "覆盖与对账"), "s5");
	assert.equal(resolveKey(TAXONOMIES["pentest"], "ghost-cat"), null, "垃圾串不得模糊命中");
	const typo = resolveKey(TAXONOMIES["pentest"], "injection/sqll");
	assert.equal(typo?.key, "injection/sqli", "高置信 typo 自愈");
});

await ok("R3·终态中文标签归一（两套 UI 词表 + canonical）", () => {
	assert.equal(resolveStateLabel("tested-found"), "tested-found");
	assert.equal(resolveStateLabel("已测·有发现"), "tested-found");
	assert.equal(resolveStateLabel("已审·有 finding"), "tested-found");
	assert.equal(resolveStateLabel("无finding"), "tested-clear");
	assert.equal(resolveStateLabel("不适用"), "na");
	assert.equal(resolveStateLabel("未完成"), "budget-stop");
	assert.equal(resolveStateLabel("让位"), "budget-stop");
	assert.equal(resolveStateLabel("瞎写的态"), "");
});

// ===== P2 矩阵批量同步 =====
await ok("parseCoverageTable：表头定位/分隔行跳过/列映射/乱序容错", () => {
	const md = [
		"# 覆盖矩阵", "",
		"| 主类 | 格子 | 终态 | 原因 | finding | 目标 |",
		"|---|---|---|---|---|---|",
		"| RCE | 任意上传RCE | 已审·有 finding |  | code-audit-2 | oa.xxx |",
		"| sink | SQL 注入 | 已审·无 finding | 白盒 grep 全量无拼接 | | oa.xxx |",
		"| sink | LDAP | 不适用 | 无 LDAP 面 | | |",
		"", "正文里孤立的 | 行不算表内行：此行在表结束后应终止解析"
	].join("\n");
	const rows = parseCoverageTable(md);
	assert.equal(rows.length, 3, "分隔行不计、表后断裂");
	assert.equal(rows[0].key, "任意上传RCE");
	assert.equal(rows[0].state, "已审·有 finding");
	assert.equal(rows[0].findingRefs, "code-audit-2");
	assert.equal(rows[2].state, "不适用");
	assert.equal(parseCoverageTable("没有表格的文本").length, 0);
});

await ok("applyCoverageRows：中文 key/终态批量落库 + 坏行跳过带行号", () => {
	const st = openStore(":memory:");
	const rows = [
		{ key: "任意上传RCE", state: "已审·有 finding", findingRefs: "code-audit-2", line: 4 },
		{ key: "sink-core/sqli", state: "无finding", reason: "白盒 grep 无拼接", line: 5 },
		{ key: "LDAP", state: "不适用", reason: "无 LDAP 面", line: 6 },
		{ key: "幽灵格子", state: "已审·有 finding", line: 7 },
		{ key: "SQL 注入", state: "乱写的态", line: 8 },
		{ key: "溢出RCE", state: "不适用", line: 9 }
	];
	const { applied, failed } = applyCoverageRows(st, CA, "sync-1", "code-audit", rows);
	assert.deepEqual(applied.sort(), ["rce-main/upload-rce", "sink-core/ldap", "sink-core/sqli"].sort());
	assert.equal(failed.length, 3, "幽灵格/坏终态/na 无原因各跳一行");
	assert.match(failed[0], /第 7 行.*合法主类/);
	assert.match(failed[1], /第 8 行.*不是合法终态/);
	assert.match(failed[2], /第 9 行.*原因/);
	const cov = getCoverage(st, "sync-1", "code-audit");
	assert.equal(cov.cells.length, 3);
	st.close();
});

// ===== P1 finding 自动亮 + P3 覆盖提醒 =====
await ok("autoLight：type/CWE 线索点亮 + finding ref 回填 + 不覆盖已有终态", async () => {
	const st = openStore(":memory:");
	const nudges = [];
	const deps = { mode: "code-audit", findFindingId: async () => "code-audit-3", followup: (m) => nudges.push(m) };
	const r1 = await autoLightFromFinding(null, st, "auto-1", { title: "F1 上传RCE", type: "任意文件上传", cwe: "", target: "oa.xxx" }, deps);
	assert.deepEqual(r1.marked, ["rce-main/upload-rce"], "type 线索归一落格");
	const cov = getCoverage(st, "auto-1", "code-audit");
	const cell = cov.cells.find((c) => c.key === "rce-main/upload-rce");
	assert.equal(cell.state, "tested-found");
	assert.equal(cell.findingRefs, "code-audit-3");
	assert.match(cell.reason, /自动：finding code-audit-3/);
	// finding 的 target 是自由文本地址：未登记不硬塞归属——落公共 scope，原值进 reason 保溯源
	assert.equal(cell.target, "");
	assert.match(cell.reason, /原报目标 oa\.xxx 未登记/);
	// 人工终态不可被自动覆盖：先手写 tested-clear，自动亮须跳过
	await dispatch(null, st, "coverage.mark", { sessionId: "auto-2", mode: "code-audit", key: "SQL 注入", state: "tested-clear", reason: "人工已排除" });
	const r2 = await autoLightFromFinding(null, st, "auto-2", { title: "F2 注入", type: "SQL 注入" }, deps);
	assert.equal(r2.marked.length, 0, "已有终态不覆盖");
	// CWE 线索
	const r3 = await autoLightFromFinding(null, st, "auto-3", { title: "F3 注入", cwe: "CWE-89" }, deps);
	assert.deepEqual(r3.marked, ["sink-core/sqli"], "CWE-89 → SQL 注入格");
	// 查不到 finding id 也不缺格（ref 空）
	const r4 = await autoLightFromFinding(null, st, "auto-4", { title: "F4", type: "命令执行" }, { ...deps, findFindingId: async () => { throw new Error("库不可用"); } });
	assert.equal(r4.marked.length, 1);
	assert.equal(getCoverage(st, "auto-4", "code-audit").cells[0].findingRefs, "");
	// 无线索/无关线索保守跳过
	assert.equal((await autoLightFromFinding(null, st, "auto-5", { title: "F5" }, deps)).marked.length, 0);
	assert.equal((await autoLightFromFinding(null, st, "auto-6", { title: "F6", type: "完全无关线索" }, deps)).marked.length, 0, "低相似线索不点亮");
	st.close();
});

await ok("autoLight·P3 覆盖提醒：每主类一次限流、文案带剩余格与 sync 指引", async () => {
	const st = openStore(":memory:");
	const nudges = [];
	const deps = { mode: "code-audit", findFindingId: async () => "", followup: (m) => nudges.push(m) };
	await autoLightFromFinding(null, st, "nudge-1", { title: "F1", type: "任意文件上传" }, deps);
	assert.equal(nudges.length, 1, "首亮即提醒一次");
	assert.match(nudges[0].content[0].text, /AttackAtlas·覆盖提醒/);
	assert.match(nudges[0].content[0].text, /RCE 主线聚焦/);
	assert.match(nudges[0].content[0].text, /redteam_coverage_sync/);
	await autoLightFromFinding(null, st, "nudge-1", { title: "F2", type: "未授权 RCE" }, deps);
	assert.equal(nudges.length, 1, "同主类第二次不重复提醒");
	await autoLightFromFinding(null, st, "nudge-1", { title: "F3", type: "SQL 注入" }, deps);
	assert.equal(nudges.length, 2, "新主类（sink 全集）新提醒");
	// 模式语态：三选一词表进提醒 + 本模式收口纪律子句
	assert.match(nudges[1].content[0].text, /已审·有 finding \/ 已审·无 finding/);
	assert.match(nudges[1].content[0].text, /已审结论附 sink 指位与复现链/);
	st.close();
});

await ok("覆盖提醒模式语态：IR 词表+先保全纪律，pentest 词表+无附加纪律句", async () => {
	const st = openStore(":memory:");
	const irItem = TAXONOMIES["incident-response"].categories[0].items[0].label;
	const irNudges = [];
	await autoLightFromFinding(null, st, "nudge-ir", { title: "F1", type: irItem }, { mode: "incident-response", findFindingId: async () => "", followup: (m) => irNudges.push(m) });
	assert.ok(irNudges.length >= 1, "IR 首亮即提醒");
	assert.ok(irNudges[0].content[0].text.includes("查实·有证据") && irNudges[0].content[0].text.includes("先保全证据（附证据指位与时间线位置）"), "IR 词表+保全纪律");
	const ptNudges = [];
	await autoLightFromFinding(null, st, "nudge-pt", { title: "F1", type: "任意文件上传" }, { mode: "pentest", findFindingId: async () => "", followup: (m) => ptNudges.push(m) });
	assert.ok(ptNudges.length >= 1 && ptNudges[0].content[0].text.includes("已验·有发现"), "pentest 词表");
	assert.ok(!/——已审结论|——查实项|——判定结果/.test(ptNudges[0].content[0].text), "pentest 无五模式附加纪律句");
	st.close();
});

// ===== 阶段门联动：stage_gate PASS → 阶段带级联点亮 =====
import { autoStageFromGate, isGatePassText } from "../lib/index.js";

await ok("门映射完备：八模式全部门 id 有阶段映射且阶段 id 在体系内", async () => {
	let gatesObj = null;
	try { ({ GATES: gatesObj } = await import("@dsh-external/dsh-stage-gate")); } catch { gatesObj = null; }
	for (const [mode, mapping] of Object.entries(GATE_STAGE_REF)) {
		const t = TAXONOMIES[mode];
		assert.ok(t && !t.pending, `${mode} 体系就绪`);
		const stageIds = new Set((t.stages ?? []).map((s) => s.id));
		for (const stageId of Object.values(mapping)) assert.ok(stageIds.has(stageId), `${mode} 映射 ${stageId} 不在体系阶段内`);
		if (gatesObj) {
			for (const gateId of Object.keys(gatesObj[mode] ?? {})) assert.ok(mapping[gateId], `${mode} 门 ${gateId} 缺阶段映射`);
			assert.equal(Object.keys(mapping).length, Object.keys(gatesObj[mode] ?? {}).length, `${mode} 映射与门数一致`);
		}
	}
	assert.ok(gatesObj, "桥接环境应有 stage-gate 可交叉核对（CI/debug 均满足）");
});
// 从模块导出里拿 GATE_STAGE（经 autoStageFromGate 反推不便，直接再导出一份引用）
import { GATE_STAGE as GATE_STAGE_REF } from "../lib/index.js";

await ok("autoStageFromGate：PASS 级联点亮此前全部阶段；未知门不动", () => {
	const st = openStore(":memory:");
	const marked = autoStageFromGate(st, CA, "gate-1", "code-audit", "A2");
	assert.deepEqual(marked, ["s1", "s2"], "A2 过门 → s1-s2 级联（s3 条件性、s4 逐 finding 双链门均不凭过门推定）");
	const cov = getCoverage(st, "gate-1", "code-audit");
	assert.equal(cov.stages.length, 2);
	assert.ok(cov.stages.every((s) => s.state === "done"));
	assert.deepEqual(autoStageFromGate(st, CA, "gate-1", "code-audit", "A9"), [], "未知门不动");
	assert.deepEqual(autoStageFromGate(st, TAXONOMIES["ctf-solver"], "gate-2", "ctf-solver", "flag"), ["s1", "s2", "s3"], "ctf flag 过门 → s1-s3 级联");
	st.close();
});

await ok("isGatePassText：仅本门 PASS 前缀命中，FAIL/他门不误触", () => {
	assert.equal(isGatePassText("stage_gate code-audit/A2: PASS — manual review still required: x", "code-audit", "A2"), true);
	assert.equal(isGatePassText("stage_gate code-audit/A2: FAIL — missing: assets", "code-audit", "A2"), false);
	assert.equal(isGatePassText("stage_gate code-audit/A3: PASS", "code-audit", "A2"), false);
	assert.equal(isGatePassText("", "code-audit", "A2"), false);
});


// ===== 工具 schema 宿主编译防回归（defineTool 同一编译器；items.object 必须显式 additionalProperties）=====
import { defineTool } from "@deepseek-ai/dsh-tools";
await ok("sync 工具 schema 可过宿主编译器（runtime boot 防崩溃）", () => {
	const params = { rows: { type: "array", items: { type: "object", additionalProperties: true }, description: "x" }, path: { type: "string" } };
	defineTool({ name: "_schema_probe_sync", description: "x", parameters: params, output: { schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean" } } } }, execute: () => Promise.resolve({ ok: true }) });
});

// ===== 分模式锚定与目标词表 =====
await ok("锚定分模式：七模式各自对象/基线/纪律词，pentest 原文不变", () => {
	const noTarget = (mode) => triggerMessage(TAXONOMIES[mode], { level: "category", categoryId: TAXONOMIES[mode].categories[0].id, formId: "all", targets: [] });
	assert.match(noTarget("av-evasion"), /在验载荷/);
	assert.match(noTarget("av-evasion"), /experiment-plan/);
	assert.match(noTarget("av-evasion"), /本地默认验证/);
	assert.match(noTarget("ctf-solver"), /题目/);
	assert.match(noTarget("ctf-solver"), /平台规则即边界/);
	assert.match(noTarget("code-audit"), /审计对象/);
	assert.match(noTarget("code-audit"), /面映射/);
	assert.match(noTarget("binary-analysis"), /B0/);
	assert.match(noTarget("incident-response"), /保全清单/);
	assert.match(noTarget("cloud-security"), /cloud-assets\.md/);
	assert.match(noTarget("pentest"), /授权目标/);
	assert.match(noTarget("pentest"), /assets\.md/);
	const av = triggerMessage(TAXONOMIES["av-evasion"], { level: "category", categoryId: TAXONOMIES["av-evasion"].categories[0].id, formId: "all", targets: [{ label: "exp/x.jsp", kind: "webshell" }] });
	assert.match(av, /对象锚定：「exp\/x.jsp」WebShell/, "新 kind 词表生效");
	assert.match(av, /已测·过检 \/ 已测·被检出 \/ 不适用（无环境）/, "三选一按模式图例生成");
});

await ok("派单三选一按模式图例：ctf/binary/IR 各自词", () => {
	const cell = (mode) => { const t = TAXONOMIES[mode]; return triggerMessage(t, { level: "cell", categoryId: t.categories[0].id, itemId: t.categories[0].items[0].id, formId: "all", targets: [] }); };
	assert.match(cell("ctf-solver"), /已解·flag 验证 \/ 已试·卡点/);
	assert.match(cell("binary-analysis"), /已分析·有结论 \/ 已分析·未见异常/);
	assert.match(cell("incident-response"), /查实·有证据 \/ 已查·未命中/);
});


// ===== ref 路由化 / 姿势词 / 级联排除 =====
await ok("sink 类格子 refHint 走 README 路由（不预设语言）", () => {
	const msg = triggerMessage(CA, { level: "cell", categoryId: "sink-core", itemId: "sqli", formId: "all", targets: [] });
	assert.match(msg, /refs\/README\.md（按目标语言快速路由/, "sqli 派单不再硬编码 java 手册");
	const path = triggerMessage(CA, { level: "cell", categoryId: "sink-core", itemId: "path", formId: "all", targets: [] });
	assert.match(path, /按目标语言快速路由/);
});

await ok("派单姿势词按模式语态：IR=取证 / av=实验 / ctf=解题", () => {
	const cell = (mode) => { const t2 = TAXONOMIES[mode]; return triggerMessage(t2, { level: "cell", categoryId: t2.categories[0].id, itemId: t2.categories[0].items[0].id, formId: "all", targets: [] }); };
	assert.match(cell("incident-response"), /取证姿势执行（先保全后分析、只读优先）/);
	assert.match(cell("av-evasion"), /实验姿势执行（本地默认验证/);
	assert.match(cell("ctf-solver"), /解题姿势执行（平台规则内/);
	assert.match(cell("pentest"), /验证姿势执行（最小影响、非破坏性）/, "渗透保持原姿势词");
});

await ok("级联排除：pentest P2 不点亮 s3/s5；binary B1 不点亮 s3/s4（逐条目门不推定阶段整体完成）", () => {
	const st = openStore(":memory:");
	const marked = autoStageFromGate(st, TAXONOMIES["pentest"], "nf-1", "pentest", "P2");
	assert.ok(!marked.includes("s3"), "s3 登陆口专线不凭过门推定完成");
	assert.ok(!marked.includes("s5"), "s5 验证与影响证明不凭单 finding 复核（P2）推定完成");
	assert.ok(marked.includes("s0") && marked.includes("s4"), "画像与此前无条件阶段照常点亮");
	const marked2 = autoStageFromGate(st, TAXONOMIES["binary-analysis"], "nf-2", "binary-analysis", "B1");
	assert.ok(!marked2.includes("s3"), "binary s3 动态分析不凭 B1 推定完成");
	assert.ok(!marked2.includes("s4"), "B1 逐样本还原门不推定 s4 还原破解整体完成");
	st.close();
});

await ok("逐条目门阶段由覆盖度终门回填：P3→s5、A3→s4、B2→s4、V4→s5（av V3 仍不点 s5）", () => {
	const st = openStore(":memory:");
	assert.ok(autoStageFromGate(st, TAXONOMIES["pentest"], "ff-1", "pentest", "P3").includes("s5"), "P3 覆盖度门级联补齐 s5");
	assert.ok(autoStageFromGate(st, CA, "ff-2", "code-audit", "A3").includes("s4"), "A3 回填 s4");
	const b2 = autoStageFromGate(st, TAXONOMIES["binary-analysis"], "ff-3", "binary-analysis", "B2");
	assert.ok(b2.includes("s4") && !b2.includes("s3"), "B2 回填 s4；binary s3 条件性仍不回填");
	assert.ok(!autoStageFromGate(st, TAXONOMIES["av-evasion"], "ff-4", "av-evasion", "V3").includes("s5"), "av V3 逐实验配对门不点 s5");
	assert.ok(autoStageFromGate(st, TAXONOMIES["av-evasion"], "ff-4b", "av-evasion", "V4").includes("s5"), "V4 终门回填 s5");
	st.close();
});

import { taxonomyWithCaps } from "../lib/index.js";
await ok("cap forms 点亮：自定义主类/子类的适用形态并入合并类目（矩阵形态过滤对自定义格生效）", () => {
	const st = openStore(":memory:");
	const catKey = saveCap(st, { mode: "pentest", kind: "category", label: "自定义面", forms: "web,api" }).cat;
	saveCap(st, { mode: "pentest", kind: "item", cat: catKey, label: "自定义格", forms: "api,未知词" });
	const merged = taxonomyWithCaps(st, TAXONOMIES["pentest"], "pentest");
	const custCat = merged.categories.find((c) => c.id === catKey);
	assert.deepEqual(custCat.forms, ["web", "api"], "自定义主类 forms 解析为数组（未知词忽略）");
	assert.deepEqual(custCat.items[0].forms, ["api"], "自定义子项 forms 生效（供矩阵 item 形态过滤）");
	assert.ok((merged.formCategories.web || []).includes(catKey) && (merged.formCategories.api || []).includes(catKey), "自定义主类并入 formCategories（形态切换可见）");
	const again = taxonomyWithCaps(st, TAXONOMIES["pentest"], "pentest");
	assert.equal(merged.formCategories.web.length, again.formCategories.web.length, "重复合并不重复累积（内置数组不被污染）");
	st.close();
});

// ===== pentest：包含规则修正 / autoLight CWE 提取 / stage.mark 归一 / mode 白名单 / 换主类迁移 =====
await ok("包含规则修正：未授权→access/unauth（前缀优先）、越权→歧义拒、RCE 不再误中 sourcemap", () => {
	const T = TAXONOMIES.pentest;
	assert.equal(resolveKey(T, "未授权")?.key, "access/unauth", "前缀命中优先——不再被「LLM API 未授权…」最长包含抢走");
	const yq = resolveKey(T, "越权");
	assert.ok(yq?.ambiguous, "越权多命中同长（水平/垂直）——歧义拒报候选，不再静默选 openid 格");
	assert.ok(JSON.stringify(yq.ambiguous).includes("horiz"), "候选含水平越权");
	assert.equal(resolveKey(T, "RCE"), null, "短 ASCII 线索词边界匹配——「sourcemap」内嵌 rce 不再误报");
	assert.equal(resolveKey(T, "XSS")?.key, "injection/xss", "词边界命中的短线索照常工作");
});

await ok("autoLight：type 内嵌 CWE 一并提取（cwe 字段缺填不绕空）", async () => {
	const st = openStore(":memory:");
	const r = await autoLightFromFinding(null, st, "s-cwe", { type: "注入（CWE-89）", title: "注入点" }, { mode: "pentest", findFindingId: async () => "", followup: () => {} });
	assert.ok(r.marked.includes("injection/sqli"), "type 内嵌 CWE-89 点亮 SQL 注入格");
	st.close();
});

await ok("HTTP stage.mark 中文标签归一落库（与工具路径同规，校验/落库不再两套语义）", async () => {
	const st = openStore(":memory:");
	const stages = TAXONOMIES.pentest.stages;
	const last = stages[stages.length - 1];
	const r = await dispatch(null, st, "stage.mark", { sessionId: "s-st", mode: "pentest", stage: last.label, state: "done" });
	assert.equal(r.ok, true);
	const cov = getCoverage(st, "s-st", "pentest");
	assert.ok(cov.stages.some((s) => s.stage === last.id && s.state === "done"), "中文标签归一到 canonical id 落库");
	st.close();
});

await ok("mode 白名单：未知 mode 拒绝并报合法清单（不再落幽灵行）", async () => {
	const st = openStore(":memory:");
	await assert.rejects(() => dispatch(null, st, "coverage.get", { sessionId: "s-x", mode: "bogus" }), /未知模式 bogus/);
	st.close();
});

await ok("编辑自定义子类换主类：coverage 行随迁不留孤儿", async () => {
	const st = openStore(":memory:");
	const cat1 = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "category", label: "临时主类A" });
	const cat2 = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "category", label: "临时主类B" });
	const item = await dispatch(null, st, "caps.save", { mode: "pentest", kind: "item", cat: cat1.cat, label: "临时子类" });
	const oldKey = `${cat1.cat}/${item.item}`;
	markCell(st, "s-move", "pentest", oldKey, { state: "tested-found", reason: "x" });
	const moved = await dispatch(null, st, "caps.save", { id: item.id, mode: "pentest", kind: "item", cat: cat2.cat, label: "临时子类" });
	assert.equal(moved.cat, cat2.cat);
	const cov = getCoverage(st, "s-move", "pentest");
	const newKey = `${cat2.cat}/${item.item}`;
	assert.ok(cov.cells.some((c) => c.key === newKey), "终态行已随迁到新主类");
	assert.ok(!cov.cells.some((c) => c.key === oldKey), "旧 key 无孤儿行");
	st.close();
});

// ===== attack-defense 批：战果词别名 / 序号前缀剥离 / 链路互链 findingRef / 形态列完备 =====
await ok("ad 战果词别名全表：十个官方战果词全部点亮对应主类", () => {
	const ad = TAXONOMIES["attack-defense"];
	const cases = { "入口点": "entry-vec", "数据读取成果": "hv-target", "凭据·密码本": "cred-line", "哈希集(hash map)": "win-chain", "横向立足点": "lateral", "域控成果": "domain-attack", "Webshell 部署": "foothold", "持久化项": "persistence", "内网资产": "host-collect", "检测gap": "defense-verify" };
	for (const [w, cat] of Object.entries(cases)) assert.equal(resolveKey(ad, w)?.key, cat, `${w} 应别名点亮 ${cat}`);
});
await ok("序号前缀剥离：ad entry-vec 标签带序号，SQL/SSRF 词边界恢复命中", () => {
	const ad = TAXONOMIES["attack-defense"];
	assert.equal(resolveKey(ad, "SQL")?.key, "entry-vec/sqli");
	assert.equal(resolveKey(ad, "SSRF")?.key, "entry-vec/ssrf");
});
await ok("ad autoLight 端到端：官方战果词登记即点亮（不再零点亮、P3 不再哑火）", async () => {
	const st = openStore(":memory:");
	const r = await autoLightFromFinding(null, st, "s-ad", { type: "域控成果", title: "DC 权限落袋" }, { mode: "attack-defense", findFindingId: async () => "", followup: () => {} });
	assert.ok(r.marked.includes("domain-attack"), "域控成果 → domain-attack 主类");
	st.close();
});
await ok("链路互链：节点带 findingRef 往返 + chainRefIndex 反查（成果页互链行数据源）", () => {
	const st = openStore(":memory:");
	addChainNode(st, "s-l", "attack-defense", { id: "dc-01", label: "DC01", kind: "dc", major: true, findingRef: "attack-defense-3" });
	const chain = listChain(st, "s-l", "attack-defense");
	assert.equal(chain.nodes[0].findingRef, "attack-defense-3");
	const idx = chainRefIndex(st, "attack-defense");
	assert.ok(idx["s-l:attack-defense-3"] && idx["s-l:attack-defense-3"][0].nodeId === "dc-01" && idx["s-l:attack-defense-3"][0].major === 1, "反查索引键=会话:findingRef");
	st.close();
});
await ok("ad formCategories 完备：21 主类全部至少归属一个形态列（形态筛选不再漏类）", () => {
	const ad = TAXONOMIES["attack-defense"];
	const inForms = new Set(Object.values(ad.formCategories).flat());
	for (const c of ad.categories) assert.ok(inForms.has(c.id), `主类 ${c.id} 不在任何形态列`);
});

// ===== code-audit 批：CSRF fuzzy 闸 / 代审别名 / GATE_NO_FILL s3 / A1→s1 =====
await ok("CSRF 不再经 fuzzy 误点亮 ssrf（短 ASCII 线索禁走全局模糊）", () => {
	const ca = TAXONOMIES["code-audit"];
	assert.equal(resolveKey(ca, "CSRF"), null, "code-audit 无 CSRF 格——宁拒不误亮");
	assert.equal(resolveKey(TAXONOMIES.pentest, "XSS")?.key, "injection/xss", "pentest 词边界命中的短线索不受影响");
});
await ok("代审登记词别名：命令注入/文件包含/硬编码前端绕过/组件词全中格子级", () => {
	const ca = TAXONOMIES["code-audit"];
	assert.equal(resolveKey(ca, "命令注入")?.key, "sink-core/cmd");
	assert.equal(resolveKey(ca, "文件包含")?.key, "sink-core/file-rw");
	assert.equal(resolveKey(ca, "硬编码前端绕过")?.key, "rce-main/hardcoded-rce");
	assert.equal(resolveKey(ca, "fastjson")?.key, "rce-main/deep-deser");
	assert.equal(resolveKey(ca, "log4j")?.key, "rce-main/cve-patterns");
});
await ok("级联排除：code-audit A2 过门不点亮 s3 动态验证/s4 确证闭环（逐 finding 双链门）；A1=面映射出口点 s1", () => {
	const st = openStore(":memory:");
	const marked = autoStageFromGate(st, TAXONOMIES["code-audit"], "nf-ca", "code-audit", "A2");
	assert.ok(!marked.includes("s3"), "s3 动态验证不凭 A2 推定完成");
	assert.ok(!marked.includes("s4"), "s4 确证闭环不凭单 finding 双链过门（A2）推定完成");
	const a1 = autoStageFromGate(st, TAXONOMIES["code-audit"], "nf-ca", "code-audit", "A1");
	assert.deepEqual(a1, ["s1"], "A1=面映射（s1 出口）——不再把 s2 静态审计一并标 done");
	st.close();
});

// ===== cloud-security：战果词别名全表 / exfil 新格 / autoLight 端到端 =====
await ok("cloud 别名全表：官方 12 路径类型词+AK/SK 族+破歧义词全中", () => {
	const cl = TAXONOMIES["cloud-security"];
	const cases = {
		"凭证泄露利用": "entry-disc", "元数据服务": "entry-disc/imds", "对象存储": "deep-dig/bucket-public",
		"云数据库": "loot-order/data-face", "权限提升": "deep-dig/iam-deep", "K8s 集群": "k8s-line",
		"CI-CD": "cicd-line", "持久化": "persist-cloud", "AK/SK": "entry-disc/hardcoded-first",
		"AccessKey": "entry-disc/hardcoded-first", "子账号接管": "loot-order/ctrl-face", "IAM": "perm-recon",
		"Secret 泄露": "loot-order/secret-face", "OIDC": "trust-lateral/oidc", "数据外传": "loot-order/exfil"
	};
	for (const [w, k] of Object.entries(cases)) assert.equal(resolveKey(cl, w)?.key, k, `${w} 应别名点亮 ${k}`);
});
await ok("cloud exfil 语义格新增：loot-order/exfil 存在且 ref/pb 锚点有效", () => {
	const cl = TAXONOMIES["cloud-security"];
	const it = cl.categories.find((c) => c.id === "loot-order").items.find((i) => i.id === "exfil");
	assert.ok(it, "exfil 子项存在");
	assert.ok(it.pb || it.ref, "锚点非空");
});
await ok("cloud autoLight 端到端：官方词登记即点亮（CI-CD 错位/持久化落点修）", async () => {
	const st = openStore(":memory:");
	const r1 = await autoLightFromFinding(null, st, "s-cl1", { type: "CI-CD", title: "流水线接管" }, { mode: "cloud-security", findFindingId: async () => "", followup: () => {} });
	assert.ok(r1.marked.includes("cicd-line"), "CI-CD→cicd-line（不再被 hv-cloud/cicd-hv 抢走）");
	const r2 = await autoLightFromFinding(null, st, "s-cl2", { type: "凭证泄露利用", title: "AK 泄露" }, { mode: "cloud-security", findFindingId: async () => "", followup: () => {} });
	assert.ok(r2.marked.includes("entry-disc"), "凭证泄露利用→entry-disc");
	st.close();
});

// ===== ctf-solver：模块别名 + autoLight 端到端 =====
await ok("ctf 模块别名：成果页 type=模块主线词全中格子", () => {
	const ct = TAXONOMIES["ctf-solver"];
	assert.equal(resolveKey(ct, "web")?.key, "mod-core/web");
	assert.equal(resolveKey(ct, "pwn")?.key, "mod-core/pwn");
	assert.equal(resolveKey(ct, "rev")?.key, "mod-core/reverse");
	assert.equal(resolveKey(ct, "supply")?.key, "mod-eco/supply");
	assert.equal(resolveKey(ct, "supply-chain")?.key, "mod-eco/supply");
	assert.equal(resolveKey(ct, "ad")?.key, "mod-eco/ad-domain");
	assert.equal(resolveKey(ct, "ai-ml")?.key, "mod-core/ai-ml");
});
await ok("autoLight 端到端 ctf：type=web/pwn 点亮模块格（不再静默失效）", async () => {
	const st = openStore(":memory:");
	const r1 = await autoLightFromFinding(null, st, "al-ctf1", { title: "题-web", type: "web" }, { mode: "ctf-solver", findFindingId: async () => "" });
	assert.deepEqual(r1.marked, ["mod-core/web"]);
	const r2 = await autoLightFromFinding(null, st, "al-ctf2", { title: "题-pwn", type: "pwn" }, { mode: "ctf-solver", findFindingId: async () => "" });
	assert.deepEqual(r2.marked, ["mod-core/pwn"]);
	st.close();
});

// ===== incident-response：别名双轴桥 + autoLight 端到端（含纠偏断言） =====
await ok("IR 别名双轴桥：persona 链节点词+自然事件词全中，六错位词纠偏", () => {
	const ir = TAXONOMIES["incident-response"];
	assert.equal(resolveKey(ir, "入口点")?.key, "card-vuln/exp-anchor", "入口点→卡6 EXP 锚点");
	assert.equal(resolveKey(ir, "持久化")?.key, "compromise-check", "持久化→失陷排查主类（不再三格歧义拒）");
	assert.equal(resolveKey(ir, "横向")?.key, "spread-loop/five-dim", "横向→五维扩线（纠偏：原错位勒索卡前兆格）");
	assert.equal(resolveKey(ir, "横向移动")?.key, "spread-loop/five-dim");
	assert.equal(resolveKey(ir, "数据外传")?.key, "card-forensics/rebuild", "数据外传→行为重建（纠偏：原错位双勒索格）");
	assert.equal(resolveKey(ir, "处置清理")?.key, "remediation/checklist");
	assert.equal(resolveKey(ir, "勒索病毒")?.key, "card-ransom");
	assert.equal(resolveKey(ir, "挖矿木马")?.key, "compromise-check/backdoor");
	assert.equal(resolveKey(ir, "日志清除")?.key, "card-forensics/rebuild");
	assert.equal(resolveKey(ir, "暴力破解")?.key, "card-live/chain-ser");
	assert.equal(resolveKey(ir, "凭据窃取")?.key, "spread-loop/five-dim");
	assert.equal(resolveKey(ir, "提权")?.key, "chain-rebuild", "提权→攻击链还原（纠偏：原错位 webshell 伴随格）");
	assert.equal(resolveKey(ir, "失陷")?.key, "compromise-check", "失陷→失陷排查（纠偏：原错位云实例格）");
	assert.equal(resolveKey(ir, "IOC")?.key, "ioc-enrich", "IOC→IOC 富化（纠偏：原错位收敛格）");
	assert.equal(resolveKey(ir, "时间线")?.key, "timeline", "时间线→时间线还原主类（纠偏：原错位报告格）");
});
await ok("autoLight 端到端 IR：type=webshell 正常命中、type=横向 纠偏点亮", async () => {
	const st = openStore(":memory:");
	const r1 = await autoLightFromFinding(null, st, "al-ir1", { title: "主机A发现 webshell", type: "webshell" }, { mode: "incident-response", findFindingId: async () => "" });
	assert.deepEqual(r1.marked, ["compromise-check/webshell"]);
	const r2 = await autoLightFromFinding(null, st, "al-ir2", { title: "横向扩散节点", type: "横向" }, { mode: "incident-response", findFindingId: async () => "" });
	assert.deepEqual(r2.marked, ["spread-loop/five-dim"], "横向不再点亮 card-ransom/pre-lateral");
	st.close();
});

// ===== 链路边类型学：五型落库 / 未知回落 / 生成文案带类型词 =====
await ok("链路边类型学：edgeType 落库、未知回落未分类、chain-gen 文案带五型词", () => {
	const st = openStore(":memory:");
	addChainNode(st, "et-1", "attack-defense", { id: "web1", label: "边界 Web", kind: "entry" });
	addChainNode(st, "et-1", "attack-defense", { id: "dc1", label: "域控", kind: "dc", major: true });
	const e = addChainEdge(st, "et-1", "attack-defense", { src: "web1", dst: "dc1", label: "凭据复用", edgeType: "exploits" });
	assert.equal(e.edgeType, "exploits");
	const e2 = addChainEdge(st, "et-1", "attack-defense", { src: "web1", dst: "dc1", label: "旧边" });
	assert.equal(e2.edgeType, "", "缺省=未分类（旧调用兼容）");
	const e3 = addChainEdge(st, "et-1", "attack-defense", { src: "web1", dst: "dc1", label: "坏型", edgeType: "bogus" });
	assert.equal(e3.edgeType, "", "未知类型回落未分类（不抛错）");
	const list = listChain(st, "et-1", "attack-defense");
	assert.ok(list.edges.every((x) => "edgeType" in x), "listChain 返回 edgeType 字段");
	const msg = triggerMessage(TAXONOMIES["attack-defense"], { level: "chain-gen" });
	assert.match(msg, /discovered_on/);
	assert.match(msg, /edgeType/);
	st.close();
});


// ── MISS 缺口台账：未命中落库 + 聚合 + dispatch 端点（v1.1.4）──
await ok("recordMiss/missSummary：落库、聚合计数、频次降序、limit 生效", async () => {
	const st = openStore(":memory:");
	recordMiss(st, { mode: "pentest", kind: "cell", query: "注入/ORM 注入", error: "子项不存在", sessionId: "s1" });
	recordMiss(st, { mode: "pentest", kind: "cell", query: "注入/ORM 注入", error: "子项不存在", sessionId: "s2" });
	recordMiss(st, { mode: "ctf-solver", kind: "stage", query: "pwning", error: "阶段不存在", sessionId: "s3" });
	const sum = missSummary(st, {});
	assert.equal(sum.total, 3, "total=3");
	assert.equal(sum.rows[0].query, "注入/ORM 注入", "高频在前");
	assert.equal(sum.rows[0].n, 2, "同 query 聚合计数");
	assert.equal(sum.rows[0].last_at.length, 19, "最近时间字段");
	assert.equal(sum.rows[1].n, 1, "次频");
	assert.equal(missSummary(st, { limit: 1 }).rows.length, 1, "limit 生效");
	const viaDispatch = await dispatch(null, st, "misses.list", {});
	assert.equal(viaDispatch.total, 3, "dispatch misses.list");
	let threw = false;
	try { await dispatch(null, st, "misses.nope", {}); } catch { threw = true; }
	assert.ok(threw, "未知端点仍拒绝");
	// recordMiss 脏输入不炸（best-effort）
	recordMiss(st, {});
	assert.equal(missSummary(st, {}).total, 4, "脏输入静默落库不抛");
	st.close();
});

await ok("triggerMessage 模式语态：动词+要求句逐模式分化，机制原子八模式统一", async () => {
	const expect = {
		"incident-response": ["整组排查", "先保全后分析、只读优先", "证据指位与时间线位置"],
		"code-audit": ["整组审计", "扫描链禁网", "复现链与 sink 指位"],
		"binary-analysis": ["整组分析", "假设台账", "IOC 假设"],
		"av-evasion": ["整组实验", "experiment-plan 为基线", "判定环境与判定依据"],
		"ctf-solver": ["平台规则即边界", "challenge-board 同步"],
		pentest: ["整组开测", "已验·有发现", "速率与红线"],
		"attack-defense": ["整组开测", "速率与红线"],
		"cloud-security": ["整组开测", "速率与红线"]
	};
	for (const [mode, kws] of Object.entries(expect)) {
		const t = TAXONOMIES[mode];
		const cat = triggerMessage(t, { level: "category", categoryId: t.categories[0].id });
		for (const kw of kws) assert.ok(cat.includes(kw), `${mode} 缺「${kw}」`);
		assert.ok(cat.includes("终态三选一") && cat.includes("redteam_coverage_mark") && cat.includes("redteam_finding_register"), `${mode} 机制原子缺失`);
	}
});

await ok("triggerMessage 格子档：动词与姿势语态同步（audit 审计姿势禁网/IR 取证姿势排查）+ pentest 词表定制", async () => {
	const au = TAXONOMIES["code-audit"];
	const cell = triggerMessage(au, { level: "item", categoryId: au.categories[0].id, itemId: au.categories[0].items?.[0]?.id ?? "" });
	assert.ok(cell.includes("对以下格子审计") && cell.includes("审计姿势") && cell.includes("扫描链禁网"), "代审格子语态");
	const ir = TAXONOMIES["incident-response"];
	const irCell = triggerMessage(ir, { level: "item", categoryId: ir.categories[0].id, itemId: ir.categories[0].items?.[0]?.id ?? "" });
	assert.ok(irCell.includes("对以下格子排查") && irCell.includes("取证姿势"), "IR 格子语态");
	const pentestCat = triggerMessage(TAXONOMIES.pentest, { level: "category", categoryId: "hardcoded" });
	assert.ok(pentestCat.includes("已验·有发现") && !pentestCat.includes("已测·有发现"), "pentest 词表从默认已测定制为已验");
});

console.log(`\n${passed} passed`);
