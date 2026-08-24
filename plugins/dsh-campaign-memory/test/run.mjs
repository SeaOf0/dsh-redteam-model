// dsh-campaign-memory 离线单测：原文存储（不脱敏，凭据原样入库）/存储 CRUD/
// 过期语义/热度记账与排序/召回注入块（标记化+预算）/端点分发/信任栅栏。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openStore, writeMemory, searchMemories, topForInjection, listMemories, getMemory, removeMemory, statsMemories, purgeExpired, kindLabel, MAX_ROWS_PER_WORKSPACE } from "../lib/store.js";
import { buildMemoryBlock, dispatch, isTrustedRequest, MODE_IDS, checkCsrf } from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

// 1. 原文存储：地址/指纹细节保真（打法价值所在），无任何转换
{
	const st = openStore(":memory:");
	const w = writeMemory(st, { mode: "pentest", kind: "fingerprint", title: "入口与跳板链", content: "入口 10.1.2.33 → 跳板 172.16.8.9，凭据在 webshell 连接库 ws-01，公网 8.8.8.8", workspace: "client-a" });
	const row = listMemories(st, { mode: "pentest" }).find((r) => r.id === w.id);
	ok("内网地址原文保真", row.content.includes("10.1.2.33") && row.content.includes("172.16.8.9"));
	ok("凭据走指位（存连接库引用）不落明文", row.content.includes("webshell 连接库 ws-01") && !/\b(password|token)\s*[:=]/i.test(row.content));
	st.close();
}

// 2. 写入语义：detect 默认 30 天过期并清理；fingerprint 默认 180 天；自定义天数；其余永久
{
	const st = openStore(":memory:");
	const det = writeMemory(st, { mode: "pentest", kind: "detect", title: "载荷 A 过 360 全家桶", content: "2026-08 实测通过" });
	ok("detect 默认过期时间已设", det.expires_at !== null);
	const fp = writeMemory(st, { mode: "pentest", kind: "fingerprint", title: "目标指纹", content: "x" });
	ok("fingerprint 默认 180 天时效", fp.expires_at !== null);
	const tac = writeMemory(st, { mode: "pentest", kind: "tactic", title: "打法", content: "内容" });
	ok("tactic 默认永久", tac.expires_at === null);
	const custom = writeMemory(st, { mode: "pentest", kind: "tactic", title: "短期", content: "x", expires_days: 7 });
	ok("自定义 7 天过期", custom.expires_at !== null);
	await assert.rejects(async () => writeMemory(st, { mode: "pentest", kind: "tactic", title: "", content: "x" }), /必填/);
	st.close();
}

// 3. 检索：LIKE 命中、类别过滤、检索不记账/读全文记账、热度×半衰排序、过期不召回（指纹例外带标记）
{
	const st = openStore(":memory:");
	writeMemory(st, { mode: "pentest", kind: "tactic", title: "XX 网关后台弱口令", content: "admin/admin123 直连", tags: "网关,弱口令" });
	writeMemory(st, { mode: "pentest", kind: "fingerprint", title: "某客户门户指纹", content: "portal 框架特征", target_kind: "web" });
	const old = writeMemory(st, { mode: "pentest", kind: "tactic", title: "过期打法", content: "已失效", expires_days: 1 });
	st.db.prepare("UPDATE memories SET expires_at = '2020-01-01 00:00:00' WHERE id = ?").run(old.id);
	const oldFp = writeMemory(st, { mode: "pentest", kind: "fingerprint", title: "老客户指纹", content: "老环境特征", expires_days: 1 });
	st.db.prepare("UPDATE memories SET expires_at = '2020-01-01 00:00:00' WHERE id = ?").run(oldFp.id);
	ok("过期记忆默认不列出", listMemories(st, { mode: "pentest" }).length === 2);
	ok("含已过期可列出（治理取舍）", listMemories(st, { mode: "pentest", includeExpired: true }).length === 4);
	const s1 = searchMemories(st, { mode: "pentest", query: "弱口令" });
	ok("关键词命中且检索不记账", s1.length === 1 && s1[0].title.includes("弱口令") && s1[0].usageCount === 0);
	getMemory(st, s1[0].id);
	const row = listMemories(st, { mode: "pentest" }).find((r) => r.id === s1[0].id);
	ok("读全文即记账（usage/last_used 落库）", row.usageCount === 1 && row.lastUsedAt !== "");
	const s2 = searchMemories(st, { mode: "pentest", query: "" });
	ok("读过的按热度排前", s2[0].title.includes("弱口令") && s2[0].usageCount === 1);
	const sf = searchMemories(st, { mode: "pentest", query: "", kind: "fingerprint" });
	ok("类别过滤（过期指纹仍命中带标记）", sf.length === 2 && sf.some((r) => r.expired) && sf.some((r) => !r.expired));
	ok("过期指纹命中带复活指引", searchMemories(st, { mode: "pentest", query: "老环境" })[0].content.includes("已过期"));
	ok("过期 tactic 不召回", searchMemories(st, { mode: "pentest", query: "失效" }).length === 0);
	ok("过期指纹不注入（退出自动召回）", topForInjection(st, "pentest", "", 3).every((r) => !r.expired));
	ok("模式隔离", searchMemories(st, { mode: "code-audit", query: "弱口令" }).length === 0);
	// 热度×30 天半衰：高热但久未读取 vs 新鲜低热——衰减后让位
	const hot = writeMemory(st, { mode: "pentest", kind: "tactic", title: "旧热打法", content: "x" });
	st.db.prepare("UPDATE memories SET usage_count = 8, last_used_at = '2026-05-01 00:00:00' WHERE id = ?").run(hot.id);
	const fresh = writeMemory(st, { mode: "pentest", kind: "tactic", title: "新打法", content: "y" });
	ok("时间衰减：90 天前高热让位新鲜记忆", searchMemories(st, { mode: "pentest", query: "打法" })[0].id === fresh.id);
	st.close();
}

// 4. 召回注入：工作区隔离（注入只带本工作区=新工作区干净开局）、不记账、预算截断
{
	const st = openStore(":memory:");
	writeMemory(st, { mode: "pentest", kind: "tactic", title: "T1", content: "内容一", workspace: "client-a" });
	writeMemory(st, { mode: "pentest", kind: "fingerprint", title: "T2", content: "内容二", workspace: "client-a" });
	writeMemory(st, { mode: "pentest", kind: "tactic", title: "他区记忆", content: "别的工作区", workspace: "client-b" });
	const block = buildMemoryBlock("pentest", "client-a", topForInjection(st, "pentest", "client-a", 3));
	ok("注入块带起止标记与模式/工作区属性", block.startsWith('<dsh-campaign-memory mode="pentest" workspace="client-a" n="2">') && block.endsWith("</dsh-campaign-memory>"));
	ok("注入只带本工作区（不跨客户串场）", block.includes("T1") && block.includes("T2") && !block.includes("他区记忆"));
	ok("新工作区注入为空（干净开局）", topForInjection(st, "pentest", "client-c", 3).length === 0 && buildMemoryBlock("pentest", "client-c", []) === "");
	ok("注入块含沉淀/检索指引与原文入库说明", block.includes("campaign_memory_write") && block.includes("campaign_memory_search") && block.includes("原样入库不脱敏"));
	ok("召回注入不记账（确定性）", listMemories(st, { mode: "pentest" }).every((r) => r.usageCount === 0));
	ok("空集返回空串", buildMemoryBlock("pentest", []) === "");
	const fb = buildMemoryBlock("pentest", "client-a", [{ kind: "tactic", title: "长记忆", content: "x".repeat(2000) }, { kind: "tactic", title: "更长", content: "y".repeat(2000) }]);
	ok("短集合不触发截断仍闭合收尾", fb.length <= 700 && fb.endsWith("</dsh-campaign-memory>"));
	// 真触发预算截断：10 条长行，断言硬上限、闭合标签、指引保留、n 同步
	const many = Array.from({ length: 10 }, (_, i) => ({ kind: "tactic", title: "超预算行" + i + "－" + "标题填充".repeat(12), content: "细节" + i + "：" + "z".repeat(90) }));
	const fb2 = buildMemoryBlock("pentest", "client-a", many);
	const nMatch = / n="(\d+)">/.exec(fb2);
	ok("预算截断硬上限 ≤700（修复 723 超限）", fb2.length <= 700 && fb2.endsWith("</dsh-campaign-memory>"));
	ok("截断先减记忆行：指引行保留、首行保留、n 同步实留行数", fb2.includes("campaign_memory_search") && fb2.includes("超预算行0") && !fb2.includes("超预算行9") && nMatch !== null && Number(nMatch[1]) < 10);
	ok("九模式名单齐", MODE_IDS.length === 9 && MODE_IDS.includes("redteam"));
	st.close();
}

// 5. 端点分发往返 + 统计/清理 + 信任栅栏
{
	const st = openStore(":memory:");
	const w = await dispatch(null, st, "memory.write", { mode: "pentest", kind: "tactic", title: "端点打法", content: "经端点写入原文 10.1.2.33", tags: "e2e" });
	ok("memory.write 原文落库", w.ok === true);
	const lst = await dispatch(null, st, "memory.list", { mode: "pentest" });
	ok("memory.list 返回原文", lst.memories.length === 1 && lst.memories[0].content.includes("10.1.2.33"));
	await dispatch(null, st, "memory.write", { mode: "pentest", kind: "lesson", title: "他区教训", content: "另一个工作区的经验", workspace: "client-b" });
	const sr = await dispatch(null, st, "memory.search", { mode: "pentest", query: "" });
	ok("memory.search 跨工作区命中并带来源标注", sr.memories.length === 2 && sr.memories.some((m) => m.workspace === "client-b"));
	const got = await dispatch(null, st, "memory.get", { id: w.id });
	ok("memory.get 返回全文", got.memory && got.memory.content.includes("10.1.2.33") && got.memory.content.length >= 10);
	const stat = await dispatch(null, st, "memory.stats", { mode: "pentest" });
	ok("memory.stats 计数", stat.stats.total === 2 && stat.stats.byKind.tactic === 1 && stat.stats.byKind.lesson === 1);
	await dispatch(null, st, "memory.remove", { id: w.id });
	await dispatch(null, st, "memory.remove", { id: (await dispatch(null, st, "memory.list", { mode: "pentest" })).memories.find((m) => m.workspace === "client-b").id });
	ok("memory.remove 删除后清零", (await dispatch(null, st, "memory.list", { mode: "pentest" })).memories.length === 0);
	await assert.rejects(() => dispatch(null, st, "memory.list", {}), /mode required/);

	ok("栅栏：loopback 放行、外域拒、跨源 Origin 拒",
		isTrustedRequest({ headers: { host: "127.0.0.1:3080" } }, []) === true &&
		isTrustedRequest({ headers: { host: "evil.com:3080" } }, []) === false &&
		isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://evil.com" } }, []) === false &&
		isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://127.0.0.1:9999" } }, []) === false && // 本机他端口 Origin 拒
		isTrustedRequest({ headers: { host: "127.0.0.1:3080", origin: "http://127.0.0.1:3080" } }, []) === true &&
		isTrustedRequest({}, []) === false);
	ok("kindLabel 中文标签", kindLabel("detect") === "检测指纹");
	// 检索预览截断：写入超长正文，search/list 返回带截断标记，get 拿全文
	const long = writeMemory(st, { mode: "pentest", kind: "tactic", title: "长打法", content: "A".repeat(3000) });
	const srLong = await dispatch(null, st, "memory.search", { mode: "pentest", query: "长打法" });
	ok("search 正文预览 ≤600 且带全文指引", srLong.memories[0].content.length <= 640 && srLong.memories[0].content.includes("campaign_memory_get"));
	const lstLong = await dispatch(null, st, "memory.list", { mode: "pentest" });
	const rowLong = lstLong.memories.find((m) => m.id === long.id);
	ok("list 正文预览 ≤200", rowLong.content.length <= 240);
	const gotLong = await dispatch(null, st, "memory.get", { id: long.id });
	ok("get 返回完整正文", gotLong.memory.content.length === 3000);
	await dispatch(null, st, "memory.remove", { id: long.id });
	st.close();
}

// 6. 记账落库（临时目录验证 write→get 的 last_used 落库）+ 清理只清过期检测指纹
{
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-"));
	const st = openStore(path.join(dir, "m.db"));
	const w = writeMemory(st, { mode: "av-evasion", kind: "detect", title: "免杀指纹", content: "载荷特征" });
	searchMemories(st, { mode: "av-evasion", query: "指纹" });
	ok("检索不记账", listMemories(st, { mode: "av-evasion" })[0].usageCount === 0);
	getMemory(st, w.id);
	const row = listMemories(st, { mode: "av-evasion" })[0];
	ok("读全文后 last_used_at 已落库", row.lastUsedAt !== "" && row.usageCount === 1);
	st.close();
	const st2 = openStore(path.join(dir, "m2.db"));
	const expDet = writeMemory(st2, { mode: "av-evasion", kind: "detect", title: "过期检测", content: "x", expires_days: 1 });
	const expFp = writeMemory(st2, { mode: "av-evasion", kind: "fingerprint", title: "过期指纹", content: "y", expires_days: 1 });
	st2.db.prepare("UPDATE memories SET expires_at = '2020-01-01 00:00:00' WHERE id IN (?, ?)").run(expDet.id, expFp.id);
	st2.close();
	const st3 = openStore(path.join(dir, "m2.db"));
	const after = listMemories(st3, { mode: "av-evasion", includeExpired: true });
	ok("开库自动清理只清过期检测指纹（指纹保留资产）", after.length === 1 && after[0].kind === "fingerprint");
	st3.close();
	fs.rmSync(dir, { recursive: true, force: true });
}

// 7. 同题刷新（写入查重）：同模式同工作区同题=更新而非新增；跨工作区同题各自独立；过期指纹同题重写复活
{
	const st = openStore(":memory:");
	const a = writeMemory(st, { mode: "pentest", kind: "tactic", title: "网关弱口令 打法", content: "v1", workspace: "client-a" });
	const b = writeMemory(st, { mode: "pentest", kind: "tactic", title: "网关弱口令打法", content: "v2 刷新", workspace: "client-a" });
	ok("同题（归一比较）刷新不新增", b.id === a.id && b.refreshed === true);
	const rows = listMemories(st, { mode: "pentest", includeExpired: true });
	ok("刷新后正文更新且不产生重复", rows.length === 1 && rows[0].content.startsWith("v2"));
	const c = writeMemory(st, { mode: "pentest", kind: "tactic", title: "网关弱口令打法", content: "别区", workspace: "client-b" });
	ok("跨工作区同题各自独立", c.id !== a.id && listMemories(st, { mode: "pentest", includeExpired: true }).length === 2);
	getMemory(st, a.id);
	const refreshed = writeMemory(st, { mode: "pentest", kind: "tactic", title: "网关弱口令打法", content: "v3", workspace: "client-a" });
	const rowA = listMemories(st, { mode: "pentest", includeExpired: true }).find((r) => r.id === a.id);
	ok("刷新保留热度", refreshed.id === a.id && rowA.usageCount === 1);
	const fpA = writeMemory(st, { mode: "pentest", kind: "fingerprint", title: "客户 X 指纹", content: "旧", workspace: "client-a", expires_days: 1 });
	st.db.prepare("UPDATE memories SET expires_at = '2020-01-01 00:00:00' WHERE id = ?").run(fpA.id);
	const fpB = writeMemory(st, { mode: "pentest", kind: "fingerprint", title: "客户 X 指纹", content: "新", workspace: "client-a" });
	ok("同题重写复活过期指纹（时效刷新）", fpB.id === fpA.id && listMemories(st, { mode: "pentest" }).some((r) => r.id === fpA.id));
	st.close();
}

// 8. 行数钳制与浏览不记账：search 默认 8 上限 20；list 默认 50 上限 200（token 收敛）；peek 读全文不记账
{
	const st = openStore(":memory:");
	for (let i = 0; i < 55; i++) writeMemory(st, { mode: "pentest", kind: "tactic", title: "限行检查" + i, content: "内容" + i });
	ok("search 行数默认 8", searchMemories(st, { mode: "pentest", query: "限行检查" }).length === 8);
	ok("search 行数上限 20", searchMemories(st, { mode: "pentest", query: "限行检查", limit: 99 }).length === 20);
	ok("list 默认 50（不再全量倾倒）", listMemories(st, { mode: "pentest" }).length === 50);
	ok("list 上限 200 可覆盖全量", listMemories(st, { mode: "pentest", limit: 200 }).length === 55);
	ok("peek 读全文不记账（Web 浏览不推高召回热度）", (() => { const row = listMemories(st, { mode: "pentest" })[0]; getMemory(st, row.id, { account: false }); return listMemories(st, { mode: "pentest" })[0].usageCount === 0; })());
	st.close();
}

// 9. 路径哈希隔离：同名目录不串场、移动目录=新 key 干净开局、无键行旧语义兼容
{
	const st = openStore(":memory:");
	writeMemory(st, { mode: "pentest", kind: "tactic", title: "打法A", content: "客户1的打法", workspace: "client-a", workspace_key: "client-a@11111111" });
	writeMemory(st, { mode: "pentest", kind: "tactic", title: "打法B", content: "客户2的打法", workspace: "client-a", workspace_key: "client-a@22222222" });
	writeMemory(st, { mode: "pentest", kind: "tactic", title: "旧库行", content: "无键旧行", workspace: "client-a" });
	ok("同名目录不同路径：注入按隔离键互不串场", topForInjection(st, "pentest", "client-a", 3, "client-a@11111111").every((r) => r.title === "打法A") && topForInjection(st, "pentest", "client-a", 3, "client-a@22222222").every((r) => r.title === "打法B"));
	ok("同题同 key 刷新（同名目录不误合并）", writeMemory(st, { mode: "pentest", kind: "tactic", title: "打法A", content: "v2", workspace: "client-a", workspace_key: "client-a@11111111" }).refreshed === true);
	ok("移动目录=新 key 干净开局；旧记忆跨工作区检索找回", topForInjection(st, "pentest", "client-a", 3, "client-a@33333333").length === 0 && searchMemories(st, { mode: "pentest", query: "打法A" }).length === 1);
	ok("旧语义兼容：无键调用只匹配无键行", topForInjection(st, "pentest", "client-a", 3).length === 1 && topForInjection(st, "pentest", "client-a", 3)[0].title === "旧库行");
	st.close();
}

// 10. 注入行 160 字符 / 多目标提示行 / 工作区总量上限冷淘汰
{
	const st = openStore(":memory:");
	const b160 = buildMemoryBlock("binary-analysis", "bin-a", [{ kind: "fingerprint", targetKind: "a1b2c3d4", title: "家族指纹", content: "x".repeat(400) }]);
	ok("注入行预览放宽至 160 字符（家族指纹/工具配方不再过短腰斩）", /x{160}/.test(b160) && !/x{161}/.test(b160) && b160.length <= 700);
	const two = buildMemoryBlock("cloud-security", "cw", [{ kind: "tactic", targetKind: "aliyun", title: "A", content: "a" }, { kind: "tactic", targetKind: "tencent", title: "B", content: "b" }]);
	const one = buildMemoryBlock("cloud-security", "cw", [{ kind: "tactic", targetKind: "aliyun", title: "A", content: "a" }]);
	ok("多目标工作区注入带提示行（单目标不带）", two.includes("多目标") && two.includes("target_kind") && !one.includes("多目标"));
	let last = null;
	for (let i = 0; i < MAX_ROWS_PER_WORKSPACE + 2; i++) last = writeMemory(st, { mode: "pentest", kind: "tactic", title: "上限行" + i, content: "c" + i, workspace: "cap-ws", workspace_key: "cap-ws@abcd1234" });
	const n = st.db.prepare("SELECT COUNT(*) AS n FROM memories WHERE mode = ? AND workspace = ?").get("pentest", "cap-ws").n;
	ok("工作区上限 400：超限冷淘汰至 400，新写行保留", n === MAX_ROWS_PER_WORKSPACE && last.evicted >= 1 && !!st.db.prepare("SELECT id FROM memories WHERE id = ?").get(last.id));
	writeMemory(st, { mode: "pentest", kind: "tactic", title: "另键位行", content: "x", workspace: "cap-ws", workspace_key: "cap-ws@zzzz9999" });
	ok("冷淘汰只动本键位行（另键位行不受影响）", st.db.prepare("SELECT COUNT(*) AS n FROM memories WHERE mode = ? AND workspace = ? AND workspace_key = ?").get("pentest", "cap-ws", "cap-ws@zzzz9999").n === 1);
	st.close();
}

// 11. 同题刷新带 target_kind 维度（同名题跨平台不互覆）
{
	const st = openStore(":memory:");
	writeMemory(st, { mode: "ctf-solver", kind: "tactic", title: "signin 题解套路", content: "平台A套路", target_kind: "platform-a", workspace: "ctf-ws", workspace_key: "ctf-ws@11111111" });
	const w2 = writeMemory(st, { mode: "ctf-solver", kind: "tactic", title: "signin 题解套路", content: "平台B套路", target_kind: "platform-b", workspace: "ctf-ws", workspace_key: "ctf-ws@11111111" });
	ok("同名题跨平台不互覆（同题判定带 target_kind 维度）", w2.refreshed === false);
	const w3 = writeMemory(st, { mode: "ctf-solver", kind: "tactic", title: "signin 题解套路", content: "平台A套路v2", target_kind: "platform-a", workspace: "ctf-ws", workspace_key: "ctf-ws@11111111" });
	ok("同题同平台刷新而非新增", w3.refreshed === true && w3.id !== w2.id);
	ok("两条共存", st.db.prepare("SELECT COUNT(*) AS n FROM memories WHERE mode = ?").get("ctf-solver").n === 2);
	st.close();
}

// 12. 应急溯源用例（案件号 target_kind 隔离 + 写入读回）
{
	const st = openStore(":memory:");
	writeMemory(st, { mode: "incident-response", kind: "fingerprint", title: "银狐家族指纹", content: "特征串 abc", target_kind: "case-2026-01", workspace: "ir-ws", workspace_key: "ir-ws@11111111" });
	const w2 = writeMemory(st, { mode: "incident-response", kind: "tactic", title: "webshell 排查配方", content: "时间窗+内容特征定位", target_kind: "case-2026-02", workspace: "ir-ws", workspace_key: "ir-ws@11111111" });
	ok("IR 多案件同目录不互覆（案件号维度）", w2.refreshed === false);
	ok("IR 按 target_kind 过滤检索", searchMemories(st, { mode: "incident-response", query: "银狐", target_kind: "case-2026-01" }).length === 1);
	const top = topForInjection(st, "incident-response", "ir-ws", 3, "ir-ws@11111111");
	ok("IR 注入行带案件标注（多目标提示触发）", top.length === 2 && top.some((r) => r.targetKind === "case-2026-01"));
	st.close();
}

	ok("CSRF 头校验：匹配放行/缺失或错值拒",
		checkCsrf({ headers: { "x-dsh-csrf": "T" } }, "T") === true &&
		checkCsrf({ headers: { "x-dsh-csrf": "X" } }, "T") === false &&
		checkCsrf({ headers: {} }, "T") === false && checkCsrf({}, "T") === false);

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
process.exit(fail ? 1 : 0);
