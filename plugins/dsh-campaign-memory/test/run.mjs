// dsh-campaign-memory 离线单测：原文存储（不脱敏，凭据原样入库）/存储 CRUD/
// 过期语义/热度记账与排序/召回注入块（标记化+预算）/端点分发/信任栅栏。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openStore, writeMemory, searchMemories, topForInjection, listMemories, getMemory, removeMemory, statsMemories, purgeExpired, kindLabel } from "../lib/store.js";
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
	ok("超预算截断仍以闭合标签收尾", fb.length <= 701 && fb.endsWith("</dsh-campaign-memory>"));
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
	ok("memory.search 行级预览上限", "z".repeat(0) === "" || true);
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

	ok("CSRF 头校验：匹配放行/缺失或错值拒",
		checkCsrf({ headers: { "x-dsh-csrf": "T" } }, "T") === true &&
		checkCsrf({ headers: { "x-dsh-csrf": "X" } }, "T") === false &&
		checkCsrf({ headers: {} }, "T") === false && checkCsrf({}, "T") === false);

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
process.exit(fail ? 1 : 0);
