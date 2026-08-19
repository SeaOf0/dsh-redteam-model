// dsh-hunter 离线单测：DSL 解析与平台转换 / 去重合并 / 指纹节解析 / L0 指纹匹配 /
// L1 授权验证 / 流水线（mock 搜索与探测）/ 放宽寻源阶梯 / 配置视图与存储。
import assert from "node:assert";
import { parseDsl, buildQueries, mergeAssets, fofaGuard, LIMITS } from "../lib/adapters.js";
import { parseFingerprint, fingerprintQuery, fingerprintLadder, searchWithRelax, fingerprintMatches, verifyPipeline } from "../lib/verify.js";
import { openHunterStore, configView, getKey } from "../lib/store.js";

let pass = 0, fail = 0;
// 异步用例必须等待完成后再计数，否则断言未执行就被进程退出（假绿）。
async function ok(name, fn) {
	try { await fn(); pass++; console.log("ok   " + name); }
	catch (e) { fail++; console.log("FAIL " + name + "\n     " + (e?.message ?? e)); }
}

// 1. DSL 解析
await ok("dsl 解析多字段", () => {
	const f = parseDsl('title:"login page" body:xxl-job port:8080 protocol:"http"');
	assert.equal(f.get("title"), "login page");
	assert.equal(f.get("body"), "xxl-job");
	assert.equal(f.get("port"), "8080");
	assert.equal(f.get("protocol"), "http");
});
await ok("dsl 未知字段抛错", () => {
	assert.throws(() => parseDsl('foo:"bar"'), /未知字段/);
});
await ok("dsl 空输入抛错", () => {
	assert.throws(() => parseDsl("   "), /查询为空/);
});
await ok("dsl 无解析片段抛错", () => {
	assert.throws(() => parseDsl("hello world"), /未识别到任何/);
});

// 2. 平台转换
await ok("转换：FOFA/Hunter/Quake 语法差异", () => {
	const q = buildQueries('title:"login" app:"Nginx" port:8080', "dsl");
	assert.ok(q.fofa.includes('title="login"') && q.fofa.includes('app="Nginx"') && q.fofa.includes(" && "));
	assert.ok(q.hunter.includes('web.title="login"') && q.hunter.includes('app.name="Nginx"') && q.hunter.includes('ip.port="8080"'));
	assert.ok(q.quake.includes('title:"login"') && q.quake.includes('app:"Nginx"') && q.quake.includes('port:"8080"'));
});
await ok("转换：native 模式直贴", () => {
	const q = buildQueries('title="x" && port="80"', "native");
	assert.equal(q.fofa, 'title="x" && port="80"');
	assert.equal(q.hunter, 'title="x" && port="80"');
});
await ok("蜜罐过滤附加", () => {
	assert.ok(fofaGuard('app="Nginx"').includes("is_honeypot=false"));
});
await ok("限额常量", () => {
	assert.equal(LIMITS.fofa.freeExport, 10000);
	assert.ok(LIMITS.fofa.nextSize >= 1000);
	assert.equal(LIMITS.hunter.pageSize, 100);
});

// 3. 去重合并
await ok("merge：ip:port 去重，冲突取时间新者", () => {
	const a = [{ ip: "1.1.1.1", port: "80", title: "旧标题", time: "2025-01-01", platform: "fofa" }];
	const b = [{ ip: "1.1.1.1", port: "80", title: "新标题", time: "2025-06-01", platform: "hunter" }];
	const m = mergeAssets(a, b);
	assert.equal(m.length, 1);
	assert.equal(m[0].title, "新标题");
	assert.deepEqual(m[0].platforms, ["fofa", "hunter"]);
});

// 4. 指纹节解析
await ok("指纹节与 L1 验证节解析", () => {
	const fp = parseFingerprint(`指纹:framework=xxl-job,version=2.4.0,title="任务调度中心",body="XXL-JOB"\nL1验证:GET /toLogin 期望:任务调度中心`);
	assert.equal(fp.fields.get("framework"), "xxl-job");
	assert.equal(fp.fields.get("title"), "任务调度中心");
	assert.equal(fp.l1.method, "GET");
	assert.equal(fp.l1.path, "/toLogin");
	assert.equal(fp.l1.expect, "任务调度中心");
});
await ok("无指纹节返回空字段", () => {
	const fp = parseFingerprint("普通 poc 文本");
	assert.equal(fp.fields.size, 0);
	assert.equal(fp.l1, null);
});
await ok("指纹生成查询（title/body 特征）", () => {
	const fp = parseFingerprint('指纹:title="任务调度中心",body="XXL-JOB"');
	assert.equal(fingerprintQuery(fp), 'title:"任务调度中心" body:"XXL-JOB"');
});
await ok("指纹仅 framework 时兜底 app 查询", () => {
	const fp = parseFingerprint("指纹:framework=xxl-job");
	assert.equal(fingerprintQuery(fp), 'app:"xxl-job"');
});

// 5. L0 指纹匹配
await ok("L0：title 特征命中", () => {
	const fp = parseFingerprint('指纹:title="任务调度中心"');
	const probe = { title: "任务调度中心 v2.4", bodyPrefix: "", server: "" };
	assert.deepEqual(fingerprintMatches(probe, fp), { match: true, kind: "title", value: "任务调度中心" });
});
await ok("L0：body 特征命中", () => {
	const fp = parseFingerprint('指纹:body="XXL-JOB"');
	const probe = { title: "", bodyPrefix: "<html>XXL-JOB admin</html>", server: "" };
	assert.equal(fingerprintMatches(probe, fp).match, true);
});
await ok("L0：特征均未命中", () => {
	const fp = parseFingerprint('指纹:title="任务调度中心"');
	const probe = { title: "别的系统", bodyPrefix: "", server: "" };
	assert.equal(fingerprintMatches(probe, fp).match, false);
});

// 6. 流水线（mock 搜索 + 假探测：用 stopOnFirstL0=false 统计，验证分级与停止）
const makeAsset = (ip, port, title) => ({ ip, port, title, protocol: "http", platform: "fofa", host: ip });
await ok("流水线：无资产 → no-assets + 建议", async () => {
	const r = await verifyPipeline(async () => [], async () => new Set(), { fingerprint: parseFingerprint('指纹:title="x"') });
	assert.equal(r.verdict, "no-assets");
	assert.ok(r.suggestions.length >= 3);
});
await ok("流水线：L0 成立未授权 → 建议含渗透模式交接路径（不做死路拒绝）", async () => {
	const http = await import("node:http");
	const server = http.createServer((req, res) => { res.end("<html><head><title>调度中心</title></head></html>"); });
	await new Promise((r) => server.listen(0, "127.0.0.1", r));
	const assets = [makeAsset("127.0.0.1", String(server.address().port))];
	const r = await verifyPipeline(async () => assets, async () => new Set(), { fingerprint: parseFingerprint('指纹:title="调度中心"'), budget: 1 });
	assert.equal(r.verdict, "l0-confirmed");
	assert.ok(r.suggestions.some((s) => s.includes("渗透测试模式")), "建议须含渗透模式路径");
	assert.ok(r.suggestions.some((s) => s.includes("标记授权")), "建议须保留标记授权快验路径");
	await new Promise((r2) => server.close(r2));
});
await ok("流水线：搜索抛错 → search-error", async () => {
	const r = await verifyPipeline(async () => { throw new Error("401: key invalid"); }, async () => new Set(), { fingerprint: parseFingerprint('指纹:title="x"') });
	assert.equal(r.verdict, "search-error");
	assert.ok(r.detail.includes("401"));
});
await ok("流水线：L0 成立（真实探测 localhost HTTP）", async () => {
	// 本地起一个 HTTP 服务充当“存活且指纹一致”的资产（真实探测路径）
	const http = await import("node:http");
	const server = http.createServer((req, res) => {
		res.setHeader("server", "test-srv");
		res.end("<html><head><title>任务调度中心</title></head><body>XXL-JOB</body></html>");
	});
	await new Promise((r) => server.listen(0, "127.0.0.1", r));
	const port = server.address().port;
	const fp = parseFingerprint('指纹:title="任务调度中心"');
	const assets = [makeAsset("127.0.0.1", String(port)), makeAsset("10.0.0.9", "80")];
	const r = await verifyPipeline(async () => assets, async () => new Set(), { fingerprint: fp, budget: 2 });
	assert.equal(r.verdict, "l0-confirmed");
	assert.equal(r.detail.l0Hits, 1);
	assert.ok(r.detail.firstL0.title.includes("任务调度中心"));
	await new Promise((r2) => server.close(r2));
});
await ok("流水线：授权资产 L1 通过 → l1-passed 且立即停", async () => {
	const http = await import("node:http");
	const server = http.createServer((req, res) => {
		res.setHeader("server", "s");
		if (req.url.startsWith("/toLogin")) { res.end("任务调度中心 VERIFY_7f3a9c"); return; }
		res.end("<html><head><title>任务调度中心</title></head><body>x</body></html>");
	});
	await new Promise((r) => server.listen(0, "127.0.0.1", r));
	const port = server.address().port;
	const fp = parseFingerprint('指纹:title="任务调度中心"\nL1验证:GET /toLogin 期望:VERIFY_7f3a9c');
	const assets = [makeAsset("127.0.0.1", String(port)), makeAsset("127.0.0.1", String(port))];
	const authorized = new Set([`127.0.0.1:${port}`]);
	const r = await verifyPipeline(async () => assets, async () => authorized, { fingerprint: fp, budget: 2 });
	assert.equal(r.verdict, "l1-passed");
	assert.equal(r.detail.l1Passed, 1);
	assert.ok(r.detail.stoppedEarly);
	await new Promise((r2) => server.close(r2));
});
await ok("流水线：未授权资产不做 L1（L0 成立但 L1=0）", async () => {
	const http = await import("node:http");
	const server = http.createServer((req, res) => {
		res.setHeader("server", "s");
		if (req.url.startsWith("/toLogin")) { res.end("VERIFY_7f3a9c"); return; }
		res.end("<html><head><title>任务调度中心</title></head></html>");
	});
	await new Promise((r) => server.listen(0, "127.0.0.1", r));
	const port = server.address().port;
	const fp = parseFingerprint('指纹:title="任务调度中心"\nL1验证:GET /toLogin 期望:VERIFY_7f3a9c');
	const r = await verifyPipeline(async () => [makeAsset("127.0.0.1", String(port))], async () => new Set(), { fingerprint: fp, budget: 1 });
	assert.equal(r.verdict, "l0-confirmed");
	assert.equal(r.detail.l1Passed, 0, "未授权资产绝不执行 L1");
	await new Promise((r2) => server.close(r2));
});
await ok("流水线：全部不匹配 → l0-none + 检查建议", async () => {
	const http = await import("node:http");
	const server = http.createServer((req, res) => { res.end("<html><title>别的系统</title></html>"); });
	await new Promise((r) => server.listen(0, "127.0.0.1", r));
	const port = server.address().port;
	const fp = parseFingerprint('指纹:title="任务调度中心"');
	const r = await verifyPipeline(async () => [makeAsset("127.0.0.1", String(port))], async () => new Set(), { fingerprint: fp, budget: 1 });
	assert.equal(r.verdict, "l0-none");
	assert.ok(r.suggestions.length >= 3);
	await new Promise((r2) => server.close(r2));
});

// 7. hunter store
await ok("hunter store：配置视图不回传完整 key", () => {
	const st = openHunterStore(":memory:");
	st.setKey.run("fofa", "abcdef1234567890", "2026-01-01T00:00:00.000Z");
	const view = configView(st);
	assert.equal(view.fofa.configured, true);
	assert.equal(view.fofa.tail, "…7890");
	assert.ok(!JSON.stringify(view).includes("abcdef1234567890"));
	assert.equal(getKey(st, "fofa"), "abcdef1234567890", "插件内部可读完整 key");
	st.close();
});
	await ok("hunter store：历史与授权白名单", () => {
		const st = openHunterStore(":memory:");
		st.insertHistory.run("2026-01-01T00:00:00Z", "code-audit-1", "code-audit", 'title:"x"', "fofa,hunter", "l0-confirmed", "{}");
		assert.equal(st.listHistory.all(10).length, 1);
		st.authorize.run("1.2.3.4:80", "测试资产", "2026-01-01T00:00:00Z");
		assert.equal(st.listAuthorized.all().length, 1);
		st.unauthorize.run("1.2.3.4:80");
		assert.equal(st.listAuthorized.all().length, 0);
		st.close();
	});

// 7. 互联网侧寻源（放宽阶梯）
await ok("阶梯：全特征有序且框架兜底在末", () => {
	const l = fingerprintLadder(parseFingerprint('指纹:framework=xxl-job,title="任务调度中心",body="XXL-JOB",header="xxl"'));
	assert.equal(l.length, 5);
	assert.equal(l[0].label, "特征组合");
	assert.equal(l[0].query, 'title:"任务调度中心" body:"XXL-JOB" header:"xxl"');
	assert.equal(l[4].label, "框架名兜底");
	assert.equal(l[4].query, 'app:"xxl-job"');
});
await ok("阶梯：单一特征不出重复级", () => {
	const l = fingerprintLadder(parseFingerprint('指纹:title="abc"'));
	assert.equal(l.length, 1);
	assert.equal(l[0].query, 'title:"abc"');
});
await ok("放宽寻源：主查询零命中→放宽级命中并衔接", async () => {
	const calls = [];
	const r = await searchWithRelax(
		async (q) => { calls.push(q); return q === 'title:"调度中心"' ? [] : [makeAsset("1.2.3.4", "80", "x")]; },
		fingerprintLadder(parseFingerprint('指纹:framework=xxl-job,title="调度中心"'))
	);
	assert.equal(r.assets.length, 1);
	assert.equal(r.hit.label, "框架名兜底");
	assert.equal(calls.length, 2);
});
await ok("放宽寻源：全部零命中→空+null（衔接 no-assets 建议）", async () => {
	const r = await searchWithRelax(async () => [], fingerprintLadder(parseFingerprint('指纹:title="x"')));
	assert.equal(r.assets.length, 0);
	assert.equal(r.hit, null);
});

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
process.exit(fail ? 1 : 0);
