// dsh-webshell-mgr HTTP 通道：node:http/https 直连（不用全局 fetch——需要自签证书放行、
// 精确超时与原始字节响应）。附带多字符集解码（utf-8/gbk/gb18030，TextDecoder 全 ICU）
// 与按连接的轻量 Cookie 罐（godzilla-mod 等会话通行证协议需要跨请求保持 Cookie）。

import http from "node:http";
import https from "node:https";
import { randomBytes, createHash } from "node:crypto";

const CHARSET_ALIASES = {
	"gb2312": "gbk",
	"gb18030": "gb18030",
	"gbk": "gbk",
	"utf-8": "utf-8",
	"utf8": "utf-8",
	"big5": "big5",
	"shift_jis": "shift_jis",
	"euc-jp": "euc-jp"
};

/** 解析响应字节 → 字符串。encoding 为 auto 时用 Content-Type charset，默认 utf-8。 */
export function decodeBody(buffer, encoding, contentType) {
	let enc = String(encoding ?? "auto").trim().toLowerCase();
	if (enc === "auto" || enc === "") {
		const m = /charset=([\w-]+)/i.exec(String(contentType ?? ""));
		enc = m ? CHARSET_ALIASES[m[1].toLowerCase()] ?? "utf-8" : "utf-8";
	}
	enc = CHARSET_ALIASES[enc] ?? "utf-8";
	try { return new TextDecoder(enc).decode(buffer); } catch { return buffer.toString("utf8"); }
}

/**
 * 单次 HTTP 请求。
 * @returns {Promise<{status:number, headers:object, bodyBuffer:Buffer}>}
 */
export function httpRequest({ url, method = "POST", headers = {}, body = null, timeoutMs = 20000 }) {
	return new Promise((resolve, reject) => {
		let target;
		try { target = new URL(url); } catch (e) { reject(new Error(`URL 无效：${url}`)); return; }
		const mod = target.protocol === "https:" ? https : http;
		const opts = {
			method,
			headers: { ...headers },
			timeout: Math.min(Math.max(Number(timeoutMs) || 20000, 1000), 180000)
		};
		let bodyBuf = null;
		if (body != null) {
			bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body);
			opts.headers["content-length"] = String(bodyBuf.length);
		}
		if (mod === https) opts.rejectUnauthorized = false; // webshell 目标常见自签/过期证书
		const req = mod.request(target, opts, (res) => {
			const chunks = [];
			res.on("data", (c) => chunks.push(c));
			res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, bodyBuffer: Buffer.concat(chunks) }));
			res.on("error", reject);
		});
		req.on("timeout", () => { req.destroy(new Error(`请求超时（${opts.timeout}ms）`)); });
		req.on("error", reject);
		if (bodyBuf != null) req.write(bodyBuf);
		req.end();
	});
}

/** 按连接的 Cookie 罐：Map<scopeKey, Map<name, value>>。scopeKey 用 conn.id 或 url。 */
const cookieJars = new Map();

export function cookieHeaderFor(scopeKey) {
	const jar = cookieJars.get(scopeKey);
	if (!jar) return "";
	const parts = [];
	for (const [name, value] of jar) parts.push(`${name}=${value}`);
	return parts.length ? parts.join("; ") : "";
}

export function absorbCookies(scopeKey, resHeaders) {
	const setCookies = resHeaders?.["set-cookie"];
	if (!setCookies) return;
	let jar = cookieJars.get(scopeKey);
	if (!jar) { jar = new Map(); cookieJars.set(scopeKey, jar); }
	for (const line of Array.isArray(setCookies) ? setCookies : [setCookies]) {
		const pair = String(line).split(";")[0];
		const eq = pair.indexOf("=");
		if (eq <= 0) continue;
		jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
	}
}

export function clearCookies(scopeKey) {
	cookieJars.delete(scopeKey);
}

// 密码学/编码工具（协议层共用）
export const randBytes = (n) => randomBytes(n);
export const b64 = (buf) => Buffer.from(buf).toString("base64");
export const unb64 = (s) => Buffer.from(String(s), "base64");
export const hex = (buf) => Buffer.from(buf).toString("hex");
export const md5hex = (s) => createHash("md5").update(Buffer.from(s, "utf8")).digest("hex");
export const md5raw = (s) => createHash("md5").update(Buffer.from(s, "utf8")).digest();
