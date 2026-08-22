// C2 流量伪装 profile：按连接定制请求头/UA 轮换/响应剖离。
// profile JSON：{ "uas": ["UA1","UA2"], "headers": {"X-Static":"v"}, "strip": ["前缀","后缀"] }
// —— uas 逐请求轮换（每 scope 计数）；headers 静态附加（低于连接显式 headers——可被覆盖）；
// strip 剖离响应首尾装饰（伪装页面外皮——剖离后再走标记/JSON 解析）。
// 存储于 connections.profile_json；空/非法 = 不启用（零开销直通）。

const counters = new Map(); // scope → UA 轮换计数

function parseProfile(conn) {
	const raw = conn?.profile_json ?? conn?.profileJson ?? "";
	if (!raw) return null;
	try {
		const p = JSON.parse(raw);
		if (!p || typeof p !== "object") return null;
		return p;
	} catch {
		return null;
	}
}

/** 请求头整形：附加 profile 头 + UA 轮换（连接显式 headers 优先——放在 spread 之后）。 */
export function shapeHeaders(conn, baseHeaders) {
	const p = parseProfile(conn);
	if (!p) return baseHeaders;
	const out = { ...baseHeaders };
	if (Array.isArray(p.headers) === false && p.headers && typeof p.headers === "object") {
		for (const [k, v] of Object.entries(p.headers)) {
			if (!(k.toLowerCase() in out)) out[k] = String(v);
		}
	}
	if (Array.isArray(p.uas) && p.uas.length > 0 && !("user-agent" in out) && !("User-Agent" in out)) {
		const scope = conn.__scope ?? conn.id ?? conn.url ?? "x";
		const n = counters.get(scope) ?? 0;
		counters.set(scope, n + 1);
		out["User-Agent"] = String(p.uas[n % p.uas.length]);
	}
	return out;
}

/** 响应剖离：strip [前缀, 后缀] 命中即剥（文本协议用）。 */
export function stripResponse(conn, text) {
	const p = parseProfile(conn);
	if (!p || !Array.isArray(p.strip) || p.strip.length !== 2) return text;
	const [pre, post] = p.strip;
	let t = text;
	if (pre && t.startsWith(pre)) t = t.slice(pre.length);
	if (post && t.endsWith(post)) t = t.slice(0, t.length - post.length);
	return t;
}

/** profile 有效性校验（连接保存时用）。 */
export function validateProfile(raw) {
	if (!raw || !String(raw).trim()) return { ok: true };
	try {
		const p = JSON.parse(raw);
		if (p && typeof p === "object" && !Array.isArray(p)) {
			if (p.uas !== undefined && !Array.isArray(p.uas)) throw new Error("uas 须为字符串数组");
			if (p.headers !== undefined && (typeof p.headers !== "object" || Array.isArray(p.headers))) throw new Error("headers 须为对象");
			if (p.strip !== undefined && (!Array.isArray(p.strip) || (p.strip.length !== 0 && p.strip.length !== 2))) throw new Error("strip 须为 [前缀, 后缀]（空数组=不剖离）");
			return { ok: true };
		}
		throw new Error("profile 须为 JSON 对象");
	} catch (e) {
		return { ok: false, error: `profile JSON 无效：${e.message}` };
	}
}
