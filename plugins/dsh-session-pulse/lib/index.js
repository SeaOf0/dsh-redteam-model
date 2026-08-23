// dsh-session-pulse — 会话状态面板宿主插件（九模式）。
//
// 服务端极薄：唯一职责是 session.mode 端点——列表源的 agentPreset 在宿主重启后会
// 退化为组合名，客户端门控拿不准时问一次真相（agents 注册表 → composedPreset，
// 与 AttackAtlas 的 session.mode 同款双源解析）。进度/子代理目录/提示词全部由
// 客户端直读宿主运行时（todos 投影、subagentsByParent 目录、chat 快照），不经本通道。

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import os from "node:os";
import zlib from "node:zlib";
import { PULSE_MODES, parseTranscript } from "./pulse.js";

const name = "dsh-session-pulse";
const inject = ["webServer", "webRuntime", "agentPresets"];

const ROUTE_PATH = "/dsh-session-pulse";
/** 进程级 CSRF token：GET <route>/csrf 由同源页取走（跨源响应不可读），POST 须回带 x-dsh-csrf 头。 */
const CSRF_TOKEN = crypto.randomBytes(24).toString("hex");
export function checkCsrf(req, token) {
	return String(req?.headers?.["x-dsh-csrf"] ?? "") === String(token ?? "");
}
const MAX_BODY = 1024 * 1024;
const SESSIONS_ROOT = () => path.join(os.homedir(), ".dsh", "sessions");
const SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9-]{7,63}$/;

/** 多帧 zstd 会话日志全量解压（宿主每次落盘一个独立帧，单帧 API 只解第一帧）。 */
function decompressFrames(buf) {
	const parts = [];
	for (let i = 0; i + 4 <= buf.length; i++) {
		if (buf[i] === 0x28 && buf[i + 1] === 0xB5 && buf[i + 2] === 0x2F && buf[i + 3] === 0xFD) {
			try { parts.push(zlib.zstdDecompressSync(buf.subarray(i))); } catch { /* 帧内魔法误命中，跳过 */ }
		}
	}
	return Buffer.concat(parts).toString("utf8");
}

/**
 * 子代理运行内容转写：定位 ~/.dsh/sessions 下的 <工作区目录>/<sessionId>/session.jsonl.zstd 并提取。
 * sessionId 只作目录名匹配（白名单字符），解析后仍校验父目录确为会话根——无路径穿越面。
 */
export function subagentTranscript(sessionId, sessionsRoot) {
	const sid = String(sessionId ?? "");
	if (!SESSION_ID_RE.test(sid)) throw new Error("sessionId 非法");
	const root = sessionsRoot ?? SESSIONS_ROOT();
	for (const dir of fs.readdirSync(root, { withFileTypes: true })) {
		if (!dir.isDirectory()) continue;
		const file = path.join(root, dir.name, sid, "session.jsonl.zstd");
		let stat;
		try { stat = fs.statSync(file); } catch { continue; }
		if (!stat.isFile() || stat.size > 64 * 1024 * 1024) continue;
		const resolved = path.resolve(path.dirname(file));
		if (path.dirname(resolved) !== path.resolve(root, dir.name)) throw new Error("路径越界");
		return { sessionId: sid, entries: parseTranscript(decompressFrames(fs.readFileSync(file))) };
	}
	throw new Error(`会话日志不存在：${sid}`);
}

function hostOf(headers) {
	const h = headers?.host;
	return typeof h === "string" ? h : "";
}
function isLoopbackHostname(hostname) {
	if (hostname === "localhost" || hostname === "[::1]") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}
export function isTrustedRequest(req, trustedHosts) {
	const host = hostOf(req.headers);
	if (host === "") return false;
	let hostUrl;
	try { hostUrl = new URL(`http://${host}`); } catch { return false; }
	const okHost = isLoopbackHostname(hostUrl.hostname) || (trustedHosts ?? []).some((t) => {
		try { return new URL(`http://${t}`).hostname === hostUrl.hostname; } catch { return false; }
	});
	if (!okHost) return false;
	const origin = req.headers?.origin;
	if (typeof origin === "string" && origin !== "null") {
		try {
			const originUrl = new URL(origin);
			if (originUrl.host !== hostUrl.host) return false; // 含端口：本机他端口页面的 Origin 不放行
		} catch { return false; }
	}
	return true;
}

function resolveAgents(ctx) {
	try { return ctx.get("agents"); } catch { /* 该 fiber 未声明 agents */ }
	try { return ctx.agents; } catch { /* 同上 */ }
	return undefined;
}

/** 通道端点分发（纯逻辑，供路由与测试复用）。 */
export async function dispatch(ctx, endpoint, payload) {
	const p = payload ?? {};
	if (endpoint === "session.mode") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const agents = resolveAgents(ctx);
		const agent = agents?.get?.(sessionId);
		let mode = "";
		try { mode = String(ctx.agentPresets?.composedPreset?.(agent.ctx) ?? ""); } catch { /* 组合未就绪 */ }
		if (!PULSE_MODES.includes(mode)) {
			const header = agent?.session?.header?.agentPreset;
			mode = PULSE_MODES.includes(header) ? header : "";
		}
		return { mode };
	}
	if (endpoint === "subagent.transcript") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return subagentTranscript(sessionId);
	}
	throw new Error(`unknown endpoint ${endpoint}`);
}

function apply(ctx) {
	const trustedHosts = () => {
		try { return ctx.webRuntime?.trustedHosts ?? []; } catch { return []; }
	};
	ctx.effect(() => ctx.webServer.register({
		kind: "prefix",
		path: ROUTE_PATH,
		handler: async (req, res) => {
			const send = (code, body) => {
				const text = JSON.stringify(body);
				res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
				res.end(text);
			};
			if (!isTrustedRequest(req, trustedHosts())) { res.writeHead(403); res.end("forbidden"); return; }
			let csrfPath = "";
			try { csrfPath = new URL(req.url ?? "/", "http://x").pathname; } catch { csrfPath = ""; }
			if (req.method === "GET" && csrfPath === ROUTE_PATH + "/csrf") { send(200, { token: CSRF_TOKEN }); return; }
			if (req.method !== "POST") { res.writeHead(405); res.end("method not allowed"); return; }
			if (!checkCsrf(req, CSRF_TOKEN)) { res.writeHead(403); res.end("csrf token missing or invalid"); return; }
			let endpoint = "";
			try { endpoint = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname.slice(ROUTE_PATH.length)).replace(/^\/+/, ""); } catch { endpoint = ""; }
			if (endpoint === "") { res.writeHead(404); res.end("not found"); return; }
			try {
				const raw = await new Promise((resolve, reject) => {
					let size = 0;
					const chunks = [];
					req.on("data", (c) => {
						size += c.length;
						if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); return; }
						chunks.push(c);
					});
					req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
					req.on("error", reject);
				});
				const payload = raw === "" ? {} : JSON.parse(raw);
				const result = await dispatch(ctx, endpoint, payload);
				send(200, result);
			} catch (e) {
				send(400, { ok: false, error: e?.message ?? String(e) });
			}
		}
	}), "dsh-session-pulse: web route");
}

export { PULSE_MODES, ROUTE_PATH, apply, inject, name };
