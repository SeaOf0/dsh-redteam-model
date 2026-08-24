// dsh-hunter「hunter狩猎」宿主插件：
//   1) Web 通道：/dsh-hunter 前缀路由（同源信任栅栏）——设置/查询/导出/实测/历史 RPC；
//   2) 存储：独立 SQLite ~/.dsh/hunter/hunter.db（API key + 实测历史 + 授权白名单）；
//   3) 实测流水线：读 redteam-results 同一 results.db 取 finding → 指纹搜索 → 存活探测 →
//      L0/L1 分级验证 → 回写 retestNote/evidence/status + 历史 + 会话 followup 通知。
//
// 授权边界：互联网资产仅 L0（GET 首页+指纹）；L1 最小影响验证
// 仅对用户标记授权的资产；L2 完整 EXP 不做。

import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { openHunterStore, configView, getKey, nowIso } from "./store.js";
import { buildQueries, searchFofaPage, searchHunterPage, searchQuakePage, mergeAssets, fofaGuard, LIMITS, daysAgoStamp, nowStamp } from "./adapters.js";
import { parseFingerprint, fingerprintQuery, fingerprintLadder, searchWithRelax, verifyPipeline, SEARCH_BUDGET } from "./verify.js";
import { openStore as openResultsStore, getFinding, updateFinding } from "@dsh-external/dsh-redteam-results/store";

const name = "dsh-hunter";
const inject = ["webServer", "webRuntime"];

const ROUTE_PATH = "/dsh-hunter";
/** 进程级 CSRF token：GET <route>/csrf 由同源页取走（跨源响应不可读），POST 须回带 x-dsh-csrf 头。 */
const CSRF_TOKEN = crypto.randomBytes(24).toString("hex");
export function checkCsrf(req, token) {
	return String(req?.headers?.["x-dsh-csrf"] ?? "") === String(token ?? "");
}
const DB_PATH = path.join(os.homedir(), ".dsh", "hunter", "hunter.db");
const RESULTS_DB_PATH = path.join(os.homedir(), ".dsh", "redteam-results", "results.db");

let store;
function theStore() {
	if (store === undefined) store = openHunterStore(DB_PATH);
	return store;
}
let resultsStore;
function theResultsStore() {
	if (resultsStore === undefined) resultsStore = openResultsStore(RESULTS_DB_PATH);
	return resultsStore;
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		req.on("data", (c) => chunks.push(c));
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
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

/** 同源信任栅栏：Host 是本机/受信授权，且 Origin（浏览器跨站标记）与 Host 同源。 */
function isTrustedRequest(req, trustedHosts) {
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

/** 各平台 key 已配置清单 + 并发搜索。 */
async function runSearch(p, st) {
	const query = String(p.query ?? "").trim();
	if (!query) throw new Error("查询为空");
	const mode = p.mode === "native" ? "native" : "dsl";
	const queries = buildQueries(query, mode);
	const size = Math.min(Number(p.size) || SEARCH_BUDGET, 500);
	const jobs = [];
	const push = (platform, fn) => {
		const key = getKey(st, platform);
		if (!key) return;
		jobs.push(fn(key).then((rows) => ({ platform, rows })).catch((e) => ({ platform, rows: [], error: String(e?.message ?? e) })));
	};
	push("fofa", (key) => searchFofaPage(key, fofaGuard(queries.fofa), size).then((r) => r.rows.map((x) => x).slice(0, size)));
	push("hunter", (key) => searchHunterPage(key, queries.hunter, 1, Math.min(size, LIMITS.hunter.pageSize)).then((r) => r.rows.slice(0, size)));
	push("quake", (key) => searchQuakePage(key, queries.quake, 0, Math.min(size, LIMITS.quake.pageSize)).then((r) => r.rows.slice(0, size)));
	if (jobs.length === 0) throw new Error("未配置任何平台 API——先点右上角设置配置 FOFA/Hunter/Quake 至少一个");
	const results = await Promise.all(jobs);
	const errors = results.filter((r) => r.error);
	const rowsByPlatform = results.map((r) => normalizeRows(r.platform, r.rows));
	const assets = mergeAssets(...rowsByPlatform);
	return {
		queries,
		assets,
		platformErrors: errors.map((r) => ({ platform: r.platform, error: r.error })),
		configuredPlatforms: jobs.map((_, i) => results[i]?.platform)
	};
}

function normalizeRows(platform, rows) {
	// adapters 的归一化内联在 search 函数里；这里按平台映射输出统一行。
	return rows.map((r) => {
		if (platform === "fofa") {
			return { host: String(r[0] ?? ""), title: String(r[1] ?? ""), ip: String(r[2] ?? ""), domain: String(r[3] ?? ""), port: String(r[4] ?? ""), protocol: String(r[5] ?? ""), server: String(r[6] ?? ""), isp: String(r[7] ?? ""), time: String(r[10] ?? ""), platform };
		}
		if (platform === "hunter") {
			return { host: String(r.url ?? ""), title: String(r.web_title ?? ""), ip: String(r.ip ?? ""), domain: String(r.domain ?? ""), port: String(r.port ?? ""), protocol: String(r.protocol ?? ""), server: String(r.web_server ?? ""), isp: String(r.isp ?? ""), time: String(r.updated_at ?? ""), platform };
		}
		return { host: "", title: String(r.service?.[0]?.http?.title ?? ""), ip: String(r.ip ?? ""), domain: String(r.domain ?? ""), port: String(r.port ?? ""), protocol: String(r.service?.[0]?.name ?? ""), server: String(r.service?.[0]?.http?.server ?? ""), isp: String(r.isp ?? ""), time: String(r.time ?? ""), platform };
	});
}

/** 实测：读 finding → 指纹 → 搜索 → 流水线 → 回写 + 历史 + followup。 */
/** 实测防重：sessionId:findingId → 最近执行时间（10 分钟窗口——流水线含搜索+最多 50 资产探测，防连点并发重复扣平台配额）。 */
const LIVE_VERIFY_SENT = new Map();
const LIVE_VERIFY_WINDOW_MS = 10 * 60 * 1000;

async function runVerify(ctx, p) {
	const sessionId = String(p.sessionId ?? "");
	const findingId = String(p.findingId ?? "");
	if (!sessionId || !findingId) throw new Error("sessionId/findingId required");
	const rst = theResultsStore();
	const finding = getFinding(rst, sessionId, findingId);
	if (!finding) throw new Error("finding 不存在");
	if (finding.mode !== "code-audit") throw new Error("实测仅支持 code-audit 模式 finding");
	const vkey = `${sessionId}:${findingId}`;
	const lastRun = LIVE_VERIFY_SENT.get(vkey) ?? 0;
	if (Date.now() - lastRun < LIVE_VERIFY_WINDOW_MS) throw new Error("实测已在此前 10 分钟内执行——请稍后再试（重复执行会重复消耗平台配额）");
	LIVE_VERIFY_SENT.set(vkey, Date.now());

	const fp = parseFingerprint(finding.poc);
	const query = fingerprintQuery(fp);
	if (query === null) throw new Error("finding.poc 缺「指纹:」节——无法生成特征查询（audit-playbook 约定：指纹:framework=xxx,title=\"特征\"）");

	const st = theStore();
	const platforms = ["fofa", "hunter", "quake"].filter((pl) => getKey(st, pl));
	if (platforms.length === 0) throw new Error("未配置任何平台 API——先到「hunter 狩猎」页右上角设置配置");

	const allMode = p.allMode === true;
	const dynamic = finding.auditMode === "dynamic";

	// 互联网侧寻源：主特征查询零命中时按阶梯放宽（单一特征→框架名）自动续搜，衔接后续 L0/L1。
	const searchOnce = async (dsl) => {
		const queries = buildQueries(dsl, "dsl");
		const jobs = platforms.map((pl) => {
			const key = getKey(st, pl);
			if (pl === "fofa") return searchFofaPage(key, fofaGuard(queries.fofa), SEARCH_BUDGET).then((r) => r.rows.map(normalizeFofaRow));
			if (pl === "hunter") return searchHunterPage(key, queries.hunter, 1, SEARCH_BUDGET).then((r) => r.rows.map(normalizeHunterRow));
			return searchQuakePage(key, queries.quake, 0, SEARCH_BUDGET).then((r) => r.rows.map(normalizeQuakeRow));
		});
		const settled = await Promise.all(jobs.map((j) => j.catch((e) => ({ error: String(e?.message ?? e), rows: [] }))));
		const ok = settled.filter((r) => !r.error);
		const errs = settled.filter((r) => r.error);
		if (ok.length === 0) throw new Error("全部平台搜索失败: " + errs[0]?.error);
		return mergeAssets(...ok.map((r) => r.rows));
	};
	let relaxHit = null;
	const searchFn = async () => {
		const r = await searchWithRelax(searchOnce, fingerprintLadder(fp));
		relaxHit = r.hit;
		return r.assets;
	};

	let result;
	if (dynamic) {
		// 动态审计=影响面评估：搜→探测→统计，不执行 L1。
		result = await verifyPipeline(searchFn, async () => new Set(), {
			budget: SEARCH_BUDGET, allMode: true, stopOnFirstL0: false, fingerprint: fp,
			onProgress: () => {}
		});
		result.verdict = result.verdict === "l0-confirmed" ? "impact-mapped" : result.verdict;
		result.summary = result.detail?.l0Hits > 0
			? `影响面评估：${result.detail.searched} 个候选资产中 ${result.detail.l0Hits} 个存活且框架指纹一致（动态审计 EXP 已在本地复现，不重复验证）`
			: result.summary;
	} else {
		result = await verifyPipeline(searchFn, async () => new Set(st.listAuthorized.all().map((a) => a.key)), {
			budget: SEARCH_BUDGET, allMode, stopOnFirstL0: false, fingerprint: fp,
			onProgress: () => {}
		});
	}

	// 放宽寻源信息并入结论（summary/detail），历史登记实际命中的查询串。
	if (relaxHit) result.summary += `（主特征零命中，放宽至「${relaxHit.label}」后从互联网侧命中资产）`;
	if (result.detail && typeof result.detail === "object") result.detail.relax = relaxHit ? { level: relaxHit.level, label: relaxHit.label, query: relaxHit.query } : null;

	// 回写 finding（数据变更）
	const note = `[实测] ${nowIso().slice(0, 19)} ${result.summary}`;
	const patch = { retestNote: note, evidence: [finding.evidence, `实测:${result.verdict} (L0=${result.detail?.l0Hits ?? 0}/L1=${result.detail?.l1Passed ?? 0})`].filter(Boolean).join("；") };
	if (result.verdict === "l1-passed") {
		patch.status = "verified";
		patch.auditMode = "dynamic"; // L1 实测过=形态升格动态——消除「已验证+静态审计」词面矛盾（过程形态随实测事实更新）
	}
	updateFinding(rst, sessionId, finding.mode, findingId, patch);

	// 历史
	st.insertHistory.run(nowIso(), findingId, finding.mode, relaxHit ? relaxHit.query : query, platforms.join(","), result.verdict, JSON.stringify({ summary: result.summary, detail: result.detail }));

	// 会话通知（原会话可达时 followup）
	let notified = false;
	try {
		const agents = ctx.get("agents");
		const agent = agents?.get?.(sessionId);
		if (agent && typeof agent.followup === "function") {
			agent.followup({
				id: `hunter-${Date.now()}-${finding.seq}`,
				role: "user",
				content: [{ type: "text", text: `[hunter 实测] finding #${finding.seq}「${finding.title}」：${result.summary}\n细节：${JSON.stringify(result.detail)}\n建议：${result.suggestions.join("；")}` }],
				source: { kind: "user" }
			});
			notified = true;
		}
	} catch { /* 会话不可达 → 仅页面通知 */ }

	return { ok: true, verdict: result.verdict, summary: result.summary, detail: result.detail, suggestions: result.suggestions, notified, query };
}

const normalizeFofaRow = (r) => ({ host: String(r[0] ?? ""), title: String(r[1] ?? ""), ip: String(r[2] ?? ""), domain: String(r[3] ?? ""), port: String(r[4] ?? ""), protocol: String(r[5] ?? ""), server: String(r[6] ?? ""), isp: String(r[7] ?? ""), time: String(r[10] ?? ""), platform: "fofa" });
const normalizeHunterRow = (r) => ({ host: String(r.url ?? ""), title: String(r.web_title ?? ""), ip: String(r.ip ?? ""), domain: String(r.domain ?? ""), port: String(r.port ?? ""), protocol: String(r.protocol ?? ""), server: String(r.web_server ?? ""), isp: String(r.isp ?? ""), time: String(r.updated_at ?? ""), platform: "hunter" });
const normalizeQuakeRow = (r) => ({ host: String(r.service?.[0]?.http?.host ?? ""), title: String(r.service?.[0]?.http?.title ?? ""), ip: String(r.ip ?? ""), domain: String(r.domain ?? ""), port: String(r.port ?? ""), protocol: String(r.service?.[0]?.name ?? ""), server: String(r.service?.[0]?.http?.server ?? ""), isp: String(r.isp ?? ""), time: String(r.time ?? ""), platform: "quake" });

/** 平台 key 校验：一页小请求验 key 与额度。 */
async function testKey(platform, key) {
	try {
		if (platform === "fofa") {
			const res = await fetch(`https://fofa.info/api/v1/info/my?key=${encodeURIComponent(key)}`, { signal: AbortSignal.timeout(8000) });
			const data = await res.json();
			if (data.error) return { ok: false, error: `FOFA: ${data.errmsg}` };
			return { ok: true, info: `FOFA 已连接${data.remain_api_query ? `，剩余查询 ${data.remain_api_query}` : ""}` };
		}
		if (platform === "hunter") {
			const r = await searchHunterPage(key, `web.title="a"`, 1, 1, { startTime: daysAgoStamp(1), endTime: nowStamp() });
			return { ok: true, info: `Hunter 已连接（样例查询命中 ${r.total} 条）` };
		}
		const r = await searchQuakePage(key, `title:"a"`, 0, 1);
		return { ok: true, info: `Quake 已连接（样例查询命中 ${r.total} 条）` };
	} catch (e) {
		return { ok: false, error: String(e?.message ?? e) };
	}
}

export async function dispatch(ctx, st, endpoint, payload) {
	const p = payload ?? {};
	if (endpoint === "config.get") return { config: configView(st), platforms: ["fofa", "hunter", "quake"] };
	if (endpoint === "config.set") {
		const platform = String(p.platform ?? "");
		if (!["fofa", "hunter", "quake"].includes(platform)) throw new Error("platform 必须是 fofa/hunter/quake");
		const key = String(p.key ?? "").trim();
		if (key) {
			const test = await testKey(platform, key);
			if (!test.ok) throw new Error(`校验失败：${test.error}`);
		}
		st.setKey.run(platform, key, nowIso());
		return { ok: true, config: configView(st) };
	}
	if (endpoint === "config.test") {
		const platform = String(p.platform ?? "");
		const key = p.key !== undefined ? String(p.key) : getKey(st, platform);
		if (!key) throw new Error("该平台未配置 key");
		const r = await testKey(platform, key);
		return r.ok ? { ok: true, info: r.info } : { ok: false, error: r.error };
	}
	if (endpoint === "search") {
		const { queries, assets, platformErrors } = await runSearch(p, st);
		return { ok: true, queries, assets, platformErrors, limits: LIMITS };
	}
	if (endpoint === "export") {
		const { assets, platformErrors } = await runSearch(p, st);
		const format = p.format === "json" ? "json" : "csv";
		if (format === "json") return { ok: true, format, text: JSON.stringify(assets, null, 2) };
		const head = ["host", "ip", "port", "protocol", "title", "server", "domain", "isp", "time", "platforms"];
		const lines = [head.join(","), ...assets.map((a) => head.map((h) => `"${String(a[h] ?? (h === "platforms" ? (a.platforms ?? [a.platform]).join("|") : "")).replace(/"/g, '""')}"`).join(","))];
		return { ok: true, format, text: lines.join("\n"), platformErrors };
	}
	if (endpoint === "verify.live") return runVerify(ctx, p);
	if (endpoint === "history.list") return { ok: true, history: st.listHistory.all(Number(p.limit) || 50) };
	if (endpoint === "authorized.list") return { ok: true, authorized: st.listAuthorized.all() };
	if (endpoint === "authorized.add") {
		const key = `${String(p.ip ?? "").trim()}:${String(p.port ?? "").trim()}`;
		if (!p.ip || !p.port) throw new Error("ip/port required");
		st.authorize.run(key, String(p.note ?? ""), nowIso());
		return { ok: true, authorized: st.listAuthorized.all() };
	}
	if (endpoint === "authorized.remove") {
		st.unauthorize.run(String(p.key ?? ""));
		return { ok: true, authorized: st.listAuthorized.all() };
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
				const text = typeof body === "string" ? body : JSON.stringify(body);
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
				const raw = await readBody(req);
				const payload = raw === "" ? {} : JSON.parse(raw);
				const result = await dispatch(ctx, theStore(), endpoint, payload);
				send(200, result);
			} catch (e) {
				send(400, { ok: false, error: e?.message ?? String(e) });
			}
		}
	}), "dsh-hunter: web route");
}

export { apply, inject, name, ROUTE_PATH, DB_PATH, openHunterStore, LIMITS, isTrustedRequest };
