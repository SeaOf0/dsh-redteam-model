// dsh-hunter verify：代码审计 finding 的实测验证流水线（纯逻辑，宿主侧执行）。
//
// finding.poc 顶部约定节（audit-playbook 配套约定）：
//   指纹:framework=xxx,version=1.2.3,title="特征词",body="特征词",header="特征词"
//   L1验证:GET /admin/ping?marker=VERIFY_7f3a9c 期望:VERIFY_7f3a9c
//
// 分级：
//   L0 测绘级：存活探测（GET 首页）+ 指纹一致性 —— 所有搜到资产
//   L1 无害验证：L1验证请求（只读/minimal）—— 仅授权资产白名单
//   L2 完整 EXP：默认禁用，不做
//
// 停止条件：任一 L0+授权资产 L1 成立即停（除非 allMode）；搜零结果→下一步建议。
// 动态审计（auditMode=dynamic）：影响面评估语义——统计存活+指纹一致资产数量，不执行 L1。

const SEARCH_BUDGET = 50;      // 默认 50 条/次
const PROBE_CONCURRENCY = 5;   // 存活探测并发
const PROBE_TIMEOUT_MS = 3000;

/** 从 poc 文本提取指纹节与 L1 验证节。 */
export function parseFingerprint(pocText) {
	const s = String(pocText ?? "");
	const fp = { fields: new Map(), l1: null };
	const fpMatch = s.match(/指纹[:：]([^\n]+)/);
	if (fpMatch) {
		const seg = fpMatch[1];
		const re = /([a-z_]+)\s*=\s*("[^"]*"|[^,，]+)/gi;
		let m;
		while ((m = re.exec(seg)) !== null) {
			const v = m[2].replace(/^"|"$/g, "").trim();
			if (v) fp.fields.set(m[1].toLowerCase(), v);
		}
	}
	const l1Match = s.match(/L1验证[:：]([^\n]+)/);
	if (l1Match) {
		const parts = l1Match[1].split(/\s+/);
		const method = parts[0]?.toUpperCase();
		const path = parts[1];
		const expectIdx = l1Match[1].indexOf("期望");
		const expect = expectIdx >= 0 ? l1Match[1].slice(expectIdx + 2).replace(/^[:：=\s]+/, "").trim() : "";
		if (method && path) fp.l1 = { method, path, expect };
	}
	return fp;
}

/** 指纹 → 统一 DSL 查询串（title/body/header 特征优先，framework/app 兜底）。 */
export function fingerprintQuery(fp) {
	const f = fp.fields;
	const parts = [];
	if (f.get("title")) parts.push(`title:"${f.get("title")}"`);
	if (f.get("body")) parts.push(`body:"${f.get("body")}"`);
	if (f.get("header")) parts.push(`header:"${f.get("header")}"`);
	if (f.get("app")) parts.push(`app:"${f.get("app")}"`);
	if (parts.length === 0) {
		if (f.get("framework")) parts.push(`app:"${f.get("framework")}"`);
		if (f.get("version")) parts.push(`body:"${f.get("version")}"`);
	}
	if (parts.length === 0) return null;
	return parts.join(" ");
}

/** 指纹查询阶梯（互联网侧寻源）：特征组合 → 单一特征（title/body/header）→ 框架名兜底。
 *  同串去重；每一级即一轮搜索（查询预算考虑，最多 5 轮）。 */
export function fingerprintLadder(fp) {
	const f = fp.fields;
	const steps = [];
	const push = (level, label, query) => {
		if (query && !steps.some((s) => s.query === query)) steps.push({ level, label, query });
	};
	push(0, "特征组合", fingerprintQuery(fp));
	if (f.get("title")) push(1, "仅 title 特征", `title:"${f.get("title")}"`);
	if (f.get("body")) push(2, "仅 body 特征", `body:"${f.get("body")}"`);
	if (f.get("header")) push(3, "仅 header 特征", `header:"${f.get("header")}"`);
	const fw = f.get("app") || f.get("framework");
	if (fw) push(4, "框架名兜底", `app:"${fw}"`);
	return steps;
}

/** 逐级放宽搜索：主特征零命中时自动降级续搜，任一级命中即返回该级资产与命中信息；
 *  全部零命中返回空（由流水线衔接 no-assets 建议路径）。 */
export async function searchWithRelax(searchOnce, ladder) {
	for (const step of ladder) {
		const assets = await searchOnce(step.query);
		if (assets.length > 0) return { assets, hit: step };
	}
	return { assets: [], hit: null };
}

/** 存活探测：GET http(s)://ip:port/ ，返回 { alive, title, server, bodyPrefix, error }。 */
export async function probeAsset(asset, timeoutMs = PROBE_TIMEOUT_MS) {
	const proto = asset.protocol === "https" ? "https" : "http";
	const host = asset.ip || (asset.host || "").split(":")[0];
	const port = asset.port || (proto === "https" ? 443 : 80);
	const url = `${proto}://${host}:${port}/`;
	const ac = new AbortController();
	const t = setTimeout(() => ac.abort(), timeoutMs);
	try {
		const res = await fetch(url, {
			signal: ac.signal,
			redirect: "follow",
			headers: { "user-agent": "Mozilla/5.0 (compatible; DSH-Hunter/1.0)" }
		});
		const text = await res.text();
		const titleM = text.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
		return {
			alive: true,
			status: res.status,
			title: titleM ? titleM[1].trim() : "",
			server: String(res.headers.get("server") ?? ""),
			bodyPrefix: text.slice(0, 4000),
			error: ""
		};
	} catch (e) {
		return { alive: false, status: 0, title: "", server: "", bodyPrefix: "", error: String(e?.name ?? e) };
	} finally {
		clearTimeout(t);
	}
}

/** 指纹一致性校验（L0）：title/body/header 特征任一在探测结果中实际出现。 */
export function fingerprintMatches(probe, fp) {
	const f = fp.fields;
	const checks = [
		f.get("title") ? [probe.title, "title"] : null,
		f.get("body") ? [probe.bodyPrefix, "body"] : null,
		f.get("header") ? [probe.server, "header"] : null
	].filter(Boolean);
	if (checks.length === 0) return { match: false, reason: "指纹节无 title/body/header 特征" };
	for (const [hay, kind] of checks) {
		if (hay && String(hay).includes(f.get(kind))) return { match: true, kind, value: f.get(kind) };
	}
	return { match: false, reason: "title/body/header 特征均未命中" };
}

/** 并发限制的批量存活探测。 */
export async function probeBatch(assets, concurrency = PROBE_CONCURRENCY, onProgress) {
	const out = [];
	let idx = 0;
	async function worker() {
		while (idx < assets.length) {
			const i = idx++;
			const probe = await probeAsset(assets[i]);
			out[i] = { asset: assets[i], probe };
			onProgress?.(i + 1, assets.length);
		}
	}
	await Promise.all(Array.from({ length: Math.min(concurrency, assets.length) }, () => worker()));
	return out;
}

/** L1 最小影响验证：仅授权资产执行 L1验证请求。 */
export async function runL1(asset, l1, timeoutMs = PROBE_TIMEOUT_MS) {
	const proto = asset.protocol === "https" ? "https" : "http";
	const host = asset.ip || (asset.host || "").split(":")[0];
	const port = asset.port || (proto === "https" ? 443 : 80);
	const url = `${proto}://${host}:${port}${l1.path}`;
	const ac = new AbortController();
	const t = setTimeout(() => ac.abort(), timeoutMs);
	try {
		const res = await fetch(url, { signal: ac.signal, method: l1.method, redirect: "follow" });
		const text = await res.text();
		const passed = l1.expect ? text.includes(l1.expect) : res.ok;
		return { executed: true, passed, status: res.status, bodyPrefix: text.slice(0, 2000), error: "" };
	} catch (e) {
		return { executed: false, passed: false, status: 0, bodyPrefix: "", error: String(e?.name ?? e) };
	} finally {
		clearTimeout(t);
	}
}

/**
 * 实测流水线主入口。
 * @param searchFn  async (platformQueryMap) => assets[] —— 已归一化合并的资产列表
 * @param authorizedFn  async () => Set<"ip:port"> —— 授权白名单
 * @param opts { allMode, budget, onProgress }
 * @returns 结论对象（verdict/细节/下一步建议/逐资产记录）
 */
export async function verifyPipeline(searchFn, authorizedFn, opts = {}) {
	const budget = opts.budget ?? SEARCH_BUDGET;
	const allMode = opts.allMode === true;
	const report = [];
	let assets;
	try {
		assets = await searchFn();
	} catch (e) {
		return { verdict: "search-error", summary: "资产搜索失败", detail: String(e?.message ?? e), assets: [], suggestions: ["检查平台 API key 是否有效/额度是否耗尽", "更换特征词重试"] };
	}
	if (!assets || assets.length === 0) {
		return {
			verdict: "no-assets",
			summary: "未找到可验证资产",
			detail: "三平台均未返回匹配资产",
			assets: [],
			suggestions: [
				"扩大特征词：去掉版本号、泛化框架名（如 shiro → app:\"Apache Shiro\"）",
				"降低指纹严格度：只保留 title 或 body 单一特征",
				"提供授权资产或本地同版本靶场做完整 EXP 验证",
				"改用影响面评估模式（动态审计）做量级统计"
			]
		};
	}
	const authorized = await authorizedFn();
	const capped = assets.slice(0, budget);
	const probed = await probeBatch(capped, PROBE_CONCURRENCY, (done, total) => opts.onProgress?.("probe", done, total));
	let l0Hits = 0, l1Passed = 0, firstL0 = null, firstL1 = null;
	for (const { asset, probe } of probed) {
		if (!probe.alive) {
			report.push({ asset, stage: "dead", detail: probe.error || "unreachable" });
			continue;
		}
		const fp = opts.fingerprint;
		const fm = fingerprintMatches(probe, fp ?? { fields: new Map() });
		if (!fm.match) {
			report.push({ asset, stage: "alive-mismatch", detail: fm.reason, probe: { status: probe.status, title: probe.title.slice(0, 60), server: probe.server } });
			continue;
		}
		l0Hits++;
		report.push({ asset, stage: "l0-hit", kind: fm.kind, value: fm.value, probe: { status: probe.status, title: probe.title.slice(0, 60), server: probe.server } });
		if (firstL0 === null) firstL0 = { asset, probe, fm };
		const isAuth = authorized.has(`${asset.ip || (asset.host || "").split(":")[0]}:${asset.port}`);
		if (isAuth && fp?.l1) {
			const r = await runL1(asset, fp.l1);
			if (r.executed && r.passed) {
				l1Passed++;
				report[report.length - 1].stage = "l1-passed";
				report[report.length - 1].l1 = { status: r.status, expect: fp.l1.expect };
				if (firstL1 === null) firstL1 = { asset, l1: fp.l1, r };
				if (!allMode) break;
			} else {
				report[report.length - 1].l1 = { executed: r.executed, passed: false, error: r.error || "expect 未命中" };
			}
		}
	}
	const stoppedEarly = !allMode && (l1Passed > 0 || (opts.stopOnFirstL0 === true && l0Hits > 0));
	const verdict = l1Passed > 0 ? "l1-passed" : l0Hits > 0 ? "l0-confirmed" : "l0-none";
	const summary = l1Passed > 0
		? `实测成立：授权资产上最小影响验证通过（L1）——静态审计结果真实可用`
		: l0Hits > 0
			? `框架真实存在且一致（L0）：${l0Hits} 个存活资产指纹一致——EXP 潜在可用；完整验证三条路：标记授权后重试 L1 / 交接渗透测试模式做完整 POC 验证 / 本地靶场`
			: `资产存活但指纹均不一致（探测 ${capped.length} 个）——审计指纹可能过时或特征词偏差`;
	return {
		verdict,
		summary,
		detail: {
			searched: assets.length, probed: capped.length, alive: probed.filter((r) => r.probe.alive).length,
			l0Hits, l1Passed, stoppedEarly, firstL0: firstL0 ? { ip: firstL0.asset.ip, port: firstL0.asset.port, title: firstL0.probe.title.slice(0, 80) } : null,
			firstL1: firstL1 ? { ip: firstL1.asset.ip, port: firstL1.asset.port, expect: firstL1.l1.expect } : null
		},
		assets: report,
		// 未授权资产不做死路拒绝：L1 快验之外给出渗透模式交接路径（含操作建议）与本地靶场兜底。
		suggestions: l1Passed > 0 ? ["实测已成立，可回写 finding 状态为 verified"] : l0Hits > 0
			? [
				"路径一（L1 快验）：将任一一致资产在 hunter 页「标记授权」后重试实测——仅对该资产执行最小影响验证",
				"路径二（完整 POC）：交接渗透测试模式执行——先向用户确认该资产的测试授权，再按渗透纪律做探测复测与完整 POC 验证（对照三件套留证、命中后按渗透模式登记成果并回标审计 finding）",
				"路径三（本地兜底）：提供本地同版本靶场做完整 EXP 验证，不触互联网资产"
			]
			: ["检查指纹特征与目标框架实际 banner 是否一致", "用 hunter 页直接搜索框架名观察真实资产特征", "在本地搭建同版本环境确认 EXP 有效性"]
	};
}

export { SEARCH_BUDGET, PROBE_CONCURRENCY, PROBE_TIMEOUT_MS };
