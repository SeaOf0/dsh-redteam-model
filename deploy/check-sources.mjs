#!/usr/bin/env node
// check-sources.mjs — 外部来源链接健康检查（链接腐烂兜底）
// 用法：node deploy/check-sources.mjs [--timeout 8000] [--conc 16]
// 退出码：0=高易逝域零失效；1=存在高易逝域失效（发布前必须处理）
// 原则：只探活不抓正文；补天正文登录墙属正常态（200 即可达，不判内容）。
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const argv = process.argv;
const opt = (k, d) => (argv.includes(`--${k}`) ? argv[argv.indexOf(`--${k}`) + 1] : d);
const TIMEOUT = Number(opt("timeout", 8000));
const CONC = Number(opt("conc", 16));
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MODES = join(ROOT, "modes");
// 高易逝域：社区帖（删帖/收紧常态）；github/官方文档归稳定域
const FRAGILE = [/xz\.aliyun\.com/, /forum\.butian\.net/, /mp\.weixin\.qq\.com/, /zone\.huoxian\.cn/, /anquanke/, /freebuf/, /seebug/, /zhihu/, /csdn\.net/, /cnblogs/];

const walk = (dir, out = []) => {
	for (const e of readdirSync(dir)) {
		const p = join(dir, e);
		if (statSync(p).isDirectory()) walk(p, out);
		else if (e.endsWith(".md")) out.push(p);
	}
	return out;
};

import { spawn } from "node:child_process";
function curlOnce(url, head) {
	// curl 异步探活（HEAD 失败自动降级 GET 单字节）；spawnSync 会阻塞事件循环使并发失效
	const args = ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", String(Math.ceil(TIMEOUT / 1000)), "-L", ...(head ? ["-I"] : ["-r", "0-0"])];
	return new Promise((resolve) => {
		const ch = spawn("curl", [...args, url]);
		let out = "";
		const kill = setTimeout(() => ch.kill("SIGKILL"), TIMEOUT + 3000);
		ch.stdout.on("data", (d) => (out += d));
		ch.on("error", () => { clearTimeout(kill); resolve("ERR:spawn"); });
		ch.on("close", () => { clearTimeout(kill); resolve(out.trim()); });
	});
}
async function probe(url) {
	let code = await curlOnce(url, true);
	if (!/^[0-9]{3}$/.test(code) || code === "000") code = await curlOnce(url, false);
	return { url, status: /^[0-9]{3}$/.test(code) ? Number(code) : "ERR:" + String(code).slice(0, 30) };
}

const urls = new Map();
for (const mode of readdirSync(MODES)) {
	for (const base of ["refs", "skills"].map((s) => join(MODES, mode, s))) {
		let files = [];
		try { files = walk(base); } catch { continue; }
		for (const f of files) {
			const rel = `${mode}/` + f.split(join(MODES, mode) + "/")[1];
			const text = readFileSync(f, "utf8");
			for (const m of text.matchAll(/https?:\/\/[a-zA-Z0-9][^\s)\]}"'<>，。、{}]*/g)) {
				const u = m[0].replace(/[.,;:]+$/, "");
				// 跳过文档内 payload/示例占位域（非真实来源）
				if (/[.?\/](target|attacker|example|evil|malicious|test|localhost|127\.0\.0\.1|victim|fake|demo|sample)[.!?:/]|\[|^https?:\/\/\$|\{$/i.test(u)) continue;
				if (!urls.has(u)) urls.set(u, []);
				if (urls.get(u).length < 3) urls.get(u).push(rel);
			}
		}
	}
}
const list = [...urls.keys()].sort();
// ── 技能库供应链静态扫描（SKILL.md 是模型消费的指令文档：检出可疑指令模式即警告人工复核）──
const SUSPICIOUS = [
	[/ignore (all|previous|above) (instructions|rules)/i, "疑似指令覆盖（ignore previous）"],
	[/忽略(之前|以上|所有)(的)?(指令|规则|指示)/, "疑似指令覆盖（中文）"],
	[/exfiltrate|send .*to .*attacker|上传.*到.*外部|外传(到)?(攻击者|外部)/i, "疑似外传指令"],
	[/curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh/i, "疑似管道执行远程脚本"],
	[/disable (all )?(safety|guardrails)|禁用.*(安全|防护)/i, "疑似关闭防护"],
];
let susp = 0;
for (const mode of readdirSync(MODES)) {
	for (const base of ["refs", "skills"].map((s) => join(MODES, mode, s))) {
		let files = [];
		try { files = walk(base); } catch { continue; }
		for (const f of files) {
			const text = readFileSync(f, "utf8");
			for (const [re, why] of SUSPICIOUS) {
				const m = text.match(re);
				if (m) { susp++; console.log(`⚠ [SKILL-SEC] ${why}: "${m[0].slice(0, 50)}" @ ${mode}/` + f.split(join(MODES, mode) + "/")[1]); }
			}
		}
	}
}
console.log(susp === 0 ? "技能库静态扫描：无可疑指令模式。\n" : `技能库静态扫描：${susp} 处命中，人工复核（可能是安全研究内容本身的正常引用，逐条判断）。\n`);
console.log(`refs/skills 共 ${list.length} 个外部 URL，探活（timeout ${TIMEOUT}ms 并发 ${CONC}）...\n`);

const results = [];
let idx = 0;
async function worker() {
	while (idx < list.length) results.push(await probe(list[idx++]));
}
await Promise.all(Array.from({ length: CONC }, worker));

const isDead = (s) => s === "TIMEOUT-ABORT" || String(s).startsWith("ERR:") || s === 404 || s === 410;
let dead = 0, deadFragile = 0;
for (const r of results.sort((a, b) => String(a.status).localeCompare(String(b.status)))) {
	const fragile = FRAGILE.some((re) => re.test(r.url));
	const d = isDead(r.status);
	if (d) { dead++; if (fragile) deadFragile++; }
	if (d || fragile) {
		console.log(`${d ? "✗" : "✓"} [${d ? (fragile ? "DEAD-FRAGILE" : "DEAD") : fragile ? "fragile" : "ok"}] ${r.status}  ${r.url}`);
		if (d) console.log(`    ↳ ${urls.get(r.url).join(" ; ")}`);
	}
}
const ok = results.length - dead;
console.log(`\n可达 ${ok}/${results.length}（稳定域失效 ${dead - deadFragile} 未逐条列出，见上方 DEAD 行）`);
if (deadFragile > 0) {
	console.log(`高易逝域失效 ${deadFragile} 条——处置：用标题/关键词找转载版更新 URL，找不到则确认对应 refs 内容仍可独立使用。`);
	process.exit(1);
}
console.log("高易逝域零失效，可发布。");
