// dsh-semgrep-audit 离线单测：解析/去重/截断、参数构造、refs 定位、对账双写、
// 运行核心（注入 spawn/fs，离线全链）。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseSemgrepJson, buildArgs, findRefsDir, appendReconcile, runSemgrep, RULE_LAYERS } from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

// 1. 解析：计数/去重/截断/摘要
{
	const fixture = JSON.stringify({
		results: [
			{ check_id: "java.lang.security.audit.sqli", path: "src/Main.java", start: { line: 10 }, extra: { severity: "ERROR", message: "SQL injection sink" } },
			{ check_id: "java.lang.security.audit.sqli", path: "src/Main.java", start: { line: 10 }, extra: { severity: "ERROR", message: "dup" } },
			{ check_id: "php.cmd.exec", path: "app/x.php", start: { line: 3 }, extra: { severity: "WARNING", message: "command exec" } }
		],
		errors: []
	});
	const p = parseSemgrepJson(fixture);
	ok("解析：total 3 / 去重 2 / 分级计数", p.ok && p.total === 3 && p.unique === 2 && p.bySeverity.ERROR === 2 && p.bySeverity.WARNING === 1);
	ok("解析：Top 规则摘要与对账指引文案", p.summaryText.includes("java.lang.security.audit.sqli×2") && p.summaryText.includes("命中≠漏洞"));
	const capped = parseSemgrepJson(JSON.stringify({ results: Array.from({ length: 500 }, (_, i) => ({ check_id: "r" + i, path: "a.java", start: { line: i }, extra: { severity: "ERROR", message: "m" } })) }), 50);
	ok("解析：展示截断（500 命中展示 50，unique 全计）", capped.hits.length === 50 && capped.unique === 500);
	ok("解析：非 JSON 拒绝", parseSemgrepJson("not json").ok === false);
}

// 2. 参数构造：规则层→--config 路径；custom 用 rulesPath
{
	const { args, configs } = buildArgs("builtin-java", "/repo", undefined, "/refs");
	ok("args：java 层 config 指 refs 子目录 + json/metrics/quiet", args.includes("--config") && configs[0].endsWith("lang/java-audit/semgrep-rules") && args.includes("--metrics=off") && args.includes("--json") && args[args.length - 1] === "/repo");
	const c = buildArgs("custom", "/repo", "/my/rules.yml", "");
	ok("args：custom 层用 rulesPath", c.configs[0] === "/my/rules.yml");
	ok("RULE_LAYERS 三内置层齐", Object.keys(RULE_LAYERS).join() === "builtin-java,builtin-php,oss");
}

// 3. refs 定位：候选注入（存在 java 规则目录的候选胜出；全不存在返回空）
{
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sg-refs-"));
	fs.mkdirSync(path.join(dir, "lang", "java-audit", "semgrep-rules"), { recursive: true });
	ok("findRefsDir：命中含规则集的候选", findRefsDir([path.join(dir, "nonexist"), dir]) === dir);
	ok("findRefsDir：全不存在返回空串", findRefsDir([path.join(dir, "none1"), path.join(dir, "none2")]) === "");
	fs.rmSync(dir, { recursive: true, force: true });
}

// 4. 对账双写：md 行格式 + csv 表头/转义
{
	const ws = fs.mkdtempSync(path.join(os.tmpdir(), "sg-ws-"));
	const n = appendReconcile(fs, ws, [{ rule: 'r"1', file: "a.java", line: 5, severity: "ERROR", message: "m" }]);
	const md = fs.readFileSync(path.join(ws, "scan-reconcile.md"), "utf8");
	const csv = fs.readFileSync(path.join(ws, "scan-reconcile.csv"), "utf8");
	ok("md：表头+待处置行", md.includes("| 来源 | 命中 | 终态 |") && md.includes('| semgrep | r"1 @ a.java:5 [ERROR] | 待处置'));
	ok("csv：机读表头+引号转义", csv.startsWith("scanner,rule,file,line,verdict,reason") && csv.includes('"r""1"') && csv.endsWith("待处置,命中≠漏洞，复核后经 register 升格\n"));
	appendReconcile(fs, ws, [{ rule: "r2", file: "b.php", line: 1, severity: "WARNING", message: "" }]);
	ok("双写追加不重建表头", fs.readFileSync(path.join(ws, "scan-reconcile.csv"), "utf8").split("scanner,rule").length === 2);
	fs.rmSync(ws, { recursive: true, force: true });
}

// 5. 运行核心（注入 spawn/fs + refs 候选）：产物/证据/对账全链
{
	const ws = fs.mkdtempSync(path.join(os.tmpdir(), "sg-run-"));
	const target = path.join(ws, "repo");
	const refs = path.join(ws, "refs");
	fs.mkdirSync(target, { recursive: true });
	fs.mkdirSync(path.join(refs, "lang", "java-audit", "semgrep-rules"), { recursive: true });
	const semgrepOut = JSON.stringify({ results: [{ check_id: "r.a", path: "A.java", start: { line: 1 }, extra: { severity: "ERROR", message: "m" } }], errors: [] });
	const r = runSemgrep({
		workspace: ws, target, layer: "builtin-java",
		spawnFn: (bin, args) => ({ status: 0, stdout: semgrepOut, args }),
		fsMod: fs, refsCandidates: [refs], hasBinFn: () => true
	});
	ok("运行：产物 JSON 落盘 + 证据行 + 对账双写", r.ok && r.total === 1 && r.reconciled === 1 && fs.existsSync(path.join(ws, "artifacts", "scans")) && fs.readFileSync(path.join(ws, "evidence-index.md"), "utf8").includes("semgrep scan --json"));
	ok("运行：证据编号自增格式", /^E\d+$/.test(r.evidenceId));
	const r2 = runSemgrep({ workspace: ws, target, layer: "custom", rulesPath: "/no/such.yml", spawnFn: () => ({ status: 0, stdout: "{}" }), fsMod: fs, refsCandidates: [refs], hasBinFn: () => true });
	ok("运行：custom 规则路径不存在拒绝", r2.ok === false && r2.error.includes("规则路径不存在"));
	const r3 = runSemgrep({ workspace: ws, target, layer: "builtin-java", spawnFn: () => ({ status: 0, stdout: "{}" }), fsMod: fs, refsCandidates: ["/none"], hasBinFn: () => true });
	ok("运行：refs 未定位拒绝并提示 custom 兜底", r3.ok === false && r3.error.includes("layer=custom"));
	const r4 = runSemgrep({ workspace: ws, target, layer: "builtin-java", spawnFn: () => ({ status: 0, stdout: "{}" }), fsMod: fs, refsCandidates: [refs], hasBinFn: () => false });
	ok("运行：缺装拒绝走三级兜底提示（检测制）", r4.ok === false && r4.error.includes("绝不自动装"));
	fs.rmSync(ws, { recursive: true, force: true });
}

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
process.exit(fail ? 1 : 0);
