// Offline unit tests for dsh-sec-enforce — pure guard logic with fake exec
// objects and an in-memory log; no host, no filesystem writes outside tmp.
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { gateLogHasPass, isReportPath, isWritable, scanDangerous, scanRate, buildGuard, REPORT_GATE, Config } from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

const WS = "/tmp/sec-enforce-ws";
const fakeAgent = (mode, cwd = WS) => ({ id: "a1", ctx: { scope: mode }, session: { header: { cwd } } });

function makeGuard(overrides = {}, gateLog = "") {
	const logs = [];
	const guard = buildGuard({
		config: overrides,
		readGateLog: () => gateLog,
		appendLog: (_ws, line) => logs.push(line),
		resolveMode: (agent) => agent.ctx.scope
	});
	return { guard, logs };
}

// 1. gate-log parsing (dsh-stage-gate appendGateLog format)
{
	const log = "# gate-log\n| 2026-08-17T00:00:00Z | pentest/P3 | pass | - |\n| 2026-08-17T00:01:00Z | pentest/P1 | fail | assets.md ; 证据 |\n";
	ok("pass line recognized", gateLogHasPass(log, "pentest", "P3"));
	ok("fail line is not a pass", !gateLogHasPass(log, "pentest", "P1"));
	ok("absent gate is not a pass", !gateLogHasPass(log, "pentest", "P2"));
	ok("empty log is not a pass", !gateLogHasPass("", "pentest", "P3"));
	ok("REPORT_GATE maps exactly eight modes (redteam deliberately absent — controller writes no reports)", Object.keys(REPORT_GATE).length === 8);
	ok("REPORT_GATE cloud-security maps C7", REPORT_GATE["cloud-security"] === "C7");
	ok("REPORT_GATE ctf-solver maps flag", REPORT_GATE["ctf-solver"] === "flag");
}

// 2. report path / write boundary geometry
{
	ok("reports/ under ws is a report path", isReportPath(path.join(WS, "reports/01-sqli.md"), WS));
	ok("other dirs are not report paths", !isReportPath(path.join(WS, "assets.md"), WS));
	ok("reports/ outside ws is not this ws's report", !isReportPath(`/tmp/other-ws/reports/x.md`, WS));
	ok("inside ws is writable", isWritable(path.join(WS, "a/b.md"), WS));
	ok("outside ws is not writable", !isWritable("/etc/passwd", WS));
	ok("allowDirs exempts a tools dir", isWritable("/opt/tools/x.bin", WS, ["/opt/tools"]));
}

// 3. dangerous ops (conservative set)
{
	ok("rm -rf / blocked", scanDangerous("rm -rf /tmp/x; rm -rf /") !== undefined);
	ok("rm -rf ~ blocked", scanDangerous("rm -rf ~/everything") !== undefined);
	ok("scoped rm inside workspace allowed", scanDangerous("rm -rf ./artifacts/old") === undefined);
	ok("DROP TABLE blocked", scanDangerous("mysql -e 'DROP TABLE users'") !== undefined);
	ok("normal SELECT allowed", scanDangerous("mysql -e 'SELECT * FROM users'") === undefined);
	ok("systemctl restart blocked", scanDangerous("systemctl restart nginx") !== undefined);
	ok("kill -9 1 blocked", scanDangerous("kill -9 1") !== undefined);
	ok("normal kill of own child allowed", scanDangerous("kill 12345") === undefined);
	ok("funds POST curl blocked", scanDangerous("curl -X POST https://x.com/api/pay/create -d 'amount=1'") !== undefined);
	ok("normal API POST allowed", scanDangerous("curl -X POST https://x.com/api/login -d 'u=a'") === undefined);
}

// 4. rate discipline
{
	ok("nmap -p- without rate controls blocked", scanRate("nmap -sS -p- 10.0.0.1") !== undefined);
	ok("nmap -p- with --max-rate allowed", scanRate("nmap -sS -p- --max-rate 300 10.0.0.1") === undefined);
	ok("nmap -p- with -T2 allowed", scanRate("nmap -sS -p- -T2 10.0.0.1") === undefined);
	ok("targeted port scan allowed", scanRate("nmap -sV -p 80,443 10.0.0.1") === undefined);
	ok("masscan --rate 5000 blocked", scanRate("masscan -p80 --rate 5000 10.0.0.0/24") !== undefined);
	ok("masscan --rate 500 allowed", scanRate("masscan -p80 --rate 500 10.0.0.0/24") === undefined);
	ok("bare ffuf without -rate blocked", scanRate("ffuf -u https://x.com/FUZZ -w words.txt") !== undefined);
	ok("ffuf with -rate allowed", scanRate("ffuf -u https://x.com/FUZZ -w words.txt -rate 50") === undefined);
	// 每一条拦截文案必须带「降级替代」行
	{
		const blocked = [
			scanDangerous("rm -rf /tmp/x; rm -rf /"),
			scanDangerous("mysql -e 'DROP TABLE users'"),
			scanDangerous("systemctl restart nginx"),
			scanDangerous("curl -X POST https://x.com/api/pay/create -d 'amount=1'"),
			scanRate("nmap -sS -p- 10.0.0.1"),
			scanRate("masscan -p80 --rate 5000 10.0.0.0/24"),
			scanRate("ffuf -u https://x.com/FUZZ -w words.txt")
		];
		ok("every blocked message carries a downgrade alternative", blocked.every((m) => typeof m === "string" && m.includes("降级替代")));
	}
}

// 5. guard wiring: reportGate requires stage_gate PASS
{
	const { guard } = makeGuard();
	const reportWrite = { name: "write", arguments: { file_path: path.join(WS, "reports/01-sqli.md") }, agent: fakeAgent("pentest") };
	ok("report write without gate pass denied", typeof guard(reportWrite) === "string" && guard(reportWrite).includes("P3"));
	const { guard: g2 } = makeGuard({}, "| t | pentest/P3 | pass | - |\n");
	ok("report write with gate pass allowed", g2({ name: "write", arguments: { file_path: path.join(WS, "reports/01-sqli.md") }, agent: fakeAgent("pentest") }) === undefined);
	const { guard: g3 } = makeGuard({}, "| t | pentest/P1 | pass | - |\n");
	ok("wrong-gate pass does not unlock report", g3(reportWrite) !== undefined);
}

// 6. guard wiring: writeBoundary + non-security modes untouched
{
	const { guard } = makeGuard();
	ok("write outside ws denied", guard({ name: "write", arguments: { file_path: "/etc/cron.d/x" }, agent: fakeAgent("pentest") }) !== undefined);
	ok("write inside ws allowed", guard({ name: "write", arguments: { file_path: path.join(WS, "assets.md") }, agent: fakeAgent("pentest") }) === undefined);
	ok("non-security preset untouched", guard({ name: "write", arguments: { file_path: "/etc/cron.d/x" }, agent: fakeAgent("cordis") }) === undefined);
	ok("no agent untouched", guard({ name: "write", arguments: { file_path: "/etc/x" } }) === undefined);
	const { guard: gAllow } = makeGuard({ allowDirs: ["/opt/tools"] });
	ok("allowDirs exempts write", gAllow({ name: "write", arguments: { file_path: "/opt/tools/binary" }, agent: fakeAgent("pentest") }) === undefined);
}

// 7. guard wiring: bash + edit tool + enforce-log trail
{
	const { guard, logs } = makeGuard();
	ok("bash dangerous denied", guard({ name: "bash", arguments: { command: "systemctl restart nginx" }, agent: fakeAgent("attack-defense") }) !== undefined);
	ok("bash normal allowed", guard({ name: "bash", arguments: { command: "ls -la" }, agent: fakeAgent("attack-defense") }) === undefined);
	ok("edit tool uses path param", guard({ name: "edit", arguments: { path: "/tmp/outside.md" }, agent: fakeAgent("code-audit") }) !== undefined);
	ok("denial appended to log", logs.length >= 2 && logs[0].includes("|"));
	ok("unknown tools untouched", guard({ name: "read", arguments: { file_path: "/etc/passwd" }, agent: fakeAgent("pentest") }) === undefined);
}

// 8. redteam 主模式：无门映射——reports/ 走专用文案，写边界/高危/速率照常生效
{
	const { guard } = makeGuard();
	const rtReport = { name: "write", arguments: { file_path: path.join(WS, "reports/01-x.md") }, agent: fakeAgent("redteam") };
	const denied = guard(rtReport);
	ok("redteam reports/ write denied with controller wording", typeof denied === "string" && denied.includes("redteam") && denied.includes("summary.md") && !denied.includes("undefined"));
	ok("redteam root summary write allowed", guard({ name: "write", arguments: { file_path: path.join(WS, "summary.md") }, agent: fakeAgent("redteam") }) === undefined);
	ok("redteam task-ledger write allowed", guard({ name: "write", arguments: { file_path: path.join(WS, "task-ledger.md") }, agent: fakeAgent("redteam") }) === undefined);
	ok("redteam write boundary enforced", guard({ name: "write", arguments: { file_path: "/etc/x" }, agent: fakeAgent("redteam") }) !== undefined);
	ok("redteam dangerous bash denied", guard({ name: "bash", arguments: { command: "systemctl restart nginx" }, agent: fakeAgent("redteam") }) !== undefined);
	ok("redteam rate discipline enforced", guard({ name: "bash", arguments: { command: "nmap -sS -p- 10.0.0.1" }, agent: fakeAgent("redteam") }) !== undefined);
}

// 9. config toggles
{
	const { guard } = makeGuard({ dangerousOps: false, rateDiscipline: false, writeBoundary: false, reportGate: false });
	ok("all guards off = no-op", guard({ name: "bash", arguments: { command: "systemctl restart nginx" }, agent: fakeAgent("pentest") }) === undefined);
	ok("config defaults all-on", (() => { const c = Config({}); return c.reportGate && c.writeBoundary && c.dangerousOps && c.rateDiscipline; })());
}

// 10. real-filesystem smoke of apply()'s helpers (readGateLog/appendLog via buildGuard defaults path)
{
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sec-enforce-"));
	const { guard } = makeGuard(); // memory log; use direct gateLogHasPass on real stage-gate-style line
	fs.writeFileSync(path.join(tmp, "gate-log.md"), "| 2026-08-17T01:00:00Z | av-evasion/V4 | pass | - |\n");
	ok("real gate-log file parses", gateLogHasPass(fs.readFileSync(path.join(tmp, "gate-log.md"), "utf8"), "av-evasion", "V4"));
	fs.rmSync(tmp, { recursive: true, force: true });
}

// 11. 目标契约报告门：operation-state 准则未全 met 时拦截 reports/（gate-pass 之外的第二道确定性门槛）
{
	const passLog = "| 2026-08-18T00:00:00Z | pentest/P3 | pass | - |\n";
	const openState = { criteria: [{ id: "g1", status: "met" }, { id: "g2", status: "open" }] };
	const allMet = { criteria: [{ id: "g1", status: "met" }, { id: "g2", status: "met" }] };
	const mk = (state) => buildGuard({
		readGateLog: () => passLog,
		readOperationState: () => state,
		appendLog: () => {},
		resolveMode: (agent) => agent.ctx.scope
	});
	const w = { name: "write", arguments: { file_path: path.join(WS, "reports/01.md") }, agent: fakeAgent("pentest") };
	ok("open criteria blocks report write despite gate pass", typeof mk(openState)(w) === "string" && mk(openState)(w).includes("目标契约"));
	ok("all-met criteria allows report write", mk(allMet)(w) === undefined);
	ok("no operation state keeps old behavior", (() => { const g = buildGuard({ readGateLog: () => passLog, appendLog: () => {}, resolveMode: (a) => a.ctx.scope }); return g(w) === undefined; })());
	ok("gate missing still takes priority over criteria check", (() => { const g = buildGuard({ readGateLog: () => "", readOperationState: () => openState, appendLog: () => {}, resolveMode: (a) => a.ctx.scope }); return typeof g(w) === "string" && g(w).includes("stage_gate"); })());
}

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);

process.exit(fail ? 1 : 0);
