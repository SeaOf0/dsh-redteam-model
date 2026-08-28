// Offline unit tests for dsh-sec-enforce — pure guard logic with fake exec
// objects and an in-memory log; no host, no filesystem writes outside tmp.
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { gateLogHasPass, isReportPath, isWritable, scanDangerous, scanRate, scanAsk, buildAskListener, buildGuard, REPORT_GATE, Config } from "../lib/index.js";

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

// 12. ask 中间档（v1.1.0）：变更性但可逆类走人工审批而非硬拦
{
	ok("useradd 命中 ask", scanAsk("sudo useradd -m backdoor") !== undefined);
	ok("改密命中 ask", scanAsk("passwd root") !== undefined);
	ok("SQL 授权面命中 ask", scanAsk("mysql -e 'GRANT ALL ON *.* TO x@%'") !== undefined);
	ok("iptables 清空命中 ask", scanAsk("iptables -F") !== undefined);
	ok("nft 修改命中 ask", scanAsk("nft add rule filter input accept") !== undefined);
	ok("ufw 开关命中 ask", scanAsk("ufw enable") !== undefined);
	ok("flood 压测命中 ask", scanAsk("hping3 -S --flood -p 80 10.0.0.1") !== undefined);
	ok("slowloris 命中 ask", scanAsk("perl slowloris.pl -dns target") !== undefined);
	// 保守性：正常工作流不命中
	ok("工作区 chmod 不命中", scanAsk("chmod +x ./exploit.py") === undefined);
	ok("普通 nmap 不命中（归速率档管）", scanAsk("nmap -sV -p 80,443 10.0.0.1") === undefined);
	ok("SELECT 不命中", scanAsk("mysql -e 'SELECT * FROM users'") === undefined);
	ok("iptables 只读列表不命中", scanAsk("iptables -L -n") === undefined);
	ok("curl 正常请求不命中", scanAsk("curl -s http://t/login") === undefined);
	// 分级边界：deny 档命令不在 ask 档（shutdown 归 scanDangerous）
	ok("shutdown 不重复命中 ask", scanAsk("shutdown -h now") === undefined);
}

// 13. ask 监听器（waterfall 礼仪：无候选 next；有候选且下游 allow 才覆盖；尊重更强决策）
{
	const logs = [];
	const listener = buildAskListener({ appendLog: (_ws, line) => logs.push(line), resolveMode: (agent) => agent.ctx.scope });
	const askExec = { name: "bash", arguments: { command: "useradd svc" }, agent: fakeAgent("pentest") };
	const plainExec = { name: "bash", arguments: { command: "ls -la" }, agent: fakeAgent("pentest") };
	ok("无候选透传下游", (await listener(plainExec, async () => ({ kind: "allow" }))).kind === "allow");
	const ask = await listener(askExec, async () => ({ kind: "allow" }));
	ok("下游 allow 时以 ask 覆盖", ask.kind === "ask" && ask.reason.includes("账号"));
	ok("ask 提案落审计行", logs.length === 1 && logs[0].includes("| ask |"));
	const denyDownstream = await listener(askExec, async () => ({ kind: "deny", reason: "强门" }));
	ok("下游更强决策不被打断", denyDownstream.kind === "deny" && denyDownstream.reason === "强门");
	// 非安全模式/非 bash 工具：不触发
	const alien = await listener({ name: "bash", arguments: { command: "useradd x" }, agent: { ctx: { scope: "plain" }, session: { header: { cwd: WS } } } }, async () => ({ kind: "allow" }));
	ok("非安全模式不触发 ask", alien.kind === "allow");
	const notBash = await listener({ name: "fetch", arguments: { url: "http://t" }, agent: fakeAgent("pentest") }, async () => ({ kind: "allow" }));
	ok("非 bash 工具不触发 ask", notBash.kind === "allow");
	// askGate 关闭：透传
	const off = buildAskListener({ config: { askGate: false }, appendLog: () => {}, resolveMode: (agent) => agent.ctx.scope });
	ok("askGate=false 关闭", (await off(askExec, async () => ({ kind: "allow" }))).kind === "allow");
	ok("config 默认 askGate 开", Config({}).askGate === true);
}

// 14. deny 档不变：ask 层引入后 guard 硬拦语义原样
{
	const { guard } = makeGuard();
	ok("shutdown 仍硬拦（deny 档）", guard({ name: "bash", arguments: { command: "shutdown -h now" }, agent: fakeAgent("pentest") }) !== undefined);
	ok("useradd 不硬拦（归 ask 档）", guard({ name: "bash", arguments: { command: "useradd svc" }, agent: fakeAgent("pentest") }) === undefined);
}


// 15. 意图台账报告门（v1.2.0）：open 意图拦报告，收口/关闭开关放行
{
	const passLog = "| 2026-08-18T00:00:00Z | pentest/P3 | pass | - |\n";
	const state = { criteria: [{ id: "g1", status: "met" }], intents: [{ id: "i1", status: "open" }, { id: "i2", status: "done" }] };
	const mk = (st, cfg = {}) => buildGuard({
		config: cfg,
		readGateLog: () => passLog,
		readOperationState: () => st,
		appendLog: () => {},
		resolveMode: (a) => a.ctx.scope
	});
	const w = { name: "write", arguments: { file_path: path.join(WS, "reports/01.md"), content: "x" }, agent: fakeAgent("pentest") };
	const g = mk(state);
	const denied = g(w);
	ok("open intent blocks report write", typeof denied === "string" && denied.includes("意图台账") && denied.includes("i1") && !denied.includes("i2"));
	const closed = mk({ ...state, intents: [{ id: "i1", status: "blocked" }] })(w);
	ok("closed intent allows report write", closed === undefined);
	ok("no intents keeps old behavior", mk({ criteria: [{ id: "g1", status: "met" }] })(w) === undefined);
	ok("intentGate=false disables", mk(state, { intentGate: false })(w) === undefined);
}

// 16. redteam 任务书锚点守卫（v1.2.0）：缺依据行拦，补齐放行，非任务书不拦
{
	const { guard } = makeGuard();
	const brief = (content) => ({ name: "write", arguments: { file_path: path.join(WS, "task-briefs/t-001.md"), content }, agent: fakeAgent("redteam") });
	ok("任务书无依据行被拦", typeof guard(brief("# 任务书\n\n- 目标：审计 x 服务\n")) === "string" && guard(brief("# x\n")).includes("依据"));
	ok("任务书带依据行放行", guard(brief("# 任务书\n\n- 目标：x\n\n依据：用户要求对 x 服务做渗透（原话引用）\n")) === undefined);
	ok("锚点行也认", guard(brief("…\n锚点：pentest-3\n")) === undefined);
	ok("列表前缀容忍", guard(brief("…\n- 依据：材料 docs/收集.md\n")) === undefined);
	ok("非任务书路径不拦", guard({ name: "write", arguments: { file_path: path.join(WS, "summary.md"), content: "无锚" }, agent: fakeAgent("redteam") }) === undefined);
	ok("非 md 任务书路径不拦", guard({ name: "write", arguments: { file_path: path.join(WS, "task-briefs/t-001.json"), content: "{}" }, agent: fakeAgent("redteam") }) === undefined);
	ok("专业模式写任务书目录不拦（守卫仅总控）", guard({ name: "write", arguments: { file_path: path.join(WS, "task-briefs/t.md"), content: "无锚" }, agent: fakeAgent("pentest") }) === undefined);
	ok("redteam 无 content 的 write 不炸", guard({ name: "write", arguments: { file_path: path.join(WS, "task-briefs/t.md") }, agent: fakeAgent("redteam") }) === undefined);
}


// 17. 任务约束门（v1.3.0）：deny 带匹配词命中 bash/fetch 即拦；无匹配词/allow 不拦
{
	const mk = (st, cfg = {}) => buildGuard({
		config: cfg,
		readGateLog: () => "",
		readOperationState: () => st,
		appendLog: () => {},
		resolveMode: (a) => a.ctx.scope
	});
	const st = { criteria: [], constraints: [
		{ id: "c1", kind: "deny", text: "不碰支付接口", keywords: ["pay", "refund"] },
		{ id: "c2", kind: "deny", text: "只读原则（提示层）", keywords: [] },
		{ id: "c3", kind: "allow", text: "允许测 x 子域", keywords: ["x.example.com"] }
	] };
	const g = mk(st);
	const bashPay = { name: "bash", arguments: { command: "sqlmap -u https://t/api/pay/order?id=1 --batch" }, agent: fakeAgent("pentest") };
	const denied = g(bashPay);
	ok("deny 匹配词命中 bash 拦", typeof denied === "string" && denied.includes("c1") && denied.includes("不碰支付接口"));
	ok("fetch URL 命中拦", typeof g({ name: "fetch", arguments: { url: "https://t/refund/list" }, agent: fakeAgent("pentest") }) === "string");
	ok("无匹配词 deny 不拦（提示层归信封）", g({ name: "bash", arguments: { command: "rm -rf /tmp/x && echo done" }, agent: fakeAgent("pentest") }) === undefined || !String(g({ name: "bash", arguments: { command: "echo ok" }, agent: fakeAgent("pentest") })).includes("c2"));
	ok("allow 条目不拦", g({ name: "bash", arguments: { command: "nmap -sV x.example.com" }, agent: fakeAgent("pentest") }) === undefined);
	ok("大小写不敏感命中", typeof g({ name: "bash", arguments: { command: "sqlmap -u https://t/PAY/id=1" }, agent: fakeAgent("pentest") }) === "string");
	ok("无约束台账不拦", mk({ criteria: [] })({ name: "bash", arguments: { command: "curl https://t/pay" }, agent: fakeAgent("pentest") }) === undefined);
	ok("constraintGate=false 关", mk(st, { constraintGate: false })(bashPay) === undefined);
	ok("原有高危档优先于约束文案", (() => { const r = g({ name: "bash", arguments: { command: "shutdown -h now" }, agent: fakeAgent("pentest") }); return typeof r === "string" && r.includes("停机"); })());
}

// 16. 全局熔断（跨模式事实层）：标记文件存在拦全部工具，移除即恢复，开关可关
{
	const marker = path.join(os.tmpdir(), `kill-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`);
	process.env.DSH_KILL_SWITCH_FILE = marker;
	try {
		const { guard } = makeGuard();
		fs.writeFileSync(marker, "trip");
		ok("kill: 触发时 write 拦", guard({ name: "write", arguments: { file_path: path.join(WS, "assets.md") }, agent: fakeAgent("pentest") }) !== undefined);
		ok("kill: 触发时 bash 拦", guard({ name: "bash", arguments: { command: "ls" }, agent: fakeAgent("pentest") }) !== undefined);
		ok("kill: 非安全模式同样拦（跨模式事实层）", guard({ name: "bash", arguments: { command: "ls" }, agent: fakeAgent("cordis") }) !== undefined);
		ok("kill: 拦截文案含恢复方法", (() => { const r = guard({ name: "bash", arguments: { command: "ls" }, agent: fakeAgent("pentest") }); return (r?.reason ?? String(r)).includes("全局熔断已触发") && (r?.reason ?? String(r)).includes("移除标记文件"); })());
		fs.rmSync(marker, { force: true });
		ok("kill: 移除标记即恢复（无需重启）", guard({ name: "bash", arguments: { command: "ls" }, agent: fakeAgent("pentest") }) === undefined);
		fs.writeFileSync(marker, "trip");
		const { guard: gOff } = makeGuard({ killSwitch: false });
		ok("kill: 开关关闭时标记不生效", gOff({ name: "bash", arguments: { command: "ls" }, agent: fakeAgent("pentest") }) === undefined);
	} finally {
		fs.rmSync(marker, { force: true });
		delete process.env.DSH_KILL_SWITCH_FILE;
	}
}

// 17. ask 档 passwd 语境化（T2 考场首轮实测教训：裸子串误伤 /etc/passwd 读与字面量）
{
	ok("passwd 命令位命中（sudo passwd）", (() => { const r = scanAsk("sudo passwd root"); return r && r.reason.includes("账号/权限体系变更"); })());
	ok("chpasswd 管道位命中", (() => { const r = scanAsk("echo u:p | chpasswd"); return !!r; })());
	ok("行首 passwd 命中", (() => { const r = scanAsk("passwd testx"); return !!r; })());
	ok("/etc/passwd 读路径不误伤（LFI 验证正路）", scanAsk("curl -s 'http://t/fi/?page=/etc/passwd'") === undefined);
	ok("代码字符串字面量不误伤（probe: passwd）", scanAsk('echo "probe: passwd"') === undefined);
	ok("useradd 仍命中", (() => { const r = scanAsk("useradd testx"); return !!r; })());
}

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);

process.exit(fail ? 1 : 0);
