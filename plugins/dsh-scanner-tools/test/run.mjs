// Standalone tests: registration check + rate/wordlist rejection paths (no binaries needed).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import url from "node:url";
import { checkRegistered, hasBin, RATE_DEFAULTS, runScan, governPreview, spillOutput, breakerCheck, breakerRecord, runGoverned, runProcess, machinePressure, machineGate } from "../lib/index.js";
import { TOOL_DEFS, buildArgs, tiersLine } from "../lib/registry.js";

const F = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "fixture");
let failed = 0;
const expect = (n, c, d) => { if (c) console.log(`ok   ${n}`); else { failed++; console.log(`FAIL ${n} ${d ?? ""}`); } };

// checkRegistered
let r = checkRegistered(fs, F, "http://127.0.0.1:8081/x");
expect("已登记目标通过", r.ok);
r = checkRegistered(fs, F, "http://10.0.0.9/");
expect("未登记目标拒绝", !r.ok && r.hint.includes("防盲打"));
r = checkRegistered(fs, { readFileSync: () => { throw new Error("x"); } }, "http://a/");
expect("无 assets.md 拒绝并提示先过 Gate P1", !r.ok && r.hint.includes("Gate P1"));

// rate defaults sanity
expect("保守默认值齐备", RATE_DEFAULTS.nuclei === 15 && RATE_DEFAULTS.httpx === 25 && RATE_DEFAULTS.ffuf === 50);

// 缺字典拒绝（execute 层逻辑经由直接调用 runScan 不可达——此处验证 runScan 的未登记拦截独立于字典）
r = await runScan({ bin: "definitely-missing-bin-xyz", args: [], workspace: F, tool: "nuclei", rate: undefined, defaultRate: 15, active: false, target: "x" });
expect("缺二进制走三级兜底提示", !r.ok && r.error.includes("三级兜底"));

// ── 注册表参数模型 ──
let b = buildArgs(TOOL_DEFS.nmap, { target: "10.0.0.5" });
expect("nmap 默认参齐（-Pn -sT -sV --max-rate 1000）且无留痕", b.argv.join(" ").includes("-Pn -sT -sV") && b.argv.join(" ").includes("--max-rate 1000") && b.argv[b.argv.length - 1] === "10.0.0.5" && b.audit.length === 0);
b = buildArgs(TOOL_DEFS.nmap, { target: "10.0.0.5", ports: "80,443", rate: 5000 });
expect("flags/combined 生效+显式覆盖留痕", b.argv.includes("-p") && b.argv.includes("80,443") && b.audit.some((x) => x.includes("--max-rate 5000")));
let threw = false;
try { buildArgs(TOOL_DEFS.nmap, { target: "x", nope: 1 }); } catch { threw = true; }
expect("未知参数拒绝", threw);
threw = false;
try { buildArgs(TOOL_DEFS.nmap, { target: "a;rm" }); } catch { threw = true; }
expect("目标 shell 元字符拒绝", threw);
threw = false;
try { buildArgs(TOOL_DEFS.whatweb, { target: "https://a", aggression: 4 }); } catch { threw = true; }
expect("aggression 上限 3 护栏", threw);
b = buildArgs(TOOL_DEFS.subfinder, { domain: "example.com" });
expect("subfinder -d 域参数+默认参", b.argv.includes("-d") && b.argv.includes("example.com") && b.argv.includes("-silent"));
threw = false;
try { buildArgs(TOOL_DEFS.subfinder, {}); } catch { threw = true; }
expect("subfinder 缺域拒绝", threw);
b = buildArgs(TOOL_DEFS.nmap, { target: "10.0.0.5", extra: "-v --open" });
expect("extra 逃生门拆词+留痕", b.argv.includes("-v") && b.audit.some((x) => x.startsWith("extra:")));

// ── 六节点工具调用阶梯 ──
const tl = tiersLine(TOOL_DEFS.nmap);
expect("六节点阶梯文案（本机→MCP→替代→MCP 备选→问装→脚本）", tl.includes("1. 本机 nmap") && tl.includes("已装可代替工具") && tl.includes("询问用户是否安装") && tl.includes("6. 不批准则脚本编写") && tl.split("\n").length === 7);
expect("三工具 def 阶梯齐备", ["nmap", "subfinder", "whatweb"].every((k) => TOOL_DEFS[k].tiers.length === 6 && TOOL_DEFS[k].tiers[5].includes("脚本")));

// ── 输出治理：预览封顶 + 全文落盘 ──
const short = governPreview("x".repeat(100));
expect("短输出原样不截断", !short.truncated && short.preview.length === 100);
const long = governPreview("y".repeat(12000));
expect("长输出封顶（头尾+省略量+总字节）", long.truncated && long.preview.includes("中间省略") && long.bytes === 12000 && long.preview.length < 7000);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scan-gov-"));
const rel = spillOutput(fs, tmp, "nmap", "hello");
expect("全文落盘+相对路径回读指针", fs.readFileSync(path.join(tmp, rel), "utf8") === "hello" && rel.split(path.sep).join("/").startsWith("artifacts/tool-output/"));

// ── 熔断 ──
const t0 = 1_000_000;
breakerRecord("bt", false, t0);
breakerRecord("bt", false, t0 + 1);
expect("两次失败未熔断", breakerCheck("bt", t0 + 2) === 0);
breakerRecord("bt", false, t0 + 2);
expect("三次失败进 60s 冷却", breakerCheck("bt", t0 + 3) > 0 && breakerCheck("bt", t0 + 3) <= 60);
expect("冷却到期放行", breakerCheck("bt", t0 + 61_000) === 0);
breakerRecord("bt", true, t0 + 4);
expect("成功清零计数", breakerCheck("bt", t0 + 5) === 0);

// ── runGoverned 守卫与阶梯（不触真实二进制）──
const g = await runGoverned({ def: TOOL_DEFS.nmap, params: { target: "10.99.99.99", workspace: F }, workspace: F });
expect("nmap 防盲打：未登记目标拒绝（spawn 前）", !g.ok && g.error.includes("防盲打"));
const g2 = await runGoverned({ def: { ...TOOL_DEFS.nmap, bin: "definitely-missing-bin-xyz" }, params: { target: "127.0.0.1", workspace: F }, workspace: F });
expect("缺二进制返回六节点阶梯提示（绝不自动安装）", !g2.ok && g2.error.includes("绝不自动安装") && g2.error.includes("脚本"));

// ── 扩面七工具：默认参/护栏/开关/守卫 ──
expect("十工具 def 齐备且各带六节点阶梯", ["nmap", "masscan", "subfinder", "gau", "whatweb", "wafw00f", "dirsearch", "sqlmap", "nikto", "hydra"].every((k) => TOOL_DEFS[k].tiers.length === 6 && !!TOOL_DEFS[k].name && !!TOOL_DEFS[k].bin));
b = buildArgs(TOOL_DEFS.masscan, { target: "10.0.0.0/24", ports: "80,443" });
expect("masscan 默认 --rate 1000 + ports 必填入参", b.argv.join(" ").includes("--rate 1000") && b.argv.includes("-p") && b.argv.includes("80,443"));
threw = false;
try { buildArgs(TOOL_DEFS.masscan, { target: "x" }); } catch { threw = true; }
expect("masscan 缺 ports 拒绝", threw);
threw = false;
try { buildArgs(TOOL_DEFS.masscan, { target: "x", ports: "80", rate: 99999 }); } catch { threw = true; }
expect("masscan rate 硬上限 5000", threw);
b = buildArgs(TOOL_DEFS.sqlmap, { url: "http://a/?id=1" });
expect("sqlmap 保守默认（--batch level1 risk1 threads1）", b.argv.join(" ") === "--batch --level 1 --risk 1 --threads 1 -u http://a/?id=1");
b = buildArgs(TOOL_DEFS.sqlmap, { url: "http://a/?id=1", dbs: true, banner: true, risk: 2 });
expect("sqlmap 布尔开关入参 + risk 显式留痕", b.argv.includes("--dbs") && b.argv.includes("--banner") && b.audit.some((x) => x.includes("--risk 2")));
expect("sqlmap 危险开关不在白名单（--dump/--os-shell 仅经 extra 留痕）", !Object.values(TOOL_DEFS.sqlmap.args.switches).some((f) => /dump|os-shell|sql-shell/.test(f)));
b = buildArgs(TOOL_DEFS.hydra, { target: "10.0.0.5 ssh", passFile: "/tmp/p.txt" });
expect("hydra -f 首中即停 + -t 4 默认 + 组合位置参数在尾", b.argv.join(" ").includes("-f") && b.argv.join(" ").includes("-t 4") && b.argv[b.argv.length - 1] === "10.0.0.5 ssh");
b = buildArgs(TOOL_DEFS.dirsearch, { url: "http://a" });
expect("dirsearch -t 10 默认 + -u 入参", b.argv.join(" ").includes("-t 10") && b.argv.includes("-u"));
const guardIds = Object.values(TOOL_DEFS).filter((d) => d.guard.active).map((d) => d.id);
expect("主动扫描六件套防盲打；被动三件免登记", ["nmap", "masscan", "dirsearch", "sqlmap", "nikto", "hydra"].every((k) => guardIds.includes(k)) && !guardIds.includes("subfinder") && !guardIds.includes("gau") && !guardIds.includes("wafw00f"));
const g3 = await runGoverned({ def: TOOL_DEFS.dirsearch, params: { url: "http://10.99.99.99", workspace: F }, workspace: F });
expect("dirsearch targetParam=url 防盲打拒绝", !g3.ok && g3.error.includes("防盲打"));
const g4 = await runGoverned({ def: TOOL_DEFS.sqlmap, params: { url: "http://10.99.99.99/?id=1", workspace: F }, workspace: F });
expect("sqlmap targetParam=url 防盲打拒绝", !g4.ok && g4.error.includes("防盲打"));

// ── 攻防三件套：impacket / netexec / crackmapexec ──
expect("十三工具 def 齐备（含攻防三件套）", ["impacket", "netexec", "crackmapexec"].every((k) => TOOL_DEFS[k].tiers.length === 6 && !!TOOL_DEFS[k].name));
expect("impacket 双安装名候选（{module} 占位）", JSON.stringify(TOOL_DEFS.impacket.bins) === JSON.stringify(["impacket-{module}", "{module}.py"]));
expect("netexec/crackmapexec 双别名候选", JSON.stringify(TOOL_DEFS.netexec.bins) === JSON.stringify(["netexec", "nxc"]) && JSON.stringify(TOOL_DEFS.crackmapexec.bins) === JSON.stringify(["crackmapexec", "cme"]));
expect("netexec 与 crackmapexec 互为替代（阶梯第 3 级）", TOOL_DEFS.netexec.tiers[2].includes("crackmapexec") && TOOL_DEFS.crackmapexec.tiers[2].includes("netexec"));
b = buildArgs(TOOL_DEFS.netexec, { protocol: "smb", target: "10.0.0.0/24", user: "a", passPol: true, threads: 30 });
expect("netexec 协议打头+目标在尾+开关+threads 留痕", b.argv[0] === "smb" && b.argv[b.argv.length - 1] === "10.0.0.0/24" && b.argv.includes("--pass-pol") && b.argv.includes("-t") && b.audit.some((x) => x.includes("-t 30")));
b = buildArgs(TOOL_DEFS.crackmapexec, { protocol: "winrm", target: "10.0.0.5", hashes: ":abc123" });
expect("crackmapexec 同语法（--hashes 入参）", b.argv[0] === "winrm" && b.argv.includes("--hashes") && b.argv.includes(":abc123"));
threw = false;
try { buildArgs(TOOL_DEFS.netexec, { target: "10.0.0.5" }); } catch { threw = true; }
expect("netexec 缺 protocol 拒绝", threw);
b = buildArgs(TOOL_DEFS.impacket, { module: "secretsdump", target: "DOM/a@10.0.0.5", hashes: ":nt" });
expect("impacket 模块参数+hashes 入参", b.argv.includes("-hashes") && b.argv[b.argv.length - 1] === "DOM/a@10.0.0.5" && !b.argv.includes("secretsdump"));
const guardIds2 = Object.values(TOOL_DEFS).filter((d) => d.guard.active).map((d) => d.id);
expect("攻防三件套全部防盲打须登记", ["impacket", "netexec", "crackmapexec"].every((k) => guardIds2.includes(k)));
const g5 = await runGoverned({ def: TOOL_DEFS.netexec, params: { protocol: "smb", target: "10.99.99.0/24", workspace: F }, workspace: F });
expect("netexec 防盲打：未登记网段拒绝（spawn 前）", !g5.ok && g5.error.includes("防盲打"));
const g6 = await runGoverned({ def: TOOL_DEFS.impacket, params: { module: "secretsdump", target: "x@10.99.99.99", workspace: F }, workspace: F });
expect("impacket 防盲打：未登记目标拒绝", !g6.ok && g6.error.includes("防盲打"));

// ── 异步执行器回归：子进程运行期间事件循环不被阻塞 ──
// spawnSync 时代这里 ticks 恒为 0——nmap/semgrep 一跑整个 DSH 进程就冻住（本组即该缺陷的回归网）。
{
	let ticks = 0;
	const iv = setInterval(() => { ticks += 1; }, 20);
	const p = await runProcess(process.execPath, ["-e", "setTimeout(() => {}, 400)"], { timeoutMs: 20_000 });
	clearInterval(iv);
	expect("异步执行：子进程运行期间事件循环可调度（ticks>1）", p.status === 0 && ticks > 1, `ticks=${ticks}`);
	const t0b = Date.now();
	const t = await runProcess(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { timeoutMs: 500 });
	expect("异步执行：超时杀进程树并报 ETIMEDOUT", t.error?.code === "ETIMEDOUT" && Date.now() - t0b < 20_000, `elapsed=${Date.now() - t0b} status=${t.status}`);
	const o = await runProcess(process.execPath, ["-e", "process.stdout.write('x'.repeat(200000))"], { timeoutMs: 20_000, maxBuffer: 1000 });
	expect("异步执行：输出超限截断+记账（不丢结果、不卡管道）", o.status === 0 && o.stdout.length === 1000 && o.stderr.includes("输出超限"));
	// 心跳巡检：长静默子进程在 stderr 记巡检行（不误杀，进程照常跑完）
	const hb = await runProcess(process.execPath, ["-e", "setTimeout(() => process.stdout.write('done'), 3000)"], { timeoutMs: 20_000, inspectEveryMs: 1000 });
	expect("执行中巡检：静默超窗记心跳行且不误杀", hb.status === 0 && hb.stdout.includes("done") && /巡检.*已静默/.test(hb.stderr), `stderr=${JSON.stringify(hb.stderr.slice(0, 160))}`);
}

// ── 机器负载闸门：尺度随机器现状调整（osMod 注入离线验证三档判定与等待/拒绝）──
{
	const osOk = { cpus: () => [1, 2, 3, 4], loadavg: () => [1, 0, 0], freemem: () => 8 * 1024 * 1024 * 1024 };
	const osHigh = { cpus: () => [1, 2, 3, 4], loadavg: () => [9, 0, 0], freemem: () => 8 * 1024 * 1024 * 1024 };
	const osCrit = { cpus: () => [1, 2, 3, 4], loadavg: () => [20, 0, 0], freemem: () => 8 * 1024 * 1024 * 1024 };
	const osLowMem = { cpus: () => [1, 2, 3, 4], loadavg: () => [0.1, 0, 0], freemem: () => 100 * 1024 * 1024 };
	expect("机器闸门：正常负载放行不等待", machinePressure(osOk).level === "ok" && (await machineGate({ pollMs: 1, waitMs: 10, osMod: osOk })).ok);
	expect("机器闸门：高载判定 high / 严重过载判定 critical", machinePressure(osHigh).level === "high" && machinePressure(osCrit).level === "critical");
	expect("机器闸门：低内存按 critical 拒绝", machinePressure(osLowMem).level === "critical");
	expect("机器闸门：严重过载立即拒绝并给阶梯出口", !(await machineGate({ pollMs: 1, waitMs: 10, osMod: osCrit })).ok);
	const gCrit = await machineGate({ pollMs: 1, waitMs: 10, osMod: osCrit });
	expect("机器闸门：拒绝文案含机器状态与下级通道提示", gCrit.note.includes("机器压力未回落") && gCrit.note.includes("MCP"));
	const t0g = Date.now();
	const gHigh = await machineGate({ pollMs: 5, waitMs: 12, osMod: osHigh });
	expect("机器闸门：高载轮询等待，窗口耗尽转拒绝", !gHigh.ok && Date.now() - t0g >= 10 && gHigh.note.includes("已等待"));
}

process.exit(failed ? 1 : 0);
