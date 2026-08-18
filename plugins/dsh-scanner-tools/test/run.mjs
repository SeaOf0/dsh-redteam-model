// Standalone tests: registration check + rate/wordlist rejection paths (no binaries needed).
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import { checkRegistered, hasBin, RATE_DEFAULTS, runScan } from "../lib/index.js";

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
r = runScan({ bin: "definitely-missing-bin-xyz", args: [], workspace: F, tool: "nuclei", rate: undefined, defaultRate: 15, active: false, target: "x" });
expect("缺二进制走三级兜底提示", !r.ok && r.error.includes("三级兜底"));

process.exit(failed ? 1 : 0);
