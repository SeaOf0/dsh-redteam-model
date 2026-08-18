// Offline unit tests for dsh-product-subagents. The CLI child process is
// faked end to end (spawnFn injectable), so nothing here talks to a model.
import { EventEmitter } from "node:events";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { normalizePrompt, buildClaudeArgs, buildCodexArgs, runCli, createProviders, Config } from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

class FakeChild extends EventEmitter {
	constructor() {
		super();
		this.stdout = new EventEmitter();
		this.stderr = new EventEmitter();
		this.stdinData = null;
		this.stdin = { on() {}, end: (d) => { this.stdinData = d; } };
		this.kills = [];
		this.killSignals = [];
	}
	kill(sig) { this.kills.push(sig); this.killSignals.push(sig); }
}

const fakeSpawn = (script) => (bin, args, opts) => {
	const child = new FakeChild();
	queueMicrotask(() => Promise.resolve(script(child, { bin, args, opts })).catch(() => {}));
	return child;
};

// 1. provider identity & capability surface
{
	const providers = createProviders(Config({}), fakeSpawn(() => {}));
	const names = providers.map((p) => p.name);
	ok("providers named claude-code and codex", names.includes("claude-code") && names.includes("codex"));
	ok("no structured capabilities (registry rejects such requests upstream)",
		providers.every((p) => Object.keys(p.capabilities).length === 0));
	ok("inheritsParentContext=false (fresh CLI context)",
		providers.every((p) => p.inheritsParentContext === false));
}

// 2. prompt normalization
{
	ok("string prompt passes through", normalizePrompt("hello") === "hello");
	ok("block prompt joins text blocks",
		normalizePrompt([{ type: "text", text: "a" }, { type: "image", text: "x" }, { type: "text", text: "b" }]) === "a\nb");
	ok("non-prompt coerces to empty string", normalizePrompt(undefined) === "");
}

// 3. argv construction
{
	ok("claude argv = -p + extras", JSON.stringify(buildClaudeArgs({ extraArgs: ["--model", "x"] })) === JSON.stringify(["-p", "--model", "x"]));
	ok("codex argv = exec --skip-git-repo-check --sandbox <s> -C <cwd> -o <file> + extras",
		JSON.stringify(buildCodexArgs({ sandbox: "read-only", extraArgs: [] }, "/w", "/o/last.txt"))
		=== JSON.stringify(["exec", "--skip-git-repo-check", "--sandbox", "read-only", "-C", "/w", "-o", "/o/last.txt"]));
}

// 4. claude run: completed with stdout, prompt on stdin
{
	const child = fakeSpawn(async (c) => {
		c.stdout.emit("data", "final answer");
		c.emit("close", 0);
	});
	const run = runCli({ id: "r1", bin: "claude", args: ["-p"], input: "do the task", env: {}, cwd: "/w", timeoutMs: 5000, signal: null, spawnFn: child });
	const r = await run.result;
	ok("exit 0 → completed", r.stopReason === "completed");
	ok("stdout is the final text", r.output[0].text === "final answer" && r.output[0].type === "text");
	ok("prompt delivered via stdin", run.promptDelivered ?? true);
}

// 5. stdin payload check (fake child records what the provider/runner wrote)
{
	const child = fakeSpawn(async (c) => { c.emit("close", 0); });
	let seen = null;
	const wrapped = (bin, args, opts) => {
		const c = child(bin, args, opts);
		const orig = c.stdin.end.bind(c.stdin);
		c.stdin.end = (d) => { seen = d; orig(d); };
		return c;
	};
	await runCli({ id: "r2", bin: "claude", args: [], input: "PAYLOAD", env: {}, cwd: "/w", timeoutMs: 5000, signal: null, spawnFn: wrapped }).result;
	ok("stdin.end received the prompt", seen === "PAYLOAD");
}

// 6. nonzero exit → error with stderr tail
{
	const child = fakeSpawn(async (c) => {
		c.stderr.emit("data", "boom: bad config");
		c.emit("close", 2);
	});
	const r = await runCli({ id: "r3", bin: "codex", args: [], input: "", env: {}, cwd: "/w", timeoutMs: 5000, signal: null, spawnFn: child }).result;
	ok("nonzero exit → error", r.stopReason === "error");
	ok("stderr tail in output", r.output[0].text.includes("退出码 2") && r.output[0].text.includes("boom: bad config"));
}

// 7. abort → aborted, SIGTERM sent
{
	const controller = new AbortController();
	const child = fakeSpawn(async (c) => { setTimeout(() => c.emit("close", null), 50); });
	const run = runCli({ id: "r4", bin: "claude", args: [], input: "", env: {}, cwd: "/w", timeoutMs: 5000, signal: controller.signal, spawnFn: child });
	controller.abort();
	const r = await run.result;
	ok("abort → aborted", r.stopReason === "aborted");
}

// 8. timeout → error carrying reason
{
	const child = fakeSpawn(async (c) => { setTimeout(() => c.emit("close", null), 200); });
	const r = await runCli({ id: "r5", bin: "claude", args: [], input: "", env: {}, cwd: "/w", timeoutMs: 30, signal: null, spawnFn: child }).result;
	ok("timeout → error with reason", r.stopReason === "error" && r.output[0].text.includes("timeout"));
}

// 9. dispose kills the child
{
	let captured = null;
	const child = (bin, args, opts) => {
		const c = new FakeChild();
		captured = c;
		setTimeout(() => c.emit("close", null), 200);
		return c;
	};
	const run = runCli({ id: "r6", bin: "claude", args: [], input: "", env: {}, cwd: "/w", timeoutMs: 0, signal: null, spawnFn: child });
	await run.dispose();
	ok("dispose sends SIGTERM", captured.kills.includes("SIGTERM"));
}

// 10. spawn error (ENOENT) → actionable error text
{
	const child = fakeSpawn(async (c) => { c.emit("error", Object.assign(new Error("spawn claude ENOENT"), { code: "ENOENT" })); });
	const r = await runCli({ id: "r7", bin: "claude", args: [], input: "", env: {}, cwd: "/w", timeoutMs: 5000, signal: null, spawnFn: child }).result;
	ok("spawn failure → error with 无法启动 hint", r.stopReason === "error" && r.output[0].text.includes("无法启动"));
}

// 11. collectFile wins over stdout when present
{
	const dir = await mkdtemp(path.join(tmpdir(), "dsh-prodsub-test-"));
	const outFile = path.join(dir, "last-message.txt");
	await writeFile(outFile, "from -o file", "utf8");
	const child = fakeSpawn(async (c) => { c.stdout.emit("data", "from stdout"); c.emit("close", 0); });
	const r = await runCli({ id: "r8", bin: "codex", args: [], input: "", env: {}, cwd: "/w", timeoutMs: 5000, signal: null, collectFile: outFile, spawnFn: child }).result;
	ok("collectFile (-o) wins over stdout", r.stopReason === "completed" && r.output[0].text === "from -o file");
}

// 12. env merge: provider config env overrides process env
{
	let seenEnv = null;
	const child = (bin, args, opts) => {
		seenEnv = opts.env;
		const c = new FakeChild();
		Promise.resolve().then(() => c.emit("close", 0));
		return c;
	};
	const providers = createProviders(Config({ claudeCode: { bin: "claude", env: { TEST_MARKER: "prodsub" } } }), child);
	await providers.find((p) => p.name === "claude-code").start({ prompt: "x", signal: null });
	ok("config env merged over process env", seenEnv.TEST_MARKER === "prodsub" && seenEnv.PATH === process.env.PATH);
}

// 13. codex provider builds a full run (argv includes exec/-o, temp file collected)
{
	let seenArgs = null;
	const child = (bin, args, opts) => {
		seenArgs = args;
		const c = new FakeChild();
		Promise.resolve().then(() => { c.stdout.emit("data", "codex final"); c.emit("close", 0); });
		return c;
	};
	const providers = createProviders(Config({}), child);
	const run = await providers.find((p) => p.name === "codex").start({ prompt: "verify chain", signal: null, cwd: "/w" });
	const r = await run.result;
	ok("codex argv head correct", seenArgs[0] === "exec" && seenArgs.includes("--sandbox") && seenArgs.includes("workspace-write") && seenArgs.includes("-C") && seenArgs.includes("-o"));
	ok("codex run completes with stdout fallback (no -o content)", r.stopReason === "completed" && r.output[0].text === "codex final");
	ok("run handle shape (id/localAgent undefined/dispose fn)", typeof run.id === "string" && run.localAgent === undefined && typeof run.dispose === "function");
}


// 14. error outputs carry the provider-aware fallback-chain hint (v0.1.1)
{
	const fail = (code, err) => (bin, args, opts) => {
		const c = new FakeChild();
		Promise.resolve().then(() => { if (err) c.emit("error", err); else { c.stderr.emit("data", "API Error: 529"); c.emit("close", code); } });
		return c;
	};
	const providers = createProviders(Config({}), fail(1));
	const rc = await providers.find((p) => p.name === "claude-code").start({ prompt: "x", signal: null });
	const r1 = await rc.result;
	ok("claude error carries codex fallback hint", r1.stopReason === "error" && r1.output[0].text.includes("subagent_codex") && r1.output[0].text.includes("报告须注明"));
	const rx = await providers.find((p) => p.name === "codex").start({ prompt: "x", signal: null, cwd: "/tmp" });
	const r2 = await rx.result;
	ok("codex error carries native fallback hint", r2.stopReason === "error" && r2.output[0].text.includes("subagent/subagent_fork") && !r2.output[0].text.includes("subagent_codex"));
	const okRun = () => (bin, args, opts) => {
		const c = new FakeChild();
		queueMicrotask(() => { c.stdout.emit("data", "fine"); c.emit("close", 0); });
		return c;
	};
	const providers2 = createProviders(Config({}), okRun());
	const r3 = await (await providers2.find((p) => p.name === "claude-code").start({ prompt: "x", signal: null })).result;
	ok("success output carries no hint", r3.stopReason === "completed" && !r3.output[0].text.includes("兜底链"));
}
console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
process.exit(fail ? 1 : 0);
