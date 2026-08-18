// dsh-product-subagents — host-plane subagent providers for the local product CLIs.
//
// The security presets' composition rows name provider: "claude-code" and
// "codex" (tool-subagent, toolName subagent_claude_code / subagent_codex), but
// the shipped host registers only spawn/fork — those two rows sat waiting for
// providers that never arrived, and dsh-tool-subagent registers nothing while
// it waits (silent degradation). This plugin registers the two missing names.
//
// Shape: each provider spawns the CLI HEADLESS and maps the process outcome to
// the one-shot run contract (id / result{stopReason, output blocks} / dispose).
// The CLIs keep their own model backend (~/.claude/settings.json env,
// ~/.codex/config.toml) — this plugin passes no credentials, only a prompt on
// stdin and conservative defaults. Capabilities are all false: a CLI child
// cannot enforce outputSchema/depthLimit/toolFilter/persona, and the registry
// rejects requests asking for them before they reach the provider.

import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import z from "@deepseek-ai/schemastery";

const name = "dsh-product-subagents";
const inject = ["subagents"];

const ProviderConfig = z.object({
	bin: z.string(),
	timeoutMs: z.natural().default(600000),
	extraArgs: z.array(z.string()).default([]),
	env: z.object({}).default({})
});

const CodexProviderConfig = z.object({
	bin: z.string(),
	timeoutMs: z.natural().default(600000),
	extraArgs: z.array(z.string()).default([]),
	env: z.object({}).default({}),
	sandbox: z.string().default("workspace-write")
});

const Config = z.object({
	claudeCode: ProviderConfig.default({ bin: "claude" }),
	codex: CodexProviderConfig.default({ bin: "codex" })
});

const OUTPUT_CAP = 2 * 1024 * 1024; // per-stream accumulation cap
const SIGKILL_GRACE_MS = 5000;

/** Prompt arrives from the tool as blocks; a plain string is also accepted. */
export function normalizePrompt(prompt) {
	if (typeof prompt === "string") return prompt;
	if (Array.isArray(prompt)) {
		return prompt
			.filter((block) => block?.type === "text" && typeof block.text === "string")
			.map((block) => block.text)
			.join("\n");
	}
	return String(prompt ?? "");
}

const text = (t) => [{ type: "text", text: String(t) }];
const tail = (s, n = 2000) => (s.length > n ? `…${s.slice(-n)}` : s);

/** claude headless: prompt on stdin, final answer on stdout. */
export function buildClaudeArgs(config) {
	return ["-p", ...config.extraArgs];
}

/** codex headless: instructions on stdin, final message collected via -o.
 * `--skip-git-repo-check` because preset workspaces need not be git repos. */
export function buildCodexArgs(config, cwd, outFile) {
	return ["exec", "--skip-git-repo-check", "--sandbox", config.sandbox, "-C", cwd, "-o", outFile, ...config.extraArgs];
}

/**
 * Run one CLI child as a seam run handle ({id, localAgent, result, dispose}).
 * `spawnFn` is injectable for tests. Abort (signal) and dispose kill the child
 * (SIGTERM, SIGKILL after a grace period); a timeout kills it too and settles
 * as an error carrying the reason. `collectFile`, when set, wins over stdout
 * as the completed run's final text. Error outputs carry `fallbackHint` — the
 * persona 兜底链 rendered provider-aware, so the orchestrator model degrades
 * loudly (subagent_codex / native subagent) and notes the review method in
 * the report instead of retrying blindly. Silent in-plugin fallback to the
 * DSH LLM is deliberately NOT implemented: it would destroy cross-harness
 * double-sign independence invisibly .
 */
export function runCli({ id, bin, args, input, env, cwd, timeoutMs, signal, collectFile = "", fallbackHint = "", spawnFn = spawn }) {
	const child = spawnFn(bin, args, { env, cwd, stdio: ["pipe", "pipe", "pipe"] });
	let stdout = "";
	let stderr = "";
	let killed = false;
	let killedBy = "";
	let closed = false;
	let killer = null;
	const kill = (reason) => {
		if (closed || killed) return;
		killed = true;
		killedBy = reason;
		child.kill("SIGTERM");
		killer = setTimeout(() => child.kill("SIGKILL"), SIGKILL_GRACE_MS);
	};
	const onAbort = () => kill("abort");
	signal?.addEventListener("abort", onAbort, { once: true });
	const timer = timeoutMs > 0 ? setTimeout(() => kill("timeout"), timeoutMs) : null;
	child.stdout?.on("data", (d) => { if (stdout.length < OUTPUT_CAP) stdout += d; });
	child.stderr?.on("data", (d) => { if (stderr.length < OUTPUT_CAP) stderr += d; });
	const result = (async () => {
		try {
			if (child.stdin) {
				child.stdin.on("error", () => {}); // EPIPE when the CLI exits before reading stdin
				child.stdin.end(input);
			}
			const [code, spawnError] = await new Promise((resolve) => {
				child.on("error", (e) => resolve([-1, e]));
				child.on("close", (c) => resolve([c, null]));
			});
			closed = true;
			if (timer) clearTimeout(timer);
			if (killer) clearTimeout(killer);
			signal?.removeEventListener("abort", onAbort);
			if (spawnError) return { stopReason: "error", output: text(`无法启动 ${bin}：${spawnError.message}（本机未装该 CLI？）${fallbackHint}`) };
			if (killed) {
				if (killedBy === "abort") return { stopReason: "aborted", output: [] };
				return { stopReason: "error", output: text(`子代理进程被终止（${killedBy}）${stderr ? `\nstderr 尾部：\n${tail(stderr)}` : ""}${fallbackHint}`) };
			}
			let finalText = stdout.trim();
			if (collectFile) {
				try { finalText = (await readFile(collectFile, "utf8")).trim() || finalText; } catch {}
			}
			if (code === 0) return { stopReason: "completed", output: finalText ? text(finalText) : text("(CLI 无输出)") };
			return { stopReason: "error", output: text(`CLI 退出码 ${code}${stderr ? `\nstderr 尾部：\n${tail(stderr)}` : stdout ? `\nstdout 尾部：\n${tail(stdout)}` : ""}${fallbackHint}`) };
		} catch (e) {
			return { stopReason: "error", output: text(`子代理运行异常：${e?.message ?? e}`) };
		}
	})();
	return {
		id,
		localAgent: undefined,
		result,
		dispose() {
			kill("dispose");
			return Promise.resolve();
		}
	};
}

/**
 * One product-CLI provider. start() is async because codex needs a temp file
 * for -o before argv exists; the registry awaits start(), and a rejection
 * there is a failed delegation with no orphaned child.
 */
class CliSubagentProvider {
	providerName;
	kind;
	config;
	spawnFn;
	constructor(providerName, kind, config, spawnFn) {
		this.providerName = providerName;
		this.kind = kind;
		this.config = config;
		this.spawnFn = spawnFn;
	}
	get name() { return this.providerName; }
	capabilities = {};
	inheritsParentContext = false;
	async start(request) {
		const id = randomUUID();
		const input = normalizePrompt(request.prompt);
		const cwd = typeof request.cwd === "string" && request.cwd ? request.cwd : process.cwd();
		const env = { ...process.env, ...this.config.env };
		// Provider-aware 兜底链 hint (persona fallback chain, made loud on errors).
		const fallbackHint = this.kind === "claude"
			? "\n兜底链指引：claude 不可用 → 改用 subagent_codex；仍不可用 → DSH 原生 subagent/subagent_fork。降级后复核独立性变化，报告须注明实际复核方式。"
			: "\n兜底链指引：codex 不可用 → DSH 原生 subagent/subagent_fork。降级后复核独立性变化，报告须注明实际复核方式。";
		if (this.kind === "codex") {
			const dir = await mkdtemp(path.join(tmpdir(), "dsh-codex-"));
			const outFile = path.join(dir, "last-message.txt");
			const handle = runCli({
				id,
				bin: this.config.bin,
				args: buildCodexArgs(this.config, cwd, outFile),
				input, env, cwd,
				timeoutMs: this.config.timeoutMs,
				signal: request.signal,
				collectFile: outFile,
				fallbackHint,
				spawnFn: this.spawnFn
			});
			handle.result.finally(() => rm(dir, { recursive: true, force: true }).catch(() => {}));
			return handle;
		}
		return runCli({
			id,
			bin: this.config.bin,
			args: buildClaudeArgs(this.config),
			input, env, cwd,
			timeoutMs: this.config.timeoutMs,
			signal: request.signal,
			fallbackHint,
			spawnFn: this.spawnFn
		});
	}
}

export function createProviders(config, spawnFn) {
	return [
		new CliSubagentProvider("claude-code", "claude", config.claudeCode, spawnFn),
		new CliSubagentProvider("codex", "codex", config.codex, spawnFn)
	];
}

function apply(ctx, config) {
	for (const provider of createProviders(config)) ctx.subagents.registerProvider(provider);
}

export { Config, apply, inject, name };
