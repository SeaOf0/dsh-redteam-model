// Real-CLI smoke: one tiny prompt through each provider's true path.
import { createProviders, Config } from "../lib/index.js";

const providers = createProviders(Config({}));
for (const p of providers) {
	const t0 = Date.now();
	const run = await p.start({ prompt: "Reply with exactly: ok", signal: null, cwd: "/tmp" });
	const r = await run.result;
	console.log(p.name, "->", r.stopReason, JSON.stringify(String(r.output[0]?.text ?? "").slice(0, 120)), `(${Date.now() - t0}ms)`);
}
process.exit(0);
