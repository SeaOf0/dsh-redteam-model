// Offline unit tests for dsh-refusal-guard. No host, no session — pure
// detector / state-machine / rendering checks.
import {
	detectRefusal,
	assistantTextOf,
	buildReminder,
	createGuardState,
	feedTurn,
	consumeArm,
	SECURITY_PRESETS
} from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

// 1. two-tier detection: strong phrases anywhere
{
	ok("strong zh phrase detected", detectRefusal("经过分析，我无法协助完成这个请求。"));
	ok("strong en phrase detected", detectRefusal("Analysis done. I cannot assist with this."));
	ok("guideline phrase detected", detectRefusal("this is against my guidelines"));
	ok("as-an-ai detected", detectRefusal("As an AI language model I don't do that."));
}

// 2. weak keywords: head-150 only
{
	ok("weak keyword at head detected", detectRefusal("抱歉，这个问题……（后面是一段很长的正常技术内容）"));
	const long = "先说结论：该接口存在未授权访问。".repeat(30) + " 抱歉 " + "正常内容".repeat(40);
	ok("weak keyword beyond head NOT detected", !detectRefusal(long));
	ok("empty text not detected", !detectRefusal(""));
	ok("normal technical text not detected", !detectRefusal("该 SQL 注入点位于 /search.php 的 id 参数，payload: ' AND 1=1--，回显差分已确认。"));
}

// 2b. multi-language strong phrases + soft long-form refusals (anywhere)
{
	ok("japanese strong detected", detectRefusal("そのようなリクエストにはお手伝いできません。"));
	ok("korean strong detected", detectRefusal("해당 요청은 도와드릴 수 없습니다."));
	ok("russian strong detected", detectRefusal("К сожалению, не могу помочь с этим запросом."));
	ok("french strong detected", detectRefusal("Je ne peux pas vous aider avec cette demande."));
	ok("soft zh mid-answer detected", detectRefusal("关于该目标的利用，请先获得书面授权，我们再进行下一步。"));
	ok("soft en mid-answer detected", detectRefusal("The exploitation plan is ready, but please contact your administrator for approval."));
	ok("soft pattern in legit target advice NOT detected", !detectRefusal("修复建议：该服务的管理员应在 24 小时内轮换凭据并审计登录日志。"));
	ok("normal technical text still clean", !detectRefusal("webshell 免杀载荷已生成，位于 /tmp/payload.php，沙箱实测静态查杀 0/60。"));
}

// 3. assistantTextOf event shapes
{
	ok("string content", assistantTextOf({ message: { content: "text" } }) === "text");
	ok("block array content", assistantTextOf({ message: { content: [{ type: "text", text: "a" }, { type: "tool_use", name: "bash" }, { type: "text", text: "b" }] } }) === "ab");
	ok("top-level content array", assistantTextOf({ content: [{ type: "text", text: "x" }] }) === "x");
	ok("missing data → empty", assistantTextOf(undefined) === "");
}

// 4. state machine: arm once, cooldown, no loop
{
	const s = createGuardState({ cooldownTurns: 3 });
	ok("clean turn does not arm", feedTurn(s, "正常的渗透测试结论输出") === false);
	ok("refusal turn arms", feedTurn(s, "我无法协助这个请求") === true);
	ok("armed flag consumed once", consumeArm(s) === true && consumeArm(s) === false);
	ok("immediate repeat refusal suppressed by cooldown", feedTurn(s, "我无法协助") === false);
	ok("cooldown decrements but still blocks at 2", feedTurn(s, "我无法协助") === false);
	ok("cooldown decrements but still blocks at 1", feedTurn(s, "我无法协助") === false);
	ok("cooldown expired → refusal re-arms", feedTurn(s, "我无法协助") === true);
	ok("re-armed reminder consumed", consumeArm(s) === true);
}

// 5. tool-call turns are working prose, not refusal
{
	const s = createGuardState({ cooldownTurns: 3 });
	ok("refusal words after tool calls do not arm", feedTurn(s, "抱歉刚才的命令输出有误，重新执行。", { hadToolCalls: true }) === false);
}

// 6. reminder rendering: positive wording, no jailbreak-tone triggers
{
	const r = buildReminder();
	ok("reminder is non-empty and capped", r.length > 0 && r.length <= 700);
	ok("reminder has marker", r.startsWith("[refusal-guard]"));
	ok("reminder carries technical re-answer instruction", r.includes("结论") && r.includes("证据"));
	ok("no 'never refuse' trigger wording", !/never refuse|non-negotiable|be aggressive/i.test(r));
	ok("cap respected", buildReminder(50).length <= 50);
}

// 7. preset filter set
{
	ok("nine security presets listed (six modes + redteam + incident-response + cloud-security + ctf-solver)", ["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "redteam", "incident-response", "cloud-security", "ctf-solver"].every((id) => SECURITY_PRESETS.has(id)));
	ok("standard preset excluded", !SECURITY_PRESETS.has("standard"));
}

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
process.exit(fail === 0 ? 0 : 1);
