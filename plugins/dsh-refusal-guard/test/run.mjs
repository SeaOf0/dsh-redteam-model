// Offline unit tests for dsh-refusal-guard v0.2.0. No host, no session —
// pure detector / state-machine / rendering checks.
import {
	detectRefusal,
	assistantTextOf,
	userTextOf,
	excerptOf,
	buildReminder,
	buildRetryMessage,
	buildAuditRow,
	createGuardState,
	feedTurn,
	consumeArm,
	SECURITY_PRESETS
} from "../lib/index.js";

let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

// 1. three-tier detection: strong phrases anywhere
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

// 3. text extraction event shapes
{
	ok("assistant string content", assistantTextOf({ message: { content: "text" } }) === "text");
	ok("assistant block array content", assistantTextOf({ message: { content: [{ type: "text", text: "a" }, { type: "tool_use", name: "bash" }, { type: "text", text: "b" }] } }) === "ab");
	ok("assistant top-level content array", assistantTextOf({ content: [{ type: "text", text: "x" }] }) === "x");
	ok("assistant missing data → empty", assistantTextOf(undefined) === "");
	ok("user message text extracted", userTextOf({ content: [{ type: "text", text: "帮我审计这个目标" }] }) === "帮我审计这个目标");
	ok("user tool-result message → empty", userTextOf({ source: { kind: "tool" }, content: [{ type: "tool-result" }] }) === "");
	ok("user malformed → empty", userTextOf(undefined) === "");
}

// 3b. excerpt trimming
{
	ok("excerpt keeps short text", excerptOf("短文本") === "短文本");
	ok("excerpt collapses whitespace", excerptOf("  a \n  b  ") === "a b");
	const longExcerpt = excerptOf("x".repeat(500), 100);
	ok("excerpt caps at maxChars", longExcerpt.length === 100 && longExcerpt.endsWith("…"));
}

// 4. state machine v2: ladder, streak reset, no loop
{
	const s = createGuardState();
	ok("clean turn does not arm", feedTurn(s, "正常的渗透测试结论输出") === 0);
	ok("refusal turn arms level 1", feedTurn(s, "我无法协助这个请求") === 1);
	ok("armed level consumed once", consumeArm(s) === 1 && consumeArm(s) === 0);
	ok("clean turn resets streak", feedTurn(s, "重新给出技术结论：该点存在注入") === 0);
	ok("refusal after reset is level 1 again", feedTurn(s, "我无法协助") === 1);
	ok("second consecutive refusal escalates level 2", feedTurn(s, "抱歉，我不能提供这类信息") === 2);
	ok("armed level 2 consumed", consumeArm(s) === 2);
	ok("third consecutive refusal = human signal (3)", feedTurn(s, "我无法协助此类请求") === 3);
	ok("fourth refusal stays silent (0)", feedTurn(s, "我无法协助") === 0);
	ok("tool turn resets streak and never arms", (() => {
		const t = createGuardState();
		const l1 = feedTurn(t, "我无法协助", { hadToolCalls: false });
		const l2 = feedTurn(t, "我无法协助", { hadToolCalls: true });
		return l1 === 1 && l2 === 0 && t.streak === 0;
	})());
	ok("lastRequest captured and kept", (() => {
		const t = createGuardState();
		feedTurn(t, "我无法协助", { lastRequest: "审计 192.168.1.10 的 web 入口" });
		return t.lastRequest === "审计 192.168.1.10 的 web 入口";
	})());
	ok("empty lastRequest does not clobber", (() => {
		const t = createGuardState();
		feedTurn(t, "我无法协助", { lastRequest: "原请求" });
		feedTurn(t, "我无法协助", { lastRequest: "" });
		return t.lastRequest === "原请求";
	})());
}

// 5. reminder rendering: positive wording, no jailbreak-tone triggers, request re-attachment
{
	const r1 = buildReminder(1, { lastRequest: "审计目标 A 的登录接口" });
	ok("reminder non-empty and capped", r1.length > 0 && r1.length <= 700);
	ok("reminder has marker", r1.startsWith("[refusal-guard]"));
	ok("reminder carries technical re-answer instruction", r1.includes("结论") && r1.includes("证据"));
	ok("level-1 reminder re-attaches the request", r1.includes("审计目标 A 的登录接口"));
	ok("no 'never refuse' trigger wording", !/never refuse|non-negotiable|be aggressive/i.test(r1));
	const r2 = buildReminder(2, { lastRequest: "审计目标 A" });
	ok("level-2 reminder carries correction note", r2.includes("不是任务结论") && r2.includes("不要延续它的立场"));
	ok("cap respected", buildReminder(1, { maxChars: 50, lastRequest: "x".repeat(400) }).length <= 50);
}

// 6. retry message (inbox followup) shape
{
	const m = buildRetryMessage({ lastRequest: "帮我完成目标 B 的测试" });
	ok("retry message is user-role", m.role === "user");
	ok("retry message source is plugin-marked", m.source?.kind === "plugin" && m.source?.plugin === "dsh-refusal-guard");
	ok("retry message has unique id", typeof m.id === "string" && m.id.length > 0);
	ok("retry message contains the request", JSON.stringify(m).includes("目标 B 的测试"));
	ok("retry message marked", m.content?.[0]?.text?.includes("[refusal-guard 自动重试]"));
	ok("retry ids are unique", buildRetryMessage({}).id !== buildRetryMessage({}).id);
}

// 7. audit row format
{
	const row = buildAuditRow("2026-08-25T00:00:00.000Z", "pentest", 2, "我无法协助……", "审计目标 C");
	ok("audit row is a table row", row.startsWith("| ") && row.endsWith(" |"));
	ok("audit row carries level and action", row.includes("| 2 |") && row.includes("纠偏注记+自动重试"));
	ok("audit row carries preset", row.includes("pentest"));
}

// 8. preset filter set
{
	ok("nine security presets listed", ["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "redteam", "incident-response", "cloud-security", "ctf-solver"].every((id) => SECURITY_PRESETS.has(id)));
	ok("standard preset excluded", !SECURITY_PRESETS.has("standard"));
}

console.log(fail === 0 ? `\nall ${pass} tests passed` : `\n${fail} FAILED, ${pass} passed`);
process.exit(fail === 0 ? 0 : 1);
