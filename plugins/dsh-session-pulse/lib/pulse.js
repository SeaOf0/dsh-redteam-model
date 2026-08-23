// dsh-session-pulse pulse — 纯逻辑层（进度/子代理分组/提示词提取/模式门控）。
//
// 本文件是可测的单一事实源：client.js 内为镜像实现（client 侧无法相对引用本文件，
// 改动须双侧同步并保持逐行为等价——test/run.mjs 以本文件为准）。

/** 九模式名单（会话状态面板的作用域）。 */
export const PULSE_MODES = ["redteam", "pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];

export const MODE_LABELS = {
	redteam: "安全研究员", pentest: "渗透测试", "code-audit": "代码审计", "binary-analysis": "二进制分析",
	"attack-defense": "攻防评估", "av-evasion": "免杀对抗", "incident-response": "应急溯源", "cloud-security": "云安全攻防", "ctf-solver": "CTF 解题"
};

/** 会话摘要上的 agentPreset 是否属于九模式（列表源重启后可能退化为组合名，须走服务端兜底）。 */
export function modeOk(agentPreset, serverMode) {
	if (PULSE_MODES.includes(agentPreset)) return true;
	if (serverMode && PULSE_MODES.includes(serverMode)) return true;
	return false;
}

/** 任务进度：todos 投影（null=未用任务清单）→ {total, done, active, pending, pct, allDone}。 */
export function progressOf(todos) {
	if (!Array.isArray(todos) || todos.length === 0) return null;
	let done = 0, active = 0;
	for (const t of todos) {
		if (t && t.status === "completed") done++;
		else if (t && t.status === "in_progress") active++;
	}
	const total = todos.length;
	return { total, done, active, pending: total - done - active, pct: Math.round((done / total) * 100), allDone: done === total };
}

/**
 * 子代理目录分组：subagentsByParent[sessionId].entries（宿主 subagents.list 目录行）。
 * running=activity==="running"；已结束里 one-shot→已完成、continuable→已结束；按原序稳定。
 */
export function groupSubagents(catalog) {
	const entries = Array.isArray(catalog?.entries) ? catalog.entries : [];
	const running = [];
	const finished = [];
	for (const e of entries) {
		if (!e || typeof e.id !== "string") continue;
		const row = {
			id: e.id,
			label: String(e.label || e.id).slice(0, 80),
			mode: e.mode === "continuable" ? "continuable" : "one-shot",
			running: e.activity === "running",
			hasChildren: !!e.hasChildren,
			status: e.activity === "running" ? "running" : (e.mode === "continuable" ? "ended" : "completed")
		};
		(row.running ? running : finished).push(row);
	}
	return { running, finished };
}

export const SUB_STATUS_LABELS = { running: "运行中", completed: "已完成", ended: "已结束" };

/**
 * 提示词清单：会话 chat 快照（order + nodes）里的 user 节点按序提取。
 * 返回 [{ key, seq, time, text, preview }]——key 即 DOM 锚点（data-chat-anchor-key）。
 */
export function promptEntries(chat, previewMax = 160) {
	const order = chat?.order ?? [];
	const nodes = chat?.nodes;
	if (!nodes || typeof nodes.get !== "function") return [];
	const out = [];
	for (const key of order) {
		const node = nodes.get(key);
		const data = node?.data ?? node;
		if ((node?.kind ?? data?.kind) !== "user") continue;
		const text = textOf(data);
		if (!text) continue;
		out.push({ key, seq: Number(data.seq) || 0, time: Number(data.time) || 0, text, preview: clip(text, previewMax) });
	}
	return out;
}

/** user 节点 content 部件的纯文本（text 部件拼接；非文本部件跳过）。 */
export function textOf(data) {
	const parts = data?.content;
	if (!Array.isArray(parts)) return "";
	return parts.filter((p) => p && p.type === "text" && typeof p.text === "string").map((p) => p.text.trim()).filter(Boolean).join("\n");
}

/**
 * 子代理会话日志 → 抽屉内运行内容（转写条目）。
 * 事件按序：user/message=任务块 / assistant/message=文本（reasoning 跳过）/ tool/call=工具行。
 * 上限：条目 ≤ limits.entries（默认 600）、单条文本 ≤ limits.text（默认 900）、工具参数 ≤ limits.brief（默认 140）。
 */
export function parseTranscript(jsonlText, limits) {
	const lim = { entries: 600, text: 900, brief: 140, ...(limits ?? {}) };
	const out = [];
	if (typeof jsonlText !== "string") return out;
	for (const line of jsonlText.split("\n")) {
		if (out.length >= lim.entries) break;
		const raw = line.trim();
		if (!raw) continue;
		let ev;
		try { ev = JSON.parse(raw); } catch { continue; }
		if (!ev || typeof ev.type !== "string") continue;
		if (ev.type === "user/message") {
			const text = textOf(ev.data);
			if (text) out.push({ kind: "user", seq: Number(ev.seq) || 0, time: Number(ev.time) || 0, text: clip(text, lim.text) });
		} else if (ev.type === "assistant/message") {
			const text = textOf(ev.data?.message);
			if (text) out.push({ kind: "assistant", seq: Number(ev.seq) || 0, time: Number(ev.time) || 0, text: clip(text, lim.text) });
		} else if (ev.type === "tool/call") {
			out.push({ kind: "tool", seq: Number(ev.seq) || 0, time: Number(ev.time) || 0, name: String(ev.data?.name ?? "?").slice(0, 60), brief: clip(String(ev.data?.arguments ?? ""), lim.brief) });
		}
	}
	return out;
}

/** 预览裁剪（保留换行结构；超长加省略号）。 */
export function clip(text, max) {
	const t = String(text ?? "");
	return t.length > max ? t.slice(0, max) + "…" : t;
}

/** 卡片标题：第一个非空行裁剪（提示词记录卡的加粗标题）。 */
export function titleLine(text, max = 42) {
	const t = String(text ?? "").split("\n").map((l) => l.trim()).find(Boolean) ?? "";
	return t.length > max ? t.slice(0, max) + "…" : t;
}
