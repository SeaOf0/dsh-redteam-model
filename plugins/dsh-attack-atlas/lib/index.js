// dsh-attack-atlas — 攻击面图谱宿主插件。
//
// 三件事：
//   1) 类目体系：lib/taxonomy.js 纯数据（渗透模式首发 13 主类 × 9 形态 × 7 阶段）；
//   2) 覆盖态：模型侧 redteam_coverage_mark / redteam_coverage_stage / redteam_coverage_list
//      回写终态（会话 × 模式隔离），SQLite 落 ~/.dsh/attack-atlas/atlas.db；
//   3) Web 通道：webServer 自注册 /dsh-attack-atlas 前缀路由 + 同源信任栅栏；
//      会话标签页「攻击面图谱」读体系/读覆盖态/双击派单（followup 进当前会话）。
//
// 派单语义：双击格子/主类/阶段 = 把一条用户消息注入当前会话，模型按 playbook
// 对应章节开测，完成后经 redteam_coverage_mark 回写点亮——图谱即覆盖度参考标准。

import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { openStore, markCell, markStage, getCoverage, clearCoverage, addTarget, listTargets, removeTarget, switchTarget, addChainNode, addChainEdge, listChain, clearChain, CHAIN_NODE_KINDS, CHAIN_EDGE_TYPES, chainKindLabel, CELL_STATES, STAGE_STATES, TARGET_KINDS, targetKindLabel, saveMethod, listMethods, getMethod, removeMethod, copyMethod, exportMethods, importMethods, saveCap, listCaps, removeCap, exportCaps, importCaps, recordMiss, missSummary } from "./store.js";
import { TAXONOMIES, ATLAS_MODES, locate } from "./taxonomy.js";
import { validateMethod, methodRunMessage, inferTargetKind, METHOD_LIMITS } from "./method.js";

const name = "dsh-attack-atlas";
const inject = ["tools", "webServer", "webRuntime", "agentPresets"];

const ROUTE_PATH = "/dsh-attack-atlas";
/** 进程级 CSRF token：GET <route>/csrf 由同源页取走（跨源响应不可读），POST 须回带 x-dsh-csrf 头。 */
const CSRF_TOKEN = crypto.randomBytes(24).toString("hex");
export function checkCsrf(req, token) {
	return String(req?.headers?.["x-dsh-csrf"] ?? "") === String(token ?? "");
}
const MODE_LABELS = {
	pentest: "渗透测试模式",
	"code-audit": "代码审计模式",
	"binary-analysis": "二进制分析模式",
	"attack-defense": "攻防评估模式",
	"av-evasion": "免杀对抗模式",
	"incident-response": "应急溯源模式",
	"cloud-security": "云安全攻防模式",
	"ctf-solver": "CTF 解题模式"
};
for (const [_m, _tax] of Object.entries(TAXONOMIES)) _tax.id = _m; // 锚定生成器按模式取词
const DB_PATH = path.join(os.homedir(), ".dsh", "attack-atlas", "atlas.db");
const MAX_BODY = 1024 * 1024;

let store;
function theStore() {
	if (store === undefined) store = openStore(DB_PATH);
	return store;
}

//#region 通道与工具共用逻辑

/** 双击派单的注入文案（用户消息；模型按 playbook 对应章节执行并回写点亮）。 */
/** 各模式执行姿势词（派单文案用模式自己的语态，不统一用攻击措辞）。 */
const MODE_POSTURE = {
	pentest: "按 playbook 验证姿势执行（最小影响、非破坏性）",
	"code-audit": "按 playbook 审计姿势执行（扫描链禁网；结论须 sink 指位与复现链）",
	"attack-defense": "按 playbook 验证姿势执行（最小影响、非破坏性）",
	"cloud-security": "按 playbook 验证姿势执行（只读探测优先、最小影响）",
	"binary-analysis": "按 playbook 分析姿势执行（样本不外传；动态分析须隔离环境）",
	"av-evasion": "按 playbook 实验姿势执行（本地默认验证；授权目标按任务）",
	"incident-response": "按 playbook 取证姿势执行（先保全后分析、只读优先）",
	"ctf-solver": "按 playbook 解题姿势执行（平台规则内，flag 以平台回显为准）"
};
/** 各模式派单动词（头部语态）：应急是排查、代审是审计、二进制是分析、免杀是实验——不是所有模式都"开测"。 */
const MODE_VERB = {
	"code-audit": "审计",
	"binary-analysis": "分析",
	"incident-response": "排查",
	"av-evasion": "实验"
};
const verbOf = (taxonomy) => MODE_VERB[taxonomy?.id] || "开测";
const postureOf = (taxonomy) => MODE_POSTURE[taxonomy?.id] || MODE_POSTURE.pentest;
function trioWords(taxonomy) {
	const sl = taxonomy.stateLabels || {};
	return `${sl["tested-found"] || "已测·有发现"} / ${sl["tested-clear"] || "已测·未命中"} / ${sl.na || "N-A 附原因"}`;
}
/** 各模式主类派单的要求句：机制原子全模式统一（逐格推进+终态三选一+coverage_mark 回写+finding 登记），
 *  动词与纪律子句按各模式自己的方法论语态——pentest/attack-defense/cloud 走默认速率红线句。 */
const MODE_REQUIREMENT = {
	"code-audit": (trio) => `要求：子项逐格审计，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；finding 即 redteam_finding_register 登记（附复现链与 sink 指位，双链命中对账）；扫描链禁网，深度审计链按面映射推进。`,
	"binary-analysis": (trio) => `要求：子项逐格分析，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；有结论即 redteam_finding_register 登记（附能力与危害判定、IOC 假设指位）；静态优先、动态须隔离环境，样本外传须登记，假设台账同步更新。`,
	"av-evasion": (trio) => `要求：子项逐格实验，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；检出/过检即 redteam_finding_register 登记（附判定环境与判定依据）；判定环境以 experiment-plan 为基线不污染，本地默认验证。`,
	"incident-response": (trio) => `要求：子项逐格排查，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；查实 IOC/入侵痕迹即 redteam_finding_register 登记（附证据指位与时间线位置）；先保全后分析、只读优先，不扰动现场。`,
	"ctf-solver": (trio) => `要求：子项逐格推进，每格终态三选一（${trio}），逐格调用 redteam_coverage_mark 回写；解出即 redteam_finding_register 登记（附 flag 与解题路径）；平台规则即边界，题面登记与 challenge-board 同步。`
};
const requirementOf = (taxonomy, trio) => (MODE_REQUIREMENT[taxonomy?.id] ?? ((t) => `要求：子项逐格推进，每格终态三选一（${t}），逐格调用 redteam_coverage_mark 回写；发现即 redteam_finding_register 登记；速率与红线照 playbook 执行。`))(trio);
/** 覆盖提醒的收口纪律子句（finding 自动点亮后的余格提醒）：pentest/attack-defense/cloud 不附加
 *  （速率红线已在主类派单要求句），五模式附本模式收口时该带什么。 */
const MODE_CLOSE_HINT = {
	"code-audit": "——已审结论附 sink 指位与复现链（双链命中对账）",
	"binary-analysis": "——分析结论同步假设台账与 IOC 假设",
	"av-evasion": "——判定结果附判定环境与判定依据",
	"incident-response": "——查实项先保全证据（附证据指位与时间线位置）再标终态",
	"ctf-solver": "——解出项附 flag 与解题路径"
};
/** 各模式锚定三元组（对象称谓/登记指引+基线/边界纪律）——词取自各模式 playbook 的既有定义，
 *  pentest/attack-defense 为原生授权目标语义走默认文案。 */
const MODE_ANCHOR = {
	"code-audit": { word: "对象", obj: "审计对象", reg: "开工先确认仓库/版本范围并调 redteam_atlas_target 登记审计对象（应用/模块组/源码仓库）", baseline: "面映射基线（入口清单+sink 面）", discipline: "不超出约定审计范围", detail: "入口清单与 sink 面见面映射表" },
	"binary-analysis": { word: "样本", obj: "样本", reg: "先过样本登记（B0：sha256/形态/来源）并调 redteam_atlas_target 登记", baseline: "样本登记与假设台账", discipline: "按受理样本分析，样本外传须登记", detail: "样本档案与假设台账见 B0 登记产物" },
	"av-evasion": { word: "对象", obj: "在验载荷", reg: "先调 redteam_atlas_target 登记实验对象（生成的 shell/载荷/引擎族）", baseline: "experiment-plan 判定环境清单", discipline: "本地默认验证；授权目标按任务执行", detail: "判定环境与实验课题见 experiment-plan" },
	"incident-response": { word: "范围", obj: "调查对象", reg: "受理后先调 redteam_atlas_target 登记调查对象（受侵主机/案件）", baseline: "证据保全清单", discipline: "先保全后分析，不超出受理范围", detail: "主机与证据明细见保全清单" },
	"cloud-security": { word: "目标", obj: "云目标", reg: "先调 redteam_atlas_target 登记云目标（账号/租户/集群）", baseline: "cloud-assets.md 测绘基线", discipline: "只读探测优先；环境改动逐项登记还原", detail: "资产明细见 cloud-assets.md 暴露面测绘" },
	"ctf-solver": { word: "对象", obj: "题目", reg: "先调 redteam_atlas_target 登记题目/赛局", baseline: "challenge-board.md 题面登记", discipline: "平台规则即边界", detail: "题面与解题进度见 challenge-board" }
};
/** 锚定行：当前锚定突出 + 其余已登记（换对象先 switch 切锚，回写缺省归当前锚定）。
 *  无激活（外部直调容错）平铺全清单；八模式分语态词（MODE_ANCHOR）套同一结构。 */
function anchorLines(taxonomy, targets) {
	const cfg = MODE_ANCHOR[taxonomy?.id ?? ""];
	const word = cfg ? cfg.word : "目标";
	if (!targets || targets.length === 0) {
		if (cfg) return `${cfg.word}锚定：本会话尚未登记${cfg.obj}——${cfg.reg}（与${cfg.baseline}同步），${cfg.discipline}。`;
		return "目标锚定：本会话尚未登记目标——开测前先确认授权目标（单位/资产域，组织类 kind=org）并调 redteam_atlas_target 登记（与资产清单基线 assets.md 同步），严格不超出授权范围。";
	}
	const labelOf = (t) => `「${t.label}」${targetKindLabel(t.kind)}`;
	const tail = cfg
		? `（${cfg.detail}；换${cfg.word}作业先 redteam_atlas_target switch 切锚再回写，回写不带 target 默认归当前锚定，异${cfg.obj}须带 target 参数注明；N-A 须注明对哪个${cfg.obj}不具备）`
		: `（资产明细见 assets.md/入口面盘点表；换目标作业先 redteam_atlas_target switch 切锚再回写，回写不带 target 默认归当前锚定，异目标须带 target 参数注明；N-A 须注明对哪个目标不具备）`;
	const act = targets.find((t) => t.active);
	if (!act) return `${word}锚定：${targets.map(labelOf).join("、")}${tail}`;
	const rest = targets.filter((t) => t !== act).map(labelOf).join("、");
	return `${word}锚定：当前锚定 ${labelOf(act)}${rest ? `；其余已登记：${rest}` : ""}${tail}`;
}
export function triggerMessage(taxonomy, payload) {
	const formLabel = payload.formId && payload.formId !== "all"
		? `｜形态「${(taxonomy.forms.find((f) => f.id === payload.formId) || {}).label || payload.formId}」` : "";
	if (payload.level === "chain-gen") {
		return [
			"[AttackAtlas·链路拓扑生成] 请依据本会话整体上下文（evidence-index 攻击图 links、已获权限/凭据、突破路径）登记攻击链拓扑：",
			`① redteam_atlas_chain add-node 逐个登记节点（kind：${Object.entries(taxonomy.chainKinds || {}).map(([id, m]) => id + " " + m.label).join("/") || "entry 入口/host 主机/segment 网段关口/bastion 堡垒机/dc 域控/cred 凭据"}；重大成果节点 major=true；seg 填网段如 10.1.1.x）`,
			"② add-edge 登记边——优先带 edgeType 类型化（discovered_on 在…发现 / exploits 利用 / enables 使可行 / depends_on 前置依赖 / leads_to 导致），label 补动作细节（获取权限/凭据复用/隔离突破/密码抓取/域控获取…）；多入口/无拓扑按实际登记，不虚构。",
			"登记即自动成图（「链路拓扑图」弹窗实时刷新）。"
		].join("\n");
	}
	if (payload.level === "stage") {
		const stage = taxonomy.stages.find((s) => s.id === payload.stageId);
		return [
			`[AttackAtlas·阶段推进] 进入阶段「${stage ? stage.label : payload.stageId}」（${taxonomy.label}模式作战流程）。`,
			`按 playbook 该阶段章节执行；完成后调用 redteam_coverage_stage(stage="${payload.stageId}", state="done") 回写点亮。`,
			anchorLines(taxonomy, payload.targets)
		].join("\n");
	}
	if (payload.level === "category") {
		const category = taxonomy.categories.find((c) => c.id === payload.categoryId);
		return [
			`[AttackAtlas·主类派单] 对主类「${category ? category.label : payload.categoryId}」整组${verbOf(taxonomy)}（${taxonomy.label}模式${formLabel}）。`,
			requirementOf(taxonomy, trioWords(taxonomy)),
			anchorLines(taxonomy, payload.targets)
		].join("\n");
	}
	const loc = locate(taxonomy, `${payload.categoryId}/${payload.itemId}`);
	const category = loc?.category;
	const item = loc?.item;
	let refHint = "";
	if (item?.ref) { const pre = `${verbOf(taxonomy)}前先读`; refHint = item.ref.startsWith("pentest:") ? `\n知识手册：pentest refs/${item.ref.slice(8)}（${pre}）` : item.ref === "README.md" ? `\n知识手册：refs/README.md（按目标语言快速路由到对应语言手册后再读——语言类格子不预设语言）` : `\n知识手册：refs/${item.ref}（${pre}）`; }
	else if (item?.pb) refHint = `\n打法出处：本模式 playbook ${item.pb}`;
	return [
		`[AttackAtlas·格子派单] 对以下格子${verbOf(taxonomy)}（${taxonomy.label}模式${formLabel}）：`,
		`主类「${category ? category.label : payload.categoryId}」｜子项「${item ? item.label : payload.itemId}」${refHint}`,
		`${postureOf(taxonomy)}；终态三选一（${trioWords(taxonomy)}），完成后调用 redteam_coverage_mark 回写点亮；有发现即 redteam_finding_register 登记。`,
		anchorLines(taxonomy, payload.targets)
	].join("\n");
}

function sessionOf(ctx, exec) {
	const agent = exec?.agent;
	const id = agent?.session?.id;
	if (!id) return undefined;
	let preset;
	try { preset = ctx.agentPresets?.composedPreset?.(agent.ctx); } catch { /* 组合未就绪 */ }
	if (typeof preset !== "string") preset = agent?.session?.header?.agentPreset;
	return { id: String(id), mode: ATLAS_MODES.includes(preset) ? preset : undefined };
}

function resolveAgents(ctx) {
	try { return ctx.get("agents"); } catch { /* 该 fiber 未声明 agents */ }
	try { return ctx.agents; } catch { /* 同上 */ }
	return undefined;
}

/** 会话真实模式的权威源：agents 注册表 → composedPreset（列表源重启后可能退化为组合名）。
 *  工具路径（sessionOf/exec）与事件路径（仅 sessionId）共用。 */
function modeOfSession(ctx, sessionId) {
	const agents = resolveAgents(ctx);
	const agent = agents?.get?.(sessionId);
	let mode = "";
	try { mode = String(ctx.agentPresets?.composedPreset?.(agent?.ctx) ?? ""); } catch { /* 组合未就绪 */ }
	if (!ATLAS_MODES.includes(mode)) {
		const header = agent?.session?.header?.agentPreset;
		mode = ATLAS_MODES.includes(header) ? header : "";
	}
	return mode;
}

/** 合并类目：内置 taxonomy 副本 + 本模式自定义主类/子类（key 同构；_cap 携带自定义元数据）。
 *  方法论的校验/定位/信封全部走合并版——自定义模块自动被认得。
 *  自定义项的适用形态（forms 串）解析为数组并入合并树：矩阵形态过滤/形态切换对自定义格同样生效。 */
function capFormsOf(taxonomy, raw) {
	const ids = new Set((taxonomy.forms || []).map((f) => f.id));
	return String(raw ?? "").split(/[,，;；\s]+/).map((s) => s.trim()).filter((s) => ids.has(s));
}
export function taxonomyWithCaps(st, taxonomy, mode) {
	const caps = listCaps(st, mode);
	const itemsByCat = {};
	for (const c of caps) if (c.kind === "item") (itemsByCat[c.cat] = itemsByCat[c.cat] || []).push(c);
	const capItemNode = (i) => {
		const fs = capFormsOf(taxonomy, i.forms);
		return { id: i.item, label: i.label, ref: i.ref || undefined, pb: i.pb || undefined, ...(fs.length ? { forms: fs } : {}), _cap: i };
	};
	const categories = taxonomy.categories.map((c) => {
		const extra = (itemsByCat[c.id] || []).map(capItemNode);
		return extra.length ? { ...c, items: c.items.concat(extra) } : c;
	});
	const formCategories = { ...(taxonomy.formCategories || {}) };
	for (const c of caps) {
		if (c.kind !== "category") continue;
		const fs = capFormsOf(taxonomy, c.forms);
		for (const f of fs) formCategories[f] = [...(formCategories[f] || []), c.cat]; // 克隆追加，不污染内置数组
		categories.push({ id: c.cat, label: c.label, desc: c.descr, ...(fs.length ? { forms: fs } : {}), _cap: c, items: (itemsByCat[c.cat] || []).map(capItemNode) });
	}
	return { ...taxonomy, categories, formCategories };
}

//#region 词典治理：标签等价与报错带候选

const LABEL_STRIP = /[\s·•,，、。.；;：:！!？?（）()\[\]【】「」『』/／\-—_~*"'`|｜\\#]/g;
const FUZZY_MIN = 0.45;    // bigram Dice 最低分：低于不认（宁拒勿猜）
const FUZZY_MARGIN = 1.25; // 最佳与次佳须拉开倍率（防歧义误亮）
const FUZZY_INCOV = 0.6;   // 输入侧 bigram 覆盖率：垃圾串只零星命中即拒（ghost-cat 类假阳性）

function normLabel(s) {
	// 剥行首序号前缀（"9 SQL 注入"→"sql注入"）：部分体系标签带列表序号，序号非语义且破坏词边界匹配；
	// 仅剥 1-2 位数字+分隔符（空白/./、），不误伤 0day/2FA 这类前缀无分隔符的语义数字。
	return String(s ?? "").toLowerCase().normalize("NFKC").replace(/^\d{1,2}[\s.、．]+/, "").replace(LABEL_STRIP, "");
}
function bigramSet(s) {
	const set = new Set();
	for (let i = 0; i < s.length - 1; i++) set.add(s.slice(i, i + 2));
	return set;
}
function diceScore(a, b) {
	if (!a || !b) return 0;
	const A = bigramSet(a), B = bigramSet(b);
	if (!A.size || !B.size) return 0;
	let hit = 0;
	for (const g of A) if (B.has(g)) hit++;
	return (2 * hit) / (A.size + B.size);
}

function keyLabel(taxonomy, key) {
	const [catId, itemId] = String(key).split("/");
	const cat = taxonomy.categories.find((c) => c.id === catId);
	if (!cat) return key;
	if (itemId === undefined) return cat.label;
	return `${cat.label}/${cat.items.find((i) => i.id === itemId)?.label ?? itemId}`;
}

/** 在一组候选（item 或 category）里按 标签全等 → 包含 → bigram Dice 选出唯一解。
 *  返回 { ok, best, second, top }——ok=Dice 过阈、与次佳拉开倍率、且输入侧覆盖率达标。 */
function bestOf(cands, norm) {
	const inputGrams = bigramSet(norm);
	let best = null, second = 0;
	for (const c of cands) {
		const grams = bigramSet(normLabel(c.label));
		let hit = 0;
		for (const g of inputGrams) if (grams.has(g)) hit++;
		const score = inputGrams.size && grams.size ? (2 * hit) / (inputGrams.size + grams.size) : 0;
		const inputCov = inputGrams.size ? hit / inputGrams.size : 0;
		if (!best || score > best.score) { if (best) second = best.score; best = { ...c, score, inputCov }; }
		else if (score > second) second = score;
	}
	const top = cands.map((c) => { const grams = bigramSet(normLabel(c.label)); let hit = 0; for (const g of inputGrams) if (grams.has(g)) hit++; return { ...c, score: inputGrams.size && grams.size ? (2 * hit) / (inputGrams.size + grams.size) : 0 }; }).sort((a, b) => b.score - a.score).slice(0, 5);
	const ok = !!(best && inputGrams.size >= 3 && best.score >= FUZZY_MIN && best.score >= FUZZY_MARGIN * Math.max(second, 0.01) && best.inputCov >= FUZZY_INCOV);
	return { ok, best, top };
}

/** 解析覆盖 key：canonical id（含 cat/中文子项混合形）→ 标签全等 → 包含 → Dice 模糊。
 *  返回 { key, catId, itemId? }（解析成功）/ { ambiguous: [...] } / { missingItem: {...} } / null。
 *  实测锚点：「任意上传RCE」→ rce-main/upload-rce（Dice）；「深度反序列化」→ rce-main/deep-deser（全等）。 */
export function resolveKey(taxonomy, input) {
	const raw = String(input ?? "").trim();
	if (!raw) return null;
	const norm = normLabel(raw);
	if (!norm) return null;
	// 模式词表别名（如 ad 战果词「域控成果」→domain-attack 主类）：结果名词与技法标签的桥接，
	// 别名与标签同源维护（taxonomy.aliases）——mark/sync/自动点亮全入口同享。值支持主类 id 或 cat/item。
	for (const [aliasKey, ref] of Object.entries(taxonomy.aliases ?? {})) {
		if (normLabel(aliasKey) === norm) {
			if (String(ref).includes("/")) {
				const [cId, iId] = String(ref).split("/");
				const c = taxonomy.categories.find((x) => x.id === cId);
				if (c?.items.some((it) => it.id === iId)) return { key: String(ref), catId: cId, itemId: iId, via: "alias" };
			} else {
				const c = taxonomy.categories.find((x) => x.id === ref);
				if (c) return { key: c.id, catId: c.id, via: "alias" };
			}
		}
	}
	if (raw.includes("/")) {
		const idx = raw.indexOf("/");
		const catId = raw.slice(0, idx), itemIdRaw = raw.slice(idx + 1);
		const cat = taxonomy.categories.find((c) => c.id === catId);
		if (cat) {
			if (cat.items.some((it) => it.id === itemIdRaw)) return { key: `${catId}/${itemIdRaw}`, catId, itemId: itemIdRaw, via: "id" };
			const items = cat.items.map((it) => ({ key: `${catId}/${it.id}`, catId, itemId: it.id, label: it.label }));
			for (const it of items) if (normLabel(it.label) === normLabel(itemIdRaw)) return { ...it, via: "label" };
			const hits = items.filter((it) => { const l = normLabel(it.label); return l.includes(normLabel(itemIdRaw)) || normLabel(itemIdRaw).includes(l); });
			if (hits.length === 1) return { ...hits[0], via: "contains" };
			const b = bestOf(items, normLabel(itemIdRaw));
			if (b.ok) return { key: b.best.key, catId, itemId: b.best.itemId, via: "fuzzy" };
			if (b.best && b.best.score >= FUZZY_MIN) return { ambiguous: b.top.filter((x) => x.score >= FUZZY_MIN).map((x) => ({ key: x.key, catId, itemId: x.itemId })) };
			return { missingItem: { catId, input: raw } };
		}
	}
	const allItems = [];
	for (const c of taxonomy.categories) for (const it of c.items) allItems.push({ key: `${c.id}/${it.id}`, catId: c.id, itemId: it.id, label: it.label });
	for (const it of allItems) if (normLabel(it.label) === norm) return { ...it, via: "label" };
	const catExact = taxonomy.categories.find((c) => normLabel(c.label) === norm);
	if (catExact) return { key: catExact.id, catId: catExact.id, via: "label" };
	// 包含命中判定：短 ASCII 线索（≤4 字符）要求词边界匹配——防 "RCE" 经 "sourcemap" 这类
	// 嵌入子串误报（边界两侧不得是字母数字）；中文线索不受影响。
	const shortAscii = /^[a-z0-9]{1,4}$/.test(norm);
	const tokenHit = (label) => {
		const l = normLabel(label);
		if (l.includes(norm)) {
			if (!shortAscii) return true;
			let i = l.indexOf(norm);
			while (i !== -1) {
				const before = i === 0 ? "" : l[i - 1];
				const after = i + norm.length >= l.length ? "" : l[i + norm.length];
				if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) return true;
				i = l.indexOf(norm, i + 1);
			}
			return false;
		}
		return norm.includes(l);
	};
	const hits = allItems.filter((it) => tokenHit(it.label));
	const catHits = taxonomy.categories.filter((c) => tokenHit(c.label));
	if (hits.length === 1) return { ...hits[0], via: "contains" };
	if (hits.length > 1) {
		// 多命中取舍：前缀命中优先（标签以线索开头=最贴题，如「未授权」→「未授权访问…」而非
		// 「LLM API 未授权与密钥泄露」）；其后取最短标签（最简释义）；同长才是真歧义
		// （「上传」命中多个上传格）——歧义拒并报候选，不静默选边。
		const prefixed = hits.filter((it) => normLabel(it.label).startsWith(norm));
		const pool = prefixed.length ? prefixed : hits;
		if (pool.length === 1) return { ...pool[0], via: "contains" };
		const byLen = [...pool].sort((a, b) => normLabel(a.label).length - normLabel(b.label).length);
		if (normLabel(byLen[0].label).length < normLabel(byLen[1].label).length) return { ...byLen[0], via: "contains" };
		return { ambiguous: byLen.slice(0, 6).map((h) => ({ key: h.key, catId: h.catId, itemId: h.itemId })) };
	}
	if (catHits.length === 1) return { key: catHits[0].id, catId: catHits[0].id, via: "contains" };
	// 短 ASCII 线索（≤4 字符）禁走全局模糊：bigram Dice 会跨词误中（CSRF↔SSRF 得 0.667 过阈）——
	// 词边界闸只在包含级，模糊级没有；短词宁拒不猜（命中靠 contains/别名/全等已足够）。
	if (shortAscii) return null;
	const bi = bestOf(allItems, norm);
	const bc = bestOf(taxonomy.categories.map((c) => ({ key: c.id, catId: c.id, label: c.label })), norm);
	if (bi.ok && (!bc.best || bi.best.score >= bc.best.score)) return { key: bi.best.key, catId: bi.best.catId, itemId: bi.best.itemId, via: "fuzzy" };
	if (bc.ok) return { key: bc.best.key, catId: bc.best.key, via: "fuzzy-cat" };
	if (bi.best && bi.best.score >= FUZZY_MIN && bi.best.inputCov >= FUZZY_INCOV) return { ambiguous: bi.top.filter((x) => x.score >= FUZZY_MIN).map((x) => ({ key: x.key, catId: x.catId, itemId: x.itemId })) };
	return null;
}

export function canonicalKey(taxonomy, input) {
	const res = resolveKey(taxonomy, input);
	return res?.key ?? undefined;
}

/** 覆盖 key 对合并体系的存在性校验：拼错即拒（否则终态落库但矩阵永不渲染——静默丢失）。
 *  key 形如 cat（主类整组）或 cat/item；亦接受主类/子类中文标签；报错必带合法候选（R2）。 */
export function validateCoverageRef(taxonomy, key) {
	const raw = String(key ?? "").trim();
	if (!raw) return "key 不能为空（形如 cat/item 或 cat，也接受主类/格子中文标签）";
	const res = resolveKey(taxonomy, raw);
	if (res?.key) return "";
	if (res?.missingItem) {
		const cat = taxonomy.categories.find((c) => c.id === res.missingItem.catId);
		return `子项不存在：「${raw}」——主类「${cat?.label ?? res.missingItem.catId}」合法子项：${(cat?.items ?? []).map((it) => `${it.label}(${cat.id}/${it.id})`).join("、")}`;
	}
	if (res?.ambiguous) return `「${raw}」无法唯一解析（命中多格）：${res.ambiguous.map((a) => keyLabel(taxonomy, a.key)).join("、")}——请写完整标签或 cat/item 形式 key`;
	return `主类不存在：「${raw}」（不在${taxonomy.label}体系）。合法主类：${taxonomy.categories.map((c) => `${c.label}(${c.id})`).join("、")}；key=主类id 或 主类id/子项id，也接受中文标签`;
}

/** 阶段解析：canonical id → 标签全等/包含 → Dice。 */
export function resolveStageId(taxonomy, input) {
	const raw = String(input ?? "").trim();
	if (!raw) return "";
	const stages = taxonomy.stages ?? [];
	for (const s of stages) if (s.id === raw) return s.id;
	const norm = normLabel(raw);
	for (const s of stages) if (normLabel(s.label) === norm) return s.id;
	for (const s of stages) { const l = normLabel(s.label); if (l.includes(norm) || norm.includes(l)) return s.id; }
	const b = bestOf(stages.map((s) => ({ key: s.id, label: s.label })), norm);
	return b.ok ? b.best.key : "";
}

/** 阶段 id 对体系的存在性校验（同上——防拼错静默丢失；报错带全量阶段清单）。 */
export function validateStageRef(taxonomy, stage) {
	const raw = String(stage ?? "").trim();
	if (resolveStageId(taxonomy, raw)) return "";
	return `阶段不存在：「${raw}」（不在${taxonomy.label}作战流程）。合法阶段：${(taxonomy.stages ?? []).map((s) => `${s.id} ${s.label}`).join("、")}——也接受阶段中文标签`;
}

//#endregion

//#region 终态标签等价 + 覆盖表批量同步（P2）

const STATE_ALIASES = [
	["tested-found", ["已测有发现", "已审有finding", "有finding", "走通", "有战果", "发现", "过检"]],
	["tested-clear", ["已测未命中", "已审无finding", "无finding", "未走通", "未命中", "被检出", "卡点"]],
	["na", ["不适用"]],
	["budget-stop", ["未完成", "让位", "预算耗尽", "预算", "未测", "未开", "未查", "未分析"]]
];
// 七模式图例词并入（各模式四态语义不同、canonical 全局一致）：
// av=已测·过检/被检出、ctf=已解·flag 验证/已试·卡点、IR=查实·有证据/已查·未命中、
// binary=已分析·有结论/未见异常、ad/cloud=走通·有战果/执行·未走通、代审=已审·有/无 finding。
for (const _t of Object.values(TAXONOMIES)) {
	if (!_t.stateLabels) continue;
	for (const [canonical, label] of Object.entries(_t.stateLabels)) {
		const n = normLabel(label);
		const row = STATE_ALIASES.find(([c]) => c === canonical);
		if (row && !row[1].includes(n)) row[1].push(n);
	}
}

/** 终态归一：canonical id 或中文标签（各模式图例词/常用简称均可）→ 四态；歧义或未知返回 ""。 */
export function resolveStateLabel(input) {
	const raw = String(input ?? "").trim().toLowerCase();
	if (CELL_STATES.includes(raw)) return raw;
	const norm = normLabel(raw);
	if (!norm) return "";
	for (const [canonical, aliases] of STATE_ALIASES) {
		if (norm === normLabel(canonical) || aliases.includes(norm)) return canonical;
	}
	// 包含式唯一匹配：图例全称/简称互认（「执行·未走通」→「未走通」→ tested-clear）；
	// 命中多个 canonical（如裸「已分析」）判歧义返回空，宁拒勿猜。
	const hits = new Set();
	for (const [canonical, aliases] of STATE_ALIASES) {
		for (const a of aliases) {
			if (norm.includes(a) || a.includes(norm)) { hits.add(canonical); break; }
		}
	}
	if (hits.size === 1) return [...hits][0];
	return "";
}

/** 解析覆盖矩阵 markdown 表：表头须含「格子」「终态」列（兼容 key/state/原因/finding/目标列名），
 *  分隔行自动跳过；返回带原始行号的行集。 */
export function parseCoverageTable(text) {
	const rows = [];
	const lines = String(text ?? "").split(/\r?\n/);
	let cols = null;
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i].trim();
		if (!line.startsWith("|")) { if (cols) break; continue; }
		const cells = line.replace(/^\|/, "").split("|").map((c) => c.trim());
		if (cells.length && cells[cells.length - 1] === "") cells.pop();
		if (cells.every((c) => /^:?-{2,}:?$/.test(c))) continue;
		if (!cols) {
			const norm = cells.map((c) => normLabel(c));
			const keyCol = norm.findIndex((c) => c.includes("格子") || c === "key");
			const stateCol = norm.findIndex((c) => c.includes("终态") || c === "state");
			if (keyCol < 0 || stateCol < 0) continue;
			cols = {
				key: keyCol, state: stateCol,
				reason: norm.findIndex((c) => c.includes("原因")),
				finding: norm.findIndex((c) => c.includes("finding")),
				target: norm.findIndex((c) => c.includes("目标"))
			};
			continue;
		}
		const at = (idx) => (idx >= 0 && idx < cells.length ? cells[idx] : "");
		rows.push({ key: at(cols.key), state: at(cols.state), reason: at(cols.reason), findingRefs: at(cols.finding), target: at(cols.target), line: i + 1 });
	}
	return rows;
}

/** 批量落终态（sync 工具与测试共用核心）：逐行解析（key/终态均走标签归一）→ markCell；
 *  坏行跳过并附行号说明，好行照常落库（先例：methods.import 坏行不阻整体）。 */
export function applyCoverageRows(st, taxonomy, sessionId, mode, rows) {
	const applied = [];
	const failed = [];
	let n = 0;
	for (const row of rows) {
		n++;
		const where = row.line ? `第 ${row.line} 行` : `rows[${n - 1}]`;
		const keyRaw = String(row.key ?? "").trim();
		const state = resolveStateLabel(row.state);
		if (!keyRaw) { failed.push(`${where}：格子列为空，跳过`); continue; }
		if (!state) { failed.push(`${where}：「${row.state}」不是合法终态（tested-found/tested-clear/na/budget-stop，接受中文标签），跳过`); continue; }
		let key = keyRaw;
		if (taxonomy) {
			const bad = validateCoverageRef(taxonomy, keyRaw);
			if (bad) { failed.push(`${where}：${bad}，跳过`); continue; }
			key = canonicalKey(taxonomy, keyRaw) ?? keyRaw;
		}
		try {
			markCell(st, sessionId, mode, key, { state, reason: String(row.reason ?? ""), findingRefs: String(row.findingRefs ?? ""), target: String(row.target ?? "") });
			applied.push(key);
		} catch (e) {
			failed.push(`${where}：${e?.message ?? e}，跳过`);
		}
	}
	return { applied, failed };
}

//#endregion

//#endregion

//#region HTTP 通道（自注册路由 + 同源信任栅栏）

function hostOf(headers) {
	const h = headers?.host;
	return typeof h === "string" ? h : "";
}

function isLoopbackHostname(hostname) {
	if (hostname === "localhost" || hostname === "[::1]") return true;
	const parts = hostname.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

export function isTrustedRequest(req, trustedHosts) {
	const host = hostOf(req.headers);
	if (host === "") return false;
	let hostUrl;
	try { hostUrl = new URL(`http://${host}`); } catch { return false; }
	const okHost = isLoopbackHostname(hostUrl.hostname) || (trustedHosts ?? []).some((t) => {
		try { return new URL(`http://${t}`).hostname === hostUrl.hostname; } catch { return false; }
	});
	if (!okHost) return false;
	const origin = req.headers?.origin;
	if (typeof origin === "string" && origin !== "null") {
		try {
			const originUrl = new URL(origin);
			if (originUrl.host !== hostUrl.host) return false; // 含端口：本机他端口页面的 Origin 不放行
		} catch { return false; }
	}
	return true;
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let size = 0;
		const chunks = [];
		req.on("data", (c) => {
			size += c.length;
			if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); return; }
			chunks.push(c);
		});
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

/** 通道端点分发（纯逻辑，供路由与测试复用）。 */
export async function dispatch(ctx, st, endpoint, payload) {
	const p = payload ?? {};
	// 模式白名单：mode 形参只认八专业模式（未知 mode 直接拒并报合法清单——不落永不渲染的幽灵行）
	if (p.mode !== undefined && String(p.mode) !== "" && !ATLAS_MODES.includes(String(p.mode))) {
		throw new Error(`未知模式 ${p.mode}（合法：${ATLAS_MODES.join("、")}）`);
	}
	if (endpoint === "taxonomy.get") {
		return {
			modes: ATLAS_MODES.map((m) => ({ id: m, label: MODE_LABELS[m], pending: !!TAXONOMIES[m]?.pending })),
			taxonomies: TAXONOMIES
		};
	}
	if (endpoint === "session.mode") {
		// 会话真实模式的权威源：agents 注册表 → composedPreset（列表源重启后可能退化为组合名）。
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { mode: modeOfSession(ctx, sessionId) };
	}
	if (endpoint === "coverage.get") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return getCoverage(st, sessionId, String(p.mode ?? "pentest"));
	}
	if (endpoint === "coverage.mark") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const mode = String(p.mode ?? "pentest");
		const base = TAXONOMIES[mode];
		let key = String(p.key ?? "");
		if (base && !base.pending) {
			const tax = taxonomyWithCaps(st, base, mode);
			const bad = validateCoverageRef(tax, key);
			if (bad) throw new Error(bad);
			key = canonicalKey(tax, key) ?? key;
		}
		const state = resolveStateLabel(p.state) || String(p.state ?? "");
		const cell = markCell(st, sessionId, mode, key, {
			state, reason: p.reason, findingRefs: p.findingRefs, target: p.target
		});
		return { ok: true, cell };
	}
	if (endpoint === "stage.mark") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const mode = String(p.mode ?? "pentest");
		const base = TAXONOMIES[mode];
		if (base && !base.pending) {
			const tax = taxonomyWithCaps(st, base, mode);
			const bad = validateStageRef(tax, p.stage);
			if (bad) throw new Error(bad);
			// 校验接受中文标签，落库须 canonical id——与工具路径（redteam_coverage_stage）同规，防「校验放行落库被拒」
			const stageId = resolveStageId(tax, p.stage) || String(p.stage ?? "");
			return { ok: true, stage: markStage(st, sessionId, mode, stageId, String(p.state ?? ""), p.target !== undefined ? String(p.target) : "") };
		}
		return { ok: true, stage: markStage(st, sessionId, mode, String(p.stage ?? ""), String(p.state ?? ""), p.target !== undefined ? String(p.target) : "") };
	}
	if (endpoint === "coverage.clear") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, ...clearCoverage(st, sessionId, String(p.mode ?? "pentest"), p.key ? String(p.key) : "", p.target !== undefined ? String(p.target) : undefined) };
	}
	if (endpoint === "targets.add") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, target: addTarget(st, sessionId, String(p.mode ?? "pentest"), { label: String(p.label ?? ""), kind: String(p.kind ?? "other"), note: p.note }) };
	}
	if (endpoint === "targets.switch") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const which = p.label !== undefined && String(p.label) !== "" ? String(p.label) : Number(p.seq);
		return { ok: true, target: switchTarget(st, sessionId, String(p.mode ?? "pentest"), which) };
	}
	if (endpoint === "targets.list") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { targets: listTargets(st, sessionId, String(p.mode ?? "pentest")) };
	}
	if (endpoint === "targets.remove") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, ...removeTarget(st, sessionId, String(p.mode ?? "pentest"), p.seq) };
	}
	if (endpoint === "chain.node") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, node: addChainNode(st, sessionId, String(p.mode ?? "pentest"), { id: p.id, label: p.label, kind: p.kind, seg: p.seg, note: p.note, major: !!p.major, findingRef: p.findingRef, target: p.target !== undefined ? String(p.target) : "" }) };
	}
	if (endpoint === "chain.edge") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, edge: addChainEdge(st, sessionId, String(p.mode ?? "pentest"), { src: p.src, dst: p.dst, label: p.label, edgeType: p.edgeType, target: p.target !== undefined ? String(p.target) : "" }) };
	}
	if (endpoint === "chain.list") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return listChain(st, sessionId, String(p.mode ?? "pentest"), p.target !== undefined ? String(p.target) : undefined);
	}
	if (endpoint === "chain.clear") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		return { ok: true, ...clearChain(st, sessionId, String(p.mode ?? "pentest"), p.target !== undefined ? String(p.target) : undefined) };
	}
	if (endpoint === "caps.list") {
		const mode = String(p.mode ?? "");
		if (!mode) throw new Error("mode required");
		return { caps: listCaps(st, mode) };
	}
	if (endpoint === "caps.save") {
		const mode = String(p.mode ?? "");
		const base = TAXONOMIES[mode];
		if (!base || base.pending) throw new Error(`模式 ${mode} 的体系编排中`);
		if (String(p.kind) === "item") {
			const cat = String(p.cat ?? "");
			const okBuiltin = base.categories.some((c) => c.id === cat);
			const okCustom = listCaps(st, mode).some((c) => c.kind === "category" && c.cat === cat);
			if (!okBuiltin && !okCustom) throw new Error(`所属主类不存在：${cat || "(空)"}（内置与自定义主类均无，先添加主类或选内置主类）`);
		}
		const cap = saveCap(st, { id: p.id, mode, kind: p.kind, cat: p.cat, label: p.label, desc: p.desc, template: p.template, ref: p.ref, pb: p.pb, forms: p.forms });
		return { ok: true, ...cap };
	}
	if (endpoint === "caps.remove") {
		return { ok: true, ...removeCap(st, String(p.id ?? "")) };
	}
	if (endpoint === "caps.export") {
		return { format: "attack-atlas-caps", version: 1, capabilities: exportCaps(st, p.mode ? String(p.mode) : undefined) };
	}
	if (endpoint === "caps.import") {
		if (!Array.isArray(p.capabilities)) throw new Error("capabilities 数组必填");
		if (p.capabilities.length > 200) throw new Error("单次导入上限 200 条");
		// 悬挂/撞车检查：item 所属主类须内置或本次导入/库内自定义；自定义主类/子类标识
		// 不得与该模式内置 key 相同——同 key 在合并类目里会互相遮蔽、矩阵重复计数。
		const batchCats = new Map();
		for (const row of p.capabilities) {
			const m = String(row?.mode ?? "");
			if (String(row?.kind) !== "category") continue;
			const key = String(row?.cat ?? "");
			if (TAXONOMIES[m] && !TAXONOMIES[m].pending && /^[a-z0-9][a-z0-9-]{0,39}$/.test(key)) {
				if (!batchCats.has(m)) batchCats.set(m, new Set());
				batchCats.get(m).add(key);
			}
		}
		for (const [m] of batchCats) for (const c of listCaps(st, m)) if (c.kind === "category") batchCats.get(m).add(c.cat);
		const checked = [];
		const skippedPre = [];
		for (const row of p.capabilities) {
			const m = String(row?.mode ?? "");
			const base = TAXONOMIES[m];
			const kind = String(row?.kind ?? "");
			const label = String(row?.label ?? "(无名)");
			if (base && !base.pending && kind === "category") {
				const key = String(row?.cat ?? "");
				if (base.categories.some((c) => c.id === key)) { skippedPre.push({ name: label, reason: `主类标识与内置主类相同：${key}（同 key 会互相遮蔽，请换标识）` }); continue; }
			}
			if (base && !base.pending && kind === "item") {
				const cat = String(row?.cat ?? "");
				const ik = String(row?.item ?? "");
				const hit = base.categories.find((c) => c.id === cat);
				if (hit && hit.items.some((i) => i.id === ik)) { skippedPre.push({ name: label, reason: `子类标识与内置子类相同：${cat}/${ik}（同 key 会互相遮蔽，请换标识）` }); continue; }
				const okBuiltin = !!hit;
				const okCustom = (batchCats.get(m) || new Set()).has(cat);
				if (!okBuiltin && !okCustom) { skippedPre.push({ name: label, reason: `所属主类不存在：${cat}` }); continue; }
			}
			checked.push(row);
		}
		const r = importCaps(st, checked, ATLAS_MODES);
		return { ok: true, imported: r.imported, skipped: skippedPre.concat(r.skipped) };
	}
	if (endpoint === "methods.list") {
		const mode = String(p.mode ?? "");
		if (!mode) throw new Error("mode required");
		return { methods: listMethods(st, mode) };
	}
	if (endpoint === "methods.get") {
		const m = getMethod(st, String(p.id ?? ""));
		if (!m) throw new Error(`模板不存在：${p.id}`);
		return { method: m };
	}
	if (endpoint === "methods.validate") {
		const mode = String(p.mode ?? "");
		const base = TAXONOMIES[mode];
		if (!base || base.pending) throw new Error(`模式 ${mode} 的体系编排中`);
		const taxonomy = taxonomyWithCaps(st, base, mode);
		const v = validateMethod(p.name, p.graph, taxonomy);
		return { ok: true, errors: v.errors, warnings: v.warnings, hints: v.hints, graph: v.graph };
	}
	if (endpoint === "methods.save") {
		const mode = String(p.mode ?? "");
		const base = TAXONOMIES[mode];
		if (!base || base.pending) throw new Error(`模式 ${mode} 的体系编排中`);
		const taxonomy = taxonomyWithCaps(st, base, mode);
		const v = validateMethod(p.name, p.graph, taxonomy);
		if (v.errors.length) return { ok: false, error: `结构问题（修正后才能保存）：\n- ${v.errors.join("\n- ")}` };
		const saved = saveMethod(st, { id: p.id ? String(p.id) : undefined, mode, name: v.name, target: p.target, notes: p.notes, graph: v.graph });
		return { ok: true, id: saved.id, created: saved.created, warnings: v.warnings, hints: v.hints };
	}
	if (endpoint === "methods.remove") {
		return { ok: true, ...removeMethod(st, String(p.id ?? "")) };
	}
	if (endpoint === "methods.copy") {
		return { ok: true, ...copyMethod(st, String(p.id ?? "")) };
	}
	if (endpoint === "methods.export") {
		return { format: "attack-atlas-methods", version: 1, methods: exportMethods(st, p.mode ? String(p.mode) : undefined) };
	}
	if (endpoint === "methods.import") {
		if (!Array.isArray(p.methods)) throw new Error("methods 数组必填");
		if (p.methods.length > METHOD_LIMITS.importBatch) throw new Error(`单次导入上限 ${METHOD_LIMITS.importBatch} 条`);
		// 导入与保存同规：逐行过 validateMethod（结构硬校验不被导入旁路），坏行跳过说明原因
		const taxCache = {};
		const checked = [];
		const skippedV = [];
		for (const row of p.methods) {
			const m = String(row?.mode ?? "");
			const base = TAXONOMIES[m];
			if (!base || base.pending) { checked.push(row); continue; }
			if (!taxCache[m]) taxCache[m] = taxonomyWithCaps(st, base, m);
			const v = validateMethod(String(row?.name ?? ""), row?.graph, taxCache[m]);
			if (v.errors.length) { skippedV.push({ name: String(row?.name ?? "(无名)"), reason: `结构问题：${v.errors[0]}` }); continue; }
			checked.push(row);
		}
		const r = importMethods(st, checked, ATLAS_MODES);
		return { ok: true, imported: r.imported, skipped: skippedV.concat(r.skipped) };
	}
	if (endpoint === "methods.run") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const m = getMethod(st, String(p.id ?? ""));
		if (!m) throw new Error(`模板不存在：${p.id}`);
		const mode = m.mode;
		if (p.mode && String(p.mode) !== mode) return { ok: false, error: `模板属于 ${MODE_LABELS[mode] || mode}，与当前会话模式不符` };
		const base = TAXONOMIES[mode];
		if (!base || base.pending) return { ok: false, error: `模式 ${mode} 的体系编排中` };
		const taxonomy = taxonomyWithCaps(st, base, mode);
		const agents = resolveAgents(ctx);
		const agent = agents?.get?.(sessionId);
		if (!agent || typeof agent.followup !== "function") return { ok: false, unreachable: true, error: "会话不可达（会话可能已删除或代理未运行）" };
		let targets = listTargets(st, sessionId, mode);
		const runTarget = String(p.target ?? m.target ?? "").trim().slice(0, METHOD_LIMITS.target);
		if (runTarget) {
			// 运行即切锚：对哪个目标跑方法论，当前锚定就指向它——后续不带 target 的回写天然归对
			if (!targets.some((t) => t.label === runTarget)) {
				addTarget(st, sessionId, mode, { label: runTarget, kind: inferTargetKind(runTarget) });
			}
			switchTarget(st, sessionId, mode, runTarget);
			targets = listTargets(st, sessionId, mode);
		}
		const notes = String(p.notes ?? m.notes ?? "").trim().slice(0, METHOD_LIMITS.notes);
		agent.followup({
			id: `atlas-method-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
			role: "user",
			content: [{ type: "text", text: methodRunMessage(taxonomy, m, { anchor: anchorLines(taxonomy, targets), notes }) }],
			source: { kind: "user" }
		});
		return { ok: true };
	}
	if (endpoint === "atlas.trigger") {
		const sessionId = String(p.sessionId ?? "");
		if (!sessionId) throw new Error("sessionId required");
		const mode = String(p.mode ?? "pentest");
		const taxonomy = TAXONOMIES[mode];
		if (!taxonomy || taxonomy.pending) return { ok: false, error: `模式 ${mode} 的体系编排中，暂不可派单` };
		const agents = resolveAgents(ctx);
		const agent = agents?.get?.(sessionId);
		if (!agent || typeof agent.followup !== "function") return { ok: false, unreachable: true, error: "会话不可达（会话可能已删除或代理未运行）" };
		agent.followup({
			id: `atlas-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
			role: "user",
			content: [{ type: "text", text: triggerMessage(taxonomy, { ...p, targets: listTargets(st, sessionId, mode) }) }],
			source: { kind: "user" }
		});
		return { ok: true };
	}
	if (endpoint === "misses.list") {
		// MISS 缺口台账：模型想点亮但体系里不存在的 key 聚合——高频未命中即「值得建自定义模块」清单
		return missSummary(st, { limit: p.limit });
	}
	throw new Error(`unknown endpoint ${endpoint}`);
}

//#endregion

//#region host wiring

//#region 阶段门联动：stage_gate PASS → 阶段带级联点亮

/** 门 id → 阶段 id（八模式）。流程带顺序语义：过门凭据蕴含此前阶段已完成，
 *  少门模式（pentest 3 门/7 阶段等）靠级联补齐，未设门阶段留手动。 */
export /** 级联不点亮的阶段（按 `mode/gate` 键控，只列级联范围触及该阶段的门），两类：
 *  ①条件性阶段（点亮须自身凭据，任何门都不推定）——pentest s3 登陆口专线（无帐密才走）、binary s3 动态分析（无动态环境即 N-A）、code-audit s3 动态验证（纯静态审计即 N-A）；
 *  ②逐条目门的阶段（仅逐条目门不推定，覆盖度终门照常补齐）——pentest s5（P2 逐 finding 复核门；P3 补齐）、code-audit s4（A2 逐 finding 双链门；A3 补齐）、binary s4（B1 逐样本还原门；B2 补齐）、av s5（V3 逐实验配对门；V4 补齐）：
 *  首条目过门不蕴含阶段整体完成，整体完成由覆盖度终门级联补齐。 */
const GATE_NO_FILL = {
	"pentest/P2": ["s3", "s5"], "pentest/P3": ["s3"],
	"code-audit/A2": ["s3", "s4"], "code-audit/A3": ["s3"],
	"binary-analysis/B1": ["s3", "s4"], "binary-analysis/B2": ["s3"],
	"av-evasion/V3": ["s5"]
};
export const GATE_STAGE = {
	pentest: { "P1": "s1", "P2": "s5", "P3": "s6" },
	"code-audit": { "A1": "s1", "A2": "s4", "A3": "s5" },
	"binary-analysis": { "B0": "s1", "B1": "s4", "B2": "s5" },
	"attack-defense": { "recon": "s1", "breach": "s2", "lateral": "s3", "persistence": "s4", "report": "s5" },
	"av-evasion": { "V1": "s2", "V2": "s4", "V3": "s5", "V4": "s6" },
	"incident-response": { "I1": "s1", "I2": "s3", "I3": "s4", "I4": "s5", "I5": "s6" },
	"cloud-security": { "C1": "s1", "C2": "s2", "C3": "s3", "C4": "s4", "C5": "s5", "C6": "s6", "C7": "s7" },
	"ctf-solver": { "board": "s1", "flag": "s3" }
};

/** stage_gate 结果文本判定（render 前缀确定性）：仅 PASS 触发，FAIL 不动阶段带。 */
export function isGatePassText(text, mode, gate) {
	return String(text ?? "").startsWith(`stage_gate ${mode}/${gate}: PASS`);
}

/** 门 PASS → 目标阶段及此前全部阶段标 done（级联）；未知门/未知阶段返回空。 */
export function autoStageFromGate(st, taxonomy, sessionId, mode, gateId) {
	const target = GATE_STAGE[mode]?.[gateId];
	if (!target) return [];
	const stages = taxonomy?.stages ?? [];
	const idx = stages.findIndex((s) => s.id === target);
	if (idx < 0) return [];
	const marked = [];
	const noFill = GATE_NO_FILL[`${mode}/${gateId}`] ?? [];
	for (let i = 0; i <= idx; i++) {
		if (noFill.includes(stages[i].id)) continue; // 条件性阶段不凭过门推定完成
		try {
			markStage(st, sessionId, mode, stages[i].id, "done");
			marked.push(stages[i].id);
		} catch { /* 单阶段失败不阻级联 */ }
	}
	return marked;
}

//#endregion

//#region finding 自动点亮（P1）与覆盖提醒（P3）

/** 常用 CWE → 类目语义标签（与体系子项标签对齐后再走 resolveKey；未收录返回 ""，保守跳过）。 */
const CWE_LABELS = {
	78: "命令执行", 77: "命令注入", 89: "SQL 注入", 79: "XSS", 22: "路径穿越", 918: "SSRF",
	611: "XXE", 502: "反序列化", 674: "反序列化", 94: "代码注入", 917: "表达式注入", 915: "表达式注入",
	434: "任意文件上传", 98: "文件包含", 73: "文件读写", 352: "CSRF", 287: "认证绕过", 862: "未授权访问",
	798: "硬编码凭据", 321: "硬编码凭据", 327: "密码学实现误用", 362: "并发", 840: "业务逻辑", 1336: "正则拒绝服务",
	269: "权限提升", 522: "密钥泄露", 863: "权限提升"
};
function cweToLabel(cwe) {
	const m = /(\d+)/.exec(String(cwe ?? ""));
	return m ? (CWE_LABELS[Number(m[1])] ?? "") : "";
}

let resultsStoreCache;
/** 从 redteam-results 库反查 finding id（同进程只读；失败返回空串——自动面缺 ref 不缺格）。 */
async function findFindingIdInResults(sessionId, mode, title) {
	if (!title) return "";
	const mod = await import("@dsh-external/dsh-redteam-results/store");
	if (!resultsStoreCache) resultsStoreCache = mod.openStore(path.join(os.homedir(), ".dsh", "redteam-results", "results.db"));
	const hit = (mod.allFindings(resultsStoreCache, sessionId, mode) || []).find((f) => f.title === title);
	return hit?.id ?? "";
}

/** 每主类一次的覆盖提醒限流（进程级；会话删除/重启自然重置）。 */
const NUDGED_CATS = new Set();
function nudgeUndetermined(ctx, sessionId, mode, taxonomy, doneKeys, markedCats, deps = {}) {
	const out = [];
	let agent = null;
	if (!deps.followup) {
		const agents = resolveAgents(ctx);
		agent = agents?.get?.(sessionId);
		if (!agent || typeof agent.followup !== "function") return out;
	}
	for (const catId of markedCats) {
		const cat = taxonomy.categories.find((c) => c.id === catId);
		if (!cat) continue;
		const nk = `${sessionId}:${mode}:${catId}`;
		if (NUDGED_CATS.has(nk)) continue;
		const undetermined = cat.items.filter((it) => !doneKeys.has(`${catId}/${it.id}`));
		if (!undetermined.length) continue;
		NUDGED_CATS.add(nk);
		const names = undetermined.slice(0, 8).map((it) => it.label).join("、") + (undetermined.length > 8 ? " 等" : "");
		const message = {
			id: `atlas-nudge-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
			role: "user",
			content: [{ type: "text", text: `[AttackAtlas·覆盖提醒] finding 已自动点亮「${cat.label}」内关联格子。该主类仍有 ${undetermined.length} 格未终态：${names}——收口时逐格终态三选一（${trioWords(taxonomy)}）${MODE_CLOSE_HINT[mode] ?? ""}，或用 redteam_coverage_sync 整表批量回写（key/终态均可写中文标签）。` }],
			source: { kind: "user" }
		};
		if (deps.followup) deps.followup(message); else agent.followup(message);
		out.push(catId);
	}
	return out;
}

/** finding 登记成功 → 类型/CWE/标题走 resolveKey 解析格子 → 仅对无终态格子落 tested-found
 *  （人工终态永不被自动覆盖，终态判定按归属 scope）；关联主类若有剩余未终态格，注入一次覆盖提醒（P3）。
 *  归属：finding 的 target 是自由文本地址（地址/位置）——与已登记 label 精确匹配才归该目标，
 *  否则归当前激活目标（无激活落公共 scope）；未匹配的原值进 reason 保溯源。
 *  deps 供测试注入：{ mode, findFindingId, followup }。 */
export async function autoLightFromFinding(ctx, st, sessionId, findingArgs, deps = {}) {
	const mode = deps.mode ?? modeOfSession(ctx, sessionId);
	if (!mode) return { marked: [], nudged: [] };
	const base = TAXONOMIES[mode];
	if (!base || base.pending) return { marked: [], nudged: [] };
	const taxonomy = taxonomyWithCaps(st, base, mode);
	const title = String(findingArgs?.title ?? "").trim();
	const typeStr = String(findingArgs?.type ?? "").trim();
	// 线索：type + cwe 字段映射 + type 内嵌 CWE（工具描述引导「type 可含 CWE」——缺填 cwe 字段时不绕空）+ 标题
	const cues = [typeStr, cweToLabel(findingArgs?.cwe)];
	for (const m of typeStr.matchAll(/cwe[-\s]*(\d{1,4})/gi)) { const lbl = cweToLabel(m[1]); if (lbl) cues.push(lbl); }
	cues.push(title);
	const uniqueCues = [...new Set(cues.map((c) => String(c ?? "").trim()).filter(Boolean))];
	if (!uniqueCues.length) return { marked: [], nudged: [] };
	let ref = "";
	try {
		ref = deps.findFindingId ? await deps.findFindingId(sessionId, mode, title) : await findFindingIdInResults(sessionId, mode, title);
	} catch { ref = ""; }
	const cov = getCoverage(st, sessionId, mode);
	const ft = String(findingArgs?.target ?? "").trim().slice(0, 120);
	const scope = cov.targets.find((t) => t.label === ft)?.label ?? cov.targets.find((t) => t.active)?.label ?? "";
	const unmatched = ft && ft !== scope ? `（原报目标 ${ft} 未登记，归${scope ? "当前锚定" : "公共 scope"}）` : "";
	const done = new Set(cov.cells.filter((c) => c.target === scope).map((c) => c.key));
	const marked = [];
	const markedCats = new Set();
	for (const cue of uniqueCues) {
		const res = resolveKey(taxonomy, cue);
		if (!res || !res.key || res.ambiguous || res.missingItem) continue;
		if (done.has(res.key)) continue;
		markCell(st, sessionId, mode, res.key, {
			state: "tested-found",
			reason: `自动：finding${ref ? ` ${ref}` : ""}「${title.slice(0, 40)}」${unmatched}类型关联点亮（人工终态可覆盖）`,
			findingRefs: ref,
			target: scope
		});
		done.add(res.key);
		marked.push(res.key);
		markedCats.add(res.catId);
	}
	const nudged = markedCats.size ? nudgeUndetermined(ctx, sessionId, mode, taxonomy, done, [...markedCats], deps) : [];
	return { marked, nudged };
}

//#endregion

function apply(ctx) {
	//#region 模型工具（宿主平面注册；八专业模式会话内可用——light 通用模式等非图谱会话执行被拒）
	ctx.tools.register(defineTool({
		name: "redteam_coverage_mark",
		description: "把攻击面图谱（「攻击面图谱」标签页）里的一个格子或主类标为终态。每个格子终态：tested-found / tested-clear / na / budget-stop（图例按模式显示对应语义——渗透=已验·有发现/未命中、免杀=已测·过检/被检出、CTF=已解·flag 验证/已试·卡点、应急=查实·有证据/已查·未命中等）。key 形如 injection/sqli（格子）或 injection（主类整组 N-A），也接受主类/格子的中文标签（自动归一）；写错时报错会列出该模式全部合法主类。tested-clear 时 reason 建议写未排除面；tested-found 时 findingRefs 填关联 finding id。逐格回写，图谱实时点亮。",
		parameters: {
			key: { type: "string", required: true, description: "cat/item 格子 key、cat 主类 key，或主类/格子中文标签" },
			state: { type: "string", required: true, enum: CELL_STATES, description: "终态" },
			reason: { type: "string", description: "原因（na/budget-stop 必填；tested-clear 建议写未排除面）" },
			findingRefs: { type: "string", description: "关联 finding id（逗号分隔）" },
			target: { type: "string", description: "该终态所属目标（按目标分账：同格每目标各一行；须为已登记 label，写错报已登记清单；缺省=当前锚定目标，未登记任何目标时落会话公共 scope）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `图谱已点亮：${v.key} → ${v.state}` : `点亮失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用（当前会话未挂专业模式）" });
			try {
				const base = TAXONOMIES[session.mode];
				let key = String(args.key ?? "");
				if (base && !base.pending) {
					const tax = taxonomyWithCaps(theStore(), base, session.mode);
					const bad = validateCoverageRef(tax, key);
					if (bad) {
						recordMiss(theStore(), { mode: session.mode, kind: "cell", query: key, error: bad, sessionId: session.id });
						return Promise.resolve({ ok: false, error: bad });
					}
					key = canonicalKey(tax, key) ?? key;
				}
				const cell = markCell(theStore(), session.id, session.mode, key, { state: resolveStateLabel(args.state) || args.state, reason: args.reason, findingRefs: args.findingRefs, target: args.target });
				return Promise.resolve({ ok: true, key: cell.key, state: cell.state });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_coverage_stage",
		description: "推进攻击面图谱顶部的作战流程带：进入某阶段标 active、完成标 done。stage 取当前模式体系的阶段 id（渗透模式为 s0-s6：防护画像/被动收集/入口面盘点/登陆口专线/逐面挖掘/验证与影响证明/收口），也接受阶段中文标签（自动归一）；写错时报错会列出该模式全部合法阶段。阶段带按目标分账：target 缺省推进当前锚定目标的阶段。stage_gate 判定 PASS 后对应阶段（及其此前阶段）自动回写 done（归当时锚定目标），本工具用于无门阶段的推进与补记。",
		parameters: {
			stage: { type: "string", required: true, description: "阶段 id 或阶段中文标签" },
			state: { type: "string", required: true, enum: STAGE_STATES, description: "active=进行中 done=完成" },
			target: { type: "string", description: "推进哪个目标的阶段带（须为已登记 label；缺省=当前锚定目标）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `阶段已点亮：${v.stage} → ${v.state}` : `阶段点亮失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			try {
				const base = TAXONOMIES[session.mode];
				let stage = String(args.stage ?? "");
				if (base && !base.pending) {
					const tax = taxonomyWithCaps(theStore(), base, session.mode);
					const bad = validateStageRef(tax, stage);
					if (bad) {
						recordMiss(theStore(), { mode: session.mode, kind: "stage", query: stage, error: bad, sessionId: session.id });
						return Promise.resolve({ ok: false, error: bad });
					}
				stage = resolveStageId(tax, stage) || stage;
			}
			const marked = markStage(theStore(), session.id, session.mode, stage, args.state, args.target !== undefined ? String(args.target) : "");
			return Promise.resolve({ ok: true, stage: marked.stage, state: marked.state });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_coverage_sync",
		description: "批量回写覆盖终态（覆盖对账/收口用）：一次调用替代逐格 redteam_coverage_mark。入口二选一——rows=[{key,state,reason,findingRefs,target}] 数组，或 path=覆盖矩阵 markdown 文件（表头须含「格子」「终态」列名，兼容 原因/finding/目标 列，分隔行自动跳过）。key 与终态均接受中文标签（自动归一到体系 key 与四态）；坏行跳过并在结果逐行说明原因，好行照常落库。",
		parameters: {
			rows: { type: "array", items: { type: "object", additionalProperties: true }, description: "终态行数组（与 path 二选一）：{key, state, reason, findingRefs, target}" },
			path: { type: "string", description: "覆盖矩阵文件路径（与 rows 二选一；工作区相对或绝对路径）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `批量回写：成功 ${v.applied.length} 格${v.failed.length ? `，跳过 ${v.failed.length} 行（${v.failed.slice(0, 3).join("；")}${v.failed.length > 3 ? " 等" : ""}）` : ""}` : `批量回写失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			try {
				let rows = Array.isArray(args.rows) ? args.rows.map((r) => ({ ...r })) : [];
				if (!rows.length && args.path) {
					const text = fs.readFileSync(String(args.path), "utf8");
					rows = parseCoverageTable(text);
					if (!rows.length) return Promise.resolve({ ok: false, error: "文件里没找到覆盖表（表头须含「格子」「终态」两列名的 markdown 表）" });
				}
				if (!rows.length) return Promise.resolve({ ok: false, error: "rows 与 path 至少给一个" });
				const base = TAXONOMIES[session.mode];
				const taxonomy = base && !base.pending ? taxonomyWithCaps(theStore(), base, session.mode) : null;
				const { applied, failed } = applyCoverageRows(theStore(), taxonomy, session.id, session.mode, rows);
				return Promise.resolve({ ok: true, applied, failed });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_coverage_list",
		description: "读取本会话攻击面图谱的全部覆盖终态（格子+阶段），复核员抽查与收口核对用。",
		parameters: {},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? `本会话图谱终态：${v.cells.length} 格 / ${v.stages.length} 阶段` : `读取失败：${v.error}` }]
		},
		execute(_args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			const cov = getCoverage(theStore(), session.id, session.mode);
			return Promise.resolve({ ok: true, cells: cov.cells, stages: cov.stages });
		}
	}));
	ctx.tools.register(defineTool({
		name: "redteam_atlas_target",
		description: "登记/切换/查看本会话 AttackAtlas 的作战目标（与资产清单基线 assets.md 同步维护；入口面盘点发现的每个资产均登记）。覆盖态按目标分账：每个目标有独立的矩阵点亮、阶段推进与链路拓扑。add=登记（首个目标自动成为当前锚定，并把此前公共 scope 的回写扫入它）；switch=切换当前锚定（回写不带 target 默认归当前锚定、派单信封锚定行随切更新——换对象作业的第一动作）；remove=删除目标并级联清理其覆盖终态/阶段/链路（错登清理用；做完的目标 switch 切走即可，勿删）。kind 取 domain/web/ip/org 组织单位/api/miniprogram/android/ios/desktop/component/cloud/ai/repo/sample/payload/webshell/loader/memshell/c2/host/case 案件/challenge 题目/account/tenant/cluster/other。",
		parameters: {
			action: { type: "string", required: true, enum: ["add", "switch", "list", "remove"], description: "add=登记 switch=切换当前锚定 list=列出 remove=删除（级联清数据）" },
			label: { type: "string", description: "目标标识（域名/ip:port/公司名/样本 sha256 前缀等），action=add 必填；action=switch 可按 label 切锚" },
			kind: { type: "string", enum: TARGET_KINDS, description: "目标形态" },
			note: { type: "string", description: "备注（入口/授权范围片段）" },
			seq: { type: "number", description: "action=remove/switch 时的序号（与 label 二选一）" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? (v.targets ? `本会话目标 ${v.targets.length} 个（当前锚定：${(v.targets.find((t) => t.active) || {}).label ?? "无"}）：${v.targets.map((t) => `${t.label}${t.active ? "（锚）" : ""}`).join("、")}` : (v.switched != null ? `锚定已切换：${v.label}（${v.kindLabel}）` : (v.removed != null ? `目标已移除（含其覆盖/阶段/链路数据）：序号 ${v.removed}` : `目标已登记：${v.label}（${v.kindLabel}）${v.active ? "，已设为当前锚定" : ""}`))) : `目标操作失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			try {
				if (args.action === "list") return Promise.resolve({ ok: true, targets: listTargets(theStore(), session.id, session.mode) });
				if (args.action === "switch") {
					const which = args.label !== undefined && String(args.label) !== "" ? String(args.label) : Number(args.seq);
					const t = switchTarget(theStore(), session.id, session.mode, which);
					return Promise.resolve({ ok: true, switched: t.seq, label: t.label, kindLabel: targetKindLabel(t.kind) });
				}
				if (args.action === "remove") { removeTarget(theStore(), session.id, session.mode, args.seq); return Promise.resolve({ ok: true, removed: args.seq }); }
				const t = addTarget(theStore(), session.id, session.mode, { label: args.label, kind: args.kind, note: args.note });
				return Promise.resolve({ ok: true, label: t.label, kind: t.kind, kindLabel: targetKindLabel(t.kind), seq: t.seq, active: t.active });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	ctx.tools.register(defineTool({
		name: "redteam_atlas_chain",
		description: "登记/查看本会话 AttackAtlas 的攻击链拓扑（仅攻防评估/应急溯源/云安全三模式有链路体系，其余模式不可用；链路拓扑图弹窗实时成图）。链路按目标分账：登记与查看都带 target 维度，缺省归当前锚定目标。节点：攻防/应急用 entry 入口/host 主机/segment 网段关口/bastion 堡垒机/dc 域控/cred 凭据；云安全用 identity 身份/角色、secret 密钥面、resource 云资源、orgroot 组织根/KMS（major）、pivot 信任链/横移。重大成果节点 major=true，seg 填网段（如 10.1.1.x）；边 label 写动作（获取权限/凭据复用/隔离突破/域控获取/角色链入…）。多入口/暂无链路按实际登记，不虚构。突破成立、拿下一台主机、跨段、拿到关键凭据时即登记——链路拓扑随战役推进实时生长。",
		parameters: {
			action: { type: "string", required: true, enum: ["add-node", "add-edge", "list", "clear"], description: "add-node=登记节点 add-edge=登记边 list=查看（list 可带 target 过滤，缺省全目标并集） clear=清空" },
			id: { type: "string", description: "节点 id（字母数字与 ._-，如 h-192-168-1-2；action=add-node 必填）" },
			label: { type: "string", description: "节点显示名（域名/ip/凭据名）" },
			kind: { type: "string", enum: CHAIN_NODE_KINDS, description: "节点类型" },
			seg: { type: "string", description: "所属网段（如 10.1.1.x）" },
			note: { type: "string", description: "备注（拿到什么权限/凭据名）" },
			major: { type: "boolean", description: "重大成果节点（堡垒机/域控/全域权限等）" },
			findingRef: { type: "string", description: "关联战果 finding id（redteam_finding_register 返回的 id，如 attack-defense-3）——链路节点与「redteam 成果」页互链；无关联省略" },
			target: { type: "string", description: "登记到哪个目标的链路面（须为已登记 label；缺省=当前锚定目标）" },
			src: { type: "string", description: "边起点节点 id（action=add-edge 必填）" },
			dst: { type: "string", description: "边终点节点 id" },
			edgeLabel: { type: "string", description: "边动作标签（获取权限/凭据复用/隔离突破…）" },
			edgeType: { type: "string", enum: ["discovered_on", "exploits", "enables", "depends_on", "leads_to"], description: "边类型（推荐填）：discovered_on 在…发现 / exploits 利用 / enables 使可行 / depends_on 前置依赖 / leads_to 导致——类型化边让拓扑图与攻击链复盘可按边语义聚合" }
		},
		output: {
			schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean", required: true } } },
			render: (_a, v) => [{ type: "text", text: v.ok ? (v.chain ? `链路拓扑：${v.chain.nodes.length} 节点 / ${v.chain.edges.length} 边` : `已登记：${v.what}`) : `链路登记失败：${v.error}` }]
		},
		execute(args, exec) {
			const session = sessionOf(ctx, exec);
			if (!session?.mode) return Promise.resolve({ ok: false, error: "仅专业模式会话内可用" });
			if (!TAXONOMIES[session.mode]?.chain) return Promise.resolve({ ok: false, error: "本模式无链路拓扑体系（链路图仅 攻防评估/应急溯源/云安全 三模式）" });
			try {
				const tgt = args.target !== undefined ? String(args.target) : "";
				if (args.action === "list") return Promise.resolve({ ok: true, chain: listChain(theStore(), session.id, session.mode, args.target !== undefined ? String(args.target) : undefined) });
				if (args.action === "clear") { clearChain(theStore(), session.id, session.mode, args.target !== undefined ? String(args.target) : undefined); return Promise.resolve({ ok: true, what: "链路已清空" }); }
				if (args.action === "add-node") { const n = addChainNode(theStore(), session.id, session.mode, { id: args.id, label: args.label, kind: args.kind, seg: args.seg, note: args.note, major: args.major, findingRef: args.findingRef, target: tgt }); return Promise.resolve({ ok: true, what: `节点 ${n.label}（${chainKindLabel(n.kind)}${n.major ? "·重大" : ""}${n.findingRef ? `·关联成果 ${n.findingRef}` : ""}）` }); }
				const e = addChainEdge(theStore(), session.id, session.mode, { src: args.src, dst: args.dst, label: args.edgeLabel, edgeType: args.edgeType, target: tgt });
				return Promise.resolve({ ok: true, what: `边 ${e.src} → ${e.dst}${e.edgeType ? "（" + CHAIN_EDGE_TYPES[e.edgeType] + "）" : ""}${e.label ? "·" + e.label : ""}` });
			} catch (e) {
				return Promise.resolve({ ok: false, error: e?.message ?? String(e) });
			}
		}
	}));

	//#endregion

	//#region finding 自动点亮与阶段门联动：监听工具事件流（tool/call + tool/result 按 callId 配对）
	const inflight = new Map();
	ctx.on("session/event", (session, event) => {
		if (event?.type === "tool/call") {
			const nm = event.data?.name;
			if (nm !== "redteam_finding_register" && nm !== "stage_gate") return;
			let args = {};
			try { args = JSON.parse(String(event.data.arguments ?? "{}")); } catch { args = {}; }
			inflight.set(`${session?.id}:${event.data.callId}`, { name: nm, args });
			return;
		}
		if (event?.type === "tool/result") {
			const message = event.data?.message ?? {};
			const callId = typeof message.source?.callId === "string" && message.source?.kind === "tool" ? message.source.callId : (Array.isArray(message.content) ? message.content.find((b) => typeof b?.toolCallId === "string")?.toolCallId : undefined);
			if (typeof callId !== "string") return;
			const key = `${session?.id}:${callId}`;
			const entry = inflight.get(key);
			if (!entry) return;
			inflight.delete(key);
			const failed = (Array.isArray(message.content) && message.content.some((b) => b?.isError === true)) || event.data?.error !== undefined;
			if (failed) return;
			if (entry.name === "redteam_finding_register") {
				autoLightFromFinding(ctx, theStore(), String(session?.id ?? ""), entry.args).catch(() => { /* 自动面不阻塞业务 */ });
				return;
			}
			// stage_gate：PASS → 阶段带级联点亮（会话模式权威；未挂模式时回落门的 mode）
			const sid = String(session?.id ?? "");
			let mode = modeOfSession(ctx, sid);
			if (!mode && ATLAS_MODES.includes(entry.args.mode)) mode = entry.args.mode;
			if (!mode || String(entry.args.mode ?? "") !== mode) return;
			const text = (Array.isArray(message.content) ? message.content.find((b) => b?.type === "text")?.text : "") ?? "";
			if (!isGatePassText(text, mode, String(entry.args.stage ?? ""))) return;
			try { autoStageFromGate(theStore(), TAXONOMIES[mode], sid, mode, String(entry.args.stage ?? "")); } catch { /* 自动面不阻塞业务 */ }
		}
	});
	//#endregion

	//#region Web 通道路由（自注册 + 同源栅栏）
	const trustedHosts = () => {
		try { return ctx.webRuntime?.trustedHosts ?? []; } catch { return []; }
	};
	ctx.effect(() => ctx.webServer.register({
		kind: "prefix",
		path: ROUTE_PATH,
		handler: async (req, res) => {
			const send = (code, body) => {
				const text = JSON.stringify(body);
				res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
				res.end(text);
			};
			if (!isTrustedRequest(req, trustedHosts())) { res.writeHead(403); res.end("forbidden"); return; }
			let csrfPath = "";
			try { csrfPath = new URL(req.url ?? "/", "http://x").pathname; } catch { csrfPath = ""; }
			if (req.method === "GET" && csrfPath === ROUTE_PATH + "/csrf") { send(200, { token: CSRF_TOKEN }); return; }
			if (req.method !== "POST") { res.writeHead(405); res.end("method not allowed"); return; }
			if (!checkCsrf(req, CSRF_TOKEN)) { res.writeHead(403); res.end("csrf token missing or invalid"); return; }
			let endpoint = "";
			try { endpoint = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname.slice(ROUTE_PATH.length)).replace(/^\/+/, ""); } catch { endpoint = ""; }
			if (endpoint === "") { res.writeHead(404); res.end("not found"); return; }
			try {
				const raw = await readBody(req);
				const payload = raw === "" ? {} : JSON.parse(raw);
				const result = await dispatch(ctx, theStore(), endpoint, payload);
				send(200, result);
			} catch (e) {
				send(400, { ok: false, error: e?.message ?? String(e) });
			}
		}
	}), "dsh-attack-atlas: web route");
	//#endregion
}

export { ATLAS_MODES, MODE_LABELS, CELL_STATES, STAGE_STATES, ROUTE_PATH, apply, inject, name, openStore };

//#endregion
