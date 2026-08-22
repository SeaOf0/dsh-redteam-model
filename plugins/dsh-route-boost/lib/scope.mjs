// dsh-route-boost scope —— 任务口径判定：用户显式指定的定向任务优先于全流程。
//
// 判定三源：①图谱类目命中（用户文本提到具体子项名，如「SQL注入」「XSS」——类目数据来自
// 同 bundle 的 dsh-attack-atlas taxonomy，导入失败降级为零命中仍可工作）；②显式定向措辞
// （只测/仅做/专项/就好…）；③泛类词+动作词组合（注入/xss/越权… × 测/查/验证…）。
// 未命中 = 全流程默认（给目标不管了 → 按模式矩阵全量推进）。
// 定向口径下：只执行用户指定项并逐项回写点亮，未指定项不补测不欠账；转全流程须用户明示。

let TAXONOMIES = {};
try {
	// bundle 布局保证同级插件在位；try 保持手工部分安装可降级（零命中仍可判定）
	({ TAXONOMIES } = await import("../../dsh-attack-atlas/lib/taxonomy.js"));
} catch {
	TAXONOMIES = {};
}
function taxonomyItems(presetId) {
	const tax = TAXONOMIES?.[presetId];
	if (!tax || !Array.isArray(tax.categories)) return [];
	return tax.categories.flatMap((c) => (c.items ?? []).map((i) => String(i.label ?? "")));
}

const norm = (s) => String(s ?? "").toLowerCase().replace(/[\s　]/g, "");
const EXPLICIT_RE = /(只测|只做|只查|只检查|仅测|仅做|仅查|只看|只挖|专项|针对性|别的不用|其他不用|其他别测|不用全|不全测|不要全)/;
const GENERIC_RE = /(注入|xss|csrf|ssrf|xss漏洞|越权|未授权|横向|提权|泄露|弱口令|默认口令|上传|下载|反序列化|rce|命令执行|逻辑漏洞|支付|越级|接管|劫持|文件包含|遍历|爆破|钓鱼|免杀|加壳|脱壳|内存马|webshell)/;
const ACTION_RE = /(测|测一下|测试|测下|查|查一下|检查|验证|试试|试下|挖掘|找找|看下|看看|打一下|打下)/;

/** 类目命中：全名匹配优先，括注前缀（「XSS（反射/…」→ XSS）次之；短名防误命中。 */
function labelHits(labels, text) {
	const t = norm(text);
	if (!t) return [];
	const hits = [];
	const seen = new Set();
	for (const raw of labels) {
		const full = norm(raw);
		const head = norm(raw.split(/（|\(|·|\/|、/)[0]);
		const cand = full.length >= 3 && t.includes(full) ? raw : (head.length >= 3 && t.includes(head) ? head : "");
		if (cand && !seen.has(cand)) { seen.add(cand); hits.push(cand); }
	}
	return hits;
}

/** 判定任务口径。返回 { directed, hits, explicit }——确定性：同文本同结论。 */
export function detectScope(presetId, text) {
	const t = norm(text);
	if (!t) return { directed: false, hits: [], explicit: false };
	const explicit = EXPLICIT_RE.test(t);
	const hits = labelHits(taxonomyItems(presetId), text);
	const generic = GENERIC_RE.test(t) && ACTION_RE.test(t);
	const directed = explicit || hits.length > 0 || generic;
	return { directed, hits, explicit };
}
