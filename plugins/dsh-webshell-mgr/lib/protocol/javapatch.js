// Java class 字节码补丁器：给已编译载荷做「发送前实参注入」。
// 依据 JVM class 文件规范做常量池级补丁——不改任何方法字节码（无 StackMapTable 重算问题）：
//   ① 字段实参注入：定位 static final String 字段的 ConstantValue 属性 → 其指向的 Utf8
//      常量整条替换（内容变长安全——常量池各表项自描述长度，重建时池内偏移自然平移，
//      池外结构只按「索引」引用池项，索引不变）。
//   ② 类名随机化：this_class → Class 项 → Utf8 替换为随机内部名——每次请求换名，规避
//      同一 ClassLoader 下重复 defineClass 同名类的 LinkageError。
// 局限：参数按 Java modified-UTF-8 写入，本通道参数（命令/路径/base64）不含 NUL 与增补
// 字符，标准 UTF-8 与 modified UTF-8 字节一致。

const MAGIC = 0xCAFEBABE;

/** 解析 class 文件 → { minor, major, entries: Map<index,{tag,bytes}>, sections }。 */
function parseClass(buf) {
	const u2 = (o) => buf.readUInt16BE(o);
	const u4 = (o) => buf.readUInt32BE(o);
	if (buf.length < 10 || buf.readUInt32BE(0) !== MAGIC) throw new Error("非 class 文件（magic 不符）");
	const minor = u2(4), major = u2(6);
	const count = u2(8);
	const entries = new Map();
	const phantom = new Set();
	let o = 10;
	for (let i = 1; i < count; i++) {
		const idx = i; // 本表项真实槽位（Long/Double 双槽时 i 会自增——存储须用原槽位）
		const tag = buf.readUInt8(o); o += 1;
		let len;
		switch (tag) {
			case 1: len = 2 + u2(o); break;            // Utf8
			case 3: case 4: len = 4; break;            // Integer/Float
			case 5: case 6: len = 8; phantom.add(i + 1); i++; break; // Long/Double（占双槽，次位为幻影）
			case 7: case 8: case 16: case 19: case 20: len = 2; break; // Class/String/MethodType/Module/Package
			case 9: case 10: case 11: case 12: case 17: case 18: len = 4; break; // 各类 ref/NameAndType/Dynamic
			case 15: len = 3; break;                   // MethodHandle
			default: throw new Error(`未知常量池 tag ${tag} @${o - 1}`);
		}
		entries.set(idx, { tag, bytes: Buffer.from(buf.subarray(o, o + len)) });
		o += len;
	}
	// 池后结构全量扫描（成员/方法/属性只按长度跳过，属性体保持不透明 blob——池索引不变即有效）
	let p = o;
	const u16 = () => { const v = buf.readUInt16BE(p); p += 2; return v; };
	const after = { pos: o, access: u16(), thisClass: u16(), superClass: u16() };
	after.interfaces = [];
	for (let i = 0, n = u16(); i < n; i++) after.interfaces.push(u16());
	const member = () => {
		const m = { access: u16(), nameIndex: u16(), descIndex: u16(), attrs: [] };
		for (let i = 0, n = u16(); i < n; i++) {
			const nameIndex = u16();
			const len = buf.readUInt32BE(p); p += 4;
			m.attrs.push({ nameIndex, data: Buffer.from(buf.subarray(p, p + len)) });
			p += len;
		}
		return m;
	};
	after.fields = [];
	for (let i = 0, n = u16(); i < n; i++) after.fields.push(member());
	after.methods = [];
	for (let i = 0, n = u16(); i < n; i++) after.methods.push(member());
	after.classAttrs = [];
	for (let i = 0, n = u16(); i < n; i++) {
		const nameIndex = u16();
		const len = buf.readUInt32BE(p); p += 4;
		after.classAttrs.push({ nameIndex, data: Buffer.from(buf.subarray(p, p + len)) });
		p += len;
	}
	if (p !== buf.length) throw new Error(`class 结构解析不完整（${p}/${buf.length}）`);
	return { minor, major, entries, phantom, after };
}

function utf8Of(parsed, index) {
	const e = parsed.entries.get(index);
	if (!e || e.tag !== 1) throw new Error(`池项 ${index} 非 Utf8`);
	return e.bytes.subarray(2).toString("utf8");
}

function replaceUtf8(parsed, index, value) {
	const e = parsed.entries.get(index);
	if (!e || e.tag !== 1) throw new Error(`池项 ${index} 非 Utf8`);
	const data = Buffer.from(String(value), "utf8");
	if (data.length > 0xFFFF) throw new Error("参数超出 Utf8 常量 64KB 上限——请分块");
	e.bytes = Buffer.concat([Buffer.from([data.length >> 8, data.length & 0xFF]), data]);
}

/** 序列化回 class 字节。 */
function serialize(parsed) {
	const parts = [Buffer.from([0xCA, 0xFE, 0xBA, 0xBE])];
	const head = Buffer.alloc(6);
	head.writeUInt16BE(parsed.minor, 0);
	head.writeUInt16BE(parsed.major, 2);
	// 池计数 = 最大索引 + 1（Long/Double 双槽已占位）
	let maxIdx = 0;
	for (const i of parsed.entries.keys()) if (i > maxIdx) maxIdx = i;
	head.writeUInt16BE(maxIdx + 1, 4);
	parts.push(head);
	for (let i = 1; i <= maxIdx; i++) {
		if (parsed.phantom.has(i)) continue; // Long/Double 双槽的幻影次位不序列化
		const e = parsed.entries.get(i);
		if (!e) throw new Error(`池索引 ${i} 缺失（池解析不完整）`);
		parts.push(Buffer.from([e.tag]), e.bytes);
	}
	const putMember = (m) => {
		const b = Buffer.alloc(8);
		b.writeUInt16BE(m.access, 0); b.writeUInt16BE(m.nameIndex, 2);
		b.writeUInt16BE(m.descIndex, 4); b.writeUInt16BE(m.attrs.length, 6);
		parts.push(b);
		for (const a of m.attrs) {
			const ah = Buffer.alloc(6);
			ah.writeUInt16BE(a.nameIndex, 0); ah.writeUInt32BE(a.data.length, 2);
			parts.push(ah, a.data);
		}
	};
	const put16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v); parts.push(b); };
	put16(parsed.after.access); put16(parsed.after.thisClass); put16(parsed.after.superClass);
	put16(parsed.after.interfaces.length);
	for (const i of parsed.after.interfaces) put16(i);
	put16(parsed.after.fields.length);
	for (const f of parsed.after.fields) putMember(f);
	put16(parsed.after.methods.length);
	for (const m of parsed.after.methods) putMember(m);
	put16(parsed.after.classAttrs.length);
	for (const a of parsed.after.classAttrs) {
		const ah = Buffer.alloc(6);
		ah.writeUInt16BE(a.nameIndex, 0); ah.writeUInt32BE(a.data.length, 2);
		parts.push(ah, a.data);
	}
	return Buffer.concat(parts);
}

/**
 * 补丁入口：实参注入 + 类名随机化。
 * @param classBuf 原始 class 字节（static final String 字段带唯一占位初值）
 * @param fields {字段名: 值}；未列出的字段保持占位值（载荷侧自行跳过）
 * @param rename 新内部类名（如 "x/Ab12cd"）；空串 = 不改名
 */
export function patchClass(classBuf, fields = {}, rename = "") {
	const parsed = parseClass(classBuf);
	if (rename) {
		const cls = parsed.entries.get(parsed.after.thisClass);
		if (!cls || cls.tag !== 7) throw new Error("this_class 非 Class 常量");
		replaceUtf8(parsed, cls.bytes.readUInt16BE(0), rename);
	}
	const want = new Map(Object.entries(fields).map(([k, v]) => [k, String(v ?? "")]));
	for (const f of parsed.after.fields) {
		const fname = utf8Of(parsed, f.nameIndex);
		if (!want.has(fname)) continue;
		let patched = false;
		for (const a of f.attrs) {
			if (utf8Of(parsed, a.nameIndex) !== "ConstantValue" || a.data.length !== 2) continue;
			const strIdx = a.data.readUInt16BE(0);
			const str = parsed.entries.get(strIdx);
			if (!str || str.tag !== 8) throw new Error(`字段 ${fname} 的 ConstantValue 非 String 常量`);
			replaceUtf8(parsed, str.bytes.readUInt16BE(0), want.get(fname));
			patched = true;
		}
		if (!patched) throw new Error(`字段 ${fname} 无 ConstantValue 属性（载荷源码须为 static final String 且初值为唯一常量）`);
		want.delete(fname);
	}
	if (want.size) throw new Error(`载荷缺少可注入字段：${[...want.keys()].join(", ")}`);
	return serialize(parsed);
}

/** 读字段当前 ConstantValue（测试/诊断用）。 */
export function readFieldValues(classBuf) {
	const parsed = parseClass(classBuf);
	const out = {};
	for (const f of parsed.after.fields) {
		const fname = utf8Of(parsed, f.nameIndex);
		for (const a of f.attrs) {
			if (utf8Of(parsed, a.nameIndex) !== "ConstantValue" || a.data.length !== 2) continue;
			const str = parsed.entries.get(a.data.readUInt16BE(0));
			if (str?.tag === 8) out[fname] = utf8Of(parsed, str.bytes.readUInt16BE(0));
		}
	}
	return out;
}

/** 当前类内部名（测试/诊断用）。 */
export function classNameOf(classBuf) {
	const parsed = parseClass(classBuf);
	return utf8Of(parsed, parsed.entries.get(parsed.after.thisClass).bytes.readUInt16BE(0));
}
