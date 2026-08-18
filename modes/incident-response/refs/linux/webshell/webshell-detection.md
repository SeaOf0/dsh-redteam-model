# Linux webshell 检测与溯源

> 定位：Web 服务器（nginx/apache 等）被植入 webshell 后，从「访问日志 + 文件系统」两个维度定位木马脚本并还原攻击者 IP 与时间线。
> 本文为自写原创方法论，来源链接见文末。

---

## 0. 先确认 Web 环境

```bash
# 确定 Web 服务器与日志路径
ps -eo comm,args | grep -iE 'nginx|apache|httpd|php-fpm|tomcat|java'
# nginx 日志（常见位置）
ls -la /var/log/nginx/
# apache/httpd 日志
ls -la /var/log/apache2/ /var/log/httpd/
# 站点根目录
grep -rniE 'root\s|DocumentRoot' /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -vE '^\s*#'
```

判据：先拿到「日志路径 + 站点根目录 + Web 技术栈（PHP/JSP/ASP.NET）」，webshell 检测才有靶子。日志被删/轮转丢失本身也是一条线索。

---

## 1. access_log 特征检索（定位 webshell 访问记录）

### 1.1 高危关键词（命中即重点核查）

```bash
LOGDIR=/var/log/nginx     # 或 /var/log/apache2 /var/log/httpd

# 检索「请求里携带恶意函数/编码」的访问（webshell 流量特征）
grep -rniE 'eval\s*\(|base64_decode|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec|exec\s*\(|preg_replace.*\/e|create_function|str_rot13|gzuncompress|gzinflate' \
  "$LOGDIR"/access*.log 2>/dev/null | head -50
```

判据：
- 出现 `eval(base64_decode(...))`、`assert($_POST[...])`、`system($_GET[...])` 之类 = 典型的「一句话木马」或「编码混淆马」访问流量。
- 请求方法为 `POST` 且 URL 是 `.php`/`.jsp`/`.aspx`/`.phtml`/`.php5` 等可执行脚本后缀。

误报规避：
- `base64_decode` 等关键词也可能出现在正常业务（如图片 base64 上传、JWT 解码），要结合「URL 是脚本文件 + 参数里带函数名 + 状态码 200」三要素综合判定。
- `grep` 会命中 URL 编码形式（如 `%65%76%61%6C` = eval），必要时先 `urldecode` 再查。

### 1.2 行为特征（POST + 异常状态码/UA/Referer）

```bash
# ① POST 到脚本文件且返回 200（webshell 上传/执行成功）
awk '$6=="\"POST" {print $0}' "$LOGDIR"/access*.log 2>/dev/null | \
  grep -E '\.(php|jsp|aspx|phtml|php5|asa|cer|ashx)(\?| )' | head -50

# ② 返回 200 但无 Referer（正常浏览器访问脚本一般有 Referer）
awk '$9==200 && $11=="\"-\"" {print $1, $6, $7}' "$LOGDIR"/access*.log 2>/dev/null | head -50

# ③ 异常 User-Agent（脚本型 UA：python-requests/curl/wget/Go-http-client）
grep -iE 'python-requests|curl/|wget|Go-http-client|libwww|nikto|sqlmap|nmap' "$LOGDIR"/access*.log 2>/dev/null | head -50

# ④ 对同一脚本文件的高频/短间隔请求（webshell 心跳或反复利用）
awk '{print $1, $7}' "$LOGDIR"/access*.log 2>/dev/null | sort | uniq -c | sort -rn | head -30
```

判据：
- 某公网 IP 在短时间窗内反复 `POST` 同一个脚本文件（如 `/shell.php`）且都返回 200 = 正在用 webshell。
- UA 是 `python-requests`/`curl` 但请求的是业务脚本、且带可疑参数 = 工具化攻击。

误报规避：API 接口（如 `/api/xxx.php`）会被正常前端高频 POST，要先区分「业务 API」与「异常脚本路径」；无 Referer 也可能是手机 App 直连，需结合 UA 和路径判断。

### 1.3 日志字段速查（nginx 与 apache）

nginx 默认 `combined` 格式字段顺序：`$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`。

```bash
# 按字段提取：来源 IP | 请求方法 | 请求路径 | 状态码 | UA
awk '{print $1, $6, $7, $9, $NF}' "$LOGDIR"/access*.log 2>/dev/null | head -30
# 按状态码统计（大量 200 但路径异常 = 成功执行；404/403 = 试探）
awk '{print $9}' "$LOGDIR"/access*.log 2>/dev/null | sort | uniq -c | sort -rn
```

---

## 2. 文件系统：时间戳 + 内容定位 webshell

### 2.1 按时间戳找「近期新增/改动的脚本文件」

```bash
SITEDIR=/var/www/html     # 站点根

# 近期（30 天）新增或修改的 Web 脚本文件
find "$SITEDIR" -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' -o -name '*.phtml' -o -name '*.php5' -o -name '*.asa' -o -name '*.cer' \) -mtime -30 -exec ls -la {} \; 2>/dev/null

# 对比「文件 mtime 与站点部署时间」——正常业务文件 mtime 集中在部署日，webshell 是后加的
find "$SITEDIR" -type f -newermt "2025-08-01" -exec ls -la {} \; 2>/dev/null | head -50
```

判据：正常站点脚本的 `mtime` 集中在「上线/发版日」，若某脚本 `mtime` 落在失陷时间窗且不是发版日 = 高度可疑。

### 2.2 上传目录检查（图片目录里混入脚本）

```bash
# 上传目录里出现「非图片」后缀的可执行文件
find "$SITEDIR"/uploads "$SITEDIR"/upload "$SITEDIR"/images "$SITEDIR"/static 2>/dev/null -type f \
  \( -name '*.php' -o -name '*.jsp' -o -name '*.php.jpg' -o -name '*.php.png' -o -name '*.php5' \) -exec ls -la {} \;

# 图片目录里「文件内容」实际是 PHP/脚本（双扩展名或伪装 MIME）
for f in $(find "$SITEDIR"/uploads "$SITEDIR"/images 2>/dev/null -type f \( -name '*.jpg' -o -name '*.png' -o -name '*.gif' \)); do
  head -c 200 "$f" 2>/dev/null | grep -qE '<\?php|<%@|eval\(' && echo "SUSPECT: $f"
done
```

判据：
- 上传目录出现 `.php` 或 `.jpg.php`/`.php.jpg` 双扩展名 = 典型上传绕过 webshell。
- `.jpg` 文件内容以 `<?php` 开头 = 伪装成图片的脚本马。

### 2.3 全站内容特征扫描

```bash
# 全站脚本文件里检索危险函数（webshell 特征码）
grep -rnE 'eval\s*\(|base64_decode|assert\s*\(|shell_exec|passthru|system\s*\(|proc_open|popen|call_user_func.*assert|\$_(GET|POST|REQUEST|COOKIE)\[' \
  "$SITEDIR" --include='*.php' --include='*.jsp' --include='*.aspx' 2>/dev/null | head -80

# 找「极小体积」的脚本（一句话木马通常只有几十字节到几百字节）
find "$SITEDIR" -type f -name '*.php' -size -1k -exec ls -la {} \; 2>/dev/null
```

判据：
- 出现 `eval($_POST[...])`、`assert($_GET[...])`、`system($_REQUEST[...])` 单行 = 一句话木马。
- 极小的 `.php` 文件（<1KB）且内容是危险函数 = 一句话马高发。

误报规避：
- 正常框架（ThinkPHP/Laravel/WordPress）源码里也有 `eval`、`call_user_func` 等，要区分「框架自带」与「独立小文件里的裸 eval」。**判据是：文件是否属于框架 + 是否直接吃 `$_GET/$_POST` 再 eval**。

---

## 3. 攻击 IP 溯源与时间线

```bash
# 定位访问过可疑脚本的所有来源 IP 与时间
SUSPECT=/shell.php
grep "$SUSPECT" "$LOGDIR"/access*.log 2>/dev/null | awk '{print $1, $4, $6, $7, $9}'

# 还原该 IP 的完整攻击轨迹（爆破→上传→访问 webshell）
ATTIP=1.2.3.4
grep "$ATTIP" "$LOGDIR"/access*.log 2>/dev/null | awk '{print $4, $6, $7, $9}' | head -100

# 关联认证日志（该 IP 是否先爆破 SSH 再传马）
grep "$ATTIP" /var/log/secure* /var/log/auth.log* 2>/dev/null | tail -50
```

判据与后续：
- 从 access_log 拿到「首次访问 webshell 的时间」+「来源 IP」→ 交叉 `secure/auth.log` 看是否同一 IP 先爆破 → 还原完整攻击链。
- 对该 IP 做 `whois`/威胁情报查询（见 `attack-chain/attack-chain-reconstruction.md` 第 5 节）。

```bash
whois $ATTIP | grep -iE 'netname|country|org|descr' | head
```

---

## 4. 内存马（不落盘 webshell）补充排查

Java/PHP 内存马不写文件，第 2 节的文件检测会落空，需从进程内存/注入点排查：

```bash
# Java Agent 型内存马：查 JVM 是否被挂 agent
ps -eo pid,args | grep -iE 'java' | grep -iE 'agent|instrument'
# 查 java 进程加载的可疑 jar（Filter/Servlet 内存马注册点）
jcmd <pid> VM.system_properties 2>/dev/null | grep -iE 'javaagent|instrument'
jcmd <pid> VM.class_hierarchy 2>/dev/null | grep -iE 'Servlet|Filter' | head

# PHP 内存马（常驻 php-fpm worker 内存）：比对 php-fpm 内存
grep -iE 'memory|php' /proc/<php-fpm-pid>/status 2>/dev/null
```

判据：`javaagent` 指向 `/tmp`/可疑 jar、或 php-fpm worker 常驻内存异常增大且无对应文件 = 内存马线索。内存马排查见 `malware/mining-ransomware-backdoor.md` 第 4 节。

---

## 来源

- nginx 日志攻击溯源思路（wafai）：https://www.wafai.cn/nginx-log-attack-tracing/
- 全站日志检索 webshell 特征（php.cn）：https://www.php.cn/faq/2567753.html
- 内存马排查（PHP/Java Agent 型）：https://blog.csdn.net/m0_60571842/article/details/137352323
- 攻击 IP 溯源：https://www.gm7.org/archives/25902
- 本库 `cookbook-linux/15-小技巧.md` 0x14「查找特定时间段内的文件」（GPL-3.0 原文）
