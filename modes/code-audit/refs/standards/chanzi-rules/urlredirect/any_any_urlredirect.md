# Java 语言 URL 重定向漏洞完整解析

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_any_urlredirect` · 类别：urlredirect · 关键 sink：HttpHeaders, sendRedirect, setLocation
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java 语言 URL 重定向漏洞完整解析
URL 重定向漏洞（也常被称为“开放重定向漏洞”）是一类典型的Web安全漏洞，核心成因是**应用程序未对重定向目标URL进行严格校验**，导致攻击者可构造恶意URL，诱导用户跳转到钓鱼网站、恶意站点或执行其他恶意操作。在Java生态中，该漏洞的触发场景、底层原因和表现形式与Java Web的核心组件（Servlet、Spring、Struts等）强相关，以下从漏洞本质、触发条件、典型场景、变种情况等维度完整描述：

#### 一、漏洞本质
Java Web应用中，重定向功能通常通过`HttpServletResponse.sendRedirect()`、框架封装的重定向API（如Spring MVC的`RedirectView`）实现。当这些API的目标URL参数**直接或间接来源于用户输入**（如请求参数、Cookie、Header等），且应用未对输入的URL做合法性校验（如域名白名单、协议限制）时，攻击者可篡改该参数，将用户重定向到任意恶意地址，引发钓鱼、账号窃取、恶意代码执行等风险。

#### 二、核心触发条件
1. **输入可控**：重定向的目标URL包含用户可控的输入（如`http://example.com/redirect?url=用户输入`）；
2. **校验缺失**：应用未对用户输入的URL做以下关键校验：
   - 协议校验（如限制仅允许`http/https`，禁止`javascript/file`等协议）；
   - 域名校验（如仅允许跳转到自身域名或可信白名单域名）；
   - 路径合法性校验（如禁止跨域、禁止相对路径跳转至恶意域名）；
   - 特殊字符/绕过手法校验（如`@`、`//`、`\`、URL编码等）；
3. **输出未过滤**：用户输入的URL直接拼接到重定向目标中，无转义或过滤。

#### 三、Java中URL重定向漏洞的典型场景
##### 场景1：原生Servlet中的直接重定向（最基础场景）
Java Servlet是Web应用的核心组件，`HttpServletResponse.sendRedirect()`是最常用的重定向API，若直接使用用户输入作为参数，必然触发漏洞。

**示例代码（存在漏洞）**：
```java
@WebServlet("/redirect")
public class RedirectServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // 直接获取用户输入的url参数作为重定向目标
        String targetUrl = request.getParameter("url");
        // 无任何校验，直接重定向
        response.sendRedirect(targetUrl);
    }
}
```
**攻击利用**：
用户访问`http://example.com/redirect?url=http://malicious.com`，会被直接跳转到恶意站点；
进一步可构造`url=javascript:alert(1)`（部分浏览器/场景下可执行JS），或`url=file:///etc/passwd`（尝试读取本地文件）。

##### 场景2：Spring MVC中的重定向（框架层漏洞）
Spring MVC作为主流Java Web框架，提供了多种重定向方式，若使用不当易触发漏洞：
- **方式1：返回字符串形式的重定向指令**
  Spring MVC中返回`redirect:xxx`会触发重定向，若`xxx`包含用户输入且未校验，即存在漏洞。

  **示例代码（存在漏洞）**：
  ```java
  @Controller
  public class RedirectController {
      @GetMapping("/spring/redirect")
      public String redirect(@RequestParam("url") String url) {
          // 直接拼接用户输入到重定向指令中
          return "redirect:" + url;
      }
  }
  ```
- **方式2：使用RedirectView类**
  `RedirectView`是Spring MVC封装的重定向视图，若构造时传入用户可控的URL且未校验，同样触发漏洞。

  **示例代码（存在漏洞）**：
  ```java
  @GetMapping("/spring/redirectView")
  public View redirectView(@RequestParam("url") String url) {
      // 无校验构造RedirectView
      return new RedirectView(url);
  }
  ```

##### 场景3：Struts2框架中的重定向
Struts2作为经典MVC框架，其配置文件或Action中若允许用户控制重定向目标，会触发漏洞：
- **配置文件方式（struts.xml）**
  若`<result>`标签的`location`属性引用用户可控的OGNL表达式，无校验则漏洞：
  ```xml
  <action name="strutsRedirect" class="com.example.RedirectAction">
      <!-- location引用用户输入的url参数 -->
      <result type="redirect">${param.url}</result>
  </action>
  ```
- **Action代码方式**
  若Action中直接将用户输入赋值给重定向目标，无校验则漏洞：
  ```java
  public class RedirectAction extends ActionSupport {
      private String url;
      // 省略getter/setter
      public String execute() {
          // 重定向到用户输入的url
          ServletActionContext.getResponse().sendRedirect(url);
          return NONE;
      }
  }
  ```

##### 场景4：带“伪校验”的绕过场景（最易被忽视）
部分应用看似做了校验，但校验逻辑存在缺陷，可被攻击者绕过，这是Java中URL重定向漏洞的高频变种：

###### 变种4.1：仅校验URL是否包含自身域名（前缀绕过）
**错误校验代码**：
```java
String targetUrl = request.getParameter("url");
// 仅校验是否包含自身域名，存在绕过
if (targetUrl.contains("example.com")) {
    response.sendRedirect(targetUrl);
}
```
**绕过方式**：
构造`url=http://malicious.com@example.com`（`@`符号后为域名，前为用户名，浏览器解析时会跳转到`malicious.com`）；
或`url=http://example.com.evil.com`（子域名绕过，校验仅匹配字符串包含，未验证域名归属）。

###### 变种4.2：仅校验协议为http/https（URL编码/双编码绕过）
**错误校验代码**：
```java
String targetUrl = request.getParameter("url");
// 仅校验协议开头，未处理编码
if (targetUrl.startsWith("http://") || targetUrl.startsWith("https://")) {
    response.sendRedirect(targetUrl);
}
```
**绕过方式**：
构造URL编码后的恶意协议：`url=javascript%3Aalert(1)`（部分容器会自动解码，触发JS执行）；
或双编码：`url=javascript%253Aalert(1)`（若应用仅解码一次，最终仍会还原为`javascript:alert(1)`）。

###### 变种4.3：仅校验相对路径（绝对路径绕过）
**错误校验代码**：
```java
String targetUrl = request.getParameter("url");
// 仅禁止绝对路径，认为相对路径安全
if (!targetUrl.startsWith("http")) {
    response.sendRedirect(targetUrl);
}
```
**绕过方式**：
构造相对路径指向恶意域名：`url=//malicious.com`（协议相对URL，浏览器会使用当前页面协议跳转到恶意域名）；
或`url=/../../malicious.com`（路径遍历+绝对跳转，部分容器解析异常时触发）。

###### 变种4.4：校验后重新拼接（二次赋值绕过）
**错误校验代码**：
```java
String targetUrl = request.getParameter("url");
// 校验原始参数，但拼接时引入新风险
if (targetUrl.startsWith("/")) { // 仅允许站内相对路径
    targetUrl = "http://example.com" + targetUrl;
    response.sendRedirect(targetUrl);
}
```
**绕过方式**：
构造`url=/\malicious.com`（反斜杠`\`在Java中若未转义，拼接后变为`http://example.com/\malicious.com`，浏览器解析为跳转到`malicious.com`）；
或`url=/@malicious.com`（拼接后为`http://example.com/@malicious.com`，触发`@`符号绕过）。

##### 场景5：间接可控的重定向（隐蔽场景）
用户输入并非直接作为重定向URL，而是通过中间变量、配置、数据库等间接传递，易被开发者忽视：
- **示例1：从Cookie读取重定向目标**
  ```java
  // 从Cookie获取url，用户可篡改Cookie值
  String targetUrl = request.getCookie("redirect_url").getValue();
  response.sendRedirect(targetUrl);
  ```
- **示例2：从Header读取重定向目标**
  ```java
  // 从Referer/Origin等Header获取，攻击者可伪造Header
  String targetUrl = request.getHeader("Referer");
  response.sendRedirect(targetUrl);
  ```
- **示例3：从数据库读取用户可控的URL**
  若用户注册/设置时可提交URL并存储到数据库，后续重定向时直接读取该URL且未校验：
  ```java
  // 从数据库读取用户之前提交的url
  String targetUrl = userService.getRedirectUrl(userId);
  response.sendRedirect(targetUrl);
  ```

##### 场景6：跨框架/组件交互的重定向漏洞
Java Web应用常整合多个框架/组件，交互过程中若参数传递未校验，会触发漏洞：
- **示例：Spring Boot + Thymeleaf模板引擎**
  Thymeleaf模板中直接使用用户输入作为重定向目标：
  ```html
  <!-- 模板中直接拼接用户输入的url参数 -->
  <a th:href="@{/redirect(url=${param.url})}">跳转</a>
  ```
  后端Servlet/Spring MVC未对该参数校验，导致点击链接后跳转到恶意地址。
- **示例：Spring Security的登录重定向**
  Spring Security默认支持登录后重定向到`redirect`参数指定的地址，若未限制：
  ```java
  @Override
  protected void configure(HttpSecurity http) throws Exception {
      http.formLogin()
          .loginPage("/login")
          // 登录成功后重定向到redirect参数，无校验
          .successForwardUrl("/login/success?redirect=" + request.getParameter("redirect"));
  }
  ```
  攻击者构造`/login?redirect=http://malicious.com`，用户登录后直接跳转到恶意站点。

#### 四、漏洞的危害表现
1. **钓鱼攻击**：诱导用户跳转到仿冒的登录页，窃取账号密码；
2. **恶意代码执行**：通过`javascript:`协议执行恶意JS（如窃取Cookie、挖矿、弹窗诈骗）；
3. **敏感信息泄露**：跳转到恶意站点后，通过Referer Header泄露当前页面的URL（含敏感参数）；
4. **声誉损害**：利用合法域名的重定向跳转至恶意站点，降低用户对应用的信任；
5. **绕过防护机制**：结合其他漏洞（如CSRF），通过重定向绕过同源策略限制。

#### 五、Java中漏洞的特殊触发点
1. **字符编码问题**：Java默认使用UTF-8编码，但部分容器（如Tomcat）对URL的解码规则不同，导致校验逻辑失效（如双编码绕过）；
2. **空值/默认值处理**：若用户输入的URL为空，应用默认跳转到`request.getHeader("Referer")`或其他可控地址，触发漏洞；
3. **重定向链问题**：多个重定向步骤串联（如A重定向到B，B重定向到用户输入），仅校验A的目标，未校验B的目标，导致漏洞；
4. **异步请求中的重定向**：AJAX请求中返回重定向指令，前端未校验目标URL，直接执行跳转（如`window.location.href = 后端返回的URL`）。

综上，Java语言中的URL重定向漏洞并非单一场景，而是覆盖原生Servlet、主流框架、校验绕过、间接可控等多类情况，核心根源是“用户输入可控+校验逻辑缺失/缺陷”，其表现形式与Java Web的组件特性、编码规则、框架机制深度绑定。

