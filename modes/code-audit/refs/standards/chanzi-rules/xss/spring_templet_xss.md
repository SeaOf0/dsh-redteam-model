# Java Spring MVC 中模版引擎渲染场景下XSS漏洞（仅描述漏洞场景，无修复建议）

> 规则 ID：`spring_templet_xss` · 类别：xss · 关键 sink：Model, ModelAndView, ModelMap, addAttribute, addObject, put
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Spring MVC 中模版引擎渲染场景下XSS漏洞（仅描述漏洞场景，无修复建议）
## 一、核心背景
Spring MVC 中模版引擎（如Thymeleaf、FreeMarker、Velocity、JSP等）是视图渲染的核心组件，XSS漏洞本质是**用户可控输入未经过滤/转义直接嵌入HTML/JS/CSS等上下文**，导致浏览器执行恶意脚本。以下分「直接返回String」「返回ModelAndView」两类场景，结合不同模版引擎、不同数据传递方式、不同上下文维度，完整描述XSS漏洞触发场景。

### 前置说明
1. 所有场景均基于「用户输入可控」前提（如请求参数、表单数据、路径变量、Cookie/Header等）；
2. 区分「模版引擎默认转义」「开发者主动关闭转义」「特殊上下文绕过转义」三类核心触发条件；
3. 覆盖HTML正文、属性、JS、CSS、URL等典型XSS上下文。

## 二、场景1：Controller直接返回String的XSS漏洞
Controller返回String分两种子场景：「返回视图名（由模版引擎渲染）」「直接返回文本内容（如HTML/JSON）」，两类均存在XSS风险。

### 子场景1.1：返回视图名（String为视图标识，数据通过Model/Request传递）
此场景下String仅指定模版文件名，数据通过`Model`/`HttpServletRequest`传入模版，XSS漏洞出现在「数据渲染阶段」。

#### 1.1.1 Thymeleaf模版引擎场景
Thymeleaf默认对`th:text`做HTML转义，但以下情况触发XSS：
- 情况1：使用`th:utext`（unescaped text）渲染用户输入
  Controller代码：
  ```java
  @GetMapping("/thymeleaf/utext")
  public String thymeleafUtext(@RequestParam("content") String content, Model model) {
      model.addAttribute("unsafeContent", content); // content为用户输入，如<script>alert(1)</script>
      return "xss/utext-page"; // 视图名，对应utext-page.html
  }
  ```
  模版代码（utext-page.html）：
  ```html
  <div th:utext="${unsafeContent}"></div>
  ```
  漏洞触发：`th:utext`直接将用户输入作为原始HTML渲染，恶意脚本被执行。

- 情况2：HTML属性中使用未转义的用户输入（如`th:attr`、直接拼接属性值）
  Controller代码：
  ```java
  @GetMapping("/thymeleaf/attr")
  public String thymeleafAttr(@RequestParam("title") String title, Model model) {
      model.addAttribute("title", title); // title为用户输入，如" onmouseover="alert(1)" "
      return "xss/attr-page";
  }
  ```
  模版代码：
  ```html
  <!-- 方式1：th:attr直接赋值属性 -->
  <div th:attr="title=${title}">测试</div>
  <!-- 方式2：属性内直接拼接（Thymeleaf对属性值默认转义，但开发者手动拼接会绕过） -->
  <div title="固定内容: [[${title}]]">测试</div> <!-- 注：[[]]是Thymeleaf内联转义，但开发者误写为[()]则不转义 -->
  <div title="固定内容: [(${title})]">测试</div> <!-- [()]为未转义内联，触发XSS -->
  ```
  漏洞触发：用户输入拼接至HTML属性中，构造闭合属性的恶意字符，触发事件型XSS（如onmouseover、onclick）。

- 情况3：JS上下文渲染用户输入（Thymeleaf默认转义HTML，但JS上下文需单独处理）
  Controller代码：
  ```java
  @GetMapping("/thymeleaf/js")
  public String thymeleafJs(@RequestParam("userId") String userId, Model model) {
      model.addAttribute("userId", userId); // userId为用户输入，如1';alert(1);//
      return "xss/js-page";
  }
  ```
  模版代码：
  ```html
  <script>
      var uid = [[${userId}]]; // Thymeleaf转义HTML（如&rarr;&），但JS上下文仍可绕过
      // 或开发者直接嵌入：
      var uid = '${userId}'; // 未经过JS转义，恶意输入闭合引号执行脚本
  </script>
  ```
  漏洞触发：JS上下文内的用户输入未做JS转义（仅做HTML转义），构造闭合引号/分号的恶意代码，执行脚本。

#### 1.1.2 FreeMarker模版引擎场景
FreeMarker默认对`${变量}`做HTML转义，但以下情况触发XSS：
- 情况1：使用`${变量?no_esc}`关闭转义
  Controller代码：
  ```java
  @GetMapping("/freemarker/noesc")
  public String freemarkerNoEsc(@RequestParam("content") String content, Model model) {
      model.addAttribute("unsafeContent", content); // content=<script>alert(1)</script>
      return "xss/noesc-page.ftl";
  }
  ```
  模版代码（noesc-page.ftl）：
  ```html
  <div>${unsafeContent?no_esc}</div>
  ```
  漏洞触发：`?no_esc`禁用HTML转义，恶意脚本直接渲染执行。

- 情况2：模版配置全局关闭转义（`setting number_format="0" escape=false`）
  Controller代码同上，模版配置：
  ```ftl
  <#setting escape=false>
  <div>${unsafeContent}</div>
  ```
  漏洞触发：全局关闭转义后，所有`${变量}`均直接渲染原始内容，触发XSS。

- 情况3：CSS上下文渲染用户输入
  Controller代码：
  ```java
  @GetMapping("/freemarker/css")
  public String freemarkerCss(@RequestParam("color") String color, Model model) {
      model.addAttribute("color", color); // color为用户输入，如red; background-image: url(javascript:alert(1));
      return "xss/css-page.ftl";
  }
  ```
  模版代码：
  ```html
  <style>
      .box { color: ${color}; }
  </style>
  ```
  漏洞触发：CSS上下文内用户输入未做CSS转义，构造分号闭合后注入恶意CSS表达式/JS伪协议，触发XSS。

#### 1.1.3 JSP模版引擎场景
JSP是早期Spring MVC常用模版，默认`<%= 变量 %>`无转义，XSS风险极高：
- 情况1：使用`<%= %>`输出用户输入
  Controller代码：
  ```java
  @GetMapping("/jsp/raw")
  public String jspRaw(@RequestParam("content") String content, HttpServletRequest request) {
      request.setAttribute("unsafeContent", content); // content=<script>alert(1)</script>
      return "xss/raw.jsp";
  }
  ```
  JSP代码（raw.jsp）：
  ```jsp
  <div><%= request.getAttribute("unsafeContent") %></div>
  ```
  漏洞触发：`<%= %>`直接输出原始字符串，恶意脚本执行。

- 情况2：使用EL表达式`${}`但未配置转义（JSP 2.0+默认转义，但低版本/自定义配置例外）
  JSP代码：
  ```jsp
  <div>${unsafeContent}</div>
  <!-- 或开发者手动关闭转义： -->
  <div>${unsafeContent != null ? unsafeContent : ''}</div> <!-- 某些场景下EL表达式嵌套会绕过转义 -->
  ```
  漏洞触发：EL表达式转义失效，用户输入直接渲染。

- 情况3：URL参数拼接（JSP中拼接a标签href）
  Controller代码：
  ```java
  @GetMapping("/jsp/url")
  public String jspUrl(@RequestParam("redirect") String redirect, Model model) {
      model.addAttribute("redirect", redirect); // redirect=javascript:alert(1)
      return "xss/url.jsp";
  }
  ```
  JSP代码：
  ```jsp
  <a href="/redirect?url=${redirect}">跳转</a>
  ```
  漏洞触发：URL参数中注入`javascript:`伪协议，点击链接执行脚本。

### 子场景1.2：直接返回String内容（非视图名，如@ResponseBody返回HTML/文本）
此场景下Controller不通过模版引擎，直接返回字符串（如HTML片段），用户输入直接拼接进返回内容，XSS风险更直接。

#### 1.2.1 无@ResponseBody（默认视图解析器，但返回HTML字符串）
Controller代码：
```java
@GetMapping("/raw/html")
public String rawHtml(@RequestParam("content") String content) {
    // 直接返回HTML字符串，拼接用户输入
    return "<html><body>" + content + "</body></html>"; // content=<script>alert(1)</script>
}
```
漏洞触发：返回的String直接作为HTTP响应体，浏览器解析为HTML，恶意脚本执行。

#### 1.2.2 有@ResponseBody（返回纯文本/HTML，Content-Type为text/html）
Controller代码：
```java
@GetMapping("/response/html")
@ResponseBody
public String responseHtml(@RequestParam("content") String content) {
    return "<div>" + content + "</div>"; // content=<script>alert(1)</script>
}
```
漏洞触发：`@ResponseBody`将String直接返回，若响应头`Content-Type`为`text/html`（默认或手动设置），浏览器解析HTML执行脚本；即使是`text/plain`，若前端将内容插入DOM（如innerHTML），仍触发XSS。

#### 1.2.3 返回JSON格式String但拼接用户输入（JSON注入导致XSS）
Controller代码：
```java
@GetMapping("/response/json")
@ResponseBody
public String responseJson(@RequestParam("username") String username) {
    // 手动拼接JSON，未转义用户输入
    return "{\"username\":\"" + username + "\"}"; // username为" <script>alert(1)</script> "
}
```
漏洞触发：前端解析JSON后将`username`插入DOM（如`div.innerHTML = data.username`），恶意脚本执行；若JSON注入构造`"</script><script>alert(1)</script>"`，还可突破<script>标签闭合。

## 三、场景2：Controller返回ModelAndView的XSS漏洞
`ModelAndView`包含「视图名+模型数据」，本质与「返回视图名+Model传参」逻辑一致，但数据传递方式更灵活，XSS漏洞场景覆盖以下维度：

### 子场景2.1：基础数据渲染漏洞（同1.1，但基于ModelAndView传参）
Controller代码：
```java
@GetMapping("/mav/basic")
public ModelAndView mavBasic(@RequestParam("content") String content) {
    ModelAndView mav = new ModelAndView("xss/utext-page"); // 对应Thymeleaf视图
    mav.addObject("unsafeContent", content); // content=<script>alert(1)</script>
    return mav;
}
```
模版代码同1.1.1的`th:utext`场景，漏洞触发逻辑一致：未转义的用户输入通过`ModelAndView`传递到模版，渲染后执行脚本。

### 子场景2.2：路径变量（PathVariable）传递数据导致XSS
用户输入通过URL路径变量传入`ModelAndView`，未过滤转义：
Controller代码：
```java
@GetMapping("/mav/path/{id}")
public ModelAndView mavPath(@PathVariable("id") String id) {
    ModelAndView mav = new ModelAndView("xss/path-page");
    mav.addObject("id", id); // id为用户输入，如1<script>alert(1)</script>
    return mav;
}
```
模版代码（Thymeleaf）：
```html
<div th:text="${id}"></div> <!-- 若开发者误写为th:utext="${id}"，触发XSS -->
```
漏洞触发：路径变量作为用户可控输入，传入模版后未转义渲染，执行脚本。

### 子场景2.3：嵌套对象/集合数据渲染漏洞
`ModelAndView`传递嵌套对象（如User）或集合（List），其中嵌套属性含用户输入，渲染时未转义：
Controller代码：
```java
@GetMapping("/mav/object")
public ModelAndView mavObject(@RequestParam("nickname") String nickname) {
    User user = new User();
    user.setNickname(nickname); // nickname=<img src=x onerror=alert(1)>
    ModelAndView mav = new ModelAndView("xss/object-page");
    mav.addObject("user", user);
    return mav;
}
```
模版代码（FreeMarker）：
```html
<div>${user.nickname?no_esc}</div>
```
漏洞触发：嵌套对象的属性未转义，恶意内容渲染执行；若为集合（如List<User>），循环渲染时每个元素的属性均可能触发XSS。

### 子场景2.4：重定向/转发场景的XSS
`ModelAndView`指定重定向/转发，参数拼接至URL或页面：
#### 2.4.1 重定向URL拼接XSS
Controller代码：
```java
@GetMapping("/mav/redirect")
public ModelAndView mavRedirect(@RequestParam("msg") String msg) {
    // 重定向时拼接用户输入到URL
    ModelAndView mav = new ModelAndView("redirect:/target?msg=" + msg);
    return mav; // msg为%3Cscript%3Ealert(1)%3C/script%3E（URL编码的<script>alert(1)</script>）
}
```
漏洞触发：重定向后的URL中包含恶意脚本，若目标页面解析URL参数并渲染（如`msg`参数直接插入DOM），触发XSS；或直接构造`javascript:`伪协议重定向。

#### 2.4.2 转发场景数据传递XSS
Controller代码：
```java
@GetMapping("/mav/forward")
public ModelAndView mavForward(@RequestParam("content") String content) {
    ModelAndView mav = new ModelAndView("forward:/inner/page");
    mav.addObject("content", content); // content=<script>alert(1)</script>
    return mav;
}
```
转发目标Controller：
```java
@GetMapping("/inner/page")
public String innerPage(@ModelAttribute("content") String content, Model model) {
    model.addAttribute("content", content);
    return "xss/inner-page"; // 模版未转义渲染content
}
```
漏洞触发：转发过程中用户输入未过滤，传递到目标页面后渲染执行脚本。

### 子场景2.5：ModelAndView设置响应头/上下文参数导致XSS
通过`ModelAndView`的`addAllObjects`或扩展方法设置响应上下文参数，间接导致XSS：
Controller代码：
```java
@GetMapping("/mav/context")
public ModelAndView mavContext(@RequestParam("title") String title) {
    ModelAndView mav = new ModelAndView("xss/context-page");
    Map<String, Object> context = new HashMap<>();
    context.put("pageTitle", title); // title=</title><script>alert(1)</script>
    mav.addAllObjects(context);
    return mav;
}
```
模版代码（JSP）：
```jsp
<title>${pageTitle}</title>
```
漏洞触发：用户输入闭合`<title>`标签，插入恶意脚本，执行XSS。

## 四、通用触发条件（跨场景）
1. 开发者误判「模版引擎默认转义」：认为所有场景均自动转义，忽略JS/CSS/URL等非HTML上下文的转义需求；
2. 手动拼接模版内容：在Controller或模版中手动拼接HTML/JS/CSS字符串（如`"<div>" + content + "</div>"`），绕过模版引擎转义；
3. 用户输入来源未覆盖：忽略Cookie、Header、数据库读取的恶意内容（非仅请求参数），这些数据传入模版仍触发XSS；
4. 富文本场景：允许用户输入HTML（如编辑器），未做白名单过滤，直接渲染富文本内容；
5. 动态生成JS/CSS文件：通过Spring MVC返回动态JS/CSS（如`.js`/`.css`后缀的视图），用户输入拼接其中，触发XSS。

## 五、总结
Spring MVC中无论返回String（视图名/直接内容）还是ModelAndView，XSS漏洞的核心触发逻辑均为：**用户可控数据未在对应上下文（HTML/属性/JS/CSS/URL）做针对性转义，直接嵌入渲染内容**。模版引擎的默认转义仅覆盖基础HTML场景，开发者的自定义配置（关闭转义）、上下文误判、手动拼接、特殊场景（如富文本、动态资源）是触发XSS的主要原因，且漏洞场景覆盖从数据传入（Controller）、数据传递（Model/ModelAndView）到数据渲染（模版引擎）的全链路。

