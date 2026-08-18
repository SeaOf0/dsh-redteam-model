# Java语言中的XSS漏洞

> 规则 ID：`other_any_xss` · 类别：xss · 关键 sink：PrintWriter, format, printf, println
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java语言中的XSS漏洞
XSS（Cross-Site Scripting，跨站脚本攻击）是Web应用中最常见的安全漏洞之一，本质是攻击者将恶意脚本注入到Web页面中，当用户访问该页面时，脚本在用户浏览器中执行，从而窃取信息、伪造操作、劫持会话等。Java作为Web开发的主流语言，因Web框架、数据处理方式、输出渲染逻辑等差异，XSS漏洞呈现出多种形态，以下从核心原理、分类、Java场景下的具体触发情况、典型代码示例等维度完整描述。

## 一、XSS漏洞的核心原理（Java视角）
Java Web应用的核心流程是：**接收用户输入→服务端处理→渲染输出到客户端页面**。XSS漏洞的本质是：用户输入的恶意脚本（如`<script>alert(1)</script>`）未被有效过滤/转义，服务端将其作为“合法内容”嵌入到响应页面（HTML/JS/CSS/XML等）中，浏览器解析页面时将恶意脚本当作正常代码执行。

Java生态中，XSS的触发核心是“输入未净化 + 输出未转义”，且因Java Web的分层架构（Controller、Service、View），漏洞可能出现在任意数据流转环节。

## 二、XSS漏洞的通用分类（适配Java场景）
根据攻击脚本的执行时机、注入方式和影响范围，XSS分为三类核心类型，Java应用中各有典型触发场景：

### 1. 存储型XSS（Persistent XSS，持久化XSS）
#### 核心特征
恶意脚本被**永久存储**在服务端（如MySQL、Redis、文件系统等），所有访问该数据的用户都会触发漏洞，危害最大。
#### Java场景下的触发条件
用户输入的恶意脚本通过Java接口（如Servlet、Spring MVC Controller）写入数据库，后续其他用户请求数据时，Java服务端从数据库读取该数据，直接渲染到页面响应中，未做转义。
#### 典型Java代码示例（漏洞代码）
```java
// 1. Spring MVC Controller接收用户输入并写入数据库（无过滤）
@PostMapping("/comment/add")
public String addComment(@RequestParam String content) {
    // 直接将用户输入存入数据库（MyBatis示例）
    commentMapper.insert(new Comment(null, content, new Date()));
    return "redirect:/comment/list";
}

// 2. 读取评论并渲染到页面（无转义）
@GetMapping("/comment/list")
public String listComments(Model model) {
    List<Comment> comments = commentMapper.selectAll();
    model.addAttribute("comments", comments); // 恶意content直接传入视图
    return "comment/list"; // 跳转到JSP/Thymeleaf视图
}

// 3. JSP视图渲染（直接输出用户输入）
<%
    List<Comment> comments = (List<Comment>) request.getAttribute("comments");
    for (Comment c : comments) {
%>
    <div class="comment"><%= c.getContent() %></div> <!-- 此处直接输出，触发XSS -->
<% } %>
```
#### 触发场景举例
- 论坛/评论区：用户发布含`<script>stealCookie()</script>`的评论，所有访问该评论区的用户都会执行脚本；
- 用户资料页：攻击者修改昵称/签名为`<img src=x onerror=alert(document.cookie)>`，其他用户查看其资料时触发；
- 订单备注：恶意备注脚本被存储，商家后台查看订单时执行。

### 2. 反射型XSS（Reflected XSS，非持久化XSS）
#### 核心特征
恶意脚本通过URL、表单等方式提交给服务端，服务端**即时反射**到响应页面中，仅对当前请求的用户生效，需诱骗用户点击含恶意参数的链接。
#### Java场景下的触发条件
Java服务端接收URL参数/表单参数后，未转义直接拼接进HTML响应（如Servlet直接输出、Controller返回拼接字符串、重定向带参数等）。
#### 典型Java代码示例（漏洞代码）
```java
// 示例1：Servlet直接反射URL参数
@WebServlet("/search")
public class SearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        String keyword = request.getParameter("kw"); // 接收用户输入的关键词
        // 直接将关键词输出到页面，无转义
        out.println("您搜索的关键词：" + keyword);
    }
}
// 攻击URL：http://localhost:8080/search?kw=<script>alert(document.cookie)</script>

// 示例2：Spring MVC返回拼接字符串（反射型）
@GetMapping("/hello")
@ResponseBody
public String hello(@RequestParam String name) {
    // 直接拼接用户输入到响应字符串
    return "Hello, " + name + "!";
}
// 攻击URL：http://localhost:8080/hello?name=<script>alert(1)</script>
```
#### 触发场景举例
- 搜索结果页：URL参数`kw`直接输出到页面，攻击者构造含脚本的搜索链接；
- 错误提示页：服务端将错误参数（如用户名不存在）直接输出到错误页面；
- 重定向页面：Controller将用户输入拼接进重定向URL的HTML响应中。

### 3. DOM型XSS（DOM-based XSS）
#### 核心特征
恶意脚本的执行完全发生在**客户端浏览器**，服务端仅传递数据，不参与脚本渲染，漏洞根源是前端JS操作DOM时未过滤用户输入，Java服务端本身不直接触发，但Java应用的前端（如JSP、Vue+Java）常存在此类漏洞。
#### Java场景下的关联触发条件
Java服务端返回的页面包含未过滤的前端JS代码，该代码从URL、本地存储等位置读取数据并插入DOM，导致脚本执行。
#### 典型Java+前端代码示例（漏洞代码）
```java
// Java Servlet仅返回包含前端JS的页面，不处理用户输入
@WebServlet("/dom-xss")
public class DomXssServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        // 输出包含前端JS的页面，JS读取URL参数并插入DOM
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<body>");
        out.println("<div id='content'></div>");
        out.println("<script>");
        // 前端JS读取URL参数并直接插入DOM，无转义
        out.println("var name = new URLSearchParams(window.location.search).get('name');");
        out.println("document.getElementById('content').innerHTML = 'Hello, ' + name;");
        out.println("</script>");
        out.println("</body>");
        out.println("</html>");
    }
}
// 攻击URL：http://localhost:8080/dom-xss?name=<script>alert(1)</script>
```
#### 触发场景举例
- 前端模板渲染：Thymeleaf/Vue页面中，JS从URL参数读取数据并通过`innerHTML`插入页面；
- JSP页面中的本地存储操作：前端JS读取`localStorage`中的用户输入（由Java服务端传递）并渲染；
- 动态菜单/导航：前端JS根据URL参数动态生成导航链接，未过滤脚本标签。

## 三、Java语言中XSS漏洞的特殊触发场景
除上述三类核心类型外，Java生态的特性导致一些特殊的XSS触发情况，需单独说明：

### 1. 框架内置功能的XSS漏洞
#### （1）JSP内置对象的直接输出
JSP的`<%= %>`、`out.print()`等语法直接输出用户输入时，无默认转义（JSP本身不提供自动转义），是最常见的XSS触发点：
```jsp
<%
    String username = request.getParameter("username");
    out.print("Welcome: " + username); // 直接输出，触发XSS
%>
```

#### （2）Spring框架的默认行为
- Spring MVC的`@ResponseBody`返回字符串时，默认不转义HTML特殊字符；
- Thymeleaf模板默认开启HTML转义（`th:text`），但使用`th:utext`（无转义文本）时会触发XSS：
  ```html
  <!-- Thymeleaf漏洞示例：th:utext直接输出用户输入 -->
  <div th:utext="${user.comment}"></div>
  ```

#### （3）Struts2框架的XSS风险
Struts2的OGNL表达式在页面中直接输出用户输入时，若未配置转义，易触发XSS：
```jsp
<!-- Struts2漏洞示例：直接输出OGNL表达式结果 -->
<s:property value="param.name" escapeHtml="false" />
```

### 2. 数据转换/序列化中的XSS
#### （1）JSON数据输出未转义
Java服务端返回JSON数据（如`@ResponseBody`返回Map/POJO），前端将JSON中的字符串直接插入DOM，若JSON中的内容含恶意脚本，触发XSS：
```java
// Java端返回含恶意脚本的JSON
@GetMapping("/user/json")
@ResponseBody
public Map<String, String> getUserJson(@RequestParam String nickname) {
    Map<String, String> map = new HashMap<>();
    map.put("nickname", nickname); // 接收恶意输入，如<script>alert(1)</script>
    return map; // 返回JSON：{"nickname":"<script>alert(1)</script>"}
}
// 前端漏洞：直接将JSON中的nickname插入DOM
<script>
    fetch('/user/json?nickname=<script>alert(1)</script>')
        .then(res => res.json())
        .then(data => {
            document.getElementById('nick').innerHTML = data.nickname;
        });
</script>
```

#### （2）XML/XMLHttpRequest响应未转义
Java服务端生成XML响应时，未转义XML特殊字符（如`<`、`>`、`&`），前端解析XML后插入页面，触发XSS：
```java
// Java生成XML响应（无转义）
@GetMapping("/xml")
public void getXml(HttpServletRequest request, HttpServletResponse response) throws IOException {
    response.setContentType("text/xml;charset=UTF-8");
    String content = request.getParameter("content");
    PrintWriter out = response.getWriter();
    out.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.println("<root><content>" + content + "</content></root>"); // 直接拼接
}
```

### 3. 文件上传/下载关联的XSS
#### （1）上传文件的文件名/备注未过滤
Java服务端允许上传文件，文件名含恶意脚本（如`<script>alert(1)</script>.png`），在文件列表页直接输出文件名，触发XSS：
```java
// 文件上传后，存储文件名并在列表页输出
@PostMapping("/upload")
public String upload(@RequestParam MultipartFile file) {
    String fileName = file.getOriginalFilename(); // 接收恶意文件名
    fileMapper.insert(fileName); // 存入数据库
    return "redirect:/file/list";
}

// 文件列表页JSP输出文件名
<% for (String name : fileNames) { %>
    <div>文件名：<%= name %></div> <!-- 触发XSS -->
<% } %>
```

#### （2）下载页面的文件名/参数输出未转义
下载链接的参数（如文件名、文件ID）直接输出到页面，攻击者构造含脚本的下载链接：
```java
@GetMapping("/download")
public String downloadPage(@RequestParam String fileId, Model model) {
    model.addAttribute("fileId", fileId); // 接收恶意fileId，如<script>alert(1)</script>
    return "download";
}
```

### 4. 富文本编辑器的XSS
Java应用集成富文本编辑器（如UEditor、CKEditor）时，若服务端未过滤富文本中的危险标签/属性（如`<script>`、`onclick`、`onerror`），攻击者可通过富文本插入恶意脚本，存储后触发存储型XSS：
```java
// 接收富文本内容并存储（无过滤）
@PostMapping("/article/save")
public String saveArticle(@RequestParam String richContent) {
    articleMapper.insert(new Article(null, richContent)); // 富文本含<script>标签
    return "redirect:/article/detail";
}
```

### 5. 跨域场景下的XSS协同攻击
Java服务端配置不当的CORS（跨域资源共享），允许恶意域名访问接口，攻击者结合XSS窃取跨域数据：
```java
// 不当的CORS配置：允许所有域名访问
@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*"); // 允许所有域名
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        // ...
    }
}
// 攻击者通过XSS脚本调用该接口，窃取用户数据
```

## 四、Java XSS漏洞的触发条件总结
无论哪种类型的XSS，在Java应用中触发需满足以下核心条件：
1. **输入入口**：存在用户可控的输入（URL参数、表单、文件、Cookie、Header等）；
2. **数据流转**：输入的恶意脚本未被过滤/净化，完整传递到输出环节；
3. **输出渲染**：恶意脚本被嵌入到响应内容（HTML/JS/XML/CSS）中，且浏览器将其解析为可执行代码；
4. **无防护机制**：Java服务端/前端未对输出做HTML转义、未过滤危险标签/属性。

以上是Java语言中XSS漏洞的完整描述，涵盖核心原理、分类、典型场景、代码示例及特殊触发情况，未包含修复建议。

