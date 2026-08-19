# Java EL注入漏洞（Expression Language Injection）完整解析

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`other_el_codei` · 类别：codei · 关键 sink：ExpressionFactory, createValueExpression
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java EL注入漏洞（Expression Language Injection）完整解析
EL（Expression Language，表达式语言）是Java EE规范中用于简化JSP、JSF等视图层开发的脚本语言，核心作用是在视图层便捷访问后端数据（如`${user.name}`）。**EL注入漏洞** 指攻击者通过构造恶意EL表达式，注入到应用程序的EL解析流程中，导致表达式被执行，进而实现代码执行、敏感信息泄露、权限绕过等攻击效果。

#### 一、EL的核心特性与执行机制
EL的执行依赖`ELContext`上下文环境，核心组件包括：
1. **表达式解析器（ELResolver）**：负责解析`${}`或`#{}`格式的表达式，映射到Java对象、方法调用、运算符执行等；
2. **隐式对象**：EL内置了如`pageContext`（页面上下文）、`request`（请求对象）、`session`（会话）、`application`（应用上下文）、`param`（请求参数）等隐式对象，可直接通过表达式访问；
3. **执行权限**：EL默认支持调用Java方法（如`${obj.method()}`）、访问类静态方法（需开启特定配置）、执行算术/逻辑运算等。

EL注入的本质是：**用户可控的输入未被过滤/转义，直接拼接进EL表达式并被解析执行**，攻击者借此篡改表达式逻辑，触发恶意操作。

#### 二、EL注入的触发场景分类
EL注入的触发核心是“用户输入参与EL表达式构造”，根据使用场景和EL版本（EL 2.1/3.0+）、容器（Tomcat/Jetty/GlassFish）的差异，主要分为以下几类：

### 场景1：JSP页面直接拼接用户输入到EL表达式中
这是最基础的触发场景，常见于开发者手动拼接EL表达式（而非使用标签库）。
#### 示例代码（漏洞代码）：
```jsp
<%-- 从请求参数获取用户输入，直接拼接进EL表达式 --%>
<%
    String userInput = request.getParameter("name");
    // 拼接成EL表达式并输出（实际中可能通过out.print执行解析）
    out.print("${'" + userInput + "'}");
%>
```
#### 攻击原理：
攻击者构造`name`参数为：`'} + (new java.lang.Runtime()).exec('calc') + '`，拼接后的EL表达式变为：
```el
${'' + (new java.lang.Runtime()).exec('calc') + ''}
```
若容器允许EL执行Runtime类方法，将直接触发系统命令执行。

#### 关键前提：
- JSP页面未开启EL禁用（默认启用，可通过`<%@ page isELIgnored="true" %>`禁用）；
- 用户输入未被转义（如未过滤`${}`、`()`、`+`等EL特殊字符）。

### 场景2：框架/组件间接解析用户输入为EL表达式
许多Java Web框架（如Struts2、Spring MVC、JSF）或组件（如JSTL）会自动解析特定上下文的用户输入为EL表达式，若输入可控则触发注入。

#### 子场景2.1：Struts2的EL注入（OGNL/EL混用）
Struts2默认使用OGNL，但部分版本/配置下会解析EL表达式，例如：
- Struts2标签的`value`属性若直接绑定用户输入，且配置为EL解析模式：
  ```jsp
  <s:property value="%{#param.name}" />
  ```
  若`name`参数构造为`${T(java.lang.Runtime).getRuntime().exec('calc')}`，且Struts2上下文允许EL解析，将触发执行。

#### 子场景2.2：Spring MVC的EL注入
Spring MVC的`@Value`注解、SpEL（Spring表达式语言，与EL语法相似）若误用用户输入，或视图层（如Thymeleaf）配置不当：
- Thymeleaf中若使用`${param.name}`且未做转义，攻击者构造`name`为`${T(java.lang.System).getProperty('user.dir')}`，可泄露服务器目录。

#### 子场景2.3：JSF的EL注入
JSF（JavaServer Faces）重度依赖EL，若页面中`h:outputText value="#{param.input}"`未过滤输入，攻击者构造`input`为`#{request.getSession().getAttribute('adminToken')}`，可窃取会话中的敏感数据。

### 场景3：EL 3.0+的静态方法调用注入
EL 3.0引入了`T()`语法支持直接调用Java类的静态方法（需容器允许），这大幅扩大了注入的危害：
#### 攻击表达式示例：
```el
${T(java.lang.Runtime).getRuntime().exec('rm -rf /')}  // 命令执行
${T(java.lang.Class).forName('java.sql.Driver').newInstance()}  // 加载恶意类
${T(java.lang.System).getenv('PATH')}  // 泄露环境变量
```
#### 触发条件：
- 容器（如Tomcat 8+、GlassFish 4+）启用了EL 3.0特性；
- 应用未限制EL对`java.lang`、`java.io`等危险包的访问。

### 场景4：EL隐式对象滥用注入
EL内置的隐式对象是注入的核心突破口，攻击者可通过操控这些对象实现多种攻击：
| 隐式对象       | 攻击用途                                  | 示例表达式                          |
|----------------|-------------------------------------------|-----------------------------------|
| `pageContext`  | 访问请求/响应对象、获取ServletContext     | `${pageContext.request.getHeader('Cookie')}` |
| `request`      | 读取请求参数、头信息、会话属性            | `${request.session.getAttribute('user')}` |
| `application`  | 访问应用全局属性、ClassLoader             | `${application.getAttribute('config')}` |
| `paramValues`  | 批量读取请求参数                          | `${paramValues.id[0]}`            |
| `initParam`    | 读取web.xml中的初始化参数                 | `${initParam.db_password}`        |

#### 示例攻击：
通过`pageContext`获取服务器绝对路径：
```el
${pageContext.servletContext.getRealPath('/')}
```
结果可能返回`/usr/local/tomcat/webapps/ROOT/`，为后续文件写入攻击铺垫。

### 场景5：EL运算符与逻辑注入
EL支持算术运算、逻辑运算、三元表达式等，攻击者可通过运算符篡改表达式逻辑，实现权限绕过：
#### 漏洞代码示例：
```jsp
<%-- 意图：仅当userRole=admin时显示管理界面 --%>
<c:if test="${param.role == 'admin'}">
    <a href="/admin">管理后台</a>
</c:if>
```
#### 攻击构造：
攻击者构造`role`参数为`admin' or '1'=='1`，拼接后的EL表达式变为：
```el
${param.role == 'admin' or '1'=='1'}
```
表达式恒为`true`，绕过权限验证。

### 场景6：嵌套EL表达式注入（多层解析）
部分应用会对用户输入进行多次解析（如先拼接为字符串，再二次解析为EL），导致嵌套注入：
#### 漏洞代码逻辑：
```java
// 后端拼接表达式，前端二次解析
String input = request.getParameter("data");
String elExpr = "${" + input + "}";
// 将elExpr存入请求属性，JSP页面读取并解析
request.setAttribute("expr", elExpr);
```
JSP页面：
```jsp
${expr}  // 二次解析，触发注入
```
#### 攻击构造：
攻击者构造`data`为`T(java.lang.Runtime).getRuntime().exec('calc')`，最终执行的表达式为：
```el
${T(java.lang.Runtime).getRuntime().exec('calc')}
```

### 三、EL注入的危害分级
根据注入场景和权限，危害从低到高分为：
1. **信息泄露**：窃取会话、配置、服务器路径、环境变量等；
2. **权限绕过**：篡改EL逻辑，越权访问功能/数据；
3. **代码执行**：调用Runtime、ProcessBuilder等执行系统命令；
4. **服务器接管**：通过加载恶意类、写入webshell等完全控制服务器。

### 四、EL注入的触发前提总结
1. 用户输入可进入EL表达式的解析流程（未被过滤/转义）；
2. 应用/容器未禁用EL的危险特性（如静态方法调用、方法执行）；
3. EL解析的上下文权限过高（如以Tomcat管理员权限执行）；
4. 未限制EL对敏感类/方法的访问（如Runtime、Class.forName）。

综上，EL注入的核心风险在于“用户可控输入与EL解析的无防护结合”，其攻击面覆盖从简单的信息泄露到远程代码执行，且因EL是Java EE的标准组件，几乎所有基于JSP/JSF/Struts2/Spring MVC的应用都存在潜在风险。

