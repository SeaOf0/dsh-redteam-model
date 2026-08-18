# Java语言BeanShell RCE（远程代码执行）漏洞全解析

> 规则 ID：`any_BeanShell_codei` · 类别：codei · 关键 sink：Interpreter, eval, source
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java语言BeanShell RCE（远程代码执行）漏洞全解析
BeanShell（BSH）是一款基于Java的轻量级脚本语言，支持动态执行Java代码片段，常被集成在各类Java应用（如Apache Ant、JMeter、部分CMS/中间件）中用于动态扩展或脚本化配置。其设计初衷是简化Java代码的动态执行，但因输入校验、沙箱机制缺陷等问题，极易引发远程代码执行（RCE）漏洞，成为Java生态中高频高危漏洞类型之一。

## 一、漏洞核心原理
BeanShell的核心风险源于其**无限制的动态代码执行能力**：它允许将外部输入的字符串直接解析为BeanShell脚本或Java代码并执行，若攻击者能控制这些输入内容，即可注入恶意代码，接管目标服务器的Java进程。
具体底层逻辑：
1. BeanShell通过`Interpreter`类（核心执行引擎）解析执行脚本，支持直接调用Java原生API（如`Runtime.getRuntime().exec()`、`ProcessBuilder`）；
2. 若应用未对传入BeanShell的参数、配置项、请求参数等做严格校验，攻击者可构造恶意脚本字符串，被`Interpreter.eval()`、`bsh.Eval.eval()`等方法执行，进而触发RCE。

## 二、漏洞触发的核心场景分类
BeanShell RCE的触发场景可按“使用方式”和“漏洞根源”分为以下几类，覆盖绝大多数实际攻击场景：

### 场景1：直接调用BeanShell执行外部可控字符串（最基础且高发）
这是最典型的漏洞场景，应用直接将用户输入（如HTTP请求参数、表单数据、配置文件内容）传入BeanShell的执行方法，无任何过滤或校验。

#### 核心代码示例（漏洞代码）：
```java
import bsh.Interpreter;
import javax.servlet.http.HttpServletRequest;

public class BshRceServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request) {
        String cmd = request.getParameter("cmd"); // 攻击者可控输入
        Interpreter interpreter = new Interpreter();
        try {
            interpreter.eval(cmd); // 直接执行用户输入的字符串
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
#### 攻击方式：
攻击者发送请求：`http://target.com/bsh?cmd=Runtime.getRuntime().exec("calc.exe");`（Windows）或`cmd=Runtime.getRuntime().exec("id");`（Linux），即可执行任意系统命令。

#### 变种：
- 输入参数被拼接进BeanShell脚本后执行（如`interpreter.eval("String str = \"" + userInput + "\"; " + userInput);`）；
- 通过`bsh.Eval`工具类执行：`Eval.eval("bsh.Interpreter", userInput);`。

### 场景2：BeanShell沙箱绕过（官方沙箱失效）
BeanShell曾提供简单的“安全管理器/沙箱”（`bsh.SecurityManager`），试图限制危险API调用，但因沙箱设计缺陷，攻击者可通过多种方式绕过，即使启用沙箱仍能执行恶意代码。

#### 沙箱绕过的核心方式：
1. **反射绕过**：通过Java反射调用被沙箱禁止的类/方法，例如：
   ```java
   // 绕过沙箱执行命令
   Class clazz = Class.forName("java.lang.Runtime");
   Method getRuntime = clazz.getMethod("getRuntime");
   Runtime rt = (Runtime) getRuntime.invoke(null);
   rt.exec("id");
   ```
2. **类加载器绕过**：利用BeanShell的`ClassPath`机制加载自定义恶意类，或通过`bsh.ClassManager`加载危险类；
3. **内置对象绕过**：BeanShell内置`this`、`super`、`bsh.system`等对象，可通过这些对象间接调用系统API，例如：
   ```java
   bsh.system.setOut(new java.io.PrintStream(new java.io.FileOutputStream("/etc/passwd"))); // 读取敏感文件
   ```

### 场景3：依赖BeanShell的第三方组件/框架漏洞
很多Java组件（如JMeter、Apache Struts2、WebLogic）内部集成了BeanShell，若组件自身对BeanShell的使用未做安全控制，会间接引入RCE漏洞。

#### 典型案例：
1. **Apache Struts2 S2-003**：Struts2的`ActionSupport`类在处理表单参数时，会将可控参数传入BeanShell执行，攻击者构造`redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'cmd','/c','calc.exe'})).start()}`即可触发RCE；
2. **JMeter RCE（CVE-2021-4104）**：JMeter的HTTP(S) Test Script Recorder组件使用BeanShell解析配置，攻击者通过构造恶意HTTP请求，注入BeanShell脚本执行系统命令；
3. **WebLogic BeanShell RCE（CVE-2019-2725）**：WebLogic的`wls9_async_response.war`组件中，BeanShell脚本解析可控输入，导致未授权RCE。

### 场景4：BeanShell脚本文件/配置文件篡改
若应用加载外部BeanShell脚本文件（如`.bsh`、`.beanshell`）或从配置文件中读取BeanShell代码执行，攻击者可通过文件上传、文件篡改等方式替换脚本内容，触发RCE。

#### 攻击流程：
1. 攻击者通过文件上传漏洞，将恶意BeanShell脚本（如`exec("rm -rf /");`）上传至应用加载脚本的目录；
2. 应用启动或触发脚本加载时，执行恶意脚本；
3. 若配置文件（如`application.properties`）中包含BeanShell代码片段（如`bsh.script=${user.input}`），攻击者篡改配置项也可触发漏洞。

### 场景5：反序列化结合BeanShell触发RCE
Java反序列化漏洞中，若目标环境存在BeanShell依赖，攻击者可构造包含BeanShell`Interpreter`类的恶意序列化数据，反序列化后触发`eval()`方法执行代码。

#### 核心逻辑：
BeanShell的`Interpreter`类实现了`Serializable`接口，攻击者可序列化一个预先注入恶意脚本的`Interpreter`对象，目标应用反序列化该对象时，会自动执行脚本：
```java
// 恶意序列化对象构造
Interpreter evilInterpreter = new Interpreter();
evilInterpreter.eval("Runtime.getRuntime().exec(\"id\");");
// 将evilInterpreter序列化为字节流，发送给目标
```

### 场景6：BeanShell的“命名空间（Namespace）”注入
BeanShell的`Namespace`用于管理变量和方法作用域，若攻击者能控制`Namespace`中的变量，可注入恶意代码片段，在后续脚本执行时触发RCE。

#### 示例：
```java
// 漏洞代码：将用户输入存入Namespace
Namespace ns = new Namespace();
ns.setVariable("userScript", request.getParameter("script"), false);
Interpreter interpreter = new Interpreter(ns, null, null, false);
interpreter.eval("${userScript}"); // 执行Namespace中的恶意变量
```

## 三、漏洞触发的前提条件
1. 目标应用引入了BeanShell依赖（常见版本：bsh-2.0b4、bsh-2.0b5、bsh-3.0.x等，几乎所有版本均存在基础执行风险）；
2. 应用将外部可控输入传入BeanShell的执行方法（`eval()`、`evalScript()`、`run()`等）；
3. 应用未对输入做严格过滤（如禁止调用`Runtime`、`ProcessBuilder`、`Class`等危险类/方法）；
4. 执行BeanShell的Java进程具备较高权限（如root/Administrator），会放大漏洞危害。

## 四、漏洞危害特征
1. **无差别执行**：可执行任意Java代码或系统命令，包括文件读写、进程控制、权限提升；
2. **跨平台性**：基于Java特性，漏洞可在Windows、Linux、macOS等所有Java运行环境触发；
3. **隐蔽性**：BeanShell脚本执行无明显日志特征，攻击行为难以被常规WAF/日志审计发现；
4. **连锁危害**：若结合文件上传、反序列化、组件漏洞等，可实现无授权远程攻击。

## 五、特殊版本/环境下的漏洞差异
1. **BeanShell 1.x vs 2.x vs 3.x**：
   - 1.x版本：沙箱机制缺失，直接执行可控输入即可触发RCE；
   - 2.x版本：新增沙箱但存在大量绕过方式，官方未修复核心缺陷；
   - 3.x版本：部分危险API默认禁用，但仍可通过反射、类加载器绕过；
2. **Java 8及以上环境**：因模块化（Module）机制，部分反射绕过方式需适配，但核心RCE风险仍存在；
3. **安全管理器（Java SecurityManager）启用场景**：若应用启用了自定义SecurityManager，可能限制部分命令执行，但BeanShell仍可通过内存操作、网络请求等方式造成危害。

综上，BeanShell RCE的本质是“动态执行能力”与“输入不可信”的冲突，其触发场景覆盖了直接调用、沙箱绕过、第三方组件、文件篡改、反序列化等多个维度，是Java生态中需重点防范的高危漏洞类型。

