# Java ScriptEngine 注入漏洞

> 规则 ID：`any_ScriptEngine_codei` · 类别：codei · 关键 sink：Context, ScriptEngine, ScriptEngineFactory, eval, evaluateString, getMethodCallSyntax, getProgram
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java ScriptEngine 注入漏洞
Java 的 `ScriptEngine` 是 JDK 提供的脚本引擎接口（位于 `javax.script` 包），支持执行 JavaScript、Groovy、Python 等脚本语言，其核心设计目标是实现 Java 与脚本语言的交互，但因使用不当或底层实现缺陷，极易引发**脚本注入漏洞**（也常被称为代码执行漏洞）。以下从漏洞本质、触发场景、不同维度的触发情况、底层原理、典型案例等维度完整描述该漏洞，暂不涉及修复建议。

## 一、漏洞本质
ScriptEngine 注入漏洞的核心是：**攻击者能够控制传入 ScriptEngine 的脚本代码片段/参数，使引擎执行非预期的、恶意的脚本代码**，而这些脚本代码可通过脚本引擎与 Java 底层的交互能力，突破沙箱限制（若存在），最终实现任意 Java 代码执行、系统命令执行、文件读写、权限提权等高危操作。

ScriptEngine 本身是“中立”的执行容器，漏洞的根源并非接口本身，而是**输入未做严格校验** + **脚本引擎的权限未做限制** + **脚本与 Java 环境的无缝交互能力** 三者叠加的结果。

## 二、核心触发前提
1. 应用程序通过 `ScriptEngineManager` 获取脚本引擎实例（如 Nashorn、Rhino、GraalJS 等 JavaScript 引擎）；
2. 执行脚本的代码中，包含**用户可控的输入**（如 HTTP 参数、表单数据、配置文件内容、数据库查询结果等）；
3. 脚本引擎未做安全限制（如未禁用 Java 类加载、未限制反射、未禁用系统命令执行等）；
4. 执行脚本的上下文拥有较高权限（如应用以 root/Administrator 身份运行，或拥有读写敏感文件、访问数据库的权限）。

## 三、不同维度的触发情况
### （一）按脚本引擎类型划分
Java 内置/常用的脚本引擎均存在注入风险，不同引擎的触发方式略有差异：

#### 1. Nashorn 引擎（JDK 8 内置，JDK 15 移除）
Nashorn 是 JDK 8 替代 Rhino 的 JavaScript 引擎，对 Java 交互的支持极为灵活，是最易触发注入的引擎之一。
- **基础注入场景**：直接拼接用户输入到脚本字符串中执行
  示例代码（存在漏洞）：
  ```java
  ScriptEngineManager manager = new ScriptEngineManager();
  ScriptEngine engine = manager.getEngineByName("nashorn");
  // userInput 为用户可控输入，如 "1; java.lang.Runtime.getRuntime().exec('calc.exe')"
  String script = "var result = " + userInput + "; result;";
  engine.eval(script);
  ```
  触发原理：用户输入的恶意代码被直接拼接进脚本，Nashorn 会执行包含 Java 原生方法调用的 JavaScript 代码，通过 `Runtime`/`ProcessBuilder` 执行系统命令。

- **进阶注入场景**：绕过简单过滤的注入
  若应用过滤了 `Runtime`，攻击者可通过反射、类加载器等方式绕过：
  用户输入示例：
  ```javascript
  1;
  var clazz = Java.type('java.lang.Class');
  var rt = clazz.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null);
  rt.exec('cmd /c dir');
  ```
  Nashorn 支持 `Java.type()` 直接加载 Java 类，即使直接调用 `Runtime` 被过滤，也可通过反射、类名拼接（如 `'java.lang.R'+'untime'`）绕过。

- **无拼接的注入场景**：直接执行用户输入的完整脚本
  若应用直接将用户输入作为脚本内容执行（而非拼接），风险更高：
  ```java
  // userInput 直接是恶意脚本：Java.type('java.io.FileWriter').newInstance('test.txt').write('malicious');
  engine.eval(userInput);
  ```

#### 2. Rhino 引擎（JDK 6/7 内置，JDK 8 仍可兼容使用）
Rhino 作为老牌 JavaScript 引擎，交互逻辑与 Nashorn 略有不同，但注入原理一致：
- 基础注入：通过 `Packages` 访问 Java 类（Rhino 特有）
  用户输入示例：
  ```javascript
  Packages.java.lang.Runtime.getRuntime().exec('ls -la');
  ```
- 绕过过滤：通过 `JavaImporter` 导入类
  ```javascript
  var importer = new JavaImporter(Packages.java.lang);
  with (importer) {
      Runtime.getRuntime().exec('cat /etc/passwd');
  }
  ```

#### 3. GraalJS 引擎（JDK 11+ 推荐替代 Nashorn 的引擎）
GraalJS 是 GraalVM 提供的高性能 JavaScript 引擎，也可集成到标准 JDK 中，其安全机制比 Nashorn 更严格，但配置不当仍可注入：
- 默认场景：GraalJS 默认禁用直接访问 Java 类，但通过 `--engine.AllowAllAccess=true` 等参数开启后，可触发注入：
  用户输入示例：
  ```javascript
  Java.type('java.lang.Runtime').getRuntime().exec('whoami');
  ```
- 沙箱逃逸场景：即使开启基础沙箱，攻击者可通过 GraalJS 的内部 API 绕过限制，访问 Java 底层。

#### 4. 非 JavaScript 引擎（Groovy、Python 等）
ScriptEngine 也支持 Groovy、Jython（Python）、JRuby 等引擎，这些引擎的注入风险更高（Groovy 几乎等同于 Java 代码执行）：
- Groovy 引擎注入示例：
  应用代码：
  ```java
  ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
  // userInput 为用户可控："new ProcessBuilder(['sh','-c','id']).start()"
  engine.eval(userInput);
  ```
  触发结果：直接执行系统命令，Groovy 对 Java 代码的兼容性极高，几乎所有 Java 代码都可直接在 Groovy 中执行。
- Jython 引擎注入示例：
  用户输入示例（Python 调用 Java 类）：
  ```python
  from java.lang import Runtime
  Runtime.getRuntime().exec('ping -c 1 127.0.0.1')
  ```

### （二）按输入可控程度划分
#### 1. 完全可控输入
用户可直接提交完整的恶意脚本代码，是最严重的场景：
- 场景示例：应用提供“在线脚本调试”功能，允许用户输入 JavaScript 代码并通过 ScriptEngine 执行，无任何校验；
- 攻击效果：攻击者可执行任意 Java 代码、系统命令，完全控制服务器。

#### 2. 部分可控输入（拼接注入）
用户输入仅作为脚本的一部分（如变量值、表达式片段），通过拼接突破上下文限制：
- 场景示例：应用通过用户输入的“计算表达式”动态生成脚本：
  ```java
  // 需求：计算用户输入的数学表达式，如 "1+2*3"
  String userInput = request.getParameter("expr");
  String script = "var res = " + userInput + "; print(res);";
  engine.eval(script);
  ```
- 攻击输入：`1; java.lang.Runtime.getRuntime().exec('rm -rf /')`
- 触发原理：分号分隔 JavaScript 语句，用户输入的表达式后拼接恶意代码，引擎会依次执行所有语句。

#### 3. 间接可控输入（数据污染）
用户输入不直接传入 ScriptEngine，但会污染脚本执行的上下文（如绑定的变量）：
- 场景示例：应用将用户输入绑定为脚本上下文的变量，脚本中引用该变量：
  ```java
  ScriptContext context = engine.getContext();
  // userInput 为用户可控："',''); java.lang.Runtime.getRuntime().exec('calc'); //"
  context.setAttribute("username", userInput, ScriptContext.ENGINE_SCOPE);
  // 脚本拼接变量，形成注入
  String script = "var user = '" + context.getAttribute("username") + "'; print(user);";
  engine.eval(script);
  ```
- 触发原理：用户输入通过闭合字符串、注释剩余代码，拼接出恶意语句。

### （三）按沙箱/权限配置划分
#### 1. 无沙箱限制（默认场景）
绝大多数应用使用 ScriptEngine 时未配置任何沙箱，引擎拥有与当前 Java 进程相同的权限：
- 攻击能力：可执行任意系统命令、读写任意文件（进程权限范围内）、访问数据库、调用任意 Java API；
- 典型危害：删除核心文件、窃取敏感数据、植入后门程序。

#### 2. 弱沙箱限制（仅禁用部分 API）
应用通过自定义 `SecurityManager` 或引擎内置配置禁用了部分敏感 API（如 `Runtime.exec`），但未完全限制：
- 绕过方式：
  - 反射：通过 `Class.forName` 加载被禁用的类，调用私有方法；
  - 替代 API：使用 `ProcessBuilder` 替代 `Runtime.exec` 执行命令；
  - 类加载器：通过自定义类加载器加载恶意类；
  - JNI 调用：通过 Java 调用本地方法（JNI）绕过限制。

#### 3. 严格沙箱限制（但配置不当）
应用使用引擎自带的沙箱（如 Nashorn 的 `SecureJS`、GraalJS 的沙箱），但因配置错误导致沙箱失效：
- 示例：Nashorn 沙箱未禁用 `Java.type()`，攻击者仍可加载任意 Java 类；
- 示例：GraalJS 沙箱未限制 `polyglot` 接口，攻击者通过跨语言调用绕过限制。

### （四）按漏洞触发后的危害程度划分
#### 1. 任意文件读写
攻击者通过脚本调用 Java 的 `File`、`FileReader`、`FileWriter`、`Files` 等类，读写服务器文件：
- 读文件：读取 `/etc/passwd`、`application.properties`、数据库配置文件等；
- 写文件：写入恶意 JSP 后门、修改配置文件（如添加管理员账号）。

#### 2. 任意系统命令执行
通过 `Runtime.exec`、`ProcessBuilder`、`ProcessImpl` 等执行系统命令，控制服务器：
- 危害：反弹 Shell、挖矿、勒索软件、横向渗透。

#### 3. 任意 Java 代码执行
通过脚本加载并执行恶意 Java 类（如通过 `ClassLoader` 加载远程类，或动态编译 Java 代码）：
- 示例：
  ```javascript
  // Nashorn 中动态编译执行 Java 代码
  var compiler = Java.type('javax.tools.ToolProvider').getSystemJavaCompiler();
  var file = Java.type('java.io.File').newInstance('Malicious.java');
  compiler.run(null, null, null, file.getPath());
  // 加载并执行编译后的类
  var clazz = Java.type('Malicious');
  clazz.execute();
  ```

#### 4. 权限提权
若 Java 进程以高权限运行（如 root），攻击者可通过脚本修改系统权限配置（如添加 sudo 权限、修改 `/etc/sudoers`）；若进程权限较低，可通过提权漏洞（结合脚本注入）实现权限提升。

#### 5. 数据泄露
通过脚本访问应用内存中的敏感数据（如会话信息、用户凭证、数据库连接），或调用应用的业务 API 窃取数据。

## 四、典型触发场景（业务层面）
1. **在线计算器/表达式解析**：应用为实现动态计算功能，将用户输入的表达式传入 ScriptEngine 执行；
2. **动态配置解析**：应用将用户可控的配置内容（如 JSON/YAML 中的脚本片段）通过 ScriptEngine 解析；
3. **模板引擎集成**：部分模板引擎（如 FreeMarker、Velocity）支持调用 ScriptEngine，若模板内容可控则触发注入；
4. **后台管理工具**：运维后台提供“脚本执行”功能，供管理员调试，但未限制访问权限或输入校验；
5. **第三方组件依赖**：应用依赖的第三方库（如规则引擎、工作流引擎）内部使用 ScriptEngine，且未过滤用户输入；
6. **序列化/反序列化配合**：攻击者通过反序列化漏洞传入恶意脚本内容，触发 ScriptEngine 执行。

## 五、底层技术原理
ScriptEngine 注入的核心技术基础是 **Java 脚本引擎的“脚本- Java 互操作”能力**：
1. 所有符合 JSR 223 规范的脚本引擎，都设计了脚本语言访问 Java 类、方法、字段的接口（如 Nashorn 的 `Java.type()`、Rhino 的 `Packages`）；
2. 脚本引擎执行时，运行在与 Java 主线程相同的 JVM 上下文，拥有相同的类加载器、权限上下文；
3. 脚本语言的动态性（如 JavaScript 的动态类型、Groovy 的动态编译）使得攻击者可灵活构造恶意代码，绕过简单的静态过滤；
4. JVM 的 `SecurityManager` 是可选配置，默认未启用，导致脚本引擎无权限限制，可调用任意敏感 API。

## 六、易被忽视的触发情况
1. **编码转换导致的注入**：应用对用户输入做了 URL 编码/Base64 解码，但解码后未校验，攻击者可通过编码绕过前端过滤；
2. **多引擎叠加注入**：应用同时加载多个脚本引擎，攻击者通过一个引擎的漏洞触发另一个引擎的执行（如 JavaScript 调用 Groovy 引擎）；
3. **脚本缓存导致的注入**：应用缓存执行过的脚本，攻击者输入的恶意代码被缓存后，后续请求无需重新输入即可触发；
4. **异常处理中的注入**：应用在异常捕获代码中执行脚本，攻击者通过构造异常输入，将恶意代码传入异常处理逻辑；
5. **跨上下文注入**：ScriptEngine 的上下文（`ScriptContext`）被多个请求共享，攻击者可通过修改上下文变量，影响其他请求的脚本执行。

综上，Java ScriptEngine 注入漏洞的触发场景覆盖“输入可控性、引擎类型、权限配置、业务场景”等多个维度，其核心风险在于脚本引擎与 Java 环境的无缝交互能力，以及默认无权限限制的运行特性，使得任意可控输入都可能引发高危代码执行。

