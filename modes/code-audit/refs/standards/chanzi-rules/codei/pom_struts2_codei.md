# Java Struts2 远程代码执行（RCE）漏洞

> 规则 ID：`pom_struts2_codei` · 类别：codei · 关键 sink：（cypher 结构提取，见原文）
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Struts2 远程代码执行（RCE）漏洞
Struts2 作为 Apache 基金会开源的 MVC 框架，因核心的 OGNL（Object-Graph Navigation Language）表达式解析机制设计缺陷，曾爆发多起高危远程代码执行漏洞，成为 Java Web 应用中最具代表性的安全风险之一。以下从漏洞根源、核心触发逻辑、不同版本/场景的典型漏洞变体、触发条件与影响范围等维度，完整描述各类 RCE 漏洞情况。

## 一、漏洞核心根源：OGNL 表达式解析的设计缺陷
Struts2 依赖 OGNL 实现数据绑定（如将 HTTP 请求参数映射到 Action 属性），其核心风险在于：**框架未对用户输入的表达式进行严格校验/沙箱限制，导致恶意构造的 OGNL 表达式可被解析执行，进而触发任意 Java 代码执行**。

关键执行链路：
1. 用户输入的恶意参数被 Struts2 拦截器（如 `ParametersInterceptor`、`CookieInterceptor` 等）接收；
2. 输入被带入 OGNL 表达式解析器（`OgnlValueStack`）执行；
3. 恶意表达式通过 OGNL 的静态方法调用、类实例化等语法，绕过框架限制执行系统命令或任意代码。

OGNL 本身支持的危险语法是基础：
- 静态方法调用：`@java.lang.Runtime@getRuntime().exec("cmd")`
- 类实例化：`new java.lang.ProcessBuilder(new String[]{"cmd","/c","whoami"}).start()`
- 上下文变量调用：`#_memberAccess.allowStaticMethodAccess=true`（突破沙箱限制）

## 二、Struts2 RCE 漏洞的核心分类与典型变体
Struts2 的 RCE 漏洞并非单一漏洞，而是不同版本因拦截器、表达式解析逻辑、沙箱机制不同，衍生出的多类变体，核心可分为「参数解析型」「结果处理型」「类型转换型」三大类，以下是影响范围最广的典型漏洞：

### （一）参数解析型 RCE：最核心、最常见的类别
此类漏洞源于 `ParametersInterceptor`（参数拦截器）对用户输入的不当解析，是 Struts2 RCE 漏洞的主流形式，典型代表包括 S2-001、S2-007、S2-016、S2-032、S2-045/046 等。

#### 1. S2-001（CVE-2007-4556）：首个大规模 RCE 漏洞
- 影响版本：Struts 2.0.0 ~ 2.0.8
- 触发场景：Action 中存在可被用户控制的属性，且属性类型为 `String` 以外的复杂类型（如 `Integer`、自定义对象）；
- 触发逻辑：当框架尝试将用户输入的字符串转换为目标类型时，恶意 OGNL 表达式被直接解析执行；
- 典型 payload：`?name=(%23context["xwork.MethodAccessor.denyMethodExecution"]=+new+java.lang.Boolean(false),+%23_memberAccess["allowStaticMethodAccess"]=true,+%23a=@java.lang.Runtime@getRuntime().exec("cmd /c whoami").getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23out.println(%23d),%23out.close())`
- 核心特点：首次暴露 OGNL 沙箱绕过的可能性，无严格的表达式过滤，直接执行任意代码。

#### 2. S2-007（CVE-2009-2891）：OGNL 表达式重复解析漏洞
- 影响版本：Struts 2.0.0 ~ 2.2.3
- 触发场景：Action 属性为 `Map` 或 `List` 类型，且用户可提交包含 OGNL 表达式的键/值；
- 触发逻辑：框架对用户输入的 Map/List 键值进行两次 OGNL 解析，首次解析将表达式转为字符串，第二次解析执行该字符串；
- 典型 payload：`?map['key']=%25{@java.lang.Runtime@getRuntime().exec("whoami")}`（%25 是 URL 编码的 %，触发二次解析）；
- 核心特点：依赖「重复解析」逻辑，仅针对集合类型属性生效，漏洞利用条件略苛刻但危害相同。

#### 3. S2-016（CVE-2013-2135）：命名空间解析 RCE
- 影响版本：Struts 2.0.0 ~ 2.3.15
- 触发场景：Struts2 的 `DefaultActionMapper` 处理 URL 命名空间时，未过滤用户输入的 OGNL 表达式；
- 触发逻辑：通过修改 URL 中的命名空间参数（`namespace`），注入 OGNL 表达式，框架解析命名空间时执行恶意代码；
- 典型 payload：`/struts2-blank/example/%24%7B%23_memberAccess.allowStaticMethodAccess%3Dtrue%2C@java.lang.Runtime@getRuntime().exec(%22whoami%22)%7D/action.action`（`${}` 包裹表达式，URL 编码后注入命名空间）；
- 核心特点：无需依赖 Action 特定属性，直接通过 URL 路径注入，利用门槛极低，是传播最广的 Struts2 RCE 之一。

#### 4. S2-032（CVE-2016-3081）：动态方法调用+OGNL 解析
- 影响版本：Struts 2.3.18 ~ 2.3.28.1（除 2.3.20.3/24.3）
- 触发场景：开启动态方法调用（`struts.enable.DynamicMethodInvocation=true`，默认开启），且 URL 中可注入 OGNL 表达式；
- 触发逻辑：框架处理动态方法调用时，将 URL 中的方法名参数作为 OGNL 表达式解析，绕过沙箱执行代码；
- 典型 payload：`/action!%25{@java.lang.Runtime@getRuntime().exec("whoami")}.action`；
- 核心特点：依赖动态方法调用开关，修复版本仅针对特定版本，后续仍有变种。

#### 5. S2-045/046（CVE-2017-5638/CVE-2017-5639）：Content-Type 头注入
- 影响版本：S2-045（2.3.5 ~ 2.3.31、2.5 ~ 2.5.10）；S2-046（2.3.x 全版本、2.5.x 部分版本）
- 触发场景：通过 HTTP 请求头（Content-Type、Content-Disposition）注入 OGNL 表达式；
- 触发逻辑：框架解析 `multipart/form-data` 类型请求时，未过滤请求头中的恶意 OGNL 表达式，导致解析执行；
- 典型 payload（S2-045）：`Content-Type: %{#_memberAccess.allowStaticMethodAccess=true,@java.lang.Runtime@getRuntime().exec("whoami")}`；
- 核心特点：无需在 URL/表单参数中注入，通过请求头绕过部分 WAF 检测，利用隐蔽性高。

### （二）结果处理型 RCE：基于结果页/模板解析的漏洞
此类漏洞源于 Struts2 对结果页（Result）、模板引擎（如 Freemarker）的解析逻辑缺陷，典型代表为 S2-005、S2-020。

#### 1. S2-005（CVE-2008-5354）：OGNL 表达式在结果页执行
- 影响版本：Struts 2.0.0 ~ 2.1.8.1
- 触发场景：使用 Freemarker/Velocity 模板引擎，且结果页中包含用户可控的 OGNL 表达式变量；
- 触发逻辑：框架渲染结果页时，未过滤用户输入的表达式，直接解析执行；
- 典型 payload：在表单提交参数中注入 `%{@java.lang.Runtime@getRuntime().exec("calc")}`，结果页渲染时执行；
- 核心特点：依赖前端模板渲染，漏洞利用需结合结果页的变量输出逻辑。

#### 2. S2-020（CVE-2014-0094）：参数拦截器绕过+结果解析
- 影响版本：Struts 2.0.0 ~ 2.3.16
- 触发场景：通过修改 `struts.enable.SlashesInActionNames` 等配置，绕过参数拦截器的过滤规则；
- 触发逻辑：构造特殊的 URL 路径，将 OGNL 表达式注入到结果页的解析流程中，绕过框架的基础过滤；
- 核心特点：属于「绕过型」漏洞，利用框架配置项的逻辑缺陷，突破已有防护措施。

### （三）类型转换型 RCE：基于 OGNL 类型转换的漏洞
此类漏洞源于 OGNL 对不同类型数据转换时的解析缺陷，典型代表为 S2-048、S2-052。

#### 1. S2-048（CVE-2017-9791）：OGNL 类型转换 RCE
- 影响版本：Struts 2.3.x 全版本、2.5.x 部分版本
- 触发场景：Action 中存在 `Date` 类型属性，且用户可提交包含 OGNL 表达式的日期字符串；
- 触发逻辑：框架将用户输入的字符串转换为 `Date` 类型时，恶意 OGNL 表达式被解析执行；
- 核心特点：仅针对特定数据类型（Date）生效，利用条件较窄，但仍可触发远程代码执行。

#### 2. S2-052（CVE-2017-9805）：XML 配置解析 RCE
- 影响版本：Struts 2.0.0 ~ 2.5.12
- 触发场景：使用 `Struts2` 的 XML 配置文件（如 `struts.xml`）动态加载功能，且用户可控制 XML 内容；
- 触发逻辑：框架解析 XML 配置时，对其中的 OGNL 表达式未做过滤，导致注入的表达式被执行；
- 核心特点：属于「配置解析」漏洞，需控制 XML 配置文件的输入，通常结合文件上传等漏洞利用。

## 三、漏洞触发的通用前置条件
无论哪种变体，Struts2 RCE 漏洞的触发通常满足以下核心条件：
1. **框架版本未修复**：使用存在漏洞的 Struts2 核心包（`struts2-core.jar`）版本，未升级到安全版本；
2. **OGNL 解析未被限制**：默认情况下 Struts2 未禁用 OGNL 的静态方法调用、类实例化等危险操作（或可通过 payload 绕过沙箱）；
3. **用户输入可进入 OGNL 解析流程**：恶意表达式被带入 `OgnlValueStack` 的 `findValue()`、`setValue()` 等核心方法中执行；
4. **无额外防护措施**：未部署 WAF、未对输入做严格过滤（如拦截 `${}`、`%{}` 等 OGNL 表达式标识）。

## 四、漏洞影响范围与执行能力
1. **执行权限**：以运行 Web 容器（如 Tomcat）的用户权限执行代码（通常为 `tomcat`、`www-data` 或 `root`）；
2. **执行内容**：可执行任意系统命令（如 `whoami`、`rm -rf /`、`nc 反弹shell`）、加载恶意类、读写服务器文件、控制整个应用服务器；
3. **影响范围**：覆盖所有使用漏洞版本 Struts2 的 Java Web 应用，包括电商、政务、金融等核心系统；
4. **利用难度**：多数漏洞（如 S2-016、S2-045）利用门槛极低，无需认证、无需了解应用业务逻辑，仅需发送构造好的 HTTP 请求即可触发。

## 五、特殊场景：沙箱绕过与变种利用
Struts2 后续版本曾尝试通过「OGNL 沙箱」限制危险操作（如禁用静态方法调用），但攻击者通过以下方式绕过：
1. **修改沙箱配置变量**：通过 OGNL 表达式修改 `#_memberAccess.allowStaticMethodAccess`、`#_memberAccess.allowPrivateAccess` 等变量，突破沙箱限制；
2. **使用替代类/方法**：避开被禁用的 `Runtime` 类，改用 `ProcessBuilder`、`java.lang.Class` 等类执行代码；
3. **链式调用绕过**：通过多层 OGNL 表达式嵌套，绕过简单的字符匹配过滤（如 `%{#a=1,#b=@java.lang.Runtime@getRuntime(),#b.exec("cmd")}`）。

## 六、漏洞传播与利用特征
1. **请求特征**：请求中包含 `${}`、`%{}` 等 OGNL 表达式标识，或包含 `@java.lang.Runtime@`、`exec(`、`ProcessBuilder` 等关键词；
2. **传输位置**：恶意表达式可出现在 URL 路径、查询参数、表单参数、HTTP 请求头（Content-Type、Cookie、Referer）、Multipart 请求体等位置；
3. **编码特征**：为绕过 WAF，攻击者常对表达式进行 URL 编码、Base64 编码、Unicode 编码等多层编码。

综上，Struts2 远程代码执行漏洞的核心是 OGNL 表达式解析的失控，不同版本的漏洞变体仅在于「表达式注入的位置」和「解析触发的逻辑」，但其本质危害（任意代码执行）完全一致，且因 Struts2 的广泛使用，成为 Java Web 安全中最需重点防范的漏洞类型之一。

