# Java 审计 Sink 大表（按类型）

> 定位：Java 审计覆盖矩阵的「sink 类型轴」单一地基（对齐 PHP 侧 `php-sink-reference.md`）。
> 由 `java-audit-pipeline` / 面映射引用：用于从 trace / 静态命中判断触发哪个 `java-*-audit`
> 子技能。每条含 **Source / Sink / 危险模式 / 强制验证** 四要素。

---

## 1. SQL 注入（SQL）

**Source**：HTTP 参数、`@RequestParam`/`@RequestBody`/`@PathVariable`、Session、Header 等进入字符串构造。

**Sink**：
- `Statement.executeQuery/executeUpdate/execute`（拼接 SQL）
- `PreparedStatement`（若 prepare 内仍拼接危险）
- JPA：`EntityManager.createQuery/createNativeQuery`（拼接 JPQL/SQL）
- MyBatis：mapper XML 中 `${}`（非 `#{}`）、`@Select` 注解拼接
- Spring Data：`@Query` 拼接（动态排序/表名）

**危险模式**：SQL/JPQL 文本与变量 `+` 拼接、`String.format`、`${}`。

**强制验证**：参数化绑定（`?`/`#{}/@Param`）；动态表名/列名/排序字段白名单映射。

---

## 2. 命令注入（CMD）

**Sink**：
- `Runtime.getRuntime().exec(cmd)` / `exec(String[])`
- `new ProcessBuilder(cmd...)` / `ProcessBuilder.command(...)`
- `javax.script.ScriptEngine.eval(script)`（ScriptEngineManager）
- `ProcessBuilder` + `shell`（Linux sh -c 变体）

**危险模式**：命令字符串/参数拼接用户输入（`;|&`、参数注入、路径拼接）。

**强制验证**：参数数组（ProcessBuilder 无 shell 拼接）；白名单命令/参数；无 shell 元字符。

---

## 3. SSRF（SSRF）

**Sink**：
- `new URL(url).openConnection()/openStream()`
- `HttpClient` / `HttpURLConnection` / `OkHttp` / `RestTemplate` / `WebClient` / `Feign`
- `URLConnection.getInputStream()`、`ImageIO.read(url)`、`SAXParser`/`DocumentBuilder.parse(uri)`

**危险模式**：用户控制协议/主机/端口，缺内网拒绝与协议白名单。

**强制验证**：scheme allowlist（http/https）；DNS/IP 解析后内网拦截；重定向与最终地址校验；云元数据面（见 php-ssrf-audit 云元数据判据，Java 侧同源）。

---

## 4. XSS（XSS）

**Sink**：
- `response.getWriter().write/print`（回显用户输入）
- JSP 表达式 `<%= %>` / `${}`（未转义）
- 前端框架：`v-html`（Vue）、`dangerouslySetInnerHTML`（React）、`innerHTML`（JS）
- 富文本/模板回显未编码

**危险模式**：用户输入进 HTML/JS/属性上下文未编码。

**强制验证**：输出上下文（body/attribute/script/URL）；框架自动转义是否关闭。

---

## 5. 文件读取/路径穿越（FILE）

**Sink**：
- `new File(path)` / `Paths.get(path)` + `Files.readAllBytes/copy`
- `FileInputStream` / `FileReader` / `BufferedReader`
- `ClassLoader.getResource/getResourceAsStream`
- 下载接口 `response.getOutputStream()` 回写文件

**危险模式**：`base + userInput` 拼接、`resolve` 后未 `normalize` + 前缀校验。

**强制验证**：`Path.normalize()` + `startsWith(base)`；`../`/编码/符号链绕过；扩展名校验。

---

## 6. 文件上传（UPLOAD）

**Sink**：
- `MultipartFile.transferTo(dest)` / `getOriginalFilename()`
- `Files.copy(inputStream, dest)`
- `commons-fileupload` 的 `FileItem.write`

**危险模式**：信任客户端文件名；仅扩展名校验；Web 根内可执行。

**强制验证**：UUID 重命名 + 白名单扩展名 + 魔数校验 + 脱离 Web 根。

---

## 7. XXE（XXE）

**Sink**：
- `DocumentBuilderFactory.newDocumentBuilder().parse(...)`
- `SAXParserFactory` / `SAXReader` / `XMLReader`
- `XMLInputFactory`（StAX）/ `TransformerFactory`（XSLT）
- `Unmarshaller`（JAXB）/ `SchemaFactory`

**危险模式**：默认允许外部实体/DOCTYPE；`XInclude` 开启。

**强制验证**：`disallow-doctype-decl=true`、`external-general/parameter-entities=false`、`XIncludeAware(false)`。

---

## 8. 反序列化（DESER）

**Sink**：
- `new ObjectInputStream(...).readObject()`
- `new XMLDecoder(...)`、`XStream.fromXML`
- `HessianInput/Hessian2Input`（Dubbo/Sofa）
- `fastjson JSON.parse/parseObject`、`Jackson enableDefaultTyping`、`SnakeYAML new Yaml()`

**危险模式**：用户可控数据直接反序列化；无类白名单；gadget 依赖在 classpath（见 `java-deser-gadget-chains.md`）。

**强制验证**：数据来源与 gadget 链核对；`ObjectInputFilter`/白名单；JDK/依赖版本判据。

---

## 9. 模板注入/SSTI（TPL）

**Sink**：
- FreeMarker：`new Template(name, content, cfg)` / `Template.process`
- Velocity：`Velocity.evaluate(ctx, writer, logtag, template)` / `Velocity.mergeTemplate`
- Thymeleaf：模板名/预处理表达式 `__${...}__`
- Groovy 模板、`ScriptEngine` 渲染模板

**危险模式**：用户输入进模板内容/模板名/预处理表达式。

**强制验证**：模板引擎入口参数映射；禁用 `new()` 内置指令（FreeMarker `Configuration.setNewBuiltinClassResolver`）；模板名白名单。

---

## 10. LDAP 注入（LDAP）

**Sink**：
- `InitialDirContext.search(base, filter, ...)`（filter 拼接）
- Spring `LdapTemplate.search` / `LdapQuery`

**危险模式**：filter/DN 拼接用户输入，未 `LdapEncoder`/`encodeForFilter`。

**强制验证**：`LdapEncoder.filterEncode`/`encodeForDN`；可控域 allowlist；`* ) (` 注入。

---

## 11. 表达式注入（EXPR）

**Sink**：
- SpEL：`new SpelExpressionParser().parseExpression(expr).getValue(...)`（`StandardEvaluationContext`）
- OGNL：`Ognl.getValue/setValue/parseExpression`（Struts2 `ValueStack.findValue`）
- MVEL：`MVEL.eval(expr)` / `MVEL.executeExpression`
- EL：`ELProcessor.eval(expr)` / `ValueExpression`（JSF/JSP）

**危险模式**：用户输入进表达式且无沙箱/白名单（详见 `java-expr-injection-audit.md`）。

**强制验证**：`SimpleEvaluationContext`（SpEL）、OGNL 禁用静态方法/白名单、MVEL 无沙箱即高危、EL `ELProcessor` 反射面。

---

## 12. JNDI 注入（JNDI）

**Sink**：
- `InitialContext.lookup(name)` / `Context.lookup`
- `JndiTemplate.lookup`（Spring）
- Log4j2 `${jndi:...}`（消息查找）

**危险模式**：`name` 用户可控且形如 `ldap://`/`rmi://`；JDK 版本决定远程类加载可用性（8u191+ 需本地 gadget）。

**强制验证**：lookup 参数来源；协议白名单；JDK 版本 + 本地 gadget 判定。

---

## 13. 鉴权绕过/越权（AUTH）

**检查点**：受保护资源前登录与权限校验；`@PreAuthorize`/`@Secured`/`Filter` 覆盖；多入口绕过同一鉴权链。

**强制验证**：端点列表 vs 权限注解覆盖；`hasRole/hasAuthority/authorize` 误用或早退；CORS 通配符 + 凭据。

---

## 14. CSRF（CSRF）

**检查点**：状态变更方法与 token 校验覆盖；Spring Security `csrf()` 是否禁用。

**强制验证**：`http.csrf().disable()` 命中；token 来源/接收/校验；AJAX/Header 分支。

---

## 15. 开放重定向（REDIR）

**Sink**：
- `response.sendRedirect(url)` / `return "redirect:" + url`
- `ModelAndView("redirect:"+url)`

**强制验证**：目的地变量映射；归一化后 allowlist/scheme 拒绝（`//evil.com` 变体）。

---

## 16. CRLF（CRLF）

**Sink**：`response.setHeader(name, value)` / `addHeader` / 日志输出用户输入。

**强制验证**：`\r\n`/控制字符过滤；PoC 体现 `%0d%0a` 可控链。

---

## 17. 会话与 Cookie（SESS）

**Sink**：`session.setAttribute`、Cookie 构造（`HttpOnly`/`Secure`/`SameSite` 缺失）、JWT 校验。

**强制验证**：Session 固定化防护（`changeSessionId`）、Cookie flags、JWT 算法校验（见 crypto-misuse）。

---

## 18. 配置安全（CFG）

**Sink**：Spring Boot actuator 暴露、CORS、错误暴露、安全头、危险 `application.yml` 组合。

**强制验证**：actuator 端点清单与鉴权（见 `java-unauth-rce.md`）；配置与入口/响应链关联。

---

## 19. 归档解压（ARCHIVE / Zip Slip）

**Sink**：`ZipFile` / `ZipInputStream` / `ZipEntry.getName()` + 落盘（详见 `java-archive-extract-audit.md`）。

**危险模式**：entry 穿越 base（`../`/绝对路径/盘符/软链/解压炸弹）。

**强制验证**：entry 来源；resolved path 仍在 base 内；净化在解析前完成。

---

## 20. 未授权危险接口（UNAUTH-RCE）

**Sink**：actuator（heapdump/env/jolokia/restart）、JMX、RMI、JDWP 远程 debug（详见 `java-unauth-rce.md`）。

**危险模式**：默认无认证 + 直达命令执行/反序列化/上传。

**强制验证**：接口鉴权缺失判定 + 直达原语判定（命令执行/反序列化/上传）。

---

## 覆盖矩阵使用说明

- 面映射阶段：把源码中命中的 sink 反查到上表类型，作为「模块 × sink 类型」覆盖矩阵的轴；
- 审计工人：按模块扇出，每格终态三选一（已审/N-A/未完成），见 audit-playbook 覆盖规则；
- 本表是「地基」，具体深审走对应 `java-*-audit.md` 子技能。
