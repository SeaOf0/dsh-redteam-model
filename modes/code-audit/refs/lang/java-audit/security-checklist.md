# Java Web 应用安全审计检查清单

**版本**: v1.0  
**适用于**: java-audit-skill Phase 2 Layer 1-2

> **相关文档**：
> - 漏洞成立条件：[vulnerability-conditions.md](vulnerability-conditions.md)
> - DKTSS 评分体系：[dktss-scoring.md](dktss-scoring.md)
> - 业务场景标签：[business-scenario-tags.md](business-scenario-tags.md)
> - 报告模板：[report-template.md](report-template.md)

---

## 使用说明

本检查清单用于指导 AI 完成系统化的安全审计，每个检查项包含：
- **检查方法**: 具体的扫描命令或分析步骤
- **风险等级**: 严重/高/中/低
- **验证要点**: 确认漏洞成立的条件

---

## 1. 认证与授权 (Authentication & Authorization)

### 1.1 认证机制

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 1.1.1 | 身份认证机制是否存在 | `grep -rn "@EnableWebSecurity\|SecurityConfig\|WebSecurityConfigurerAdapter" --include="*.java" --include="*.kt"` | 严重 | 无任何认证 → 所有接口暴露 |
| 1.1.2 | 密码存储是否加密 | `grep -rn "BCrypt\|PBKDF2\|SCrypt\|Argon2" --include="*.java" --include="*.kt"` | 严重 | 明文存储密码 → 数据库泄露即泄露 |
| 1.1.3 | 弱哈希算法用于密码 | `grep -rn "MD5\|SHA1\|MessageDigest" --include="*.java" --include="*.kt" \| grep -i "password"` | 严重 | MD5/SHA1 哈希 → 可彩虹表破解 |
| 1.1.4 | 登录失败锁定机制 | 检查登录 Controller 失败处理逻辑 | 高 | 无锁定 → 暴力破解 |
| 1.1.5 | 验证码机制 | `grep -rn "captcha\|验证码" --include="*.java" --include="*.kt"` | 中 | 无验证码 → 自动化攻击 |
| 1.1.6 | 多因素认证 | 检查敏感操作是否有二次验证 | 中 | 无 MFA → 凭据泄露即入侵 |
| 1.1.7 | 登录信息明文传输 | 检查是否强制 HTTPS | 严重 | HTTP 明文 → 中间人攻击 |

### 1.2 授权机制

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 1.2.1 | 权限控制注解 | `grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed" --include="*.java"` | 严重 | 0个注解 → 无权限控制 |
| 1.2.2 | hasRole/hasAuthority 使用 | `grep -rn "hasRole\|hasAuthority\|permitAll" --include="*.java"` | 高 | permitAll 滥用 → 接口暴露 |
| 1.2.3 | 水平越权检查 | 修改请求中的用户ID参数测试 | 高 | 可访问他人数据 → 水平越权 |
| 1.2.4 | 垂直越权检查 | 低权限用户访问高权限接口 | 高 | 可访问管理接口 → 垂直越权 |
| 1.2.5 | URL 权限绕过 | `grep -rn "antMatchers\|mvcMatchers" --include="*.java"` | 高 | 路径匹配不严 → 绕过认证 |
| 1.2.6 | 数据归属校验 | 检查 CRUD 操作是否校验数据归属 | 高 | 无归属校验 → 越权访问 |

**越权测试脚本**:
```bash
# 水平越权 - 修改用户ID
curl -H "Authorization: Bearer $TOKEN" http://api/user/123/profile
curl -H "Authorization: Bearer $TOKEN" http://api/user/456/profile  # 改成其他用户

# 垂直越权 - 普通用户访问管理接口
curl -H "Authorization: Bearer $USER_TOKEN" http://api/admin/users
```

---

## 2. 输入验证 (Input Validation)

### 2.1 参数校验

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 2.1.1 | @Valid/@NotNull 使用 | `grep -rn "@Valid\|@NotNull\|@NotEmpty\|@NotBlank" --include="*.java"` | 高 | 无校验 → 任意输入 |
| 2.1.2 | 参数长度校验 | `grep -rn "@Size\|@Length\|@Max\|@Min" --include="*.java"` | 中 | 无长度限制 → 缓冲区/DoS |
| 2.1.3 | 参数格式校验 | `grep -rn "@Pattern\|@Email\|@URL" --include="*.java"` | 中 | 无格式校验 → 格式注入 |
| 2.1.4 | 必填参数检查 | `grep -rn "@RequestParam" --include="*.java" \| grep "required.*false"` | 中 | 非必填但未校验空值 |
| 2.1.5 | 前端校验绕过 | 抓包修改参数测试 | 高 | 仅前端校验 → 可绕过 |

### 2.2 XSS 防护

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 2.2.1 | XSS 过滤器 | `grep -rn "HtmlUtils\|StringEscapeUtils\|Jsoup\|XSSFilter" --include="*.java"` | 高 | 无转义 → 存储型 XSS |
| 2.2.2 | 富文本过滤 | `grep -rn "富文本\|editor\|ckeditor\|ueditor" --include="*.java"` | 高 | 未过滤危险标签 → XSS |
| 2.2.3 | CSP 头配置 | `grep -rn "Content-Security-Policy" --include="*.java"` | 中 | 无 CSP → XSS 无防护层 |
| 2.2.4 | X-XSS-Protection | `grep -rn "X-XSS-Protection" --include="*.java"` | 低 | 浏览器 XSS 过滤 |
| 2.2.5 | 直接输出用户数据 | `grep -rn "response.getWriter\|PrintWriter\|out.print" --include="*.java"` | 高 | 未编码直接输出 → XSS |

**XSS 测试 Payload**:
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
```

---

## 3. SQL 注入 (SQL Injection)

### 3.1 MyBatis

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 3.1.1 | `${}` 使用 | `grep -rn '\${' --include="*.xml" \| grep -v "log\|LOG"` | 严重 | `${}` 直接拼接 → SQL注入 |
| 3.1.2 | 动态表名 | `grep -rn '\${.*table\|tableName' --include="*.xml"` | 严重 | 表名可控 → 注入 |
| 3.1.3 | ORDER BY 注入 | `grep -rn 'ORDER BY \${\|order by \${' --include="*.xml"` | 高 | 排序字段可控 → 注入 |
| 3.1.4 | LIKE 查询安全 | 检查 LIKE 参数是否使用 `#{}` | 高 | LIKE 拼接 → 注入 |
| 3.1.5 | IN 子句安全 | 检查 IN 子句是否使用 foreach | 中 | IN 拼接 → 注入 |

### 3.2 JPA/Hibernate

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 3.2.1 | 原生 SQL | `grep -rn "createNativeQuery\|createQuery" --include="*.java"` | 高 | 字符串拼接 → 注入 |
| 3.2.2 | HQL 拼接 | `grep -rn '"+.*+"\|StringBuilder.*append" --include="*.java" \| grep -i "select\|from\|where"` | 高 | HQL 拼接 → 注入 |
| 3.2.3 | @Query 注解 | `grep -rn "@Query" --include="*.java" \| grep -v "?\|:"` | 中 | 参数绑定检查 |
| 3.2.4 | JdbcTemplate | `grep -rn "JdbcTemplate\|query.*+" --include="*.java"` | 高 | 字符串拼接 → 注入 |

### 3.3 JDBC 原生

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 3.3.1 | Statement 使用 | `grep -rn "Statement\|createStatement" --include="*.java"` | 严重 | Statement → 注入 |
| 3.3.2 | PreparedStatement | 检查是否使用 PreparedStatement | 高 | 未使用预编译 → 注入 |
| 3.3.3 | executeQuery 拼接 | `grep -rn "executeQuery.*+\|executeUpdate.*+" --include="*.java"` | 严重 | SQL 拼接 → 注入 |

**SQL 注入测试 Payload**:
```sql
' OR '1'='1
" OR "1"="1
1; DROP TABLE users--
1 UNION SELECT username,password FROM users--
```

---

## 4. 文件操作 (File Operations)

### 4.1 文件上传

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 4.1.1 | 上传接口发现 | `grep -rn "MultipartFile\|@RequestPart\|@FilePart" --include="*.java"` | 高 | 所有上传点需检查 |
| 4.1.2 | 文件类型校验 | `grep -rn "getContentType\|endsWith\|getOriginalFilename" --include="*.java"` | 严重 | 无类型校验 → 上传恶意文件 |
| 4.1.3 | 文件大小限制 | `grep -rn "max-file-size\|maxRequestSize\|getSize" --include="*.yml\|*.properties\|*.java"` | 高 | 无大小限制 → DoS |
| 4.1.4 | 文件名处理 | 检查是否重命名或校验文件名 | 高 | 原始文件名 → 路径遍历/覆盖 |
| 4.1.5 | 上传路径可控 | `grep -rn "uploadPath\|uploadDir\|savePath" --include="*.java"` | 严重 | 路径可控 → 任意目录写入 |
| 4.1.6 | 文件内容校验 | 检查是否检查文件头/魔数 | 高 | 仅检查后缀 → 伪装绕过 |
| 4.1.7 | 可执行目录 | 检查上传目录是否可执行 | 严重 | 可执行目录 → RCE |

**危险文件类型**:
```
.jsp, .jspx, .jspf, .jspa, .jsw, .jsv  # Java WebShell
.php, .php3, .php4, .php5, .phtml      # PHP WebShell
.exe, .sh, .bat, .cmd, .com            # 可执行文件
.jar, .war                              # Java 打包文件
```

### 4.2 文件下载

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 4.2.1 | 下载接口发现 | `grep -rn "download\|getFile\|exportFile" --include="*.java"` | 高 | 所有下载点需检查 |
| 4.2.2 | 路径参数可控 | `grep -rn "fileName\|filePath\|file=.*request" --include="*.java"` | 严重 | 路径可控 → 任意文件读取 |
| 4.2.3 | 路径遍历防护 | 检查是否过滤 `../` | 严重 | 未过滤 → 路径遍历 |
| 4.2.4 | 下载权限校验 | 检查文件归属校验 | 高 | 无校验 → 越权下载 |

**路径遍历测试**:
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
```

### 4.3 文件读写

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 4.3.1 | 文件读取操作 | `grep -rn "FileInputStream\|Files.read\|new File.*read" --include="*.java"` | 高 | 路径可控 → 任意读取 |
| 4.3.2 | 文件写入操作 | `grep -rn "FileOutputStream\|Files.write\|FileWriter" --include="*.java"` | 高 | 路径可控 → 任意写入 |
| 4.3.3 | 临时文件安全 | `grep -rn "createTempFile\|File.createTemp" --include="*.java"` | 中 | 临时文件权限 |

---

## 5. 会话管理 (Session Management)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 5.1 | Session 超时配置 | `grep -rn "session.timeout\|setMaxInactiveInterval" --include="*.yml\|*.properties\|*.java"` | 中 | 过长 → 劫持风险 |
| 5.2 | 登出是否销毁 Session | `grep -rn "logout\|invalidate" --include="*.java"` | 高 | 未销毁 → 会话复用 |
| 5.3 | Cookie Secure 标志 | `grep -rn "setSecure\|secure:" --include="*.java\|*.yml"` | 高 | 无 Secure → HTTP 泄露 |
| 5.4 | Cookie HttpOnly 标志 | `grep -rn "setHttpOnly\|httpOnly:" --include="*.java\|*.yml"` | 高 | 无 HttpOnly → XSS 窃取 |
| 5.5 | Cookie SameSite 属性 | `grep -rn "SameSite\|sameSite" --include="*.java\|*.yml"` | 中 | 无 SameSite → CSRF |
| 5.6 | Session ID 可预测性 | 检查 Session 生成方式 | 高 | 可预测 → 会话劫持 |
| 5.7 | 并发登录控制 | 检查同一账户多点登录 | 中 | 无控制 → 账户共享 |
| 5.8 | JWT 安全配置 | `grep -rn "jwt\|JwtUtils\|signWith" --include="*.java"` | 高 | 弱密钥/无过期 |

---

## 6. 加密与密钥 (Cryptography)

### 6.1 密码存储

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 6.1.1 | 强哈希算法 | `grep -rn "BCrypt\|PBKDF2\|SCrypt\|Argon2" --include="*.java"` | 严重 | MD5/SHA1 存密码 → 可破解 |
| 6.1.2 | 盐值使用 | 检查密码哈希是否加盐 | 高 | 无盐 → 彩虹表攻击 |

### 6.2 加密算法

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 6.2.1 | 弱加密算法 | `grep -rn "DES\|3DES\|RC4\|Blowfish" --include="*.java"` | 高 | 弱算法 → 可破解 |
| 6.2.2 | AES ECB 模式 | `grep -rn "AES/ECB\|AES.*ECB" --include="*.java"` | 高 | ECB → 模式泄露 |
| 6.2.3 | RSA 填充模式 | `grep -rn "RSA/ECB/PKCS1Padding" --include="*.java"` | 中 | 不安全填充 |
| 6.2.4 | 随机数安全 | `grep -rn "Random\|Math.random" --include="*.java" \| grep -v "SecureRandom"` | 中 | 非安全随机数 |

### 6.3 密钥管理

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 6.3.1 | 硬编码密钥 | `grep -rn "secret\|password\|key\|token" --include="*.java" \| grep -v "@Value\|placeholder\|ENC("` | 严重 | 硬编码 → 泄露不可控 |
| 6.3.2 | 配置文件明文密钥 | `grep -rn "password:\|secret:\|key:" --include="*.yml\|*.properties" \| grep -v "ENC(\|\${"` | 严重 | 明文存储 → 配置泄露 |
| 6.3.3 | 密钥强度 | 检查密钥长度是否足够 | 高 | 短密钥 → 暴力破解 |

---

## 7. 敏感数据处理 (Sensitive Data)

### 7.1 日志脱敏

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 7.1.1 | 密码记录日志 | `grep -rn "log\.\|logger\.\|System.out" --include="*.java" \| grep -i "password"` | 严重 | 密码入日志 → 泄露 |
| 7.1.2 | 身份证脱敏 | 检查日志输出是否脱敏 | 高 | 身份证明文 → 隐私泄露 |
| 7.1.3 | 手机号脱敏 | 检查日志输出是否脱敏 | 高 | 手机号明文 → 隐私泄露 |
| 7.1.4 | Token 记录日志 | `grep -rn "log.*token\|logger.*token" --include="*.java"` | 高 | Token 入日志 → 劫持 |

### 7.2 响应脱敏

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 7.2.1 | 敏感字段脱敏 | `grep -rn "idCard\|phone\|mobile\|bankCard" --include="*Dto.java\|*Vo.java"` | 高 | 返回明文敏感信息 |
| 7.2.2 | 错误信息泄露 | `grep -rn "e.getMessage\|printStackTrace" --include="*.java"` | 中 | 异常堆栈返回前端 |
| 7.2.3 | 系统信息泄露 | 检查错误响应是否暴露版本/路径 | 中 | 信息泄露 → 辅助攻击 |

---

## 8. 网络请求安全 (Network Security)

### 8.1 SSRF

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 8.1.1 | 外部 URL 请求 | `grep -rn "URL(\|HttpURLConnection\|HttpClient\|RestTemplate\|WebClient\|OkHttp" --include="*.java"` | 高 | 所有外部请求点需检查 |
| 8.1.2 | URL 参数可控 | 检查 URL 参数来源 | 严重 | 用户可控 → SSRF |
| 8.1.3 | URL 白名单 | `grep -rn "allowList\|whiteList\|ALLOWED_URL" --include="*.java"` | 高 | 无白名单 → 任意请求 |
| 8.1.4 | 内网地址过滤 | 检查是否过滤 127.0.0.1/10.x/192.168.x | 严重 | 未过滤 → 内网探测 |
| 8.1.5 | 协议限制 | 检查是否只允许 http/https | 高 | 允许 file:// → 任意读取 |

**SSRF 测试 Payload**:
```
http://127.0.0.1:8080/admin
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a...
```

### 8.2 请求超时

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 8.2.1 | 连接超时设置 | `grep -rn "connectTimeout\|setConnectTimeout" --include="*.java\|*.yml"` | 中 | 无超时 → 连接挂起 |
| 8.2.2 | 读取超时设置 | `grep -rn "readTimeout\|setReadTimeout" --include="*.java\|*.yml"` | 中 | 无超时 → 响应挂起 |

---

## 9. 反序列化安全 (Deserialization)

### 9.1 Java 原生

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 9.1.1 | ObjectInputStream | `grep -rn "ObjectInputStream\|readObject\|readUnshared" --include="*.java"` | 严重 | 存在 → 可能 RCE |
| 9.1.2 | ObjectInputFilter | `grep -rn "ObjectInputFilter\|serialFilter" --include="*.java"` | 高 | 无过滤器 → 无限制 |

### 9.2 Fastjson

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 9.2.1 | Fastjson 版本 | `grep -rn "fastjson" --include="pom.xml"` | 严重 | < 1.2.83 有漏洞 |
| 9.2.2 | JSON.parseObject | `grep -rn "JSON\.parseObject\|JSON\.parse\|JSON\.parseArray" --include="*.java"` | 高 | 所有使用点需检查 |
| 9.2.3 | autoType 配置 | `grep -rn "autoType\|ParserConfig.getGlobalInstance" --include="*.java"` | 严重 | 开启 autoType → RCE |
| 9.2.4 | safeMode | `grep -rn "safeMode" --include="*.java"` | 高 | 未开启 → 风险 |

### 9.3 Jackson

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 9.3.1 | 多态类型处理 | `grep -rn "@JsonTypeInfo\|enableDefaultTyping" --include="*.java"` | 高 | 开启多态 → 可能 RCE |
| 9.3.2 | 白名单配置 | `grep -rn "addMixIn\|registerSubtypes" --include="*.java"` | 中 | 无白名单 → 无限制 |

### 9.4 其他反序列化

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 9.4.1 | XMLDecoder | `grep -rn "XMLDecoder" --include="*.java"` | 严重 | 存在 → RCE |
| 9.4.2 | XStream | `grep -rn "XStream" --include="*.java"` | 高 | 未配置安全 → RCE |
| 9.4.3 | Hessian | `grep -rn "HessianInput\|Hessian2Input" --include="*.java"` | 高 | 版本检查 |
| 9.4.4 | SnakeYAML | `grep -rn "Yaml\|SnakeYAML" --include="*.java"` | 高 | 版本检查 |

---

## 10. 命令执行 (Command Execution)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 10.1 | Runtime.exec | `grep -rn "Runtime\.getRuntime\(\)\.exec" --include="*.java"` | 严重 | 命令拼接 → RCE |
| 10.2 | ProcessBuilder | `grep -rn "ProcessBuilder\|start()" --include="*.java"` | 严重 | 命令拼接 → RCE |
| 10.3 | 命令参数来源 | 追踪命令参数是否用户可控 | 严重 | 用户可控 → RCE |
| 10.4 | 命令白名单 | 检查是否限制可执行命令 | 高 | 无限制 → 任意命令 |

---

## 11. 表达式注入 (Expression Injection)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 11.1 | SpEL 注入 | `grep -rn "SpelExpressionParser\|parseExpression\|ExpressionParser" --include="*.java"` | 严重 | 用户输入入参 → RCE |
| 11.2 | OGNL 注入 | `grep -rn "Ognl\|OgnlUtil\|ValueStack" --include="*.java"` | 严重 | Struts 漏洞历史 |
| 11.3 | EL 注入 | `grep -rn "ExpressionFactory\|createValueExpression" --include="*.java"` | 高 | JSP EL 注入 |

---

## 12. SSTI (Server-Side Template Injection)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 12.1 | Velocity | `grep -rn "Velocity\|VelocityEngine" --include="*.java"` | 严重 | 用户输入模板 → RCE |
| 12.2 | FreeMarker | `grep -rn "FreeMarker\|Template\.process" --include="*.java"` | 严重 | 用户输入模板 → RCE |
| 12.3 | Thymeleaf | `grep -rn "Thymeleaf\|SpringTemplateEngine" --include="*.java"` | 高 | 模板注入检查 |
| 12.4 | 模板路径可控 | 检查模板路径参数 | 严重 | 路径可控 → 任意模板 |

---

## 13. JNDI 注入

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 13.1 | InitialContext.lookup | `grep -rn "InitialContext\|lookup(" --include="*.java"` | 严重 | 参数可控 → RCE |
| 13.2 | JdbcRowSetImpl | `grep -rn "JdbcRowSetImpl\|setDataSourceName" --include="*.java"` | 严重 | JNDI 注入点 |
| 13.3 | Spring JNDI | `grep -rn "JndiObjectFactoryBean" --include="*.java"` | 高 | JNDI 配置检查 |

---

## 14. 日志安全 (Logging Security)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 14.1 | Log4j2 版本 | `grep -rn "log4j" --include="pom.xml"` | 严重 | < 2.17.0 → Log4Shell |
| 14.2 | JNDI Lookup | `grep -rn '\${jndi:\${ctx:' --include="*.xml\|*.java"` | 严重 | 存在 → Log4Shell |
| 14.3 | 日志注入 | 检查用户输入是否直接入日志 | 中 | 未转义 → 日志伪造 |
| 14.4 | 日志文件权限 | 检查日志目录权限 | 中 | 权限过宽 → 敏感信息泄露 |

---

## 15. 配置安全 (Configuration Security)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 15.1 | 调试模式 | `grep -rn "debug:\|debug=true" --include="*.yml\|*.properties"` | 高 | 生产开启 debug → 信息泄露 |
| 15.2 | Swagger 暴露 | `grep -rn "swagger\|knife4j" --include="*.yml\|*.properties"` | 高 | 生产暴露 → API 泄露 |
| 15.3 | Actuator 暴露 | `grep -rn "actuator\|management.endpoints" --include="*.yml\|*.properties"` | 高 | 暴露敏感端点 |
| 15.4 | 错误堆栈返回 | `grep -rn "server.error\|always-include-stacktrace" --include="*.yml"` | 中 | 返回堆栈 → 信息泄露 |
| 15.5 | 端口最小化 | 检查开放端口 | 中 | 多余端口 → 攻击面 |

---

## 16. 依赖安全 (Dependency Security)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 16.1 | Log4j2 版本 | `grep -rn "log4j2" --include="pom.xml"` + **tavily 搜索 CVE** | 严重 | >= 2.17.1 安全 |
| 16.2 | Fastjson 版本 | `grep -rn "fastjson" --include="pom.xml"` + **tavily 搜索 CVE** | 严重 | >= 1.2.83 或 2.x |
| 16.3 | Spring 版本 | `grep -rn "spring-boot\|spring-framework" --include="pom.xml"` + **tavily 搜索 CVE** | 高 | 检查 CVE |
| 16.4 | Shiro 版本 | `grep -rn "shiro" --include="pom.xml"` + **tavily 搜索 CVE** | 严重 | 检查 CVE |
| 16.5 | Tomcat 版本 | `grep -rn "tomcat" --include="pom.xml"` + **tavily 搜索 CVE** | 高 | 检查 CVE |
| 16.6 | 依赖漏洞扫描 | `mvn org.owasp:dependency-check-maven:check` | 高 | 全量扫描 |

**⚠️ CVE 查询必须使用 tavily（禁止凭记忆编造）**：

```bash
# 使用 tavily 搜索 CVE 信息
web_search "<组件名> <版本号> CVE" -n 10

# 示例
web_search "log4j-core 2.14.1 CVE" -n 10
web_search "fastjson 1.2.79 vulnerability" -n 10
web_search "hessian 4.0.63 CVE" -n 10
```

**CVE 核实要点**：
1. 从 NVD、Snyk、官方公告确认 CVE 真实存在
2. 确认影响版本范围
3. 确认 CVE 影响的具体组件（artifact）
   - 示例：CVE-2020-1948 是 Apache Dubbo 漏洞，不是 Hessian 漏洞
   - 示例：CVE-2024-46983 是 SOFA Hessian 漏洞，不是 Caucho Hessian 漏洞

**版本对比方法**: 见 [vulnerability-conditions.md](vulnerability-conditions.md) 第 18 节

---

## 17. 接口安全 (API Security)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 17.1 | 接口限流 | `grep -rn "RateLimiter\|@Limit\|@RateLimit" --include="*.java"` | 高 | 无限流 → DoS |
| 17.2 | 接口鉴权 | 检查 Token/签名验证 | 严重 | 无鉴权 → 未授权访问 |
| 17.3 | 参数签名 | `grep -rn "sign\|signature\|签名" --include="*.java"` | 中 | 无签名 → 篡改 |
| 17.4 | 重放攻击防护 | `grep -rn "nonce\|timestamp\|replay" --include="*.java"` | 中 | 无防护 → 重放 |
| 17.5 | 幂等性设计 | 检查重复请求处理 | 中 | 无幂等 → 重复操作 |
| 17.6 | Feign 服务间认证 | `grep -rn "Feign\|@FeignClient" --include="*.java"` | 严重 | 无认证 → 内部接口暴露 |

---

## 18. 业务逻辑 (Business Logic)

### 18.1 订单/支付

| # | 检查项 | 检查方法 | 风险 | 验证要点 |
|---|--------|----------|------|----------|
| 18.1.1 | 金额篡改 | 抓包修改金额测试 + **代码分析** | 严重 | 负金额/0元支付 |
| 18.1.2 | 数量篡改 | 抓包修改数量测试 + **代码分析** | 严重 | 负数量/超库存 |
| 18.1.3 | 库存校验 | 检查库存扣减逻辑 + **并发控制检查** | 高 | 超量下单 |
| 18.1.4 | 并发控制 | 检查锁机制 + **原子操作判断** | 高 | 并发导致库存异常 |
| 18.1.5 | 支付状态校验 | 检查状态机 + **前置条件分析** | 高 | 跳过支付直接发货 |

**代码分析方法**: 见 [vulnerability-conditions.md](vulnerability-conditions.md) 第 16 节

### 18.2 用户管理

| # | 检查项 | 检查方法 | 风险 | 验证要点 |
|---|--------|----------|------|----------|
| 18.2.1 | 注册限流 | 检查注册接口 | 高 | 无限制 → 批量注册 |
| 18.2.2 | 密码强度 | 检查密码规则 | 中 | 弱密码 → 暴力破解 |
| 18.2.3 | 手机验证 | 检查短信验证码 | 高 | 无限制 → 短信轰炸 |
| 18.2.4 | 密码重置 | 检查重置流程 | 严重 | 越权重置密码 |

### 18.3 权限管理

| # | 检查项 | 检查方法 | 风险 | 验证要点 |
|---|--------|----------|------|----------|
| 18.3.1 | 水平越权 | 同角色不同用户测试 + **归属校验代码分析** | 高 | 访问他人数据 |
| 18.3.2 | 垂直越权 | 低权限访问高权限接口 + **权限注解检查** | 高 | 权限提升 |
| 18.3.3 | 数据隔离 | 检查数据归属校验 + **SQL 条件分析** | 高 | 数据泄露 |

**代码分析方法**: 见 [vulnerability-conditions.md](vulnerability-conditions.md) 第 17 节

---

## 19. XXE (XML External Entity)

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 19.1 | XML 解析 | `grep -rn "DocumentBuilder\|SAXParser\|XMLReader\|Unmarshaller" --include="*.java"` | 高 | 所有 XML 解析点 |
| 19.2 | 外部实体禁用 | `grep -rn "disallow-doctype-decl\|FEATURE_SECURE_PROCESSING" --include="*.java"` | 严重 | 未禁用 → XXE |
| 19.3 | Excel 导入 | `grep -rn "POI\|EasyExcel\|SXSSFWorkbook" --include="*.java"` | 高 | OOXML 格式有 XXE 风险 |

---

## 20. SSRF 风险汇总

| 场景 | 触发点 | 风险 |
|------|--------|------|
| 图片抓取 | 用户提交 URL 抓取图片 | 内网探测/云元数据 |
| 预览功能 | URL 预览生成 | 内网服务访问 |
| 支付回调 | 支付回调地址可配置 | 内网支付接口 |
| 文件导入 | 远程文件 URL 导入 | 任意文件读取 |
| Webhook | Webhook URL 可配置 | 内网服务调用 |

---

## 附录 A: 快速扫描脚本

```bash
#!/bin/bash
# Java 安全审计快速扫描脚本
PROJECT_PATH=$1

echo "=== 1. 权限控制 ==="
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed" --include="*.java" $PROJECT_PATH | wc -l

echo "=== 2. SQL 注入 ==="
grep -rn '\${' --include="*.xml" $PROJECT_PATH | grep -i "order\|where\|select"

echo "=== 3. 命令执行 ==="
grep -rn "Runtime\.getRuntime\|ProcessBuilder" --include="*.java" $PROJECT_PATH

echo "=== 4. 文件上传 ==="
grep -rn "MultipartFile" --include="*.java" $PROJECT_PATH

echo "=== 5. 反序列化 ==="
grep -rn "ObjectInputStream\|XMLDecoder\|JSON\.parse" --include="*.java" $PROJECT_PATH

echo "=== 6. SSRF ==="
grep -rn "URL(\|HttpURLConnection\|RestTemplate" --include="*.java" $PROJECT_PATH

echo "=== 7. 敏感配置 ==="
grep -rn "password:\|secret:\|key:" --include="*.yml\|*.properties" $PROJECT_PATH | grep -v "ENC(\|\${"

echo "=== 8. 表达式注入 ==="
grep -rn "SpelExpression\|Ognl\|Velocity\|FreeMarker" --include="*.java" $PROJECT_PATH
```

---

## 15. JWT 安全检查（补充）

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 15.1 | JWT 弱密钥 | `grep -rn "secret\|key.*=.*\"" --include="*.java" \| grep -i jwt` | 严重 | 弱密钥 → 可伪造 Token |
| 15.2 | 算法混淆 | 检查是否验证算法 | 高 | alg=none → 绕过签名 |
| 15.3 | Token 过期时间 | `grep -rn "setExpiration\|exp" --include="*.java"` | 高 | 无过期 → Token 永久有效 |
| 15.4 | 敏感信息存 JWT | 检查 JWT payload 内容 | 高 | 密码/密钥存 JWT → 泄露 |

**JWT 弱密钥检测**:
```bash
# 检查常见弱密钥
grep -rn "secret.*=.*\"123\|secret.*=.*\"password\|secret.*=.*\"key" --include="*.java"
```

---

## 16. LDAP 注入检查

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 16.1 | LDAP 查询拼接 | `grep -rn "search\|lookup" --include="*.java" \| grep -i "ldap\|DirContext"` | 高 | 用户输入拼接到 LDAP 查询 |
| 16.2 | 特殊字符过滤 | 检查是否过滤 `* ( ) \x00` | 高 | 未过滤 → LDAP 注入 |

**LDAP 注入 Payload**:
```
*)(uid=*))(|(uid=*
*)(objectClass=*)
```

---

## 17. CORS 配置检查

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 17.1 | Access-Control-Allow-Origin | `grep -rn "Access-Control-Allow-Origin\|allowedOrigins\|addCorsMappings" --include="*.java\|*.yml"` | 高 | `*` → 任意域访问 |
| 17.2 | credentials 模式 | `grep -rn "allowCredentials\|Access-Control-Allow-Credentials" --include="*.java\|*.yml"` | 严重 | `*` + `true` → Cookie 泄露 |
| 17.3 | 暴露敏感头 | `grep -rn "exposedHeaders" --include="*.java\|*.yml"` | 中 | 暴露 Authorization 等敏感头 |

**危险 CORS 配置**:
```java
// 危险配置
@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");           // 危险：允许任意域
        config.setAllowCredentials(true);       // 危险：允许携带 Cookie
        return new CorsFilter(...);
    }
}
```

---

## 18. 请求走私检查

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 18.1 | 代理服务器配置 | 检查 Nginx/Apache 配置 | 高 | 配置不当 → 请求走私 |
| 18.2 | Content-Length 处理 | 检查后端如何处理 CL | 高 | 前后端解析不一致 |
| 18.3 | Transfer-Encoding | 检查后端是否处理 TE | 高 | TE + CL → 走私 |

---

## 19. 其他补充检查项

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 19.1 | 敏感接口限流 | `grep -rn "RateLimiter\|@Limit\|Throttle" --include="*.java"` | 中 | 无限流 → 暴力攻击 |
| 19.2 | 接口幂等性 | 检查支付/下单等接口是否有幂等控制 | 高 | 无幂等 → 重复操作 |
| 19.3 | 批量操作限制 | 检查批量删除/导出接口 | 中 | 无限制 → DoS |
| 19.4 | 异步任务安全 | `grep -rn "@Async\|CompletableFuture\|ThreadPoolExecutor" --include="*.java"` | 中 | 敏感操作是否鉴权 |

---

## 附录 B: 风险等级定义

| 等级 | 定义 | 示例 |
|------|------|------|
| **严重** | 可直接获取系统权限或敏感数据 | RCE、SQL注入、未授权访问 |
| **高** | 可造成数据泄露或业务影响 | XSS、SSRF、越权访问 |
| **中** | 需要特定条件才能利用 | 信息泄露、CSRF |
| **低** | 影响有限或利用困难 | 版本泄露、调试信息 |

---

## 附录 C: 参考标准

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Java Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Cheatsheet.html)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [阿里巴巴 Java 安全编码规范](https://github.com/alibaba/java-coding-guidelines)

---

**文档版本**: v1.1  
**最后更新**: 2026-04-03  
**维护者**: java-audit-skill

---

## 20. 前端 XSS 安全检查

### 20.1 DOM-based XSS

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 20.1.1 | innerHTML 使用 | `grep -rn "innerHTML\|outerHTML" --include="*.js" --include="*.ts"` | 严重 | 用户输入直接渲染 → XSS |
| 20.1.2 | document.write | `grep -rn "document\.write\|document\.writeln" --include="*.js"` | 严重 | 存在 → XSS 风险 |
| 20.1.3 | eval 使用 | `grep -rn "eval(\|new Function(" --include="*.js" --include="*.ts"` | 严重 | 用户输入入参 → 代码注入 |
| 20.1.4 | setTimeout 字符串 | `grep -rn "setTimeout\s*\(\s*['\"]" --include="*.js"` | 高 | 字符串参数 → eval 执行 |
| 20.1.5 | URL 参数直接使用 | `grep -rn "location\.hash\|location\.search\|URLSearchParams" --include="*.js"` | 高 | 未验证直接使用 → DOM XSS |

### 20.2 React XSS

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 20.2.1 | dangerouslySetInnerHTML | `grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx"` | 严重 | 用户输入直接渲染 → XSS |
| 20.2.2 | href 用户输入 | `grep -rn "href\s*=\s*{" --include="*.jsx" --include="*.tsx" \| grep -i "props\|state"` | 高 | href 注入 → XSS/重定向 |
| 20.2.3 | javascript: 协议 | `grep -rn "href.*javascript:" --include="*.jsx" --include="*.tsx"` | 严重 | javascript: 协议 → XSS |
| 20.2.4 | SSR 渲染 | `grep -rn "renderToString" --include="*.js" --include="*.ts"` | 高 | SSR 渲染用户输入 → XSS |

### 20.3 Vue XSS

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 20.3.1 | v-html 指令 | `grep -rn "v-html" --include="*.vue"` | 严重 | 用户输入直接渲染 → XSS |
| 20.3.2 | 动态模板 | `grep -rn "template\s*:" --include="*.vue" \| grep -i "props\|data"` | 严重 | 用户输入模板 → SSTI |
| 20.3.3 | render 函数 | `grep -rn "render\s*:\s*function\|\$createElement" --include="*.vue"` | 高 | 手动渲染 → XSS 风险 |
| 20.3.4 | 动态组件 | `grep -rn "<component\s+:is" --include="*.vue"` | 高 | 动态组件名 → 渲染恶意组件 |

---

## 21. 前端代码注入检查

### 21.1 eval 相关

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 21.1.1 | eval 调用 | `grep -rn "eval(" --include="*.js" --include="*.ts"` | 严重 | 用户输入入参 → RCE |
| 21.1.2 | new Function | `grep -rn "new Function(" --include="*.js" --include="*.ts"` | 严重 | 动态函数 → 代码注入 |
| 21.1.3 | setTimeout/setInterval 字符串 | `grep -rn "setTimeout\s*\(|setInterval\s*\(" --include="*.js" \| grep -v "function"` | 高 | 字符串参数 → eval |

### 21.2 原型污染

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 21.2.1 | 对象合并 | `grep -rn "\.merge\|\.extend\|Object\.assign" --include="*.js" --include="*.ts"` | 高 | 深度合并用户输入 → 原型污染 |
| 21.2.2 | __proto__ 操作 | `grep -rn "__proto__\|constructor\.prototype" --include="*.js" --include="*.ts"` | 严重 | 直接修改原型 → 原型污染 |
| 21.2.3 | lodash 版本 | `grep -rn "lodash" --include="package.json"` | 高 | < 4.17.21 → 原型污染漏洞 |

---

## 22. 前端敏感信息泄露检查

### 22.1 硬编码敏感信息

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 22.1.1 | API Key 硬编码 | `grep -rn "api[_-]?key\|apikey" --include="*.js" --include="*.ts" \| grep -E "=.*['\"]"` | 严重 | 硬编码 → 泄露不可控 |
| 22.1.2 | Secret 硬编码 | `grep -rn "secret\|private[_-]?key" --include="*.js" --include="*.ts" \| grep -E "=.*['\"]"` | 严重 | 硬编码 → 泄露不可控 |
| 22.1.3 | 密码硬编码 | `grep -rn "password\|passwd" --include="*.js" --include="*.ts" \| grep -E "=.*['\"]"` | 严重 | 硬编码密码 → 泄露 |
| 22.1.4 | .env 文件检查 | `grep -rn "API_KEY\|SECRET\|PASSWORD" --include="*.env" --include=".env.*"` | 高 | 敏感信息入配置 → 泄露 |

### 22.2 存储安全

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 22.2.1 | localStorage 敏感信息 | `grep -rn "localStorage\.setItem" --include="*.js" --include="*.ts" \| grep -i "token\|password"` | 高 | XSS 可窃取 |
| 22.2.2 | sessionStorage 敏感信息 | `grep -rn "sessionStorage\.setItem" --include="*.js" --include="*.ts" \| grep -i "password"` | 中 | XSS 可窃取 |
| 22.2.3 | console.log 敏感信息 | `grep -rn "console\.log" --include="*.js" --include="*.ts" \| grep -i "password\|token\|secret"` | 中 | 控制台泄露 |

---

## 23. 前端配置安全检查

### 23.1 CORS 配置

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 23.1.1 | Access-Control-Allow-Origin | `grep -rn "Access-Control-Allow-Origin" --include="*.js" --include="*.json" --include="*.yaml"` | 高 | `*` → 任意域访问 |
| 23.1.2 | Allow-Credentials + Origin:* | `grep -rn "Access-Control-Allow-Credentials.*true" --include="*.js" --include="*.json"` | 严重 | Cookie 泄露 |
| 23.1.3 | CORS 白名单 | 检查是否有域名白名单验证 | 高 | 无白名单 → 任意域 |

### 23.2 CSP 配置

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 23.2.1 | CSP 配置存在 | `grep -rn "Content-Security-Policy" --include="*.html" --include="*.js"` | 中 | 无 CSP → XSS 无防护层 |
| 23.2.2 | unsafe-inline | `grep -rn "unsafe-inline" --include="*.html" --include="*.js"` | 高 | 允许内联脚本 → XSS 绕过 |
| 23.2.3 | unsafe-eval | `grep -rn "unsafe-eval" --include="*.html" --include="*.js"` | 高 | 允许 eval → 代码注入 |

### 23.3 开发配置

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 23.3.1 | 调试模式 | `grep -rn "debug.*true\|NODE_ENV.*development" --include="*.js" --include="*.env"` | 高 | 生产开启调试 → 信息泄露 |
| 23.3.2 | Source Map | `grep -rn "sourcemap.*true\|sourceMap.*true" --include="*.js" --include="*.json"` | 中 | 源码泄露 |
| 23.3.3 | 错误详情暴露 | 检查前端错误处理 | 中 | 详细错误返回 → 信息泄露 |

---

## 24. 前端开放重定向检查

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 24.1 | window.location 赋值 | `grep -rn "window\.location\s*=" --include="*.js" --include="*.ts"` | 高 | 用户可控 → 开放重定向 |
| 24.2 | history.push 用户输入 | `grep -rn "history\.push\|router\.push" --include="*.js" --include="*.ts" \| grep -i "props\|query"` | 高 | URL 参数控制 → 重定向 |
| 24.3 | URL 白名单 | 检查是否有跳转白名单 | 高 | 无白名单 → 任意跳转 |
| 24.4 | redirect 参数 | `grep -rn "redirect\|next\|returnUrl" --include="*.js" --include="*.ts"` | 高 | URL 参数直接跳转 |

---

## 25. 前端依赖安全检查

| # | 检查项 | 扫描命令/方法 | 风险 | 验证要点 |
|---|--------|---------------|------|----------|
| 25.1 | lodash 版本 | `grep -rn "lodash" --include="package.json"` | 高 | < 4.17.21 → 原型污染 |
| 25.2 | axios 版本 | `grep -rn "axios" --include="package.json"` | 中 | < 0.21.1 → SSRF |
| 25.3 | react 版本 | `grep -rn "react" --include="package.json"` | 中 | < 16.14.0 → XSS |
| 25.4 | vue 版本 | `grep -rn "vue" --include="package.json"` | 中 | < 2.6.14 → XSS |
| 25.5 | jquery 版本 | `grep -rn "jquery" --include="package.json"` | 高 | < 3.6.0 → XSS |
| 25.6 | npm audit | `npm audit --json` | 高 | 检查所有依赖漏洞 |

**依赖漏洞检查命令**:
```bash
# 使用 npm audit
npm audit

# 使用 snyk
snyk test

# 使用 yarn audit
yarn audit
```

---

## 26. 前端安全检查汇总

| 类别 | 检查项数量 | 严重 | 高 | 中 |
|------|------------|------|----|----|
| XSS 安全 | 12 | 8 | 4 | 0 |
| 代码注入 | 5 | 3 | 2 | 0 |
| 敏感信息泄露 | 7 | 3 | 3 | 1 |
| 配置安全 | 9 | 1 | 5 | 3 |
| 开放重定向 | 4 | 0 | 4 | 0 |
| 依赖安全 | 6 | 0 | 3 | 3 |
| **总计** | **43** | **15** | **21** | **7** |

---

## 附录 D: 前端安全测试 Payload

### XSS 测试 Payload
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
```

### 原型污染测试 Payload
```json
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
```

### 开放重定向测试 Payload
```
//evil.com
https://evil.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```