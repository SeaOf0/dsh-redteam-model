# Java JdbcTemplate SQL注入漏洞

> 规则 ID：`any_jdbctemplate_sqli` · 类别：sqli · 关键 sink：JdbcOperations, JdbcTemplate, batchUpdate, execute, query, queryForList, queryForMap, queryForObject, queryForRowSet
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java JdbcTemplate SQL注入漏洞
JdbcTemplate是Spring Framework提供的JDBC操作封装工具，旨在简化JDBC的繁琐代码（如连接管理、Statement创建、异常处理等），但**并非天然免疫SQL注入**——其是否存在注入风险，核心取决于SQL语句的构建方式、参数绑定形式，以及开发者对参数处理的规范性。以下从漏洞本质、触发场景、各类注入情况展开详细说明。

## 一、漏洞本质
SQL注入的核心是：攻击者通过可控输入篡改SQL语句的语义，使数据库执行非预期的操作（如查询敏感数据、修改数据、执行系统命令等）。
JdbcTemplate本身不直接产生注入，但如果开发者未正确使用其参数绑定机制，而是通过**字符串拼接**构建SQL语句，或误用参数绑定方式，会导致用户输入直接嵌入SQL语句中，最终引发注入。

## 二、JdbcTemplate的核心执行方式与注入关联性
JdbcTemplate提供了多类SQL执行方法，可分为“安全的参数绑定”和“危险的字符串拼接”两大类，前者通过预编译（PreparedStatement）规避注入，后者则完全暴露风险：
| 执行方式                | 底层实现       | 注入风险 | 核心原理                     |
|-------------------------|----------------|----------|------------------------------|
| `update(String sql, Object... args)` | PreparedStatement | 无（正确使用时） | 参数通过`?`占位符绑定，预编译隔离输入 |
| `query(String sql, RowMapper rowMapper, Object... args)` | PreparedStatement | 无（正确使用时） | 同上                         |
| `execute(String sql)`   | Statement      | 高       | 直接执行拼接后的SQL字符串    |
| 拼接SQL后传入参数绑定方法 | PreparedStatement | 高       | 拼接已篡改SQL语义，占位符仅替换值 |

## 三、JdbcTemplate SQL注入的各类触发场景
### 场景1：直接字符串拼接SQL（最常见）
开发者将用户可控参数直接拼接到SQL语句字符串中，而非使用`?`占位符，此时即使调用JdbcTemplate的参数绑定方法，也无法规避注入——因为SQL语义已在拼接阶段被篡改。

#### 示例代码（危险）：
```java
// 用户可控输入（如从请求中获取）
String userId = request.getParameter("userId");
// 直接拼接SQL，而非使用?占位符
String sql = "SELECT * FROM user WHERE id = " + userId;
// 调用JdbcTemplate查询，此时SQL已被拼接完成
List<User> users = jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(User.class));
```

#### 注入攻击演示：
若攻击者传入`userId=1 OR 1=1`，最终执行的SQL为：
```sql
SELECT * FROM user WHERE id = 1 OR 1=1
```
结果会查询出所有用户数据；若传入`userId=1; DROP TABLE user;`（部分数据库支持多语句执行），可能导致表被删除。

### 场景2：拼接SQL片段（表名/列名/排序字段等）
参数绑定（`?`占位符）仅支持“值替换”，无法绑定表名、列名、排序字段（ORDER BY）、聚合函数、SQL关键字（如ASC/DESC）等语法元素。若开发者将用户可控输入拼接至这些位置，必然引发注入。

#### 示例1：动态表名拼接
```java
// 用户可控的表名参数
String tableName = request.getParameter("table");
// 拼接表名（无法用?占位符）
String sql = "SELECT * FROM " + tableName + " WHERE status = ?";
// 即使部分参数用占位符，表名拼接仍有注入风险
jdbcTemplate.query(sql, new Object[]{1}, new BeanPropertyRowMapper<>(User.class));
```
#### 攻击演示：
攻击者传入`tableName=user UNION SELECT id, name, password FROM admin`，最终SQL：
```sql
SELECT * FROM user UNION SELECT id, name, password FROM admin WHERE status = 1
```
可窃取管理员密码。

#### 示例2：动态排序字段拼接
```java
// 用户可控的排序字段
String sortBy = request.getParameter("sortBy");
// 拼接排序字段
String sql = "SELECT * FROM user ORDER BY " + sortBy + " ASC";
jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(User.class));
```
#### 攻击演示：
攻击者传入`sortBy=id; UPDATE user SET password='123456' WHERE id=1`，最终SQL执行后会篡改管理员密码。

### 场景3：误用NamedParameterJdbcTemplate（命名参数）
NamedParameterJdbcTemplate是JdbcTemplate的扩展，支持命名参数（如`:userId`），底层仍基于PreparedStatement，本身安全，但开发者若错误地拼接命名参数或混用字符串拼接，仍会触发注入。

#### 示例1：拼接命名参数（危险）
```java
String userId = request.getParameter("userId");
// 错误拼接命名参数，而非绑定
String sql = "SELECT * FROM user WHERE id = :" + userId;
NamedParameterJdbcTemplate npjt = new NamedParameterJdbcTemplate(dataSource);
npjt.query(sql, new MapSqlParameterSource(), new BeanPropertyRowMapper<>(User.class));
```
#### 攻击演示：
攻击者传入`userId=1 OR 1=1`，最终SQL变为`SELECT * FROM user WHERE id = :1 OR 1=1`，命名参数解析失败，且OR条件直接生效，导致查询所有用户。

#### 示例2：命名参数+字符串拼接混合使用
```java
String sortDir = request.getParameter("sortDir"); // 可控输入：ASC/DESC
String sql = "SELECT * FROM user WHERE id = :userId ORDER BY id " + sortDir;
MapSqlParameterSource params = new MapSqlParameterSource();
params.addValue("userId", 1);
NamedParameterJdbcTemplate npjt = new NamedParameterJdbcTemplate(dataSource);
npjt.query(sql, params, new BeanPropertyRowMapper<>(User.class));
```
#### 攻击演示：
攻击者传入`sortDir=ASC; DELETE FROM user WHERE 1=1`，最终SQL：
```sql
SELECT * FROM user WHERE id = ? ORDER BY id ASC; DELETE FROM user WHERE 1=1
```
若数据库支持多语句执行（如MySQL开启`allowMultiQueries=true`），会直接删除全表数据。

### 场景4：批量操作中的注入（batchUpdate）
JdbcTemplate的`batchUpdate`方法支持批量执行SQL，若批量SQL通过字符串拼接构建，而非使用参数绑定，会引发批量注入。

#### 示例代码（危险）：
```java
List<String> userIds = Arrays.asList(request.getParameterValues("userIds")); // 可控批量输入
StringBuilder sqlBatch = new StringBuilder();
for (String id : userIds) {
    // 拼接批量删除SQL
    sqlBatch.append("DELETE FROM user WHERE id = ").append(id).append(";");
}
// 执行批量SQL
jdbcTemplate.execute(sqlBatch.toString());
```
#### 攻击演示：
攻击者传入`userIds=1 OR 1=1`，最终批量SQL为`DELETE FROM user WHERE id = 1 OR 1=1;`，直接删除全表数据。

### 场景5：存储过程调用中的注入
JdbcTemplate调用存储过程时，若存储过程参数通过字符串拼接传入，或存储过程内部未对参数做校验，会引发“二次注入”或直接注入。

#### 示例代码（危险）：
```java
String userId = request.getParameter("userId");
// 拼接存储过程参数
String sql = "CALL getUserInfo(" + userId + ")";
jdbcTemplate.execute(sql);
```
#### 攻击演示：
若存储过程`getUserInfo`内部直接使用传入的参数拼接SQL（如`SELECT * FROM user WHERE id = @userId`，但@userId未做转义），攻击者传入`userId=1; DROP TABLE log`，会触发存储过程内部的SQL注入。

### 场景6：特殊字符未过滤导致的注入（即使使用占位符）
极少数情况下，开发者虽使用`?`占位符，但对参数做了“反向处理”（如手动拼接引号、转义字符），导致占位符失效，触发注入。

#### 示例代码（危险）：
```java
String username = request.getParameter("username");
// 错误手动添加引号，破坏占位符机制
username = "'" + username + "'";
String sql = "SELECT * FROM user WHERE username = ?";
// 此时参数是带引号的字符串，若攻击者传入逃逸字符，仍可注入
jdbcTemplate.query(sql, new Object[]{username}, new BeanPropertyRowMapper<>(User.class));
```
#### 攻击演示：
攻击者传入`username=admin' OR '1'='1`，经手动拼接后参数变为`'admin' OR '1'='1'`，最终SQL：
```sql
SELECT * FROM user WHERE username = 'admin' OR '1'='1'
```
直接查询所有用户。

## 四、关键补充：JdbcTemplate注入的易忽略点
1. **预编译的局限性**：PreparedStatement仅对“值”占位符生效，对SQL语法元素（表名、列名、排序关键字）无保护，这是JdbcTemplate无法规避此类注入的核心原因；
2. **数据库特性影响**：部分数据库（如MySQL）开启`allowMultiQueries=true`时，支持多语句执行（`;`分隔），会放大注入危害（如拼接删除/修改语句）；
3. **ORM框架混用风险**：若项目中同时使用JdbcTemplate和MyBatis等ORM框架，开发者可能因习惯差异，在JdbcTemplate中误用拼接方式，引发注入；
4. **动态SQL生成器风险**：若使用第三方动态SQL生成工具（如拼接SQL的工具类），且工具类未做安全处理，即使调用JdbcTemplate的参数绑定方法，仍会因生成的SQL已被篡改而注入。

综上，JdbcTemplate本身并非“防注入神器”，其安全与否完全取决于开发者是否遵循“参数绑定而非字符串拼接”的核心原则——任何绕过占位符、直接将用户输入嵌入SQL语句的行为，都会触发SQL注入漏洞。

