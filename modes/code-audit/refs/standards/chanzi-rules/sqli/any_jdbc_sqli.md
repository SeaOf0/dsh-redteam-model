# Java JDBC SQL注入漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_jdbc_sqli` · 类别：sqli · 关键 sink：Connection, Statement, execute, executeQuery, executeUpdate, prepareCall, prepareStatement
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java JDBC SQL注入漏洞
SQL注入（SQL Injection）是一种常见的Web安全漏洞，本质是攻击者通过构造恶意SQL语句片段，注入到应用程序的SQL执行流程中，篡改原有SQL逻辑，从而实现未授权的数据访问、修改、删除，甚至控制数据库服务器。在Java JDBC场景下，SQL注入的核心诱因是**直接拼接用户输入到SQL语句字符串中**，而非通过参数化查询（PreparedStatement）处理用户输入，导致用户可控的恶意字符破坏SQL语法结构。

#### 一、JDBC中SQL注入的核心原理
JDBC操作数据库的基本流程为：
1. 加载驱动并建立数据库连接（Connection）；
2. 构造SQL语句字符串；
3. 创建Statement/PreparedStatement对象执行SQL；
4. 处理结果集（ResultSet）。

当使用`Statement`（而非`PreparedStatement`）且直接拼接用户输入时，用户输入的恶意字符（如`'`、`OR`、`UNION`、`;`等）会被解析为SQL语法的一部分，而非普通字符串参数，从而篡改SQL逻辑。

#### 二、JDBC中SQL注入的常见场景与案例
以下按注入方式、业务场景分类，结合具体代码示例说明（均为**存在漏洞**的代码）：

##### 场景1：基础字符串拼接导致的注入（最典型）
**核心特征**：将用户输入（如表单参数、URL参数）直接拼接到SQL语句中，使用`Statement`执行。

###### 子场景1.1：登录验证绕过（布尔型注入）
业务逻辑：根据用户名和密码查询用户，存在则登录成功。
漏洞代码：
```java
// 接收用户输入（模拟前端传参）
String username = request.getParameter("username");
String password = request.getParameter("password");

// 直接拼接SQL（高危）
String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

// 使用Statement执行SQL
Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);

if (rs.next()) {
    System.out.println("登录成功");
} else {
    System.out.println("登录失败");
}
```
**攻击方式**：
攻击者输入：
- username: `admin' OR '1'='1`
- password: 任意值

拼接后的SQL变为：
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '任意值'
```
由于`'1'='1'`恒成立，SQL逻辑被篡改，无需正确密码即可登录。

###### 子场景1.2：数据遍历/窃取（联合查询注入）
业务逻辑：根据用户ID查询个人信息。
漏洞代码：
```java
String userId = request.getParameter("userId");
String sql = "SELECT name, phone FROM user_info WHERE id = " + userId; // 未加引号，数字型注入

Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```
**攻击方式**：
攻击者输入userId: `1 UNION SELECT username, password FROM admin`
拼接后的SQL变为：
```sql
SELECT name, phone FROM user_info WHERE id = 1 UNION SELECT username, password FROM admin
```
若数据库支持UNION查询，攻击者可窃取管理员账号密码。

##### 场景2：特殊字符转义失效导致的注入
部分开发者误以为“转义单引号”即可防注入，但转义逻辑不完整或场景适配错误仍会导致漏洞：
###### 子场景2.1：仅转义单引号但忽略其他分隔符
漏洞代码：
```java
String username = request.getParameter("username");
// 仅简单替换单引号（不彻底）
username = username.replace("'", "''");
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```
**攻击方式**：
若数据库为MySQL，攻击者可使用`\`转义替换后的单引号：
输入username: `admin\' OR 1=1 #`
替换后变为：`admin\'' OR 1=1 #`
拼接后的SQL：
```sql
SELECT * FROM users WHERE username = 'admin\'' OR 1=1 #'
```
MySQL中`\`会转义单引号，导致`OR 1=1`生效，`#`注释掉后续语句，注入成功。

###### 子场景2.2：数字型参数未转义
当SQL中参数为数字类型（无需单引号包裹），开发者常忽略转义，直接拼接：
漏洞代码：
```java
String orderId = request.getParameter("orderId");
// 数字型参数直接拼接，无任何处理
String sql = "DELETE FROM orders WHERE id = " + orderId;
Statement stmt = conn.createStatement();
stmt.executeUpdate(sql);
```
**攻击方式**：
输入orderId: `1 OR 1=1`
拼接后的SQL：
```sql
DELETE FROM orders WHERE id = 1 OR 1=1
```
结果是删除表中所有订单，而非指定ID的订单。

##### 场景3：批量操作/动态SQL拼接导致的注入
开发者为实现动态条件查询、批量更新等功能，手动拼接复杂SQL，易引入注入：
###### 子场景3.1：动态WHERE条件拼接
漏洞代码：
```java
String keyword = request.getParameter("keyword");
String status = request.getParameter("status");

StringBuilder sql = new StringBuilder("SELECT * FROM goods WHERE 1=1");
if (keyword != null && !keyword.isEmpty()) {
    sql.append(" AND name LIKE '%").append(keyword).append("%'");
}
if (status != null && !status.isEmpty()) {
    sql.append(" AND status = '").append(status).append("'");
}

Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql.toString());
```
**攻击方式**：
输入keyword: `' OR 1=1 #`
拼接后的SQL：
```sql
SELECT * FROM goods WHERE 1=1 AND name LIKE '%' OR 1=1 #%' AND status = 'xxx'
```
`OR 1=1`生效，`#`注释后续条件，查询所有商品。

###### 子场景3.2：批量插入拼接VALUES
漏洞代码：
```java
// 模拟批量插入用户输入的多条数据
String[] usernames = request.getParameterValues("usernames");
String[] emails = request.getParameterValues("emails");

StringBuilder sql = new StringBuilder("INSERT INTO temp_users (name, email) VALUES ");
for (int i = 0; i < usernames.length; i++) {
    if (i > 0) {
        sql.append(",");
    }
    sql.append("('").append(usernames[i]).append("', '").append(emails[i]).append("')");
}

Statement stmt = conn.createStatement();
stmt.executeUpdate(sql.toString());
```
**攻击方式**：
输入usernames[0]: `admin', 'admin@test.com'); DROP TABLE temp_users; --`
拼接后的SQL：
```sql
INSERT INTO temp_users (name, email) VALUES ('admin', 'admin@test.com'); DROP TABLE temp_users; --', 'xxx@test.com')
```
`;`结束INSERT语句，执行`DROP TABLE`，删除整个表。

##### 场景4：存储过程调用中的注入
JDBC调用数据库存储过程时，若拼接存储过程参数，仍会触发注入：
漏洞代码：
```java
String userId = request.getParameter("userId");
// 拼接存储过程参数
String sql = "CALL getUserInfo('" + userId + "')";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```
**攻击方式**：
输入userId: `1'; UPDATE users SET password = '123456' WHERE username = 'admin'; --`
拼接后的SQL：
```sql
CALL getUserInfo('1'); UPDATE users SET password = '123456' WHERE username = 'admin'; --')
```
执行存储过程后，额外执行UPDATE语句，篡改管理员密码。

##### 场景5：框架封装后的间接注入（易被忽视）
即使使用轻量级JDBC封装工具（如DbUtils），若未使用参数化，仍会注入：
漏洞代码（Apache DbUtils）：
```java
String username = request.getParameter("username");
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
QueryRunner queryRunner = new QueryRunner(dataSource);
User user = queryRunner.query(sql, new BeanHandler<>(User.class));
```
本质仍是拼接SQL，注入原理与原生Statement一致。

#### 三、SQL注入的危害分级（JDBC场景）
1. **数据泄露**：窃取用户密码、订单、敏感配置等（最常见）；
2. **数据篡改**：修改用户信息、订单状态、金额等；
3. **数据删除**：删除表数据、甚至DROP表/库；
4. **权限提升**：通过注入修改管理员账号、获取数据库服务器权限；
5. **服务器控制**：若数据库账户权限过高（如root），可通过SQL注入执行系统命令（如MySQL的`into outfile`写文件、SQL Server的`xp_cmdshell`）。

#### 四、JDBC中SQL注入的关键触发条件
1. **输入可控**：攻击者可修改拼接进SQL的参数（如URL、表单、Cookie参数）；
2. **SQL拼接**：将用户输入直接拼接到SQL语句字符串中，未做参数化处理；
3. **执行权限过高**：数据库连接账户权限过大（如拥有SELECT/UPDATE/DELETE/DROP权限），放大注入危害；
4. **无输入校验**：未对用户输入做类型、长度、字符集的严格校验（如数字参数未校验是否为纯数字）。

#### 总结
JDBC中的SQL注入本质是“用户输入未被正确隔离为参数，而是作为SQL语法的一部分执行”，核心载体是`Statement`类的字符串拼接执行方式。其场景覆盖登录、查询、删除、批量操作、存储过程调用等几乎所有数据库交互场景，危害程度取决于数据库账户权限和业务数据敏感度。

