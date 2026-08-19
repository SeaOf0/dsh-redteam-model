# Java JPA SQL注入漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`other_jpa_sqli` · 类别：sqli · 关键 sink：EntityManager, createNativeQuery
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java JPA SQL注入漏洞
JPA（Java Persistence API）是Java EE中用于对象关系映射（ORM）的标准规范，其核心目标是简化数据库操作、屏蔽底层SQL细节，但**不当使用仍会引入SQL注入漏洞**。SQL注入的本质是攻击者通过构造恶意输入，篡改SQL语句的逻辑，实现未授权的数据访问、修改甚至服务器接管。以下从JPA的核心使用场景出发，完整拆解其SQL注入的成因、表现形式及各类触发场景。

#### 一、JPA SQL注入的核心成因
JPA本身提供了两种核心的数据库操作方式：**JPQL（Java Persistence Query Language）** 和 **原生SQL查询**，此外还包括Criteria API、命名查询等衍生方式。SQL注入的根源在于：
1. **字符串拼接**：将用户可控的输入直接拼接进JPQL/SQL语句，而非使用参数绑定；
2. **参数绑定失效**：错误的参数绑定方式（如手动拼接参数值、对关键字段未做参数化）；
3. **框架特性滥用**：对JPA的动态查询、原生SQL执行等特性使用不当，绕过框架的参数化保护。

JPA的参数绑定（`?` 或命名参数 `:param`）本质是借助JDBC的PreparedStatement实现预编译，能有效阻断注入；但一旦脱离参数化，直接拼接字符串，就会暴露注入风险。

#### 二、JPA SQL注入的核心场景分类
##### 场景1：JPQL查询中的字符串拼接注入（最常见）
JPQL是JPA的面向对象查询语言，语法类似SQL但操作实体类而非表。若直接拼接用户输入到JPQL语句中，会触发注入。

###### 子场景1.1：简单条件拼接注入
**示例代码（有漏洞）**：
```java
// 接收用户输入的用户名（攻击者可控）
String username = request.getParameter("username");
// 直接拼接JPQL语句，未使用参数绑定
String jpql = "SELECT u FROM User u WHERE u.username = '" + username + "'";
Query query = entityManager.createQuery(jpql);
List<User> users = query.getResultList();
```
**注入攻击演示**：
攻击者输入 `admin' OR '1'='1`，拼接后的JPQL变为：
```jpql
SELECT u FROM User u WHERE u.username = 'admin' OR '1'='1'
```
该语句会查询所有用户（绕过用户名验证），若场景是登录验证，则无需密码即可登录任意账号。

###### 子场景1.2：排序/分页参数拼接注入
JPQL支持 `ORDER BY` 排序，若排序字段/排序方向由用户输入直接拼接，会触发注入（排序参数无法通过参数绑定，是JPA的设计特性）。

**示例代码（有漏洞）**：
```java
// 用户可控的排序字段（如传入 "u.id; DELETE FROM User; --"）
String sortField = request.getParameter("sortField");
// 用户可控的排序方向（ASC/DESC）
String sortDir = request.getParameter("sortDir");
// 拼接排序语句
String jpql = "SELECT u FROM User u ORDER BY " + sortField + " " + sortDir;
Query query = entityManager.createQuery(jpql);
List<User> users = query.getResultList();
```
**注入攻击演示**：
攻击者输入 `sortField=u.id' OR '1'='1; DROP TABLE User; --`，拼接后的JPQL会被解析为包含恶意SQL的语句（若底层数据库支持，可能执行删表操作）；即使不支持DDL，也可通过 `ORDER BY (SELECT 1 FROM dual WHERE 1=1 AND (SELECT password FROM User WHERE username='admin')='123456')` 窃取敏感数据。

###### 子场景1.3：IN子句拼接注入
JPQL的IN子句若直接拼接用户输入的多个值，而非使用参数列表，会触发注入。

**示例代码（有漏洞）**：
```java
// 用户输入的ID列表，如 "1,2,3' OR '1'='1"
String userIds = request.getParameter("userIds");
String jpql = "SELECT u FROM User u WHERE u.id IN (" + userIds + ")";
Query query = entityManager.createQuery(jpql);
List<User> users = query.getResultList();
```
**注入攻击演示**：
攻击者输入 `1) OR (1=1 --`，拼接后的JPQL变为：
```jpql
SELECT u FROM User u WHERE u.id IN (1) OR (1=1 --)
```
结果返回所有用户，突破数据访问限制。

##### 场景2：原生SQL查询中的注入（风险更高）
JPA允许通过 `createNativeQuery()` 执行原生SQL，若拼接用户输入，直接对接底层数据库，注入风险远高于JPQL（可执行任意SQL语句）。

###### 子场景2.1：简单原生SQL拼接
**示例代码（有漏洞）**：
```java
String username = request.getParameter("username");
String sql = "SELECT * FROM t_user WHERE username = '" + username + "'";
Query query = entityManager.createNativeQuery(sql, User.class);
List<User> users = query.getResultList();
```
**注入攻击演示**：
攻击者输入 `admin' AND (SELECT COUNT(*) FROM t_admin) > 0 --`，可探测管理员表是否存在；若输入 `admin'; DELETE FROM t_user WHERE 1=1 --`，直接删除全表数据。

###### 子场景2.2：原生SQL的批量操作注入
**示例代码（有漏洞）**：
```java
String roleId = request.getParameter("roleId");
String sql = "UPDATE t_user SET role_id = " + roleId + " WHERE status = 1";
Query query = entityManager.createNativeQuery(sql);
int affectedRows = query.executeUpdate();
```
**注入攻击演示**：
攻击者输入 `999; UPDATE t_user SET password = '123456' --`，拼接后的SQL变为：
```sql
UPDATE t_user SET role_id = 999; UPDATE t_user SET password = '123456' -- WHERE status = 1
```
执行后所有用户密码被篡改，造成严重安全事故。

###### 子场景2.3：原生SQL的表名/字段名拼接
表名、字段名无法通过参数绑定（PreparedStatement仅支持值绑定，不支持对象名绑定），若直接拼接用户输入，必现注入。

**示例代码（有漏洞）**：
```java
// 用户输入要查询的表名，如 "t_user; DROP TABLE t_log --"
String tableName = request.getParameter("tableName");
String sql = "SELECT * FROM " + tableName + " WHERE id = 1";
Query query = entityManager.createNativeQuery(sql);
List<Object[]> result = query.getResultList();
```
**注入攻击演示**：
攻击者输入 `t_user UNION ALL SELECT username, password FROM t_admin --`，可跨表窃取管理员账号密码；若输入 `t_user; TRUNCATE TABLE t_order --`，清空订单表。

##### 场景3：命名查询（Named Query）中的注入
JPA的命名查询（在实体类通过 `@NamedQuery` 定义）本身是预编译的，但**动态拼接命名查询的参数/内容**仍会触发注入。

###### 子场景3.1：动态修改命名查询的JPQL内容
**示例代码（有漏洞）**：
```java
// 实体类定义的命名查询：@NamedQuery(name = "User.findByUsername", query = "SELECT u FROM User u WHERE u.username = :username")
String username = request.getParameter("username");
// 恶意拼接命名查询的JPQL（覆盖原有参数绑定）
String dynamicJpql = "SELECT u FROM User u WHERE u.username = '" + username + "'";
Query query = entityManager.createQuery(dynamicJpql); // 未使用命名查询的参数化
List<User> users = query.getResultList();
```
本质仍是JPQL拼接注入，命名查询的预编译特性被绕过。

###### 子场景3.2：命名原生查询的参数拼接
**示例代码（有漏洞）**：
```java
// 实体类定义：@NamedNativeQuery(name = "User.countByRole", query = "SELECT COUNT(*) FROM t_user WHERE role_id = ?")
String roleId = request.getParameter("roleId");
// 拼接参数到命名查询的SQL中（而非使用setParameter）
String dynamicSql = "SELECT COUNT(*) FROM t_user WHERE role_id = " + roleId;
Query query = entityManager.createNativeQuery(dynamicSql);
Long count = (Long) query.getSingleResult();
```
同样触发原生SQL注入，命名查询的保护机制失效。

##### 场景4：Criteria API的间接注入（易被忽视）
Criteria API是JPA的类型安全查询方式，本身能避免大部分注入，但**不当的动态条件拼接**仍可能引入风险：

###### 子场景4.1：动态拼接Predicate的字符串参数
**示例代码（有漏洞）**：
```java
String username = request.getParameter("username");
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<User> query = cb.createQuery(User.class);
Root<User> root = query.from(User.class);
// 错误：直接拼接字符串作为条件（而非使用cb.equal）
Predicate predicate = cb.equal(root.get("username"), cb.literal(username));
// 若攻击者输入 "admin' OR '1'='1"，literal会直接拼接为字符串常量，触发注入
query.where(predicate);
List<User> users = entityManager.createQuery(query).getResultList();
```
**注**：Criteria API的 `cb.literal()` 会将输入作为字面量拼接，而非参数绑定，若输入包含恶意SQL片段，仍会触发注入；正确方式应使用 `cb.equal(root.get("username"), username)`（自动参数绑定）。

###### 子场景4.2：动态字段名拼接
**示例代码（有漏洞）**：
```java
String sortField = request.getParameter("sortField"); // 如 "username' DESC; --"
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<User> query = cb.createQuery(User.class);
Root<User> root = query.from(User.class);
// 动态拼接排序字段（无校验）
query.orderBy(cb.asc(root.get(sortField)));
List<User> users = entityManager.createQuery(query).getResultList();
```
若攻击者输入的 `sortField` 包含恶意JPQL片段，会被解析为查询的一部分，触发注入（如 `username') OR (1=1) --`）。

##### 场景5：框架扩展/第三方库的JPA注入
部分基于JPA的扩展框架（如Spring Data JPA）若使用不当，也会引入注入：

###### 子场景5.1：Spring Data JPA的@Query注解拼接
**示例代码（有漏洞）**：
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // 直接拼接参数到JPQL，未使用参数绑定
    @Query("SELECT u FROM User u WHERE u.username = '" + "#{#username}" + "'")
    List<User> findByUsername(@Param("username") String username);
}
```
**注**：错误使用SpEL表达式拼接参数，而非 `:username`，导致参数未被绑定，触发注入。

###### 子场景5.2：Spring Data JPA的动态查询（Query By Example）滥用
```java
// 攻击者可控的Example匹配条件
String username = request.getParameter("username");
User exampleUser = new User();
exampleUser.setUsername(username); // 若username为 "admin' OR '1'='1"
Example<User> example = Example.of(exampleUser);
List<User> users = userRepository.findAll(example);
```
Query By Example本身基于参数绑定，但若手动修改Example的匹配规则（如使用模糊匹配时拼接通配符），仍可能引入注入：
```java
String username = request.getParameter("username");
// 错误：拼接通配符到参数中
String fuzzyUsername = "%" + username + "%";
User exampleUser = new User();
exampleUser.setUsername(fuzzyUsername);
Example<User> example = Example.of(exampleUser);
List<User> users = userRepository.findAll(example);
```
若攻击者输入 `%' OR '1'='1%`，拼接后的模糊查询会匹配所有记录。

#### 三、JPA SQL注入的特殊风险点
1. **多数据源场景**：若JPA对接多数据库（如MySQL、Oracle），注入语句可针对不同数据库的语法特性定制（如MySQL的 `--` 注释、Oracle的 `--`/`/* *\/` 注释），攻击面更广；
2. **事务上下文**：注入的恶意SQL若在事务中执行，可能造成批量数据篡改且无法回滚（如执行 `COMMIT` 强制提交）；
3. **权限放大**：若JPA使用的数据库账号权限过高（如DBA权限），注入可执行 `CREATE USER`、`GRANT` 等操作，接管数据库服务器；
4. **盲注场景**：若JPA查询无返回结果（如登录验证），攻击者可通过时间盲注（`AND SLEEP(5)`）或布尔盲注（`AND (SELECT LENGTH(password) FROM t_admin WHERE id=1)=8`）窃取数据，隐蔽性更强。

#### 四、总结
JPA的SQL注入本质是**脱离参数化查询的字符串拼接**，核心触发点覆盖JPQL、原生SQL、命名查询、Criteria API及第三方扩展框架。其中：
- JPQL注入主要影响数据查询逻辑，风险相对可控；
- 原生SQL注入可直接执行任意数据库操作，是最高风险场景；
- 排序字段、表名/字段名、IN子句等无法参数化的场景，是注入防护的难点；
- 框架特性（如Criteria API的literal、Spring Data JPA的SpEL）的不当使用，易被忽视但同样触发注入。

所有场景的共性是未将用户输入作为“参数”传递，而是作为“SQL语句的一部分”拼接，最终导致攻击者可篡改SQL逻辑。

