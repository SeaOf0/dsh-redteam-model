# MyBatis SQL注入漏洞完整描述

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_mybatis_sqli` · 类别：sqli · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## MyBatis SQL注入漏洞完整描述
MyBatis作为Java生态中主流的半ORM（对象关系映射）框架，其核心是通过XML或注解方式映射SQL语句，兼具原生SQL的灵活性和ORM的便捷性。但因SQL语句编写不规范、框架特性使用不当等问题，极易引发SQL注入漏洞——攻击者通过构造恶意输入参数，篡改原有SQL的逻辑结构，最终执行非预期的SQL操作（如未授权数据查询、修改、删除，甚至数据库服务器权限提权等）。

MyBatis的SQL注入风险并非框架本身的漏洞，而是**开发者使用方式不当**导致的，其风险点集中在SQL语句的动态拼接环节，核心根源是：未对用户输入做有效转义，且将用户可控参数直接拼入SQL语句执行。以下按不同使用场景，详细拆解MyBatis中SQL注入的各类情况：

## 一、核心前提：MyBatis的参数传递机制
MyBatis提供两种核心参数传递方式，这是区分注入风险的基础：
1. **#{}（参数占位符）**：默认采用预编译（PreparedStatement）方式，MyBatis会自动将参数替换为`?`占位符，且对参数值做转义处理（如单引号转义），**天然防御SQL注入**；
2. **${}（字符串替换）**：直接将参数值拼接进SQL语句（相当于字符串拼接），无任何转义处理，**是SQL注入的核心风险点**。

所有MyBatis SQL注入场景，本质都是开发者错误使用`${}`，或在动态SQL中不当拼接用户可控参数导致的。

## 二、MyBatis SQL注入的具体场景
### 场景1：直接使用${}拼接用户可控参数（最常见）
当开发者为了实现动态参数（如动态表名、列名、排序字段），直接用`${}`接收用户输入时，会直接将恶意参数拼入SQL，引发注入。

#### 子场景1.1：动态表名/库名注入
**业务场景**：系统支持按不同业务模块查询数据，表名由用户输入指定（如`user_2024`、`user_2025`），开发者用`${}`拼接表名。
**示例代码（XML映射文件）**：
```xml
<select id="queryByTable" resultType="User">
    SELECT * FROM ${tableName} WHERE id = #{id}
</select>
```
**攻击过程**：
用户传入`tableName=user UNION SELECT id, name, password FROM admin`，拼接后的SQL变为：
```sql
SELECT * FROM user UNION SELECT id, name, password FROM admin WHERE id = ?
```
攻击者可通过UNION查询获取管理员表的敏感数据。

#### 子场景1.2：动态排序字段/排序方向注入
**业务场景**：前端传递排序字段（如`name`）和排序方向（`ASC`/`DESC`），开发者用`${}`拼接排序逻辑。
**示例代码（注解方式）**：
```java
@Select("SELECT * FROM user ORDER BY ${sortField} ${sortDir}")
List<User> queryUser(@Param("sortField") String sortField, @Param("sortDir") String sortDir);
```
**攻击过程**：
用户传入`sortDir=DESC; DROP TABLE user;`，拼接后的SQL变为：
```sql
SELECT * FROM user ORDER BY name DESC; DROP TABLE user;
```
若数据库支持多语句执行（如MySQL开启`allowMultiQueries=true`），会直接删除`user`表；即使不支持多语句，也可构造`sortDir=ASC AND 1=0 UNION SELECT 1,2,3 FROM admin`篡改查询结果。

#### 子场景1.3：动态条件拼接（替代#{}）
部分开发者因不了解`#{}和${}`的区别，错误地用`${}`接收普通查询参数（如用户ID、用户名），导致基础查询注入。
**示例代码**：
```xml
<select id="getUserByName" resultType="User">
    SELECT * FROM user WHERE username = ${username}
</select>
```
**攻击过程**：
用户传入`username=' OR '1'='1`，拼接后的SQL变为：
```sql
SELECT * FROM user WHERE username = ' OR '1'='1
```
直接查询出所有用户数据。

### 场景2：动态SQL标签中拼接用户可控参数
MyBatis提供`<if>`、`<where>`、`<foreach>`、`<set>`等动态SQL标签，若在这些标签内拼接用户输入的参数（尤其是未过滤的字符串），仍会引发注入。

#### 子场景2.1：<if>标签内的参数拼接
**业务场景**：多条件查询，用户传入多个筛选参数，开发者在`<if>`中用`${}`拼接条件。
**示例代码**：
```xml
<select id="queryUserByCondition" resultType="User">
    SELECT * FROM user
    <where>
        <if test="username != null">
            AND username = ${username}
        </if>
        <if test="role != null">
            AND role = ${role}
        </if>
    </where>
</select>
```
**攻击过程**：
用户传入`username=' OR '1'='1 -- `，拼接后的SQL变为：
```sql
SELECT * FROM user WHERE username = ' OR '1'='1 --  AND role = ?
```
`--`注释掉后续条件，直接绕过权限筛选，查询所有用户。

#### 子场景2.2：<foreach>标签的不当使用
`<foreach>`用于批量操作（如IN查询、批量插入），若对`collection`中的元素未做处理，或错误使用`${}`遍历，会引发注入。
**示例1（IN查询注入）**：
```xml
<select id="queryUserByIds" resultType="User">
    SELECT * FROM user WHERE id IN (${ids})
</select>
```
用户传入`ids=1,2) OR 1=1 -- `，拼接后的SQL变为：
```sql
SELECT * FROM user WHERE id IN (1,2) OR 1=1 -- )
```
直接查询所有用户。

**示例2（批量插入注入）**：
```xml
<insert id="batchInsertUser">
    INSERT INTO user (username, password) VALUES
    <foreach collection="list" item="item" separator=",">
        (${item.username}, ${item.password})
    </foreach>
</insert>
```
用户传入`username='test', '123') ; DROP TABLE log; -- `，拼接后的SQL变为：
```sql
INSERT INTO user (username, password) VALUES ('test', '123') ; DROP TABLE log; -- , (...)
```
执行插入后，删除日志表。

#### 子场景2.3：<bind>标签的风险
`<bind>`标签用于在XML中定义变量，若绑定的变量是用户可控的，且后续用`${}`使用该变量，仍会注入。
**示例代码**：
```xml
<select id="queryUser" resultType="User">
    <bind name="searchName" value="'%' + username + '%'"/>
    SELECT * FROM user WHERE username LIKE ${searchName}
</select>
```
用户传入`username='%' OR '1'='1 -- `，`searchName`变为`'%' OR '1'='1 -- %'`，拼接后的SQL变为：
```sql
SELECT * FROM user WHERE username LIKE '%' OR '1'='1 -- %'
```
绕过模糊查询，查询所有用户。

### 场景3：注解方式的动态SQL拼接
除XML映射外，MyBatis的注解（`@Select`、`@Insert`、`@Update`、`@Delete`）也支持动态SQL，若在注解中拼接用户参数，风险与XML方式一致。

#### 示例（注解+字符串拼接）：
```java
@Select({"<script>",
        "SELECT * FROM user",
        "<where>",
        "   <if test='keyword != null'>",
        "       AND username LIKE '%${keyword}%'",
        "   </if>",
        "</where>",
        "</script>"})
List<User> searchUser(@Param("keyword") String keyword);
```
**攻击过程**：
用户传入`keyword=' OR 1=1 -- `，拼接后的SQL变为：
```sql
SELECT * FROM user WHERE username LIKE '%' OR 1=1 -- %'
```
直接查询所有用户。

### 场景4：框架扩展/插件导致的注入
MyBatis支持自定义插件（如分页插件、通用Mapper），若插件内部未对参数做过滤，直接拼接用户输入，会引发间接注入。

#### 示例（分页插件注入）：
某分页插件自动拼接`ORDER BY ${sortField} ${sortDir}`，若`sortField`和`sortDir`由用户传入且未校验，攻击者可构造：
`sortField=id; DROP TABLE user;`，最终执行的SQL包含恶意语句，导致表删除。

### 场景5：特殊场景的注入（边界情况）
#### 子场景5.1：参数类型转换导致的注入
若用户传入的参数是数值类型，但开发者用`${}`拼接（而非`#{}）`，攻击者可构造数值+恶意SQL的形式注入。
**示例**：
```xml
<select id="queryUserById" resultType="User">
    SELECT * FROM user WHERE id = ${id}
</select>
```
用户传入`id=1 OR 1=1`，拼接后的SQL变为：
```sql
SELECT * FROM user WHERE id = 1 OR 1=1
```
查询所有用户（注：数值类型注入无需单引号，风险更隐蔽）。

#### 子场景5.2：数据库函数/关键字拼接注入
若拼接用户参数到数据库函数（如`CONCAT`、`DATE_FORMAT`）或SQL关键字中，会引发注入。
**示例**：
```xml
<select id="queryUserByTime" resultType="User">
    SELECT * FROM user WHERE create_time > DATE_FORMAT(${time}, '%Y-%m-%d')
</select>
```
用户传入`time='2024-01-01' OR 1=1 -- `，拼接后的SQL变为：
```sql
SELECT * FROM user WHERE create_time > DATE_FORMAT('2024-01-01' OR 1=1 -- , '%Y-%m-%d')
```
篡改时间条件，查询所有用户。

## 三、SQL注入的危害总结
无论哪种场景，MyBatis SQL注入最终会导致：
1. **数据泄露**：查询到未授权的敏感数据（如用户密码、手机号、财务数据）；
2. **数据篡改/删除**：修改、删除数据库中的数据（如篡改用户余额、删除核心业务数据）；
3. **权限提权**：通过注入获取数据库管理员权限（如MySQL的`root`、Oracle的`sysdba`）；
4. **服务器入侵**：利用数据库的扩展功能（如MySQL的`outfile`、`load_file`）读写服务器文件，甚至执行系统命令。

综上，MyBatis SQL注入的核心是“用户可控参数未经转义直接拼入SQL语句”，所有风险场景均围绕`${}`的不当使用、动态SQL标签的参数拼接、插件/扩展的不规范处理展开，其本质是开发者未遵循“预编译优先”的SQL编写原则。

