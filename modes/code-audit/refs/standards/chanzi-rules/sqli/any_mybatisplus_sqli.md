# MyBatis-Plus SQL注入漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_mybatisplus_sqli` · 类别：sqli · 关键 sink：EntityWrapper, LambdaQueryWrapper, LambdaUpdateWrapper, QueryWrapper, UpdateWrapper, addFilter, and, apply, groupBy, having, inSql, last
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## MyBatis-Plus SQL注入漏洞
MyBatis-Plus（简称MP）是基于MyBatis的增强工具，核心优势是简化CRUD操作、提供通用Mapper/Service、条件构造器（Wrapper）等功能，但这些便捷特性若使用不当，会引入SQL注入漏洞。SQL注入的本质是攻击者通过拼接恶意SQL片段，篡改原有SQL逻辑，实现未授权的数据查询、修改、删除甚至服务器端命令执行，其风险根源在于**用户输入未被有效过滤/转义，直接参与SQL语句拼接**。

以下从MP的核心功能模块出发，完整梳理其SQL注入漏洞的产生场景、触发条件、漏洞原理及典型案例：

## 一、漏洞核心前提
MP本身并非“自带漏洞”，而是**使用方式不当**导致：
1. MP的底层仍依赖MyBatis的SQL解析与执行，若绕过MyBatis的参数绑定（#{}），直接使用字符串拼接（${}）或未校验的用户输入构造SQL，会触发注入；
2. MP的条件构造器、通用CRUD、自定义SQL、注解等功能，若未对用户输入做校验，均可能成为注入入口；
3. 注入风险的核心区别：MyBatis的`#{}`是预编译参数（安全），`${}`是字符串直接替换（危险），MP的部分API默认/允许使用`${}`拼接SQL，易被忽视。

## 二、主要漏洞场景及详细说明
### 场景1：条件构造器（Wrapper）的不当使用
MP的`QueryWrapper`/`UpdateWrapper`/`LambdaQueryWrapper`是最常用的条件构造工具，也是注入高发区，核心风险点在于**直接拼接用户输入的字符串到SQL片段中**。

#### 子场景1.1：使用`apply()`方法拼接未过滤的用户输入
`apply()`方法用于拼接自定义SQL片段，支持动态SQL，若直接传入用户可控参数且未做处理，会触发注入。
- 原理：`apply()`的参数若包含`${}`或直接拼接用户输入，会绕过预编译，直接融入SQL语句；
- 触发条件：用户输入可控制`apply()`的参数内容；
- 典型案例：
  ```java
  // 业务场景：按用户输入的排序字段和方式查询
  @GetMapping("/users")
  public List<User> getUsers(@RequestParam String sortField, @RequestParam String sortType) {
      QueryWrapper<User> wrapper = new QueryWrapper<>();
      // 危险：直接拼接用户输入到apply中，无过滤
      wrapper.apply("ORDER BY ${sortField} ${sortType}");
      // 等价于生成SQL：SELECT * FROM user ORDER BY [sortField] [sortType]
      return userMapper.selectList(wrapper);
  }
  ```
  攻击者构造请求：`/users?sortField=id; DROP TABLE user; -- &sortType=asc`，最终SQL变为：
  `SELECT * FROM user ORDER BY id; DROP TABLE user; -- asc`，导致表被删除。

#### 子场景1.2：`last()`方法拼接恶意SQL片段
`last()`方法用于在SQL末尾追加自定义片段（如LIMIT、ORDER BY、甚至子查询），无内置过滤，用户输入可控时直接触发注入。
- 原理：`last()`的参数会直接拼接到SQL最后，覆盖MP自动生成的后缀逻辑；
- 触发条件：用户输入可传入`last()`方法；
- 典型案例：
  ```java
  // 业务场景：用户指定分页条数
  @GetMapping("/users/page")
  public List<User> getUsersByPage(@RequestParam String limit) {
      QueryWrapper<User> wrapper = new QueryWrapper<>();
      // 危险：直接使用用户输入的limit参数
      wrapper.last("LIMIT " + limit);
      return userMapper.selectList(wrapper);
  }
  ```
  攻击者请求：`/users/page?limit=1; UPDATE user SET password='123456' WHERE id=1; --`，最终SQL：
  `SELECT * FROM user LIMIT 1; UPDATE user SET password='123456' WHERE id=1; --`，导致密码被篡改。

#### 子场景1.3：`like()`/`or()`等方法的参数未转义
`like()`方法用于生成模糊查询（`LIKE '%xxx%'`），若用户输入包含`%`、`_`、`'`等特殊字符且未转义，可能拼接恶意SQL；`or()`方法若条件由用户控制，易被构造“永真条件”。
- 原理：`like()`默认直接拼接参数，若用户输入含单引号闭合语句，会篡改查询逻辑；
- 典型案例：
  ```java
  // 业务场景：按用户名模糊查询
  @GetMapping("/users/like")
  public List<User> getUsersLike(@RequestParam String username) {
      QueryWrapper<User> wrapper = new QueryWrapper<>();
      // 危险：直接拼接用户输入到like中
      wrapper.like("username", username);
      // 等价于：SELECT * FROM user WHERE username LIKE '%${username}%'
      return userMapper.selectList(wrapper);
  }
  ```
  攻击者输入：`admin' OR '1'='1`，最终SQL：
  `SELECT * FROM user WHERE username LIKE '%admin' OR '1'='1%'`，等价于`SELECT * FROM user WHERE 1=1`，导致全表数据泄露。

#### 子场景1.4：LambdaWrapper的“伪安全”误区
LambdaQueryWrapper通过Lambda表达式指定字段（如`lambdaQuery.eq(User::getId, id)`），看似避免了字段名拼接，但**参数值仍可能注入**；若Lambda表达式的字段由反射/用户输入动态生成（非硬编码），仍有风险。
- 典型案例：
  ```java
  // 危险：字段名通过用户输入动态获取（反射生成Lambda）
  String fieldName = request.getParameter("field"); // 如传入 "id' OR 1=1 --"
  LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
  wrapper.eq(ReflectUtil.getLambda(User.class, fieldName), 1);
  // 生成SQL：SELECT * FROM user WHERE id' OR 1=1 -- = 1，触发注入
  ```

### 场景2：通用CRUD的主键/条件参数注入
MP的通用Mapper（如`selectById()`、`deleteById()`、`updateById()`）看似安全，但以下情况仍会注入：
#### 子场景2.1：主键参数为字符串类型且未校验
若主键是字符串（如`varchar`类型的ID），用户输入含单引号/恶意SQL片段，且MP未强制预编译，会触发注入。
- 典型案例：
  ```java
  // 业务场景：按字符串类型ID查询用户
  @GetMapping("/users/{id}")
  public User getUserById(@PathVariable String id) {
      // 危险：id为字符串，用户输入 "1' OR '1'='1"
      return userMapper.selectById(id);
  }
  ```
  若MP底层对字符串主键未使用`#{}`，而是拼接为`SELECT * FROM user WHERE id = '1' OR '1'='1'`，导致查询所有用户。

#### 子场景2.2：`selectByMap()`/`updateByMap()`的Map参数注入
`selectByMap(Map<String, Object> params)`/`updateByMap()`通过Map传递查询/更新条件，Map的key为字段名、value为值，若key由用户输入控制，会直接拼接字段名到SQL中。
- 原理：Map的key会被作为字段名直接拼接（使用`${}`），value若为字符串也可能未转义；
- 典型案例：
  ```java
  // 业务场景：动态条件查询
  Map<String, Object> params = new HashMap<>();
  String field = request.getParameter("field"); // 传入 "username'='admin' OR 1=1 --"
  String value = request.getParameter("value");
  params.put(field, value);
  // 生成SQL：SELECT * FROM user WHERE username'='admin' OR 1=1 -- = 'xxx'
  return userMapper.selectByMap(params);
  ```

### 场景3：自定义SQL与MP注解的混合使用
MP支持在Mapper接口中写自定义SQL（结合`@Select`/`@Update`等注解），若自定义SQL中混用MP的`${}`或未过滤用户输入，会触发注入，常见于：
#### 子场景3.1：`@Select`注解中使用`${}`拼接用户输入
MyBatis的`@Select`注解中，`${}`是字符串替换，`#{}`是预编译，若开发者误用`${}`接收用户输入，直接触发注入。
- 典型案例：
  ```java
  @Mapper
  public interface UserMapper extends BaseMapper<User> {
      // 危险：使用${}接收用户输入的排序字段
      @Select("SELECT * FROM user ORDER BY ${sortField} ${sortType}")
      List<User> selectBySort(@Param("sortField") String sortField, @Param("sortType") String sortType);
  }
  ```
  攻击者调用时传入`sortField=id; DELETE FROM user; --`，导致删表。

#### 子场景3.2：MP的`@TableName`/`@TableField`动态拼接
`@TableName`支持动态表名（如`@TableName("user_${suffix}")`），若`suffix`由用户输入控制且未过滤，会拼接恶意表名或SQL片段。
- 典型案例：
  ```java
  // 实体类：动态表名依赖用户输入的suffix
  @TableName("user_${suffix}")
  public class User {
      @TableField("name")
      private String name;
  }
  // 业务层：suffix从请求中获取
  String suffix = request.getParameter("suffix"); // 传入 "1; DROP TABLE user_1; --"
  QueryWrapper<User> wrapper = new QueryWrapper<>();
  wrapper.eq("name", "admin");
  // 生成SQL：SELECT * FROM user_1; DROP TABLE user_1; -- WHERE name = 'admin'
  userMapper.selectList(wrapper);
  ```

#### 子场景3.3：`SqlRunner`/`ExecuteBatch`执行动态SQL
MP的`SqlRunner`（通用SQL执行器）、`ExecuteBatch`（批量执行）若直接执行用户拼接的SQL字符串，无任何过滤，会导致严重注入。
- 典型案例：
  ```java
  // 危险：直接执行用户输入的SQL
  String sql = request.getParameter("sql"); // 如传入 "DROP TABLE user"
  SqlRunner sqlRunner = SqlRunner.create();
  sqlRunner.run(sql);
  ```

### 场景4：分页插件（PaginationInterceptor）的注入风险
MP的分页插件（如`MybatisPlusInterceptor`+`PaginationInnerInterceptor`）若配置不当，或分页参数（页码、页大小）由用户控制且未校验，可能触发注入：
#### 子场景4.1：分页参数拼接至SQL末尾
若分页插件底层使用`${}`拼接`LIMIT ${pageNum}, ${pageSize}`，用户输入`pageNum=1; UPDATE user SET status=0; --`，会篡改SQL；
#### 子场景4.2：自定义分页SQL的参数未转义
自定义分页查询时，若分页条件（如`WHERE`子句）由用户输入拼接，且未使用预编译，会注入。
- 典型案例：
  ```java
  @Select("SELECT * FROM user ${ew.customSqlSegment} LIMIT #{pageNum}, #{pageSize}")
  IPage<User> selectUserPage(IPage<User> page, @Param(Constants.WRAPPER) QueryWrapper<User> wrapper);
  // 若wrapper由用户控制，customSqlSegment会拼接恶意条件
  ```

### 场景5：代码生成器（Generator）的默认配置风险
MP的代码生成器（AutoGenerator）若使用默认配置，可能生成含`${}`的Mapper方法（如排序、模糊查询），开发者直接使用生成的代码而未修改，会引入“先天”注入风险：
- 典型情况：生成的`list()`方法默认支持动态排序，使用`${orderBy}`拼接排序字段，未过滤用户输入。

### 场景6：多租户插件（TenantLineInterceptor）的绕过注入
MP的多租户插件通过自动拼接租户ID（`WHERE tenant_id = #{tenantId}`）实现数据隔离，但以下情况会绕过并注入：
1. 用户输入构造条件覆盖租户ID（如`OR tenant_id=123`）；
2. 自定义SQL中未包含租户字段，且插件未强制过滤；
3. 租户ID参数由用户控制，未做权限校验。

## 三、注入漏洞的共性特征
1. **输入可控**：攻击者能控制参与SQL拼接的参数（字段名、排序方式、查询条件、分页参数等）；
2. **拼接无过滤**：未使用MyBatis的`#{}`预编译，而是直接用`${}`、字符串拼接、`apply()`/`last()`等方法拼接用户输入；
3. **逻辑篡改**：注入后的SQL会改变原有逻辑（如永真条件、删改语句、跨表查询）；
4. **影响范围**：轻则泄露全表数据，重则删改数据、执行恶意SQL（如`LOAD_FILE`、`INTO OUTFILE`，需数据库权限）。

## 四、易被忽视的“隐性”注入场景
1. **批量操作（`updateBatchById()`/`insertBatchSomeColumn()`）**：批量参数若包含用户输入的恶意值，且未转义，会批量注入；
2. **枚举/常量类的动态赋值**：若枚举值由用户输入动态生成（如`Status.valueOf(request.getParameter("status"))`），拼接至SQL时可能注入；
3. **缓存/ORM层的二次拼接**：MP结合Redis缓存时，若缓存中存储的SQL片段由用户输入生成，读取后拼接执行会触发注入；
4. **数据库函数调用**：使用`apply()`调用数据库函数（如`DATE_FORMAT(create_time, '${format}')`），`format`由用户控制时，可能注入（如`%Y-%m-%d'; DROP TABLE user; --`）。

综上，MyBatis-Plus的SQL注入漏洞并非工具本身的缺陷，而是**开发者对MP API的安全特性理解不足、未遵循“用户输入不可信”原则**导致的。不同场景的注入核心均围绕“用户输入未过滤且直接参与SQL拼接”，其表现形式随MP功能模块的不同而变化，但本质一致。

