# Java 异常堆栈信息泄露漏洞 完整描述

> 规则 ID：`exception_any_infoleak` · 类别：infoleak · 关键 sink：HttpServletResponse, Model, PrintWriter, ServletOutputStream, addAttribute, append, format, print, printf, println, sendError, write
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java 异常堆栈信息泄露漏洞 完整描述
Java 异常堆栈信息泄露漏洞，本质是**程序未对异常信息进行合理管控，导致包含敏感上下文的堆栈轨迹（Stack Trace）被泄露到不可控的输出渠道**（如前端页面、日志文件、API 响应、控制台等），攻击者可通过这些信息分析程序内部结构、逻辑缺陷、依赖组件、配置细节甚至数据链路，进而实施精准攻击。

该漏洞的核心风险在于：堆栈信息包含大量「非公开的内部信息」，而非单纯的错误提示；泄露场景覆盖开发、测试、生产全环境，且泄露渠道多样，是 Java 应用中最常见的信息泄露类漏洞之一。


## 一、漏洞核心：异常堆栈信息的敏感内容
Java 异常堆栈轨迹（通过 `Throwable.printStackTrace()`、`e.getMessage()` 或框架自动序列化异常返回）会包含以下敏感信息，均可能成为攻击突破口：
1. **代码结构信息**：类全限定名（如 `com.company.dao.UserDao`）、方法名（如 `queryUserByToken`）、行号（如 `UserDao.java:45`），直接暴露业务逻辑分层、核心接口、数据访问层位置；
2. **依赖组件信息**：第三方库类名（如 `org.springframework.jdbc.BadSqlGrammarException`、`com.mysql.cj.jdbc.exceptions.MySQLSyntaxErrorException`），泄露使用的框架（Spring/Spring Boot）、数据库（MySQL/Oracle）、中间件（Redis/MQ）及版本特征；
3. **运行时上下文**：参数值（如 `SQLException: Table 'user_2024' doesn't exist`）、配置信息（如 `ConnectException: Connection refused to host: 192.168.1.100; port: 3306`）、文件路径（如 `FileNotFoundException: /opt/app/config/db.properties`）；
4. **认证/授权线索**：如 `AccessDeniedException: User 'test' has no permission to access /admin/api`，泄露权限控制规则、用户名格式；
5. **JVM 环境信息**：如 `OutOfMemoryError: Java heap space` 泄露 JVM 内存配置，`ClassNotFoundException: com.company.secret.api.SecretService` 泄露未公开的内部服务。


## 二、漏洞触发的典型场景
异常堆栈泄露的核心诱因是「异常处理不当」或「框架默认行为未覆盖」，具体可分为以下几类场景：

### 场景1：直接打印/返回完整堆栈（最基础且高发）
开发人员为调试便利，直接将异常堆栈输出到前端、API 响应或公网可访问的日志中，是最常见的泄露方式。
#### 典型代码示例：
```java
// 场景1.1：接口层直接返回堆栈信息
@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        try {
            return userService.getUserById(id);
        } catch (Exception e) {
            // 直接将堆栈转为字符串返回给前端
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity.status(500).body(sw.toString()); // 前端可见完整堆栈
        }
    }
}

// 场景1.2：控制台打印（生产环境控制台暴露/日志被采集到公网）
public class OrderService {
    public void createOrder(Order order) {
        try {
            orderDao.insert(order);
        } catch (SQLException e) {
            e.printStackTrace(); // 生产环境控制台/日志中泄露数据库异常堆栈
        }
    }
}
```
#### 泄露结果：
前端页面/API 响应直接显示 `java.sql.SQLException: ...` + 完整类名、方法名、行号；日志文件中包含数据库连接信息、表名等敏感内容。

### 场景2：框架默认异常处理机制泄露
Spring、Spring Boot、Struts2 等主流框架默认的异常处理器会将未捕获的异常堆栈返回给客户端，开发人员未自定义异常处理逻辑时触发。
#### 典型场景：
- Spring Boot 应用未配置 `@ControllerAdvice`，当接口抛出 `NullPointerException`/`SQLSyntaxErrorException` 时，默认返回包含完整堆栈的 JSON/HTML 响应；
- Struts2 应用未配置 `exception-mapping`，异常时直接渲染包含堆栈的错误页面。
#### 泄露示例（HTTP 响应）：
```json
{
  "timestamp": "2025-12-06T10:00:00.000+00:00",
  "status": 500,
  "error": "Internal Server Error",
  "trace": "java.sql.SQLSyntaxErrorException: Unknown column 'user_token' in 'field list'\n\tat com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:120)\n\tat com.company.dao.UserDao.query(UserDao.java:78)\n\tat com.company.service.UserService.getUser(UserService.java:45)...",
  "message": "Unknown column 'user_token' in 'field list'",
  "path": "/user/1"
}
```

### 场景3：日志系统未过滤堆栈信息
日志组件（Log4j2、SLF4J/Logback）配置不当，将包含完整堆栈的异常信息输出到：
- 公网可访问的日志平台（如未授权的 ELK 集群）；
- 前端可查看的应用日志页面；
- 第三方日志服务（如未加密的云日志）。
#### 典型代码示例：
```java
// Logback/Log4j2 中直接记录完整堆栈
private static final Logger logger = LoggerFactory.getLogger(PayService.class);

public void pay(String orderId) {
    try {
        payDao.deductBalance(orderId);
    } catch (Exception e) {
        // 日志中记录完整堆栈（无过滤）
        logger.error("支付失败", e);
    }
}
```
#### 泄露结果：
日志文件中包含 `com.company.dao.PayDao.deductBalance(PayDao.java:99)`、`SQLException: Table 'pay_order_2024' lock wait timeout` 等信息，若日志被泄露，攻击者可分析支付核心逻辑、数据库表结构。

### 场景4：序列化/反序列化异常泄露
当异常对象被序列化（如跨进程通信、RPC 调用、缓存存储）时，堆栈信息随对象传输，若传输链路未加密或接收方未过滤，导致信息泄露：
#### 典型场景：
- Dubbo/gRPC 接口抛出异常时，堆栈信息随响应序列化返回给调用方（若调用方是外部系统）；
- 将异常对象存入 Redis/Memcached 缓存，缓存被未授权访问时泄露；
- 分布式追踪系统（如 SkyWalking、Zipkin）未脱敏，将异常堆栈作为追踪数据公开。

### 场景5：测试环境配置泄露到生产
开发/测试环境为调试开启了「完整异常显示」配置，上线时未关闭，导致生产环境泄露：
- Spring Boot：`server.error.include-stacktrace=always`（默认仅开发环境为 `always`，若生产环境手动配置则泄露）；
- Tomcat：`web.xml` 中 `error-page` 未配置，默认显示堆栈的错误页面；
- JSP 页面：`<%@ page isErrorPage="true" %>` 且页面中直接输出 `<%= exception.printStackTrace(new PrintWriter(out)) %>`。

### 场景6：自定义异常处理不彻底
开发人员仅捕获部分异常，未处理「异常链」（`Throwable.getCause()`），导致底层异常堆栈仍被泄露：
#### 典型代码示例：
```java
public void updateUser(User user) {
    try {
        userDao.update(user);
    } catch (RuntimeException e) {
        // 仅捕获外层异常，未处理底层 cause（如 SQLException）
        throw new BusinessException("更新失败：" + e.getMessage());
    }
}
```
#### 泄露结果：
若 `e.getMessage()` 包含底层 `SQLException` 的详细信息（如表名、字段名），或框架在处理 `BusinessException` 时仍会打印完整异常链堆栈，导致敏感信息泄露。

### 场景7：第三方组件/依赖的异常泄露
应用依赖的第三方库（如支付SDK、缓存客户端、ORM框架）抛出未封装的异常，开发人员未二次处理，导致堆栈泄露：
#### 典型场景：
- MyBatis 抛出 `PersistenceException`，底层包含 `MySQLIntegrityConstraintViolationException`（泄露唯一键约束名：`UK_user_mobile`）；
- Redis 客户端（Jedis/Lettuce）抛出 `RedisConnectionException`，泄露 Redis 地址（`redis://10.0.0.5:6379`）；
- OAuth2 客户端抛出 `InvalidTokenException`，泄露 token 校验逻辑、授权服务器地址。

### 场景8：命令行/容器日志泄露
Java 应用运行在容器（Docker/K8s）中时，`java -jar` 启动的应用若未重定向标准输出/错误，异常堆栈会被写入容器日志：
- `docker logs <容器ID>` 可直接查看完整堆栈；
- K8s `kubectl logs <pod名>` 暴露堆栈信息，若未配置日志权限控制，任意有权限的用户可查看。


## 三、漏洞的影响范围与危害
1. **信息收集**：攻击者通过堆栈中的类名、方法名、行号，绘制应用的业务逻辑图，定位核心接口（如支付、用户认证）；
2. **精准攻击**：利用泄露的数据库表名/字段名构造 SQL 注入攻击，利用 Redis 地址尝试未授权访问，利用依赖组件版本（如 Log4j2 2.14.1）发起已知漏洞攻击；
3. **合规风险**：违反《网络安全法》《数据安全法》中「敏感信息保护」要求，堆栈中的配置信息、用户数据相关上下文可能涉及个人信息泄露；
4. **业务逻辑泄露**：核心业务流程（如订单状态流转、权限校验规则）通过堆栈暴露，增加业务逻辑被绕过/仿冒的风险；
5. **内网信息泄露**：堆栈中的内网 IP（如数据库、Redis 地址）、文件路径（如 `/opt/app/config`），为攻击者突破内网边界提供线索。


## 四、漏洞的触发条件
1. 异常被触发（如参数错误、数据库连接失败、权限不足等）；
2. 异常未被「脱敏处理」（仅保留通用错误提示，移除堆栈、敏感上下文）；
3. 异常信息输出到「不可控渠道」（前端、公网日志、未授权的控制台/容器日志等）；
4. 输出渠道无访问控制（如日志页面无需登录、容器日志可被任意用户查看）。

该漏洞不依赖特定 Java 版本（JDK 6/8/11/17 均可能出现），核心诱因是「开发习惯」和「配置管理」问题，而非 Java 语言本身的缺陷。


