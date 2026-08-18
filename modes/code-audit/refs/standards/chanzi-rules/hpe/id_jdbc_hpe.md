# Java 语言水平越权漏洞

> 规则 ID：`id_jdbc_hpe` · 类别：hpe · 关键 sink：PreparedStatement, Statement, executeQuery
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java 语言水平越权漏洞
水平越权（Horizontal Privilege Escalation）是权限控制漏洞中最常见的类型之一，核心特征是**同一权限等级的用户（如普通用户A和普通用户B）能够非法访问/操作其他同级别用户的资源**，本质是系统未对用户的“资源归属权”做严格校验，仅依赖前端传参、会话弱校验等不可信数据判定资源访问权限。

Java 作为企业级应用的主流开发语言，水平越权漏洞的触发场景与 Java 生态的技术栈（如 Servlet、Spring MVC、MyBatis、JPA 等）深度绑定，以下按“核心原理+典型场景+代码示例+触发条件”完整拆解所有常见情况：

---

## 一、水平越权的核心本质
Java 应用中，水平越权的根因可归纳为：
1. **身份标识与资源归属解耦**：系统仅验证用户“已登录”（如 Session 存在、Token 有效），但未验证“当前用户是否为资源的合法所有者”；
2. **依赖不可信输入**：通过前端传递的 `userId`、`orderId`、`fileId` 等参数直接作为数据库查询/业务操作的条件，未与当前登录用户的唯一标识（如登录态中的 `uid`）做关联校验；
3. **权限校验逻辑位置错误**：校验逻辑仅在前端（如隐藏按钮、前端路由拦截）或未覆盖全链路（如仅接口入口校验，内部服务调用时跳过校验）。

---

## 二、Java 中水平越权的典型场景（按技术维度分类）
### 场景1：基于 Session 的传统 Web 应用（Servlet/JSP）水平越权
#### 核心特征
基于 `HttpSession` 存储用户身份，但业务逻辑中直接使用请求参数（如 `request.getParameter("userId")`）作为资源查询条件，未与 `Session` 中的用户标识比对。

#### 代码示例（漏洞代码）
```java
// Servlet 处理用户订单查询接口
@WebServlet("/order/query")
public class OrderQueryServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // 仅验证用户已登录（会话存在），未校验资源归属
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("loginUser") == null) {
            response.sendRedirect("/login");
            return;
        }

        // 直接从请求参数获取要查询的订单ID和用户ID（不可信输入）
        String orderId = request.getParameter("orderId");
        String userId = request.getParameter("userId"); // 前端传参，可被篡改

        // 直接查询该userId的orderId，未关联Session中的真实用户ID
        OrderDao orderDao = new OrderDao();
        Order order = orderDao.getOrderByIdAndUserId(orderId, userId);

        // 返回订单数据（若篡改userId为其他用户，可查询到他人订单）
        response.getWriter().write(JSON.toJSONString(order));
    }
}

// DAO层代码
public class OrderDao {
    public Order getOrderByIdAndUserId(String orderId, String userId) {
        Connection conn = DBUtil.getConnection();
        String sql = "SELECT * FROM t_order WHERE id = ? AND user_id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, orderId);
        pstmt.setString(2, userId); // 直接使用前端传入的userId
        ResultSet rs = pstmt.executeQuery();
        // 封装订单数据...
        return order;
    }
}
```

#### 触发条件
1. 攻击者登录自己的账号（获取合法 Session）；
2. 篡改请求参数中的 `userId` 为其他用户ID（如从 `1001` 改为 `1002`）；
3. 系统未校验 `userId` 是否与 Session 中的 `loginUser.getId()` 一致，直接返回他人订单数据。

#### 变种情况
- 仅校验 `orderId` 存在，未关联 `userId`（如 `SELECT * FROM t_order WHERE id = ?`）；
- Session 中存储的用户标识可被伪造/篡改（如 SessionID 未做安全配置，或用户ID明文存储在 Cookie 中）。

---

### 场景2：Spring MVC/Spring Boot 接口水平越权（最常见）
#### 子场景2.1：PathVariable 传参未校验归属
通过 URL 路径参数传递资源ID（如 `/user/{userId}/info`），未校验路径中的 `userId` 与当前登录用户ID一致。

##### 漏洞代码
```java
// Spring Boot 接口
@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;

    // 获取用户个人信息接口
    @GetMapping("/{userId}/info")
    public ResponseEntity<UserVO> getUserInfo(@PathVariable String userId, HttpServletRequest request) {
        // 仅验证登录态，未校验路径中的userId是否为当前用户ID
        String loginUserId = (String) request.getAttribute("loginUserId"); // 从拦截器存入的登录用户ID
        if (loginUserId == null) {
            return ResponseEntity.status(401).build();
        }

        // 直接查询传入的userId的信息，未做归属校验
        UserVO userVO = userService.getUserById(userId);
        return ResponseEntity.ok(userVO);
    }
}
```

##### 触发条件
攻击者登录后，访问 `/user/1002/info`（将路径中的 `userId` 改为其他用户ID），即可获取他人信息。

#### 子场景2.2：RequestParam 传参未校验归属
通过 URL 入参（如 `/order/query?orderId=123&userId=1001`）传递资源关联ID，未与登录用户ID比对。

##### 漏洞代码
```java
@RestController
@RequestMapping("/order")
public class OrderController {
    @Autowired
    private OrderService orderService;

    @GetMapping("/query")
    public ResponseEntity<OrderVO> queryOrder(
            @RequestParam String orderId,
            @RequestParam(required = false) String userId,
            @LoginUser String loginUserId) { // 自定义注解获取登录用户ID

        // 若前端未传userId，则直接使用orderId查询（未关联用户）；若传了userId，未校验是否等于loginUserId
        OrderVO orderVO;
        if (userId != null) {
            orderVO = orderService.getOrderByOrderIdAndUserId(orderId, userId);
        } else {
            orderVO = orderService.getOrderByOrderId(orderId); // 仅查orderId，未关联用户
        }
        return ResponseEntity.ok(orderVO);
    }
}
```

#### 子场景2.3：JSON 请求体传参未校验归属
通过 POST/PUT 请求的 JSON 体传递资源关联信息（如修改订单归属、查询他人数据），未校验请求体中的用户ID与登录用户一致。

##### 漏洞代码
```java
// 修改订单收货地址接口
@PutMapping("/order/updateAddress")
public ResponseEntity<Void> updateOrderAddress(@RequestBody OrderAddressDTO dto, @LoginUser String loginUserId) {
    // 仅验证登录，未校验dto中的orderId是否属于loginUserId
    orderService.updateAddress(dto.getOrderId(), dto.getAddress());
    return ResponseEntity.ok().build();
}

// Service层
@Service
public class OrderService {
    @Transactional
    public void updateAddress(String orderId, String address) {
        // 直接更新订单地址，未校验订单归属
        String sql = "UPDATE t_order SET address = ? WHERE id = ?";
        jdbcTemplate.update(sql, address, orderId);
    }
}
```

##### 触发条件
攻击者构造 JSON 请求体，将 `orderId` 改为其他用户的订单ID，即可修改他人订单的收货地址。

---

### 场景3：MyBatis/ORM 层查询条件缺失归属校验
即使业务层有初步校验，但若 DAO/ORM 层的查询条件未强制关联当前用户ID，仍可能触发水平越权（如业务层校验被绕过、或批量操作时遗漏）。

#### 子场景3.1：MyBatis XML 映射文件未加用户ID条件
##### 漏洞代码（Mapper XML）
```xml
<!-- 查询用户订单列表 -->
<select id="listOrderByUserId" resultType="com.example.entity.Order">
    SELECT * FROM t_order
    WHERE user_id = #{userId} <!-- 依赖业务层传入的userId，若业务层传错则越权 -->
    AND status = #{status}
</select>
```
##### 风险点
若业务层误将前端传入的 `userId` 直接传入（而非登录用户ID），或批量查询时未传入 `userId`（如 XML 中 `user_id = #{userId}` 改为 `1=1`），则可查询所有用户的订单。

#### 子场景3.2：JPA/Hibernate 动态查询未关联用户ID
##### 漏洞代码
```java
@Repository
public interface OrderRepository extends JpaRepository<Order, String> {
    // 仅按订单状态查询，未关联用户ID
    List<Order> findByStatus(Integer status);
}

// Service层
@Service
public class OrderService {
    @Autowired
    private OrderRepository orderRepository;

    public List<OrderVO> listOrderByStatus(Integer status) {
        // 直接查询所有该状态的订单，未关联当前用户
        List<Order> orders = orderRepository.findByStatus(status);
        return orders.stream().map(this::convertToVO).collect(Collectors.toList());
    }
}
```
##### 触发条件
攻击者调用接口后，可获取系统中所有该状态的订单（如所有待付款订单），而非仅自己的订单。

---

### 场景4：批量操作/导出接口水平越权
批量查询、导出、删除等接口中，未对批量传入的资源ID做归属校验，导致可操作他人资源。

#### 漏洞代码
```java
// 批量导出订单接口
@PostMapping("/order/batch/export")
public ResponseEntity<byte[]> batchExportOrder(
        @RequestBody List<String> orderIds,
        @LoginUser String loginUserId) {
    // 仅验证登录，未校验所有orderIds是否属于loginUserId
    List<Order> orders = orderService.listOrderByIds(orderIds);
    // 导出订单数据为Excel
    byte[] excelBytes = excelExportService.exportOrder(orders);
    return ResponseEntity.ok(excelBytes);
}

// Service层
public List<Order> listOrderByIds(List<String> orderIds) {
    return orderRepository.findByIdIn(orderIds); // 仅按ID查询，未关联用户ID
}
```

#### 触发条件
攻击者传入多个他人的 `orderIds`，即可导出所有传入ID的订单数据，而非仅自己的。

---

### 场景5：内部服务调用/微服务场景下的水平越权
微服务架构中，服务间调用（如 Feign、Dubbo）时未传递/校验用户身份，导致下游服务直接基于传入的资源ID返回数据。

#### 漏洞代码（微服务示例）
```java
// 订单服务（下游服务）
@RestController
@RequestMapping("/inner/order")
public class InnerOrderController {
    // 供用户服务调用的内部接口，未校验用户归属
    @PostMapping("/queryByIds")
    public List<Order> queryOrderByIds(@RequestBody List<String> orderIds) {
        // 仅按ID查询，未关联用户ID
        return orderRepository.findByIdIn(orderIds);
    }
}

// 用户服务（上游服务）
@Service
public class UserService {
    @Autowired
    private OrderFeignClient orderFeignClient;

    public List<OrderVO> getUserOrder(String userId) {
        // 直接调用下游接口，传入前端/业务层的userId对应的orderIds（未校验userId是否为登录用户）
        List<String> orderIds = orderRelationRepository.listOrderIdByUserId(userId);
        List<Order> orders = orderFeignClient.queryOrderByIds(orderIds);
        return convertToVO(orders);
    }
}
```

#### 风险点
1. 上游服务若传入篡改后的 `userId`，下游服务未做二次校验，直接返回该 `userId` 关联的所有订单；
2. 内部接口未做权限控制（如未校验调用方身份、未传递登录用户ID）。

---

### 场景6：文件/附件/媒体资源水平越权
Java 应用中文件上传/下载接口未校验文件归属，导致可下载/修改他人上传的文件。

#### 漏洞代码
```java
// 文件下载接口
@GetMapping("/file/download")
public ResponseEntity<Resource> downloadFile(@RequestParam String fileId, HttpServletRequest request) {
    // 仅验证登录，未校验fileId是否属于当前用户
    String loginUserId = (String) request.getAttribute("loginUserId");
    if (loginUserId == null) {
        return ResponseEntity.status(401).build();
    }

    // 直接查询文件信息，未关联用户ID
    FileInfo fileInfo = fileService.getFileById(fileId);
    Resource resource = new FileSystemResource(fileInfo.getFilePath());
    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + fileInfo.getFileName())
            .body(resource);
}
```

#### 触发条件
攻击者篡改 `fileId` 为其他用户上传的文件ID，即可下载他人的敏感文件（如身份证照片、合同等）。

---

### 场景7：缓存/会话共享场景下的水平越权
缓存（如 Redis）中存储的用户资源未按用户ID隔离，导致可获取他人缓存数据。

#### 漏洞代码
```java
@Service
public class UserCacheService {
    @Autowired
    private RedisTemplate<String, UserVO> redisTemplate;

    public UserVO getUserInfoFromCache(String userId) {
        // 缓存Key仅用userId，未做隔离校验
        String cacheKey = "user:info:" + userId;
        UserVO userVO = redisTemplate.opsForValue().get(cacheKey);
        if (userVO == null) {
            userVO = userService.getUserById(userId);
            redisTemplate.opsForValue().set(cacheKey, userVO, 1, TimeUnit.HOURS);
        }
        return userVO;
    }
}

// Controller层
@GetMapping("/user/info")
public UserVO getUserInfo(@RequestParam String userId, @LoginUser String loginUserId) {
    // 未校验userId == loginUserId，直接查询缓存
    return userCacheService.getUserInfoFromCache(userId);
}
```

#### 风险点
1. 缓存Key可被预测（如 `user:info:1001`），攻击者构造其他用户的缓存Key即可获取数据；
2. 分布式会话共享中，会话数据未做用户隔离（如 Redis 中存储的 `order_list` 未关联用户ID）。

---

### 场景8：权限框架配置不当导致的水平越权
使用 Spring Security、Shiro 等权限框架时，仅配置了“角色/权限”校验，未配置“资源归属”校验。

#### 漏洞代码（Spring Security 示例）
```java
// Spring Security 配置
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 仅校验ROLE_USER角色，未校验资源归属
                .antMatchers("/user/**").hasRole("USER")
                .anyRequest().authenticated();
    }
}

// Controller层
@GetMapping("/user/{userId}/info")
@PreAuthorize("hasRole('USER')") // 仅校验角色，未校验userId归属
public UserVO getUserInfo(@PathVariable String userId) {
    return userService.getUserById(userId);
}
```

#### 风险点
权限框架仅验证“用户有访问该接口的权限”，但未验证“用户有访问该接口下特定资源的权限”。

---

## 三、水平越权的隐蔽场景（易被忽略）
1. **分页/排序接口越权**：分页查询接口（如 `/order/list?page=1&size=10`）未加用户ID条件，返回所有用户的订单列表；
2. **日志/调试接口越权**：调试接口（如 `/debug/query?sql=SELECT * FROM t_user WHERE id=?`）未校验传入的ID归属；
3. **第三方集成接口越权**：对接第三方的接口（如支付回调、物流查询）未校验回调参数中的资源归属；
4. **异步任务/定时任务越权**：异步处理任务（如消息队列消费）时，未校验消息中的资源归属，导致处理他人数据；
5. **多租户场景下的租户内越权**：SaaS 系统中，仅校验租户ID（TenantID），未校验租户内的用户ID归属，导致租户内用户越权访问同租户其他用户资源。

---

## 四、水平越权的触发路径总结
所有 Java 水平越权漏洞的触发路径可归纳为：
```
用户登录（获取合法身份）→ 构造恶意请求（篡改资源ID/用户ID参数）→ 接口未校验资源归属 → 系统返回/操作非本人资源
```

## 五、关键特征识别
1. 接口仅验证“登录态”，未验证“资源归属”；
2. 资源查询/操作的 SQL/NoSQL 语句中，缺失“当前用户ID”作为查询条件；
3. 前端传入的用户ID/资源ID直接作为业务逻辑的核心参数，未与登录态中的用户标识做比对；
4. 批量操作、内部接口、缓存查询等非前端直接调用的链路中，未做归属校验。

以上覆盖了 Java 语言中水平越权漏洞的所有核心场景、变种情况及触发条件，未包含修复建议，仅聚焦漏洞本身的特征与表现形式。

