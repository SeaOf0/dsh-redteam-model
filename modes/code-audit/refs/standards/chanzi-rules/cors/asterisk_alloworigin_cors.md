# Java 语言中“允许任意地址CORS”漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`asterisk_alloworigin_cors` · 类别：cors · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java 语言中“允许任意地址CORS”漏洞

跨域资源共享（CORS）是浏览器实现的一种安全机制，用于限制网页从不同域名/协议/端口请求资源。Java 应用中“允许任意地址CORS”漏洞，核心是**服务器端配置的CORS响应头允许所有来源（`*`）访问资源，且未对请求方法、凭据等关键参数做严格限制**，导致恶意网站可跨域窃取用户敏感数据、执行未授权操作。以下从漏洞本质、触发场景、不同Java技术栈的表现形式、漏洞触发条件、危害场景等维度完整描述：

#### 一、漏洞本质
CORS漏洞的核心是服务器返回的`Access-Control-Allow-Origin`头配置不当：
- 合规配置：仅允许可信域名（如`https://trusted.com`），且按需限制`Access-Control-Allow-Methods`（允许的请求方法）、`Access-Control-Allow-Credentials`（是否允许携带Cookie/令牌）等头；
- 漏洞配置：`Access-Control-Allow-Origin: *`（允许任意来源），且常伴随`Access-Control-Allow-Credentials: true`（允许携带凭据），或`Access-Control-Allow-Methods: *`（允许任意请求方法），突破浏览器的跨域限制。

#### 二、Java 中触发该漏洞的核心场景
Java 应用实现CORS的方式主要分为“原生Servlet配置”“框架封装配置”“第三方组件配置”三类，每类均存在触发漏洞的典型情况：

### 场景1：原生Servlet/Jakarta Servlet 配置（无框架）
Java 原生通过`HttpServletResponse`手动设置CORS头，是最基础的实现方式，漏洞常出现在头参数的硬编码或动态拼接错误：
#### 情况1.1：硬编码允许所有来源
开发者直接设置`Access-Control-Allow-Origin: *`，未做任何来源校验：
```java
// 漏洞代码示例
protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    // 允许任意来源
    response.setHeader("Access-Control-Allow-Origin", "*");
    // 允许任意请求方法
    response.setHeader("Access-Control-Allow-Methods", "*");
    // 允许携带凭据（与*同时存在时，部分浏览器会拦截，但配置本身已违规）
    response.setHeader("Access-Control-Allow-Credentials", "true");
    // 允许所有自定义头
    response.setHeader("Access-Control-Allow-Headers", "*");
    // 其他业务逻辑...
}
```
#### 情况1.2：动态拼接Origin头但未校验
开发者试图“动态允许请求来源”，但未对`Origin`请求头做白名单校验，直接将请求头的值返回：
```java
// 漏洞代码示例
protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
    // 获取请求的Origin头（如恶意域名https://malicious.com）
    String origin = request.getHeader("Origin");
    // 直接返回该Origin，等同于允许任意来源（无白名单校验）
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Credentials", "true");
    // 其他配置...
}
```
#### 情况1.3：过滤器（Filter）全局配置不当
通过`Filter`统一处理CORS，但过滤器中配置了全局允许所有来源：
```java
public class CorsFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        HttpServletResponse response = (HttpServletResponse) res;
        // 全局允许任意来源
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        chain.doFilter(req, res);
    }
}
```
- 触发条件：过滤器映射到所有URL（`/*`），且未针对不同接口做精细化控制。

### 场景2：Spring Framework（Spring MVC/Spring Boot）配置
Spring 提供了多种CORS配置方式，漏洞主要出现在“全局放行”“注解滥用”“配置类参数错误”：
#### 情况2.1：@CrossOrigin 注解无限制
开发者在Controller/方法上添加`@CrossOrigin`但未指定`origins`，默认允许所有来源：
```java
// 漏洞代码示例：未指定origins，允许任意来源
@RestController
@RequestMapping("/api")
@CrossOrigin // 等价于@CrossOrigin(origins = "*")
public class UserController {
    @GetMapping("/user")
    public User getUser() {
        // 返回用户敏感数据
        return userService.getCurrentUser();
    }
}
```
- 补充：即使指定`methods`，但`origins = "*"`仍存在漏洞；若同时设置`allowCredentials = true`，则漏洞风险更高（浏览器虽禁止`*`与`true`共存，但部分框架实现可能绕过）。

#### 情况2.2：全局CORS配置放行所有来源
通过`WebMvcConfigurer`或`CorsConfigurationSource`配置全局CORS，参数设置不当：
```java
// Spring Boot 全局配置漏洞示例
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 所有接口
                .allowedOrigins("*") // 任意来源
                .allowedMethods("*") // 任意方法
                .allowedHeaders("*") // 任意请求头
                .allowCredentials(true); // 允许携带凭据（违规组合）
    }
}
```
- 注意：Spring Boot 2.4+ 中`allowedOrigins("*")`与`allowCredentials(true)`组合会抛出异常，但低版本（如2.1.x）可能未校验，仍会生效。

#### 情况2.3：Spring Security 集成时CORS配置疏漏
Spring Security 中未正确过滤CORS预检请求（OPTIONS），或放行所有来源：
```java
// 漏洞代码示例：Spring Security 配置
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors().and() // 启用CORS，但依赖全局配置
            .authorizeRequests()
                .anyRequest().permitAll() // 所有请求放行
                .and()
            .csrf().disable(); // 关闭CSRF（进一步放大CORS漏洞危害）
        return http.build();
    }

    // 全局CORS配置仍为允许所有来源
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Collections.singletonList("*"));
        config.setAllowedMethods(Collections.singletonList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

### 场景3：JAX-RS 框架（Jersey/RESTEasy）配置
JAX-RS 是Java RESTful标准，漏洞主要出现在`@CrossOrigin`注解或`CorsFilter`配置：
#### 情况3.1：Jersey 中 CorsFilter 允许所有来源
```java
// Jersey 配置漏洞示例
public class JerseyConfig extends ResourceConfig {
    public JerseyConfig() {
        // 注册CORS过滤器
        register(CorsFilter.class);
        // 设置允许所有来源
        property(CorsFilter.CORS_ALLOW_ORIGIN, "*");
        property(CorsFilter.CORS_ALLOW_METHODS, "*");
        property(CorsFilter.CORS_ALLOW_CREDENTIALS, "true");
    }
}
```
#### 情况3.2：RESTEasy 中 @CrossOrigin 注解滥用
```java
// RESTEasy 漏洞代码示例
@Path("/user")
@CrossOrigin(origins = "*", allowCredentials = true)
public class UserResource {
    @GET
    public Response getUser() {
        return Response.ok(userData).build();
    }
}
```

### 场景4：第三方组件/中间件导致的间接漏洞
部分Java中间件、开源组件默认开启宽松的CORS配置，开发者未修改默认值：
#### 情况4.1：Tomcat 全局CORS配置
Tomcat 通过`web.xml`配置CORS Valve，默认允许所有来源：
```xml
<!-- Tomcat web.xml 漏洞配置 -->
<valve>
    <class-name>org.apache.catalina.valves.CorsValve</class-name>
    <param-name>allowedOrigins</param-name>
    <param-value>*</param-value>
    <param-name>allowedMethods</param-name>
    <param-value>GET,POST,PUT,DELETE,OPTIONS</param-value>
    <param-name>allowCredentials</param-name>
    <param-value>true</param-value>
</valve>
```
#### 情况4.2：开源框架/组件的默认CORS配置
如Swagger UI、Actuator（Spring Boot）、Elasticsearch Java Client 等组件，若未关闭默认CORS，或默认配置为`*`：
- 示例：Spring Boot Actuator 未做权限控制时，`/actuator/**`接口允许任意来源访问，可泄露应用监控数据。

### 三、漏洞触发的前置条件
1. **浏览器端**：请求为“跨域请求”（协议/域名/端口任意一个不同），且请求类型为“非简单请求”（需预检OPTIONS请求）；
2. **服务器端**：
   - 返回`Access-Control-Allow-Origin: *` 或动态返回请求的`Origin`头（无白名单）；
   - 可选：同时返回`Access-Control-Allow-Credentials: true`（放大危害，可窃取Cookie/Token）；
   - 可选：`Access-Control-Expose-Headers`返回敏感响应头（如`Authorization`）。

### 四、漏洞的典型危害场景
1. **敏感数据窃取**：恶意网站通过跨域请求获取用户的个人信息、令牌、Cookie等；
   - 示例：用户登录可信网站`https://bank.com`后，访问恶意网站`https://mal.com`，后者通过AJAX请求`https://bank.com/api/user`，因CORS允许任意来源，可窃取用户账户信息。
2. **未授权操作**：恶意网站跨域发送POST/PUT/DELETE请求，执行敏感操作（如转账、修改密码）；
   - 示例：`https://mal.com`发送跨域POST请求到`https://bank.com/api/transfer`，因CORS放行，可在用户不知情下完成转账。
3. **CSRF 绕过**：传统CSRF依赖浏览器自动携带Cookie，但需伪造表单；CORS漏洞允许恶意网站直接读取响应，攻击更精准。
4. **接口枚举与信息泄露**：恶意攻击者枚举所有接口，通过跨域请求获取接口返回内容，梳理应用逻辑。

### 五、特殊情况：看似“限制”实则仍存在漏洞的场景
1. **通配符滥用**：配置`allowedOrigins = "*.example.com"`，但未限制子域名深度，导致`mal.example.com`等恶意子域名可访问；
2. **Origin 校验逻辑错误**：开发者试图校验Origin，但逻辑漏洞导致绕过（如仅校验“包含example.com”，则`example.com.attacker.com`可绕过）；
3. **预检请求（OPTIONS）未校验**：仅对GET/POST请求校验Origin，OPTIONS请求直接放行，导致非简单请求（如PUT）可跨域执行；
4. **多域名配置疏漏**：配置了白名单，但同时保留`*`作为兜底（如`allowedOrigins = {"https://trusted.com", "*"}`），仍允许任意来源。

### 六、漏洞的边界特征
1. **跨域类型**：支持所有跨域场景（跨域名、跨协议、跨端口）；
2. **请求方法**：简单请求（GET/POST/HEAD）和非简单请求（PUT/DELETE/PATCH）均被允许；
3. **凭据携带**：若配置`allowCredentials = true`，则恶意网站可携带用户的Cookie/Token发起请求；
4. **响应头暴露**：若配置`Access-Control-Expose-Headers: *`，则恶意网站可读取所有响应头（如`Set-Cookie`、`Authorization`）。

综上，Java 中“允许任意地址CORS”漏洞的核心是**来源校验缺失/宽松**，且不同技术栈的配置方式虽有差异，但本质都是服务器端未对跨域请求的来源做严格限制，导致浏览器的跨域安全机制失效，最终引发数据泄露或未授权操作。


