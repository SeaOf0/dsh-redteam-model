# Java 反射型CORS漏洞

> 规则 ID：`origin_alloworigin_cors` · 类别：cors · 关键 sink：setHeader
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java 反射型CORS漏洞
反射型CORS（Cross-Origin Resource Sharing，跨域资源共享）漏洞是一类因服务端动态生成CORS响应头时存在输入验证缺陷，且结合Java反射机制放大风险的跨域安全问题。其核心成因是：服务端未严格校验请求头中的`Origin`值，通过反射机制动态拼接/生成`Access-Control-Allow-Origin`等CORS响应头，导致恶意域名可被授权跨域访问敏感资源。以下从漏洞本质、触发条件、Java反射关联场景、不同变种情况、影响范围等维度完整描述。

## 一、CORS基础与反射型CORS核心原理
### 1. CORS正常流程
CORS是浏览器为解决跨域请求限制制定的规范，核心依赖服务端返回的响应头：
- `Access-Control-Allow-Origin`：指定允许跨域的源（如`https://example.com`或`*`）；
- `Access-Control-Allow-Credentials`：是否允许携带Cookie等凭证（值为`true`时，`Allow-Origin`不能为`*`）；
- `Access-Control-Allow-Methods`/`Allow-Headers`：允许的请求方法/请求头。

正常场景下，服务端应配置**白名单**，仅允许可信域名跨域，例如固定返回`Access-Control-Allow-Origin: https://trusted.com`。

### 2. 反射型CORS核心特征
反射型CORS的关键是：服务端将请求头中的`Origin`值**直接/间接反射**到`Access-Control-Allow-Origin`响应头中，且未做严格校验。例如：
```java
// 简单反射场景（无校验）
String origin = request.getHeader("Origin");
response.setHeader("Access-Control-Allow-Origin", origin);
response.setHeader("Access-Control-Allow-Credentials", "true");
```
此时攻击者构造恶意请求（如`Origin: https://attacker.com`），服务端会返回`Allow-Origin: https://attacker.com`，浏览器会认为该域名被授权，允许攻击者读取跨域响应数据。

### 3. Java反射机制的放大作用
Java反射并非漏洞直接成因，但会**降低校验逻辑的可控性**，或让攻击者通过反射绕过不严谨的校验规则，主要体现在：
- 反射动态获取/设置CORS相关响应头：开发者通过反射（如`HttpServletResponse.class.getMethod("setHeader", String.class, String.class)`）动态设置`Allow-Origin`，导致校验逻辑被绕开；
- 反射读取配置/白名单：若白名单存储在配置类中，攻击者可通过反射（如框架漏洞）篡改白名单，或反射调用校验方法时传入恶意`Origin`；
- 反射动态拼接响应头值：通过反射拼接`Allow-Origin`值（如拼接多个Origin），破坏原有校验逻辑。

## 二、反射型CORS漏洞的核心触发条件
需同时满足以下条件才具备可利用性：
1. **响应头反射**：`Access-Control-Allow-Origin`值与请求头`Origin`一致（反射）；
2. **凭证允许**：`Access-Control-Allow-Credentials: true`（无此头则仅能发起简单请求，无法读取敏感响应；有此头则可携带Cookie等凭证）；
3. **无有效校验**：服务端未对`Origin`做白名单校验，或校验逻辑存在缺陷；
4. **Java环境特性**：反射机制导致校验逻辑失效（如反射跳过校验、动态修改响应头）。

## 三、Java反射型CORS的不同变种场景
### 场景1：纯反射拼接响应头（无任何校验）
#### 特征
开发者通过Java反射动态获取`Origin`请求头，并直接设置到`Allow-Origin`，无任何白名单/格式校验，是最基础且高危的变种。

#### 代码示例
```java
@RequestMapping("/api/data")
public ResponseEntity<?> getSensitiveData(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // 反射获取Origin请求头
    Method getHeaderMethod = HttpServletRequest.class.getMethod("getHeader", String.class);
    String origin = (String) getHeaderMethod.invoke(request, "Origin");

    // 反射设置CORS响应头
    Method setHeaderMethod = HttpServletResponse.class.getMethod("setHeader", String.class, String.class);
    setHeaderMethod.invoke(response, "Access-Control-Allow-Origin", origin);
    setHeaderMethod.invoke(response, "Access-Control-Allow-Credentials", "true");

    return ResponseEntity.ok("敏感数据：用户token=xxx");
}
```
#### 风险
攻击者构造`Origin: https://attacker.com`的请求，服务端反射返回该Origin，浏览器允许攻击者的页面读取包含敏感数据的响应，结合Cookie可直接冒充用户操作。

### 场景2：反射绕过弱校验（后缀/前缀校验）
#### 特征
开发者虽添加了简单校验（如仅校验Origin是否以可信域名开头/结尾），但通过反射动态拼接Origin值，导致校验失效。

#### 代码示例
```java
// 白名单：仅允许example.com域名
private static final String ALLOWED_ORIGIN = "https://example.com";

@RequestMapping("/api/user")
public void getUserInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String origin = request.getHeader("Origin");

    // 弱校验：仅检查Origin是否包含example.com后缀
    if (origin != null && origin.endsWith(ALLOWED_ORIGIN)) {
        response.setHeader("Access-Control-Allow-Origin", origin);
    } else {
        // 反射动态拼接Origin，绕过校验
        Class<?> responseClass = response.getClass();
        Field headerField = responseClass.getDeclaredField("headers"); // 假设可反射获取响应头Map
        headerField.setAccessible(true);
        Map<String, String> headers = (Map<String, String>) headerField.get(response);
        // 拼接恶意Origin：https://attacker.example.com
        headers.put("Access-Control-Allow-Origin", origin);
    }
    response.setHeader("Access-Control-Allow-Credentials", "true");
}
```
#### 风险
攻击者构造`Origin: https://attacker.example.com`，虽满足“后缀为example.com”的弱校验，或通过反射直接修改响应头Map，绕过校验逻辑，实现跨域访问。

### 场景3：反射读取配置白名单，篡改校验逻辑
#### 特征
白名单存储在配置类中，开发者通过反射读取白名单，但未限制反射权限，导致攻击者（或内部恶意代码）通过反射篡改白名单，扩大允许的Origin范围。

#### 代码示例
```java
// 配置类：存储可信Origin白名单
@Component
public class CORSConfig {
    private Set<String> allowedOrigins = new HashSet<>(Arrays.asList("https://example.com", "https://admin.example.com"));

    // 反射可访问的get/set方法
    public Set<String> getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(Set<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }
}

// 业务接口
@RequestMapping("/api/admin")
public void adminApi(HttpServletRequest request, HttpServletResponse response) throws Exception {
    CORSConfig corsConfig = (CORSConfig) SpringContextUtil.getBean("CORSConfig");
    String origin = request.getHeader("Origin");

    // 反射读取白名单
    Method getMethod = CORSConfig.class.getMethod("getAllowedOrigins");
    Set<String> allowedOrigins = (Set<String>) getMethod.invoke(corsConfig);

    if (allowedOrigins.contains(origin)) {
        response.setHeader("Access-Control-Allow-Origin", origin);
        response.setHeader("Access-Control-Allow-Credentials", "true");
    }

    // 攻击者可通过反射调用setAllowedOrigins，添加恶意Origin
    // 示例：
    // Method setMethod = CORSConfig.class.getMethod("setAllowedOrigins", Set.class);
    // Set<String> newOrigins = new HashSet<>(Arrays.asList("https://attacker.com"));
    // setMethod.invoke(corsConfig, newOrigins);
}
```
#### 风险
若反射权限未限制（如未禁用`setAccessible(true)`），攻击者可通过反射调用`setAllowedOrigins`篡改白名单，添加恶意域名，实现持久化的跨域漏洞。

### 场景4：反射处理预检请求（OPTIONS），放大漏洞范围
#### 特征
CORS预检请求（OPTIONS方法）用于询问服务端是否允许跨域，若开发者通过反射处理预检请求的响应头，且未校验，会导致所有跨域请求都被允许。

#### 代码示例
```java
@RequestMapping(value = "/api/data", method = RequestMethod.OPTIONS)
public void handlePreflight(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // 反射获取所有请求头
    Method getHeaderNamesMethod = HttpServletRequest.class.getMethod("getHeaderNames");
    Enumeration<String> headerNames = (Enumeration<String>) getHeaderNamesMethod.invoke(request);

    // 反射设置预检响应头
    Method setHeaderMethod = HttpServletResponse.class.getMethod("setHeader", String.class, String.class);
    setHeaderMethod.invoke(response, "Access-Control-Allow-Origin", request.getHeader("Origin"));
    setHeaderMethod.invoke(response, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    setHeaderMethod.invoke(response, "Access-Control-Allow-Headers", "Authorization, Content-Type");
    setHeaderMethod.invoke(response, "Access-Control-Allow-Credentials", "true");
    setHeaderMethod.invoke(response, "Access-Control-Max-Age", "3600");
}
```
#### 风险
预检请求通过后，浏览器会允许后续的实际请求（如POST/PUT）跨域，攻击者可发起任意方法的跨域请求，修改用户数据（如转账、修改密码）。

### 场景5：框架层面的反射型CORS（如Spring MVC反射配置）
#### 特征
使用Spring等框架时，若通过反射动态配置CORS（如`CorsConfiguration`），且未限制Origin，会导致全局CORS漏洞。

#### 代码示例
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        try {
            // 反射获取CorsRegistration对象
            Method addMappingMethod = CorsRegistry.class.getMethod("addMapping", String.class);
            Object corsRegistration = addMappingMethod.invoke(registry, "/**");

            // 反射设置允许的Origin为请求头的值（动态反射）
            Method allowedOriginsMethod = corsRegistration.getClass().getMethod("allowedOrigins", String[].class);
            // 此处错误地将Origin设置为动态值（实际应为白名单）
            allowedOriginsMethod.invoke(corsRegistration, new String[]{request.getHeader("Origin")}); // 伪代码，实际需结合请求上下文

            Method allowCredentialsMethod = corsRegistration.getClass().getMethod("allowCredentials", boolean.class);
            allowCredentialsMethod.invoke(corsRegistration, true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
#### 风险
框架层面的CORS配置会作用于所有接口，导致整个应用的所有接口都存在反射型CORS漏洞，影响范围最大。

## 四、反射型CORS的特殊情况（易被忽略）
### 1. 空Origin/Null Origin反射
部分场景下，请求头`Origin`为空或为`null`，若服务端反射该值到`Allow-Origin`（如`Access-Control-Allow-Origin: null`），攻击者可构造`Origin: null`的请求（如通过`data:`/`file:`协议的页面），实现跨域访问。

### 2. 多Origin拼接反射
开发者试图支持多个可信Origin，通过反射拼接`Allow-Origin`值（如`Origin1, Origin2`），但浏览器仅识别第一个值，攻击者可构造包含恶意Origin的拼接值，实现反射。

### 3. 反射型CORS+CSRF结合
即使无`Allow-Credentials`头，反射型CORS仍可结合CSRF发起跨域请求（如GET请求窃取数据），若响应包含敏感信息（如JSON），攻击者可通过`<script>`标签或`fetch`读取。

### 4. Java反射权限配置不当
若JVM未限制反射权限（如未启用`SecurityManager`，或未禁止`setAccessible(true)`），攻击者可通过反射绕过所有自定义校验逻辑，直接修改响应头。

## 五、漏洞影响范围
1. **数据泄露**：攻击者可读取跨域响应中的敏感数据（如用户信息、token、交易记录）；
2. **权限提升**：结合Cookie凭证，冒充用户执行操作（如登录后台、转账）；
3. **数据篡改**：通过跨域POST/PUT请求修改数据（如修改用户密码、订单信息）；
4. **批量攻击**：反射型CORS可被自动化工具利用，攻击大量用户；
5. **内网渗透**：若服务端允许内网域名反射，攻击者可通过跨域访问内网接口，获取内网信息。

## 六、反射型CORS与普通CORS漏洞的区别
| 维度                | 普通反射型CORS                | Java反射型CORS                |
|---------------------|-------------------------------|-------------------------------|
| 响应头设置方式      | 直接调用`setHeader`           | 通过反射动态设置/修改响应头   |
| 校验绕过方式        | 弱校验（如后缀匹配）          | 反射篡改校验逻辑/白名单       |
| 影响范围            | 单个接口                      | 可通过反射扩展到全局接口      |
| 修复难度            | 简单添加白名单即可            | 需限制反射权限+修复校验逻辑   |

综上，Java反射型CORS漏洞的核心是“反射机制放大了CORS配置的不严谨性”，其本质仍是CORS响应头的输入验证缺陷，但反射让校验逻辑更易被绕过，且影响范围更广，是Java应用中跨域安全的高频风险点。

