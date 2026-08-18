---
name: java-unauth-rce
description: Java 未授权 RCE 危险接口清单。Spring Boot actuator（heapdump/env/jolokia/restart 端点风险映射）、JMX 未授权（MBean→RCE）、RMI 未授权（反序列化）、远程 debug 未授权（JDWP）。每个接口给出「鉴权缺失判定 + 是否直达命令执行/反序列化/上传」的直达 RCE 判定清单。
---

# Java 未授权 RCE 危险接口清单（java-unauth-rce）

> 红线②「未授权 RCE」的 Java 落地：危险接口的鉴权是否缺失或可绕过 → 接口是否**直达**
> 命令执行/反序列化/上传。与 `java-auth-audit.md`（Filter 层/登录检查/越权）互补——
> 那篇管「应用自己的鉴权链」，本篇管「框架/运行时自带的管理与调试接口」。

## 0. 直达 RCE 判定总则

对每个暴露接口回答两个问题：
1. **鉴权**：默认是否开启认证？缺失/可绕过吗？（管理端点、调试端口常默认开放）
2. **直达能力**：接口是否直达以下三类危险原语之一？
   - **命令执行**（JMX MBean 调用、Jolokia、heapdump→凭据→登录→RCE）
   - **反序列化**（RMI、JMX 基于序列化的传输）
   - **上传/写**（restart/logger 写、JMX 内存马注入）

两问皆「是」→ 未授权 RCE 高危，直接进 P0 深审。

---

## 1. Spring Boot Actuator 未授权

### 1.1 端点清单与风险映射

| 端点 | 默认是否暴露 | 直达能力 | 风险 |
|------|--------------|----------|------|
| `/actuator/health` | 是 | 只读 | 低（但可能泄露组件版本） |
| `/actuator/info` | 是 | 只读 | 低 |
| `/actuator/env` | 否（默认关闭，但常被 `*` 全开） | 读环境变量 | **严重**：泄露 DB 密码/API Key/配置 |
| `/actuator/heapdump` | 否 | 下载 JVM 堆转储 | **严重**：提取内存中明文凭据 → 登录 → RCE |
| `/actuator/configprops` | 否 | 读配置属性 | **高**：含敏感值 |
| `/actuator/mappings` | 否 | 读路由映射 | **中**：泄露攻击面 |
| `/actuator/beans` | 否 | 读 Spring Bean | **中**：泄露组件与类路径 |
| `/actuator/trace` / `httptrace` | 否 | 读请求追踪 | **高**：含 Session/Cookie/Header |
| `/actuator/jolokia` | 否（需 jolokia 依赖） | **JMX 代理 → MBean 调用 → RCE** | **严重**：直达命令执行 |
| `/actuator/restart` / `shutdown` | 否 | 重启/关闭应用 | **高**：DoS/配合写文件触发加载 |
| `/actuator/loggers` | 否 | 改日志级别 | **中**：日志注入面 |

### 1.2 配置判据（源码侧）

```yaml
# ❌ 危险：所有端点暴露 + 无鉴权
management:
  endpoints:
    web:
      exposure:
        include: "*"          # env/heapdump/jolokia 全开
      # 未配置 exposure.exclude
  # 未接入 Spring Security 保护 actuator

# ✅ 安全
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
      base-path: /actuator-内部路径
  endpoint:
    env.enabled: false
    heapdump.enabled: false
    configprops.enabled: false
  server:
    address: 127.0.0.1       # 仅本地
```

### 1.3 heapdump 泄露 → 凭据 → RCE 链

```
GET /actuator/heapdump → 下载 .hprof 堆转储
  → 用 MAT / jhat / heapdump_tool 检索明文密码、JWT、Session、密钥
    → 用泄露凭据登录管理面 / SSH / 数据库
      → RCE / 数据泄露
```

### 1.4 审计 grep

```bash
grep -rn 'management.endpoints.web.exposure\|include.*\*\|actuator\|jolokia\|heapdump\|env.enabled' --include='*.yml' --include='*.yaml' --include='*.properties' .
grep -rn 'spring-boot-actuator\|jolokia' pom.xml build.gradle
```

---

## 2. JMX 未授权（MBean → RCE）

### 2.1 直达判定

- **入口**：`java.rmi.server.hostname`/`com.sun.management.jmxremote` 开启远程 JMX，
  端口默认 1099（RMI registry）+ 随机连接端口；无认证（未设 `-Dcom.sun.management.jmxremote.authenticate=true`
  或未配 password/access 文件）即未授权。
- **直达能力**：远程调用 MBean（`javax.management.loading.MLet` 加载远程类、
  `getMBeanServerInfo`、任意 MBean 操作）→ **直接 RCE**（MLet 从攻击者 URL 加载恶意类）。

### 2.2 判据

```bash
# 启动参数判据（无 authenticate=true 或未配口令 = 未授权）
ps aux | grep -E 'jmxremote|management.jmxremote'
# 关键：-Dcom.sun.management.jmxremote.port=PORT  + 缺 authenticate/ssl 配置

# 源码/部署脚本核对
grep -rn 'jmxremote\|MBeanServer\|MLet\|JMXConnectorServer' --include='*.java' --include='*.sh' --include='*.conf' .
```

### 2.3 修复

- 强制 `-Dcom.sun.management.jmxremote.authenticate=true` + `password.properties`（权限 600）
  + `-Dcom.sun.management.jmxremote.ssl=true`；
- 用 `-Dcom.sun.management.jmxremote.local.only=true` 或防火墙限源。

---

## 3. RMI 未授权（反序列化）

### 3.1 直达判定

- **入口**：暴露的 RMI 远程对象（`UnicastRemoteObject` 导出、RMI registry 1099），
  无认证即可 `lookup` + `invoke`。
- **直达能力**：RMI 方法参数经 Java 原生序列化传输 → 服务端反序列化不可信参数 →
  **反序列化 RCE**（配合 classpath gadget 链，见 `java-deser-gadget-chains.md`）。
  攻击手法：`ysoserial JRMPClient`（回连攻击者 JRMPListener 二次反序列化）。

### 3.2 判据

```bash
# 源码核对
grep -rn 'UnicastRemoteObject\|Registry.bind\|Naming.rebind\|LocateRegistry\|RMI\|rmi://' --include='*.java' .
# 依赖核对
mvn dependency:tree | grep -iE 'commons-collections|commons-beanutils'
```

### 3.3 修复

- RMI 出口加认证/防火墙限源；JEP 290 反序列化过滤器（`jdk.serialFilter`）；
- 移除 classpath 中 gadget 依赖；迁移到无原生序列化的 RPC（gRPC/HTTP+JSON）。

---

## 4. 远程 debug 未授权（JDWP）

### 4.1 直达判定

- **入口**：JVM 启动参数 `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:PORT`
  开启远程调试端口（JDWP）。
- **直达能力**：JDWP 允许任意代码执行（`jdb`/`jdwp-shellifier` 执行任意 Java 代码）→
  **直接 RCE**，无需认证（JDWP 协议本身无认证机制）。

### 4.2 判据

```bash
ps aux | grep -E 'jdwp|agentlib|transport=dt_socket'
grep -rn 'jdwp\|agentlib\|dt_socket\|address=.*:.*server=y' --include='*.sh' --include='*.conf' --include='*.xml' .
```

### 4.3 修复

- 生产环境禁用远程 debug（`address=localhost:PORT` 或完全移除）；
- 必须保留时用 SSH 隧道/防火墙限源。

---

## 5. 直达 RCE 判定清单（收口）

| 接口 | 默认认证 | 直达原语 | 未授权即高危？ |
|------|----------|----------|----------------|
| Actuator heapdump | 无（依赖 Security 保护） | 凭据泄露（间接 RCE） | 高（组合链） |
| Actuator jolokia | 无 | **命令执行**（JMX） | 是 |
| Actuator env/configprops | 无 | 敏感信息泄露 | 高（凭据链） |
| JMX 远程 | 无（默认关认证） | **命令执行**（MLet/任意 MBean） | 是 |
| RMI | 无 | **反序列化** | 是（依赖 gadget） |
| JDWP 远程 debug | 无（协议无认证） | **命令执行** | 是 |

## 来源

- Spring Boot Actuator 官方文档：<https://docs.spring.io/spring-boot/reference/actuator/endpoints.html>
- jdwp-shellifier：<https://github.com/IOActive/jdwp-shellifier>
- RMI/JMX 反序列化：见 `java-deser-gadget-chains.md`（ysoserial JRMP payload）
