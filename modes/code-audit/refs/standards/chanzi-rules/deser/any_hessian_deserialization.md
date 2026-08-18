# Java Hessian反序列化漏洞 完整技术描述

> 规则 ID：`any_hessian_deserialization` · 类别：deser · 关键 sink：deserialize
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。



# Java Hessian反序列化漏洞 完整技术描述
Hessian是一种轻量级的二进制RPC（远程过程调用）协议，由Caucho Technology开发，广泛用于Java生态中跨服务的数据传输与远程调用。其核心依赖自定义的序列化/反序列化机制实现对象的编解码，但该机制的设计缺陷与实现漏洞，导致攻击者可通过构造恶意的Hessian二进制数据，触发反序列化过程中的任意代码执行（RCE）、敏感信息泄露等安全问题。


## 一、漏洞核心原理
Hessian反序列化漏洞的本质是：**Hessian在反序列化过程中，未对待反序列化的类进行严格校验，且会自动调用目标类的特定方法（如构造函数、readObject、getter/setter、静态代码块等），攻击者可构造包含恶意类/恶意数据的Hessian数据流，利用这些方法执行任意代码**。

### 1. Hessian序列化/反序列化的核心流程
Hessian序列化时，会将Java对象转换为包含类名、字段名、字段值的二进制格式；反序列化时，核心步骤为：
1. 解析二进制流，提取目标类名；
2. 通过类加载器加载该类（若类存在于应用类路径中）；
3. 实例化该类（调用无参构造函数或特定构造逻辑）；
4. 为类的字段赋值（调用setter方法或直接反射赋值）；
5. 若类实现了`HessianSerializable`接口，会调用`readObject(HessianInput)`方法完成自定义反序列化。

正是步骤3、4、5的“无约束执行”，成为漏洞利用的关键入口。

### 2. 漏洞触发的核心条件
- 应用引入了包含Hessian反序列化逻辑的依赖（如`com.caucho:hessian:4.0.0+`、`org.springframework:spring-remoting`等）；
- 存在可控的Hessian数据输入点（如RPC接口、接口参数、文件解析等）；
- 应用类路径中存在可被利用的“Gadget类”（即包含危险方法、可被反序列化触发代码执行的类）。


## 二、漏洞的不同触发场景与利用路径
Hessian反序列化漏洞的利用场景因Hessian版本、依赖环境、目标类路径中的Gadget不同而分为多个类型，核心可归纳为以下几类：

### 场景1：基于Hessian内置类的原生漏洞（低版本Hessian）
早期Hessian版本（如4.0.x、4.1.x）自身的核心类存在设计缺陷，无需依赖第三方Gadget即可触发漏洞：
- **核心类：`com.caucho.hessian.io.JavaSerializer`/`JavaDeserializer`**
  这类类在反序列化时，会通过反射遍历目标类的所有字段，自动调用字段的setter方法。若目标类的setter方法包含危险逻辑（如执行系统命令、修改文件），攻击者可构造包含该类的Hessian数据，触发setter方法执行。
- **核心类：`com.caucho.hessian.io.Hessian2Input`**
  该类在解析“类型引用”时，未校验类名的合法性，攻击者可构造指向恶意类（如`java.lang.Runtime`）的引用，直接实例化并调用其方法。

#### 示例利用逻辑（早期版本）：
构造Hessian数据指向`java.lang.ProcessBuilder`，通过反序列化时的字段赋值（如设置`command`字段为`["/bin/bash", "-c", "whoami"]`），再触发其`start()`方法，执行系统命令。


### 场景2：基于第三方依赖Gadget的利用（通用场景）
当Hessian自身无原生漏洞，但应用类路径中存在常见的反序列化Gadget库（如Commons Collections、Commons Beanutils、Spring、Groovy等）时，攻击者可拼接Gadget链，通过Hessian反序列化触发执行：
#### 2.1 基于Commons Collections的Gadget链
最经典的利用路径，依赖`commons-collections:3.1+`：
- 核心Gadget：`InvokerTransformer`/`ChainedTransformer` + `TransformedMap` + `AnnotationInvocationHandler`
- 触发逻辑：
  1. 构造`ChainedTransformer`，包含执行系统命令的`InvokerTransformer`（调用`Runtime.getRuntime().exec()`）；
  2. 将`ChainedTransformer`传入`TransformedMap`的valueTransformer；
  3. 通过Hessian反序列化`AnnotationInvocationHandler`（持有`TransformedMap`）；
  4. 反序列化时触发`AnnotationInvocationHandler`的`readObject`方法，遍历`TransformedMap`，执行`transform`方法，最终触发命令执行。

#### 2.2 基于Spring的Gadget链
依赖Spring框架（`spring-core:4.1.x+`），无需Commons Collections：
- 核心Gadget：`org.springframework.beans.factory.ObjectFactory` + `org.springframework.aop.framework.AdvisedSupport`
- 触发逻辑：
  1. 构造`AdvisedSupport`，设置其`targetSource`为恶意的`ObjectFactory`（包含命令执行逻辑）；
  2. Hessian反序列化`AdvisedSupport`时，调用其`getTarget`方法；
  3. 触发`ObjectFactory`的`getObject`方法，执行恶意代码。

#### 2.3 基于Groovy的Gadget链
依赖Groovy库（`groovy-all:2.3.x+`）：
- 核心Gadget：`groovy.lang.GroovyShell` + `java.lang.ProcessBuilder`
- 触发逻辑：
  1. 构造`GroovyShell`，执行恶意Groovy脚本（如`"exec('whoami')"`）；
  2. Hessian反序列化`GroovyShell`时，触发其构造函数或`evaluate`方法，执行脚本并调用系统命令。


### 场景3：基于自定义类的“业务Gadget”利用
应用自身的自定义类若包含危险逻辑，且可被Hessian反序列化触发，会成为“业务专属Gadget”：
- 典型案例：
  1. 自定义工具类：如`com.xxx.utils.ProcessUtil`，其`setCommand(String cmd)`方法会直接执行`Runtime.exec(cmd)`；
  2. 持久化类：如`com.xxx.entity.User`，其`readObject`方法会读取文件并写入磁盘（可触发文件写入+代码执行）；
  3. 监听器类：如`com.xxx.listener.ConfigListener`，反序列化时会加载外部配置文件（可注入恶意配置）。
- 触发条件：
  攻击者需知晓目标应用的自定义类名、字段名、方法名，构造包含该类的Hessian数据，通过反序列化触发危险方法。


### 场景4：Hessian 2.0协议的特殊漏洞
Hessian 2.0（Hessian2）是优化后的二进制协议，虽修复了部分早期漏洞，但引入了新的风险点：
- **类型混淆漏洞**：Hessian2的类型编码机制允许将“字符串”伪装为“类引用”，攻击者可构造数据，让Hessian将恶意字符串解析为类名，加载并实例化危险类；
- **空指针触发的代码执行**：Hessian2在处理空值字段时，若目标类的setter方法未做空值校验，反序列化空值时会触发空指针异常，若异常处理逻辑包含危险代码（如日志打印时执行命令），可间接触发执行；
- **循环引用处理漏洞**：Hessian2支持循环引用，但解析循环引用时的反射操作可被利用，绕过类校验机制，加载恶意类。


### 场景5：结合类加载器的无文件落地执行
攻击者可通过Hessian反序列化触发自定义类加载器，加载远程恶意字节码，实现无文件落地执行：
- 核心逻辑：
  1. 构造`java.net.URLClassLoader`，指向远程恶意JAR包；
  2. 通过Hessian反序列化`URLClassLoader`，触发其`loadClass`方法；
  3. 加载并实例化恶意类，执行代码。
- 依赖条件：应用未限制`URLClassLoader`的使用，且网络可访问攻击者的恶意JAR服务器。


## 三、漏洞影响范围与触发条件差异
### 1. 版本差异
| Hessian版本       | 核心风险点                     | 利用难度 |
|-------------------|--------------------------------|----------|
| Hessian 3.x       | 原生类反射执行、无类名校验     | 低       |
| Hessian 4.0.x-4.1.x | Setter方法自动调用、Gadget兼容 | 中       |
| Hessian 4.2.x+    | 修复部分原生漏洞、需依赖Gadget | 中高     |
| Hessian2（全版本） | 类型混淆、循环引用解析漏洞     | 中       |

### 2. 环境依赖差异
- 无第三方Gadget：仅能利用Hessian原生漏洞或业务自定义Gadget，利用范围窄；
- 含Commons Collections/Spring/Groovy：利用路径丰富，易触发RCE；
- 高权限类加载器：可实现无文件落地执行，危害更大。

### 3. 输入点差异
- RPC接口参数：最常见，攻击者可直接构造Hessian数据发送请求；
- 文件解析（如Hessian格式配置文件）：需上传恶意文件并触发解析；
- 缓存反序列化（如Redis存储Hessian数据）：需污染缓存数据，触发后续反序列化。


## 四、漏洞的典型危害
1. **远程代码执行（RCE）**：最核心危害，攻击者可执行任意系统命令，控制服务器；
2. **敏感信息泄露**：反序列化过程中读取服务器本地文件（如/etc/passwd、配置文件）；
3. **数据篡改**：修改应用内存中的对象数据，破坏业务逻辑；
4. **权限提升**：执行高权限命令（如sudo），突破应用权限限制；
5. **横向移动**：利用漏洞控制服务器后，进一步攻击内网其他主机。


## 总结
Hessian反序列化漏洞的本质是“无约束的类实例化+方法执行”，其利用场景覆盖从原生协议漏洞到第三方Gadget链，再到业务自定义类的全维度，核心依赖“可控输入+类路径中存在可利用的Gadget”。不同版本、不同环境下的触发路径虽有差异，但最终均可导致严重的代码执行或信息泄露风险，是Java生态中典型且高危的反序列化漏洞类型。

