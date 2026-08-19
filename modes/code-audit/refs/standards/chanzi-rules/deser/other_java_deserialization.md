# Java反序列化漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`other_java_deserialization` · 类别：deser · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java反序列化漏洞
Java反序列化漏洞是Java生态中最经典、影响范围最广的安全漏洞之一，其本质是**攻击者通过构造恶意的序列化数据，在目标系统反序列化过程中执行任意代码**，核心根源在于Java序列化机制的设计缺陷——反序列化过程会自动触发类的特定方法，且未对反序列化的对象类型和内容做严格校验。

#### 一、Java序列化与反序列化基础
要理解该漏洞，需先明确Java序列化的核心逻辑：
1. **序列化（Serialization）**：将Java对象转换为字节序列（二进制数据），用于网络传输、持久化存储（如文件、数据库）等场景，通过实现`java.io.Serializable`接口的类可被序列化，核心API为`ObjectOutputStream.writeObject()`。
2. **反序列化（Deserialization）**：将字节序列还原为Java对象，核心API为`ObjectInputStream.readObject()`，该过程会自动恢复对象的状态，且会触发一系列隐式方法调用（这是漏洞的关键）。

#### 二、漏洞核心原理
Java反序列化时，`ObjectInputStream.readObject()`会根据字节流中的类信息，实例化对应对象并恢复其属性，且在这个过程中：
- 若目标类重写了`readObject()`方法，该方法会被自动调用；
- 若类中包含其他可序列化的成员变量，成员变量的反序列化也会递归触发；
- 部分JDK内置类/第三方库类的`readObject()`方法存在“危险逻辑”（如执行命令、调用本地方法、加载恶意类等）。

攻击者只需构造包含恶意逻辑的序列化字节流，让目标系统的反序列化接口（如接收序列化数据的RPC接口、文件解析功能）读取该字节流，即可触发恶意代码执行。

#### 三、漏洞触发的必要条件
1. **反序列化入口**：目标系统存在可接收外部输入的反序列化操作（如接口参数为`Object`类型、读取本地序列化文件并反序列化）；
2. **恶意类可达**：构造的恶意类必须在目标系统的类路径（ClassPath）中存在（或可通过类加载机制加载）；
3. **触发链存在**：存在从`readObject()`到恶意代码执行的调用链（即“反序列化gadget”，gadget指可被利用的代码片段）。

#### 四、漏洞的常见场景与分类
根据触发方式、影响范围和利用链的不同，Java反序列化漏洞可分为以下几类：

##### 1. 基于JDK内置类的原生利用链
JDK自身的部分类因`readObject()`设计不当，可被直接或间接利用触发恶意行为，典型代表：
- **`java.util.HashMap`**：HashMap的`readObject()`会遍历键值对并调用`hash()`方法，若键为恶意实现的类（如重写`hashCode()`执行命令），可触发代码执行；
- **`java.io.ObjectInputStream$GetField`**：配合自定义类的`readObject()`可绕过部分校验；
- **`java.lang.reflect.Constructor`/`Method`**：通过反序列化反射对象，调用任意方法；
- **`sun.rmi.server.UnicastRef`**：RMI反序列化时，该类的`readObject()`会触发远程方法调用，可被利用加载恶意类。

##### 2. 基于第三方库的利用链（最主流）
绝大多数实际漏洞利用依赖第三方开源库的gadget链，因为JDK原生链往往受限于环境，而第三方库（如Apache Commons、Spring、Fastjson等）的广泛使用使其成为主要攻击面：
| 第三方库       | 典型利用链                | 触发逻辑                                                                 |
|----------------|---------------------------|--------------------------------------------------------------------------|
| Apache Commons Collections | CC1/CC2/CC3/CC4/CC5/CC6   | CC1链核心是`Transformer`接口的实现类（如`InvokerTransformer`），通过`readObject()`触发`transform()`方法，调用`Runtime.exec()`执行命令；后续CC链针对JDK版本（如JDK 8u71修复CC1）做了变种； |
| Apache Commons Beanutils | Beanutils1                | 利用`BeanComparator`结合反射，在反序列化时调用恶意方法；|
| Spring         | Spring1/Spring2           | 利用`SimpleEvaluationContext`或`StandardEvaluationContext`执行SpEL表达式，触发代码执行； |
| Fastjson       | 反序列化漏洞（非标准Java序列化） | Fastjson虽不是基于`Serializable`的序列化，但通过`parseObject()`自动实例化类，若类有`setter`/`getter`或构造方法包含危险逻辑，可触发命令执行（常被归为广义的反序列化漏洞）； |
| Jackson        | 反序列化漏洞              | 开启`enableDefaultTyping()`后，可反序列化任意类，若类包含危险逻辑（如`java.lang.ProcessBuilder`），可执行命令； |

##### 3. 基于自定义类的反序列化漏洞
开发者自定义的可序列化类若存在不当的`readObject()`实现，也会引入漏洞：
- 场景1：`readObject()`中直接执行系统命令（如读取配置文件时调用`Runtime.exec()`，且参数可被反序列化控制）；
- 场景2：`readObject()`中未校验输入，直接将反序列化的属性值传入危险方法（如`FileOutputStream`写入任意文件，或反射调用任意方法）；
- 场景3：`readObject()`中调用外部接口，且参数可控，导致SSRF/任意请求伪造。

##### 4. 基于RMI/JNDI的反序列化攻击（远程利用）
RMI（远程方法调用）、JNDI（Java命名和目录接口）是反序列化漏洞的高频利用场景，攻击者可通过远程触发反序列化：
- RMI：客户端向RMI服务器发送恶意序列化对象，服务器反序列化时触发漏洞；或服务器向客户端返回恶意对象，客户端反序列化时中招；
- JNDI：通过反序列化触发JNDI lookup，指向攻击者控制的LDAP/RMI服务器，加载恶意类（如`javax.naming.Context`的反序列化，配合LDAP服务器返回`Reference`类，触发类加载）；JDK 8u191前的版本默认允许加载远程类，该利用链杀伤力极强。

##### 5. 序列化数据篡改导致的漏洞（非代码执行）
反序列化漏洞不仅限于代码执行，还可能导致敏感信息泄露/权限绕过：
- 场景1：序列化数据中包含用户权限信息（如`isAdmin=false`），攻击者篡改字节流为`isAdmin=true`，反序列化后提升权限；
- 场景2：序列化数据包含订单金额、用户ID等核心数据，篡改后导致业务逻辑漏洞（如支付金额被修改为0）；
- 场景3：反序列化时未校验对象的签名/哈希，导致恶意构造的对象被成功反序列化（若有签名校验，可绕过则触发漏洞，不可绕过则无法利用）。

#### 五、漏洞的影响范围与特点
1. **影响版本**：几乎覆盖所有Java版本（JDK 1.1至最新版，不同版本仅修复部分利用链，无完全免疫版本）；
2. **利用难度**：从“开箱即用”（如CC1链）到“高度定制”（需适配目标环境的类路径）不等，存在大量公开的利用工具（如ysoserial、JNDIExploit）；
3. **无前置条件**：无需目标系统存在注入点、上传点等，仅需存在可接收序列化数据的入口；
4. **隐蔽性强**：序列化字节流为二进制数据，难以通过特征检测发现，且攻击行为发生在反序列化过程中，日志中可能无明显异常。

#### 六、典型利用流程（以CC1链为例）
1. 攻击者使用ysoserial工具，基于Apache Commons Collections 3.1版本生成包含CC1链的恶意序列化字节流；
2. 找到目标系统的反序列化入口（如某接口接收`Object`类型参数，通过`readObject()`反序列化）；
3. 将恶意字节流发送至该入口；
4. 目标系统执行`readObject()`时，触发CC1链的调用逻辑：`HashMap.readObject()` → `hash()` → `Transformer.transform()` → `InvokerTransformer.invoke()` → `Runtime.exec()`；
5. 最终执行攻击者指定的命令（如`calc.exe`、`rm -rf /`）。

综上，Java反序列化漏洞的本质是“反序列化过程中不可控的代码执行”，其利用场景覆盖JDK原生类、第三方库、自定义类，且结合RMI/JNDI等机制可实现远程无文件攻击，是Java安全中最核心的风险点之一。


