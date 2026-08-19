# Java Dubbo反序列化漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`pom_dubbo_deserialization` · 类别：deser · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。

# Java Dubbo反序列化漏洞
Dubbo是阿里巴巴开源的高性能、轻量级Java RPC框架，其底层依赖序列化/反序列化机制实现跨进程数据传输。反序列化漏洞的核心根源是：**攻击者构造恶意序列化数据，通过Dubbo的反序列化流程执行任意代码**，该类漏洞贯穿Dubbo不同版本和使用场景，以下从漏洞本质、触发场景、不同维度的漏洞变体、影响范围等维度完整描述。

## 一、漏洞本质
Java反序列化漏洞的核心是：Java序列化机制允许将对象转化为字节流，反序列化时恢复为对象，若过程中调用了恶意类的`readObject()`/`readResolve()`等魔术方法，且该类可被ClassLoader加载，则攻击者可通过构造字节流触发任意代码执行。

Dubbo作为RPC框架，其通信协议（如Dubbo协议、Hessian协议等）、序列化方式（如Java原生序列化、Hessian2、Fastjson等）均依赖反序列化逻辑，一旦框架或依赖组件的反序列化流程未做严格校验，攻击者即可利用该漏洞远程攻击。

## 二、Dubbo反序列化漏洞的核心触发前提
1. 攻击者可直接向Dubbo服务端口发送恶意构造的数据包；
2. Dubbo服务端开启了可被利用的序列化方式（如原生Java序列化）；
3. 服务端ClassPath中存在可被利用的“反序列化利用链”依赖（如Commons Collections、Commons Beanutils、Fastjson等）；
4. Dubbo未对反序列化的类做白名单/黑名单限制，或限制逻辑可被绕过。

## 三、不同维度的漏洞场景与变体
### （一）按序列化方式分类的漏洞
Dubbo支持多种序列化方式，不同序列化方式对应不同的反序列化漏洞类型：

#### 1. Java原生序列化（serialization）漏洞
- **启用场景**：Dubbo配置`serialization="java"`（早期版本默认或可手动配置），或使用Dubbo的`JavaSerialization`/`JavaObjectInput`实现；
- **漏洞原理**：Dubbo服务端接收客户端请求后，直接调用`ObjectInputStream.readObject()`反序列化数据，若攻击者构造包含利用链的Java序列化字节流，即可触发RCE；
- **典型利用链**：依赖服务端存在的第三方库，如：
  - Commons Collections 3.x/4.x（CC1/CC2/CC3/CC4/CC5/CC6等）；
  - Commons Beanutils 1.9.2及以下（CB1）；
  - Groovy 2.3.x及以下（Groovy1）；
  - JRE内置类（如TemplatesImpl、FileSystemXmlApplicationContext等）；
- **触发点**：Dubbo协议的请求体反序列化、参数反序列化、附件（attachment）反序列化等；
- **特点**：利用链成熟，攻击成本低，只要服务端存在对应依赖即可触发。

#### 2. Hessian2序列化漏洞
- **启用场景**：Dubbo默认序列化方式为Hessian2（`serialization="hessian2"`），是最广泛的使用场景；
- **漏洞原理**：
  - Hessian2自身的反序列化逻辑存在缺陷，可解析恶意构造的字节流实例化危险类；
  - Dubbo对Hessian2反序列化的类未做严格校验，攻击者可构造包含危险类（如`org.apache.commons.collections.functors.ConstantTransformer`）的Hessian2数据；
- **典型利用链**：
  - Hessian2原生利用链（如通过`com.caucho.naming.QName`、`com.caucho.hessian.io.JavaSerializer`触发类加载）；
  - 结合Commons Collections的Hessian利用链；
  - 针对Hessian2解析逻辑的绕过（如利用`java.lang.reflect.Proxy`动态代理类）；
- **特殊点**：Hessian2不依赖`readObject()`方法，而是通过自身的`Serializer`/`Deserializer`机制反序列化，因此部分Java原生利用链不适用，但存在专属利用链。

#### 3. Fastjson序列化漏洞
- **启用场景**：Dubbo配置`serialization="fastjson"`，显式使用Fastjson作为序列化方式；
- **漏洞原理**：复用Fastjson自身的反序列化漏洞（如Fastjson 1.2.24及以下的autoType漏洞），攻击者构造包含`@type`字段的恶意JSON数据，Dubbo服务端反序列化时触发RCE；
- **典型利用方式**：
  - 利用`com.sun.rowset.JdbcRowSetImpl`触发JNDI注入；
  - 利用`org.apache.tomcat.dbcp.dbcp2.BasicDataSource`等类触发命令执行；
- **特点**：依赖Fastjson版本，与Fastjson自身漏洞强绑定。

#### 4. Kryo/FST序列化漏洞
- **启用场景**：Dubbo配置`serialization="kryo"`或`serialization="fst"`（高性能序列化方式，多用于内部服务）；
- **漏洞原理**：
  - Kryo/FST的反序列化逻辑允许实例化任意类，且未做类校验；
  - 攻击者构造包含利用链的Kryo/FST字节流，服务端反序列化时触发代码执行；
- **特点**：利用链与Java原生序列化类似，但需适配Kryo/FST的序列化格式，攻击工具较少但危害相同。

### （二）按Dubbo协议/组件分类的漏洞
#### 1. Dubbo协议（默认）反序列化漏洞
- **通信方式**：基于TCP的Dubbo私有协议，端口默认20880；
- **触发位置**：
  - 请求头（header）中的附件（attachment）反序列化；
  - 请求体（body）中的参数/返回值反序列化；
  - 心跳包（heartbeat）中的扩展字段反序列化；
- **典型漏洞**：
  - Dubbo < 2.6.5 / < 2.7.0 版本中，`com.alibaba.dubbo.rpc.protocol.dubbo.DecodeableRpcInvocation`类在反序列化时未校验类名，可触发Java原生序列化漏洞；
  - Dubbo 2.7.x早期版本中，Hessian2反序列化附件时未过滤危险类。

#### 2. HTTP协议（dubbo-remoting-http）反序列化漏洞
- **启用场景**：Dubbo配置使用HTTP协议（`protocol="http"`），基于Servlet/Netty HTTP；
- **漏洞原理**：HTTP请求体中的数据通过指定序列化方式（如Hessian2、Fastjson）反序列化，攻击者发送POST请求携带恶意数据即可触发；
- **特点**：可通过HTTP端口（如8080）攻击，易绕过防火墙（相比TCP 20880）。

#### 3. RMI协议（dubbo-rpc-rmi）反序列化漏洞
- **启用场景**：Dubbo适配RMI协议（`protocol="rmi"`）；
- **漏洞原理**：复用Java RMI自身的反序列化漏洞，Dubbo作为RMI服务端时，接收客户端的恶意RMI调用请求，反序列化触发代码执行；
- **特点**：与原生RMI反序列化漏洞完全兼容，利用链通用。

#### 4. Dubbo Registry（注册中心）相关反序列化漏洞
- **启用场景**：Dubbo接入Zookeeper/Etcd/Nacos等注册中心；
- **漏洞原理**：
  - 注册中心存储的服务元数据（如URL、参数）被序列化后，消费者/提供者拉取时反序列化；
  - 攻击者攻陷注册中心后，篡改元数据为恶意序列化数据，触发消费端/提供端反序列化漏洞；
- **特点**：间接攻击，需先控制注册中心，危害范围广（影响所有接入该注册中心的服务）。

### （三）按漏洞触发阶段分类的漏洞
#### 1. 服务端接收请求时的反序列化漏洞（最常见）
- **场景**：客户端（攻击者）向Dubbo服务端发送恶意请求，服务端反序列化请求数据时触发；
- **角色**：攻击者作为客户端，目标为Dubbo服务端；
- **危害**：直接控制服务端，执行任意命令。

#### 2. 客户端调用服务时的反序列化漏洞（反向攻击）
- **场景**：恶意服务端返回包含恶意序列化数据的响应，客户端反序列化响应数据时触发；
- **角色**：攻击者搭建恶意Dubbo服务端，诱导合法客户端调用；
- **危害**：控制客户端（如消费端应用），多见于内部服务调用场景。

#### 3. 本地反序列化漏洞（非远程）
- **场景**：Dubbo日志/缓存中存储了序列化数据，攻击者通过本地文件读取等方式触发反序列化；
- **触发条件**：需先获取本地序列化文件，结合文件读取漏洞利用；
- **危害**：本地代码执行，多为组合漏洞利用场景。

### （四）按版本与修复绕过分类的漏洞
#### 1. 历史核心漏洞版本
- Dubbo 2.0.x - 2.6.4：Java原生序列化未校验，可通过`RpcInvocation`/`RpcResult`触发RCE；
- Dubbo 2.6.5 - 2.6.9：修复了部分类校验，但存在附件（attachment）反序列化绕过；
- Dubbo 2.7.0 - 2.7.3：Hessian2反序列化未过滤`java.lang.ProcessBuilder`等危险类；
- Dubbo 3.0.x早期版本：对Kryo序列化的类校验不完善。

#### 2. 漏洞绕过方式
- **类名绕过**：Dubbo对黑名单类名做了字符串匹配，攻击者通过类名变形（如使用内部类、别名、类加载器差异）绕过；
- **序列化方式绕过**：服务端限制了Java序列化，但未限制Hessian2/Fastjson，攻击者切换序列化方式触发；
- **附件/扩展字段绕过**：Dubbo对请求体做了校验，但忽略了header/attachment中的扩展字段反序列化；
- **依赖版本绕过**：服务端升级了Dubbo，但依赖的Commons Collections未升级，仍可触发利用链；
- **动态类加载绕过**：利用JRE内置类（如`javax.script.ScriptEngineManager`）代替第三方库，绕过依赖检查。

## 四、影响范围与关键依赖
### 1. 受影响的Dubbo核心版本
- Apache Dubbo（原Alibaba Dubbo）：2.0.0 ~ 2.7.10、3.0.0 ~ 3.0.5（部分版本）；
- 阿里云EDAS封装的Dubbo版本：未同步修复的定制版本；
- Dubbo Spring Cloud集成版本：依赖底层Dubbo核心版本的漏洞。

### 2. 关键依赖（触发漏洞的必要条件）
- 第三方利用链库：Commons Collections (3.1-3.2.1、4.0-4.4)、Commons Beanutils (1.8.0-1.9.2)、Groovy (2.0.0-2.3.9)；
- 序列化组件：Hessian (4.0.0-4.0.63)、Fastjson (1.2.0-1.2.83)、Kryo (4.0.0-5.0.0)；
- JRE版本：JDK 6-8（高版本JDK对JNDI、类加载做了限制，部分利用链失效）。

## 五、漏洞触发的典型流程（以Dubbo协议+Java原生序列化为例）
1. 攻击者构造包含CC1利用链的Java序列化字节流；
2. 将字节流封装为Dubbo协议格式（包含魔数、版本、请求类型、附件、请求体）；
3. 向Dubbo服务端20880端口发送该数据包；
4. 服务端`DecodeableRpcInvocation.decode()`方法调用`ObjectInputStream.readObject()`反序列化请求体；
5. 反序列化过程中执行CC1利用链的`transform()`方法，触发`Runtime.exec()`执行任意命令；
6. 命令执行结果无需返回，攻击者通过DNSlog/反弹Shell验证漏洞利用成功。

## 六、非典型触发场景
1. **Dubbo泛化调用（Generic Invoke）**：启用泛化调用后，服务端接收任意类的参数，反序列化校验被弱化，易触发漏洞；
2. **Dubbo扩展机制**：自定义序列化扩展、过滤器（Filter）、拦截器（Interceptor）中存在反序列化逻辑，未做校验；
3. **Dubbo测试工具**：如`dubbo-admin`、`dubbo-monitor`等配套工具，自身存在反序列化漏洞，可作为攻击入口；
4. **跨语言调用**：Java Dubbo服务端接收非Java客户端（如Go/PHP）发送的恶意序列化数据，因跨语言序列化格式兼容问题触发漏洞。

综上，Dubbo反序列化漏洞并非单一漏洞，而是覆盖“序列化方式-通信协议-触发阶段-版本绕过”的多维度漏洞体系，其危害本质是反序列化流程中缺乏严格的类校验和利用链阻断，导致攻击者可构造恶意数据执行任意代码。

