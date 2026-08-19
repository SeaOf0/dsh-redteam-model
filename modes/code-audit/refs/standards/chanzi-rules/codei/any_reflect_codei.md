# Java 不安全的反射调用漏洞：完整描述与典型场景

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_reflect_codei` · 类别：codei · 关键 sink：Class, Method, forName, invoke
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java 不安全的反射调用漏洞：完整描述与典型场景
Java 反射机制允许程序在运行时动态获取类的信息（如字段、方法、构造器）并调用其成员，突破了编译期的访问限制（如访问 `private` 成员）。但**不安全的反射调用**会绕过语言本身的访问控制和安全校验，导致代码执行、数据泄露、权限提升等严重安全漏洞，是 Java 应用中高频且高危的漏洞类型。

#### 一、漏洞核心本质
反射的设计初衷是为框架（如 Spring、MyBatis）提供动态扩展能力，但当反射调用的**目标类/方法/参数**可被外部控制（如用户输入、配置文件、网络请求参数），且未做任何校验时，攻击者可构造恶意输入，触发非预期的类加载、方法执行或字段操作，进而控制程序执行流程。

核心风险点：
1. 绕过访问修饰符（`private`/`protected`/`default`）：通过 `setAccessible(true)` 突破封装性；
2. 动态执行任意代码：调用危险方法（如 `Runtime.exec()`、`ProcessBuilder.start()`）；
3. 敏感数据泄露：读取私有字段（如密码、密钥、配置）；
4. 破坏对象完整性：修改不可变字段（如 `final` 字段）；
5. 类加载/实例化风险：加载恶意类或触发危险构造器。

#### 二、漏洞的典型触发场景
以下按“调用类型+风险场景”分类，详细说明各类不安全反射的具体表现：

##### 场景1：动态调用执行命令的方法（最高危）
攻击者通过控制反射的“类名”“方法名”或“参数”，调用系统命令执行相关方法，实现远程代码执行（RCE）。

###### 子场景1.1：直接调用 Runtime/ProcessBuilder 执行命令
反射调用 `java.lang.Runtime` 的 `exec()` 方法是最典型的 RCE 场景，核心代码特征：
```java
// 危险代码：用户输入直接作为反射参数
String className = request.getParameter("className"); // 可控输入
String methodName = request.getParameter("methodName"); // 可控输入
String cmd = request.getParameter("cmd"); // 可控输入

Class<?> clazz = Class.forName(className);
Method method = clazz.getMethod(methodName, String.class);
method.invoke(clazz.getMethod("getRuntime").invoke(null), cmd);
```
攻击者只需传入：
- `className=java.lang.Runtime`
- `methodName=exec`
- `cmd=rm -rf /`（Linux）或 `cmd=del C:\Windows\System32\*`（Windows）
即可执行任意系统命令。

###### 子场景1.2：间接调用危险方法（如通过 ClassLoader 加载恶意类）
通过反射调用 `ClassLoader.loadClass()` 或 `Class.newInstance()` 加载恶意类，再调用其方法：
```java
// 危险代码：可控类名加载任意类
String evilClassName = request.getParameter("evilClass");
Class<?> evilClazz = Class.forName(evilClassName);
Object evilObj = evilClazz.newInstance();
Method evilMethod = evilClazz.getMethod("attack");
evilMethod.invoke(evilObj);
```
若攻击者提前将恶意类（含 `attack()` 方法，内部执行 `Runtime.exec()`）注入类路径，即可触发代码执行。

##### 场景2：绕过访问控制读取/修改敏感私有字段
反射可通过 `setAccessible(true)` 强制访问类的私有字段，导致敏感数据泄露或数据篡改。

###### 子场景2.1：读取私有敏感字段（如密码、密钥）
```java
// 危险代码：可控类名和字段名，读取任意私有字段
String targetClass = request.getParameter("class");
String targetField = request.getParameter("field");

Class<?> clazz = Class.forName(targetClass);
Object obj = clazz.getDeclaredConstructor().newInstance();
Field field = clazz.getDeclaredField(targetField);
field.setAccessible(true); // 突破 private 限制
Object sensitiveData = field.get(obj);
System.out.println(sensitiveData); // 泄露数据
```
例如攻击者传入 `targetClass=com.example.User`、`targetField=password`，即可读取用户私有密码字段。

###### 子场景2.2：修改 final 字段或核心配置字段
```java
// 危险代码：修改 final 字段
String clazzName = request.getParameter("clazz");
String fieldName = request.getParameter("field");
String newValue = request.getParameter("value");

Class<?> clazz = Class.forName(clazzName);
Field field = clazz.getDeclaredField(fieldName);
field.setAccessible(true);
// 绕过 final 修饰符（反射可修改 final 字段）
Field modifiersField = Field.class.getDeclaredField("modifiers");
modifiersField.setAccessible(true);
modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

field.set(null, newValue); // 修改静态 final 字段（如系统配置）
```
例如修改 `java.lang.System` 的 `out` 字段，篡改日志输出；或修改业务类的 `isAdmin` 字段，提升自身权限。

##### 场景3：调用危险构造器实例化恶意对象
通过反射调用类的构造器，实例化具有危险行为的对象（如序列化相关、资源消耗类）。

###### 子场景3.1：实例化 Serializable 类触发反序列化漏洞
```java
// 危险代码：可控类名实例化任意可序列化类
String className = request.getParameter("className");
Class<?> clazz = Class.forName(className);
Constructor<?> constructor = clazz.getDeclaredConstructor();
constructor.setAccessible(true);
Object obj = constructor.newInstance();

// 若 obj 是恶意序列化类，后续序列化/反序列化会触发漏洞
ByteArrayOutputStream bos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(bos);
oos.writeObject(obj);
```
例如攻击者传入 `className=org.apache.commons.collections.Transformer`，结合反序列化漏洞执行代码。

###### 子场景3.2：实例化资源消耗类导致 DoS
```java
// 危险代码：实例化大对象导致内存耗尽
String className = request.getParameter("className");
Class<?> clazz = Class.forName(className);
Constructor<?> constructor = clazz.getDeclaredConstructor(int.class);
constructor.setAccessible(true);
// 传入超大数值，实例化大数组/集合
Object obj = constructor.newInstance(Integer.parseInt(request.getParameter("size")));
```
例如传入 `className=java.util.ArrayList`、`size=100000000`，实例化超大 ArrayList 导致内存溢出（DoS）。

##### 场景4：反射调用重载方法时的参数注入
当反射调用重载方法时，若参数类型/数量可控，攻击者可触发非预期的方法重载，导致逻辑绕过或代码执行。

```java
// 危险代码：重载方法参数可控
String className = request.getParameter("className");
String methodName = request.getParameter("methodName");
String paramType = request.getParameter("paramType"); // 可控参数类型
String paramValue = request.getParameter("paramValue");

Class<?> clazz = Class.forName(className);
Class<?>[] paramTypes = {Class.forName(paramType)};
Method method = clazz.getMethod(methodName, paramTypes);
method.setAccessible(true);
method.invoke(clazz.newInstance(), paramValue);
```
例如业务类有两个重载方法：
- `public void doSomething(String s)`：合法业务逻辑；
- `private void doSomething(Runtime r)`：执行命令。
攻击者传入 `paramType=java.lang.Runtime`、`paramValue=Runtime.getRuntime()`，即可触发私有重载方法执行命令。

##### 场景5：通过反射调用 native 方法触发底层漏洞
Java 的 `native` 方法调用底层 C/C++ 代码，若反射调用可控，可能触发底层内存破坏或系统级漏洞。

```java
// 危险代码：调用 native 方法
String className = request.getParameter("className");
String methodName = request.getParameter("methodName");

Class<?> clazz = Class.forName(className);
Method method = clazz.getMethod(methodName);
method.setAccessible(true);
method.invoke(null); // 调用静态 native 方法
```
例如攻击者调用 `sun.misc.Unsafe` 的 `native` 方法（如 `allocateMemory`），篡改内存数据或触发段错误。

#### 三、漏洞的扩展风险场景
1. **框架层反射滥用**：Spring 的 `BeanWrapper`、MyBatis 的 Mapper 反射、Struts2 的 OGNL 表达式（底层依赖反射），若参数可控，会放大反射漏洞风险；
2. **JNDI 结合反射**：通过反射调用 `InitialContext.lookup()`，结合 JNDI 注入加载远程恶意类；
3. **模块/插件反射调用**：动态加载的插件通过反射调用主程序的私有方法，导致权限边界突破；
4. **调试/日志反射**：日志框架（如 Log4j2）通过反射获取参数时，若参数含恶意类名，触发类加载漏洞（如 Log4j2 的 JNDI 漏洞本质是反射+JNDI）。

#### 四、漏洞的关键特征总结
1. 反射调用的核心参数（类名、方法名、字段名、参数值）可被外部控制；
2. 调用 `setAccessible(true)` 绕过访问修饰符限制；
3. 未对反射的目标类/方法进行白名单校验；
4. 反射调用危险 API（`Runtime.exec()`、`ClassLoader.loadClass()`、`Field.set()` 等）；
5. 反射结合序列化/反序列化、JNDI、OGNL 等技术，放大漏洞危害。

该漏洞的本质是“动态性”与“可控性”的结合：反射的动态扩展能力被滥用，且缺乏对调用目标的校验，导致攻击者可突破Java的安全模型，执行任意操作。

