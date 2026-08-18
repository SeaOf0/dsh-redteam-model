# Java `readObject` 不安全实现的安全漏洞

> 规则 ID：`readobject_any_cmdi` · 类别：cmdi · 关键 sink：Class, Method, ProcessBuilder, Runtime, command, exec, forName, invoke
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java `readObject` 不安全实现的安全漏洞
Java 的对象序列化（`Serializable`）机制中，`readObject()` 方法是反序列化的核心入口。该方法若未做安全校验，会成为严重的安全漏洞入口——攻击者可构造恶意序列化字节流，绕过正常逻辑、篡改对象状态，甚至执行任意代码。以下从漏洞本质、核心风险场景、典型攻击路径及具体案例，完整拆解该漏洞的所有关键维度。

## 一、漏洞本质
`Serializable` 接口的反序列化过程由 JVM 主导，但自定义 `readObject()` 方法会覆盖默认反序列化逻辑。若该方法未对反序列化输入做**合法性校验**、**状态约束**或**恶意数据过滤**，攻击者可：
1. 构造违背业务规则的对象属性（如将不可变字段篡改）；
2. 触发未预期的代码执行（如在 `readObject()` 中调用危险方法）；
3. 绕过访问控制（如篡改私有字段、越权操作）；
4. 利用反序列化链执行任意代码（如结合 `InvokerTransformer` 等 Gadget）。

核心根源：反序列化过程本质是“字节流→对象实例”的重建，但 `readObject()` 若缺失安全边界，相当于将对象状态的控制权完全交给外部输入。

## 二、核心风险场景分类
### 场景1：未校验关键字段的合法性
#### 原理
对象的核心字段（如权限标识、金额、状态、边界值）在反序列化时未做校验，攻击者可篡改这些字段，突破业务规则或数据完整性约束。
#### 典型案例
##### 案例1.1：权限字段篡改
```java
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private boolean isAdmin; // 核心权限字段

    // 不安全的readObject：未校验isAdmin字段
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject(); // 直接读取所有字段，无任何校验
    }

    // 业务逻辑：仅管理员可执行
    public void deleteData() {
        if (isAdmin) {
            System.out.println("敏感数据已删除");
        }
    }
}
```
攻击方式：攻击者构造序列化字节流，将 `isAdmin` 字段篡改为 `true`，反序列化后普通用户可执行管理员操作。

##### 案例1.2：数值边界突破
```java
public class BankAccount implements Serializable {
    private static final long serialVersionUID = 1L;
    private long balance; // 余额，正常应为非负数

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 无余额合法性校验
    }

    public void withdraw(long amount) {
        if (balance >= amount) {
            balance -= amount;
        }
    }
}
```
攻击方式：构造 `balance` 为负数的序列化字节流，反序列化后调用 `withdraw(0)` 可让余额无限减少，突破业务逻辑约束。

##### 案例1.3：引用类型字段篡改（空指针/恶意实例）
```java
public class Order implements Serializable {
    private static final long serialVersionUID = 1L;
    private Product product; // 非空业务字段

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 未校验product是否为null
    }

    public void calculatePrice() {
        System.out.println(product.getPrice()); // 反序列化后product为null则抛NPE
    }
}
```
攻击方式：构造 `product` 为 `null` 的序列化字节流，反序列化后调用 `calculatePrice()` 触发空指针异常，导致服务崩溃；或构造恶意 `Product` 实例（如重写 `getPrice()` 执行恶意逻辑）。

### 场景2：`readObject()` 中执行危险操作
#### 原理
`readObject()` 不仅负责字段读取，若其中包含危险操作（如文件写入、网络请求、反射、系统命令调用），且未校验输入，攻击者可通过篡改字段触发这些操作。
#### 典型案例
##### 案例2.1：触发文件写入
```java
public class FileHandler implements Serializable {
    private static final long serialVersionUID = 1L;
    private String filePath;
    private String content;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 反序列化时直接写入文件，无路径校验
        Files.write(Paths.get(filePath), content.getBytes());
    }
}
```
攻击方式：构造 `filePath="/etc/passwd"`、`content="恶意内容"` 的序列化字节流，反序列化后覆盖系统关键文件。

##### 案例2.2：触发反射执行任意方法
```java
public class ReflectExecutor implements Serializable {
    private static final long serialVersionUID = 1L;
    private String className;
    private String methodName;

    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        // 无类名/方法名校验，直接反射调用
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getMethod(methodName);
        method.invoke(null);
    }
}
```
攻击方式：构造 `className="java.lang.Runtime"`、`methodName="exec"`（配合参数篡改），反序列化后执行系统命令（如 `rm -rf /`）。

### 场景3：绕过不可变性设计
#### 原理
Java 中不可变对象（如 `String`、自定义不可变类）通常通过 `final` 字段+私有构造器实现，但反序列化可绕过构造器，直接修改 `final` 字段（若 `readObject()` 未做约束）。
#### 典型案例
```java
public final class ImmutableUser implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String id; // 设计为不可变的唯一ID
    private final String name;

    public ImmutableUser(String id, String name) {
        // 构造器中校验ID合法性
        if (!id.matches("[0-9]{6}")) {
            throw new IllegalArgumentException("非法ID");
        }
        this.id = id;
        this.name = name;
    }

    // 不安全的readObject：未复用构造器的校验逻辑
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 无ID校验，且final字段可被反序列化篡改
    }
}
```
攻击方式：构造 `id="恶意ID123"` 的序列化字节流，反序列化后得到违背不可变性设计的对象，ID 字段被篡改（即使是 `final`）。

### 场景4：反序列化链攻击（利用第三方库 Gadget）
#### 原理
若 `readObject()` 调用了第三方库的类（如 Apache Commons Collections、Spring、Jackson），且这些类存在可被利用的“Gadget”（触发代码执行的链式调用），攻击者可构造包含这些 Gadget 的序列化字节流，通过 `readObject()` 触发完整攻击链。
#### 典型案例（Apache Commons Collections 3.x 经典漏洞）
```java
public class GadgetContainer implements Serializable {
    private static final long serialVersionUID = 1L;
    private Transformer transformer;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 调用第三方库方法，触发Gadget
        transformer.transform(null);
    }
}
```
攻击方式：攻击者构造包含 `InvokerTransformer` 的 `transformer` 实例（链式调用 `Runtime.exec()`），序列化后传入，反序列化时 `readObject()` 调用 `transform()` 触发系统命令执行。

### 场景5：私有字段/内部状态篡改
#### 原理
Java 序列化会序列化所有非 `transient` 字段（包括私有字段），`readObject()` 若未对私有字段做校验，攻击者可篡改这些本应仅内部访问的字段，破坏对象内部状态。
#### 典型案例
```java
public class ConnectionPool implements Serializable {
    private static final long serialVersionUID = 1L;
    private int maxConnections = 10; // 私有字段，默认最大连接数
    private transient boolean initialized = false;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 未校验maxConnections，且直接初始化连接池
        initPool(maxConnections);
    }

    private void initPool(int max) {
        // 初始化max个连接，无上限校验
        for (int i = 0; i < max; i++) {
            new Socket("127.0.0.1", 8080); // 创建连接
        }
        initialized = true;
    }
}
```
攻击方式：构造 `maxConnections=10000` 的序列化字节流，反序列化后触发大量连接创建，导致服务器端口耗尽（DoS 攻击）。

### 场景6：忽略反序列化的继承风险
#### 原理
若子类重写 `readObject()` 但未调用父类的 `readObject()`，或父类的 `readObject()` 存在安全漏洞，子类会继承该风险；反之，父类也可能受子类不安全 `readObject()` 影响。
#### 典型案例
```java
public class Parent implements Serializable {
    private static final long serialVersionUID = 1L;
    protected String sensitiveData;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 父类未校验sensitiveData
    }
}

public class Child extends Parent {
    private static final long serialVersionUID = 1L;
    private String normalData;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 子类仅校验自己的字段，忽略父类的sensitiveData
        if (normalData == null) {
            throw new IllegalArgumentException("normalData不能为空");
        }
    }
}
```
攻击方式：构造 `sensitiveData="管理员凭证"` 的序列化字节流，反序列化 `Child` 实例时，子类未校验父类字段，导致敏感数据被篡改。

## 三、漏洞的共性特征
所有不安全的 `readObject()` 实现都具备以下一个或多个特征：
1. 直接调用 `in.defaultReadObject()` 后无任何校验逻辑；
2. 反序列化过程中执行危险操作（文件、网络、反射、命令）且未过滤输入；
3. 未复用构造器/业务层的合法性校验逻辑；
4. 忽略 `final` 字段、私有字段的篡改风险；
5. 未限制反序列化的类范围（如允许反序列化任意类）；
6. 依赖存在已知 Gadget 的第三方库，且未做隔离。

## 四、攻击触发条件
1. 目标类实现 `Serializable` 接口；
2. 目标类自定义了 `readObject()` 方法且存在上述安全缺陷；
3. 攻击者可控制反序列化的字节流输入（如通过网络传输、文件读取、数据库存储的序列化数据）；
4. 应用程序存在反序列化入口（如 `ObjectInputStream.readObject()` 调用）。

综上，`readObject()` 的安全漏洞本质是“反序列化过程的输入可控性”与“缺乏安全边界”的叠加，其风险覆盖数据篡改、权限绕过、代码执行、DoS 等多个维度，且攻击路径与业务逻辑、依赖库版本高度相关。

