# Java 语言 SSRF 漏洞

> 规则 ID：`other_any_ssrf` · 类别：ssrf · 关键 sink：AbstractHttpClient, AbstractRequestBuilder, AsyncRestTemplate, BasicDataSource, Call, Client, CloseableHttpAsyncClient, CloseableHttpClient, DataSource, DocumentBuilder, DocumentBuilderFactory, DriverManager
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java 语言 SSRF 漏洞
SSRF（Server-Side Request Forgery，服务器端请求伪造）是一种由攻击者构造请求，诱导服务器端发起非预期的网络请求的安全漏洞。Java 作为主流的后端开发语言，因广泛使用各类网络请求库、框架，且常涉及内部服务交互，成为 SSRF 漏洞的高发场景。以下从**漏洞本质**、**Java 中 SSRF 的核心成因**、**典型触发场景**、**不同请求库的 SSRF 表现**、**绕过方式**、**危害场景**等维度完整描述。

## 一、漏洞本质
Java 服务端在处理用户输入（如 URL、IP、端口等参数）时，未对输入进行严格校验或限制，直接将其作为网络请求的目标地址，导致攻击者可操控服务器向任意地址（内网/外网/本地）发起请求，进而探测内网服务、窃取敏感数据、攻击内部系统，甚至通过特殊协议执行恶意操作。

## 二、Java 中 SSRF 的核心成因
Java 程序中 SSRF 的根本原因是**用户可控输入直接进入网络请求构造逻辑**，且未做以下防护：
1. 未校验请求目标的协议、IP、端口合法性；
2. 未限制请求的内网地址（如 127.0.0.1、192.168.0.0/16、10.0.0.0/8 等）；
3. 未过滤特殊协议（如 file、jar、dns、ftp 等）；
4. 未限制请求重定向（如 302 跳转至内网地址）；
5. 依赖不可信的 URL 解析逻辑（如绕过 IP 格式校验的特殊写法）。

## 三、Java 中 SSRF 的典型触发场景
### 场景 1：业务功能中的 URL 转发/抓取
常见于需要从外部 URL 拉取资源的场景，如：
- 图片/文件下载功能（用户传入图片 URL，服务器下载后返回）；
- 爬虫/数据采集功能（用户指定目标 URL，服务器发起请求并解析内容）；
- 第三方 API 调用代理（用户传入 API 地址，服务器代为请求）；
- 链接预览功能（解析用户输入的 URL，生成标题/摘要）。

**示例代码（存在 SSRF）**：
```java
// Spring Boot 接口示例：根据用户传入的 URL 下载内容
@RestController
public class SSRFController {
    @GetMapping("/download")
    public ResponseEntity<byte[]> download(@RequestParam String url) throws Exception {
        // 直接使用用户输入的 URL 发起请求，无任何校验
        URL targetUrl = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
        InputStream in = conn.getInputStream();
        byte[] data = IOUtils.toByteArray(in); // 依赖 Apache Commons IO
        return ResponseEntity.ok(data);
    }
}
```
攻击者可传入 `http://192.168.1.100:8080/admin` 诱导服务器访问内网管理后台。

### 场景 2：配置/依赖中的间接请求
Java 框架或第三方依赖可能因配置不当引入 SSRF：
- 分布式配置中心（如 Nacos、Apollo）：若配置项支持动态 URL 且可被用户控制，可能触发 SSRF；
- 日志采集/监控组件：若允许用户指定日志上报地址，未校验则可伪造请求；
- 数据库/缓存客户端：部分客户端支持通过 URL 加载配置，若 URL 可控则存在风险；
- 依赖注入框架：若恶意构造注入的 URL 参数，可能触发服务器端请求。

### 场景 3：云服务/内部服务交互
Java 后端常与云服务（如对象存储、云函数）或内部微服务交互，若用户输入可渗透到服务间调用的地址参数中：
- 例如：用户传入 “存储桶地址” 为内网地址，服务器直接发起请求；
- 例如：微服务网关中，用户可控的服务路由地址未校验，导致请求转发至内网节点。

## 四、Java 不同网络请求库的 SSRF 表现
Java 中常用的网络请求库因实现方式不同，SSRF 风险和表现也存在差异：

### 1. JDK 原生 API（HttpURLConnection、URL）
- **核心风险**：支持多种协议（http、https、file、ftp、jar、dns、ldap 等），默认允许重定向；
- **特殊表现**：
  - `file` 协议可读取服务器本地文件（如 `file:///etc/passwd`、`file:///C:/Windows/win.ini`）；
  - `dns` 协议可触发 DNS 解析，结合 DNS 日志实现盲 SSRF 探测；
  - `ldap`/`rmi` 协议可配合反序列化漏洞执行代码（如 JNDI 注入）；
  - 支持 IP 多种写法（如 127.0.0.1 可写成 0x7f000001、127.1、localhost 等），易绕过简单校验。

**示例（file 协议读取本地文件）**：
攻击者请求 `http://target.com/download?url=file:///C:/Windows/system32/drivers/etc/hosts`，服务器会读取本地 hosts 文件并返回。

### 2. Apache HttpClient
- **核心风险**：功能更强大，默认允许重定向，支持自定义协议；
- **特殊表现**：
  - 可配置是否允许重定向，但默认开启；
  - 支持连接池，恶意请求可能占用服务器连接资源；
  - 对 URL 解析更严格，但仍可通过 IP 变形绕过校验；
  - 新版本（HttpClient 5.x）默认限制部分危险协议，但旧版本无限制。

### 3. OkHttp（Square 开源，Android/后端常用）
- **核心风险**：轻量高效，默认跟随重定向（最多 20 次），支持 HTTP/2；
- **特殊表现**：
  - 可通过 `followRedirects(false)` 关闭重定向，但默认开启；
  - 支持 `socket` 协议直接建立 TCP 连接，可探测内网端口开放状态；
  - 对 IPv6 地址支持较好，攻击者可使用 `[::1]` 代替 127.0.0.1 绕过校验。

### 4. Spring RestTemplate
- **核心风险**：基于 HttpClient/OkHttp/HttpURLConnection 封装，简化 REST 请求，默认允许重定向；
- **特殊表现**：
  - 底层依赖的客户端决定协议支持（如默认用 HttpURLConnection 则支持 file 协议）；
  - `getForObject`/`postForObject` 等方法直接接收 URL 参数，无校验则直接触发 SSRF；
  - 支持 `exchange` 方法自定义请求头，攻击者可构造恶意请求头（如 X-Forwarded-For）辅助绕过。

**示例（RestTemplate 触发 SSRF）**：
```java
@GetMapping("/proxy")
public String proxy(@RequestParam String url) {
    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForObject(url, String.class); // 无校验，直接请求
}
```

## 五、Java SSRF 的常见绕过方式
攻击者为绕过 Java 程序中的基础校验（如黑名单过滤内网 IP），会采用以下绕过手段：

### 1. IP 地址变形绕过
Java 解析器支持多种 IP 格式，可绕过简单的字符串匹配校验：
- 十进制转十六进制：127.0.0.1 → 0x7f000001；
- 十进制转八进制：127.0.0.1 → 017700000001；
- 省略写法：127.0.0.1 → 127.1（仅最后一段非 0 可省略）、0（等价于 0.0.0.0）；
- IPv6 格式：127.0.0.1 → [::ffff:127.0.0.1]、[::1]；
- 数字格式：127.0.0.1 → 2130706433（十进制整数形式）；
- 域名映射：使用指向内网 IP 的域名（如 attacker.com 解析到 192.168.1.100）。

### 2. 协议绕过
- 若过滤 `http`/`https`，可使用 `HTTPS`（大小写）、`hxxp`（替换字符）；
- 若限制协议，可利用重定向：先请求外网合法域名（如 `http://attacker.com/redirect`），该域名 302 跳转到内网地址；
- 利用 `//` 省略协议：`//192.168.1.100:8080`（默认继承当前页面协议，如 http）。

### 3. 重定向绕过
- 服务器仅校验初始 URL，未校验重定向后的地址：攻击者构造外网 URL，该 URL 跳转至内网地址（如 `http://attacker.com/redirect?to=http://192.168.1.100/admin`）；
- 多层重定向：绕过单次重定向校验，通过多次跳转最终指向内网。

### 4. 特殊域名/主机名绕过
- 使用 `localhost`、`localhost.localdomain` 代替 127.0.0.1；
- 使用内网域名（如 `internal-service:8080`），若服务器可解析内网 DNS，则直接访问；
- 使用短链接（如 tinyurl.com）隐藏真实目标地址。

### 5. 端口绕过
- 若过滤常见内网端口（如 8080、3389），可使用端口的十进制/八进制形式（如 8080 → 017500 → 15776）；
- 利用默认端口省略：`http://192.168.1.100`（默认 80 端口）。

## 六、Java SSRF 的危害场景
### 1. 内网探测与信息收集
- 探测内网存活主机、开放端口（如扫描 192.168.0.0/24 网段的 80、8080、3306 等端口）；
- 访问内网管理后台（如 MySQL、Redis、Elasticsearch、K8s 等的 Web 管理界面），获取敏感配置；
- 读取内网服务的 API 文档、swagger 页面，获取接口信息。

### 2. 敏感数据窃取
- 通过 `file` 协议读取服务器本地文件（配置文件、日志、密钥文件等）；
- 访问内网服务的敏感接口（如 `/api/user/list`、`/api/config`），窃取用户数据、数据库凭证；
- 抓取内网存储的文件（如对象存储、共享文件服务器）。

### 3. 攻击内部系统
- 利用内网服务的未授权访问/弱口令漏洞，执行操作（如 Redis 未授权写公钥、MySQL 执行 SQL）；
- 触发内网服务的漏洞（如内网 JBoss 反序列化漏洞、Tomcat 弱口令）；
- 发起 DoS 攻击：向内网服务发起大量请求，消耗内网资源。

### 4. 代码执行（高危）
- 结合 JNDI 注入：通过 `ldap://`/`rmi://` 协议指向恶意 JNDI 服务器，触发 Java 反序列化漏洞执行代码；
- 若服务器存在其他漏洞（如文件上传、命令执行），SSRF 可作为辅助手段进一步利用。

### 5. 盲 SSRF（无回显场景）
- 服务器无返回结果，但攻击者可通过 DNS 日志、HTTP 日志、延时判断请求是否成功；
- 例如：构造 `http://192.168.1.100:8080`，若服务器响应延时较长，说明该端口开放；
- 利用 `dns` 协议：`dns://attacker.com/192.168.1.100:8080`，攻击者通过 DNS 解析日志确认服务器发起了请求。

## 七、特殊场景：Java 中的盲 SSRF
盲 SSRF 是指服务器未将请求结果返回给攻击者，但攻击者可通过间接方式判断请求是否成功，Java 中典型触发方式：
1. **DNS 日志监控**：构造 `http://[随机字符串].attacker.com`，若攻击者的 DNS 服务器收到该域名的解析请求，说明服务器发起了请求；
2. **延时判断**：向不同内网端口发起请求，根据服务器响应时间判断端口是否开放（开放端口响应快，关闭端口响应慢）；
3. **日志泄露**：若服务器将请求日志输出到可访问的位置（如日志文件、监控平台），攻击者可通过日志获取结果；
4. **第三方回调**：构造请求触发内网服务的回调（如 Webhook），回调至攻击者的服务器，获取内网信息。

## 总结
Java 语言的 SSRF 漏洞本质是用户可控输入进入网络请求逻辑且未做严格校验，其风险覆盖从简单的内网探测到严重的代码执行，且因 Java 生态中多样的网络请求库、灵活的 URL 解析规则、丰富的协议支持，导致 SSRF 场景复杂、绕过方式多样。不同请求库的协议支持、重定向策略进一步增加了漏洞的多样性，而内网服务的普遍存在则放大了 SSRF 的危害。

