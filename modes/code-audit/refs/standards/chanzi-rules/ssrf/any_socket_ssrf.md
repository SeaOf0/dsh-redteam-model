# Java Socket 类型 SSRF 漏洞解析

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_socket_ssrf` · 类别：ssrf · 关键 sink：Socket, connect
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Socket 类型 SSRF 漏洞解析
SSRF（Server-Side Request Forgery，服务器端请求伪造）是攻击者利用服务器端发起未授权请求的漏洞，而 Java 中基于 `java.net.Socket` 及相关套接字 API 实现的网络请求，因设计或编码不当极易触发 SSRF 漏洞。以下从**核心原理、Socket 相关 API 场景、攻击维度、特殊场景变种**四个维度完整描述该漏洞，暂不涉及修复方案。

## 一、核心原理
Java 程序中若通过 `Socket`、`ServerSocket`、`SocketChannel` 等 API 发起网络请求时，未对目标地址/端口做严格校验，攻击者可通过可控参数（如请求参数、配置项、表单数据）篡改请求目标，使服务器向**内网未授权地址、本地回环地址、禁止访问的外部地址**发起套接字连接，从而实现信息探测、端口扫描、内网服务攻击甚至命令执行（依赖内网服务脆弱性）。

Socket 本质是 TCP/UDP 通信端点，Java 对 Socket 的封装（如 `Socket` 类直接建立 TCP 连接）未内置安全校验，完全依赖开发者对目标地址、端口、协议的过滤，这是漏洞产生的核心前提。

## 二、基于 Socket 核心 API 的 SSRF 场景
### 1. 基础 Socket 类（java.net.Socket）场景
`Socket` 是 Java 实现 TCP 客户端的核心类，构造方法直接接收目标地址和端口，若参数可控则直接触发 SSRF：
#### 核心构造方法（可控参数风险点）：
```java
// 场景1：直接传入可控的主机名/IP + 端口
String targetHost = request.getParameter("host"); // 攻击者可控参数
int targetPort = Integer.parseInt(request.getParameter("port"));
Socket socket = new Socket(targetHost, targetPort); // 无校验则触发SSRF

// 场景2：通过InetAddress封装地址（同样可控）
InetAddress addr = InetAddress.getByName(targetHost);
Socket socket = new Socket(addr, targetPort);

// 场景3：指定本地绑定地址（次要，但可被利用绕过源IP限制）
Socket socket = new Socket(targetHost, targetPort, InetAddress.getLocalHost(), 0);
```
#### 攻击行为：
- 攻击者传入 `127.0.0.1:8080` 探测本地服务；
- 传入 `192.168.1.100:3389` 扫描内网 Windows 远程桌面端口；
- 传入 `10.0.0.5:6379` 尝试连接内网 Redis 服务。

### 2. SocketChannel（NIO 套接字）场景
Java NIO 的 `SocketChannel` 是非阻塞式套接字实现，同样存在参数可控风险，且因非阻塞特性易被用于批量端口扫描：
```java
String targetHost = request.getParameter("host");
int targetPort = Integer.parseInt(request.getParameter("port"));
// 打开SocketChannel并连接目标
SocketChannel channel = SocketChannel.open();
channel.connect(new InetSocketAddress(targetHost, targetPort)); // 可控地址+端口
```
#### 特殊风险：
非阻塞模式下，攻击者可通过多线程批量传入内网 IP 段+端口范围，利用 `channel.finishConnect()` 判断端口是否开放，实现高效内网端口扫描。

### 3. ServerSocket 反向 SSRF 场景
`ServerSocket` 用于创建 TCP 服务端套接字，若绑定地址/端口可控，攻击者可：
- 让服务器绑定内网地址（如 `0.0.0.0`），暴露未授权服务；
- 绑定本地高权限端口（如 80/443），抢占系统端口导致服务异常；
- 配合端口转发，将内网服务暴露到公网。
```java
int bindPort = Integer.parseInt(request.getParameter("port"));
String bindHost = request.getParameter("host"); // 可控绑定地址
ServerSocket serverSocket = new ServerSocket(bindPort, 50, InetAddress.getByName(bindHost));
```

### 4. 基于 URLConnection 的 Socket 间接调用
`URLConnection` 底层依赖 Socket 实现网络通信，若 URL 参数可控，即使未直接使用 Socket，也会触发 SSRF：
```java
String url = request.getParameter("url"); // 攻击者传入 http://192.168.1.100:8080
URLConnection conn = new URL(url).openConnection();
conn.connect(); // 底层Socket建立连接
```
#### 扩展场景：
- 支持 `file://` 协议读取本地文件（结合 Socket 权限绕过）；
- 支持 `ftp://`/`gopher://` 等协议，通过 Socket 发送特殊构造的数据包攻击内网服务（如 Redis 未授权访问）。

## 三、Socket SSRF 的攻击维度
### 1. 内网地址探测
攻击者通过遍历内网 IP 段（如 192.168.0.0/24、10.0.0.0/8）+ 常用端口（80、443、3389、6379、8080 等），利用 Socket 连接的超时/成功状态，判断内网存活主机和开放端口：
- 连接成功：返回 `Socket connected` 或响应数据；
- 连接超时/拒绝：返回 `Connection refused` 或超时异常。

### 2. 端口扫描
Java Socket 连接的超时时间可被攻击者利用（默认超时约 30 秒，可通过 `socket.setSoTimeout()` 调整），批量发送连接请求实现内网端口扫描：
```java
// 攻击者可控的IP和端口范围
String[] ips = {"192.168.1.1", "192.168.1.2", "192.168.1.3"};
int[] ports = {80, 443, 8080, 6379};
for (String ip : ips) {
    for (int port : ports) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ip, port), 1000); // 1秒超时
            System.out.println(ip + ":" + port + " open");
            socket.close();
        } catch (Exception e) {
            System.out.println(ip + ":" + port + " closed");
        }
    }
}
```

### 3. 内网服务攻击
#### （1）无授权服务利用
若内网服务（如 Redis、MySQL、Zookeeper）未做权限控制，攻击者可通过 Socket 发送协议数据包实现攻击：
- Redis：发送 `CONFIG SET dir /var/www/html` + `SET xx "\<?php eval($_POST['cmd'])?>"` + `SAVE`，写入 Webshell；
- MySQL：尝试弱密码爆破（通过 Socket 发送 MySQL 认证数据包）。

#### （2）HTTP 服务请求伪造
通过 Socket 直接构造 HTTP 请求，攻击内网 Web 服务（如后台管理系统、未授权 API）：
```java
String target = request.getParameter("target"); // 内网地址：192.168.1.100:8080/admin
Socket socket = new Socket(target.split(":")[0], Integer.parseInt(target.split(":")[1]));
// 构造HTTP POST请求
String request = "POST /admin/addUser HTTP/1.1\r\n" +
                 "Host: 192.168.1.100:8080\r\n" +
                 "Content-Length: 20\r\n\r\n" +
                 "username=attacker&role=admin";
OutputStream os = socket.getOutputStream();
os.write(request.getBytes());
os.flush();
// 读取响应，获取攻击结果
InputStream is = socket.getInputStream();
// ...
```

### 4. 本地服务攻击（Loopback 地址）
攻击者利用 `127.0.0.1`/`localhost`/`0.0.0.0` 等回环地址，通过 Socket 攻击服务器本地服务：
- 攻击本地 Redis（127.0.0.1:6379）；
- 读取本地敏感文件（结合 `file://` 协议 + Socket 权限）；
- 攻击本地未授权的管理后台（如 127.0.0.1:8080/console）。

### 5. 绕过防火墙/安全组
#### （1）地址绕过
- 利用 IP 进制转换：将 `192.168.1.1` 转为八进制 `0300.0250.01.01`、十六进制 `0xC0A80101`，绕过简单的字符串匹配过滤；
- 利用域名解析：构造恶意域名（如 `internal.server.attacker.com`）解析到内网 IP，绕过 IP 黑名单。

#### （2）端口绕过
- 利用端口别名：如 `80` 对应 `http`，`443` 对应 `https`，部分程序仅过滤数字端口，可通过别名绕过；
- 利用端口范围：部分程序仅限制常用端口，攻击者使用非常规端口（如 8081、65534）发起请求。

#### （3）协议绕过
- 利用 `gopher://` 协议封装 TCP 数据包，绕过 HTTP 协议限制，直接通过 Socket 发送任意数据；
- 利用 `ftp://` 协议的被动模式，让服务器主动连接内网 FTP 服务，实现反向 SSRF。

## 四、特殊场景变种
### 1. 被动 Socket SSRF
服务器通过 `ServerSocket` 监听端口，接收外部连接后，转发请求到内网地址（如反向代理），若转发目标可控，则触发被动 SSRF：
```java
// 服务器监听端口，接收攻击者的连接请求
ServerSocket serverSocket = new ServerSocket(8888);
Socket clientSocket = serverSocket.accept(); // 接收攻击者连接
// 攻击者可控的转发目标
String forwardHost = request.getParameter("forwardHost");
int forwardPort = Integer.parseInt(request.getParameter("forwardPort"));
// 建立到内网目标的Socket连接，转发数据
Socket targetSocket = new Socket(forwardHost, forwardPort);
// 转发客户端数据到目标服务
new Thread(() -> {
    try (InputStream in = clientSocket.getInputStream(); OutputStream out = targetSocket.getOutputStream()) {
        byte[] buffer = new byte[1024];
        int len;
        while ((len = in.read(buffer)) != -1) {
            out.write(buffer, 0, len);
        }
    } catch (Exception e) {}
}).start();
```

### 2. 带认证的 Socket SSRF
若 Socket 连接需要基础认证（如 HTTP Basic Auth），攻击者可通过构造包含认证信息的请求，绕过认证限制：
```java
String target = request.getParameter("target"); // 如 http://admin:password@192.168.1.100:8080
URL url = new URL(target);
Socket socket = new Socket(url.getHost(), url.getPort());
// 构造带认证的请求头
String auth = Base64.getEncoder().encodeToString("admin:password".getBytes());
String request = "GET / HTTP/1.1\r\nAuthorization: Basic " + auth + "\r\n\r\n";
socket.getOutputStream().write(request.getBytes());
```

### 3. 超时配置不当导致的放大攻击
若开发者未设置 Socket 超时时间（`setSoTimeout`），攻击者可发送大量指向不存在内网地址的请求，导致服务器大量 Socket 连接处于阻塞状态，耗尽系统文件描述符，引发 DoS 攻击：
```java
// 无超时设置，连接不存在的内网地址会阻塞30秒以上
Socket socket = new Socket("192.168.99.99", 80); // 阻塞直至超时
```

### 4. UDP Socket SSRF
Java `DatagramSocket` 用于 UDP 通信，虽无 TCP 连接的“建立/拒绝”状态，但仍可用于内网 UDP 服务探测（如 DNS、SNMP、NTP）：
```java
String targetHost = request.getParameter("host");
int targetPort = Integer.parseInt(request.getParameter("port"));
DatagramSocket socket = new DatagramSocket();
// 发送UDP数据包到内网DNS服务器
byte[] data = "test".getBytes();
DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName(targetHost), targetPort);
socket.send(packet);
// 接收响应，判断服务是否存在
byte[] buf = new byte[1024];
DatagramPacket response = new DatagramPacket(buf, buf.length);
socket.receive(response); // 超时则判断服务不可达
```

## 总结
Java Socket 类型 SSRF 的核心风险在于**网络请求目标参数未校验**，覆盖 TCP/UDP、阻塞/非阻塞、客户端/服务端等所有 Socket 应用场景，且可通过协议封装、地址绕过、端口扫描等方式扩展攻击范围，不仅能探测内网信息，还能直接攻击内网脆弱服务，甚至引发 DoS 或权限提升。其攻击面覆盖 Socket 核心 API、底层依赖 Socket 的高层通信类（URLConnection）、被动转发场景等，是 Java 服务端网络编程中最典型的 SSRF 漏洞类型之一。


