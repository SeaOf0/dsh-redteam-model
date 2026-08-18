# WAF / IDS / C2 网络层规避 — 完整手册

> 本文件为 `evasion-comprehensive.md` §5 的伴生手册（补齐「Full WAF/IDS bypass guide」断链）。
> 覆盖 Web 应用层 + 网络层 + C2 流量的**原理 → 实现 → 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`；TLS 指纹/C2 协议深补见 `PROTOCOL_EVASION.md`。

## 0. 分层模型

```
应用层 WAF（正则/语义） → 网络 IDS/IPS（特征） → NDR（TLS 指纹/流量基线） → 行为
```

---

## 1. WAF 绕过（应用层）

### 1.1 编码绕过

| 编码 | 示例 | 目标 |
|---|---|---|
| URL | `%27` → `'` | 字符串匹配 |
| 双重 URL | `%2527` → `'` | 解码一次 WAF |
| Unicode | `%u0027` → `'` | IIS + 部分 WAF |
| HTML 实体 | `&#39;` → `'` | 上下文相关 |
| Base64 | `Jw==` → `'` | 应用层解码 |
| Hex | `0x27` → `'` | SQL 上下文 |
| 注释拆分 | `SEL/**/ECT` | SQL 关键字 |

### 1.2 路径/方法绕过

```bash
# 路径归一化
/admin/  //admin//  /./admin/  /admin..;/  /%61dmin
# 大小写
/ADMIN /Admin /aDmIn
# HTTP 方法切换
GET -> POST/PUT/PATCH/OPTIONS/TRACE
# 头部覆盖（代理/框架解析差异）
X-Original-URL: /admin
X-Rewrite-URL: /admin
# 主机/IP 覆盖
X-Forwarded-For: 127.0.0.1
X-Real-IP: localhost
```

### 1.3 参数污染/分片

```bash
# 参数污染：同名参数多个值，后端取最后一个
?id=1&id=1' OR '1'='1
# 分片：payload 拆多参数，服务端拼装
?a=sel&b=ect&c=+1
```

### 1.4 检测侧

| 技术 | 检测点 |
|---|---|
| 编码 | 解码后二次匹配（WAF 递归解码） |
| 路径绕过 | 归一化后匹配 + 语义分析 |
| 参数污染/分片 | 参数完整性校验 + 拼装后检测 |

---

## 2. IDS/IPS 绕过（网络层）

### 2.1 分片/分段

```bash
# IP 分片：把 payload 拆到多个分片，绕过只看单包的特征匹配
# TCP 分段：把攻击串拆到多个 TCP 段
```

### 2.2 协议混淆

- **HTTP/2 → HTTP/1.1 降级**：绕过只解析单一协议的 IDS。
- **TLS 之上再做应用层加密**：IDS 只能看密文，特征失效。
- **DNS over HTTPS**：把 DNS 查询藏进 HTTPS，绕过 DNS 监控。

### 2.3 检测侧

| 技术 | 检测点 |
|---|---|
| 分片 | IDS 重组后再匹配（现代 IDS 已支持） |
| 协议混淆 | 协议解析广度 + NDR 加密流量基线 |
| DoH | NDR 对 DoH 端点的 TLS 指纹 + 频率 |

---

## 3. C2 网络规避（速查，深补见 PROTOCOL_EVASION.md）

### 3.1 流量整形

- **包大小**：控制在正常范围（避免超大/超小异常包）。
- **抖动**：beacon 间隔加随机抖动，避免固定节拍。
- **URI 结构**：仿正常网站路径（`/api/v1/report` 而非 `/beacon`）。

### 3.2 TLS 指纹

- **JA3/JA3S**：客户端/服务端 TLS 握手指纹，伪造匹配浏览器（uTLS/ja3transport）。
- **JA4/JA4+**：JA3 的下一代（含 QUIC/HTTP2 指纹），见 `PROTOCOL_EVASION.md`。

### 3.3 检测侧

| 技术 | 检测点 |
|---|---|
| 流量整形 | 流量基线（包大小/频率/URI 熵） |
| TLS 指纹 | NDR JA3/JA4 被动指纹比对 |
| 域前置 | SNI/Host 不一致检测（见 PROTOCOL_EVASION.md） |

---

## 4. 检测侧总表（回馈 attack-defense）

| 层 | 检测点 | 判据 |
|---|---|---|
| WAF | 解码/归一化后语义 | 递归解包命中 |
| IDS | 重组 + 协议解析 | 分片重组命中 |
| NDR | TLS 指纹 + 流量基线 | JA3/JA4 异常 + 体积/频率异常 |
| C2 | 域前置/隧道 | SNI/Host 不一致 + 隧道熵 |

## 5. 实测判据

| 判据 | 方法 |
|---|---|
| 是否绕过 WAF | 目标请求返回 200 且未被拦截 |
| 是否绕过 IDS | 抓包确认攻击串分片/加密后不可见 |
| 是否暴露 C2 | NDR 工具对流量打 JA3/JA4 指纹比对浏览器基线 |

*WARNING: 授权红队评估与安全研究专用。*
