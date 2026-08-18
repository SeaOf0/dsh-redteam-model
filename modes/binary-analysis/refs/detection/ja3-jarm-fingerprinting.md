# JA3 / JARM 指纹体系（TLS 客户端/服务端指纹识别）

> 定位：补「网络侧指纹」专项——JA3/JA3S（被动 TLS 指纹）与 JARM（主动 TLS 服务端指纹），
> 用于 C2 基础设施识别、恶意 TLS 流量归类、家族/工具归因。
> 此前仅在 malware-analysis-methodology.md 与 C2 通信节提过一句「JA3/JARM」，本篇给完整体系与可执行用法。
> 工具按检测制：`command -v` 探测 tshark/zeek/jarm/ja3，缺失走四级兜底。

---

## 0. 三者分工

| 指纹 | 采集方式 | 识别对象 | 典型用途 |
|---|---|---|---|
| JA3 | 被动（抓包） | TLS 客户端（ClientHello 特征） | 识别恶意软件 TLS 客户端/C2 客户端 |
| JA3S | 被动（抓包） | TLS 服务端（ServerHello 特征） | 配合 JA3 双端归类 |
| JARM | 主动（探测） | TLS 服务端（10 个探测包响应） | 主动识别 C2 服务器（无需客户端流量） |

---

## 1. JA3 / JA3S

### 原理

JA3 = MD5（TLS 版本 + 密码套件列表 + 扩展列表 + 椭圆曲线 + 椭圆曲线格式）。
JA3S = MD5（TLS 版本 + 选中的密码套件 + 扩展列表）。

### 采集（被动）

```bash
# tshark（检测后使用，含 ja3 字段）
tshark -r capture.pcap -Y tls.handshake.type==1 \
  -T fields -e tls.handshake.ja3 -e tls.handshake.ja3s -e ip.src -e ip.dst

# zeek（含 JA3 插件）
zeek -r capture.pcap
# 输出 conn.log / ssl.log 含 ja3/ja3s 字段
```

输出解读：相同恶意软件家族/工具的 TLS 客户端产生稳定 JA3（库版本不变则指纹不变），可做归类与关联。

判据：恶意样本的 JA3 与已知家族/工具的 JA3 库匹配 → 家族/工具归因；同一 JA3 的多个 C2 → 同源关联。

---

## 2. JARM

### 原理

JARM 主动向目标发送 10 个「构造的 ClientHello」探测包（变换密码套件/版本/扩展），
对每个 ServerHello 响应取特征，拼接后 SHA256 → 64 字符指纹。相同 TLS 服务端栈产生相同 JARM。

### 采集（主动）

```bash
# jarm（Salesforce，pip/仓库获取）
pip install pyjarm          # 或按官方 README
jarm <host>:<port>
# 输出 64 字符 JARM 指纹

# python 库用法
python3 -c "import jarm; print(jarm.scan('example.com', 443))"
```

输出解读：JARM 指纹对应「服务端 TLS 实现栈」——Cobalt Strike 等 C2 框架的默认 TLS 配置有已知 JARM 指纹，
可主动识别 C2 服务器（无需客户端流量，不受客户端加密影响）。

判据：目标 JARM 命中已知 C2 框架（Cobalt Strike/Sliver 等）指纹库 → C2 判定（结合其他证据，不单点定性）。

---

## 3. 应用场景

### 3.1 C2 基础设施识别

```text
1. 从样本提取 C2 地址（配置提取，见 malware-config-extraction.md）。
2. JARM 主动扫描 C2 → 命中已知恶意 TLS 指纹。
3. 流量侧 JA3/JA3S 关联客户端↔服务端。
```

### 3.2 家族/工具归因

```text
- 同一恶意工具（如某 RAT 的 TLS 客户端）→ 稳定 JA3。
- 多个样本共享 JA3 → 同源/同工具链关联。
```

### 3.3 检测规则

```text
- Zeek/Suricata 规则：命中已知恶意 JA3/JARM 即告警。
- 与自签证书指纹（恶意配置里的 Certificate 字段）互补。
```

---

## 4. 局限与判据

| 局限 | 对策 |
|---|---|
| JA3 可被客户端伪造/随机化 | 结合 JARM（服务端）+ 证书 + 行为多证据 |
| JARM 会扰动目标（主动 10 包） | 授权范围内 + 记录探测时间（最小影响） |
| 指纹库需持续更新 | 命中是「相似」，不是「实锤」；多证据交叉 |

判据：任何指纹命中只作「线索」，须与样本配置/行为/证书等互证后才定性（persona 硬规则：单指标不下结论）。

---

## 来源与延伸

- JARM（Salesforce）：https://github.com/salesforce/jarm
- JA3（Salesforce）：https://github.com/salesforce/ja3
- C2 通信分析与配置提取：`methodology/malware-analysis-methodology.md`（C2 节）、`methodology/malware-config-extraction.md`。
- 恶意配置的自签证书字段（TLS 指纹关联）：`malware-config-extraction.md` §4。
