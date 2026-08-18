---
name: http3-quic-attacks
description: >-
  HTTP/3 and QUIC attack surface: protocol basics, h3 FIN/EOM desync, QPACK table poisoning,
  QUIC request smuggling (CVE-2026-33555 zero-byte packet desync), pseudo-header injection,
  and detection criteria. Use when the target advertises Alt-Svc: h3 or serves HTTP/3.
---

# HTTP/3 / QUIC 协议攻击面与走私 — 完整攻防手册

> **AI LOAD INSTRUCTION**: Use this skill when a target supports HTTP/3 (check
> `Alt-Svc: h3=":443"` or `h3-<ver>`). HTTP/3 runs over QUIC (UDP), so classic TCP-based WAFs and
> smuggling techniques do **not** apply the same way — the attack surface is the HTTP/3 *stream*
> framing (`FIN`/`EOM`), QPACK header compression state, and QUIC packet coalescing. Authorized
> targets only. Companion files: [http2-specific-attacks.md](./http2-specific-attacks.md),
> [web-request-smuggling.md](../web/web-request-smuggling.md).

---

## 0. 快速识别

```bash
# 探测 HTTP/3 支持（curl 需编译 h3，通常带 --http3）
curl --http3 -I https://target.example.com/

# 或看 Alt-Svc 头（普通 curl）
curl -sI https://target.example.com/ | grep -i alt-svc
# Alt-Svc: h3=":443"; ma=86400
```

- 响应头含 `Alt-Svc: h3` = 支持 HTTP/3。
- 仅 TCP 抓包看不到 QUIC 流量，需 UDP 443 抓包（Wireshark 有 `quic`/`http3` dissector）。

---

## Part A：攻击方法论

### 1. 协议原理（最小背景）

| 概念 | 说明 |
|---|---|
| QUIC | 基于 UDP 的传输层；连接由 `connection ID` 标识，不依赖 4 元组 |
| 流（stream） | QUIC 连接内的独立双向字节流；HTTP/3 每个请求/响应占一个流 |
| HTTP/3 帧 | `HEADERS`、`DATA`、`SETTINGS`、`GOAWAY`、`CANCEL_PUSH` 等 |
| FIN（流层） | 流数据结束位（QUIC STREAM 帧 `FIN` 标志） |
| EOM（应用层） | HTTP/3 `DATA` 帧里「End Of Message」隐含在最后一个 DATA 帧（流 FIN） |
| QPACK | HTTP/3 的头部压缩（HPACK 的 QUIC 版本），用动态表 + 静态表 |
| 伪头 | `:method`、`:path`、`:authority`、`:scheme`、`:status` |

**核心差异**：HTTP/1.1 用 `Content-Length`/`Transfer-Encoding` 划分消息边界；HTTP/3 用
**流边界（FIN）** 划分。当「前端代理（H3 终结者）→ 后端（H1/H2）翻译」时，`FIN`/`EOM`
语义与后端 `Content-Length`/帧边界的**翻译不一致**就是走私/desync 的根。

### 2. h3 FIN / EOM desync（nullrabbit 研究）

#### 2.1 原理

- 前端把 HTTP/3 请求翻译为后端 HTTP/1.1 时，需要给后端补一个 `Content-Length`（或 chunked）。
- 若翻译器依赖「流的 FIN」判断消息结束，而**流在 DATA 全部发出前/后**发送 FIN 的时序与后端
  解析器预期不一致，就可能在前后端之间「多出/少掉」一段字节，造成请求边界错位（desync）。
- 攻击者可通过**提前 FIN、延迟 FIN、把 FIN 与 EOM 分离**制造前后端对「这个请求在哪结束」的分歧。

#### 2.2 构造步骤

```
1. 与前端建立 QUIC 连接（HTTP/3）
2. 在同一个 QUIC 连接里打开流，发送 HEADERS + 部分 DATA
3. 在「后端以为消息已结束」的时机发 STREAM FIN，但把剩余 DATA 通过
   同一连接的其他流 / 后续帧送达
4. 观察后端把剩余字节当作下一个请求的前缀（smuggled prefix）
```

#### 2.3 判据

- 后端对「被走私前缀」的响应与正常请求不同（例如第二个请求被前缀污染，返回 404/异常）。
- 用 `Alt-Svc: h3` 确认是 H3 路径，排除 H1/H2 走私干扰。

> 来源：nullrabbit.ai — "The h3 FIN/EOM desync"（审计 §7）。

### 3. QPACK 表投毒 / desync

#### 3.1 原理

- QPACK 用**动态表**缓存已见头部；解码方按表索引还原头。
- 若前后端各自维护的 QPACK 动态表**状态不一致**（例如某些帧在翻译过程中被丢弃/重放，
  或表项引用序号错位），解码出的头部就会「错位」——前端看到一个头，后端解出另一个头
  （表投毒）。
- 这种不一致可被利用来让后端看到前端没看到的 `:path`/`content-length` 语义（desync）。

#### 3.2 构造步骤

```
1. 建立 H3 连接，先发送一组头部填充 QPACK 动态表
2. 制造「表更新帧」与「引用该表项的 HEADERS 帧」的乱序/重复（利用 QUIC 帧可重传/乱序特性）
3. 使前端翻译器与后端 QPACK 解码器对同一索引解析出不同头部
4. 若解析差异落在 :method/:path/content-length 上 → 走私
```

#### 3.3 工具

- **tetsuo-h3sec**（`github.com/tetsuo-ai/tetsuo-h3sec`）—— HTTP/3 QPACK desync 扫描器。
- 用法思路：对目标发起 QPACK 表状态探测，报告是否存在前后端表状态不一致。

#### 3.4 判据

- 扫描器报告 QPACK desync 候选；再手工用「表投毒后二次请求」验证后端是否解析出被污染的头部。
- 来源：tetsuo-ai/h3sec（审计 §7）。

### 4. QUIC 走私（CVE-2026-33555 零字节包 desync）

#### 4.1 原理

- CVE-2026-33555（HAProxy 相关）利用**零字节 QUIC 包 / 空 STREAM 帧**的解析差异。
- 攻击者发送一个「合法但字节数为 0」的 QUIC 包（或空流），前端与后端对其「是否算一个完整
  请求边界」判断不同，导致后续真实请求的字节被并入前一个请求（或反之），形成走私。

#### 4.2 构造步骤

```
1. 定位「前端 QUIC 终结 → 后端 HTTP」的翻译器（如 HAProxy）
2. 发送零字节/空 STREAM 包制造边界分歧
3. 紧随其后发送受害者/攻击者请求
4. 后端把空包与后续请求拼成不同消息 → 走私
```

#### 4.3 判据

- 复现「第二个请求响应被前缀污染」，且升级到不受影响版本后现象消失。
- 来源：r3verii/CVE-2026-33555（审计 §7）。

### 5. 伪头注入与其他面

- **伪头注入**：`:method`/`:path` 里塞入后端 H1 翻译时不合法的字符（换行、`Content-Length` 名），
  翻译器未严格校验时可能注入 H1 头。
- **UDP 层面绕过 TCP-only WAF**：很多 WAF 只挂 TCP 443，H3 走 UDP 443 直接穿透（这也是「QUIC
  绕 WAF」的朴素来源，见 `web-file-handling.md` 注记）。
- **连接迁移**：QUIC 支持 connection ID 迁移，攻击者可切换源 IP 保持连接，干扰按 IP 的信誉/限速。

---

## Part B：检测与防御

### 6. 检测

- 监控 UDP 443 上 QUIC 流量（很多组织只监控 TCP）。
- 对 H3 终结器与后端各做「消息边界」日志，比对 `content-length`/流 FIN 的翻译是否一致。
- 关注「零字节/空 STREAM 帧、异常 FIN 时序、QPACK 表引用越界」等异常模式。

### 7. 修复

| 措施 | 说明 |
|---|---|
| 前后端使用同一 HTTP 版本 | 避免 H3→H1 翻译引入边界歧义 |
| 翻译器严格校验 FIN/EOM 与 Content-Length 一致 | 不允许「流未 FIN 就发完整 Content-Length」等歧义 |
| QPACK 表状态严格同步 | 拒绝越界/乱序表引用 |
| 升级受影响组件 | CVE-2026-33555 等按厂商公告升级 |
| 对 H3 与 TCP 同等监控 | 不在 UDP 443 留盲区 |

> 来源：nullrabbit.ai（h3 FIN/EOM desync）、tetsuo-ai/h3sec、r3verii/CVE-2026-33555（审计 §7）。
> 本文为原理重构与通用构造步骤，未整篇搬运外部原文。
