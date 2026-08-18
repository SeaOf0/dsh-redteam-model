---
name: grpc-security
description: >-
  gRPC attack surface: protobuf deserialization, server reflection abuse, field smuggling,
  deadline/metadata abuse, and gRPC-Web downgrade. Use when the target exposes gRPC (protobuf)
  or gRPC-Web endpoints.
---

# SKILL: gRPC 安全

> **AI LOAD INSTRUCTION**: This skill covers gRPC protocol basics, server reflection disclosure,
> protobuf deserialization, field smuggling, metadata/deadline abuse, and gRPC-Web downgrade.
> Apply only in **authorized** tests. Companion: [api-recon-and-docs.md](./api-recon-and-docs.md),
> [protocol-reverse](../web/web-api-security.md).

---

## 0. 快速识别

- gRPC 走 HTTP/2，`Content-Type: application/grpc`（或 `application/grpc+proto`）。
- 端点常为 `POST /<package>.<Service>/<Method>`。
- gRPC-Web 走 `application/grpc-web`（或 `+proto`），浏览器直连。

```bash
# grpcurl 探测（需服务端开启反射）
grpcurl -plaintext target.example.com:50051 list
grpcurl -plaintext target.example.com:50051 describe <Service>
```

---

## Part A：攻击方法论

### 1. 服务端反射泄露（Reflection）

#### 1.1 原理

gRPC **server reflection** 允许客户端列出全部服务/方法/schema，本是调试功能，暴露即等价于
「接口内省泄露」——攻击者无需 proto 文件即可枚举攻击面。

#### 1.2 利用

```bash
# 列出服务
grpcurl -plaintext target.example.com:50051 list
# grpc.reflection.v1alpha.ServerReflection
# myapp.UserService

# 列出方法
grpcurl -plaintext target.example.com:50051 list myapp.UserService
# myapp.UserService.GetUser
# myapp.UserService.UpdateUser

# 描述 schema
grpcurl -plaintext target.example.com:50051 describe myapp.UserService

# 直接调用
grpcurl -plaintext -d '{"id":1}' target.example.com:50051 myapp.UserService/GetUser
```

**判据**：`list` 返回业务服务名 = 反射开启；进一步用 `describe` 拿字段做参数化测试。

### 2. Protobuf 反序列化与字段走私

#### 2.1 原理

Protobuf 用「字段号 + wire type + 值」编码，**字段号冲突/未知字段**在反序列化时可能被
「合并/覆盖/忽略」，前后端（或不同语言实现）对**未知字段**的处理不一致 → 字段走私。

#### 2.2 构造

```python
# 用 protobuf-inspector / protoc --decode_raw 还原结构后手工改字段
echo "0a0541646d696e" | xxd -r -p | protoc --decode_raw
# 1: "Admin"
```

- **字段走私**：发送前端 schema 之外的字段号，观察后端是否把它并入逻辑判断（如把
  `field 2 = role` 塞进 `field 2 = id` 的请求）。
- **wire type 混淆**：把 `varint` 字段发成 `length-delimited` 字符串，触发解析差异/注入。
- **未知字段回显**：后端把未知字段原样存/回显 → 数据泄露/注入面。

**判据**：发送非法/未知字段号后，后端行为改变（越权/报错泄露字段结构）= 字段走私/反序列化漏洞。

### 3. Metadata 滥用

- gRPC metadata（头部键值对）承载鉴权（`authorization`）与路由信息。
- **大小写/重复键**：某些实现把 metadata key 大小写归一化不一致，重复 key 后取值歧义 → 绕过。
- **伪头注入**：`:path`/`:authority` 可被 gRPC-Web 或降级层污染。

**判据**：重复/大小写变体 metadata 改变鉴权或路由结果。

### 4. Deadline / 流控滥用

- gRPC 的 **deadline/超时** 与 **流式**（streaming）调用可被滥用：
  - 取消/超时后仍发送数据，触发后端「已取消请求」处理不一致。
  - 慢流（slowloris 式）占满连接。
- **判据**：超时/取消后服务端资源未释放，或慢流导致连接耗尽。

### 5. gRPC-Web 降级面

- gRPC-Web 把 gRPC 降级为「HTTP/1.1 可达」的 `application/grpc-web`，常由 Envoy/代理翻译。
- 降级翻译层是**走私/解析差异**高发地：`Content-Type` 变体（`+proto`/`+json`）、trailer 翻译、
  二进制帧边界。
- **判据**：通过 gRPC-Web 发「降级层翻译后与原 gRPC 语义不同」的请求，改变后端行为。

---

## Part B：检测与防御

### 6. 检测

- 反射接口是否在生产开放（`grpcurl list` 非空即暴露）。
- 监控未知/异常字段号、wire type 混淆、重复 metadata key。
- 关注 deadline/取消后的资源释放与慢流。

### 7. 修复

| 措施 | 说明 |
|---|---|
| 生产关闭反射 | 反射仅内网/调试环境开放 |
| 严格校验字段 | 未知字段按策略处理（丢弃/拒绝），不并入逻辑 |
| metadata key 归一化 | 统一大小写/去重，避免取值歧义 |
| 校验 wire type | 拒绝类型不匹配字段 |
| 流控与 deadline | 限制流大小/时长，取消后释放资源 |
| 降级层严格翻译 | gRPC-Web 翻译不引入语义差异 |

---

## 8. RELATED ROUTING

- [api-recon-and-docs.md](./api-recon-and-docs.md) — API 侦察与文档
- [websocket-security.md](./websocket-security.md) — 二进制消息反序列化（同类思路）
- [protocol-reverse](../web/web-api-security.md) — protobuf/gRPC 还原（gRPC C4 节）
