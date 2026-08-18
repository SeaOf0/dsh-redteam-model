---
name: graphql-and-hidden-parameters
description: >-
  GraphQL and hidden parameter testing playbook: introspection, alias/rate-limit bypass, batching,
  persisted query abuse, field suggestion abuse, DoS amplification, and hidden parameter discovery.
  Use when GraphQL exists or REST docs suggest optional/undocumented fields.
---

# SKILL: GraphQL 深度滥用与隐藏参数 — 完整攻防手册

> **AI LOAD INSTRUCTION**: Use this skill when GraphQL exists or REST documentation suggests optional,
> deprecated, or undocumented fields. Covers schema discovery, alias-based rate-limit bypass,
> introspection → field enumeration, persisted-query abuse, field-suggestion abuse, batching depth,
> and DoS amplification. Authorized targets only. Companion:
> [api-authorization-and-bola.md](./api-authorization-and-bola.md).

---

## 0. 快速识别

```http
POST /graphql HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"query":"{ __typename }"}
```

- 端点常见于 `/graphql`、`/api/graphql`、`/v1/graphql`、`/query`、`/gql`。
- `Content-Type: application/graphql` 直接放 query 字符串也是合法变体。
- GET 携带 `?query={...}`（有的实现同时支持 GET 与 POST）。

---

## Part A：攻击方法论

### 1. 内省（Introspection）→ 字段枚举

#### 1.1 标准内省

```graphql
query {
  __schema {
    queryType { name }
    types { name kind }
    mutationType { name }
    subscriptionType { name }
  }
}
```

#### 1.2 定向类型/字段枚举

```graphql
query {
  __type(name: "User") {
    name
    fields { name type { name kind ofType { name kind } } }
  }
}
```

#### 1.3 内省被禁时的枚举手段

- **字段建议（field suggestion）**：发送一个**不存在的字段**，错误信息常泄露「你是否想输入 X」：

```graphql
query { usr { id } }   # 错误: "Did you mean 'user'?"
```

- **类型提示**：发送错误类型名，错误信息可能列出相近类型。
- **`__type(name:"...")` 探测**：已知类型名逐一探测字段。
- **JS/mobile bundle 提取**：前端打包里的 GraphQL 查询字符串是最全的 schema 线索。

**判据**：能枚举出 schema 中「文档未公开」的字段/类型，即内省泄露升级；进一步用这些字段做
BOLA/越权（见 api-authorization-and-bola.md）。

### 2. Alias 批量绕过限速

GraphQL 的 **alias（别名）** 允许一次请求重复同一字段多次，绕过「每个字段/每请求一次」的限速。

```graphql
# 限速只数 "1 个 login 字段"，但实际执行 100 次
query {
  a1: login(user:"u", pass:"p1") { token }
  a2: login(user:"u", pass:"p2") { token }
  # ... a100
}
```

**判据**：单请求内 100 次 `login` 都返回独立结果（或独立错误，可用于口令爆破/枚举），说明限速
按「字段名」而非「实际执行次数」计数。

**变体**：alias 绕过「每请求一个 mutation」的限制，一次性批量执行敏感 mutation。

### 3. Batching 深度

#### 3.1 数组批处理

```json
[
  {"query":"query { user(id: 1) { name } }"},
  {"query":"query { user(id: 2) { name } }"}
]
```

- 批处理可把多个 IDOR 探测压进一个请求，绕过「每请求一次」的鉴权/限速。
- 部分实现把批处理里的每个请求**独立鉴权**，部分**共享一次鉴权**——共享鉴权的实现更容易越权。

#### 3.2 判据

- 数组里的第 2 个请求用受害者 ID 返回数据 = IDOR；若限速器只看到 1 个 HTTP 请求 = 限速绕过。

### 4. Persisted Query 滥用

Persisted query：客户端只发 `queryId`/`sha256Hash`，服务端按 ID 查已注册查询。

```json
{"id":"a1b2c3...","variables":{"id":1}}
```

滥用面：

- **ID 枚举**：爆破/遍历 `id` 找管理员预注册的高权限查询。
- **未注册查询拒绝但泄露 schema**：错误信息可能透露已注册查询列表。
- **变量注入**：persisted query 本身固定，但 `variables` 可控 → 把恶意值注入变量（IDOR/注入）。
- **hash 碰撞/别名**：某些实现允许 `id` 或 `query` 二选一，绕过「只允许 persisted」的限制直接发任意 query。

**判据**：通过 `id` 枚举触发管理员查询或通过 `variables` 越权，即 persisted query 滥用成立。

### 5. 字段建议滥用（Schema 泄露）

- 字段建议本是 UX 功能，但**等价于内省泄露**：逐个猜字段名，用「Did you mean」回显确认存在。
- 自动化：字典爆破字段名，根据错误回显逐步拼出完整 schema。

**判据**：在内省关闭时，仍能通过字段建议重建 schema。

### 6. DoS 放大

- **深层嵌套查询**（资源放大）：

```graphql
query {
  user(id:1) { posts { comments { author { posts { comments { author { ... } } } } } } }
}
```

- **宽字段 fan-out**：`user(id:1) { friends { friends { friends { ... } } } }` 指数放大。
- **循环类型**：利用 `User -> Post -> User` 的循环关系构造无限深。
- **大字段**：请求返回超大字符串/文件字段反复。

**判据**：请求导致后端 CPU/内存显著上升、超时或 OOM = DoS 放大（GraphQLArmor 研究覆盖的
深度限制绕过：`max_depth`/`cost` 分析未启用或被别名/碎片绕过）。

### 7. 隐藏参数发现（REST 侧）

- 字段出现在 admin 文档但不在 public 文档。
- `additionalProperties` 或宽松 schema 允许未知字段。
- 前端代码用比 UI 更丰富的请求体。
- 移动端端点携带 `role`、`org`、`feature-flag`、`internal` 过滤字段。

---

## Part B：检测与防御

### 8. 检测

- 内省请求特征：`__schema`/`__type`/`__typename` 在 body 中高频出现。
- alias 批量：单请求内同名字段大量重复。
- 深层嵌套：query 的 AST 深度/节点数异常。
- persisted query：`id` 枚举与未注册 `query` 混用。

### 9. 修复（OWASP GraphQL CheatSheet / GraphQLArmor 对齐）

| 措施 | 说明 |
|---|---|
| 生产关闭内省 | 或按角色白名单内省 |
| 禁用字段建议 | 关闭「Did you mean」泄露 |
| 查询复杂度分析 | `max_depth`、`cost`、节点数限制（GraphQLArmor 等中间件） |
| 持久化查询白名单 | 只允许已注册 `id`，拒绝任意 `query` |
| 批处理/alias 限速 | 按「实际执行次数」而非请求数限速 |
| persisted query 变量校验 | 变量也做鉴权与注入防护 |
| 关闭循环类型放大 | 类型图里限制环与 fan-out 深度 |

### 10. NEXT ROUTING

- 字段影响权限：见 [api-authorization-and-bola.md](./api-authorization-and-bola.md)
- batching 改变鉴权/限速：见 [api-auth-and-jwt-abuse.md](./api-auth-and-jwt-abuse.md)
- 端点发现不全：见 [api-recon-and-docs.md](./api-recon-and-docs.md)

> 参考：OWASP GraphQL CheatSheet、GraphQLArmor 绕过研究（深度限制/别名/批处理滥用）。
> 本文为方法论重构，未整篇搬运外部原文。
