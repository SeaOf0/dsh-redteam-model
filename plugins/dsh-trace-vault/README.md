# dsh-trace-vault 过程库

九个安全模式的过程留痕与检索面：自动捕获每一次工具调用，跨 compaction 可检索。

## 做什么

- **自动留痕**：监听 `session/event` 的 `tool/call` + `tool/result`（callId 配对），
  九个安全模式会话的每次调用落 SQLite（`~/.dsh/trace-vault/traces.db`）：
  调用参数、结果文本、出局分类、耗时。零行为改变——不拦截、不改写、不注入。
- **过程检索**（模型工具）：`trace_search`（关键词子串命中参数/响应）、
  `trace_get`（按 id 取全文）、`trace_recent`（最近调用+出局统计）。
- **失败归因信封（v0.2.0）**：每轮装配重渲染本会话近 30 分钟的 blocked 聚集，
  ≥2 次时投一行提示（换路径/降速/换 UA + 指引 trace_search 检索拦截原文）；
  无信号/信号未变时零 token（变化才投，与 route-boost 同机制）。

## 定位与边界

- **索引不是归档**：args 落库截 8K、result 截 32K，全文在会话 transcript；
  检索命中后按 id 取回的是截断内全文。
- **与战役记忆分工**：campaign-memory 存成果（结构化打法），trace-vault 存
  原始调用流（未成形的观察——某次报错、拦截页、回显）。
- **仅安全模式入库**：其余会话零捕获。本地库不做脱敏（过程证据的价值所在）。
- **LIKE 检索**：子串语义、跨机器行为一致；量级上来后升级 FTS5 trigram，接口不变。

## 配置

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `capture` | `true` | 事件捕获开关 |
| `tools` | `true` | 模型工具注册开关 |
| `envelope` | `true` | 失败归因信封节开关（v0.2.0） |
| `retentionDays` | `14` | 保留天数（开库与每 200 次写入时清理） |
| `maxRows` | `50000` | 总量上限（超限最旧淘汰） |

## 测试

`node test/run.mjs`——分类器/截断/配对落库/检索转义/统计/清理/上限/装配/信封。
