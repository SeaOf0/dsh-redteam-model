---
name: php-nosql-audit
description: PHP Web 源码 NoSQL 注入审计工具。识别用户输入进入 MongoDB/DocumentDB 查询构造，分析是否存在 operator 注入（$gt/$ne/$where 等），输出分级、PoC 与修复建议（禁止省略）。
---

# PHP NoSQL 注入审计（php-nosql-audit）

分析 PHP 项目源码，识别用户输入如何进入 NoSQL 查询条件，并检测 operator 注入导致的鉴权绕过/数据泄露。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-NOSQL-{序号}`

## 必检 Sink（强制）
常见于 MongoDB 驱动/ODM：
- `collection->find($filter)`
- `findOne($filter)` / `update($filter, {value})` / `delete($filter)`
- `where($condition)` 或 `->filter({value})`
- 将用户输入拼入查询数组/表达式的封装函数

## 必检危险模式（强制）
必须输出以下判断证据：
- 用户输入直接作为 filter/condition 数组的一部分（尤其是 `json_decode` 的结果）
- 存在“把用户输入当成结构化条件”的行为，而未强制类型/白名单
- query 中包含可能被滥用的运算符字段：`$ne/$gt/$lt/$or/$and/$where/$regex`

## tracer 触发条件
当用户输入是 JSON/数组/嵌套结构，且进入查询构造前有多层封装时，必须追踪到最终 sink。

## 报告输出
```
{output_path}/vuln_audit/nosql_{timestamp}.md
```

## 条目模板（强制）
每条漏洞必须包含：
- 位置证据（查询构造函数/最终 find/update 调用）
- 数据流链（输入解析 -> 类型 -> 查询条件）
- 可利用前置条件（鉴权状态/需要登录与否/能否改变查询操作符）
- 验证 PoC（必须真实路由与真实参数名；payload 为结构化 NoSQL 条件示例）
- 修复建议（严格字段 allowlist + 强制类型 + 避免把用户输入当作查询表达式）

## 证据引用（强制：来自 php-route-tracer）
每条 NoSQL 注入疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **NOSQL 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_NOSQL_QUERY_CONSTRUCTION`：NoSQL 查询构造点证据（对应 find/update/delete 或 query builder 执行点）
2. `EVID_NOSQL_USER_INPUT_INTO_QUERY_STRUCTURE`：用户输入进入查询条件结构的证据（可控字段进入 filter/where 的结构）
3. `EVID_NOSQL_OPERATOR_INJECTION_FIELDS`：operator 注入字段证据（$ne/$gt/$or/$where/$regex 等）

## tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

