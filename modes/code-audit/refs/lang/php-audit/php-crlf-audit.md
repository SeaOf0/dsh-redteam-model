---
name: php-crlf-audit
description: PHP Web 源码 CRLF/响应分割审计工具。识别用户输入进入 HTTP 响应头，分析换行/控制字符过滤与编码，输出分级、PoC 与修复建议（禁止省略）。
---

# PHP CRLF 响应分割审计（php-crlf-audit）

分析 PHP 项目源码，识别用户可控数据是否进入响应头（header）、Cookie、或其他可被浏览器/中间件解释为新头，从而造成响应拆分、缓存投毒或重定向劫持。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-CRLF-{序号}`

## 必检 Sink（强制）
识别以下点：
- `header()` 的 header 值参数含用户输入
- `setcookie()` 的 cookie name/value/domain/path 中含用户输入
- 输出到自定义 header 的函数/封装（最终仍调用 header）
- 返回 body 内拼接到 HTTP 响应头（少见，但仍需在代码中证据化）

## 必检过滤与归一化（强制）
必须输出：
- 是否对 `\r`、`\n` 做了拒绝或清洗
- 是否对可见控制字符进行了处理
- 是否进行了 URL 编码/转义（但注意：错误的“部分过滤”可能绕过）

## PoC（强制）
- 必须给出真实路由与可控字段名
- payload 必须体现 CRLF：`%0d%0a`（或 `\r\n`）并说明预期效果（如注入 Location 或自定义 header）

## 报告输出
```
{output_path}/vuln_audit/crlf_{timestamp}.md
```

## 条目模板（强制）
必须包含：位置证据 + 数据流链 + 可利用前置条件 + PoC + 修复建议 + 代码搜索语句。

## 证据引用（强制：来自 php-route-tracer）
每条 CRLF/响应分割疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **CRLF 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_CRLF_OUTPUT_POINT`：响应头/ Cookie 输出点位置证据（header/setcookie 等最终输出位置）
2. `EVID_CRLF_USER_INPUT_INTO_HEADER_COOKIE`：用户输入进入 header/cookie 值的证据（包含控制字符进入点）
3. `EVID_CRLF_CONTROL_CHAR_FILTERING_ENCODING`：`\r\n` 或控制字符过滤/编码证据（拒绝/清洗/编码实现的对应片段）

## tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

