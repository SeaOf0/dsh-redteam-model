---
name: php-ldap-audit
description: PHP Web 源码 LDAP 注入审计工具。识别用户可控数据进入 LDAP filter/DN 构造并被 ldap_search/ldap_read 执行，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP LDAP 注入审计（php-ldap-audit）

分析 PHP 项目源码，识别 LDAP 查询相关代码（filter/DN 构造），检测 LDAP 注入风险：攻击者可通过控制 filter 或 DN 片段改变 LDAP 查询语义，从而导致未授权查询、数据泄露或认证绕过。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-LDAP-{序号}`

## LDAP Sink（必做）
识别以下函数/语句作为最终执行点：
- `ldap_search({value})` / `ldap_read({value})` / `ldap_list({value})`
- 以及它们的项目封装（只要最终还是传入 filter/DN 字符串）

## 必检证据点（必做，trace 契约对齐）
每条 LDAP 疑似漏洞必须逐项引用 `php-route-tracer` trace 中 `## 9) Sink Evidence Type Checklist` 的 **LDAP 行**对应证据点 ID：
1. `EVID_LDAP_EXEC_POINT`：LDAP 查询执行点（ldap_* 函数调用/封装最终传参处）证据
2. `EVID_LDAP_FILTER_STRING_CONSTRUCTION`：LDAP filter/DN 字符串构造位置（拼接/模板化）证据
3. `EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT`：用户可控参数到 filter/DN 片段的映射证据

## 可控性与注入点确认（必做）
必须输出并判断：
- 用户输入从哪里来：`$_GET/$_POST/json/php://input/$_COOKIE/$_FILES` 或其衍生字段
- filter/DN 是如何构造：是否直接字符串拼接、是否经过转义、是否存在 allowlist 白名单
- 注入可改变的语义点：例如可否注入 `*`、`(`、`)` 等 LDAP filter 语法相关字符（或通过编码绕过转义）
- 是否存在转义/净化：优先使用 `ldap_escape`（或自定义等价函数），且必须能证明用于最终 filter/DN 构造

## tracer 触发条件（必做）
当满足任一条件时，应触发 `php-route-tracer`（或同等深度追踪）：
- filter/DN 由多个变量/函数层级拼接或经过 JSON 解码后拼接
- filter/DN 进入 `ldap_search/read/list` 之前存在分支（if/switch/try）或提前 return/throw
- 转义逻辑存在条件分支（某些分支没转义、或仅转义部分字段）

## 报告输出
输出到：
```
{output_path}/vuln_audit/ldap_{timestamp}.md
```

## 漏洞条目模板（强制）
每条 LDAP 漏洞必须包含以下结构：
```markdown
### [{等级前缀}-LDAP-{序号}] LDAP 注入漏洞（filter/DN 拼接导致查询语义被改变）

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function}) |

#### 数据流链（Source → Sink）
(按路由逐行写出：输入读取 -> 变量拼接/转换/转义 -> filter/DN 最终生成 -> 调用 ldap_* 执行，禁止省略)

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常/环境依赖}
- 转义/白名单可靠性：{已可靠防护/防护缺失/防护可绕过}

#### 证据引用（强制：来自 php-route-tracer）
- `EVID_LDAP_EXEC_POINT`：{对应证据要点简述}
- `EVID_LDAP_FILTER_STRING_CONSTRUCTION`：{对应证据要点简述}
- `EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT`：{对应证据要点简述}

#### 验证 PoC（强制：给出可执行请求）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Cookie/Auth}

{Payload}
```

PoC 生成策略（必须写清楚）：
- 先用“探测 payload”证明 filter/DN 被求值（返回数量/状态码/响应差异）
- 再用“注入 payload”证明可改变查询语义（如扩大匹配范围/绕过条件）

#### 建议修复
- 使用 `ldap_escape($value, '', LDAP_ESCAPE_FILTER)`（或等价函数）对 filter 用户输入做严格转义
- 对可控字段做 allowlist（仅允许合法字符集、固定属性名、限制长度）
- 禁止直接字符串拼接 filter/DN；改用参数化/模板化安全拼装（即使 PHP 无原生 LDAP 参数化，也要在代码层严格拼装）
- 给出代码搜索语句（`rg`）用于定位所有 filter/DN 拼接点
```

## tracer 证据缺失处理（强制）
- 若 trace 契约的 LDAP 行中任一关键证据点（`EVID_LDAP_EXEC_POINT / EVID_LDAP_FILTER_STRING_CONSTRUCTION / EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT`）缺失或无法对应到本条漏洞：状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

