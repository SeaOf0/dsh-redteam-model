---
name: php-expr-audit
description: PHP Web 源码表达式注入（非模板）审计工具。识别用户可控表达式字符串进入表达式引擎求值/编译并最终导致敏感语义执行，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP 表达式注入（非模板）审计（php-expr-audit）

分析 PHP 项目源码，识别“表达式求值/编译”入口点：用户可控表达式字符串被传入表达式引擎（或 PHP 语言级代码执行函数），从而改变条件判断、路由决策、权限表达式或执行敏感语义（Expression Injection/代码注入类）。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-EXPR-{序号}`

## EXPR Sink（必做）
识别表达式引擎的求值/编译入口点（优先），以及 PHP 语言级“字符串即代码”的执行函数：
- `ExpressionLanguage->evaluate({value})`
- `ExpressionLanguage->compile({value})` 后续的执行/求值使用点
- `eval($code)`（当 `$code` 可由用户控制时）
- `assert($assertion)`（当 `$assertion` 为字符串且可由用户控制时）
- `preg_replace({value}, $replacement, {value})` 中使用 deprecated 的 `/e` 修饰符（当 replacement 可控时）
- 以及等价的“表达式解析/求值”引擎（项目封装的 evaluate/parse/compile 方法，只要最终把表达式字符串作为输入）

## 必检证据点（必做，trace 契约对齐）
每条 EXPR 疑似漏洞必须逐项引用 `php-route-tracer` trace 中 `## 9) Sink Evidence Type Checklist` 的 **EXPR 行**对应证据点 ID：
1. `EVID_EXPR_EVAL_ENTRY`：表达式解析/编译/求值入口点位置证据
2. `EVID_EXPR_EXPR_CONTROL`：表达式字符串是否来自用户可控输入的映射证据
3. `EVID_EXPR_EXEC_CHAIN_ENTRY`：表达式求值链的后续使用证据（求值结果如何进入敏感语义/安全关键分支，或最终执行点）

## 可控性与注入语义确认（必做）
必须输出并判断：
- 表达式字符串从哪里来：请求字段/JSON 字段/参数拼接后作为表达式输入
- 是否存在白名单/沙箱：是否限制函数、变量、常量、类型；是否对表达式语法进行拒绝或替换
- 是否存在“求值结果进入安全关键逻辑”：例如进入 if/过滤条件、权限判定、模板外表达式执行等
- 是否存在分支绕过：某些分支对表达式不做限制、或仅对部分输入做净化

## tracer 触发条件（必做）
当满足任一条件时触发 `php-route-tracer`（或同等深度追踪）：
- 表达式字符串经过多层函数/JSON 解码/拼接后才进入 evaluate/compile
- 表达式引擎求值结果参与安全关键条件或敏感操作（必须能在 trace 中追踪）
- 表达式限制逻辑存在条件分支（某些分支没限制、或限制可被绕过）

## 报告输出
输出到：
```
{output_path}/vuln_audit/expr_{timestamp}.md
```

## 漏洞条目模板（强制）
每条 EXPR 注入漏洞必须包含以下结构：
```markdown
### [{等级前缀}-EXPR-{序号}] 表达式注入漏洞（非模板）

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function}) |

#### 数据流链（Source → Sink）
(按路由逐行写出：输入读取 -> 表达式字符串构造 -> evaluate/compile 入口 -> 求值结果进入敏感语义，禁止省略)

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常/环境依赖}
- 沙箱/白名单可靠性：{已可靠防护/防护缺失/防护可绕过}

#### 证据引用（强制：来自 php-route-tracer）
- `EVID_EXPR_EVAL_ENTRY`：{对应证据要点简述}
- `EVID_EXPR_EXPR_CONTROL`：{对应证据要点简述}
- `EVID_EXPR_EXEC_CHAIN_ENTRY`：{对应证据要点简述}

#### 验证 PoC（强制：给出可执行请求）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Cookie/Auth}

{Payload}
```

PoC 生成策略（必须写清楚）：
- 第一步：使用“探测 payload”证明表达式确实被求值（例如算术结果、条件分支结果变化、返回值差异）
- 第二步：在探测成立后，构造“注入 payload”证明可改变安全关键语义（如绕过过滤/更改权限判断结果），若必须依赖具体引擎函数白名单，则标注为 `🔍环境依赖/⚠️待验证`，但仍给出可落地尝试方式

#### 建议修复
- 禁止将用户输入直接作为表达式字符串传入 evaluate/compile
- 使用严格 allowlist：仅允许固定表达式模板 + 参数占位符（并对参数做类型/范围校验）
- 为表达式引擎启用沙箱策略：限制函数/变量/访问范围；禁用危险操作（若引擎支持）
- 对表达式语法做拒绝策略（例如拒绝注入控制字符）并说明拒绝点位置
- 给出代码搜索语句（`rg`）定位所有 evaluate/compile 入口与表达式字符串构造点
```

## tracer 证据缺失处理（强制）
- 若 trace 契约的 EXPR 行中任一关键证据点（`EVID_EXPR_EVAL_ENTRY / EVID_EXPR_EXPR_CONTROL / EVID_EXPR_EXEC_CHAIN_ENTRY`）缺失或无法对应到本条漏洞：状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

