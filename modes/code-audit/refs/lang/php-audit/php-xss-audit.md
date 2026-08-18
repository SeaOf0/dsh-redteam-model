---
name: php-xss-audit
description: PHP Web 源码 XSS 审计工具。识别用户输入进入输出上下文（HTML/属性/JS/URL/模板），分析转义与防护策略，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP XSS 审计（php-xss-audit）

分析 PHP 项目源码，识别跨站脚本（XSS）：用户输入进入输出上下文且未做正确转义/编码，或框架禁用了自动转义导致表达式执行/HTML 注入。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-XSS-{序号}`

## XSS Sink（必做）
识别以下输出点：
- 原生输出：`echo/print/printf/<?= ?>`（输出变量到响应）
- 字符串拼接到响应：`header()` / `setcookie()`（若包含可控内容）
- 模板渲染：
  - Twig：`{{ }}`（转义）与 `{% autoescape false %}` / `|raw` 风险点
  - Smarty：`fetch/display` 与不安全变量输出
  - Blade 类：`{!! !!}`（不转义输出）
- 动态脚本/事件属性：输出到 `on*` 属性、`<script>` 内、URL 参数

## 逃逸/防护检查（必做）
对每条疑似链必须分析：
- 是否存在 `htmlspecialchars/htmlentities` 或框架自动转义
- 是否存在上下文编码（HTML、属性、JS、URL）
- 是否禁用了转义（raw/raw filter/unescaped output）

## tracer 触发条件（必做）
- 用户输入经历多层处理、拼接成 HTML 片段
- 存在分支：某分支转义，另一分支不转义
- 输出点在模板层，输入在 controller 层

## 报告输出
输出到：
```
{output_path}/vuln_audit/xss_{timestamp}.md
```

## 漏洞条目模板（强制）
与 `php-sql-audit` 基本一致，但在数据流链里必须明确：
- 输出上下文：HTML body/attribute/script/URL 参数/模板片段
- 具体转义函数或转义关闭点的位置与证据
- PoC 必须包含可执行 XSS payload，并区分需要的编码方式

## 证据引用（强制：来自 php-route-tracer）
每条 XSS 疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **XSS 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_XSS_OUTPUT_POINT`：响应输出点位置证据（echo/模板输出/`<script>`或属性/URL 上下文）
2. `EVID_XSS_USER_INPUT_INTO_OUTPUT`：用户输入进入输出的证据
3. `EVID_XSS_ESCAPE_OR_RAW_CONTROL`：转义/禁用转义证据（htmlspecialchars 等或 raw/raw 模式证据）

## tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

