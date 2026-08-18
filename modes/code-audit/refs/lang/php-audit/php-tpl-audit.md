---
name: php-tpl-audit
description: PHP Web 源码模板注入/SSTI 审计工具。识别模板引擎渲染点与模板名/表达式可控性，追踪到 eval/执行链，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP 模板注入/SSTI 审计（php-tpl-audit）

分析 PHP 项目源码，识别模板注入（SSTI）与危险表达式执行风险：用户可控内容影响模板选择、渲染表达式解析或转为可执行代码。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-TPL-{序号}`

## TPL Sink（必做）
模板相关渲染/执行点：
- Twig：
  - `Environment->load($templateName)` / `createTemplate($name)` / `render($template)`
  - `|raw` 或关闭自动转义策略（必须有证据点）
- Laravel Blade（Illuminate/View，PHP 原生常见）：
  - `view($templateName, $data)` / `View::make($templateName, $data)`
  - `Illuminate\View\Factory->make($template)` / 渲染入口 `$engine->render({value})`
  - 当模板可控时：Blade raw 输出（`{!! !!}`）与 `@php` 指令属于高危执行链（必须用证据点落到渲染/编译入口）
- Smarty：
  - `Smarty->fetch($template)` / `display($template)`
- 自定义模板引擎：
  - `eval()`、`preg_replace('/e')`、`create_function` 等被用于模板表达式
  - `call_user_func` / `call_user_func_array` 参数来自用户输入（可能触发表达式）

## 可控性（必做）
必须输出：
- 用户输入如何进入“模板名/模板片段/表达式字符串”
- 是否存在严格的白名单模板名映射
- 是否存在沙箱/表达式限制

## tracer 触发条件（必做）
- 模板选择/表达式构造跨多个函数或经过字符串拼接

## 证据引用（强制：来自 php-route-tracer）
每条模板注入/SSTI 疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **TPL 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_TPL_ENGINE_RENDER_OR_PARSE_ENTRY`：模板引擎渲染/表达式解析点位置证据（load/createTemplate/fetch/render 或等价入口）
2. `EVID_TPL_TEMPLATE_OR_EXPR_CONTROL`：模板名或表达式是否可控证据（来自路由参数到模板构造变量的映射）
3. `EVID_TPL_EXEC_CHAIN_ENTRY`：执行链入口证据（表达式求值/编译/执行：如 raw/disable escape、eval/use of call_user_func 等）

## tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

## 报告输出
输出到：
```
{output_path}/vuln_audit/tpl_{timestamp}.md
```

条目必须包含：数据流链、可利用前置条件、可执行 PoC 框架、修复建议与搜索语句。

