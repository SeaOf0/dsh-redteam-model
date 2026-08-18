---
name: php-xxe-audit
description: PHP Web 源码 XXE 审计工具。识别 XML 解析点与实体处理配置，追踪 XML 输入来源与回显，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP XXE 审计（php-xxe-audit）

分析 PHP 项目源码，识别 XXE（XML External Entity）风险：当 XML 解析点允许外部实体/DOCTYPE，且 XML 输入可控、并存在回显或 OOB 通道时，可能导致文件读取/SSRF/DoS。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-XXE-{序号}`

## XXE Sink（必做）
识别 XML 解析相关：
- `DOMDocument->loadXML/loadHTML`
- `simplexml_load_string/simplexml_load_file`
- `XMLReader->open/xml`
- `DOMDocument->load`（若内容来自用户可控字符串/流）
危险模式：
- 未禁用外部实体/未限制网络访问
- 解析参数允许 DOCTYPE

## 防护检查（必做）
必须输出解析器防护证据：
- libxml 安全参数：`LIBXML_NONET`、`LIBXML_NOENT`（注意：NOENT 可能放大风险）、`LIBXML_DTDLOAD` 等使用情况
- 是否使用：`libxml_disable_entity_loader(true)`（不同 PHP 版本策略不同，仍需给证据）
- 解析时是否传入安全选项并禁用网络访问

## 输入来源与回显（必做）
必须分别输出：
- XML 输入来源：`$_POST`/`php://input`/上传文件流等
- 回显路径：是否把解析结果写回响应（`echo`/模板输出）或仅 Blind（OOB）。

## tracer 触发条件（必做）
- XML 经过多层传递/解析后字段再输出
- 回显位置不清晰或在工具类中

## 证据引用（强制：来自 php-route-tracer）
每条 XXE 疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **XXE 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_XXE_PARSER_CALL`：XML 解析器调用点位置证据（DOMDocument->loadXML/simplexml_load_string/XMLReader->open 等）
2. `EVID_XXE_INPUT_SOURCE`：输入流来源证据（$_POST/`php://input`/上传读取/参数进入解析的对应证据）
3. `EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO`：外部实体/DOCTYPE 禁用相关安全选项证据（LIBXML_* 或禁用策略）以及解析结果回显位置证据

## tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

## 报告输出
输出到：
```
{output_path}/vuln_audit/xxe_{timestamp}.md
```

