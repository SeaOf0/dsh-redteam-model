---
name: php-file-read-audit
description: PHP Web 源码任意文件读取/路径穿越审计工具。识别文件读取 Sink，追踪路径来源与校验逻辑，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP 任意文件读取审计（php-file-read-audit）

分析 PHP 项目源码，识别文件读取与包含执行风险：路径穿越导致任意文件读取、包含任意文件（include/require）导致信息泄露或代码执行（当包含的是可执行内容/或受流包装器影响）。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-FILE-{序号}`

## FILE Sink（必做）
识别以下函数/语法：
- 读取：`file_get_contents/readfile/fopen/stream_get_contents/file/Storage::get`
- 包含：`include/require/include_once/require_once`（路径拼接风险尤其高危）
- 压缩/归档：`ZipArchive->open`（若路径可控）
- 流包装/过滤：`php://filter`、`php://input`（若被作为文件内容读取/包含）
危险：当 `allow_url_fopen/allow_url_include` 或 wrapper 允许时，读取/包含可跨协议
危险模式：
- 读取/包含路径变量直接来自用户输入
- 路径拼接未做规范化与 basePath 校验
- 允许 `file://`、`php://`、`data://`、`zip://` 等流包装且未限制
- 在 include/require 场景存在 `allow_url_include=On` 或通过配置/封装间接开启网络/跨协议 include 的证据

## 路径穿越检测（必做）
必须分析并给出证据：
- 是否过滤 `../`、`..\\`、混合分隔符
- 是否做 `realpath/canonicalize` 并用 basePath 校验前缀
- 是否处理流包装器（wrapper）前缀：`php://`、`file://`、`phar://`、`zip://` 等（必须逐项证据化）
- 编码/双重编码/大小写/尾部空格/`\0`（旧版本 PHP）绕过可能性
- 是否对后缀/扩展名做白名单，并且白名单不易绕过

## 包含执行判定（强制：提升真阳性）
当检测到 `include/require*` 使用可控路径时，必须输出以下判定证据（不能跳过）：
1. **包含内容类型**：包含目标是否可能被当作 PHP 代码执行（例如扩展名/解析方式/执行路径证据）
2. **包含路径的最终解析结果**：wrapper 解析后是否仍指向可控资源
3. **执行面边界**：include/require 是否位于异常处理、return/throw 分支之后（即使能读也可能不执行）
4. **配置证据**：是否存在 `allow_url_include=On`、或 `auto_prepend_file/auto_append_file`、或自定义封装对 include 的放行点

## tracer 触发条件（必做）
- 路径经过多层函数/JSON 字段传递
- 存在分支：校验逻辑是否只在某路径分支生效

## 报告输出
输出到：
```
{output_path}/vuln_audit/file_{timestamp}.md
```

## 漏洞条目模板（强制）
必须包含：
- 位置证据
- 数据流链（Source→Sink，包含路径拼接与校验分支）
- 证据引用（来自 `php-route-tracer` 输出，必须逐项引用）：必须对应并引用 trace 的 `## 9) Sink Evidence Type Checklist`（FILE 行）中的证据要点
  - `EVID_FILE_WRAPPER_PREFIX`：wrapper/流包装前缀（如 `php://`/`phar://`/`zip://` 等）
  - `EVID_FILE_RESOLVED_TARGET`：final/resolved target（wrapper 解析后的最终目标）
  - `EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY`：include/require 执行面边界（是否会执行 PHP 代码 vs 仅读取内容/报错；该证据点也可包含与 allow_url_include/封装放行相关的证据）
- 可利用前置条件（鉴权/输入可控性/触发条件）
- 可执行 PoC（HTTP 请求，含真实路由）
- 建议修复（basePath 校验 + 流包装禁用策略 + include/require 的安全替代要点 + 代码搜索语句）

## tracer 证据缺失处理（强制）
- 若 trace 的 `## 9) Sink Evidence Type Checklist`（FILE 行）中任一关键证据要点缺失或无法对应到本条漏洞：该条漏洞状态必须为 `⚠️待验证`（不得直接给出 `✅已确认可利用`）。

