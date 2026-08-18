---
name: php-cmd-audit
description: PHP Web 源码命令注入审计工具。识别命令执行 Sink（exec/system/shell_exec 等），追踪用户输入进入命令拼接，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP 命令注入审计（php-cmd-audit）

分析 PHP 项目源码，识别系统命令执行相关代码，并追踪用户输入到命令构造点，验证是否存在命令注入风险。

## CRITICAL
- 必须使用数据流链证据判定可利用性
- 禁止省略：不得出现任何省略占位符；每条条目必须包含完整的证据链与可观测验证框架
- 每条高危/中危条目必须含：位置证据 + Source→Sink 数据流链 + 可利用前置条件 + 可执行 PoC + 修复建议

## 分级与编号
- 详见 `shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-CMD-{序号}`

## 命令执行 Sink（必做）
识别以下函数/语法：
- `exec/system/shell_exec/passthru`
- `proc_open/popen/pcntl_exec`
- 反引号语法：`` `cmd` ``
危险模式：
- 命令字符串通过拼接包含用户输入（GET/POST/Body/参数字段）
- 未做白名单/未做 shell 转义，尤其包含 `;|&`、`$()`、反引号、换行等

## 追踪与验证（必做）
触发 `php-route-tracer` 的条件：
- 命令字符串由多个变量组成
- 存在参数经过 JSON 解码/多层传递
- 命令构造被 if/try 分支影响

## 报告输出
输出到：
```
{output_path}/vuln_audit/cmd_{timestamp}.md
```

## 漏洞条目模板（强制）
```markdown
### [{等级前缀}-CMD-{序号}] {风险标题}

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source → Sink）
（逐行写出：请求参数读取 -> 拼接/拼装 -> 命令执行函数/语句）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常/环境依赖}

#### 证据引用（强制：来自 php-route-tracer）
每条命令注入疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **CMD 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_CMD_EXEC_POINT`：命令执行函数/语句位置（对应 trace 的 CMD 执行点证据）
2. `EVID_CMD_COMMAND_STRING_CONSTRUCTION`：命令字符串/关键参数构造位置（拼接/模板化证据）
3. `EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT`：用户可控参数到命令关键片段的映射证据

#### tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

#### 验证 PoC（强制）
```http
POST {完整路径} HTTP/1.1
Host: {host}
{必要 Cookie/Auth}

{Payload}
```

#### 建议修复
- 强制使用命令参数白名单 + 安全参数拼接策略（避免 shell=true 的情况）
- 推荐替代实现（如使用不经 shell 的进程调用方式，或完全避免拼接）
- 给出代码搜索语句（`rg`）定位同类拼接点
```

