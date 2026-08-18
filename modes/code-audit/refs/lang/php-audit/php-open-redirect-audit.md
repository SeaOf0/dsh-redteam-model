---
name: php-open-redirect-audit
description: PHP Web 源码开放重定向审计工具。识别用户可控重定向目的地进入 header Location/跳转函数，分析校验与 allowlist，输出分级、PoC 与修复建议（禁止省略）。
---

# PHP 开放重定向审计（php-open-redirect-audit）

分析 PHP 项目源码中，所有“跳转/重定向”行为是否可能被用户控制目的地址，导致钓鱼或 OAuth 等流程被劫持。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-REDIR-{序号}`

## 必检 Sink（强制）
识别以下跳转输出点：
- `header("Location: {value}")`
- `<meta http-equiv="refresh" content="{value}">`
- `redirect()` / `to()` / `return redirect({value})`
- 自定义跳转函数（内部最终调用 Location 输出）

## 可控性追踪（必做）
必须追踪以下两类变量：
1. 目的地来源：通常来自 `$_GET['next']`/`$_POST['url']`/`Referer`/`return_to`
2. 目的地校验：是否只允许相对路径、是否 allowlist、是否拒绝 scheme（`http://`/`//`）、是否校验域名

## 绕过条件（必做）
必须识别并输出潜在绕过：
- scheme 绕过：`//evil.com`、`http:%2f%2fevil.com`
- 编码绕过：双重编码、URL 编码的冒号/斜杠
- 尾部/空白字符绕过（旧实现常见）

## 报告输出
```
{output_path}/vuln_audit/redir_{timestamp}.md
```

## 条目模板（强制）
每条漏洞必须包含：
- 位置证据：跳转函数位置 + 路由
- 数据流链：用户输入 -> 校验 -> header/redirect
- 可利用前置条件：通常需登录（若在登录后跳转）与攻击者能否控制参数
- 验证 PoC（必须真实路由；把目的地参数替换为真实字段名）
- 修复建议：只允许相对路径 + 服务器端 allowlist + 对编码/scheme 做归一化后校验

## 证据引用（强制：来自 php-route-tracer）
每条开放重定向疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **REDIR 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_REDIR_OUTPUT_POINT`：跳转输出点位置证据（header/redirect 的最终输出位置）
2. `EVID_REDIR_DEST_SOURCE_MAPPING`：目的地来源变量映射证据（从路由参数到目的地变量）
3. `EVID_REDIR_DEST_VALIDATION_NORMALIZATION`：目的地校验/归一化/allowlist/refuse scheme 的分支证据（含编码绕过处理分支）

## tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

