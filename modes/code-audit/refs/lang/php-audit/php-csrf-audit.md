---
name: php-csrf-audit
description: PHP Web 源码 CSRF 审计工具。识别状态变更接口是否受 CSRF 保护，追踪 token 生成、校验与绕过条件，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP CSRF 审计（php-csrf-audit）

分析 PHP 项目源码中，所有可能造成状态变更的接口（POST/PUT/PATCH/DELETE，或含副作用的 GET）是否实现了 CSRF 防护（token 校验、SameSite/CORS 配合、双提交 cookie 等）。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-CSRF-{序号}`

## 保护点与必检内容（强制）
必须识别并输出：
1. 状态变更入口：路由的 HTTP 方法、是否包含副作用（写数据库/更新权限/发起交易/触发任务等）
2. CSRF token 生成：token 来源（session/cookie/random）、字段名、注入到表单或请求头的方式
3. CSRF token 校验：后端验证逻辑位置与条件（是否只校验登录用户、是否存在绕过分支）
4. 校验绕过：是否存在“某些分支不校验”“仅校验特定 Content-Type”“只在 AJAX 时校验”等
5. 同源/跨站辅助：`SameSite`、CORS/跨域设置、Referer/Origin 校验（注意：Referer/Origin 单独依赖也可能不稳）

## 数据流追踪要求
必须追踪至少一条链：
- 从 token 来源（如 `$_SESSION['csrf']`）到前端输出
- 再到后端的 token 接收（`$_POST/headers`）与校验（比较/哈希校验）

## 报告输出
输出到：
```
{output_path}/vuln_audit/csrf_{timestamp}.md
```

## 漏洞条目模板（强制）
必须包含以下部分：
- 位置证据（路由 + 校验函数/中间件位置）
- 数据流链（token 生成 -> 前端携带 -> 后端校验）
- 可利用前置条件（是否需要登录；攻击者能否构造页面；浏览器同站策略）
- 验证 PoC（必须包含真实路由与请求结构；若需配合登录，给出 cookie/登录态说明）
- 建议修复（token 校验放置、失败响应策略、字段名统一、对绕过分支加覆盖）

## 证据引用（强制：来自 php-route-tracer）
每条 CSRF 风险必须逐项引用 trace 中的证据点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_CSRF_STATE_CHANGE_HANDLER_EXEC`：状态变更 handler 的执行证据（trace 的分支路径证据）
2. `EVID_CSRF_TOKEN_SOURCE`：CSRF token 来源与生成证据（session/cookie/random 等）
3. `EVID_CSRF_TOKEN_RECEIVE`：CSRF token 在请求中的接收/进入校验逻辑的位置证据（trace 的参数进入点/分支证据）
4. `EVID_CSRF_TOKEN_VERIFY`：CSRF 校验比较/哈希判断位置证据（trace 的条件与早退证据）
5. `EVID_CSRF_BYPASS_BRANCH`：绕过分支证据（如仅校验某些 Content-Type 或仅对 AJAX 校验）

## tracer 证据缺失处理（强制）
- 若 trace 契约校验失败或缺失上述 1~5 任一关键证据点：该风险只能标记为 `⚠️待验证`，不得给出“已确认可利用”的断言。

