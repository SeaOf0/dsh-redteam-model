---
name: php-auth-audit
description: PHP Web 源码鉴权机制审计工具。从源码中识别所有认证/鉴权实现并分析风险，输出路由-鉴权映射与漏洞分析（含 PoC 与修复建议）。
---

# PHP 鉴权机制审计（Auth Audit）

分析 PHP Web 项目源码，识别认证与授权链路，判断每条路由的鉴权状态，并检测鉴权绕过/越权/IDOR 风险。

## CRITICAL：完整分析（强制）
- 必须处理所有在 `php-route-mapper` 中出现的路由
- 必须识别认证链：Session/JWT/中间件/自定义校验函数
- 必须输出路由-鉴权映射表（不做省略）
- 对所有可疑点给出：位置证据 + 数据流链 + 可利用性分析 + 验证 PoC + 修复建议

## 运行模式（强制：与流水线阶段对齐）
此技能支持两种模式，用于解决“尚未生成 trace 之前无法引用 EVID_*”的问题：

1. `STATIC_MAPPING`（推荐用于流水线阶段 1）
   - 只生成 `auth_mapping_{timestamp}.md`（以及可选的 `auth_README_{timestamp}.md`）
   - 允许缺少 `php-route-tracer` 的 `EVID_*` 证据点引用
   - 必须给出：鉴权状态分级（✅/⚠️/❌/❓）与 P0/P1 分桶依据（不需要 PoC）

2. `TRACE_AUDIT`（推荐用于流水线阶段 4，trace 已存在）
   - 生成完整的 `auth_audit_report_{timestamp}.md`，并强制逐条引用 trace 契约中的 `EVID_*` 证据点
   - PoC/修复建议必须齐全

## 漏洞分级
详见：`shared/SEVERITY_RATING.md`

## 输入依赖
建议输入（与 `shared/IO_PATH_CONVENTION.md` 一致；合并流水线时读总报告中等价章节）：
- `routes_{timestamp}.md`（独立落盘时常为 `route_mapping/routes_{timestamp}.md`）
- `params_{timestamp}.md`（独立落盘时常为 `route_mapping/params_{timestamp}.md`）

可选：
- `source_path`

## 识别鉴权实现（必做）
按框架识别：
- Laravel：
  - `middleware('auth'|'can'|'role:')`
  - `Auth::check()/Auth::user()`
  - Policies/Gates：`Gate::allows`、`->can({value})`
  - 路由保护：`Route::middleware([{value}])->group({value})`
- Symfony：
  - security.yaml / access_control
  - `denyAccessUnlessGranted`、`isGranted`
  - voter/policy
- 原生 PHP：
  - `session_start` + `$_SESSION` 判断
  - `if (!isset($_SESSION['user']))`/`requireLogin()`
  - 自定义函数：`checkAuth/authorize/hasRole/isAdmin`

## 路由-鉴权映射（必做）
对每条路由输出以下状态：
- ✅ 公开：显式允许，无鉴权检查
- ✅ 受保护：存在完整认证/授权检查
- ⚠️ 仅认证：只校验登录态，无角色/资源级授权
- ❌ 无鉴权：没有任何鉴权链路命中
- ❓ 不确定：动态权限/复杂自定义逻辑导致难判（仍必须写出证据点）

并输出风险类型：`AUTH`，包括：
- 认证绕过（登录态校验被绕过）
- 授权绕过/越权（角色校验缺失或错误）
- IDOR（对象访问缺少所有权/归属校验）

## 可疑模式检测（必做，给出证据链）
### 1) 路径/URI 匹配导致鉴权绕过
在 PHP 中常见根因：
- 用原始 `$_SERVER['REQUEST_URI']` 或 `parse_url` 结果做白名单匹配，但路径未规范化
- 编码/大小写/重复斜杠/尾部字符差异导致匹配失败（实际路由进入受保护 handler）

必须输出：
- 白名单检查位置与代码片段
- 绕过请求（PoC）与命中的 handler 证据

### 2) 仅校验登录态，缺少角色/资源授权
必须输出：
- 路由的“认证检查”位置
- “授权检查缺失”位置（例如只判断 `user!=null` 后直接执行敏感操作）

### 3) IDOR/越权
必须输出：
- 敏感对象 id 来自哪里（GET/POST/URL）
- 用于查询/更新的“归属校验”是否存在（WHERE 里是否包含 user_id/owner_id）
- 未校验的原因与可达性

## 报告输出（按运行模式）
输出到：
```
{output_path}/auth_audit/
├── auth_audit_report_{timestamp}.md
├── auth_mapping_{timestamp}.md
└── auth_README_{timestamp}.md
```
强制规则：
- `STATIC_MAPPING`：必须生成 `auth_mapping_{timestamp}.md`；`auth_audit_report_{timestamp}.md` 可以省略或生成空壳（并标注：仅分桶映射，不含 trace 证据）
- `TRACE_AUDIT`：必须生成完整三文件，并要求 trace 证据点齐全

### 文件1：主报告 `auth_audit_report_{timestamp}.md`
包含：
- 鉴权框架识别（含版本/实现证据）
- 鉴权架构概览（middleware/函数/handler）
- 风险统计
- 每条风险的完整漏洞结构（编号/分级/数据流/PoC/修复）

### 文件2：映射表 `auth_mapping_{timestamp}.md`
只列路由与鉴权状态、所需角色/条件（不要放漏洞详细分析）。
但必须新增分桶字段（用于流水线阶段 3 选路）：
- `p_bucket`：`P0` 或 `P1`
  - `P0`：❌ 无鉴权
  - `P1`：⚠️ 仅认证，或检测到存在授权绕过/越权/IDOR 风险（即使鉴权状态显示为“仅认证”，也要在 `p1_reason` 里说明为什么进入 P1）
- `p1_reason`：一段简短静态依据（如“仅登录态，缺少 hasRole/authorize 或缺少 owner_id 校验”）

### 文件3：说明文档 `auth_README_{timestamp}.md`
只说明方法论、工具与验证指南，不包含具体漏洞细节。

## PoC 验证模板（强制）
必须区分至少以下场景：
- 未登录访问（无 cookie/session/JWT）
- 普通用户访问（普通账号 cookie/JWT）
- 管理员/高权限对照（如适用）

PoC 必须是可执行 HTTP 请求代码块，并且路由路径必须使用真实路由规则。

## 证据引用（按运行模式强制）
- `STATIC_MAPPING`：不强制引用 trace 的 `EVID_*` 证据点（只需输出鉴权分级与 P0/P1 分桶依据）。
- `TRACE_AUDIT`：每条疑似鉴权风险必须逐项引用 trace 输出中的证据（允许状态标记为待验证，但证据引用必须存在）：
1. `EVID_AUTH_PATH_PROTECTED_MATCH`：路由进入受保护 handler 的路径匹配证据（对应 trace 的分支路径证据）
2. `EVID_AUTH_TOKEN_DECODE_JUDGMENT`：登录态/Token 解码结果如何被判断的证据（对应 trace 中 session/JWT 读取与条件分支）
3. `EVID_AUTH_PERMISSION_CHECK_EXEC`：权限判断函数或条件语句（如 `hasRole/authorize`）的执行证据（trace sink 定位或分支证据）
4. `EVID_AUTH_IDOR_OWNERSHIP_CONDITION`：IDOR 归属校验（WHERE/条件）是否包含 owner_id/user_id 的证据（trace 中最终查询条件或状态更新语句）

## tracer 证据缺失处理（强制）
- `STATIC_MAPPING`：不适用（分桶依据以静态代码证据为准）。
- `TRACE_AUDIT`：若 trace 契约校验失败或无法定位 1~4 任一关键证据点：该风险只能标记为 `⚠️待验证`，不得给出 `✅已确认可利用` 或“确定可绕过”的结论。

