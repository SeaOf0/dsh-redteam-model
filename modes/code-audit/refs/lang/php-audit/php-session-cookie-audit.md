---
name: php-session-cookie-audit
description: PHP Web 源码会话与 Cookie 安全审计工具。识别 session 固定、Cookie flags 不安全、JWT 验证缺陷与记住登录风险，输出分级、PoC 与修复建议（禁止省略）。
---

# PHP 会话与 Cookie 安全审计（php-session-cookie-audit）

分析 PHP 项目源码中认证会话相关的安全设置与实现逻辑，重点检测：
- session fixation
- cookie flags 缺失（HttpOnly/Secure/SameSite）
- JWT 校验缺陷（签名算法混淆、未校验 exp/iss/aud、弱密钥）
- remember-me/持久登录弱点（若存在）

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-SESS-{序号}`

## 必检内容（强制）
1. Session 初始化：
   - 是否在登录后 `session_regenerate_id`
   - 是否设置合理的超时、cookie 参数
2. Cookie flags：
   - `HttpOnly`、`Secure`、`SameSite` 是否明确设置
3. JWT：
   - decode/verify 使用的算法是否固定
   - 是否验证 `exp`/`nbf`/`iss`/`aud`
   - secret/公钥是否硬编码或读取不安全
4. 退出/失效：
   - logout 是否真正清除 session 与 token

## PoC 要求（强制）
- 对 session fixation：给出请求序列（登录前固定 session id -> 登录后验证会话变化）
- 对 cookie flags：说明浏览器侧可见差异与危害（并给出示例 HTTP 响应头）
- 对 JWT：给出“签名算法/claim 校验缺失”的请求 PoC 框架（必须说明 payload 如何构造）

## 证据引用（强制：来自 php-route-tracer）
每条会话与 Cookie 安全疑似风险必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **SESS 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_SESS_SESSION_INIT_REGEN`：登录后是否 `session_regenerate_id` 等会话固定防护证据
2. `EVID_SESS_COOKIE_FLAGS`：Cookie flags（HttpOnly/Secure/SameSite）设置证据
3. `EVID_SESS_JWT_VERIFY_CLAIMS`：JWT 签名算法固定与 exp/nbf/iss/aud 等 claim 校验证据
4. `EVID_SESS_LOGOUT_CLEAR`：logout 是否真正清除 session 与 token 的证据

## tracer 证据缺失处理（强制）
- 若 trace 契约校验失败或缺失上述 1~4 任一关键证据点：该风险只能标记为 `⚠️待验证`，不得给出“已确认可利用”的断言。

## 报告输出
```
{output_path}/vuln_audit/sess_{timestamp}.md
```

## 条目模板（强制）
必须包含：位置证据 + 数据流链（token/session -> 校验 -> 授权）+ 可利用前置条件 + PoC + 修复建议 + `rg` 搜索语句。

