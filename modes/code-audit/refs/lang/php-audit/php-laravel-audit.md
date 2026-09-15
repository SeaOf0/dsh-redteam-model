---
name: php-laravel-audit
description: Laravel 框架特效安全审计工具。针对 Laravel 常见鉴权/CSRF/Session/模型填充/Blade 渲染等框架特性进行白盒静态审计，并将风险映射到你现有通用漏洞类型体系（AUTH/CSRF/LOGIC/XSS/CFG 等）。
---

# PHP Laravel 框架安全审计（php-laravel-audit）

分析 Laravel 项目源码中的“框架特效安全机制”和“常见踩坑模式”，重点覆盖：
- 鉴权与路由保护（middleware/auth/Policies/Gates）
- CSRF 与 token 保护（VerifyCsrfToken、except 列表、API 与 Cookie 认证差异）
- Session 与 Cookie 安全（session_regenerate_id、cookie flags、remember 机制的风险点）
- Eloquent mass assignment 与 request-to-model 写入缺陷（Model::create/fill/update 与 `$request->all()` 链）
- Blade 模板渲染中的 raw 输出与表达式执行风险（`{!! !!}`、`@php` 以及未转义输出）
- Laravel signed URL 与路由签名校验是否闭环（Signed middleware 与生成位置）

## 输入
用户提供：
- `source_path`：Laravel 项目源码根目录
可选：
- `output_path`：输出目录路径（默认 `{source_path}_audit`）

## 输出目录
输出到：
```
{output_path}/framework_audit/
  laravel_{timestamp}.md
```

## 框架识别（必做）
必须给出你识别该项目为 Laravel 的证据点（不允许空口断言）：
- `composer.json` 依赖
- 典型目录：`app/`、`routes/`、`config/`
- 核心入口：`public/index.php`、`bootstrap/app.php`

## 风险类型映射（必做）
每条发现都必须写明：
- 适用的通用类型码：`AUTH` / `CSRF` / `LOGIC` / `XSS` / `CFG` / `SESS` / `FILE` 等（从你的 `shared/SEVERITY_RATING.md` 可用类型码中选）
- 这条 Laravel 风险为什么落到该通用类型码（用一句话解释映射逻辑）

## 必审清单（必做：逐项检查并输出结果）

### 1) 鉴权与权限保护（AUTH）
必须定位并输出以下证据：
- 受保护路由进入点：`routes/web.php` 与 `routes/api.php` 中的 `middleware('auth')` / `middleware('can')` / `Route::middleware([{value}])->group({value})`
- 权限逻辑：`Gate::` / `Policy` / `authorize` / `can` / `->can({value})` 的位置证据
- 风险判断：是否存在“已登录但无资源级归属校验”的模式（例如只判断 user 存在，不判断 owner）
- 路由命名与资源绑定：是否存在 Route Model Binding 但未做归属校验

输出要求：
- 若发现缺失：必须给出“缺失位置 + 可能被绕过的请求类型（GET/POST/API）+ 修复建议”
- 若未发现：也必须输出“未发现的判定依据”（例如 except/guard 为空、敏感路由均有 middleware 等）

### 2) CSRF 与 token 保护（CSRF）
必须定位：
- CSRF middleware：`VerifyCsrfToken` 或等价中间件
- except 列表：哪些路由被排除
- API 与 Cookie 认证差异：若项目对 API 使用 Cookie/session，需要确认 API 路由是否仍受 CSRF 保护

输出要求：
- 必须覆盖“可能绕过分支”：例如仅部分方法不校验、仅某些 Content-Type 不校验、仅在 AJAX 时跳过等

### 3) Session 与 Cookie 安全（SESS）
必须定位：
- 登录后会话固定防护：是否存在 `session_regenerate_id` 或 Laravel 对应机制证据
- Cookie flags：`HttpOnly`/`Secure`/`SameSite` 的配置位置（`config/session.php` 或自定义中间件）
- logout：退出是否清理 session

### 4) Eloquent mass assignment（LOGIC）
必须定位并输出数据流链证据：
- request 输入获取：`$request->all()`、`$request->input({value})`、`json_decode({value})`
- 写入模型点：`Model::create({value})` / `Model::update({value})` / `$model->fill({value})` / `->save()`
- 模型填充策略：`$fillable` / `$guarded` 的配置位置

判定规则：
- `$request->all()` 或等价输入直接进入 `create/fill/update`，且模型缺少针对敏感字段的 denylist（或 `$fillable` 过宽），则输出风险

### 5) Blade raw 输出（XSS）
必须定位并输出：
- raw 输出：`{!! {value} !!}`、`@php` 以及任何“跳过转义”的指令或回调
- 用户输入来源：来自 `$request`、`request()`、数据库字段回填但未转义时的证据

判定规则：
- 若 raw 输出内容存在用户可控字段，且未做 `e()` 或等价 escape，则输出风险映射到 `XSS` 或相关模板注入风险（若你项目用到模板表达式执行则映射到 `TPL`）

### 6) Signed URLs 与签名校验闭环（AUTH 或 CFG）
必须定位：
- 签名 URL 生成：`URL::temporarySignedRoute` / `URL::signedRoute`
- 验证中间件：`middleware('signed')` 或等价校验机制

判定规则：
- 若仅生成但无签名验证中间件，或验证逻辑可被绕过，输出风险映射到 `AUTH` 或 `CFG`

## 可观测 PoC（必做：框架特效可观测验证框架）
至少给出以下两类其一并写清观察点：
- 鉴权缺失/越权绕过：给出真实路由与 payload 目标（例如切换对象 id）
- CSRF 缺失/绕过：给出真实路由与需要携带/不携带的 token 场景，并说明观察点

PoC 输出要求：
- 必须包含真实路由（从 `routes/*.php` 真实可命中位置抽取）
- 必须包含真实字段名（如 `csrf` 字段、或表单 action）

## 输出完整性检查（强制）
- [ ] 输出包含：Laravel 识别证据点
- [ ] CSRF/Auth/Session/Mass Assignment/Blade raw/Signed URL 六大块均有“检查结果”
- [ ] 每条风险都有：映射类型码 + 位置证据 + 可观测验证框架 + 修复建议

