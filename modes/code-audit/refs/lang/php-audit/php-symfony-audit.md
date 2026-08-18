---
name: php-symfony-audit
description: Symfony 框架特效安全审计工具。针对 Symfony 常见 security.yaml、CSRF、Twig/Twig raw、表达式与访问控制等框架机制做白盒静态审计，并将风险映射到通用漏洞类型体系（AUTH/CSRF/CFG/XSS/TPL/LOGIC 等）。
---

# PHP Symfony 框架安全审计（php-symfony-audit）

分析 Symfony 项目源码中的“框架特效安全机制”和“配置/用法踩坑”，重点覆盖：
- `config/packages/security*.yaml` 的 access_control、firewalls 配置正确性
- CSRF 防护机制（表单提交与 token 验证）
- Twig 渲染自动转义与 raw 输出风险
- Symfony 访问表达式与安全拦截链（map 到 AUTH/EXPR/TPL 视情况）
- HttpClient 外联策略（SSRF 类风险以通用 SSRF 类型映射）

## 输入
用户提供：
- `source_path`：Symfony 项目源码根目录
可选：
- `output_path`：输出目录路径（默认 `{source_path}_audit`）

## 输出目录
输出到：
```
{output_path}/framework_audit/
  symfony_{timestamp}.md
```

## 框架识别（必做）
必须给出识别为 Symfony 的证据点（不允许空口断言）：
- 典型目录：`config/`、`src/`、`templates/`
- 依赖证据：`composer.json` 中 `symfony/framework-bundle` 等
- 入口证据：`public/index.php` 或类似前端控制器

## 风险类型映射（必做）
每条发现都必须写明：
- 适用的通用类型码：`AUTH` / `CSRF` / `CFG` / `XSS` / `TPL` / `LOGIC` / `SESS` / `SSRF` / `EXPR` 等
- 映射原因：为什么该 Symfony 风险会落在该类型码（用一句话）

## 必审清单（必做：逐项检查并输出结果）

### 1) 访问控制与鉴权策略（AUTH）
必须定位并输出：
- `security.yaml` 中的 `access_control` 规则
- `firewalls` 配置（是否 `anonymous: true`、是否 `stateless: true` 与认证方式）
- `switch_user`、`role_hierarchy` 或 voter/policy 类配置（如存在）

判定规则：
- 若存在过宽允许（例如过于泛化的匿名规则覆盖敏感路径），输出 AUTH 风险
- 若存在“有认证但缺少角色/归属校验”的模式，输出 AUTH 或 LOGIC 风险

### 2) CSRF 防护（CSRF）
必须定位并输出：
- Symfony CSRF 相关配置（`framework: csrf_protection` 或组件级配置）
- 表单类型使用中 CSRF token 的生成与接收方式
- token 验证失败的处理路径（是否早退、是否仅在某些分支校验）

判定规则：
- 若存在“某些路由/表单禁用了 CSRF 或 CSRF token 接收字段不一致”，输出 CSRF 风险

### 3) Twig 自动转义与 raw 输出（XSS/TPL）
必须定位并输出：
- Twig 配置：自动转义是否被关闭（全局或局部）
- 模板中 raw 输出点：`|raw`、`{% autoescape false %}`、以及任何“绕过转义”的指令
- 数据来源：raw 输出的变量来自哪里（request/session/数据库字段）

判定规则：
- raw 输出变量来源可控且未做 escape，则映射到 XSS 或 TPL（若存在表达式执行/模板引擎可控）

### 4) 安全表达式与求值风险（EXPR/TPL/AUTH）
必须定位并输出：
- ExpressionLanguage 用于 security 的位置（voter/policy 中 `is_granted` 或表达式条件）
- 表达式字符串来源是否可能被用户控制（例如表达式拼接）

判定规则：
- 若表达式字符串可控，按 EXPR 或 TPL 风险输出

### 5) 外联 HTTP 与内网访问（SSRF）
必须定位并输出（仅做框架关联检查）：
- `HttpClient`/`KernelInterface` 等外联调用的封装入口
- URL/host 是否来源于用户输入，是否存在 allowlist 或内网拦截

## 可观测 PoC（必做：框架特效可观测验证框架）
至少给出以下两类其一并写清观察点：
- 访问控制错误：用未登录/低权限用户访问疑似受保护路由，观察响应差异
- CSRF 错误：构造表单请求缺失或伪造 CSRF token，观察状态码/错误路径

PoC 输出要求：
- 必须包含真实路由与真实表单 action（或路由路径）
- 必须说明预期观察点（例如是否返回 403、是否继续执行状态变更）

## 输出完整性检查（强制）
- [ ] 输出包含：Symfony 识别证据点
- [ ] AUTH/CSRF/Twig(raw)/安全表达式/HttpClient(可选) 五块均有检查结果
- [ ] 每条风险都有：映射类型码 + 位置证据 + 可观测验证框架 + 修复建议

