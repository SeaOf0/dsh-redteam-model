---
name: php-config-audit
description: PHP Web 配置安全审计工具。识别 CORS/错误暴露/调试开关/安全头/危险运行时开关等，输出分级、可利用性分析、PoC 与修复建议（禁止省略）。
---

# PHP 配置安全审计（php-config-audit）

分析 PHP 项目配置与运行时设置，检测安全相关配置缺陷：
- CORS 过宽（允许所有来源、credentials 组合不当）
- 错误与调试信息暴露（display_errors、debug 模式、未隐藏堆栈）
- 安全响应头缺失（CSP、X-Frame-Options/Frame-Options、Referrer-Policy、HSTS 等）
- 危险 PHP/运行时开关（如 `allow_url_include`、`file_uploads` 等与业务联动的危险组合）
- 上传/下载目录的可访问/可执行属性（若可由配置推断则输出证据）

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-CFG-{序号}`

## 必检证据（强制）
必须给出每条问题的证据路径：
- 配置文件/环境变量位置（例如 `.env`、`config/*.php/yaml`、`php.ini`、Dockerfile/entrypoint）
- 运行时设置代码位置（`ini_set`、`set_exception_handler`、响应头中间件）
- 影响点：哪些路由/响应被该配置影响（必须关联至少一类入口/响应链）

## 可利用性与前置条件（强制）
- 错误暴露：是否会泄露敏感信息并被攻击者利用（例如结合任意文件读取/SQLi 提升）
- CORS：是否存在受害者浏览器场景与 credentials 组合
- 安全头缺失：是否可与 XSS/点击劫持链式利用

## PoC（强制）
必须给出可观察 PoC（例如 `curl -i`）或请求步骤：
- 用真实路由触发响应
- 展示缺失/错误的响应头或堆栈输出证据

## 证据引用（强制：静态证据优先，trace 可选增强）

> **CFG 属于非 trace-gate 类别**：配置安全审计以静态配置文件/代码证据为主要依据，不以 `php-route-tracer` 的 trace-gate 或 `## 9) Sink Evidence Type Checklist` 作为前置硬门槛。若 trace 产出中存在 CFG 行证据，可作为增强引用。

每条配置安全疑似风险必须给出以下证据（来源为静态代码/配置文件，trace 可作为增强）：
1. `EVID_CFG_CONFIG_LOCATION`：配置文件/环境变量位置证据（例如 `.env`、`config/*.php/yaml`、`php.ini`、Dockerfile/entrypoint）
2. `EVID_CFG_RUNTIME_SETTING_CODE`：运行时设置代码位置证据（ini_set/set_exception_handler/响应头中间件等）
3. `EVID_CFG_IMPACT_ASSOCIATION`：影响点关联证据（哪些路由/响应被该配置影响）
4. `EVID_CFG_SECURITY_SWITCH_EVIDENCE`：安全头/错误暴露/CORS/危险开关等关键配置证据

## 证据缺失处理（强制，遵循统一标准）
- 配置项可从静态文件直接取证，不依赖 trace 完整性。
- 若上述 1~4 的静态证据齐全且影响路径清晰：可直接给出 `✅已确认可利用` 或 `🟡高概率`。
- 若关键影响点关联（3）缺失（无法确认哪些入口/响应受影响）：降级为 `⚠️待验证`。

## 报告输出
```
{output_path}/vuln_audit/cfg_{timestamp}.md
```

