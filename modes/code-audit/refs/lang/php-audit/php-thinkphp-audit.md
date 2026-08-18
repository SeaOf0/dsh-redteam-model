---
name: php-thinkphp-audit
description: ThinkPHP 框架特效安全审计工具。针对 ThinkPHP 常见的鉴权/CSRF/模板转义/ORM 写入（Mass Assignment）/调试与配置暴露等机制进行白盒静态审计，并映射到通用漏洞类型体系（AUTH/CSRF/TPL/XSS/LOGIC/CFG/SESS/SQL 等）。
---

# PHP ThinkPHP 框架安全审计（php-thinkphp-audit）

分析 ThinkPHP 项目源码中的“框架特效安全机制”和典型踩坑模式，重点覆盖：
- 鉴权/权限控制（auth 模块、控制器/中间件 gate）
- CSRF token 机制与跳过路径
- ThinkPHP 模板引擎的自动转义与 raw 输出风险
- ORM/Model 层写入链路导致的 Mass Assignment（`allowField`/场景校验）
- 数据库原生表达式/原始 SQL 注入入口（映射到通用 SQL 类风险）
- debug/异常输出与安全配置开关（映射到 CFG）

## 输入
用户提供：
- `source_path`：ThinkPHP 项目根目录
可选：
- `output_path`：输出目录路径（默认 `{source_path}_audit`）

## 输出目录
输出到：
```
{output_path}/framework_audit/
  thinkphp_{timestamp}.md
```

## 框架识别（必做）
必须给出证据点证明识别为 ThinkPHP：
- 依赖证据：`composer.json` 含 `topthink/think-*` 或 `thinkphp/think-*` 相关依赖
- 入口证据：`public/index.php` 或等价前端入口
- 配置证据：`config/` 目录存在 ThinkPHP 配置文件（如 `app.php`、`database.php`、`middleware.php` 等，按项目实际）
- 运行目录证据：`runtime/` 目录结构（若存在）

## 风险类型映射（必做）
每条发现都必须写明：
- 通用类型码：`AUTH` / `CSRF` / `XSS` / `TPL` / `LOGIC` / `CFG` / `SESS` / `SQL` 等（从你的统一类型码里选）
- 映射原因：为什么落到该类型码（用一句话解释映射逻辑）

## 必审清单（必做：逐项检查并输出结果）

### 1) 鉴权与权限控制（AUTH）
必须定位并输出：
- 鉴权入口：控制器中间件/过滤器、基类 Controller/Behavior、路由层权限中间件
- auth 模块使用：是否使用 ThinkPHP 的 auth 相关能力（如 `Auth`/RBAC/角色权限校验函数或等价封装）
- 权限校验的参数来源：资源 ID/用户 ID 来自哪里（路由参数/请求 body/会话），以及是否做归属校验

判定规则：
- 发现“只判断登录态但缺少资源归属/角色细分”则输出 AUTH 风险
- 发现“权限校验在某些分支缺失/异常后绕过”则输出 AUTH 或 LOGIC 风险

### 2) CSRF 防护（CSRF）
必须定位并输出：
- CSRF token 的启用位置：配置项/中间件/表单生成逻辑
- token 的接收字段：来自 body/header 的哪个字段（按项目实际）
- token 校验逻辑：校验函数/中间件入口与失败处理（是否 return/throw 并阻断状态变更）
- 跳过规则：哪些路由、哪些请求方法或哪些场景跳过 CSRF 校验

判定规则：
- 存在跳过规则但覆盖到了状态变更接口 => CSRF 风险
- token 校验失败但仍继续执行业务（例如异常被吞掉）=> CSRF 风险

### 3) 模板引擎转义与 raw 输出（XSS/TPL）
必须定位并输出：
- 模板自动转义策略：模板语法是否默认转义、是否全局关闭
- raw 输出/跳过转义语法：例如模板中存在 `raw`/`|raw` 或等价机制（按项目实际模板引擎版本与用法）
- 用户输入进入模板变量：变量从哪里来（request/session/db），以及是否被直接拼到 HTML/JS/属性上下文

判定规则：
- 若 raw 输出变量可控且未转义 => 映射到 XSS 或 TPL（若涉及表达式/执行链）

### 4) ORM 写入链路（LOGIC：Mass Assignment）
必须定位并输出：
- 输入获取：是否把 `request->param()` / `request->all()` / `$this->request->post()` / 等价结构整体传入模型写入
- 模型写入点：`Model::create/save/update`、`$model->save($data)`、批量赋值行为
- 允许字段策略：是否配置 `allowField`/`field`/场景（scenario）或等价白名单机制

判定规则：
- 输入整体写入且模型缺少敏感字段 deny/allow 约束 => LOGIC 风险
- 存在允许字段白名单但仍包含高风险字段 => LOGIC 风险

### 5) 数据库原生表达式/原始 SQL 风险（SQL）
必须定位并输出：
- 原生 SQL 入口：`Db::query($sql)`、`Db::execute($sql)`、`whereRaw`、`orderRaw`、`buildExpression` 等（按项目实际）
- 用户输入进入原生表达式的证据：拼接、模板替换、字符串拼装点
- 是否存在参数化/绑定策略：`->bind/placeholder/prepare` 等（按项目实际）

判定规则：
- 用户输入进入字符串拼接的原生 SQL 表达式 => SQL 风险

### 6) 安全配置与调试暴露（CFG/SESS）
必须定位并输出：
- debug/异常输出：`app_debug`、`trace`、错误页输出策略、日志级别（按项目实际）
- cookie/session 安全参数：若项目配置文件可见（HttpOnly/Secure/SameSite 等），输出 SESS/CFG 风险映射

判定规则：
- 生产 debug 开启/堆栈回显 => CFG 风险

## 可观测 PoC（必做：框架特效可观测验证框架）
至少给出以下两类之一并写清观察点：
- AUTH：使用低权限用户请求疑似受保护 action，观察是否成功访问/是否发生业务副作用
- CSRF：对状态变更路由构造缺失或错误 CSRF token 的请求，观察是否返回阻断与业务是否仍执行

PoC 输出要求：
- 必须包含真实路由/控制器 action（从你的路由映射或代码入口证据中抽取）
- 必须包含 token 字段名/校验所需字段（按项目实际字段名输出）
- 必须说明观察点（HTTP 状态码、响应内容特征、业务副作用是否发生）

## 输出完整性检查（强制）
- [ ] 输出包含：ThinkPHP 识别证据 + AUTH/CSRF/模板输出/ORM 写入/数据库原生入口/调试配置 六大块检查结果
- [ ] 每条风险都有：映射类型码 + 位置证据 + 可观测验证框架 + 修复建议

