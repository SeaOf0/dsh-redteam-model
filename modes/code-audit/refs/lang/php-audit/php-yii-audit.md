---
name: php-yii-audit
description: Yii 框架特效安全审计工具。针对 Yii（通常指 Yii2）访问控制（AccessControl/RBAC）、CSRF、输入过滤规则、输出编码策略、URL/重定向安全等进行白盒静态审计，并映射到通用漏洞类型体系（AUTH/CSRF/XSS/CFG/LOGIC 等）。
---

# PHP Yii（Yii2）框架安全审计（php-yii-audit）

分析 Yii2 项目的框架机制与配置踩坑，重点覆盖：
- 访问控制：`AccessControl` filter、`roles` 规则、matchCallback 的使用
- RBAC：`user->can`/`can()` 路径的鉴权完整性
- CSRF：`enableCsrfValidation` 与 cookie validation
- 输出编码：views 是否使用 `Html::encode`、`HtmlPurifier`，以及危险的原样输出
- URL 与跳转：redirect/Url 生成是否受信任输入控制
- 入参过滤：`rules()`、`safeAttributes()`、场景（scenario）是否导致 Mass Assignment

## 输入
用户提供：
- `source_path`：Yii 项目根目录
可选：
- `output_path`：输出目录路径（默认 `{source_path}_audit`）

## 输出目录
输出到：
```
{output_path}/framework_audit/
  yii_{timestamp}.md
```

## 框架识别（必做）
必须给出 Yii 识别证据点（不允许空口断言）：
- 依赖证据：`composer.json` 包含 `yiisoft/yii2` 或相关组件
- 入口证据：`web/index.php` 或 `yii` 入口脚本
- 应用目录：`controllers/`、`models/`、`views/`

## 风险类型映射（必做）
每条发现都必须写明：
- 通用类型码：`AUTH` / `CSRF` / `XSS` / `CFG` / `LOGIC` 等
- 映射原因

## 必审清单（必做：逐项检查并输出结果）

### 1) AccessControl 鉴权规则正确性（AUTH）
必须定位并输出：
- `behaviors()` 中的 `AccessControl` 配置：`rules`、`roles`、`matchCallback` 与 action 覆盖范围
- 是否存在只依赖 matchCallback 的宽松模式
- 是否有自定义认证逻辑但未落到统一 filter

判定规则：
- 有路径能绕过 AccessControl 或 rules 过宽，则输出 AUTH 风险

### 2) RBAC/权限校验完整性（AUTH/LOGIC）
必须定位并输出：
- 控制器/服务层的 `user->can({value})`、`can()` 或等价权限判断
- 对象归属校验：是否同时验证 owner_id/user_id 或资源的归属关系

判定规则：
- 若仅判断“用户有权限类型”，但未校验对象归属，输出 AUTH 或 LOGIC 风险

### 3) CSRF（CSRF）
必须定位并输出：
- `enableCsrfValidation` 与 cookie validation 设置
- token 接收字段与验证失败处理方式（是否早退）

### 4) 输出编码与 XSS（XSS）
必须定位并输出：
- views 中是否存在原样输出：`Html::encode` 被绕过的情况、或使用 `raw` 类机制
- 模板中是否将用户输入直接拼接到 HTML 属性/JS/URL 中

### 5) 输入过滤与 Mass Assignment（LOGIC）
必须定位并输出：
- 模型 `rules()`、`safeAttributes()`、`scenarios()` 的配置
- 是否存在 `load($request->post())` 后直接保存，而敏感字段未被禁止

## 可观测 PoC（必做：框架特效可观测验证框架）
至少给出以下两类其一并写清观察点：
- AUTH：对疑似受保护 action，用低权限用户请求，观察响应差异或业务副作用
- CSRF：对疑似受保护的状态变更 POST 请求，缺失 CSRF token，观察错误与是否仍成功执行

PoC 输出要求：
- 必须包含 controller/action 路由与参数字段
- 必须说明你要观察的 HTTP 状态码与业务结果

## 输出完整性检查（强制）
- [ ] 输出包含：AccessControl/RBAC/CSRF/输出编码/Input filtering 检查结果
- [ ] 每条风险都有：映射类型码 + 位置证据 + 可观测验证框架 + 修复建议

