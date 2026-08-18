---
name: php-codeigniter-audit
description: CodeIgniter 框架特效安全审计工具。针对 CodeIgniter 的 CSRF、XSS 输出过滤、数据库查询构造、路由与验证器配置、会话 Cookie 安全等机制进行白盒静态审计，并映射到通用漏洞类型体系（CSRF/AUTH/XSS/SQL/CFG/SESS 等）。
---

# PHP CodeIgniter 框架安全审计（php-codeigniter-audit）

分析 CodeIgniter 项目的框架机制与配置踩坑，重点覆盖：
- CSRF 保护是否启用与 token 名称/校验逻辑是否正确
- 输出过滤与 XSS 防护（CI 自带过滤器是否被禁用或错误使用）
- 数据库查询构造：是否存在用户输入拼接到 `$this->db->query` 或原生 SQL
- 表单验证器是否被覆盖或绕过
- 会话 Cookie flags 安全性（CI 会话设置）

## 输入
用户提供：
- `source_path`：CodeIgniter 项目根目录
可选：
- `output_path`：输出目录路径（默认 `{source_path}_audit`）

## 输出目录
输出到：
```
{output_path}/framework_audit/
  codeigniter_{timestamp}.md
```

## 框架识别（必做）
必须给出识别证据（不允许空口断言）：
- 典型目录：`application/`、`system/`
- 配置文件：`application/config/config.php` 或会话/安全配置文件
- 版本线索：`composer.json` 或 `system/core/` 结构

## 风险类型映射（必做）
每条发现都必须写明：
- 通用类型码：`CSRF` / `XSS` / `SQL` / `AUTH` / `CFG` / `SESS` / `LOGIC` 等
- 映射原因

## 必审清单（必做：逐项检查并输出结果）

### 1) CSRF 保护（CSRF）
必须定位并输出：
- CSRF 是否启用（CI 3：`config.php` 的 csrf 配置，CI 4：Security 类配置）
- token 名称、校验入口与跳过规则（是否某些控制器/方法未启用校验）

判定规则：
- 存在状态变更路由但未启用 CSRF，则输出 CSRF 风险

### 2) XSS 输出防护（XSS/CFG）
必须定位并输出：
- CI 的 XSS 过滤器是否启用（如 `global_xss_filtering`、`Security::xss_clean` 等）
- 视图层是否对用户输入做了正确 `html_escape` 或等价转义

判定规则：
- 如果禁用过滤或未转义输出，且用户输入能进入视图输出，则输出 XSS

### 3) 数据库查询拼接（SQL）
必须定位并输出：
- 原生查询：`$this->db->query($sql)` 或 `->query($userInput)` 的拼接证据
- 正确路径：Query Builder 与绑定参数使用

判定规则：
- 若存在用户输入进入 SQL 字符串拼接，输出 SQL 风险

### 4) 会话与 Cookie（SESS/CFG）
必须定位并输出：
- cookie flags：HttpOnly/Secure/SameSite（如在项目中配置）
- session 配置：会话超时、固定防护（如存在）

### 5) 鉴权与访问控制（AUTH）
必须定位并输出：
- 控制器中访问保护模式：自定义 `auth` helper、基类 controller 的校验、过滤器
- 路由层过滤器或中间件（CI 4 filters）

判定规则：
- 若敏感控制器或方法缺少统一鉴权，输出 AUTH 风险

## 可观测 PoC（必做：框架特效可观测验证框架）
至少给出以下两类其一并写清观察点：
- CSRF：缺失 CSRF token 调用状态变更路由，观察是否成功与副作用
- SQL：使用注入 payload 调用疑似拼接 SQL 路径，观察返回差异或错误回显

## 输出完整性检查（强制）
- [ ] 输出包含：CSRF/XSS/SQL/Session/Auth 的检查结果
- [ ] 每条风险都有：映射类型码 + 位置证据 + 可观测验证框架 + 修复建议

