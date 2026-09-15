---
name: php-wordpress-audit
description: WordPress 框架特效安全审计工具。针对 WordPress 常见 nonce/capability/check_admin_referer、AJAX action、escape/sanitize、重定向、安全上传与远程请求等机制进行白盒静态审计，并映射到通用漏洞类型体系（AUTH/CSRF/XSS/SQL/CFG/SSRF 等）。
---

# PHP WordPress 框架安全审计（php-wordpress-audit）

分析 WordPress 项目中的框架特效安全机制，重点覆盖：
- nonce 校验与 capability 权限检查（防止 CSRF 与越权）
- WordPress AJAX 回调（`admin-ajax.php` 的 `wp_ajax_*` 与 `wp_ajax_nopriv_*`）
- 输出 escaping 与模板注入风险（esc_html/esc_attr/esc_url/wp_kses 等）
- `$wpdb` 查询参数化与直接拼接风险
- 重定向（wp_redirect 与 wp_safe_redirect）
- 上传处理（wp_handle_upload）与可执行文件风险
- 远程 HTTP（wp_remote_get/wp_remote_post）与 SSRF 关联

## 输入
用户提供：
- `source_path`：WordPress 代码目录根（含 wp-content/plugins 或主题目录）
可选：
- `output_path`：输出目录路径（默认 `{source_path}_audit`）

## 输出目录
输出到：
```
{output_path}/framework_audit/
  wordpress_{timestamp}.md
```

## 框架识别（必做）
必须给出识别 WordPress 的证据点（不允许空口断言）：
- 目录特征：`wp-content/`、`wp-admin/`、`wp-includes/`
- 核心文件：`wp-config.php` 或 `wp-settings.php`
- 插件/主题目录：`wp-content/plugins/`、`wp-content/themes/`

## 风险类型映射（必做）
每条发现都必须写明：
- 通用类型码：`AUTH` / `CSRF` / `XSS` / `SQL` / `CFG` / `SSRF` / `UPLOAD` 等
- 映射原因：为什么 WordPress 风险落到该类型码

## 必审清单（必做：逐项检查并输出结果）

### 1) nonce 与 CSRF 防护（CSRF/AUTH）
必须定位并输出：
- 表单输出 nonce：`wp_nonce_field` 或自定义 nonce 输出
- 提交处校验：`check_admin_referer`、`wp_verify_nonce` 的位置
- AJAX nonce 校验：`check_ajax_referer`（若存在）

判定规则：
- 若 nonce 存在但校验缺失或仅做在部分分支输出，则输出 CSRF 或 AUTH 风险

### 2) capability 权限校验（AUTH）
必须定位并输出：
- 所有敏感操作调用前：`current_user_can`、`user_can`、`is_user_logged_in`
- capability 值是否被用户控制或过宽（例如只做 `manage_options` 缺失但仍执行高权限操作）

### 3) AJAX action 与路由暴露（AUTH/CSRF）
必须定位并输出：
- `add_action('wp_ajax_{action}', {value})` 与 `add_action('wp_ajax_nopriv_{action}', {value})`
- 回调函数内部是否对能力与 nonce 做校验

### 4) 输出 escaping 与 XSS（XSS）
必须定位并输出：
- 直接 echo/print 用户数据的点
- 是否使用 `esc_html`、`esc_attr`、`esc_url`、`wp_kses_post` 等
- 插件主题是否禁用了过滤或使用了 raw 输出

### 5) `$wpdb` 查询参数化（SQL）
必须定位并输出：
- 正确路径：`$wpdb->prepare` 与 prepare 占位符使用
- 危险路径：`$wpdb->query`、`get_results`、`get_row` 直接拼接 SQL 字符串

### 6) 重定向与跳转安全（REDIR/CFG）
必须定位并输出：
- `wp_redirect` 与 `wp_safe_redirect` 使用情况
- 目的地来源（通常为用户输入）与是否做 scheme/host 校验

### 7) 上传与远程请求（UPLOAD/SSRF）
必须定位并输出：
- 上传：`wp_handle_upload`、`media_handle_upload`，以及文件类型/目录/访问控制是否安全
- 远程请求：`wp_remote_get`/`wp_remote_post`，目的 URL 是否可控以及是否做 allowlist

## 可观测 PoC（必做：框架特效可观测验证框架）
至少给出以下两类之一并写清观察点：
- CSRF：缺失 nonce 校验的 action，构造缺失或错误 nonce 请求，观察响应与状态变更
- AUTH：缺失 capability 校验的 action，使用低权限用户请求敏感 action，观察是否成功

PoC 输出要求：
- 必须包含 action 标识、真实请求入口（通常 `admin-ajax.php` 或相应表单提交路径）
- 必须说明你要观察的结果（HTTP 状态码与业务侧效果）

## 输出完整性检查（强制）
- [ ] 输出包含：nonce/capability/AJAX/XSS/SQL/REDIR/UPLOAD/SSRF 的检查结果
- [ ] 每条风险都有：映射类型码 + 位置证据 + 可观测验证框架 + 修复建议

