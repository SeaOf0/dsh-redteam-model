---
name: php-route-mapper
description: PHP Web 源码路由与参数映射分析工具。从源码中提取所有入口路由与参数结构，输出完整请求模板与参数清单（禁止省略）。
---

# PHP 源码 Route & Param Mapper

分析 PHP Web 项目源码，提取**完整**的 HTTP 路由入口与请求参数结构，生成可用于安全测试的请求模板（Burp/Repeater 风格），并自动保存为 Markdown。

## CRITICAL：完整输出（强制）
此技能必须输出所有发现的路由与接口，不允许省略：
- 禁止出现省略占位符；必须输出完整的路由与参数内容
- 禁止只输出“关键路由/重要路由”
- 每条路由必须包含：HTTP 方法、路径规则、处理器位置、完整参数结构、完整请求模板（在代码块里）

## 核心输入
用户提供：
- `source_path`：PHP 项目源码根目录
可选：
- `context_path`：如果存在反向代理/网关前缀，可用于拼接完整路径（必须有证据来源）

## 输出目录结构（建议）
```
{output_path}/
├── route_mapping/
│   ├── routes_{timestamp}.md
│   └── params_{timestamp}.md
└── quality/
    └── route_mapper_validation_{timestamp}.md
```

路径与流水线合并模式下的对应关系见 **`shared/IO_PATH_CONVENTION.md`**（`route_mapping/*.md` 与报告内「路由/参数」章节等价）。

## 识别范围（必做）
1. 路由配置/定义（按框架识别）
   - Laravel：`routes/web.php`、`routes/api.php`、`Route::get/post/{subpath}`、`Route::resource`、Route group 前缀与中间件
   - Symfony：`config/routes/*`、PHP8 attribute `#[Route({route_options})]`、Annotation `@Route({route_options})`
   - Slim：`$app->get/post/any({handler})`、自定义中间件
   - WordPress：`admin-post.php`/`admin-ajax.php`、`add_action('admin_post_*')`、`add_action('wp_ajax_*')`
   - 纯 PHP：front controller（如 `public/index.php`）的分发逻辑、基于 `$_SERVER['REQUEST_URI']` 的路由匹配
2. 动态路由/参数化路由（必做）
   - `{id}` / `(?P<id>{id_pattern})` / 正则路由：必须把可控参数列出来
   - 路由约束（where/regex limit）：必须输出约束规则与可控性边界

## 参数结构解析（必做）
对每条路由输出以下参数来源与类型信息：
- Path 参数：来自路由规则的占位（输出如 `{id}`）
- Query 参数：`$_GET` / `request()->query({query})` / 框架 query 解析结果
- Body 参数：`php://input`、`$_POST`、JSON `json_decode({json})`
- Header 参数：`getallheaders()`、`$_SERVER[{value}]`、框架 request header API
- Cookie 参数：`$_COOKIE`
- File 参数：`$_FILES`（输出字段名与 filename 来源）

## 处理器位置（必做）
每条路由必须给出处理器来源证据：
- 文件路径（相对/绝对均可，但必须一致）
- 函数/类/方法签名（在源码中能定位到的名称）
- 关键分发点：路由匹配如何进入 handler（如 switch case / include 文件链）

## 输出格式（强制）
### `routes_{timestamp}.md`：主索引（逐条列出）
说明：本 skill 使用 `routes_{timestamp}.md` 中 `=== [N] {route_summary} ===` 的 `N` 作为 **HTTP 路由**的 `route_id`（流水线后续用于 `route_tracer/{route_id}/trace_{timestamp}.md` 文件分桶）。**CLI / hook / sink-only** 等合成 `route_id` 由 `php-audit-pipeline` 阶段 3 写入 `high_risk_routes_{timestamp}.md`，**不**占用本文件的 `[N]` 序号。
```markdown
# {project_name} - 路由与接口索引（PHP）
生成时间: {timestamp}
分析路径: {source_path}

## 路由清单（全部）
=== [1] GET /path/to/{id} ===
HTTP 方法: GET
路由路径规则: /path/to/{id}
处理器: ControllerClass@method / functionName
位置: path/to/file.php:line（若无法获取行号，标注“待定位：需人工打开文件确认”但仍给出文件路径）
参数概览:
  Path: id (类型推断/约束)
  Query: {query_params}

=== [2] POST /path/to/{id}/action ===
HTTP 方法: POST
路由路径规则: /path/to/{id}/action
处理器: ControllerClass@action / functionName
位置: path/to/file.php:line（若无法获取行号，标注“待定位：需人工打开文件确认”但仍给出文件路径）
参数概览:
  Path: id (类型推断/约束)
  Query: {query_params}
```

### `params_{timestamp}.md`：参数详细（逐条列出）
```markdown
# {project_name} - 路由参数结构（逐条）
生成时间: {timestamp}

=== 路由: GET /path/to/{id} ===
1) Path 参数
| 参数 | 类型/约束 | 位置 | 必填 |
|------|------------|------|------|
| id   | int/regex{id_pattern} | Router rule | 是/否/不确定 |

2) Query 参数
| 参数 | 类型 | 来源 | 必填 | 说明 |

3) Body 参数（如 JSON）
| 字段 | 类型 | JSON 路径 | 必填 |

4) Header/ Cookie / File（如有）
| 字段 | 类型 | 来源 | 必填 |

5) 完整请求模板（必须在代码块里）
```http
GET /path/to/{id}?a={a}&b={b} HTTP/1.1
Host: {host}
Cookie: {cookie}
Authorization: Bearer {token}
Content-Type: application/json

{"k":"{v}"}
```
```

## 输出前自检（强制）
- [ ] routes 与 params 中每条路由“序号/路由标识”一致
- [ ] 没有出现省略占位符
- [ ] 每条路由都有“完整请求模板”代码块

