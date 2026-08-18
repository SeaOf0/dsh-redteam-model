---
name: php-route-tracer
description: PHP Web 路由到 Sink 的多层数据流追踪工具。根据用户指定路由，追踪从 handler 到最终敏感操作点，输出层级证据、参数变量追踪、可控性分析（不做漏洞结论）。
---

# PHP Route Tracer（数据流追踪，不做漏洞结论）

根据 `php-route-mapper` 的路由（或 `php-audit-pipeline` 给出的合成入口），追踪从 **handler / CLI 入口 / 指定符号** 到最终 Sink（SQL/命令/文件/SSRF/XSS/模板渲染/反序列化等）的位置，输出完整数据流链、参数变量名变化与可控性分析。

## CRITICAL：只输出追踪，不输出漏洞建议
- 禁止给出“漏洞结论/风险等级/CVSS/修复建议”
- 只输出：数据流链证据、分支执行路径、Sink 定位、参数可控性判定表（可控性不等于漏洞结论）

## 输入依赖
- `routes_{timestamp}.md`：路由定义（独立落盘时常为 `route_mapping/routes_{timestamp}.md`，见 `shared/IO_PATH_CONVENTION.md`）
- `params_{timestamp}.md`：参数结构（独立落盘时常为 `route_mapping/params_{timestamp}.md`）
- `source_path`：源码根目录
- `route_id`：来自 `cross_analysis/high_risk_routes_{timestamp}.md`；可为 HTTP 路由序号，或 **`php-audit-pipeline` 阶段 3 的合成 ID**（`ENTRY_CLI:` / `ENTRY_CRON:` / `ENTRY_QUEUE:` / `ENTRY_HOOK:` / `ENTRY_INCLUDE:` / `SINK_ONLY:` 等）。
- **合成入口（当非 HTTP 路由时必填）**：`entry_file`（相对 `source_path`）、`entry_symbol`（函数/方法或 `global`）、`trace_from`（从何处开始向 sink 追踪的说明）。

## 追踪范围（必做）
1. handler 入口（controller 方法/闭包函数/中间件最终处理函数）；**非 HTTP 任务**时以输入中的 `entry_file` + `entry_symbol` 为追踪起点（见「输入依赖」）
2. 请求参数进入 handler 的位置（request 获取、解码 JSON、提取 $_GET/$_POST）
3. 参数在函数/方法之间的传递（assignment、数组字段访问、对象属性访问）
4. 分支条件（if/switch/try/catch/return/throw）与提前退出点
5. 最终 Sink 的调用点与参数位置（函数调用参数名/位置）

## 输出文件结构（建议）
```
{output_path}/route_tracer/
└── {route_id}/
    ├── trace_{method}_{timestamp}.md
    └── trace_all_{timestamp}.md
```
说明：**HTTP 路由**：`route_id` 宜与 `php-route-mapper` 的 `routes_{timestamp}.md` 中 `=== [N] {route_summary} ===` 的序号 `N` 一致。**CLI / hook / sink-only 等**：使用流水线合成 `route_id`，追踪起点以输入中的 `entry_file` + `entry_symbol` + `trace_from` 为准，不要求与 URI 对应。

## 单路由报告模板（强制）
```markdown
# Route Call Trace

追踪路由: {HTTP_METHOD} {route_rule}
生成时间: {timestamp}
项目路径: {source_path}

---
## 1) 完整请求模板（来自 route-mapper）
```http
{完整请求模板}
```

---
## 2) 参数进入点
| 参数 | HTTP 来源 | 进入 handler 的变量/字段 | 位置 |
|------|----------|-----------------------------|------|
|      |          |                             |      |

---
## 3) 调用链层级证据（逐层，不省略）
Level-1: {file}:{line} {Function/Class}.{method}({args})
关键代码:
```php
// 展示将参数传入下一层的关键片段
```

Level-2: {file}:{line} {Function/Class}.{method}({args})

---
## 4) 分支路径追踪（Branch Execution Proof，必须输出）
path A:
条件: {if/switch/try/catch/return/throw 的条件摘要}
执行: {在该分支下参数如何继续流转到 Sink 的摘要}
Sink：是否执行 = 是/否

path B:
条件: {另一条分支条件摘要}
执行: {另一条分支下参数的处理/提前退出摘要}

---
## 5) 参数可控性矩阵（Controllability Matrix，强制字段名与列必须一致）
| 参数 | HTTP/Body 字段 | 预处理/归一化 | Sink类型 | 覆盖类型 | 覆盖条件 | BlockReason(如有) | 可控性结论(✅/⚠️/❌) | 实际使用(是/否) | 可控场景 |
|------|------------------|------------------|-----------|-----------|-----------|--------------------|----------------------|------------------|----------|

---
## 6) Sink 定位（Sink Parameter Mapping，强制字段名与列必须一致）
| Sink类型 | 函数/方法 | 调用点(file:line) | Sink参数名/位置 | 参数映射（Sink参数 <- 可控参数） | 证据(关键代码片段) |
|----------|-----------|-------------------|-------------------|----------------------------------------------|----------------------|
```

## 7) Sink Summary（强制：用于 pipeline 的硬门槛校验）
必须输出一个汇总表（不允许省略）：
| route_id | Sink类型 | Sink函数/语句 | 是否执行(是/否) | 触发分支(条件摘要) | 关联参数(来自可控性矩阵) | 证据(代码片段) |
|----------|---------|---------------|----------------|--------------------|------------------------------|----------------------|

---
## 8) Trace 完整性声明（强制）
| trace_status | 含义 |
|-------------|------|
| COMPLETE | 调用链与 sink 证据齐全，参数可控性可判断 |
| PARTIAL | 只有局部链路证据或分支证据不完整，但 sink 存在或参数流可证明一部分 |
| UNRESOLVED | 无法定位到明确 sink 或可控性证据不足 |

并给出：
- 缺失项列表（必须逐条列出缺失：调用链层级/分支/映射/证据）
- 回退建议（允许的回退：重新 tracer 或进入对应子 skill 的 ⚠️待验证模式）

## 必做的“禁止项”
- 禁止用省略符省略调用链层级
- 禁止保留未替换模板变量（如 `${route}` 未替换为真实 route_id）
- 禁止将“不可控”与“无风险”混为一谈：本 skill 只输出可控性，不输出漏洞结论

## 9) Sink Evidence Type Checklist（强制：用于 pipeline 硬门槛）
要求在每条 trace 报告中输出本检查清单（允许内容为空，但必须存在标题与表头；并对实际命中的 sink 写出证据来源与证据片段）。

| Sink类型 | 必须包含的证据要点（来自代码/配置的可证据片段） | 证据位置 |
|----------|----------------------------------------------------|----------|
| FILE | `EVID_FILE_WRAPPER_PREFIX`: wrapper/流包装前缀（如 `php://`/`phar://`/`zip://`）的使用方式；`EVID_FILE_RESOLVED_TARGET`: 包含/读取的最终解析结果（resolved target）；`EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY`: include/require 的执行面边界（是否真的执行 PHP 代码还是仅读取报错） | file:line |
| WRITE | `EVID_WRITE_WRITE_CALLSITE`: 写入/落点变更调用点证据（如 `file_put_contents`/`fwrite`/`fopen(...,'w')`/`rename`/`copy` 等）；`EVID_WRITE_DESTPATH_JOIN_AND_NORMALIZATION`: 写入目的路径拼接与归一化证据（base join、净化/拒绝穿越片段、realpath 前缀校验等）；`EVID_WRITE_DESTPATH_RESOLVED_TARGET`: 最终解析落点 resolved target 以及 base 约束逃逸判定证据；`EVID_WRITE_CONTENT_SOURCE_INTO_WRITE`: 写入内容参数与用户可控输入的映射证据；`EVID_WRITE_TRUNCATE_OR_OVERWRITE_MODE`: 覆盖/截断/追加模式证据（写入模式或覆盖策略）；`EVID_WRITE_EXECUTION_ACCESSIBILITY_PROOF`: 写完后的可执行性/可触达性证据（web 根/可包含目录/执行禁用策略等） | file:line |
| UPLOAD | `EVID_UPLOAD_DESTPATH`: 保存目录最终落点（destPath）；`EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE`: 文件名/扩展名解析与净化逻辑；`EVID_UPLOAD_ACCESSIBILITY_PROOF`: 写入后是否形成可访问面（静态直连证据/映射证据）；`EVID_UPLOAD_EXEC_DISABLE_STRATEGY`: 服务端执行禁用策略（如有） | file:line |
| ARCHIVE | `EVID_ARCHIVE_EXTRACT_CALLSITE`: 归档解压/提取调用点位置（如 `ZipArchive->extractTo/->extract`，`PharData->extractTo` 等）；`EVID_ARCHIVE_ENTRY_NAME_SOURCE`: 解压条目名称/路径来源证据（archive 内 entry name/path 或由用户输入构造的条目列表）；`EVID_ARCHIVE_ENTRY_SANITIZATION`: 条目路径净化/归一化证据（去除 `../`、绝对路径、Windows 盘符等路径穿越字符）；`EVID_ARCHIVE_EXTRACT_BASE_DIR`: 解压基目录（base directory）传入证据；`EVID_ARCHIVE_FINAL_TARGET`: 最终解析目标路径（base + entry join 后的 resolved target）以及 base 目录约束判定证据（若存在） | file:line |
| SSRF | `EVID_SSRF_URL_NORMALIZATION`: URL 归一化步骤；`EVID_SSRF_FINAL_URL_HOST_PORT`: 发起请求前的最终 URL/Host/Port；`EVID_SSRF_FINAL_REDIRECT_URL`: 若存在重定向/跟随跳转，最终重定向后地址证据（final URL）；`EVID_SSRF_DNSIP_AND_INNER_BLOCK`: DNS/IP 解析与内网拦截判定证据 | file:line |
| SQL | `EVID_SQL_EXEC_POINT`: SQL 执行函数/语句位置（如 `$pdo->query/exec/prepare` 或 `mysqli_query` / ORM 执行点）；`EVID_SQL_STRING_CONSTRUCTION`: SQL 字符串构造/拼接位置；`EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT`: 用户可控参数到 SQL 片段的映射（可控性矩阵对应字段） | file:line |
| NOSQL | `EVID_NOSQL_QUERY_CONSTRUCTION`: NoSQL 查询构造点（find/update/delete 或 query builder）；`EVID_NOSQL_USER_INPUT_INTO_QUERY_STRUCTURE`: 用户输入进入查询条件结构的证据（可控字段进入 filter/where 的结构）；`EVID_NOSQL_OPERATOR_INJECTION_FIELDS`: operator 注入字段证据（$ne/$gt/$or/$where/$regex 等） | file:line |
| CMD | `EVID_CMD_EXEC_POINT`: 命令执行函数/语句位置（如 `exec/system/shell_exec/passthru` 或 `proc_open/popen/pcntl_exec`）；`EVID_CMD_COMMAND_STRING_CONSTRUCTION`: 命令字符串/关键参数构造位置（拼接/模板化）；`EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT`: 用户可控参数到命令片段的映射 | file:line |
| XSS | `EVID_XSS_OUTPUT_POINT`: 响应输出点位置（echo/printf/模板渲染输出/`<script>`/属性/URL 上下文）；`EVID_XSS_USER_INPUT_INTO_OUTPUT`: 用户输入进入输出的证据；`EVID_XSS_ESCAPE_OR_RAW_CONTROL`: 转义/禁用转义证据（如正确 escape 或 raw 输出关闭点） | file:line |
| REDIR | `EVID_REDIR_OUTPUT_POINT`: 跳转输出点位置（`header(Location={location})`/redirect/return_to）；`EVID_REDIR_DEST_SOURCE_MAPPING`: 目的地来源变量映射证据；`EVID_REDIR_DEST_VALIDATION_NORMALIZATION`: 目的地校验/归一化/allowlist/拒绝 scheme 的分支证据（含编码绕过处理证据） | file:line |
| CRLF | `EVID_CRLF_OUTPUT_POINT`: 响应头/ Cookie 输出点位置（header/setcookie）；`EVID_CRLF_USER_INPUT_INTO_HEADER_COOKIE`: 用户输入进入 header/cookie 值的证据；`EVID_CRLF_CONTROL_CHAR_FILTERING_ENCODING`: `\r\n` 或控制字符过滤/编码证据 | file:line |
| XXE | `EVID_XXE_PARSER_CALL`: XML 解析器调用点位置（DOMDocument->loadXML/simplexml_load_string/XMLReader->open）；`EVID_XXE_INPUT_SOURCE`: 输入流来源证据（php://input/上传读取/参数）；`EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO`: 外部实体/DOCTYPE 禁用相关安全选项证据 + 解析结果回显位置证据 | file:line |
| DESER | `EVID_DESER_CALLSITE`: 反序列化调用点位置（`unserialize` 等）；`EVID_DESER_INPUT_SOURCE`: 入参用户可控来源证据；`EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN`: 反序列化后对象类型/魔术方法触发条件证据 + 最终敏感操作点链路证据（若可定位） | file:line |
| TPL | `EVID_TPL_ENGINE_RENDER_OR_PARSE_ENTRY`: 模板引擎渲染/表达式解析点位置；`EVID_TPL_TEMPLATE_OR_EXPR_CONTROL`: 模板名或表达式是否可控证据；`EVID_TPL_EXEC_CHAIN_ENTRY`: 执行链入口证据（表达式求值/编译/执行）与禁用/沙箱策略证据（如存在） | file:line |
| LDAP | `EVID_LDAP_EXEC_POINT`: LDAP 查询/读/列举等执行函数/语句位置；`EVID_LDAP_FILTER_STRING_CONSTRUCTION`: LDAP 过滤器/查询条件字符串构造/拼接位置；`EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT`: 用户可控参数到 LDAP filter/DN 片段的映射证据 | file:line |
| EXPR | `EVID_EXPR_EVAL_ENTRY`: 表达式解析/编译/求值入口点；`EVID_EXPR_EXPR_CONTROL`: 表达式字符串是否可控的证据；`EVID_EXPR_EXEC_CHAIN_ENTRY`: 执行链入口证据（求值结果进一步进入敏感语义/或最终求值执行点） | file:line |
| AUTH | `EVID_AUTH_PATH_PROTECTED_MATCH`: 路由进入受保护 handler 的路径匹配证据；`EVID_AUTH_TOKEN_DECODE_JUDGMENT`: 登录态/Token 解码结果如何被判断证据；`EVID_AUTH_PERMISSION_CHECK_EXEC`: 权限判断函数或条件语句执行证据（如 hasRole/authorize）；`EVID_AUTH_IDOR_OWNERSHIP_CONDITION`: IDOR/归属校验（WHERE/条件）是否包含 owner_id/user_id 的证据 | file:line |
| CSRF | `EVID_CSRF_STATE_CHANGE_HANDLER_EXEC`: 状态变更 handler 的执行证据（trace 的分支路径证据）；`EVID_CSRF_TOKEN_SOURCE`: CSRF token 来源与生成证据（session/cookie/random）；`EVID_CSRF_TOKEN_RECEIVE`: CSRF token 在请求中的接收/进入校验逻辑的位置证据；`EVID_CSRF_TOKEN_VERIFY`: 后端校验比较/哈希判断位置与早退证据；`EVID_CSRF_BYPASS_BRANCH`: 绕过分支证据（如仅校验特定 Content-Type / 仅 AJAX 校验 / 某分支不校验） | file:line |
| SESS | `EVID_SESS_SESSION_INIT_REGEN`: 登录后是否 `session_regenerate_id` 等会话固定防护证据；`EVID_SESS_COOKIE_FLAGS`: Cookie flags（HttpOnly/Secure/SameSite）设置证据；`EVID_SESS_JWT_VERIFY_CLAIMS`: JWT 签名算法固定与 exp/nbf/iss/aud 等 claim 校验证据；`EVID_SESS_LOGOUT_CLEAR`: logout 是否真正清除 session 与 token 的证据 | file:line |
| CFG | `EVID_CFG_CONFIG_LOCATION`: 配置文件/环境变量位置证据（.env/config/php.ini/Dockerfile 等）；`EVID_CFG_RUNTIME_SETTING_CODE`: 运行时设置代码位置证据（ini_set/set_exception_handler/安全中间件等）；`EVID_CFG_IMPACT_ASSOCIATION`: 影响点关联证据（哪些路由/响应被该配置影响）；`EVID_CFG_SECURITY_SWITCH_EVIDENCE`: 安全头/错误暴露/CORS/危险开关等关键配置证据 | file:line |


