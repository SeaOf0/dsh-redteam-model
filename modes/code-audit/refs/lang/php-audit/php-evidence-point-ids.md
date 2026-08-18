# 证据点 ID 统一字典（用于 trace 契约与子 skill 对齐）

说明：
- 本文件用于让 `php-route-tracer` 的 `## 9) Sink Evidence Type Checklist` 与各子审计 skill 的“证据引用（强制）”之间实现字段级同名对齐。
- 任何子 skill 在 `证据引用（强制）` 部分必须逐项引用本字典中的证据点 ID；缺失则只能标记为 `⚠️待验证`。

### 尚未执行 `php-route-tracer` 或 trace 不可用时（避免“跑不通”）

子 skill 文中常见「必须引用 trace 的 `## 9)`」是指在**流水线正常路径**下应以 trace 为首选证据源；**不表示**没有 trace 文件就禁止出报告。此时允许且要求：

1. 仍按本字典 **逐条列出相同 `EVID_*` ID**，证据内容改为 **静态源码**（`file:line` + 关键摘录）+ 一句说明：`trace 未执行` / `trace_status=PARTIAL|UNRESOLVED`。
2. 该条结论 **仅允许** `⚠️待验证` 或 `🔍环境依赖`，**禁止** `✅已确认可利用`（与 `php-audit-pipeline` 及子 skill 自己的「证据缺失处理」一致）。
3. 若走 `php-audit-pipeline`，对应项应同步进入总报告 **「Trace 未闭合 / 待补证风险池」**（见 pipeline 阶段 5）。

如此可避免 Agent 在字面上陷入「没有 trace 就无法满足强制引用」的死锁。

## FILE（FILE 行）
- `EVID_FILE_WRAPPER_PREFIX`：wrapper/流包装前缀（如 `php://`/`phar://`/`zip://`）的使用方式
- `EVID_FILE_RESOLVED_TARGET`：包含/读取的最终解析结果（resolved target）
- `EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY`：include/require 的执行面边界（是否真的执行 PHP 代码 vs 仅读取内容/报错）

## WRITE（WRITE 行）
- `EVID_WRITE_WRITE_CALLSITE`：写入/落点变更的调用点位置证据（file_put_contents/fwrite/fopen('w')/rename/copy 等）
- `EVID_WRITE_DESTPATH_JOIN_AND_NORMALIZATION`：目的路径拼接与归一化证据（base join、净化/拒绝穿越片段、realpath 前缀校验等）
- `EVID_WRITE_DESTPATH_RESOLVED_TARGET`：最终解析落点（resolved target）证据（是否逃逸 base）
- `EVID_WRITE_CONTENT_SOURCE_INTO_WRITE`：写入内容参数与用户可控输入的映射证据
- `EVID_WRITE_TRUNCATE_OR_OVERWRITE_MODE`：覆盖/截断/追加模式证据（写入模式或覆盖策略）
- `EVID_WRITE_EXECUTION_ACCESSIBILITY_PROOF`：写完后的可执行性/可触达性证据（web 根/可包含目录/执行禁用策略等）

## UPLOAD（UPLOAD 行）
- `EVID_UPLOAD_DESTPATH`：保存目录最终落点（destPath）
- `EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE`：文件名/扩展名解析与净化逻辑
- `EVID_UPLOAD_ACCESSIBILITY_PROOF`：写入后是否形成可访问面（静态直连证据/映射证据）
- `EVID_UPLOAD_EXEC_DISABLE_STRATEGY`：服务端执行禁用策略证据（如有）

## ARCHIVE（ARCHIVE 行）
- `EVID_ARCHIVE_EXTRACT_CALLSITE`：归档解压/提取调用点位置（如 `ZipArchive->extractTo/->extract`，`PharData->extractTo`）
- `EVID_ARCHIVE_ENTRY_NAME_SOURCE`：解压条目名称/路径来源证据（archive 内 entry name/path，或从用户输入构造的条目列表）
- `EVID_ARCHIVE_ENTRY_SANITIZATION`：条目路径净化/归一化证据（去除 `../`、绝对路径、Windows 盘符等路径穿越字符）
- `EVID_ARCHIVE_EXTRACT_BASE_DIR`：解压基目录（base directory）传入证据
- `EVID_ARCHIVE_FINAL_TARGET`：最终解析目标路径（base + entry join 后的 resolved target）以及 base 目录约束判定证据（若存在）

## SSRF（SSRF 行）
- `EVID_SSRF_URL_NORMALIZATION`：URL 归一化步骤
- `EVID_SSRF_FINAL_URL_HOST_PORT`：发起请求前的最终 URL/Host/Port
- `EVID_SSRF_FINAL_REDIRECT_URL`：最终重定向后地址证据（final URL）（若存在跟随跳转）
- `EVID_SSRF_DNSIP_AND_INNER_BLOCK`：DNS/IP 解析与内网拦截判定证据

## SQL（SQL 行）
- `EVID_SQL_EXEC_POINT`：SQL 执行函数/语句位置
- `EVID_SQL_STRING_CONSTRUCTION`：SQL 字符串构造/拼接位置
- `EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT`：用户可控参数到 SQL 片段的映射证据（可控性矩阵对应字段）

## NOSQL（NOSQL 行）
- `EVID_NOSQL_QUERY_CONSTRUCTION`：NoSQL 查询构造点（find/update/delete 或 query builder 执行点）
- `EVID_NOSQL_USER_INPUT_INTO_QUERY_STRUCTURE`：用户输入进入查询条件结构的证据（可控字段进入 filter/where 的结构）
- `EVID_NOSQL_OPERATOR_INJECTION_FIELDS`：operator 注入字段证据（$ne/$gt/$or/$where/$regex）

## CMD（CMD 行）
- `EVID_CMD_EXEC_POINT`：命令执行函数/语句位置
- `EVID_CMD_COMMAND_STRING_CONSTRUCTION`：命令字符串/关键参数构造位置（拼接/模板化）
- `EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT`：用户可控参数到命令关键片段的映射证据

## XSS（XSS 行）
- `EVID_XSS_OUTPUT_POINT`：响应输出点位置（echo/printf/模板输出/`<script>`或属性或 URL 上下文）
- `EVID_XSS_USER_INPUT_INTO_OUTPUT`：用户输入进入输出的证据
- `EVID_XSS_ESCAPE_OR_RAW_CONTROL`：转义/禁用转义证据（如正确 escape 或 raw 输出关闭点）

## REDIR（REDIR 行）
- `EVID_REDIR_OUTPUT_POINT`：跳转输出点位置（`header(Location={location})`/redirect/return_to）
- `EVID_REDIR_DEST_SOURCE_MAPPING`：目的地来源变量映射证据
- `EVID_REDIR_DEST_VALIDATION_NORMALIZATION`：目的地校验/归一化/allowlist/拒绝 scheme 的分支证据（含编码绕过处理）

## CRLF（CRLF 行）
- `EVID_CRLF_OUTPUT_POINT`：响应头/ Cookie 输出点位置（header/setcookie）
- `EVID_CRLF_USER_INPUT_INTO_HEADER_COOKIE`：用户输入进入 header/cookie 值的证据（包含控制字符进入点）
- `EVID_CRLF_CONTROL_CHAR_FILTERING_ENCODING`：`\r\n` 或控制字符过滤/编码证据

## XXE（XXE 行）
- `EVID_XXE_PARSER_CALL`：XML 解析器调用点位置（DOMDocument->loadXML/simplexml_load_string/XMLReader->open）
- `EVID_XXE_INPUT_SOURCE`：输入流来源证据（php://input/上传读取/参数进入解析）
- `EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO`：外部实体/DOCTYPE 禁用相关安全选项证据 + 解析结果回显位置证据

## DESER（DESER 行）
- `EVID_DESER_CALLSITE`：反序列化调用点位置（例如 `unserialize`）
- `EVID_DESER_INPUT_SOURCE`：入参用户可控来源证据
- `EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN`：反序列化后对象类型/魔术方法触发条件证据 + 最终敏感操作点链路证据（若可定位）

## TPL（TPL 行）
- `EVID_TPL_ENGINE_RENDER_OR_PARSE_ENTRY`：模板引擎渲染/表达式解析点位置
- `EVID_TPL_TEMPLATE_OR_EXPR_CONTROL`：模板名或表达式是否可控证据
- `EVID_TPL_EXEC_CHAIN_ENTRY`：执行链入口证据（表达式求值/编译/执行）与禁用/沙箱策略证据（如存在）

## AUTH（AUTH 行）
- `EVID_AUTH_PATH_PROTECTED_MATCH`：路由进入受保护 handler 的路径匹配证据（trace 分支/路由匹配证据）
- `EVID_AUTH_TOKEN_DECODE_JUDGMENT`：登录态/Token 解码结果如何被判断的证据（session/JWT 读取与条件分支）
- `EVID_AUTH_PERMISSION_CHECK_EXEC`：权限判断函数或条件语句执行证据（如 hasRole/authorize）
- `EVID_AUTH_IDOR_OWNERSHIP_CONDITION`：IDOR/归属校验（WHERE/条件）是否包含 owner_id/user_id 的证据

## CSRF（CSRF 行）
- `EVID_CSRF_STATE_CHANGE_HANDLER_EXEC`：状态变更 handler 的执行证据（trace 的分支路径证据）
- `EVID_CSRF_TOKEN_SOURCE`：CSRF token 来源与生成证据（session/cookie/random）
- `EVID_CSRF_TOKEN_RECEIVE`：CSRF token 在请求中的接收/进入校验逻辑的位置证据
- `EVID_CSRF_TOKEN_VERIFY`：后端校验比较/哈希判断位置与早退证据
- `EVID_CSRF_BYPASS_BRANCH`：绕过分支证据（如仅校验特定 Content-Type / 仅 AJAX 校验 / 某分支不校验）

## SESS（SESS 行）
- `EVID_SESS_SESSION_INIT_REGEN`：登录后是否使用 `session_regenerate_id` 进行会话固定防护证据
- `EVID_SESS_COOKIE_FLAGS`：Cookie flags（HttpOnly/Secure/SameSite）设置证据
- `EVID_SESS_JWT_VERIFY_CLAIMS`：JWT 签名算法固定与 exp/nbf/iss/aud 的 claim 校验证据
- `EVID_SESS_LOGOUT_CLEAR`：logout 是否真正清除 session 与 token 的证据

## CFG（CFG 行）
- `EVID_CFG_CONFIG_LOCATION`：配置文件/环境变量位置证据（.env/config/php.ini/Dockerfile）
- `EVID_CFG_RUNTIME_SETTING_CODE`：运行时设置代码位置证据（ini_set/set_exception_handler/响应头中间件）
- `EVID_CFG_IMPACT_ASSOCIATION`：影响点关联证据（哪些路由/响应被该配置影响）
- `EVID_CFG_SECURITY_SWITCH_EVIDENCE`：安全头/错误暴露/CORS/危险开关等关键配置证据

## LDAP（LDAP 行）
- `EVID_LDAP_EXEC_POINT`：LDAP 查询/读/列举等执行函数/语句位置（如 `ldap_search/ldap_read/ldap_list` 或其封装）
- `EVID_LDAP_FILTER_STRING_CONSTRUCTION`：LDAP 过滤器/查询条件字符串构造/拼接位置（如构造 `(uid={uid})` 或 DN 字符串）
- `EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT`：用户可控参数到 LDAP filter/DN 片段的映射证据

## EXPR（EXPR 行）
- `EVID_EXPR_EVAL_ENTRY`：表达式解析/编译/求值入口点（如 ExpressionLanguage->evaluate/compile 或等价引擎入口）
- `EVID_EXPR_EXPR_CONTROL`：表达式字符串是否可控的证据（来自路由/请求字段/变量拼接）
- `EVID_EXPR_EXEC_CHAIN_ENTRY`：执行链入口证据（表达式求值后的结果如何被进一步使用到敏感语义上；或最终求值/执行点）

