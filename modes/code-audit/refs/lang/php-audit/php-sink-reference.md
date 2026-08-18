# PHP 审计 Sink 与强制验证参考（按类型）

由 **`php-audit-pipeline`** 引用：用于从 trace / 静态命中判断是否触发对应 `php-*-audit` 子 skill。

**路径**：本文件位于本仓库 `shared/`，与其它 `shared/*.md` 一致，均以**项目根目录**（`php-skill-` 包根）为相对基准。各 skill 输入输出目录别名见 **`shared/IO_PATH_CONVENTION.md`**。

---

## 3.1 SQL 注入（SQL）

**Source**：任意用户输入进入字符串构造。

**Sink（常见）**：
- `$pdo->query($sql)` / `$pdo->exec($sql)` / `$pdo->prepare($sql)`（若 prepare 内仍拼接危险）
- `mysqli_query($conn, $sql)` / `mysqli_prepare($conn, $sql)`（prepare 里若拼接也算）
- ORM：`whereRaw($expr)`、`orderByRaw($expr)`、Doctrine `createQuery({base_expr} + $var)`

**危险模式**：SQL 文本与变量拼接：`.`, `sprintf`, `vsprintf`, `join`, `implode` + 用户输入。

**强制验证**：参数化绑定（PDO `?`/`:name` + `bindValue/bindParam`）；白名单/枚举（如排序字段映射）。

---

## 3.2 命令注入（CMD）

**Sink**：`exec/system/shell_exec/passthru`、`proc_open/popen/pcntl_exec`、反引号 `` `cmd` ``（cmd 含用户可控内容）。

**危险模式**：命令字符串直接拼接用户输入（`;|&`、参数、路径）。

**强制验证**：转义/白名单/参数化策略（PHP 无原生命令绑定）。

---

## 3.3 SSRF（SSRF）

**Sink**：`curl_setopt(CURLOPT_URL)` / `curl_exec`、`file_get_contents($url)`、`fopen`/`readfile`、`fsockopen`、`get_headers` 等。

**危险模式**：用户控制协议/主机/端口且缺内网拒绝与协议白名单。

**强制验证**：URL 拼接与协议分支；scheme allowlist；DNS/IP 解析后内网拦截。

---

## 3.4 XSS（XSS）

**Sink**：`echo/print/printf`、短标签输出；Twig/Blade `{!! !!}`、Smarty 等。

**危险模式**：用户输入进 HTML 上下文未 `htmlspecialchars`/等价转义。

**强制验证**：输出上下文（body/attribute/script/URL/template）；框架自动转义是否被关闭。

---

## 3.5 文件读取/路径穿越（FILE）

**Sink**：`file_get_contents/readfile/fopen`、`include/require`（拼接路径）、存储封装 `get($path)` 等。

**危险模式**：`$base.$user`、`sprintf` 路径拼接、`realpath` 误用。

**强制验证**：`realpath` + basePath、扩展名、`../` 与编码绕过。

---

## 3.6 文件上传（UPLOAD）

**Sink**：`move_uploaded_file/rename`、`$_FILES` 与保存路径拼接。

**危险模式**：仅扩展名、无 MIME/magic；文件名未随机化；Web 可访问且可执行。

**强制验证**：保存路径、鉴权、是否脱离 Web 根。

---

## 3.7 XXE（XXE）

**Sink**：`DOMDocument->loadXML`、`simplexml_load_string`、`XMLReader` 等。

**危险模式**：默认允许外部实体/DOCTYPE。

**强制验证**：禁用外部实体/DOCTYPE、`LIBXML_NONET` 等；解析结果是否回显。

---

## 3.8 反序列化（DESER）

**Sink**：`unserialize`；魔术方法链触发敏感操作。

**危险模式**：用户可控数据直接 `unserialize`。

**强制验证**：数据来源与 `__wakeup/__destruct/__call` 等触发链。

---

## 3.9 模板注入/SSTI（TPL）

**Sink**：模板名或表达式受控的渲染。

**危险模式**：用户输入进模板选择/编译表达式/raw 输出。

**强制验证**：模板引擎入口参数映射。

---

## LDAP 注入（LDAP）

**Sink**：`ldap_search/read/list` 及封装；filter/DN 参数。

**危险模式**：拼接用户输入且未 `ldap_escape`/等价；可注入 `* ) (` 等。

**强制验证**：构造点与字段映射；`ldap_escape`；可控域 allowlist。

---

## 表达式注入（EXPR）

**Sink**：`ExpressionLanguage->evaluate/compile`、`eval`、`assert`（字符串可控）、`preg_replace` `/e`。

**危险模式**：用户输入进表达式且无白名单/沙箱。

**强制验证**：表达式构造点追踪到用户输入；引擎白名单/沙箱配置。

---

## 3.10 鉴权绕过/越权（AUTH）

**检查点**：受保护资源前登录与权限校验；多入口绕过同一鉴权链。

**强制验证**：Session/JWT 与 RBAC；`isAdmin/hasRole/authorize` 误用或早退。

---

## 3.11 CSRF（CSRF）

**检查点**：状态变更方法与 token 校验覆盖所有分支/Content-Type/AJAX。

**强制验证**：token 来源、接收、校验比较；绕过分支说明。

---

## 3.12 开放重定向（REDIR）

**Sink**：`header(Location)`、`redirect()` 等。

**强制验证**：目的地变量映射；归一化后 allowlist/scheme 拒绝。

---

## 3.13 CRLF（CRLF）

**Sink**：`header()` 值、`setcookie()` 参数。

**强制验证**：`\r\n`/控制字符过滤；PoC 体现 `%0d%0a` 可控链。

---

## 3.14 会话与 Cookie（SESS）

**Sink**：`session_regenerate_id` 时机；Cookie flags；JWT claims；logout 清理。

**强制验证**：证据落到具体代码与配置。

---

## 3.15 配置安全（CFG）

**Sink**：CORS、错误暴露、安全头、危险 `php.ini` 组合。

**强制验证**：配置与入口/响应链关联；证据路径。

---

## 3.16 归档解压（ARCHIVE / Zip Slip）

**Sink**：`ZipArchive->extractTo`、`PharData->extractTo`、自定义解压拼接 entry。

**危险模式**：entry 穿越 base；未归一化或可绕过。

**强制验证**：entry 来源；resolved path 仍在 base 内；净化在解析前完成。
