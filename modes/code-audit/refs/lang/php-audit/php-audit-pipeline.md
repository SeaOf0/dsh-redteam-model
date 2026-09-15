---
name: php-audit-pipeline
description: PHP Web 全链路白盒代码安全审计流水线（多文件版编排）。作为总编排参考，按 Sink 类型调用各子审计 skill（`php-route-mapper/php-auth-audit/php-route-tracer/php-*-audit`），并复用统一输出与分级标准。
---

## 运行依赖说明（避免误导）
本 skill 在当前安装形态下是“文档编排/方法论”版本，通常不会在本地仓库中提供可执行脚本（例如 `scripts/*.py`）。
当环境中不存在对应执行器时，应直接使用文档里描述的阶段化流程（route-mapper / auth-audit / vuln-scanner / route-tracer 等）进行源码分析与报告生成；如果看到“正在寻找执行器脚本”的提示，可将其视为“未找到执行器，改走阶段化降级流程”，不要把它当作路径错误。

## 无执行器时的人工等价落地（推荐）
当环境缺少可执行流水线脚本或 `trace` 证据不足时，可以按“等价方法论”手工完成同一目标：输出可修复的漏洞审计结论，并确保“可利用性与执行点”不过度推断。

1. 先做关键字/函数抓手定位（Source/Sink）
   - 从 `source_path` 根目录开始递归遍历（不限定具体业务目录；默认仍排除 `vendor/`、缓存目录，可按需要调整）检索 Source/Sink 候选。
   - 对每个命中的 Sink，记录：文件路径、函数/方法签名、所在控制器/中间件/服务类上下文、sink 参数变量名。

2. 再做参数可控性验证（可控性矩阵）
   - 追踪 sink 参数变量来自哪里：例如 `get_params()`、`request()->post()`、`$_GET/$_POST/$_REQUEST`、body（`php://input`）、header/cookie。
   - 判断该参数在进入危险拼接/执行前是否被：白名单/枚举校验、类型转换、转义/过滤、长度/字符集约束等硬化覆盖。
   - 输出可控性状态：`✅完全可控 / ⚠️条件可控 / ❌不可控`，并写出拦截/硬化点的代码证据位置。

3. 最后做执行点确认（真实落点）
   - 确认该 sink 参数最终是否真的在危险上下文执行，而不是仅被传入后又被安全处理或未真正触发。
   - 若无法证明“真实落点执行”，一律标记为 `⚠️待验证` / `🔍环境依赖`，不要写 `✅已确认可利用`。

4. 输出建议（用于降低误报）
   - 只要涉及“执行点/分支”无法完整证明，就把结论降级为待验证，并把缺失证据点写清楚（例如：分支条件未覆盖、输入在上游被过滤、trace-gate 不满足等）。

（可选）示例验证抓手（与你的本次审计一致，作为参考，不作为唯一标准）：
- `Db::query($sql)` / 动态查询相关调用：验证 `$sql` 是否由用户输入拼接或经过不充分校验。
- `unlink()` / `rmdir()` / `fopen()` / `opendir()`：验证路径参数来源与路径穿越/相对路径归一化情况。
- `Filesystem::putFileAs(...)`：验证落点目录是否可控、是否可被 Web 访问、是否可执行。
- `unserialize($data)`：验证 `$data` 是否直接/间接来自用户输入，以及是否存在可触发魔术方法链。
- `curl_exec` / `curl_setopt(CURLOPT_URL, $url)`：验证 URL 是否可控，协议/内网过滤是否存在。

# PHP 全链路代码审计流水线（白盒）

你是一位高级白盒安全审计专家。你的目标不是“找一两个危险点”，而是以**数据流分析 + 业务逻辑验证**的方式，输出一份可用于落地修复的安全审计报告。

## 编排说明
本流水线采用“先分后合”的两阶段输出策略：

1. **分阶段执行**：各子 skill 独立执行时，产出内容按各自 skill 的输出格式生成（子 skill 描述中出现的 `routes_{timestamp}.md`、`vuln_audit/sql_{timestamp}.md` 等路径，表示各子 skill 的逻辑输出单元，而非独立落盘文件）。
2. **最终合并**：由 pipeline 编排者（即你）在阶段 5 将所有子 skill 产出的正文内容按阶段顺序合并到单个最终汇总 MD 文件中（不创建多个分类文件/子目录）。

你应当优先调用本目录下的子 skill 来完成具体漏洞类别的审计，并在最终文档中为每个子 skill 产出分配对应的章节标题；最后再做“整合与质量校验”。

## 子审计覆盖矩阵（强制）

阶段 4 与阶段 5 的「质量报告章节」中必须包含 **子 skill / 审计面覆盖矩阵**（建议放在靠前位置）。**矩阵的每一行**须与下文「子 Skill 对照表」中的能力一一对应（含路由、鉴权、trace、供应链、各专项 `php-*-audit`）。列至少包含：

| 列 | 含义 |
|----|------|
| 子 skill 或审计面 | 与对照表名称一致 |
| 状态 | **已执行** / **不适用** / **已延期**（三选一，禁止留空） |
| 触发依据 | 已执行：依据（trace-gate、静态 sink、配置证据等）；不适用：**否定证据**（如全仓库检索无相关 API，须写明范围与 ripgrep 模式）；已延期：**残留风险**与补做条件 |
| 产出锚点 | 总报告中章节标题或段落首句，便于复核 |

**规则**：不要求单次会话内对每个子 skill 都执行一遍；但 **矩阵须 100% 行有结论**。「不适用」「已延期」必须符合上表证据要求，禁止无理由空行。

## 角色与方法
### 三层分析法（强制）
- **面**：模式/关键字扫描，快速定位高风险区域
- **线**：逐行审计并追踪变量流向（Source → Sink）
- **点**：逻辑验证，确认绕过/利用是否真的成立

### 10 个安全维度
- D1 注入：SQL/命令/LDAP/SSRF/模板注入/SSTI/表达式注入
- D2 认证：Token/Session/JWT/框架认证链
- D3 授权：越权一致性、IDOR、RBAC/ABAC 校验
- D4 反序列化：unserialize/object injection gadget
- D5 文件操作：上传/下载/路径穿越/包含任意文件
- D6 SSRF：URL 注入、协议限制、内网访问限制
- D7 加密：密钥管理、密码模式、签名/校验弱点
- D8 配置：CORS/错误暴露/调试开关/安全头
- D9 业务逻辑：竞态、Mass Assignment、状态机缺陷
- D10 供应链：Composer 依赖已知漏洞

## 漏洞分级（强制使用）
### 严重等级计算公式
```
严重等级 = f(可达性, 影响范围, 利用复杂度)
Score = R × 0.40 + I × 0.35 + C × 0.25
CVSS 映射 = Score / 3.0 × 10.0
```

### 三维评分标准（强制）
- **可达性 R**
  - 3：无需认证，HTTP 直接可达
  - 2：需要普通用户认证
  - 1：需要管理员权限或内网访问
  - 0：代码不可达/死代码
- **影响范围 I**
  - 3：RCE/任意文件写入/完全数据泄露/系统沦陷
  - 2：敏感数据泄露/越权/部分文件读取
  - 1：有限信息泄露/低影响配置读取
  - 0：无实际安全影响
- **利用复杂度 C**
  - 3：低复杂度（单次请求可用）
  - 2：中复杂度（需构造 payload 或多步操作）
  - 1：高复杂度（需要特定环境/竞态/链式利用）
  - 0：不可利用（有效防护，绕不过）

### 等级映射（强制）
- 🔴 C（Critical）：CVSS 9.0-10.0
- 🟠 H（High）：CVSS 7.0-8.9
- 🟡 M（Medium）：CVSS 4.0-6.9
- 🔵 L（Low）：CVSS 0.1-3.9

### 漏洞编号规范（强制）
格式：`{等级前缀}-{类型代码}-{序号}`

类型代码（PHP 版扩展）：
- `SQL`：SQL 注入
- `NOSQL`：NoSQL 注入
- `CMD`：命令注入
- `SSRF`：SSRF
- `XSS`：跨站脚本
- `FILE`：任意文件读取/路径穿越
- `UPLOAD`：任意文件上传/可执行上传
- `WRITE`：任意文件写入（路径穿越到写入落点）
- `REDIR`：开放重定向
- `CRLF`：CRLF/响应分割
- `XXE`：XXE
- `DESER`：反序列化/对象注入
- `TPL`：模板注入/SSTI
- `LDAP`：LDAP 注入/查询过滤器注入/DN 注入
- `EXPR`：表达式注入（非模板表达式求值；包含 eval/assert 等）
- `AUTH`：认证/鉴权绕过/越权（含 IDOR）
- `CSRF`：CSRF
- `SESS`：会话固定/Cookie flags/JWT 校验缺陷/注销不彻底
- `CFG`：安全配置/CORS/错误暴露/安全头/危险开关
- `CRYPTO`：加密与密钥安全缺陷
- `LOGIC`：业务逻辑漏洞（Mass Assignment/竞态/状态机/流程绕过等）
- `FS`：文件系统操作风险（权限/链接/删除/TOCTOU 等用于链式利用）
- `LOG`：安全日志与监控缺陷（缺失审计/敏感信息写入/日志注入等）

## 关键约束（强制）
### 完整性约束
1. **禁止省略**：不得出现任何省略占位符；所有清单必须逐项完整输出。
2. **禁止模板未替换**：所有请求/PoC 模板必须用真实路由与真实参数完成替换，不得保留 `${var}`。对于请求头/Body 中的主机与会话字段，统一使用 `{host}`/`{cookie}`/`{token}` 等占位符，不得出现未替换的 `{{...}}`。
3. **禁止只给结论**：每个高危漏洞必须包含“位置证据 + 数据流链 + 可利用性分析 + 验证 PoC + 修复建议”。
4. **非漏洞必须有解释**：对于可疑模式，必须给出“被硬编码覆盖/被校验拦截/绕过无效/仅 Blind 无法验证”等结论与证据。

### 输出完整性校验（强制）
完成后必须执行以下检查清单：
- [ ] 路由清单与参数清单“非空且数量一致”（若拆分到多个文件，分别检查各自完整性）
- [ ] 鉴权映射表覆盖所有接口（或标明“此接口为静态资源/非入口/无路由绑定”但同样要落表）
- [ ] 漏洞清单中每条漏洞均有：编号、等级、位置、数据流链、可利用性、验证 PoC、修复建议
- [ ] 报告内没有未替换的模板占位符（例如 `${var}` 或未替换的 `{{...}}`）

## 输入
用户提供：
- `source_path`：PHP 项目源码路径（可为目录、仓库根目录）
- `output_path`：输出目录路径（默认 `{source_path}_audit`）

派生变量（用于保证各子 skill 输出可对齐）：
- `project_name`：从 `source_path` 目录名提取（basename）
- `timestamp`：生成时间戳，建议格式为 `YYYY_MM_DD_HH_mm`（用于文件名示例：`2026_03_20_18_00`）

## 输出目录结构（建议强制）
```
{output_path}/
└── {project_name}_代码审计_{timestamp}.md
```

说明：
- 后文出现的 `routes_{timestamp}.md`、`auth_mapping_{timestamp}.md`、`vuln_audit/sql_{timestamp}.md` 等“文件路径”，都仅表示要写入本次总报告中的对应章节内容分段；不落地为独立文件。
- 同理，“读取文件”改为“引用本报告中已生成的对应章节内容”。
- **与子 skill 的路径统一**：各子 skill 中出现的 `route_mapping/routes_*.md` 等与上表**逻辑等价**，详见 `shared/IO_PATH_CONVENTION.md`（流水线合并 vs 独立落盘）。

## 执行流程（阶段化流水线：更高真阳性）

### 漏报抑制（强制，贯穿各阶段）

- **禁止静默丢弃**：`trace_status = UNRESOLVED`、未进入 `SINK_SUSPECT` 启发式列表、或 trace 契约未通过时，**不得**在报告中消失。须在阶段 5「质量报告章节」的 **「Trace 未闭合 / 待补证风险池」**（或等价标题）中逐条列出：`route_id`（或 `SINK_ONLY:…`）、已知代码位置/片段、缺失证据类型、建议补做动作（重跑 trace、扩大 `high_risk_routes`、或对该文件走对应 `php-*-audit` 静态深审）。
- **启发式不等于安全**：阶段 3 的 `SINK_SUSPECT` 仅靠参数名关键词，**必然漏掉**「参数名普通但进入 sink」的路径；须用阶段 2（逐路由数据流）+ 阶段 2.5（全局 sink 兜底）+ 各子 skill 的 sink 扫描互相补齐。
- **阶段 2.5 与阶段 4 的关系**：2.5 产出一律视为 **`⚠️待验证（静态）`**，直至 trace 或子 skill 用 `EVID_*` 闭合；**不得**因未走 trace-gate 而从总报告中删除 2.5 条目。
- **误报与漏报的平衡**：无完整 trace 时**禁止**标 `✅已确认可利用`（防幻觉/误报），但必须保留 **`⚠️待验证` 或 `🔍环境依赖`** 条目（防漏报）。

### 阶段 1：侦察（Recon）
目标：识别全部“入口→路由→参数→认证链”的基础数据。

1. **识别技术栈/入口形态（必做）**
   - Laravel：`routes/web.php`、`routes/api.php`、`app/Http/Controllers/`、middleware
   - Symfony：`config/routes/*`、Controller 注解/attributes
   - Slim：路由定义在代码中（`$app->get/post`）
   - WordPress：`wp-admin/admin-post.php`、`admin-ajax.php`、hook 回调
   - 原生 PHP：front controller、`index.php`、`include` 链、`$_GET/$_POST` 分发
2. **枚举路由/入口（必做，禁止省略）**
   - 从路由配置或分发逻辑中提取：HTTP 方法、路径/规则、对应 handler（文件/函数/类方法）
   - 对动态路由（如 `{id}`、正则路由、WordPress 参数路由）必须写出“解析规则与可控参数列表”
3. **枚举参数（必做）**
   - 识别 Source：`$_GET/$_POST/$_REQUEST/$_FILES/$_COOKIE`、`php://input`、`getallheaders()`
   - 识别 JSON：`json_decode(file_get_contents('php://input'), true)`
   - 识别文件：`$_FILES['{file_field}']` 字段与文件名来源（`name`/`tmp_name`）
4. **识别认证链与会话机制（必做）**
   - Session：`session_start()`、`$_SESSION['key']`、登录态判断
   - JWT：`JWT::decode`、签名校验逻辑、`Authorization: Bearer`
   - Middlewares：Laravel middleware、Symfony event listener、Slim middleware
   - 自定义鉴权：`checkAuth()/requireLogin()/authorize()` 类函数

5. **生成鉴权映射（静态映射，先不依赖 trace）**
   - 调用：`php-auth-audit`
   - 模式：`STATIC_MAPPING`（仅生成 `auth_mapping_{timestamp}.md` 用于 P0/P1 路由分桶）
   - 约束：当尚未生成 `route_tracer/` trace 时，允许“缺少 trace 契约证据点”，但必须输出“鉴权状态分级 + P0/P1 分桶依据”

6. **供应链漏洞扫描（组件已知 CVE/Advisory）**
   - 调用：`php-vuln-scanner`
   - 输出：`vuln_report/{project_name}_composer_vuln_report_{timestamp}.md`

7. **框架特效审计（可选：检测到对应框架才调用）**
   - 检测原则（必做）：依据 `composer.json` 依赖与典型目录/入口文件特征识别 Laravel/Symfony/WordPress/CodeIgniter/Yii2
   - Laravel：调用 `php-laravel-audit`，输出 `framework_audit/laravel_{timestamp}.md`
   - Symfony：调用 `php-symfony-audit`，输出 `framework_audit/symfony_{timestamp}.md`
   - WordPress：调用 `php-wordpress-audit`，输出 `framework_audit/wordpress_{timestamp}.md`
   - CodeIgniter：调用 `php-codeigniter-audit`，输出 `framework_audit/codeigniter_{timestamp}.md`
   - Yii2：调用 `php-yii-audit`，输出 `framework_audit/yii_{timestamp}.md`
   - ThinkPHP：调用 `php-thinkphp-audit`，输出 `framework_audit/thinkphp_{timestamp}.md`

阶段 1 输出：
- `routes_{timestamp}.md`：完整路由清单（逐条）
- `params_{timestamp}.md`：每条路由参数来源与类型/结构（逐条）
- `auth_audit/auth_mapping_{timestamp}.md`：路由鉴权映射（含 P0/P1 分桶依据）
- `vuln_report/{project_name}_composer_vuln_report_{timestamp}.md`：组件漏洞清单（用于推断受影响路由）
- `framework_audit/*_{timestamp}.md`：框架特效审计报告（仅在阶段 1 检测到对应框架时产出）

### 阶段 2：建模（Modeling）
目标：建立 Source → Sink 数据流图的“可追踪版本”。

对每个路由，建立至少一条“从入口参数到敏感 Sink 的最短路径”，并记录：
- Source 参数名/数据结构字段路径（如 `pageJson.orderBy` 的 PHP 对应：数组字段路径）
- 中间变量名变化（assignment/concat/transform）
- 分支条件（if/switch/try/catch）与提前返回（return/throw）
- Sink 类型与调用点（文件/行号/函数名）

阶段 2 输出：
- 路由级数据流链证据（建议嵌入到 `vuln_audit/*` 或单独建 `dataflow_tracer/`，这里保持简洁：内联到漏洞报告中也可）

### 阶段 2.5：Sink-only 全局扫描兜底（提升召回，覆盖 RCE 及扩展高危）
目标：在路由枚举/trace-gate 失败或证据不足时，仍能通过“静态 Sink 命中 + 本地可控性回溯 + 执行点确认”找到高危点，并一律降级为 `⚠️待验证（静态证据）`，**直至**阶段 3/4 补证。

> **与阶段 3/4 的差异**：阶段 2.5 面向全部 PHP 源文件做“宽谱 Sink 初筛”，不依赖路由完整性与 trace 完整性，产出进入降级候选池；阶段 3/4 则在路由+trace 完成后，针对 trace-gate 通过的 Sink 做“高置信度精确审计”。两者扫描范围可能重叠，但执行时机、目标精度和输出流向不同——阶段 2.5 的产出不会替代阶段 4 的确认结果，仅作为补漏兜底。

1. 扫描范围（不限定目录）
   - 从 `source_path` 根目录开始递归遍历，覆盖项目内所有 PHP 源文件（例如 `*.php`）。
   - 为减少噪音可默认排除 `vendor/` 与缓存目录（如需最大召回可把排除策略关闭）。

2. **必覆盖 Sink 集合（最低集）**（防 RCE/对象注入漏报）
   - CMD：`exec/system/shell_exec/passthru/proc_open/popen/pcntl_exec` 与反引号 `` `cmd` ``
   - EXPR：`eval/assert` 以及已弃用但仍常见的 `preg_replace(..., ..., .../e)` 风险点
   - FILE（执行面边界）：`include/require` 在“可执行内容/执行边界”上存在风险时（仅读取不等于 RCE，需确认执行语义）
   - DESER：`unserialize(...)` 在可控输入链上存在潜在魔术方法执行链（静态证据足够时再升级；否则待验证）
3. **扩展扫描（强烈推荐，防 SQL/SSRF/任意读等漏报）**：在业务代码目录上，按 `shared/PHP_SINK_REFERENCE.md` 再扫一轮 **SQL 执行族**（`query/exec/prepare`+拼接线索）、**SSRF 族**（`curl_exec`/`file_get_contents($url)` 等）、**任意读族**（`file_get_contents`/`fopen`+路径拼接）。命中写入同一 `sink_static_index_{timestamp}.md`（或扩展 `rce_sinks` 附录），条目标注「扩展扫描」；结论仍为 `⚠️待验证` 直至 trace 或对应 `php-sql-audit`/`php-ssrf-audit`/`php-file-read-audit` 闭合。

4. 每个命中点的本地分析（必须输出）
   - 位置：`file:line`、函数/语句、sink 参数表达式（原样摘录关键片段）
   - 可控性回溯：在同一文件/相邻调用链内追踪 sink 参数是否来自请求输入（`get/post/request()->param()`、`$_GET/$_POST/$_REQUEST`、JSON `php://input` 解码结果、header/cookie 等）
   - 执行点确认：若无法证明危险上下文真的会执行（例如分支提前 return/异常跳过/被过滤），结论必须降级为 `⚠️待验证`

5. 输出与汇总规则（不依赖 route_id）
   - 输出到 `{output_path}/global_sink_fallback/`：
     - `rce_sinks_{timestamp}.md`：RCE/高危执行点静态命中清单（每条包含位置、可控性回溯证据、执行点确认与结论降级理由）
     - `sink_static_index_{timestamp}.md`：静态命中索引（用于质量统计与后续手工补全 trace）
   - 阶段 5 汇总时：在“质量报告章节”的“漏洞列表总览”中额外引用 `global_sink_fallback/rce_sinks_{timestamp}.md`，并将这些项标注为“静态证据（非 trace-gate）”。

### 阶段 3：分批追踪（Only When Trace Proves）
目标：通过 `php-route-tracer` 的“实际执行证据”，把漏洞挖掘从“关键字扫描”升级为“可控性与分支证据驱动”，最大化真阳性。

阶段 3 必须按以下顺序执行：
1. **生成高危路由集合**：
   - 读取 `auth_audit/auth_mapping_{timestamp}.md`，提取 P0（❌无鉴权）与 P1（⚠️仅认证 或 🔓可绕过/越权/IDOR 的风险路由）
   - 读取 `vuln_report/{project_name}_composer_vuln_report_{timestamp}.md`，把与解析入口/敏感功能相关的组件漏洞触发点“推断映射”到可能受影响路由，并标注“推断理由”
   - 基于静态参数线索补充 `SINK_SUSPECT` 路由（不依赖 trace 证据点，trace-gate 在阶段 4 再做硬门槛确认）
     - LDAP：参数名/字段名包含 `dn/baseDn/filter/searchFilter/ldap/filterString` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - EXPR：参数名/字段名包含 `expr/expression/condition/where/rule/eval` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - SQL：参数名/字段名包含 `sql/query/filter/orderBy/sort/limit/search` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - CMD：参数名/字段名包含 `cmd/command/exec/shell/run/path/filename` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - SSRF：参数名/字段名包含 `url/uri/target/host/port/protocol/path` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - FILE：参数名/字段名包含 `file/path/filename/download/view/document/template` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - UPLOAD：参数名/字段名包含 `upload/file/tmp_name/filename/multipart` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - WRITE：参数名/字段名包含 `write/put_contents/fwrite/fopen/rename/copy/truncate/error_log/dest/path/target/path` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - XSS：参数名/字段名包含 `content/body/comment/title/description/html` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - TPL：参数名/字段名包含 `template/view/engine/renderer/format/expr` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - XXE：参数名/字段名包含 `xml/doctype/dtd/xxe` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - DESER：参数名/字段名包含 `serialize/unserialize/payload/object/serialized` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - NOSQL：参数名/字段名包含 `filter/query/where/operator/op/regex/whereClause` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - REDIR：参数名/字段名包含 `next/return_to/redirect/target/url` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - CRLF：参数名/字段名包含 `header/cookie/location/set-cookie` 等关键词（或其在路由 params 中的 JSON 字段路径）
     - ARCHIVE：参数名/字段名包含 `zip/tar/phar/archive/entry/extractTo/unzip/untar` 等关键词（或其在路由 params 中的 JSON 字段路径）
   - **合成 `route_id`（强制）**：条目来自 CLI/cron/队列、WordPress hook、`include` 链、阶段 2.5 静态 sink 等**且无 HTTP 路由**时，须使用稳定 ID（禁止留空），并在同行写明 `entry_file`（相对 `source_path`）、`entry_symbol`（函数/方法或 `global`）、`trace_from`（从何处开始向 sink 追踪）。推荐：`ENTRY_CLI:{脚本标识}`、`ENTRY_CRON:{任务名}`、`ENTRY_QUEUE:{消费者类或文件}`、`ENTRY_HOOK:{hook 名}`、`ENTRY_INCLUDE:{文件}:{符号}`、`SINK_ONLY:{序号}:{基名}:{行号}`（可与 `sink_static_index` 交叉引用）。
   - 输出：`cross_analysis/high_risk_routes_{timestamp}.md`（含 P0/P1/SINK_SUSPECT；**每条须有 `route_id`**（含合成 ID）。`php-route-tracer` 以 `route_id` 标识任务，追踪起点以 `entry_file`+`entry_symbol`+`trace_from` 为准，不要求 ID 形如 URI。）
2. **生成分批追踪计划**：
   - 读取 `high_risk_routes_{timestamp}.md`
   - **分批参数化（强制）**：顺序 **P0 → P1 → SINK_SUSPECT**。`trace_batch_max_size` **默认 10**，可在 **5–30** 间按项目调整；须在计划中写**选型理由**（例：同模块可合并加大批次；调用链深、跨文件多、参数面宽或上下文预算紧则减小批次）。
   - `trace_batch_plan_{timestamp}.md` **每一批**须含：`batch_id`、本批采用的 `trace_batch_max_size`、**选型理由**（1–3 句）、本批 `route_id` 有序列表。
   - 输出：`cross_analysis/trace_batch_plan_{timestamp}.md`
3. **批量调用追踪器**（必须）：
   - 对每批路由调用 `php-route-tracer`
   - 输出：`route_tracer/{route_id}/trace_{timestamp}.md`
4. **触发条件（硬门槛）**：
   - 只有当某类 sink 在 trace 中出现“真实 sink 执行点”，且 trace 契约校验通过，且对应参数在 trace 的可控性矩阵里不是“不可控/无实际使用（被硬编码覆盖）”，才允许进入阶段 4 触发对应 `php-*-audit`

5. **trace 契约校验（必须）**：
   - 每个 trace 文件必须包含以下段落/表头（字段名必须一致，不得重命名）：
     - `## 7) Sink Summary`
     - `## 5) 参数可控性矩阵`
     - `## 6) Sink 定位`
     - `## 8) Trace 完整性声明`
     - `## 9) Sink Evidence Type Checklist`
   - 如果 trace 契约校验失败：
     - 必须标记该 route 的 trace 为 `PARTIAL` 或 `UNRESOLVED`
     - 对所有由该 trace 支持的漏洞，状态必须降级为 `⚠️待验证`，且不得直接给出 `✅已确认可利用`。

Sink 类型抓手、危险模式与强制验证的完整条文见本仓库 **`shared/PHP_SINK_REFERENCE.md`**（章节 3.1–3.16 及 LDAP/EXPR）。阶段 3/4 据 trace 筛选是否触发对应 `php-*-audit` 时，以该文件为准。

阶段 3 输出：
- `cross_analysis/high_risk_routes_{timestamp}.md`
- `cross_analysis/trace_batch_plan_{timestamp}.md`
- `route_tracer/` 下每条追踪路由的 `trace_{timestamp}.md`（含参数可控性表与分支路径证据）

### 阶段 4：Sink 审计执行（Only When Trace Proves）
步骤：
1. 从 `route_tracer/` 的 trace 中筛选需要“trace-gate”的漏洞类别与“参数实际使用状态”（必须以 trace 可控性矩阵为准）。
   - trace-gate 类别：SQL/NOSQL/CMD/SSRF/FILE/UPLOAD/WRITE/ARCHIVE/XSS/REDIR/CRLF/XXE/DESER/TPL/LDAP/EXPR/AUTH/CSRF/SESS
   - 非 trace-gate 类别：CFG/CRYPTO/LOGIC/LOG（可基于静态扫描与代码配置证据直接调用对应 skill，**不以** trace `## 9) … CFG` **作为**唯一门槛）。说明：`php-route-tracer` 的检查表中虽含 CFG 行，仅作**增强证据**；`php-config-audit` 等仍须在阶段 4 **无条件按计划执行**（除非覆盖矩阵中已用否定证据标为不适用）。
2. 仅对命中的类别调用对应子审计 skill；并满足以下“证据来源”规则（禁止仅凭关键字推断）：
   - 若类别属于 trace-gate：必须逐项引用 `php-route-tracer` 的 `## 9) Sink Evidence Type Checklist` 对应行（FILE/UPLOAD/WRITE/ARCHIVE/SSRF/SQL/NOSQL/CMD/XSS/REDIR/CRLF/XXE/DESER/TPL/LDAP/EXPR/AUTH/CSRF/SESS）的证据要点作为审计依据（要求证据点 ID 原样一致）
   - 若类别为 `AUTH`：调用 `php-auth-audit` 的 `TRACE_AUDIT` 模式（必须引用 trace 证据点 ID）
3. 对每条疑似漏洞，必须输出“可利用性前置条件”：
- 鉴权要求：✅无需 / ⚠️需登录 / ❌不可利用门槛
- 输入可控性：✅完全可控 / ⚠️条件可控 / ❌不可控（硬编码覆盖）
- 触发条件：分支条件/异常路径/环境依赖（数据库类型、网络可达性）

4. **trace 完整性回退规则（必须）**：
   - 若 trace_status = PARTIAL：只能进入 `⚠️待验证` 模式（不得直接给出 `✅已确认可利用`）
   - 若 trace_status = UNRESOLVED：**禁止静默漏报**——不得写成「无风险」或从报告中消失。必须在总报告 **「Trace 未闭合 / 待补证风险池」** 中为该 `route_id` 单列一条：`已知片段`（来自 trace 的可达部分）、`缺失证据`、`建议下一步`（补 trace / 纳入 `SINK_ONLY` 静态深审 / 调用对应 `php-*-audit`）。若该路由与阶段 2.5 静态命中可关联，须写交叉引用。

5. **文件系统操作审计（非 trace-gate，静态证据驱动）**：
   - 调用：`php-filesystem-audit`
   - 输出：`vuln_audit/fs_{timestamp}.md`
   - 判定规则：允许基于源代码定位的“文件系统操作证据链 + 路径控制来源 + TOCTOU/链接绕过解释”直接输出 `✅/⚠️/❌/🔍`，不以 `php-route-tracer` 的证据契约字段为前置硬门槛

并最终给出：
- 状态：✅已确认 / ⚠️待验证 / ❌不可利用 / 🔍环境依赖
- 严重等级与 CVSS 映射（按上方公式）

### 阶段 5：汇总报告（Report）
在总报告中生成“质量报告章节”，包含：
- **子 skill / 审计面覆盖矩阵**：与上文「子审计覆盖矩阵（强制）」同结构，置于质量报告靠前位置；须与阶段 4 实际执行情况一致，不得矛盾。
- 风险统计表（🔴/🟠/🟡/🔵 数量与 CVSS 区间）
- 漏洞列表总览（逐条引用本报告中对应的漏洞详情段落）
- **「Trace 未闭合 / 待补证风险池」**（强制）：汇总 `trace_status ∈ {PARTIAL, UNRESOLVED}` 的 `route_id`、阶段 2.5 `sink_static_index` 中尚未被 trace 闭合的条目、以及「扩展扫描」命中项；与「漏洞列表总览」并列，**禁止**因证据不足而删除记录（未闭合 ≠ 无风险）。
- 覆盖率：路由覆盖、鉴权覆盖、Sink 覆盖、关键分支覆盖（用“已完成/待补充”而非省略；建议阈值：路由覆盖与 Sink 覆盖 >= 90%）
- 框架特效审计汇总：如果存在 `framework_audit/*.md`，需要将其风险映射到统一类型码（AUTH/CSRF/TPL/XSS/SQL/LOGIC/CFG/SESS/SSRF/…），统计数量与最高严重等级，并在汇总中注明“框架风险来源于哪些 framework_audit 报告文件”

  > **框架审计豁免说明**：框架特效审计（Laravel/Symfony/WordPress/CodeIgniter/Yii2/ThinkPHP）属于“静态配置/模式匹配”型审计，其发现的风险不需要经过 `php-route-tracer` 的 trace-gate 或 `## 9) Sink Evidence Type Checklist` 的证据校验。框架审计结果直接按其自身规则分级并映射到统一类型码即可。
- 证据完整度评分（Evidence Completeness）：对所有 trace-gate sink 类型（FILE/UPLOAD/WRITE/ARCHIVE/SSRF/SQL/NOSQL/CMD/XSS/REDIR/CRLF/XXE/DESER/TPL/LDAP/EXPR/AUTH/CSRF/SESS），按 `shared/EVIDENCE_POINT_IDS.md` 中定义的证据点 ID 集合进行计数：`覆盖率% = 已满足证据点数 / 该类型所需证据点总数 × 100%`；并在表格中列出缺失的证据点 ID（必须原样一致）与缺失原因（如 trace_status=PARTIAL/UNRESOLVED、证据点定位失败、参数不可控等）。

阶段 5.1：利用链聚合（强制）
- 调用：`php-exploit-chain-audit`
- 在“质量报告章节”的“漏洞列表总览”之后增加一段“利用链聚合章节”：引用利用链聚合报告的链路总览表与最短利用链（只需引用、不重复内容）。

## 漏洞详情模板（强制使用）
每条漏洞必须遵循以下结构（写入本次总报告的漏洞详情段落）：
```markdown
### [{等级前缀}-{类型代码}-{序号}] {风险标题}

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {文件路径}:{行号} ({函数/方法}) |

#### 数据流链（Source → Sink）
```
(按路由逐行写出赋值/传递/拼接/校验/分支，禁止省略)

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常/环境依赖}

#### 验证 PoC（强制给出可执行请求）
```http
{HTTP Method} {完整路径与查询/Body} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```

#### 建议修复
- 以“代码替换建议”为主（给出安全写法要点）
- 给出“如何在代码中搜索修复是否遗漏”的搜索语句（bash/rg 形式）
```

## 说明文档（审计 READMEs）
必须在本次总报告内生成以下附录章节：
- 如何识别 PHP 路由与参数
- 如何识别会话/JWT 并审计鉴权链
- 如何结合 `shared/PHP_SINK_REFERENCE.md` 做按类型的 Sink 挖掘与 trace-gate 对齐

## 自检与质量保证（强制）
在标记完成前，必须回答并自检：
- [ ] 「子 skill / 审计面覆盖矩阵」是否已对对照表**每一行**给出已执行/不适用/已延期，且不适用与已延期均附触发依据或否定证据？
- [ ] 我是否按 `shared/PHP_SINK_REFERENCE.md` 与 trace 结果覆盖了常见高危类别（SQL/NOSQL/CMD/SSRF/XSS/FILE/UPLOAD/WRITE/ARCHIVE/XXE/DESER/TPL/AUTH/CSRF/REDIR/CRLF/SESS/CRYPTO/CFG/LOG/FS）？
- [ ] 我是否覆盖 LDAP/EXPR（或矩阵中「不适用」已附否定证据）？
- [ ] 每条漏洞是否都有数据流链与可利用前置条件？
- [ ] 是否没有任何省略写法？
- [ ] 是否没有任何未替换的模板占位符？
- [ ] **「Trace 未闭合 / 待补证风险池」**是否已列出所有 `PARTIAL/UNRESOLVED` 及 2.5 未闭合静态命中，且与漏洞列表无矛盾？

## 子 Skill 对照表（能力清单 + 矩阵对齐）
下表为**必须出现在「子 skill / 审计面覆盖矩阵」中的行清单**。阶段 3/4 按 trace-gate 与静态证据触发对应 skill；**未执行**的行须在矩阵中标记「不适用」或「已延期」并满足矩阵列要求（禁止空行、禁止无理由跳过）。

1. 路由/参数：`php-route-mapper`
2. 鉴权：`php-auth-audit`
3. 深度追踪：`php-route-tracer`（用于任何需要可控性/分支证据的场景）
4. 组件漏洞（供应链）：`php-vuln-scanner`

5. 利用链聚合：`php-exploit-chain-audit`（在阶段 5.1 强制调用）

6. 文件系统操作审计：`php-filesystem-audit`（在阶段 4 以静态证据驱动执行）

按漏洞类别调用：
- SQL 注入：`php-sql-audit`
- NoSQL 注入：`php-nosql-audit`
- 命令注入：`php-cmd-audit`
- SSRF：`php-ssrf-audit`
- XSS：`php-xss-audit`
- 模板注入/SSTI：`php-tpl-audit`
- LDAP 注入：`php-ldap-audit`
- 表达式注入（非模板）：`php-expr-audit`
- 任意文件读取/路径穿越：`php-file-read-audit`
- 文件上传：`php-file-upload-audit`
- 任意文件写入：`php-file-write-audit`
- 归档解压路径穿越/Zip Slip：`php-archive-extract-audit`
- XXE：`php-xxe-audit`
- 反序列化/对象注入：`php-deser-audit`
- 认证/鉴权绕过/越权/IDOR：`php-auth-audit`（与鉴权状态、资源归属一起落入汇总）
- CSRF：`php-csrf-audit`
- 开放重定向：`php-open-redirect-audit`
- CRLF/响应分割：`php-crlf-audit`
- 会话与 Cookie 安全：`php-session-cookie-audit`
- 加密与密钥安全：`php-crypto-audit`
- 安全配置（CORS/错误暴露/安全头/危险开关）：`php-config-audit`
- 业务逻辑漏洞（Mass Assignment/竞态/状态机/流程绕过）：`php-logic-audit`
- 安全日志与监控：`php-logging-audit`

