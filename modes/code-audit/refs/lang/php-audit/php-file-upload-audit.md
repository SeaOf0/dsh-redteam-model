---





name: php-file-upload-audit





description: PHP Web 源码文件上传审计工具。识别上传入口与保存路径、文件名处理与校验逻辑，检测任意文件上传/路径穿越/可执行上传风险，输出可利用性分级、PoC 与修复建议（禁止省略）。





---





# PHP 文件上传审计（php-file-upload-audit）





## 统一执行策略（强制）





必须遵循：`shared/PHP_AUDIT_EXECUTION_POLICY.md`。





执行时统一采用“双通道 + 证据分层”规则：





- 高召回通道：先做静态 `source/sink` 初筛，覆盖 HTTP 路由与非路由入口（CLI/cron/queue/include）





- 高置信通道：再用 `trace/EVID` 做确认与降噪





状态判定统一为：`✅已确认 / 🟡高概率 / ⚠️待验证 / ❌不可利用 / 🔍环境依赖`





- 满足最小证据集（可达片段 + 可控线索 + sink 触发线索）=> 可标记 `🟡高概率`





- 满足完整 trace + EVID => 标记 `✅已确认`





- 证据不足 => 标记 `⚠️待验证`





严谨性要求保持不变，但不得因 trace 不完整而沉默：仍需输出疑似高危与缺失证据。





分析 PHP 项目源码，识别文件上传逻辑：`$_FILES`、`move_uploaded_file` 等，追踪保存目录与文件名处理方式，检测：





- 任意文件上传（任意类型/任意扩展名）





- 路径穿越（使用原始文件名拼接）





- 可执行文件上传（上传到 Web 可访问目录且未限制执行）





- 覆盖/同名冲突风险






## 统一审计标准（强制）
必须遵循：`shared/PHP_AUDIT_UNIFIED_STANDARD.md`。

状态顺序必须固定为：`✅已确认 / 🟡高概率 / ⚠️待验证 / ❌不可利用 / 🔍环境依赖`。
trace 证据判定必须分层执行：
- 满足最小证据集（入口可达 + 参数可控链路 + sink 执行线索 + 基本前置条件）=> `🟡高概率`
- 满足完整证据集（trace COMPLETE + EVID 对齐 + 分支覆盖）=> `✅已确认`
- 不满足最小证据集 => `⚠️待验证`

误报抑制必须检查：硬编码覆盖、白名单生效、不可达分支、沙箱/权限边界。
漏报抑制必须执行：trace 不全不沉默、sink-only 回退。
输出最小字段必须包含：位置、source->sink、前置条件、状态、PoC、修复。
执行优先级必须遵循：先发现、后文档。

## 证据置信度字段与复核清单（强制）
证据置信度字段（强制）：按 `shared/PHP_AUDIT_UNIFIED_STANDARD.md` 输出 HIGH/MEDIUM/LOW，并给出判定依据（与状态一致）。
复核清单（强制，至少 5 项）：
- 是否已执行高召回通道（阶段0）或已启用 sink-only 回退，并覆盖非路由入口
- 是否完成同类扩展检查（命中某类 upload sink 后横向扫同类入口/保存封装）
- 是否按最小证据集/完整证据集规则给出 🟡高概率/✅已确认/⚠️待验证，并说明缺失点
- 是否明确 source->sink 数据流链到文件名解析/扩展名净化/落点拼接/访问可达性
- 是否对误报抑制做了硬编码/白名单/不可达/权限边界/格式不成立说明
- 是否给出可执行 PoC 与可替换修复建议（含随机化策略/MIME 校验/访问面限制/搜索定位要点）

## 分级与编号





- 详见：`shared/SEVERITY_RATING.md`





- 漏洞编号：`{C/H/M/L}-UPLOAD-{序号}`





## 上传入口识别（必做）





识别：





- `$_FILES['{value}']` 字段





- `move_uploaded_file($_FILES['{value}']['tmp_name'], $dest)`





- 保存路径拼接：`$uploadDir.$filename`、`sprintf`、`join` 等





- 重命名：`uniqid`/`random_bytes`/时间戳（若仍可控 filename 仍高危）





## 校验逻辑审计（必做）





必须逐点检查并输出证据：





- 扩展名/白名单：是否只校验后缀（可绕过）





- 扩展名解析安全：是否存在“双后缀/多点后缀”绕过（如 `a.php.jpg`、`.pHp` 大小写绕过、尾部空白/Unicode 分隔符）





- MIME/魔数：是否做 `finfo_file`/`mime_content_type`/文件头识别





- MIME/魔数一致性：是否检查“服务端实际内容类型”与“扩展名/后缀”是否一致（避免仅信任 `Content-Type`）





- 文件名净化：是否去除路径分隔符与危险字符（`../`、`\`、`:`、空字节等）





- 上传目录：是否在 Web 根目录；是否有执行权限控制





- 写入后可访问性链：是否存在上传目录的静态映射/直链访问（需要结合路由或 webserver 配置证据）





- 鉴权：上传接口是否受保护





## tracer 触发条件（必做）





- 保存路径或文件名经过多层封装函数





- 校验逻辑存在分支，难以确认对所有上传路径生效





## 报告输出





输出到：





```





{output_path}/vuln_audit/upload_{timestamp}.md





```





## 漏洞条目模板（强制）





必须包含：





- 位置证据（保存/校验函数位置）





- 数据流链（filename/path 来源 -> 校验 -> 目标路径 -> 写入）





- 证据引用（来自 `php-route-tracer` 输出，必须逐项引用）：必须对应并引用 trace 的 `## 9) Sink Evidence Type Checklist`（UPLOAD 行）中的证据要点





  - `EVID_UPLOAD_DESTPATH`：destPath（保存目录最终落点）





  - `EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE`：file name/extension parsing & sanitization（文件名/扩展名解析与净化逻辑）





  - `EVID_UPLOAD_ACCESSIBILITY_PROOF`：可访问面证据（写入后是否形成可访问面：静态直连证据/映射证据）





  - `EVID_UPLOAD_EXEC_DISABLE_STRATEGY`：执行禁用策略证据（服务端执行禁用策略，如有）





- 可利用前置条件（鉴权/目录可访问性/绕过条件）





- 验证 PoC（包含真实上传路由，给出必要的 multipart 请求结构）





- 修复建议（白名单 + 魔数校验 + 目录隔离 + 随机化文件名 + 覆盖策略 + Webserver 执行禁用要点）





## tracer 证据缺失处理（强制，遵循统一标准）
- 若 trace 的 `## 9) Sink Evidence Type Checklist`（UPLOAD 行）中上述关键证据要点缺失：
  - **满足最小证据集**（可达性 + 参数可控性线索 + Sink 执行线索 + 基本前置条件）：可标记为 `🟡高概率`，在报告中注明缺失的 EVID 点与补全建议。
  - **不满足最小证据集**：只能标记为 `⚠️待验证`（不得直接给出 `✅已确认可利用`）。
  - **满足完整证据集**（全部 EVID 对齐 + 完整 trace + 分支覆盖）：可标记为 `✅已确认可利用`。





