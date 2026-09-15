---
name: php-file-write-audit
description: PHP Web 源码任意文件写入审计工具。识别用户可控数据进入写入 Sink 的链路，追踪任意落点写入/路径穿越到 write，并评估写入后的可执行性（禁止省略）。
---

# PHP 任意文件写入审计（php-file-write-audit）

分析 PHP 项目源码中“将数据写入磁盘文件”的实现逻辑，重点覆盖：

- 任意落点写入：写入目标路径可被攻击者控制（含路径穿越到落点）
- 写入内容可控：写入的文件内容来源于用户输入（为后续 RCE/覆写创造条件）
- 覆盖/截断模式：是否以 `w/x` 等覆盖方式写入，或会产生可利用的同名冲突覆盖

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-WRITE-{序号}`

## WRITE Sink（必做）
识别并追踪以下写入/落点变更相关函数/语句（按项目实际出现情况选取）：

- 直接写入：
  - `file_put_contents({path}, {data})`
  - `fwrite($handle, {data})`（通常配合 `fopen($path, 'w'|'ab'|'x'|...)`）
  - `stream_write($stream, {data})` / `fputs($handle, {data})`
- 打开并写入（覆盖/截断）：
  - `fopen($path, 'w'|'x'|'a'|'ab'|'wb'|...)`
  - `ftruncate($handle, {size})`（若路径由用户控制或与路径拼接链路相关）
- 重命名/复制导致的落点变更（可形成“写入落点”）：
  - `rename($src, $dest)`
  - `copy($src, $dest)`
  - `move_uploaded_file($tmp, $dest)`（若不是纯 UPLOAD 场景，且核心风险是落点/路径可控）
- 日志落点写入（可选，但按你项目风险选择启用）：
  - `error_log($message, 3, $destination)`（message_type=3 时 destination 为文件）

## 路径穿越到写入落点检测（必做）
必须分析并给出证据化判断（不能只写“可能”）：

1. 路径拼接与归一化链路
- base 目录（如 `$baseDir` / `$uploadDir` / `$dataDir`）如何与用户输入 join（`$base.$user` / `sprintf` / `join` / 数组路径字段拼接）
- 是否进行目录净化/拒绝穿越片段（`../`、`..\\`、混合分隔符、Windows 盘符、绝对路径、尾部空白等）
- 是否使用 `realpath/canonicalize` 以及“最终 resolved 是否仍在 base 前缀下”的前缀校验

2. 写入落点最终解析结果
- 写入前的目标路径字符串是否会因为 wrapper/符号链接/realpath 解析而改变最终落点
- 最终 `resolved target` 是否逃逸 base 约束（逃逸则倾向落点可控）

## 写入内容可控性与覆盖策略（必做）
必须追踪并输出（链路逐步写出）：

1. 写入内容来源
- `{data}/{content}` 参数是否来自用户可控输入（GET/POST/JSON/COOKIE/上传字段等）
- 是否存在 decode/拼接/模板化/编码步骤后仍可控

2. 覆盖/截断模式
- 写入模式是否为覆盖（`fopen(...,'w'|'x')` 等）或明确允许覆盖同名文件
- 是否存在基于模式的条件分支（某些分支才覆盖、某些分支只追加等）

## 写入后的可执行性/可触达性评估（必做）
由于文件写入常直接导致 RCE，本 skill 必须输出“写完之后能不能被执行/访问”的可证据判断（禁止省略）：

- 若写入的是 PHP/可执行脚本：检查扩展名/解析路径（如最终落点以 `.php` 结尾，或写入的内容被包含/解析）
- 若落点位于 Web 根目录或应用可包含目录：输出静态映射证据（例如 dest 指向 `public/`、`www/` 或框架模板/配置目录）
- 若存在“执行禁用策略”（例如目录不执行 PHP、或服务端配置禁止执行）：输出对应证据与缺失提示

## tracer 证据引用（强制：来自 php-route-tracer）
每条 WRITE 疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **WRITE 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：

1. `EVID_WRITE_WRITE_CALLSITE`：写入/落点变更的调用点位置证据（file_put_contents/fwrite/fopen('w')/rename/copy 等）
2. `EVID_WRITE_DESTPATH_JOIN_AND_NORMALIZATION`：目的路径拼接与归一化证据（base join、净化/拒绝穿越片段、realpath 前缀校验等）
3. `EVID_WRITE_DESTPATH_RESOLVED_TARGET`：最终解析落点（resolved target）证据（是否逃逸 base）
4. `EVID_WRITE_CONTENT_SOURCE_INTO_WRITE`：写入内容参数与用户可控输入的映射证据
5. `EVID_WRITE_TRUNCATE_OR_OVERWRITE_MODE`：覆盖/截断/追加模式证据（写入模式或覆盖策略）
6. `EVID_WRITE_EXECUTION_ACCESSIBILITY_PROOF`：写完后的可执行性/可触达性证据（web 根/可包含目录/执行禁用策略等）

## tracer 证据缺失处理（强制）
- 若 trace 的 `## 9) Sink Evidence Type Checklist`（WRITE 行）中任一关键证据要点缺失或无法对应到本条漏洞：该条漏洞状态只能标记为 `⚠️待验证`（不得直接给出 `✅已确认可利用`）。

## tracer 触发条件（必做）
至少满足其一，且必须依赖 trace 验证 sink 存在：

- 写入目标路径经过多层函数/对象属性/JSON 字段传递后到达写入函数
- 写入内容（data/content）经过 decode/拼接后仍可控
- 存在分支逻辑导致仅部分情况下会覆盖/截断/落到可写可控目录

## 报告输出
输出到：
```
{output_path}/vuln_audit/write_{timestamp}.md
```

## 漏洞条目模板（强制）
每条漏洞必须遵循以下结构（不得省略）：

```markdown
### [{等级前缀}-WRITE-{序号}] 任意文件写入（路径穿越到落点/写入链）风险

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source -> Path Transform -> Content Transform -> Sink）
（逐行写出：用户输入进入 destination/path 的链路、归一化/净化/realpath 约束检查 -> 最终 resolved target -> 用户输入进入写入内容 data 的链路 -> 进入写入函数参数位置 -> 是否覆盖/截断 -> 写入调用点）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常路径/需要特定服务器文件权限/需要落到可执行目录}

#### 证据引用（强制：来自 php-route-tracer）
必须逐项引用：
- `EVID_WRITE_WRITE_CALLSITE`：{证据点简述（包括 file:line）}
- `EVID_WRITE_DESTPATH_JOIN_AND_NORMALIZATION`：{证据点简述}
- `EVID_WRITE_DESTPATH_RESOLVED_TARGET`：{证据点简述}
- `EVID_WRITE_CONTENT_SOURCE_INTO_WRITE`：{证据点简述}
- `EVID_WRITE_TRUNCATE_OR_OVERWRITE_MODE`：{证据点简述}
- `EVID_WRITE_EXECUTION_ACCESSIBILITY_PROOF`：{证据点简述}

#### 验证 PoC（强制：可执行或可观测验证框架）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```

PoC 输出/观察点（必须写清楚）：
- 写入目标文件是否在 Web 可访问位置出现（或是否可通过后续业务逻辑包含/读取到）
- 若写入的是 PHP：观察是否可触发代码执行（或至少观察文件内容回显/下载成功）

#### 建议修复
- 以“最终 resolved target 是否在允许 base 目录内”为准，强制 `realpath + 前缀校验`
- 严格限制可写目录（allowlist），并避免把用户输入直接拼到文件路径
- 对写入内容做类型约束：禁止写入可执行脚本到可执行目录；对内容进行不可执行化（如仅允许序列化数据格式）
- 覆盖策略上避免以 `'w'/'x'` 直接覆盖敏感文件；对同名冲突做安全拒绝
- 给出代码搜索语句（`rg`）：定位所有写入 API 与路径 join 点
```

## PoC/修复建议搜索语句（强制提供参考）
- 写入 API：
  - `rg -n "file_put_contents\\(|fwrite\\(|fopen\\(|stream_write\\(|rename\\(|copy\\(|ftruncate\\(|error_log\\(" .`
- 路径拼接/归一化（常见变量名仅作提示，最终以项目为准）：
  - `rg -n "realpath\\(|canonicalize\\(|\\.\\.\\/|\\.\\.\\\\|allowlist|baseDir|dest(path)?|target(path)?|mkdir\\(" .`

