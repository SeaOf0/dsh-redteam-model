---
name: php-filesystem-audit
description: PHP 文件系统操作审计工具。聚焦 mkdir/chmod/chown/unlink/rmdir/link/symlink/readlink/touch/权限与 TOCTOU 等操作的安全风险，为路径校验绕过与写入链利用提供“可利用性增强证据”（不替代 FILE/UPLOAD/WRITE 等 sink 子审计）。
---

# PHP 文件系统操作审计（php-filesystem-audit）

分析 PHP 项目中对文件系统的关键操作，特别关注这些操作如何与：

- 路径校验/归一化失败（目录遍历、basePath 缺失）
- 落点写入/读取/包含链路
- 写后触发（可执行性、可包含性）
- 竞争条件（TOCTOU）

发生联动，从而提升真实利用可能性。

## 覆盖范围（必做）
必须覆盖并输出“证据点 + 风险解释 + 可利用性判断”的点：

### 1) 创建/目录操作
- `mkdir($path, $mode, $recursive)`
- `rmdir($path)`
- `touch($path)`
- `tmpfile()` / `tempnam()`
- 框架封装的目录创建（如 `Storage::put`/`ensureDirectory` 的底层封装，若识别得到）

### 2) 权限/所有权变更（常用于提权链或绕过执行策略）
- `chmod/chown/chgrp`
- `umask`

### 3) 链接与重定向落点（常见 symlink/hardlink 绕过）
- `symlink($target, $link)`
- `link($target, $link)`
- `readlink($path)`

### 4) 删除与清理（结合 TOCTOU 或覆盖链）
- `unlink($path)`
- `unlink/rename` 变体删除
- `rename($src, $dest)`（用于落点变更时需特别关注 TOCTOU）
- `copy/move` 变体（当作为“落点准备步骤”出现）

### 5) 路径竞态与 TOCTOU（必须单独审计）
对“检查-使用分离”的代码模式给出判定：
- 是否存在 `if (realpath/canonicalize + 前缀校验)` 后又在某个分支/异常处理里重复 join/open/write（路径可能变化）
- 是否存在先判断可写/再写入、先检查再执行文件操作
- 是否存在符号链接解析/不一致解析（检查时与实际打开时 resolved path 不一致）

## 关键输出要求（强制）
每条发现必须包含：

1. 位置证据：文件路径与函数/调用点（尽量带行号；找不到行号则标注待定位）
2. 操作类型：创建/权限/链接/删除/重命名/拷贝等
3. 路径控制来源：路径参数来自 GET/POST/SESSION/配置还是硬编码
4. 跟链路的关系（必须至少选一条说明）：
   - 与 `WRITE`/`UPLOAD` 落点可执行性或可包含性关联
   - 与 `FILE`（读取/包含）或 `ARCHIVE`（解压落点）关联
   - 与鉴权/资源归属关联（例如仅管理员目录有写权限但绕过）
   - 与 TOCTOU 竞态关联（检查点 -> 使用点之间路径可能被替换）
5. 可利用性判断：
   - ✅ 已确认：能证明利用链的关键前置条件由此文件系统操作提供（或与 WRITE/UPLOAD/FILE 的证据形成闭环）
   - ⚠️ 待验证：存在风险，但缺少某个关键前置条件或 trace/解析证据不足
   - ❌ 不可利用：有强约束（baseDir allowlist 生效、resolved path 一致性保护、权限固定且无法更改、竞态窗口被消除）
   - 🔍 环境依赖：需依赖特定文件系统/权限/并发时序/服务端目录结构

6. 可触发性约束（强制）：
   - 仅对“能够被具体 HTTP 路由/入口触发”的文件系统操作生成漏洞条目，并且必须能提供真实路由与完整参数用于 PoC。
   - 若无法定位具体路由入口（如纯后台任务/定时任务/命令行工具且入口不可追踪），该 FS 风险只能在报告中标注“未能定位入口，跳过条目生成（待人工补齐触发路径）”，不得仍按漏洞条目模板强行输出不可执行 PoC。

## 报告输出
输出到：
```
{output_path}/vuln_audit/fs_{timestamp}.md
```

## 漏洞编号规范（建议：FS）
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-FS-{序号}`

## 漏洞条目模板（强制）
每条发现必须遵循以下结构（不得省略）：

```markdown
### [{等级前缀}-FS-{序号}] 文件系统操作链风险（权限/链接/删除/TOCTOU/路径控制）

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source → Path Control → FS Operation → Chain Influence）
（逐行写出：用户/上下文输入如何进入路径控制变量、是否经过 realpath/canonicalize 及前缀校验、最终如何落到 mkdir/chown/symlink/unlink/rename/等文件系统操作参数、以及该文件系统操作如何影响后续链路能力：WRITE/UPLOAD/FILE/ARCHIVE/CMD/TPL/EXPR/DESER 等）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常路径/需要特定文件系统权限/需要竞态窗口/需要特定目录结构}
- 链路承接：{它如何为其它 sink 类别提供“可利用性增强”说明（写入落点/可包含性/权限提升/绕过执行策略/触发竞态）}

#### 验证 PoC（强制：可观测验证框架）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```

PoC 输出/观察点（必须写清楚）：
1. 由该 FS 操作造成的文件系统状态变化是否可观测（例如：目标路径下文件创建/权限变化/链接指向变化/删除结果/最终落点存在性）。
2. 若为 TOCTOU：展示“检查点与使用点 resolved path 不一致/窗口可被利用”的可观测现象（例如并发触发导致最终落点改变）。

#### 证据引用（强制：来自源码片段）
必须至少包含三段与定位对应的证据片段（可以直接在文本中复述关键行）：
1. FS 操作调用点（mkdir/chmod/chown/symlink/unlink/rename 等）及参数位置（file:line）
2. 路径校验/归一化逻辑（realpath/canonicalize/baseDir 前缀校验）及其与 FS 操作之间的关系（同一函数内或跨函数）
3. 路径控制来源（GET/POST/SESSION/配置硬编码等）及其传递链

#### 建议修复
- 路径校验与实际使用必须绑定到同一个 resolved target：`realpath`/canonicalize 后用同一个值进行 open/rename/write（避免 TOCTOU）
- 禁止对可被攻击者影响的路径进行“先校验后使用”的拆分；若必须拆分，应在同一系统调用/同一文件描述符上下文内完成
- 对 symlink/hardlink：在目标落点启用防链接策略（平台支持时禁用跟随符号链接，或基于 inode/文件描述符校验一致性）
- 权限变更必须最小化并确保不可由用户影响；避免攻击者能控制 `chmod/chown` 的路径

#### 代码搜索语句（强制）
```text
rg -n "(mkdir\\(|rmdir\\(|touch\\(|tmpfile\\(|tempnam\\(|chmod\\(|chown\\(|chgrp\\(|symlink\\(|readlink\\(|link\\(|unlink\\(|rename\\(|copy\\(|symlink\\()" .
rg -n "(realpath\\(|canonicalize\\(|dirname\\(|basename\\(|baseDir|dest(path)?|target(path)?)" .
```

## 修复建议（强制要点）
- 路径校验与实际使用必须绑定到同一个 resolved target：`realpath`/canonicalize 后用同一个值进行 open/rename/write（避免 TOCTOU）
- 禁止对可被攻击者影响的路径进行“先校验后使用”的拆分；若必须拆分，应在同一系统调用/同一文件描述符上下文内完成
- 对 symlink/hardlink：在目标落点上启用防链接策略（平台支持时禁用跟随符号链接，或基于 inode/文件描述符校验一致性）
- 权限变更必须最小化并确保不可由用户影响；避免攻击者能控制 `chmod/chown` 的路径

