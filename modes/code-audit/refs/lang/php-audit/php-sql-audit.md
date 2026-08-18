---
name: php-sql-audit
description: PHP Web 源码 SQL 注入漏洞审计工具。从源码中识别所有 SQL 执行点并分析注入风险，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP SQL 注入审计（php-sql-audit）

分析 PHP 项目源码，识别 SQL 执行相关代码（PDO/mysqli/ORM），追踪用户输入到 SQL 构造点，验证是否存在 SQL 注入，并输出完整漏洞报告。

## CRITICAL：禁止省略与禁止误报
- 必须审计所有在路由参数中出现的字符串来源（GET/POST/Body/参数字段）进入 SQL 的路径
- 必须使用“数据流追踪证据”判定可利用性；不得只靠关键字猜测
- 禁止省略：不得出现任何省略占位符；必须输出完整的漏洞证据链与修复建议

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-SQL-{序号}`

## 输入依赖
建议至少有（与 `shared/IO_PATH_CONVENTION.md` 一致；合并流水线时读总报告中等价章节即可）：
- `routes_{timestamp}.md`（独立落盘时常为 `route_mapping/routes_{timestamp}.md`）
- `params_{timestamp}.md`（独立落盘时常为 `route_mapping/params_{timestamp}.md`）
可选但推荐：
- `route_tracer/` 输出，用于精准判定参数实际使用状态

## SQL Sink 识别（必做）
1. PDO / PDOStatement
   - 相对危险：`$pdo->query($sql)` / `$pdo->exec($sql)`（若 $sql 来自拼接/包含用户输入）
   - 形式检查：`$pdo->prepare($sql)` 只有在 `$sql` 中使用占位符且后续 `bindParam/bindValue` 或正确传参时更安全
   - ORM/DB 包装：`DB::select(DB::raw({value}))`、Doctrine `createQuery` 等
2. mysqli / mysqli_stmt
   - `mysqli_query($conn, $sql)` 拼接危险
   - `mysqli_prepare` 只有 prepare + bind 正确时才可能安全
3. 典型危险构造模式（必做）
   - SQL 字符串与变量拼接：`.`, `sprintf`, `vsprintf`, `implode/join` + SQL 关键字
   - 动态排序：`order by $x` / `ORDER BY ".$x."`（常见高危）

## 需要触发 tracer 的条件（必做）
满足任一条时必须调用 `php-route-tracer`（或同等追踪证据）：
- 参数经过多层传递或 JSON 解码后取字段进入 SQL
- SQL 构造点位于基类/工具类/父函数中
- 存在分支条件（if/try/catch）导致 SQL 是否执行不确定

## 报告输出
输出到：
```
{output_path}/vuln_audit/
└── sql_{timestamp}.md
```

## 漏洞报告条目模板（强制）
```markdown
### [{等级前缀}-SQL-{序号}] {风险标题}

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source → Sink）
（按路由逐行写出：请求参数读取 -> 变量赋值/拼接/转换 -> 分支 -> SQL 进入执行点。禁止省略）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常/环境依赖}

#### 证据引用（强制：来自 php-route-tracer）
每条 SQL 疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **SQL 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_SQL_EXEC_POINT`：SQL 执行函数/语句位置（对应 trace 的 SQL 执行点证据）
2. `EVID_SQL_STRING_CONSTRUCTION`：SQL 字符串构造/拼接位置（对应 trace 的 SQL 拼接证据）
3. `EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT`：用户可控参数到 SQL 片段的映射（对应 trace 的可控性矩阵字段证据）

#### tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

#### 验证 PoC（强制，可执行请求）
```http
{HTTP Method} {完整路径与查询/Body} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```

#### 建议修复
- 给出安全写法要点（PDO prepare + bind 且保证 SQL 片段不拼接用户输入）
- 给出代码搜索语句（`rg`/`grep` 风格）用于定位所有同类拼接点
```

## 输出完整性检查（强制）
- [ ] 至少输出：风险统计 + 每条漏洞完整条目
- [ ] 不出现任何省略占位符
- [ ] 每条漏洞都包含：数据流链、可利用前置条件、可执行 PoC、修复建议

