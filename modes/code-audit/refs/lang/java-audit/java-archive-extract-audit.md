---
name: java-archive-extract-audit
description: Java 归档解压路径穿越（Zip Slip）审计工具。识别 ZipFile/ZipInputStream 的 ZipEntry.getName() 条目名如何与目标目录拼接、是否存在 base dir 约束缺失，输出可利用性分级、可观测 PoC 与修复建议（禁止省略）。
---

# Java 归档解压路径穿越审计（java-archive-extract-audit）

分析 Java 项目中「解压/提取归档文件到磁盘目录」的实现逻辑。重点审计 Zip Slip 类问题：
攻击者通过精心构造归档条目名（entry name/path）使最终写入落点逃逸目标目录。
本文件与 PHP 侧 `php-archive-extract-audit.md` 同构，对齐五证据点契约。

## 分级与编号
- 严重度评级见 `java-severity-rating.md`
- 漏洞编号：`{C/H/M/L}-ARCHIVE-{序号}`

## ARCHIVE Sink（必做）
识别并追踪归档提取调用点，至少包括：
- `new ZipInputStream(input)` + `zipIn.getNextEntry()` + `Files.copy(zipIn, target)`
- `new ZipFile(path)` + `zf.entries()` / `zf.getInputStream(entry)` + 落盘
- `java.util.jar.JarFile` + `JarEntry.getName()` + 落盘
- 三方库解压封装：Apache Commons Compress（`ZipArchiveInputStream`/`ZipFile`）、
  `org.zeroturnaround.zip`、`Zip4j`（`net.lingala.zip4j`）、`ant.Unzip` 等最终仍对每个
  entry name 做「拼接到 destination 目录并落盘」
- 自定义解压封装：遍历 `ZipEntry` 后用 `FileOutputStream`/`Files.newOutputStream` 写文件

## 必检证据点（强制：trace 契约对齐）
每条 ARCHIVE 疑似漏洞必须逐项引用调用链 trace 输出的 **ARCHIVE 行**对应证据要点
（允许状态为待验证，但证据引用必须存在）：
1. `EVID_ARCHIVE_EXTRACT_CALLSITE`：归档解压/提取调用点证据（ZipFile/ZipInputStream/封装函数入口）
2. `EVID_ARCHIVE_ENTRY_NAME_SOURCE`：entry name/path 来源证据（`ZipEntry.getName()`/`JarEntry.getName()` 返回值，或由用户输入构造的条目路径）
3. `EVID_ARCHIVE_ENTRY_SANITIZATION`：条目路径净化/归一化证据（去除/拒绝 `../`、绝对路径、盘符、反斜杠、软链条目；`normalize()` 是否在解析前执行）
4. `EVID_ARCHIVE_EXTRACT_BASE_DIR`：解压基目录证据（destination/base directory 的来源与传入方式）
5. `EVID_ARCHIVE_FINAL_TARGET`：最终解析落点证据（entry join 后的 resolved final path，以及 base 目录约束判定是否成立）

## 可利用性与漏洞成立条件（必做）
必须输出并判断：
- entry name/path 是否可被攻击者控制（至少来自 attacker's crafted zip 的条目）
- 基目录约束是否真正执行到“最终路径解析之后”（`Path.normalize()` + `startsWith(base)`，
  而非仅字符串 `startsWith` 前缀比较）
- 是否存在绕过：双重编码、混合分隔符（`/` vs `\`）、Windows 盘符（`C:`）、
  绝对路径（`/etc/...`）、软链条目（zip 内符号链接 entry）、尾部/空白/控制字符、
  Unicode 同形字符、解压炸弹（高压缩比 zip 消耗磁盘）
- 写入是否真的发生在目标目录之外（或至少能够证明 final target 逃逸）

## 落点覆盖判定（RCE 达成，必做）
Zip Slip 是否升级为 RCE 取决于落点是否被运行时使用：
- **webroot 覆盖**：落点是否可写进静态资源目录/JSP 目录/模板目录（覆盖或新增可执行文件）
- **依赖/类路径覆盖**：落点是否覆盖 `WEB-INF/lib` 下 jar、`classes` 下 `.class`（类加载劫持）
- **启动脚本覆盖**：落点是否覆盖启动脚本/cron/计划任务/`/etc/` 配置（重启触发）
- 若仅逃逸到无执行面目录（如日志目录、临时目录），则降级为「任意文件写」而非 RCE。

## tracer 触发条件（必做）
当满足任一条件时必须依赖 route-tracer：
- destination/base directory 或 entry name 经过多层函数/对象封装后才进入解压落盘
- entry name 列表或解压路径存在分支逻辑（某些 entry 才被过滤/某些分支未过滤）

## 报告输出
输出到：
```
{output_path}/vuln_audit/archive_{timestamp}.md
```

## 漏洞条目模板（强制）
每条漏洞必须遵循以下结构（不得省略）：
```markdown
### [{等级前缀}-ARCHIVE-{序号}] 归档解压路径穿越（Zip Slip）风险

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source -> Transform -> Sink）
（逐行写出：ZipEntry.getName() 来源 -> 净化/归一化 -> base destination resolve -> resolved final target -> 是否逃逸 base 约束 -> 实际落盘调用点）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常路径/需要特定归档格式/需要落点可执行面}

#### 证据引用（强制：来自 route-tracer）
必须逐项引用：
- `EVID_ARCHIVE_EXTRACT_CALLSITE`：{证据点简述}
- `EVID_ARCHIVE_ENTRY_NAME_SOURCE`：{证据点简述}
- `EVID_ARCHIVE_ENTRY_SANITIZATION`：{证据点简述（缺失则写“未发现过滤/归一化不足”并给出 trace 证据）}
- `EVID_ARCHIVE_EXTRACT_BASE_DIR`：{证据点简述}
- `EVID_ARCHIVE_FINAL_TARGET`：{证据点简述（说明 resolved target 是否逃逸）}

#### 验证 PoC（强制：可观测验证框架）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```
PoC 生成/触发策略（必须写清楚你要观察什么）：
- 制作恶意 zip，包含路径穿越 entry（`../../../../webapps/ROOT/pwn.jsp` 或 Windows 盘符/软链变体）
- 触发解压路由（上传 zip / 提供下载 URL 后服务端解压）
- 观察点：目标目录之外是否出现文件、落点是否在 webroot/依赖/启动脚本面内可被访问或执行

#### 建议修复
- 以“最终解析落点”为准：`Path target = base.resolve(entryName).normalize();` 后执行
  `target.startsWith(base)` 校验（`base` 先 `toAbsolutePath().normalize()`）
- 拒绝绝对路径/盘符/反斜杠分隔/目录上跳/软链条目：entry name 发现穿越片段直接跳过
- 使用安全封装（如 `org.zeroturnaround.zip` 的 zip-slip 防护，或手写规范化校验）
- 解压炸弹防护：限制总解压大小与压缩比
- 给出代码搜索语句：`rg` 定位所有 `ZipFile`/`ZipInputStream`/`getNextEntry`/`ZipEntry.getName` 与落盘拼接逻辑
```

## tracer 证据缺失处理（强制）
- 若 trace 中任一关键证据点（`EVID_ARCHIVE_EXTRACT_CALLSITE / EVID_ARCHIVE_ENTRY_NAME_SOURCE / EVID_ARCHIVE_ENTRY_SANITIZATION / EVID_ARCHIVE_EXTRACT_BASE_DIR / EVID_ARCHIVE_FINAL_TARGET`）缺失或无法对应到本条漏洞：该条漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

## 修复代码模板

```java
// ✅ 安全的 zip 解压（规范化 + base 前缀校验 + 解压炸弹防护）
public void safeExtract(InputStream in, Path baseDir) throws IOException {
    Path base = baseDir.toAbsolutePath().normalize();
    long total = 0;
    try (ZipInputStream zis = new ZipInputStream(in)) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName();
            // 拒绝绝对路径 / 盘符 / 反斜杠 / 软链
            if (name.startsWith("/") || name.matches("^[a-zA-Z]:.*") || name.contains("\\") || name.contains("..")) {
                throw new SecurityException("Illegal entry: " + name);
            }
            Path target = base.resolve(name).normalize();
            if (!target.startsWith(base)) {
                throw new SecurityException("Zip Slip detected: " + name);
            }
            if (entry.isDirectory()) { Files.createDirectories(target); continue; }
            Files.createDirectories(target.getParent());
            // 解压炸弹防护
            if (entry.getSize() > MAX_ENTRY || (total += entry.getSize()) > MAX_TOTAL) {
                throw new SecurityException("Zip bomb detected");
            }
            Files.copy(zis, target);
        }
    }
}
```
