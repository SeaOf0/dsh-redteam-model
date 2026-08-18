# Windows 应急工具速查卡

> 正文自写原创；工具用途与命令按各工具官方文档整理（见各节 URL），不照抄原文。
> 用法：按场景选工具，每节给「用途 / 关键用法 / 输出解读 / 获取」。工具分四类：日志分析、取证采集、样本 IOC 检测、系统排查。

## 1. 日志/事件分析

### 1.1 Hayabusa（隼）

- 用途：Sigma 驱动的 Windows 事件日志威胁狩猎 + 快速时间线生成；Rust 实现，快。
- 关键用法：

```bat
:: 对导出的 EVTX 目录跑 Sigma 检测 + 时间线
hayabusa.exe csv-timeline -d C:\evtx -o hayabusa-out --profile standard
hayabusa.exe json-timeline -d C:\evtx -o out.jsonl
:: 只跑威胁检测（不打时间线）
hayabusa.exe json-timeline -d C:\evtx -o out.jsonl --no-wizard
```

- 输出解读：命中规则会标 `RuleTitle`、`Level`（critical/high/med/low）、`EventID`、`Computer`；按 Level 从高到低复核，`critical/high` 优先。
- 获取：https://github.com/Yamato-Security/hayabusa

### 1.2 Chainsaw

- 用途：用 Sigma 规则快速搜索/狩猎 EVTX 取证痕迹。
- 关键用法：

```bat
:: 用 Sigma 规则扫描 EVTX
chainsaw.exe hunt C:\evtx -s sigma-rules/ -m mapping.yml --csv --output out
:: 用关键字/正则搜
chainsaw.exe search C:\evtx -e "powershell -enc|cmd.exe /c"
:: 按时间窗过滤
chainsaw.exe search C:\evtx -e "svchost" --from "2026-08-01T00:00:00" --to "2026-08-12T00:00:00"
```

- 输出解读：命中显示规则名、事件 ID、时间、字段值；结合时间线判断是否攻击链一环。
- 获取：https://github.com/WithSecureLabs/chainsaw

### 1.3 EvtxECmd

- 用途：Eric Zimmerman 的 EVTX 解析器，把事件映射为字段化 CSV（含 MapDescription 人话描述）。
- 关键用法：

```bat
EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv out --csvf evtx.csv
EvtxECmd.exe -f Security.evtx --csv out --csvf security.csv
```

- 输出解读：每条事件一行，`TimeCreated`/`EventId`/`MapDescription`/各字段列；配合 Timeline Explorer 打开排序过滤。
- 获取：https://ericzimmerman.github.io/

### 1.4 LogonTracer

- 用途：登录日志可视化关系图（横向移动分析，JPCERT/CC）。
- 关键用法：喂 Security 日志 EVTX，生成 Neo4j 关系图（登录主机↔账户↔源 IP 关系），识别横向移动路径。
- 输出解读：图中异常「源 IP → 多主机 → 多账户」边密集处即横向移动嫌疑。
- 获取：https://github.com/JPCERTCC/LogonTracer

## 2. 取证采集

### 2.1 KAPE

- 用途：按目标（Targets）快速提取 Windows 取证痕迹，DFIR 事实标准采集器。
- 关键用法：

```bat
kape.exe --tsource C: --target "!SANS_Triage" --tdest C:\kape-out --mdest C:\kape-out\parsed --vss
kape.exe --tsource C: --target EvtxEvidence,RegistryHives,Amcache,Prefetch --tdest out
```

- 输出解读：`--tdest` 是原始采集、`--mdest` 是解析后的 CSV；`--vss` 同时采卷影副本（覆盖被删文件）。
- 获取：https://github.com/EricZimmerman/KapeFiles

### 2.2 Velociraptor

- 用途：端点取证/可见性/采集平台，VQL 语言，支持实时+离线、跨多主机。
- 关键用法：部署 server+agent，用 VQL 采集（进程/网络/文件/事件日志）并 hunt 多端点；离线模式用 `velociraptor collect` 采单机。
- 输出解读：Artifact 采集结果（进程列表、网络连接、autoruns 等），可导出 JSON/CSV。
- 获取：https://github.com/Velocidex/velociraptor

### 2.3 DFIR-ORC

- 用途：法国 ANSSI 的取证编排工具箱，一键采集（内存/磁盘/日志/注册表）并产出归档。
- 关键用法：`DFIR-ORC.exe /quiet /out=out.zip` 一键采集；配 `orc2timeline` 解析归档生成时间线。
- 输出解读：归档内分类存放证据；orc2timeline 产出的时间线用于后续攻击链还原。
- 获取：https://github.com/DFIR-ORC/dfir-orc · https://github.com/ANSSI-FR/orc2timeline

## 3. 样本/IOC 检测

### 3.1 Loki

- 用途：基于 IOC + YARA 的简单主机扫描器（Neo23x0）。
- 关键用法：

```bat
:: 用默认规则扫全盘
loki.exe --noprocscan --intense --noindicator
:: 指定 IOC 文件扫描
loki.exe --dontwait --noprocscan --csv -l full.csv
```

- 输出解读：`WARNING`/`ALERT` 分级命中，ALERT 优先；命中项含文件路径/规则名/哈希，逐条复核（有误报可能）。
- 获取：https://github.com/Neo23x0/Loki （Rust 多线程版：https://github.com/Neo23x0/Loki-RS ）

### 3.2 YARA

- 用途：恶意样本模式匹配规则引擎（事实标准）。
- 关键用法：

```bat
yara64.exe rules.yar C:\Windows\Temp
yara64.exe -r -s rules.yar <样本>
```

- 输出解读：命中显示规则名 + 匹配字符串；多规则命中且规则为知名家族（如 `AgentTesla`/`CobaltStrike`）可快速定性。
- 获取：https://github.com/VirusTotal/yara

## 4. 系统排查

### 4.1 Autoruns

- 用途：自启动点全量枚举（持久化排查首选）。
- 关键用法：

```bat
autorunsc.exe -a * -c -h -s -v -o autostarts.csv
```

- 输出解读：列 Run 键/服务/计划任务/驱动/Winlogon/WMI/浏览器扩展等全部自启动；`-v` 列 VirusTotal 判定（未签名+VT 命中=重点复核）。
- 获取：https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns

### 4.2 Process Explorer

- 用途：进程树+签名验证+句柄/DLL 查看。
- 关键用法：图形查看进程树（父进程关系）、右键进程 → Properties（签名、DLL、句柄）；"Verify Signatures" 标出无签名进程。
- 输出解读：路径不在 System32 的系统进程名、无签名进程、异常父进程 = 疑点。
- 获取：https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer

### 4.3 System Informer（原 Process Hacker）

- 用途：开源进程/服务/网络管理，能看隐藏进程。
- 关键用法：图形看进程/服务/网络/句柄；"Find Handles" 找文件占用；看加载的驱动。
- 输出解读：隐藏进程（不显示在任务管理器的）、可疑驱动、异常句柄。
- 获取：https://github.com/winsiderss/systeminformer

### 4.4 OpenArk

- 用途：开源 ARK 反内核工具，查隐藏进程/SSDT 钩子/隐藏服务/回调。
- 关键用法：图形扫描内核钩子（SSDT/Inline Hook）、隐藏进程、隐藏驱动、注册表隐藏键。
- 输出解读：内核态异常钩子 = 潜在 rootkit/EDR 对抗。
- 获取：https://github.com/BlackINT3/OpenArk

### 4.5 Sysmon

- 用途：系统监控服务，记录进程/网络/文件/注册表/DNS 等事件（补日志盲区的事实标准）。
- 关键用法：

```bat
:: 安装（推荐配 SwiftOnSecurity 或 olafhartong 的高质量规则）
sysmon64.exe -accepteula -i sysmon-config.xml
:: 查看事件
wevtutil qe "Microsoft-Windows-Sysmon/Operational" /c:100 /f:text
```

- 输出解读：Event ID 1/3/7/10/11/13/15/22/23（见 logs/windows-eventid-detection.md 第 6 节）；规则决定记录粒度。
- 获取：https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon ；规则配置 https://github.com/SwiftOnSecurity/sysmon-config · https://github.com/olafhartong/sysmon-modular

### 4.6 RegRipper

- 用途：注册表痕迹一键解析（Harlan Carvey）。
- 关键用法：

```bat
rip.exe -r NTUSER.DAT -a          # 跑全部插件
rip.exe -r SYSTEM -p samparse     # 跑指定插件（SAM 账户解析）
```

- 输出解读：UserAssist/最近文件/启动项/SAM 账户/时区等痕迹，重点看「执行痕迹」与「账户」插件。
- 获取：https://github.com/keydet89/RegRipper

## 5. 工具速查总表

| 工具 | 类别 | 一句话用途 | URL |
|---|---|---|---|
| Hayabusa | 日志分析 | Sigma 威胁狩猎 + 时间线 | github.com/Yamato-Security/hayabusa |
| Chainsaw | 日志分析 | Sigma 快速搜 EVTX | github.com/WithSecureLabs/chainsaw |
| EvtxECmd | 日志分析 | EVTX 字段化 CSV | ericzimmerman.github.io |
| LogonTracer | 日志分析 | 登录关系图（横向） | github.com/JPCERTCC/LogonTracer |
| KAPE | 取证采集 | 目标化取证采集 | github.com/EricZimmerman/KapeFiles |
| Velociraptor | 取证采集 | 端点取证平台 | github.com/Velocidex/velociraptor |
| DFIR-ORC | 取证采集 | 一键取证归档 | github.com/DFIR-ORC/dfir-orc |
| Loki | IOC 检测 | IOC+YARA 扫描器 | github.com/Neo23x0/Loki |
| YARA | IOC 检测 | 样本模式匹配 | github.com/VirusTotal/yara |
| Autoruns | 系统排查 | 自启动枚举 | learn.microsoft.com/sysinternals |
| Process Explorer | 系统排查 | 进程树+签名 | learn.microsoft.com/sysinternals |
| System Informer | 系统排查 | 隐藏进程/服务 | github.com/winsiderss/systeminformer |
| OpenArk | 系统排查 | ARK 反内核 | github.com/BlackINT3/OpenArk |
| Sysmon | 系统排查 | 系统监控事件源 | learn.microsoft.com/sysinternals |
| RegRipper | 系统排查 | 注册表解析 | github.com/keydet89/RegRipper |
