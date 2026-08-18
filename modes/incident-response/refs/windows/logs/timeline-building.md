# Windows 时间线构建方法论

> 正文自写原创；工具链与思路参考 Eric Zimmerman / KAPE / plaso 官方文档（见文末来源），不照抄原文。
> 目标：把 EVTX、MFT、注册表、DNS 缓存、内存、网络等多源痕迹统一到一条 Super Timeline，按时间序还原「攻击者何时、以什么身份、做了什么」。

## 1. 为什么多源聚合

单源时间线有盲区，必须多源互证：

| 来源 | 记录什么 | 盲区 |
|---|---|---|
| EVTX 事件日志 | 登录/进程/服务/计划任务/清理 | 需开审计才全；可被清除/停用 |
| MFT（$MFT） | 文件创建/修改/访问/改名 | 不记录「谁」做的；时间戳可伪造 |
| 注册表（NTUSER.DAT/SYSTEM） | UserAssist/最近文件/启动项/MRU | 只记录部分行为；键值时间难精确 |
| DNS 缓存 | 域名解析历史（时间戳） | 缓存条目会过期/刷新 |
| Prefetch/Amcache/ShimCache | 程序执行痕迹 | 有容量/清理策略 |
| 内存镜像 | 进程/网络/命令行「当时」快照 | 只有抓取那一刻的状态 |

聚合原则：**时间戳对齐（统一到 UTC + 记录与目标机的时区偏移）→ 事件归一（统一字段：时间/来源/动作/对象/主体）→ 排序 → 找行为链**。

## 2. 时间戳基准对齐

```powershell
# 目标机当前时间 + 时区 + 与真实时间的偏移
Get-Date
Get-TimeZone
w32tm /query /status        # NTP 状态，看是否被改
```

- 关键：攻击者可能回拨/篡改系统时间（反取证），需交叉核对「日志 TimeCreated」与「MFT 时间戳」与「网络设备时间」是否一致；发现时间轴「倒流」或跳跃即标记时间戳伪造嫌疑。

## 3. 多源采集与解析工作流

### 3.1 KAPE 一键采集（推荐入口）

KAPE（Kroll Artifact Parser and Extractor）用「目标（Targets）+ 模块（Modules）」两条流水线：Targets 采集痕迹、Modules 现场解析产出 CSV/时间线。

```bat
:: Target 采集（KapeFiles 仓库里的 !SANS_Triage / Windows 全量目标）
kape.exe --tsource C: --target "!SANS_Triage" --tdest C:\kape-out --mdest C:\kape-out\parsed --vss
:: 常用参数：--tsource 源盘 --tdest 采集输出 --mdest 解析输出 --vss 同时采集卷影副本
```

- 常用 Targets：`!SANS_Triage`（应急分诊全量）、`EvtxEvidence`、`RegistryHives`、`Amcache`、`Prefetch`、`WebServerLogs`（IIS 日志）。
- 常用 Modules：`EvtxECmd`、`MFTECmd`、`Registry-RECmd`、`AmcacheParser`、`PECmd`。

### 3.2 EvtxECmd 解析 EVTX → CSV

```bat
EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv C:\kape-out\parsed\evtx --csvf evtx-all.csv
```

- 产出每条事件一行 CSV，含 `TimeCreated`/`EventId`/`MapDescription`/字段值；用 Timeline Explorer 打开按时间排序过滤。

### 3.3 MFTECmd 解析 MFT → 文件系统时间线

```bat
MFTECmd.exe -f C:\$MFT --csv C:\kape-out\parsed\mft --csvf mft.csv
```

- 每条记录含 `$STANDARD_INFORMATION`（SI，4 个时间戳）与 `$FILE_NAME`（FN，4 个时间戳）两套时间，是时间戳伪造识别的关键（见第 5 节）。

### 3.4 plaso / log2timeline 构建 Super Timeline

```bash
# plaso 把 EVTX/MFT/注册表/浏览器/跳转列表等统一为 plaso 存储，再导出时间线
log2timeline.py --storage-file timeline.plaso evtx/ mft/ registry/ dns/
psort.py -o l2tcsv -w timeline.csv timeline.plaso
```

- 适合离线深度分析；配合 Timesketch（web 界面）做协同时间线分析。

### 3.5 注册表时间戳

注册表键值没有原生时间戳，靠以下方式补时间线索：

- UserAssist（最后运行时间）、RunMRU/RecentDocs（MRU 顺序）、`HKLM\SYSTEM\CurrentControlSet\Services\<svc>`（服务安装时间）。
- 用 RegRipper / Registry Explorer 解析；RECmd 批量出时间线条目。

### 3.6 DNS 缓存

```powershell
# 导出 DNS 缓存（含解析时间）
Get-DnsClientCache | Select Entry,Data,TimeToLive | Export-Csv dns-cache.csv
ipconfig /displaydns
```

- DNS 缓存时间戳粗（只有 TTL 与缓存时间），用于「某进程在时间窗内解析过某域名」的弱证据，需与 Sysmon 22（DNS 查询）或 netstat 交叉。

## 4. Super Timeline 构建步骤（汇总）

```
1) 采集：KAPE Targets 拉 EVTX/注册表/MFT/Prefetch/Amcache/DNS/IIS 日志
2) 解析：EvtxECmd/MFTECmd/AmcacheParser/PECmd/RECmd → 各自 CSV
3) 归一：统一字段（Timestamp,Source,EventType,Subject,Object,Detail）
4) 排序：按 UTC 排序（Timeline Explorer / plaso psort / Excel）
5) 聚类：按对象（进程名/文件路径/账户/IP）聚出行为片段
6) 锚点：找「首个可疑动作」作为时间线起点，前后推
```

## 5. 文件时间戳伪造识别（STANDARD_INFO vs FILE_NAME）

NTFS 每个文件两套时间戳：

- `$STANDARD_INFORMATION`（SI）：可通过 API 任意修改（攻击者用 `timestomp`/`SetFileTime` 伪造，掩盖「何时创建/修改」）。
- `$FILE_NAME`（FN）：由文件系统维护，攻击者难直接改（需 MFT 离线篡改，少见）。

识别方法：

```bat
MFTECmd.exe -f C:\$MFT --csv out --csvf mft.csv
:: 打开 mft.csv，比对每条记录的 SI 与 FN 时间：
:: 判据 1：SI 创建时间 > SI 修改时间（创建晚于修改，正常不可能）→ 伪造
:: 判据 2：SI 与 FN 相差巨大（> 数天）→ SI 被改
:: 判据 3：SI 时间与所在目录其他文件时间明显孤立/整齐（整批被 timestomp）
```

- 补充：`$MFT` 的 `Last Access`（最近访问）在新系统默认关闭（`fsutil behavior query disablelastaccess`），若出现可疑的访问时间需确认该功能是否开启，避免误判。
- 时间戳伪造是「样本落盘后改时间」的典型反取证手法，识别它能把「伪造时间」还原回真实攻击时间窗。

## 6. 时间线产出物

- `timeline.csv`：归一后的 Super Timeline（主交付物）。
- `anchor-points.md`：锚点清单（每条：时间/来源/事件/证据编号），供攻击链还原引用。
- 与 attack-chain/attack-chain-reconstruction.md 衔接：时间线是攻击链的证据底座，攻击链的每个节点都要能回指时间线上的某条记录。

## 来源

- KAPE（Eric Zimmerman / Kroll）：https://github.com/EricZimmerman/KapeFiles
- Eric Zimmerman Tools（EvtxECmd/MFTECmd/AmcacheParser/PECmd/RECmd/Registry Explorer/Timeline Explorer）：https://ericzimmerman.github.io/
- plaso / log2timeline / Timesketch：https://github.com/log2timeline/plaso
- RegRipper（Harlan Carvey）：https://github.com/keydet89/RegRipper
- SANS DFIR Posters（取证位置速查）：https://www.sans.org/posters/
