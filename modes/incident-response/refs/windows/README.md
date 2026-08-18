# incident-response 参考手册库 · Windows 侧（refs/windows/）

> 本目录随 incident-response 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——Windows 应急响应的深度方法论与命令级排查手册；需要细节时用 read 直接读取。
> 口径：全部中文；**实现级**（每条排查给完整 cmd/PowerShell/wmic 命令 + 字段级判据 + 阈值/误报规避）；
> 所有正文为自写原创（主题域参照公开应急响应资料，正文不照抄任何在线版；许可证红线见 README 末尾）。
> 覆盖面：七步闭环总方法论 / 常规安全检查总纲（0x00–0x36）/ Event ID 检测集 / 时间线构建 / webshell 与内存马 /
> 勒索与木马远控挖矿 / 持久化点全表与弱口令失陷 / 攻击链还原 / 工具速查 / 知识库索引 / 场景专项（钓鱼/badusb/MSSQL/非持续与隧道）。共 18 篇 md。

## 快速路由（按应急阶段找文件）

| 阶段/任务 | 文件 |
|---|---|
| 接手事件、跑处置流程 | `methodology/incident-flow.md`（七步闭环） |
| 处置收尾/日常体检 | `methodology/security-checklist.md`（0x00–0x36 清单） |
| 日志分析、Event ID 判疑 | `logs/windows-eventid-detection.md` |
| 还原时间线 | `logs/timeline-building.md` |
| 疑似 webshell / 内存马 | `webshell/webshell-detection.md` + `webshell/memory-shell.md` |
| 勒索 / 木马远控挖矿 | `malware/ransomware.md` + `malware/trojan-virus.md` |
| 钓鱼 / badusb / MSSQL / 非持续与隧道事件 | `scenarios/phishing.md` + `scenarios/badusb.md` + `scenarios/mssql.md` + `scenarios/non-persistent-tunnel.md` |
| 持久化点排查 / 弱口令失陷 | `persistence/persistence-points.md` + `persistence/weak-password-compromise.md` |
| 完整攻击链还原 + 报告 | `attack-chain/attack-chain-reconstruction.md` |
| 选工具 | `tools/tool-cards.md` |
| 找外部知识库/交叉引用 | `knowledge/awesome-indexes.md` |

## 目录索引

### 根目录（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| README.md | 本索引 | 每次进入本库 |

### methodology/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| incident-flow.md | 七步闭环总方法论（固定证据→确定 IOC→定位样本→处理进程→删除文件→善后→体检），每步给命令与证据登记要求 | 接手任何 Windows 事件，先读定流程 |
| security-checklist.md | 常规安全检查总纲（0x00–0x36 全量排查面：杀毒白名单/近期活动工件/证书/账户与隐藏账户/登录/启动项/计划任务与隐藏任务/网络/IPC/进程/环境变量与 CLR/补丁/日志/命令历史/PowerShell 三件套/服务与隐藏服务/RDP/DLL 检查与 KnownDLLs/WMI/最近文件/敏感文件夹/ADS/系统完整性 sfc/BITS/浏览器取证/屏保/NetSh/辅助功能后门/AppCertDlls/AppInit/Shimming/IFEO/COM/Password Filter/Network Provider/Winsock NSP/Defender 日志/防火墙放行/PATHEXT/Sandbox 与空格路径） | 处置收尾体检或巡检 |

### logs/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| windows-eventid-detection.md | Event ID 检测集（4624/4625/4648/4672/4688/4689/4697/4698/4702/4720/4728/4732/1102/7045/104/4103/4104 逐条字段判据 + Sysmon 1/3/7/10/11/13/15/22/23 表 + 日志清除反取证 + PowerShell 日志分析） | 日志分析阶段、按 Event ID 捞日志判疑 |
| timeline-building.md | 时间线构建（EVTX/MFT/注册表/DNS 缓存多源聚合、KAPE/EvtxECmd/plaso 工作流、STANDARD_INFO vs FILE_NAME 时间戳伪造识别） | 还原时间线、攻击链还原前 |

### webshell/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| webshell-detection.md | webshell 检测（IIS 日志特征/文件时间戳/静态危险函数/菜刀冰蝎哥斯拉蚁剑指纹/D盾河马专杀） | 疑似 Web 被植入后门 |
| memory-shell.md | 内存马排查（IIS Module 注入/.NET 反序列化/Java Filter-Listener-Servlet 动态注册/PHP 无文件马 + 内存分析要点） | 文件系统查不到 shell 时 |

### malware/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| ransomware.md | 勒索排查（家族识别/加密器定位/VSS 检查/MBR 加密/No More Ransom 与 ID Ransomware 用法） | 文件被加密、出现勒索信 |
| trojan-virus.md | 木马/远控/挖矿排查（进程/网络/持久化定位链 + 挖矿无文件 PowerShell 拉起特征） | 疑似远控/窃密/挖矿 |

### scenarios/（4 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| phishing.md | 钓鱼事件（邮件证据固定→入口还原→落地执行链四点时间线→凭据暴露面） | 邮件/IM 投递入口 |
| badusb.md | BadUSB 投毒（USB 接入历史 setupapi/20001 事件→接入窗密集命令链→HID 特征判据） | 疑似无人交互执行 |
| mssql.md | MSSQL 失陷（ERRORLOG 18456/18454→xp_cmdshell 启用链→sqlservr 父进程子进程→触发器/Agent 库内后门→备份外带评估） | 数据库服务失陷 |
| non-persistent-tunnel.md | 非持续性事件（Prefetch/4104/USN/内存取证/布控）+ 隧道事件（frp/nps/Web 隧道/CS DNS Beacon/ICMP 指纹与流量判型） | 无持久化痕迹扑空、边界隐蔽通道 |

### persistence/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| persistence-points.md | 持久化点全表（Run 键/启动目录/计划任务/服务+ServiceDll/WMI 订阅/COM 劫持/AppInit/BootExecute/IFEO/DLL 侧加载/Winlogon/PowerShell Profile/证书/隐藏账户/隐藏服务——每项位置+检查命令+清理注意） | 处置收尾清后门、防复发 |
| weak-password-compromise.md | 弱口令失陷调查（4625 爆破聚合/RDP 3389/MSSQL 18456/爆破后账户组计划任务服务三查） | 疑似被爆破失陷 |

### attack-chain/（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| attack-chain-reconstruction.md | 完整攻击链还原（入口→提权→持久化→横向→目标达成证据链闭环、时间线锚点、IP 溯源去伪、Super Timeline、报告叙事结构） | 溯源阶段、写报告前 |

### tools/（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| tool-cards.md | 工具速查卡（Hayabusa/Chainsaw/EvtxECmd/KAPE/Velociraptor/DFIR-ORC/Loki/YARA/Autoruns/Process Explorer/System Informer/OpenArk/Sysmon/LogonTracer/RegRipper——每个用途/命令/输出解读/获取） | 选工具、查命令 |

### knowledge/（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| awesome-indexes.md | 知识库索引（awesome-incident-response/Awesome-DFIR/MITRE ATT&CK/LOLBAS/UltimateWindowsSecurity/Atomic Red Team/SANS 海报/SigmaHQ——每项「是什么/何时查/URL」） | 找外部交叉引用来源 |

## 计数

- md 文件总数：**18 篇**
- 根目录：1 篇（README.md）
- methodology/：2 篇
- logs/：2 篇
- webshell/：2 篇
- malware/：2 篇
- scenarios/：4 篇
- persistence/：2 篇
- attack-chain/：1 篇
- tools/：1 篇
- knowledge/：1 篇

## 来源与许可说明

- 本库正文**全部自写原创**，未照抄任何受版权保护的在线版正文/文章。
- **主题域说明**：`methodology/`、`malware/`、`scenarios/`、`persistence/`、`attack-chain/` 的排查面清单参照公开应急响应资料的主题域划分，正文均为自写实现级内容。
- Microsoft / SANS / The DFIR Report 的受版权文章**仅参考其思想**写自写方法论，来源 URL 放在各文件文末「来源」节。
- Sigma 规则库（SigmaHQ，DRL 许可证）**不整库拷贝规则**，只在文档中引用外部来源。
- 第三方来源文件的许可注记见各文件「来源」节。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- 命令示例中的系统路径（如 `C:\Windows\System32\`、`C:\inetpub\`）为通用系统路径，非本机特定路径。
- refs/ 不经技能加载器发现，仅由 read 按需读取；本库面向 Windows 目标机，命令写通用写法（cmd + PowerShell 双写法）。
