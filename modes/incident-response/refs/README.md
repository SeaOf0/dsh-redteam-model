# incident-response 参考手册库（refs/）

> 本目录随 incident-response 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——ir-playbook 是速查卡，这里的文件是深度手册与排查方法库；需要细节时用 read 直接读取。
> 路径解析：加载 ir-playbook 技能时你会得到该技能的 base 目录（SKILL.md 所在目录，
> 即 `skills/ir-playbook/`）；refs/ 相对 base 目录 = `../../refs/`。
> 覆盖面：Windows/Linux 应急响应方法论（七步闭环/六段式）、日志分析（Event ID 检测集/auditd/journald）、
> webshell 与内存马检测、勒索/木马/挖矿排查、持久化点全表与隐藏后门（含 Linux .so 型/rootkit）、
> 弱口令失陷调查、完整攻击链还原（时间线方法论）、工具速查卡、知识库索引。
> Linux 侧含 GPL-3.0 授权的系统化应急响应知识库（linux/cookbook-linux/，随附 LICENSE）。

## 快速路由（按调查任务找目录）

| 任务 | 目录 |
|---|---|
| Windows 七步闭环 + 常规安全检查总纲 | `windows/methodology/` |
| Windows 日志分析（Event ID 检测集 / Sysmon / 时间线构建） | `windows/logs/` |
| Windows webshell / 内存马检测 | `windows/webshell/` |
| Windows 勒索 / 木马 / 挖矿排查 | `windows/malware/` |
| Windows 钓鱼 / badusb / MSSQL / 非持续与隧道事件 | `windows/scenarios/` |
| Windows 持久化点全表 / 弱口令失陷调查 | `windows/persistence/` |
| Windows 攻击链还原 / 工具速查 / 知识库索引 | `windows/attack-chain/` · `windows/tools/` · `windows/knowledge/` |
| Linux 日志分析 / 隐藏进程排查 | `linux/logs/` · `linux/process/` |
| Linux 持久化排查（cron/systemd/PAM/udev/.pth 等） | `linux/persistence/` |
| Linux .so 隐藏后门 / rootkit（LD_PRELOAD/ld.so.preload/LKM/eBPF） | `linux/rootkit/` |
| Linux webshell / 挖矿勒索远控 / 攻击链还原 | `linux/webshell/` · `linux/malware/` · `linux/attack-chain/` |
| Linux 工具速查 / 知识库索引 | `linux/tools/` · `linux/knowledge/` |
| 2026 威胁情报锚点（银狐仿冒链/Weax-Sorry 勒索，入口定性与家族识别对照） | `knowledge/threat-intel-2026.md` |
| 云审计日志失陷指标判读（五类指标：凭据/提权/外带/持久化/清理） | `knowledge/cloud-audit-indicators.md` |
| 盘面取证 artifacts（Win：$MFT/$UsnJrnl/Prefetch…十优先序；Linux：日志体系/清除检测/时间线） | `windows/methodology/disk-artifacts.md` · `linux/knowledge/disk-artifacts.md` |
| Linux 应急响应手册原文（GPL-3.0，NOP Team，17 章） | `linux/cookbook-linux/` |

## 目录索引

### windows/（Windows 侧，自写原创方法论）

| 目录 | 内容 | 何时读 |
|---|---|---|
| windows/methodology/ | 七步闭环总方法论 + 常规安全检查总纲（0x00–0x36 全量排查面） | 开工定流程 / 体检阶段 |
| windows/logs/ | Event ID 检测集（4624/4625/4688/7045…）、Sysmon、时间线构建 | 日志分析阶段 |
| windows/webshell/ | webshell 检测（IIS 日志/时间戳/静态特征/专杀）+ 内存马排查 | web 失陷调查 |
| windows/malware/ | 勒索（家族识别/VSS/MBR/解密工具）、木马/远控/挖矿排查 | 恶意程序排查 |
| windows/scenarios/ | 场景专项：钓鱼（入口还原四点时间链）、badusb（USB 接入史+密集命令链）、MSSQL（ERRORLOG/xp_cmdshell/触发器后门）、非持续性事件（内存取证+布控）与隧道（frp/nps/CS DNS Beacon 指纹） | 入口类/形态类事件 |
| windows/persistence/ | 持久化点全表（Run/计划任务/服务/WMI/COM/IFEO/侧加载…）+ 弱口令失陷调查 | 后门排查 |
| windows/attack-chain/ | 完整攻击链还原方法论（入口→提权→持久化→横向→目标，IP 溯源） | 溯源还原阶段 |
| windows/tools/ | 工具速查卡（Hayabusa/Chainsaw/KAPE/EZ Tools/Velociraptor/Loki/YARA…） | 工具手册查阅 |
| windows/knowledge/ | 知识库索引（awesome-incident-response/ATT&CK/LOLBAS…） | 扩展检索 |

> 说明：Windows 侧文档为**自写原创方法论**——主题域参照公开应急响应资料
> https://book.noptrace.com/ ），因该仓库无开源许可证（保留所有权利），正文不照抄、自写实现级内容。

### linux/（Linux 侧，cookbook 原文 + 自写方法论）

| 目录 | 内容 | 何时读 |
|---|---|---|
| linux/cookbook-linux/ | NOP Team《Linux 应急响应手册》17 章原文（GPL-3.0，随附 LICENSE） | Linux 应急总纲 |
| linux/logs/ | 日志分析（secure/auth.log/journald/auditd/bash history/wtmp-btmp） | 日志分析阶段 |
| linux/process/ | 可疑与隐藏进程排查（/proc vs ps、unhide、pspy、挖矿进程特征） | 进程排查 |
| linux/persistence/ | 持久化排查（cron 全位置/systemd/rc.local/PAM/udev/.pth/TCP Wrappers…） | 后门排查 |
| linux/rootkit/ | .so 隐藏后门与 rootkit（LD_PRELOAD/ld.so.preload/libc 篡改/LKM/eBPF） | 高级后门排查 |
| linux/webshell/ | webshell 检测（access_log 特征/时间戳/上传目录/IP 溯源） | web 失陷调查 |
| linux/malware/ | 挖矿/勒索/远控排查线（/proc/pid/exe、crontab 拉活、外连定位） | 恶意程序排查 |
| linux/attack-chain/ | 攻击链还原（SSH 爆破失陷调查/时间线/plaso/IP 溯源） | 溯源还原阶段 |
| linux/tools/ | 工具速查卡（chkrootkit/rkhunter/Lynis/osquery/Falco/auditd/LiME/Volatility3…） | 工具手册查阅 |
| linux/knowledge/ | 知识库索引（awesome-incident-response/awesome-forensics/SigmaHQ/ATT&CK Linux） | 扩展检索 |

## 使用约定

- 深度手册按需 read，不整库灌入上下文；本 README 是快速路由入口。
- 全部文件只引用预设内相对路径，禁本机绝对路径（可分发原则）。
- linux/cookbook-linux/ 目录为 GPL-3.0 原文，其 LICENSE 随目录分发。
- 计数与文件清单见各平台子目录 README（windows/README.md、linux/README.md）。
