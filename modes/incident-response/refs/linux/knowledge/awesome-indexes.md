# 知识库索引：Linux 应急外部资源导航

> 定位：本目录 refs 之外的外部知识库导航。本库内的自写方法论与 cookbook 原文是第一手，这里列的是「需要更多工具/规则/映射时去查的社区权威索引」。
> 本文为自写原创索引；各来源许可见对应项目（SigmaHQ 受 DRL 约束，仅引用不整库拷贝）。

---

## 1. awesome-incident-response

- **简介**：IR 领域最全的 curated 工具/资源索引（meirwah 维护），按「工具、取证、狩猎、演练、书籍、社区」分类，是应急工具清单的骨架来源。
- **何时用**：需要某个细分场景（如 Linux 取证、内存分析、时间线、威胁狩猎）的「有哪些成熟工具可选」时，来这找候选，再回本库 `tools/tool-cards.md` 看用法。
- **URL**：https://github.com/meirwah/awesome-incident-response

## 2. awesome-forensics

- **简介**：DFIR 领域 curated 资源索引（cugu 维护，即社区「Awesome-DFIR」事实标准），覆盖磁盘/内存/网络/移动/云取证、时间线、工件分析。
- **何时用**：取证深度问题（如某类文件系统、某类内存镜像、某类日志工件的专用解析工具）在本库没覆盖时，来这找专业工具与教程。
- **URL**：https://github.com/cugu/awesome-forensics

## 3. SigmaHQ / sigma

- **简介**：社区标准的检测规则库，用「平台无关的 Sigma 规则」描述攻击行为，可转译成 SIEM/EDR 查询；含 Linux 的 `process_creation`、`file_event`、`network_connection` 等目录。
- **何时用**：需要把某个攻击行为（如挖矿进程、LD_PRELOAD 注入、crontab 持久化）变成「可落进 SIEM 的检测规则」时，来这找现成规则或参照写法转译。
- **许可注意**：SigmaHQ 规则受 **DRL（Detection Rule License）** 约束——**不要整库拷贝进本库**，只引用外部来源；需要时点对点引用单条规则并保留其许可注记。
- **URL**：https://github.com/SigmaHQ/sigma

## 4. MITRE ATT&CK Linux Matrix

- **简介**：MITRE ATT&CK 的 Linux 企业矩阵，按「战术（Tactic）→ 技术（Technique）→ 子技术」组织攻击行为，是攻击映射与检测覆盖度分析的业界标准。
- **何时用**：需要把本库排查项「映射到 TTP」、评估检测覆盖、或写报告时标注攻击技术编号（如 T1053.003 cron、T1574.006 LD_PRELOAD）时用。
- **URL**：https://attack.mitre.org/matrices/enterprise/linux/

---

## 快速对照：本库主题 → 对应外部资源

| 本库主题 | 可查的外部资源 |
| :--- | :--- |
| 工具选型 | awesome-incident-response、awesome-forensics |
| 检测规则（挖矿/LD_PRELOAD/cron 持久化） | SigmaHQ（DRL 约束，仅引用） |
| 攻击技术映射/报告编号 | MITRE ATT&CK Linux Matrix |
| cookbook 原文方法论 | 本库 `cookbook-linux/`（GPL-3.0） |
| 自写实现级命令 | 本库 logs/process/persistence/rootkit/webshell/malware/attack-chain 各目录 |

> 原则：本库优先自包含（自写方法论 + cookbook 原文），外部索引只做「深度扩展导航」，不整库搬运第三方受许可约束的内容。
