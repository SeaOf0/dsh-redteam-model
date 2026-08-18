# 知识库索引（自写简介 + 何时用）

> 本文只做「这是什么 / 何时查 / URL」的索引，不拷贝任何源内容。每个知识库是应急溯源时的交叉引用来源，按需联网查原文。

## 1. awesome-incident-response

- 这是什么：meirwah 维护的应急响应工具/资源精选清单，按分类（证据采集、内存取证、日志分析、威胁情报、网络取证等）汇总社区优质项目。
- 何时查：需要「某类工具/资源」的横向选型时（例如「内存取证有哪些工具」），先来这找候选清单，再到具体项目仓库看用法。
- URL：https://github.com/meirwah/awesome-incident-response

## 2. Awesome-DFIR

- 这是什么：sbousseaden 维护的数字取证与 IR 精选清单，覆盖取证/时间线/内存/浏览器/云取证等，比 awesome-incident-response 更偏取证侧。
- 何时查：取证分析选型（时间线、MFT、注册表、内存镜像分析工具）时。
- URL：https://github.com/sbousseaden/awesome-dfir

## 3. MITRE ATT&CK

- 这是什么：攻击技术/战术的标准分类框架（T 编号），每个技术给检测建议、缓解措施、关联的持久化/提权/横向手法。
- 何时查：攻击链还原时给每个行为映射 T 编号（报告要求 ATT&CK 映射）；持久化点分类（Persistence/Privilege Escalation 矩阵）；找某技术的检测思路。
- URL：https://attack.mitre.org/

## 4. LOLBAS Project

- 这是什么：Living Off The Land Binaries And Scripts——合法系统二进制（`regsvr32`、`mshta`、`rundll32`、`certutil`、`bitsadmin`、`wmic` 等）被滥用为执行/下载/持久化的清单。
- 何时查：看到可疑命令行里出现系统合法程序时，查它是否「正常用法 vs 滥用用法」，判断是否为无文件攻击/持久化。
- URL：https://lolbas-project.github.io/

## 5. UltimateWindowsSecurity Security Log Encyclopedia

- 这是什么：Randy Franklin Smith 维护的 Windows 安全日志 Event ID 词典，逐条给字段/审计策略/缓解说明。
- 何时查：不确定某 Event ID 的字段含义、审计策略、误报成因时（比官方文档更面向实战排查）。
- URL：https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

## 6. Atomic Red Team

- 这是什么：Red Canary 维护的「原子攻击」测试集——每个 ATT&CK 技术都有可执行的最小攻击步骤（YAML），用于模拟攻击验证检测。
- 何时查：验证检测规则/还原链路是否闭环时（跑一遍原子测试看日志/Sysmon 是否留痕）；或做靶场/自测素材。
- URL：https://github.com/redcanaryco/atomic-red-team

## 7. SANS DFIR Posters

- 这是什么：SANS 免费 DFIR 海报（Windows Forensic Analysis、Hunt Evil、Evidence of… 等），把事件 ID 与取证位置做成速查图。
- 何时查：需要「事件 ID / 取证位置」速查时（比翻文档快），尤其日志分析与时间线构建阶段。
- URL：https://www.sans.org/posters/

## 8. SigmaHQ / Sigma

- 这是什么：通用检测规则格式（YAML）+ 海量现成规则（Windows 检测集），可转成 SIEM 查询或直接喂 Chainsaw/Hayabusa。
- 何时查：落地检测规则时——把本库「Event ID 检测集」转成可执行规则，或直接引用现成规则做狩猎。
- URL：https://github.com/SigmaHQ/sigma

## 9. 补充：中文应急响应手册（在线版）

- 这是什么：NOP Team 的中文 Windows 应急响应手册（在线版），事件驱动 + 七步闭环 + 常规安全检查总纲。
- 何时查：需要中文主机体检清单、事件处置流参照时。
- https://book.noptrace.com/

## 知识库速查总表

| 知识库 | 一句话 | 何时查 | URL |
|---|---|---|---|
| awesome-incident-response | IR 工具/资源清单 | 工具选型 | github.com/meirwah/awesome-incident-response |
| Awesome-DFIR | DFIR 工具/资源清单 | 取证选型 | github.com/sbousseaden/awesome-dfir |
| MITRE ATT&CK | 攻击技术标准分类 | ATT&CK 映射/检测思路 | attack.mitre.org |
| LOLBAS | 合法二进制滥用清单 | 可疑命令行判 LOtL | lolbas-project.github.io |
| UltimateWindowsSecurity | Event ID 词典 | Event ID 字段/审计策略 | ultimatewindowssecurity.com/securitylog/encyclopedia |
| Atomic Red Team | 原子攻击测试集 | 验证检测/靶场自测 | github.com/redcanaryco/atomic-red-team |
| SANS DFIR Posters | 事件 ID/取证位置海报 | 速查 | sans.org/posters |
| SigmaHQ/Sigma | 检测规则格式+规则库 | 落地检测规则 | github.com/SigmaHQ/sigma |
| 中文应急响应手册 | 中文应急手册 | 主题域参照 | book.noptrace.com |
