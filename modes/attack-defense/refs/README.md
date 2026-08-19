# attack-defense 参考手册库（refs/）

> 本目录随 attack-defense 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——ad-playbook 是速查卡，这里的文件是深度手册与 payload 库；需要细节时用 read 直接读取。
> 路径解析：加载 ad-playbook 技能时你会得到该技能的 base 目录（SKILL.md 所在目录，
> 即 `skills/ad-playbook/`）；refs/ 相对 base 目录 = `../../refs/`。
> 覆盖面：红队演练方法论与治理 / 域渗透（AD/ADCS/Kerberos/NTLM）/ 横向与隧道 / 凭证与 C2 /
> 检测工程（Sigma/YARA/Suricata/ATT&CK 映射）/ 威胁狩猎与情报（H 域 + STIX/TAXII/MISP）/
> 事件响应取证 / AI 应用红队 / 中文内网 payload 域 / 趋势。共 62 篇 md。

## 快速路由（按评估阶段找目录）

| 阶段/任务 | 目录 |
|---|---|
| 演练规划与治理（条令/对手画像/操作纪律） | `offensive/`（red-team-* 与 adversary-*） |
| 突破与提权 | `offensive/`（initial-access / privilege-escalation / reverse-shell） |
| 域渗透 | `offensive/`（AD 系 6 篇）+ `zh-intranet/`（域渗透 payload） |
| 横向/隧道/凭证 | `offensive/`（lateral 系 / tunneling / credential）+ `zh-intranet/` |
| 防御验证（detection gap） | `defense/`（检测工程 4 篇 + 狩猎 2 篇）+ `defense/ir-*` |
| 情报与 IOC 关联 | `defense/`（TI 域 8 篇） |
| AI 应用红队 | `ai/`（3 篇）+ trends 的 Agentic Top 10 节 |
| 单机落点信息收集（已控主机，横向前置） | `zh-intranet/intranet-host-collect.md`（W/L 模块库+触发表+凭证发散） |
| 内网后渗透（中文 payload 大全） | `zh-intranet/`（12 篇 payload 库） |
| 2026 行业坐标（AEV/agentic 验证）+ 2026 攻击范式与检测对照（边界设备出血/勒索铁三角/Containerd 逃逸，攻击×检测成对） | `trends/`（2 篇） |

## 目录索引

### offensive/（进攻侧，23 篇）

**演练方法论与治理**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| red-team-engagement.md | 红队演练全景方法论 | 演练规划阶段 |
| red-team-operations.md | 红队操作手册（201 行：任务执行纪律） | 执行阶段 |
| red-team-command-doctrine.md | 红队指挥条令（阶段选择/路由/pack 选择/OPSEC 推进——治理技能随预设分发） | 全程（轻量治理） |
| adversary-profile-tracking.md | 对手画像追踪（APT 战术偏好建模，354 行） | 仿真对手设计 |
| phishing-campaign.md / social-engineering.md | 钓鱼活动与社工方法论 | 社工面评估 |
| initial-access.md / privilege-escalation.md | 初始访问与提权 | 对应阶段 |
| evasion-techniques.md / c2-infrastructure.md | 规避与 C2 基础设施（总览视角；载荷开发按生态交 av-evasion） | 突破/持久化阶段 |
| reverse-shell-techniques.md | 反向 shell 技巧（290 行） | 拿到执行点后 |

**域渗透专项**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| active-directory-security.md | AD 安全总览（攻击视角） | AD 环境评估入口 |
| ad-acl-abuse.md | AD ACL 滥用（295 行） | 域内权限路径 |
| adcs-attacks.md | ADCS/证书服务攻击（ESC 系列手法，303 行） | 环境 含 PKI |
| ad-kerberos-attacks.md | Kerberos 攻击（Kerberoasting/黄金白银票据等，311 行） | 域认证面 |
| ntlm-relay-coercion.md | NTLM Relay 与强制认证（267 行） | 域网络面 |
| bloodhound-ad.md | BloodHound 图分析（139 行） | 攻击路径规划 |

**横向与枢纽**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| lateral-movement.md | 横向移动技术总解 | 横向阶段入口 |
| windows-lateral-movement.md / linux-lateral-movement.md | Windows/Linux 横向专项（335/348 行） | 对应平台 |
| tunneling-pivoting.md | 隧道与枢纽（343 行） | 网络打通 |
| credential-harvesting.md | 凭证窃取（174 行） | 凭证面 |
| bastion-jumpserver.md | 堡垒机 / JumpServer 攻击面（组件架构/CVE/凭据库/检测） | 堡垒机为跳板或目标时 |

### defense/（防御侧，22 篇）

**检测工程（detection gap 的产出工具面）**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| sigma-rule-development.md | Sigma 规则开发（408 行） | 检测规则建议产出 |
| yara-detection.md | YARA 检测规则（313 行） | 样本侧规则建议 |
| suricata-snort-rules.md | Suricata/Snort 网络检测规则（303 行） | 网络侧规则建议 |
| attack-mapping-analysis.md | MITRE ATT&CK 映射与覆盖度分析（342 行） | ATT&CK 映射章（persona 报告要求） |
| detection-matrix.md | 攻击技术↔事件ID↔Sysmon↔EDR遥测↔Sigma 映射表 | detection gap 判定的「应留痕迹」可查表 |

**威胁狩猎与威胁情报**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| threat-hunting.md | 威胁狩猎方法论（H 域） | 防御验证的主动面 |
| threat-hunting-procedures.md | 威胁狩猎程序集（312 行） | 具体狩猎假设 |
| threat-modeling.md | 威胁建模（H 域） | 评估范围设计 |
| threat-actor-profiling.md | 威胁行为者画像（H 域） | 对手仿真参照 |
| threat-intel-platform.md / threat-intel-correlation.md | 威胁情报平台与关联分析（correlation 663 行） | 情报侧核对 |
| ioc-management.md | IOC 管理与富化（H 域） | IOC 汇总 |
| stix-taxii-workflows.md / misp-opencti-integration.md | STIX/TAXII 工作流（438 行）与 MISP/OpenCTI 集成（396 行） | 情报工程 |
| dark-web-monitoring.md | 暗网监控（H 域） | 泄露面核对 |

**事件响应与取证（目标侧视角）**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| ir-triage-scoping.md | 事件分级与范围界定 | 防御验证（怎么查告警） |
| ir-forensics-windows.md / ir-forensics-linux.md / ir-forensics-disk.md | Windows/Linux/磁盘取证 | 目标侧取证视角 |
| ir-timeline-analysis.md | 时间线分析 | 检测时序核对 |
| ir-phishing-response.md / ir-ransomware-response.md | 钓鱼/勒索事件响应 | 对应演练对照 |

### ai/（AI 应用红队，3 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| ai-prompt-injection.md | 提示注入攻击面 | AI 红队基础 |
| ai-jailbreak-techniques.md | 越狱技术 | AI 红队评估 |
| ai-agent-safety.md | Agent/MCP 安全（工具滥用/间接注入/多 agent 链——对应 Agentic Top 10 2026 ASI01-04） | Agent 化目标（Garak/PyRIT/Promptfoo 矩阵的方法论底座） |

### zh-intranet/（中文内网 payload 域，13 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| intranet-host-collect.md | 单机落点信息收集命令库（Windows W1~W21 / Linux L1~L14 模块表 + 必做清单自检 + 深挖触发表 + 资产归纳与凭证发散闭环 + 执行通道坑表） | 拿到已控主机的执行通道后、横向派单前 |
| intranet-postexp.md | 内网后渗透 playbook（4845 行：域/横向/权限维持/凭证全景） | 内网阶段总手册 |
| intranet-recon.md | 内网信息收集 payload | 内网侦察 |
| intranet-domain-attacks.md | 域渗透攻击 payload | 域内推进 |
| intranet-adcs.md / intranet-exchange.md / intranet-sharepoint.md | ADCS/Exchange/SharePoint 攻击 payload | 对应服务命中 |
| intranet-lateral.md / intranet-tunneling.md | 横向移动/隧道代理 payload | 对应阶段 |
| intranet-privesc.md / intranet-persistence.md | 权限提升/权限维持 payload | 对应阶段 |
| intranet-credential-theft.md | 凭证窃取 payload | 凭证面 |
| intranet-password-collection.md | 密码收集 payload（密码本/字典生成/配置口令/共享盘） | 凭证面（收割侧） |

### trends/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| ad-trends-2025-2026.md | Gartner AEV Market Guide 2026（AEV 成独立市场、合并 BAS/自动化渗透）、agentic 验证主线（28%/51% 数据点）、Agentic Top 10 2026 与 AI 红队工具锚点（全部附来源，2026-08 核实） | 评估规划与报告「行业坐标」章 |
| 2026-attack-paradigm-detection.md | 2026 攻击范式×检测对照：Citrix Bleed 2（snprintf 残留泄露）与 FortiBleed（43 万台防火墙僵尸化运维/凭证市场交叉销售）、勒索铁三角（BYOVD 白菜化 54 家族 35 驱动/RMM 白名单滥用）、响应大小异常检测、驱动加载×进程终止时序关联、RMM 行为基线三问、Containerd checkpoint 逃逸 | 攻击面选择（边界设备/BYOVD/RMM 链）与 detection gap 设计两头用；检测范式「识别恶意→定义正常」引用 |

## 来源与说明

- **offensive 前 9 篇（red-team-engagement/initial-access/privilege-escalation/lateral-movement/
  active-directory-security/evasion-techniques/c2-infrastructure/phishing-campaign/social-engineering）**：
  ，按原文收录。
- **defense/ir-* 7 篇**：。
- **defense 威胁情报 6 篇（threat-hunting/threat-modeling/threat-actor-profiling/
  threat-intel-platform/ioc-management/dark-web-monitoring）**：内容整理收录
  H-威胁情报 分域（全量）。
- **offensive 域/横向/隧道/凭证/操作 10 篇 + defense 检测工程与 TI 工程 8 篇 + ai/ 3 篇**：
  与 开源安全知识库，按原文收录。
- **offensive/red-team-command-doctrine**：用户自有治理技能（原 runtime skill）随预设分发一份——
  治理技能注册来源确认以此方式落地（refs 只读副本，
  runtime 注册另行处理）。
- **zh-intranet/ 12 篇**：内容整理收录，按原文收录；
  「免杀与规避」一篇按生态边界未收——av-evasion 领域）。
- **zh-intranet/intranet-host-collect.md**：自写（2026-08-19 补单机落点收集缺口），
  覆盖此前的「已控主机全量收集 SOP + 必做清单 + 触发表 + 凭证发散闭环」零覆盖项。
- **trends/**：playbook 自建（自建），条目联网核实并附来源链接。
- 本目录随预设打包分发；第三方来源文件的许可注记见各 README。
- 与 playbook 的关系：速查卡（playbook）→ 深度手册（refs/）→ 证据落盘（任务工作区，见
  ecosystem-cooperation 技能「产物落盘与交接约定」）。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- 收录文件内部的相对链接指向兄弟技能；按技能名在本库检索同名文件即可。
- frontmatter 为源文件自带，保留原样；refs/ 不经技能加载器发现，仅由 read 按需读取。
- 生态边界：免杀/载荷对抗开发（c2-custom-evasion、windows-av-evasion、免杀与规避 payload）
  在 av-evasion 模式；样本逆向交 binary-analysis；单点漏洞验证交 pentest；本模式收口
  全链路编排、防御验证与评分（各模式 refs 各自完整，跨模式按 ecosystem-cooperation 规则协作）。
