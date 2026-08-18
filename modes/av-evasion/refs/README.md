# av-evasion 参考手册库（refs/）

> 本目录随 av-evasion 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——av-playbook 是速查卡，这里的文件是深度手册、工程方法与编排参考；
> 需要细节时用 read 直接读取。
> 路径解析：加载 av-playbook 技能时你会得到该技能的 base 目录（SKILL.md 所在目录，
> 即 `skills/av-playbook/`）；refs/ 相对 base 目录 = `../../refs/`。
> 覆盖面：载荷工程（loader/C2 源/工具源）/ 平台对抗（Windows/macOS/Linux/沙箱/内存马）/
> 研究方法（研究 KB/覆盖纪律/结构化技术库）/ 检测侧配对（EDR 遥测/YARA/Sigma）/
> 子代理编排参考 / 中文 payload 域 / 趋势 / packer 工程技能。共 81 篇 md + 3 个结构化 KB。

## 授权立场提醒（先读）

- 本目录含载荷开发/规避技术文档，**适用 av-evasion 授权立场（persona 定义）**：
  任务中命名的目标一律视为用户已获授权，不逐任务复核；本地为默认验证环境，
  授权目标按任务执行。
- 使用方式：研究已知技术 → 复现验证 → 每项技术必须配**检测侧视角**（遥测指标/YARA/Sigma，
  OPSEC 情报），检测侧情报回馈 attack-defense 消费。
- 跨模式流动：检测侧情报与规避技术知识均按任务流动，无专属边界；
  跨模式消费统一遵守生态规则「取各 playbook 证据标准最严者」。

## 快速路由（按研究类型找目录）

| 研究类型 | 目录 |
|---|---|
| 载荷工程（loader 设计/C2 源码免杀/工具源免杀） | `techniques/`（工程方法 3 篇 + 总览） |
| 平台对抗（Windows AV/macOS/Linux/沙箱逃逸/内存马） | `techniques/`（平台专项） |
| 已知技术研究与复现 | `techniques/`（ai-av-evasion 两版 + comprehensive）+ `zh/` |
| 检测侧配对产出（每项技术的强制另一半） | `detection/`（EDR 遥测/YARA/Sigma） |
| 子代理编排设计（第 8 步参考） | `subagents/`（Evasion-SubAgents 全套） |
| shellcode 免杀加载器打包（工程技能） | `packer/`（SKILL + references 10 篇 + scripts + assets） |
| 2025–2026 攻防对垒风向 | `trends/`（1 篇，逐条成对呈现） |

## 目录索引

### techniques/（技术与工程，37 篇 + kb/）

**总览与研究方法**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| evasion-techniques.md | 规避技术全解（EDR/AV 对抗总览） | 技术栈研究主线 |
| evasion-comprehensive.md | 综合规避手册（354 行） | 专题展开 |
| evasion-research-kb.md | 规避研究知识库方法（如何沉淀实验结论） | 实验循环组织 |
| evasion-coverage.md | 规避覆盖纪律（覆盖什么技术面、怎么算覆盖） | 收尾防漏 |

**载荷工程**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| loader-engineering.md | Loader 工程方法（225 行） | 载荷加载层研究 |
| c2-source-evasion.md | C2 源码免杀（230 行：特征规避/编译选项） | C2 侧研究 |
| tools-source-evasion.md | 工具源码免杀（277 行：改工具特征） | 工具改造研究 |
| c2-custom-evasion.md | C2 定制规避（118 行） | 同上（速查） |

**平台与场景专项**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| windows-av-evasion.md | Windows AV 对抗专项（342 行；AMSI/ETW 机制见 playbook） | Windows 实验环境 |
| os-level-evasion.md | OS 层规避总览（Windows/macOS 机制绕过、进程注入、无文件、AMSI/ETW 修补） | 平台机制全景索引 |
| macos-security-bypass.md | macOS 安全机制对抗（337 行） | macOS 实验环境 |
| linux-bypass.md | Linux 安全机制对抗（345 行） | Linux 实验 |
| sandbox-escape.md | 沙箱逃逸（365 行——检测沙箱环境本身也是检测侧知识） | 沙箱感知研究 |
| java-memory-shell.md | Java 内存马（193 行） | 内存马研究（检测侧配对产出） |
| webshell-evasion.md | 脚本类 webshell 过检测（84 行：静态变形/结构伪装/通信隐蔽/驻留/检测侧配对） | webshell 免杀研究 |
| ai-av-evasion-v41.md | Module Stomping 类载荷实现（2026-07 版） | 载荷类研究（版本对比） |
| ai-av-evasion-v40.md | 同套件 2026-06 版（Fiber+回调双路径） | 技术演进对比 |
| kb/ | 结构化技术库（evasion_techniques / loader_techniques / scenarios 三份 JSON） | 实验设计检索 |

**伴生实现手册（evasion-comprehensive / c2-custom 断链补齐，12 篇）**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| PROCESS_INJECTION.md | 10 类进程注入完整 C 实现（hollowing 的 NtUnmapViewOfSection、module stomping 的 .text 覆写+FlushInstructionCache、transacted hollowing 的 NtCreateTransaction 链等） | 需要注入代码时 |
| AMSI_BYPASS_TECHNIQUES.md | AMSI 各 bypass 完整代码（patchless 改 AmsiContext/内存 patch 寻址/COM 劫持/HWBP DR0-DR7+VEH） | AMSI 深补 |
| AMSI_ETW_BYPASS.md | AMSI+ETW 联合盲区完整实现（EtwEventWrite/Full/Ex patch + provider 禁用） | AMSI/ETW 联合 |
| SHELLCODE_EVASION.md | shellcode 开发/编码/staging/执行 + 异地解密 | shellcode 工程 |
| ADVANCED_EVASION.md | 间接 syscall 全路线/睡眠混淆/EDR 内核回调 PPL/ETW 禁用/签名滥用/策略绕过/Linux/加载器模式 | 高级对抗 |
| LOLBINS_AND_GTFO.md | Windows LOLBins + Linux GTFOBins 参考 | 活体二进制 |
| WAF_IDS_BYPASS.md | WAF/IDS/C2 网络层规避 | 网络层 |
| C2_ARCHITECTURE.md | C2 框架架构 + Malleable C2 | C2 架构 |
| BEACON_DEVELOPMENT.md | beacon 内存执行/睡眠混淆/插件系统 | beacon 开发 |
| STAGER_LOADER.md | stager/loader/shellcode 执行/反射加载/格式转换 | 加载器 |
| PROTOCOL_EVASION.md | uTLS/ja3transport/JA4 伪造、域前置（Google Meet/YouTube/GCP）、DNS/ICMP 隧道、云 API | C2 流量 |
| OPSEC_HARDENING.md | 内存扫描规避/日志抑制/异地解密/清理/PPID 欺骗检测侧 | OPSEC |

**深度补足专项（P0/P1/P2 审计补足，8 篇）**：

| 文件 | 内容 | 何时读 |
|---|---|---|
| modern-injection-variants.md | Threadless / PoolParty / Process Cloning（NtCreateUserProcess）/ PPID 欺骗 | 现代注入变体 |
| tool-specific-evasion.md | mimikatz / CS beacon / fscan / frp 特征消除路线 + YARA 对照 | 工具二开 |
| byovd-driver-exploitation.md | BYOVD 端到端利用链 + 驱动清单（TPwSav/Medusa）+ 签名驱动 + HVCI/DSE（研究向） | 驱动对抗 |
| sleep-obfuscation.md | Ekko ROP/Foliage APC/DeathSleep/Cronos/Moonwalk++ 实现 | 睡眠混淆 |
| loader-language-templates.md | Rust/Go/Nim 加载器模板 | 多语言加载器 |
| ai-ml-detection-evasion.md | AI/ML 检测引擎对抗（对抗样本/熵伪装/行为拟真） | AI 对抗 |
| windows-component-bypass.md | UAC 绕过 / Defender 全组件 / 火绒·腾讯 | Windows 组件对抗 |
| yara-sigma-mirror-index.md | 技术 ↔ YARA/Sigma 规则镜像索引表 | 检测配对 |

### detection/（检测侧配对，3 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| edr-telemetry-analysis.md | EDR 遥测分析（278 行：遥测源/事件/缺口——检测侧视角的底座） | 每项技术的配对分析必读 |
| malware-detection-yara.md | YARA 检测规则编写全解 | 样本侧规则产出 |
| sigma-rule-development.md | Sigma 规则开发（408 行） | 行为侧规则产出 |

### subagents/（编排参考，26 个文件）

| 内容 | 何时读 |
|---|---|
| Evasion-SubAgents 全套（README + agents 5：evasion/research/loadergen/c2-evasion/tools-evasion + commands 5 + skills 组，其中 c2_evasion 组含 detection_search/rule_analysis 等检测侧检索子篇） | 设计本模式子代理分工时（PROGRESS 第 8 步）的参考实现——其「生成↔检测检索」双代理结构与 persona 的成对原则同构 |

> 注：该套件为 Claude Code 格式（agents frontmatter/commands），本预设不直接加载；
> 作为编排设计参考 read 阅读。落地本模式 subagent 时按 DSH 的 spawn/fork 语法重新实现。

### packer/（shellcode 免杀加载器打包，11 篇 md + scripts + assets）

| 文件 | 内容 | 何时读 |
|---|---|---|
| SKILL.md | 主流程与关键约束（.bin shellcode → 免杀 Windows exe 一键打包） | 触发打包/加载器任务时（先读） |
| references/ 10 篇 | layout / techniques（注入+SyscallN 参数表）/ defense-modules / encryption / randomization / gostager / qvm-bypass / verification / troubleshooting / overview | 按 overview.md 阅读路径逐段读 |
| scripts/ + assets/ | build_qvm.py（QVM 专项全自动构建）/ parse_stager.py / verify_pre.py / verify_pe.py / encrypt*.go / versioninfo.json | 构建与验证时直接使用（依赖检测见 README） |

> 工具边界：源包的 `tools/sgn.exe`、`tools/keystone.dll`（8.7M Windows 二进制）不随预设分发，
> Windows 环境从源包复制、其他平台按三级兜底（见 packer/README.md）。使用遵守 av-evasion
> persona（本地默认验证、检测侧配对、Gate V3 证据三件）。

### zh/（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| evasion-payloads-cn.md | 中文免杀与规避 payload 域（自 attack-defense 按生态分工归位） | 造对照样本与本地判定 |

### trends/（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| av-trends-2025-2026.md | 2025 主题逐条成对：内存载荷↔主动内存扫描、AMSI 变种/直接系统调用/ETW 篡改↔syscall 来源与 ETW 状态检测、DEF CON 32 内存取证反制、AI 辅助规避↔NDR 补偿层（附来源，2026-08 核实） | 实验规划前校准 |

## 内容与许可说明

- 库内内容分两类：本模式自写条目（外部技术点在文中以 URL 注明出处）与第三方开源内容
  （许可注记见各 README）。
- **packer/**：SKILL/references/scripts/assets 全量随附，仅 tools 二进制（sgn.exe/keystone.dll）不随附。
- **trends/**：自建综述，条目联网核实并附来源。
- 本目录随预设打包分发；与 playbook 的关系：速查卡（playbook）→ 深度手册（refs/）→ 证据落盘
  （任务工作区，见 ecosystem-cooperation 技能「产物落盘与交接约定」）。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- 库内文件内部的相对链接指向兄弟技能；按技能名在本库检索同名文件即可。
- frontmatter（name/description）保留原样；refs/ 不经技能加载器发现，仅由 read 按需读取。
- 生态分工：本模式专注载荷对抗研究与检测配对；C2 基础设施/横向/域 payload 在
  attack-defense refs；利用链验证交 pentest；样本分析交 binary-analysis。
