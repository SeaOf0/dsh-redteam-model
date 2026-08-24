# binary-analysis 参考手册库（refs/）

> 本目录随 binary-analysis 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——re-playbook 是速查卡，这里的文件是深度手册、专项逆向技能与速查表；
> 需要细节时用 read 直接读取。
> 路径解析：加载 re-playbook 技能时你会得到该技能的 base 目录（SKILL.md 所在目录，
> 即 `skills/re-playbook/`）；refs/ 相对 base 目录 = `../../refs/`。
> 覆盖面：恶意样本分析（静态/动态/内存/持久化/勒索）/ 逆向工具（IDA/Ghidra/r2/x64dbg）/
> 平台逆向（macOS/.NET/Go·Rust/JS/协议/胖客户端/浏览器扩展）/ 移动逆向与脱壳
> （Android/iOS/加固专项）/ 方法论（反调试/壳/混淆还原/补丁对比/1day）/ 固件 /
> 检测规则 / pwn / 漏洞挖掘与利用开发（fuzz/崩溃/缓解/边界/shellcode） / 硬件与无线 / EDR 绕过逆向 / 趋势。共 270 篇 md
> （扩容：reverse-engineering 补 20 篇 + pwn/hardware/edr-bypass-re + android v1/v2；
> 本轮补 binary-analysis 审计 13 缺口 +10 篇：Windows 壳脱壳 OEP/IAT、注册算法还原、macOS 破解、
> RAT 配置提取、native VM devirt、符号执行深度、Volatility 取证、UEFI、Rust、浏览器扩展、
> 驱动回调/签名、符号恢复、JA3·JARM；扩展 +5 篇：frida 脚本库、IDA 插件生态、
> x64dbg 调试方法论/插件、Ghidra MCP 联动、下载器链逐级解码；
> 补足 exploit-dev/ 10 篇：fuzzing 双篇、漏洞利用开发双篇、崩溃分析、Windows 缓解机制、
> Windows 安全边界、漏洞类别与 CVE 实例、基础利用、shellcode）.

## 快速路由（按任务类型找目录）

| 任务类型 | 目录 |
|---|---|
| 恶意样本分析流程 | `static/` `dynamic/` `behavior/`（F 域 8 篇） |
| 反编译器/调试器使用 | `tools/`（5 个技能目录） |
| 特定平台/格式的逆向 | `platform/`（7 个技能目录） |
| Android/iOS 逆向与脱壳 | `mobile/`（apk/mobile/android-reverse + 加固脱壳专项） |
| 方法论：对抗/还原/对比/1day | `methodology/`（8 个技能目录 + 7 篇，含 kernel-0day-hunting 内核找洞方法论） |
| 固件分析 | `firmware/`（2） |
| 二进制漏洞研究（pwn） | `pwn/`（stack/heap/kernel 3 篇 + SKILL） |
| 漏洞挖掘与利用开发（fuzz/崩溃/缓解/边界） | `exploit-dev/`（10 篇：fuzzing·课程、利用开发·路线图、崩溃分析、Windows 缓解、Windows 边界、漏洞类别、基础利用、shellcode） |
| 硬件/无线/工控（固件相邻） | `hardware/`（hardware-security/radio-sdr/ot-ics/wifi-wireless 四技能） |
| EDR 绕过逆向（检测侧视角） | `edr-bypass-re/`（telemetry-blinding/hook-survey/unhook + SKILL） |
| IOC/YARA 输出 | `detection/` + methodology/malware-analysis |
| 2025–2026 工具链风向 | `trends/`（1） |

## 目录索引

### 基础分析（F-恶意软件与逆向 域，10 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| static/malware-analysis-static.md | 恶意样本静态分析全解 | 静态分析阶段 |
| static/reverse-engineering-binary.md | 二进制逆向通用手册（反汇编/结构） | 逆向通用流程 |
| dynamic/malware-analysis-dynamic.md | 恶意样本动态分析全解 | 动态分析阶段 |
| dynamic/malware-analysis-memory.md | 内存分析（dump/取证视角） | 内存取证场景 |
| dynamic/macos-process-injection.md | macOS 进程注入技术（本机分析环境的注入面） | macOS 动态分析/插桩 |
| dynamic/frida-script-library.md | Frida 脚本库集中索引（基础/API 追踪/反调试/SSL unpinning/内存/native+RPC 六类模板） | 需要 frida 脚本模板时 |
| behavior/malware-persistence.md | 恶意持久化行为解析 | 持久化行为分析 |
| behavior/reverse-engineering-ransomware.md | 勒索软件逆向专项 | 勒索样本分析 |
| detection/malware-detection-yara.md | YARA 检测规则编写全解 | IOC/检测规则输出 |
| detection/ja3-jarm-fingerprinting.md | JA3/JA3S/JARM TLS 指纹体系（C2 识别/家族归因） | 网络侧指纹/C2 归类 |

### tools/（反编译器与调试器，5 个技能目录 + 2 篇）

| 目录/文件 | 内容 | 何时读 |
|---|---|---|
| ida-reverse/ | IDA 逆向技能（含 ida-mcp-cheatsheet——IDA 的 MCP 桥接速查，配合 trends） | IDA 可用时 （2026-08-17 补齐 scripts/open.ps1|start.ps1：IDA 启动辅助）
| ida-ai-reversing/ | IDA AI 逆向工作流（397 行） | IDA + AI 协作 |
| ida-plugin-ecosystem.md | IDA 插件生态 2025-2026（IDAPython/MCP 桥接/AI 插件/经典插件/新插件） | IDA 插件/脚本/AI 协作 |
| x64dbg-reversing/ | x64dbg 动态调试手册（652 行，MCP 命令速查）+ references/unpacking-oep-iat.md（OEP 方法体系 + IAT 重建对比 + B1 三验判据）+ references/x64dbg-debugging-and-plugins.md（断点方法论/插件生态/脚本系统） | Windows 样本动态调试/脱壳 |
| ghidra-reverse/ | Ghidra 逆向（含 ghidra-cheatsheet） | Ghidra 可用时 |
| ghidra-mcp-workflow.md | Ghidra headless 脚本（analyzeHeadless）+ MCP 联动（GhidraMCP/ReVa） | Ghidra 批量/无 GUI/AI 协作 |
| radare2/ | radare2 逆向（含 cheatsheet，129 行） | r2 命令行逆向（含 scripts/recon.sh|.ps1：r2 分诊速启）

### platform/（平台与格式专项，7 个技能目录）

| 目录 | 内容 | 何时读 |
|---|---|---|
| macos-reverse/ | macOS/Mach-O 逆向（macho-triage 完整破解路线：结构→签名/entitlement→TCC→launchd→lldb→补丁重签名） | macOS 样本 |
| macos-security-bypass/ | macOS 安全机制绕过分析（Gatekeeper/SIP/AMFI/公证，逆向视角；refs 根目录，供 dynamic/macos-process-injection 引用） | macOS 安全机制/注入受阻时 |
| dotnet-reverse/ | .NET 逆向（common-workflow / obfuscators 混淆器 / sharp-tools） | .NET 样本 |
| go-rust-reverse/ | Go/Rust 二进制逆向（go-rust-notes：Go 锚点 + Rust 识别/符号 demangle/字符串恢复/类型布局） | Go/Rust 样本 |
| js-reverse/ | JS 逆向（12 篇参考：ast-deobfuscation、instrumentation、env-patching、automation-entry 等） | 混淆 JS/小程序 JS/协议还原 |
| protocol-reverse/ | 协议逆向（protocol-workflow）——C2 私有协议/加密通信还原 | 样本通信协议分析 |
| thick-client/ | 胖客户端逆向（thick-client-checklist） | Electron/Qt/原生客户端 |
| browser-extension-reverse/ | 浏览器扩展逆向（extension-analysis 完整路线：manifest→background/content script→凭据流量→去混淆） | 恶意/可疑扩展 |

### mobile/（移动逆向与脱壳，含 v1/v2 历史包计 117 篇）

| 目录/文件 | 内容 | 何时读 |
|---|---|---|
| reverse-engineering-mobile.md | 移动端逆向总手册（Android/iOS） | 移动逆向总览 |
| apk-reverse/ | APK 逆向技能（android-advanced、apk-security-checklist、frida-cookbook、frida-bypass-kit 反检测套件） | Android 逆向主技能（含 scripts/ 7 文件：decode/frida-run/manifest-summary/rebuild-sign-install 完整 unpack→patch→resign→install 闭环脚本，.sh/.ps1 双平台）
| mobile-reverse/ | 跨端移动逆向（ios-reverse-guide、frida-objection-deep、anti-detection-bypass） | iOS 逆向与 frida 深度 |
| android-reverse/ | Android 逆向全技能（SKILL/PROMPTS + references 57 篇：JNI/native/WebView/smal/dex/加密定位 + docs guides/reference 24 篇 + 任务 schema 与输入示例 JSON） | Android 深度逆向主入口（先读其 SKILL.md） |
| android-reverse/engineering-skill-v1/、v2/ | android-reverse-engineering-skill 的 v1/v2 版本：v1 含 kotlin-name-recovery + 配套 recover-kotlin-names 脚本；v2 含 dynamic-analysis / native-analysis + frida 脚本集（dump_dex/keystore_dump/jni_method_trace 等）；与主线 57 篇并存，同名 references 为不同版本、互不覆盖 | 需要 v1/v2 增量视角（Kotlin 名恢复、动态分析、frida 脚本）时 |
| dumpapkpack/ | 加固脱壳专项 6 篇：packer-360jiagu（360 加固）、packer-ijiami（爱加密）、packer-template（新壳分析模板）、tools-reference、SKILL、README | 脱壳还原（persona 硬规则的实操手册） |

### methodology/precedents/（先例库，19 文件，field-journal RE 子集）

真实案例（Go 逆向/DSL-VM 验证码/Android 自解压还原/Electron bytenode/Cortex-M 固件加密/
Windows 逆向工具链引导）+ seed 先例（ELF 加壳/stripped Go/JS webpack 签名/APK pin bypass/
iOS 越狱检测/ROP/pcap 协议/il2cpp/IoT UART）+ anonymization 脱敏规范 + _template 案例模板 +
precedent-reverse 索引。**写自己的实战案例时循 _template 并先过 anonymization**。

### methodology/ops/（证据与决策纪律，3 篇）

evidence-finding-path（证据→结论→路径链）、sandbox-profile（工具↔沙箱映射）、
analysis-decision-framework（分析决策框架）——与预设证据标准同向的案例工程纪律。

### methodology/reverse-engineering/dsl-vm-reverse/（DSL/VM 解释器逆向，374 行）

JS 系自定义 DSL/VM 解释器与风控引擎逆向：识别启发（IIFE+switch 分发/常量表）、
opcode 提取分类、运行时 VM 状态捕获——js-reverse 去混淆之外的 VM 型混淆专项。

### methodology/（方法论与对抗，8 目录 + 7 篇）

| 目录/文件 | 内容 | 何时读 |
|---|---|---|
| reverse-engineering/ | 逆向总纲（26 篇：ai-assisted-re / ollvm-deobfuscation / nonpe-format-cookbook / re-agent-workflow + 扩展 20 篇——anti-analysis、elf-analysis、kernel-driver-reverse、go-reverse、languages*、patterns*、platforms*、tools*、crypto-decode-tools、awesome-re-resources 等；本轮补 native-vm-devirt（VMProtect/Themida devirt）、symbolic-execution-deep（angr/unicorn 深度）、symbol-recovery（符号恢复新法）） | 开工总入口 |
| malware-analysis/ | 恶意分析技能（anti-analysis-techniques 反分析对抗、sandbox-orchestration 沙箱编排+CAPE debugger 实操、yara-sigma-rules、memory-forensics-volatility Volatility3 体系） | 恶意样本全流程 |
| software-cracking/ | 注册算法还原方法体系（SKILL.md：验证点定位→算法还原→keygen→补丁→网络验证绕过） | 逆向破解主线（key/算法/授权还原） |
| malware-analysis-methodology.md | 恶意软件分析方法论（478 行） | 分析规划 |
| kernel-0day-hunting.md | 内核 0day 找洞方法论（CVE 范本提炼） | 内核方向开工 |
| malware-config-extraction.md | 主流恶意家族配置提取（Quasar/AsyncRAT/RedLine + Maco/rat-king-parser/cape-parsers） | RAT/Stealer 配置提取 |
| downloader-chain-decoding.md | 下载器链逐级解码（宏/VBS/JS/PS1 多级下载器：olevba→-enc 解码→反射加载→多级 URL，衔接 Gate B0） | 宏/脚本下载器链分析 |
| binary-diff/ | 二进制差异分析（含 prompt-template） | 版本对比找改动 |
| patch-diff-exploit/ | 补丁对比与 1day 定位（diff-tools-comparison、patch-tuesday-workflow、root-cause-and-poc） | 补丁日 1day 研究（发现交 pentest/attack-defense 验证） |
| anti-debugging.md | 反调试技术全解（440 行）——识别与绕过 | 样本带反调试时 |
| binary-protection.md | 二进制保护机制（295 行：NX/Canary/CFG 等） | 保护机制识别 |
| code-obfuscation-deobfuscation.md | 代码混淆与去混淆（391 行） | 混淆样本还原 |

### firmware/（3 项）

| 目录/文件 | 内容 | 何时读 |
|---|---|---|
| firmware-pentest/ | 固件安全分析（extraction-methodology 提取、emba-automated-analysis 自动化、emulation-and-fuzz 模拟与 fuzz） | 固件样本 |
| firmware-analysis.md | 固件分析方法论（242 行） | 固件分析规划 |
| uefi-reverse.md | UEFI 固件逆向专项（SPI 读取/DXE·PEI/Setup 变量/Secure Boot 绕过/UEFI 驱动） | UEFI/BIOS 固件样本 |

### exploit-dev/（漏洞挖掘与利用开发，10 篇）

课程式编排（系列内互引 Week 结构），每篇含 Overview + 分日实操 + 命令块；与本库 pwn/（Linux CTF 向）互补，侧重方法论体系与 Windows 向。

| 文件 | 内容 | 何时读 |
|---|---|---|
| exploit-dev-course.md | 利用开发课程路线图（12 周课表/每周主题/实验环境搭建/学习路径） | 系统学习规划/新人上手 |
| vuln-classes.md | 漏洞类别与真实 CVE 实例（栈/堆溢出、UAF、整数溢出、格式化字符串、类型混淆、竞态） | 漏洞类别判别/CVE 模式研究 |
| fuzzing.md | fuzzing 实操方法论（目标选择、AFL++/libFuzzer/Boofuzz/Peach 选型、harness 编写、语料治理、变异策略、覆盖度量、崩溃分诊） | fuzz campaign 搭建与执行 |
| fuzzing-course.md | fuzzing 课程篇（语料生成、覆盖引导、结构化 fuzz、崩溃去重） | fuzz 系统学习 |
| crash-analysis.md | 崩溃分析与可利用性评估（WinDbg/GDB、ASAN/MSAN 输出解读、寄存器/栈回溯、根因定位、可利用性判定） | fuzzer 崩溃/崩溃 dump 分析 |
| basic-exploitation.md | 基础利用技术（EIP/RIP 控制、ROP 构造、ret2libc、shellcode 注入、堆喷、ASLR/NX/Canary 绕过） | 首个 PoC 构造/经典利用原语 |
| exploit-development.md | 利用开发操作指南（环境搭建、调试工作流、PoC 生命周期、pwntools/pwndbg、堆利用、武器化考量） | 利用开发实操 |
| windows-mitigations.md | Windows 缓解机制深潜（DEP/ASLR/CFG/CET 影子栈/SEHOP/Heap Guard/ACG：机制原理 + 已知绕过） | Windows 样本缓解识别/绕过研究 |
| shellcode.md | Shellcode 机制参考（x86/x64 编写、null 字节规避、位置无关代码、编码器/解码器模式、staged/stageless；样本载荷识别与利用构造的机制底座） | 分析样本中的 shellcode 载荷 / 构造利用载荷前理解机制 |
| windows-boundaries.md | Windows 安全边界分类与攻击面枚举（内核/用户边界、LPAC/AppContainer 沙箱、COM/RPC 边界、虚拟化边界、信任级迁移；含缓解指纹侦察） | 提权路径规划/沙箱逃逸研究/Windows 架构理解 |

> 生态边界：本目录收**知识与方法论**；利用验证实操交 pentest/attack-defense，载荷规避与免杀交 av-evasion（与库尾「路径与链接约定」一致）。

### trends/（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| re-trends-2025-2026.md | agent-on-top-of-decompiler 架构、IDA/Ghidra 的 MCP 桥接（ida-pro-mcp/ReVa）、DecLLM 可重编译反编译、Talos LLM sidekick 工作流（全部附来源，2026-08 核实） | 开工前校准工具链 |

## 来源与说明

- **基础分析 8 篇（原 static/dynamic/behavior/detection）**：内容整理收录，
  覆盖 F-恶意软件与逆向分域全量，按原文收录。
- **tools/、platform/、mobile/apk-reverse、mobile/mobile-reverse、methodology/ 四个目录
  （reverse-engineering、malware-analysis、binary-diff、patch-diff-exploit）、firmware/firmware-pentest**：
  按原文收录。
- **mobile/android-reverse/**：内容整理收录，
  artifacts 样例产物未随附；references 内含任务 schema 与输入示例 JSON）。
- **mobile/dumpapkpack/**：内容整理收录，按原文收录。
- **tools/ida-ai-reversing、tools/x64dbg-reversing**：内容整理收录。
- **methodology 四篇单文件（malware-analysis-methodology / anti-debugging / binary-protection /
  code-obfuscation-deobfuscation）**：按原文收录。
- **dynamic/macos-process-injection**：内容整理收录。
- **methodology/reverse-engineering 补 20 篇、pwn/、hardware/、edr-bypass-re/**：内容整理收录
  reverse-skill-main 技能库，按原文收录；CTF-Sandbox-Orchestrator（93 篇
  竞赛场景编排）与 pentest-tools/code-audit 等非二进制领域技能未收录（按生态分工归
  对应模式；需要时按 ecosystem-cooperation 跨模式取）。
- **mobile/android-reverse/engineering-skill-v1、v2**：内容整理收录
  android-reverse-engineering-skill 的 v1/v2 插件包，按原文收录；
  与主线 android-reverse（57 篇）为不同版本源，同名文件内容有差异，按版本并存。
- **trends/**：playbook 自建（自建），条目联网核实并附来源链接。
- **缺口补足 10 篇（binary-analysis 审计 13 缺口）**：
  `methodology/software-cracking/SKILL.md`、`methodology/malware-config-extraction.md`、
  `tools/x64dbg-reversing/references/unpacking-oep-iat.md`、`macos-security-bypass/SKILL.md`、
  `methodology/reverse-engineering/references/native-vm-devirt.md`、
  `methodology/reverse-engineering/references/symbolic-execution-deep.md`、
  `methodology/reverse-engineering/references/symbol-recovery.md`、
  `methodology/malware-analysis/references/memory-forensics-volatility.md`、
  `firmware/uefi-reverse.md`、`detection/ja3-jarm-fingerprinting.md`
  —— 均为自写（非整篇搬运），外部技术点引审计报告 §4 URL；另重写/扩充
  `platform/macos-reverse/references/macho-triage.md`、`platform/go-rust-reverse/references/go-rust-notes.md`、
  `platform/browser-extension-reverse/references/extension-analysis.md`、
  `methodology/reverse-engineering/references/kernel-driver-reverse.md`（补回调/签名）与
  `methodology/malware-analysis/references/sandbox-orchestration.md`（补 CAPE debugger）。
- **追加 +5 篇（遗留项：frida/IDA/x64dbg）**：
  `dynamic/frida-script-library.md`（frida 脚本库集中索引）、`tools/ida-plugin-ecosystem.md`（IDA 插件生态）、
  `tools/x64dbg-reversing/references/x64dbg-debugging-and-plugins.md`（x64dbg 调试方法论/插件/脚本）、
  `tools/ghidra-mcp-workflow.md`（Ghidra headless + MCP 联动）、`methodology/downloader-chain-decoding.md`（下载器链逐级解码）
  —— 均为自写，外部技术点引审计报告 §4 与公开项目 URL；另在 `tools/x64dbg-reversing/SKILL.md` 补交叉引用。
- **补足 exploit-dev/ 10 篇（2026-08-19）**：fuzzing 双篇 / 利用开发双篇 / 崩溃分析 /
  Windows 缓解 / Windows 边界 / 漏洞类别 / 基础利用 / shellcode，按原文收录（覆盖本库此前
  libFuzzer·honggfuzz·CWE·崩溃分析·Windows 利用开发·Windows 缓解·shellcode 机制七项零覆盖缺口）。
- 本目录随预设打包分发；第三方来源文件的许可注记见各 README。
- 与 playbook 的关系：速查卡（playbook）→ 深度手册（refs/）→ 证据落盘（任务工作区，见
  ecosystem-cooperation 技能「产物落盘与交接约定」）。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- 收录文件内部的相对链接指向兄弟技能；多数兄弟技能已按原目录结构收录，
  库内相对路径可直接解析；未收录的按技能名在本库检索。
- frontmatter 为源文件自带，保留原样；refs/ 不经技能加载器发现，仅由 read 按需读取。
- 生态边界：pwn（stack/heap/kernel）与 EDR 绕过**逆向分析视角**已随
  reverse-skill 收录（refs/pwn/、refs/edr-bypass-re/）；**利用验证与规则产出**仍按生态
  分工交 pentest/attack-defense 与 av-evasion。
  patch-diff-exploit 的「发现」在本模式完成，利用验证交 pentest/attack-defense。
