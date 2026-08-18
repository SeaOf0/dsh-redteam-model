# Evasion Detail Pack

## Focus
- AV / EDR bypass directions
- WAF and 403 bypass paths
- CSP / browser-side hardening bypass checks
- sandbox escape and environment-aware evasions
- **工程化能力**：shellcode loader 生成 + evasion 二开 + C2/工具源码级免杀

## Primary leaf skills
- `windows-av-evasion`
- `waf-bypass-techniques`
- `401-403-bypass-techniques`
- `csp-bypass-advanced`
- `sandbox-escape-techniques`
- `linux-security-bypass`
- `macos-security-bypass`
- `java-memory-shell`
- `references/os-level-evasion` — AV/EDR bypass, AMSI/ETW patching, process injection, 403 bypass, fileless attacks

## Primary leaf skills (continued)
- `references/red-team-operations` — full scope engagement, phishing, C2 infrastructure, OPSEC, social engineering

## Primary leaf skills — Engineering (v2 新增，源自 Evasion-SubAgents 整合)
- `references/loader-engineering` — shellcode loader 工程化生成 + evasion 二开（C/C++/Rust，172 项 evasion 技术 + 85 个组件）
- `references/c2-source-evasion` — C2 框架（Havoc/Sliver/Covenant 等）源码级免杀：YARA/Sigma 识别 + 源码修改
- `references/tools-source-evasion` — 渗透工具（fscan/nuclei/mimikatz 等）源码级免杀
- `references/evasion-research-kb` — GitHub 技术研究 + 知识库构建方法论

## Knowledge Base (v2 新增)
- `references/knowledge-base/evasion_techniques.json` — 172 项 evasion 技术详细数据库（含 APIs + code_template + source URL）
- `references/knowledge-base/loader_techniques.json` — 85 个 loader 组件（15 storage + 14 allocator + 9 copier + 47 executor）
- `references/knowledge-base/scenarios.json` — 25 个已验证组合场景
- `references/lib/knowledge_manager.py` — 知识库查询/添加脚本（可选，需 Python 3.8+）

## Enhancement skills
> 以下引用外部独立安装的 skill。如未安装则无影响；所有 Primary leaf 均为项目自包含。
- `windows-av-evasion` — Windows AV signature and behavioral evasion
- `macos-process-injection` — macOS-specific process injection techniques
- `anti-reversing-techniques` — anti-debugging and anti-analysis methods
- `steganography-techniques` — data hiding and covert channel techniques

## Enhancement: Detection Skills (Red Team Context)

These detection-oriented skills provide blue-team visibility that red team operators should understand:

- **detecting-evasion-techniques-in-endpoint-logs**: Detect defense evasion techniques used by adversaries in endpoint logs including log tampering, timestomping, process injection, and security tool disabling
- **detecting-process-injection-techniques**: Detect and analyze process injection techniques used by malware including classic DLL injection, process hollowing, APC injection, thread hijacking, and reflective loading using memory forensics, API monitoring, and behavioral analysis
- **detecting-t1055-process-injection-with-sysmon**: Detect process injection techniques (T1055) by analyzing cross-process memory operations, remote thread creation, and anomalous DLL loading patterns in Sysmon events
- **detecting-rootkit-activity**: Detect rootkit presence on compromised systems by identifying hidden processes, hooked syscalls, modified kernel structures, hidden files, and covert network connections using memory forensics, cross-view detection, and integrity verification
- **detecting-dll-sideloading-attacks**: Detect DLL sideloading attacks where attackers place malicious DLLs alongside legitimate applications to hijack execution flow for defense evasion
- **detecting-t1548-abuse-elevation-control-mechanism**: Detect elevation control mechanism abuse including UAC bypass, sudo exploitation, and setuid/setgid manipulation by monitoring registry modifications, process elevation flags, and anomalous parent-child process relationships

## Usage rule
- Primary leaf 优先，Enhancement 可选叠加
- Stay evidence-first: separate host-side evasion from network-side bypass, and keep the minimum proving step explicit
- **工程化任务（生成 loader / 改 C2 源码）**：用 Engineering leaf 优先，引用 knowledge-base JSON 中的具体技术 ID
- **理论研究任务（理解 evasion 方法）**：用 os-level-evasion / windows-av-evasion 等理论 leaf

