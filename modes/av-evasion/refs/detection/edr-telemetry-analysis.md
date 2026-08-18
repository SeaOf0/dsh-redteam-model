---
name: edr-telemetry-analysis
description: >-
  Analyze EDR telemetry for threat detection and investigation. Covers endpoint sensor deployment, process-level detection, credential dumping identification, lateral movement analysis, and SIEM correlation queries using CrowdStrike, Microsoft Defender, and Sysmon data.
---

# SKILL: EDR Telemetry Analysis

## 1. QUICK START

1. Ensure EDR agents are deployed with correct sensor policies across all endpoints.
2. Identify the detection hypothesis or investigation scope (technique, host, user).
3. Query EDR telemetry for relevant events (process creation, network, file, registry).
4. Correlate multiple event types to build attack timelines.
5. Validate findings and escalate or close based on evidence.

## 2. RULES / METHODOLOGY

### 2.1 EDR Platform Data Sources

| Event Category | Sysmon ID | Security Event | CrowdStrike | MDE |
|----------------|-----------|----------------|-------------|-----|
| Process Create | 1 | 4688 | ProcessRollup2 | DeviceProcessEvents |
| Network Connect | 3 | - | NetworkConnect | DeviceNetworkEvents |
| File Create | 11 | - | FileWrite | DeviceFileEvents |
| Registry Modify | 12,13,14 | 4656/4663 | RegKeyValue | DeviceRegistryEvents |
| Process Access | 10 | - | ProcessAccess | LsassAccess |
| DNS Query | 22 | - | DnsRequest | DeviceEvents |
| Image Load | 7 | - | - | DeviceImageLoadEvents |
| Service Install | - | 7045,4697 | - | DeviceEvents |

### 2.2 Credential Dumping Detection (T1003)

**LSASS Access Detection (Sysmon Event 10):**

```
Suspicious GrantedAccess masks:
  0x1010     = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (Mimikatz default)
  0x1F0FFF   = PROCESS_ALL_ACCESS
  0x1FFFFF   = PROCESS_ALL_ACCESS (alternate)
  0x143A     = Used by some credential tools
  0x0040     = PROCESS_VM_READ64 (rare, suspicious)
```

**Splunk Detection Query:**
```spl
index=sysmon EventCode=10
| where match(TargetImage, "(?i)lsass\.exe$")
| where GrantedAccess IN ("0x1FFFFF", "0x1F3FFF", "0x143A", "0x1F0FFF", "0x0040", "0x1010")
| where NOT match(SourceImage, "(?i)(csrss|lsass|svchost|MsMpEng|WmiPrvSE|taskmgr|procexp)\.exe$")
| table _time Computer SourceImage SourceProcessId GrantedAccess CallTrace
```

**Sigma Rule:**
```yaml
title: LSASS Memory Credential Dumping Attempt
status: stable
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1FFFFF'
            - '0x1F3FFF'
            - '0x143A'
            - '0x0040'
    filter:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\lsass.exe'
            - '\MsMpEng.exe'
            - '\svchost.exe'
    condition: selection and not filter
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

**Credential Dumping Tool Signatures:**

| Tool | Detection Pattern | ATT&CK |
|------|-------------------|--------|
| Mimikatz | `sekurlsa::logonpasswords`, `lsadump::lsa` | T1003.001 |
| ProcDump | `procdump.exe -ma lsass.exe` | T1003.001 |
| Comsvcs DLL | `rundll32.exe comsvcs.dll MiniDump [PID]` | T1003.001 |
| Task Manager | Right-click LSASS -> Create dump file | T1003.001 |
| reg.exe SAM | `reg save HKLM\SAM sam.bak` | T1003.002 |
| NTDS extract | `ntdsutil "ac i ntds" ifm` | T1003.003 |
| DCSync | Event 4662 with DS-Replication GUIDs from non-DC | T1003.006 |

### 2.3 EDR Agent Deployment Best Practices

**CrowdStrike Falcon Sensor Deployment:**
```cmd
# Windows silent install
WindowsSensor_7.18.exe /install /quiet /norestart CID=<YOUR_CID>

# Linux
sudo dpkg -i falcon-sensor_7.18_amd64.deb
sudo /opt/CrowdStrike/falconctl -s --cid=<YOUR_CID>
sudo systemctl start falcon-sensor

# macOS
sudo installer -pkg FalconSensorMacOS.pkg -target /
sudo /Applications/Falcon.app/Contents/Resources/falconctl license <CID>
```

**Protection Policy Configuration:**
- **Workstations**: Aggressive ML, exploit mitigation, ransomware protection enabled
- **Servers**: Moderate ML (avoid performance impact), exploit mitigation enabled
- **Domain Controllers**: Maximum protection, RTR enabled, credential dump alerts critical

**SIEM Integration:**
- Use Falcon Event Stream API or FDR (Falcon Data Replicator) for telemetry export
- Configure Splunk Add-on for CrowdStrike or Elastic Fleet integration
- Stream detection events, audit events, and process telemetry to central SIEM

### 2.4 Process Tree Analysis

Build process ancestry to distinguish legitimate vs malicious execution:

```
Legitimate:
  wininit.exe -> services.exe -> svchost.exe -> MsMpEng.exe (Defender scan)

Suspicious:
  outlook.exe -> cmd.exe -> powershell.exe -> mimikatz.exe
  excel.exe -> cmd.exe /c whoami
  svchost.exe (unusual parent) -> powershell.exe -enc [base64]
```

**Splunk Process Tree Query:**
```spl
index=sysmon EventCode=1
| search ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe"
| where match(Image, "(?i)(cmd|powershell|wscript|cscript|mshta)\.exe")
| table _time Computer ParentImage Image CommandLine User
```

### 2.5 KQL Queries for Microsoft Defender for Endpoint

```kql
// Credential dumping detection
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("LsassAccess", "CredentialDumpingActivity")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, ActionType

// Lateral movement indicators
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType in ("Network", "RemoteInteractive")
| where RemoteIP !in ("10.0.0.0", "172.16.0.0")
| summarize count(), dcount(DeviceName) by AccountName, RemoteIP
| where count_ > 10

// File creation in suspicious locations
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath has_any (@"C:\Temp\", @"C:\Users\Public\", @"\AppData\Local\Temp\")
| where FileName endswith ".exe" or FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

### 2.6 Endpoint Hardening for Detection Quality

Configure Windows audit policies for maximum telemetry:

```powershell
# Enable advanced audit policy (via GPO preferred)
# Process creation with command line logging
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWORD -Force

# Increase Security log to 1 GB
wevtutil sl Security /ms:1073741824

# Increase PowerShell operational log
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:536870912

# Configure Windows Event Forwarding (WEF)
wecutil qc /q
# Forward events: 4624, 4625, 4648, 4672, 4688, 4697, 4720, 7045, 1102
```

## 3. EXAMPLES

### Example 1: Hunt for Comsvcs DLL LSASS Dump

```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)comsvcs\.dll.*MiniDump")
| table _time Computer User Image CommandLine ParentImage
```

### Example 2: Hunt for SAM Registry Hive Export

```spl
index=wineventlog EventCode=4656 OR EventCode=4663
| where match(ObjectName, "(?i)(SAM|SECURITY|SYSTEM)")
| where match(ProcessName, "(?i)reg\.exe")
| table _time Computer SubjectUserName ProcessName ObjectName AccessMask
```

### Example 3: Detect DCSync from Non-Domain Controller

```spl
index=wineventlog EventCode=4662
| where match(ObjectType, ".*bf967a86-0de6-11d0-a285-00aa003049e2.*")
    OR match(Properties, ".*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*")
| where NOT match(SubjectUserName, ".*\\$$")
| table _time Computer SubjectUserName SubjectDomainName ObjectName
```

### Example 4: Credential Access Correlation Timeline

```spl
index=sysmon (EventCode=10 AND TargetImage="*lsass*")
    OR (EventCode=1 AND Image="*mimikatz*")
    OR (EventCode=11 AND TargetFilename="*.dmp")
| eval activity=case(
    EventCode==10, "LSASS_ACCESS",
    EventCode==1 AND match(Image, "(?i)mimikatz"), "MIMIKATZ_EXEC",
    EventCode==11, "DUMP_FILE_CREATED"
)
| stats values(activity) as activities by Computer, User
| where isnotnull(activities)
```

## 4. VALIDATION

### EDR Coverage Validation Checklist

- [ ] EDR agents deployed to 100% of endpoints (workstations + servers + DCs)
- [ ] LSASS access monitoring enabled and generating events
- [ ] Process creation events include command-line data
- [ ] Network connection events captured for all endpoints
- [ ] File creation events in critical directories monitored
- [ ] Registry modification events for persistence paths monitored
- [ ] Credential Guard / RunAsPPL enabled on Windows 10+ endpoints
- [ ] SIEM receiving EDR telemetry with < 5 minute latency

### Detection Testing

```powershell
# Test LSASS access detection (generate benign test event)
# Use CsTestDetect.exe from CrowdStrike or equivalent test tool
.\CsTestDetect.exe
# Verify alert appears in Falcon console within 60 seconds

# Test process creation detection
Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" `
  -EntryType SuccessAudit -EventId 4688 -Message "Test detection rule"

# Validate Sysmon configuration
sysmon -c | findstr "ProcessAccess"
# Confirm LSASS monitoring is enabled
```

### Performance Validation

- EDR agent CPU usage < 2% average on workstations, < 1% on servers
- Memory usage within agent limits (CrowdStrike ~30MB, MDE ~100MB)
- No sensor connectivity issues (RFM state = false)

## 5. REFERENCES

- **CrowdStrike Falcon**: https://falcon.crowdstrike.com/ -- EDR console and documentation
- **Microsoft Defender for Endpoint**: https://learn.microsoft.com/en-us/defender-endpoint/ -- MDE documentation
- **Sysmon**: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon -- System Monitor
- **MITRE ATT&CK T1003**: https://attack.mitre.org/techniques/T1003/ -- Credential Dumping techniques
- **MITRE ATT&CK T1059**: https://attack.mitre.org/techniques/T1059/ -- Command and Scripting Interpreter
- **Windows Event Logging**: Advanced audit policies for quality endpoint detection telemetry
- **Velociraptor**: https://docs.velociraptor.app/ -- Endpoint forensics and artifact collection

---

## 6. 国产 EDR + SentinelOne 遥测面（P0 补强，审计 #20）

> 补齐 SentinelOne / 360 天擎 / 火绒 / 腾讯 EDR 的遥测事件字段与查询示例。
> 字段名按各产品文档惯例给出（标注「产品相关」表示需按版本核对），不做产品绑定承诺。

### 6.1 SentinelOne（Deep Visibility）

| 遥测类别 | 字段 | 查询示例（PowerQuery/SQL 风格） |
|---|---|---|
| 进程 | `process.name`, `process.cmdLine`, `src.process.parent.name` | `process.name == "powershell.exe" AND process.cmdLine contains "-enc"` |
| 文件 | `file.fullName`, `file.sha256`, `file.eventType` | `file.eventType == "write" AND file.fullName contains "Temp"` |
| 网络 | `net.dns.request`, `net.connections.dstIp`, `net.connections.dstPort` | `net.dns.request endsWith ".top"` |
| 注册表 | `registry.keyPath`, `registry.value` | `registry.keyPath contains "Run"` |
| 指标(Indicator) | `indicator.name`, `indicator.category`, `indicator.metadata` | `indicator.category == "Behavioral"` |

**Deep Visibility 特点**：Kafka 流式导出（Deep Visibility 2.0），支持 `src.process`/`tgt.process` 关系建模，
进程树/父子关系可作为关联键。

### 6.2 360 天擎（EDR）

| 遥测类别 | 字段 | 查询示例 |
|---|---|---|
| 进程 | 进程名、命令行、父进程、MD5/SHA256、签名 | 命令行含 `mimikatz` 或 `sekurlsa` |
| 文件 | 文件路径、哈希、操作类型 | 写 `C:\Users\Public\*.exe` |
| 网络 | 源/目的 IP/端口、URL、DNS | 外连非白名单域名 + 固定节拍 |
| 行为 | 内存操作、进程注入、驱动加载 | 进程注入行为（跨进程写/线程创建） |

**360 对抗要点**（与 packer 的 QVM 专项同源，见 `../packer/references/qvm-bypass.md`）：QVM 七维对抗
（PE 结构/导入表/节区熵/行为序列/数字签名/编译特征/云查杀）需逐维消减。

### 6.3 火绒（Huorong）

| 遥测类别 | 字段 | 查询示例 |
|---|---|---|
| 进程 | 进程名、命令行、父进程链、哈希 | 父进程异常（explorer→cmd→powershell） |
| 文件 | 路径、哈希、病毒名 | 落地可疑 PE + 杀软命名 |
| 网络 | 连接、端口、协议 | 异常外连 + 心跳 |
| 行为 | HIPS 拦截日志（文件/注册表/进程） | HIPS 拦注入/驱动加载 |

**火绒对抗要点**（P1 #23，七维外推）：火绒 HIPS 对「进程注入/驱动加载/注册表敏感项」强拦截，对抗点
在「最小化显式危险行为」+「合法二进制承载」（LOLBin/签名 DLL 侧加载）。

### 6.4 腾讯（Tencent PC Manager / 御点）

| 遥测类别 | 字段 | 查询示例 |
|---|---|---|
| 进程 | 进程名、命令行、哈希、签名 | 可疑进程 + 无签名 |
| 文件 | 路径、哈希 | 落地 PE + 云查杀 |
| 网络 | IP/域名/端口 | 异常外连 |
| 行为 | 驱动对抗、注入、内存操作 | 驱动级对抗行为 |

**腾讯对抗要点**（P1 #23）：腾讯御点侧重「云查杀 + 驱动级防护」，对抗点在「离线/本地优先」+「驱动对抗
（BYOVD 杀驱动或降级）」，检测侧对「驱动加载事件 + 签名」敏感。

### 6.5 国产 EDR 查询示例（通用 SQL 风格，产品相关）

```sql
-- 进程注入检测（通用）
SELECT * FROM process_events
WHERE action IN ('WriteProcessMemory','CreateRemoteThread','SetThreadContext')
  AND target_process IN ('lsass.exe','svchost.exe');

-- 驱动加载检测（BYOVD）
SELECT * FROM driver_events
WHERE driver_hash IN (SELECT hash FROM loldrivers_blocklist);
```

---

## 7. 行为检测模型 → 对抗点双向映射（P0 补强，审计 #21）

> 体系化「检测模型 ↔ 对抗点」双向映射，作为 persona「技术↔检测双向镜像」的检测侧底座。

| 行为检测模型 | 检测原理 | 对抗点（免杀技术） | 对抗后检测补偿 |
|---|---|---|---|
| **内存扫描** | 扫描进程内存找明文 payload/高熵区 | 加密 + 睡眠混淆（Ekko/Foliage/DeathSleep）、分段解密 | 睡眠期频繁快照 + 解密瞬间抓明文 |
| **栈回溯（call stack）** | 校验返回地址是否在合法模块 | call stack spoofing（Moonwalk++/间接 syscall 返回地址伪造） | call gadget 校验 + 返回地址合法域细查 |
| **进程树分析** | 校验父子进程关系 | PPID 欺骗、进程克隆（NtCreateUserProcess） | 4688 真实父进程溯源 + 进程树评分 |
| **内存属性监控** | RWX/RX 转换轨迹 | RW→RX 分离、Module Stomping、无 RWX | 磁盘/内存节区哈希比对 |
| **线程创建监控** | CreateRemoteThread/NtCreateThreadEx | Threadless、线程复用、回调执行 | SetThreadContext RIP/RSP 突变遥测 |
| **syscall 来源** | syscall 指令地址合法性 | 间接 syscall（jmp ntdll） | ETWTI 内核遥测 + 返回地址域校验 |
| **ETW 遥测** | provider 事件流 | ETW patch/provider 禁用 | provider 心跳 + 完整性校验 |
| **AMSI 内容扫描** | 脚本/程序集扫描 | AMSI patch/patchless/COM 劫持 | AmsiContext 完整性 + scan skipped |

### 7.1 反向映射（对抗点 → 检测模型）

| 免杀技术 | 被哪个检测模型命中 |
|---|---|
| 内存加密/睡眠混淆 | 内存扫描 |
| call stack spoofing | 栈回溯 |
| PPID 欺骗/进程克隆 | 进程树分析 |
| Module Stomping | 内存属性 + 节区哈希 |
| Threadless | 线程创建（反）→ 线程状态突变 |
| 间接 syscall | syscall 来源 |
| ETW patch | ETW 遥测 |
| AMSI patch | AMSI 内容扫描 |

### 7.2 使用说明

- 每次实现一项免杀技术，必须同时回答「它被上表哪个检测模型命中 + 如何补偿检测」。
- 国产 EDR（360/火绒/腾讯）在上述模型之上叠加「云查杀 + 驱动级防护」，对抗时需额外消减
  「数字签名/编译特征/云样本特征」维度。
