# 弱口令失陷调查

> 正文自写原创，命令与判据自写，来源链接见文末。
> 适用：RDP/SMB/MSSQL 等被弱口令爆破、口令喷洒后失陷的调查。目标：还原爆破过程、确认成功时间、定位爆破后痕迹。

## 1. 爆破检测总纲

爆破留下三类痕迹，逐一排查：

1. **登录日志**：Security 4625（失败）→ 4624（成功）的序列，按源 IP 聚合。
2. **网络/会话痕迹**：netstat 会话、登录源 IP、RDP/MSSQL 连接历史。
3. **爆破后痕迹**：新建账户/加组/计划任务/服务（拿到权限后干什么）。

## 2. 4625 爆破聚合

### 2.1 聚合命令

```powershell
# 按源 IP 聚合 4625（找爆破源）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20000 |
  Group-Object { $_.Properties[18].Value } |
  Sort-Object Count -Descending |
  Select Count, Name, @{n='SampleUser';e={$_.Group[0].Properties[5].Value}}, @{n='FirstSeen';e={$_.Group[0].TimeCreated}}
```

- 阈值建议：单源 IP 对单账户 ≥ 5 次/分钟，或单源 IP ≥ 10 次/分钟，判爆破。失败原因 `0xC000006A`（密码错）与 `0xC0000064`（用户不存在）混杂 = 字典爆破；只针对一个账户 = 定点爆破/口令喷洒。

### 2.2 找爆破成功点（4624 紧跟 4625）

```powershell
# 同源 IP 的 4624（成功）——爆破成功的决定性证据
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20000 |
  Where-Object { $_.Properties[18].Value -eq '<爆破源IP>' } |
  Select TimeCreated, @{n='LogonType';e={$_.Properties[8].Value}}, @{n='User';e={$_.Properties[5].Value}}
```

- 判据：同一源 IP 先出现大量 4625，随后出现 4624，即爆破成功；记录成功登录的 `Logon Type` 与账户。

## 3. RDP（3389）爆破专项

### 3.1 RDP 登录痕迹

```powershell
# RDP 登录 = 4624/4625 且 LogonType=10
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Where-Object {$_.Properties[8].Value -eq 10} | Group-Object {$_.Properties[18].Value} | Sort-Object Count -Descending | Select Count,Name
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | Where-Object {$_.Properties[8].Value -eq 10} | Select TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='IP';e={$_.Properties[18].Value}}
```

### 3.2 RDP 客户端连接历史（攻击者本机痕迹，也用于横向溯源）

```bat
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" /v MRU*
```

### 3.3 RDP 状态检查

```bat
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
```

- 判据：`fDenyTSConnections=0`（RDP 开）+ 大量 Type 10 的 4625 + 源 IP 异常；成功登录账户非业务账户。

## 4. MSSQL（1433）爆破专项

### 4.1 SQL Server 错误日志 18456

```powershell
# SQL Server 错误日志里的 18456（登录失败）——MSSQL 爆破核心证据
Get-Content 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\LOG\ERRORLOG*' | Select-String -Pattern '18456'
# 聚合失败登录的客户端 IP 与账户
```

- 判据：ERRORLOG 里大量 18456，`客户端: <IP>` 与 `用户 '<账户>'` 高频出现；随后出现成功登录记录。

### 4.2 成功后痕迹

```powershell
# xp_cmdshell 被启用（MSSQL 拿 shell 的关键）
Get-ChildItem 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\LOG\ERRORLOG*' | Select-String -Pattern 'xp_cmdshell|sp_configure'
# SQL Server 进程拉起 cmd 子进程
Get-CimInstance Win32_Process | Where-Object {$_.ParentProcessId -in (Get-Process sqlservr -ErrorAction SilentlyContinue).Id} | Select Name,CommandLine
```

## 5. SMB 爆破专项

```powershell
# SMB 爆破 = 4625 且 LogonType=3（网络登录），源端口 445
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Where-Object {$_.Properties[8].Value -eq 3} | Group-Object {$_.Properties[18].Value} | Sort-Object Count -Descending | Select Count,Name
```

- 判据：单源 IP 大量 Type 3 的 4625；失败后出现 Type 3 的 4624（SMB 登录成功，常用于横向）。

## 6. 爆破后痕迹三查（账户/组/计划任务/服务）

爆破成功只是入口，重点查「进来后干了什么」：

```powershell
# ① 新建账户 / 加组
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4732,4728} | Select TimeCreated,Id,Message
Get-LocalUser | Where-Object {$_.LastLogon -gt (Get-Date).AddDays(-7)} | Select Name,Enabled
Get-LocalGroupMember -Group Administrators | Select Name

# ② 计划任务
Get-ScheduledTask | ForEach-Object { $_.Actions } | Where-Object {$_.Execute -match 'powershell|cmd|mshta|regsvr32|rundll32'} | Select Execute,Arguments

# ③ 服务
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} | Select TimeCreated,@{n='Svc';e={$_.Properties[0].Value}},@{n='Path';e={$_.Properties[1].Value}}
Get-CimInstance Win32_Service | Where-Object {$_.PathName -match 'temp|Users|ProgramData'} | Select Name,PathName
```

- 判据：爆破成功时间点之后，出现新建账户（4720）→ 加管理员组（4732）→ 建计划任务/服务（4698/7045）的连续链，即「爆破 → 提权 → 持久化」完整失陷链。

## 7. 处置清单（用户确认后执行）

1. 禁用/删除异常账户（`net user <账户> /active:no` 或删除）。
2. 改弱口令 + 启用强口令策略/账户锁定策略（`net accounts /lockoutthreshold`）。
3. 清持久化（账户/组/计划任务/服务，见 persistence-points.md）。
4. 收敛暴露面：关不必要的 RDP/MSSQL 对公网暴露、改端口、防火墙白名单、启用 MFA。
5. 封禁爆破源 IP（防火墙/边界设备）。

## 来源

- https://book.noptrace.com/
- MITRE ATT&CK（Brute Force T1110 / Valid Accounts T1078）：https://attack.mitre.org/
