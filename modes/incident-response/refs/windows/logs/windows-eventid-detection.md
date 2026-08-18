# Windows 日志分析 Event ID 检测集

> 正文自写原创；本文件为「应急场景下的字段级判据 + 查询命令」，不照抄原文，来源链接见文末。
> 用法：确定时间窗后按 Event ID 定向捞日志，结合「字段值 + 时间相关性 + 行为链」判疑；单条日志不构成结论。
> 通用查询先过滤「安全日志/系统日志/应用程序日志」三类主日志，再按需查 PowerShell/Sysmon 专用日志。

## 0. 日志查询基础命令

```bat
:: 列可用日志
wevtutil el
:: 读 Security 最近 100 条
wevtutil qe Security /c:100 /f:text /rd:true
:: 按 Event ID 过滤（XPath）
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:100 /f:text
```

```powershell
# Get-WinEvent 按 ID 过滤 + 时间窗
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)} | Select TimeCreated,Id,@{n='IP';e={$_.Properties[18].Value}},@{n='User';e={$_.Properties[5].Value}}
```

> 技巧：`Get-WinEvent -FilterHashtable` 比 `Where-Object` 快一个量级（服务端过滤）；`-MaxEvents` 控制量；结果量大时用 `Export-Csv` 落盘后用 Log Parser/Excel 聚合。

---

## 1. 登录与认证类

### 4624 登录成功

- 含义：账户成功登录。字段要点：`Logon Type`（登录类型）、`Logon Process`、`New Logon` 的账户名/域、`Source Network Address`（来源 IP）、`Process Name`（发起进程）。
- 登录类型速查：2=交互式、3=网络（SMB/映射）、4=批处理（计划任务）、5=服务、7=解锁、8=网络明文、9=新凭据（runas）、10=远程交互（RDP）、11=缓存凭据。
- 应急场景：确认失陷账户、定位横向移动（Type 3 网络登录）、RDP 失陷（Type 10）、服务账户异常（Type 5）。
- 可疑判据：Type 3/10 且来源 IP 为外部/内网非常规段；`Logon Process` 为 `NtLmSsp` 的异常登录；非工作时间窗的成功登录；`Process Name` 为 `psexec`/`wsmprovhost` 等横向工具。

### 4625 登录失败

- 含义：登录失败。字段要点：`Failure Reason`（失败原因状态码/子状态）、`Account Name`、`Logon Type`、`Source Network Address`。
- 应急场景：**暴力破解/口令喷洒**检测的首选信号。
- 判据与阈值：同一来源 IP 对同一/多账户短时间内（如 5 分钟）产生大量 4625（阈值建议：单源 IP ≥ 10 次/分钟，或单账户 ≥ 5 次/分钟），且失败原因集中在 `0xC000006A`（密码错）/`0xC0000064`（用户不存在）→ 判爆破。
- 聚合命令：

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10000 |
  Group-Object { $_.Properties[18].Value } |
  Sort-Object Count -Descending |
  Select-Object Count, Name
```

### 4648 显式凭据登录

- 含义：用显式凭据登录（runas、PsExec、计划任务 `Run As`、WINRM）。字段：`Account Whose Credentials Were Used`（被借用的账户）、`Target Server`（目标服务器）、`Process Name`（发起进程）。
- 应急场景：**横向移动**关键信号——攻击者用 `runas`/PsExec 借高权限账户。
- 可疑判据：普通账户用管理员凭据登录到非本机目标；`Process Name` 是 `psexec.exe`/`powershell` 且目标为横向目标；同账户短时间对多台主机 4648。

### 4672 特殊权限分配

- 含义：登录会话被授予特殊权限（管理员组/SeDebugPrivilege 等）。字段：`Account`、`Security ID`、`Privileges`。
- 应急场景：提权、管理员登录、SeDebugPrivilege 授予（可用于 dump 凭据/注入）。
- 可疑判据：非管理员账户突然获得 SeDebugPrivilege/SeTcbPrivilege；账户与 4624 Type 3/10 同源。

### 4776 NTLM 校验（补充，域环境）

- 含义：域控用 NTLM 校验账户（含哈希传递/NTLM 爆破痕迹）。字段：`Source Workstation`、`Status`、`Account Name`。
- 可疑判据：`Status=0xC000006A` 高频（NTLM 爆破）；来源主机异常。

## 2. 进程与执行类

### 4688 进程创建

- 含义：新进程创建（**需启用「审核进程创建」+ 命令行日志**才含命令行）。字段：`New Process Name`、`Creator Process`、`Command Line`、`Token Elevation Type`。
- 应急场景：**攻击链还原的核心日志**——还原攻击者跑了什么、用什么参数。
- 启用命令：

```powershell
# 审核进程创建 + 命令行（命令行日志需 Win8.1/2012R2+ 且注册表开启）
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

- 可疑判据：命令行含 `-enc`/`DownloadString`/`IEX`/`Invoke-WebRequest`/`regsvr32 /i`/`mshta`/`rundll32 javascript`；父进程是 Office/浏览器/Web 服务进程却拉起 cmd/powershell；`Token Elevation Type` 突变为 2（提权）。

### 4689 进程退出

- 含义：进程退出。字段：`Process Name`、`Process ID`、`Exit Status`。
- 应急场景：配合 4688 建立进程生命周期（进程存活时长异常可辅助判疑）。

## 3. 服务/计划任务/账户变更类

### 4697 服务安装（Security 日志）

- 含义：系统安装了服务。字段：`Service Name`、`Service File Name`（镜像路径）、`Account Name`（服务账户）。
- 应急场景：恶意服务持久化。与 System 日志 7045 是同一动作的两个视角（4697=Security 审核、7045=Service Control Manager）。
- 可疑判据：`Service File Name` 指向临时目录/用户目录；服务账户为高权限且新建时间落在攻击窗。

### 7045 服务安装（System 日志）

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} | Select TimeCreated,@{n='Svc';e={$_.Properties[0].Value}},@{n='Path';e={$_.Properties[1].Value}}
```

- 可疑判据同上；7045 默认开启，比 4697 更易拿到（很多机器未开进程/服务审计）。

### 4698 / 4702 计划任务创建/更新

- 含义：4698=计划任务创建、4699=删除、4700=启用、4701=禁用、4702=更新。字段：`Task Name`、`Task Content`（含 XML，含 `<Command>` 动作）。
- 应急场景：计划任务持久化。
- 可疑判据：`Task Content` 的 `<Command>` 是 powershell/mshta/regsvr32/rundll32，`<Arguments>` 含编码/下载；任务被设「以 SYSTEM 运行」且触发频繁。

### 4720 / 4726 用户账户创建/删除

- 含义：4720=创建账户、4726=删除账户。字段：`Account Name`、`Security ID`、`Account Domain`。
- 应急场景：**后门账户**。
- 可疑判据：创建账户名带 `$` 后缀、RID 异常、创建后随即加入管理员组（关联 4732）。

### 4728 / 4732 组成员添加

- 含义：4728=添加进全局安全组、4732=添加进本地安全组（含管理员组）。字段：`Member Name`、`Group Name`、`Member Security ID`。
- 应急场景：**权限维持**——把后门账户拉进管理员组。
- 可疑判据：非预期账户被加入 Administrators/Remote Desktop Users 组；加入时间在攻击窗。

## 4. 反取证与日志清除

### 1102 审计日志清除（Security）

- 含义：Security 日志被清除（`wevtutil cl Security` / `Clear-EventLog`）。字段：`Account Name`（清除者）。
- 应急场景：**反取证**——攻击者清日志掩盖痕迹。
- 可疑判据：1102 本身即高危（正常运维极少清 Security）；清除者账户非预期。

### 104 事件日志清除（System）

- 含义：某事件日志被清除。字段：`Log`（被清的日志名）、`Subject User`。
- 可疑判据：出现 104 且被清的日志恰是攻击痕迹所在（Security/PowerShell/Sysmon）。

> 反取证自查：即使日志被清，也要查 1102/104 本身、`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>` 的配置是否被改（日志禁用/重定向），以及 Sysmon 服务是否被停用。

## 5. PowerShell 日志

### 4104 脚本块日志

- 含义：记录执行的 PowerShell 脚本块（含编码命令解码前的原文，需启用 Script Block Logging）。字段：`ScriptBlockText`、`Path`、`UserId`。
- 应急场景：**无文件攻击、编码命令、混淆脚本**的核心证据。
- 启用命令：

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

- 查询：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[(EventID=4104)]]" | Select TimeCreated,@{n='Script';e={$_.Properties[2].Value}}
```

- 可疑判据：ScriptBlockText 含 base64 大块、`DownloadString`、`FromBase64String`、`[System.Reflection.Assembly]::Load`、`Invoke-Expression`、`Net.WebClient`、`Net.Sockets`；`Path` 来自临时目录或 Web 进程。

### 4103 模块日志

- 含义：PowerShell 模块/命令执行记录（Pipeline Execution Details）。字段：`Payload`、`ContextInfo`。
- 应急场景：补全 4104 未覆盖的模块调用（4103 记录模块执行，4104 记录脚本块）。
- 可疑判据：加载陌生模块、调用危险 cmdlet（`Invoke-Mimikatz`、`Invoke-Shellcode`）。

## 6. Sysmon Event ID 速查表（1/3/7/10/11/13/15/22/23）

> Sysmon 补全了系统审计日志的盲区，是「攻击链还原」最依赖的事件源。启用与配置见 tools/tool-cards.md。

| ID | 事件 | 关键字段 | 应急判据 |
|---|---|---|---|
| 1 | 进程创建 | Image、CommandLine、ParentImage、ParentCommandLine、User、Hashes | 可疑命令行/父进程、无签名、哈希命中 IOC |
| 3 | 网络连接 | Image、DestinationIp、DestinationPort、SourceIp、Protocol | 系统进程外连非常规 IP、命中恶意 IP/端口 |
| 7 | 镜像（DLL）加载 | Image、ImageLoaded、Hashes、Signed | 从用户可写目录加载同名系统 DLL（DLL 劫持）、加载未签名陌生 DLL |
| 10 | 进程访问 | SourceImage、TargetImage、GrantedAccess、CallTrace | 对 lsass.exe 的 0x1010/0x143a 访问（凭据 dump）、远程线程注入 |
| 11 | 文件创建 | Image、TargetFilename | 在启动目录/系统目录创建可执行文件（覆盖改名） |
| 13 | 注册表值设置 | Image、TargetObject、Details | Run 键/服务 ServiceDll/WMI 订阅被写入 |
| 15 | 文件流哈希（ADS） | Image、TargetFilename、Hash、Contents | 创建可疑 ADS（`合法文件:evil`） |
| 22 | DNS 查询 | Image、QueryName、QueryResults | 进程查询 DGA 域名/C2 域名 |
| 23 | 文件删除 | Image、TargetFilename、Archived、IsExecutable | 删除自身/删除样本/删除日志，配合时间线还原「删除痕迹」 |

- Sysmon 查询模板：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" | Select TimeCreated,@{n='Image';e={$_.Properties[4].Value}},@{n='Cmd';e={$_.Properties[10].Value}}
```

## 7. 日志清除反取证检测（汇总）

| 检测点 | 命令 | 判据 |
|---|---|---|
| Security 日志清除 | `Get-WinEvent Security -FilterXPath "*[System[(EventID=1102)]]"` | 1102 出现 |
| 任意日志清除 | `Get-WinEvent System -FilterXPath "*[System[(EventID=104)]]"` | 104 出现且日志名敏感 |
| 日志服务停用 | `wevtutil gl Security` / 查 EventLog 服务配置 | 日志被禁用/重定向/最大大小被改小 |
| Sysmon 停用 | `sc query Sysmon` / `fltmc` 查 SysmonDrv 过滤器 | Sysmon 服务停止、驱动卸载（攻击者常先杀 Sysmon） |
| 时间戳回拨 | 对比多条日志 TimeCreated 与 `systeminfo` 系统时间、Event 的 `TimeCreated` 倒退 | 日志时间轴出现「倒流」（时间戳伪造） |

---

## 来源

- Microsoft 安全日志事件参考（官方审计策略与字段）：https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing
- UltimateWindowsSecurity Security Log Encyclopedia（Event ID 词典）：https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
- Sysmon（Sysinternals）：https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- SigmaHQ（Windows 检测规则集，供 Chainsaw/Hayabusa 落地）：https://github.com/SigmaHQ/sigma
