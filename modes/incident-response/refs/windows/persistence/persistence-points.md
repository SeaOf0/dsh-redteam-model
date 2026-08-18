# Windows 持久化点全表

> 正文自写原创；持久化点分类参考 MITRE ATT&CK Persistence/Privilege Escalation 矩阵（见文末来源），位置/命令/清理为自写。
> 用法：处置收尾时逐项排查，确认无残留后门。每项=位置 + 检查命令 + 清理注意。删除类操作只出清单用户确认执行。

## 0. 排查总入口（一次枚举大部分自启动点）

```powershell
# Autoruns 是持久化排查首选（图形 + 命令行），一次列出 Run 键/服务/计划任务/驱动/Winlogon/WMI 等
autorunsc.exe -a * -c -h -s -v   # -a * 全部, -c CSV, -h 含隐藏, -s 校验签名, -v 校验 VirusTotal
```

- 配合 `Get-CimInstance Win32_StartupCommand`、`Get-ScheduledTask`、`Get-Service` 做交叉验证。

## 1. Run 键（注册表自启动）

| 位置 | 说明 |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 所有用户 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | 一次性（重启后删） |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 当前用户 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | 组策略 |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | 32 位视图 |

```bat
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /s
```

- 清理注意：删值用 `reg delete <键> /v <值名> /f`；先确认值指向的 exe 确实是恶意的，删前导出 `.reg` 备份。

## 2. 启动目录

| 位置 | 说明 |
|---|---|
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` | 所有用户 |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp` | 当前用户 |

```powershell
Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp','$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StartUp' -Force
```

- 清理注意：删快捷方式/文件即可，但先看指向目标；快捷方式里可能藏着参数（`cmd /c ...`）。

## 3. 计划任务

```bat
schtasks /query /fo csv /v
:: 任务 XML 目录 + 注册表
dir C:\Windows\System32\Tasks /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
```

```powershell
Get-ScheduledTask | Select TaskPath,TaskName,State
Get-ScheduledTask | ForEach-Object { $_.Actions } | Select Execute,Arguments
```

- 清理注意：`schtasks /delete /tn "<任务名>" /f`；删前 `/xml` 导出备份。隐藏任务（SDDL 伪装）需先比对 XML 文件与注册表差集。

## 4. 服务 + ServiceDll

| 位置 | 说明 |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\<服务名>` | `ImagePath`（可执行）、`ServiceDll`（svchost 托管）、`Start`（2=自动 3=手动 4=禁用） |

```bat
sc query state= all
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f ServiceDll
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<服务名>" /v ImagePath
```

```powershell
Get-CimInstance Win32_Service | Select Name,PathName,StartMode,State
```

- 清理注意：`sc stop <服务名>` → `sc delete <服务名>`；svchost 托管服务需先定位 ServiceDll 对应服务，删 ServiceDll 对应的注册表 `Parameters\ServiceDll` 指向（或还原被替换的 DLL）。删服务前记录 `ImagePath` 原值。

## 5. WMI 事件订阅（过滤器/消费者/绑定三件套）

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select Name,Query
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Select Name,CommandLineTemplate,ExecutablePath
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer | Select Name,ScriptText
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Select Filter,Consumer
```

- 清理注意：删除顺序**绑定 → Consumer → Filter**（反了会留孤立对象/报错）；用 `Remove-WmiObject`。

## 6. COM 劫持

| 位置 | 说明 |
|---|---|
| `HKCR\CLSID\{CLSID}\InprocServer32` | 替换 COM 组件的 DLL 路径 |
| `HKCU\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` | 用户级 COM 劫持（免管理员） |

```powershell
# 枚举 InprocServer32 指向用户可写目录的 CLSID
Get-ChildItem "Registry::HKEY_CLASSES_ROOT\CLSID" -Recurse -ErrorAction SilentlyContinue |
  Where-Object {$_.Name -like '*InprocServer32'} | Get-ItemProperty |
  Where-Object {$_.'(default)' -notlike 'C:\Windows\*' -and $_.'(default)' -like '*.dll'} | Select PSChildName,'(default)'
```

- 清理注意：还原 `(default)` 值为原始系统 DLL；删用户级劫持键。

## 7. AppInit_DLLs / BootExecute / IFEO

| 项 | 位置 | 说明 |
|---|---|---|
| AppInit_DLLs | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` + `LoadAppInit_DLLs=1` | 所有加载 user32.dll 的进程都会加载该 DLL |
| BootExecute | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` | 开机执行（默认 `autocheck autochk *`） |
| IFEO 映像劫持 | `HKLM\...\Image File Execution Options\<exe>\Debugger` | 运行某程序时改执行 Debugger 指定的程序 |

```bat
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /f Debugger
```

- 清理注意：BootExecute 默认值 `autocheck autochk *`，多出的项即可疑；IFEO 的 Debugger 值删掉即可，注意别删整个 IFEO 键（可能含合法配置）。

## 8. DLL 侧加载（搜索顺序劫持）

- 原理：在目标程序的当前目录放置同名恶意 DLL，利用 DLL 搜索顺序让程序加载它而非系统 DLL。
- 排查：Sysmon 7（镜像加载）过滤「从非系统目录加载了本应来自 System32 的 DLL」；Procmon 抓 `NAME NOT FOUND` 后在同目录出现同名 DLL。
- 清理注意：删掉放置的恶意 DLL，并确认目标程序目录权限（为何攻击者能写）。

## 9. Winlogon（Shell/Userinit/AppCertDlls）

| 位置 | 说明 |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | 默认 `explorer.exe`，被改成 `explorer.exe,<恶意>` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | 默认 `C:\Windows\system32\userinit.exe,`，可追加恶意 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` | 每个进程都会加载 |

```bat
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v AppCertDlls
```

- 清理注意：Shell 还原为 `explorer.exe`、Userinit 还原为 `C:\Windows\system32\userinit.exe,`（注意结尾逗号）；AppCertDlls 非空即高度可疑。

## 10. PowerShell Profile

```powershell
$PROFILE | Format-List *   # 4 种 profile 路径
Test-Path $PROFILE.CurrentUserAllHosts
Get-Content $PROFILE -ErrorAction SilentlyContinue
```

- 清理注意：删 profile 里的恶意行或整个文件（若原本无 profile）；检查是否还通过 profile 引用了别的 ps1。

## 11. 证书（恶意根证书/代码签名证书）

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.NotBefore -gt (Get-Date).AddDays(-90)}
Get-ChildItem Cert:\LocalMachine\My | Select Subject,NotAfter,Thumbprint
```

- 清理注意：删可疑根证书用 `Remove-Item Cert:\LocalMachine\Root\<Thumbprint>`；先确认证书非业务所需。

## 12. 隐藏账户

```bat
:: $ 结尾账户（classic 隐藏）
reg query "HKLM\SAM\SAM\Domains\Account\Users\Names"
:: 与 lusrmgr.msc 图形比对（图形不显示 $ 账户）
```

```powershell
Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Select Name,SID
```

- 清理注意：`net user <账户> /delete`；先确认账户非系统账户，删除前记录 SID。

## 13. 隐藏服务（SDDL 权限隐藏）

```powershell
# 注册表有但 sc query 不显示的服务（SDDL 隐藏）
$reg = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | Select-Object -ExpandProperty PSChildName
$svc = Get-Service | Select-Object -ExpandProperty Name
Compare-Object $reg $svc
```

- 清理注意：隐藏服务需先恢复 SDDL 可见性（还原服务键的 Security 描述符）再 `sc delete`。

## 14. 持久化点速查总表

| 持久化点 | 位置 | ATT&CK | 检查命令 |
|---|---|---|---|
| Run 键 | HKLM/HKCU\...\Run, RunOnce | T1547.001 | `reg query` |
| 启动目录 | ProgramData/AppData\...\StartUp | T1547.001 | `Get-ChildItem` |
| 计划任务 | Tasks + 注册表 Schedule | T1053.005 | `schtasks` |
| 服务 | Services\<svc>\ImagePath/ServiceDll | T1543.003 | `sc query` / `Get-Service` |
| WMI 订阅 | root\subscription 三件套 | T1546.003 | `Get-WmiObject` |
| COM 劫持 | CLSID\...\InprocServer32 | T1546.015 | 注册表枚举 |
| AppInit_DLLs | Windows\AppInit_DLLs | T1546.010 | `reg query` |
| BootExecute | Session Manager\BootExecute | T1547.014 | `reg query` |
| IFEO | IFEO\<exe>\Debugger | T1546.012 | `reg query /f Debugger` |
| DLL 侧加载 | 目标目录恶意 DLL | T1574.001 | Sysmon 7 |
| Winlogon | Shell/Userinit/AppCertDlls | T1547.004 | `reg query` |
| PS Profile | $PROFILE | T1546.013 | `Get-Content $PROFILE` |
| 证书 | Cert:\LocalMachine | T1553.004 | `Get-ChildItem Cert:` |
| 隐藏账户 | SAM `$` 账户 | T1136.001 | `net user` / SAM |
| 隐藏服务 | SDDL 隐藏服务 | T1564 | 注册表 vs sc 差集 |

## 来源

- MITRE ATT&CK（Persistence / Privilege Escalation）：https://attack.mitre.org/
- LOLBAS（合法二进制滥用，交叉引用）：https://lolbas-project.github.io/
- Autoruns（Sysinternals）：https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://book.noptrace.com/
