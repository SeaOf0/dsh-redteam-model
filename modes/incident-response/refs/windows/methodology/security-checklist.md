# Windows 常规安全检查总纲（0x00–0x36，全量 55 面）

> 正文为自写原创排查面总纲。覆盖口径：公开资料 66 项排查面中同义合并后为本文 55 面（0x00–0x36）；WMI 事件订阅/COM/IFEO/AppInit 在 `../persistence/persistence-points.md` 有全表展开，本文 0x2A/0x2C/0x2E/0x2F 为检查命令视角。
> 用法：处置收尾或日常巡检时，从 0x00 到 0x36 逐项过；每项给「命令级检查步骤 + 可疑判据」。单项可疑不代表失陷，需多源互证（时间相关 + 行为链）。
> 命令默认 cmd + PowerShell 双写法；`wmic` 在新版系统已弃用，但老系统仍广泛存在，故保留等价写法。

## 0x00 杀毒软件与白名单/排除项

攻击者常把恶意文件路径加入杀软排除目录，让杀软对其「视而不见」。

```bat
:: 查 Windows Defender 排除项（注册表）
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
```

```powershell
Get-MpPreference | Select-Object -Property ExclusionPath,ExclusionExtension,ExclusionProcess
```

- 可疑判据：排除项里出现 `C:\Windows\Temp\`、`C:\ProgramData\`、回收站、用户下载目录等非常规位置；或出现陌生进程名/扩展名（`.ps1`、`.vbs`、`.dll` 被加入排除）。
- 交叉验证：`Get-MpComputerStatus` 看实时保护是否被关闭（`RealTimeProtectionEnabled=False`）。

## 0x01 近期活动（程序执行痕迹全家桶）

Windows 会留下大量「程序何时被运行过」的痕迹，是定位「攻击者跑过什么」的核心面。逐项：

### Amcache（程序首次运行/哈希）

```powershell
# 关联文件：C:\Windows\AppCompat\Programs\Amcache.hve
# 用 Zimmerman AmcacheParser 解析；注册表在线查：
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache" -ErrorAction SilentlyContinue
```

- 可疑判据：Amcache 里出现临时目录/用户目录的 exe 条目，时间戳与攻击时间窗重合。

### ShimCache（AppCompatCache，程序执行时间）

```powershell
# 用 Zimmerman AppCompatCacheParser 解析 SYSTEM 注册表；在线位置：
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
```

- 可疑判据：记录了已被删除的 exe（「跑了就删」的样本），路径可疑。

### UserAssist（GUI 程序运行次数与最后运行时间）

```powershell
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count" | Select-Object -ExpandProperty PSObject.Properties
```

- 可疑判据：出现 `cmd.exe`/`powershell.exe`/`regsvr32.exe`/`rundll32.exe`/`mshta.exe` 等 LOLBin 的异常运行记录，尤其来自临时目录。

### MUICache / RunMRU / LastVisitedMRU（运行与最近访问痕迹）

```powershell
Get-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
```

### Prefetch（程序执行痕迹，含运行次数与时间）

```powershell
# 目录：C:\Windows\Prefetch\*.pf
Get-ChildItem C:\Windows\Prefetch\*.pf | Select Name,LastWriteTime | Sort LastWriteTime -Descending | Select -First 50
# 解析 pf 文件用 PECmd（Zimmerman）
```

- 可疑判据：出现 `SUSPICIOUS.EXE-XXXX.pf` 这类临时目录样本的 prefetch；或 `POWERSHELL.EXE-*.pf` 异常高频。

### Jump Lists / CustomDestinations（最近打开文档）

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations" | Sort LastWriteTime -Descending
# 解析用 JLECmd / LECmd（Zimmerman）
```

### SRUM（系统资源使用与网络流量历史）

```powershell
# 数据在 C:\Windows\System32\sru\SRUDB.dat（需 SYSTEM 权限），解析用 srum-dump（Mark Baggett）
```

- 可疑判据：SRUM 里某进程产生异常网络流量/运行时长，与告警时间窗吻合。

## 0x02 证书排查

恶意根证书可用于中间人/签名的恶意驱动。

```bat
certmgr.msc    :: 图形查看个人/受信任根证书颁发机构
```

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.NotBefore -gt (Get-Date).AddDays(-90)} | Select Subject,NotAfter,Thumbprint
Get-ChildItem Cert:\LocalMachine\My | Select Subject,NotAfter,Thumbprint
```

- 可疑判据：受信任根里出现近期新增、组织名陌生、NotBefore 落在攻击时间窗的证书；`My` 个人存储出现非业务自签证书。

## 0x03 账号信息与隐藏账户

```bat
net user                  :: 列用户
net localgroup administrators   :: 列管理员组
wmic useraccount get Name,SID,Disabled,LocalAccount /format:list
```

```powershell
Get-LocalUser | Select Name,Enabled,LastLogon,SID
Get-LocalGroupMember -Group Administrators
```

隐藏账户排查（`$` 结尾账户是 classic 隐藏手法）：

```bat
:: 注册表直接读 SAM 里的用户列表（需 SYSTEM）
reg query "HKLM\SAM\SAM\Domains\Account\Users\Names"
:: PowerShell 枚举，注意与 lusrmgr.msc 图形界面比对（图形界面可能不显示 $ 隐藏账户）
Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Select Name,SID
```

- 可疑判据：账户名以 `$` 结尾、无描述、LastLogon 异常、SID 尾号 RID 500（Administrator）被改名、新建的低权限账户突然进了管理员组。

## 0x04 登录信息

```bat
query session         :: 本地/远程会话
query user            :: 登录用户
```

```powershell
quser 2>$null; qwinsta 2>$null
Get-CimInstance Win32_LogonSession | Where-Object {$_.LogonType -in 2,10} | Select LogonId,StartTime,LogonType
```

- 可疑判据：存在来源为 RDP/网络的活跃会话，对应账户非业务账户；会话建立时间在非工作时间窗。

## 0x05 启动项

```bat
msconfig                     :: 图形
:: 全局/用户启动目录
dir "%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"
:: 注册表启动项
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
:: 组策略启动脚本
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
```

```powershell
Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User
```

- 可疑判据：Run 键值指向临时目录/用户目录/陌生路径；启动脚本里出现 PowerShell 下载执行、`-enc` 编码命令、`iex (New-Object Net.WebClient).DownloadString` 等。

## 0x06 计划任务与隐藏计划任务

```bat
schtasks /query /fo csv /v          :: 全量计划任务
taskschd.msc                        :: 图形
:: 任务目录文件（XML 定义）
dir C:\Windows\System32\Tasks /s
:: 注册表任务定义
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
```

```powershell
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName,TaskPath,State
Get-ScheduledTask | ForEach-Object { $_ | Get-ScheduledTaskInfo } | Where-Object {$_.LastRunTime -gt (Get-Date).AddDays(-7)} | Select TaskName,LastRunTime,LastTaskResult
```

隐藏计划任务排查（SD 值非默认、无 XML 文件对应、图形界面不显示）：

```powershell
# 对比「XML 文件」与「注册表 TaskCache」两条线索是否一致；XML 缺失但注册表有 = 隐藏
Get-ChildItem C:\Windows\System32\Tasks -Recurse | Select FullName,LastWriteTime
# 查任务的安全描述符（SD），攻击者改 SDDL 隐藏任务
schtasks /query /tn "<任务名>" /xml
```

- 可疑判据：任务动作是 `powershell -enc ...`、`regsvr32 /i:http...`、`mshta http...`、`rundll32 ...javascript`；触发器异常频繁（每分钟）；任务作者（Author）非 SYSTEM/Administrator 常规名。

## 0x07 网络连接

```bat
netstat -ano          :: TCP/UDP + PID
netstat -anob         :: 带进程名（需管理员）
nbtstat -n            :: NetBIOS
```

```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
Get-NetUDPEndpoint | Select LocalAddress,LocalPort,OwningProcess
```

- 可疑判据：系统进程（svchost/explorer）主动外连非常规 IP；连向已知恶意 IP/域名；异常高端口监听；进程名与 PID 不符。

## 0x08 IPC 共享

```bat
net share             :: 列共享
net use               :: 列已连接共享
```

```powershell
Get-SmbShare | Select Name,Path,Description
Get-SmbConnection | Select ServerName,ShareName,UserName
```

- 可疑判据：出现 `ADMIN$`/`C$`/`IPC$` 之外的新建共享指向敏感目录；存在非本机发起的 SMB 连接。

## 0x09 进程

```bat
tasklist /v           :: 详细进程
tasklist /m           :: 带模块
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine /format:csv
```

```powershell
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | Sort ParentProcessId
```

图形工具：Process Explorer（签名验证+进程树）、System Informer（隐藏进程）、OpenArk（ARK 反内核隐藏进程/钩子）。

- 可疑判据：`svchost.exe`/`explorer.exe`/`lsass.exe` 路径不在 System32；系统进程的父进程是浏览器/Office；进程名拼写伪装（`svch0st`、`exp1orer`）；无签名或签名异常。

## 0x10 环境变量与 CLR 劫持

```bat
set                   :: 当前用户环境变量
:: 系统/用户环境变量注册表
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
reg query "HKCU\Environment"
```

CLR 劫持排查（.NET 程序启动时加载恶意 DLL）：

```bat
reg query "HKLM\SOFTWARE\Microsoft\.NETFramework" /v OnlyUseLatestCLR
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework" /v OnlyUseLatestCLR
:: CLR 版本目录下的 mscorlib 是否被替换/新增（比对签名）
dir C:\Windows\Microsoft.NET\Framework\v4.0.30319\*.dll /s
```

- 可疑判据：环境变量被追加恶意路径（PATH 首部指向临时目录）；`COR_ENABLE_PROFILING`/`COR_PROFILER_PATH` 指向陌生 DLL；`.NETFramework` 相关键被改。

## 0x11 系统基本信息及补丁

```bat
systeminfo                     :: 含补丁列表
wmic qfe list brief            :: 补丁
wmic os get osarchitecture,version
```

```powershell
Get-HotFix | Select HotFixID,InstalledOn | Sort InstalledOn -Descending
```

- 补丁缺口评估：导出补丁清单喂 Windows-Exploit-Suggester / WES-NG，比对未打补丁与公开 EXP 的匹配面（评估「可被利用面」，是定损与加固依据）。

## 0x12 系统日志分析

```bat
eventvwr.msc                   :: 图形
wevtutil el                    :: 列日志
wevtutil qe Security /c:100 /f:text   :: 读 Security
```

```powershell
Get-WinEvent -LogName Security -MaxEvents 100 | Select TimeCreated,Id,Message
Get-WinEvent -LogName System -MaxEvents 100 | Where-Object {$_.Id -in 7045,7036,7034}
Get-WinEvent -LogName Application -MaxEvents 50
```

- 详细 Event ID 判据见 logs/windows-eventid-detection.md；Sysmon 采集与配置见 tools/tool-cards.md。
- 日志分析工具：Log Parser（SQL 查询）、LogParser Lizard（GUI）、FullEventLogView、LogonTracer（登录关系图）。

## 0x13 命令历史

```powershell
# PowerShell 历史（PSReadLine，当前用户）
Get-Content (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue
# 控制台历史（cmd 用 F7 查看，落盘在 consolehost 历史，图形为主）
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

- 可疑判据：历史里出现 `Invoke-Expression`/`DownloadString`/`-enc`/`Add-MpPreference -ExclusionPath`/`net user`/`net localgroup` 等攻击或反取证命令。

## 0x14 PowerShell 配置文件（Profile）

```powershell
$PROFILE | Format-List *   # 列出 4 种 profile 路径
Test-Path $PROFILE.CurrentUserAllHosts
Get-Content $PROFILE -ErrorAction SilentlyContinue
```

- 可疑判据：profile 里出现下载执行、加载陌生 ps1、`Add-Type`/反射加载、编码命令。Profile 是常用持久化点。

## 0x15 PowerShell 日志

```powershell
# 脚本块日志（4104）+ 模块日志（4103），需先启用（组策略/注册表）
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -in 4103,4104} | Select TimeCreated,Id,Message
```

- 可疑判据：4104 里出现 base64 编码块、`DownloadString`、反射加载、`IEX`。详细见 logs/windows-eventid-detection.md。

## 0x16 PowerShell Alias

```powershell
Get-Alias | Sort-Object Name
# profile 里被 Set-Alias 篡改的别名
Get-Content $PROFILE | Select-String "Set-Alias|New-Alias"
```

- 可疑判据：常见命令（`ls`/`dir`/`curl`/`wget`）被别名指向陌生脚本/程序（攻击者用它劫持管理员常用命令）。

## 0x17 服务程序与 ServiceDll 与隐藏服务

```bat
sc query state= all
wmic service get Name,DisplayName,PathName,StartMode,State /format:csv
```

```powershell
Get-Service | Select Name,DisplayName,Status,StartType
Get-CimInstance Win32_Service | Select Name,PathName,StartMode,State
```

ServiceDll 检查（svchost 托管服务的关键点）：

```bat
:: 列出 Services 下所有 ServiceDll
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f ServiceDll
```

隐藏服务排查：

```powershell
# 注册表枚举的「服务名」与 sc query 结果比对，注册表有但 sc 不显示 = 隐藏（SDDL 权限）
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | Select-Object -ExpandProperty PSChildName
Get-Service | Select-Object -ExpandProperty Name
# 进阶：比对两列表差集
```

- 可疑判据：服务 PathName 指向临时目录/用户目录；svchost 服务的 ServiceDll 不在 System32 且被替换；服务名带 `$` 或被 SDDL 隐藏；服务 BinaryPathName 含 `cmd /c`、`powershell`、`mshta`、`rundll32`。

## 0x18 远程桌面 RDP

```bat
:: RDP 启用状态
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
:: 用户 RDP 连接历史（HKCU，攻击者常清这里）
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default"
```

- 可疑判据：RDP 历史里出现非业务服务器 IP；`fDenyTSConnections=0`（RDP 开启）但业务不需要；出现异常来源账户的 RDP 登录（交叉 Security 4624 Type 10）。

## 0x19 DLL 检查（劫持/注入/KnownDLLs）

```powershell
# 当前加载了陌生 DLL 的进程
Get-Process | ForEach-Object { $_.Modules } | Where-Object {$_.FileName -notlike "C:\Windows\*" -and $_.FileName -like "*.dll"} | Select ModuleName,FileName
```

DLL 劫持排查思路：

- 找「从非系统目录加载了本应来自系统目录的 DLL」的进程（Procmon 过滤 `CreateFile` 结果 `NAME NOT FOUND` + `.dll`）。
- 检查 KnownDLLs（`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`）是否被删除/篡改（KnownDLLs 保证系统 DLL 从 System32 加载）。
- 检查目标目录是否被放置恶意同名 DLL（搜索顺序劫持）。

- 可疑判据：进程加载路径指向用户可写目录的同名系统 DLL；KnownDLLs 键异常。

## 0x20 WMI 排查（过滤器/消费者/绑定三件套）

```bat
wmic /namespace:"\\root\subscription" path __EventFilter get * /value
wmic /namespace:"\\root\subscription" path CommandLineEventConsumer get * /value
wmic /namespace:"\\root\subscription" path __FilterToConsumerBinding get * /value
```

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select Name,Query
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Select Name,CommandLineTemplate
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer | Select Name,ScriptText
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Select Filter,Consumer
```

- 可疑判据：存在 `__EventFilter`+`CommandLineEventConsumer`+绑定 的完整三件套，Consumer 命令行为 PowerShell 下载执行/`-enc`；ActiveScriptEventConsumer 的 ScriptText 为恶意脚本；命名空间异常（非 `root\subscription`）。
- 删除后门：先删绑定 → 再删 Consumer → 再删 Filter（顺序不能反，否则残留孤立对象）。

## 0x21 最近打开的文件

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" | Sort LastWriteTime -Descending | Select -First 30 Name,LastWriteTime
# 注册表 ComDlg32 最近文件 MRU
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
```

- 可疑判据：最近文件里出现攻击工具、敏感数据导出文件、陌生文档（疑似钓鱼附件）。

## 0x22 敏感文件夹检查

```powershell
# 临时目录（恶意样本常见落点）
Get-ChildItem C:\Windows\Temp -Recurse -Force | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select FullName,LastWriteTime,Length
Get-ChildItem "$env:TEMP" -Recurse -Force | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select FullName,LastWriteTime
# 垃圾桶（删掉的样本可能还原）
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue
# 被删用户的家目录残留
Get-ChildItem C:\Users -Directory -Force | Select Name,LastWriteTime
```

- 可疑判据：临时目录出现近期落盘的可执行文件/脚本/打包样本；回收站出现被删的可疑样本；存在异常的新建/删除用户目录。

## 0x23 附加项：NTFS ADS（备用数据流）与文件隐藏

攻击者用 ADS 隐藏 payload，或对文件设置隐藏属性/系统属性：

```bat
:: 列目录下文件的 ADS
dir /r <目录>
:: 用 streams（Sysinternals）递归查 ADS
streams.exe -s <目录>
:: 查隐藏/系统属性文件
attrib /s /d
```

```powershell
Get-Item <文件> -Stream * | Select Stream,Length
Get-ChildItem <目录> -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.Attributes -band [System.IO.FileAttributes]::Hidden}
```

- 可疑判据：正常文件携带陌生 ADS（如 `合法文件:evil.exe`）；可疑文件被设 hidden+system 属性（`attrib +s +h`）。

## 0x24 DLL 检查（KnownDLLs / 加载验证）

```powershell
# KnownDLLs 清单（这些路径攻击者无法用同名 DLL 抢先劫持，列表外才可能被劫持）
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" | Format-List
# 进程实际加载的 DLL（System Informer：进程属性 → DLL 页；命令行走 listdlls）
listdlls.exe -p <pid>   # Sysinternals，标"no verified signature"的 DLL 重点看
# 全盘搜未签名 DLL（近期落盘优先）
Get-ChildItem C:\ -Recurse -Include *.dll -Force -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} | Get-AuthenticodeSignature |
  Where-Object {$_.Status -ne 'Valid'} | Select Path,@{n='Time';e={(Get-Item $_.Path).LastWriteTime}}
```

- 可疑判据：系统进程（lsass/winlogon/services）加载了无签名/路径异常（Temp、Public、回收站、用户目录）的 DLL；KnownDLLs 列表被改动过（对照同版本干净系统）；DLL 的时间戳晚于其所在目录其他文件且与失陷时间窗重合。
- DLL 注入验证：System Informer 查目标进程 DLL 列表里出现与该进程不匹配的陌生模块；或比对模块加载路径与磁盘文件哈希不一致（内存补丁/ hollowing）。

## 0x25 系统完整性检查（sfc / DISM）

```bat
sfc /verifyonly
DISM /Online /Cleanup-Image /ScanHealth
```

- 判读：sfc 报告"Windows 资源保护找到了损坏文件"且涉及系统二进制 → 结合 CBS.log（`C:\Windows\Logs\CBS\CBS.log`）确认哪些文件被改；被改的系统文件名+时间即攻击时间线锚点（攻击者常替换 sethc/utilman/合法签名二进制做后门）。
- 注意：先做本节之外的证据固定再跑 `/scannow`（修复会覆盖现场）；排查阶段只用 `/verifyonly`（只读）。

## 0x26 Bits Job（后台智能传输服务滥用）

```powershell
bitsadmin /list /allusers /verbose
Get-BitsTransfer -AllUsers
# 持久化样貌：任务指向恶意 URL，且 DisplayName 随机/伪装系统名
```

- 可疑判据：存在下载可执行文件的 Transfer 任务（远程 URL 指向陌生域名/裸 IP，本地目标在 Temp/Public）；任务由非系统账户创建；创建时间与失陷窗重合。BITS 是 LOLBin（attacker 用它下载+延迟执行，进程归 svchost，绕过对浏览器进程的怀疑）。

## 0x27 浏览器排查（下载/访问记录/插件）

```powershell
# Chrome/Edge（Chromium 系）历史与下载：SQLite，路径
#   历史：%LOCALAPPDATA%\Google\Chrome\User Data\Default\History（Edge 换 Microsoft\Edge）
#   下载表：downloads（含 URL/起始时间/目标路径）；访问表：urls（URL/标题/最后访问）
copy "$env:LOCALAPPDATA%\Google\Chrome\User Data\Default\History" history.db
sqlite3 history.db "select datetime(start_time/1000000-11644473600,'unixepoch'),target_path,url from downloads order by start_time desc limit 50;"
sqlite3 history.db "select datetime(last_visit_time/1000000-11644473600,'unixepoch'),url,title from urls order by last_visit_time desc limit 100;"
# 扩展目录（恶意扩展持久化）
Get-ChildItem "$env:LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions" -Directory | Select Name,LastWriteTime
```

- 可疑判据：下载记录中出现攻击工具/未知可执行文件/时间在失陷窗内；访问记录佐证入口点（钓鱼链接/漏洞利用管理页/网盘中转）；陌生扩展或既有扩展的 manifest.json 被改（permissions 加 `<all_urls>`、`nativeMessaging`）。
- 无 sqlite3 时按工具缺四级兜底用 python3（标准库 sqlite3）读同一张表。

## 0x28 屏幕保护（SCR 劫持）

```powershell
Get-ItemProperty "HKCU:\Control Panel\Desktop" | Select SCRNSAVE.EXE,ScreenSaveTimeOut,ScreenSaverIsSecure
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SCRNSAVE.EXE" -ErrorAction SilentlyContinue
```

- 可疑判据：SCRNSAVE.EXE 指向非系统目录（%TEMP%/Public/用户目录）的 .scr/.exe；ScreenSaveTimeOut 异常短（登录后很快触发执行）；键值时间在失陷窗内。SCR 持久化冷门但 Autoruns 覆盖不到 HKCU 某些场景，手工兜底。

## 0x29 NetSh 辅助 DLL 劫持

```powershell
# 查已注册 helper DLL
netsh show helper
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NetSh" | Get-ItemProperty | Select PSChildName,'(default)'
```

- 可疑判据：helper DLL 位于用户可写目录/无签名；DLL 名伪装系统组件；注册时间在失陷窗内。netsh 每次执行都会加载全部 helper DLL——经典持久化+执行触发器。

## 0x2A 辅助功能程序后门（sethc/utilman/osk 等替换）

```powershell
# Image File Execution Options 劫持（Debugger 重定向）与直接替换都要查
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
  Where-Object {(Get-ItemProperty $_.PSPath).Debugger} | Select PSChildName,@{n='Debugger';e={(Get-ItemProperty $_.PSPath).Debugger}}
# 比对辅助程序本体是否被替换（应位于 System32 且微软签名）
foreach ($f in 'sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe') {
  $p = "C:\Windows\System32\$f"; if (Test-Path $p) { $s = Get-AuthenticodeSignature $p; "{0}  {1}  {2}" -f $f, $s.Status, (Get-Item $p).LastWriteTime }
}
```

- 可疑判据：IFEO 里 sethc/utilman 等带 Debugger 键（指向 cmd/payload）；System32 下辅助程序签名无效或时间戳异常（被直接替换）。远程登录界面按 5 次 Shift 即触发——无凭据执行通道。

## 0x2B AppCertDlls（全进程注入点）

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"
```

- 可疑判据：该键非空且 DLL 无签名/位于用户可写目录。凡走 Win32 子系统的进程（几乎所有 exe）创建时都会加载这里的 DLL——影响面极大，出现即高危。

## 0x2C AppInit_DLLs（user32 加载链注入）

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" | Select AppInit_DLLs,LoadAppInit_DLLs,RequireSignedAppInit_DLLs
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" | Select AppInit_DLLs,LoadAppInit_DLLs
```

- 可疑判据：AppInit_DLLs 非空且指向非微软 DLL；LoadAppInit_DLLs 被设为 1（启用）。加载 user32.dll 的 GUI 进程都会带上它。

## 0x2D Application Shimming（自定义兼容性数据库后门）

```powershell
# 已安装的自定义 SDB（sdbinst 装的 shim 数据库）
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" -Recurse | Select PSPath
Get-ChildItem "C:\Windows\AppPatch\Custom","C:\Windows\AppPatch\Custom\Custom64" -Force -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" -ErrorAction SilentlyContinue
```

- 可疑判据：Custom 目录下出现陌生 .sdb（尤其近期）；InstalledSDB 有非微软条目；Layers 键里给可疑 exe 设了 shim（Relaunch/DisableNX 等补丁类型可改行为）。Shim 可执行任意补丁逻辑——隐蔽持久化。

## 0x2E IFEO Debugger 注入（0x2A 的通用面）

```powershell
# 全量列带 Debugger/GlobalFlag 的 IFEO 项（不只辅助功能）
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath; if ($p.Debugger -or $p.GlobalFlag) { [pscustomobject]@{Image=$_.PSChildName; Debugger=$p.Debugger; GlobalFlag=$p.GlobalFlag} }
}
```

- 可疑判据：任意系统进程/安全软件进程带 Debugger 键（安全工具被劫持=瘫痪防守）；GlobalFlag+SilentProcessExit 组合（FlightingMonitor 静默执行）。

## 0x2F COM 劫持（InprocServer32 重定向）

```powershell
# HKCU 下出现本应在 HKLM 的 CLSID = 经典劫持（HKCU 优先于 HKLM 加载）
Get-ChildItem "HKCU:\Software\Classes\CLSID" -Recurse -ErrorAction SilentlyContinue |
  Where-Object {$_.PSChildName -eq 'InprocServer32'} | ForEach-Object { Get-ItemProperty $_.PSPath } |
  Select '(default)' | Where-Object {$_.'(default)' -notmatch 'system32|Windows'}
# 应用扩展点：搜索对用户可写路径 DLL 的引用
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" -Recurse -ErrorAction SilentlyContinue |
  Where-Object {$_.PSChildName -eq 'InprocServer32'} | ForEach-Object { Get-ItemProperty $_.PSPath } |
  Where-Object {$_.'(default)' -match 'AppData|Temp|Public|ProgramData'} | Select '(default)'
```

- 可疑判据：HKCU\Software\Classes\CLSID 里出现带可执行 DLL 的项；HKLM CLSID 的 InprocServer32 指向用户可写目录；对应 DLL 无签名/近期落盘。触发面=资源管理器（Shell 扩展）等常驻进程。

## 0x30 Password Filter DLL（凭据窃听持久化）

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select "Notification Packages"
```

- 可疑判据：Notification Packages 列表除 `scecli`（默认）外多出陌生 DLL 名；对应 DLL 在 System32 下、无签名、近期落盘。任何人（含管理员）改密码时 LSA 会加载该 DLL 并收到明文新密码——凭据收割后门，高危。

## 0x31 Network Provider 持久化

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*\NetworkProvider" -ErrorAction SilentlyContinue |
  Select PSPath,ProviderPath
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ServiceControlManagerExtension" -ErrorAction SilentlyContinue
```

- 可疑判据：ProviderPath 指向非系统 DLL；ProviderOrder 里出现陌生项。登录会话建立时加载——比 Notification Packages 更早的执行点。

## 0x32 Winsock 名称空间提供者（NSP）劫持

```powershell
# 名称空间目录（每个目录项是一个 DLL，解析名字时加载）
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries" -Recurse |
  ForEach-Object { Get-ItemProperty $_.PSPath } | Select LibraryPath
```

- 可疑判据：LibraryPath 出现非 `%SystemRoot%\system32\` 前缀的 DLL（NLA/nsi 等默认都在系统目录）；DLL 无签名/近期。网络活动即触发加载，隐蔽性好。

## 0x33 Windows Defender 日志与防篡改排查

```powershell
# Defender 自身事件（Microsoft-Windows-Windows Defender/Operational）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=5001,1116,1117,5007} -MaxEvents 200
#   5001=实时保护被关闭  1116/1117=检测到恶意软件(含路径与名称)  5007=配置变更
# 排除项（攻击者常给自己加免杀排除）
Get-MpPreference | Select ExclusionPath,ExclusionExtension,ExclusionProcess
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions" -Recurse -Force -ErrorAction SilentlyContinue
# 引擎日志（检出被清除的记录细节）
# C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log
```

- 可疑判据：5001（关实时保护）/5007（关 tamper protection、加排除）时间在失陷窗内=攻击者第一步动作；1116/1117 直接给出恶意文件路径与检出名（可作家族线索）；排除项里出现攻击者后续使用的目录/扩展名。Defender 被卸载/服务被停（WinDefend 服务状态）也记入时间线。

## 0x34 防火墙配置与放行痕迹

```powershell
netsh advfirewall show allprofiles state
# 全量规则（重点：新增的 ALLOW 入站）
netsh advfirewall firewall show rule name=all dir=in status=enabled | Select-String -Context 0,6 "Rule Name|Action|Program|LocalPort|RemoteIP"
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
  Where-Object {$_.CreationTime -and $_.CreationTime -gt (Get-Date).AddDays(-30)} |
  Select DisplayName,CreationTime | Sort CreationTime
# 防火墙日志（需预先开启）：C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

- 可疑判据：失陷窗内新增的入站 ALLOW 规则（尤其放行远控端口/程序级放行 Temp 下的 exe）；DROP 规则被关闭；pfirewall.log 里失陷窗的外连记录（回连 C2）。防火墙规则是攻击者"开门"动作的直接证据，规则创建时间可入时间线。

## 0x35 PATHEXT 劫持

```powershell
$env:PATHEXT
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" | Select PATHEXT
Get-ItemProperty "HKCU:\Environment" | Select PATHEXT
```

- 可疑判据：PATHEXT 出现非默认顺序/陌生扩展（默认 `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC`）；被插入靠前的高优扩展。配合同名无后缀文件执行（`evil` 命中 `evil.bat`）实现劫持。

## 0x36 Windows Sandbox 残留与空格路径截断

```powershell
# Windows Sandbox 配置文件（.wsb 可配置共享目录/启动命令，投毒载体）
Get-ChildItem "$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop" -Filter *.wsb -Recurse -ErrorAction SilentlyContinue
Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM | Select State
# 无引号服务路径截断劫持：binPath 含空格且未加引号 → 上级目录放同名 exe 可被抢先执行
Get-CimInstance Win32_Service | Where-Object {($_.PathName -notmatch '^"') -and ($_.PathName -match ' ')} |
  Select Name,PathName,StartMode
```

- 可疑判据：陌生 .wsb 文件（Sandbox 启动即执行其中的 LogonCommand）；无引号服务路径的截断位（如 `C:\Program Files\svc\svc.exe` 的 `C:\Program.exe`、`C:\Program Files\svc.exe`）存在可写落点文件。

---

## 来源

- https://book.noptrace.com/
- Zimmerman Tools（AmcacheParser/AppCompatCacheParser/PECmd/JLECmd/LECmd）：https://ericzimmerman.github.io/
- Sysinternals（Autoruns/Process Explorer/streams）：https://learn.microsoft.com/en-us/sysinternals/
- MITRE ATT&CK Persistence 矩阵：https://attack.mitre.org/
- LOLBAS（合法二进制滥用清单）：https://lolbas-project.github.io/
