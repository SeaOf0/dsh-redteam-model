# Windows 应急响应七步闭环总方法论

> 
> 适用对象：Windows 主机侧失陷后的现场处置；本方法论为「事件无关」的通用流，具体事件（挖矿/远控/勒索/爆破/钓鱼/webshell）的专项细节见本库 malware/、webshell/、persistence/ 各篇。
> 铁律（与预设 persona 一致）：先留证后处置；处置只出清单与建议，用户确认后执行；删除类操作严禁执行只提示。

## 0. 流程总览

```
第 1 步 固定证据 ──► 第 2 步 确定 IOC ──► 第 3 步 定位样本 ──► 第 4 步 处理进程
    (快照/磁盘/内存/针对性)   (哈希/域名/IP/端口)   (定位落盘样本)     (采样→分析→查杀)
                                                                        │
第 7 步 体检 ◄── 第 6 步 善后 ◄── 第 5 步 删除文件 ◄──────────────────────┘
  (0x00-0x22+ 清单)  (定损+针对性)   (查占用→查注册表→删除)
```

每步产出都要写入证据登记（evidence-index），登记字段：时间戳、动作、命令原文、输出摘要、哈希、涉及文件路径。无证据不下结论，单条证据不下结论（多源互证）。

---

## 第 1 步：固定证据（证据保全）

处置前先把现场固化为可复查的只读快照，处置动作本身不得破坏证据。四类取证做法：

### 1.1 系统快照（最低成本，先做）

采集当前系统的「活」状态，防止进程退出/重启后证据消失：

```bat
:: 系统基本信息 + 时间（校准时间戳基准）
systeminfo > evidence\01-systeminfo.txt
echo %DATE% %TIME% > evidence\00-clock.txt
hostname >> evidence\00-clock.txt
whoami >> evidence\00-clock.txt

:: 进程 + 网络快照（含 PID 与父子关系，用于定位样本）
tasklist /v /fo csv > evidence\01-process.csv
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate /format:csv > evidence\01-process-wmic.csv
netstat -ano > evidence\01-netstat.txt
netstat -anob > evidence\01-netstat-b.txt

:: 服务 + 计划任务 + 自启动项快照
sc query state= all > evidence\01-services.txt
schtasks /query /fo csv /v > evidence\01-schtasks.csv
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" evidence\01-run-hklm.reg /y
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" evidence\01-run-hkcu.reg /y
```

PowerShell 等价写法：

```powershell
Get-ComputerInfo | Out-File evidence\01-systeminfo.txt
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | Export-Csv evidence\01-process.csv
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv evidence\01-netstat.csv
Get-Service | Export-Csv evidence\01-services.csv
Get-ScheduledTask | Export-Csv evidence\01-schtasks.csv
```

### 1.2 磁盘取证（离线镜像，条件允许时做）

优先于处置前对关键盘做镜像或至少对关键目录做哈希基线：

```bat
:: 哈希基线（对疑似样本/关键目录，用 certutil 或 PowerShell Get-FileHash）
certutil -hashfile C:\Windows\Temp\suspicious.exe SHA256
Get-FileHash -Algorithm SHA256 C:\Windows\Temp\suspicious.exe

:: 取证级镜像（现场用 FTK Imager / dd / VHD 创建），通用思路：
:: 1) 挂载只读（diskpart: attributes disk set readonly）
:: 2) 逐扇区镜像到外置介质（FTK Imager 图形界面 "Create Disk Image" → E01/RAW）
:: 3) 记录镜像哈希（SHA256）作为证据链锚点
```

> 现场无外置介质时，退而求其次：把 C:\Windows\System32\winevt\Logs、C:\Windows\System32\config（含 SAM/SYSTEM/SOFTWARE/NTUSER.DAT）、用户目录、网站根目录打包留证。证据包用 `7z a -p` 加密并记录哈希。

### 1.3 内存取证（可疑活跃攻击/无文件恶意软件必做）

无文件攻击（PowerShell 内存马、注入型木马）在磁盘上查不到，必须抓内存：

- 工具：DumpIt（一键）、Magnet RAM Capture、WinPmem（开源）、FTK Imager（GUI 内 "Memory Capture"）。
- 抓取后即得 `.raw`/`.mem` 镜像，用 Volatility 3 / Volatility Workbench 分析：`python3 vol.py -f mem.raw windows.psscan`、`windows.netscan`、`windows.cmdline`、`windows.dlllist`、`windows.malfind`（检测注入的 VAD）。
- 抓内存动作会轻微扰动目标（写一个抓取进程），登记在案即可，不要反复抓。

### 1.4 针对性取证（按事件类型定向采集）

根据告警来源定向采集，避免无差别全盘采集：

| 事件线索 | 定向采集 |
|---|---|
| 疑似 webshell | IIS 日志、网站目录 MFT、应用进程模块 |
| 疑似挖矿/远控 | 进程树、网络连接、DNS 缓存、计划任务/服务 |
| 疑似爆破失陷 | Security 日志 4624/4625、登录源 IP、新建账户/组 |
| 疑似勒索 | MFT 时间戳、勒索信、VSS 状态、加密扩展名清单 |

---

## 第 2 步：确定 IOC

把告警/线索转成可检索的 IOC 四元组，作为后续所有排查的检索条件：

| IOC 类型 | 提取命令 | 说明 |
|---|---|---|
| 文件哈希 | `Get-FileHash <样本> -Algorithm MD5,SHA1,SHA256` | MD5/SHA1/SHA256 三值都记，不同平台口径不同 |
| 域名 | `ipconfig /displaydns`、`Get-DnsClientCache` | DNS 缓存里的可疑解析记录 |
| IP | `netstat -ano` + 威胁情报比对 | 出站连接的远端 IP，排除内网网段 |
| 端口 | `netstat -ano` | 监听端口/出站目的端口 |

IOC 富化（联网核查）：哈希投 VirusTotal/微步/奇安信，域名/IP 投威胁情报平台查历史恶意性。**富化结果只是参考**，最终定性靠本机证据（文件行为+时间线+多源互证），不能只凭 VT 命中数下结论。

IOC 落地为可执行检索：

```powershell
# 按哈希在全盘找同名/同哈希文件
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Get-FileHash -Algorithm MD5 | Where-Object Hash -eq '<MD5>'
# 按 IP 找建立连接的进程
Get-NetTCPConnection | Where-Object RemoteAddress -eq '<IP>' | Select OwningProcess
```

---

## 第 3 步：定位样本

把 IOC 落到的进程定位到磁盘上的样本文件：

### 3.1 按进程定位可执行文件

```bat
:: 按 PID 找进程镜像路径（注意区分"路径是否可疑"：System32 下的正常系统进程 vs 临时目录/用户目录）
wmic process where "ProcessId=<PID>" get ExecutablePath,CommandLine
```

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" | Select ExecutablePath,CommandLine,ParentProcessId
```

### 3.2 定位后固定样本

```bat
:: 复制样本到隔离区（只读，不执行），并算哈希
copy <样本路径> evidence\sample_<PID>.bin
certutil -hashfile evidence\sample_<PID>.bin SHA256
```

> 判据：路径落在 `C:\Windows\Temp\`、`C:\Users\<用户>\AppData\Local\Temp\`、`C:\ProgramData\`、回收站、`C:\PerfLogs\` 等非常规位置，且进程名伪装成 `svchost.exe`/`explorer.exe` 但路径不是 System32 的，优先判疑。

---

## 第 4 步：处理异常进程

五步：**采样 → 分析 → 找病毒报告 → 查杀（暂停/杀进程/杀进程树/杀线程）**。

### 4.1 采样（处置前留样本）

对异常进程抓内存段/导出可执行文件：

- 导出进程 PE：Process Explorer 右键进程 → "Create Dump" → "Create Full Dump"；或 `procdump -ma <PID> evidence\dump_<PID>.dmp`。
- 导出镜像文件：Process Explorer → "Properties" → "Image" 面板可看到镜像路径，直接 copy 该文件。

### 4.2 分析（本机初判）

```bat
:: 看进程链（父进程是谁，是否被 System 直接拉起）
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine /format:list
:: 看网络（是否主动外连）
netstat -anob | findstr <PID>
:: 看加载模块（是否注入了可疑 DLL）
tasklist /m /fi "PID eq <PID>"
```

### 4.3 找病毒报告（富化）

样本哈希投多引擎（VirusTotal/微步），找同家族公开分析报告，确定查杀方式与残留清理要点。远程分析是首选（避免在本机二次感染），离线时用本库 tools/ 的 YARA/Loki 本地扫。

### 4.4 查杀（先暂停后杀，逐级递进）

> 以下为**处置建议**，须用户确认后执行；本模式默认只输出命令不代为执行。

```bat
:: 1) 暂停进程（保留现场可再取证）
:: 图形：Process Explorer 右键 → Suspend；命令行：
:: 使用 pssuspend -n <PID>（Sysinternals）

:: 2) 杀单进程
taskkill /PID <PID> /F

:: 3) 杀进程树（连带子进程，先确认子进程清单再杀）
tasklist /fi "ParentImageName eq <父进程名>"   :: 或 wmic 查 ParentProcessId
taskkill /PID <PID> /T /F

:: 4) 杀线程（针对注入到正常进程的恶意线程，不杀宿主进程）
:: Process Explorer 找到目标进程 → Threads 面板 → 定位可疑线程起始地址 → Suspend/Kill
```

> 注意：如果异常进程是 `svchost.exe`/`services.exe` 等关键系统进程宿主，杀进程会连带系统功能，优先用「杀线程/卸载模块」而非杀进程；确认后再动。

---

## 第 5 步：删除恶意文件

三步：**查占用 → 查注册表 → 删除**。

### 5.1 查占用（谁锁着文件，删不掉先找占用者）

```bat
:: findstr 不直接给占用者，用 handle（Sysinternals）或图形工具
handle.exe <文件路径>
:: 或 PowerShell（需管理员）
openfiles /query
```

### 5.2 查注册表（清理关联的自启动/服务/计划任务，否则文件删了又复活）

先找到样本在注册表里的持久化痕迹，一并列入清理清单（详见 persistence/persistence-points.md）：

```bat
:: 服务对应的 ImagePath
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<服务名>" /v ImagePath
:: Run 键
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
:: 计划任务
schtasks /query /tn "<任务名>" /xml
```

### 5.3 删除（只出清单，用户执行）

> 删除类操作严禁执行，只输出删除清单：文件路径 + 关联注册表键 + 关联服务/任务名 + 删除命令 + 删除前备份步骤。

```bat
:: 删除前备份（归档留证）
mkdir evidence\deleted-backup
copy <恶意文件> evidence\deleted-backup\

:: 删除命令（用户确认后执行）
:: 先解除占用：handle -c <handle号> -p <占用进程PID>；或重启进安全模式再删
del /f /q <恶意文件路径>
:: 删除关联服务
sc delete <服务名>
:: 删除关联计划任务
schtasks /delete /tn "<任务名>" /f
:: 删除关联注册表项
reg delete "HKLM\...\Run" /v <值名> /f
```

---

## 第 6 步：善后阶段（定损 + 针对性处理）

### 6.1 定损（评估影响范围）

- 样本行为分析结论：它干了什么（挖矿/窃密/勒索/后门/横向）。
- 数据是否外泄：外连目标 IP/域名、上传流量方向、被访问的敏感文件清单。
- 影响主机范围：是否从本机横向到内网其它主机（登录源、共享、服务创建）。
- 账号影响：是否新建账户/加入管理员组/导出凭据。

### 6.2 针对性处理

按事件类型做定向排查收尾：

- 爆破失陷 → 改口令、禁用异常账户、查持久化三件套（账户/组/计划任务/服务）。
- 勒索 → 隔离加密器、恢复 VSS/备份、评估是否支付（不建议支付）。
- 远控/后门 → 全量清持久化点，防二次回连。
- webshell → 清 shell 文件 + 查内存马 + 查 IIS/中间件配置篡改。

---

## 第 7 步：体检（常规安全检查）

处置完成后跑一遍 0x00–0x22+ 主机体检清单，确认无残留持久化与隐藏后门，再宣告闭环。完整清单见 methodology/security-checklist.md。

体检通过判据：

- 无未知自启动项/服务/计划任务/账户。
- 关键日志（Security/System/PowerShell）无新的可疑 Event ID。
- 网络无异常外连、进程无异常子进程。
- 敏感位置（临时目录/启动目录/WMI 订阅）无新增可疑物。

---

## 证据登记要求（贯穿七步）

每一步都把动作登记进 evidence-index.md，字段：

| 字段 | 说明 |
|---|---|
| 时间 | 动作执行时间（与目标机时钟对齐，记录偏移） |
| 步骤 | 七步中的第几步 |
| 动作 | 取证/查询/处置动作名 |
| 命令 | 完整命令原文 |
| 输出摘要 | 关键结果（命中项/哈希/IP/Event ID） |
| 证据文件 | 输出落盘的相对路径 + 哈希 |

报告阶段把 evidence-index 里的编号回填到攻击链时间线表的「证据」列，保证时间线每个节点可溯源。

## 来源

- https://book.noptrace.com/
- Sysinternals（procdump/handle/pssuspend/Process Explorer）：https://learn.microsoft.com/en-us/sysinternals/
- Volatility 3（内存分析）：https://github.com/volatilityfoundation/volatility3
