# 非持续性事件与隧道事件排查（Windows 侧）

> 正文自写原创，命令与判据自写，来源链接见文末。
> 两类合册：**非持续性事件**＝恶意程序不落盘/不持久化（内存马、无文件攻击、一次执行）；**隧道事件**＝失陷后在边界上开隐蔽通道。共同点是「常规持久化排查扑空」——靠执行痕迹、网络痕迹与内存取证闭环。

## 1. 非持续性事件：排查主线

```
确认一次性执行痕迹（哪来的/跑了什么）→ 内存取证（活证据）→ 网络痕迹（去了哪）→ 布控等待复现 → 通用面收尾
```

### 1.1 一次性执行痕迹

```powershell
# Prefetch：执行过即留痕（无文件也会记父进程与引用 DLL）
Get-ChildItem C:\Windows\Prefetch -Filter *.pf | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Sort LastWriteTime
# Amcache 首次执行（含 SHA1，就算文件已删记录仍在）
# 用 Zimmerman AmcacheParser 解析 Amcache.hve（工具缺则 python3 读注册表 hive：regipy）
# 无文件执行链：PowerShell 历史与脚本块日志（4104，需启用）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 500 -ErrorAction SilentlyContinue
# 已删文件痕迹：USN journal（$Extend/$UsnJrnl:$J）
fsutil usn readjournal C: csv | Select-String "malware|\.ps1|\.tmp"   # 按失陷窗与关键词
```

- 可疑判据：失陷窗内 Prefetch 出现陌生解释器/工具的 .pf；4104 脚本块含 `-enc` 下载执行；USN 记录「创建→删除」间隔极短的文件（无文件攻击落地临时文件即删）。

### 1.2 内存取证（无文件攻击唯一活证据）

- 优先级最高：先 dump 后处置（`DumpIt`/`FTK Imager`/`Comae DumpIt`；完整流程见 `../methodology/incident-flow.md` 固定证据节）。
- Volatility 3 检查面：`windows.pstree`（隐藏进程/异常父子）、`windows.netscan`（外连）、`windows.malfind`（注入/无文件 payload 页）、`windows.cmdline`（命令行还原）。
- 判据：malfind 命中 RX 权限可执行页且无磁盘文件对应=无文件攻击定性证据；netscan 外连与 DNS 缓存互证。

### 1.3 布控等待复现（非持续性事件的收口手段）

- DNS 布控：改 hosts 把已知 IOC 域名指向受控监听 IP，或在本机/内网 DNS 开解析日志（`Get-DnsServerQueryResolutionStatistics` 或 DNS 审计日志），恶意程序再次执行时留下来源。
- 文件布控：在恶意程序探测的路径放诱饵（hash 采集目录变更）。
- Sysmon 常驻：装 Sysmon（网络+进程创建+镜像加载），等复现期全程留痕——比事后日志更完整。

## 2. 隧道事件：排查主线

```
异常监听/外连定位 → 隧道进程与组件（frp/nps/reGeorg/iox/CS Beacon）→ 流量特征判型 → 通道关闭与加固
```

### 2.1 异常监听与外连

```powershell
# 监听端口全景（隧道进程必开本地口或保持长连）
Get-NetTCPConnection -State Listen | Where-Object {$_.LocalAddress -notin '0.0.0.0','::'} | Select LocalAddress,LocalPort,OwningProcess
Get-NetTCPConnection -State Established | Group-Object RemoteAddress | Sort Count -Descending | Select -First 15 Count,Name
# 对应进程与路径（重点：非系统目录的陌生进程）
Get-Process -Id (Get-NetTCPConnection -State Listen).OwningProcess -ErrorAction SilentlyContinue | Select Id,Name,Path
```

### 2.2 常见隧道组件指纹（Windows 侧）

| 隧道型 | 进程/组件特征 | 落点与配置 |
|---|---|---|
| frp | `frpc.exe`/改名 exe + `frpc.ini/toml`（server_addr/token） | Temp/Public/ProgramData；服务方式常驻 |
| nps/npc | `npc.exe -server=… -vkey=…` 命令行即配置 | 命令行留痕（4688） |
| Web 隧道（reGeorg/suo5/Neo-reGeorg） | IIS/Tomcat 目录下 tunnel.jsp/aspx/ashx；连接特征为 POST 长轮询 | web 根目录按时间窗扫；见 `../webshell/webshell-detection.md` |
| CS DNS Beacon | `rundll32.exe` 无参数常驻；DNS 查询高频+随机子域长度异常 | malleable 配置；DNS 服务器日志为核心证据 |
| ICMP 隧道 | ping.exe 常驻或驱动级；ICMP payload 异常大 | 防火墙 ICMP 日志/packet 计数 |
| iox/其它 TCP 中转 | 陌生进程 `--proxy/--forward` 参数 | 4688 命令行 |

```powershell
# rundll32 无参常驻（CS DNS Beacon 形态）
Get-CimInstance Win32_Process -Filter "Name='rundll32.exe'" | Select ProcessId,CommandLine,ExecutablePath
# 服务方式常驻的隧道（frpc 常见）
Get-CimInstance Win32_Service | Where-Object {$_.PathName -match 'frp|npc|tunnel|iox'} | Select Name,PathName,State
# TAP/虚拟网卡安装痕迹（部分隧道组件装驱动）
Get-NetAdapter -IncludeHidden | Where-Object {$_.InterfaceDescription -match 'TAP|TUN'} | Select Name,InterfaceDescription,DriverDate
```

### 2.3 流量特征判型（与防火墙/DNS 日志互证）

- DNS 隧道：单一域名子域长度均值 >30、查询频率异常（每分钟数十条 TXT/A）、NXDOMAIN 占比高——DNS 服务器日志与 `ipconfig /displaydns` 缓存交叉。
- 长连接心跳：固定间隔小包外连（Beacon 默认 30-60s jitter）——防火墙日志按远端 IP 聚合看间隔分布。
- 判型后：C2 域名/IP 全部进 IOC 清单，供 IOC 扩线与善后定损。

## 3. 收尾（两类通用）

- 非持续事件定性证据=「执行痕迹+内存证据」二选一闭环，仅有单源一律「疑似」；布控期内复现可升 confirmed。
- 隧道关闭在处置清单（用户确认后）：kill 进程/删服务/清 web 隧道文件/封 IOC；加固=出口白名单+DNS 日志常开+Sysmon 常驻。
- 时间线登记：非持续事件从「首次执行痕迹」起链；隧道从「通道建立」（进程创建/服务安装/web 文件落盘时间）起链。

## 来源

- https://book.noptrace.com/
- frp（github.com/fatedier/frp）、nps（github.com/ehang-io/nps）、suo5、Neo-reGeOrg——组件识别参考
- CobaltStrike DNS Beacon 流量特征：MITRE T1071.004（DNS）
