# BadUSB 投毒事件排查

> 正文自写原创，命令与判据自写，来源链接见文末。
> 适用：Rubber Ducky/Bash Bunny/自制 HID 设备等「模拟键盘输入」型投毒。特征是**无人交互的密集命令执行**——设备一插即执行，用户往往不在场。

## 1. 排查主线

```
USB 接入历史还原 → 接入时间窗内的执行链 → 落地样本与持久化 → 通用排查面收尾
```

## 2. USB 接入历史（锚点）

```powershell
# USB 存储设备接入史（设备名/序列号/时间）
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -Recurse -ErrorAction SilentlyContinue | Select PSPath
# 驱动安装日志（含精确接入时间）：C:\Windows\INF\setupapi.dev.log
Select-String -Path C:\Windows\INF\setupapi.dev.log -Pattern "Device Install.*USB" | Select -Last 30
# 设备安装事件（Microsoft-Windows-DriverFrameworks-UserMode/Operational：20001/20003）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational';Id=20001,20003} -MaxEvents 100 -ErrorAction SilentlyContinue | Select TimeCreated,Message
```

- 可疑判据：接入时间在非工作时段/用户声明离开的时段；设备名陌生（"USB Input Device" 键盘类大量新条目、HID 设备而非存储）；同一序列号多次接入（定向投毒）。

## 3. 接入时间窗内的执行链

```powershell
# 以接入时间为锚点 ±5 分钟，看 4688/Sysmon 1 的密集命令
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=(Get-Date "2026-01-01 03:00");EndTime=(Get-Date "2026-01-01 03:05")} |
  Select TimeCreated,Message
```

- 可疑判据（HID 模拟键盘特征）：极短时间（数秒~几十秒）内串行出现 `powershell -windowstyle hidden -enc …`、`curl/wget 下载`、`reg add`、`net user add` 等序列；无鼠标/窗口交互前兆（对比 RDP/交互会话日志）；命令序列典型 Ducky 脚本形态（改注册表隐藏、下载 payload、清痕迹）。
- 电源状态佐证：屏幕解锁/锁屏事件（4800/4801）在接入时刻附近，排除「无人可操作」与键盘注入的矛盾。

## 4. 落地样本与持久化

- Ducky/Bash Bunny 常见落点：`%TEMP%`、`C:\Users\Public\Downloads`（Bash Bunny 盘符挂载拷贝）、`Startup` 目录直接放 lnk/exe。
- 排查：接入窗内新落盘文件（`Get-ChildItem` 时间窗过滤全盘高危目录）+ 启动目录/Run 键/计划任务在接入窗内的新增项（按 `../persistence/persistence-points.md` 全表过）。

## 5. 通用收尾

- 后续链发现走恶意程序/持久化/日志通用面；时间线以「USB 接入时刻」为第一锚点，串联执行链各节点。
- 证据登记：setupapi.dev.log 摘录、事件 20001/2003 原文、执行链命令行、落地样本哈希。

## 来源

- https://book.noptrace.com/
- USB 设备取证（USBForensics / USB Detective 思路）：https://github.com/ralphje/USBDriveLog（Sysinternals USBDriveLog 亦可快速枚举）
