---
name: ir-forensics-windows
description: >
  Windows 系统取证完整手册：覆盖 Windows 事件日志提取与分析、注册表工件取证、
  Prefetch/Amcache/Shimcache 执行痕迹、LNK/Jump List 用户活动、ShellBags 文件夹浏览记录、
  Eric Zimmerman 工具集使用、浏览器取证（Hindsight）、Outlook PST 邮件取证、
  Splunk 日志分析查询、证据收集自动化脚本、攻击时间线重建。
  攻防合一：取证调查方法 + Splunk 检测规则 + 证据保全流程。
domain: cybersecurity
subdomain: digital-forensics
tags: [windows-forensics, event-logs, registry-forensics, prefetch, amcache, shellbags,
  lnk-files, eric-zimmerman-tools, browser-forensics, outlook-pst, splunk, timeline]
version: 2.0.0
---

# Windows 系统取证 — 完整手册

## 适用场景

**适用于:** Windows 工作站/服务器入侵调查、用户活动重建、恶意软件执行痕迹追踪、
浏览器历史取证、邮件证据提取、事件日志深度分析、攻击时间线构建。

**不适用于:** 磁盘镜像获取（见 ir-forensics-disk）、Linux 取证（见 ir-forensics-linux）、
内存取证（见 malware-analysis-memory）、网络流量分析（见 network-traffic-analysis）。

**前置条件:**
- 受感染 Windows 系统的管理员权限
- Eric Zimmerman 工具集（最新版）
- Plaso/log2timeline 用于时间线构建
- Splunk 或 ELK 用于日志分析
- 可信的取证 USB 或远程取证工具（Velociraptor、GRR）

---

## Part A：取证方法论

### 1. 初始响应 — 易失性与非易失性证据收集

#### 1.1 易失性证据收集脚本

```powershell
# ir_volatile_collect.ps1 — Windows 易失性证据收集
$OUTDIR = "C:\ir_evidence\volatile_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $OUTDIR -Force | Out-Null

# 1. 系统时间
Get-Date -Format u > "$OUTDIR\system_time.txt"
w32tm /query /status >> "$OUTDIR\system_time.txt"

# 2. 运行进程
Get-Process | Select-Object Id, ParentId, Name, Path, StartTime, `
  @{N='Hash';E={if($_.Path){Get-FileHash $_.Path -Algorithm MD5 | Select -Exp Hash}}} `
  | Export-Csv "$OUTDIR\processes.csv" -NoTypeInformation

# 3. 网络连接
netstat -anob > "$OUTDIR\netstat_anob.txt"
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess `
  | Export-Csv "$OUTDIR\tcp_connections.csv" -NoTypeInformation

# 4. 已加载 DLL (可疑进程)
foreach ($proc in Get-Process | Where { $_.Path -and $_.Path -notlike "C:\Windows\*" }) {
    try {
        $proc.Modules | Select ModuleName, FileName, FileVersion `
          | Export-Csv "$OUTDIR\dlls_$($proc.Id)_$($proc.Name).csv" -NoTypeInformation
    } catch {}
}

# 5. ARP 缓存
arp -a > "$OUTDIR\arp.txt"
Get-NetNeighbor | Export-Csv "$OUTDIR\neighbors.csv" -NoTypeInformation

# 6. DNS 缓存
ipconfig /displaydns > "$OUTDIR\dns_cache.txt"
Get-DnsClientCache | Export-Csv "$OUTDIR\dns_cache.csv" -NoTypeInformation

# 7. 已建立会话
net session > "$OUTDIR\net_sessions.txt"
net use > "$OUTDIR\net_use.txt"
net share > "$OUTDIR\net_shares.txt"

# 8. 计划任务
schtasks /query /fo CSV /v > "$OUTDIR\scheduled_tasks.csv"

# 9. WMI 事件订阅
Get-WMIObject -Class __FilterToConsumerBinding -Namespace root\subscription `
  | Select * | Export-Csv "$OUTDIR\wmi_bindings.csv" -NoTypeInformation
Get-WMIObject -Class __EventFilter -Namespace root\subscription `
  | Select * | Export-Csv "$OUTDIR\wmi_filters.csv" -NoTypeInformation
Get-WMIObject -Class __EventConsumer -Namespace root\subscription `
  | Select * | Export-Csv "$OUTDIR\wmi_consumers.csv" -NoTypeInformation

# 10. 剪贴板
Get-Clipboard > "$OUTDIR\clipboard.txt" 2>$null

Write-Host "[+] 易失性证据已保存到 $OUTDIR"
```

#### 1.2 非易失性证据提取清单

| 工件 | 路径 | 用途 |
|------|------|------|
| 事件日志 | `C:\Windows\System32\winevt\Logs\*.evtx` | 系统活动记录 |
| Prefetch | `C:\Windows\Prefetch\*.pf` | 程序执行历史 |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | 程序执行+文件哈希 |
| Shimcache | `SYSTEM` 注册表 `ControlSet*\Control\Session Manager\AppCompatCache` | 程序执行痕迹 |
| ShellBags | `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags` | 文件夹浏览记录 |
| LNK 文件 | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | 文件打开记录 |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*` | 程序最近文件 |
| UserAssist | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*` | GUI 程序执行 |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | 网络使用统计 |
| BAM | `SYSTEM` 注册表 `ControlSet*\Services\bam\UserSettings\*` | 后台活动管理 |
| 注册表 | `NTUSER.DAT`, `SOFTWARE`, `SYSTEM`, `SAM`, `SECURITY` | 系统配置+用户活动 |
| 浏览器 | 各浏览器 profile 目录 | 浏览历史+下载记录 |
| Outlook PST | `%LOCALAPPDATA%\Microsoft\Outlook\*.pst` | 邮件取证 |

---

### 2. Windows 事件日志深度分析

#### 2.1 关键安全事件 ID 速查

| 事件 ID | 日志源 | 含义 | 取证价值 |
|---------|--------|------|----------|
| 4624 | Security | 登录成功 | 登录类型、来源 IP、用户 |
| 4625 | Security | 登录失败 | 暴力破解检测 |
| 4634 | Security | 注销 | 会话时长 |
| 4648 | Security | 显式凭据登录 | 横向移动指标 |
| 4672 | Security | 特权登录 | 管理员活动 |
| 4688 | Security | 进程创建 | 命令行参数（需启用） |
| 4697 | Security | 服务安装 | 持久化指标 |
| 4720 | Security | 创建用户 | 后门账户 |
| 4728/4732 | Security | 添加到管理员组 | 权限提升 |
| 4738 | Security | 用户属性修改 | 账户篡改 |
| 4768/4769 | Security | Kerberos TGT/ST 请求 | Kerberoasting 检测 |
| 4697 | Security | 服务安装 | 恶意服务 |
| 7045 | System | 新服务创建 | 恶意驱动/服务 |
| 7036 | System | 服务状态变更 | 服务启停时间线 |
| 1 | Sysmon | 进程创建 | 完整命令行+哈希 |
| 3 | Sysmon | 网络连接 | 网络活动映射 |
| 7 | Sysmon | DLL 加载 | DLL 注入检测 |
| 8 | Sysmon | CreateRemoteThread | 进程注入 |
| 10 | Sysmon | Process Access | 凭据读取 |
| 11 | Sysmon | 文件创建 | 落地文件检测 |
| 13 | Sysmon | 注册表值设置 | 注册表修改 |
| 23 | Sysmon | 文件删除 | 日志清除/勒索 |
| 255 | Sysmon | 错误 | Sysmon 被破坏指标 |
| 1102 | Security | 审计日志清除 | 反取证指标 |
| 104 | System | 事件日志清除 | 反取证指标 |

#### 2.2 事件日志提取方法

```powershell
# 方法 1: PowerShell 直接导出
Get-WinEvent -LogName 'Security' | Where { $_.Id -eq 4624 } |
  Select TimeCreated, Id,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}} |
  Export-Csv security_4624.csv -NoTypeInformation

# 方法 2: wevtutil 命令行
wevtutil epl Security C:\ir_evidence\Security.evtx
wevtutil epl System C:\ir_evidence\System.evtx
wevtutil epl Application C:\ir_evidence\Application.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\ir_evidence\Sysmon.evtx

# 方法 3: 批量提取所有安全相关日志
$logs = @('Security','System','Application',
  'Microsoft-Windows-Sysmon/Operational',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
  'Microsoft-Windows-Security-Auditing',
  'Microsoft-Windows-TaskScheduler/Operational',
  'Microsoft-Windows-WMI-Activity/Operational')
foreach ($log in $logs) {
    try { wevtutil epl $log "C:\ir_evidence\$($log -replace '/','_').evtx" }
    catch { Write-Warning "无法提取: $log" }
}

# 方法 4: 远程提取（Velociraptor）
# velociraptor --config client.config.yaml artifacts collect Windows.EventLogs.Evtx
```

#### 2.3 Splunk 检测查询

```splunk-spl
### 暴力破解检测 — 10 分钟内同一来源 5+ 次失败
index=wineventlog EventCode=4625
| bucket _time span=10m
| stats count as failures dc(TargetUserName) as unique_users by _time, src_ip, host
| where failures > 5
| sort -failures

### 横向移动 — Pass-the-Hash (LogonType=3 + NTLM)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| eval is_local=if(src_ip=="-" OR src_ip=="127.0.0.1" OR src_ip==host, "local", "remote")
| search is_local=remote
| table _time, host, TargetUserName, src_ip, LogonType

### 凭据转储 — Mimikatz 特征 (Sysmon EventID=10)
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| table _time, host, SourceImage, SourceProcessId, GrantedAccess

### 服务创建恶意指标
index=wineventlog (EventCode=7045 OR EventCode=4697)
| eval suspicious=if(match(ImagePath, "(cmd\.exe|powershell|\\\\127\.0|\\\\0\.0\.0|Temp|Public|\\\\\\\\)"), "HIGH", "LOW")
| table _time, host, ServiceName, ServiceFileName, ServiceType, suspicious

### 日志清除 — 反取证
index=wineventlog (EventCode=1102 OR EventCode=104)
| table _time, host, EventCode, User, Message

### 计划任务创建
index=wineventlog EventCode=4698
| table _time, host, TaskName, TaskContent

### RDP 登录
index=wineventlog EventCode=4624 LogonType=10
| table _time, host, TargetUserName, src_ip

### PowerShell 混淆检测
index=wineventlog EventCode=4104
| eval obfuscated=if(match(Message, "(-enc|-enco|frombase64|string|\\\\x|\\[Char\\]|Invoke-Expression|IEX|&\s*\()"), "YES", "NO")
| search obfuscated=YES
| table _time, host, ScriptBlockText
```

---

### 3. 注册表工件分析

#### 3.1 关键注册表取证路径

```
# 用户活动
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\
  ├── UserAssist\{GUID}\Count     ← GUI 程序执行计数+时间 (ROT13 编码)
  ├── RunMRU                      ← 运行对话框历史
  ├── ComDlg32\OpenSavePidlMRU   ← 文件打开/保存对话框
  ├── ComDlg32\LastVisitedPidlMRU← 最后访问目录
  └── TypedPaths                  ← 资源管理器地址栏输入

# 系统级
SOFTWARE\Microsoft\Windows\CurrentVersion\
  ├── Run                         ← 启动项(HKLM)
  ├── RunOnce                     ← 一次启动项
  └── Explorer\SharedTaskScheduler ← 任务调度持久化

SYSTEM\ControlSet001\Control\
  ├── Session Manager\AppCompatCache  ← Shimcache (程序执行)
  └── Services\bam\UserSettings\{SID} ← BAM (后台活动时间)

SYSTEM\ControlSet001\Enum\USBSTOR    ← USB 设备连接历史
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList  ← 网络连接历史
```

#### 3.2 Eric Zimmerman 工具集使用

```powershell
# --- Registry Explorer (注册表浏览) ---
# 加载离线注册表
RegistryExplorer.exe C:\ir_evidence\SOFTWARE
RegistryExplorer.exe C:\ir_evidence\NTUSER.DAT

# --- AppCompatCache Parser (Shimcache) ---
AppCompatCacheParser.exe --csv C:\ir_evidence\out -f C:\ir_evidence\SYSTEM
# 输出: 执行程序路径、大小、最后修改时间、Shimcache 标志位

# --- AmcacheParser ---
AmcacheParser.exe -f C:\ir_evidence\Amcache.hve --csv C:\ir_evidence\out
# 输出: SHA1 哈希、编译时间、链接时间、版本信息
# 关键: 可找到已删除程序的执行痕迹（通过哈希比对恶意软件）

# --- ShellBags Explorer ---
ShellBagsExplorer.exe -f C:\ir_evidence\NTUSER.DAT --csv C:\ir_evidence\out
# 输出: 浏览过的文件夹路径、最后访问时间、窗口位置
# 用途: 证明用户访问了特定目录（如攻击者的工具目录）

# --- LECmd (LNK 文件解析) ---
LECmd.exe -d "C:\ir_evidence\Recent" --csv C:\ir_evidence\out
# 输出: 目标路径、创建/修改/访问时间、机器名、卷序列号

# --- JLECmd (Jump Lists 解析) ---
JLECmd.exe -d "C:\ir_evidence\AutomaticDestinations" --csv C:\ir_evidence\out
# 输出: 应用程序关联的最近文件列表

# --- PECmd (Prefetch 解析) ---
PECmd.exe -d "C:\ir_evidence\Prefetch" --csv C:\ir_evidence\out
# 输出: 可执行文件路径、运行次数、最后运行时间、引用的 DLL/文件

# --- SBECmd (SRUM 数据库) ---
SBECmd.exe -f "C:\ir_evidence\SRUDB.dat" --csv C:\ir_evidence\out
# 输出: 应用程序网络使用量（上传/下载字节），时间跨度 30-60 天

# --- EvtxECmd (EVTX 解析，替代 LogParser) ---
EvtxECmd.exe -f "C:\ir_evidence\Security.evtx" --csv C:\ir_evidence\out
# 输出: 结构化 CSV，字段已解析

# --- 批量全工件提取 ---
# 使用 KAPE (Kroll Artifact Parser and Extractor)
kape.exe --target SANS_Triage --dest C:\ir_evidence\kape_out
# 或自定义目标:
kape.exe --target !EZParser --dest C:\ir_evidence\out
```

---

### 4. Prefetch 分析

#### 4.1 Prefetch 基础

```
位置: C:\Windows\Prefetch\*.pf
格式: <EXE_NAME>-<HASH>.pf (如 NOTEPAD.EXE-A2BCD1EF.pf)
内容: 可执行文件路径、运行次数、8个最后运行时间、引用的文件/DLL、目录列表
限制: 默认最多保存 1024/128 个文件（Win10+）
注意: SSD 上可能禁用 Prefetch (EnablePrefetch=0)
```

#### 4.2 Python Prefetch 解析

```python
#!/usr/bin/env python3
"""prefetch_analyzer.py — 批量解析 Prefetch 文件，提取执行证据"""
import os
import csv
import argparse
from datetime import datetime, timezone

try:
    from libs.prefetch import Prefetch  # windowsprefetch-parser
except ImportError:
    # 备选: 使用 prefetch_parser
    try:
        import prefetch_parser as pp
    except ImportError:
        print("[!] 请安装: pip install prefetch-parser 或 windowsprefetch")
        raise

def parse_prefetch_dir(pf_dir, output_csv):
    results = []
    for f in os.listdir(pf_dir):
        if not f.lower().endswith('.pf'):
            continue
        path = os.path.join(pf_dir, f)
        try:
            pf = Prefetch(path)
            for run_time in pf.timestamps:
                results.append({
                    'executable': pf.executable,
                    'prefetch_file': f,
                    'hash': pf.hash,
                    'run_count': pf.run_count,
                    'run_time': run_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'volume_serial': pf.volume_serial,
                    'volume_path': pf.volume_device_path,
                    'referenced_files': len(pf.referenced_files),
                })
        except Exception as e:
            results.append({
                'executable': f,
                'prefetch_file': f,
                'hash': 'PARSE_ERROR',
                'run_count': 0,
                'run_time': str(e),
                'volume_serial': '',
                'volume_path': '',
                'referenced_files': 0,
            })

    # 按时间排序
    results.sort(key=lambda x: x.get('run_time', ''), reverse=True)

    with open(output_csv, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"[+] 解析完成: {len(results)} 条记录 -> {output_csv}")

    # 检测可疑执行
    suspicious_keywords = ['mimikatz', 'lazagne', 'procdump', 'pwdump',
                           'nc.exe', 'ncat', 'psexec', 'psexec64',
                           'curl', 'wget', 'certutil', 'bitsadmin',
                           'schtasks', 'wmic', 'dsquery', 'bloodhound']
    print("\n[!] 可疑程序执行:")
    for r in results:
        exe_lower = r['executable'].lower()
        if any(kw in exe_lower for kw in suspicious_keywords):
            print(f"  {r['run_time']} | {r['executable']} | 运行 {r['run_count']} 次")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Prefetch 取证分析')
    parser.add_argument('-d', '--dir', default=r'C:\Windows\Prefetch')
    parser.add_argument('-o', '--output', default='prefetch_analysis.csv')
    args = parser.parse_args()
    parse_prefetch_dir(args.dir, args.output)
```

#### 4.3 Prefetch 取证决策树

```
发现 Prefetch 文件
├── 程序名可疑？
│   ├── YES → 提取运行时间线 → 关联事件日志 4688 → 确认执行上下文
│   └── NO → 检查引用文件
│       ├── 引用了可疑 DLL？(如 mimilib.dll,恶意注入器)
│       │   └── YES → 该 DLL 可能被合法进程加载 → 进一步分析
│       └── 引用了可疑路径？(如 \Temp\, \Public\, \Users\*\AppData\)
│           └── YES → 可能是 LOLBin 滥用 → 检查命令行参数
├── 运行次数异常？
│   ├── 首次运行在攻击时间窗内 → 新增可疑
│   └── 运行次数突增 → 可能是脚本循环调用
└── 时间戳被篡改？
    └── 对比 $MFT 修改时间 vs Prefetch 时间 → 不一致=反取证
```

---

### 5. Amcache 与 Shimcache 分析

#### 5.1 Amcache.hve 关键表

```
Amcache.hve 结构:
├── Root\InventoryApplicationFile\    ← 程序执行记录
│   └── <SHA1>  → FileId(sha1), Size, Version, Publisher,
│                  LinkDate(编译时间), LastModified
├── Root\InventoryDevice\             ← USB/设备连接
└── Root\InventoryDriverBinary\       ← 驱动程序

取证价值:
- 即使 Prefetch 被清除，Amcache 仍保留程序执行记录
- SHA1 哈希可用于比对恶意软件样本
- 编译时间(LinkDate)可区分原始/修改二进制
```

#### 5.2 Amcache + Shimcache 时间线关联

```python
#!/usr/bin/env python3
"""amcache_shimcache_correlate.py — 关联 Amcache 和 Shimcache 构建执行时间线"""
import csv
from datetime import datetime

def load_shimcache(path):
    """Shimcache: 路径 + 最后修改时间 + 数据大小"""
    entries = []
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            entries.append({
                'path': row.get('Path', '').lower(),
                'modified': row.get('LastModified', ''),
                'size': row.get('DataSize', '0'),
                'flag': row.get('ShimFlags', ''),
                'source': 'shimcache',
            })
    return entries

def load_amcache(path):
    """Amcache: 路径 + SHA1 + 编译时间 + 版本"""
    entries = []
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            entries.append({
                'path': row.get('FullPath', row.get('Path', '')).lower(),
                'sha1': row.get('SHA1', row.get('FileId', '')),
                'link_date': row.get('LinkDate', ''),
                'modified': row.get('LastModified', ''),
                'size': row.get('Size', ''),
                'publisher': row.get('Publisher', ''),
                'version': row.get('Version', ''),
                'source': 'amcache',
            })
    return entries

def correlate(shimcache_path, amcache_path, output_path):
    shim = load_shimcache(shimcache_path)
    amc = load_amcache(amcache_path)

    # 建立 Amcache SHA1 索引
    sha1_index = {}
    for e in amc:
        if e['sha1']:
            sha1_index[e['path']] = e

    # 合并时间线
    timeline = []
    seen_paths = set()
    for e in shim:
        key = e['path']
        if key in sha1_index:
            a = sha1_index[key]
            timeline.append({
                'path': e['path'],
                'sha1': a['sha1'],
                'shimcache_modified': e['modified'],
                'amcache_modified': a['modified'],
                'link_date': a['link_date'],
                'publisher': a['publisher'],
                'source': 'BOTH',
            })
            seen_paths.add(key)
        else:
            timeline.append({
                'path': e['path'],
                'sha1': '',
                'shimcache_modified': e['modified'],
                'amcache_modified': '',
                'link_date': '',
                'publisher': '',
                'source': 'SHIMCACHE_ONLY',
            })
            seen_paths.add(key)

    for e in amc:
        if e['path'] not in seen_paths:
            timeline.append({
                'path': e['path'],
                'sha1': e['sha1'],
                'shimcache_modified': '',
                'amcache_modified': e['modified'],
                'link_date': e['link_date'],
                'publisher': e['publisher'],
                'source': 'AMCACHE_ONLY',
            })

    # 排序输出
    timeline.sort(key=lambda x: x.get('shimcache_modified') or x.get('amcache_modified') or '', reverse=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=timeline[0].keys())
        writer.writeheader()
        writer.writerows(timeline)

    print(f"[+] 关联完成: {len(timeline)} 条记录")
    both = sum(1 for t in timeline if t['source'] == 'BOTH')
    print(f"    双源确认: {both} | 仅 Shimcache: {sum(1 for t in timeline if t['source']=='SHIMCACHE_ONLY')} | 仅 Amcache: {sum(1 for t in timeline if t['source']=='AMCACHE_ONLY')}")

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-s', '--shimcache', required=True)
    p.add_argument('-a', '--amcache', required=True)
    p.add_argument('-o', '--output', default='execution_timeline.csv')
    correlate(p.parse_args().shimcache, p.parse_args().amcache, p.parse_args().output)
```

---

### 6. LNK 文件与 Jump List 分析

#### 6.1 LNK 文件取证值

```
位置:
- %APPDATA%\Microsoft\Windows\Recent\*.lnk         ← 用户最近打开文件
- C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
- C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\

LNK 文件包含:
- 目标文件路径 (原始路径 + 相对路径)
- 创建/修改/访问时间 (目标文件的 MAC 时间)
- 目标文件大小
- 卷序列号 + 卷标签
- 机器名
- 网络共享路径 (如 \\server\share\file)
- 命令行参数
- 图标位置
- 16字节 TrackerDataBlock (机器ID + 安全ID)
```

#### 6.2 自动化 LNK + Jump List 解析

```powershell
# 使用 LECmd 批量解析
LECmd.exe -d "C:\ir_evidence\Recent" --csv C:\ir_evidence\out --dl all

# 使用 JLEcmd 解析 Jump Lists
JLECmd.exe -d "C:\ir_evidence\AutomaticDestinations" --csv C:\ir_evidence\out

# 快速搜索 — 找到用户访问过的可疑文件
$lnkData = Import-Csv "C:\ir_evidence\out\LECmd_*.csv"
$lnkData | Where {
    $_.TargetFilePath -match '\\(Temp|Public|AppData|Downloads|tmp)\\' -or
    $_.TargetFilePath -match '\.(exe|bat|ps1|vbs|dll|py)$'
} | Select TargetFilePath, Created, Modified, Accessed, MachineId |
  Sort-Object Modified -Descending |
  Export-Csv suspicious_lnk.csv -NoTypeInformation
```

---

### 7. 浏览器取证 (Hindsight)

#### 7.1 浏览器工件位置

| 浏览器 | 历史数据库 | 下载记录 | Cookie |
|--------|-----------|---------|--------|
| Chrome | `...\Google\Chrome\User Data\Default\History` | 同一DB | `Cookies` |
| Edge | `...\Microsoft\Edge\User Data\Default\History` | 同一DB | `Cookies` |
| Firefox | `...\Firefox\Profiles\*.default\places.sqlite` | 同一DB | `cookies.sqlite` |
| IE | `...\History\History.IE5\*` | `...\Downloads\*` | `%USERPROFILE%\Cookies\*` |

#### 7.2 Hindsight 使用

```bash
# 安装
pip install pyhindsight

# 分析 Chrome profile
hindsight.py -i "C:\ir_evidence\Chrome\User Data\Default" -o chrome_report

# 分析 Firefox profile
hindsight.py -i "C:\ir_evidence\Firefox\Profiles\xxxxx.default" -o firefox_report --browser firefox

# 输出格式: SQLite (默认) / JSON / XLSX
hindsight.py -i <profile_dir> --output xlsx -o report.xlsx

# Hindsight 输出包含:
# - URL 访问记录 (含标题、访问次数、时间)
# - 下载历史 (含文件路径、大小)
# - 自动填充数据
# - 书签
# - Cookie (含值、过期时间)
# - 本地存储 (LocalStorage)
# - 登录凭据 (需解密)
# - 扩展程序列表
```

#### 7.3 Chrome 历史快速查询 (离线 SQLite)

```python
#!/usr/bin/env python3
"""chrome_history_analyzer.py — 离线分析 Chrome History SQLite"""
import sqlite3
import csv
import sys
from datetime import datetime

def chrometime_to_utc(chrometime):
    """Chrome时间 = 微秒自1601-01-01"""
    epoch_diff = 11644473600  # 1601 到 1970 的秒数
    return datetime.utcfromtimestamp(chrometime / 1000000 - epoch_diff)

def analyze(history_db, output_csv):
    conn = sqlite3.connect(history_db)
    cursor = conn.cursor()

    results = []

    # URL 访问
    cursor.execute("""
        SELECT urls.url, urls.title, visits.visit_time, visits.transition,
               visits.from_visit, visits.visit_duration
        FROM urls JOIN visits ON urls.id = visits.url
        ORDER BY visits.visit_time DESC
    """)
    for url, title, vt, trans, from_v, dur in cursor.fetchall():
        results.append({
            'type': 'visit',
            'time': chrometime_to_utc(vt).strftime('%Y-%m-%d %H:%M:%S'),
            'url': url,
            'title': title,
            'transition': trans,
            'duration_s': dur / 1000000 if dur else 0,
        })

    # 下载记录
    cursor.execute("""
        SELECT target_path, tab_url, total_bytes, start_time, end_time, danger_type
        FROM downloads
        ORDER BY start_time DESC
    """)
    for path, tab_url, size, st, et, danger in cursor.fetchall():
        results.append({
            'type': 'download',
            'time': chrometime_to_utc(st).strftime('%Y-%m-%d %H:%M:%S') if st else '',
            'url': tab_url,
            'title': path,
            'transition': f'danger_type={danger}',
            'duration_s': size or 0,
        })

    results.sort(key=lambda x: x['time'], reverse=True)

    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"[+] 解析完成: {len(results)} 条记录 -> {output_csv}")

    # 检测可疑 URL
    suspicious_patterns = ['pastebin', 'githubusercontent', 'transfer.sh', 'upload',
                           '.ps1', '.bat', '.exe', '.dll', 'webshell', 'c2', 'beacon']
    print("\n[!] 可疑浏览/下载:")
    for r in results:
        url_lower = r['url'].lower()
        title_lower = (r['title'] or '').lower()
        if any(p in url_lower or p in title_lower for p in suspicious_patterns):
            print(f"  [{r['type']}] {r['time']} | {r['url'][:120]}")

    conn.close()

if __name__ == '__main__':
    analyze(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'chrome_analysis.csv')
```

---

### 8. Outlook PST 邮件取证

#### 8.1 PST 文件提取

```powershell
# 方法 1: libpst (readpst)
# 安装: apt install pst-utils (Linux) 或编译 Windows 版
readpst -M -b -o C:\ir_evidence\pst_output victim.pst
# -M: 邮件格式 (mbox), -b: 不保存附件到子目录, -o: 输出目录
# 输出: 每个 PST 文件夹一个 mbox 文件

# 方法 2: Python (使用 libratom/libpst)
pip install libratom
# 使用 pypff 从 PST 提取邮件
```

```python
#!/usr/bin/env python3
"""pst_email_extract.py — 从 Outlook PST 提取邮件元数据和附件"""
import os
import csv
import hashlib
import argparse

def extract_pst_metadata(pst_path, output_dir):
    """使用 pypff 提取 PST 邮件"""
    try:
        from pypff import file as pypff_file
    except ImportError:
        print("[!] 请安装: pip install libpff-python")
        print("    或使用 readpst 命令行工具")
        return

    pst = pypff_file.file()
    pst.open(pst_path)
    root = pst.get_root_folder()

    results = []

    def process_folder(folder, path=""):
        folder_name = folder.get_name() or "Root"
        current_path = f"{path}/{folder_name}" if path else folder_name

        for i in range(folder.get_number_of_sub_messages()):
            msg = folder.get_sub_message(i)
            headers = msg.get_transport_headers() or ""
            subject = msg.get_subject() or ""
            sender = msg.get_sender_name() or ""
            body = msg.get_plain_text_body()
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='replace')

            delivery_time = msg.get_delivery_time()
            client_submit = msg.get_client_submit_time()

            # 提取附件
            attachments = []
            for j in range(msg.get_number_of_attachments()):
                att = msg.get_attachment(j)
                att_name = att.get_name() or f"attachment_{j}"
                att_data = att.get_data()
                if att_data:
                    att_hash = hashlib.sha256(att_data).hexdigest()[:16]
                    att_path = os.path.join(output_dir, f"{att_hash}_{att_name}")
                    with open(att_path, 'wb') as f:
                        f.write(att_data)
                    attachments.append(f"{att_name} (sha256:{att_hash})")

            results.append({
                'folder': current_path,
                'subject': subject,
                'sender': sender,
                'delivery_time': str(delivery_time),
                'client_submit_time': str(client_submit),
                'has_attachments': len(attachments) > 0,
                'attachments': '; '.join(attachments),
                'body_preview': (body or '')[:200],
                'headers_preview': headers[:500] if headers else '',
            })

        for i in range(folder.get_number_of_sub_folders()):
            process_folder(folder.get_sub_folder(i), current_path)

    process_folder(root)

    csv_path = os.path.join(output_dir, 'pst_emails.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"[+] 提取完成: {len(results)} 封邮件 -> {csv_path}")

    # 检测钓鱼指标
    phishing_indicators = ['verify your account', 'click here', 'urgent',
                           'suspended', 'password expire', 'wire transfer',
                           'invoice attached', 'secure your account']
    print("\n[!] 潜在钓鱼邮件:")
    for r in results:
        body_lower = r['body_preview'].lower()
        subj_lower = r['subject'].lower()
        matches = [ind for ind in phishing_indicators if ind in body_lower or ind in subj_lower]
        if matches:
            print(f"  {r['delivery_time']} | From: {r['sender']} | Subj: {r['subject'][:80]}")
            print(f"    匹配指标: {', '.join(matches)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('pst_path', help='PST 文件路径')
    parser.add_argument('-o', '--output', default='pst_output')
    args = parser.parse_args()
    os.makedirs(args.output, exist_ok=True)
    extract_pst_metadata(args.pst_path, args.output)
```

---

### 9. ShellBags 分析

```
ShellBags 记录:
- 用户浏览过的文件夹（包括已删除/网络/压缩包内路径）
- 窗口位置和大小
- 最后访问时间 + 最后修改时间
- 解析注册表路径: NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags\

取证场景:
1. 证明用户访问了特定目录（如 C:\Tools\exploits\）
2. 重建用户的文件夹浏览轨迹
3. 发现网络共享路径（如 \\DC01\C$\ 证明横向移动）
4. 发现 ZIP/7z 内浏览过的文件路径
```

```powershell
# ShellBagsExplorer 解析
ShellBagsExplorer.exe -f "C:\ir_evidence\NTUSER.DAT" --csv C:\ir_evidence\out

# 关键字段: Path, LastAccessedTime, ModifiedTime, FileAttributes
# 搜索网络路径证据
$shellbags = Import-Csv "C:\ir_evidence\out\ShellBags_*.csv"
$shellbags | Where { $_.Path -match '^\\\\\\\\' } | Select Path, LastAccessedTime
# 输出示例: \\DC01\C$\Windows\Temp, \\FILESVR\Share\Confidential
```

---

## Part B：检测与防御

### 10. Sigma 检测规则

```yaml
# 暴力破解检测
title: Possible Brute Force Attack - Multiple Failed Logins
id: 1e2367a3-7e4f-4e6a-8b5c-9d0e1f2a3b4c
status: production
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 10m
    condition: selection | count() by TargetUserName > 5
level: high
tags:
    - attack.credential_access
    - attack.t1110

---
# Mimikatz 凭据转储
title: Potential Mimikatz - LSASS Access
id: 2f3467a3-7e4f-4e6a-8b5c-9d0e1f2a3b4d
status: production
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: lsass.exe
    filter_legitimate:
        SourceImage|endswith:
            - '\vmtoolsd.exe'
            - '\svchost.exe'
            - '\msmpeng.exe'
            - '\procexp64.exe'
    condition: selection and not filter_legitimate
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001

---
# 反取证 — 日志清除
title: Security Audit Log Cleared
id: 3f4567a3-7e4f-4e6a-8b5c-9d0e1f2a3b4e
status: production
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1102
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1070.001

---
# 可疑服务创建
title: Suspicious Service Creation
id: 4f5677a3-7e4f-4e6a-8b5c-9d0e1f2a3b4f
status: production
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    suspicious_path:
        ServiceFileName|contains:
            - '\Temp\'
            - '\Public\'
            - '\Users\'
            - 'cmd.exe /c'
            - 'powershell'
            - '\\127.0.0.1'
            - '\\0.0.0.0'
    condition: selection and suspicious_path
level: high
tags:
    - attack.persistence
    - attack.t1543.003

---
# 恶意 PowerShell 执行
title: Obfuscated PowerShell Execution
id: 5f6787a3-7e4f-4e6a-8b5c-9d0e1f2a3b50
status: production
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - 'FromBase64String'
            - 'Invoke-Expression'
            - 'IEX'
            - '[Char]'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1027
```

### 11. 证据保全最佳实践

```
证据保全四原则:
1. 不修改原始证据 → 只操作副本
2. 记录所有操作 → 带时间戳的日志
3. 验证完整性 → SHA256 哈希
4. 保持链条 → 证据移交签名

证据收集操作流程:
1. 拍照 → 屏幕内容、物理环境
2. 易失性数据 → 上述脚本（内存 > 网络 > 进程 > 配置）
3. 非易失性数据 → 磁盘镜像（FTK Imager / dd）
4. 哈希验证 →
   certutil -hashfile evidence.dd SHA256
   fciv -sha256 evidence.dd
5. 时间同步 → 记录系统时间与 UTC 偏移
6. 网络隔离 → 拔网线/禁用网卡，防止远程清除
```

### 12. 防御加固建议

```
1. 启用完整审计策略:
   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
   auditpol /set /subcategory:"Process Termination" /success:enable
   # 启用命令行审计:
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
     /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

2. 部署 Sysmon:
   sysmon -i sysmonconfig.xml
   # 使用 SwiftOnSecurity 配置模板

3. 启用 Prefetch (SSD 可能禁用):
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" ^
     /v EnablePrefetcher /t REG_DWORD /d 3

4. 配置日志大小:
   wevtutil sl Security /ms:4294967296   # 4GB
   wevtutil sl System /ms:1073741824     # 1GB
   wevtutil sl Application /ms:1073741824

5. 日志转发到 SIEM:
   wecutil qc
   # 配置 Windows Event Collector 服务集中收集
```

---

## 速查表

### Windows 取证工件速查矩阵

| 工件 | 位置 | 时间范围 | 保留时长 | 取证值 |
|------|------|----------|----------|--------|
| Prefetch | `C:\Windows\Prefetch\` | 程序执行 | ~30天 | ★★★★★ |
| Amcache | `Amcache.hve` | 程序执行+SHA1 | 数月-年 | ★★★★★ |
| Shimcache | SYSTEM 注册表 | 程序执行 | 数月 | ★★★★☆ |
| 事件日志 | `winevt\Logs\` | 系统活动 | 配置决定 | ★★★★★ |
| LNK | `Recent\*.lnk` | 文件打开 | 数月 | ★★★★☆ |
| Jump Lists | `AutomaticDestinations\` | 应用文件 | 数月 | ★★★★☆ |
| ShellBags | NTUSER.DAT | 文件夹浏览 | 永久 | ★★★☆☆ |
| UserAssist | NTUSER.DAT | GUI 程序 | 永久 | ★★★☆☆ |
| SRUM | `SRUDB.dat` | 网络使用 | 30-60天 | ★★★★☆ |
| BAM | SYSTEM 注册表 | 后台进程 | 数天 | ★★★☆☆ |
| USB | SYSTEM 注册表 | 设备连接 | 永久 | ★★★★☆ |
| 浏览器 | Profile 目录 | 浏览历史 | 数月 | ★★★★★ |
| PST/OST | Outlook 目录 | 邮件 | 永久 | ★★★★☆ |
| $MFT | NTFS 根 | 文件元数据 | 永久 | ★★★★★ |
| USN Journal | NTFS | 文件变更 | 数周-月 | ★★★★☆ |

### Eric Zimmerman 工具速查

| 工具 | 用途 | 命令 |
|------|------|------|
| PECmd | Prefetch 解析 | `PECmd.exe -d C:\Prefetch --csv out` |
| AmcacheParser | Amcache 解析 | `AmcacheParser.exe -f Amcache.hve --csv out` |
| AppCompatCacheParser | Shimcache 解析 | `AppCompatCacheParser.exe -f SYSTEM --csv out` |
| LECmd | LNK 文件解析 | `LECmd.exe -d C:\Recent --csv out` |
| JLECmd | Jump Lists 解析 | `JLECmd.exe -d C:\AutoDest --csv out` |
| ShellBagsExplorer | ShellBags 解析 | `ShellBagsExplorer.exe -f NTUSER.DAT --csv out` |
| SBECmd | SRUM 解析 | `SBECmd.exe -f SRUDB.dat --csv out` |
| EvtxECmd | EVTX 转 CSV | `EvtxECmd.exe -f Security.evtx --csv out` |
| RegistryExplorer | 注册表浏览 | `RegistryExplorer.exe SOFTWARE` |
| MFTECmd | $MFT 解析 | `MFTECmd.exe -f C:\..\$MFT --csv out` |
| VSCMount | VSS 挂载 | `VSCMount.exe -d \\.\C: -o C:\vss` |

---

## Part C：2025-2026 前沿补充

### C.1 Windows 11 PCA (Program Compatibility Assistant) 取证工件

> Windows 11 22H2+ 引入的全新执行证据工件，填补了 GUI 程序执行的取证空白。
> 来源: [Sygnia](https://www.sygnia.co/blog/new-windows-11-pca-artifact/) / [Kaspersky](https://securelist.com/forensic-artifacts-in-windows-11/117680/)

#### 工件位置

```
C:\Windows\appcompat\pca\
├── PcaAppLaunchDic.txt     ← GUI 程序执行记录 (ANSI/CP-1252)
├── PcaGeneralDb0.txt       ← 详细程序信息 (UTF-16LE, 滚动2MB)
└── PcaGeneralDb1.txt       ← 溢出/轮转数据库 (UTF-16LE)
```

**适用版本**: Windows 11 22H2 (Build 22621+) 和 23H2。Windows 10 及更早版本不存在。

#### PcaAppLaunchDic.txt 格式

```
格式: [完整可执行文件路径]|[YYYY-MM-DD HH:MM:SS.f] (UTC, 管道符分隔)
编码: ANSI (CP-1252), CRLF
注意: 时间戳记录在进程终止时(非启动时)
限制: 仅记录 GUI 启动的程序(Explorer/RDP/Chrome下载页/7-Zip GUI)
      不记录命令行/计划任务/PsExec执行的程序
已知缺陷: 路径含非ANSI字符时行被截断,之后不再写入新条目
```

#### PcaGeneralDb0.txt / PcaGeneralDb1.txt 格式

```
编码: UTF-16LE
格式: 8个管道符分隔字段:
  [启动时间]|[记录类型(0-4)][可执行文件路径]|[产品名]|[公司名]|[版本]|[ProgramID]|[消息]
滚动: 主文件达2MB时,次文件被清空并角色互换 → 任意时刻有2-4MB历史数据
路径脱敏: 盘符移除,小写化,用户名替换为 %USERNAME% 或 usersxxxxx
```

#### 记录类型取证价值

| 类型 | 含义 | 取证价值 |
|------|------|----------|
| 0 | Installer Failed | 不完整/崩溃的安装 → 攻击工具安装失败证据 |
| 1 | Driver was Blocked | **CET/HVCI 触发 → BYOVD 攻击检测独有证据** |
| 2 | Abnormal Process Exit | 含十六进制退出码 → 程序是否成功运行/失败原因 |
| 3 | PCA Resolve Called | 含解析器名称和结果 → 明确的程序执行证据 |
| 4 | Unknown/Not Set | 未分类 |

#### PCA vs 其他工件对比

```
                PCA          Prefetch      Shimcache      Amcache
GUI程序执行     ✅            ✅            ⚠️(不精确)     ✅
CLI程序执行     ❌            ✅            ✅             ✅
SHA1哈希        ❌            ❌            ❌             ✅
驱动阻止事件    ✅(独有)      ❌            ❌             ❌
退出状态码      ✅(独有)      ❌            ❌             ❌
ProgramID关联   ✅            ❌            ❌             ✅(可交叉引用)
反取证持久性    ✅(不易清除)  ⚠️(可删除)   ⚠️(注册表)     ⚠️(可删除)
```

#### PCA 收集与解析

```powershell
# KAPE 收集 (使用 AppCompatPCA target)
kape.exe --target AppCompatPCA --dest C:\ir_evidence\pca

# 手动收集
Copy-Item "C:\Windows\appcompat\pca\*" -Destination C:\ir_evidence\pca\

# Velociraptor VQL 收集
SELECT * FROM glob(globs='C:/Windows/appcompat/pca/*')

# 快速解析 PcaAppLaunchDic.txt
Get-Content "C:\ir_evidence\pca\PcaAppLaunchDic.txt" | ForEach-Object {
    $parts = $_ -split '\|'
    if ($parts.Count -ge 2) {
        [PSCustomObject]@{
            Executable = $parts[0]
            LastRun = $parts[1]
        }
    }
} | Sort-Object LastRun -Descending | Export-Csv pca_timeline.csv -NoTypeInformation
```

---

### C.2 Windows 11 其他新取证工件

#### C.2.1 Microsoft Recall 取证 (ARM+NPU 设备)

> Windows 11 ARM 设备上的屏幕快照 AI 功能，含大量用户活动证据。
> 来源: [Kaspersky Securelist](https://securelist.com/forensic-artifacts-in-windows-11/117680/)

```
屏幕截图位置:
  %AppData%\Local\CoreAIPlatform.00\UKP\{GUID}\ImageStore\* (原始JPEG)

元数据 (Exif.Photo.MakerNote 标签):
  - 窗口边界坐标
  - 捕获时间戳
  - 窗口标题
  - 窗口ID
  - 进程路径
  - URI/域名 (如为浏览器活动)

SQLite 数据库:
  %AppData%\Local\CoreAIPlatform.00\UKP\{GUID}\ukg.db
  (20+ 表, 生产版本加密)

关键表:
  - App: 进程数据
  - AppDwellTime: 启动时间 + 显示持续时间
  - WindowCapture: 窗口生命周期事件
  - WindowCaptureTextIndex_content: OCR 提取的屏幕文本

注册表控制键:
  Software\Policies\Microsoft\Windows\WindowsAI\

适用条件: 仅 ARM CPU + NPU; 企业版默认禁用
```

#### C.2.2 Windows 11 Notepad 多标签取证

```
位置:
  %LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\

TabState\{GUID}.bin:
  - 标签内容(如未保存)
  - 文件路径(如已保存)
  - SHA-256 哈希
  - 编码格式
  - 最后写入时间
  - 光标位置

WindowsState\*.0.bin 或 *.1.bin:
  - 标签数量和顺序
  - 活动标签
  - 窗口位置

解析工具: notepad_parser (by AbdulRhman Alfaifi)
```

#### C.2.3 Windows Search Index 结构变化 (Win10 → Win11)

```
Windows 10 (单一 ESE 数据库):
  %PROGRAMDATA%\Microsoft\Search\Data\Applications\Windows\Windows.edb

Windows 11 (拆分为 3 个 SQLite 数据库):
  Windows-gather.db:
    - SystemIndex_Gthr 表: 索引文件/文件夹名, 最后修改时间
    - SystemIndex_GthrPth 表: 父子目录关系
  Windows.db:
    - SystemIndex_1_PropertyStore 表: 文件元数据
  Windows-usn.db:
    - 取证价值有限

取证价值: 可发现已删除文件的存在证据(SQLite中索引可能保留)
```

#### C.2.4 NTFS 时间戳行为变化 (Win10 vs Win11 24H2)

```
Win10 行为:
  - >128GB 卷禁用最后访问时间更新
  - 重命名: 访问时间不变
  - 复制: 元数据更新
  - 卷内移动: 访问时间不变

Win11 24H2 行为:
  - 文件访问时间现在会更新(不再按卷大小禁用)
  - 重命名: 访问时间更新为修改时间
  - 复制: 元数据继承自原文件
  - 卷内移动: 访问时间更新为移动时间
  - $FILENAME 属性: 重命名/移动/回收站时继承 $STANDARD_INFORMATION 时间戳

取证影响: 访问时间更可靠, 但需要了解行为差异以避免误判
```

#### C.2.5 MUICache 作为执行证据

```
注册表路径:
  HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache

内容: GUI 可执行文件完整路径 + 有限 PE 信息
取证价值: 证明程序曾在 GUI 环境下执行(与 PCA 互补)
持久性: 即使程序已删除,条目可能保留
```

---

### C.3 2025-2026 关键 CVE 速查

| CVE | 严重性 | 影响 | 取证关联 |
|-----|--------|------|----------|
| CVE-2025-29969 | Critical | MS-EVEN RPC RCE → 可远程攻击事件日志服务 | 事件日志完整性受威胁,需检查 RPC 异常连接 |
| CVE-2025-21299 | Important | Credential Guard 绕过 (Kerberos Unguarding) | 凭据保护失效,检查 4624/4672 异常模式 |
| CVE-2025-29809 | Important | NTLM 认证绕过 (Pass-the-Challenge) | NTLM 中继证据可能被伪造 |
| CVE-2025-26647 | Important | Windows Server 2008 Kerberos 提权 | 域控制器取证时检查 Kerberos 异常 |

#### CVE-2025-29969 深度分析

```
影响组件: MS-EVEN (EventLog Remote) RPC 协议
攻击面: 可远程触发,无需认证
取证影响:
  1. 攻击者可远程操纵事件日志服务
  2. 可能注入虚假事件记录(证据完整性受损)
  3. 可能导致事件日志服务崩溃(DoS)

检测方法:
  - 监控 EventLog 服务异常重启 (EventID 7034/7036)
  - 检查 RPC 接口异常连接 (Sysmon EventID 3, 目标端口 135)
  - 事件日志时间戳跳跃或内容异常
  - 服务崩溃后的 EventID 1100 (事件服务关闭)

缓解: 确保安装 2025年6月及以后的累积更新
```

#### Credential Guard 绕过取证考量

```
SO-CON 2025 (Ceri Coburn, NetSPI) 研究表明 Credential Guard 可被绕过:
  - CVE-2025-21299 + CVE-2025-29809 组合 → Kerberos Unguarding
  - Pass-the-Challenge NTLM 恢复技术
  - Token Protection 仍可绕过(截至2025年中)

取证检测:
  - EventID 4624 中检查 "Remote Credential Guard" 字段(Win11新增)
  - LSA 错误 EventID 6155 ("LSA package is not signed as expected")
  - 异常的 NTLM 认证模式 (EventID 4624, LogonType=3, NTLM)
  - 凭据转储尝试 (Sysmon EventID 10, lsass.exe 访问)

防御建议:
  - 启用 Windows Defender Credential Guard
  - 启用 Token Protection (RCG)
  - 部署 LSA Protection (RunAsPPL)
  - 监控 LSA 相关注册表修改
```

---

### C.4 工具生态更新

#### C.4.1 Eric Zimmerman 工具集

```
重大更新: 所有 GUI 工具已迁移至 .NET 9
一键下载: Get-ZimmermanTools PowerShell 脚本
官方页面: https://ericzimmerman.github.io/

新增/更新工具:
  RECmd — 命令行注册表数据提取 (替代 RegRipper)
  RLA — 注册表事务日志回放
  PECmd — 支持 Windows 11 PCA 文件解析
  KAPE — 内嵌完整 EZ 工具套件
  KapeFiles 社区持续更新: https://github.com/EricZimmerman/KapeFiles
```

#### C.4.2 Velociraptor 更新

```
v0.74+ 关键特性:
  - 新增 NOTEBOOK artifact 类型 (全局笔记本模板)
  - Linux 取证增强 (文件描述符/套接字元数据)
  - Windows.KapeFiles.Targets 集成 KAPE 全部目标
  - VQL 查询语言持续增强
  - Hunt Manager 改进

Windows 取证相关 Artifact:
  - Windows.EventLogs.Evtx — 事件日志批量收集
  - Windows.KapeFiles.Targets — KAPE 目标收集
  - Windows.Search.Index — 搜索索引解析
  - Windows.PCA — PCA 工件收集
  - Windows.Registry.NTUser — 用户注册表分析

下载: https://github.com/Velocidex/velociraptor/releases
```

#### C.4.3 Plaso/log2timeline

```
持续更新的超时间线引擎:
  - 支持 Windows 11 新工件解析器
  - 性能优化 (大镜像处理)
  - 新输出格式和时间线分析工具
  - pinfo 工具用于验证时间线数据完整性

安装: pip install plaso
文档: https://plaso.readthedocs.io/
GitHub: https://github.com/log2timeline/plaso

关键工作流:
  log2timeline.py --storage-file case.plaso image.dd
  psort.py -o l2tcsv -w timeline.csv case.plaso
  pinfo.py case.plaso  # 验证数据完整性
```

---

### C.5 事件日志分析增强 (基于 Elcomsoft 2026 研究)

#### C.5.1 高价值事件 ID 补充

| 事件 ID | 日志源 | 含义 | 备注 |
|---------|--------|------|------|
| 21/22/24/25 | TerminalServices-LocalSessionManager | RDP 会话生命周期 | 21=登录,22=Shell启动,24=断开,25=重连 |
| 10000-10002 | Storage-ClassPnP | USB 设备连接 | 含 VID/PID/序列号 |
| 507/512 | DriverFrameworks-UserMode | USB 用户模式驱动 | 补充 USB 时间线 |
| 7040 | System | 服务启动类型变更 | 持久化检测 |
| 7034 | System | 服务崩溃 | 可能指示攻击/反取证 |
| 1100 | Security | 事件服务关闭 | 日志中断指标 |
| 6155 | Security | LSA 签名异常 | Credential Guard 问题 |

#### C.5.2 VSS 事件日志恢复

```powershell
# 列出卷影副本
vssadmin list shadows

# 挂载 VSS (获取历史事件日志)
New-Item -ItemType Directory -Path C:\vss_mount -Force
symlinkd C:\vss_mount \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# 从 VSS 恢复事件日志
Copy-Item "C:\vss_mount\Windows\System32\winevt\Logs\Security.evtx" `
  -Destination "C:\ir_evidence\vss\Security.evtx"

# 使用 EvtxECmd 解析恢复的日志
EvtxECmd.exe -f "C:\ir_evidence\vss\Security.evtx" --csv C:\ir_evidence\vss_out
```

#### C.5.3 噪音事件 ID 过滤指南

```
高噪音低信号(建议过滤):
  5156, 5158 — WFP 过滤事件 (海量)
  4662 — DS Access (AD 环境极高噪音)
  4770 — Kerberos 票据续订 (正常行为)
  4634/4647 — 注销事件 (通常无取证价值)

遗留事件 ID (已弃用,使用新版替代):
  528 → 使用 4624
  540 → 使用 4624
  529-537 → 使用 4625
  538 → 使用 4634/4647
```

---

### C.6 Windows 11 取证决策树 (更新版)

```
Windows 11 入侵调查
├── 检查 PCA 工件 (C:\Windows\appcompat\pca\)
│   ├── PcaAppLaunchDic.txt → GUI 程序执行时间线
│   └── PcaGeneralDb0.txt → 驱动阻止/异常退出/ProgramID
├── 检查 Recall 工件 (仅 ARM+NPU)
│   ├── ImageStore → 屏幕截图证据
│   └── ukg.db → OCR 文本/窗口活动
├── 检查 Notepad 标签 (可能的脚本/配置证据)
│   └── TabState → 未保存内容
├── 检查 Search Index (SQLite, 非 ESE)
│   ├── Windows-gather.db → 已删除文件索引
│   └── Windows.db → 文件元数据
├── 注意 NTFS 时间戳行为差异
│   └── Win11 24H2: 访问时间会更新 → 更可靠但需了解差异
├── 检查 MUICache (补充 GUI 执行证据)
│   └── NTUSER.DAT\...\MuiCache
└── 标准工件 (Prefetch/Amcache/Shimcache/事件日志/LNK/ShellBags)
```

---

### C.7 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| 奇安信 | 2025年应急响应分析报告 (575起案例) | https://www.qianxin.com/threat/reportaptlist |
| 腾讯云 | 日志分析从基础到实战 (Windows/Linux/Web/DB) | https://cloud.tencent.com/developer/article/2560131 |
| 知乎 | Windows入侵排查应急响应篇 | https://zhuanlan.zhihu.com/p/608654371 |
| GitHub | 全网优秀攻防武器库 (应急响应工具集) | https://github.com/guchangan1/All-Defense-Tool |
| FreeBuf | Windows域控制器DDoS僵尸网络取证 | https://m.freebuf.com/articles/system/443710.html |
| FreeBuf | WinRM隐秘渗透AD网络取证指标 | https://m.freebuf.com/articles/system/430574.html |
| 奇安信攻防社区 | 漏洞分析/应急响应板块 | https://mdrforum.butian.net/ |
| blue.y1ng.org | 数字取证大合集 (蓝队清单) | https://blue.y1ng.org/0x6_digital_forensics/ |

---

### C.8 防御升级路线图

```
P0 (立即):
  ├── 部署 Sysmon (SwiftOnSecurity 配置模板)
  ├── 启用命令行审计 (ProcessCreationIncludeCmdLine_Enabled=1)
  ├── 配置日志大小 (Security 4GB, System/Application 1GB)
  ├── 启用 Prefetch (EnablePrefetcher=3, 含SSD)
  └── 安装 2025年6月+ 累积更新 (CVE-2025-29969 修复)

P1 (30天内):
  ├── 部署 Credential Guard + LSA Protection (RunAsPPL)
  ├── 配置日志转发到 SIEM (WEC/WEF)
  ├── KAPE 目标包含 PCA 工件 (Windows 11)
  ├── Velociraptor 远程取证能力部署
  └── 事件日志 VSS 备份策略

P2 (90天内):
  ├── 取证管线自动化 (KAPE+Plaso+EZ Tools)
  ├── Sigma 规则库持续更新
  ├── Windows 11 新工件纳入标准取证流程
  └── 取证响应 Playbook 文档化

P3 (持续):
  ├── 监控 EZ Tools/KapeFiles 更新
  ├── 跟踪 MITRE ATT&CK v19 取证映射更新
  ├── 评估 AI/LLM 辅助日志分析工具
  └── Windows 11 24H2 行为变更纳入取证知识库
```

---

## MITRE ATT&CK 映射 (更新版)

| 战术 | 技术 | ID | 取证工件 |
|------|------|----|----------|
| Execution | Command/Scripting | T1059 | Prefetch, 4688, 4104, LNK, PCA |
| Execution | GUI Program Execution | T1059 | PCA PcaAppLaunchDic, MUICache, UserAssist |
| Persistence | Registry Run Keys | T1547.001 | 注册表 Run, 4697 |
| Persistence | Scheduled Task | T1053.005 | 4698, tasks folder |
| Persistence | WMI Event Subscription | T1546.003 | WMI namespace, 4688 |
| Defense Evasion | Log Deletion | T1070.001 | 1102, 104, VSS 恢复 |
| Defense Evasion | Timestomping | T1070.006 | $MFT vs Prefetch 对比 (注意Win11行为差异) |
| Defense Evasion | BYOVD Attack | T1068 | PCA Type 1 (Driver Blocked), 独有检测 |
| Credential Access | OS Credential Dumping | T1003.001 | Sysmon 10, 4688, LSA EventID 6155 |
| Credential Access | Kerberoasting | T1558.002 | 4769 |
| Credential Access | Credential Guard Bypass | T1555 | Kerberos Unguarding (CVE-2025-21299) |
| Lateral Movement | Pass-the-Hash | T1550.002 | 4624 Type 3 NTLM |
| Lateral Movement | RDP | T1021.001 | 4624 Type 10, TermSrv 21/22/24/25 |
| Discovery | File/Directory Discovery | T1083 | ShellBags, LNK, Search Index |
| Exfiltration | Data Transfer Size | T1048 | SRUM, 浏览器下载 |
| Collection | Email Collection | T1114 | PST/OST 分析 |
| Collection | Screen Capture | T1113 | Microsoft Recall ImageStore |

## 前置条件

- Windows 10/11 目标系统（部分工件需 Windows 11 22H2+）
- 管理员权限（系统级工件访问）
- Eric Zimmerman 工具集 v2025+ (.NET 9)
- Python 3.8+（分析脚本）
- Splunk Enterprise 或类似 SIEM
- Velociraptor v0.74+（远程取证）
- KAPE (Kroll Artifact Parser and Extractor)
- Plaso/log2timeline（时间线构建）
- 可信取证 USB 或隔离取证环境
