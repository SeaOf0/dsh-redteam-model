---
name: threat-hunting
description: >
  威胁狩猎完整手册：覆盖全类别主动狩猎方法论 — Living off the Land (LOLBins/LOLBAS)、
  C2 Beaconing 检测、DNS 隧道、Webshell 发现、持久化机制狩猎（注册表/WMI/计划任务/启动文件夹/DNS）、
  横向移动检测（DCOM/WMI）、凭据访问、数据外泄前兆、供应链入侵、异常 PowerShell、
  频率分析、域前置 C2、进程注入、防御规避（Timestomping）、账号操纵。
  Part A 攻击视角：红队如何规避狩猎。Part B 防御视角：假设驱动的狩猎方法论与检测规则。
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-hunting, LOLBins, LOLBAS, beaconing, DNS-tunneling, webshell, persistence, lateral-movement, credential-access, exfiltration, supply-chain, PowerShell, MITRE-ATTCK, Sigma, detection]
version: 2.0.0
---

# 威胁狩猎 — 完整攻防手册

## 适用场景

**适用：** 已有 SIEM/EDR 但需要主动寻找未知威胁的 SOC 团队；需要验证检测覆盖率的蓝队；假设驱动的持续威胁狩猎项目。
**不适用：** 实时告警响应（参考 ir-triage-scoping）；被动监控（参考 network-defense）；漏洞扫描（参考 web-pentest-comprehensive）。

## 前置条件

- SIEM（Splunk/Elastic/QRadar）已部署并采集日志
- EDR（CrowdStrike/Defender/SentinelOne）端点遥测
- 网络 IDS/Zeek 流量数据
- MITRE ATT&CK 框架基础知识
- Python 3.10+ 用于分析脚本

---

## 狩猎方法论框架

```
┌──────────────────────────────────────────────────────┐
│            假设驱动威胁狩猎循环                         │
│                                                      │
│  1. 假设形成 ← 威胁情报/ATT&CK Gap/异常观测            │
│  2. 数据收集 ← SIEM查询/端点遥测/网络流量              │
│  3. 分析触发 ← 统计分析/机器学习/模式匹配              │
│  4. 确认/排除 ← 上下文富化/沙箱分析/人工研判            │
│  5. 检测自动化 ← Sigma规则/EDR规则/SOAR Playbook       │
│                                                      │
│  ┌────────────────────┐                              │
│  │ 狩猎矩阵：                                          │
│  │ 持久化 │ 凭据访问 │ 横向移动 │ C2 │ 外泄            │
│  │ ├ LOLBins          │ ├ 凭据转储  │ ├ WMI    │ ├ DNS │ ├ Staging│
│  │ ├ 注册表           │ ├ DCSync   │ ├ DCOM   │ ├ HTTP│ ├ DNS    │
│  │ ├ 计划任务         │ ├ Mimikatz │ ├ RDP    │ ├ 域前│ ├ Cloud  │
│  │ ├ WMI订阅          │ ├ 破解     │ ├ PsExec │ ├ 信标│ ├ HTTPS  │
│  │ ├ 启动文件夹       │            │          │       │          │
│  │ └ DNS             │            │          │       │          │
│  └────────────────────┘                              │
└──────────────────────────────────────────────────────┘
```

## Part A：攻击视角 — 红队如何规避狩猎

### 1. LOLBins/LOLBAS 规避技术

```
红队常用 LOLBins（合法工具滥用）执行恶意操作，
蓝队狩猎关键：监控这些工具的异常参数和非典型父进程。

高频滥用工具清单：
┌──────────────────┬──────────────────┬─────────────────────┐
│ 工具              │ 滥用方式          │ 难以检测的原因        │
├──────────────────┼──────────────────┼─────────────────────┤
│ certutil.exe     │ 下载/编码/解码    │ 合法证书管理工具      │
│ mshta.exe        │ 执行HTA/VBS      │ HTML应用宿主         │
│ msiexec.exe      │ 远程安装恶意MSI   │ Windows安装服务      │
│ rundll32.exe     │ 加载恶意DLL       │ 系统核心组件          │
│ regsvr32.exe     │ 加载COM对象       │ 注册服务器            │
│ wmic.exe         │ 远程命令执行      │ WMI管理工具           │
│ bitsadmin.exe    │ 后台下载          │ 智能传输服务          │
│ esentutl.exe     │ 文件复制/提取     │ 数据库工具            │
│ expand.exe       │ CAB解压执行       │ 系统解压工具          │
│ forfiles.exe     │ 代理执行          │ 批处理辅助            │
│ pcalua.exe       │ 代理执行          │ 程序兼容性助手        │
│ svchost.exe      │ DLL注入宿主       │ 服务宿主进程          │
│ msbuild.exe      │ 内联C#执行        │ 构建工具              │
│ cscript/wscript  │ VBS/JS执行        │ 脚本宿主              │
│ cmd.exe /c       │ 命令执行          │ 基础命令行            │
│ powershell.exe   │ 脚本执行/下载     │ 管理框架              │
└──────────────────┴──────────────────┴─────────────────────┘
```

### 2. C2 通信规避策略

```
红队 C2 规避层级：

Level 1 — 基础规避（绕过签名检测）：
  - HTTPS 加密通信
  - 自定义 User-Agent
  - 域前置 (Domain Fronting)
  - DNS over HTTPS (DoH) C2

Level 2 — 中级规避（绕过行为检测）：
  - Jitter 信标间隔（±30%随机化）
  - 长间隔信标（60-300秒）
  - 有效载荷嵌入合法流量
  - 合法 Web 服务中转（Slack/Telegram/GitHub）

Level 3 — 高级规避（绕过频率分析）：
  - 非规律信标间隔
  - 仅在有数据时通信（事件驱动）
  - 使用 CDN 作为 C2 中转
  - 双通道 C2（DNS + HTTPS 混合）

防御检测要点：
  - 信标间隔统计分析（标准差 < 阈值 = 可疑）
  - 固定大小的心跳包
  - 新出现的 TLS JA3/JA4 指纹
  - 异常的证书特征
```

---

## Part B：防御视角 — 假设驱动狩猎

### 3. LOLBins/LOLBAS 狩猎

```python
# hunt_lolbins.py — LOLBins 异常使用检测
import json
from collections import Counter

# 高风险 LOLBins 进程列表
HIGH_RISK_PROCESSES = {
    "certutil.exe": {
        "suspicious_args": ["-urlcache", "-f", "-encode", "-decode", "ping", "download"],
        "normal_parents": ["services.exe", "svchost.exe"],
        "risk": "high"
    },
    "mshta.exe": {
        "suspicious_args": ["http", "https", "vbscript", "javascript", ".hta"],
        "normal_parents": ["explorer.exe"],
        "risk": "critical"
    },
    "rundll32.exe": {
        "suspicious_args": ["javascript:", "vbscript:", ".txt,", ".dat,", ".tmp,", 
                           "#1", "DllRegisterServer", "EntryPoint"],
        "normal_parents": ["explorer.exe", "svchost.exe", "services.exe"],
        "risk": "high"
    },
    "regsvr32.exe": {
        "suspicious_args": ["/i:", "http", "scrobj.dll", "/n", "/u"],
        "normal_parents": ["explorer.exe", "msiexec.exe"],
        "risk": "critical"
    },
    "wmic.exe": {
        "suspicious_args": ["process call create", "shadowcopy delete", 
                           "node:", "/namespace:", "AntiVirusProduct"],
        "normal_parents": ["explorer.exe", "cmd.exe", "taskmgr.exe"],
        "risk": "high"
    },
    "bitsadmin.exe": {
        "suspicious_args": ["/transfer", "/create", "/addfile", "http"],
        "normal_parents": ["svchost.exe", "services.exe"],
        "risk": "critical"
    },
    "msbuild.exe": {
        "suspicious_args": [".csproj", ".xml", "inline", "csharp"],
        "normal_parents": ["devenv.exe", "msbuild.exe", "dotnet.exe"],
        "risk": "high"
    },
}

def hunt_lolbins_splunk():
    """Splunk 查询 — LOLBins 异常使用"""
    queries = {
        "certutil_download": '''
index=endpoint OR index=sysmon EventCode=1 
(Image="*\\certutil.exe" AND CommandLine="*urlcache*" AND CommandLine="*http*")
| table _time, Computer, Image, CommandLine, ParentImage, User
''',
        
        "mshta_remote": '''
index=sysmon EventCode=1 Image="*\\mshta.exe"
(CommandLine="*http*" OR CommandLine="*https*")
| table _time, Computer, Image, CommandLine, ParentImage
''',
        
        "rundll32_suspicious": '''
index=sysmon EventCode=1 Image="*\\rundll32.exe"
(CommandLine="*javascript:*" OR CommandLine="*.txt,*" OR CommandLine="*.tmp,*")
| table _time, Computer, Image, CommandLine, ParentImage
''',
        
        "regsvr32_remote": '''
index=sysmon EventCode=1 Image="*\\regsvr32.exe"
(CommandLine="*/i:*http*" OR CommandLine="*scrobj.dll*")
| table _time, Computer, Image, CommandLine, ParentImage, User
''',
        
        "bitsadmin_transfer": '''
index=sysmon EventCode=1 Image="*\\bitsadmin.exe" CommandLine="*/transfer*"
| table _time, Computer, Image, CommandLine, ParentImage
''',
    }
    return queries

# Sigma 规则
LOLBIN_SIGMA_RULES = '''
title: Suspicious Certutil Usage
status: experimental
description: Detects certutil.exe used for downloading or encoding files
references:
    - https://attack.mitre.org/techniques/T1105/
author: CTI Platform
date: 2026/01/01
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-encode'
            - 'ping'
    condition: selection
falsepositives:
    - Legitimate certificate management operations
level: high
'''
```

### 4. C2 Beaconing 频率分析

```python
# beacon_detector.py — 检测网络信标行为
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

class BeaconDetector:
    """基于网络流量间隔分析检测 C2 信标"""
    
    def __init__(self, jitter_threshold=0.3, min_connections=10):
        self.jitter_threshold = jitter_threshold
        self.min_connections = min_connections
    
    def analyze_connection_intervals(self, connections):
        """
        connections: list of (timestamp, src_ip, dst_ip, dst_port, bytes_sent)
        返回可疑信标连接
        """
        # 按目标 IP 分组
        by_target = defaultdict(list)
        for ts, src, dst, port, size in connections:
            by_target[(dst, port)].append({
                "timestamp": ts, "src": src, "size": size
            })
        
        beacons = []
        for target, conn_list in by_target.items():
            if len(conn_list) < self.min_connections:
                continue
            
            # 按时间排序
            conn_list.sort(key=lambda x: x["timestamp"])
            
            # 计算间隔
            intervals = []
            for i in range(1, len(conn_list)):
                delta = (conn_list[i]["timestamp"] - conn_list[i-1]["timestamp"]).total_seconds()
                intervals.append(delta)
            
            if not intervals:
                continue
            
            # 分析间隔特征
            analysis = self._analyze_intervals(intervals)
            
            if analysis["is_beacon"]:
                beacons.append({
                    "target_ip": target[0],
                    "target_port": target[1],
                    "connections": len(conn_list),
                    "avg_interval_sec": round(analysis["mean"], 1),
                    "std_deviation": round(analysis["stdev"], 1),
                    "jitter_ratio": round(analysis["jitter"], 3),
                    "confidence": analysis["confidence"],
                    "first_seen": conn_list[0]["timestamp"],
                    "last_seen": conn_list[-1]["timestamp"],
                })
        
        return sorted(beacons, key=lambda x: x["confidence"], reverse=True)
    
    def _analyze_intervals(self, intervals):
        """分析间隔的规律性"""
        mean = statistics.mean(intervals)
        if mean == 0:
            return {"is_beacon": False}
        
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter = stdev / mean  # 变异系数
        
        # 信标判断逻辑
        is_beacon = False
        confidence = 0
        
        if jitter < 0.1:       # 非常规律
            is_beacon = True
            confidence = 95
        elif jitter < 0.2:     # 较规律
            is_beacon = True
            confidence = 85
        elif jitter < 0.3:     # 有一定 Jitter
            is_beacon = True
            confidence = 70
        elif jitter < 0.5:     # 较大 Jitter
            is_beacon = True
            confidence = 50
        
        # 额外检查：间隔是否集中在特定值附近
        mode_like = statistics.median(intervals)
        within_10pct = sum(
            1 for i in intervals 
            if abs(i - mode_like) / mode_like < 0.1
        )
        if within_10pct / len(intervals) > 0.5:
            confidence = min(100, confidence + 15)
        
        return {
            "is_beacon": is_beacon,
            "mean": mean,
            "stdev": stdev,
            "jitter": jitter,
            "confidence": confidence,
            "median": statistics.median(intervals),
        }

# Splunk 查询版
BEACON_SPLUNK = '''
index=proxy OR index=firewall 
| bucket _time span=5m
| stats count as connections, 
        dc(dest_ip) as unique_dests,
        avg(bytes_out) as avg_bytes,
        stdev(bytes_out) as stdev_bytes,
        values(dest_ip) as dest_ips
  by src_ip, _time
| where connections > 3 AND unique_dests == 1
| eventstats avg(connections) as avg_conn, 
              stdev(connections) as stdev_conn 
  by src_ip
| eval regularity = abs(connections - avg_conn) / avg_conn
| where regularity < 0.3
| table _time, src_ip, dest_ips, connections, avg_bytes, regularity
'''
```

### 5. DNS 隧道检测

```python
# dns_tunnel_detector.py — DNS 隧道狩猎
class DNSTunnelDetector:
    """检测 DNS 隧道通信"""
    
    def detect_high_entropy_domains(self, dns_logs, threshold=3.5):
        """
        检测高熵 DNS 查询（DNS 隧道特征）
        dns_logs: list of {"domain": str, "query_type": str, "src_ip": str, "bytes": int}
        """
        import math
        
        def shannon_entropy(text):
            """计算 Shannon 熵"""
            if not text:
                return 0
            freq = Counter(text)
            length = len(text)
            return -sum(
                (count / length) * math.log2(count / length)
                for count in freq.values()
            )
        
        suspicious = []
        for log in dns_logs:
            domain = log["domain"]
            # 取最左侧子域名（隧道编码部分）
            parts = domain.split(".")
            if len(parts) >= 3:
                subdomain = ".".join(parts[:-2])  # 去掉 TLD 和 SLD
            else:
                subdomain = parts[0]
            
            entropy = shannon_entropy(subdomain)
            
            # 多重判断
            flags = []
            
            # 高熵
            if entropy > threshold:
                flags.append(f"high_entropy({entropy:.1f})")
            
            # 异常长的子域名
            if len(subdomain) > 30:
                flags.append(f"long_subdomain({len(subdomain)})")
            
            # 大量 TXT/NULL 查询
            if log["query_type"] in ("TXT", "NULL", "ANY"):
                flags.append(f"suspicious_type({log['query_type']})")
            
            # 高频查询同一基域
            base_domain = ".".join(parts[-2:])
            
            if flags:
                suspicious.append({
                    "domain": domain,
                    "src_ip": log["src_ip"],
                    "entropy": round(entropy, 2),
                    "subdomain_length": len(subdomain),
                    "flags": flags,
                    "query_type": log["query_type"],
                })
        
        return sorted(suspicious, key=lambda x: x["entropy"], reverse=True)

# Splunk DNS 隧道狩猎
DNS_TUNNEL_SPLUNK = '''
index=dns 
| eval subdomain_length=len(replace(query, "\\.[^.]*\\.[^.]*$", ""))
| eval label_length=len(split(query, "."))
| where subdomain_length > 30 OR label_length > 6
| stats count as queries,
        dc(query) as unique_queries,
        values(query) as sample_queries,
        sum(response_size) as total_bytes
  by src_ip
| where queries > 50
| eval bytes_per_query = total_bytes / queries
| sort - queries
| table src_ip, queries, unique_queries, total_bytes, bytes_per_query, sample_queries
'''
```

### 6. 持久化机制狩猎

```python
# persistence_hunter.py — 持久化机制全面狩猎
class PersistenceHunter:
    """狩猎所有主要持久化机制"""
    
    # Splunk/Sigma 查询集合
    HUNTS = {
        # === 注册表 Run Key ===
        "registry_run_key": {
            "splunk": '''
index=sysmon (EventCode=12 OR EventCode=13 OR EventCode=14)
(TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" OR
 TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*")
| table _time, Computer, EventCode, TargetObject, Details, Image, User
''',
            "sigma": '''
title: Registry Run Key Modification
status: experimental
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            - '\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
    condition: selection
level: medium
tags: [attack.persistence, attack.t1547.001]
''',
            "attck": "T1547.001"
        },
        
        # === 计划任务 ===
        "scheduled_task": {
            "splunk": '''
index=windows (EventCode=4698 OR EventCode=4702)
OR index=sysmon EventCode=1 Image="*\\schtasks.exe"
(CommandLine="*/create*" OR CommandLine="*/change*")
| table _time, Computer, EventCode, TaskName, CommandLine, Image, User
''',
            "sigma": '''
title: Suspicious Scheduled Task Creation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'
    filter_legitimate:
        ParentImage|endswith:
            - '\\svchost.exe'
            - '\\services.exe'
    condition: selection and not filter_legitimate
level: medium
tags: [attack.persistence, attack.t1053.005]
''',
            "attck": "T1053.005"
        },
        
        # === WMI 事件订阅 ===
        "wmi_subscription": {
            "splunk": '''
index=sysmon EventCode=19 OR EventCode=20 OR EventCode=21
| table _time, Computer, EventCode, Name, Operation, Filter, Consumer, Image
''',
            "sigma": '''
title: WMI Event Subscription
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID:
            - 19  # WmiEventFilter
            - 20  # WmiEventConsumer
            - 21  # WmiEventConsumerToFilter
    condition: selection
level: high
tags: [attack.persistence, attack.t1546.003]
''',
            "attck": "T1546.003"
        },
        
        # === 启动文件夹 ===
        "startup_folder": {
            "splunk": '''
index=sysmon EventCode=11 
(TargetFilename="*\\Start Menu\\Programs\\Startup\\*" OR
 TargetFilename="*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
| table _time, Computer, Image, TargetFilename, User
''',
            "attck": "T1547.012"
        },
        
        # === DNS 持久化 ===
        "dns_persistence": {
            "splunk": '''
index=dns 
| stats dc(query) as unique_queries, 
        count as total_queries,
        values(query) as queries,
        values(src_ip) as sources
  by dest_ip
| where unique_queries > 100 AND total_queries > 500
| eval avg_query_length = total_queries / unique_queries
| table dest_ip, unique_queries, total_queries, sources, queries
''',
            "attck": "T1071.004"
        },
        
        # === 服务安装 ===
        "service_install": {
            "splunk": '''
index=windows EventCode=7045 OR EventCode=7036
| where NOT (ServiceName IN ("Windows Update", "WinDefend", "BITS"))
| table _time, Computer, ServiceName, ServiceFileName, ServiceType, ServiceStartType
''',
            "sigma": '''
title: New Service Installation
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter_known:
        ServiceFileName|startswith:
            - 'C:\\Windows\\'
            - 'C:\\Program Files\\'
    condition: selection and not filter_known
level: medium
tags: [attack.persistence, attack.t1543.003]
''',
            "attck": "T1543.003"
        },
    }
    
    def run_all_hunts(self):
        """返回所有狩猎查询"""
        return {name: hunt["splunk"] for name, hunt in self.HUNTS.items()}
```

### 7. 横向移动狩猎

```python
# lateral_movement_hunter.py

LATERAL_MOVEMENT_HUNTS = {
    # === WMI 横向移动 ===
    "wmi_lateral": {
        "splunk": '''
index=sysmon EventCode=1 
(Image="*\\wmic.exe" AND CommandLine="*/node:*")
| table _time, Computer, CommandLine, TargetFilename, User
| eval target_node = if(match(CommandLine, "/node:(\\S+)"), 
    replace(CommandLine, ".*?/node:(\\S+).*", "\\1"), "unknown")
''',
        "attck": "T1047",
    },
    
    # === DCOM 横向移动 ===
    "dcom_lateral": {
        "splunk": '''
index=sysmon EventCode=1 
Image="*\\mmc.exe" CommandLine="*\\ExecuteShim*" 
OR (Image="*\\svchost.exe" CommandLine="*-k DcomLaunch*")
| table _time, Computer, Image, CommandLine, SourceImage, TargetImage
''',
        "attck": "T1021.003",
    },
    
    # === PsExec ===
    "psexec_lateral": {
        "splunk": '''
index=sysmon (EventCode=1 AND Image="*\\psexec*" AND CommandLine="*\\\\*")
OR (EventCode=13 AND TargetObject="*\\services\\PSEXESVC*")
OR (EventCode=1 AND Image="*\\PSEXESVC.exe")
| table _time, Computer, EventCode, Image, CommandLine, User
''',
        "attck": "T1021.002",
    },
    
    # === RDP 异常 ===
    "rdp_anomaly": {
        "splunk": '''
index=windows EventCode=4624 LogonType=10
| stats count as rdp_logins, 
        dc(WorkstationName) as unique_sources,
        values(WorkstationName) as sources,
        dc(IpAddress) as unique_ips
  by TargetUserName, _time
| where unique_ips > 3
| table _time, TargetUserName, rdp_logins, unique_ips, sources
''',
        "attck": "T1021.001",
    },
    
    # === Pass-the-Hash ===
    "pth_detection": {
        "splunk": '''
index=windows EventCode=4624 LogonType=3
(AuthenticationPackageName="NTLM" AND TargetUserName!="ANONYMOUS LOGON")
| stats dc(IpAddress) as unique_src_ips,
        values(IpAddress) as src_ips
  by TargetUserName
| where unique_src_ips > 5
| table TargetUserName, unique_src_ips, src_ips
''',
        "attck": "T1550.002",
    },
}
```

### 8. 凭据访问狩猎

```python
# credential_hunter.py

CREDENTIAL_HUNTS = {
    # === LSASS 访问 ===
    "lsass_access": {
        "splunk": '''
index=sysmon EventCode=10 
(TargetImage="*\\lsass.exe" AND 
 NOT (SourceImage IN ("*\\svchost.exe", "*\\csrss.exe", "*\\smss.exe", "*\\wininit.exe")))
| table _time, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
| eval access_hex = tostringGrantedAccess, "hex")
| where match(access_hex, "^0x(1010|1410|143a|1f0fff|1f1fff)")
''',
        "sigma": '''
title: LSASS Memory Access
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
    filter:
        SourceImage|endswith:
            - '\\svchost.exe'
            - '\\csrss.exe'
            - '\\smss.exe'
            - '\\wininit.exe'
    condition: selection and not filter
level: high
tags: [attack.credential_access, attack.t1003.001]
''',
        "attck": "T1003.001"
    },
    
    # === SAM 数据库访问 ===
    "sam_dump": {
        "splunk": '''
index=sysmon EventCode=1 
(CommandLine="*reg*save*hklm\\sam*" OR CommandLine="*reg*save*hklm\\system*" OR
 CommandLine="*reg*save*hklm\\security*" OR CommandLine="*vssadmin*create*shadow*")
| table _time, Computer, Image, CommandLine, User
''',
        "attck": "T1003.002"
    },
    
    # === DCSync ===
    "dcsync_detect": {
        "splunk": '''
index=windows (EventCode=4662)
(ObjectType="%bf967a86-0de6-11d0-a285-00aa003049e2" 
 OR ObjectName="DS-Replication-Get-Changes*")
AND NOT (SubjectUserName IN ("*$", "NTDS*", "DC$"))
| table _time, Computer, SubjectUserName, ObjectName, Properties
''',
        "attck": "T1003.006"
    },
    
    # === Mimikatz 特征 ===
    "mimikatz_patterns": {
        "splunk": '''
index=sysmon EventCode=1 
(CommandLine="*sekurlsa*logonpasswords*" OR CommandLine="*lsadump*dcsync*" OR
 CommandLine="*kerberos*ptt*" OR CommandLine="*sekurlsa*pth*" OR
 CommandLine="*crypto*certificates*" OR CommandLine="*privilege*debug*")
| table _time, Computer, Image, CommandLine, ParentImage, User
''',
        "attck": "T1055.001"
    },
    
    # === 凭据填充 ===
    "credential_stuffing": {
        "splunk": '''
index=proxy OR index=web 
| stats count as attempts,
        dc(src_ip) as unique_ips,
        values(src_ip) as ips,
        values(user_agent) as uas
  by dest_host, user
| where attempts > 20 AND unique_ips > 3
| table dest_host, user, attempts, unique_ips, ips
| sort - attempts
''',
        "attck": "T1110.004"
    },
}
```

### 9. PowerShell 异常狩猎

```python
# powershell_hunter.py

POWERSHELL_HUNTS = {
    "encoded_commands": {
        "splunk": '''
index=windows (EventCode=4104 OR EventCode=1)
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-e *")
| table _time, Computer, CommandLine, ParentImage, User
''',
        "attck": "T1027"
    },
    
    "amsi_bypass": {
        "splunk": '''
index=windows EventCode=4104
(Message="*AMSI*" OR Message="*amsiInitFailed*" OR 
 Message="*System.Management.Automation.AmsiUtils*")
| table _time, Computer, ScriptBlockText, User
''',
        "attck": "T1562.001"
    },
    
    "download_cradles": {
        "splunk": '''
index=windows EventCode=4104
(ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*")
AND (ScriptBlockText="*New-Object*Net.WebClient*" OR 
     ScriptBlockText="*Invoke-WebRequest*" OR
     ScriptBlockText="*DownloadString*" OR
     ScriptBlockText="*Start-BitsTransfer*")
| table _time, Computer, ScriptBlockText, User
''',
        "attck": "T1059.001"
    },
    
    "suspicious_modules": {
        "splunk": '''
index=windows EventCode=4104
(ScriptBlockText="*Get-ADUser*" AND ScriptBlockText="* -Properties *" AND ScriptBlockText="*| export*")
OR (ScriptBlockText="*Get-WmiObject*" AND ScriptBlockText="*Win32_UserAccount*")
OR (ScriptBlockText="*Get-Process*" AND ScriptBlockText="*lsass*")
| table _time, Computer, ScriptBlockText, User
''',
        "attck": "T1087"
    },
}
```

### 10. Webshell 狩猎

```bash
# Webshell 狩猎 — 文件系统扫描
# 查找最近修改的 Web 可写目录中的文件
find /var/www -type f -name "*.php" -mtime -7 -ls 2>/dev/null

# 查找常见 Webshell 特征
grep -rl "eval(base64_decode\|system(\|exec(\|passthru(\|shell_exec(\|assert(\|preg_replace.*\/e\|create_function\|call_user_func" \
  /var/www/ 2>/dev/null

# 查找异常的 PHP 文件（一行超长、高熵）
find /var/www -name "*.php" -exec awk 'length($0) > 500 {print FILENAME":"NR":"length($0)}' {} \; 2>/dev/null

# IIS Webshell 狩猎
# 检查 ASPX 文件中的可疑代码
find C:\\inetpub -name "*.aspx" -exec grep -l "Process.Start\|cmd.exe\|eval(" {} \;
```

```python
# webshell_detector.py — Webshell 特征检测
import os
import re
from pathlib import Path

WEBSHELL_PATTERNS = {
    "php": [
        r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)",
        r"\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(",
        r"assert\s*\(",
        r"preg_replace\s*\(.*/[a-z]*e[a-z]*'",
        r"create_function\s*\(",
        r"call_user_func(_array)?\s*\(",
        r"system\s*\(\s*\$",
        r"passthru\s*\(\s*\$",
        r"shell_exec\s*\(\s*\$",
        r"\\x[0-9a-f]{2}",  # Hex encoding
        r"chr\s*\(\d+\)",    # Char encoding
    ],
    "aspx": [
        r"Process\.Start",
        r"cmd\.exe",
        r"eval\s*\(",
        r"Response\.Write\s*\(",
        r"Request\b.*\bInputStream",
    ],
    "jsp": [
        r"Runtime\.getRuntime\(\)\.exec",
        r"ProcessBuilder",
        r"request\.getParameter",
    ],
}

def scan_directory(root_path, extensions=None):
    """扫描目录中的 Webshell"""
    if extensions is None:
        extensions = [".php", ".aspx", ".jsp", ".jspx"]
    
    findings = []
    
    for ext in extensions:
        lang = ext.lstrip(".")
        patterns = WEBSHELL_PATTERNS.get(lang, [])
        
        for filepath in Path(root_path).rglob(f"*{ext}"):
            try:
                content = filepath.read_text(errors="ignore")
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "file": str(filepath),
                            "language": lang,
                            "pattern": pattern[:50],
                            "matches": len(matches),
                            "size": filepath.stat().st_size,
                        })
            except Exception:
                continue
    
    return sorted(findings, key=lambda x: x["matches"], reverse=True)
```

### 11. 数据外泄前兆狩猎

```python
# exfiltration_hunter.py

EXFILTRATION_HUNTS = {
    "data_staging": {
        "splunk": '''
index=sysmon EventCode=11 
(TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z"
 OR TargetFilename="*.tar.gz")
| where NOT (TargetFilename="*\\Downloads\\*" OR TargetFilename="*\\Temp\\*")
| table _time, Computer, Image, TargetFilename, User
''',
        "attck": "T1560.001"
    },
    
    "large_data_transfer": {
        "splunk": '''
index=proxy OR index=firewall
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where total_bytes > 104857600  # > 100MB
| eval total_mb = round(total_bytes / 1048576, 1)
| table src_ip, dest_ip, dest_port, total_mb
| sort - total_mb
''',
        "attck": "T1048"
    },
    
    "unusual_dns_volume": {
        "splunk": '''
index=dns
| stats sum(response_size) as total_bytes,
        count as queries,
        dc(query) as unique_domains,
        values(query) as sample_domains
  by src_ip
| eval bytes_per_query = total_bytes / queries
| where bytes_per_query > 500  # 异常大的 DNS 响应
| table src_ip, total_bytes, queries, unique_domains, bytes_per_query, sample_domains
| sort - total_bytes
''',
        "attck": "T1048.003"
    },
    
    "cloud_exfil": {
        "splunk": '''
index=proxy dest_host IN ("drive.google.com", "dropbox.com", "onedrive.live.com",
 "mega.nz", "wetransfer.com", "sendanywhere.com")
| stats sum(bytes_out) as upload_bytes by src_ip, user, dest_host
| eval upload_mb = round(upload_bytes / 1048576, 1)
| where upload_mb > 50
| table src_ip, user, dest_host, upload_mb
''',
        "attck": "T1567"
    },
}
```

### 12. 供应链入侵狩猎

```python
# supply_chain_hunter.py

SUPPLY_CHAIN_HUNTS = {
    "new_service_accounts": {
        "splunk": '''
index=windows EventCode=4720  # 用户创建
| table _time, Computer, TargetUserName, SubjectUserName, SamAccountName
| where NOT match(TargetUserName, "^(Admin|Svc|Srv|Service)")
''',
        "attck": "T1136.001"
    },
    
    "unusual_binary_signing": {
        "splunk": '''
index=sysmon EventCode=7  # Image Loaded
| eval is_signed = if(match(Signed, ".*Valid.*"), "yes", "no")
| where is_signed="no"
| stats count by Image, Signed
| sort - count
| head 50
''',
        "attck": "T1195"
    },
    
    "nuget_pip_npm_anomaly": {
        "splunk": '''
index=proxy (url="*pypi.org*" OR url="*npmjs.com*" OR url="*nuget.org*")
| stats dc(url) as unique_packages, values(url) as packages by src_ip
| where unique_packages > 50
| table src_ip, unique_packages, packages
''',
        "attck": "T1195.002"
    },
}
```

### 13. 进程注入与防御规避狩猎

```python
# evasion_hunter.py

EVASION_HUNTS = {
    "process_injection": {
        "splunk": '''
index=sysmon EventCode=8  # CreateRemoteThread
| table _time, Computer, SourceImage, TargetImage, SourceProcessId, TargetProcessId
''',
        "attck": "T1055"
    },
    
    "timestomping": {
        "splunk": '''
index=sysmon EventCode=2  # File time changed
(TargetFilename="*.exe" OR TargetFilename="*.dll" OR TargetFilename="*.ps1")
| eval creation_year = strftime(_time, "%Y")
| where creation_year < 2020
| table _time, Computer, Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime
''',
        "attck": "T1070.006"
    },
    
    "account_manipulation": {
        "splunk": '''
index=windows (EventCode=4738 OR EventCode=4728 OR EventCode=4732)
| table _time, Computer, SubjectUserName, TargetUserName, GroupName, 
        OldAdminCount, NewAdminCount
| where NewAdminCount=1 OR GroupName="Domain Admins"
''',
        "attck": "T1098"
    },
    
    "domain_fronting": {
        "splunk": '''
index=proxy 
| eval tls_sni = coalesce(ssl_server_name, http_host)
| stats count by tls_sni, dest_ip, dest_port
| eventstats dc(dest_ip) as ip_count by tls_sni
| where ip_count > 10  # 同一 SNI 解析到大量不同 IP（CDN特征）
| eval fronting_suspect = if(match(dest_ip, "^(104\\.16|104\\.17|172\\.67|141\\.101)"), "CDN_OK", "REVIEW")
| table tls_sni, dest_ip, ip_count, fronting_suspect
| sort - ip_count
''',
        "attck": "T1090.004"
    },
    
    "shadow_copy_deletion": {
        "splunk": '''
index=sysmon EventCode=1 
(CommandLine="*vssadmin*delete*shadows*" OR 
 CommandLine="*wmic*shadowcopy*delete*" OR
 CommandLine="*wbadmin*delete*catalog*" OR
 CommandLine="*Get-WmiObject*Win32_ShadowCopy*Delete*")
| table _time, Computer, Image, CommandLine, User
''',
        "attck": "T1490"
    },
}
```

---

## 速查表

### 狩猎类型 → ATT&CK → 检测矩阵

| 狩猎类别 | ATT&CK 战术/技术 | 关键数据源 | 首选工具 |
|---------|-----------------|-----------|---------|
| LOLBins | T1218/T1202 | Sysmon EID 1 | Sigma + EDR |
| Beaconing | T1071 | Proxy/NetFlow | 频率分析脚本 |
| DNS 隧道 | T1071.004 | DNS 日志 | 熵分析 + Splunk |
| 持久化-注册表 | T1547.001 | Sysmon EID 12-14 | Sigma |
| 持久化-计划任务 | T1053.005 | Win EID 4698 | Sigma |
| 持久化-WMI | T1546.003 | Sysmon EID 19-21 | WMI 监控 |
| 横向移动-WMI | T1047 | Sysmon EID 1 | Splunk |
| 横向移动-DCOM | T1021.003 | Sysmon EID 1 | EDR |
| 凭据-LSASS | T1003.001 | Sysmon EID 10 | EDR |
| 凭据-DCSync | T1003.006 | Win EID 4662 | DC 审计 |
| 凭据-Mimikatz | T1055.001 | Sysmon EID 1 | Sigma |
| Webshell | T1505.003 | 文件系统 + HTTP | 文件扫描 |
| 数据外泄 | T1048/T1567 | Proxy/Firewall | Splunk |
| 供应链 | T1195 | Sysmon EID 7 | 签名验证 |
| 进程注入 | T1055 | Sysmon EID 8 | EDR |
| 域前置 | T1090.004 | Proxy/TLS | SNI 分析 |
| Timestomping | T1070.006 | Sysmon EID 2 | 时间分析 |
| PowerShell | T1059.001 | PS ScriptBlock | AMSI + 4104 |
| 账号操纵 | T1098 | Win EID 4738 | AD 审计 |
| VSS 删除 | T1490 | Sysmon EID 1 | Sigma |

### 狩猎频率建议

| 狩猎类型 | 频率 | 耗时 | 优先级 |
|---------|------|------|--------|
| LOLBins 异常 | 每日 | 15min | P1 |
| C2 Beaconing | 每日 | 30min | P1 |
| 新增持久化 | 每日 | 15min | P1 |
| 凭据访问 | 每日 | 20min | P1 |
| DNS 异常 | 每日 | 15min | P2 |
| 横向移动 | 每周 | 60min | P2 |
| Webshell | 每周 | 30min | P2 |
| 数据外泄 | 每周 | 45min | P2 |
| 供应链 | 每月 | 120min | P3 |
| 域前置 | 每月 | 60min | P3 |

---

## MITRE ATT&CK 映射

| 战术 | 覆盖技术 | 狩猎模块 |
|------|---------|---------|
| Persistence | T1547.001, T1053.005, T1546.003, T1543.003 | persistence_hunter |
| Privilege Escalation | T1547.012, T1098 | persistence_hunter, evasion_hunter |
| Defense Evasion | T1027, T1070.006, T1562.001, T1055 | evasion_hunter, powershell_hunter |
| Credential Access | T1003.001, T1003.002, T1003.006, T1110.004 | credential_hunter |
| Discovery | T1087 | powershell_hunter |
| Lateral Movement | T1021.001, T1021.002, T1021.003, T1047, T1550.002 | lateral_movement_hunter |
| Collection | T1560.001 | exfiltration_hunter |
| Command & Control | T1071.001, T1071.004, T1090.004 | beacon_detector, dns_tunnel_detector |
| Exfiltration | T1048, T1048.003, T1567 | exfiltration_hunter |
| Impact | T1490 | evasion_hunter |
| Execution | T1059.001, T1218, T1202 | lolbin_hunter, powershell_hunter |

---

## 前置条件

1. **数据源**：Sysmon（推荐配置 SwiftOnSecurity 模板）、Windows Event Logs、DNS 日志、Proxy/Firewall 日志
2. **平台**：Splunk/Elastic SIEM、Sigma 规则引擎、EDR 控制台
3. **工具**：ATT&CK Navigator（覆盖率可视化）、Sigma CLI（规则转换）
4. **流程**：每周至少 2-3 次主动狩猎、结果文档化、有效狩猎转为自动检测
5. **技能**：ATT&CK 框架理解、Windows 内部机制、网络协议分析

---

## Part C：2025-2026 精细化补充

### C.1 AI/LLM 辅助威胁狩猎

#### 背景

AI 自动化正在重塑威胁狩猎：IBM 2025 报告显示 AI + 自动化缩短违规生命周期约 80 天；世界经济论坛 2026 数据显示 **77% 组织已采用 AI 进行网络安全**。SOC 自动化趋势预计到 2026 年 **90%+ Tier 1 告警可自主解决**（Swimlane 预测）。

#### 自主威胁狩猎平台矩阵（2026）

| 平台 | 核心能力 | 适用场景 | 集成 |
|------|---------|---------|------|
| **Dropzone AI** | AI Agent 自主调查告警 + 连续狩猎；复制精英分析师行为 | 24/7 自主狩猎，95% 手动调查削减 | Splunk/CrowdStrike/ SentinelOne |
| **Radiant Security** | L1 自主分流 + 自然语言狩猎界面 | 企业 SOC 告警自动化 | 主要 SIEM/EDR |
| **Prophet Security** | 端到端告警调查 + 自主狩猎 | 告警量大、分析师不足的团队 | 多源集成 |
| **Simbian** | AI 驱动 SOC 自动化 + 自主 Playbook | 全自动 SOC 运营 | 广泛 SIEM/SOAR |
| **D3 Security** | AI 增强调查 + 自动升级 | 企业级 MSSP 场景 | 原生 SOAR 平台 |

#### LLM 日志分析器实战脚本

```python
# llm_threat_hunter.py — LLM 辅助威胁狩猎日志分析
import json
from datetime import datetime, timedelta

class LLMThreatHunter:
    """使用 LLM 辅助分析 SIEM 日志，生成狩猎假设
    
    支持三种模式：
    1. 假设生成：基于日志摘要自动生成狩猎假设
    2. 异常检测：识别统计异常模式
    3. ATT&CK 映射：将观测行为映射到 ATT&CK 技术
    """
    
    PROMPT_TEMPLATES = {
        "hypothesis_generation": """
你是威胁狩猎专家。基于以下 SIEM 日志摘要，生成 3-5 个具体可测试的威胁狩猎假设。
每个假设应包含：假设描述、目标 ATT&CK 技术、推荐数据源、预期狩猎时长。

日志摘要：
{log_summary}

关键指标：
- 时间范围：{time_range}
- 涉及主机数：{host_count}
- 异常事件数：{anomaly_count}
- top 异常类型：{top_anomalies}
""",
        "anomaly_explanation": """
分析以下网络异常行为，判断是否为 APT/C2/横向移动/数据外泄。
返回 JSON 格式：{"verdict": "benign|suspicious|malicious", "confidence": 0-100,
"attck_technique": "Txxxx.xxx", "reasoning": "..."}

异常事件：
{anomaly_events}
""",
    }
    
    def generate_hunt_hypotheses(self, siem_summary: dict) -> list:
        """基于 SIEM 摘要生成狩猎假设"""
        hypotheses = []
        # 基于统计异常自动生成假设框架
        anomaly_types = siem_summary.get("top_anomalies", [])
        
        if "unusual_process" in anomaly_types:
            hypotheses.append({
                "hypothesis": "攻击者使用 LOLBins 执行横向移动或凭据访问",
                "attck": ["T1218", "T1047", "T1003"],
                "datasource": "Sysmon EID 1 + Security EID 4624",
                "estimated_hours": 2,
                "priority": "P1"
            })
        
        if "network_anomaly" in anomaly_types:
            hypotheses.append({
                "hypothesis": "C2 信标通信使用合法 Web 服务作为中转",
                "attck": ["T1071.001", "T1090.004", "T1102"],
                "datasource": "Proxy + DNS + NetFlow + JA4+ 指纹",
                "estimated_hours": 4,
                "priority": "P1"
            })
        
        if "credential_anomaly" in anomaly_types:
            hypotheses.append({
                "hypothesis": "Kerberoasting 或 DCSync 攻击正在域内进行",
                "attck": ["T1558.001", "T1003.006"],
                "datasource": "DC Security EID 4769 + 4662",
                "estimated_hours": 3,
                "priority": "P1"
            })
        
        return hypotheses

# 实际调用示例（需配合 LLM API）:
# hunter = LLMThreatHunter()
# summary = {"top_anomalies": ["unusual_process", "network_anomaly"], ...}
# hypotheses = hunter.generate_hunt_hypotheses(summary)
```

#### AI 狩猎成熟度模型

```
L0 — 无 AI        手动狩猎，完全依赖分析师经验
L1 — AI 辅助      LLM 生成假设、日志摘要、ATT&CK 映射建议
L2 — AI 增强      AI 自动执行常见狩猎模式，分析师审批发现
L3 — AI 自主      AI Agent 连续狩猎，自主调查告警，仅升级高置信度发现
L4 — AI 闭环      AI 狩猎 → 检测规则生成 → 自动部署 → 持续优化
```

---

### C.2 MITRE ATT&CK v19 更新映射（2026-04-28）

#### 核心变更：Defense Evasion 拆分

ATT&CK v19 最大结构性变更：**Defense Evasion (TA0005) 战术退役**，拆分为两个更精确的战术：

| 原战术 | 新战术 | ID | 覆盖范围 | 狩猎影响 |
|--------|--------|----|---------|---------|
| Defense Evasion | **Stealth** | TA0005（继承原ID） | 行为伪装、隐藏活动，防御设施不受影响 | Timestomping/进程注入/混淆等狩猎不变 |
| Defense Evasion | **Defense Impairment** | 新 ID | 主动降级、禁用安全控制 | AMSI 绕过/EDR Killing/日志清除等狩猎归入此 |

#### 其他 v19 变更

- **AI 对抗技术扩展**：新增对手利用 AI 进行攻击研究、内容生成的技术覆盖
- **ICS 子技术细化**：工业控制系统子技术扩展，增强 OT 狩猎覆盖
- **社交工程 AI 增强**：新增 AI 辅助社交工程攻击的技术映射

#### v19 狩猎迁移检查清单

```
□ 更新 ATT&CK Navigator 图层：Defense Evasion → Stealth + Defense Impairment
□ Sigma 规则 tags 更新：
    - tags: [attack.defense_evasion] → 检查是否应改为 attack.stealth 或 attack.defense_impairment
□ 检测报告模板更新：在狩猎报告中反映新战术分类
□ SIEM 仪表板：添加 Stealth 和 Defense Impairment 分类面板
□ 覆盖率评估：基于 v19 重新评估狩猎覆盖 gap
```

---

### C.3 JA4+ 网络指纹威胁狩猎

#### 背景

JA4+ 是 JA3/JA3S 的继任者，由 FoxIO 开发，提供跨协议（TLS/HTTP/SSH/DNS）的模块化网络指纹。与 JA3 相比，JA4+ 具有人类可读、机器友好、协议无关的优势，已成为 2025-2026 网络威胁狩猎的标配。

#### JA4+ 指纹套件

| 指纹 | 协议 | 用途 | 狩猎场景 |
|------|------|------|---------|
| **JA4** | TLS Client | 客户端 TLS 指纹 | C2 工具识别/恶意客户端检测 |
| **JA4S** | TLS Server | 服务器 TLS 指纹 | 恶意服务端/C2 基础设施识别 |
| **JA4H** | HTTP Client | HTTP 请求指纹 | User-Agent 伪造检测/爬虫识别 |
| **JA4L** | Network Latency | 网络延迟指纹 | 隧道/DNS 隧道/VPN 检测 |
| **JA4X** | X.509 Certificate | 证书指纹 | 自签名证书/恶意 CA 检测 |
| **JA4SSH** | SSH | SSH 会话指纹 | 恶意 SSH 会话/自动化工具检测 |

#### JA4+ C2 信标狩猎实战

```python
# ja4_beacon_hunter.py — 基于 JA4+ 指纹的 C2 信标检测
class JA4BeaconHunter:
    """结合 JA4+ 指纹与频率分析检测 C2 通信"""
    
    # 已知恶意 JA4 指纹库（持续更新）
    KNOWN_MALICIOUS_JA4 = {
        # Cobalt Strike 默认指纹变体
        "t13d1516h2_8daaf6152771_edb75500b77d": "CobaltStrike-Default",
        "t12d1516h2_8daaf6152771_edb75500b77d": "CobaltStrike-TLS12",
        # Sliver C2
        "t13d1515h2_002f523d1082_000000000000": "Sliver-C2",
        # Metasploit
        "t13d1515h2_8daaf6152771_3b7f4a6c4a77": "Metasploit-HTTPS",
    }
    
    # 可疑 JA4 指纹模式（通配符匹配）
    SUSPICIOUS_PATTERNS = [
        # 非浏览器客户端特征：缺少 ALPN / 使用罕见密码套件组合
        {"pattern": "t13d*_h2_*", "reason": "仅 HTTP/2 无 HTTP/1.1，可疑"},
        {"pattern": "t12d*__*_000000000000", "reason": "无扩展指纹，可能是自定义客户端"},
    ]
    
    def hunt_c2_with_ja4(self, zeek_logs: list) -> list:
        """结合 Zeek JA4+ 数据与信标分析"""
        # 步骤 1: 提取 JA4 指纹
        ja4_connections = {}
        for log in zeek_logs:
            ja4 = log.get("ja4", "")
            if not ja4:
                continue
            key = (log["id.orig_h"], log["id.resp_h"], log["id.resp_p"])
            ja4_connections.setdefault(key, {
                "ja4": ja4, "timestamps": []
            })["timestamps"].append(log["ts"])
        
        # 步骤 2: 匹配已知恶意指纹
        hits = []
        for conn, data in ja4_connections.items():
            ja4 = data["ja4"]
            ts_list = sorted(data["timestamps"])
            
            # 已知恶意匹配
            if ja4 in self.KNOWN_MALICIOUS_JA4:
                hits.append({
                    "type": "known_malicious",
                    "src": conn[0], "dst": conn[1], "port": conn[2],
                    "ja4": ja4,
                    "tool": self.KNOWN_MALICIOUS_JA4[ja4],
                    "connections": len(ts_list),
                    "confidence": 95,
                })
                continue
            
            # 频率分析（同 Part B Section 4 逻辑）
            if len(ts_list) >= 10:
                import statistics
                intervals = [ts_list[i+1]-ts_list[i] for i in range(len(ts_list)-1)]
                jitter = statistics.stdev(intervals) / max(statistics.mean(intervals), 0.001)
                
                if jitter < 0.3:  # 规律信标
                    hits.append({
                        "type": "beaconing_suspicious_ja4",
                        "src": conn[0], "dst": conn[1], "port": conn[2],
                        "ja4": ja4,
                        "connections": len(ts_list),
                        "avg_interval": round(statistics.mean(intervals), 1),
                        "jitter": round(jitter, 3),
                        "confidence": 70 if jitter < 0.2 else 50,
                    })
        
        return sorted(hits, key=lambda x: x["confidence"], reverse=True)

# Splunk JA4+ 狩猎查询
JA4_SPLUNK_HUNTS = '''
# 已知恶意 JA4 指纹匹配
index=zeek ja4!=""
| lookup known_malicious_ja4.csv ja4 OUTPUT tool
| where isnotnull(tool)
| stats count, values(tool) as c2_tool by id.orig_h, id.resp_h, id.resp_p, ja4

# 非浏览器 TLS 客户端检测
index=zeek ja4!=""
| eval ja4_prefix = substr(ja4, 1, 4)
| where ja4_prefix="t13d" AND NOT (ja4 LIKE "%chrome%" OR ja4 LIKE "%firefox%")
| stats dc(ja4) as unique_fingerprints by id.orig_h, id.resp_h
| where unique_fingerprints == 1
'''
```

#### JA4+ 工具集成

| 工具 | JA4+ 支持 | 用途 |
|------|----------|------|
| **Wireshark 4.4+** | 原生 JA4/JA4S 列 | 流量分析/威胁狩猎 |
| **Zeek + ja4 plugin** | JA4/JA4S/JA4H/JA4L | 网络狩猎自动化 |
| **Suricata 8.0+** | ja4 关键字 | 规则匹配 |
| **TheHive** | JA4 集成 | IR 工作流 |
| **Cloudflare** | Inter-Request Signals | 大规模网络指纹分析 |

---

### C.4 eBPF 内核级威胁狩猎

#### 背景

eBPF（Extended Berkeley Packet Filter）已成为 2025-2026 内核级威胁检测的基础设施。相比传统基于日志/系统调用的检测，eBPF 提供内核级可见性、极低性能开销、无需内核模块的优势。

#### eBPF 安全工具对比矩阵

| 特性 | **Falco** | **Tetragon** | **Tracee** |
|------|----------|-------------|-----------|
| 核心能力 | 检测（Detection-only） | 检测 + 执行（Enforcement） | 检测 + 追踪 |
| eBPF 深度 | 系统调用层 | 内核全栈追踪点 | 系统调用 + 内核 |
| 规则引擎 | YAML 规则（成熟） | TracingPolicy（K8s 原生） | Go 规则 |
| 实时阻断 | 不支持 | 支持（内核级执行控制） | 不支持 |
| K8s 集成 | DaemonSet | Cilium 生态 | Aqua Security |
| 性能开销 | 低 | 极低 | 低 |
| AI/ML 集成 | 规则生成 | 事件流训练模型 | 实验性 |
| 社区成熟度 | 最成熟（CNCF 孵化） | 快速增长（Cilium 企业版） | Aqua 维护 |
| 迁移趋势 | → Tetragon（需执行能力时） | 默认选择（2026） | 轻量场景 |

#### Tetragon TracingPolicy 狩猎示例

```yaml
# tetragon-hunt-process-injection.yaml
# 检测跨进程内存写入（进程注入指标）
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: hunt-process-injection
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchNames:
      - namespace: "default"
      matchBinaries:
      - operator: "NotIn"
        values:
        - "/usr/bin/containerd"
        - "/usr/bin/dockerd"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: 10s
```

#### eBPF 狩猎场景覆盖

| 场景 | Falco 规则 | Tetragon TracingPolicy | 检测能力 |
|------|-----------|----------------------|---------|
| 容器逃逸 | `Container Escaping` | 内核层追踪 | Tetragon 更深 |
| 进程注入 | `Detect ptrace` | 追踪 `process_vm_writev` | 两者均可 |
| io_uring rootkit | 不覆盖 | 追踪 `io_uring_setup` | 仅 Tetragon |
| 网络连接异常 | 系统调用级 | TCP 层 + BPF | Tetragon 更精确 |
| 文件完整性 | `Sensitive File Access` | VFS 层追踪 | 两者均可 |

---

### C.5 云原生威胁狩猎

#### Kubernetes 狩猎查询集

```python
# k8s_threat_hunter.py — K8s 环境威胁狩猎
K8S_HUNTS = {
    "privilege_escalation_pod": {
        "description": "检测特权容器/HostPID/HostNetwork Pod",
        "kubectl": '''
kubectl get pods -A -o json | jq -r '.items[] |
  select(.spec.containers[].securityContext.privileged == true
    or .spec.hostPID == true
    or .spec.hostNetwork == true
    or .spec.containers[].securityContext.capabilities.add[] == "SYS_ADMIN") |
  "\(.metadata.namespace)/\(.metadata.name): privileged=\(.spec.containers[].securityContext.privileged) hostPID=\(.spec.hostPID)"'
''',
        "attck": "T1611",
    },
    
    "suspicious_cronjob": {
        "description": "检测可疑 CronJob（反弹 Shell/下载执行）",
        "kubectl": '''
kubectl get cronjobs -A -o json | jq -r '.items[] |
  select(.spec.jobTemplate.spec.template.spec.containers[].command[] |
    test("nc |ncat|/dev/tcp|curl.*\\|.*sh|wget.*\\|.*sh|base64.*-d")) |
  "\(.metadata.namespace)/\(.metadata.name): \(.spec.jobTemplate.spec.template.spec.containers[].command)"'
''',
        "attck": "T1053.007",
    },
    
    "secret_access_anomaly": {
        "description": "异常 Secret 访问（大量读取/非预期命名空间）",
        "audit_log": '''
# K8s Audit Log 查询（Elastic）
kubernetes.audit.logs* 
  AND verb:"get" AND objectRef.resource:"secrets"
  | stats count by user.username, objectRef.namespace, objectRef.name
  | where count > 10
  | sort -count
''',
        "attck": "T1552.007",
    },
    
    "new_admission_controller": {
        "description": "新安装的 ValidatingWebhook/MutatingWebhook（后门风险）",
        "kubectl": '''
kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations -A -o json | 
  jq -r '.items[] | "\(.kind)/\(.metadata.name): \(.webhooks[].clientConfig.service)"' |
  grep -v "kube-system\|cert-manager\|gatekeeper"
''',
        "attck": "T1554",
    },
}

# AWS 云狩猎
AWS_CLOUD_HUNTS = {
    "role_assumption_chain": {
        "description": "检测异常长度的角色假设链（提权指标）",
        "splunk": '''
index=aws_cloudtrail eventName=AssumeRole
| transaction userIdentity.arn maxspan=1h
| eval chain_length = eventcount
| where chain_length > 3
| table _time, userIdentity.arn, chain_length, requestParameters.roleArn
''',
        "attck": "T1548.001",
    },
    
    "s3_data_exfil": {
        "description": "异常 S3 下载（大量 GetObject）",
        "splunk": '''
index=aws_cloudtrail eventName=GetObjects
| stats count as downloads, sum(requestParameters.length) as bytes
  by userIdentity.arn, requestParameters.bucketName
| eval mb = round(bytes/1048576, 1)
| where mb > 100
| table userIdentity.arn, requestParameters.bucketName, downloads, mb
''',
        "attck": "T1530",
    },
}
```

---

### C.6 2025-2026 威胁狩猎态势统计

| 指标 | 数据 | 来源 |
|------|------|------|
| 全球威胁狩猎市场规模（2025） | $39.8B | Fortune Business Insights |
| 预计市场规模（2034） | $141.6B（CAGR 15.14%） | Fortune Business Insights |
| AI 缩短违规生命周期 | ~80 天 | IBM Cost of Data Breach 2025 |
| 组织 AI 网络安全采用率 | 77% | WEF 2026 |
| Tier-1 告警自主解决率预期 | 90%+ | Swimlane 2026 |
| 单次狩猎平均耗时 | ~40 小时跨工具调查 | Dropzone AI 2026 |
| AI 增强检测速度提升 | 73% | Unit 42 IR Report |
| 攻击者利用 AI 增长 | 89% | GTI 2026 Core Findings |
| 无文件攻击占比 | 75% | GTI 2026 Core Findings |

---

### C.7 工具生态更新

#### 狩猎工具矩阵 v2.0（2026）

| 工具 | 类型 | 版本 | 关键更新 | 适用场景 |
|------|------|------|---------|---------|
| **Velociraptor** | 端点取证/狩猎 | v0.77+ | VQL 增强 + Fedora RPM + K8s 集群采集 | 端点狩猎 + DFIR |
| **Elastic EASE** | AI SOC Engine | 2026 GA | AI 驱动告警分流 + 自动调查 | 大规模 SOC |
| **Sigma** | 检测规则 | v3.x | v19 tags + CI/CD Pipeline | 规则生命周期管理 |
| **ATT&CK Navigator** | 覆盖率可视化 | v7+ | v19 多层支持 + Stealth/Impair 层 | 狩猎覆盖 Gap 分析 |
| **Falco** | eBPF 运行时 | v0.40+ | 新规则关键字 + 性能优化 | 容器检测 |
| **Tetragon** | eBPF 内核级 | v1.3+ | TracingPolicy + 执行控制 | K8s 深度检测 |
| **Zeek** | 网络分析 | v8.0 | JA4+ 原生 + Telemetry 框架 | 网络狩猎 |
| **Suricata** | IDS/IPS | v8.0 | ja4 关键字 + entropy 匹配 | 规则化网络检测 |
| **Dropzone AI** | AI 自主狩猎 | 2026 | AI Threat Hunter 连续自主狩猎 | 24/7 自主狩猎 |
| **TheHive** | IR 平台 | v5.x | JA4 集成 + Cortex AI 分析器 | IR 工作流 |
| **YARA** | 文件检测 | v4.5 / YARA-X | YARA-X Rust 重写 2-5x 性能 | 文件/内存扫描 |

---

### C.8 中文社区精华参考

| 主题 | 来源 | 关键内容 |
|------|------|---------|
| 威胁狩猎综述 | 安全客 (secrss.com) | 定义、方法论（Sqrrl/TAQ/MITRE）、未来发展路线 |
| 威胁狩猎流程详解 | 长亭百川云 | 数据收集→假设建立→工具分析→情报丰富 完整流程 |
| 阿里云威胁狩猎服务 | 阿里云产品 | 高交互蜜罐 + 欺骗伪装 + 专家运营模式 |
| AI 时代威胁狩猎 | 51CTO | 介于 EASM 和 SOC 之间的定位、AI 自动化趋势 |
| 威胁情报前沿趋势 | 知乎专栏 | 一键威胁狩猎、AI 攻击增长 89%、无文件攻击 75% |
| 奇安信威胁态势 | 奇安信 | 2024 漏洞态势、威胁狩猎最佳实践 |
| IBM X-Force 2026 | IBM | 自主安全运营中心、Agentic AI 增强狩猎到修复全流程 |
| 绿盟全球威胁狩猎 | 绿盟科技 | 伏影实验室监测数据、DDoS 威胁报告 |
| CrowdStrike TI | CrowdStrike | Threat AI 自动化、实时指标、暗网监控 |
| Fortinet 2026 威胁态势 | Fortinet | AI 攻击利用 + 暗网 + 自动化防御策略 |

---

### 防御升级路线图

```
P0 — 即时（0-30 天）
  □ 更新 ATT&CK 映射至 v19（Stealth + Defense Impairment）
  □ 部署 JA4+ 指纹采集（Zeek/Suricata 升级）
  □ 验证 eBPF 检测覆盖（Falco/Tetragon 基线规则集）
  □ Sigma 规则 tags 更新至 v19

P1 — 短期（1-3 月）
  □ 建立 AI 辅助狩猎 PoC（LLM 日志分析/假设生成）
  □ 云原生狩猎查询集部署（K8s/AWS/Azure）
  □ eBPF 运行时检测覆盖评估
  □ JA4+ 已知恶意指纹库建设与自动化匹配

P2 — 中期（3-6 月）
  □ AI 狩猎成熟度从 L1 提升至 L2（AI 增强模式）
  □ Tetragon TracingPolicy 自定义规则开发
  □ 狩猎结果 → Sigma 规则自动化管线建设
  □ 供应链/容器/无服务器狩猎专项

P3 — 长期（6-12 月）
  □ AI 自主狩猎平台评估（Dropzone AI/Radiant 等）
  □ eBPF + AI/ML 威胁检测模型训练
  □ 跨集群/多云威胁关联分析能力
  □ 狩猎成熟度目标：L3（AI 自主 + 人工审批）
```
