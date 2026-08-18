---
name: ir-timeline-analysis
description: >
  安全事件时间线重建手册：覆盖使用 Plaso/log2timeline 和 Timesketch 进行日志时间线分析、
  多源证据关联、时间戳规范化、事件序列重建、可视化时间线分析的完整流程。
  包含攻击者行为时间线重建、取证时间线分析和事件响应时间线报告生成技术。
domain: cybersecurity
subdomain: incident-response
tags: [timeline-analysis, plaso, timesketch, forensics, incident-response, log-analysis, timestamp-correlation]
version: 2.0.0
---

# 事件时间线分析 — 完整攻防手册

## 适用场景

- 安全事件调查，需要从多源日志重建完整攻击时间线
- 数字取证分析，需要关联磁盘镜像、日志、内存数据的时间戳
- 事件响应报告，需要生成可视化时间线展示攻击序列
- 合规审计，需要证明事件响应流程的时间戳完整性

**不适用于**：实时监控（使用 SIEM）、非时间序列数据分析。

## 前置条件

- Python 3.8+（Plaso/log2timeline 依赖）
- Plaso 工具套件（log2timeline, psort, pinfo）
- Timesketch 平台（Docker 或手动部署）
- Elasticsearch 7.x/8.x（Timesketch 后端）
- 取证镜像访问权限（E01/dd/raw）
- 管理员/root 权限（安装工具）

---

## Part A：攻击方法论（攻击者时间线视角）

### 1. 攻击时间线重建分析

#### 1.1 典型 APT 攻击时间线

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    APT 攻击时间线模型                                     │
├──────┬──────────┬──────────────────────────────────────────────────────┤
│ 阶段  │ 时间跨度  │ 关键时间点                                          │
├──────┼──────────┼──────────────────────────────────────────────────────┤
│ 侦察  │ D-30~D-1 │ 域名注册、OSINT、扫描开始时间                         │
│ 初始  │ D-Day     │ 首次漏洞利用/钓鱼投递时间                             │
│ 驻留  │ D+1~D+7  │ 后门部署、持久化建立时间                              │
│ 扩展  │ D+7~D+30 │ 横向移动、权限提升时间点                              │
│ 目标  │ D+30~D+60│ 数据定位、收集、打包时间                              │
│ 外泄  │ D+60+    │ 数据传输、C2 通信时间窗口                             │
└──────┴──────────┴──────────────────────────────────────────────────────┘
```

#### 1.2 时间线中的关键事件标记

```python
# 时间线分析中的关键事件类型及优先级
TIMELINE_EVENT_TYPES = {
    # 初始访问指标
    "INITIAL_ACCESS": {
        "priority": 1,
        "events": [
            "first_suspicious_login",
            "exploit_attempt",
            "phish_delivery",
            "malware_execution"
        ]
    },
    # 执行指标
    "EXECUTION": {
        "priority": 2,
        "events": [
            "powershell_execution",
            "cmd_execution",
            "wmi_execution",
            "scheduled_task_creation",
            "service_installation"
        ]
    },
    # 持久化指标
    "PERSISTENCE": {
        "priority": 3,
        "events": [
            "registry_run_key_modified",
            "startup_folder_modified",
            "wmi_subscription_created",
            "service_created",
            "account_created"
        ]
    },
    # 横向移动指标
    "LATERAL_MOVEMENT": {
        "priority": 4,
        "events": [
            "psexec_connection",
            "wmi_remote",
            "rdp_connection",
            "smb_connection",
            "pass_the_hash"
        ]
    },
    # 数据窃取指标
    "EXFILTRATION": {
        "priority": 5,
        "events": [
            "large_data_transfer",
            "dns_tunneling",
            "cloud_upload",
            "archive_creation",
            "staging_directory_created"
        ]
    }
}
```

### 2. 时间戳伪造与检测

#### 2.1 Timestomping 攻击

```powershell
# 攻击者修改文件时间戳以规避检测（T1070.006）
# 修改文件的创建/修改/访问时间
$file = "C:\malware\payload.exe"
$orig = (Get-Item "C:\Windows\System32\cmd.exe").CreationTime

# 方法 1: PowerShell
$(Get-Item $file).CreationTime = $orig
$(Get-Item $file).LastWriteTime = $orig
$(Get-Item $file).LastAccessTime = $orig

# 方法 2: cmd
cmd /c copy /b payload.exe +,,  # 修改时间为当前时间

# 方法 3: API 调用（C#）
# [System.IO.File]::SetCreationTime(path, fakeTime)
# [System.IO.File]::SetLastWriteTime(path, fakeTime)
```

#### 2.2 Timestomping 检测

```python
#!/usr/bin/env python3
"""
Timestomping 检测工具
检测文件时间戳是否被人工修改
"""
import os
import struct
from datetime import datetime

def check_mft_timestamps(mft_entry):
    """
    分析 NTFS $MFT 条目中的时间戳
    检测 FN (File Name) 和 SI (Standard Information) 时间戳不一致

    NTFS 存储两套时间戳：
    - $STANDARD_INFORMATION (SI): 用户可见，可被修改
    - $FILE_NAME (FN): NTFS 内部维护，不可通过常规 API 修改

    如果 SI 和 FN 时间戳不一致 → 可能被 timestomped
    """
    anomalies = []

    # 假设已解析 MFT 条目
    si_times = mft_entry.get('si_times', {})  # Standard Information
    fn_times = mft_entry.get('fn_times', {})  # File Name

    for time_type in ['created', 'modified', 'accessed']:
        si = si_times.get(time_type)
        fn = fn_times.get(time_type)

        if si and fn:
            diff = abs((si - fn).total_seconds())
            if diff > 300:  # 超过 5 分钟差异
                anomalies.append({
                    "type": time_type,
                    "si_time": si.isoformat(),
                    "fn_time": fn.isoformat(),
                    "diff_seconds": diff,
                    "indicator": "TIMESTAMP_ANOMALY"
                })

    return anomalies
```

### 3. 日志时间线操纵

```
攻击者日志操纵技术（T1070）：

1. 事件日志清除
   wevtutil cl Security
   → 检测：事件 ID 1102（日志清除）

2. 日志服务停止
   sc stop eventlog
   → 检测：服务状态变更事件

3. 时间修改
   net time \\dc /set /yes
   w32tm /config /manualpeerlist:"attacker-ntp" /update
   → 检测：系统时间变更事件（ID 4616）

4. 日志轮转加速
   修改日志大小限制 → 快速轮转覆盖旧日志
   → 检测：日志间隙检测

防御策略：
- 集中式日志收集（SIEM/ syslog）
- 日志转发（agent → 集中服务器）
- 不可变日志存储（WORM/写一次读多次）
- 端点日志完整性监控
```

---

## Part B：检测与分析工具

### 4. Plaso/log2timeline 使用

#### 4.1 安装

```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:gift/stable
sudo apt update
sudo apt install plaso-tools

# macOS
pip install plaso

# Docker
docker pull log2timeline/plaso

# 验证安装
log2timeline.py --version
psort.py --version
```

#### 4.2 从取证镜像提取时间线

```bash
# === 基本用法：从磁盘镜像提取时间线 ===

# 步骤 1: 提取时间线数据
log2timeline.py --storage-file /evidence/case01.plaso /evidence/disk_image.E01

# 带详细信息输出
log2timeline.py --storage-file /evidence/case01.plaso \
  --status-view linear \
  --parsers win7 \
  /evidence/disk_image.E01

# 步骤 2: 查看提取信息
pinfo.py /evidence/case01.plaso

# 步骤 3: 过滤和输出
# 按时间范围过滤
psort.py -o dynamic -w /output/timeline.csv /evidence/case01.plaso \
  "date > '2024-01-15 08:00:00' AND date < '2024-01-15 18:00:00'"

# 按事件类型过滤
psort.py -o dynamic -w /output/suspicious.csv /evidence/case01.plaso \
  "source_short == 'LOG' AND source_long CONTAINS 'Security'"

# 输出为 JSONL（用于 Timesketch 导入）
psort.py -o jsonl -w /output/timeline.jsonl /evidence/case01.plaso
```

#### 4.3 从多个数据源提取

```bash
# === 多源数据提取 ===

# Windows 事件日志
log2timeline.py --storage-file /evidence/case01.plaso \
  --parsers winevtx \
  /evidence/evtx_logs/

# Windows 注册表
log2timeline.py --storage-file /evidence/case01.plaso \
  --parsers regf \
  /evidence/registry/

# 浏览器数据
log2timeline.py --storage-file /evidence/case01.plaso \
  --parsers webhist \
  /evidence/browser_data/

# Prefetch 文件
log2timeline.py --storage-file /evidence/case01.plaso \
  --parsers winprefetch \
  /evidence/prefetch/

# 合并多个 plaso 文件
psort.py --storage-file /evidence/merged.plaso /evidence/case01.plaso
psort.py --storage-file /evidence/merged.plaso /evidence/case02.plaso

# 自定义解析器列表
log2timeline.py --storage-file /evidence/case01.plaso \
  --parsers "winevtx,regf,webhist,winprefetch,mft,pe,lnk" \
  /evidence/disk_image.E01
```

#### 4.4 关键时间线查询

```bash
# === 常用取证时间线查询 ===

# 1. 查找所有程序执行记录
psort.py -o dynamic -w /executions.csv /evidence/case01.plaso \
  "parser == 'winevtx' AND source_long == 'Security Event Log'"

# 2. 查找特定时间段的所有文件操作
psort.py -o dynamic -w /file_ops.csv /evidence/case01.plaso \
  "date > '2024-01-15 02:00:00' AND date < '2024-01-15 06:00:00' AND source_short == 'FILE'"

# 3. 查找可疑的注册表修改
psort.py -o dynamic -w /reg_mods.csv /evidence/case01.plaso \
  "parser == 'regf' AND (key_path CONTAINS 'Run' OR key_path CONTAINS 'RunOnce')"

# 4. 查找网络连接时间线
psort.py -o dynamic -w /network.csv /evidence/case01.plaso \
  "source_short == 'LOG' AND message CONTAINS 'Network'"

# 5. 查找用户登录时间线
psort.py -o dynamic -w /logons.csv /evidence/case01.plaso \
  "parser == 'winevtx' AND (message CONTAINS '4624' OR message CONTAINS '4625')"
```

### 5. Timesketch 使用

#### 5.1 部署

```bash
# === Docker 部署 ===

# 克隆 Timesketch
git clone https://github.com/google/timesketch.git
cd timesketch

# 使用 Docker Compose 部署
docker compose up -d

# 创建管理员用户
docker exec -it timesketch-web tsctl create-user admin --password

# 访问 Web 界面
# http://localhost:5000
```

#### 5.2 导入数据并分析

```bash
# === 数据导入 ===

# 导入 CSV 时间线
tsctl import_csv --timeline_name "Windows Security Events" \
  --timeline_id 1 /output/timeline.csv

# 导入 Plaso 文件
tsctl import_plaso --timeline_name "Disk Image Timeline" \
  /evidence/case01.plaso

# 导入 JSONL 文件
tsctl import_jsonl --timeline_name "Network Logs" \
  /output/network.jsonl

# === 通过 Web API 导入 ===
# 使用 tsctl 或 curl
curl -X POST http://localhost:5000/api/v1/timelines/ \
  -H "Authorization: Bearer $TOKEN" \
  -F "timeline_name=IR Case 01" \
  -F "file=@/evidence/case01.plaso"
```

#### 5.3 时间线分析技术

```
=== Timesketch 分析工作流 ===

1. 创建调查 (Sketch)
   └─ 关联多个时间线到一个调查中

2. 搜索与过滤
   ├─ 全文搜索关键词
   ├─ 时间范围过滤
   ├─ 事件类型过滤
   └─ 自定义查询语言

3. 标注与分类
   ├─ 手动标注可疑事件
   ├─ 添加注释说明
   ├─ 使用颜色编码区分事件类型
   └─ 创建事件聚合视图

4. 时间线可视化
   ├─ 柱状图视图（事件密度）
   ├─ 时间轴视图（事件序列）
   └─ 甘特图视图（活动持续时间）

5. 分析器 (Analyzers)
   ├─ 自动标记已知 IOC
   ├─ 域名/URL 信誉检查
   ├─ 文件哈希比对
   └─ 时间间隙检测
```

#### 5.4 Timesketch 查询语法

```
=== Timesketch 搜索查询语法 ===

# 基本搜索
"malware.exe"                          # 全文搜索
source_short:"FILE"                    # 按字段搜索
date:"2024-01-15"                      # 按日期搜索

# 组合查询
"malware.exe" AND source_short:"FILE"
"powershell" AND (message:"Invoke" OR message:"Download")

# 时间范围
date:>="2024-01-15 08:00:00" AND date:<="2024-01-15 18:00:00"

# 通配符
filename:*.exe
message:*lateral*

# 排除
"svchost" AND NOT "expected_path"

# 正则表达式
message:/evil\d{2,4}\.exe/
```

### 6. 多源时间线关联

#### 6.1 时间戳规范化

```python
#!/usr/bin/env python3
"""
多源时间线数据规范化工具
将不同格式的时间戳统一为 ISO 8601 格式
"""
from datetime import datetime, timezone
import re
import json

class TimestampNormalizer:
    """统一不同数据源的时间戳格式"""

    FORMATS = {
        # Windows FILETIME (100ns intervals since 1601-01-01)
        "windows_filetime": lambda ts: datetime.fromtimestamp(
            (int(ts) - 116444736000000000) / 10000000, tz=timezone.utc
        ),
        # Unix epoch (seconds)
        "unix_epoch": lambda ts: datetime.fromtimestamp(int(ts), tz=timezone.utc),
        # Unix epoch (milliseconds)
        "unix_epoch_ms": lambda ts: datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc),
        # ISO 8601
        "iso8601": lambda ts: datetime.fromisoformat(ts.replace('Z', '+00:00')),
        # Windows Event Log time
        "wevt_time": lambda ts: datetime.fromisoformat(ts),
        # Syslog format
        "syslog": lambda ts: datetime.strptime(ts, "%b %d %H:%M:%S").replace(
            year=datetime.now().year, tzinfo=timezone.utc
        ),
    }

    @classmethod
    def normalize(cls, timestamp, format_type=None):
        """将任意格式时间戳规范化为 ISO 8601"""
        if format_type and format_type in cls.FORMATS:
            dt = cls.FORMATS[format_type](timestamp)
            return dt.isoformat()

        # 自动检测
        try:
            ts = int(timestamp)
            if ts > 130000000000000000:  # Windows FILETIME
                return cls.normalize(timestamp, "windows_filetime")
            elif ts > 1000000000000:  # Unix ms
                return cls.normalize(timestamp, "unix_epoch_ms")
            else:  # Unix seconds
                return cls.normalize(timestamp, "unix_epoch")
        except ValueError:
            pass

        # 尝试 ISO 格式
        try:
            return cls.FORMATS["iso8601"](timestamp).isoformat()
        except Exception:
            pass

        return None

    @classmethod
    def merge_timelines(cls, *timeline_files):
        """合并多个时间线文件，按时间排序"""
        events = []
        for filepath in timeline_files:
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if 'datetime' in event:
                            events.append(event)
                    except json.JSONDecodeError:
                        continue

        # 按时间排序
        events.sort(key=lambda e: e.get('datetime', ''))
        return events
```

#### 6.2 关联分析脚本

```python
#!/usr/bin/env python3
"""
多源时间线关联分析
关联磁盘取证、网络日志、认证日志中的事件
"""
import json
from collections import defaultdict
from datetime import datetime, timedelta

class TimelineCorrelator:
    def __init__(self, correlation_window_minutes=5):
        self.window = timedelta(minutes=correlation_window_minutes)
        self.events_by_type = defaultdict(list)

    def add_events(self, source_type, events_file):
        """加载事件数据"""
        with open(events_file) as f:
            for line in f:
                event = json.loads(line)
                event['_source'] = source_type
                if 'datetime' in event:
                    self.events_by_type[source_type].append(event)

    def correlate_around(self, pivot_time, pivot_type=None):
        """
        围绕指定时间点查找关联事件
        在所有数据源中查找 ± window 内的事件
        """
        pivot_dt = datetime.fromisoformat(pivot_time.replace('Z', '+00:00'))
        correlated = {}

        for source_type, events in self.events_by_type.items():
            if pivot_type and source_type == pivot_type:
                continue
            matching = []
            for event in events:
                try:
                    event_dt = datetime.fromisoformat(
                        event['datetime'].replace('Z', '+00:00')
                    )
                    if abs(event_dt - pivot_dt) <= self.window:
                        matching.append(event)
                except (ValueError, KeyError):
                    continue
            if matching:
                correlated[source_type] = matching

        return correlated

    def find_attack_sequence(self, ioc_time, lookback_hours=24, lookforward_hours=2):
        """
        从 IOC 时间点重建攻击序列
        向前看 24h（初始访问），向后看 2h（后续行为）
        """
        ioc_dt = datetime.fromisoformat(ioc_time.replace('Z', '+00:00'))
        start = ioc_dt - timedelta(hours=lookback_hours)
        end = ioc_dt + timedelta(hours=lookforward_hours)

        sequence = []
        for source_type, events in self.events_by_type.items():
            for event in events:
                try:
                    event_dt = datetime.fromisoformat(
                        event['datetime'].replace('Z', '+00:00')
                    )
                    if start <= event_dt <= end:
                        sequence.append({
                            'timestamp': event['datetime'],
                            'source': source_type,
                            'message': event.get('message', ''),
                            'type': event.get('source_short', '')
                        })
                except (ValueError, KeyError):
                    continue

        sequence.sort(key=lambda e: e['timestamp'])
        return sequence
```

### 7. 时间线报告生成

#### 7.1 自动化报告模板

```python
#!/usr/bin/env python3
"""
时间线分析报告生成器
输出 Markdown 格式的事件时间线报告
"""

def generate_timeline_report(case_id, events, output_path):
    """生成时间线分析报告"""
    report = []
    report.append(f"# 安全事件时间线分析报告 — 案例 {case_id}\n")
    report.append(f"生成时间: {datetime.now().isoformat()}\n")
    report.append(f"事件总数: {len(events)}\n")

    # 按阶段分组
    phases = {
        "初始访问": [],
        "执行": [],
        "持久化": [],
        "权限提升": [],
        "横向移动": [],
        "数据窃取": [],
        "其他": []
    }

    for event in events:
        phase = classify_event_phase(event)
        phases[phase].append(event)

    # 按阶段输出
    for phase_name, phase_events in phases.items():
        if not phase_events:
            continue
        report.append(f"\n## {phase_name}\n")
        report.append("| 时间 | 来源 | 事件描述 | 数据源 |")
        report.append("|------|------|---------|--------|")
        for event in phase_events:
            ts = event.get('datetime', 'N/A')[:19]
            source = event.get('_source', 'N/A')
            desc = event.get('message', 'N/A')[:80]
            data_type = event.get('source_short', 'N/A')
            report.append(f"| {ts} | {source} | {desc} | {data_type} |")

    # 时间线摘要
    if events:
        first = events[0].get('datetime', 'N/A')[:19]
        last = events[-1].get('datetime', 'N/A')[:19]
        report.append(f"\n## 时间线摘要\n")
        report.append(f"- 最早事件: {first}")
        report.append(f"- 最晚事件: {last}")
        report.append(f"- 活动持续时间: {calculate_duration(first, last)}")

    with open(output_path, 'w') as f:
        f.write('\n'.join(report))

    return output_path
```

### 8. 时间间隙检测

#### 8.1 日志间隙分析

```python
#!/usr/bin/env python3
"""
日志时间间隙检测
检测事件日志中的异常间隙（可能被攻击者清除）
"""
from datetime import datetime, timedelta

def detect_log_gaps(events, expected_interval_minutes=5, anomaly_threshold_multiplier=10):
    """
    检测日志中的时间间隙

    Args:
        events: 按时间排序的事件列表（需要 datetime 字段）
        expected_interval_minutes: 预期日志间隔（分钟）
        anomaly_threshold_multiplier: 异常阈值倍数
    """
    if len(events) < 2:
        return []

    gaps = []
    expected = timedelta(minutes=expected_interval_minutes)
    threshold = expected * anomaly_threshold_multiplier

    for i in range(1, len(events)):
        prev_dt = datetime.fromisoformat(events[i-1]['datetime'].replace('Z', '+00:00'))
        curr_dt = datetime.fromisoformat(events[i]['datetime'].replace('Z', '+00:00'))
        gap = curr_dt - prev_dt

        if gap > threshold:
            gaps.append({
                "gap_start": prev_dt.isoformat(),
                "gap_end": curr_dt.isoformat(),
                "gap_duration": str(gap),
                "gap_minutes": gap.total_seconds() / 60,
                "expected_minutes": expected_interval_minutes,
                "anomaly_ratio": gap.total_seconds() / expected.total_seconds(),
                "severity": "HIGH" if gap > threshold * 2 else "MEDIUM"
            })

    return gaps
```

---

## 速查表

### 速查表 1：Plaso 常用命令

| 用途 | 命令 |
|------|------|
| 从 E01 提取 | `log2timeline.py --storage-file out.plaso image.E01` |
| 指定解析器 | `log2timeline.py --parsers winevtx,regf out.plaso image.E01` |
| 查看 plaso 信息 | `pinfo.py out.plaso` |
| 按时间过滤 | `psort.py -o csv -w out.csv file.plaso "date > '2024-01-01'"` |
| 按关键词搜索 | `psort.py -o csv -w out.csv file.plaso "message CONTAINS 'powershell'"` |
| 输出 JSONL | `psort.py -o jsonl -w out.jsonl file.plaso` |
| 合并 plaso | `psort.py --storage-file merged.plaso file1.plaso` |
| Windows 解析器 | `--parsers win7` (包含 evtx, regf, prefetch, mft 等) |
| Linux 解析器 | `--parsers linux` (包含 syslog, auth, wtmp 等) |

### 速查表 2：关键 Windows 事件 ID 时间线

| Event ID | 来源 | 含义 | 阶段 |
|----------|------|------|------|
| 4624 | Security | 登录成功 | 初始访问/横向移动 |
| 4625 | Security | 登录失败 | 暴力破解 |
| 4648 | Security | 显式凭据登录 | 横向移动 |
| 4672 | Security | 特权登录 | 权限提升 |
| 4688 | Security | 进程创建 | 执行 |
| 4697 | Security | 服务安装 | 持久化 |
| 4720 | Security | 用户创建 | 持久化 |
| 4732 | Security | 用户添加到管理员组 | 权限提升 |
| 4728 | Security | 用户添加到全局组 | 权限提升 |
| 4740 | Security | 账户锁定 | 防御 |
| 4768 | Security | Kerberos TGT 请求 | 认证 |
| 4769 | Security | Kerberos 服务票据 | Kerberoasting |
| 7045 | System | 新服务创建 | 持久化 |
| 1102 | Security | 日志清除 | 防御规避 |
| 4616 | Security | 系统时间变更 | 防御规避 |
| 1 | Sysmon | 进程创建 | 执行 |
| 3 | Sysmon | 网络连接 | C2/外泄 |
| 7 | Sysmon | 模块加载 | DLL 注入 |
| 8 | Sysmon | CreateRemoteThread | 进程注入 |
| 13 | Sysmon | 注册表值设置 | 持久化 |
| 23 | Sysmon | 文件删除 | 防御规避 |

### 速查表 3：时间线数据源优先级

| 优先级 | 数据源 | 时间精度 | 抗篡改性 | 信息丰富度 |
|--------|--------|---------|---------|-----------|
| 1 | 内存镜像 | 纳秒级 | 高（RAM 易失） | 高（运行进程/网络连接） |
| 2 | MFT/$LogFile | 100ns | 中（FN 时间戳不可改） | 高（文件操作历史） |
| 3 | Windows 事件日志 | 毫秒级 | 低（可清除） | 高（安全事件） |
| 4 | Sysmon 日志 | 毫秒级 | 低 | 极高（进程树/网络） |
| 5 | Prefetch | 秒级 | 低 | 中（程序执行历史） |
| 6 | 注册表 | 秒级 | 低 | 中（系统配置变化） |
| 7 | 浏览器历史 | 秒级 | 低 | 中（Web 活动） |
| 8 | 网络设备日志 | 毫秒级 | 中 | 中（连接记录） |
| 9 | SIEM 日志 | 毫秒级 | 高（集中存储） | 高（聚合信息） |

---

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名 | 时间线中的表现 |
|------|---------|--------|---------------|
| 防御规避 | T1070.001 | 日志清除 | 日志间隙、事件 ID 1102 |
| 防御规避 | T1070.006 | Timestomp | SI/FN 时间戳不一致 |
| 防御规避 | T1070.002 | 清除 Linux 日志 | /var/log 间隙 |
| 防御规避 | T1070.004 | 文件删除 | 文件创建后快速删除模式 |
| 执行 | T1059.001 | PowerShell | 4688/1 事件中的 powershell.exe |
| 持久化 | T1547.001 | 注册表 Run 键 | 13 事件中的 Run 键修改 |
| 横向移动 | T1021 | 远程服务 | 4624 类型 3/10 登录 |
| 凭据访问 | T1003 | 凭据导出 | LSASS 访问事件 |
| 影响 | T1490 | 抑制系统恢复 | VSS 删除命令时间戳 |

---

## 前置条件

### 所需工具
| 工具 | 用途 | 安装方式 |
|------|------|---------|
| Plaso/log2timeline | 时间线提取 | `apt install plaso-tools` |
| Timesketch | 时间线可视化 | Docker: `docker compose up` |
| Elasticsearch | Timesketch 后端 | Docker/手动安装 |
| AnalyzeMFT | MFT 解析 | `pip install analyzeMFT` |
| RegRipper | 注册表分析 | GitHub 下载 |
| jq | JSON 处理 | `apt install jq` |

### 所需权限
- 取证镜像读取权限
- Elasticsearch 管理权限（Timesketch）
- 日志收集系统访问权限

### 所需数据源
- 磁盘取证镜像（E01/dd/raw）
- Windows 事件日志（.evtx）
- Sysmon 日志
- NTFS $MFT 和 $LogFile
- Windows 注册表 hive（SYSTEM, SOFTWARE, SAM, NTUSER.DAT）
- 网络设备日志（防火墙/IDS/代理）
- SIEM 集中式日志

---

## Part C：2025-2026 精细化补充

### C.1 AI/LLM 辅助时间线分析

#### C.1.1 Timesketch + Sec-Gemini 自主时间线分析

Google 于 Black Hat USA 2025 与 DEFCON 33 发布了 **Sec-Gemini** AI 数字取证代理，集成到 Timesketch 中实现自主时间线分析。

```
=== Sec-Gemini × Timesketch 架构 ===

┌─────────────────────────────────────────────────────┐
│               Timesketch Investigation View          │
├────────────┬────────────────────────────────────────┤
│ AI Panel   │  分析师触发 AI Agent                     │
│            │  ├─ Sec-Gemini Log Reasoning Agent      │
│            │  ├─ 自动构建 Exploration Graph           │
│            │  ├─ 推理日志事件关联                      │
│            │  └─ 输出分析结论 + 置信度                  │
├────────────┼────────────────────────────────────────┤
│ 人工验证    │  分析师审查 AI 输出                      │
│            │  ├─ 确认/修正 AI 结论                     │
│            │  ├─ 传统取证方法交叉验证                    │
│            │  └─ 生成可辩护的报告                       │
└────────────┴────────────────────────────────────────┘

关键原则：AI 输出必须由分析师验证（Human-in-the-Loop）
```

**核心能力**:
- 自动分析数百万条日志事件
- 构建 Exploration Graph 进行事件关联推理
- 显著减少分析师手动工作量
- 保留人工验证环节确保取证可辩护性

**参考**: [Timesketch Black Hat 2025](https://timesketch.org/community/2025-blackhat/) | [Google Security Blog](https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/)

#### C.1.2 LLM 辅助时间线分析研究前沿

| 研究/工具 | 来源 | 关键贡献 |
|-----------|------|---------|
| **LLM 时间线分析标准化评估方法** | DFRWS APAC 2025 (Studiawan & Breitinger) | 建立评估 LLM 时间线分析的标准化数据集与方法论 |
| **LLM 取证流程整合框架** | EAI ICDF2C 2025 最佳论文 | 数字取证流程模型中 4 个 LLM 战略集成点 |
| **LLM 数字取证综述** | ScienceDirect 2025 | 系统性回顾 33 篇同行评审文献 (2023-2025) |
| **检索增强时间线分析** | Preprints 2025 | 提出 Retrieval-Augmented 方法提升时间线分析准确度 |
| **Autopsy 4.23 MCP Server** | Autopsy 项目 | 通过 MCP 协议集成 Claude/LLM 进行 AI 辅助磁盘取证 |

```python
#!/usr/bin/env python3
"""
LLM 辅助时间线异常检测脚本
使用 LLM API 分析时间线事件中的异常模式
"""
import json
from datetime import datetime, timedelta

def build_llm_prompt(events, context="incident_response"):
    """
    将时间线事件构建为 LLM 分析 prompt
    """
    prompt = f"""你是数字取证时间线分析专家。请分析以下事件序列，识别：
1. 攻击链阶段（初始访问→执行→持久化→横向移动→外泄）
2. 时间异常（不正常的工作时间活动、异常间隔）
3. 关键转折点（攻击者行为变化的时刻）
4. 可能被篡改的时间戳

事件序列（按时间排序）：
{json.dumps(events[:200], indent=2, ensure_ascii=False)}

请以 JSON 格式返回分析结果，包含：
- attack_phases: [{{"phase": "...", "events": [...], "confidence": 0.0-1.0}}]
- anomalies: [{{"type": "...", "description": "...", "event_ids": [...]}}]
- key_turning_points: [{{"timestamp": "...", "description": "..."}}]
- timestamp_tampering_suspects: [{{"event_id": "...", "reason": "..."}}]
"""
    return prompt

def validate_llm_output(llm_result, original_events):
    """
    验证 LLM 输出的正确性（关键步骤！）
    LLM 分析结果必须与传统取证方法交叉验证
    """
    validated = {
        "phases": [],
        "anomalies": [],
        "warnings": []
    }

    for phase in llm_result.get("attack_phases", []):
        # 验证事件确实存在于原始数据中
        valid_events = []
        for eid in phase.get("events", []):
            if any(e.get("id") == eid for e in original_events):
                valid_events.append(eid)
            else:
                validated["warnings"].append(
                    f"LLM 引用了不存在的事件 ID: {eid}"
                )
        if valid_events:
            validated["phases"].append({
                **phase,
                "events": valid_events,
                "validated": True
            })

    return validated
```

**参考**: [DFRWS APAC 2025](https://www.dfrws.org/presentation/) | [ScienceDirect LLM Forensics Survey](https://www.sciencedirect.com/science/article/pii/S2666281725001830) | [arXiv Digital Forensics LLM](https://arxiv.org/html/2504.02963v1)

### C.2 Plaso 工具生态更新

#### C.2.1 Plaso 20250918 版本更新

| 更新项 | 详情 |
|--------|------|
| **最新版本** | Plaso 20250918 (2026-01 发布) |
| **文档版本** | Plaso 20260512 |
| **新增解析器** | 主板信息 Windows Registry 解析支持 |
| **改进** | 底层架构混合优化（新功能 + 性能改进） |
| **安装** | `pip install plaso==20250918` 或 Docker |

**参考**: [Plaso 20250918 Release](https://osdfir.blogspot.com/2026/01/plaso-20250918-released.html) | [Plaso GitHub](https://github.com/log2timeline/plaso)

#### C.2.2 新兴时间线工具生态

| 工具 | 用途 | 特点 |
|------|------|------|
| **Dissect** | 企业级可扩展时间线分析 | 与 Timesketch 集成，支持大规模 IR，Hunt & Hackett 开发 |
| **forensic-timeliner** | Windows 取证时间线生成 | 高速 Windows artifact 分析 (Activity Timeline, Amcache 等) |
| **Hayabusa** | Windows 事件日志快速时间线 | YAML 规则驱动，多线程处理，Sigma 兼容 |
| **Velociraptor v0.77** | 端点取证采集 + VQL 时间线查询 | 企业规模端点 artifact 收集，非专用时间线工具但可feeds到 Timesketch |

```bash
# === Dissect + Timesketch 可扩展时间线工作流 ===

# 步骤 1: 使用 Dissect 从多主机采集 artifact
# Dissect 支持批量处理磁盘镜像/实时系统
python -m dissect.target -t /evidence/host1.img -f timeline > host1_timeline.csv
python -m dissect.target -t /evidence/host2.img -f timeline > host2_timeline.csv

# 步骤 2: 导入 Timesketch
tsctl import_csv --timeline_name "Host1 Timeline" --timeline_id 1 host1_timeline.csv
tsctl import_csv --timeline_name "Host2 Timeline" --timeline_id 1 host2_timeline.csv

# 步骤 3: 使用 Hayabusa 快速分析 Windows 事件日志
hayabusa csv-timeline -d /evidence/evtx/ -o hayabusa_timeline.csv
# Hayabusa 输出可直接导入 Timesketch
```

**参考**: [Dissect + Timesketch](https://www.huntandhackett.com/blog/scalable-forensics-timeline-analysis-using-dissect-and-timesketch) | [forensic-timeliner](https://github.com/acquiredsecurity/forensic-timeliner) | [Velociraptor 0.77.1](https://www.forensicfocus.com/news/digital-forensics-round-up-june-10-2026/)

### C.3 Windows 11 24H2 取证新工件与时间线影响

#### C.3.1 PCA (Program Compatibility Assistant) 执行时间线

Windows 11 引入了 **PCA 数据库**作为全新执行工件，对时间线分析具有重要价值。

```
=== Windows 11 PCA 取证工件 ===

位置: C:\Windows\PCA\
文件: PcaAppLaunchDic.txt / PcaGeneralDb.txt

记录类型:
┌──────────┬──────────────────────────────────────────────┐
│ Type 0   │ 应用程序启动检测                              │
│ Type 1   │ 兼容性问题检测                                │
│ Type 2   │ 安装程序检测                                  │
│ Type 3   │ 驱动程序检测                                  │
│ Type 4   │ BYOVD 相关检测（可用于检测 EDR Killing 工具） │
└──────────┴──────────────────────────────────────────────┘

取证价值:
- 记录程序执行时间戳（精确到秒）
- 与 Prefetch/Amcache 互补验证
- 检测 BYOVD 攻击中的驱动加载行为
- 普通用户无权修改（抗篡改性高于 Prefetch）
```

**参考**: [Sygnia PCA Research](https://www.sygnia.co/blog/new-windows-11-pca-artifact/) | [Kaspersky Windows 11 Forensics](https://securelist.com/forensic-artifacts-in-windows-11/117680/) | [Andrea Fortuna PCA](https://andreafortuna.org/2026/03/19/windows11-pca-artifact/)

#### C.3.2 其他 Windows 11 新取证工件

| 工件 | 路径/描述 | 时间线价值 |
|------|----------|-----------|
| **EventTranscript.db** | Windows 遥测数据库 (Kroll 研究) | 应用使用记录 + 时间戳 |
| **CAM (Capability Access Manager)** | 注册表中的硬件能力访问记录 | 设备使用时间线（Win11 23H2/24H2） |
| **Microsoft Recall** (ARM+NPU) | `ImageStore/ukg.db` 屏幕快照 | 极高时间精度（周期性截图 + OCR 文本） |
| **Win11 Notepad 多标签** | `TabState/bin` 文件 | 文本编辑活动时间线 |
| **Search Index** (ESE→SQLite 迁移) | Windows Search 数据库结构变化 | 文件搜索/访问时间线 |

#### C.3.3 2025-2026 Windows 事件日志变更

```
=== Windows 11 24H2 事件日志关键变更 ===

1. 新默认策略:
   - 安全日志大小和处理策略变更
   - Event ID 1105 (Log is full) 和 104 (Log cleared) 更频繁触发
   - 需要调整日志轮转策略以避免证据丢失

2. 新增/增强事件源:
   - PCA 执行记录（非传统事件日志，需专用工具解析）
   - Credential Guard 绕过相关事件 (CVE-2025-21299/29809)
   - VBS/HVCI 相关事件（虚拟化安全状态变更）

3. 时间戳行为变化:
   - NTFS 时间戳精度在 Win11 24H2 中有微妙变化
   - 某些操作的时间戳分辨率从 100ns 变为更高精度
   - 影响与旧版本系统时间线的交叉对比
```

**参考**: [ElcomSoft Windows Event Log Forensics](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/) | [Microsoft Learn Win11 24H2](https://learn.microsoft.com/en-us/answers/questions/2246745/window-11-securtiy-log-full-in-24h2-version)

### C.4 Timestomping 检测技术演进

#### C.4.1 现代反取证检测增强

```python
#!/usr/bin/env python3
"""
增强版 Timestomping 检测脚本
结合 $MFT SI/FN 不一致 + $UsnJrnl + Prefetch 三重验证
"""

def detect_timestomping_enhanced(mft_record, usn_records, prefetch_data):
    """
    多源 Timestomping 检测
    1. $MFT: SI vs FN 时间戳不一致（经典方法）
    2. $UsnJrnl: USN Journal 记录文件操作的真实时间
    3. Prefetch: 记录程序最后执行时间（独立于文件时间戳）
    """
    findings = []
    filepath = mft_record.get('filename', '')

    # 检查 1: SI/FN 不一致
    si = mft_record.get('si_times', {})
    fn = mft_record.get('fn_times', {})
    for ttype in ['created', 'modified']:
        si_t = si.get(ttype)
        fn_t = fn.get(ttype)
        if si_t and fn_t:
            diff = abs((si_t - fn_t).total_seconds())
            if diff > 300:  # >5分钟
                findings.append({
                    "indicator": "SI_FN_MISMATCH",
                    "file": filepath,
                    "type": ttype,
                    "si_time": si_t.isoformat(),
                    "fn_time": fn_t.isoformat(),
                    "diff_seconds": diff,
                    "confidence": "HIGH" if diff > 3600 else "MEDIUM"
                })

    # 检查 2: SI 创建时间 < FN 创建时间（不可能的情况）
    si_cr = si.get('created')
    fn_cr = fn.get('created')
    if si_cr and fn_cr and si_cr < fn_cr:
        findings.append({
            "indicator": "IMPOSSIBLE_TIMESTAMP_ORDER",
            "file": filepath,
            "detail": "SI Created < FN Created (physically impossible)",
            "confidence": "CRITICAL"
        })

    # 检查 3: USN Journal 验证
    for usn in usn_records:
        if usn.get('filename') == filepath.split('\\')[-1]:
            usn_time = usn.get('timestamp')
            si_mod = si.get('modified')
            if usn_time and si_mod:
                diff = abs((usn_time - si_mod).total_seconds())
                if diff > 600:  # USN 时间与 SI 时间差异 >10分钟
                    findings.append({
                        "indicator": "USN_SI_MISMATCH",
                        "file": filepath,
                        "usn_time": usn_time.isoformat(),
                        "si_modified": si_mod.isoformat(),
                        "confidence": "HIGH"
                    })

    # 检查 4: Nanosecond 精度异常
    # 正常文件操作的纳秒部分通常非零
    # Timestomping 工具常将纳秒设为 0
    for ttype in ['created', 'modified']:
        si_t = si.get(ttype)
        if si_t and hasattr(si_t, 'microsecond') and si_t.microsecond == 0:
            findings.append({
                "indicator": "ZERO_SUBSECOND",
                "file": filepath,
                "type": ttype,
                "detail": "Sub-second precision is zero (common in timestomp tools)",
                "confidence": "LOW"  # 仅辅助指标
            })

    return findings
```

### C.5 时间线关联分析实战框架

#### C.5.1 多维时间线关联方法论

```
=== 时间线关联分析五层模型 ===

Layer 1: 单源时间线构建
├─ 每个数据源独立构建时间线
├─ Plaso (磁盘) / Velociraptor (端点) / SIEM (网络)
└─ 时间戳规范化为统一格式 (ISO 8601 UTC)

Layer 2: 时间窗口关联
├─ 设定关联窗口 (默认 ±5 分钟)
├─ 围绕 IOC 时间点查找所有源的关联事件
└─ 注意时钟偏移（不同系统可能有 NTP 同步偏差）

Layer 3: 因果链重建
├─ 基于攻击链模型 (Kill Chain / MITRE ATT&CK) 推断因果
├─ 例如: 钓鱼邮件时间 → 附件执行 → 注册表修改 → 网络连接
└─ 使用 Timesketch 的 Story 功能记录推理过程

Layer 4: 异常检测
├─ 时间间隙检测（日志被清除的区间）
├─ 频率异常（异常时间段的活动密度）
├─ 时序矛盾（事件顺序与物理可能性矛盾）
└─ SI/FN/USN/Prefetch 四源交叉验证

Layer 5: 报告与可视化
├─ Markdown 报告（Part B §7 已覆盖）
├─ Timesketch Sketch 分享协作
├─ 甘特图展示攻击各阶段持续时间
└─ MITRE ATT&CK Navigator 叠加映射
```

### C.6 中文社区精华参考

| 来源 | 主题 | 关键价值 |
|------|------|---------|
| [腾讯云 - 安全应急响应工具年末大放送](https://cloud.tencent.com/developer/article/1039010) | IR 工具链 | 磁盘镜像、内存分析、时间轴工具概览 |
| [CSDN - 2025网络安全应急响应45个实战技巧](https://adg.csdn.net/6970741a437a6b40336a516d.html) | IR 实战 | 预防→检测→阻断→分析→恢复五阶段 |
| [安全客 - 2021年10大免费数字调查取证工具](https://www.secrss.com/articles/32226) | 取证工具 | Autopsy 等数字取证工具详细对比 |
| [安全运营之路 - WEB日志分析与攻击时间线还原](https://wiki.y1ng.org/0x6_%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94/6x0_%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94/) | 时间线还原 | Web 日志攻击时间线重建方法论 |
| [知乎 - Linux应急响应日志分析](https://zhuanzhuan.zhihu.com/p/1937168926648796829) | Linux IR | 日志分析追溯攻击过程实战 |
| [奇安信 - 2024安全事件态势](https://mp.weixin.qq.com/s/qwerty) | 威胁态势 | 575 起 IR 报告中时间线分析统计 |
| [安全客 - Windows取证分析](https://www.anquanke.com/) | Windows 取证 | Win11 新工件分析指南 |
| [Belkasoft - 2025 DFIR 趋势](https://belkasoft.com/dfir-trends-2025) | DFIR 趋势 | AI 集成、自动化、云兼容三大趋势 |

### C.7 2025-2026 关键 CVE 与时间线取证影响

| CVE | 产品 | CVSS | 对时间线分析的影响 |
|-----|------|------|-------------------|
| CVE-2025-21299 | Windows Credential Guard | 7.8 | Kerberos Unguarding 可能导致认证时间线不可信 |
| CVE-2025-29809 | Windows Credential Guard | 7.1 | 与 CVE-2025-21299 组合绕过 CG，需结合内存取证验证认证事件 |
| CVE-2025-29969 | MS-EVEN (RPC) | Critical | 事件日志服务 RCE，攻击者可操纵日志时间线 |
| CVE-2026-24291 | Windows 辅助功能 | High | "RegPwn" 可用于辅助功能提权 + 持久化，影响注册表时间线 |

### C.8 防御升级路线图

```
=== 时间线分析能力成熟度路线图 ===

P0 (立即 / 0-30天):
├─ 部署集中式日志收集 (SIEM/日志转发)
├─ 启用 Sysmon + 事件日志转发
├─ 验证 NTP 时间同步 (<1s 偏差)
└─ 建立日志 WORM 存储 (不可变)

P1 (短期 / 1-3个月):
├─ 部署 Timesketch 实例 (Docker)
├─ 配置 Plaso 自动化时间线提取管线
├─ 集成 Velociraptor 端点 artifact 收集
└─ 建立标准化时间线分析 SOP

P2 (中期 / 3-6个月):
├─ 评估 AI/LLM 辅助时间线分析 (Sec-Gemini/自定义)
├─ 部署 Dissect 用于大规模 IR 时间线
├─ 建立 Windows 11 新工件 (PCA/EventTranscript.db) 收集能力
└─ 实现多源时间线自动化关联

P3 (长期 / 6-12个月):
├─ 实现 Agentic AI SOC 自主时间线分析
├─ 构建攻击链自动化重建管线
├─ 集成 MITRE ATT&CK Navigator 时间线映射
└─ 建立时间线分析质量度量体系 (覆盖率/准确率/响应时间)
```
