---
name: ir-triage-scoping
description: >
  安全事件分流与范围界定完整手册：覆盖事件分级 (SEVERITY/PRIORITY 矩阵)、警报分类、
  SIEM 分流工作流 (Splunk/Elastic/QRadar)、IR Playbook 执行、恶意软件事件响应、
  安全泄露遏制与范围控制。包含分流决策树、警报分类模板、范围界定检查清单、
  事件升级矩阵和 MITRE ATT&CK 映射。
domain: cybersecurity
subdomain: incident-response
tags: [incident-response, triage, scoping, siem, playbook, containment, malware-response,
  alert-classification, severity-assessment]
version: 2.0.0
---

# 安全事件分流与范围界定 — 完整手册

## 适用场景

**适用于:** 安全运营中心 (SOC) 警报分流、安全事件初步评估、事件严重等级判定、
IR Playbook 触发决策、恶意软件事件初始响应、安全泄露范围控制。

**不适用于:** 数字取证（见 ir-forensics-*）、漏洞管理流程、威胁狩猎（见 threat-hunting）、
合规审计。

**前置条件:**
- SIEM/SOAR 平台（Splunk/Elastic/QRadar/XSOAR）
- 已部署的检测规则和告警管道
- IR 团队联系表和升级矩阵
- 事件记录系统 (ticketing)

---

## Part A：攻击视角 — 理解攻击如何触发警报

### 1. 常见攻击触发的警报模式

#### 1.1 初始访问警报

```
攻击链: 钓鱼邮件 → 附件执行 → 端点警报
触发警报:
  - EDR: 可疑进程创建 (powershell from outlook.exe)
  - Proxy: C2 域名连接
  - Email Gateway: 恶意附件/链接
  - SIEM: 异常登录 (新设备/新地域)

关键判断:
  - 是否成功执行？(沙箱报告 vs 端点日志)
  - 横向移动证据？(认证日志 4624/4625)
  - 数据外传迹象？(DNS 查询、大文件传输)
```

#### 1.2 横向移动警报

```
攻击链: Pass-the-Hash → WMI/SMB 连接 → 凭证转储
触发警报:
  - EDR: mimikatz/sharphound 执行签名
  - DC: 异常 Kerberos 请求 (RC4 加密)
  - Network: 非工作时间 SMB 连接
  - Sysmon: 远程线程创建 (Event ID 8)

关键判断:
  - 攻击者获得了什么权限？(普通用户 vs 管理员 vs 域管)
  - 受影响系统范围？(单机 vs 整个 OU)
  - 是否到达关键资产？(DC/数据库/文件服务器)
```

#### 1.3 数据泄露警报

```
攻击链: 数据定位 → 压缩/加密 → 外传
触发警报:
  - DLP: 敏感文件操作
  - Proxy: 大量上传到云存储
  - DNS: 异常 TXT 记录查询 (DNS 隧道)
  - Firewall: 非 HTTPS 大流量外发

关键判断:
  - 什么类型的数据？(PII/IP/财务)
  - 多少数据量？
  - 外传到哪里？(已知恶意/可疑/合法云)
```

### 2. 攻击者规避检测的常见手法

```markdown
规避技术 → 对应分流挑战:
- 生活在陆地 (LOTL): 警报模式不明显，需行为基线
- 减慢攻击节奏: 时间线跨度大，关联困难
- 使用合法工具: 工具签名不可靠
- 加密通信: 内容检查失效
- 多阶段分步: 单个警报看似低危
```

---

## Part B：检测与防御 — 分流与遏制

### 3. 事件分流决策树

```
收到警报
├── 是误报?
│   ├── Yes → 关闭 + 调优检测规则
│   └── No → 继续评估
│
├── 确认是安全事件?
│   ├── 需要确认:
│   │   ├── 警报关联的 IOCs 是否可信?
│   │   ├── 受影响资产的业务重要性?
│   │   ├── 是否有横向移动证据?
│   │   └── 是否有数据外传迹象?
│   │
│   └── 分级:
│       ├── SEV-1 (紧急): 活跃入侵/勒索/数据泄露进行中
│       ├── SEV-2 (高): 已确认入侵，尚在扩大范围
│       ├── SEV-3 (中): 可疑活动需调查，尚无确认入侵
│       └── SEV-4 (低): 信息性事件，需关注但不紧急
│
└── 按严重等级执行对应 Playbook:
    ├── SEV-1: 立即执行遏制 (15分钟内)
    ├── SEV-2: 1小时内完成调查+遏制
    ├── SEV-3: 4小时内完成调查
    └── SEV-4: 24小时内处理
```

### 4. 严重等级评估矩阵

| 因素 | P0 (紧急) | P1 (高) | P2 (中) | P3 (低) |
|------|-----------|---------|---------|---------|
| **资产敏感性** | DC/核心数据库 | 业务服务器 | 普通工作站 | 测试环境 |
| **攻击阶段** | 数据外传/破坏 | 横向移动 | 初始访问 | 侦察 |
| **攻击者权限** | Domain Admin | Local Admin | 普通用户 | 未授权 |
| **影响范围** | 全域/多站点 | 单站点 | 单系统 | 单用户 |
| **业务影响** | 业务中断 | 部分影响 | 潜在风险 | 无直接影响 |
| **响应时间** | 15 min | 1 hr | 4 hr | 24 hr |

### 5. SIEM 分流工作流

#### 5.1 Splunk 分流查询

```spl
# 检查警报关联的上下文
index=* sourcetype=* [search index=alerts earliest=-1h | fields src_ip]
| stats count by src_ip, dest_ip, action, user
| sort -count

# 确认是否为已知误报
index=notable review_time>-7d search_name="$alert_name$"
| stats count by status, reviewer, comment

# 关联用户活动
index=* user="$suspicious_user$" earliest=-24h
| stats count values(action) as actions values(dest) as targets by sourcetype
| sort -count

# 检查横向移动证据
index=wineventlog (EventCode=4624 OR EventCode=4625) user="$user$"
| stats count by EventCode, src_ip, dest_ip, Logon_Type
| sort -count

# 检查数据外传
index=proxy src_ip="$suspicious_ip$" earliest=-24h
| eval mb=bytes/1048576
| stats sum(mb) as total_mb by dest_domain
| where total_mb > 100
| sort -total_mb
```

#### 5.2 Elastic 分流查询

```json
# 检查警报实体的历史
GET _search
{
  "query": {
    "bool": {
      "must": [
        {"term": {"host.ip": "suspicious_ip"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "aggs": {
    "by_action": {"terms": {"field": "event.action"}},
    "by_dest": {"terms": {"field": "destination.ip"}}
  }
}

# 进程血缘追踪
GET _search
{
  "query": {
    "bool": {
      "must": [
        {"term": {"process.entity_id": "$entity_id$"}},
        {"term": {"event.category": "process"}}
      ]
    }
  },
  "size": 50,
  "sort": [{"@timestamp": "asc"}]
}
```

### 6. 恶意软件事件响应流程

```markdown
## 恶意软件事件分流 Playbook

### Phase 1: 初步评估 (0-15 分钟)

1. 确认检测来源
   □ EDR 告警? → 获取进程树和文件哈希
   □ AV 告警? → 获取文件路径和检测结果
   □ 用户报告? → 收集样本和时间线
   □ 网络告警? → 获取 C2 地址和通信模式

2. 初始分类
   □ 哈希查询 (VirusTotal/Hybrid Analysis)
   □ 文件类型和行为分析
   □ 恶意软件家族识别
   □ 已知 IOCs 匹配

3. 严重等级判定
   □ 自我传播? (蠕虫) → SEV-1
   □ 勒索行为? (加密文件) → SEV-1
   □ 后门/C2? → SEV-2
   □ 信息窃取? → SEV-2
   □ 广告软件/PUA? → SEV-3

### Phase 2: 范围界定 (15-60 分钟)

4. 确定感染范围
   □ 初始感染向量
   □ 受影响系统列表
   □ 恶意软件传播路径
   □ 受感染账户/凭证
   □ 被访问的敏感数据

5. 网络关联分析
   □ 查询相同 IOC 在全网的匹配
   □ 检查 DNS 日志中的 C2 解析
   □ 分析代理日志中的 C2 通信
   □ 检查横向移动 (PsExec/WMI/SMB)

### Phase 3: 遏制决策

6. 遏制策略选择
   ├── SEV-1 (活跃勒索/蠕虫):
   │   □ 立即断网受影响网段
   │   □ 禁用受感染账户
   │   □ 阻断 C2 通信 (防火墙/DNS sinkhole)
   │   □ 通知管理层
   │
   ├── SEV-2 (后门/C2):
   │   □ 隔离受感染端点 (不关机)
   │   □ 重置受影响账户密码
   │   □ 阻断 C2 IP/域
   │   □ 准备取证镜像
   │
   └── SEV-3 (信息窃取):
       □ 收集额外证据
       □ 评估数据影响
       □ 计划清理时间
       □ 监控持续活动
```

### 7. 活跃泄露遏制流程

```markdown
## 活跃安全泄露遏制 Playbook

### Step 1: 立即行动 (0-15 min)

□ **止血**: 阻断攻击路径
  - 防火墙规则: 阻断源/目标 IP
  - DNS: Sinkhole 恶意域名
  - VPN: 断开受感染会话
  - 账户: 禁用/锁定受影响凭证

□ **通知**:
  - IR 团队 Lead
  - CISO/安全主管
  - IT 运维 (执行技术遏制)
  - 法务 (如涉及数据泄露)

### Step 2: 范围控制 (15-60 min)

□ **边界确认**:
  - 攻击入口点
  - 横向移动范围
  - 受影响系统清单
  - 受影响数据类型和量
  - 攻击者当前状态 (活跃/已潜伏/已撤离)

□ **隔离措施**:
  - VLAN 隔离受影响网段
  - 禁用受感染系统网络
  - 限制 VPN 访问
  - 加强认证要求 (强制 MFA)

### Step 3: 证据保全

□ **易失性证据** (优先):
  - 内存镜像 (整台受感染机器)
  - 网络连接状态
  - 运行进程列表
  - ARP/DNS 缓存

□ **持久化证据**:
  - 磁盘镜像 (ftk imager/dd)
  - 日志归档 (SIEM 导出)
  - 网络流量捕获 (pcap)
  - 云快照 (如适用)

### Step 4: 恢复规划

□ 制定恢复优先级 (按业务影响)
□ 准备干净系统/镜像
□ 凭证重置计划 (分批)
□ 监控加强期计划 (7-30 天)
```

### 8. SSVC 漏洞优先级框架

```markdown
## SSVC (Stakeholder-Specific Vulnerability Categorization)

适用于漏洞类事件的优先级决策:

决策点:
1. Exploitation: 漏洞是否已被活跃利用?
   - Active → 高优先级
   - PoC → 中优先级
   - None → 低优先级

2. Exposure: 系统是否暴露?
   - Open → 增加优先级
   - Controlled → 降低优先级

3. Utility: 利用价值?
   - RCE → 高
   - LPE → 中
   - Info Disclosure → 低-中

4. Impact: 业务影响?
   - Safety → 最高
   - Mission → 高
   - Reputational → 中

快速决策:
Active exploit + Open exposure + RCE + Safety impact = SEV-1
PoC exists + Controlled + LPE + Mission impact = SEV-2
None + Open + Info Disclosure + Reputational = SEV-3
```

---

## 速查表

### 事件类型快速分类

| 事件类型 | 初始指标 | 关键日志源 | 严重等级 | 遏制优先级 |
|---------|---------|-----------|---------|-----------|
| 勒索软件 | 文件加密/勒索信 | EDR, 文件审计 | SEV-1 | 断网 |
| 活跃入侵 | C2 通信 | 防火墙, 代理 | SEV-1 | 阻断 C2 |
| 凭证泄露 | 异常登录 | AD, IAM | SEV-2 | 密码重置 |
| 恶意软件 | AV/EDR 告警 | 端点 | SEV-2 | 隔离端点 |
| 钓鱼攻击 | 用户报告 | 邮件网关 | SEV-3 | 删除邮件 |
| 策略违规 | SIEM 规则 | 多源 | SEV-4 | 记录 |
| 漏洞利用 | IPS/IDS | 网络 | SEV-2/3 | 补丁/虚拟补丁 |
| DDoS | 流量异常 | 网络 | SEV-2 | 流量清洗 |

### SIEM 分流查询模板

```
1. 警报实体上下文:
   index=* [entity_field=$value$] earliest=-24h | stats count by sourcetype

2. 历史误报检查:
   index=notable search_name=$alert$ | stats count by status

3. 关联分析:
   index=* src=$ip$ | stats values(dest) by sourcetype

4. 用户行为基线:
   index=* user=$user$ | timechart count by sourcetype

5. IOC 扩展:
   index=* [$ioc_list$] | stats count by host, source
```

### 遏制行动矩阵

| 行动 | 影响范围 | 可逆性 | 适用场景 | 执行者 |
|------|---------|--------|---------|--------|
| 阻断 IP/域 | 网络 | 高 | C2 通信 | 防火墙管理员 |
| 隔离端点 | 单机 | 高 | 恶意软件 | EDR 操作员 |
| 禁用账户 | 单用户 | 高 | 凭证泄露 | IT 服务台 |
| VLAN 隔离 | 网段 | 中 | 蠕虫传播 | 网络工程师 |
| 断网 | 全站 | 低 | 勒索爆发 | CISO 授权 |
| DNS sinkhole | DNS | 高 | 恶意域名 | DNS 管理员 |
| VPN 断开 | 远程 | 中 | 远程入侵 | VPN 管理员 |
| 强制 MFA | 全域 | 高 | 凭证攻击 | IAM 管理员 |

### 事件升级矩阵

| 条件 | 升级到 | 时间限制 |
|------|--------|---------|
| SEV-1 事件 | IR Lead + CISO | 立即 |
| SEV-2 无进展 | Senior Analyst | 2 小时 |
| 需要业务决策 | 业务所有者 | 4 小时 |
| 涉及 PII/PCI | 法务/合规 | 1 小时 |
| 需要执法协助 | 法务 + CISO | 按需 |
| 供应商通知 | 供应商管理 | 24-72 小时 |
| 监管报告 | 法务/合规 | 按法规要求 |

---

## MITRE ATT&CK 映射

| Technique ID | 名称 | 阶段 | 分流关注点 |
|-------------|------|------|-----------|
| T1566 | Phishing | 初始访问 | 邮件网关 + 端点联动 |
| T1059 | Command and Scripting Interpreter | 执行 | PowerShell/Bash 异常 |
| T1055 | Process Injection | 防御绕过 | EDR 进程树分析 |
| T1003 | OS Credential Dumping | 凭证访问 | LSASS 访问监控 |
| T1021 | Remote Services | 横向移动 | 非常规 RDP/SMB/WMI |
| T1071 | Application Layer Protocol | 命令控制 | HTTP/DNS 异常流量 |
| T1048 | Exfiltration Over Alternative Protocol | 外传 | DNS 隧道/大流量外发 |
| T1486 | Data Encrypted for Impact | 影响 | 大规模文件加密 |
| T1490 | Inhibit System Recovery | 影响 | VSS 删除/shadow copy |
| T1078 | Valid Accounts | 防御绕过 | 异常登录模式 |

---

## 前置条件

### SOC 工具链
```bash
# SIEM 接入
# Splunk/Elastic/QRadar — 确保日志源覆盖:
#   - Windows Event Logs (Security, Sysmon, PowerShell)
#   - Network (Firewall, Proxy, DNS)
#   - Endpoint (EDR, AV)
#   - Identity (AD, IAM, VPN)

# SOAR 平台
# Cortex XSOAR / Splunk SOAR / Microsoft Sentinel
# 配置自动化 Playbook:
#   - 警报富化 (VirusTotal, Shodan, WHOIS)
#   - 自动隔离端点
#   - 自动阻断 IOC

# Ticketing
# ServiceNow / Jira / TheHive
# 确保事件模板包含:
#   - 严重等级
#   - 受影响资产
#   - IOCs 列表
#   - 时间线
#   - 负责人
```

### IR 团队准备
```markdown
□ IR 联系表 (24/7 on-call 轮值)
□ 升级矩阵 (明确各级审批人)
□ 通讯渠道 (OOB: Signal/电话)
□ 战争房间 (物理/虚拟)
□ 法务联系方式 (数据泄露通知)
□ 外部 IR 供应商合同 (如需要)
```

---

## Part C：2025-2026 更新

### 9. AI 驱动的事件分流 (LLM 辅助告警分类)

#### 9.1 LLM 在事件分流中的角色

```markdown
## LLM 辅助分流架构

### 分流辅助层级
1. L0 — 自动分类 (规则引擎/SOAR Playbook)
   - 基于签名的确定性匹配
   - 已知误报模式自动关闭
   - 处理量: ~70% 告警

2. L1 — LLM 辅助研判
   - LLM 汇总告警上下文 (日志摘要、实体关联、历史事件)
   - 生成自然语言分析摘要
   - 给出分类建议 + 置信度评分
   - 处理量: ~25% 告警

3. L2 — 人工深度分析
   - 复杂/高影响事件由分析师介入
   - LLM 提供调查路径建议
   - 处理量: ~5% 告警

### LLM 分流 Prompt 模板
角色: 你是一名资深 SOC 分析师，负责对安全告警进行分流分类。

输入告警数据:
- 告警名称: {alert_name}
- 源 IP: {src_ip}，目标 IP: {dest_ip}
- 受影响主机: {hostname}，用户: {username}
- 检测规则: {detection_rule}
- 最近 24h 关联事件数: {correlated_events}
- 资产重要性: {asset_criticality}

请分析并输出:
1. 事件分类: [误报/低危/中危/高危/紧急]
2. 攻击阶段判断 (Kill Chain 位置)
3. 建议响应动作 (investigate/contain/escalate/close)
4. 置信度 (0-100%)
5. 一句话分析摘要

### 关键防护措施
- LLM 输出仅作为建议，人工确认后方可执行遏制动作
- 禁止 LLM 直接操作生产系统 (仅通过 SOAR 审批流程)
- 记录所有 LLM 辅助决策用于审计
- 定期评估 LLM 分类准确率 (目标 > 90%)
```

#### 9.2 AI 分流效率指标

```markdown
| 指标 | 传统分流 | AI 辅助分流 | 目标 |
|------|---------|------------|------|
| 平均分流时间 (MTTT) | 15-30 min | 3-5 min | < 5 min |
| 误报处理率 | 60% 手动 | 85% 自动 | > 80% |
| 分类准确率 | 因人而异 | 88-94% | > 90% |
| L1 分析师负载 | 100% | 30% | < 40% |
| 事件遗漏率 | 2-5% | < 1% | < 1% |
```

---

### 10. MITRE ATT&CK 基于战术的分流决策树

```markdown
## ATT&CK 战术驱动分流

收到告警 → 识别 ATT&CK 战术 → 按战术分流路径处理:

### Reconnaissance (侦察) — TA0043
├── 告警类型: 端口扫描、DNS 枚举、Web 爬取
├── 严重等级: SEV-4 (信息性)
├── 分流动作: 记录 → 归入威胁情报 → 检查是否有后续利用
└── 注意: 内部侦察 (BloodHound/SharpHound) 升级为 SEV-2

### Initial Access (初始访问) — TA0001
├── 告警类型: 钓鱼邮件、漏洞利用、供应链投毒
├── 严重等级: SEV-2 → SEV-1 (如确认利用成功)
├── 分流动作:
│   ├── 钓鱼: 隔离邮件 → 检查其他收件人 → 重置凭证
│   ├── 漏洞利用: 确认补丁状态 → 检查利用证据 → 遏制
│   └── 供应链: 识别受影响组件 → 评估暴露面 → 隔离
└── 关键: 快速判断利用是否成功 (端点日志 > 沙箱报告)

### Execution (执行) — TA0002
├── 告警类型: PowerShell 混淆、宏执行、WMI 调用、shellcode
├── 严重等级: SEV-2
├── 分流动作:
│   ├── 提取执行命令 → 解混淆 → 判断恶意度
│   ├── 检查父进程链 (是否从办公软件/浏览器派生)
│   └── 搜索全网相同执行模式
└── 关键: PowerShell -EncodedCommand / FromBase64String 是高频恶意标志

### Persistence (持久化) — TA0003
├── 告警类型: 注册表自启动、计划任务、WMI 订阅、服务创建
├── 严重等级: SEV-2
├── 分流动作:
│   ├── 识别持久化机制 → 检查关联的恶意文件/进程
│   ├── 判断是否为合法管理操作 (管理员 + 变更管理工单)
│   └── 检查同类型持久化在其他系统上的存在
└── 关键: APT 常用 WMI Event Subscription (极难发现)

### Privilege Escalation (权限提升) — TA0004
├── 告警类型: UAC 绕过、令牌操纵、SUID 滥用、内核漏洞
├── 严重等级: SEV-1 → SEV-2
├── 分流动作:
│   ├── 确认提升前后的权限级别
│   ├── 检查是否达到管理员/ root / SYSTEM
│   └── 立即评估受影响资产范围
└── 关键: 从普通用户到域管 = 立即 SEV-1

### Defense Evasion (防御绕过) — TA0005
├── 告警类型: 日志清理、进程注入、禁用安全工具、Timestomp
├── 严重等级: SEV-1 (高置信度) / SEV-3 (低置信度)
├── 分流动作:
│   ├── 确认安全工具是否被成功禁用
│   ├── 检查日志完整性 (是否有缺口)
│   └── 评估攻击者反取证意识
└── 关键: 防御绕过几乎总是伴随其他战术 → 必须关联分析

### Credential Access (凭证访问) — TA0006
├── 告警类型: LSASS 转储、Kerberoasting、密码喷洒、键盘记录
├── 严重等级: SEV-1 → SEV-2
├── 分流动作:
│   ├── 确认哪些凭证被暴露 (用户/管理员/服务账户)
│   ├── 检查被盗凭证的使用 (异常登录)
│   └── 立即重置受影响凭证
└── 关键: 凭证访问 → 横向移动 的链路极快，需加速响应

### Lateral Movement (横向移动) — TA0008
├── 告警类型: PsExec/WMI/SMB/RDP 异常连接、Pass-the-Hash
├── 严重等级: SEV-1
├── 分流动作:
│   ├── 映射横向移动路径 (源 → 目标)
│   ├── 确认是否触及关键资产 (DC/数据库/金融系统)
│   ├── 立即阻断移动路径 + 隔离受影响系统
│   └── 检查 DC 是否受影响 → 如是，全域 SEV-1
└── 关键: 横向移动 = 已确认入侵，不再需要"是否成功"判断

### Command and Control (命令控制) — TA0011
├── 告警类型: 异常 DNS/HTTP/HTTPS 通信、信标行为、加密隧道
├── 严重等级: SEV-1
├── 分流动作:
│   ├── 确认 C2 域名/IP → 情报富化 (WHOIS/被动DNS/证书)
│   ├── 检查 C2 通信持续时间 → 估算潜伏期
│   ├── 阻断 C2 通信 (DNS sinkhole / 防火墙)
│   └── 基于 C2 通信时间线回溯所有受感染主机
└── 关键: 使用 JA3/JA3S 指纹识别加密 C2

### Exfiltration (数据外传) — TA0010
├── 告警类型: 大文件外传、DNS 隧道、云存储上传、USB 拷贝
├── 严重等级: SEV-1
├── 分流动作:
│   ├── 识别外传数据类型和量
│   ├── 确认外传目标 (国家/云服务/IP 信誉)
│   ├── 立即阻断外传通道
│   └── 启动数据泄露通知流程 (法务/合规)
└── 关键: 涉及 PII/PHI → 法定通知时限开始计算

### Impact (影响) — TA0040
├── 告警类型: 勒索加密、数据破坏、服务中断、磁盘擦除
├── 严重等级: SEV-1 (无条件)
├── 分流动作:
│   ├── 立即执行灾难遏制 (断网)
│   ├── 确认勒索软件家族 → 查找已知解密工具
│   ├── 评估备份完整性
│   └── 通知管理层 + 准备事件声明
└── 关键: 勒索软件 = 不尝试恢复，优先阻止传播
```

---

### 11. SOAR 自动化 Playbook

#### 11.1 Palo Alto XSOAR Playbook 框架

```yaml
# XSOAR 事件分流自动化 Playbook 示例
name: "安全事件自动分流 v2.0"
id: incident-triage-v2
version: 2.0
starttaskid: "初始分类"

tasks:
  初始分类:
    id: t1
    type: condition
    conditions:
      - label: "已知误报模式"
        condition:
          - operator: isIn
            left:
              value: ${incident.labels}
            right:
              value: ${KnownFalsePositivePatterns}
        next:
          - id: t_close_fp

      - label: "高置信度威胁"
        condition:
          - operator: greaterThan
            left:
              value: ${incident.threatscore}
            right:
              value: 80
        next:
          - id: t_auto_contain

      - label: "需要分析"
        condition:
          - operator: greaterThan
            left:
              value: ${incident.threatscore}
            right:
              value: 30
        next:
          - id: t_llm_enrichment

      - label: "低优先级"
        next:
          - id: t_queue_low

    # 自动富化步骤
  t_llm_enrichment:
    id: t_enrich
    type: playbook
    subplaybook: "告警富化与上下文收集"
    actions:
      - VirusTotal IOC 查询
      - Shodan IP 信誉查询
      - WHOIS 域名查询
      - AD 用户信息查询
      - 资产 CMDB 查询
      - LLM 分析摘要生成
    next:
      - id: t_analyst_review

  # 自动遏制 (仅限高置信度)
  t_auto_contain:
    id: t_contain
    type: playbook
    subplaybook: "自动遏制响应"
    actions:
      - EDR 隔离端点
      - 防火墙阻断 C2 IP/域
      - AD 禁用受影响账户
      - 创建 SEV-1 事件工单
      - 通知 IR Lead (Slack/邮件/短信)

  # 低优先级队列
  t_queue_low:
    id: t_low
    type: regular
    script: |
      incident.severity = "low"
      incident.owner = "L1-Queue"

  # 误报关闭 + 规则调优
  t_close_fp:
    id: t_close
    type: regular
    script: |
      incident.closeReason = "False Positive"
      incident.closeNotes = "匹配已知误报模式，自动关闭"
      # 创建检测规则调优建议
      createDetectionTuningTask(incident.detectionRule)
```

#### 11.2 Splunk SOAR (Phantom) Playbook

```yaml
# Splunk SOAR 分流自动化
name: "事件分流与富化"
actions:
  # Phase 1: 自动富化 (并行执行)
  - parallel:
      - action: "virustotal_file_reputation"
        inputs: { hash: "${artifact.file_hash}" }
      - action: "ip_reputation"
        inputs: { ip: "${artifact.source_ip}" }
      - action: "whois_domain"
        inputs: { domain: "${artifact.destination_domain}" }
      - action: "active_directory_query"
        inputs: { username: "${artifact.username}" }

  # Phase 2: 风险评分
  - action: "calculate_risk_score"
    inputs:
      vt_score: "${virustotal_result.positives}"
      ip_reputation: "${ip_rep_result.risk}"
      asset_criticality: "${cmdb_result.criticality}"
      user_privilege: "${ad_result.privilege_level}"
    outputs:
      risk_score: "${calculated_score}"
      severity: "${mapped_severity}"

  # Phase 3: 自动决策
  - condition: "${risk_score} > 80"
    actions:
      - action: "isolate_endpoint"
        inputs: { hostname: "${artifact.hostname}" }
      - action: "block_ip"
        inputs: { ip: "${artifact.source_ip}" }
      - action: "create_ticket"
        inputs: { severity: "critical" }

  - condition: "${risk_score} > 40 AND ${risk_score} <= 80"
    actions:
      - action: "assign_to_analyst"
        inputs: { queue: "L1" }
      - action: "add_artifact_context"
        inputs: { enrichment_data: "${all_enrichment}" }
```

#### 11.3 奇安信 SOAR 集成

```markdown
## 奇安信天眼 + SOAR 联合分流方案

### 架构
天眼 (威胁检测) → 奇安信 SOAR (自动化分流) → 处置响应

### 自动化能力
1. 天眼告警自动接入 SOAR
   - 流量传感器告警 (APT 攻击检测)
   - 文件威胁鉴定告警
   - 邮件告警 (钓鱼/恶意附件)
   - 天堤防火墙联动告警

2. SOAR 自动化编排
   - Playbook 剧本: 预定义的分流处置流程
   - 情报富化: 奇安信威胁情报自动查询
   - 通知: 自动生成分析报告并推送
   - 处置: 联动防火墙/EDR 执行阻断

3. 效率提升
   - 安全处置效率提升 10 倍以上
   - 重复性操作效率提升数百倍
   - SOAR 剧本生成准确率持续提升
   - 天眼 + SOAR 实现从检测到响应的全流程自动化
```

---

### 12. 云事件分流

#### 12.1 AWS GuardDuty 事件分流

```markdown
## AWS GuardDuty 发现类型与分流

### 高优先级发现 (SEV-1/SEV-2)
| 发现类型 | 描述 | 分流动作 |
|---------|------|---------|
| Backdoor:EC2/DenialOfSystem | EC2 后门 | 隔离实例 → 取证镜像 |
| CryptoCurrency:EC2/BitcoinTool | 加密挖矿 | 隔离实例 → 检查 IAM |
| CredentialAccess:IAMUser/AnomalousBehavior | 异常凭证访问 | 禁用 IAM 用户 → 审计 CloudTrail |
| DefenseEvasion:IAMUser/AnomalousBehavior | 异常防御绕过 | 审计 IAM 策略变更 |
| Exfiltration:IAMUser/AnomalousBehavior | 异常数据外传 | 检查 S3 访问日志 → 阻断 |
| Impact:EC2/WinRMBruteForce | WinRM 暴力破解 | 检查安全组 → 限制 IP |
| Persistence:IAMUser/AnomalousBehavior | 异常持久化 | 审计 IAM 角色/策略 |
| Policy:IAMUser/RootCredentialUsage | Root 凭证使用 | 立即调查 → 轮换密钥 |
| UnauthorizedAccess:EC2/TorClient | Tor 客户端 | 隔离实例 → 调查 |
| UnauthorizedAccess:EC2/SSHBruteForce | SSH 暴力破解 | 检查安全组 → 封禁 IP |

### 分流自动化 (AWS Lambda + EventBridge)
```python
import json, boto3

def lambda_handler(event, context):
    finding = event['detail']['findings'][0]
    severity = finding['Severity']
    finding_type = finding['Type']

    # 自动分流逻辑
    if severity >= 7.0:  # High/Critical
        # 通知 SOC
        notify_soc(finding)
        # 自动隔离 EC2 (仅限特定高危类型)
        if finding_type in ['Backdoor:EC2/DenialOfSystem',
                            'CryptoCurrency:EC2/BitcoinTool']:
            isolate_ec2_instance(finding['Resources'][0]['Id'])
        # 创建 Jira/ServiceNow 工单
        create_incident(finding, severity='SEV-1')
    elif severity >= 4.0:  # Medium
        # 富化 + 分配 L1 分析师
        enrich_finding(finding)
        assign_to_queue(finding, queue='L1')
    else:  # Low/Informational
        # 记录 + 定期审查
        log_finding(finding)
```

#### 12.2 Azure Sentinel 事件分流

```markdown
## Azure Sentinel 分流要点

### 关键检测连接器
- Azure AD Identity Protection (风险登录/凭证泄露)
- Microsoft Defender for Endpoint (端点检测)
- Microsoft Defender for Cloud (云安全态势)
- Office 365 (邮件/SharePoint/Teams)
- Azure Firewall / Application Gateway

### Sentinel Analytics Rule 分流
| 规则类别 | 示例 | 分流优先级 |
|---------|------|-----------|
| Fusion (多源关联) | APT 检测 | SEV-1 |
| ML Behavior Analytics | 异常登录/文件访问 | SEV-1/2 |
| Scheduled Analytics | 自定义 KQL 规则 | 按规则定义 |
| Microsoft Security | Defender 告警导入 | 按原始严重性 |

### KQL 分流查询
```kql
// 检查用户在多个数据源的异常行为
let user = "suspicious@domain.com";
union SecurityEvent, SigninLogs, OfficeActivity, AzureActivity
| where TimeGenerated > ago(24h)
| where Account has user or UserPrincipalName has user
| summarize event_count=count(),
            sources=make_set(Type),
            ips=make_set(IPAddress),
            actions=make_set(OperationName)
    by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Sentinel SOAR (Logic Apps) 自动化
- 自动触发: 高严重性事件创建时
- 自动动作: 禁用用户 + 阻断 IP + 创建工单 + 通知 SOC
- 审批门控: 关键遏制动作需 SOC Lead 审批

#### 12.3 GCP Security Command Center 分流

```markdown
## GCP SCC 发现分流

### 高优先级发现类型
| 发现类别 | 示例 | 分流动作 |
|---------|------|---------|
| EXFILTRATION | 数据外传 | 检查 VPC Flow Logs → 限制 IAM |
| MALWARE | 恶意软件 | 隔离 VM → 取证 |
| MISCONFIGURATION | 公开存储桶 | 立即修复 IAM 策略 |
| ACCESS_KEY_LEAK | 密钥泄露 | 立即轮换 Service Account Key |
| CRYPTO_MINING | 加密挖矿 | 隔离 VM → 审计 IAM |

### GCP 分流自动化 (Cloud Function)
```python
def triage_scc_finding(event, context):
    finding = event['jsonPayload']
    severity = finding['severity']
    category = finding['category']

    if severity in ['CRITICAL', 'HIGH']:
        # 通知 SOC (Pub/Sub → Slack)
        notify_soc(finding)
        # 联动补救
        if category == 'MISCONFIGURATION':
            auto_remediate(finding)
        elif category == 'CRYPTO_MINING':
            stop_vm(finding['resource']['name'])
```

---

### 13. 勒索软件快速分流检查清单

```markdown
## 勒索软件快速分流 (Ransomware Rapid Triage)

### 第一分钟 — 确认
□ 确认是否为勒索软件事件:
  - 有勒索信文件? (README.txt / .html / .hta)
  - 文件扩展名被修改? (.encrypted / .locked / .crypt)
  - 文件无法打开/损坏?
  - 壁纸被篡改 (勒索信息)?

□ 识别勒索软件家族 (关键决策):
  - 勒索信内容 → 上传 ID Ransomware (https://id-ransomware.malwarehunterteam.com/)
  - 文件加密扩展名 → 查询 NoMoreRansom (https://www.nomoreransom.org/)
  - 是否有已知解密工具? → 有则可能恢复数据

### 前 5 分钟 — 遏制
□ **立即断网** (不要关机):
  - 物理断开网络线缆
  - 或通过 EDR 网络隔离
  - 保持系统运行状态 (内存中可能有加密密钥)

□ **阻止传播**:
  - 关闭 SMB 共享 (445 端口)
  - 禁用 RDP (3389 端口)
  - 检查并阻断所有横向移动路径

□ **评估传播范围**:
  - 检查文件服务器/共享目录
  - 检查备份系统 (是否也被加密)
  - 检查 VSS/快照 (是否被删除)

### 前 15 分钟 — 评估与通知
□ **评估影响**:
  - 受影响系统数量
  - 受影响数据类型和量
  - 关键业务是否中断
  - 备份是否完整可用

□ **通知**:
  - CISO/安全主管
  - IT 运维团队
  - 业务连续性团队
  - 法务 (如涉及数据加密)
  - 公关 (如事件可能公开)

□ **证据保全**:
  - 收集勒索信副本
  - 加密文件样本 (原始 + 加密后)
  - 网络流量 pcap (如正在捕获)
  - 不要尝试恢复/清理 → 保留证据

### 前一小时 — 深入调查
□ **确定入侵路径**:
  - 钓鱼邮件? → 检查邮件网关
  - VPN 漏洞? → 检查 VPN 日志
  - RDP 暴破? → 检查 RDP 日志
  - 供应链? → 检查近期软件更新

□ **检查所有可能受影响的系统**:
  - 基于勒索软件 IOCs 全网扫描
  - 检查计划任务 (定时执行勒索)
  - 检查组策略 (是否被推送勒索脚本)

□ **恢复准备**:
  - 确认备份完整性 (离线备份优先)
  - 准备干净的恢复环境
  - 制定分阶段恢复计划

### 勒索软件家族快速识别参考
| 家族 | 扩展名 | 特征 | 已知解密 |
|------|--------|------|---------|
| LockBit 3.0 | .lockbit | 双勒索 (加密+泄露) | 部分 |
| ALPHV/BlackCat | .alphv | Rust 编写, 跨平台 | 无 |
| Cl0p | .Clop | 利用 MOVEit/GoAnywhere | 无 |
| Royal/BlackSuit | .royal/.blacksuit | 部分加密加速 | 无 |
| Akira | .akira | VPN 漏洞入侵 | 无 |
| PLAY | .play | 不留勒索信, 仅扩展名 | 无 |
| Rhysida | .rhysida | Coercion 模式 | 部分 |
| BianLian | 无扩展名 | 只窃取不加密 (2023后) | N/A |
```

---

### 14. 供应链攻击识别要点

```markdown
## 供应链攻击分流 (Supply Chain Attack Triage)

### 14.1 供应链攻击告警信号

#### 高风险指标
- 软件供应商发布紧急安全公告
- CI/CD 管道异常 (未授权代码提交)
- 包管理器中出现同音/拼写混淆包
- 构建系统被入侵 (构建产物被篡改)
- 第三方 SaaS 服务异常行为
- 开源库维护权转移 (被恶意接管)
- 自动更新推送了未签名/签名不匹配的包

#### 典型供应链攻击模式
```
攻击路径 → 分流关注点:

1. 源代码投毒
   - 恶意 PR/Commit 注入开源项目
   → 检查: git blame, code review 记录, 签名验证

2. 构建管道入侵
   - 篡改 CI/CD 构建脚本插入后门
   → 检查: 构建日志, 构建环境完整性, SBOM 对比

3. 包替换/混淆
   - npm/PyPI 发布混淆包名
   → 检查: 包元数据, 下载量异常, 维护者历史

4. 更新通道劫持
   - 中间人攻击软件更新
   → 检查: 证书验证, 签名校验, CDN 日志

5. 第三方服务入侵
   - IT 服务商/托管服务商被入侵
   → 检查: 第三方访问日志, 供应商安全通告

6. 凭证泄露 → 上游供应链
   - 开发者凭证泄露导致仓库被接管
   → 检查: 开发者 GitHub/GitLab 活动异常
```

### 14.2 供应链事件分流决策

```
供应链安全告警
├── 来源: 供应商通知
│   ├── 受影响产品在本环境使用?
│   │   ├── Yes → 紧急评估暴露面 (SEV-1/2)
│   │   │   ├── 确认漏洞/后门版本号
│   │   │   ├── 检查是否有利用证据
│   │   │   ├── 评估替代方案/补丁
│   │   │   └── 通知业务所有者
│   │   └── No → 记录 + 监控 (SEV-4)
│   └── 影响程度不明?
│       └── 主动联系供应商确认 → 24h 内跟进

├── 来源: 内部检测
│   ├── SBOM 异常 (未授权组件/版本)
│   │   ├── 核心业务组件? → SEV-1
│   │   └── 辅助工具? → SEV-2/3
│   ├── 构建管道异常
│   │   ├── 代码签名不匹配? → SEV-1 (可能已投毒)
│   │   └── 构建环境异常? → SEV-1 (隔离构建环境)
│   └── 包管理器告警
│       ├── 已安装恶意包? → SEV-1 (隔离 + 审计)
│       └── 阻止安装? → SEV-3 (记录)
│
└── 来源: 情报源 (CVE/安全通告)
    ├── 在野利用证据? → SEV-1
    ├── PoC 公开? → SEV-2
    └── 仅理论风险? → SEV-3
```

### 14.3 供应链攻击调查 Playbook

```markdown
## 供应链攻击调查步骤

### Step 1: 确认暴露 (0-2h)
□ 获取 SBOM (软件物料清单)
□ 对比受影响版本与已部署版本
□ 检查部署时间线 (何时引入漏洞版本)
□ 确认组件在哪些业务系统中使用

### Step 2: 证据收集 (2-8h)
□ 收集受影响组件的构建日志
□ 检查网络日志 (组件是否连接异常地址)
□ 检查进程日志 (组件是否执行异常操作)
□ 文件完整性检查 (组件文件是否被篡改)

### Step 3: 影响评估 (8-24h)
□ 评估攻击者通过组件能获得什么权限
□ 检查是否有数据访问/外传
□ 评估对客户的影响 (如产品交付)
□ 制定补救计划 (更新/替换/隔离)

### Step 4: 遏制与恢复
□ 应用供应商提供的补丁/更新
□ 如无补丁 → 应用虚拟补丁/WAF 规则
□ 轮换可能与受影响组件交互的凭证
□ 加强监控期 (7-30 天)
```

---

### 15. 更新 MITRE ATT&CK 映射

```markdown
## MITRE ATT&CK 映射 (2025-2026 更新)

### 新增/重点关注技术

| Technique ID | 名称 | 战术 | 分流关注点 | 更新原因 |
|-------------|------|------|-----------|---------|
| T1195.002 | Supply Chain Compromise: Software Supply Chain | 初始访问 | SBOM 对比、构建完整性 | 供应链攻击激增 |
| T1195.001 | Supply Chain Compromise: Hardware | 初始访问 | 固件完整性验证 | 硬件后门风险 |
| T1552.005 | Cloud Instance Metadata API | 凭证访问 | IMDSv1 vs IMDSv2 | 云凭证泄露 |
| T1530 | Data from Cloud Storage | 收集 | S3/Blob/GCS 异常访问 | 云数据窃取 |
| T1537 | Transfer Data to Cloud Account | 外传 | 跨云数据传输 | 云间数据移动 |
| T1078.004 | Valid Accounts: Cloud Accounts | 防御绕过 | 云 IAM 异常登录 | 云账户滥用 |
| T1098.001 | Additional Cloud Credentials | 持久化 | 云服务账户密钥创建 | 云持久化 |
| T1136.003 | Create Account: Cloud Account | 持久化 | 异常云账户创建 | 云环境持久化 |
| T1578 | Modify Cloud Compute Infrastructure | 影响 | VM 篡改/快照删除 | 云破坏 |
| T1525 | Implant Internal Image | 持久化 | 容器镜像供应链 | 容器安全 |
| T1609 | Container Administration Command | 执行 | kubectl/exec 异常 | 容器逃逸 |
| T1613 | Container and Resource Discovery | 发现 | 容器枚举 | 容器侦察 |
| T1556.006 | Multi-Factor Authentication | 凭证访问 | MFA 绕过/疲劳攻击 | MFA 疲劳攻击激增 |
| T1621 | Multi-Factor Authentication Request Generation | 凭证访问 | 异常 MFA 推送 | MFA 疲劳攻击 |
| T1119 | Automated Collection | 收集 | 批量数据访问脚本 | 自动化窃取 |
| T1659 | Content Injection | 初始访问 | 恶意内容注入合法网站 | 浏览器漏洞利用 |

### AI/LLM 相关新兴技术

| 关注领域 | 描述 | 分流策略 |
|---------|------|---------|
| Prompt Injection | LLM 提示注入攻击 | 监控 LLM API 异常输入/输出 |
| AI Model Poisoning | 训练数据投毒 | 模型行为基线监控 |
| LLM Data Leakage | 通过 LLM 泄露数据 | 监控敏感数据在 AI 服务中的传输 |
| AI-Generated Phishing | AI 生成钓鱼内容 | 加强邮件内容分析 (AI 检测 AI) |
| Deepfake Social Engineering | 深伪社工攻击 | 语音/视频验证流程 |

### 分流优先级映射更新

```
ATT&CK 战术 → 默认严重等级 (2025 更新):
TA0001 Initial Access:    SEV-2 (如利用成功 → SEV-1)
TA0002 Execution:         SEV-2
TA0003 Persistence:       SEV-2 (云持久化 → SEV-1)
TA0004 Privilege Escalation: SEV-1
TA0005 Defense Evasion:   SEV-1 (高置信度) / SEV-3 (低置信度)
TA0006 Credential Access: SEV-1 (域管/云凭证) / SEV-2 (普通用户)
TA0007 Discovery:         SEV-3
TA0008 Lateral Movement:  SEV-1
TA0009 Collection:        SEV-2
TA0010 Exfiltration:      SEV-1
TA0011 Command and Control: SEV-1
TA0040 Impact:            SEV-1
TA0042 Resource Development: SEV-4 (情报性)
TA0043 Reconnaissance:    SEV-4 (内部侦察 → SEV-2)
```

### 来源 (Part B)
- [奇安信 SOAR 产品页](https://www.qianxin.com/product/detail/pid/360)
- [奇安信天眼+SOAR 入选 2025 智能化安全运营中心应用指南](https://www.qianxin.com/news/detail?news_id=13280)
- [奇安信 SOAR 3.0 发布](https://www.secrss.com/articles/28275)
- [Gartner SOAR 解决方案市场指南](https://www.qianxin.com/news/detail?news_id=5359)
- [SOAR Playbook 实践 (知乎)](https://zhuanlan.zhihu.com/p/387137924)
- [奇安信 AI+网络安全产品能力](https://www.bita.org.cn/newsinfo/8229515.html)

---

## Part D：2025-2026 精细化复核补充

### 16. Agentic AI SOC — 自主事件分流前沿

#### 16.1 从 SOAR 到 Agentic AI 的范式转变

```markdown
## SOC 自动化三代演进

### 第一代: 规则 SOAR (2018-2023)
- 手动编写 Playbook, 固定流程
- 需要大量维护, 集成困难
- 处理 ~30-40% L1 告警

### 第二代: AI 辅助 SOAR (2023-2025)
- LLM 摘要 + 分类建议
- AI 辅助但不自主决策
- 处理 ~60-70% L1 告警

### 第三代: Agentic AI SOC (2025-2026+)
- AI Agent 自主调查、分流、响应
- 多步推理 + 工具调用 + 上下文记忆
- 处理 90%+ Tier 1 告警
- 人工仅处理 ~5% 复杂/高影响事件

### 2026 Agentic SOC 市场格局 (15+ 供应商)
| 平台 | 类型 | 核心能力 | 定位 |
|------|------|---------|------|
| Cisco (Splunk) Agentic AI | SIEM+SOAR | Triage Agent + AI Playbook Authoring + Response Importer | 企业级传统 SOC 升级 |
| Elastic AI SOC Engine (EASE) | SIEM | 上下文感知检测 + AI 驱动分流 (Serverless) | 开源生态 + 云原生 |
| Microsoft Sentinel + Security Copilot | SIEM+SOAR | AI 驱动威胁狩猎 + 自动化 Playbook | Azure/M365 深度集成 |
| D3 Morpheus | SOAR | 95% 告警 2 分钟内自主调查 + 800+ 自愈集成 | 自主 SOAR 替代 |
| Torq | SOAR | AI Agent 全生命周期 (分流→调查→响应→解决) | 低代码 Agentic SOAR |
| Tines | SOAR | 工作流自动化 + AI 辅助 | 安全 + IT 跨场景 |
| Swimlane Turbine | SOAR | AI 增强编排 + 大规模自动化 | 企业级低代码 |
| Simbian AI SOC Agent | AI Agent | 全自主调查 + 行动建议 | 新兴纯 AI SOC |
| Radiant Security | AI Agent | Agentic 分流 + 调查 + 响应 | 新兴 AI SOC |
| Prophet Security | AI Agent | 自动化告警分流 + 上下文推理 | 新兴 AI SOC |
```

#### 16.2 Cisco Agentic AI for SOC (2025-09)

```markdown
## Cisco Agentic AI — 2025 年 9 月发布

### 四大核心能力

1. **Triage Agent (分流智能体)**
   - 自动接收告警 → 上下文富化 → 分类建议
   - 利用 Cisco Talos 威胁情报实时丰富每个告警
   - 生成自然语言调查摘要
   - 置信度评分 → 自动分流到对应队列

2. **AI Playbook Authoring (AI Playbook 编写)**
   - 自然语言描述 → 自动生成 SOAR Playbook
   - 降低 Playbook 开发门槛
   - 自动映射到 ATT&CK 技术

3. **Response Importer (响应导入器)**
   - 从历史事件学习响应模式
   - 将人工分析师的最佳实践固化为自动化流程
   - 持续优化分流和响应准确率

4. **AI-Enhanced Detection Library (AI 增强检测库)**
   - AI 辅助检测规则编写
   - 基于威胁情报自动生成 Sigma/YARA 规则
   - 减少误报 + 提高检出率

### Splunk ES 8.0/8.2 关键更新
- Cisco Talos + Splunk 威胁情报集成到每个告警
- Finding 状态直接管理 (Owner/Status/Urgency/Sensitivity/Disposition)
- Splunk SOAR 7.0.0 (2025-09): Python 3.13 + IPv6 支持
```

#### 16.3 Elastic AI SOC Engine (EASE, 2025-08)

```markdown
## Elastic AI SOC Engine (EASE) — 2025 年 8 月

### 核心架构
- Serverless 部署, 无需管理基础设施
- AI 驱动上下文感知检测和分流
- 与 Elastic Security 紧密集成
- 利用 Elastic Search AI 进行威胁分析

### 分流增强
- 自动告警优先级排序 (基于资产上下文 + 威胁情报)
- AI 生成调查建议和下一步行动
- 跨数据源关联分析自动化
- 告警疲劳缓解 — 减少 85%+ 低价值告警噪音

### Elastic Security 8.x 分流查询增强
```json
// EASE AI 增强的告警查询 — 上下文感知
GET /.alerts-security*/_search
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"term": {"event.kind": "alert"}}
      ]
    }
  },
  "aggs": {
    "by_rule": {"terms": {"field": "rule.name"}},
    "by_severity": {"terms": {"field": "event.severity"}},
    "by_host_risk": {"terms": {"field": "host.risk.score"}}
  }
}
```
```

### 17. 2026 Unit 42 全球事件响应报告 — 关键统计

```markdown
## Unit 42 2025-2026 IR 报告关键发现

### 攻击入口统计
| 初始访问方法 | 占比 | 趋势 |
|-------------|------|------|
| 身份技术 (钓鱼+凭证窃取+MFA绕过) | 65% | ↑ 持续增长 |
| 漏洞利用 (已知CVE) | ~20% | → 稳定 |
| 供应链攻击 | ~10% | ↑ 增长 |
| 物理攻击/内部威胁 | ~5% | → 稳定 |

### 勒索软件态势
| 指标 | 2024 | 2025/2026 | 变化 |
|------|------|-----------|------|
| 中位赎金需求 | $1.25M | $1.5M | ↑ 20% |
| 业务中断比例 | ~80% | 86% | ↑ |
| 数据窃取+勒索双重勒索 | ~70% | ~85% | ↑ |
| 浏览器相关攻击 | — | 44% | 新指标 |

### 新型勒索策略
- **虚假数据勒索**: 声称窃取数据但实际未窃取, 降低攻击成本
- **物理勒索信**: 寄送勒索信到高管家中, 增加心理压力
- **四重勒索**: 加密+窃取+DDoS+联系客户/合作伙伴

### 分流响应时间建议 (基于 Unit 42 数据更新)
| 事件类型 | 平均发现时间 (Unit 42) | 建议分流时限 | 建议遏制时限 |
|---------|----------------------|------------|------------|
| 勒索软件 | ~5 天 (从入侵到加密) | < 5 min | < 15 min |
| 凭证窃取 | ~10 天 (从泄露到利用) | < 15 min | < 1 hr |
| C2 通信 | ~21 天 (从建立到发现) | < 30 min | < 2 hr |
| 数据外传 | ~15 天 (从访问到外传) | < 30 min | < 2 hr |
| 供应链 | ~30 天 (从投毒到发现) | < 1 hr | < 4 hr |
```

### 18. MITRE ATT&CK v19 (2026-04) 分流更新

```markdown
## ATT&CK v19 分流相关更新

### 版本演进对分流的影响
- v15 (2024-04): 升级检测 + 新分析格式
- v16: 引入 ICS 子技术 + 跨域映射
- v17-v18: 持续更新技术/组织/活动
- v19 (2026-04): 最新版本, 覆盖 Enterprise/Mobile/ICS

### 新增/变更的分流关注技术 (v17-v19)

| Technique ID | 名称 | 战术 | 分流变化 |
|-------------|------|------|---------|
| T1552.005 | Cloud Instance Metadata API | 凭证访问 | 增加 IMDSv2 绕过场景 |
| T1621 | MFA Request Generation | 凭证访问 | MFA 疲劳攻击持续激增 |
| T1195.002 | Software Supply Chain | 初始访问 | SBOM 比对成为标准分流步骤 |
| T1136.003 | Create Cloud Account | 持久化 | 云账户创建监控加强 |
| T1078.004 | Cloud Accounts | 防御绕过 | 云 IAM 异常登录检测 |
| T1098.001 | Additional Cloud Credentials | 持久化 | 服务账户密钥创建告警 |
| T1525 | Implant Internal Image | 持久化 | 容器镜像供应链检测 |
| T1609 | Container Admin Command | 执行 | kubectl/exec 异常检测 |
| T1659 | Content Injection | 初始访问 | 浏览器内容注入检测 |
| T1556.006 | Multi-Factor Authentication | 凭证访问 | MFA 绕过技术持续演进 |

### ICS ATT&CK 分流要点 (v16+ 子技术)
- 12 个战术 + 83+ 技术 (含新增子技术)
- 工控事件分流需额外关注:
  - **TA0101 响应程序操纵**: 工艺流程篡改告警 → SEV-1
  - **TA0102 保护系统操纵**: 安全仪表系统篡改 → SEV-1 (安全风险)
  - **TA0109 影响**: 物理破坏 → 立即通知 OT 运维 + 安全
  - **Gold-Copy 备份恢复**: ICS 事件遏制后的快速恢复方案
```

### 19. AI 告警分流实施路线图

```markdown
## AI SOC 分流实施 90 天路线图

### Phase 1: 评估与准备 (Day 1-30)
□ 现状评估
  - 统计当前告警量/类型/误报率
  - 测量 MTTD/MTTR 基线
  - 识别 Top 10 高频告警 (占 80% 工作量)
  - 评估现有 SOAR/SIEM 平台的 AI 就绪度

□ 选择方案
  - 对比评估: Agentic AI 平台 vs 增强 SOAR vs 自建 LLM 管道
  - 参考评估维度: 调查深度 / 集成广度 / 部署复杂度 / 成本
  - POC 选定 1-2 个候选平台

### Phase 2: 试点部署 (Day 31-60)
□ 小范围试点
  - 选择 3-5 个高频告警类型 (如: 恶意软件检测/异常登录/钓鱼)
  - 配置 AI 分流 Pipeline (告警接入 → AI 分析 → 分类建议)
  - 设置人工复核率 100% (验证 AI 准确率)

□ 效果测量
  - AI 分类准确率 (目标 > 85%)
  - 误报自动关闭率 (目标 > 70%)
  - 平均分流时间缩短 (目标 > 50%)
  - 分析师满意度调查

### Phase 3: 扩展与优化 (Day 61-90)
□ 扩展覆盖范围
  - 增加到 10-15 个告警类型
  - 引入自动遏制 (高置信度场景)
  - 降低人工复核率到 ~20% (仅边缘案例)

□ 持续优化
  - 建立反馈循环 (分析师纠正 → 模型优化)
  - 定期评估 AI 分流质量 (月度)
  - 监控 AI 安全风险 (Prompt 注入/数据泄露)
  - 准备扩展到 Tier 2 调查自动化

### AI 分流成熟度模型
| 级别 | 描述 | 覆盖率 | 人工介入 |
|------|------|--------|---------|
| L0 - 基础 | 规则引擎 + 已知模式匹配 | ~30% | 100% |
| L1 - AI 辅助 | LLM 摘要 + 分类建议 | ~60% | ~40% |
| L2 - AI 自主 | Agent 自主调查 + 分类 | ~80% | ~20% |
| L3 - 全面自主 | 全生命周期 AI 处理 | ~95% | ~5% |
| L4 - 预测 | 威胁预测 + 主动防御 | ~99% | 异常事件 |
```

### 20. 2025-2026 关键 CVE 速查 (事件分流相关)

```markdown
## 事件分流场景常见 CVE

### 需立即响应 (SEV-1 触发)
| CVE | 产品 | CVSS | 关键指标 | 分流动作 |
|-----|------|------|---------|---------|
| CVE-2025-55241 | Microsoft Entra ID | 9.0 | 跨租户 Actor Token | 检查 Entra ID 登录日志 → 禁用可疑 Token |
| CVE-2025-53770 | SharePoint | 9.8 | ToolShell 反序列化 | 检查 IIS 日志 → 隔离 SharePoint |
| CVE-2025-46377 | ADOdb | 10.0 | SQL 注入 | 检查 Web 日志 → 阻断攻击 IP |
| CVE-2025-15467 | OpenSSL CMS | 9.8 | 栈溢出 Pre-Auth | 检查 TLS 连接日志 → 虚拟补丁 |
| CVE-2025-1974 | K8s IngressNightmare | 9.8 | Ingress 注入 | 检查 K8s API 审计日志 → 隔离 Pod |
| CVE-2025-55182 | React2Shell (Flight) | 10.0 | 协议 RCE | 检查 Web 服务器进程创建 → 隔离 |
| CVE-2025-68121 | Go crypto/tls | Critical | Config.Clone 密钥泄漏 | 检查 TLS 连接 → 轮换证书密钥 |

### 需优先调查 (SEV-2 触发)
| CVE | 产品 | CVSS | 关键指标 | 分流动作 |
|-----|------|------|---------|---------|
| CVE-2025-24813 | Apache Tomcat | 9.8 | Partial PUT RCE | 检查 PUT 请求日志 → 虚拟补丁 |
| CVE-2025-29927 | Next.js | High | 中间件授权绕过 | 检查 x-middleware-subrequest → 升级 |
| CVE-2025-33073 | Windows SMB | High | NTLM 反射提权 | 检查 SMB 认证日志 → 补丁 |
| CVE-2025-54918 | Windows NTLM | 8.8 | LDAP 认证绕过 | 检查 LDAP 绑定日志 → 域控隔离评估 |
| CVE-2025-33074 | Azure Functions | High | SSRF RCE | 检查 Functions 出站连接 → 限制 |

### 分流查询模板 (CVE 快速检查)
```spl
# 检查环境是否存在特定 CVE 利用指标
index=* (sourcetype=proxy OR sourcetype=wineventlog OR sourcetype=ids)
[
| makeresults
| eval cve_list="CVE-2025-55241,CVE-2025-53770,CVE-2025-1974"
| makemv cve_list delim=","
| mvexpand cve_list
| rename cve_list as cve
| lookup cve_indicators cve OUTPUT indicator, ioc_type
| table indicator, ioc_type
| format
]
| stats count by src_ip, dest_ip, cve, action
| sort -count
```
```

### 21. 中文社区精华参考

```markdown
## 中文社区事件响应/分流精华

### 综合参考
- [从POC到规模化生产：为什么2025年是AI-SOC的真正爆发点？](https://www.secrss.com/articles/86519) — AI-SOC自律型告警分流7×24、缓解人力短缺、加速事件处置
- [万字报告解读：通往AI增强型SOC之路](https://www.secrss.com/articles/74219) — AI/大模型重塑SOC工作流、自动化告警管理、事件响应时间优化
- [2025年安全运营中心的AI现状：最新调研洞察](https://modelengine.csdn.net/690c526b5511483559e2b062.html) — 67%告警分流由AI承担、生成式AI在规则编写/攻击模拟/威胁情报的应用

### 阿里云
- [Agentic SOC 威胁分析与响应](https://help.aliyun.com/zh/security-center/user-guide/overview-of-threat-analysis) — 云原生SIEM+SOAR平台、集中采集分析多云环境日志与告警
- [人工智能和2025年SIEM格局：SOC领导者指南](https://www.elastic.co/cn/blog/ai-siem-landscape) — Elastic中文解读、AI驱动告警分类

### 勒索软件态势
- [360 2025年勒索软件流行态势报告](http://pub1-bjyt.s3.360.cn/bcms/2025%E5%B9%B4%E5%8B%92%E7%B4%A2%E8%BD%AF%E4%BB%B6%E6%B5%81%E8%A1%8C%E6%80%81%E5%8A%BF%E6%8A%A5%E5%91%8A.pdf) — 5858起攻击线索、1639家受害单位、62个勒索家族、52个境外攻击来源国

### Unit 42 中文
- [2026 Unit 42 全球事件响应报告](https://www.paloaltonetworks.cn/resources/research/unit-42-incident-response-report) — 65%身份技术初始访问、$1.5M中位赎金、86%业务中断

### 奇安信
- [补天2025白帽人才报告](https://www.qianxin.com/news/detail?news_id=14336) — 白帽人才实战化能力评估与漏洞响应能力

### Elastic
- [Elastic AI SOC Engine (EASE)](https://www.helpnetsecurity.com/2025/08/07/elastic-ai-soc-engine-helps-soc-teams-expose-hidden-threats/) — Serverless AI驱动上下文感知检测与分流

### Cisco/Splunk
- [Cisco Agentic AI Elevates SOC](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2025/m09/cisco-elevates-the-soc-with-agentic-ai-for-faster-threat-response-and-reduced-complexity.html) — Triage Agent + AI Playbook Authoring + Response Importer
```

### 22. 防御升级路线图

```markdown
## IR 分流防御升级路线图 (P0-P3)

### P0 — 立即实施 (0-30 天)
□ 部署 Agentic AI 分流 POC (选定 1 个平台)
  - 推荐: Cisco Agentic AI (已有 Splunk) / Elastic EASE (已有 Elastic)
□ 建立勒索软件快速分流 SOP (使用 §13 检查清单)
□ 更新事件升级矩阵 (加入身份技术初始访问 65% 统计)
□ 配置 Unit 42 Top CVE 仪表板 (§20 CVE 速查)

### P1 — 短期优化 (1-3 月)
□ AI 分流扩展到 10+ 告警类型
□ 实施供应链攻击分流 SOP (§14)
□ 云事件分流自动化 (§12 GuardDuty/Sentinel/SCC)
□ MITRE ATT&CK v19 映射更新 (§18)

### P2 — 中期建设 (3-6 月)
□ AI SOC 成熟度从 L1 提升到 L2
□ 自动遏制覆盖高置信度场景 (80%+ 准确率)
□ ICS/OT 事件分流 SOP (如有 OT 环境)
□ 告警疲劳量化指标基线建立

### P3 — 持续优化 (6-12 月)
□ AI 分流成熟度 L2 → L3
□ 预测性威胁检测试点
□ 跨组织威胁情报共享
□ 年度 IR 分流效能报告
```

---

### 来源 (Part D)
- [AI SOC Automation in 2026 — Underdefense](https://underdefense.com/blog/ai-soc-automation/)
- [Cisco Elevates SOC with Agentic AI (2025-09)](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2025/m09/cisco-elevates-the-soc-with-agentic-ai-for-faster-threat-response-and-reduced-complexity.html)
- [Elastic AI SOC Engine (EASE) — HelpNetSecurity (2025-08)](https://www.helpnetsecurity.com/2025/08/07/elastic-ai-soc-engine-helps-soc-teams-expose-hidden-threats/)
- [Splunk ES 8.x Tech Talk 2025](https://www.splunk.com/en_us/pdfs/infographics/splunk-enterprise-security-8-x-tech-talk-2025.pdf)
- [2026 Unit 42 Global IR Report](https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report)
- [Unit 42 Extortion and Ransomware Trends 2025](https://unit42.paloaltonetworks.com/2025-ransomware-extortion-trends/)
- [MITRE ATT&CK v19 Updates (2026-04)](https://attack.mitre.org/resources/updates/)
- [Top 15 AI SOC Platforms 2026 — Intezer](https://intezer.com/blog/top-15-ai-soc-platforms-in-2026/)
- [D3 Morpheus SOAR Platform](https://d3security.com/soar-platform/)
- [Best SOAR Platforms 2026 — Exabeam](https://www.exabeam.com/explainers/soar/best-soar-platforms-for-enterprises-top-5-options/)
- [AI-Enabled Incident Triage Playbook — UnderDefense](https://underdefense.com/blog/ai-enabled-incident-triage/)
- [Cyber Triage in 2026 — Radiant Security](https://radiantsecurity.ai/learn/cyber-triage-in-2026-process-technology-and-tips-for-success/)
- [从POC到规模化生产：AI-SOC爆发点 — 安全内参](https://www.secrss.com/articles/86519)
- [万字报告：通往AI增强型SOC之路 — 安全内参](https://www.secrss.com/articles/74219)
- [2025年SOC的AI现状调研 — ModelEngine](https://modelengine.csdn.net/690c526b5511483559e2b062.html)
- [阿里云 Agentic SOC](https://help.aliyun.com/zh/security-center/user-guide/overview-of-threat-analysis)
- [360 2025勒索软件流行态势报告](http://pub1-bjyt.s3.360.cn/bcms/2025%E5%B9%B4%E5%8B%92%E7%B4%A2%E8%BD%AF%E4%BB%B6%E6%B5%81%E8%A1%8C%E6%80%81%E5%8A%BF%E6%8A%A5%E5%91%8A.pdf)
- [AI-Driven Alert Screening Survey — arXiv (2025)](https://arxiv.org/html/2605.08316v2)
