# 完整攻击链还原方法论

> 正文自写原创，来源链接见文末。
> 目标：把「可疑 IP → 入口点 → 攻击行为 → 持久化 → 影响范围」串成一条有证据闭环的攻击链，产出可复核的溯源报告。

## 1. 攻击链模型

标准五段链，每段都要有证据锚点：

```
入口(Initial Access) → 提权(Priv Esc) → 持久化(Persistence) → 横向(Lateral Movement) → 目标达成(Impact)
```

| 阶段 | 典型证据（Event ID / 痕迹） | 自写检测点 |
|---|---|---|
| 入口 | 钓鱼（邮件头/附件哈希/4688 打开附件）、爆破（4625→4624）、漏洞（补丁缺口 + 利用日志） | 入口源 IP、入口方式 |
| 提权 | 4672 特殊权限、4688 提权工具、Token 提升 | 谁从普通权限变管理员 |
| 持久化 | 4697/7045 服务、4698 计划任务、4720/4732 账户、Run 键、WMI 订阅 | 落盘样本 + 持久化点 |
| 横向 | 4624 Type 3、4648 显式凭据、4776 NTLM、4688 PsExec/schtasks | 从 A 主机到 B 主机的登录/执行 |
| 目标达成 | 数据外传（外连 IP/流量）、勒索加密（MFT 时间戳）、窃密（lsass 访问） | 影响范围 + 数据去向 |

## 2. 时间线锚点选取

从多源时间线（见 logs/timeline-building.md）里选锚点，锚点=「可被独立证据支撑的关键动作时间」：

```powershell
# 锚点候选（每个锚点都查具体证据，不只看时间）
# ① 首个异常登录（入口）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} | Where-Object {$_.Properties[18].Value -eq '<可疑IP>'} | Select TimeCreated,Id
# ② 首个异常进程（落地/执行）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} | Where-Object {$_.Properties[8].Value -match '<样本名>|powershell|cmd'} | Select TimeCreated
# ③ 首个持久化动作（服务/任务/账户）
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} | Select TimeCreated,Id
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698,4720,4732} | Select TimeCreated,Id
```

- 锚点选取原则：优先选「有独立证据源可交叉」的时间点（同一动作在日志+MFT+注册表都能看到）；锚点间隔越短，攻击链还原越可信。

## 3. 证据链闭环（多源互证）

单条证据不构成结论，每个链节点需至少两个独立来源互证：

| 链节点 | 证据源 1 | 证据源 2 | 证据源 3（可选） |
|---|---|---|---|
| 入口登录 | Security 4624（源 IP/账户） | RDP/中间件日志 c-ip | DNS 缓存/防火墙日志 |
| 样本落地 | MFT（文件创建时间/路径） | Sysmon 11（文件创建） | Amcache/Prefetch（执行痕迹） |
| 命令执行 | 4688（命令行） | PowerShell 4104（脚本块） | Sysmon 1（进程创建） |
| 持久化 | 4698/7045（任务/服务） | 注册表（Run 键/Service） | 计划任务 XML 文件时间戳 |
| 数据外传 | netstat/Sysmon 3（外连） | 防火墙日志（流量） | DNS 缓存/Sysmon 22 |

- 闭环判据：时间相关（各证据时间戳在合理误差内一致）+ 行为链（A 动作的产出是 B 动作的输入，如「落地样本 → 样本被执行 → 样本写服务」）。

## 4. IP 溯源（攻击者 IP 的确定与去伪）

### 4.1 攻击源 IP 的多个来源

```powershell
# ① DNS 缓存（域名→IP 解析历史）
Get-DnsClientCache | Select Entry,Data,TimeToLive
ipconfig /displaydns

# ② 当前网络连接（是否还有活跃外连）
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select RemoteAddress,RemotePort,OwningProcess

# ③ 登录源 IP（Security 日志）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} | Group-Object {$_.Properties[18].Value} | Select Count,Name

# ④ 中间件日志 c-ip（Web 入口）
Get-ChildItem C:\inetpub\logs\LogFiles -Recurse -Filter *.log | Select-String -Pattern '<可疑URI>' | ForEach-Object { ($_ -split ' ')[8] } | Group-Object | Sort-Object Count -Descending
```

### 4.2 防火墙日志

```powershell
# Windows 防火墙日志（需开启；位置 C:\Windows\System32\LogFiles\Firewall\pfirewall.log）
Get-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log -Tail 500
# 字段：日期 时间 动作 协议 源IP 目的IP 源端口 目的端口
```

### 4.3 IP 去伪（关键：区分「真攻击源」与「跳板/代理/误报」）

- 攻击源 IP 可能是：真实攻击者、被控制的跳板主机、VPN/代理/Tor 出口、云厂商匿名 IP、内网其它失陷主机（横向源）。
- 去伪方法：威胁情报富化（是否已知恶意/扫描源）、WHOIS 归属（云厂商 IP 常是匿名攻击基建）、时间相关性（该 IP 是否只在攻击窗出现）、多主机交叉（是否多台主机都记录到同一 IP = 真实横向源）。
- **结论表述**：只能确定「发起攻击的源 IP」，不能武断「攻击者身份」；跳板 IP 记为「攻击流量来源」，真实归属需情报侧进一步关联。

## 5. Super Timeline 构建（还原全貌）

```powershell
# 把多源证据并入一条时间线（详见 logs/timeline-building.md）
# 1) KAPE 采集 → 2) EvtxECmd/MFTECmd 解析 → 3) 归一排序 → 4) 聚类行为
```

- 攻击链还原 = Super Timeline 上「按对象（IP/账户/样本/主机）聚类出行为片段，再按时间串成链」。

## 6. 报告叙事结构（真实案例报告形态）

溯源报告建议章节（自写，不抄其文章）：

1. **摘要**：一句话结论（什么事件、谁（源 IP）、怎么进来、影响多大）。
2. **时间线总览**：攻击链时间线表（时间节点 | 可疑 IP | 事件 | 证据编号），一屏看清全链。
3. **入口点与失陷原因**：入口方式（爆破/钓鱼/漏洞）+ 失陷根因（弱口令/未打补丁/配置缺陷）。
4. **攻击链还原**：逐段展开（入口→提权→持久化→横向→影响），每段附证据原文（日志片段/哈希/时间戳）。
5. **影响范围评估**：受影响主机/账户/数据清单 + 数据外泄评估。
6. **恶意文件与持久化清单**：路径 + 哈希 + 持久化点 + MITRE ATT&CK 映射。
7. **IOC 汇总**：哈希/域名/IP/端口四元组（供封禁与检测）。
8. **处置建议**：清理清单（用户确认执行）+ 加固建议。
9. **证据索引**：artifact list（文件 + 哈希 + 时间戳），保证可复核。

## 7. 报告要求（对齐 persona 六字段）

- 每条时间线结论必须有证据支撑（日志原文/哈希/时间戳/进程/网络），无证据标「疑似」。
- 时间线节点登记到会话「redteam 成果」页 incident-response 页（时间线板式），一行=一个节点。
- 攻击链每个节点回指时间线锚点 + 证据编号，做到「结论 → 证据 → 编号」可回溯。

## 来源

- The DFIR Report（攻击链还原报告范式，正文自写）：https://thedfirreport.com/
- SANS DFIR Posters（取证位置/事件 ID 速查）：https://www.sans.org/posters/
- KAPE / plaso（时间线工具链）：https://github.com/EricZimmerman/KapeFiles · https://github.com/log2timeline/plaso
- MITRE ATT&CK（攻击阶段分类）：https://attack.mitre.org/
