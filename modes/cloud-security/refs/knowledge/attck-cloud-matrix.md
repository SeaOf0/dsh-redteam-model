# ATT&CK Cloud Matrix 速查（战术与技术 ID 对照）

> 定位：知识索引手册。报告第 7 章「MITRE ATT&CK Cloud Matrix 映射」的对照底表——把每条
> 攻击路径映射到云矩阵战术/技术 ID，并标注 Azure/GCP 变体。技术 ID 为 ATT&CK 标准编号，
> 随版本演进，写入报告时以当次检索到的版本为准。

## 1. 云矩阵战术（Tactics）总表

| TA ID | 战术 | 云上典型动作 |
|---|---|---|
| TA0042 | Resource Development（资源发展） | 注册云账号、获取被盗凭证、构建云基础设施 |
| TA0001 | Initial Access（初始访问） | 有效云账号登录、利用公开应用、窃取应用访问令牌 |
| TA0003 | Persistence（持久化） | 额外云凭证、额外云角色、额外邮箱委派权限 |
| TA0004 | Privilege Escalation（权限提升） | 云账号滥用、额外云凭证/角色、滥用提权机制 |
| TA0005 | Defense Evasion（防御规避） | 关闭日志、修改云基础设施、禁用监控 |
| TA0006 | Credential Access（凭据访问） | 云实例元数据 API、不安全的凭证存储 |
| TA0007 | Discovery（发现） | 云基础设施/服务/对象存储/容器发现 |
| TA0008 | Lateral Movement（横向移动） | 云账号切换、应用令牌窃取、角色冒充 |
| TA0009 | Collection（收集） | 云存储对象、配置仓库数据 |
| TA0010 | Exfiltration（窃取） | 转存到云账号、经 Web 服务外传 |
| TA0040 | Impact（影响） | 数据销毁、资源劫持（挖矿）、网络拒绝服务 |

## 2. 云矩阵技术（Techniques）与厂商变体

### 2.1 身份与凭据

| T ID | 技术 | AWS 表现 | Azure 表现 | GCP 表现 |
|---|---|---|---|---|
| T1078.004 | Cloud Accounts（有效云账号） | IAM 用户/角色登录 | 用户/SPN/托管身份 | 用户/服务账号 |
| T1528 | Steal Application Access Token | 窃取 OAuth/STS 令牌 | 窃取 OAuth/托管身份令牌 | 窃取 OAuth 令牌 |
| T1552.005 | Cloud Instance Metadata API | IMDS v1/v2 取角色凭证 | IMDS 取托管身份令牌 | 元数据服务取服务账号令牌 |
| T1098.001 | Additional Cloud Credentials | 新建 IAM AccessKey | 为 SPN 添加凭据 | 新建服务账号密钥 |
| T1098.002 | Additional Email Delegate Permissions | — | 邮箱委派/转发 | — |
| T1098.003 | Additional Cloud Roles | 附加高权策略/角色 | 附加 Azure AD 角色 | 绑定高权 IAM 角色 |
| T1136.003 | Cloud Account | 新建 IAM 用户 | 新建 Azure AD 用户 | 新建服务账号/用户 |
| T1078 | Valid Accounts | 通用 | 通用 | 通用 |

### 2.2 权限提升与滥用

| T ID | 技术 | AWS 表现 | Azure 表现 | GCP 表现 |
|---|---|---|---|---|
| T1078.004 | Cloud Accounts（高权账号） | AssumeRole 链 | 角色激活/提权 | 角色冒充 |
| T1548 | Abuse Elevation Control Mechanism | 滥用角色信任策略 | 滥用托管身份/角色 | 滥用 actAs/impersonation |
| T1098.001 | Additional Cloud Credentials（提权） | 自建密钥 | 自加 SPN 凭据 | 自建 key |

### 2.3 发现（Discovery）

| T ID | 技术 | 说明 |
|---|---|---|
| T1526 | Cloud Service Discovery | 枚举云服务/API |
| T1580 | Cloud Infrastructure Discovery | 枚举云基础设施（实例/网络/存储） |
| T1619 | Cloud Storage Object Discovery | 枚举对象存储对象 |
| T1613 | Container and Resource Discovery | 容器与资源发现 |
| T1083 | File and Directory Discovery | 文件目录发现 |

### 2.4 收集与窃取（Collection / Exfiltration）

| T ID | 技术 | 说明 |
|---|---|---|
| T1530 | Data from Cloud Storage Object | 读取云存储对象 |
| T1602.002 | Network Device Configuration Dump | 网络配置转储 |
| T1537 | Transfer Data to Cloud Account | 数据转存到攻击者云账号 |
| T1567 | Exfiltration Over Web Service | 经 Web 服务外传 |
| T1119 | Automated Collection | 自动化收集 |

### 2.5 影响与破坏（Impact）

| T ID | 技术 | 说明 |
|---|---|---|
| T1485 | Data Destruction | 数据销毁 |
| T1496.001 | Compute Hijacking | 计算资源劫持（挖矿） |
| T1498 | Network Denial of Service | 网络拒绝服务 |
| T1578 | Modify Cloud Compute Infrastructure | 修改云计算基础设施 |

### 2.6 防御规避与基础设施（Defense Evasion / Resource Development）

| T ID | 技术 | 说明 |
|---|---|---|
| T1578.001 | Create Snapshot | 建快照（偷数据/留副本） |
| T1578.002 | Create Cloud Instance | 建实例 |
| T1578.003 | Delete Cloud Instance | 删实例（毁证据） |
| T1578.004 | Revert Cloud Instance | 回滚实例（毁证据） |
| T1525 | Implant Internal Image | 植入内部镜像（供应链） |
| T1190 | Exploit Public-Facing Application | 利用公开应用 |
| T1195.001 | Compromise Software Dependencies and Development Tools | 供应链投毒 |

## 3. 云攻击路径 → ATT&CK 映射速查

| 攻击路径 | 主要战术 | 主要技术 ID |
|---|---|---|
| AK/SK 泄露 → 对象读取 | TA0001→TA0009→TA0010 | T1078.004 → T1530/T1619 → T1567 |
| 元数据 SSRF → 角色接管 | TA0006→TA0004 | T1552.005 → T1078.004 |
| IAM 提权/后门 | TA0004/TA0003 | T1098.001/T1098.003/T1136.003 |
| 对象存储配置缺陷（公开桶） | TA0009/TA0010 | T1530/T1619 → T1567 |
| 安全组放行 → 横向 | TA0008 | T1078.004/T1528 |
| 容器逃逸 → 集群提权 | TA0004→TA0008 | T1613/T1078.004 |
| 关闭审计（反取证） | TA0005 | T1578/T1562（Indicator Removal） |
| 勒索/挖矿（影响） | TA0040 | T1485/T1496.001/T1486 |

## 4. 使用口径

- 每条攻击路径在报告第 7 章映射到 1 个战术 + 1–3 个技术 ID，写「路径 → 战术 TAxxxx →
  技术 Txxxx[.xxx]」，与第 2 章攻击路径清单一一对应。
- 映射要克制：只标**已实际发生/已验证**的技术，不把未执行步骤的技术 ID 塞进报告
  （主观念「发现 ≠ 真实」在映射上的体现）。
- 云矩阵技术 ID 以 ATT&CK 官方当前版本为准，写入时确认编号未变；本表为常用对照快照。
- 检测侧：每个技术 ID 可反查「该技术应留的日志与规则」→ `../detection/cloud-detection-rule-design.md`
  与 `../detection/cloud-audit-log-systems.md`，用于 C5 检测缺口评估。
