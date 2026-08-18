# 云安全监控与告警基线

> 定位：检测侧第四手册。给「控制面变更告警清单」与「日志投递完整性检查」两份可照做的基线，
> 用于 C5 检测缺口评估的收口对照：评估完逐项打勾，勾不上的就是缺口。基线只列检测与告警，
> 不含攻击载荷。

## 1. 控制面变更告警清单（默认应告警项）

按「高价值控制面动作」分组，规则缺失即检测缺口。事件名以 AWS 为主列出，其余厂商对应名
见 `cloud-detection-rule-design.md` 第 2 节。

### 1.1 身份与权限（P0）

| # | 告警项 | 触发动作（跨厂商） | 为什么告警 |
|---|---|---|---|
| 1 | 新建/导入用户或角色 | CreateUser / CreateRole / 新建子用户 | 后门账号 |
| 2 | 新建访问密钥/登录配置 | CreateAccessKey / CreateLoginProfile / createKey | 持久化凭证 |
| 3 | 策略/授权变更 | AttachUserPolicy / PutUserPolicy / roleAssignments/write / setIamPolicy / AttachPolicy | 权限提升 |
| 4 | 信任策略/委托篡改 | UpdateAssumeRolePolicy / 委托关系变更 | 角色链后门 |
| 5 | 角色切换/冒充 | AssumeRole / actAs / AssumeRole | 横向与提权 |
| 6 | Root/主账号直接操作 | Root 身份任意高危 API | 越权管理面 |

### 1.2 资源与暴露面（P1）

| # | 告警项 | 触发动作（跨厂商） | 为什么告警 |
|---|---|---|---|
| 7 | 桶/对象公开化 | PutBucketPolicy / PutBucketAcl / SetIamPolicy(公开) / setIamPolicy | 数据泄露前置 |
| 8 | 安全组/防火墙放行 | AuthorizeSecurityGroupIngress / 安全规则 write / firewalls.patch | 暴露面扩大 |
| 9 | 数据库/密钥库访问策略变更 | 实例公网/白名单/策略变更 | 数据面暴露 |
| 10 | 磁盘/快照公开共享 | 快照共享/镜像公开 | 数据泄露 |

### 1.3 检测对抗（P0）

| # | 告警项 | 触发动作（跨厂商） | 为什么告警 |
|---|---|---|---|
| 11 | 关闭/删除审计 | StopLogging / DeleteTrail / deleteTracker / 诊断设置删除 | 反取证 |
| 12 | 篡改日志投递 | UpdateTrail / PutEventSelectors / updateSink / 投递目标修改 | 截断日志 |
| 13 | 关闭告警/监控 | DisableAlarm / 告警规则删除 / 关闭监控 | 压制告警 |
| 14 | 篡改日志内容/删除日志 | 删除日志存储对象/清空日志 | 证据销毁 |

### 1.4 侦察与异常（P1）

| # | 告警项 | 触发动作（跨厂商） | 为什么告警 |
|---|---|---|---|
| 15 | 身份侦察高频 | 高频 GetCallerIdentity / GetUser / 枚举 | 攻击前置 |
| 16 | 连续拒绝风暴 | 连续 AccessDenied / PermissionDenied | 权限探测 |
| 17 | 异常地域/IP | 敏感动作出现在异常地域/代理 | 账号失陷信号 |
| 18 | 非工作时间高危操作 | 高危动作落在异常时段 | 可疑 |

## 2. 日志投递完整性检查清单

逐项核对，未通过即投递缺口（直接映射 C5 gap=1）：

| # | 检查项 | 通过标准 | 对应厂商配置点 |
|---|---|---|---|
| 1 | 控制面审计开启 | 组织内所有账号/订阅/项目均开启审计 | Trail/诊断设置/Log Router/追踪器 |
| 2 | 数据面日志开启 | 对象存储对象级读取、密钥库读、DB 读已开启 | Data Events/资源日志/数据事件 |
| 3 | 全组织覆盖 | 多账号 Trail、订阅级诊断、组织级 Router/追踪器 | 组织级配置 |
| 4 | 投递到 SIEM | 审计日志进入统一 SIEM/日志平台可检索 | S3→SIEM、Log Analytics、BigQuery、SLS/CLS/LTS |
| 5 | 留存达标 | 满足合规取证周期（≥ 要求的月数） | 生命周期/保留期/归档 |
| 6 | 防篡改 | 日志目标启用对象锁/不可变/`_Required` 桶 | 桶锁、存储不可变 |
| 7 | 告警通道连通 | 规则触发能送达告警（邮件/工单/IM） | 告警订阅/通知 |
| 8 | 日志删除有防护 | 删日志/关审计本身会告警且受限 | 见 1.3 |

## 3. 告警基线的落地口径

- **告警分级**：P0（身份/权限/反取证）实时 + 高优；P1（暴露面/侦察）准实时 + 中优。
- **白名单**：合规扫描器、IaC 流水线、运维自动化身份 + 规律时间窗 + 固定 UA 才可豁免，
  白名单外身份触发同动作升级。
- **基线快照**：评估前快照目标环境的审计/告警/投递配置，登记进任务工作区基线表，
  可还原可对照（与主观念「变更前快照」一致）。
- **检测侧结论**：本清单逐项勾完后，把「勾不上」的项按 `cloud-detection-gap-methodology.md`
  的终态编码写入 `detection-gap.md`；「勾上了」的项记为 covered。

## 4. 告警基线自测打分表（C5 评估落地）

逐项打分，未通过项直接进 `detection-gap.md` 缺口清单：

| # | 打分项 | 通过判据 | 未通过编码 |
|---|---|---|---|
| 1 | 身份/权限类告警（P0 六项）全覆盖 | 每项都有启用中的规则 | 缺哪项哪项 gap=1 |
| 2 | 暴露面类告警（P1 四项）全覆盖 | 每项都有启用中的规则 | 缺哪项哪项 gap=1 |
| 3 | 反取证类告警（P0 四项）全覆盖 | 关日志/改投递/关告警/删日志均告警 | 缺哪项哪项 gap=1 |
| 4 | 侦察异常告警（P1 四项）全覆盖 | 高频侦察/拒绝风暴/异常地域/异常时段有规则 | 缺哪项哪项 gap=1 |
| 5 | 告警通道连通 | 规则触发能送达人（邮件/工单/IM） | 无通道 = 告警无效 → gap=1 |
| 6 | 投递完整性（第 2 节八项）全通过 | 八项均满足 | 缺哪项哪项 gap=1 |
| 7 | 数据面日志覆盖 | 对象存储/密钥库/DB 读取已开 | 未开 → 对应路径 gap=1 |
| 8 | 处置闭环 | 告警有 SOP/责任人与时效 | 无处置 → 记为「规则存在但检测无效」 |

## 5. 各厂商关键告警配置锚点（速查）

| 厂商 | 审计开启点 | 告警/规则点 | 投递目标 |
|---|---|---|---|
| AWS | CloudTrail Trail（多区域+组织） | CloudWatch Alarms / EventBridge Rules / GuardDuty / Security Hub | S3 → SIEM |
| Azure | 诊断设置（订阅级批量） | 监控告警 / Sentinel 分析规则 / Defender for Cloud | Log Analytics / 事件中心 |
| GCP | Log Router 组织级 sink | 日志告警 / Security Command Center / Chronicle | BigQuery / Pub/Sub / Cloud Storage |
| 阿里云 | ActionTrail Trail（全局+多账号） | 云监控告警 / 日志服务 SLS 告警 | OSS / SLS |
| 腾讯云 | CloudAudit 操作审计 | 日志服务 CLS 告警 / 云监控 | COS / CLS / CKafka |
| 华为云 | CTS 追踪器（组织级） | LTS 告警 / SMN 通知 | OBS / LTS |

## 6. 与本目录其它手册的关系

- 事件名/字段含义 → `cloud-audit-log-systems.md`
- 事件 → 规则映射与 Sigma 思路 → `cloud-detection-rule-design.md`
- 三态判定与 C5 编码 → `cloud-detection-gap-methodology.md`
- 本基线 = 判定完成后的「对照打分表」。
