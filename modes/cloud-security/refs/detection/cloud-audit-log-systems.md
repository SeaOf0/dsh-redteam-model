# 云审计日志体系（六厂商对照）

> 定位：检测侧第一手册。C5「检测缺口评估」与「日志投递完整性检查」的事实底座——
> 判定一条攻击路径「检测到/未检测到/无法评估」前，先要知道该厂商到底产生什么审计事件、
> 哪些字段能锁定身份、日志默认留多久、投递到哪。本手册给出六厂商审计日志的事件类型、
> 关键字段、留存与投递配置三件套；保留期数字为常见默认值，**一律以各厂商控制台当前
> 默认值为准**（版本/区域/套餐可能调整）。

## 1. 六厂商审计日志总览

| 厂商 | 审计服务 | 控制面事件 | 数据面事件 | 身份日志 | 长期投递目标 |
|---|---|---|---|---|---|
| AWS | CloudTrail | 管理事件（默认） | 数据事件（S3 对象级/DynamoDB/Lambda，需显式开启） | IAM/STS 事件 | S3 / CloudWatch Logs / EventBridge / CloudTrail Lake |
| Azure | Monitor Activity Log + 诊断设置 | 管理事件（Administrative） | 资源日志（各资源诊断设置单独开启） | Entra ID（SignIn/Audit） | Log Analytics / 存储账户 / 事件中心 |
| GCP | Cloud Audit Logs | Admin Activity（默认常开） | Data Access（默认关闭，按服务开启） | Admin Activity 内 authenticationInfo | Cloud Storage / BigQuery / Pub/Sub / Log Analytics |
| 阿里云 | ActionTrail（操作审计） | 管控事件（默认） | 数据事件（OSS 对象级，需开启） | 管控事件内 userIdentity | OSS / SLS / MNS / MaxCompute |
| 腾讯云 | CloudAudit（操作审计） | 管理事件（默认） | 数据事件（COS 对象级，需开启） | 管理事件内 userIdentity | COS / CLS / CKafka |
| 华为云 | CTS（云审计服务） | 管理事件（默认） | 数据事件（OBS 对象级，需开启） | 管理事件内 user | OBS / LTS / SMN |

**检测侧共性结论**：控制面事件几乎都默认产生、免费、留得久；数据面事件（对象存储读取、
库表访问）几乎都要**显式开启且常计费**——这就是「对象存储对象级读取」类攻击路径最容易
被标为「无法评估/未检测到」的结构性原因。

## 2. AWS CloudTrail

**事件类型**

| 类型 | 触发内容 | 是否默认 | 计费 |
|---|---|---|---|
| Management Events（管理事件） | 控制面 API：IAM/EC2/STS/S3 控制面等 | 默认 | 免费（Event history 90 天） |
| Data Events（数据事件） | S3 对象级 GetObject/PutObject、DynamoDB 表级、Lambda Invoke | 否，逐 Trail 开启 | 计费 |
| Insights Events（洞察事件） | 异常 API 调用率（写/删激增）、异常错误率 | 否，逐 Trail 开启 | 计费 |
| Network Activity Events | VPC 内流量元数据（需 VPC Flow Logs 之外的本体） | 否 | 计费 |

**关键字段**（管理事件样例语义）

| 字段 | 检测用途 |
|---|---|
| `userIdentity.type` | 身份类型：Root/IAMUser/AssumedRole/AWSAccount/AWSService/WebIdentityUser/SAMLUser |
| `userIdentity.arn` / `accessKeyId` / `userName` | 锁定执行者（`AssumedRole` 时含 sessionContext 会话链） |
| `eventSource` / `eventName` | 服务与动作（如 `s3.amazonaws.com` / `PutBucketPolicy`） |
| `eventTime` / `awsRegion` | 时间与区域锚点 |
| `sourceIPAddress` / `userAgent` | 源 IP 与调用方 UA（元数据 SSRF 常现 `169.254.169.254` 侧 UA 或异常 UA） |
| `requestParameters` / `responseElements` | 请求/响应参数（策略变更原文、被读对象 key） |
| `errorCode` / `errorMessage` | 拒绝与失败（`AccessDenied`、`UnauthorizedOperation` 是侦察指纹） |
| `readOnly` | 只读与否（只读侦察 vs 变更） |

**留存与投递**

- 控制台「Event history」默认保留 90 天管理事件，不可配。
- Trail 投递 S3 后按桶生命周期策略决定，默认无限期（建议设 WORM/版本化防篡改）。
- CloudTrail Lake 事件数据存储最长 7 年（3660 天），可配置 7–3657 天。
- 投递链：Trail → S3（gzip JSON）→ 可选 CloudWatch Logs / EventBridge（近实时规则）/ Lake。

## 3. Azure Monitor Activity Log + Entra ID

**事件类型**

| 日志 | 类别 | 内容 | 默认 |
|---|---|---|---|
| Activity Log | Administrative | 控制面写操作（创建 VM、改 NSG） | 默认（90 天保留） |
| Activity Log | Security | Defender for Cloud / Key Vault 告警 | 默认 |
| Activity Log | Policy | 策略评估与违规 | 默认 |
| Activity Log | ServiceHealth / ResourceHealth / Alert / Autoscale / Recommendation | 平台健康与建议 | 默认 |
| 资源日志（诊断设置） | 各资源自定义 | 数据面（存储/Key Vault/DB 访问） | 逐资源开启 |
| Entra ID（原 Azure AD） | SignInLogs / AuditLogs / ProvisioningLogs | 登录、目录变更、用户置备 | 随许可证 |

**关键字段**

| 字段 | 检测用途 |
|---|---|
| `caller` | 操作者（UPN/SPN） |
| `correlationId` / `operationId` | 关联同一请求链 |
| `operationName` | 动作名（如 `Microsoft.Compute/virtualMachines/write`） |
| `category` / `status` | 类别与结果（Succeeded/Failed） |
| `claims`（objectId/tenantId） | 服务主体标识（SPN 是 Azure 攻击面高频身份） |
| `eventTimestamp` / `resourceId` | 时间与资源 |

**留存与投递**

- Activity Log 默认 90 天（平台保留，不可调）；投递后按目标策略延长。
- 投递目标：Log Analytics（1–730 天可配）、存储账户（不可变 blob，长期）、事件中心（近实时）。
- Entra ID 日志保留期随许可证（免费/P1/P2 不同），投递 Log Analytics 后统一留存。
- **检测侧要点**：Azure 控制面变更默认留痕良好；数据面（存储/Key Vault）必须逐资源开诊断设置。

## 4. GCP Cloud Audit Logs

**日志类型**

| 类型 | 内容 | 默认 | 计费 |
|---|---|---|---|
| Admin Activity | 控制面写操作、配置修改 | 常开 | 免费 |
| Data Access | 数据读/写（对象、数据集、Secret 读） | 默认关闭，按服务开启 | 计费 |
| System Event | 平台/元数据服务自身动作 | 常开 | 免费 |
| Policy Denied | 被 IAM 拒绝的请求 | 默认关闭，建议开启 | 计费（可选） |
| Access Transparency | Google 内部人员访问用户数据 | 自动 | 免费 |

**关键字段**

| 字段 | 检测用途 |
|---|---|
| `protoPayload.methodName` / `serviceName` | 动作与服务（如 `storage.objects.get`、`iam.serviceAccounts.actAs`） |
| `protoPayload.authenticationInfo.principalEmail` | 执行者（服务账号/用户） |
| `protoPayload.authorizationInfo[]` | 逐权限判定（permission + granted + resource）——判定越权/尝试的黄金字段 |
| `protoPayload.requestMetadata.callerIp` / `callerSuppliedUserAgent` | 源 IP 与 UA |
| `resource.type` / `resource.labels` | 资源类型与标签 |
| `severity` / `timestamp` | 级别与时间 |

**留存与投递**

- `_Required` 桶：Admin Activity + System Event + Access Transparency，默认 400 天，不可改不可删。
- `_Default` 桶：其余日志，默认 30 天，可调（上限 3650 天）。
- Log Router（汇）→ Cloud Storage / BigQuery / Pub/Sub / Log Analytics / 第三方。
- **检测侧要点**：`Policy Denied` 是侦察/横向尝试的检测富矿，务必开启并投递。

## 5. 阿里云 ActionTrail（操作审计）

**事件类型**

| 类型 | 内容 | 默认 |
|---|---|---|
| 管控事件 | 控制面 API（RAM/ECS/OSS 控制面等） | 默认 |
| 数据事件 | OSS 对象级、部分数据面 API | 需开启（计费） |
| 洞察事件 | 异常行为（高频调用/异常地域） | 需开启 |

**关键字段**

| 字段 | 检测用途 |
|---|---|
| `userIdentity.type` / `principalId` / `accountId` / `accessKeyId` / `userName` | 身份（root/ram-user/assumed-role） |
| `eventName` / `serviceName` / `eventSource` | 动作与服务 |
| `eventTime` / `acsRegion` | 时间与区域 |
| `sourceIpAddress` / `userAgent` | 源 IP 与 UA |
| `requestParameters` / `responseElements` | 参数与响应（策略变更原文） |
| `errorCode` / `readOnly` | 失败与只读标记 |

**留存与投递**

- 控制台默认查询保留常见为 90 天，可延长至 180 天（免费额度，以控制台为准）。
- 投递：OSS（长期归档）/ SLS（检索告警）/ MNS（消息）/ MaxCompute（大数据）。
- 支持单账号/多账号（资源目录）与全局/单地域 Trail。

## 6. 腾讯云 CloudAudit（操作审计）

**事件类型**

| 类型 | 内容 | 默认 |
|---|---|---|
| 管理事件 | 控制面 API（CAM/CVM/COS 控制面等） | 默认 |
| 数据事件 | COS 对象级、部分数据面 | 需开启（计费） |
| 洞察事件 | 异常行为分析 | 需开启 |

**关键字段**

| 字段 | 检测用途 |
|---|---|
| `userIdentity`（type/principalId/accountId/accessKeyId/userName） | 身份（主账号/子用户/角色） |
| `eventName` / `eventSource` / `serviceName` | 动作与服务 |
| `eventTime` / `eventRegion` | 时间与地域 |
| `sourceIpAddress` / `userAgent` | 源 IP 与 UA |
| `requestParameters` / `responseElements` | 参数与响应 |
| `errorCode` / `eventId` | 失败与事件 ID |

**留存与投递**

- 控制台默认查询保留期以控制台为准（常见 90 天级别，随版本调整）。
- 投递：COS（长期归档）/ CLS（日志服务，检索告警）/ CKafka（流式消费）。

## 7. 华为云 CTS（云审计服务）

**事件类型**

| 类型 | 内容 | 默认 |
|---|---|---|
| 管理事件 | 控制面 API（IAM/ECS/OBS 控制面等） | 默认 |
| 数据事件 | OBS 对象级、部分数据面 | 需开启（计费） |
| 关键操作通知 | 高价值操作实时通知 | 可配 |

**关键字段**

| 字段 | 检测用途 |
|---|---|
| `user`（type/name/domain） | 身份（主账号/IAM 用户/委托） |
| `service_type` / `resource_type` / `trace_name` | 服务/资源/动作名 |
| `time` / `region_id` | 时间与区域 |
| `source_ip` / `user_agent` | 源 IP 与 UA |
| `request` / `response` | 参数与响应 |
| `code` / `message` | 结果码与消息 |

**留存与投递**

- 控制台默认查询保留常见为 7 天，可配置（7/30/180/365 天，以控制台为准）。
- 投递：OBS（长期归档）/ LTS（日志检索告警）/ SMN（通知）/ DIS（流式）。
- 追踪器支持组织级与跨地域。

## 8. 跨厂商关键字段对照（检测写规则用）

| 检测需求 | AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|---|---|---|---|---|---|---|
| 执行者身份 | userIdentity.arn | caller/claims | authenticationInfo.principalEmail | userIdentity.principalId | userIdentity | user.name |
| 动作名 | eventName | operationName | protoPayload.methodName | eventName | eventName | trace_name |
| 服务名 | eventSource | 资源 provider | protoPayload.serviceName | serviceName/eventSource | eventSource | service_type |
| 源 IP | sourceIPAddress | callerIpAddress | callerIp | sourceIpAddress | sourceIpAddress | source_ip |
| 失败/拒绝 | errorCode | status | authorizationInfo/PermissionDenied | errorCode | errorCode | code |
| 只读标记 | readOnly | —（按 operationName 推断） | —（按 methodName 前缀 Get/List 推断） | readOnly | — | — |

## 9. 检测侧要点（C5 用）

- **投递完整性检查**：控制面事件是否全部投递到 SIEM/长期存储？数据面事件是否开启？
  是否覆盖组织内所有账号/订阅/项目（多账号 Trail、诊断设置批量、Log Router 组织级）？
- **留存是否够**：默认控制台保留远短于合规要求（常见 90 天/7 天），长期取证必须投递。
- **防篡改**：S3/OBS/COS 对象锁、存储账户不可变 blob、`_Required` 桶不可删——是否启用。
- **数据面盲区**：对象存储对象级读取、密钥库读、数据库读默认不记——对应攻击路径
  「OSS/COS/S3 公开对象枚举读取」「Secrets Manager 读」常标「未检测到」或「无法评估」。
- 本手册只回答「日志在不在/留不留/投没投」，判定三态的方法走
  `cloud-detection-gap-methodology.md`；事件→规则的映射走 `cloud-detection-rule-design.md`。
