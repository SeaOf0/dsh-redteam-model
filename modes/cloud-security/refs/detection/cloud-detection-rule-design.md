# 云检测规则设计（事件 → 检测规则）

> 定位：检测侧第二手册。把「关键攻击动作」映射为「各厂商审计事件名」，再给出检测规则要点
> 与 Sigma 规则云版思路。用于 C5 检测缺口评估时回答「这条攻击路径在目标环境里**应该**留下
> 什么日志、对应什么规则、规则缺失即缺口」。规则只面向检测与告警，不含攻击载荷。

## 1. 关键攻击动作 → 审计事件名映射（总表）

| 攻击动作 | AWS 事件名 | Azure | GCP | 阿里云 | 腾讯云 | 华为云 | 检测要点 |
|---|---|---|---|---|---|---|---|
| 身份侦察（我是谁） | `sts:GetCallerIdentity` | —（IMDS 或 Graph 调用） | `sts.GetCallerIdentity`（或元数据） | `ram:GetUser`/`sts:GetCallerIdentity` | `cam:GetUserAppId`/GetCallerIdentity 类 | `iam:showUser`/元数据 | 高频 GetCallerIdentity 多为侦察指纹 |
| 角色/身份切换 | `sts:AssumeRole` | SPN 授权（`Microsoft.Authorization/roleAssignments/write`） | `iam.serviceAccounts.actAs` / `sts.ExchangeToken` | `sts:AssumeRole` | `cam:AssumeRole` | `iam:assumeRole`/委托 | AssumeRole 后 sessionContext 锁定信任链 |
| 元数据服务访问 | `ec2` 实例内（通常不产生控制面事件） | IMDS 访问（主机侧留痕弱） | `compute` 元数据访问（主机侧） | ECS 元数据访问（主机侧） | CVM 元数据访问（主机侧） | ECS 元数据访问（主机侧） | 元数据 SSRF 常无控制面日志，靠 VPC Flow / 主机 agent / 应用日志 |
| 桶/对象策略变更 | `s3:PutBucketPolicy` / `PutBucketAcl` / `PutObject` | 存储容器 ACL / 防火墙策略变更 | `storage.buckets.setIamPolicy` | `oss:PutBucketPolicy` / `PutBucketAcl` | `cos:PutBucketPolicy` / `PutBucketAcl` | `obs:SetBucketPolicy` / `SetBucketAcl` | 公开化是数据泄露前置，必告警 |
| IAM/权限变更 | `iam:CreateAccessKey` / `AttachUserPolicy` / `CreateRole` / `UpdateAssumeRolePolicy` / `PutUserPolicy` | `Microsoft.Authorization/roleAssignments/write` / SPN 凭据添加 | `iam.serviceAccounts.create` / `setIamPolicy` / `createKey` | `ram:CreateAccessKey` / `AttachPolicyToUser` / `CreateRole` | `cam:CreateAccessKey` / `AttachPolicy` / `CreateRole` | `iam:createAKSK` / `grantRoleToUser` | 权限提升与后门账号核心，必告警 |
| 密钥/凭证读取 | `secretsmanager:GetSecretValue` / `kms:Decrypt` | Key Vault 数据面 `VaultGet` | `secretmanager.versions.access` | `kms:Decrypt` / OSS 凭证读取 | `cam:GetSecretValue` 类 / SSM | `kms:decrypt` / DEW 读 | 高频读密或异常身份读密 |
| 安全组/防火墙放行 | `ec2:AuthorizeSecurityGroupIngress` | `Microsoft.Network/networkSecurityGroups/securityRules/write` | `compute.firewalls.patch` | `ecs:AuthorizeSecurityGroup` | `vpc:ModifySecurityGroupPolicies` 类 | `vpc:updateSecurityGroupRule` | 0.0.0.0/0 放行高危端口必告警 |
| 日志/监控关闭 | `cloudtrail:StopLogging` / `DeleteTrail` / `cloudwatch:DisableAlarm` | 诊断设置删除 / 告警规则删除 | `logging.updateSink`（禁用/改投递） | `actiontrail:StopLogging` | `cloudaudit:StopLogging` | `cts:deleteTracker` | 反取证，必告警且投递前不可被删 |
| 容器/集群操作 | `eks:UpdateClusterConfig` / `sts:GetCallerIdentity`→kubeconfig | AKS `Microsoft.ContainerService` 操作 | `container.clusters.*` | `cs:...`（ACK） | `tke:...` | `cce:...` | 集群接管前兆 |
| 横向/角色链 | 多次 `AssumeRole` + 资源枚举 | 多 SPN 切换 | 多 `actAs` | 多次 AssumeRole | 多次 AssumeRole | 多次委托 | 角色链异常即告警 |

## 2. 各厂商高价值检测事件清单（建规则优先覆盖）

**AWS（CloudTrail eventName）**

| 优先级 | 事件 | 含义 |
|---|---|---|
| P0 | `CreateAccessKey` / `CreateLoginProfile` / `AttachUserPolicy` / `PutUserPolicy` / `CreateUser` | 新凭证/提权/后门 |
| P0 | `UpdateAssumeRolePolicy` / `CreateRole` / `AssumeRole` | 信任策略篡改/角色切换 |
| P0 | `StopLogging` / `DeleteTrail` / `UpdateTrail` / `PutEventSelectors` | 审计禁用/投递篡改 |
| P1 | `PutBucketPolicy` / `PutBucketAcl` / `PutBucketPublicAccessBlock`（反向关闭） | 桶公开化 |
| P1 | `AuthorizeSecurityGroupIngress` / `ModifySecurityGroupRules` | 网络放行 |
| P1 | `GetSecretValue` / `Decrypt`（异常） | 读密 |
| P1 | `GetCallerIdentity`（异常高频/异常地域） | 侦察 |

**Azure（operationName）**

| 优先级 | operationName | 含义 |
|---|---|---|
| P0 | `Microsoft.Authorization/roleAssignments/write` | RBAC 授权（提权/持久化） |
| P0 | `Microsoft.AzureActiveDirectory/...`（Entra Audit：添加应用凭据/SPN、同意授权） | OAuth 后门 |
| P0 | 诊断设置删除 / `Microsoft.Insights/.../delete` | 监控关闭 |
| P1 | `Microsoft.Network/networkSecurityGroups/securityRules/write` | 网络放行 |
| P1 | `Microsoft.Storage/storageAccounts/...`（容器 ACL 变更、Blob 公开） | 存储公开化 |
| P1 | Key Vault `VaultGet`（数据面，诊断设置开启后） | 读密 |

**GCP（protoPayload.methodName）**

| 优先级 | methodName | 含义 |
|---|---|---|
| P0 | `iam.serviceAccounts.create` / `iam.serviceAccounts.createKey` / `setIamPolicy` | 服务账号/密钥/授权 |
| P0 | `logging.updateSink` / `logging.deleteSink` | 日志投递篡改 |
| P0 | `storage.buckets.setIamPolicy` / `setIamPolicy`（公开） | 桶公开化 |
| P1 | `secretmanager.versions.access` | 读密 |
| P1 | `compute.firewalls.patch` / `insert` | 防火墙放行 |
| P1 | `sts.ExchangeToken` / `iam.serviceAccounts.actAs` | 令牌交换/冒充 |

**阿里云 / 腾讯云 / 华为云（eventName/trace_name）**

| 优先级 | 通用动作（各厂商名） | 含义 |
|---|---|---|
| P0 | CreateAccessKey / CreateUser / AttachPolicy / CreateRole / AssumeRole | 凭证/提权/后门 |
| P0 | StopLogging / DeleteTrail / UpdateTrail | 审计禁用 |
| P1 | PutBucketPolicy / PutBucketAcl / SetBucketPolicy / SetBucketAcl | 桶公开化 |
| P1 | AuthorizeSecurityGroup / ModifySecurityGroupRule | 网络放行 |
| P1 | GetSecret / Decrypt（异常） | 读密 |

## 3. 检测规则要点（每条规则三问）

写规则前对每条事件回答三问，缺一即「规则不完整」：

1. **身份维度**：执行者是谁？是否异常身份（Root 直接操作、临时会话、跨账号 AssumeRole、
   平时不用的服务账号、新创建的账号）。规则应锚定 `userIdentity` 或 `authenticationInfo`。
2. **上下文维度**：源 IP/UA 是否异常（境外、代理、`169.254.169.254` 回环、脚本 UA）？
   时间是否异常（非工作时间、爆破式高频）？资源是否高敏（生产桶、密钥库、根账号策略）？
3. **结果维度**：成功还是失败？连续 `AccessDenied`/`PermissionDenied` 是侦察前置；
   成功的高危变更（公开化、授权、关日志）才是告警主体。

**误报规避**：合规扫描器、IaC 部署流水线、运维自动化会规律性触发 CreateAccessKey/
AuthorizeSecurityGroup 等事件——规则要白名单「已知自动化身份 + 规律时间窗 + 固定 UA」，
对白名单外身份的同事件升级为高优。

## 4. Sigma 规则云版思路

Sigma 规则跨 SIEM 可移植；云事件源用 `logsource.category` 与 `service` 标识。云版要点：

- **logsource 约定**（示例结构，非某产品专属）：

```yaml
title: 云账号疑似权限提升（新建访问密钥）
logsource:
  category: cloud_audit          # 云审计日志统一类别
  service: aws.cloudtrail         # 或 azure.activitylog / gcp.cloudaudit / aliyun.actiontrail ...
detection:
  selection:
    eventName: CreateAccessKey
  condition: selection
level: high
```

- **字段映射**：不同 SIEM 里同一语义字段名不同（`eventName`/`operationName`/`methodName`/
  `trace_name`），Sigma 用 `fieldmappings` 归一，或直接写多服务规则拆分。
- **跨厂商同义动作**：一套「桶公开化」检测要覆盖 6 个厂商的事件名（见第 1 节），建议
  按服务拆成多规则、共享一份「高危动作名清单」。
- **数据面事件源**：对象存储对象级读取多记录于访问日志（S3 访问日志、OSS/COS/OBS 日志），
  不是控制面审计——Sigma 应单列 `category: cloud_data_access`。
- **元数据 SSRF 检测难在控制面无事件**：应结合 VPC Flow Logs（去 169.254.169.254 的异常
  回环流量）+ 应用侧 SSRF 特征（`Host: 169.254.169.254`、`X-Forwarded-For` 注入）。

## 5. 规则产出优先级（C5 评估用）

| 序 | 规则主题 | 对应攻击路径 | 覆盖缺口判定 |
|---|---|---|---|
| 1 | IAM/凭证变更告警 | 权限提升/后门账号 | 无此规则 → 该路径「未检测到」gap=1 |
| 2 | 桶/对象公开化告警 | 对象存储配置缺陷 | 同上 |
| 3 | 安全组/防火墙放行告警 | 暴露面扩大 | 同上 |
| 4 | 日志/监控关闭告警 | 检测对抗 | 同上 |
| 5 | 读密/解密异常告警 | 凭证读取/横向 | 同上 |
| 6 | 身份侦察（GetCallerIdentity/AssumeRole 链） | 侦察与角色链 | 同上 |

> 规则存在 ≠ 检测有效：还要看「日志是否投递到规则所在 SIEM」「规则是否已启用并接入告警
> 通道」「告警是否有人处置」。完整判定走 `cloud-detection-gap-methodology.md`。
