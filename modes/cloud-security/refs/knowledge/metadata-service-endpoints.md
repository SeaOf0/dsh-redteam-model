# 六厂商元数据服务端点与实例身份对照表（附录 A）

> 定位：知识索引附录 A，元数据 SSRF 与实例身份接管的速查底座。云安全模式的元数据探测、
> SSRF→实例角色/托管身份/服务账号接管的路径验证，都以本表为准。路径与端点以官方文档
> 为准（版本/区域可能调整），表中为常见公开默认值；访问实例元数据属于授权范围内的
> 只读验证动作，探测须遵守 `cloud-api-readonly-probing.md`（附录 B）的速率与账单纪律。

## 1. 六厂商元数据端点总览

| 厂商 | 元数据 IP | 域名别名 | 认证方式 | 实例身份凭证类型 |
|---|---|---|---|---|
| AWS | 169.254.169.254 | — | IMDSv1（无令牌）或 IMDSv2（PUT 令牌） | 实例角色（临时 AK/SK/Token） |
| Azure | 169.254.169.254 | — | 必须带 `Metadata: true` 头 + api-version | 托管身份（OAuth2 访问令牌） |
| GCP | 169.254.169.254 | metadata.google.internal | 必须带 `Metadata-Flavor: Google` 头 | 服务账号（访问令牌/身份 JWT） |
| 阿里云 | 100.100.100.200 | 100.100.100.200 | 默认无头（可配访问限制） | RAM 角色（临时 AK/SK/Token） |
| 腾讯云 | 169.254.0.23 | metadata.tencentyun.com | 默认无头 | CAM 角色（临时密钥） |
| 华为云 | 169.254.169.254 | — | 默认无头 | 委托（Agency）临时密钥 |

**关键差异记忆点**：阿里云元数据 IP 不是 169.254.169.254 而是 **100.100.100.200**；
腾讯云是 **169.254.0.23**；Azure 靠 `Metadata: true` 头、GCP 靠 `Metadata-Flavor: Google`
头做访问控制；AWS 有 v1/v2 两代（v2 需先 PUT 拿令牌）。

## 2. AWS IMDS（v1/v2）

| 项 | IMDSv1 | IMDSv2 |
|---|---|---|
| 访问方式 | 直接 `GET /latest/meta-data/...` | 先 `PUT /latest/api/token` 拿令牌再 `GET` |
| 令牌请求头 | — | `X-aws-ec2-metadata-token-ttl-seconds: 21600` |
| 后续请求头 | — | `X-aws-ec2-metadata-token: <TOKEN>` |
| SSRF 利用难点 | 简单（直接 GET） | 需能发 PUT 且带 TTL 头（多数 HTTP 库 SSRF 只 GET，天然阻断） |

**常用路径**

| 路径 | 返回 |
|---|---|
| `/latest/meta-data/` | 元数据根（列可用的子项） |
| `/latest/meta-data/instance-id` | 实例 ID |
| `/latest/meta-data/hostname` / `local-hostname` | 主机名 |
| `/latest/meta-data/iam/security-credentials/` | 可用的角色名列表 |
| `/latest/meta-data/iam/security-credentials/<role>` | 角色的临时 AK/SK/Token/Expiration（核心） |
| `/latest/meta-data/public-keys/` | 公钥材料 |
| `/latest/meta-data/network/interfaces/macs/<mac>/` | 网络接口信息 |
| `/latest/dynamic/instance-identity/document` | 实例身份文档（accountId/region/instanceId） |
| `/latest/user-data/` | 用户数据（常含敏感 bootstrap 脚本/密钥） |

**禁用/加固**

| 项 | 说明 |
|---|---|
| `HttpEndpoint=disabled` | 彻底关闭 IMDS |
| `HttpTokens=required` | 强制 IMDSv2（阻断纯 GET SSRF） |
| `HttpPutResponseHopLimit=1` | 限制令牌转发跳数（防容器/多跳） |
| 实例元数据选项 | 通过实例 metadata options / launch template 配置 |

## 3. Azure IMDS（托管身份）

**访问要求**：所有请求必须带 `Metadata: true`（区分大小写）头，且指定 `api-version`。

| 路径 | 返回 |
|---|---|
| `/metadata/instance?api-version=2021-02-01` | 计算实例信息根 |
| `/metadata/instance/compute/name` / `resourceGroupName` / `subscriptionId` / `vmId` | 实例与订阅信息 |
| `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<aud>` | 托管身份访问令牌（核心） |

**托管身份令牌请求样例语义**

```
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Headers: Metadata: true
```
返回 `access_token`（含 `expires_in`/`token_type`），即实例对应系统/用户托管身份的令牌。
`resource` 决定令牌受众（`management.azure.com`、`vault.azure.net`、`graph.microsoft.com` 等）。

**禁用/加固**：系统托管身份在 VM 上可关闭（Managed Identity 开关）；IMDS 本身不可整机关闭，
但可通过限制实例网络（NSG 拒绝 169.254.169.254 出站）与关闭托管身份降低风险。

## 4. GCP 元数据服务器（服务账号）

**访问要求**：必须带 `Metadata-Flavor: Google` 头（防 SSRF 的经典手段）。

| 路径 | 返回 |
|---|---|
| `/computeMetadata/v1/` | 元数据根 |
| `/computeMetadata/v1/instance/` | 实例信息（id/hostname/zone 等） |
| `/computeMetadata/v1/project/project-id` | 项目 ID |
| `/computeMetadata/v1/instance/service-accounts/` | 服务账号列表 |
| `/computeMetadata/v1/instance/service-accounts/<sa>/token` | 服务账号访问令牌（核心，OAuth） |
| `/computeMetadata/v1/instance/service-accounts/<sa>/identity?audience=<aud>` | 身份 JWT（用于服务间认证） |
| `/computeMetadata/v1/instance/service-accounts/<sa>/email` | 服务账号邮箱 |
| `/computeMetadata/v1/instance/attributes/` | 自定义元数据（可能含密钥/启动脚本） |

**禁用/加固**：元数据服务器可选「禁用」；GKE 上可用 Workload Identity 替代节点服务账号；
默认服务账号的 OAuth scope 应最小化。

## 5. 阿里云 ECS 元数据（RAM 角色）

| 项 | 说明 |
|---|---|
| 元数据 IP | 100.100.100.200（非 169.254.169.254） |
| 访问方式 | 默认无认证头；可配置「元数据访问限制」（hops） |

| 路径 | 返回 |
|---|---|
| `/latest/meta-data/` | 元数据根 |
| `/latest/meta-data/instance-id` / `hostname` | 实例 ID/主机名 |
| `/latest/meta-data/ram/security-credentials/` | 可用的 RAM 角色名 |
| `/latest/meta-data/ram/security-credentials/<role>` | 角色的临时 AK/SK/SecurityToken/Expiration（核心） |
| `/latest/dynamic/instance-identity/document` | 实例身份文档（account-id/region/instance-id） |
| `/latest/user-data/` | 用户数据（bootstrap 脚本） |

**禁用/加固**：关闭实例元数据访问；配置 hops 限制；RAM 角色最小权限 + 限制角色被谁 Assume。

## 6. 腾讯云 CVM 元数据（CAM 角色）

| 项 | 说明 |
|---|---|
| 元数据 IP | 169.254.0.23（域名 metadata.tencentyun.com） |
| 访问方式 | 默认无认证头 |

| 路径 | 返回 |
|---|---|
| `/latest/meta-data/` | 元数据根 |
| `/latest/meta-data/instance-id` / `hostname` | 实例 ID/主机名 |
| `/latest/meta-data/cam/security-credentials/` | 可用的 CAM 角色名 |
| `/latest/meta-data/cam/security-credentials/<role>` | 角色的临时密钥（TmpSecretId/TmpSecretKey/Token/ExpiredTime，核心） |
| `/latest/meta-data/app-id` / `uuid` | 应用/实例标识 |
| `/latest/meta-data/user-data` | 用户数据 |

**禁用/加固**：关闭元数据访问或限制 hops；CAM 角色最小权限、绑定实例。

## 7. 华为云 ECS 元数据（委托 Agency）

| 项 | 说明 |
|---|---|
| 元数据 IP | 169.254.169.254 |
| 访问方式 | 默认无认证头 |

| 路径 | 返回 |
|---|---|
| `/openstack/latest/meta_data.json` | 实例元数据 JSON（含 instance-id/hostname 等） |
| `/latest/meta-data/` | 元数据根 |
| `/latest/meta-data/instance-id` / `hostname` | 实例 ID/主机名 |
| `/latest/meta-data/securitykey` | 委托（Agency）临时密钥（AK/SK/securitytoken，核心） |
| `/latest/meta-data/user_data` | 用户数据 |

**禁用/加固**：关闭元数据访问或限制 hops；委托最小权限、限制委托给哪些服务。

## 8. 实例身份/角色/凭证获取路径对照（核心速查）

| 厂商 | 身份凭证路径 | 返回的关键字段 | 认证头 |
|---|---|---|---|
| AWS | `/latest/meta-data/iam/security-credentials/<role>` | AccessKeyId/SecretAccessKey/Token/Expiration | v2 需令牌头 |
| Azure | `/metadata/identity/oauth2/token?...` | access_token/expires_in/token_type | `Metadata: true` |
| GCP | `/computeMetadata/v1/instance/service-accounts/<sa>/token` | access_token（OAuth） | `Metadata-Flavor: Google` |
| 阿里云 | `/latest/meta-data/ram/security-credentials/<role>` | AccessKeyId/SecretAccessKey/SecurityToken/Expiration | 无（默认） |
| 腾讯云 | `/latest/meta-data/cam/security-credentials/<role>` | TmpSecretId/TmpSecretKey/Token/ExpiredTime | 无（默认） |
| 华为云 | `/latest/meta-data/securitykey` | AK/SK/securitytoken | 无（默认） |

## 9. 禁用方法对照（加固侧）

| 厂商 | 关闭/加固手段 |
|---|---|
| AWS | HttpEndpoint=disabled；HttpTokens=required（v2）；HttpPutResponseHopLimit=1 |
| Azure | 关闭系统托管身份；NSG 阻断 169.254.169.254 出站 |
| GCP | 元数据服务器设为禁用；Workload Identity；最小 scope |
| 阿里云 | 关闭元数据访问；hops 限制；RAM 角色最小化 |
| 腾讯云 | 关闭元数据访问；hops 限制；CAM 角色最小化 |
| 华为云 | 关闭元数据访问；hops 限制；委托最小化 |

## 10. 检测侧映射（元数据 SSRF 怎么被发现）

- 控制面审计**通常不记录实例内元数据访问**（见 `../detection/cloud-audit-log-systems.md`），
  元数据 SSRF 的检测靠：VPC Flow Logs / 云防火墙对 169.254.169.254（及 100.100.100.200、
  169.254.0.23）回环流量的异常统计、主机 agent 的进程级外联、应用层 SSRF 日志。
- 判定该攻击路径「检测到/未检测到」走 `../detection/cloud-detection-gap-methodology.md`。
