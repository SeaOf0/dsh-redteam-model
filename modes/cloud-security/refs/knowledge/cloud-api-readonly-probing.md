# 云 API 只读探测纪律与速率默认值（附录 B）

> 定位：知识索引附录 B，云 API 验证纪律的速查底座。主观念「只读 API 优先、破坏性操作先
> 询问、速率与账单意识」的落地细则。本表给各厂商只读 API 示例、速率/限流与账单意识要点、
> 最小影响验证原则；探测只做 Describe/Get/List 类只读，不做写/删/改。

## 1. 只读 API 优先原则

验证一条发现（配置缺陷/暴露面/凭证权限）时，先确认它是真实的，用**只读**调用：
`Describe*` / `Get*` / `List*`（AWS/阿里云/腾讯云/华为云）、`Get-Az*` / `az * show|list`
（Azure）、`gcloud ... describe|list`（GCP）。写/删/改一律先询问用户并快照基线。

**只读 API 判定规则**：动作名以 `Describe`/`Get`/`List`/`Head` 开头，或 CLI 子命令为
`show`/`list`/`describe`，且不影响目标状态。

## 2. 各厂商只读 API 示例

| 厂商 | 只读动作示例 | 用途 | 对应变更动作（避免） |
|---|---|---|---|
| AWS | `sts:GetCallerIdentity`、`iam:GetUser`/`ListUsers`/`GetRole`、`s3:GetBucketPolicy`/`GetBucketAcl`/`ListObjectsV2`、`ec2:DescribeInstances`/`DescribeSecurityGroups`、`cloudtrail:DescribeTrails` | 身份/权限/桶/实例/审计盘点 | Create*、Put*、Delete*、Update* |
| Azure | `az vm list`、`az storage blob list`、`az role assignment list`、`az network nsg show`、`Get-AzVM`/`Get-AzStorageAccount` | 资源/授权/网络盘点 | `az ... create/delete/update` |
| GCP | `gcloud projects list`、`gcloud compute instances describe`、`gcloud storage ls`、`gcloud iam service-accounts list`、`gcloud projects get-iam-policy` | 项目/实例/桶/授权盘点 | `gcloud ... create/delete/set-iam-policy` |
| 阿里云 | `aliyun ecs DescribeInstances`、`aliyun ram ListUsers`/`GetUser`、`aliyun oss ls`/`GetBucketPolicy`/`GetBucketAcl`、`aliyun sts GetCallerIdentity` | 资源/授权/桶盘点 | Create*/Put*/Delete* |
| 腾讯云 | `tccli cvm DescribeInstances`、`tccli cam GetUser`/`ListUsers`、`tccli cos ls`（coscmd） | 资源/授权/桶盘点 | Create*/Put*/Delete* |
| 华为云 | `hcloud ECS ListServersDetails`、`hcloud IAM ShowUser`、`obsutil ls` | 资源/授权/桶盘点 | Create*/Put*/Delete* |

## 3. 速率与限流默认值（探测纪律）

云 API 有配额与限流，**探测必须限速**，避免触发风控/拖慢租户/产生账单。默认值以各厂商
控制台为准，下表为常见公开默认（保守口径）：

| 厂商 | 常见默认限流量级 | 探测建议速率 |
|---|---|---|
| AWS | 各 API 独立限速（如 EC2 Describe 数十次/秒，IAM 更严，STS 有全局桶） | 每 API ≤ 1 次/秒，批 API 用分页 50–100/页，退避重试 |
| Azure | Resource Manager 读 12000/小时/订阅级别（按 API 不同） | 读 ≤ 数 QPS，分页遍历，退避重试 |
| GCP | 各 API 配额（如 Storage 列表 数千/分钟） | 读 ≤ 数 QPS，退避重试 |
| 阿里云 | 各 API 独立 QPS（如 ECS Describe 数十 QPS，RAM 更严） | 读 ≤ 1 QPS，退避重试 |
| 腾讯云 | 各 API 独立限频（CAM/STS 更严） | 读 ≤ 1 QPS，退避重试 |
| 华为云 | 各 API 独立限流 | 读 ≤ 1 QPS，退避重试 |

**通用纪律**：

- 单目标动作串行 + 间隔（≥ 1s），批量枚举用分页/并发上限（≤ 5），失败即指数退避（1s/2s/4s）。
- 遇到限流错误（Throttling/RequestLimitExceeded/429/RateLimitExceeded）立即退避，不硬撞。
- 枚举类操作先问「这条枚举是否必要」，能点查就不全量拉。
- 只读探测也要登记：探测了什么 API、次数、结果，写进证据索引（evidence-index.md）。

## 4. 账单意识

只读 API 大多免费或极廉价，但以下会**计费/产生配额消耗**，探测前确认：

| 成本点 | 说明 | 规避 |
|---|---|---|
| 数据面读取 | 对象存储对象级读取（GetObject 类）、数据流出（出网流量）计费 | 点查替代全量；不拉取大对象；注意流量方向 |
| 数据事件日志 | 开启数据面审计（Data Events/数据事件）会产生日志量费用 | 评估前与用户确认是否临时开启 |
| 洞察/智能分析 | Insights/洞察事件、智能体检类服务计费 | 默认不开 |
| 大数据/日志投递 | 投递到 BigQuery/SLS/CLS/LTS 产生存储与计算费用 | 按需最小投递 |
| 跨区/公网流量 | 跨区域读取、公网出口流量 | 尽量区域内、走内网端点 |

## 5. 最小影响验证原则

- **点查优于枚举**：验证「桶是否公开」用 `GetBucketPolicy`/`GetBucketAcl` 单点，而非拉全量对象。
- **读不写**：验证权限用「尝试只读调用是否成功」（`Get*` 返回 200/AccessDenied），不创建探测资源。
- **whoami 级影响证明**：需要证明影响时，用 `GetCallerIdentity`/读单条元数据这类最小影响
  动作证明「拿到了什么」，等价于主机侧的 whoami。
- **凭证不滥用**：发现的 AK/SK/token 只用于验证授权范围内的最小只读动作，登记出处与权限
  范围后提示轮换，不外传、不打印超出影响证明所需内容。
- **基线快照**：任何需要验证「变更类」结论的场景，先只读快照当前配置（策略/ACL/安全组），
  登记进任务工作区基线表，再决定是否在用户确认下做受控变更验证。

## 6. 各厂商只读动作扩展清单（按侦察面）

**身份与权限**

| 厂商 | 只读动作 |
|---|---|
| AWS | `iam:ListUsers` `iam:ListRoles` `iam:GetRole` `iam:ListAttachedRolePolicies` `iam:GetPolicy` `sts:GetCallerIdentity` `iam:ListAccessKeys` |
| Azure | `az ad user list` `az ad sp list` `az role assignment list` `az role definition list` `az ad signed-in-user show` |
| GCP | `gcloud projects get-iam-policy` `gcloud iam service-accounts list` `gcloud iam roles list` |
| 阿里云 | `aliyun ram ListUsers` `ListRoles` `GetRole` `ListPoliciesForRole` `aliyun sts GetCallerIdentity` |
| 腾讯云 | `tccli cam ListUsers` `ListRoles` `GetRole` `tccli sts GetCallerIdentity` |
| 华为云 | `hcloud IAM ListUsers` `ShowUser` `hcloud STS ...` |

**对象存储**

| 厂商 | 只读动作 |
|---|---|
| AWS | `s3:ListBuckets` `GetBucketPolicy` `GetBucketAcl` `ListObjectsV2` `GetBucketVersioning` `GetBucketEncryption` |
| Azure | `az storage account list` `az storage blob list` `az storage container list` `az storage account show` |
| GCP | `gcloud storage ls` `gcloud storage buckets describe` `gsutil iam get` |
| 阿里云 | `aliyun oss ls` `GetBucketPolicy` `GetBucketAcl` `GetBucketInfo` |
| 腾讯云 | `tccli cos`（coscmd）`ls` / 桶策略只读查询 |
| 华为云 | `obsutil ls` / 桶策略只读查询 |

**网络与计算**

| 厂商 | 只读动作 |
|---|---|
| AWS | `ec2:DescribeInstances` `DescribeSecurityGroups` `DescribeVpcs` `DescribeSubnets` |
| Azure | `az network nsg list` `az vm list` `az network nsg show` |
| GCP | `gcloud compute instances list` `gcloud compute firewall-rules list` |
| 阿里云 | `aliyun ecs DescribeInstances` `DescribeSecurityGroupAttribute` |
| 腾讯云 | `tccli vpc DescribeSecurityGroups` `tccli cvm DescribeInstances` |
| 华为云 | `hcloud ECS ListServersDetails` `hcloud VPC ListSecurityGroups` |

## 7. 探测前检查清单（每轮探测前过一遍）

- [ ] 目标与范围在授权清单内（不碰未授权云资产）。
- [ ] 用的是只读凭证/只读身份，动作名 Describe/Get/List 开头。
- [ ] 已确认限速与退避参数（≤ 1 QPS、失败指数退避）。
- [ ] 已确认无计费点（对象读取/流量方向/日志投递）。
- [ ] 变更类结论先只读快照基线并登记，再决定是否受控验证。
- [ ] 探测动作与结果登记 evidence-index.md（含 API、次数、结果）。

## 8. 退避重试与限流处理

- 识别限流信号：`Throttling`/`ThrottlingException`/`RequestLimitExceeded`/`RateLimitExceeded`/
  `429 Too Many Requests`/`429 TooManyRequests`。
- 处置：立即停止该 API 后续调用 → 按 `1s → 2s → 4s → 8s` 指数退避重试 → 仍失败则换页/换
  时间窗/换查询条件，不硬撞。
- 记录：把限流发生时间、API、重试次数记入 evidence-index，供报告「局限性声明」引用。

## 9. 与本库其它手册的关系

- 元数据端点探测的路径表 → `metadata-service-endpoints.md`（附录 A）。
- 权限策略语法/过宽权限判定 → `iam-policy-language-cheatsheet.md`。
- 只读探测产出的证据登记 → 任务工作区 evidence-index.md（主观念证据三档）。
- 检测侧：只读侦察在审计日志里的指纹（GetCallerIdentity/枚举/AccessDenied 风暴）→
  `../detection/cloud-detection-rule-design.md` 第 1、2 节。
