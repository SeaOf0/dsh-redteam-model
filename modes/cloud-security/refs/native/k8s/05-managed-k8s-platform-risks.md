# 多云托管 K8s 特性与集成风险（EKS / AKS / GKE / ACK / TKE）

> 定位：托管 K8s 把控制面交给云厂商，但也引入「云身份 ↔ 集群身份」的映射层。攻击路径的
> 增量在：云凭证如何变成集群权限、节点/负载如何借元数据拿到云权限、各厂商默认差异埋下
> 的坑。本手册逐厂商给出只读探测与检测侧对照。破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

托管 K8s 的核心攻击面是「两个身份平面的桥」：

- 云身份平面：IAM 用户/角色、AK/SK、实例角色、OIDC 身份。
- 集群身份平面：ServiceAccount、用户/组、RBAC。

桥接机制各厂商不同：EKS 用 `aws-auth` ConfigMap + IAM Roles for ServiceAccounts (IRSA)、
AKS 用 Microsoft Entra ID + Workload Identity、GKE 用 Workload Identity + IAM 绑定、ACK 用
RAM（角色）映射、TKE 用 CAM + RBAC。桥一旦配错（过宽映射、默认管理员、元数据可达），
就出现「低权云身份 → cluster-admin」或「低权 Pod → 云账号」的放大链。

## 2. 暴露面探测（只读命令优先）

### 2.1 身份映射只读盘点

```bash
# EKS：读 aws-auth ConfigMap（控制面身份映射）
kubectl get configmap aws-auth -n kube-system -o yaml 2>/dev/null

# 通用：当前集群身份自省
kubectl auth whoami 2>/dev/null || kubectl auth can-i --list -A

# 云身份自省（只读，不改动）
aws sts get-caller-identity            # AWS
az account show                        # Azure
gcloud auth list                       # GCP
aliyun sts GetCallerIdentity           # 阿里云（或 aliyun ram ListUsers 视权限）
tccli sts GetCallerIdentity            # 腾讯云
```

### 2.2 元数据服务可达性探测（只读）

```bash
# 各厂商实例元数据端点（只读 GET，不改动）
curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS
curl -s -m 3 -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure
curl -s -m 3 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token  # GCP
curl -s -m 3 http://100.100.100.200/latest/meta-data/ram/security-credentials/    # 阿里云 ECS
curl -s -m 3 http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/  # 腾讯云 CVM
```

判定口径：返回临时凭证（AccessKey/Token/ClientSecret）即元数据可达且实例绑定了角色；这是
「Pod → 云账号」提权的第一步。

### 2.3 工作负载身份配置只读盘点

```bash
# EKS IRSA：Pod 的 serviceAccount 是否带 eks.amazonaws.com/role-arn
kubectl get sa -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{.metadata.annotations}{"\n"}{end}' 2>/dev/null | grep -i role-arn
# GKE：sa 的 iam.gke.io/gcp-service-account 注解
kubectl get sa -A -o yaml 2>/dev/null | grep -i 'gcp-service-account'
```

## 3. 缺陷与利用路径

### 3.1 EKS `aws-auth` 过宽映射

- 缺陷：`aws-auth` ConfigMap 把 IAM 角色/用户映射到 `system:masters`（cluster-admin），或
  映射的 IAM 角色本身假设门槛过低。
- 验证命令（只读）：读 `aws-auth` 的 `mapRoles/mapUsers`，看 `groups` 是否含
  `system:masters`；`aws sts get-caller-identity` 确认当前身份是否命中映射。
- 影响：命中映射的低权云身份直接变 cluster-admin。
- 检测侧：K8s audit 记录 `configmaps get`（读 aws-auth）+ 该身份后续的高权操作；CloudTrail
  记录 `GetCallerIdentity`/`AssumeRole`；两者时间关联即提权链。

### 3.2 IRSA / Workload Identity 注解信任链过宽

- 缺陷：SA 的 `eks.amazonaws.com/role-arn`（或 GKE `iam.gke.io/gcp-service-account`、
  AKS Workload Identity）指向的云角色信任策略过宽（`Principal` 写通配、`Condition` 缺失），
  导致任意同集群 Pod 都能假冒该 SA 拿到云角色。
- 验证命令（只读）：读 SA 注解得到 role-arn → 读云角色信任策略
  `aws iam get-role --role-name <name>` / `gcloud iam service-accounts get-iam-policy` 看
  `Condition` 是否锁定 OIDC 主体与 namespace。
- 影响：低权 Pod 假冒高权 SA，跨到云账号执行高危动作。
- 检测侧：CloudTrail `AssumeRoleWithWebIdentity`（EKS）、Cloud Audit Logs 的
  `GenerateAccessToken`（GKE）记录假冒行为；归属 OIDC subject 与预期 SA 不符即告警。

### 3.3 元数据服务未限制（IMDSv1 / 无 Hop Limit）

- 缺陷：节点/Pod 能访问元数据服务且实例角色权限大；EKS 未强制 IMDSv2（`HttpTokens`
  仍接受 v1）、AKS/GKE 未限制，SSRF/容器内请求即可拉实例角色凭证。
- 验证命令（只读）：`curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  返回角色名即可；再 `GetCallerIdentity` 确认权限面。
- 影响：实例角色凭证 = 云账号权限（常含 S3/存储/密钥访问）。
- 检测侧：CloudTrail 记录元数据派生的 `GetCallerIdentity`/资源操作；VPC Flow Logs 记录
  169.254.169.254 流量；K8s 侧无 audit 事件（纯云面）。

### 3.4 AKS 默认本地账号与 Entra 集成缺陷

- 缺陷：AKS 默认存在 `clusterAdmin`/`clusterUser` 本地 kubeconfig 账号（`--local-accounts
  ` 未关闭），且 Entra ID 集成把过宽的组映射为 cluster-admin。
- 验证命令（只读）：`kubectl auth whoami` 看主体；`az aks show -n <c> -g <g>` 看
  `disableLocalAccounts` 是否 false；Entra 组映射只读盘点。
- 影响：本地管理员账号凭据泄露即控制面；过宽组映射放大众账号。
- 检测侧：Azure 活动日志记录 AKS 控制面操作与 `ListClusterAdminCredentials` 调用；
  K8s audit 记录该主体后续操作。

### 3.5 多厂商共性：节点组 IAM/RAM/CAM 角色过宽

- 缺陷：节点角色（EKS node group role、ACK RAM 角色、TKE CAM 角色）被赋予过宽云权限，而
  节点上所有 Pod 默认共享该角色的元数据可达性。
- 验证命令（只读）：`GetCallerIdentity` 确认节点角色；`aws iam list-attached-role-policies`
  / `aliyun ram ListPoliciesForRole` 只读列出附加策略。
- 影响：任一 Pod 逃逸或 SSRF 即继承节点级云权限。
- 检测侧：CloudTrail/RAM 审计记录角色使用与策略查询；节点角色权限清单是 `cloud-assets.md`
  的登记项。

## 4. 提权与持久化

- 提权链模板：
  - Pod/SSRF → 元数据实例角色 → 云账号（横向 S3/密钥/其他集群）。
  - 低权云身份 → aws-auth/Entra/RAM 映射 → cluster-admin → 集群资源 + Secret。
  - 低权 SA → IRSA/OIDC 假冒 → 云角色 → 云账号。
- 持久化（授权内人工确认后执行）：在云侧创建高权角色/访问密钥、在集群侧写 aws-auth 映射
  或建隐蔽 SA，逐项登记 `environment-restore.md`；凭证发现后提示轮换。

## 5. 检测与加固要点

### 5.1 K8s audit 事件名对照

| 攻击行为 | audit 事件 |
|---|---|
| 读 aws-auth | `configmaps get` + resourceNames=aws-auth |
| 篡改 aws-auth | `configmaps update/patch` + resourceNames=aws-auth |
| 控制面高权操作 | `clusterrolebindings create` / `secrets list` + 云映射主体 |

### 5.2 云审计事件名对照

| 厂商 | 关键事件 |
|---|---|
| AWS | `GetCallerIdentity`、`AssumeRole`、`AssumeRoleWithWebIdentity`、`ListBuckets` |
| Azure | `ListClusterAdminCredentials`、`Microsoft.ContainerService` 写操作 |
| GCP | `GenerateAccessToken`、`SetIamPolicy`、`CreateCluster` |
| 阿里云 | RAM `GetCallerIdentity`、`AssumeRole`、STS 临时凭证签发 |
| 腾讯云 | CAM `GetCallerIdentity`、`AssumeRole` |

### 5.3 加固要点

- 强制 IMDSv2（EKS 设 `HttpTokens=required`、Hop Limit=1）；AKS/GKE 用网络策略/防火墙限
  元数据访问。
- aws-auth/Entra/RAM 映射最小化，禁 `system:masters` 泛映射；审计映射变更。
- IRSA/OIDC 信任策略锁定 `sub`/`namespace`/`audience`，禁通配 Principal。
- 关闭 AKS 本地账号（`disableLocalAccounts=true`）；节点角色最小权限，按节点组隔离。
