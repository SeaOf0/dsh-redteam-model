# Cloud IAM 与权限攻防

Cloud IAM 是 GCP 的统一权限模型，用「成员（member）→ 角色（role）→ 资源（resource）」的三元组表达授权。攻击面围绕三类对象展开：成员（用户、组、服务账号、域）、角色（基础角色/预定义角色/自定义角色，及其内置权限集）、以及服务账号这个「机器身份」的特殊性——它能被密钥、元数据 token、Workload Identity 多种方式冒充。理解权限提升的关键在于：某些角色虽看似无害，却内含可组合的「危险权限」，能通过服务账号间接放大到更高权限。

## 一、攻击面

Cloud IAM 的攻击面可归纳为：

1. **基础角色（Basic roles）过宽**：`roles/owner`、`roles/editor`、`roles/viewer` 为项目级巨量权限，尤其 `owner` 含全部管理权限、`editor` 含写权限，常被滥用授予。
2. **服务账号**：服务账号是 GCP 内最常见的「机器身份」，其密钥泄露、`actAs` 冒充、Workload Identity 映射错误，构成提权主干。
3. **服务账号密钥**：长期有效的用户管理密钥（`gcloud iam service-accounts keys`）一旦泄露，可离线长期冒充，且默认无轮换。
4. **角色内嵌的危险权限**：`iam.serviceAccounts.actAs`、`iam.serviceAccounts.getAccessToken`、`iam.serviceAccounts.signJwt`、`iam.serviceAccounts.signBlob`、`iam.serviceAccounts.createKey` 等权限单独看似无害，组合即可冒充高权限服务账号。
5. **Workload Identity**：Kubernetes 服务账号到 GCP 服务账号的映射（`iam.workloadIdentityUser`）配置错误，可让集群内任意 Pod 冒充高权限 GCP 身份。
6. **自定义角色**：自定义角色若把危险权限打包授予低权限主体，会形成隐蔽提权路径。
7. **组织/文件夹级策略继承**：组织级、文件夹级 IAM 策略的过宽授予会下溢到所有子项目。

## 二、信息收集 / 暴露面探测

以下命令为只读探测，用于枚举身份、角色与权限关系。

```bash
# 查看当前登录身份（谁、以什么方式认证）
gcloud auth list

# 查看当前激活配置与项目
gcloud config list

# 查看项目 IAM 策略（成员 → 角色映射）
gcloud projects get-iam-policy <PROJECT> --format=json

# 查看组织级 IAM 策略（如可访问）
gcloud organizations get-iam-policy <ORG_ID> --format=json

# 查看文件夹级 IAM 策略（如可访问）
gcloud resource-manager folders get-iam-policy <FOLDER_ID> --format=json

# 列出项目下全部服务账号及其角色
gcloud iam service-accounts list

# 查看某个服务账号详情（含唯一 ID、描述、是否被禁用）
gcloud iam service-accounts describe <SA_EMAIL>

# 列出某服务账号的用户管理密钥（含创建时间，可判断密钥年龄）
gcloud iam service-accounts keys list --iam-account <SA_EMAIL>

# 查看某个预定义角色的权限集（用于判断是否含危险权限）
gcloud iam roles describe roles/iam.serviceAccountTokenCreator

# 查看项目自定义角色列表
gcloud iam roles list --project <PROJECT>
```

探测要点：把「成员 → 角色」展开后，逐一判断角色内含的权限；优先标记持有 `iam.serviceAccounts.*`、`iam.roles.*`、`resourcemanager.*.setIamPolicy` 的主体；服务账号密钥列表中的长期密钥是重点目标。

## 三、常见配置缺陷与利用路径

### 3.1 基础角色（owner/editor）过度授予

**缺陷描述**：`roles/owner` 与 `roles/editor` 是历史遗留的基础角色，权限覆盖几乎所有资源。将这类角色授予服务账号、外包账号或低信任成员，等于把项目控制权拱手交出。

**验证命令（只读优先）**：

```bash
# 只读枚举持有 owner/editor/viewer 的成员
gcloud projects get-iam-policy <PROJECT> --format=json \
  | python3 -c "import sys,json; [print(b['role'], m) for b in json.load(sys.stdin)['bindings'] for m in b['members'] if b['role'] in ('roles/owner','roles/editor','roles/viewer')]"
```

**影响**：`owner` 可修改项目 IAM、删除资源、管理计费；`editor` 可读写绝大多数资源。过度授予导致攻击面极大，任一成员失陷即项目失陷。

**检测侧建议**：授予这些角色的动作对应 Cloud Audit Logs 事件 `resourcemanager.projects.setIamPolicy`（Admin Activity）。SCC 会给出「基础角色滥用」「权限过宽」发现项；建议用 IAM Recommender 的过度权限建议，将基础角色迁移为最小权限预定义角色。

### 3.2 服务账号密钥长期存在且未轮换

**缺陷描述**：服务账号支持用户管理密钥（默认十年有效期），团队常在本地生成后长期不轮换、不吊销，且密钥文件常被打包进代码仓库、镜像或配置文件，成为泄露重灾区。

**验证命令（只读优先）**：

```bash
# 只读列出服务账号的用户管理密钥（validAfterTime 可判断密钥年龄）
gcloud iam service-accounts keys list --iam-account <SA_EMAIL> --format=json
```

**影响**：泄露的服务账号密钥可离线冒充该服务账号调用 API，且不受实例生命周期、scope 限制；密钥即长期后门。

**检测侧建议**：创建密钥对应 `iam.serviceAccounts.createKey` 事件（Admin Activity），是「密钥外带」的前置信号；删除密钥对应 `iam.serviceAccounts.deleteKey`。SCC 的「陈旧密钥」「密钥外泄」发现项可命中。建议禁用用户管理密钥（组织策略 `iam.disableServiceAccountKeyCreation`），改用 Workload Identity 或短期凭据。

### 3.3 服务账号冒充（actAs / TokenCreator）提权

**缺陷描述**：`roles/iam.serviceAccountUser`（含 `iam.serviceAccounts.actAs`）允许以该服务账号身份部署/附加资源；`roles/iam.serviceAccountTokenCreator`（含 `iam.serviceAccounts.getAccessToken`、`signJwt`、`signBlob`）允许直接生成该服务账号的访问令牌或签名凭据。攻击者若对某个高权限服务账号持有这两个角色，即可冒充其获得全部权限。

**验证命令（只读优先）**：

```bash
# 只读查看谁能 actAs / 生成某服务账号的 token（即该项目上含 iam.serviceAccounts.actAs 权限的主体）
gcloud projects get-iam-policy <PROJECT> --format=json

# 只读查看服务账号自身的 IAM 策略（谁能冒充它）
gcloud iam service-accounts get-iam-policy <SA_EMAIL> --format=json
```

**影响**：这是最经典的「权限放大」链路：低权限用户 → 冒充高权限服务账号 → 项目接管。`signJwt`/`signBlob` 还可伪造以该服务账号为签名的 JWT，用于调用需要签名鉴权的下游服务。

**检测侧建议**：冒充动作在 Cloud Audit Logs 中体现为服务账号首次被非预期主体调用 API，以及 `iam.serviceAccounts.actAs` 关联事件；`getAccessToken`/`signBlob`/`signJwt` 调用会记录为 `iam.serviceAccounts.getAccessToken` 等（Data Access 域，需开启记录）。应严格最小化 `serviceAccountUser`、`serviceAccountTokenCreator` 的授予范围。

### 3.4 serviceAccountKeyAdmin / serviceAccountAdmin 自提权

**缺陷描述**：`roles/iam.serviceAccountKeyAdmin` 允许为服务账号创建/删除密钥；`roles/iam.serviceAccountAdmin` 更进一步允许创建服务账号并对其完整管理。攻击者持有这些角色时，可为任意高权限服务账号生成新密钥并自行使用，实现提权。

**验证命令（只读优先）**：

```bash
# 只读查看持有 serviceAccountAdmin / serviceAccountKeyAdmin 的成员
gcloud projects get-iam-policy <PROJECT> --format=json \
  | python3 -c "import sys,json; [print(b['role'], m) for b in json.load(sys.stdin)['bindings'] for m in b['members'] if 'serviceAccount' in b['role']]"
```

**影响**：持有者可为 `owner` 服务账号生成密钥，直接获取项目最高权限；删除密钥（破坏性）可造成业务中断，须授权内人工确认后执行。

**检测侧建议**：`iam.serviceAccounts.createKey`、`iam.serviceAccounts.deleteKey` 事件是核心告警点；为高权限服务账号生成密钥的动作应触发实时告警。建议通过组织策略禁用服务账号密钥创建，切断此提权路径。

### 3.5 自定义角色打包危险权限

**缺陷描述**：自定义角色允许把任意权限组合命名后授予。若团队把 `resourcemanager.projects.setIamPolicy`、`iam.serviceAccounts.actAs` 等危险权限打进某个看似业务性的自定义角色，会形成隐蔽的提权入口，且命名不反映真实能力。

**验证命令（只读优先）**：

```bash
# 只读列出项目自定义角色及其权限
gcloud iam roles list --project <PROJECT> --format=json

# 只读展开某个自定义角色的权限集
gcloud iam roles describe <CUSTOM_ROLE> --project <PROJECT> --format=json
```

**影响**：攻击者一旦获得该自定义角色，即可调用其中打包的危险权限提权，且这类角色在常规资产盘点中易被忽略。

**检测侧建议**：创建/更新自定义角色对应 `iam.roles.create`、`iam.roles.update` 事件；应定期审计自定义角色的权限集，禁止在其中混入 `setIamPolicy`、`actAs`、`createKey` 等敏感权限。

### 3.6 Workload Identity 映射错误

**缺陷描述**：Workload Identity 允许 GKE 内的 Kubernetes 服务账号（KSA）通过 `iam.workloadIdentityUser` 绑定冒充 GCP 服务账号（GSA）。若 KSA 与 GSA 的映射过宽（如通配命名空间、绑定到高权限 GSA），集群内任意 Pod 都可获得高权限 GCP 身份。

**验证命令（只读优先）**：

```bash
# 只读查看某 GCP 服务账号的 IAM 策略（含 workloadIdentityUser 绑定，principal 形如 serviceAccount:PROJECT.svc.id.goog[ns/ksa]）
gcloud iam service-accounts get-iam-policy <GSA_EMAIL> --format=json
```

**影响**：映射错误使「集群内任意 Pod → 高权限 GCP 服务账号」成为直达提权路径，是云原生场景下的高频缺陷。

**检测侧建议**：绑定变更对应 `iam.serviceAccounts.setIamPolicy` 事件；应以最小 KSA 粒度绑定、避免通配，并审计 `iam.workloadIdentityUser` 绑定的 GSA 权限是否最小化。

## 四、权限提升与持久化路径

**权限提升主线（经典链）**：

1. **getIamPolicy 枚举 → 定位危险角色持有者**：先通过只读枚举，找出持有 `serviceAccountTokenCreator`、`serviceAccountUser`、`serviceAccountKeyAdmin`、`resourcemanager.*.setIamPolicy` 的主体与目标高权限服务账号。
2. **TokenCreator 冒充**：对目标服务账号调用 `generateAccessToken`/`signJwt`，直接获得其访问令牌（详见 `./metadata-ssrf.md` 的 token 使用范式）。
3. **KeyAdmin 造密钥**：为高权限服务账号创建新密钥并用其认证（授权内人工确认后执行）。
4. **setIamPolicy 自授**：持有 `resourcemanager.projects.setIamPolicy` 者直接给自己绑定 `roles/owner`，一步到位。
5. **Workload Identity 横向**：集群内 Pod 借助错误映射冒充高权限 GSA。

**持久化路径**：

1. **新服务账号 + 密钥**：创建新服务账号并生成长期密钥持有（授权内人工确认后执行），独立于原有身份。
2. **IAM 绑定自留**：在项目/组织 IAM 上为自己绑定持久角色，作为长期入口。
3. **服务账号密钥后门**：为关键服务账号额外生成一把密钥长期保存。
4. **自定义角色后门**：创建含敏感权限的自定义角色并授予自己，隐蔽且不易被基础角色审计发现。

## 五、防御与检测要点

审计日志事件名清单：

| 事件名 | 含义 | 关注点 |
| --- | --- | --- |
| `resourcemanager.projects.setIamPolicy` | 修改项目 IAM | owner/editor 授予、自授权 |
| `iam.serviceAccounts.createKey` | 创建服务账号密钥 | 密钥外带前置 |
| `iam.serviceAccounts.deleteKey` | 删除服务账号密钥 | 破坏/清理痕迹 |
| `iam.serviceAccounts.create` | 创建服务账号 | 新建持久身份 |
| `iam.serviceAccounts.setIamPolicy` | 修改服务账号 IAM | actAs / workloadIdentityUser 绑定 |
| `iam.serviceAccounts.actAs` | 以服务账号身份动作 | 冒充 |
| `iam.serviceAccounts.getAccessToken` | 生成访问令牌 | 冒充（Data Access，需开启记录） |
| `iam.serviceAccounts.signJwt` / `signBlob` | 签名 JWT/Blob | 伪造签名凭据 |
| `iam.serviceAccounts.signBlob` | 签名 Blob | 凭据伪造 |
| `iam.roles.create` / `iam.roles.update` | 创建/更新自定义角色 | 打包危险权限 |
| `iam.serviceAccounts.disable` / `enable` | 禁用/启用服务账号 | 破坏或恢复 |

防御建议：

- 禁用基础角色授予，迁移到最小权限预定义角色；启用 IAM Recommender 权限精简建议。
- 组织策略禁用服务账号用户管理密钥（`iam.disableServiceAccountKeyCreation`），强制 Workload Identity 或短期凭据。
- 服务账号密钥强制轮换与审计，禁止把密钥写入代码仓库/镜像。
- 严格最小化 `serviceAccountTokenCreator`、`serviceAccountUser`、`serviceAccountKeyAdmin` 的授予，并对高权限服务账号单独设 IAM 策略。
- Workload Identity 以最小 KSA 粒度绑定，禁用通配命名空间映射。
- 对 `setIamPolicy`、`createKey`、`getAccessToken` 建立实时告警，并开启 Data Access logs 捕获 token 生成行为。
