# Cloud Storage 对象存储攻防

Cloud Storage 是 GCP 的对象存储服务，以 bucket（桶）组织对象。其权限模型历经两代：传统「对象级 ACL + bucket ACL」与较新的「统一 bucket 级权限（uniform bucket-level access）」。攻击面主要集中在「谁能让桶被公开读取/写入」「谁能枚举桶名与对象」「被删除的桶名能否被接管复用」以及「签名 URL 的越权与泄露」。

## 一、攻击面

Cloud Storage 的攻击面可归纳为：

1. **桶公开访问**：`allUsers` / `allAuthenticatedUsers` 被授予 `storage.objectViewer`、`storage.objectCreator`、`storage.objectAdmin` 等角色，导致匿名/任意登录用户可读、写甚至删除对象。
2. **对象级 ACL 遗留**：未启用统一权限的桶，单个对象可能被设为公开（`publicRead`），而桶本身仍显示为私有，造成「桶私有但对象公开」的盲区。
3. **桶名可枚举与暴力枚举**：桶名全局唯一且解析为可预测的存储域名，配合对象列举权限可探测存量数据。
4. **桶接管（bucket takeover）**：桶被删除后，其全局唯一名称进入可复用状态；攻击者若在目标组织于其它服务（如 CDN、域名解析）仍引用该桶名的情况下抢先注册同名桶，即可接管流量或投毒内容。
5. **签名 URL / 签名策略**：`storage.objects.get` 的 V2/V4 签名 URL、`POST policy` 若生成参数过宽（长有效期、通配路径）或密钥泄露，可被越权使用。
6. **服务账号密钥托管**：HMAC 密钥、服务账号密钥用于对象读写时，密钥泄露即对象泄露。
7. **生命周期与版本残留**：旧版本对象、被软删除的对象仍可能持有历史敏感数据。

## 二、信息收集 / 暴露面探测

以下命令为只读探测，用于枚举桶与对象可访问性。

```bash
# 列出当前项目下可访问的桶
gcloud storage buckets list

# 列出全部项目可见的桶（需相应权限）
gcloud storage ls

# 查看某个桶的 IAM 策略（判断是否含 allUsers / allAuthenticatedUsers）
gcloud storage buckets get-iam-policy gs://<BUCKET> --format=json

# 查看桶的对象列表（若可读，说明存在读取权限或公开）
gcloud storage ls gs://<BUCKET>/

# 查看单个对象的公开状态与元数据（只读）
gcloud storage objects describe gs://<BUCKET>/<OBJECT> --format=json

# 查看桶是否启用了统一权限（uniformBucketLevelAccess 字段）
gcloud storage buckets describe gs://<BUCKET> --format=json

# 查看桶的公开访问预防（publicAccessPrevention 字段，enforced 表示强制阻止公开）
gcloud storage buckets describe gs://<BUCKET> \
  --format="value(iamConfiguration.publicAccessPrevention,iamConfiguration.uniformBucketLevelAccess.enabled)"
```

**匿名探测（无需 gcloud 凭据，只读）**：对可疑桶名，可对存储公网端点发起只读 GET 请求（端点主机名为 `storage.googleapis.com`，桶名拼接在路径中，形如 `<BUCKET>/`），依据 HTTP 状态码判断访问性：

| 状态码 | 含义 |
| --- | --- |
| 200（返回对象/清单） | 桶公开可列举，或对象公开可读 |
| 403 | 桶存在但无匿名权限 |
| 404 | 桶不存在（名称可能可复用） |

> 注：上述对 `storage.googleapis.com` 的只读匿名探测须在授权范围内执行；写入类探测一律禁止。

探测要点：桶是否可匿名列举（返回对象清单）、是否存在 `allUsers` 授权、是否启用统一权限与公开访问预防、对象 ACL 是否残留 `publicRead`。

## 三、常见配置缺陷与利用路径

### 3.1 桶被授予 allUsers 读取/写入

**缺陷描述**：桶 IAM 中 `allUsers`（任何人，含匿名）或 `allAuthenticatedUsers`（任意 GCP 登录用户）持有 `storage.objectViewer`、`storage.objectAdmin` 等角色，导致数据对外暴露甚至可被篡改。常见成因是「一键公开」、误点「公网可读」、或测试残留。

**验证命令（只读优先）**：

```bash
# 只读查看桶 IAM，确认是否含 allUsers / allAuthenticatedUsers
gcloud storage buckets get-iam-policy gs://<BUCKET> --format=json

# 只读匿名验证读取能力：对存储公网端点（主机名 storage.googleapis.com，路径 <BUCKET>/<OBJECT>）发起 GET，
# 返回 200 表示匿名可读
```

**影响**：敏感对象（密钥、备份、客户数据）可被匿名下载；若授予写入/删除角色，攻击者可投毒内容、篡改静态站点、清空数据（破坏性步骤须授权内人工确认后执行）。

**检测侧建议**：授予 `allUsers`/`allAuthenticatedUsers` 权限的动作对应 Cloud Audit Logs 事件 `storage.buckets.setIamPolicy`（Admin Activity）；匿名读取命中对象则出现在 Data Access 日志（`storage.objects.get`，需开启 Data Access logs 才能记录）。SCC 对「公开 bucket」提供高严重度发现项，可近乎实时告警。

### 3.2 统一权限未启用导致对象级 ACL 公开

**缺陷描述**：未启用 uniform bucket-level access 的桶，每个对象可单独设置 ACL。攻击者常绕过「桶看起来私有」的假象，逐对象探测 `publicRead` 残留；而防守方在桶 IAM 面板看不到对象级公开。

**验证命令（只读优先）**：

```bash
# 只读查看桶是否启用统一权限
gcloud storage buckets describe gs://<BUCKET> \
  --format="value(iamConfiguration.uniformBucketLevelAccess.enabled)"

# 只读查看单个对象的 ACL（在未启用统一权限时有效）
gcloud storage objects get-iam-policy gs://<BUCKET>/<OBJECT> --format=json
```

**影响**：对象级公开是典型的「隐藏公开面」，数据泄露后难以在桶级策略中定位根因。

**检测侧建议**：对象 ACL 变更事件为 `storage.objects.setIamPolicy`、`storage.objects.update`（Data Access 域，需开启记录）；SCC 的「公开对象」发现项可覆盖桶级面板的盲区。建议统一启用 uniform bucket-level access 并设置 `publicAccessPrevention=enforced` 从根上阻断对象级公开。

### 3.3 桶名枚举与猜测

**缺陷描述**：桶名全局唯一且具备可预测命名规律（公司名、项目名、`-backup`、`-prod` 后缀）。攻击者通过字典枚举桶名并观察响应差异，可在不接触内部系统的前提下发现存量桶。

**验证命令（只读优先）**：

```bash
# 只读探测桶是否存在：对存储公网端点（主机名 storage.googleapis.com，路径 <GUESSED_BUCKET>/）发起 GET，
# 404=不存在，403=存在但无权限，200/返回清单=公开
```

**影响**：桶名枚举本身低危，但能辅助定位后续攻击目标，结合公开缺陷即可批量收割泄露数据。

**检测侧建议**：匿名桶探测流量会以 `storage.objects.list`/`storage.objects.get` 的 403 形式出现在 Data Access 日志（需开启）；对桶名做随机化、避免可预测命名，并限制公开访问预防可显著降低枚举价值。

### 3.4 桶接管（bucket takeover）

**缺陷描述**：桶被删除后，其全局唯一名称重新可用。若组织的其它资产（DNS CNAME、CDN、应用硬编码）仍指向该桶名，攻击者抢先创建同名桶并写入恶意内容，即可接管对应域名/流量，实现内容投毒甚至子域接管。

**验证命令（只读优先）**：

```bash
# 只读确认桶是否已不存在：对存储公网端点（主机名 storage.googleapis.com，路径 <BUCKET>/）发起 GET，
# 404 表示桶已删除、名称可能可复用
```

**影响**：接管成功后攻击者可对指向该桶名的域名投毒页面、注入恶意脚本，造成钓鱼与供应链污染。创建同名桶属写入/占用操作，须授权内人工确认后执行。

**检测侧建议**：删除桶的事件 `storage.buckets.delete`（Admin Activity）是首要关注点；防守方应在删除桶前审计 DNS/应用对该桶名的引用，并在删除后保留「占位桶」或及时回收引用，避免名称进入可复用池。

### 3.5 签名 URL 越权与泄露

**缺陷描述**：V2/V4 签名 URL 与 POST policy 授予的权限完全由生成时参数决定。若有效期过长、对象路径使用通配、或签名密钥（服务账号密钥/HMAC 密钥）泄露，攻击者可放大为任意对象读写。

**验证命令（只读优先）**：

```bash
# 只读验证已知签名 URL 是否仍有效（返回 200 表示有效）
curl -s -o /dev/null -w "%{http_code}\n" "<SIGNED_URL>"

# 只读查看与对象访问相关的服务账号密钥是否存在（详见 ./iam.md）
gcloud iam service-accounts keys list --iam-account <SA_EMAIL>
```

**影响**：泄露的签名 URL 可在有效期内被无限重放；若签名密钥本身泄露，则攻击者可自行签发任意 URL，等价于获得该密钥对应权限。

**检测侧建议**：签名 URL 的使用会在 Data Access 日志中记录为 `storage.objects.get`，但难以区分合法签名与泄露重放；应通过 HMAC 密钥/服务账号密钥的创建事件 `storage.hmacKeys.create`、`iam.serviceAccounts.createKey` 进行源头审计，并限制签名有效期与路径范围。

## 四、权限提升与持久化路径

**权限提升主线**：

1. **对象读写 → 元数据/凭据窃取**：可读桶中的备份、配置、密钥文件可直接获取数据库口令、服务账号密钥、云凭据，实现横向到其它服务的提权。
2. **对象写入 → 投毒**：对静态站点桶或应用所消费配置桶的写入权限，可投毒页面或注入恶意配置，诱导内部用户或下游系统执行。
3. **桶 IAM 自扩**：若攻击者已持有某桶的 `storage.admin` 或具备 `storage.buckets.setIamPolicy` 权限，可给自己授予更高对象权限，扩大控制面。

**持久化路径**：

1. **对象级后门**：在应用消费的桶中放置被篡改的脚本/配置，长期生效。
2. **抢占同名桶**：在目标删除桶后注册同名桶（授权内人工确认后执行），形成对旧引用的持续接管。
3. **保留服务账号/HMAC 密钥**：以密钥形式持有长期访问，不依赖会话生命周期（见 `./iam.md`）。

## 五、防御与检测要点

审计日志事件名清单：

| 事件名 | 含义 | 关注点 |
| --- | --- | --- |
| `storage.buckets.setIamPolicy` | 修改桶 IAM | allUsers/allAuthenticatedUsers 授权 |
| `storage.buckets.delete` | 删除桶 | 桶接管前置 |
| `storage.buckets.create` | 创建桶 | 抢占同名桶 |
| `storage.objects.setIamPolicy` | 修改对象 ACL | 对象级公开 |
| `storage.objects.get` | 读取对象 | 匿名下载（Data Access，需开启记录） |
| `storage.objects.list` | 列举对象 | 匿名枚举（Data Access） |
| `storage.objects.delete` | 删除对象 | 数据破坏 |
| `storage.hmacKeys.create` | 创建 HMAC 密钥 | 长期凭据 |
| `storage.objects.update` | 更新对象 | 内容投毒 |

防御建议：

- 全组织启用 uniform bucket-level access，并设置 `publicAccessPrevention=enforced`，从策略层禁止一切公开。
- 默认不授予 `allUsers` / `allAuthenticatedUsers`，确有需要时使用 Signed URL 或 VPC Service Controls 替代。
- 桶名避免可预测，删除桶前审计外部引用，删除后保留占位桶。
- 开启 Data Access logs（`storage.objects.get/list`），对匿名读取建立告警。
- 对 `storage.buckets.setIamPolicy`、`storage.buckets.delete`、`storage.buckets.create` 建立实时告警，联动 SCC 公开桶发现项。
