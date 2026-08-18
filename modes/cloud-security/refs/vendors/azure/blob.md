# Azure Blob Storage 对象存储攻防

Azure Blob Storage 是 Azure 的对象存储服务，以存储账户（Storage Account）为顶层资源，其下按容器（Container）组织 Blob。攻击面集中在「访问控制层级」：存储账户级密钥/SAS 与容器级 ACL 的叠加关系复杂，历史上大量数据泄露源自公有容器、过度宽松的 SAS 与密钥泄露。

## 一、攻击面

- **存储账户（Storage Account）**：资源本身，支持存储账户密钥（两个 512 位 key）与基于 Microsoft Entra ID 的 RBAC 授权两种方式。密钥可读可写整个账户，是最高权重凭据。
- **容器（Container）与 Blob**：容器有「公有访问级别」（Private / Blob / Container）设置，Blob 级可再叠加 SAS（共享访问签名）。层级关系决定了匿名可达性。
- **共享访问签名（SAS）**：账户级 SAS 与服务级 SAS，含权限、起止时间、签名；SAS 泄露或权限过宽（如 `racwdl` 全权限、长时间有效）是主要风险。
- **连接字符串（Connection String）**：内含账户名与密钥或 SAS，常见于应用代码、配置文件、CI/CD 变量、日志与公开仓库。
- **访问控制组合**：匿名公有容器、密钥、SAS、RBAC 数据面角色（如「存储 Blob 数据读取者」）四种机制并存，容易因叠加误判而过度暴露。
- **数据面与管理面**：`Microsoft.Storage/storageAccounts/regenerateKey/action`、`listKeys/action` 属管理面，拿到密钥即转入数据面完全读写。
- **网络访问规则**：存储防火墙（IP 白名单）、服务终结点、私有终结点决定网络可达性；默认「允许所有网络」是常见暴露点。
- **静态网站托管与生命周期**：静态网站托管、软删除、版本控制、不可变存储等数据面特性，误配可扩大泄露或阻碍事后恢复。
- **跨区域复制与备份**：异地复制、对象复制、备份策略若未纳入访问控制，可能形成额外的数据副本暴露面。
- **诊断与日志**：存储诊断日志（StorageAnalyticsLogs）、Defender for Storage 的启用状态决定防守侧可见性。

## 二、信息收集 / 暴露面探测

以下命令只读优先，用于枚举存储账户、容器、公有访问级别与匿名可达性。

```bash
# 列出订阅内所有存储账户
az storage account list --query "[].{name:name, kind:kind, httpsOnly:enableHttpsTrafficOnly}" --output table

# 列出某账户下所有容器及公有访问级别
az storage container list --account-name <acct> \
  --query "[].{name:name, public:properties.publicAccess}" --output table

# 列出某容器内的 Blob（需有访问权限）
az storage blob list --account-name <acct> --container-name <container> \
  --query "[].{name:name, length:properties.contentLength}" --output table

# 查看账户关键属性（公开访问、共享密钥、TLS 版本）
az storage account show --name <acct> \
  --query "{allowBlobPublicAccess:allowBlobPublicAccess, allowSharedKeyAccess:allowSharedKeyAccess, minTlsVersion:minimumTlsVersion}"

# 查看账户网络访问规则（默认是否允许所有网络）
az storage account network-rule list --account-name <acct>

# 枚举账户是否启用了匿名 Blob 访问
az storage account list --query "[].{name:name, blobPublic:allowBlobPublicAccess}" --output table
```

探测要点：`properties.publicAccess` 为 `Blob` 或 `Container` 时存在匿名读取入口；`allowBlobPublicAccess=false` 表示账户级已禁止匿名访问；网络规则 `defaultAction=Allow` 表示对全网可达。匿名探测应使用不含密钥的方式，以验证真实的公开暴露。

## 三、常见配置缺陷与利用路径

### 3.1 容器 / Blob 公有访问级别误设

- **缺陷描述**：容器公有访问级别被设为 `Blob` 或 `Container`，或账户级 `allowBlobPublicAccess` 未关闭，导致任何人无需凭据即可匿名列举（Container 级）或读取（Blob 级）对象。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看容器公有访问级别
az storage container list --account-name <acct> \
  --query "[?properties.publicAccess].{name:name, public:properties.publicAccess}" --output table

# 只读验证：尝试匿名列举容器内 Blob（不带密钥，只读）
az storage blob list --account-name <acct> --container-name <container> \
  --auth-mode login --query "[].name"
```

- **影响**：敏感对象（备份、凭据文件、源码包、用户数据）被匿名下载，直接造成数据泄露，且无需任何账户。
- **检测侧建议**：存储账户诊断日志 `StorageAnalyticsLogs`（StorageRead/StorageWrite 操作）会记录匿名读取请求，`AnonymousSuccess` 状态可标识匿名成功访问。防守方应在 Sentinel 中基于 `StorageAnalyticsLogs` 建立「匿名成功读取」「非预期读取」告警，并启用 Defender for Storage 的公开访问扫描。

### 3.2 存储账户密钥泄露与复用

- **缺陷描述**：账户密钥通过应用配置、连接字符串、源码仓库、CI/CD 日志、环境变量泄露；或密钥长期未轮换，攻击者持 key 即可对整个账户做完全读写与删除。
- **验证命令（只读优先）**：

```bash
# 只读验证：确认当前登录身份是否有列出密钥的权限（管理面）
az storage account keys list --resource-group <rg> --account-name <acct>

# 只读验证：检查账户密钥轮换属性（keyCreationTime 可判断密钥年龄）
az storage account show --name <acct> --query "keyCreationTime"
```

- **影响**：密钥等价于账户完全控制，可读取、篡改、导出全部数据，并可用于构造后续持久化的 SAS。
- **检测侧建议**：管理面 `listKeys` 由 Activity Log 记录 `Microsoft.Storage/storageAccounts/listKeys/action`；数据面密钥操作记录在 `StorageAnalyticsLogs`。防守方应监控 `listKeys/action` 的调用主体与频率，对密钥泄露场景尽快轮换（轮换为破坏性操作，须授权内人工确认后执行）。

### 3.3 过度宽松 / 长期有效的 SAS

- **缺陷描述**：SAS 权限过宽（如 `sp=racwdl` 全部权限）、有效期过长、或账户级 SAS 泄露，攻击者可凭 SAS 长期读写容器/Blob，甚至执行写入（污染数据）。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看账户 SAS 相关配置（共享访问签名的授权记录）
az storage account show --name <acct> --query "{name:name, id:id}"

# 只读验证：用已获取的 SAS 只读列举容器内 Blob（若 SAS 为只读）
az storage blob list --account-name <acct> --container-name <container> --sas-token "<sas>"
```

- **影响**：SAS 绕过 Entra ID RBAC 的精细授权，泄露后难以吊销（除非撤销账户密钥使服务级 SAS 失效），可造成长期静默数据访问。
- **检测侧建议**：`StorageAnalyticsLogs` 记录每次 SAS 鉴权的操作与 `AuthenticationType`（如 `SAS`），可回溯 SAS 的使用 IP 与时间。防守方应限制 SAS 最长有效期、禁用账户级 SAS，并在日志中监控 `AuthenticationType=SAS` 的异常访问模式。

### 3.4 允许共享密钥访问未收紧

- **缺陷描述**：账户允许共享密钥访问（`allowSharedKeyAccess=true`）时，任何持密钥或连接字符串的主体都可绕过 Entra ID RBAC 的数据面控制，扩大密钥泄露的后果。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看是否允许共享密钥访问
az storage account show --name <acct> \
  --query "{allowSharedKeyAccess:allowSharedKeyAccess, allowBlobPublicAccess:allowBlobPublicAccess}"
```

- **影响**：即便数据面 RBAC 已细粒度配置，共享密钥仍是「万能钥匙」，密钥泄露即可完全读写。
- **检测侧建议**：Activity Log 记录 `Microsoft.Storage/storageAccounts/regenerateKey/action`（轮换/禁用密钥）与账户配置变更；`StorageAnalyticsLogs` 的 `AuthenticationType=AccountKey` 标识密钥访问。防守方应在可行场景下关闭共享密钥访问，改用 Entra ID 数据面角色，并监控 `AccountKey` 鉴权。

### 3.5 存储网络访问规则缺失（默认全网可达）

- **缺陷描述**：存储账户未配置网络访问规则（IP 白名单/服务终结点/私有终结点），`defaultAction` 保持 `Allow`，使账户端点对互联网可达，配合泄露的密钥/SAS 即被直接访问。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看网络访问规则与默认动作
az storage account network-rule list --account-name <acct> \
  --query "{defaultAction:defaultAction, rules:ipRules}"
```

- **影响**：账户脱离网络隔离，任何持有凭据或匿名权限的主体都可从任意位置访问，扩大泄露后果。
- **检测侧建议**：Activity Log 记录网络规则变更 `Microsoft.Storage/storageAccounts/networkAcls/write`；`StorageAnalyticsLogs` 记录访问请求的 IP。防守方应默认配置私有终结点/IP 白名单，并对网络规则变更告警。

## 四、权限提升与持久化路径

- **密钥 → 全账户接管**：由 `listKeys/action` 或应用配置泄露获得密钥，实现从「单容器读取」到「全账户读写」的提权。
- **regenerateKey 持久化**：持有 `Microsoft.Storage/storageAccounts/regenerateKey/action` 权限的主体可轮换密钥，既可用于持久化访问，也可用于破坏/阻断（轮换会中断现有依赖方，属破坏性操作，须授权内人工确认后执行）。
- **SAS 持久化**：利用账户密钥生成长期账户级 SAS，作为不依赖密钥轮换的独立访问凭据（服务级 SAS 随密钥轮换失效，账户级 SAS 则独立）。
- **写入型后门**：通过 SAS 或密钥向公开可读容器写入恶意文件，利用宿主应用的静态资源加载实现持久化或投毒。

## 五、防御与检测要点

关键审计日志事件名清单：

| 服务/日志 | 关键事件 / 操作 |
| --- | --- |
| Azure Activity Log | `Microsoft.Storage/storageAccounts/listKeys/action` |
| Azure Activity Log | `Microsoft.Storage/storageAccounts/regenerateKey/action` |
| Azure Activity Log | `Microsoft.Storage/storageAccounts/write`（配置变更，含允许公开访问开关） |
| Azure Activity Log | `Microsoft.Storage/storageAccounts/networkAcls/write`（网络规则变更） |
| 存储账户诊断日志 | `StorageAnalyticsLogs` 的 `StorageRead`/`StorageWrite`、`AuthenticationType`（Anonymous/AccountKey/SAS） |
| 存储账户诊断日志 | `AnonymousSuccess`（匿名成功访问标记） |
| Microsoft Defender for Storage | 公有容器暴露、可疑数据外泄告警 |
| Microsoft Sentinel | 基于 StorageAnalyticsLogs 的匿名/SAS 异常访问规则 |

云检测缺口提示：匿名读取与 SAS 访问不会触发管理面 Activity Log 事件，仅记录在 `StorageAnalyticsLogs` 数据面日志中。若未启用存储诊断日志，匿名泄露可长时间静默。防守方应把「数据面日志」而非「管理面日志」作为存储泄露检测的主数据源。

防御要点小结：账户级关闭 `allowBlobPublicAccess` 与 `allowSharedKeyAccess`、密钥定期轮换并限制 `listKeys` 权限、SAS 短时且最小权限并禁用账户级 SAS、网络访问规则默认收紧、启用诊断日志与 Defender for Storage、对 `listKeys`/`regenerateKey` 建立告警与审批。
