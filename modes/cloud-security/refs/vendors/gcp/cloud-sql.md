# Cloud SQL 云数据库攻防

Cloud SQL 是 GCP 的托管关系型数据库服务，支持 MySQL、PostgreSQL、SQL Server。其攻击面集中在「网络暴露」与「认证方式」两条线：实例是否拥有公网 IP、`authorized networks` 是否开放到 `0.0.0.0/0`、是否启用了 IAM 数据库认证、是否强制 SSL/TLS、密码强度与轮换策略，以及数据库实例标志（flags）中是否存在危险配置。

## 一、攻击面

Cloud SQL 的攻击面可归纳为：

1. **公网 IP + 开放授权网络**：实例启用公网 IP 且 `authorized networks` 含 `0.0.0.0/0` 时，数据库端口直接对互联网开放，成为暴力破解与已知口令重放的首要目标。
2. **弱口令与默认口令**：托管数据库不设默认口令，但用户常设置弱口令或复用口令；暴力破解、口令喷洒可命中。
3. **未强制 SSL/TLS**：明文传输使同一网络段的监听者或中间人可以窃听数据库流量与口令。
4. **IAM 数据库认证**：PostgreSQL/MySQL 支持用 Cloud IAM 身份登录数据库；配置错误会导致服务账号被错误映射为高权限数据库账号。
5. **数据库实例标志（flags）**：如 `skip_show_database`、`log_connections`、`local_infile`（MySQL）等标志关闭或开启不当，会放大信息泄露与数据读取面。
6. **备份与副本**：备份导出、跨区域副本、自动备份若权限失控，可被读取整库数据。
7. **Cloud SQL Auth Proxy**：代理以服务账号身份连接，若服务账号权限过宽，数据库连接凭据可被横向使用。
8. **实例级 IAM 权限**：`cloudsql.instances.get`、`cloudsql.instances.export`、`cloudsql.users.list` 等权限可被用于元数据泄露与数据导出。

## 二、信息收集 / 暴露面探测

以下命令为只读探测，用于枚举数据库实例与网络暴露面。

```bash
# 列出当前项目下全部 Cloud SQL 实例
gcloud sql instances list

# 查看单个实例详情：数据库版本、公网 IP、区域、状态、磁盘、备份配置
gcloud sql instances describe <INSTANCE> --format=json

# 只读提取实例网络配置（ipAddresses、authorized networks、requireSsl）
gcloud sql instances describe <INSTANCE> \
  --format="value(settings.ipConfiguration)"

# 查看实例是否强制 SSL（requireSsl 字段）
gcloud sql instances describe <INSTANCE> \
  --format="value(settings.ipConfiguration.requireSsl)"

# 列出实例的数据库用户（账号名与认证类型）
gcloud sql users list --instance <INSTANCE>

# 查看实例的数据库列表（需具备相应数据库连接权限）
gcloud sql databases list --instance <INSTANCE>

# 查看实例操作历史（备份、导出、重启等）
gcloud sql operations list --instance <INSTANCE>

# 查看实例的 IAM 策略（谁能管理该实例）
gcloud sql instances get-iam-policy <INSTANCE> --format=json
```

探测要点：优先确认实例是否暴露公网 IP 且 `authorized networks` 为 `0.0.0.0/0`；确认 `requireSsl` 是否启用；确认是否存在使用 IAM 认证的用户；关注 `cloudsql.instances.export`、`cloudsql.instances.import` 等高危权限归属。

## 三、常见配置缺陷与利用路径

### 3.1 公网 IP + authorized networks 0.0.0.0/0

**缺陷描述**：实例启用公网 IP 且授权网络被配置为 `0.0.0.0/0`（允许任意源），数据库端口（MySQL 3306、PostgreSQL 5432、SQL Server 1433）对全网开放。这是最常见的暴露缺陷。

**验证命令（只读优先）**：

```bash
# 只读查看实例授权网络与 SSL 配置
gcloud sql instances describe <INSTANCE> \
  --format="json(settings.ipConfiguration)"
```

**影响**：开放数据库端口直接进入暴力破解与口令喷洒的攻击面；一旦口令被命中或存在未授权访问，数据可被整库读取、篡改或破坏（破坏性操作须授权内人工确认后执行）。

**检测侧建议**：修改实例网络配置对应 Cloud Audit Logs 事件 `cloudsql.instances.update`（Admin Activity）；SCC 会对「数据库实例对公网开放」「授权网络 0.0.0.0/0」给出发现项。数据库连接层应启用 `log_connections`（PostgreSQL）或 `log_error_verbosity` 等标志，将连接尝试落入数据库日志，便于关联暴力破解。

### 3.2 弱口令与口令喷洒

**缺陷描述**：数据库账号使用弱口令、默认组合或与其它系统复用口令。攻击者通过口令喷洒/暴力破解即可登录，无需其它漏洞。

**验证命令（只读优先）**：

```bash
# 只读枚举用户列表（确认目标账号，需数据库连接权限）
gcloud sql users list --instance <INSTANCE>
```

> 实际登录验证为最小影响的认证尝试，须在授权范围内对测试账号执行，禁止对生产账号做高频爆破。

**影响**：弱口令命中即获得数据库读写能力，可窃取整库数据、篡改业务数据、作为跳板向实例服务账号（若配置了）或相邻系统横向移动。

**检测侧建议**：数据库连接与认证行为默认落在实例数据库日志中（需开启相应日志标志），可通过 Cloud Logging 汇聚；Cloud SQL 自身的失败登录不直接产生 Admin Activity 事件，因此应在数据库侧开启失败登录记录并接入 SIEM。SCC 的「数据库弱口令」类发现项可辅助识别。

### 3.3 未强制 SSL/TLS 明文传输

**缺陷描述**：实例未开启 `requireSsl` 时，客户端到数据库的流量默认明文传输，口令与数据在网络链路上可被嗅探或中间人窃听。

**验证命令（只读优先）**：

```bash
# 只读确认实例是否强制 SSL
gcloud sql instances describe <INSTANCE> \
  --format="value(settings.ipConfiguration.requireSsl)"
```

**影响**：明文流量泄露数据库凭据与业务数据，尤其在跨网络、跨区域或共享网络环境下风险更高。

**检测侧建议**：`requireSsl` 配置变更落在 `cloudsql.instances.update` 事件；防守方应强制 SSL，并在客户端侧限制仅允许 SSL 连接。明文传输本身难以在云审计日志中直接观测，需结合网络层监控（VPC Flow Logs、抓包）识别异常。

### 3.4 IAM 数据库认证配置错误

**缺陷描述**：PostgreSQL/MySQL 支持 Cloud IAM 数据库认证，服务账号或用户经 IAM 映射为数据库账号。若映射规则配置错误，低权限 IAM 主体可能被映射为高权限数据库角色，或数据库账号密码认证与 IAM 认证并存造成双通道。

**验证命令（只读优先）**：

```bash
# 只读查看实例的用户列表与认证类型（IAM 认证用户标记为 CLOUD_IAM_SERVICE_ACCOUNT / CLOUD_IAM_USER）
gcloud sql users list --instance <INSTANCE>
```

**影响**：错误的 IAM 映射会放大权限，使持有低权限服务账号的攻击者获得数据库高权限；同时服务账号密钥泄露会连锁导致数据库接管。

**检测侧建议**：IAM 数据库认证的用户创建/修改对应 `cloudsql.users.create`、`cloudsql.users.update` 事件；实例侧 `cloudsql.instances.update` 记录了认证开关变更。应审计 IAM 数据库用户到角色的映射，避免过度授权，并优先启用 IAM 认证关闭密码通道。

### 3.5 危险数据库标志（flags）

**缺陷描述**：数据库标志配置不当会放大攻击面，例如 MySQL `local_infile=ON` 可被用于从客户端读取本地文件（配合 SQL 注入/恶意客户端），`skip_show_database=OFF` 暴露数据库名枚举。

**验证命令（只读优先）**：

```bash
# 只读查看实例的数据库标志
gcloud sql instances describe <INSTANCE> \
  --format="json(settings.databaseFlags)"
```

**影响**：危险标志被利用后，可造成本地文件读取、数据库结构枚举、审计日志被关闭等后果。

**检测侧建议**：标志变更落在 `cloudsql.instances.update` 事件；数据库侧应保持 `local_infile` 关闭、`skip_show_database` 开启（MySQL），并启用连接与查询日志标志以支撑审计。

## 四、权限提升与持久化路径

**权限提升主线**：

1. **数据库权限 → 实例元数据/凭据**：若数据库实例关联了服务账号（用于导出、代理连接），攻破数据库后可读取存储于库中的备份口令、连接串，进一步使用 `cloudsql.instances.export` 导出整库到可控位置。
2. **cloudsql.instances.export 滥用**：持有该权限者可把整库导出为 SQL/CSV 到指定 Cloud Storage 桶，实现数据外带，权限上等价于数据库读取能力的「云侧副本」。
3. **服务账号 → 数据库 IAM 认证**：持有实例关联服务账号者，若 IAM 数据库认证已启用，可直接以该服务账号身份登录数据库，无需数据库口令。

**持久化路径**：

1. **数据库后门账号**：在数据库内创建高权限账号长期使用（授权内人工确认后执行），对应数据库侧 `CREATE USER`/`GRANT`。
2. **实例 IAM 授权自留**：在实例 IAM 上给自己授予管理权限，保留云侧入口。
3. **备份/导出持久化**：定期导出数据到可控存储位置，形成持续外带通道。
4. **关闭审计标志**：修改数据库标志关闭日志，降低后续操作可见性（授权内人工确认后执行）。

## 五、防御与检测要点

审计日志事件名清单：

| 事件名 | 含义 | 关注点 |
| --- | --- | --- |
| `cloudsql.instances.update` | 修改实例配置 | 网络开放、SSL、标志变更 |
| `cloudsql.instances.create` | 创建实例 | 初始网络暴露面 |
| `cloudsql.instances.delete` | 删除实例 | 数据破坏 |
| `cloudsql.instances.export` | 导出数据库 | 数据外带 |
| `cloudsql.instances.import` | 导入数据库 | 数据投毒/恢复 |
| `cloudsql.instances.getIamPolicy` / `setIamPolicy` | 读取/修改实例 IAM | 权限变更 |
| `cloudsql.users.create` / `cloudsql.users.update` / `cloudsql.users.delete` | 用户增删改 | 后门账号、认证类型变更 |
| `cloudsql.instances.restart` | 重启实例 | 配合配置生效 |

防御建议：

- 数据库实例优先使用私网 IP（VPC 内访问），确需公网时用最小化 `authorized networks`，严禁 `0.0.0.0/0`。
- 强制 SSL（`requireSsl=true`），并启用 IAM 数据库认证、关闭密码通道。
- 数据库标志保持安全默认：`local_infile` 关闭、`skip_show_database` 开启，开启连接与查询日志。
- 对 `cloudsql.instances.export`、`cloudsql.instances.update`、`cloudsql.users.create` 建立实时告警。
- 数据库口令纳入密钥管理并定期轮换，启用备份加密与访问审计。
