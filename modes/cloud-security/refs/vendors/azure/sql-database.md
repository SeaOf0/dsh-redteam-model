# Azure SQL Database / Cosmos DB 云数据库攻防

Azure 云数据库涵盖关系型（Azure SQL Database、Azure Database for PostgreSQL/MySQL/MariaDB）与 NoSQL（Azure Cosmos DB）。攻击面集中在「网络可达性（防火墙规则）」「管理员账号与密钥」「公开端点与私有终结点」三者的交叉，多数暴露由防火墙规则误设为 `0.0.0.0`、管理员凭据弱化或连接字符串泄露引起。

## 一、攻击面

- **SQL 逻辑服务器（SQL Server）**：Azure SQL Database 挂靠逻辑服务器，服务器级防火墙规则控制公网可达性；服务器级管理员（Server Admin）与数据库级用户构成认证层。
- **防火墙规则**：`az sql server firewall-rule` 管理允许访问的 IP 范围；`StartIpAddress=0.0.0.0`、`EndIpAddress=255.255.255.255` 表示对全互联网开放。
- **公开端点与私有终结点**：默认 `PublicNetworkAccess` 决定是否暴露公网端点；私有终结点（Private Endpoint）走 VNet 隔离。公开端点 + 宽松防火墙 + 弱凭据是经典暴露链。
- **Cosmos DB**：账户级主密钥（primary/secondary key）、读写密钥（read-write/readonly）、连接字符串；`disableLocalAuth` 决定是否允许密钥/本地认证。
- **管理员与 RBAC**：SQL Server 的 Microsoft Entra ID 管理员（Entra Admin）、Cosmos DB 的数据面 RBAC 与密钥并存，权限叠加复杂。
- **审计与诊断**：SQL 审计日志、诊断设置、Cosmos DB 诊断日志，是防守侧可见性的主要数据源。
- **连接字符串**：数据库连接串（含服务器名、账号、密码）常见于应用配置、源码、CI/CD 变量，泄露即数据面完全访问。
- **跨区域复制与备份**：异地复制、长期备份保留若未加密或未纳入访问控制，形成额外副本暴露面。
- **威胁防护与漏洞评估**：SQL 威胁检测、漏洞评估、透明数据加密（TDE）等防护未启用时，攻击更难被发现。
- **连接策略与传输安全**：连接策略、最低 TLS 版本、强制加密等传输层配置缺失，扩大中间人窃听面。

## 二、信息收集 / 暴露面探测

以下命令只读优先，用于枚举数据库服务器、防火墙规则、公开访问状态与管理员配置。

```bash
# 列出订阅内所有 SQL 服务器
az sql server list --query "[].{name:name, public:publicNetworkAccess, admin:administratorLogin}" --output table

# 列出某服务器的防火墙规则（识别 0.0.0.0 开放）
az sql server firewall-rule list --resource-group <rg> --server <server> \
  --query "[].{name:name, start:startIpAddress, end:endIpAddress}" --output table

# 列出某服务器的数据库
az sql db list --resource-group <rg> --server <server> \
  --query "[].{name:name, status:status}" --output table

# 查看服务器级 Entra ID 管理员（是否存在）
az sql server ad-admin list --resource-group <rg> --server <server>

# 列出订阅内 Cosmos DB 账户
az cosmosdb list --query "[].{name:name, public:publicNetworkAccess}" --output table

# 查看 Cosmos DB 账户是否允许本地认证/密钥
az cosmosdb show --name <acct> --resource-group <rg> \
  --query "{disableLocalAuth:disableLocalAuth, publicNetworkAccess:publicNetworkAccess}"
```

探测要点：`publicNetworkAccess=Enabled` 表示公网端点可用；防火墙规则含 `0.0.0.0-255.255.255.255` 即全网可达；`administratorLogin` 为空或弱口令是尝试登录的前提；`disableLocalAuth=false` 表示密钥/本地认证仍可用。

## 三、常见配置缺陷与利用路径

### 3.1 防火墙规则全网开放 + 弱管理员凭据

- **缺陷描述**：SQL 服务器防火墙规则设为 `0.0.0.0/0` 或全地址段，且服务器级管理员使用弱密码/默认凭据，攻击者可绕过 VNet 隔离直接对公网端点进行认证尝试。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出防火墙规则，确认全网开放
az sql server firewall-rule list --resource-group <rg> --server <server> \
  --query "[?startIpAddress=='0.0.0.0'].{name:name, end:endIpAddress}" --output table

# 只读验证：确认公网访问开关
az sql server show --resource-group <rg> --name <server> --query "publicNetworkAccess"
```

- **影响**：攻击者一旦通过认证，可读取/导出数据库全部数据（如备份、用户表、密钥），并可能利用数据库内存储过程或作业实现命令执行或横向。
- **检测侧建议**：SQL 审计日志记录登录事件（`DATABASE AUTHENTICATION SUCCEEDED`/`FAILED`）与源 IP；活动日志记录防火墙规则变更 `Microsoft.Sql/servers/firewallRules/write`。防守方应在 Sentinel 中监控「非预期 IP 的成功登录」「防火墙规则新增 0.0.0.0」事件。

### 3.2 公开端点暴露 + 无私有终结点隔离

- **缺陷描述**：数据库启用 `PublicNetworkAccess` 且未配置私有终结点，将数据库暴露到互联网可达的端点，叠加宽松防火墙即形成完整暴露链。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出公开访问与私有终结点状态
az sql server show --resource-group <rg> --name <server> \
  --query "{public:publicNetworkAccess, privateEndpoint:privateEndpointConnections}"
```

- **影响**：数据库脱离内部网络隔离，暴露给公网扫描与暴力尝试，扩大凭据爆破与数据泄露面。
- **检测侧建议**：Activity Log 记录 `Microsoft.Sql/servers/privateEndpointConnections/write`（私有终结点变更）与服务器配置变更；SQL 审计日志记录所有成功/失败登录的源 IP。防守方应把「PublicNetworkAccess=Enabled 且无私有终结点」列为 Defender for SQL 的基线告警。

### 3.3 连接字符串 / 管理员凭据泄露

- **缺陷描述**：应用连接字符串（含服务器名、账号、密码）泄露于源码仓库、配置文件、环境变量或部署日志；或 SQL Server / Cosmos DB 密钥在应用中硬编码。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看 Cosmos DB 账户密钥权限与是否禁用本地认证
az cosmosdb show --name <acct> --resource-group <rg> \
  --query "{disableLocalAuth:disableLocalAuth, keyVersion:keyVaultKeyUri}"

# 只读验证：列出 Cosmos DB 数据库/容器（需账户访问）
az cosmosdb sql database list --account-name <acct> --resource-group <rg> --output table
```

- **影响**：连接字符串/密钥等价于数据面完全访问，可读取或篡改全部数据，且 Cosmos DB 主密钥可读写整个账户。
- **检测侧建议**：Cosmos DB 诊断日志记录数据面请求；Activity Log 记录密钥轮换 `Microsoft.DocumentDB/databaseAccounts/regenerateKey/action` 与 `listKeys`。防守方应对源码与 CI/CD 变量做密钥扫描，并对 `regenerateKey`/`listKeys` 建立告警。

### 3.4 Cosmos DB 允许本地认证未收紧

- **缺陷描述**：Cosmos DB 账户未设置 `disableLocalAuth=true`，主密钥/读写密钥仍可用，密钥泄露即完全接管，绕过了 Entra ID 数据面 RBAC 的精细控制。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看本地认证开关与密钥状态
az cosmosdb show --name <acct> --resource-group <rg> \
  --query "{disableLocalAuth:disableLocalAuth, publicNetworkAccess:publicNetworkAccess}"
```

- **影响**：即便已配置 RBAC，遗留的主密钥仍是「万能钥匙」，扩大密钥泄露后果。
- **检测侧建议**：Activity Log 记录 `Microsoft.DocumentDB/databaseAccounts/regenerateKey/action`；诊断日志记录 `AuthenticationType` 区分密钥与 Entra ID 鉴权。防守方应在可行时禁用本地认证，并监控密钥鉴权。

### 3.5 数据库审计 / 诊断未启用

- **缺陷描述**：SQL Server 或 Cosmos DB 未启用审计日志/诊断设置，攻击者的登录、数据导出、敏感查询无日志可查，泄露长期不可见。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看 SQL 服务器的审计策略状态
az sql server audit-policy show --resource-group <rg> --server <server>

# 只读验证：查看 Cosmos DB 诊断设置
az monitor diagnostic-settings list --resource <cosmosdb-resource-id> --output json
```

- **影响**：数据面攻击（SELECT 大范围导出、异常登录）无法被溯源，降低防守侧取证与响应能力。
- **检测侧建议**：启用审计后，SQL 审计日志记录 `DATABASE AUTHENTICATION SUCCEEDED/FAILED`、`SELECT` 等语句级事件；Cosmos DB 诊断日志记录数据面操作。防守方应强制开启审计并纳入 Sentinel，缺失审计本身即作为合规告警。

## 四、权限提升与持久化路径

- **数据库登录 → 服务器内横向**：SQL 服务器级管理员凭据可访问同服务器下全部数据库，实现从单库到多库的权限扩散。
- **SQL 作业/存储过程作为持久化**：在获得数据库高权限后，通过 SQL Agent 作业、触发器或存储过程植入持久化逻辑（须授权内确认）。
- **密钥轮换持久化/破坏**：持有 `regenerateKey/action` 权限可轮换 Cosmos DB 主密钥，既可用作持久化，也可破坏现有依赖方（破坏性，须授权内人工确认后执行）。
- **数据外泄与投毒**：通过数据库高权限直接导出数据或篡改业务数据，实现持久影响或数据破坏。

## 五、防御与检测要点

关键审计日志事件名清单：

| 服务/日志 | 关键事件 / 操作 |
| --- | --- |
| Azure Activity Log | `Microsoft.Sql/servers/firewallRules/write`（防火墙规则变更） |
| Azure Activity Log | `Microsoft.Sql/servers/privateEndpointConnections/write` |
| Azure Activity Log | `Microsoft.DocumentDB/databaseAccounts/regenerateKey/action`、`listKeys` |
| SQL 审计日志 | `DATABASE AUTHENTICATION SUCCEEDED` / `DATABASE AUTHENTICATION FAILED`（含源 IP） |
| SQL 审计日志 | 敏感数据访问（`SELECT` 大范围导出） |
| Cosmos DB 诊断日志 | 数据面请求与 `AuthenticationType`（密钥/Entra ID） |
| Microsoft Defender for SQL | 公网暴露、异常登录、SQL 注入、可疑数据外泄 |
| Microsoft Defender for Cloud | 数据库公开访问、未启用审计的合规建议 |

云检测缺口提示：数据库数据面攻击（成功登录、数据导出）不产生 Activity Log 事件，仅在 SQL 审计日志/Cosmos DB 诊断日志中可见。若未启用审计，数据泄露可完全静默。防守方应以「审计/诊断日志」为数据库检测主数据源，并把「审计未启用」本身作为高优先级告警。

防御要点小结：默认禁用公网端点或强制私有终结点、防火墙规则最小化并监控 `0.0.0.0` 变更、使用 Entra ID 管理员并禁用本地密钥认证、强制 SQL 审计与 Defender for SQL、对密钥轮换与防火墙变更建立告警与审批。
