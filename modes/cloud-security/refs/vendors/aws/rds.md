# RDS 云数据库攻防

本文聚焦 Amazon RDS 云数据库的攻击面、常见配置缺陷与检测要点，供授权安全评估参考。权限模型见 `./iam.md`，网络暴露面见 `./network.md`，数据库层通用攻防另见数据库安全相关文档。

## 一、攻击面

RDS 攻击面集中在**暴露面**与**数据副本**两条主线：

- **网络暴露**：`PubliclyAccessible` 开启、安全组放行公网、子网组配置错误
- **认证面**：MasterUser 弱口令、IAM 数据库认证配置、未强制 TLS
- **数据副本**：快照公开共享、跨账户快照复制、备份未加密
- **配置面**：参数组（如 `skip_grant_tables`、日志开关）、事件订阅、性能洞察
- **引擎面**：MySQL / PostgreSQL / SQL Server / Oracle 各引擎特有的用户与权限模型

## 二、信息收集 / 暴露面探测

```bash
# 枚举数据库实例（关注 PubliclyAccessible、Endpoint、Engine、安全组）
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Engine,PubliclyAccessible,Endpoint.Address,Endpoint.Port]'

# 枚举集群（Aurora）
aws rds describe-db-clusters

# 枚举快照（关注共享/公开状态）
aws rds describe-db-snapshots --query 'DBSnapshots[].[DBSnapshotIdentifier,DBInstanceIdentifier,Status,Encrypted]'

# 查看快照共享属性
aws rds describe-db-snapshot-attributes --db-snapshot-identifier snap-id

# 查看子网组与参数组
aws rds describe-db-subnet-groups
aws rds describe-db-parameters --db-parameter-group-name default.mysql8.0

# 查看实例绑定的安全组
aws rds describe-db-instances --db-instance-identifier db-id --query 'DBInstances[].VpcSecurityGroups[]'
```

## 三、常见配置缺陷与利用路径

### 3.1 公开可访问数据库

**缺陷描述**：`PubliclyAccessible=true` 且安全组允许公网入站，数据库端点直接暴露在互联网，成为口令爆破与漏洞利用的入口。

**验证命令（只读优先）**：

```bash
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible,Endpoint.Address,Endpoint.Port]'
```

**影响**：数据库直接暴露，弱口令或未修复引擎漏洞可被利用；爆破与恶意连接会留下大量失败尝试。

**检测侧建议**：`ModifyDBInstance`（`PubliclyAccessible` 变更）写入 CloudTrail；RDS 事件订阅可对连接异常告警，CloudWatch 指标（`DatabaseConnections`、失败登录）可佐证爆破。建议关闭公网、经跳板或专用连接访问。

### 3.2 快照公开共享

**缺陷描述**：数据库快照被共享为 public 或共享给陌生账号，任何账号可复制快照并恢复出完整库，含全部业务数据与用户表。

**验证命令（只读优先）**：

```bash
aws rds describe-db-snapshot-attributes --db-snapshot-identifier snap-id
aws rds describe-db-snapshots --include-shared --include-public
```

**影响**：全量数据泄露，等价于数据库文件被导出；破坏性风险低但影响极大。

**检测侧建议**：`ModifyDBSnapshotAttribute` 写入 CloudTrail；Config 可检测公开快照。建议快照默认私有、跨账户共享仅限可信账号并加 KMS 加密。

### 3.3 MasterUser 弱口令与默认账户

**缺陷描述**：MasterUser 密码弱、复用或写进代码/配置；未启用 IAM 数据库认证，长期依赖单一主账号口令。

**验证命令（只读优先，连接测试需授权）**：

```bash
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,MasterUsername]'
```

**影响**：口令泄露或爆破后获得数据库最高权限，可拖库、篡改、删除。删除/改密属破坏性，需**授权内人工确认后执行**。

**检测侧建议**：口令登录失败在引擎审计日志与 CloudWatch 中可见（如 MySQL `Access denied`）；建议强制轮换、最小权限账户、启用 IAM 认证与密码策略。

### 3.4 传输未加密

**缺陷描述**：实例未强制 TLS，或应用以明文连接，敏感数据在 VPC 内外传输时可能被嗅探（尤其跨公网/跨区域链路）。

**验证命令（只读优先）**：

```bash
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Endpoint]'
```

**影响**：口令与数据明文传输，中间人可窃听。

**检测侧建议**：连接是否加密难以直接日志化，需靠配置审计（参数组 `require_secure_transport`、`rds.force_ssl`）与 VPC Flow Logs 佐证异常明文流量。建议对公网/跨区链路强制 TLS。

### 3.5 备份与快照未加密

**缺陷描述**：未开启加密的实例，其快照与自动备份也是明文；快照泄露后数据可被直接读取。

**验证命令（只读优先）**：

```bash
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,StorageEncrypted]'
aws rds describe-db-snapshots --query 'DBSnapshots[].[DBSnapshotIdentifier,Encrypted]'
```

**影响**：副本泄露即数据泄露，且不满足合规要求。

**检测侧建议**：加密状态可通过 Config 规则检查；建议创建时即启用 KMS 加密（加密属性创建后不可直接翻转）。

### 3.6 过度授权安全组与子网组

**缺陷描述**：数据库安全组放行 `0.0.0.0/0` 或过大网段，子网组把数据库放进公网子网，绕过网络隔离预期。

**验证命令（只读优先）**：

```bash
aws rds describe-db-instances --query 'DBInstances[].VpcSecurityGroups[]'
aws ec2 describe-security-groups --group-ids sg-0abcd1234 --query 'SecurityGroups[].IpPermissions[]'
```

**影响**：内网越权访问数据库，扩大横向移动面。

**检测侧建议**：安全组变更 `AuthorizeSecurityGroupIngress` 写入 CloudTrail（见 `./network.md`）；建议数据库专用安全组白名单化、置于私有子网。

## 四、权限提升与持久化路径

- **快照导出与复制**：拥有 `rds:CopyDBSnapshot` / `rds:ModifyDBSnapshotAttribute` 时，把快照复制到攻击者账户离线恢复（需授权内确认）。
- **参数组注入**：修改参数组（如开启 `general_log`、调整审计）以捕获后续口令或数据，或为后续提权铺路。
- **主密码重置**：拥有 `rds:ModifyDBInstance` 时重置 MasterUserPassword 接管数据库（破坏性，需授权内确认）。
- **跨账户恢复后门**：将含后门账户的快照恢复回目标账号，诱导其继续使用该库。

## 五、防御与检测要点

| 攻击者动作 | CloudTrail 事件名 | 检测/告警建议 |
| --- | --- | --- |
| 修改实例配置 | `ModifyDBInstance` | 对 `PubliclyAccessible`、密码重置、参数组变更告警 |
| 修改快照共享 | `ModifyDBSnapshotAttribute` | 对 public / 陌生账号共享告警 |
| 创建/复制快照 | `CreateDBSnapshot`、`CopyDBSnapshot` | 对跨账户复制告警 |
| 从快照恢复 | `RestoreDBInstanceFromDBSnapshot` | 对非预期恢复告警 |
| 删除实例/快照 | `DeleteDBInstance`、`DeleteDBSnapshot` | 对删除动作做二次确认审计 |
| 修改子网组 | `ModifyDBSubnetGroup` | 对子网拓扑变更告警 |
| 下载数据库日志 | `DownloadDBLogFilePortion` | 对日志外带行为告警 |

配套日志与检测服务：CloudTrail、CloudWatch（连接/失败登录指标）、RDS 事件订阅、Config、GuardDuty、Security Hub。防线核心：关闭公网、快照私有加密、MasterUser 最小权限与轮换、强制 TLS、审计参数组变更。

## 六、云检测缺口小结

RDS 场景的检测缺口集中在**数据面**与**副本**两类：

- **数据面盲区**：数据库内 SQL、拖库、表级读写默认不在 CloudTrail 可见，需依赖引擎审计日志（`general_log` / `pgaudit`）与 `DownloadDBLogFilePortion` 事件联动。
- **副本泄露**：快照公开/跨账户共享的关键事件是 `ModifyDBSnapshotAttribute`，若该事件未纳入告警，等量级的数据泄露可能完全静默。
- **配置态盲区**：`PubliclyAccessible`、加密状态、参数组是静态配置，需 Config 合规规则与安全组巡检兜底，不能只靠事件告警。

补齐思路：引擎审计日志开启并接入 SIEM、快照共享变更实时告警、配置合规规则全量覆盖，把「看不到的拖库」转化为「可告警的副本/配置异动」。
