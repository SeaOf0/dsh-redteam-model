# TencentDB 云数据库攻防

> 面向授权安全测试的 TencentDB 云数据库攻击面梳理与方法论，涵盖 MySQL、PostgreSQL、SQL Server 与 TDSQL，聚焦公网访问、账号权限与审计缺口。所有验证以只读探测优先，破坏性操作需「授权内人工确认后执行」。

## 一、攻击面

TencentDB 是腾讯云托管数据库产品族，包括云数据库 MySQL（CDB）、PostgreSQL、SQL Server 与分布式数据库 TDSQL。其攻击面集中于网络暴露、账号体系与审计能力，可归纳为：

- **网络暴露面**：公网地址开启、安全组放行、VPC 内网暴露。
- **账号体系**：弱口令、默认账号、账号权限过宽、内网免密。
- **实例配置面**：备份下载、参数组、审计开关、SSL 未启用。
- **数据面**：慢查询日志、错误日志中的敏感信息、SQL 注入后的数据访问。

下表列出 TencentDB 攻击面与对应防守视角：

| 攻击面 | 攻击者关注点 | 防守者关注点 |
| --- | --- | --- |
| 公网访问 | 公网地址 + 弱口令 | `ModifyDBInstanceAccessWhiteList` 审计 |
| 账号权限 | 高权限账号滥用 | 数据库审计、账号变更审计 |
| 备份 | 备份下载越权 | 备份下载限制审计 |
| 参数组 | 危险参数开启 | 参数修改审计 |

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于枚举当前账号授权范围内的数据库实例与配置。

```bash
# 列出云数据库 MySQL 实例（只读）
tccli cdb DescribeDBInstances

# 列出云数据库 PostgreSQL 实例（只读）
tccli postgres DescribeDBInstances

# 列出云数据库 SQL Server 实例（只读）
tccli sqlserver DescribeDBInstances

# 列出 TDSQL（分布式数据库）实例（只读）
tccli dcdb DescribeDCDBInstances
```

从返回中重点提取：实例 ID、内网地址（`Vip`/`Vport`）、公网地址是否开启（`WanStatus`）、所属 VPC/子网、安全组、引擎版本、账号白名单。

```bash
# 查看实例安全组（只读）
tccli cdb DescribeDBSecurityGroups --InstanceId cdb-xxxxx

# 查看账号列表与权限（只读，部分引擎支持）
tccli cdb DescribeAccounts --InstanceId cdb-xxxxx
```

公网地址形态如 `cdb-xxxxx.mysql.tencentcdb.com`（此处仅描述域名形态，不含协议前缀），确认 `WanStatus` 为开启即存在公网暴露。

## 三、常见配置缺陷与利用路径

### 3.1 公网地址开启 + 弱口令

**缺陷描述**：数据库实例开启公网访问，且账号使用弱口令或默认口令，导致数据库可直接被互联网暴力破解或直接登录。

**验证命令（只读优先）**：

```bash
# 确认公网访问状态（只读）
tccli cdb DescribeDBInstances --InstanceIds '["cdb-xxxxx"]'
```

检查返回中 `WanStatus` 字段，若为开启则公网可达。弱口令验证以最小影响登录探测为限，禁止高频爆破。

**影响**：攻击者登录数据库后可读取、篡改或导出全量业务数据。

**检测侧建议**：暴力破解与异常登录由数据库审计记录（登录成功/失败事件）；公网地址开启由 CloudAudit `ModifyDBInstanceAccessWhiteList` 或实例创建/修改事件追踪；SOC 对异地登录与爆破建立告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 公网连接 + 弱口令登录 |
| 防守者 | 数据库审计、CloudAudit 访问白名单事件 |

### 3.2 账号权限过宽（高权限账号滥用）

**缺陷描述**：业务账号被授予过高权限（如可跨库访问、可执行 `LOAD_FILE`、可创建账号），一旦泄露即扩大影响。

**验证命令（只读优先）**：

```bash
# 列出账号及权限（只读）
tccli cdb DescribeAccounts --InstanceId cdb-xxxxx
```

登录后（授权内）可用只读查询确认当前账号权限范围，避免实际写操作。

**影响**：高权限账号泄露可导致跨库拖库、写入后门、甚至尝试文件读取（取决于引擎与参数）。

**检测侧建议**：高危 SQL（跨库查询、敏感表访问）由数据库审计记录；账号创建/授权由 CloudAudit `CreateDBImportJob` 等实例操作与数据库审计账号 DDL 记录；SOC 对异常跨库访问告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 高权限账号跨库读写 |
| 防守者 | 数据库审计、账号 DDL 审计 |

### 3.3 备份下载未受限

**缺陷描述**：备份下载权限配置不当（未限制下载网段或未启用下载限制），备份文件被越权下载。

**验证命令（只读优先）**：

```bash
# 查看备份列表与下载限制配置（只读）
tccli cdb DescribeBackups --InstanceId cdb-xxxxx
tccli cdb DescribeBackupDownloadRestriction
```

**影响**：备份文件含全量业务数据，被下载即造成数据泄露。

**检测侧建议**：备份下载行为由 CloudAudit `DescribeBackups`、备份下载事件及 SOC 异常下载告警记录；下载限制变更由 `ModifyBackupDownloadRestriction` 追踪。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 越权下载备份文件 |
| 防守者 | CloudAudit 备份下载事件、下载限制审计 |

### 3.4 安全组过度放行数据库端口

**缺陷描述**：数据库实例绑定的安全组放行 `0.0.0.0/0` 访问 3306/5432/1433 等数据库端口。

**验证命令（只读优先）**：

```bash
# 查看实例绑定安全组（只读）
tccli cdb DescribeDBSecurityGroups --InstanceId cdb-xxxxx

# 查看安全组规则（只读）
tccli vpc DescribeSecurityGroupPolicies --SecurityGroupId sg-xxxxx
```

**影响**：数据库端口暴露公网，即使未开公网地址也可能被同 VPC 内其它受损主机访问，或被安全组放行波及。

**检测侧建议**：安全组规则变更由 CloudAudit `ModifySecurityGroupPolicies` 记录；数据库连接由数据库审计与云监控连接数告警覆盖。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 扫描数据库端口 + 弱口令/漏洞利用 |
| 防守者 | CloudAudit `ModifySecurityGroupPolicies`、数据库审计 |

### 3.5 数据库审计未开启（审计缺口）

**缺陷描述**：数据库审计功能未开启或未覆盖关键实例，导致数据面操作无日志，攻击者 SQL 行为不可见。

**验证命令（只读优先）**：

```bash
# 查看实例审计配置（只读，部分引擎支持）
tccli cdb DescribeAuditConfig --InstanceId cdb-xxxxx
```

**影响**：攻击者在数据面的拖库、篡改、后门写入无审计痕迹，形成「云检测缺口」。

**检测侧建议**：审计开关本身是防守能力缺口点；建议开启数据库审计并接入 SOC，对高危 SQL 模板（`SELECT * FROM` 全表、`DROP`/`DELETE` 无 WHERE 等）建立规则。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 审计缺失，SQL 行为不可见 |
| 防守者 | 数据库审计开启 + SOC 高危 SQL 规则 |

## 四、权限提升与持久化路径

- **账号创建持久化**：登录高权限账号后创建隐蔽新账号（`CREATE USER`），需授权内人工确认后评估。检测点：数据库审计账号 DDL。
- **慢日志/错误日志挖掘**：从日志中提取表结构、敏感查询与连接串。检测点：`DescribeSlowLogs` 等只读审计。
- **参数组篡改**：修改危险参数（如开启 `LOAD DATA LOCAL`、关闭 `skip_name_resolve` 等）扩大攻击面，破坏性，授权内人工确认后执行。检测点：CloudAudit 参数修改事件。
- **只读副本泄露**：只读副本配置遗漏导致数据外泄通道。检测点：实例创建/修改审计。

上述操作若涉及账号创建、参数修改或数据写入，一律标注「授权内人工确认后执行」。

## 五、防御与检测要点

核心审计事件清单（CloudAudit 操作审计，辅以数据库审计）：

- `CreateDBInstance` / `ModifyDBInstance` — 实例创建/修改
- `ModifyDBInstanceAccessWhiteList` — 访问白名单（公网）变更
- `ModifySecurityGroupPolicies` — 安全组规则变更
- `CreateAccounts` / `ModifyAccountPassword` — 账号创建/改密
- `DescribeBackups` / 备份下载 — 备份访问
- `ModifyBackupDownloadRestriction` — 备份下载限制变更
- `ModifyDBParameters` — 参数修改
- `RestartDBInstance` / `DestroyDBInstance` — 重启/销毁

防御建议：

1. 数据库默认关闭公网地址，如需访问走 VPN/专线或最小白名单。
2. 账号最小权限，禁用高权限账号的跨库与文件能力。
3. 备份下载启用网段限制并全程审计。
4. 安全组仅放行可信网段，杜绝 `0.0.0.0/0`。
5. 全面开启数据库审计并接入 SOC，覆盖高危 SQL 模板。
