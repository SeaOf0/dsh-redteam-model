# RDS 云数据库攻防

本文覆盖阿里云 RDS 云数据库（MySQL/PostgreSQL/SQL Server）在授权评估中的攻击面、暴露面探测、常见配置缺陷与利用路径、权限提升与持久化，以及对应检测要点。所有命令以只读探测为优先，破坏性操作须在授权范围内人工确认后执行。

## 一、攻击面

RDS 的攻击面集中于网络暴露、访问控制与数据通道：

- **公网访问地址**：开启公网访问后，实例获得公网 IP，若配合弱口令即成为直接入口。
- **白名单 IP**：白名单设为 `0.0.0.0/0` 或过宽，放行任意连接。
- **账号与口令**：弱口令、默认账号、多实例复用口令。
- **数据库引擎与版本**：老版本引擎存在已知漏洞，未及时升级。
- **只读实例 / 灾备实例**：常被忽视的副本节点同样暴露数据。
- **备份与恢复**：备份文件可下载、跨地域恢复权限过大。
- **审计与加密**：SQL 审计、TDE 未开启，攻击行为与数据落盘不可追溯。

## 二、信息收集 / 暴露面探测

已获得 AK 后，用只读命令摸清 RDS 实例、网络与账号情况。

```bash
# 列出全部 RDS 实例（含引擎、版本、状态、公网地址）
aliyun rds DescribeDBInstances --RegionId cn-hangzhou

# 查看实例详情（白名单、网络类型、主备、存储加密等）
aliyun rds DescribeDBInstanceAttribute --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou

# 查看实例网络与公网连接信息（公网地址、端口）
aliyun rds DescribeDBInstanceNetInfo --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou

# 查看白名单（识别 0.0.0.0/0 或过宽网段）
aliyun rds DescribeDBInstanceIPArrayList --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou

# 列出数据库账号
aliyun rds DescribeAccounts --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou

# 查看实例高可用/只读/灾备配置（识别被忽视的副本节点）
aliyun rds DescribeDBInstanceHAConfig --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou

# 查看 SSL 连接配置（是否强制加密传输）
aliyun rds DescribeDBInstanceSSL --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou

# 查看备份策略与保留周期
aliyun rds DescribeBackupPolicy --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
```

常见引擎默认端口（用于端口连通性确认）：MySQL `3306`、PostgreSQL `5432`、SQL Server `1433`、MariaDB `3306`。

对外部暴露的数据库端口做只读连通性探测（仅确认端口开放，不做口令爆破）：

```bash
nc -zv <rds-public-ip> 3306   # MySQL
nc -zv <rds-public-ip> 5432   # PostgreSQL
nc -zv <rds-public-ip> 1433   # SQL Server
```

## 三、常见配置缺陷与利用路径

### 3.1 公网访问开启且白名单过宽

**缺陷描述**：实例开启公网访问，且白名单为 `0.0.0.0/0` 或覆盖过大网段，数据库直接暴露于公网。

**验证命令（只读优先）**：

```bash
aliyun rds DescribeDBInstanceNetInfo --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
# 关注 ConnectionString 是否含公网地址

aliyun rds DescribeDBInstanceIPArrayList --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
# 关注 SecurityIPList 是否为 0.0.0.0/0
```

**影响**：公网暴露 + 弱口令/已知漏洞即可被远程利用；即便口令未知，也会成为爆破与扫描目标。

**检测侧建议**：RDS 审计日志记录连接方与失败登录；ActionTrail 记录 `AllocateInstancePublicConnection`、`ModifySecurityIps` 等变更事件。防守方可对「公网连接 + 陌生 IP + 高频失败登录」告警。

### 3.2 弱口令与高权限账号

**缺陷描述**：账号使用弱口令、默认口令，或业务账号被授予过高权限（如 DDL、系统表、复制权限）。

**验证命令（只读优先）**：

```bash
aliyun rds DescribeAccounts --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
# 查看账号列表与权限类型（高权限账号/普通账号）
```

**影响**：口令失陷后可直接读写全库数据；高权限账号可进一步执行系统级操作或拖库。

**检测侧建议**：RDS 审计日志可记录登录成功/失败、SQL 执行；云监控可对连接数激增、CPU 异常告警。防守方应强制强口令与最小权限账号体系。

### 3.3 备份文件可公开下载

**缺陷描述**：备份策略允许手动/自动备份落盘到可公开访问位置，或备份下载权限未做隔离，导致备份文件（内含全量数据）被越权获取。

**验证命令（只读优先）**：

```bash
# 查看备份列表（识别备份频率与保留策略）
aliyun rds DescribeBackups --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
```

**影响**：备份是完整数据副本，一旦被下载即造成整库数据泄漏，且通常不在应用侧监控范围内。

**检测侧建议**：ActionTrail 记录 `CreateBackup`、`DownloadBackup`、`DescribeBackups`；OSS 访问日志可记录备份文件下载。防守方应限制备份下载权限并对下载事件告警。

### 3.4 审计日志与加密未开启

**缺陷描述**：SQL 审计、TDE 存储加密未开启，攻击行为无法还原、数据落盘明文，事后取证与合规均受影响。

**验证命令（只读优先）**：

```bash
aliyun rds DescribeDBInstanceAttribute --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
# 关注 TDE、审计相关字段状态
```

**影响**：拖库、篡改等行为无审计痕迹，增加检测与溯源难度；明文落盘扩大物理介质风险。

**检测侧建议**：优先在控制面强制开启审计与加密；审计开启后，RDS 审计日志成为关键检测源，配合 ActionTrail 的 `ModifyDBInstanceTDE`、`ModifySQLCollectorPolicy` 等事件监控配置漂移。

### 3.5 只读实例与灾备实例被忽视

**缺陷描述**：主实例配置了只读实例、灾备实例或跨地域备份，但这些副本节点的访问控制与审计往往弱于主实例，且常被资产盘点遗漏。

**验证命令（只读优先）**：

```bash
aliyun rds DescribeDBInstanceHAConfig --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
# 查看只读/灾备节点与同步拓扑

aliyun rds DescribeDBInstances --RegionId cn-hangzhou
# 核对是否遗漏了只读/灾备实例及其公网暴露
```

**影响**：副本实例承载与主库一致的数据，一旦副本暴露且防护较弱，数据同样可被拖取，且可能绕过仅针对主库的监控。

**检测侧建议**：ActionTrail 记录副本创建事件（如 `CreateReadOnlyDBInstance`、`CreateDBInstance`）；防守方应将只读/灾备实例统一纳入暴露面与审计范围，避免监控盲区。

### 3.6 数据库引擎版本过旧

**缺陷描述**：实例使用已停止维护或存在已知漏洞的引擎小版本，未及时升级，存在可被远程利用的公开漏洞面。

**验证命令（只读优先）**：

```bash
aliyun rds DescribeDBInstanceAttribute --DBInstanceId rm-xxxxxxxx --RegionId cn-hangzhou
# 关注 Engine 与 EngineVersion 字段，比对已知漏洞范围
```

**影响**：老版本引擎可能直接暴露认证绕过、越权读写等风险，扩大初始入口面。

**检测侧建议**：云监控可对实例版本升级状态告警；ActionTrail 记录 `UpgradeDBInstanceEngineVersion`；防守方应建立版本生命周期管理，定期核查并升级。

## 四、权限提升与持久化路径

- **数据库账号 → 实例内高权限**：低权限账号通过引擎特性（如 MySQL 用户定义函数、存储过程链）尝试提升，仅在授权范围内最小化验证，不写完整提权脚本。
- **跨实例横向**：同白名单网段内多实例，攻破一台后复用口令横向到其它实例。
- **备份窃取持久化**：通过备份下载获取全量数据，实现数据侧长期驻留。
- **账号持久化**：具备高权限账号时创建影子账号或保留后门账号（须授权内人工确认后执行，避免破坏业务）。
- **只读副本滥用**：向只读实例或灾备实例同步恶意数据或读取主库同步数据，扩大影响面。

## 五、防御与检测要点

审计日志事件名清单（ActionTrail + RDS 审计日志）：

| 事件名 | 含义 | 风险提示 |
| --- | --- | --- |
| `CreateDBInstance` | 创建实例 | 关注非授权创建 |
| `AllocateInstancePublicConnection` | 开通公网连接 | 公网暴露入口 |
| `ModifySecurityIps` | 修改白名单 | 关注设为 0.0.0.0/0 |
| `ModifyDBInstanceNetworkType` | 变更网络类型 | 关注公网切换 |
| `CreateAccount` / `ModifyAccountPrivilege` | 创建/改账号权限 | 关注影子账号与提权 |
| `CreateBackup` / `DownloadBackup` | 备份/下载 | 数据外带风险 |
| `ModifyDBInstanceTDE` | 修改 TDE | 关注加密被关闭 |
| `CreateReadOnlyDBInstance` | 创建只读实例 | 副本数据面扩大 |
| `UpgradeDBInstanceEngineVersion` | 升级引擎版本 | 关注拖延升级 |
| `ModifySQLCollectorPolicy` | 修改审计采集 | 关注审计被关闭 |
| `DescribeDBInstances` | 枚举实例 | 侦察指标 |

防御建议：

- 默认关闭公网访问，确需访问走跳板机或 VPC 私网；白名单最小化。
- 强制强口令、MFA 化的控制台与 SDK 访问，账号最小权限。
- 开启 SQL 审计与 TDE，备份下载权限隔离并告警。
- 在云监控配置连接数、CPU、异常登录告警；ActionTrail 关注白名单与网络类型变更。
