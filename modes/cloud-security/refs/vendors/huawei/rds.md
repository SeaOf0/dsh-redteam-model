# 华为云 RDS 云数据库攻防

> 定位：围绕 MySQL/PostgreSQL/SQL Server/GaussDB 四类引擎的公网访问、安全组、白名单、
> 弱口令、备份与审计六类攻击面，给出只读优先的探测命令与配置缺陷利用路径。工具以
> `hcloud rds` 与数据库客户端为主，写操作统一标注「授权内人工确认后执行」。每条路径配
> 检测侧对照（CTS 事件名 + 数据库审计/慢日志）。身份凭证见 `./iam.md`，网络见 `./network.md`。

## 一、攻击面

RDS 是托管数据库服务，攻击面围绕「数据库实例如何被访问」与「数据如何被保护」：

- 公网访问：实例误开公网 IP，数据库端口直接暴露互联网。
- 安全组：入方向放行 3306/5432/1433/8635 到 `0.0.0.0/0`。
- 白名单缺失：未配置访问白名单（IP 白名单/安全组），任意地址可连接。
- 弱口令：数据库账号弱口令/默认口令，配合公网暴露即被爆破。
- 备份：备份未加密、备份存储公开、备份下载链接泄露。
- 审计与监控：数据库审计、慢日志、错误日志未开启，攻击行为不可见。

四要素落点：身份（数据库账号/主账号 AK/SK）→ 权限（账号权限与实例操作权限）→ 资源（实例/
库表/备份）→ 影响（脱库、写入后门、备份窃取）。

## 二、信息收集 / 暴露面探测

以下命令只读，用于枚举 RDS 实例、网络暴露与账号配置。

### 2.1 实例清单枚举

```bash
# 列出全部 RDS 实例（实例 ID、引擎、版本、规格、状态、内网地址）
hcloud rds list-instances

# 查看单个实例详情（公网 IP、安全组、端口、备份策略、参数组）
hcloud rds show-instance --instance-id <instance_id>
```

### 2.2 网络暴露探测（只读）

```bash
# 从实例详情提取公网 IP 与端口，再只读验证端口连通性
hcloud rds show-instance --instance-id <instance_id> | grep -iE 'public|port'
nc -zv <public_ip> 3306 5432 1433 8635 2>&1
```

说明：端口连通性探测仅对授权目标、逐端口限速执行，不做口令爆破。

### 2.3 参数组与账号只读枚举

```bash
# 列出实例关联的参数组（判断审计/日志相关参数是否开启）
hcloud rds list-configurations --instance-id <instance_id> 2>/dev/null

# 查看实例已配置的数据库账号列表（只读，需实例管理权限）
hcloud rds list-database-users --instance-id <instance_id> 2>/dev/null
```

### 2.4 备份与日志状态

```bash
# 查看备份策略与最近备份（判断是否加密、保留周期）
hcloud rds list-backups --instance-id <instance_id> 2>/dev/null
hcloud rds show-backup-policy --instance-id <instance_id> 2>/dev/null
```

## 三、常见配置缺陷与利用路径

### 3.1 公网访问开启 + 弱口令

- 缺陷描述：实例开启公网 IP 且数据库账号使用弱口令/默认口令，攻击者可直接从公网爆破登录，
  是最常见的数据库沦陷路径。
- 验证命令（只读优先）：

```bash
# 只读确认实例是否开启公网 IP 及端口
hcloud rds show-instance --instance-id <instance_id> | grep -iE 'public|port'
# 连通性验证（只读，不携带口令）
nc -zv <public_ip> 3306 2>&1
# 口令强度验证仅对授权账号做单次登录测试，禁止批量爆破
mysql -h <public_ip> -P 3306 -u <user> -p'<password>' -e 'select version();' 2>&1
```

- 影响：弱口令被爆破后直接读库/脱库、写入后门、提权到系统（UDF/扩展，视引擎而定）。
- 检测侧建议：CTS 事件 `createInstance` 记录公网开启配置；数据库侧依赖数据库审计（开启后
  记录登录成败、SQL）；未开审计则爆破与脱库行为不可见，检测缺口明确。

### 3.2 安全组放行数据库端口到全网

- 缺陷描述：安全组入方向将 3306/5432/1433/8635 对 `0.0.0.0/0` 放行，数据库虽「有口令」
  但仍全网可达，成为爆破与已知 CVE 利用的入口。
- 验证命令（只读）：

```bash
hcloud rds show-instance --instance-id <instance_id> | grep -iE 'security_group'
hcloud vpc list-security-group-rules --security-group-id <sg_id> | grep -E '3306|5432|1433|8635'
```

- 影响：全网可达的数据库端口放大爆破面，结合版本已知漏洞可直接利用。
- 检测侧建议：CTS 事件 `createSecurityGroupRule`、`updateSecurityGroup` 记录规则变更；异常
  登录与 SQL 由数据库审计记录，未开启即检测缺口。

### 3.3 访问白名单缺失

- 缺陷描述：实例未配置 IP 白名单（或白名单过宽如 `0.0.0.0/0`），任意地址均可尝试连接，
  白名单本应是最外层的第一道闸门。
- 验证命令（只读）：

```bash
# 查看实例是否配置了访问白名单（只读）
hcloud rds show-instance --instance-id <instance_id> | grep -iE 'whitelist|allow'
# 从非授权地址发起连接测试（只验证是否被拒，属授权探测）
nc -zv <public_ip> 3306 2>&1
```

- 影响：无白名单时，爆破、凭据填充、漏洞利用均无地址限制，攻击面最大化。
- 检测侧建议：CTS 事件 `updateInstance`（白名单变更）留痕；白名单为空属配置态，需配置合规
  （SA）巡检发现，检测缺口在配置态。

### 3.4 备份未加密或备份下载链接泄露

- 缺陷描述：备份未开启加密，或备份下载链接（临时 URL）被泄露/复用，攻击者拿到备份即可
  离线还原数据库全量数据。
- 验证命令（只读）：

```bash
# 查看备份策略是否加密、备份保留周期（只读）
hcloud rds show-backup-policy --instance-id <instance_id>
# 列出备份清单与状态（只读）
hcloud rds list-backups --instance-id <instance_id>
```

- 影响：备份是数据的完整副本，泄露即等于全库泄露，且离线脱库难以被实时检测发现。
- 检测侧建议：CTS 事件 `createBackup`、`restoreInstance` 记录备份与恢复；备份下载数据面行为
  需开启操作审计，未开启即检测缺口。

### 3.5 数据库审计与慢日志未开启

- 缺陷描述：数据库审计、慢日志、错误日志未开启，攻击者登录与数据导出行为无记录，事后取证
  与实时告警均缺失。
- 验证命令（只读）：

```bash
# 查看实例审计与日志相关配置（只读）
hcloud rds show-instance --instance-id <instance_id> | grep -iE 'audit|log'
hcloud rds list-configurations --instance-id <instance_id> 2>/dev/null
```

- 影响：数据面行为（SELECT 大量数据、导出、写入后门）不可见，检测完全依赖控制面事件。
- 检测侧建议：数据库审计开启后记录登录与 SQL 事件；审计未开启即核心检测缺口，需在开工阶段
  显式登记为 gap。

### 3.6 GaussDB 配置缺陷（以 GaussDB(for MySQL) 为例）

- 缺陷描述：GaussDB 引擎的默认账号权限、参数组（如审计参数、SSL 连接）配置不当，或误开
  公网访问，形成与开源引擎类似的暴露面。
- 验证命令（只读）：

```bash
# 列出 GaussDB 实例与参数组（只读）
hcloud rds list-instances | grep -i gauss
hcloud rds list-configurations --instance-id <instance_id> 2>/dev/null
# 只读验证端口连通性
nc -zv <public_ip> 8635 2>&1
```

- 影响：GaussDB 参数组未开审计/SSL 时，连接与 SQL 明文不可审计，泄露与篡改风险并存。
- 检测侧建议：CTS 事件 `createInstance`、`updateInstance`（参数组变更）留痕；SQL 层依赖数据库
  审计，未开启即检测缺口。

## 四、权限提升与持久化路径

- 账号提权：低权限数据库账号利用引擎特性（MySQL UDF、PostgreSQL 扩展、SQL Server xp_cmdshell）
  尝试提权到系统——仅作授权内评估，不提供完整利用脚本。
- 跨库横向：从已沦陷实例的配置/日志中提取连接串，横向连接其他 RDS/内网数据库。
- 持久化方式：创建高权限后门账号、写定时任务/存储过程、利用备份恢复植入。以上写操作均属
  「授权内人工确认后执行」，本文不提供脚本。
- 数据面盲区：后门账号创建、数据导出属数据库层操作，CTS 不记录，依赖数据库审计。

## 五、防御与检测要点

| 层 | 关键动作 | 审计/监控事件 |
|---|---|---|
| 实例生命周期 | 创建/删除/变更实例 | `createInstance`、`deleteInstance`、`updateInstance` |
| 网络暴露 | 公网开启/白名单/安全组变更 | `updateInstance`、`createSecurityGroupRule`、`updateSecurityGroup` |
| 备份 | 备份创建/恢复/下载 | `createBackup`、`restoreInstance`、`downloadBackup` |
| 数据库数据面 | 登录成败、SQL、导出 | 数据库审计（非 CTS，需显式开启） |
| 性能/异常 | 慢查询、连接数异常 | 慢日志、CES 指标（非 CTS） |

防御建议：

- 默认关闭公网访问，确需公网走 VPN/专线或白名单收敛。
- 安全组数据库端口仅放行应用服务器网段，杜绝 `0.0.0.0/0`。
- 强口令 + 定期轮换，禁用默认账号，账号最小权限。
- 开启数据库审计并投递 SIEM，补齐数据面盲区（核心缺口）。
- 备份加密（KMS）与访问控制，下载链接短时有效且审计。
- 开启慢日志与 CES 告警，监控异常连接与批量导出。

## 审计事件名清单（本节汇总）

`createInstance`、`deleteInstance`、`updateInstance`、`createBackup`、`restoreInstance`、
`downloadBackup`、`createSecurityGroupRule`、`updateSecurityGroup`。
