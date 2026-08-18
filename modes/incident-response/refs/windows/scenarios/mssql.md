# MSSQL 事件排查（数据库失陷专项）

> 正文自写原创，命令与判据自写，来源链接见文末。
> 适用：MSSQL 弱口令/`sa` 失陷、`xp_cmdshell` 利用、触发器后门、数据库数据外带。SQL Server 既是服务也是「执行引擎」——排查要**双线**：OS 进程线 + 数据库内部线。

## 1. 排查主线

```
登录证据（谁从哪连进来）→ 权限与配置变更（xp_cmdshell/扩展过程）→ OS 执行链（sqlservr 拉起子进程）→ 库内后门（触发器/账户/任务）→ 数据外带评估
```

## 2. 登录证据（ERRORLOG 为纲）

```bat
:: 登录失败/成功：18456 失败（含原因码）、18454 成功（含来源 IP）
findstr /C:"Login failed" /C:"Login succeeded" "C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG*"
```

- 可疑判据：外部/非常规内网 IP 的成功登录（18454 行尾 `... from <IP>`）；爆破样态（同 IP 连续 18456 后接 18454）；`sa` 在非运维时段登录；Windows 认证账户被陌生主机使用。
- 客户端侧：`C:\Program Files\Microsoft SQL Server\*\Tools\Bin\netstat` 不必——服务端 ERRORLOG 已含来源；1433 端口的防火墙日志交叉。

## 3. 权限与配置变更（xp_cmdshell 启用链）

```sql
-- 服务器上执行（用现有合法客户端连接只读查询）
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';        -- 当前值+最近修改时间线入口
SELECT create_date, modify_date, name FROM sys.sql_modules m JOIN sys.objects o ON o.object_id=m.object_id
 WHERE o.type IN ('P','X') AND m.definition LIKE '%xp_cmdshell%';   -- 谁的存储过程碰了它
SELECT name, create_date, modify_date FROM sys.objects WHERE is_ms_shipped = 0 ORDER BY modify_date DESC; -- 近期新建/改动的对象
```

```bat
:: ERRORLOG 里的配置变更记录（sp_configure/xp_cmdshell 字样）
findstr /C:"xp_cmdshell" /C:"Configuration option" "C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG*"
```

- 可疑判据：`xp_cmdshell` 处于 1（默认 0）且启用时间在失陷窗内；`sp_configure 'Ole Automation Procedures'`/`Ad Hoc Distributed Queries` 被顺手打开（外带/下载用）。

## 4. OS 执行链（sqlservr 拉起子进程）

```powershell
# sqlservr.exe 作父进程的命令执行（4688）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 10000 |
  Where-Object {$_.Message -match 'sqlservr.exe'} | Select TimeCreated,Message -First 30
```

- 可疑判据：`sqlservr.exe → cmd.exe/powershell.exe`（xp_cmdshell 直接特征）；子进程命令行含 `net user`/下载器/添加账户/开 RDP（`REG ADD ... fDenyTSConnections=0`）；执行账户为 SQL 服务账户（`NT SERVICE\MSSQLSERVER`）。
- 落地文件：服务账户的 TEMP（`C:\Users\MSSQL$<实例>\AppData\Local\Temp` 或 `C:\Windows\Temp`）按时间窗扫。

## 5. 库内后门（触发器/账户/任务）

```sql
-- 触发器后门：DDL/DML 触发器里藏执行逻辑
SELECT t.name, t.type_desc, t.create_date, t.modify_date, m.definition
  FROM sys.triggers t JOIN sys.sql_modules m ON t.object_id = m.object_id
  WHERE m.definition LIKE '%xp_cmdshell%' OR m.definition LIKE '%sp_OA%' OR m.definition LIKE '%OPENROWSET%';
-- 新增登录/账户与角色变更
SELECT name, create_date, modify_date FROM sys.sql_logins ORDER BY create_date DESC;
SELECT name, type_desc, create_date FROM sys.server_principals WHERE type IN ('S','U') AND is_disabled = 0;
-- SQL Agent 任务被用作持久化
SELECT j.name, j.date_created, j.date_modified, s.command
  FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id
  WHERE j.date_created > DATEADD(day,-30,GETDATE()) OR s.command LIKE '%xp_cmdshell%';
```

- 可疑判据：业务库表上出现访问时间异常的 INSERT/UPDATE 触发器且定义含系统过程调用；新登录账户/提权成员；Agent 任务命令行藏 payload（无计划的「定时复活」）。

## 6. 数据外带评估

- `BACKUP`/`BCP` 痕迹：ERRORLOG 里的 backup 命令、`msdb.dbo.backupset` 历史表（异常时间的全量/日志备份=外带前置）；`BCP`/`OPENROWSET` 出现在 4688 命令行。
- 评估口径：能接触的库/表范围 × 时间窗内的导出动作 → 「哪些数据类别可能已外带」三档结论（已外带/可能/无证据），登记 evidence-index。

## 7. 收尾

- 入口定性后：持久化全表（含服务/触发器两线）、横向还原（该服务账户的 Type 3 登录散布）、改密与加固建议（关 xp_cmdshell、限登录来源、强口令）进处置清单。

## 来源

- https://book.noptrace.com/
- MSSQL 攻击面（MITRE T1505.003 SQL Stored Procedures / T1078.004）；sqlserver killer 思路：https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/SQL%20Injection%20MSSQL.md
