# Serverless 函数权限与触发器滥用：事件注入、S3 触发链

> 定位：Serverless（AWS Lambda/Azure Functions/GCP Cloud Functions/阿里云函数计算/腾讯云 SCF）
> 把「入口」从 HTTP 扩散到事件源（对象存储、消息队列、定时器、流）。攻击面从「怎么调用函数」
> 变成「怎么让事件触发函数、事件里塞什么」。本手册梳理触发器滥用、事件注入与只读探测，
> 每条路径配检测侧对照。破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

Serverless 的攻击面 = 触发器面 + 函数权限面：

| 面 | 形态 | 风险 |
|---|---|---|
| 触发器面 | S3/OSS 事件、消息队列、定时器、API Gateway、流 | 事件注入、触发链越权 |
| 函数权限面 | 执行角色（IAM/服务角色）过宽 | 函数 → 云资源越权 |
| 调用面 | 未鉴权 HTTP 入口、公开触发器 | 未授权调用 |

事件注入的本质：如果函数信任事件负载里的字段（文件名、URL、消息体）而不校验归属，攻击者
就能通过可写的上游（如一个公开可写的桶）注入恶意负载，借函数的执行角色去读不该读的资源。

## 2. 暴露面探测（只读命令优先）

### 2.1 函数与触发器只读盘点

```bash
# AWS：列函数、看触发器映射（只读）
aws lambda list-functions --query 'Functions[].FunctionName'
aws lambda list-event-source-mappings --query 'EventSourceMappings[].{fn:FunctionArn,src:EventSourceArn}'
# 阿里云函数计算 / 腾讯云 SCF 对应 CLI 只读 list 命令
```

### 2.2 触发器上游可写性只读探测

```bash
# S3 桶是否公开可写（只读，不改动）
aws s3api get-bucket-acl --bucket <b> --query 'Grants[]'
aws s3api get-bucket-policy --bucket <b> 2>/dev/null
# 队列/流是否公开可写（只读）
aws sqs get-queue-attributes --queue-url <u> --attribute-names Policy 2>/dev/null
```

判定口径：触发源（桶/队列）`PutObject`/`SendMessage` 对匿名或低权主体开放 = 可注入事件；
结合函数执行角色权限判断注入后的放大面。

### 2.3 函数执行角色只读盘点

```bash
aws lambda get-function --function-name <f> --query 'Configuration.Role'
aws iam list-attached-role-policies --role-name <role>   # 读执行角色策略
aws iam get-role-policy --role-name <role> --policy-name <p>
```

判定口径：执行角色含 `s3:*`、`secretsmanager:*`、`dynamodb:*`、`iam:PassRole` 等即高危。

## 3. 缺陷与利用路径

### 3.1 S3/OSS 事件注入（信任文件名触发命令/SSRF）

- 缺陷：函数由对象存储事件触发，处理 `event.Records[].s3.object.key`（文件名/URL）时未
  校验归属与内容，文件名或对象内容被拼进命令/URL/路径。
- 验证命令（只读）：读函数代码逻辑（`aws lambda get-function` 拿代码位置，本地只读分析）；
  确认上游桶可写性（`get-bucket-acl`）。
- 影响：注入恶意对象触发函数，借函数执行角色读写内部资源、触发 SSRF 拉元数据。
- 检测侧：云审计记录函数调用（`Invoke`）与对象写入（`PutObject`）的时间关联；函数日志
  记录异常入参；异常调用源（匿名 PutObject → Invoke）是强信号。

### 3.2 触发器链越权（函数 A 触发函数 B 的敏感逻辑）

- 缺陷：事件源把低权域的写入映射到高权函数；或函数被多余的事件源绑定（一个本应私有的
  函数被公开队列触发）。
- 验证命令（只读）：`list-event-source-mappings` 列所有绑定，对照「哪些触发源本不该触发
  该函数」。
- 影响：绕过入口鉴权，直达函数内部逻辑。
- 检测侧：云审计记录事件源配置变更（`CreateEventSourceMapping`）与跨服务调用链；函数日志
  显示非预期触发源。

### 3.3 未鉴权 HTTP 入口 / 公开触发器

- 缺陷：API Gateway/HTTP 触发器的鉴权未开（IAM/Authorizer 缺失），函数可被匿名直接调用。
- 验证命令（只读）：读 API Gateway 资源策略与 Authorizer 配置；对入口做只读请求探测
  （`Invoke` 只读路径，避免触发破坏性逻辑）。
- 影响：绕过鉴权直接执行函数逻辑（可能含内部数据读写）。
- 检测侧：云审计记录 API 调用与函数 Invoke；API 访问日志（匿名主体 + 高频/异常路径）。

### 3.4 事件负载篡改（消息队列投毒）

- 缺陷：函数消费的消息队列可被低权主体写入，消息体（如订单 ID、用户 ID）被篡改导致越权
  读（IDOR 类）。
- 验证命令（只读）：读队列策略（`get-queue-attributes Policy`）确认可写主体；读函数消费
  逻辑判断是否信任消息字段。
- 影响：越权读其他租户数据、触发高危内部操作。
- 检测侧：云审计记录 `SendMessage` 与函数调用关联；消息审计（若开启）记录投毒主体；函数
  日志记录异常字段值。

### 3.5 死信/重试通道注入（消费失败路径被利用）

- 缺陷：函数的死信队列（DLQ）或重试策略可被低权主体写入，投毒消息反复触发函数，放大
  消费逻辑缺陷或造成资源消耗。
- 验证命令（只读）：读函数 DLQ/重试配置与队列策略；读消费逻辑判断对重试/死信消息的处理。
- 影响：利用重试放大注入面，或触发账单/资源滥用。
- 检测侧：云审计记录 DLQ 写入与函数调用关联；函数日志异常重试次数；消息审计。

## 4. 提权与持久化

- 提权链：公开桶注入 → 函数执行角色 → 读内部桶/密钥 → 横向；函数 `iam:PassRole` → 给新
  函数/资源挂高权角色。
- 持久化（授权内人工确认后执行）：创建定时触发器函数作为回调后门、在函数环境变量写持久
  凭证、给函数追加新事件源；逐项登记 `environment-restore.md`，删除类只出清单由用户执行。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 事件注入 | 云审计 `PutObject` + `Invoke` 时间关联；函数日志异常入参 |
| 触发器配置篡改 | 云审计 `CreateEventSourceMapping`/`UpdateEventSourceMapping`/`AddPermission` |
| 匿名调用函数 | 云审计 `Invoke` + 匿名/异常主体；API 访问日志 |
| 越权读数据 | 函数日志 + 云审计资源读事件 + 消息审计 |
| 执行角色越权 | 云审计以执行角色主体发起的资源操作 |

### 5.2 加固要点

- 函数入口显式鉴权（IAM/Authorizer/签名）；私有函数禁公开触发源。
- 事件负载做归属校验（校验桶归属、签名、白名单）与内容校验；不信任文件名/消息字段。
- 执行角色最小权限；按函数隔离角色，避免「一函数一高权角色」扩散。
- 触发源可写性收敛（桶/队列私有 + 跨账号授权收紧）；开启函数并发/超时/账单告警。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 公开函数/触发器未鉴权调用 | T1190 Exploit Public-Facing Application |
| 云存储数据窃取 | T1530 Data from Cloud Storage |
| 复用函数执行角色 | T1078 Valid Accounts |
| 事件注入触发函数 | T1204 User Execution |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 触发源可写性、函数执行角色权限清单登记 cloud-assets.md。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| 函数与触发器 | `list-functions` / `list-event-source-mappings` |
| 触发源可写性 | `get-bucket-acl`/`get-bucket-policy`、队列 Policy |
| 执行角色策略 | `list-attached-role-policies` |
