# 云函数特有持久化

> 定位：Serverless 的持久化与主机不同——没有常驻进程，但可以通过触发器、函数代码、环境
> 变量、事件源、版本别名等「无服务器」方式留下长驻后门。本手册梳理云函数特有的持久化面、
> 只读探测与检测侧对照。持久化类操作均为变更性，标「授权内人工确认后执行」。

## 1. 攻击面

云函数持久化的特征面：

| 面 | 形态 | 隐蔽性成因 |
|---|---|---|
| 触发器持久化 | 定时触发器、事件源绑定作为回调 | 无长驻进程，难用进程列表发现 |
| 代码持久化 | 函数代码内后门、Layer 后门 | 与业务代码混在一起 |
| 凭证持久化 | 环境变量/参数里写死凭证 | 静态凭证不随实例销毁 |
| 身份持久化 | 额外执行角色、跨账号信任 | 权限残留 |
| 版本/别名 | 旧版本保留后门、别名漂移 | 审计只看 latest 漏掉历史版本 |

核心差异：主机后门看进程/端口/计划任务，云函数后门要看「配置面」（触发器、环境变量、
版本、角色），检测思路完全不同。

## 2. 暴露面探测（只读命令优先）

### 2.1 触发器与事件源只读盘点（找回调后门）

```bash
aws lambda list-event-source-mappings --query 'EventSourceMappings[].{fn:FunctionArn,src:EventSourceArn}'
aws events list-rules --query 'Rules[].{name:Name,state:State,schedule:ScheduleExpression}'  # 定时规则
aws lambda list-functions --query 'Functions[].FunctionName'   # 全量函数（找陌生函数）
```

判定口径：出现陌生函数、陌生定时规则、函数被多余事件源绑定 = 持久化候选；与基线快照
（`cloud-assets.md` 基线登记）比对。

### 2.2 环境变量与参数只读盘点（找凭证后门）

```bash
aws lambda get-function-configuration --function-name <f> --query 'Environment.Variables'
```

判定口径：环境变量出现攻击者可控的密钥/回调地址/令牌 = 凭证持久化。

### 2.3 版本与别名只读盘点（找历史后门）

```bash
aws lambda list-versions-by-function --function-name <f> --query 'Versions[].Version'
aws lambda list-aliases --function-name <f> --query 'Aliases[].{name:Name,version:FunctionVersion}'
```

判定口径：存在大量历史版本或别名指向非 `$LATEST` = 版本漂移/旧后门残留；别名被改指向
含后门版本。

### 2.4 执行角色与跨账号信任只读盘点

```bash
aws lambda get-function --function-name <f> --query 'Configuration.Role'
aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument'  # 看信任主体
```

判定口径：执行角色信任策略含异常外部账号/主体 = 身份持久化。

## 3. 缺陷与利用路径

### 3.1 定时触发器回调后门

- 缺陷：攻击者创建 CloudWatch Events/EventBridge 定时规则周期性触发后门函数（拉取命令/
  回连），无长驻进程。
- 验证命令（只读）：`events list-rules` + 规则目标（`list-targets-by-rule`）看指向哪个函数；
  与基线比对发现新增规则。
- 影响：周期性回连、数据外传、命令执行。
- 检测侧：云审计记录 `PutRule`/`PutTargets`/`PutPermission`；函数 Invoke 日志（定时触发）；
  规则创建/修改告警。

### 3.2 事件源绑定追加（扩触发面）

- 缺陷：给已有高权函数追加公开事件源（S3/SQS）作为隐蔽入口，绕过原鉴权。
- 验证命令（只读）：`list-event-source-mappings` 找函数的多余绑定。
- 影响：通过公开桶/队列间接调用私有函数。
- 检测侧：云审计 `CreateEventSourceMapping`；函数日志显示非预期触发源；跨服务调用链告警。

### 3.3 环境变量 / 参数凭证后门

- 缺陷：在函数环境变量或配置参数里写入攻击者凭证，实现「静态凭证」持久化（不依赖实例）。
- 验证命令（只读）：`get-function-configuration` 读环境变量找异常凭证。
- 影响：凭证长期可复用，函数删了凭证还在（若未轮换）。
- 检测侧：云审计 `UpdateFunctionConfiguration`（Environment 变更）；凭证使用审计；secret
  scanning。

### 3.4 旧版本 / 别名后门残留

- 缺陷：后门注入历史版本后，别名漂移指向它，或回滚时又激活旧后门；审计只看 latest 会漏。
- 验证命令（只读）：`list-versions-by-function` + `list-aliases` 看版本树与别名指向。
- 影响：干净版本部署后，后门仍可从旧版本/别名复活。
- 检测侧：云审计 `PublishVersion`/`UpdateAlias`；版本与别名变更告警；部署历史比对。

### 3.5 执行角色 / 跨账号信任持久化

- 缺陷：给函数执行角色追加攻击者账号作为信任主体，或 `iam:PassRole` 留后门，实现长期
  跨账号访问。
- 验证命令（只读）：`get-role` 读 AssumeRolePolicyDocument 看信任主体。
- 影响：攻击者账号可持续 AssumeRole 进目标云账号。
- 检测侧：云审计 `UpdateAssumeRolePolicy`/`CreateRole`/`PutRolePolicy`；信任策略变更告警。

### 3.6 并发/超时/账单滥用（资源型持久化与 DoS）

- 缺陷：攻击者借公开触发源高频调用函数，制造账单放大或占满并发，掩盖真实后门流量。
- 验证命令（只读）：读函数并发/超时/账单配置与近期调用指标（只读查询，不改动）。
- 影响：账单滥用 + 告警噪声掩护持久化。
- 检测侧：云审计记录高频 Invoke 与账单异常；函数并发/错误率告警；触发源可写性审计。

## 4. 提权与持久化

- 本手册即持久化专题；提权链见 `01-function-permission-trigger-abuse.md`（执行角色放大）。
- 所有持久化落地均为变更性操作：**授权内人工确认后执行**，逐项登记 `environment-restore.md`
  与 `lateral-persistence.md`，终态三选一（执行/未执行/不适用）禁留空；删除类只出清单由
  用户确认后执行。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 定时后门 | 云审计 `PutRule`/`PutTargets` + 函数 Invoke（定时触发） |
| 追加事件源 | 云审计 `CreateEventSourceMapping`/`AddPermission` |
| 凭证后门 | 云审计 `UpdateFunctionConfiguration`（Environment 变更）+ secret scanning |
| 版本/别名后门 | 云审计 `PublishVersion`/`UpdateAlias` |
| 信任策略后门 | 云审计 `UpdateAssumeRolePolicy`/`PutRolePolicy` |

### 5.2 加固要点

- 触发器/事件源/函数/角色纳入基线快照，变更告警 + 定期对账。
- 环境变量禁写长期凭证；凭证集中管理 + 短生命周期 + 轮换。
- 版本生命周期管理：清理历史版本，别名锁定 + 变更审计。
- 执行角色信任策略最小化 + 变更告警；开启函数配置项变更的云审计告警。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 创建后门身份/角色 | T1136 Create Account |
| 配置/绑定篡改 | T1098 Account Manipulation |
| 定时回调后门 | T1053 Scheduled Task/Job |
| 函数/宿主持久化 | T1543 Create or Modify System Process |

## 7. 证据记录要点

- 持久化项逐条落 lateral-persistence.md，终态三选一（执行/未执行/不适用）禁留空。
- 触发器/函数/角色纳入基线快照，变更与基线对账。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式；删除类只出清单由用户执行。
