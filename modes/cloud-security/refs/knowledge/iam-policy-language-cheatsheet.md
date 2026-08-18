# IAM/权限策略语言速查（AWS IAM / Azure RBAC / GCP IAM / 阿里云 RAM）

> 定位：知识索引手册。四厂商权限策略语法对比 + 常见过宽权限模式清单，用于权限链收口
> （C4）与「过宽权限」类配置缺陷的判定——一条提权链/过宽权限要在报告里写清策略名、
> 动作、资源与效果，本表提供判定语言。只写授权测试与检测知识，不含攻击载荷。

## 1. 四厂商策略模型对比

| 维度 | AWS IAM | Azure RBAC | GCP IAM | 阿里云 RAM |
|---|---|---|---|---|
| 主体 | IAM 用户/角色/组 | 用户/组/服务主体/托管身份 | 用户/组/服务账号 | RAM 用户/角色/组 |
| 授权载体 | 策略（Policy，JSON） | 角色（Role）+ 角色分配（Assignment） | 策略绑定（Policy Binding） | 策略（Policy，JSON） |
| 最小单元 | 身份策略/资源策略/Session 策略 | 内建角色/自定义角色 | 预定义角色/自定义角色 | 系统策略/自定义策略 |
| 效果 | Allow/Deny | Allow/Deny（Deny 优先） | allow（Deny 靠条件） | Allow/Deny |
| 判定模型 | 显式 Deny > Allow；身份+资源+边界/Session 取交集 | Deny > Allow（分配范围生效） | 并集 allow；条件可拒绝 | 显式 Deny > Allow |
| 资源范围 | ARN | 订阅/资源组/资源 | 资源全路径 | 资源 ARN |
| 条件 | Condition 键 | 分配范围（scope） | 条件（condition，CEL） | Condition |

## 2. AWS IAM Policy 语法

**结构**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::example-bucket/*"],
      "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxxx"}}
    }
  ]
}
```

| 元素 | 说明 |
|---|---|
| `Effect` | Allow / Deny |
| `Action` | 服务:动作（通配 `*`、前缀 `s3:*`） |
| `Resource` | ARN 或 `*` |
| `Condition` | 条件键（`aws:*` 全局、`s3:*` 服务级；算子 StringEquals/ArnEquals/IpAddress 等） |
| 身份/资源/Session/边界策略 | 四类取交集，任一 Deny 即拒绝 |

**常见危险写法**：`"Action": "*"` + `"Resource": "*"`（完全管理员级）；`s3:*` 全域；
`iam:*`（可自建密钥提权）；`sts:AssumeRole` 无 `Condition` 限制信任方。

## 3. Azure RBAC 语法

**模型**：安全主体（主体）→ 角色（role definition）→ 范围（scope：管理组/订阅/资源组/资源）。

| 元素 | 说明 |
|---|---|
| 角色定义 | 内建（Contributor/Owner/Reader）或自定义（`actions`/`notActions`/`dataActions`） |
| 角色分配 | `az role assignment create --assignee <sp> --role <Role> --scope <scope>` |
| `actions` | 控制面操作（`Microsoft.Storage/*`、`*/read`） |
| `dataActions` | 数据面操作（`Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`） |
| 范围 | 订阅/资源组/资源/管理组 |
| Deny 优先 | DenyAssignment 优先于 Allow |

**常见危险模式**：`Owner` 或 `Contributor` 分配过宽范围（订阅级）；`*/read` + 数据面
`.../blobs/*`（可读全部对象）；服务主体持有 `Microsoft.Authorization/roleAssignments/write`
（可自我提权）；SPN 长期有效密钥未轮换。

## 4. GCP IAM 语法

**模型**：成员（member）→ 角色（role）→ 资源（resource）的绑定（Binding）；角色分
预定义（`roles/...`）、基本（`roles/editor`/`viewer`/`owner`）、自定义。

| 元素 | 说明 |
|---|---|
| member | `user:` / `group:` / `serviceAccount:` / `domain:` / `allAuthenticatedUsers` / `allUsers` |
| 角色 | `roles/storage.objectViewer` 等预定义；`roles/owner` 等基本角色 |
| 绑定 | `gcloud projects get-iam-policy <p>` 查看；`set-iam-policy` 变更 |
| 条件 | IAM Conditions（CEL 表达式，如按时间/资源属性限制） |
| 资源层级 | 组织/文件夹/项目/资源（继承） |

**常见危险模式**：`roles/editor`（含数据面写）；`roles/owner`；`allUsers`/`allAuthenticatedUsers`
绑定（公开）；服务账号密钥（`iam.serviceAccountKeyAdmin` 可造 key）；`iam.serviceAccounts.actAs`
可冒充。

## 5. 阿里云 RAM 策略语法

**结构**

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["oss:GetObject", "oss:ListObjects"],
      "Resource": ["acs:oss:*:*:example-bucket/*"],
      "Condition": {"IpAddress": {"acs:SourceIp": ["10.0.0.0/8"]}}
    }
  ]
}
```

| 元素 | 说明 |
|---|---|
| `Effect` | Allow / Deny |
| `Action` | 服务:动作（`oss:*`、`ram:*`） |
| `Resource` | `acs:服务:区域:账号:资源`（`*` 通配） |
| `Condition` | 条件（acs:SourceIp、acs:MFAPresent 等） |
| 系统策略 | `AliyunOSSFullAccess`、`AdministratorAccess` 等 |

**常见危险模式**：`AdministratorAccess` 全管理；`"Action":"*","Resource":"*"`；`ram:*` 可
自建密钥/授权提权；`sts:AssumeRole` 无条件信任。

## 6. 常见过宽权限模式清单（判定用，跨厂商）

| # | 过宽模式 | 检测判定 | 风险 |
|---|---|---|---|
| 1 | 全管理角色/策略（`*`/`*`、Owner、roles/owner、AdministratorAccess） | 主体命中即高危 | 完全接管 |
| 2 | 身份管理写权限（iam:*、roleAssignments/write、iam.*、ram:*） | 可自建密钥/改策略 | 权限提升 |
| 3 | 数据面全域（s3:*、blobs/*、storage.*、oss:*、对象读写全域） | 可读改全部对象 | 数据泄露/破坏 |
| 4 | 角色切换无限制（AssumeRole 无 Condition、actAs、AssumeRole） | 可冒充高权角色 | 横向提权 |
| 5 | 公开访问（allUsers/allAuthenticatedUsers、`*` Principal、桶策略公开） | 资源对外 | 数据公开 |
| 6 | 密钥/密钥库全域读（GetSecretValue 全域、VaultGet、secretmanager.*） | 可读全部密钥 | 凭证泄露 |
| 7 | 网络全域（ec2:*/防火墙写全域） | 可放行任意端口 | 暴露面扩大 |
| 8 | 审计/日志全域（cloudtrail:*/日志删除） | 可关审计 | 反取证 |

## 7. 判定与收口口径

- 写进 `privilege-chains.md`（C4 门）时，每条链注明：起点身份 → 权限变化（策略名+动作）
  → 终点资源 + 证据（策略文档原文/`get-iam-policy` 输出/角色分配列表）。
- 过宽权限「可到达性证明」：谁能 Assume/持有该角色、能对哪些资源执行哪些动作、拿到什么
  —— 三要素闭环，与主观念一致。
- 只读枚举权限的验证走 `cloud-api-readonly-probing.md`（附录 B）；元数据/实例身份走
  `metadata-service-endpoints.md`（附录 A）。
