# IAM 与权限攻防

本文聚焦 AWS IAM 身份与权限的攻击面、常见配置缺陷与检测要点，供授权安全评估参考。实例元数据凭证链路见 `./ssrf-metadata.md`，桶策略与资源级权限见 `./s3.md`。

## 一、攻击面

IAM 是整个云权限模型的枢纽，攻击面集中在**身份**与**策略**两条主线：

- **用户与组**：长期 AccessKey、登录口令、MFA 状态、组成员关系
- **角色**：角色信任策略（跨账户/服务主体）、角色附加策略
- **策略**：托管策略、内联策略、权限边界、服务控制策略（SCP）
- **凭证面**：AccessKey / SecretKey、Session Token、临时凭证（STS）
- **信任面**：跨账户 AssumeRole、身份提供商（OIDC/SAML）、资源级信任

IAM 滥用几乎贯穿所有攻击阶段：初始凭证获取、横向移动、权限提升、持久化。

## 二、信息收集 / 暴露面探测

```bash
# 当前身份
aws sts get-caller-identity

# 枚举用户、角色、组、策略
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies --scope Local

# 枚举用户附加策略与内联策略
aws iam list-attached-user-policies --user-name alice
aws iam list-user-policies --user-name alice
aws iam list-groups-for-user --user-name alice

# 枚举角色信任策略与附加策略
aws iam list-attached-role-policies --role-name dev-role
aws iam get-role --role-name dev-role --query 'Role.AssumeRolePolicyDocument'

# 全量账户授权详情（一次性导出账户内所有身份/策略/组关系）
aws iam get-account-authorization-details

# 枚举 AccessKey 状态
aws iam list-access-keys --user-name alice

# 查看具体策略版本内容
aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/name --version-id v1

# 模拟权限判断（只读，验证某身份对某动作是否放行）
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:user/alice --action-names s3:ListBucket iam:CreateUser
```

## 三、常见配置缺陷与利用路径

### 3.1 AccessKey 硬编码与泄露

**缺陷描述**：长期 AccessKey 被硬编码进代码、镜像、前端或配置仓库，经代码泄露、对象存储公开或日志外泄被获取。

**验证命令（只读优先）**：

```bash
aws iam list-access-keys --user-name alice
aws sts get-caller-identity   # 用泄露凭证验证身份与权限
```

**影响**：凭证泄露即身份接管，权限随该用户策略而定，可进一步横向或提权。

**检测侧建议**：泄露本身难在 CloudTrail 直接捕获，但凭证的异常调用会留下对应 API 事件；GuardDuty 的凭证泄露检测（如异常区域/资源访问）可告警。建议用短期凭证、周期性轮换、接入凭证扫描，并启用 Access Analyzer 定位外部可访问资源。

### 3.2 策略过度授权（通配符）

**缺陷描述**：策略使用 `Action: "*"`、`Resource: "*"` 或过于宽泛的服务前缀（如 `s3:*`），主体实际权限远大于业务所需，为提权留出空间。

**验证命令（只读优先）**：

```bash
aws iam get-account-authorization-details --query 'UserDetailList[].AttachedPolicies[]'
aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/name --version-id v1
```

**影响**：单个身份被攻破即可能覆盖全服务面，破坏最小权限原则。

**检测侧建议**：策略变更（`AttachUserPolicy`、`PutUserPolicy`、`CreatePolicyVersion`）写入 CloudTrail；Access Analyzer 可生成最小权限建议。建议策略白名单化，禁止 `*:*` 组合。

### 3.3 未启用 MFA

**缺陷描述**：控制台登录用户或高权限用户未启用 MFA，口令泄露后即可直接接管；`sts:AssumeRole` 未要求 MFA 条件时临时凭证亦不设防。

**验证命令（只读优先）**：

```bash
aws iam get-account-authorization-details --query 'UserDetailList[].[UserName,PasswordLastUsed]'
aws iam list-mfa-devices --user-name alice
```

**影响**：口令爆破或钓鱼后无二次验证屏障，接管风险升高。

**检测侧建议**：`DeactivateMFADevice`、`UpdateLoginProfile` 写入 CloudTrail；可用 Credential Report 与 Config 检查 MFA 覆盖率。建议对根账户与特权用户强制 MFA。

### 3.4 跨账户信任配置错误

**缺陷描述**：角色信任策略 `Principal` 写为 `*`、宽泛账号 ID 或含 `sts:AssumeRole` 但缺少 `ExternalId`/条件约束，导致陌生账号可代入该角色。

**验证命令（只读优先）**：

```bash
aws iam get-role --role-name cross-role --query 'Role.AssumeRolePolicyDocument'
```

**影响**：跨账户提权，攻击者账号可 AssumeRole 获取目标账号内该角色权限。

**检测侧建议**：`UpdateAssumeRolePolicy` 写入 CloudTrail；Access Analyzer 可发现可被外部主体假定的角色。建议跨账户信任加 `ExternalId`、限定具体账号与条件键。

### 3.5 内联策略与托管策略管理混乱

**缺陷描述**：大量内联策略分散在单个用户/角色上，缺少集中治理；或过度依赖宽泛的 AWS 托管策略（如 `AdministratorAccess`），无法细粒度收口。

**验证命令（只读优先）**：

```bash
aws iam list-user-policies --user-name alice
aws iam list-attached-user-policies --user-name alice
```

**影响**：权限难以审计与回收，存在长期静默越权。

**检测侧建议**：`PutUserPolicy`、`AttachUserPolicy` 变更进入 CloudTrail；建议统一使用版本化托管策略 + 权限边界，定期做权限清理。

### 3.6 未使用凭证长期存在

**缺陷描述**：离职员工、废弃服务的用户与 AccessKey 未清理，长期未轮换，成为被遗忘的攻击入口。

**验证命令（只读优先）**：

```bash
aws iam get-credential-report   # 生成并拉取凭证报告（含最后使用时间）
aws iam list-access-keys --user-name alice --query 'AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]'
```

**影响**：僵尸凭证被窃取后不易被察觉，长期驻留。

**检测侧建议**：Credential Report 的 `AccessKeyLastUsed` 与 Config 可识别未使用凭证；建议定期停用/删除 90 天未用凭证，启用 AccessKey 生命周期治理。

## 四、权限提升与持久化路径

- **AssumeRole 横向/纵向提权**：利用泄露凭证或信任链代入更高权限角色（`aws sts assume-role`）。
- **创建后门用户与 AccessKey**：拥有 `iam:CreateUser` + `iam:CreateAccessKey` 时创建新身份作为长期后门（需授权内确认）。
- **附加策略提权**：`iam:AttachUserPolicy` / `iam:PutUserPolicy` / `iam:AttachRolePolicy` 给自己或同伙加宽权限（需授权内确认）。
- **修改信任策略持久化**：`iam:UpdateAssumeRolePolicy` 加入攻击者账号，建立跨账户持久访问。
- **临时凭证续期**：通过 `sts:GetSessionToken` / `GetFederationToken` 维持会话。

## 五、防御与检测要点

| 攻击者动作 | CloudTrail 事件名 | 检测/告警建议 |
| --- | --- | --- |
| 创建/删除用户 | `CreateUser`、`DeleteUser` | 对新身份创建即时告警 |
| 创建/删除 AccessKey | `CreateAccessKey`、`DeleteAccessKey`、`UpdateAccessKey` | 对新增长期凭证告警 |
| 附加/内联策略变更 | `AttachUserPolicy`、`DetachUserPolicy`、`PutUserPolicy`、`AttachRolePolicy` | 对宽策略附加告警 |
| 创建角色/改信任策略 | `CreateRole`、`UpdateAssumeRolePolicy` | 对信任策略 `Principal` 变更告警 |
| 代入角色 | `AssumeRole`、`GetSessionToken`、`GetFederationToken` | 对跨账户/异常地域代入告警 |
| 登录配置变更 | `CreateLoginProfile`、`UpdateLoginProfile` | 对密码重置/控制台访问开通告警 |
| MFA 变更 | `DeactivateMFADevice`、`EnableMFADevice` | 对关闭 MFA 告警 |

配套日志与检测服务：CloudTrail、IAM Access Analyzer、Security Hub、Config、Credential Report、GuardDuty。防线核心：最小权限、强制 MFA、短期凭证、信任策略加 `ExternalId`、权限边界与 SCP 收口、定期清理僵尸凭证。
