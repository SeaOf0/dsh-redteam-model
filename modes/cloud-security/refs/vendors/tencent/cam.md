# CAM 访问管理攻防

> 面向授权安全测试的 CAM（访问管理）攻击面梳理与方法论，涵盖用户、角色、策略、SecretId/SecretKey 与 STS 临时凭证。所有验证以只读探测优先，破坏性操作需「授权内人工确认后执行」。

## 一、攻击面

CAM 是腾讯云身份与访问管理服务，负责用户、用户组、角色、策略与访问密钥的管控。其攻击面集中于凭据管理与权限授予，可归纳为：

- **访问密钥面**：SecretId/SecretKey 泄露、密钥长期未轮换、密钥未启用 MFA。
- **权限策略面**：策略过宽（`*` 资源、`*` 动作、`AdministratorAccess`）、策略绑定关系混乱。
- **角色面**：角色信任策略过宽、角色被跨账号 AssumeRole、角色绑定高危服务。
- **临时凭证面**：STS 临时凭证（FederationToken/AssumeRole）滥用。

下表列出 CAM 攻击面与对应防守视角：

| 攻击面 | 攻击者关注点 | 防守者关注点 |
| --- | --- | --- |
| 访问密钥 | 泄露密钥枚举权限 | `CreateAccessKey`、密钥轮换审计 |
| 策略 | 过宽策略利用 | `AttachPolicyToUser` 审计 |
| 角色 | 信任策略滥用 | `AssumeRole`、`UpdateRoleDescription` 审计 |
| 临时凭证 | STS 凭证越权 | `AssumeRole`、`GetFederationToken` 审计 |

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于枚举当前账号授权范围内的 CAM 资源与配置。

```bash
# 查看当前调用者身份（只读，确认当前凭据归属）
tccli sts GetCallerIdentity

# 列出用户（只读）
tccli cam ListUsers

# 查看指定用户（只读）
tccli cam GetUser --Name <username>

# 列出用户已绑定的策略（只读）
tccli cam ListAttachedUserPolicies --TargetUin <uin>

# 列出用户可用的全部策略（含继承，只读）
tccli cam ListPoliciesForUser --Uin <uin>

# 列出访问密钥（只读，不返回 SecretKey）
tccli cam ListAccessKeys --TargetUin <uin>

# 列出角色（只读）
tccli cam DescribeRoleList

# 查看策略详情（只读）
tccli cam GetPolicy --PolicyId <policy-id>
```

从 `ListAttachedUserPolicies` / `ListPoliciesForUser` 提取绑定的策略名，重点识别 `AdministratorAccess`、`QcloudCVMFullAccess`、`QcloudCOSFullAccess` 等高权限策略。从 `DescribeRoleList` 提取角色信任策略（`AssumeRolePolicyDocument`）。

## 三、常见配置缺陷与利用路径

### 3.1 SecretId/SecretKey 泄露

**缺陷描述**：访问密钥被提交至代码仓库、前端源码、备份文件或通过日志泄露，且未启用 MFA、长期未轮换。

**验证命令（只读优先）**：

```bash
# 用泄露密钥确认身份与账号（只读）
tccli sts GetCallerIdentity --secret-id <SecretId> --secret-key <SecretKey>

# 枚举该密钥可访问的资源（只读）
tccli cam ListPoliciesForUser --Uin <uin>
```

**影响**：密钥泄露等同于持有对应身份的全部权限，可调用云 API 枚举资源、导出数据、修改配置。

**检测侧建议**：密钥的 API 调用由 CloudAudit 记录（含调用方 IP、UA、调用者）；`GetCallerIdentity` 高频调用可被 SOC 关联为密钥泄露迹象；密钥创建/删除由 `CreateAccessKey`、`DeleteAccessKey` 审计。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 泄露密钥调用云 API |
| 防守者 | CloudAudit API 调用日志、SOC 异常调用方告警 |

### 3.2 权限策略过宽（`*` 资源 / 高权限托管策略）

**缺陷描述**：用户或角色绑定了 `*` 资源、`*` 动作的自定义策略，或直接绑定 `AdministratorAccess` 等高权限托管策略。

**验证命令（只读优先）**：

```bash
# 列出绑定策略（只读）
tccli cam ListAttachedUserPolicies --TargetUin <uin>

# 查看策略详情，识别 * 资源与 * 动作（只读）
tccli cam GetPolicy --PolicyId <policy-id>
```

**影响**：过宽策略使任何单一凭据泄露都可能升级为账号级接管，扩大横向移动与数据导出能力。

**检测侧建议**：策略绑定变更由 CloudAudit `AttachPolicyToUser`、`DetachUserPolicy` 审计；SOC 可对高权限策略绑定建立告警，并对策略内容做周期性最小权限扫描。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 高权限策略滥用、横向枚举 |
| 防守者 | CloudAudit `AttachPolicyToUser`、SOC 权限扫描 |

### 3.3 角色信任策略过宽导致跨账号 AssumeRole

**缺陷描述**：角色信任策略允许任意账号或过宽主体 AssumeRole，攻击者可经受控账号扮演该角色获取其权限。

**验证命令（只读优先）**：

```bash
# 查看角色及信任策略（只读）
tccli cam DescribeRoleList
tccli cam GetRole --RoleName <role-name>

# 尝试扮演角色（最小影响验证，仅当授权内确认信任策略可被利用时）
tccli sts AssumeRole --RoleArn <role-arn> --RoleSessionName probe
```

**影响**：跨账号角色扮演可将低权限账号提升为高权限角色，实现越权访问目标账号资源。

**检测侧建议**：`AssumeRole` 由 CloudAudit 记录（含调用者账号与角色 ARN）；SOC 对异常调用方账号的 `AssumeRole` 建立告警，并对信任策略做最小化收敛。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 跨账号 AssumeRole 获取角色权限 |
| 防守者 | CloudAudit `AssumeRole`、异常角色扮演告警 |

### 3.4 临时凭证（STS）滥用与长期有效

**缺陷描述**：STS 临时凭证（FederationToken）有效期过长或泄露，攻击者复用临时凭证持续访问云 API。

**验证命令（只读优先）**：

```bash
# 确认临时凭证身份（只读）
tccli sts GetCallerIdentity --secret-id <TmpSecretId> --secret-key <TmpSecretKey> --token <Token>

# 查看当前账号可发放临时凭证的角色/联邦配置（只读）
tccli sts GetFederationToken  # 慎用，仅授权内评估
```

**影响**：临时凭证泄露后在其有效期内可执行与母体相同的 API 调用，形成持久访问窗口。

**检测侧建议**：临时凭证调用由 CloudAudit 记录，`AssumeRole` / `GetFederationToken` 事件可追踪签发行为；SOC 对临时凭证（`TmpSecretId` 前缀）调用方异常告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 复用泄露的临时凭证 |
| 防守者 | CloudAudit `AssumeRole`/`GetFederationToken`、临时凭证告警 |

### 3.5 访问密钥长期未轮换 / 未启用 MFA

**缺陷描述**：访问密钥长期未轮换且未绑定 MFA，泄露后无法及时发现与阻断。

**验证命令（只读优先）**：

```bash
# 查看密钥创建时间（只读，判断密钥年龄）
tccli cam ListAccessKeys --TargetUin <uin>

# 查看用户 MFA 状态（只读）
tccli cam DescribeSafeAuthFlag --Uin <uin>
```

**影响**：老密钥泄露面更大，且无 MFA 的密钥可直接被远程利用，无二次验证屏障。

**检测侧建议**：密钥创建时间与 MFA 状态是防守侧配置基线项；SOC 可对无 MFA 高权限用户、密钥超期未轮换建立合规告警，CloudAudit `CreateAccessKey` 记录密钥生命周期。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 利用无 MFA 老密钥 |
| 防守者 | MFA 合规基线、CloudAudit `CreateAccessKey` |

## 四、权限提升与持久化路径

- **新建高权限用户**：持管理员密钥的攻击者创建新用户并绑定高权限策略（`CreateUser` + `AttachPolicyToUser`），需授权内人工确认后评估。检测点：CloudAudit `CreateUser`、`AttachPolicyToUser`。
- **新增访问密钥**：为既有用户创建额外密钥作为持久后门（`CreateAccessKey`）。检测点：CloudAudit `CreateAccessKey`。
- **修改角色信任策略**：放宽角色信任主体引入攻击者账号（`UpdateRoleDescription`/信任策略更新），破坏性，授权内人工确认后执行。检测点：CloudAudit 角色信任策略变更事件。
- **临时凭证长生命周期**：通过 `GetFederationToken` 发放长有效期临时凭证。检测点：CloudAudit `GetFederationToken`。

上述操作若涉及创建用户/密钥或修改信任策略，一律标注「授权内人工确认后执行」。

## 五、防御与检测要点

核心审计事件清单（CloudAudit 操作审计）：

- `CreateUser` / `DeleteUser` — 用户创建/删除
- `CreateAccessKey` / `DeleteAccessKey` — 访问密钥创建/删除
- `AttachPolicyToUser` / `DetachUserPolicy` — 策略绑定/解绑
- `CreatePolicy` / `UpdatePolicy` — 策略创建/修改
- `CreateRole` / `UpdateRoleDescription` — 角色创建/信任策略变更
- `AssumeRole` / `GetFederationToken` — 临时凭证签发
- `GetCallerIdentity` — 身份确认（泄露密钥探测信号）
- `ListUsers` / `ListPolicies` / `DescribeRoleList` — 枚举行为（异常批量枚举告警）

防御建议：

1. 访问密钥最小化发放，启用 MFA，定期轮换，密钥不入库、不进代码仓库。
2. 策略遵循最小权限，杜绝 `*` 资源/`*` 动作，慎用 `AdministratorAccess`。
3. 角色信任策略严格限定主体账号与条件（`Condition`）。
4. 临时凭证设置短有效期，避免明文泄露。
5. 对 `CreateUser`、`CreateAccessKey`、`AttachPolicyToUser`、`AssumeRole` 建立高危告警与 SOC 关联规则。
