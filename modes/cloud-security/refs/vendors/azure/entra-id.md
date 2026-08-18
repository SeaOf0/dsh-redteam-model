# Microsoft Entra ID（原 Azure AD）身份与权限攻防

Microsoft Entra ID（原 Azure Active Directory）是 Azure 云身份与访问管理的中枢，管理租户（Tenant）、用户、组、应用注册（App Registration）、企业应用、服务主体（Service Principal）与角色（Role/RBAC）。攻击面集中在「应用/服务主体的凭据」「角色分配过宽」「旧版授权协议」「用户凭据弱化」与「跨租户信任」几条线。

## 一、攻击面

- **租户（Tenant / Directory）**：Entra ID 租户是身份的边界，租户 ID、域名、联合（Federation）配置决定身份路由与信任关系。
- **用户与组**：云用户、同步用户（源自本地 AD）、来宾用户（B2B）；密码策略、MFA 状态、管理员角色成员是关注点。
- **应用注册与服务主体**：应用注册是应用身份的定义，服务主体是其在该租户内的实例化身份，可被授予角色（RBAC）、API 权限（OAuth scope）。服务主体凭据（客户端密钥 client secret、证书）是高频泄露点。
- **角色（RBAC）**：Entra 目录角色（如全局管理员、特权角色管理员）与 Azure 资源 RBAC 角色（如所有者/参与者）两套体系；`az role assignment list` 枚举资源角色，目录角色经 Microsoft Graph 查询。
- **旧版授权协议**：OAuth 权限、应用模拟、默认用户角色等历史遗留，常构成隐式信任。
- **跨租户与联合**：B2B 来宾、外部协作设置、联合身份提供商，是跨租户横向的入口。
- **条件访问与 PIM**：条件访问策略（Conditional Access）与特权身份管理（PIM）决定特权账户的保护强度，关闭或误配即放大风险。
- **密码与认证策略**：口令策略、自助密码重置、MFA 注册与条件访问的配置强度，决定账户被喷射/撞库的难易。

## 二、信息收集 / 暴露面探测

以下命令只读优先，用于枚举用户、服务主体、角色分配与租户配置。

```bash
# 查看当前登录账户与租户
az account show

# 列出租户内用户（含 UPN、类型、是否启用）
az ad user list --query "[].{upn:userPrincipalName, type:userType, enabled:accountEnabled}" --output table

# 列出服务主体（含应用标识与类型）
az ad sp list --query "[].{displayName:displayName, appId:appId, type:servicePrincipalType}" --output table

# 列出角色分配（含订阅/资源范围），识别高权限主体
az role assignment list --all --query "[].{principal:principalName, role:roleDefinitionName, scope:scope}" --output table

# 列出应用注册（需相应目录权限）
az ad app list --query "[].{name:displayName, appId:appId}" --output table

# 列出订阅可用区域（辅助判断资源分布）
az account list-locations --query "[].name"
```

探测要点：优先枚举「高权限角色 + 服务主体」组合——服务主体被授予所有者/参与者角色、或持有旧版 `azure activedirectory` 权限、或客户端密钥长期有效，是高价值目标。目录角色（全局管理员等）成员与用户 MFA 状态需经 Microsoft Graph 的 directoryRoles、authenticationMethods 端点查询，均属只读探测。

## 三、常见配置缺陷与利用路径

### 3.1 服务主体凭据泄露 / 高权限服务主体

- **缺陷描述**：应用注册的客户端密钥（client secret）或证书私钥泄露（源码、配置、CI/CD 变量），且该服务主体被授予高权限角色（所有者/参与者/全局管理员），攻击者可凭凭据直接获得租户/资源管理权。
- **验证命令（只读优先）**：

```bash
# 只读验证：枚举高权限服务主体（角色分配中 role=Owner/Contributor 且 principalType=ServicePrincipal）
az role assignment list --all \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{principal:principalName, principalType:principalType, scope:scope}" --output table

# 只读验证：列出服务主体，交叉比对应用标识
az ad sp list --query "[].{displayName:displayName, appId:appId}" --output table
```

- **影响**：攻击者以服务主体身份登录（`az login --service-principal`）获得授权，可管理订阅资源、读取密钥（listKeys）、创建新主体，实现持久化与横向。
- **检测侧建议**：Microsoft Entra ID 登录日志记录服务主体登录（`client credentials` 认证类型）；Activity Log 记录该主体 `initiatedBy` 的操作。防守方应监控「服务主体登录 + 后续高权限操作」的组合，并对服务主体凭据做定期轮换与到期告警。

### 3.2 特权用户凭据弱化 / MFA 未启用

- **缺陷描述**：特权用户（全局管理员等）未启用 MFA、使用弱密码或复用凭据，攻击者经密码喷射、钓鱼、撞库获得特权账户。特权账户一旦被接管，等价于租户级控制。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出启用状态的用户，识别潜在特权账户候选
az ad user list --query "[?accountEnabled].{upn:userPrincipalName}" --output table

# 只读验证：枚举资源级角色分配，识别被授予高权限的用户
az role assignment list --all \
  --query "[?principalType=='User'].{principal:principalName, role:roleDefinitionName, scope:scope}" --output table
```

- **影响**：特权账户被接管后可重置其它用户密码、授予角色、注册应用、修改条件访问策略，实现长期控制与横向。
- **检测侧建议**：Entra ID 登录日志记录交互式登录、MFA 状态与风险检测（如不可能旅行、匿名 IP、泄露凭据）；审计日志记录角色变更与密码重置。防守方应启用 PIM 与条件访问，对「无 MFA 的特权登录」「风险登录」告警。

### 3.3 角色分配过宽 / 永久权限

- **缺陷描述**：服务主体或用户被永久授予高权限角色（所有者/参与者/全局管理员），而非按需激活（PIM），一旦凭据泄露或账户被接管，权限立即可用且难以审计。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出全部角色分配及范围（识别永久高权限）
az role assignment list --all \
  --query "[].{principal:principalName, role:roleDefinitionName, scope:scope}" --output table

# 只读验证：查看角色定义中的可分配范围与权限
az role definition list --query "[].{name:roleName, type:roleType}" --output table
```

- **影响**：权限过宽导致最小权限原则失效，任何单一凭据泄露即可造成大面积资源接管。
- **检测侧建议**：Activity Log 记录角色分配变更 `Microsoft.Authorization/roleAssignments/write`；Entra 审计日志记录目录角色分配。防守方应定期做权限清理（Privileged Access Review），并对「新增高权限角色分配」告警。

### 3.4 旧版 OAuth 权限与跨租户信任滥用

- **缺陷描述**：应用被授予旧版 `azure activedirectory` 权限（可模拟任意用户）、或 B2B 外部协作配置过宽，攻击者经被信任应用或来宾账户实现跨身份/跨租户访问。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看应用/服务主体的 OAuth 权限授予（识别高权限 scope）
az ad app permission list --id <app-id> --query "[].{scope:resourceAccess}" --output json

# 只读验证：列出来宾用户（识别外部身份）
az ad user list --query "[?userType=='Guest'].{upn:userPrincipalName}" --output table
```

- **影响**：旧版权限可模拟任意用户身份，跨租户来宾则绕过本地边界，构成隐式提权与横向。
- **检测侧建议**：Entra 审计日志记录 OAuth 权限授予与应用授权（`Add app role assignment`、`Add delegated permission grant`）；登录日志记录来宾/外部身份登录。防守方应审查高权限 OAuth 授予，收紧外部协作设置。

### 3.5 密码喷射与凭据填充

- **缺陷描述**：租户允许传统口令认证且未对关键账户启用 MFA/条件访问，攻击者针对大量用户做低频密码喷射（规避账户锁定），或利用外部泄露的凭据做撞库，命中未受保护账户。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出启用状态用户，评估可被喷射的目标面（只读枚举）
az ad user list --query "[?accountEnabled].{upn:userPrincipalName}" --output table

# 只读验证：查看用户类型分布（云用户/同步用户/来宾），判断认证路径
az ad user list --query "[].userType" --output tsv | sort | uniq -c
```

- **影响**：命中未受 MFA 保护的账户后，结合其角色/权限实现初始访问或提权，进而横向。
- **检测侧建议**：Entra ID 登录日志记录大量失败登录（`50126` 无效凭据、`50053` 账户锁定）与风险检测（`passwordSpray`、`unfamiliarFeatures`）。防守方应在 Sentinel 中监控「短时间多账户失败登录」喷射模式并告警。

## 四、权限提升与持久化路径

- **服务主体 → 订阅接管**：泄露服务主体凭据 → 登录 → 若为所有者/参与者，管理全部资源，实现持久控制。
- **全局管理员 → 角色持久化**：全局管理员可注册新应用、创建新服务主体并授予高权限，作为难以发现的持久化后门。
- **PIM 角色激活滥用**：持有可激活特权的用户（或已被接管的用户）可临时提升到全局管理员执行操作，须监控激活记录。
- **密码重置与账户接管**：特权账户可重置目标用户密码，实现账户级持久化；此属写操作，须授权内人工确认后执行。
- **跨租户持久化**：经 B2B 来宾或外部应用维持跨租户访问，绕过本地身份边界。
- **凭据窃取与重放**：从应用配置、环境变量、托管标识 token（见 `./managed-identity-ssrf.md`）提取身份凭据并重放。

## 五、防御与检测要点

关键审计日志事件名清单：

| 服务/日志 | 关键事件 / 操作 |
| --- | --- |
| Microsoft Entra ID 登录日志 | 服务主体登录（`client credentials`）、风险登录、无 MFA 登录、来宾登录 |
| Microsoft Entra ID 审计日志 | 角色分配变更、目录角色成员变更、OAuth 权限授予（`Add delegated permission grant`） |
| Microsoft Entra ID 审计日志 | 应用注册创建、服务主体创建、凭据添加（`Add service principal credentials`） |
| Microsoft Entra ID 审计日志 | 密码重置（`Reset user password`）、条件访问策略变更 |
| Azure Activity Log | `Microsoft.Authorization/roleAssignments/write` |
| Azure Activity Log | `initiatedBy` 为服务主体/托管标识的高权限操作 |
| Microsoft Defender for Identity / Defender for Cloud | 可疑身份行为、特权账户异常 |
| Microsoft Sentinel | 服务主体登录 + 高权限操作关联告警 |

云检测缺口提示：服务主体凭据泄露后若仅做数据面读取（不触发管理面写操作），Activity Log 可能无对应记录，仅 Entra 登录日志留下 `client credentials` 登录痕迹。防守方应以「登录事件」而非「管理操作」作为检测主线，建立服务主体登录基线与异常比对。

防御要点小结：服务主体凭据定期轮换并限制角色、特权用户强制 MFA + PIM 按需激活、角色分配最小化并定期审查、收紧旧版 OAuth 权限与外部协作、对「新增高权限角色分配」「服务主体登录后高权限操作」建立告警。
