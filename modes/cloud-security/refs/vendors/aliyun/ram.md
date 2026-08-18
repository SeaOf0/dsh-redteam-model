# RAM 访问控制与权限攻防

本文覆盖阿里云 RAM 访问控制在授权评估中的攻击面、暴露面探测、常见配置缺陷与利用路径、权限提升与持久化，以及对应检测要点。所有命令以只读探测为优先，破坏性操作须在授权范围内人工确认后执行。

## 一、攻击面

RAM 是整个账号权限体系的枢纽，攻击面集中于身份与策略两类对象：

- **RAM 用户**：长期 AccessKey、登录口令、MFA 状态、权限边界。
- **RAM 角色**：AssumeRole 信任策略、服务角色、跨账号角色。
- **权限策略**：`AdministratorAccess`、`*:*` 通配符、过宽的 Action/Resource。
- **AccessKey**：硬编码、泄漏、未轮换、未关闭。
- **STS 临时凭证**：有效期、续期、权限范围。
- **主账号别名**：登录 URL 中的别名可被枚举与定向爆破。
- **根账号**：根账号 AK、根账号未开启 MFA。

RAM 的风险在于「凭证失陷 → 权限枚举 → 横向提权 → 持久化」链条完整且难以在单一服务内感知，需要跨 ActionTrail 与云监控联动。

## 二、信息收集 / 暴露面探测

已获得一组 AK 后，先确认身份，再只读枚举账号、角色、策略与用户权限。

```bash
# 确认当前调用者身份（账号 ID、用户/角色、ARN）
aliyun sts GetCallerIdentity

# 获取主账号别名（用于登录入口与后续定向测试）
aliyun ram GetAccountAlias

# 列出 RAM 用户
aliyun ram ListUsers

# 列出 RAM 角色
aliyun ram ListRoles

# 列出某用户的 AccessKey（识别泄漏与未轮换的 AK）
aliyun ram ListAccessKeys --UserName <user>

# 列出某用户已绑定的策略（识别权限边界与可提权路径）
aliyun ram ListPoliciesForUser --UserName <user>

# 列出全部策略（识别自定义策略中的宽泛授权）
aliyun ram ListPolicies

# 查看某策略详情（Action/Resource 是否含通配符）
aliyun ram GetPolicy --PolicyName <name> --PolicyType Custom
```

## 三、常见配置缺陷与利用路径

### 3.1 AccessKey 硬编码或泄漏

**缺陷描述**：AK 泄漏于代码仓库、前端、CI、日志或第三方系统，且长期有效、未轮换。

**验证命令（只读优先）**：

```bash
aliyun sts GetCallerIdentity
# 返回账号 ID 与身份类型，确认 AK 有效

aliyun ram ListAccessKeys --UserName <user>
# 查看该用户 AK 数量与状态（Active/Inactive）
```

**影响**：AK 有效即等于以该用户身份调用云 API，权限范围内资源全部暴露；若为根账号 AK 则完全接管。

**检测侧建议**：ActionTrail 记录 `GetCallerIdentity` 及后续所有 API 调用与调用方 IP；云监控可对 AK 异常调用（陌生 IP、非工作时间、高频）告警。防守方应强制 AK 轮换与最小权限。

### 3.2 权限策略使用通配符或过度授权

**缺陷描述**：自定义策略使用 `Action: *`、`Resource: *`，或直接绑定 `AdministratorAccess`，导致单一用户权限覆盖全账号。

**验证命令（只读优先）**：

```bash
aliyun ram ListPoliciesForUser --UserName <user>
# 识别是否绑定 AdministratorAccess 或宽泛自定义策略

aliyun ram GetPolicy --PolicyName <name> --PolicyType Custom
# 检查 PolicyDocument 中 Action/Resource 通配符
```

**影响**：低价值业务账号一旦失陷即可横向控制全账号，扩大单点失陷的爆炸半径。

**检测侧建议**：ActionTrail 记录 `CreatePolicy`、`AttachPolicyToUser`、`AttachPolicyToRole`；防守方应通过权限审计定期盘点通配符策略与高危授权，并对策略变更告警。

### 3.3 角色信任策略过宽（跨账号 AssumeRole）

**缺陷描述**：角色信任策略允许任意账号、任意用户或过宽 Principal 承担该角色，导致跨账号权限被冒用。

**验证命令（只读优先）**：

```bash
aliyun ram ListRoles
aliyun ram GetRole --RoleName <name>
# 检查 AssumeRolePolicyDocument 中的 Principal 与 Action
```

**影响**：攻击者可用自身账号承担目标角色，获取角色权限，绕过账号边界。

**检测侧建议**：ActionTrail 记录 `AssumeRole`（含调用方账号与调用方 IP）；防守方应对跨账号 AssumeRole 建立告警，并收紧信任策略 Principal。

### 3.4 未开启 MFA 与主账号别名弱口令

**缺陷描述**：RAM 用户（尤其高权限用户）与根账号未开启 MFA，或主账号别名 + 弱口令可被定向爆破。

**验证命令（只读优先）**：

```bash
aliyun ram GetAccountAlias
# 确认登录别名，评估是否易被枚举

aliyun ram ListUsers
# 结合 ListVirtualMFADevices 判断用户 MFA 绑定情况
aliyun ram ListVirtualMFADevices
```

**影响**：口令泄露即可登录控制台，绕过 API 层面的部分审计，直接操作资源。

**检测侧建议**：ActionTrail 记录 `CreateLoginProfile`、`UpdateLoginProfile`、控制台登录相关事件；防守方应强制 MFA 与强口令策略，对异常地域登录告警。

## 四、权限提升与持久化路径

- **权限枚举 → 提权**：用当前身份只读枚举可调用的 Action，识别可写 RAM 的权限（`CreateUser`、`AttachPolicyToUser`、`CreateAccessKey`），据此构造提权路径。
- **创建高权限子用户**：具备 RAM 写权限时创建子用户并绑定 `AdministratorAccess`，实现持久化（见 `./ssrf-console.md`）。
- **新增 AccessKey 持久化**：为目标用户新增 AK 作为备用通道（`CreateAccessKey`），须授权内人工确认后执行。
- **AssumeRole 跨账号驻留**：在信任策略过宽的角色上持续承担角色，实现跨账号访问。
- **影子用户与影子策略**：创建不显眼的用户或自定义策略用于长期驻留，须授权内人工确认后执行。

删除类操作（`DeleteUser`、`DeleteRole`、`DeletePolicy`、`DeleteAccessKey`）均为高影响动作，评估中严禁执行，仅作风险提示。

## 五、防御与检测要点

审计日志事件名清单（ActionTrail）：

| 事件名 | 含义 | 风险提示 |
| --- | --- | --- |
| `GetCallerIdentity` | 身份自检 | 泄漏 AK 的首次调用 |
| `AssumeRole` | 承担角色 | 关注跨账号与陌生调用方 |
| `CreateUser` | 创建用户 | 影子用户持久化 |
| `CreateAccessKey` | 创建 AK | 备用通道持久化 |
| `CreateLoginProfile` | 创建登录配置 | 控制台接管 |
| `AttachPolicyToUser` | 用户绑定策略 | 高权限授予 |
| `AttachPolicyToRole` | 角色绑定策略 | 角色提权 |
| `CreatePolicy` / `UpdatePolicy` | 创建/改策略 | 宽泛策略注入 |
| `CreateRole` / `UpdateRole` | 创建/改角色 | 信任策略篡改 |
| `GetAccountAlias` | 获取别名 | 侦察指标 |
| `DeleteUser` / `DeleteAccessKey` | 删除用户/AK | 高影响，须告警 |

防御建议：

- 全面启用 MFA，尤其根账号与高权限用户；AK 定期轮换、按需关闭。
- 策略最小权限，禁止 `*:*` 与宽泛通配符；角色信任策略收紧 Principal。
- 禁用或严格限制根账号 AK；使用 STS 临时凭证替代长期 AK。
- 通过 ActionTrail 对上述事件建集中告警，重点关注「Create + Attach + Login」组合与陌生调用方。
