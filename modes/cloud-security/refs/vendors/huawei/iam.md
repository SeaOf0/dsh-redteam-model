# 华为云 IAM 身份与权限攻防

> 定位：围绕用户、用户组、角色、策略、委托（agency）、AK/SK 六类身份要素，给出只读优先的
> 枚举命令与权限缺陷利用路径。工具以 `hcloud iam` 为主，写/删操作统一标注「授权内人工确认
> 后执行」。每条路径配检测侧对照（CTS 事件名 + 权限变更审计）。元数据换委托临时凭证见
> `./metadata-ssrf.md`。

## 一、攻击面

IAM 是云上身份与权限的总闸门，攻击面集中在「凭证的生成、分发、回收」与「策略的收敛度」：

- AK/SK：永久访问密钥一旦泄露（源码、镜像、对象存储、CI/CD 日志），即等于长期有效身份。
- 委托（agency）：跨账号/跨服务授权的信任关系，信任配置过宽或被滥用可借道提权。
- 用户/用户组：弱密码策略、离职用户未回收、用户组权限继承过宽。
- 角色/策略：策略过度授权（admin 滥用）、策略拼接导致权限漂移、`*` 通配资源。
- 临时凭证：委托换取的 STS 临时凭证，权限等同委托，是元数据 SSRF 的终点。

四要素落点：身份（AK/SK / 用户名密码 / 委托临时凭证）→ 权限（策略/角色/委托策略）→ 资源
（用户/组/委托/项目）→ 影响（读敏感资源、提权、持久化）。

## 二、信息收集 / 暴露面探测

以下命令只读，用于枚举身份要素与权限边界。

### 2.1 用户与用户组枚举

```bash
# 列出全部 IAM 用户（只读）
hcloud iam list-users

# 列出全部用户组（只读）
hcloud iam list-user-groups

# 查看某用户组成员（只读）
hcloud iam list-group-members --group-name <group_name> 2>/dev/null
```

### 2.2 委托与角色枚举

```bash
# 列出全部委托（agency，只读，重点看信任主体与权限策略）
hcloud iam list-agencies

# 查看单个委托详情（信任账号/服务 + 绑定的权限策略）
hcloud iam show-agency --agency-name <agency_name> 2>/dev/null

# 列出可用角色与自定义策略（只读）
hcloud iam list-roles 2>/dev/null
hcloud iam list-policies 2>/dev/null
```

### 2.3 AK/SK 与密码策略枚举

```bash
# 列出某用户的永久访问密钥（AK，只读；SK 不落盘、不可回读）
hcloud iam list-permanent-access-keys --user-name <user_name> 2>/dev/null

# 查看账号密码策略（只读：长度、复杂度、有效期、登录失败锁定）
hcloud iam show-account-password-policy 2>/dev/null

# 查看当前身份（自省：确认当前 AK 对应的用户与权限边界）
hcloud iam show-user --user-name <current_user> 2>/dev/null
```

### 2.4 策略与权限边界只读核对

```bash
# 列出某用户/用户组已绑定的权限策略（只读，判断是否过度授权）
hcloud iam list-user-permissions --user-name <user_name> 2>/dev/null
hcloud iam list-group-permissions --group-name <group_name> 2>/dev/null
```

## 三、常见配置缺陷与利用路径

### 3.1 AK/SK 泄露（源码/镜像/对象存储/CI 日志）

- 缺陷描述：AK/SK 被硬编码进代码、提交进仓库、打包进镜像、写入公开桶或 CI/CD 构建日志，
  泄露后攻击者直接以该身份调用云 API，长期有效。
- 验证命令（只读优先）：

```bash
# 只读扫描仓库/镜像/对象中的 AK 特征（AK 形如 AK 开头的长串，只定位不泄露 SK）
grep -RniE 'AK[A-Z0-9]{16,}' <code_dir> 2>/dev/null | head -20
# 用泄露 AK 做只读自省，确认身份与权限（不调用破坏性 API）
hcloud iam show-user --user-name <user_name> 2>/dev/null
hcloud iam list-user-permissions --user-name <user_name> 2>/dev/null
```

- 影响：永久 AK/SK 无过期时间，泄露即长期越权访问，范围由该用户策略决定，可能直通 admin。
- 检测侧建议：CTS 事件 `createAK`、`deleteAK` 记录密钥创建与删除；AK 被异地/异常源使用属
  行为态，需 IAM 侧的调用审计 + 异常登录告警（如异地 IP 调用控制面）发现，缺规则即检测缺口。

### 3.2 委托（agency）信任配置过宽

- 缺陷描述：委托的信任主体被配置为「任意账号/任意服务」，或委托绑定了过宽的权限策略
  （如全局 admin），使低权限主体可借委托切换到高权限身份。
- 验证命令（只读）：

```bash
hcloud iam list-agencies
hcloud iam show-agency --agency-name <agency_name>   # 看信任主体与权限策略
hcloud iam list-agency-permissions --agency-name <agency_name> 2>/dev/null
```

- 影响：委托是权限的「借道」入口，信任过宽 = 越权切换，配合元数据/SSRF 可直接提权到控制面。
- 检测侧建议：CTS 事件 `createAgency`、`updateAgency`、`assumeRole`（委托换证）留痕；异常
  委托换证（陌生源、非预期服务）应触发告警，未配置规则即检测缺口。

### 3.3 弱密码策略与未回收用户

- 缺陷描述：账号密码策略过弱（无复杂度/无过期/无失败锁定），离职用户、临时用户长期未回收
  或未禁用，成为撞库与残留身份入口。
- 验证命令（只读）：

```bash
hcloud iam show-account-password-policy          # 看密码策略是否过弱
hcloud iam list-users                              # 排查长期未登录/离职未禁用用户
hcloud iam list-user-groups                        # 排查用户组权限继承过宽
```

- 影响：弱密码可被爆破，残留用户（尤其带 AK/SK 的）是休眠入口，激活后难以关联到真人。
- 检测侧建议：CTS 事件 `createUser`、`updateUser`、`deleteUser` 记录用户生命周期；长期未登录
  用户属配置态，需 IAM 合规扫描（SA）发现，检测缺口在配置态。

### 3.4 策略过度授权（admin 滥用 / `*` 通配）

- 缺陷描述：为用户/组/委托直接绑定 admin 或含 `*:*`（任意服务任意动作）的宽策略，权限远超
  实际职责，一旦该身份失陷即全盘沦陷。
- 验证命令（只读）：

```bash
hcloud iam list-user-permissions --user-name <user_name> 2>/dev/null
hcloud iam list-group-permissions --group-name <group_name> 2>/dev/null
# 重点识别含 Action 通配或 Resource 为 * 的策略
```

- 影响：过度授权放大单点失陷后果，越权访问、数据删除、资源劫持均可行。
- 检测侧建议：CTS 事件 `createPolicy`、`attachPolicy`、`updatePolicy` 记录策略变更；`*` 通配
  授权属配置态，需 IAM 权限审计（SA/权限校验报告）发现，检测缺口在配置态。

### 3.5 AK 未轮换 / 未删除

- 缺陷描述：长期未轮换的 AK 增加泄露窗口；已离职/停用身份仍保留 AK，成为无人认领的入口。
- 验证命令（只读）：

```bash
hcloud iam list-permanent-access-keys --user-name <user_name> 2>/dev/null
# 记录 AK 创建时间，排查超期未轮换的密钥
```

- 影响：AK 使用越久越可能已泄露，回收不及时则入口长期存在，且事后难以溯源。
- 检测侧建议：CTS 事件 `createAK`、`deleteAK` 记录密钥生命周期；未轮换属配置态，需密钥轮换
  合规（SA）发现，检测缺口在配置态。

### 3.6 委托与 AK 组合滥用（元数据换证）

- 缺陷描述：ECS 绑定的委托通过元数据换取临时凭证，攻击者拿到临时凭证后以委托权限横向调用
  API，形成「实例失陷 → 控制面失陷」的放大链。
- 验证命令（只读）：

```bash
# 实例内读元数据（只读，详见 ./metadata-ssrf.md）
curl -s http://169.254.169.254/openstack/latest/meta_data.json
# 换取的临时凭证只读自省（不调用破坏性 API）
hcloud iam list-agencies
```

- 影响：委托临时凭证等同于委托权限，配合过宽委托策略可直通控制面，是云上最典型的提权链。
- 检测侧建议：CTS 事件 `assumeRole`（委托换证）留痕；元数据读取数据面不产生 CTS 事件，需
  结合 CES 网络指标 + IAM 调用频次异常告警，检测缺口集中在数据面读取环节。

## 四、权限提升与持久化路径

- 委托换证提权：低权限 → 读元数据/SSRF → 换委托临时凭证 → 以委托权限枚举与扩大（见
  `./metadata-ssrf.md`）。
- 策略拼接提权：利用多策略拼接形成的权限漂移（不同策略的资源/动作并集）扩大实际权限。
- 持久化方式：创建后门 AK/SK、创建新用户并绑 admin、创建高权限委托、在用户组中注入后门
  成员。以上写操作均属「授权内人工确认后执行」，本文不提供脚本。
- 检测盲区：后门身份创建与控制面调用有 CTS 留痕，但数据面元数据读取无 CTS 事件。

## 五、防御与检测要点

| 层 | 关键动作 | 审计/监控事件 |
|---|---|---|
| 用户 | 创建/删除/变更用户 | `createUser`、`deleteUser`、`updateUser` |
| 用户组 | 组与成员变更 | `createGroup`、`updateGroup`、`addUserToGroup` |
| 委托 | 创建/更新/删除委托 | `createAgency`、`updateAgency`、`deleteAgency` |
| 换证 | 委托换取临时凭证 | `assumeRole` |
| 密钥 | AK/SK 创建/删除 | `createAK`、`deleteAK` |
| 策略 | 策略创建/绑定/更新 | `createPolicy`、`attachPolicy`、`updatePolicy` |
| 登录 | 控制台/API 登录异常 | IAM 登录审计 + 异常源 IP 告警 |

防御建议：

- AK/SK 最小化：优先临时凭证与委托，永久 AK 限量、定期轮换、即时回收离职身份。
- 委托收紧：信任主体最小化到具体账号/服务，权限策略最小化到具体资源与动作。
- 密码策略强化：复杂度、过期、失败锁定、MFA 全量覆盖。
- 策略审计：定期做权限收敛（去除 `*` 通配、回收未用权限），用 IAM 权限校验报告。
- 检测落地：CTS 投递 SIEM + IAM 变更告警 + 异常调用（异地/异源/高频）规则，补数据面盲区。

## 审计事件名清单（本节汇总）

`createUser`、`deleteUser`、`updateUser`、`createGroup`、`updateGroup`、
`addUserToGroup`、`createAgency`、`updateAgency`、`deleteAgency`、`assumeRole`、
`createAK`、`deleteAK`、`createPolicy`、`attachPolicy`、`updatePolicy`。
