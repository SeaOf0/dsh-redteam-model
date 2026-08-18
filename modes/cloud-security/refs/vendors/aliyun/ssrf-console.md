# 从 SSRF 到接管控制台

本文梳理阿里云环境中「应用 SSRF → 元数据 RAM 临时凭证 → 创建高权限子用户 → 控制台接管」的完整链路，供授权评估中识别与验证该风险。全文以只读探测与最小影响验证为原则，创建/删除类操作须授权内人工确认后执行。

## 一、攻击面

该链路的核心攻击面是三个信任边界的叠加：

- **应用 SSRF 点**：可被诱导发起服务端请求的参数（URL 导入、回源、回调、代理、预览等）。
- **元数据服务**：固定链路地址 `100.100.100.200` 提供实例属性与 RAM 角色临时凭证，默认无鉴权（未开加固模式时）。
- **RAM 角色权限**：实例绑定的角色若含 RAM 写权限，临时凭证即可被用于创建高权限子用户。

一旦三者同时满足，即可实现「一处应用漏洞 → 云账号控制面接管」的跨越式提权，是云环境最具代表性的攻击链之一。

## 二、信息收集 / 暴露面探测

先确认 SSRF 点可达性，再逐步探测元数据服务与角色凭证。

```bash
# 1. 确认 SSRF 可达内网/链路地址（返回状态码或内容差异即存在）
#    以应用参数为载体请求 http://100.100.100.200/latest/meta-data/

# 2. 从应用侧回显读取元数据根目录，确认可访问
curl http://100.100.100.200/latest/meta-data/

# 3. 读取本机绑定的 RAM 角色名（为空则无角色）
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/

# 4. 读取角色临时凭证（AccessKeyId / AccessKeySecret / SecurityToken）
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>
```

若目标启用了元数据加固模式，需先申请 token 再携带访问：

```bash
# 加固模式：先获取元数据 token
TOKEN=$(curl -X PUT "http://100.100.100.200/latest/api/token" \
  -H "X-aliyun-ecs-metadata-token-ttl-seconds: 21600")

# 再携带 token 访问元数据
curl -H "X-aliyun-ecs-metadata-token: $TOKEN" \
  http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>
```

常用元数据路径清单（只读探测参考）：

| 路径 | 含义 |
| --- | --- |
| `/latest/meta-data/` | 元数据根目录 |
| `/latest/meta-data/instance-id` | 实例 ID |
| `/latest/meta-data/image-id` | 镜像 ID |
| `/latest/meta-data/ram/security-credentials/` | 绑定的 RAM 角色名列表 |
| `/latest/meta-data/ram/security-credentials/<role>` | 角色临时凭证 |
| `/latest/user-data/` | 用户数据（可能含明文凭据） |
| `/latest/api/token` | 加固模式 token 申请入口 |

取得凭证后，用只读命令确认身份与权限边界：

```bash
# 确认临时凭证对应的身份（账号 ID、角色 ARN）
aliyun sts GetCallerIdentity \
  --AccessKeyId <AKID> --AccessKeySecret <AKSEC> --SecurityToken <TOKEN>

# 只读枚举当前身份可见的 RAM 资源，评估是否具备提权条件
aliyun ram ListUsers
aliyun ram ListRoles
aliyun ram GetAccountAlias
```

## 三、常见配置缺陷与利用路径

### 3.1 SSRF 未过滤内网与链路地址

**缺陷描述**：应用对 SSRF 目标未做协议/地址过滤，可请求 `100.100.100.200` 等链路地址与内网地址。

**验证命令（只读优先）**：

```bash
# 通过应用 SSRF 参数请求元数据根目录，观察回显
# 以只读方式确认返回了 meta-data 目录列表即为存在
```

**影响**：打通了从应用侧到元数据服务的通路，成为整条提权链的入口。

**检测侧建议**：应用侧 WAF/网关可对出站请求到链路地址与内网网段的行为告警；主机侧可监控进程对 `100.100.100.200` 的异常访问。云侧暂无单一事件覆盖，需依赖应用层与主机层日志。

### 3.2 元数据服务未加固

**缺陷描述**：实例未启用元数据加固模式，元数据（含角色临时凭证）可被实例内任意进程无鉴权读取。

**验证命令（只读优先）**：

```bash
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
# 无需 token 即返回角色名，说明未启用加固
```

**影响**：SSRF、命令注入、容器逃逸等任意「实例内读取」能力都会转化为云凭证泄露。

**检测侧建议**：启用加固模式后，无 token 访问会失败；防守方可在云监控对元数据服务高频访问配置告警，并通过安全中心主机基线强制加固。

### 3.3 实例角色授予 RAM 写权限

**缺陷描述**：实例绑定的角色被授予 `CreateUser`、`AttachPolicyToUser`、`CreateLoginProfile` 等 RAM 写权限或 `AdministratorAccess`，临时凭证可直接创建高权限子用户。

**验证命令（只读优先）**：

```bash
aliyun sts GetCallerIdentity --AccessKeyId <AKID> --AccessKeySecret <AKSEC> --SecurityToken <TOKEN>
aliyun ram ListPoliciesForUser --UserName <user>
# 只读判断当前身份是否具备 RAM 写权限，不执行写操作
```

**影响**：临时凭证的权限决定链路终点，具备 RAM 写权限即可完成控制台接管。

**检测侧建议**：ActionTrail 记录 `AssumeRole`、`CreateUser`、`AttachPolicyToUser`、`CreateLoginProfile`；防守方应限制实例角色权限为最小必要，并对「角色凭证调用方 + RAM 写操作」组合告警。

### 3.4 元数据加固模式未覆盖全部读取面

**缺陷描述**：即使启用了元数据加固模式，若应用 SSRF 可携带自定义请求方法（PUT）与请求头，仍可能代申请 token 后继续读取凭证。

**验证命令（只读优先）**：

```bash
# 若 SSRF 支持自定义方法与头，可代发 PUT 申请 token（只读验证能力边界）
# 观察应用是否允许对 /latest/api/token 的 PUT 请求与自定义头回传
```

**影响**：加固模式的防护被 SSRF 的「方法与头可控」能力绕过，凭证仍可被读取。

**检测侧建议**：加固模式 + 应用侧严格限制 SSRF 请求方法与头缺一不可；防守方应在应用网关拦截对链路地址的 PUT 请求，并在主机侧监控对 `/latest/api/token` 的异常调用。

## 四、权限提升与持久化路径

完整链路（仅列步骤与用途，创建/删除类操作须授权内人工确认后执行）：

1. **SSRF 读取元数据**：获取实例 RAM 角色临时凭证（只读）。
2. **确认身份**：`sts GetCallerIdentity` 识别账号 ID 与角色（只读）。
3. **枚举权限**：`ram ListUsers`、`ListPoliciesForUser` 确认可写范围（只读）。
4. **创建高权限子用户**：`ram CreateUser` 创建新用户（授权内人工确认后执行）。
5. **授予管理权限**：`ram AttachPolicyToUser` 绑定 `AdministratorAccess`（授权内人工确认后执行）。
6. **开通控制台登录**：`ram CreateLoginProfile` 设置登录口令（授权内人工确认后执行）。
7. **控制台接管**：使用主账号别名登录控制台，完成账号级控制面接管。

持久化路径：

- **影子用户 + AK**：`CreateAccessKey` 为新建用户生成长期 AK，作为备用通道。
- **高权限角色驻留**：若具备 `CreateRole`/`UpdateRole` 权限，可创建含宽泛信任策略的角色长期承担。
- **删除痕迹**：攻击者可能删除临时用户或 AK 以掩盖，评估中严禁执行删除操作，仅作风险提示。

该链路每一步都会在 ActionTrail 留下事件，防守方若能关联「AssumeRole 调用方 IP ≠ 实例 IP」与「短时间内 CreateUser + AttachPolicyToUser + CreateLoginProfile」即可识别。

## 五、防御与检测要点

审计日志事件名清单（ActionTrail）：

| 事件名 | 含义 | 风险提示 |
| --- | --- | --- |
| `AssumeRole` | 承担角色获取临时凭证 | 关注调用方 IP 与实例 IP 不一致 |
| `GetCallerIdentity` | 身份自检 | 凭证被外部使用的首个信号 |
| `GetAccountAlias` | 获取主账号别名 | 控制台接管前的侦察 |
| `CreateUser` | 创建子用户 | 影子用户持久化 |
| `CreateAccessKey` | 创建 AK | 备用通道持久化 |
| `AttachPolicyToUser` | 绑定高权限策略 | 提权关键动作 |
| `CreateLoginProfile` | 开通控制台登录 | 控制台接管关键动作 |
| `ListUsers` / `ListPoliciesForUser` | 枚举用户/权限 | 侦察指标 |

防御建议：

- 应用侧对 SSRF 做协议与地址白名单过滤，禁止链路地址与内网网段。
- 实例默认启用元数据加固模式，必须携带 token 才能读取敏感元数据。
- 实例角色最小权限，禁止授予 RAM 写权限或 `AdministratorAccess`，确需时走 STS 精确授权。
- 云监控对元数据高频访问告警；ActionTrail 对「CreateUser + AttachPolicyToUser + CreateLoginProfile」组合建立强告警，并校验 AssumeRole 调用方。
