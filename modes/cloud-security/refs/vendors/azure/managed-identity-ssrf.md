# 从 SSRF 到托管标识（Managed Identity）元数据 Token 攻防

托管标识（Managed Identity，MSI）是 Azure 为计算资源（VM、应用服务、函数、容器实例等）提供的免密钥身份。其核心信任假设是「运行在资源内部的代码即代表该资源」，因此元数据服务在资源内无条件签发访问 token。一旦攻击者能通过服务端请求伪造（SSRF）或任意代码执行让目标资源「内部」发起请求，即可窃取该身份的 token，完成从数据面到管理面的权限提升。

## 一、攻击面

- **实例元数据服务（IMDS）**：链路本地地址 `169.254.169.254`，仅资源内部可达。访问必须带 `Metadata: true` 请求头与 `api-version` 参数，否则拒绝。
- **托管标识 token 端点**：路径 `/metadata/identity/oauth2/token`，`resource` 参数指定目标受众（管理面、Key Vault、存储等受众标识），系统分配身份无需 `client_id`，用户分配身份需带 `client_id`。
- **SSRF 源**：Web 应用、API、代理、文件导入、URL 预览、Webhook 回调等服务端发起请求的功能，是触发元数据服务请求的主要入口。
- **自定义数据（Custom Data）**：VM 预配时注入的自定义数据经元数据服务返回，常被误用于存放敏感配置。
- **token 受众范围**：token 可针对不同 `resource` 受众签发，决定其后续能访问的资源面（管理面、密钥库、存储、目录）。
- **托管标识共享**：用户分配托管标识可被多个资源共享，单一身份 token 泄露影响多个资源。

## 二、信息收集 / 暴露面探测

以下命令只读优先，用于确认托管标识是否启用、其身份与角色范围，以及元数据服务的可达性。

```bash
# 只读验证：读取实例元数据（需 Metadata 头）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 只读验证：读取实例计算信息（含身份、资源组、订阅、位置）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"

# 只读验证：查看 VM 是否启用托管标识（管理面视角）
az vm show --resource-group <rg> --name <vm> \
  --query "identity" --output json

# 只读验证：查看该托管标识的身份主体 ID
az vm identity show --resource-group <rg> --name <vm> \
  --query "principalId"

# 只读验证：查询该身份被授予的角色范围
az role assignment list --all \
  --query "[?principalId=='<principal-id>'].{role:roleDefinitionName, scope:scope}" --output table
```

探测要点：`compute` 元数据中的 `identity` 字段给出 principalId 与 clientId；`resourceGroupName`、`subscriptionId`、`location` 可直接泄露环境拓扑信息。`az vm identity show` 返回的 principalId 可用于关联该身份的角色范围。

## 三、常见配置缺陷与利用路径

### 3.1 SSRF 触发元数据服务读取实例信息

- **缺陷描述**：应用存在 SSRF（URL 导入、Webhook、代理、PDF 渲染等），服务端可发起任意内部请求且未过滤链路本地地址，攻击者可让服务端访问 `169.254.169.254` 读取实例元数据。
- **验证命令（只读优先）**：

```bash
# 只读验证：从目标资源内部探测元数据服务（最小影响，只读取实例信息）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"
```

- **影响**：泄露实例身份、环境信息、自定义数据，为后续 token 窃取与权限评估奠定基础。
- **检测侧建议**：元数据服务请求不产生 Activity Log 事件，但 SSRF 触发的外部请求可见于应用日志与 NSG 流日志（对 `169.254.169.254` 的出站流）。防守方应在应用层拦截 SSRF、限制出站到链路本地地址，并在应用/WAF 日志中监控指向元数据地址的请求模式。

### 3.2 获取托管标识 Token（系统分配）

- **缺陷描述**：目标资源启用系统分配托管标识，SSRF 或代码执行可请求 token 端点获取面向管理面的 access token，从而以资源身份调用 ARM API。
- **验证命令（只读优先）**：

```bash
# 只读验证：请求面向管理面的 token（系统分配，无需 client_id；resource 为管理面受众）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<管理面受众>"
```

- **影响**：获得的 token 权限取决于该身份被授予的 RBAC 角色，可能直接获得订阅/资源管理权，构成核心提权。
- **检测侧建议**：token 请求本身不写 Activity Log，但 token 后续以托管标识为主体的操作会记录 `initiatedBy` 为托管标识的 Activity Log 事件；Entra ID 登录日志记录该身份的令牌签发/使用。防守方应监控「托管标识发起的异常高权限操作」并与资源行为基线比对。

### 3.3 获取托管标识 Token（用户分配 / client_id）

- **缺陷描述**：目标资源使用用户分配托管标识，token 端点需带 `client_id` 参数；若攻击者已知 clientId（常可从应用配置、前端、错误信息泄露），可定向获取特定身份的 token。
- **验证命令（只读优先）**：

```bash
# 只读验证：请求面向管理面的 token（用户分配，带 client_id；resource 为管理面受众）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=<client-id>&resource=<管理面受众>"
```

- **影响**：用户分配身份可能被多个资源共享，泄露一个身份 token 影响多个资源；跨资源共享身份扩大了横向范围。
- **检测侧建议**：与系统分配类似，token 使用记录在 Activity Log（`initiatedBy` 为用户分配托管标识）与 Entra ID 登录日志。防守方应限制用户分配身份的共享范围，并监控该身份的异常登录/操作。

### 3.4 Token 面向多受众的资源面滥用

- **缺陷描述**：token 可针对不同 `resource` 受众签发，除管理面外还可面向 Key Vault、存储、目录等。若身份被授予相应数据面权限，攻击者可用 token 读取密钥、访问存储或查询目录。
- **验证命令（只读优先）**：

```bash
# 只读验证：请求面向密钥库的 token（仅示意受众切换，最小影响）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<密钥库受众>"
```

- **影响**：从单一 token 端点扩展到多个资源面，攻击者依据身份权限读取密钥、数据或目录对象，扩大影响。
- **检测侧建议**：Key Vault 审计日志（`AuditEvent`）记录 token 鉴权的数据面访问；存储诊断日志记录托管标识访问。防守方应按最小权限控制身份的跨资源授权，并在各资源面日志中监控「非预期身份的读取」。

### 3.5 自定义数据 / 环境变量中的敏感信息

- **缺陷描述**：VM 自定义数据或应用环境变量中存放了连接字符串、密钥、token 等敏感信息，SSRF 读取元数据或代码执行即可直接获取，无需经过 token 请求链路。
- **验证命令（只读优先）**：

```bash
# 只读验证：读取实例自定义数据（部分场景经元数据服务返回）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-02-01"
```

- **影响**：直接泄露可长期使用的静态凭据，绕过托管标识的令牌生命周期管理。
- **检测侧建议**：此类读取不直接产生管理面日志，但应用访问日志与 NSG 流日志可见元数据请求。防守方应避免在自定义数据/环境变量中存放长期凭据，改用托管标识或密钥库。

### 3.6 绕过 SSRF 过滤读取元数据

- **缺陷描述**：应用对 SSRF 做了地址黑名单过滤，但过滤不完整（未覆盖 DNS 重绑定、十进制/十六进制 IP 表示、IPv6 映射、短链跳转、重定向跟随等），攻击者可绕过过滤让服务端最终请求元数据地址。
- **验证命令（只读优先）**：

```bash
# 只读验证：经重定向跟随探测元数据（-L 跟随跳转，最小影响只读实例信息）
curl -s -L -H "Metadata: true" "<可控跳转端点>"
```

- **影响**：过滤形同虚设，元数据服务仍可达，token 窃取链路得以建立。
- **检测侧建议**：应用/WAF 日志记录被重定向/别名请求的最终目标；NSG 流日志可见对 `169.254.169.254` 的最终出站流。防守方应在 DNS 层与应用层双重阻断链路本地地址，并监控重定向到内部地址的请求。

## 四、权限提升与持久化路径

- **SSRF → Token → ARM 提权**：由 SSRF 获取 MSI token → 以身份调用 ARM API → 若身份为所有者/参与者，管理订阅资源，完成数据面到管理面提权。
- **Token 换取其它身份 / 凭据**：用管理面权限读取其它资源密钥（`listKeys`）、创建新服务主体、授予角色，实现横向与持久化。
- **面向 Key Vault 的密钥窃取**：身份若对 Key Vault 有读取权限，用 token 直接读取存储的机密（连接串、私钥），用于持久化或横向。
- **自定义数据/环境变量作为凭据源**：应用从自定义数据或环境变量读取的凭据一旦泄露，可绕过元数据服务直接获得访问。
- **身份角色自我提权**：若托管标识身份被授予角色管理权限，可用其 token 给自己或新主体授予更高角色（写操作，须授权内人工确认后执行）。

## 五、防御与检测要点

关键审计日志事件名清单：

| 服务/日志 | 关键事件 / 操作 |
| --- | --- |
| Azure Activity Log | `initiatedBy` 为托管标识/服务主体的高权限操作 |
| Azure Activity Log | 资源写操作（token 使用侧，如 `Microsoft.Resources/.../write`） |
| Microsoft Entra ID 登录日志 | 托管标识/服务主体的令牌签发与使用 |
| NSG 流日志 | 指向 `169.254.169.254` 的异常出站流 |
| 应用日志 / WAF 日志 | SSRF 触发的指向链路本地地址的请求 |
| Key Vault 诊断日志 | `AuditEvent`（token 鉴权的数据面访问） |
| Microsoft Defender for Cloud | 托管标识权限过宽、SSRF 相关的应用安全建议 |

云检测缺口提示：SSRF 读取元数据与 token 签发本身不产生管理面 Activity Log 事件，攻击者若仅做数据面读取，管理面日志近乎「静默」。防守方必须依赖网络流日志（对元数据地址的出站流）、应用日志与身份登录日志补齐可见性，而非仅依赖 Activity Log。

防御要点小结：应用层严格过滤 SSRF 与出站地址（含链路本地、`169.254.169.254`、内部网段）、托管标识仅授予完成任务所需的最小角色、避免用户分配身份跨资源共享、对「托管标识发起的异常高权限操作」建立告警与行为基线、监控指向元数据地址的网络流。
