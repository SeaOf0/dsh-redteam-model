# Azure VM 计算实例攻防

Azure 虚拟机（Virtual Machine，VM）是 Azure 计算层的核心资源，遵循 Azure 资源管理器（ARM）资源模型。攻击面由「管理面」与「数据面」两层构成：管理面指通过 ARM API、az CLI、Portal 对 VM 资源本身的生命周期与配置操作；数据面指登录到 guest OS 之后的操作。二者权限体系相互独立但存在多条跨越边界的利用路径。

## 一、攻击面

- **管理面（ARM 控制面）**：VM 的创建、删除、重启、密码重置、Run Command 调用、扩展（Extension）安装、磁盘挂载/分离、快照复制等。入口是 ARM API 与 `az` CLI，鉴权依赖 Microsoft Entra ID（原 Azure AD）的 RBAC 角色与 Azure 资源级锁。
- **数据面（Guest OS）**：RDP（3389）、SSH（22）、WinRM（5985/5986）、以及应用自暴露的服务端口。鉴权依赖本地账户、域账户或 SSH 密钥。
- **实例元数据服务（IMDS）**：链路本地地址 `169.254.169.254`，guest OS 内可达，是托管标识（Managed Identity）与自定义数据（Custom Data）的出口，也是 SSRF 到云凭证的经典中转点。
- **扩展（Extension）与 Run Command**：VM 扩展是 Azure 平台代执行的插件机制，自定义脚本扩展（CustomScriptExtension）与 Run Command 允许授权主体在 guest OS 内以高权限执行任意命令，本质是「管理面到数据面」的桥。
- **磁盘与快照**：OS 磁盘、数据磁盘、托管磁盘（Managed Disk）、快照（Snapshot）承载持久数据。磁盘若未加密，快照可被复制后挂载到攻击者自己的 VM 直接读盘。
- **凭据与密钥**：管理员用户名/密码、SSH 公钥、开机后可被重置的密码、以及磁盘加密集（Disk Encryption Set）与客户托管密钥（CMK）。

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于摸清订阅内 VM 资产的分布、网络暴露、扩展与磁盘状态。

```bash
# 确认当前登录身份与订阅
az account show

# 列出订阅内所有 VM 及其资源组
az vm list --output table

# 查看单台 VM 详情（含大小、可用区、托管标识、网络配置）
az vm show --resource-group <rg> --name <vm> --show-details

# 列出 VM 的扩展及其预配状态
az vm extension list --resource-group <rg> --vm-name <vm>

# 列出 VM 关联的公网/私网 IP
az vm list-ip-addresses --resource-group <rg> --name <vm>

# 列出所有公网 IP 资源（识别暴露入口）
az network public-ip list --query "[].{ip:ipAddress, name:name}" --output table

# 查看 VM 运行状态与实例视图
az vm get-instance-view --resource-group <rg> --name <vm>

# 列出 VM 内的本地用户（依赖 guest 扩展/agent 返回，只读）
az vm user list --resource-group <rg> --name <vm>

# 列出磁盘与快照
az disk list --query "[].{name:name, encrypted:encryption.type, os:osType}" --output table
az snapshot list --query "[].{name:name, src:creationData.sourceResourceId}" --output table

# 列出 VM 可用的规格（评估实例性能与可用区域）
az vm list-sizes --location <location> --output table
```

探测要点：优先确认 VM 是否分配了公网 IP、NSG 是否放行 22/3389（见 `./network.md`）、是否启用系统分配/用户分配托管标识（`identity` 字段）、磁盘加密类型是否为 `EncryptionAtHost` 或 ADE。

## 三、常见配置缺陷与利用路径

### 3.1 Run Command / 自定义脚本扩展滥用

- **缺陷描述**：持有 `Microsoft.Compute/virtualMachines/runCommand/action` 权限的主体（常见于「虚拟机参与者 Contributor」角色或过度授权的服务主体），可直接在 guest OS 内以 root / SYSTEM 身份执行任意命令，无需登录凭据、无需网络可达性。Run Command 与自定义脚本扩展（CustomScriptExtension）是同一能力的两条入口。
- **验证命令（只读优先）**：

```bash
# 只读验证：以默认命令在 VM 内执行 id / whoami（最小影响）
az vm run-command invoke --resource-group <rg> --vm-name <vm> \
  --command-id RunShellScript --scripts "id"

# 只读验证：查看已安装扩展（判断 CustomScriptExtension 是否已存在）
az vm extension list --resource-group <rg> --vm-name <vm> --output table
```

- **影响**：攻击者在 guest OS 内获得与运行命令等价的最高本地权限；可读取磁盘敏感数据、导出内存/凭据、读取元数据服务托管标识 token（见 `./managed-identity-ssrf.md`），并以此为跳板向管理面或其它资源横向移动。
- **检测侧建议**：Azure Activity Log 会记录 `Microsoft.Compute/virtualMachines/runCommand/action` 与扩展安装 `Microsoft.Compute/virtualMachines/extensions/write` 操作。防守方应在 Sentinel 中监控该类事件，并将执行账户、目标 VM、命令内容（Run Command 参数会出现在日志中）纳入告警。

### 3.2 托管磁盘 / 快照公开与未加密

- **缺陷描述**：磁盘快照或托管磁盘被误设为公开共享（或经共享磁盘/共享快照跨订阅暴露），且 OS 磁盘未启用加密时，攻击者可复制快照到自己订阅，创建新磁盘并挂载到自己的 VM 直接读取全部数据。
- **验证命令（只读优先）**：

```bash
# 只读验证：检查磁盘/快照的公开访问策略与加密状态
az disk list --query "[].[name, networkAccessPolicy, encryption.type]" --output table
az snapshot list --query "[].[name, networkAccessPolicy, encryption.type]" --output table

# 只读验证：查看磁盘是否启用 Azure 磁盘加密（ADE）或加密集
az disk show --resource-group <rg> --name <disk> --query "{enc:encryption, osType:osType}"
```

- **影响**：一旦快照可被复制，等价于整盘数据（系统凭据、应用密钥、数据库文件、SSH 私钥等）泄露；即便 VM 本身未暴露公网端口，该路径也能绕过网络隔离。
- **检测侧建议**：Activity Log 记录 `Microsoft.Compute/disks/write`、`Microsoft.Compute/snapshots/write`、`Microsoft.Compute/snapshots/beginGetAccess/action`（授予快照访问 SAS）。防守方应监控跨订阅的磁盘/快照创建与 `beginGetAccess` 调用，并定期用 Defender for Cloud 扫描「磁盘未加密」「快照公开」的合规项。

### 3.3 公网 RDP/SSH 暴露 + 弱凭据 / 凭据复用

- **缺陷描述**：VM 分配公网 IP 且 NSG 放行 22/3389 到互联网（`0.0.0.0/0`），配合弱密码、默认账户或跨机器复用凭据，成为最直接的初始访问路径。
- **验证命令（只读优先）**：

```bash
# 只读验证：定位暴露到公网的 VM 及其 NSG 放行规则
az vm list-ip-addresses --query "[?publicIpAddresses].{name:name, ip:publicIpAddresses[0].ipAddress}" --output table

# 只读验证：查看 NSG 是否放行 22/3389 到 0.0.0.0/0（见 network.md）
az network nsg rule list --resource-group <rg> --nsg-name <nsg> \
  --query "[?destinationPortRange=='22'||destinationPortRange=='3389'].{rule:name, src:sourceAddressPrefix}" --output table
```

- **影响**：攻击者获得 guest OS 初始立足点，可进一步提权、横向、读取 MSI token 或持久化。
- **检测侧建议**：NSG 流日志（NSG Flow Logs）记录允许/拒绝的流；guest OS 内 Linux `auth.log` 的 SSH 失败记录、Windows 安全事件 `4625`（登录失败）与 `4624`（登录成功）可复现暴力破解。防守方应把「公网 22/3389 + 大量 4625 + 快速成功登录」作为初始访问告警组合。

### 3.4 元数据服务 / 托管标识滥用

- **缺陷描述**：guest OS 内可达的 `169.254.169.254` 元数据服务在 VM 启用系统分配托管标识时，会无条件签发访问 Azure 管理面/资源面的 access token，任何能在 guest 内执行代码的主体（含 SSRF 触发的服务端请求）都可据此冒充 VM 身份。
- **验证命令（只读优先）**：

```bash
# 只读验证：读取实例元数据（需 Metadata 头）
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 只读验证：查看 VM 是否启用托管标识（管理面视角）
az vm show --resource-group <rg> --name <vm> \
  --query "identity" --output json
```

- **影响**：MSI token 的权限取决于分配给该 VM 身份的 RBAC 角色，可能直接获得对订阅、存储、Key Vault 的读写，构成从数据面到管理面的权限提升。
- **检测侧建议**：token 请求走元数据服务，不直接产生 Activity Log 事件，但 token 的后续使用会以 VM 托管标识为主体记录在 Activity Log 中。防守方应结合 Entra ID 登录日志（服务主体登录）与 Activity Log 中 `initiatedBy` 为托管标识的操作做行为基线；详细路径见 `./managed-identity-ssrf.md`。

## 四、权限提升与持久化路径

- **MSI token 提权**：从 guest OS 内读取托管标识 token → 以 VM 身份调用 ARM API → 若该身份被授予过高 RBAC 角色（如 Contributor），可管理订阅内其它资源，完成跨资源提权。详见 `./managed-identity-ssrf.md`。
- **Run Command 作为持久化后门**：攻击者若已持有 `runCommand/action` 权限，可周期性调用 Run Command 执行指令，绕过 guest 内杀软与登录审计，作为「管理面级」持久化。
- **自定义脚本扩展持久化**：通过 `az vm extension set` 安装/更新 CustomScriptExtension，注入开机自启脚本或计划任务。
- **密码重置与账户后门**：持有 `Microsoft.Compute/virtualMachines/write` 权限可调用 `az vm user update --password` 重置管理员密码；或在 guest 内新增用户、追加 SSH authorized_keys。以下为破坏性/写操作，须「授权内人工确认后执行」：

```bash
# 以下为写操作示例，仅示意，须授权内人工确认后执行
az vm user update --resource-group <rg> --name <vm> --username <admin> --password <new-pass>
```

- **磁盘/快照窃取**：将目标 OS 磁盘/快照复制到攻击者订阅（`beginGetAccess` 授予 SAS 后下载或直接挂载），离线提取凭据与数据，避免触碰目标 guest。

## 五、防御与检测要点

关键审计日志事件名清单（供 Sentinel / Defender for Cloud 告警与狩猎）：

| 服务/日志 | 关键事件 / 操作 |
| --- | --- |
| Azure Activity Log | `Microsoft.Compute/virtualMachines/runCommand/action` |
| Azure Activity Log | `Microsoft.Compute/virtualMachines/extensions/write` |
| Azure Activity Log | `Microsoft.Compute/virtualMachines/write`（配置变更/密码重置路径） |
| Azure Activity Log | `Microsoft.Compute/disks/write`、`Microsoft.Compute/snapshots/write` |
| Azure Activity Log | `Microsoft.Compute/snapshots/beginGetAccess/action` |
| NSG 流日志 | 公网到 22/3389 的允许流与突发连接 |
| guest OS 日志 | Windows `4625`/`4624`、Linux `auth.log` 失败登录 |
| Microsoft Entra ID | 托管标识/服务主体登录日志（`initiatedBy` 关联） |
| Microsoft Defender for Cloud | 磁盘未加密、快照公开、VM 无端点保护等建议 |

防御要点小结：默认禁用公网 SSH/RDP（经 Bastion 或 VPN）、对 VM 启用磁盘加密（ADE/CMK/EncryptionAtHost）、最小化托管标识的 RBAC 角色、对 Run Command 与扩展操作建立变更审批与告警、在 Sentinel 中对 `runCommand/action` 与跨订阅磁盘操作设置高优先级规则。
