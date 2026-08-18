# Compute Engine 计算实例攻防

Compute Engine 是 GCP 的 IaaS 计算服务，承载虚拟机实例。实例的安全态势由四个要素共同决定：启动脚本（startup script）、附加的服务账号（service account）、实例的访问范围（scope）以及实例/项目元数据（metadata）。其中服务账号与 scope 的组合是横向与纵向移动的核心抓手——实例上运行代码所能触达的 GCP 权限，本质上等于「实例附加服务账号的权限」与「实例 scope 允许的 OAuth 范围」两者取交集。

## 一、攻击面

Compute Engine 的攻击面可归纳为以下几条主线：

1. **实例元数据**：项目级与实例级 metadata 可存放自定义键值，常被误用来保存口令、私钥、内部地址等敏感信息；同时 `ssh-keys`、`startup-script` 等特殊键会直接改变实例行为。
2. **启动脚本**：`startup-script`、`startup-script-url`、`windows-startup-script-*` 在实例每次启动（或首次启动）时以 root/管理员身份执行，是命令注入与持久化的高价值入口。
3. **服务账号与 scope**：默认服务账号 `PROJECT_NUMBER-compute@developer.gserviceaccount.com` 若被授予过宽角色，且实例 scope 为 `cloud-platform`（全量），则实例内任意代码都能以该账号身份访问 GCP API。
4. **SSH 元数据密钥**：未启用 OS Login 时，项目 metadata 中的 `ssh-keys` 可向全部实例注入公钥；项目级 `enable-oslogin` 未开启会让密钥分散在实例间难以回收。
5. **串行端口输出**：`get-serial-port-output` 可读取实例启动日志，若启动脚本回显了敏感环境变量，攻击者可借此无认证读取。
6. **磁盘与镜像**：公开镜像、自定义镜像携带的历史凭据、磁盘快照的共享范围。
7. **屏蔽虚机（Shielded VM）缺失**：未启用 Secure Boot、vTPM、完整性监控的实例更易被引导级篡改。

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于在获得某个项目或账号的访问权限后，枚举实例资产与权限面。命令用途写在注释中。

```bash
# 列出当前可访问项目下的全部实例
gcloud compute instances list

# 查看单个实例的完整配置：机器类型、服务账号、scope、metadata、磁盘、网络接口
gcloud compute instances describe <INSTANCE> --zone <ZONE>

# 查看实例当前附加的服务账号及 scope（describe 输出中的 serviceAccounts 字段）
gcloud compute instances describe <INSTANCE> --zone <ZONE> \
  --format="flattened(serviceAccounts)"

# 查看实例启动脚本内容（若存在）
gcloud compute instances describe <INSTANCE> --zone <ZONE> \
  --format="value(metadata.items[].value)"

# 查看项目级通用元数据（ssh-keys 常在此处）
gcloud compute project-info describe --format="value(commonInstanceMetadata.items)"

# 读取实例串行端口输出（启动日志）
gcloud compute instances get-serial-port-output <INSTANCE> --zone <ZONE>

# 查看实例磁盘及其是否启用了删除保护、是否可被快照
gcloud compute disks list

# 查看快照与镜像（注意自定义镜像是否公开）
gcloud compute snapshots list
gcloud compute images list --no-standard-images

# 查看实例标签与网络标签（network tags 关联防火墙规则）
gcloud compute instances describe <INSTANCE> --zone <ZONE> \
  --format="value(tags.items,networkInterfaces[].network)"
```

探测要点：优先关注 `serviceAccounts` 字段中邮箱后缀与 scope 是否为 `cloud-platform`；关注 `metadata` 中是否出现 `startup-script`、`startup-script-url`、`ssh-keys` 等键；关注自定义镜像与快照的共享范围是否公开。

## 三、常见配置缺陷与利用路径

### 3.1 默认服务账号 + cloud-platform 全量 scope

**缺陷描述**：实例创建时未显式指定服务账号与 scope，GCP 会回退到默认服务账号，且部分模板/控制台会默认勾选「允许对所有 Cloud API 的完全访问」，即 scope 为 `https://www.googleapis.com/auth/cloud-platform`。此时实例内代码可用该账号身份调用几乎所有 GCP API，权限完全取决于默认服务账号被授予的 IAM 角色。

**验证命令（只读优先）**：

```bash
# 在实例内验证当前服务账号与 scope
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# 读取当前实例身份 token（只读，返回 JSON，含 access_token）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

实际验证通常直接调用 Cloud API 探活，例如：

```bash
# 只读验证当前身份可见的项目（最小影响）
gcloud projects list
# 只读验证当前身份可见的存储桶（需 storage scope，cloud-platform 则通吃）
gcloud storage ls
```

**影响**：实例上任意可执行代码的位置（应用漏洞、供应链组件、临时文件写入点）都可直接升级为对项目 GCP API 的完全访问，构成「实例入侵 → 云控制面接管」的最短路径。

**检测侧建议**：攻击者调用元数据获取 token 的动作本身不落 Cloud Audit Logs（元数据服务不产生 Admin Activity 记录），但随后用该 token 调用的 API 会以服务账号身份记录。应在 Cloud Logging 中关注该默认服务账号首次出现在非预期 API 调用中的情况，并结合 Security Command Center 的「过宽 scope」「默认服务账号持有高权限角色」发现项。数据面 API 调用需已开启 Data Access logs 才可见。

### 3.2 启动脚本含敏感信息或可注入命令

**缺陷描述**：`startup-script` 常被用来拉取配置、写入密钥、初始化服务，若脚本内硬编码口令/私钥/数据库连接串，或以 root 身份执行从实例 metadata 或外部输入拼接的命令，则构成敏感信息泄露与命令注入点。

**验证命令（只读优先）**：

```bash
# 只读查看实例启动脚本全文
gcloud compute instances describe <INSTANCE> --zone <ZONE> \
  --format="json(metadata.items)"
```

**影响**：硬编码凭据可被具备 `compute.instances.get` 权限的任意账号读出；启动脚本以 root 身份执行，若其内容受攻击者可控（如从 metadata 变量拼接），可在实例内植入持久后门。

**检测侧建议**：读取实例 metadata 的 API 调用 `compute.instances.get` 与 `compute.projects.get` 会写入 Cloud Audit Logs（Admin Activity）；修改启动脚本的 `compute.instances.setMetadata` 是重点审计事件。SCC 的「实例启动脚本包含敏感数据」类发现项可直接命中硬编码密钥。

### 3.3 项目级 ssh-keys 元数据密钥注入

**缺陷描述**：未启用 OS Login 的实例会把项目 metadata 中 `ssh-keys` 内列出的公钥注入所有实例的 `~/.ssh/authorized_keys`。持有 `compute.projects.setCommonInstanceMetadata` 权限者可在不改动实例的前提下，向全项目实例追加公钥，实现 SSH 登录。

**验证命令（只读优先）**：

```bash
# 只读检查项目是否启用了 OS Login（enable-oslogin）
gcloud compute project-info describe \
  --format="value(commonInstanceMetadata.items)"

# 只读查看实例上 OS Login 状态
gcloud compute instances describe <INSTANCE> --zone <ZONE> \
  --format="value(metadata.items)"
```

**影响**：项目级 `ssh-keys` 是横向移动的「一键铺开」入口：一次写入即可获得全部未启用 OS Login 实例的 SSH 访问，且这类登录走 SSH 通道，不直接产生云控制面审计。

**检测侧建议**：修改项目公共 metadata 的 `compute.projects.setCommonInstanceMetadata` 事件必须重点监控。OS Login 方式下，SSH 登录经 IAM 鉴权，会在 Cloud Logging 中留下 `compute.instances.osLogin` 相关记录，而传统 `ssh-keys` 注入几乎不产生云侧登录审计——这正是建议强制开启 OS Login 的核心理由。

### 3.4 串行端口输出泄露启动信息

**缺陷描述**：实例串行端口默认对所有具备 `compute.instances.getSerialPortOutput` 权限的账号可读。若启动脚本或应用把 token、口令、内部 IP 等回显到控制台，可被无认证路径（配合其它权限）读出。

**验证命令（只读优先）**：

```bash
gcloud compute instances get-serial-port-output <INSTANCE> --zone <ZONE>
```

**影响**：串行端口输出是常见的信息泄露通道，尤其当实例启动脚本通过 `echo` 打印敏感变量时。攻击者可据此获取内部网络拓扑或初始凭据，为后续横向移动铺路。

**检测侧建议**：`compute.instances.getSerialPortOutput` 属于 Admin Activity 事件，可在 Cloud Audit Logs 中检索；对高价值实例建议关闭「允许从串口控制台读写」（实例创建选项），并审计频繁读取串口的账号。

### 3.5 自定义镜像/快照共享范围过宽

**缺陷描述**：自定义镜像或磁盘快照若被设为「公开」或共享给过宽范围，其他项目可直接基于其创建实例，从而复现镜像内残留的凭据、SSH 密钥、历史配置与应用代码。

**验证命令（只读优先）**：

```bash
# 只读查看快照是否公开共享
gcloud compute snapshots list --format="table(name,sourceDisk,status)"

# 只读查看镜像是否公开（guestOsFeatures/标签与源）
gcloud compute images list --no-standard-images --format="table(name,family,status)"
```

**影响**：镜像/快照共享范围失控等价于把「带完整历史的系统盘」交给外部，残留密钥与内部地址全部暴露，属于高影响配置缺陷。

**检测侧建议**：修改镜像/快照 IAM 或公开性的操作对应 `compute.images.setIamPolicy`、`compute.snapshots.setIamPolicy` 事件；SCC 会对「公开镜像」「公开快照」给出高风险发现项。

## 四、权限提升与持久化路径

**权限提升主线**：

1. **scope 差集放大**：实例 scope 只能收窄不能放大已授权 OAuth 范围，但攻击者若拿到一个只有受限 scope 的实例内凭据，可通过元数据服务请求受限 scope 对应的 token；真正放大源于「服务账号权限 > 当前 scope」的错配，此时只需在能控制 scope 的位置（重建实例、修改模板）或切换到该服务账号密钥即可。
2. **服务账号密钥接管**：若攻击者能读到实例内挂载的服务账号密钥文件（如容器内挂载的密钥卷或挂载点），可直接脱离 scope 限制，以该账号离线调用 API。相关细节见 `./iam.md`。
3. **默认服务账号 → 高权限角色**：默认服务账号若被误授 `roles/editor` 甚至 `roles/owner`，则实例入侵直接等于项目接管。
4. **通过 setMetadata 自我提权**：具备 `compute.instances.setMetadata` 权限者，可给目标实例注入新的 `startup-script`（重启后以 root 执行）或注入 `ssh-keys`，从而在实例内获得执行能力。

**持久化路径**：

1. **启动脚本持久化**：在实例 metadata 写入 `startup-script`，每次重启都重新执行后门逻辑。
2. **快照/镜像持久化**：在实例内植入后门后创建自定义镜像，后续基于该镜像新建实例天然携带后门；此操作对应 `compute.images.insert`，需授权内人工确认后执行。
3. **服务账号密钥持久化**：创建新的服务账号密钥长期持有（见 `./iam.md`），不依赖实例生命周期。
4. **SSH 公钥持久化**：向项目 metadata 的 `ssh-keys` 追加自己的公钥，长期保留 SSH 入口。

## 五、防御与检测要点

审计日志事件名清单（Cloud Audit Logs / Cloud Logging）：

| 事件名 | 含义 | 关注点 |
| --- | --- | --- |
| `compute.instances.setMetadata` | 修改实例 metadata | 注入 startup-script / ssh-keys 的前置动作 |
| `compute.instances.insert` | 创建实例 | 关注 scope 与服务账号选择 |
| `compute.instances.setServiceAccount` | 更换实例服务账号 | 权限面变更 |
| `compute.instances.getSerialPortOutput` | 读取串口输出 | 信息泄露探测 |
| `compute.projects.setCommonInstanceMetadata` | 修改项目公共 metadata | 项目级 ssh-keys 注入 |
| `compute.instances.setShieldedInstanceIntegrityPolicy` | 修改完整性策略 | 关闭防护 |
| `compute.images.insert` / `compute.images.setIamPolicy` | 创建镜像 / 修改镜像共享 | 镜像持久化与公开 |
| `compute.snapshots.setIamPolicy` | 修改快照共享 | 快照泄露 |
| `compute.disks.setIamPolicy` | 修改磁盘共享 | 磁盘泄露 |
| `iam.serviceAccounts.actAs` | 以服务账号身份动作 | 与实例服务账号关联的动作 |

防御建议：

- 实例一律显式指定最小权限服务账号，禁止默认服务账号持有项目级写权限角色。
- 实例 scope 按需收窄（如仅 `storage-ro`、`logging-write`），避免 `cloud-platform` 全量。
- 全项目强制开启 OS Login，禁用 metadata `ssh-keys` 注入。
- 启用 Shielded VM（Secure Boot + vTPM + 完整性监控），对高价值实例开启串口读禁用。
- 敏感启动脚本避免回显、避免硬编码密钥，改用 Secret Manager 注入。
- 在 Cloud Logging 中对上述 `setMetadata`、`setCommonInstanceMetadata`、`setIamPolicy` 事件建立告警。
