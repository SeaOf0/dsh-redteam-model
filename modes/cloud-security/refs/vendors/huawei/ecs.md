# 华为云 ECS 弹性云服务器攻防

> 定位：围绕 ECS 实例、私有镜像、密钥对、安全组、用户数据、元数据服务六类攻击面，
> 给出只读优先的探测命令与配置缺陷利用路径。所有命令以 hcloud CLI 与元数据接口为主，
> 写操作统一标注「授权内人工确认后执行」。每条路径配检测侧对照（CTS 事件名 + 监控可见性）。
> 元数据 SSRF 链详见 `./metadata-ssrf.md`，身份凭证见 `./iam.md`，网络暴露见 `./network.md`。

## 一、攻击面

ECS 是华为云最基础的 IaaS 资源，攻击面围绕「一台虚拟机从创建到运行」的全程暴露点：

- 实例本体：公网弹性 IP（EIP）、操作系统开放端口、SSH/RDP 弱口令或密钥管理不当。
- 私有镜像：镜像内残留历史凭据、SSH 密钥、`cloud-init` 用户数据、构建期写入的 AK/SK。
- 密钥对：`.pem` 私钥泄露、私钥权限过宽（0600 未设）、密钥对绑定多台实例共享。
- 安全组：入方向 `0.0.0.0/0` 放行管理端口（22/3389）、出方向全放行。
- 用户数据（user_data）：创建时注入脚本常含数据库口令、初始化密钥、内网地址。
- 元数据服务：`169.254.169.254` 以 OpenStack 风格暴露实例信息与委托临时凭证。

四要素落点：身份（AK/SK 或委托凭证）→ 权限（IAM 策略覆盖的 ECS 动作）→ 资源（实例/镜像/
密钥对/安全组）→ 影响（读取元数据、SSH 登录、镜像内凭据复用）。

## 二、信息收集 / 暴露面探测

以下命令全部只读，用于枚举 ECS 相关资源与暴露面。执行前先确认 CLI 已配置（`hcloud configure`）。

### 2.1 实例清单枚举

```bash
# 列出全部实例（含实例 ID、名称、状态、规格、私有 IP）
hcloud ecs list-servers

# 查看单个实例详情（含弹性公网 IP、安全组、镜像、元数据配置）
hcloud ecs show-server --server-id <server_id>

# 列出实例挂载的云硬盘（判断数据盘是否加密、是否可快照复制）
hcloud ecs list-server-block-devices --server-id <server_id>
```

### 2.2 密钥对与镜像枚举

```bash
# 列出项目内全部密钥对（判断是否存在长期未轮换/多实例共享的密钥对）
hcloud ecs list-server-keypairs

# 列出私有镜像（判断是否残留构建期凭据，需结合镜像内容检查）
hcloud ims list-images --imagetype private

# 列出公共镜像与市场镜像（识别实例操作系统版本，用于后续补丁面评估）
hcloud ims list-images --imagetype public
```

### 2.3 安全组与端口暴露探测（只读）

```bash
# 列出实例绑定的安全组
hcloud ecs list-security-groups --server-id <server_id>   # 部分版本为关联查询
# 通用做法：从 VPC 侧列出安全组与规则（见 ./network.md）
hcloud vpc list-security-groups
hcloud vpc list-security-group-rules --security-group-id <sg_id>
```

端口暴露可从实例公网 IP 做只读扫描验证（仅对授权目标，逐端口、限速）：

```bash
# 对授权实例的公网 IP 做常见管理端口连通性探测（只读，不写、不爆破）
nc -zv <public_ip> 22 3389 80 443 8080 3306 5432 2>&1
```

### 2.4 用户数据与元数据读取

```bash
# 在已获得实例内执行权限后，读取 cloud-init 用户数据残留
cat /var/lib/cloud/instance/user-data.txt 2>/dev/null
cat /var/lib/cloud/seed/nocloud-net/user-data 2>/dev/null

# 读元数据服务（OpenStack 风格，只读；代理委托凭证详见 ./metadata-ssrf.md）
curl http://169.254.169.254/openstack/latest/meta_data.json
```

## 三、常见配置缺陷与利用路径

### 3.1 元数据服务可被实例内任意进程访问

- 缺陷描述：ECS 默认可从实例内部访问 `169.254.169.254`，若实例上存在 SSRF 或任意命令执行，
  元数据中的委托临时凭证可被窃取；同时实例内非特权进程也能读到 meta_data.json 暴露的内网
  架构信息。
- 验证命令（只读）：

```bash
curl -s http://169.254.169.254/openstack/latest/meta_data.json | head -50
# 观察返回中是否包含 project_id、hostname、uuid 等实例信息
```

- 影响：泄露实例身份与网络拓扑；若实例绑定了委托（agency），可进一步换取临时 AK/SK，
  进入控制面（详见 `./metadata-ssrf.md`）。
- 检测侧建议：CTS 控制面事件 `getMetadata` / `assumeRole`（委托换证）会留痕；数据面读
  meta_data.json 不产生 CTS 事件，属检测盲区，需在实例内通过主机日志或网络层访问监控
  （CES 网络指标）辅助发现，检测缺口明显。

### 3.2 私有镜像残留凭据

- 缺陷描述：使用「整机镜像 / 云服务器备份」制作的私有镜像，常残留原实例的 SSH 私钥、
  `authorized_keys`、数据库口令、`.bash_history`、应用配置中的 AK/SK。
- 验证命令（只读，需先获得一台由该镜像派生的实例的合法登录权）：

```bash
# 检查残留密钥与历史
cat ~/.ssh/id_rsa 2>/dev/null && cat ~/.ssh/authorized_keys 2>/dev/null
cat ~/.bash_history 2>/dev/null | grep -Ei 'passwd|secret|token|ak|sk' 2>/dev/null
# 全盘搜常见凭据文件（只读，限量）
grep -RniE 'AK[A-Z0-9]{10,}|secret_key|password' /etc /opt 2>/dev/null | head -50
```

- 影响：镜像一旦共享给他人（跨项目共享镜像）或用于新实例，凭据随镜像扩散，横向复用。
- 检测侧建议：CTS 事件 `createImage`、`shareImage`（镜像共享）可追溯镜像创建与分享动作；
  镜像内部残留属主机层盲区，需靠实例上线后的主机安全（HSS/企业主机安全）基线扫描发现。

### 3.3 密钥对私钥泄露或权限过宽

- 缺陷描述：SSH 密钥对 `.pem` 私钥在代码仓库、对象存储、协作工具中泄露，或下载后文件权限
  未设为 0600，可被同机其他用户读取；同一密钥对绑定多台实例导致单点泄露全盘沦陷。
- 验证命令（只读）：

```bash
# 检查本地私钥文件权限（0644/0666 即过宽）
ls -l ~/Downloads/*.pem 2>/dev/null
# 用私钥测试能否登录授权实例（只验证连通与身份，不执行破坏性操作）
ssh -i <key.pem> -o BatchMode=yes -o ConnectTimeout=5 <user>@<public_ip> 'whoami' 2>&1
```

- 影响：攻击者拿到私钥即可登录绑定该密钥对的所有实例，形成 SSH 入口持久化。
- 检测侧建议：CTS 事件 `createKeypair`、`importKeypair`、`deleteKeypair` 记录密钥对生命周期；
  SSH 登录成功不产生 CTS 事件，需主机层审计（HSS 登录日志、`/var/log/secure`）配合；异常
  源 IP 的 SSH 登录应触发告警，否则为检测缺口。

### 3.4 用户数据（user_data）注入敏感信息

- 缺陷描述：创建实例时通过 user_data 注入的初始化脚本常硬编码数据库连接串、应用密钥、
  内网服务地址；该数据在实例运行期间可被本地读取，也可能因实例被快照/整机镜像而外泄。
- 验证命令（只读）：

```bash
# 读取 cloud-init 用户数据原始内容
sudo cat /var/lib/cloud/instance/user-data.txt 2>/dev/null
# 从元数据查询 user_data（需具备实例内访问）
curl -s http://169.254.169.254/openstack/latest/user_data 2>/dev/null | head -50
```

- 影响：用户数据是高频凭据泄露源，泄露后可直接连接数据库/内网服务，扩大影响面。
- 检测侧建议：CTS 事件 `createServer`（创建实例时的 user_data 作为参数，但控制面日志通常
  不落 user_data 明文）；数据面读 user_data 无 CTS 事件，属盲区，需依赖实例内文件完整性
  监控或主机审计，检测缺口明确。

### 3.5 安全组入方向放行管理端口到全网

- 缺陷描述：安全组规则将 22/3389/3306 等端口对 `0.0.0.0/0`（或过宽的网段）放行，使实例
  管理面直接暴露在公网，成为爆破与漏洞利用的第一入口。
- 验证命令（只读）：

```bash
hcloud vpc list-security-groups
hcloud vpc list-security-group-rules --security-group-id <sg_id> | grep -E '22|3389|3306|5432'
# 观察 direction=ingress 且 remote_ip_prefix=0.0.0.0/0 的规则
```

- 影响：全网可达的管理端口成为爆破、凭据填充、已知漏洞利用的直接入口，扩大初始访问面。
- 检测侧建议：CTS 事件 `createSecurityGroupRule`、`updateSecurityGroup` 记录规则变更；异常
  登录尝试由 HSS/主机安全告警（暴力破解）；CTS 无「端口被全网放行」的配置合规告警，需
  结合配置审计或态势感知（SA）合规检查补齐，否则为配置态检测缺口。

### 3.6 实例绑定过宽委托或无委托基线

- 缺陷描述：为运维方便给实例绑定高权限委托（agency），或本不该有委托的实例被误绑定，
  一旦实例失陷，攻击者经元数据即可换取等同于委托权限的临时凭证。
- 验证命令（只读）：

```bash
# 查看实例是否绑定委托及委托名称
hcloud ecs show-server --server-id <server_id> | grep -i agency
# 在实例内读取委托相关元数据（详见 ./metadata-ssrf.md）
curl -s http://169.254.169.254/openstack/latest/meta_data.json
```

- 影响：委托权限过宽使「实例失陷」直接放大为「控制面权限失陷」，跳过身份边界。
- 检测侧建议：CTS 事件 `createAgency`、`updateAgency`、`assumeRole`（委托换证）留痕；实例
  元数据被读取不产生 CTS 事件，需结合委托使用审计（IAM 侧调用频次异常）与 CES 指标告警，
  检测缺口集中在数据面读取环节。

## 四、权限提升与持久化路径

- 委托提权：实例内通过元数据换委托临时凭证 → 以委托权限调 `hcloud iam`/`hcloud ecs` 枚举
  并扩大权限（详见 `./metadata-ssrf.md`）。
- 凭据复用提权：从镜像残留/用户数据拿到 AK/SK 或 SSH 私钥 → 登录其他实例 → 横向移动。
- 持久化方式：向 `authorized_keys` 写入攻击者公钥；在用户数据/开机脚本注入反向连接；创建
  共享私有镜像作为后门分发载体。以上写操作均为「授权内人工确认后执行」，本文不提供脚本。
- 数据面持久化盲区：`authorized_keys` 追加、开机脚本注入属主机层操作，CTS 不记录，需 HSS
  文件完整性监控与异常进程检测补齐。

## 五、防御与检测要点

| 层 | 关键动作 | 审计/监控事件（CTS 为主） |
|---|---|---|
| 实例生命周期 | 创建/删除/变更实例 | `createServer`、`deleteServer`、`resizeServer` |
| 镜像 | 制作/共享/导出镜像 | `createImage`、`shareImage`、`exportImage` |
| 密钥对 | 创建/导入/删除密钥对 | `createKeypair`、`importKeypair`、`deleteKeypair` |
| 安全组 | 规则增删改 | `createSecurityGroupRule`、`updateSecurityGroup` |
| 委托 | 创建/更新/换证 | `createAgency`、`updateAgency`、`assumeRole` |
| 数据面（主机层） | SSH 登录、文件篡改、进程异常 | HSS 登录/文件监控、CES 网络指标（非 CTS） |

防御建议：

- 最小化委托：仅对确有需要的实例绑定委托，并收紧委托策略到具体资源与动作。
- 密钥对管控：私钥落地即 0600，禁止多实例共享同一密钥对，定期轮换。
- 镜像安全：制作镜像前清理凭据与历史，共享镜像遵循白名单。
- 用户数据治理：禁止硬编码口令，敏感初始化改走密钥管理（DEW/KMS）。
- 安全组最小化：管理端口收敛到堡垒机网段，杜绝 `0.0.0.0/0`。
- 检测落地：CTS 投递 SIEM + 配置合规（SA）+ 主机 HSS 三层联动，重点补「数据面读取盲区」。

## 审计事件名清单（本节汇总）

`createServer`、`deleteServer`、`resizeServer`、`startServer`、`stopServer`、
`createImage`、`shareImage`、`exportImage`、`createKeypair`、`importKeypair`、
`deleteKeypair`、`createSecurityGroupRule`、`updateSecurityGroup`、`createAgency`、
`updateAgency`、`assumeRole`。
