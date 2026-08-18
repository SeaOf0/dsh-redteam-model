# ECS 计算实例攻防

本文覆盖阿里云 ECS 弹性计算实例在授权评估中的攻击面、暴露面探测、常见配置缺陷与利用路径、权限提升与持久化，以及对应检测要点。所有命令以只读探测与最小影响验证为优先，破坏性操作须在授权范围内人工确认后执行。

## 一、攻击面

ECS 是云上最核心的计算资源，攻击面集中于实例本身与围绕它的配置对象：

- **实例**：操作系统漏洞、未修复组件、弱口令、高危服务暴露。
- **镜像**：公共镜像、自定义镜像、共享镜像可能包含敏感数据、残留凭据或恶意后门。
- **密钥对**：KeyPair 私钥泄漏、未轮换、多实例复用同一密钥。
- **安全组**：入方向放行 `0.0.0.0/0` 到高危端口，或规则过于宽松。
- **用户数据**：UserData 内明文写入数据库口令、AccessKey、初始化脚本。
- **元数据服务**：实例内通过固定链路地址可读取实例属性与 RAM 角色临时凭证。
- **实例 RAM 角色**：绑定给实例的角色权限过大时，实例内任意进程均可换取云 API 权限。

各对象间存在信任传导：实例内任意代码执行 → 元数据读取 → 角色临时凭证 → 云 API 调用，是 ECS 场景最核心的一条提权链。

## 二、信息收集 / 暴露面探测

已获得一组可用凭据或立足点后，先用只读命令摸清实例、安全组、镜像、密钥对与网络暴露情况。

```bash
# 列出某地域全部 ECS 实例（含实例 ID、名称、状态、内网/公网 IP）
aliyun ecs DescribeInstances --RegionId cn-hangzhou

# 查看单个实例详情（镜像、vSwitch、安全组、实例角色等）
aliyun ecs DescribeInstanceAttribute --InstanceId i-xxxxxxxx --RegionId cn-hangzhou

# 列出安全组及其规则（判断高危端口是否对公网开放）
aliyun ecs DescribeSecurityGroups --RegionId cn-hangzhou
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId sg-xxxxxxxx --RegionId cn-hangzhou

# 列出镜像（含自定义/共享镜像，用于识别可能残留凭据的镜像）
aliyun ecs DescribeImages --RegionId cn-hangzhou

# 列出密钥对（识别复用与未轮换的密钥）
aliyun ecs DescribeKeyPairs --RegionId cn-hangzhou

# 列出实例关联的 RAM 角色（元数据凭证链路的先决条件）
aliyun ecs DescribeInstanceRamRole --RegionId cn-hangzhou
```

已进入某台实例后，从实例内部探测元数据服务与本地敏感信息：

```bash
# 读取元数据根目录（实例属性、网络、用户数据等）
curl http://100.100.100.200/latest/meta-data/

# 读取本实例绑定的 RAM 角色名（若为空则无角色）
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/

# 读取用户数据（可能含明文凭据与初始化脚本）
curl http://100.100.100.200/latest/user-data/

# 读取本机公网 IP、实例 ID、镜像 ID 等属性
curl http://100.100.100.200/latest/meta-data/instance-id
curl http://100.100.100.200/latest/meta-data/image-id
```

## 三、常见配置缺陷与利用路径

### 3.1 安全组放行公网访问高危端口

**缺陷描述**：安全组入方向规则对 `0.0.0.0/0` 开放 SSH(22)、RDP(3389)、数据库(3306/5432/1433)、Redis(6379) 等端口，使实例直接暴露于公网。

**验证命令（只读优先）**：

```bash
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId sg-xxxxxxxx --RegionId cn-hangzhou
# 关注 SourceCidrIp=0.0.0.0/0、PortRange 覆盖 22/3389/3306/6379 的规则
```

**影响**：暴露端口一旦存在弱口令、未认证服务或已知漏洞，即可被直接利用，成为云上初始入侵的常见入口。

**检测侧建议**：云监控(CloudMonitor)可对安全组规则变更与异常网络流量告警；安全中心(Security Center)可对公网暴露的脆弱端口与爆破行为告警。审计侧对应 `AuthorizeSecurityGroup` 事件（见 `./network.md`）。

### 3.2 密钥对私钥泄漏或复用

**缺陷描述**：KeyPair 私钥在代码仓库、跳板机、聊天记录中泄漏，或同一密钥对绑定多台实例，导致单点私钥失陷后多实例横向。

**验证命令（只读优先）**：

```bash
# 枚举密钥对绑定情况，识别复用
aliyun ecs DescribeKeyPairs --RegionId cn-hangzhou

# 进入实例后检查 authorized_keys，确认对应密钥指纹
cat ~/.ssh/authorized_keys
```

**影响**：私钥泄漏等于获得对应实例的 SSH 登录能力；复用密钥会放大影响范围。

**检测侧建议**：安全中心可采集实例登录成功/失败事件；ActionTrail 记录 `ImportKeyPair`、`AttachKeyPair`、`DetachKeyPair` 等密钥对操作，可用于回溯密钥引入与绑定变更。

### 3.3 用户数据明文存储敏感信息

**缺陷描述**：创建实例时在 UserData 中写入数据库口令、AccessKey、私钥、内网地址等敏感信息，且未加密或未及时清理。

**验证命令（只读优先）**：

```bash
# 从实例内部读取用户数据
curl http://100.100.100.200/latest/user-data/

# 从控制面查看实例的 UserData（仅可见于创建时的元数据）
aliyun ecs DescribeUserData --InstanceId i-xxxxxxxx --RegionId cn-hangzhou
```

**影响**：任何能读取元数据的进程（含 SSRF、容器逃逸后的进程）均可提取明文凭据，直接用于进一步访问。

**检测侧建议**：元数据读取行为在实例内不易被常规主机监控覆盖；应在云侧通过安全中心主机安全基线约束 UserData 内容，并在交付前对实例镜像做敏感信息扫描。

### 3.4 元数据服务可访问且绑定高权限角色

**缺陷描述**：实例绑定了权限过大的 RAM 角色（如 `AdministratorAccess` 或宽泛 `*:*` 策略），且未启用元数据加固模式，实例内任意进程可无鉴权读取角色临时凭证。

**验证命令（只读优先）**：

```bash
# 查看角色名
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/

# 读取角色临时凭证（AccessKeyId/AccessKeySecret/SecurityToken）
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>
```

**影响**：凭证可离线用于云 API 调用，权限等同于角色本身；若角色可调用 RAM、OSS、RDS 等接口，即形成完整提权与数据访问链路（见 `./ram.md`、`./ssrf-console.md`）。

**检测侧建议**：ActionTrail 记录 `AssumeRole` 与后续各服务 API 调用；若凭证被外部主机使用，调用方 IP 与实例 IP 不一致可作为异常指标。云监控可对元数据服务高频访问配置告警。

## 四、权限提升与持久化路径

- **元数据凭证提权**：实例内读取角色临时凭证 → 调用 STS/RAM 接口确认身份与权限 → 若具备 `CreateUser`、`AttachPolicyToUser` 权限，创建高权限子用户实现持久化（完整链路见 `./ssrf-console.md`）。
- **密钥对替换**：具备 ECS 写权限时，为实例绑定新的自有密钥对以维持 SSH 访问（`AttachKeyPair`），须授权内人工确认后执行。
- **用户数据注入**：通过重装系统盘（`ReplaceSystemDisk`）或重启前注入脚本建立驻留；此类操作破坏实例运行状态，须授权内人工确认后执行。
- **镜像投毒**：向共享镜像或自定义镜像写入后门，使后续新实例继承恶意配置；属于影响面较大的持久化方式，须授权内人工确认后执行。
- **安全组开口**：新增或修改安全组规则为自己预留访问通道，审计侧可见 `AuthorizeSecurityGroup`。

持久化操作普遍会留下 `CreateInstance`、`ReplaceSystemDisk`、`AttachKeyPair`、`AuthorizeSecurityGroup` 等 ActionTrail 事件，蓝队应重点关联「新对象创建 + 高权限授予 + 规则放开」三要素。

## 五、防御与检测要点

审计日志事件名清单（ActionTrail）：

| 事件名 | 含义 | 风险提示 |
| --- | --- | --- |
| `RunInstances` / `CreateInstance` | 创建实例 | 关注非授权时间段批量创建 |
| `ReplaceSystemDisk` | 重装系统盘 | 可能伴随持久化注入 |
| `AttachKeyPair` / `DetachKeyPair` | 绑定/解绑密钥对 | 关注新密钥对绑定 |
| `ImportKeyPair` | 导入密钥对 | 外部私钥引入 |
| `AuthorizeSecurityGroup` | 放行安全组规则 | 关注放行 `0.0.0.0/0` |
| `ModifyInstanceAttribute` | 修改实例属性 | 关注绑定实例角色变更 |
| `AttachInstanceRamRole` / `DetachInstanceRamRole` | 绑定/解绑实例角色 | 元数据凭证链路的开关 |
| `DescribeInstances` | 枚举实例 | 高频调用可作为侦察指标 |

防御建议：

- 安全组最小化放行，高危端口禁止 `0.0.0.0/0`，改用跳板机或 IP 白名单。
- 启用元数据加固模式，实例内须携带 `X-aliyun-ecs-metadata-token` 头才能读取敏感元数据。
- 实例角色遵循最小权限，避免绑定 `AdministratorAccess` 或 `*:*` 策略。
- UserData 与镜像禁止存放明文凭据；密钥对按实例隔离并定期轮换。
- 在云监控与安全中心配置公网暴露、异常登录、元数据高频访问、安全组规则变更告警。
