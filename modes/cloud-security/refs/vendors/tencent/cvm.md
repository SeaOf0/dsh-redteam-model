# CVM 云服务器攻防

> 面向授权安全测试的 CVM（云服务器）攻击面梳理与方法论，涵盖实例、镜像、密钥对、安全组、用户数据与元数据。所有验证以只读探测优先，破坏性操作需「授权内人工确认后执行」。

## 一、攻击面

CVM 是腾讯云 IaaS 核心计算资源，其安全边界由实例本身、网络（安全组/VPC）、身份（CAM/密钥对/角色）、镜像与引导配置共同构成。攻击面可归纳为：

- **网络暴露面**：公网 IP、安全组入站规则、暴露端口与服务。
- **实例配置面**：用户数据（UserData）、角色绑定、登录方式（密码/密钥对）。
- **镜像面**：公共镜像、自定义镜像、共享镜像、镜像内残留敏感信息。
- **身份凭据面**：密钥对私钥、实例角色、元数据服务中的临时凭证。
- **管理面**：控制台/API 的 CAM 权限、操作审计缺口。

下表列出 CVM 攻击面与对应防守视角：

| 攻击面 | 攻击者关注点 | 防守者关注点 |
| --- | --- | --- |
| 安全组 | 0.0.0.0/0 全端口放行 | `ModifySecurityGroupPolicies` 审计 |
| 密钥对 | 私钥泄露、弱口令管理 | 登录审计、密钥轮换 |
| 镜像 | 共享镜像信息泄露 | `ModifyImageSharePermission` 审计 |
| 用户数据 | 明文口令/脚本残留 | `RunInstances`、启动脚本审计 |
| 元数据 | 实例角色凭证窃取 | `AssumeRole` 审计、SSRF 应用日志 |

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于枚举当前账号授权范围内的 CVM 资产与配置。执行前确认已配置 tccli 与目标地域（`--region`）。

```bash
# 列出实例
tccli cvm DescribeInstances

# 列出安全组
tccli cvm DescribeSecurityGroups

# 列出密钥对
tccli cvm DescribeKeyPairs

# 列出镜像（含自定义镜像）
tccli cvm DescribeImages

# 列出可用区
tccli cvm DescribeZones
```

从 `DescribeInstances` 返回中重点提取：公网 IP、安全组 ID、密钥对 ID、角色绑定（`CamRoleName` 字段）、VPC/子网 ID、镜像 ID。

从 `DescribeSecurityGroups` 与 `DescribeSecurityGroupPolicies` 提取入站规则，识别 `0.0.0.0/0`、`::/0` 全放行及敏感端口（22/3389/6379/27017 等）。

## 三、常见配置缺陷与利用路径

### 3.1 安全组 0.0.0.0/0 全端口放行

**缺陷描述**：安全组入站规则误配为任意网段（`0.0.0.0/0` 或 `::/0`）且放行全部端口或敏感端口，导致实例管理端口与数据库端口直接暴露公网。

**验证命令（只读优先）**：

```bash
# 查看安全组入站规则（只读）
tccli vpc DescribeSecurityGroupPolicies --SecurityGroupId sg-xxxxx
```

确认 `Ingress` 规则中 `CidrBlock` 为 `0.0.0.0/0` 且 `Action` 为 `ACCEPT`。

**影响**：攻击者可直接对暴露端口发起暴力破解、漏洞利用或未授权访问（如 Redis/MongoDB 未授权），进而获取实例控制权。

**检测侧建议**：攻击行为在实例侧表现为异常登录与异常网络连接；管理侧可依赖安全运营中心（SOC）的暴露面检测与云监控的流量告警。安全组变更可由 CloudAudit 事件 `ModifySecurityGroupPolicies` 追踪。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 端口扫描 + 服务指纹 + 弱口令/未授权尝试 |
| 防守者 | 云监控流量告警、SOC 暴露面扫描、CloudAudit `ModifySecurityGroupPolicies` |

### 3.2 密钥对私钥泄露

**缺陷描述**：密钥对私钥被提交至代码仓库、备份目录或通过弱口令保护，导致持有私钥者可直接登录实例。

**验证命令（只读优先）**：

```bash
# 枚举账号内密钥对（只读）
tccli cvm DescribeKeyPairs
```

结合实例列表确认哪些实例绑定了泄露密钥（`KeyIds` 字段）。

**影响**：私钥泄露等同于实例登录凭据泄露，攻击者可直接 SSH/RDP 登录，进一步横向移动或植入持久化。

**检测侧建议**：登录行为由实例侧主机日志（SSH 登录日志）记录；云侧可通过 SOC 异常登录告警识别异地/异常调用方登录。CAM 侧密钥对管理操作事件（如 `CreateKeyPair`）由 CloudAudit 记录。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 私钥直接登录，无管理面痕迹 |
| 防守者 | 主机登录日志、SOC 异常登录、CloudAudit `CreateKeyPair` |

### 3.3 镜像共享与自定义镜像信息泄露

**缺陷描述**：自定义镜像或共享镜像内残留敏感信息（历史口令、私钥、配置、源代码），或镜像被意外共享给外部账号。

**验证命令（只读优先）**：

```bash
# 列出全部镜像，识别共享/自定义镜像（只读）
tccli cvm DescribeImages
```

检查镜像 `ImageState`、`ImageSource`，以及是否存在跨账号共享（`ImageSharePermission`）。

**影响**：攻击者从共享镜像启动实例后，可直接提取镜像内历史数据与凭据，实现凭据复用与权限扩散。

**检测侧建议**：镜像共享与启动行为由 CloudAudit `ModifyImageSharePermission`、`RunInstances` 事件记录；SOC 可对镜像导出/共享行为设置告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 从共享镜像启动实例提取残留数据 |
| 防守者 | CloudAudit `ModifyImageSharePermission`、`RunInstances` |

### 3.4 用户数据（UserData）敏感信息残留

**缺陷描述**：实例创建时通过 UserData 注入的启动脚本中硬编码口令、数据库连接串、私钥或 CAM 密钥，任何可读取实例元数据或拥有实例查看权限者均可获取。

**验证命令（只读优先）**：

```bash
# 查看实例创建配置与用户数据（只读，需对应 CAM 权限）
tccli cvm DescribeInstancesAttribute --InstanceId ins-xxxxx
```

UserData 亦可经实例内部元数据接口读取（见 `./metadata-ssrf.md`）。

**影响**：UserData 明文凭据泄露可直接导致数据库、对象存储或内部系统被接管。

**检测侧建议**：UserData 写入依赖实例创建事件 `RunInstances`；实例内元数据读取行为依赖主机侧日志与云监控。建议对含敏感关键字的 UserData 做静态检测。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 元数据接口或 API 读取 UserData |
| 防守者 | CloudAudit `RunInstances`、主机侧启动脚本审计 |

### 3.5 元数据服务暴露

**缺陷描述**：实例绑定 CAM 角色后，元数据服务可返回该角色的临时凭证。若实例内存在 SSRF 或任意文件读取，攻击者可借此获取角色权限。

**验证命令（只读优先）**：

```bash
curl http://metadata.tencentyun.com/latest/meta-data/
```

详细路径与凭证利用见 `./metadata-ssrf.md`。

**影响**：元数据凭证泄露可能将 SSRF 升级为对云 API 的任意调用，实现越权。

**检测侧建议**：元数据访问在实例侧无默认审计；角色临时凭证签发由 CAM/STS 侧 `AssumeRole` 事件记录，需结合 SOC 关联分析。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | SSRF/文件读取 → 元数据 → 临时凭证 |
| 防守者 | CloudAudit `AssumeRole`、SSRF 应用日志 |

## 四、权限提升与持久化路径

- **实例角色滥用**：从普通 Web 漏洞获取的实例内权限，经元数据凭证调用 `tccli cvm DescribeInstances` 枚举全量实例，再经安全组漏洞横向移动。检测点：`AssumeRole` 事件频率异常。
- **密钥对添加持久化**：持有 CAM 权限的攻击者在实例上新增密钥对实现持续登录（`AssociateInstancesKeyPairs`），需授权内人工确认后评估。检测点：CloudAudit `AssociateInstancesKeyPairs`。
- **快照/镜像导出**：对高价值实例创建快照并导出到攻击者可控实例读取数据。检测点：`CreateSnapshot`、`CreateImage`、`ExportImage`。
- **安全组放行后门**：临时放开入站端口作为后门通道。检测点：`ModifySecurityGroupPolicies`。

上述持久化操作若涉及破坏或配置变更，一律标注「授权内人工确认后执行」，不在自动化测试中落地。

## 五、防御与检测要点

核心审计事件清单（CloudAudit 操作审计）：

- `RunInstances` / `TerminateInstances` — 实例创建/销毁
- `AssociateInstancesKeyPairs` / `DisassociateInstancesKeyPairs` — 密钥对绑定/解绑
- `CreateKeyPair` / `DeleteKeyPairs` — 密钥对创建/删除
- `ModifySecurityGroupPolicies` — 安全组规则变更
- `CreateImage` / `ExportImage` / `ModifyImageSharePermission` — 镜像创建/导出/共享
- `CreateSnapshot` — 快照创建
- `RebootInstances` / `StopInstances` — 重启/停机
- `AssumeRole` — 角色临时凭证签发

防御建议：

1. 安全组最小化放行，杜绝 `0.0.0.0/0` 全端口。
2. 密钥对定期轮换，私钥不入库、不进代码仓库。
3. 镜像导出/共享默认关闭并审计。
4. UserData 禁止硬编码敏感信息，改为经参数/凭据引用。
5. 实例角色遵循最小权限，限制元数据凭证的 API 范围。
6. 开启 CloudAudit 与 SOC，对上述事件建立告警与关联规则。
