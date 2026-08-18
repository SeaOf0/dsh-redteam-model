# EC2 计算实例攻防

本文聚焦 Amazon EC2 计算实例的攻击面、常见配置缺陷与检测要点，供授权安全评估参考。涉及元数据凭证利用的完整链路另见 `./ssrf-metadata.md`，权限模型见 `./iam.md`，网络暴露面见 `./network.md`。

## 一、攻击面

EC2 是云上最核心的计算资源，攻击面横跨多个维度：

- **实例本体**：操作系统、运行服务、开放端口、弱口令、未修复漏洞
- **启动配置**：用户数据（user data）、启动模板、AMI 镜像与镜像共享
- **凭证面**：SSH/RDP 密钥对、实例元数据服务（IMDS）承载的临时凭证
- **管理面**：AWS Systems Manager（SSM）、IAM 实例角色、实例属性修改
- **数据面**：EBS 卷、快照、跨账户共享镜像

评估时应先厘清实例的**角色绑定关系**与**元数据可达性**，因为临时凭证往往是横向移动的起点。

## 二、信息收集 / 暴露面探测

以下命令以只读优先，用于枚举计算资源与配置。

```bash
# 枚举实例基本信息（实例 ID、状态、AMI、私有/公有 IP、安全组、实例角色）
aws ec2 describe-instances --region us-east-1

# 查看实例绑定的 IAM 实例角色（instance-profile 字段）
aws ec2 describe-instances --instance-ids i-0abcd1234 --query 'Reservations[].Instances[].IamInstanceProfile'

# 查看实例用户数据（明文回显，常含引导脚本/密钥）
aws ec2 describe-instance-attribute --instance-id i-0abcd1234 --attribute userData

# 枚举镜像与共享状态
aws ec2 describe-images --owners self
aws ec2 describe-images --executable-users all   # 列出可被他人执行的镜像

# 枚举密钥对
aws ec2 describe-key-pairs

# 枚举快照（含公共快照）
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-snapshots --restorable-by-user-ids all

# 枚举启动模板
aws ec2 describe-launch-templates

# 枚举 SSM 托管的实例（前提：拥有 ssm 读权限）
aws ssm describe-instance-information
```

## 三、常见配置缺陷与利用路径

### 3.1 用户数据泄露凭证

**缺陷描述**：用户数据（user data）在启动时以明文注入实例，开发者常在其中写入数据库口令、私钥、初始化 token；该数据可被后续拥有 `ec2:DescribeInstanceAttribute` 权限的主体读取。

**验证命令（只读优先）**：

```bash
aws ec2 describe-instance-attribute --instance-id i-0abcd1234 --attribute userData --query 'UserData.Value' --output text | base64 -d
```

**影响**：凭证泄露后可接管业务系统或数据库，进而扩大横向移动面。

**检测侧建议**：`DescribeInstanceAttribute` 在 CloudTrail 中留下 `DescribeInstanceAttribute` 事件；正常运维极少高频读取 userData，可对非预期账号的读取行为告警；同时建议将敏感初始化配置迁移至 SSM Parameter Store / Secrets Manager。

### 3.2 共享 AMI / 公共 AMI 泄露敏感信息

**缺陷描述**：AMI 被误共享为 public 或共享给陌生账号，镜像内残留的历史口令、SSH 私钥、应用配置、`bash_history`、临时凭证文件可被他人启动实例后读取。

**验证命令（只读优先）**：

```bash
aws ec2 describe-images --owners self --query 'Images[].[ImageId,Public,Name]'
aws ec2 describe-image-attribute --image-id ami-0abcd1234 --attribute launchPermission
```

**影响**：镜像信息泄露导致凭据与业务逻辑外泄，攻击者可复现环境进一步渗透。

**检测侧建议**：`ModifyImageAttribute`（`CreateImage` 配合）写入 CloudTrail；可结合 Config 规则检查镜像 `Public` 属性，GuardDuty 亦对异常镜像共享有告警能力。防线要点：发布前对镜像做凭据清理，镜像共享采用白名单账号。

### 3.3 密钥对管理不当 / 私钥泄露

**缺陷描述**：密钥对私钥被上传至代码仓库、对象存储或共享目录；或同一密钥对在大量实例间复用，一处泄露全盘失守。

**验证命令（只读优先）**：

```bash
aws ec2 describe-key-pairs --query 'KeyPairs[].[KeyName,KeyPairId,KeyFingerprint]'
```

**影响**：拿到私钥即可登录对应实例；若该密钥对复用于多台实例，形成横向入口。

**检测侧建议**：`CreateKeyPair`、`ImportKeyPair`、`DeleteKeyPair` 均有 CloudTrail 事件；密钥泄露本身难以被日志直接捕获，需依赖凭证扫描、GuardDuty 异常登录（结合 VPC Flow Logs 与实例侧登录日志）与 SIEM 关联。

### 3.4 SSM 权限滥用

**缺陷描述**：实例配置了 SSM 且某主体拥有 `ssm:SendCommand` + `ssm:ListCommandInvocations` 权限时，可对受管实例下发任意命令，等效于实例级命令执行。

**验证命令（只读优先，先确认受管实例与文档）**：

```bash
aws ssm describe-instance-information --query 'InstanceInformationList[].[InstanceId,PingStatus,PlatformName]'
aws ssm describe-document --name AWS-RunShellScript
```

**影响**：命令执行入口，可读取文件、提取凭证、建立持久化。下发命令属破坏性/影响性操作，需**授权内人工确认后执行**。

**检测侧建议**：`SendCommand` 事件写入 CloudTrail，含 `DocumentName`、`InstanceIds`；GuardDuty 对 SSM 滥用亦有检测。防线：收紧 `ssm:SendCommand` 授权范围，限制可执行文档与实例集合。

### 3.5 实例元数据服务暴露凭证（IMDS 未加固）

**缺陷描述**：实例默认可用 IMDSv1，无需 token 即可读取角色临时凭证；SSRF 或实例内低权限进程可借此窃取 `AccessKeyId/SecretAccessKey/Token`。

**验证命令（只读优先，实例内探测）**：

```bash
curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

**影响**：拿到实例角色临时凭证即可以角色身份调用 AWS API，链路详见 `./ssrf-metadata.md`。

**检测侧建议**：凭证使用会以角色身份产生 CloudTrail 事件（如 `GetCallerIdentity`、`DescribeInstances`），可对比实例正常基线识别越界调用；建议强制 IMDSv2 并下调 `HttpPutResponseHopLimit`，关闭非必要实例角色。

### 3.6 快照公开共享

**缺陷描述**：EBS 快照被误共享为 public，任何账号可复制该快照并挂载，读取其中的数据库、源码与配置。

**验证命令（只读优先）**：

```bash
aws ec2 describe-snapshot-attribute --snapshot-id snap-0abcd1234 --attribute createVolumePermission
```

**影响**：数据外泄，等价于磁盘镜像泄露。

**检测侧建议**：`ModifySnapshotAttribute` 写入 CloudTrail；Config 可检测公开快照。防线：快照默认私有，共享仅限可信账号，定期审计 `createVolumePermission`。

## 四、权限提升与持久化路径

- **元数据凭证提权**：实例角色权限高于宿主进程预期时，窃取临时凭证后越权调用 API（详见 `./ssrf-metadata.md`）。
- **SSM 会话持久化**：通过 `ssm:StartSession` 建立交互式会话并维持访问。
- **用户数据后门**：拥有 `ec2:ModifyInstanceAttribute` 权限时改写 userData 注入反弹脚本，配合重启触发（破坏性，需授权内确认）。
- **AMI 后门化**：将植入后门的镜像共享回目标账号，诱导其基于该镜像发布新实例。
- **快照数据回取**：复制目标快照到攻击者账户，离线分析获取持久化凭据。

## 五、防御与检测要点

| 攻击者动作 | CloudTrail 事件名 | 检测/告警建议 |
| --- | --- | --- |
| 读取实例属性/用户数据 | `DescribeInstanceAttribute` | 对非运维账号、异常频率告警 |
| 修改实例属性 | `ModifyInstanceAttribute` | 关联 userData 变更与后续启动 |
| 创建/导入密钥对 | `CreateKeyPair`、`ImportKeyPair` | 对新密钥对与实例绑定关系审计 |
| 下发 SSM 命令 | `SendCommand` | 对高危文档与目标实例告警 |
| 修改镜像/快照共享属性 | `ModifyImageAttribute`、`ModifySnapshotAttribute` | 对 Public 属性变更即时告警 |
| 启动实例 | `RunInstances` | 关联发起 IP 与镜像出处 |
| 更换实例角色绑定 | `AssociateIamInstanceProfile`、`ReplaceIamInstanceProfileAssociation` | 对角色绑定变更告警 |

配套日志与检测服务：AWS CloudTrail、Config、GuardDuty、Security Hub、VPC Flow Logs。防线建议强制 IMDSv2、收紧 SSM 与实例角色权限、对镜像与快照共享做白名单治理。
