# 从 SSRF 到元数据凭证（IMDSv1/v2）攻防

本文聚焦从服务端请求伪造（SSRF）到 AWS 实例元数据凭证的完整链路、配置缺陷与检测要点，供授权安全评估参考。计算实例面见 `./ec2.md`，权限模型见 `./iam.md`，网络隔离见 `./network.md`。

## 一、攻击面

SSRF 是云上最典型的初始访问放大漏洞，攻击面包含两层：

- **应用层**：存在 SSRF 的 Web 服务、API、代理、导入导出、URL 拉取、回调等功能点
- **基础设施层**：实例元数据服务（IMDS，地址 `169.254.169.254`）承载实例角色临时凭证；容器/任务环境另有各自元数据入口

一旦 SSRF 可触达元数据服务，即可把**应用漏洞**转化为**云身份凭证**，进而以实例角色权限调用 AWS API。IMDSv1 与 IMDSv2 的差异决定利用难度与检测窗口。

## 二、信息收集 / 暴露面探测

```bash
# 实例内直接探测元数据（无 scheme，curl 默认走 HTTP）
curl -s 169.254.169.254/latest/meta-data/

# IMDSv1：直接读取角色名与临时凭证
curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# IMDSv2：先取 token 再携带 token 访问
TOKEN=$(curl -s -X PUT 169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" 169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# 实例身份文档（含账号 ID、区域、实例 ID）
curl -s 169.254.169.254/latest/dynamic/instance-identity/document

# 用获取的临时凭证验证身份与权限
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

SSRF 侧探测要点：先确认是否存在 URL 拉取类功能点，再以 `169.254.169.254` 为目标做可达性验证，观察响应差异与错误信息。

常用元数据路径清单（只读探测）：

| 路径 | 用途 |
| --- | --- |
| `/latest/meta-data/` | 元数据根目录，枚举可用字段 |
| `/latest/meta-data/instance-id` | 实例 ID |
| `/latest/meta-data/iam/security-credentials/` | 列出已绑定的实例角色名 |
| `/latest/meta-data/iam/security-credentials/<role>` | 读取角色临时凭证 |
| `/latest/dynamic/instance-identity/document` | 实例身份文档（账号 ID/区域/实例 ID） |
| `/latest/meta-data/public-ipv4` | 公网 IPv4 |
| `/latest/meta-data/local-ipv4` | 内网 IPv4 |
| `/latest/user-data` | 用户数据（可能含初始化密钥/脚本） |

## 三、常见配置缺陷与利用路径

### 3.1 SSRF 未过滤元数据地址

**缺陷描述**：应用对用户可控 URL 未做协议/目标校验，攻击者直接请求 `169.254.169.254` 的元数据路径，读取实例角色临时凭证。

**验证命令（只读优先，SSRF 载体内请求）**：

```bash
curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/
```

**影响**：实例角色临时凭证泄露，攻击者可在实例外以该角色身份调用 AWS API，权限取决于角色策略。

**检测侧建议**：应用侧 SSRF 难以被 CloudTrail 直接记录，但凭证的后续使用（如 `GetCallerIdentity`、`DescribeInstances`）会以实例角色身份产生 CloudTrail 事件，发起 IP 为攻击者而非实例，可通过异常发起地识别；GuardDuty 对元数据访问异常亦有检测。建议对出站请求做 SSRF 防护（协议白名单、地址黑名单、DNS 重绑定防护）。

### 3.2 IMDSv1 未禁用

**缺陷描述**：实例未强制 IMDSv2，仍接受 IMDSv1 的无 token 请求，任何能触达元数据的路径（SSRF、实例内低权限进程）都可直接读取凭证。

**验证命令（只读优先）**：

```bash
curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/
aws ec2 describe-instances --instance-ids i-0abcd1234 --query 'Reservations[].Instances[].MetadataOptions'
```

**影响**：凭证窃取门槛极低，IMDSv1 请求无 token 校验，攻击者无需先取得 PUT 能力。

**检测侧建议**：`ModifyInstanceMetadataOptions`（`HttpTokens` 改为 `required`）写入 CloudTrail；建议全量强制 IMDSv2，未加固实例纳入 Config 检查与告警。

### 3.3 IMDSv2 token 可被 SSRF 获取

**缺陷描述**：IMDSv2 需先发起 `PUT` 请求带 `X-aws-ec2-metadata-token-ttl-seconds` 头获取 token；若应用 SSRF 支持自定义方法与请求头，攻击者同样可完成取 token 再读凭证的两步流程，v2 仅提高门槛而非杜绝。

**验证命令（只读优先，两步）**：

```bash
TOKEN=$(curl -s -X PUT 169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" 169.254.169.254/latest/meta-data/iam/security-credentials/
```

**影响**：在可发 PUT 且可带自定义头的 SSRF 场景下，IMDSv2 仍可被绕过，凭证照常泄露。

**检测侧建议**：元数据 `PUT /latest/api/token` 请求在实例网络层可见；结合 `HttpPutResponseHopLimit`（默认 1）限制 token 转发跳数，可阻断经代理/容器的二次跳转。建议同时下调跳数并配合网络层阻断非本机对 `169.254.169.254` 的访问。

### 3.4 重定向与协议绕过

**缺陷描述**：SSRF 校验仅看初始 URL，未跟随重定向目标做二次校验，或未封禁 `file`/`gopher` 等协议，攻击者借重定向或协议绕过访问内网与元数据。

**验证命令（只读优先，验证重定向）**：

```bash
curl -s -L 169.254.169.254/latest/meta-data/iam/security-credentials/
```

**影响**：绕过薄弱校验，扩大 SSRF 可达面，间接触达元数据或内网服务。

**检测侧建议**：应用侧应禁用危险协议、对重定向链逐跳校验；网络侧用出口代理/防火墙限制到链路本地地址的访问。日志上，异常内部访问可经 VPC Flow Logs 或代理日志识别。

### 3.5 容器/任务环境元数据暴露

**缺陷描述**：ECS 等容器任务环境中，元数据/凭证通过任务端点暴露给容器；容器内 SSRF 或逃逸可读取任务角色凭证，链路与 EC2 元数据类似。

**验证命令（只读优先，容器内探测）**：

```bash
# ECS 任务元数据端点（地址依环境而定，示例为常见链路本地地址）
curl -s 169.254.170.2
curl -s 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

**影响**：任务角色凭证泄露，权限横向扩展到云控制面或关联服务。

**检测侧建议**：凭证调用以任务角色身份产生 CloudTrail 事件；GuardDuty 与 ECS 审计可关联异常发起地。建议容器网络隔离、关闭不必要的元数据暴露、最小化任务角色权限。

## 四、权限提升与持久化路径

- **凭证横向使用**：泄露的临时凭证可脱离实例在攻击者主机使用，权限与角色策略一致，用于枚举、读写目标资源。
- **AssumeRole 扩展**：若实例角色可 `sts:AssumeRole` 其他角色，可借信任链纵向提权（见 `./iam.md`）。
- **凭证回传持久化**：把窃取的凭证外传到攻击者侧存储，在凭证有效期与轮换窗口内持续使用。
- **内网横向**：借 SSRF 继续探测 VPC 内网服务（数据库、内部 API），结合凭证扩大战果。

## 五、防御与检测要点

| 攻击者动作 | 观测点 / 事件 | 检测/告警建议 |
| --- | --- | --- |
| 读取元数据 | 实例网络层对 `169.254.169.254` 的请求 | 用代理/防火墙阻断非本机访问 |
| 凭证调用 AWS API | CloudTrail 对应 API 事件 | 对比实例角色正常基线，识别异地/异常发起地 |
| 取 token 请求 | 元数据 `PUT /latest/api/token` | 下调 `HttpPutResponseHopLimit`，记录异常跳数 |
| 修改元数据选项 | CloudTrail `ModifyInstanceMetadataOptions` | 对 `HttpTokens` 回退为 optional 告警 |
| 身份探测 | CloudTrail `GetCallerIdentity` | 对首次/异常地域的身份探测告警 |
| 角色横向 | CloudTrail `AssumeRole` | 对实例角色异常代入其他角色告警 |

配套日志与检测服务：CloudTrail、VPC Flow Logs、GuardDuty、Security Hub、Config。防线核心：强制 IMDSv2 + 降低跳数 + 网络层阻断链路本地地址、应用侧 SSRF 全防护（协议/地址/重定向三重校验）、实例角色权限最小化、凭证异常使用基线告警。

## 六、云检测缺口小结

SSRF 到元数据凭证链路的核心检测缺口在于：

- **数据面盲区**：对 `169.254.169.254` 的元数据读取默认不产生 CloudTrail 记录，SSRF 本身在控制面不可见。
- **凭证异用识别**：泄露的临时凭证被异地使用时，会以实例角色身份产生 CloudTrail 事件，这是主要可见点，依赖角色基线对比与异常发起地识别。
- **跳数与协议绕过**：`HttpPutResponseHopLimit` 未下调、危险协议未封禁时，绕过难以在日志层面直接告警，需网络层与代理日志兜底。

补齐思路：强制 IMDSv2 + 降低跳数 + 网络层阻断链路本地地址 + 实例角色权限最小化 + 凭证异常使用基线告警，把「看不到的攻击」转化为「可告警的凭证异用」。
