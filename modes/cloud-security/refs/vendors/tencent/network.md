# VPC / 安全组 / CLB / NAT 网络攻防

> 面向授权安全测试的腾讯云网络层攻击面梳理与方法论，涵盖 VPC、子网、安全组、CLB（负载均衡）与 NAT 网关。所有验证以只读探测优先，破坏性操作需「授权内人工确认后执行」。

## 一、攻击面

腾讯云网络由 VPC（私有网络）、子网、路由表、安全组、NAT 网关、VPN/专线及 CLB（负载均衡）等组成。其攻击面集中于访问控制与流量路径，可归纳为：

- **安全组面**：入站规则过度放行、规则优先级冲突、绑定实例过多。
- **CLB 面**：监听器暴露内网后端、转发规则泄露、未授权访问后端端口。
- **NAT/VPC 面**：子网公网暴露、路由表指向错误、跨 VPC 互通（对等连接/云联网）未隔离。
- **网络 ACL 面**：网络 ACL 与安全组双控未生效、ACL 规则误配。

下表列出网络攻击面与对应防守视角：

| 攻击面 | 攻击者关注点 | 防守者关注点 |
| --- | --- | --- |
| 安全组 | 0.0.0.0/0 放行 | `ModifySecurityGroupPolicies` 审计 |
| CLB | 监听器暴露后端 | `CreateListener`、`ModifyListener` 审计 |
| 路由表 | 路由指向错误 | `ModifyRouteTableAttribute` 审计 |
| NAT/VPC | 子网公网暴露 | `CreateSubnet`、`CreateNatGateway` 审计 |

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于枚举当前账号授权范围内的网络资源与配置。

```bash
# 列出 VPC（只读）
tccli vpc DescribeVpcs

# 列出子网（只读）
tccli vpc DescribeSubnets

# 列出安全组（只读）
tccli vpc DescribeSecurityGroups

# 查看安全组规则（只读）
tccli vpc DescribeSecurityGroupPolicies --SecurityGroupId sg-xxxxx

# 列出路由表（只读）
tccli vpc DescribeRouteTables

# 列出 NAT 网关（只读）
tccli vpc DescribeNatGateways

# 列出 VPN 网关（只读）
tccli vpc DescribeVpnGateways

# 列出负载均衡（只读）
tccli clb DescribeLoadBalancers
```

从 `DescribeVpcs`/`DescribeSubnets` 提取网段划分与子网是否绑定公网（NAT/公网 IP）。从 `DescribeRouteTables` 提取路由条目，识别默认路由指向 NAT 或对等连接。从 `DescribeLoadBalancers` 提取监听器与后端目标。

```bash
# 列出 CLB 监听器（只读）
tccli clb DescribeListeners --LoadBalancerId lb-xxxxx

# 列出监听器后端目标（只读）
tccli clb DescribeTargets --LoadBalancerId lb-xxxxx
```

## 三、常见配置缺陷与利用路径

### 3.1 安全组 0.0.0.0/0 入站放行

**缺陷描述**：安全组入站规则误配为任意网段（`0.0.0.0/0`、`::/0`）且放行全部或敏感端口，导致内网服务暴露公网。

**验证命令（只读优先）**：

```bash
# 查看安全组规则（只读）
tccli vpc DescribeSecurityGroupPolicies --SecurityGroupId sg-xxxxx
```

确认 `Ingress` 规则中 `CidrBlock` 为 `0.0.0.0/0` 且 `Action` 为 `ACCEPT`，并统计该安全组绑定的实例数量。

**影响**：攻击者可访问本应内网隔离的服务（管理端口、数据库、内网 API），绕过网络分区。

**检测侧建议**：安全组变更由 CloudAudit `ModifySecurityGroupPolicies` 记录；SOC 可对全放行规则建立暴露面扫描与告警；云监控对异常端口流量告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 端口扫描 + 访问内网服务 |
| 防守者 | CloudAudit `ModifySecurityGroupPolicies`、SOC 暴露面扫描 |

### 3.2 CLB 监听器暴露内网后端

**缺陷描述**：CLB 监听器将未加认证的内网后端（如内部 API、管理后台）暴露到公网，或转发规则将公网流量转发至敏感后端。

**验证命令（只读优先）**：

```bash
# 列出 CLB 及监听器（只读）
tccli clb DescribeLoadBalancers
tccli clb DescribeListeners --LoadBalancerId lb-xxxxx

# 查看后端目标端口与健康检查（只读）
tccli clb DescribeTargets --LoadBalancerId lb-xxxxx
```

**影响**：公网用户可直达内网后端端口，绕过原网络隔离，触发未授权访问或越权。

**检测侧建议**：监听器创建/修改由 CloudAudit `CreateListener`、`ModifyListener` 记录；SOC 对新增公网监听器与后端端口暴露建立告警；CLB 访问日志记录转发流量。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 经 CLB 公网访问内网后端 |
| 防守者 | CloudAudit `CreateListener`/`ModifyListener`、CLB 访问日志 |

### 3.3 路由表指向错误 / 跨 VPC 互通未隔离

**缺陷描述**：路由表默认路由指向错误（如指向对等连接或错误的 NAT），或 VPC 对等连接/云联网（CCN）未做路由隔离，导致跨环境可达。

**验证命令（只读优先）**：

```bash
# 查看路由表与路由条目（只读）
tccli vpc DescribeRouteTables

# 列出云联网（只读）
tccli vpc DescribeCcns

# 列出对等连接（只读）
tccli vpc DescribeVpcPeeringConnections
```

**影响**：跨 VPC/跨账号网络互通未隔离，攻击者可从受控环境横向访问高价值环境。

**检测侧建议**：路由变更由 CloudAudit `ModifyRouteTableAttribute`、`CreateRoutes` 记录；CCN/对等连接创建由 `CreateCcn`、`CreateVpcPeeringConnection` 审计；SOC 对跨 VPC 路由互通建立告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 跨 VPC 横向访问 |
| 防守者 | CloudAudit 路由/CCN/对等连接事件 |

### 3.4 NAT 网关 SNAT 出口滥用

**缺陷描述**：NAT 网关为私网子网提供统一出网，若出网未做域名/IP 白名单，攻击者可借受损主机经 NAT 外联或扫描外部资产。

**验证命令（只读优先）**：

```bash
# 列出 NAT 网关及绑定的弹性 IP（只读）
tccli vpc DescribeNatGateways
```

**影响**：NAT 出口成为攻击者外联/数据外带通道，且出网源 IP 归一为 NAT EIP，增加溯源难度。

**检测侧建议**：NAT 出网流量由云监控与 NAT 流日志记录（出网目标、端口）；SOC 对异常外联目标（矿池、C2 特征端口）建立告警；NAT 创建由 `CreateNatGateway` 审计。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 经 NAT 外联/外带数据 |
| 防守者 | NAT 流日志、云监控出网告警、CloudAudit `CreateNatGateway` |

### 3.5 子网默认公网暴露

**缺陷描述**：子网内实例默认绑定公网 IP 或子网被配置为公网可达，导致本应纯内网的资源暴露。

**验证命令（只读优先）**：

```bash
# 查看子网与实例公网 IP（只读）
tccli vpc DescribeSubnets
tccli cvm DescribeInstances
```

从实例返回中的公网 IP 字段与子网关联，识别纯内网规划但意外绑定公网 IP 的实例。

**影响**：内网资源暴露公网，扩大攻击面，破坏网络分区设计。

**检测侧建议**：实例公网 IP 绑定由 `AllocateAddresses`、`AssociateAddress` 审计；SOC 对纯内网子网出现公网 IP 建立合规告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 直接访问意外暴露的内网资源 |
| 防守者 | CloudAudit `AllocateAddresses`/`AssociateAddress`、SOC 暴露面扫描 |

## 四、权限提升与持久化路径

- **安全组放行后门**：临时放开入站端口作为后门通道。检测点：CloudAudit `ModifySecurityGroupPolicies`。
- **新增 CLB 监听器**：创建公网监听器指向敏感后端。检测点：CloudAudit `CreateListener`。
- **路由表篡改**：修改默认路由指向攻击者可控网段，破坏性，授权内人工确认后执行。检测点：CloudAudit `ModifyRouteTableAttribute`。
- **弹性 IP 绑定**：为受损实例绑定公网 IP 建立外联通道。检测点：CloudAudit `AssociateAddress`。

上述操作若涉及路由/监听器变更或公网暴露，一律标注「授权内人工确认后执行」。

## 五、防御与检测要点

核心审计事件清单（CloudAudit 操作审计，辅以 NAT/CLB 流日志）：

- `ModifySecurityGroupPolicies` — 安全组规则变更
- `CreateSecurityGroup` / `DeleteSecurityGroup` — 安全组创建/删除
- `CreateSubnet` / `ModifySubnetAttribute` — 子网创建/修改
- `ModifyRouteTableAttribute` / `CreateRoutes` — 路由变更
- `CreateNatGateway` / `DeleteNatGateway` — NAT 网关创建/删除
- `CreateVpcPeeringConnection` / `CreateCcn` — 跨 VPC 互通创建
- `CreateLoadBalancer` / `CreateListener` / `ModifyListener` — CLB 与监听器变更
- `AllocateAddresses` / `AssociateAddress` — 公网 IP 分配/绑定

防御建议：

1. 安全组与网络 ACL 双控，入站规则最小化，杜绝 `0.0.0.0/0`。
2. CLB 监听器仅暴露必要后端端口，后端做独立认证。
3. 路由表与 CCN/对等连接严格隔离，跨 VPC 互通默认关闭。
4. NAT 出网做域名/IP 白名单，开启流日志。
5. 纯内网子网禁止绑定公网 IP，建立暴露面持续扫描。
