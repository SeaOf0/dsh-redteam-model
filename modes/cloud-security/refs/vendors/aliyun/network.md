# VPC/vSwitch/安全组/SLB/NAT 网络攻防

本文覆盖阿里云网络体系（VPC、vSwitch、安全组、SLB、NAT 网关、网络 ACL）在授权评估中的攻击面、暴露面探测、常见配置缺陷与利用路径、权限提升与持久化，以及对应检测要点。所有命令以只读探测为优先，破坏性操作须在授权范围内人工确认后执行。

## 一、攻击面

网络层决定流量能否触达与如何在云内横向：

- **VPC**：网段规划、跨 VPC 对等连接、跨账号打通。
- **vSwitch**：子网划分、与安全组/ACL 的边界关系。
- **安全组**：实例级入/出方向规则，放行过宽是主要风险。
- **SLB 负载均衡**：监听端口、后端服务器组，可能将内网服务暴露到公网。
- **NAT 网关**：SNAT 出网、DNAT 端口转发，DNAT 暴露内网主机。
- **网络 ACL**：子网级无状态访问控制，未配置或过宽。
- **EIP**：公网 IP 绑定，暴露面扩大。

网络配置的「过度暴露」是绝大多数云入侵的入口：一处 DNAT 或安全组规则即可把内网资产推到公网。

## 二、信息收集 / 暴露面探测

已获得 AK 后，用只读命令绘制网络拓扑与暴露面。

```bash
# 列出 VPC 与网段
aliyun vpc DescribeVpcs --RegionId cn-hangzhou

# 列出 vSwitch 与所属 VPC/可用区
aliyun vpc DescribeVSwitches --RegionId cn-hangzhou

# 列出 NAT 网关（识别出网/入网转发）
aliyun vpc DescribeNatGateways --RegionId cn-hangzhou

# 列出网络 ACL 及其绑定子网
aliyun vpc DescribeNetworkAcls --RegionId cn-hangzhou

# 列出 SLB 负载均衡与监听
aliyun slb DescribeLoadBalancers --RegionId cn-hangzhou
aliyun slb DescribeLoadBalancerAttribute --LoadBalancerId lb-xxxxxxxx --RegionId cn-hangzhou

# 列出安全组与规则
aliyun ecs DescribeSecurityGroups --RegionId cn-hangzhou
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId sg-xxxxxxxx --RegionId cn-hangzhou

# 列出 EIP 及绑定关系（公网暴露面）
aliyun vpc DescribeEipAddresses --RegionId cn-hangzhou

# 列出 VPC 对等连接（跨 VPC 互通通道）
aliyun vpc DescribeVpcPeerConnections --RegionId cn-hangzhou
```

外部连通性只读探测（仅确认端口开放）：

```bash
nc -zv <public-ip> 80
nc -zv <public-ip> 22
```

## 三、常见配置缺陷与利用路径

### 3.1 安全组规则放行 0.0.0.0/0

**缺陷描述**：实例安全组入方向对 `0.0.0.0/0` 开放管理或业务端口，使实例直接暴露公网。

**验证命令（只读优先）**：

```bash
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId sg-xxxxxxxx --RegionId cn-hangzhou
# 关注 SourceCidrIp=0.0.0.0/0 且 PortRange 覆盖敏感端口的规则
```

**影响**：配合弱口令、未认证服务或已知漏洞即可完成初始入侵。

**检测侧建议**：ActionTrail 记录 `AuthorizeSecurityGroup`、`ModifySecurityGroupRule`；云监控可对安全组变更与公网扫描告警。防守方应定期盘点 `0.0.0.0/0` 规则并最小化放行。

### 3.2 NAT 网关 DNAT 暴露内网主机

**缺陷描述**：DNAT 端口转发把内网主机的管理端口（SSH、数据库、远程桌面）映射到公网，形成隐式暴露。

**验证命令（只读优先）**：

```bash
aliyun vpc DescribeNatGateways --RegionId cn-hangzhou
# 进一步查看 DNAT 条目（ForwardEntry）
aliyun vpc DescribeForwardTableEntries --RegionId cn-hangzhou --NatGatewayId ngw-xxxxxxxx
```

**影响**：内网本不该对外的资产被端口转发暴露，且易被资产盘点遗漏。

**检测侧建议**：ActionTrail 记录 `CreateForwardEntry`、`ModifyForwardEntry`；防守方应把 DNAT 条目纳入暴露面清单，对非预期端口转发告警。

### 3.3 SLB 监听暴露内网服务

**缺陷描述**：SLB 监听端口开放过大，或后端服务器组把内网服务（数据库、内网管理台）挂到公网监听。

**验证命令（只读优先）**：

```bash
aliyun slb DescribeLoadBalancerAttribute --LoadBalancerId lb-xxxxxxxx --RegionId cn-hangzhou
# 关注 ListenerPorts 与 BackendServers，判断暴露面
```

**影响**：内网服务经 SLB 公网可达，绕过网络分区意图。

**检测侧建议**：ActionTrail 记录 `CreateLoadBalancer`、`CreateListener`、`AddBackendServers`；防守方应对监听端口与后端变化告警，并与安全组策略联动复核。

### 3.4 网络 ACL 未配置或过宽

**缺陷描述**：子网级网络 ACL 未配置默认拒绝，或入/出方向规则过宽，导致子网间横向无约束。

**验证命令（只读优先）**：

```bash
aliyun vpc DescribeNetworkAcls --RegionId cn-hangzhou
# 关注是否绑定关键子网，以及入方向是否放行过宽
```

**影响**：一旦单点失陷，缺乏子网级隔离，横向移动阻力小。

**检测侧建议**：ActionTrail 记录 `CreateNetworkAcl`、`ModifyNetworkAclAttributes`；防守方应按「默认拒绝」模型配置 ACL，并对子网边界规则变更告警。

### 3.5 VPC 对等连接跨账号打通

**缺陷描述**：VPC 对等连接或跨账号网络打通未做严格授权审查，使原本隔离的网络域可互通，扩大横向移动范围。

**验证命令（只读优先）**：

```bash
aliyun vpc DescribeVpcPeerConnections --RegionId cn-hangzhou
# 查看对等连接两端 VPC 与状态，识别跨账号或非预期互通
```

**影响**：一旦某一 VPC 内资产失陷，可经对等连接横向到对端 VPC，突破网络分区。

**检测侧建议**：ActionTrail 记录 `CreateVpcPeerConnection`、`ModifyVpcPeerConnectionAttribute`；防守方应对对等连接的建立与变更告警，并定期复核网络边界。

### 3.6 EIP 绑定管理不规范

**缺陷描述**：EIP 长期绑定到内网资产、未及时解绑，或 EIP 与实例/网关的映射关系混乱，造成公网暴露面失控。

**验证命令（只读优先）**：

```bash
aliyun vpc DescribeEipAddresses --RegionId cn-hangzhou
# 查看 EIP 状态与绑定对象，识别非预期公网暴露
```

**影响**：本应私网运行的资产被公网 IP 直连，绕过内网访问控制意图。

**检测侧建议**：ActionTrail 记录 `AllocateEipAddress`、`AssociateEipAddress`、`UnassociateEipAddress`；防守方应将 EIP 纳入暴露面资产对账，对异常绑定告警。

## 四、权限提升与持久化路径

- **内网横向**：利用安全组/ACL 过宽，从单点实例横向到同 VPC 内其它资产。
- **安全组开口**：修改安全组规则为自己预留入站通道（`AuthorizeSecurityGroup`），须授权内人工确认后执行。
- **DNAT 隧道**：新增或修改 DNAT 条目建立持久外联通道，须授权内人工确认后执行。
- **跨 VPC 打通**：利用对等连接或跨账号角色打通目标 VPC，须授权内人工确认后执行。
- **SLB 后端投毒**：向 SLB 后端服务器组注入恶意节点或篡改健康检查，劫持流量，须授权内人工确认后执行。

网络层的持久化普遍可被 `AuthorizeSecurityGroup`、`CreateForwardEntry`、`AddBackendServers` 等事件捕获，防守方应重点监控「规则新增 + 端口放行 + 后端变更」。

## 五、防御与检测要点

审计日志事件名清单（ActionTrail）：

| 事件名 | 含义 | 风险提示 |
| --- | --- | --- |
| `CreateVpc` / `CreateVSwitch` | 创建网络 | 关注非授权建网 |
| `AuthorizeSecurityGroup` | 放行安全组规则 | 关注 0.0.0.0/0 与高危端口 |
| `ModifySecurityGroupRule` | 修改安全组规则 | 规则篡改 |
| `RevokeSecurityGroup` | 撤销规则 | 关注先撤后加的规避 |
| `CreateNatGateway` | 创建 NAT 网关 | 出网/入网通道 |
| `CreateForwardEntry` / `ModifyForwardEntry` | DNAT 转发 | 内网暴露 |
| `CreateLoadBalancer` / `CreateListener` | 创建 SLB/监听 | 公网暴露内网服务 |
| `AddBackendServers` | 添加后端 | 流量劫持 |
| `CreateNetworkAcl` / `ModifyNetworkAclAttributes` | 网络 ACL | 子网边界变更 |
| `CreateVpcPeerConnection` | 创建对等连接 | 跨 VPC 打通 |
| `AllocateEipAddress` / `AssociateEipAddress` | 分配/绑定 EIP | 公网暴露面扩大 |

防御建议：

- 安全组默认拒绝、最小化放行，高危端口禁止 `0.0.0.0/0`。
- DNAT、SLB 监听、EIP 纳入统一暴露面管理，定期对账。
- 网络 ACL 按「默认拒绝」模型配置，关键子网边界明确。
- 对上述事件建立集中告警，重点关联「规则新增 + 端口放行 + 后端变更」组合与陌生调用方。
