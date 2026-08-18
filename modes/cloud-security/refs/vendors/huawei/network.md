# 华为云 VPC/子网/安全组/ELB/NAT 网络攻防

> 定位：围绕 VPC、子网、安全组、ELB、NAT 网关五类网络资源，给出只读优先的探测命令与网络
> 配置缺陷利用路径。工具以 `hcloud vpc` 与 `hcloud elb` 为主，写操作统一标注「授权内人工
> 确认后执行」。每条路径配检测侧对照（CTS 事件名 + 网络监控）。ECS 侧安全组见 `./ecs.md`。

## 一、攻击面

网络是云资源的连通骨架，攻击面集中在「谁和谁可达」与「出向是否可控」：

- VPC/子网：子网路由表指向公网网关或 NAT，内网资源被误接入公网。
- 安全组：入方向规则过宽（`0.0.0.0/0`）、出方向全放行、规则堆积导致实际暴露面不可见。
- ELB（负载均衡）：监听器明文转发、后端服务器组暴露、证书过期、健康检查配置泄露内网。
- NAT 网关：SNAT 出向不可控，沦为数据外传与 C2 回连的通道。
- 对等连接/专线：VPC 互联过宽，横向移动跨过网络隔离边界。

四要素落点：身份（AK/SK 或已沦陷实例）→ 权限（VPC 相关策略）→ 资源（VPC/子网/安全组/ELB/
NAT）→ 影响（内网可达、流量劫持、数据外传）。

## 二、信息收集 / 暴露面探测

以下命令只读，用于枚举网络拓扑与暴露面。

### 2.1 VPC 与子网枚举

```bash
# 列出全部 VPC（只读）
hcloud vpc list-vpcs

# 列出全部子网及关联路由表（只读）
hcloud vpc list-subnets

# 查看路由表（判断默认路由是否指向公网网关/NAT）
hcloud vpc list-route-tables
```

### 2.2 安全组与规则枚举

```bash
# 列出全部安全组（只读）
hcloud vpc list-security-groups

# 查看某安全组规则（只读，重点看 ingress 0.0.0.0/0 与高危端口）
hcloud vpc list-security-group-rules --security-group-id <sg_id>
```

### 2.3 ELB 枚举

```bash
# 列出负载均衡器（只读）
hcloud elb list-loadbalancers

# 查看监听器（协议、端口、证书、后端服务器组）
hcloud elb list-listeners --loadbalancer-id <lb_id>

# 查看后端服务器组与成员（判断是否暴露内网资产）
hcloud elb list-pools --loadbalancer-id <lb_id> 2>/dev/null
```

### 2.4 NAT 与公网带宽枚举

```bash
# 列出 NAT 网关（只读）
hcloud nat list-nat-gateways 2>/dev/null || hcloud vpc list-nat-gateways

# 列出弹性公网 IP（EIP，判断哪些实例/服务暴露公网）
hcloud vpc list-publicips
```

## 三、常见配置缺陷与利用路径

### 3.1 安全组入方向过宽（0.0.0.0/0）

- 缺陷描述：安全组入方向规则对 `0.0.0.0/0` 放行，或源网段过宽（如整个内网段），使管理端口
  与业务端口对全网可达。
- 验证命令（只读）：

```bash
hcloud vpc list-security-groups
hcloud vpc list-security-group-rules --security-group-id <sg_id> | grep -E '0.0.0.0/0|ingress'
```

- 影响：全网可达端口成为爆破、漏洞利用、未授权访问的直接入口。
- 检测侧建议：CTS 事件 `createSecurityGroupRule`、`updateSecurityGroup` 记录规则变更；规则
  过宽属配置态，需配置合规（SA）扫描发现，检测缺口在配置态。

### 3.2 子网误接公网（默认路由指向公网网关）

- 缺陷描述：私有子网的路由表被配置了指向公网网关的默认路由，或子网内的实例被绑定 EIP，
  使本应内网隔离的资源暴露公网。
- 验证命令（只读）：

```bash
hcloud vpc list-subnets
hcloud vpc list-route-tables | grep -iE '0.0.0.0/0|internet|nat'
hcloud vpc list-publicips   # 排查哪些内网实例意外绑定 EIP
```

- 影响：内网数据库、中间件、内部服务意外暴露公网，绕过「内网隔离」的安全假设。
- 检测侧建议：CTS 事件 `createRoute`、`updateRoute` 记录路由变更；EIP 绑定内网资产属配置态，
  需配置合规 + 资产测绘发现，检测缺口在配置态。

### 3.3 ELB 明文转发与后端暴露

- 缺陷描述：ELB 监听器使用 HTTP 明文转发（未上 TLS）、后端服务器组暴露内部资产、证书过期
  或缺失，导致流量可被窃听、内网拓扑泄露。
- 验证命令（只读）：

```bash
hcloud elb list-loadbalancers
hcloud elb list-listeners --loadbalancer-id <lb_id>   # 看 protocol 与端口
hcloud elb list-pools --loadbalancer-id <lb_id> 2>/dev/null   # 看后端成员内网地址
```

- 影响：明文流量可被中间人窃听（口令/凭证/会话）；后端成员地址泄露辅助内网横向。
- 检测侧建议：CTS 事件 `createListener`、`updateListener` 记录监听器配置；明文监听属配置态，
  需配置合规发现，检测缺口在配置态。

### 3.4 NAT 网关出向不可控（SNAT 数据外传）

- 缺陷描述：NAT 网关对子网全量放行出向（SNAT），已沦陷实例可经 NAT 外传数据、回连 C2，
  出向流量无细粒度控制与审计。
- 验证命令（只读）：

```bash
hcloud vpc list-nat-gateways
# 查看 NAT 关联的子网（只读，判断哪些子网可出公网）
hcloud vpc list-route-tables | grep -i nat
```

- 影响：数据外传通道隐蔽，攻击者持久化与窃密的出向流量混入正常业务流量。
- 检测侧建议：NAT 出向流量由 VPC 流日志（Flow Log）与 CES 网络指标记录；未开流日志则出向
  数据面不可见，检测缺口明确。

### 3.5 对等连接/VPC 互联过宽

- 缺陷描述：VPC 对等连接、专线、企业路由器互联范围过宽，不同安全域（生产/测试/办公）之间
  全通，横向移动跨过网络隔离。
- 验证命令（只读）：

```bash
hcloud vpc list-vpc-peerings 2>/dev/null || hcloud vpc list-peering-connections
# 查看路由表，判断是否通过 peer 路由打通了跨 VPC 网段
hcloud vpc list-route-tables
```

- 影响：一个 VPC 沦陷即可横向到互联的其它 VPC，隔离失效，攻击面扩散。
- 检测侧建议：CTS 事件 `createVpcPeering`、`updateVpcPeering` 记录互联建立；互联范围过宽属
  配置态，需网络拓扑审计（SA/配置合规）发现，检测缺口在配置态。

### 3.6 安全组规则堆积（规则漂移与失效管理）

- 缺陷描述：长期堆叠安全组规则，旧规则未回收、规则顺序/优先级混乱，导致实际放行面远超预期，
  且无人能说清当前暴露面。
- 验证命令（只读）：

```bash
hcloud vpc list-security-groups
hcloud vpc list-security-group-rules --security-group-id <sg_id>
# 统计规则数量与源网段分布，识别长期未变更的宽规则
```

- 影响：规则漂移使「以为收敛」的安全组实际大开，暴露面不可见、不可审计。
- 检测侧建议：CTS 事件 `createSecurityGroupRule`、`deleteSecurityGroupRule` 记录规则增删；规则
  漂移需定期配置基线比对（SA/合规）发现，检测缺口在配置态。

## 四、权限提升与持久化路径

- 横向移动：利用过宽安全组/对等连接从已沦陷 VPC 跨子网、跨 VPC 触达数据库与内部服务。
- 流量劫持：ELB 明文监听 + 后端暴露，结合中间人位置窃取凭据（授权评估范畴）。
- 出向持久化：经 NAT 建立回连 C2 通道，长期驻留并外传数据。
- 以上写/改操作均属「授权内人工确认后执行」，本文不提供脚本；出向 C2 通道仅作风险说明。

## 五、防御与检测要点

| 层 | 关键动作 | 审计/监控事件 |
|---|---|---|
| 安全组 | 规则增删改 | `createSecurityGroupRule`、`updateSecurityGroup`、`deleteSecurityGroupRule` |
| 路由 | 路由表/默认路由变更 | `createRoute`、`updateRoute`、`deleteRoute` |
| ELB | 监听器/后端配置变更 | `createListener`、`updateListener` |
| 互联 | 对等连接/专线建立 | `createVpcPeering`、`updateVpcPeering` |
| 公网 | EIP 绑定/解绑 | `assignPublicIp`、`unassignPublicIp` |
| 数据面流量 | 出入向流日志 | VPC Flow Log + CES 网络指标（非 CTS） |

防御建议：

- 安全组最小化：入方向收敛到堡垒机/应用网段，出方向按需放行，定期基线比对清理漂移。
- 子网分段：公网子网与私网子网隔离，默认路由谨慎指向公网网关，私网资产不绑 EIP。
- ELB 加固：统一 TLS、证书自动轮换、后端组最小暴露。
- NAT 出向审计：开启 VPC 流日志并投递 SIEM，监控异常出向（大数据量外传、非业务端口回连）。
- 互联收敛：对等/专线按安全域最小打通，跨域访问走审批与审计。
- 检测落地：CTS + VPC 流日志 + CES 网络告警三层联动，重点补数据面流量盲区。

## 审计事件名清单（本节汇总）

`createSecurityGroupRule`、`updateSecurityGroup`、`deleteSecurityGroupRule`、
`createRoute`、`updateRoute`、`deleteRoute`、`createListener`、`updateListener`、
`createVpcPeering`、`updateVpcPeering`、`assignPublicIp`、`unassignPublicIp`。
