# Azure VNet / NSG / 负载均衡 / 应用网关网络攻防

Azure 网络层由虚拟网络（VNet）、子网（Subnet）、网络安全组（NSG）、路由表（Route Table）、负载均衡（Load Balancer）与应用网关（Application Gateway）等资源构成。攻击面集中在「NSG 规则误配」「负载均衡/应用网关的端口转发与后端暴露」「路由与对等（Peering）导致的横向通道」三方面。

## 一、攻击面

- **虚拟网络（VNet）与子网**：VNet 是网络隔离边界，子网划分与对等（Peering）、VPN/ExpressRoute 网关决定跨网络可达性。
- **网络安全组（NSG）**：挂载到子网或网卡（NIC），以「入站/出站安全规则」按优先级（100–4096）匹配源/目的/端口/协议，决定放行或拒绝。
- **路由表（Route Table）与默认路由**：用户自定义路由（UDR）可改变流量走向，错误路由可能把内部流量引向不可信下一跳。
- **负载均衡（Load Balancer）**：公网/内部负载均衡器的入站 NAT 规则（Inbound NAT）与负载均衡规则把公网流量转发到后端 VM 端口。
- **应用网关（Application Gateway）**：七层反向代理，WAF 策略、后端池与监听器配置错误会导致后端直接暴露或绕过过滤。
- **NSG 流日志（Flow Logs）**：记录允许/拒绝的流，是防守侧网络可见性的核心数据源。
- **服务终结点与私有终结点**：服务终结点（Service Endpoint）与私有终结点（Private Endpoint）决定 PaaS 资源的网络可达边界，配置遗漏即扩大暴露。

## 二、信息收集 / 暴露面探测

以下命令只读优先，用于枚举 VNet、NSG 规则、负载均衡转发规则与公网暴露。

```bash
# 列出所有 VNet 及子网
az network vnet list --query "[].{name:name, subnets:subnets[].name}" --output json

# 列出所有 NSG 及其规则
az network nsg list --query "[].{name:name, rules:securityRules}" --output json

# 列出某 NSG 的规则（重点看 0.0.0.0/0 与高风险端口）
az network nsg rule list --resource-group <rg> --nsg-name <nsg> \
  --query "[].{rule:name, dir:direction, src:sourceAddressPrefix, dst:destinationPortRange, access:access, priority:priority}" --output table

# 列出公网 IP 及其关联
az network public-ip list --query "[].{ip:ipAddress, name:name}" --output table

# 列出负载均衡器的入站 NAT 规则（公网到后端端口映射）
az network lb inbound-nat-rule list --resource-group <rg> --lb-name <lb> \
  --query "[].{name:name, frontendPort:frontendPort, backendPort:backendPort}" --output table

# 列出应用网关后端池与监听器
az network application-gateway list --query "[].{name:name, frontendPorts:frontendPorts, backendPools:backendAddressPools}" --output json

# 列出 VNet 对等关系（识别跨网络通道）
az network vnet peering list --resource-group <rg> --vnet-name <vnet> \
  --query "[].{name:name, remote:remoteVirtualNetwork.id}" --output table
```

探测要点：NSG 规则 `sourceAddressPrefix=0.0.0.0/0` 且 `access=Allow` 指向 22/3389/数据库端口即公网暴露；负载均衡 NAT 规则揭示公网端口到后端端口映射；对等关系揭示横向可达的其它 VNet。

## 三、常见配置缺陷与利用路径

### 3.1 NSG 规则过度放行 / 全网开放

- **缺陷描述**：NSG 入站规则将高风险端口（22/3389/数据库/管理端口）对 `0.0.0.0/0` 放行，或规则优先级编排错误导致默认拒绝被绕过，使内部资源暴露到互联网。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出全网开放的入站规则
az network nsg rule list --resource-group <rg> --nsg-name <nsg> \
  --query "[?direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0')].{rule:name, port:destinationPortRange, priority:priority}" --output table
```

- **影响**：攻击者直接对暴露服务进行漏洞利用、凭据爆破或未授权访问，构成初始访问。
- **检测侧建议**：NSG 流日志记录每个允许/拒绝的流及方向、端口、源 IP；Defender for Cloud 会标记「NSG 管理端口开放」「数据库端口开放」建议。防守方应在 Sentinel 中基于流日志监控「公网到高风险端口的允许流」并告警。

### 3.2 负载均衡 / 应用网关后端直连暴露

- **缺陷描述**：负载均衡 NAT 规则或应用网关将公网流量转发到后端 VM 的高风险端口，或后端池配置错误导致后端绕过 WAF 直接暴露，使七层过滤形同虚设。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看入站 NAT 规则的前后端端口映射
az network lb inbound-nat-rule list --resource-group <rg> --lb-name <lb> \
  --query "[].{name:name, frontend:frontendPort, backend:backendPort}" --output table

# 只读验证：查看应用网关监听器与后端池
az network application-gateway listener list --resource-group <rg> --gateway-name <gw> \
  --query "[].{name:name, port:frontendPort.id}" --output table
```

- **影响**：攻击者可绕过 WAF/过滤直接命中后端服务，扩大可利用面；应用网关未正确配置后端访问控制时可能泄露后端地址与内部服务。
- **检测侧建议**：NSG 流日志 + 应用网关访问日志记录转发请求与发起方；Defender for Cloud 标记「应用网关 WAF 策略缺失」。防守方应确保后端不可公网直连、WAF 开启且后端地址仅内部可达。

### 3.3 VNet 对等 / 路由误配导致横向通道

- **缺陷描述**：VNet 对等（Peering）配置为允许转发/网关传输，或 UDR 把流量路由到不可信下一跳，使隔离失效，攻击者在获得某一 VNet 内主机后横向到其它网络。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出 VNet 对等及其允许转发/网关传输属性
az network vnet peering list --resource-group <rg> --vnet-name <vnet> \
  --query "[].{name:name, allowForwardedTraffic:allowForwardedTraffic, allowGatewayTransit:allowGatewayTransit}" --output table

# 只读验证：列出路由表与自定义路由
az network route-table route list --resource-group <rg> --route-table-name <rt> \
  --query "[].{name:name, addressPrefix:addressPrefix, nextHopType:nextHopType}" --output table
```

- **影响**：网络分段被穿透，攻击者可访问相邻 VNet 内的数据库、密钥服务或管理平面，扩大横向范围。
- **检测侧建议**：NSG 流日志可反映跨对等 VNet 的异常流；Activity Log 记录对等创建 `Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write` 与路由变更。防守方应遵循最小对等原则，并对新增对等/路由变更告警。

### 3.4 公网 IP 未受控 / 未关联 NSG

- **缺陷描述**：VM/负载均衡器分配了公网 IP，但其所在子网或网卡未关联 NSG（或 NSG 无默认拒绝规则），导致所有端口暴露，攻击面不受控。
- **验证命令（只读优先）**：

```bash
# 只读验证：列出公网 IP 及其关联对象
az network public-ip list --query "[].{ip:ipAddress, name:name, attached:ipConfiguration.id}" --output table

# 只读验证：检查 NSG 是否关联到子网/网卡
az network nsg show --resource-group <rg> --name <nsg> \
  --query "{subnets:subnets, nics:networkInterfaces}" --output json
```

- **影响**：所有开放端口直接暴露公网，扩大漏洞利用、爆破与未授权访问面。
- **检测侧建议**：NSG 流日志记录所有入站流；Defender for Cloud 标记「VM 无 NSG 保护」。防守方应确保所有公网入口关联最小化 NSG，并对「公网 IP 新增」告警。

### 3.5 应用网关 WAF 未启用 / 处于检测模式

- **缺陷描述**：应用网关未关联 WAF 策略，或 WAF 处于「检测模式」（Detection）而非「防护模式」（Prevention），恶意请求不被拦截，后端应用直接暴露于注入、遍历、RCE 等攻击。
- **验证命令（只读优先）**：

```bash
# 只读验证：查看应用网关关联的 WAF 策略及运行模式
az network application-gateway waf-policy list --resource-group <rg> \
  --query "[].{name:name, mode:policySettings.mode, enabled:policySettings.state}" --output table
```

- **影响**：七层攻击（SQLi、XSS、路径遍历、命令注入）绕过防护直达后端，扩大应用层暴露。
- **检测侧建议**：应用网关访问日志记录 WAF 规则命中与放行请求；Defender for Cloud 标记「WAF 策略缺失/检测模式」。防守方应强制 WAF 防护模式，并对「WAF 规则命中」「检测模式降级」告警。

## 四、权限提升与持久化路径

- **网络暴露 → 初始访问 → 横向**：经公网暴露端口进入某主机后，利用 VNet 对等/路由误配横向到内部高价值资源。
- **NSG 规则篡改**：持有 `Microsoft.Network/networkSecurityGroups/write` 权限的主体可临时放行端口作为访问通道，或删除日志规则降低可见性（写操作，须授权内人工确认后执行）。
- **入站 NAT 规则作为持久后门**：在负载均衡器上新增 NAT 规则将公网端口映射到受害主机，作为稳定回连入口。
- **路由/网关篡改**：修改 UDR 或对等配置重定向流量，实现流量劫持式持久化（写操作，须授权内确认）。

## 五、防御与检测要点

关键审计日志事件名清单：

| 服务/日志 | 关键事件 / 操作 |
| --- | --- |
| NSG 流日志（Flow Logs） | 允许/拒绝流记录（源/目的 IP、端口、方向、协议） |
| Azure Activity Log | `Microsoft.Network/networkSecurityGroups/write`、`.../securityRules/write` |
| Azure Activity Log | `Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write` |
| Azure Activity Log | `Microsoft.Network/loadBalancers/write`、`.../inboundNatRules/write` |
| Azure Activity Log | `Microsoft.Network/publicIPAddresses/write` |
| 应用网关访问日志 | 请求方、目标后端、WAF 规则命中 |
| Microsoft Defender for Cloud | 管理端口开放、WAF 缺失、NSG 未关联等建议 |
| Microsoft Sentinel | 基于流日志的公网到高风险端口异常告警 |

云检测缺口提示：网络层攻击（端口扫描、横向连接尝试）不产生管理面 Activity Log 事件，主要靠 NSG 流日志与应用网关访问日志可见。若未启用 NSG 流日志，横向移动可长时间静默。防守方应把「流日志」作为网络检测主数据源，并对「公网到高风险端口的允许流」「跨 VNet 异常流」建立基线告警。

防御要点小结：NSG 规则最小化并定期审查、管理端口经 Bastion/VPN 收敛、负载均衡/应用网关后端不公网直连且 WAF 开启、VNet 对等最小化并监控路由变更、所有公网入口关联 NSG、对 NSG/路由/对等配置变更建立告警。
