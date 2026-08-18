# VPC / 子网 / 防火墙规则 / 负载均衡网络攻防

GCP 的网络层由 VPC（虚拟私有云）、子网、防火墙规则、路由、负载均衡与 VPC Peering 等构成。网络攻防的核心是「连通性」与「暴露面」：防火墙规则决定哪些流量能进出实例，负载均衡与转发规则决定哪些端口对外暴露，VPC Peering 决定跨网络的可达性。配置失误往往把内网资源意外暴露到公网，或让低信任网络与高信任网络直接互通。

## 一、攻击面

VPC 网络攻击面可归纳为：

1. **防火墙规则过宽**：允许 `0.0.0.0/0` 访问 SSH(22)、RDP(3389)、数据库端口、管理端口，把实例直接暴露给全网。
2. **优先级与默认规则**：防火墙规则按优先级匹配，`default-allow-internal`、`default-allow-ssh` 等隐含规则常被忽略，形成意外的开放面。
3. **负载均衡与转发规则**：后端服务、目标池、转发规则的端口/协议配置错误，会暴露内部服务；HTTP(S) 负载均衡对未加密或源未受限的流量转发。
4. **VPC Peering / 共享 VPC**：Peering 使两个网络互通，共享 VPC 使多项目共享网络平面，配置过宽会放大横向移动面。
5. **公网 IP 与 NAT**：实例绑定外部 IP、Cloud NAT 使内网出站可达公网，暴露面与数据外带通道并存。
6. **私有 Google 访问 / Private Service Connect**：配置错误可能让内网绕过边界直连外部服务。
7. **DNS 与区域间互通**：Cloud DNS、VPC 网络内 DNS 解析可泄露内部主机名与拓扑。

## 二、信息收集 / 暴露面探测

以下命令为只读探测，用于枚举网络拓扑、防火墙规则与负载均衡暴露面。

```bash
# 列出所有 VPC 网络
gcloud compute networks list

# 查看 VPC 子网及 CIDR 范围
gcloud compute networks subnets list

# 列出全部防火墙规则（按优先级与方向）
gcloud compute firewall-rules list

# 查看单条防火墙规则的详细配置（允许的协议、端口、源/目标）
gcloud compute firewall-rules describe <RULE> --format=json

# 查看路由表（下一跳、目标范围）
gcloud compute routes list

# 列出外部 IP（静态与临时）及绑定对象
gcloud compute addresses list

# 查看实例绑定的网络接口与外部 IP
gcloud compute instances list --format="table(name,networkInterfaces[].accessConfigs[0].natIP,networkInterfaces[].network)"

# 列出转发规则（负载均衡入口）
gcloud compute forwarding-rules list

# 列出后端服务与健康检查
gcloud compute backend-services list
gcloud compute health-checks list

# 查看 VPC Peering 连接
gcloud compute networks peerings list

# 查看 Cloud NAT 网关
gcloud compute routers nats list --router <ROUTER> --region <REGION>
```

探测要点：把防火墙规则按「源 0.0.0.0/0 + 高危端口」过滤；核对负载均衡转发规则暴露的端口与后端；确认 Peering 连接的目标网络与是否过度互通。

## 三、常见配置缺陷与利用路径

### 3.1 防火墙规则 0.0.0.0/0 开放高危端口

**缺陷描述**：防火墙规则以 `0.0.0.0/0` 为源，放行 SSH(22)、RDP(3389)、数据库(3306/5432/1433/6379)、管理面板等端口，使这些服务直接对全网可达，成为暴力破解与已知漏洞利用的直接入口。

**验证命令（只读优先）**：

```bash
# 只读列出允许源为 0.0.0.0/0 的入站规则
gcloud compute firewall-rules list --format="table(name,direction,allowed[].map().firewall_rule().list(),sourceRanges.list())"
```

**影响**：高危端口公网开放后，SSH/RDP 面临口令暴力破解，数据库与管理面板面临未授权访问与已知漏洞利用，攻击者可直接获得主机或数据控制权。

**检测侧建议**：修改防火墙规则对应 Cloud Audit Logs 事件 `compute.firewalls.insert`、`compute.firewalls.patch`、`compute.firewalls.update`（Admin Activity）；SCC 的「防火墙规则开放到 0.0.0.0/0」发现项可命中。VPC Flow Logs 能记录异常连接尝试，用于关联暴力破解与扫描流量。

### 3.2 默认规则与优先级导致意外开放

**缺陷描述**：VPC 创建时附带 `default-allow-internal`（允许同网络内互通）与 `default-allow-ssh`（开放 22）等默认规则；团队新增的 deny 规则若优先级（数值）高于默认 allow 规则，会被默认规则覆盖，导致「以为已封禁、实际仍开放」。

**验证命令（只读优先）**：

```bash
# 只读查看全部规则及优先级（priority 数值越小优先级越高）
gcloud compute firewall-rules list --format="table(name,priority,direction,allowed[].map().firewall_rule().list(),sourceRanges.list())"
```

**影响**：默认规则与优先级误配导致攻击者可借助「内部互通」横向移动到本应隔离的网段，或通过残留的 SSH 默认开放进入实例。

**检测侧建议**：`compute.firewalls.insert`/`patch`/`update` 记录规则变更；应审计默认规则，删除不必要的 `default-allow-*`，并明确 deny 规则的优先级与默认规则的关系，避免规则遮蔽。

### 3.3 负载均衡转发规则暴露内部服务

**缺陷描述**：转发规则与后端服务把内部服务映射到公网；若健康检查、后端端口、协议配置错误，或后端服务未做源限制，内部管理接口/API 可被外部访问。

**验证命令（只读优先）**：

```bash
# 只读列出转发规则暴露的协议与端口
gcloud compute forwarding-rules list --format="table(name,IPProtocol,portRange,IPAddress,target)"

# 只读查看后端服务的协议与端口
gcloud compute backend-services list --format="table(name,protocol,port,loadBalancingScheme)"
```

**影响**：内部服务被公网暴露后，可能被未授权访问、利用已知漏洞或作为进入内网的跳板。

**检测侧建议**：转发规则与后端服务的创建/修改对应 `compute.forwardingRules.insert`、`compute.backendServices.update` 等事件；应结合 SCC 的「负载均衡后端开放」发现项与 VPC Flow Logs，审计公网入口与后端映射是否最小化。

### 3.4 VPC Peering / 共享 VPC 过度互通

**缺陷描述**：VPC Peering 使两个 VPC 路由互通，共享 VPC 让宿主项目与多个服务项目共享网络平面。若 Peering 建立到不受信任网络、或共享 VPC 未做子网级隔离，攻击者在一个项目/网络中失陷后可横向蔓延到其它网络。

**验证命令（只读优先）**：

```bash
# 只读列出 VPC Peering 连接及对端网络
gcloud compute networks peerings list --format="table(name,network,peerNetwork,state)"

# 只读列出共享 VPC 的宿主项目与关联服务项目
gcloud compute shared-vpc list-associated-resources <HOST_PROJECT>
```

**影响**：过度互通使网络隔离失效，攻击者可在多个网络间横向移动，扩大数据访问与权限范围。

**检测侧建议**：Peering 建立/删除对应 `compute.networks.addPeering`、`compute.networks.removePeering` 事件；共享 VPC 关联变更对应 `compute.projects.enableXpnResource` 等。应最小化 Peering 范围、启用子网级导出策略，并审查共享 VPC 的宿主/服务项目边界。

### 3.5 内网出站不受控（Cloud NAT / 外部 IP）导致数据外带

**缺陷描述**：实例绑定外部 IP 或经 Cloud NAT 出站，使内网可主动连接公网。攻击者获得内网立足点后，可借此向外部 C2 回连、外带数据，形成隐蔽的数据出口。

**验证命令（只读优先）**：

```bash
# 只读列出绑定外部 IP 的实例
gcloud compute instances list --format="table(name,networkInterfaces[].accessConfigs[0].natIP)"

# 只读查看 Cloud NAT 网关（是否存在出站 NAT）
gcloud compute routers nats list --router <ROUTER> --region <REGION>
```

**影响**：不受控的出站通道使数据外带与 C2 回连难以被阻断，延长攻击者驻留时间。

**检测侧建议**：VPC Flow Logs 可记录出站流量，配合 Cloud Logging 对「内网 → 公网异常目的地」的流量建立基线检测；SCC 与 VPC 防火墙层级策略（Hierarchical Firewall）可限制出站。应在 NAT 与外部 IP 分配上做最小化与审计。

## 四、权限提升与持久化路径

**权限提升主线**：

1. **公网入口 → 内网横向**：通过暴露的 SSH/数据库/负载均衡入口获得单点立足，再借助 `default-allow-internal` 或 Peering 横向移动到内网其它资源。
2. **网络侧提权到云控制面**：在实例内读取元数据服务账号凭据（见 `./metadata-ssrf.md`），将网络立足点升级为云控制面权限。
3. **Peering 跨网络提权**：利用 Peering 互通，从一个网络跳入共享或宿主网络，触达更高价值资源。

**持久化路径**：

1. **新增开放防火墙规则**：写入一条 `0.0.0.0/0` 开放高危端口的规则作为长期入口（授权内人工确认后执行）。
2. **负载均衡后门转发**：新增转发规则/后端服务把内部服务暴露为公网入口。
3. **Peering 后门**：建立到攻击者控制网络的 Peering（授权内人工确认后执行），保留跨网络通道。
4. **外部 IP 保留**：静态保留外部 IP 作为长期回连地址。

## 五、防御与检测要点

审计日志事件名清单：

| 事件名 | 含义 | 关注点 |
| --- | --- | --- |
| `compute.firewalls.insert` | 创建防火墙规则 | 开放 0.0.0.0/0 |
| `compute.firewalls.patch` / `compute.firewalls.update` | 修改防火墙规则 | 放宽源/端口 |
| `compute.firewalls.delete` | 删除防火墙规则 | 破坏防护 |
| `compute.networks.addPeering` | 建立 Peering | 跨网络互通 |
| `compute.networks.removePeering` | 删除 Peering | 边界变化 |
| `compute.forwardingRules.insert` | 创建转发规则 | 暴露内部服务 |
| `compute.backendServices.update` | 修改后端服务 | 后端映射变更 |
| `compute.routers.update` | 修改路由器（含 NAT） | 出站通道变更 |
| `compute.addresses.insert` | 分配外部 IP | 出站/入口 |
| `compute.projects.enableXpnResource` | 共享 VPC 关联 | 网络平面扩展 |

防御建议：

- 防火墙规则遵循最小开放，禁止 `0.0.0.0/0` 访问管理/数据库端口，SSH/RDP 用 IAP（Identity-Aware Proxy）代替公网开放。
- 定期审计默认规则与优先级，删除不必要的 `default-allow-*`，明确 deny 规则遮蔽关系。
- 负载均衡后端做源限制与鉴权，健康检查与转发端口最小化。
- VPC Peering 与共享 VPC 做子网级隔离，最小化互通范围，并审计关联变更。
- 启用 VPC Flow Logs，建立内网出站基线，检测异常外联与扫描流量；配合层级防火墙策略限制出站。
