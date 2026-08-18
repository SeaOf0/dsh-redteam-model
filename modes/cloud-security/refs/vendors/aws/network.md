# VPC / 安全组 / NACL / ELB / Route53 网络攻防

本文聚焦 AWS 网络层的攻击面、常见配置缺陷与检测要点，供授权安全评估参考。实例元数据与 SSRF 链路见 `./ssrf-metadata.md`，计算资源见 `./ec2.md`，数据库暴露见 `./rds.md`。

## 一、攻击面

网络层攻击面覆盖从边界到服务的整条链路：

- **安全组（Security Group）**：有状态，控制实例/资源级入站出站规则，过度放行是首要问题
- **NACL**：无状态，子网级允许/拒绝规则，规则顺序错误易致绕过
- **路由表与子网**：公网/私有子网划分、路由指向错误、VPC 对等与端点
- **ELB**：负载均衡监听器、安全组、访问日志，明文端口与过宽入站范围
- **Route53**：DNS 托管区、记录篡改、悬空 CNAME/别名导致的域名接管

## 二、信息收集 / 暴露面探测

```bash
# VPC / 子网 / 路由表拓扑
aws ec2 describe-vpcs
aws ec2 describe-subnets
aws ec2 describe-route-tables

# 安全组与 NACL 规则
aws ec2 describe-security-groups --query 'SecurityGroups[].[GroupId,GroupName,IpPermissions,IpPermissionsEgress]'
aws ec2 describe-network-acls

# 对等连接与端点
aws ec2 describe-vpc-peering-connections
aws ec2 describe-vpc-endpoints

# 负载均衡器（ELB/ALB/NLB）
aws elbv2 describe-load-balancers
aws elbv2 describe-listeners --load-balancer-arn arn:aws:elasticloadbalancing:...
aws elbv2 describe-target-groups

# Route53 托管区与记录
aws route53 list-hosted-zones
aws route53 list-resource-record-sets --hosted-zone-id Z0123ABCD

# 弹性 IP 与 NAT 网关
aws ec2 describe-addresses
aws ec2 describe-nat-gateways
```

## 三、常见配置缺陷与利用路径

### 3.1 安全组过度开放

**缺陷描述**：安全组入站规则放行 `0.0.0.0/0` 或过宽网段，尤其是管理端口（22/3389）与数据库端口（3306/5432/1433）直接对公网开放。

**验证命令（只读优先）**：

```bash
aws ec2 describe-security-groups --query 'SecurityGroups[].[GroupId,GroupName,IpPermissions[].{FromPort:FromPort,ToPort:ToPort,IpRanges:IpRanges}]'
```

**影响**：实例/服务直接暴露公网，成为爆破、漏洞利用入口，扩大初始访问面。

**检测侧建议**：`AuthorizeSecurityGroupIngress` 写入 CloudTrail；Config 可检测对 `0.0.0.0/0` 的开放。建议默认拒绝、管理端口仅限跳板网段、按服务拆分安全组。

### 3.2 NACL 规则顺序与无状态误配

**缺陷描述**：NACL 规则按编号顺序匹配，误把高编号的 Deny 放在 Allow 之后，或未正确配置返回流量（无状态需显式放行双向），导致限制失效或服务异常。

**验证命令（只读优先）**：

```bash
aws ec2 describe-network-acls --query 'NetworkAcls[].[NetworkAclId,Entries[]]'
```

**影响**：边界过滤被绕过，本应隔离的子网互通，横向移动面扩大。

**检测侧建议**：`CreateNetworkAclEntry`、`ReplaceNetworkAclEntry` 写入 CloudTrail；建议对 NACL 变更做变更审计，规则排序与双向放行做规范化检查。

### 3.3 ELB 监听器配置不当

**缺陷描述**：ELB 监听器仅配置明文端口（80/未加密内部端口），或安全组/监听器入站范围过宽；NLB 透传时后端安全组被忽略，防护依赖后端自身。

**验证命令（只读优先）**：

```bash
aws elbv2 describe-listeners --load-balancer-arn arn:aws:elasticloadbalancing:...
aws elbv2 describe-load-balancers --query 'LoadBalancers[].[LoadBalancerName,Scheme,SecurityGroups]'
```

**影响**：明文流量可被嗅探，后端直接暴露，形成数据泄露或攻击面放大。

**检测侧建议**：`CreateListener`、`ModifyListener` 写入 CloudTrail；结合 ELB 访问日志与 VPC Flow Logs 识别异常明文流量。建议公网监听强制 TLS 重定向。

### 3.4 Route53 域名接管

**缺陷描述**：DNS 记录指向已释放的 ELB 别名、CloudFront 分配或悬空 CNAME 目标，攻击者重新占用该目标后接管域名，用于钓鱼或内容投毒。

**验证命令（只读优先）**：

```bash
aws route53 list-resource-record-sets --hosted-zone-id Z0123ABCD
aws elbv2 describe-load-balancers --query 'LoadBalancers[].DNSName'
```

**影响**：子域名接管，客户流量被重定向，可投放钓鱼页面或窃取凭证。

**检测侧建议**：`ChangeResourceRecordSets` 写入 CloudTrail；结合 Route53 查询日志与 DNS 解析结果监测悬空记录。建议删除资源前先清理 DNS 记录。

### 3.5 VPC 对等与路由泄露

**缺陷描述**：VPC 对等连接或路由表配置错误，使生产网段与测试/第三方网段互通，绕过网络隔离预期。

**验证命令（只读优先）**：

```bash
aws ec2 describe-vpc-peering-connections
aws ec2 describe-route-tables --query 'RouteTables[].Routes[]'
```

**影响**：跨环境横向移动，隔离域失效。

**检测侧建议**：`CreateVpcPeeringConnection`、`AcceptVpcPeeringConnection`、`CreateRoute`、`ReplaceRoute` 写入 CloudTrail；建议对等连接白名单化，路由变更纳入变更管理。

### 3.6 VPC 端点策略过宽

**缺陷描述**：S3/Gateway 端点或 Interface 端点策略未限制，任何能到达该端点的流量都可访问对应服务，绕过出口管控。

**验证命令（只读优先）**：

```bash
aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].[VpcEndpointId,ServiceName,VpcEndpointType]'
```

**影响**：内网主机经端点直连外部服务，数据外带或越权访问。

**检测侧建议**：`CreateVpcEndpoint`、`ModifyVpcEndpoint` 写入 CloudTrail；建议端点策略最小化，配合 VPC Flow Logs 审计端点流量。

## 四、权限提升与持久化路径

- **安全组自我放行**：拥有 `ec2:AuthorizeSecurityGroupIngress` 时给自己的 IP 放行，绕过网络隔离（需授权内确认）。
- **路由表劫持**：修改路由把流量指向攻击者可控的 NAT/实例，进行中间人或数据窃取（需授权内确认）。
- **Route53 记录篡改**：修改 A/别名记录把域名指向恶意主机，持续钓鱼或窃密。
- **VPC 对等持久化**：建立并维持对等连接，形成长期跨环境通道。

## 五、防御与检测要点

| 攻击者动作 | CloudTrail 事件名 | 检测/告警建议 |
| --- | --- | --- |
| 安全组入站放行 | `AuthorizeSecurityGroupIngress`、`RevokeSecurityGroupIngress` | 对 `0.0.0.0/0` 与管理端口告警 |
| 创建/修改安全组 | `CreateSecurityGroup`、`ModifySecurityGroupRules` | 对非预期规则告警 |
| NACL 变更 | `CreateNetworkAclEntry`、`ReplaceNetworkAclEntry` | 对 Deny/Allow 顺序变更审计 |
| 路由变更 | `CreateRoute`、`ReplaceRoute`、`DeleteRoute` | 对默认路由/指向变更告警 |
| 监听器变更 | `CreateListener`、`ModifyListener` | 对明文端口/过宽范围告警 |
| DNS 记录变更 | `ChangeResourceRecordSets` | 对 A/别名记录变更告警 |
| 对等/端点变更 | `CreateVpcPeeringConnection`、`CreateVpcEndpoint` | 对跨环境通道建立告警 |

配套日志与检测服务：CloudTrail、VPC Flow Logs、Config、GuardDuty、Route53 查询日志、ELB 访问日志、Security Hub。防线核心：默认拒绝、安全组最小化、管理端口仅跳板可达、DNS 记录与资源生命周期联动、对等与端点白名单治理。
