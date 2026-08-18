# cloud-security refs 知识库

云安全攻防模式深度手册库。按需读入上下文，不主动全量加载。共 61 篇。

## knowledge/（知识速查）（5 篇）

| 文件 | 标题 |
|---|---|
| knowledge/attck-cloud-matrix.md | ATT&CK Cloud Matrix 速查（战术与技术 ID 对照） |
| knowledge/cloud-api-readonly-probing.md | 云 API 只读探测纪律与速率默认值（附录 B） |
| knowledge/cloud-security-tool-cards.md | 云安全工具卡 |
| knowledge/iam-policy-language-cheatsheet.md | IAM/权限策略语言速查（AWS IAM / Azure RBAC / GCP IAM / 阿里云 RAM） |
| knowledge/metadata-service-endpoints.md | 六厂商元数据服务端点与实例身份对照表（附录 A） |

## vendors/（厂商云服务攻防）（36 篇）

| 文件 | 标题 |
|---|---|
| vendors/aliyun/ecs.md | ECS 计算实例攻防 |
| vendors/aliyun/network.md | VPC/vSwitch/安全组/SLB/NAT 网络攻防 |
| vendors/aliyun/oss.md | OSS 对象存储攻防 |
| vendors/aliyun/ram.md | RAM 访问控制与权限攻防 |
| vendors/aliyun/rds.md | RDS 云数据库攻防 |
| vendors/aliyun/ssrf-console.md | 从 SSRF 到接管控制台 |
| vendors/aws/ec2.md | EC2 计算实例攻防 |
| vendors/aws/iam.md | IAM 与权限攻防 |
| vendors/aws/network.md | VPC / 安全组 / NACL / ELB / Route53 网络攻防 |
| vendors/aws/rds.md | RDS 云数据库攻防 |
| vendors/aws/s3.md | S3 对象存储攻防 |
| vendors/aws/ssrf-metadata.md | 从 SSRF 到元数据凭证（IMDSv1/v2）攻防 |
| vendors/azure/blob.md | Azure Blob Storage 对象存储攻防 |
| vendors/azure/entra-id.md | Microsoft Entra ID（原 Azure AD）身份与权限攻防 |
| vendors/azure/managed-identity-ssrf.md | 从 SSRF 到托管标识（Managed Identity）元数据 Token 攻防 |
| vendors/azure/network.md | Azure VNet / NSG / 负载均衡 / 应用网关网络攻防 |
| vendors/azure/sql-database.md | Azure SQL Database / Cosmos DB 云数据库攻防 |
| vendors/azure/vm.md | Azure VM 计算实例攻防 |
| vendors/gcp/cloud-sql.md | Cloud SQL 云数据库攻防 |
| vendors/gcp/cloud-storage.md | Cloud Storage 对象存储攻防 |
| vendors/gcp/compute-engine.md | Compute Engine 计算实例攻防 |
| vendors/gcp/iam.md | Cloud IAM 与权限攻防 |
| vendors/gcp/metadata-ssrf.md | 从 SSRF 到元数据服务账号 token 攻防 |
| vendors/gcp/network.md | VPC / 子网 / 防火墙规则 / 负载均衡网络攻防 |
| vendors/huawei/ecs.md | 华为云 ECS 弹性云服务器攻防 |
| vendors/huawei/iam.md | 华为云 IAM 身份与权限攻防 |
| vendors/huawei/metadata-ssrf.md | 华为云 从 SSRF 到元数据委托临时凭证攻防 |
| vendors/huawei/network.md | 华为云 VPC/子网/安全组/ELB/NAT 网络攻防 |
| vendors/huawei/obs.md | 华为云 OBS 对象存储攻防 |
| vendors/huawei/rds.md | 华为云 RDS 云数据库攻防 |
| vendors/tencent/cam.md | CAM 访问管理攻防 |
| vendors/tencent/cos.md | COS 对象存储攻防 |
| vendors/tencent/cvm.md | CVM 云服务器攻防 |
| vendors/tencent/database.md | TencentDB 云数据库攻防 |
| vendors/tencent/metadata-ssrf.md | 从 SSRF 到元数据 CAM 临时凭证攻防 |
| vendors/tencent/network.md | VPC / 安全组 / CLB / NAT 网络攻防 |

## native/（云原生攻防）（16 篇）

| 文件 | 标题 |
|---|---|
| native/cicd/01-pipeline-attack-surface.md | CI-CD 流水线攻击面：构建系统凭据泄露、Runner 接管 |
| native/cicd/02-code-repo-permission-abuse.md | 代码仓库权限滥用 |
| native/cicd/03-artifact-repo-poisoning.md | 制品仓库投毒与签名绕过 |
| native/cicd/04-iac-template-misconfig.md | IaC 模板缺陷引入：Terraform / CloudFormation 权限过宽 |
| native/container/01-container-escape-paths.md | 容器逃逸路径全景：privileged、capabilities、挂载 socket、内核漏洞类、运行时配置 |
| native/container/02-image-supply-chain.md | 镜像供应链：Dockerfile 缺陷、镜像层泄露、私有仓库未授权 |
| native/container/03-container-network-runtime-detection.md | 容器网络与运行时安全：seccomp / AppArmor / 运行时审计（检测侧） |
| native/k8s/01-cluster-exposure-mapping.md | K8s 集群暴露面测绘：API Server / kubelet / etcd 暴露与未授权探测 |
| native/k8s/02-rbac-abuse-privesc.md | K8s RBAC 权限滥用与提权：ServiceAccount 权限枚举、cluster-admin 获取链 |
| native/k8s/03-admission-networkpolicy-bypass.md | K8s 准入控制器与网络策略绕过 |
| native/k8s/04-secret-config-exposure.md | K8s Secret 与配置泄露利用 |
| native/k8s/05-managed-k8s-platform-risks.md | 多云托管 K8s 特性与集成风险（EKS / AKS / GKE / ACK / TKE） |
| native/serverless/01-function-permission-trigger-abuse.md | Serverless 函数权限与触发器滥用：事件注入、S3 触发链 |
| native/serverless/02-env-secrets.md | Serverless 环境变量与密钥 |
| native/serverless/03-supply-chain-dependency-poisoning.md | Serverless 函数供应链与依赖投毒 |
| native/serverless/04-function-persistence.md | 云函数特有持久化 |

## detection/（检测侧）（4 篇）

| 文件 | 标题 |
|---|---|
| detection/cloud-audit-log-systems.md | 云审计日志体系（六厂商对照） |
| detection/cloud-detection-gap-methodology.md | 云检测缺口分析方法论（三态判定 ↔ C5 门） |
| detection/cloud-detection-rule-design.md | 云检测规则设计（事件 → 检测规则） |
| detection/cloud-monitoring-alerting-baseline.md | 云安全监控与告警基线 |

## 使用约定

- 引用一律相对路径（refs 内互引、playbook 引用本目录）；禁止绝对路径。
- 每个利用路径条目自带检测侧对照（该攻击在云审计/监控里的可见性）。
- 正文无来源痕迹；技术事实（API 名/端点/策略语法/ATT&CK ID）正常保留。
- 附录 A=六厂商元数据端点与实例身份对照（knowledge/metadata-service-endpoints.md）；
  附录 B=云 API 只读探测纪律与速率默认值（knowledge/cloud-api-readonly-probing.md）。
