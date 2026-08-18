# native/ 云原生攻防参考库（refs/native/）

> 本目录随 cloud-security 预设打包分发，是 `refs/native/` 下「云原生」攻击面的深度手册库，
> 覆盖 Kubernetes / 容器 / Serverless / CI-CD 四大块。所有文件为预设内自包含资源，互相引用
> 只用相对路径，不依赖机器特定路径。路径解析：相对 `refs/` 即 `native/`；从 SKILL 侧访问用
> `refs/native/`。

## 授权立场提醒（先读）

- 本目录属 cloud-security 授权攻防立场：攻击视角默认授权，统一授权立场，不逐任务复核；
  本地为默认验证环境，授权目标按任务执行。
- 使用方式：只读 API/命令优先 → 研究已知缺陷 → 复现验证（破坏性步骤标「授权内人工确认后
  执行」）→ 每项缺陷必须配**检测侧视角**（K8s audit 事件名 / 运行时审计 / 云审计日志 /
  secret scanning / CSPM），检测侧情报回馈 attack-defense 与 `detection-gap.md`。
- 破坏性/变更性操作先询问；删除操作严禁执行，只出清单由用户确认后执行；凭证发现登记归属
  后提示轮换；不写完整武器化利用代码，只写授权测试思路与只读探测命令。
- 跨模式流动：与 pentest（web 入口）、code-audit（IaC/云源码）、attack-defense/av-evasion
  （检测侧）按任务协同，遵守生态规则「取各 playbook 证据标准最严者」。

## 快速路由（按研究类型找目录）

| 研究类型 | 目录 |
|---|---|
| Kubernetes 集群攻防（暴露面/RBAC/准入网络/Secret/托管集群） | `k8s/` |
| 容器攻防（逃逸/镜像供应链/运行时检测侧） | `container/` |
| Serverless 攻防（触发器滥用/密钥/供应链/持久化） | `serverless/` |
| CI-CD 攻防（流水线/代码仓库/制品仓库/IaC） | `cicd/` |

## 目录索引（全量）

### k8s/（5 篇）

| 文件 | 内容 |
|---|---|
| 01-cluster-exposure-mapping.md | API Server / kubelet / etcd 暴露与未授权探测 |
| 02-rbac-abuse-privesc.md | ServiceAccount 权限枚举、RBAC 提权、cluster-admin 获取链 |
| 03-admission-networkpolicy-bypass.md | 准入控制器与网络策略绕过 |
| 04-secret-config-exposure.md | Secret 与配置泄露利用 |
| 05-managed-k8s-platform-risks.md | EKS/AKS/GKE/ACK/TKE 集成风险 |

### container/（3 篇）

| 文件 | 内容 |
|---|---|
| 01-container-escape-paths.md | 容器逃逸路径全景（privileged/capabilities/socket/内核/运行时配置） |
| 02-image-supply-chain.md | 镜像供应链（Dockerfile 缺陷/镜像层泄露/私有仓库未授权） |
| 03-container-network-runtime-detection.md | 容器网络与运行时安全（seccomp/AppArmor/运行时审计，检测侧） |

### serverless/（4 篇）

| 文件 | 内容 |
|---|---|
| 01-function-permission-trigger-abuse.md | 函数权限与触发器滥用（事件注入/S3 触发链） |
| 02-env-secrets.md | 环境变量与密钥 |
| 03-supply-chain-dependency-poisoning.md | 函数供应链与依赖投毒 |
| 04-function-persistence.md | 云函数特有持久化 |

### cicd/（4 篇）

| 文件 | 内容 |
|---|---|
| 01-pipeline-attack-surface.md | CI-CD 流水线攻击面（构建凭据泄露/Runner 接管） |
| 02-code-repo-permission-abuse.md | 代码仓库权限滥用 |
| 03-artifact-repo-poisoning.md | 制品仓库投毒与签名绕过 |
| 04-iac-template-misconfig.md | IaC 模板缺陷引入（Terraform/CFN 权限过宽） |

## 计数

共 16 篇 md + 4 个子目录 README + 本总 README。
