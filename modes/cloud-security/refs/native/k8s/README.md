# k8s/ 参考手册（云原生 · Kubernetes）

> 本目录随 cloud-security 预设打包分发，是 `refs/native/k8s/` 下关于 Kubernetes 集群攻击面
> 的深度手册。所有文件为预设内自包含资源，互相引用只用相对路径，不依赖机器特定路径。
> 路径解析：相对 `refs/native/` 即 `k8s/`；从 SKILL 侧访问用 `refs/native/k8s/`。

## 授权立场提醒（先读）

- 本目录属 cloud-security 授权攻防立场：攻击视角默认授权，统一授权立场，不逐任务复核；
  只读 API/命令优先，破坏性/变更性操作先询问，删除操作只出清单由用户确认后执行。
- 每篇的利用路径条目都配**检测侧对照**（K8s audit 事件名 / 云审计事件），检测侧情报回馈
  attack-defense 与 `detection-gap.md` 消费。
- 破坏性步骤一律标「授权内人工确认后执行」；凭证发现登记归属后提示用户轮换。

## 快速路由（按研究类型找文件）

| 研究类型 | 文件 |
|---|---|
| 集群暴露面测绘（API Server/kubelet/etcd 未授权探测） | `01-cluster-exposure-mapping.md` |
| RBAC 权限枚举与提权（SA 权限、cluster-admin 获取链） | `02-rbac-abuse-privesc.md` |
| 准入控制器与网络策略绕过 | `03-admission-networkpolicy-bypass.md` |
| Secret 与配置泄露利用 | `04-secret-config-exposure.md` |
| 多云托管 K8s 特性与集成风险 | `05-managed-k8s-platform-risks.md` |

## 目录索引

| 文件 | 内容 | 何时读 |
|---|---|---|
| 01-cluster-exposure-mapping.md | API Server/kubelet/etcd 暴露面与未授权探测（只读命令、判定口径、影响分级） | 开工第 1 步测绘 |
| 02-rbac-abuse-privesc.md | ServiceAccount 权限枚举、RBAC 提权链、token 铸造、pods/exec 跳板 | 拿到有限身份后 |
| 03-admission-networkpolicy-bypass.md | 准入 Webhook 绕过、网络策略默认放行/egress 缺失 | 部署受控、横向通信受限时 |
| 04-secret-config-exposure.md | Secret/ConfigMap/SA token/镜像层/GitOps 泄露与云凭证放大 | 找凭证与横向时 |
| 05-managed-k8s-platform-risks.md | EKS/AKS/GKE/ACK/TKE 云身份↔集群身份桥接风险 | 托管集群或云账号联动时 |

## 计数

共 5 篇 md。
