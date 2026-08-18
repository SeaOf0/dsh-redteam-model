# K8s 集群暴露面测绘：API Server / kubelet / etcd 暴露与未授权探测

> 定位：云原生攻击路径的第一步。本手册给出对 Kubernetes 控制平面三件套（API Server、
> kubelet、etcd）暴露面的只读探测方法、未授权访问的判定口径、影响分级与逐项检测侧对照。
> 主观念约束：发现 ≠ 真实；真实 = API 响应原文 + 审计日志 + 权限清单三重证据。只读探测优先，
> 破坏性步骤一律标「授权内人工确认后执行」。

## 1. 攻击面

Kubernetes 集群的攻击面按「谁暴露在网络上、暴露面背后的权限是什么」分层：

| 组件 | 默认端口 | 暴露形态 | 未授权风险 |
|---|---|---|---|
| API Server | 6443 / 8080(已废弃) | 公网/内网 LB、TLS 端口 | 匿名访问 / 弱凭证 / 已泄露 kubeconfig |
| kubelet | 10250(读写) / 10255(只读,已废弃) | 节点直连端口，常无鉴权 | 匿名 exec/logs/run 命令 |
| etcd | 2379/2380 | 常仅节点网，但配置错误会暴露 | 匿名读写全部集群状态（含 Secret） |
| 附加面 | — | dashboard、metrics-server、kube-state-metrics | 仪表盘未鉴权、指标泄露元数据 |

攻击面测绘回答三个问题：控制面端口在哪里可到达、到达后是否免凭证、免凭证后能读到什么。

## 2. 暴露面探测（只读命令优先）

### 2.1 端口与可到达性探测

先用网络层只读探测确认可达性，不改动集群状态：

```bash
# 端口连通性（TCP SYN 扫描，只发握手，不建立完整会话）
nc -zv <host> 6443 10250 10255 2379 2380 2>&1

# 若在集群内 Pod，先看本 Pod 所处的网段与服务发现
env | grep -iE 'kubernetes|kube'       # 读环境变量
cat /etc/resolv.conf                    # 读 DNS 配置，推断集群域
```

### 2.2 API Server 匿名探测

匿名探测以「只读」方式判断是否允许匿名访问，不写入任何对象：

```bash
# 匿名探测：不携带凭证，看 API Server 是否应答
curl -k -s https://<apiserver>:6443/version
curl -k -s https://<apiserver>:6443/api/v1/namespaces
curl -k -s https://<apiserver>:6443/api  # 列出 API 组与资源版本

# 已废弃的 insecure-port（8080）只在老版本存在
curl -s http://<apiserver>:8080/version
```

判定口径：匿名返回 200 且 body 里有资源对象 = 匿名可读；返回 403/401 = 匿名被拒（正常）。
返回 `version` 对象（gitVersion/编译信息）本身不算高危，但能用于版本指纹与已知 CVE 匹配。

### 2.3 kubelet 未授权探测

kubelet 读写端口 10250 默认**不要求客户端证书**，通过 `/pods` 暴露完整 Pod 列表与
Secret 引用（Secret 值在 K8s ≥1.7 后不随 /pods 返回，但 metadata/环境变量/挂载路径可见）：

```bash
# 只读探测：列节点上的 Pod（含 namespace、容器、镜像、环境变量、挂载点）
curl -k -s https://<node>:10250/pods
curl -k -s http://<node>:10255/pods    # 只读端口（老版本）
```

判定口径：`/pods` 返回 Pod 清单 = kubelet 未授权读。后续章节会展开 exec/run 的读写面，
此处只做暴露面登记。

### 2.4 etcd 暴露探测

etcd 用 gRPC-gateway 暴露 HTTP API，2.x/3.x 的版本探测与匿名读探测：

```bash
# 版本只读探测
curl -s http://<etcd>:2379/version
# 匿名读 key（若未启用 auth，直接可读；auth 开启则返回 401）
curl -s http://<etcd>:2379/v3/kv/range -X POST -d '{"key":"Lw=="}'  # base64("/") 前缀探测
```

判定口径：`/version` 可读但范围探测被拒 = 仅端口暴露（中低危）；范围探测返回 key = etcd
未鉴权（极高危，等价于拿到全部 Secret 与集群状态）。

### 2.5 仪表盘与附加组件探测

```bash
curl -s -o /dev/null -w '%{http_code}' https://<host>/api/v1/namespaces/kube-system/services/kubernetes-dashboard/proxy/
# 指标端点只读探测（可能泄露容器/命名空间元数据）
curl -s http://<host>:10255/metrics
```

## 3. 缺陷与利用路径

### 3.1 API Server 匿名访问（RBAC 未关闭匿名组）

- 缺陷：`--anonymous-auth=true`（默认）时，未授权请求落入 `system:unauthenticated` 组；
  若集群误把该组绑进 `cluster-admin` 或读权限，匿名即读集群。
- 验证命令（只读）：`curl -k -s https://<apiserver>:6443/api/v1/secrets` 若返回 Secret 列表
  即命中。
- 影响：匿名可枚举 Secret/ConfigMap/Pod，后续拼接凭证即可提权。
- 检测侧：K8s audit 记录 `secrets list` 的 `user.username=system:anonymous`、
  `user.groups=[system:unauthenticated]`；响应码 200 与匿名主体组合即告警特征。

### 3.2 kubelet 未授权 /pods 泄露元数据

- 缺陷：kubelet 10250 默认无客户端鉴权（仅部分发行版/云厂商开启 Webhook 鉴权）。
- 验证命令（只读）：`curl -k -s https://<node>:10250/pods | jq '.items[].spec.containers[].env'`
  查看容器环境变量，其中常见注入的数据库密码、对象存储 AK/SK、第三方 API Key。
- 影响：环境变量与挂载路径直接泄露；可进一步通过 exec 通道进入 Pod（见读写面章节）。
- 检测侧：节点级运行时审计与 `kubelet` 日志（`GET /pods`、`GET /exec` 请求行 + 源 IP）；
  K8s audit 不覆盖 kubelet 平面，须靠节点审计 + API Server 之外的主机日志。

### 3.3 etcd 未鉴权暴露

- 缺陷：etcd 未启用 `--client-cert-auth` / auth，且监听 0.0.0.0 或被错误映射到公网。
- 验证命令（只读）：`curl -s http://<etcd>:2379/v3/kv/range -X POST -d '{"key":"L3JlZ2lzdHJ5"}'`
  （base64 "/registry" 前缀），返回 Secret 键名即命中。
- 影响：etcd 是全集群唯一事实源，含全部 Secret、ServiceAccount token、Pod 定义；可恢复
  cluster-admin 控制面。
- 检测侧：etcd 服务端访问日志（grpc 方法 Range + 源 IP）+ 云审计对 2379 端口的网络流；
  K8s audit 在控制面「之上」，etcd 直连不产生 audit 事件——这是关键检测缺口。

### 3.4 已泄露 kubeconfig 的只读定位

- 缺陷：kubeconfig 中的 token/client-certificate 是控制面凭证，泄露即等于身份泄露。
- 验证命令（只读）：拿到疑似 kubeconfig 后
  `kubectl --kubeconfig=<file> auth can-i --list -A`（自省当前身份可做什么，不改动）。
- 影响：视凭证绑定的 Role/ClusterRole 而定，可能是完整控制。
- 检测侧：K8s audit 的 `selfsubjectaccessreviews create` 事件（`verb=create,
  resource=selfsubjectaccessreviews`）正是攻击者/工具枚举权限的强信号；云审计记录访问源 IP。

## 4. 提权与持久化

暴露面测绘阶段的「提权」以只读自省为主，避免在此阶段做写入：

- 权限自省（只读）：`kubectl auth can-i --list -A`、`kubectl auth can-i get secrets -A`。
- 身份映射（只读）：读取当前 `~/.kube/config` 或容器内
  `/var/run/secrets/kubernetes.io/serviceaccount/token` 的 `sub/iss` 声明，判断身份。
- 持久化思路（授权内人工确认后执行）：在拿到写入权限后创建高权限 ServiceAccount 或
  RoleBinding 属于变更性操作，须在 `lateral-persistence.md` 登记、授权确认后执行，且
  逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 K8s audit 事件名对照

| 攻击行为 | audit 事件（objectRef.resource + verb） |
|---|---|
| 匿名枚举 Secret | `secrets` + `list/get` + `user.username=system:anonymous` |
| 枚举自身权限 | `selfsubjectaccessreviews` + `create` |
| 遍历命名空间 | `namespaces` + `list` |
| 读取全部 Secret | `secrets` + `list`（`resourceNames` 为空表示全量） |
| 探测 API 组 | `apiservices` / `apiregistration.k8s.io` + `list` |

### 5.2 云审计日志可见性

- 托管 K8s（EKS/AKS/GKE）控制面审计默认接入云审计：EKS 需显式开启控制面日志投递
  CloudWatch/CloudTrail，AKS 有诊断设置，GKE 有 Cloud Audit Logs 的 Admin Activity。
- kubelet 平面与 etcd 直连通常**不进**云审计，须靠节点日志/主机审计补位——在
  `detection-gap.md` 登记为 gap。

### 5.3 加固要点

- API Server：关闭 `--anonymous-auth` 或确保 `system:unauthenticated` 无任何绑定；
  对外暴露走受控 LB + 网络策略 + 白名单源 IP。
- kubelet：开启 Webhook 鉴权与授权（`--authorization-mode=Webhook`），关闭只读端口
  10255（`--read-only-port=0`）。
- etcd：启用 `--client-cert-auth` 与 RBAC，绑定内网接口，禁用公网映射，定期轮换证书。
- 统一：禁止把 6443/10250/2379 直接映射公网；用端口级网络策略 + 云安全组兜底。
