# K8s 准入控制器与网络策略绕过

> 定位：RBAC 只回答「谁能做什么」，准入控制器（Admission Controllers）回答「什么请求能落地」，
> 网络策略回答「Pod 之间谁能通信」。本手册梳理两者的常见缺陷、绕过路径与只读探测方法，
> 每条路径配检测侧对照。破坏性/变更性步骤标「授权内人工确认后执行」。

## 1. 攻击面

- 准入控制器：Mutating/Validating Webhook、内置控制器（`AlwaysPullImages`、`PodSecurity`、
  `NodeRestriction`、`LimitRanger` 等）。缺陷面在「准入链路可被绕过」「Webhook 配置可被篡改」
  「Webhook 服务本身未鉴权/可被投毒」。
- 网络策略：CNI 实现的 NetworkPolicy 默认放行（未定义 policy 时 Pod 全互通），且策略对
  hostNetwork、kube-system、部分 CNI 覆盖不全；绕过面在「策略遗漏」「策略语义误读」「CNI
  未实际执行策略」。

两条面合起来回答：一个 RBAC 上「不该落地/不该通信」的请求，能不能在准入层与网络层钻过去。

## 2. 暴露面探测（只读命令优先）

### 2.1 准入配置只读盘点

```bash
# 列出准入 Webhook 配置与内置插件（只读）
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o yaml 2>/dev/null
kubectl get podsecuritypolicies 2>/dev/null          # 老版本 PSP
kubectl get --raw /apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations 2>/dev/null
```

关注点：Webhook `failurePolicy=Fail` 还是 `Ignore`、`namespaceSelector` 是否有空匹配、
`rules` 是否覆盖关键资源、`clientConfig.service` 指向的 webhook 服务是否在公网可解析。

### 2.2 网络策略只读盘点

```bash
kubectl get networkpolicies -A -o wide 2>/dev/null
kubectl get networkpolicies -n <ns> -o yaml 2>/dev/null
```

关注点：是否存在「空 namespaceSelector + 空 podSelector」的默认拒绝策略；策略是否只覆盖
部分命名空间；`egress` 是否被限制（横向移动与数据外传都依赖 egress）。

### 2.3 CNI 实际执行验证（只读）

```bash
# 集群内自省：本 Pod 能否解析并连接目标服务（只读连通性）
kubectl run probe-$RANDOM --rm -it --restart=Never --image=busybox -- sh -c \
  'wget -qO- --timeout=3 http://<target-svc>.<ns>.svc.cluster.local' 2>/dev/null
# 注意：临时 probe Pod 属变更性（创建后 --rm 删除），登记 environment-restore 再执行
```

## 3. 缺陷与利用路径

### 3.1 Validating Webhook `failurePolicy=Ignore` + 服务不可用

- 缺陷：Webhook 配置为 `failurePolicy=Ignore` 时，若 webhook 服务宕机/不可达，准入检查被
  跳过，恶意请求直接落地。
- 验证命令（只读）：`kubectl get validatingwebhookconfigurations -o yaml` 查看
  `failurePolicy` 字段；再探测 webhook 服务端点连通性。
- 影响：绕过准入层的安全校验（如禁止 privileged、禁止高危挂载），把受控请求变不受控。
- 检测侧：K8s audit 记录 `admission webhook` 相关失败与请求落地；webhook 服务不可达会在
  apiserver 日志留 `failed calling webhook`；云审计记录控制面异常。

### 3.2 Webhook `namespaceSelector` 空匹配（匹配了不该匹配的命名空间）

- 缺陷：`namespaceSelector: {}` 匹配所有命名空间（含 kube-system），导致准入规则覆盖
  本不该覆盖的高敏感命名空间，或反过来漏掉攻击者新建的命名空间。
- 验证命令（只读）：读 Webhook 配置的 `namespaceSelector` 与 `objectSelector`，对照命名空间
  标签，判断实际覆盖范围。
- 影响：准入校验出现盲区，攻击者在未覆盖命名空间部署高权负载。
- 检测侧：K8s audit 记录命名空间与对象创建；SIEM 用「创建请求 → 未触发准入校验」的负向
  特征（缺失 webhook 日志）检测，属检测缺口，登记 `detection-gap.md`。

### 3.3 Webhook 服务投毒（客户端 TLS 校验缺失）

- 缺陷：`clientConfig` 未配 `caBundle` 或使用明文/无校验连接，攻击者若能在集群内抢注同名
  服务或劫持 DNS，可让 apiserver 信任伪造的准入响应。
- 验证命令（只读）：`kubectl get validatingwebhookconfigurations -o yaml` 检查
  `clientConfig.caBundle` 是否为空、`url` 是否指向 http。
- 影响：伪造「放行」响应，从准入层整体失效。
- 检测侧：K8s audit 记录 webhook 调用异常；apiserver 日志 `unable to load root ca` /
  `x509` 错误；网络层对 webhook 端口异常流量留痕。

### 3.4 网络策略默认放行与 hostNetwork 逃逸

- 缺陷：集群未设默认拒绝 NetworkPolicy（`{}` 全匹配 deny-all），Pod 之间全互通，横向移动
  无障碍；`hostNetwork: true` 的 Pod 共享节点网络栈，绕开 Pod 级策略。
- 验证命令（只读）：`kubectl get networkpolicies -A` 看是否缺默认拒绝；`kubectl get pod -o
  yaml` 查 `spec.hostNetwork`。
- 影响：一次入口失陷即可横向打所有 Pod，甚至直连节点服务（kubelet/etcd/内部端口）。
- 检测侧：CNI 网络流日志（如 Cilium Hubble、Calico flow log）；云 VPC Flow Logs 记录跨 Pod
  异常流；K8s audit 无法看到 L3/L4 流量，需网络可观测性补位。

### 3.5 网络策略 egress 未限制 → 数据外传/元数据 SSRF

- 缺陷：策略只限制 ingress 或完全没限制 egress，容器可自由访问元数据服务
  （169.254.169.254）与外网 C2。
- 验证命令（只读）：`kubectl get networkpolicies -o yaml` 看 `egress` 段是否缺失；
  结合元数据端点只读探测（见云平台手册附录）。
- 影响：实例角色凭证（IAM/AK）被 SSRF 拉取，横向到云账号。
- 检测侧：云审计记录元数据服务访问与 `AssumeRole`/`GetCallerIdentity` 调用；VPC Flow Logs
  记录 169.254.169.254 目标流量。

### 3.6 PodSecurity/内置准入未启用（无默认安全基座）

- 缺陷：集群未启用 PodSecurity Admission（或等价的准入策略基座），privileged、hostPath、
  hostNetwork 等高危配置可无校验落地。
- 验证命令（只读）：`kubectl get --raw /apis/policy/v1/podsecurityconfigurations 2>/dev/null`
  或读命名空间 `pod-security.kubernetes.io/enforce` 标签看 enforce 级别。
- 影响：高危负载部署无统一拦截，逃逸/越权面扩大。
- 检测侧：K8s audit `pods create` 请求体含高危字段且无对应拒绝；CSPM/配置审计告警缺基座。

## 4. 提权与持久化

- 提权链：准入绕过（部署高权负载）→ 高权 Pod 落地 → 借宿主挂载/特权逃逸（见容器逃逸手册）
  → 节点/云账号。
- 持久化（授权内人工确认后执行）：篡改 Webhook 配置指向攻击者服务（持续放行）；在未覆盖
  命名空间部署长驻 DaemonSet。均为变更性操作，逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 K8s audit 事件名对照

| 攻击行为 | audit 事件 |
|---|---|
| 篡改 Webhook 配置 | `mutatingwebhookconfigurations/validatingwebhookconfigurations update/patch/create` |
| Webhook 调用失败 | apiserver 日志 `failed calling webhook`（非 audit，需日志侧采集） |
| 高权负载落地 | `pods create` + `responseStatus.code=201` + 请求体含 privileged/hostPath |
| 异常命名空间创建 | `namespaces create` + 无对应 webhook 命中 |

### 5.2 云审计与网络可见性

- VPC/VNet Flow Logs 覆盖 L3/L4：横向流量、元数据服务访问、异常外联。
- 云审计覆盖控制面 API；准入层与网络层在云审计中多为「间接证据」，须与集群日志、CNI 流
  日志联合判定。

### 5.3 加固要点

- Webhook：`failurePolicy=Fail`；`caBundle` 必填且用受信 CA；`namespaceSelector` 显式白名单。
- 网络策略：全命名空间默认拒绝 + 显式放行；限制 egress（默认拒绝外联 + 白名单）；隔离
  hostNetwork Pod；隔离 kube-system 与业务网。
- 用 OPA/Gatekeeper/Kyverno 把「禁止 privileged、禁止 hostPath、禁止高危挂载、禁止 cluster
  管理员绑定」写成可审计的拒绝策略。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 准入 Webhook 配置篡改 | T1098 Account Manipulation |
| 部署高权/特权负载 | T1610 Deploy Container |
| 网络策略绕过横向 | T1021 Remote Services |
| 未限 egress 数据外传 | T1048 Exfiltration Over Alternative Protocol |
| 集群暴露面探测 | T1613 Container and Resource Discovery |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 只读验证命令的输出原文存 evidence-index.md；疑似结论标 partial/unknown，不进 confirmed。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。
