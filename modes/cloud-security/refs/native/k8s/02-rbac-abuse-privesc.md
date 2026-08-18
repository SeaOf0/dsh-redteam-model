# K8s RBAC 权限滥用与提权：ServiceAccount 权限枚举、cluster-admin 获取链

> 定位：拿到一个有限身份（Pod 内 ServiceAccount、CI 机器人、普通用户）后，如何只读地枚举
> 其权限边界、拼出到 cluster-admin 的提权链。所有枚举命令以 `auth can-i` 自省为主，写操作
> 统一标「授权内人工确认后执行」。每条路径配检测侧对照（K8s audit 事件名 + 云审计）。

## 1. 攻击面

RBAC 是 Kubernetes 授权的最小模型：`Role/ClusterRole` 定义「能做什么」，`RoleBinding/
ClusterRoleBinding` 定义「谁拥有它」。攻击面本质是三条：

- 权限边界不清：ServiceAccount 被绑了超出工作负载需要的 verbs/resources。
- 可写绑定：当前身份能创建/修改 RoleBinding，就能给自己或他人授 cluster-admin。
- 高价值资源可达：`secrets`、`serviceaccounts/token`、`pods/exec`、`pods`（挂载宿主敏感
  路径）、`roles/rolebindings` 五类资源是提权跳板。

核心枚举结论要落到「四要素」：身份（SA/用户/组）→ 权限（Role 清单）→ 资源（可达对象）→
影响（能做什么）。

## 2. 暴露面探测（只读命令优先）

### 2.1 身份自省

```bash
# 当前身份是谁（自省，不写）
kubectl auth whoami 2>/dev/null || \
kubectl get pod -A -o yaml >/dev/null 2>&1; \
kubectl config current-context 2>/dev/null
```

Pod 内读 ServiceAccount token 的声明，判断身份与 issuer（不泄密值，只读声明）：

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
# 只解码 payload 的 sub/namespace/kubernetes.io/serviceaccount/name 声明
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null
```

### 2.2 权限清单枚举（只读核心命令）

```bash
# 全命名空间自省：当前身份在 -A 范围可做哪些 verbs
kubectl auth can-i --list -A

# 针对性探测（只读，逐项问「我能不能」）
kubectl auth can-i list secrets -A
kubectl auth can-i create token --as=<sa> -n <ns>      # 能否为某 SA 铸造 token
kubectl auth can-i create serviceaccounts -n <ns>
kubectl auth can-i create rolebindings -n <ns>
kubectl auth can-i create clusterrolebindings
kubectl auth can-i get pods -A
kubectl auth can-i create pods/exec -A
```

判定口径：`yes` = 该动词该资源可执行；`--list -A` 输出为「资源 / verbs / 命名空间」三元组，
是后续拼链的原材料。

### 2.3 只读拉取现有绑定关系

```bash
# 列出可读命名空间内的 Role/RoleBinding/ClusterRole/ClusterRoleBinding（只读）
kubectl get roles,rolebindings,clusterroles,clusterrolebindings -A -o wide 2>/dev/null
# 单条绑定详情（看谁绑了 cluster-admin）
kubectl get clusterrolebinding cluster-admin -o yaml 2>/dev/null
```

若对绑定资源有读权限，即可绘制「主体 → 角色 → 资源」图，找到已达 cluster-admin 的入口点。

## 3. 缺陷与利用路径

### 3.1 ServiceAccount 权限过宽（直接越权读 Secret）

- 缺陷：工作负载 SA 被绑了 `secrets` 的 `get/list` 或 `*`，而业务本不需要。
- 验证命令（只读）：`kubectl auth can-i list secrets -A` 返回 yes 后，
  `kubectl get secrets -A` 拉取全部 Secret。
- 影响：拿到集群内全部凭据（数据库、第三方 AK/SK、其他 SA token），横向展开。
- 检测侧：K8s audit `secrets list`（空 `resourceNames` 全量）+ 主体为普通 SA 名；
  云审计对控制面 API 调用留痕，异常主体 + 全量 secrets 组合触发告警。

### 3.2 可写 RoleBinding → 自我提权

- 缺陷：当前身份对 `rolebindings` 或 `clusterrolebindings` 有 `create/update/patch` 权限。
- 验证命令（只读）：`kubectl auth can-i create rolebindings -n <ns>` 返回 yes 即存在路径。
- 影响：创建一条把自身绑到 `cluster-admin`（或高权 ClusterRole）的 Binding 即完成提权。
  执行属于变更性操作：**授权内人工确认后执行**，并在 `environment-restore.md` 登记。
- 检测侧：K8s audit `rolebindings create` / `clusterrolebindings create` 事件，`responseStatus
  .code=201`，`requestObject.roleRef.name=cluster-admin` 是最高危特征。

### 3.3 ServiceAccount token 铸造（TokenRequest 提权）

- 缺陷：对目标 SA 有 `create` 权限（`serviceaccounts/token` 子资源）即可为其铸造长期/短期
  token，无需知道其现有凭证。
- 验证命令（只读）：`kubectl auth can-i create token --as=<target-sa> -n <ns>` 返回 yes。
- 影响：若目标 SA 是 cluster-admin 绑定，铸造 token 即等于接管控制面。
- 检测侧：K8s audit `serviceaccounts/token create`（`create token`）事件，`user.username` 与
  `as` 伪装主体分离；连续对多个 SA 铸造 token 是典型攻击特征。

### 3.4 `pods/exec` + 宿主挂载 → 节点逃逸前置

- 缺陷：对 `pods/exec` 有执行权限，且目标 Pod 挂载了宿主敏感路径（如 `/var/run/docker.sock`、
  `/proc`、宿主 `/`）或以 privileged 运行。
- 验证命令（只读）：`kubectl get pod <p> -o yaml` 看 `spec.volumes[*].hostPath` 与
  `securityContext.privileged`；`kubectl auth can-i create pods/exec` 确认执行面。
- 影响：exec 进容器后借挂载面逃逸（详见容器逃逸手册 `../container/01-container-escape-paths.md`）。
- 检测侧：K8s audit `pods/exec create` + `attach`，`requestObject.container` 与源 IP 留痕；
  运行时审计记录 exec 会话。

## 4. 提权与持久化

### 4.1 提权链模板

```
有限 SA ──(can-i list secrets)──▶ 读 Secret ──▶ 拿到高权 SA token / 云 AK
有限 SA ──(create rolebinding)──▶ 绑 cluster-admin ──▶ 控制面
有限 SA ──(create token on 高权 SA)──▶ 铸造高权 token ──▶ 控制面
有限 SA ──(exec + hostPath/socket)──▶ 节点/容器逃逸
```

每条链落盘时补「四要素 + 证据编号」，疑似链不进 confirmed。

### 4.2 持久化（授权内人工确认后执行）

- 创建额外 ServiceAccount + 隐蔽命名空间 + 绑定（登记 `lateral-persistence.md`）。
- 创建指向自身的长效 TokenRequest（`audience` 定制，绕开默认短期 token 上限）。
- 以上均为变更性操作，逐项在 `environment-restore.md` 登记还原方式。

## 5. 检测与加固要点

### 5.1 K8s audit 事件名对照

| 攻击行为 | audit 事件 |
|---|---|
| 权限枚举 | `selfsubjectaccessreviews create`（高频即告警） |
| 全量读 Secret | `secrets list`（空 resourceNames） |
| 自我提权 | `rolebindings/clusterrolebindings create`，roleRef=cluster-admin |
| token 铸造 | `serviceaccounts/token create`（或 `create token`） |
| exec 进入 | `pods/exec create`、`pods/attach create` |
| 创建高权 SA | `serviceaccounts create` + `rolebindings create` 成对出现 |

### 5.2 云审计与第三方

- EKS 控制面审计、GKE Admin Activity、AKS 诊断日志都会记录上述 API 调用，可做 SIEM 规则。
- 云审计给「谁、何时、从哪个 IP、调哪个 K8s API」的归因，弥补集群内匿名面的归属困难。

### 5.3 加固要点

- 最小权限：SA 默认只绑必要 verbs/resources，禁用 `*` 与全命名空间 `secrets` 读。
- 禁止普通身份创建 rolebinding/clusterrolebinding；用准入策略（OPA/Kyverno）拦截
  cluster-admin 绑定。
- TokenRequest 边界：限制可被铸造 token 的 SA 集合，缩短 token 生命周期。
- 审计告警：对 `selfsubjectaccessreviews` 突发、`cluster-admin` 绑定、全量 secrets 读设阈值。
