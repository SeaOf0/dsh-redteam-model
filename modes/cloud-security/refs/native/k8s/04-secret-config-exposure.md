# K8s Secret 与配置泄露利用

> 定位：Secret/ConfigMap 是 K8s 里最密集的凭证载体，也是攻击路径里「身份→权限」的跳板。
> 本手册梳理 Secret 的存储/挂载/暴露形态、只读提取方法、凭证到云账号的放大链，以及每条
> 路径的检测侧对照。破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

Secret 的泄露面分四层：

| 层 | 形态 | 典型载体 |
|---|---|---|
| 集群内 | etcd 明文存储、API 读权限、SA token | Secret 对象、ServiceAccount token |
| 挂载层 | 被挂进 Pod 为文件/环境变量 | `/var/run/secrets/...`、env |
| 镜像层 | 构建时被烤进镜像 | Dockerfile 里的密码、`docker history` 泄露 |
| 外部同步 | Secret 同步到外部存储/CI 变量 | ExternalSecrets、GitOps 仓库、Helm values |

常见高价值 Secret 类型：云 AK/SK（AWS AccessKey/阿里云 AK）、数据库密码、私有仓库凭证
（imagePullSecret）、其他命名空间的 SA token、TLS 私钥。

## 2. 暴露面探测（只读命令优先）

### 2.1 读权限自省

```bash
kubectl auth can-i get secrets -n <ns>
kubectl auth can-i list secrets -A
```

### 2.2 只读提取 Secret（有权限时）

```bash
kubectl get secrets -A -o wide                        # 列表（name/type/data 键名）
kubectl get secret <name> -n <ns> -o yaml             # 详情，data 为 base64
kubectl get secret <name> -n <ns> -o jsonpath='{.data}' | while read k v; do echo "$k=$(echo $v | base64 -d)"; done
```

### 2.3 Pod 内挂载面只读盘点

```bash
# 看当前容器挂载了哪些 secret/环境变量（不泄密值，先列名）
env | grep -iE 'key|token|secret|password|ak|sk|credential'
ls -la /var/run/secrets/kubernetes.io/serviceaccount/    # SA token 挂载
find / -maxdepth 4 -name '*.pem' -o -name 'token' 2>/dev/null | head
```

### 2.4 ConfigMap 泄露只读盘点

```bash
kubectl get configmaps -A -o wide 2>/dev/null
kubectl get configmap <name> -n <ns> -o yaml 2>/dev/null   # 常含明文配置/连接串
```

判定口径：`data` 里出现 `password`/`accessKey`/`secretKey`/`ConnectionString` 等键即登记，
值不进报告原文（脱敏后引用），凭证纪律要求提示用户轮换。

## 3. 缺陷与利用路径

### 3.1 Secret 明文存 etcd 且未加密

- 缺陷：默认 etcd 存储的 Secret 不加密（KMS 静态加密需显式开启），etcd 泄露 = Secret 全量
  泄露（与 `01-cluster-exposure-mapping.md` 的 etcd 面联动）。
- 验证命令（只读）：见 etcd 探测（`01-cluster-exposure-mapping.md` 第 2.4 节）。
- 影响：全部凭证可恢复。
- 检测侧：etcd 访问日志（Range 方法）；K8s audit 不覆盖 etcd 直连，登记检测缺口。

### 3.2 过度授权导致 Secret 全量可读

- 缺陷：普通身份被绑了 `secrets get/list`，或用了 `cluster-admin` 到处跑。
- 验证命令（只读）：`kubectl auth can-i list secrets -A` + `kubectl get secrets -A`。
- 影响：横向读全部凭据。
- 检测侧：K8s audit `secrets list`（空 resourceNames，全量）+ 非系统主体；云审计归因源 IP。

### 3.3 SA token 挂载泄露（automountServiceAccountToken）

- 缺陷：Pod 默认挂载 SA token，若应用有 SSRF/文件读取/命令注入，token 可被读取并用于
  以 SA 身份调用 API。
- 验证命令（只读）：`kubectl get pod -o yaml` 查 `automountServiceAccountToken` 是否 false；
  Pod 内 `ls /var/run/secrets/kubernetes.io/serviceaccount/token`。
- 影响：token 即身份，权限=SA 绑定权限，可横向调用 API。
- 检测侧：K8s audit 记录以该 SA 主体发起的 API 调用（`user.username=system:serviceaccount:
  <ns>:<sa>`），异常时段的调用即告警。

### 3.4 镜像层与构建配置泄露

- 缺陷：Dockerfile 里写死密码、`ARG` 传 AK/SK、`docker build --build-arg` 传密钥，历史层
  残留可读。
- 验证命令（只读）：`docker history --no-trunc <image>` 或镜像仓库层拉取查看；私有仓库
  未授权则整库可拉（见容器供应链手册 `../container/02-image-supply-chain.md`）。
- 影响：镜像即凭证分发面。
- 检测侧：仓库访问日志（匿名/越权 pull）；镜像扫描工具检出硬编码密钥（secret scanning）。

### 3.5 GitOps / Helm values / ExternalSecrets 同步面泄露

- 缺陷：Secret 明文提交到 GitOps 仓库、Helm values 明文、ExternalSecrets 引用错误的远端
  存储导致越权读取。
- 验证命令（只读）：仓库历史搜索（`git log -p` 搜 `AKIA`/`BEGIN PRIVATE KEY`/`password`）；
  ExternalSecrets CR 读引用路径。
- 影响：凭证外溢到版本库与外部存储，脱离集群审计视野。
- 检测侧：Git 仓库审计与 secret scanning；云审计记录外部密钥存储（SSM/Secrets Manager/KMS）
  的 GetSecretValue/Decrypt 调用。

### 3.6 imagePullSecret 滥用（私有仓库凭证横向复用）

- 缺陷：imagePullSecret 绑定的私有仓库凭证被过宽授予，或该凭证可在多命名空间复用，攻击者
  用它拉取其它命名空间的私有镜像。
- 验证命令（只读）：`kubectl get secret <pull-secret> -n <ns> -o yaml` 看 type 是否为
  kubernetes.io/dockerconfigjson；`kubectl get sa -A -o yaml` 看哪些 SA 引用了它。
- 影响：私有仓库凭证复用，拉取内部镜像找密钥/源码。
- 检测侧：仓库访问审计（凭证拉取记录）；K8s audit `secrets get`（imagePullSecret）；
  云审计记录仓库 API 调用。

## 4. 提权与持久化

- 提权链：Secret（云 AK/SK）→ 云账号 AssumeRole/GetCallerIdentity 自省 → IAM 权限放大 →
  云资源接管（见云平台手册）；Secret（SA token）→ `auth can-i --list` → RBAC 提权（见
  `02-rbac-abuse-privesc.md`）。
- 持久化（授权内人工确认后执行）：用泄露的 imagePullSecret 拉取/投毒镜像；用高权 SA token
  铸造长效 token。变更性操作逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 K8s audit 事件名对照

| 攻击行为 | audit 事件 |
|---|---|
| 全量读 Secret | `secrets list`（空 resourceNames） |
| 读单个 Secret | `secrets get` + `resourceNames=<name>` |
| 以窃取 SA 身份调 API | 任意事件 + `user.username=system:serviceaccount:<ns>:<sa>` |
| 读 ConfigMap | `configmaps get/list` |

### 5.2 云审计可见性

- 云密钥读取（`GetSecretValue`/`Decrypt`/`AssumeRole`）在 CloudTrail/Cloud Audit Logs/活动
  日志留痕，是「Secret 是否被云侧滥用」的关键证据。
- 集群内 Secret 读与云侧密钥读要做关联分析（同一身份/时间窗/源 IP）。

### 5.3 加固要点

- etcd 开启静态加密（KMS envelope）；开启 audit 并保留 Secret 访问事件。
- 最小权限：禁全量 `secrets list`；Secret 按命名空间隔离。
- 关闭非必要 `automountServiceAccountToken`；用 IRSA/Workload Identity/OIDC 替代静态 AK/SK。
- 禁明文进仓库：secret scanning + ExternalSecrets/SealedSecrets 托管；镜像构建用多阶段 +
  不在历史层留密钥。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| Secret/凭证泄露 | T1552 Unsecured Credentials |
| 窃取 ServiceAccount token | T1528 Steal Application Access Token |
| 复用泄露身份 | T1078 Valid Accounts |
| 读取云存储数据 | T1530 Data from Cloud Storage |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 凭证值脱敏引用，不进报告原文；登记归属后提示用户轮换。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。
