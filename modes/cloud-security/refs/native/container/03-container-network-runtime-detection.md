# 容器网络与运行时安全：seccomp / AppArmor / 运行时审计（检测侧）

> 定位：本篇是容器三篇里的「检测侧」半场——从防御方视角讲 seccomp/AppArmor 如何拦下逃逸
> 原语、运行时审计如何把这些拦下的行为变成可查询的告警，以及攻击者视角下这些机制的缺口
> 在哪里。与 `01-container-escape-paths.md` 的利用路径一一配对使用。只读探测为主。

## 1. 攻击面（检测侧视角）

容器检测侧的三道闸：

| 层 | 机制 | 拦截什么 |
|---|---|---|
| 内核系统调用 | seccomp（默认 profile 拦 mount/关键 syscall） | 逃逸原语 syscall |
| LSM 强制访问控制 | AppArmor / SELinux | 文件/挂载/网络的强制策略 |
| 运行时观测 | Falco / Sysdig / 云运行时审计 | 把行为转成告警事件 |

检测侧的攻击面（即「检测缺口」）在：seccomp 未启用或被设为 unconfined、AppArmor 未加载、
运行时审计未部署或规则过宽、日志未集中导致告警丢失。

## 2. 暴露面探测（只读命令优先）

### 2.1 seccomp / AppArmor 状态自省（只读）

```bash
# 容器内看 seccomp 是否生效（0=未启用，2=filter 模式）
grep Seccomp /proc/self/status
# 宿主看 AppArmor 是否加载、容器 profile 是否 enforce
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
docker inspect <cid> --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null
kubectl get pod <p> -o yaml | grep -A3 securityContext   # 看 seccompProfile/appArmorProfile
```

判定口径：`Seccomp: 0` + `securityContext` 未指定 profile = 逃逸原语 syscall 未被拦；
`apparmor` 未 enabled 或 profile 为 `unconfined` = LSM 失效。

### 2.2 运行时审计部署只读盘点

```bash
# 集群内运行时审计组件（Falco 等）是否部署
kubectl get pods -A | grep -iE 'falco|sysdig|audit'
# 云运行时审计开关（各厂商控制台/CLI 只读查询）
```

判定口径：无运行时审计组件 = 逃逸行为无观测，登记 `detection-gap.md`。

## 3. 缺陷与利用路径（检测侧对照）

### 3.1 seccomp=unconfined 或未启用

- 缺陷：Pod 未指定 seccompProfile 且运行时默认放行（部分运行时默认 unconfined），逃逸相关
  syscall（`mount`、`ptrace`、`keyctl`、`bpf` 等）可自由调用。
- 验证命令（只读）：`grep Seccomp /proc/self/status`；`kubectl get pod -o yaml` 看
  `seccompProfile` 是否缺省。
- 影响：逃逸原语无内核层拦截，成功率显著上升。
- 检测侧：seccomp 未启用本身是审计项（K8s audit `pods create` 请求体缺 seccompProfile）；
  运行时审计仍能记录 `mount`/`ptrace` 调用，但拦截缺失，须配置告警。

### 3.2 AppArmor 未加载 / profile=unconfined

- 缺陷：宿主未启用 AppArmor 或容器 profile 为 `unconfined`，文件与挂载访问不受 LSM 约束。
- 验证命令（只读）：`cat /sys/module/apparmor/parameters/enabled`；`docker inspect` 的
  `SecurityOpt`。
- 影响：`CAP_DAC_READ_SEARCH` 等能力 + 无 LSM = 读宿主敏感文件更易。
- 检测侧：宿主审计记录 LSM 拒绝/放行事件；AppArmor 审计日志（`/var/log/audit` 或 journal）
  记录 profile 违规；未加载 LSM 是配置审计项。

### 3.3 运行时审计规则过宽 / 未覆盖关键事件

- 缺陷：Falco 等规则被裁剪（如关闭「Mount」「Read Sensitive File Untrusted」），或只监控
  部分命名空间。
- 验证命令（只读）：读运行时审计规则集与作用范围；`kubectl get pods -A | grep falco` 看
  部署范围。
- 影响：真实逃逸行为落入盲区，告警缺失。
- 检测侧：这是「检测的检测」——对审计组件自身做配置审计与覆盖评估；告警吞吐基线对比。

### 3.4 运行时审计日志未集中 / 告警未联动

- 缺陷：Falco 输出只落本地 stdout，未进 SIEM/云安全中心，无告警路由与响应。
- 验证命令（只读）：看审计组件日志输出与转发配置；云安全中心是否订阅运行时告警。
- 影响：攻击行为有记录但无人看，检测失效。
- 检测侧：日志集中与告警链路完整性审计；用受控的只读探针（非破坏性）验证告警可达。

### 3.5 审计规则投毒（篡改规则使高危行为放行）

- 缺陷：运行时审计组件（Falco 等）的规则/配置被篡改，关闭「Mount」「Read Sensitive File
  Untrusted」等关键规则，或把告警输出重定向到黑洞。
- 验证命令（只读）：读审计组件规则集与配置，比对基线；`kubectl get ds <falco> -o yaml`
  看规则挂载与最近变更。
- 影响：真实逃逸行为落入盲区，检测被掐断。
- 检测侧：K8s audit `daemonsets update`/`configmaps update`（审计组件配置变更）；
  审计组件自身日志（规则重载）；告警吞吐基线骤降。

### 3.6 容器网络横向与元数据访问的检测缺口

- 缺陷：容器网络层（东西向流量、元数据服务访问）无流量镜像/审计，横向与 SSRF 拉取实例
  角色凭证无观测。
- 验证命令（只读）：只读盘点 CNI 流日志开关（如 Hubble/flow log 是否启用）、云 VPC Flow
  Logs 是否覆盖集群网段。
- 影响：横向移动与元数据窃取不可见，检测滞后。
- 检测侧：VPC/VNet Flow Logs（169.254.169.254 目标流量、跨 Pod 异常流）；云审计记录
  GetCallerIdentity/AssumeRole；K8s audit 无法覆盖 L3/L4，登记 detection-gap.md。

## 4. 提权与持久化

（本篇为检测侧，提权/持久化主路径见 `01-container-escape-paths.md`；检测侧的「提权」指：
关闭/篡改审计组件、投毒审计规则使其放行。此类操作属变更性，**授权内人工确认后执行**，
并登记 `environment-restore.md`。）

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| mount 逃逸原语 | seccomp 放行/拒绝日志、Falco「Mount」 |
| 读宿主敏感文件 | Falco「Read Sensitive File Untrusted」、AppArmor 拒绝 |
| ptrace 宿主进程 | Falco「Ptrace」、宿主 auditd ptrace |
| 容器内异常进程 | Falco「Execution from /proc」「Terminal Shell in Container」 |
| 审计组件被篡改 | K8s audit `daemonsets update`（Falco 规则/config 变更） |

### 5.2 加固要点

- 强制 seccomp 默认 profile + 关键工作负载自定义 profile；禁 `unconfined`。
- 启用 AppArmor/SELinux，按工作负载加载 enforce profile。
- 部署运行时审计（Falco/Sysdig）覆盖全命名空间，规则保默认高危集；日志进 SIEM + 告警联动。
- 把「审计组件自身」纳入审计与配置漂移检测，防止检测链被掐断。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 关闭/削弱检测 | T1562 Impair Defenses |
| 容器逃逸检测 | T1611 Escape to Host |
| 运行时探测 | T1613 Container and Resource Discovery |

## 7. 证据记录要点

- 检测侧结论逐项落到 detection-gap.md：gap=1（缺失）/无法评估=0/不适用=2，禁空泛。
- 对审计组件自身做配置审计与覆盖评估，防止「检测的检测」成盲区。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| seccomp 状态 | `grep Seccomp /proc/self/status` |
| AppArmor 状态 | `cat /sys/module/apparmor/parameters/enabled` |
| 运行时审计部署 | `kubectl get pods -A | grep falco` |
| 审计组件配置 | `kubectl get ds <falco> -o yaml` |
| 元数据/外联流量 | VPC Flow Logs 只读查询（169.254.169.254 目标） |
