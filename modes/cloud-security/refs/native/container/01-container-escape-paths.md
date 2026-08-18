# 容器逃逸路径全景：privileged、capabilities、挂载 socket、内核漏洞类、运行时配置

> 定位：容器逃逸是「容器 → 宿主」的边界突破，是云原生攻击里影响最大的一跳。本手册按逃逸
> 原语分类给出只读判定命令、影响分级与检测侧对照；只写授权测试思路，不写完整武器化利用，
> 破坏性验证统一标「授权内人工确认后执行」。检测侧以运行时审计 + 宿主审计 + K8s audit 三
> 层叠加。

## 1. 攻击面

容器逃逸的根因是「隔离边界上有一个多余的能力/挂载/缺陷」。按原语分五类：

| 类别 | 原语 | 后果 |
|---|---|---|
| 特权容器 | `privileged: true`（等于宿主 root 的绝大多数能力） | 直接挂载宿主设备、写宿主进程 |
| 能力超配 | `CAP_SYS_ADMIN`、`CAP_DAC_READ_SEARCH`、`CAP_NET_RAW` 等 | 挂载、ptrace、抓包越界 |
| 挂载泄露 | `/var/run/docker.sock`、`/proc`、宿主 `/`、`/dev` | 操控 Docker 守护进程、读写宿主 |
| 内核漏洞 | Dirty COW / Dirty Pipe 类、内核提权 CVE | 从容器 root 提宿主 root |
| 运行时配置 | 未用 user namespace、seccomp/AppArmor 未开、runC/containerd 旧版 CVE | 隔离失效 |

攻击面判定先回答：容器内是否 root、有哪些 capability、挂载了什么敏感路径、运行时是什么版本。

## 2. 暴露面探测（只读命令优先）

### 2.1 能力与特权自省（只读）

```bash
# 当前能力位图（只读）
grep Cap /proc/self/status
capsh --print 2>/dev/null | grep -iE 'current|bounding'
# 是否是特权容器（只读，通过设备与能力推断）
ls -l /dev/ 2>/dev/null | head
cat /proc/1/status | grep -E 'CapEff|Seccomp'
```

判定口径：`CapEff` 含 `CAP_SYS_ADMIN`（bit 21）、`CAP_DAC_READ_SEARCH`（bit 2）即高危；
`/dev` 可见全部块设备且可读写 = 特权容器特征。

### 2.2 挂载面自省（只读）

```bash
mount | grep -E 'overlay|/dev/|/proc|hostPath|docker'
cat /proc/self/mountinfo | grep -E '/docker.sock|/run/containerd|/host|/proc'
ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
```

判定口径：挂载了 `docker.sock` 或 `containerd.sock` = 可通过守护进程 API 逃逸；挂载宿主
`/` 或 `/proc` = 直接读写宿主。

### 2.3 内核与运行时版本自省（只读）

```bash
uname -a
cat /proc/version
# 容器运行时（若有 sock 或客户端）
docker version 2>/dev/null || ctr version 2>/dev/null
```

判定口径：内核版本匹配已知提权 CVE 即登记；运行时版本匹配 runC/containerd CVE 即登记。

## 3. 缺陷与利用路径

### 3.1 privileged 容器 → 挂载宿主设备

- 缺陷：`securityContext.privileged: true`，容器拥有宿主根级设备访问。
- 验证命令（只读）：`lsblk` / `cat /proc/partitions` 看宿主磁盘；`ls -l /dev/` 看设备可写。
  实际挂载宿主根属破坏性，**授权内人工确认后执行**。
- 影响：读写宿主文件系统，落植入/窃取宿主敏感文件（如 `/etc/shadow`、kubelet 配置、
  云凭证文件）。
- 检测侧：K8s audit `pods create` 请求体含 `privileged: true`；运行时审计（Falco）规则
  「Privileged Container」+「Read Sensitive File Untrusted」；宿主审计记录异常 mount。

### 3.2 挂载 docker.sock → 守护进程 API 接管

- 缺陷：`hostPath` 挂载 `/var/run/docker.sock`，容器可通过 Unix socket 调 Docker API 启动
  一个挂载宿主 `/` 的新容器。
- 验证命令（只读）：`docker -H unix:///var/run/docker.sock ps`（列出宿主容器）确认 API 可达。
  启动逃逸容器属破坏性，**授权内人工确认后执行**。
- 影响：等价宿主 root，可横向到同节点所有容器与节点本身。
- 检测侧：运行时审计「Container Started in Container」（sock 调用）；K8s audit `pods create`
  请求体含 docker.sock hostPath；宿主审计记录 dockerd 收到的新容器创建。

### 3.3 CAP_SYS_ADMIN + 未限制 mount → 挂载宿主

- 缺陷：容器有 `CAP_SYS_ADMIN` 且 seccomp/AppArmor 未禁止 `mount`/`pivot_root`，可挂载宿主
  文件系统。
- 验证命令（只读）：`capsh --print` 确认 `CAP_SYS_ADMIN`；`cat /proc/self/status | grep Seccomp`
  看 seccomp 是否 0（未启用）。实际挂载属破坏性，**授权内人工确认后执行**。
- 影响：读写宿主，同 privileged 后果。
- 检测侧：运行时审计「Mount」异常（容器内非预期 mount 调用）；seccomp audit 日志记录被
  拦/放行的 mount syscall；K8s audit 请求体含 `capabilities.add: [SYS_ADMIN]`。

### 3.4 CAP_DAC_READ_SEARCH / 未隔离 procfs → 读宿主进程

- 缺陷：容器有 `CAP_DAC_READ_SEARCH` 或挂载了宿主 `/proc`，可绕过文件权限读宿主敏感文件、
  甚至对宿主进程 ptrace。
- 验证命令（只读）：`capsh --print` 确认能力；`ls /proc | head` 看是否可见宿主 PID。
- 影响：窃取宿主进程内存/凭据，进一步提权。
- 检测侧：运行时审计「Read Sensitive File Untrusted」/「Ptrace」；宿主审计记录异常
  `open`/`ptrace`；K8s audit 请求体含 `CAP_DAC_READ_SEARCH`。

### 3.5 内核漏洞类提权（Dirty Pipe 等）

- 缺陷：容器共享宿主内核，内核提权 CVE 在容器内触发即可提宿主 root。
- 验证命令（只读）：`uname -a` 比对内核版本是否落在受影响区间；`cat /proc/version` 确认
  发行版补丁状态。实际触发 exploit 属破坏性，**授权内人工确认后执行**，且只在授权实验
  环境复现。
- 影响：容器 root → 宿主 root，突破一切容器隔离。
- 检测侧：宿主审计记录异常 syscall 序列（如 splice 越界写特征）；EDR/宿主 HIDS 记录提权；
  K8s audit 无法看到内核层，须宿主侧检测补位（登记检测缺口）。

### 3.6 运行时旧版 CVE（runC / containerd）

- 缺陷：runC/containerd 历史版本存在逃逸 CVE（如 runC 覆盖宿主二进制、containerd 抽象
  socket 漏洞）。
- 验证命令（只读）：`docker version` / `ctr version` 读版本，比对受影响区间。
- 影响：容器逃逸或宿主 RCE。
- 检测侧：运行时升级与补丁审计；宿主审计记录异常进程执行路径；容器镜像内不可信进程落地
  宿主文件。

## 4. 提权与持久化

- 提权链：容器 → 逃逸宿主（socket/特权/内核）→ 宿主 root → 读 kubelet 凭据/节点凭证 →
  K8s 控制面（见 `../k8s/` 手册）→ 云账号（节点角色元数据，见 `../k8s/05-managed-k8s-platform-risks.md`）。
- 持久化（授权内人工确认后执行）：在宿主落 cron/systemd 后门、写 `.ssh/authorized_keys`、
  用 sock 启动长驻特权容器；逐项登记 `environment-restore.md`，删除类只出清单由用户执行。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| privileged 落地 | K8s audit `pods create` + 请求体 privileged；Falco「Privileged Container」 |
| sock 逃逸 | Falco「Container Started in Container」；dockerd 日志 |
| 异常 mount | Falco「Mount」；seccomp audit 日志 mount syscall |
| 读宿主敏感文件 | Falco「Read Sensitive File Untrusted」；宿主 auditd open |
| 内核提权 | 宿主 auditd/EDR 异常 syscall + 提权告警 |
| 宿主进程执行 | Falco「Execution from /proc」；宿主 auditd execve |

### 5.2 加固要点

- 禁 `privileged: true`；capabilities 白名单最小化（默认 drop ALL + add 所需）。
- 禁挂 `docker.sock`/`containerd.sock`/宿主 `/`/`/proc`；用准入策略硬拦截。
- 启用 seccomp（default profile）+ AppArmor/SELinux；启用 user namespace remap。
- 运行时保新（runC/containerd 补丁）；内核及时打补丁。
- 部署运行时审计（Falco/Sysdig）+ 宿主 auditd + EDR，三层叠加覆盖「K8s audit 看不到的
  内核与宿主页」。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 容器逃逸 | T1611 Escape to Host |
| 部署特权容器 | T1610 Deploy Container |
| 内核/能力提权 | T1068 Exploitation for Privilege Escalation |
| 宿主持久化 | T1543 Create or Modify System Process |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 逃逸验证只在授权实验环境复现，触发 exploit 前标「授权内人工确认后执行」。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。
