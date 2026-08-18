---
name: ir-forensics-linux
description: >
  Linux 系统取证完整手册：覆盖 Linux 系统工件分析 (日志、进程、网络)、审计日志入侵检测、
  内核 Rootkit 检测与分析、文件系统 Slack 空间分析、Linux 持久化机制调查。
  包含应急响应命令集、日志分析查询、Rootkit 检测工具、证据收集脚本、命令速查表和 MITRE ATT&CK 映射。
domain: cybersecurity
subdomain: digital-forensics
tags: [linux-forensics, linux-ir, rootkit-detection, audit-logs, slack-space, persistence,
  linux-artifacts]
version: 2.0.0
---

# Linux 系统取证 — 完整手册

## 适用场景

**适用于:** Linux 服务器入侵调查、Linux 系统工件分析、内核 Rootkit 检测、
审计日志分析、文件系统 Slack 空间取证、持久化机制发现。

**不适用于:** 磁盘镜像获取（见 ir-forensics-disk）、Windows 取证（见 ir-forensics-windows）、
网络流量分析（见 network-traffic-analysis）。

**前置条件:**
- 受感染 Linux 系统的 root 权限
- 取证工具集 (SIFT/REMnux 或手动安装)
- 了解 Linux 文件系统层次和进程模型
- 可信的静态编译工具 (或从 USB 运行)

---

## Part A：取证方法论

### 1. 初始响应 — 易失性证据收集

#### 1.1 优先收集顺序（按易失性排序）

```bash
#!/bin/bash
# ir_volatile_collect.sh — 易失性证据收集脚本
# 在受感染系统上运行，输出保存到外部存储

OUTDIR="/mnt/evidence/volatile_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] 收集易失性证据..."

# 1. 当前日期时间
date -u > "$OUTDIR/timestamp.txt"

# 2. 运行进程
ps auxf > "$OUTDIR/ps_auxf.txt"
ps -eo pid,ppid,user,start,etime,cmd > "$OUTDIR/ps_full.txt"
top -b -n 1 > "$OUTDIR/top.txt"

# 3. 网络连接
ss -tulpn > "$OUTDIR/ss_tulpn.txt"
ss -tulpna > "$OUTDIR/ss_all.txt"
netstat -tulpna > "$OUTDIR/netstat.txt" 2>/dev/null
ip addr show > "$OUTDIR/ip_addr.txt"
ip route show > "$OUTDIR/ip_route.txt"
arp -a > "$OUTDIR/arp.txt"

# 4. 打开文件
lsof > "$OUTDIR/lsof.txt" 2>/dev/null
lsof -i > "$OUTDIR/lsof_network.txt" 2>/dev/null

# 5. 内存映射
cat /proc/*/maps > "$OUTDIR/proc_maps.txt" 2>/dev/null

# 6. 内核模块
lsmod > "$OUTDIR/lsmod.txt"
cat /proc/modules > "$OUTDIR/proc_modules.txt"

# 7. 已挂载文件系统
mount > "$OUTDIR/mount.txt"
cat /proc/mounts > "$OUTDIR/proc_mounts.txt"

# 8. 计划任务
crontab -l > "$OUTDIR/crontab_root.txt" 2>/dev/null
ls -la /etc/cron* > "$OUTDIR/cron_dirs.txt"
cat /etc/crontab > "$OUTDIR/etc_crontab.txt"
for u in $(cut -d: -f1 /etc/passwd); do
  crontab -u "$u" -l >> "$OUTDIR/crontab_all.txt" 2>/dev/null
done

# 9. Systemd 定时器
systemctl list-timers --all > "$OUTDIR/systemd_timers.txt"
systemctl list-units --type=service --all > "$OUTDIR/systemd_services.txt"

# 10. 环境变量
env > "$OUTDIR/env.txt"

# 11. 用户登录记录
last > "$OUTDIR/last.txt"
lastlog > "$OUTDIR/lastlog.txt"
who > "$OUTDIR/who.txt"

# 12. 计算所有输出文件哈希
cd "$OUTDIR"
find . -type f -exec sha256sum {} \; > checksums.sha256
echo "[+] 易失性证据收集完成: $OUTDIR"
```

### 2. 日志分析

#### 2.1 系统日志关键查询

```bash
# 认证日志 (Ubuntu/Debian: /var/log/auth.log, RHEL/CentOS: /var/log/secure)
# 检查 SSH 暴力破解
grep -i "failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# 成功 SSH 登录
grep "Accepted" /var/log/auth.log
grep "session opened" /var/log/auth.log

# sudo 使用记录
grep "sudo:" /var/log/auth.log
grep "COMMAND=" /var/log/auth.log

# 用户切换
grep "su:" /var/log/auth.log

# 新用户/组创建
grep "new user\|new group" /var/log/auth.log

# 系统日志关键事件
grep -iE "error|fail|warn|critical|panic" /var/log/syslog | tail -100

# 内核消息
dmesg | grep -iE "kill|oom|segfault|error"
```

#### 2.2 Audit 日志入侵检测

```bash
# 确保 auditd 正在运行
systemctl status auditd

# 检查审计规则
auditctl -l

# 关键审计查询

# 1. 特定用户的所有操作
ausearch -ua 1000 -ts today | ausearch -ua 1000 -ts today

# 2. 特定文件的所有访问
ausearch -f /etc/shadow -ts today

# 3. 系统调用监控 (execve = 命令执行)
ausearch -sc execve -ts today

# 4. 网络连接
ausearch -sc connect,bind,accept -ts today

# 5. 用户切换/sudo
ausearch -m USER_ACCT,USER_AUTH,USER_MGMT -ts today

# 6. 文件修改
ausearch -m PATH -ts today | grep -E "fcntl|open|truncate"

# 7. 恶意命令执行分析
# 从 audit 日志提取所有执行的命令
ausearch -sc execve -ts 01/01/2024 | aureport -x

# 8. 未授权访问尝试
ausearch -m ANOM_LOGIN_FAILURES -ts today
ausearch -m USER_ACCT -sv no -ts today

# 9. 关键系统文件变更
ausearch -f /etc/passwd -f /etc/shadow -f /etc/sudoers -ts today

# 10. 格式化审计报告
aureport -au    # 认证报告
aureport -x     # 执行报告
aureport -f     # 文件报告
aureport -l     # 登录报告
aureport -m     # 账户修改报告
```

#### 2.3 日志完整性验证

```bash
# 检查日志时间戳跳跃 (可能被篡改)
awk '{print $1,$2,$3}' /var/log/auth.log | uniq -c | awk '$1 > 10'

# 检查日志文件属性
ls -la /var/log/auth.log /var/log/syslog

# 检查日志轮换配置
cat /etc/logrotate.conf
ls -la /etc/logrotate.d/

# 检查 rsyslog 远程转发是否被篡改
cat /etc/rsyslog.conf | grep -E "^\*|@|@@"

# 文件系统时间戳分析
stat /var/log/auth.log
# 检查 Modify vs Change 时间差异
```

### 3. Linux 持久化机制调查

```bash
# 1. 用户账户检查
cat /etc/passwd | awk -F: '$3 == 0 {print "[!] Root 权限用户:", $1}'
cat /etc/passwd | awk -F: '$3 >= 1000 {print $1, $3, $7}'
grep -v "nologin\|false" /etc/passwd | awk -F: '{print $1, $7}'

# 2. SSH 授权密钥
for user_dir in /home/* /root; do
  if [ -f "$user_dir/.ssh/authorized_keys" ]; then
    echo "[*] $user_dir/.ssh/authorized_keys:"
    cat "$user_dir/.ssh/authorized_keys"
  fi
done

# 3. Shell 配置文件后门
grep -r "nc\|ncat\|socat\|/dev/tcp\|bash -i" /home/*/.bashrc /home/*/.bash_profile /root/.bashrc 2>/dev/null

# 4. SSH 配置篡改
grep -E "PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|AuthorizedKeysFile" /etc/ssh/sshd_config | grep -v "^#"

# 5. Systemd 服务持久化
find /etc/systemd/system/ /usr/lib/systemd/system/ /run/systemd/system/ -name "*.service" -newer /etc/hostname 2>/dev/null
# 检查可疑服务
for svc in /etc/systemd/system/*.service; do
  if ! dpkg -S "$svc" 2>/dev/null && ! rpm -qf "$svc" 2>/dev/null; then
    echo "[!] 非包管理器安装的服务: $svc"
  fi
done

# 6. 共享库注入
cat /etc/ld.so.preload
ls -la /etc/ld.so.conf.d/

# 7. init.d/rc.d 脚本
find /etc/init.d/ /etc/rc.d/ -type f -executable | while read f; do
  head -5 "$f" | grep -qi "python\|perl\|nc\|socat" && echo "[!] 可疑启动脚本: $f"
done

# 8. UDEV 规则
cat /etc/udev/rules.d/*.rules | grep -iE "run|exec|script"

# 9. XDG Autostart
ls -la /etc/xdg/autostart/ /home/*/.config/autostart/ 2>/dev/null
```

### 4. 内核 Rootkit 检测

#### 4.1 手动检测

```bash
# 1. /proc 与 /sys 异常
# 检查隐藏模块
cat /proc/modules | awk '{print $1}' | sort > /tmp/modules_proc.txt
lsmod | awk '{print $1}' | sort > /tmp/modules_lsmod.txt
diff /tmp/modules_proc.txt /tmp/modules_lsmod.txt

# 2. 系统调用表检查
cat /proc/kallsyms | grep sys_call_table
# 检查是否有非内核地址的系统调用
cat /proc/kallsyms | grep "T sys_" | awk '{print $1}' | sort | uniq -d

# 3. 检查中断描述符表
cat /proc/kallsyms | grep "idt_table"

# 4. 检查内核代码段完整性
# 对比运行的内核与磁盘上的 vmlinux
# sha256sum /boot/vmlinuz-$(uname -r)

# 5. 检查 /proc 隐藏进程
# 比较 readdir 和直接访问的差异
python3 << 'PYTHON'
import os
readdir_pids = set(os.listdir('/proc'))
direct_pids = set()
for d in os.listdir('/proc'):
    try:
        direct_pids.add(str(int(d)))
    except ValueError:
        pass
hidden = readdir_pids - direct_pids
if hidden:
    print(f"[!] Hidden PIDs: {hidden}")
PYTHON

# 6. 检查网络连接隐藏
# 比较 /proc/net 和 ss 输出
cat /proc/net/tcp | awk '{print $2}' | tail -n +2 | sort > /tmp/proc_net.txt
ss -tln | awk 'NR>1{print $5}' | sed 's/.*://' | sort > /tmp/ss_net.txt
diff /tmp/proc_net.txt /tmp/ss_net.txt
```

#### 4.2 自动化 Rootkit 检测工具

```bash
# chkrootkit
chkrootkit -q 2>&1 | grep -i "INFECTED\|WARNING\|suspicious"

# rkhunter
rkhunter --check --skip-keypress --report-warnings-only

# OSSEC rootcheck (Wazuh 内建)
# 自动运行，检查 /var/ossec/logs/rootcheck.log

# 使用 debugfs 检查 ext 文件系统
debugfs -R "ls -l /" /dev/sda1 2>/dev/null

# 内存中的 Rootkit 检测 (需要 Volatility)
# 见 malware-analysis-memory.md
```

### 5. Slack 空间与文件系统工件分析

```bash
# 1. 文件系统 Slack 空间
# 计算 slack 空间大小
df -i /  # 查看 inode 使用
tune2fs -l /dev/sda1 | grep -i "block size\|reserved"

# 2. 从 slack 空间提取数据
# 使用 bmap 提取 slack 空间
# bmap --mode slack /dev/sda1 > /evidence/slack_data.bin

# 3. 搜索 slack 空间中的敏感数据
strings -a /evidence/slack_data.bin | grep -iE "password|secret|key|token"

# 4. 检查交换空间
swapon --show
dd if=/dev/sda2 of=/evidence/swap.img bs=4M  # sda2 = swap 分区
strings /evidence/swap.img | grep -iE "password|secret|credential" | head -50

# 5. 检查已删除但未覆盖的 inode
# 使用 debugfs
debugfs -R "lsdel" /dev/sda1 2>/dev/null | head -30

# 6. /tmp 和其他临时目录
ls -la /tmp/ /var/tmp/ /dev/shm/
find /tmp/ -type f -executable 2>/dev/null
```

---

## Part B：检测与防御

### 6. Linux 取证加固

#### 6.1 审计规则部署

```bash
# /etc/audit/rules.d/ir_rules.rules — 事件响应审计规则

# 文件监控
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k ssh_config

# 命令执行监控
-a always,exit -F arch=b64 -S execve -F auid>=1000 -k cmd_exec
-a always,exit -F arch=b64 -S execve -F uid=0 -k root_cmds

# 网络监控
-a always,exit -F arch=b64 -S connect -k network
-a always,exit -F arch=b64 -S bind -k network

# 系统调用监控
-a always,exit -F arch=b64 -S clone,fork,vfork -k process_create
-a always,exit -F arch=b64 -S kill -F auid>=1000 -k signal

# 模块加载
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_unload
-w /sbin/modprobe -p x -k module_load

# 时间变更
-a always,exit -F arch=b64 -S settimeofday,clock_settime -k time_change

# 应用规则
augenrules --load
```

#### 6.2 日志完整性保护

```bash
# 使用 rsyslog 前向签名 (RFC 5848)
cat > /etc/rsyslog.d/sign.conf << 'CONF'
$ModLoad imsux
$SystemLogRateLimitInterval 0
# 前向密封签名
$WorkDirectory /var/spool/rsyslog
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
CONF

# 或使用 syslog-ng 的日志签名功能

# 远程日志转发 (防篡改)
cat > /etc/rsyslog.d/remote.conf << 'CONF'
*.* @@log-server.example.com:6514;RSYSLOG_TraditionalFileFormat
CONF

# 文件完整性监控 (AIDE)
aide --init
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# 每日检查 cron
echo "0 6 * * * root /usr/bin/aide --check" > /etc/cron.d/aide
```

---

## 速查表

### Linux IR 命令速查

| 类别 | 命令 | 用途 |
|------|------|------|
| 进程 | `ps auxf` | 完整进程树 |
| 进程 | `lsof -i` | 网络连接关联 |
| 进程 | `lsof -p PID` | 进程打开的所有文件 |
| 网络 | `ss -tulpna` | 所有监听/连接 |
| 网络 | `arp -a` | ARP 表 |
| 网络 | `ip route` | 路由表 |
| 用户 | `last -a` | 登录历史 |
| 用户 | `lastlog` | 最近登录 |
| 用户 | `who -a` | 当前登录 |
| 日志 | `journalctl -u ssh` | SSH 服务日志 |
| 日志 | `ausearch -m USER_AUTH` | 认证事件 |
| 文件 | `find / -ctime -1` | 最近 24h 修改 |
| 文件 | `find / -nouser -nogroup` | 无主文件 |
| 模块 | `lsmod` | 已加载模块 |
| 模块 | `cat /proc/kallsyms` | 内核符号表 |
| 持久化 | `crontab -l` | 计划任务 |
| 持久化 | `systemctl list-units` | 服务列表 |
| 持久化 | `cat /etc/ld.so.preload` | 预加载库 |

### 日志文件位置

| 日志 | 路径 | 内容 |
|------|------|------|
| 认证 | /var/log/auth.log (Debian) | SSH, sudo, su |
| 认证 | /var/log/secure (RHEL) | SSH, sudo, su |
| 系统 | /var/log/syslog (Debian) | 通用系统日志 |
| 系统 | /var/log/messages (RHEL) | 通用系统日志 |
| 内核 | /var/log/kern.log | 内核消息 |
| 审计 | /var/log/audit/audit.log | auditd 日志 |
| Boot | /var/log/boot.log | 启动日志 |
| 应用 | /var/log/nginx/ | Web 服务器 |
| 邮件 | /var/log/mail.log | 邮件服务 |
| Cron | /var/log/cron | 计划任务 |

### Rootkit 检测检查清单

```
□ /proc/modules vs lsmod 差异
□ /proc/net/tcp vs ss 输出差异
□ /proc/*/maps 中的可疑映射
□ cat /etc/ld.so.preload 内容
□ 非标准内核模块 (未知模块名)
□ sys_call_table 地址异常
□ 隐藏进程 (readdir vs 直接遍历)
□ chkrootkit 扫描结果
□ rkhunter 扫描结果
□ /boot/vmlinuz 完整性校验
□ 网卡混杂模式检查 (ip link | grep PROMISC)
```

---

## MITRE ATT&CK 映射

| Technique ID | 名称 | 阶段 | Linux 取证指标 |
|-------------|------|------|--------------|
| T1543.002 | Systemd Service | 持久化 | 可疑 .service 文件 |
| T1053.003 | Scheduled Task/Job: Cron | 持久化 | crontab 分析 |
| T1136.001 | Create Account | 持久化 | /etc/passwd 变更 |
| T1098 | Account Manipulation | 持久化 | 权限提升记录 |
| T1070.002 | Clear Linux Logs | 防御绕过 | 日志缺失/截断 |
| T1014 | Rootkit | 防御绕过 | 内核模块检查 |
| T1574.006 | LD_PRELOAD | 劫持 | /etc/ld.so.preload |
| T1036 | Masquerading | 防御绕过 | 进程名伪装 |
| T1059.004 | Bash | 执行 | shell 历史分析 |
| T1071 | Application Layer Protocol | C2 | 网络连接分析 |

---

## 前置条件

```bash
# 取证工具安装
apt install -y auditd aide chkrootkit rkhunter lsof strace \
  binwalk foremost scalpel testdisk sleuthkit

# 静态编译工具 (用于不可信环境)
# 从可信系统编译或下载 SIFT 静态工具集
# /usr/local/sbin/ps_static
# /usr/local/sbin/netstat_static
# /usr/local/sbin/lsmod_static

# 远程取证工具
apt install -y dd dcfldd dc3dd ewf-tools guymager

# 验证
which auditctl aide chkrootkit rkhunter foremost binwalk
```

---

## Part C：2025-2026 更新

### 7. eBPF 取证

eBPF (extended Berkeley Packet Filter) 是现代 Linux 内核的可观测性核心，可在内核态挂载 tracepoint/kprobe/uprobe 实现零侵入式取证，无需安装内核模块。

#### 7.1 bcc 工具集取证命令

```bash
# 安装 bcc 工具集
apt install -y bpfcc-tools linux-headers-$(uname -r)
# 或
dnf install -y bcc-tools kernel-devel-$(uname -r)

# === 进程取证 ===

# 1. 实时追踪所有 execve 系统调用 (命令执行)
execsnoop-bpfcc
# 输出: PCOMM PID PPID RET ARGS

# 2. 追踪进程生命周期 (fork/exec/exit)
execsnoop-bpfcc -x   # 包含失败执行
killsnoop-bpfcc       # 追踪 kill 信号

# 3. 检测进程注入 (ptrace 附着)
# 自定义 eBPF 程序追踪 ptrace 系统调用
bpftool prog load xdp_trace.o /sys/fs/bpf/ptrace_trace

# === 文件取证 ===

# 4. 追踪敏感文件访问
opensnoop-bpfcc -f /etc/shadow,/etc/passwd,/etc/sudoers
# 或使用 vfs 跟踪点
bpftool prog tracings

# 5. 追踪文件写操作
biosnoop-bpfcc        # 块设备 I/O
filelife-bpfcc        # 文件生命周期 (创建/删除)
vfsstat-bpfcc 1 10    # VFS 操作统计

# 6. 追踪文件权限变更
# 自定义 tracepoint: sys_enter_chmod / sys_enter_fchmod

# === 网络取证 ===

# 7. 追踪 TCP 连接建立 (比 netstat/ss 实时)
tcplife-bpfcc         # TCP 连接生命周期
tcpconnect-bpfcc      # 活跃 TCP 连接 (含短连接)
tcpaccept-bpfcc       # 被动接受的连接

# 8. DNS 查询追踪 (检测 DNS 隧道/数据外泄)
# 使用 funccount 统计 dns 相关函数
funccount-bpfcc -p 'c:res_*'  # DNS 解析函数调用频率

# 9. 追踪网络连接的进程 (替代 lsof -i)
sockstat-bpfcc        # socket 统计

# === 内存取证 ===

# 10. 追踪内存分配 (检测堆喷射/异常分配)
memleak-bpfcc -p <PID>   # 指定进程内存泄漏
oomkill-bpfcc            # OOM Killer 事件

# === 安全监控 ===

# 11. 追踪内核模块加载
bpftool prog show       # 列出所有已加载 eBPF 程序
bpftool map show        # 列出所有 eBPF map

# 12. capability 使用追踪
capable-bpfcc           # 追踪内核 capability 检查
```

#### 7.2 内存取证 tracepoint

```bash
# 列出可用的 tracepoint
bpftool perf list
cat /sys/kernel/debug/tracing/available_events | grep -E "syscalls|sched|net|sock"

# 关键 tracepoint:
# syscalls:sys_enter_execve    — 命令执行
# syscalls:sys_enter_connect   — 网络连接
# syscalls:sys_enter_ptrace    — 进程注入
# syscalls:sys_enter_mount     — 文件系统挂载
# sched:sched_process_exec     — 进程映像替换
# sched:sched_process_fork     — 进程创建
# net:net_dev_xmit             — 网络包发送

# 使用 bpftrace 进行自定义追踪 (One-Liner 取证)
# 安装 bpftrace
apt install -y bpftrace

# 追踪所有 TCP connect 调用 (IP + 端口 + 进程)
bpftrace -e 'kprobe:tcp_connect { printf("%s [%d] ", comm, pid); }'

# 追踪 LD_PRELOAD 篡改
bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2:*preload* { printf("PID %d comm %s\n", pid, comm); }'

# 追踪新创建的进程
bpftrace -e 'tracepoint:sched:sched_process_exec { printf("%s -> %s (pid:%d)\n", comm, args->filename, pid); }'
```

#### 7.3 eBPF 取证数据持久化

```bash
# 将 eBPF 追踪输出写入文件
execsnoop-bpfcc > /evidence/ebpf_execs_$(date +%Y%m%d_%H%M%S).log &
tcpconnect-bpfcc > /evidence/ebpf_tcpconn_$(date +%Y%m%d_%H%M%S).log &

# 使用 bpftool 保存 eBPF 程序 (供离线分析)
bpftool prog dump xlated id <ID> > /evidence/ebpf_prog_<ID>.txt
bpftool prog dump jited id <ID> > /evidence/ebpf_jit_<ID>.txt
```

---

### 8. 容器 / 容器环境取证

#### 8.1 Docker 容器取证

```bash
# === 容器运行时状态收集 ===

# 1. 列出所有容器 (含已停止)
docker ps -a --no-trunc --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}\t{{.Command}}'

# 2. 检查可疑容器
docker ps -a --filter "status=running" --format '{{.Names}}' | while read c; do
  # 检查特权容器
  docker inspect "$c" --format '{{.HostConfig.Privileged}}' | grep -q true && \
    echo "[!] 特权容器: $c"
  # 检查挂载了宿主机根目录的容器
  docker inspect "$c" --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' | \
    grep -E "^/:" && echo "[!] 宿主机挂载: $c"
  # 检查网络模式 host
  docker inspect "$c" --format '{{.HostConfig.NetworkMode}}' | \
    grep -q host && echo "[!] Host网络: $c"
done

# 3. 容器日志提取
docker logs --timestamps <CONTAINER_ID> > /evidence/docker_<CONTAINER_ID>.log

# 4. 容器文件系统差异 (检测篡改)
docker diff <CONTAINER_ID>
# A = Added, C = Changed, D = Deleted

# 5. 导出容器文件系统 (离线分析)
docker export <CONTAINER_ID> > /evidence/container_<CONTAINER_ID>.tar
# 或使用 docker save 保存镜像
docker save <IMAGE_NAME> > /evidence/image_<NAME>.tar

# 6. 容器内进程和网络
docker top <CONTAINER_ID>
docker exec <CONTAINER_ID> netstat -tulpn 2>/dev/null
docker exec <CONTAINER_ID> ps auxf

# === Docker 持久化机制检查 ===

# 7. 检查 Docker Socket 挂载
find / -name "docker.sock" 2>/dev/null
docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/run/docker.sock"}}[!] Docker Socket 挂载: {{.Name}}{{end}}{{end}}' $(docker ps -q)

# 8. 检查可疑镜像
docker images --no-trunc --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}\t{{.Size}}'
# 分析镜像层历史
docker history --no-trunc <IMAGE_ID>

# 9. Docker 事件日志
docker events --since "2024-01-01" --until "2024-12-31" > /evidence/docker_events.log

# 10. Docker 审计日志 (需要 auditd 规则)
ausearch -m avc -c docker 2>/dev/null
```

#### 8.2 Kubernetes 取证

```bash
# === 集群状态收集 ===

# 1. 所有 Pod (含已终止)
kubectl get pods -A -o wide --show-all 2>/dev/null || kubectl get pods -A -o wide

# 2. 可疑 Pod 识别
kubectl get pods -A -o json | jq -r '.items[] | select(
  .spec.containers[].securityContext.privileged == true or
  .spec.hostPID == true or
  .spec.hostNetwork == true or
  .spec.containers[].volumeMounts[]?.mountPath == "/" or
  (.spec.containers[].volumeMounts[]?.name | test("docker-sock"))
) | "\(.metadata.namespace)/\(.metadata.name) [!] 特权Pod/\(.spec.containers[].securityContext.privileged)"'

# 3. Pod 事件日志
kubectl get events -A --sort-by='.lastTimestamp' > /evidence/k8s_events.txt
kubectl describe pod <POD_NAME> -n <NAMESPACE> > /evidence/k8s_pod_<POD_NAME>.txt

# 4. 审计日志 (Kubernetes API Server)
# 审计日志位置取决于集群配置
cat /var/log/kubernetes/audit.log 2>/dev/null
# 或
cat /etc/kubernetes/audit/policy.yaml 2>/dev/null
# 云托管集群查询:
# aws: CloudTrail + EKS audit logs
# azure: Azure Activity Log + AKS diagnostics
# gcp: Cloud Audit Logs + GKE audit

# 5. 容器运行时取证
# 检查 crictl (containerd)
crictl ps -a
crictl logs <CONTAINER_ID>
crictl inspect <CONTAINER_ID> | jq '.info.runtimeSpec'

# 6. Kubernetes Secrets 泄露检查
kubectl get secrets -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.type)"'
# 检查环境变量中的密钥
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].env[]? | select(.value != null) | "\(.name)=\(.value)"' | grep -iE "password|secret|token|key|api"

# 7. kubeconfig 和凭据
find / -name "kubeconfig" -o -name ".kube/config" -o -name "admin.conf" 2>/dev/null
cat /etc/kubernetes/admin.conf 2>/dev/null
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null

# === Kubernetes 持久化检查 ===

# 8. 检查异常的 ClusterRole/ClusterRoleBinding
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[] | test(".*")) | .metadata.name'
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | "\(.metadata.name) -> \(.subjects[].name)"'

# 9. 检查 Webhook 配置 (可能被用于持久化/攻击)
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# 10. 检查 CronJob (持久化向量)
kubectl get cronjobs -A
```

#### 8.3 容器取证工具

```bash
# 使用 ctr (containerd CLI) 进行低层分析
ctr -n k8s.io containers ls
ctr -n k8s.io snapshots ls

# 容器镜像层分析 (dive 工具)
# dive <IMAGE_NAME>  -- 交互式分析每一层的文件变更

# 使用 Skopeo 检查远程镜像 (不需要 pull)
skopeo inspect docker://registry.example.com/suspicious:latest

# 使用 Trivy 扫描容器镜像
trivy image <IMAGE_NAME>
trivy image --security-checks vuln,misconfig,secret <IMAGE_NAME>
```

---

### 9. Auditd 高级规则

#### 9.1 事件响应专用规则集

```bash
# /etc/audit/rules.d/ir-advanced.rules — 高级 IR 审计规则
# === 命令执行全面监控 ===

# 捕获所有用户执行的命令 (含 uid=0)
-a always,exit -F arch=b64 -S execve -F auid!=-1 -F auid!=4294967295 -k cmd_exec_all

# 捕获特定危险命令
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F exe=/usr/bin/wget -k download_tool
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F exe=/usr/bin/curl -k download_tool
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/ncat -k reverse_shell_tool
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/socat -k reverse_shell_tool

# === 文件完整性监控 (扩展) ===

# 系统关键配置文件
-w /etc/ssh/sshd_config -p wa -k ssh_config_change
-w /etc/pam.d/ -p wa -k pam_config_change
-w /etc/nsswitch.conf -p wa -k nss_change
-w /etc/resolv.conf -p wa -k dns_change
-w /etc/hosts -p wa -k hosts_change
-w /etc/environment -p wa -k env_change
-w /etc/profile -p wa -k profile_change
-w /etc/ld.so.preload -p wa -k ld_preload_attack
-w /etc/ld.so.conf.d/ -p wa -k ld_config_change

# 认证相关
-w /etc/shadow -p wa -k shadow_change
-w /etc/passwd -p wa -k passwd_change
-w /etc/group -p wa -k group_change
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoersd_change

# === 特权操作监控 ===

# ptrace (进程注入/调试)
-a always,exit -F arch=b64 -S ptrace -k ptrace_attempt

# 内核模块操作
-a always,exit -F arch=b64 -S init_module -k kernel_module_load
-a always,exit -F arch=b64 -S delete_module -k kernel_module_unload
-a always,exit -F arch=b64 -S finit_module -k kernel_module_load

# capabilities 操作
-a always,exit -F arch=b64 -S capset -k capability_change

# 网络配置变更
-a always,exit -F arch=b64 -S sethostname -k hostname_change
-a always,exit -F arch=b64 -S setdomainname -k domainname_change

# 时间篡改
-a always,exit -F arch=b64 -S clock_settime -k time_change
-a always,exit -F arch=b64 -S stime -k time_change
-a always,exit -F arch=b64 -S settimeofday -k time_change
-a always,exit -F arch=b64 -S adjtimex -k time_change

# === Docker/容器审计 ===

-w /var/lib/docker -p wa -k docker_fs_change
-w /etc/docker/daemon.json -p wa -k docker_config_change
-w /etc/containerd/ -p wa -k containerd_config_change

# === Kubernetes 审计 ===

-w /etc/kubernetes/ -p wa -k k8s_config_change
-w /var/lib/kubelet/ -p wa -k kubelet_change

# 应用规则
augenrules --load
systemctl restart auditd
```

#### 9.2 ausearch/aureport 高级查询

```bash
# === 时间范围查询 ===

# 指定日期范围
ausearch -ts 01/15/2025 00:00:00 -te 01/16/2025 00:00:00 -k cmd_exec_all

# 最近 N 分钟
ausearch-ts $(date -d '60 minutes ago' +%m/%d/%Y\ %H:%M:%S) -k cmd_exec_all

# === 关键事件查询 ===

# 所有失败的系统调用 (可能的攻击尝试)
ausearch -sv no -m SYSCALL -ts today | aureport -x

# 所有网络连接 (来源/目标/端口)
ausearch -m SOCKADDR -ts today | aureport --summary

# 特定 PID 的所有活动
ausearch -p <PID> -ts today

# 所有 root 命令执行
ausearch -sc execve -ua 0 -ts today | aureport -x -i

# 所有文件删除
ausearch -m DELETE -ts today

# 未授权访问尝试
ausearch -m ANOM_ABEND,ANOM_LOGIN_FAILURES,ANOM_MAX_DAC -ts today

# === 报告生成 ===

# 生成综合取证报告
aureport -ts today --summary > /evidence/audit_summary_$(date +%Y%m%d).txt

# 按用户分组报告
aureport -u -ts today -i

# 文件访问报告 (含文件名)
aureport -f -ts today -i

# 系统调用报告
aureport -s -ts today --summary

# 生成可读的命令执行时间线
ausearch -sc execve -ts today -i | \
  awk '/type=EXECVE/ {for(i=1;i<=NF;i++) if($i ~ /^argc/) print}' | \
  sort -u
```

---

### 10. Journalctl 取证查询

systemd journal 已成为现代 Linux 发行版的默认日志系统，journalctl 提供比传统 syslog 更强大的过滤能力。

```bash
# === 时间过滤 ===

# 指定时间范围
journalctl --since "2025-01-15 08:00:00" --until "2025-01-15 18:00:00"

# 相对时间
journalctl --since "2 hours ago"
journalctl --since yesterday
journalctl --since "3 days ago"

# === 服务过滤 ===

# SSH 服务日志
journalctl -u sshd --since "24 hours ago"
journalctl -u ssh --since "24 hours ago"

# Docker 服务日志
journalctl -u docker --since "24 hours ago"
journalctl -u containerd --since "24 hours ago"

# === 取证查询 ===

# 1. SSH 暴力破解检测
journalctl -u sshd --since "24 hours ago" | grep "Failed password" | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# 2. SSH 成功登录
journalctl -u sshd --since "7 days ago" | grep "Accepted"
journalctl _SYSTEMD_UNIT=sshd SYSLOG_IDENTIFIER=sshd | grep "session opened"

# 3. sudo 命令记录
journalctl -t sudo --since "24 hours ago"
# 或
journalctl SYSLOG_IDENTIFIER=sudo

# 4. 用户创建/删除
journalctl --since "7 days ago" | grep -E "new user|delete user|useradd|userdel"

# 5. 系统服务状态变更
journalctl -t systemd --since "24 hours ago" | grep -E "Started|Stopped|Failed|Deactivating"

# 6. 内核模块加载
journalctl -t kernel --since "24 hours ago" | grep -E "module|insmod|modprobe"

# 7. OOM Kill 事件
journalctl -t kernel --since "7 days ago" | grep -i "oom-kill"

# 8. SELinux/AppArmor 拒绝
journalctl --since "24 hours ago" | grep -E "AVC denial|type=1400|apparmor=\"DENIED\""

# 9. 磁盘/文件系统错误
journalctl -t kernel --since "24 hours ago" | grep -iE "ext4.*error|xfs.*error|I/O error|read-error"

# === 结构化日志查询 ===

# 10. 按优先级过滤 (0=emerg, 3=err, 4=warning)
journalctl -p err --since "24 hours ago"
journalctl -p warning..err --since "24 hours ago"

# 11. 按 UID 过滤
journalctl _UID=0 --since "24 hours ago"      # root
journalctl _UID=1000 --since "24 hours ago"    # 指定用户

# 12. 按可执行文件过滤
journalctl _EXE=/usr/sbin/sshd --since "24 hours ago"
journalctl _EXE=/usr/bin/sudo --since "24 hours ago"

# === 日志完整性 ===

# 13. 验证日志连续性 (检测日志篡改)
journalctl --verify

# 14. 检查日志时间间隙
journalctl --list-boots   # 列出所有启动会话
journalctl -b -1          # 上一次启动的日志

# 15. 导出日志 (取证备份)
journalctl --since "2025-01-01" --output=json > /evidence/journal_export.json
journalctl --since "2025-01-01" --output=export > /evidence/journal_export.log

# 16. 输出格式化
journalctl --output=verbose --since "1 hour ago" | head -100
journalctl --output=cat --since "1 hour ago" -u sshd
```

---

### 11. 内存取证 — Volatility3 Linux

Volatility3 是目前主流的开源内存取证框架，已替代 Volatility2，对 Linux 提供更好的支持。

#### 11.1 Linux 内存镜像获取

```bash
# === 方法1: LiME (Linux Memory Extractor) — 推荐 ===

# 编译 LiME (需要内核头文件)
apt install -y linux-headers-$(uname -r) build-essential
git clone https://github.com/504ensicsLabs/lime.git
cd lime/src
make
# 加载并获取内存
insmod lime-$(uname -r).ko "path=/evidence/physmem.lime format=lime"
# 格式: lime (推荐), raw, padded
rmmod lime

# === 方法2: /dev/mem (简单但有限) ===
# 仅限未启用 STRICT_DEVMEM 的系统
dd if=/dev/mem of=/evidence/physmem.raw bs=1M

# === 方法3: VMware 内存快照 ===
# 如果目标运行在 VMware 上
# vmware-cmd <vmx_path> snapshot dumpMemory

# === 方法4: /proc/kcore (ELF 格式内存) ===
# 需要 debugfs 支持
ls -la /proc/kcore
# cp /proc/kcore /evidence/kcore.dump
```

#### 11.2 Volatility3 Linux 分析

```bash
# 安装 Volatility3
pip3 install volatility3

# === 基础分析 ===

# 1. 识别系统信息
vol -f /evidence/physmem.lime banners
vol -f /evidence/physmem.lime linuxbanner

# 2. 列出进程 (类似 ps aux)
vol -f /evidence/physmem.lime linux.pslist
vol -f /evidence/physmem.lime linux.pstree        # 进程树
vol -f /evidence/physmem.lime linux.psscan         # 扫描隐藏进程 (可检测 DKOM)

# 3. 检测隐藏进程 (pslist vs psscan 差异)
diff <(vol -f /evidence/physmem.lime linux.pslist | awk '{print $2}' | sort) \
     <(vol -f /evidence/physmem.lime linux.psscan | awk '{print $2}' | sort)

# 4. 进程内存映射
vol -f /evidence/physmem.lime linux.proc.Maps -p <PID>

# 5. 进程命令行参数
vol -f /evidence/physmem.lime linux.psaux

# === 网络分析 ===

# 6. 网络连接
vol -f /evidence/physmem.lime linux.sockstat        # 所有 socket
vol -f /evidence/physmem.lime linux.netstat         # 网络连接表

# 7. 检查异常连接 (外连 C2)
vol -f /evidence/physmem.lime linux.netstat | \
  awk '$3 != "127.0.0.1" && $3 != "0.0.0.0" && $3 != "::"'

# === 文件分析 ===

# 8. 打开文件列表
vol -f /evidence/physmem.lime linux.lsof -p <PID>

# 9. 文件系统缓存
vol -f /evidence/physmem.lime linux.dentry_cache
vol -f /evidence/physmem.lime linux.find_file -L /tmp/malware

# === 恶意代码检测 ===

# 10. 检查共享库注入
vol -f /evidence/physmem.lime linux.ldsofunc -p <PID>

# 11. 检查进程内存中的可疑字符串
vol -f /evidence/physmem.lime linux.strings -s "password|secret|token|http://|https://"

# 12. 检查 bash 命令历史 (内存中)
vol -f /evidence/physmem.lime linux.bash

# === 内核分析 ===

# 13. 内核模块列表
vol -f /evidence/physmem.lime linux.lsmod

# 14. 检测 Rootkit (内核模块 vs /proc/modules 差异)
diff <(vol -f /evidence/physmem.lime linux.lsmod | awk '{print $1}') \
     <(cat /evidence/lsmod.txt | awk '{print $1}')
```

#### 11.3 Linux Symbols / Profile 管理

```bash
# Volatility3 使用 Symbol 表替代 Volatility2 的 Profile
# Symbol 表位于 volatility3/symbols/linux/

# 1. 自动生成 Linux Symbol (需要 dwarf2json)
# 安装 dwarf2json
go install github.com/volatilityfoundation/dwarf2json@latest

# 2. 从目标系统生成 Symbol
# 在目标系统上运行:
dwarf2json linux --elf /boot/vmlinux-$(uname -r) > /evidence/symbols.json

# 或使用 System.map + vmlinux
dwarf2json linux \
  --system-map /boot/System.map-$(uname -r) \
  --elf /boot/vmlinux-$(uname -r) \
  > /evidence/symbols_$(uname -r).json

# 3. 复制到 Volatility3 符号目录
cp /evidence/symbols_$(uname -r).json volatility3/symbols/linux/

# 4. 常见发行版 vmlinux 获取
# Debian/Ubuntu:
apt install -y linux-image-$(uname -r)-dbgsym
# vmlinux 位于 /usr/lib/debug/boot/vmlinux-$(uname -r)

# RHEL/CentOS:
debuginfo-install kernel-$(uname -r)
# vmlinux 位于 /usr/lib/debug/lib/modules/$(uname -r)/vmlinux
```

---

### 12. 恶意软件持久化检测 (2025 增强)

#### 12.1 Systemd Timer 持久化

```bash
# Systemd Timer 是日益流行的持久化方式 (比 cron 更隐蔽)

# 列出所有 timer
systemctl list-timers --all --no-pager

# 检查可疑 timer
find /etc/systemd/system/ /usr/lib/systemd/system/ /run/systemd/system/ \
  ~/.config/systemd/user/ -name "*.timer" -type f 2>/dev/null | while read timer; do
  echo "[*] Timer: $timer"
  cat "$timer"
  # 获取关联的 service
  grep -oP '(?<=Unit=).*' "$timer" 2>/dev/null
done

# 检查非包管理器安装的 timer
for timer in /etc/systemd/system/*.timer; do
  if ! dpkg -S "$timer" 2>/dev/null && ! rpm -qf "$timer" 2>/dev/null; then
    echo "[!] 非包管理器安装的 timer: $timer"
    cat "$timer"
    # 检查对应的 service
    svc=$(grep -oP '(?<=Unit=).*' "$timer" 2>/dev/null || \
          echo "${timer%.timer}.service")
    echo "[!] 关联 Service:"
    cat "$svc" 2>/dev/null
    echo "---"
  fi
done
```

#### 12.2 Cron 持久化 (深度检测)

```bash
# 全面检查所有 cron 位置

# 1. 系统 crontab
cat /etc/crontab

# 2. 系统 cron 目录
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  echo "[*] $dir:"
  ls -la "$dir" 2>/dev/null
  for f in "$dir"/*; do
    [ -f "$f" ] && echo "=== $f ===" && cat "$f"
  done
done

# 3. 用户 crontab (spool 目录)
ls -la /var/spool/cron/crontabs/ 2>/dev/null
ls -la /var/spool/cron/ 2>/dev/null
for user_crondir in /var/spool/cron/crontabs/*; do
  echo "[*] User crontab: $user_crondir"
  cat "$user_crondir"
done

# 4. anacron (异步任务)
cat /etc/anacrontab 2>/dev/null

# 5. 检查 cron 脚本中的可疑模式
find /etc/cron* -type f -exec grep -lE "curl|wget|nc |ncat|socat|/dev/tcp|bash -i|base64 -d|eval\s|python -c|perl -e" {} \; 2>/dev/null

# 6. 检查最近修改的 cron 文件
find /etc/cron* -type f -mtime -30 2>/dev/null
```

#### 12.3 ld.so.preload 持久化检测

```bash
# ld.so.preload 是 Linux 上最常见的用户态 Rootkit 持久化方式

# 1. 检查 preload 文件
echo "[*] /etc/ld.so.preload:"
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# 2. 检查 ld.so.conf.d/ 中的可疑条目
echo "[*] ld.so.conf.d:"
for f in /etc/ld.so.conf.d/*.conf; do
  echo "=== $f ==="
  cat "$f"
done

# 3. 验证所有预加载库
while IFS= read -r lib; do
  [ -z "$lib" ] && continue
  [[ "$lib" =~ ^# ]] && continue
  echo "[*] 预加载库: $lib"
  file "$lib" 2>/dev/null
  sha256sum "$lib" 2>/dev/null
  strings "$lib" 2>/dev/null | grep -iE "connect|execve|open|readdir|socket" | head -10
done < /etc/ld.so.preload 2>/dev/null

# 4. 检查 LD_PRELOAD 环境变量 (运行进程)
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  preload=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD)
  [ -n "$preload" ] && echo "[!] PID $pid: $preload ($(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '))"
done

# 5. 检查全局环境配置中的 LD_PRELOAD
grep -r "LD_PRELOAD" /etc/profile /etc/profile.d/ /etc/environment /etc/bash.bashrc /home/*/.bashrc /home/*/.bash_profile /root/.bashrc /root/.bash_profile 2>/dev/null
```

#### 12.4 其他持久化机制

```bash
# 1. SSH wrapper 后门
ls -la /usr/sbin/sshd
file /usr/sbin/sshd
sha256sum /usr/sbin/sshd
# 对比官方包的哈希
dpkg -V openssh-server 2>/dev/null || rpm -V openssh-server 2>/dev/null

# 2. PAM 后门
ls -la /lib/x86_64-linux-gnu/security/pam_*.so /lib64/security/pam_*.so 2>/dev/null
# 检查 PAM 配置中的可疑条目
grep -rv "^#" /etc/pam.d/ | grep -v "pam_unix\|pam_deny\|pam_permit\|pam_env\|pam_limits" | grep -iE "pam_"

# 3. XDG Desktop Entry 持久化 (桌面系统)
find /etc/xdg/autostart/ /home/*/.config/autostart/ /usr/share/autostart/ \
  -name "*.desktop" -exec grep -l "Terminal=false\|Hidden=false" {} \; 2>/dev/null

# 4. 内核模块持久化
# 检查 /etc/modules-load.d/ 和 /etc/modprobe.d/
cat /etc/modules-load.d/*.conf 2>/dev/null
grep -r "install\|options" /etc/modprobe.d/ | grep -viE "alx|e1000|nvme|snd"

# 5. initramfs 后门
lsinitramfs /boot/initrd.img-$(uname -r) | grep -vE "kernel|lib|firmware|usr" | head -20

# 6. EFI/GRUB 持久化
cat /boot/grub/grub.cfg 2>/dev/null | grep -vE "^#\|^$" | head -30
efibootmgr -v 2>/dev/null
```

---

### 13. 云环境 Linux 取证

#### 13.1 AWS EC2 取证

```bash
# === 实例级取证 ===

# 1. 实例元数据 (IMDSv2)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/user-data/

# 2. 检查 IMDSv1 是否启用 (安全风险)
curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null && \
  echo "[!] IMDSv1 可访问 (凭据泄露风险)"

# 3. EC2 Instance Connect 日志
journalctl -u sshd --since "7 days ago" | grep -i "ec2-instance-connect"

# === AWS 管理平面取证 (使用 AWS CLI) ===

# 4. CloudTrail 事件 (API 调用审计)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-<INSTANCE_ID> --max-results 50

# 5. 检查最近的 EC2 API 调用
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances --start-time $(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ)

# 6. 检查安全组变更
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress

# 7. EC2 快照取证 (无需停机)
aws ec2 create-snapshot --volume-id vol-<VOLUME_ID> --description "IR-forensics-snapshot-$(date +%Y%m%d)" --tag-specifications 'ResourceType=snapshot,Tags=[{Key=IR,Value=true}]'

# 8. 从快照创建取证卷
aws ec2 create-volume --snapshot-id snap-<ID> --availability-zone <AZ> --tag-specifications 'ResourceType=volume,Tags=[{Key=Forensics,Value=true}]'

# 9. VPC Flow Logs 分析
aws logs filter-log-events --log-group-name <VPC_FLOW_LOG_GROUP> \
  --filter-pattern "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport != 443, protocol, packets, bytes, start, end, action=\"REJECT\"]" \
  --start-time $(($(date -d '24 hours ago' +%s) * 1000))

# 10. GuardDuty 告警
aws guardduty list-findings --detector-id <DETECTOR_ID>
aws guardduty get-findings --detector-id <DETECTOR_ID> --finding-ids <FINDING_ID>
```

#### 13.2 Azure VM 取证

```bash
# === 实例元数据 ===

# 1. Azure Instance Metadata Service (IMDS)
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq .
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq .

# 2. Azure Activity Log
az monitor activity-log list --resource-group <RG> --caller <UPN> --max-events 50

# 3. 检查 VM 扩展 (可能被用于持久化)
az vm extension list --resource-group <RG> --vm-name <VM_NAME> -o table

# 4. Azure 磁盘快照取证
az snapshot create --resource-group <RG> --source /subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.Compute/disks/<DISK> --name ir-snapshot-$(date +%Y%m%d)

# 5. NSG Flow Logs
az network watcher flow-log show --resource-group <RG> --nsg <NSG_NAME>

# 6. Azure Security Center 告警
az security alert list
az security alert show --name <ALERT_NAME> --location <LOCATION>
```

#### 13.3 GCP Compute 取证

```bash
# === 实例元数据 ===

# 1. GCP Metadata Server
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# 2. 检查服务账号 (可能的提权路径)
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes

# 3. Cloud Audit Logs
gcloud logging read 'logName="projects/<PROJECT>/logs/cloudaudit.googleapis.com%2Factivity" AND resource.labels.instance_id="<INSTANCE_ID>"' --limit 50 --format json

# 4. 磁盘快照取证
gcloud compute disks snapshot <DISK_NAME> --zone=<ZONE> --snapshot-names=ir-snapshot-$(date +%Y%m%d)

# 5. VPC Flow Logs
gcloud logging read 'resource.type="gce_subnetwork" AND jsonPayload.connection.src_ip="<SUSPICIOUS_IP>"' --limit 100 --format json

# 6. Security Command Center 发现
gcloud scc findings list <ORG_ID> --filter="resource_name:\"<INSTANCE_ID>\""

# 7. 检查启动脚本和元数据 (持久化向量)
gcloud compute instances describe <INSTANCE_NAME> --zone=<ZONE> --format=json | jq '.metadata'
```

#### 13.4 云环境通用取证注意事项

```bash
# === 云取证通用流程 ===

# 1. 隔离实例 (不关机,保留内存证据)
# AWS:
aws ec2 modify-instance-attribute --instance-id <ID> --groups <ISOLATED_SG>
# Azure:
az network nic update --resource-group <RG> --name <NIC> --network-security-group <ISOLATED_NSG>
# GCP:
gcloud compute instances add-tags <INSTANCE> --tags=isolated --zone=<ZONE>
# 防火墙规则拒绝所有入站/出站

# 2. 内存获取 (在隔离实例上执行)
# 使用 LiME 获取内存 (见 11.1 节)

# 3. 磁盘快照 (云原生方式,无需停机)
# 见各云服务商磁盘快照命令

# 4. 云日志关联
# 同时收集: 实例日志 + CloudTrail/Activity Log/Audit Logs + VPC Flow Logs
# 使用时间戳对齐关联

# 5. 临时凭据检查
# 检查是否有人通过元数据服务获取了临时凭据
grep -r "x-amz-security-token\|Authorization\|Bearer" /var/log/ 2>/dev/null | head -50

# 6. 云代理/代理日志
cat /var/log/amazon/ssm/amazon-ssm-agent.log 2>/dev/null     # AWS SSM
cat /var/log/waagent.log 2>/dev/null                           # Azure WALinuxAgent
cat /var/log/google-guest-agent.log 2>/dev/null                # GCP Guest Agent
```

---

### 14. 更新 MITRE ATT&CK 映射

| Technique ID | 名称 | 阶段 | Linux 取证指标 | 新增/更新 |
|-------------|------|------|--------------|----------|
| T1053.006 | Scheduled Task/Job: Systemd Timer | 持久化 | 可疑 .timer 文件 | 新增 |
| T1543.002 | Systemd Service | 持久化 | 可疑 .service 文件 | 更新 |
| T1053.003 | Scheduled Task/Job: Cron | 持久化 | crontab 深度分析 | 更新 |
| T1136.001 | Create Account | 持久化 | /etc/passwd 变更 | - |
| T1098 | Account Manipulation | 持久化 | 权限提升记录 | - |
| T1070.002 | Clear Linux Logs | 防御绕过 | journalctl --verify | 更新 |
| T1014 | Rootkit | 防御绕过 | 内核模块 + eBPF 程序检查 | 更新 |
| T1574.006 | LD_PRELOAD | 劫持 | /etc/ld.so.preload + LD_PRELOAD 环境变量 | 更新 |
| T1036 | Masquerading | 防御绕过 | 进程名伪装 | - |
| T1059.004 | Bash | 执行 | shell 历史分析 | - |
| T1071 | Application Layer Protocol | C2 | 网络连接分析 | - |
| T1574.007 | Path Interception | 劫持 | PATH 环境变量篡改 | 新增 |
| T1622 | Debugger Evasion | 防御绕过 | ptrace 检测, eBPF 追踪 | 新增 |
| T1055 | Process Injection | 防御绕过 | /proc/PID/maps 异常映射 | 新增 |
| T1055.008 | Ptrace System Calls | 防御绕过 | ptrace 系统调用审计 | 新增 |
| T1106 | Native API | 执行 | eBPF tracepoint 监控 | 新增 |
| T1070.004 | File Deletion | 防御绕过 | auditd DELETE 事件 | 新增 |
| T1562.001 | Impair Defenses: Disable Tools | 防御绕过 | auditd/SELinux 停止 | 新增 |
| T1036.004 | Masquerading: Masquerade Task or Service | 防御绕过 | systemd 服务名伪装 | 新增 |
| T1205.001 | Traffic Signaling: Port Knocking | C2 | eBPF tcpconnect 追踪 | 新增 |
| T1078.003 | Valid Accounts: Local Accounts | 访问 | /var/log/auth.log + journalctl | 更新 |
| T1190 | Exploit Public-Facing Application | 初始访问 | Web 日志 + auditd | 更新 |
| T1133 | External Remote Services | 初始访问 | SSH/VPN 日志分析 | 更新 |
| T1059.002 | Python | 执行 | auditd execve + journalctl | 新增 |
| T1546.004 | Event Triggered Execution: .bashrc/.bash_profile | 持久化 | shell 配置文件篡改 | 新增 |
| T1546.005 | Event Triggered Execution: Trap | 持久化 | shell trap 命令检查 | 新增 |
| T1552.003 | Unsecured Credentials: Bash History | 凭据访问 | bash_history + 内存取证 | 新增 |
| T1552.001 | Unsecured Credentials: Credentials In Files | 凭据访问 | 配置文件中的明文凭据 | 新增 |
| T1601.001 | Modify System Image: Patch System Image | 防御绕过 | vmlinux 完整性校验 | 新增 |
| T1070.006 | Timestomp | 防御绕过 | stat 时间戳分析 | 新增 |

---

### 速查表更新 (2025-2026)

| 类别 | 命令 | 用途 |
|------|------|------|
| eBPF | `execsnoop-bpfcc` | 实时命令执行追踪 |
| eBPF | `tcpconnect-bpfcc` | TCP 连接实时追踪 |
| eBPF | `bpftool prog show` | 列出已加载 eBPF 程序 |
| eBPF | `bpftrace -e '...'` | 自定义内核追踪 |
| 容器 | `docker diff <ID>` | 容器文件系统变更 |
| 容器 | `docker export <ID>` | 导出容器文件系统 |
| 容器 | `crictl ps -a` | containerd 容器列表 |
| K8s | `kubectl get events -A` | 集群事件日志 |
| K8s | `kubectl get pods -A -o json \| jq` | 可疑 Pod 识别 |
| Auditd | `ausearch -sv no -m SYSCALL` | 失败系统调用 |
| Auditd | `aureport -x -i` | 可读执行报告 |
| Journal | `journalctl --verify` | 日志完整性验证 |
| Journal | `journalctl -u sshd --since` | SSH 服务日志查询 |
| 内存 | `vol -f mem.lime linux.pslist` | Volatility3 进程列表 |
| 内存 | `vol -f mem.lime linux.bash` | 内存中的 bash 历史 |
| 内存 | `vol -f mem.lime linux.sockstat` | 内存中的网络连接 |
| 云 | `aws cloudtrail lookup-events` | AWS API 审计 |
| 云 | `az monitor activity-log list` | Azure 活动日志 |
| 云 | `gcloud logging read` | GCP Cloud Logging |

---

### 15. io_uring "Curing" Rootkit — 2025 最重大 Linux 规避突破

io_uring 是 Linux 5.1 引入的高性能异步 I/O 接口，通过共享环形缓冲区在内核态完成 I/O 操作。2025 年 ARMO 研究团队发布 PoC rootkit "Curing"，利用 io_uring 完全绕过基于 syscall hook 的安全监控工具（Falco、Tetragon、Microsoft Defender 等），这是 2025 年最重大的 Linux 取证/检测挑战。

#### 15.1 攻击原理

```
传统安全工具监控链:
  用户态程序 → syscall (read/write/openat/execve) → 内核 → 安全工具 hook 点 → 审计日志

io_uring 绕过链:
  用户态程序 → io_uring SQE (Submission Queue Entry) → 内核态异步完成
                  ↑ 无传统 syscall 调用，安全工具完全看不到
```

- **核心机制**: io_uring 允许用户态程序通过共享内存环形缓冲区提交 I/O 请求，内核异步完成处理
- **规避范围**: 文件读写 (IORING_OP_READ/WRITE)、文件打开 (IORING_OP_OPENAT)、
  目录遍历 (IORING_OP_GETDENTS)、命令执行 (IORING_OP_EXECVEAT) 等
- **影响工具**: Falco (libscap/syscall hook)、Tetragon (bpf tracepoint)、
  Microsoft Defender for Linux、Auditd、任何基于 syscall 的监控方案
- **前置条件**: 内核 ≥ 5.1（RHEL 8+/Ubuntu 20.04+/Debian 11+）

#### 15.2 取证检测方法

```bash
# === 1. 检查 io_uring 系统调用使用情况 ===

# 检查是否有进程使用 io_uring setup
grep -r "io_uring_setup\|io_uring_enter\|io_uring_register" /proc/*/syscall 2>/dev/null | \
  awk -F/ '{print $3}' | sort -u | while read pid; do
    echo "[!] PID $pid 使用 io_uring: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
  done

# 使用 eBPF 追踪 io_uring 操作 (需要内核支持 tracepoint)
bpftrace -e 'tracepoint:io_uring:io_uring_setup { printf("PID %d comm %s sq_entries %d cq_entries %d\n", pid, comm, args->sq_entries, args->cq_entries); }'

# === 2. 检查 io_uring 文件描述符 ===
# io_uring 实例出现在 /proc/PID/fd/ 中
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  fds=$(ls -la /proc/$pid/fd/ 2>/dev/null | grep -c "anon_inode:\[io_uring\]")
  [ "$fds" -gt 0 ] && echo "[!] PID $pid: $fds io_uring FD(s) — $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
done

# === 3. 检查 io_uring 相关的内核模块 ===
cat /proc/modules | grep -i "io_uring"
lsmod | grep -i "io_uring"

# === 4. 审计 io_uring 系统调用 ===
# 添加 auditd 规则
cat >> /etc/audit/rules.d/ir-advanced.rules << 'EOF'
# io_uring 监控 (Linux 5.1+)
-a always,exit -F arch=b64 -S io_uring_setup -k io_uring_setup
-a always,exit -F arch=b64 -S io_uring_enter -k io_uring_enter
-a always,exit -F arch=b64 -S io_uring_register -k io_uring_register
EOF
augenrules --load

# === 5. 禁用 io_uring (如环境不需要) ===
# 方法1: sysctl (临时)
sysctl -w kernel.io_uring_disabled=2
# 方法2: 永久
echo "kernel.io_uring_disabled = 2" >> /etc/sysctl.d/99-disable-io-uring.conf
# 值说明: 0=所有人可用, 1=仅特权用户, 2=完全禁用
# 注意: 禁用前评估影响，部分应用 (数据库/容器运行时) 可能依赖 io_uring

# === 6. Sysdig/Falco 检测规则 (io_uring) ===
cat > /etc/falco/rules.d/io_uring_rules.yaml << 'YAML'
- rule: Suspicious io_uring Usage
  desc: Detect processes using io_uring that are not in the expected list
  condition: >
    evt.type in (io_uring_setup, io_uring_enter) and
    not proc.name in (postgres, mysql, redis-server, mongod, containerd, dockerd,
                      nginx, envoy, istio, java, node, python3)
  output: >
    Suspicious io_uring usage detected
    (user=%user.name command=%proc.cmdline pid=%proc.pid container=%container.id)
  priority: WARNING
  tags: [filesystem, mitre_defense_evasion]
YAML
```

#### 15.3 参考资料

- [ARMO - io_uring Rootkit Bypasses Linux Security Tools](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [Sysdig - Detecting and Mitigating io_uring Abuse](https://www.sysdig.com/blog/detecting-and-mitigating-io-uring-abuse-for-malware-evasion/)
- [Elastic Security Labs - Hooked on Linux: Rootkit Detection Engineering](https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act)
- [The Hacker News - Linux io_uring PoC Rootkit](https://thehackernews.com/2025/04/linux-iouring-poc-rootkit-bypasses.html)
- [0xMatheuZ - Evading Linux EDRs with io_uring](https://matheuzsecurity.github.io/hacking/evading-linux-edrs-with-io-uring/)

---

### 16. eBPF Rootkit 检测前沿 (2025-2026 学术研究)

#### 16.1 HKRD — Hidden Kernel Rootkit Detector

2025 年 [Computers & Security 期刊](https://www.sciencedirect.com/science/article/abs/pii/S0167404825002718) 发表基于 eBPF 的隐藏内核 rootkit 检测框架 HKRD:

- **原理**: 利用 eBPF 在内核关键函数入口/出口挂载探针，收集函数执行时序和返回值
- **检测目标**: 隐藏进程 (DKOM)、隐藏文件/目录、隐藏网络连接、syscall table hook
- **优势**: 无需安装内核模块，对系统性能影响极小

#### 16.2 时序异常检测

[arXiv 2503.02402](https://arxiv.org/html/2503.02402v1) 提出通过 eBPF 测量被 rootkit 操纵的内核函数执行时间异常:

```bash
# 开源工具: https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace

# 原理: rootkit hook 内核函数后，函数执行时间会产生可检测的偏差
# 步骤:
# 1. 使用 eBPF 收集关键内核函数的执行时间基线
# 2. 持续监控并比较偏离度
# 3. 异常偏离 = 潜在 rootkit hook

# 检测脚本示例
bpftrace -e '
kprobe:sys_read   { @start_read[pid] = nsecs; }
kretprobe:sys_read /@start_read[pid]/ {
  @read_ns = hist(nsecs - @start_read[pid]);
  delete(@start_read[pid]);
}
'
# 如果 sys_read 执行时间出现异常峰值，可能被 rootkit hook
```

#### 16.3 eBPF 双刃剑: Rootkit 利用 eBPF

攻击者也在利用 eBPF 构建高级 rootkit ([Synacktiv LinkPro 分析](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis)):

- **攻击手法**: 恶意 eBPF 程序 hook syscall、tracepoint、LSM hooks
- **规避检测**: 阻断安全工具的 eBPF 程序类型 (kprobe、tracepoint、LSM、iterator)
- **影响范围**: 可致 Falco、bpftrace、Tracee、Cilium 等工具失效

```bash
# 检查系统上所有已加载的 eBPF 程序 (检测恶意 eBPF rootkit)
bpftool prog show --json | jq -r '.[] | "\(.id) \(.type) \(.name) \(.tag)"'

# 检查 eBPF map (可能被用于存储恶意数据)
bpftool map show --json | jq -r '.[] | "\(.id) \(.name) \(.type) keys:\(.entries.max_entries)"'

# 列出 eBPF 程序附加到的挂载点
bpftool cgroup show /sys/fs/cgroup/ 2>/dev/null
bpftool net show  # 网络附加的 eBPF 程序

# 检测 LSM hook 点上的可疑 eBPF 程序
bpftool prog show type lsm 2>/dev/null
```

---

### 17. 2025-2026 关键 Linux 内核 CVE (取证相关)

| CVE | 子系统 | CVSS | 描述 | 取证指标 |
|-----|--------|------|------|----------|
| CVE-2026-46333 | ptrace | Critical | ptrace 路径逻辑缺陷，本地 root 提权 + 凭据泄露 (Qualys) | auditd ptrace 日志异常 |
| CVE-2026-46300 | XFRM ESP-in-TCP | Critical | "Fragnesia" — IPsec 子系统本地提权 (Red Hat) | IPsec/ESP 内存工件 |
| CVE-2026-43284 | xfrm-ESP + rxrpc | Critical | "Dirty Frag" — 双页面缓存写原语链式提权 (Wiz) | 页缓存腐败 + 网络分片异常 |
| CVE-2026-31431 | authencesn (crypto) | 7.8 | "Copy Fail" — 加密子系统 AF_ALG 页面缓存腐败，本地提权 | crypto API 异常使用模式 |
| CVE-2026-31508 | Open vSwitch | 7.8 | OVS 模块提权漏洞 | OVS 流表异常、crash dump |
| CVE-2025-6018 | PAM | 7.8 | PAM 认证绕过 (openSUSE/SUSE) | auth.log 异常成功登录 |
| CVE-2025-6019 | Polkit | 7.8 | Polkit 规则绕过 + CVE-2025-6018 链式提权 | polkit 日志异常 |
| CVE-2026-5928 | glibc | 7.5 | ungetwc() 缓冲区溢出 | 异常 locale/wide-char 使用 |
| CVE-2025-0395 | glibc | 7.3 | assert() 缓冲区溢出 | 异常程序崩溃 + assert 失败 |

#### 17.1 CVE-2026-31431 "Copy Fail" 取证检测

```bash
# "Copy Fail" 利用 AF_ALG (内核加密 API) 的页面缓存腐败
# 取证检测要点:

# 1. 检查 AF_ALG socket 使用 (异常进程)
grep -r "AF_ALG\|alg_" /proc/*/net/sockstat 2>/dev/null
ss -x | grep alg  # AF_ALG Unix socket

# 2. auditd 规则 — 监控 crypto API 调用
cat >> /etc/audit/rules.d/ir-advanced.rules << 'EOF'
# AF_ALG crypto API 监控 (CVE-2026-31431 检测)
-a always,exit -F arch=b64 -S bind -F auid>=1000 -k crypto_bind
-a always,exit -F arch=b64 -S sendmsg -F auid>=1000 -k crypto_sendmsg
EOF

# 3. 检查内核是否已补丁
uname -r  # 对比已修复版本
# Ubuntu: 6.8.0-52.53 (2026-06-10 修复)
# RHEL 9: 5.14.0-570.11.1 (2026-06-05 修复)
# Debian: 6.12.27-1 (2026-06-08 修复)

# 4. Sigma 检测规则
cat > /evidence/sigma/cve-2026-31431.yaml << 'YAML'
title: Potential CVE-2026-31431 "Copy Fail" Exploitation
description: Detects AF_ALG crypto API usage by non-standard processes
references:
  - https://www.picussecurity.com/resource/blog/copy-fail-critical-linux-kernel-privilege-escalation-vulnerability-cve-2026-31431
author: IR Team
date: 2026/06/13
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: SYSCALL
    syscall: bind
    key: crypto_bind
  filter:
    exe|endswith:
      - '/openssl'
      - '/gnutls-cli'
      - '/ssh'
      - '/nginx'
      - '/httpd'
  condition: selection and not filter
level: high
tags:
  - attack.privilege_escalation
  - attack.t1068
  - cve.2026-31431
YAML
```

---

### 18. AI/LLM 辅助 Linux 取证

#### 18.1 AI 驱动的日志分析

```python
#!/usr/bin/env python3
"""
linux_log_ai_analyzer.py — AI 辅助 Linux 日志分析器
使用 LLM 对大规模日志进行智能摘要和异常检测
"""

import json
import subprocess
from collections import Counter
from datetime import datetime

# === 1. 日志收集与预处理 ===

def collect_auth_events(hours=24):
    """收集认证事件"""
    cmd = f'journalctl -u sshd --since "{hours} hours ago" --output=json'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        return []
    events = []
    for line in result.stdout.strip().split('\n'):
        try:
            entry = json.loads(line)
            events.append({
                'timestamp': entry.get('__REALTIME_TIMESTAMP', ''),
                'message': entry.get('MESSAGE', ''),
                'host': entry.get('_HOSTNAME', ''),
                'priority': entry.get('PRIORITY', '')
            })
        except json.JSONDecodeError:
            continue
    return events

def collect_audit_events(hours=24):
    """收集 audit 事件"""
    cmd = f'ausearch -ts $(date -d "{hours} hours ago" +%m/%d/%Y\\ %H:%M:%S) -i --format json 2>/dev/null'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

# === 2. 统计分析 (无需 AI 即可运行) ===

def analyze_ssh_bruteforce(events):
    """SSH 暴力破解检测"""
    failed_ips = Counter()
    for e in events:
        msg = e.get('message', '')
        if 'Failed password' in msg:
            # 提取 IP
            parts = msg.split('from ')
            if len(parts) > 1:
                ip = parts[1].split()[0]
                failed_ips[ip] += 1

    suspicious = {ip: count for ip, count in failed_ips.items() if count > 10}
    return {
        'total_failed': sum(failed_ips.values()),
        'unique_ips': len(failed_ips),
        'suspicious_ips': suspicious,
        'severity': 'CRITICAL' if max(failed_ips.values(), default=0) > 100 else
                    'HIGH' if max(failed_ips.values(), default=0) > 50 else
                    'MEDIUM' if max(failed_ips.values(), default=0) > 10 else 'LOW'
    }

# === 3. AI 增强分析提示词 ===

AI_ANALYSIS_PROMPT = """分析以下 Linux 系统日志事件，识别潜在的入侵指标:

## SSH 认证分析
{ssh_analysis}

## 可疑事件摘要
{suspicious_events}

请提供:
1. 入侵置信度评分 (0-100)
2. 关键发现列表 (按严重程度排序)
3. 可能的攻击阶段 (侦察/初始访问/持久化/横向移动/数据外泄)
4. 建议的响应措施 (按优先级排序)
5. 需要进一步调查的领域
"""

# === 4. 工具生态 ===
# - BelkaGPT (Belkasoft): AI 辅助取证分析
# - Magnet AXIOM 2025-2026: AI 增强证据发现
# - Volatility3 + LLM: 通过 MCP 接口集成 AI 分析
# - Elastic AI Assistant: 日志异常智能摘要
# - 自定义: 上述脚本 + Claude/GPT API 调用

def main():
    print("[*] 收集 SSH 认证事件...")
    ssh_events = collect_auth_events(24)
    print(f"[+] 收集到 {len(ssh_events)} 条 SSH 事件")

    print("[*] 分析暴力破解...")
    brute_analysis = analyze_ssh_bruteforce(ssh_events)
    print(f"[+] 可疑 IP: {brute_analysis['suspicious_ips']}")
    print(f"[+] 严重程度: {brute_analysis['severity']}")

    print("[*] 收集 Audit 事件...")
    audit_events = collect_audit_events(24)
    print(f"[+] 收集到 {len(audit_events)} 条 Audit 事件")

    # 生成 AI 分析提示词
    prompt = AI_ANALYSIS_PROMPT.format(
        ssh_analysis=json.dumps(brute_analysis, indent=2),
        suspicious_events=json.dumps(ssh_events[:20], indent=2)  # 截取前20条
    )
    print("\n[*] AI 分析提示词已生成，可粘贴到 LLM 进行分析")

if __name__ == '__main__':
    main()
```

#### 18.2 AI 取证工具生态

| 工具 | 类型 | 功能 | Linux 支持 |
|------|------|------|-----------|
| BelkaGPT | 商业 | AI 辅助证据发现和分析 | 是 |
| Magnet AXIOM 2025-2026 | 商业 | AI 增强取证、自动工件发现 | 是 |
| Elastic AI SOC Engine | 商业/开源 | AI 驱动告警分流和日志摘要 | 是 |
| Volatility3 + MCP | 开源 | 通过 MCP 接口集成 LLM 分析 | 是 |
| Cisco AI Triage Agent | 商业 | 自主事件分流 Agent | 是 |

---

### 19. 工具生态更新 (2025-2026)

#### 19.1 企业级 Linux 取证工具

| 工具 | 版本 | 更新要点 | 适用场景 |
|------|------|----------|----------|
| **Velociraptor** | v0.74+ | 官方 Fedora RPM (2025-11); 企业级端点取证 | 大规模 Linux 集群实时取证 |
| **Volatility3** | v2.28.1 | Parity Release; Linux 插件全面更新; 自动 Symbol 识别 | 内存取证分析 |
| **GRR Rapid Response** | v3.4+ | 企业端点遥测; Linux 客户端增强 | 大规模远程取证 |
| **OSQuery** | v5.12+ | 实时系统查询; SQL 接口 | 持续监控与取证查询 |
| **UAC (Unix Artifacts Collector)** | v2.7+ | 轻量级 Unix/Linux 工件收集 | 快速证据采集 |

#### 19.2 Velociraptor Linux 取证实战

```bash
# === Velociraptor Linux 取证 VQL 查询 ===

# 1. 收集所有 SSH 授权密钥
SELECT * FROM foreach(
  row={
    SELECT Name, Directory FROM glob(globs='/home/*', nosymlink=TRUE)
  },
  query={
    SELECT Name, Mtime, Size, read_file(filename=OSPath) AS Content
    FROM glob(globs=Directory + '/.ssh/authorized_keys', nosymlink=TRUE)
  }
)

# 2. 检测异常 cron 任务
SELECT * FROM foreach(
  row={
    SELECT OSPath, Mtime, read_file(filename=OSPath) AS Content
    FROM glob(globs=['/etc/crontab', '/etc/cron.d/*', '/var/spool/cron/*'])
  },
  query={
    SELECT OSPath, Mtime, Content
    FROM scope()
    WHERE Content =~ '(?i)(curl|wget|nc |ncat|socat|/dev/tcp|base64 -d|eval)'
  }
)

# 3. 检测隐藏进程 (对比 /proc 和 ps)
LET proc_ls = SELECT Pid, Name, CommandLine FROM pslist()
LET proc_proc = SELECT Pid, Name FROM glob(globs='/proc/*/status', nosymlink=TRUE)
SELECT * FROM difference(
  left=proc_proc,
  right=proc_ls,
  on="Pid"
)
-- 结果为隐藏进程 (DKOM rootkit)

# 4. 收集 io_uring 使用进程
SELECT Pid, Name, CommandLine, {
  SELECT count(items=Fd) AS Count FROM glob(globs='/proc/' + Pid + '/fd/*')
  WHERE Name =~ 'io_uring'
} AS io_uring_fds
FROM pslist()
WHERE io_uring_fds.Count > 0
```

#### 19.3 取证工具选择决策树

```
Linux 取证工具选择:
├── 单机取证
│   ├── 易失性证据 → ir_volatile_collect.sh (本文 §1)
│   ├── 内存取证 → LiME + Volatility3 (本文 §11)
│   ├── 磁盘取证 → dd/dcfldd/Guymager (见 ir-forensics-disk.md)
│   └── Rootkit 检测 → chkrootkit + rkhunter + eBPF (本文 §4, §15)
├── 企业级远程取证
│   ├── Velociraptor → 大规模端点取证/实时查询 (推荐)
│   ├── GRR → 企业级远程工件收集
│   └── OSQuery → 持续监控/SQL 接口
├── 容器取证
│   ├── Docker → docker diff/export/logs (本文 §8)
│   ├── Kubernetes → kubectl + crictl (本文 §8)
│   └── 容器镜像 → Trivy + dive (本文 §8)
└── 云环境取证
    ├── AWS → CloudTrail + VPC Flow Logs + EC2 快照 (本文 §13)
    ├── Azure → Activity Log + NSG Flow Logs + 磁盘快照 (本文 §13)
    └── GCP → Cloud Audit Logs + VPC Flow Logs + 磁盘快照 (本文 §13)
```

---

### 20. 中文社区精华参考

| 来源 | 标题/主题 | 链接 |
|------|-----------|------|
| 火山引擎 | Linux 应急响应笔记 — 静态 busybox 取证 | [developer.volcengine.com](https://developer.volcengine.com/articles/7381512331072962570) |
| gm7.org | Linux 应急响应手册-最新版 | [gm7.org](https://www.gm7.org/archives/27413) |
| 阿里云 | 安全态势报告 (2025-2026) | [help.aliyun.com](https://help.aliyun.com/zh/acsg/security-posture-report-december-2025) |
| 阿里云 AVD | Linux Kernel "Dirty Frag" 提权漏洞通告 | [avd.aliyun.com](https://avd.aliyun.com/) |
| 安全客 | 应急事件检测入门-Linux 信息检测 | [anquanke.com](https://www.anquanke.com/post/id/264087) |
| 网宿科技 | Linux 应急响应思路：日志分析篇 | [wangsu.com](https://www.wangsu.com/news/content/blog/3900) |
| 腾讯云 | 安全之应急响应 (FreeBuf 甲方社群) | [cloud.tencent.com](https://cloud.tencent.com/developer/article/2258836) |
| 跳跳糖 | Linux 新版内核内存取证分析 | [tttang.com](https://tttang.com/archive/1762/) |
| 知乎 | Linux 内存取证入门 | [zhuanlan.zhihu.com](https://zhuanlan.zhihu.com/p/661647774) |

---

### 21. 防御升级路线图 (P0-P3)

| 优先级 | 行动项 | 影响 | 时间线 |
|--------|--------|------|--------|
| **P0 (立即)** | 部署 io_uring 审计规则; 评估是否可禁用 io_uring | 检测 "Curing" 类 rootkit | 1 周 |
| **P0 (立即)** | 应用内核安全补丁 (CVE-2026-46333/46300/43284/31431) | 阻止已知提权路径 | 1 周 |
| **P1 (短期)** | 部署增强型 auditd 规则集 (§9); 配置远程日志转发 | 提升审计覆盖 | 2-4 周 |
| **P1 (短期)** | 安装 eBPF 取证工具集 (bcc/bpftrace); 配置基线 | 实时内核级监控 | 2-4 周 |
| **P2 (中期)** | 部署 Velociraptor/GRR 实现远程取证能力 | 企业级 IR 响应 | 1-2 月 |
| **P2 (中期)** | 构建 Linux 取证自动化管线 (证据收集 → AI 分析 → 报告) | 加速 IR 周期 | 1-2 月 |
| **P3 (长期)** | 实施持续监控体系 (OSQuery + Elastic + Falco) | 预防性检测 | 3-6 月 |
| **P3 (长期)** | 建立内存取证能力 (LiME + Volatility3 + AI 分析) | 高级威胁检测 | 3-6 月 |

---

### 参考资源

- [Elastic Security Labs - Auditd 检测工程](https://www.elastic.co/cn/security-labs/linux-detection-engineering-with-auditd)
- [Elastic Security Labs - Linux Rootkit Detection Engineering](https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act)
- [ARMO - io_uring Rootkit](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [Sysdig - Detecting io_uring Abuse](https://www.sysdig.com/blog/detecting-and-mitigating-io-uring-abuse-for-malware-evasion/)
- [Qualys - CVE-2026-46333 ptrace 提权](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Wiz - Dirty Frag](https://www.wiz.io/blog/dirty-frag-linux-kernel-local-privilege-escalation-via-esp-and-rxrpc)
- [ScienceDirect - eBPF HKRD](https://www.sciencedirect.com/science/article/abs/pii/S0167404825002718)
- [arXiv - Temporal Anomaly Rootkit Detection](https://arxiv.org/html/2503.02402v1)
- [Synacktiv - LinkPro eBPF Rootkit](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis)
- [Volatility3 v2.28.1 Parity Release](https://volatilityfoundation.org/announcing-the-official-parity-release-of-volatility-3/)
- [SANS - Linux IR and Threat Hunting Poster](https://www.sans.org/posters/linux-incident-response-threat-hunting-poster)
- [SentinelOne - 5 DFIR Solutions for 2026](https://www.sentinelone.com/cybersecurity-101/services/dfir-solutions/)
- [Linux 应急响应日志分析 (2025)](https://www.wangsu.com/news/content/blog/3900)
- [Linux 内存取证入门](https://zhuanlan.zhihu.com/p/661647774)
- [Linux 新版内核内存取证分析](https://tttang.com/archive/1762/)
- [Linux 取证系列](https://github.com/aplyc1a/blogs/blob/master/%E5%8F%96%E8%AF%81%E6%BA%AF%E6%BA%90/Linux%E5%8F%96%E8%AF%81-(3).md)
- [Linux 入侵应急响应黄金 1 小时](https://www.gm7.org/archives/107595)
- [火山引擎 - Linux 应急响应笔记](https://developer.volcengine.com/articles/7381512331072962570)
- [gm7.org - Linux 应急响应手册最新版](https://www.gm7.org/archives/27413)
- [Huntress - Velociraptor Misuse via WSUS (2025)](https://www.huntress.com/blog/velociraptor-misuse-part-one-wsus-up)
