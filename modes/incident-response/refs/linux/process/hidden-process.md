# Linux 可疑与隐藏进程排查

> 定位：从「一堆正在运行的进程」里快速找出异常与「被隐藏的进程」。隐藏进程是 Linux 应急最容易被漏掉的一环——攻击者用 LD_PRELOAD/ld.so.preload/libc 篡改或 LKM 内核模块，让 `ps`/`top`/`netstat` 看不到自己。
> 本文为自写原创方法论，来源链接见文末。

---

## 0. 为什么 `ps` 会骗你

`ps`/`top`/`ss` 等用户态工具读取 `/proc` 或调用 `readdir()`/`getdents()` 获取进程/网络信息。攻击者若注入恶意 `.so`（LD_PRELOAD、`/etc/ld.so.preload`）或加载 LKM 内核模块，钩住这些 syscall，就能对特定进程/端口做「过滤返回」，让工具看不见。因此排查的核心原则是：**用多套独立数据源交叉比对，任何单一工具的结果都不作数。**

---

## 1. 进程全景采集（三套源比对）

### 1.1 直接遍历 /proc（绕开用户态工具）

```bash
# 直接读 /proc 下所有数字目录 = 所有 PID（内核视角，不受 ps 欺骗）
ls -1 /proc | grep -E '^[0-9]+$' | sort -n > /tmp/proc_pids.txt

# 对应每个 PID 取进程名与命令行
for p in $(cat /tmp/proc_pids.txt); do
  name=$(cat /proc/$p/comm 2>/dev/null)
  cmd=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
  echo "$p $name $cmd"
done | sort -n > /tmp/proc_view.txt

# ps 视角
ps -eo pid,comm,args --sort=pid > /tmp/ps_view.txt
```

判据：**对比 `/tmp/proc_view.txt` 与 `/tmp/ps_view.txt`**，前者有、后者没有的 PID = 被隐藏的进程。这能绕过绝大多数用户态隐藏。

### 1.2 交叉比对的实现

```bash
# 提取 ps 里出现的 PID 集合
awk '{print $1}' /tmp/ps_view.txt | grep -E '^[0-9]+$' | sort -n | uniq > /tmp/ps_pids.txt

# 差集：/proc 有、ps 没有 = 隐藏进程
comm -23 /tmp/proc_pids.txt /tmp/ps_pids.txt
```

误报规避：极短命的进程（`ps` 快照瞬间已退出）会出现在差集里，属正常；**连续多次采样都稳定存在的差集 PID 才定性为隐藏**。

### 1.3 全量进程异常特征速览

```bash
# 按 CPU 排序（挖矿最直观）
ps -eo pid,ppid,user,%cpu,%mem,etime,comm,args --sort=-%cpu | head -40

# 按启动时间排序（新出现的进程，找攻击者刚拉起的）
ps -eo pid,ppid,user,lstart,comm,args --sort=start_time | tail -40

# 关注「高 CPU 且名字像系统进程但路径在 /tmp 或 /dev/shm」
ps -eo pid,user,%cpu,comm,args | awk '$3>50 {print}'
```

判据（字段级）：
- `%cpu` 持续接近/超过单核 100%（多线程可超 100）且 `comm` 是 `kdevtmpfsi`/`kinsing`/`xmrig` 或随机字母串 = 挖矿。
- `args` 路径落在 `/tmp/`、`/dev/shm/`、`/var/tmp/`、`/run/` 且带执行权限 = 高危。
- `ppid=1`（父进程是 init）且 `comm` 不像标准守护进程 = 被 systemd/init 收养的孤儿恶意进程。

误报规避：数据库/Java 服务、编译任务、备份任务也会高 CPU，要结合「进程路径 + 启动时间 + 外连 IP」三要素判定，不能只看 CPU。

---

## 2. 隐藏进程识别工具：unhide

unhide 用多套手段交叉检测被隐藏的进程与端口，是「不信 ps」的直接落地。

```bash
# 快速扫描（brute + proc + sys 三种技法）
unhide quick

# 全量：进程 + 端口 + 文件
unhide proc
unhide sys
unhide brute
unhide-tcp        # 端口隐藏检测（比对 /proc/net/tcp 与 ss/netstat 输出）
```

判据与解读：
- `unhide sys`/`unhide proc` 输出 `Found HIDDEN PID: <pid>` = 确认隐藏进程，`<pid>` 直接进 `/proc/<pid>` 深挖。
- `unhide-tcp` 输出隐藏端口 = 攻击者把 C2 监听端口从 `ss -tlnp` 里藏掉了，但 `/proc/net/tcp` 内核态仍在。
- 输出为空 + 退出码 0 = 未发现（不代表绝对安全，见第 4 节内核态隐藏）。

获取：`apt install unhide` / `yum install unhide`，或从 https://github.com/yuriygr/unhide 编译（`make && make install`）。应急现场无网时可用静态编译版放 `/tmp` 跑。

---

## 3. 进程监控：pspy（无 root 嗅探）

pspy 不需要 root，靠轮询 `/proc` 抓「进程的启动、退出、以及由它们触发的命令」——尤其能抓到「定时拉活」的挖矿/后门。

```bash
# 基础模式（默认每 100ms 轮询，抓到就打印）
./pspy

# 精简输出 + 只记录新进程
./pspy64 -p -f   # -p 打印命令行 -f 打印文件系统事件（cron 等写文件）

# 抓 cron 任务实际执行（cron 由 root 触发，pspy 能看到瞬时进程）
./pspy64 -p | grep -iE 'cron|curl|wget|sh|bash|chmod|base64'
```

判据：
- 观察到周期性的 `curl/wget xxx.sh && sh xxx.sh` = 挖矿/后门拉活链（哪怕 crontab 文件已被删，执行动作仍被 pspy 抓到）。
- 观察到 `useradd`/`crontab -e`/`echo > authorized_keys` 等瞬时高危命令 = 攻击者正在做持久化。

获取：https://github.com/DominicBreuker/pspy 的 release 下载 `pspy64`（64 位）或 `pspy32`，单二进制无需安装。

误报规避：pspy 会刷屏（系统里每毫秒都有进程启停），务必用 `grep` 过滤或 `-f` 只看文件事件；长时间运行建议重定向到文件再离线分析。

---

## 4. LD_PRELOAD / ld.so.preload 隐藏进程识别

这是 Linux 应急最高频的用户态隐藏手段——恶意 `.so` 钩住 `readdir`，让 `ps` 读 `/proc` 时跳过自己的进程名。

### 4.1 检查注入点

```bash
# 1. 环境变量 LD_PRELOAD（当前 shell 与全局）
echo "$LD_PRELOAD"
env | grep -i preload

# 2. 全局预加载文件（最高危，对所有进程生效，重启仍在）
cat /etc/ld.so.preload 2>/dev/null
ls -la /etc/ld.so.preload

# 3. 恶意 so 文件本身
ls -la /lib/  /lib64/ /usr/lib/ /usr/lib64/ 2>/dev/null | grep -iE '\.so' | grep -vE '\.so\.[0-9]'
```

判据：
- `/etc/ld.so.preload` 内容非空 = **立即告警**（正常系统该文件不存在或为空）。
- 指向的 `.so` 文件 `stat` 看 mtime 是否为近期、`ls -la` 看权限是否为 root 且最近改动。
- `LD_PRELOAD` 环境变量被写进 `/etc/profile`、`/etc/bash.bashrc`、`~/.bashrc` = 持久化注入（见 persistence 篇）。

### 4.2 识别被隐藏的进程（比 /proc 遍历更进一步）

恶意 so 常通过 hook `readdir` 隐藏「特定名字」的进程，直接遍历 `/proc/<pid>/comm` 也可能被过滤。更硬的交叉验证：

```bash
# 1. 用 syscall 直读（strace 跟踪 ps 实际读到的目录项）
strace -e getdents64 ps aux 2>&1 | grep -E 'getdents64|comm' | head -50

# 2. 枚举 /proc 里的 exe 软链（隐藏进程通常不隐藏 /proc/<pid>/exe 本身）
for p in $(ls -1 /proc | grep -E '^[0-9]+$'); do
  exe=$(readlink /proc/$p/exe 2>/dev/null)
  [ -n "$exe" ] && echo "$p $exe"
done | grep -vE '\(deleted\)' > /tmp/exe_view.txt

# 3. 找「路径可疑」的进程（在 /tmp、/dev/shm、隐藏目录运行）
grep -E '/tmp/|/dev/shm|/var/tmp|/\.[a-z]' /tmp/exe_view.txt
```

判据：`/tmp/exe_view.txt` 里出现路径在 `/tmp`、`/dev/shm`、`/var/tmp`、或以 `.` 开头的隐藏目录下的进程 = 高危；出现 `(deleted)` 且不是正常升级残留 = 进程可执行文件已被删除（常见于内存马/一次性后门）。

---

## 5. 挖矿进程特征速查

| 特征 | 判据 | 命令 |
| :--- | :--- | :--- |
| 高 CPU | `%cpu` 持续 > 90% | `top -b -n1 \| head -30` |
| 已知矿工进程名 | `xmrig`、`kdevtmpfsi`、`kinsing`、`kthreaddk`、`sysupdate`、`networkservice` | `ps -eo comm \| sort \| uniq -c \| sort -rn \| head` |
| 伪装系统进程 | 名字像内核线程（如 `kdevtmpfsi`）但 `ppid` 不是 `kthreadd`(pid 2) | `ps -eo pid,ppid,comm,args` |
| 运行路径异常 | exe 在 `/tmp`、`/dev/shm`、`/var/tmp` | `ls -l /proc/<pid>/exe` |
| 外连矿池 | 连接 4444/5555/3333/14444 等端口或已知矿池 IP | `ss -tnp \| grep <pid>` |
| crontab 拉活 | 周期执行挖矿脚本 | 见 persistence 篇 |

```bash
# 一次性捞出「高 CPU + 路径可疑」的进程
ps -eo pid,user,%cpu,comm,args --sort=-%cpu | \
  awk 'NR>1 && ($3>50 || $5 ~ /\/tmp\/|\/dev\/shm|\/var\/tmp/) {print}'

# 定位矿工样本与启动命令
PID=<可疑pid>
ls -l /proc/$PID/exe        # 样本真实路径（可能是 (deleted)）
cat /proc/$PID/cmdline | tr '\0' ' '; echo
cat /proc/$PID/environ | tr '\0' '\n' | grep -iE 'pool|wallet|xmr|mine'
cat /proc/$PID/status | grep -E '^(Name|PPid|Uid)'
```

判据：`/proc/<pid>/environ` 里出现 `pool`、`wallet`、`xmr`、`rig-id`、矿池域名/IP = 实锤挖矿；`Name`/`PPid` 用于判断是否伪装内核线程。

误报规避：`kdevtmpfsi` 是高仿内核线程名（真内核线程叫 `kdevtmpfs`，多一个 `i`），但真系统里也有叫 `kdevtmpfs` 的内核线程，务必核对 PPid 是否为 2（kthreadd）再定性。

---

## 6. 内核态隐藏进程（LKM rootkit）补充识别

用户态方法对 LKM rootkit 无效（它直接 hook 内核）。检测思路：

```bash
# 1. lsmod 与 /proc/modules、/sys/module 三源比对
lsmod | sort > /tmp/lsmod.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/procmod.txt
ls /sys/module | sort > /tmp/sysmod.txt
comm -3 /tmp/lsmod.txt /tmp/procmod.txt   # 不一致 = 有模块被隐藏

# 2. 非法/未签名模块
modinfo <模块名> | grep -E 'sig|signer|filename'
# 对签名配置检查（内核是否要求签名）
cat /proc/sys/kernel/modules_disabled
grep -i CONFIG_MODULE_SIG /boot/config-$(uname -r) 2>/dev/null
```

判据：`lsmod` 里没有、但 `/proc/modules` 或 `/sys/module` 里有的模块 = 被隐藏的 LKM；`modules_disabled=1` 下仍出现新模块 = 异常（该值为 1 时禁止加载模块）。

详见 `rootkit/so-backdoor-rootkit.md`。

---

## 来源

- unhide（隐藏进程/端口检测）：https://github.com/yuriygr/unhide
- pspy（无 root 进程/cron 嗅探）：https://github.com/DominicBreuker/pspy
- Wiz《Linux rootkits explained – Part 1: Dynamic linker hijacking》：https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking
- 进程隐藏原理梳理（安恒/FreeBuf 系参考）：https://www.anquanke.com/post/id/226285
- 本库 `cookbook-linux/12-常规安全检查.md` 0x08「动态链接库劫持」、0x30/0x31「内核模块签名」、0x33「proc 与 ps 进程对比」（GPL-3.0 原文）
- 本库 `cookbook-linux/16-知识点附录.md` 0x05「与 C&C 隐藏技术的对抗」（GPL-3.0 原文）
