# .so 隐藏持久后门与 rootkit 排查

> 定位：识别并定位「通过动态链接库（.so）或内核模块（LKM/eBPF）实现隐藏与持久化」的后门。这类后门能骗过 `ps`/`ls`/`ss`，是 Linux 应急的最高对抗面。
> 本文为自写原创方法论，来源链接见文末。

---

## 0. 分层心智模型

Linux 后门按「运行在哪个层」分三档，检测方法完全不同：

| 层 | 手段 | 隐藏面 | 检测要点 |
| :--- | :--- | :--- | :--- |
| 用户态 | LD_PRELOAD、`/etc/ld.so.preload`、libc 篡改、动态链接器劫持 | 进程/文件/端口（hook 用户态 syscall 封装） | 查注入点、比对 readelf/ldd、校验 libc |
| 内核态 LKM | 未签名/隐藏的内核模块 | 一切（直接 hook syscall 表） | lsmod vs /proc/modules、签名检查 |
| 内核态 eBPF | 挂接 kprobe/tracepoint | 一切（更隐蔽，无需 LKM） | 审计挂载的 eBPF 程序 |

**核心原则**：用户态工具（ps/ls/ss）的结果都不可信，必须用「内核视角数据源」（`/proc`、`/sys`、syscall 直读）交叉比对。

---

## 1. 用户态 .so 后门：动态链接器劫持检测

### 1.1 三个注入点逐一排查

```bash
# ① 进程级环境变量 LD_PRELOAD
env | grep -i preload
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  v=$(tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep -E '^LD_PRELOAD=')
  [ -n "$v" ] && echo "$p $v"
done

# ② 全局预加载 /etc/ld.so.preload（对几乎所有进程生效，持久化）
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# ③ 动态链接器搜索路径（rpath / LD_LIBRARY_PATH / ld.so.conf）
grep -rniE 'LD_LIBRARY_PATH' /etc/profile /etc/profile.d /etc/bash.bashrc /root/.* /home/*/.* 2>/dev/null
cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null
# 找被塞进链接器缓存的可疑库
ldconfig -p | grep -vE '^[[:space:]]+lib[a-zA-Z0-9_.+-]+\.so' | head
```

判据：
- `/etc/ld.so.preload` 非空 = **立即告警**（正常系统该文件不存在或空）。
- `/proc/<pid>/environ` 里某进程有 `LD_PRELOAD=<可疑.so>` = 该进程被注入。
- `ld.so.conf.d/` 里新增指向 `/tmp`/隐藏目录的 `.conf` = 动态链接器搜索路径被劫持。

### 1.2 定位被 hook 的库与函数

```bash
# 用 readelf 看某个 .so 导出了哪些「系统函数名」（恶意 so 常导出 readdir/open/stat 等）
readelf -Ws /etc/ld.so.preload里指向的.so 2>/dev/null | grep -E 'GLOBAL.*(readdir|getdents|open|stat|accept|connect|exec)' 

# 比对：ldd 报告依赖 vs 实际加载
ldd /bin/ps        # 看 ps 依赖哪些库，是否有异常路径
# 用 LD_DEBUG 跟踪实际加载了哪个库（关键验证手段）
LD_DEBUG=libs /bin/ls 2>&1 | grep -iE 'preload|\.so' | head -40
```

判据：
- `ldd /bin/ps` 输出里多出一行指向 `/tmp`/隐藏目录的 `.so` = 依赖被劫持。
- `LD_DEBUG=libs` 输出里出现「某个 `.so` 被先于 libc 加载」= preload 注入的实锤。
- 恶意 `.so` 通常导出与系统函数同名的符号（`readdir`、`open`、`accept`），`readelf -Ws` 里能看到这些 GLOBAL 符号。

误报规避：`ldd` 本身也可能被 hook（它是个普通 ELF），若怀疑 `ldd` 被劫持，用 `readelf -d /bin/ps | grep NEEDED` 直接读 ELF 的 DT_NEEDED 段，这是静态分析不受运行态影响。

### 1.3 libc 完整性校验（检测 libc 篡改）

```bash
# 定位当前 libc
ldd /bin/ls | grep libc
# 用包管理器校验 libc 是否被改（RHEL：rpm -V；Debian：debsums）
rpm -V glibc 2>/dev/null | grep -E '^\S*[5S].*libc|libc-'
dpkg -V libc6 2>/dev/null | grep -E 'libc-'

# 无包管理器校验时：比对 libc 大小/mtime（改过的 libc mtime 会变）
ls -la /lib/x86_64-linux-gnu/libc.so.6 /lib64/libc.so.6 2>/dev/null
# 对比发行版同版本 libc 的 MD5（需离线对照镜像）
md5sum /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null
```

判据：`rpm -V glibc` 里 libc 的 `5`（MD5 不符）/`S`（大小不符）= libc 被篡改（恶意者替换 libc 以实现全局 hook）。

---

## 2. 内核态 LKM rootkit 检测

### 2.1 三源比对发现隐藏模块

```bash
lsmod | awk 'NR>1{print $1}' | sort > /tmp/lsmod.txt
cat /proc/modules | awk '{print $1}' | sort > /tmp/procmod.txt
ls /sys/module | sort > /tmp/sysmod.txt
echo "=== /proc/modules 有而 lsmod 没有（隐藏模块） ==="; comm -23 /tmp/procmod.txt /tmp/lsmod.txt
echo "=== /sys/module 有而 lsmod 没有 ==="; comm -23 /tmp/sysmod.txt /tmp/lsmod.txt
```

判据：`comm` 输出的差集 = 被隐藏的内核模块（rootkit 常 hook 让 `lsmod` 读不到自己，但 `/proc/modules`、`/sys/module` 内核态仍在）。

### 2.2 模块签名与来源

```bash
# 每个模块的签名信息
for m in $(lsmod | awk 'NR>1{print $1}'); do
  echo "=== $m ==="; modinfo "$m" 2>/dev/null | grep -E 'filename|sig_|description|license'
done

# 内核签名配置
grep -iE 'CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE' /boot/config-$(uname -r) 2>/dev/null
cat /proc/sys/kernel/modules_disabled 2>/dev/null
```

判据：
- `modinfo` 里 `signer:` 为空/缺失的第三方模块（尤其 `vermagic` 异常、`license` 是 `GPL` 伪造但无签名）= 可疑。
- `CONFIG_MODULE_SIG_FORCE=y` 且 `modules_disabled=1` 却仍出现新模块 = 绕过签名强制加载（或内核被 patch）。

误报规避：NVIDIA/VMware/云厂商 virtio 等合法第三方模块也无内核签名（`signer` 空），要结合「模块名是否在基线里 + 时间戳 + 是否近期加载」判断。

### 2.3 隐藏文件/进程的 LKM 特征

LKM rootkit 除了隐藏模块，常隐藏文件与进程。检测：

```bash
# 文件隐藏：stat 已知存在的文件 vs ls 看不到
stat /etc/cron.d 2>/dev/null; ls -la /etc/cron.d
# 用 /proc/<pid> 遍历对比（见 process/hidden-process.md 第 4 节）
# 检查 syscall 表是否被篡改（/proc/kallsyms 里的符号地址与预期不符）
grep -E ' sys_call_table| sys_read$| sys_getdents' /proc/kallsyms 2>/dev/null | head
```

判据：`/proc/kallsyms` 里 `sys_call_table` 地址与内核映像导出的不符（或被置 0 隐藏）= syscall 表被 hook（需 root 且 `kptr_restrict=0` 才可见）。

---

## 3. eBPF 型 rootkit 对抗思路

eBPF 后门无需加载 LKM，用 `kprobe`/`tracepoint` 挂接内核函数实现隐藏/窃取，`lsmod` 完全看不到。检测：

```bash
# 枚举当前挂载的 eBPF 程序（bpftool）
bpftool prog list 2>/dev/null
# 关注 kprobe/tracepoint 类型（rootkit 常用）
bpftool prog list 2>/dev/null | grep -B2 -iE 'kprobe|tracepoint|fentry'

# 无 bpftool 时：看加载的 BPF 对象
ls -la /sys/fs/bpf/ 2>/dev/null
# 找挂接内核函数做「过滤/隐藏」的程序
bpftool prog dump xlated id <prog_id> 2>/dev/null | grep -iE 'getdents|filldir|readdir|tcp4_seq' | head
```

判据：
- `bpftool prog list` 出现「无对应运维工具归属」的 `kprobe`/`tracepoint` 程序，且挂接点是 `getdents64`/`filldir64`/`tcp4_seq_show` 这类「枚举类」函数 = 隐藏型 rootkit。
- `/sys/fs/bpf/` 下出现持久化的 pinned 程序（`bpffs` 挂载点）且无人认领 = 可疑。

误报规避：正常系统里 Falco、Cilium、systemd、容器运行时都会挂 eBPF 程序，先列出「基线程序清单」，只挑基线外的 `kprobe`/`tracepoint` 且挂接枚举函数的。

对抗要点：eBPF 后门清理要找到「谁加载的」（`bpftool prog show id <id>` 看 `pids` 字段关联的进程），杀进程 + `rm /sys/fs/bpf/<pinned>` 双管齐下，否则进程重启又加载。

---

## 4. rootkit 检测工具：chkrootkit / rkhunter

### 4.1 chkrootkit

```bash
chkrootkit                     # 全量扫描
chkrootkit -q                  # 安静模式（只输出命中的）
chkrootkit | grep -vE 'not (found|infected|tested)|nothing (found|detected)'   # 过滤噪音只看命中
```

解读：
- 输出 `INFECTED` = 命中已知 rootkit 特征。
- 输出 `not infected` / `nothing found` = 该检测项未命中。
- 注意：chkrootkit 的 `possible LKM trojan`、`suspicious files` 类结果常伴随误报，需人工复核具体文件。

获取：`apt install chkrootkit` / `yum install chkrootkit`，或 http://www.chkrootkit.org/ 编译。

### 4.2 rkhunter

```bash
rkhunter --check --skip-keypress    # 全量扫描（--skip-keypress 免交互回车）
rkhunter --check --skip-keypress --rwo   # --rwo 只输出告警（report warnings only）
rkhunter --propupd                  # 首次安装后更新基线（后续 --check 对比文件哈希）
```

解读：
- 输出 `Warning:` 开头的 = 需人工复核（分「文件被改」「隐藏文件」「可疑内核模块」「可疑启动项」等类别）。
- **关键用法**：先 `--propupd` 建立干净基线，之后每次 `--check` 会自动比对文件哈希，攻击者改系统文件（如替换 `ls`、libc、sshd）会被 `file properties` 检测拦出。

获取：`apt install rkhunter` / `yum install rkhunter`，或 http://rkhunter.sourceforge.net/

### 4.3 工具局限（必须知道）

- chkrootkit/rkhunter 都是**特征库**检测，对已知 rootkit 有效，对新型/定制 eBPF、改签名 LKM 的检出能力有限。
- 两者都可能被 rootkit 反制（rootkit 检测到它们就隐藏自己），**不能作为唯一结论源**，要与第 1~3 节的手工交叉比对结合。

---

## 5. 处置建议（发现后门后）

1. **先取证再清理**：`cp` 恶意 `.so`/模块/进程内存（`gcore <pid>`）留证；记录 `/proc/<pid>/exe`、`environ`、外连。
2. **清注入点**：移除 `/etc/ld.so.preload`、清 `LD_PRELOAD`、还原 libc/sshd/pam 被改文件（用包管理器重装对应包：`rpm -Uvh --force` / `apt install --reinstall`）。
3. **卸载模块**：`rmmod <模块>`（若 `modules_disabled=1` 需先 `echo 0 > /proc/sys/kernel/modules_disabled` 或重启）。
4. **重启前先拔网线/隔离**：内存态后门重启即消失，但若持久化点未清干净，重启会重新拉起。
5. **重建系统**：内核级 rootkit 高度可信度失陷时，正解是「取证镜像 → 重装 → 从备份恢复」，不要在受感染内核上继续相信任何结果。

---

## 来源

- Wiz《Linux rootkits explained – Part 1: Dynamic linker hijacking》：https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking
- chkrootkit：http://www.chkrootkit.org/
- rkhunter：http://rkhunter.sourceforge.net/
- 本库 `cookbook-linux/12-常规安全检查.md` 0x08「动态链接库劫持」、0x30/0x31「内核模块签名」、0x21「iptables 端口复用」（GPL-3.0 原文）
- 本库 `cookbook-linux/16-知识点附录.md` 0x05「与 C&C 隐藏技术的对抗」（GPL-3.0 原文）
