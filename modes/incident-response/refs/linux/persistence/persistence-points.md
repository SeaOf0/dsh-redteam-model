# Linux 持久化排查点全集

> 定位：失陷后攻击者用来「重启/登出后还能回来」的所有落点。本清单按「位置 + 检查命令 + 判据」逐项给出，可当可勾选清单逐项过。
> 本文为自写原创方法论；与 cookbook 第 12 章「39 项常规安全检查」互补（那边是原文清单，这里是实现级命令与字段判据）。来源链接见文末。

---

## 0. 排查总原则

1. **优先级排序**：先查「能远程重新登录」的（authorized_keys、PAM、账户），再查「能自启动」的（cron、systemd、rc），最后查「能劫持命令」的（alias、函数、LD_PRELOAD）。
2. **所有命令用绝对/明确路径**，因为攻击者可能改 `$PATH` 让 `cat`/`ls`/`ps` 指向木马。
3. **时间戳交叉**：任何可疑落点，都 `stat <文件>` 看 mtime/ctime 是否与失陷时间窗重合。
4. **先做基线**：正常系统这些位置也有内容，先理解「默认长什么样」再挑「多出来的」。

---

## 1. 计划任务（cron）——挖矿/后门最高频拉活手段

### 1.1 全部 cron 落点

```bash
# 一次性列出所有计划任务落点及内容
echo "=== /etc/crontab ==="; cat /etc/crontab
echo "=== /etc/cron.d/* ==="; for f in /etc/cron.d/*; do echo "--- $f ---"; cat "$f"; done
echo "=== /var/spool/cron/*（用户级） ==="; for f in /var/spool/cron/*; do echo "--- $f ---"; cat "$f"; done
echo "=== /etc/anacrontab ==="; cat /etc/anacrontab 2>/dev/null
echo "=== cron.daily/hourly/weekly/monthly ==="; ls -la /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
echo "=== at/batch ==="; ls -la /var/spool/at /var/spool/cron/atjobs 2>/dev/null; for f in /var/spool/at/*; do [ -f "$f" ] && { echo "--- $f ---"; cat "$f"; }; done
```

判据：
- 任何指向 `/tmp/`、`/dev/shm/`、`/var/tmp/`、`/run/` 下脚本的条目 = 高危。
- 内容含 `wget|curl|base64 -d|/bin/sh -c|chmod +x` 且下载外网地址 = 实锤拉活。
- 频率异常（`*/1 * * * *` 每分钟）且不是系统任务 = 拉活链。
- **注意**：`/etc/cron.d/` 下文件名必须以 `[a-zA-Z0-9_-]` 构成（不能带点），攻击者常用 `..` 之类名字伪装，`ls -la` 要连隐藏文件一起看。

### 1.2 检查「正在执行」的计划任务

crontab 文件可能被删，但已加载进 cron 守护进程的任务仍在跑：

```bash
# 看 cron 守护进程实际加载的任务
grep -aE '^\*|^[0-9]|^@' /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null
# 或直接看运行中的 cron 进程命令行
ps -eo pid,ppid,args | grep -iE 'cron|CRON'
```

误报规避：系统自带 `run-parts /etc/cron.daily`、`logrotate`、`anacron` 是正常项；把正常基线列一张表，异常 = 不在表内的。

---

## 2. systemd 单元（service/timer/socket/path）

```bash
# 列出所有单元，按修改时间排序（找最近新增/改动的）
find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -type f \
  \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) \
  -printf '%T+ %p\n' 2>/dev/null | sort -r | head -40

# 已启用（开机自启）的单元
systemctl list-unit-files --state=enabled | grep -viE '^(dbus|getty|multi-user|network|ssh|systemd)' 

# 可疑单元的内容与状态
systemctl cat <可疑单元名>
systemctl status <可疑单元名>
```

判据：
- `ExecStart=` 指向 `/tmp`、`/dev/shm`、隐藏目录下的二进制/脚本 = 后门。
- 单元名伪装（`systemd-network.service` 多空格、`syslogd.service` 拼写错）或与系统单元重名但路径在 `/etc/systemd/system`（用户级覆盖系统级）= 篡改。
- 新建 `.timer` 触发周期执行 = 替代 cron 的拉活（比 cron 更隐蔽，易漏）。

误报规避：第三方软件（docker、nginx、prometheus）会装自己的 service，属正常；只挑「时间戳异常 + ExecStart 路径异常 + 名字伪装」三者叠加的。

---

## 3. 启动项脚本与配置

### 3.1 rc.local / init.d / rc*.d

```bash
cat /etc/rc.local 2>/dev/null
cat /etc/rc.d/rc.local 2>/dev/null     # RHEL 系
ls -la /etc/init.d/
# 检查 rc*.d 里指向 /tmp、可疑脚本的软链
find /etc/rc*.d /etc/init.d -type l -exec ls -la {} \; 2>/dev/null | grep -iE '/tmp|/dev/shm|/var/tmp|/root/\.'
```

判据：`rc.local` 里 `exit 0` 之前被插入 `sh /tmp/xxx.sh` 之类 = 开机自启后门。

### 3.2 profile / bashrc（全局 + 用户）

```bash
# 全局登录脚本
cat /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc 2>/dev/null | grep -vE '^\s*#|^\s*$'

# 所有用户的家目录登录脚本
for f in /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /root/.bashrc /root/.bash_profile /root/.profile; do
  [ -f "$f" ] && { echo "--- $f ---"; grep -vE '^\s*#|^\s*$' "$f"; }
done
```

判据：出现 `alias` 重定义系统命令、`export LD_PRELOAD=`、`source /tmp/xxx`、`echo xxx >> authorized_keys`、`/dev/shm/xxx &` = 劫持/后门。

误报规避：正常 `.bashrc` 有大量 alias（如 `alias ll='ls -alF'`）和提示符设置，属正常；重点看 `alias` 指向 `/tmp` 脚本、或重定义了 `ls`/`cat`/`ps` 等核心命令。

---

## 4. SSH 凭据与配置持久化

### 4.1 authorized_keys 后门

```bash
# 所有 authorized_keys 内容与时间戳
find /home /root -name authorized_keys -exec ls -la {} \; 2>/dev/null
find /home /root -name authorized_keys -exec sh -c 'echo "=== $1 ==="; cat "$1"' _ {} \; 2>/dev/null

# 找「近期新增」的公钥（对比时间戳）
find /home /root -name authorized_keys -mtime -30 -exec ls -la {} \; 2>/dev/null
```

判据：
- 公钥文件末尾多出一行「未知来源」的公钥 = 后门登录入口。
- 公钥注释（最后一段）是攻击者邮箱/主机名/随机串，与已知运维公钥注释不符。
- `authorized_keys` 的 mtime 与失陷时间窗重合。

误报规避：正常运维会加自己的公钥，需与「已知运维公钥清单」比对；注释字段是最佳鉴别点。

### 4.2 sshd_config / ssh config 篡改

```bash
grep -vE '^\s*#|^\s*$' /etc/ssh/sshd_config
# 用户级 ssh config（可配 UserKnownHostsFile 指向木马、LocalForward 开隧道）
find /home /root -name config -path '*/.ssh/*' -exec sh -c 'echo "=== $1 ==="; cat "$1"' _ {} \; 2>/dev/null
```

判据：
- `PermitRootLogin yes`（被从 no 改成 yes）、`PasswordAuthentication yes`（原禁止）、新增 `AllowUsers/AllowGroups` 排除审计账户。
- 用户 `~/.ssh/config` 里异常 `LocalForward`/`RemoteForward`（端口转发后门）、`UserKnownHostsFile /dev/null`（关闭主机指纹校验）。

---

## 5. 账户与提权持久化

```bash
# 新增账户 / UID=0 账户
grep -E 'x:0:' /etc/passwd           # UID=0 的账户（正常只有 root）
grep -vE '^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody)' /etc/passwd | tail -30
cat /etc/passwd | awk -F: '$3==0 {print}'
# 特权组
grep -E '^(sudo|wheel|adm):' /etc/group
# 无密码 sudo
grep -E 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
# 最近改过密码的账户（/etc/shadow 时间戳）
grep -vE ':\*|:!' /etc/shadow | awk -F: '{print $1, $3}'
```

判据：
- `/etc/passwd` 里出现第二个 `x:0:`（UID=0）账户 = 攻击者留的后门超管。
- 账户名伪装成系统名（如 `systemd`、`dbus`、`ftp` 但 UID 是 0 或近期创建）。
- `sudoers` 里 `ALL=(ALL) NOPASSWD: ALL` 且用户是近期新增 = 提权持久化。

误报规避：`/etc/shadow` 的 `$3` 字段是密码最后修改的 epoch 天，近期大改需对照变更管理记录，正常运维也会改。

---

## 6. PAM 后门

PAM（可插拔认证模块）被篡改可实现「万能密码」「免密登录」「记录明文口令」。

```bash
# 定位被篡改的 PAM 模块（比对模块文件时间戳与校验）
ls -la /lib/x86_64-linux-gnu/security/ /lib64/security/ 2>/dev/null
# 找近期改动的 pam 模块
find /lib*/security /usr/lib*/security -name 'pam_*.so' -mtime -60 -exec ls -la {} \; 2>/dev/null

# 检查 PAM 配置文件是否引用了异常模块
grep -rnE 'pam_[a-z_]+\.so' /etc/pam.d/ | grep -viE 'pam_(unix|env|deny|permit|systemd|limits|loginuid|nologin|motd|mail|keyinit|selinux|faillock|tally2|sss|access|echo|cap|mkhomedir|umask|lastlog|securetty|wheel|pwquality|cracklib|pwhistory|tty_audit|debian)\.so'

# 对比模块内容（找被插桩的 pam_unix/pam_systemd）
rpm -Vf /lib64/security/pam_unix.so 2>/dev/null || dpkg -V libpam-modules 2>/dev/null
```

判据：
- `rpm -Vf`/`dpkg -V` 输出 `5`（MD5 校验失败）或 `S`（大小变化）的 pam 模块 = 被篡改。
- `/etc/pam.d/` 里出现引用非标准 pam 模块的 `auth` 行，或 `pam_unix.so` 之前被插入了未知模块 = 后门。

误报规避：`rpm -V` 对配置文件（`c` 标记）的告警是正常的（本地改过配置），只盯 `.so` 二进制库的 `5`/`S` 校验失败。

---

## 7. 环境变量 / BASH 函数 / alias 劫持

```bash
# 环境变量注入点
grep -rniE 'export.*(LD_PRELOAD|PATH|LD_LIBRARY_PATH|PROMPT_COMMAND|BASH_ENV)' /etc/profile /etc/profile.d /etc/bash.bashrc /root/.* /home/*/.* 2>/dev/null

# BASH 函数钩子（用函数重定义系统命令）
grep -rnE '^[a-zA-Z_]+\(\)' /etc/profile /etc/bash.bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null

# alias 劫持（重定义 ls/cat/ps/ss 等）
grep -rnE 'alias (ls|cat|ps|ss|netstat|top|w|who|id|whoami)=' /etc/profile /etc/bash.bashrc /root/.* /home/*/.* 2>/dev/null

# PROMPT_COMMAND 劫持（每次命令执行前触发）
grep -rniE 'PROMPT_COMMAND' /etc/profile /etc/bash.bashrc /root/.* /home/*/.* 2>/dev/null
```

判据：
- `alias ls='...'` 指向 `/tmp` 脚本，或 `PROMPT_COMMAND` 里执行上传/回连 = 命令劫持。
- BASH 函数 `cat() { ... }` 重定义系统命令 = 隐藏攻击者文件（函数里过滤掉自己的文件）。
- `BASH_ENV` 指向 `/tmp` 脚本 = 每个非交互 shell 都加载后门。

---

## 8. 高级持久化（易漏面）

### 8.1 udev 规则后门

```bash
ls -la /etc/udev/rules.d/ /usr/lib/udev/rules.d/ 2>/dev/null
# 找触发执行二进制/脚本的规则
grep -rnE 'RUN\+?=' /etc/udev/rules.d/ /usr/lib/udev/rules.d/ 2>/dev/null
```

判据：udev 规则里 `RUN+=` 指向 `/tmp` 脚本、或 `ACTION=="add"` 触发可疑命令（如插入 U 盘即执行后门）= 硬件事件触发型后门。

### 8.2 Python .pth 后门

```bash
# 找所有 site-packages 下的 .pth 文件
find /usr/lib/python* /usr/local/lib/python* -name '*.pth' -exec sh -c 'echo "=== $1 ==="; cat "$1"' _ {} \; 2>/dev/null
```

判据：`.pth` 文件里出现 `import os; os.system(...)` 或指向 `/tmp` 模块路径 = Python 启动即执行的后门（`.pth` 第一行以 `import` 开头会被自动执行）。

### 8.3 TCP Wrappers（hosts.allow/deny 篡改）

```bash
cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null
```

判据：`hosts.allow` 里被加入 `ALL: <攻击者IP>`（放行自己）或 `sshd: ALL` 之前插入了特定 IP = 访问控制篡改。

### 8.4 /etc/skel（家目录模板）

```bash
ls -la /etc/skel/ 2>/dev/null
cat /etc/skel/.bashrc 2>/dev/null | grep -vE '^\s*#|^\s*$'
```

判据：`/etc/skel` 里被植入 `.bashrc`/`.profile` 后门 = 任何新建用户都会继承后门。

### 8.5 motd（登录横幅注入）

```bash
ls -la /etc/motd /etc/update-motd.d/ 2>/dev/null
cat /etc/motd 2>/dev/null
# 找可执行脚本形式的 motd 片段
grep -rlnE 'curl|wget|bash|/dev/shm' /etc/update-motd.d/ 2>/dev/null
```

判据：`/etc/update-motd.d/` 下新增可执行脚本，或 `/etc/motd` 被改成软链指向可写文件 = 每次 SSH 登录触发执行。

### 8.6 SSH 其他（sshd_config 子系统 / 动态库）

```bash
# AuthorizedKeysCommand 被指向可疑命令（替代 authorized_keys 校验）
grep -E 'AuthorizedKeysCommand|AuthorizedKeysFile' /etc/ssh/sshd_config
# 软链劫持 sshd 依赖库
ldd /usr/sbin/sshd | grep -vE '/lib|/usr/lib'
```

---

## 来源

- 本库 `cookbook-linux/12-常规安全检查.md`（GPL-3.0 原文）0x03 计划任务 / 0x04 账户 / 0x05 特权账户 / 0x09 BASH 内置命令 / 0x10 BASH 函数 / 0x11 环境变量 / 0x12 启动项 / 0x13 ssh key / 0x14 ssh config / 0x15 alias / 0x24 motd / 0x32 PAM / 0x35 家目录模板 / 0x36 TCP Wrappers / 0x38 udev 后门 / 0x39 Python .pth 后门
- 本库 `cookbook-linux/16-知识点附录.md` 0x02「启动项默认情况」（GPL-3.0 原文）
- MITRE ATT&CK Linux Matrix（持久化战术）：https://attack.mitre.org/matrices/enterprise/linux/
