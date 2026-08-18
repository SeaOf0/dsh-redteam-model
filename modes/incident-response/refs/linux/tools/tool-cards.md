# Linux 应急工具速查卡

> 定位：15 个核心工具的「用途 / 关键命令 / 输出解读 / 获取」四字段速查卡，应急现场按需取用。
> 本文为自写原创内容，工具官方来源见每卡「获取」与文末。

---

## 1. chkrootkit — rootkit 特征扫描

- **用途**：扫描已知 rootkit / 后门 / 被篡改的系统二进制特征。
- **关键命令**：
  ```bash
  chkrootkit            # 全量
  chkrootkit -q         # 只输出命中
  chkrootkit | grep -E 'INFECTED|suspicious|possible'
  ```
- **输出解读**：`INFECTED` = 命中已知特征；`not infected`/`nothing found` = 未命中；`possible LKM trojan`/`suspicious files` 类结果常伴随误报，需人工复核具体文件。
- **获取**：`apt install chkrootkit` / `yum install chkrootkit`；http://www.chkrootkit.org/

## 2. rkhunter（Rootkit Hunter）— rootkit + 文件完整性

- **用途**：rootkit 检测 + 系统文件哈希基线比对（防 libc/sshd/ls 被替换）。
- **关键命令**：
  ```bash
  rkhunter --propupd                    # 首次建立文件哈希基线
  rkhunter --check --skip-keypress      # 全量检查
  rkhunter --check --rwo                # 只输出告警（report warnings only）
  ```
- **输出解读**：`Warning:` 开头 = 需复核（分文件被改/隐藏文件/可疑模块/可疑启动项）；`--rwo` 用于降噪只留告警。
- **获取**：`apt install rkhunter` / `yum install rkhunter`；http://rkhunter.sourceforge.net/

## 3. Lynis — 主机安全审计/加固

- **用途**：Linux 主机安全审计与加固基准（CISOfy），善后加固阶段用。
- **关键命令**：
  ```bash
  lynis audit system                   # 全量审计
  lynis audit system --quick           # 快速模式
  grep -E 'Suggestion|Warning' /var/log/lynis.log | head -50
  ```
- **输出解读**：输出 `Suggestion`（加固建议）与 `Warning`（风险项），结尾给硬化指数（Hardening index）；用于善后阶段「还差哪些加固」。
- **获取**：`apt install lynis` / `yum install lynis`；https://github.com/CISOfy/lynis

## 4. osquery — SQL 查询端点状态

- **用途**：用 SQL 查询进程/文件/网络/用户等端点状态，检测基线化、可分布式。
- **关键命令**：
  ```bash
  osqueryi                          # 交互式
  osqueryi "SELECT pid,name,path,cmdline FROM processes WHERE name LIKE '%xmrig%';"
  osqueryi "SELECT * FROM listening_ports WHERE port NOT IN (22,80,443);"
  osqueryi "SELECT * FROM crontab;"
  osqueryi "SELECT * FROM users WHERE uid=0;"
  ```
- **输出解读**：表结构清晰（`processes`/`listening_ports`/`crontab`/`users`/`file` 等），一条 SQL 一个排查点，可写成定时 query pack 做持续检测。
- **获取**：`apt install osquery` / `yum install osquery`；https://github.com/osquery/osquery

## 5. Falco — 运行时威胁检测（eBPF/sysdig）

- **用途**：基于 eBPF/sysdig 内核事件流，检测容器/主机异常行为（反弹 shell、敏感文件读写、异常进程）。
- **关键命令**：
  ```bash
  falco                              # 前台运行（默认规则）
  falco -r /etc/falco/falco_rules.yaml
  # 关键规则场景：shell 到容器、读写 /etc/shadow、非预期网络外连
  ```
- **输出解读**：告警含「规则名 + 事件时间 + 进程 + 用户 + 详情」，如 `Terminal shell in container`、`Read sensitive file untrusted`；适合持续在线检测而非事后取证。
- **获取**：https://github.com/falcosecurity/falco

## 6. Sysdig — 系统调用级捕获与深度分析

- **用途**：系统调用级抓取与「类 tcpdump 的 syscall 抓包」，深度分析进程行为、抓反弹 shell、查隐藏活动。
- **关键命令**：
  ```bash
  sysdig -c topprocs_cpu                # 按 CPU 排行进程
  sysdig proc.name=bash                 # 只看 bash 的 syscall
  sysdig -c spy_users                   # 抓用户输入（键盘记录还原）
  sysdig -c shellshock_detect           # 检测 shell 注入类
  sysdig -w /tmp/evidence.scap          # 抓包留证（事后回放）
  sysdig -r /tmp/evidence.scap proc.name=curl
  ```
- **输出解读**：`-c` 后的 chisel（`spy_users`/`spy_file`/`shellshock_detect`）是内置分析器，直接给结论；`-w` 抓的 `.scap` 是审计级证据，可离线回放。
- **获取**：`apt install sysdig` / `yum install sysdig`；https://github.com/draios/sysdig

## 7. Velociraptor — 开源远程 DFIR 平台

- **用途**：远程采集、威胁狩猎、证据收集的开源 DFIR 框架（client-server 架构，规模化应急）。
- **关键命令**：
  ```bash
  velociraptor --config client.yaml client --help
  # 通过 GUI/API 下发 VQL 采集与狩猎 artifact（进程/文件/内存/网络）
  # 常用 VQL 示例（采集所有进程）
  # SELECT * FROM pslist()
  ```
- **输出解读**：采集结果回传 server 集中分析；用 VQL（Velociraptor Query Language）编写可复用的采集/狩猎 artifact，适合多主机批量取证。
- **获取**：https://github.com/Velocidex/velociraptor

## 8. unhide — 隐藏进程/端口检测

- **用途**：用 brute/proc/sys 多手段发现被 rootkit 隐藏的进程与端口。
- **关键命令**：
  ```bash
  unhide quick
  unhide proc
  unhide sys
  unhide-tcp          # 端口隐藏检测
  ```
- **输出解读**：`Found HIDDEN PID: <pid>` = 确认隐藏进程；`unhide-tcp` 输出隐藏端口（比对 `/proc/net/tcp` 与 `ss`）；空输出 + 退出码 0 = 未发现（不等于绝对安全）。
- **获取**：`apt install unhide` / `yum install unhide`；https://github.com/yuriygr/unhide

## 9. pspy — 无 root 进程/cron 嗅探

- **用途**：无 root 权限轮询 `/proc`，抓进程启动、cron 执行、命令执行（抓「定时拉活」挖矿/后门）。
- **关键命令**：
  ```bash
  ./pspy64              # 默认 100ms 轮询
  ./pspy64 -p -f        # -p 打印命令行，-f 打印文件系统事件
  ./pspy64 -p | grep -iE 'curl|wget|sh |bash|chmod|base64|cron'
  ```
- **输出解读**：输出「时间 + UID + 进程启动/退出 + 命令行」，能抓到瞬时执行的高危命令（哪怕 crontab 文件已删）；噪音大，务必 grep 过滤。
- **获取**：https://github.com/DominicBreuker/pspy（release 下载 `pspy64`/`pspy32` 单二进制）

## 10. auditd — 内核审计框架

- **用途**：内核级细粒度审计（syscall/文件/命令），攻击链还原核心证据源。
- **关键命令**：
  ```bash
  auditctl -l                          # 列规则（空 = 被清空/未配置）
  auditctl -w /etc/passwd -p wa -k identity_change
  ausearch -k identity_change -i
  ausearch -ts 08/01/2025 00:00:00 -te 08/02/2025 23:59:59
  aureport -l | aureport -f | aureport -x
  ```
- **输出解读**：`ausearch -i` 把 uid/syscall 翻译成可读名，字段 `syscall/comm/exe/auid/uid/key` 是关键；`aureport -l/-x/-f` 给登录/执行/文件汇总。
- **获取**：`apt install auditd` / `yum install audit`；https://github.com/linux-audit/audit-userspace

## 11. LiME — Linux 内存镜像提取

- **用途**：从运行中的 Linux 提取内存镜像（配合 Volatility 分析），rootkit/恶意进程/隐藏网络还原。
- **关键命令**：
  ```bash
  # 编译（需内核头文件）
  make
  insmod lime-$(uname -r).ko "path=/tmp/mem.lime format=lime"
  # 或 format=raw；抓完后 rmmod lime 或直接带出
  ```
- **输出解读**：生成 `.lime` 内存镜像；`format=lime` 是 LiME 格式（Volatility 直接支持），`raw` 是原始格式；抓取过程不破坏系统状态。
- **获取**：https://github.com/504ensicsLabs/LiME

## 12. AVML — 跨发行版易失内存采集

- **用途**：微软出品，无需编译、跨发行版的易失内存快速采集（一条命令出镜像）。
- **关键命令**：
  ```bash
  ./avml /tmp/mem.img             # 采集到文件
  ./avml --compress /tmp/mem.img.gz   # 压缩采集（省空间）
  ```
- **输出解读**：生成内存镜像文件（`.img`），供 Volatility3 分析；比 LiME 简单（免编译、免内核头），适合现场快速抓取。
- **获取**：https://github.com/microsoft/avml（release 下载静态二进制）

## 13. Volatility 3 — 内存镜像分析框架

- **用途**：分析内存镜像，还原进程、网络连接、加载模块、隐藏 rootkit、恶意进程。
- **关键命令**：
  ```bash
  vol -f /tmp/mem.img linux.pslist            # 进程列表
  vol -f /tmp/mem.img linux.pstree            # 进程树
  vol -f /tmp/mem.img linux.netstat           # 网络连接
  vol -f /tmp/mem.img linux.lsmod             # 加载模块
  vol -f /tmp/mem.img linux.bash              # bash 历史（内存态）
  vol -f /tmp/mem.img linux.check_syscall      # syscall 表完整性
  vol -f /tmp/mem.img banners.Banners         # 识别内核版本
  ```
- **输出解读**：`linux.pslist` 能还原「进程已退出/被隐藏」的痕迹（内存里还在）；`linux.check_syscall` 检测 syscall 表被 hook 的 rootkit；`linux.bash` 挖出被清空的 bash 历史。
- **获取**：`pip install volatility3`；https://github.com/volatilityfoundation/volatility3

## 14. plaso（log2timeline）— 超级时间线

- **用途**：把文件系统、日志、注册表等异构证据聚合成统一时间线。
- **关键命令**：
  ```bash
  log2timeline.py /output/evidence.plaso /mnt/evidence
  psort.py -o l2tcsv -w /output/timeline.csv /output/evidence.plaso
  psort.py -o l2tcsv -w /output/t.csv /output/evidence.plaso "date > '2025-08-01'"
  ```
- **输出解读**：导出的 CSV 按时间排序，攻击者动作（登录→下载→落地→执行→持久化→外连）连成流水账；`timestamp_desc`/`source`/`message` 是关键列。
- **获取**：`pip install plaso`（或发行版 `plaso`）；https://github.com/log2timeline/plaso

## 15. ZLT（ZavetSec Linux Triage）— 一键取证

- **用途**：bash 单命令采集 13 模块、内联分析、映射 MITRE ATT&CK、输出可交互 HTML 报告。
- **关键命令**：
  ```bash
  # 下载 ZLT 后（需 bash + 少量依赖）
  ./ZLT.sh -l        # 列出模块
  ./ZLT.sh -a        # 全模块采集 + 分析 + 生成 HTML 报告
  ```
- **输出解读**：生成 HTML 报告，13 个模块（进程/网络/账户/持久化/日志/内存线索等）内联分析并映射 MITRE ATT&CK 技术，适合「上手快、快速出基线」的现场初查。
- **获取**：https://github.com/zavetsec/ZLT

---

## 工具选型速查

| 场景 | 首选工具 |
| :--- | :--- |
| 现场初查/快速出基线 | ZLT |
| 隐藏进程/端口 | unhide、pspy |
| rootkit/文件篡改 | chkrootkit、rkhunter |
| 攻击链溯源 | auditd、plaso |
| 内存取证 | AVML/LiME（采集）+ Volatility3（分析） |
| 持续检测/容器 | Falco、osquery |
| 深度 syscall 分析 | Sysdig |
| 规模化远程 DFIR | Velociraptor |
| 善后加固 | Lynis |
