# Linux 盘面取证 artifacts

> 数字取证线 Linux 侧深度手册。Linux 无注册表类集中痕迹，重点在日志体系、shell 痕迹、
> 时间线扫描与"清除检测"。

## artifacts 清单

| 类 | Artifact | 位置 | 取证值 |
|---|---|---|---|
| 审计 | auditd 日志 | `/var/log/audit/audit.log`（若有） | 系统调用级：execve/文件访问/用户切换——最细粒度，若被停用本身即信号（`systemctl status auditd`+启停时间） |
| 日志 | journald | `/var/log/journal/` | 二进制日志（含已删服务的残留）；`journalctl --verify` 验完整性 |
| 登录 | wtmp/btmp/lastlog | `/var/log/wtmp`·`btmp`·`lastlog` | 登录成功/失败史（二进制，`last -f` 读）；文件被截断=清除信号 |
| 认证 | auth.log / secure | `/var/log/auth.log`·`/var/log/secure` | SSH 认证/sudo/密钥部署（authorized_keys 修改时间旁证） |
| Shell | `.bash_history` 等各 shell | 用户家目录 | 命令史；**清除检测**：文件截断/空段/时间戳与 mtime 断层/`HISTFILE` 改向痕迹（.bashrc 检查） |
| 计划任务 | cron | `/var/spool/cron/`·`/etc/cron.*` | 持久化与定时行为；内容+**mtime 双取**（新建/修改时间即行为时间） |
| 服务 | systemd 单元 | `/etc/systemd/system/`·`/usr/lib/systemd/` | 恶意单元与 mtime；`systemctl list-unit-files --state=enabled` 对照 |
| 文件系统 | 全盘时间线 | — | `fls -m`（Sleuth Kit，镜像上）或 `find / -newermt <t0> ! -newermt <t1>`（窗口扫描）；inode ctime 无法被用户级伪造（区别于 mtime/atime）——**ctime 与 mtime 背离即反取证信号** |
| 用户痕迹 | `.ssh/known_hosts`·`viminfo`·`.*_history` | 家目录 | 横向目标记录（known_hosts=连过谁）、编辑器痕迹 |
| 临时与落地 | `/tmp`·`/dev/shm`·`/var/tmp` | — | 无目录权限落地常见位（配合 mtime 扫描） |

## 采集纪律

1. 镜像优先（dd/E01+哈希）；运行中系统次选只读方式逐项采集（`cat`/`cp` 后即时哈希，
   二进制日志用对应工具只读解析）；
2. **volatile 先于盘面**：进程/连接/内存先取（与内存取证线衔接），再动盘面；
3. 时间基准：`/etc/localtime`、`timedatectl`、硬件钟与 NTP 状态记录后再比对。

## 清除检测要点（攻击者清痕本身是证据）

- wtmp/btmp 截断（`last` 输出突变段）；auth.log 空洞或轮转异常；
- `.bash_history` 清空/`unset HISTFILE`·`history -c` 后的残留配置；
- auditd/journald 停用时间窗（与攻击时间窗对照——停用动作本身要个解释）；
- inode ctime 与 mtime 背离文件清单（timestomp 面）。

## 解析通道

- 本地：Sleuth Kit（fls/mactime 产 super-timeline 输入）、journalctl/last/ausearch 只读；
- kali MCP 备胎：镜像外传分析（哈希登记+敏感先问）；
- 脚本兜底：python 解析 wtmp 二进制结构/日志聚合（标注近似解析）。
