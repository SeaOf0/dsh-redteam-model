# Linux 应急溯源参考手册库（refs/linux/）

> 本目录随 incident-response 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——incident-response 的 playbook 是速查卡，这里的文件是深度手册；需要细节时用 read 直接读取。
> 路径解析：refs/linux/ 相对预设 base 目录 = `refs/linux/`。
> 覆盖面：日志分析 / 隐藏进程 / 持久化排查 / .so 后门与 rootkit / webshell / 挖矿勒索远控 /
> 攻击链还原 / 工具速查 / 知识库索引，外加 GPL-3.0 授权知识库 17 章全量收录。
> 共 27 篇 md（另有 1 份 GPL-3.0 LICENSE）。

## 快速路由（按应急阶段找目录）

| 阶段/任务 | 目录 |
|---|---|
| 先定性事件类型（挖矿/勒索/远控/爆破/隧道/供应链） | `cookbook-linux/`（05~11 章原文） |
| 全面排查持久化与后门（39 项清单原文） | `cookbook-linux/12-常规安全检查.md` |
| 日志与登录痕迹分析 | `logs/linux-log-analysis.md` |
| 可疑/隐藏进程定位 | `process/hidden-process.md` |
| 持久化点逐项排查 | `persistence/persistence-points.md` |
| .so 后门 / rootkit / 内核模块 | `rootkit/so-backdoor-rootkit.md` |
| webshell 检测与溯源 | `webshell/webshell-detection.md` |
| 挖矿/勒索/远控处置线 | `malware/mining-ransomware-backdoor.md` |
| 攻击链还原 / 时间线 | `attack-chain/attack-chain-reconstruction.md` |
| 工具选型与用法 | `tools/tool-cards.md` |
| 外部知识库导航 | `knowledge/awesome-indexes.md` |

## 目录索引

### cookbook-linux/（GPL-3.0 授权知识库，17 篇 md + LICENSE）

> ⚠️ **许可**：本目录是 NOP Team《Linux 应急响应手册》（Linux-INCIDENT-RESPONSE-COOKBOOK）在线版
> 17 章全文收录，受 **GPL-3.0** 约束，随附 `LICENSE`（GPL-3.0 全文）。
> 再分发本目录须保留 `LICENSE`、`SOURCE.md` 与各文件头部的来源注记。
> 作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK 。

| 文件 | 内容 | 何时读 |
|---|---|---|
| `00-封面与更新日记.md` | 封面 + 更新日记（合并简述） | 了解版本演进 |
| `01-简介.md` | 手册定位与使用方法 | 首次接触本手册 |
| `03-处置前准备.md` | 应急准备项 | 处置前 |
| `04-注意事项.md` | 删除文件、`rm ./*` 不删隐藏文件等坑 | 处置中 |
| `05-挖矿病毒.md` | 挖矿病毒完整处置线（六段式） | 定性为挖矿 |
| `06-远控后门.md` | 远控后门处置线（EDR 定位 → 外连反查） | 定性为远控 |
| `07-勒索病毒.md` | 勒索病毒处置线（家族识别 → 解密） | 定性为勒索 |
| `08-暴力破解.md` | SSH/Mysql/FTP/Redis/Mongodb/smtp 爆破排查 | 定性为爆破 |
| `09-非持续性事件.md` | 域名/IP 劫持处置 | 定性为劫持 |
| `10-恶意软件包供应链攻击.md` | 恶意软件包供应链攻击处置 | 定性为供应链 |
| `11-隧道.md` | SSH/DNS/ICMP/HTTP(S)/Socks 隧道处置 | 定性为隧道 |
| `12-常规安全检查.md` | **39 项常规安全检查清单（全书最大亮点）** | 所有事件的「善后/全面排查」阶段 |
| `13-善后阶段.md` | 定损与针对性排查处理 | 处置收尾 |
| `14-常见问题的解决方法.md` | `ps/top` 看不到进程、`netstat` pid 显示 `-` 等坑 | 遇到误判时 |
| `15-小技巧.md` | 17 项（查文件/完整性/文件监控/数据恢复/history 时间等） | 具体操作技巧 |
| `16-知识点附录.md` | 守护进程/启动项/SSH 隧道/**与 C&C 隐藏技术对抗** | 深入原理与对抗面 |
| `SOURCE.md` | 来源与抓取说明 | 核对来源/许可 |

### logs/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `linux-log-analysis.md` | secure/auth.log、journald、auditd（ausearch/aureport）、bash history（HISTTIMEFORMAT/绕过检测）、last/lastb/wtmp/btmp、cron 日志、低噪声审计配置（308 行） | 需要从日志还原攻击痕迹 |

### process/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `hidden-process.md` | /proc 遍历 vs ps 对比、unhide、pspy、LD_PRELOAD/ld.so.preload 隐藏进程识别、挖矿进程特征（225 行） | 怀疑有隐藏进程或高 CPU 异常 |

### persistence/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `persistence-points.md` | cron 全位置、systemd、rc.local/profile/bashrc/init.d、authorized_keys、ssh config、PAM、环境变量/BASH 函数/alias、udev、Python .pth、TCP Wrappers、/etc/skel、motd——每项位置+命令+判据（279 行） | 找攻击者留下的持久化后门 |

### rootkit/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `so-backdoor-rootkit.md` | LD_PRELOAD/ld.so.preload/libc 篡改、动态链接器劫持检测（readelf/ldd/libc 完整性）、LKM（lsmod vs /proc/modules/签名）、eBPF rootkit 对抗、chkrootkit/rkhunter（217 行） | 怀疑 .so 后门或内核级隐藏 |

### webshell/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `webshell-detection.md` | nginx/apache access_log 特征（POST 可疑脚本/无 Referer/UA 异常/eval|base64_decode 关键词）、文件时间戳、上传目录、攻击 IP 溯源（184 行） | Web 服务器疑似被挂马 |

### malware/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `mining-ransomware-backdoor.md` | /proc/<pid>/exe 定样本、crontab 拉活链、外连 IP/端口、勒索家族识别与解密、远控定位链、恶意软件包供应链处置（254 行） | 定性挖矿/勒索/远控后走处置线 |

### attack-chain/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `attack-chain-reconstruction.md` | SSH 爆破失陷调查、时间线构建（mtime/ctime/atime+日志+进程启动交叉验证）、plaso 超级时间线、可疑 IP 溯源（whois/威胁情报）（184 行） | 需要还原完整攻击时序 |

### tools/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `tool-cards.md` | chkrootkit/rkhunter/Lynis/osquery/Falco/Sysdig/Velociraptor/unhide/pspy/auditd/LiME/AVML/Volatility3/plaso/ZLT 15 工具速查卡（215 行） | 应急现场选工具 |

### knowledge/（自写，1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `awesome-indexes.md` | awesome-incident-response、awesome-forensics、SigmaHQ（DRL 约束）、MITRE ATT&CK Linux Matrix 索引（45 行） | 需要外部知识库导航 |

## 计数

| 目录 | md 篇数 | 说明 |
|---|---|---|
| `cookbook-linux/` | 17 | 15 章全量原文 + 1 篇封面/更新日记合并简述 + SOURCE.md（另有 GPL-3.0 LICENSE 1 份，非 md） |
| `logs/` | 1 | 自写 |
| `process/` | 1 | 自写 |
| `persistence/` | 1 | 自写 |
| `rootkit/` | 1 | 自写 |
| `webshell/` | 1 | 自写 |
| `malware/` | 1 | 自写 |
| `attack-chain/` | 1 | 自写 |
| `tools/` | 1 | 自写 |
| `knowledge/` | 1 | 自写 |
| 根（本 README） | 1 | 索引 |
| **合计** | **27** | |

## 来源与说明

- **cookbook-linux/ 章节文件**：GPL-3.0 授权内容整理成文
  （https://book.noptrace.com/ ，GPL-3.0）。章节 1、3~16 共 15 章全量原文不改写（仅 HTML→Markdown
  结构转换），封面（0）与更新日记（2）合并为 1 篇简述；随附 GPL-3.0 LICENSE 与
  SOURCE.md（抓取说明 + 文件命名对照）。详见 `cookbook-linux/SOURCE.md`。
- **logs/process/persistence/rootkit/webshell/malware/attack-chain/tools/knowledge 共 9 篇**：
  自写原创实现级方法论（按主题域用命令级内容写成，
  未照抄受版权文章；来源 URL 放各文件文末「来源」节）。
- **Sigma 规则（SigmaHQ）**：受 DRL 约束，未整库拷贝，仅在 `knowledge/awesome-indexes.md` 引用外部来源。
- 本目录随预设打包分发；cookbook-linux 的 GPL-3.0 许可注记见各文件头部与 SOURCE.md。
- 与 playbook 的关系：速查卡（playbook）→ 深度手册（refs/linux/）→ 证据落盘（任务工作区）。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- Linux 系统通用路径（如 `/var/log/secure`、`/etc/ld.so.preload`、`/etc/crontab`）属排查对象本身，
  可正常出现；禁止的是本机用户目录（如 macOS `~/` 家目录）、Homebrew 安装目录等机器特定路径。
- cookbook 原文文件内部的相对链接指向在线版站点；按章节号在本目录检索同名文件即可。
- 生态边界：本目录收口 Linux 侧应急溯源；Windows 侧由 windows/ 目录对应；样本逆向交
  binary-analysis 模式；单点漏洞验证交 pentest 模式（各模式 refs 各自完整，跨模式按
  ecosystem-cooperation 规则协作）。
