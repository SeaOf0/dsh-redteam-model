# 攻击技术检测矩阵

> 定位：攻防评估「detection gap」判定的**可查表**——每条攻击技术应留下什么痕迹（Windows 事件 ID /
> Sysmon EventID / EDR 遥测行为 / 现成 Sigma 规则），按 ATT&CK T 编号对齐。
> 用法：防御验证员判定某条 finding「目标侧检测到没」时，先查本表对应行的「应留痕迹」，再核对目标侧
> SIEM/EDR 是否具备该日志来源与告警；缺日志来源或未告警 → 记为 gap 或「无法评估」。
> 覆盖范围：zh-intranet/ 11 篇 payload 主要类目 + offensive/ 域攻防主链。
> 结构：检测侧配对到字段/阈值/规则级，不止名词。

---

## 一、域侦察与枚举

| 攻击技术 | ATT&CK | Windows 事件 ID | Sysmon EventID | EDR 遥测行为 | Sigma 规则（现成/命名） |
|---|---|---|---|---|---|
| LDAP/AD 枚举（BloodHound/PowerView） | T1018/T1087 | 4662（LDAP 读，需 SACL） | 3（LDAP 连接） | 单源高频 LDAP 查询、读取大量对象属性 | `win_ad_ldap_recon` / PowerView 命令模式 |
| SPN 枚举（Kerberoasting 前置） | T1558.003 | 4769（RC4 加密类型） | 3 | 高频 TGS-REQ、RC4_HMAC 加密类型 | `win_susp_spn_enum` |
| 网络/共享枚举（NetExec --shares） | T1018/T1135 | 4624(LogonType 3) + 5140 | 3 | 批量 SMB 连接、共享访问 | `win_smb_share_enum` |
| 端口扫描 | T1046 | — | 3（多目标 SYN） | 单源多目标连接突发 | `win_susp_scan` |

## 二、凭证访问（Kerberos/NTLM）

| 攻击技术 | ATT&CK | Windows 事件 ID | Sysmon EventID | EDR 遥测行为 | Sigma 规则 |
|---|---|---|---|---|---|
| Kerberoasting | T1558.003 | 4769（RC4 + 非服务主体现） | 3 | TGS-REQ 用 RC4_HMAC，目标 SPN 异常 | `win_security_susp_kerberoasting` |
| AS-REP Roasting | T1558.004 | 4768（无预认证） | — | TGT 请求无 PA-ENC-TIMESTAMP | `win_security_asreproasting` |
| DCSync | T1003.006 | 4662（`DS-Replication-Get-Changes`）+ 4663 | 3 | 非 DC 主机发起目录复制 | `win_security_dcsync` |
| 黄金/白银票据 | T1558.001/002 | 4768（票据 TTL/字段异常） | — | 票据生命周期超长、PAC 异常 | `win_security_susp_golden_ticket` |
| PTH | T1550.002 | 4624(LogonType 3, NTLM) + 4776 | 10（访问 LSASS） | 同一 NT 哈希多主机登录、`NTLMSSP` 无 Kerberos | `win_susp_pass_the_hash` |
| PTT/Overpass | T1550.003 | 4768/4769（票据来源异常） | 10 | Kerberos 票据注入、`kerberos::ptt` | `win_susp_pass_the_ticket` |
| NTLM Relay | T1557 | 4624(LogonType 3) + 4776 + 4648 | 3 | 认证中继、源 IP 与目标不匹配 | `win_ntlm_relay` |
| 强制认证（Coercion） | T1187 | 4648（显式凭据）+ 4624 | 3 | 异常 RPC 调用（EFSRPC/RPRN） | `win_susp_coercer` |

## 三、凭证转储（主机侧）

| 攻击技术 | ATT&CK | Windows 事件 ID | Sysmon EventID | EDR 遥测行为 | Sigma 规则 |
|---|---|---|---|---|---|
| LSASS dump（mimikatz/comsvcs/nanodump） | T1003.001 | 4663（LSASS 句柄）+ 4656 | 10（访问 lsass.exe） | 非白名单进程打开 lsass 句柄、`sekurlsa` 调用 | `win_susp_lsass_dump` |
| SAM dump（reg save/VSS） | T1003.002 | 4663（SAM 句柄） | 11（写 SAM 副本） | 注册表 hive 导出、vssadmin 调用 | `win_susp_reg_save_sam` |
| NTDS.dit dump | T1003.003 | 4662 + 4663 | 11 | ntdsutil/vssadmin 执行、复制 ntds.dit | `win_susp_ntds_dump` |
| LSA Secrets（secretsdump） | T1003.004 | 4663（LSA） | 10 | 读取 LSA 密钥 | `win_susp_lsa_secrets` |
| DPAPI 解密（SharpDPAPI/DonPAPI） | T1555.004 | 5379（凭据管理器读取）+ 4663 | 10/13 | CryptUnprotectData、读取 Credentials 目录 | `win_susp_dpapi_abuse` |
| 浏览器凭据（HackBrowserData/SharpWeb） | T1555.003 | 4663（Login Data 句柄） | 11（访问 Login Data/Cookies） | 非浏览器进程读取浏览器数据文件 | `win_susp_browser_cred` |

## 四、横向移动

| 攻击技术 | ATT&CK | Windows 事件 ID | Sysmon EventID | EDR 遥测行为 | Sigma 规则 |
|---|---|---|---|---|---|
| PsExec/SMBExec | T1021.002 | 4624(LogonType 3) + 7045（服务安装） | 1（`PsExec.exe`/`services.exe` 子进程） | 远程服务创建 + `-r` 命名服务 | `win_susp_psexec` |
| WMIExec | T1021.001 | 4624 + 4688 | 1（wmiprvse.exe 启动 cmd） | WMI 进程启动远程命令 | `win_susp_wmi_exec` |
| DCOMExec | T1021.003 | 4624 | 1（dllhost.exe 异常） | DCOM 对象实例化远程执行 | `win_susp_dcom_exec` |
| WinRM/PSRemoting | T1021.006 | 4624 + 4648 | 1（wsmprovhost.exe） | WinRM 远程会话、PSSession | `win_susp_winrm` |
| RDP 劫持/登录 | T1021.001 | 4624(LogonType 10) + 4778 | 1 | RDP 会话建立、`tscon` 劫持 | `win_susp_rdp` |
| SSH 横向（Linux） | T1021.004 | —（Linux 侧） | 3 | 单源多目标 SSH 登录 | `linux_susp_ssh_lateral` |

## 五、持久化

| 攻击技术 | ATT&CK | Windows 事件 ID | Sysmon EventID | EDR 遥测行为 | Sigma 规则 |
|---|---|---|---|---|---|
| 注册表 Run/Userinit | T1547.001 | 4657（注册表修改） | 13 | Run/RunOnce/Userinit 键写入 | `win_susp_reg_run` |
| WMI 事件订阅 | T1546.003 | — | 19/20/21（WMI 事件） | 新建 `__EventConsumer` | `win_susp_wmi_consumer` |
| 计划任务 | T1053 | 4698（计划任务创建） | 1（schtasks） | schtasks/`Register-ScheduledTask` | `win_susp_schtask` |
| 服务创建/修改 | T1543.003 | 7045（服务安装） | 6（驱动加载）/1 | `sc create` 异常 binPath | `win_susp_service_create` |
| COM 劫持 | T1546.015 | 4657（CLSID 注册表修改） | 13 | `InprocServer32` 指向异常 DLL | `win_susp_com_hijack` |
| Skeleton Key | T1556.001 | 4611（LSASS 内存修改） | 10 | lsass 进程内存写入 | `win_susp_skeleton_key` |
| DSRM 后门 | T1098 | 4740 + 4624 | — | DSRM 账户登录 | `win_susp_dsrm` |
| AdminSDHolder/SDProp | T1098 | 5136（AdminSDHolder 修改） | — | 60 分钟内批量 ACL 传播 | `win_ad_adminsdholder_mod` |

## 六、AD CS（证书服务）

| 攻击技术 | ATT&CK | Windows 事件 ID | Sysmon EventID | EDR 遥测行为 | Sigma 规则 |
|---|---|---|---|---|---|
| ESC1（SAN 指定） | T1649 | 4887（证书颁发） | 1（certreq） | 请求管理员 UPN 的证书 | `win_adcs_esc1` |
| ESC8（中继） | T1649 | 4887 + 4624 | 3 | HTTP 证书端点认证 + NTLM 中继 | `win_adcs_esc8` |
| ESC16（无 SID 扩展） | T1649 | 4887（证书无 SID） | — | 颁发证书缺少 SID 扩展 | `win_adcs_esc16` |
| 证书模板修改（ESC4） | T1649 | 5136（模板对象修改） | — | `mspki-certificate-name-flag` 变更 | `win_adcs_esc4` |

## 七、检测工程要点（把表落地成判定）

1. **先核日志来源**：Windows 安全日志需开启「进程创建(4688)」「对象访问(4662/4663 + SACL)」「目录服务变更(5136)」；Sysmon 需部署默认配置（含 Event 1/3/10/11/13）。
2. **字段级阈值示例**：Kerberoasting 看 `4769` 中 `TicketEncryptionType=0x17(RC4)` 且 `ServiceName` 非白名单；DCSync 看 `4662` 中 `AccessMask` 含 `Control Access` + `Properties` 含 `DS-Replication-Get-Changes`。
3. **EDR 遥测行为是兜底**：事件日志缺失时，靠 EDR 的「进程访问 lsass / 注册表 Run 键写入 / 异常服务创建」行为告警判定。
4. **gap 判定**：目标侧「无该日志来源」或「有日志但无对应告警规则」→ 记 gap；「无法拿到日志权限」→ 记「无法评估」。

## 参考

- ATT&CK：T1003（OS Credential Dumping）、T1558（Steal or Forge Kerberos Tickets）、T1550（Use Alternate Authentication Material）、T1557（Adversary-in-the-Middle）、T1021（Remote Services）、T1547/T1546/T1053（Persistence）、T1649（Steal or Forge Authentication Certificates）。
- Sigma 规则库（SigmaHQ）：<https://github.com/SigmaHQ/sigma>
- Sysmon 事件参考：<https://learn.microsoft.com/sysinternals/downloads/sysmon>
