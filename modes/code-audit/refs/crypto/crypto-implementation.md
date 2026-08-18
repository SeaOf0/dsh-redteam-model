---
name: crypto-implementation
description: >
  完整的密码学安全实现与工程手册。涵盖 AES-256-GCM 静态加密、Ed25519 数字签名、
  TLS 1.3 安全配置、双向 TLS (mTLS) 部署、密码学应用审计方法论、
  后量子密码迁移 (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+)。
  包含侧信道攻击、Padding Oracle、证书伪造、量子威胁时间线等攻击视角，
  以及完整的防御实现代码和审计检查清单。
domain: cybersecurity
subdomain: cryptography
tags: [aes-256-gcm, ed25519, tls-1.3, mtls, crypto-audit, post-quantum, kyber, dilithium, encryption-at-rest, side-channel, padding-oracle]
version: 2.0.0
---

# 密码学实现与工程 — 完整攻防手册

## 适用场景

- 需要为应用数据设计静态加密方案 (AES-256-GCM)
- 需要实现数字签名与验证 (Ed25519)
- 需要配置或加固 TLS 1.3 / mTLS 通信安全
- 需要对应用进行密码学审计
- 需要规划后量子密码学 (PQC) 迁移路线
- 评估现有加密实现是否存在侧信道、填充预言等漏洞

---

## Part A：攻击方法论

### 1. 对称加密攻击

#### 1.1 Padding Oracle Attack

```
攻击条件：服务端对 CBC 模式密文解密后泄露 padding 是否有效
影响：无需密钥即可恢复完整明文

CBC Padding Oracle 流程：
1. 修改密文块 C[i] 的前一密文块 C[i-1]
2. 发送修改后的密文给服务端
3. 根据 padding 验证结果（有效/无效）推断中间值
4. 逐字节恢复所有明文块

检测向量：
- HTTP 状态码差异 (200 vs 500)
- 错误消息差异 ("padding error" vs "MAC error")
- 响应时间差异（计时侧信道）
```

```python
# Padding Oracle 攻击检测脚本
import requests
import base64

def detect_padding_oracle(url, ciphertext_b64):
    """检测目标是否存在 padding oracle"""
    ct_bytes = base64.b64decode(ciphertext_b64)
    results = {"valid": 0, "invalid": 0, "error": 0}

    for i in range(256):
        modified = bytearray(ct_bytes)
        modified[0] ^= i  # 修改第一字节
        try:
            r = requests.post(url, data={"ct": base64.b64encode(bytes(modified))})
            if r.status_code == 200:
                results["valid"] += 1
            elif r.status_code == 400:
                results["invalid"] += 1
            else:
                results["error"] += 1
        except:
            results["error"] += 1

    # 如果响应有明确区分 → 存在 padding oracle
    return results["valid"] > 0 and results["invalid"] > 0
```

#### 1.2 ECB 模式攻击 ( Penguin Attack )

```
ECB 模式弱点：
- 相同明文块 → 相同密文块（无扩散）
- 可识别图像模式（ECB企鹅）
- 块重排攻击：重新排列密文块改变明文结构

检测方法：
1. 加密重复明文 "AAAAAAAAAAAAAAAA" (16字节)
2. 观察密文是否出现重复块
3. 重复块出现 → ECB 模式确认
```

#### 1.3 IV/Nonce 重用攻击 (CTR/GCM)

```
GCM Nonce 重用后果：
- 认证标签完全失效（可伪造任意消息）
- 明文可被 XOR 恢复

攻击场景：
- 两个密文 C1, C2 使用相同 key+nonce
- C1 XOR C2 = P1 XOR P2（明文 XOR）
- 已知任一明文即可恢复另一明文

检测：审计 nonce 生成逻辑
- 随机 nonce → 检查是否有碰撞概率问题
- 计数器 nonce → 检查是否在密钥轮转后重置
```

### 2. 侧信道攻击

#### 2.1 计时攻击

```python
# 不安全的字符串比较（易受计时攻击）
def insecure_compare(a, b):
    for x, y in zip(a, b):
        if x != y:
            return False  # 第一次不匹配立即返回 → 泄露位置
    return True

# HMAC 计时攻击流程：
# 1. 发送请求，测量响应时间
# 2. 逐字节猜测 HMAC 标签
# 3. 正确字节 → 多一轮比较 → 时间略长
# 4. 统计分析恢复完整 HMAC

# 防御：恒定时间比较
import hmac
def secure_compare(a, b):
    return hmac.compare_digest(a, b)
```

#### 2.2 功耗/电磁侧信道 (DPA/CPA)

```
攻击目标：智能卡、HSM、嵌入式设备中的密钥
方法：
- 差分功耗分析 (DPA)：采集大量功耗轨迹，统计关联恢复密钥位
- 相关功耗分析 (CPA)：利用 Hamming Weight/Distance 模型
- 电磁辐射分析：近场探头采集 EM 信号

防御措施：
- 掩码 (Masking)：随机化中间值
- 隐藏 (Hiding)：恒定时间执行、随机时延
- Shuffling：随机化操作顺序
```

### 3. 证书与 TLS 攻击

#### 3.1 证书伪造与chain攻击

```bash
# 检测证书链验证漏洞
# 1. 自签名证书替换测试
openssl req -x509 -newkey rsa:2048 -keyout fake.key -out fake.crt \
    -days 365 -subj "/CN=target.com"

# 2. 中间CA伪造（需要CA私钥泄露场景）
# 3. 证书链不完整验证测试
curl --cacert fake.crt https://target.com -v 2>&1 | grep "verify"

# 4. 检查证书pinning实现
# Android: 检查 NetworkSecurityConfig
# iOS: 检查 ATS 和 certificate pinning
```

#### 3.2 TLS 降级攻击

```bash
# 测试是否允许 TLS 1.0/1.1（已废弃协议）
nmap --script ssl-enum-ciphers -p 443 target.com

# 测试是否强制 TLS 1.3
openssl s_client -connect target.com:443 -tls1_3

# 检查是否存在协议降级漏洞 (POODLE/BEAST 等)
testssl.sh --protocols target.com:443
```

#### 3.3 mTLS 绕过

```bash
# 1. 无客户端证书测试（服务端是否强制要求）
curl -k https://mtls-target.com/api/secure -v

# 2. 自签名客户端证书测试
openssl req -new -x509 -key client.key -out client.crt \
    -subj "/CN=spoofed-user"
curl --cert client.crt --key client.key https://mtls-target.com/

# 3. 过期/吊销证书测试
# 检查 CRL/OCSP 验证是否生效

# 4. 证书主体伪造
# CN=admin vs CN=user → RBAC 是否依赖证书字段
```

### 4. 量子威胁时间线

```
量子计算对密码学的威胁等级：

┌─────────────────────┬──────────────┬─────────────────────────┐
│ 算法类型             │ 量子威胁     │ 时间估计                │
├─────────────────────┼──────────────┼─────────────────────────┤
│ RSA-2048            │ Shor算法破解 │ ~4096 逻辑量子比特      │
│ ECDSA/ECDH (P-256)  │ Shor算法破解 │ ~2330 逻辑量子比特      │
│ AES-128             │ Grover搜索   │ 密钥空间降为 2^64       │
│ AES-256             │ Grover搜索   │ 密钥空间降为 2^128(安全)│
│ SHA-256             │ Grover搜索   │ 碰撞降为 2^128(可接受)  │
│ Ed25519             │ Shor算法破解 │ 同ECDSA                 │
└─────────────────────┴──────────────┴─────────────────────────┘

"Store Now, Decrypt Later" (SNDL) 威胁：
- 攻击者现在窃取加密数据，等量子计算机成熟后解密
- 影响需要长期保密的数据（>10年）：医疗、国防、金融

NIST PQC 标准化结果 (2024)：
- FIPS 203: ML-KEM (Kyber) — 密钥封装
- FIPS 204: ML-DSA (Dilithium) — 数字签名
- FIPS 205: SLH-DSA (SPHINCS+) — 无状态哈希签名
```

---

## Part B：检测与防御

### 5. AES-256-GCM 静态加密实现

#### 5.1 正确实现模式

```python
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode

class SecureEncryption:
    """生产级 AES-256-GCM 静态加密"""

    def __init__(self, master_key: bytes = None):
        if master_key:
            self.key = master_key
        else:
            self.key = AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> dict:
        """加密数据，返回可序列化的密文包"""
        nonce = os.urandom(12)  # GCM 推荐 96-bit nonce
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        return {
            "alg": "AES-256-GCM",
            "nonce": b64encode(nonce).decode(),
            "ct": b64encode(ciphertext).decode(),
            "aad": b64encode(aad).decode(),
            "version": 1  # 密钥版本号，支持密钥轮转
        }

    def decrypt(self, encrypted_package: dict) -> bytes:
        """解密数据"""
        nonce = b64decode(encrypted_package["nonce"])
        ciphertext = b64decode(encrypted_package["ct"])
        aad = b64decode(encrypted_package.get("aad", ""))
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, aad)

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
        """从密码派生密钥 (PBKDF2)"""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,  # OWASP 2023 推荐
        )
        key = kdf.derive(password.encode())
        return key, salt
```

#### 5.2 密钥管理架构

```yaml
# 密钥管理层次结构 (Key Hierarchy)
密钥管理:
  L0_主密钥:
    存储: HSM / Cloud KMS (AWS KMS, Azure Key Vault, GCP KMS)
    用途: 加密 L1 密钥
    轮转: 每年

  L1_密钥加密密钥(KEK):
    存储: 加密后存储在数据库
    用途: 加密 L2 数据加密密钥
    轮转: 每季度

  L2_数据加密密钥(DEK):
    存储: 加密后与数据同存储
    用途: 直接加密业务数据
    轮转: 每月或每 N 次加密操作

密钥轮转流程:
  1. 生成新 DEK
  2. 新数据使用新 DEK 加密
  3. 旧 DEK 仅用于解密（标记为只读）
  4. 后台异步重加密旧数据到新 DEK
  5. 验证完成后安全擦除旧 DEK
```

### 6. Ed25519 数字签名

#### 6.1 签名与验证

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

class SecureSigner:
    """Ed25519 数字签名实现"""

    def __init__(self, private_key_pem: bytes = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem, password=None
            )
        else:
            self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign(self, message: bytes) -> bytes:
        """签名消息（64字节签名）"""
        return self.private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """验证签名"""
        try:
            self.public_key.verify(signature, message)
            return True
        except Exception:
            return False

    def export_public_key(self) -> bytes:
        """导出公钥 PEM"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def export_private_key(self, password: bytes = None) -> bytes:
        """导出私钥 PEM（推荐加密）"""
        enc = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        )
```

#### 6.2 签名方案选择矩阵

```
┌──────────────┬──────────┬───────────┬────────────┬──────────────────────┐
│ 算法         │ 签名大小 │ 公钥大小  │ 验证速度   │ 适用场景             │
├──────────────┼──────────┼───────────┼────────────┼──────────────────────┤
│ Ed25519      │ 64 B     │ 32 B      │ 极快       │ 通用签名、JWT、SSH   │
│ ECDSA P-256  │ 64 B     │ 33 B      │ 快         │ TLS证书、FIPS合规    │
│ RSA-2048     │ 256 B    │ 256 B     │ 慢         │ 兼容旧系统、代码签名 │
│ RSA-4096     │ 512 B    │ 512 B     │ 更慢       │ 长期安全             │
│ ML-DSA-65    │ 3309 B   │ 1952 B    │ 中等       │ 后量子签名(主)       │
│ SLH-DSA-128f │ 17088 B  │ 32 B      │ 快         │ 后量子签名(备用)     │
└──────────────┴──────────┴───────────┴────────────┴──────────────────────┘
```

### 7. TLS 1.3 安全配置

#### 7.1 Nginx TLS 1.3 配置

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    # TLS 1.3 only
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;

    # TLS 1.3 cipher suites (服务端偏好)
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;

    # 证书配置
    ssl_certificate     /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;

    # 会话配置
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;  # 前向保密：禁用 session ticket

    # 安全头
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # 0-RTT 配置（谨慎启用）
    # ssl_early_data off;  # 默认关闭，防止重放攻击
}
```

#### 7.2 TLS 1.3 握手流程

```
标准 TLS 1.3 握手 (1-RTT):

ClientHello
  → supported_versions: TLS 1.3
  → key_share: (X25519/ECDH 公钥)
  → signature_algorithms: ed25519,ecdsa_secp256r1
← ServerHello
  → key_share: (服务端ECDH公钥)
  → [EncryptedExtensions]
  → [Certificate]
  → [CertificateVerify]
  → [Finished]
→ [Finished]
  ← Application Data (加密)

TLS 1.3 改进：
- 完全加密握手（除 ClientHello/ServerHello）
- 移除 RSA 密钥交换 → 仅支持 (EC)DHE
- 移除自定义 DH 参数 → 仅支持内置命名组
- 1-RTT 握手 (TLS 1.2 需要 2-RTT)
- 0-RTT 可选（有重放风险，需谨慎）
```

### 8. mTLS 双向认证配置

#### 8.1 证书体系搭建

```bash
#!/bin/bash
# mTLS 证书体系生成脚本

# 1. 根 CA
openssl genpkey -algorithm ED25519 -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 \
    -subj "/CN=MyOrg Root CA"

# 2. 服务端证书
openssl genpkey -algorithm ED25519 -out server.key
openssl req -new -key server.key -out server.csr \
    -subj "/CN=service.internal"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365 \
    -extfile <(echo "subjectAltName=DNS:service.internal,DNS:api.example.com")

# 3. 客户端证书（每个客户端/服务一个）
openssl genpkey -algorithm ED25519 -out client1.key
openssl req -new -key client1.key -out client1.csr \
    -subj "/CN=client-service-1"
openssl x509 -req -in client1.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client1.crt -days 90

# 4. 验证证书链
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client1.crt
```

#### 8.2 服务端 mTLS 配置 (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/ssl/server.crt;
    ssl_certificate_key /etc/ssl/server.key;
    ssl_protocols       TLSv1.3;

    # mTLS: 客户端证书验证
    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client on;        # 强制客户端证书
    ssl_verify_depth 2;

    # 将客户端证书信息传递给后端
    proxy_set_header X-Client-CN $ssl_client_s_dn;
    proxy_set_header X-Client-Verify $ssl_client_verify;
    proxy_set_header X-Client-Fingerprint $ssl_client_fingerprint;

    location /api/ {
        # 后端可基于 X-Client-CN 做 RBAC
        proxy_pass http://backend:8080;
    }
}
```

#### 8.3 mTLS 密钥轮转与吊销

```yaml
mTLS 运维:
  证书吊销:
    - CRL: 定期下载证书吊销列表
    - OCSP: 实时查询证书状态（推荐）
    - 短有效期: 证书有效期 < 90天，依赖自动轮转

  自动轮转 (cert-manager / Vault):
    - cert-manager + Kubernetes: 自动签发和轮转
    - HashiCorp Vault PKI: 动态证书签发
    - SPIFFE/SPIRE: 工作负载身份框架

  监控指标:
    - 证书过期倒计时 (alert < 14天)
    - 客户端证书验证失败率
    - OCSP/CRL 更新状态
```

### 9. 密码学审计方法论

#### 9.1 审计检查清单

```markdown
## 密码学审计框架

### A. 算法选择审计
- [ ] 是否使用已废弃算法 (DES, 3DES, RC4, MD5, SHA-1)
- [ ] 对称加密是否使用认证加密模式 (GCM/CCM/ChaCha20-Poly1305)
- [ ] 密钥长度是否达标 (AES ≥ 256, RSA ≥ 2048, ECC ≥ 256)
- [ ] 是否使用已证明安全的曲线 (X25519, P-256, Ed25519)
- [ ] 随机数生成器是否使用 CSPRNG (/dev/urandom, java.security.SecureRandom)

### B. 实现审计
- [ ] 是否存在硬编码密钥/密码
- [ ] IV/Nonce 生成是否正确（不重用、足够长度）
- [ ] 是否使用恒定时间比较（防计时攻击）
- [ ] 错误消息是否泄露密码学细节
- [ ] 密钥是否在内存中安全清零 (secure zeroing)

### C. 密钥管理审计
- [ ] 密钥是否使用 KMS/HSM 管理
- [ ] 密钥轮转策略是否就位
- [ ] 密钥分发是否使用安全通道
- [ ] 密钥备份和恢复流程是否安全
- [ ] 退役密钥是否安全销毁

### D. TLS 配置审计
- [ ] 是否禁用 TLS 1.0/1.1
- [ ] 是否优先使用 TLS 1.3
- [ ] 证书链验证是否完整
- [ ] 证书吊销检查是否启用 (OCSP/CRL)
- [ ] HSTS 是否配置且包含预加载

### E. 证书管理审计
- [ ] 私钥保护是否充分（文件权限、加密存储）
- [ ] 证书有效期是否合理（≤ 90天推荐）
- [ ] SAN 配置是否正确
- [ ] CA信任链是否最小化

### F. 侧信道抵抗审计
- [ ] 密码比较是否使用 hmac.compare_digest / ConstantTimeCompare
- [ ] 加密操作执行时间是否恒定
- [ ] 是否防御功耗分析 (HSM/TEE)
- [ ] 日志中是否避免记录敏感密码学材料
```

#### 9.2 自动化审计工具

```bash
# TLS 配置扫描
testssl.sh --full --openssl --severity LOW target.com:443

# 证书透明度日志检查
curl -s "https://crt.sh/?q=example.com&output=json" | jq '.[].name_value' | sort -u

# 密码学漏洞扫描 (nmap)
nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,sslv2 -p 443 target.com

# 代码中硬编码密钥检测
grep -rn "password\s*=" --include="*.py" --include="*.java" --include="*.go" .
trufflehog filesystem ./src/
detect-secrets scan ./src/

# SSH 配置审计
ssh-audit target.com

# 密码库版本检查（已知漏洞）
# OpenSSL: openssl version → 对照 CVE 数据库
# BoringSSL: 检查构建版本
# libgcrypt: rpm -q libgcrypt / dpkg -l libgcrypt
```

### 10. 后量子密码学 (PQC) 迁移

#### 10.1 NIST PQC 标准算法

```
┌────────────────────────┬────────────┬───────────────┬─────────────────────────┐
│ NIST 标准              │ 原始算法   │ 类型          │ 关键参数                │
├────────────────────────┼────────────┼───────────────┼─────────────────────────┤
│ FIPS 203 ML-KEM-768    │ Kyber      │ 密钥封装(KEM) │ 公钥1184B, 密文1088B    │
│ FIPS 204 ML-DSA-65     │ Dilithium  │ 数字签名      │ 公钥1952B, 签名3309B    │
│ FIPS 205 SLH-DSA-128f  │ SPHINCS+   │ 哈希签名(备用)│ 公钥32B, 签名17088B     │
└────────────────────────┴────────────┴───────────────┴─────────────────────────┘

混合策略（过渡期推荐）：
- 密钥交换: X25519 + ML-KEM-768 (复合)
- 签名: Ed25519 + ML-DSA-65 (复合)
- 浏览器支持: Chrome 124+, Firefox 128+ 已支持 X25519Kyber768
```

#### 10.2 PQC 迁移路线图

```yaml
PQC迁移阶段:

  Phase1_发现 (0-3个月):
    - 密码学资产清单：所有使用公钥密码的位置
    - 数据分类：按保密期 >10年 / <10年 分级
    - 依赖映射：密码库、TLS库、HSM 固件版本
    - 风险评估：SNDL 威胁优先级排序

  Phase2_准备 (3-9个月):
    - 升级密码库到 PQC 支持版本
      - OpenSSL 3.5+ (ML-KEM/ML-DSA)
      - BoringSSL (Kyber 支持)
      - liboqs (Open Quantum Safe)
    - 建立 PQC 测试环境
    - 性能基准测试（握手延迟、吞吐量影响）
    - 证书基础设施升级 (PKI 支持 PQC)

  Phase3_试点 (9-15个月):
    - 混合模式部署: 经典 + PQC 组合
    - TLS 混合密钥交换 (X25519+ML-KEM)
    - 内部 mTLS 先迁移
    - 监控兼容性问题

  Phase4_全面部署 (15-24个月):
    - 外部 TLS 迁移到混合模式
    - 代码签名迁移到 ML-DSA
    - 文档签名迁移
    - HSM 固件升级

  Phase5_经典算法退役 (24-36个月):
    - 禁用纯经典密钥交换
    - 证书策略要求 PQC
    - 审计验证 100% PQC 覆盖
```

#### 10.3 PQC 代码示例 (liboqs)

```python
# 使用 liboqs-python 进行后量子密钥封装
# pip install liboqs

import oqs

def ml_kem_keygen():
    """ML-KEM-768 (Kyber) 密钥生成与封装"""
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        public_key = kem.generate_keypair()
        # 封装：生成共享密钥和密文
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return {
            "public_key": public_key.hex(),
            "ciphertext": ciphertext.hex(),
            "shared_secret": shared_secret.hex(),
            "algorithm": "ML-KEM-768"
        }

def ml_kem_decap(ciphertext_hex, private_key_context):
    """ML-KEM-768 解封装"""
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        shared_secret = kem.decap_secret(bytes.fromhex(ciphertext_hex))
        return shared_secret

# 混合密钥交换: X25519 + ML-KEM-768
def hybrid_key_exchange():
    """经典 + 后量子混合密钥交换"""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    # 经典 X25519
    classic_key = X25519PrivateKey.generate()
    classic_pub = classic_key.public_key()

    # 后量子 ML-KEM-768
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pq_pub = kem.generate_keypair()
        pq_ct, pq_secret = kem.encap_secret(pq_pub)

    # 混合共享密钥 = KDF(经典共享 || 后量子共享)
    # 任一算法安全则整体安全
    return {
        "classic_pub": classic_pub,
        "pq_pub": pq_pub.hex(),
        "pq_ct": pq_ct.hex(),
        "combined_secret": pq_secret  # 简化，实际应 KDF 合并两者
    }
```

---

## 速查表

### 算法选择速查

```
┌─────────────────────┬──────────────────────┬──────────────────────┐
│ 用途                │ 当前推荐             │ 后量子推荐           │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ 静态加密            │ AES-256-GCM          │ AES-256-GCM (不变)   │
│ 流加密              │ ChaCha20-Poly1305    │ 同左                 │
│ 密钥交换            │ X25519               │ X25519+ML-KEM-768    │
│ 数字签名            │ Ed25519              │ Ed25519+ML-DSA-65    │
│ 哈希                │ SHA-256 / SHA-3      │ 同左                 │
│ 密码派生            │ Argon2id / PBKDF2    │ 同左                 │
│ HMAC                │ HMAC-SHA256          │ 同左                 │
│ 证书签名            │ ECDSA P-256          │ ML-DSA-65 (待CA支持) │
└─────────────────────┴──────────────────────┴──────────────────────┘
```

### TLS 1.3 Cipher Suites

```
强制套件 (TLS 1.3 仅 5 个):
  TLS_AES_128_GCM_SHA256       ← 最低要求
  TLS_AES_256_GCM_SHA384       ← 推荐
  TLS_CHACHA20_POLY1305_SHA256 ← 移动端友好
  TLS_AES_128_CCM_SHA256       ← IoT 场景
  TLS_AES_128_CCM_8_SHA256     ← 低带宽场景

命名组 (Key Exchange):
  x25519        ← 首选 ( fastest )
  secp256r1     ← 兼容
  ffdhe2048+    ← 仅兼容，不推荐

签名算法:
  ed25519           ← 首选
  ecdsa_secp256r1   ← FIPS 合规
  rsa_pss_rsae_sha256 ← 兼容
```

### 密码学审计 CLI 速查

```bash
# TLS 全面扫描
testssl.sh --full target.com:443

# SSH 审计
ssh-audit target.com

# 证书透明度查询
curl -s "https://crt.sh/?q=TARGET&output=json" | jq '.[].name_value' | sort -u

# 硬编码密钥检测
trufflehog filesystem ./src/
detect-secrets scan --list-all-plugins

# OpenSSL 版本检查
openssl version -a  # 对照 CVE

# 证书信息提取
openssl x509 -in cert.pem -text -noout | grep -E "Issuer|Subject|Not|Algorithm"

# 生成密码学安全随机数
openssl rand -hex 32     # 256-bit 密钥
openssl rand -base64 16  # 128-bit token
```

### PQC 迁移优先级矩阵

```
┌──────────────────────────┬───────────────┬────────────────────────────────┐
│ 系统类型                 │ 迁移优先级    │ 原因                           │
├──────────────────────────┼───────────────┼────────────────────────────────┤
│ 长期归档数据 (>10年)     │ P0 立即       │ SNDL 威胁最大                  │
│ TLS 前端 (面向公网)      │ P1 高         │ 浏览器已开始支持               │
│ 内部 mTLS (微服务)       │ P1 高         │ 可控环境，易迁移               │
│ SSH 基础设施访问         │ P2 中         │ OpenSSH 9.x 已支持             │
│ 代码/工件签名            │ P2 中         │ 需要工具链支持                 │
│ VPN/WireGuard            │ P3 低         │ 对称密码为主，量子影响小       │
│ 磁盘加密 (LUKS/BitLocker)│ P3 低         │ 对称密码，Grover影响可接受     │
└──────────────────────────┴───────────────┴────────────────────────────────┘
```

---

## MITRE ATT&CK 映射

```
攻击技术:
  T1040  Network Sniffing          — 捕获未加密/TLS弱配置流量
  T1119  Automated Collection      — 批量窃取加密数据 (SNDL)
  T1573  Encrypted Channel         — 攻击者使用加密通信规避检测
  T1600  Weaken Encryption         — 降级加密强度（协议降级攻击）
  T1145  Private Keys              — 窃取私钥/证书

防御技术:
  D3-PLA Protocol Analysis         — TLS 流量分析检测异常
  D3-NTA Network Traffic Analysis  — 密码学异常行为检测
  M1041  Encrypt Sensitive Data    — 静态加密（AES-256-GCM）
  M1042  Disable/Remove Feature    — 禁用旧TLS版本
  M1054  Compromise Hardening       — mTLS 零信任网络分段
  M1071  Least Functionality        — 仅启用强密码套件
```

---

## 前置条件

```
工具:
  - OpenSSL 3.x+ (TLS/PQC支持)
  - testssl.sh (TLS审计)
  - ssh-audit (SSH审计)
  - trufflehog / detect-secrets (密钥泄露检测)
  - liboqs + oqs-provider (PQC开发)
  - Python cryptography 库

知识:
  - 对称加密基础 (AES, GCM, CBC)
  - 非对称加密基础 (RSA, ECC, Ed25519)
  - TLS 握手流程
  - PKI 证书体系
  - 后量子密码基础概念

环境:
  - 目标应用源码访问权限（代码审计）
  - 网络访问权限（TLS测试）
  - 密钥管理服务访问权限（KMS审计）
```

---

## Part C：2025-2026 工程前沿补充

> 本章为联网复核新增（数据截至 2026-06-13）。涵盖 OpenSSL 4.0 GA、AI 辅助密码学挖掘、PQC 落地实测、最新 CVE 深度分析、工具生态、中文社区精华、防御升级路线图。
> 与 [[crypto-attacks]] 互补：crypto-attacks 侧重"密码分析侧"（Coppersmith/Marvin/PQC 攻击），本文档侧重"工程实现侧"（库版本、配置、迁移、审计）。

---

### C.1 OpenSSL 4.0 GA 与版本矩阵（2026-06 实测）

#### C.1.1 OpenSSL 主线版本矩阵（截至 2026-06-09）

```
┌────────────┬──────────┬───────────────┬───────────────┬──────────────────────────┐
│ 系列       │ 最新版本 │ 发布日期      │ EOL           │ 关键定位                 │
├────────────┼──────────┼───────────────┼───────────────┼──────────────────────────┤
│ 4.0        │ 4.0.1    │ 2026-06-09    │ 2027-05-14    │ 新主线（2026-04-14 GA）  │
│ 3.6        │ 3.6.3    │ 2026-06-09    │ 2026-11-01    │ 过渡版                   │
│ 3.5 [LTS]  │ 3.5.7    │ 2026-06-09    │ 2030-04-08    │ 当前 LTS（推荐）        │
│ 3.4        │ 3.4.6    │ 2026-06-09    │ 2026-10-22    │ 维护                     │
│ 3.0 [LTS]  │ 3.0.21   │ 2026-06-09    │ 2026-09-07    │ 旧 LTS 即将 EOL         │
└────────────┴──────────┴───────────────┴───────────────┴──────────────────────────┘

FIPS 验证版本（重要）:
┌────────────┬───────────────┬────────────────────────────────────────────────┐
│ 版本       │ 证书          │ 备注                                           │
├────────────┼───────────────┼────────────────────────────────────────────────┤
│ 3.1.2      │ CMVP #4985    │ FIPS 140-3 ← 当前唯一 140-3 验证版本           │
│ 3.0.9      │ CMVP #4282    │ FIPS 140-2                                    │
│ 3.0.8/3.0.0│ CMVP #4282    │ FIPS 140-2                                    │
└────────────┴───────────────┴────────────────────────────────────────────────┘

路线图（每两年一个 major）:
  4.0   2026-04   non-LTS
  4.1   2026-10   non-LTS
  4.2   2027-04   LTS (→2032)
  5.0   2027-10   non-LTS
```

**关键事实**：
- OpenSSL 3.5 起调整发版策略：LTS 至少 5 年支持，每 2 年至少一个新 LTS；non-LTS 至少 13 个月支持
- FIPS 140-3 验证版本目前**仅 3.1.2**（CMVP #4985）。OpenSSL 4.0/3.6/3.5/3.4/3.0 可共用 3.0.9 验证的 FIPS provider，但**禁止自建 FIPS provider**用于合规场景
- 1.1.1 / 1.0.2 已停止社区维护，仅 OpenSSL Corporation 提供付费扩展支持

#### C.1.2 OpenSSL 4.0 主要变更（工程视角）

```
1. ASN1_STRING 类型现在不透明
   - 影响：直接访问 ASN1_STRING->data / ->length 的旧代码必须改用
     ASN1_STRING_get0_data() / ASN1_STRING_length()
   - 风险：第三方 PKI/CMC/SMIME 库可能编译失败或运行崩溃
   - 审计 grep: grep -rn "ASN1_STRING\b" src/ | grep -v get0_data

2. X509 函数 const 化
   - 影响：未声明 const 的回调签名触发 -Werror 编译失败
   - 审计：必须重新测试所有证书解析路径

3. 移除 atexit() 使用
   - 影响：嵌入式 / 内核模块 / 早期 cleanup 场景行为变化
   - 修复：显式 OPENSSL_cleanup() / OPENSSL_atexit() 注册

4. 移除固定 (D)TLS 版本方法函数
   - 删除：TLSv1_method(), TLSv1_1_method(), TLSv1_2_method(),
           SSLv3_method(), DTLSv1_method() 等
   - 替换：SSL_CTX_new(SSL_CTX_new(TLS_method())) + SSL_CTX_set_min_proto_version()
   - 风险：大量遗留代码硬编码 method，编译直接失败

5. 弃用 EVP_MD_CTX_get0_md_data()
   - 替换：自定义 provider 暴露的 OSSL_PARAM 接口

6. 弃用 ASN1_OBJECT_new()
   - 替换：OBJ_txt2obj() / 内置常量
```

#### C.1.3 OpenSSL 4.0 算法支持矩阵（实测）

```
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ 类别             │ 支持的算法/Provider                                      │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ KEM (后量子)     │ ML-KEM-512, ML-KEM-768, ML-KEM-1024                      │
│ 签名 (后量子)    │ ML-DSA-44, ML-DSA-65, ML-DSA-87                         │
│                  │ SLH-DSA-SHA2-128f/128s/192f/192s/256f/256s               │
│                  │ SLH-DSA-SHAKE-128f/128s/192f/192s/256f/256s              │
│                  │ LMS (Leighton-Micali, RFC 8554)                          │
│ KEM (经典)       │ RSA-OAEP-KEM, ECIES (X25519/X448/ECDH)                   │
│ 签名 (经典)      │ Ed25519, Ed448, ECDSA, RSA, RSA-PSS, SM2                 │
│ 对称             │ AES, ARIA, Camellia, SEED, SM4, ChaCha20, DES (legacy)   │
│ 哈希             │ SHA-1/2/3, SHAKE, cSHAKE, Keccak, SM3, BLAKE2, RIPEMD160 │
│ MAC              │ HMAC, CMAC, GMAC, KMAC128/256, Poly1305, SipHash, BLAKE2│
│ KDF              │ HKDF, PBKDF2, scrypt, **Argon2** (4.0 新增原生),         │
│                  │ TLS13_KDF, TLS1_PRF, X9.42, X9.63, PVKKDF, SSHKDF, ...   │
│ RAND             │ CTR-DRBG, HASH-DRBG, HMAC-DRBG, **Jitter** (新增),       │
│                  │ SEED-SRC, CRNG-TEST, TEST-RAND                          │
│ Provider         │ default, FIPS, base, legacy, null, **winstore** (新增)   │
└──────────────────┴──────────────────────────────────────────────────────────┘

注意：
- Argon2 KDF 原生支持（4.0 新增）→ PBKDF2 已不再是 password hashing 首选
- Jitter RNG → 硬件熵增强（虚拟机/容器场景关键）
- OSSL_PROVIDER-winstore → 直接读取 Windows 证书存储
```

---

### C.2 AI/LLM 辅助密码学实现：风险与机遇

#### C.2.1 AI 辅助发现 OpenSSL CVE 实证（2025-2026）

```
2026-06-09 OpenSSL 同批 5 CVE 中 AI 团队贡献:

CVE-2026-34181 (Low)   PKCS#12 PBMAC1 短 HMAC 接受
  发现者: Pavol Žáčik (Red Hat) + Alex Gaynor (Anthropic)
  ← Anthropic 团队通过 AI 工具发现
  影响: 1/256 概率伪造 PKCS#12 证书+私钥

CVE-2026-34182 (Moderate) CMS AuthEnvelopedData 伪造
  发现者: Asim Viladi Oglu Manizada + Alex Gaynor (Anthropic) +
          Ying Dong + Haiyang Huang
  ← Anthropic + 独立研究员联合
  影响: AES-GCM→AES-256-OFB OID 重写绕过完整性 / 标签长度截断到 1 字节

CVE-2026-35188 (Moderate) OCSP Stapled Response 双重释放
  发现者: Wang Kenaz (UIUC) + Guido Vranken (Aisle Research) +
          Aaron Grattafiori (Nvidia)
  ← Aisle Research 团队（Stanislav Fort 系）

2025-09-30 批次:
CVE-2025-9230 (Moderate) RFC 3211 KEK Unwrap 越界读写
  发现者: Stanislav Fort (Aisle Research)

CVE-2025-9231 (Moderate) SM2 时序侧信道 (ARM64)
  发现者: Stanislav Fort (Aisle Research)

CVE-2025-9232 (Low) HTTP 客户端 no_proxy 越界读
  发现者: Stanislav Fort (Aisle Research)
```

**关键观察**：
- **Aisle Research** 在 2025-09 ~ 2026-06 半年内贡献 4 个 OpenSSL CVE，全部通过 AI/LLM 辅助挖掘（与 Google Big Sleep、Anthropic AI 类似项目机制）
- **Anthropic** 团队 Alex Gaynor 直接挂名 CVE 发现者，标志着 AI 辅助漏洞挖掘已进入主流密码学库审计
- CVE 类型分布：**密码学协议语义错误**（CMS PBMAC1/AEAD tag 长度）+ **传统内存安全**（double-free, OOB）混合

#### C.2.2 AI 辅助密码学工程的两面性

```
┌──────────────────────────────┬─────────────────────────────────────────────┐
│ 维度                        │ 实证 / 风险                                 │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ ✅ 漏洞挖掘                 │ Aisle/Anthropic 在 OpenSSL 半年 4+ CVE      │
│                              │ Google Big Sleep 发现 sqlite/openssl 0-day  │
│ ✅ 代码审计辅助             │ CodeQL LLM 自定义查询 / Semgrep AI          │
│ ✅ PQC 迁移评估             │ LLM 识别 RSA/ECC 调用点+生成替换模板        │
│ ✅ 密码学文档翻译           │ Cloudflare 开源 PQ-Audit 工具（2025-10）    │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ ⚠️ AI 生成加密代码          │ Copilot/Claude 生成 ECB/CBC-MAC/弱 nonce    │
│                              │ 调研: 42% AI 生成密码学代码存在实现缺陷     │
│ ⚠️ Prompt 注入伪造加密参数  │ 攻击者通过恶意文档让 LLM 改 nonce 长度     │
│ ⚠️ 训练数据陈旧             │ 仍推荐 RC4/3DES/CBC（2025 LLM 实测）        │
│ ⚠️ 假信心                   │ LLM 输出"secure AES-256"但漏 GCM nonce 检查 │
└──────────────────────────────┴─────────────────────────────────────────────┘

防御原则（红队测试 AI 生成代码）:
1. 永不接受 AI 生成的密码学代码未经专家评审
2. 强制 cryptofuzz /wycheproof 测试覆盖
3. CI/CD 集成 djblib/tests/expanded testing for AI commits
4. 标记 AI generated 文件并在 PR 模板要求声明
```

#### C.2.3 AI 生成密码学代码常见缺陷模式（审计 grep）

```bash
# 1. ECB 模式（AI 最常见错误）
grep -rn "AES_MODE_ECB\|MCRYPT_MODE_ECB\|CryptoJS.mode.ECB\|AES/ECB" src/

# 2. 硬编码 IV/nonce（第二个 AI 高频错误）
grep -rnE '0x00, ?0x00, ?0x00.*//.*iv|nonce.*=.*\[0[x0-9 ,]*\]' src/

# 3. MD5/SHA1 用于密码（已破）
grep -rn "md5(password\|sha1(password\|hashpw.*md5\|hashpw.*sha1" src/

# 4. 弱 KDF（迭代次数 < 100k）
grep -rnE "PBKDF2|pbkdf2" src/ | grep -vE "iterations[= :]+[1-9][0-9]{5,}"

# 5. RSA 无 OAEP / 无 PSS
grep -rn "RSA_PKCS1_PADDING\|RSA_NO_PADDING\|CryptoJS.RSA.*encrypt" src/

# 6. 弱随机数
grep -rnE "Math\.random|rand\(\)|random\.random\(\)" src/ | grep -iE "key|iv|nonce|token|salt"

# 7. TLS 弱版本
grep -rn "SSLv23_method\|TLSv1_method\|TLSv1_1_method" src/

# 8. Cert 验证关闭
grep -rn "SSL_VERIFY_NONE\|verify=False\|verify_peer = 0\|CURLOPT_SSL_VERIFYPEER.*FALSE" src/

# 一键扫描脚本（GitHub Actions 集成）
# bash crypto-ai-audit.sh && fail-on-findings
```

---

### C.3 PQC 落地实战：2025-2026 关键里程碑

#### C.3.1 全球 PQ 部署时间线（Cloudflare 2025-10-28 报告汇总）

```
2016-07  Chrome 首次实验（CECPQ）
2018-06  Cloudflare / Google 联合实验（CECPQ2 = NTRU-HRSS + X25519, CECPQ2b = SIKE + X25519）
2022-10  Cloudflare 服务端默认开启 PQ（Kyber）
2023-11  Chrome Desktop PQ 推广至 10%
2024-03  Chrome Desktop 默认开启 PQ（X25519Kyber768Draft）
2024-08  Go 默认开启 PQ
2024-11  Chrome Android / Firefox Desktop 默认开启
2025-04  OpenSSL 默认开启 PQ（X25519MLKEM768）
2025-10  Apple iOS / iPadOS / macOS 26 默认 PQ
2025-10  Cloudflare 宣布：>50% 人类发起流量使用 PQ 加密 ← 里程碑

未来预期:
2026     Chrome Android 在长尾设备上完成
2026-08  EU AI Act 高风险系统强制要求密码学清单
2027     X25519MLKEM768 进入 RFC 标准（摆脱 draft 状态）
```

#### C.3.2 X25519MLKEM768 工程数据

```
性能对比（Cloudflare 2025-10 实测）:
┌──────────────────┬──────────────┬──────────────┬──────────────────┐
│ 算法             │ 公钥/密文    │ 握手开销     │ 安全等级         │
├──────────────────┼──────────────┼──────────────┼──────────────────┤
│ X25519           │ 32+32 = 64B  │ 基线         │ ~AES-128 经典    │
│ ML-KEM-512       │ 800+768=1568B│ 较 X25519 快 │ AES-128 PQ       │
│ ML-KEM-768       │ 1184+1088B   │ 较 X25519 快 │ AES-192 PQ       │
│ ML-KEM-1024      │ 1568+1568B   │ 显著快于 X25519│ AES-256 PQ     │
│ X25519MLKEM768   │ 1216+1120B   │ 接近 ML-KEM  │ 经典+PQ 双重保险 │
│  (混合, 事实标准) │              │              │                  │
└──────────────────┴──────────────┴──────────────┴──────────────────┘

为什么是 X25519 + ML-KEM-768 而非 ML-KEM-512?
1. 安全裕度: 抗未来格密码分析改进
2. 实现缺陷对冲: KyberSlash 类型时序攻击历史 → 经典部分兜底
3. 协议完整性: ML-KEM 实现漏洞通常需主动攻击者 → X25519 防止 cookie/token 窃取

KyberSlash 教训（PQ 部署的现实风险）:
- 2019 年 Kyber 实现中的时序侧信道
- 影响: Kyber 解密变量中的除法依赖密钥 → 缓存时序泄露
- 不影响 TLS 中的 Kyber（仅影响非 TLS 用法）
- 但未来类似实现缺陷**可能**影响 TLS → 混合部署是工程必需
```

#### C.3.3 主要库 PQC 支持矩阵（2026-06）

```
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ 库                  │ PQC 状态                                            │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ OpenSSL 3.5+        │ X25519MLKEM768 默认 (TLS), provider 全套 ML-KEM/    │
│                     │ ML-DSA/SLH-DSA                                      │
│ OpenSSL 4.0+        │ 全套 + LMS + Argon2 KDF + Jitter RNG                │
│ BoringSSL (Google)  │ X25519Kyber768 长期支持，最先在 Chrome 部署         │
│ AWS-LC              │ X25519MLKEM768 GA，FIPS 140-3 验证中                │
│                     │ AWS KMS 已支持 ML-KEM 用于 PQ-TLS                  │
│ liboqs /            │ 完整 NIST PQC 候选，研究/测试首选                   │
│  oqs-provider       │ 通过 provider 插件让 OpenSSL 3.x 支持 PQ            │
│ BouncyCastle        │ Java 1.84 / C# 2.x: ML-KEM/ML-DSA/SLH-DSA 全套     │
│ wolfSSL             │ wolfCOSE + ML-DSA 产品级（CAVP 验证）              │
│                     │ wolfCrypt FIPS 140-3 certificate #4479              │
│ pyca/cryptography   │ 49.0.0 已支持 X25519MLKEM768 (via OpenSSL 3.5+)    │
│ Rust ring           │ X25519MLKEM768 实验性，rustls PQ 支持跟进           │
│ Go crypto/tls       │ 1.23+ 默认 X25519MLKEM768（CVE-2025-68121 已修）   │
│ Node.js             │ 22+ 通过 OpenSSL 3.x 继承 PQ                        │
│ Java (JDK 24+)      │ JEP 496: Quantum-Resistant ML-KEM (Phase 1)         │
│                     │ JEP 510: Key Derivation Function API                │
│ Apple crypto        │ iOS 18.4+ / macOS 15.4+ PQ3 iMessage（Signal 协议）│
│                     │ iOS/iPadOS/macOS 26 TLS PQ 默认                    │
│ Signal              │ PQXDH（X3DH + ML-KEM-1024）2023-09 GA              │
│ Apple iMessage      │ PQ3（Kyber-1024 + 接续身份验证）2024-02 GA         │
└─────────────────────┴─────────────────────────────────────────────────────┘
```

#### C.3.4 PQC 工程决策树（2026 实战版）

```
开始
  │
  ├─ 数据保密期 < 3 年 且 仅互联网公开数据?
  │     └─ 是: P3 优先级（保持现状，监控即可）
  │
  ├─ 系统/数据保密期 > 10 年（如医疗记录、政府档案）?
  │     └─ 是: P0 立即启动 SNDL 评估，12 个月内完成混合部署
  │
  ├─ 面向公网 TLS（Web/App API）?
  │     └─ 是: P1 6 个月内升级到 X25519MLKEM768
  │           - OpenSSL ≥ 3.5 / Nginx 1.26+ / HAProxy 3.0+
  │           - 验证 middlebox 兼容性（ClientHello 大小变化）
  │
  ├─ 内部 mTLS / 服务网格?
  │     └─ 是: P1 9 个月内迁移，可控环境易实施
  │
  ├─ 代码/工件签名（Sigstore/cosign/CI 流水线）?
  │     └─ 是: P2 引入 ML-DSA-65 作为附加签名（混合）
  │
  ├─ SSH 基础设施?
  │     └─ 是: P2 OpenSSH 9.9+ 使用 mlkem768x25519-sha256@openssh.com
  │
  ├─ 长期归档 / 备份加密?
  │     └─ 是: P0 立即评估，归档数据是 SNDL 最大受害者
  │
  └─ HSM / 硬件密钥管理?
        └─ 是: P2 评估 HSM 固件升级路径（AWS CloudHSM/YubiHSM 2.4+/Thales Luna 7.x+）

决策原则:
1. 永远先混合部署 → 不接受纯 PQ 切换（ cryptanalysis 仍可能突破）
2. 公开标准优先（FIPS 203/204/205）→ 不接受非标算法（如 SIKE 教训）
3. Crypto-Agility 优先 → KEX 算法列表可热升级，不写死
4. 中间盒兼容性是部署最大障碍 → 灰度 + A/B 测试
```

---

### C.4 2025-2026 密码学实现关键 CVE 速查（工程视角）

> 与 [[crypto-attacks]] C.18 节互补，本节聚焦"实现层 / 配置层 / 工程层"漏洞。

```
┌─────────────────────┬────────┬──────────────────────────────────────────────┐
│ CVE                 │ 严重度 │ 影响与工程含义                               │
├─────────────────────┼────────┼──────────────────────────────────────────────┤
│ 2026 年 OpenSSL 批次（2026-06-09）                                          │
├─────────────────────┼────────┼──────────────────────────────────────────────┤
│ CVE-2026-34180      │ Low    │ ASN.1 元素 >2GB 触发整数截断 → 堆越界读      │
│                     │        │   影响: d2i_X509/d2i_PKCS7 调用方            │
│                     │        │   不影响: FIPS provider, 命令行工具          │
│                     │        │   修复: OpenSSL ≥ 4.0.1 / 3.6.3 / 3.5.7     │
│                     │        │   平台: 仅 64-bit Unix/Linux (Win/32-bit 不受影响) │
│                     │        │                                              │
│ CVE-2026-34181      │ Low    │ PKCS#12 PBMAC1 1-byte HMAC 接受 → 证书伪造   │
│                     │        │   概率: 1/256 通过                           │
│                     │        │   发现者: Anthropic Alex Gaynor (AI 辅助)    │
│                     │        │   工程含义: 不要信任 PKCS#12 上传服务        │
│                     │        │   修复: OpenSSL ≥ 4.0.1 / 3.6.3 / 3.5.7 / 3.4.6 │
│                     │        │                                              │
│ CVE-2026-34182      │ Mod    │ CMS AuthEnvelopedData 接受伪造                │
│                     │        │   攻击: 捕获合法 AES-GCM CMS → 重写 OID 为   │
│                     │        │         AES-256-OFB + 攻击者 IV/CT → MAC 跳过 │
│                     │        │   第二路径: AEAD tag 截断至 1 字节 → 暴力破解 │
│                     │        │   发现者: Anthropic + Ying Dong + Haiyang Huang │
│                     │        │   修复: OpenSSL ≥ 4.0.1 / 3.6.3 / 3.5.7 / 3.4.6 / 3.0.21 │
│                     │        │                                              │
│ CVE-2026-34183      │ Mod    │ QUIC PATH_CHALLENGE 洪水 → 无界内存增长 DoS   │
│                     │        │   工程含义: QUIC 服务端需 rate limit          │
│                     │        │   不影响: FIPS provider (QUIC 在模块边界外)   │
│                     │        │   修复: OpenSSL ≥ 4.0.1 / 3.6.3 / 3.5.7 / 3.4.6 │
│                     │        │                                              │
│ CVE-2026-35188      │ Mod    │ OCSP Stapled Response 双重释放 → 堆腐败/RCE   │
│                     │        │   发现者: Aisle Research + UIUC + Nvidia      │
│                     │        │   触发: 恶意 TLS 服务端通过 status_request    │
│                     │        │   修复: 仅 4.0.1 / 3.6.3（旧版本可能未回移） │
├─────────────────────┼────────┼──────────────────────────────────────────────┤
│ 2025 年 OpenSSL 批次                                                       │
├─────────────────────┼────────┼──────────────────────────────────────────────┤
│ CVE-2025-9230       │ Mod    │ RFC 3211 KEK Unwrap 越界读写                  │
│                     │        │   影响: CMS 密码加密 (PWRI, 极少使用)         │
│                     │        │   修复: OpenSSL ≥ 3.5.4 / 3.4.3 / 3.0.18     │
│                     │        │                                              │
│ CVE-2025-9231       │ Mod    │ SM2 时序侧信道（64-bit ARM）                  │
│                     │        │   影响: 私钥恢复（仅 ARM64，SM2 几乎不在 TLS）│
│                     │        │   发现者: Stanislav Fort (Aisle Research)    │
│                     │        │   修复: OpenSSL ≥ 3.5.4 / 3.4.3 / 3.3.5 / 3.2.6 │
│                     │        │                                              │
│ CVE-2025-4575       │ Low    │ x509 -addreject 误添加为 trusted use          │
│                     │        │   原因: 复制粘贴错误（OpenSSL 3.5 独有）      │
│                     │        │   修复: OpenSSL ≥ 3.5.1                       │
│                     │        │                                              │
│ CVE-2024-12797      │ High   │ RFC7250 Raw Public Keys 握手未中止            │
│                     │        │   影响: RPK TLS MITM（默认关闭，需手动启用）  │
│                     │        │   发现者: Apple Inc.                          │
│                     │        │   修复: OpenSSL ≥ 3.4.1 / 3.3.3 / 3.2.4      │
│                     │        │                                              │
│ CVE-2024-13176      │ Low    │ ECDSA 时序侧信道（NIST P-521，300ns 信号）   │
│                     │        │   修复: OpenSSL ≥ 3.4.1 / 3.3.3 / 3.2.4 /    │
│                     │        │         3.1.8 / 3.0.16                       │
├─────────────────────┼────────┼──────────────────────────────────────────────┤
│ 其他关键库                                                                  │
├─────────────────────┼────────┼──────────────────────────────────────────────┤
│ CVE-2025-68121      │ Crit   │ Go crypto/tls Config.Clone 泄漏 session      │
│                     │        │   ticket key → Docker Engine 等大量项目受影响 │
│                     │        │   修复: Go ≥ 1.24.5 / 1.23.11                │
│                     │        │                                              │
│ CVE-2026-32289      │ High   │ Go crypto/x509 通配符证书验证绕过 → MITM     │
│                     │        │   修复: Go ≥ 1.24.x                           │
│                     │        │                                              │
│ CVE-2025-15467      │ High   │ OpenSSL CMS 栈溢出 Pre-Auth RCE（已在        │
│                     │        │   [[crypto-attacks]] D.18 详述）              │
│                     │        │                                              │
│ CVE-2026-26007      │ High   │ pyca/cryptography SECT 子群攻击（Lim-Lee）   │
│                     │        │   修复: cryptography ≥ 48.0.0                 │
│                     │        │                                              │
│ CVE-2026-42768      │ High   │ Bleichenbacher Oracle 现代变体（PKCS7）       │
│                     │        │   修复: OpenSSL ≥ 4.0.x                       │
└─────────────────────┴────────┴──────────────────────────────────────────────┘

CVE 检查脚本（一键扫描全栈）:
#!/bin/bash
# crypto_cve_check.sh — 2026-06-13 version
echo "=== OpenSSL ==="
openssl version
case $(openssl version | awk '{print $2}') in
  4.0.0)        echo "❌ CVE-2026-34180/34181/34182/34183/35188 — 升级到 4.0.1";;
  3.6.0|3.6.1|3.6.2) echo "❌ CVE-2026-* 系列 — 升级到 3.6.3";;
  3.5.0|3.5.1|3.5.2|3.5.3|3.5.4|3.5.5|3.5.6)
                echo "❌ CVE-2026-34180/34182/34183 + CVE-2025-4575(3.5.0) — 升级到 3.5.7";;
  3.4.0|3.4.1|3.4.2|3.4.3|3.4.4|3.4.5)
                echo "❌ CVE-2026-34180/34182/34183 — 升级到 3.4.6";;
  3.0.*)        echo "❌ 3.0 即将 EOL（2026-09-07）— 立即迁移到 3.5 LTS";;
esac

echo "=== Go ==="
go version 2>/dev/null
echo "=== Python cryptography ==="
python3 -c "import cryptography; print(cryptography.__version__)" 2>/dev/null
echo "=== BouncyCastle ==="
find / -name "bcprov-jdk*-1.*.jar" 2>/dev/null | head -5
echo "=== libssh ==="
ssh -V
```

---

### C.5 工具生态 2025-2026 版本矩阵（实现层）

```
┌──────────────────────┬──────────────┬───────────────────────────────────────┐
│ 工具/库              │ 2026-06 版本 │ 关键更新                              │
├──────────────────────┼──────────────┼───────────────────────────────────────┤
│ OpenSSL              │ 4.0.1        │ PQ GA + Argon2 + Jitter RNG           │
│                      │ 3.5.7 LTS    │ LTS 推荐                              │
│ BoringSSL            │ 持续         │ X25519Kyber768 Chrome 部署基石        │
│ AWS-LC               │ 1.43.x       │ FIPS 140-3 验证中 + X25519MLKEM768 GA │
│ GnuTLS               │ 3.8.10       │ PQ 实验性                             │
│ LibreSSL             │ 4.1.x        │ 仍不支持 PQ（滞后）                   │
│ liboqs               │ 0.12.0       │ 完整 NIST PQC 候选 + 测试向量         │
│ oqs-provider         │ 0.7.0        │ OpenSSL 3.x PQ 插件                   │
│ wolfSSL              │ 5.8.0        │ wolfCOSE + ML-DSA (CAVP)              │
│ wolfCrypt FIPS       │ 5.x          │ CMVP #4479 (FIPS 140-3)               │
│ pyca/cryptography    │ 49.0.0       │ 继承 OpenSSL 3.5+ PQ + Argon2         │
│                      │ 48.0.0       │ SECT 子群修复 CVE-2026-26007          │
│ Rust ring            │ 0.17.x       │ X25519MLKEM768 实验性                 │
│ rustls               │ 0.23.x       │ PQ 插件式（rustls-post-quantum）      │
│ BouncyCastle Java    │ 1.84         │ 全套 ML-KEM/ML-DSA/SLH-DSA + Argon2   │
│ BouncyCastle C#      │ 2.6.x        │ 同步 Java 特性                       │
│ Go crypto/tls        │ 1.24.x       │ X25519MLKEM768 默认（CVE-2025-68121 已修）│
│ Java (JDK)           │ 24 / 25 EA   │ JEP 496 ML-KEM + JEP 510 KDF API      │
│ Node.js              │ 22.x / 24.x  │ 继承 OpenSSL 3.x PQ                  │
│ Tink (Google)        │ 1.17.0       │ ML-KEM-768 实验性                     │
│ age (FiloSottile)    │ 1.3.x        │ 后量子 age-plugin-oqs                 │
│ Minisign             │ 0.11         │ 签名工具（仍 Ed25519，可考虑 PQ 替代）│
│ Sigstore/cosign      │ 3.x          │ keyless + ML-DSA 实验性               │
│ Vault Transit        │ 1.20.x       │ 加密即服务 + PQ 路线图               │
│ HashiCorp Vault      │ 1.20.x       │ AWS Auth 绕过修复 (CVE-2026-34986 等) │
│                      │              │   详见 [[devsecops-secrets]]          │
│ Keycloak             │ 26.x         │ OAuth/OIDC，依赖底层库的 PQ           │
│ testssl.sh           │ 3.2.x        │ PQ 套件检测                           │
│ Cryptofuzz           │ 持续         │ OSS-Fuzz 默认组件                    │
│ Project Wycheproof   │ 持续         │ Google 密码学实现缺陷测试集           │
│ djbscrypt/cryptobench│ 持续         │ 学术基准                              │
└──────────────────────┴──────────────┴───────────────────────────────────────┘

审计工具矩阵:
- testssl.sh — TLS 全面扫描（含 PQ 套件）
- ssh-audit — SSH 配置审计
- cryptofuzz — 差分模糊测试密码学实现
- wycheproof — 已知缺陷模式回归测试
- tlsfuzzer — TLS 协议级模糊测试
- defund/cryptography-bugs — CVE 静态扫描
- dlint/spectral/bandit — 通用代码扫描（含密码学规则）
- trufflehog/gitleaks — 硬编码密钥检测
```

---

### C.6 工程实现常见缺陷模式扩展（2025-2026）

#### C.6.1 GCM Nonce 管理缺陷（最常见）

```python
# ❌ 错误: 计数器 nonce 在 key rotation 后重置
class BadCrypto:
    def __init__(self, key):
        self.key = key
        self.counter = 0  # 重启后回到 0
    def encrypt(self, plaintext):
        nonce = self.counter.to_bytes(12, 'big')
        self.counter += 1
        # 同一 key + nonce 重用 → 完全失败
        return aesgcm_encrypt(self.key, nonce, plaintext)

# ✅ 正确: 随机 nonce 或 key-bound counter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

class GoodCrypto:
    def __init__(self, key):
        # key rotation 时新 key + 新 nonce 空间
        self.key = key
    def encrypt(self, plaintext):
        # 每次随机 nonce (96-bit)
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self.key).encrypt(nonce, plaintext, None)
        return nonce + ct
    # 推荐使用限定次数的计数器 nonce + 持久化状态
    # 见 RFC 8439 / RFC 5116
```

#### C.6.2 Ed25519 与 Ed25519ctx/Ed25519ph 混淆

```python
# ❌ 错误: 在协议要求 Ed25519ctx 时使用纯 Ed25519
# 跨实现互操作失败 + 域分离缺失导致签名可被重用
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
sig = key.sign(message)  # 纯 Ed25519

# ✅ 正确: 显式选择算法变体
# RFC 8032: Ed25519 (纯), Ed25519ctx (上下文), Ed25519ph (预哈希)
# 工程建议: 协议设计时明确选择 + 在签名内绑定上下文字符串
```

#### C.6.3 RSA PKCS1 v1.5 加密（Bleichenbacher）

```python
# ❌ 错误: 默认 PKCS1 v1.5 padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
cipher = PKCS1_v1_5.new(RSA.import_key(pubkey))
ct = cipher.encrypt(message)  # ← Bleichenbacher Oracle 风险

# ✅ 正确: RSA-OAEP
from cryptography.hazmat.primitives.asymmetric import padding
ct = pubkey.encrypt(message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
```

#### C.6.4 JWT 算法混淆（RS256 → HS256）

```python
# ❌ 错误: 不验证 JWT alg 字段
import jwt
decoded = jwt.decode(token, public_key, algorithms=None)  # 接受任意 alg

# 攻击: 攻击者改 alg=HS256，用 RSA 公钥作 HMAC secret 签名 → 验证通过

# ✅ 正确: 显式指定允许的算法
decoded = jwt.decode(token, public_key, algorithms=['RS256'])
# 禁止: alg=None / alg 混淆 / 默认信任 token 中的 alg
```

#### C.6.5 国密 SM2/SM3/SM4 实现陷阱

```python
# 中国合规场景: GB/T 38636-2020 GM/T 0006-2012
# 1. SM2 必须使用曲线参数（不能替换为标准 P-256）
# 2. SM3 输出 256 位，必须替换 SHA-256（不能混用）
# 3. SM4 必须使用 GCM/CTR/CBC 模式，禁止 ECB
# 4. 中国合规: 需要 SM 证书 + SM2 签名 + SM4 加密 全套

# OpenSSL 4.0+ 已原生支持 SM2/SM3/SM4 + 证书体系
# 命令行生成 SM2 证书:
# openssl ecparam -name SM2 -genkey -noout -out sm2.key
# openssl req -new -x509 -key sm2.key -out sm2.crt -sm3 -days 365
```

---

### C.7 中文社区精华参考

```
┌──────────────────┬──────────────────────────────────────────────────────┐
│ 来源             │ 精华内容（推荐阅读）                                 │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 阿里云先知       │ bReaK_1 Android 18 篇系列（部分含 SM2 实现）        │
│ xz.aliyun.com    │ 长亭科技 Padding Oracle 实战                         │
│                  │ 国密 SM2/SM3/SM4 工程实现（搜索 tag: 国密）          │
│                  │ TLS 1.3 部署与 Q&A                                   │
│                  │ HertzBeat SnakeYAML 反序列化（CVE-2024-42323）       │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 奇安信攻防社区   │ CVE-2025-15467 OpenSSL CMS 栈溢出深度分析            │
│ pub.kdsec.com    │ 2025 漏洞态势报告（密码学相关章节）                 │
│                  │ 双重验证 RCE 构造（含密码学签名绕过）               │
├──────────────────┼──────────────────────────────────────────────────────┤
│ FreeBuf          │ 国密算法合规实践（商用密码管理条例解读）             │
│ freebuf.com      │ 后量子密码迁移系列（Cloudflare/Google 解读）         │
│                  │ 密评 GB/T 39786-2021 实操                            │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 腾讯云           │ TLS 1.3 配置最佳实践（CVM/CN 网络环境）             │
│ cloud.tencent.com│ 微服务 mTLS 实施（TKE 服务网格）                     │
│                  │ KMS 密钥轮转策略                                     │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 阿里云           │ 国密合规方案（阿里云密钥管理服务 KMS）               │
│ developer.aliyun.com 抗量子密码（AWS KMS PQC 接入实践）              │
│                  │ OpenSSL 3.5 升级指南                                │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 安全客           │ Aisle Research 发现 OpenSSL SM2 时序 CVE-2025-9231   │
│ anquanke.com     │ Anthropic Big Sleep 系列解读                         │
│                  │ Cloudflare PQ 2025 报告中文解读                      │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 微步 X 情报      │ XGPT 双备案（含密码学合规）                          │
│                  │ 国密算法威胁情报来源                                 │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 看雪 / 吾爱破解  │ 逆向分析中识别密码学常量（S-box/曲线参数）          │
│                  │ Android Keystore 实现                                │
├──────────────────┼──────────────────────────────────────────────────────┤
│ 中国合规法规     │ 商用密码管理条例 (2023-07 修订)                      │
│                  │ GB/T 39786-2021 信息安全技术 信息系统密码应用基本要求 │
│                  │ GB/T 37092-2018 密码模块安全要求                     │
│                  │ GB/T 38636-2020 信息安全技术 SM2 密钥交换协议        │
│                  │ 等保 2.0 三级要求中密码学条款                         │
│                  │ 关键信息基础设施安全保护条例（2022-09-01）           │
└──────────────────┴──────────────────────────────────────────────────────┘

中国商用密码合规生态:
- 商用密码检测中心: 密码产品认证（SM2/3/4 实现合规）
- 国家密码管理局: 商密产品型号证书
- 主要厂商: 卫士通/中电科/得安/江苏百识/上海格尔/鼎铉/三未信安/信安世纪
- 云厂商合规: 阿里云/华为云/腾讯云 KMS 均通过商密二级认证
```

---

### C.8 防御升级路线图（P0-P3 分级，2026 版）

```
┌──────┬──────────────────────────────────────────────────────────────────┐
│ 级别 │ 立即行动（含截止日期）                                          │
├──────┼──────────────────────────────────────────────────────────────────┤
│      │ 0-3 个月（立即实施）                                            │
│ P0   ├──────────────────────────────────────────────────────────────────┤
│      │ □ 升级 OpenSSL 到 4.0.1 / 3.5.7 LTS / 3.4.6（修 2026-06 CVE 批）│
│      │ □ 升级 Go 到 1.24.5+（修 CVE-2025-68121）                       │
│      │ □ 升级 pyca/cryptography 到 49.0.0+（修 SECT 子群）             │
│      │ □ 禁用 SSLv3/TLSv1.0/TLSv1.1（强制 TLS 1.2+，推荐 TLS 1.3）    │
│      │ □ 移除所有 RSA PKCS1 v1.5 加密（改用 RSA-OAEP）                  │
│      │ □ 移除所有 AES-ECB 使用（改用 AES-GCM/ChaCha20-Poly1305）       │
│      │ □ 强制 PBKDF2 ≥ 600k 迭代 或迁移到 Argon2id                     │
│      │ □ RSA 密钥 ≥ 3072 位 或迁移到 ECDSA P-256/Ed25519               │
│      │ □ 长期归档数据（>10 年）启动 SNDL 风险评估                      │
│      │ □ 部署硬编码密钥扫描（trufflehog CI gate）                      │
│      │ □ TLS 配置审计: testssl.sh 全资产扫描                           │
│      │ □ 中国合规场景: 启用 SM2/SM3/SM4 (OpenSSL 4.0+ 原生)            │
├──────┼──────────────────────────────────────────────────────────────────┤
│      │ 3-6 个月（短期）                                                │
│ P1   ├──────────────────────────────────────────────────────────────────┤
│      │ □ 面向公网 TLS 启用 X25519MLKEM768（OpenSSL ≥ 3.5）             │
│      │ □ 内部 mTLS 迁移到混合 PQ                                       │
│      │ □ SSH 升级到 OpenSSH 9.9+（mlkem768x25519-sha256@openssh.com）  │
│      │ □ 引入 cryptofuzz/wycheproof 进入 CI                            │
│      │ □ Crypto-Agility 改造: KEX 算法列表可热升级（不写死）           │
│      │ □ mTLS 客户端证书轮转自动化（≤ 90 天）                          │
│      │ □ HSM 集成: AWS CloudHSM 2.4+ / YubiHSM 2 / Thales Luna 7.x+   │
│      │ □ KMS 密钥轮转策略（≤ 365 天，关键 ≤ 90 天）                    │
│      │ □ 部署 OCSP Stapling 监控（CVE-2026-35188 防护）                │
│      │ □ QUIC 服务端 rate limit（CVE-2026-34183 防护）                 │
│      │ □ JDK 24+ 评估 ML-KEM 支持（JEP 496）                           │
├──────┼──────────────────────────────────────────────────────────────────┤
│      │ 6-12 个月（中期）                                               │
│ P2   ├──────────────────────────────────────────────────────────────────┤
│      │ □ 代码/工件签名 引入 ML-DSA-65 作为附加签名（混合）             │
│      │ □ Sigstore/cosign 部署 ML-DSA                                  │
│      │ □ HSM 固件升级到 PQC 支持                                       │
│      │ □ PQC 全面评估（X25519 + ML-KEM 完整迁移）                      │
│      │ □ Java 21+ Virtual Threads 安全审计中密码学上下文传播           │
│      │ □ 部署 TLS 1.3 Hybrid Key Exchange (X25519MLKEM768)            │
│      │ □ Argon2 KDF 全面替换 PBKDF2（OpenSSL 4.0 原生）                │
│      │ □ 部署 eBPF 监控密码学调用异常（Falco 自定义规则）              │
│      │ □ Vault Transit 模式 PQ 路线图实施                              │
│      │ □ CNAPP 工具升级到 PQ-aware 版本                                │
├──────┼──────────────────────────────────────────────────────────────────┤
│      │ 12-24 个月（长期）                                              │
│ P3   ├──────────────────────────────────────────────────────────────────┤
│      │ □ 禁用纯经典密钥交换（仅 X25519MLKEM768 等混合）                │
│      │ □ 证书策略强制 PQC（X.509 + ML-DSA）                            │
│      │ □ 100% PQC 覆盖审计                                             │
│      │ □ 后量子 HSM 替换（YubiHSM 3 / Luna 8 / CloudHSM PQ-GA）        │
│      │ □ 国密 + PQC 双合规（中国出海产品）                              │
│      │ □ PQ3 协议（Apple iMessage 类）评估用于内部即时通讯             │
│      │ □ FIPS 140-3 PQC 验证模块部署                                   │
│      │ □ AI 辅助密码学审计 L3-L4 成熟度（Cellebrite 类 Agentic）       │
│      │ □ NIST IR 8547 PQC 迁移完整实施                                 │
│      │ □ Java JDK 26+ 全面 PQ 迁移（JEP 496 GA）                       │
└──────┴──────────────────────────────────────────────────────────────────┘

KPI 指标（年度评估）:
- TLS 1.3 覆盖率 ≥ 95%
- X25519MLKEM768 覆盖率 ≥ 80%（公网 TLS）
- 硬编码密钥事件 ≤ 5/年（CI/CD 阻断）
- 密码学库 CVE 平均修复时间 ≤ 7 天（Critical）/ 30 天（High）
- mTLS 证书轮转率 100% 自动化
- PQC 覆盖率 ≥ 60%（关键资产 100%）
- Crypto-Agility: KEX 算法可热升级无重启
```

---

### C.9 综合 CVE 速查（实现层 → 2025-2026）

```
┌─────────────────────┬────────┬──────────────┬──────────────────────────────┐
│ CVE                 │ 库     │ 严重度       │ 工程含义                     │
├─────────────────────┼────────┼──────────────┼──────────────────────────────┤
│ CVE-2026-34180      │ OpenSSL│ Low          │ ASN.1 >2GB 解析堆越界读      │
│ CVE-2026-34181      │ OpenSSL│ Low          │ PKCS#12 PBMAC1 短 HMAC 接受  │
│ CVE-2026-34182      │ OpenSSL│ Moderate     │ CMS AuthEnvelopedData 伪造   │
│ CVE-2026-34183      │ OpenSSL│ Moderate     │ QUIC PATH_CHALLENGE DoS      │
│ CVE-2026-35188      │ OpenSSL│ Moderate     │ OCSP Stapling double-free    │
│ CVE-2025-9230       │ OpenSSL│ Moderate     │ RFC 3211 KEK 越界读写        │
│ CVE-2025-9231       │ OpenSSL│ Moderate     │ SM2 时序侧信道（ARM64）      │
│ CVE-2025-9232       │ OpenSSL│ Low          │ HTTP 客户端 no_proxy 越界读  │
│ CVE-2025-4575       │ OpenSSL│ Low          │ x509 -addreject 误用         │
│ CVE-2024-12797      │ OpenSSL│ High         │ RFC7250 RPK 握手未中止 MITM  │
│ CVE-2024-13176      │ OpenSSL│ Low          │ ECDSA P-521 时序侧信道       │
│ CVE-2025-68121      │ Go     │ Critical     │ crypto/tls Config.Clone 泄漏 │
│ CVE-2026-32289      │ Go     │ High         │ crypto/x509 通配符验证绕过   │
│ CVE-2026-26007      │ Python │ High         │ cryptography SECT 子群攻击   │
│ CVE-2025-15467      │ OpenSSL│ High         │ CMS 栈溢出 Pre-Auth RCE      │
│ CVE-2026-42768      │ OpenSSL│ High         │ Bleichenbacher Oracle 现代变 │
│ CVE-2025-61726      │ Go     │ DoS          │ net/url URL 解析 DoS         │
│ CVE-2026-34986      │ Vault  │ High         │ AWS Auth 绕过 (Vault 2.0 修复)│
│ CVE-2025-43530      │ macOS  │ High         │ TCC VoiceOver 绕过           │
│ CVE-2025-52573      │ MCP    │ Critical     │ LLM EchoLeak 零点击 Prompt  │
└─────────────────────┴────────┴──────────────┴──────────────────────────────┘

工程层 CVE 来源持续监控:
- https://openssl-library.org/news/fips-cve/ (FIPS 影响)
- https://www.openssl.org/news/vulnerabilities.xml (RSS)
- https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=cryptography&search_type=all
- CISA KEV Catalog (强制修复列表)
- GitHub Security Advisories (GHSA)
- 商用密码检测中心公告（中国合规）
```

---

### C.10 综合参考与工具速查

```
官方文档:
- OpenSSL 4.0 迁移指南: https://docs.openssl.org/4.0/man7/ossl-guide-migration/
- OpenSSL 路线图: https://openssl-library.org/roadmap/
- OpenSSL 漏洞页: https://openssl-library.org/news/vulnerabilities/
- FIPS 验证: https://openssl-library.org/source/ (CMVP #4985/#4282)
- NIST PQC 标准: FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)
- NIST IR 8547 PQC 迁移: https://csrc.nist.gov/pubs/ir/8547/iprd
- CISA PQC 路线图: https://www.cisa.gov/resources-tools/resources/post-quantum-cryptography
- Cloudflare PQ 2025: https://blog.cloudflare.com/pq-2025/
- Cloudflare PQ-Audit 工具: 开源代码翻译器（2025-10）
- AWS-LC PQC: https://github.com/aws/aws-lc
- liboqs: https://openquantumsafe.org/
- oqs-provider: https://github.com/open-quantum-safe/oqs-provider
- Google Big Sleep: https://googleprojectzero.blogspot.com/ (含密码学发现)
- Aisle Research: 持续贡献 OpenSSL CVE

工具命令速查（2026 版）:
# OpenSSL 4.0 PQ 算法列表
openssl list -providers
openssl list -kem-algorithms | grep -i ml_kem
openssl list -signature-algorithms | grep -i ml_dsa

# 生成 ML-KEM 密钥
openssl genpkey -algorithm ML-KEM-768 -out mlkem768.key
openssl pkey -in mlkem768.key -pubout -out mlkem768.pub

# 生成 ML-DSA 密钥
openssl genpkey -algorithm ML-DSA-65 -out mldsa65.key

# TLS PQ 套件检查
testssl.sh --PFS --pfs --cipher-per-proto --pq target.com:443

# Argon2 密码哈希（OpenSSL 4.0+）
openssl kdf -keylen 32 -kdfopt pass:password -kdfopt salt:saltbytes \
  -kdfopt mem:65536 -kdfopt iter:3 -kdfopt parallel:4 ARGON2ID

# Cryptofuzz 模糊测试 OpenSSL
git clone https://github.com/guidovranken/cryptofuzz
cd cryptofuzz && make -j$(nproc)
./cryptofuzz --module=openssl

# Wycheproof 测试
git clone https://github.com/google/wycheproof
# 加载到你的密码学实现测试套件

# 硬编码密钥检测
trufflehog filesystem ./src/ --only-verified
gitleaks detect --source ./ --report-format json --report-path leaks.json

# 国密证书生成（中国合规）
openssl ecparam -name SM2 -genkey -noout -out sm2.key
openssl req -new -x509 -key sm2.key -out sm2.crt -sm3 -days 365 \
  -subj "/CN=example.com/O=YourOrg/C=CN"

中文资源:
- 商用密码检测中心: https://www.scctc.org.cn/
- 国家密码管理局: http://www.sca.gov.cn/
- 阿里云商密合规 KMS: https://help.aliyun.com/product/28933.html
- 华为云 DEW (数据加密服务): https://www.huaweicloud.com/product/dew.html
- 腾讯云 KMS: https://cloud.tencent.com/product/kms
- 奇安信攻防社区: https://pub.kdsec.com/
- 先知社区: https://xz.aliyun.com/
- 安全客: https://www.anquanke.com/
- FreeBuf: https://www.freebuf.com/

学术前沿（2025-2026）:
- Anthropic + Aisle Research 持续贡献 OpenSSL CVE（AI 辅助挖掘）
- Google Big Sleep 发现 sqlite、OpenSSL 0-day
- NDSS 2026: LLM 生成密码学代码安全分析
- USENIX Security 2025: AI 辅助 PQC 迁移工具评估
- ACM CCS 2025: KyberSlash 类时序攻击扩展研究
- IACR ePrint 2025/2026: ML-KEM 实现安全持续分析
- arXiv 2026: LLM 辅助漏洞挖掘在密码学库的覆盖率研究
```

---

## Part C 章节总结

| 章节 | 关键交付 |
|------|---------|
| C.1 | OpenSSL 4.0 GA、版本矩阵、FIPS 140-3 验证版本、4.0 主要变更、算法支持矩阵 |
| C.2 | AI 辅助挖掘 OpenSSL CVE 实证（Aisle/Anthropic 半年 4+ CVE）、AI 生成代码缺陷模式 |
| C.3 | 全球 PQ 部署时间线（Cloudflare 50%+）、X25519MLKEM768 工程数据、主要库 PQC 支持矩阵、决策树 |
| C.4 | 2025-2026 实现/配置层 CVE 速查（OpenSSL 11 个 + Go 2 + Python 1 + 其他）、CVE 检查脚本 |
| C.5 | 工具生态版本矩阵（OpenSSL/Go/Python/BouncyCastle/wolfSSL/Tink/age/Sigstore/Vault 等 25+ 工具） |
| C.6 | 工程实现常见缺陷模式扩展（GCM nonce/Ed25519 变体/RSA padding/JWT 算法混淆/国密合规） |
| C.7 | 中文社区精华参考（10 类来源 + 中国商用密码合规生态） |
| C.8 | 防御升级路线图 P0-P3 分级 + KPI 指标 |
| C.9 | 综合实现层 CVE 速查（19 个） + 持续监控源 |
| C.10 | 综合参考（官方/学术/工具命令/中文资源） |

