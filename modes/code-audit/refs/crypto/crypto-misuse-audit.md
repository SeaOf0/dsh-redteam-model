---
name: crypto-misuse-audit
description: 加密误用源码审计专项（逐语言 sink 表 + 签名验证绕过模式）。JWT alg=none/弱密钥/算法混淆、verify 返回值被忽略、length extension、Java SecureRandom vs Random、Node crypto.randomBytes vs Math.random、Python secrets vs random 等。与 crypto-implementation.md（工程实现视角）互补。
---

# 加密误用源码审计（crypto-misuse-audit）

> 定位：`crypto-implementation.md` 是工程实现视角（padding oracle/ECB/GCM nonce 重用/侧信道/PQC），
> 本篇是**源码审计视角的逐语言 sink 大表**与**签名验证绕过模式**——补齐「nonce/IV/弱随机数/
> 硬编码密钥」之外的「签名验证缺失/绕过」这一缺口。

## 0. 签名验证绕过模式清单（最高优先）

| 模式 | 危险形态 | 判据 |
|------|----------|------|
| **JWT `alg=none`** | 库接受 `alg:none`，跳过签名验证 | 校验代码是否显式拒绝 `none` 算法 |
| **JWT 弱密钥** | HS256 密钥可枚举（短/默认/硬编码） | 密钥长度与来源（硬编码/默认值） |
| **JWT 算法混淆** | RS256 公钥被当 HS256 密钥（用公钥签名） | 是否强制指定算法 + 区分公私钥用途 |
| **verify 返回值忽略** | `verify()` 返回值未判 `false` 就放行 | 校验调用是否检查布尔返回值/异常 |
| **Length Extension** | MD5/SHA1/SHA2 对 `secret + data` 签名可被扩展 | HMAC 是否用 `H(key‖msg)` 而非 `HMAC` |
| **签名缺失** | 只验「数据可解析」不验「签名有效」 | 解码（decode）与验签（verify）是否分离且都执行 |

## 1. 逐语言 sink 大表

### 1.1 Java

| 类别 | 危险 sink | 安全替代 |
|------|-----------|----------|
| 弱随机数 | `new java.util.Random()` / `Math.random()` | `java.security.SecureRandom`（`getInstanceStrong()`） |
| 弱哈希 | `MessageDigest.getInstance("MD5"/"SHA1")` | `SHA-256` 及以上；密码用 Argon2/BCrypt |
| 弱加密 | `Cipher.getInstance("DES"/"AES/ECB"/"RSA"无 padding)` | `AES/GCM/NoPadding`、`RSA/ECB/OAEPWithSHA-256AndMGF1Padding` |
| JWT | `JWT.require(Algorithm.none())`、HS256 弱密钥 | 强制算法 + 公钥验签 |
| 硬编码密钥 | `private static final String SECRET = "..."` | Vault/KMS/环境变量 |

```bash
grep -rn 'new Random()\|Math.random\|MD5\|SHA1\b\|DES\|ECB\|Algorithm.none\|Jwts.parser' --include='*.java' .
```

### 1.2 Node.js / JavaScript

| 类别 | 危险 sink | 安全替代 |
|------|-----------|----------|
| 弱随机数 | `Math.random()`（token/nonce/IV） | `crypto.randomBytes` / `crypto.randomUUID` |
| 弱哈希 | `crypto.createHash('md5'/'sha1')` | `sha256`；密码 `scrypt`/`argon2` |
| JWT | `jwt.verify(token, secret, { algorithms:['none'] })`、`jwt.decode` 后未 verify | 显式 `algorithms:['HS256']` + `verify` |
| 硬编码密钥 | `const SECRET = "..."` | 环境变量/secret manager |

```bash
grep -rn 'Math.random\|createHash(.md5\|createHash(.sha1\|jwt.decode\|algorithms.*none\|jsonwebtoken' --include='*.js' --include='*.ts' .
```

### 1.3 Python

| 类别 | 危险 sink | 安全替代 |
|------|-----------|----------|
| 弱随机数 | `random.randint/random/choice`（token/OTP） | `secrets.token_urlsafe` / `secrets.randbelow` |
| 弱哈希 | `hashlib.md5/sha1` | `hashlib.sha256`；密码 `argon2`/`bcrypt` |
| JWT | `jwt.decode(token, options={"verify_signature": False})`、`algorithms=["none"]` | 显式 `algorithms=["HS256"]` + 强制验签 |
| Length Extension | `hashlib.sha256(secret + data).hexdigest()` 做 MAC | `hmac.new(secret, data, hashlib.sha256)` |

```bash
grep -rn 'random\.\(randint\|random\|choice\)\|hashlib.md5\|hashlib.sha1\|verify_signature.*False\|algorithms=.*none\|jwt.decode' --include='*.py' .
```

### 1.4 Go / Rust / PHP

| 语言 | 危险 sink | 安全替代 |
|------|-----------|----------|
| Go | `math/rand`（`rand.Intn`）、`crypto/md5`、`crypto/sha1`、JWT 不验签名 | `crypto/rand`、`crypto/sha256`、验签 + `alg` 白名单 |
| Rust | `rand::thread_rng` 误用于密码学、`md5`/`sha1` crate | `rand::rngs::OsRng`、`sha2`、`argon2` |
| PHP | `rand()/mt_rand()`、`md5()/sha1()`（密码）、`JWT::decode` 不验签名 | `random_bytes()`、`password_hash`（bcrypt/argon2）、验签 |

## 2. 签名验证绕过审计要点（入口识别 → 验证方法）

### 2.1 JWT `alg=none` / 算法混淆

```python
# ❌ Python 不验签名
jwt.decode(token, key, algorithms=["none"])  # 接受 none

# ❌ 不验签名（verify_signature=False）
jwt.decode(token, options={"verify_signature": False})

# ✅ 强制算法 + 验签
jwt.decode(token, key, algorithms=["HS256"])
```

```java
// ❌ Java none 算法
JWT.require(Algorithm.none()).build().verify(token);

// ✅ 强制 RS256/HS256 + 指定公钥
JWT.require(Algorithm.RSA256(publicKey, null)).build().verify(token);
```

**验证方法**：构造 `alg=none` 的 JWT（去掉签名段），观察服务端是否放行；算法混淆则用
RS256 公钥作 HS256 密钥重签名测试。

### 2.2 verify 返回值忽略

```python
# ❌ 忽略返回值
hmac.compare_digest(got, want)   # 结果未判断
# ❌ 异常未捕获/未阻断
try:
    jwt.decode(...)
except Exception:
    pass   # 静默吞掉验签失败
```

**验证方法**：伪造签名/篡改 payload，观察是否仍被放行（说明验签结果未被用于阻断）。

### 2.3 Length Extension（HMAC 误用）

```python
# ❌ H(secret ‖ message) 可被 length extension 攻击
sig = hashlib.sha256(secret.encode() + data).hexdigest()

# ✅ 用 HMAC
sig = hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
```

**验证方法**：若 MAC 用 `H(secret‖data)` 形式且 hash 为 MD5/SHA1/SHA2，攻击者可追加数据
扩展有效签名（用 `hashpump` 类工具验证）。

## 3. 修复建议（按层）

1. **随机数**：安全场景一律密码学安全随机源（`SecureRandom`/`crypto.randomBytes`/`secrets`/`OsRng`）。
2. **哈希/加密**：密码用 Argon2/BCrypt；数据哈希用 SHA-256+；对称加密用 AES-GCM；RSA 用 OAEP。
3. **签名**：JWT 显式算法白名单 + 强密钥 + 验签结果必须阻断；MAC 用 HMAC 而非裸 hash。
4. **密钥**：硬编码密钥清零，走 secret manager；密钥轮转。

## 来源

- OWASP Cryptographic Failures（A02:2021）：<https://owasp.org/Top10/A02_2021-Cryptographic_Failures/>
- JWT `alg:none` / 算法混淆：<https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens>
- Length Extension：<https://en.wikipedia.org/wiki/Length_extension_attack>
