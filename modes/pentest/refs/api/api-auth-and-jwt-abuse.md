---
name: api-auth-and-jwt-abuse
description: >-
  API authentication and JWT abuse playbook. Use when testing bearer tokens, API keys, claim trust, header spoofing, rate limits, and API auth boundary weaknesses.
---

# SKILL: API Auth and JWT Abuse — Token Trust, Header Tricks, and Rate Limits

> **AI LOAD INSTRUCTION**: Use this skill when APIs rely on JWT, bearer tokens, API keys, or weak request identity signals. Focus on token trust boundaries, claim misuse, header spoofing, and rate-limit bypass.

## 1. TOKEN TRIAGE

Inspect:

- `alg`, `kid`, `jku`, `x5u`
- role, org, tenant, scope, or privilege claims
- issuer and audience mismatches
- reuse of mobile and web tokens across products

## 2. QUICK ATTACK PICKS

| Pattern | First Test |
|---|---|
| `alg:none` acceptance | unsigned token with trailing dot |
| RS256 confusion | switch to HS256 using public key as secret |
| `kid` lookup trust | path traversal or injection in `kid` |
| remote key fetch trust | attacker-controlled `jku` or `x5u` |
| weak secret | offline crack with targeted wordlists |

## 3. HIDDEN FIELDS AND BATCH ABUSE

### Mass assignment field picks

```text
role
isAdmin
admin
verified
plan
tier
permissions
org
owner
```

### Rate limit and batch abuse picks

```text
X-Forwarded-For: 1.2.3.4
X-Real-IP: 5.6.7.8
Forwarded: for=9.9.9.9
```

GraphQL or JSON batch abuse candidates:

- arrays of login mutations
- bulk object fetches with varying IDs
- repeated password reset or verification calls in one request

## 4. RATE LIMIT BYPASS FAMILIES

```text
X-Forwarded-For
X-Real-IP
Forwarded
User-Agent rotation
Path case / slash variants
```

## 5. NEXT ROUTING

- For GraphQL batching and hidden parameters: [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md)
- For default credential and brute-force planning: [authentication bypass](../authbypass-authentication-flaws/SKILL.md)
- For full JWT and OAuth depth: [jwt oauth token attacks](../jwt-oauth-token-attacks/SKILL.md)
- For OAuth or OIDC configuration flaws in browser and SSO flows: [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- For credentialed browser reads and origin trust bugs: [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md)

## 6. CLIENT_CREDENTIALS 弱口令面（2026 社区实战）

> 来源：奇安信攻防社区《AI 渗透初探》（forum.butian.net/share/4944）——登录框无注册口、无凭据时的非预期突破。

OAuth2 四模式中 `client_credentials` 是服务端对服务端的授权：**不需要用户参与，拿到 client_id + client_secret
即拿到客户端身份的 access_token**。实战面：

```
POST /auth/oauth2/token HTTP/1.1
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

- 攻击判定顺序：JS/接口里发现 `/auth/oauth2/token` 或任意 token 端点 → 尝试 `grant_type=client_credentials`
  （多数测试者只会打 authorization_code 的劫持链，这个模式常被遗忘）→ Basic 头爆破弱口令；
- 字典要点：client_id/client_secret 常见**对称默认值**（`app:app`、`client:client`、`id:secret`），
  再叠加目标业务名组合（`xxx:xxx`）；批量生成 base64 后的 Authorization 字典；
- 拿到 token 后的扩线：token 复用到 JS 收集的其他接口（同样的 Bearer 凭据常覆盖后台 API）；
  AI/自研工具辅助解密下游拿到的加密凭据（hashcat/john 按密文形态识别）。
- 来源: [奇安信攻防社区 — AI 渗透初探](https://forum.butian.net/share/4944)
