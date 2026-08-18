# 编码解码

_6 条工具命令_

### Base64编码  `base64-encode`
_Base64编码/解码命令集合_

**Step 0**
> 各平台Base64编码方法
```
# Linux:
echo -n "payload" | base64
base64 file.txt > encoded.txt

# Windows PowerShell:
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("payload"))

# Python:
python3 -c "import base64; print(base64.b64encode(b'payload').decode())"
```

**Step 0**
> 各平台Base64解码方法
```
# Linux:
echo "cGF5bG9hZA==" | base64 -d
base64 -d encoded.txt > decoded.txt

# Windows PowerShell:
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("cGF5bG9hZA=="))

# Python:
python3 -c "import base64; print(base64.b64decode('cGF5bG9hZA==').decode())"
```

**Step 0**
> URL安全的Base64编码(+/替换为-_)
```
# Python:
import base64
base64.urlsafe_b64encode(b"payload").decode()
base64.urlsafe_b64decode("cGF5bG9hZA==").decode()
```

---

### URL编码  `url-encode`
_URL编码/解码命令集合_

**Step 0**
> URL编码方法(单次/双重)
```
# Python:
python3 -c "from urllib.parse import quote; print(quote('<script>alert(1)</script>'))"

# 双重编码:
python3 -c "from urllib.parse import quote; print(quote(quote('<script>alert(1)</script>')))"

# CyberChef在线: https://gchq.github.io/CyberChef/
```

**Step 0**
> URL解码方法
```
# Python:
python3 -c "from urllib.parse import unquote; print(unquote('%3Cscript%3Ealert(1)%3C%2Fscript%3E'))"

# Linux:
printf '%b' "\x3Cscript\x3E"
```

---

### Hex编码  `hex-encode`
_十六进制编码/解码命令集合_

**Step 0**
> 十六进制编码方法
```
# Linux:
echo -n "payload" | xxd -p
echo -n "payload" | od -A n -t x1 | tr -d " \n"

# Python:
python3 -c "print('payload'.encode().hex())"
python3 -c "print('\\x'.join([hex(ord(c))[2:] for c in 'payload']))"
```

**Step 0**
> 十六进制解码方法
```
# Linux:
echo "7061796c6f6164" | xxd -r -p

# Python:
python3 -c "print(bytes.fromhex('7061796c6f6164').decode())"
```

**Step 0**
> 在SQL注入和XSS中使用十六进制编码
```
# SQL注入中使用:
SELECT 0x61646D696E  -- "admin"

# XSS中使用:
<img src=x onerror=\x61\x6c\x65\x72\x74(1)>
```

---

### HTML编码  `html-encode`
_HTML实体编码/解码命令集合_

**Step 0**
> HTML实体编码(命名/十进制/十六进制)
```
# Python:
python3 -c "import html; print(html.escape('<script>alert(1)</script>'))"

# 数字编码:
python3 -c "print(''.join(['&#'+str(ord(c))+';' for c in '<script>alert(1)</script>']))"

# 十六进制HTML编码:
python3 -c "print(''.join(['&#x'+hex(ord(c))[2:]+';' for c in 'alert']))"
```

**Step 0**
> HTML实体解码
```
# Python:
python3 -c "import html; print(html.unescape('&lt;script&gt;alert(1)&lt;/script&gt;'))"
```

**Step 0**
> XSS绕过常用的HTML实体对照
```
# 常用HTML实体:
# < => &lt; 或 &#60; 或 &#x3c;
# > => &gt; 或 &#62; 或 &#x3e;
# " => &quot; 或 &#34; 或 &#x22;
# ' => &apos; 或 &#39; 或 &#x27;
# & => &amp; 或 &#38; 或 &#x26;
```

---

### Unicode编码  `unicode-encode`
_Unicode编码/解码命令集合_

**Step 0**
> Unicode各种编码形式
```
# Python Unicode转义:
python3 -c "print(''.join(['\\u'+hex(ord(c))[2:].zfill(4) for c in 'alert']))"
# 输出: \u0061\u006c\u0065\u0072\u0074

# UTF-8字节:
python3 -c "print('alert'.encode('utf-8'))"
```

**Step 0**
> Unicode解码方法
```
# Python:
python3 -c "print('\\u0061\\u006c\\u0065\\u0072\\u0074'.encode().decode('unicode_escape'))"

# JavaScript:
console.log("\u0061\u006c\u0065\u0072\u0074")
```

**Step 0**
> 使用Unicode编码绕过WAF/过滤
```
# JavaScript Unicode绕过:
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

# Overlong UTF-8编码:
# / => %c0%af (可绕过路径过滤)
# . => %c0%ae
```

---

### JWT解码  `jwt-decode`
_JWT(JSON Web Token)解码和分析工具_

**Step 0**
> 使用在线工具解码JWT
```
# 在线工具:
# https://jwt.io
# https://token.dev
# 粘贴JWT即可查看Header和Payload
```

**Step 0**
> 使用Python命令行解码JWT
```
# Python:
python3 -c "
import base64, json, sys
token = sys.argv[1]
parts = token.split('.')
for i, part in enumerate(parts[:2]):
    padded = part + '=' * (4 - len(part) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    print(json.dumps(json.loads(decoded), indent=2))
" YOUR_JWT_HERE
```

**Step 0**
> JWT结构分析和安全检查要点
```
# JWT结构: Header.Payload.Signature
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"sub":"1234","name":"user","iat":1516239022}
# Signature: HMACSHA256(base64url(header)+"."+base64url(payload), secret)

# 检查要点:
# 1. alg是否可改为none
# 2. 密钥是否为弱密码
# 3. 是否可将RS256改为HS256
# 4. exp是否已过期
```

---

### 冷门编码工具链  `encoding-edge-cases`
_UTF-7 / UTF-16 / 超长 UTF-8 / Unicode 规范化（NFKC/NFD）编解码命令（WAF 绕过用）_

**Step 0**
> UTF-7 编码/解码
```
# 编码（iconv）
echo -n '<script>alert(1)</script>' | iconv -f UTF-8 -t UTF-7
# 输出: +ADw-script+AD4-alert(1)+ADw-/script+AD4-

# 解码（iconv）
echo -n '+ADw-script+AD4-' | iconv -f UTF-7 -t UTF-8

# Python（UTF-7 编码）
python3 -c "print('<script>'.encode('utf-7').decode())"
```

**Step 0**
> UTF-16 编码/解码
```
# 编码（UTF-16LE 十六进制）
python3 -c "print('<script>'.encode('utf-16le').hex())"
# 3c 00 73 00 63 00 ...

# %u 形式（IIS 类历史解码）
# %u003Cscript%u003E

# 解码（UTF-16LE）
python3 -c "print(bytes.fromhex('3c007300630072006900700074003e').decode('utf-16le'))"
```

**Step 0**
> 超长 UTF-8（Overlong）编码
```
# 概念：用非最短字节序编码同一字符（历史解析器宽松时接受）
# 如 '/' (0x2F) 的超长二字节形式: %c0%af
# '.' (0x2E) 的超长二字节形式: %c0%ae

# Python 生成超长编码（仅作结构示意，按需自实现）
python3 -c "print('%c0%af %c0%ae')"
```

**Step 0**
> Unicode 规范化（NFKC / NFD）
```
# NFKC：全角→半角、兼容字符合并（后端归一化后成为危险字符）
python3 -c "import unicodedata; print(unicodedata.normalize('NFKC', '＜script＞'))"
# 输出: <script>

python3 -c "import unicodedata; print(unicodedata.normalize('NFKC', 'ＳＥＬＥＣＴ'))"
# 输出: SELECT

# NFD：分解重音（é → e + 组合重音）
python3 -c "import unicodedata; print(unicodedata.normalize('NFD', 'é'))"
# 输出: é

# 生成全角变体
python3 -c "
s='<script>'
print(''.join(chr(0xFEE0+ord(c)) if 0x21<=ord(c)<=0x7E else c for c in s))
"
# 输出: ＜ｓｃｒｉｐｔ＞
```

**Step 0**
> 判据（何时算绕过）
```
1. 后端确实「解码/规范化后执行」才构成绕过（XSS 触发/SQL 生效/路径穿越成功）
2. 后端原样返回编码串 = 无效，换一层编码或换目标解析器
3. 组合顺序：编码叠加（双重 URL + 全角 + 注释拆分）比单层更稳
```

---

> 详见 `../../web/waf-bypass-techniques.md` 2.11 节与 `../waf-bypass-payloads.md` 冷门编码段。
