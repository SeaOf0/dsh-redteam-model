---
description: "FUCK-CDN：绕过CDN查询网站真实源站IP。输入目标域名，按优先级自动穷尽所有OSINT方法，构建证据链输出最终判定。支持 Shodan/FOFA/Censys 等 API Key 注入，自动适配 Windows/Linux。"
---

# FUCK-CDN — 穷尽一切手段，扒光 CDN 的底裤，找到真实 IP

## 调用方式

用户输入目标域名即启动：`example.com` 或 `sub.example.com`

---

## API Key 配置

以下 Key 由用户按需填入。**留空则跳过对应模块**，不报错。Key 越多精度越高。

```
SHODAN_API_KEY     = ""
FOFA_EMAIL         = ""
FOFA_API_KEY       = ""
CENSYS_API_ID      = ""
CENSYS_API_SECRET  = ""
SECURITYTRAILS_KEY = ""
ZOOMEYE_API_KEY    = ""
QUAKE_API_KEY      = ""
HUNTER_API_KEY     = ""
VIRUSTOTAL_KEY     = ""
```

用户在对话中提供 Key（如"我的 Shodan key 是 xxx"）时，仅在内存中使用，**绝不写入文件、输出到屏幕、提交到 git**。

---

## 跨平台适配规则

开始执行前先检测当前平台：

```
if platform == win32:
    shell = PowerShell       # 使用 PowerShell 工具
    nslookup 可用，dig 通常不可用
    openssl 通过 Git Bash（Bash 工具）执行
    curl 通过 Bash 工具执行（Git Bash 自带 curl）
    python 命令用 python 而非 python3
    临时文件路径用 $env:TEMP 而非 /tmp
else:
    shell = Bash
    dig/host/whois 可能可用
    openssl/curl 直接使用
    python 命令用 python3
    临时文件路径用 /tmp
```

**原则**：
- `nslookup` 跨平台可用，优先使用
- `curl` / `openssl` 统一走 **Bash 工具**（Windows 上 Git Bash 自带）
- `dig` / `host` / `whois` 仅 Linux/macOS 可用，Windows 上用 `nslookup` 或 WebFetch 替代
- Python 脚本中 Windows 用 `python`，Linux 用 `python3`

---

## 核心原则

1. **最小 Token 优先**：按优先级执行，P0 方法命中即进入验证，未命中再升级到 P1、P2、P3
2. **早停机制**：当 P0/P1 阶段已有 2+ 独立来源交叉确认同一 IP，直接进入验证阶段，不必穷尽所有 P2/P3 方法
3. **晚停兜底**：如果到 P2 仍无候选 IP，才执行全部 P3 高级方法
4. **死磕到底**：如果 P0-P3 + CDN 特定绕过 + 通用绕过全部失败，进入 P4 深度挖掘——穷尽一切非常规手段，不留死角
5. **证据分级**：每条发现标注强度（决定性 / 强佐证 / 弱线索 / 已排除）
6. **误判排除**：每个候选 IP 必须通过验证流程，排除 CDN/WAF/废弃服务器
7. **并行执行**：同一优先级内的独立步骤并行调用，节省 Token 和时间

---

## 优先级分层

| 优先级 | 方法类别 | Token 成本 | 命中率 | 说明 |
|---|---|---|---|---|
| **P0** | 快速低成本 | 极低 | 高 | DNS 记录泄露、SPF/MX、历史 DNS 回溯 |
| **P1** | 中等成本 | 中 | 中高 | SSL 证书比对、子域名枚举、HTTP 行为分析 |
| **P2** | 较高成本 | 较高 | 中 | 空间搜索引擎、Favicon/Body Hash、全端口扫描 |
| **P3** | 高成本/手动 | 高 | 低 | 邮件触发、源码审计、同组织关联、CDN 特定绕过 |
| **P4** | 深度挖掘 | 极高 | 不定 | 穷尽一切非常规手段：时间线考古、被动流量分析、云厂商元数据、WAF 绕过、社工辅助等 |

**执行策略**：P0 全部执行 → 有候选则验证 → 无候选执行 P1 → 有候选则验证 → 无候选执行 P2 → ... → P3

---

## P0：快速命中（必须全部执行）

所有 P0 步骤并行执行，总成本极低。

### P0-1：SPF/MX/TXT 记录直接泄露

```bash
# 这些记录经常直接包含源站 IP
nslookup -type=TXT <root_domain>          # 看 SPF: v=spf1 ip4:x.x.x.x
nslookup -type=MX <root_domain>           # 邮件服务器可能就是源站
nslookup -type=TXT _dmarc.<root_domain>   # DMARC 报告地址
nslookup -type=TXT _spf.<root_domain>     # SPF 子记录
```

**解析 SPF**：如果 TXT 记录包含 `v=spf1 ip4:1.2.3.4` 或 `v=spf1 include:... ip4:1.2.3.4`，这个 IP 极可能是源站。

**解析 MX**：MX 记录指向的主机名再做 A 记录解析，如果不是第三方邮件服务（Gmail/QQ 企业邮/阿里企业邮），则可能是源站自建邮件。

### P0-2：IPv6 记录

```bash
nslookup -type=AAAA <target>
nslookup -type=AAAA <root_domain>
```

很多站只给 IPv4 接了 CDN，IPv6 AAAA 记录直接指向源站。

### P0-3：历史 DNS 回溯（最高命中率方法）

**并行查询以下平台**：

```
WebFetch: https://ipchaxun.com/<target>/
  → prompt: "提取所有历史 IP 地址及日期范围，重点关注最早的记录"

WebFetch: https://ipchaxun.com/<root_domain>/
  → prompt: "提取所有历史 IP 地址及日期范围，重点关注最早的记录"

WebFetch: https://site.ip138.com/<root_domain>/
  → prompt: "提取所有绑定过的域名和 IP 地址及日期"
```

**关键分析**：
- 找**最早的** A 记录 IP — 通常是 CDN 接入前的源站
- 找 CDN 启用的时间拐点 — 拐点前后 IP 数量从 1-2 个暴增到 10+ 个
- 长期稳定的 1-2 个 IP = 可能是源站；大量频繁变化的 IP = CDN 节点

### P0-4：基础 DNS + CDN 识别（画像用，同步进行）

```bash
nslookup <target>             # CNAME 链 → 识别 CDN 类型
nslookup <root_domain>        # 根域是否也走 CDN
nslookup -type=NS <root_domain>  # DNS 托管商
nslookup -type=SOA <root_domain> # 权威 DNS
```

CDN CNAME 指纹表：

| CNAME 关键字 | CDN |
|---|---|
| `cloudflare` | Cloudflare |
| `eo.dnse5.com` / `edgeone` | 腾讯 EdgeOne |
| `cdn.dnsv1.com` | 腾讯云 CDN |
| `kunlun` / `tbcache` / `alikunlun` / `cdngslb` | 阿里云 CDN/DCDN |
| `cdnhwc` / `huaweicloud` | 华为云 CDN |
| `cloudfront.net` | AWS CloudFront |
| `azureedge.net` / `azurefd.net` | Azure CDN/Front Door |
| `fastly.net` / `fastlylb.net` | Fastly |
| `akamai` / `akamaiedge` / `akadns` | Akamai |
| `cdn77.org` | CDN77 |
| `kxcdn.com` / `keycdn` | KeyCDN |
| `stackpathdns` / `highwinds` / `hwcdn` | StackPath |
| `vercel-dns.com` | Vercel |
| `netlify` | Netlify |
| `incapdns.net` / `impervadns` | Imperva/Incapsula |
| `sucuri.net` | Sucuri WAF |
| `baidustatic` / `bdydns` / `bcebos` | 百度云 CDN |
| `wscloudcdn` / `ourwebpic` / `wswebpic` | 网宿 CDN |
| `lxdns.com` / `chinacache` | 蓝汛 CDN |
| `ccgslb.com` | 联通 CDN |
| `bsclink` / `bsgslb` | 白山云 CDN |
| `jiashule.com` / `jiasule` | 知道创宇加速乐 |
| `yundunddos` / `yundun` | 云盾 |
| `nscloudwaf` | 创宇盾 |
| `365cyd` | 365 CDN |
| `anquanbao` | 安全宝 |
| `doyocdn` | DoYo CDN |

同时通过 HTTP 响应头确认：

```bash
curl -sI -m 10 https://<target> -A "Mozilla/5.0"
```

响应头指纹表：

| 响应头 | CDN |
|---|---|
| `Server: cloudflare` + `CF-RAY` | Cloudflare |
| `Server: TencentEdgeOne` + `EO-LOG-UUID` | 腾讯 EdgeOne |
| `Server: Tengine` / `EagleId` / `Via: cache*.cn` | 阿里云 CDN |
| `X-Cache-Lookup` + `Server: JSP3/2.0.14` | 腾讯云 CDN |
| `Via: *.cloudfront.net` / `X-Amz-Cf-*` | AWS CloudFront |
| `X-Azure-Ref` / `X-MSEdge-Ref` | Azure CDN/Front Door |
| `X-Fastly-Request-ID` / `Fastly-Debug-*` | Fastly |
| `X-Akamai-*` / `X-True-Cache-Key` | Akamai |
| `X-CDN: Incapsula` / `X-Iinfo` | Imperva |
| `X-Sucuri-*` | Sucuri |
| `Powered-By-ChinaCache` | 蓝汛 |
| `X-Ws-Request-Id` | 网宿 |
| `Server: yunjiasu` / `X-Jiasule-*` | 加速乐 |
| `X-Via: *.hwcdn.net` | StackPath/Highwinds |
| `X-HW-*` | 华为云 CDN |

**同时注意泄露头**（有的 CDN/反代配置不当会直接暴露源站）：
- `X-Real-IP` / `X-Forwarded-For`（可能是源站 IP 而非客户端 IP）
- `X-Origin-IP` / `X-Backend-Server` / `X-Backend-Host`
- `X-Upstream-Addr` / `X-Served-By`
- `Via`（某些格式会包含源站地址）

### P0 结果判断

如果 P0 产出了候选 IP → 跳转到**验证阶段**
如果无候选 IP → 继续 P1

---

## P1：证书与行为分析

### P1-1：SSL 证书指纹提取

通过 Bash 工具执行（跨平台）：

```bash
# 提取完整证书信息
echo | openssl s_client -connect <target>:443 -servername <target> 2>/dev/null | \
  openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName 2>/dev/null

# SHA256 指纹（用于空间搜索引擎）
echo | openssl s_client -connect <target>:443 -servername <target> 2>/dev/null | \
  openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256
```

记录：**Serial Number**（验证阶段的核心比对字段）、Subject CN、SHA256、SAN 列表。

### P1-2：证书透明度日志

```bash
curl -s "https://crt.sh/?q=<root_domain>&output=json" 2>/dev/null | \
  python -c "
import sys,json
try:
    data=json.load(sys.stdin)
    seen=set()
    for e in data:
        nv=e.get('name_value','')
        for name in nv.split('\n'):
            name=name.strip().lower()
            if name and name not in seen:
                seen.add(name)
                print(name)
except: pass
" 2>/dev/null
```

从 CT 日志发现的子域名，逐个做 DNS 查询，找非 CDN 的。

### P1-3：高优先级子域名枚举

```bash
# 这些子域名最可能直接暴露源站 IP
for sub in mail mx smtp pop imap webmail \
           ftp sftp ssh vpn \
           origin direct real backend internal src \
           api api2 gateway \
           admin panel cpanel whm \
           dev test staging beta uat \
           db mysql redis \
           monitor grafana zabbix \
           git gitlab jenkins ci \
           oa erp crm \
           old bak backup \
           m wap h5 app \
           pay cdn static img; do
  full="$sub.<root_domain>"
  result=$(nslookup "$full" 8.8.8.8 2>&1)

  # 判断是否绕过了 CDN
  if echo "$result" | grep -q "Address" && \
     ! echo "$result" | grep -qi "cdn\|cloudflare\|dnse5\|edgeone\|akamai\|fastly\|cloudfront\|kunlun\|tbcache\|azureedge\|incapd\|sucuri\|hwcdn\|wscloud\|lxdns"; then
    echo "[POTENTIAL] $full"
    echo "$result" | tail -5
  fi
done
```

**注意通配符**：如果所有子域名都解析到相同 CDN CNAME，说明是通配符记录 `*.domain`。此时子域名枚举方法失效，跳过。

### P1-4：CDN 节点行为基线

从 DNS 解析出的 IP 中任选一个，建立 CDN 节点的"指纹"：

```bash
CDN_IP="<dns_resolved_ip>"

# 三个测试
curl -sI -m 5 -k https://$CDN_IP                                          # 直连无 Host
curl -sI -m 5 http://$CDN_IP                                              # HTTP 直连
curl -sI -m 5 -k --resolve <target>:443:$CDN_IP https://<target>          # 带 Host
```

记录 CDN 节点的响应模式（如 EdgeOne 返回 `418`+`TencentEdgeOne`，Cloudflare 返回默认页等），后续用来区分源站。

### P1 结果判断

如果子域名枚举发现了非 CDN 的 IP → 跳转**验证阶段**
如果有历史 DNS 候选但还没验证 → 跳转**验证阶段**
如果仍无候选 → 继续 P2

---

## P2：深度搜索

### P2-1：空间搜索引擎 — 证书搜索

这是最强力的方法之一：在全网扫描数据库中搜索持有同一 SSL 证书的所有 IP。

#### Shodan（需要 SHODAN_API_KEY）

```bash
# 按证书 CN 搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=ssl.cert.subject.CN:%22<root_domain>%22"

# 按 HTTP 标题搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.title:%22<page_title>%22"

# 按 favicon hash 搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.favicon.hash:<favicon_murmur3>"

# 验证候选 IP 详情
curl -s "https://api.shodan.io/shodan/host/<candidate_ip>?key=${SHODAN_API_KEY}"
```

#### FOFA（需要 FOFA_EMAIL + FOFA_API_KEY）

```bash
# 按证书搜索
Q=$(echo -n 'cert="<root_domain>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# 按 favicon mmh3 hash 搜索
Q=$(echo -n 'icon_hash="<mmh3_hash>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# 按 body 关键字搜索
Q=$(echo -n 'body="<unique_keyword>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# 按标题搜索
Q=$(echo -n 'title="<page_title>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
```

#### Censys（需要 CENSYS_API_ID + CENSYS_API_SECRET）

```bash
# 按证书 CN 搜索
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name%3A<root_domain>&per_page=50"

# 按证书 SHA256 搜索
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.fingerprint%3A<cert_sha256>&per_page=50"
```

#### ZoomEye（需要 ZOOMEYE_API_KEY）

```bash
curl -s -H "API-KEY: ${ZOOMEYE_API_KEY}" \
  "https://api.zoomeye.org/host/search?query=ssl.cert.subject.cn%3A<root_domain>&page=1"
```

#### 360 Quake（需要 QUAKE_API_KEY）

```bash
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "X-QuakeToken: ${QUAKE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"query":"cert:\"<root_domain>\"","start":0,"size":50}'
```

#### 鹰图 Hunter（需要 HUNTER_API_KEY）

```bash
Q=$(echo -n 'cert.subject.cn="<root_domain>"' | base64)
curl -s "https://hunter.qianxin.com/openApi/search?api-key=${HUNTER_API_KEY}&search=${Q}&page=1&page_size=100"
```

#### SecurityTrails（需要 SECURITYTRAILS_KEY）

```bash
curl -s "https://api.securitytrails.com/v1/history/<root_domain>/dns/a" \
  -H "APIKEY: ${SECURITYTRAILS_KEY}"
```

#### VirusTotal（需要 VIRUSTOTAL_KEY）

```bash
curl -s "https://www.virustotal.com/api/v3/domains/<root_domain>/resolutions" \
  -H "x-apikey: ${VIRUSTOTAL_KEY}"
```

#### 无 Key 时替代方案

```
WebSearch: site:shodan.io "<root_domain>"
WebSearch: site:search.censys.io "<root_domain>"
WebSearch: fofa.info "<root_domain>" cert
WebFetch: https://www.shodan.io/search?query=ssl.cert.subject.CN%3A<root_domain>
```

### P2-2：Favicon Hash 计算

```bash
# 下载 favicon
curl -sL -m 10 -o /tmp/fav.ico "https://<target>/favicon.ico" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 计算 hash（跨平台 Python）
python -c "
import hashlib,base64,struct,sys
try:
    with open('/tmp/fav.ico','rb') as f: data=f.read()
    if len(data)<100: print('WARN: too small, likely error page'); sys.exit(1)
    b64=base64.encodebytes(data)
    # mmh3 hash (FOFA/Shodan)
    try:
        import mmh3
        print(f'FOFA: icon_hash=\"{mmh3.hash(b64)}\"')
    except ImportError:
        print('mmh3 not installed, try: pip install mmh3')
    print(f'MD5: {hashlib.md5(data).hexdigest()}')
    print(f'SHA256: {hashlib.sha256(data).hexdigest()}')
except Exception as e: print(f'Error: {e}')
"
```

### P2-3：多端口扫描

```bash
CANDIDATE="<candidate_ip>"
for port in 80 81 443 2052 2053 2082 2083 2086 2087 2095 2096 \
            3000 4443 5000 8000 8001 8008 8080 8081 8443 8880 8888 9000 9090 9443; do
  r=$(curl -sI -m 2 -k https://$CANDIDATE:$port 2>&1 | head -1)
  [ -n "$r" ] && ! echo "$r"|grep -q "curl:" && echo "HTTPS:$port $r"
  r=$(curl -sI -m 2 http://$CANDIDATE:$port 2>&1 | head -1)
  [ -n "$r" ] && ! echo "$r"|grep -q "curl:" && echo "HTTP:$port  $r"
done
```

### P2-4：IP 反查确认

对每个候选 IP：

```
WebFetch: https://ipchaxun.com/<candidate_ip>/
  → prompt: "提取该IP的归属地、运营商、以及绑定过的所有域名列表"

WebFetch: https://site.ip138.com/<candidate_ip>/
  → prompt: "提取该IP绑定过的所有域名及时间"
```

### P2-5：网站特征指纹搜索

```bash
# 获取页面源码，提取唯一特征
PAGE=$(curl -s -m 10 https://<target> -A "Mozilla/5.0")

# 提取 title
echo "$PAGE" | grep -oiE '<title>[^<]+</title>'

# 查找页面中硬编码的 IP
echo "$PAGE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'

# 查找 JS/CSS 资源路径（可能指向非 CDN 源）
echo "$PAGE" | grep -oE '(src|href)="https?://[^"]*"'

# 查找唯一关键字（版权声明、特殊 ID 等）
echo "$PAGE" | grep -oiE '(copyright|powered by|generator)[^<]*'
```

---

## P3：高级 / 手动方法

仅在 P0-P2 均未找到候选 IP 时执行。

### P3-1：邮件触发法

提示用户操作：

```
请尝试以下操作，然后将邮件原始头部（raw headers）粘贴给我：
1. 在目标网站注册一个账号（会收到验证邮件）
2. 或使用"找回密码"功能
3. 或使用"联系我们"表单

收到邮件后，查看邮件原始头部（Gmail: 显示原始邮件; QQ邮箱: 显示邮件头），
重点关注 Received: 字段中的 IP 地址。
```

解析 `Received:` 头中的 IP：

```
Received: from mail.example.com (1.2.3.4) by ...
→ 1.2.3.4 很可能是源站 IP
```

### P3-2：网站源码深度审计

```bash
# phpinfo 泄露
for path in phpinfo.php info.php test.php pi.php; do
  curl -sI -m 3 "https://<target>/$path" -A "Mozilla/5.0"
done

# 环境文件泄露
for path in .env .env.local .env.production config.php wp-config.php; do
  curl -sI -m 3 "https://<target>/$path"
done

# robots.txt / sitemap / crossdomain
curl -s -m 5 "https://<target>/robots.txt"
curl -s -m 5 "https://<target>/sitemap.xml" | head -30
curl -s -m 5 "https://<target>/crossdomain.xml"
curl -s -m 5 "https://<target>/.well-known/security.txt"

# JS 文件中的 API 地址/IP
curl -s "https://<target>" | grep -oE 'src="[^"]*\.js"' | head -10
# 对每个 JS 文件：
curl -s "<js_url>" | grep -oE '(https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|api[._-]?url|baseURL|endpoint)[^"'"'"']*'
```

### P3-3：Web Archive

```
WebFetch: https://web.archive.org/web/2024*/https://<target>
→ 查找 CDN 接入前的历史快照，提取其中的绝对 URL
```

### P3-4：DNS Zone Transfer

```bash
# 仅 Linux/macOS
dig @<ns_server> <root_domain> AXFR 2>&1 | head -50
```

### P3-5：DNSSEC NSEC Walking

```bash
nslookup -type=NSEC <root_domain>
# 仅 Linux/macOS
dig <root_domain> NSEC +short
```

### P3-6：同组织域名关联

```
WebSearch: "<registrant_email>" 域名注册
WebSearch: "<registrant_org>" 域名 备案
WebSearch: site:whois "<registrant_name>"
```

找到同一注册人/组织的其他域名 → 查这些域名的 A 记录 → 可能共用源站。

### P3-7：Google Analytics / AdSense ID 关联

```bash
# 提取页面中的 GA/AdSense ID
curl -s "https://<target>" | grep -oE 'UA-[0-9]+-[0-9]+|G-[A-Z0-9]+|ca-pub-[0-9]+'
```

用提取到的 ID 搜索：`WebSearch: "UA-XXXXXX" site`，找到使用同一统计 ID 的其他网站，这些网站可能直接暴露源站 IP。

### P3-8：SSH / FTP 探测

```bash
CANDIDATE="<candidate_ip>"
# SSH banner grab
timeout 3 bash -c "echo '' | curl -s -m 3 telnet://$CANDIDATE:22" 2>&1 | head -1
# FTP banner grab
curl -s -m 3 ftp://$CANDIDATE/ 2>&1 | head -3
```

SSH/FTP 存在 = 真实服务器（CDN 节点不开放这些端口）。

### P3-9：WebSocket 探测

```bash
# 检查目标是否使用 WebSocket
curl -s "https://<target>" | grep -i "websocket\|ws://\|wss://"
# 某些 CDN 不完全代理 WebSocket 的握手过程，可能泄露源站
```

### P3-10：CORS / CSP 头分析

```bash
# 某些 CORS 配置会泄露源站域名或 IP
curl -sI -m 5 -H "Origin: https://evil.com" https://<target>
# 检查 Access-Control-Allow-Origin
# 检查 Content-Security-Policy 中的 connect-src / script-src
```

### P3-11：/24 邻居扫描

如果有一个可能的源站 IP 但不确定：

```bash
# 扫描同 C 段
# 仅在有空间搜索引擎 Key 时有效
Q=$(echo -n 'ip="<candidate_ip>/24"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
```

---

## CDN 特定绕过方法

根据阶段 P0-4 识别到的 CDN 类型，执行对应的特定绕过技术。

### Cloudflare

```bash
# 1. Cloudflare 仅代理特定端口，非代理端口直达源站
#    HTTP 代理端口: 80, 8080, 8880, 2052, 2082, 2086, 2095
#    HTTPS 代理端口: 443, 2053, 2083, 2087, 2096, 8443
#    其他端口（如 8888, 9090, 21, 22）不经过 Cloudflare
for port in 21 22 25 8888 9090 3306 5432; do
  curl -sI -m 2 http://<target>:$port 2>&1 | head -3
done

# 2. CrimeFlare / CloudFlair 数据库
WebSearch: "<root_domain>" site:crimeflare.org
WebSearch: "<root_domain>" cloudflare bypass real IP

# 3. direct-connect 子域名
curl -sI "https://direct.<root_domain>"
curl -sI "https://direct-connect.<root_domain>"

# 4. Cloudflare 不代理非 HTTP 协议
#    如果源站开了 FTP/SSH/SMTP，这些不经过 CF

# 5. 老旧 DNS 记录
#    Cloudflare 接入前的 A 记录（通过 P0-3 历史 DNS 查）

# 6. Cloudflare Partner 泄露
#    某些 Cloudflare 合作伙伴的 CNAME 接入可能泄露
```

### 腾讯 EdgeOne

```bash
# 特征：CNAME *.eo.dnse5.com, Server: TencentEdgeOne
# HTTP 567 = WAF 拦截, HTTP 418 = 无匹配域名

# 1. 腾讯云网络层保护
#    即使直连源站 IP + Host 头，可能仍被 EdgeOne 拦截
#    表现：返回 567 而非源站内容
#    判定：如果某 IP 对域名返回 567 但直连返回 nginx/apache → 这是源站

# 2. 源站通常在腾讯云 CVM
#    常见网段: 101.32-35.x.x, 43.x.x.x, 49.x.x.x, 118.x.x.x, 129.x.x.x
#    用历史 DNS 找到的 IP 如果在这些段内 → 重点验证

# 3. EdgeOne 的 SSL 证书由 EdgeOne 管理
#    源站可能部署了相同证书（自动同步）
#    SSL 证书比对仍然有效
```

### 阿里云 CDN / DCDN

```bash
# 特征：CNAME *.cdngslb.com / *.alikunlun.com / *.tbcache.com
# 响应头：Server: Tengine, EagleId, Via: cache*.cn

# 1. 阿里云 CDN 的回源 Host 配置
#    如果回源 Host 与加速域名不同，直接用回源 Host 访问源站 IP 可能绕过

# 2. 阿里云源站通常在 ECS
#    常见网段: 47.x.x.x, 39.x.x.x, 120.x.x.x, 121.x.x.x, 106.x.x.x

# 3. OSS Bucket 源站
#    CNAME 含 oss-cn-*.aliyuncs.com → 源站是 OSS，非传统服务器
#    此时"真实 IP"是 OSS 的 IP，意义不大

# 4. 函数计算 / Serverless
#    如果源站是 FC，同理没有固定 IP
```

### AWS CloudFront

```bash
# 特征：CNAME *.cloudfront.net, Via: *.cloudfront.net

# 1. CloudFront 仅代理 HTTP/HTTPS
#    SSH/FTP/其他端口不代理

# 2. S3 Bucket 源站
#    如果源站是 S3，域名格式 <bucket>.s3.amazonaws.com
#    尝试直接访问 S3 endpoint

# 3. ALB/ELB 源站
#    通过 DNS 枚举可能找到直接的 ALB 域名

# 4. AWS IP 段非常大
#    https://ip-ranges.amazonaws.com/ip-ranges.json 可下载
#    筛选 service=EC2 的段缩小范围

# 5. 旧 SSL 证书可能在 ACM 中有记录
```

### Azure CDN / Front Door

```bash
# 特征：CNAME *.azureedge.net / *.azurefd.net, X-Azure-Ref

# 1. Azure 源站通常在 Azure VM
#    常见域名: *.cloudapp.azure.com

# 2. Front Door 后端池探测
#    Front Door 的 health probe 路径可能暴露后端信息

# 3. 非标准端口不代理
```

### Fastly

```bash
# 特征：CNAME *.fastly.net, X-Fastly-Request-ID

# 1. Fastly 使用 Anycast，所有 CDN 节点共享 IP 池
#    nslookup 返回少量固定 IP（非基于地理的）

# 2. X-Served-By 头有时泄露 cache 节点信息

# 3. Fastly Shield 配置可能暴露源站区域
```

### Akamai

```bash
# 特征：CNAME *.akamaiedge.net / *.akamai.net, X-Akamai-*

# 1. Akamai SureRoute Test Object
#    某些配置下 /_akamai/sureroute-test-object.html 可访问

# 2. Akamai Ghost 头
#    Pragma: akamai-x-cache-on, akamai-x-get-true-cache-key
#    添加这些 Pragma 头可能获得更多源站信息
curl -sI -H "Pragma: akamai-x-cache-on, akamai-x-get-true-cache-key, akamai-x-check-cacheable, akamai-x-get-extracted-values" https://<target>

# 3. Akamai 的 staging 网络
#    将域名解析到 *.akamaiedge-staging.net 的 IP 可获得调试信息
```

### Imperva / Incapsula

```bash
# 特征：CNAME *.incapdns.net, X-CDN: Incapsula, X-Iinfo

# 1. Incapsula 的回源可能不验证 Host
#    直接 IP 访问可能返回源站内容

# 2. X-Iinfo 头包含 session 信息，可能泄露源站标识

# 3. Incapsula 仅代理 80 和 443
```

### Sucuri WAF

```bash
# 特征：CNAME *.sucuri.net, X-Sucuri-*

# 1. Sucuri 的 firewall 通常只代理 80/443
#    非标准端口直达源站

# 2. Sucuri 历史 IP
#    Sucuri 接入前的 DNS 记录通常就是源站 IP

# 3. X-Sucuri-Cache 头
```

### 华为云 CDN

```bash
# 特征：CNAME *.cdnhwc*.com, X-HW-*

# 1. 源站通常在华为云 ECS
#    通过历史 DNS + IP 反查确认

# 2. 华为云 CDN 的调试头
#    X-HW-Via 可能包含节点信息
```

### 网宿 CDN (ChinaNetCenter)

```bash
# 特征：CNAME *.wscloudcdn.com / *.ourwebpic.com, X-Ws-Request-Id

# 1. 国内老牌 CDN，早期配置可能有缺陷
# 2. 网宿的节点 IP 通常在运营商网段
# 3. 历史 DNS 回溯效果好
```

### 百度云 CDN

```bash
# 特征：CNAME *.baidustatic.com / *.bdydns.com / *.bcebos.com

# 1. BCH (百度云虚机) 源站
# 2. BOS (百度对象存储) 源站
# 3. 百度云加速的历史 DNS 泄露率较高
```

### 通用 CDN / 未知厂商（兜底）

当 CNAME / 响应头无法匹配上述任何已知厂商时，执行以下通用绕过流程：

**第一步：识别 CDN 类型**

```bash
# 1. CNAME 链追踪 — 看最终 CNAME 归属
nslookup -type=CNAME <target>
# 将末端域名（如 *.cdn.example.com）WebSearch 确认是哪家 CDN

# 2. HTTP 响应头指纹采集
curl -sI https://<target> | grep -iE "^(Server|Via|X-CDN|X-Cache|X-Served-By|X-Edge|CF-RAY|X-Amz|X-HW|X-Swift|X-Varnish|Powered-By):"
# 上述头中任意一个即可定位 CDN 厂商

# 3. IP 归属 ASN 查询
curl -s "https://ipinfo.io/<cdn_node_ip>/json" | grep -E "(org|asn)"
# ASN 名称通常直接包含 CDN 厂商名（如 AS13335=Cloudflare, AS16509=AWS）

# 4. 在线 CDN 检测服务
WebSearch: "<target>" CDN detection
WebFetch: https://check-host.net/check-dns?host=<target>
```

**第二步：通用绕过方法（适用于任何 CDN）**

```bash
# 1. 非标准端口扫描 — 绝大多数 CDN 只代理 80/443
for port in 21 22 25 81 888 2222 3000 3306 4443 5432 5900 6379 8000 8080 8443 8888 9090 9443; do
  result=$(curl -sI -m 2 http://<target>:$port 2>&1 | head -3)
  [ -n "$result" ] && echo "Port $port: $result"
done

# 2. 直接 IP 访问行为差异
#    CDN 节点通常：返回 403/421/418/502 或 CDN 自定义错误
#    源站通常：返回 200/301/nginx-apache 默认页
curl -sI -k https://<candidate_ip>
curl -sI http://<candidate_ip>
# 对比 Server 头：CDN 标识 vs 真实 Web 服务器

# 3. 协议层绕过
#    CDN 通常只代理 HTTP/HTTPS，不代理：
#    - SSH (22)、FTP (21)、SMTP (25)、数据库端口
#    直接连接这些端口可确认是否是真实服务器
timeout 3 bash -c "echo | curl -s -m 3 telnet://<candidate_ip>:22" 2>&1 | head -1
timeout 3 bash -c "echo | curl -s -m 3 telnet://<candidate_ip>:21" 2>&1 | head -1

# 4. EDNS Client Subnet 绕过
#    某些 CDN 根据客户端 IP 返回不同节点
#    使用不同地区 DNS + EDNS 可能获得不同结果
#    需要 dig 命令（Linux）
dig +subnet=0.0.0.0/0 <target> @8.8.8.8

# 5. 老旧/过期 CDN 配置
#    某些小众 CDN 仅保护主域名，www/子域名可能未接入
#    或 CDN 仅覆盖 HTTPS 而 HTTP 直连源站
curl -sI http://<target>    # HTTP 可能未走 CDN
curl -sI https://<target>   # HTTPS 走 CDN
# 对比两者 Server 头和响应 IP
```

**第三步：通用空间搜索（CDN 无关）**

```bash
# 所有空间搜索引擎方法（P2）本身就不依赖 CDN 类型
# 以下查询对任何 CDN 都有效：

# Shodan: 按 SSL 证书搜索
WebFetch: https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=ssl.cert.serial:<cert_serial>

# FOFA: 按 favicon hash 搜索
# 先计算 favicon 的 mmh3 hash，再搜索
WebFetch: https://<target>/favicon.ico  # 获取 favicon
# python3 -c "import mmh3,codecs; print(mmh3.hash(codecs.lookup('base64').encode(open('favicon.ico','rb').read())[0]))"

# Censys: 按证书指纹搜索
WebFetch: https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf.fingerprint_sha256:<sha256>&per_page=25

# 这些搜索返回的 IP 中排除 CDN ASN 后就是候选源站
```

**注意事项**：
- 对于未知 CDN，P0-P2 通用方法的命中率已经很高（历史 DNS + SSL 证书比对覆盖 80%+ 场景）
- CDN 特定绕过只是在通用方法失败时的补充
- 遇到完全未知的 CDN，优先查其文档了解代理范围（哪些端口/协议被代理），然后从未代理的端口/协议入手

---

## P4：深度挖掘（穷尽一切手段）

**触发条件**：P0-P3 通用方法 + CDN 特定绕过 + 通用 CDN 兜底均未产出可验证的候选 IP。进入此阶段意味着目标防护极强，需要动用一切非常规手段。

### P4-1：Web Archive 时间线考古

```bash
# 1. Wayback Machine 历史快照
WebFetch: https://web.archive.org/cdx/search/cdx?url=<target>&output=json&fl=timestamp,original,statuscode,mimetype&collapse=digest&limit=50

# 2. 分析历史快照中的资源引用
#    某些历史快照可能包含源站 IP 的直接引用（JS/CSS/图片 URL）
#    重点关注最早期的快照——CDN 接入前的状态
WebFetch: https://web.archive.org/web/20240101000000*/<target>

# 3. 历史快照中的响应头
#    Wayback CDX API 存储了历史响应头（部分），可能包含源站 IP
WebFetch: https://web.archive.org/cdx/search/cdx?url=<target>&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&limit=20
```

### P4-2：源码与配置文件深度审计

```bash
# 1. 常见泄露路径——逐一探测
for path in \
  "/.env" "/.env.bak" "/.env.production" "/.env.local" \
  "/wp-config.php.bak" "/wp-config.php~" "/wp-config.php.old" \
  "/config.php.bak" "/configuration.php.old" \
  "/phpinfo.php" "/info.php" "/test.php" "/i.php" \
  "/.git/config" "/.svn/entries" "/.DS_Store" \
  "/server-status" "/server-info" \
  "/.well-known/security.txt" \
  "/crossdomain.xml" "/clientaccesspolicy.xml" \
  "/sitemap.xml" "/robots.txt" \
  "/readme.html" "/README.md" \
  "/debug" "/trace" "/actuator/env" "/actuator/health" \
  "/.htaccess" "/web.config" \
  "/api/config" "/api/v1/config" "/api/debug" \
  "/graphql" "/.graphql" \
  "/swagger.json" "/swagger-ui.html" "/api-docs" \
  "/elmah.axd" "/error_log" "/errors.log"; do
  code=$(curl -sI -m 3 -o /dev/null -w "%{http_code}" "https://<target>$path")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$path → HTTP $code"
done

# 2. JS 文件中的 IP / 内网地址 / API endpoint
curl -s "https://<target>" | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | while read js; do
  [ "${js:0:2}" = "//" ] && js="https:$js"
  [ "${js:0:1}" = "/" ] && js="https://<target>$js"
  curl -s "$js" | grep -oP '(?:https?://|//)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:/]?' | sort -u
  curl -s "$js" | grep -oP '(?:https?://|//)((?:api|backend|server|origin|internal|staging|dev|admin|gateway)\.[a-z0-9.-]+)' | sort -u
done

# 3. HTML 注释中的 IP / 内网域名
curl -s "https://<target>" | grep -oP '<!--[\s\S]*?-->' | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# 4. WebSocket 连接地址
curl -s "https://<target>" | grep -oP 'wss?://[^"'"'"'\s<>]+' | sort -u
```

### P4-3：被动情报与第三方数据源

```bash
# 1. DNSDumpster — 被动 DNS 聚合
WebSearch: site:dnsdumpster.com "<root_domain>"

# 2. ThreatCrowd — 威胁情报关联
WebFetch: https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=<root_domain>

# 3. AlienVault OTX — 开源威胁情报
WebFetch: https://otx.alienvault.com/api/v1/indicators/domain/<root_domain>/passive_dns

# 4. RiskIQ / PassiveTotal（Community 版）
WebSearch: "<root_domain>" site:community.riskiq.com

# 5. BGP Toolkit — ASN 和 IP 段关联
WebSearch: "<root_domain>" bgp.he.net

# 6. Netcraft — 站点技术栈和历史
WebSearch: site:netcraft.com "<root_domain>"

# 7. BuiltWith — 技术栈指纹
WebSearch: site:builtwith.com "<root_domain>"

# 8. URLScan.io — 最近扫描记录中可能包含源站连接
WebFetch: https://urlscan.io/api/v1/search/?q=domain:<root_domain>&size=10
```

### P4-4：云厂商元数据与特征

```bash
# 1. 常见云厂商内部域名探测
#    很多源站在云上部署时有内部域名（无 CDN 保护）
for prefix in \
  "<root_domain_no_tld>" "<root_domain_no_tld>-prod" "<root_domain_no_tld>-api" \
  "<root_domain_no_tld>-backend" "<root_domain_no_tld>-origin" "<root_domain_no_tld>-server"; do
  for suffix in \
    ".vm.elb.amazonaws.com" ".elasticbeanstalk.com" \
    ".azurewebsites.net" ".cloudapp.azure.com" \
    ".appspot.com" ".run.app" \
    ".herokuapp.com" \
    ".myqcloud.com" ".ap-guangzhou.myqcloud.com" ".ap-shanghai.myqcloud.com" \
    ".aliyuncs.com" ".ecs.aliyuncs.com"; do
    ip=$(nslookup "${prefix}${suffix}" 2>/dev/null | grep -A1 "Name:" | grep "Address" | awk '{print $2}')
    [ -n "$ip" ] && echo "FOUND: ${prefix}${suffix} → $ip"
  done
done

# 2. 云厂商 IP 段筛选
#    如果已知源站在某云厂商，可从空间搜索引擎按 IP 段 + 证书缩小范围
#    AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
#    Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519
#    GCP: nslookup -type=TXT _cloud-netblocks.googleusercontent.com
```

### P4-5：WAF / 防护层穿透

```bash
# 1. HTTP 方法绕过
#    某些 WAF 只拦截 GET/POST，不拦截其他方法
for method in OPTIONS HEAD TRACE PUT DELETE PATCH CONNECT; do
  curl -s -X $method -m 3 -o /dev/null -w "$method → %{http_code} %{size_download}B\n" "https://<target>"
done

# 2. 路径混淆
#    通过特殊字符绕过 WAF 路径匹配
curl -sI "https://<target>/..;/"
curl -sI "https://<target>/%2e%2e/"
curl -sI "https://<target>/.%00/"

# 3. Host 头注入测试
#    某些服务器对异常 Host 头返回源站 IP
curl -sI -H "Host: localhost" "https://<cdn_node_ip>" -k
curl -sI -H "Host: 127.0.0.1" "https://<cdn_node_ip>" -k
curl -sI -H "Host: " "https://<cdn_node_ip>" -k

# 4. X-Forwarded-For / X-Real-IP 欺骗
#    某些后端会在响应中回显真实 IP
curl -sI -H "X-Forwarded-For: 127.0.0.1" "https://<target>"
curl -sI -H "X-Real-IP: 127.0.0.1" "https://<target>"
# 检查响应头和响应体中是否出现源站 IP

# 5. 大请求体绕过
#    某些 CDN/WAF 对超大请求体不检测直接转发
python3 -c "print('A'*1000000)" | curl -s -X POST -d @- "https://<target>" -o /dev/null -w "%{http_code} %{size_download}B"
```

### P4-6：时间维度攻击

```bash
# 1. SSL 证书续期监控
#    Let's Encrypt 证书 90 天续期，续期时的 ACME HTTP-01 验证
#    可能暂时绕过 CDN（取决于验证路径配置）
curl -sI "https://<target>/.well-known/acme-challenge/test"
# 如果返回源站特征而非 CDN 特征 → 存在绕过窗口

# 2. CDN 配置不一致时间窗
#    某些目标在更新 CDN 配置时会短暂暴露源站
#    通过反复 DNS 查询（不同时间段）捕捉配置变更瞬间
#    可设置定时任务监控：
# */5 * * * * dig +short <target> >> /tmp/dns_monitor.log

# 3. 新增子域名监控
#    新上线的子域名可能还未接入 CDN
WebFetch: https://crt.sh/?q=%25.<root_domain>&output=json
# 筛选最近 7 天签发的证书中出现的新子域名
# 逐一 nslookup 检查是否直连
```

### P4-7：社工辅助情报（被动收集）

```bash
# 1. GitHub / GitLab 代码搜索
#    搜索目标域名在公开代码仓库中的引用，可能包含源站 IP、配置文件
WebSearch: site:github.com "<root_domain>" ip OR host OR server OR origin OR backend
WebSearch: site:github.com "<root_domain>" ".env" OR "config" OR "database_host"

# 2. Pastebin / 代码分享平台
WebSearch: site:pastebin.com "<root_domain>"
WebSearch: site:paste.ee "<root_domain>"

# 3. 搜索引擎缓存
#    Google 可能缓存了包含源站 IP 的页面
WebSearch: "<root_domain>" intext:"server" intext:"nginx" OR intext:"apache" -site:<root_domain>
WebSearch: "<root_domain>" "real ip" OR "origin ip" OR "源站" OR "真实IP"

# 4. 社交媒体 / 论坛泄露
WebSearch: "<root_domain>" ip address site:reddit.com OR site:stackoverflow.com OR site:v2ex.com OR site:52pojie.cn

# 5. 安全报告 / 漏洞披露
WebSearch: "<root_domain>" "HackerOne" OR "bugcrowd" OR "vulnerability" OR "漏洞"
```

### P4-8：网络拓扑推断

```bash
# 1. Traceroute 分析
#    对 CDN 节点 traceroute，分析倒数几跳的网络拓扑
#    某些 CDN 的回源路径在 traceroute 中可见
traceroute <target> 2>/dev/null || tracert <target> 2>/dev/null

# 2. MTR 分析（Linux）
mtr --report --report-cycles 5 <target> 2>/dev/null

# 3. TCP 指纹比对
#    不同操作系统的 TCP 实现有不同指纹（TTL、窗口大小等）
#    CDN 节点通常是 Linux，如果源站是 Windows 可通过 TTL 区分
curl -sI -m 3 "https://<target>" -w "\nTTL-related: local_ip=%{local_ip} remote_ip=%{remote_ip}\n" 2>&1

# 4. ICMP Ping 对比
#    CDN 节点和源站的 TTL / 响应时间可能有明显差异
ping -c 3 <target> 2>/dev/null || ping -n 3 <target> 2>/dev/null
```

### P4-9：国际出口 / 地域差异利用

```bash
# 1. 某些 CDN 只覆盖特定地区
#    使用不同地区的 DNS / 代理可能获得不同结果
#    在线多地点 DNS 查询工具：
WebFetch: https://check-host.net/check-dns?host=<target>
WebFetch: https://www.whatsmydns.net/api/details?server=dns&q=<target>&type=A

# 2. IPv4 vs IPv6 差异
#    某些 CDN 仅覆盖 IPv4，IPv6 直连源站
nslookup -type=AAAA <target>
# 如果有 AAAA 记录，curl -6 直连测试

# 3. 境外 DNS 解析可能跳过国内 CDN
nslookup <target> 8.8.8.8
nslookup <target> 1.1.1.1
nslookup <target> 208.67.222.222
# 对比国内 DNS (114.114.114.114) 结果是否不同
```

---

## 验证阶段（对每个候选 IP 执行）

无论哪个优先级发现了候选 IP，都必须通过此阶段验证。

### V-1：SSL 证书序列号精确比对（决定性验证）

```bash
CANDIDATE="<candidate_ip>"
CDN_NODE="<any_cdn_node_ip>"

# CDN 节点证书序列号（基准）
CDN_SERIAL=$(echo | openssl s_client -connect $CDN_NODE:443 -servername <target> 2>/dev/null | \
  openssl x509 -noout -serial 2>/dev/null)

# 候选 IP - 使用 SNI 的证书
CAND_SERIAL=$(echo | openssl s_client -connect $CANDIDATE:443 -servername <target> 2>/dev/null | \
  openssl x509 -noout -serial 2>/dev/null)

# 候选 IP - 默认证书（不使用 SNI）
DEFAULT_CERT=$(echo | openssl s_client -connect $CANDIDATE:443 2>/dev/null | \
  openssl x509 -noout -subject -serial 2>/dev/null)

echo "CDN 证书 Serial: $CDN_SERIAL"
echo "候选 IP SNI 证书 Serial: $CAND_SERIAL"
echo "候选 IP 默认证书: $DEFAULT_CERT"
```

**判定规则**：

| CDN Serial = 候选 SNI Serial? | 默认证书 | Server 头 | 结论 |
|---|---|---|---|
| 一致 | 是另一个域名的 | nginx/apache/IIS | **确认源站**（决定性） |
| 一致 | 无 / 连接失败 | nginx/apache/IIS | **高度可能源站** |
| 一致 | 与 SNI 相同 | CDN 标识 | CDN 节点，排除 |
| 不一致 | — | — | 非关联服务器，排除 |
| 连接失败 | — | — | 需其他方法验证 |

### V-2：HTTP 行为对比

```bash
CANDIDATE="<candidate_ip>"

# 直接访问（核心差异点）
echo "=== Direct HTTP ==="
curl -sI -m 5 http://$CANDIDATE | head -10

echo "=== Direct HTTPS ==="
curl -sI -m 5 -k https://$CANDIDATE | head -10

echo "=== With Host header ==="
curl -sI -m 5 -k --resolve <target>:443:$CANDIDATE https://<target> | head -10
```

**源站特征**：直连返回 `Server: nginx/apache/IIS`（非 CDN 标识）
**CDN 特征**：直连返回 CDN 专属标识（`TencentEdgeOne` / `cloudflare` / `Tengine` 等）

### V-3：IP 归属与域名反查

```
WebFetch: https://ipchaxun.com/<candidate_ip>/
  → 确认归属地、运营商
  → 确认是否有目标域名的绑定记录
```

### V-4：多端口/服务验证

```bash
# SSH 存在 = 真实服务器
timeout 3 bash -c "echo|curl -s -m 3 telnet://$CANDIDATE:22" 2>&1 | head -1

# 非标准端口 web 服务
for port in 8080 8443 8888 3000; do
  curl -sI -m 2 http://$CANDIDATE:$port 2>&1 | head -3
done
```

---

## 证据链与最终判定

### 证据强度定义

| 等级 | 名称 | 典型证据 |
|---|---|---|
| S | 决定性 | SSL 证书序列号匹配 + 默认证书不同 + Server 头差异 |
| A | 强佐证 | 历史 DNS 直接解析确认 / IP 反查绑定确认 / 空间搜索引擎命中 |
| B | 佐证 | SPF 记录包含 / 子域名解析到 / 同 C 段有关联域名 |
| C | 弱线索 | 搜索引擎提及 / GA ID 关联 / 同组织域名 |
| X | 已排除 | 确认为 CDN 节点 / 无关服务器 / 已下线 |

### 置信度评级

| 置信度 | 条件 |
|---|---|
| **确定** (95%+) | ≥1 个 S 级证据 + ≥1 个 A 级证据 |
| **高度可信** (80-95%) | ≥2 个 A 级证据互相印证 |
| **可能** (60-80%) | 1 个 A 级 + ≥1 个 B 级 |
| **猜测** (<60%) | 仅有 B/C 级线索 |

### 最终报告格式

```
╔══════════════════════════════════════════════════════════╗
║  CDN 真实 IP 溯源报告                                    ║
║  目标: <target_domain>                                   ║
║  时间: <date>                                            ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  CDN 类型: <cdn_name>                                    ║
║  DNS 托管: <dns_provider>                                ║
║  SSL 证书: <cert_cn> (Serial: <serial>)                  ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  溯源结论                                                ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  真实 IP:  <final_ip>                                    ║
║  置信度:  <confidence> (<percentage>)                     ║
║  归属地:  <location>                                     ║
║  运营商:  <isp>                                          ║
║  服务器:  <server_software>                              ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  证据链                                                  ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [S] <evidence_1>                                        ║
║  [A] <evidence_2>                                        ║
║  [A] <evidence_3>                                        ║
║  [B] <evidence_4>                                        ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  已排除 IP                                               ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [X] <ip_1> — <reason>                                   ║
║  [X] <ip_2> — <reason>                                   ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  执行方法 (<N> 种)                                       ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  P0: <method> → <result>                                 ║
║  P1: <method> → <result>                                 ║
║  P2: <method> → <result>                                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

### 未能确定时的报告

```
溯源结论: 未能确定真实 IP
已执行方法: <N> 种（P0: X种, P1: X种, P2: X种, P3: X种）
最佳候选: <ip> (置信度 <X>%, 因 <reason> 无法最终确认)
建议后续操作:
  1. 尝试邮件触发法（注册/找回密码）获取邮件头
  2. 申请 Shodan/FOFA/Censys 账号后补充扫描
  3. 等待 SSL 证书续期（Let's Encrypt 每 90 天），续期时的 DNS 验证可能暴露源站
  4. 监控域名 DNS 变更（CDN 切换/故障时可能回退到源站 A 记录）
```

---

## 执行控制

1. **Token 节省**：P0 全部并行 → 有候选即验证 → 无候选再逐级升级
2. **并行执行**：同优先级内的独立步骤并行调用工具
3. **跨平台**：openssl / curl 通过 Bash 工具执行；nslookup 通过系统原生 shell；Python 注意 python vs python3
4. **容错**：某平台/工具不可用时跳过，不阻塞流程
5. **频率控制**：避免短时间大量请求同一目标触发 WAF
6. **Key 安全**：API Key 仅在内存中使用，不写入任何文件
7. **合法合规**：仅用于授权安全测试、教学、CTF 竞赛
8. **记录一切**：每个步骤的结果必须记录，包括"无结果"
