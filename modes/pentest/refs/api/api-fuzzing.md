---
name: api-fuzzing
description: >-
  API fuzzing with RESTler and manual techniques — stateful REST API fuzzing, OpenAPI-driven
  test generation, payload dictionaries, and bug bounty fuzzing strategies.
---

# API Fuzzing

> **AI LOAD INSTRUCTION**: Use when performing automated or semi-automated API security testing via fuzzing, especially with OpenAPI specs and RESTler.

## 1. RESTler — Stateful REST API Fuzzing

### Setup
```bash
git clone https://github.com/microsoft/restler-fuzzer.git
cd restler-fuzzer && python3 ./build-restler.py --dest_dir /opt/restler

# Compile OpenAPI spec
/opt/restler/restler/Restler compile --api_spec /path/to/openapi.yaml
# Output: Compile/grammar.py, grammar.json, dict.json, engine_settings.json
```

### Custom Fuzzing Dictionary (dict.json)
```json
{
    "restler_fuzzable_string": [
        "' OR '1'='1", "<script>alert(1)</script>",
        "../../../etc/passwd", "${7*7}", "{{7*7}}",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ],
    "restler_fuzzable_int": ["0", "-1", "999999999", "2147483647"],
    "restler_fuzzable_bool": ["true", "false", "null"],
    "restler_custom_payload": {
        "/users/{userId}": ["1", "0", "-1", "admin", "' OR 1=1--"],
        "/orders/{orderId}": ["1", "0", "999999999"]
    }
}
```

### Authentication Configuration
```python
# authentication_token.py
import requests, time
class Auth:
    def get_auth_header(self):
        r = requests.post("https://target/api/auth/login",
                          json={"email":"fuzzer@test.com","password":"pass"})
        return f"Authorization: Bearer {r.json()['access_token']}"
```

### Engine Settings (engine_settings.json)
```json
{
    "authentication": {"token": {
        "token_refresh_interval": 300,
        "token_refresh_cmd": "python3 auth.py"
    }},
    "max_combinations": 20,
    "max_request_execution_time": 30,
    "garbage_collection_interval": 300,
    "max_sequence_length": 10
}
```

### Run Modes
```bash
# Test mode — smoke test all endpoints
/opt/restler/restler/Restler test \
    --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json \
    --settings Compile/engine_settings.json --target_ip target --target_port 443

# Fuzz-lean — one-pass with security checkers
/opt/restler/restler/Restler fuzz-lean \
    --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json \
    --settings Compile/engine_settings.json --target_ip target --target_port 443 \
    --time_budget 1

# Full fuzz — extended coverage
/opt/restler/restler/Restler fuzz \
    --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json \
    --settings Compile/engine_settings.json --target_ip target --target_port 443 \
    --time_budget 4 \
    --enable_checkers UseAfterFree NamespaceRule ResourceHierarchy LeakageRule PayloadBody
```

### Built-in Checkers
| Checker | Tests For |
|---|---|
| UseAfterFree | Access deleted resources |
| NamespaceRule | Cross-tenant/namespace access |
| ResourceHierarchy | Wrong parent resource IDs |
| LeakageRule | Info disclosure in error responses |
| InvalidDynamicObject | Malformed dynamic object IDs |
| PayloadBody | Injection in request body |

## 2. Manual API Fuzzing Techniques

### Parameter Fuzzing
```bash
# ffuf — parameter name discovery
ffuf -u https://target/api/users/me?FUZZ=test -w params.txt -H "Auth: Bearer TOKEN" -ac

# Value fuzzing for specific parameter
ffuf -u https://target/api/orders/FUZZ -w ids.txt -H "Auth: Bearer TOKEN" -mc 200 -ac
```

### Content-Type Fuzzing
```bash
# Try different content types to bypass validation
curl -X POST https://target/api/orders -H "Content-Type: application/xml" -d '<order><id>1</id></order>'
curl -X POST https://target/api/orders -H "Content-Type: text/plain" -d '{"id":1}'
```

### HTTP Method Fuzzing
```bash
for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE; do
    echo "$method: $(curl -s -o /dev/null -w '%{http_code}' -X $method https://target/api/resource)"
done
```

## 3. api-fuzzing-bug-bounty — Fuzzing Strategies for Bug Bounty

### Common Fuzzing Targets

| Target | Payload | Expected Finding |
|---|---|---|
| Numeric IDs | Sequential/enumeration | IDOR/BOLA |
| UUID parameters | Other users' UUIDs | IDOR if UUID leaked |
| JSON fields | Extra privileged fields | Mass assignment |
| File upload | Double extension, polyglot | Upload bypass |
| Search/filter params | SQL/NoSQL injection | Injection |
| URL parameters | Internal IPs/hostnames | SSRF |
| Date parameters | Extreme values | Logic bugs |

### Fuzzing Automation with Python
```python
import requests, json

BASE = "https://target/api/v1"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}

# Enumerate all endpoints from OpenAPI spec
spec = requests.get(f"{BASE}/../swagger.json").json()
for path, methods in spec.get("paths", {}).items():
    for method in methods:
        if method in ("get","post","put","patch","delete"):
            # Fuzz each parameter with common payloads
            params = methods[method].get("parameters", [])
            for param in params:
                for payload in ["' OR 1=1--","{{7*7}}","../../../etc/passwd",
                                "A"*1000,"-1","0","999999999"]:
                    test_url = f"{BASE}{path}".replace(f"{{{param['name']}}}", payload)
                    r = requests.request(method.upper(), test_url, headers=HEADERS)
                    if r.status_code == 500:
                        print(f"[500] {method.upper()} {path} [{param['name']}={payload}]")
                    elif r.status_code == 200 and payload in r.text:
                        print(f"[REFLECT] {method.upper()} {path} [{param['name']}={payload}]")
```

### Rate-Limited Fuzzing
```bash
# ffuf with rate limiting for stealth
ffuf -u https://target/api/users/FUZZ -w ids.txt -H "Auth: Bearer TOKEN" -rate 5 -ac -o results.json

# Sequential with delay
for id in $(seq 1 1000); do
    curl -s -H "Authorization: Bearer TOKEN" "https://target/api/users/$id" -o /dev/null -w "%{http_code}\n"
    sleep 0.5
done
```

## 4. Decision Tree

```
API fuzzing task
├── Have OpenAPI spec?
│   ├── YES → RESTler: compile → test → fuzz-lean → fuzz
│   └── NO → Manual: ffuf path/param discovery → targeted fuzzing
├── Target type?
│   ├── IDs (numeric/UUID) → Sequential enumeration, IDOR testing
│   ├── JSON fields → Mass assignment payload injection
│   ├── Search/filter → SQL/NoSQL injection payloads
│   └── URLs → SSRF payloads
├── Coverage goal?
│   ├── Quick scan → fuzz-lean (1hr)
│   ├── Deep scan → full fuzz (4-8hr)
│   └── Targeted → manual fuzzing on specific endpoints
└── Results analysis
    ├── 500 errors → potential crash/injection
    ├── Unexpected 200 → potential authz bypass
    └── Response diffs → information disclosure
```

## 5. Tools

| Tool | Purpose |
|---|---|
| RESTler | Stateful OpenAPI-driven fuzzing |
| Schemathesis | Property-based API testing from schemas |
| ffuf | Fast web fuzzer for paths and parameters |
| Arjun | Hidden parameter discovery |
| nuclei | Template-based API vulnerability scanning |
| Burp Intruder | Manual payload delivery and analysis |
