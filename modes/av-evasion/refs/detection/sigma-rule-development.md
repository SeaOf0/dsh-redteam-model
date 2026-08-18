---
name: sigma-rule-development
description: >-
  Write, validate, convert, and deploy Sigma detection rules across SIEM platforms (Splunk, Elastic, Sentinel). Covers rule authoring, MITRE ATT&CK mapping, pySigma conversion pipelines, and detection-as-code workflows.
---

# SKILL: Sigma Rule Development

## 1. QUICK START

1. Define detection logic from threat intelligence or ATT&CK technique.
2. Write a Sigma YAML rule with logsource, detection, and condition fields.
3. Validate syntax with `sigma check`.
4. Convert to target SIEM query using pySigma backends.
5. Test against sample data and deploy to production.

## 2. RULES / METHODOLOGY

### 2.1 Sigma Rule Anatomy

Every Sigma rule has three mandatory sections:

```yaml
title: Descriptive Rule Name
id: <uuid4>
status: stable|test|experimental
level: critical|high|medium|low|informational
description: What the rule detects and why it matters
logsource:
    category: process_creation|process_access|network_connection|...
    product: windows|linux|macos|windows_defender|...
detection:
    selection:
        FieldName|modifier: value
    filter_legitimate:
        FieldName: excluded_value
    condition: selection and not filter_legitimate
falsepositives:
    - Expected benign activity that matches
tags:
    - attack.tactic_name
    - attack.tXXXX.YYY
```

### 2.2 Key Detection Modifiers

| Modifier | Purpose | Example |
|----------|---------|---------|
| `contains` | Substring match | `CommandLine|contains: 'mimikatz'` |
| `endswith` | Suffix match | `TargetImage|endswith: '\lsass.exe'` |
| `startswith` | Prefix match | `SourceImage|startswith: 'C:\Temp'` |
| `re` | Regex match | `CommandLine|re: '.*-enc.*[A-Za-z0-9+/]{50,}'` |
| `base64offset` | Base64 encoded content | `CommandLine|base64offset: 'http://'` |
| `all` | All values must match | `selection|all` |
| `windash` | Windows dash variants | `-|windash: '-param'` |

### 2.3 Logsource Categories by Platform

**Windows (Sysmon + Security Event Log):**
- `process_creation` (Sysmon 1, Security 4688)
- `process_access` (Sysmon 10)
- `network_connection` (Sysmon 3)
- `file_event` (Sysmon 11, 23)
- `registry_event` (Sysmon 12, 13, 14)
- `create_remote_thread` (Sysmon 8)
- `dns_query` (Sysmon 22)

**Linux:**
- `process_creation` (auditd execve)
- `network_connection` (auditd sockaddr)
- `file_event` (auditd path)

**Network:**
- `firewall` (firewall logs)
- `webserver` (HTTP access logs)
- `proxy` (web proxy logs)
- `dns` (DNS query logs)

### 2.4 Condition Logic Patterns

```yaml
# Simple AND
condition: selection

# AND NOT filter
condition: selection and not 1 of filter_*

# Time-based correlation
detection:
    selection1:
        EventID: 4624
        LogonType: 10
    selection2:
        EventID: 4624
        LogonType: 2
    timeframe: 5m
    condition: selection1 | near selection2

# Count-based aggregation
condition: selection | count() by src_ip > 100

# Multiple selection groups (OR logic)
condition: 1 of selection_*
```

### 2.5 SIEM Conversion Pipeline

```
Sigma YAML Rule
    |
    v  pySigma + Pipeline (field mapping)
    +---> Splunk SPL
    +---> Elastic EQL / KQL / Lucene
    +---> Microsoft Sentinel KQL
    +---> QRadar AQL
    +---> Carbon Black query
```

**Conversion with pySigma (Python):**

```python
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

pipeline = splunk_windows_pipeline()
backend = SplunkBackend(pipeline)
rule = SigmaRule.from_yaml(open("rule.yml").read())
splunk_query = backend.convert_rule(rule)
print(splunk_query[0])
```

**CLI conversion:**

```bash
# Install backend
pip install pySigma pySigma-backend-splunk pySigma-backend-elasticsearch

# Convert
sigma convert -t splunk -p splunk_windows rules/lsass_access.yml
sigma convert -t lucene -p ecs_windows rules/lsass_access.yml
sigma convert -t kql rules/lsass_access.yml
```

### 2.6 Windows Event Logging for Detection

Configure advanced audit policies to generate quality telemetry:

**Required audit policies (via GPO):**
- Account Logon: Credential Validation (Success, Failure)
- Logon: Logon (Success, Failure), Special Logon (Success)
- Object Access: File Share (Success, Failure), Removable Storage (Success, Failure)
- Privilege Use: Sensitive Privilege Use (Success, Failure)
- Detailed Tracking: Process Creation (Success)

**Enable command-line logging in Event 4688:**
```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWORD -Force
```

**Increase Security log size (minimum 1 GB):**
```powershell
wevtutil sl Security /ms:1073741824
```

**Key Event IDs for detection:**

| Event ID | Source | Use Case |
|----------|--------|----------|
| 4624/4625 | Security | Authentication success/failure |
| 4648 | Security | Explicit credential logon (RunAs, Pass-the-Hash) |
| 4672 | Security | Special privileges assigned |
| 4688 | Security | Process creation (with command line) |
| 4697 | Security | Service installed |
| 4720/4728 | Security | User/group created/modified |
| 7045 | System | New service installed (persistence) |
| 1102 | Security | Audit log cleared (anti-forensics) |

### 2.7 MITRE ATT&CK Mapping

Tag every rule with ATT&CK technique IDs:

```yaml
tags:
    - attack.credential_access        # Tactic
    - attack.t1003.001                # Sub-technique
    - attack.t1003                    # Parent technique
```

Generate ATT&CK Navigator coverage layers:

```python
import json, os
from sigma.rule import SigmaRule

layer = {
    "name": "SOC Detection Coverage",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": []
}

for root, dirs, files in os.walk("sigma/rules/windows/"):
    for f in files:
        if f.endswith(".yml"):
            rule = SigmaRule.from_yaml(open(os.path.join(root, f)).read())
            for tag in rule.tags:
                if str(tag).startswith("attack.t"):
                    tid = str(tag).replace("attack.", "").upper()
                    layer["techniques"].append({
                        "techniqueID": tid, "color": "#31a354", "score": 1
                    })

with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
```

## 3. EXAMPLES

### Example 1: LSASS Credential Dumping Detection

```yaml
title: Mimikatz Credential Dumping via LSASS Access
id: 0d894093-71bc-43c3-8d63-bf520e73a7c5
status: stable
level: high
description: Detects process accessing lsass.exe memory with suspicious access rights
references:
    - https://attack.mitre.org/techniques/T1003/001/
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
    filter_main_svchost:
        SourceImage|endswith: '\svchost.exe'
    filter_main_csrss:
        SourceImage|endswith: '\csrss.exe'
    filter_main_wininit:
        SourceImage|endswith: '\wininit.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate security tools accessing LSASS
    - Windows Defender scanning
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Example 2: Encoded PowerShell Execution

```yaml
title: Encoded PowerShell Command Execution
id: f3a1c8b2-7d4e-4a12-b5c9-6e8d3f1a2b4c
status: stable
level: high
description: Detects use of encoded commands in PowerShell, common in obfuscated attacks
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec'
    condition: selection
falsepositives:
    - Legitimate admin scripts using encoding
tags:
    - attack.execution
    - attack.t1059.001
```

### Example 3: Suspicious Service Installation

```yaml
title: Service Installation with Suspicious Binary Path
id: c8d4e2a1-9b3f-4d6e-8c7a-5b1e3f2d4a6c
status: stable
level: medium
description: Detects new service installation pointing to unusual file paths
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    suspicious_paths:
        ImagePath|contains:
            - 'C:\Users\'
            - 'C:\ProgramData\'
            - 'C:\Temp\'
            - 'C:\Windows\Temp\'
            - '\AppData\'
    condition: selection and suspicious_paths
falsepositives:
    - Software installers placing services in user directories
tags:
    - attack.persistence
    - attack.t1543.003
```

### Example 4: Splunk Correlation Search (Brute Force)

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| stats count as failed_logins dc(TargetUserName) as unique_users by src_ip
| where failed_logins > 10 AND unique_users > 3
| lookup asset_lookup ip as src_ip OUTPUT asset_category, asset_owner
| eval severity="high"
| eval description="Brute force from ".src_ip.": ".failed_logins." failures across ".unique_users." accounts"
```

### Example 5: Elastic EQL Rule

```toml
[rule]
name = "LSASS Memory Access - Credential Dumping"
description = "Detects suspicious access to LSASS process memory"
risk_score = 73
severity = "high"
type = "eql"
query = '''
process where event.action == "access" and
  process.name == "lsass.exe" and
  not process.executable : ("*\\svchost.exe", "*\\csrss.exe")
'''

[rule.threat]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1003"
name = "OS Credential Dumping"
```

## 4. VALIDATION

### Syntax Validation

```bash
# Validate Sigma rules
pip install pySigma pySigma-validators-sigmaHQ
sigma check rule.yml
sigma check rules/          # Validate directory

# Python validation
from sigma.rule import SigmaRule
from sigma.validators.core import SigmaValidator
rule = SigmaRule.from_yaml(open("rule.yml").read())
issues = SigmaValidator().validate_rule(rule)
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

### Test Against Sample Data

```bash
# Convert and test in SIEM
sigma convert -t splunk -p splunk_windows rules/lsass_access.yml
# Run converted query against 7-day lookback in Splunk
# Verify true positive rate and false positive rate
```

### Performance Testing

```spl
# Check query execution time
index=wineventlog EventCode=4688
| stats count by sourcetype
| eval query_perf="Check execution time in Splunk Job Inspector"
```

### CI/CD Integration

```yaml
# .github/workflows/sigma-ci.yml
name: Sigma Rule CI
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install pySigma pySigma-validators-sigmaHQ
      - run: sigma check rules/
      - run: sigma convert -t splunk -p splunk_windows rules/ > /dev/null
```

## 5. REFERENCES

- **SigmaHQ**: https://github.com/SigmaHQ/sigma -- Official Sigma rule repository with 3000+ community rules
- **pySigma**: https://github.com/SigmaHQ/pySigma -- Python library for Sigma rule processing
- **MITRE ATT&CK**: https://attack.mitre.org/ -- Technique mapping framework
- **ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/ -- Detection coverage visualization
- **Uncoder.IO**: https://uncoder.io/ -- Web-based Sigma rule converter for 30+ SIEM platforms
- **Splunk CIM**: https://docs.splunk.com/Documentation/CIM/latest/User/Overview -- Common Information Model data models
- **Windows Event Logging**: Configure advanced audit policies via GPO for quality detection telemetry
