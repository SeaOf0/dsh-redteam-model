# Detection Rule Search for Tools

Search for YARA, Sigma, and other detection rules for penetration testing tools.

## Verified Detection Rule Repositories

### YARA Repositories

| Repository | Description | Status |
|------------|-------------|--------|
| Yara-Rules/rules | Classic community rules, well-organized | ✅ Active |
| Neo23x0/signature-base | High quality, low false positives, used by LOKI/THOR | ✅ Active |
| elastic/protections-artifacts | Elastic Security rules | ✅ Active |
| advanced-threat-research/Yara-Rules | Trellix/McAfee rules | ✅ Active |
| stratosphereips/yara-rules | Network-based YARA rules | ✅ Active |
| InQuest/awesome-yara | Curated list of YARA resources | ✅ Active |
| ReversingLabs/reversinglabs-yara-rules | Vendor rules | ✅ Active |

### Sigma Repositories

| Repository | Description | Status |
|------------|-------------|--------|
| SigmaHQ/sigma | Official Sigma repository, 3000+ rules | ✅ Active |
| mdecrevoisier/SIGMA-detection-rules | Advanced correlation rules | ✅ Active |
| P4T12ICK/Sigma-Rule-Repository | Rules with test documentation | ✅ Active |

### Network/IDS Rules

| Repository | Description | Status |
|------------|-------------|--------|
| EmergingThreats | Network IDS rules | https://rules.emergingthreats.net/ |

## Multi-Source Search Strategy

### 1. Tool-Specific Search

```bash
# Search by tool name (multiple variations)
gh search code "<tool_name>" --extension yar
gh search code "<tool_name> yara" --extension yar
gh search code "<tool_name> detection" --extension yar
gh search code "<tool_name> malware" --extension yar
gh search code "<tool_name> rule" --extension yar
gh search code "<tool_name> trojan" --extension yar

# Search by alternative names/aliases
gh search code "<alt_name1>" --extension yar
gh search code "<alt_name2>" --extension yar

# Case variations
gh search code "<ToolName>" --extension yar
gh search code "<TOOL_NAME>" --extension yar
```

### 2. YARA Repository Search

```bash
# Major YARA repositories (verified)
gh search code "repo:Yara-Rules/rules <keyword>"
gh search code "repo:Neo23x0/signature-base <keyword>"
gh search code "repo:elastic/protections-artifacts <keyword>"
gh search code "repo:advanced-threat-research/Yara-Rules <keyword>"
gh search code "repo:stratosphereips/yara-rules <keyword>"
gh search code "repo:InQuest/awesome-yara <keyword>"
gh search code "repo:ReversingLabs/reversinglabs-yara-rules <keyword>"
```

### 3. Sigma Rule Search

```bash
# Sigma rules by tool name
gh search code "<tool_name>" --extension yml --filename sigma
gh search code "repo:SigmaHQ/sigma <tool_name>"

# Sigma rules by behavior
gh search code "repo:SigmaHQ/sigma <behavior_keyword>"

# Other Sigma repositories
gh search code "repo:mdecrevoisier/SIGMA-detection-rules <keyword>"
gh search code "repo:P4T12ICK/Sigma-Rule-Repository <keyword>"
```

### 4. Network/IDS Rule Search

```bash
# Snort/Suricata rules
gh search code "<tool_name> snort" --extension rules
gh search code "<tool_name> suricata" --extension rules

# Zeek rules
gh search code "<tool_name> zeek" --extension zeek

# Network signatures
gh search code "<tool_name> network signature"
```

### 5. Behavior-Based Search

```bash
# Search by API patterns
gh search code "VirtualAlloc shellcode" --extension yar
gh search code "CreateRemoteThread" --extension yar
gh search code "process injection" --extension yar

# Search by HTTP patterns
gh search code "User-Agent <pattern>" --extension yar
gh search code "X-<header>" --extension yar

# Search by network behavior
gh search code "<port> beacon" --extension yar
gh search code "http <path> implant" --extension yar
```

## Keyword Extraction

Extract keywords from tool for searching:

| Source | Keywords to Extract |
|--------|---------------------|
| Tool Name | Exact name, variations, aliases |
| README | Author, project name, features |
| Source Code | Function names, string constants, API calls |
| HTTP Traffic | User-Agent, headers, URL paths |
| Network | Ports, protocols, domain patterns |
| Process | Process names, command lines |
| Registry | Registry keys, values |
| Files | File names, paths, extensions |

## Rule Categorization

### YARA Rules

| Category | Description | File Pattern |
|----------|-------------|--------------|
| String | Detect string constants | `*.yar` with `$s` patterns |
| Hex | Detect byte patterns | `*.yar` with `{ }` patterns |
| Regex | Detect patterns | `*.yar` with `/ /` patterns |
| Condition | Logic combinations | `*.yar` with `and`, `or` |

### Sigma Rules

| Category | Description | File Pattern |
|----------|-------------|--------------|
| process_creation | Process spawn detection | `proc_creation_*.yml` |
| network_connection | Network activity | `net_connection_*.yml` |
| file_event | File operations | `file_event_*.yml` |
| registry_event | Registry changes | `registry_*.yml` |
| process_access | Memory access | `proc_access_*.yml` |
| create_remote_thread | Remote thread | `create_remote_thread_*.yml` |
| image_load | DLL loading | `image_load_*.yml` |
| dns_query | DNS queries | `dns_query_*.yml` |

### Network Rules

| Category | Description | File Pattern |
|----------|-------------|--------------|
| HTTP | HTTP traffic detection | `*.rules` with `http` |
| DNS | DNS queries | `*.rules` with `dns` |
| TCP/UDP | Network connections | `*.rules` with `tcp/udp` |

## Save Rules

For each rule found, save with metadata:

```
rules/{tool_name}/
├── yara/
│   ├── <source>_<rulename>.yar
│   └── metadata.json
├── sigma/
│   ├── <rulename>.yml
│   └── metadata.json
├── network/
│   └── <rulename>.rules
├── other/
│   └── <rulename>.<ext>
├── tool_profile.md
├── behavior_analysis.md
└── rule_inventory.md
```

### Metadata Format

```json
{
  "source": "Yara-Rules/rules",
  "url": "https://github.com/Yara-Rules/rules/blob/main/...",
  "author": "author_name",
  "date": "YYYY-MM-DD",
  "target": "tool_name",
  "type": "YARA",
  "patterns_count": 5
}
```

## Rule Inventory Format

```markdown
# Rule Inventory for {tool_name}

## Summary

| Type | Count | Sources |
|------|-------|---------|
| YARA | X | Yara-Rules, Elastic, ... |
| Sigma | Y | SigmaHQ |
| Network | Z | ... |

## YARA Rules

| File | Author | Patterns | Target |
|------|--------|----------|--------|
| rule1.yar | Elastic | 5 strings, 3 hex | Implant |
| rule2.yar | Yara-Rules | 2 strings | Agent |

## Sigma Rules

| File | Category | Detection |
|------|----------|-----------|
| proc_creation_xxx.yml | process_creation | Image + CommandLine |
| net_connection_xxx.yml | network_connection | Port + Image |

## Network Rules

| File | Type | Patterns |
|------|------|----------|
| rule1.rules | HTTP | Headers |
```

## Important Notes

1. **Multiple keywords**: Use multiple search variations to find all rules
2. **Multiple repositories**: Search across multiple detection repositories
3. **Behavior patterns**: Don't just search by tool name, also search by behavior
4. **Save all rules**: Even partial matches can be useful
5. **Record sources**: Always record where each rule came from
6. **Verify repositories**: Some repositories may be renamed or archived
