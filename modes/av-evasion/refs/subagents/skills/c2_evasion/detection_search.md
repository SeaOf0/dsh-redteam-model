# Detection Rule Search

Search for YARA, Sigma, and network detection rules for C2 frameworks.

## YARA Rule Search

Search multiple keywords and repositories:

```bash
# Search by C2 name (multiple variations)
gh search code "<c2_name>" --extension yar
gh search code "<c2_name> yara" --extension yar
gh search code "<c2_name> rule" --extension yar
gh search code "<c2_name> trojan" --extension yar
gh search code "<c2_name> malware" --extension yar
gh search code "<c2_name> beacon" --extension yar
gh search code "<c2_name> agent" --extension yar

# Search by functionality keywords
gh search code "beacon http implant" --extension yar
gh search code "shellcode loader" --extension yar
gh search code "cobalt strike" --extension yar
gh search code "sliver implant" --extension yar

# Search by API patterns
gh search code "VirtualAlloc beacon" --extension yar
gh search code "wininet http" --extension yar

# Search specific YARA repositories
gh search code "repo:bartblaze/Yara-rules <keyword>"
gh search code "repo:Neo23x0/signature-base <keyword>"
gh search code "repo:elastic/protections-artifacts <keyword>"
gh search code "repo:CAPE-sandbox/CAPE-Yara <keyword>"
gh search code "repo:sboussema/Yara-Bootloader <keyword>"
gh search code "repo:Yara-Rules/rules <keyword>"
```

## Sigma Rule Search

```bash
gh search code "<c2_name> sigma" --extension yml
gh search code "<c2_name>" --extension yml --filename sigma
gh search code "repo:SigmaHQ/sigma <c2_name>"
```

## Network/IDS Rule Search

```bash
gh search code "<c2_name> snort" --extension rules
gh search code "<c2_name> suricata" --extension rules
gh search code "<c2_name> zeek" --extension zeek
```

## Save Rules

Save all found rules to:

```
./rules/<c2_name>/
├── yara/
│   └── *.yar
├── sigma/
│   └── *.yml
├── network/
│   └── *.rules
└── detection_analysis.md
```

## Pattern Extraction

For each YARA rule found, extract:

| Pattern Type | Syntax | Example |
|--------------|--------|---------|
| String | `$s1 = "text"` | `$s1 = "BeaconOutput"` |
| Hex | `$h1 = { bytes }` | `$h1 = { 48 83 EC 58 }` |
| Hex with wildcard | `$h1 = { ?? ?? }` | `$h1 = { B8 ?? ?? 00 }` |
| Regex | `$r1 = /pattern/` | `$r1 = /X-[a-z]+-Id/` |

## Rule Analysis

For each rule, identify:

1. **Target component**: Implant, server, network
2. **Pattern types**: String, hex, regex
3. **Detection focus**: Names, APIs, bytes, config

## Output Format

```markdown
## Detection Rules Found

### YARA Rules (X from N repositories)
| Rule File | Author | Patterns | Target |
|-----------|--------|----------|--------|
| Windows_Trojan_Adaptix.yar | Elastic | hex | C++ beacon |
| Adaptix_Beacon.yar | bartblaze | string | Go agent |

### Sigma Rules (Y)
| Rule File | Category | Detection |
|-----------|----------|-----------|
| AdaptixC2.yml | process_creation | Hash + keyword |

### Network Rules (Z)
| Rule File | Type | Patterns |
|-----------|------|----------|
| adaptix.rules | HTTP | Headers |
```
