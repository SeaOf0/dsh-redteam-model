# Behavior Analysis for Tools

Analyze tool behavior based on detection rule categories and patterns.

## Detection Categories (Based on Sigma/YARA)

Detection rules categorize behaviors into specific domains. When analyzing a tool, check for behaviors in these categories:

### Windows Detection Categories

| Category | Description | Key Detection Points |
|----------|-------------|---------------------|
| process_creation | Process spawn events | Image path, CommandLine, ParentImage, OriginalFileName |
| process_access | Process memory access | SourceImage, TargetImage, GrantedAccess |
| create_remote_thread | Remote thread creation | SourceImage, TargetImage, StartAddress |
| network_connection | Network connections | Image, SourceIP, DestinationIP, DestinationPort |
| dns_query | DNS queries | Image, QueryName |
| file_event | File operations | TargetFilename, Image |
| registry | Registry operations | TargetObject, Details, EventType |
| image_load | DLL loading | ImageLoaded, Image |
| driver_load | Driver loading | ImageLoaded, Hashes |
| pipe_created | Named pipe operations | PipeName |
| powershell | PowerShell execution | CommandLine, ScriptBlockText |

### Linux Detection Categories

| Category | Description | Key Detection Points |
|----------|-------------|---------------------|
| process_creation | Process execution | exe, cmdline, comm |
| network_connection | Network connections | exe, src_ip, dst_ip, dst_port |
| file_event | File operations | path, exe |
| auditd | Audit events | type, exe, key |

### Network Detection Categories

| Category | Description | Key Detection Points |
|----------|-------------|---------------------|
| dns | DNS traffic | query, answer |
| firewall | Firewall logs | src_ip, dst_ip, dst_port, action |
| zeek | Network analysis | id.orig_h, id.resp_h, id.resp_p |

## Detection Patterns by Category

### 1. Process Creation

Detection patterns:
- **Image name**: Executable name (e.g., `mimikatz.exe`, `crackmapexec.exe`)
- **OriginalFileName**: Original file name even if renamed
- **CommandLine**: Command line arguments
- **ParentImage**: Parent process
- **Hashes**: File hash (MD5, SHA1, SHA256)
- **Imphash**: Import hash

Example detection:
```yaml
detection:
    selection:
        Image|endswith: '\mimikatz.exe'
        CommandLine|contains: 'sekurlsa::logonpasswords'
```

### 2. Process Access

Detection patterns:
- **SourceImage**: Source process
- **TargetImage**: Target process (often `lsass.exe`)
- **GrantedAccess**: Access rights (e.g., `0x1010`, `0x1410`)
- **CallTrace**: Stack trace

Example detection:
```yaml
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess: '0x1010'
```

### 3. Network Connection

Detection patterns:
- **Image**: Process making connection
- **SourceIP/SourcePort**: Source address
- **DestinationIP/DestinationPort**: Destination address
- **Initiated**: Connection direction

Example detection:
```yaml
detection:
    selection:
        Image|endswith: '\certutil.exe'
        DestinationPort:
            - 80
            - 443
```

### 4. File Event

Detection patterns:
- **TargetFilename**: File path created/modified
- **Image**: Process creating the file
- **CreationUtcTime**: Timestamp

Example detection:
```yaml
detection:
    selection:
        TargetFilename|endswith: '.kirbi'
```

### 5. Registry

Detection patterns:
- **TargetObject**: Registry key path
- **Details**: Value data
- **EventType**: set, delete, create

Example detection:
```yaml
detection:
    selection:
        TargetObject|contains: '\PowerShell\ScriptBlockLogging'
        Details: 'DWORD (0x00000000)'
```

### 6. YARA Patterns

Detection patterns:
- **String patterns**: `$s1 = "malicious_string"`
- **Hex patterns**: `$h1 = { 48 83 EC 58 }`
- **Regex patterns**: `$r1 = /X-[a-z]+-Id/`
- **Condition logic**: `any of them`, `all of them`, `count`

Example detection:
```yara
strings:
    $s1 = "BeaconOutput" wide ascii
    $h1 = { 48 83 EC 58 }
condition:
    any of them
```

## Analysis Workflow

### Step 1: Identify Tool Category

Based on tool functionality, determine which detection categories apply:

| Tool Type | Primary Categories |
|-----------|-------------------|
| C2/Beacon | process_creation, network_connection, file_event |
| Credential Tool | process_creation, process_access, file_event |
| Scanner | network_connection, dns_query |
| Exploit | process_creation, file_event, registry |
| Lateral Movement | process_creation, network_connection, create_remote_thread |
| Persistence | registry, file_event, process_creation |
| Evasion | process_creation, registry, image_load |

### Step 2: Extract Tool Indicators

For each applicable category, extract indicators from source code:

**Process Creation:**
```bash
# Executable names
grep -rn "exe" <tool_path>
grep -rn "process" <tool_path>

# Command line arguments
grep -rn "args\|argv\|command" <tool_path>
```

**Network Connection:**
```bash
# IP/Port
grep -rn "connect\|dial\|socket" <tool_path>
grep -rn ":80\|:443\|:8080" <tool_path>

# HTTP headers
grep -rn "User-Agent\|Content-Type\|X-" <tool_path>

# URLs
grep -rn "http\|/api\|/checkin" <tool_path>
```

**Process Access:**
```bash
# Process operations
grep -rn "OpenProcess\|VirtualAllocEx\|WriteProcessMemory" <tool_path>
grep -rn "CreateRemoteThread\|QueueUserAPC" <tool_path>
```

**File Event:**
```bash
# File operations
grep -rn "CreateFile\|WriteFile\|fopen" <tool_path>
grep -rn "\.dll\|\.exe\|\.log\|\.kirbi" <tool_path>
```

**Registry:**
```bash
# Registry operations
grep -rn "RegOpenKey\|RegSetValue\|HKEY_" <tool_path>
```

### Step 3: Create Behavior Profile

Output: `rules/{tool_name}/behavior_analysis.md`

```markdown
# Behavior Analysis: {tool_name}

## Detection Categories

### Process Creation
| Indicator | Value | File:Line | Detection Risk |
|-----------|-------|-----------|----------------|
| Image | tool.exe | main.go:1 | High |
| CommandLine | --beacon | config.go:20 | Medium |
| OriginalFileName | tool.exe | - | High |

### Network Connection
| Indicator | Value | File:Line | Detection Risk |
|-----------|-------|-----------|----------------|
| DestinationPort | 443 | config.go:15 | Low |
| User-Agent | "Tool/1.0" | http.go:45 | High |
| URL Pattern | /api/checkin | client.go:78 | High |

### File Event
| Indicator | Value | File:Line | Detection Risk |
|-----------|-------|-----------|----------------|
| TargetFilename | output.log | file.go:12 | Low |

### Process Access
| Indicator | Value | File:Line | Detection Risk |
|-----------|-------|-----------|----------------|
| TargetImage | lsass.exe | inject.go:34 | Critical |

## Risk Summary

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Process Creation | 0 | 2 | 1 | 0 |
| Network | 0 | 2 | 0 | 1 |
| File | 0 | 0 | 0 | 1 |
| Process Access | 1 | 0 | 0 | 0 |

## Recommendations

1. [Priority recommendations based on risk]
```

## Important Notes

1. Focus on **detection categories** - rules detect specific event types
2. Extract **exact indicators** - precise values matter for detection
3. Consider **all applicable categories** - tools often trigger multiple categories
4. Understand **detection context** - same behavior may have different risk in different contexts
