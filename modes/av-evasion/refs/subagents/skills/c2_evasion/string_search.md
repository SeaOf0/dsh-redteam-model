# Proactive Sensitive String Search

Search for sensitive strings in source code that detection rules might target.

## Key Principle

**This phase is MANDATORY** - Even if YARA rules contain only hex patterns, the source code may contain sensitive strings that OTHER detection rules could target.

## String Categories

### HIGH Priority

| Category | Patterns | Why High |
|----------|----------|----------|
| **C2 Names** | beacon, implant, agent, payload, shellcode, c2, command | Direct indicators |
| **Function Names** | TaskProcess, jobRun, execBof, shellExec, killProcess | Suspicious activity |
| **HTTP Headers** | X-Beacon-Id, X-C2-, Cookie: session=, Authorization: Bearer | Network detection |
| **URL Patterns** | /api/, /checkin, /task, /result, /register | C2 communication |

### MEDIUM Priority

| Category | Patterns | Why Medium |
|----------|----------|------------|
| **API Names** | VirtualAlloc, CreateRemoteThread, NtWriteVirtualMemory | Common in malware |
| **Config Strings** | SleepInterval, Jitter, KillDate, WorkingHours | C2 configuration |
| **Process Names** | svchost.exe, explorer.exe, cmd.exe, powershell.exe | Masquerading targets |

### LOW Priority

| Category | Patterns | Why Low |
|----------|----------|---------|
| **Common Strings** | http, https, POST, GET, connect | Too generic |
| **Error Messages** | Error:, Failed:, Success | Not indicators |

## Search Commands

### C/C++ Implants

```bash
# C2 names and function names
grep -rn "beacon\|implant\|agent\|payload\|shellcode\|c2\|command" <implant_path> \
  -i --include="*.c" --include="*.cpp" --include="*.h"

# HTTP and network
grep -rn "http\|https\|post\|get\|connect\|socket\|send\|recv" <implant_path> \
  --include="*.c" --include="*.cpp" --include="*.h"

# Sensitive APIs
grep -rn "VirtualAlloc\|CreateThread\|WriteProcessMemory\|NtQueryInformationProcess\|CreateRemoteThread" <implant_path>

# HTTP headers
grep -rn "X-\|Cookie\|User-Agent\|Authorization\|Bearer\|Session" <implant_path> \
  --include="*.c" --include="*.cpp" --include="*.h"

# URL patterns
grep -rn "/api/\|/checkin\|/task\|/result\|/register" <implant_path> \
  --include="*.c" --include="*.cpp" --include="*.h"
```

### Go Implants

```bash
# C2 names
grep -rn "beacon\|implant\|agent\|payload\|c2" <implant_path> --include="*.go" -i

# Function names (Go style)
grep -rn "task\|job\|exec\|run\|process\|kill\|shell\|cmd" <implant_path> --include="*.go"

# Network
grep -rn "http\|https\|net\|dial\|request\|response\|client" <implant_path> --include="*.go"

# Config patterns
grep -rn "Sleep\|Jitter\|KillDate\|Interval" <implant_path> --include="*.go"
```

### Rust Implants

```bash
# C2 and function names
grep -rn "beacon\|implant\|agent\|payload\|task\|job\|exec" <implant_path> \
  --include="*.rs" -i

# Network
grep -rn "http\|https\|reqwest\|hyper\|tokio\|net" <implant_path> --include="*.rs"
```

## String Obfuscation Patterns

### Strings to Look For

| Pattern Type | Example | Detection Risk |
|--------------|---------|-----------------|
| Plaintext URL | `"http://c2.example.com/api"` | HIGH |
| Plaintext header | `"X-Beacon-Id: %s"` | HIGH |
| Plaintext API | `"kernel32.dll"` | MEDIUM |
| Config key | `"SleepInterval"` | MEDIUM |
| Debug string | `"[BEACON] Task received"` | HIGH |

### Obfuscation Methods

| Method | Before | After |
|--------|--------|-------|
| XOR | `"beacon"` | `char s[] = {0x07,0x06,0x0b,0x0c,0x0e,0x06}` |
| Stack string | `"beacon"` | `char s[] = {'b','e','a','c','o','n',0}` |
| XOR with key | `"beacon"` | `xor_string("beacon", 0x41)` |
| Base64 | `"beacon"` | `"YmVhY29u"` |
| Compile-time | `"beacon"` | `obf("beacon")` |

## Function Renaming

### Go Functions

Go binaries embed function names in symbol table - these are HIGH priority.

```bash
# Find Go function names that need renaming
grep -rn "func task\|func job\|func exec\|func shell" <path> --include="*.go"
```

**Before:**
```go
func taskProcess(cmd string) { }
func jobRun(id int) { }
func execBof(data []byte) { }
```

**After:**
```go
func cmdProc(cmd string) { }
func jobExec(id int) { }
func runObj(data []byte) { }
```

### C/C++ Functions

C/C++ function names are not embedded unless debug symbols are included.

```bash
# Check for debug symbols
file implant.exe
# Strip if needed
strip implant.exe
```

## Output Format

```markdown
## Sensitive Strings Found

### HIGH Priority

| String | File | Line | Category | Action |
|--------|------|------|----------|--------|
| "beacon_id" | config.h | 23 | C2 Name | Rename to "session_id" |
| "TaskProcess" | main.go | 45 | Function | Rename to "CmdProc" |
| "X-Beacon-Id" | http.go | 78 | HTTP Header | Obfuscate |
| "/api/checkin" | config.go | 12 | URL Pattern | Change to "/api/sync" |

### MEDIUM Priority

| String | File | Line | Category | Action |
|--------|------|------|----------|--------|
| "VirtualAlloc" | alloc.c | 34 | API | Hash or PEB walk |
| "SleepInterval" | config.h | 45 | Config | Obfuscate key name |

### Go Function Renames

| Original | New | File | Line |
|----------|-----|------|------|
| taskProcess | cmdProc | main.go | 45 |
| jobRun | jobExec | tasks.go | 120 |
| execBof | runObj | bof.go | 67 |
```

## Verification

After obfuscation, verify strings are removed:

```bash
# Check for old strings (should return nothing)
grep -rn "beacon\|TaskProcess\|X-Beacon-Id" <path>

# Check for new strings exist
grep -rn "session_id\|CmdProc\|X-Session-Id" <path>
```
