---
name: tools_evasion
description: Analyze penetration testing tools, find detection rules (YARA, Sigma, etc.), and directly modify source code to evade detection. Use this skill when the user wants to bypass tool detection, modify tool source code, or evade security products. Triggers on phrases like "tools evasion", "tool bypass", "tool detection", "免杀工具", "绕过检测", "工具源码改造", "工具免杀", "bypass tool", "evade detection", "tool modification". Supports penetration testing tools including recon, exploit, post-exploitation, scanners, and other security tools. For C2 frameworks, use c2_evasion skill instead.
version: 1.1.0
---

# Tools Evasion Skill

Analyze penetration testing tools and modify source code to evade detection for authorized security testing.

## Authorization Context

**AUTHORIZED USE CASE: Defensive Security Research**

- Understanding detection signatures to improve security products
- Red team assessments with explicit authorization
- Security product testing and evaluation
- Penetration testing with proper authorization

## Workflow

```
Phase 1: Tool Understanding
    ├─ Read README, docs
    ├─ Analyze source structure
    ├─ Identify core functionality
    └─ Determine tool purpose & scenarios
    ↓
Phase 2: Open Source Detection
    ├─ Check if open source
    ├─ Extract keywords (name, author, features)
    └─ Search GitHub for tool-specific rules
    ↓
Phase 3: Behavior Analysis
    ├─ Identify core behavior patterns
    ├─ Extract behavioral signatures
    └─ Search for behavior-based rules
    ↓
Phase 4: Rule Collection
    ├─ Save all rules to rules/{tool_name}/
    └─ Categorize by type (YARA/Sigma/etc.)
    ↓
Phase 5: Per-Rule Analysis
    ├─ Parse each rule's patterns
    ├─ Identify pattern sources in code
    └─ Develop evasion strategies
    ↓
Phase 6: Source Modification
    ├─ Apply targeted changes
    └─ Ensure functionality preserved
    ↓
Phase 7: Verification & Summary
    ├─ Verify patterns removed
    ├─ Document modifications
    └─ Report unevadable items
```

## Phase 1: Tool Understanding

### Step 1.1: Read Documentation

```bash
# Find and read documentation
ls -la <tool_path>
cat <tool_path>/README.md
cat <tool_path>/README*
cat <tool_path>/docs/*.md
```

### Step 1.2: Analyze Source Structure

```bash
# Identify programming language
find <tool_path> -name "*.go" -o -name "*.c" -o -name "*.py" -o -name "*.rs" -o -name "*.cs"

# Check build files
ls <tool_path>/Makefile <tool_path>/CMakeLists.txt <tool_path>/go.mod <tool_path>/Cargo.toml <tool_path>/*.csproj

# List main directories
ls -la <tool_path>/
```

### Step 1.3: Identify Core Functionality

Read main entry points and understand:
- What the tool does
- Target scenarios (recon, exploitation, post-exploitation, etc.)
- Key features
- Network behavior
- File operations
- API usage patterns

### Step 1.4: Output - Tool Profile

```markdown
## Tool Profile

| Attribute | Value |
|-----------|-------|
| Name | [tool name] |
| Language | [Go/C/Python/Rust/C#] |
| Type | [recon/exploit/C2/post-exploitation/scanner/etc.] |
| Open Source | [Yes/No] |
| Source URL | [if open source] |
| Core Features | [list] |
| Key Files | [list] |
```

## Phase 2: Open Source Detection

### Step 2.1: Determine if Open Source

Check for:
- `.git` directory
- `LICENSE` file
- Public repository URL in README
- Package manager files (go.mod, Cargo.toml, requirements.txt)

### Step 2.2: Extract Keywords

Extract from:
- Tool name
- Author names
- Feature descriptions
- Unique strings
- GitHub repository name (if found)

### Step 2.3: Search for Tool-Specific Rules

```bash
# Search by tool name
gh search code "<tool_name>" --extension yar
gh search code "<tool_name> yara" --extension yar
gh search code "<tool_name> detection" --extension yar
gh search code "<tool_name> malware" --extension yar
gh search code "<tool_name> rule" --extension yar

# Search by alternative names
gh search code "<alt_name1>" --extension yar
gh search code "<alt_name2>" --extension yar

# Search Sigma rules
gh search code "<tool_name>" --extension yml --filename sigma
gh search code "repo:SigmaHQ/sigma <tool_name>"

# Search other detection formats
gh search code "<tool_name> sigma"
gh search code "<tool_name> snort"
gh search code "<tool_name> suricata"
```

## Phase 3: Behavior Analysis

### Step 3.1: Identify Core Behavior Patterns

Analyze source code for:

| Behavior Category | Patterns to Look For |
|-------------------|---------------------|
| Network | HTTP headers, URL patterns, ports, protocols |
| File System | File paths, extensions, read/write patterns |
| Process | Process creation, injection, token manipulation |
| Registry | Registry keys, values, operations |
| Memory | Allocation patterns, permissions, execution |
| API Usage | Windows APIs, syscalls, library loading |
| Crypto | Encryption algorithms, keys, signatures |
| Strings | Error messages, log formats, identifiers |

### Step 3.2: Extract Behavioral Signatures

```markdown
## Behavioral Signatures

### Network Behavior
- HTTP User-Agent: [pattern]
- HTTP Headers: [headers]
- URL Patterns: [patterns]
- Ports: [ports]

### Process Behavior
- Process names: [names]
- Command lines: [patterns]
- Parent-child relationships: [patterns]

### File Behavior
- File paths: [paths]
- File names: [patterns]
- Extensions: [extensions]

### API Patterns
- API calls: [list]
- Call sequences: [sequences]
```

### Step 3.3: Search for Behavior-Based Rules

```bash
# Search by behavior patterns
gh search code "VirtualAlloc shellcode" --extension yar
gh search code "process injection" --extension yar
gh search code "<api_pattern>" --extension yar
gh search code "<http_header>" --extension yar

# Search in detection repositories
gh search code "repo:bartblaze/Yara-rules <behavior>"
gh search code "repo:Neo23x0/signature-base <behavior>"
gh search code "repo:elastic/protections-artifacts <behavior>"
gh search code "repo:CAPE-sandbox/CAPE-Yara <behavior>"
```

## Phase 4: Rule Collection

### Output Directory Structure

```
rules/{tool_name}/
├── yara/
│   └── *.yar
├── sigma/
│   └── *.yml
├── network/
│   └── *.rules
├── other_rules/
│   └── *.json, *.txt, etc.
├── tool_profile.md
├── behavior_analysis.md
└── rule_inventory.md
```

### Save Rules

For each rule found:
1. Save original rule file
2. Record source URL
3. Note detection target

## Phase 5: Per-Rule Analysis

**CRITICAL: Process EVERY rule, no skipping.**

For EACH detection rule:

### Step 5.1: Parse All Patterns

```markdown
## Rule Analysis: [rule_name]

### Rule Info
| Attribute | Value |
|-----------|-------|
| Source | [URL/Repo] |
| Author | [Author] |
| Type | [YARA/Sigma/etc.] |
| Target | [Component] |

### Patterns
| ID | Pattern | Type | Meaning |
|----|---------|------|---------|
| $s1 | "BeaconOutput" | string | HTTP header |
| $h1 | { 48 83 EC 58 } | hex | Function prologue |
| $r1 | /X-[a-z]+-Id/ | regex | Header pattern |
```

### Step 5.2: Identify Pattern Source

For each pattern, find source location:

| Pattern Type | Search Method |
|--------------|---------------|
| String | `grep -rn "string" <tool_path>` |
| Hex bytes | Convert to string, search source |
| API sequence | `grep -rn "API_name" <tool_path>` |
| Regex pattern | Extract literals, search source |

### Step 5.3: Develop Evasion Strategies

**Priority Order:**
1. **Compiler flags** (LOWEST effort, HIGHEST impact)
2. **Build configuration** (Makefile, CMakeLists, etc.)
3. **Source code changes** (if compiler flags insufficient)
4. **Struct/function refactoring** (last resort)

| Strategy | Priority | Effort | When to Use |
|----------|----------|--------|-------------|
| Compiler flags | 1 | Low | Function prologues, multiple patterns |
| String encryption | 2 | Low | String byte patterns |
| API obfuscation | 3 | Medium | API import patterns |
| Function rename | 4 | Medium | Function name patterns |
| Behavior change | 5 | High | Behavioral patterns |

### Step 5.4: Output - Evasion Plan

```markdown
## Evasion Plan for [rule_name]

### Patterns & Sources
| Pattern | Source File:Line | Evasion Strategy |
|---------|------------------|------------------|
| $s1 = "BeaconOutput" | http.go:78 | XOR encrypt |
| $h1 = { 48 83 EC 58 } | main.c:45 | Compiler flag |

### Implementation Steps
1. [Step 1]
2. [Step 2]

### Verification
grep -rn "BeaconOutput" <tool_path>  # Should return nothing
```

## Phase 6: Source Modification

**CRITICAL: Directly modify source files using Edit tool.**

### Step 6.1: Compiler Flags (Priority 1)

Check build files first:

**Makefile:**
```makefile
CFLAGS += -fno-stack-protector -fno-ident -O2
LDFLAGS += -Wl,--build-id=none -Wl,--gc-sections
```

**CMakeLists.txt:**
```cmake
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -fno-ident")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--build-id=none")
```

**go.mod:**
```bash
go build -ldflags="-s -w -buildid=" -trimpath
```

### Step 6.2: String Obfuscation (Priority 2)

```c
// Before
char* header = "X-Beacon-Id";

// After
char header[] = { 0x18, 0x02, 0x11, ... }; // XOR encrypted
void xor_decrypt(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) data[i] ^= KEY;
}
xor_decrypt(header, sizeof(header));
```

```go
// Before
header := "X-Beacon-Id"

// After
header := xorDecrypt([]byte{0x18, 0x02, 0x11, ...})
```

### Step 6.3: API Obfuscation (Priority 3)

```c
// Before
HMODULE hNtdll = LoadLibraryA("ntdll.dll");
LPVOID func = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

// After
// Use API hashing or dynamic resolution
DWORD hash = 0x...;
LPVOID func = GetAPIByHash(hash);
```

### Step 6.4: Function Rename (Priority 4)

```bash
# Search for function
grep -rn "func taskProcess" <tool_path>

# Replace function name (ensure uniqueness)
# Edit: taskProcess -> cmdProc
```

### Step 6.5: Build Configuration

```go
// go.mod - Add to build command
// -ldflags="-s -w -buildid=" -trimpath
```

## Phase 7: Verification & Summary

### Step 7.1: Verify Each Pattern

For each detection rule:
```bash
# Verify string patterns removed
grep -rn "pattern_string" <tool_path>

# Verify function names changed
grep -rn "old_function_name" <tool_path>

# Verify API patterns removed
grep -rn "LoadLibraryA" <tool_path>
```

### Step 7.2: Test Compilation

```bash
# Rebuild tool
cd <tool_path>
make clean && make
# OR
go build .
# OR
cargo build --release
```

### Step 7.3: Create Summary Report

Create `rules/{tool_name}/modifications_summary.md`:

```markdown
# Tools Evasion Report

## Tool Profile

| Attribute | Value |
|-----------|-------|
| Name | [tool name] |
| Language | [language] |
| Type | [tool type] |
| Open Source | [Yes/No] |
| Source URL | [if applicable] |

## Rules Analyzed

| Type | Count | Sources |
|------|-------|---------|
| YARA | X | bartblaze, Elastic, ... |
| Sigma | Y | SigmaHQ |
| Network | Z | ... |
| Other | N | ... |

## Core Behavior Patterns

| Category | Patterns | Risk Level |
|----------|----------|------------|
| Network | [patterns] | High/Medium/Low |
| Process | [patterns] | High/Medium/Low |
| File | [patterns] | High/Medium/Low |
| API | [patterns] | High/Medium/Low |

## Modifications Applied

### Build Configuration
| File | Change | Purpose |
|------|--------|---------|
| Makefile | Added -fno-stack-protector | Remove stack canary |
| go.mod | Added -ldflags="-s -w" | Strip symbols |

### Source Changes
| File | Line | Before | After | Reason |
|------|------|--------|-------|--------|
| http.go | 78 | "BeaconOutput" | XOR encrypted | YARA $s1 |
| main.c | 45 | taskProcess() | cmdProc() | Sigma rule |

### Pattern Status
| Rule | Pattern | Status | Notes |
|------|---------|--------|-------|
| rule1.yar | $s1 | ✅ Evaded | String encrypted |
| rule1.yar | $h1 | ✅ Evaded | Compiler flag |
| rule2.yar | $s2 | ⚠️ Unevadable | Core behavior |

## Unevadable Items

| Pattern | Rule | Reason | Mitigation |
|---------|------|--------|------------|
| "HTTP/1.1" | rule3.yar | Protocol requirement | Use alternative protocol |
| Process creation | rule4.yar | Core functionality | Rename process only |

## Detection Risk Assessment

**Overall Risk: Low/Medium/High**

- String signatures: [X/Y evaded]
- Hex patterns: [X/Y evaded]
- Behavioral patterns: [X/Y evaded]

## Recommendations

1. [Recommendation 1]
2. [Recommendation 2]

## Testing Notes

- [ ] Compilation successful
- [ ] Functionality preserved
- [ ] All patterns verified
```

## Reference Files

Read these files for detailed instructions:

| Phase | Reference File | Purpose |
|-------|----------------|---------|
| 2 | `references/detection_search.md` | YARA/Sigma search commands |
| 3 | `references/behavior_analysis.md` | Behavior pattern analysis |
| 5 | `references/rule_analysis.md` | Per-rule analysis & evasion planning |
| 6 | `references/source_modify.md` | Modification patterns |

## Important Rules

1. **NEVER skip a rule** - Every detection rule must have an analysis
2. **ALWAYS try compiler flags first** - Lowest effort, highest impact
3. **ONLY modify code in user-provided path** - Never touch other files
4. **PRESERVE functionality** - Tool must work after modification
5. **NEVER run/test modified tools** - Compilation success is sufficient
6. **Document everything** - All changes must be recorded
7. **Check binary assets** - Shellcode, resources, configs
8. **Verify after each change** - Confirm patterns are removed
9. **Report unevadable items** - Explain why evasion is not possible
10. **Direct modification** - Use Edit tool, don't just document

## Output Files

All outputs go to `rules/{tool_name}/`:

```
rules/{tool_name}/
├── yara/           # YARA rule files
├── sigma/          # Sigma rule files
├── network/        # Network detection rules
├── other_rules/          # Other detection formats
├── tool_profile.md       # Tool analysis
├── behavior_analysis.md  # Behavioral signatures
├── rule_inventory.md     # All rules found
├── rule_analysis/        # Per-rule analysis
│   ├── rule1.md
│   └── rule2.md
└── modifications_summary.md  # Final report
```
