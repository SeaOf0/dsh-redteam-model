# Hex Pattern Deep Analysis

Analyze hex patterns in YARA rules and identify source-level causes and evasion methods.

## Key Principle

**Hex patterns are NOT unchangeable.** They represent compiled code features that CAN be modified through source code changes or compiler flags.

## Hex Pattern Categories

| Category | Example | Source Cause | Evasion Method |
|----------|---------|--------------|----------------|
| **PE Header** | `{ 4D 5A 90 }` | DOS stub | Makefile flags |
| **Function Prologue** | `{ 48 83 EC 58 }` | Stack allocation | Reduce locals, use heap |
| **String in Code** | `{ 68 74 74 70 }` | "http" in binary | Obfuscate strings |
| **Config Structure** | `{ 8D ?? ?? E8 }` | Struct init | Reorder struct fields |
| **API Call Sequence** | `{ B9 77 00 00 }` | Wininet calls | Change API order |
| **Magic Constants** | `{ 41 42 43 44 }` | Hardcoded values | Change constants |
| **Build Artifacts** | Timestamp, checksum | Compiler generated | Makefile flags |

## Analysis Process

### Step 1: Convert Hex to ASCII

```bash
# Check if hex represents a string
echo "48 65 6C 6C 6F" | xxd -r -p
# Output: Hello
```

### Step 2: Locate in Binary

```bash
# Find hex pattern in binary
xxd implant.exe | grep -i "4883 ec 58"

# Use objdump to identify function
objdump -d implant.exe | grep -B 20 "48 83 ec 58"
```

### Step 3: Map to Source

```bash
# Function prologue indicates stack allocation
# 0x58 = 88 bytes, look for:
grep -rn "char buffer\[88\]" <source_path>
grep -rn "char buffer\[0x58\]" <source_path>
grep -rn "int locals\[22\]" <source_path>  # 88/4 = 22

# API call sequences
grep -rn "InternetOpenA\|InternetConnectA\|HttpOpenRequestA" <source_path>
```

### Step 4: Identify Evasion Strategy

| Source Pattern | Hex Impact | Evasion |
|----------------|------------|---------|
| `char buf[0x100]` | Function prologue | Use heap or reduce size |
| `InternetOpenA()` before `InternetConnectA()` | Call sequence | Reorder calls |
| `"http://"` | String bytes | Encrypt string |
| `#define MAGIC 0x1234` | Constant bytes | Change value |

## Makefile Analysis

Check build files for evasion opportunities:

```bash
find <path> -name "Makefile" -o -name "CMakeLists.txt" -o -name "*.cmake" -o -name "build.sh"
```

### Makefile Evasion Flags

| Flag | Effect | Hex Impact |
|------|--------|------------|
| `-O0` vs `-O2` | Different optimization | Different code structure |
| `-fno-stack-protector` | Remove canary | Removes stack check bytes |
| `-fno-asynchronous-unwind-tables` | Remove unwind | Removes CFI tables |
| `-Wl,--strip-all` | Strip symbols | Removes symbol table |
| `-Wl,--build-id=none` | Remove build ID | Removes unique bytes |
| `-Wl,--file-alignment=0x200` | Section alignment | Changes PE structure |
| `-ffunction-sections` | Separate functions | Changes section layout |
| `-fno-ident` | Remove ident | Removes compiler strings |
| `-static` vs `-dynamic` | Linking mode | Changes import table |
| `-mtune=` | CPU tuning | Different instructions |

### Example Makefile Modification

```makefile
# Before
CFLAGS = -O2 -g

# After (evasion-focused)
CFLAGS = -O2 -fno-stack-protector -fno-asynchronous-unwind-tables \
         -fno-ident -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--strip-all -Wl,--build-id=none -Wl,--gc-sections
```

## Source Code Changes

### Function Prologue Evasion

```c
// Before - creates prologue { 48 83 EC 58 }
void func() {
    char buffer[0x50];  // 80 bytes on stack
    int locals[10];
}

// After - different prologue
void func() {
    char* buffer = malloc(0x50);  // Heap allocation
    // Different hex pattern
}
```

### API Sequence Evasion

```c
// Before - fixed sequence
hInternet = InternetOpenA(...);
hConnect = InternetConnectA(hInternet, ...);
hRequest = HttpOpenRequestA(hConnect, ...);

// After - different order or APIs
hSession = WinHttpOpen(...);
hConnect = WinHttpConnect(hSession, ...);
```

### String Evasion

```c
// Before - plaintext string
char* url = "http://c2.example.com";

// After - XOR encrypted
char url[] = { 0x3a, 0x37, 0x37, 0x34, ... };  // XOR'd "http"
```

## Output Format

```markdown
## Hex Pattern Analysis

| Pattern | Type | Source Cause | Evasion Method | Status |
|---------|------|--------------|----------------|--------|
| { 48 83 EC 58 } | Function prologue | func() allocates 0x58 | Reduced to 0x30 | ✓ Evaded |
| { B9 77 00 00 } | API sequence | Wininet calls | Reordered calls | ✓ Evaded |
| { 4D 5A 90 00 } | PE header | DOS stub | Makefile flags | Skip (standard) |

## Makefile Changes

| File | Flag Added | Purpose |
|------|------------|---------|
| Makefile | -fno-stack-protector | Remove canary bytes |
| Makefile | -Wl,--build-id=none | Remove build ID |
```
