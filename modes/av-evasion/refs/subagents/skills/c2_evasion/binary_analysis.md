# Binary Asset Analysis

Analyze embedded binary resources in C2 projects that YARA rules may target.

## Key Principle

C2 projects often contain embedded resources (shellcode, binaries, configs) that are **high-value detection targets**.

## Asset Types to Find

### 1. Binary Files

```bash
# Find all binary files
find <path> -type f \( -name "*.bin" -o -name "*.raw" -o -name "*.dat" -o -name "*.rsrc" -o -name "*.res" \)
```

### 2. Embedded Shellcode (in source)

```bash
# Find embedded shellcode in hex arrays
grep -rn "0x[0-9a-fA-F]\{2\}.*0x[0-9a-fA-F]\{2\}.*0x[0-9a-fA-F]\{2\}" <path> \
  --include="*.c" --include="*.cpp" --include="*.h"

# Find base64 encoded content
grep -rn "[A-Za-z0-9+/]\{40,\}=" <path> \
  --include="*.c" --include="*.cpp" --include="*.go"
```

### 3. Resource Files

```bash
# Find resource files
find <path> -type f \( -name "*.rc" -o -name "*.res" -o -name "*.rsrc" -o -name "resources*" \)

# Check for embedded resources in .rc files
grep -rn "RCDATA\|BITMAP\|ICON\|MANIFEST" <path> --include="*.rc"
```

### 4. Configuration Templates

```bash
# Find config files with potential signatures
find <path> -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" -o -name "*.conf" \)

# Check for hardcoded values
grep -rn "User-Agent\|X-\|Cookie\|Authorization\|Bearer\|Session" <path> \
  --include="*.json" --include="*.yaml"

# Check for default ports, URLs, paths
grep -rn ":[0-9]\{4,5\}\|http://\|https://\|/api/\|/checkin\|/task" <path> \
  --include="*.json" --include="*.yaml"
```

## Shellcode Analysis

### Common Patterns to Detect

| Pattern | Hex | Detection Type |
|---------|-----|----------------|
| MZ Header | `{ 4D 5A }` | PE shellcode |
| Function Prologue | `{ 55 8B EC }` or `{ 48 89 5C 24 }` | x86/x64 prologue |
| Syscall Stub | `{ 4C 8B D1 B8 }` | Direct syscall |
| API Call | `{ B8 ?? ?? ?? ?? FF D0 }` | Call eax |
| String | `"kernel32.dll"` | Hardcoded string |

### Analyze Shellcode

```bash
# View shellcode bytes
xxd shellcode.bin | head -50

# Extract strings
strings shellcode.bin

# Check for PE header
xxd shellcode.bin | grep "4d5a"
```

## Evasion Strategies

### Option A: Encrypt Shellcode

```c
// Original (detectable)
unsigned char shellcode[] = { 0x4d, 0x5a, 0x90, ... };

// After (encrypted)
unsigned char shellcode_encrypted[] = { 0x0c, 0x1b, 0xd1, ... }; // XOR with key

void decrypt_shellcode(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Usage
decrypt_shellcode(shellcode_encrypted, sizeof(shellcode_encrypted), 0x41);
```

### Option B: Replace Shellcode

Generate new shellcode with different characteristics:
- Use different encoder
- Use different shellcode generator
- Modify existing shellcode

### Option C: Modular Loading

```c
// Instead of embedding, load from external source
unsigned char* shellcode = load_from_resource(IDR_SHELLCODE);
// or
unsigned char* shellcode = download_shellcode(config.url);
```

### Option D: Change Format

```c
// Instead of raw bytes, use base64 with encryption
char* shellcode_b64 = "BASE64_ENCODED_ENCRYPTED_DATA";
unsigned char* shellcode = base64_decode(decrypt(shellcode_b64));
```

## Detection Risk Assessment

| Asset Type | Detection Risk | Priority |
|------------|----------------|----------|
| Embedded shellcode (.bin) | **HIGH** | Modify immediately |
| Shellcode in source (hex array) | **HIGH** | Encrypt or externalize |
| Config with hardcoded values | **MEDIUM** | Obfuscate |
| Icons/manifests | **LOW** | Change metadata |
| Default binaries | **HIGH** | Replace with custom |

## Output Format

```markdown
## Binary Assets Analyzed

| Asset | Type | Size | Detection Risk | Action |
|-------|------|------|----------------|--------|
| shellcode.bin | Raw shellcode | 4KB | HIGH | Encrypt with XOR |
| beacon.bin | PE binary | 64KB | HIGH | Replace/modify |
| config.json | Template | 2KB | MEDIUM | Obfuscate strings |
| resource.rc | Resource file | 1KB | LOW | No changes needed |

## Embedded Shellcode in Source

| File | Line | Pattern | Action |
|------|------|---------|--------|
| loader.c:45 | 0x4d, 0x5a, ... | MZ header | Encrypt with XOR key 0x41 |
| beacon.go:120 | base64 string | Encoded shellcode | Add encryption layer |

## Config Templates

| File | Hardcoded Values | Action |
|------|------------------|--------|
| profile.yaml | User-Agent, X-Beacon-Id | Obfuscate strings |
| config.json | /api/checkin, /api/task | Change paths |
```
