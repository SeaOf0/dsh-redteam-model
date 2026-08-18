# Source Modification for Tools

Patterns and techniques for modifying tool source code to evade detection.

## Modification Priority

**CRITICAL: Follow this order for minimal risk and maximum impact.**

```
1. Build Configuration (Makefile, CMakeLists, go.mod, Cargo.toml)
   └─ Lowest risk, affects multiple patterns
   
2. Compiler Flags
   └─ Low risk, can evade function prologues
   
3. String Obfuscation
   └─ Low risk, evades string patterns
   
4. API Obfuscation
   └─ Medium risk, evades API import patterns
   
5. Function/Variable Rename
   └─ Medium risk, evades name patterns
   
6. Logic Refactoring
   └─ High risk, evades behavior patterns
   
7. Behavior Modification
   └─ Highest risk, may break functionality
```

## 1. Build Configuration

### Makefile (C/C++)

```makefile
# Add to existing CFLAGS
CFLAGS += -fno-stack-protector -fno-ident -O2 -fomit-frame-pointer

# Add to existing LDFLAGS
LDFLAGS += -Wl,--build-id=none -Wl,--gc-sections -s

# Full example
CC = gcc
CFLAGS = -Wall -fno-stack-protector -fno-ident -O2 -fomit-frame-pointer
LDFLAGS = -Wl,--build-id=none -Wl,--gc-sections -s

all:
	$(CC) $(CFLAGS) -o tool main.c $(LDFLAGS)
```

### CMakeLists.txt (C/C++)

```cmake
# Add compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -fno-ident -O2 -fomit-frame-pointer")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector -fno-ident -O2 -fomit-frame-pointer")

# Add linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--build-id=none -Wl,--gc-sections -s")

# Strip symbols
add_custom_command(TARGET tool POST_BUILD COMMAND ${CMAKE_STRIP} tool)
```

### go.mod (Go)

```bash
# Build command with flags
go build -ldflags="-s -w -buildid=" -trimpath -o tool.exe

# Or in Makefile
build:
	go build -ldflags="-s -w -buildid=" -trimpath -o tool.exe

# For garble (Go obfuscator)
garble -tiny -literals -seed=random build -o tool.exe
```

### Cargo.toml (Rust)

```toml
[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Link-time optimization
codegen-units = 1   # Better optimization
panic = "abort"     # Remove panic unwinding
strip = true        # Strip symbols
```

```bash
# Build command
cargo build --release
```

### pyproject.toml / setup.py (Python)

```python
# Use PyInstaller with obfuscation
pyinstaller --onefile --noconsole \
    --key=your_secret_key \
    --add-data "data:data" \
    tool.py

# Or useNuitka for compilation
nuitka --standalone --onefile \
    --nofollow-imports \
    --output-dir=dist \
    tool.py
```

## 2. String Obfuscation

### C/C++ String Encryption

```c
// Before
char* header = "X-Beacon-Id";
char* url = "/api/checkin";

// After - XOR encryption
#include <string.h>

#define XOR_KEY 0x42

void xor_decrypt(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

// Encrypted strings (pre-computed)
char header[] = { 0x18, 0x02, 0x13, 0x27, 0x05, 0x27, 0x2b, 0x28, 0x03, 0x00 };
char url[] = { 0x26, 0x07, 0x29, 0x28, 0x00 };

// Usage
xor_decrypt(header, sizeof(header) - 1);
xor_decrypt(url, sizeof(url) - 1);
```

### Go String Encryption

```go
// Before
header := "X-Beacon-Id"
url := "/api/checkin"

// After - XOR encryption
const xorKey = 0x42

func xorDecrypt(data []byte) string {
    result := make([]byte, len(data))
    for i, b := range data {
        result[i] = b ^ xorKey
    }
    return string(result)
}

// Encrypted strings (pre-computed)
var headerEnc = []byte{0x18, 0x02, 0x13, 0x27, 0x05, 0x27, 0x2b, 0x28, 0x03}
var urlEnc = []byte{0x26, 0x07, 0x29, 0x28}

// Usage
header := xorDecrypt(headerEnc)
url := xorDecrypt(urlEnc)
```

### Python String Encryption

```python
# Before
header = "X-Beacon-Id"
url = "/api/checkin"

# After - XOR encryption
XOR_KEY = 0x42

def xor_decrypt(data: bytes) -> str:
    return bytes(b ^ XOR_KEY for b in data).decode()

# Encrypted strings (pre-computed)
header_enc = bytes([0x18, 0x02, 0x13, 0x27, 0x05, 0x27, 0x2b, 0x28, 0x03])
url_enc = bytes([0x26, 0x07, 0x29, 0x28])

# Usage
header = xor_decrypt(header_enc)
url = xor_decrypt(url_enc)
```

### Rust String Encryption

```rust
// Before
let header = "X-Beacon-Id";
let url = "/api/checkin";

// After - XOR encryption
const XOR_KEY: u8 = 0x42;

fn xor_decrypt(data: &[u8]) -> String {
    data.iter().map(|b| (b ^ XOR_KEY) as char).collect()
}

// Encrypted strings (pre-computed)
const HEADER_ENC: &[u8] = &[0x18, 0x02, 0x13, 0x27, 0x05, 0x27, 0x2b, 0x28, 0x03];
const URL_ENC: &[u8] = &[0x26, 0x07, 0x29, 0x28];

// Usage
let header = xor_decrypt(HEADER_ENC);
let url = xor_decrypt(URL_ENC);
```

## 3. API Obfuscation

### C/C++ API Hashing

```c
// Before
HMODULE hNtdll = LoadLibraryA("ntdll.dll");
LPVOID func = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

// After - API hashing
#include <windows.h>

DWORD hash_api(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

// Pre-computed hashes
#define HASH_NTALLOCATEVIRTUALMEMORY 0x...

LPVOID get_api_by_hash(HMODULE hModule, DWORD targetHash) {
    // Implementation to walk export table and find by hash
    // ...
}

// Usage
HMODULE hNtdll = LoadLibraryA("ntdll.dll");
LPVOID func = get_api_by_hash(hNtdll, HASH_NTALLOCATEVIRTUALMEMORY);
```

### Go API Hashing (Windows)

```go
// Before
mod := windows.NewLazySystemDLL("ntdll.dll")
proc := mod.NewProc("NtAllocateVirtualMemory")

// After - Use obfuscated names
import "golang.org/x/sys/windows"

var ntdllName = xorDecrypt([]byte{...}) // "ntdll.dll"
var funcName = xorDecrypt([]byte{...})  // "NtAllocateVirtualMemory"

mod := windows.NewLazySystemDLL(ntdllName)
proc := mod.NewProc(funcName)
```

## 4. Function/Variable Rename

### Rename Process

```bash
# 1. Search for all occurrences
grep -rn "oldFunctionName" <tool_path>

# 2. Verify no conflicts with new name
grep -rn "newFunctionName" <tool_path>

# 3. Replace all occurrences
# Use Edit tool for each file
```

### Naming Guidelines

| Before | After | Reason |
|--------|-------|--------|
| taskProcess | cmdProc | Remove obvious C2 naming |
| beaconCheckin | statusUpdate | Remove C2 terminology |
| shellcodeExec | memExec | Remove shellcode reference |
| implantConfig | appConfig | Remove implant reference |
| BeaconOutput | Response | Generic naming |

## 5. Network Signature Evasion

### HTTP Headers

```go
// Before
req.Header.Set("X-Beacon-Id", id)
req.Header.Set("User-Agent", "Beacon/1.0")

// After
req.Header.Set("X-Request-Id", id)  // Generic header
req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...")  // Legitimate UA
```

### URL Patterns

```go
// Before
url := "/api/beacon/checkin"
url := "/api/task/get"

// After
url := "/api/v1/status"    // Generic API pattern
url := "/api/v1/messages"  // Generic API pattern
```

## 6. Process Signature Evasion

### Process Names

```bash
# Search for process name references
grep -rn "process_name" <tool_path>
grep -rn "CreateProcess" <tool_path>
```

### Command Line Arguments

```c
// Before
char* args[] = {"--beacon", "--server", "http://..."};

// After
char* args[] = {"--config", "--url", "http://..."};
```

## Verification After Modification

### Verify String Patterns Removed

```bash
# Check for string patterns
grep -rn "BeaconOutput" <tool_path>  # Should return nothing
grep -rn "X-Beacon" <tool_path>      # Should return nothing
grep -rn "implant" <tool_path>       # Should return nothing
```

### Verify Function Names Changed

```bash
# Check for old function names
grep -rn "taskProcess" <tool_path>   # Should return nothing
grep -rn "beaconCheckin" <tool_path> # Should return nothing
```

### Verify Compilation

```bash
# Rebuild tool
cd <tool_path>
make clean && make

# Or for Go
go build -o tool.exe .

# Or for Rust
cargo build --release
```

## Important Rules

1. **Preserve functionality** - Every modification must maintain original behavior
2. **Document changes** - Record every change with reason
3. **Test compilation** - Verify tool compiles after each change
4. **Incremental changes** - Make one change at a time, verify after each
5. **Backup original** - Keep backup of original files
6. **No random changes** - Only modify what detection rules target
7. **Prioritize low-risk** - Use compiler flags before source changes
8. **Verify all patterns** - Re-check all detection patterns after changes

## 7. CRITICAL: Fixed-Length Protocol Fields

### ⚠️ 核心原则

**修改网络工具的字符串常量时，必须保持原有长度！**

### 高风险字符串类型

| 类型 | 风险 | 原因 |
|------|------|------|
| 协议UUID/标识符 | ❌ 高 | 固定长度字段 |
| Magic bytes | ❌ 高 | 协议握手验证 |
| 消息头字段 | ❌ 高 | 二进制解析依赖 |
| 日志消息 | ✅ 低 | 不参与协议解析 |
| Banner文本 | ✅ 低 | 纯显示用途 |
| 错误消息 | ✅ 低 | 纯显示用途 |

### 修改前检查

```bash
# 1. 检查固定长度读取
grep -rn "make(\[\]byte" --include="*.go"
grep -rn "io.ReadFull" --include="*.go"
grep -rn "recv(" --include="*.c"

# 2. 检查结构体定义
grep -rn "type.*struct" --include="*.go" | grep -i "header\|message"

# 3. 验证字符串长度
# 原始: len("IAMADMINXD") = 10
# 修改: len("CTRL-00001") = 10 ✅
```

### 修改规则

1. **计数长度** - 新字符串长度必须等于原长度
2. **检查用途** - 确认字符串是否参与协议解析
3. **立即测试** - 修改后立即测试连接功能
