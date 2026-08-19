# Java Agent 型注入（attach 路线）

- 路线：外部 attach（`com.sun.tools.attach.VirtualMachine.loadAgent`）注入构建好的 agent；
  agentmain 里走 `Instrumentation.retransformClasses` 挂钩 Filter 链/关键 Servlet——与
  Filter/Controller 型互补（对已加载类生效，不依赖容器注册入口）。
- agent jar 构建：MANIFEST 加 `Agent-Class`/`Launcher-Class`；前提=目标 JDK attach 机制可用。
- 检测侧配对：attach API 调用遥测；retransform 敏感类监控；JVM 工具接口使用审计。
- 判定表：| 检测面 | 结果 | 原文行 |
