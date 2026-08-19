# Tomcat Filter 型内存马

- 注入路径：反序列化/JNDI/文件马执行 injector → 注册动态 Filter → 自删落地文件（无文件态）。
- 技术侧：addFilter + setUrlPatterns(/*) 全局劫持；触发走自定义 Header——无路径特征。
- 变体登记：Listener 型（ServletRequestListener）、Servlet 型、Valve 型（管道更深处）。
- 检测侧配对：运行时动态 Filter 注册遥测（RASP）；全量 URL 模式 Filter 审计；内存 dump
  与 web.xml 部署描述符差集比对。
- 判定表：| RASP/EDR | 结果 | 原文行 |
