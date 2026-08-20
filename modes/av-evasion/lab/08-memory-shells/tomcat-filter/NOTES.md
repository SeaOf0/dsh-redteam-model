# Tomcat Filter 型内存马（08-memory-shells / tomcat-filter）

- 注入路径：反序列化/JNDI/初始 webshell 执行 `FilterShell.inject(application)` → 注册动态
  Filter → 手工删除落地引导马（无文件态收尾，自删步骤见 FilterShell.java 头部注释——不在
  代码内自动删，删除行为本身是检测点）。
- 构建：
  `javac -cp "$CATALINA_HOME/lib/servlet-api.jar:$CATALINA_HOME/lib/catalina.jar" FilterShell.java`
  （Tomcat 9+ 时 FilterDef/FilterMap 位于 org.apache.tomcat.util.descriptor.web 包，需改 import）。
- 技术侧：
  1. 注册三步（经典路线）：addFilterDef(FilterDef) → addFilterMap(FilterMap, /*, REQUEST) →
     反射插入 filterConfigs（ApplicationFilterConfig 构造）——filterStart 已跑过的容器必须
     走此步，否则新 FilterDef 不进过滤链；
  2. Filter 名随机化（反检测：无字典特征，静态审计常见命名不命中）；
  3. 触发仅凭 Header X-C——URL 路径零特征；
  4. 响应 Base64 包装（stdout[|stderr]），避免明文回显流量特征；
  5. 防重复注入（injected 标志）；执行异常静默放行（业务链路不中断）。
- 变体登记：Listener 型（ServletRequestListener 不占 Filter 链位置）；Servlet 型；Valve 型
  （管道更深处、绕 Filter 链审计）；Connector 型（HTTP 协议层）；addFilter+filterStart 简化
  路线（仅容器启动早期可用）；大输出双线程并发读（防管道满死锁）。
- 检测侧配对：
  1. RASP/容器遥测：运行态动态 Filter 注册（addFilterDef/addFilterMap 调用点）；
  2. 差集审计：StandardContext.filterConfigs 与 web.xml 声明差集（运行态新出现 = 告警）；
  3. 配置侧：全量 URL 模式（/*）Filter 审计（业务应用极少注册全量 Filter）；
  4. JVM 层：非磁盘类加载审计（匿名 Filter 类无 jar 来源）；内存 dump 与部署描述符比对。
- 判定表（本地实测后填）：| RASP/EDR | 结果 | 原文行 |
  jar 的符号（servlet-api/catalina 未提供：ServletContext/Filter/FilterDef/FilterMap/
  StandardContext/ApplicationFilterConfig/Context 共 7 个，无一处指向自身代码）；完整
  编译与运行时验证未做（无 Tomcat 环境），判定表留待本地实测后填。
