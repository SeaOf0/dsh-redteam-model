# Spring Controller 型内存马（08-memory-shells / spring-controller）

- 注入路径：SPEL/反序列化点执行 injector（入口代码见 ControllerShell.java 头部注释：
  RequestContextHolder → WebApplicationContextUtils.getWebApplicationContext → inject）；
  注册后返回实际伪装路径供回连。
- 构建：`javac -cp "spring-webmvc-*.jar:spring-web-*.jar:spring-context-*.jar" ControllerShell.java`
- 技术侧：
  1. RequestMappingHandlerMapping.registerMapping 动态注册——无 Controller 类文件、无注解
     扫描痕迹；
  2. 伪装路径：health/metrics 类低注意力前缀 + 随机后缀（随机生成、注入方回读实际路径）；
  3. 触发仅凭 Header X-C；无头访问返回 "ok"（伪装健康检查接口）；
  4. 响应 Base64 包装 + 执行异常仍返回 "ok"（错误静默）；
  5. 防重复注册（同路径二次注册会抛异常 + 留下日志特征）。
- 变体登记：Interceptor 型；WebSocket 型（握手劫持）；WebFlux 路由型；headers 条件映射
  （把 X-C 触发条件编进 RequestMappingInfo——连 handle 内判断都省掉，但条件表达式进
  注册表，差集审计可见——取舍见页内注释）。
- 检测侧配对：
  1. 注册表差集审计：HandlerMapping 启动后新增映射 = 告警（actuator/mappings 对照基线）；
  2. 路由遥测：registerMapping 调用点监控（RASP 插桩）；
  3. 流量侧：伪装路径 + Header 触发的请求对（无前端引用入口的孤立 GET）；
  4. JVM 层：非磁盘类加载审计（ControllerShell 类无 jar 来源）。
- 判定表（本地实测后填）：| 检测面 | 结果 | 原文行 |
  jar 的符号（spring-webmvc/servlet-api 未提供：WebApplicationContext/
  RequestContextHolder/ServletRequestAttributes/RequestMappingHandlerMapping/
  RequestMappingInfo/RequestMethod/HttpServletRequest 共 8 个，无一处指向自身代码）；
  完整编译与运行时验证未做（无 Spring 环境），判定表留待本地实测后填。
