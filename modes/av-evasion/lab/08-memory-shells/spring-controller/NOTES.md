# Spring Controller 型内存马

- 注入路径：SPEL/反序列化点执行 injector；映射注册到伪装路径（/health 类低注意力面）。
- 技术侧：registerMapping 动态注册——无 Controller 类文件；触发走 Header。
- 变体登记：Interceptor 型、WebSocket 型（握手劫持）、WebFlux 路由型。
- 检测侧配对：HandlerMapping 注册表差集审计（启动后新增映射=告警）；actuator/mappings
  对照基线；路由注册遥测。
- 判定表：| 检测面 | 结果 | 原文行 |
