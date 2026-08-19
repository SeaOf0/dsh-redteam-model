# ASPX IHttpModule 型内存马

- 注入路径：文件马执行注册 → 自删；.NET Framework 版本决定注册面（web.config modules /
  HttpApplication 动态事件 / PreApplicationStartMethod）。
- 检测侧配对：modules 注册差集审计；BeginRequest 钩子链枚举比对；IIS 配置变更遥测。
- 判定表：| 检测面 | 结果 | 原文行 |
