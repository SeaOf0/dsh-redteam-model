# ASPX webshell 免杀

- 形态谱系：①关键字变形 ②反射加载马（本 demo）③IHttpModule 内存马（见 08）
  ④与 02 AMSI 上下文破坏联合。
- 检测侧配对：Assembly.Load 非镜像来源遥测；.NET 反射敏感调用（与 02 重叠）；
  aspx 编译行为模型。
- 变体登记：ashx/asmx 形态；Web.config handler 注册驻留。
- 判定表：| 引擎 | 结果 | 原文行 |
