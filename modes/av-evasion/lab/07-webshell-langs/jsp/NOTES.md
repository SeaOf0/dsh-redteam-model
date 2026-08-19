# JSP/JSPX webshell 免杀

- 形态谱系：①关键字变形马 ②加密通讯马 ③字节码马（本 demo：defineClass 动态类，
  执行逻辑不在页面）④表达式驻留（EL/OGNL 型，衔接 08 内存马）。
- 检测侧配对：defineClass/ClassLoader 动态定义类遥测（RASP）；JSP 编译后类行为模型；
  密文请求+明文响应统计特征。
- 变体登记：JSPX（XML 形态绕后缀策略）、taglib 混淆、落地即转内存驻留并自删。
- 判定表：| 引擎 | 结果 | 原文行 |
