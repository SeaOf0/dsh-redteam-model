# ASPX webshell 免杀（07-webshell-langs / ASPX 支线）

- 部署：上传至 IIS 站点目录（.aspx 即时编译）；执行体打包：C# 编译出含类型 P（public static
  string Run() / Run(string)）的程序集 → base64 作为 body，X-K 填 payload 的 SHA1 大写十六进制
  （`openssl dgst -sha1 Payload.dll` 取 hex 大写）。
- 技术侧（形态谱系）：①关键字变形 ②反射加载马（本实现：Assembly.Load(byte[]) 主路线、
  SHA1 请求-体绑定校验、X-A 可选传参、异常全静默 404；DLR 动态编译 CSharpCodeProvider/CodeDom
  变体以注释代码块保留在页尾）③IHttpModule 内存马（见 08）④与 02 AMSI 上下文破坏联合
  （脚本层扫描失效后本马静态侧零关键词）。
- 变体登记：ashx/asmx 形态（同反射路线换后缀）；Web.config handler 注册驻留；DLR 变体
  （兼容性差+特征函数多，取舍见页内注释块）。
- 检测侧配对：
  1. .NET 遥测：Assembly.Load 非镜像来源加载事件（EDR/ETW 主检测面，与 02 重叠）；
  2. 流量：POST .aspx + X-K 哈希头 + 高熵 base64 body（业务上传接口少见的签名-载荷对）；
  3. 静态：aspx 编译缓存与源文件差集；页面中反射/哈希组合的行为模型；
  4. 进程侧：DLR 变体的 csc.exe 编译进程链（仅选 DLR 路线才出现）。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
  为 Mono 实现，未用于本文件验证）；仅人工复核 + 括号配对粗检；运行时验证未做，判定表留待
  本地实测后填。
