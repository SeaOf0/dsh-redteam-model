# ASPX IHttpModule 型内存马（08-memory-shells / aspx-module）

- 注入路径：文件马（如 07 reflect.aspx）执行 `M.ModuleInjector.Install(HttpContext.Current)`
  → 反射写入运行态 _moduleCollection → 手工删除落地引导马（无文件态收尾，自删步骤见
  ModuleShell.cs 头部注释——不在代码内自动删）。演示亦可走 web.config <modules> 静态注册。
- 构建：`mcs -target:library -r:System.Web ModuleShell.cs`（Mono 演示）；IIS 侧用 csc 编译为
  dll 放 /bin，或与引导马同页内联（aspx 内直接定义本类）。
- 技术侧：
  1. 双事件面：BeginRequest（链首劫持，Header X-C 触发执行）+ PreSendRequestContent
     （响应输出前 Clear + Base64 包装——避免 Response.End 截断管线的线程中止异常）；
  2. 注册面按 .NET 版本选：web.config modules / 反射 _moduleCollection（本注入器）/
     PreApplicationStartMethod；
  3. 模块名随机化（反静态审计）；触发仅凭 Header（URL 零特征）；
  4. 执行异常静默（业务链路不中断）。
- 变体登记：PreApplicationStartMethod 反射驻留；managed module 换 native module
  （IIS C++ 模块）；Global.asax 事件直挂（无需模块注册）。
- 连接管理：本型内存马可由 dsh-webshell-mgr 的 dsh-mem 通道直连（X-C 头触发，stderr 段原文兼容）。
- 检测侧配对：
  1. 差集审计：运行态 _moduleCollection 与 web.config 声明差集（新模块 = 告警）；
  2. 钩子链枚举：BeginRequest 事件委托链比对基线（IIS ETW/遥测可列委托）；
  3. 配置遥测：IIS 配置变更 / AppDomain 内反射调用监控；
  4. 无文件驻留检测面：w3wp.exe 进程内存 dump 与部署目录差集比对。
- 判定表（本地实测后填）：| 检测面 | 结果 | 原文行 |
  ModuleShell.cs`，exit 0，产物定向到 /tmp/lab_check/ModuleShell.dll，未在仓库内生成文件）；
  运行时验证未做（无 IIS/.NET Framework 判定环境），判定表留待本地实测后填。
