# 内存马（无文件 Webshell）排查

> 正文自写原创，不照抄原文，来源链接见文末。
> 定义：内存马=不落盘、注入到 Web 进程内存的 webshell。文件系统查不到，重启进程即消失，是绕过文件扫描的高级持久化。

## 1. 内存马类型与原理

| 类型 | 载体 | 原理 |
|---|---|---|
| IIS Module 注入 | .NET / IIS 原生 | 向 IIS 进程注入恶意托管/原生 Module，劫持请求管线，不落盘 |
| .NET 反序列化马 | ASP.NET | 利用反序列化漏洞动态加载恶意程序集到内存 |
| Java Filter/Listener/Servlet | Tomcat/Java 中间件 | 动态注册 Filter/Servlet 到内存，接管请求 |
| PHP 无文件马 | PHP-FPM/Apache | 利用扩展/内存执行，不落盘 .php 文件 |
| 进程注入型 | 任意 Web 进程 | 注入 DLL/Shellcode 到 w3wp/httpd/java 进程，hook 请求处理函数 |

共同特征：**磁盘上无 webshell 文件，但 Web 进程内存里有恶意代码/模块，且会产生与落盘 webshell 相同的行为痕迹（执行系统命令、外连）**。

## 2. 检测思路总纲

内存马「无文件」但「有行为」，从三条线入手：

1. **进程行为线**：Web 进程是否拉起 cmd/powershell 子进程、是否外连、是否加载了可疑模块。
2. **内存取证线**：dump Web 进程内存，搜 webshell 指纹/命令痕迹/可疑模块。
3. **日志与配置线**：IIS/中间件日志里的异常请求 + 中间件配置是否被动态改。

---

## 3. IIS Module 注入检测

### 3.1 枚举已加载的 IIS 模块

```powershell
# 列 IIS 全局模块与站点模块（对比基线，找新增）
Get-WebGlobalModule | Select Name,Image,Precondition
Get-WebModule | Select Name,Image,Precondition
# IIS 配置里的模块注册
appcmd.exe list modules
appcmd.exe list config -section:system.webServer/modules
```

- 可疑判据：出现不在基线里的模块名/镜像路径（镜像在临时目录、用户目录，或模块名伪装成系统模块名）；原生模块（`<globalModules>`）被新增。

### 3.2 枚举 IIS worker 进程加载的原生/托管模块

```powershell
# 找 w3wp 进程，列加载的 DLL（重点看非 System32 路径）
Get-Process w3wp -ErrorAction SilentlyContinue | ForEach-Object {
  $_.Modules | Where-Object {$_.FileName -notlike "C:\Windows\*"} | Select ModuleName,FileName
}
```

- 可疑判据：`w3wp.exe` 加载了来自临时目录/用户目录/网站目录的 DLL（正常 IIS 模块来自 System32/inetsrv/GAC）。

### 3.3 查 IIS 请求管线劫持痕迹

- Failed Request Tracing（FRT）：开启后抓命中可疑请求的完整 pipeline 事件，看是否有非预期模块参与处理。
- ETW：`Microsoft-Windows-IIS-*` 提供程序记录模块事件，用 `logman` 抓取。

---

## 4. .NET 内存马（反序列化/Assembly.Load）

```powershell
# 查 w3wp/dotnet 进程加载的托管程序集（内存加载不落盘，需 dump 分析）
# 用 dotnet-dump / procdump 抓 w3wp 内存，再用 clrmd 或 dnSpy 分析 AppDomain 里的程序集
procdump -ma <w3wp_pid> w3wp.dmp
```

- 可疑判据：dump 分析发现 AppDomain 里加载了来源为字节数组/网络的程序集（`Assembly.Load(byte[])` 特征），或存在 `System.Reflection` 动态编译痕迹。
- 反序列化入口线索：IIS 日志里出现大量对同一端点（如 `*.ashx`、`/__browserLink`）的异常 POST，配合已知 .NET 反序列化漏洞（`BinaryFormatter`、`LosFormatter`、`ObjectStateFormatter`）判断。

## 5. Java Filter/Listener/Servlet 动态注册检测（Tomcat 等）

### 5.1 内存中动态注册的 Filter/Servlet

```bash
# 用 arthas 挂到 java 进程，枚举内存中的 Filter/Servlet 与请求映射
./as.sh <java_pid>
# 在 arthas 里：
sc -d javax.servlet.Filter      # 查 Filter 类
vmtool --action getInstances --className javax.servlet.Filter --limit 20   # 查实例
```

- 可疑判据：内存里存在不在 web.xml / 注解基线里的 Filter/Servlet 类（类名随机、继承 `javax.servlet.http.HttpServlet`）；存在动态注册（`ServletContext.addFilter/addServlet` 被反射调用）痕迹。

### 5.2 Java 进程行为

```powershell
# java 进程是否拉起 shell 子进程
Get-CimInstance Win32_Process | Where-Object {$_.ParentProcessId -in (Get-Process java -ErrorAction SilentlyContinue).Id} | Select ProcessId,Name,CommandLine
```

## 6. PHP 无文件马

- 原理：PHP 的 `eval`/`assert` 直接执行内存里的 payload，或利用 `php://filter`、`include` 远程/数据流，不写 .php 文件。
- 检测：`php.ini` 里 `disable_functions` 是否被绕过、`auto_prepend_file`/`auto_append_file` 是否指向可疑流；PHP-FPM 进程是否拉起 shell 子进程；访问日志里的异常 URI（`php://input`、data 流、加密参数）。

## 7. 内存分析要点（通用）

```powershell
# 1) 抓 Web 进程内存
procdump -ma <pid> web.dmp
# 2) 用 Volatility 3 分析（windows.malfind 查注入、windows.dlllist 查模块、windows.cmdline 查命令行）
python3 vol.py -f web.dmp windows.malfind
python3 vol.py -f web.dmp windows.dlllist
python3 vol.py -f web.dmp windows.cmdline
# 3) 在 dump 里搜 webshell 特征串
strings web.dmp | findstr /i "eval cmd.exe /bin/sh AntSword Behinder"
```

- 判据：`malfind` 命中带 `PAGE_EXECUTE_READWRITE` 的注入区域；`dlllist` 出现来源不明的 DLL；dump 里搜到 webshell 家族关键词（`AntSword`/`Behinder`/`eval`/`Process.Start`/`Runtime.getRuntime`）。

## 8. 处置要点

- 内存马重启进程即清，但**入口漏洞与持久化根因必须同时修**，否则会再被注入：
  1. 定位入口：反序列化漏洞/上传漏洞/中间件漏洞 → 打补丁/改配置。
  2. 清持久化：查中间件配置文件、启动脚本是否被篡改（把注入逻辑写成开机自启）。
  3. 杀进程重启：确认根因清除后，重启 Web 进程/服务（`iisreset` / 重启 Tomcat）。
  4. 复检：重启后再次 dump 验证内存马已消失。

> 处置动作（iisreset/重启进程）属变更性操作，须用户确认后执行。

## 来源

- Microsoft Security Blog — IIS modules: The evolution of web shells and how to detect them：https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/
- Volatility 3（内存分析）：https://github.com/volatilityfoundation/volatility3
- Arthas（Java 进程诊断）：https://github.com/alibaba/arthas
- 应急响应-web后门（中间件）排查思路（CSDN）：https://blog.csdn.net/qq_53577336/article/details/132127596
