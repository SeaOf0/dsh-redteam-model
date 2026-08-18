# Windows/IIS Webshell 检测

> 正文自写原创，不照抄原文，来源链接见文末。
> 适用：Web 服务器（IIS/.NET）疑似被植入 webshell 后的检测。内存马（无文件 webshell）专项见 memory-shell.md。

## 1. 检测维度总览

webshell 检测四个维度，按成本从低到高：

1. **日志维度**：IIS 访问日志里的异常请求特征（最快，先查）。
2. **文件维度**：网站目录里的可疑脚本文件（时间戳/内容）。
3. **静态特征**：危险函数与已知 webshell 指纹。
4. **专杀工具**：D盾/河马等对已知家族快速命中。

---

## 2. 日志维度（IIS W3SVC 日志）

IIS 日志默认路径 `C:\inetpub\logs\LogFiles\W3SVC<站点ID>\`，字段：`c-ip`（客户端 IP）、`cs-method`、`cs-uri-stem`、`cs-uri-query`、`sc-status`、`sc-bytes`、`cs(User-Agent)`。

### 2.1 直接查可疑请求

```powershell
# 聚合某 URI 的访问量与来源 IP（找高频被请求的可疑脚本）
Get-ChildItem C:\inetpub\logs\LogFiles -Recurse -Filter *.log | Select-String -Pattern "\.(aspx|ashx|asp|php|jsp)" |
  ForEach-Object { ($_ -split ' ') } |
  Group-Object { $_[4] } | Sort-Object Count -Descending | Select -First 30 Count,Name
```

```powershell
# 找「返回 200 但 URI 异常短 / 参数为 base64 / 单 IP 高频 POST」的请求
Get-ChildItem C:\inetpub\logs\LogFiles -Recurse -Filter *.log |
  Select-String -Pattern 'POST' | Where-Object { $_.Line -match 'sc-status 200' -and $_.Line -match '(eval|base64|cmd|execute|shell|pass|cmd=)' }
```

### 2.2 IIS 日志可疑判据

- **高频短 URI + 200**：正常页面 URI 语义明确，webshell 常是 `.aspx` 单文件被反复 POST，参数是加密串。
- **404 探测后的成功回连**：攻击者先 404 探测一批路径（`/xx.aspx`、`/shell.asp`），随后某 URI 开始 200——日志里「同一 c-ip 先 404 后 200」是植入成功的典型形态。
- **异常 User-Agent**：蚁剑/冰蝎等客户端 UA 特征（如 `AntSword`、`Behinder`、`python-requests`、空白 UA）。
- **POST 参数含 base64/加密串**：`cs-uri-query` 或 POST body 是长 base64（冰蝎/哥斯拉加密流量特征）。
- **单 c-ip 对大量不同 .aspx 发起请求**：扫描+爆破 webshell 口令。

### 2.3 IIS 请求体审计（配合 IIS Advanced Logging / failed request tracing）

IIS 默认不记 POST body，加密 webshell 流量在日志里只有「频繁 POST 200」这一弱特征。启用 IIS Advanced Logging 或 Failed Request Tracing 抓 body，或用网络侧（抓包/IDS）补全。

---

## 3. 文件维度

### 3.1 时间戳可疑

```powershell
# 网站目录最近 30 天新增/修改的脚本文件
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.aspx,*.ashx,*.asp,*.php,*.jsp,*.jspx,*.ashx,*.cshtml,*.asmx -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
  Select FullName,Length,CreationTime,LastWriteTime | Sort LastWriteTime -Descending
```

- 可疑判据：创建时间晚于修改时间（timestomp 痕迹）；单个脚本文件时间戳与同目录业务文件孤立（业务文件是部署时批量同时间，webshell 是后补的孤立时间）；文件在非发布时段被修改。

### 3.2 文件内容静态特征

```powershell
# 扫网站目录里的危险函数
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.aspx,*.ashx,*.asp,*.php -ErrorAction SilentlyContinue |
  Select-String -Pattern 'eval|assert|base64_decode|System\.Reflection|Process\.Start|Assembly\.Load|Runtime\.getRuntime|WScript\.Shell|cmd\.exe|Execute\(|CreateObject|Server\.CreateObject|eval_request|UdpOpen'
```

- 危险函数速查（跨语言）：

| 语言 | 危险函数/特征 |
|---|---|
| ASP/.NET | `eval`、`System.Reflection.Assembly.Load`、`Process.Start`、`Server.Execute`、`File.ReadAllText`、`cmd.exe` |
| PHP | `eval`、`assert`、`base64_decode`、`system`、`exec`、`shell_exec`、`preg_replace /e`、`create_function` |
| JSP | `Runtime.getRuntime().exec`、`ProcessBuilder`、`Class.forName`、反射加载 |

- 注意：危险函数单独出现不必然恶意（业务代码也可能用 `Process.Start`），需结合「文件是否新增/孤立 + 是否有加密串 + 是否接受外部参数」综合判疑。

## 4. 已知 webshell 家族指纹

| 家族 | 特征 | 识别要点 |
|---|---|---|
| 菜刀（chopper） | PHP/ASP 一句话，明文传输 | 常见 `eval($_POST[...])`、`@eval`、`execute`；流量里 `z0/z1/z2` 参数 |
| 蚁剑（AntSword） | 多语言，payload base64 | 请求里 `@ini_set("display_errors","0");@set_time_limit(0);` 开头；UA `AntSword` |
| 冰蝎（Behinder） | 加密流量（AES），动态加载 | 请求体 base64，返回体 base64；UA 默认空或 `Behinder`；`.jsp/.php/.aspx` 均可 |
| 哥斯拉（Godzilla） | 加密流量，密码口令 + key | 请求/响应均加密，特征弱；UA 常伪装；需解流量看 session |
| 天蝎（Skyscorpion） | 较新，加密 | 与哥斯拉类似，需静态特征 + 流量解密 |

- 指纹识别工具：D盾、河马(Hippo)、悬镜、长亭牧云等国内专杀可直接命中已知家族；`yara` 规则库（如 web shell yara）做自定义扫描。
- 手工确认：对命中的脚本看源码，核对「一句话特征 + 密码参数 + 危险函数」，避免误报。

## 5. 检测命令汇总（一屏版）

```powershell
# 1) 日志：高频脚本请求 + 先404后200 + 异常UA
Get-ChildItem C:\inetpub\logs\LogFiles -Recurse -Filter *.log | Select-String -Pattern '\.(aspx|ashx|php|jsp)' | Measure-Object
# 2) 文件：近期新增脚本
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.aspx,*.ashx,*.asp,*.php,*.jsp | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)}
# 3) 内容：危险函数
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.aspx,*.ashx,*.asp,*.php | Select-String -Pattern 'eval|System\.Reflection|Process\.Start|cmd\.exe'
# 4) 进程：Web 进程是否拉起 cmd/powershell 子进程（内存马/命令执行痕迹）
Get-CimInstance Win32_Process | Where-Object {$_.ParentProcessId -in (Get-Process w3wp,dotnet -ErrorAction SilentlyContinue).Id} | Select ProcessId,Name,CommandLine
```

- 判据：`w3wp.exe`（IIS worker）/`dotnet.exe`/`java.exe`（Tomcat）的子进程出现 `cmd.exe`/`powershell.exe`/`whoami`/`net` 等，说明 webshell 已执行系统命令（离被拿 shell 一步之遥）。

## 来源

- Microsoft Security Blog — IIS modules: The evolution of web shells and how to detect them：https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/
- 应急响应-web后门（中间件）排查思路（CSDN）：https://blog.csdn.net/qq_53577336/article/details/132127596
- 应急响应-网站入侵篡改指南 & Webshell 内存马查杀 & 漏洞排查 & 时间分析（腾讯云）：https://cloud.tencent.com/developer/article/2437226
- 专杀工具：D盾、河马(Hippo)、悬镜、长亭牧云（国内 webshell 静态查杀补充）
