# Java 命令注入漏洞 完整解析

> 规则 ID：`any_any_cmdi` · 类别：cmdi · 关键 sink：ExecuteShellUtil, ExecuteShellUtils, ProcessBuilder, Runtime, command, exec, execute
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java 命令注入漏洞 完整解析
Java 命令注入漏洞是一类严重的代码执行漏洞，核心成因是**应用程序将不可信的用户输入直接拼接进系统命令执行逻辑中**，未做任何安全校验或转义，导致攻击者可构造恶意输入篡改原有命令逻辑，执行任意系统命令，进而控制服务器、窃取数据、破坏系统等。

该漏洞本质是“信任边界突破”：应用将用户可控的输入当作“可信的命令参数/逻辑”传递给操作系统执行，违背了“最小权限”和“输入不可信”的安全原则。


## 一、漏洞核心原理
Java 中执行系统命令的核心 API 主要分为两类，命令注入均围绕这些 API 展开：
### 1. 基础执行 API
- `Runtime.getRuntime().exec(String command)`：直接传入拼接好的命令字符串，底层会调用操作系统的命令解释器（如 Linux 的 `/bin/sh`、Windows 的 `cmd.exe`）执行。
- `Runtime.getRuntime().exec(String[] cmdarray)`：传入命令+参数的数组，理论上更安全，但仍可能因参数处理不当触发注入。
- `ProcessBuilder`：构造进程执行命令，本质与 `Runtime.exec` 一致，支持字符串或数组传参。

### 2. 注入触发逻辑
操作系统的命令解释器支持**命令拼接符**（如 `;`、`&&`、`||`、`|` 等），若用户输入被直接拼接进命令字符串，攻击者可通过拼接符截断原有命令，追加恶意命令。

示例（漏洞代码）：
```java
// 接收用户输入的文件名（可控输入）
String fileName = request.getParameter("fileName");
// 直接拼接进系统命令（Linux 场景：查看文件内容）
String command = "cat " + fileName;
// 执行命令
Process process = Runtime.getRuntime().exec(command);
```
攻击者输入：`/etc/passwd; rm -rf /`，拼接后命令变为：`cat /etc/passwd; rm -rf /`，操作系统会先执行 `cat`，再执行 `rm -rf /` 销毁系统文件。


## 二、命令注入的典型场景
### 场景 1：直接拼接字符串传参（最常见）
#### 特征
使用 `Runtime.exec(String command)` 或 `ProcessBuilder(String command)` 直接拼接用户输入，未做任何过滤/转义。
#### 触发条件
用户输入包含命令拼接符，且操作系统解释器支持该拼接符。
#### 不同系统的拼接符差异
| 操作系统 | 拼接符       | 作用                                  | 示例                          |
|----------|--------------|---------------------------------------|-------------------------------|
| Linux    | ;            | 分隔命令，依次执行（无论前序是否失败） | `ls; id`                      |
| Linux    | &&           | 前序命令成功后执行后续命令            | `ls /tmp && cat /etc/shadow`  |
| Linux    | \|\|         | 前序命令失败后执行后续命令            | `ls /xxx || whoami`           |
| Linux    | \|           | 管道，前序输出作为后序输入            | `ls -la | grep root`          |
| Linux    | `command`    | 执行子命令                            | `echo `whoami``               |
| Windows  | &            | 分隔命令，依次执行                    | `dir & ipconfig`              |
| Windows  | &&           | 前序成功后执行                        | `dir C:\ && net user`         |
| Windows  | \|\|         | 前序失败后执行                        | `dir D:\xxx || tasklist`      |
| Windows  | \|           | 管道                                  | `dir | findstr txt`           |
| Windows  | ^            | 转义符（可被利用绕过简单过滤）        | `dir ^& whoami`               |

#### 示例漏洞代码（Windows 场景）：
```java
String ip = request.getParameter("ip");
// 拼接 ping 命令
String cmd = "ping " + ip;
Process process = Runtime.getRuntime().exec(cmd);
```
攻击者输入：`127.0.0.1 & net user admin /add`，拼接后执行 `ping 127.0.0.1` 后，新增管理员账户。

### 场景 2：数组传参的“隐性注入”
开发者误以为使用 `exec(String[])` 数组传参就绝对安全，但以下情况仍会触发注入：
#### 情况 2.1：数组元素包含拼接符（参数被解释器解析）
```java
String ip = request.getParameter("ip");
// 数组传参，但 ip 包含拼接符
String[] cmdArray = {"ping", ip};
Process process = Runtime.getRuntime().exec(cmdArray);
```
攻击者输入：`127.0.0.1; whoami`，在 Linux 下，`exec` 会调用 `/bin/sh -c "ping 127.0.0.1; whoami"`，拼接符仍被解析。

#### 情况 2.2：手动拼接数组元素
```java
String arg1 = request.getParameter("arg1");
String arg2 = request.getParameter("arg2");
// 手动拼接数组元素，引入注入风险
String[] cmdArray = {"sh", "-c", "echo " + arg1 + " && echo " + arg2};
Process process = Runtime.getRuntime().exec(cmdArray);
```
攻击者输入 `arg1=test; rm -rf /`，拼接后数组第三个元素为 `echo test; rm -rf / && echo ...`，触发恶意命令。

#### 情况 2.3：Windows 下的 `cmd /c` 嵌套
```java
String file = request.getParameter("file");
String[] cmdArray = {"cmd", "/c", "type " + file};
Process process = Runtime.getRuntime().exec(cmdArray);
```
攻击者输入 `file=test.txt & net user`，`cmd /c` 会解析拼接符，执行后续恶意命令。

### 场景 3：间接命令注入（输入被二次处理后拼接）
用户输入并非直接拼接进命令，而是经过中间处理（如数据库查询、配置读取、日志拼接）后，被传入命令执行逻辑，属于“隐性注入”，更难发现。
#### 示例 3.1：从数据库读取可控内容拼接命令
```java
// 从数据库读取用户提交的“文件名”（已存入数据库）
String fileName = db.query("SELECT file_name FROM user_files WHERE id=?", userId).getString("file_name");
// 拼接命令执行
String cmd = "cat " + fileName;
Runtime.getRuntime().exec(cmd);
```
攻击者可通过篡改数据库中 `file_name` 字段为 `/etc/passwd; whoami`，触发注入。

#### 示例 3.2：配置文件中写入可控内容
```java
// 读取配置文件中的“备份路径”（用户可通过接口修改）
String backupPath = ConfigUtil.getConfig("backup.path");
String cmd = "tar -czf backup.tar.gz " + backupPath;
Runtime.getRuntime().exec(cmd);
```
攻击者修改配置文件中 `backup.path` 为 `/tmp/*; rm -rf /`，执行备份命令时触发删除操作。

### 场景 4：特殊字符绕过过滤的注入
若开发者仅做简单的字符过滤（如过滤 `;`、`&&`），攻击者可通过编码、转义、替代字符绕过，触发注入：
#### 情况 4.1：URL 编码绕过
过滤了 `;`，但攻击者输入 `%3b`（`;` 的 URL 编码），若应用未解码直接拼接：
```java
String input = request.getParameter("input");
// 仅过滤分号，未处理编码
input = input.replace(";", "");
String cmd = "echo " + input;
Runtime.getRuntime().exec(cmd);
```
攻击者输入 `%3b whoami`，应用解码后为 `; whoami`，绕过过滤。

#### 情况 4.2：转义字符绕过（Linux）
过滤了 `&&`，攻击者使用 `\&\&` 或 `&&` 的 Unicode 变体（如 `＆＆` 全角符号）：
```java
String input = request.getParameter("input");
input = input.replace("&&", "");
String cmd = "ls " + input;
Runtime.getRuntime().exec(cmd);
```
攻击者输入 `\&\& whoami`，拼接后命令为 `ls \&\& whoami`，Linux shell 会解析为 `ls && whoami`。

#### 情况 4.3：替代拼接符
过滤了 `;` 和 `&&`，但未过滤 `|` 或 `||`：
攻击者输入 `127.0.0.1 | whoami`，仍可执行恶意命令。

### 场景 5：跨平台注入（多系统兼容逻辑）
应用为兼容 Linux/Windows 编写跨平台命令执行逻辑，因不同系统拼接符、命令语法差异，导致过滤规则失效，触发注入：
```java
String os = System.getProperty("os.name").toLowerCase();
String input = request.getParameter("input");
String cmd;
if (os.contains("windows")) {
    cmd = "dir " + input;
} else {
    cmd = "ls " + input;
}
Runtime.getRuntime().exec(cmd);
```
攻击者可针对不同系统输入对应拼接符：Windows 输入 `test & net user`，Linux 输入 `test; whoami`，均触发注入。

### 场景 6：后台任务/定时任务中的注入
应用将用户输入写入定时任务脚本（如 crontab、Windows 计划任务），或后台异步执行的命令逻辑中，注入的恶意命令会在后台持续执行，危害更大：
```java
// 接收用户输入的“备份参数”，写入定时任务脚本
String backupParam = request.getParameter("backupParam");
String script = "echo 'tar -czf /backup.tar.gz " + backupParam + "' > /etc/cron.daily/backup.sh";
Runtime.getRuntime().exec(script);
```
攻击者输入 `backupParam=/tmp/*; rm -rf /`，定时任务执行时会触发删除操作。


## 三、命令注入的影响范围
1. **系统层面**：执行任意命令（如创建管理员账户、删除文件、下载恶意软件、开启端口转发），完全控制服务器；
2. **数据层面**：读取敏感文件（`/etc/passwd`、`/var/log`、数据库配置文件）、篡改数据、窃取用户信息；
3. **横向渗透**：利用服务器权限访问内网其他主机，扩大攻击范围；
4. **持久化攻击**：写入定时任务、后门脚本，实现长期控制。


## 四、易触发漏洞的业务场景
Java 应用中以下业务逻辑最易出现命令注入：
- 系统运维功能（如服务器监控、文件备份、日志清理）；
- 网络工具类功能（如 ping 检测、端口扫描、traceroute 路由追踪）；
- 文件操作功能（如文件解压、批量删除、格式转换）；
- 第三方工具调用（如调用 ffmpeg、ImageMagick、ffprobe 等命令行工具）；
- 云原生/容器场景（调用 docker/k8s 命令，如 `docker exec`、`kubectl`）。


## 五、关键注意点
1. `Runtime.exec()` 与 `ProcessBuilder` 本质无安全差异，核心风险是“输入是否可控+是否拼接”；
2. 命令注入的触发与操作系统强相关（拼接符、命令解释器不同），跨平台应用需关注多系统适配带来的漏洞；
3. 即使应用部署在容器/沙箱中，命令注入仍可突破容器隔离（如挂载宿主机目录时）；
4. 部分 Java 框架/库（如 Apache Commons Exec）封装了命令执行逻辑，若使用不当（如直接拼接输入），仍会触发注入。
