# dsh-webshell-mgr「webshell 管理」

会话标签页「webshell 管理」（conversation.view，位于 hunter 狩猎右侧）：连接注册表 + 协议自动识别 +
命令执行 / 虚拟终端 + 文件管理（二进制安全传输/权限/时间戳伪造/远程下载）+ 数据库控制台（PDO 原生）+
生成器 + 声明式载荷插件体系；模型工具面授权五安全模式；包内同核 stdio MCP 服务供外部 harness 接入。

## 架构

```
lib/index.js            宿主入口：/dsh-webshell-mgr 前缀路由（同源信任栅栏）+ 八件模型工具
lib/store.js            SQLite ~/.dsh/webshell-mgr/webshell.db
                        （connections / conn_states / db_profiles / generations / op_log）
lib/protocol/
  registry.js           协议注册表 + 自动识别链（detect 顺序见下表）
  http-client.js        node:http/https 直连（自签放行/超时/多字符集解码/Cookie 罐）
  command-build.js      命令翻译层：三套引号转义 + ls/dir 解析 + 文件操作→命令映射
  snippets.js           PHP 片段库（eval 通道的结构化操作：ls/读写/数据库 PDO…）
  capabilities.js       能力层：统一操作面（原生操作码 > eval 片段 > 命令翻译）
  cmd.js / dsh-aes.js / behinder.js / godzilla.js / behinder-mod.js / godzilla-mod.js
lib/generators.js       生成器（10 种产物模板）
lib/plugins-registry.js 载荷插件注册表（声明式 plugin.json + 模板渲染 + 通道执行）
lib/client.js           会话标签页 UI（手写 CJS bundle，React.createElement，零构建）
mcp/server.mjs          零依赖 stdio JSON-RPC 2.0 MCP 服务（与宿主同核同库）
plugins/examples/       随包示例载荷插件（sysinfo / portscan）
```

宿主平面（UI 常驻全模式）；工具面执行时解析 composedPreset，仅
redteam / pentest / attack-defense / av-evasion / ctf-solver 五模式放行。
不走 connection.rpc（部分 fiber 静默 405 坑）；全部操作入 op_log 台账（报告门/清痕对账用）。

## 协议矩阵（自动识别顺序 = 下表序）

| 通道 | 形态 | 密钥/凭据 | 能力 | 备注 |
|---|---|---|---|---|
| dsh-aes | 自研加密马 v1/v2 | 每请求随机（X-T 头携带 IV‖KEY） | cmd + 二进制读写（u/d）+ eval（v2 e 操作码） | 与免杀侧加密马同协议；首选 |
| dsh-mem | 内存马（X-C 头触发） | 无凭据（触发头即凭据） | cmd（文件走命令翻译） | Filter/Controller/Module 型内存马；URL 任意存活路径；回显 b64(stdout)[\|stderr]，stderr 段原文兼容 |
| cmd-eval | 一句话 eval（PHP） | pass 参数名 + 口令 | cmd + eval 片段（结构化全量） | 蚁剑默认马同形 |
| cmd-system | 口令门+命令参数马 | 口令参数 + 命令参数 | cmd（文件/数据库走命令翻译） | 通用兜底 |
| behinder | 冰蝎型 PHP（AES-128-ECB） | key=md5(密码)[0:16] | cmd + eval 片段（桥接载荷） | 桥接 payload 赋予完整 eval 能力；信封不带 assert\| 前缀（PHP8 兼容） |
| behinder-java | 冰蝎型 JSP/Java 内存马（AES-128-ECB + 编译载荷） | key=md5(密码)[0:16] | cmd + 原生列目录 + b64 读写 + JDBC 数据库 + 内存马卸载 | 请求体=b64(AES-ECB(class 字节))；自有反射载荷族 + 常量池实参注入 + 类名随机化；连冰蝎型 JSP 文件马与同协议内存马（与原版冰蝎默认马互操作） |
| behinder-aspx | 冰蝎型 ASPX/IIS Module 内存马（AES-128-ECB + 程序集载荷） | key=md5(密码)[0:16] | cmd + 原生列目录 + b64 读写 | 请求体=raw AES-ECB(U.dll 程序集)；实参走 X-W-P 头（k=b64;k=b64，不进默认访问日志）；连冰蝎型 ASPX/ASHX 文件马与 IIS Module 型内存马（与原版冰蝎默认 aspx 马互操作） |
| godzilla-java | 哥斯拉型 JSP/Java 内存马（JAVA_AES_BASE64 + 会话态 dispatcher） | password=POST 字段名，secret_key=密钥源（key=md5(secretKey)[0:16]） | cmd + 原生列目录 + b64 读写（大文件字节流分块）+ 交互终端 + HTTP 隧道 | 请求体=pass=b64(AES(gzip(Parameter 序列化)))；响应 md5 定位符包裹；自有 WsmG dispatcher（equals 三连注入 + toString 执行；t.*/e.* 隧道与终端会话态） |
| godzilla | 哥斯拉型（PHP_XOR_BASE64） | password=POST 字段名，secret_key=密钥源（key=md5(secretKey)[0:16]） | cmd + eval 片段（桥接载荷） | 参数序列化 key+\x02+int32LE+value；md5 定位符回传 |
| behinder-mod | av-lab 魔改冰蝎 | password=X-T 值，secret_key=盐 | cmd | UA 池 + nonce 协商 + CTR 分块异或 |
| godzilla-mod | av-lab 魔改哥斯拉 | password=X-G 值，secret_key=盐 | cmd | ECB + sid 通行证 + md5 前缀 XOR 回传 |

原生冰蝎/哥斯拉兼容采用**自有载荷**路线：不内嵌任何外部载荷文件——PHP 侧以桥接载荷
（冰蝎：`main($whatever,$code)` 契约 / 哥斯拉：`run($pms)` methodName 分派）实现协议互通；
Java 侧以编译载荷管线（反射式 .class + 常量池补丁）实现协议互通，经此获得与自研 v2 同级的
结构化操作能力。ASPX 冰蝎/哥斯拉协议与 JSP 哥斯拉协议未实现（能力矩阵如实标注）。

**内存马连接**：连接表单「形态」选内存马 + 通道选 dsh-mem（X-C 触发型）或 behinder-java
（冰蝎协议型）；URL 填任意存活路径（Filter/Module 全站劫持；Spring Controller 型填注入器
返回的伪装路径）。自动识别命中无文件后缀的 URL 时按内存马形态预填。

## 生成器（15 种）

`php-oneliner / php-basic / php-aes1 / php-aes2 / php-behinder / php-godzilla / jsp-basic / jsp-aes1 / jsp-behinder / jsp-godzilla / jsp-mem-filter / aspx-basic / aspx-aes1 / aspx-behinder / aspx-godzilla / asp-basic`
——产物落 `~/.dsh/webshell-mgr/generated/` 并登记；「从文件导入」可登记免杀模式产物。
`jsp-mem-filter` 为 Tomcat Filter 型内存马引导器：上传到可执行 JSP 目录 → 访问一次（回显
MEMSHELL-OK）→ 删除引导文件（先备份，trash 不 rm）→ 以 behinder-java + 内存马形态连接任意
存活路径。免杀变体不在生成器职责内（免杀对抗模式自产）。

## 数据库

需 eval 能力通道（cmd-eval / dsh-aes v2 / behinder / godzilla）。PHP 侧走目标机 PDO 原生驱动
（mysql / pgsql / sqlite / mssql——不依赖目标机 CLI 客户端）；每连接多套档案；库→表→列逐级
手动展开；SELECT 预览前 200 行。dbEncoding 独立于 shell 编码。

## 载荷插件（声明式，零客户端代码执行）

目录 `~/.dsh/webshell-mgr/plugins/<name>/`：

```json
{
  "name": "portscan", "version": "1.0.0", "type": "scan",
  "langs": ["php"], "protocols": ["cmd-eval", "dsh-aes"],
  "params": [{ "key": "host", "label": "目标主机", "type": "string", "default": "" }],
  "entry": "payload.php"
}
```

- `payload.php` 为目标侧载荷模板（不含 `<?php` 亦可——发送前自动整形）；
  参数占位两种形态：`base64_decode('{{key}}')`（值经 b64 内嵌，任意字符安全，推荐）
  与 `{{key}}`（裸值直换，仅受限词表参数）。
- 输出约定：`echo 'WSMJSON' . json_encode(...)`（结构化）/ `echo 'WSMB64' . base64_encode(...)`（二进制）。
- 会话发现：模型经 `webshell_plugin_list` 读清单、`webshell_plugin_run` 按需执行；
  UI 插件页声明式参数表单。随包示例：sysinfo（信息收集）、portscan（内网端口扫描）。

## 模型工具面（五模式）

`webshell_generate / webshell_connect（自动识别）/ webshell_list / webshell_exec / webshell_file
（ls/read/write/delete/delete-dir/mkdir/mv/chmod/touch/stat/wget/roots）/ webshell_db
（profile.save/dbs/tables/tableinfo/exec）/ webshell_plugin_list / webshell_plugin_run`

工具上传属环境改动——进操作痕迹台账（每次操作已记 op_log，概览页可查）。

## MCP

`node mcp/server.mjs`（stdio / JSON-RPC 2.0，零依赖）——工具面镜像宿主八件，同一 protocol/store
核心与 SQLite（WAL 多进程共存）。面向外部 harness（claude/codex CLI 或任意 MCP 客户端）；
**dsh 会话内无需本服务**（宿主模型工具即原生通道）。挂载：dsh-mcp-studio 添加 stdio 服务
（内置 chip「Webshell MCP」，默认关闭，替换占位路径后开启）。

## 安全纪律

- 仅授权测试环境使用——工具描述与本文档口径一致；
- 连接凭据明文落 `~/.dsh/webshell-mgr/webshell.db`（一次性作战凭据不加密落盘；彻底清除时删库文件，
  需要彻底清除时删库文件并 VACUUM）；
- 路由走同源信任栅栏（loopback / trustedHosts + Origin 同源校验）；
- 删除连接不删目标上的马（清痕由会话按模式纪律执行，op_log 供对账）。

## 能力矩阵与经典工具差距

### 当前支持（✅）与已知差距（✗/△）

| 能力 | 本插件 | 冰蝎 | 哥斯拉 | 说明 |
|---|---|---|---|---|
| PHP 连接（eval/AES/XOR） | ✅ | ✅ | ✅ | 七通道全覆盖 |
| PHP5 后缀识别 | ✅ | ✅ | ✅ | suffixLang 归一 |
| JSP 文件马（自研加密） | ✅ | — | — | dsh-aes + cmd-system |
| JSP 冰蝎协议 | ✅ | ✅ | ✅ | behinder-java 编译载荷管线（自有反射载荷 + 常量池实参注入 + 类名随机化）；与原版冰蝎默认 JSP 马互操作 |
| JSP 哥斯拉协议 | ✅ | ✅ | ✅ | godzilla-java 会话态 dispatcher（WsmG）+ Parameter 序列化 + gzip 载荷层；生成马全链路支持 |
| ASPX 文件马（自研加密） | ✅ | — | — | dsh-aes + cmd-system |
| ASPX 冰蝎协议 | ✅ | ✅ | ✅ | behinder-aspx 程序集管线（U.dll + X-W-P 头实参）；与原版冰蝎默认 aspx 马互操作 |
| ASPX 哥斯拉协议（CSHAP_AES_BASE64 同型） | ✅ | ✅ | ✅ | godzilla-aspx 通道（AES-CBC IV=key + md5 标记 + gzip/Parameter 层 + UG 会话态 dispatcher）；自有模板（原版 aspx 马互操作未验证——如实标注）；全链路支持 |
| ASP 经典（VBScript） | ✅ | ✅ | ✅ | cmd-system 通道（WScript.Shell 重定向 + FSO 读取，Windows/IIS 专属）；asp-basic 生成器；**无本机 ASP 宿主——仅静态验证**（如实标注） |
| ASHX/ASMX | △ | — | ✅ | 同 ASPX 协议（后缀已识别）；冰蝎/哥斯拉协议依赖 ASPX 管线 |
| 内存马 PHP | △ | — | — | kind=mem 已预留；PHP-FPM 场景可用现有协议 |
| 内存马 Java（冰蝎协议 Filter/Servlet/Listener） | ✅ | ✅ | ✅ | behinder-java 通道：URL 填任意存活路径，kind=mem 登记；生成器产 Filter 引导器（jsp-mem-filter，访问即注入、删文件连接仍在） |
| 内存马 Java（Controller/Valve 型） | ✅ | ✅ | ✅ | X-C 触发型用 dsh-mem 连接；冰蝎协议型用 behinder-java 连接；注入器归免杀对抗模式自产（连接侧全支持） |
| 内存马 ASPX（IIS Module） | ✅ | — | — | dsh-mem 通道（X-C 头触发 + b64 回显；Module 型 stderr 段原文兼容） |
| 内存马注入 | ✅ | ✅ | ✅ | jsp-mem-filter 引导器（生成器产；上传→访问→删引导文件三步） |
| 内存马卸载 | ✅ | ✅ | ✅ | WsmMemUnload 载荷（Filter 三注册面移除）+ UI 卸载按钮 + webshell_mem_unload 工具；引导器 x-n 属性自动定位；注入→连接→卸载→断连全闭环 |
| 文件管理（全操作） | ✅ | ✅ | ✅ | 含文本编辑/时间戳伪造/远程下载/复制 |
| 大文件断点续传 | ✅ | ✅ | ✅ | WsmRead 范围读（RANGE offset/len/total 元数据）+ 写侧分块追加（behinder-java）；godzilla-java 字节流 128KB 分块 |
| ZIP 压缩/解压 | ✅ | ✅ | ✅ | WsmZip 载荷（java.util.zip，behinder-java）+ file.action zip/unzip；目录级往返 |
| 数据库 PHP（PDO） | ✅ | ✅ | ✅ | mysql/pgsql/sqlite/mssql 原生 |
| 数据库 JSP（JDBC） | ✅ | ✅ | ✅ | WsmDb 载荷（纯 JDK）+ 档案→JDBC 映射（mysql/mssql/pgsql/oracle）；目标应用自带驱动 jar 即可；MySQL 8 全链路支持 |
| 数据库 ASPX | ✅ | ✅ | ✅ | U 载荷 db op（反射 ADO.NET，目标 bin/GAC 驱动即可）；sqlite 往返 + affected 计数 |
| Oracle | ✅（JDBC） | ✅ | ✅ | PHP PDO 无 Oracle（目标机限制）；behinder-java JDBC 支持 oracle（档案映射已含） |
| 应用内连接池凭据收集 | ✅ | — | ✅ | WsmEnumDb（Tomcat JNDI resources + context-param 过滤）；JNDI 资源全凭据提取；db.action enum |
| SOCKS 代理（目标侧） | ✅ | ✅ | ✅ | WsmSocks（纯 JDK 无鉴权 CONNECT，lambda 单类交付）；标准 SOCKS5 客户端可穿代理 |
| 端口转发 | ✅ | ✅ | ✅ | WsmFwd（监听→目标中继）；数据库客户端可穿转发查询 |
| HTTP 隧道 | ✅ | — | ✅ | WsmG t.* ops + 本地 SOCKS5 监听（tunnel.js）——全部流量封装 web 请求，目标不开新端口；数据库协议流量可穿越 |
| 反向连接/反弹 shell | ✅ | ✅ | — | WsmReverse（回连+sh 双泵）；回连后交互式读写 |
| 命令执行 | ✅ | ✅ | ✅ | 行缓冲虚拟终端 |
| 交互式终端 | ✅ | ✅ | ✅ | WsmG e.* ops 会话终端（持久 /bin/sh 管道、状态跨命令、UI 交互模式轮询）——非 TTY 特性（无 job control/全屏程序），godzilla-java 通道 |
| 流量伪装（C2 Profile） | ✅ | — | ✅ | 连接级 profile JSON：uas 轮换 + headers 附加 + 响应 strip 剖离（四编译载荷通道生效）；表单内联编辑 + 保存校验 |
| UA 池/Referer 随机 | ✅ | ✅ | — | profile.uas 逐请求轮换（behinder-java/aspx、godzilla-java/aspx 四通道）；显式头优先 |
| 载荷插件体系 | ✅ | ✅ | ✅ | 声明式（最安全）；三方为编译产物 |
| 多 shell 批量操作 | ✅ | ✅ | — | UI 批量执行（多选连接 + 同命令 + 结果表）+ conn.batch 路由 + webshell_batch_exec 工具；多连接并发 |
| MCP 服务 | ✅ | — | — | 本插件独有 |
| 模型工具面（AI 自操作） | ✅ | — | — | 本插件独有 |
| C2 回连载荷上传 | ✅ | △ | △ | file write + exec 已通；无专用 C2 profile |
| 凭据收集（浏览器/SSH/配置） | ✅ | △ | ✅ | 经 exec/file 命令式；哥斯拉有 SharpWeb 等专用插件 |
| 权限提升（Potato 系列） | ✅（通道） | — | ✅ | 上传+执行管线就绪（file write + exec + op_log 台账）；载荷本体归攻防/免杀模式产（模式层定位——管理器不内置提权二进制） |
| 截屏 | ✅ | — | ✅ | WsmShot（AWT Robot → PNG base64，headless 明确报错）；file.action shot 产物落 generated/；PNG 产物落盘 |

### 关键架构差距

**编译载荷管线（已落地 Java 侧）**：

JSP 通道与 PHP 的本质差异在载荷交付方式——PHP 走 `eval()` 文本解释，JSP 走
`ClassLoader.defineClass()` 字节码加载，ASPX 走 `Assembly.Load()` 程序集加载。桥接
载荷路线（PHP 文本内嵌）无法延伸到 JSP/ASPX。

本插件已落地的 Java 侧管线（`behinder-java` 通道）：

- 自有载荷类族（`payload-src/java/`，javac -g:none 编译嵌入）：默认包、零 servlet
  依赖（纯反射从 PageContext / Object[]{req,resp} 取上下文）、每类自包含、
  `equals(Object)` 入口——五件：WsmProbe（探测+基本信息）/ WsmCmd（命令，合并流防死锁）/
  WsmList（JSON 列目录）/ WsmRead（b64 读）/ WsmWrite（b64 写，覆盖/追加）；
- `lib/protocol/javapatch.js`：class 常量池级补丁——static final String 字段的
  ConstantValue 替换（实参注入，内容变长安全）+ this_class 类名随机化（规避同
  ClassLoader 重复 defineClass 的 LinkageError）；
- 线协议：`POST body = base64(AES-128-ECB(class 字节))`，key=md5(口令)[0:16]，
  外加 X-T:1 标记头（内存马 Filter 的门控凭据，对文件马无影响）；
- 支持链路：自产 jsp-behinder 文件马全操作 / jsp-mem-filter Filter 内存马（删引导
  文件后存活、业务流量不受门控外影响）/ X-C 型 Filter 内存马 / 原版冰蝎默认 JSP 马
  （自有载荷经其 defineClass 管线执行）。

已落地矩阵（Java + .NET 两侧）：

- Java 侧：五件常量池载荷 + WsmG 会话态 dispatcher（godzilla-java）+ WsmDb JDBC + WsmMemUnload；
- .NET 侧：U 单程序集多操作（behinder-aspx）——实参走 X-W-P 头免程序集补丁，mono mcs 编译
  （IIS .NET Framework 与 mono 双侧可载，Equals 须 override 而非 hide——object 引用虚调用才派发）。

未落地的后续差距：

- ASPX 哥斯拉协议（CSHAP_AES 会话态 + .NET 模板管线）；
- ASPX 数据库（.NET DbProvider 管线）与 ASPX 内存马注入器（Module 注册引导器）；
- Spring Controller / Valve / Listener 型注入器（连接侧全支持；注入器归免杀对抗模式自产）。

## 测试

`node test/run.mjs`——离线单测（引号/解析/AES 信封/store/插件校验/生成器/MCP 握手/
javapatch 补丁往返/behinder-java 线协议自洽/dsh-mem 段解码）
+ PHP 回路烟测（本机有 php 时：九通道识别→执行→文件→数据库→插件全链路；av-lab 两匹魔改马
字节级互通；冰蝎/哥斯拉形态马以生成器产物验证协议）。

Java 侧端到端验证：behinder-java 文件马（probe/cmd/
ls/b64 读写含 NUL 与中文往返/delete）、Filter 内存马（注入→任意路径连接→删引导文件存活→
业务流量无头透传回归）、X-C 型 Filter 内存马（cmd/ls/read 命令翻译）、原版冰蝎默认 JSP 马
互操作（rebeyond 口令）。
