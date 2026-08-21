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
| cmd-eval | 一句话 eval（PHP） | pass 参数名 + 口令 | cmd + eval 片段（结构化全量） | 蚁剑默认马同形 |
| cmd-system | 口令门+命令参数马 | 口令参数 + 命令参数 | cmd（文件/数据库走命令翻译） | 通用兜底 |
| behinder | 冰蝎型（AES-128-ECB） | key=md5(密码)[0:16] | cmd + eval 片段（桥接载荷） | 桥接 payload 赋予完整 eval 能力；信封不带 assert\| 前缀（PHP8 兼容） |
| godzilla | 哥斯拉型（PHP_XOR_BASE64） | password=POST 字段名，secret_key=密钥源（key=md5(secretKey)[0:16]） | cmd + eval 片段（桥接载荷） | 参数序列化 key+\x02+int32LE+value；md5 定位符回传 |
| behinder-mod | av-lab 魔改冰蝎 | password=X-T 值，secret_key=盐 | cmd | UA 池 + nonce 协商 + CTR 分块异或 |
| godzilla-mod | av-lab 魔改哥斯拉 | password=X-G 值，secret_key=盐 | cmd | ECB + sid 通行证 + md5 前缀 XOR 回传 |

原生冰蝎/哥斯拉兼容采用**桥接载荷**路线：不内嵌任何外部载荷文件，以自有 PHP 载荷
（冰蝎：`main($whatever,$code)` 契约 / 哥斯拉：`run($pms)` methodName 分派）实现协议互通，
经此获得与自研 v2 同级的结构化操作能力。JSP/ASPX 原生形态未实现（能力矩阵如实标注；
JSP/ASPX 马可用本插件生成器产出的自研加密通道马）。

## 生成器（10 种）

`php-oneliner / php-basic / php-aes1 / php-aes2 / php-behinder / php-godzilla / jsp-basic / jsp-aes1 / aspx-basic / aspx-aes1`
——产物落 `~/.dsh/webshell-mgr/generated/` 并登记；「从文件导入」可登记免杀模式产物。
免杀变体不在生成器职责内（免杀对抗模式自产）。

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
  教训同 hunter 的 VACUUM 记录）；
- 路由走同源信任栅栏（loopback / trustedHosts + Origin 同源校验）；
- 删除连接不删目标上的马（清痕由会话按模式纪律执行，op_log 供对账）。

## 测试

`node test/run.mjs`——离线单测（引号/解析/AES 信封/store/插件校验/生成器/MCP 握手）
+ PHP 回路烟测（本机有 php 时：九通道识别→执行→文件→数据库→插件全链路；av-lab 两匹魔改马
字节级互通；冰蝎/哥斯拉形态马以生成器产物验证协议）。
