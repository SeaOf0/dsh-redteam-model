---
name: php-deser-audit
description: PHP Web 源码反序列化/对象注入审计工具。覆盖显式 unserialize 入口与 phar:// 隐式反序列化两类入口，追踪魔术方法链与框架 POP 链（ThinkPHP/Laravel/WordPress/Yii），结合 phpggc gadget 库，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP 反序列化审计（php-deser-audit）

分析 PHP 项目源码，识别用户可控数据进入反序列化点的两类入口：

1. **显式**：`unserialize()` 或等价反序列化调用；
2. **隐式（phar 元数据）**：任意文件操作函数对 `phar://` 流的处理会触发 phar 归档
   元数据中的 `__wakeup/__destruct`，**即使代码里根本没有 `unserialize()` 也会中招**。

结合类的魔术方法（`__wakeup/__destruct/__call/__toString` 等）与框架 POP 链判断是否存在
对象注入可利用链。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-DESER-{序号}`

## 危险 Sink（必做）

**显式反序列化：**
- `unserialize($data)`
- `unserialize(base64_decode({value}))`
- 任何将用户输入转换后再反序列化的路径

**隐式 phar 反序列化（文件操作函数触发 phar 元数据）：**
- 文件存在/类型判定类：`file_exists`、`is_dir`、`is_file`、`file_get_contents`、
  `filesize`、`filemtime`、`stat`、`file`、`fopen`、`readfile`、`copy`、`rename`、
  `unlink`、`mkdir`、`rmdir`、`opendir`、`file_put_contents`
- 路径处理类：`realpath`、`pathinfo`、`basename`、`dirname`、`glob`、`scandir`
- 流/封装类：`include`/`require`、`getimagesize`、`exif_imagetype`、`hash_file`、
  `md5_file`、`sha1_file`、`get_meta_tags`、`parse_ini_file`
- 关键判据：以上任一函数的参数可控且指向 `phar://...`（或通过 `phar://` 流封装器
  打开归档），即隐式触发反序列化。

## 可控性（必做）
必须追踪并输出：
- 反序列化入参来自哪里：GET/POST/Cookie/Session/Header/数据库字段等
- 是否存在 base64/加密/解码/拼接步骤（仍可能可控）
- 是否有校验/签名（如 `hash_hmac`）以及签名是否可靠（需要证据）

## gadget 链识别（必做）
必须输出：
- 反序列化后的对象类型（或可能类型集合）
- 该类型类中魔术方法列表与触发条件
- “从对象创建 -> 魔术方法触发 -> 最终敏感操作（如文件/命令/SSRF/数据库）”的数据流链

## tracer 触发条件（必做）
- 反序列化入参经过多层 decode/封装
- 魔术方法链跨多个类/文件

## 证据引用（强制：来自 php-route-tracer）
每条反序列化/对象注入疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **DESER 行**对应证据要点（允许状态为待验证，但证据引用必须存在）：
1. `EVID_DESER_CALLSITE`：反序列化调用点位置证据（unserialize 等等价点）
2. `EVID_DESER_INPUT_SOURCE`：入参用户可控来源证据
3. `EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN`：反序列化后对象类型/魔术方法触发条件证据（以及最终敏感操作点链路证据，若能定位）

## tracer 证据缺失处理（强制）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

## 报告输出
输出到：
```
{output_path}/vuln_audit/deser_{timestamp}.md
```

## PoC（强制，但标注为“概念 PoC/验证 PoC”）
必须给出：
- 真实路由（或 cookie/session 字段使用方式）
- payload 生成思路（若无法生成真实 gadget payload，必须给出“需人工补齐的部分”并说明原因，同时仍保留可执行框架与可替换字段）

---

## 附 A：phar:// 反序列化检测入口清单

> phar 反序列化是 PHP 审计**最易漏**的一类——`unserialize()` 不存在也会中招。审计时把
> 「文件操作函数 + 用户可控路径/文件名」当作一等 sink 处理。

### A.1 原理

- `.phar` 归档的 manifest 区以 PHP 序列化格式存储**元数据**（`Phar::setMetadata()` 写入）。
- 任何对 `phar://archive.phar/...` 的文件操作，PHP 在解析归档时都会反序列化该元数据，
  触发其中对象的魔术方法。
- 攻击者把恶意 phar 上传（或让应用处理本地 phar），再让某个文件操作函数处理
  `phar://<恶意文件>` 路径，即完成隐式对象注入。

### A.2 检测清单

1. **文件操作函数扫描**（见上「隐式 phar 反序列化」sink 列表），逐个核对参数是否可控。
2. **可控性链**：参数能否被拼成 `phar://` 前缀？（例如 `file_exists($base . $name)`，
   若 `$name` 可控且无前缀过滤，则 `phar://` 可注入。）
3. **上传面**：是否存在 phar/压缩包上传点、或服务端有可被写入 phar 的路径。
4. **协议限制**：是否有 `allow_url_fopen`/`allow_url_include`/stream wrapper 白名单拦截
   `phar://`（PHP 8.0+ 默认 `phar` 协议仍可用，需代码层显式拒绝）。
5. **版本判据**：PHP ≥ 8.0 中 phar 元数据反序列化仍成立；老版本（< 8）更宽松。

```bash
# phar 反序列化入口扫描
grep -rn 'file_exists\|is_dir\|is_file\|file_get_contents\|filesize\|filemtime\|stat\b\|realpath\|glob\|scandir\|readfile\|fopen\|copy\|rename\|unlink\|include\|require' --include='*.php' . | grep -v 'test\|Test'
```

---

## 附 B：phpggc gadget 库用法

> phpggc（PHP Generic Gadget Chains）是 PHP 反序列化 payload 生成库，
> 官方：<https://github.com/ambionics/phpggc>。

```bash
# 列出支持的框架/gadget 清单（-l 输出框架分类）
php phpggc -l

# 常用框架 gadget（示例，以实际 -l 输出为准）
#   Laravel/RCE1         Laravel 框架 RCE 链
#   ThinkPHP/RCE1..N     ThinkPHP 框架 RCE 链
#   WordPress/*          WordPress 插件/主题链
#   Yii2/RCE1            Yii2 框架链
#   Symfony/RCE*         Symfony 框架链
#   CodeIgniter4/RCE*    CodeIgniter 框架链
#   Monolog/RCE*         Monolog 组件链

# 生成 payload（以 Laravel/RCE1 为例）
php phpggc Laravel/RCE1 "system" "id" -b            # -b 输出 base64
php phpggc ThinkPHP/RCE1 "system" "id"              # 裸序列化串

# 链详情
php phpggc -i Laravel/RCE1
```

**审计用法**：把框架 POP 链起点（见附 C）与目标源码中的魔术方法/危险调用对齐；目标命中
某框架且存在反序列化入口时，用 phpggc 生成对应链 payload 做 PoC 验证。

---

## 附 C：框架 POP 链起点表

> 「起点」= 攻击者构造对象进入反序列化后，第一个被触发的魔术方法/危险调用点；
> 审计时在目标框架源码中检索这些起点即可定位 POP 链是否成立。

| 框架 | 常见 POP 链起点（类/方法） | 关键魔术方法 | 危险落点 |
|------|----------------------------|--------------|----------|
| **ThinkPHP** | `think\process\pipes\Windows`（`__destruct` → `removeFiles`）、`think\view\driver\Php`、`think\route\dispatch` | `__destruct`/`__toString`/`__call` | 文件删除/文件写/命令执行（`Output::write` 等） |
| **Laravel** | `Symfony\Component\Process\Process`（`__destruct` → `stop`）、`Faker\Generator`（`__destruct` → 任意方法调用）、`Illuminate\Broadcasting\PendingBroadcast` | `__destruct`/`__call` | 命令执行/任意方法调用 |
| **WordPress** | 插件/主题类（`WP_Query` 链、`Requests_Utility_FilteredIterator` 等），依赖具体插件 gadget | `__destruct`/`__toString`/`__wakeup` | 文件读/写、对象方法调用 |
| **Yii2** | `yii\base\Object`/`yii\db\BatchQueryResult`（`__destruct` → `reset`）、`Codeception` 系列 | `__destruct`/`__call` | 任意方法调用/文件操作 |
| **Symfony** | `Symfony\Component\Process\Process`、`Symfony\Component\Finder\Finder` | `__destruct` | 命令执行 |
| **CodeIgniter4** | `CodeIgniter\Debug\Exceptions`（`__destruct` → 日志/类加载） | `__destruct` | 文件写/类加载 |

**审计核对法**：目标框架命中上述起点类时，回溯「该类被反序列化后首个触发的魔术方法 →
后续危险操作」是否被源码放行（无白名单、无 `__wakeup` 拦截）。

---

## 附 D：CVE-2025-49113 Roundcube PHP 对象注入（实战锚点）

> 来源：<https://github.com/rippsec/CVE-2025-49113-Roundcube-RCE>

- **性质**：Roundcube Webmail 的 PHP 对象注入（unserialize 可控），导致 RCE。
- **审计锚点**：这是「Webmail 类应用对象注入」的典型形态——
  1. **入口**：用户可控数据（邮件解析/请求字段）进入 `unserialize()`；
  2. **POP 链**：借 Roundcube 自带类的魔术方法串联到危险操作（文件写/命令执行/任意方法调用）；
  3. **版本判据**：受影响的 Roundcube 版本范围需对照官方公告/NVD 核实。
- **迁移审计法**：把「邮件/文档/请求解析 → 反序列化 → 框架类 POP 链」作为通用主线，
  与 §附 C 框架 POP 链起点表联合使用；PHP 应用含 `unserialize` 且类库复杂时按此模式排查。

---

## 附 E：修复建议（按层）

1. **入口层**：`unserialize` 入参必须签名校验（`hash_hmac`）且禁止使用用户可控数据；
   优先用 `json_decode` 替代。
2. **phar 层**：文件操作前对路径做 `stream_wrapper` 白名单，显式拒绝 `phar://`；
   上传面禁止 `.phar` 落地到可被文件操作触达的路径。
3. **类层**：对反序列化类加 `__wakeup` 防御（校验/抛异常阻断后续魔术方法链）。
4. **依赖层**：框架/插件升级到修复对象注入的版本；禁用不必要的 autoload 类面。
