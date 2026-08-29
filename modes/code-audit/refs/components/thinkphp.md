# ThinkPHP 专项审计手册

> 定位：国内高频 PHP 应用框架（大量老系统存量）。**版本分代是第一件事**：
> 3.2 / 5.0 / 5.1 / 6.x / 8.x 攻击面差异极大——`composer.json`/`think` 版本锁定后按代核对。

## 已知漏洞面清单（按版本代核对）

1. **TP5 核心 RCE（5.0/5.1 经典面）**：路由未过滤导致方法名/控制器名可控 →
   `invokeFunction` 反射调用任意函数（`s=index/\think\app/invokefunction` 形态）→ RCE。
   核对点：核心版本是否在受影响区间、路由兼容模式（`s=` 参数）是否开启、补丁位核对。
2. **TP5 SQL 注入**：`where()` 收数组时的键名/拼接注入（`parseWhere` 面）、聚合函数参数
   注入、`order(`/`field(` 直收用户输入的列名注入——按版本核历史修复位。
3. **多语言包包含 RCE**：开启多语言（`lang_switch_on`）时 `lang` 参数可控语言包路径 →
   本地文件包含（含日志/上传临时文件 getshell 链）。核对点：多语言开关、`allow_lang_list`
   限制、包含路径白名单。
4. **缓存/日志文件链**：`runtime/` 下日志与缓存文件可写入用户内容（UA/报错消息带 payload）
   → 结合包含类漏洞 getshell；核对 runtime 目录 web 可达性与日志内容反射面。
5. **phar 反序列化**：文件操作函数（`file_exists` 等）收 `phar://` 用户输入路径 →
   phar 元数据反序列化（POP 链对照 php 反序列化知识）；核对文件名/路径参数是否过滤协议。
6. **TP6+/8.x**：核心收紧后的历史面逐项核（5.x 面大多已修）；重点转二次开发与生态包
   （think-orm 拼接、验证器、多应用路由）。
7. **TP3.2 存量**：`I()` 函数过滤配置（`DEFAULT_FILTER`）、`assign` 模板变量注入、
   `where` 拼接面——老系统整体按「存量高危」姿态全过。

## Sink 快速核对（通用）

- `Db::query(`/`execute(` 拼接、`where(` 数组键可控、`order(`/`field(`/`table(` 直收输入；
- 文件类：`file_get_contents(` 路径含输入（协议过滤核对）、上传类 `move(` 的后缀校验；
- 模板：`fetch(` 视图名拼接、原生 `eval`/`assert`（业务层遗留）。

## 审计流程建议

锁版本分代 → 按代核上表已知面 → 未命中登记「已核无」→ 二次开发走模块×sink 矩阵
（php-sink-reference）→ 覆盖矩阵登记。利用条件纪律同 `jeecg-boot.md`（版本区间/配置
开关/路由形态全列——TP 的面几乎全部版本敏感）。
