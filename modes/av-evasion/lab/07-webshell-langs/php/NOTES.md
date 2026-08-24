# PHP webshell 免杀（07-webshell-langs / PHP 支线）

- 部署：`cp encrypted.php /var/www/html/legacy_api.php`（文件名伪装业务接口；依赖 PHP >= 7.0
  的 Throwable 捕获 + openssl 扩展）
- 客户端打包（本地实验环境，openssl CLI + curl 即可，无额外依赖）：
  ```bash
  IV=$(openssl rand -hex 16); KEY=$(openssl rand -hex 16)
  T=$(printf '%s' "$(echo $IV$KEY | xxd -r -p)" | base64)           # X-T = b64(iv||key)
  BODY=$(printf 'c id' | openssl enc -aes-128-cbc -K "$KEY" -iv "$IV" | base64)
  curl -s -X POST -H "X-T: $T" --data-binary "$BODY" http://target/legacy_api.php
  ```
- 技术侧（形态谱系，三代）：
  ① 大马（功能型文件管理：上传/下载/执行全功能）——功能全但体积大、静态特征多；
  ② 小马（一句话变形：动态函数/异或构造关键词）——体积小但回显行为单一、易行为建模；
  ③ 加密马（本实现）——密钥走请求头 X-T（非 Cookie 单点）、AES-128-CBC 解密 php://input、
  敏感函数名 chr() 拼装（零明文关键词）、多操作分派（c/u/d 三操作码）、响应 base64+业务
  JSON 包装、404/500 静默降级。
- 变体登记：KEY 派生模式（X-T 只带 IV，KEY=X-Sid+服务端盐 md5 截 16B）；IV/KEY 双向随机
  滚动（响应带下一轮 IV，防重放）；分段执行（段解段用）；session 无文件化（参数存 session
  + 文件自删）。
- 检测侧配对：
  1. 静态/语义引擎：AST 常量折叠还原 chr() 拼接 → 还原后 openssl_decrypt+shell_exec 组合词表命中；
  2. 流量侧：php://input 密文 POST 无 Cookie/session 绑定 + 响应固定 JSON 骨架（code/data 双层
     base64 熵特征，业务接口少见 base64(AES) 嵌套）；
  3. 行为侧：404/500 与 200 混排的异常状态分布；X-T 自定义头不随会话流转（正常业务头随 Cookie 绑定）；
  4. 无文件检测面：opcache 缓存与源文件差集；触发类请求的 URI 无静态引用入口（日志中孤立 POST）。
- 判定表（本地实测后填）：| 引擎/WAF | 结果 | 原文行 |
- 构建/语法验证记录：2026-08-20 `php -l encrypted.php`（PHP 8.5.9）通过，"No syntax errors"；
  未做运行时验证（无靶机 PHP 环境），判定表留待本地实测后填。
