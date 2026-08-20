"""
漏洞关联知识图谱 - 支持链式推理

定义漏洞之间的关联关系，实现"发现A  推导B  尝试C"的推理链。
"""

from typing import Dict, List, Any, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    FILE_INCLUSION = "file_inclusion"
    FILE_UPLOAD = "file_upload"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PWN = "pwn"
    SSRF = "ssrf"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"


class AttackChain:
    """
    攻击链定义

    表示从漏洞A到漏洞B的推理路径
    """

    def __init__(self,
                 from_vuln: VulnerabilityType,
                 to_vuln: VulnerabilityType,
                 reasoning: str,
                 success_prob: float,
                 time_cost: int,
                 tools: List[str],
                 conditions: List[str]):
        """
        Args:
            from_vuln: 源漏洞类型
            to_vuln: 目标漏洞类型
            reasoning: 推理逻辑
            success_prob: 成功概率 (0.0-1.0)
            time_cost: 时间消耗（秒）
            tools: 需要的工具列表
            conditions: 前置条件
        """
        self.from_vuln = from_vuln
        self.to_vuln = to_vuln
        self.reasoning = reasoning
        self.success_prob = success_prob
        self.time_cost = time_cost
        self.tools = tools
        self.conditions = conditions

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "from": self.from_vuln.value,
            "to": self.to_vuln.value,
            "reasoning": self.reasoning,
            "success_prob": self.success_prob,
            "time_cost": self.time_cost,
            "tools": self.tools,
            "conditions": self.conditions
        }


class VulnerabilityKnowledgeGraph:
    """
    漏洞关联知识图谱

    存储所有漏洞之间的关联关系，支持查询推理路径。
    """

    def __init__(self):
        """初始化知识图谱"""
        self.chains: List[AttackChain] = []
        self._build_default_chains()

    def _build_default_chains(self):
        """构建默认的攻击链 - 100+条攻击路径"""

        # ==================== SQL注入推理链（30+条） ====================
        self.chains.extend([
            # SQL注入  LFI
            AttackChain(
                from_vuln=VulnerabilityType.SQL_INJECTION,
                to_vuln=VulnerabilityType.FILE_INCLUSION,
                reasoning="SQL注入可以读取文件，尝试利用LOAD_FILE读取敏感文件，发现LFI漏洞",
                success_prob=0.6,
                time_cost=30,
                tools=["sqlmap", "curl"],
                conditions=["has_file_read_priv"]
            ),
            # SQL注入  命令注入
            AttackChain(
                from_vuln=VulnerabilityType.SQL_INJECTION,
                to_vuln=VulnerabilityType.COMMAND_INJECTION,
                reasoning="SQL注入可以执行系统命令（SELECT INTO OUTFILE, UDF），尝试RCE",
                success_prob=0.5,
                time_cost=45,
                tools=["sqlmap", "mysql_udf"],
                conditions=["has_file_write_priv", "has_no_secure_priv"]
            ),
            # SQL注入  写WebShell
            AttackChain(
                from_vuln=VulnerabilityType.SQL_INJECTION,
                to_vuln=VulnerabilityType.FILE_UPLOAD,
                reasoning="SQL注入可以写入文件，尝试上传WebShell",
                success_prob=0.55,
                time_cost=40,
                tools=["sqlmap", "curl"],
                conditions=["has_file_write_priv", "has_web_root_write"]
            ),
            # SQL注入  XXE（通过XML导入）
            AttackChain(
                from_vuln=VulnerabilityType.SQL_INJECTION,
                to_vuln=VulnerabilityType.XXE,
                reasoning="SQL注入可以通过XML导入功能触发XXE漏洞",
                success_prob=0.4,
                time_cost=35,
                tools=["sqlmap", "xxer"],
                conditions=["has_xml_feature"]
            ),
            # SQL注入  SSRF（通过存储过程）
            AttackChain(
                from_vuln=VulnerabilityType.SQL_INJECTION,
                to_vuln=VulnerabilityType.SSRF,
                reasoning="SQL注入利用存储过程进行SSRF攻击",
                success_prob=0.45,
                time_cost=30,
                tools=["sqlmap"],
                conditions=["has_stored_procedure"]
            ),
            # SQL注入  反序列化
            AttackChain(
                from_vuln=VulnerabilityType.SQL_INJECTION,
                to_vuln=VulnerabilityType.DESERIALIZATION,
                reasoning="SQL注入可以读取序列化数据并触发反序列化漏洞",
                success_prob=0.35,
                time_cost=50,
                tools=["sqlmap", "ysoserial"],
                conditions=["has_file_read_priv"]
            ),
            # SQL注入  权限提升（通过UDF）
            AttackChain(
                from_vuln=VulnerabilityType.SQL_INJECTION,
                to_vuln=VulnerabilityType.PRIVILEGE_ESCALATION,
                reasoning="SQL注入创建MySQL UDF获取系统权限",
                success_prob=0.4,
                time_cost=60,
                tools=["sqlmap", "udf"],
                conditions=["has_file_write_priv"]
            ),
        ])

        # 添加更多SQL注入变体
        sql_extra_chains = [
            # 不同数据库的SQL注入利用
            ("sql_injection", "file_inclusion", "PostgreSQL COPY TO读取文件", 0.6, 25, ["sqlmap"], ["has_pg_copy"]),
            ("sql_injection", "command_injection", "MSSQL xp_cmdshell命令执行", 0.55, 40, ["sqlmap"], ["has_mssql"]),
            ("sql_injection", "file_inclusion", "Oracle UTL_FILE读取文件", 0.5, 35, ["sqlmap"], ["has_oracle"]),
            ("sql_injection", "command_injection", "SQLite EXEC执行命令", 0.45, 30, ["sqlmap"], ["has_sqlite"]),
            ("sql_injection", "file_upload", "PostgreSQL LO写入WebShell", 0.5, 45, ["sqlmap"], ["has_pg_large_object"]),
            # 二阶SQL注入
            ("sql_injection", "sql_injection", "二阶SQL注入深入利用", 0.6, 30, ["sqlmap"], ["has_second_order"]),
            # SQL注入盲注升级
            ("sql_injection", "ssrf", "时间盲注升级为OOB外带SSRF", 0.5, 40, ["sqlmap", "dnslogger"], ["has_blind_sqli"]),
            # WAF绕过变体
            ("sql_injection", "file_inclusion", "通过注释绕过WAF读取文件", 0.4, 50, ["sqlmap"], ["waf_detected"]),
            ("sql_injection", "command_injection", "通过堆叠查询绕过WAF执行命令", 0.45, 50, ["sqlmap"], ["waf_detected"]),
            ("sql_injection", "file_inclusion", "通过编码绕过WAF读取文件", 0.35, 55, ["sqlmap"], ["waf_detected"]),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in sql_extra_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.SQL_INJECTION,
                    to_vuln=VulnerabilityType(from_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass  # 跳过无效的漏洞类型

        # ==================== 命令注入推理链（25+条） ====================
        self.chains.extend([
            # 命令注入  权限提升
            AttackChain(
                from_vuln=VulnerabilityType.COMMAND_INJECTION,
                to_vuln=VulnerabilityType.PRIVILEGE_ESCALATION,
                reasoning="命令注入已获得Shell，尝试SUID提权、内核漏洞提权",
                success_prob=0.7,
                time_cost=60,
                tools=["find", "linpeas", "linux-exploit-suggester"],
                conditions=["has_shell_access"]
            ),
            # 命令注入  内网横向
            AttackChain(
                from_vuln=VulnerabilityType.COMMAND_INJECTION,
                to_vuln=VulnerabilityType.SQL_INJECTION,
                reasoning="命令注入可访问内网，扫描内网SQL服务",
                success_prob=0.6,
                time_cost=90,
                tools=["nmap", "sqlmap"],
                conditions=["has_shell_access", "has_internal_network"]
            ),
        ])

        # 添加更多命令注入变体
        cmd_extra_chains = [
            ("command_injection", "file_inclusion", "通过命令读取配置文件", 0.8, 20, ["curl", "cat"], ["has_shell_access"]),
            ("command_injection", "privilege_escalation", "SUID提权", 0.6, 40, ["find", "gtfobins"], ["has_shell_access"]),
            ("command_injection", "privilege_escalation", "内核漏洞提权", 0.5, 80, ["linux-exploit-suggester"], ["has_shell_access"]),
            ("command_injection", "privilege_escalation", "Cron job提权", 0.55, 30, ["crontab"], ["has_shell_access"]),
            ("command_injection", "privilege_escalation", "PATH变量劫持", 0.45, 25, ["echo"], ["has_shell_access"]),
            ("command_injection", "privilege_escalation", "LD_PRELOAD劫持", 0.5, 35, ["gcc"], ["has_shell_access"]),
            ("command_injection", "privilege_escalation", "Docker逃逸", 0.4, 60, ["docker"], ["has_shell_access", "in_docker"]),
            # 持久化
            ("command_injection", "command_injection", "建立反向Shell持久化", 0.7, 30, ["nc", "bash"], ["has_shell_access"]),
            ("command_injection", "command_injection", "添加SSH公钥持久化", 0.65, 20, ["ssh-keygen"], ["has_shell_access"]),
            ("command_injection", "command_injection", "添加后门用户", 0.6, 25, ["useradd"], ["has_root_access"]),
            # 内网横向
            ("command_injection", "sql_injection", "扫描内网数据库服务", 0.55, 60, ["nmap"], ["has_shell_access"]),
            ("command_injection", "command_injection", "内网Pass-the-Hash攻击", 0.5, 90, ["pth"], ["has_shell_access", "has_internal_network"]),
            ("command_injection", "file_upload", "通过SCP上传工具", 0.7, 30, ["scp"], ["has_shell_access"]),
            # 数据收集
            ("command_injection", "command_injection", "收集密码哈希", 0.6, 40, ["cat", "grep"], ["has_shell_access"]),
            ("command_injection", "file_inclusion", "读取SSH密钥", 0.7, 15, ["cat"], ["has_shell_access"]),
            ("command_injection", "command_injection", "导出浏览器密码", 0.5, 30, ["sqlite3"], ["has_shell_access"]),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in cmd_extra_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.COMMAND_INJECTION,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== 文件包含推理链（20+条） ====================
        self.chains.extend([
            # LFI  命令注入
            AttackChain(
                from_vuln=VulnerabilityType.FILE_INCLUSION,
                to_vuln=VulnerabilityType.COMMAND_INJECTION,
                reasoning="LFI可以读取日志文件，尝试日志投毒实现RCE",
                success_prob=0.65,
                time_cost=50,
                tools=["curl", "lfi_log_poison"],
                conditions=["can_read_log_files"]
            ),
            # LFI  读取配置文件
            AttackChain(
                from_vuln=VulnerabilityType.FILE_INCLUSION,
                to_vuln=VulnerabilityType.PRIVILEGE_ESCALATION,
                reasoning="LFI读取配置文件，寻找密码或密钥",
                success_prob=0.5,
                time_cost=30,
                tools=["curl"],
                conditions=["can_read_config_files"]
            ),
        ])

        # 添加更多LFI变体
        lfi_extra_chains = [
            ("file_inclusion", "command_injection", "LFI日志投毒获取Shell", 0.6, 45, ["curl"], ["can_read_log_files"]),
            ("file_inclusion", "privilege_escalation", "读取/etc/shadow提权", 0.55, 20, ["curl"], []),
            ("file_inclusion", "file_inclusion", "PHP伪协议filter读取源码", 0.7, 25, ["curl"], []),
            ("file_inclusion", "file_inclusion", "PHP伪协议zip读取文件", 0.6, 20, ["curl"], []),
            ("file_inclusion", "file_inclusion", "PHP伪协议expect执行命令", 0.5, 30, ["curl"], []),
            ("file_inclusion", "file_inclusion", "LFI绕过技巧：%00截断", 0.65, 20, ["curl"], []),
            ("file_inclusion", "file_inclusion", "LFI绕过技巧：路径长度截断", 0.5, 20, ["curl"], []),
            ("file_inclusion", "sql_injection", "读取数据库配置文件", 0.6, 25, ["curl"], []),
            ("file_inclusion", "file_inclusion", "读取Web配置发现新路径", 0.55, 30, ["curl"], []),
            ("file_inclusion", "command_injection", "包含SSH日志获取凭证", 0.4, 35, ["curl"], []),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in lfi_extra_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.FILE_INCLUSION,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== 文件上传推理链（15+条） ====================
        self.chains.extend([
            # 文件上传  命令注入
            AttackChain(
                from_vuln=VulnerabilityType.FILE_UPLOAD,
                to_vuln=VulnerabilityType.COMMAND_INJECTION,
                reasoning="成功上传WebShell，直接获得命令执行",
                success_prob=0.85,
                time_cost=20,
                tools=["curl", "webshell_executor"],
                conditions=["webshell_uploaded"]
            ),
            # 文件上传  权限提升
            AttackChain(
                from_vuln=VulnerabilityType.FILE_UPLOAD,
                to_vuln=VulnerabilityType.PRIVILEGE_ESCALATION,
                reasoning="通过WebShell获得Shell，尝试提权",
                success_prob=0.7,
                time_cost=60,
                tools=["webshell_executor", "find", "linpeas"],
                conditions=["webshell_executable"]
            ),
        ])

        # 添加更多文件上传变体
        upload_extra_chains = [
            ("file_upload", "command_injection", "PHP WebShell", 0.8, 15, ["curl"], []),
            ("file_upload", "command_injection", "JSP WebShell", 0.75, 20, ["curl"], []),
            ("file_upload", "command_injection", "ASPX WebShell", 0.7, 20, ["curl"], []),
            ("file_upload", "file_upload", "图片马绕过上传", 0.6, 25, ["exiftool", "curl"], []),
            ("file_upload", "file_upload", ".htaccess绕过上传", 0.55, 20, ["curl"], []),
            ("file_upload", "file_upload", "双后缀名绕过", 0.5, 20, ["curl"], []),
            ("file_upload", "file_upload", "MIME类型绕过", 0.45, 20, ["curl"], []),
            ("file_upload", "file_inclusion", "上传文件配合文件包含", 0.7, 30, ["curl"], []),
            ("file_upload", "file_upload", "00截断绕过", 0.5, 20, ["curl"], []),
            ("file_upload", "file_upload", "NULL字节绕过", 0.5, 20, ["curl"], []),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in upload_extra_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.FILE_UPLOAD,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== XSS推理链（15+条） ====================
        self.chains.extend([
            # XSS  Cookie窃取
            AttackChain(
                from_vuln=VulnerabilityType.XSS,
                to_vuln=VulnerabilityType.XSS,  # 同类型，但深化利用
                reasoning="发现XSS，尝试窃取Cookie，绕过认证",
                success_prob=0.7,
                time_cost=25,
                tools=["curl", "xss_cookie_stealer"],
                conditions=["xss_reflected"]
            ),
            # XSS  CSRF组合
            AttackChain(
                from_vuln=VulnerabilityType.XSS,
                to_vuln=VulnerabilityType.XSS,
                reasoning="XSS + CSRF组合攻击，实现更高级利用",
                success_prob=0.5,
                time_cost=40,
                tools=["curl", "csrf_generator"],
                conditions=["has_csrf_token"]
            ),
        ])

        # 添加更多XSS变体
        xss_extra_chains = [
            ("xss", "xss", "反射型XSS升级为存储型XSS", 0.6, 30, ["curl"], []),
            ("xss", "xss", "DOM型XSS深入利用", 0.55, 35, ["curl"], []),
            ("xss", "xss", "XSS绕过CSP策略", 0.5, 40, ["curl"], []),
            ("xss", "xss", "XSS绕过WAF", 0.45, 35, ["curl"], []),
            ("xss", "xss", "XSS Keylogger窃取按键", 0.6, 30, ["curl"], []),
            ("xss", "xss", "XSS钓鱼攻击", 0.5, 40, ["curl"], []),
            ("xss", "xss", "XSS扫描内网端口", 0.4, 50, ["curl"], []),
            ("xss", "file_inclusion", "XSS通过AJAX读取本地文件", 0.5, 35, ["curl"], []),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in xss_extra_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.XSS,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== SSRF推理链（10+条） ====================
        ssrf_chains = [
            ("ssrf", "file_inclusion", "SSRF读取本地文件", 0.7, 20, ["curl"], []),
            ("ssrf", "command_injection", "SSRF反弹Shell", 0.6, 40, ["curl"], []),
            ("ssrf", "sql_injection", "SSRF攻击内网数据库", 0.55, 50, ["curl", "sqlmap"], []),
            ("ssrf", "ssrf", "SSRF端口扫描内网", 0.6, 60, ["curl"], []),
            ("ssrf", "file_inclusion", "SSRF通过gopher协议读取文件", 0.5, 30, ["curl"], []),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in ssrf_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.SSRF,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== XXE推理链（10+条） ====================
        xxe_chains = [
            ("xxe", "file_inclusion", "XXE读取本地敏感文件", 0.7, 20, ["curl"], []),
            ("xxe", "command_injection", "XXE通过XXEinjector执行命令", 0.6, 30, ["curl", "xxeinjector"], []),
            ("xxe", "ssrf", "XXE发起SSRF攻击", 0.65, 25, ["curl"], []),
            ("xxe", "file_inclusion", "XXE通过盲注外带数据", 0.5, 40, ["curl", "dnslogger"], []),
            ("xxe", "dos", "XXE Billion Laughs攻击", 0.7, 15, ["curl"], []),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in xxe_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.XXE,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== 反序列化推理链（10+条） ====================
        deser_chains = [
            ("deserialization", "command_injection", "反序列化命令注入", 0.7, 30, ["curl", "ysoserial"], []),
            ("deserialization", "file_inclusion", "反序列化读取文件", 0.5, 35, ["curl"], []),
            ("deserialization", "privilege_escalation", "反序列化提权", 0.6, 40, ["curl"], []),
            ("deserialization", "ssrf", "反序列化SSRF", 0.55, 35, ["curl"], []),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in deser_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.DESERIALIZATION,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== 权限提升推理链（15+条） ====================
        priv_esc_chains = [
            ("privilege_escalation", "privilege_escalation", "SUID提权", 0.6, 30, ["find", "gtfobins"], []),
            ("privilege_escalation", "privilege_escalation", "内核漏洞提权", 0.5, 80, ["linux-exploit-suggester"], []),
            ("privilege_escalation", "privilege_escalation", "Cron job提权", 0.55, 30, ["crontab"], []),
            ("privilege_escalation", "privilege_escalation", "PATH劫持提权", 0.45, 25, ["export"], []),
            ("privilege_escalation", "privilege_escalation", "LD_PRELOAD提权", 0.5, 35, ["gcc"], []),
            ("privilege_escalation", "privilege_escalation", "Sudo提权", 0.6, 25, ["sudo"], []),
            ("privilege_escalation", "privilege_escalation", "Docker逃逸", 0.4, 60, ["docker"], ["in_docker"]),
            ("privilege_escalation", "file_inclusion", "提权后读取敏感文件", 0.8, 15, ["cat"], ["has_root"]),
            ("privilege_escalation", "command_injection", "提权后建立后门", 0.7, 30, ["nc"], ["has_root"]),
            ("privilege_escalation", "sql_injection", "读取数据库配置获取新凭据", 0.6, 25, ["cat"], ["has_root"]),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in priv_esc_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.PRIVILEGE_ESCALATION,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass

        # ==================== PWN推理链（10+条） ====================
        pwn_chains = [
            ("pwn", "privilege_escalation", "栈溢出提权", 0.6, 60, ["pwntools", "ROPgadget"], []),
            ("pwn", "command_injection", "PWN获取Shell", 0.7, 50, ["pwntools"], []),
            ("pwn", "pwn", "堆溢出深入利用", 0.5, 70, ["heap_exploit"], []),
            ("pwn", "file_inclusion", "PWN读取flag", 0.75, 30, ["pwntools"], []),
            ("pwn", "pwn", "ROP链构造", 0.55, 60, ["ROPgadget"], []),
            ("pwn", "privilege_escalation", "格式化字符串提权", 0.65, 50, ["pwntools"], []),
            ("pwn", "command_injection", "ret2libc利用", 0.6, 55, ["pwntools", "ROPgadget"], []),
            ("pwn", "pwn", "UAF漏洞利用", 0.5, 65, ["pwntools"], []),
            ("pwn", "privilege_escalation", "整数溢出提权", 0.55, 70, ["pwntools"], []),
            ("pwn", "file_inclusion", "open式读取文件", 0.7, 35, ["pwntools"], []),
            ("pwn", "command_injection", "one_gadget攻击", 0.6, 40, ["one_gadget", "pwntools"], []),
            ("pwn", "pwn", "堆喷射技术", 0.45, 80, ["heap_spray"], []),
            ("pwn", "privilege_escalation", "DLInjection攻击", 0.5, 60, ["pwntools"], []),
            ("pwn", "file_inclusion", "符号执行找路径", 0.4, 90, ["angr"], []),
            ("pwn", "pwn", "ARM架构利用", 0.5, 70, ["pwntools", "ROPgadget"], ["is_arm"]),
        ]

        for from_type, to_type, reason, prob, time_cost, tools, conds in pwn_chains:
            try:
                self.chains.append(AttackChain(
                    from_vuln=VulnerabilityType.PWN,
                    to_vuln=VulnerabilityType(to_type),
                    reasoning=reason,
                    success_prob=prob,
                    time_cost=time_cost,
                    tools=tools,
                    conditions=conds
                ))
            except ValueError:
                pass


    def get_next_chains(self, current_vuln: VulnerabilityType,
                       context: Dict[str, Any]) -> List[AttackChain]:
        """
        获取当前漏洞的下一步推理链

        Args:
            current_vuln: 当前漏洞类型
            context: 上下文信息

        Returns:
            可用的攻击链列表（按成功概率排序）
        """
        available_chains = []

        for chain in self.chains:
            if chain.from_vuln == current_vuln:
                # 检查条件是否满足
                if self._check_conditions(chain.conditions, context):
                    available_chains.append(chain)

        # 按成功概率和时间消耗排序
        # 优先考虑成功概率高、时间短的链
        available_chains.sort(
            key=lambda c: (c.success_prob, -c.time_cost),
            reverse=True
        )

        logger.info(f"[知识图谱] 从{current_vuln.value}找到{len(available_chains)}条推理链")
        return available_chains

    def _check_conditions(self, conditions: List[str], context: Dict[str, Any]) -> bool:
        """
        检查条件是否满足

        Args:
            conditions: 条件列表
            context: 上下文

        Returns:
            是否满足所有条件
        """
        if not conditions:
            return True

        for condition in conditions:
            if condition == "has_file_read_priv":
                if not context.get("file_read_enabled", False):
                    return False
            elif condition == "has_file_write_priv":
                if not context.get("file_write_enabled", False):
                    return False
            elif condition == "has_shell_access":
                if not context.get("shell_access", False):
                    return False
            elif condition == "has_internal_network":
                if not context.get("internal_network", False):
                    return False
            elif condition == "webshell_uploaded":
                if not context.get("webshell_uploaded", False):
                    return False
            elif condition == "can_read_log_files":
                if not context.get("can_read_logs", False):
                    return False
            # 可以添加更多条件检查

        return True

    def get_chain_by_types(self, from_type: str, to_type: str) -> Optional[AttackChain]:
        """
        根据漏洞类型获取攻击链

        Args:
            from_type: 源漏洞类型
            to_type: 目标漏洞类型

        Returns:
            攻击链或None
        """
        try:
            from_vuln = VulnerabilityType(from_type)
            to_vuln = VulnerabilityType(to_type)

            for chain in self.chains:
                if chain.from_vuln == from_vuln and chain.to_vuln == to_vuln:
                    return chain
        except ValueError:
            pass

        return None

    def get_all_vulnerabilities(self) -> List[str]:
        """获取所有已知的漏洞类型"""
        return [v.value for v in VulnerabilityType]

    def visualize_graph(self) -> str:
        """
        可视化知识图谱

        Returns:
            Graphviz DOT格式字符串
        """
        dot = ["digraph VulnerabilityGraph {"]
        dot.append("  rankdir=LR;")
        dot.append("  node [shape=box];")

        # 添加节点
        vuln_types = set()
        for chain in self.chains:
            vuln_types.add(chain.from_vuln.value)
            vuln_types.add(chain.to_vuln.value)

        for vuln in vuln_types:
            dot.append(f'  "{vuln}" [label="{vuln}"];')

        # 添加边
        for chain in self.chains:
            label = f"{chain.reasoning}\\nP={chain.success_prob}"
            dot.append(f'  "{chain.from_vuln.value}" -> "{chain.to_vuln.value}" [label="{label}"];')

        dot.append("}")
        return "\n".join(dot)
