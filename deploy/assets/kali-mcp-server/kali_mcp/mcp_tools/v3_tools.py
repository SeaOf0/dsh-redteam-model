"""
MCP工具注册 - v3深度挖掘器

将深度挖掘器注册为MCP工具，使其可以通过MCP框架调用。
"""

from typing import Dict, Any
from kali_mcp.diggers.sql_injection_digger import SQLInjectionDigger
from kali_mcp.diggers.command_injection_digger import CommandInjectionDigger
from kali_mcp.diggers.privilege_escalation_digger import PrivilegeEscalationDigger
from kali_mcp.diggers.xss_digger import XSSDigger
from kali_mcp.diggers.file_upload_digger import FileUploadDigger
from kali_mcp.diggers.file_inclusion_digger import FileInclusionDigger
from kali_mcp.diggers.pwn_digger import PWNDigger

# 创建挖掘器实例
_sql_digger = SQLInjectionDigger()
_cmd_digger = CommandInjectionDigger()
_priv_esc_digger = PrivilegeEscalationDigger()
_xss_digger = XSSDigger()
_file_upload_digger = FileUploadDigger()
_file_inclusion_digger = FileInclusionDigger()
_pwn_digger = PWNDigger()


def register_v3_tools(mcp_instance):
    """
    注册所有v3深度挖掘器到MCP

    Args:
        mcp_instance: MCP实例
    """
    global mcp
    mcp = mcp_instance

    # ==================== SQL注入深度挖掘器 ====================

    @mcp.tool()
    def sql_injection_deep_excavate(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        SQL注入深度挖掘器 - CTF和渗透测试双模式

        支持的模式：
        - ctf: 60秒快速找Flag，Flag导向
        - pentest: 深度全面挖掘，完整利用链
        - auto: 自动识别目标类型

        技术覆盖：
        - 数据库: MySQL, PostgreSQL, MSSQL, SQLite, Oracle
        - 注入类型: 联合/报错/盲注/堆叠/OOB
        - 利用技术: 数据提取/文件读写/命令执行

        Args:
            target: 目标URL或IP地址
            mode: 工作模式 (ctf/pentest/auto)，默认auto

        Returns:
            挖掘结果，包含：
            - mode: 实际使用的模式
            - phases: 各阶段执行结果
            - findings: 发现列表
            - flags: 提取的Flag列表
            - summary: 执行摘要
            - duration: 执行耗时（秒）

        Example (CTF模式):
            target = "http://ctf.example.com/challenge?id=1"
            result = sql_injection_deep_excavate(target, mode="ctf")
            # 60秒内快速找到Flag

        Example (渗透测试模式):
            target = "http://testphp.vulnweb.com/artists.php?artist=1"
            result = sql_injection_deep_excavate(target, mode="pentest")
            # 深度枚举数据库、提取敏感数据、尝试文件操作和命令执行
        """
        return _sql_digger.excavate(target, mode)

    # ==================== 命令注入深度挖掘器 ====================

    @mcp.tool()
    def command_injection_deep_excavate(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        命令注入深度挖掘器 - CTF和渗透测试双模式

        支持的模式：
        - ctf: 60秒快速RCE找Flag
        - pentest: 深度全面挖掘，Shell建立+持久化
        - auto: 自动识别目标类型

        技术覆盖：
        - 注入类型: ; | & ` $() \n \r
        - Blind RCE: 时间盲注、OOB外带
        - Shell技术: 反向Shell、Bind Shell
        - 权限提升: 从Web用户到系统权限

        Args:
            target: 目标URL或IP地址，或Shell连接信息
            mode: 工作模式 (ctf/pentest/auto)，默认auto

        Returns:
            挖掘结果，包含：
            - mode: 实际使用的模式
            - phases: 各阶段执行结果
            - findings: 发现列表
            - flags: 提取的Flag列表
            - shell_access: 是否获得Shell
            - privilege_escalation: 提权结果
            - summary: 执行摘要
            - duration: 执行耗时（秒）

        Example (CTF模式):
            # 直接RCE读取flag
            result = command_injection_deep_excavate("http://ctf.example.com?cmd=cat+/flag", mode="ctf")

        Example (渗透测试模式):
            # 完整命令注入利用链
            result = command_injection_deep_excavate("http://target.com/vuln.php", mode="pentest")
        """
        return _cmd_digger.excavate(target, mode)

    # ==================== 权限提升深度挖掘器 ====================

    @mcp.tool()
    def privilege_escalation_deep_excavate(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        权限提升深度挖掘器 - CTF和渗透测试双模式

        支持的模式：
        - ctf: 60秒快速提权找Flag
        - pentest: 深度全面枚举所有提权向量
        - auto: 自动识别目标类型

        技术覆盖：
        - Linux提权: SUID/内核/配置错误/Docker
        - Windows提权: 服务/DLL/UAC
        - 容器逃逸: Docker/K8s
        - 提权优先级: P1(快速)  P2(中等)  P3(困难)

        Args:
            target: 目标Shell连接或文件系统访问
            mode: 工作模式 (ctf/pentest/auto)，默认auto

        Returns:
            挖掘结果，包含：
            - mode: 实际使用的模式
            - phases: 各阶段执行结果（P1/P2/P3提权向量）
            - findings: 发现列表
            - flags: 提取的Flag列表
            - root_access: 是否获得root
            - escalation_paths: 可用的提权路径
            - summary: 执行摘要
            - duration: 执行耗时（秒）

        Example (CTF模式):
            # 快速提权并读取/root/flag
            result = privilege_escalation_deep_excavate("shell_connection", mode="ctf")

        Example (渗透测试模式):
            # 全面枚举所有提权向量
            result = privilege_escalation_deep_excavate("shell_connection", mode="pentest")
        """
        return _priv_esc_digger.excavate(target, mode)

    # ==================== XSS深度挖掘器 ====================

    @mcp.tool()
    def xss_deep_excavate(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        XSS深度挖掘器 - CTF和渗透测试双模式

        支持的模式：
        - ctf: 60秒快速XSS验证
        - pentest: 深度XSS利用链
        - auto: 自动识别目标类型

        技术覆盖：
        - XSS类型: 反射型/存储型/DOM型
        - 绕过技术: CSP绕过/WAF绕过/编码绕过
        - 利用技术: Cookie窃取/CSRF组合/Beacon Payload

        Args:
            target: 目标URL
            mode: 工作模式 (ctf/pentest/auto)，默认auto

        Returns:
            挖掘结果，包含：
            - mode: 实际使用的模式
            - phases: 各阶段执行结果
            - findings: 发现列表
            - flags: 提取的Flag列表
            - xss_confirmed: XSS是否确认
            - summary: 执行摘要
            - duration: 执行耗时（秒）

        Example (CTF模式):
            result = xss_deep_excavate("http://ctf.example.com/search?q=test", mode="ctf")
            # 快速检测XSS并验证弹窗

        Example (渗透测试模式):
            result = xss_deep_excavate("http://target.com/search", mode="pentest")
            # 完整XSS利用：Cookie窃取、CSRF组合、持久化Beacon
        """
        return _xss_digger.excavate(target, mode)

    # ==================== 文件上传深度挖掘器 ====================

    @mcp.tool()
    def file_upload_deep_excavate(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        文件上传深度挖掘器 - CTF和渗透测试双模式

        支持的模式：
        - ctf: 60秒快速WebShell上传
        - pentest: 深度文件上传利用链
        - auto: 自动识别目标类型

        技术覆盖：
        - 绕过技术: 20+种绕过方法（扩展名/MIME/双文件等）
        - 文件类型: 图片马/多语言WebShell
        - 隐蔽技术: 内存WebShell/无扩展名
        - 利用: RCE/权限提升/持久化

        Args:
            target: 目标URL
            mode: 工作模式 (ctf/pentest/auto)，默认auto

        Returns:
            挖掘结果，包含：
            - mode: 实际使用的模式
            - phases: 各阶段执行结果
            - findings: 发现列表
            - flags: 提取的Flag列表
            - webshell_uploaded: WebShell是否上传成功
            - summary: 执行摘要
            - duration: 执行耗时（秒）

        Example (CTF模式):
            result = file_upload_deep_excavate("http://ctf.example.com/upload", mode="ctf")
            # 快速绕过限制上传WebShell并RCE读取flag

        Example (渗透测试模式):
            result = file_upload_deep_excavate("http://target.com/upload.php", mode="pentest")
            # 全面绕过测试、隐蔽WebShell、持久化后门
        """
        return _file_upload_digger.excavate(target, mode)

    # ==================== 文件包含深度挖掘器 ====================

    @mcp.tool()
    def file_inclusion_deep_excavate(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        文件包含深度挖掘器 - CTF和渗透测试双模式

        支持的模式：
        - ctf: 60秒快速LFI利用
        - pentest: 深度文件包含利用链
        - auto: 自动识别目标类型

        技术覆盖：
        - LFI: 本地文件包含完整利用
        - PHP伪协议: php://filter, php://input, data://, expect://, zip://
        - 日志投毒: Apache/Nginx/SSH日志
        - LFI2RCE: 通过LFI实现RCE
        - RFI: 远程文件包含

        Args:
            target: 目标URL
            mode: 工作模式 (ctf/pentest/auto)，默认auto

        Returns:
            挖掘结果，包含：
            - mode: 实际使用的模式
            - phases: 各阶段执行结果
            - findings: 发现列表
            - flags: 提取的Flag列表
            - lfi_confirmed: LFI是否确认
            - summary: 执行摘要
            - duration: 执行耗时（秒）

        Example (CTF模式):
            result = file_inclusion_deep_excavate("http://ctf.example.com?page=index", mode="ctf")
            # 快速LFI检测并读取flag文件

        Example (渗透测试模式):
            result = file_inclusion_deep_excavate("http://target.com?file=home", mode="pentest")
            # 完整LFI利用：伪协议、日志投毒、LFI2RCE
        """
        return _file_inclusion_digger.excavate(target, mode)

    # ==================== PWN深度挖掘器 ====================

    @mcp.tool()
    def pwn_deep_excavate(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        PWN深度挖掘器 - CTF和渗透测试双模式

        支持的模式：
        - ctf: 60秒快速二进制利用
        - pentest: 深度PWN利用链
        - auto: 自动识别目标类型

        技术覆盖：
        - 栈溢出：缓冲区溢出/返回地址覆盖
        - 堆利用：UAF/fastbin/double free/unsafe unlink
        - ROP链：自动构造ROP链
        - Shellcode：Shellcode注入和执行
        - AEG：自动漏洞利用生成
        - 后门植入：持久化后门

        Args:
            target: 二进制文件路径或远程目标（host:port）
            mode: 工作模式 (ctf/pentest/auto)，默认auto

        Returns:
            挖掘结果，包含：
            - mode: 实际使用的模式
            - phases: 各阶段执行结果
            - findings: 发现列表
            - flags: 提取的Flag列表
            - exploit_generated: Exploit是否生成成功
            - summary: 执行摘要
            - duration: 执行耗时（秒）

        Example (CTF模式):
            result = pwn_deep_excavate("/tmp/challenge_binary", mode="ctf")
            # 快速分析二进制  检测漏洞  生成exploit  获取flag

        Example (渗透测试模式):
            result = pwn_deep_excavate("/tmp/vulnerable_binary", mode="pentest")
            # 完整PWN利用：栈溢出/堆利用  ROP链  Shellcode  后门植入
        """
        return _pwn_digger.excavate(target, mode)


# v3工具计数
V3_TOOL_COUNT = 7  # 所有深度挖掘器已注册（SQL注入、命令注入、权限提升、XSS、文件上传、文件包含、PWN）

__all__ = [
    'register_v3_tools',
    'V3_TOOL_COUNT',
]
