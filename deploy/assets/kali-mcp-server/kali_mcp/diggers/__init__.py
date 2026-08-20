"""
Kali MCP v3.0 - 深度挖掘器模块

本模块实现了7个核心深度挖掘器，每个都支持CTF和渗透测试双模式：
1. SQL注入深度挖掘器 
2. 命令注入深度挖掘器 
3. 权限提升深度挖掘器 
4. XSS深度挖掘器 
5. 文件上传深度挖掘器 
6. 文件包含深度挖掘器 
7. PWN深度挖掘器 

每个挖掘器都继承自BaseDeepDigger基类，支持：
- CTF模式：60秒快速挖掘，Flag导向
- 渗透测试模式：深度全面挖掘，取证导向
- 自动模式：智能识别目标类型
"""

from .base_digger import BaseDeepDigger
from .sql_injection_digger import SQLInjectionDigger
from .command_injection_digger import CommandInjectionDigger
from .privilege_escalation_digger import PrivilegeEscalationDigger
from .xss_digger import XSSDigger
from .file_upload_digger import FileUploadDigger
from .file_inclusion_digger import FileInclusionDigger
from .pwn_digger import PWNDigger

__all__ = [
    'BaseDeepDigger',
    'SQLInjectionDigger',
    'CommandInjectionDigger',
    'PrivilegeEscalationDigger',
    'XSSDigger',
    'FileUploadDigger',
    'FileInclusionDigger',
    'PWNDigger',
]
