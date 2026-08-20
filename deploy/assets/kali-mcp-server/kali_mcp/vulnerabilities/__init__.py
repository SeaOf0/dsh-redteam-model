"""
漏洞数据库模块

提供0day/1day/nday漏洞管理和查询功能。
"""

from .vuln_database import (
    Vulnerability,
    VulnerabilityDatabase,
    VulnCategory,
    VulnSeverity,
    VulnType,
    get_vulnerability_database
)

__all__ = [
    'Vulnerability',
    'VulnerabilityDatabase',
    'VulnCategory',
    'VulnSeverity',
    'VulnType',
    'get_vulnerability_database'
]
