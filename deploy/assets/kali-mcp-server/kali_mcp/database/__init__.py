#!/usr/bin/env python3
"""
Kali MCP 数据库模块

提供数据持久化功能:
- ScanRepository: 扫描结果存储
- VulnRepository: 漏洞记录存储
- SessionRepository: 会话历史存储
"""

from .repository import (
    ScanRepository,
    VulnRepository,
    SessionRepository,
    get_scan_repository,
    get_vuln_repository,
    get_session_repository
)

__all__ = [
    "ScanRepository",
    "VulnRepository",
    "SessionRepository",
    "get_scan_repository",
    "get_vuln_repository",
    "get_session_repository",
]
