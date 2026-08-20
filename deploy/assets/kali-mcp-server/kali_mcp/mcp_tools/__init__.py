#!/usr/bin/env python3
"""
MCP工具注册模块

按类别组织的MCP工具注册函数
"""

from .recon_tools import register_recon_tools
from .ai_tools import register_ai_session_tools
from .code_audit_tools import register_code_audit_tools
from .misc_tools import register_misc_tools
from .apt_tools import register_apt_tools
from .ctf_tools import register_ctf_tools
from .scan_workflow_tools import register_scan_workflow_tools
from .advanced_ctf_tools import register_advanced_ctf_tools
from .session_tools import register_session_tools
from .pwn_tools import register_pwn_tools
from .adaptive_tools import register_adaptive_tools
from .deep_test_tools import register_deep_test_tools
from .vuln_mgmt_tools import register_vuln_mgmt_tools
from .chain_mgmt_tools import register_chain_mgmt_tools
from .pentagi_bridge_tools import register_pentagi_bridge_tools
from .llm_react_tools import register_llm_react_tools
from .assessment_tools import register_assessment_tools
from .v2_tools import register_v2_tools, V2_TOOL_COUNT
from .v3_tools import register_v3_tools, V3_TOOL_COUNT
from .vuln_db_tools import register_vulnerability_tools, VULN_TOOL_COUNT
from .kali_extended_tools import register_kali_extended_tools, KALI_EXTENDED_TOOL_COUNT

try:
    from .browser_tools import register_browser_tools
except ImportError:
    register_browser_tools = None


__all__ = [
    "register_recon_tools",
    "register_ai_session_tools",
    "register_code_audit_tools",
    "register_misc_tools",
    "register_apt_tools",
    "register_ctf_tools",
    "register_scan_workflow_tools",
    "register_advanced_ctf_tools",
    "register_session_tools",
    "register_pwn_tools",
    "register_adaptive_tools",
    "register_deep_test_tools",
    "register_vuln_mgmt_tools",
    "register_chain_mgmt_tools",
    "register_pentagi_bridge_tools",
    "register_llm_react_tools",
    "register_assessment_tools",
    "register_browser_tools",
    "register_v2_tools",
    "V2_TOOL_COUNT",
    "register_v3_tools",
    "V3_TOOL_COUNT",
    "register_vulnerability_tools",
    "VULN_TOOL_COUNT",
    "register_kali_extended_tools",
    "KALI_EXTENDED_TOOL_COUNT",
]
