#!/usr/bin/env python3
"""
工具路由器 - 管理工具复杂度分类和执行路径决策
"""

from typing import Set, Dict, Any
import logging

logger = logging.getLogger(__name__)

class ToolRouter:
    """工具路由决策器"""

    # 复杂工具集合（需要代理协作）
    COMPLEX_TOOLS: Set[str] = {
        # CTF工具
        "intelligent_ctf_solver",          # 实际函数名（含r）
        "ctf_web_comprehensive_solver",
        "ctf_pwn_solver",
        "ctf_crypto_solver",
        "ctf_multi_agent_solve",
        "smart_ctf_solve",
        "ctf_ultimate_solve",

        # APT工具
        "intelligent_apt_campaign",
        "apt_web_application_attack",
        "apt_network_penetration",
        "apt_comprehensive_attack",
        "adaptive_apt_attack",
        "start_adaptive_apt_attack",
        "auto_apt_attack_with_poc",

        # 自适应渗透
        "adaptive_web_penetration",
        "adaptive_network_penetration",

        # 综合扫描
        "comprehensive_recon",
        "smart_web_recon",
        "smart_network_recon",
        "smart_full_pentest",
        "auto_pentest",
        "ultimate_scan",
        "auto_pilot_attack",

        # 智能评估
        "intelligent_vulnerability_assessment",
        "intelligent_penetration_testing",
        "intelligent_smart_scan",

        # 自动化工作流
        "auto_web_security_workflow",
        "auto_network_discovery_workflow",
        "auto_osint_workflow",
        "intelligent_attack_with_poc",

        # PWN综合攻击
        "pwn_comprehensive_attack",
        "auto_ctf_solve_with_poc",
        "advanced_web_security_assessment",
        "network_penetration_test",
        "web_app_security_assessment",

        # 授权综合评估
        "authorized_comprehensive_security_assessment",
    }

    # 简单工具（直接执行）
    SIMPLE_TOOLS: Set[str] = {
        "nmap_scan", "gobuster_scan", "sqlmap_scan", "nikto_scan",
        "hydra_attack", "john_crack", "nuclei_scan", "whatweb_scan",
        "subfinder_scan", "amass_scan", "dnsrecon_scan",
    }

    @classmethod
    def is_complex(cls, tool_name: str) -> bool:
        """判断工具是否复杂"""
        return tool_name in cls.COMPLEX_TOOLS

    @classmethod
    def is_simple(cls, tool_name: str) -> bool:
        """判断工具是否简单"""
        return tool_name in cls.SIMPLE_TOOLS

    @classmethod
    def get_route(cls, tool_name: str, data: Dict[str, Any]) -> str:
        """获取工具执行路由: 'agent' 或 'direct'"""
        if cls.is_complex(tool_name):
            return "agent"
        elif cls.is_simple(tool_name):
            return "direct"
        else:
            # 未分类工具，根据数据特征判断
            if cls._has_complex_features(data):
                return "agent"
            return "direct"

    @classmethod
    def _has_complex_features(cls, data: Dict[str, Any]) -> bool:
        """检查数据是否有复杂特征"""
        # 多目标
        if isinstance(data.get("targets"), list) and len(data["targets"]) > 1:
            return True
        # 多阶段
        if data.get("multi_phase") or data.get("comprehensive"):
            return True
        # 需要协作
        if data.get("requires_collaboration"):
            return True
        return False
