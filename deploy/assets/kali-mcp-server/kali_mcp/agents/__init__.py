#!/usr/bin/env python3
"""
Kali MCP Agents Module

多智能体集群系统 - Agent模块

包含：
- BaseAgentV2: 增强版Agent基类
- 专业Agent实现（信息收集、漏洞发现、攻击利用、专项领域）
"""

__version__ = "2.0.0"

from kali_mcp.agents.base_agent_v2 import (
    BaseAgentV2,
    AgentCapability,
    ResourceProfile,
    PerformanceMetrics,
    LoadReport
)
from kali_mcp.agents.specialized.code_audit_agent import CodeAuditAgent

__all__ = [
    'BaseAgentV2',
    'AgentCapability',
    'ResourceProfile',
    'PerformanceMetrics',
    'LoadReport',
    'CodeAuditAgent'
]
