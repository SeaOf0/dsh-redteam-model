#!/usr/bin/env python3
"""
Kali MCP - 智能化渗透测试MCP服务器
模块化架构版本 v5.2

核心执行路径: mcp_server.py  kali_mcp/mcp_tools/*.py  LocalCommandExecutor
"""

__version__ = "5.2.0"
__author__ = "SeaOf0"

# Legacy core modules — soft import (these exist but are NOT the primary path;
# LocalCommandExecutor in core/local_executor.py is the active executor).
try:
    from .core.executor import AsyncExecutor
    from .core.session import SessionManager, SessionContext
    from .core.strategy import StrategyEngine
    from .core.cache import ResultCache
except ImportError:
    AsyncExecutor = None  # type: ignore
    SessionManager = None  # type: ignore
    SessionContext = None  # type: ignore
    StrategyEngine = None  # type: ignore
    ResultCache = None  # type: ignore

# Tools subsystem availability flags
try:
    from .tools.base import BaseTool, ToolResult, ToolRegistry
except ImportError:
    BaseTool = None  # type: ignore
    ToolResult = None  # type: ignore
    ToolRegistry = None  # type: ignore

try:
    from .tools import (
        AD_TOOLS_AVAILABLE,
        FORENSICS_TOOLS_AVAILABLE,
        MOBILE_TOOLS_AVAILABLE,
        CLOUD_TOOLS_AVAILABLE,
        CONTAINER_TOOLS_AVAILABLE,
    )
except ImportError:
    AD_TOOLS_AVAILABLE = False
    FORENSICS_TOOLS_AVAILABLE = False
    MOBILE_TOOLS_AVAILABLE = False
    CLOUD_TOOLS_AVAILABLE = False
    CONTAINER_TOOLS_AVAILABLE = False

# Core engine availability flags
try:
    from .core import (
        ULTIMATE_ENGINE_AVAILABLE,
        ORCHESTRATOR_AVAILABLE,
        OPTIMIZER_AVAILABLE,
        SKILL_DISPATCHER_AVAILABLE,
    )
except ImportError:
    ULTIMATE_ENGINE_AVAILABLE = False
    ORCHESTRATOR_AVAILABLE = False
    OPTIMIZER_AVAILABLE = False
    SKILL_DISPATCHER_AVAILABLE = False

# V2 MCP tool registration
try:
    from .mcp_tools_v2 import register_v2_tools, V2_TOOL_COUNT
except ImportError:
    register_v2_tools = None  # type: ignore
    V2_TOOL_COUNT = 0

__all__ = [
    "__version__",
    "__author__",
    "register_v2_tools",
    "V2_TOOL_COUNT",
]
