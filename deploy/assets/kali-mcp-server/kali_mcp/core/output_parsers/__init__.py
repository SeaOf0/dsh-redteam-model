#!/usr/bin/env python3
"""
output_parsers 子包 — 向后兼容的公共接口

所有原 output_parsers.py 的公共符号均在此重新导出，
确保现有代码无需修改即可继续使用:

    from kali_mcp.core.output_parsers import parse_output
    from kali_mcp.core.output_parsers import ParsedResult, detect_flags
    from kali_mcp.core.output_parsers import NmapParser, GobusterParser
"""

# 基础类型和工具函数
from ._base import (
    ParsedResult,
    BaseOutputParser,
    detect_flags,
    smart_truncate,
    _is_trivial_hash,
)

# 具体解析器
from ._port_scanners import NmapParser, MasscanParser
from ._web_scanners import GobusterParser
from ._vuln_scanners import NucleiParser, NiktoParser
from ._exploit_tools import SqlmapParser
from ._recon_tools import SubfinderParser
from ._password_tools import HydraParser
from ._web_tech import WhatwebParser
from ._generic import GenericParser

# 注册表和调度函数
from ._registry import (
    PARSER_REGISTRY,
    parse_output,
    get_parser,
    register_parser,
    list_parsers,
)

__all__ = [
    # 数据结构
    "ParsedResult",
    "BaseOutputParser",
    # 工具函数
    "detect_flags",
    "smart_truncate",
    "_is_trivial_hash",
    # 具体解析器
    "NmapParser",
    "MasscanParser",
    "GobusterParser",
    "NucleiParser",
    "NiktoParser",
    "SqlmapParser",
    "SubfinderParser",
    "HydraParser",
    "WhatwebParser",
    "GenericParser",
    # 注册表 API
    "PARSER_REGISTRY",
    "parse_output",
    "get_parser",
    "register_parser",
    "list_parsers",
]
