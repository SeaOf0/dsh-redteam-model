#!/usr/bin/env python3
"""Parser registry and dispatch functions."""

import logging
from typing import Dict, Any, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate
from ._port_scanners import NmapParser, MasscanParser
from ._web_scanners import GobusterParser
from ._vuln_scanners import NucleiParser, NiktoParser
from ._exploit_tools import SqlmapParser
from ._recon_tools import SubfinderParser
from ._password_tools import HydraParser
from ._web_tech import WhatwebParser
from ._generic import GenericParser

logger = logging.getLogger(__name__)


# ============================================================
# 解析器注册表和调度器
# ============================================================

# 解析器单例注册表
PARSER_REGISTRY: Dict[str, BaseOutputParser] = {
    # 端口扫描
    "nmap": NmapParser(),
    "masscan": MasscanParser(),
    # 目录扫描
    "gobuster": GobusterParser(),
    "dirb": GobusterParser(),
    "ffuf": GobusterParser(),
    "feroxbuster": GobusterParser(),
    # 漏洞扫描
    "nuclei": NucleiParser(),
    "nikto": NiktoParser(),
    # SQL 注入
    "sqlmap": SqlmapParser(),
    # 子域名枚举
    "subfinder": SubfinderParser(),
    "sublist3r": SubfinderParser(),
    "amass": SubfinderParser(),
    # 密码爆破
    "hydra": HydraParser(),
    # 技术栈识别
    "whatweb": WhatwebParser(),
}

# 通用解析器实例
_GENERIC_PARSER = GenericParser()


def parse_output(
    tool_name: str,
    output: str,
    return_code: int = 0,
    data: Optional[Dict[str, Any]] = None,
) -> ParsedResult:
    """
    解析工具输出的主入口 — 根据工具名自动分发到对应解析器。

    Args:
        tool_name: 工具名称 (nmap, gobuster, nuclei, sqlmap, etc.)
        output: 工具的原始 stdout 输出
        return_code: 进程退出码
        data: 工具调用时的参数字典

    Returns:
        统一的 ParsedResult

    Examples:
        >>> result = parse_output("nmap", nmap_output, 0, {"target": "10.0.0.1"})
        >>> result.structured_data["ports"]
        [{"port": 80, "protocol": "tcp", "state": "open", ...}]

        >>> result = parse_output("gobuster", gobuster_output, 0, {"url": "http://target"})
        >>> result.structured_data["interesting"]
        ["/admin", "/.git"]
    """
    data = data or {}

    # 规范化工具名
    normalized = tool_name.lower().strip()

    parser = PARSER_REGISTRY.get(normalized, _GENERIC_PARSER)

    # 为通用解析器传递工具名
    if parser is _GENERIC_PARSER:
        data = dict(data)
        data["_tool_name"] = tool_name

    try:
        return parser.parse(output, return_code, data)
    except Exception as e:
        logger.error(f"解析器 {normalized} 异常: {e}")
        # 最终兜底 — 即使解析器完全崩溃也返回有用结果
        truncated, _ = smart_truncate(output or "")
        return ParsedResult(
            tool_name=tool_name,
            success=return_code == 0,
            summary=f"{tool_name} 输出解析异常: {str(e)[:100]}",
            structured_data={"parse_error": str(e)},
            raw_output=truncated,
            flags_found=detect_flags(output or ""),
            next_steps=[],
            severity="info",
            confidence=0.0,
        )


def get_parser(tool_name: str) -> BaseOutputParser:
    """
    获取指定工具的解析器实例。

    Args:
        tool_name: 工具名称

    Returns:
        解析器实例（无匹配时返回 GenericParser）
    """
    return PARSER_REGISTRY.get(tool_name.lower().strip(), _GENERIC_PARSER)


def register_parser(tool_name: str, parser: BaseOutputParser) -> None:
    """
    注册自定义解析器。

    Args:
        tool_name: 工具名称
        parser: 解析器实例
    """
    PARSER_REGISTRY[tool_name.lower().strip()] = parser


def list_parsers() -> Dict[str, str]:
    """列出所有已注册的解析器及其类名"""
    return {
        name: type(parser).__name__
        for name, parser in PARSER_REGISTRY.items()
    }
