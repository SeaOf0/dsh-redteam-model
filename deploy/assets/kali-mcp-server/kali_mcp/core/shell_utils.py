#!/usr/bin/env python3
"""
Shell 参数清洗工具和执行配置

从 local_executor.py 中抽取，打破 local_executor <-> tool_registry 循环依赖。
"""

import os
import shlex


def sanitize_shell_arg(value: str) -> str:
    """使用 shlex.quote() 转义 shell 参数，防止命令注入"""
    if not value:
        return ""
    return shlex.quote(str(value))


def sanitize_shell_fragment(value: str) -> str:
    """
    转义包含多个参数的片段，避免把 '-sV -sC -T3' 当成单个参数。
    """
    if not value:
        return ""
    try:
        tokens = shlex.split(str(value))
    except ValueError:
        tokens = [str(value)]
    return " ".join(shlex.quote(token) for token in tokens if token)


EXEC_CONFIG = {
    "default_timeout": int(os.environ.get("KALI_MCP_TIMEOUT", "60")),
    "nuclei_rate_limit": int(os.environ.get("KALI_MCP_NUCLEI_RATE", "150")),
    "nuclei_timeout": int(os.environ.get("KALI_MCP_NUCLEI_TIMEOUT", "15")),
    "retry_count": int(os.environ.get("KALI_MCP_RETRY_COUNT", "2")),
    "retry_delay": int(os.environ.get("KALI_MCP_RETRY_DELAY", "3")),
    "tool_timeouts": {
        "nmap": 180,
        "masscan": 120,
        "sqlmap": 300,
        "hydra": 300,
        "nikto": 120,
        "nuclei": 90,
        "wpscan": 120,
        "gobuster": 90,
        "ffuf": 90,
        "whatweb": 30,
        "httpx": 30,
        "subfinder": 60,
        "amass": 120,
    },
}
