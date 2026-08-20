#!/usr/bin/env python3
"""
本地命令执行器

从 mcp_server.py 提取:
- LocalCommandExecutor: 本地Kali工具命令执行器
"""

import os
import re
import json
import shlex
import time
import logging
import subprocess
import hashlib
import threading

# 并发上限：远程客户端并行调用时防止同时拉起过多扫描器；环境变量可调
_MAX_CONCURRENT = max(1, int(os.getenv("KALI_MCP_MAX_CONCURRENT", "4")))
_EXEC_SEMAPHORE = threading.BoundedSemaphore(_MAX_CONCURRENT)
from typing import Dict, Any, Optional, List, Set
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from kali_mcp.security import engagement_manager
except Exception:
    engagement_manager = None

# v6.0: 声明式工具注册表 + 结构化输出解析器
try:
    from kali_mcp.core.tool_registry import (
        build_command as _registry_build_command,
        ALLOWED_TOOLS as _REGISTRY_ALLOWED_TOOLS,
        get_tool_spec,
        get_output_parser_name,
    )
    _HAS_TOOL_REGISTRY = True
except ImportError:
    _HAS_TOOL_REGISTRY = False
    logger.debug("tool_registry 未加载，使用内置 elif 路由")

try:
    from kali_mcp.core.output_parsers import (
        parse_output as _parse_output,
        detect_flags,
        smart_truncate,
    )
    _HAS_OUTPUT_PARSERS = True
except ImportError:
    _HAS_OUTPUT_PARSERS = False
    logger.debug("output_parsers 未加载，使用原始输出")

# v5.1: 可选事件总线 — 不存在时静默降级
_event_bus = None

def set_event_bus(bus):
    """注入全局事件总线实例（由 mcp_server.py 启动时调用）"""
    global _event_bus
    _event_bus = bus


from kali_mcp.core.shell_utils import (
    sanitize_shell_arg,
    sanitize_shell_fragment,
    EXEC_CONFIG,
)

ALLOWED_TOOLS: Set[str] = {
    "nmap", "gobuster", "sqlmap", "nikto", "hydra", "dirb",
    "wfuzz", "ffuf", "feroxbuster", "wafw00f", "whatweb",
    "wpscan", "joomscan", "masscan", "zmap", "arp-scan", "arpscan",
    "fping", "netdiscover", "dnsrecon", "dnsenum", "fierce",
    "dnsmap", "sublist3r", "subfinder", "amass", "john", "hashcat",
    "medusa", "ncrack", "patator", "crowbar", "brutespray",
    "aircrack-ng", "aircrack", "reaver", "bully", "pixiewps",
    "wifiphisher", "bluesnarfer", "btscanner", "ettercap",
    "responder", "bettercap", "dsniff", "ngrep", "tshark",
    "nuclei", "searchsploit", "enum4linux", "theHarvester",
    "sherlock", "recon-ng", "binwalk", "radare2", "r2",
    "slowhttptest", "yersinia", "httpx", "metasploit",
    "msfconsole", "msfvenom",
    "semgrep", "bandit", "flawfinder", "shellcheck",
    # v5.1: 新增基础工具
    "curl", "wget", "nc", "ncat", "netcat",
    "ssh", "scp", "python3", "python",
    "dig", "host", "whois", "traceroute",
    "openssl", "base64", "xxd",
    "grep", "awk", "sed", "jq",
    "steghide", "zsteg", "exiftool", "foremost",
    "volatility", "strings",
    # v6.1: Kali extended tools
    "commix", "nosqlmap", "xsstrike", "dalfox", "arjun",
    "crackmapexec", "netexec", "nxc",
    "impacket-secretsdump", "impacket-psexec", "impacket-smbexec",
    "impacket-wmiexec", "impacket-GetNPUsers", "impacket-getTGT",
    "impacket-ntlmrelayx",
    "bloodhound-python", "bloodhound",
    "findomain", "assetfinder",
    "chisel", "proxychains", "proxychains4",
}


def validate_tool_name(name: str) -> bool:
    """验证工具名是否在白名单中

    v6.0: 同时检查内置白名单和注册表工具集。
    """
    if name in ALLOWED_TOOLS:
        return True
    if _HAS_TOOL_REGISTRY and name in _REGISTRY_ALLOWED_TOOLS:
        return True
    return False

class LocalCommandExecutor:
    """本地命令执行器 - 直接使用subprocess执行Kali工具"""

    def __init__(self, timeout: int = 300, working_dir: str = None):
        """
        初始化本地命令执行器

        Args:
            timeout: 命令执行超时时间（秒）
            working_dir: 工作目录
        """
        self.timeout = timeout
        self.working_dir = working_dir or os.getcwd()
        logger.info(f"初始化本地命令执行器，工作目录: {self.working_dir}")

    def execute_command(self, command: str, timeout: int = None) -> Dict[str, Any]:
        """
        执行shell命令

        Args:
            command: 要执行的命令
            timeout: 命令超时时间（可选，覆盖默认值）

        Returns:
            执行结果字典
        """
        cmd_timeout = timeout or self.timeout

        # 合规策略 - 授权范围门禁
        if engagement_manager is not None:
            extracted_targets = engagement_manager.extract_targets(command)
            allowed, reason = engagement_manager.validate_targets(extracted_targets)
            if not allowed:
                return {
                    "success": False,
                    "error": f"Scope blocked command: {reason}",
                    "output": "",
                    "return_code": -3,
                    "command": command,
                    "scope": {
                        "targets": extracted_targets,
                        "reason": reason,
                    },
                }

        try:
            logger.debug(f"执行命令: {command}")

            with _EXEC_SEMAPHORE:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=cmd_timeout,
                    cwd=self.working_dir
                )

            success = result.returncode == 0

            return {
                "success": success,
                "output": result.stdout,
                "error": result.stderr if not success else "",
                "return_code": result.returncode,
                "command": command
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"命令执行超时 ({cmd_timeout}秒): {command}")
            return {
                "success": False,
                "error": f"Command timeout after {cmd_timeout} seconds",
                "output": "",
                "return_code": -1,
                "command": command
            }
        except Exception as e:
            logger.error(f"命令执行失败: {command}, 错误: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "return_code": -1,
                "command": command
            }

    def check_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        if not validate_tool_name(tool_name):
            logger.warning(f"工具名不在白名单中: {tool_name}")
            return False
        result = self.execute_command(f"which {sanitize_shell_arg(tool_name)}", timeout=5)
        return result["success"]

    def get_tool_version(self, tool_name: str) -> str:
        """获取工具版本"""
        if not validate_tool_name(tool_name):
            logger.warning(f"工具名不在白名单中: {tool_name}")
            return "Unknown"
        result = self.execute_command(f"{sanitize_shell_arg(tool_name)} --version 2>&1 | head -1", timeout=5)
        return result["output"].strip() if result["success"] else "Unknown"

    def execute_tool_with_data(self, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据工具名称和数据字典执行工具命令

        Args:
            tool_name: 工具名称
            data: 工具参数字典

        Returns:
            执行结果
        """
        # 工具级授权范围门禁
        if engagement_manager is not None:
            allowed_tool, reason_tool = engagement_manager.is_tool_allowed(tool_name)
            if not allowed_tool:
                return {
                    "success": False,
                    "error": f"Tool denied by profile: {reason_tool}",
                    "return_code": -4,
                    "tool_name": tool_name,
                }
            targets = engagement_manager.extract_targets(json.dumps(data or {}, ensure_ascii=False))
            allowed_scope, reason_scope = engagement_manager.validate_targets(targets)
            if not allowed_scope:
                return {
                    "success": False,
                    "error": f"Scope blocked tool call: {reason_scope}",
                    "return_code": -3,
                    "tool_name": tool_name,
                    "scope": {
                        "targets": targets,
                        "reason": reason_scope,
                    },
                }

        command = self._build_tool_command(tool_name, data)
        if not command:
            in_whitelist = tool_name in ALLOWED_TOOLS
            if in_whitelist:
                reason = f"工具 '{tool_name}' 在白名单中但无法构建命令，请检查参数"
            else:
                reason = f"工具 '{tool_name}' 不在白名单中，拒绝执行"
            logger.error(reason)
            return {"success": False, "error": reason, "tool_name": tool_name}

        # v5.1: 工具级超时
        tool_timeout = EXEC_CONFIG["tool_timeouts"].get(tool_name, EXEC_CONFIG["default_timeout"])

        start_time = time.time()
        result = self.execute_command(command, timeout=tool_timeout)
        duration = round(time.time() - start_time, 2)

        result["duration"] = duration
        result["tool_name"] = tool_name

        # v6.0: 结构化输出解析
        if _HAS_OUTPUT_PARSERS:
            try:
                raw_output = result.get("output", "")
                parsed = _parse_output(tool_name, raw_output, result.get("success", False))
                result["parsed"] = parsed.to_dict()
                # 智能截断替代硬截断
                truncated_output, was_truncated = smart_truncate(raw_output)
                if was_truncated:
                    result["output_truncated"] = True
                # Flag 检测
                if parsed.flags_found:
                    result["flags_found"] = parsed.flags_found
                    logger.info(f" 发现 Flag: {parsed.flags_found}")
                # 下一步建议
                if parsed.next_steps:
                    result["next_steps"] = parsed.next_steps
            except Exception as e:
                logger.debug(f"输出解析失败 (非致命): {e}")

        # v5.1: 通过事件总线广播工具执行结果
        if _event_bus is not None:
            try:
                target = data.get("target", data.get("url", data.get("domain", "")))
                # v6.0: 使用智能截断替代硬截断
                event_output = result.get("output", "")
                if _HAS_OUTPUT_PARSERS:
                    event_output, _ = smart_truncate(event_output, 5000)
                else:
                    event_output = event_output[:5000]
                _event_bus.emit("tool.result", {
                    "tool_name": tool_name,
                    "target": target,
                    "success": result.get("success", False),
                    "output": event_output,
                    "duration": duration,
                    "data": {k: v for k, v in data.items() if k != "additional_args"},
                }, source="executor")
            except Exception as e:
                logger.debug(f"EventBus emit failed (non-fatal): {e}")

        return result

    def execute_with_retry(self, tool_name: str, data: Dict[str, Any],
                           retry_count: int = None, retry_delay: int = None) -> Dict[str, Any]:
        """
        带自动重试的工具执行

        失败时自动重试，每次可调整参数（如缩小扫描范围）。

        Args:
            tool_name: 工具名称
            data: 工具参数
            retry_count: 重试次数，默认从 EXEC_CONFIG 读取
            retry_delay: 重试间隔秒数
        """
        max_retries = retry_count if retry_count is not None else EXEC_CONFIG["retry_count"]
        delay = retry_delay if retry_delay is not None else EXEC_CONFIG["retry_delay"]

        last_result = None
        for attempt in range(max_retries + 1):
            result = self.execute_tool_with_data(tool_name, data)
            if result.get("success"):
                return result
            last_result = result

            if attempt < max_retries:
                logger.info(f"工具 {tool_name} 第{attempt+1}次失败，{delay}秒后重试")
                time.sleep(delay)
                # 超时失败时缩小范围
                if "timeout" in str(result.get("error", "")).lower():
                    data = dict(data)  # 不修改原始dict
                    if "additional_args" not in data:
                        data["additional_args"] = ""
                    # 对特定工具添加快速模式参数
                    if tool_name == "nmap" and "-T5" not in data.get("additional_args", ""):
                        data["additional_args"] += " -T5 --max-retries 1"
                    elif tool_name == "gobuster" and "-t" not in data.get("additional_args", ""):
                        data["additional_args"] += " -t 20"

        return last_result

    def _build_tool_command(self, tool_name: str, data: Dict[str, Any]) -> str:
        """构建工具命令

        v6.0: 声明式工具注册表 (tool_registry) 是唯一路由路径。
        """
        if _HAS_TOOL_REGISTRY:
            cmd = _registry_build_command(tool_name, data)
            if cmd:
                return cmd

        # ==================== v5.2: 通用 catch-all ====================
        # 对于白名单中有但没有专门路由的工具，尝试通用构建
        if tool_name in ALLOWED_TOOLS:
            target = data.get("target", data.get("url", data.get("domain", "")))
            additional_args = data.get("additional_args", "")
            cmd = tool_name
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            if target:
                cmd += f" {sanitize_shell_arg(target)}"
            logger.info(f"使用通用路由构建: {tool_name}")
            return cmd

        # 未知工具，返回空字符串并记录详细原因
        logger.warning(f"未知工具名: {tool_name}，不在白名单中，拒绝构建命令")
        return ""
