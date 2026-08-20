#!/usr/bin/env python3
"""
ToolBridge — MCP 全量工具桥接层

通过 duck-type 兼容 FastMCP 的 ToolRegistry，调用所有 register_xxx_tools()
函数捕获工具函数，然后通过 call_tool(name, params) 暴露给 Web UI 的 LLM ReAct 引擎。
"""

import asyncio
import inspect
import json
import logging
from typing import Callable, Dict, Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ToolRegistry — 模拟 FastMCP.tool() 接口
# ---------------------------------------------------------------------------

class ToolRegistry:
    """模拟 FastMCP.tool() 接口，捕获所有注册的工具函数"""

    def __init__(self):
        self.tools: Dict[str, Callable] = {}
        self.tool_docs: Dict[str, str] = {}

    def tool(self):
        """兼容 @mcp.tool() 装饰器"""
        def decorator(func):
            self.tools[func.__name__] = func
            self.tool_docs[func.__name__] = func.__doc__ or ""
            return func
        return decorator


# ---------------------------------------------------------------------------
# ToolBridge — 初始化全部工具 + 调用接口
# ---------------------------------------------------------------------------

class ToolBridge:
    """桥接 MCP 工具到 Web UI LLM 引擎"""

    def __init__(self, executor):
        self.executor = executor
        self.registry = ToolRegistry()
        self._register_all_tools()
        logger.info(
            f"ToolBridge 初始化完成 — 捕获 {len(self.registry.tools)} 个工具"
        )

    # ------------------------------------------------------------------
    # 注册全部 MCP 工具 (与 mcp_server.py setup_mcp_server 保持一致)
    # ------------------------------------------------------------------
    def _register_all_tools(self):
        from kali_mcp.core.ai_context import AIContextManager
        from kali_mcp.core.ml_optimizer import MLStrategyOptimizer
        try:
            from kali_mcp.mcp_tools.v2_tools import register_v2_tools
            from kali_mcp.mcp_tools.v3_tools import register_v3_tools
            from kali_mcp.mcp_tools.vuln_db_tools import register_vulnerability_tools
        except Exception:
            register_v2_tools = None
            register_v3_tools = None
            register_vulnerability_tools = None

        from kali_mcp.mcp_tools import (
            register_recon_tools,
            register_ai_session_tools,
            register_code_audit_tools,
            register_misc_tools,
            register_apt_tools,
            register_ctf_tools,
            register_scan_workflow_tools,
            register_advanced_ctf_tools,
            register_session_tools,
            register_pwn_tools,
            register_adaptive_tools,
            register_deep_test_tools,
            register_vuln_mgmt_tools,
            register_chain_mgmt_tools,
            register_pentagi_bridge_tools,
            register_llm_react_tools,
            register_assessment_tools,
        )
        try:
            import deep_test_engine  # noqa: F401
            deep_test_available = True
        except Exception:
            deep_test_available = False

        reg = self.registry
        exe = self.executor

        # 共享状态 (轻量副本，与 mcp_server.py 全局变量对应)
        ai_ctx = AIContextManager()
        ml_opt = MLStrategyOptimizer()
        tasks: Dict[str, Any] = {}
        workflows: Dict[str, Any] = {}
        adaptive_attacks: Dict[str, Any] = {}
        attack_sessions: Dict[str, Any] = {}
        current_session_id = None
        ctf_mode_enabled = False
        ctf_sessions: Dict[str, Any] = {}
        current_ctf_session = None
        detected_flags: list = []
        ctf_challenges: Dict[str, Any] = {}
        multi_agent_state = {
            "agent_registry": None,
            "multi_agent_coordinator": None,
            "message_bus": None,
            "initialized": False,
        }

        # --- 逐个调用 register 函数，失败不影响其他模块 ---
        _calls = [
            ("recon",           lambda: register_recon_tools(reg, exe)),
            ("ai_session",      lambda: register_ai_session_tools(reg, exe, ai_ctx, ml_opt)),
            ("code_audit",      lambda: register_code_audit_tools(reg, exe)),
            ("misc",            lambda: register_misc_tools(reg, exe, tasks, workflows)),
            ("apt",             lambda: register_apt_tools(reg, exe, adaptive_attacks)),
            ("ctf",             lambda: register_ctf_tools(
                reg, exe, ctf_mode_enabled, ctf_sessions,
                current_ctf_session, detected_flags, ctf_challenges)),
            ("scan_workflow",   lambda: register_scan_workflow_tools(reg, exe)),
            ("advanced_ctf",    lambda: register_advanced_ctf_tools(reg, exe)),
            ("session",         lambda: register_session_tools(reg, exe, attack_sessions, current_session_id)),
            ("pwn",             lambda: register_pwn_tools(reg, exe)),
            ("adaptive",        lambda: register_adaptive_tools(reg, exe)),
            ("deep_test",       lambda: register_deep_test_tools(reg, exe, deep_test_available)),
            ("vuln_mgmt",       lambda: register_vuln_mgmt_tools(reg, exe)),
            ("chain_mgmt",      lambda: register_chain_mgmt_tools(reg, exe)),
            ("pentagi_bridge",  lambda: register_pentagi_bridge_tools(reg, exe)),
            ("llm_react",       lambda: register_llm_react_tools(reg, exe)),
            ("assessment",      lambda: register_assessment_tools(reg, exe)),
        ]
        if register_v3_tools:
            _calls.append(("v3_tools", lambda: register_v3_tools(reg)))
        if register_v2_tools:
            _calls.append(("v2_tools", lambda: register_v2_tools(reg, exe)))
        if register_vulnerability_tools:
            _calls.append(("vuln_db_tools", lambda: register_vulnerability_tools(reg)))

        for name, fn in _calls:
            try:
                fn()
                logger.debug(f"ToolBridge: {name} 注册成功")
            except Exception as e:
                logger.warning(f"ToolBridge: {name} 注册失败: {e}")

    # ------------------------------------------------------------------
    # 调用工具
    # ------------------------------------------------------------------
    async def call_tool(self, tool_name: str, params: dict) -> str:
        """调用 MCP 工具，返回输出文本"""
        func = self.registry.tools.get(tool_name)
        if not func:
            return f"[error] 未知工具: {tool_name}"
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(**params)
            else:
                result = await asyncio.to_thread(func, **params)
        except Exception as e:
            return f"[error] 工具 {tool_name} 执行失败: {e}"

        if isinstance(result, dict):
            return result.get("output", "") or json.dumps(
                result, ensure_ascii=False, default=str
            )
        return str(result)

    # ------------------------------------------------------------------
    # 生成工具目录 (嵌入 LLM system prompt)
    # ------------------------------------------------------------------
    def get_catalog_prompt(self) -> str:
        """生成按类别分组的工具目录文本"""
        categories = self._categorize_tools()
        lines = [
            f"## 可用 MCP 工具 (共 {len(self.registry.tools)} 个，"
            f'使用 action: "call_tool")\n',
        ]
        for cat_name, tools in categories.items():
            lines.append(f"### {cat_name}")
            for tname in sorted(tools):
                doc = self.registry.tool_docs.get(tname, "")
                short_doc = self._first_line(doc)
                sig = self._param_summary(tname)
                lines.append(f"- {tname}: {short_doc} | {sig}")
            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------
    @staticmethod
    def _first_line(doc: str) -> str:
        for line in doc.strip().splitlines():
            line = line.strip()
            if line:
                return line[:60]
        return "无描述"

    def _param_summary(self, tool_name: str) -> str:
        func = self.registry.tools.get(tool_name)
        if not func:
            return ""
        try:
            sig = inspect.signature(func)
        except (ValueError, TypeError):
            return ""
        parts = []
        for pname, param in sig.parameters.items():
            if param.default is inspect.Parameter.empty:
                parts.append(f"{pname}(必填)")
            else:
                parts.append(pname)
        return ", ".join(parts) if parts else "无参数"

    def _categorize_tools(self) -> Dict[str, list]:
        """按工具名前缀 / 关键词分组"""
        cats: Dict[str, list] = {
            "信息收集": [],
            "Web 应用测试": [],
            "密码攻击": [],
            "漏洞利用与 APT": [],
            "CTF 专用": [],
            "PWN 与逆向": [],
            "智能化工具 (推荐优先使用)": [],
            "会话与上下文管理": [],
            "系统与其他": [],
        }
        for name in self.registry.tools:
            cats[self._classify(name)].append(name)
        # 去掉空类别
        return {k: v for k, v in cats.items() if v}

    @staticmethod
    def _classify(name: str) -> str:
        n = name.lower()
        if any(k in n for k in (
            "nmap", "masscan", "arp_scan", "fping", "netdiscover",
            "subfinder", "amass", "sublist3r", "dnsrecon", "dnsenum",
            "fierce", "dnsmap", "theharvester", "whatweb", "httpx",
            "wafw00f", "sherlock", "recon", "tshark", "ngrep",
            "comprehensive_recon",
        )):
            return "信息收集"
        if any(k in n for k in (
            "gobuster", "dirb", "ffuf", "feroxbuster", "wfuzz",
            "nikto", "sqlmap", "nuclei", "wpscan", "joomscan",
            "web_app", "web_security", "xss", "sql_injection",
            "command_injection", "file_upload", "file_inclusion",
        )):
            return "Web 应用测试"
        if any(k in n for k in (
            "hydra", "john", "hashcat", "medusa", "ncrack",
            "patator", "crowbar", "brutespray", "aircrack",
            "reaver", "bully", "pixiewps", "crack", "brute",
        )):
            return "密码攻击"
        if any(k in n for k in (
            "metasploit", "searchsploit", "enum4linux", "responder",
            "ettercap", "bettercap", "apt_", "exploit", "privilege",
            "lateral",
        )):
            return "漏洞利用与 APT"
        if any(k in n for k in (
            "ctf", "flag", "challenge",
        )):
            return "CTF 专用"
        if any(k in n for k in (
            "pwn", "binwalk", "reverse", "radare2", "ghidra",
            "crypto",
        )):
            return "PWN 与逆向"
        if any(k in n for k in (
            "intelligent", "smart", "adaptive", "ai_",
            "auto_", "comprehensive_web", "comprehensive_network",
        )):
            return "智能化工具 (推荐优先使用)"
        if any(k in n for k in (
            "session", "context", "knowledge", "memory",
            "checkpoint", "pipeline", "chain", "fragment",
            "shared_context", "decision",
        )):
            return "会话与上下文管理"
        return "系统与其他"
