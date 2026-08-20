#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.


import sys
import os
import argparse
import logging

from mcp.server.transport_security import TransportSecuritySettings
import shlex
from typing import Dict, Any, Optional, List, Set, Tuple
import time
import json
import uuid
import random
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        # IMPORTANT: In MCP stdio transport, stdout is reserved for JSON-RPC messages.
        # All logs/banners must go to stderr, otherwise the client handshake will fail.
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# 深度智能化模式 - 启用连接池和结果缓存
OPTIMIZATION_ENABLED = True
logger.info("深度智能化模式 - 启用连接池优化和结果缓存")

# v2/v3/vuln_db 模块导入 (统一块)
try:
    from kali_mcp.mcp_tools.v2_tools import register_v2_tools, V2_TOOL_COUNT
    from kali_mcp.mcp_tools.v3_tools import register_v3_tools, V3_TOOL_COUNT
    from kali_mcp.mcp_tools.vuln_db_tools import register_vulnerability_tools, VULN_TOOL_COUNT
    V2_TOOLS_AVAILABLE = True
    V3_TOOLS_AVAILABLE = True
    VULN_DB_TOOLS_AVAILABLE = True
    logger.info(f" v2({V2_TOOL_COUNT})/v3({V3_TOOL_COUNT})/vuln_db({VULN_TOOL_COUNT}) 模块加载成功")
except ImportError as e:
    V2_TOOLS_AVAILABLE = False
    V3_TOOLS_AVAILABLE = False
    VULN_DB_TOOLS_AVAILABLE = False
    register_v2_tools = register_v3_tools = register_vulnerability_tools = None
    V2_TOOL_COUNT = V3_TOOL_COUNT = VULN_TOOL_COUNT = 0
    logger.warning(f" v2/v3/vuln_db 模块加载失败: {e}")

# 多智能体集群系统模块导入 (v4.0)
try:
    from kali_mcp.core.agent_registry import AgentRegistry
    from kali_mcp.core.agent_coordinator import CoordinatorAgent
    from kali_mcp.agents.information_gathering.recon_agent import ReconAgent
    from kali_mcp.agents.information_gathering.subdomain_agent import SubdomainAgent
    from kali_mcp.agents.information_gathering.web_recon_agent import WebReconAgent
    from kali_mcp.agents.vulnerability_discovery.vuln_scanner_agent import VulnScannerAgent
    from kali_mcp.agents.vulnerability_discovery.web_vuln_agent import WebVulnAgent
    from kali_mcp.agents.vulnerability_discovery.auth_agent import AuthAgent
    from kali_mcp.agents.vulnerability_discovery.network_vuln_agent import NetworkVulnAgent
    from kali_mcp.agents.vulnerability_discovery.vuln_verifier_agent import VulnVerifierAgent
    from kali_mcp.agents.exploitation.exploit_agent import ExploitAgent
    from kali_mcp.agents.exploitation.privilege_agent import PrivilegeAgent
    from kali_mcp.agents.exploitation.lateral_agent import LateralAgent
    from kali_mcp.agents.specialized.pwn_agent import PwnAgent
    from kali_mcp.agents.specialized.crypto_agent import CryptoAgent
    from kali_mcp.agents.specialized.forensics_agent import ForensicsAgent
    from kali_mcp.agents.specialized.code_audit_agent import CodeAuditAgent
    from kali_mcp.agents.specialized.source_code_agent import SourceCodeAgent
    from kali_mcp.agents.specialized.code_analyze_agent import CodeAnalyzeAgent
    MULTI_AGENT_SYSTEM_AVAILABLE = True
    logger.info(" 多智能体集群系统模块加载成功 - v4.0 架构")
except ImportError as e:
    MULTI_AGENT_SYSTEM_AVAILABLE = False
    logger.warning(f" 多智能体集群系统模块加载失败: {e}")


# 多智能体系统全局状态存储（用于MCP工具访问）
# 使用全局字典而不是闭包，确保FastMCP工具可以访问
MULTI_AGENT_STATE = {
    "agent_registry": None,
    "multi_agent_coordinator": None,
    "message_bus": None,
    "initialized": False
}


# 深度测试引擎导入 (v2.1 - Burp Suite级别交互能力)
try:
    from deep_test_engine import (
        DeepTestEngine,
        HTTPInteractionEngine,
        ResponseAnalyzer,
        DynamicFuzzer,
        ENGINES_AVAILABLE
    )
    DEEP_TEST_ENGINE_AVAILABLE = True
    logger.info(" 深度测试引擎加载成功 - HTTP/WS/gRPC交互能力已启用")
except ImportError as e:
    DEEP_TEST_ENGINE_AVAILABLE = False
    logger.warning(f" 深度测试引擎加载失败: {e}")

# 已删除伪智能化CTF引擎导入，现在使用真正的AI智能化MCP工具

# v6.0: 反检测浏览器引擎导入 (Playwright)
try:
    from kali_mcp.core.browser_engine import StealthBrowserEngine, HAS_PLAYWRIGHT
    BROWSER_ENGINE_AVAILABLE = HAS_PLAYWRIGHT
    if BROWSER_ENGINE_AVAILABLE:
        logger.info(" 反检测浏览器引擎加载成功 - Playwright 心跳维持已启用")
    else:
        logger.warning(" playwright 未安装, 浏览器引擎不可用. 运行: pip install playwright && playwright install chromium")
except ImportError as e:
    BROWSER_ENGINE_AVAILABLE = False
    logger.warning(f" 浏览器引擎模块加载失败: {e}")


# ==================== 从模块导入核心类 (v5.0 模块化) ====================

from kali_mcp.core.mcp_session import SessionContext, StrategyEngine
from kali_mcp.core.ai_context import AIContextManager
from kali_mcp.core.interaction import IntelligentInteractionManager
from kali_mcp.core.ml_optimizer import MLStrategyOptimizer
from kali_mcp.core.memory_persistence import AdvancedMemoryPersistence
from kali_mcp.core.local_executor import (
    LocalCommandExecutor, sanitize_shell_arg, ALLOWED_TOOLS, validate_tool_name,
    set_event_bus,
)
from kali_mcp.core.multi_target import TargetProfile, AttackTask, MultiTargetOrchestrator
from kali_mcp.core.context_analyzer import ContextPattern, AdvancedContextAnalyzer
from kali_mcp.core.knowledge_graph import KnowledgeNode, KnowledgeRelation, AttackKnowledgeGraph
from kali_mcp.core.adaptive_exec_engine import ExecutionContext, AdaptiveExecutionEngine

# 全局ML策略优化器实例
ml_strategy_optimizer = MLStrategyOptimizer()

# 全局攻击会话存储
_ATTACK_SESSIONS = {}
_CURRENT_ATTACK_SESSION_ID = None

# 全局任务和工作流存储
_TASKS = {}
_WORKFLOWS = {}

# 全局自适应攻击存储
_ADAPTIVE_ATTACKS = {}

# 全局CTF模式状态
_CTF_MODE_ENABLED = False
_CTF_SESSIONS = {}
_CURRENT_CTF_SESSION = None
_DETECTED_FLAGS = []
_CTF_CHALLENGES = {}

# 全局AI上下文管理器实例
ai_context_manager = AIContextManager()

# Default configuration
DEFAULT_KALI_SERVER = os.environ.get("KALI_MCP_SERVER", "")  # 可选的旧式 API server 地址（本地执行模式不需要）
DEFAULT_REQUEST_TIMEOUT = 10  # 10 seconds ultra fast timeout for API requests

# ==================== MCP工具注册模块导入 (v5.0 模块化) ====================

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
    register_kali_extended_tools,
)

# v6.0: 浏览器自动化工具
try:
    from kali_mcp.mcp_tools.browser_tools import register_browser_tools
    _BROWSER_TOOLS_IMPORT_OK = True
except ImportError:
    _BROWSER_TOOLS_IMPORT_OK = False
    register_browser_tools = None

from kali_mcp.security import load_tool_profile, engagement_manager

def setup_mcp_server(
    profile_name: str = None,
    force_enable_modules: List[str] = None,
    force_disable_modules: List[str] = None,
) -> FastMCP:
    """
    Set up the MCP server with all tool functions.

    v5.0 模块化架构: 工具按类别分散到 kali_mcp/mcp_tools/ 模块中,
    通过 register_xxx_tools() 函数注册到 FastMCP 实例。

    Returns:
        Configured FastMCP instance
    """
    # 创建全局本地命令执行器
    global executor
    executor = LocalCommandExecutor(timeout=300)
    logger.info("本地命令执行器已初始化")

    # ==================== v5.1: 统一事件总线初始化 ====================
    event_bus = None
    try:
        from kali_mcp.core.event_bus import (
            EventBus,
            KnowledgeGraphSubscriber,
            VulnManagerSubscriber,
            MLOptimizerSubscriber,
            DecisionBrainSubscriber,
            DiggerSubscriber,
        )
        event_bus = EventBus()

        # 连接知识图谱订阅者
        try:
            kg = AttackKnowledgeGraph()
            KnowledgeGraphSubscriber(kg).register(event_bus)
            logger.info("   知识图谱  事件总线")
        except Exception as e:
            logger.debug(f"  知识图谱订阅跳过: {e}")

        # 连接漏洞管理器订阅者
        try:
            from kali_mcp.core.vuln_manager import VulnManager
            vm = VulnManager()
            VulnManagerSubscriber(vm).register(event_bus)
            logger.info("   漏洞管理器  事件总线")
        except Exception as e:
            logger.debug(f"  漏洞管理器订阅跳过: {e}")

        # 连接ML优化器订阅者
        try:
            MLOptimizerSubscriber(ml_strategy_optimizer).register(event_bus)
            logger.info("   ML优化器  事件总线")
        except Exception as e:
            logger.debug(f"  ML优化器订阅跳过: {e}")

        # 连接决策引擎订阅者
        try:
            from kali_mcp.core.decision_brain import DecisionBrain
            db = DecisionBrain(
                ml_optimizer=ml_strategy_optimizer,
                vuln_manager=vm if 'vm' in dir() else None,
            )
            DecisionBrainSubscriber(db).register(event_bus)
            logger.info("   决策引擎  事件总线")
        except Exception as e:
            logger.debug(f"  决策引擎订阅跳过: {e}")

        # v5.2: 连接Digger事件订阅者
        try:
            DiggerSubscriber(
                ml_optimizer=ml_strategy_optimizer,
                vuln_manager=VulnManager() if 'VulnManager' in dir() else None,
            ).register(event_bus)
            logger.info("   Digger事件  事件总线")
        except Exception as e:
            logger.debug(f"  Digger订阅跳过: {e}")

        # 注入事件总线到执行器
        set_event_bus(event_bus)
        logger.info(" 统一事件总线初始化完成")
    except ImportError as e:
        logger.warning(f" 事件总线模块加载失败: {e}")
    except Exception as e:
        logger.warning(f" 事件总线初始化失败: {e}")

    # 声明使用全局的多智能体系统标志
    global MULTI_AGENT_SYSTEM_AVAILABLE

    mcp = FastMCP(
        "kali-mcp",
        instructions="""Kali 安全测试 MCP 服务端 - 使用规则：

1. 工具调用优先
   安全测试动作优先调用本服务的 MCP 工具（而非客户端自行跑 bash）：参数安全清理、
   超时控制、结构化输出解析在这里统一生效。

2. 工具选择指南（全部为实际注册的工具名）
   - 端口/服务扫描    nmap_scan、masscan_fast_scan
   - 子域/资产        subfinder_scan、amass_scan、theharvester_osint、fierce_scan
   - 存活/指纹        httpx_probe、whatweb_scan、wafw00f_scan
   - 目录/路径枚举    ffuf_scan、gobuster_scan、dirsearch_scan、feroxbuster_scan、dirb_scan
   - 漏洞验证         nuclei_scan / nuclei_cve_scan / nuclei_web_scan（命中须复核）、
                      sqlmap_scan（注入点来自参数枚举，不盲扫）、nosqlmap_scan
   - Web 漏洞利用     dalfox_scan、commix_scan、xsstrike_scan、nikto_scan、wpscan_scan
   - 内网横向         crackmapexec_scan（netexec）、evil_winrm_connect、
                      impacket_psexec / impacket_wmiexec / impacket_smbexec /
                      impacket_secretsdump / impacket_ntlmrelayx / impacket_getnpusers
   - 枚举查询         smbclient_list_shares、rpcclient_query、snmpcheck_scan、
                      onesixtyone_scan、enum4linux_scan
   - 凭据/哈希        hydra_attack、medusa_attack、ncrack_attack、john_crack、hashcat_crack
   - 横向基础设施     chisel_tunnel、socat_relay、proxychains_run、responder_attack
   - 域信息收集       bloodhound_collect
   - 二进制/取证      radare2_analyze_binary、binwalk_analysis、volatility_analyze、
                      searchsploit_search
   - 无线审计         aircrack_attack、wifite_attack、bettercap_attack、ettercap_attack
   - 漏洞情报/OSINT   sherlock_search、traceroute_scan

3. 输出与超时
   超长输出智能截断（保留头尾并置 output_truncated 标记）；每个工具有独立超时。
   全端口/全模板等长扫描请在客户端调大单次调用超时后再发起。

4. 边界
   被包装的是本机已装工具：未装的工具会如实返回 success=false 与原因，由客户端按其
   通道降级策略处理；所有流量的授权范围由调用方约束。"""

    )
    tool_profile = load_tool_profile(
        profile_name=profile_name,
        force_enable=force_enable_modules or [],
        force_disable=force_disable_modules or [],
    )
    engagement_manager.set_profile(tool_profile.name)
    logger.info(f" 工具档位: {tool_profile.summary()}")

    def _module_enabled(module_key: str) -> bool:
        enabled = tool_profile.allows(module_key)
        if not enabled:
            logger.info(f"  ⏭ 跳过模块[{module_key}]，由工具档位策略禁用")
        return enabled

    # ==================== 多智能体集群系统初始化 (v4.0) ====================
    global MULTI_AGENT_STATE

    multi_agent_coordinator = None
    agent_registry = None

    logger.info(f"[DEBUG] 开始多智能体系统初始化, MULTI_AGENT_SYSTEM_AVAILABLE={MULTI_AGENT_SYSTEM_AVAILABLE}")

    should_init_multi_agent = MULTI_AGENT_SYSTEM_AVAILABLE and _module_enabled("multi_agent")
    if should_init_multi_agent:
        try:
            from kali_mcp.core.mesh_message_bus import MeshMessageBus

            message_bus = MeshMessageBus()
            logger.info(" 网状消息总线初始化成功")

            agent_registry = AgentRegistry()
            logger.info(" Agent注册表初始化成功")

            agent_classes = [
                (ReconAgent, "侦察智能体"),
                (SubdomainAgent, "子域名智能体"),
                (WebReconAgent, "Web侦察智能体"),
                (VulnScannerAgent, "漏洞扫描智能体"),
                (WebVulnAgent, "Web漏洞智能体"),
                (AuthAgent, "认证攻击智能体"),
                (NetworkVulnAgent, "网络漏洞智能体"),
                (VulnVerifierAgent, "漏洞验证智能体"),
                (ExploitAgent, "漏洞利用智能体"),
                (PrivilegeAgent, "权限提升智能体"),
                (LateralAgent, "横向移动智能体"),
                (PwnAgent, "二进制利用智能体"),
                (CryptoAgent, "密码学智能体"),
                (ForensicsAgent, "取证智能体"),
                (CodeAuditAgent, "代码审计智能体"),
                (SourceCodeAgent, "源码获取智能体"),
                (CodeAnalyzeAgent, "代码分析智能体"),
            ]

            agents = []
            for agent_class, desc in agent_classes:
                agent = agent_class(message_bus=message_bus, tool_registry=agent_registry, executor=executor)
                agents.append(agent)
                agent_registry.register_agent(agent)
                logger.info(f" {desc} ({agent.agent_id}) 初始化成功")

            multi_agent_coordinator = CoordinatorAgent(agent_registry=agent_registry)
            logger.info(f" 中心调控智能体初始化成功")
            logger.info(f" 多智能体集群系统v4.0启动完成 - {len(agents)}个专业智能体就绪")

            MULTI_AGENT_STATE["agent_registry"] = agent_registry
            MULTI_AGENT_STATE["multi_agent_coordinator"] = multi_agent_coordinator
            MULTI_AGENT_STATE["message_bus"] = message_bus
            MULTI_AGENT_STATE["initialized"] = True

        except Exception as e:
            logger.warning(f" 多智能体系统初始化失败: {e}")
            import traceback
            logger.warning(f"[DEBUG] Traceback: {traceback.format_exc()}")
            MULTI_AGENT_SYSTEM_AVAILABLE = False
    else:
        logger.warning(
            f"[DEBUG] 跳过初始化: MULTI_AGENT_SYSTEM_AVAILABLE={MULTI_AGENT_SYSTEM_AVAILABLE}, "
            f"multi_agent_enabled={tool_profile.allows('multi_agent')}"
        )

    # ==================== 代理适配器初始化 (v5.0 架构激活) ====================
    agent_adapter = None
    if MULTI_AGENT_STATE.get("initialized"):
        try:
            from kali_mcp.core.agent_adapter import AgentAdapter
            agent_adapter = AgentAdapter(
                executor=executor,
                coordinator_agent=MULTI_AGENT_STATE.get("multi_agent_coordinator"),
                agent_registry=MULTI_AGENT_STATE.get("agent_registry")
            )
            logger.info(" 代理适配器初始化成功 - 复杂工具将通过多智能体协作执行")
        except Exception as e:
            logger.warning(f" 代理适配器初始化失败: {e}")

    # ==================== Kali MCP v3.0 深度挖掘器注册 ====================
    if V3_TOOLS_AVAILABLE and _module_enabled("v3"):
        try:
            register_v3_tools(mcp)
            logger.info(f" Kali MCP v3.0 深度挖掘器注册成功 - {V3_TOOL_COUNT} 个挖掘器")
        except Exception as e:
            logger.warning(f" Kali MCP v3.0 深度挖掘器注册失败: {e}")

    # ==================== 按类别注册MCP工具 (v5.0 模块化) ====================
    logger.info(" 开始注册MCP工具模块...")

    def _safe_register(module_key: str, label: str, fn, *fn_args):
        if not _module_enabled(module_key):
            return
        try:
            fn(*fn_args)
            logger.info(f"   {label}注册完成")
        except Exception as e:
            logger.warning(f"   {label}注册失败: {e}")

    _safe_register("assessment", "授权评估工具", register_assessment_tools, mcp, executor, agent_adapter)
    _safe_register("recon", "信息收集工具", register_recon_tools, mcp, executor)
    _safe_register("ai_session", "AI会话工具", register_ai_session_tools, mcp, executor, ai_context_manager, ml_strategy_optimizer)
    _safe_register("code_audit", "代码审计工具", register_code_audit_tools, mcp, executor)
    _safe_register("misc", "杂项工具", register_misc_tools, mcp, executor, _TASKS, _WORKFLOWS)
    _safe_register("apt", "APT攻击链工具", register_apt_tools, mcp, executor, _ADAPTIVE_ATTACKS, agent_adapter)
    _safe_register(
        "ctf",
        "CTF工具",
        register_ctf_tools,
        mcp,
        executor,
        _CTF_MODE_ENABLED,
        _CTF_SESSIONS,
        _CURRENT_CTF_SESSION,
        _DETECTED_FLAGS,
        _CTF_CHALLENGES,
    )
    _safe_register("scan_workflow", "扫描工作流工具", register_scan_workflow_tools, mcp, executor, agent_adapter)
    _safe_register("advanced_ctf", "增强CTF工具", register_advanced_ctf_tools, mcp, executor, agent_adapter)
    _safe_register("session", "会话管理工具", register_session_tools, mcp, executor, _ATTACK_SESSIONS, _CURRENT_ATTACK_SESSION_ID)
    _safe_register("pwn", "PWN工具", register_pwn_tools, mcp, executor, agent_adapter)
    _safe_register("adaptive", "自适应执行工具", register_adaptive_tools, mcp, executor)
    _safe_register("vuln_mgmt", "漏洞管理工具", register_vuln_mgmt_tools, mcp, executor)
    _safe_register("chain_mgmt", "攻击链管理工具", register_chain_mgmt_tools, mcp, executor)
    _safe_register("pentagi_bridge", "Pentagi扩展工具", register_pentagi_bridge_tools, mcp, executor)
    _safe_register("llm_react", "LLM ReAct工具", register_llm_react_tools, mcp, executor)
    _safe_register("kali_extended", "Kali扩展工具", register_kali_extended_tools, mcp, executor)

    # ==================== 外部工具模块注册 ====================
    if V2_TOOLS_AVAILABLE and _module_enabled("v2"):
        try:
            register_v2_tools(mcp, executor)
            logger.info("   Kali MCP v2.0 工具注册成功")
        except Exception as e:
            logger.warning(f"   Kali MCP v2.0 工具注册失败: {e}")

    if VULN_DB_TOOLS_AVAILABLE and _module_enabled("vuln_db"):
        try:
            register_vulnerability_tools(mcp)
            logger.info("   漏洞数据库工具注册成功")
        except Exception as e:
            logger.warning(f"   漏洞数据库工具注册失败: {e}")

    _safe_register("deep_test", "深度测试引擎工具", register_deep_test_tools, mcp, executor, DEEP_TEST_ENGINE_AVAILABLE)

    # v6.0: 反检测浏览器引擎工具
    if _BROWSER_TOOLS_IMPORT_OK and register_browser_tools is not None:
        _safe_register("browser", "反检测浏览器引擎工具", register_browser_tools, mcp, executor, BROWSER_ENGINE_AVAILABLE)

    logger.info(" 所有MCP工具模块注册完成")

    return mcp

# ==================== 全局实例 ====================

# 全局自适应执行引擎实例
adaptive_execution_engine = AdaptiveExecutionEngine()

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Server")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER,
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-websocket", action="store_true", help="Disable WebSocket connections, use HTTP only")

    # 传输模式配置
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse", "streamable-http"],
                      help="Transport mode: stdio (default), sse (legacy remote), or streamable-http (recommended remote)")
    parser.add_argument("--allowed-host", action="append", default=[],
                      help="额外放行的 Host 头地址（内网远程访问时传宿主可达的本机地址，可多次）")
    parser.add_argument("--disable-dns-protection", action="store_true",
                      help="关闭 DNS 重绑定保护（仅建议隔离网络使用）")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                      help="SSE server host (default: 127.0.0.1, only used with --transport=sse)")
    parser.add_argument("--port", type=int, default=8765,
                      help="SSE server port (default: 8765, only used with --transport=sse)")
    parser.add_argument(
        "--tool-profile",
        type=str,
        choices=["strict", "compliance", "full"],
        default=os.environ.get("KALI_MCP_TOOL_PROFILE", "compliance"),
        help="Tool registration profile (default: compliance)",
    )
    parser.add_argument(
        "--enable-module",
        action="append",
        default=[],
        help="Force-enable module key (repeatable), e.g. --enable-module pwn",
    )
    parser.add_argument(
        "--disable-module",
        action="append",
        default=[],
        help="Force-disable module key (repeatable), e.g. --disable-module apt",
    )

    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""

    # 解析命令行参数
    args = parse_args()

    # 根据传输模式显示不同的横幅
    if args.transport == "sse":
        banner = f"""

                      Kali MCP 智能安全测试系统                          
                    Intelligent Security Testing Framework              

                                                                         
   运行模式: SSE 远程访问模式 (REMOTE ACCESS MODE)                     
                                                                         
   HTTP服务: 监听 http://{args.host}:{args.port}                       
   远程连接: 外部AI可通过SSE协议连接                                   
   MCP工具: 运行时按模块动态注册                                      
                                                                         

  连接方式:                                                              
  - SSE端点: http://{args.host}:{args.port}/sse                          
  - 消息端点: http://{args.host}:{args.port}/messages                    

        """.strip()
    else:
        banner = f"""

                      Kali MCP 智能安全测试系统                          
                    Intelligent Security Testing Framework              

                                                                         
   运行模式: 本地执行模式 (LOCAL EXECUTION MODE)                       
                                                                         
   直接执行: 通过subprocess调用本地安全工具                            
   无需后端: 不需要启动kali_server.py                                 
   无需配置: 不需要KALI_API_URL环境变量                                
   MCP工具: 运行时按模块动态注册                                      
                                                                         

  系统信息:                                                              
  - 传输模式: stdio (Claude Desktop/Code 本地连接)                       
  - 工作目录: {os.getcwd()[:50]}                                         
  - Python版本: {sys.version.split()[0]}                                 

        """.strip()

    # IMPORTANT: In MCP stdio transport, stdout is reserved for JSON-RPC messages.
    # Always print the banner to stderr to avoid breaking the handshake.
    print(banner, file=sys.stderr)
    logger.info("=" * 80)
    logger.info(" 启动 Kali MCP 服务器...")
    logger.info(f" 传输模式: {args.transport.upper()}")
    logger.info(f" 工具档位: {args.tool_profile}")
    if args.transport == "sse":
        logger.info(f" 监听地址: http://{args.host}:{args.port}")
    logger.info("=" * 80)

    try:
        # Set up and run the MCP server
        mcp = setup_mcp_server(
            profile_name=args.tool_profile,
            force_enable_modules=args.enable_module,
            force_disable_modules=args.disable_module,
        )
        logger.info(" MCP服务器初始化完成")
        tool_count = len(getattr(getattr(mcp, "_tool_manager", None), "_tools", {}))
        if tool_count > 0:
            logger.info(f" {tool_count} 个安全工具已就绪")
        else:
            logger.info(" 安全工具已就绪")
        logger.info(" 服务器启动中...")

        # 根据传输模式启动（host/port 经 settings 传入，兼容当前 mcp SDK 的 run() 签名）
        if args.transport in ("sse", "streamable-http"):
            mcp.settings.host = args.host
            mcp.settings.port = args.port
            # SDK 默认 DNS 重绑定保护只放行 localhost；内网远程访问须显式放行目标地址
            hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"] + [f"{h}:*" for h in args.allowed_host]
            origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
            mcp.settings.transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=not args.disable_dns_protection,
                allowed_hosts=hosts,
                allowed_origins=origins,
            )
            endpoint = "/sse" if args.transport == "sse" else "/mcp"
            logger.info(f" {args.transport} 服务器启动于 http://{args.host}:{args.port}")
            logger.info(f" 外部AI连接地址: http://<your-ip>:{args.port}{endpoint}")
            mcp.run(transport=args.transport)
        else:
            logger.info(" stdio模式: 等待Claude Desktop/Code连接...")
            mcp.run()

    except KeyboardInterrupt:
        logger.info("\n 收到停止信号，正在关闭服务器...")
    except Exception as e:
        logger.error(f" 服务器错误: {str(e)}")
        raise
    finally:
        logger.info(" MCP服务器已安全关闭")

if __name__ == "__main__":
    main()
