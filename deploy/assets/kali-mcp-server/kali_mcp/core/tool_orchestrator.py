#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能工具编排系统 - Intelligent Tool Orchestrator

核心功能:
1. 结果驱动编排 - 根据上一个工具的结果自动选择下一个工具
2. 攻击链自动构建 - 识别攻击路径并自动串联工具
3. 失败自动重试 - 使用备选工具和参数
4. 深度优先策略 - 发现漏洞后深入挖掘

设计目标:
- 最大化工具利用率
- 最大化漏洞发现率
- 自动化攻击链构建
"""

import asyncio
import json
import re
import time
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


class ToolCategory(Enum):
    """工具类别"""
    RECON = "reconnaissance"
    DISCOVERY = "discovery"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    PASSWORD = "password_attack"
    PRIVILEGE = "privilege_escalation"
    LATERAL = "lateral_movement"


class TriggerCondition(Enum):
    """触发条件"""
    PORT_OPEN = "port_open"
    SERVICE_DETECTED = "service_detected"
    VULN_FOUND = "vulnerability_found"
    CMS_DETECTED = "cms_detected"
    WAF_DETECTED = "waf_detected"
    AUTH_REQUIRED = "auth_required"
    INJECTION_POSSIBLE = "injection_possible"
    FILE_UPLOAD = "file_upload_found"
    ADMIN_PANEL = "admin_panel_found"
    DEFAULT_CREDS = "default_creds_possible"
    CVE_IDENTIFIED = "cve_identified"
    SUBDOMAIN_FOUND = "subdomain_found"


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_name: str
    success: bool
    output: str
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    triggered_conditions: List[TriggerCondition] = field(default_factory=list)
    next_tools: List[str] = field(default_factory=list)
    execution_time: float = 0.0


@dataclass
class AttackChain:
    """攻击链"""
    name: str
    description: str
    tools: List[str]
    current_step: int = 0
    success: bool = False
    findings: List[Dict] = field(default_factory=list)


class ToolOrchestrator:
    """
    智能工具编排器

    根据工具输出自动决定下一步操作
    """

    # 结果触发规则 - 根据输出自动触发后续工具
    RESULT_TRIGGERS = {
        # 端口发现触发
        "port_80_open": {
            "pattern": r"80/tcp\s+open|:80\s+open",
            "condition": TriggerCondition.PORT_OPEN,
            "triggers": ["whatweb_scan", "gobuster_scan", "nikto_scan", "nuclei_web_scan"],
            "priority": 1,
        },
        "port_443_open": {
            "pattern": r"443/tcp\s+open|:443\s+open",
            "condition": TriggerCondition.PORT_OPEN,
            "triggers": ["whatweb_scan", "gobuster_scan", "nikto_scan", "nuclei_scan"],
            "priority": 1,
        },
        "port_22_open": {
            "pattern": r"22/tcp\s+open",
            "condition": TriggerCondition.PORT_OPEN,
            "triggers": ["hydra_attack", "searchsploit_search"],
            "priority": 2,
        },
        "port_21_open": {
            "pattern": r"21/tcp\s+open",
            "condition": TriggerCondition.PORT_OPEN,
            "triggers": ["hydra_attack", "nmap_scan"],  # FTP scripts
            "priority": 2,
        },
        "port_445_open": {
            "pattern": r"445/tcp\s+open",
            "condition": TriggerCondition.PORT_OPEN,
            "triggers": ["enum4linux_scan", "nmap_scan"],  # SMB scripts
            "priority": 1,
        },
        "port_3306_open": {
            "pattern": r"3306/tcp\s+open",
            "condition": TriggerCondition.PORT_OPEN,
            "triggers": ["hydra_attack", "nmap_scan"],  # MySQL scripts
            "priority": 2,
        },
        "port_1433_open": {
            "pattern": r"1433/tcp\s+open",
            "condition": TriggerCondition.PORT_OPEN,
            "triggers": ["hydra_attack", "nmap_scan"],  # MSSQL scripts
            "priority": 2,
        },

        # CMS检测触发
        "wordpress_detected": {
            "pattern": r"wordpress|wp-content|wp-admin|wp-includes",
            "condition": TriggerCondition.CMS_DETECTED,
            "triggers": ["wpscan_scan", "nuclei_scan"],
            "priority": 1,
        },
        "joomla_detected": {
            "pattern": r"joomla|/administrator",
            "condition": TriggerCondition.CMS_DETECTED,
            "triggers": ["joomscan_scan", "nuclei_scan"],
            "priority": 1,
        },
        "drupal_detected": {
            "pattern": r"drupal",
            "condition": TriggerCondition.CMS_DETECTED,
            "triggers": ["nuclei_scan"],
            "priority": 1,
        },

        # WAF检测触发
        "waf_detected": {
            "pattern": r"cloudflare|akamai|imperva|waf|firewall|blocked|forbidden",
            "condition": TriggerCondition.WAF_DETECTED,
            "triggers": ["generate_waf_bypass_payload", "wafw00f_scan"],
            "priority": 1,
        },

        # 漏洞发现触发
        "sql_injection_possible": {
            "pattern": r"sql\s*injection|sqli|error.*sql|mysql.*error|syntax.*error.*sql",
            "condition": TriggerCondition.INJECTION_POSSIBLE,
            "triggers": ["sqlmap_scan", "intelligent_sql_injection_payloads"],
            "priority": 1,
        },
        "xss_possible": {
            "pattern": r"xss|cross.?site.?script|reflected|<script>",
            "condition": TriggerCondition.INJECTION_POSSIBLE,
            "triggers": ["intelligent_xss_payloads"],
            "priority": 1,
        },
        "command_injection_possible": {
            "pattern": r"command\s*injection|rce|remote.*code.*execution|os\s*command",
            "condition": TriggerCondition.INJECTION_POSSIBLE,
            "triggers": ["intelligent_command_injection_payloads"],
            "priority": 1,
        },
        "lfi_possible": {
            "pattern": r"local\s*file\s*inclusion|lfi|path\s*traversal|\.\.\/",
            "condition": TriggerCondition.INJECTION_POSSIBLE,
            "triggers": ["nuclei_scan", "ffuf_scan"],
            "priority": 1,
        },

        # 目录发现触发
        "admin_panel_found": {
            "pattern": r"/admin|/administrator|/manage|/dashboard|/panel|/login",
            "condition": TriggerCondition.ADMIN_PANEL,
            "triggers": ["hydra_attack", "nuclei_scan", "intelligent_sql_injection_payloads"],
            "priority": 1,
        },
        "upload_found": {
            "pattern": r"/upload|file.*upload|multipart",
            "condition": TriggerCondition.FILE_UPLOAD,
            "triggers": ["nuclei_scan", "ffuf_scan"],
            "priority": 1,
        },
        "api_found": {
            "pattern": r"/api/|/v1/|/v2/|rest|graphql",
            "condition": TriggerCondition.SERVICE_DETECTED,
            "triggers": ["ffuf_scan", "nuclei_scan", "sqlmap_scan"],
            "priority": 1,
        },

        # CVE发现触发
        "cve_found": {
            "pattern": r"CVE-\d{4}-\d+",
            "condition": TriggerCondition.CVE_IDENTIFIED,
            "triggers": ["searchsploit_search", "metasploit_run"],
            "priority": 1,
        },

        # 认证相关触发
        "login_form_found": {
            "pattern": r"<form.*login|<input.*password|authentication",
            "condition": TriggerCondition.AUTH_REQUIRED,
            "triggers": ["hydra_attack", "intelligent_sql_injection_payloads"],
            "priority": 2,
        },

        # 子域名发现触发
        "subdomain_found": {
            "pattern": r"subdomain|\..*\.[a-z]+",
            "condition": TriggerCondition.SUBDOMAIN_FOUND,
            "triggers": ["httpx_probe", "nuclei_scan"],
            "priority": 2,
        },
    }

    # 工具链定义 - 预定义的攻击工具链
    ATTACK_CHAINS = {
        "web_full_assessment": AttackChain(
            name="Web完整评估",
            description="Web应用完整安全评估工具链",
            tools=[
                "whatweb_scan",       # 技术识别
                "wafw00f_scan",       # WAF检测
                "gobuster_scan",      # 目录扫描
                "ffuf_scan",          # 参数模糊
                "nuclei_web_scan",    # 漏洞扫描
                "nikto_scan",         # Web服务器扫描
                "sqlmap_scan",        # SQL注入
                "intelligent_xss_payloads",  # XSS测试
            ],
        ),
        "network_penetration": AttackChain(
            name="网络渗透",
            description="网络渗透测试工具链",
            tools=[
                "nmap_scan",          # 端口扫描
                "masscan_fast_scan",  # 快速扫描
                "nuclei_network_scan", # 网络漏洞
                "enum4linux_scan",    # SMB枚举
                "hydra_attack",       # 密码攻击
                "searchsploit_search", # 漏洞搜索
            ],
        ),
        "ctf_web_chain": AttackChain(
            name="CTF Web攻击链",
            description="CTF Web题目专用工具链",
            tools=[
                "whatweb_scan",
                "gobuster_scan",
                "ffuf_scan",
                "nuclei_scan",
                "sqlmap_scan",
                "intelligent_sql_injection_payloads",
                "intelligent_xss_payloads",
                "intelligent_command_injection_payloads",
                "ctf_web_comprehensive_solver",
            ],
        ),
        "sql_injection_deep": AttackChain(
            name="SQL注入深度利用",
            description="SQL注入漏洞深度利用链",
            tools=[
                "sqlmap_scan",        # 基础检测
                "intelligent_sql_injection_payloads",  # 智能Payload
                "sqlmap_scan",        # 深度利用 (--level=5 --risk=3)
            ],
        ),
        "authentication_attack": AttackChain(
            name="认证攻击",
            description="认证系统攻击工具链",
            tools=[
                "hydra_attack",       # 密码爆破
                "medusa_bruteforce",  # 备选爆破
                "intelligent_sql_injection_payloads",  # 认证绕过
                "nuclei_scan",        # 认证漏洞
            ],
        ),
    }

    # 工具备选方案 - 当工具失败时的替代
    FALLBACK_TOOLS = {
        "gobuster_scan": ["ffuf_scan", "feroxbuster_scan", "dirb_scan"],
        "ffuf_scan": ["gobuster_scan", "wfuzz_scan", "feroxbuster_scan"],
        "hydra_attack": ["medusa_bruteforce", "ncrack_attack", "patator_attack"],
        "nuclei_scan": ["nuclei_web_scan", "nikto_scan"],
        "sqlmap_scan": ["intelligent_sql_injection_payloads"],
        "nmap_scan": ["masscan_fast_scan"],
    }

    # 工具参数升级 - 失败后使用更激进的参数
    AGGRESSIVE_PARAMS = {
        "sqlmap_scan": {
            "level_1": {"additional_args": "--level=1 --risk=1"},
            "level_2": {"additional_args": "--level=3 --risk=2"},
            "level_3": {"additional_args": "--level=5 --risk=3 --batch"},
        },
        "gobuster_scan": {
            "level_1": {"wordlist": "/usr/share/wordlists/dirb/common.txt"},
            "level_2": {"wordlist": "/usr/share/wordlists/dirb/big.txt"},
            "level_3": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"},
        },
        "nuclei_scan": {
            "level_1": {"severity": "critical,high"},
            "level_2": {"severity": "critical,high,medium"},
            "level_3": {"severity": "critical,high,medium,low"},
        },
        "hydra_attack": {
            "level_1": {"password_file": "/usr/share/wordlists/rockyou.txt", "additional_args": "-t 4"},
            "level_2": {"password_file": "/usr/share/wordlists/rockyou.txt", "additional_args": "-t 16"},
            "level_3": {"password_file": "/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt"},
        },
    }

    def __init__(self, mcp_tools: Dict[str, Callable] = None):
        """初始化编排器"""
        self.mcp_tools = mcp_tools or {}
        self.execution_history: List[ToolResult] = []
        self.triggered_conditions: Set[TriggerCondition] = set()
        self.discovered_data: Dict[str, Any] = defaultdict(list)
        self.tools_executed: Set[str] = set()
        self.current_chain: Optional[AttackChain] = None

    def analyze_output(self, tool_name: str, output: str) -> ToolResult:
        """
        分析工具输出，识别触发条件

        根据输出自动决定下一步工具
        """
        result = ToolResult(
            tool_name=tool_name,
            success=True,
            output=output,
        )

        output_lower = output.lower()

        # 匹配所有触发规则
        for trigger_name, trigger_config in self.RESULT_TRIGGERS.items():
            pattern = trigger_config["pattern"]

            if re.search(pattern, output_lower, re.IGNORECASE):
                condition = trigger_config["condition"]
                result.triggered_conditions.append(condition)
                self.triggered_conditions.add(condition)

                # 添加触发的工具（去重）
                for tool in trigger_config["triggers"]:
                    if tool not in self.tools_executed and tool not in result.next_tools:
                        result.next_tools.append(tool)

                # 提取相关数据
                self._extract_data(trigger_name, pattern, output, result)

        # 按优先级排序下一步工具
        result.next_tools = self._prioritize_tools(result.next_tools)

        return result

    def _extract_data(self, trigger_name: str, pattern: str, output: str,
                     result: ToolResult):
        """从输出中提取有用数据"""

        # 提取端口
        if "port" in trigger_name:
            ports = re.findall(r'(\d+)/tcp\s+open', output)
            result.extracted_data["open_ports"] = [int(p) for p in ports]
            self.discovered_data["open_ports"].extend(result.extracted_data["open_ports"])

        # 提取URL路径
        if "found" in trigger_name or "admin" in trigger_name:
            paths = re.findall(r'(/[a-zA-Z0-9_\-/]+)', output)
            result.extracted_data["paths"] = paths
            self.discovered_data["paths"].extend(paths)

        # 提取CVE
        if "cve" in trigger_name:
            cves = re.findall(r'CVE-\d{4}-\d+', output)
            result.extracted_data["cves"] = cves
            self.discovered_data["cves"].extend(cves)

        # 提取子域名
        if "subdomain" in trigger_name:
            domains = re.findall(r'([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+)', output)
            result.extracted_data["subdomains"] = domains
            self.discovered_data["subdomains"].extend(domains)

    def _prioritize_tools(self, tools: List[str]) -> List[str]:
        """按优先级排序工具"""
        # 高优先级工具
        high_priority = ["sqlmap_scan", "intelligent_sql_injection_payloads",
                        "nuclei_scan", "wpscan_scan", "searchsploit_search"]

        # 中优先级工具
        medium_priority = ["gobuster_scan", "ffuf_scan", "nikto_scan",
                          "hydra_attack", "intelligent_xss_payloads"]

        sorted_tools = []

        # 先添加高优先级
        for tool in high_priority:
            if tool in tools:
                sorted_tools.append(tool)
                tools.remove(tool)

        # 再添加中优先级
        for tool in medium_priority:
            if tool in tools:
                sorted_tools.append(tool)
                tools.remove(tool)

        # 添加剩余工具
        sorted_tools.extend(tools)

        return sorted_tools

    async def execute_with_orchestration(self, start_tool: str, target: str,
                                         max_depth: int = 10,
                                         max_tools: int = 50) -> Dict[str, Any]:
        """
        使用编排执行工具

        从起始工具开始，根据结果自动触发后续工具
        """
        print(f"[*] 智能编排启动")
        print(f"[*] 起始工具: {start_tool}")
        print(f"[*] 目标: {target}")

        results = []
        tool_queue = [(start_tool, 0, {})]  # (tool_name, depth, params)
        tools_to_execute = set()

        while tool_queue and len(results) < max_tools:
            tool_name, depth, params = tool_queue.pop(0)

            if depth > max_depth:
                continue

            if tool_name in self.tools_executed:
                continue

            print(f"\n[*] 执行: {tool_name} (深度: {depth})")

            # 执行工具
            tool_result = await self._execute_tool(tool_name, target, params)
            self.tools_executed.add(tool_name)
            results.append(tool_result)

            if tool_result.success:
                # 分析输出
                analysis = self.analyze_output(tool_name, tool_result.output)

                # 添加触发的工具到队列
                for next_tool in analysis.next_tools:
                    if next_tool not in self.tools_executed:
                        tool_queue.append((next_tool, depth + 1, {}))
                        print(f"     触发: {next_tool}")

            else:
                # 尝试备选工具
                fallbacks = self.FALLBACK_TOOLS.get(tool_name, [])
                for fallback in fallbacks:
                    if fallback not in self.tools_executed:
                        tool_queue.append((fallback, depth, {}))
                        print(f"     备选: {fallback}")
                        break

        # 生成报告
        report = {
            "start_tool": start_tool,
            "target": target,
            "total_tools_executed": len(results),
            "triggered_conditions": [c.value for c in self.triggered_conditions],
            "discovered_data": dict(self.discovered_data),
            "results": [
                {
                    "tool": r.tool_name,
                    "success": r.success,
                    "next_tools_triggered": r.next_tools,
                }
                for r in results
            ],
        }

        print(f"\n[+] 编排完成")
        print(f"    工具执行: {len(results)}个")
        print(f"    触发条件: {len(self.triggered_conditions)}个")

        return report

    async def _execute_tool(self, tool_name: str, target: str,
                           params: Dict = None) -> ToolResult:
        """执行单个工具"""
        params = params or {}
        start_time = time.time()

        try:
            if tool_name in self.mcp_tools:
                # 构建参数
                tool_params = self._build_params(tool_name, target, params)

                # 执行
                output = await self.mcp_tools[tool_name](**tool_params)

                return ToolResult(
                    tool_name=tool_name,
                    success=True,
                    output=str(output),
                    execution_time=time.time() - start_time,
                )
            else:
                return ToolResult(
                    tool_name=tool_name,
                    success=False,
                    output=f"Tool {tool_name} not available",
                    execution_time=time.time() - start_time,
                )

        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                output=str(e),
                execution_time=time.time() - start_time,
            )

    def _build_params(self, tool_name: str, target: str,
                     override_params: Dict = None) -> Dict:
        """构建工具参数"""
        params = override_params.copy() if override_params else {}

        # 添加目标
        if "target" not in params and "url" not in params:
            if tool_name in ["whatweb_scan", "gobuster_scan", "ffuf_scan",
                            "feroxbuster_scan", "nikto_scan", "sqlmap_scan",
                            "nuclei_scan", "nuclei_web_scan", "wpscan_scan"]:
                if target.startswith("http"):
                    params["url"] = target
                else:
                    params["url"] = f"http://{target}"
            else:
                params["target"] = target

        return params

    async def execute_attack_chain(self, chain_name: str, target: str) -> Dict[str, Any]:
        """
        执行预定义攻击链
        """
        if chain_name not in self.ATTACK_CHAINS:
            return {"error": f"Unknown chain: {chain_name}"}

        chain = self.ATTACK_CHAINS[chain_name]

        print(f"[*] 执行攻击链: {chain.name}")
        print(f"[*] 描述: {chain.description}")
        print(f"[*] 工具数: {len(chain.tools)}")

        results = []

        for i, tool_name in enumerate(chain.tools):
            print(f"\n[*] 步骤 {i+1}/{len(chain.tools)}: {tool_name}")

            result = await self._execute_tool(tool_name, target)
            results.append(result)

            if result.success:
                # 分析输出
                analysis = self.analyze_output(tool_name, result.output)

                # 检查是否发现漏洞
                if analysis.triggered_conditions:
                    print(f"    发现: {[c.value for c in analysis.triggered_conditions]}")

        return {
            "chain_name": chain_name,
            "target": target,
            "steps_completed": len(results),
            "results": [
                {"tool": r.tool_name, "success": r.success}
                for r in results
            ],
        }

    async def deep_exploit(self, vuln_type: str, target: str,
                          initial_params: Dict = None) -> Dict[str, Any]:
        """
        深度利用漏洞

        使用多轮升级参数尝试
        """
        print(f"[*] 深度利用: {vuln_type}")
        print(f"[*] 目标: {target}")

        results = []

        # 获取相关工具
        vuln_tools = {
            "sqli": ["sqlmap_scan", "intelligent_sql_injection_payloads"],
            "xss": ["intelligent_xss_payloads"],
            "command_injection": ["intelligent_command_injection_payloads"],
            "brute_force": ["hydra_attack", "medusa_bruteforce"],
        }

        tools = vuln_tools.get(vuln_type, [])

        for tool_name in tools:
            if tool_name in self.AGGRESSIVE_PARAMS:
                # 多轮尝试，每轮使用更激进的参数
                for level in ["level_1", "level_2", "level_3"]:
                    params = self.AGGRESSIVE_PARAMS[tool_name].get(level, {})

                    print(f"\n[*] {tool_name} - {level}")

                    result = await self._execute_tool(tool_name, target, params)
                    results.append({
                        "tool": tool_name,
                        "level": level,
                        "success": result.success,
                    })

                    if result.success:
                        # 检查是否成功利用
                        if self._check_exploit_success(result.output, vuln_type):
                            print(f"[+] 利用成功!")
                            return {
                                "success": True,
                                "vuln_type": vuln_type,
                                "tool": tool_name,
                                "level": level,
                                "results": results,
                            }

            else:
                result = await self._execute_tool(tool_name, target)
                results.append({
                    "tool": tool_name,
                    "success": result.success,
                })

        return {
            "success": False,
            "vuln_type": vuln_type,
            "results": results,
        }

    def _check_exploit_success(self, output: str, vuln_type: str) -> bool:
        """检查利用是否成功"""
        output_lower = output.lower()

        success_indicators = {
            "sqli": ["database:", "table:", "column:", "dumped", "extracted"],
            "xss": ["alert", "script executed", "xss confirmed"],
            "command_injection": ["uid=", "root", "command executed"],
            "brute_force": ["password:", "login successful", "valid credentials"],
        }

        indicators = success_indicators.get(vuln_type, [])
        return any(ind in output_lower for ind in indicators)

    def get_orchestration_stats(self) -> Dict[str, Any]:
        """获取编排统计"""
        return {
            "tools_executed": len(self.tools_executed),
            "conditions_triggered": len(self.triggered_conditions),
            "discovered_data_summary": {
                k: len(v) for k, v in self.discovered_data.items()
            },
            "execution_history": len(self.execution_history),
        }


class AutoPilotAttack:
    """
    自动驾驶攻击模式

    完全自动化的攻击流程，无需人工干预
    """

    def __init__(self, orchestrator: ToolOrchestrator):
        self.orchestrator = orchestrator
        self.attack_phases = [
            "reconnaissance",
            "discovery",
            "vulnerability_scanning",
            "exploitation",
            "post_exploitation",
        ]

    async def run_autopilot(self, target: str,
                           mode: str = "comprehensive") -> Dict[str, Any]:
        """
        运行自动驾驶攻击

        mode:
        - quick: 快速扫描，只使用核心工具
        - comprehensive: 全面扫描，使用所有相关工具
        - deep: 深度扫描，多轮迭代
        """
        print(f"[*] 自动驾驶攻击启动")
        print(f"[*] 目标: {target}")
        print(f"[*] 模式: {mode}")

        results = {
            "target": target,
            "mode": mode,
            "phases": {},
            "vulnerabilities": [],
            "recommendations": [],
        }

        # 阶段1: 侦察
        print("\n[*] ===== 阶段1: 侦察 =====")
        recon_result = await self.orchestrator.execute_with_orchestration(
            start_tool="nmap_scan",
            target=target,
            max_depth=3,
        )
        results["phases"]["reconnaissance"] = recon_result

        # 检测目标类型
        is_web = any(p in [80, 443, 8080, 8443]
                    for p in self.orchestrator.discovered_data.get("open_ports", []))

        # 阶段2: 发现
        print("\n[*] ===== 阶段2: 发现 =====")
        if is_web:
            discovery_result = await self.orchestrator.execute_with_orchestration(
                start_tool="gobuster_scan",
                target=target,
                max_depth=5,
            )
        else:
            discovery_result = await self.orchestrator.execute_with_orchestration(
                start_tool="enum4linux_scan",
                target=target,
                max_depth=3,
            )
        results["phases"]["discovery"] = discovery_result

        # 阶段3: 漏洞扫描
        print("\n[*] ===== 阶段3: 漏洞扫描 =====")
        vuln_result = await self.orchestrator.execute_attack_chain(
            chain_name="web_full_assessment" if is_web else "network_penetration",
            target=target,
        )
        results["phases"]["vulnerability"] = vuln_result

        # 阶段4: 深度利用发现的漏洞
        print("\n[*] ===== 阶段4: 深度利用 =====")
        conditions = self.orchestrator.triggered_conditions

        if TriggerCondition.INJECTION_POSSIBLE in conditions:
            exploit_result = await self.orchestrator.deep_exploit("sqli", target)
            results["phases"]["exploitation"] = exploit_result

        # 生成报告
        results["summary"] = self.orchestrator.get_orchestration_stats()

        return results


# 导出
__all__ = [
    "ToolOrchestrator",
    "AutoPilotAttack",
    "ToolCategory",
    "TriggerCondition",
    "ToolResult",
    "AttackChain",
]
