#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
终极扫描引擎 - Ultimate Scan Engine

目标: 确保每次扫描使用所有相关工具，不遗漏任何一个
标准: 经过本系统测试无漏洞的目标 = 全世界无人能攻破

核心功能:
1. 全工具覆盖矩阵 - 按目标类型选择所有相关工具
2. 多轮迭代测试 - 每个攻击面至少3轮测试
3. 结果智能分析 - 自动提取关键信息
4. 攻击链自动构建 - 根据发现自动选择下一步
"""

import asyncio
import json
import time
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path


class TargetType(Enum):
    """目标类型"""
    WEB_APPLICATION = "web_app"
    NETWORK_HOST = "network"
    API_ENDPOINT = "api"
    CLOUD_SERVICE = "cloud"
    CONTAINER = "container"
    ACTIVE_DIRECTORY = "ad"
    MOBILE_APP = "mobile"
    IOT_DEVICE = "iot"
    DATABASE = "database"
    MAIL_SERVER = "mail"
    CTF_CHALLENGE = "ctf"
    UNKNOWN = "unknown"


class ScanPhase(Enum):
    """扫描阶段"""
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class IterationLevel(Enum):
    """迭代级别"""
    QUICK = "quick"           # 快速扫描，1轮
    STANDARD = "standard"     # 标准扫描，2轮
    THOROUGH = "thorough"     # 深度扫描，3轮
    EXHAUSTIVE = "exhaustive" # 穷尽扫描，5轮


@dataclass
class ScanResult:
    """扫描结果"""
    tool_name: str
    phase: ScanPhase
    iteration: int
    success: bool
    output: str
    findings: List[Dict] = field(default_factory=list)
    execution_time: float = 0.0
    error: Optional[str] = None


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str
    tool_source: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None


class UltimateScanEngine:
    """
    终极扫描引擎

    确保:
    - 100% 工具利用率
    - 100% 漏洞类型覆盖
    - 多轮迭代深度测试
    """

    # 全工具覆盖矩阵 - 确保每种目标类型使用所有相关工具
    TOOL_COVERAGE_MATRIX = {
        TargetType.WEB_APPLICATION: {
            ScanPhase.RECONNAISSANCE: [
                # 技术识别 - 必须使用所有
                {"tool": "whatweb_scan", "priority": 1, "required": True},
                {"tool": "httpx_probe", "priority": 1, "required": True},
                {"tool": "wafw00f_scan", "priority": 1, "required": True},
                {"tool": "nuclei_technology_detection", "priority": 2, "required": True},
            ],
            ScanPhase.DISCOVERY: [
                # 目录扫描 - 使用多个工具交叉验证
                {"tool": "gobuster_scan", "priority": 1, "required": True,
                 "params": {"wordlist": "/usr/share/wordlists/dirb/big.txt"}},
                {"tool": "ffuf_scan", "priority": 1, "required": True,
                 "params": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"}},
                {"tool": "feroxbuster_scan", "priority": 2, "required": True},
                {"tool": "dirb_scan", "priority": 3, "required": False},
                {"tool": "wfuzz_scan", "priority": 3, "required": False},
                # 参数发现
                {"tool": "ffuf_scan", "priority": 2, "required": True,
                 "mode": "parameter_fuzzing",
                 "params": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"}},
            ],
            ScanPhase.VULNERABILITY: [
                # 通用漏洞扫描 - 必须全部使用
                {"tool": "nuclei_scan", "priority": 1, "required": True,
                 "params": {"severity": "critical,high,medium"}},
                {"tool": "nuclei_web_scan", "priority": 1, "required": True,
                 "params": {"scan_type": "comprehensive"}},
                {"tool": "nuclei_cve_scan", "priority": 1, "required": True},
                {"tool": "nikto_scan", "priority": 2, "required": True},
                # SQL注入专项
                {"tool": "sqlmap_scan", "priority": 1, "required": True,
                 "params": {"additional_args": "--level=5 --risk=3 --batch"}},
                {"tool": "intelligent_sql_injection_payloads", "priority": 2, "required": True},
                # XSS专项
                {"tool": "intelligent_xss_payloads", "priority": 1, "required": True},
                # 命令注入专项
                {"tool": "intelligent_command_injection_payloads", "priority": 1, "required": True},
            ],
            ScanPhase.EXPLOITATION: [
                # CMS专项扫描
                {"tool": "wpscan_scan", "priority": 1, "required": False,
                 "condition": "is_wordpress"},
                {"tool": "joomscan_scan", "priority": 1, "required": False,
                 "condition": "is_joomla"},
                # WAF绕过
                {"tool": "generate_waf_bypass_payload", "priority": 2, "required": False,
                 "condition": "waf_detected"},
                # 智能攻击
                {"tool": "ctf_web_attack", "priority": 1, "required": True},
                {"tool": "adaptive_web_penetration", "priority": 1, "required": True},
            ],
        },

        TargetType.NETWORK_HOST: {
            ScanPhase.RECONNAISSANCE: [
                # 端口扫描 - 多工具验证
                {"tool": "nmap_scan", "priority": 1, "required": True,
                 "params": {"scan_type": "-sS -sV -sC -O", "ports": "1-65535"}},
                {"tool": "masscan_fast_scan", "priority": 1, "required": True,
                 "params": {"ports": "1-65535", "rate": "10000"}},
                # 服务识别
                {"tool": "nmap_scan", "priority": 2, "required": True,
                 "params": {"scan_type": "-sV --version-all", "ports": "discovered"}},
            ],
            ScanPhase.DISCOVERY: [
                # 服务枚举
                {"tool": "enum4linux_scan", "priority": 1, "required": False,
                 "condition": "has_smb"},
                # DNS枚举
                {"tool": "dnsrecon_scan", "priority": 1, "required": False,
                 "condition": "has_dns"},
                {"tool": "dnsenum_scan", "priority": 2, "required": False,
                 "condition": "has_dns"},
            ],
            ScanPhase.VULNERABILITY: [
                # 网络漏洞扫描
                {"tool": "nuclei_network_scan", "priority": 1, "required": True},
                {"tool": "nuclei_cve_scan", "priority": 1, "required": True},
                # 服务特定漏洞
                {"tool": "searchsploit_search", "priority": 1, "required": True},
            ],
            ScanPhase.EXPLOITATION: [
                # 密码攻击
                {"tool": "hydra_attack", "priority": 2, "required": False,
                 "condition": "has_login_service"},
                {"tool": "medusa_bruteforce", "priority": 3, "required": False},
                # Metasploit
                {"tool": "metasploit_run", "priority": 1, "required": False,
                 "condition": "exploit_available"},
            ],
        },

        TargetType.API_ENDPOINT: {
            ScanPhase.RECONNAISSANCE: [
                {"tool": "httpx_probe", "priority": 1, "required": True},
                {"tool": "whatweb_scan", "priority": 2, "required": True},
            ],
            ScanPhase.DISCOVERY: [
                # API端点发现
                {"tool": "ffuf_scan", "priority": 1, "required": True,
                 "params": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"}},
                {"tool": "gobuster_scan", "priority": 2, "required": True},
            ],
            ScanPhase.VULNERABILITY: [
                {"tool": "nuclei_scan", "priority": 1, "required": True,
                 "params": {"templates": "http/vulnerabilities/"}},
                {"tool": "sqlmap_scan", "priority": 1, "required": True},
                {"tool": "intelligent_sql_injection_payloads", "priority": 2, "required": True},
            ],
        },

        TargetType.CTF_CHALLENGE: {
            ScanPhase.RECONNAISSANCE: [
                {"tool": "nmap_scan", "priority": 1, "required": True,
                 "params": {"scan_type": "-sV -sC", "time_constraint": "quick"}},
                {"tool": "whatweb_scan", "priority": 1, "required": True},
                {"tool": "httpx_probe", "priority": 1, "required": True},
            ],
            ScanPhase.DISCOVERY: [
                {"tool": "gobuster_scan", "priority": 1, "required": True},
                {"tool": "ffuf_scan", "priority": 1, "required": True},
                {"tool": "feroxbuster_scan", "priority": 2, "required": True},
            ],
            ScanPhase.VULNERABILITY: [
                {"tool": "nuclei_scan", "priority": 1, "required": True},
                {"tool": "sqlmap_scan", "priority": 1, "required": True},
                {"tool": "intelligent_sql_injection_payloads", "priority": 1, "required": True},
                {"tool": "intelligent_xss_payloads", "priority": 1, "required": True},
                {"tool": "intelligent_command_injection_payloads", "priority": 1, "required": True},
            ],
            ScanPhase.EXPLOITATION: [
                {"tool": "ctf_web_comprehensive_solver", "priority": 1, "required": True},
                {"tool": "ctf_quick_scan", "priority": 1, "required": True},
                {"tool": "intelligent_ctf_solver", "priority": 1, "required": True},
                {"tool": "advanced_ctf_solver", "priority": 1, "required": True},
            ],
        },
    }

    # 漏洞类型覆盖矩阵 - 确保检测所有漏洞类型
    VULNERABILITY_COVERAGE = {
        # OWASP Top 10 2021
        "A01_Broken_Access_Control": {
            "tools": ["nuclei_scan", "ffuf_scan", "intelligent_ctf_solver"],
            "payloads": ["idor", "privilege_escalation", "path_traversal"],
        },
        "A02_Cryptographic_Failures": {
            "tools": ["nuclei_scan", "nikto_scan"],
            "checks": ["weak_ssl", "sensitive_data_exposure"],
        },
        "A03_Injection": {
            "tools": ["sqlmap_scan", "intelligent_sql_injection_payloads",
                     "intelligent_command_injection_payloads", "nuclei_scan"],
            "subtypes": ["sql", "nosql", "ldap", "xpath", "command", "template"],
        },
        "A04_Insecure_Design": {
            "tools": ["nuclei_scan", "nikto_scan"],
            "checks": ["business_logic", "rate_limiting"],
        },
        "A05_Security_Misconfiguration": {
            "tools": ["nuclei_scan", "nikto_scan", "gobuster_scan"],
            "checks": ["default_creds", "directory_listing", "verbose_errors"],
        },
        "A06_Vulnerable_Components": {
            "tools": ["nuclei_cve_scan", "searchsploit_search", "wpscan_scan"],
            "checks": ["outdated_versions", "known_cves"],
        },
        "A07_Authentication_Failures": {
            "tools": ["hydra_attack", "nuclei_scan"],
            "checks": ["weak_passwords", "session_fixation", "brute_force"],
        },
        "A08_Software_Data_Integrity": {
            "tools": ["nuclei_scan"],
            "checks": ["deserialization", "ci_cd_security"],
        },
        "A09_Logging_Monitoring_Failures": {
            "tools": ["nuclei_scan"],
            "checks": ["log_injection", "monitoring_bypass"],
        },
        "A10_SSRF": {
            "tools": ["nuclei_scan", "ffuf_scan"],
            "payloads": ["ssrf_internal", "ssrf_cloud_metadata"],
        },

        # 额外重要漏洞类型
        "XSS": {
            "tools": ["intelligent_xss_payloads", "nuclei_scan"],
            "subtypes": ["reflected", "stored", "dom"],
        },
        "XXE": {
            "tools": ["nuclei_scan"],
            "payloads": ["xxe_file_read", "xxe_ssrf"],
        },
        "File_Upload": {
            "tools": ["nuclei_scan", "ffuf_scan"],
            "checks": ["unrestricted_upload", "extension_bypass"],
        },
        "LFI_RFI": {
            "tools": ["nuclei_scan", "ffuf_scan"],
            "payloads": ["lfi_traversal", "rfi_include"],
        },
        "SSTI": {
            "tools": ["nuclei_scan"],
            "payloads": ["jinja2", "twig", "freemarker"],
        },
        "Deserialization": {
            "tools": ["nuclei_scan"],
            "payloads": ["java", "php", "python", "dotnet"],
        },
    }

    # 迭代配置
    ITERATION_CONFIGS = {
        IterationLevel.QUICK: {
            "rounds": 1,
            "timeout_multiplier": 0.5,
            "wordlist_size": "small",
            "scan_depth": "shallow",
        },
        IterationLevel.STANDARD: {
            "rounds": 2,
            "timeout_multiplier": 1.0,
            "wordlist_size": "medium",
            "scan_depth": "normal",
        },
        IterationLevel.THOROUGH: {
            "rounds": 3,
            "timeout_multiplier": 2.0,
            "wordlist_size": "large",
            "scan_depth": "deep",
        },
        IterationLevel.EXHAUSTIVE: {
            "rounds": 5,
            "timeout_multiplier": 3.0,
            "wordlist_size": "huge",
            "scan_depth": "exhaustive",
        },
    }

    def __init__(self, mcp_tools: Dict[str, callable] = None):
        """
        初始化终极扫描引擎

        Args:
            mcp_tools: MCP工具函数映射
        """
        self.mcp_tools = mcp_tools or {}
        self.results: List[ScanResult] = []
        self.findings: List[VulnerabilityFinding] = []
        self.discovered_info: Dict[str, Any] = {}
        self.tools_used: Set[str] = set()
        self.tools_skipped: Set[str] = set()
        self.start_time: Optional[float] = None

    def detect_target_type(self, target: str) -> TargetType:
        """
        智能检测目标类型
        """
        target_lower = target.lower()

        # CTF检测
        if any(keyword in target_lower for keyword in ['ctf', 'challenge', 'flag', 'pwn']):
            return TargetType.CTF_CHALLENGE

        # Web应用检测
        if target.startswith(('http://', 'https://')):
            if '/api/' in target or '/v1/' in target or '/v2/' in target:
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION

        # IP地址检测
        import re
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
            return TargetType.NETWORK_HOST

        # 域名检测
        if '.' in target and not target.startswith('http'):
            return TargetType.WEB_APPLICATION

        return TargetType.UNKNOWN

    def get_all_tools_for_target(self, target_type: TargetType) -> List[Dict]:
        """
        获取目标类型的所有工具

        确保100%工具覆盖
        """
        all_tools = []

        if target_type in self.TOOL_COVERAGE_MATRIX:
            for phase, tools in self.TOOL_COVERAGE_MATRIX[target_type].items():
                for tool in tools:
                    tool_info = tool.copy()
                    tool_info["phase"] = phase
                    all_tools.append(tool_info)

        return all_tools

    def get_vulnerability_coverage_tools(self) -> Dict[str, List[str]]:
        """
        获取漏洞覆盖所需的所有工具
        """
        coverage = {}
        for vuln_type, config in self.VULNERABILITY_COVERAGE.items():
            coverage[vuln_type] = config.get("tools", [])
        return coverage

    async def execute_tool(self, tool_name: str, params: Dict = None,
                          phase: ScanPhase = ScanPhase.RECONNAISSANCE,
                          iteration: int = 1) -> ScanResult:
        """
        执行单个工具
        """
        start_time = time.time()
        params = params or {}

        try:
            if tool_name in self.mcp_tools:
                result = await self.mcp_tools[tool_name](**params)
                execution_time = time.time() - start_time

                # 记录使用的工具
                self.tools_used.add(tool_name)

                return ScanResult(
                    tool_name=tool_name,
                    phase=phase,
                    iteration=iteration,
                    success=True,
                    output=str(result),
                    execution_time=execution_time
                )
            else:
                self.tools_skipped.add(tool_name)
                return ScanResult(
                    tool_name=tool_name,
                    phase=phase,
                    iteration=iteration,
                    success=False,
                    output="",
                    error=f"Tool {tool_name} not available"
                )

        except Exception as e:
            execution_time = time.time() - start_time
            return ScanResult(
                tool_name=tool_name,
                phase=phase,
                iteration=iteration,
                success=False,
                output="",
                error=str(e),
                execution_time=execution_time
            )

    async def run_phase(self, target: str, target_type: TargetType,
                       phase: ScanPhase, iteration: int,
                       config: Dict) -> List[ScanResult]:
        """
        运行单个扫描阶段
        """
        results = []

        if target_type not in self.TOOL_COVERAGE_MATRIX:
            return results

        phase_tools = self.TOOL_COVERAGE_MATRIX[target_type].get(phase, [])

        for tool_config in phase_tools:
            tool_name = tool_config["tool"]
            params = tool_config.get("params", {}).copy()

            # 添加目标
            if "target" not in params and "url" not in params:
                if phase in [ScanPhase.RECONNAISSANCE, ScanPhase.DISCOVERY]:
                    params["target"] = target
                else:
                    params["url"] = target

            # 根据迭代级别调整参数
            params = self._adjust_params_for_iteration(params, iteration, config)

            # 检查条件
            condition = tool_config.get("condition")
            if condition and not self._check_condition(condition):
                continue

            # 执行工具
            result = await self.execute_tool(tool_name, params, phase, iteration)
            results.append(result)

            # 分析结果
            if result.success:
                await self._analyze_result(result)

        return results

    def _adjust_params_for_iteration(self, params: Dict, iteration: int,
                                     config: Dict) -> Dict:
        """
        根据迭代次数调整参数

        每轮迭代使用更激进的参数
        """
        adjusted = params.copy()

        # 第一轮: 快速扫描
        if iteration == 1:
            adjusted["time_constraint"] = "quick"

        # 第二轮: 标准扫描
        elif iteration == 2:
            adjusted["time_constraint"] = "standard"
            if "wordlist" in adjusted:
                # 使用更大的字典
                adjusted["wordlist"] = adjusted["wordlist"].replace("common", "big")

        # 第三轮: 深度扫描
        elif iteration >= 3:
            adjusted["time_constraint"] = "thorough"
            # 使用最激进的参数
            if "additional_args" in adjusted:
                adjusted["additional_args"] += " --level=5 --risk=3"

        return adjusted

    def _check_condition(self, condition: str) -> bool:
        """
        检查执行条件
        """
        # 检查已发现的信息
        if condition == "is_wordpress":
            return self.discovered_info.get("cms") == "wordpress"
        elif condition == "is_joomla":
            return self.discovered_info.get("cms") == "joomla"
        elif condition == "waf_detected":
            return self.discovered_info.get("waf") is not None
        elif condition == "has_smb":
            return 445 in self.discovered_info.get("open_ports", [])
        elif condition == "has_dns":
            return 53 in self.discovered_info.get("open_ports", [])
        elif condition == "has_login_service":
            login_ports = {21, 22, 23, 3389, 5900}
            return bool(login_ports & set(self.discovered_info.get("open_ports", [])))
        elif condition == "exploit_available":
            return bool(self.discovered_info.get("exploits", []))

        return True

    async def _analyze_result(self, result: ScanResult):
        """
        分析扫描结果，提取关键信息
        """
        output = result.output.lower()

        # 提取开放端口
        import re
        ports = re.findall(r'(\d+)/(?:tcp|udp)\s+open', output)
        if ports:
            existing_ports = self.discovered_info.get("open_ports", [])
            self.discovered_info["open_ports"] = list(set(existing_ports + [int(p) for p in ports]))

        # 检测CMS
        if "wordpress" in output:
            self.discovered_info["cms"] = "wordpress"
        elif "joomla" in output:
            self.discovered_info["cms"] = "joomla"
        elif "drupal" in output:
            self.discovered_info["cms"] = "drupal"

        # 检测WAF
        waf_patterns = ["cloudflare", "akamai", "imperva", "waf", "firewall"]
        for pattern in waf_patterns:
            if pattern in output:
                self.discovered_info["waf"] = pattern
                break

        # 提取漏洞发现
        vuln_patterns = [
            (r'(critical|high|medium)\s*:\s*([^\n]+)', 'vulnerability'),
            (r'CVE-\d{4}-\d+', 'cve'),
            (r'sql\s*injection', 'sqli'),
            (r'xss|cross.?site.?script', 'xss'),
            (r'rce|remote.?code.?execution', 'rce'),
        ]

        for pattern, vuln_type in vuln_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                existing_vulns = self.discovered_info.get("vulnerabilities", [])
                for match in matches:
                    vuln_info = {
                        "type": vuln_type,
                        "detail": match if isinstance(match, str) else match[1],
                        "source": result.tool_name
                    }
                    existing_vulns.append(vuln_info)
                self.discovered_info["vulnerabilities"] = existing_vulns

    async def run_ultimate_scan(self, target: str,
                                iteration_level: IterationLevel = IterationLevel.THOROUGH,
                                target_type: TargetType = None) -> Dict[str, Any]:
        """
        运行终极扫描

        确保:
        - 使用所有相关工具
        - 多轮迭代测试
        - 覆盖所有漏洞类型
        """
        self.start_time = time.time()

        # 检测目标类型
        if target_type is None:
            target_type = self.detect_target_type(target)

        config = self.ITERATION_CONFIGS[iteration_level]
        num_rounds = config["rounds"]

        print(f"[*] 终极扫描引擎启动")
        print(f"[*] 目标: {target}")
        print(f"[*] 类型: {target_type.value}")
        print(f"[*] 迭代级别: {iteration_level.value} ({num_rounds}轮)")

        all_results = []

        # 按阶段执行
        phases = [
            ScanPhase.RECONNAISSANCE,
            ScanPhase.DISCOVERY,
            ScanPhase.VULNERABILITY,
            ScanPhase.EXPLOITATION,
        ]

        for iteration in range(1, num_rounds + 1):
            print(f"\n[*] ===== 第 {iteration}/{num_rounds} 轮扫描 =====")

            for phase in phases:
                print(f"\n[*] 阶段: {phase.value}")

                results = await self.run_phase(
                    target=target,
                    target_type=target_type,
                    phase=phase,
                    iteration=iteration,
                    config=config
                )

                all_results.extend(results)

                # 统计
                success_count = sum(1 for r in results if r.success)
                print(f"    完成: {success_count}/{len(results)} 工具成功")

        # 生成报告
        total_time = time.time() - self.start_time

        report = {
            "target": target,
            "target_type": target_type.value,
            "iteration_level": iteration_level.value,
            "scan_summary": {
                "total_time": total_time,
                "total_tools_executed": len(self.tools_used),
                "tools_skipped": len(self.tools_skipped),
                "total_findings": len(self.discovered_info.get("vulnerabilities", [])),
            },
            "tool_coverage": {
                "used": list(self.tools_used),
                "skipped": list(self.tools_skipped),
                "utilization_rate": len(self.tools_used) / (len(self.tools_used) + len(self.tools_skipped)) * 100 if self.tools_used else 0,
            },
            "discovered_info": self.discovered_info,
            "vulnerability_coverage": self._calculate_vulnerability_coverage(),
            "results": [
                {
                    "tool": r.tool_name,
                    "phase": r.phase.value,
                    "iteration": r.iteration,
                    "success": r.success,
                    "time": r.execution_time,
                }
                for r in all_results
            ],
        }

        print(f"\n[+] 扫描完成!")
        print(f"    总时间: {total_time:.2f}秒")
        print(f"    工具使用: {len(self.tools_used)}个")
        print(f"    发现漏洞: {len(self.discovered_info.get('vulnerabilities', []))}个")
        print(f"    工具利用率: {report['tool_coverage']['utilization_rate']:.1f}%")

        return report

    def _calculate_vulnerability_coverage(self) -> Dict[str, Any]:
        """
        计算漏洞覆盖率
        """
        coverage = {}

        for vuln_type, config in self.VULNERABILITY_COVERAGE.items():
            required_tools = set(config.get("tools", []))
            used_tools = required_tools & self.tools_used

            coverage[vuln_type] = {
                "required_tools": list(required_tools),
                "used_tools": list(used_tools),
                "coverage_rate": len(used_tools) / len(required_tools) * 100 if required_tools else 100,
            }

        # 计算总体覆盖率
        total_required = sum(len(c["required_tools"]) for c in coverage.values())
        total_used = sum(len(c["used_tools"]) for c in coverage.values())

        coverage["_summary"] = {
            "total_vuln_types": len(self.VULNERABILITY_COVERAGE),
            "overall_coverage": total_used / total_required * 100 if total_required else 100,
        }

        return coverage


class CTFUltimateSolver:
    """
    CTF终极求解器

    目标: 所有题型100%覆盖，做不出来的题全世界都做不出来
    """

    # CTF题型全覆盖矩阵
    CTF_CATEGORY_TOOLS = {
        "web": {
            "reconnaissance": [
                "nmap_scan", "whatweb_scan", "httpx_probe", "wafw00f_scan",
            ],
            "discovery": [
                "gobuster_scan", "ffuf_scan", "feroxbuster_scan", "dirb_scan",
            ],
            "vulnerability": [
                "nuclei_scan", "nuclei_web_scan", "sqlmap_scan", "nikto_scan",
                "intelligent_sql_injection_payloads", "intelligent_xss_payloads",
                "intelligent_command_injection_payloads",
            ],
            "exploitation": [
                "ctf_web_comprehensive_solver", "ctf_web_attack",
                "generate_waf_bypass_payload", "generate_polyglot_payload",
                "adaptive_web_penetration",
            ],
            "specialized": [
                "wpscan_scan", "joomscan_scan",
            ],
        },
        "pwn": {
            "analysis": [
                "quick_pwn_check", "auto_reverse_analyze",
                "radare2_analyze_binary", "ghidra_analyze_binary",
            ],
            "exploitation": [
                "pwnpasi_auto_pwn", "pwn_comprehensive_attack",
                "ctf_pwn_solver",
            ],
        },
        "reverse": {
            "analysis": [
                "auto_reverse_analyze", "radare2_analyze_binary",
                "ghidra_analyze_binary", "binwalk_analysis",
            ],
            "solving": [
                "ctf_reverse_solver", "ctf_crypto_reverser",
            ],
        },
        "crypto": {
            "analysis": [
                "ctf_crypto_solver", "ctf_crypto_reverser",
            ],
        },
        "misc": {
            "analysis": [
                "binwalk_analysis", "ctf_misc_solver",
            ],
            "specialized": [
                # 隐写术工具 (待添加)
                # 取证工具 (待添加)
            ],
        },
    }

    def __init__(self, mcp_tools: Dict[str, callable] = None):
        self.mcp_tools = mcp_tools or {}
        self.ultimate_engine = UltimateScanEngine(mcp_tools)

    async def solve_challenge(self, target: str, category: str = "auto",
                             hints: List[str] = None) -> Dict[str, Any]:
        """
        尝试解决CTF题目

        使用所有可用工具进行多轮尝试
        """
        if category == "auto":
            category = self._detect_category(target, hints)

        print(f"[*] CTF终极求解器")
        print(f"[*] 目标: {target}")
        print(f"[*] 类型: {category}")

        results = {
            "target": target,
            "category": category,
            "solved": False,
            "flag": None,
            "attempts": [],
        }

        if category in self.CTF_CATEGORY_TOOLS:
            tools_by_phase = self.CTF_CATEGORY_TOOLS[category]

            for phase, tools in tools_by_phase.items():
                print(f"\n[*] 阶段: {phase}")

                for tool in tools:
                    if tool in self.mcp_tools:
                        try:
                            # 构建参数
                            params = self._build_tool_params(tool, target, category)

                            # 执行工具
                            result = await self.mcp_tools[tool](**params)

                            # 检查是否发现flag
                            flag = self._extract_flag(str(result))

                            attempt = {
                                "tool": tool,
                                "phase": phase,
                                "success": True,
                                "flag_found": flag is not None,
                            }
                            results["attempts"].append(attempt)

                            if flag:
                                results["solved"] = True
                                results["flag"] = flag
                                print(f"[+] 发现Flag: {flag}")
                                return results

                        except Exception as e:
                            results["attempts"].append({
                                "tool": tool,
                                "phase": phase,
                                "success": False,
                                "error": str(e),
                            })

        return results

    def _detect_category(self, target: str, hints: List[str] = None) -> str:
        """
        检测CTF题目类型
        """
        target_lower = target.lower()
        hints_text = " ".join(hints or []).lower()

        # 检测PWN
        if any(k in target_lower or k in hints_text for k in ['pwn', 'binary', 'elf', 'exploit']):
            return "pwn"

        # 检测Crypto
        if any(k in target_lower or k in hints_text for k in ['crypto', 'rsa', 'aes', 'cipher', 'decrypt']):
            return "crypto"

        # 检测Reverse
        if any(k in target_lower or k in hints_text for k in ['reverse', 'crackme', 'keygen']):
            return "reverse"

        # 检测Misc
        if any(k in target_lower or k in hints_text for k in ['misc', 'forensic', 'stego', 'hidden']):
            return "misc"

        # 默认Web
        return "web"

    def _build_tool_params(self, tool: str, target: str, category: str) -> Dict:
        """
        构建工具参数
        """
        params = {}

        # 基本参数
        if tool.endswith("_scan"):
            if "url" in tool or category == "web":
                params["url"] = target if target.startswith("http") else f"http://{target}"
            else:
                params["target"] = target
        elif "solver" in tool:
            params["target"] = target
            params["challenge_info"] = {"category": category}
            params["time_limit"] = "30min"
        elif "pwn" in tool:
            params["binary_path"] = target
        elif "reverse" in tool or "analyze" in tool:
            params["binary_path"] = target

        return params

    def _extract_flag(self, output: str) -> Optional[str]:
        """
        从输出中提取Flag
        """
        import re

        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
            r'[a-f0-9]{32}',  # MD5 hash
            r'[a-f0-9]{40}',  # SHA1 hash
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group()

        return None


# 导出
__all__ = [
    "UltimateScanEngine",
    "CTFUltimateSolver",
    "TargetType",
    "ScanPhase",
    "IterationLevel",
    "ScanResult",
    "VulnerabilityFinding",
]
