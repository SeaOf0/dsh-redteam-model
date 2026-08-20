#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能调度层 - Skill知识库集成与工具自动编排

核心功能:
1. 读取和解析 ~/.claude/skills/kali-security.md 知识库
2. 根据目标类型自动选择最佳工具组合
3. 实现工具链的自动化执行和结果传递
4. 确保覆盖常见漏洞检测，不遗漏关键点
5. 将Skill知识转化为实际的工具调用策略

用于CTF竞赛和授权的安全评估
"""

import os
import re
import json
import asyncio
import logging
from typing import Optional, List, Dict, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime

# 设置模块级 logger，禁止输出到控制台
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# 不添加 handler，避免输出到前台


class TargetType(Enum):
    """目标类型"""
    WEB_APP = "web_app"              # Web应用
    NETWORK = "network"              # 网络/IP
    API = "api"                      # API接口
    CLOUD = "cloud"                  # 云环境
    CONTAINER = "container"          # 容器环境
    BINARY = "binary"                # 二进制文件
    MOBILE = "mobile"                # 移动应用
    ACTIVE_DIRECTORY = "ad"          # AD域
    IOT = "iot"                      # IoT设备
    DATABASE = "database"            # 数据库
    CTF = "ctf"                      # CTF挑战
    UNKNOWN = "unknown"


class ScanDepth(Enum):
    """扫描深度"""
    QUICK = "quick"           # 快速扫描 (5分钟)
    STANDARD = "standard"     # 标准扫描 (15分钟)
    COMPREHENSIVE = "comprehensive"  # 全面扫描 (30分钟)
    DEEP = "deep"             # 深度扫描 (60分钟+)


@dataclass
class ToolChain:
    """工具链定义"""
    name: str
    description: str
    tools: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    estimated_time: int = 300  # 秒
    success_criteria: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityPattern:
    """漏洞检测模式"""
    name: str
    category: str
    detection_tools: List[str]
    exploitation_tools: List[str]
    indicators: List[str]
    severity: str = "MEDIUM"


@dataclass
class SkillKnowledge:
    """Skill知识库结构"""
    tool_mappings: Dict[str, Dict]           # 工具映射
    decision_trees: Dict[str, List[Dict]]    # 决策树
    vulnerability_patterns: List[VulnerabilityPattern]  # 漏洞模式
    attack_chains: Dict[str, ToolChain]      # 攻击链
    ctf_strategies: Dict[str, List[str]]     # CTF策略
    quick_references: Dict[str, str]         # 快速参考


class SkillParser:
    """Skill知识库解析器"""

    def __init__(self, skill_path: str = None):
        self.skill_path = skill_path or os.path.expanduser("~/.claude/skills/kali-security.md")
        self.knowledge = SkillKnowledge(
            tool_mappings={},
            decision_trees={},
            vulnerability_patterns=[],
            attack_chains={},
            ctf_strategies={},
            quick_references={}
        )
        self._parse_skill_file()

    def _parse_skill_file(self):
        """解析skill文件"""
        if not os.path.exists(self.skill_path):
            self._use_default_knowledge()
            return

        try:
            with open(self.skill_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self._extract_tool_mappings(content)
                self._extract_decision_trees(content)
                self._extract_vulnerability_patterns(content)
                self._extract_attack_chains(content)
        except Exception as e:
            logger.debug(f"解析skill文件失败: {e}")
            self._use_default_knowledge()

    def _use_default_knowledge(self):
        """使用默认知识库"""
        # 默认工具映射
        self.knowledge.tool_mappings = {
            "端口扫描": {"tools": ["nmap_scan", "masscan_fast_scan"], "priority": 1},
            "目录扫描": {"tools": ["gobuster_scan", "ffuf_scan", "feroxbuster_scan", "dirb_scan"], "priority": 2},
            "漏洞扫描": {"tools": ["nuclei_scan", "nikto_scan"], "priority": 3},
            "SQL注入": {"tools": ["sqlmap_scan", "intelligent_sql_injection_payloads"], "priority": 4},
            "XSS检测": {"tools": ["intelligent_xss_payloads"], "priority": 5},
            "命令注入": {"tools": ["intelligent_command_injection_payloads"], "priority": 6},
            "技术识别": {"tools": ["whatweb_scan", "httpx_probe"], "priority": 1},
            "子域名": {"tools": ["subfinder_scan", "amass_enum", "sublist3r_scan"], "priority": 2},
            "密码破解": {"tools": ["hydra_attack", "john_crack", "hashcat_crack"], "priority": 7},
            "WAF检测": {"tools": ["wafw00f_scan"], "priority": 1},
        }

        # 默认决策树
        self.knowledge.decision_trees = {
            "web": [
                {"condition": "always", "action": "whatweb_scan", "next": "check_tech"},
                {"condition": "check_tech", "action": "wafw00f_scan", "next": "dir_scan"},
                {"condition": "dir_scan", "action": "gobuster_scan", "next": "vuln_scan"},
                {"condition": "vuln_scan", "action": "nuclei_web_scan", "next": "sql_check"},
                {"condition": "sql_check", "action": "sqlmap_scan", "next": "xss_check"},
            ],
            "network": [
                {"condition": "always", "action": "nmap_scan", "next": "service_enum"},
                {"condition": "service_enum", "action": "nuclei_network_scan", "next": "vuln_check"},
            ]
        }

        # 默认漏洞模式
        self.knowledge.vulnerability_patterns = [
            VulnerabilityPattern(
                name="SQL Injection",
                category="web",
                detection_tools=["sqlmap_scan", "nuclei_scan"],
                exploitation_tools=["sqlmap_scan"],
                indicators=["error", "mysql", "syntax", "query"],
                severity="HIGH"
            ),
            VulnerabilityPattern(
                name="XSS",
                category="web",
                detection_tools=["nuclei_scan", "intelligent_xss_payloads"],
                exploitation_tools=["intelligent_xss_payloads"],
                indicators=["<script>", "alert", "onerror"],
                severity="MEDIUM"
            ),
            VulnerabilityPattern(
                name="Command Injection",
                category="web",
                detection_tools=["nuclei_scan", "intelligent_command_injection_payloads"],
                exploitation_tools=["intelligent_command_injection_payloads"],
                indicators=["root:", "uid=", "/etc/passwd"],
                severity="CRITICAL"
            ),
            VulnerabilityPattern(
                name="File Inclusion",
                category="web",
                detection_tools=["nuclei_scan", "ffuf_scan"],
                exploitation_tools=["ffuf_scan"],
                indicators=["include", "require", "../", "file://"],
                severity="HIGH"
            ),
            VulnerabilityPattern(
                name="SSRF",
                category="web",
                detection_tools=["nuclei_scan"],
                exploitation_tools=["nuclei_scan"],
                indicators=["169.254.169.254", "localhost", "127.0.0.1"],
                severity="HIGH"
            ),
        ]

        # 默认攻击链
        self.knowledge.attack_chains = {
            "web_comprehensive": ToolChain(
                name="Web综合扫描链",
                description="完整的Web应用安全评估",
                tools=[
                    "whatweb_scan",      # 1. 技术识别
                    "wafw00f_scan",      # 2. WAF检测
                    "gobuster_scan",     # 3. 目录扫描
                    "ffuf_scan",         # 4. 参数模糊
                    "nikto_scan",        # 5. Web服务器扫描
                    "nuclei_web_scan",   # 6. 漏洞扫描
                    "sqlmap_scan",       # 7. SQL注入
                ],
                priority=1,
                estimated_time=1800
            ),
            "network_pentest": ToolChain(
                name="网络渗透链",
                description="网络层渗透测试",
                tools=[
                    "nmap_scan",         # 1. 端口扫描
                    "nuclei_network_scan", # 2. 网络漏洞
                    "enum4linux_scan",   # 3. SMB枚举
                    "hydra_attack",      # 4. 密码破解
                ],
                priority=2,
                estimated_time=1200
            ),
            "quick_ctf": ToolChain(
                name="CTF快速链",
                description="CTF快速解题",
                tools=[
                    "nmap_scan",
                    "gobuster_scan",
                    "nuclei_scan",
                ],
                priority=1,
                estimated_time=300
            ),
        }

    def _extract_tool_mappings(self, content: str):
        """从内容中提取工具映射"""
        # 查找工具映射表格
        pattern = r'\|\s*([^|]+)\s*\|\s*`([^`]+)`'
        matches = re.findall(pattern, content)

        for intent, tool in matches:
            intent = intent.strip()
            tool = tool.strip()
            if intent and tool:
                if intent not in self.knowledge.tool_mappings:
                    self.knowledge.tool_mappings[intent] = {"tools": [], "priority": 5}
                if tool not in self.knowledge.tool_mappings[intent]["tools"]:
                    self.knowledge.tool_mappings[intent]["tools"].append(tool)

    def _extract_decision_trees(self, content: str):
        """提取决策树"""
        # 简化的决策树提取
        pass

    def _extract_vulnerability_patterns(self, content: str):
        """提取漏洞模式"""
        pass

    def _extract_attack_chains(self, content: str):
        """提取攻击链"""
        pass

    def get_tools_for_intent(self, intent: str) -> List[str]:
        """根据意图获取工具列表"""
        intent_lower = intent.lower()

        # 模糊匹配
        for key, mapping in self.knowledge.tool_mappings.items():
            if key.lower() in intent_lower or intent_lower in key.lower():
                return mapping.get("tools", [])

        return []

    def get_attack_chain(self, chain_name: str) -> Optional[ToolChain]:
        """获取攻击链"""
        return self.knowledge.attack_chains.get(chain_name)


class IntelligentDispatcher:
    """智能调度器 - 根据目标自动选择和执行工具"""

    def __init__(self, tool_executor: Callable = None):
        self.skill_parser = SkillParser()
        self.tool_executor = tool_executor
        self.execution_history = []
        self.discovered_info = {}

        # 工具全覆盖映射 - 确保每种漏洞类型都有对应工具
        self.vulnerability_coverage = {
            "sql_injection": {
                "detection": ["sqlmap_scan", "nuclei_scan"],
                "exploitation": ["sqlmap_scan", "intelligent_sql_injection_payloads"],
                "keywords": ["sql", "注入", "database", "数据库"]
            },
            "xss": {
                "detection": ["nuclei_scan"],
                "exploitation": ["intelligent_xss_payloads"],
                "keywords": ["xss", "跨站", "script"]
            },
            "command_injection": {
                "detection": ["nuclei_scan"],
                "exploitation": ["intelligent_command_injection_payloads"],
                "keywords": ["命令", "command", "rce", "exec"]
            },
            "file_inclusion": {
                "detection": ["nuclei_scan", "ffuf_scan"],
                "exploitation": ["ffuf_scan"],
                "keywords": ["lfi", "rfi", "文件包含", "include"]
            },
            "ssrf": {
                "detection": ["nuclei_scan"],
                "exploitation": ["nuclei_scan"],
                "keywords": ["ssrf", "url", "redirect"]
            },
            "xxe": {
                "detection": ["nuclei_scan"],
                "exploitation": ["nuclei_scan"],
                "keywords": ["xxe", "xml", "entity"]
            },
            "deserialization": {
                "detection": ["nuclei_scan"],
                "exploitation": ["nuclei_scan"],
                "keywords": ["反序列化", "deserialize", "unserialize"]
            },
            "authentication": {
                "detection": ["nuclei_scan", "hydra_attack"],
                "exploitation": ["hydra_attack", "medusa_bruteforce"],
                "keywords": ["认证", "auth", "login", "password"]
            },
            "information_disclosure": {
                "detection": ["gobuster_scan", "nuclei_scan", "nikto_scan"],
                "exploitation": [],
                "keywords": ["信息泄露", "disclosure", "leak"]
            },
            "misconfiguration": {
                "detection": ["nikto_scan", "nuclei_scan"],
                "exploitation": [],
                "keywords": ["配置", "config", "setup"]
            },
        }

        # 目标类型到工具链的映射
        self.target_tool_chains = {
            TargetType.WEB_APP: self._get_web_tool_chain,
            TargetType.NETWORK: self._get_network_tool_chain,
            TargetType.API: self._get_api_tool_chain,
            TargetType.CLOUD: self._get_cloud_tool_chain,
            TargetType.CONTAINER: self._get_container_tool_chain,
            TargetType.CTF: self._get_ctf_tool_chain,
            TargetType.ACTIVE_DIRECTORY: self._get_ad_tool_chain,
        }

    def detect_target_type(self, target: str) -> TargetType:
        """自动检测目标类型"""
        target_lower = target.lower()

        # CTF特征
        if any(kw in target_lower for kw in ["ctf", "challenge", "flag", "pwn"]):
            return TargetType.CTF

        # 云特征
        if any(kw in target_lower for kw in ["aws", "azure", "gcp", "s3", "blob", "cloud"]):
            return TargetType.CLOUD

        # 容器特征
        if any(kw in target_lower for kw in ["docker", "k8s", "kubernetes", "container", "pod"]):
            return TargetType.CONTAINER

        # AD特征
        if any(kw in target_lower for kw in ["ldap", "domain", "active directory", "dc", "kerberos"]):
            return TargetType.ACTIVE_DIRECTORY

        # API特征
        if any(kw in target_lower for kw in ["api", "graphql", "rest", "/v1/", "/v2/"]):
            return TargetType.API

        # 二进制特征
        if target.endswith((".exe", ".elf", ".bin", ".so", ".dll")):
            return TargetType.BINARY

        # Web应用特征
        if target.startswith(("http://", "https://")) or any(kw in target_lower for kw in ["www", ".com", ".cn", ".io"]):
            return TargetType.WEB_APP

        # 网络特征 (IP地址)
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, target):
            return TargetType.NETWORK

        return TargetType.UNKNOWN

    def get_comprehensive_tool_chain(self,
                                     target: str,
                                     depth: ScanDepth = ScanDepth.COMPREHENSIVE,
                                     focus_areas: List[str] = None) -> List[Dict]:
        """
        获取全面的工具链

        确保覆盖所有常见漏洞类型，不遗漏关键检测点

        Args:
            target: 目标
            depth: 扫描深度
            focus_areas: 重点关注的漏洞类型

        Returns:
            工具执行计划列表
        """
        target_type = self.detect_target_type(target)
        chain_getter = self.target_tool_chains.get(target_type, self._get_web_tool_chain)

        # 获取基础工具链
        base_chain = chain_getter(depth)

        # 根据focus_areas添加额外工具
        if focus_areas:
            for area in focus_areas:
                area_lower = area.lower()
                for vuln_type, vuln_info in self.vulnerability_coverage.items():
                    if any(kw in area_lower for kw in vuln_info["keywords"]):
                        for tool in vuln_info["detection"] + vuln_info["exploitation"]:
                            if not any(step["tool"] == tool for step in base_chain):
                                base_chain.append({
                                    "tool": tool,
                                    "phase": "focused_scan",
                                    "priority": 8,
                                    "description": f"针对 {vuln_type} 的专项检测"
                                })

        # 确保覆盖所有关键漏洞类型
        if depth in [ScanDepth.COMPREHENSIVE, ScanDepth.DEEP]:
            base_chain = self._ensure_full_coverage(base_chain)

        return sorted(base_chain, key=lambda x: x.get("priority", 5))

    def _ensure_full_coverage(self, chain: List[Dict]) -> List[Dict]:
        """确保工具链覆盖所有关键漏洞类型"""
        existing_tools = {step["tool"] for step in chain}

        # 必须包含的核心检测工具
        core_detection_tools = [
            ("nuclei_scan", "核心漏洞扫描", 3),
            ("nikto_scan", "Web服务器扫描", 4),
            ("sqlmap_scan", "SQL注入检测", 5),
        ]

        for tool, desc, priority in core_detection_tools:
            if tool not in existing_tools:
                chain.append({
                    "tool": tool,
                    "phase": "vulnerability_scan",
                    "priority": priority,
                    "description": desc
                })

        return chain

    def _get_web_tool_chain(self, depth: ScanDepth) -> List[Dict]:
        """Web应用工具链"""
        chain = [
            # 阶段1: 信息收集
            {"tool": "whatweb_scan", "phase": "recon", "priority": 1, "description": "Web技术识别"},
            {"tool": "wafw00f_scan", "phase": "recon", "priority": 1, "description": "WAF检测"},

            # 阶段2: 目录和资源发现
            {"tool": "gobuster_scan", "phase": "discovery", "priority": 2, "description": "目录扫描"},
        ]

        if depth in [ScanDepth.STANDARD, ScanDepth.COMPREHENSIVE, ScanDepth.DEEP]:
            chain.extend([
                {"tool": "ffuf_scan", "phase": "discovery", "priority": 2, "description": "参数模糊测试"},
                {"tool": "nikto_scan", "phase": "vulnerability", "priority": 3, "description": "Web服务器漏洞"},
            ])

        if depth in [ScanDepth.COMPREHENSIVE, ScanDepth.DEEP]:
            chain.extend([
                # 阶段3: 漏洞扫描
                {"tool": "nuclei_web_scan", "phase": "vulnerability", "priority": 3, "description": "Nuclei Web扫描"},
                {"tool": "nuclei_cve_scan", "phase": "vulnerability", "priority": 3, "description": "CVE漏洞扫描"},

                # 阶段4: 专项检测
                {"tool": "sqlmap_scan", "phase": "exploitation", "priority": 4, "description": "SQL注入检测"},
                {"tool": "intelligent_xss_payloads", "phase": "exploitation", "priority": 5, "description": "XSS检测"},
                {"tool": "intelligent_command_injection_payloads", "phase": "exploitation", "priority": 5, "description": "命令注入"},
            ])

        if depth == ScanDepth.DEEP:
            chain.extend([
                {"tool": "feroxbuster_scan", "phase": "discovery", "priority": 2, "description": "深度目录扫描"},
                {"tool": "wpscan_scan", "phase": "cms", "priority": 4, "description": "WordPress扫描"},
                {"tool": "joomscan_scan", "phase": "cms", "priority": 4, "description": "Joomla扫描"},
            ])

        return chain

    def _get_network_tool_chain(self, depth: ScanDepth) -> List[Dict]:
        """网络渗透工具链"""
        chain = [
            {"tool": "nmap_scan", "phase": "recon", "priority": 1, "description": "端口扫描"},
        ]

        if depth in [ScanDepth.STANDARD, ScanDepth.COMPREHENSIVE, ScanDepth.DEEP]:
            chain.extend([
                {"tool": "nuclei_network_scan", "phase": "vulnerability", "priority": 2, "description": "网络漏洞扫描"},
                {"tool": "enum4linux_scan", "phase": "enum", "priority": 3, "description": "SMB枚举"},
            ])

        if depth in [ScanDepth.COMPREHENSIVE, ScanDepth.DEEP]:
            chain.extend([
                {"tool": "hydra_attack", "phase": "exploitation", "priority": 4, "description": "密码破解"},
                {"tool": "searchsploit_search", "phase": "exploitation", "priority": 4, "description": "漏洞搜索"},
            ])

        return chain

    def _get_api_tool_chain(self, depth: ScanDepth) -> List[Dict]:
        """API安全工具链"""
        chain = [
            {"tool": "httpx_probe", "phase": "recon", "priority": 1, "description": "HTTP探测"},
            {"tool": "nuclei_scan", "phase": "vulnerability", "priority": 2, "description": "API漏洞扫描"},
            {"tool": "ffuf_scan", "phase": "discovery", "priority": 2, "description": "API端点发现"},
        ]

        if depth in [ScanDepth.COMPREHENSIVE, ScanDepth.DEEP]:
            chain.extend([
                {"tool": "sqlmap_scan", "phase": "exploitation", "priority": 3, "description": "API注入测试"},
            ])

        return chain

    def _get_cloud_tool_chain(self, depth: ScanDepth) -> List[Dict]:
        """云环境工具链"""
        return [
            {"tool": "cloud_enum", "phase": "recon", "priority": 1, "description": "多云资源枚举"},
            {"tool": "aws_s3_enum", "phase": "recon", "priority": 2, "description": "S3存储桶扫描"},
            {"tool": "azure_blob_enum", "phase": "recon", "priority": 2, "description": "Azure Blob扫描"},
            {"tool": "gcp_bucket_enum", "phase": "recon", "priority": 2, "description": "GCP存储桶扫描"},
        ]

    def _get_container_tool_chain(self, depth: ScanDepth) -> List[Dict]:
        """容器安全工具链"""
        return [
            {"tool": "docker_enum", "phase": "recon", "priority": 1, "description": "Docker枚举"},
            {"tool": "docker_escape_check", "phase": "exploitation", "priority": 2, "description": "容器逃逸检测"},
            {"tool": "k8s_enum", "phase": "recon", "priority": 1, "description": "K8s枚举"},
            {"tool": "k8s_rbac_enum", "phase": "analysis", "priority": 2, "description": "RBAC分析"},
        ]

    def _get_ctf_tool_chain(self, depth: ScanDepth) -> List[Dict]:
        """CTF工具链"""
        chain = [
            {"tool": "nmap_scan", "phase": "recon", "priority": 1, "description": "快速端口扫描"},
            {"tool": "gobuster_scan", "phase": "discovery", "priority": 2, "description": "目录扫描"},
            {"tool": "nuclei_scan", "phase": "vulnerability", "priority": 3, "description": "漏洞扫描"},
        ]

        if depth in [ScanDepth.COMPREHENSIVE, ScanDepth.DEEP]:
            chain.extend([
                {"tool": "sqlmap_scan", "phase": "exploitation", "priority": 4, "description": "SQL注入"},
                {"tool": "intelligent_command_injection_payloads", "phase": "exploitation", "priority": 4, "description": "命令注入"},
            ])

        return chain

    def _get_ad_tool_chain(self, depth: ScanDepth) -> List[Dict]:
        """AD域工具链"""
        return [
            {"tool": "nmap_scan", "phase": "recon", "priority": 1, "description": "端口扫描"},
            {"tool": "enum4linux_scan", "phase": "enum", "priority": 2, "description": "SMB/AD枚举"},
            {"tool": "hydra_attack", "phase": "exploitation", "priority": 3, "description": "密码破解"},
        ]

    async def execute_chain(self,
                           target: str,
                           chain: List[Dict],
                           stop_on_success: bool = False) -> Dict:
        """
        执行工具链

        Args:
            target: 目标
            chain: 工具链
            stop_on_success: 发现漏洞时是否停止

        Returns:
            执行结果
        """
        results = {
            "target": target,
            "start_time": datetime.now().isoformat(),
            "tool_results": [],
            "vulnerabilities_found": [],
            "flags_found": [],
            "recommendations": []
        }

        for step in chain:
            tool_name = step["tool"]

            # 执行工具
            if self.tool_executor:
                try:
                    result = await self.tool_executor(tool_name, target=target)
                    step_result = {
                        "tool": tool_name,
                        "phase": step.get("phase"),
                        "success": result.get("status") == "success",
                        "data": result.get("data"),
                        "summary": result.get("summary")
                    }

                    results["tool_results"].append(step_result)

                    # 分析结果，提取漏洞和flag
                    vulns = self._analyze_for_vulnerabilities(result)
                    flags = self._extract_flags(result)

                    results["vulnerabilities_found"].extend(vulns)
                    results["flags_found"].extend(flags)

                    # 根据结果动态调整后续工具
                    additional_tools = self._get_follow_up_tools(result, step)
                    for additional in additional_tools:
                        if not any(s["tool"] == additional["tool"] for s in chain):
                            chain.append(additional)

                    if stop_on_success and (vulns or flags):
                        break

                except Exception as e:
                    results["tool_results"].append({
                        "tool": tool_name,
                        "phase": step.get("phase"),
                        "success": False,
                        "error": str(e)
                    })

        results["end_time"] = datetime.now().isoformat()
        results["recommendations"] = self._generate_recommendations(results)

        return results

    def _analyze_for_vulnerabilities(self, result: Dict) -> List[Dict]:
        """分析结果中的漏洞"""
        vulnerabilities = []
        data_str = str(result.get("data", "")).lower()

        for vuln_type, vuln_info in self.vulnerability_coverage.items():
            for indicator in vuln_info.get("indicators", []):
                if indicator.lower() in data_str:
                    vulnerabilities.append({
                        "type": vuln_type,
                        "indicator": indicator,
                        "severity": vuln_info.get("severity", "MEDIUM")
                    })
                    break

        return vulnerabilities

    def _extract_flags(self, result: Dict) -> List[str]:
        """提取flag"""
        flags = []
        data_str = str(result.get("data", ""))

        # 常见flag格式
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
            r'[a-f0-9]{32}',  # MD5
            r'[a-f0-9]{64}',  # SHA256
        ]

        for pattern in flag_patterns:
            matches = re.findall(pattern, data_str, re.IGNORECASE)
            flags.extend(matches)

        return list(set(flags))

    def _get_follow_up_tools(self, result: Dict, current_step: Dict) -> List[Dict]:
        """根据结果获取后续工具"""
        follow_ups = []
        data_str = str(result.get("data", "")).lower()

        # 发现WordPress
        if "wordpress" in data_str:
            follow_ups.append({
                "tool": "wpscan_scan",
                "phase": "cms_specific",
                "priority": 4,
                "description": "WordPress专项扫描"
            })

        # 发现登录页面
        if any(kw in data_str for kw in ["login", "signin", "admin"]):
            follow_ups.append({
                "tool": "hydra_attack",
                "phase": "credential",
                "priority": 5,
                "description": "登录页面密码破解"
            })

        # 发现SQL错误
        if any(kw in data_str for kw in ["sql", "mysql", "syntax error", "postgresql"]):
            follow_ups.append({
                "tool": "sqlmap_scan",
                "phase": "exploitation",
                "priority": 3,
                "description": "SQL注入利用"
            })

        return follow_ups

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """生成建议"""
        recommendations = []

        if results["vulnerabilities_found"]:
            recommendations.append("发现漏洞，建议深入利用测试")

        if not results["vulnerabilities_found"] and not results["flags_found"]:
            recommendations.append("未发现明显漏洞，建议尝试深度扫描模式")
            recommendations.append("考虑手动测试业务逻辑漏洞")

        return recommendations

    def get_tools_for_vulnerability(self, vuln_type: str) -> Dict[str, List[str]]:
        """获取针对特定漏洞类型的工具"""
        vuln_lower = vuln_type.lower()

        for vt, info in self.vulnerability_coverage.items():
            if vt in vuln_lower or any(kw in vuln_lower for kw in info.get("keywords", [])):
                return {
                    "detection": info["detection"],
                    "exploitation": info["exploitation"]
                }

        return {"detection": ["nuclei_scan"], "exploitation": []}


# 创建全局实例
skill_dispatcher = IntelligentDispatcher()


def get_skill_based_tools(target: str, depth: str = "comprehensive") -> List[Dict]:
    """
    根据Skill知识库获取工具链

    这是对外暴露的主要接口
    """
    depth_map = {
        "quick": ScanDepth.QUICK,
        "standard": ScanDepth.STANDARD,
        "comprehensive": ScanDepth.COMPREHENSIVE,
        "deep": ScanDepth.DEEP,
    }

    scan_depth = depth_map.get(depth.lower(), ScanDepth.COMPREHENSIVE)
    return skill_dispatcher.get_comprehensive_tool_chain(target, scan_depth)


def get_vulnerability_tools(vuln_type: str) -> Dict[str, List[str]]:
    """根据漏洞类型获取工具"""
    return skill_dispatcher.get_tools_for_vulnerability(vuln_type)


def detect_target(target: str) -> str:
    """检测目标类型"""
    return skill_dispatcher.detect_target_type(target).value


# 导出
__all__ = [
    "IntelligentDispatcher",
    "SkillParser",
    "TargetType",
    "ScanDepth",
    "ToolChain",
    "get_skill_based_tools",
    "get_vulnerability_tools",
    "detect_target",
    "skill_dispatcher",
]
