#!/usr/bin/env python3
"""
SubdomainAgent - 子域名智能体

负责DNS枚举和子域名发现：
- 子域名暴力破解
- DNS记录枚举
- 证书透明度查询
- 搜索引擎发现
- DNS区域传送

集成工具：10个
"""

import logging
import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from ipaddress import ip_address

from kali_mcp.agents.base_agent_v2 import BaseAgentV2, AgentCapability
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.core.result_aggregator import AgentResult, Finding, ResultType, ResultSeverity

logger = logging.getLogger(__name__)


class RecordType(Enum):
    """DNS记录类型"""
    A = "A"           # IPv4地址
    AAAA = "AAAA"     # IPv6地址
    CNAME = "CNAME"   # 别名
    MX = "MX"         # 邮件交换
    NS = "NS"         # 名称服务器
    TXT = "TXT"       # 文本记录
    SOA = "SOA"       # 区域授权


@dataclass
class Subdomain:
    """子域名信息"""
    domain: str                      # 子域名
    ip_addresses: List[str]           # IP地址列表
    record_types: List[RecordType]    # DNS记录类型
    source: str                       # 发现来源
    confidence: float                 # 置信度


class SubdomainAgent(BaseAgentV2):
    """
    子域名智能体

    专门负责DNS枚举和子域名发现，包括：
    - 子域名枚举（subfinder, amass, sublist3r）
    - DNS记录枚举（dnsrecon, dnsenum, dnsmap）
    - DNS区域传送（fierce）
    - OSINT搜集（theharvester）
    """

    def __init__(self, message_bus=None, tool_registry=None, executor=None):
        # 创建能力对象
        capabilities = AgentCapability(
            name="subdomain_discovery",
            category="information_gathering",
            supported_tools={
                # 子域名枚举工具
                "subfinder_scan", "amass_enum", "sublist3r_scan",

                # DNS枚举工具
                "dnsrecon_scan", "dnsenum_scan", "dnsmap_scan",
                "fierce_scan",

                # OSINT工具
                "theharvester_osint"
            },
            max_concurrent_tasks=5,
            specialties=["subdomain_enum", "dns_enum", "osint"]
        )

        super().__init__(
            agent_id="subdomain_agent",
            name="Subdomain Discovery Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )

        # 子域名发现配置
        self.wordlists = {
            "quick": "/usr/share/seclists/Discovery/DNS/subdomains-100.txt",
            "standard": "/usr/share/seclists/Discovery/DNS/subdomains-1000.txt",
            "comprehensive": "/usr/share/seclists/Discovery/DNS/subdomains-5000.txt"
        }

        logger.info("SubdomainAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        """处理接收到的消息（BaseAgent抽象方法）"""
        from kali_mcp.core.ctf_agent_framework import MessageType

        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value}")

        if message.type == MessageType.TASK:
            logger.info(f"收到任务消息: {message.content}")
        elif message.type == MessageType.STATUS:
            logger.debug(f"收到状态更新: {message.content}")
        elif message.type == MessageType.ERROR:
            logger.warning(f"收到错误消息: {message.content}")

    async def run(self, context):
        """执行Agent任务（BaseAgent抽象方法）"""
        logger.info(f"[{self.agent_id}] 开始执行任务")

        target = context.parameters.get("target", "") if hasattr(context, 'parameters') else ""

        if not target:
            return {"success": False, "error": "未指定目标"}

        try:
            # 执行标准子域名枚举流程
            logger.info(f"开始子域名枚举: {target}")

            # 1. 子域名枚举
            subdomain_result = await self._call_tool("subfinder_scan", {
                "domain": target
            })

            # 2. DNS记录枚举
            dns_result = await self._call_tool("dnsrecon_scan", {
                "domain": target,
                "scan_type": "-t std"
            })

            return {
                "success": True,
                "target": target,
                "subdomain_scan": subdomain_result[:100] + "..." if len(subdomain_result) > 100 else subdomain_result,
                "dns_scan": dns_result[:100] + "..." if len(dns_result) > 100 else dns_result
            }

        except Exception as e:
            logger.error(f"执行任务失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    # ==================== Task对象支持（BaseAgentV2）====================

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        """执行子域名枚举任务"""
        start_time = datetime.now()
        output = ""
        parsed_findings = []
        errors = []
        success = False

        try:
            target = task.parameters.get("target", "")
            enum_type = task.parameters.get("enum_type", "standard")

            logger.info(f"开始子域名枚举: {target}, 类型: {enum_type}")

            # 调用内部实现方法
            output = await self._execute_task_impl(
                task_type=task.tool_name,
                task_data=task.parameters,
                task_id=task.task_id
            )

            # 解析结果
            parsed_findings = self._parse_subdomain_output(
                task.tool_name,
                output,
                target
            )

            success = True

        except Exception as e:
            error_msg = f"子域名枚举失败: {str(e)}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)
            output = str(e)

        execution_time = (datetime.now() - start_time).total_seconds()

        return AgentResult(
            agent_id=self.agent_id,
            task_id=task.task_id,
            tool_name=task.tool_name,
            target=task.parameters.get("target", ""),
            success=success,
            execution_time=execution_time,
            output=output,
            parsed_data={"findings": [self._finding_to_dict(f) for f in parsed_findings]},
            findings=parsed_findings,
            errors=errors
        )

    async def _execute_task_impl(
        self,
        task_type: str,
        task_data: Dict[str, Any],
        task_id: str
    ) -> Any:
        """执行任务实现"""
        if task_type == "subfinder_scan":
            return await self._execute_subfinder_impl(task_data)
        elif task_type == "amass_enum":
            return await self._execute_amass_impl(task_data)
        elif task_type == "sublist3r_scan":
            return await self._execute_sublist3r_impl(task_data)
        elif task_type == "dnsrecon_scan":
            return await self._execute_dnsrecon_impl(task_data)
        elif task_type == "theharvester_osint":
            return await self._execute_theharvester_impl(task_data)
        else:
            return await self._call_tool(task_type, task_data)

    # ==================== 子域名枚举相关 ====================

    async def _execute_subfinder_impl(self, parameters: Dict[str, Any]) -> str:
        """执行Subfinder扫描"""
        domain = parameters.get("domain", "")
        sources = parameters.get("sources", "")

        return await self._call_tool("subfinder_scan", {
            "domain": domain,
            "sources": sources
        })

    async def _execute_amass_impl(self, parameters: Dict[str, Any]) -> str:
        """执行Amass枚举"""
        domain = parameters.get("domain", "")
        mode = parameters.get("mode", "enum")

        return await self._call_tool("amass_enum", {
            "domain": domain,
            "mode": mode
        })

    async def _execute_sublist3r_impl(self, parameters: Dict[str, Any]) -> str:
        """执行Sublist3r扫描"""
        domain = parameters.get("domain", "")

        return await self._call_tool("sublist3r_scan", {
            "domain": domain,
            "additional_args": "-v"
        })

    # ==================== DNS枚举相关 ====================

    async def _execute_dnsrecon_impl(self, parameters: Dict[str, Any]) -> str:
        """执行DNSRecon枚举"""
        domain = parameters.get("domain", "")
        scan_type = parameters.get("scan_type", "-t std")

        return await self._call_tool("dnsrecon_scan", {
            "domain": domain,
            "scan_type": scan_type
        })

    async def _execute_theharvester_impl(self, parameters: Dict[str, Any]) -> str:
        """执行theHarvester OSINT搜集"""
        domain = parameters.get("domain", "")
        sources = parameters.get("sources", "anubis,crtsh,dnsdumpster,hackertarget")
        limit = parameters.get("limit", "500")

        return await self._call_tool("theharvester_osint", {
            "domain": domain,
            "sources": sources,
            "limit": limit
        })

    # ==================== 结果解析 ====================

    def _parse_subdomain_output(
        self,
        tool_name: str,
        output: str,
        target: str
    ) -> List[Finding]:
        """解析子域名枚举输出"""
        findings = []

        # 解析Subfinder输出
        if tool_name == "subfinder_scan":
            findings.extend(self._parse_subfinder_output(output, target))

        # 解析Amass输出
        elif tool_name == "amass_enum":
            findings.extend(self._parse_amass_output(output, target))

        # 解析Sublist3r输出
        elif tool_name == "sublist3r_scan":
            findings.extend(self._parse_sublist3r_output(output, target))

        # 解析DNSRecon输出
        elif tool_name == "dnsrecon_scan":
            findings.extend(self._parse_dnsrecon_output(output, target))

        # 解析theHarvester输出
        elif tool_name == "theharvester_osint":
            findings.extend(self._parse_theharvester_output(output, target))

        return findings

    def _parse_subfinder_output(self, output: str, target: str) -> List[Finding]:
        """解析Subfinder输出"""
        findings = []

        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and target in line:
                # 简单的子域名验证
                if '.' in line and not line.startswith('http'):
                    findings.append(Finding(
                        finding_type=ResultType.ASSET,
                        severity=ResultSeverity.INFO,
                        title=f"发现子域名: {line}",
                        description=f"通过Subfinder发现子域名 {line}",
                        evidence=[line],
                        source=self.agent_id,
                        confidence=0.85
                    ))

        return findings

    def _parse_amass_output(self, output: str, target: str) -> List[Finding]:
        """解析Amass输出"""
        findings = []

        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and target in line and '.' in line:
                findings.append(Finding(
                    finding_type=ResultType.ASSET,
                    severity=ResultSeverity.INFO,
                    title=f"发现子域名: {line}",
                    description=f"通过Amass发现子域名 {line}",
                    evidence=[line],
                    source=self.agent_id,
                    confidence=0.90
                ))

        return findings

    def _parse_sublist3r_output(self, output: str, target: str) -> List[Finding]:
        """解析Sublist3r输出"""
        findings = []

        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            # Sublist3r通常直接输出子域名，每行一个
            if line and target in line and '.' in line:
                findings.append(Finding(
                    finding_type=ResultType.ASSET,
                    severity=ResultSeverity.INFO,
                    title=f"发现子域名: {line}",
                    description=f"通过Sublist3r发现子域名 {line}",
                    evidence=[line],
                    source=self.agent_id,
                    confidence=0.80
                ))

        return findings

    def _parse_dnsrecon_output(self, output: str, target: str) -> List[Finding]:
        """解析DNSRecon输出"""
        findings = []

        # DNSRecon输出格式解析
        # 例如: "A       example.com       192.168.1.1"
        record_pattern = re.compile(r'([A-Z]+)\s+([\w.-]+)\s+([\d.:a-fA-F]+)')

        for match in record_pattern.finditer(output):
            record_type = match.group(1)
            domain = match.group(2)
            value = match.group(3)

            if target in domain:
                findings.append(Finding(
                    finding_type=ResultType.ASSET,
                    severity=ResultSeverity.INFO,
                    title=f"DNS记录: {record_type} {domain}",
                    description=f"{domain} 的 {record_type} 记录指向 {value}",
                    evidence=[f"{record_type} {domain} -> {value}"],
                    source=self.agent_id,
                    confidence=0.95
                ))

        return findings

    def _parse_theharvester_output(self, output: str, target: str) -> List[Finding]:
        """解析theHarvester输出"""
        findings = []

        # theHarvester输出格式: "[*] Subdomain found: api.example.com"
        subdomain_pattern = re.compile(r'\[\*\]\s+Subdomain found:\s+([\w.-]+)')

        for match in subdomain_pattern.finditer(output):
            subdomain = match.group(1)
            if target in subdomain:
                findings.append(Finding(
                    finding_type=ResultType.ASSET,
                    severity=ResultSeverity.INFO,
                    title=f"发现子域名: {subdomain}",
                    description=f"通过theHarvester发现子域名 {subdomain}",
                    evidence=[match.group(0)],
                    source=self.agent_id,
                    confidence=0.75
                ))

        return findings

    # ==================== 辅助方法 ====================

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """将Finding对象转换为字典"""
        return {
            "type": finding.finding_type.value,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence,
            "confidence": finding.confidence
        }

    async def report_load(self):
        """报告负载"""
        return super().report_load()

    # ==================== 扫描规划 ====================

    def get_wordlist(self, intensity: str) -> str:
        """获取字典文件路径"""
        return self.wordlists.get(intensity, self.wordlists["standard"])

    async def plan_subdomain_scan(
        self,
        target: str,
        intensity: str = "standard",
        include_osint: bool = True
    ) -> List[Task]:
        """
        规划子域名扫描任务

        Args:
            target: 目标域名
            intensity: 扫描强度 (quick, standard, comprehensive)
            include_osint: 是否包含OSINT搜集

        Returns:
            任务列表
        """
        tasks = []
        task_id = 0

        # 1. Subfinder快速扫描
        tasks.append(Task(
            task_id=f"subdomain_{task_id}",
            name=f"Subfinder子域名枚举: {target}",
            category=TaskCategory.RECONNAISSANCE,
            tool_name="subfinder_scan",
            parameters={
                "domain": target
            },
            priority=8,
            estimated_duration=90,
            tags=["subdomain", "quick"]
        ))

        task_id += 1

        # 2. Amass深度枚举（仅standard和comprehensive）
        if intensity in ["standard", "comprehensive"]:
            tasks.append(Task(
                task_id=f"subdomain_{task_id}",
                name=f"Amass深度枚举: {target}",
                category=TaskCategory.RECONNAISSANCE,
                tool_name="amass_enum",
                parameters={
                    "domain": target,
                    "mode": "enum"
                },
                priority=7,
                estimated_duration=180,
                tags=["subdomain", "deep"]
            ))

            task_id += 1

        # 3. OSINT搜集（如果启用）
        if include_osint:
            tasks.append(Task(
                task_id=f"subdomain_{task_id}",
                name=f"OSINT子域名搜集: {target}",
                category=TaskCategory.RECONNAISSANCE,
                tool_name="theharvester_osint",
                parameters={
                    "domain": target,
                    "sources": "anubis,crtsh,dnsdumpster,hackertarget",
                    "limit": "500"
                },
                priority=6,
                estimated_duration=120,
                tags=["subdomain", "osint"]
            ))

        return tasks
