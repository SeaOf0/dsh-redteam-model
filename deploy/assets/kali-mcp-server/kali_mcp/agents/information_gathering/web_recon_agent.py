#!/usr/bin/env python3
"""
WebReconAgent - Web侦察智能体

负责Web应用信息收集：
- 目录和文件枚举
- 路径发现
- 技术栈识别
- WAF检测
- 敏感文件扫描

集成工具：12个
"""

import logging
import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from kali_mcp.agents.base_agent_v2 import BaseAgentV2, AgentCapability
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.core.result_aggregator import AgentResult, Finding, ResultType, ResultSeverity

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """资源类型"""
    DIRECTORY = "directory"           # 目录
    FILE = "file"                     # 文件
    ENDPOINT = "endpoint"             # API端点
    TECHNOLOGY = "technology"         # 技术栈
    WAF = "waf"                       # WAF
    VULNERABILITY = "vulnerability"   # 漏洞


class WebReconAgent(BaseAgentV2):
    """
    Web侦察智能体

    专门负责Web应用信息收集，包括：
    - 目录枚举（gobuster, dirb, ffuf, feroxbuster, wfuzz）
    - 技术识别（whatweb, httpx）
    - WAF检测（wafw00f）
    - CMS扫描（wpscan, joomscan）
    """

    def __init__(self, message_bus=None, tool_registry=None, executor=None):
        # 创建能力对象
        capabilities = AgentCapability(
            name="web_reconnaissance",
            category="information_gathering",
            supported_tools={
                # 目录枚举工具
                "gobuster_scan", "dirb_scan", "ffuf_scan",
                "feroxbuster_scan", "wfuzz_scan",

                # 技术识别工具
                "whatweb_scan", "whatweb_identify", "httpx_probe",

                # WAF检测
                "wafw00f_scan",

                # CMS扫描
                "wpscan_scan", "joomscan_scan",

                # 高级扫描
                "comprehensive_web_security_scan"
            },
            max_concurrent_tasks=5,
            specialties=["directory_enum", "tech_detect", "waf_detect"]
        )

        super().__init__(
            agent_id="web_recon_agent",
            name="Web Reconnaissance Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )

        # 字典配置
        self.wordlists = {
            "quick": "/usr/share/wordlists/dirb/common.txt",
            "standard": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "comprehensive": "/usr/share/seclists/Discovery/Web-Content/big.txt"
        }

        logger.info("WebReconAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        """处理接收到的消息（BaseAgent抽象方法）"""
        from kali_mcp.core.ctf_agent_framework import MessageType

        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value}")

        if message.type == MessageType.VULNERABILITY:
            logger.info(f"收到漏洞报告: {message.content}")

    async def run(self, context):
        """执行Agent任务（BaseAgent抽象方法）"""
        logger.info(f"[{self.agent_id}] 开始执行Web侦察")

        target = context.parameters.get("target", "") if hasattr(context, 'parameters') else ""

        if not target:
            return {"success": False, "error": "未指定目标"}

        try:
            # 执行标准Web侦察流程
            result = await self._call_tool("gobuster_scan", {
                "url": target,
                "mode": "dir"
            })

            return {
                "success": True,
                "target": target,
                "scan_result": result[:200] + "..." if len(result) > 200 else result
            }

        except Exception as e:
            logger.error(f"执行任务失败: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Task对象支持 ====================

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        """执行Web侦察任务"""
        start_time = datetime.now()
        output = ""
        parsed_findings = []
        errors = []
        success = False

        try:
            target = task.parameters.get("target", "")
            scan_type = task.parameters.get("scan_type", "standard")

            logger.info(f"开始Web侦察: {target}, 类型: {scan_type}")

            # 调用内部实现方法
            output = await self._execute_task_impl(
                task_type=task.tool_name,
                task_data=task.parameters,
                task_id=task.task_id
            )

            # 解析结果
            parsed_findings = self._parse_web_recon_output(
                task.tool_name,
                output,
                target
            )

            success = True

        except Exception as e:
            error_msg = f"Web侦察失败: {str(e)}"
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
        if task_type == "gobuster_scan":
            return await self._execute_gobuster_impl(task_data)
        elif task_type == "dirb_scan":
            return await self._execute_dirb_impl(task_data)
        elif task_type == "ffuf_scan":
            return await self._execute_ffuf_impl(task_data)
        elif task_type == "whatweb_scan":
            return await self._execute_whatweb_impl(task_data)
        elif task_type == "wafw00f_scan":
            return await self._execute_wafw00f_impl(task_data)
        else:
            return await self._call_tool(task_type, task_data)

    # ==================== 目录枚举相关 ====================

    async def _execute_gobuster_impl(self, parameters: Dict[str, Any]) -> str:
        """执行Gobuster扫描"""
        url = parameters.get("url", "")
        mode = parameters.get("mode", "dir")
        wordlist = parameters.get("wordlist", self.wordlists["standard"])

        return await self._call_tool("gobuster_scan", {
            "url": url,
            "mode": mode,
            "wordlist": wordlist
        })

    async def _execute_dirb_impl(self, parameters: Dict[str, Any]) -> str:
        """执行Dirb扫描"""
        url = parameters.get("url", "")
        wordlist = parameters.get("wordlist", self.wordlists["standard"])

        return await self._call_tool("dirb_scan", {
            "url": url,
            "wordlist": wordlist
        })

    async def _execute_ffuf_impl(self, parameters: Dict[str, Any]) -> str:
        """执行FFUF扫描"""
        url = parameters.get("url", "")
        wordlist = parameters.get("wordlist", self.wordlists["standard"])

        return await self._call_tool("ffuf_scan", {
            "url": url,
            "wordlist": wordlist
        })

    # ==================== 技术识别相关 ====================

    async def _execute_whatweb_impl(self, parameters: Dict[str, Any]) -> str:
        """执行WhatWeb识别"""
        target = parameters.get("target", "")
        aggression = parameters.get("aggression", "1")

        return await self._call_tool("whatweb_scan", {
            "target": target,
            "aggression": aggression
        })

    async def _execute_wafw00f_impl(self, parameters: Dict[str, Any]) -> str:
        """执行WAF检测"""
        target = parameters.get("target", "")

        return await self._call_tool("wafw00f_scan", {
            "target": target
        })

    # ==================== 结果解析 ====================

    def _parse_web_recon_output(
        self,
        tool_name: str,
        output: str,
        target: str
    ) -> List[Finding]:
        """解析Web侦察输出"""
        findings = []

        # 解析目录枚举输出
        if tool_name in ["gobuster_scan", "dirb_scan", "ffuf_scan", "feroxbuster_scan"]:
            findings.extend(self._parse_directory_enum_output(output, target))

        # 解析技术识别输出
        elif tool_name in ["whatweb_scan", "whatweb_identify"]:
            findings.extend(self._parse_tech_detect_output(output, target))

        # 解析WAF检测输出
        elif tool_name == "wafw00f_scan":
            findings.extend(self._parse_waf_detect_output(output, target))

        return findings

    def _parse_directory_enum_output(self, output: str, target: str) -> List[Finding]:
        """解析目录枚举输出"""
        findings = []

        # Gobuster输出格式: "http://example.com/admin (Status: 301)"
        gobuster_pattern = re.compile(r'(https?://[\w./-]+)\s+\(Status:\s+(\d+)\)')

        for match in gobuster_pattern.finditer(output):
            path = match.group(1)
            status = match.group(2)

            # 判断资源类型
            if status.startswith("2"):
                resource_type = "有效资源"
            elif status.startswith("3"):
                resource_type = "重定向"
            else:
                resource_type = f"状态码{status}"

            findings.append(Finding(
                finding_type=ResultType.ASSET,
                severity=ResultSeverity.INFO,
                title=f"发现路径: {path}",
                description=f"{resource_type} - {path}",
                evidence=[match.group(0)],
                source=self.agent_id,
                confidence=0.90
            ))

        # Dirb输出格式: "http://example.com/admin (CODE:200|SIZE:1234)"
        dirb_pattern = re.compile(r'(https?://[\w./-]+)\s+\(CODE:(\d+)\|SIZE:\d+\)')

        for match in dirb_pattern.finditer(output):
            path = match.group(1)
            status = match.group(2)

            if int(status) < 400:  # 只记录有效路径
                findings.append(Finding(
                    finding_type=ResultType.ASSET,
                    severity=ResultSeverity.INFO,
                    title=f"发现路径: {path}",
                    description=f"状态码: {status}",
                    evidence=[match.group(0)],
                    source=self.agent_id,
                    confidence=0.85
                ))

        return findings

    def _parse_tech_detect_output(self, output: str, target: str) -> List[Finding]:
        """解析技术识别输出"""
        findings = []

        # WhatWeb输出: 每行一个技术栈
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('|') and not line.startswith('+'):
                # 提取技术栈信息
                parts = line.split(',')
                if len(parts) >= 1:
                    tech = parts[0].strip()
                    findings.append(Finding(
                        finding_type=ResultType.INFO,
                        severity=ResultSeverity.INFO,
                        title=f"检测到技术: {tech}",
                        description=f"目标 {target} 使用 {tech}",
                        evidence=[line.strip()],
                        source=self.agent_id,
                        confidence=0.85
                    ))

        return findings

    def _parse_waf_detect_output(self, output: str, target: str) -> List[Finding]:
        """解析WAF检测输出"""
        findings = []

        # wafw00f输出格式: "Behind WAF? Yes [Cloudflare]"
        waf_pattern = re.compile(r'Behind WAF\?\s+(Yes|No)\s+\[([\w\s]+)\]')

        for match in waf_pattern.finditer(output):
            detected = match.group(1)
            waf_name = match.group(2)

            if detected == "Yes":
                findings.append(Finding(
                    finding_type=ResultType.INFO,
                    severity=ResultSeverity.MEDIUM,
                    title=f"检测到WAF: {waf_name}",
                    description=f"目标 {target} 使用 {waf_name} WAF",
                    evidence=[match.group(0)],
                    source=self.agent_id,
                    confidence=0.95
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

    async def plan_web_reconnaissance(
        self,
        target: str,
        intensity: str = "standard",
        detect_waf: bool = True
    ) -> List[Task]:
        """
        规划Web侦察任务

        Args:
            target: 目标URL
            intensity: 扫描强度 (quick, standard, comprehensive)
            detect_waf: 是否检测WAF

        Returns:
            任务列表
        """
        tasks = []
        task_id = 0

        # 1. 目录枚举
        tasks.append(Task(
            task_id=f"web_recon_{task_id}",
            name=f"目录枚举: {target}",
            category=TaskCategory.RECONNAISSANCE,
            tool_name="gobuster_scan",
            parameters={
                "url": target,
                "wordlist": self.get_wordlist(intensity)
            },
            priority=8,
            estimated_duration=180,
            tags=["web_recon", "directory_enum"]
        ))

        task_id += 1

        # 2. 技术识别
        tasks.append(Task(
            task_id=f"web_recon_{task_id}",
            name=f"技术识别: {target}",
            category=TaskCategory.SCANNING,
            tool_name="whatweb_scan",
            parameters={
                "target": target,
                "aggression": "1"
            },
            priority=7,
            estimated_duration=60,
            tags=["web_recon", "tech_detect"]
        ))

        task_id += 1

        # 3. WAF检测（如果启用）
        if detect_waf:
            tasks.append(Task(
                task_id=f"web_recon_{task_id}",
                name=f"WAF检测: {target}",
                category=TaskCategory.SCANNING,
                tool_name="wafw00f_scan",
                parameters={
                    "target": target
                },
                priority=6,
                estimated_duration=30,
                tags=["web_recon", "waf_detect"]
            ))

        return tasks
