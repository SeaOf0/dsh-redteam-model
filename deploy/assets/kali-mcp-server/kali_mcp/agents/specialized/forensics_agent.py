#!/usr/bin/env python3
"""
ForensicsAgent - 取证智能体

负责取证和数据恢复：
- 流量分析
- 隐写术检测和提取
- 内存取证
- 数据恢复
- 文件系统分析

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


class ForensicsType(Enum):
    """取证类型"""
    NETWORK = "network"       # 网络取证
    MEMORY = "memory"         # 内存取证
    DISK = "disk"             # 磁盘取证
    STEGANOGRAPHY = "steg"    # 隐写术
    MALWARE = "malware"       # 恶意软件分析


@dataclass
class ForensicsResult:
    """取证结果"""
    forensics_type: ForensicsType  # 取证类型
    evidence_type: str            # 证据类型
    description: str               # 描述
    findings: List[str]            # 发现列表
    confidence: float              # 置信度


class ForensicsAgent(BaseAgentV2):
    """
    取证智能体

    专门负责取证和数据恢复，包括：
    - 隐写术检测和提取（stego_detect）
    - 内存取证（memory_forensics）
    - 文件系统取证（forensics_full_analysis）
    - 流量包分析
    """

    def __init__(self, message_bus=None, tool_registry=None, executor=None):
        # 创建能力对象
        capabilities = AgentCapability(
            name="forensics",
            category="specialized",
            supported_tools={
                # 取证工具
                "forensics_full_analysis",
                "stego_detect",
                "memory_forensics",

                # 二进制分析工具（可用于取证）
                "binwalk_analysis",

                # CTF取证工具
                "ctf_misc_solver"
            },
            max_concurrent_tasks=3,
            specialties=["forensics", "steganography", "memory", "recovery"]
        )

        super().__init__(
            agent_id="forensics_agent",
            name="Forensics Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )

        logger.info("ForensicsAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        """处理接收到的消息（BaseAgent抽象方法）"""
        from kali_mcp.core.ctf_agent_framework import MessageType

        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value}")

        if message.type == MessageType.VULNERABILITY:
            logger.info(f"收到漏洞报告: {message.content}")

    async def run(self, context):
        """执行Agent任务（BaseAgent抽象方法）"""
        logger.info(f"[{self.agent_id}] 开始执行取证分析")

        target = context.parameters.get("target", "") if hasattr(context, 'parameters') else ""

        if not target:
            return {"success": False, "error": "未指定目标"}

        try:
            # 执行隐写术检测
            result = await self._call_tool("stego_detect", {
                "file_path": target
            })

            return {
                "success": True,
                "target": target,
                "forensics_result": result[:200] + "..." if len(result) > 200 else result
            }

        except Exception as e:
            logger.error(f"执行任务失败: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Task对象支持 ====================

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        """执行取证任务"""
        start_time = datetime.now()
        output = ""
        parsed_findings = []
        errors = []
        success = False

        try:
            target = task.parameters.get("target", "")
            forensics_type = task.parameters.get("forensics_type", "")

            logger.info(f"开始取证分析: {target}, 类型: {forensics_type}")

            # 调用内部实现方法
            output = await self._execute_task_impl(
                task_type=task.tool_name,
                task_data=task.parameters,
                task_id=task.task_id
            )

            # 解析结果
            parsed_findings = self._parse_forensics_output(
                task.tool_name,
                output,
                target
            )

            success = True

        except Exception as e:
            error_msg = f"取证分析失败: {str(e)}"
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
        if task_type == "stego_detect":
            return await self._execute_stego_impl(task_data)
        elif task_type == "memory_forensics":
            return await self._execute_memory_impl(task_data)
        elif task_type == "forensics_full_analysis":
            return await self._execute_forensics_impl(task_data)
        else:
            return await self._call_tool(task_type, task_data)

    # ==================== 取证工具相关 ====================

    async def _execute_stego_impl(self, parameters: Dict[str, Any]) -> str:
        """执行隐写术检测"""
        file_path = parameters.get("file_path", "")

        return await self._call_tool("stego_detect", {
            "file_path": file_path,
            "extract_data": True
        })

    async def _execute_memory_impl(self, parameters: Dict[str, Any]) -> str:
        """执行内存取证"""
        dump_path = parameters.get("dump_path", "")

        return await self._call_tool("memory_forensics", {
            "dump_path": dump_path,
            "profile": "auto"
        })

    async def _execute_forensics_impl(self, parameters: Dict[str, Any]) -> str:
        """执行全面取证分析"""
        target_path = parameters.get("target_path", "")

        return await self._call_tool("forensics_full_analysis", {
            "target_path": target_path,
            "analysis_type": "auto"
        })

    # ==================== 结果解析 ====================

    def _parse_forensics_output(
        self,
        tool_name: str,
        output: str,
        target: str
    ) -> List[Finding]:
        """解析取证输出"""
        findings = []

        # 解析隐写术检测输出
        if tool_name == "stego_detect":
            findings.extend(self._parse_stego_output(output, target))

        # 解析内存取证输出
        elif tool_name == "memory_forensics":
            findings.extend(self._parse_memory_output(output, target))

        # 解析全面取证分析输出
        elif tool_name == "forensics_full_analysis":
            findings.extend(self._parse_forensics_analysis_output(output, target))

        return findings

    def _parse_stego_output(self, output: str, target: str) -> List[Finding]:
        """解析隐写术检测输出"""
        findings = []

        # 检测隐写术成功标志
        success_indicators = [
            r"Steganography\s+detected",
            r"Hidden\s+data\s+found",
            r"Secret\s+extracted",
            r"Flag\s+found",
            r"hidden\s+file"
        ]

        for pattern in success_indicators:
            if re.search(pattern, output, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=ResultType.VULNERABILITY,
                    severity=ResultSeverity.HIGH,
                    title="检测到隐写术",
                    description=f"文件 {target} 包含隐藏数据",
                    evidence=[pattern],
                    source=self.agent_id,
                    confidence=0.85
                ))
                break

        # 检测Flag
        flag_pattern = re.compile(r'flag\{[^}]+\}', re.IGNORECASE)
        flags = flag_pattern.findall(output)

        if flags:
            findings.append(Finding(
                finding_type=ResultType.VULNERABILITY,
                severity=ResultSeverity.CRITICAL,
                title=f"发现Flag: {len(flags)}个",
                description=f"隐写术分析提取到Flag",
                evidence=[f"Flag: {', '.join(flags)}"],
                source=self.agent_id,
                confidence=0.95
            ))

        return findings

    def _parse_memory_output(self, output: str, target: str) -> List[Finding]:
        """解析内存取证输出"""
        findings = []

        # 检测进程信息
        if "process" in output.lower():
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title="发现进程信息",
                description=f"内存取证分析发现进程信息",
                evidence=["Process information found"],
                source=self.agent_id,
                confidence=0.80
            ))

        # 检测网络连接
        if "network" in output.lower() or "connection" in output.lower():
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title="发现网络连接",
                description=f"内存取证分析发现网络连接信息",
                evidence=["Network connections found"],
                source=self.agent_id,
                confidence=0.80
            ))

        # 检测密码或凭据
        if "password" in output.lower() or "credential" in output.lower():
            findings.append(Finding(
                finding_type=ResultType.VULNERABILITY,
                severity=ResultSeverity.HIGH,
                title="发现凭据",
                description=f"内存取证分析发现密码或凭据",
                evidence=["Credentials found"],
                source=self.agent_id,
                confidence=0.90
            ))

        return findings

    def _parse_forensics_analysis_output(self, output: str, target: str) -> List[Finding]:
        """解析全面取证分析输出"""
        findings = []

        # 检测文件系统证据
        if "file" in output.lower() or "filesystem" in output.lower():
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title="发现文件系统证据",
                description=f"取证分析发现文件系统信息",
                evidence=["File system evidence found"],
                source=self.agent_id,
                confidence=0.80
            ))

        # 检测删除文件
        if "deleted" in output.lower() or "recovered" in output.lower():
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.MEDIUM,
                title="发现已删除或恢复的文件",
                description=f"取证分析发现已删除或恢复的文件",
                evidence=["Deleted/recovered files found"],
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

    # ==================== 取证分析规划 ====================

    async def plan_forensics_analysis(
        self,
        target: str,
        analysis_type: str = "auto"
    ) -> List[Task]:
        """
        规划取证分析任务

        Args:
            target: 目标文件或路径
            analysis_type: 分析类型 (auto, steg, memory, file)

        Returns:
            任务列表
        """
        tasks = []
        task_id = 0

        # 1. 隐写术检测
        if analysis_type in ["auto", "steg"]:
            tasks.append(Task(
                task_id=f"forensics_{task_id}",
                name=f"隐写术检测: {target}",
                category=TaskCategory.SCANNING,
                tool_name="stego_detect",
                parameters={
                    "file_path": target,
                    "extract_data": True
                },
                priority=8,
                estimated_duration=120,
                tags=["forensics", "steganography"]
            ))
            task_id += 1

        # 2. 内存取证
        if analysis_type in ["auto", "memory"]:
            tasks.append(Task(
                task_id=f"forensics_{task_id}",
                name=f"内存取证: {target}",
                category=TaskCategory.SCANNING,
                tool_name="memory_forensics",
                parameters={
                    "dump_path": target,
                    "profile": "auto"
                },
                priority=7,
                estimated_duration=180,
                tags=["forensics", "memory"]
            ))

        return tasks
