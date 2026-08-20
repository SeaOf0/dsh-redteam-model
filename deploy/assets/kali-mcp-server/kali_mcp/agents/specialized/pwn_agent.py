#!/usr/bin/env python3
"""
PwnAgent - 二进制利用智能体

负责PWN和逆向分析：
- 二进制漏洞分析
- ROP链构造
- Shellcode注入
- 格式化字符串攻击
- 栈溢出利用
- 逆向工程

集成工具：20个
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


class VulnClass(Enum):
    """漏洞类型"""
    STACK_OVERFLOW = "stack_overflow"       # 栈溢出
    HEAP_OVERFLOW = "heap_overflow"         # 堆溢出
    FORMAT_STRING = "format_string"         # 格式化字符串
    UAF = "uaf"                            # Use After Free
    INTEGER_OVERFLOW = "integer_overflow"   # 整数溢出
    RET2LIBC = "ret2libc"                   # ret2libc


@dataclass
class BinaryInfo:
    """二进制信息"""
    file_path: str                   # 文件路径
    arch: str                        # 架构
    protection: Dict[str, bool]      # 保护机制
    vulnerable_functions: List[str]  # 危险函数
    confidence: float                # 置信度


class PwnAgent(BaseAgentV2):
    """
    二进制利用智能体

    专门负责PWN和逆向分析，包括：
    - 快速PWN检查（quick_pwn_check）
    - 自动化利用（pwnpasi_auto_pwn）
    - 逆向分析（radare2, ghidra）
    - 反编译（auto_reverse_analyze）
    """

    def __init__(self, message_bus=None, tool_registry=None, executor=None):
        # 创建能力对象
        capabilities = AgentCapability(
            name="pwn_binary_exploitation",
            category="specialized",
            supported_tools={
                # PWN自动化工具
                "quick_pwn_check", "pwnpasi_auto_pwn", "pwn_comprehensive_attack",

                # 逆向分析工具
                "auto_reverse_analyze", "radare2_analyze_binary",
                "ghidra_analyze_binary",

                # 取证和分析
                "binwalk_analysis", "memory_forensics",

                # CTF工具
                "ctf_pwn_solver", "ctf_reverse_solver", "ctf_crypto_reverser"
            },
            max_concurrent_tasks=3,
            specialties=["pwn", "reverse", "binary_exploitation"]
        )

        super().__init__(
            agent_id="pwn_agent",
            name="PWN Binary Exploitation Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )

        logger.info("PwnAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        """处理接收到的消息（BaseAgent抽象方法）"""
        from kali_mcp.core.ctf_agent_framework import MessageType

        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value}")

        if message.type == MessageType.VULNERABILITY:
            logger.info(f"收到漏洞报告: {message.content}")

    async def run(self, context):
        """执行Agent任务（BaseAgent抽象方法）"""
        logger.info(f"[{self.agent_id}] 开始执行PWN分析")

        target = context.parameters.get("target", "") if hasattr(context, 'parameters') else ""

        if not target:
            return {"success": False, "error": "未指定目标"}

        try:
            # 执行快速PWN检查
            result = await self._call_tool("quick_pwn_check", {
                "binary_path": target
            })

            return {
                "success": True,
                "target": target,
                "pwn_result": result[:200] + "..." if len(result) > 200 else result
            }

        except Exception as e:
            logger.error(f"执行任务失败: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Task对象支持 ====================

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        """执行PWN任务"""
        start_time = datetime.now()
        output = ""
        parsed_findings = []
        errors = []
        success = False

        try:
            target = task.parameters.get("target", "")
            pwn_type = task.parameters.get("pwn_type", "")

            logger.info(f"开始PWN分析: {target}, 类型: {pwn_type}")

            # 调用内部实现方法
            output = await self._execute_task_impl(
                task_type=task.tool_name,
                task_data=task.parameters,
                task_id=task.task_id
            )

            # 解析结果
            parsed_findings = self._parse_pwn_output(
                task.tool_name,
                output,
                target
            )

            success = True

        except Exception as e:
            error_msg = f"PWN分析失败: {str(e)}"
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
        if task_type == "quick_pwn_check":
            return await self._execute_quick_check_impl(task_data)
        elif task_type == "pwnpasi_auto_pwn":
            return await self._execute_pwnpasi_impl(task_data)
        elif task_type == "auto_reverse_analyze":
            return await self._execute_reverse_impl(task_data)
        elif task_type == "radare2_analyze_binary":
            return await self._execute_radare2_impl(task_data)
        else:
            return await self._call_tool(task_type, task_data)

    # ==================== PWN工具相关 ====================

    async def _execute_quick_check_impl(self, parameters: Dict[str, Any]) -> str:
        """执行快速PWN检查"""
        binary_path = parameters.get("binary_path", "")

        return await self._call_tool("quick_pwn_check", {
            "binary_path": binary_path
        })

    async def _execute_pwnpasi_impl(self, parameters: Dict[str, Any]) -> str:
        """执行PwnPasi自动化利用"""
        binary_path = parameters.get("binary_path", "")
        remote_ip = parameters.get("remote_ip", "")
        remote_port = parameters.get("remote_port", 0)

        return await self._call_tool("pwnpasi_auto_pwn", {
            "binary_path": binary_path,
            "remote_ip": remote_ip,
            "remote_port": remote_port
        })

    async def _execute_reverse_impl(self, parameters: Dict[str, Any]) -> str:
        """执行逆向分析"""
        binary_path = parameters.get("binary_path", "")

        return await self._call_tool("auto_reverse_analyze", {
            "binary_path": binary_path
        })

    async def _execute_radare2_impl(self, parameters: Dict[str, Any]) -> str:
        """执行Radare2分析"""
        binary_path = parameters.get("binary_path", "")

        return await self._call_tool("radare2_analyze_binary", {
            "binary_path": binary_path
        })

    # ==================== 结果解析 ====================

    def _parse_pwn_output(
        self,
        tool_name: str,
        output: str,
        target: str
    ) -> List[Finding]:
        """解析PWN输出"""
        findings = []

        # 解析快速PWN检查输出
        if tool_name == "quick_pwn_check":
            findings.extend(self._parse_quick_check_output(output, target))

        # 解析PwnPasi输出
        elif tool_name == "pwnpasi_auto_pwn":
            findings.extend(self._parse_pwnpasi_output(output, target))

        # 解析逆向分析输出
        elif tool_name in ["auto_reverse_analyze", "radare2_analyze_binary"]:
            findings.extend(self._parse_reverse_output(output, target))

        return findings

    def _parse_quick_check_output(self, output: str, target: str) -> List[Finding]:
        """解析快速PWN检查输出"""
        findings = []

        # 检测保护机制
        protection_patterns = {
            "RELRO": r"RELRO.*?(Full|Partial)",
            "Stack": r"Canary.*?(Yes|No)",
            "NX": r"NX.*?(Enabled|Disabled)",
            "PIE": r"PIE.*?(Enabled|Disabled)"
        }

        protections = {}
        for prot, pattern in protection_patterns.items():
            match = re.search(pattern, output)
            if match:
                protections[prot] = match.group(1)

        # 检测危险函数
        dangerous_funcs = ["gets", "strcpy", "sprintf", "scanf", "fgets", "strcat"]
        found_funcs = [func for func in dangerous_funcs if func in output]

        if found_funcs:
            findings.append(Finding(
                finding_type=ResultType.VULNERABILITY,
                severity=ResultSeverity.HIGH,
                title=f"检测到危险函数: {', '.join(found_funcs)}",
                description=f"二进制 {target} 存在危险函数调用",
                evidence=[f"函数: {', '.join(found_funcs)}"],
                source=self.agent_id,
                confidence=0.85
            ))

        # 汇报保护机制
        if protections:
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title=f"二进制保护机制: {', '.join(protections.keys())}",
                description=f"{target} 的保护机制: {protections}",
                evidence=[str(protections)],
                source=self.agent_id,
                confidence=0.95
            ))

        return findings

    def _parse_pwnpasi_output(self, output: str, target: str) -> List[Finding]:
        """解析PwnPasi输出"""
        findings = []

        # PwnPasi成功标志
        success_indicators = [
            r"Exploit successful",
            r"Shell obtained",
            r"Got shell",
            r"pwn!"
        ]

        for pattern in success_indicators:
            if re.search(pattern, output, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=ResultType.VULNERABILITY,
                    severity=ResultSeverity.CRITICAL,
                    title="PWN利用成功",
                    description=f"目标 {target} 利用成功",
                    evidence=[pattern],
                    source=self.agent_id,
                    confidence=0.95
                ))
                break

        return findings

    def _parse_reverse_output(self, output: str, target: str) -> List[Finding]:
        """解析逆向分析输出"""
        findings = []

        # 检测函数 - 支持多种格式
        function_patterns = [
            re.compile(r'0x[0-9a-fA-F]+\s+(\w+)\('),  # radare2格式
            re.compile(r'^-\s+(\w+)', re.MULTILINE),   # 列表格式 (需要MULTILINE标志)
        ]

        functions = []
        for pattern in function_patterns:
            for match in pattern.finditer(output):
                func_name = match.group(1)
                # 过滤掉无效函数名
                if func_name and func_name not in functions and len(func_name) > 2:
                    functions.append(func_name)

        if functions:
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title=f"发现函数: {len(functions)}个",
                description=f"二进制 {target} 包含函数: {', '.join(functions[:10])}",
                evidence=[f"函数数量: {len(functions)}"],
                source=self.agent_id,
                confidence=0.90
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

    # ==================== PWN规划 ====================

    async def plan_pwn_attack(
        self,
        binary_path: str,
        remote_target: Optional[str] = None
    ) -> List[Task]:
        """
        规划PWN攻击任务

        Args:
            binary_path: 二进制文件路径
            remote_target: 远程目标（ip:port格式，可选）

        Returns:
            任务列表
        """
        tasks = []
        task_id = 0

        # 1. 快速PWN检查
        tasks.append(Task(
            task_id=f"pwn_{task_id}",
            name=f"快速PWN检查: {binary_path}",
            category=TaskCategory.SCANNING,
            tool_name="quick_pwn_check",
            parameters={
                "binary_path": binary_path
            },
            priority=8,
            estimated_duration=30,
            tags=["pwn", "recon"]
        ))

        task_id += 1

        # 2. 逆向分析
        tasks.append(Task(
            task_id=f"pwn_{task_id}",
            name=f"逆向分析: {binary_path}",
            category=TaskCategory.SCANNING,
            tool_name="auto_reverse_analyze",
            parameters={
                "binary_path": binary_path
            },
            priority=7,
            estimated_duration=120,
            tags=["pwn", "reverse"]
        ))

        task_id += 1

        # 3. 自动化利用（如果有远程目标）
        if remote_target:
            ip, port = remote_target.split(':') if ':' in remote_target else (remote_target, 0)
            tasks.append(Task(
                task_id=f"pwn_{task_id}",
                name=f"PWN自动化利用: {binary_path}",
                category=TaskCategory.EXPLOITATION,
                tool_name="pwnpasi_auto_pwn",
                parameters={
                    "binary_path": binary_path,
                    "remote_ip": ip,
                    "remote_port": int(port)
                },
                priority=9,
                estimated_duration=300,
                tags=["pwn", "exploit"]
            ))

        return tasks
