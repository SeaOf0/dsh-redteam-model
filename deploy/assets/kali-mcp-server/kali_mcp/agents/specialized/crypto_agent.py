#!/usr/bin/env python3
"""
CryptoAgent - 密码学智能体

负责密码学和加密分析：
- 加密算法识别
- 密码破解
- 编码解码
- CTF密码学题目
- 哈希分析

集成工具：8个
"""

import logging
import asyncio
import re
import base64
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from kali_mcp.agents.base_agent_v2 import BaseAgentV2, AgentCapability
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.core.result_aggregator import AgentResult, Finding, ResultType, ResultSeverity

logger = logging.getLogger(__name__)


class CryptoType(Enum):
    """密码学类型"""
    SYMMETRIC = "symmetric"       # 对称加密
    ASYMMETRIC = "asymmetric"     # 非对称加密
    HASH = "hash"                 # 哈希
    ENCODING = "encoding"         # 编码
    STREAM = "stream"             # 流密码
    BLOCK = "block"               # 块密码


@dataclass
class CryptoAnalysis:
    """密码学分析结果"""
    crypto_type: CryptoType       # 密码学类型
    algorithm: str               # 算法名称
    key_length: int              # 密钥长度
    description: str             # 描述
    confidence: float            # 置信度


class CryptoAgent(BaseAgentV2):
    """
    密码学智能体

    专门负责密码学和加密分析，包括：
    - CTF密码学题目求解（ctf_crypto_solver）
    - 密码学逆向（ctf_crypto_reverser）
    - 编码识别和解码
    - 哈希分析和识别
    """

    def __init__(self, message_bus=None, tool_registry=None, executor=None):
        # 创建能力对象
        capabilities = AgentCapability(
            name="cryptography",
            category="specialized",
            supported_tools={
                # CTF密码学工具
                "ctf_crypto_solver",
                "ctf_crypto_reverser",

                # 哈希破解
                "john_crack",
                "hashcat_crack",

                # 编码工具（在MCP中可能不存在，但可以实现自定义分析）
            },
            max_concurrent_tasks=3,
            specialties=["crypto", "encoding", "hash", "ctf"]
        )

        super().__init__(
            agent_id="crypto_agent",
            name="Cryptography Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )

        # 常见编码特征
        self.encoding_signatures = {
            "base64": r'^[A-Za-z0-9+/]+={0,2}$',
            "hex": r'^[0-9a-fA-F]+$',
            "url": r'^%[0-9a-fA-F]{2}',
            "rot13": r'^[a-zA-Z]+$'
        }

        # 哈希特征
        self.hash_signatures = {
            "md5": (32, r'^[a-f0-9]{32}$'),
            "sha1": (40, r'^[a-f0-9]{40}$'),
            "sha256": (64, r'^[a-f0-9]{64}$'),
            "sha512": (128, r'^[a-f0-9]{128}$'),
            "ntlm": (32, r'^[a-f0-9]{32}$')
        }

        logger.info("CryptoAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        """处理接收到的消息（BaseAgent抽象方法）"""
        from kali_mcp.core.ctf_agent_framework import MessageType

        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value}")

        if message.type == MessageType.VULNERABILITY:
            logger.info(f"收到漏洞报告: {message.content}")

    async def run(self, context):
        """执行Agent任务（BaseAgent抽象方法）"""
        logger.info(f"[{self.agent_id}] 开始执行密码学分析")

        target = context.parameters.get("target", "") if hasattr(context, 'parameters') else ""

        if not target:
            return {"success": False, "error": "未指定目标"}

        try:
            # 执行编码识别
            result = await self._identify_encoding({
                "data": target
            })

            return {
                "success": True,
                "target": target,
                "analysis_result": result
            }

        except Exception as e:
            logger.error(f"执行任务失败: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Task对象支持 ====================

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        """执行密码学任务"""
        start_time = datetime.now()
        output = ""
        parsed_findings = []
        errors = []
        success = False

        try:
            data = task.parameters.get("data", "")
            crypto_type = task.parameters.get("crypto_type", "")

            logger.info(f"开始密码学分析: {crypto_type}")

            # 调用内部实现方法
            output = await self._execute_task_impl(
                task_type=task.tool_name,
                task_data=task.parameters,
                task_id=task.task_id
            )

            # 解析结果
            parsed_findings = self._parse_crypto_output(
                task.tool_name,
                output,
                task.parameters.get("target", data)
            )

            success = True

        except Exception as e:
            error_msg = f"密码学分析失败: {str(e)}"
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
        if task_type == "identify_encoding":
            return await self._identify_encoding(task_data)
        elif task_type == "identify_hash":
            return await self._identify_hash(task_data)
        elif task_type in ["ctf_crypto_solver", "ctf_crypto_reverser"]:
            return await self._call_tool(task_type, task_data)
        else:
            return await self._call_tool(task_type, task_data)

    # ==================== 密码学分析相关 ====================

    async def _identify_encoding(self, parameters: Dict[str, Any]) -> str:
        """识别编码类型"""
        data = parameters.get("data", "")

        analysis_result = f"[*] 编码识别分析\n\n输入数据: {data[:100]}...\n\n"

        # 检测Base64
        if self._is_base64(data):
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            analysis_result += f"[+] 检测到Base64编码\n解码结果: {decoded[:100]}...\n\n"

        # 检测十六进制
        if self._is_hex(data):
            decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
            analysis_result += f"[+] 检测到十六进制编码\n解码结果: {decoded[:100]}...\n\n"

        # 检测URL编码
        if self._is_url_encoded(data):
            analysis_result += f"[+] 检测到URL编码\n\n"

        # 检测ROT13
        if self._is_rot13(data):
            decoded = self._rot13_decode(data)
            analysis_result += f"[+] 检测到ROT13编码\n解码结果: {decoded[:100]}...\n\n"

        if analysis_result.count("[+]") == 0:
            analysis_result += "[*] 未检测到常见编码格式"

        return analysis_result

    async def _identify_hash(self, parameters: Dict[str, Any]) -> str:
        """识别哈希类型"""
        data = parameters.get("data", "")

        analysis_result = f"[*] 哈希识别分析\n\n哈希值: {data}\n\n"

        for hash_type, (length, pattern) in self.hash_signatures.items():
            if len(data) == length and re.match(pattern, data):
                analysis_result += f"[+] 检测到{hash_type.upper()}哈希\n"
                analysis_result += f"长度: {length} 字符\n"
                break
        else:
            analysis_result += "[*] 未识别的哈希格式\n"
            analysis_result += f"长度: {len(data)} 字符\n"

        return analysis_result

    # ==================== 辅助检测方法 ====================

    def _is_base64(self, data: str) -> bool:
        """检测是否为Base64编码"""
        if len(data) % 4 != 0:
            return False
        return bool(re.match(self.encoding_signatures["base64"], data))

    def _is_hex(self, data: str) -> bool:
        """检测是否为十六进制编码"""
        if len(data) % 2 != 0:
            return False
        return bool(re.match(self.encoding_signatures["hex"], data))

    def _is_url_encoded(self, data: str) -> bool:
        """检测是否为URL编码"""
        return '%' in data and re.search(self.encoding_signatures["url"], data)

    def _is_rot13(self, data: str) -> bool:
        """检测是否为ROT13编码"""
        return bool(re.match(self.encoding_signatures["rot13"], data))

    def _rot13_decode(self, data: str) -> str:
        """ROT13解码"""
        result = ""
        for char in data:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result

    # ==================== 结果解析 ====================

    def _parse_crypto_output(
        self,
        tool_name: str,
        output: str,
        target: str
    ) -> List[Finding]:
        """解析密码学输出"""
        findings = []

        # 解析CTF密码学求解器输出
        if tool_name in ["ctf_crypto_solver", "ctf_crypto_reverser"]:
            findings.extend(self._parse_ctf_crypto_output(output, target))

        # 解析编码识别输出
        elif tool_name == "identify_encoding":
            findings.extend(self._parse_encoding_output(output, target))

        # 解析哈希识别输出
        elif tool_name == "identify_hash":
            findings.extend(self._parse_hash_output(output, target))

        return findings

    def _parse_ctf_crypto_output(self, output: str, target: str) -> List[Finding]:
        """解析CTF密码学输出"""
        findings = []

        # 检测Flag
        flag_pattern = re.compile(r'flag\{[^}]+\}|FLAG\{[^}]+\}', re.IGNORECASE)
        flags = flag_pattern.findall(output)

        if flags:
            findings.append(Finding(
                finding_type=ResultType.VULNERABILITY,
                severity=ResultSeverity.CRITICAL,
                title=f"发现Flag: {len(flags)}个",
                description=f"CTF密码学求解成功",
                evidence=[f"Flag: {', '.join(flags)}"],
                source=self.agent_id,
                confidence=0.95
            ))

        return findings

    def _parse_encoding_output(self, output: str, target: str) -> List[Finding]:
        """解析编码识别输出"""
        findings = []

        if "Base64" in output:
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title="检测到Base64编码",
                description=f"数据 {target[:50]}... 被识别为Base64编码",
                evidence=["Base64 detected"],
                source=self.agent_id,
                confidence=0.90
            ))

        if "十六进制" in output:
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title="检测到十六进制编码",
                description=f"数据 {target[:50]}... 被识别为十六进制编码",
                evidence=["Hex detected"],
                source=self.agent_id,
                confidence=0.90
            ))

        return findings

    def _parse_hash_output(self, output: str, target: str) -> List[Finding]:
        """解析哈希识别输出"""
        findings = []

        hash_types = ["MD5", "SHA1", "SHA256", "SHA512", "NTLM"]

        for hash_type in hash_types:
            if hash_type in output:
                findings.append(Finding(
                    finding_type=ResultType.INFO,
                    severity=ResultSeverity.INFO,
                    title=f"识别为{hash_type}哈希",
                    description=f"数据 {target[:20]}... 被识别为{hash_type}哈希",
                    evidence=[f"{hash_type} hash detected"],
                    source=self.agent_id,
                    confidence=0.95
                ))
                break

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

    # ==================== 密码学分析规划 ====================

    async def plan_crypto_analysis(
        self,
        data: str,
        analysis_type: str = "auto"
    ) -> List[Task]:
        """
        规划密码学分析任务

        Args:
            data: 待分析的数据
            analysis_type: 分析类型 (auto, encoding, hash, ctf)

        Returns:
            任务列表
        """
        tasks = []
        task_id = 0

        # 1. 编码识别
        if analysis_type in ["auto", "encoding"]:
            tasks.append(Task(
                task_id=f"crypto_{task_id}",
                name=f"编码识别: {data[:30]}...",
                category=TaskCategory.SCANNING,
                tool_name="identify_encoding",
                parameters={
                    "data": data
                },
                priority=8,
                estimated_duration=10,
                tags=["crypto", "encoding"]
            ))
            task_id += 1

        # 2. 哈希识别
        if analysis_type in ["auto", "hash"]:
            tasks.append(Task(
                task_id=f"crypto_{task_id}",
                name=f"哈希识别: {data[:30]}...",
                category=TaskCategory.SCANNING,
                tool_name="identify_hash",
                parameters={
                    "data": data
                },
                priority=7,
                estimated_duration=10,
                tags=["crypto", "hash"]
            ))

        return tasks
