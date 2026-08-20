#!/usr/bin/env python3
"""
CodeAuditAgent - 代码审计智能体

负责源代码安全审计：
- 静态分析 (Semgrep, Bandit, Flawfinder, ShellCheck)
- 危险模式搜索 (eval, exec, system, SQL拼接等)
- 综合代码审计编排

集成工具：5个
"""

import logging
import re
from typing import Dict, List, Any
from datetime import datetime

from kali_mcp.agents.base_agent_v2 import BaseAgentV2, AgentCapability
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.core.result_aggregator import (
    AgentResult, Finding, ResultType, ResultSeverity
)

logger = logging.getLogger(__name__)


class CodeAuditAgent(BaseAgentV2):
    """
    代码审计智能体

    专门负责源代码安全分析，包括：
    - semgrep_scan: Semgrep 静态分析
    - bandit_scan: Python 安全扫描
    - flawfinder_scan: C/C++ 漏洞扫描
    - shellcheck_scan: Shell 脚本分析
    - code_pattern_search: 危险代码模式搜索
    """

    # 危险代码模式
    DANGEROUS_PATTERNS = [
        (r'eval\s*\(', 'eval() 调用 - 可能导致代码注入'),
        (r'exec\s*\(', 'exec() 调用 - 可能导致代码注入'),
        (r'system\s*\(', 'system() 调用 - 可能导致命令注入'),
        (r'popen\s*\(', 'popen() 调用 - 可能导致命令注入'),
        (r'subprocess\.call.*shell\s*=\s*True',
         'subprocess shell=True - 可能导致命令注入'),
        (r'os\.system\s*\(', 'os.system() - 可能导致命令注入'),
        (r'pickle\.loads?\s*\(', 'pickle反序列化 - 可能导致RCE'),
        (r'yaml\.load\s*\((?!.*Loader)',
         'yaml.load不安全 - 使用safe_load'),
        (r'SELECT.*\+.*["\']', 'SQL字符串拼接 - 可能导致SQL注入'),
        (r'innerHTML\s*=', 'innerHTML赋值 - 可能导致XSS'),
        (r'document\.write\s*\(', 'document.write - 可能导致XSS'),
        (r'__import__\s*\(', '动态导入 - 可能导致代码注入'),
        (r'chmod\s+777', '权限设置过宽 - 安全风险'),
        (r'password\s*=\s*["\'][^"\']+["\']',
         '硬编码密码 - 凭据泄露风险'),
        (r'(api_key|secret|token)\s*=\s*["\'][^"\']+["\']',
         '硬编码密钥 - 凭据泄露风险'),
    ]

    def __init__(self, message_bus=None, tool_registry=None,
                 executor=None):
        capabilities = AgentCapability(
            name="code_audit",
            category="specialized",
            supported_tools={
                "semgrep_scan",
                "bandit_scan",
                "flawfinder_scan",
                "shellcheck_scan",
                "code_pattern_search",
            },
            max_concurrent_tasks=3,
            specialties=[
                "code_audit", "static_analysis", "sast",
                "vulnerability_detection"
            ]
        )

        super().__init__(
            agent_id="code_audit_agent",
            name="Code Audit Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )

        logger.info("CodeAuditAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ===========

    def handle_message(self, message):
        """处理接收到的消息（BaseAgent抽象方法）"""
        from kali_mcp.core.ctf_agent_framework import MessageType
        logger.info(
            f"[{self.agent_id}] 收到消息: {message.type.value}"
        )

    async def run(self, context):
        """执行Agent任务（BaseAgent抽象方法）"""
        logger.info(f"[{self.agent_id}] 开始执行代码审计")
        target = (
            context.parameters.get("target_path", "")
            if hasattr(context, 'parameters') else ""
        )
        if not target:
            return {"success": False, "error": "未指定目标路径"}

        try:
            result = await self._call_tool("semgrep_scan", {
                "target_path": target,
                "config": "auto"
            })
            return {
                "success": True,
                "target": target,
                "audit_result": (
                    result[:500] + "..."
                    if len(result) > 500 else result
                )
            }
        except Exception as e:
            logger.error(f"执行任务失败: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Task对象支持 ====================

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        """执行代码审计任务"""
        start_time = datetime.now()
        output = ""
        parsed_findings = []
        errors = []
        success = False

        try:
            target = task.parameters.get("target_path", "")
            logger.info(f"开始代码审计: {target}")

            output = await self._execute_task_impl(
                task_type=task.tool_name,
                task_data=task.parameters,
                task_id=task.task_id
            )

            parsed_findings = self._parse_audit_output(
                task.tool_name, output, target
            )
            success = True

        except Exception as e:
            error_msg = f"代码审计失败: {str(e)}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)
            output = str(e)

        execution_time = (
            datetime.now() - start_time
        ).total_seconds()

        return AgentResult(
            agent_id=self.agent_id,
            task_id=task.task_id,
            tool_name=task.tool_name,
            target=task.parameters.get("target_path", ""),
            success=success,
            execution_time=execution_time,
            output=output,
            parsed_data={
                "findings": [
                    self._finding_to_dict(f)
                    for f in parsed_findings
                ]
            },
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
        if task_type == "semgrep_scan":
            return await self._call_tool("semgrep_scan", task_data)
        elif task_type == "bandit_scan":
            return await self._call_tool("bandit_scan", task_data)
        elif task_type == "flawfinder_scan":
            return await self._call_tool(
                "flawfinder_scan", task_data
            )
        elif task_type == "shellcheck_scan":
            return await self._call_tool(
                "shellcheck_scan", task_data
            )
        elif task_type == "code_pattern_search":
            return await self._execute_pattern_search(task_data)
        else:
            return await self._call_tool(task_type, task_data)

    # ==================== 危险模式搜索 ====================

    async def _execute_pattern_search(
        self, parameters: Dict[str, Any]
    ) -> str:
        """搜索代码中的危险模式"""
        target_path = parameters.get("target_path", ".")
        results = []

        for pattern, description in self.DANGEROUS_PATTERNS:
            grep_result = await self._call_tool("ngrep_search", {
                "pattern": "",
                "additional_args": ""
            })
            # 使用executor直接执行grep
            if self.executor:
                import asyncio
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda p=pattern: self.executor.execute_command(
                        f"grep -rn '{p}' {target_path} "
                        f"--include='*.py' --include='*.js' "
                        f"--include='*.php' --include='*.c' "
                        f"--include='*.cpp' --include='*.java' "
                        f"--include='*.sh' --include='*.rb' "
                        f"2>/dev/null | head -20"
                    )
                )
                if result.get("success") and result.get("output", "").strip():
                    results.append(
                        f"\n[!] {description}\n{result['output']}"
                    )

        if results:
            return (
                f"=== 危险代码模式扫描结果 ===\n"
                f"目标: {target_path}\n"
                f"发现 {len(results)} 类危险模式\n"
                + "\n".join(results)
            )
        return f"未在 {target_path} 中发现已知危险模式"

    # ==================== 结果解析 ====================

    def _parse_audit_output(
        self, tool_name: str, output: str, target: str
    ) -> List[Finding]:
        """解析代码审计输出"""
        findings = []

        if not output:
            return findings

        # 通用：检测高危关键词
        high_keywords = [
            "critical", "high", "error", "vulnerability",
            "injection", "xss", "rce"
        ]
        medium_keywords = [
            "medium", "warning", "deprecated", "unsafe"
        ]

        output_lower = output.lower()

        for kw in high_keywords:
            if kw in output_lower:
                findings.append(Finding(
                    finding_type=ResultType.VULNERABILITY,
                    severity=ResultSeverity.HIGH,
                    title=f"代码审计发现高危问题 ({tool_name})",
                    description=(
                        f"工具 {tool_name} 在 {target} "
                        f"中检测到高危安全问题"
                    ),
                    evidence=[f"关键词匹配: {kw}"],
                    source=self.agent_id,
                    confidence=0.80
                ))
                break

        for kw in medium_keywords:
            if kw in output_lower:
                findings.append(Finding(
                    finding_type=ResultType.VULNERABILITY,
                    severity=ResultSeverity.MEDIUM,
                    title=f"代码审计发现中危问题 ({tool_name})",
                    description=(
                        f"工具 {tool_name} 在 {target} "
                        f"中检测到中危安全问题"
                    ),
                    evidence=[f"关键词匹配: {kw}"],
                    source=self.agent_id,
                    confidence=0.70
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
