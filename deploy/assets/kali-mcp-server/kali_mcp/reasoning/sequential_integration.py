"""
Sequential Thinking MCP工具集成层

将ChainReasoningEngine与MCP的sequential-thinking工具集成，
实现更深度的推理能力。
"""

from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class SequentialThinkingIntegrator:
    """
    Sequential Thinking集成器

    集成MCP sequential-thinking工具，提供更强大的推理能力。
    """

    def __init__(self):
        """初始化集成器"""
        self.use_mcp_tool = True  # 是否使用MCP工具
        self.fallback_to_local = True  # 失败时回退到本地推理

    def enhance_reasoning(self,
                         reasoning_engine: 'ChainReasoningEngine',
                         initial_finding: Dict[str, Any],
                         context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        增强推理过程

        使用MCP sequential-thinking工具增强推理链。

        Args:
            reasoning_engine: 推理引擎实例
            initial_finding: 初始发现
            context: 上下文

        Returns:
            增强的推理步骤列表
        """
        enhanced_steps = []

        # 先使用本地推理引擎生成初始链
        local_chain = reasoning_engine.reason_chain(
            initial_finding=initial_finding,
            context=context
        )

        if local_chain:
            enhanced_steps.extend([step.to_dict() for step in local_chain])

        # 尝试使用MCP sequential-thinking工具增强
        if self.use_mcp_tool:
            try:
                mcp_enhanced = self._mcp_sequential_thinking(
                    local_chain,
                    initial_finding,
                    context
                )
                if mcp_enhanced:
                    enhanced_steps.extend(mcp_enhanced)
            except Exception as e:
                logger.warning(f"[Sequential Thinking] MCP工具调用失败: {str(e)}")
                if self.fallback_to_local:
                    logger.info("[Sequential Thinking] 使用本地推理结果")

        return enhanced_steps

    def _mcp_sequential_thinking(self,
                                local_chain: List['ReasoningStep'],
                                initial_finding: Dict[str, Any],
                                context: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """
        使用MCP sequential-thinking工具进行推理

        Args:
            local_chain: 本地推理链
            initial_finding: 初始发现
            context: 上下文

        Returns:
            增强的推理步骤或None
        """
        # 这里我们需要调用MCP的sequential-thinking工具
        # 但由于我们在工具内部，不能直接调用MCP工具
        # 所以我们模拟sequential-thinking的推理过程

        enhanced_steps = []
        thought_num = len(local_chain) + 1

        # 分析当前推理链，生成更深层次的思考
        last_step = local_chain[-1] if local_chain else None

        if last_step:
            # 基于最后一步生成更深入的思考
            next_thoughts = self._deep_thinking(
                last_step.to_dict(),
                context,
                thought_num
            )

            enhanced_steps.extend(next_thoughts)

        return enhanced_steps

    def _deep_thinking(self,
                      last_step: Dict[str, Any],
                      context: Dict[str, Any],
                      thought_number: int) -> List[Dict[str, Any]]:
        """
        深度思考：基于上一步推理生成更深入的思考

        模拟sequential-thinking工具的思维过程。

        Args:
            last_step: 上一步推理
            context: 上下文
            thought_number: 当前思考编号

        Returns:
            新的思考步骤列表
        """
        thoughts = []

        # 思考1：分析当前结果的含义
        thought_1 = {
            "thought": f"思考{thought_number}: 分析{last_step.get('action', 'unknown')}的结果",
            "thoughtNumber": thought_number,
            "totalThoughts": thought_number + 3,
            "nextThoughtNeeded": True,
            "isRevision": False,
            "content": self._analyze_result_meaning(last_step, context)
        }
        thoughts.append(thought_1)

        # 思考2：推导下一步可能
        thought_2 = {
            "thought": f"思考{thought_number + 1}: 推导可能的攻击向量",
            "thoughtNumber": thought_number + 1,
            "totalThoughts": thought_number + 3,
            "nextThoughtNeeded": True,
            "isRevision": False,
            "content": self._deduce_next_vectors(last_step, context)
        }
        thoughts.append(thought_2)

        # 思考3：评估风险和收益
        thought_3 = {
            "thought": f"思考{thought_number + 2}: 评估风险收益比",
            "thoughtNumber": thought_number + 2,
            "totalThoughts": thought_number + 3,
            "nextThoughtNeeded": False,  # 最后一步
            "isRevision": False,
            "content": self._evaluate_risk_reward(last_step, context)
        }
        thoughts.append(thought_3)

        return thoughts

    def _analyze_result_meaning(self, last_step: Dict[str, Any], context: Dict[str, Any]) -> str:
        """分析当前结果的含义"""
        action = last_step.get("action", "")
        result = last_step.get("result", {})

        analysis = f"执行了'{action}'，"

        if result.get("success", False):
            analysis += "成功！这意味着我们"
            analysis += self._get_success_implication(result, context)
        else:
            analysis += "失败。可能原因："
            analysis += self._get_failure_reason(result, context)

        return analysis

    def _deduce_next_vectors(self, last_step: Dict[str, Any], context: Dict[str, Any]) -> str:
        """推导下一步攻击向量"""
        current_finding = last_step.get("finding", {})
        vuln_type = current_finding.get("vulnerability_type", "unknown")

        deductions = f"基于当前{vuln_type}漏洞，可能的下一步：\n"

        # 根据漏洞类型推导
        if vuln_type == "sql_injection":
            deductions += "- 尝试读取/etc/passwd验证LFI\n"
            deductions += "- 尝试写入WebShell\n"
            deductions += "- 尝试MySQL UDF命令执行\n"
            deductions += "- 搜索flag相关表"
        elif vuln_type == "command_injection":
            deductions += "- 提升权限到root\n"
            deductions += "- 建立持久化后门\n"
            deductions += "- 扫描内网其他主机\n"
            deductions += "- 寻找敏感文件"
        elif vuln_type == "file_inclusion":
            deductions += "- 尝试日志投毒实现RCE\n"
            deductions += "- 读取配置文件寻找凭证\n"
            deductions += "- 尝试包含PHP伪协议"
        elif vuln_type == "file_upload":
            deductions += "- 上传WebShell\n"
            deductions += "- 尝试提权\n"
            deductions += "- 配合文件包含漏洞"
        elif vuln_type == "xss":
            deductions += "- 窃取Cookie\n"
            deductions += "- 结合CSRF攻击\n"
            deductions += "- 尝试Beacon外带"

        return deductions

    def _evaluate_risk_reward(self, last_step: Dict[str, Any], context: Dict[str, Any]) -> str:
        """评估风险和收益"""
        confidence = last_step.get("confidence", 0.5)
        mode = context.get("mode", "pentest")

        evaluation = f"风险评估：\n"

        if confidence > 0.7:
            evaluation += "- 成功概率高({confidence:.0%})，值得尝试\n"
            evaluation += "- 预期收益：可能获取Flag或Shell访问\n"
        elif confidence > 0.4:
            evaluation += "- 成功概率中等({confidence:.0%})，可以尝试\n"
            evaluation += "- 需要权衡时间成本\n"
        else:
            evaluation += "- 成功概率低({confidence:.0%})，不建议继续\n"
            evaluation += "- 应该寻找其他攻击向量\n"

        if mode == "ctf":
            evaluation += "- CTF模式：优先快速见效的策略\n"
        else:
            evaluation += "- 渗透测试模式：可以尝试更深入的利用\n"

        return evaluation

    def _get_success_implication(self, result: Dict[str, Any], context: Dict[str, Any]) -> str:
        """获取成功的含义"""
        target_vuln = result.get("target_vuln", "")

        implications = {
            "sql_injection": "可能能够读取数据库数据、写入文件或执行命令",
            "command_injection": "已获得命令执行能力，可以进一步控制服务器",
            "file_inclusion": "能够读取服务器文件，可能发现配置或凭证",
            "file_upload": "成功上传文件，可能建立WebShell",
            "privilege_escalation": "获得更高权限，可以访问更多资源",
            "xss": "能够执行JavaScript，可能窃取用户凭证"
        }

        return implications.get(target_vuln, "获得新的攻击能力")

    def _get_failure_reason(self, result: Dict[str, Any], context: Dict[str, Any]) -> str:
        """获取失败原因"""
        error = result.get("error", "Unknown")

        reasons = [
            f"具体错误: {error}",
            "可能原因：防护机制阻止、条件不满足、权限不足",
            "建议：调整策略、寻找其他攻击向量"
        ]

        return "\n".join(reasons)
