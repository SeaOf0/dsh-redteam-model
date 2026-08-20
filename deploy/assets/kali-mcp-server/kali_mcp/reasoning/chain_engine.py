"""
链式推理引擎 - 实现深度推理逻辑

模拟黑客思维链，实现"发现推理行动再推理"的循环。
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

from .knowledge_graph import VulnerabilityKnowledgeGraph, VulnerabilityType
from .autonomous_engine import AutonomousReasoningEngine, AutonomousInsight

logger = logging.getLogger(__name__)


class ReasoningStep:
    """
    推理步骤

    记录单次推理的完整信息
    """

    def __init__(self,
                 step_number: int,
                 current_finding: Dict[str, Any],
                 reasoning: str,
                 action_taken: str,
                 result: Dict[str, Any],
                 next_thoughts: List[str],
                 confidence: float):
        """
        Args:
            step_number: 步骤编号
            current_finding: 当前发现
            reasoning: 推理逻辑
            action_taken: 执行的行动
            result: 行动结果
            next_thoughts: 下一步想法
            confidence: 置信度
        """
        self.step_number = step_number
        self.current_finding = current_finding
        self.reasoning = reasoning
        self.action_taken = action_taken
        self.result = result
        self.next_thoughts = next_thoughts
        self.confidence = confidence
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "step": self.step_number,
            "finding": self.current_finding,
            "reasoning": self.reasoning,
            "action": self.action_taken,
            "result": self.result,
            "next_thoughts": self.next_thoughts,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat()
        }


class ChainReasoningEngine:
    """
    链式推理引擎

    实现3-7步深度推理链，模拟黑客的思考过程。
    """

    def __init__(self):
        """初始化推理引擎"""
        self.knowledge_graph = VulnerabilityKnowledgeGraph()
        self.autonomous_engine = AutonomousReasoningEngine()  # 自主推理引擎
        self.reasoning_chain: List[ReasoningStep] = []
        self.autonomous_insights: List[AutonomousInsight] = []  # 自主洞察历史
        self.max_depth = 999  # 动态深度，几乎无限制
        self.min_confidence = 0.3  # 最小置信度阈值
        self.ctf_mode = False  # 是否CTF模式

        # 推理统计
        self.stats = {
            "total_reasoning_steps": 0,
            "successful_chains": 0,
            "failed_chains": 0,
            "average_confidence": 0.0,
            "autonomous_insights_count": 0  # 自主洞察数量
        }

    def reason_chain(self,
                     initial_finding: Dict[str, Any],
                     context: Dict[str, Any],
                     max_depth: Optional[int] = None,
                     time_limit: Optional[int] = None) -> List[ReasoningStep]:
        """
        执行完整的推理链

        Args:
            initial_finding: 初始发现
            context: 上下文信息
            max_depth: 最大推理深度（默认7）
            time_limit: 时间限制（秒）

        Returns:
            推理步骤列表
        """
        self.reasoning_chain = []
        self.ctf_mode = context.get("mode", "pentest") == "ctf"

        # 设置深度限制（几乎无限制，只在没有更多推理路径时停止）
        if max_depth:
            self.max_depth = max_depth
        # CTF模式也不再限制深度，动态决定

        # 设置时间限制
        start_time = datetime.now()
        if time_limit:
            deadline = start_time + timedelta(seconds=time_limit)
        else:
            deadline = None

        current_finding = initial_finding

        logger.info(f"[链式推理] 开始动态深度推理（最大深度: {self.max_depth}）")

        for step_num in range(1, self.max_depth + 1):
            # 检查时间限制
            if deadline and datetime.now() >= deadline:
                logger.warning(f"[链式推理] 达到时间限制，停止推理")
                break

            # 执行单步推理
            step = self._reason_step(
                step_number=step_num,
                current_finding=current_finding,
                context=context
            )

            if not step:
                logger.info(f"[链式推理] 步骤{step_num}：无法继续推理")
                break

            self.reasoning_chain.append(step)

            # 检查是否应该继续
            if not self._should_continue_reasoning(step, context):
                logger.info(f"[链式推理] 完成目标，停止推理")
                break

            # 更新当前发现
            if step.result.get("success", False):
                current_finding = self.result_to_finding(step.result)

        # 更新统计
        self._update_stats()

        return self.reasoning_chain

    def _reason_step(self,
                    step_number: int,
                    current_finding: Dict[str, Any],
                    context: Dict[str, Any]) -> Optional[ReasoningStep]:
        """
        单步推理（集成自主推理能力）

        Args:
            step_number: 步骤编号
            current_finding: 当前发现
            context: 上下文

        Returns:
            推理步骤或None
        """
        vuln_type = current_finding.get("vulnerability_type", "unknown")

        try:
            vuln_enum = VulnerabilityType(vuln_type)
        except ValueError:
            logger.warning(f"[链式推理] 未知漏洞类型: {vuln_type}")
            return None

        # 获取已尝试的攻击链
        attempted_chains = [
            f"{s.current_finding.get('vulnerability_type')}->{s.result.get('target_vuln')}"
            for s in self.reasoning_chain
        ]

        # 首先尝试从预构建知识图谱获取推理链
        chains = self.knowledge_graph.get_next_chains(vuln_enum, context)

        if not chains:
            logger.info(f"[链式推理] 预构建知识图谱中没有找到从{vuln_type}出发的推理链")
            logger.info(f"[链式推理] 触发自主推理引擎，生成创新洞察...")

            # 触发自主推理：生成创新洞察
            insights = self.autonomous_engine.generate_autonomous_insights(
                current_finding=current_finding,
                context=context,
                attempted_chains=attempted_chains
            )

            if not insights:
                logger.info(f"[链式推理] 自主推理也未生成有效洞察，停止")
                return None

            # 记录自主洞察
            self.autonomous_insights.extend(insights)
            self.stats["autonomous_insights_count"] += len(insights)

            # 选择最佳洞察
            best_insight = insights[0]

            # 基于洞察构建推理步骤
            step = ReasoningStep(
                step_number=step_number,
                current_finding=current_finding,
                reasoning=f"[自主推理] {best_insight.reasoning}",
                action_taken=f"尝试创新路径（{best_insight.insight_type}）",
                result={
                    "target_vuln": "unknown",  # 自主推理可能不指向特定漏洞
                    "tools": [],  # 需要根据推理确定工具
                    "reasoning": best_insight.reasoning,
                    "insight_type": best_insight.insight_type,
                    "novelty": best_insight.novelty_score,
                    "success": False
                },
                next_thoughts=[f"这是一个新颖度{best_insight.novelty_score:.0%}的创新思路"],
                confidence=best_insight.feasibility
            )

            logger.info(f"[链式推理] 步骤{step_number}: [自主推理] {best_insight.insight_type}")
            logger.info(f"[链式推理]   推理: {best_insight.reasoning[:100]}...")
            logger.info(f"[链式推理]   新颖度: {best_insight.novelty_score:.2f} | 可行性: {best_insight.feasibility:.2f}")

            return step

        # 如果有预构建攻击链，也尝试生成自主洞察作为补充
        if step_number % 3 == 0:  # 每3步生成一次自主洞察
            insights = self.autonomous_engine.generate_autonomous_insights(
                current_finding=current_finding,
                context=context,
                attempted_chains=attempted_chains
            )

            if insights:
                logger.info(f"[链式推理] 生成了{len(insights)}条补充性自主洞察")
                self.autonomous_insights.extend(insights)
                self.stats["autonomous_insights_count"] += len(insights)

        # 选择最佳推理链
        best_chain = chains[0]  # 已按概率排序

        # 生成推理文本
        reasoning = self._generate_reasoning(
            current_finding,
            best_chain,
            context
        )

        # 生成下一步想法
        next_thoughts = self._generate_next_thoughts(
            best_chain,
            context
        )

        # 计算置信度
        confidence = best_chain.success_prob

        # 构建推理步骤
        step = ReasoningStep(
            step_number=step_number,
            current_finding=current_finding,
            reasoning=reasoning,
            action_taken=f"尝试利用{best_chain.to_vuln.value}",
            result={
                "target_vuln": best_chain.to_vuln.value,
                "tools": best_chain.tools,
                "reasoning": best_chain.reasoning,
                "success": False  # 待执行后更新
            },
            next_thoughts=next_thoughts,
            confidence=confidence
        )

        logger.info(f"[链式推理] 步骤{step_number}: {current_finding.get('vulnerability_type')}  {best_chain.to_vuln.value}")
        logger.info(f"[链式推理]   推理: {reasoning[:100]}...")
        logger.info(f"[链式推理]   置信度: {confidence:.2f}")

        return step

    def _generate_reasoning(self,
                           current_finding: Dict[str, Any],
                           chain: 'AttackChain',
                           context: Dict[str, Any]) -> str:
        """
        生成推理文本

        Args:
            current_finding: 当前发现
            chain: 攻击链
            context: 上下文

        Returns:
            推理文本
        """
        reasoning = f"发现{chain.from_vuln.value}漏洞，"
        reasoning += f"根据知识图谱，可以通过{chain.reasoning}，"
        reasoning += f"进而尝试{chain.to_vuln.value}。"
        reasoning += f"预期成功概率: {chain.success_prob:.0%}，"
        reasoning += f"预计耗时: {chain.time_cost}秒。"

        return reasoning

    def _generate_next_thoughts(self,
                               chain: 'AttackChain',
                               context: Dict[str, Any]) -> List[str]:
        """
        生成下一步想法

        Args:
            chain: 攻击链
            context: 上下文

        Returns:
            想法列表
        """
        thoughts = [
            f"如果{chain.to_vuln.value}成功，下一步可以尝试...",
            f"需要满足条件: {', '.join(chain.conditions)}",
            f"推荐工具: {', '.join(chain.tools[:3])}"
        ]

        # 添加CTF模式的特殊想法
        if self.ctf_mode:
            thoughts.append("CTF模式：优先寻找Flag，快速验证")
        else:
            thoughts.append("渗透测试模式：深度挖掘，完整利用")

        return thoughts

    def _should_continue_reasoning(self, step: ReasoningStep, context: Dict[str, Any]) -> bool:
        """
        判断是否应该继续推理（动态判断）

        不再基于深度限制，而是基于：
        1. 是否有新的推理路径
        2. 置信度是否足够
        3. 是否已经达到目标
        4. 是否进入推理循环

        Args:
            step: 当前推理步骤
            context: 上下文

        Returns:
            是否继续
        """
        # 置信度过低，停止
        if step.confidence < self.min_confidence:
            logger.info(f"[链式推理] 置信度过低({step.confidence:.2f} < {self.min_confidence})，停止推理")
            return False

        # CTF模式：如果找到Flag，可以停止
        if self.ctf_mode and context.get("flags_found", []):
            logger.info("[链式推理] CTF模式已找到Flag，停止推理")
            return False

        # 检查是否达到目标
        if context.get("objectives_achieved", False):
            logger.info("[链式推理] 目标已达成，停止推理")
            return False

        # 检测推理循环：如果连续3步都是相同的漏洞类型，说明进入循环
        if len(self.reasoning_chain) >= 3:
            last_3 = self.reasoning_chain[-3:]
            vuln_types = [s.current_finding.get("vulnerability_type", "unknown") for s in last_3]
            if len(set(vuln_types)) == 1:  # 所有类型都相同
                logger.info(f"[链式推理] 检测到推理循环（{vuln_types[0]}），尝试其他路径")
                # 尝试返回之前的步骤并选择不同路径
                return False

        # 默认继续：只要有新的推理路径就继续深入
        return True

    def result_to_finding(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        将执行结果转换为发现格式

        Args:
            result: 执行结果

        Returns:
            发现字典
        """
        if result.get("success", False):
            return {
                "vulnerability_type": result.get("target_vuln", "unknown"),
                "confidence": result.get("confidence", 0.5),
                "evidence": result.get("evidence", {}),
                "exploitable": True
            }
        else:
            return {
                "vulnerability_type": result.get("target_vuln", "unknown"),
                "confidence": 0.0,
                "error": result.get("error", "Unknown error"),
                "exploitable": False
            }

    def _update_stats(self):
        """更新推理统计"""
        self.stats["total_reasoning_steps"] = len(self.reasoning_chain)

        if self.reasoning_chain:
            total_confidence = sum(step.confidence for step in self.reasoning_chain)
            self.stats["average_confidence"] = total_confidence / len(self.reasoning_chain)

            successful = sum(1 for step in self.reasoning_chain if step.result.get("success", False))
            self.stats["successful_chains"] = successful
            self.stats["failed_chains"] = len(self.reasoning_chain) - successful

    def visualize_chain(self) -> str:
        """
        可视化推理链（包含自主洞察）

        Returns:
            文本格式的推理链
        """
        if not self.reasoning_chain:
            return "推理链为空"

        lines = []
        lines.append("")
        lines.append("=" * 80)
        lines.append("链式推理过程可视化")
        lines.append("=" * 80)
        lines.append("")

        # 绘制推理链
        for step in self.reasoning_chain:
            # 判断是否是自主推理
            is_autonomous = step.result.get("insight_type") is not None

            if is_autonomous:
                lines.append(f"\n[步骤 {step.step_number}] [自主推理 - {step.result.get('insight_type')}] 置信度: {step.confidence:.2f}")
                lines.append(f"  当前发现: {step.current_finding.get('vulnerability_type', 'unknown')}")
                lines.append(f"  推理逻辑: {step.reasoning}")
                lines.append(f"  执行行动: {step.action_taken}")
                if step.result.get("novelty"):
                    lines.append(f"  新颖度: {step.result.get('novelty'):.0%}")
            else:
                lines.append(f"\n[步骤 {step.step_number}] 置信度: {step.confidence:.2f}")
                lines.append(f"  当前发现: {step.current_finding.get('vulnerability_type', 'unknown')}")
                lines.append(f"  推理逻辑: {step.reasoning}")
                lines.append(f"  执行行动: {step.action_taken}")

            if step.next_thoughts:
                lines.append(f"  下一步:")
                for thought in step.next_thoughts:
                    lines.append(f"    - {thought}")

        # 显示自主洞察统计
        if self.autonomous_insights:
            lines.append("\n" + "-" * 80)
            lines.append("自主推理洞察（灵光一闪）")
            lines.append("-" * 80)
            lines.append(f"  总洞察数: {len(self.autonomous_insights)}")

            # 按类型统计
            insight_types = {}
            for insight in self.autonomous_insights:
                insight_types[insight.insight_type] = insight_types.get(insight.insight_type, 0) + 1

            for insight_type, count in insight_types.items():
                lines.append(f"  {insight_type}: {count}条")

        # 推理统计
        lines.append("\n" + "=" * 80)
        lines.append("推理统计")
        lines.append("=" * 80)
        lines.append(f"  总推理步骤: {self.stats['total_reasoning_steps']}")
        lines.append(f"  成功链数: {self.stats['successful_chains']}")
        lines.append(f"  失败链数: {self.stats['failed_chains']}")
        lines.append(f"  平均置信度: {self.stats['average_confidence']:.2f}")
        lines.append(f"  自主洞察数: {self.stats.get('autonomous_insights_count', 0)}")
        lines.append("")
        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    def get_summary(self) -> Dict[str, Any]:
        """
        获取推理摘要

        Returns:
            摘要字典
        """
        return {
            "total_steps": len(self.reasoning_chain),
            "depth_reached": len(self.reasoning_chain),
            "max_depth": self.max_depth,
            "stats": self.stats,
            "chain": [step.to_dict() for step in self.reasoning_chain]
        }
