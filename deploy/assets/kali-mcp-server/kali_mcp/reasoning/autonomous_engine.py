"""
自主推理引擎 - 实现自主分析和创新推理能力

模拟人类黑客的"灵光一闪"和自我探索能力
"""

from typing import Dict, List, Any, Optional, Tuple
import random
import logging
from datetime import datetime

from .knowledge_graph import VulnerabilityKnowledgeGraph, VulnerabilityType, AttackChain

logger = logging.getLogger(__name__)


class AutonomousInsight:
    """
    自主洞察

    记录一次"灵光一闪"的创新推理
    """

    def __init__(self,
                 insight_type: str,
                 reasoning: str,
                 novelty_score: float,
                 feasibility: float,
                 estimated_time: int):
        """
        Args:
            insight_type: 洞察类型 (cross_domain, reverse_engineering, pattern_matching, mutation)
            reasoning: 推理逻辑
            novelty_score: 新颖度评分 (0-1)
            feasibility: 可行性评分 (0-1)
            estimated_time: 预计耗时（秒）
        """
        self.insight_type = insight_type
        self.reasoning = reasoning
        self.novelty_score = novelty_score
        self.feasibility = feasibility
        self.estimated_time = estimated_time
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "type": self.insight_type,
            "reasoning": self.reasoning,
            "novelty": self.novelty_score,
            "feasibility": self.feasibility,
            "time": self.estimated_time,
            "timestamp": self.timestamp.isoformat()
        }


class AutonomousReasoningEngine:
    """
    自主推理引擎

    实现以下能力：
    1. 动态路径生成 - 超越预构建的攻击链
    2. 灵光一闪 - 创新性发现新攻击向量
    3. 自我探索 - 主动探索未知的漏洞组合
    4. 跨域迁移 - 将一个领域的技术应用到另一个领域
    """

    def __init__(self):
        """初始化自主推理引擎"""
        self.knowledge_graph = VulnerabilityKnowledgeGraph()
        self.insights_history: List[AutonomousInsight] = []

        # 探索统计
        self.exploration_stats = {
            "total_insights": 0,
            "successful_insights": 0,
            "cross_domain_insights": 0,
            "mutation_insights": 0,
            "reverse_engineering_insights": 0,
            "pattern_matching_insights": 0
        }

        # 跨领域映射 - 将一个领域的技术映射到另一个领域
        self.cross_domain_mappings = {
            # SQL注入技术  其他领域
            "sql_injection": {
                "to_command_injection": [
                    "利用SQL注入的命令执行能力（xp_cmdshell, sys_exec）",
                    "通过SQL注入写入WebShell，然后执行命令",
                    "利用数据库UDF执行系统命令"
                ],
                "to_file_inclusion": [
                    "利用LOAD_FILE()函数读取文件",
                    "利用INTO DUMPFILE写入文件",
                    "利用Oracle UTL_FILE读取/写入文件"
                ],
                "to_ssrf": [
                    "利用MySQL LOAD_FILE读取本地文件触发SSRF",
                    "利用PostgreSQL COPY TO外带数据"
                ]
            },
            # 命令注入技术  其他领域
            "command_injection": {
                "to_file_inclusion": [
                    "通过cat/tail等命令读取文件",
                    "通过find命令搜索敏感文件",
                    "通过grep命令搜索配置文件中的密码"
                ],
                "to_privilege_escalation": [
                    "利用SUID二进制提权",
                    "利用内核漏洞提权",
                    "利用Cron job提权",
                    "利用PATH变量劫持提权"
                ],
                "to_sql_injection": [
                    "通过命令行连接数据库",
                    "通过mysqldump导出数据"
                ]
            },
            # 文件包含技术  其他领域
            "file_inclusion": {
                "to_command_injection": [
                    "通过LFI读取SSH密钥",
                    "通过LFI包含日志文件注入PHP代码",
                    "通过LFI包含uploads目录中的图片马",
                    "通过PHP伪协议expect执行命令"
                ],
                "to_file_upload": [
                    "通过LFI找到已上传的WebShell路径",
                    "通过LFI包含已上传的图片马"
                ],
                "to_sql_injection": [
                    "通过LFI读取数据库配置文件",
                    "通过LFI读取WordPress配置获取数据库凭据"
                ]
            },
            # XSS技术  其他领域
            "xss": {
                "to_command_injection": [
                    "XSS窃取管理员Cookie后台上传WebShell",
                    "结合CSRF自动上传WebShell"
                ],
                "to_ssrf": [
                    "XSS绕过SSRF防护（通过JavaScript发起请求）"
                ]
            },
            # SSRF技术  其他领域
            "ssrf": {
                "to_file_inclusion": [
                    "通过SSRF读取本地文件（file://协议）",
                    "通过SSRF扫描内网服务"
                ],
                "to_command_injection": [
                    "通过SSRF攻击Redis（GET /）",
                    "通过SSRF攻击FastCGI",
                    "通过SSRF攻击内网RCE服务"
                ]
            }
        }

        # 常见创新模式 - 从历史成功案例中提取
        self.innovation_patterns = [
            "绕过WAF：使用{technique_1} + {technique_2}组合",
            "提权路径：{vuln_1}  {vuln_2}  {vuln_3}",
            "数据外带：使用{protocol}协议绕过网络限制",
            "持久化：通过{method}建立隐蔽后门",
            "绕过限制：将{attack_type}转化为{another_type}",
            "组合利用：{vuln_1} + {vuln_2} = {new_effect}"
        ]

    def generate_autonomous_insights(self,
                                    current_finding: Dict[str, Any],
                                    context: Dict[str, Any],
                                    attempted_chains: List[str] = None) -> List[AutonomousInsight]:
        """
        生成自主洞察 - 实现"灵光一闪"

        Args:
            current_finding: 当前发现
            context: 上下文信息
            attempted_chains: 已尝试的攻击链（避免重复）

        Returns:
            洞察列表
        """
        insights = []
        attempted_chains = attempted_chains or []

        vuln_type = current_finding.get("vulnerability_type", "unknown")

        try:
            vuln_enum = VulnerabilityType(vuln_type)
        except ValueError:
            logger.warning(f"[自主推理] 未知漏洞类型: {vuln_type}")
            return insights

        logger.info(f"[自主推理] 为{vuln_type}生成创新洞察...")

        # 方法1: 跨域迁移
        cross_domain_insights = self._cross_domain_reasoning(vuln_enum, context, attempted_chains)
        insights.extend(cross_domain_insights)

        # 方法2: 反向推理
        reverse_insights = self._reverse_engineering_reasoning(vuln_enum, context, attempted_chains)
        insights.extend(reverse_insights)

        # 方法3: 随机突变
        mutation_insights = self._mutation_based_reasoning(vuln_enum, context, attempted_chains)
        insights.extend(mutation_insights)

        # 方法4: 模式匹配
        pattern_insights = self._pattern_matching_reasoning(current_finding, context, attempted_chains)
        insights.extend(pattern_insights)

        # 方法5: 好奇心探索
        exploration_insights = self._curiosity_driven_exploration(vuln_enum, context, attempted_chains)
        insights.extend(exploration_insights)

        # 按新颖度和可行性排序
        insights.sort(
            key=lambda i: (i.novelty_score * 0.6 + i.feasibility * 0.4),
            reverse=True
        )

        # 记录洞察历史
        self.insights_history.extend(insights)

        # 更新统计
        self._update_insight_stats(insights)

        logger.info(f"[自主推理] 生成了{len(insights)}条创新洞察")

        return insights

    def _cross_domain_reasoning(self,
                                vuln_type: VulnerabilityType,
                                context: Dict[str, Any],
                                attempted_chains: List[str]) -> List[AutonomousInsight]:
        """
        跨域迁移推理

        将一个领域的成功技术应用到另一个领域

        Args:
            vuln_type: 当前漏洞类型
            context: 上下文
            attempted_chains: 已尝试的攻击链

        Returns:
            洞察列表
        """
        insights = []
        vuln_name = vuln_type.value

        # 检查是否有跨域映射
        if vuln_name not in self.cross_domain_mappings:
            return insights

        mappings = self.cross_domain_mappings[vuln_name]

        for target_vuln_str, techniques in mappings.items():
            # 跳过已尝试的路径
            chain_id = f"{vuln_name}->{target_vuln_str}"
            if chain_id in attempted_chains:
                continue

            try:
                target_vuln = VulnerabilityType(target_vuln_str.replace("to_", ""))

                # 为每个技术生成洞察
                for technique in techniques:
                    insight = AutonomousInsight(
                        insight_type="cross_domain",
                        reasoning=f"跨域迁移：利用{vuln_name}的技术，{technique}，进而实现{target_vuln.value}",
                        novelty_score=0.7,
                        feasibility=0.6,
                        estimated_time=40
                    )
                    insights.append(insight)

            except ValueError:
                # 目标漏洞类型不存在，跳过
                continue

        if insights:
            logger.info(f"[自主推理] 跨域迁移生成{len(insights)}条洞察")

        return insights

    def _reverse_engineering_reasoning(self,
                                      vuln_type: VulnerabilityType,
                                      context: Dict[str, Any],
                                      attempted_chains: List[str]) -> List[AutonomousInsight]:
        """
        反向推理

        从目标倒推可能的攻击路径

        Args:
            vuln_type: 当前漏洞类型
            context: 上下文
            attempted_chains: 已尝试的攻击链

        Returns:
            洞察列表
        """
        insights = []

        # 定义常见目标
        goals = {
            "privilege_escalation": "提权",
            "command_injection": "命令执行",
            "file_inclusion": "读取文件",
            "flag": "获取Flag"
        }

        # 对于每个目标，倒推可能的路径
        for goal_vuln_str, goal_name in goals.items():
            try:
                if goal_vuln_str == "flag":
                    goal_vuln = vuln_type  # Flag不是一个漏洞类型
                else:
                    goal_vuln = VulnerabilityType(goal_vuln_str)

                # 生成反向推理路径
                reasoning = f"反向思考：目标是{goal_name}，从{vuln_type.value}出发，"
                reasoning += f"可能需要先利用中间漏洞跳板，最终实现{goal_name}"

                # 检查是否已尝试
                chain_id = f"{vuln_type.value}->{goal_vuln_str}"
                if chain_id not in attempted_chains:
                    insight = AutonomousInsight(
                        insight_type="reverse_engineering",
                        reasoning=reasoning,
                        novelty_score=0.5,
                        feasibility=0.7,
                        estimated_time=50
                    )
                    insights.append(insight)

            except ValueError:
                continue

        if insights:
            logger.info(f"[自主推理] 反向推理生成{len(insights)}条洞察")

        return insights

    def _mutation_based_reasoning(self,
                                  vuln_type: VulnerabilityType,
                                  context: Dict[str, Any],
                                  attempted_chains: List[str]) -> List[AutonomousInsight]:
        """
        基于突变的推理

        在现有攻击链中引入随机变化，探索新路径

        Args:
            vuln_type: 当前漏洞类型
            context: 上下文
            attempted_chains: 已尝试的攻击链

        Returns:
            洞察列表
        """
        insights = []

        # 获取现有的攻击链
        existing_chains = self.knowledge_graph.get_next_chains(vuln_type, context)

        # 对每条现有链进行突变
        for chain in existing_chains[:3]:  # 只对前3条进行突变
            # 突变1: 改变工具组合
            if len(chain.tools) > 1:
                # 随机交换工具顺序
                mutated_tools = chain.tools[1:] + [chain.tools[0]]
                reasoning = f"突变创新：{chain.reasoning}，尝试使用不同的工具组合：{mutated_tools}"

                insight = AutonomousInsight(
                    insight_type="mutation",
                    reasoning=reasoning,
                    novelty_score=0.4,
                    feasibility=0.65,
                    estimated_time=chain.time_cost + 10
                )
                insights.append(insight)

            # 突变2: 绕过WAF的变体
            if context.get("waf_detected", False):
                reasoning = f"突变创新：{chain.reasoning}，加入WAF绕过技术（编码、注释、分块）"

                insight = AutonomousInsight(
                    insight_type="mutation",
                    reasoning=reasoning,
                    novelty_score=0.5,
                    feasibility=0.55,
                    estimated_time=chain.time_cost + 20
                )
                insights.append(insight)

        if insights:
            logger.info(f"[自主推理] 突变推理生成{len(insights)}条洞察")

        return insights

    def _pattern_matching_reasoning(self,
                                    current_finding: Dict[str, Any],
                                    context: Dict[str, Any],
                                    attempted_chains: List[str]) -> List[AutonomousInsight]:
        """
        模式匹配推理

        从历史成功模式中匹配当前情况

        Args:
            current_finding: 当前发现
            context: 上下文
            attempted_chains: 已尝试的攻击链

        Returns:
            洞察列表
        """
        insights = []

        # 提取当前情况的特征
        vuln_type = current_finding.get("vulnerability_type", "")
        evidence = current_finding.get("evidence", {})
        target = context.get("target", "")

        # 模式1: 如果目标有上传功能
        if evidence.get("has_upload", False):
            reasoning = f"模式匹配：发现{vuln_type} + 文件上传功能，可能可以组合利用"
            insight = AutonomousInsight(
                insight_type="pattern_matching",
                reasoning=reasoning,
                novelty_score=0.6,
                feasibility=0.7,
                estimated_time=35
            )
            insights.append(insight)

        # 模式2: 如果是数据库相关
        db_type = evidence.get("db_type", "")
        if db_type:
            reasoning = f"模式匹配：检测到{db_type}数据库，可以利用{db_type}特有的利用技术"
            insight = AutonomousInsight(
                insight_type="pattern_matching",
                reasoning=reasoning,
                novelty_score=0.5,
                feasibility=0.75,
                estimated_time=30
            )
            insights.append(insight)

        # 模式3: 如果有WAF
        if context.get("waf_detected", False):
            reasoning = "模式匹配：检测到WAF，所有攻击都需要考虑绕过策略"
            insight = AutonomousInsight(
                insight_type="pattern_matching",
                reasoning=reasoning,
                novelty_score=0.4,
                feasibility=0.6,
                estimated_time=45
            )
            insights.append(insight)

        if insights:
            logger.info(f"[自主推理] 模式匹配生成{len(insights)}条洞察")

        return insights

    def _curiosity_driven_exploration(self,
                                     vuln_type: VulnerabilityType,
                                     context: Dict[str, Any],
                                     attempted_chains: List[str]) -> List[AutonomousInsight]:
        """
        好奇心驱动的探索

        主动探索未知的、非直观的漏洞组合

        Args:
            vuln_type: 当前漏洞类型
            context: 上下文
            attempted_chains: 已尝试的攻击链

        Returns:
            洞察列表
        """
        insights = []

        # 获取所有可能的漏洞类型
        all_vuln_types = list(VulnerabilityType)

        # 随机选择几个非直观的组合进行探索
        for _ in range(3):  # 生成3个探索性洞察
            target_vuln = random.choice(all_vuln_types)

            # 跳过相同的漏洞类型
            if target_vuln == vuln_type:
                continue

            # 跳过已尝试的
            chain_id = f"{vuln_type.value}->{target_vuln.value}"
            if chain_id in attempted_chains:
                continue

            # 生成探索性推理
            reasoning = f"好奇心探索：尝试非直观的组合 {vuln_type.value}  {target_vuln.value}，"
            reasoning += "虽然预构建知识图谱中没有这条路径，但可能存在未知的利用方式"

            insight = AutonomousInsight(
                insight_type="exploration",
                reasoning=reasoning,
                novelty_score=0.9,  # 高新颖度
                feasibility=0.3,   # 低可行性（因为是未知的）
                estimated_time=60
            )
            insights.append(insight)

        if insights:
            logger.info(f"[自主推理] 好奇心探索生成{len(insights)}条洞察")

        return insights

    def _update_insight_stats(self, insights: List[AutonomousInsight]):
        """更新洞察统计"""
        self.exploration_stats["total_insights"] += len(insights)

        for insight in insights:
            if insight.insight_type == "cross_domain":
                self.exploration_stats["cross_domain_insights"] += 1
            elif insight.insight_type == "mutation":
                self.exploration_stats["mutation_insights"] += 1
            elif insight.insight_type == "reverse_engineering":
                self.exploration_stats["reverse_engineering_insights"] += 1
            elif insight.insight_type == "pattern_matching":
                self.exploration_stats["pattern_matching_insights"] += 1

    def get_exploration_stats(self) -> Dict[str, Any]:
        """获取探索统计"""
        return {
            **self.exploration_stats,
            "recent_insights": [i.to_dict() for i in self.insights_history[-10:]]
        }

    def visualize_insights(self, insights: List[AutonomousInsight]) -> str:
        """
        可视化洞察列表

        Args:
            insights: 洞察列表

        Returns:
            文本格式的可视化
        """
        if not insights:
            return "未生成创新洞察"

        lines = []
        lines.append("")
        lines.append("=" * 80)
        lines.append("自主推理洞察 - 灵光一闪")
        lines.append("=" * 80)
        lines.append("")

        for i, insight in enumerate(insights, 1):
            lines.append(f"[洞察 {i}] {insight.insight_type}")
            lines.append(f"  新颖度: {insight.novelty_score:.0%} | 可行性: {insight.feasibility:.0%} | 预计: {insight.estimated_time}秒")
            lines.append(f"  推理: {insight.reasoning}")
            lines.append("")

        lines.append("-" * 80)
        lines.append(f"总计: {len(insights)} 条创新洞察")
        lines.append("-" * 80)
        lines.append("")

        return "\n".join(lines)
