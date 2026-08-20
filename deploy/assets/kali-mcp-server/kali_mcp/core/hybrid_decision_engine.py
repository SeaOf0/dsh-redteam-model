#!/usr/bin/env python3
"""
混合决策引擎 (HybridDecisionEngine)

结合中心战略决策和智能体战术决策：
- 战略决策模型（中心调控层）
- 战术决策模型（智能体层）
- 决策融合机制
- 上下文感知决策优化
- 决策历史追踪和学习

作者: SeaOf0
"""

import logging
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
import json

from kali_mcp.core.intent_analyzer import (
    IntentAnalysis,
    AttackIntent,
    TargetInfo,
    TargetType
)
from kali_mcp.core.task_decomposer import (
    Task,
    TaskGraph,
    TaskCategory,
    ExecutionPlan
)
from kali_mcp.core.agent_scheduler import (
    SchedulingStrategy,
    SchedulingDecision
)
from kali_mcp.core.agent_registry import BaseAgentV2, LoadReport

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class DecisionLevel(Enum):
    """决策层级"""
    STRATEGIC = "strategic"     # 战略层（中心调控）
    TACTICAL = "tactical"       # 战术层（智能体）
    OPERATIONAL = "operational" # 操作层（工具执行）


class DecisionType(Enum):
    """决策类型"""
    ATTACK_PATH = "attack_path"           # 攻击路径选择
    AGENT_SELECTION = "agent_selection"   # 智能体选择
    TOOL_SELECTION = "tool_selection"     # 工具选择
    PRIORITY_ADJUSTMENT = "priority"      # 优先级调整
    RESOURCE_ALLOCATION = "resource"      # 资源分配
    STRATEGY_SWITCH = "strategy_switch"   # 策略切换


@dataclass
class DecisionContext:
    """决策上下文"""
    intent_analysis: Optional[IntentAnalysis] = None        # 意图分析结果
    task_graph: Optional[TaskGraph] = None                  # 当前任务图
    available_agents: List[BaseAgentV2] = field(default_factory=list)    # 可用智能体
    system_load: Dict[str, float] = field(default_factory=dict)          # 系统负载 {cpu, memory, network}
    time_constraint: Optional[int] = None  # 时间约束（秒）
    resource_budget: Optional[Dict] = None # 资源预算

    # 兼容旧版字段
    intent: Optional[AttackIntent] = None
    targets: List[str] = field(default_factory=list)
    constraints: List[Any] = field(default_factory=list)
    available_resources: Optional[int] = None
    current_phase: str = "planning"
    execution_results: List[Dict[str, Any]] = field(default_factory=list)

    # 历史信息
    previous_decisions: List["Decision"] = field(default_factory=list)
    success_history: Dict[str, float] = field(default_factory=dict)  # {strategy: success_rate}

    # 实时状态
    running_tasks: List[str] = field(default_factory=list)
    completed_tasks: List[str] = field(default_factory=list)
    failed_tasks: List[str] = field(default_factory=list)
    discovered_assets: Set[str] = field(default_factory=set)

    def __post_init__(self):
        """兼容初始化：允许旧版字段构造DecisionContext。"""
        if self.intent_analysis is None:
            parsed_targets = [
                TargetInfo(
                    original=target,
                    type=TargetType.URL if target.startswith(("http://", "https://")) else TargetType.DOMAIN,
                    value=target
                )
                for target in self.targets
            ]
            self.intent_analysis = IntentAnalysis(
                user_input="",
                intent=self.intent or AttackIntent.RECONNAISSANCE,
                targets=parsed_targets,
                constraints=self.constraints or [],
                priority=5,
                confidence=0.8
            )

        if self.task_graph is None:
            self.task_graph = TaskGraph(tasks={})

        if not self.system_load:
            self.system_load = {"cpu": 0.5, "memory": 0.5, "network": 0.5}


@dataclass
class DecisionOption:
    """决策选项"""
    option_id: str                         # 选项ID
    description: str                       # 描述
    actions: List[str]                     # 行动列表
    expected_benefit: float                # 预期收益 (0-1)
    expected_cost: float                   # 预期成本 (0-1)
    risk_level: float                      # 风险等级 (0-1)
    confidence: float                      # 置信度 (0-1)

    # 约束检查
    required_resources: Dict[str, float] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)

    def calculate_score(self, risk_tolerance: float = 0.5) -> float:
        """
        计算综合得分

        Args:
            risk_tolerance: 风险承受度 (0=保守, 1=激进)

        Returns:
            综合得分 (越高的选项越优)
        """
        # 基础得分：收益 - 成本
        base_score = self.expected_benefit * 0.6 - self.expected_cost * 0.4

        # 风险调整：根据风险承受度调整
        # 低风险承受度：严重惩罚高风险
        # 高风险承受度：轻微惩罚高风险
        if risk_tolerance < 0.3:  # 保守
            risk_penalty = self.risk_level * 0.5  # 高风险惩罚
        elif risk_tolerance > 0.7:  # 激进
            risk_penalty = self.risk_level * 0.1  # 低风险惩罚
        else:  # 中等
            risk_penalty = self.risk_level * 0.3

        final_score = base_score - risk_penalty

        # 确保得分在合理范围内
        final_score = max(-1.0, min(1.0, final_score))

        # 考虑置信度
        return final_score * self.confidence


@dataclass
class Decision:
    """决策结果"""
    decision_id: str                      # 决策ID
    decision_type: DecisionType           # 决策类型
    decision_level: DecisionLevel         # 决策层级
    context: DecisionContext              # 决策上下文

    # 决策内容
    selected_option: DecisionOption       # 选中选项
    rejected_options: List[DecisionOption] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)  # 推理过程

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None

    # 执行结果
    execution_status: str = "pending"     # pending, executing, completed, failed
    execution_result: Optional[Dict] = None
    actual_benefit: Optional[float] = None
    feedback: Optional[str] = None


@dataclass
class StrategicDecision(Decision):
    """战略决策"""
    attack_strategy: str = ""             # 攻击策略
    target_priorities: Dict[str, int] = field(default_factory=dict)  # 目标优先级
    resource_allocation: Dict[str, float] = field(default_factory=dict)  # 资源分配
    estimated_duration: int = 0           # 预估时长（秒）


@dataclass
class TacticalDecision(Decision):
    """战术决策"""
    selected_agents: List[str] = field(default_factory=list)  # 选中的智能体
    task_sequence: List[str] = field(default_factory=list)     # 任务序列
    parallel_groups: List[List[str]] = field(default_factory=list)  # 并行组


# ==================== 决策模型 ====================

class DecisionModel:
    """决策模型基类"""

    def __init__(self, model_name: str):
        self.model_name = model_name
        self.decision_history: List[Decision] = []
        self.performance_metrics: Dict[str, float] = {}

    async def decide(self, context: DecisionContext) -> Decision:
        """生成决策"""
        raise NotImplementedError

    def learn_from_outcome(self, decision: Decision):
        """从决策结果中学习"""
        self.decision_history.append(decision)

        # 更新性能指标
        if decision.actual_benefit is not None:
            key = f"{decision.decision_type.value}_{decision.decision_level.value}"
            if key not in self.performance_metrics:
                self.performance_metrics[key] = []
            self.performance_metrics[key].append(decision.actual_benefit)

    def get_average_performance(self, decision_type: DecisionType,
                               decision_level: DecisionLevel) -> float:
        """获取平均性能"""
        key = f"{decision_type.value}_{decision_level.value}"
        if key in self.performance_metrics and self.performance_metrics[key]:
            return sum(self.performance_metrics[key]) / len(self.performance_metrics[key])
        return 0.5  # 默认中等性能


class StrategicDecisionModel(DecisionModel):
    """战略决策模型（中心调控层）"""

    def __init__(self):
        super().__init__("strategic_model")

        # 策略模板
        self.strategy_templates = {
            AttackIntent.CTF_SOLVING: {
                "name": "ctf_intensive",
                "time_distribution": {"recon": 0.1, "scan": 0.3, "exploit": 0.6},
                "parallelism": "high",
                "risk_tolerance": 0.8
            },
            AttackIntent.APT_SIMULATION: {
                "name": "comprehensive_apt",
                "time_distribution": {"recon": 0.3, "scan": 0.4, "exploit": 0.3},
                "parallelism": "medium",
                "risk_tolerance": 0.3
            },
            AttackIntent.RECONNAISSANCE: {
                "name": "fast_recon",
                "time_distribution": {"recon": 1.0},
                "parallelism": "high",
                "risk_tolerance": 0.1
            },
            AttackIntent.VULNERABILITY_SCANNING: {
                "name": "vuln_scan",
                "time_distribution": {"recon": 0.2, "scan": 0.8},
                "parallelism": "medium",
                "risk_tolerance": 0.2
            },
            AttackIntent.EXPLOITATION: {
                "name": "exploit_chain",
                "time_distribution": {"recon": 0.1, "scan": 0.2, "exploit": 0.7},
                "parallelism": "low",
                "risk_tolerance": 0.6
            }
        }

    async def decide(self, context: DecisionContext) -> StrategicDecision:
        """
        生成战略决策

        考虑因素：
        - 意图类型和优先级
        - 目标特征（数量、类型）
        - 约束条件（时间、资源）
        - 历史成功率
        """
        reasoning = []

        # 1. 选择攻击策略
        intent = context.intent_analysis.intent
        strategy = self.strategy_templates.get(intent, self.strategy_templates[AttackIntent.RECONNAISSANCE])
        reasoning.append(f"选择策略: {strategy['name']} 基于意图 {intent.value}")

        # 2. 确定时间分配
        total_time = context.time_constraint or 3600  # 默认1小时
        time_distribution = {}
        for phase, ratio in strategy["time_distribution"].items():
            time_distribution[phase] = int(total_time * ratio)
        reasoning.append(f"时间分配: {time_distribution}")

        # 3. 确定并行度
        parallelism = strategy["parallelism"]
        if parallelism == "high":
            max_parallel = 8
        elif parallelism == "medium":
            max_parallel = 4
        else:  # low
            max_parallel = 2

        # 根据系统负载调整
        cpu_load = context.system_load.get("cpu", 0.5)
        if cpu_load > 0.8:
            max_parallel = max(1, max_parallel // 2)
        reasoning.append(f"并行度: {max_parallel} (基于策略和系统负载)")

        # 4. 目标优先级排序
        target_priorities = self._calculate_target_priorities(context)
        reasoning.append(f"目标优先级: {target_priorities}")

        # 5. 资源分配
        resource_allocation = self._allocate_resources(context, max_parallel)
        reasoning.append(f"资源分配: {resource_allocation}")

        # 6. 生成决策选项
        options = self._generate_strategic_options(
            context, strategy, time_distribution, max_parallel, target_priorities
        )

        # 7. 选择最佳选项
        selected = self._select_best_option(options, strategy["risk_tolerance"])

        decision = StrategicDecision(
            decision_id=f"strategic_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            decision_type=DecisionType.ATTACK_PATH,
            decision_level=DecisionLevel.STRATEGIC,
            context=context,
            selected_option=selected,
            rejected_options=[opt for opt in options if opt != selected],
            reasoning=reasoning,
            attack_strategy=strategy["name"],
            target_priorities=target_priorities,
            resource_allocation=resource_allocation,
            estimated_duration=total_time
        )

        logger.info(f"战略决策生成完成: {strategy['name']}, 并行度={max_parallel}")

        return decision

    def _calculate_target_priorities(self, context: DecisionContext) -> Dict[str, int]:
        """计算目标优先级"""
        priorities = {}

        for target in context.intent_analysis.targets:
            priority = 5  # 基础优先级

            # CTF目标提高优先级
            if target.is_ctf:
                priority += 3

            # 根据目标类型调整
            if target.type == TargetType.URL:
                priority += 1  # Web目标通常更容易

            # 根据约束调整
            for constraint in context.intent_analysis.constraints:
                if constraint.get("type") == "time_limit":
                    priority += 2

            priorities[target.value] = min(10, max(1, priority))

        return priorities

    def _allocate_resources(self, context: DecisionContext,
                          max_parallel: int) -> Dict[str, float]:
        """分配资源"""
        allocation = {}

        # 基于智能体数量分配
        total_agents = len(context.available_agents)
        if total_agents > 0:
            per_agent = 1.0 / min(total_agents, max_parallel)
            for agent in context.available_agents[:max_parallel]:
                allocation[agent.agent_id] = per_agent

        return allocation

    def _generate_strategic_options(self, context: DecisionContext,
                                  strategy: Dict, time_distribution: Dict[str, int],
                                  max_parallel: int, target_priorities: Dict[str, int]) -> List[DecisionOption]:
        """生成战略选项"""
        options = []

        # 选项1: 激进策略
        options.append(DecisionOption(
            option_id="aggressive",
            description="激进快速攻击",
            actions=["parallel_execution", "skip_non_critical", "max_parallelism"],
            expected_benefit=0.8,
            expected_cost=0.7,
            risk_level=0.6,
            confidence=0.9,
            required_resources={"cpu": 0.8, "memory": 0.6}
        ))

        # 选项2: 平衡策略
        options.append(DecisionOption(
            option_id="balanced",
            description="平衡稳步推进",
            actions=["phased_execution", "full_coverage", "moderate_parallelism"],
            expected_benefit=0.7,
            expected_cost=0.5,
            risk_level=0.3,
            confidence=0.95,
            required_resources={"cpu": 0.5, "memory": 0.4}
        ))

        # 选项3: 保守策略
        options.append(DecisionOption(
            option_id="conservative",
            description="保守谨慎执行",
            actions=["sequential_execution", "verify_each_step", "minimal_parallelism"],
            expected_benefit=0.5,
            expected_cost=0.3,
            risk_level=0.1,
            confidence=0.99,
            required_resources={"cpu": 0.3, "memory": 0.2}
        ))

        return options

    def _select_best_option(self, options: List[DecisionOption],
                          risk_tolerance: float) -> DecisionOption:
        """选择最佳选项"""
        scored = [(opt.calculate_score(risk_tolerance), opt) for opt in options]
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1]


class TacticalDecisionModel(DecisionModel):
    """战术决策模型（智能体层）"""

    def __init__(self):
        super().__init__("tactical_model")

    async def decide(self, context: DecisionContext) -> TacticalDecision:
        """
        生成战术决策

        考虑因素：
        - 当前任务状态
        - 可用智能体能力
        - 任务依赖关系
        - 负载均衡
        """
        reasoning = []

        # 1. 分析当前任务状态
        ready_tasks = context.task_graph.get_ready_tasks()
        reasoning.append(f"就绪任务数: {len(ready_tasks)}")

        # 2. 对任务分组
        task_groups = self._group_tasks_by_priority(ready_tasks)
        reasoning.append(f"任务分组: 高优先级={len(task_groups.get('high', []))}, "
                       f"中优先级={len(task_groups.get('medium', []))}, "
                       f"低优先级={len(task_groups.get('low', []))}")

        # 3. 选择智能体
        agent_assignments = await self._select_agents_for_tasks(
            task_groups.get('high', []), context
        )
        reasoning.append(f"智能体分配: {len(agent_assignments)}个任务已分配")

        # 4. 确定执行序列
        task_sequence, parallel_groups = self._plan_execution_sequence(
            task_groups, agent_assignments, context
        )
        reasoning.append(f"执行序列: {len(task_sequence)}个串行任务, "
                       f"{len(parallel_groups)}个并行组")

        # 5. 生成决策选项
        options = self._generate_tactical_options(context, task_groups)

        # 6. 选择最佳选项
        selected = self._select_best_option(options)

        decision = TacticalDecision(
            decision_id=f"tactical_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            decision_type=DecisionType.AGENT_SELECTION,
            decision_level=DecisionLevel.TACTICAL,
            context=context,
            selected_option=selected,
            rejected_options=[opt for opt in options if opt != selected],
            reasoning=reasoning,
            selected_agents=list(agent_assignments.keys()),
            task_sequence=task_sequence,
            parallel_groups=parallel_groups
        )

        logger.info(f"战术决策生成完成: {len(agent_assignments)}个智能体分配")

        return decision

    def _group_tasks_by_priority(self, tasks: List[Task]) -> Dict[str, List[Task]]:
        """按优先级分组任务"""
        groups = {"high": [], "medium": [], "low": []}

        for task in tasks:
            if task.priority >= 8:
                groups["high"].append(task)
            elif task.priority >= 5:
                groups["medium"].append(task)
            else:
                groups["low"].append(task)

        return groups

    async def _select_agents_for_tasks(self, tasks: List[Task],
                                      context: DecisionContext) -> Dict[str, str]:
        """为任务选择智能体"""
        assignments = {}

        for task in tasks:
            # 查找有此工具能力的智能体
            capable_agents = [
                agent for agent in context.available_agents
                if task.tool_name in agent.get_supported_tools()
            ]

            if capable_agents:
                # 选择负载最低的
                capable_agents.sort(
                    key=lambda a: context.resource_budget.get(a.agent_id, 0)
                    if context.resource_budget else 0
                )
                assignments[task.task_id] = capable_agents[0].agent_id

        return assignments

    def _plan_execution_sequence(self, task_groups: Dict[str, List[Task]],
                                agent_assignments: Dict[str, str],
                                context: DecisionContext) -> Tuple[List[str], List[List[str]]]:
        """规划执行序列"""
        sequence = []
        parallel_groups = []

        # 高优先级任务并行执行
        high_priority = [t.task_id for t in task_groups.get('high', [])]
        if high_priority:
            parallel_groups.append(high_priority)
            sequence.extend(high_priority)

        # 中优先级任务按依赖串行
        medium_priority = task_groups.get('medium', [])
        for task in medium_priority:
            if task.task_id not in sequence:
                sequence.append(task.task_id)

        # 低优先级任务
        low_priority = [t.task_id for t in task_groups.get('low', [])]
        if low_priority:
            parallel_groups.append(low_priority)
            sequence.extend(low_priority)

        return sequence, parallel_groups

    def _generate_tactical_options(self, context: DecisionContext,
                                  task_groups: Dict[str, List[Task]]) -> List[DecisionOption]:
        """生成战术选项"""
        options = []

        total_tasks = sum(len(tasks) for tasks in task_groups.values())

        # 选项1: 全力并行
        options.append(DecisionOption(
            option_id="max_parallel",
            description="最大并行执行",
            actions=["parallel_all_ready_tasks"],
            expected_benefit=0.8,
            expected_cost=0.7,
            risk_level=0.4,
            confidence=0.8,
            required_resources={"cpu": 0.9, "memory": 0.7}
        ))

        # 选项2: 优先级串行
        options.append(DecisionOption(
            option_id="priority_serial",
            description="按优先级串行执行",
            actions=["execute_by_priority"],
            expected_benefit=0.6,
            expected_cost=0.3,
            risk_level=0.1,
            confidence=0.95,
            required_resources={"cpu": 0.3, "memory": 0.2}
        ))

        # 选项3: 混合模式
        options.append(DecisionOption(
            option_id="hybrid",
            description="高优并行，低优串行",
            actions=["high_parallel", "low_serial"],
            expected_benefit=0.75,
            expected_cost=0.5,
            risk_level=0.2,
            confidence=0.9,
            required_resources={"cpu": 0.6, "memory": 0.4}
        ))

        return options

    def _select_best_option(self, options: List[DecisionOption]) -> DecisionOption:
        """选择最佳选项"""
        # 使用中等风险承受度
        scored = [(opt.calculate_score(0.5), opt) for opt in options]
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1]


# ==================== 混合决策引擎 ====================

class HybridDecisionEngine:
    """
    混合决策引擎

    结合战略决策和战术决策，实现智能化决策融合
    """

    def __init__(self):
        """初始化决策引擎"""
        self.strategic_model = StrategicDecisionModel()
        self.tactical_model = TacticalDecisionModel()

        self.decision_history: List[Decision] = []
        self.active_decisions: Dict[str, Decision] = {}

        # 性能追踪
        self.successful_decisions = 0
        self.failed_decisions = 0

        logger.info("HybridDecisionEngine初始化完成")

    async def make_strategic_decision(self, context: DecisionContext) -> StrategicDecision:
        """
        生成战略决策

        Args:
            context: 决策上下文

        Returns:
            战略决策
        """
        logger.info("生成战略决策...")

        decision = await self.strategic_model.decide(context)
        self._track_decision(decision)

        return decision

    async def make_tactical_decision(self, context: DecisionContext) -> TacticalDecision:
        """
        生成战术决策

        Args:
            context: 决策上下文

        Returns:
            战术决策
        """
        logger.info("生成战术决策...")

        decision = await self.tactical_model.decide(context)
        self._track_decision(decision)

        return decision

    async def make_hybrid_decision(self, context: DecisionContext) -> List[Decision]:
        """
        生成混合决策（战略+战术）

        Args:
            context: 决策上下文

        Returns:
            决策列表 [战略决策, 战术决策, 融合决策]
        """
        logger.info("生成混合决策...")

        # 1. 生成战略决策
        strategic = await self.make_strategic_decision(context)

        # 2. 更新上下文（加入战略决策）
        context.previous_decisions.append(strategic)

        # 3. 生成战术决策
        tactical = await self.make_tactical_decision(context)

        # 4. 决策融合
        fused = self._fuse_decisions(strategic, tactical)

        # 5. 追踪融合决策
        self._track_decision(fused)

        return [strategic, tactical, fused]

    def _fuse_decisions(self, strategic: StrategicDecision,
                       tactical: TacticalDecision) -> Decision:
        """融合战略和战术决策"""
        reasoning = [
            "决策融合:",
            f"- 战略: {strategic.attack_strategy}",
            f"- 战术: {len(tactical.selected_agents)}个智能体",
            f"- 并行组: {len(tactical.parallel_groups)}"
        ]

        # 创建融合选项
        fused_option = DecisionOption(
            option_id="fused",
            description=f"融合决策: {strategic.attack_strategy} + 智能体分配",
            actions=strategic.selected_option.actions + tactical.selected_option.actions,
            expected_benefit=(strategic.selected_option.expected_benefit +
                            tactical.selected_option.expected_benefit) / 2,
            expected_cost=(strategic.selected_option.expected_cost +
                         tactical.selected_option.expected_cost) / 2,
            risk_level=(strategic.selected_option.risk_level +
                       tactical.selected_option.risk_level) / 2,
            confidence=(strategic.selected_option.confidence +
                      tactical.selected_option.confidence) / 2
        )

        fused = Decision(
            decision_id=f"fused_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            decision_type=DecisionType.ATTACK_PATH,
            decision_level=DecisionLevel.STRATEGIC,
            context=strategic.context,
            selected_option=fused_option,
            reasoning=reasoning
        )

        return fused

    def update_decision_outcome(self, decision_id: str,
                              success: bool,
                              actual_benefit: Optional[float] = None,
                              feedback: Optional[str] = None):
        """
        更新决策结果

        Args:
            decision_id: 决策ID
            success: 是否成功
            actual_benefit: 实际收益 (0-1)
            feedback: 反馈信息
        """
        if decision_id in self.active_decisions:
            decision = self.active_decisions[decision_id]

            decision.execution_status = "completed" if success else "failed"
            decision.actual_benefit = actual_benefit
            decision.feedback = feedback
            decision.executed_at = datetime.now()

            # 统计
            if success:
                self.successful_decisions += 1
            else:
                self.failed_decisions += 1

            # 学习
            self.strategic_model.learn_from_outcome(decision)
            self.tactical_model.learn_from_outcome(decision)

            logger.info(f"决策结果已更新: {decision_id}, 成功={success}")

    def _track_decision(self, decision: Decision):
        """追踪决策"""
        self.decision_history.append(decision)
        self.active_decisions[decision.decision_id] = decision

    def get_decision_history(self, limit: int = 100) -> List[Decision]:
        """获取决策历史"""
        return self.decision_history[-limit:]

    def get_performance_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        total = self.successful_decisions + self.failed_decisions

        metrics = {
            "total_decisions": total,
            "successful_decisions": self.successful_decisions,
            "failed_decisions": self.failed_decisions,
            "success_rate": self.successful_decisions / total if total > 0 else 0,
            "strategic_model_performance": self.strategic_model.performance_metrics,
            "tactical_model_performance": self.tactical_model.performance_metrics
        }

        return metrics

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息（兼容Coordinator调用）。"""
        return self.get_performance_metrics()

    def export_decisions(self, filepath: str):
        """导出决策历史"""
        data = {
            "decisions": [],
            "metrics": self.get_performance_metrics()
        }

        for decision in self.decision_history:
            decision_data = {
                "decision_id": decision.decision_id,
                "type": decision.decision_type.value,
                "level": decision.decision_level.value,
                "created_at": decision.created_at.isoformat(),
                "selected_option": decision.selected_option.option_id,
                "execution_status": decision.execution_status,
                "actual_benefit": decision.actual_benefit
            }
            data["decisions"].append(decision_data)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"决策历史已导出到: {filepath}")


# ==================== 导出 ====================

__all__ = [
    'HybridDecisionEngine',
    'StrategicDecisionModel',
    'TacticalDecisionModel',
    'DecisionLevel',
    'DecisionType',
    'DecisionContext',
    'DecisionOption',
    'Decision',
    'StrategicDecision',
    'TacticalDecision'
]
