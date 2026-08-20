#!/usr/bin/env python3
"""
中心调控智能体 (CoordinatorAgent)

多智能体集群系统的核心调控组件，负责：
- 意图理解和任务分解
- 智能体调度和负载均衡
- 混合决策（战略层）
- 结果整合和报告生成
"""

import logging
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

from kali_mcp.core.intent_analyzer import (
    IntentAnalyzer,
    IntentAnalysis,
    AttackIntent,
    TargetInfo,
    TargetType
)
from kali_mcp.core.task_decomposer import (
    TaskDecomposer,
    Task,
    TaskGraph,
    TaskCategory,
    TaskStatus,
    ExecutionPlan as DecomposerExecutionPlan
)
from kali_mcp.core.agent_scheduler import (
    AgentScheduler,
    SchedulingStrategy,
    SchedulingDecision,
    SchedulingStatistics
)
from kali_mcp.core.hybrid_decision_engine import (
    HybridDecisionEngine,
    DecisionContext,
    Decision,
    DecisionLevel,
    DecisionType,
    StrategicDecision,
    TacticalDecision
)
from kali_mcp.core.result_aggregator import (
    ResultAggregator,
    AgentResult,
    AggregatedResult,
    Finding,
    ResultSeverity,
    ResultType
)
from kali_mcp.core.agent_registry import AgentRegistry
from kali_mcp.core.pentest_capability_planner import PentestCapabilityPlanner

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class CoordinatorState(Enum):
    """调控器状态"""
    IDLE = "idle"                       # 空闲
    ANALYZING = "analyzing"             # 分析意图
    DECOMPOSING = "decomposing"         # 分解任务
    SCHEDULING = "scheduling"           # 调度智能体
    EXECUTING = "executing"             # 执行中
    AGGREGATING = "aggregating"         # 聚合结果
    DECIDING = "deciding"               # 决策中
    COMPLETED = "completed"             # 完成
    FAILED = "failed"                   # 失败


@dataclass
class CoordinatorExecutionPlan:
    """调控器执行计划（扩展TaskDecomposer.ExecutionPlan）"""
    plan_id: str                                        # 计划ID
    intent_analysis: IntentAnalysis                     # 意图分析
    decomposer_plan: DecomposerExecutionPlan            # TaskDecomposer生成的计划
    scheduling_decisions: List[SchedulingDecision]     # 调度决策
    required_agents: Set[str] = field(default_factory=set)  # 需要的Agent
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def task_graph(self) -> TaskGraph:
        """获取任务图"""
        return self.decomposer_plan.task_graph

    @property
    def estimated_duration(self) -> int:
        """获取预计时长"""
        return self.decomposer_plan.estimated_duration


@dataclass
class ExecutionSession:
    """执行会话"""
    session_id: str                             # 会话ID
    user_input: str                             # 用户输入
    state: CoordinatorState                     # 当前状态
    plan: Optional[CoordinatorExecutionPlan] = None  # 执行计划
    decisions: List[Decision] = field(default_factory=list)  # 决策历史
    agent_results: List[AgentResult] = field(default_factory=list)  # Agent结果
    aggregated_result: Optional[AggregatedResult] = None  # 聚合结果
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    # 统计信息
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0


# ==================== 中心调控智能体 ====================

class CoordinatorAgent:
    """
    中心调控智能体

    多智能体集群系统的核心，整合：
    - IntentAnalyzer: 意图分析
    - TaskDecomposer: 任务分解
    - AgentScheduler: 智能体调度
    - HybridDecisionEngine: 混合决策
    - ResultAggregator: 结果聚合
    """

    def __init__(
        self,
        agent_registry: AgentRegistry,
        scheduling_strategy: SchedulingStrategy = SchedulingStrategy.ADAPTIVE
    ):
        """
        初始化调控器

        Args:
            agent_registry: Agent注册表
            scheduling_strategy: 调度策略
        """
        self.agent_registry = agent_registry

        # 初始化核心组件
        self.intent_analyzer = IntentAnalyzer()
        self.task_decomposer = TaskDecomposer()
        self.agent_scheduler = AgentScheduler(agent_registry, scheduling_strategy)
        self.decision_engine = HybridDecisionEngine()
        self.result_aggregator = ResultAggregator()
        self.strategy_planner = PentestCapabilityPlanner()

        # 会话管理
        self.sessions: Dict[str, ExecutionSession] = {}
        self.current_session_id: Optional[str] = None

        # 统计信息
        self.total_sessions = 0
        self.successful_sessions = 0

        logger.info("CoordinatorAgent初始化完成")

    async def process_request(
        self,
        user_input: str,
        session_id: Optional[str] = None
    ) -> ExecutionSession:
        """
        处理用户请求（完整流程）

        Args:
            user_input: 用户输入
            session_id: 会话ID（可选）

        Returns:
            执行会话
        """
        # 创建或获取会话
        if session_id is None:
            session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
            self.sessions[session_id] = ExecutionSession(
                session_id=session_id,
                user_input=user_input,
                state=CoordinatorState.IDLE
            )
        elif session_id not in self.sessions:
            self.sessions[session_id] = ExecutionSession(
                session_id=session_id,
                user_input=user_input,
                state=CoordinatorState.IDLE
            )

        session = self.sessions[session_id]
        self.current_session_id = session_id

        try:
            # 1. 意图分析
            session.state = CoordinatorState.ANALYZING
            logger.info(f"[{session_id}] 分析意图: {user_input[:50]}...")
            intent = self.intent_analyzer.analyze(user_input)
            logger.info(f"[{session_id}] 意图: {intent.intent.value}, 置信度: {intent.confidence:.2f}")

            # 2. 任务分解
            session.state = CoordinatorState.DECOMPOSING
            logger.info(f"[{session_id}] 分解任务...")
            intent = self._attach_strategy_constraint(intent)
            decompose_result = self.task_decomposer.decompose(intent)
            task_graph = decompose_result.task_graph
            logger.info(f"[{session_id}] 生成 {len(task_graph.tasks)} 个任务")

            # 3. 创建执行计划
            session.state = CoordinatorState.SCHEDULING
            logger.info(f"[{session_id}] 调度智能体...")
            plan = await self._create_execution_plan(intent, decompose_result)
            session.plan = plan
            session.total_tasks = len(task_graph.tasks)

            # 4. 战略决策
            session.state = CoordinatorState.DECIDING
            logger.info(f"[{session_id}] 制定战略决策...")
            scheduler_stats = self.agent_scheduler.get_statistics()
            decision_context = DecisionContext(
                intent_analysis=intent,
                task_graph=task_graph,
                available_agents=self.agent_registry.get_available_agents(),
                system_load={
                    "cpu": scheduler_stats.current_load,
                    "memory": 0.5,
                    "network": 0.5
                },
                constraints=intent.constraints or [],
                available_resources=len(self.agent_registry.get_all_agents()),
                current_phase="planning",
            )
            strategic_decision = await self.decision_engine.make_strategic_decision(decision_context)
            session.decisions.append(strategic_decision)
            strategic_summary = (
                getattr(strategic_decision, "recommended_action", None)
                or strategic_decision.attack_strategy
                or strategic_decision.selected_option.description
            )
            logger.info(f"[{session_id}] 战略决策: {strategic_summary}")

            # 5. 执行任务（异步调度）
            session.state = CoordinatorState.EXECUTING
            logger.info(f"[{session_id}] 执行任务...")
            agent_results = await self._execute_plan(plan)
            session.agent_results = agent_results
            session.completed_tasks = len(agent_results)

            # 6. 战术决策（基于执行结果）
            logger.info(f"[{session_id}] 制定战术决策...")
            decision_context.current_phase = "execution"
            decision_context.execution_results = [
                {
                    "task_id": r.task_id,
                    "success": r.success,
                    "execution_time": r.execution_time
                }
                for r in agent_results
            ]
            tactical_decision = await self.decision_engine.make_tactical_decision(decision_context)
            session.decisions.append(tactical_decision)

            # 7. 混合决策
            logger.info(f"[{session_id}] 融合决策...")
            hybrid_decisions = await self.decision_engine.make_hybrid_decision(decision_context)
            session.decisions.extend(hybrid_decisions)

            # 8. 结果聚合
            session.state = CoordinatorState.AGGREGATING
            logger.info(f"[{session_id}] 聚合结果...")
            aggregated = await self.result_aggregator.aggregate_results(
                intent,
                agent_results
            )
            session.aggregated_result = aggregated

            # 9. 完成
            session.state = CoordinatorState.COMPLETED
            session.completed_at = datetime.now()
            self.successful_sessions += 1

            logger.info(
                f"[{session_id}] 会话完成: "
                f"{len(aggregated.unique_findings)}个发现, "
                f"{len(aggregated.extracted_flags)}个Flag, "
                f"耗时{(session.completed_at - session.started_at).total_seconds():.1f}秒"
            )

        except Exception as e:
            session.state = CoordinatorState.FAILED
            session.error = str(e)
            session.completed_at = datetime.now()
            logger.error(f"[{session_id}] 会话失败: {e}", exc_info=True)

        self.total_sessions += 1
        return session

    async def _create_execution_plan(
        self,
        intent: IntentAnalysis,
        decomposer_plan: DecomposerExecutionPlan
    ) -> CoordinatorExecutionPlan:
        """创建执行计划"""
        plan_id = f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # 调度所有任务
        decisions = []
        required_agents = set()
        available_agents = self.agent_registry.get_available_agents()

        task_graph = decomposer_plan.task_graph
        tasks = list(task_graph.tasks.values())

        # 按策略阶段 + 优先级排序
        sorted_tasks = sorted(
            tasks,
            key=lambda t: (
                int(t.parameters.get("strategy_stage_index", 999)),
                -int(t.priority),
                t.category.value,
            ),
        )

        for task in sorted_tasks:
            stage_candidates = self._select_stage_candidate_agents(task, available_agents)
            decision = await self.agent_scheduler.schedule_task(task, stage_candidates)

            # 非策略强约束任务允许回退分配；策略任务保持强约束
            if (
                decision.selected_agent is None
                and available_agents
                and not self._is_strategy_constrained_task(task)
            ):
                fallback_agent = available_agents[0]
                decision = SchedulingDecision(
                    task=task,
                    selected_agent=fallback_agent,
                    strategy=self.agent_scheduler.strategy,
                    confidence=0.3,
                    reasoning=[f"回退分配到可用Agent: {fallback_agent.agent_id}"]
                )
            decisions.append(decision)

            if decision.selected_agent:
                required_agents.add(decision.selected_agent.agent_id)

        plan = CoordinatorExecutionPlan(
            plan_id=plan_id,
            intent_analysis=intent,
            decomposer_plan=decomposer_plan,
            scheduling_decisions=decisions,
            required_agents=required_agents
        )

        return plan

    async def _execute_plan(self, plan: CoordinatorExecutionPlan) -> List[AgentResult]:
        """执行计划"""
        results = []

        # 获取所有可用的agents
        all_agents = self.agent_registry.get_all_agents()

        # 按依赖关系顺序执行任务
        sorted_tasks = self._topological_sort(plan.task_graph)

        for task_id in sorted_tasks:
            task = plan.task_graph.tasks[task_id]

            # 查找对应的调度决策
            decision = next(
                (d for d in plan.scheduling_decisions if d.task.task_id == task_id),
                None
            )

            if not decision or not decision.selected_agent:
                reason = "无可用Agent满足策略约束或能力要求"
                if decision and decision.reasoning:
                    reason = "; ".join(decision.reasoning)
                results.append(
                    AgentResult(
                        agent_id="coordinator",
                        task_id=task_id,
                        tool_name=task.tool_name,
                        target=task.parameters.get("target", ""),
                        success=False,
                        execution_time=0,
                        output="",
                        errors=[reason],
                    )
                )
                continue

            # 执行任务
            try:
                result = await self._execute_single_task(
                    task,
                    decision.selected_agent.agent_id
                )
                results.append(result)

                # 标记任务完成
                self.agent_scheduler.mark_task_complete(
                    task_id,
                    success=result.success
                )

            except Exception as e:
                logger.error(f"执行任务 {task_id} 失败: {e}")
                # 创建失败结果
                result = AgentResult(
                    agent_id=decision.selected_agent.agent_id,
                    task_id=task_id,
                    tool_name=task.tool_name,
                    target=task.parameters.get("target", ""),
                    success=False,
                    execution_time=0,
                    output="",
                    errors=[str(e)]
                )
                results.append(result)

        return results

    @staticmethod
    def _infer_strategy_mode(intent: IntentAnalysis) -> str:
        if intent.intent == AttackIntent.CTF_SOLVING:
            return "ctf"
        if intent.intent in {
            AttackIntent.RECONNAISSANCE,
            AttackIntent.COVERAGE_ANALYSIS,
        }:
            return "recon"
        if intent.intent in {
            AttackIntent.EXPLOITATION,
            AttackIntent.FULL_COMPROMISE,
            AttackIntent.APT_SIMULATION,
            AttackIntent.LATERAL_MOVEMENT,
        }:
            return "pentest"
        return "pentest"

    def _attach_strategy_constraint(self, intent: IntentAnalysis) -> IntentAnalysis:
        existing = []
        for item in intent.constraints or []:
            if not isinstance(item, dict):
                existing.append(item)
                continue
            if str(item.get("type", "")).lower() in {
                "execution_strategy",
                "strategy_blueprint",
                "pentest_strategy",
            }:
                continue
            existing.append(item)

        primary_target = ""
        if intent.targets:
            primary_target = intent.targets[0].value
        elif intent.user_input:
            primary_target = intent.user_input.strip()
        if not primary_target:
            primary_target = "unknown-target"

        strategy = self.strategy_planner.build_strategy(
            target=primary_target,
            prompt=intent.user_input,
            mode=self._infer_strategy_mode(intent),
            has_source=False,
        )
        existing.append(
            {
                "type": "execution_strategy",
                "source": "coordinator",
                "strategy": strategy,
            }
        )
        intent.constraints = existing
        return intent

    @staticmethod
    def _is_strategy_constrained_task(task: Task) -> bool:
        return "strategy_stage_index" in task.parameters

    def _select_stage_candidate_agents(
        self,
        task: Task,
        available_agents: List[Any],
    ) -> List[Any]:
        preferred = task.parameters.get("strategy_preferred_agents")
        if not self._is_strategy_constrained_task(task):
            return available_agents
        if not isinstance(preferred, list) or not preferred:
            return available_agents
        preferred_set = {str(agent_id) for agent_id in preferred if agent_id}
        selected = [
            agent
            for agent in available_agents
            if getattr(agent, "agent_id", "") in preferred_set
        ]
        return selected

    async def _execute_single_task(
        self,
        task: Task,
        agent_id: str
    ) -> AgentResult:
        """执行单个任务"""
        agent = self.agent_registry.get_agent(agent_id)

        if agent is None:
            raise ValueError(f"Agent {agent_id} 不存在")

        start_time = datetime.now()

        try:
            # 调用Agent执行任务
            result = await agent.execute_task(task)

            # 计算执行时间
            execution_time = (datetime.now() - start_time).total_seconds()
            result.execution_time = execution_time

            return result

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()

            return AgentResult(
                agent_id=agent_id,
                task_id=task.task_id,
                tool_name=task.tool_name,
                target=task.parameters.get("target", ""),
                success=False,
                execution_time=execution_time,
                output="",
                errors=[str(e)]
            )

    def _topological_sort(self, task_graph: TaskGraph) -> List[str]:
        """拓扑排序任务图"""
        sorted_tasks = []
        visited = set()
        temp_visited = set()

        def visit(task_id: str):
            if task_id in temp_visited:
                raise ValueError(f"检测到循环依赖: {task_id}")
            if task_id in visited:
                return

            temp_visited.add(task_id)

            task = task_graph.tasks[task_id]
            for dep_id in task.dependencies:
                visit(dep_id)

            temp_visited.remove(task_id)
            visited.add(task_id)
            sorted_tasks.append(task_id)

        for task_id in task_graph.tasks:
            if task_id not in visited:
                visit(task_id)

        return sorted_tasks

    async def make_decision(
        self,
        context: DecisionContext
    ) -> List[Decision]:
        """
        制定决策

        Args:
            context: 决策上下文

        Returns:
            决策列表（战略、战术、融合）
        """
        return await self.decision_engine.make_hybrid_decision(context)

    def get_session(self, session_id: str) -> Optional[ExecutionSession]:
        """获取会话"""
        return self.sessions.get(session_id)

    def get_current_session(self) -> Optional[ExecutionSession]:
        """获取当前会话"""
        if self.current_session_id:
            return self.sessions.get(self.current_session_id)
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        scheduler_stats = self.agent_scheduler.get_statistics()

        return {
            "coordinator": {
                "total_sessions": self.total_sessions,
                "successful_sessions": self.successful_sessions,
                "success_rate": self.successful_sessions / self.total_sessions if self.total_sessions > 0 else 0,
                "active_sessions": sum(
                    1 for s in self.sessions.values()
                    if s.state not in [CoordinatorState.COMPLETED, CoordinatorState.FAILED]
                )
            },
            "scheduler": {
                "total_assignments": scheduler_stats.total_assignments,
                "successful_assignments": scheduler_stats.successful_assignments,
                "failed_assignments": scheduler_stats.failed_assignments,
                "success_rate": scheduler_stats.success_rate,
                "avg_execution_time": scheduler_stats.avg_execution_time
            },
            "decision_engine": self.decision_engine.get_statistics(),
            "agent_registry": {
                "total_agents": len(self.agent_registry.get_all_agents()),
                "available_agents": len(self.agent_registry.get_available_agents()),
                "agents_by_capability": self.agent_registry.get_capability_summary()
            }
        }

    async def generate_report(
        self,
        session_id: str,
        output_format: str = "markdown"
    ) -> str:
        """
        生成报告

        Args:
            session_id: 会话ID
            output_format: 输出格式 (markdown, json, html)

        Returns:
            报告内容
        """
        session = self.get_session(session_id)

        if session is None:
            raise ValueError(f"会话 {session_id} 不存在")

        if session.aggregated_result is None:
            raise ValueError(f"会话 {session_id} 尚未完成结果聚合")

        return self.result_aggregator.generate_report(
            session.aggregated_result,
            output_format
        )
