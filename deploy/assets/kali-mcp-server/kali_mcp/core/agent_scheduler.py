#!/usr/bin/env python3
"""
Agent调度器 (AgentScheduler)

智能Agent调度和负载均衡：
- 负载均衡算法
- 资源分配
- 任务分配
- 调度优化

作者: SeaOf0
"""

import logging
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque
import heapq
from numbers import Number

from kali_mcp.core.task_decomposer import Task, TaskGraph, TaskCategory
from kali_mcp.core.agent_registry import (
    AgentRegistry,
    BaseAgentV2,
    SelectionCriteria,
    LoadReport
)

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class SchedulingStrategy(Enum):
    """调度策略"""
    ROUND_ROBIN = "round_robin"           # 轮询
    LEAST_LOADED = "least_loaded"           # 最少负载
    PRIORITY_BASED = "priority_based"       # 优先级驱动
    CAPABILITY_MATCH = "capability_match"   # 能力匹配
    ADAPTIVE = "adaptive"                   # 自适应


class AssignmentStatus(Enum):
    """分配状态"""
    ASSIGNED = "assigned"                   # 已分配
    PENDING = "pending"                     # 等待中
    FAILED = "failed"                       # 失败
    CANCELLED = "cancelled"                 # 已取消


@dataclass(order=True)
class ScheduledTask:
    """已调度的任务"""
    priority: int                          # 优先级（用于排序）
    created_at: datetime                   # 创建时间
    task: Task                             # 任务
    assigned_agent: Optional[BaseAgentV2] = None  # 分配的Agent
    status: AssignmentStatus = AssignmentStatus.PENDING
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class SchedulingStatistics:
    """调度统计"""
    total_assignments: int = 0
    successful_assignments: int = 0
    failed_assignments: int = 0
    total_execution_time: float = 0.0     # 总执行时间（秒）
    avg_execution_time: float = 0.0

    # 负载统计
    current_load: float = 0.0              # 当前负载（0-1）
    peak_load: float = 0.0                 # 峰值负载

    # Agent利用率
    agent_utilization: Dict[str, float] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """分配成功率（0-1）"""
        if self.total_assignments == 0:
            return 0.0
        return self.successful_assignments / self.total_assignments


@dataclass
class SchedulingDecision:
    """调度决策"""
    task: Task                             # 要调度的任务
    selected_agent: Optional[BaseAgentV2]  # 选择的Agent
    strategy: SchedulingStrategy           # 使用的策略
    confidence: float                      # 决策置信度（0-1）
    reasoning: List[str]                   # 决策推理
    estimated_duration: Optional[int] = None  # 预估时长


# ==================== Agent调度器 ====================

class AgentScheduler:
    """
    Agent调度器

    负责智能Agent调度和负载均衡
    """

    def __init__(
        self,
        agent_registry: AgentRegistry,
        strategy: SchedulingStrategy = SchedulingStrategy.ADAPTIVE
    ):
        """初始化调度器"""
        self.agent_registry = agent_registry
        self.strategy = strategy

        # 任务队列
        self.pending_tasks: deque[ScheduledTask] = deque()
        self.running_tasks: Dict[str, ScheduledTask] = {}
        self.completed_tasks: List[ScheduledTask] = []

        # 统计信息
        self.stats = SchedulingStatistics()
        self.history: List[SchedulingDecision] = []

        logger.info(f"AgentScheduler初始化完成，策略: {strategy.value}")

    async def schedule_task(
        self,
        task: Task,
        available_agents: Optional[List[BaseAgentV2]] = None
    ) -> SchedulingDecision:
        """
        调度单个任务

        Args:
            task: 要调度的任务
            available_agents: 可用的Agent列表（可选，默认从注册表获取）

        Returns:
            调度决策
        """
        logger.info(f"调度任务: {task.task_id} ({task.tool_name})")

        reasoning = []

        # 1. 获取可用Agent
        if available_agents is None:
            available_agents = self._get_available_agents()
            reasoning.append(f"从注册表获取到{len(available_agents)}个可用Agent")

        # 2. 选择调度策略
        decision = await self.recommend_agent(task, available_agents)

        # 3. 记录决策
        self.history.append(decision)
        self.stats.total_assignments += 1

        # 4. 如果分配成功，添加到运行任务
        if decision.selected_agent:
            scheduled_task = ScheduledTask(
                priority=task.priority,
                created_at=datetime.now(),
                task=task,
                assigned_agent=decision.selected_agent,
                status=AssignmentStatus.ASSIGNED,
                scheduled_at=datetime.now()
            )
            self.running_tasks[task.task_id] = scheduled_task
            self.stats.successful_assignments += 1
            reasoning.append(f"任务已分配给Agent: {decision.selected_agent.agent_id}")
        else:
            self.stats.failed_assignments += 1
            reasoning.append("未能分配任务（无可用Agent或不满足要求）")

        decision.reasoning = reasoning
        logger.info(f"调度决策: {decision.selected_agent.agent_id if decision.selected_agent else 'None'}")

        return decision

    async def recommend_agent(
        self,
        task: Task,
        available_agents: Optional[List[BaseAgentV2]] = None
    ) -> SchedulingDecision:
        """
        推荐Agent（无副作用版本）

        与 schedule_task 使用相同策略，但不更新 history/stats/running_tasks。
        """
        if available_agents is None:
            available_agents = self._get_available_agents()

        if self.strategy == SchedulingStrategy.ADAPTIVE:
            return await self._adaptive_schedule(task, available_agents)
        if self.strategy == SchedulingStrategy.LEAST_LOADED:
            return await self._least_loaded_schedule(task, available_agents)
        if self.strategy == SchedulingStrategy.PRIORITY_BASED:
            return await self._priority_schedule(task, available_agents)
        if self.strategy == SchedulingStrategy.CAPABILITY_MATCH:
            return await self._capability_schedule(task, available_agents)
        return await self._round_robin_schedule(task, available_agents)

    async def schedule_batch(
        self,
        tasks: List[Task],
        available_agents: Optional[List[BaseAgentV2]] = None
    ) -> List[SchedulingDecision]:
        """
        批量调度任务

        Args:
            tasks: 要调度的任务列表
            available_agents: 可用的Agent列表（可选）

        Returns:
            调度决策列表
        """
        logger.info(f"批量调度{len(tasks)}个任务")

        decisions = []

        # 按优先级排序
        sorted_tasks = sorted(tasks, key=lambda t: t.priority, reverse=True)

        for task in sorted_tasks:
            decision = await self.schedule_task(task, available_agents)
            decisions.append(decision)

        logger.info(f"批量调度完成: {len([d for d in decisions if d.selected_agent])}个成功分配")

        return decisions

    async def schedule_task_graph(
        self,
        task_graph: TaskGraph,
        available_agents: Optional[List[BaseAgentV2]] = None
    ) -> Dict[str, SchedulingDecision]:
        """
        调度整个任务图

        Args:
            task_graph: 任务图
            available_agents: 可用的Agent列表（可选）

        Returns:
            {task_id: SchedulingDecision}
        """
        logger.info(f"调度任务图: {len(task_graph.tasks)}个任务")

        decisions = {}

        # 按阶段调度（考虑依赖关系）
        for phase_idx, phase_tasks in enumerate(self._get_execution_phases(task_graph)):
            logger.info(f"调度阶段{phase_idx}: {len(phase_tasks)}个任务")

            phase_decisions = await self.schedule_batch(
                [task_graph.tasks[task_id] for task_id in phase_tasks],
                available_agents
            )

            # 关联决策到任务ID
            for i, task_id in enumerate(phase_tasks):
                decisions[task_id] = phase_decisions[i]

        return decisions

    def mark_task_complete(self, task_id: str, success: bool = True):
        """标记任务完成"""
        if task_id not in self.running_tasks:
            logger.warning(f"任务{task_id}不在运行任务列表中")
            return

        scheduled_task = self.running_tasks[task_id]
        scheduled_task.status = AssignmentStatus.ASSIGNED if success else AssignmentStatus.FAILED
        scheduled_task.completed_at = datetime.now()

        # 计算执行时间
        if scheduled_task.started_at and scheduled_task.completed_at:
            duration = (scheduled_task.completed_at - scheduled_task.started_at).total_seconds()
            self.stats.total_execution_time += duration

        # 移动到已完成
        self.completed_tasks.append(scheduled_task)
        del self.running_tasks[task_id]

        # 更新统计
        self._update_statistics()

        logger.info(f"任务{task_id}标记为完成")

    def get_pending_tasks(self) -> List[ScheduledTask]:
        """获取等待中的任务"""
        return list(self.pending_tasks)

    def get_running_tasks(self) -> List[ScheduledTask]:
        """获取运行中的任务"""
        return list(self.running_tasks.values())

    def get_statistics(self) -> SchedulingStatistics:
        """获取统计信息"""
        self._update_statistics()
        return self.stats

    # ==================== 调度策略 ====================

    async def _adaptive_schedule(
        self,
        task: Task,
        available_agents: List[BaseAgentV2]
    ) -> SchedulingDecision:
        """自适应调度"""
        reasoning = []

        # 获取所有Agent的负载
        load_info = {}
        for agent in available_agents:
            try:
                load_info[agent.agent_id] = await self._get_agent_load(agent)
            except Exception as e:
                logger.warning(f"获取Agent {agent.agent_id} 负载失败: {e}")
                load_info[agent.agent_id] = self._fallback_load_report(
                    agent_id=agent.agent_id,
                    current_tasks=999
                )

        # 仅选择可执行该工具的Agent
        capable_agents = [
            agent for agent in available_agents
            if self._agent_can_handle_tool(agent, task.tool_name)
        ]
        if not capable_agents:
            return SchedulingDecision(
                task=task,
                selected_agent=None,
                strategy=SchedulingStrategy.ADAPTIVE,
                confidence=0.0,
                reasoning=[f"没有Agent支持工具: {task.tool_name}"]
            )

        # 筛选可用Agent（负载<80%）
        available = [
            agent for agent in capable_agents
            if load_info.get(
                agent.agent_id,
                self._fallback_load_report(agent.agent_id, current_tasks=999)
            ).cpu_usage < 0.8
        ]

        if not available:
            return SchedulingDecision(
                task=task,
                selected_agent=None,
                strategy=SchedulingStrategy.ADAPTIVE,
                confidence=0.0,
                reasoning=["所有Agent负载过高"]
            )

        # 计算每个Agent的得分
        scored_agents = []
        for agent in available:
            score = self._calculate_agent_score(agent, task, load_info.get(agent.agent_id))
            scored_agents.append((score, agent))

        # 选择最高分Agent
        scored_agents.sort(key=lambda x: x[0], reverse=True)
        best_score, best_agent = scored_agents[0]

        return SchedulingDecision(
            task=task,
            selected_agent=best_agent,
            strategy=SchedulingStrategy.ADAPTIVE,
            confidence=min(best_score / 100.0, 1.0),
            reasoning=[
                f"自适应策略选择了{best_agent.agent_id}",
                f"得分: {best_score:.1f}"
            ]
        )

    async def _least_loaded_schedule(
        self,
        task: Task,
        available_agents: List[BaseAgentV2]
    ) -> SchedulingDecision:
        """最少负载调度"""
        reasoning = []

        # 获取负载信息
        load_info = {}
        for agent in available_agents:
            try:
                load_report = await self._get_agent_load(agent)
                load_info[agent.agent_id] = load_report.current_tasks
            except Exception:
                load_info[agent.agent_id] = 999

        capable_agents = [
            agent for agent in available_agents
            if self._agent_can_handle_tool(agent, task.tool_name)
        ]

        # 选择任务最少的可匹配Agent
        if not capable_agents:
            selected = None
        elif not load_info:
            selected = capable_agents[0]
        else:
            selected = min(capable_agents, key=lambda a: load_info.get(a.agent_id, 999))

        return SchedulingDecision(
            task=task,
            selected_agent=selected,
            strategy=SchedulingStrategy.LEAST_LOADED,
            confidence=0.8,
            reasoning=[
                "最少负载策略",
                f"选择Agent: {selected.agent_id if selected else 'None'}"
            ]
        )

    async def _priority_schedule(
        self,
        task: Task,
        available_agents: List[BaseAgentV2]
    ) -> SchedulingDecision:
        """优先级驱动调度"""
        candidates = [
            agent for agent in available_agents
            if self._agent_can_handle_tool(agent, task.tool_name)
        ]
        if not candidates:
            selected = None
        else:
            scored_agents = []
            for agent in candidates:
                load_report = await self._get_agent_load(agent)
                if task.priority >= 8 and load_report.cpu_usage >= 0.7:
                    continue
                score = self._calculate_agent_score(agent, task, load_report)
                score += max(0, task.priority - 5) * 2
                scored_agents.append((score, agent))
            selected = max(scored_agents, key=lambda x: x[0])[1] if scored_agents else None

        return SchedulingDecision(
            task=task,
            selected_agent=selected,
            strategy=SchedulingStrategy.PRIORITY_BASED,
            confidence=0.9 if selected else 0.0,
            reasoning=[
                "优先级驱动策略",
                f"任务优先级: {task.priority}",
                f"选择Agent: {selected.agent_id if selected else 'None'}"
            ]
        )

    async def _capability_schedule(
        self,
        task: Task,
        available_agents: List[BaseAgentV2]
    ) -> SchedulingDecision:
        """能力匹配调度"""
        candidates = [
            agent for agent in available_agents
            if self._agent_can_handle_tool(agent, task.tool_name)
        ]
        if not candidates:
            selected = None
        else:
            scored_agents = []
            for agent in candidates:
                load_report = await self._get_agent_load(agent)
                score = self._calculate_agent_score(agent, task, load_report)
                scored_agents.append((score, agent))
            selected = max(scored_agents, key=lambda x: x[0])[1]

        return SchedulingDecision(
            task=task,
            selected_agent=selected,
            strategy=SchedulingStrategy.CAPABILITY_MATCH,
            confidence=0.9 if selected else 0.0,
            reasoning=[
                "能力匹配策略",
                f"需要能力: {task.tool_name}",
                f"选择Agent: {selected.agent_id if selected else 'None'}"
            ]
        )

    async def _round_robin_schedule(
        self,
        task: Task,
        available_agents: List[BaseAgentV2]
    ) -> SchedulingDecision:
        """轮询调度"""
        # 简单轮询：选择第一个有能力的Agent
        for agent in available_agents:
            supported_tools = self._agent_supported_tools(agent)
            if task.tool_name in supported_tools:
                return SchedulingDecision(
                    task=task,
                    selected_agent=agent,
                    strategy=SchedulingStrategy.ROUND_ROBIN,
                    confidence=0.7,
                    reasoning=[
                        "轮询策略",
                        f"选择Agent: {agent.agent_id}"
                    ]
                )

        return SchedulingDecision(
            task=task,
            selected_agent=None,
            strategy=SchedulingStrategy.ROUND_ROBIN,
            confidence=0.0,
            reasoning=["没有Agent支持此工具"]
        )

    # ==================== 辅助方法 ====================

    def _get_available_agents(self) -> List[BaseAgentV2]:
        """获取所有可用Agent"""
        all_agents = self.agent_registry.list_all()
        available_agents = []
        for agent in all_agents:
            is_available = getattr(agent, "is_available", None)
            if callable(is_available):
                try:
                    if not is_available():
                        continue
                except Exception:
                    continue
            available_agents.append(agent)
        return available_agents

    def _calculate_agent_score(
        self,
        agent: BaseAgentV2,
        task: Task,
        load_report: Optional[LoadReport] = None
    ) -> float:
        """
        计算Agent得分（0-100）

        考虑因素：
        - 负载（40分）
        - 能力匹配（30分）
        - 成功率（20分）
        - 空闲状态（10分）
        """
        score = 0.0

        # 1. 负载得分（40分）
        if load_report:
            load_score = (1.0 - self._as_float(getattr(load_report, "cpu_usage", 1.0), 1.0)) * 40
            score += load_score
        else:
            score += 20  # 默认中等负载

        # 2. 能力匹配（30分）
        supported_tools = self._agent_supported_tools(agent)
        if task.tool_name in supported_tools:
            score += 30
        elif any(task.tool_name.startswith(prefix) for prefix in supported_tools):
            score += 15  # 部分匹配

        # 3. 成功率（20分）
        success_rate = self._as_float(
            getattr(getattr(agent, "performance_metrics", None), "success_rate", 0),
            0.0
        )
        if success_rate > 0:
            score += success_rate * 20
        else:
            score += 10  # 默认中等成功率

        # 4. 空闲状态（10分）
        current_tasks = self._as_int(getattr(load_report, "current_tasks", 999), 999) if load_report else 999
        if load_report and current_tasks == 0:
            score += 10
        elif load_report and current_tasks < 3:
            score += 5

        return score

    def _get_execution_phases(self, task_graph: TaskGraph) -> List[List[str]]:
        """获取任务图的执行阶段"""
        phases = []
        in_degree = {
            task_id: len(task.dependencies)
            for task_id, task in task_graph.tasks.items()
        }
        ready = {task_id for task_id, degree in in_degree.items() if degree == 0}

        while ready:
            current_phase = sorted(ready)
            phases.append(current_phase)

            for task_id in current_phase:
                ready.remove(task_id)
                for dependent in task_graph.adjacency_list.get(task_id, set()):
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        ready.add(dependent)

        return phases

    def _update_statistics(self):
        """更新统计信息"""
        # 计算平均执行时间
        completed_count = len(self.completed_tasks)
        if completed_count > 0:
            self.stats.avg_execution_time = (
                self.stats.total_execution_time / completed_count
            )

        # 计算当前负载
        if self.running_tasks:
            total_capacity = len(self.agent_registry.list_all()) * 10  # 假设每个Agent最多10个并发
            current_load = len(self.running_tasks) / max(total_capacity, 1)
            self.stats.current_load = min(current_load, 1.0)
            self.stats.peak_load = max(self.stats.peak_load, current_load)

        # 计算Agent利用率
        for agent in self.agent_registry.list_all():
            agent_tasks = [
                st for st in self.running_tasks.values()
                if st.assigned_agent and st.assigned_agent.agent_id == agent.agent_id
            ]
            max_concurrent_tasks = self._agent_max_concurrency(agent)
            if max_concurrent_tasks > 0:
                utilization = len(agent_tasks) / max_concurrent_tasks
                self.stats.agent_utilization[agent.agent_id] = min(utilization, 1.0)

    def _agent_supported_tools(self, agent: BaseAgentV2) -> Set[str]:
        """兼容不同Agent实现，提取支持的工具列表。"""
        try:
            result = getattr(agent, "get_supported_tools", None)
            if callable(result):
                tools = result()
                if isinstance(tools, (list, tuple, set)):
                    return set(tools)
        except Exception:
            pass

        capabilities = getattr(agent, "capabilities", None)
        if isinstance(capabilities, list):
            merged = set()
            for capability in capabilities:
                cap_tools = getattr(capability, "supported_tools", None) or getattr(capability, "tools", None)
                if isinstance(cap_tools, (list, tuple, set)):
                    merged.update(cap_tools)
            return merged

        cap_tools = getattr(capabilities, "supported_tools", None)
        if isinstance(cap_tools, (list, tuple, set)):
            return set(cap_tools)
        return set()

    def _agent_can_handle_tool(self, agent: BaseAgentV2, tool_name: str) -> bool:
        """判断Agent是否能处理指定工具。"""
        supported_tools = self._agent_supported_tools(agent)
        if tool_name in supported_tools:
            return True
        return any(tool_name.startswith(prefix) for prefix in supported_tools)

    async def _get_agent_load(self, agent: BaseAgentV2) -> LoadReport:
        """兼容同步/异步report_load，统一返回负载对象。"""
        report_fn = getattr(agent, "report_load", None)
        if not callable(report_fn):
            return self._fallback_load_report(agent.agent_id)

        report = report_fn()
        if asyncio.iscoroutine(report):
            report = await report
        if report is None:
            return self._fallback_load_report(agent.agent_id)

        # 兜底字段，兼容mock对象
        report.cpu_usage = self._as_float(getattr(report, "cpu_usage", 0.0), 0.0)
        report.current_tasks = self._as_int(getattr(report, "current_tasks", 0), 0)
        return report

    def _fallback_load_report(self, agent_id: str, current_tasks: int = 0) -> LoadReport:
        """当负载不可用时构造兜底负载对象。"""
        if LoadReport:
            return LoadReport(
                agent_id=agent_id,
                current_tasks=current_tasks,
                cpu_usage=1.0 if current_tasks >= 999 else 0.0,
                memory_usage_mb=0.0
            )

        @dataclass
        class _SimpleLoadReport:
            agent_id: str
            current_tasks: int = 0
            cpu_usage: float = 0.0
            memory_usage_mb: float = 0.0

        return _SimpleLoadReport(
            agent_id=agent_id,
            current_tasks=current_tasks,
            cpu_usage=1.0 if current_tasks >= 999 else 0.0,
            memory_usage_mb=0.0
        )

    def _agent_max_concurrency(self, agent: BaseAgentV2) -> int:
        """兼容不同capabilities结构提取并发容量。"""
        capabilities = getattr(agent, "capabilities", None)
        if isinstance(capabilities, list):
            total = sum(
                self._as_int(getattr(capability, "max_concurrent_tasks", 0), 0)
                for capability in capabilities
            )
            return total
        value = getattr(capabilities, "max_concurrent_tasks", 0) if capabilities else 0
        return self._as_int(value, 0)

    def _as_float(self, value: Any, default: float) -> float:
        """将值安全转换为float。"""
        if isinstance(value, Number):
            return float(value)
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _as_int(self, value: Any, default: int) -> int:
        """将值安全转换为int。"""
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, Number):
            return int(value)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default


# ==================== 导出 ====================

__all__ = [
    'AgentScheduler',
    'SchedulingStrategy',
    'AssignmentStatus',
    'ScheduledTask',
    'SchedulingStatistics',
    'SchedulingDecision'
]
