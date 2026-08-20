#!/usr/bin/env python3
"""
自适应并行执行引擎 (AdaptiveParallelEngine) v2.0

智能并行任务执行引擎：
- 动态并行度调整（根据任务类型和系统负载）
- DAG任务依赖管理
- 资源感知调度
- 冲突检测和解决
- 任务优先级管理

作者: SeaOf0
"""

import asyncio
import logging
import time
import psutil
from typing import Dict, List, Optional, Set, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from threading import Lock, Event
from concurrent.futures import ThreadPoolExecutor
from functools import total_ordering
import heapq

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"          # 等待执行
    READY = "ready"              # 就绪（依赖已满足）
    RUNNING = "running"          # 执行中
    COMPLETED = "completed"      # 已完成
    FAILED = "failed"            # 失败
    CANCELLED = "cancelled"      # 已取消
    BLOCKED = "blocked"          # 阻塞（依赖未满足）


class ConflictType(Enum):
    """冲突类型"""
    RESOURCE = "resource"        # 资源冲突（CPU、内存等）
    DATA = "data"                # 数据冲突（读写同一数据）
    TOOL = "tool"                # 工具冲突（同一工具不能并发）
    NETWORK = "network"          # 网络冲突（同一目标端口/服务）
    EXCLUSIVE = "exclusive"      # 互斥任务


@total_ordering
@dataclass
class TaskPriority:
    """任务优先级"""
    priority: int = 5            # 优先级（1-10，10最高），默认5
    created_at: datetime = field(default_factory=datetime.now)

    def __lt__(self, other):
        # 先按priority排序（大的优先），再按created_at排序（早的优先）
        if self.priority != other.priority:
            return self.priority > other.priority
        return self.created_at < other.created_at

    def __eq__(self, other):
        if not isinstance(other, TaskPriority):
            return NotImplemented
        return (self.priority == other.priority and
                self.created_at == other.created_at)


@dataclass
class TaskNode:
    """DAG任务节点"""
    task_id: str
    task_type: str
    task_data: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    dependencies: Set[str] = field(default_factory=set)  # 依赖的task_id集合
    dependents: Set[str] = field(default_factory=set)    # 依赖此任务的其他task_id
    priority: TaskPriority = field(default_factory=TaskPriority)

    # 执行信息
    agent_id: Optional[str] = None   # 分配的Agent
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time: float = 0.0      # 执行时长（秒）

    # 结果
    result: Optional[Any] = None
    error: Optional[str] = None

    # 资源需求
    estimated_cpu: float = 0.0       # 预估CPU使用率
    estimated_memory: float = 0.0    # 预估内存使用（MB）
    required_tools: List[str] = field(default_factory=list)

    # 冲突标记
    conflicts: Set[ConflictType] = field(default_factory=set)

    def __lt__(self, other):
        """用于堆排序的比较"""
        if not isinstance(other, TaskNode):
            return NotImplemented
        return self.priority < other.priority


@dataclass
class ConflictInfo:
    """冲突信息"""
    conflict_type: ConflictType
    task1_id: str
    task2_id: str
    reason: str
    resolution_strategy: Optional[str] = None


@dataclass
class ExecutionPlan:
    """执行计划"""
    tasks: Dict[str, TaskNode]              # 所有任务
    ready_queue: List[TaskNode]             # 就绪队列（优先级堆）
    running_tasks: Dict[str, asyncio.Task]  # 运行中的任务
    completed_tasks: Set[str]               # 已完成任务
    failed_tasks: Set[str]                  # 失败任务
    dag_levels: List[List[str]]             # DAG层级（每层的任务可并行）

    # 执行统计
    total_tasks: int = 0
    completed_count: int = 0
    failed_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


# ==================== DAG分析器 ====================

class DAGAnalyzer:
    """DAG（有向无环图）分析器"""

    def __init__(self):
        self._tasks: Dict[str, TaskNode] = {}

    def build_dag(self, task_list: List[Dict[str, Any]]) -> Dict[str, TaskNode]:
        """
        构建DAG

        Args:
            task_list: 任务列表，每个任务包含：
                - task_id: 任务ID
                - task_type: 任务类型
                - task_data: 任务数据
                - dependencies: 依赖任务ID列表
                - priority: 优先级（可选）

        Returns:
            task_id -> TaskNode映射
        """
        self._tasks = {}

        # 第一遍：创建所有节点
        for task_info in task_list:
            node = TaskNode(
                task_id=task_info["task_id"],
                task_type=task_info["task_type"],
                task_data=task_info.get("task_data", {}),
                dependencies=set(task_info.get("dependencies", []))
            )

            if "priority" in task_info:
                node.priority = TaskPriority(priority=task_info["priority"])

            self._tasks[node.task_id] = node

        # 第二遍：建立依赖关系
        for task_id, node in self._tasks.items():
            for dep_id in node.dependencies:
                if dep_id in self._tasks:
                    self._tasks[dep_id].dependents.add(task_id)
                else:
                    logger.warning(f"依赖不存在: {task_id} -> {dep_id}")

        # 验证DAG
        if not self._validate_dag():
            raise ValueError("DAG包含循环依赖")

        return self._tasks

    def _validate_dag(self) -> bool:
        """验证DAG是否为有向无环图"""
        # 使用Kahn算法检测环
        # 只考虑DAG中实际存在的任务
        in_degree = {
            task_id: len([dep for dep in node.dependencies if dep in self._tasks])
            for task_id, node in self._tasks.items()
        }
        queue = [task_id for task_id, degree in in_degree.items() if degree == 0]
        visited = 0

        while queue:
            task_id = queue.pop(0)
            visited += 1

            for dependent_id in self._tasks[task_id].dependents:
                in_degree[dependent_id] -= 1
                if in_degree[dependent_id] == 0:
                    queue.append(dependent_id)

        return visited == len(self._tasks)

    def topological_sort(self) -> List[List[str]]:
        """
        拓扑排序并分层

        Returns:
            分层的任务列表，每层的任务可以并行执行
        """
        # 计算每个任务的层级
        levels = {}

        def get_level(task_id: str) -> int:
            if task_id in levels:
                return levels[task_id]

            if not self._tasks[task_id].dependencies:
                levels[task_id] = 0
            else:
                max_dep_level = max(get_level(dep_id) for dep_id in self._tasks[task_id].dependencies)
                levels[task_id] = max_dep_level + 1

            return levels[task_id]

        # 计算所有任务的层级
        for task_id in self._tasks:
            get_level(task_id)

        # 按层级分组
        level_groups = {}
        for task_id, level in levels.items():
            if level not in level_groups:
                level_groups[level] = []
            level_groups[level].append(task_id)

        # 排序并返回
        sorted_levels = sorted(level_groups.items())
        return [tasks for _, tasks in sorted_levels]

    def find_ready_tasks(self, completed: Set[str]) -> List[TaskNode]:
        """
        找出所有就绪任务（依赖已满足）

        Args:
            completed: 已完成的任务ID集合

        Returns:
            就绪任务列表
        """
        ready = []

        for task_id, node in self._tasks.items():
            if node.status == TaskStatus.PENDING:
                # 检查依赖是否都已完成
                if node.dependencies.issubset(completed):
                    node.status = TaskStatus.READY
                    ready.append(node)

        return ready


# ==================== 冲突检测器 ====================

class ConflictDetector:
    """冲突检测器"""

    def __init__(self):
        self._resource_usage: Dict[str, float] = {}  # resource_type -> usage
        self._data_access: Dict[str, Set[str]] = {}  # data_path -> {task_ids}
        self._tool_usage: Dict[str, Set[str]] = {}   # tool_name -> {task_ids}
        self._network_targets: Dict[str, Set[str]] = {}  # target -> {task_ids}

    def detect_conflicts(
        self,
        task: TaskNode,
        running_tasks: Dict[str, TaskNode]
    ) -> List[ConflictInfo]:
        """
        检测任务与运行中任务的冲突

        Args:
            task: 待检测任务
            running_tasks: 运行中的任务

        Returns:
            冲突列表
        """
        conflicts = []

        for running_id, running_task in running_tasks.items():
            # 跳过自己
            if task.task_id == running_id:
                continue

            # 检测资源冲突
            if self._check_resource_conflict(task, running_task):
                conflicts.append(ConflictInfo(
                    conflict_type=ConflictType.RESOURCE,
                    task1_id=task.task_id,
                    task2_id=running_id,
                    reason=f"CPU/内存资源冲突"
                ))

            # 检测数据冲突
            data_conflict = self._check_data_conflict(task, running_task)
            if data_conflict:
                conflicts.append(ConflictInfo(
                    conflict_type=ConflictType.DATA,
                    task1_id=task.task_id,
                    task2_id=running_id,
                    reason=data_conflict
                ))

            # 检测工具冲突
            tool_conflict = self._check_tool_conflict(task, running_task)
            if tool_conflict:
                conflicts.append(ConflictInfo(
                    conflict_type=ConflictType.TOOL,
                    task1_id=task.task_id,
                    task2_id=running_id,
                    reason=tool_conflict
                ))

            # 检测网络冲突
            network_conflict = self._check_network_conflict(task, running_task)
            if network_conflict:
                conflicts.append(ConflictInfo(
                    conflict_type=ConflictType.NETWORK,
                    task1_id=task.task_id,
                    task2_id=running_id,
                    reason=network_conflict
                ))

        return conflicts

    def _check_resource_conflict(self, task1: TaskNode, task2: TaskNode) -> bool:
        """检查资源冲突"""
        total_cpu = task1.estimated_cpu + task2.estimated_cpu
        total_memory = task1.estimated_memory + task2.estimated_memory

        # 获取系统资源
        cpu_count = psutil.cpu_count()
        available_memory = psutil.virtual_memory().available / 1024 / 1024  # MB

        # 检查是否超出限制
        cpu_usage = (total_cpu / cpu_count) * 100 if cpu_count > 0 else 0
        memory_usage = (total_memory / available_memory) * 100 if available_memory > 0 else 0

        return cpu_usage > 90 or memory_usage > 90

    def _check_data_conflict(self, task1: TaskNode, task2: TaskNode) -> Optional[str]:
        """检查数据冲突"""
        # 从task_data中提取可能的数据路径
        data1 = self._extract_data_paths(task1)
        data2 = self._extract_data_paths(task2)

        conflicts = data1 & data2
        if conflicts:
            # 检查读写冲突
            if self._has_write_conflict(task1, task2, conflicts):
                return f"数据读写冲突: {', '.join(conflicts)}"

        return None

    def _extract_data_paths(self, task: TaskNode) -> Set[str]:
        """从任务数据中提取数据路径"""
        paths = set()

        # 常见的路径字段
        path_fields = ["target", "file", "path", "output", "input"]

        for field in path_fields:
            if field in task.task_data:
                value = task.task_data[field]
                if isinstance(value, str):
                    paths.add(value)
                elif isinstance(value, list):
                    paths.update(value)

        return paths

    def _has_write_conflict(self, task1: TaskNode, task2: TaskNode, paths: Set[str]) -> bool:
        """检查是否有写入冲突"""
        # 简化版本：如果任务类型涉及写入，则认为有冲突
        write_types = ["write", "upload", "modify", "delete", "exploit"]

        task1_writes = any(wt in task1.task_type.lower() for wt in write_types)
        task2_writes = any(wt in task2.task_type.lower() for wt in write_types)

        return task1_writes or task2_writes

    def _check_tool_conflict(self, task1: TaskNode, task2: TaskNode) -> Optional[str]:
        """检查工具冲突"""
        # 找出共同使用的工具
        tools1 = set(task1.required_tools)
        tools2 = set(task2.required_tools)
        common_tools = tools1 & tools2

        # 某些工具不能并发执行
        exclusive_tools = {
            "nmap_scan", "masscan_scan",  # 端口扫描工具
            "hydra_attack", "medusa_bruteforce",  # 暴力破解
        }

        conflicts = common_tools & exclusive_tools
        if conflicts:
            return f"互斥工具冲突: {', '.join(conflicts)}"

        return None

    def _check_network_conflict(self, task1: TaskNode, task2: TaskNode) -> Optional[str]:
        """检查网络冲突"""
        # 提取目标
        target1 = task1.task_data.get("target", "")
        target2 = task2.task_data.get("target", "")

        if target1 and target2 and target1 == target2:
            # 相同目标，检查端口
            port1 = task1.task_data.get("port")
            port2 = task2.task_data.get("port")

            if port1 and port2 and port1 == port2:
                return f"网络冲突: 相同目标端口 {target1}:{port1}"

        return None


# ==================== 自适应并行引擎 ====================

class AdaptiveParallelEngine:
    """
    自适应并行执行引擎

    核心功能：
    1. 动态并行度调整 - 根据任务类型和系统负载自动调整并行度
    2. DAG任务调度 - 基于依赖关系的智能调度
    3. 资源感知调度 - 考虑CPU、内存、网络等资源限制
    4. 冲突检测和解决 - 自动检测并解决任务冲突
    """

    def __init__(
        self,
        min_parallelism: int = 2,
        max_parallelism: int = 16,
        default_parallelism: int = 4
    ):
        """
        初始化并行引擎

        Args:
            min_parallelism: 最小并行度
            max_parallelism: 最大并行度
            default_parallelism: 默认并行度
        """
        self.min_parallelism = min_parallelism
        self.max_parallelism = max_parallelism
        self.default_parallelism = default_parallelism

        self.dag_analyzer = DAGAnalyzer()
        self.conflict_detector = ConflictDetector()

        self._lock = Lock()
        self._running = False
        self._executor = ThreadPoolExecutor(max_workers=self.max_parallelism)

        # 统计信息
        self.stats = {
            "total_executions": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "conflicts_detected": 0,
            "conflicts_resolved": 0,
            "avg_parallelism": 0.0
        }

        logger.info(
            f"AdaptiveParallelEngine初始化完成: "
            f"parallelism=[{min_parallelism}-{max_parallelism}], default={default_parallelism}"
        )

    async def execute_plan(
        self,
        tasks: List[Dict[str, Any]],
        task_executor: Callable,
        context: Optional[Dict[str, Any]] = None
    ) -> ExecutionPlan:
        """
        执行任务计划

        Args:
            tasks: 任务列表
            task_executor: 任务执行器函数 (task_node, context) -> result
            context: 执行上下文

        Returns:
            执行计划结果
        """
        start_time = datetime.now()

        # 1. 构建DAG
        logger.info(f"构建DAG，任务数: {len(tasks)}")
        task_nodes = self.dag_analyzer.build_dag(tasks)

        # 2. 分析层级
        dag_levels = self.dag_analyzer.topological_sort()
        logger.info(f"DAG层级数: {len(dag_levels)}")

        # 3. 创建执行计划
        plan = ExecutionPlan(
            tasks=task_nodes,
            ready_queue=[],
            running_tasks={},
            completed_tasks=set(),
            failed_tasks=set(),
            dag_levels=dag_levels,
            total_tasks=len(tasks),
            start_time=start_time
        )

        self.stats["total_executions"] += 1

        # 4. 执行任务
        try:
            await self._execute_dag(plan, task_executor, context or {})

        except Exception as e:
            logger.error(f"执行失败: {e}")
            raise

        finally:
            plan.end_time = datetime.now()

        # 5. 返回结果
        return plan

    async def _execute_dag(
        self,
        plan: ExecutionPlan,
        task_executor: Callable,
        context: Dict[str, Any]
    ):
        """执行DAG任务"""

        # 初始化：找出所有无依赖的任务
        initial_ready = self.dag_analyzer.find_ready_tasks(set())
        for node in initial_ready:
            heapq.heappush(plan.ready_queue, node)

        # 动态并行度调整
        parallelism = self._calculate_initial_parallelism(plan)
        logger.info(f"初始并行度: {parallelism}")

        # 主执行循环
        while plan.ready_queue or plan.running_tasks:
            # 调整并行度
            parallelism = self._adjust_parallelism(plan, parallelism)
            self.stats["avg_parallelism"] = (
                self.stats["avg_parallelism"] * 0.9 + parallelism * 0.1
            )

            # 启动新任务（直到达到并行度限制）
            while plan.ready_queue and len(plan.running_tasks) < parallelism:
                task_node = heapq.heappop(plan.ready_queue)

                # 冲突检测
                conflicts = self.conflict_detector.detect_conflicts(
                    task_node,
                    {tid: self._get_task_node(plan, tid) for tid in plan.running_tasks}
                )

                if conflicts:
                    self.stats["conflicts_detected"] += len(conflicts)
                    logger.warning(
                        f"任务冲突检测: {task_node.task_id}, 冲突数: {len(conflicts)}"
                    )

                    # 解决冲突：重新入队（降低优先级）
                    task_node.priority.priority = max(1, task_node.priority.priority - 1)
                    heapq.heappush(plan.ready_queue, task_node)
                    self.stats["conflicts_resolved"] += 1
                    continue

                # 启动任务
                await self._start_task(plan, task_node, task_executor, context)

            # 等待任一任务完成
            if plan.running_tasks:
                done, _ = await asyncio.wait(
                    plan.running_tasks.values(),
                    return_when=asyncio.FIRST_COMPLETED
                )

                # 处理完成的任务
                for task in done:
                    # 找到对应的task_id
                    task_id = None
                    for tid, t in plan.running_tasks.items():
                        if t == task:
                            task_id = tid
                            break

                    if task_id:
                        await self._handle_task_completion(plan, task_id, task)

            # 检查是否可以添加新的就绪任务
            new_ready = self.dag_analyzer.find_ready_tasks(plan.completed_tasks)
            for node in new_ready:
                if node not in plan.ready_queue:
                    heapq.heappush(plan.ready_queue, node)

        logger.info(
            f"DAG执行完成: 完成={plan.completed_count}, 失败={plan.failed_count}"
        )

    async def _start_task(
        self,
        plan: ExecutionPlan,
        task_node: TaskNode,
        task_executor: Callable,
        context: Dict[str, Any]
    ):
        """启动单个任务"""
        task_node.status = TaskStatus.RUNNING
        task_node.start_time = datetime.now()

        async def _wrapper():
            try:
                result = await task_executor(task_node, context)
                return {"success": True, "result": result, "task_id": task_node.task_id}
            except Exception as e:
                logger.error(f"任务执行失败: {task_node.task_id}: {e}")
                return {"success": False, "error": str(e), "task_id": task_node.task_id}

        # 创建异步任务
        task = asyncio.create_task(_wrapper())
        plan.running_tasks[task_node.task_id] = task

        logger.debug(f"任务启动: {task_node.task_id}, 运行中: {len(plan.running_tasks)}")

    async def _handle_task_completion(
        self,
        plan: ExecutionPlan,
        task_id: str,
        task: asyncio.Task
    ):
        """处理任务完成"""
        result = await task

        # 从运行列表移除
        del plan.running_tasks[task_id]

        # 更新任务节点
        task_node = plan.tasks[task_id]
        task_node.end_time = datetime.now()
        task_node.execution_time = (
            task_node.end_time - task_node.start_time
        ).total_seconds()

        if result.get("success"):
            task_node.status = TaskStatus.COMPLETED
            task_node.result = result.get("result")
            plan.completed_tasks.add(task_id)
            plan.completed_count += 1
            self.stats["completed_tasks"] += 1

            logger.info(f"任务完成: {task_id}, 耗时: {task_node.execution_time:.2f}秒")
        else:
            task_node.status = TaskStatus.FAILED
            task_node.error = result.get("error")
            plan.failed_tasks.add(task_id)
            plan.failed_count += 1
            self.stats["failed_tasks"] += 1

            logger.error(f"任务失败: {task_id}, 错误: {task_node.error}")

    def _calculate_initial_parallelism(self, plan: ExecutionPlan) -> int:
        """计算初始并行度"""
        # 考虑因素：
        # 1. 系统CPU核心数
        cpu_count = psutil.cpu_count()

        # 2. 任务类型（I/O密集 vs CPU密集）
        io_intensive_ratio = self._estimate_io_intensive_ratio(plan)

        # 3. 当前系统负载
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_percent = psutil.virtual_memory().percent

        # 计算基础并行度
        if io_intensive_ratio > 0.7:
            # I/O密集型：可以更高并行度
            base_parallelism = min(cpu_count * 2, self.max_parallelism)
        else:
            # CPU密集型：限制并行度
            base_parallelism = min(cpu_count, self.max_parallelism)

        # 根据系统负载调整
        if cpu_percent > 80 or memory_percent > 80:
            base_parallelism = max(self.min_parallelism, base_parallelism // 2)

        return int(base_parallelism)

    def _adjust_parallelism(self, plan: ExecutionPlan, current: int) -> int:
        """动态调整并行度"""
        # 获取当前系统状态
        cpu_percent = psutil.cpu_percent(interval=0.01)
        memory_percent = psutil.virtual_memory().percent
        running_count = len(plan.running_tasks)

        # 调整策略
        new_parallelism = current

        if cpu_percent > 90 or memory_percent > 90:
            # 系统负载高：降低并行度
            new_parallelism = max(self.min_parallelism, current - 1)
        elif cpu_percent < 30 and memory_percent < 50 and running_count < current:
            # 系统负载低：可以提高并行度
            new_parallelism = min(self.max_parallelism, current + 1)

        return new_parallelism

    def _estimate_io_intensive_ratio(self, plan: ExecutionPlan) -> float:
        """估算I/O密集型任务比例"""
        io_intensive_types = {
            "scan", "recon", "enum", "query", "http", "network",
            "web", "dns", "subdomain", "directory"
        }

        io_count = 0
        total = len(plan.tasks)

        for task_node in plan.tasks.values():
            task_type_lower = task_node.task_type.lower()
            if any(io_type in task_type_lower for io_type in io_intensive_types):
                io_count += 1

        return io_count / total if total > 0 else 0.5

    def _get_task_node(self, plan: ExecutionPlan, task_id: str) -> Optional[TaskNode]:
        """获取任务节点"""
        return plan.tasks.get(task_id)


# ==================== 导出 ====================

__all__ = [
    'AdaptiveParallelEngine',
    'DAGAnalyzer',
    'ConflictDetector',
    'TaskStatus',
    'ConflictType',
    'TaskPriority',
    'TaskNode',
    'ConflictInfo',
    'ExecutionPlan'
]
