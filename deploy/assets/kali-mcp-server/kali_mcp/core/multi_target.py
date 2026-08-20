#!/usr/bin/env python3
"""
多目标协调和攻击编排系统

从 mcp_server.py 提取:
- TargetProfile: 目标配置数据类
- AttackTask: 攻击任务数据类
- MultiTargetOrchestrator: 多目标编排器
"""

import uuid
import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class TargetProfile:
    """目标配置文件数据类"""
    target_id: str
    target_url: str
    target_type: str = "unknown"  # web, network, mobile, cloud
    priority: int = 1  # 1-10, 10 为最高优先级
    status: str = "pending"  # pending, active, completed, failed
    assigned_strategy: Optional[str] = None
    discovered_assets: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_progress: Dict[str, Any] = field(default_factory=dict)
    dependency_targets: List[str] = field(default_factory=list)  # 依赖的其他目标
    estimated_completion_time: Optional[datetime] = None
    last_update: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackTask:
    """攻击任务数据类"""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    tool_name: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    strategy_context: str = ""
    priority: int = 1
    status: str = "queued"  # queued, running, completed, failed, paused
    dependencies: List[str] = field(default_factory=list)  # 依赖的其他任务ID
    estimated_duration: int = 30  # 预估执行时间（秒）
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class MultiTargetOrchestrator:
    """多目标协调攻击编排器"""

    def __init__(self):
        self.targets: Dict[str, TargetProfile] = {}
        self.attack_tasks: Dict[str, AttackTask] = {}
        self.task_queue: List[str] = []  # 任务ID队列
        self.running_tasks: Dict[str, AttackTask] = {}
        self.completed_tasks: Dict[str, AttackTask] = {}
        self.failed_tasks: Dict[str, AttackTask] = {}

        # 协调参数
        self.max_concurrent_tasks = 5
        self.max_tasks_per_target = 3
        self.coordination_strategies = {
            "adaptive": self._adaptive_strategy
        }
        self.current_strategy = "adaptive"

        # 性能监控
        self.performance_metrics = {
            "total_targets": 0,
            "completed_targets": 0,
            "failed_targets": 0,
            "average_completion_time": 0,
            "success_rate": 0,
            "resource_utilization": 0
        }

    def add_target(self, target_url: str, target_type: str = "unknown",
                   priority: int = 1, dependencies: List[str] = None) -> str:
        """添加新目标到协调系统"""
        target_id = f"target_{int(time.time())}_{random.randint(1000, 9999)}"

        target_profile = TargetProfile(
            target_id=target_id,
            target_url=target_url,
            target_type=target_type,
            priority=priority,
            dependency_targets=dependencies or []
        )

        self.targets[target_id] = target_profile
        self.performance_metrics["total_targets"] += 1

        return target_id

    def orchestrate_attack(self, strategy: str = None) -> Dict[str, Any]:
        """执行攻击编排"""
        if strategy:
            self.current_strategy = strategy

        if self.current_strategy not in self.coordination_strategies:
            raise ValueError(f"未知的协调策略: {self.current_strategy}")

        orchestration_plan = self.coordination_strategies[self.current_strategy]()

        return {
            "orchestration_strategy": self.current_strategy,
            "execution_plan": orchestration_plan,
            "targets_count": len(self.targets),
            "tasks_count": len(self.attack_tasks),
            "estimated_total_time": self._estimate_total_execution_time(orchestration_plan)
        }

    def _adaptive_strategy(self) -> Dict[str, Any]:
        """自适应策略 - 根据目标类型和依赖关系动态调整"""
        execution_plan = []

        # 分析目标类型分布
        target_types = {}
        for target in self.targets.values():
            target_types[target.target_type] = target_types.get(target.target_type, 0) + 1

        # 处理依赖关系
        dependency_graph = self._build_dependency_graph()
        execution_order = self._topological_sort(dependency_graph)

        # 为每个执行阶段分配任务
        for phase, target_ids in enumerate(execution_order):
            phase_tasks = []

            for target_id in target_ids:
                target_tasks = [task for task in self.attack_tasks.values()
                              if task.target_id == target_id and task.status == "queued"]

                # 根据目标类型选择最佳工具组合
                optimized_tasks = self._optimize_task_sequence(target_tasks, self.targets[target_id])
                phase_tasks.extend(optimized_tasks)

            if phase_tasks:
                execution_plan.append({
                    "phase": phase + 1,
                    "execution_mode": "adaptive",
                    "target_count": len(target_ids),
                    "tasks": [
                        {
                            "task_id": task.task_id,
                            "target_id": task.target_id,
                            "tool": task.tool_name,
                            "adaptation_reason": task.metadata.get("adaptation_reason", "优化选择"),
                            "estimated_duration": task.estimated_duration
                        } for task in phase_tasks
                    ]
                })

        return {"strategy": "adaptive", "execution_phases": execution_plan}

    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """构建目标依赖图"""
        graph = {}
        for target_id, target in self.targets.items():
            graph[target_id] = target.dependency_targets
        return graph

    def _topological_sort(self, graph: Dict[str, List[str]]) -> List[List[str]]:
        """拓扑排序，返回按依赖层级排序的目标组"""
        in_degree = {node: 0 for node in graph}

        # 计算入度
        for node in graph:
            for neighbor in graph[node]:
                if neighbor in in_degree:
                    in_degree[neighbor] += 1

        # 按层级分组
        levels = []
        remaining_nodes = set(graph.keys())

        while remaining_nodes:
            # 找到当前层级的节点（入度为0）
            current_level = [node for node in remaining_nodes if in_degree[node] == 0]
            if not current_level:
                break

            levels.append(current_level)

            # 移除当前层级的节点并更新入度
            for node in current_level:
                remaining_nodes.remove(node)
                for neighbor in graph[node]:
                    if neighbor in in_degree:
                        in_degree[neighbor] -= 1

        return levels

    def _optimize_task_sequence(self, tasks: List[AttackTask], target: TargetProfile) -> List[AttackTask]:
        """根据目标特征优化任务序列"""
        optimization_rules = {
            "web": ["nmap", "dirb", "nikto", "sqlmap", "xsser"],
            "network": ["nmap", "masscan", "zmap", "ncrack"],
            "mobile": ["apktool", "jadx", "frida"],
            "cloud": ["cloudenum", "s3scanner", "awscli"]
        }

        preferred_order = optimization_rules.get(target.target_type, [])
        optimized_tasks = []

        # 首先添加按优先顺序排列的工具
        for tool_name in preferred_order:
            matching_tasks = [task for task in tasks if task.tool_name == tool_name]
            optimized_tasks.extend(matching_tasks)

        # 添加其他任务
        remaining_tasks = [task for task in tasks if task not in optimized_tasks]
        remaining_tasks.sort(key=lambda t: t.priority, reverse=True)
        optimized_tasks.extend(remaining_tasks)

        return optimized_tasks

    def _estimate_total_execution_time(self, orchestration_plan: Dict[str, Any]) -> int:
        """估算总执行时间"""
        total_time = 0
        phases = orchestration_plan.get("execution_phases", [])

        for phase in phases:
            phase_tasks = phase.get("tasks", [])
            if phase_tasks:
                # 假设阶段内任务可以部分并行
                phase_time = max([task.get("estimated_duration", 30) for task in phase_tasks] or [0])
                total_time += phase_time

        return total_time

    def get_orchestration_status(self) -> Dict[str, Any]:
        """获取编排状态"""
        total_tasks = len(self.attack_tasks)
        running_count = len(self.running_tasks)
        completed_count = len(self.completed_tasks)
        failed_count = len(self.failed_tasks)
        queued_count = len([task for task in self.attack_tasks.values() if task.status == "queued"])

        return {
            "total_targets": len(self.targets),
            "active_targets": len([t for t in self.targets.values() if t.status == "active"]),
            "completed_targets": len([t for t in self.targets.values() if t.status == "completed"]),
            "total_tasks": total_tasks,
            "queued_tasks": queued_count,
            "running_tasks": running_count,
            "completed_tasks": completed_count,
            "failed_tasks": failed_count,
            "success_rate": (completed_count / total_tasks * 100) if total_tasks > 0 else 0,
            "current_strategy": self.current_strategy,
            "resource_utilization": (running_count / self.max_concurrent_tasks * 100) if self.max_concurrent_tasks > 0 else 0,
            "performance_metrics": self.performance_metrics
        }

# 全局多目标编排器实例
multi_target_orchestrator = MultiTargetOrchestrator()

# ==================== 高级上下文关联和模式识别系统 ====================

