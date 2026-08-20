#!/usr/bin/env python3
"""
任务分解器 (TaskDecomposer)

将高层攻击意图分解为可执行的任务图：
- 策略模板管理
- 任务分解规则
- 依赖关系生成
- 执行计划构建

作者: SeaOf0
"""

import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

from kali_mcp.core.intent_analyzer import (
    IntentAnalysis,
    AttackIntent,
    TargetInfo,
    TargetType
)

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class TaskCategory(Enum):
    """任务类别"""
    RECONNAISSANCE = "recon"           # 信息收集
    SCANNING = "scan"                   # 扫描
    VULNERABILITY_SCANNING = "scan"     # 兼容旧名称
    EXPLOITATION = "exploit"            # 利用
    POST_EXPLOITATION = "post_exploit"  # 后渗透
    REPORTING = "report"                # 报告


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Task:
    """任务定义"""
    task_id: str                       # 任务ID
    name: str                          # 任务名称
    category: TaskCategory             # 任务类别
    tool_name: str                     # 使用的工具
    parameters: Dict[str, Any]         # 工具参数

    # 依赖和优先级
    dependencies: List[str] = field(default_factory=list)  # 依赖的任务ID列表
    priority: int = 5                  # 优先级（1-10）

    # 元数据
    estimated_duration: Optional[int] = None  # 预估时长（秒）
    description: Optional[str] = None         # 任务描述
    tags: Set[str] = field(default_factory=set)  # 标签

    # 执行状态
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict] = None
    error: Optional[str] = None


@dataclass
class TaskGraph:
    """任务图（DAG）"""
    tasks: Dict[str, Task]             # 所有任务 {task_id: Task}
    adjacency_list: Dict[str, Set[str]] = field(default_factory=dict)  # 邻接表 {task_id: dependent_ids}
    reverse_adjacency: Dict[str, Set[str]] = field(default_factory=dict)  # 反向邻接表

    def add_task(self, task: Task):
        """添加任务到图"""
        self.tasks[task.task_id] = task
        if task.task_id not in self.adjacency_list:
            self.adjacency_list[task.task_id] = set()
        if task.task_id not in self.reverse_adjacency:
            self.reverse_adjacency[task.task_id] = set()

        # 添加依赖关系
        for dep_id in task.dependencies:
            if dep_id not in self.adjacency_list:
                self.adjacency_list[dep_id] = set()
            if dep_id not in self.reverse_adjacency:
                self.reverse_adjacency[dep_id] = set()
            self.adjacency_list[dep_id].add(task.task_id)
            self.reverse_adjacency[task.task_id].add(dep_id)

    def get_ready_tasks(self) -> List[Task]:
        """获取所有就绪任务（无未完成依赖）"""
        ready = []
        for task_id, task in self.tasks.items():
            if task.status != TaskStatus.PENDING:
                continue

            # 检查所有依赖是否完成
            dependencies_completed = all(
                self.tasks[dep_id].status == TaskStatus.COMPLETED
                for dep_id in task.dependencies
                if dep_id in self.tasks
            )

            if dependencies_completed:
                ready.append(task)

        return ready

    def validate(self) -> Tuple[bool, List[str]]:
        """验证任务图（检测循环依赖等）"""
        errors = []

        # 检测循环依赖
        visited = set()
        rec_stack = set()

        def has_cycle(task_id: str) -> bool:
            visited.add(task_id)
            rec_stack.add(task_id)

            for neighbor in self.adjacency_list.get(task_id, set()):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True

            rec_stack.remove(task_id)
            return False

        for task_id in self.tasks:
            if task_id not in visited:
                if has_cycle(task_id):
                    errors.append(f"检测到循环依赖: {task_id}")

        # 检查依赖是否存在
        for task_id, task in self.tasks.items():
            for dep_id in task.dependencies:
                if dep_id not in self.tasks:
                    errors.append(f"任务 {task_id} 依赖不存在的任务 {dep_id}")

        return len(errors) == 0, errors


@dataclass
class ExecutionPlan:
    """执行计划"""
    task_graph: TaskGraph               # 任务图
    phases: List[List[str]]             # 执行阶段（每阶段可并行）
    estimated_duration: int             # 总预估时长
    metadata: Dict[str, Any]            # 元数据

    def get_phase_tasks(self, phase_index: int) -> List[Task]:
        """获取指定阶段的任务"""
        if phase_index >= len(self.phases):
            return []
        return [
            self.task_graph.tasks[task_id]
            for task_id in self.phases[phase_index]
            if task_id in self.task_graph.tasks
        ]


# ==================== 策略模板 ====================

@dataclass
class StrategyTemplate:
    """策略模板"""
    name: str                          # 策略名称
    description: str                    # 描述
    required_intents: Set[AttackIntent] # 适用的意图类型
    task_template: List[Dict]          # 任务模板

    def matches(self, intent: AttackIntent) -> bool:
        """检查是否匹配意图"""
        return intent in self.required_intents


# ==================== 任务分解器 ====================

class TaskDecomposer:
    """
    任务分解器

    将高层意图分解为可执行的任务图
    """

    def __init__(self):
        """初始化任务分解器"""
        self._strategy_templates = self._init_strategy_templates()
        logger.info("TaskDecomposer初始化完成")

    def decompose(self, intent_analysis: IntentAnalysis) -> ExecutionPlan:
        """
        分解意图分析为执行计划

        Args:
            intent_analysis: 意图分析结果

        Returns:
            执行计划
        """
        logger.info(f"开始分解任务: {intent_analysis.intent.value}")

        # 1. 优先尝试策略蓝图（强约束模式）
        strategy_blueprint = self._extract_strategy_blueprint(intent_analysis)
        template = self._select_template(intent_analysis.intent)

        # 2. 生成任务图
        if strategy_blueprint:
            task_graph = self._build_task_graph_from_strategy(
                intent_analysis,
                strategy_blueprint,
            )
            strategy_name = (
                strategy_blueprint.get("profile", {}).get("mode")
                or strategy_blueprint.get("name")
                or f"{template.name}_strategy"
            )
            strategy_mode = "planner_driven"
        else:
            task_graph = self._build_task_graph(
                intent_analysis,
                template
            )
            strategy_name = template.name
            strategy_mode = "template"

        # 3. 计算执行阶段
        phases = self._calculate_execution_phases(task_graph)

        # 4. 估算时长
        total_duration = self._estimate_total_duration(task_graph)

        # 5. 创建执行计划
        plan = ExecutionPlan(
            task_graph=task_graph,
            phases=phases,
            estimated_duration=total_duration,
            metadata={
                "strategy": strategy_name,
                "strategy_mode": strategy_mode,
                "intent": intent_analysis.intent.value,
                "target_count": len(intent_analysis.targets),
                "created_at": datetime.now().isoformat()
            }
        )

        logger.info(f"任务分解完成: {len(task_graph.tasks)}个任务, {len(phases)}个阶段")

        return plan

    def _select_template(self, intent: AttackIntent) -> StrategyTemplate:
        """选择策略模板"""
        # 优先匹配完全对应的模板
        for template in self._strategy_templates:
            if intent in template.required_intents:
                return template

        # 默认使用侦察策略
        return self._strategy_templates[0]

    @staticmethod
    def _extract_strategy_blueprint(intent_analysis: IntentAnalysis) -> Optional[Dict[str, Any]]:
        """从约束中提取策略蓝图。"""
        for constraint in intent_analysis.constraints or []:
            if not isinstance(constraint, dict):
                continue
            constraint_type = str(constraint.get("type", "")).lower()
            if constraint_type not in {
                "execution_strategy",
                "strategy_blueprint",
                "pentest_strategy",
            }:
                continue
            strategy = constraint.get("strategy")
            if isinstance(strategy, dict) and isinstance(strategy.get("stages"), list):
                return strategy
        return None

    @staticmethod
    def _infer_stage_category(stage_id: str) -> TaskCategory:
        normalized = (stage_id or "").lower()
        if any(token in normalized for token in ("recon", "mapping", "surface")):
            return TaskCategory.RECONNAISSANCE
        if any(token in normalized for token in ("exploit", "flag", "pivot", "lateral")):
            return TaskCategory.EXPLOITATION
        if any(token in normalized for token in ("report", "fix", "remediation")):
            return TaskCategory.REPORTING
        return TaskCategory.SCANNING

    def _build_task_graph_from_strategy(
        self,
        intent_analysis: IntentAnalysis,
        strategy_blueprint: Dict[str, Any],
    ) -> TaskGraph:
        """按策略阶段构建任务图（阶段间强依赖）。"""
        task_graph = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        stages = strategy_blueprint.get("stages", [])

        for target_idx, target in enumerate(intent_analysis.targets):
            previous_stage_task_ids: List[str] = []

            for stage_idx, stage in enumerate(stages):
                stage_id = stage.get("id") or f"stage_{stage_idx}"
                stage_name = stage.get("name") or stage_id
                stage_tools = list(stage.get("recommended_tools", []))
                backup_tools = list(stage.get("backup_tools", []))
                stage_agents = list(stage.get("agents", []))
                gate_requirements = dict(stage.get("gate_requirements", {}))

                ordered_tools = []
                for tool in stage_tools + backup_tools:
                    if tool and tool not in ordered_tools:
                        ordered_tools.append(tool)
                if not ordered_tools:
                    ordered_tools = ["manual_validation"]

                current_stage_task_ids: List[str] = []

                for tool_idx, tool_name in enumerate(ordered_tools):
                    template = {
                        "tool": tool_name,
                        "parameters": {
                            "strategy_stage_id": stage_id,
                            "strategy_stage_name": stage_name,
                            "strategy_stage_index": stage_idx,
                            "strategy_allowed_tools": ordered_tools,
                            "strategy_preferred_agents": stage_agents,
                            "strategy_gate_requirements": gate_requirements,
                        },
                    }
                    task_id = f"{target.type.value}_{target_idx}_s{stage_idx}_{tool_idx}"
                    task = Task(
                        task_id=task_id,
                        name=f"{stage_name}::{tool_name}",
                        category=self._infer_stage_category(stage_id),
                        tool_name=tool_name,
                        parameters=self._build_task_parameters(template, target, intent_analysis),
                        dependencies=previous_stage_task_ids.copy(),
                        priority=max(1, 10 - stage_idx - (1 if tool_name in backup_tools else 0)),
                        estimated_duration=None,
                        description=stage.get("objective"),
                        tags={"strategy_driven", stage_id},
                    )
                    task_graph.add_task(task)
                    current_stage_task_ids.append(task_id)

                if current_stage_task_ids:
                    previous_stage_task_ids = current_stage_task_ids

        return task_graph

    def _build_task_graph(
        self,
        intent_analysis: IntentAnalysis,
        template: StrategyTemplate
    ) -> TaskGraph:
        """构建任务图"""
        task_graph = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})

        # 为每个目标生成任务
        for target_idx, target in enumerate(intent_analysis.targets):
            target_tasks = self._generate_tasks_for_target(
                target,
                target_idx,
                intent_analysis,
                template
            )

            # 添加到任务图
            for task in target_tasks:
                task_graph.add_task(task)

        return task_graph

    def _generate_tasks_for_target(
        self,
        target: TargetInfo,
        target_idx: int,
        intent_analysis: IntentAnalysis,
        template: StrategyTemplate
    ) -> List[Task]:
        """为单个目标生成任务列表"""
        tasks = []
        task_counter = 0
        task_id_map = {}  # 索引到task_id的映射

        # 第一遍：创建所有任务并建立ID映射
        for task_template in template.task_template:
            task_id = f"{target.type.value}_{target_idx}_{task_counter}"
            task_id_map[task_counter] = task_id
            task_counter += 1

            task = Task(
                task_id=task_id,
                name=task_template.get("name", f"{task_template['tool']} on {target.value}"),
                category=TaskCategory(task_template.get("category", "scan")),
                tool_name=task_template["tool"],
                parameters=self._build_task_parameters(
                    task_template,
                    target,
                    intent_analysis
                ),
                dependencies=[],  # 先留空，第二遍填充
                priority=task_template.get("priority", 5),
                estimated_duration=task_template.get("duration"),
                description=task_template.get("description"),
                tags=set(task_template.get("tags", []))
            )

            tasks.append(task)

        # 第二遍：转换依赖关系
        for i, task_template in enumerate(template.task_template):
            template_deps = task_template.get("dependencies", [])
            resolved_deps = []

            for dep in template_deps:
                if isinstance(dep, int) and dep in task_id_map:
                    # 依赖是同目标内的任务索引
                    resolved_deps.append(task_id_map[dep])
                elif isinstance(dep, str):
                    # 依赖已经是task_id字符串
                    resolved_deps.append(dep)

            tasks[i].dependencies = resolved_deps

        return tasks

    def _build_task_parameters(
        self,
        task_template: Dict,
        target: TargetInfo,
        intent_analysis: IntentAnalysis
    ) -> Dict[str, Any]:
        """构建任务参数"""
        # 基础参数
        params = {"target": target.value}

        # 根据目标类型添加参数
        if target.type == TargetType.URL:
            params["url"] = target.value
        elif target.type == TargetType.IP_ADDRESS:
            if target.port:
                params["target"] = f"{target.value}:{target.port}"
        elif target.type == TargetType.DOMAIN:
            params["domain"] = target.value

        # 合并模板参数
        template_params = task_template.get("parameters", {})
        params.update(template_params)

        # 应用约束
        for constraint in intent_analysis.constraints:
            if constraint.get("type") == "time_limit":
                params["timeout"] = 30  # 快速模式

        return params

    def _calculate_execution_phases(self, task_graph: TaskGraph) -> List[List[str]]:
        """计算执行阶段（拓扑排序）"""
        phases = []
        in_degree = {
            task_id: len([
                dep for dep in task.dependencies
                if dep in task_graph.tasks
            ])
            for task_id, task in task_graph.tasks.items()
        }
        ready = {task_id for task_id, degree in in_degree.items() if degree == 0}

        while ready:
            # 当前阶段的所有就绪任务
            current_phase = sorted(ready)
            phases.append(current_phase)

            # 处理当前阶段
            for task_id in current_phase:
                ready.remove(task_id)

                # 减少依赖此任务的其他任务的入度
                for dependent in task_graph.adjacency_list.get(task_id, set()):
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        ready.add(dependent)

        return phases

    def _estimate_total_duration(self, task_graph: TaskGraph) -> int:
        """估算总执行时长"""
        total = 0
        for task in task_graph.tasks.values():
            if task.estimated_duration:
                total += task.estimated_duration
            else:
                # 默认时长
                default_durations = {
                    TaskCategory.RECONNAISSANCE: 60,
                    TaskCategory.SCANNING: 120,
                    TaskCategory.EXPLOITATION: 300,
                    TaskCategory.POST_EXPLOITATION: 180,
                    TaskCategory.REPORTING: 30
                }
                total += default_durations.get(task.category, 60)

        return total

    @staticmethod
    def _init_strategy_templates() -> List[StrategyTemplate]:
        """初始化策略模板"""
        return [
            # CTF解题策略
            StrategyTemplate(
                name="ctf_intensive",
                description="CTF竞赛快速解题策略",
                required_intents={AttackIntent.CTF_SOLVING},
                task_template=[
                    {
                        "name": "快速端口扫描",
                        "category": "recon",
                        "tool": "masscan_fast_scan",
                        "parameters": {"ports": "80,443,22,8080,3000", "rate": "10000"},
                        "priority": 9,
                        "duration": 30,
                        "tags": ["quick", "recon"]
                    },
                    {
                        "name": "Web技术识别",
                        "category": "scan",
                        "tool": "whatweb_scan",
                        "dependencies": [0],  # 依赖第一个任务
                        "priority": 8,
                        "duration": 15,
                        "tags": ["web", "recon"]
                    },
                    {
                        "name": "目录枚举",
                        "category": "scan",
                        "tool": "gobuster_scan",
                        "dependencies": [1],
                        "parameters": {"threads": 50},
                        "priority": 8,
                        "duration": 30,
                        "tags": ["web", "enum"]
                    },
                    {
                        "name": "漏洞扫描",
                        "category": "scan",
                        "tool": "nuclei_scan",
                        "dependencies": [1],
                        "parameters": {"severity": "critical,high,medium"},
                        "priority": 9,
                        "duration": 60,
                        "tags": ["vuln", "critical"]
                    },
                    {
                        "name": "SQL注入检测",
                        "category": "exploit",
                        "tool": "sqlmap_scan",
                        "dependencies": [2],
                        "priority": 7,
                        "duration": 45,
                        "tags": ["web", "sqli"]
                    }
                ]
            ),

            # APT模拟策略
            StrategyTemplate(
                name="comprehensive_apt",
                description="全面APT攻击模拟",
                required_intents={AttackIntent.APT_SIMULATION, AttackIntent.FULL_COMPROMISE},
                task_template=[
                    {
                        "name": "全面端口扫描",
                        "category": "recon",
                        "tool": "nmap_scan",
                        "parameters": {"scan_type": "-sV -sC", "ports": "1-65535"},
                        "priority": 8,
                        "duration": 300,
                        "tags": ["recon", "comprehensive"]
                    },
                    {
                        "name": "服务枚举",
                        "category": "scan",
                        "tool": "enum4linux_scan",
                        "dependencies": [0],
                        "priority": 7,
                        "duration": 120,
                        "tags": ["enum", "network"]
                    },
                    {
                        "name": "漏洞扫描",
                        "category": "scan",
                        "tool": "nuclei_scan",
                        "dependencies": [0],
                        "parameters": {"severity": "critical,high,medium,low"},
                        "priority": 9,
                        "duration": 600,
                        "tags": ["vuln", "comprehensive"]
                    },
                    {
                        "name": "Web应用扫描",
                        "category": "scan",
                        "tool": "nikto_scan",
                        "dependencies": [0],
                        "priority": 7,
                        "duration": 180,
                        "tags": ["web", "vuln"]
                    },
                    {
                        "name": "目录枚举",
                        "category": "scan",
                        "tool": "gobuster_scan",
                        "dependencies": [0],
                        "priority": 6,
                        "duration": 120,
                        "tags": ["web", "enum"]
                    },
                    {
                        "name": "子域名枚举",
                        "category": "recon",
                        "tool": "subfinder_scan",
                        "priority": 7,
                        "duration": 180,
                        "tags": ["recon", "dns"]
                    }
                ]
            ),

            # 快速侦察策略
            StrategyTemplate(
                name="fast_recon",
                description="快速信息收集",
                required_intents={AttackIntent.RECONNAISSANCE},
                task_template=[
                    {
                        "name": "快速端口扫描",
                        "category": "recon",
                        "tool": "nmap_scan",
                        "parameters": {"scan_type": "-sV", "ports": "1-1000"},
                        "priority": 8,
                        "duration": 120,
                        "tags": ["recon", "quick"]
                    },
                    {
                        "name": "子域名枚举",
                        "category": "recon",
                        "tool": "subfinder_scan",
                        "priority": 7,
                        "duration": 60,
                        "tags": ["recon", "dns"]
                    },
                    {
                        "name": "技术识别",
                        "category": "recon",
                        "tool": "whatweb_scan",
                        "priority": 7,
                        "duration": 30,
                        "tags": ["recon", "web"]
                    }
                ]
            ),

            # 漏洞扫描策略
            StrategyTemplate(
                name="vuln_scan",
                description="漏洞扫描",
                required_intents={AttackIntent.VULNERABILITY_SCANNING},
                task_template=[
                    {
                        "name": "端口扫描",
                        "category": "recon",
                        "tool": "nmap_scan",
                        "parameters": {"scan_type": "-sV"},
                        "priority": 8,
                        "duration": 120,
                        "tags": ["recon"]
                    },
                    {
                        "name": "漏洞扫描",
                        "category": "scan",
                        "tool": "nuclei_scan",
                        "dependencies": [0],
                        "parameters": {"severity": "critical,high,medium"},
                        "priority": 9,
                        "duration": 300,
                        "tags": ["vuln", "critical"]
                    },
                    {
                        "name": "Web扫描",
                        "category": "scan",
                        "tool": "nikto_scan",
                        "dependencies": [0],
                        "priority": 7,
                        "duration": 180,
                        "tags": ["web", "vuln"]
                    }
                ]
            ),

            # 利用策略
            StrategyTemplate(
                name="exploit_chain",
                description="漏洞利用链",
                required_intents={AttackIntent.EXPLOITATION},
                task_template=[
                    {
                        "name": "快速扫描",
                        "category": "recon",
                        "tool": "nmap_scan",
                        "parameters": {"scan_type": "-sV", "ports": "1-1000"},
                        "priority": 9,
                        "duration": 60,
                        "tags": ["recon", "quick"]
                    },
                    {
                        "name": "漏洞搜索",
                        "category": "scan",
                        "tool": "searchsploit_search",
                        "dependencies": [0],
                        "priority": 8,
                        "duration": 30,
                        "tags": ["exploit", "search"]
                    },
                    {
                        "name": "Metasploit利用",
                        "category": "exploit",
                        "tool": "metasploit_run",
                        "dependencies": [1],
                        "priority": 9,
                        "duration": 300,
                        "tags": ["exploit", "msf"]
                    }
                ]
            )
        ]


# ==================== 导出 ====================

__all__ = [
    'TaskDecomposer',
    'Task',
    'TaskGraph',
    'TaskCategory',
    'TaskStatus',
    'ExecutionPlan',
    'StrategyTemplate'
]
