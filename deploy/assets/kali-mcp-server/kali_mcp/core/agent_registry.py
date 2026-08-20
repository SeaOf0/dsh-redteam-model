#!/usr/bin/env python3
"""
Agent注册表 (AgentRegistry) v2.0

管理智能体集群的生命周期、能力查询和健康监控：
- Agent注册和注销
- 能力索引和查询
- 负载均衡调度
- 健康监控和故障转移
- Agent发现和路由

作者: SeaOf0
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from enum import Enum

# 导入Agent相关类
try:
    from kali_mcp.agents.base_agent_v2 import BaseAgentV2, AgentCapability, LoadReport
except ImportError:
    BaseAgentV2 = Any
    AgentCapability = Any

    @dataclass
    class LoadReport:  # type: ignore[override]
        """负载报告降级结构（仅用于兼容导入失败场景）"""
        agent_id: str
        current_tasks: int = 0
        cpu_usage: float = 0.0
        memory_usage_mb: float = 0.0
        load_percentage: float = 0.0
        available_capacity: int = 0
        status: str = "unknown"

try:
    from kali_mcp.core.ctf_agent_framework import AgentStatus
except ImportError:
    class AgentStatus(Enum):
        IDLE = "idle"

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class AgentState(Enum):
    """Agent状态"""
    STARTING = "starting"      # 启动中
    ACTIVE = "active"          # 活跃
    BUSY = "busy"              # 繁忙
    IDLE = "idle"              # 空闲
    OVERLOADED = "overloaded"  # 过载
    UNRESPONSIVE = "unresponsive"  # 无响应
    STOPPING = "stopping"      # 停止中
    STOPPED = "stopped"        # 已停止
    ERROR = "error"            # 错误


@dataclass
class AgentInfo:
    """Agent信息"""
    agent_id: str
    name: str
    state: AgentState
    capabilities: List[str]           # 能力名称列表
    supported_tools: List[str]        # 支持的工具列表
    registered_at: datetime            # 注册时间
    last_heartbeat: datetime           # 最后心跳时间
    heartbeat_count: int = 0           # 心跳计数
    total_tasks: int = 0               # 总任务数
    completed_tasks: int = 0           # 完成任务数
    failed_tasks: int = 0              # 失败任务数
    avg_task_duration: float = 0.0     # 平均任务持续时间
    last_error: Optional[str] = None   # 最后错误信息
    metadata: Dict[str, Any] = field(default_factory=dict)  # 元数据


@dataclass
class SelectionCriteria:
    """Agent选择标准"""
    capability: Optional[str] = None        # 需要的能力
    min_success_rate: float = 0.0           # 最低成功率
    max_load_percentage: float = 100.0      # 最大负载百分比
    prefer_idle: bool = False               # 优先选择空闲Agent
    allow_overloaded: bool = False          # 允许过载Agent
    require_mesh_bus: bool = False          # 要求MeshMessageBus支持
    tags: Optional[Set[str]] = None         # 标签过滤


# ==================== Agent注册表 ====================

class AgentRegistry:
    """
    Agent注册表 - 管理智能体集群

    核心功能：
    1. Agent注册和注销
    2. 能力索引和查询
    3. 负载均衡调度
    4. 健康监控和故障转移
    5. Agent发现和路由
    """

    def __init__(self, heartbeat_timeout: float = 60.0):
        """
        初始化Agent注册表

        Args:
            heartbeat_timeout: 心跳超时时间（秒）
        """
        self._agents: Dict[str, BaseAgentV2] = {}      # agent_id -> Agent实例
        self._agent_info: Dict[str, AgentInfo] = {}     # agent_id -> AgentInfo
        self._capability_index: Dict[str, Set[str]] = {}  # capability -> {agent_ids}
        self._tool_index: Dict[str, Set[str]] = {}      # tool -> {agent_ids}

        self._lock = RLock()
        self.heartbeat_timeout = heartbeat_timeout

        # 统计信息
        self.stats = {
            "total_registered": 0,
            "total_unregistered": 0,
            "total_heartbeats": 0,
            "failed_heartbeats": 0,
            "selections": 0,
            "selection_failures": 0
        }

        # 后台任务
        self._monitoring_task = None
        self._running = False

        logger.info("AgentRegistry初始化完成")

    # ==================== Agent注册管理 ====================

    def register_agent(self, agent: BaseAgentV2) -> bool:
        """
        注册Agent

        Args:
            agent: Agent实例

        Returns:
            是否注册成功
        """
        # 使用duck typing检查，而不是严格类型检查
        if not hasattr(agent, "agent_id"):
            logger.error(f"Agent对象缺少必要的属性或方法: {type(agent)}")
            return False

        with self._lock:
            agent_id = agent.agent_id

            # 检查是否已注册
            if agent_id in self._agents:
                logger.warning(f"Agent已注册，将更新信息: {agent_id}")
                self._unregister_agent_impl(agent_id)

            # 存储Agent实例
            self._agents[agent_id] = agent

            # 创建AgentInfo
            capabilities = []
            raw_capabilities = []

            try:
                get_caps = getattr(agent, "get_capabilities", None)
                if callable(get_caps):
                    result = get_caps()
                    if isinstance(result, list):
                        raw_capabilities = result
                    elif isinstance(result, tuple):
                        raw_capabilities = list(result)
            except Exception:
                raw_capabilities = []

            if not raw_capabilities:
                fallback_caps = getattr(agent, "capabilities", [])
                if isinstance(fallback_caps, list):
                    raw_capabilities = fallback_caps
                elif fallback_caps:
                    raw_capabilities = [fallback_caps]

            for cap in raw_capabilities:
                cap_name = getattr(cap, "name", None)
                if cap_name:
                    capabilities.append(cap_name)

            if not capabilities:
                capabilities = ["general"]

            supported_tools = []
            try:
                get_tools = getattr(agent, "get_supported_tools", None)
                if callable(get_tools):
                    tools_result = get_tools()
                    if isinstance(tools_result, (list, tuple, set)):
                        supported_tools = list(tools_result)
            except Exception:
                supported_tools = []

            if not supported_tools:
                for cap in raw_capabilities:
                    cap_tools = getattr(cap, "supported_tools", None) or getattr(cap, "tools", None)
                    if isinstance(cap_tools, (list, tuple, set)):
                        supported_tools.extend(list(cap_tools))
            supported_tools = list(dict.fromkeys(str(tool) for tool in supported_tools))

            self._agent_info[agent_id] = AgentInfo(
                agent_id=agent_id,
                name=getattr(agent, "name", agent_id),
                state=AgentState.STARTING,
                capabilities=capabilities,
                supported_tools=supported_tools,
                registered_at=datetime.now(),
                last_heartbeat=datetime.now()
            )

            # 更新能力索引
            for cap_name in capabilities:
                if cap_name not in self._capability_index:
                    self._capability_index[cap_name] = set()
                self._capability_index[cap_name].add(agent_id)

            # 更新工具索引
            for tool in supported_tools:
                if tool not in self._tool_index:
                    self._tool_index[tool] = set()
                self._tool_index[tool].add(agent_id)

            # 更新统计
            self.stats["total_registered"] += 1

            logger.info(f"Agent注册成功: {getattr(agent, 'name', agent_id)} ({agent_id})")
            logger.info(f"  能力: {len(capabilities)}个")
            logger.info(f"  工具: {len(supported_tools)}个")

            return True

    def unregister_agent(self, agent_id: str) -> bool:
        """
        注销Agent

        Args:
            agent_id: Agent ID

        Returns:
            是否注销成功
        """
        with self._lock:
            return self._unregister_agent_impl(agent_id)

    def _unregister_agent_impl(self, agent_id: str) -> bool:
        """内部注销实现（假设已获取锁）"""
        if agent_id not in self._agents:
            logger.warning(f"Agent未注册: {agent_id}")
            return False

        # 获取AgentInfo
        info = self._agent_info.get(agent_id)
        if info:
            # 清理能力索引
            for cap_name in info.capabilities:
                if cap_name in self._capability_index:
                    self._capability_index[cap_name].discard(agent_id)
                    if not self._capability_index[cap_name]:
                        del self._capability_index[cap_name]

            # 清理工具索引
            for tool in info.supported_tools:
                if tool in self._tool_index:
                    self._tool_index[tool].discard(agent_id)
                    if not self._tool_index[tool]:
                        del self._tool_index[tool]

        # 删除记录
        del self._agents[agent_id]
        del self._agent_info[agent_id]

        # 更新统计
        self.stats["total_unregistered"] += 1

        logger.info(f"Agent已注销: {agent_id}")
        return True

    def get_agent(self, agent_id: str) -> Optional[BaseAgentV2]:
        """获取Agent实例"""
        with self._lock:
            return self._agents.get(agent_id)

    def get_all_agents(self) -> List[BaseAgentV2]:
        """获取所有Agent"""
        with self._lock:
            return list(self._agents.values())

    def list_all(self) -> List[BaseAgentV2]:
        """获取所有Agent（别名，兼容AgentScheduler）"""
        return self.get_all_agents()

    def list_agent_ids(self) -> List[str]:
        """列出所有Agent ID"""
        return list(self._agents.keys())

    def get_available_agents(self) -> List[BaseAgentV2]:
        """获取当前可用Agent列表。"""
        available = []
        for agent in self.get_all_agents():
            is_available = getattr(agent, "is_available", None)
            if callable(is_available):
                try:
                    if not is_available():
                        continue
                except Exception:
                    continue
            available.append(agent)
        return available

    def get_capability_summary(self) -> Dict[str, int]:
        """获取能力分布摘要：能力名 -> Agent数量。"""
        with self._lock:
            return {
                capability: len(agent_ids)
                for capability, agent_ids in self._capability_index.items()
            }

    # ==================== 能力查询 ====================

    def find_agents_by_capability(self, capability_name: str) -> List[BaseAgentV2]:
        """
        根据能力查找Agent

        Args:
            capability_name: 能力名称

        Returns:
            具有该能力的Agent列表
        """
        with self._lock:
            agent_ids = self._capability_index.get(capability_name, set())
            return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def find_agents_by_tool(self, tool_name: str) -> List[BaseAgentV2]:
        """
        根据工具查找Agent

        Args:
            tool_name: 工具名称

        Returns:
            支持该工具的Agent列表
        """
        with self._lock:
            agent_ids = self._tool_index.get(tool_name, set())
            return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def find_capable_agents(self, task_type: str) -> List[BaseAgentV2]:
        """
        查找能处理特定任务的Agent

        Args:
            task_type: 任务类型（对应能力名称）

        Returns:
            能处理该任务的Agent列表
        """
        return self.find_agents_by_capability(task_type)

    def get_all_capabilities(self) -> Set[str]:
        """获取所有已注册的能力"""
        with self._lock:
            return set(self._capability_index.keys())

    def get_all_tools(self) -> Set[str]:
        """获取所有已注册的工具"""
        with self._lock:
            return set(self._tool_index.keys())

    # ==================== Agent选择和调度 ====================

    def find_best_agent(
        self,
        task_type: str,
        criteria: Optional[SelectionCriteria] = None
    ) -> Optional[BaseAgentV2]:
        """
        查找最适合处理任务的Agent

        选择策略：
        1. 过滤：根据标准过滤候选Agent
        2. 排序：按负载、成功率等因素排序
        3. 选择：选择最优Agent

        Args:
            task_type: 任务类型
            criteria: 选择标准（可选）

        Returns:
            最优Agent或None
        """
        criteria = criteria or SelectionCriteria()
        criteria.capability = task_type

        with self._lock:
            # 获取候选Agent
            candidates = self.find_capable_agents(task_type)

            if not candidates:
                logger.warning(f"没有Agent支持任务类型: {task_type}")
                self.stats["selection_failures"] += 1
                return None

            # 过滤候选Agent
            filtered = self._filter_agents(candidates, criteria)

            if not filtered:
                logger.warning(f"没有Agent满足选择标准: {task_type}")
                self.stats["selection_failures"] += 1
                return None

            # 排序并选择最优
            best = self._rank_and_select_agent(filtered, criteria)

            if best:
                self.stats["selections"] += 1
                logger.info(f"选择最优Agent: {best.agent_id} for {task_type}")

            return best

    def _filter_agents(
        self,
        agents: List[BaseAgentV2],
        criteria: SelectionCriteria
    ) -> List[BaseAgentV2]:
        """过滤Agent"""
        filtered = []

        for agent in agents:
            info = self._agent_info.get(agent.agent_id)
            if not info:
                continue

            # 检查状态
            if info.state in [AgentState.UNRESPONSIVE, AgentState.ERROR, AgentState.STOPPED]:
                continue

            # 检查过载
            if not criteria.allow_overloaded and info.state == AgentState.OVERLOADED:
                continue

            # 检查成功率
            if info.total_tasks > 0:
                success_rate = info.completed_tasks / info.total_tasks
                if success_rate < criteria.min_success_rate:
                    continue

            # 检查MeshMessageBus支持
            if criteria.require_mesh_bus:
                summary = agent.get_status_summary()
                if not summary.get("mesh_bus_supported"):
                    continue

            # 检查负载
            try:
                load_report = agent.report_load()
                if load_report.load_percentage > criteria.max_load_percentage:
                    continue
            except Exception as e:
                logger.warning(f"获取负载报告失败: {agent.agent_id}: {e}")
                continue

            # 优先选择空闲Agent
            if criteria.prefer_idle and info.state == AgentState.IDLE:
                filtered.insert(0, agent)  # 空闲Agent优先
            else:
                filtered.append(agent)

        return filtered

    def _rank_and_select_agent(
        self,
        agents: List[BaseAgentV2],
        criteria: SelectionCriteria
    ) -> Optional[BaseAgentV2]:
        """排序并选择最优Agent"""
        if not agents:
            return None

        # 计算每个Agent的得分
        scored_agents = []
        for agent in agents:
            score = self._calculate_agent_score(agent, criteria)
            scored_agents.append((score, agent))

        # 按得分排序（降序）
        scored_agents.sort(key=lambda x: x[0], reverse=True)

        # 返回得分最高的
        return scored_agents[0][1]

    def _calculate_agent_score(self, agent: BaseAgentV2, criteria: SelectionCriteria) -> float:
        """计算Agent得分（越高越好）"""
        info = self._agent_info.get(agent.agent_id)
        if not info:
            return 0.0

        score = 0.0

        # 1. 负载得分（0-40分）
        try:
            load_report = agent.report_load()
            load_score = max(0, 40 * (1 - load_report.load_percentage / 100))
            score += load_score
        except Exception:
            score += 20  # 默认中等负载得分

        # 2. 成功率得分（0-30分）
        if info.total_tasks > 0:
            success_rate = info.completed_tasks / info.total_tasks
            score += 30 * success_rate
        else:
            score += 15  # 新Agent给中等分

        # 3. 空闲状态加分（0-20分）
        if info.state == AgentState.IDLE:
            score += 20
        elif info.state == AgentState.ACTIVE:
            score += 10

        # 4. 任务完成数加分（0-10分）
        score += min(10, info.completed_tasks * 0.5)

        return score

    # ==================== 健康监控 ====================

    def heartbeat(self, agent_id: str) -> bool:
        """
        处理Agent心跳

        Args:
            agent_id: Agent ID

        Returns:
            心跳是否成功
        """
        with self._lock:
            if agent_id not in self._agent_info:
                logger.warning(f"心跳来自未注册的Agent: {agent_id}")
                return False

            info = self._agent_info[agent_id]
            info.last_heartbeat = datetime.now()
            info.heartbeat_count += 1

            # 更新状态
            if info.state in [AgentState.STARTING, AgentState.UNRESPONSIVE]:
                info.state = AgentState.ACTIVE

            self.stats["total_heartbeats"] += 1

            return True

    def check_agent_health(self, agent_id: str) -> bool:
        """
        检查Agent健康状态

        Args:
            agent_id: Agent ID

        Returns:
            是否健康
        """
        info = self._agent_info.get(agent_id)
        if not info:
            return False

        # 检查心跳超时
        time_since_heartbeat = datetime.now() - info.last_heartbeat
        if time_since_heartbeat.total_seconds() > self.heartbeat_timeout:
            logger.warning(f"Agent心跳超时: {agent_id}")
            info.state = AgentState.UNRESPONSIVE
            self.stats["failed_heartbeats"] += 1
            return False

        return True

    def health_check(self) -> Dict[str, bool]:
        """
        批量健康检查

        Returns:
            agent_id -> 是否健康
        """
        results = {}

        with self._lock:
            for agent_id in self._agents.keys():
                results[agent_id] = self.check_agent_health(agent_id)

        return results

    async def start_monitoring(self, interval: float = 30.0):
        """
        启动后台监控任务

        Args:
            interval: 检查间隔（秒）
        """
        if self._running:
            logger.warning("监控任务已在运行")
            return

        self._running = True

        async def _monitor():
            while self._running:
                try:
                    # 执行健康检查
                    health_results = self.health_check()

                    # 统计
                    healthy = sum(1 for v in health_results.values() if v)
                    total = len(health_results)

                    logger.info(
                        f"健康检查完成: {healthy}/{total} 个Agent健康"
                    )

                    # 等待下一次检查
                    await asyncio.sleep(interval)

                except Exception as e:
                    logger.error(f"监控任务错误: {e}")
                    await asyncio.sleep(interval)

        self._monitoring_task = asyncio.create_task(_monitor())
        logger.info(f"后台监控任务已启动，间隔: {interval}秒")

    async def stop_monitoring(self):
        """停止后台监控任务"""
        self._running = False

        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass

            self._monitoring_task = None
            logger.info("后台监控任务已停止")

    # ==================== 状态报告 ====================

    def get_agent_info(self, agent_id: str) -> Optional[AgentInfo]:
        """获取Agent信息"""
        return self._agent_info.get(agent_id)

    def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        获取Agent状态摘要

        Args:
            agent_id: Agent ID

        Returns:
            状态字典或None
        """
        agent = self._agents.get(agent_id)
        info = self._agent_info.get(agent_id)

        if not agent or not info:
            return None

        try:
            load_report = agent.report_load()
            performance = agent.get_performance_metrics()
        except Exception as e:
            logger.error(f"获取Agent状态失败: {e}")
            return None

        return {
            "agent_id": agent_id,
            "name": info.name,
            "state": info.state.value,
            "capabilities": info.capabilities,
            "supported_tools": len(info.supported_tools),
            "load": {
                "current_tasks": load_report.current_tasks,
                "load_percentage": load_report.load_percentage,
                "status": load_report.status,
                "available_capacity": load_report.available_capacity
            },
            "performance": {
                "total_tasks": info.total_tasks,
                "completed_tasks": info.completed_tasks,
                "failed_tasks": info.failed_tasks,
                "success_rate": f"{(info.completed_tasks / info.total_tasks * 100) if info.total_tasks > 0 else 0:.1f}%"
            },
            "heartbeat": {
                "last_heartbeat": info.last_heartbeat.isoformat(),
                "heartbeat_count": info.heartbeat_count,
                "time_since_last": str(datetime.now() - info.last_heartbeat)
            },
            "registered_at": info.registered_at.isoformat()
        }

    def get_registry_stats(self) -> Dict[str, Any]:
        """获取注册表统计信息"""
        with self._lock:
            # 统计各状态Agent数量
            state_counts = {}
            for info in self._agent_info.values():
                state = info.state.value
                state_counts[state] = state_counts.get(state, 0) + 1

            return {
                "total_agents": len(self._agents),
                "total_capabilities": len(self._capability_index),
                "total_tools": len(self._tool_index),
                "state_distribution": state_counts,
                "stats": self.stats.copy(),
                "monitoring_running": self._running
            }

    def get_cluster_summary(self) -> Dict[str, Any]:
        """获取集群摘要"""
        with self._lock:
            agents = []
            for agent_id, info in self._agent_info.items():
                agent = self._agents.get(agent_id)
                if agent:
                    try:
                        load_report = agent.report_load()
                    except Exception:
                        load_report = None

                    agents.append({
                        "agent_id": agent_id,
                        "name": info.name,
                        "state": info.state.value,
                        "capabilities": len(info.capabilities),
                        "load_percentage": load_report.load_percentage if load_report else 0,
                        "available_capacity": load_report.available_capacity if load_report else 0,
                        "healthy": self.check_agent_health(agent_id)
                    })

            return {
                "cluster_size": len(agents),
                "agents": agents,
                "timestamp": datetime.now().isoformat()
            }

    # ==================== 工具方法 ====================

    def update_agent_metrics(
        self,
        agent_id: str,
        task_completed: bool = True,
        task_duration: float = 0.0
    ):
        """
        更新Agent任务指标

        Args:
            agent_id: Agent ID
            task_completed: 任务是否成功完成
            task_duration: 任务持续时间（秒）
        """
        with self._lock:
            info = self._agent_info.get(agent_id)
            if not info:
                return

            info.total_tasks += 1
            if task_completed:
                info.completed_tasks += 1
            else:
                info.failed_tasks += 1

            # 更新平均任务时间（简单移动平均）
            if info.avg_task_duration == 0:
                info.avg_task_duration = task_duration
            else:
                info.avg_task_duration = (
                    info.avg_task_duration * 0.9 + task_duration * 0.1
                )

    def set_agent_state(self, agent_id: str, state: AgentState) -> bool:
        """
        设置Agent状态

        Args:
            agent_id: Agent ID
            state: 新状态

        Returns:
            是否成功
        """
        with self._lock:
            info = self._agent_info.get(agent_id)
            if not info:
                return False

            old_state = info.state
            info.state = state

            logger.info(
                f"Agent状态变更: {agent_id} {old_state.value} -> {state.value}"
            )

            return True

    def __len__(self) -> int:
        """返回已注册Agent数量"""
        return len(self._agents)

    def __contains__(self, agent_id: str) -> bool:
        """检查Agent是否已注册"""
        return agent_id in self._agents

    def __repr__(self) -> str:
        return f"<AgentRegistry agents={len(self._agents)} capabilities={len(self._capability_index)}>"


# ==================== 导出 ====================

__all__ = [
    'AgentRegistry',
    'AgentState',
    'AgentInfo',
    'SelectionCriteria'
]
