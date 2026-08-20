#!/usr/bin/env python3
"""
BaseAgentV2 - 增强版Agent基类 v2.0

在原有BaseAgent基础上新增：
- 能力描述系统
- 负载报告
- 资源管理
- 性能指标跟踪
- MeshMessageBus支持

作者: SeaOf0
基于: ctf_agent_framework.BaseAgent
"""

import asyncio
import logging
import psutil
import time
from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union
from enum import Enum
from threading import Lock
from concurrent.futures import ThreadPoolExecutor

# 导入基础框架
from kali_mcp.core.ctf_agent_framework import (
    BaseAgent,
    AgentMessage,
    MessageType,
    MessagePriority,
    AgentStatus,
    AgentContext,
    logger
)

# 导入MeshMessageBus
try:
    from kali_mcp.core.mesh_message_bus import MeshMessageBus
    MESH_BUS_AVAILABLE = True
except ImportError:
    MESH_BUS_AVAILABLE = False
    MeshMessageBus = None
    logger.warning("MeshMessageBus不可用，将回退到基础MessageBus")

# 导入Task相关类型
try:
    from kali_mcp.core.task_decomposer import Task
    TASK_AVAILABLE = True
except ImportError:
    TASK_AVAILABLE = False
    Task = None

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

@dataclass
class AgentCapability:
    """Agent能力描述

    支持两种使用方式:
    1. 完整参数: AgentCapability(name="recon", category="scanning", tools=[...], ...)
    2. 简化参数: AgentCapability(supported_tools={...}, max_concurrent_tasks=5, specialties=[...])
    """
    name: str = "general"                  # 能力名称
    category: str = "general"              # 分类 (recon, vuln_scan, exploit, etc.)
    tools: List[str] = None               # 支持的工具列表
    max_concurrent_tasks: int = 5          # 最大并发任务数
    avg_task_duration: float = 60.0        # 平均任务持续时间（秒）
    success_rate: float = 1.0              # 成功率 (0.0-1.0)
    description: str = ""                  # 能力描述

    # 兼容ReconAgent使用的简化参数
    supported_tools: Set[str] = None       # 支持的工具集合（简化版）
    specialties: List[str] = None          # 专长列表
    preferred_categories: List = None      # 偏好的任务类别

    def __post_init__(self):
        """初始化后处理"""
        # 如果使用简化参数，转换为主参数
        if self.supported_tools is not None and self.tools is None:
            self.tools = list(self.supported_tools)
        if self.tools is None:
            self.tools = []
        if self.specialties is None:
            self.specialties = []
        # 将tools转换为set以支持集合操作
        if not isinstance(self.tools, set):
            self.supported_tools = set(self.tools)
        else:
            self.supported_tools = self.tools


@dataclass
class ResourceProfile:
    """资源配置"""
    max_cpu_usage: float = 80.0        # 最大CPU使用率 (%)
    max_memory_usage: float = 80.0      # 最大内存使用率 (%)
    max_network_bandwidth: float = 100.0  # 最大网络带宽 (Mbps)
    cpu_cores: int = 1                 # 分配的CPU核心数
    memory_limit_mb: int = 1024         # 内存限制 (MB)
    priority: int = 5                  # 优先级 (1-10, 10最高)


@dataclass
class PerformanceMetrics:
    """性能指标"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    total_execution_time: float = 0.0  # 总执行时间（秒）
    avg_execution_time: float = 0.0    # 平均执行时间（秒）
    success_rate: float = 1.0           # 成功率
    last_active: Optional[datetime] = None
    peak_memory_usage_mb: float = 0.0   # 峰值内存使用
    peak_cpu_usage: float = 0.0         # 峰值CPU使用


@dataclass
class LoadReport:
    """负载报告"""
    agent_id: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    current_tasks: int = 0                 # 当前任务数
    cpu_usage: float = 0.0                 # CPU使用率 (%)
    memory_usage_mb: float = 0.0           # 内存使用 (MB)
    load_percentage: float = 0.0           # 负载百分比 (0-100)
    available_capacity: int = 0            # 可用容量（还能接受多少任务）
    status: str = "idle"                   # 状态描述


# ==================== BaseAgentV2 ====================

class BaseAgentV2(BaseAgent):
    """
    增强版Agent基类 v2.0

    在BaseAgent基础上新增：
    1. 能力描述系统 - 描述Agent的技能和工具
    2. 负载报告 - 实时报告资源使用情况
    3. 资源管理 - 智能分配和限制资源使用
    4. 性能指标 - 跟踪任务执行性能
    5. MeshMessageBus支持 - 网状拓扑通信
    6. Executor桥接 - 通过executor调用真实安全工具
    """

    # MCP工具名  executor工具名 映射
    MCP_TO_TOOL_NAME_MAP: Dict[str, str] = {
        # 信息收集
        "nmap_scan": "nmap", "masscan_fast_scan": "masscan",
        "arp_scan": "arp-scan", "fping_scan": "fping",
        "netdiscover_scan": "netdiscover",
        # DNS
        "subfinder_scan": "subfinder", "amass_enum": "amass",
        "sublist3r_scan": "sublist3r", "dnsrecon_scan": "dnsrecon",
        "dnsenum_scan": "dnsenum", "fierce_scan": "fierce",
        "dnsmap_scan": "dnsmap",
        # Web侦察
        "whatweb_scan": "whatweb", "httpx_probe": "httpx",
        "wafw00f_scan": "wafw00f",
        # 目录扫描
        "gobuster_scan": "gobuster", "dirb_scan": "dirb",
        "ffuf_scan": "ffuf", "feroxbuster_scan": "feroxbuster",
        "wfuzz_scan": "wfuzz",
        # 漏洞扫描
        "nikto_scan": "nikto", "nuclei_scan": "nuclei",
        "nuclei_web_scan": "nuclei", "nuclei_cve_scan": "nuclei",
        "nuclei_network_scan": "nuclei",
        "wpscan_scan": "wpscan", "joomscan_scan": "joomscan",
        # SQL注入
        "sqlmap_scan": "sqlmap",
        # 密码攻击
        "hydra_attack": "hydra", "john_crack": "john",
        "hashcat_crack": "hashcat", "medusa_bruteforce": "medusa",
        "ncrack_attack": "ncrack", "patator_attack": "patator",
        "crowbar_attack": "crowbar", "brutespray_attack": "brutespray",
        # 漏洞利用
        "metasploit_run": "metasploit", "searchsploit_search": "searchsploit",
        "enum4linux_scan": "enum4linux",
        # 网络攻击
        "responder_attack": "responder", "ettercap_attack": "ettercap",
        "bettercap_attack": "bettercap",
        # OSINT
        "theharvester_osint": "theHarvester", "sherlock_search": "sherlock",
        "recon_ng_run": "recon-ng",
        # 二进制/逆向
        "binwalk_analysis": "binwalk", "radare2_analyze_binary": "radare2",
        # 无线
        "aircrack_attack": "aircrack-ng", "reaver_attack": "reaver",
        "bully_attack": "bully", "pixiewps_attack": "pixiewps",
        # 嗅探
        "tshark_capture": "tshark", "ngrep_search": "ngrep",
        # 代码审计
        "semgrep_scan": "semgrep", "bandit_scan": "bandit",
        "flawfinder_scan": "flawfinder", "shellcheck_scan": "shellcheck",
    }

    def __init__(
        self,
        agent_id: str,
        name: str,
        message_bus=None,  # MeshMessageBus or MessageBus
        capabilities=None,  # AgentCapability or List[AgentCapability]
        resource_profile: Optional[ResourceProfile] = None,
        max_workers: int = 5,
        tool_registry=None,  # tool_registry for backward compatibility
        executor=None  # LocalCommandExecutor for real tool execution
    ):
        """
        初始化BaseAgentV2

        Args:
            agent_id: Agent唯一标识
            name: Agent名称
            message_bus: 消息总线（MeshMessageBus或MessageBus），可选
            capabilities: 能力对象或能力列表
            resource_profile: 资源配置
            max_workers: 最大工作线程数
            tool_registry: 工具注册表（向后兼容）
            executor: 本地命令执行器（LocalCommandExecutor），用于真实工具调用
        """
        # 调用父类初始化（如果没有message_bus，创建一个临时的）
        if message_bus is None:
            from kali_mcp.core.ctf_agent_framework import MessageBus
            message_bus = MessageBus()

        super().__init__(agent_id, name, message_bus, max_workers)

        # 标准化capabilities参数
        if capabilities is None:
            # 创建默认能力
            self.capabilities = [AgentCapability(name="general")]
        elif isinstance(capabilities, list):
            self.capabilities = capabilities
        else:
            # 单个AgentCapability对象
            self.capabilities = [capabilities]

        self.resource_profile = resource_profile or ResourceProfile()
        self.performance_metrics = PerformanceMetrics()
        self.tool_registry = tool_registry
        self.executor = executor  # 桥接到真实工具执行

        # 运行时状态
        self._current_tasks: Dict[str, Any] = {}  # task_id -> task_info
        self._task_lock = Lock()

        # MeshMessageBus特定功能
        self._is_mesh_bus = MESH_BUS_AVAILABLE and MeshMessageBus is not None and isinstance(message_bus, MeshMessageBus)

        logger.info(f"BaseAgentV2初始化完成: {name} ({agent_id})")
        logger.info(f"  能力数量: {len(self.capabilities)}")
        logger.info(f"  Executor桥接: {' 已连接' if executor else ' 模拟模式'}")
        logger.info(f"  MeshMessageBus支持: {self._is_mesh_bus}")

    # ==================== 能力查询 ====================

    def get_capabilities(self) -> List[AgentCapability]:
        """获取所有能力"""
        return self.capabilities.copy()

    def get_capability(self, name: str) -> Optional[AgentCapability]:
        """获取指定能力"""
        for cap in self.capabilities:
            if cap.name == name:
                return cap
        return None

    def has_capability(self, capability_name: str) -> bool:
        """检查是否具有指定能力"""
        return self.get_capability(capability_name) is not None

    def get_supported_tools(self) -> List[str]:
        """获取支持的所有工具"""
        tools = []
        for cap in self.capabilities:
            tools.extend(cap.tools)
        return list(set(tools))  # 去重

    def can_handle_task(self, task_type: str) -> bool:
        """检查是否能处理指定类型的任务"""
        for cap in self.capabilities:
            if cap.name == task_type:
                return True
        return False

    # ==================== 负载报告 ====================

    def report_load(self) -> LoadReport:
        """
        报告当前负载情况

        Returns:
            负载报告对象
        """
        # 获取当前进程资源使用
        process = psutil.Process()

        # CPU使用率
        cpu_usage = process.cpu_percent(interval=0.1)

        # 内存使用
        memory_info = process.memory_info()
        memory_usage_mb = memory_info.rss / 1024 / 1024  # 转换为MB

        # 当前任务数
        current_tasks = len(self._current_tasks)

        # 计算负载百分比
        # 综合考虑CPU、内存和任务数
        cpu_load = (cpu_usage / self.resource_profile.max_cpu_usage) * 100
        memory_load = (memory_usage_mb / (self.resource_profile.memory_limit_mb or 1024)) * 100
        task_load = (current_tasks / sum(cap.max_concurrent_tasks for cap in self.capabilities)) * 100 if self.capabilities else 0

        load_percentage = max(cpu_load, memory_load, task_load)

        # 计算可用容量
        total_capacity = sum(cap.max_concurrent_tasks for cap in self.capabilities)
        available_capacity = max(0, total_capacity - current_tasks)

        # 状态描述
        if load_percentage < 50:
            status = "轻载"
        elif load_percentage < 80:
            status = "正常"
        elif load_percentage < 95:
            status = "重载"
        else:
            status = "过载"

        report = LoadReport(
            agent_id=self.agent_id,
            timestamp=datetime.now().isoformat(),
            current_tasks=current_tasks,
            cpu_usage=cpu_usage,
            memory_usage_mb=memory_usage_mb,
            load_percentage=min(100, load_percentage),
            available_capacity=available_capacity,
            status=status
        )

        return report

    def get_available_capacity(self) -> int:
        """获取可用容量（还能接受多少任务）"""
        current_tasks = len(self._current_tasks)
        total_capacity = sum(cap.max_concurrent_tasks for cap in self.capabilities)
        return max(0, total_capacity - current_tasks)

    def is_overloaded(self) -> bool:
        """检查是否过载"""
        report = self.report_load()
        return report.load_percentage > 90.0

    # ==================== 资源管理 ====================

    def check_resource_availability(self) -> bool:
        """
        检查资源是否可用

        Returns:
            True如果资源充足，False如果资源不足
        """
        process = psutil.Process()

        # 检查CPU
        cpu_usage = process.cpu_percent(interval=0.1)
        if cpu_usage > self.resource_profile.max_cpu_usage:
            logger.warning(f"CPU使用率过高: {cpu_usage}%")
            return False

        # 检查内存
        memory_info = process.memory_info()
        memory_usage_mb = memory_info.rss / 1024 / 1024
        if self.resource_profile.memory_limit_mb and memory_usage_mb > self.resource_profile.memory_limit_mb:
            logger.warning(f"内存使用过高: {memory_usage_mb}MB")
            return False

        return True

    # ==================== 消息处理（增强版）====================

    async def handle_message_async(self, message: AgentMessage):
        """
        异步处理消息（增强版）

        支持：
        - 资源检查
        - 负载均衡
        - 优先级处理

        Args:
            message: 接收到的消息
        """
        try:
            # 检查资源可用性
            if not self.check_resource_availability():
                logger.warning(f"资源不足，拒绝消息: {message.id}")
                # 发送拒绝消息
                self.send_message(
                    MessageType.ERROR,
                    {"reason": "资源不足", "message_id": message.id},
                    receiver=message.sender,
                    priority=MessagePriority.HIGH
                )
                return

            # 处理消息
            await self._process_message(message)

        except Exception as e:
            logger.error(f"处理消息失败: {e}")
            # 更新性能指标
            self.performance_metrics.failed_tasks += 1

    async def _process_message(self, message: AgentMessage):
        """
        处理消息（子类可重写）

        Args:
            message: 消息对象
        """
        # 默认实现：调用基类的handle_message
        self.handle_message(message)

    # ==================== 任务执行（增强版）====================

    @abstractmethod
    async def _execute_task_impl(
        self,
        task_type: str,
        task_data: Dict[str, Any],
        task_id: str
    ) -> Any:
        """
        执行任务实现（子类必须实现）

        Args:
            task_type: 任务类型
            task_data: 任务数据
            task_id: 任务ID

        Returns:
            任务结果
        """
        pass

    # ==================== Task对象支持（Phase 2/3兼容）====================

    async def execute_task(self, *args, **kwargs) -> Any:
        """
        多态execute_task方法 - 支持两种签名

        签名1（旧版）: execute_task(task_type: str, task_data: Dict, task_id: str, priority: MessagePriority) -> Dict
        签名2（新版）: execute_task(task: Task) -> AgentResult

        通过参数类型检测自动选择正确的实现。
        """
        # 检测是否使用新版签名（Task对象）
        if len(args) == 1 and TASK_AVAILABLE and Task is not None and isinstance(args[0], Task):
            # 新版签名：execute_task(task: Task)
            return await self.execute_task_with_task_obj(args[0])
        else:
            # 旧版签名：execute_task(task_type, task_data, task_id, priority)
            task_type = args[0] if len(args) > 0 else kwargs.get('task_type', '')
            task_data = args[1] if len(args) > 1 else kwargs.get('task_data', {})
            task_id = args[2] if len(args) > 2 else kwargs.get('task_id', '')
            priority = args[3] if len(args) > 3 else kwargs.get('priority', MessagePriority.NORMAL)

            return await self._execute_task_legacy(task_type, task_data, task_id, priority)

    async def _execute_task_legacy(
        self,
        task_type: str,
        task_data: Dict[str, Any],
        task_id: str,
        priority: MessagePriority = MessagePriority.NORMAL
    ) -> Dict[str, Any]:
        """旧版execute_task实现（重命名以避免冲突）"""
        start_time = time.time()

        # 检查能力
        if not self.can_handle_task(task_type):
            return {
                "success": False,
                "error": f"不支持的任务类型: {task_type}",
                "task_id": task_id
            }

        # 检查负载
        if self.is_overloaded():
            return {
                "success": False,
                "error": "Agent过载",
                "task_id": task_id
            }

        # 记录任务
        with self._task_lock:
            self._current_tasks[task_id] = {
                "type": task_type,
                "data": task_data,
                "start_time": start_time,
                "priority": priority
            }

        try:
            # 执行任务（子类实现）
            result = await self._execute_task_impl(task_type, task_data, task_id)

            # 更新性能指标
            execution_time = time.time() - start_time
            self._update_performance_metrics(execution_time, success=True)

            return {
                "success": True,
                "result": result,
                "task_id": task_id,
                "execution_time": execution_time
            }

        except Exception as e:
            logger.error(f"任务执行失败: {e}")

            # 更新性能指标
            execution_time = time.time() - start_time
            self._update_performance_metrics(execution_time, success=False)

            return {
                "success": False,
                "error": str(e),
                "task_id": task_id,
                "execution_time": execution_time
            }

        finally:
            # 移除任务记录
            with self._task_lock:
                self._current_tasks.pop(task_id, None)

    async def execute_task_with_task_obj(self, task) -> Any:
        """
        执行Task对象（兼容task_decomposer.Task）

        这是新的execute_task签名，接受Task对象而不是分离的参数。
        子类可以重写此方法以提供自定义实现。

        Args:
            task: Task对象（来自task_decomposer）

        Returns:
            AgentResult对象或执行结果
        """
        # 如果Task可用且提供了tool_name
        if TASK_AVAILABLE and Task is not None and isinstance(task, Task):
            # 默认实现：转换为旧格式并调用execute_task
            result_dict = await self.execute_task(
                task_type=task.tool_name or task.category.value,
                task_data=task.parameters,
                task_id=task.task_id,
                priority=getattr(MessagePriority, task.priority.value.upper(), MessagePriority.NORMAL)
            )
            return result_dict
        else:
            # 不是Task对象，直接返回
            return await self.execute_task(
                task_type=str(task),
                task_data={},
                task_id=id(task)
            )

    async def _call_tool(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        调用安全工具（通过executor桥接到真实工具）

        如果executor已注入，通过executor.execute_tool_with_data()执行真实命令。
        否则回退到模拟输出（向后兼容）。

        Args:
            tool_name: 工具名称（MCP风格，如 nmap_scan）
            parameters: 工具参数

        Returns:
            工具输出字符串
        """
        if self.executor is None:
            logger.warning(f"_call_tool: executor未注入，工具调用将被模拟: {tool_name}")
            return f"[模拟输出] 工具 {tool_name} 被调用，参数: {parameters}"

        # 将MCP工具名映射到executor工具名
        executor_tool_name = self.MCP_TO_TOOL_NAME_MAP.get(tool_name, tool_name)

        logger.info(f"[{self.agent_id}] 调用工具: {tool_name}  {executor_tool_name}, 参数: {parameters}")

        try:
            # executor.execute_tool_with_data 是同步方法，在线程池中执行
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.executor.execute_tool_with_data(executor_tool_name, parameters)
            )

            if result.get("success"):
                output = result.get("output", "")
                logger.info(f"[{self.agent_id}] 工具 {tool_name} 执行成功，输出长度: {len(output)}")
                return output
            else:
                error = result.get("error", "Unknown error")
                logger.warning(f"[{self.agent_id}] 工具 {tool_name} 执行失败: {error}")
                return f"[错误] {tool_name}: {error}"

        except Exception as e:
            logger.error(f"[{self.agent_id}] 工具 {tool_name} 调用异常: {e}")
            return f"[异常] {tool_name}: {str(e)}"

    # ==================== 性能指标管理 ====================

    def _update_performance_metrics(self, execution_time: float, success: bool):
        """
        更新性能指标

        Args:
            execution_time: 执行时间（秒）
            success: 是否成功
        """
        metrics = self.performance_metrics

        metrics.total_tasks += 1
        metrics.total_execution_time += execution_time
        metrics.last_active = datetime.now()

        if success:
            metrics.completed_tasks += 1
        else:
            metrics.failed_tasks += 1

        # 计算平均执行时间
        if metrics.total_tasks > 0:
            metrics.avg_execution_time = metrics.total_execution_time / metrics.total_tasks

        # 计算成功率
        if metrics.total_tasks > 0:
            metrics.success_rate = metrics.completed_tasks / metrics.total_tasks

    def get_performance_metrics(self) -> PerformanceMetrics:
        """获取性能指标"""
        # 更新峰值资源使用
        process = psutil.Process()

        # CPU
        cpu_usage = process.cpu_percent(interval=0.1)
        if cpu_usage > self.performance_metrics.peak_cpu_usage:
            self.performance_metrics.peak_cpu_usage = cpu_usage

        # 内存
        memory_info = process.memory_info()
        memory_usage_mb = memory_info.rss / 1024 / 1024
        if memory_usage_mb > self.performance_metrics.peak_memory_usage_mb:
            self.performance_metrics.peak_memory_usage_mb = memory_usage_mb

        return self.performance_metrics

    def reset_performance_metrics(self):
        """重置性能指标"""
        self.performance_metrics = PerformanceMetrics()
        logger.info(f"性能指标已重置: {self.name}")

    # ==================== MeshMessageBus特定功能 ====================

    def subscribe_with_filters(self, filters: List):
        """
        使用过滤器订阅消息（仅MeshMessageBus）

        Args:
            filters: 过滤器列表
        """
        if self._is_mesh_bus:
            from kali_mcp.core.mesh_message_bus import MessageFilter
            # 确保filters都是MessageFilter类型
            if all(isinstance(f, MessageFilter) for f in filters):
                self.message_bus.subscribe_with_filter(
                    self.agent_id,
                    self._on_message,
                    filters
                )
                logger.info(f"已使用过滤器订阅: {len(filters)}个过滤器")
            else:
                logger.warning("过滤器类型不正确，回退到普通订阅")
        else:
            logger.warning("MeshMessageBus不可用，使用普通订阅")

    # ==================== 辅助方法 ====================

    def get_status_summary(self) -> Dict[str, Any]:
        """
        获取状态摘要

        Returns:
            包含Agent状态信息的字典
        """
        load_report = self.report_load()
        performance = self.get_performance_metrics()

        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "status": self.status.value,
            "capabilities": [cap.name for cap in self.capabilities],
            "supported_tools": self.get_supported_tools(),
            "load": {
                "current_tasks": load_report.current_tasks,
                "load_percentage": load_report.load_percentage,
                "status": load_report.status,
                "available_capacity": load_report.available_capacity
            },
            "performance": {
                "total_tasks": performance.total_tasks,
                "completed_tasks": performance.completed_tasks,
                "failed_tasks": performance.failed_tasks,
                "success_rate": f"{performance.success_rate * 100:.1f}%",
                "avg_execution_time": f"{performance.avg_execution_time:.2f}s"
            },
            "resources": {
                "cpu_usage": f"{load_report.cpu_usage:.1f}%",
                "memory_usage": f"{load_report.memory_usage_mb:.1f}MB",
                "cpu_limit": f"{self.resource_profile.max_cpu_usage}%",
                "memory_limit": f"{self.resource_profile.memory_limit_mb}MB"
            },
            "mesh_bus_supported": self._is_mesh_bus
        }

    def __repr__(self) -> str:
        return (f"<BaseAgentV2 {self.name} ({self.agent_id}) "
                f"status={self.status.value} "
                f"capabilities={len(self.capabilities)}>")


# ==================== 导出 ====================

__all__ = [
    'BaseAgentV2',
    'AgentCapability',
    'ResourceProfile',
    'PerformanceMetrics',
    'LoadReport'
]
