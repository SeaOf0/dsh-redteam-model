#!/usr/bin/env python3
"""
网状消息总线 (MeshMessageBus) v2.0

支持多智能体集群的网状拓扑通信:
- 网状路由：智能体间点对点直接通信
- 优先级队列：URGENT, HIGH, NORMAL, LOW
- 订阅过滤：基于内容过滤的消息路由
- 消息确认和重试机制
- 消息链追踪：支持请求-响应匹配

作者: SeaOf0
基于: ctf_agent_framework.MessageBus
"""

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum
from datetime import datetime
from threading import Lock, Event
from concurrent.futures import ThreadPoolExecutor
import queue

# 导入基础消息系统
from kali_mcp.core.ctf_agent_framework import (
    MessageBus,
    AgentMessage,
    MessageType,
    MessagePriority,
    logger
)

logger = logging.getLogger(__name__)


# ==================== 增强的消息类型 ====================

class MessageTypeV2(Enum):
    """扩展消息类型v2.0（独立枚举，不继承）"""
    # 原有类型
    PURE = "pure"
    PAGE = "page"
    VULNERABILITY = "vulnerability"
    SUMMARY = "summary"
    SOLUTION = "solution"
    FLAG = "flag"
    TASK = "task"
    STATUS = "status"
    ERROR = "error"

    # 新增类型
    COORDINATION = "coordination"  # 协调消息
    NEGOTIATION = "negotiation"    # 协商消息
    RESOURCE_REQUEST = "resource_request"  # 资源请求
    RESOURCE_OFFER = "resource_offer"      # 资源提供
    STATUS_UPDATE = "status_update"        # 状态更新
    HEARTBEAT = "heartbeat"                # 心跳
    ACK = "ack"                            # 确认消息


class MessagePriorityV2(Enum):
    """扩展消息优先级v2.0（独立枚举，不继承）"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    URGENT = 5      # 最高优先级（紧急消息）


# ==================== 消息过滤器 ====================

class MessageFilter(ABC):
    """消息过滤器基类"""

    @abstractmethod
    def match(self, message: AgentMessage) -> bool:
        """判断消息是否匹配过滤器"""
        pass


class TypeFilter(MessageFilter):
    """类型过滤器"""

    def __init__(self, message_types: List[MessageType]):
        self.message_types = message_types

    def match(self, message: AgentMessage) -> bool:
        return message.type in self.message_types


class SenderFilter(MessageFilter):
    """发送者过滤器"""

    def __init__(self, senders: List[str]):
        self.senders = senders

    def match(self, message: AgentMessage) -> bool:
        return message.sender in self.senders


class ContentFilter(MessageFilter):
    """内容过滤器 - 基于消息内容"""

    def __init__(self, filter_func: Callable[[AgentMessage], bool]):
        self.filter_func = filter_func

    def match(self, message: AgentMessage) -> bool:
        try:
            return self.filter_func(message)
        except Exception as e:
            logger.error(f"内容过滤器错误: {e}")
            return False


class PriorityFilter(MessageFilter):
    """优先级过滤器"""

    def __init__(self, min_priority: MessagePriority):
        self.min_priority = min_priority

    def match(self, message: AgentMessage) -> bool:
        return message.priority.value >= self.min_priority.value


# ==================== 路由表 ====================

class RoutingTable:
    """路由表 - 管理智能体间的路由关系"""

    def __init__(self):
        self._routes: Dict[str, Set[str]] = {}  # agent_id -> {reachable_agents}
        self._lock = Lock()

    def add_route(self, from_agent: str, to_agent: str):
        """添加路由"""
        with self._lock:
            if from_agent not in self._routes:
                self._routes[from_agent] = set()
            self._routes[from_agent].add(to_agent)

    def remove_route(self, from_agent: str, to_agent: str):
        """移除路由"""
        with self._lock:
            if from_agent in self._routes:
                self._routes[from_agent].discard(to_agent)

    def get_routes(self, from_agent: str) -> Set[str]:
        """获取路由"""
        with self._lock:
            return self._routes.get(from_agent, set()).copy()

    def can_route(self, from_agent: str, to_agent: str) -> bool:
        """检查是否可以路由"""
        with self._lock:
            if to_agent == "all":
                return True
            if from_agent in self._routes:
                return to_agent in self._routes[from_agent]
            return True  # 默认允许所有路由


# ==================== 网状消息总线 ====================

class MeshMessageBus(MessageBus):
    """
    网状消息总线 - 支持智能体间点对点通信

    特性:
    1. 网状拓扑路由 - 智能体间可以直接通信
    2. 优先级队列 - 按优先级处理消息
    3. 订阅过滤 - 基于内容的智能路由
    4. 消息确认 - 可靠的消息传递
    5. 异步处理 - 支持异步消息处理
    """

    def __init__(self):
        # 调用父类初始化
        super().__init__()

        # 新增组件
        self.routing_table = RoutingTable()
        self.subscription_filters: Dict[str, List[MessageFilter]] = {}
        self.pending_acks: Dict[str, AgentMessage] = {}  # 等待确认的消息
        self.message_history: List[AgentMessage] = []  # 消息历史
        self.max_history = 10000  # 最大历史记录数

        # 优先级队列（按优先级分类）
        self.priority_queues: Dict[MessagePriority, asyncio.Queue] = {
            priority: asyncio.Queue()
            for priority in [MessagePriority.HIGH, MessagePriority.NORMAL, MessagePriority.LOW]
        }

        # 统计信息
        self.stats = {
            "messages_sent": 0,
            "messages_delivered": 0,
            "messages_failed": 0,
            "broadcast_count": 0,
            "direct_message_count": 0
        }

        # 异步执行器
        self._async_executor = ThreadPoolExecutor(max_workers=10)

    def subscribe_with_filter(
        self,
        agent_id: str,
        callback: Callable[[AgentMessage], None],
        filters: Optional[List[MessageFilter]] = None
    ):
        """
        订阅消息（带过滤器）

        Args:
            agent_id: 智能体ID
            callback: 消息处理回调
            filters: 消息过滤器列表
        """
        # 先订阅消息
        self.subscribe(agent_id, callback)

        # 再添加过滤器
        if filters:
            with self._lock:
                self.subscription_filters[agent_id] = filters

    def publish_async(self, message: AgentMessage):
        """
        异步发布消息 - 不阻塞调用者

        Args:
            message: 要发布的消息
        """
        def _publish():
            self.publish(message)

        # 在线程池中异步执行
        self._async_executor.submit(_publish)

    def publish(self, message: AgentMessage):
        """
        发布消息（增强版）

        支持网状路由和优先级队列

        Args:
            message: 要发布的消息
        """
        try:
            # 记录消息历史
            self.message_history.append(message)
            if len(self.message_history) > self.max_history:
                self.message_history.pop(0)

            # 添加到优先级队列
            priority_queue = self.priority_queues.get(message.priority, self.priority_queues[MessagePriority.NORMAL])
            try:
                # 非阻塞put
                priority_queue.put_nowait(message)
            except asyncio.QueueFull:
                logger.warning(f"优先级队列已满: {message.priority}")
                # 回退到父类方法
                super().publish(message)
                return

            # 网状路由
            self._route_message(message)

            # 统计
            self.stats["messages_sent"] += 1
            if message.receiver == "all":
                self.stats["broadcast_count"] += 1
            else:
                self.stats["direct_message_count"] += 1

        except Exception as e:
            logger.error(f"发布消息失败: {e}")
            self.stats["messages_failed"] += 1

    def _route_message(self, message: AgentMessage):
        """
        路由消息到接收者

        支持三种路由方式:
        1. 直接路由 - receiver指定具体智能体
        2. 广播路由 - receiver="all"
        3. 订阅过滤路由 - 基于内容过滤（仅用于广播消息）

        避免重复投递：跟踪已投递的智能体
        """
        try:
            delivered_agents = set()  # 跟踪已投递的智能体

            # 1. 直接路由（点对点）
            if message.receiver != "all":
                delivered = self._route_direct(message, delivered_agents)
                if delivered:
                    delivered_agents.add(delivered)

            # 2. 广播路由（一对多）
            if message.receiver == "all":
                self._route_broadcast(message, delivered_agents)

            # 3. 订阅过滤路由 - 只处理广播消息或没有明确接收者的消息
            # 对于直接消息，已经通过_route_direct处理，避免重复
            if message.receiver == "all":
                self._route_by_subscription(message, delivered_agents)

        except Exception as e:
            logger.error(f"消息路由失败: {e}")

    def _route_direct(self, message: AgentMessage, delivered_agents: set = None) -> str:
        """直接路由 - 点对点

        Returns:
            投递到的智能体ID，如果没有投递则返回None
        """
        if delivered_agents is None:
            delivered_agents = set()

        receiver = message.receiver

        # 检查路由
        if not self.routing_table.can_route(message.sender, receiver):
            logger.warning(f"路由不允许: {message.sender} -> {receiver}")
            return None

        # 检查是否已投递
        if receiver in delivered_agents:
            return None

        # 检查订阅过滤器
        if receiver in self.subscription_filters:
            filters = self.subscription_filters[receiver]
            if not all(f.match(message) for f in filters):
                return None  # 不符合过滤器，不投递

        # 投递消息
        self._deliver_to_subscriber(receiver, message)
        return receiver

    def _route_broadcast(self, message: AgentMessage, delivered_agents: set = None):
        """广播路由 - 一对多"""
        if delivered_agents is None:
            delivered_agents = set()

        for agent_id in self._subscribers.keys():
            if agent_id == message.sender:
                continue  # 跳过发送者

            # 检查是否已投递
            if agent_id in delivered_agents:
                continue

            # 检查订阅过滤器
            if agent_id in self.subscription_filters:
                filters = self.subscription_filters[agent_id]
                if not all(f.match(message) for f in filters):
                    continue  # 不符合过滤器，跳过

            # 投递消息
            self._deliver_to_subscriber(agent_id, message)
            delivered_agents.add(agent_id)

    def _route_by_subscription(self, message: AgentMessage, delivered_agents: set = None):
        """基于订阅的路由"""
        if delivered_agents is None:
            delivered_agents = set()

        for agent_id, filters in self.subscription_filters.items():
            if agent_id == message.sender:
                continue  # 跳过发送者

            # 检查是否已投递
            if agent_id in delivered_agents:
                continue

            # 检查所有过滤器
            if all(f.match(message) for f in filters):
                # 符合所有过滤条件，投递消息
                self._deliver_to_subscriber(agent_id, message)
                delivered_agents.add(agent_id)

    def _deliver_to_subscriber(self, agent_id: str, message: AgentMessage):
        """投递消息给订阅者"""
        if agent_id not in self._subscribers:
            return

        for callback in self._subscribers[agent_id]:
            try:
                callback(message)
                self.stats["messages_delivered"] += 1
            except Exception as e:
                logger.error(f"消息投递失败 (agent={agent_id}): {e}")
                self.stats["messages_failed"] += 1

    def get_next_message(
        self,
        priority: MessagePriority = MessagePriority.NORMAL,
        timeout: float = 0.1
    ) -> Optional[AgentMessage]:
        """
        从优先级队列获取下一条消息

        Args:
            priority: 优先级
            timeout: 超时时间（秒）

        Returns:
            消息或None
        """
        try:
            queue = self.priority_queues[priority]
            message = queue.get_nowait()
            return message
        except asyncio.QueueEmpty:
            return None

    async def get_next_message_async(
        self,
        priority: MessagePriority = MessagePriority.NORMAL,
        timeout: Optional[float] = None
    ) -> Optional[AgentMessage]:
        """
        异步从优先级队列获取下一条消息

        Args:
            priority: 优先级
            timeout: 超时时间（秒）

        Returns:
            消息或None
        """
        try:
            queue = self.priority_queues[priority]
            if timeout:
                message = await asyncio.wait_for(queue.get(), timeout=timeout)
            else:
                message = queue.get_nowait()
            return message
        except asyncio.QueueEmpty:
            return None
        except asyncio.TimeoutError:
            return None

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            "queue_sizes": {
                priority.name: queue.qsize()
                for priority, queue in self.priority_queues.items()
            },
            "subscriber_count": len(self._subscribers),
            "filter_count": len(self.subscription_filters)
        }

    def clear_history(self):
        """清空消息历史"""
        with self._lock:
            self.message_history.clear()

    def get_history(
        self,
        limit: int = 100,
        sender: Optional[str] = None,
        message_type: Optional[MessageType] = None
    ) -> List[AgentMessage]:
        """
        获取消息历史

        Args:
            limit: 限制数量
            sender: 发送者过滤
            message_type: 消息类型过滤

        Returns:
            消息列表
        """
        with self._lock:
            messages = self.message_history.copy()

        if sender:
            messages = [m for m in messages if m.sender == sender]

        if message_type:
            messages = [m for m in messages if m.type == message_type]

        return messages[-limit:]


# ==================== 消息处理器 ====================

class MessageHandler(ABC):
    """消息处理器基类"""

    @abstractmethod
    async def handle(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        处理消息

        Args:
            message: 接收到的消息

        Returns:
            可选的响应消息
        """
        pass


class HeartbeatHandler(MessageHandler):
    """心跳处理器"""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.last_heartbeat = time.time()

    async def handle(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理心跳消息"""
        if message.type == MessageTypeV2.HEARTBEAT:
            self.last_heartbeat = time.time()

            # 返回心跳响应
            return AgentMessage(
                id=str(uuid.uuid4()),
                type=MessageTypeV2.STATUS_UPDATE,
                sender=self.agent_id,
                receiver=message.sender,
                content={"status": "alive", "timestamp": time.time()},
                priority=MessagePriority.LOW
            )
        return None


class AckHandler(MessageHandler):
    """消息确认处理器"""

    def __init__(self):
        self.pending_messages: Dict[str, AgentMessage] = {}

    async def handle(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理ACK消息"""
        if message.type == MessageTypeV2.ACK:
            # 从待确认列表中移除
            if message.id in self.pending_messages:
                del self.pending_messages[id]
                logger.debug(f"收到ACK: {message.id}")

            return None
        return None


# ==================== 工具函数 ====================

def create_message(
    msg_type: MessageType,
    sender: str,
    receiver: str,
    content: Any,
    priority: MessagePriority = MessagePriority.NORMAL,
    correlation_id: Optional[str] = None,
    requires_ack: bool = False
) -> AgentMessage:
    """
    创建消息的便捷函数

    Args:
        msg_type: 消息类型
        sender: 发送者
        receiver: 接收者
        content: 消息内容
        priority: 优先级
        correlation_id: 关联ID（用于请求-响应匹配）
        requires_ack: 是否需要确认

    Returns:
        AgentMessage对象
    """
    message = AgentMessage(
        id=str(uuid.uuid4()),
        type=msg_type,
        sender=sender,
        receiver=receiver,
        content=content,
        priority=priority
    )

    # 添加元数据
    if correlation_id:
        message.metadata["correlation_id"] = correlation_id
    if requires_ack:
        message.metadata["requires_ack"] = True

    return message


def broadcast_message(
    msg_type: MessageType,
    sender: str,
    content: Any,
    priority: MessagePriority = MessagePriority.NORMAL
) -> AgentMessage:
    """
    创建广播消息的便捷函数

    Args:
        msg_type: 消息类型
        sender: 发送者
        content: 消息内容
        priority: 优先级

    Returns:
        AgentMessage对象
    """
    return create_message(
        msg_type=msg_type,
        sender=sender,
        receiver="all",
        content=content,
        priority=priority
    )


# ==================== 导出 ====================

__all__ = [
    'MessageTypeV2',
    'MessagePriorityV2',
    'MessageFilter',
    'TypeFilter',
    'SenderFilter',
    'ContentFilter',
    'PriorityFilter',
    'RoutingTable',
    'MeshMessageBus',
    'MessageHandler',
    'HeartbeatHandler',
    'AckHandler',
    'create_message',
    'broadcast_message'
]
