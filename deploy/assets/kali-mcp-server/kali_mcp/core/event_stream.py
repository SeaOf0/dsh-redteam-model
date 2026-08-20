#!/usr/bin/env python3
"""
Kali MCP 事件流系统 v2.1

事件流架构:
- EventType: 事件类型枚举
- EventData: 事件数据结构
- EventEmitter: 事件发射器
- EventManager: 事件管理器
- StreamHandler: 流式事件处理器

适配场景:
- 安全工具执行的实时反馈
- CTF 解题过程的可视化
- 渗透测试的步骤记录
- 攻击链的进度追踪
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any, AsyncGenerator, Callable, Dict, List,
    Optional, Union
)

logger = logging.getLogger(__name__)


# ============ 事件类型 ============

class EventType(str, Enum):
    """安全测试事件类型"""

    # 阶段相关
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    PHASE_ERROR = "phase_error"

    # ReAct 思考相关
    THINKING_START = "thinking_start"
    THINKING_TOKEN = "thinking_token"
    THINKING_END = "thinking_end"
    THOUGHT = "thought"
    ACTION = "action"
    OBSERVATION = "observation"
    DECISION = "decision"

    # 工具调用相关
    TOOL_CALL = "tool_call"
    TOOL_START = "tool_start"
    TOOL_PROGRESS = "tool_progress"
    TOOL_OUTPUT = "tool_output"
    TOOL_RESULT = "tool_result"
    TOOL_ERROR = "tool_error"
    TOOL_COMPLETE = "tool_complete"

    # 发现相关
    FINDING_NEW = "finding_new"
    FINDING_VERIFIED = "finding_verified"
    VULNERABILITY = "vulnerability"
    FLAG_FOUND = "flag_found"
    CREDENTIAL_FOUND = "credential_found"

    # 攻击链相关
    ATTACK_START = "attack_start"
    ATTACK_PROGRESS = "attack_progress"
    ATTACK_SUCCESS = "attack_success"
    ATTACK_FAILED = "attack_failed"
    ATTACK_COMPLETE = "attack_complete"

    # 会话相关
    SESSION_START = "session_start"
    SESSION_UPDATE = "session_update"
    SESSION_END = "session_end"

    # 状态相关
    PROGRESS = "progress"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    DEBUG = "debug"

    # 任务相关
    TASK_START = "task_start"
    TASK_COMPLETE = "task_complete"
    TASK_ERROR = "task_error"
    TASK_CANCEL = "task_cancel"

    # 心跳
    HEARTBEAT = "heartbeat"


# ============ 事件数据结构 ============

@dataclass
class EventData:
    """事件数据"""
    event_type: EventType
    message: str = ""

    # 可选字段
    phase: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[Dict[str, Any]] = None
    tool_duration_ms: Optional[int] = None

    # 发现相关
    finding_id: Optional[str] = None
    severity: Optional[str] = None
    vulnerability_type: Optional[str] = None

    # CTF 相关
    flag: Optional[str] = None
    challenge_name: Optional[str] = None

    # 进度相关
    current: Optional[int] = None
    total: Optional[int] = None
    percentage: Optional[float] = None

    # 额外元数据
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "event_type": self.event_type.value if isinstance(self.event_type, EventType) else self.event_type,
            "message": self.message,
        }

        # 添加非空字段
        if self.phase:
            result["phase"] = self.phase
        if self.tool_name:
            result["tool_name"] = self.tool_name
        if self.tool_input:
            result["tool_input"] = self.tool_input
        if self.tool_output:
            result["tool_output"] = self.tool_output
        if self.tool_duration_ms is not None:
            result["tool_duration_ms"] = self.tool_duration_ms
        if self.finding_id:
            result["finding_id"] = self.finding_id
        if self.severity:
            result["severity"] = self.severity
        if self.vulnerability_type:
            result["vulnerability_type"] = self.vulnerability_type
        if self.flag:
            result["flag"] = self.flag
        if self.challenge_name:
            result["challenge_name"] = self.challenge_name
        if self.current is not None:
            result["current"] = self.current
        if self.total is not None:
            result["total"] = self.total
        if self.percentage is not None:
            result["percentage"] = self.percentage
        if self.metadata:
            result["metadata"] = self.metadata

        return result


@dataclass
class StreamEvent:
    """流式事件"""
    event_type: EventType
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sequence: int = 0

    # 可选上下文
    session_id: Optional[str] = None
    task_id: Optional[str] = None
    phase: Optional[str] = None
    tool_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "event_type": self.event_type.value if isinstance(self.event_type, EventType) else self.event_type,
            "data": self.data,
            "timestamp": self.timestamp,
            "sequence": self.sequence,
        }

        if self.session_id:
            result["session_id"] = self.session_id
        if self.task_id:
            result["task_id"] = self.task_id
        if self.phase:
            result["phase"] = self.phase
        if self.tool_name:
            result["tool_name"] = self.tool_name

        return result

    def to_sse(self) -> str:
        """转换为 SSE 格式"""
        event_name = self.event_type.value if isinstance(self.event_type, EventType) else self.event_type
        return f"event: {event_name}\ndata: {json.dumps(self.to_dict(), ensure_ascii=False)}\n\n"


# ============ 事件发射器 ============

class EventEmitter:
    """
    事件发射器

    用于在安全测试过程中发射各类事件
    """

    def __init__(
        self,
        session_id: str,
        event_manager: Optional['EventManager'] = None,
    ):
        self.session_id = session_id
        self.event_manager = event_manager
        self._sequence = 0
        self._current_phase: Optional[str] = None
        self._tool_start_times: Dict[str, float] = {}

    async def emit(self, event_data: EventData) -> Optional[str]:
        """发射事件"""
        self._sequence += 1

        if event_data.phase is None:
            event_data.phase = self._current_phase

        if self.event_manager:
            return await self.event_manager.add_event(
                session_id=self.session_id,
                sequence=self._sequence,
                **event_data.to_dict()
            )
        return None

    def emit_sync(self, event_data: EventData) -> Optional[str]:
        """同步发射事件"""
        self._sequence += 1

        if event_data.phase is None:
            event_data.phase = self._current_phase

        if self.event_manager:
            return self.event_manager.add_event_sync(
                session_id=self.session_id,
                sequence=self._sequence,
                **event_data.to_dict()
            )
        return None

    # ============ 阶段事件 ============

    async def emit_phase_start(self, phase: str, message: Optional[str] = None):
        """发射阶段开始事件"""
        self._current_phase = phase
        await self.emit(EventData(
            event_type=EventType.PHASE_START,
            phase=phase,
            message=message or f"开始 {phase} 阶段",
        ))

    async def emit_phase_complete(self, phase: str, message: Optional[str] = None):
        """发射阶段完成事件"""
        await self.emit(EventData(
            event_type=EventType.PHASE_COMPLETE,
            phase=phase,
            message=message or f"{phase} 阶段完成",
        ))

    # ============ ReAct 思考事件 ============

    async def emit_thinking_start(self, message: str = "正在分析..."):
        """发射思考开始事件"""
        await self.emit(EventData(
            event_type=EventType.THINKING_START,
            message=f" {message}",
        ))

    async def emit_thought(self, thought: str, iteration: int = 0):
        """发射思考内容事件"""
        display = thought[:500] + "..." if len(thought) > 500 else thought
        await self.emit(EventData(
            event_type=EventType.THOUGHT,
            message=f" 思考:\n{display}",
            metadata={"thought": thought, "iteration": iteration},
        ))

    async def emit_decision(self, decision: str, reason: str = ""):
        """发射决策事件"""
        await self.emit(EventData(
            event_type=EventType.DECISION,
            message=f" 决策: {decision}" + (f" ({reason})" if reason else ""),
            metadata={"decision": decision, "reason": reason},
        ))

    async def emit_action(self, action: str, action_input: Dict[str, Any]):
        """发射动作事件"""
        input_str = json.dumps(action_input, ensure_ascii=False)[:200]
        await self.emit(EventData(
            event_type=EventType.ACTION,
            message=f" 动作: {action}\n   参数: {input_str}",
            metadata={"action": action, "action_input": action_input},
        ))

    async def emit_observation(self, observation: str, tool_name: Optional[str] = None):
        """发射观察事件"""
        display = observation[:1000] + "..." if len(observation) > 1000 else observation
        await self.emit(EventData(
            event_type=EventType.OBSERVATION,
            message=f" 观察:\n{display}",
            tool_name=tool_name,
            metadata={"observation": observation},
        ))

    async def emit_thinking_end(self, message: str = "思考完成"):
        """发射思考结束事件"""
        await self.emit(EventData(
            event_type=EventType.THINKING_END,
            message=f" {message}",
        ))

    # ============ 工具调用事件 ============

    async def emit_tool_call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        message: Optional[str] = None,
    ):
        """发射工具调用事件"""
        self._tool_start_times[tool_name] = time.time()
        await self.emit(EventData(
            event_type=EventType.TOOL_CALL,
            tool_name=tool_name,
            tool_input=tool_input,
            message=message or f" 调用工具: {tool_name}",
        ))

    async def emit_tool_progress(
        self,
        tool_name: str,
        progress: float,
        message: Optional[str] = None,
    ):
        """发射工具进度事件"""
        await self.emit(EventData(
            event_type=EventType.TOOL_PROGRESS,
            tool_name=tool_name,
            percentage=progress,
            message=message or f" {tool_name}: {progress:.1f}%",
        ))

    async def emit_tool_result(
        self,
        tool_name: str,
        tool_output: Any,
        message: Optional[str] = None,
    ):
        """发射工具结果事件"""
        # 计算执行时间
        duration_ms = 0
        if tool_name in self._tool_start_times:
            duration_ms = int((time.time() - self._tool_start_times[tool_name]) * 1000)
            del self._tool_start_times[tool_name]

        # 处理输出
        if hasattr(tool_output, 'to_dict'):
            output_data = tool_output.to_dict()
        elif isinstance(tool_output, str):
            output_data = {"result": tool_output[:2000]}
        elif isinstance(tool_output, dict):
            output_data = tool_output
        else:
            output_data = {"result": str(tool_output)[:2000]}

        await self.emit(EventData(
            event_type=EventType.TOOL_RESULT,
            tool_name=tool_name,
            tool_output=output_data,
            tool_duration_ms=duration_ms,
            message=message or f" 工具 {tool_name} 完成 ({duration_ms}ms)",
        ))

    async def emit_tool_error(
        self,
        tool_name: str,
        error: str,
        message: Optional[str] = None,
    ):
        """发射工具错误事件"""
        await self.emit(EventData(
            event_type=EventType.TOOL_ERROR,
            tool_name=tool_name,
            message=message or f" 工具 {tool_name} 错误: {error}",
            metadata={"error": error},
        ))

    # ============ 发现事件 ============

    async def emit_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        vulnerability_type: str,
        is_verified: bool = False,
    ):
        """发射漏洞发现事件"""
        event_type = EventType.FINDING_VERIFIED if is_verified else EventType.FINDING_NEW
        prefix = " 已验证" if is_verified else " 新发现"

        await self.emit(EventData(
            event_type=event_type,
            finding_id=finding_id,
            severity=severity,
            vulnerability_type=vulnerability_type,
            message=f"{prefix}: [{severity.upper()}] {title}",
            metadata={
                "id": finding_id,
                "title": title,
                "severity": severity,
                "vulnerability_type": vulnerability_type,
                "is_verified": is_verified,
            },
        ))

    async def emit_flag_found(
        self,
        flag: str,
        challenge_name: Optional[str] = None,
        source: Optional[str] = None,
    ):
        """发射 Flag 发现事件"""
        await self.emit(EventData(
            event_type=EventType.FLAG_FOUND,
            flag=flag,
            challenge_name=challenge_name,
            message=f" 发现 Flag: {flag}",
            metadata={
                "flag": flag,
                "challenge": challenge_name,
                "source": source,
            },
        ))

    async def emit_credential_found(
        self,
        username: str,
        password: Optional[str] = None,
        service: Optional[str] = None,
    ):
        """发射凭据发现事件"""
        cred_display = f"{username}:{password[:3]}***" if password else username
        await self.emit(EventData(
            event_type=EventType.CREDENTIAL_FOUND,
            message=f" 发现凭据: {cred_display}" + (f" ({service})" if service else ""),
            metadata={
                "username": username,
                "password_found": password is not None,
                "service": service,
            },
        ))

    # ============ 攻击链事件 ============

    async def emit_attack_start(
        self,
        attack_type: str,
        target: str,
        message: Optional[str] = None,
    ):
        """发射攻击开始事件"""
        await self.emit(EventData(
            event_type=EventType.ATTACK_START,
            message=message or f" 开始 {attack_type} 攻击: {target}",
            metadata={"attack_type": attack_type, "target": target},
        ))

    async def emit_attack_progress(
        self,
        attack_type: str,
        current: int,
        total: int,
        message: Optional[str] = None,
    ):
        """发射攻击进度事件"""
        percentage = (current / total * 100) if total > 0 else 0
        await self.emit(EventData(
            event_type=EventType.ATTACK_PROGRESS,
            current=current,
            total=total,
            percentage=percentage,
            message=message or f" {attack_type}: {current}/{total} ({percentage:.1f}%)",
        ))

    async def emit_attack_success(
        self,
        attack_type: str,
        result: str,
        message: Optional[str] = None,
    ):
        """发射攻击成功事件"""
        await self.emit(EventData(
            event_type=EventType.ATTACK_SUCCESS,
            message=message or f" {attack_type} 攻击成功: {result}",
            metadata={"attack_type": attack_type, "result": result},
        ))

    async def emit_attack_failed(
        self,
        attack_type: str,
        reason: str,
        message: Optional[str] = None,
    ):
        """发射攻击失败事件"""
        await self.emit(EventData(
            event_type=EventType.ATTACK_FAILED,
            message=message or f" {attack_type} 攻击失败: {reason}",
            metadata={"attack_type": attack_type, "reason": reason},
        ))

    # ============ 状态事件 ============

    async def emit_progress(
        self,
        current: int,
        total: int,
        message: Optional[str] = None,
    ):
        """发射进度事件"""
        percentage = (current / total * 100) if total > 0 else 0
        await self.emit(EventData(
            event_type=EventType.PROGRESS,
            current=current,
            total=total,
            percentage=percentage,
            message=message or f"进度: {current}/{total} ({percentage:.1f}%)",
        ))

    async def emit_info(self, message: str, metadata: Optional[Dict] = None):
        """发射信息事件"""
        await self.emit(EventData(
            event_type=EventType.INFO,
            message=f"ℹ {message}",
            metadata=metadata,
        ))

    async def emit_warning(self, message: str, metadata: Optional[Dict] = None):
        """发射警告事件"""
        await self.emit(EventData(
            event_type=EventType.WARNING,
            message=f" {message}",
            metadata=metadata,
        ))

    async def emit_error(self, message: str, metadata: Optional[Dict] = None):
        """发射错误事件"""
        await self.emit(EventData(
            event_type=EventType.ERROR,
            message=f" {message}",
            metadata=metadata,
        ))

    # ============ 任务事件 ============

    async def emit_task_complete(
        self,
        findings_count: int = 0,
        duration_ms: int = 0,
        message: Optional[str] = None,
    ):
        """发射任务完成事件"""
        await self.emit(EventData(
            event_type=EventType.TASK_COMPLETE,
            message=message or f" 任务完成！发现 {findings_count} 个问题，耗时 {duration_ms/1000:.1f}秒",
            metadata={
                "findings_count": findings_count,
                "duration_ms": duration_ms,
            },
        ))

    async def emit_task_error(self, error: str, message: Optional[str] = None):
        """发射任务错误事件"""
        await self.emit(EventData(
            event_type=EventType.TASK_ERROR,
            message=message or f" 任务失败: {error}",
            metadata={"error": error},
        ))


# ============ 事件管理器 ============

class EventManager:
    """
    事件管理器

    负责事件的存储、检索和流式推送
    """

    def __init__(self):
        self._event_queues: Dict[str, asyncio.Queue] = {}
        self._event_callbacks: Dict[str, List[Callable]] = {}
        self._event_history: Dict[str, List[Dict[str, Any]]] = {}
        self._max_history = 1000

    async def add_event(
        self,
        session_id: str,
        event_type: Union[str, EventType],
        sequence: int = 0,
        message: str = "",
        **kwargs,
    ) -> str:
        """添加事件（异步）"""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # 构建事件数据
        event_data = {
            "id": event_id,
            "session_id": session_id,
            "event_type": event_type.value if isinstance(event_type, EventType) else event_type,
            "sequence": sequence,
            "message": message,
            "timestamp": timestamp,
            **kwargs,
        }

        # 保存到历史
        if session_id not in self._event_history:
            self._event_history[session_id] = []
        self._event_history[session_id].append(event_data)

        # 限制历史大小
        if len(self._event_history[session_id]) > self._max_history:
            self._event_history[session_id] = self._event_history[session_id][-self._max_history:]

        # 推送到队列
        if session_id in self._event_queues:
            try:
                self._event_queues[session_id].put_nowait(event_data)
            except asyncio.QueueFull:
                logger.warning(f"Event queue full for session {session_id}")

        # 调用回调
        if session_id in self._event_callbacks:
            for callback in self._event_callbacks[session_id]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event_data)
                    else:
                        callback(event_data)
                except Exception as e:
                    logger.error(f"Event callback error: {e}")

        return event_id

    def add_event_sync(
        self,
        session_id: str,
        event_type: Union[str, EventType],
        sequence: int = 0,
        message: str = "",
        **kwargs,
    ) -> str:
        """添加事件（同步）"""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        event_data = {
            "id": event_id,
            "session_id": session_id,
            "event_type": event_type.value if isinstance(event_type, EventType) else event_type,
            "sequence": sequence,
            "message": message,
            "timestamp": timestamp,
            **kwargs,
        }

        # 保存到历史
        if session_id not in self._event_history:
            self._event_history[session_id] = []
        self._event_history[session_id].append(event_data)

        # 推送到队列（非阻塞）
        if session_id in self._event_queues:
            try:
                self._event_queues[session_id].put_nowait(event_data)
            except asyncio.QueueFull:
                logger.warning(f"Event queue full for session {session_id}")

        return event_id

    def create_queue(self, session_id: str, maxsize: int = 5000) -> asyncio.Queue:
        """创建事件队列"""
        if session_id not in self._event_queues:
            self._event_queues[session_id] = asyncio.Queue(maxsize=maxsize)
        return self._event_queues[session_id]

    def remove_queue(self, session_id: str):
        """移除事件队列"""
        if session_id in self._event_queues:
            del self._event_queues[session_id]

    def add_callback(self, session_id: str, callback: Callable):
        """添加事件回调"""
        if session_id not in self._event_callbacks:
            self._event_callbacks[session_id] = []
        self._event_callbacks[session_id].append(callback)

    def remove_callback(self, session_id: str, callback: Callable):
        """移除事件回调"""
        if session_id in self._event_callbacks:
            try:
                self._event_callbacks[session_id].remove(callback)
            except ValueError:
                pass

    def get_events(
        self,
        session_id: str,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """获取事件列表"""
        if session_id not in self._event_history:
            return []

        events = [
            e for e in self._event_history[session_id]
            if e.get("sequence", 0) > after_sequence
        ]

        return events[:limit]

    async def stream_events(
        self,
        session_id: str,
        after_sequence: int = 0,
        timeout: float = 30.0,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        流式获取事件

        先发送缓存的事件，然后实时推送新事件
        """
        # 确保队列存在
        queue = self._event_queues.get(session_id)
        if not queue:
            queue = self.create_queue(session_id)

        # 先发送历史事件
        if session_id in self._event_history:
            for event in self._event_history[session_id]:
                if event.get("sequence", 0) > after_sequence:
                    yield event

                    # 检查是否是结束事件
                    if event.get("event_type") in [
                        EventType.TASK_COMPLETE.value,
                        EventType.TASK_ERROR.value,
                        EventType.TASK_CANCEL.value,
                    ]:
                        return

        # 实时推送新事件
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=timeout)

                    # 过滤旧事件
                    if event.get("sequence", 0) <= after_sequence:
                        continue

                    yield event

                    # 检查是否是结束事件
                    if event.get("event_type") in [
                        EventType.TASK_COMPLETE.value,
                        EventType.TASK_ERROR.value,
                        EventType.TASK_CANCEL.value,
                    ]:
                        break

                except asyncio.TimeoutError:
                    # 发送心跳
                    yield {
                        "event_type": EventType.HEARTBEAT.value,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

        except GeneratorExit:
            logger.debug(f"Event stream closed for session {session_id}")

    def create_emitter(self, session_id: str) -> EventEmitter:
        """创建事件发射器"""
        return EventEmitter(session_id, self)

    def clear_session(self, session_id: str):
        """清理会话数据"""
        if session_id in self._event_queues:
            del self._event_queues[session_id]
        if session_id in self._event_callbacks:
            del self._event_callbacks[session_id]
        if session_id in self._event_history:
            del self._event_history[session_id]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "active_sessions": len(self._event_queues),
            "total_events": sum(len(h) for h in self._event_history.values()),
            "sessions": {
                sid: {
                    "queue_size": q.qsize() if sid in self._event_queues else 0,
                    "history_size": len(self._event_history.get(sid, [])),
                    "callbacks": len(self._event_callbacks.get(sid, [])),
                }
                for sid in set(self._event_queues.keys()) | set(self._event_history.keys())
            },
        }


# ============ 全局实例 ============

_global_event_manager: Optional[EventManager] = None


def get_event_manager() -> EventManager:
    """获取全局事件管理器"""
    global _global_event_manager
    if _global_event_manager is None:
        _global_event_manager = EventManager()
    return _global_event_manager


def create_emitter(session_id: str) -> EventEmitter:
    """创建事件发射器的便捷函数"""
    return get_event_manager().create_emitter(session_id)


# ============ 导出 ============

__all__ = [
    # 事件类型
    "EventType",
    # 数据结构
    "EventData",
    "StreamEvent",
    # 核心类
    "EventEmitter",
    "EventManager",
    # 便捷函数
    "get_event_manager",
    "create_emitter",
]
