#!/usr/bin/env python3
"""
会话管理模块

提供攻击会话的生命周期管理:
- 会话创建和销毁
- 状态持久化
- 上下文跟踪
- 发现资产管理
"""

import json
import time
import uuid
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


class AttackMode(Enum):
    """攻击模式"""
    CTF = "ctf"                      # CTF竞赛模式
    PENTEST = "pentest"              # 渗透测试模式
    APT = "apt"                      # APT模拟模式
    VULN_RESEARCH = "vuln_research"  # 漏洞研究模式
    AWD = "awd"                      # 攻防赛模式


class SessionStatus(Enum):
    """会话状态"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class DiscoveredAsset:
    """发现的资产"""
    asset_type: str  # port, service, vulnerability, credential, file, flag
    value: str
    source_tool: str
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.asset_type,
            "value": self.value,
            "source": self.source_tool,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


@dataclass
class AttackStep:
    """攻击步骤记录"""
    step_id: str
    tool_name: str
    command: str
    success: bool
    output_summary: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "tool": self.tool_name,
            "command": self.command,
            "success": self.success,
            "summary": self.output_summary,
            "findings": self.findings,
            "timestamp": self.timestamp,
            "duration": self.duration
        }


@dataclass
class SessionContext:
    """会话上下文 - 维护攻击会话的完整状态"""

    session_id: str
    target: str
    mode: AttackMode = AttackMode.PENTEST
    status: SessionStatus = SessionStatus.ACTIVE

    # 时间信息
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # 发现的资产
    discovered_assets: List[DiscoveredAsset] = field(default_factory=list)

    # 攻击步骤历史
    attack_steps: List[AttackStep] = field(default_factory=list)

    # 对话历史
    conversation_history: List[Dict[str, str]] = field(default_factory=list)

    # 自定义元数据
    metadata: Dict[str, Any] = field(default_factory=dict)

    # CTF特有字段
    flags_found: List[str] = field(default_factory=list)
    challenge_category: str = ""

    # 统计信息
    tools_used: Set[str] = field(default_factory=set)

    def add_asset(self, asset: DiscoveredAsset):
        """添加发现的资产"""
        self.discovered_assets.append(asset)
        self.updated_at = time.time()
        logger.debug(f"添加资产: {asset.asset_type}={asset.value}")

    def add_step(self, step: AttackStep):
        """添加攻击步骤"""
        self.attack_steps.append(step)
        self.tools_used.add(step.tool_name)
        self.updated_at = time.time()

    def add_conversation(self, role: str, content: str):
        """添加对话记录"""
        self.conversation_history.append({
            "role": role,
            "content": content,
            "timestamp": time.time()
        })
        self.updated_at = time.time()

    def add_flag(self, flag: str):
        """添加发现的Flag"""
        if flag not in self.flags_found:
            self.flags_found.append(flag)
            self.add_asset(DiscoveredAsset(
                asset_type="flag",
                value=flag,
                source_tool="auto_detection"
            ))
            logger.info(f"发现Flag: {flag}")

    def get_ports(self) -> List[str]:
        """获取发现的端口列表"""
        return [a.value for a in self.discovered_assets if a.asset_type == "port"]

    def get_services(self) -> List[Dict[str, Any]]:
        """获取发现的服务列表"""
        return [a.to_dict() for a in self.discovered_assets if a.asset_type == "service"]

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """获取发现的漏洞列表"""
        return [a.to_dict() for a in self.discovered_assets if a.asset_type == "vulnerability"]

    def get_summary(self) -> Dict[str, Any]:
        """获取会话摘要"""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "mode": self.mode.value,
            "status": self.status.value,
            "duration": time.time() - self.created_at,
            "steps_count": len(self.attack_steps),
            "assets_count": len(self.discovered_assets),
            "flags_found": len(self.flags_found),
            "tools_used": list(self.tools_used),
            "success_rate": self._calculate_success_rate()
        }

    def _calculate_success_rate(self) -> float:
        """计算成功率"""
        if not self.attack_steps:
            return 0.0
        successful = sum(1 for s in self.attack_steps if s.success)
        return (successful / len(self.attack_steps)) * 100

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典(用于持久化)"""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "mode": self.mode.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "discovered_assets": [a.to_dict() for a in self.discovered_assets],
            "attack_steps": [s.to_dict() for s in self.attack_steps],
            "conversation_history": self.conversation_history,
            "metadata": self.metadata,
            "flags_found": self.flags_found,
            "challenge_category": self.challenge_category,
            "tools_used": list(self.tools_used)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionContext':
        """从字典创建(用于恢复)"""
        ctx = cls(
            session_id=data["session_id"],
            target=data["target"],
            mode=AttackMode(data.get("mode", "pentest")),
            status=SessionStatus(data.get("status", "active")),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            conversation_history=data.get("conversation_history", []),
            metadata=data.get("metadata", {}),
            flags_found=data.get("flags_found", []),
            challenge_category=data.get("challenge_category", ""),
            tools_used=set(data.get("tools_used", []))
        )

        # 恢复资产
        for asset_data in data.get("discovered_assets", []):
            ctx.discovered_assets.append(DiscoveredAsset(
                asset_type=asset_data["type"],
                value=asset_data["value"],
                source_tool=asset_data["source"],
                confidence=asset_data.get("confidence", 1.0),
                timestamp=asset_data.get("timestamp", time.time()),
                metadata=asset_data.get("metadata", {})
            ))

        # 恢复攻击步骤
        for step_data in data.get("attack_steps", []):
            ctx.attack_steps.append(AttackStep(
                step_id=step_data["step_id"],
                tool_name=step_data["tool"],
                command=step_data["command"],
                success=step_data["success"],
                output_summary=step_data["summary"],
                findings=step_data.get("findings", []),
                timestamp=step_data.get("timestamp", time.time()),
                duration=step_data.get("duration", 0.0)
            ))

        return ctx


# 会话TTL：超过此时间未更新的ACTIVE会话将被自动清理（4小时）
SESSION_TTL = 4 * 3600
# 清理检查间隔（10分钟）
_CLEANUP_INTERVAL = 600


class SessionManager:
    """会话管理器 - 管理多个攻击会话"""

    def __init__(self, storage_dir: Optional[str] = None):
        """
        初始化会话管理器

        Args:
            storage_dir: 会话存储目录
        """
        self._sessions: Dict[str, SessionContext] = {}
        self._current_session_id: Optional[str] = None
        self._lock = threading.Lock()

        if storage_dir:
            self._storage_path = Path(storage_dir)
            self._storage_path.mkdir(parents=True, exist_ok=True)
        else:
            self._storage_path = None

        # 启动后台TTL清理线程
        self._start_cleanup_thread()

        logger.info("SessionManager初始化完成")

    def _start_cleanup_thread(self):
        """启动后台会话过期清理线程"""
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

    def _cleanup_loop(self):
        """定期清理过期会话"""
        import time as _time
        while True:
            _time.sleep(_CLEANUP_INTERVAL)
            self._cleanup_expired_sessions()

    def _cleanup_expired_sessions(self):
        """清理超过TTL且处于ACTIVE状态的过期会话"""
        now = time.time()
        expired = []
        with self._lock:
            for sid, session in self._sessions.items():
                if (
                    session.status == SessionStatus.ACTIVE
                    and now - session.updated_at > SESSION_TTL
                ):
                    expired.append(sid)
            for sid in expired:
                session = self._sessions.pop(sid)
                session.status = SessionStatus.COMPLETED
                if self._current_session_id == sid:
                    self._current_session_id = None
                logger.info(f"TTL过期，自动清理会话: {sid} (target={session.target})")

    def create_session(
        self,
        target: str,
        mode: AttackMode = AttackMode.PENTEST,
        session_name: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> SessionContext:
        """
        创建新会话

        Args:
            target: 目标地址
            mode: 攻击模式
            session_name: 会话名称(可选)
            metadata: 额外元数据

        Returns:
            新创建的SessionContext
        """
        session_id = session_name or str(uuid.uuid4())[:8]

        with self._lock:
            if session_id in self._sessions:
                # 如果ID已存在，添加时间戳
                session_id = f"{session_id}_{int(time.time())}"

            session = SessionContext(
                session_id=session_id,
                target=target,
                mode=mode,
                metadata=metadata or {}
            )

            self._sessions[session_id] = session
            self._current_session_id = session_id

        logger.info(f"创建会话: {session_id} (目标: {target}, 模式: {mode.value})")
        return session

    def get_session(self, session_id: Optional[str] = None) -> Optional[SessionContext]:
        """
        获取会话

        Args:
            session_id: 会话ID，为None时返回当前会话

        Returns:
            SessionContext或None
        """
        with self._lock:
            if session_id is None:
                session_id = self._current_session_id

            if session_id is None:
                return None

            return self._sessions.get(session_id)

    def get_or_create_session(
        self,
        target: str,
        mode: AttackMode = AttackMode.PENTEST
    ) -> SessionContext:
        """
        获取或创建会话

        Args:
            target: 目标地址
            mode: 攻击模式

        Returns:
            SessionContext
        """
        session = self.get_session()

        if session is None or session.target != target:
            session = self.create_session(target, mode)

        return session

    def set_current_session(self, session_id: str) -> bool:
        """设置当前会话"""
        with self._lock:
            if session_id in self._sessions:
                self._current_session_id = session_id
                return True
            return False

    def end_session(self, session_id: Optional[str] = None) -> Optional[SessionContext]:
        """
        结束会话

        Args:
            session_id: 会话ID

        Returns:
            结束的SessionContext
        """
        with self._lock:
            if session_id is None:
                session_id = self._current_session_id

            if session_id is None or session_id not in self._sessions:
                return None

            session = self._sessions[session_id]
            session.status = SessionStatus.COMPLETED
            session.updated_at = time.time()

            # 保存到磁盘
            if self._storage_path:
                self._save_session(session)

            # 如果是当前会话，清除引用
            if self._current_session_id == session_id:
                self._current_session_id = None

        logger.info(f"结束会话: {session_id}")
        return session

    def list_sessions(self) -> List[Dict[str, Any]]:
        """列出所有会话"""
        with self._lock:
            return [s.get_summary() for s in self._sessions.values()]

    def _save_session(self, session: SessionContext):
        """保存会话到磁盘"""
        if not self._storage_path:
            return

        file_path = self._storage_path / f"{session.session_id}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(session.to_dict(), f, ensure_ascii=False, indent=2)

        logger.debug(f"会话已保存: {file_path}")

    def load_session(self, session_id: str) -> Optional[SessionContext]:
        """从磁盘加载会话"""
        if not self._storage_path:
            return None

        file_path = self._storage_path / f"{session_id}.json"
        if not file_path.exists():
            return None

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        session = SessionContext.from_dict(data)

        with self._lock:
            self._sessions[session_id] = session

        logger.info(f"加载会话: {session_id}")
        return session

    def get_stats(self) -> Dict[str, Any]:
        """获取会话管理器统计"""
        with self._lock:
            active = sum(1 for s in self._sessions.values() if s.status == SessionStatus.ACTIVE)
            completed = sum(1 for s in self._sessions.values() if s.status == SessionStatus.COMPLETED)

            return {
                "total_sessions": len(self._sessions),
                "active_sessions": active,
                "completed_sessions": completed,
                "current_session": self._current_session_id
            }


# 全局会话管理器
_global_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """获取全局会话管理器"""
    global _global_session_manager
    if _global_session_manager is None:
        _global_session_manager = SessionManager()
    return _global_session_manager
