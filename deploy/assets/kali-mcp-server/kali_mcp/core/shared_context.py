#!/usr/bin/env python3
"""
SharedContext - 分层信息共享 (v5.0)

核心功能:
- KeyMessage: 持久化关键信息 (目标环境/源码信息/漏洞候选/凭据/攻击面)
- SharedMessage: 实时广播 (Agent间发现共享)
- SQLite持久化存储
- 线程安全
"""

import json
import sqlite3
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class SharedMessage:
    """广播消息"""
    agent_id: str = ""
    message_type: str = ""       # discovery/alert/status/request
    content: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# 预定义Key常量
KEY_TARGET_ENV = "TargetEnvInfo"
KEY_SOURCE_CODE = "SourceCodeInfo"
KEY_VULN_CANDIDATES = "VulnCandidates"
KEY_CREDENTIALS = "Credentials"
KEY_ATTACK_SURFACE = "AttackSurface"
KEY_TECH_STACK = "TechStack"
KEY_OPEN_PORTS = "OpenPorts"
KEY_ENDPOINTS = "Endpoints"


class SharedContext:
    """分层信息共享上下文"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path.home() / ".kali_mcp" / "shared_context.db")
        self.db_path = db_path
        self._lock = threading.Lock()
        self._broadcasts: List[SharedMessage] = []
        self._max_broadcasts = 200
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS key_messages (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_by TEXT DEFAULT '',
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS broadcasts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    message_type TEXT,
                    content TEXT,
                    data TEXT DEFAULT '{}',
                    timestamp TEXT
                )
            """)
            conn.commit()
        logger.info(f"SharedContext 初始化完成: {self.db_path}")

    # ==================== KeyMessage (持久化) ====================

    def set_key(self, key: str, value: Any, updated_by: str = "") -> None:
        """设置持久化关键信息"""
        with self._lock:
            conn = self._get_conn()
            try:
                val_str = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
                conn.execute(
                    """INSERT OR REPLACE INTO key_messages (key, value, updated_by, updated_at)
                       VALUES (?, ?, ?, ?)""",
                    (key, val_str, updated_by, datetime.now().isoformat()))
                conn.commit()
                logger.info(f"SharedContext.set_key: {key} (by {updated_by})")
            finally:
                conn.close()

    def get_key(self, key: str) -> Optional[Any]:
        """获取持久化关键信息"""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT value FROM key_messages WHERE key=?", (key,)).fetchone()
            if not row:
                return None
            try:
                return json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                return row["value"]
        finally:
            conn.close()

    def get_all_keys(self) -> Dict[str, Any]:
        """获取所有持久化信息"""
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT key, value, updated_by, updated_at FROM key_messages").fetchall()
            result = {}
            for row in rows:
                try:
                    result[row["key"]] = {
                        "value": json.loads(row["value"]),
                        "updated_by": row["updated_by"],
                        "updated_at": row["updated_at"],
                    }
                except (json.JSONDecodeError, TypeError):
                    result[row["key"]] = {
                        "value": row["value"],
                        "updated_by": row["updated_by"],
                        "updated_at": row["updated_at"],
                    }
            return result
        finally:
            conn.close()

    def delete_key(self, key: str) -> bool:
        """删除持久化信息"""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute("DELETE FROM key_messages WHERE key=?", (key,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ==================== SharedMessage (广播) ====================

    def broadcast(self, agent_id: str, message_type: str, content: str,
                  data: Dict[str, Any] = None) -> None:
        """广播发现"""
        msg = SharedMessage(
            agent_id=agent_id,
            message_type=message_type,
            content=content,
            data=data or {},
        )
        with self._lock:
            self._broadcasts.append(msg)
            if len(self._broadcasts) > self._max_broadcasts:
                self._broadcasts = self._broadcasts[-self._max_broadcasts:]

            # 持久化到数据库
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO broadcasts (agent_id, message_type, content, data, timestamp)
                       VALUES (?, ?, ?, ?, ?)""",
                    (msg.agent_id, msg.message_type, msg.content,
                     json.dumps(msg.data, ensure_ascii=False), msg.timestamp))
                conn.commit()
            finally:
                conn.close()

        logger.info(f"SharedContext.broadcast: [{message_type}] {agent_id}: {content[:80]}")

    def get_broadcasts(self, limit: int = 50, agent_id: str = "",
                       message_type: str = "") -> List[Dict[str, Any]]:
        """获取广播消息"""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM broadcasts WHERE 1=1"
            params = []
            if agent_id:
                query += " AND agent_id=?"
                params.append(agent_id)
            if message_type:
                query += " AND message_type=?"
                params.append(message_type)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d["data"] = json.loads(d.get("data", "{}"))
                except (json.JSONDecodeError, TypeError):
                    d["data"] = {}
                result.append(d)
            return list(reversed(result))
        finally:
            conn.close()

    def get_recent_broadcasts(self, count: int = 10) -> List[SharedMessage]:
        """获取最近的内存广播"""
        return self._broadcasts[-count:]

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取共享上下文统计"""
        conn = self._get_conn()
        try:
            key_count = conn.execute("SELECT COUNT(*) FROM key_messages").fetchone()[0]
            broadcast_count = conn.execute("SELECT COUNT(*) FROM broadcasts").fetchone()[0]
            return {
                "key_count": key_count,
                "broadcast_count": broadcast_count,
                "memory_broadcasts": len(self._broadcasts),
            }
        finally:
            conn.close()
