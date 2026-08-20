#!/usr/bin/env python3
"""
CheckpointManager - 检查点管理器 (v5.0)

核心功能:
- 保存攻击进度检查点
- 支持从检查点恢复
- 自动检查点（关键阶段自动保存）
"""

import json
import sqlite3
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class CheckpointManager:
    """检查点管理器 - 攻击进度保存和恢复"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path.home() / ".kali_mcp" / "checkpoints.db")
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    phase TEXT,
                    description TEXT,
                    state TEXT DEFAULT '{}',
                    created_at TEXT
                )
            """)
            conn.commit()
        logger.info(f"CheckpointManager 初始化完成: {self.db_path}")

    def save_checkpoint(self, session_id: str, phase: str,
                        description: str, state: Dict[str, Any]) -> str:
        """保存检查点"""
        import uuid
        cp_id = f"CP-{uuid.uuid4().hex[:8].upper()}"
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO checkpoints (checkpoint_id, session_id, phase,
                       description, state, created_at) VALUES (?,?,?,?,?,?)""",
                    (cp_id, session_id, phase, description,
                     json.dumps(state, ensure_ascii=False),
                     datetime.now().isoformat()))
                conn.commit()
                logger.info(f"检查点已保存: {cp_id} [{phase}] {description}")
                return cp_id
            finally:
                conn.close()

    def load_checkpoint(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        """加载检查点"""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM checkpoints WHERE checkpoint_id=?", (checkpoint_id,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["state"] = json.loads(d.get("state", "{}"))
            return d
        finally:
            conn.close()

    def get_latest(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话最新检查点"""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM checkpoints WHERE session_id=? ORDER BY created_at DESC LIMIT 1",
                (session_id,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["state"] = json.loads(d.get("state", "{}"))
            return d
        finally:
            conn.close()

    def list_checkpoints(self, session_id: str = "") -> List[Dict[str, Any]]:
        """列出检查点"""
        conn = self._get_conn()
        try:
            if session_id:
                rows = conn.execute(
                    "SELECT checkpoint_id, session_id, phase, description, created_at "
                    "FROM checkpoints WHERE session_id=? ORDER BY created_at DESC",
                    (session_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT checkpoint_id, session_id, phase, description, created_at "
                    "FROM checkpoints ORDER BY created_at DESC LIMIT 50"
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """删除检查点"""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "DELETE FROM checkpoints WHERE checkpoint_id=?", (checkpoint_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()
