#!/usr/bin/env python3
"""
碎片管理器 (v5.0)

核心功能:
- 碎片生命周期管理 (discovered  analyzing  confirmed  chained)
- SQLite持久化存储
- 碎片关联机制 (relate_fragments)
- 统计和查询
"""

import json
import sqlite3
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from kali_mcp.core.fragment_models import Fragment

logger = logging.getLogger(__name__)


_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS fragments (
    fragment_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    fragment_type TEXT DEFAULT 'other',
    description TEXT DEFAULT '',
    target TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    status TEXT DEFAULT 'discovered',
    severity TEXT DEFAULT 'info',
    related_fragments TEXT DEFAULT '[]',
    discovered_by TEXT DEFAULT '',
    discovered_at TEXT,
    tags TEXT DEFAULT '[]'
)
"""


class FragmentManager:
    """碎片管理器 - 结构化碎片生命周期管理"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path.home() / ".kali_mcp" / "fragments.db")
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
            conn.execute(_CREATE_TABLE_SQL)
            conn.commit()
        logger.info(f"FragmentManager 数据库初始化完成: {self.db_path}")

    def _row_to_fragment(self, row: sqlite3.Row) -> Fragment:
        d = dict(row)
        d["related_fragments"] = json.loads(d.get("related_fragments", "[]"))
        d["tags"] = json.loads(d.get("tags", "[]"))
        return Fragment.from_dict(d)

    # ==================== 碎片提交 ====================

    def create_fragment(self, frag: Fragment) -> str:
        """提交碎片，返回fragment_id"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO fragments (fragment_id, title, fragment_type,
                       description, target, evidence, status, severity,
                       related_fragments, discovered_by, discovered_at, tags)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (frag.fragment_id, frag.title, frag.fragment_type,
                     frag.description, frag.target, frag.evidence,
                     frag.status, frag.severity,
                     json.dumps(frag.related_fragments),
                     frag.discovered_by, frag.discovered_at,
                     json.dumps(frag.tags)))
                conn.commit()
                logger.info(f"碎片已创建: {frag.fragment_id} [{frag.fragment_type}] {frag.title}")
                return frag.fragment_id
            finally:
                conn.close()

    # ==================== 查询 ====================

    def get_by_id(self, fragment_id: str) -> Optional[Fragment]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM fragments WHERE fragment_id=?", (fragment_id,)).fetchone()
            return self._row_to_fragment(row) if row else None
        finally:
            conn.close()

    def get_all(self, target: str = "", status: str = "") -> List[Fragment]:
        conn = self._get_conn()
        try:
            query = "SELECT * FROM fragments WHERE 1=1"
            params = []
            if target:
                query += " AND target LIKE ?"
                params.append(f"%{target}%")
            if status:
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY discovered_at DESC"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_fragment(r) for r in rows]
        finally:
            conn.close()

    def get_by_type(self, fragment_type: str) -> List[Fragment]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM fragments WHERE fragment_type=?", (fragment_type,)
            ).fetchall()
            return [self._row_to_fragment(r) for r in rows]
        finally:
            conn.close()

    # ==================== 碎片关联 ====================

    def relate_fragments(self, frag_id_a: str, frag_id_b: str) -> bool:
        """建立两个碎片之间的双向关联"""
        with self._lock:
            conn = self._get_conn()
            try:
                for src, dst in [(frag_id_a, frag_id_b), (frag_id_b, frag_id_a)]:
                    row = conn.execute("SELECT related_fragments FROM fragments WHERE fragment_id=?", (src,)).fetchone()
                    if not row:
                        return False
                    related = json.loads(row["related_fragments"])
                    if dst not in related:
                        related.append(dst)
                        conn.execute(
                            "UPDATE fragments SET related_fragments=? WHERE fragment_id=?",
                            (json.dumps(related), src))
                conn.commit()
                logger.info(f"碎片关联: {frag_id_a} <-> {frag_id_b}")
                return True
            finally:
                conn.close()

    def get_related(self, fragment_id: str) -> List[Fragment]:
        """获取关联碎片"""
        frag = self.get_by_id(fragment_id)
        if not frag or not frag.related_fragments:
            return []
        results = []
        for rid in frag.related_fragments:
            r = self.get_by_id(rid)
            if r:
                results.append(r)
        return results

    # ==================== 状态管理 ====================

    def update_status(self, fragment_id: str, new_status: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "UPDATE fragments SET status=? WHERE fragment_id=?",
                    (new_status, fragment_id))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def dismiss(self, fragment_id: str) -> bool:
        return self.update_status(fragment_id, "dismissed")

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM fragments").fetchone()[0]
            by_status = {}
            for row in conn.execute("SELECT status, COUNT(*) as cnt FROM fragments GROUP BY status"):
                by_status[row["status"]] = row["cnt"]
            by_type = {}
            for row in conn.execute("SELECT fragment_type, COUNT(*) as cnt FROM fragments GROUP BY fragment_type ORDER BY cnt DESC LIMIT 10"):
                by_type[row["fragment_type"]] = row["cnt"]
            return {
                "total": total,
                "by_status": by_status,
                "by_type": by_type,
                "discovered": by_status.get("discovered", 0),
                "confirmed": by_status.get("confirmed", 0),
                "chained": by_status.get("chained", 0),
            }
        finally:
            conn.close()
