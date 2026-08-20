#!/usr/bin/env python3
"""
攻击链管理器 (v5.0)

核心功能:
- 攻击链生命周期管理 (draft  analyzing  confirmed  executed)
- SQLite持久化存储
- 攻击链可行性评估
- 步骤管理
"""

import json
import sqlite3
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from kali_mcp.core.chain_models import AttackChain, ChainStep

logger = logging.getLogger(__name__)


_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS chains (
    chain_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    steps TEXT DEFAULT '[]',
    fragments TEXT DEFAULT '[]',
    vulns TEXT DEFAULT '[]',
    feasibility_score INTEGER DEFAULT 0,
    impact_level TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'draft',
    created_at TEXT
)
"""


class ChainManager:
    """攻击链管理器"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path.home() / ".kali_mcp" / "chains.db")
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
        logger.info(f"ChainManager 数据库初始化完成: {self.db_path}")

    def _row_to_chain(self, row: sqlite3.Row) -> AttackChain:
        d = dict(row)
        steps_raw = json.loads(d.pop("steps", "[]"))
        d["fragments"] = json.loads(d.get("fragments", "[]"))
        d["vulns"] = json.loads(d.get("vulns", "[]"))
        chain = AttackChain.from_dict(d)
        chain.steps = [ChainStep.from_dict(s) if isinstance(s, dict) else s for s in steps_raw]
        return chain

    # ==================== 创建和查询 ====================

    def create_chain(self, chain: AttackChain) -> str:
        """创建攻击链，返回chain_id"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO chains (chain_id, title, description, steps,
                       fragments, vulns, feasibility_score, impact_level, status, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (chain.chain_id, chain.title, chain.description,
                     json.dumps([s.to_dict() for s in chain.steps]),
                     json.dumps(chain.fragments), json.dumps(chain.vulns),
                     chain.feasibility_score, chain.impact_level,
                     chain.status, chain.created_at))
                conn.commit()
                logger.info(f"攻击链已创建: {chain.chain_id} {chain.title}")
                return chain.chain_id
            finally:
                conn.close()

    def get_by_id(self, chain_id: str) -> Optional[AttackChain]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM chains WHERE chain_id=?", (chain_id,)).fetchone()
            return self._row_to_chain(row) if row else None
        finally:
            conn.close()

    def get_all(self, status: str = "") -> List[AttackChain]:
        conn = self._get_conn()
        try:
            if status:
                rows = conn.execute("SELECT * FROM chains WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM chains ORDER BY created_at DESC").fetchall()
            return [self._row_to_chain(r) for r in rows]
        finally:
            conn.close()

    # ==================== 步骤管理 ====================

    def add_step(self, chain_id: str, step: ChainStep) -> bool:
        """向攻击链添加步骤"""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT steps FROM chains WHERE chain_id=?", (chain_id,)).fetchone()
                if not row:
                    return False
                steps = json.loads(row["steps"])
                step.order = len(steps) + 1
                steps.append(step.to_dict())
                conn.execute("UPDATE chains SET steps=? WHERE chain_id=?", (json.dumps(steps), chain_id))
                conn.commit()
                logger.info(f"攻击链步骤添加: {chain_id} step#{step.order} {step.title}")
                return True
            finally:
                conn.close()

    # ==================== 状态管理 ====================

    def update_status(self, chain_id: str, new_status: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute("UPDATE chains SET status=? WHERE chain_id=?", (new_status, chain_id))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ==================== 可行性评估 ====================

    def analyze_feasibility(self, chain_id: str) -> Dict[str, Any]:
        """评估攻击链可行性 (0-100分)"""
        chain = self.get_by_id(chain_id)
        if not chain:
            return {"score": 0, "reason": "攻击链不存在"}

        score = 0
        reasons = []

        # 步骤完整性 (最多40分)
        if chain.steps:
            step_score = min(40, len(chain.steps) * 10)
            score += step_score
            reasons.append(f"步骤完整性: {step_score}/40 ({len(chain.steps)}个步骤)")
        else:
            reasons.append("步骤完整性: 0/40 (无步骤)")

        # 碎片/漏洞支撑 (最多30分)
        evidence_count = len(chain.fragments) + len(chain.vulns)
        evidence_score = min(30, evidence_count * 10)
        score += evidence_score
        reasons.append(f"证据支撑: {evidence_score}/30 ({evidence_count}个关联)")

        # 步骤连贯性 (最多30分) - 检查前置条件
        if len(chain.steps) >= 2:
            has_preconditions = sum(1 for s in chain.steps if s.precondition)
            coherence = min(30, int(has_preconditions / len(chain.steps) * 30))
            score += coherence
            reasons.append(f"步骤连贯性: {coherence}/30")
        elif len(chain.steps) == 1:
            score += 15
            reasons.append("步骤连贯性: 15/30 (单步骤)")

        # 更新分数
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("UPDATE chains SET feasibility_score=? WHERE chain_id=?", (score, chain_id))
                conn.commit()
            finally:
                conn.close()

        return {
            "chain_id": chain_id,
            "score": score,
            "reasons": reasons,
            "recommendation": "可执行" if score >= 60 else "需要更多信息" if score >= 30 else "不建议执行",
        }

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM chains").fetchone()[0]
            by_status = {}
            for row in conn.execute("SELECT status, COUNT(*) as cnt FROM chains GROUP BY status"):
                by_status[row["status"]] = row["cnt"]
            return {
                "total": total,
                "by_status": by_status,
                "draft": by_status.get("draft", 0),
                "confirmed": by_status.get("confirmed", 0),
                "executed": by_status.get("executed", 0),
            }
        finally:
            conn.close()
