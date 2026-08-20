#!/usr/bin/env python3
"""
漏洞管理器 (v5.0)

核心功能:
- 漏洞生命周期管理 (candidate  verifying  verified/failed)
- SQLite持久化存储
- 黑盒+白盒交叉验证
- 统计和报告导出
"""

import json
import sqlite3
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from kali_mcp.core.vuln_models import VulnRecord, VulnStatus, VulnSeverity

logger = logging.getLogger(__name__)


_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vulns (
    vuln_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    confidence TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'candidate',
    source TEXT DEFAULT 'blackbox',
    target TEXT,
    endpoint TEXT,
    params TEXT,
    payload TEXT,
    evidence TEXT,
    cvss_score REAL DEFAULT 0.0,
    discovered_by TEXT,
    verified_by TEXT,
    discovered_at TEXT,
    verified_at TEXT,
    related_fragments TEXT DEFAULT '[]',
    tags TEXT DEFAULT '[]'
)
"""


class VulnManager:
    """漏洞管理器 - 结构化漏洞生命周期管理"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path.home() / ".kali_mcp" / "vulns.db")
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
        logger.info(f"VulnManager 数据库初始化完成: {self.db_path}")

    def _row_to_record(self, row: sqlite3.Row) -> VulnRecord:
        d = dict(row)
        d["related_fragments"] = json.loads(d.get("related_fragments", "[]"))
        d["tags"] = json.loads(d.get("tags", "[]"))
        return VulnRecord.from_dict(d)

    # ==================== 漏洞提交 ====================

    def issue_vuln(self, vuln: VulnRecord) -> str:
        """提交候选漏洞，返回vuln_id"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO vulns (vuln_id, title, vuln_type, severity,
                       confidence, status, source, target, endpoint, params,
                       payload, evidence, cvss_score, discovered_by, verified_by,
                       discovered_at, verified_at, related_fragments, tags)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (vuln.vuln_id, vuln.title, vuln.vuln_type, vuln.severity,
                     vuln.confidence, vuln.status, vuln.source, vuln.target,
                     vuln.endpoint, vuln.params, vuln.payload, vuln.evidence,
                     vuln.cvss_score, vuln.discovered_by, vuln.verified_by,
                     vuln.discovered_at, vuln.verified_at,
                     json.dumps(vuln.related_fragments),
                     json.dumps(vuln.tags)))
                conn.commit()
                logger.info(f"漏洞已提交: {vuln.vuln_id} [{vuln.severity}] {vuln.title}")
                return vuln.vuln_id
            finally:
                conn.close()

    # ==================== 查询 ====================

    def get_by_id(self, vuln_id: str) -> Optional[VulnRecord]:
        """按ID获取漏洞"""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM vulns WHERE vuln_id=?", (vuln_id,)).fetchone()
            return self._row_to_record(row) if row else None
        finally:
            conn.close()

    def get_candidates(self) -> List[VulnRecord]:
        """获取所有待验证漏洞"""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM vulns WHERE status='candidate' ORDER BY "
                "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
                "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
            ).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def get_one_candidate(self) -> Optional[VulnRecord]:
        """获取一个优先级最高的待验证漏洞"""
        candidates = self.get_candidates()
        return candidates[0] if candidates else None

    def get_verified(self) -> List[VulnRecord]:
        """获取所有已验证漏洞"""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM vulns WHERE status='verified' ORDER BY cvss_score DESC"
            ).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def get_by_type(self, vuln_type: str) -> List[VulnRecord]:
        """按漏洞类型查询"""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM vulns WHERE vuln_type=?", (vuln_type,)
            ).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def get_by_target(self, target: str) -> List[VulnRecord]:
        """按目标查询"""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM vulns WHERE target LIKE ?", (f"%{target}%",)
            ).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def get_all(self) -> List[VulnRecord]:
        """获取所有漏洞"""
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT * FROM vulns ORDER BY discovered_at DESC").fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    # ==================== 验证流程 ====================

    def start_verification(self, vuln_id: str) -> bool:
        """开始验证漏洞 (candidate  verifying)"""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "UPDATE vulns SET status='verifying' WHERE vuln_id=? AND status='candidate'",
                    (vuln_id,))
                conn.commit()
                ok = cur.rowcount > 0
                if ok:
                    logger.info(f"漏洞验证开始: {vuln_id}")
                return ok
            finally:
                conn.close()

    def submit_result(self, vuln_id: str, verified: bool,
                      evidence: str = "", verified_by: str = "") -> bool:
        """提交验证结果 (verifying  verified/failed)"""
        new_status = "verified" if verified else "failed"
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """UPDATE vulns SET status=?, evidence=CASE WHEN ?='' THEN evidence ELSE ? END,
                       verified_by=?, verified_at=?
                       WHERE vuln_id=? AND status='verifying'""",
                    (new_status, evidence, evidence, verified_by, now, vuln_id))
                conn.commit()
                ok = cur.rowcount > 0
                if ok:
                    logger.info(f"漏洞验证结果: {vuln_id}  {new_status}")
                return ok
            finally:
                conn.close()

    def dismiss(self, vuln_id: str) -> bool:
        """忽略漏洞"""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "UPDATE vulns SET status='dismissed' WHERE vuln_id=?", (vuln_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ==================== 交叉验证 ====================

    def cross_validate(self, blackbox_id: str, whitebox_id: str) -> float:
        """交叉验证: 匹配黑盒和白盒发现，提升置信度"""
        bb = self.get_by_id(blackbox_id)
        wb = self.get_by_id(whitebox_id)
        if not bb or not wb:
            return 0.0

        score = 0.0
        # 同一目标
        if bb.target and wb.target and bb.target in wb.target:
            score += 0.3
        # 同一端点
        if bb.endpoint and wb.endpoint and bb.endpoint == wb.endpoint:
            score += 0.3
        # 同一漏洞类型
        if bb.vuln_type == wb.vuln_type:
            score += 0.4

        if score >= 0.7:
            # 高匹配度，提升两者置信度
            with self._lock:
                conn = self._get_conn()
                try:
                    conn.execute(
                        "UPDATE vulns SET confidence='very_high', source='cross_validated' "
                        "WHERE vuln_id IN (?,?)", (blackbox_id, whitebox_id))
                    conn.commit()
                finally:
                    conn.close()
            logger.info(f"交叉验证匹配: {blackbox_id} + {whitebox_id} = {score:.1f}")

        return score

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取漏洞统计信息"""
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
            by_status = {}
            for row in conn.execute("SELECT status, COUNT(*) as cnt FROM vulns GROUP BY status"):
                by_status[row["status"]] = row["cnt"]
            by_severity = {}
            for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM vulns GROUP BY severity"):
                by_severity[row["severity"]] = row["cnt"]
            by_type = {}
            for row in conn.execute("SELECT vuln_type, COUNT(*) as cnt FROM vulns GROUP BY vuln_type ORDER BY cnt DESC LIMIT 10"):
                by_type[row["vuln_type"]] = row["cnt"]

            return {
                "total": total,
                "by_status": by_status,
                "by_severity": by_severity,
                "by_type": by_type,
                "candidates": by_status.get("candidate", 0),
                "verified": by_status.get("verified", 0),
                "failed": by_status.get("failed", 0),
            }
        finally:
            conn.close()

    # ==================== 报告导出 ====================

    def export_report(self, fmt: str = "json") -> str:
        """导出漏洞报告"""
        vulns = self.get_all()
        stats = self.get_statistics()

        if fmt == "json":
            report = {
                "generated_at": datetime.now().isoformat(),
                "statistics": stats,
                "vulnerabilities": [v.to_dict() for v in vulns]
            }
            return json.dumps(report, indent=2, ensure_ascii=False)

        # markdown格式
        lines = [
            "# 漏洞评估报告",
            f"\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"\n## 统计概览",
            f"- 总计: {stats['total']}",
            f"- 已验证: {stats['verified']}",
            f"- 待验证: {stats['candidates']}",
            f"- 误报: {stats['failed']}",
            "\n## 漏洞详情\n",
        ]
        for v in sorted(vulns, key=lambda x: x.severity_order, reverse=True):
            status_icon = {"verified": "", "candidate": "", "failed": ""}.get(v.status, "")
            lines.append(f"### {status_icon} [{v.severity.upper()}] {v.title}")
            lines.append(f"- ID: `{v.vuln_id}`")
            lines.append(f"- 类型: {v.vuln_type} | 来源: {v.source} | 置信度: {v.confidence}")
            lines.append(f"- 目标: {v.target}")
            if v.endpoint:
                lines.append(f"- 端点: {v.endpoint}")
            if v.payload:
                lines.append(f"- Payload: `{v.payload[:100]}`")
            lines.append("")

        return "\n".join(lines)

