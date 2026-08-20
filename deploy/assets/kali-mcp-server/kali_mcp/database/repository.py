#!/usr/bin/env python3
"""
数据仓库模块

提供SQLite数据持久化:
- 扫描结果存储
- 漏洞记录
- 会话历史
"""

import json
import sqlite3
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class ScanRecord:
    """扫描记录"""
    id: Optional[int]
    target: str
    tool_name: str
    timestamp: str
    success: bool
    summary: str
    findings_count: int
    raw_output: str
    findings_json: str
    execution_time: float


@dataclass
class VulnRecord:
    """漏洞记录"""
    id: Optional[int]
    target: str
    vuln_type: str
    severity: str
    description: str
    evidence: str
    discovered_at: str
    tool_name: str
    cve_id: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class SessionRecord:
    """会话记录"""
    id: Optional[int]
    session_id: str
    target: str
    mode: str
    start_time: str
    end_time: Optional[str]
    status: str
    tools_used: str
    findings_count: int
    flags_found: str


class BaseRepository:
    """基础仓库类"""

    def __init__(self, db_path: Optional[str] = None):
        """
        初始化

        Args:
            db_path: 数据库路径
        """
        if db_path is None:
            db_dir = Path.home() / ".kali_mcp" / "data"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "kali_mcp.db")

        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_db(self):
        """初始化数据库表"""
        raise NotImplementedError


class ScanRepository(BaseRepository):
    """扫描结果仓库"""

    def _init_db(self):
        """初始化扫描结果表"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    summary TEXT,
                    findings_count INTEGER DEFAULT 0,
                    raw_output TEXT,
                    findings_json TEXT,
                    execution_time REAL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool_name)
            """)
        logger.info("扫描结果表初始化完成")

    def save(self, record: ScanRecord) -> int:
        """
        保存扫描记录

        Args:
            record: 扫描记录

        Returns:
            记录ID
        """
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scans (
                    target, tool_name, timestamp, success, summary,
                    findings_count, raw_output, findings_json, execution_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.target, record.tool_name, record.timestamp,
                1 if record.success else 0, record.summary,
                record.findings_count, record.raw_output,
                record.findings_json, record.execution_time
            ))
            return cursor.lastrowid

    def find_by_target(
        self,
        target: str,
        limit: int = 100
    ) -> List[ScanRecord]:
        """查询目标的扫描记录"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scans WHERE target = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (target, limit))

            return [self._row_to_record(row) for row in cursor.fetchall()]

    def find_by_tool(
        self,
        tool_name: str,
        limit: int = 100
    ) -> List[ScanRecord]:
        """查询工具的扫描记录"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scans WHERE tool_name = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (tool_name, limit))

            return [self._row_to_record(row) for row in cursor.fetchall()]

    def get_recent(self, limit: int = 50) -> List[ScanRecord]:
        """获取最近的扫描记录"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?
            """, (limit,))

            return [self._row_to_record(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._get_connection() as conn:
            # 总数
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

            # 成功率
            success = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE success = 1"
            ).fetchone()[0]

            # 按工具统计
            tool_stats = conn.execute("""
                SELECT tool_name, COUNT(*) as count
                FROM scans GROUP BY tool_name
                ORDER BY count DESC LIMIT 10
            """).fetchall()

            return {
                "total_scans": total,
                "successful_scans": success,
                "success_rate": success / total if total > 0 else 0,
                "tool_stats": {row["tool_name"]: row["count"] for row in tool_stats}
            }

    def _row_to_record(self, row: sqlite3.Row) -> ScanRecord:
        """将行转换为记录"""
        return ScanRecord(
            id=row["id"],
            target=row["target"],
            tool_name=row["tool_name"],
            timestamp=row["timestamp"],
            success=bool(row["success"]),
            summary=row["summary"],
            findings_count=row["findings_count"],
            raw_output=row["raw_output"],
            findings_json=row["findings_json"],
            execution_time=row["execution_time"]
        )


class VulnRepository(BaseRepository):
    """漏洞记录仓库"""

    def _init_db(self):
        """初始化漏洞表"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    discovered_at TEXT NOT NULL,
                    tool_name TEXT,
                    cve_id TEXT,
                    remediation TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_vuln_target ON vulnerabilities(target)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)
            """)
        logger.info("漏洞表初始化完成")

    def save(self, record: VulnRecord) -> int:
        """保存漏洞记录"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO vulnerabilities (
                    target, vuln_type, severity, description, evidence,
                    discovered_at, tool_name, cve_id, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.target, record.vuln_type, record.severity,
                record.description, record.evidence, record.discovered_at,
                record.tool_name, record.cve_id, record.remediation
            ))
            return cursor.lastrowid

    def find_by_target(self, target: str) -> List[VulnRecord]:
        """查询目标的漏洞"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM vulnerabilities WHERE target = ?
                ORDER BY discovered_at DESC
            """, (target,))

            return [self._row_to_record(row) for row in cursor.fetchall()]

    def find_by_severity(self, severity: str) -> List[VulnRecord]:
        """按严重程度查询"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM vulnerabilities WHERE severity = ?
                ORDER BY discovered_at DESC
            """, (severity,))

            return [self._row_to_record(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """获取漏洞统计"""
        with self._get_connection() as conn:
            # 按严重程度统计
            severity_stats = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities GROUP BY severity
            """).fetchall()

            # 按类型统计
            type_stats = conn.execute("""
                SELECT vuln_type, COUNT(*) as count
                FROM vulnerabilities GROUP BY vuln_type
                ORDER BY count DESC LIMIT 10
            """).fetchall()

            return {
                "by_severity": {row["severity"]: row["count"] for row in severity_stats},
                "by_type": {row["vuln_type"]: row["count"] for row in type_stats},
                "total": sum(row["count"] for row in severity_stats)
            }

    def _row_to_record(self, row: sqlite3.Row) -> VulnRecord:
        """将行转换为记录"""
        return VulnRecord(
            id=row["id"],
            target=row["target"],
            vuln_type=row["vuln_type"],
            severity=row["severity"],
            description=row["description"],
            evidence=row["evidence"],
            discovered_at=row["discovered_at"],
            tool_name=row["tool_name"],
            cve_id=row["cve_id"],
            remediation=row["remediation"]
        )


class SessionRepository(BaseRepository):
    """会话记录仓库"""

    def _init_db(self):
        """初始化会话表"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL,
                    tools_used TEXT,
                    findings_count INTEGER DEFAULT 0,
                    flags_found TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_id ON sessions(session_id)
            """)
        logger.info("会话表初始化完成")

    def save(self, record: SessionRecord) -> int:
        """保存会话记录"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO sessions (
                    session_id, target, mode, start_time, end_time,
                    status, tools_used, findings_count, flags_found
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.session_id, record.target, record.mode,
                record.start_time, record.end_time, record.status,
                record.tools_used, record.findings_count, record.flags_found
            ))
            return cursor.lastrowid

    def find_by_id(self, session_id: str) -> Optional[SessionRecord]:
        """查询会话"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM sessions WHERE session_id = ?
            """, (session_id,))

            row = cursor.fetchone()
            if row:
                return self._row_to_record(row)
            return None

    def get_recent(self, limit: int = 20) -> List[SessionRecord]:
        """获取最近的会话"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?
            """, (limit,))

            return [self._row_to_record(row) for row in cursor.fetchall()]

    def update_status(
        self,
        session_id: str,
        status: str,
        end_time: Optional[str] = None
    ):
        """更新会话状态"""
        with self._get_connection() as conn:
            if end_time:
                conn.execute("""
                    UPDATE sessions SET status = ?, end_time = ?
                    WHERE session_id = ?
                """, (status, end_time, session_id))
            else:
                conn.execute("""
                    UPDATE sessions SET status = ? WHERE session_id = ?
                """, (status, session_id))

    def _row_to_record(self, row: sqlite3.Row) -> SessionRecord:
        """将行转换为记录"""
        return SessionRecord(
            id=row["id"],
            session_id=row["session_id"],
            target=row["target"],
            mode=row["mode"],
            start_time=row["start_time"],
            end_time=row["end_time"],
            status=row["status"],
            tools_used=row["tools_used"],
            findings_count=row["findings_count"],
            flags_found=row["flags_found"]
        )


# 全局实例
_scan_repo: Optional[ScanRepository] = None
_vuln_repo: Optional[VulnRepository] = None
_session_repo: Optional[SessionRepository] = None


def get_scan_repository() -> ScanRepository:
    """获取扫描仓库"""
    global _scan_repo
    if _scan_repo is None:
        _scan_repo = ScanRepository()
    return _scan_repo


def get_vuln_repository() -> VulnRepository:
    """获取漏洞仓库"""
    global _vuln_repo
    if _vuln_repo is None:
        _vuln_repo = VulnRepository()
    return _vuln_repo


def get_session_repository() -> SessionRepository:
    """获取会话仓库"""
    global _session_repo
    if _session_repo is None:
        _session_repo = SessionRepository()
    return _session_repo
