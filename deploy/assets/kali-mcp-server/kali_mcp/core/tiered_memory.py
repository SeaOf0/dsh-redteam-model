#!/usr/bin/env python3
"""
TieredMemory - 分层记忆 (v5.0)

三层记忆架构:
- working_memory: 最近10轮交互，完整保留
- important_memory: 关键发现（漏洞/凭据/路径），最多50条
- summary_memory: 历史操作自动摘要

自动摘要: working_memory超阈值时自动压缩到summary_memory
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """记忆条目"""
    content: str = ""
    source: str = ""              # agent_id或tool_name
    category: str = "interaction"  # interaction/discovery/vuln/credential/path
    importance: str = "normal"     # critical/high/normal/low
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TieredMemory:
    """分层记忆系统"""

    def __init__(self, working_limit: int = 10, important_limit: int = 50,
                 summary_limit: int = 20):
        self.working_memory: List[MemoryEntry] = []
        self.important_memory: List[MemoryEntry] = []
        self.summary_memory: List[str] = []
        self._working_limit = working_limit
        self._important_limit = important_limit
        self._summary_limit = summary_limit
        logger.info("TieredMemory 初始化完成")

    # ==================== Working Memory ====================

    def add_interaction(self, content: str, source: str = "",
                        category: str = "interaction",
                        metadata: Dict[str, Any] = None) -> None:
        """添加交互到工作记忆"""
        entry = MemoryEntry(
            content=content, source=source, category=category,
            metadata=metadata or {},
        )
        self.working_memory.append(entry)

        # 超阈值自动摘要
        if len(self.working_memory) > self._working_limit:
            self.auto_summarize()

    # ==================== Important Memory ====================

    def mark_important(self, content: str, reason: str,
                       source: str = "", category: str = "discovery",
                       importance: str = "high") -> None:
        """标记为重要记忆"""
        entry = MemoryEntry(
            content=content, source=source, category=category,
            importance=importance,
            metadata={"reason": reason},
        )
        self.important_memory.append(entry)

        # 超限裁剪（保留最重要的）
        if len(self.important_memory) > self._important_limit:
            importance_order = {"critical": 4, "high": 3, "normal": 2, "low": 1}
            self.important_memory.sort(
                key=lambda e: importance_order.get(e.importance, 0), reverse=True
            )
            self.important_memory = self.important_memory[:self._important_limit]

    # ==================== Summary Memory ====================

    def auto_summarize(self) -> str:
        """自动摘要：将working_memory压缩为摘要"""
        if not self.working_memory:
            return ""

        # 提取要摘要的条目（保留最近的，摘要较早的）
        to_summarize = self.working_memory[:-3] if len(self.working_memory) > 3 else []
        if not to_summarize:
            return ""

        # 生成摘要
        sources = set(e.source for e in to_summarize if e.source)
        categories = set(e.category for e in to_summarize)
        summary = (
            f"[{to_summarize[0].timestamp[:16]}~{to_summarize[-1].timestamp[:16]}] "
            f"{len(to_summarize)}条交互 "
            f"(来源: {', '.join(sources) if sources else 'unknown'}, "
            f"类型: {', '.join(categories)})"
        )

        self.summary_memory.append(summary)
        if len(self.summary_memory) > self._summary_limit:
            self.summary_memory = self.summary_memory[-self._summary_limit:]

        # 裁剪working_memory，保留最近3条
        self.working_memory = self.working_memory[-3:]

        logger.info(f"TieredMemory 自动摘要: {summary[:80]}")
        return summary

    # ==================== 上下文获取 ====================

    def get_context(self, include_summary: bool = True) -> List[Dict[str, Any]]:
        """获取当前上下文（用于Agent推理）"""
        context = []

        # 1. 摘要记忆（最旧）
        if include_summary and self.summary_memory:
            context.append({
                "layer": "summary",
                "entries": self.summary_memory[-5:],
            })

        # 2. 重要记忆
        if self.important_memory:
            context.append({
                "layer": "important",
                "entries": [e.to_dict() for e in self.important_memory[-10:]],
            })

        # 3. 工作记忆（最新）
        if self.working_memory:
            context.append({
                "layer": "working",
                "entries": [e.to_dict() for e in self.working_memory],
            })

        return context

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "working_count": len(self.working_memory),
            "working_limit": self._working_limit,
            "important_count": len(self.important_memory),
            "important_limit": self._important_limit,
            "summary_count": len(self.summary_memory),
            "summary_limit": self._summary_limit,
        }

    def clear(self) -> None:
        """清空所有记忆"""
        self.working_memory.clear()
        self.important_memory.clear()
        self.summary_memory.clear()
