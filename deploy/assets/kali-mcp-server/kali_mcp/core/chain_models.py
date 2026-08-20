#!/usr/bin/env python3
"""
攻击链数据模型 (v5.0)

定义攻击链管理系统的核心数据结构:
- ChainStep: 攻击链步骤
- AttackChain: 攻击链
"""

import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum


class ChainStatus(Enum):
    """攻击链状态"""
    DRAFT = "draft"               # 草稿
    ANALYZING = "analyzing"       # 分析中
    CONFIRMED = "confirmed"       # 已确认可行
    EXECUTED = "executed"         # 已执行
    FAILED = "failed"             # 执行失败


@dataclass
class ChainStep:
    """攻击链步骤"""
    order: int = 0
    title: str = ""
    description: str = ""
    precondition: str = ""        # 前置条件
    action: str = ""              # 执行动作
    expected_result: str = ""     # 预期结果
    tool_used: str = ""           # 使用的工具
    fragment_id: Optional[str] = None  # 关联碎片
    vuln_id: Optional[str] = None     # 关联漏洞

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChainStep":
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str = field(default_factory=lambda: f"CHAIN-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    steps: List[ChainStep] = field(default_factory=list)
    fragments: List[str] = field(default_factory=list)    # 关联碎片ID列表
    vulns: List[str] = field(default_factory=list)        # 关联漏洞ID列表
    feasibility_score: int = 0    # 0-100
    impact_level: str = "medium"  # critical/high/medium/low
    status: str = "draft"         # draft/analyzing/confirmed/executed/failed
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["steps"] = [s.to_dict() if isinstance(s, ChainStep) else s for s in self.steps]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackChain":
        steps_data = data.pop("steps", [])
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        chain = cls(**filtered)
        chain.steps = [ChainStep.from_dict(s) if isinstance(s, dict) else s for s in steps_data]
        return chain

    @property
    def impact_order(self) -> int:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return order.get(self.impact_level, 0)
