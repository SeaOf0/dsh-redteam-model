#!/usr/bin/env python3
"""
碎片数据模型 (v5.0)

定义碎片管理系统的核心数据结构:
- Fragment: 碎片记录 (信息泄露/弱配置/部分认证等)
- FragmentStatus: 碎片状态枚举
- FragmentType: 碎片类型枚举
"""

import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum


class FragmentStatus(Enum):
    """碎片状态"""
    DISCOVERED = "discovered"     # 已发现
    ANALYZING = "analyzing"       # 分析中
    CONFIRMED = "confirmed"       # 已确认
    CHAINED = "chained"           # 已纳入攻击链
    DISMISSED = "dismissed"       # 已忽略


class FragmentType(Enum):
    """碎片类型"""
    INFO_LEAK = "info_leak"               # 信息泄露
    WEAK_CONFIG = "weak_config"           # 弱配置
    AUTH_PARTIAL = "auth_partial"         # 部分认证信息
    PATH_DISCLOSURE = "path_disclosure"   # 路径泄露
    VERSION_LEAK = "version_leak"         # 版本信息泄露
    CREDENTIAL_HINT = "credential_hint"   # 凭据线索
    DEBUG_INFO = "debug_info"             # 调试信息
    BACKUP_FILE = "backup_file"           # 备份文件
    SOURCE_LEAK = "source_leak"           # 源码泄露
    ENDPOINT_FOUND = "endpoint_found"     # 端点发现
    TECH_STACK = "tech_stack"             # 技术栈识别
    OTHER = "other"                       # 其他


@dataclass
class Fragment:
    """碎片记录"""
    fragment_id: str = field(default_factory=lambda: f"FRAG-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    fragment_type: str = "other"          # info_leak/weak_config/auth_partial/...
    description: str = ""
    target: str = ""
    evidence: str = ""
    status: str = "discovered"            # discovered/analyzing/confirmed/chained/dismissed
    severity: str = "info"                # high/medium/low/info
    related_fragments: List[str] = field(default_factory=list)
    discovered_by: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Fragment":
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    @property
    def severity_order(self) -> int:
        order = {"high": 4, "medium": 3, "low": 2, "info": 1}
        return order.get(self.severity, 0)
