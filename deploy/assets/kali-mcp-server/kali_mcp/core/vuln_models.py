#!/usr/bin/env python3
"""
漏洞数据模型 (v5.0)

定义漏洞管理系统的核心数据结构:
- VulnRecord: 漏洞记录
- VulnStatus: 漏洞状态枚举
- VulnSeverity: 严重程度枚举
- VulnSource: 发现来源枚举
"""

import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum


class VulnStatus(Enum):
    """漏洞状态"""
    CANDIDATE = "candidate"       # 候选，待验证
    VERIFYING = "verifying"       # 验证中
    VERIFIED = "verified"         # 已验证
    FAILED = "failed"             # 验证失败（误报）
    DISMISSED = "dismissed"       # 已忽略


class VulnSeverity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnSource(Enum):
    """发现来源"""
    BLACKBOX = "blackbox"         # 黑盒扫描发现
    WHITEBOX = "whitebox"         # 白盒代码审计发现
    MANUAL = "manual"             # 手动发现
    CROSS_VALIDATED = "cross_validated"  # 交叉验证确认


class VulnConfidence(Enum):
    """置信度"""
    VERY_HIGH = "very_high"       # 交叉验证确认
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class VulnRecord:
    """漏洞记录"""
    vuln_id: str = field(default_factory=lambda: f"VULN-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    vuln_type: str = ""               # sqli/xss/rce/lfi/ssrf/idor/deserialization/...
    severity: str = "medium"          # critical/high/medium/low/info
    confidence: str = "medium"        # very_high/high/medium/low
    status: str = "candidate"         # candidate/verifying/verified/failed/dismissed
    source: str = "blackbox"          # blackbox/whitebox/manual/cross_validated
    target: str = ""                  # 目标URL/IP
    endpoint: str = ""                # 受影响端点
    params: str = ""                  # 受影响参数
    payload: str = ""                 # 利用载荷
    evidence: str = ""                # 证据
    cvss_score: float = 0.0           # CVSS评分
    discovered_by: str = ""           # 发现的Agent/工具
    verified_by: Optional[str] = None # 验证的Agent/工具
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    verified_at: Optional[str] = None
    related_fragments: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnRecord":
        """从字典创建"""
        # 过滤掉不属于dataclass字段的键
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    @property
    def severity_order(self) -> int:
        """严重程度排序值 (越高越严重)"""
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return order.get(self.severity, 0)

