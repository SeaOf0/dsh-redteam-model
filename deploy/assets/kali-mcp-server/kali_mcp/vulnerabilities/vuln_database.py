"""
漏洞数据库 - 0day/1day/nday漏洞管理系统

支持：
- 2023-2025年高危漏洞库
- 快速查询和匹配
- 与推理引擎集成
- 利用方法自动推荐
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
from datetime import date, datetime, timedelta
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class VulnCategory(Enum):
    """漏洞分类"""
    ZERO_DAY = "0day"   # 未公开或刚公开的漏洞（0-30天）
    ONE_DAY = "1day"    # 最近公开，已有利用（30-90天）
    N_DAY = "nday"      # 已公开较长时间（>90天）


class VulnSeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = "CRITICAL"  # 9.0-10.0
    HIGH = "HIGH"         # 7.0-8.9
    MEDIUM = "MEDIUM"     # 4.0-6.9
    LOW = "LOW"           # 0.1-3.9


class VulnType(Enum):
    """漏洞类型"""
    RCE = "RCE"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    CSRF = "CSRF"
    SSRF = "SSRF"
    FILE_INCLUSION = "File Inclusion"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    AUTHENTICATION_BYPASS = "Authentication Bypass"
    DESERIALIZATION = "Deserialization"
    BUFFER_OVERFLOW = "Buffer Overflow"
    CODE_EXECUTION = "Code Execution"
    INFO_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    OPEN_REDIRECT = "Open Redirect"
    HTTP_REQUEST_SMUGGLING = "HTTP Request Smuggling"


@dataclass
class Vulnerability:
    """
    漏洞数据类
    """
    cve_id: str
    name: str
    category: VulnCategory
    publish_date: date
    cvss_score: float
    severity: VulnSeverity
    affected_products: List[str]
    vuln_types: List[VulnType]
    description: str
    exploit_available: bool
    exploit_method: Optional[str] = None
    required_tools: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    poc_available: bool = False
    patch_available: bool = False
    detection_methods: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "category": self.category.value,
            "publish_date": self.publish_date.isoformat(),
            "cvss_score": self.cvss_score,
            "severity": self.severity.value,
            "affected_products": self.affected_products,
            "vuln_types": [v.value for v in self.vuln_types],
            "description": self.description,
            "exploit_available": self.exploit_available,
            "exploit_method": self.exploit_method,
            "required_tools": self.required_tools,
            "affected_versions": self.affected_versions,
            "references": self.references,
            "tags": self.tags,
            "poc_available": self.poc_available,
            "patch_available": self.patch_available,
            "detection_methods": self.detection_methods,
            "mitre_technique": self.mitre_technique
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Vulnerability':
        """从字典创建"""
        return cls(
            cve_id=data["cve_id"],
            name=data["name"],
            category=VulnCategory(data["category"]),
            publish_date=datetime.fromisoformat(data["publish_date"]).date(),
            cvss_score=data["cvss_score"],
            severity=VulnSeverity(data["severity"]),
            affected_products=data["affected_products"],
            vuln_types=[VulnType(v) for v in data["vuln_types"]],
            description=data["description"],
            exploit_available=data["exploit_available"],
            exploit_method=data.get("exploit_method"),
            required_tools=data.get("required_tools", []),
            affected_versions=data.get("affected_versions", []),
            references=data.get("references", []),
            tags=data.get("tags", []),
            poc_available=data.get("poc_available", False),
            patch_available=data.get("patch_available", False),
            detection_methods=data.get("detection_methods", []),
            mitre_technique=data.get("mitre_technique")
        )

    def matches_product(self, product_name: str) -> bool:
        """检查是否匹配产品"""
        product_lower = product_name.lower()
        return any(
            product_lower in prod.lower() or prod.lower() in product_lower
            for prod in self.affected_products
        )

    def matches_version(self, version: str) -> bool:
        """检查是否匹配版本"""
        if not self.affected_versions:
            return True  # 没有版本限制，认为匹配

        # 简化版本匹配（实际应该更复杂）
        version_lower = version.lower()
        return any(
            version_lower in affected.lower() or affected.lower() in version_lower
            for affected in self.affected_versions
        )


class VulnerabilityDatabase:
    """
    漏洞数据库

    提供：
    1. 快速查询和匹配
    2. 按产品/严重程度/时间过滤
    3. 与推理引擎集成
    4. 利用方法推荐
    """

    def __init__(self):
        """初始化数据库"""
        self.vulnerabilities: List[Vulnerability] = []
        self.product_index: Dict[str, Set[int]] = {}  # 产品到漏洞索引
        self.severity_index: Dict[VulnSeverity, Set[int]] = {}  # 严重程度索引
        self.cve_index: Dict[str, int] = {}  # CVE ID到索引

        # 统计信息
        self.stats = {
            "total": 0,
            "zero_day": 0,
            "one_day": 0,
            "n_day": 0,
            "critical": 0,
            "high": 0,
            "with_exploit": 0
        }

    def add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞"""
        idx = len(self.vulnerabilities)
        self.vulnerabilities.append(vuln)

        # 更新索引
        for product in vuln.affected_products:
            if product not in self.product_index:
                self.product_index[product] = set()
            self.product_index[product].add(idx)

        if vuln.severity not in self.severity_index:
            self.severity_index[vuln.severity] = set()
        self.severity_index[vuln.severity].add(idx)

        self.cve_index[vuln.cve_id] = idx

        # 更新统计
        self._update_stats()

    def _update_stats(self):
        """更新统计信息"""
        self.stats["total"] = len(self.vulnerabilities)
        self.stats["zero_day"] = sum(1 for v in self.vulnerabilities if v.category == VulnCategory.ZERO_DAY)
        self.stats["one_day"] = sum(1 for v in self.vulnerabilities if v.category == VulnCategory.ONE_DAY)
        self.stats["n_day"] = sum(1 for v in self.vulnerabilities if v.category == VulnCategory.N_DAY)
        self.stats["critical"] = sum(1 for v in self.vulnerabilities if v.severity == VulnSeverity.CRITICAL)
        self.stats["high"] = sum(1 for v in self.vulnerabilities if v.severity == VulnSeverity.HIGH)
        self.stats["with_exploit"] = sum(1 for v in self.vulnerabilities if v.exploit_available)

    def search_by_product(self, product_name: str) -> List[Vulnerability]:
        """按产品搜索漏洞"""
        results = []
        product_lower = product_name.lower()

        # 直接匹配
        if product_lower in self.product_index:
            for idx in self.product_index[product_lower]:
                results.append(self.vulnerabilities[idx])

        # 部分匹配
        for product, indices in self.product_index.items():
            if product_lower in product.lower() and product != product_lower:
                for idx in indices:
                    if self.vulnerabilities[idx] not in results:
                        results.append(self.vulnerabilities[idx])

        # 按CVSS评分排序
        results.sort(key=lambda v: v.cvss_score, reverse=True)
        return results

    def search_by_severity(self, min_severity: VulnSeverity = VulnSeverity.HIGH) -> List[Vulnerability]:
        """按严重程度搜索"""
        severity_order = [VulnSeverity.CRITICAL, VulnSeverity.HIGH, VulnSeverity.MEDIUM, VulnSeverity.LOW]
        min_idx = severity_order.index(min_severity)

        results = []
        for severity in severity_order[:min_idx + 1]:
            if severity in self.severity_index:
                for idx in self.severity_index[severity]:
                    results.append(self.vulnerabilities[idx])

        return results

    def search_recent(self, days: int = 90) -> List[Vulnerability]:
        """搜索最近的漏洞"""
        cutoff_date = date.today() - timedelta(days=days)
        return [
            v for v in self.vulnerabilities
            if v.publish_date >= cutoff_date
        ]

    def search_by_cve(self, cve_id: str) -> Optional[Vulnerability]:
        """按CVE ID搜索"""
        if cve_id in self.cve_index:
            return self.vulnerabilities[self.cve_index[cve_id]]
        return None

    def search_exploitable(self, product_name: str = None, min_cvss: float = 7.0) -> List[Vulnerability]:
        """搜索可利用的漏洞"""
        results = []

        for vuln in self.vulnerabilities:
            if not vuln.exploit_available:
                continue

            if vuln.cvss_score < min_cvss:
                continue

            if product_name and not vuln.matches_product(product_name):
                continue

            results.append(vuln)

        results.sort(key=lambda v: v.cvss_score, reverse=True)
        return results

    def get_exploit_recommendation(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        获取漏洞利用推荐

        Args:
            target_info: 目标信息 {"product": "...", "version": "...", "service": "..."}

        Returns:
            推荐列表 [{"vuln": Vulnerability, "reason": "...", "tools": [...]}]
        """
        recommendations = []
        product = target_info.get("product", "")
        version = target_info.get("version", "")
        service = target_info.get("service", "")

        # 搜索相关漏洞
        if product:
            vulns = self.search_by_product(product)
        elif service:
            vulns = self.search_by_product(service)
        else:
            return []

        # 过滤和排序
        for vuln in vulns:
            if not vuln.exploit_available:
                continue

            if vuln.cvss_score < 7.0:
                continue

            # 生成推荐理由
            reasons = []
            reasons.append(f"CVSS {vuln.cvss_score} - {vuln.severity.value}")
            if vuln.poc_available:
                reasons.append("有公开POC")
            if vuln.category == VulnCategory.ZERO_DAY:
                reasons.append("0day漏洞")
            elif vuln.category == VulnCategory.ONE_DAY:
                reasons.append("1day漏洞")

            # 匹配检测方法
            detection_methods = []
            if product:
                detection_methods.extend(vuln.detection_methods)

            recommendations.append({
                "vuln": vuln,
                "reason": ", ".join(reasons),
                "tools": vuln.required_tools,
                "detection": detection_methods,
                "confidence": self._calculate_confidence(vuln, target_info)
            })

        # 按置信度排序
        recommendations.sort(key=lambda r: r["confidence"], reverse=True)

        return recommendations[:5]  # 返回前5个推荐

    def _calculate_confidence(self, vuln: Vulnerability, target_info: Dict[str, Any]) -> float:
        """计算利用置信度"""
        confidence = 0.5

        # CVSS越高置信度越高
        confidence += (vuln.cvss_score / 10.0) * 0.3

        # 有POC增加置信度
        if vuln.poc_available:
            confidence += 0.2

        # 0day/1day增加置信度
        if vuln.category == VulnCategory.ZERO_DAY:
            confidence += 0.2
        elif vuln.category == VulnCategory.ONE_DAY:
            confidence += 0.1

        # 有详细利用方法增加置信度
        if vuln.exploit_method:
            confidence += 0.1

        return min(confidence, 1.0)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            "products_count": len(self.product_index),
            "avg_cvss": sum(v.cvss_score for v in self.vulnerabilities) / len(self.vulnerabilities) if self.vulnerabilities else 0
        }

    def export_json(self, filepath: str):
        """导出为JSON"""
        data = [v.to_dict() for v in self.vulnerabilities]
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def import_json(self, filepath: str):
        """从JSON导入"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for item in data:
            vuln = Vulnerability.from_dict(item)
            self.add_vulnerability(vuln)


# 全局数据库实例
_vuln_db: Optional[VulnerabilityDatabase] = None


def get_vulnerability_database() -> VulnerabilityDatabase:
    """获取全局漏洞数据库实例"""
    global _vuln_db
    if _vuln_db is None:
        _vuln_db = VulnerabilityDatabase()
        # 自动加载漏洞数据
        _load_vulnerabilities()
    return _vuln_db


def _load_vulnerabilities():
    """加载所有漏洞数据"""
    from . import zero_day_vulns, one_day_vulns, nday_vulns

    db = get_vulnerability_database()

    # 加载0day
    for vuln in zero_day_vulns.get_vulnerabilities():
        db.add_vulnerability(vuln)

    # 加载1day
    for vuln in one_day_vulns.get_vulnerabilities():
        db.add_vulnerability(vuln)

    # 加载nday
    for vuln in nday_vulns.get_vulnerabilities():
        db.add_vulnerability(vuln)

    logger.info(f"[漏洞数据库] 加载完成，共 {db.stats['total']} 个漏洞")
