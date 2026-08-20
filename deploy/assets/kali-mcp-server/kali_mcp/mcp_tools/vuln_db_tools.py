#!/usr/bin/env python3
"""
漏洞数据库MCP工具模块

将0day/1day/nday漏洞库集成到MCP服务器，提供智能漏洞查询和利用推荐功能。
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# 导入漏洞数据库
try:
    from kali_mcp.vulnerabilities import (
        get_vulnerability_database,
        VulnCategory,
        VulnSeverity,
        VulnType
    )
    VULN_DB_AVAILABLE = True
    logger.info(" 漏洞数据库模块加载成功")
except ImportError as e:
    VULN_DB_AVAILABLE = False
    logger.warning(f" 漏洞数据库模块加载失败: {e}")


def register_vulnerability_tools(mcp):
    """
    注册所有漏洞数据库工具到MCP服务器

    提供的工具：
    1. vuln_search_product - 按产品搜索漏洞
    2. vuln_search_severity - 按严重程度搜索漏洞
    3. vuln_search_cve - 按CVE ID查询
    4. vuln_search_exploitable - 搜索可利用漏洞
    5. vuln_recommendation - 获取漏洞利用推荐
    6. vuln_search_recent - 搜索最近漏洞
    7. vuln_get_statistics - 获取数据库统计信息
    8. vuln_intelligent_match - 智能漏洞匹配
    """

    if not VULN_DB_AVAILABLE:
        logger.warning(" 漏洞数据库不可用，跳过工具注册")
        return 0

    registered_count = 0

    @mcp.tool()
    def vuln_search_product(product_name: str) -> Dict[str, Any]:
        """
        按产品搜索漏洞

        快速查找指定产品的所有已知漏洞，按CVSS评分降序排列。

        Args:
            product_name: 产品名称（如 "Apache", "Confluence", "Fortinet"）

        Returns:
            包含漏洞列表的字典，每个漏洞包含CVE ID、名称、CVSS评分、严重程度等信息

        Example:
            vuln_search_product("Apache")
            vuln_search_product("Confluence")
        """
        try:
            db = get_vulnerability_database()
            vulns = db.search_by_product(product_name)

            return {
                "success": True,
                "product": product_name,
                "count": len(vulns),
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "name": v.name,
                        "category": v.category.value,
                        "cvss_score": v.cvss_score,
                        "severity": v.severity.value,
                        "vuln_types": [vt.value for vt in v.vuln_types],
                        "publish_date": v.publish_date.isoformat(),
                        "exploit_available": v.exploit_available,
                        "poc_available": v.poc_available,
                        "affected_products": v.affected_products
                    }
                    for v in vulns
                ]
            }
        except Exception as e:
            logger.error(f"产品搜索失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "product": product_name,
                "count": 0,
                "vulnerabilities": []
            }

    @mcp.tool()
    def vuln_search_severity(min_severity: str = "HIGH") -> Dict[str, Any]:
        """
        按严重程度搜索漏洞

        查找指定严重程度及以上的所有漏洞。

        Args:
            min_severity: 最低严重程度 (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            包含漏洞列表的字典

        Example:
            vuln_search_severity("CRITICAL")
            vuln_search_severity("HIGH")
        """
        try:
            db = get_vulnerability_database()

            # 转换严重程度
            severity_map = {
                "CRITICAL": VulnSeverity.CRITICAL,
                "HIGH": VulnSeverity.HIGH,
                "MEDIUM": VulnSeverity.MEDIUM,
                "LOW": VulnSeverity.LOW
            }

            min_sev = severity_map.get(min_severity.upper(), VulnSeverity.HIGH)
            vulns = db.search_by_severity(min_sev)

            return {
                "success": True,
                "min_severity": min_severity,
                "count": len(vulns),
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "name": v.name,
                        "category": v.category.value,
                        "cvss_score": v.cvss_score,
                        "severity": v.severity.value,
                        "affected_products": v.affected_products,
                        "publish_date": v.publish_date.isoformat()
                    }
                    for v in vulns
                ]
            }
        except Exception as e:
            logger.error(f"严重程度搜索失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "min_severity": min_severity,
                "count": 0,
                "vulnerabilities": []
            }

    @mcp.tool()
    def vuln_search_cve(cve_id: str) -> Dict[str, Any]:
        """
        按CVE ID查询漏洞详细信息

        查询指定CVE ID的完整漏洞信息，包括利用方法、检测方法、所需工具等。

        Args:
            cve_id: CVE标识符 (如 "CVE-2024-3400")

        Returns:
            包含完整漏洞信息的字典

        Example:
            vuln_search_cve("CVE-2024-3400")
            vuln_search_cve("CVE-2023-46604")
        """
        try:
            db = get_vulnerability_database()
            vuln = db.search_by_cve(cve_id)

            if vuln:
                return {
                    "success": True,
                    "found": True,
                    "vulnerability": {
                        "cve_id": vuln.cve_id,
                        "name": vuln.name,
                        "category": vuln.category.value,
                        "cvss_score": vuln.cvss_score,
                        "severity": vuln.severity.value,
                        "publish_date": vuln.publish_date.isoformat(),
                        "affected_products": vuln.affected_products,
                        "affected_versions": vuln.affected_versions,
                        "vuln_types": [vt.value for vt in vuln.vuln_types],
                        "description": vuln.description,
                        "exploit_available": vuln.exploit_available,
                        "exploit_method": vuln.exploit_method,
                        "required_tools": vuln.required_tools,
                        "poc_available": vuln.poc_available,
                        "patch_available": vuln.patch_available,
                        "detection_methods": vuln.detection_methods,
                        "mitre_technique": vuln.mitre_technique,
                        "references": vuln.references,
                        "tags": vuln.tags
                    }
                }
            else:
                return {
                    "success": True,
                    "found": False,
                    "cve_id": cve_id,
                    "message": f"CVE {cve_id} 未在数据库中找到"
                }
        except Exception as e:
            logger.error(f"CVE查询失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "found": False,
                "cve_id": cve_id
            }

    @mcp.tool()
    def vuln_search_exploitable(product_name: str = "", min_cvss: float = 7.0) -> Dict[str, Any]:
        """
        搜索可利用的漏洞

        查找有公开利用方法的漏洞，适合渗透测试快速利用。

        Args:
            product_name: 产品名称（可选，为空则搜索所有产品）
            min_cvss: 最低CVSS评分（默认7.0）

        Returns:
            包含可利用漏洞列表的字典

        Example:
            vuln_search_exploitable("Apache", 8.0)
            vuln_search_exploitable(min_cvss=9.0)
        """
        try:
            db = get_vulnerability_database()
            vulns = db.search_exploitable(product_name if product_name else None, min_cvss)

            return {
                "success": True,
                "product": product_name or "ALL",
                "min_cvss": min_cvss,
                "count": len(vulns),
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "name": v.name,
                        "cvss_score": v.cvss_score,
                        "category": v.category.value,
                        "exploit_method": v.exploit_method,
                        "required_tools": v.required_tools,
                        "poc_available": v.poc_available
                    }
                    for v in vulns
                ]
            }
        except Exception as e:
            logger.error(f"可利用漏洞搜索失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "count": 0,
                "vulnerabilities": []
            }

    @mcp.tool()
    def vuln_recommendation(product: str = "", version: str = "", service: str = "") -> Dict[str, Any]:
        """
        获取漏洞利用推荐

        基于目标信息，智能推荐最适合利用的漏洞，包含置信度评分和工具推荐。

        Args:
            product: 产品名称（如 "Fortinet", "Apache"）
            version: 版本号（如 "7.0"）
            service: 服务名称（如 "SSLVPN", "HTTP"）

        Returns:
            包含推荐漏洞列表的字典，每个推荐包含理由、置信度、所需工具

        Example:
            vuln_recommendation(product="Fortinet", service="SSLVPN")
            vuln_recommendation(product="Apache", version="2.4.49")
        """
        try:
            db = get_vulnerability_database()
            target_info = {
                "product": product,
                "version": version,
                "service": service
            }

            recommendations = db.get_exploit_recommendation(target_info)

            return {
                "success": True,
                "target": target_info,
                "count": len(recommendations),
                "recommendations": [
                    {
                        "cve_id": rec["vuln"].cve_id,
                        "name": rec["vuln"].name,
                        "cvss_score": rec["vuln"].cvss_score,
                        "category": rec["vuln"].category.value,
                        "reason": rec["reason"],
                        "confidence": f"{rec['confidence']:.1%}",
                        "tools": rec["tools"],
                        "detection_methods": rec["detection"]
                    }
                    for rec in recommendations
                ]
            }
        except Exception as e:
            logger.error(f"漏洞推荐失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "target": {"product": product, "version": version, "service": service},
                "count": 0,
                "recommendations": []
            }

    @mcp.tool()
    def vuln_search_recent(days: int = 90) -> Dict[str, Any]:
        """
        搜索最近发布的漏洞

        查找指定天数内发布的漏洞，适合了解最新威胁。

        Args:
            days: 天数（默认90天）

        Returns:
            包含最近漏洞列表的字典

        Example:
            vuln_search_recent(30)
            vuln_search_recent(90)
        """
        try:
            db = get_vulnerability_database()
            vulns = db.search_recent(days)

            return {
                "success": True,
                "days": days,
                "count": len(vulns),
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "name": v.name,
                        "category": v.category.value,
                        "cvss_score": v.cvss_score,
                        "publish_date": v.publish_date.isoformat(),
                        "severity": v.severity.value
                    }
                    for v in vulns
                ]
            }
        except Exception as e:
            logger.error(f"最近漏洞搜索失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "days": days,
                "count": 0,
                "vulnerabilities": []
            }

    @mcp.tool()
    def vuln_get_statistics() -> Dict[str, Any]:
        """
        获取漏洞数据库统计信息

        返回数据库的完整统计信息，包括漏洞总数、分类统计、平均CVSS评分等。

        Returns:
            包含详细统计信息的字典

        Example:
            vuln_get_statistics()
        """
        try:
            db = get_vulnerability_database()
            stats = db.get_statistics()

            return {
                "success": True,
                "statistics": {
                    "total_vulnerabilities": stats["total"],
                    "zero_day_count": stats["zero_day"],
                    "one_day_count": stats["one_day"],
                    "n_day_count": stats["n_day"],
                    "critical_count": stats["critical"],
                    "high_count": stats["high"],
                    "exploitable_count": stats["with_exploit"],
                    "products_count": stats["products_count"],
                    "average_cvss": f"{stats['avg_cvss']:.2f}"
                },
                "last_updated": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"统计信息获取失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "statistics": {}
            }

    @mcp.tool()
    def vuln_intelligent_match(target_info: str) -> Dict[str, Any]:
        """
        智能漏洞匹配

        根据目标信息（从扫描结果中提取），智能匹配最相关的漏洞。
        这是最智能的漏洞查询工具，会综合分析产品、版本、服务等多个维度。

        Args:
            target_info: JSON格式的目标信息
                可包含: product, version, service, open_ports, technology, banner等

        Returns:
            包含匹配漏洞和利用建议的字典

        Example:
            vuln_intelligent_match('{"product": "Apache", "version": "2.4.49", "service": "HTTP"}')
            vuln_intelligent_match('{"banner": "Palo Alto Networks", "open_ports": [443, 6043]}')
        """
        try:
            import json

            db = get_vulnerability_database()
            info = json.loads(target_info)

            # 提取关键信息
            product = info.get("product", "")
            service = info.get("service", "")
            version = info.get("version", "")

            # 获取漏洞推荐
            recommendations = db.get_exploit_recommendation({
                "product": product,
                "version": version,
                "service": service
            })

            # 如果有banner信息，尝试提取产品名
            if not product and "banner" in info:
                banner = info["banner"]
                # 简单的关键词匹配
                for vuln in db.vulnerabilities:
                    if any(keyword.lower() in banner.lower() for keyword in vuln.affected_products):
                        if not any(r["vuln"].cve_id == vuln.cve_id for r in recommendations):
                            recommendations.append({
                                "vuln": vuln,
                                "reason": f"Banner匹配: {banner[:50]}...",
                                "confidence": 0.7,
                                "tools": vuln.required_tools,
                                "detection": vuln.detection_methods
                            })

            # 按置信度排序
            recommendations.sort(key=lambda r: r["confidence"], reverse=True)

            return {
                "success": True,
                "target_info": info,
                "matched_count": len(recommendations),
                "matches": [
                    {
                        "cve_id": rec["vuln"].cve_id,
                        "name": rec["vuln"].name,
                        "cvss_score": rec["vuln"].cvss_score,
                        "category": rec["vuln"].category.value,
                        "reason": rec["reason"],
                        "confidence": f"{rec['confidence']:.1%}",
                        "recommended_tools": rec["tools"][:5],
                        "detection_methods": rec["detection"][:3]
                    }
                    for rec in recommendations[:5]
                ],
                "summary": {
                    "high_confidence": sum(1 for r in recommendations if r["confidence"] >= 0.8),
                    "medium_confidence": sum(1 for r in recommendations if 0.5 <= r["confidence"] < 0.8),
                    "total_matches": len(recommendations)
                }
            }
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Invalid JSON format: {e}",
                "target_info": target_info
            }
        except Exception as e:
            logger.error(f"智能匹配失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "matched_count": 0,
                "matches": []
            }

    registered_count = 8
    logger.info(f" 注册了 {registered_count} 个漏洞数据库工具")

    return registered_count


# 工具计数
VULN_TOOL_COUNT = 8
