#!/usr/bin/env python3
"""
漏洞管理MCP工具 (v5.0)

提供漏洞生命周期管理的MCP工具接口
"""

import logging
from typing import Dict, Any, Optional, List

from kali_mcp.core.vuln_models import VulnRecord
from kali_mcp.core.vuln_manager import VulnManager

logger = logging.getLogger(__name__)

# 全局VulnManager实例
_vuln_manager = None


def _get_vuln_manager() -> VulnManager:
    global _vuln_manager
    if _vuln_manager is None:
        _vuln_manager = VulnManager()
    return _vuln_manager


def register_vuln_mgmt_tools(mcp, executor):
    """注册漏洞管理MCP工具"""

    @mcp.tool()
    def issue_vulnerability(
        title: str,
        vuln_type: str,
        target: str,
        severity: str = "medium",
        confidence: str = "medium",
        source: str = "blackbox",
        endpoint: str = "",
        params: str = "",
        payload: str = "",
        evidence: str = "",
        cvss_score: float = 0.0,
        discovered_by: str = "",
        tags: str = "",
    ) -> Dict[str, Any]:
        """
        提交候选漏洞到VulnManager。

        Args:
            title: 漏洞标题
            vuln_type: 漏洞类型 (sqli/xss/rce/lfi/ssrf/idor等)
            target: 目标URL/IP
            severity: 严重程度 (critical/high/medium/low/info)
            confidence: 置信度 (very_high/high/medium/low)
            source: 发现来源 (blackbox/whitebox/manual)
            endpoint: 受影响端点
            params: 受影响参数
            payload: 利用载荷
            evidence: 证据
            cvss_score: CVSS评分 (0.0-10.0)
            discovered_by: 发现的Agent/工具名称
            tags: 标签 (逗号分隔)
        """
        try:
            mgr = _get_vuln_manager()
            tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
            vuln = VulnRecord(
                title=title,
                vuln_type=vuln_type,
                target=target,
                severity=severity,
                confidence=confidence,
                source=source,
                endpoint=endpoint,
                params=params,
                payload=payload,
                evidence=evidence,
                cvss_score=cvss_score,
                discovered_by=discovered_by,
                tags=tag_list,
            )
            vuln_id = mgr.issue_vuln(vuln)
            return {
                "success": True,
                "vuln_id": vuln_id,
                "message": f"漏洞已提交: [{severity.upper()}] {title}",
                "status": "candidate",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def get_vuln_candidates(
        target: str = "",
        vuln_type: str = "",
    ) -> Dict[str, Any]:
        """
        获取待验证的候选漏洞列表 (按严重程度排序)。

        Args:
            target: 按目标过滤 (可选)
            vuln_type: 按漏洞类型过滤 (可选)
        """
        try:
            mgr = _get_vuln_manager()
            if target:
                vulns = [v for v in mgr.get_by_target(target) if v.status == "candidate"]
            elif vuln_type:
                vulns = [v for v in mgr.get_by_type(vuln_type) if v.status == "candidate"]
            else:
                vulns = mgr.get_candidates()
            return {
                "success": True,
                "count": len(vulns),
                "candidates": [v.to_dict() for v in vulns],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def cross_validate_vulns(
        blackbox_vuln_id: str,
        whitebox_vuln_id: str,
    ) -> Dict[str, Any]:
        """
        交叉验证黑盒和白盒发现的漏洞，提升置信度。

        Args:
            blackbox_vuln_id: 黑盒扫描发现的漏洞ID
            whitebox_vuln_id: 白盒审计发现的漏洞ID
        """
        try:
            mgr = _get_vuln_manager()
            score = mgr.cross_validate(blackbox_vuln_id, whitebox_vuln_id)
            matched = score >= 0.7
            return {
                "success": True,
                "match_score": round(score, 2),
                "matched": matched,
                "message": f"匹配度: {score:.0%}" + ("  置信度已提升至very_high" if matched else ""),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def get_vuln_report(
        fmt: str = "markdown",
        target: str = "",
    ) -> Dict[str, Any]:
        """
        导出漏洞评估报告。

        Args:
            fmt: 报告格式 (markdown/json)
            target: 按目标过滤 (可选)
        """
        try:
            mgr = _get_vuln_manager()
            stats = mgr.get_statistics()
            report = mgr.export_report(fmt=fmt)
            return {
                "success": True,
                "statistics": stats,
                "report": report,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def verify_vulnerability(
        vuln_id: str,
        verified: bool,
        evidence: str = "",
        verified_by: str = "",
    ) -> Dict[str, Any]:
        """
        验证候选漏洞 (candidate  verified/failed)。

        Args:
            vuln_id: 漏洞ID
            verified: 是否验证通过
            evidence: 验证证据
            verified_by: 验证的Agent/工具名称
        """
        try:
            mgr = _get_vuln_manager()
            # 先开始验证流程
            if not mgr.start_verification(vuln_id):
                return {"success": False, "error": f"无法开始验证: {vuln_id} (可能不是candidate状态)"}
            # 提交验证结果
            ok = mgr.submit_result(vuln_id, verified, evidence, verified_by)
            status = "verified" if verified else "failed"
            return {
                "success": ok,
                "vuln_id": vuln_id,
                "new_status": status,
                "message": f"漏洞 {vuln_id}  {status}",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}