#!/usr/bin/env python3
"""
攻击链管理MCP工具 (v5.0)

提供攻击链生命周期管理的MCP工具接口
"""

import logging
from typing import Dict, Any

from kali_mcp.core.chain_models import AttackChain, ChainStep
from kali_mcp.core.chain_manager import ChainManager

logger = logging.getLogger(__name__)

_chain_manager = None


def _get_chain_manager() -> ChainManager:
    global _chain_manager
    if _chain_manager is None:
        _chain_manager = ChainManager()
    return _chain_manager


def register_chain_mgmt_tools(mcp, executor):
    """注册攻击链管理MCP工具"""

    @mcp.tool()
    def create_attack_chain(
        title: str,
        description: str = "",
        impact_level: str = "medium",
        fragments: str = "",
        vulns: str = "",
    ) -> Dict[str, Any]:
        """
        创建攻击链。

        Args:
            title: 攻击链标题
            description: 攻击链描述
            impact_level: 影响级别 (critical/high/medium/low)
            fragments: 关联碎片ID (逗号分隔)
            vulns: 关联漏洞ID (逗号分隔)
        """
        try:
            mgr = _get_chain_manager()
            frag_list = [f.strip() for f in fragments.split(",") if f.strip()] if fragments else []
            vuln_list = [v.strip() for v in vulns.split(",") if v.strip()] if vulns else []
            chain = AttackChain(
                title=title,
                description=description,
                impact_level=impact_level,
                fragments=frag_list,
                vulns=vuln_list,
            )
            cid = mgr.create_chain(chain)
            return {
                "success": True,
                "chain_id": cid,
                "message": f"攻击链已创建: {title}",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def add_chain_step(
        chain_id: str,
        title: str,
        action: str,
        description: str = "",
        precondition: str = "",
        expected_result: str = "",
        tool_used: str = "",
        fragment_id: str = "",
        vuln_id: str = "",
    ) -> Dict[str, Any]:
        """
        向攻击链添加步骤。

        Args:
            chain_id: 攻击链ID
            title: 步骤标题
            action: 执行动作
            description: 步骤描述
            precondition: 前置条件
            expected_result: 预期结果
            tool_used: 使用的工具
            fragment_id: 关联碎片ID
            vuln_id: 关联漏洞ID
        """
        try:
            mgr = _get_chain_manager()
            step = ChainStep(
                title=title,
                description=description,
                precondition=precondition,
                action=action,
                expected_result=expected_result,
                tool_used=tool_used,
                fragment_id=fragment_id or None,
                vuln_id=vuln_id or None,
            )
            ok = mgr.add_step(chain_id, step)
            if ok:
                return {"success": True, "message": f"步骤已添加: {title}"}
            return {"success": False, "error": f"攻击链不存在: {chain_id}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def analyze_attack_chain(
        chain_id: str,
    ) -> Dict[str, Any]:
        """
        评估攻击链可��性 (0-100分)。

        Args:
            chain_id: 攻击链ID
        """
        try:
            mgr = _get_chain_manager()
            result = mgr.analyze_feasibility(chain_id)
            return {"success": True, **result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def get_attack_chains(
        status: str = "",
    ) -> Dict[str, Any]:
        """
        查询攻击链列表。

        Args:
            status: 按状态过滤 (draft/analyzing/confirmed/executed)
        """
        try:
            mgr = _get_chain_manager()
            chains = mgr.get_all(status=status)
            return {
                "success": True,
                "count": len(chains),
                "chains": [c.to_dict() for c in chains],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}