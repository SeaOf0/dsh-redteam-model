#!/usr/bin/env python3
"""
自适应执行引擎工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
import time
from typing import Dict, Any, Optional, List

from kali_mcp.core.adaptive_exec_engine import AdaptiveExecutionEngine
logger = logging.getLogger(__name__)


def register_adaptive_tools(mcp, executor):
    """自适应执行引擎工具注册"""

    # 实例化自适应执行引擎
    adaptive_execution_engine = AdaptiveExecutionEngine()

    # ==================== 自适应执行引擎工具 ====================

    @mcp.tool()
    def adaptive_create_execution_context(session_id: str, target_info: str,
                                         initial_strategy: str = "auto") -> Dict[str, Any]:
        """
        创建自适应执行上下文

        Args:
            session_id: 会话ID
            target_info: 目标信息，JSON格式字符串
            initial_strategy: 初始策略名称

        Returns:
            包含执行上下文信息的字典
        """
        try:
            import json

            # 解析目标信息
            try:
                target_data = json.loads(target_info) if target_info else {}
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式目标信息"
                }

            context_id = adaptive_execution_engine.create_execution_context(
                session_id=session_id,
                target_info=target_data,
                initial_strategy=initial_strategy
            )

            return {
                "success": True,
                "context_id": context_id,
                "session_id": session_id,
                "target_info": target_data,
                "initial_strategy": initial_strategy,
                "execution_state": "planning",
                "message": f"成功创建执行上下文: {context_id}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "创建执行上下文失败"
            }

    @mcp.tool()
    def adaptive_execute_strategy(context_id: str, strategy_name: str = "") -> Dict[str, Any]:
        """
        执行自适应策略

        Args:
            context_id: 执行上下文ID
            strategy_name: 策略名称（可选，为空则自动选择）

        Returns:
            包含执行结果的字典
        """
        try:
            result = adaptive_execution_engine.execute_adaptive_strategy(
                context_id=context_id,
                strategy_name=strategy_name if strategy_name else None
            )

            if not result.get("success", False):
                return {
                    "success": False,
                    "error": result.get("error", "未知错误"),
                    "message": "策略执行失败"
                }

            return {
                "success": True,
                "execution_result": result,
                "message": f"策略 {result['strategy_name']} 执行完成，性能评分: {result['performance_score']:.2f}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "自适应策略执行失败"
            }

    @mcp.tool()
    def adaptive_get_execution_status(context_id: str) -> Dict[str, Any]:
        """
        获取执行上下文状态

        Args:
            context_id: 执行上下文ID

        Returns:
            包含执行状态的字典
        """
        try:
            status = adaptive_execution_engine.get_execution_status(context_id)

            if "error" in status:
                return {
                    "success": False,
                    "error": status["error"],
                    "message": "获取执行状态失败"
                }

            return {
                "success": True,
                "status": status,
                "message": f"上下文 {context_id} 当前状态: {status['execution_state']}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取执行状态失败"
            }

    @mcp.tool()
    def adaptive_get_insights(context_id: str) -> Dict[str, Any]:
        """
        获取自适应执行洞察

        Args:
            context_id: 执行上下文ID

        Returns:
            包含适应性洞察的字典
        """
        try:
            insights = adaptive_execution_engine.get_adaptation_insights(context_id)

            if "error" in insights:
                return {
                    "success": False,
                    "error": insights["error"],
                    "message": "获取适应性洞察失败"
                }

            return {
                "success": True,
                "insights": insights,
                "message": insights["message"]
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取适应性洞察失败"
            }

    @mcp.tool()
    def adaptive_intelligent_orchestration(target_list: str, orchestration_mode: str = "balanced") -> Dict[str, Any]:
        """
        智能编排多目标自适应攻击

        Args:
            target_list: 目标列表，JSON格式字符串
            orchestration_mode: 编排模式 (balanced, aggressive, stealth, quick)

        Returns:
            包含智能编排结果的字典
        """
        try:
            import json

            # 解析目标列表
            try:
                targets = json.loads(target_list) if target_list else []
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式目标列表"
                }

            orchestration_results = []

            for i, target in enumerate(targets):
                # 为每个目标创建执行上下文
                session_id = f"orchestration_{int(time.time())}_{i}"
                context_id = adaptive_execution_engine.create_execution_context(
                    session_id=session_id,
                    target_info=target
                )

                # 基于编排模式选择策略
                strategy_mapping = {
                    "balanced": "auto",
                    "aggressive": "comprehensive",
                    "stealth": "stealth_scan",
                    "quick": "quick_scan"
                }

                strategy = strategy_mapping.get(orchestration_mode, "auto")

                # 执行自适应策略
                execution_result = adaptive_execution_engine.execute_adaptive_strategy(
                    context_id=context_id,
                    strategy_name=strategy
                )

                orchestration_results.append({
                    "target": target,
                    "context_id": context_id,
                    "execution_result": execution_result
                })

            # 汇总结果
            total_targets = len(targets)
            successful_executions = len([r for r in orchestration_results
                                       if r["execution_result"].get("success", False)])

            return {
                "success": True,
                "orchestration_mode": orchestration_mode,
                "total_targets": total_targets,
                "successful_executions": successful_executions,
                "success_rate": successful_executions / total_targets if total_targets > 0 else 0,
                "execution_results": orchestration_results,
                "message": f"智能编排完成: {successful_executions}/{total_targets} 个目标执行成功"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "智能编排失败"
            }


