#!/usr/bin/env python3
"""
自适应执行引擎

从 mcp_server.py 提取:
- ExecutionContext: 执行上下文数据类
- AdaptiveExecutionEngine: 自适应执行引擎
"""

import uuid
import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class ExecutionContext:
    """执行上下文数据类"""
    context_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    current_strategy: str = ""
    target_info: Dict[str, Any] = field(default_factory=dict)
    execution_state: str = "idle"  # idle, planning, executing, evaluating, switching
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    adaptation_history: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)

class AdaptiveExecutionEngine:
    """自适应执行引擎"""

    def __init__(self):
        self.execution_contexts: Dict[str, ExecutionContext] = {}
        self.active_contexts: Set[str] = set()

        # 执行参数
        self.adaptation_threshold = 0.3  # 策略切换阈值
        self.max_execution_time = 300  # 最大执行时间（秒）

        # 策略性能历史
        self.strategy_performance_history: Dict[str, List[float]] = {}

    def create_execution_context(self, session_id: str, target_info: Dict[str, Any],
                                initial_strategy: str = "auto") -> str:
        """创建执行上下文"""
        context = ExecutionContext(
            session_id=session_id,
            target_info=target_info,
            current_strategy=initial_strategy,
            execution_state="planning"
        )

        self.execution_contexts[context.context_id] = context
        self.active_contexts.add(context.context_id)

        return context.context_id

    def execute_adaptive_strategy(self, context_id: str, strategy_name: str = None) -> Dict[str, Any]:
        """执行自适应策略"""
        if context_id not in self.execution_contexts:
            return {"error": "执行上下文不存在", "success": False}

        context = self.execution_contexts[context_id]

        # 如果未指定策略，使用智能选择
        if not strategy_name:
            strategy_name = self._select_optimal_strategy(context)

        # 更新上下文状态
        context.current_strategy = strategy_name
        context.execution_state = "executing"
        context.last_updated = datetime.now()

        # 模拟执行策略
        execution_result = self._simulate_strategy_execution(strategy_name, context)

        # 评估执行结果
        performance_score = self._evaluate_performance(execution_result)

        # 检查是否需要适应性调整
        adaptation_needed = performance_score < self.adaptation_threshold

        result = {
            "success": True,
            "context_id": context_id,
            "strategy_name": strategy_name,
            "performance_score": performance_score,
            "execution_result": execution_result,
            "adaptation_needed": adaptation_needed,
            "context_state": context.execution_state
        }

        if adaptation_needed:
            adaptation_action = self._trigger_adaptation(context, performance_score)
            result["adaptation_action"] = adaptation_action

        return result

    def _select_optimal_strategy(self, context: ExecutionContext) -> str:
        """智能选择最优策略"""
        target_type = context.target_info.get("type", "unknown")

        # 基于目标类型的策略映射
        strategy_mapping = {
            "web": ["web_comprehensive", "web_quick_scan"],
            "network": ["network_recon", "network_service_enum"],
            "database": ["db_discovery", "db_security_audit"],
            "unknown": ["general_recon", "adaptive_discovery"]
        }

        candidate_strategies = strategy_mapping.get(target_type, strategy_mapping["unknown"])
        return candidate_strategies[0]  # 简化实现，返回第一个策略

    def _simulate_strategy_execution(self, strategy_name: str, context: ExecutionContext) -> Dict[str, Any]:
        """模拟策略执行"""
        import random

        # 模拟执行结果
        steps_completed = random.randint(3, 8)
        total_steps = random.randint(steps_completed, 10)
        execution_time = random.uniform(30, 200)

        return {
            "strategy": strategy_name,
            "steps_completed": steps_completed,
            "total_steps": total_steps,
            "execution_time": execution_time,
            "findings": [f"发现{i+1}" for i in range(random.randint(0, 5))]
        }

    def _evaluate_performance(self, execution_result: Dict[str, Any]) -> float:
        """评估执行性能"""
        steps_completed = execution_result.get("steps_completed", 0)
        total_steps = execution_result.get("total_steps", 1)
        execution_time = execution_result.get("execution_time", 300)

        # 基础完成率分数
        completion_score = steps_completed / total_steps if total_steps > 0 else 0

        # 时间效率分数
        time_efficiency = max(0, 1 - execution_time / self.max_execution_time)

        # 综合性能分数
        performance_score = completion_score * 0.7 + time_efficiency * 0.3

        return min(1.0, max(0.0, performance_score))

    def _trigger_adaptation(self, context: ExecutionContext, performance_score: float) -> Dict[str, Any]:
        """触发适应性调整"""
        target_type = context.target_info.get("type", "unknown")
        current_strategy = context.current_strategy

        # 获取替代策略
        alternative_strategies = self._get_alternative_strategies(current_strategy, target_type)

        if alternative_strategies:
            new_strategy = alternative_strategies[0]
            context.current_strategy = new_strategy
            context.execution_state = "switching"

            adaptation_record = {
                "timestamp": datetime.now().isoformat(),
                "trigger": "low_performance",
                "old_strategy": current_strategy,
                "new_strategy": new_strategy,
                "performance_score": performance_score
            }

            context.adaptation_history.append(adaptation_record)

            return {
                "action_type": "strategy_switch",
                "new_strategy": new_strategy,
                "reason": f"性能过低 ({performance_score:.2f})",
                "adaptation_record": adaptation_record
            }

        return {"action_type": "continue", "reason": "无可用替代策略"}

    def _get_alternative_strategies(self, current_strategy: str, target_type: str) -> List[str]:
        """获取替代策略"""
        strategy_alternatives = {
            "web_comprehensive": ["web_quick_scan", "web_targeted"],
            "network_recon": ["network_fast_scan", "network_stealth"],
            "general_recon": ["adaptive_discovery", "minimal_scan"]
        }

        return strategy_alternatives.get(current_strategy, ["general_recon"])

    def get_execution_status(self, context_id: str) -> Dict[str, Any]:
        """获取执行状态"""
        if context_id not in self.execution_contexts:
            return {"error": "执行上下文不存在"}

        context = self.execution_contexts[context_id]

        return {
            "context_id": context_id,
            "session_id": context.session_id,
            "current_strategy": context.current_strategy,
            "execution_state": context.execution_state,
            "adaptation_count": len(context.adaptation_history),
            "last_updated": context.last_updated.isoformat(),
            "performance_metrics": context.performance_metrics
        }

    def get_adaptation_insights(self, context_id: str) -> Dict[str, Any]:
        """获取适应性洞察"""
        if context_id not in self.execution_contexts:
            return {"error": "执行上下文不存在"}

        context = self.execution_contexts[context_id]

        insights = {
            "total_adaptations": len(context.adaptation_history),
            "adaptation_triggers": [],
            "strategy_switches": 0,
            "performance_trend": "stable"
        }

        for record in context.adaptation_history:
            insights["adaptation_triggers"].append(record.get("trigger", "unknown"))
            if record.get("action_type") == "strategy_switch":
                insights["strategy_switches"] += 1

        return {
            "context_id": context_id,
            "insights": insights,
            "adaptation_history": context.adaptation_history[-5:],  # 最近5次适应
            "message": f"上下文已进行 {insights['total_adaptations']} 次适应性调整"
        }


# 全局自适应执行引擎实例
adaptive_execution_engine = AdaptiveExecutionEngine()
