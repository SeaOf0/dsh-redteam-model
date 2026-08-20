#!/usr/bin/env python3
"""
高级上下文分析器

从 mcp_server.py 提取:
- ContextPattern: 上下文模式数据类
- AdvancedContextAnalyzer: 高级上下文分析器
"""

import re
import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class ContextPattern:
    """上下文模式数据类"""
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pattern_name: str = ""
    pattern_type: str = "behavioral"  # behavioral, structural, temporal, causal
    pattern_signature: Dict[str, Any] = field(default_factory=dict)
    occurrence_count: int = 0
    success_rate: float = 0.0
    associated_strategies: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

class AdvancedContextAnalyzer:
    """高级上下文关联和模式识别分析器"""

    def __init__(self):
        self.pattern_repository: Dict[str, ContextPattern] = {}
        self.behavioral_sequences: List[List[Dict[str, Any]]] = []

        # 分析参数
        self.min_pattern_confidence = 0.6
        self.min_correlation_strength = 0.7
        self.pattern_discovery_window = 100  # 最近100次交互

    def analyze_context_patterns(self, session_history: List[Dict[str, Any]],
                                current_context: Dict[str, Any]) -> Dict[str, Any]:
        """分析上下文模式和关联"""
        analysis_results = {
            "discovered_patterns": [],
            "strong_correlations": [],
            "behavioral_insights": {},
            "predictive_recommendations": [],
            "confidence_metrics": {}
        }

        try:
            # 1. 发现新模式
            new_patterns = self._discover_patterns(session_history, current_context)
            analysis_results["discovered_patterns"] = new_patterns

            # 2. 分析上下文关联
            correlations = self._analyze_correlations(session_history, current_context)
            analysis_results["strong_correlations"] = correlations

            # 3. 提取行为洞察
            behavioral_insights = self._extract_behavioral_insights(session_history)
            analysis_results["behavioral_insights"] = behavioral_insights

            # 4. 生成预测性建议
            recommendations = self._generate_predictive_recommendations(current_context, new_patterns, correlations)
            analysis_results["predictive_recommendations"] = recommendations

        except Exception as e:
            analysis_results["error"] = str(e)

        return analysis_results

    def _discover_patterns(self, session_history: List[Dict[str, Any]],
                          current_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """发现新的上下文模式"""
        discovered_patterns = []

        # 序列模式发现
        sequence_patterns = self._discover_sequence_patterns(session_history)
        discovered_patterns.extend(sequence_patterns)

        # 工具使用模式
        tool_patterns = self._discover_tool_usage_patterns(session_history)
        discovered_patterns.extend(tool_patterns)

        # 成功/失败模式
        outcome_patterns = self._discover_outcome_patterns(session_history)
        discovered_patterns.extend(outcome_patterns)

        # 更新模式库
        for pattern in discovered_patterns:
            self._update_pattern_repository(pattern)

        return discovered_patterns

    def _discover_sequence_patterns(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """发现序列模式"""
        patterns = []

        if len(session_history) < 3:
            return patterns

        # 分析工具调用序列
        tool_sequences = []
        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            if tools_used:
                tool_sequences.extend(tools_used)

        # 查找频繁序列
        frequent_sequences = self._find_frequent_sequences(tool_sequences, min_length=2, min_support=2)

        for sequence, support in frequent_sequences:
            pattern = {
                "pattern_name": f"tool_sequence_{'-'.join(sequence)}",
                "pattern_type": "sequential",
                "pattern_signature": {
                    "sequence": sequence,
                    "support": support,
                    "length": len(sequence)
                },
                "confidence_score": min(support / len(session_history), 1.0)
            }
            patterns.append(pattern)

        return patterns

    def _discover_tool_usage_patterns(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """发现工具使用模式"""
        patterns = []

        # 统计工具使用频率
        tool_usage = {}
        tool_success_rate = {}

        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            success_indicators = entry.get("success_indicators", {})

            for tool in tools_used:
                tool_usage[tool] = tool_usage.get(tool, 0) + 1

                # 计算成功率
                if tool not in tool_success_rate:
                    tool_success_rate[tool] = {"success": 0, "total": 0}

                tool_success_rate[tool]["total"] += 1
                if success_indicators.get(tool, False):
                    tool_success_rate[tool]["success"] += 1

        # 识别高效工具组合
        for tool, usage_count in tool_usage.items():
            if usage_count >= 3:  # 至少使用3次
                success_rate = tool_success_rate[tool]["success"] / tool_success_rate[tool]["total"]

                if success_rate > 0.7:  # 成功率大于70%
                    pattern = {
                        "pattern_name": f"effective_tool_{tool}",
                        "pattern_type": "tool_effectiveness",
                        "pattern_signature": {
                            "tool": tool,
                            "usage_count": usage_count,
                            "success_rate": success_rate
                        },
                        "confidence_score": success_rate
                    }
                    patterns.append(pattern)

        return patterns

    def _discover_outcome_patterns(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """发现结果模式"""
        patterns = []

        # 分析成功和失败的上下文
        success_contexts = []
        failure_contexts = []

        for entry in session_history:
            outcome = entry.get("outcome", "unknown")
            context_features = self._extract_context_features(entry)

            if outcome == "success":
                success_contexts.append(context_features)
            elif outcome == "failure":
                failure_contexts.append(context_features)

        # 识别成功模式
        if len(success_contexts) >= 2:
            success_pattern = self._identify_common_features(success_contexts)
            if success_pattern:
                pattern = {
                    "pattern_name": "success_context_pattern",
                    "pattern_type": "outcome_success",
                    "pattern_signature": success_pattern,
                    "confidence_score": len(success_contexts) / max(len(session_history), 1)
                }
                patterns.append(pattern)

        return patterns

    def _analyze_correlations(self, session_history: List[Dict[str, Any]],
                             current_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """分析上下文关联"""
        correlations = []

        # 工具-结果关联
        tool_outcome_correlations = self._analyze_tool_outcome_correlations(session_history)
        correlations.extend(tool_outcome_correlations)

        return correlations

    def _analyze_tool_outcome_correlations(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """分析工具与结果的关联"""
        correlations = []

        # 统计工具和结果的共现
        tool_outcome_matrix = {}

        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            outcome = entry.get("outcome", "unknown")

            for tool in tools_used:
                if tool not in tool_outcome_matrix:
                    tool_outcome_matrix[tool] = {"success": 0, "failure": 0, "unknown": 0}
                tool_outcome_matrix[tool][outcome] += 1

        # 计算关联强度
        for tool, outcomes in tool_outcome_matrix.items():
            total = sum(outcomes.values())
            if total >= 3:  # 至少3次观察
                success_rate = outcomes["success"] / total

                if success_rate > 0.8 or success_rate < 0.2:  # 强关联
                    correlation = {
                        "correlation_type": "tool_outcome",
                        "source": tool,
                        "target": "success" if success_rate > 0.5 else "failure",
                        "correlation_strength": abs(success_rate - 0.5) * 2,
                        "evidence_count": total
                    }
                    correlations.append(correlation)

        return correlations

    def _extract_behavioral_insights(self, session_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """提取行为洞察"""
        insights = {
            "total_interactions": len(session_history),
            "tool_diversity": 0,
            "success_rate": 0,
            "common_patterns": []
        }

        if not session_history:
            return insights

        # 计算工具多样性
        all_tools = set()
        success_count = 0

        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            all_tools.update(tools_used)

            if entry.get("outcome") == "success":
                success_count += 1

        insights["tool_diversity"] = len(all_tools)
        insights["success_rate"] = success_count / len(session_history)

        return insights

    def _generate_predictive_recommendations(self, current_context: Dict[str, Any],
                                           patterns: List[Dict[str, Any]],
                                           correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成预测性建议"""
        recommendations = []

        # 基于模式的建议
        for pattern in patterns:
            if pattern.get("confidence_score", 0) > 0.7:
                recommendation = {
                    "type": "pattern_based",
                    "suggestion": f"根据模式 {pattern['pattern_name']}，建议继续使用相关策略",
                    "confidence": pattern.get("confidence_score", 0),
                    "reasoning": f"该模式在历史中表现良好，置信度为 {pattern.get('confidence_score', 0):.2f}"
                }
                recommendations.append(recommendation)

        # 基于关联的建议
        for correlation in correlations:
            if correlation.get("correlation_strength", 0) > 0.8:
                recommendation = {
                    "type": "correlation_based",
                    "suggestion": f"推荐使用工具 {correlation['source']}",
                    "confidence": correlation.get("correlation_strength", 0),
                    "reasoning": f"该工具与成功结果有强关联性，关联强度为 {correlation.get('correlation_strength', 0):.2f}"
                }
                recommendations.append(recommendation)

        return recommendations

    def _find_frequent_sequences(self, sequences: List[str], min_length: int = 2, min_support: int = 2) -> List[tuple]:
        """查找频繁序列"""
        from collections import defaultdict

        if len(sequences) < min_length:
            return []

        # 生成所有可能的子序列
        subsequences = defaultdict(int)

        for i in range(len(sequences) - min_length + 1):
            for length in range(min_length, min(len(sequences) - i + 1, 5)):  # 最大长度为5
                subseq = tuple(sequences[i:i + length])
                subsequences[subseq] += 1

        # 筛选频繁序列
        frequent = [(seq, count) for seq, count in subsequences.items() if count >= min_support]
        frequent.sort(key=lambda x: x[1], reverse=True)

        return frequent[:10]  # 返回前10个最频繁的序列

    def _extract_context_features(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """提取上下文特征"""
        features = {}

        # 提取关键特征
        features["tools_used"] = entry.get("tools_used", [])
        features["target_type"] = entry.get("target_type", "unknown")
        features["strategy"] = entry.get("strategy", "unknown")
        features["session_depth"] = entry.get("session_depth", 0)

        return features

    def _identify_common_features(self, contexts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """识别共同特征"""
        if not contexts:
            return {}

        common_features = {}

        # 查找在多数上下文中出现的特征
        for feature_name in contexts[0].keys():
            feature_values = [ctx.get(feature_name) for ctx in contexts if feature_name in ctx]

            if len(set(str(v) for v in feature_values)) == 1:  # 所有值都相同
                common_features[feature_name] = feature_values[0]

        return common_features if common_features else None

    def _update_pattern_repository(self, pattern: Dict[str, Any]):
        """更新模式库"""
        pattern_name = pattern.get("pattern_name", "unknown")

        if pattern_name in self.pattern_repository:
            # 更新现有模式
            existing = self.pattern_repository[pattern_name]
            existing.occurrence_count += 1
            existing.last_seen = datetime.now()
            # 更新置信度（移动平均）
            existing.confidence_score = (existing.confidence_score * 0.8 +
                                       pattern.get("confidence_score", 0) * 0.2)
        else:
            # 创建新模式
            new_pattern = ContextPattern(
                pattern_name=pattern_name,
                pattern_type=pattern.get("pattern_type", "unknown"),
                pattern_signature=pattern.get("pattern_signature", {}),
                occurrence_count=1,
                confidence_score=pattern.get("confidence_score", 0)
            )
            self.pattern_repository[pattern_name] = new_pattern

# 全局高级上下文分析器实例
advanced_context_analyzer = AdvancedContextAnalyzer()

# ==================== 攻击智能知识图谱系统 ====================

