#!/usr/bin/env python3
"""
机器学习策略优化引擎

从 mcp_server.py 提取:
- MLStrategyOptimizer: 基于历史数据和实时反馈优化攻击策略

v5.1 增强:
- record_tool_outcome(): 接收EventBus的工具执行结果
- SQLite持久化: 工具成功率数据跨会话保存
- recommend_tools_for_target(): 基于历史数据推荐工具
"""

import os
import time
import random
import re
import logging
import sqlite3
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from collections import defaultdict

from kali_mcp.core.mcp_session import SessionContext

logger = logging.getLogger(__name__)

class MLStrategyOptimizer:
    """机器学习策略优化引擎 - 基于历史数据和实时反馈优化攻击策略"""

    def __init__(self):
        self.strategy_performance_history = {}
        self.target_type_patterns = {}
        self.success_factors = {}
        self.learning_rate = 0.1
        self.confidence_threshold = 0.7

        # v5.1: 工具执行统计 — 真实数据驱动
        self._tool_stats = defaultdict(lambda: {"success": 0, "fail": 0, "total_duration": 0.0})
        self._tool_target_stats = defaultdict(lambda: defaultdict(lambda: {"success": 0, "fail": 0}))

        # v5.1: SQLite 持久化
        self._db_path = os.environ.get(
            "KALI_MCP_LEARNING_DB",
            os.path.join(os.path.expanduser("~"), ".kali_mcp_learning.db"),
        )
        self._init_db()
        self._load_from_db()

        # 初始化策略权重矩阵
        self.strategy_weights = {
            "web_comprehensive": {
                "port_diversity": 0.3,
                "service_versions": 0.25,
                "response_time": 0.2,
                "vulnerability_history": 0.25
            },
            "ctf_quick_solve": {
                "time_constraint": 0.4,
                "flag_pattern_match": 0.3,
                "tool_efficiency": 0.3
            },
            "network_recon": {
                "network_size": 0.35,
                "response_rate": 0.25,
                "service_diversity": 0.4
            },
            "pwn_exploitation": {
                "binary_complexity": 0.3,
                "mitigation_presence": 0.3,
                "exploit_availability": 0.4
            },
            "adaptive_multi": {
                "environment_complexity": 0.25,
                "tool_synergy": 0.3,
                "discovery_rate": 0.45
            }
        }

        # 向量存储系统用于相似性匹配
        self.target_vectors = {}
        self.strategy_embeddings = {}

    def vectorize_target_characteristics(self, session: SessionContext, scan_results: Dict[str, Any] = None) -> List[float]:
        """将目标特征向量化用于ML分析"""
        features = [0.0] * 20  # 20维特征向量

        # 基础目标特征 (0-4)
        target = session.target.lower() if session.target else ""
        features[0] = 1.0 if any(web_indicator in target for web_indicator in ["http", "www", ".com"]) else 0.0
        features[1] = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target) else 0.0
        features[2] = len(session.discovered_assets) / 10.0  # 标准化发现的资产数量
        features[3] = len(session.conversation_history) / 20.0  # 标准化对话深度
        features[4] = 1.0 if session.attack_mode == "ctf" else 0.0

        # 扫描结果特征 (5-12)
        if scan_results:
            open_ports = scan_results.get("open_ports", [])
            features[5] = len(open_ports) / 100.0  # 标准化端口数量
            features[6] = 1.0 if any(port in [80, 443, 8080] for port in open_ports) else 0.0  # Web服务
            features[7] = 1.0 if any(port in [21, 22, 23, 25] for port in open_ports) else 0.0  # 传统服务
            features[8] = 1.0 if any(port in [1433, 3306, 5432] for port in open_ports) else 0.0  # 数据库
            features[9] = scan_results.get("vulnerability_count", 0) / 50.0  # 标准化漏洞数量
            features[10] = 1.0 if scan_results.get("waf_detected", False) else 0.0  # WAF检测
            features[11] = scan_results.get("response_time_avg", 0) / 1000.0  # 标准化响应时间
            features[12] = 1.0 if scan_results.get("ssl_enabled", False) else 0.0  # SSL状态

        # 时间特征 (13-16)
        session_duration = (datetime.now() - session.start_time).total_seconds()
        features[13] = min(session_duration / 3600, 1.0)  # 会话持续时间(小时)
        features[14] = 1.0 if datetime.now().hour < 6 or datetime.now().hour > 22 else 0.0  # 夜间测试
        features[15] = len(session.completed_tasks) / 10.0  # 标准化已完成任务
        features[16] = 1.0 if any("urgent" in msg.get("user_message", "").lower()
                                for msg in session.conversation_history) else 0.0  # 紧急程度

        # 高级特征 (17-19)
        features[17] = self._calculate_environment_complexity(session)
        features[18] = self._calculate_success_probability(session)
        features[19] = self._calculate_resource_efficiency(session)

        return features

    def _calculate_environment_complexity(self, session: SessionContext) -> float:
        """计算环境复杂度"""
        complexity_score = 0.0

        # 基于发现的服务数量
        service_count = len(session.discovered_assets.get("services", []))
        complexity_score += min(service_count / 20.0, 0.4)

        # 基于交互历史复杂度
        conversation_complexity = len(set(tool for conv in session.conversation_history
                                        for tool in conv.get("tools_used", [])))
        complexity_score += min(conversation_complexity / 15.0, 0.3)

        # 基于目标多样性
        if session.target and ("/" in session.target or ":" in session.target):
            complexity_score += 0.3

        return min(complexity_score, 1.0)

    def _calculate_success_probability(self, session: SessionContext) -> float:
        """基于历史数据计算成功概率"""
        if not session.current_strategy:
            return 0.5  # 默认50%

        strategy_history = self.strategy_performance_history.get(session.current_strategy, [])
        if not strategy_history:
            return 0.5

        # 计算历史成功率
        recent_performances = strategy_history[-10:]  # 最近10次
        avg_success = sum(recent_performances) / len(recent_performances)

        # 考虑目标相似性调整
        target_type = self._classify_target_type(session.target)
        type_modifier = self.target_type_patterns.get(target_type, {}).get(session.current_strategy, 1.0)

        return min(avg_success * type_modifier, 1.0)

    def _calculate_resource_efficiency(self, session: SessionContext) -> float:
        """计算资源效率分数"""
        if not session.conversation_history:
            return 0.5

        total_tools_used = sum(len(conv.get("tools_used", [])) for conv in session.conversation_history)
        discoveries_made = len(session.discovered_assets)

        if total_tools_used == 0:
            return 0.0

        efficiency = discoveries_made / total_tools_used
        return min(efficiency, 1.0)

    def _classify_target_type(self, target: str) -> str:
        """分类目标类型"""
        if not target:
            return "unknown"

        target_lower = target.lower()

        if any(indicator in target_lower for indicator in ["http", "www", ".com", ".org"]):
            return "web_application"
        elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
            return "ip_address"
        elif any(indicator in target_lower for indicator in [".exe", ".bin"]):
            return "binary_file"
        elif "/" in target or ":" in target:
            return "complex_endpoint"
        else:
            return "unknown"

    def predict_optimal_strategy(self, session: SessionContext, user_intent: Dict[str, Any],
                                scan_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """基于ML预测最优策略"""

        # 特征向量化
        feature_vector = self.vectorize_target_characteristics(session, scan_results)

        # 计算每个策略的适配分数
        strategy_scores = {}

        for strategy_name, weights in self.strategy_weights.items():
            base_score = self._calculate_base_strategy_score(strategy_name, feature_vector, weights)

            # 历史性能调整
            historical_performance = self._get_historical_performance(strategy_name, session)

            # 上下文相似性调整
            similarity_bonus = self._calculate_context_similarity(strategy_name, session)

            # 实时学习调整
            learning_adjustment = self._get_learning_adjustment(strategy_name, user_intent)

            final_score = (base_score * 0.4 +
                          historical_performance * 0.3 +
                          similarity_bonus * 0.2 +
                          learning_adjustment * 0.1)

            strategy_scores[strategy_name] = {
                "total_score": final_score,
                "base_score": base_score,
                "historical_performance": historical_performance,
                "similarity_bonus": similarity_bonus,
                "learning_adjustment": learning_adjustment,
                "confidence": self._calculate_confidence(final_score, strategy_name)
            }

        # 排序并返回推荐
        sorted_strategies = sorted(strategy_scores.items(), key=lambda x: x[1]["total_score"], reverse=True)

        return {
            "recommended_strategy": sorted_strategies[0][0] if sorted_strategies else "adaptive_multi",
            "confidence": sorted_strategies[0][1]["confidence"] if sorted_strategies else 0.5,
            "alternative_strategies": [
                {
                    "strategy": strategy,
                    "score": details["total_score"],
                    "confidence": details["confidence"],
                    "reasoning": self._generate_strategy_reasoning(strategy, details)
                }
                for strategy, details in sorted_strategies[1:4]
            ],
            "feature_analysis": {
                "primary_factors": self._identify_primary_factors(feature_vector),
                "risk_assessment": self._assess_risk_level(feature_vector),
                "resource_estimation": self._estimate_resource_requirements(sorted_strategies[0][0] if sorted_strategies else "adaptive_multi")
            }
        }

    def _calculate_base_strategy_score(self, strategy_name: str, features: List[float], weights: Dict[str, float]) -> float:
        """计算策略基础分数"""
        score = 0.0

        if strategy_name == "web_comprehensive":
            score = (features[0] * weights["port_diversity"] +  # Web指标
                    features[6] * weights["service_versions"] +   # Web服务
                    features[11] * weights["response_time"] +     # 响应时间
                    features[9] * weights["vulnerability_history"])  # 漏洞数量

        elif strategy_name == "ctf_quick_solve":
            score = (features[4] * weights["time_constraint"] +   # CTF模式
                    features[16] * weights["flag_pattern_match"] +  # 紧急程度
                    features[19] * weights["tool_efficiency"])      # 资源效率

        elif strategy_name == "network_recon":
            score = (features[1] * weights["network_size"] +      # IP目标
                    features[5] * weights["response_rate"] +       # 端口数量
                    features[7] * weights["service_diversity"])    # 传统服务

        elif strategy_name == "pwn_exploitation":
            score = (features[17] * weights["binary_complexity"] +  # 环境复杂度
                    features[10] * weights["mitigation_presence"] +  # WAF检测
                    features[18] * weights["exploit_availability"])  # 成功概率

        elif strategy_name == "adaptive_multi":
            score = (features[17] * weights["environment_complexity"] +  # 环境复杂度
                    features[2] * weights["tool_synergy"] +              # 发现资产
                    features[15] * weights["discovery_rate"])            # 完成任务

        return min(max(score, 0.0), 1.0)

    def _get_historical_performance(self, strategy_name: str, session: SessionContext) -> float:
        """获取历史性能分数"""
        target_type = self._classify_target_type(session.target)

        # 获取策略历史记录
        strategy_history = self.strategy_performance_history.get(strategy_name, [])

        if not strategy_history:
            return 0.5  # 默认中等表现

        # 获取目标类型特定的表现
        type_specific = self.target_type_patterns.get(target_type, {}).get(strategy_name, [])

        if type_specific:
            recent_performance = sum(type_specific[-5:]) / len(type_specific[-5:])
        else:
            recent_performance = sum(strategy_history[-10:]) / len(strategy_history[-10:])

        return recent_performance

    def _calculate_context_similarity(self, strategy_name: str, session: SessionContext) -> float:
        """计算上下文相似性奖励"""
        current_context = {
            "target_type": self._classify_target_type(session.target),
            "attack_mode": session.attack_mode,
            "session_depth": len(session.conversation_history),
            "discoveries": len(session.discovered_assets)
        }

        # 查找相似的历史上下文
        similarity_scores = []

        for stored_context in self.target_vectors.values():
            if stored_context.get("successful_strategy") == strategy_name:
                similarity = self._calculate_context_cosine_similarity(current_context, stored_context)
                similarity_scores.append(similarity)

        if similarity_scores:
            return sum(similarity_scores) / len(similarity_scores)

        return 0.0

    def _calculate_context_cosine_similarity(self, ctx1: Dict, ctx2: Dict) -> float:
        """计算上下文余弦相似度"""
        # 简化的相似度计算
        score = 0.0
        total_factors = 0

        if ctx1.get("target_type") == ctx2.get("target_type"):
            score += 0.4
        total_factors += 1

        if ctx1.get("attack_mode") == ctx2.get("attack_mode"):
            score += 0.3
        total_factors += 1

        # 数值特征的相似度
        depth_diff = abs(ctx1.get("session_depth", 0) - ctx2.get("session_depth", 0))
        depth_similarity = max(0, 1 - depth_diff / 20.0)
        score += depth_similarity * 0.3
        total_factors += 1

        return score / total_factors if total_factors > 0 else 0.0

    def _get_learning_adjustment(self, strategy_name: str, user_intent: Dict[str, Any]) -> float:
        """获取实时学习调整分数"""
        adjustment = 0.0

        # 基于用户意图调整
        intent = user_intent.get("primary_intent", "")
        urgency = user_intent.get("urgency_level", "normal")

        if intent == "security_testing" and strategy_name in ["web_comprehensive", "network_recon"]:
            adjustment += 0.2
        elif intent == "ctf_solving" and strategy_name == "ctf_quick_solve":
            adjustment += 0.3
        elif intent == "exploitation" and strategy_name in ["pwn_exploitation", "adaptive_multi"]:
            adjustment += 0.25

        # 基于紧急程度调整
        if urgency == "high" and strategy_name in ["ctf_quick_solve", "network_recon"]:
            adjustment += 0.15
        elif urgency == "low" and strategy_name in ["web_comprehensive", "adaptive_multi"]:
            adjustment += 0.1

        return min(adjustment, 0.5)

    def _calculate_confidence(self, score: float, strategy_name: str) -> float:
        """计算推荐置信度"""
        base_confidence = score

        # 基于历史数据量调整置信度
        history_count = len(self.strategy_performance_history.get(strategy_name, []))
        history_bonus = min(history_count / 50.0, 0.2)  # 最多20%奖励

        # 基于策略复杂度调整
        complexity_penalty = {
            "ctf_quick_solve": 0.0,
            "network_recon": 0.05,
            "web_comprehensive": 0.1,
            "pwn_exploitation": 0.15,
            "adaptive_multi": 0.2
        }.get(strategy_name, 0.1)

        final_confidence = base_confidence + history_bonus - complexity_penalty
        return max(min(final_confidence, 1.0), 0.0)

    def _generate_strategy_reasoning(self, strategy_name: str, details: Dict[str, Any]) -> str:
        """生成策略推荐理由"""
        reasoning_parts = []

        if details["base_score"] > 0.7:
            reasoning_parts.append("目标特征高度匹配")

        if details["historical_performance"] > 0.6:
            reasoning_parts.append("历史表现优秀")

        if details["similarity_bonus"] > 0.3:
            reasoning_parts.append("发现相似成功案例")

        if details["learning_adjustment"] > 0.2:
            reasoning_parts.append("用户意图高度匹配")

        if not reasoning_parts:
            reasoning_parts.append("基于当前上下文的综合分析")

        return ", ".join(reasoning_parts)

    def _identify_primary_factors(self, features: List[float]) -> List[str]:
        """识别主要影响因素"""
        factors = []

        if features[0] > 0.5:  # Web指标
            factors.append("Web应用特征显著")
        if features[1] > 0.5:  # IP目标
            factors.append("网络目标检测")
        if features[5] > 0.3:  # 端口数量
            factors.append("多端口开放")
        if features[9] > 0.2:  # 漏洞数量
            factors.append("已知漏洞存在")
        if features[17] > 0.6:  # 环境复杂度
            factors.append("复杂环境结构")

        return factors[:3]  # 返回前3个主要因素

    def _assess_risk_level(self, features: List[float]) -> str:
        """评估风险等级"""
        risk_score = 0.0

        # WAF检测
        if features[10] > 0.5:
            risk_score += 0.3

        # SSL启用
        if features[12] > 0.5:
            risk_score += 0.2

        # 环境复杂度
        risk_score += features[17] * 0.3

        # 响应时间（可能表示监控）
        if features[11] > 0.5:
            risk_score += 0.2

        if risk_score < 0.3:
            return "低风险"
        elif risk_score < 0.6:
            return "中等风险"
        else:
            return "高风险"

    def _estimate_resource_requirements(self, strategy_name: str) -> Dict[str, Any]:
        """估算资源需求"""
        requirements = {
            "ctf_quick_solve": {
                "estimated_time": "5-15分钟",
                "cpu_intensity": "低",
                "bandwidth_usage": "低",
                "tool_count": "3-5个"
            },
            "network_recon": {
                "estimated_time": "15-30分钟",
                "cpu_intensity": "中",
                "bandwidth_usage": "中",
                "tool_count": "4-7个"
            },
            "web_comprehensive": {
                "estimated_time": "30-60分钟",
                "cpu_intensity": "高",
                "bandwidth_usage": "高",
                "tool_count": "6-10个"
            },
            "pwn_exploitation": {
                "estimated_time": "20-45分钟",
                "cpu_intensity": "高",
                "bandwidth_usage": "低",
                "tool_count": "4-8个"
            },
            "adaptive_multi": {
                "estimated_time": "45-90分钟",
                "cpu_intensity": "很高",
                "bandwidth_usage": "高",
                "tool_count": "8-15个"
            }
        }

        return requirements.get(strategy_name, requirements["adaptive_multi"])

    def update_strategy_performance(self, strategy_name: str, success_rate: float,
                                  target_type: str = None, context: Dict[str, Any] = None):
        """更新策略性能记录"""

        # 更新全局性能历史
        if strategy_name not in self.strategy_performance_history:
            self.strategy_performance_history[strategy_name] = []

        self.strategy_performance_history[strategy_name].append(success_rate)

        # 保持历史记录在合理范围内
        if len(self.strategy_performance_history[strategy_name]) > 100:
            self.strategy_performance_history[strategy_name] = \
                self.strategy_performance_history[strategy_name][-100:]

        # 更新目标类型特定的性能
        if target_type:
            if target_type not in self.target_type_patterns:
                self.target_type_patterns[target_type] = {}

            if strategy_name not in self.target_type_patterns[target_type]:
                self.target_type_patterns[target_type][strategy_name] = []

            self.target_type_patterns[target_type][strategy_name].append(success_rate)

            # 保持记录在合理范围内
            if len(self.target_type_patterns[target_type][strategy_name]) > 50:
                self.target_type_patterns[target_type][strategy_name] = \
                    self.target_type_patterns[target_type][strategy_name][-50:]

        # 存储上下文向量用于相似性匹配
        if context:
            context_id = f"{strategy_name}_{int(time.time())}"
            self.target_vectors[context_id] = {
                **context,
                "successful_strategy": strategy_name,
                "success_rate": success_rate,
                "timestamp": datetime.now().isoformat()
            }

        # 应用强化学习更新权重
        self._update_strategy_weights(strategy_name, success_rate, target_type)

    def _update_strategy_weights(self, strategy_name: str, success_rate: float, target_type: str = None):
        """使用强化学习更新策略权重"""
        if strategy_name not in self.strategy_weights:
            return

        # 计算奖励信号
        reward = (success_rate - 0.5) * 2  # 将0-1转换为-1到1的奖励

        # 使用简单的梯度上升更新权重
        for factor, current_weight in self.strategy_weights[strategy_name].items():
            adjustment = self.learning_rate * reward * current_weight
            new_weight = current_weight + adjustment

            # 保持权重在合理范围内
            self.strategy_weights[strategy_name][factor] = max(0.1, min(new_weight, 0.9))

        # 重新标准化权重
        total_weight = sum(self.strategy_weights[strategy_name].values())
        for factor in self.strategy_weights[strategy_name]:
            self.strategy_weights[strategy_name][factor] /= total_weight

    def get_performance_analytics(self) -> Dict[str, Any]:
        """获取性能分析报告"""
        analytics = {
            "strategy_performance_overview": {},
            "target_type_insights": {},
            "learning_progress": {},
            "optimization_recommendations": []
        }

        # 策略性能概览
        for strategy, history in self.strategy_performance_history.items():
            if history:
                analytics["strategy_performance_overview"][strategy] = {
                    "average_success_rate": sum(history) / len(history),
                    "recent_trend": sum(history[-10:]) / len(history[-10:]) if len(history) >= 10 else sum(history) / len(history),
                    "total_executions": len(history),
                    "best_performance": max(history),
                    "worst_performance": min(history),
                    "stability": 1.0 - (max(history) - min(history))  # 稳定性指标
                }

        # 目标类型洞察
        for target_type, strategies in self.target_type_patterns.items():
            analytics["target_type_insights"][target_type] = {
                "best_strategy": max(strategies.items(), key=lambda x: sum(x[1]) / len(x[1]))[0] if strategies else None,
                "strategy_effectiveness": {
                    strategy: sum(performance) / len(performance)
                    for strategy, performance in strategies.items()
                }
            }

        # 学习进展
        total_sessions = sum(len(history) for history in self.strategy_performance_history.values())
        analytics["learning_progress"] = {
            "total_learning_sessions": total_sessions,
            "strategies_learned": len(self.strategy_performance_history),
            "target_types_analyzed": len(self.target_type_patterns),
            "confidence_improvement": self._calculate_confidence_improvement()
        }

        # 优化建议
        analytics["optimization_recommendations"] = self._generate_optimization_recommendations()

        return analytics

    def _calculate_confidence_improvement(self) -> float:
        """计算置信度改进程度"""
        if not self.strategy_performance_history:
            return 0.0

        improvements = []
        for strategy, history in self.strategy_performance_history.items():
            if len(history) >= 10:
                early_avg = sum(history[:5]) / 5
                recent_avg = sum(history[-5:]) / 5
                improvement = recent_avg - early_avg
                improvements.append(improvement)

        return sum(improvements) / len(improvements) if improvements else 0.0

    def _generate_optimization_recommendations(self) -> List[Dict[str, str]]:
        """生成优化建议"""
        recommendations = []

        # 分析策略性能
        for strategy, history in self.strategy_performance_history.items():
            if history:
                avg_performance = sum(history) / len(history)
                if avg_performance < 0.4:
                    recommendations.append({
                        "type": "strategy_improvement",
                        "strategy": strategy,
                        "recommendation": f"{strategy}策略表现较差，建议调整权重或增加训练数据",
                        "priority": "high"
                    })
                elif avg_performance > 0.8:
                    recommendations.append({
                        "type": "strategy_expansion",
                        "strategy": strategy,
                        "recommendation": f"{strategy}策略表现优秀，建议扩展到更多场景",
                        "priority": "medium"
                    })

        # 数据不足警告
        low_data_strategies = [s for s, h in self.strategy_performance_history.items() if len(h) < 10]
        if low_data_strategies:
            recommendations.append({
                "type": "data_collection",
                "strategies": low_data_strategies,
                "recommendation": "部分策略缺乏足够的训练数据，建议增加测试频率",
                "priority": "medium"
            })

        return recommendations

    # ==================== v5.1: 统计学习引擎 ====================

    def _init_db(self):
        """初始化 SQLite 学习数据库"""
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tool_outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_name TEXT NOT NULL,
                    target_type TEXT DEFAULT 'unknown',
                    success INTEGER NOT NULL,
                    duration REAL DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tool_name
                ON tool_outcomes(tool_name)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_type
                ON tool_outcomes(target_type)
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug(f"SQLite init failed (non-fatal): {e}")

    def _load_from_db(self):
        """从 SQLite 加载历史统计到内存"""
        try:
            conn = sqlite3.connect(self._db_path)
            rows = conn.execute(
                "SELECT tool_name, target_type, success, duration FROM tool_outcomes"
            ).fetchall()
            conn.close()

            for tool, ttype, success, duration in rows:
                key = tool
                self._tool_stats[key]["total_duration"] += duration
                if success:
                    self._tool_stats[key]["success"] += 1
                else:
                    self._tool_stats[key]["fail"] += 1
                if ttype:
                    if success:
                        self._tool_target_stats[ttype][tool]["success"] += 1
                    else:
                        self._tool_target_stats[ttype][tool]["fail"] += 1

            if rows:
                logger.info(f"统计学习: 从数据库加载 {len(rows)} 条历史记录")
        except Exception as e:
            logger.debug(f"SQLite load failed (non-fatal): {e}")

    def record_tool_outcome(self, tool_name: str, target: str = "",
                            success: bool = False, duration: float = 0,
                            context: Dict[str, Any] = None):
        """
        记录工具执行结果 — 由 EventBus MLOptimizerSubscriber 调用。

        这是真正的学习数据入口：每次工具执行的成功/失败/耗时都被记录，
        用于后续的工具推荐和参数优化。

        Args:
            tool_name: 工具名称 (如 "nmap", "sqlmap")
            target: 目标地址
            success: 是否成功
            duration: 执行耗时秒数
            context: 额外上下文
        """
        # 分类目标类型
        target_type = self._classify_target_type_simple(target)

        # 更新内存统计
        self._tool_stats[tool_name]["total_duration"] += duration
        if success:
            self._tool_stats[tool_name]["success"] += 1
        else:
            self._tool_stats[tool_name]["fail"] += 1

        self._tool_target_stats[target_type][tool_name]["success" if success else "fail"] += 1

        # 持久化到 SQLite
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO tool_outcomes (tool_name, target_type, success, duration, timestamp) VALUES (?,?,?,?,?)",
                (tool_name, target_type, int(success), duration, time.time()),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug(f"SQLite insert failed (non-fatal): {e}")

    def _classify_target_type_simple(self, target: str) -> str:
        """简单目标类型分类"""
        if not target:
            return "unknown"
        t = target.lower()
        if t.startswith("http") or ":80" in t or ":443" in t or ":8080" in t:
            return "web"
        if re.match(r'^\d+\.\d+\.\d+\.\d+(/\d+)?$', t):
            return "network"
        if "." in t and not t.startswith("/"):
            return "domain"
        if t.startswith("/") or t.endswith((".elf", ".bin", ".exe")):
            return "binary"
        return "unknown"

    def get_tool_success_rate(self, tool_name: str) -> float:
        """获取工具的历史成功率"""
        stats = self._tool_stats.get(tool_name)
        if not stats:
            return 0.5  # 无数据时返回中性值
        total = stats["success"] + stats["fail"]
        if total == 0:
            return 0.5
        return stats["success"] / total

    def get_tool_avg_duration(self, tool_name: str) -> float:
        """获取工具的平均执行时间"""
        stats = self._tool_stats.get(tool_name)
        if not stats:
            return 0
        total = stats["success"] + stats["fail"]
        if total == 0:
            return 0
        return stats["total_duration"] / total

    def recommend_tools_for_target(self, target_type: str, top_n: int = 5) -> List[Dict[str, Any]]:
        """
        基于历史数据推荐最适合目标类型的工具。

        真正的统计学习：根据同类目标的历史成功率排序推荐。

        Args:
            target_type: 目标类型 (web, network, domain, binary)
            top_n: 返回前N个推荐

        Returns:
            按推荐度排序的工具列表
        """
        type_stats = self._tool_target_stats.get(target_type, {})
        if not type_stats:
            # 回退到全局统计
            type_stats = dict(self._tool_stats)

        recommendations = []
        for tool, stats in type_stats.items():
            total = stats.get("success", 0) + stats.get("fail", 0)
            if total < 1:
                continue
            success_rate = stats.get("success", 0) / total
            recommendations.append({
                "tool": tool,
                "success_rate": round(success_rate, 3),
                "total_uses": total,
                "confidence": min(1.0, total / 10),  # 10次使用达到满置信
            })

        # 按成功率 × 置信度排序
        recommendations.sort(key=lambda r: r["success_rate"] * r["confidence"], reverse=True)
        return recommendations[:top_n]

    def get_learning_summary(self) -> Dict[str, Any]:
        """获取统计学习摘要"""
        total_records = sum(s["success"] + s["fail"] for s in self._tool_stats.values())
        tool_count = len(self._tool_stats)
        target_types = list(self._tool_target_stats.keys())

        top_tools = []
        for tool, stats in self._tool_stats.items():
            total = stats["success"] + stats["fail"]
            if total >= 3:
                top_tools.append({
                    "tool": tool,
                    "success_rate": round(stats["success"] / total, 3),
                    "uses": total,
                    "avg_duration": round(stats["total_duration"] / total, 1),
                })
        top_tools.sort(key=lambda t: t["success_rate"], reverse=True)

        return {
            "total_records": total_records,
            "unique_tools": tool_count,
            "target_types": target_types,
            "db_path": self._db_path,
            "top_tools": top_tools[:10],
        }


# 全局ML策略优化器实例
ml_strategy_optimizer = MLStrategyOptimizer()
