#!/usr/bin/env python3
"""
学习反馈模块

记录和分析攻击模式，持续优化策略:
- 攻击结果记录
- 模式识别
- 策略优化建议
"""

import json
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class AttackOutcome(Enum):
    """攻击结果"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


@dataclass
class AttackRecord:
    """攻击记录"""
    timestamp: float
    target_type: str
    tool_name: str
    outcome: AttackOutcome
    findings_count: int
    execution_time: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["outcome"] = self.outcome.value
        return data


@dataclass
class Pattern:
    """识别的模式"""
    pattern_type: str
    description: str
    confidence: float
    occurrences: int
    recommendation: str


class LearningEngine:
    """学习引擎"""

    def __init__(self, data_dir: Optional[str] = None):
        """
        初始化学习引擎

        Args:
            data_dir: 数据存储目录
        """
        self.data_dir = Path(data_dir) if data_dir else Path.home() / ".kali_mcp" / "learning"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.records: List[AttackRecord] = []
        self.patterns: List[Pattern] = []

        # 统计数据
        self.tool_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"success": 0, "failure": 0, "total_time": 0, "total_findings": 0}
        )
        self.target_type_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"attacks": 0, "success": 0}
        )
        self.sequence_stats: Dict[str, int] = defaultdict(int)

        # 加载历史数据
        self._load_history()

        logger.info(f"LearningEngine 初始化完成，数据目录: {self.data_dir}")

    def record_attack(
        self,
        target_type: str,
        tool_name: str,
        outcome: AttackOutcome,
        findings_count: int = 0,
        execution_time: float = 0,
        parameters: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        error_message: str = ""
    ):
        """
        记录攻击结果

        Args:
            target_type: 目标类型
            tool_name: 工具名称
            outcome: 攻击结果
            findings_count: 发现数量
            execution_time: 执行时间
            parameters: 参数
            context: 上下文
            error_message: 错误信息
        """
        record = AttackRecord(
            timestamp=time.time(),
            target_type=target_type,
            tool_name=tool_name,
            outcome=outcome,
            findings_count=findings_count,
            execution_time=execution_time,
            parameters=parameters or {},
            context=context or {},
            error_message=error_message
        )

        self.records.append(record)

        # 更新统计
        self._update_stats(record)

        # 定期保存
        if len(self.records) % 10 == 0:
            self._save_history()

        logger.debug(f"记录攻击: {tool_name} -> {outcome.value}")

    def _update_stats(self, record: AttackRecord):
        """更新统计数据"""
        # 工具统计
        stats = self.tool_stats[record.tool_name]
        if record.outcome == AttackOutcome.SUCCESS:
            stats["success"] += 1
        else:
            stats["failure"] += 1
        stats["total_time"] += record.execution_time
        stats["total_findings"] += record.findings_count

        # 目标类型统计
        type_stats = self.target_type_stats[record.target_type]
        type_stats["attacks"] += 1
        if record.outcome == AttackOutcome.SUCCESS:
            type_stats["success"] += 1

    def analyze_patterns(self) -> List[Pattern]:
        """
        分析攻击模式

        Returns:
            识别的模式列表
        """
        patterns = []

        # 1. 分析工具效果模式
        for tool, stats in self.tool_stats.items():
            total = stats["success"] + stats["failure"]
            if total >= 5:
                success_rate = stats["success"] / total

                if success_rate >= 0.8:
                    patterns.append(Pattern(
                        pattern_type="high_success_tool",
                        description=f"{tool} 成功率很高 ({success_rate:.0%})",
                        confidence=min(1.0, total / 20),
                        occurrences=total,
                        recommendation=f"优先使用 {tool}"
                    ))
                elif success_rate <= 0.2:
                    patterns.append(Pattern(
                        pattern_type="low_success_tool",
                        description=f"{tool} 成功率较低 ({success_rate:.0%})",
                        confidence=min(1.0, total / 20),
                        occurrences=total,
                        recommendation=f"考虑替换 {tool} 或调整参数"
                    ))

        # 2. 分析目标类型模式
        for target_type, stats in self.target_type_stats.items():
            if stats["attacks"] >= 5:
                success_rate = stats["success"] / stats["attacks"]

                if success_rate >= 0.7:
                    patterns.append(Pattern(
                        pattern_type="effective_target_type",
                        description=f"对 {target_type} 目标的攻击效果好",
                        confidence=min(1.0, stats["attacks"] / 20),
                        occurrences=stats["attacks"],
                        recommendation=f"继续当前策略"
                    ))

        # 3. 分析时间模式
        slow_tools = []
        for tool, stats in self.tool_stats.items():
            total = stats["success"] + stats["failure"]
            if total > 0:
                avg_time = stats["total_time"] / total
                if avg_time > 60:
                    slow_tools.append((tool, avg_time))

        if slow_tools:
            patterns.append(Pattern(
                pattern_type="slow_execution",
                description=f"部分工具执行较慢: {', '.join(t[0] for t in slow_tools[:3])}",
                confidence=0.8,
                occurrences=len(slow_tools),
                recommendation="考虑使用快速扫描模式或调整超时设置"
            ))

        self.patterns = patterns
        return patterns

    def get_optimization_suggestions(self) -> List[Dict[str, Any]]:
        """
        获取优化建议

        Returns:
            优化建议列表
        """
        suggestions = []

        # 分析模式
        patterns = self.analyze_patterns()

        for pattern in patterns:
            suggestions.append({
                "type": pattern.pattern_type,
                "description": pattern.description,
                "recommendation": pattern.recommendation,
                "confidence": pattern.confidence
            })

        # 基于发现数量的建议
        high_finding_tools = []
        for tool, stats in self.tool_stats.items():
            total = stats["success"] + stats["failure"]
            if total > 0:
                avg_findings = stats["total_findings"] / total
                if avg_findings >= 5:
                    high_finding_tools.append((tool, avg_findings))

        if high_finding_tools:
            high_finding_tools.sort(key=lambda x: x[1], reverse=True)
            suggestions.append({
                "type": "high_finding_tools",
                "description": "高发现率工具",
                "recommendation": f"优先使用: {', '.join(t[0] for t in high_finding_tools[:3])}",
                "confidence": 0.85
            })

        return suggestions

    def get_tool_effectiveness(self, tool_name: str) -> Dict[str, Any]:
        """
        获取工具效果评估

        Args:
            tool_name: 工具名称

        Returns:
            效果评估数据
        """
        stats = self.tool_stats.get(tool_name, {
            "success": 0, "failure": 0, "total_time": 0, "total_findings": 0
        })

        total = stats["success"] + stats["failure"]

        return {
            "tool": tool_name,
            "total_executions": total,
            "success_count": stats["success"],
            "failure_count": stats["failure"],
            "success_rate": stats["success"] / total if total > 0 else 0,
            "avg_execution_time": stats["total_time"] / total if total > 0 else 0,
            "avg_findings": stats["total_findings"] / total if total > 0 else 0
        }

    def get_best_tools_for_target(
        self,
        target_type: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        获取针对特定目标类型的最佳工具

        Args:
            target_type: 目标类型
            limit: 返回数量

        Returns:
            最佳工具列表
        """
        # 从记录中筛选
        relevant_records = [
            r for r in self.records
            if r.target_type == target_type
        ]

        # 按工具聚合
        tool_performance: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"success": 0, "total": 0, "findings": 0}
        )

        for record in relevant_records:
            perf = tool_performance[record.tool_name]
            perf["total"] += 1
            if record.outcome == AttackOutcome.SUCCESS:
                perf["success"] += 1
            perf["findings"] += record.findings_count

        # 计算评分
        results = []
        for tool, perf in tool_performance.items():
            if perf["total"] >= 2:  # 至少2次使用
                score = (
                    (perf["success"] / perf["total"]) * 0.6 +
                    min(1.0, perf["findings"] / (perf["total"] * 10)) * 0.4
                )
                results.append({
                    "tool": tool,
                    "score": score,
                    "executions": perf["total"],
                    "success_rate": perf["success"] / perf["total"]
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:limit]

    def _save_history(self):
        """保存历史数据"""
        try:
            history_file = self.data_dir / "attack_history.json"

            # 只保存最近1000条记录
            recent_records = self.records[-1000:]

            data = {
                "records": [r.to_dict() for r in recent_records],
                "tool_stats": dict(self.tool_stats),
                "target_type_stats": dict(self.target_type_stats)
            }

            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            logger.debug(f"保存历史数据: {len(recent_records)} 条记录")

        except Exception as e:
            logger.error(f"保存历史数据失败: {e}")

    def _load_history(self):
        """加载历史数据"""
        try:
            history_file = self.data_dir / "attack_history.json"

            if history_file.exists():
                with open(history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # 恢复记录
                for record_data in data.get("records", []):
                    record_data["outcome"] = AttackOutcome(record_data["outcome"])
                    self.records.append(AttackRecord(**record_data))

                # 恢复统计
                for tool, stats in data.get("tool_stats", {}).items():
                    self.tool_stats[tool].update(stats)

                for target_type, stats in data.get("target_type_stats", {}).items():
                    self.target_type_stats[target_type].update(stats)

                logger.info(f"加载历史数据: {len(self.records)} 条记录")

        except Exception as e:
            logger.warning(f"加载历史数据失败: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """获取学习摘要"""
        return {
            "total_records": len(self.records),
            "tools_tracked": len(self.tool_stats),
            "target_types_tracked": len(self.target_type_stats),
            "patterns_identified": len(self.patterns),
            "data_directory": str(self.data_dir)
        }

    def reset(self):
        """重置学习数据"""
        self.records.clear()
        self.patterns.clear()
        self.tool_stats.clear()
        self.target_type_stats.clear()
        self.sequence_stats.clear()

        # 删除历史文件
        history_file = self.data_dir / "attack_history.json"
        if history_file.exists():
            history_file.unlink()

        logger.info("学习数据已重置")


# 全局实例
_global_engine: Optional[LearningEngine] = None


def get_learning_engine() -> LearningEngine:
    """获取全局学习引擎"""
    global _global_engine
    if _global_engine is None:
        _global_engine = LearningEngine()
    return _global_engine
