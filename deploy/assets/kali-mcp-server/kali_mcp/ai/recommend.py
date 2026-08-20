#!/usr/bin/env python3
"""
工具推荐模块

基于目标特征、历史效果和上下文的智能工具推荐:
- 目标类型分析
- 工具效果评分
- 上下文感知推荐
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class Recommendation:
    """推荐结果"""
    tool_name: str
    score: float
    reason: str
    priority: int = 1
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "score": self.score,
            "reason": self.reason,
            "priority": self.priority,
            "parameters": self.parameters
        }


class ToolRecommender:
    """智能工具推荐器"""

    # 目标类型到工具的映射
    TARGET_TOOL_MAP = {
        "web": [
            ("whatweb_scan", 0.9, "技术识别"),
            ("gobuster_scan", 0.85, "目录扫描"),
            ("nikto_scan", 0.8, "Web漏洞扫描"),
            ("nuclei_scan", 0.85, "漏洞检测"),
            ("sqlmap_scan", 0.7, "SQL注入测试"),
        ],
        "network": [
            ("nmap_scan", 0.95, "端口扫描"),
            ("masscan_fast_scan", 0.85, "快速端口扫描"),
            ("arp_scan", 0.7, "ARP发现"),
        ],
        "domain": [
            ("subfinder_scan", 0.9, "子域名发现"),
            ("dnsrecon_scan", 0.85, "DNS枚举"),
            ("theharvester_osint", 0.8, "信息收集"),
        ],
        "binary": [
            ("quick_pwn_check", 0.95, "PWN检查"),
            ("auto_reverse_analyze", 0.9, "逆向分析"),
            ("radare2_analyze_binary", 0.85, "深度分析"),
        ],
        "ctf": [
            ("intelligent_ctf_solve", 0.95, "CTF解题"),
            ("ctf_quick_scan", 0.9, "CTF快速扫描"),
        ],
    }

    # 服务到工具的映射
    SERVICE_TOOL_MAP = {
        "ssh": [("hydra_attack", 0.8, "SSH爆破")],
        "ftp": [("hydra_attack", 0.8, "FTP爆破")],
        "http": [
            ("gobuster_scan", 0.85, "目录扫描"),
            ("nikto_scan", 0.8, "Web扫描"),
        ],
        "https": [
            ("gobuster_scan", 0.85, "目录扫描"),
            ("nuclei_scan", 0.85, "漏洞扫描"),
        ],
        "smb": [("enum4linux_scan", 0.9, "SMB枚举")],
        "mysql": [("sqlmap_scan", 0.75, "数据库测试")],
        "wordpress": [("wpscan_scan", 0.95, "WordPress扫描")],
    }

    # 攻击阶段到工具的映射
    PHASE_TOOL_MAP = {
        "reconnaissance": [
            "nmap_scan", "subfinder_scan", "theharvester_osint",
            "whatweb_scan", "dnsrecon_scan"
        ],
        "scanning": [
            "nuclei_scan", "nikto_scan", "gobuster_scan",
            "masscan_fast_scan"
        ],
        "exploitation": [
            "sqlmap_scan", "metasploit_run", "searchsploit_search"
        ],
        "post_exploitation": [
            "enum4linux_scan", "hydra_attack"
        ],
    }

    def __init__(self):
        """初始化推荐器"""
        self.tool_scores: Dict[str, float] = defaultdict(lambda: 0.5)
        self.tool_success_count: Dict[str, int] = defaultdict(int)
        self.tool_failure_count: Dict[str, int] = defaultdict(int)
        self.history: List[Dict[str, Any]] = []
        logger.info("ToolRecommender 初始化完成")

    def recommend(
        self,
        target: str,
        target_type: str = "unknown",
        context: Optional[Dict[str, Any]] = None,
        limit: int = 5
    ) -> List[Recommendation]:
        """
        推荐工具

        Args:
            target: 目标
            target_type: 目标类型
            context: 上下文信息
            limit: 返回数量限制

        Returns:
            推荐列表
        """
        context = context or {}
        recommendations: List[Recommendation] = []

        # 1. 基于目标类型推荐
        type_recs = self._recommend_by_target_type(target_type)
        recommendations.extend(type_recs)

        # 2. 基于服务推荐
        if "services" in context:
            service_recs = self._recommend_by_services(context["services"])
            recommendations.extend(service_recs)

        # 3. 基于攻击阶段推荐
        if "phase" in context:
            phase_recs = self._recommend_by_phase(context["phase"])
            recommendations.extend(phase_recs)

        # 4. 应用历史效果评分
        for rec in recommendations:
            rec.score *= self.tool_scores[rec.tool_name]

        # 5. 去重并排序
        seen = set()
        unique_recs = []
        for rec in recommendations:
            if rec.tool_name not in seen:
                seen.add(rec.tool_name)
                unique_recs.append(rec)

        # 按分数排序
        unique_recs.sort(key=lambda r: r.score, reverse=True)

        # 设置优先级
        for i, rec in enumerate(unique_recs[:limit]):
            rec.priority = i + 1

        return unique_recs[:limit]

    def _recommend_by_target_type(self, target_type: str) -> List[Recommendation]:
        """基于目标类型推荐"""
        tools = self.TARGET_TOOL_MAP.get(target_type, [])
        return [
            Recommendation(
                tool_name=tool,
                score=score,
                reason=reason
            )
            for tool, score, reason in tools
        ]

    def _recommend_by_services(self, services: List[str]) -> List[Recommendation]:
        """基于服务推荐"""
        recommendations = []
        for service in services:
            service_lower = service.lower()
            for key, tools in self.SERVICE_TOOL_MAP.items():
                if key in service_lower:
                    for tool, score, reason in tools:
                        recommendations.append(
                            Recommendation(
                                tool_name=tool,
                                score=score,
                                reason=f"{reason} (发现{service})"
                            )
                        )
        return recommendations

    def _recommend_by_phase(self, phase: str) -> List[Recommendation]:
        """基于攻击阶段推荐"""
        tools = self.PHASE_TOOL_MAP.get(phase, [])
        return [
            Recommendation(
                tool_name=tool,
                score=0.7,
                reason=f"适用于{phase}阶段"
            )
            for tool in tools
        ]

    def update_score(
        self,
        tool_name: str,
        success: bool,
        findings_count: int = 0
    ):
        """
        更新工具效果评分

        Args:
            tool_name: 工具名称
            success: 是否成功
            findings_count: 发现数量
        """
        if success:
            self.tool_success_count[tool_name] += 1
            # 成功时提升评分
            bonus = min(0.1, findings_count * 0.02)
            self.tool_scores[tool_name] = min(
                1.0,
                self.tool_scores[tool_name] + 0.05 + bonus
            )
        else:
            self.tool_failure_count[tool_name] += 1
            # 失败时降低评分
            self.tool_scores[tool_name] = max(
                0.1,
                self.tool_scores[tool_name] - 0.03
            )

        # 记录历史
        self.history.append({
            "tool": tool_name,
            "success": success,
            "findings": findings_count
        })

        logger.debug(f"更新工具评分: {tool_name} -> {self.tool_scores[tool_name]:.2f}")

    def get_tool_stats(self, tool_name: str) -> Dict[str, Any]:
        """获取工具统计"""
        success = self.tool_success_count[tool_name]
        failure = self.tool_failure_count[tool_name]
        total = success + failure

        return {
            "tool": tool_name,
            "score": self.tool_scores[tool_name],
            "success_count": success,
            "failure_count": failure,
            "success_rate": success / total if total > 0 else 0
        }

    def suggest_tool_chain(
        self,
        target_type: str,
        objective: str = "comprehensive"
    ) -> List[str]:
        """
        建议工具链

        Args:
            target_type: 目标类型
            objective: 目标 (comprehensive/quick/stealth)

        Returns:
            推荐的工具链
        """
        chains = {
            "web": {
                "comprehensive": [
                    "whatweb_scan", "gobuster_scan", "nikto_scan",
                    "nuclei_scan", "sqlmap_scan"
                ],
                "quick": ["whatweb_scan", "gobuster_scan", "nuclei_scan"],
                "stealth": ["whatweb_scan", "nuclei_scan"],
            },
            "network": {
                "comprehensive": [
                    "nmap_scan", "masscan_fast_scan",
                    "nuclei_network_scan", "enum4linux_scan"
                ],
                "quick": ["masscan_fast_scan", "nmap_scan"],
                "stealth": ["nmap_scan"],
            },
            "binary": {
                "comprehensive": [
                    "quick_pwn_check", "auto_reverse_analyze",
                    "radare2_analyze_binary", "pwnpasi_auto_pwn"
                ],
                "quick": ["quick_pwn_check", "auto_reverse_analyze"],
            },
            "ctf": {
                "comprehensive": ["intelligent_ctf_solve"],
                "quick": ["ctf_quick_scan"],
            },
        }

        type_chains = chains.get(target_type, chains.get("web"))
        return type_chains.get(objective, type_chains.get("comprehensive", []))

    def get_all_scores(self) -> Dict[str, float]:
        """获取所有工具评分"""
        return dict(self.tool_scores)


# 全局实例
_global_recommender: Optional[ToolRecommender] = None


def get_tool_recommender() -> ToolRecommender:
    """获取全局工具推荐器"""
    global _global_recommender
    if _global_recommender is None:
        _global_recommender = ToolRecommender()
    return _global_recommender
