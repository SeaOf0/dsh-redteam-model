#!/usr/bin/env python3
"""
策略引擎模块

提供智能化攻击策略选择和执行:
- 基于目标特征的策略推荐
- 动态策略调整
- 历史成功率学习
- 多阶段攻击编排
"""

import logging
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import random

logger = logging.getLogger(__name__)


class StrategyType(Enum):
    """策略类型"""
    RECONNAISSANCE = "reconnaissance"        # 信息收集
    WEB_ATTACK = "web_attack"                # Web应用攻击
    NETWORK_ATTACK = "network_attack"        # 网络攻击
    PASSWORD_ATTACK = "password_attack"      # 密码攻击
    EXPLOIT = "exploit"                      # 漏洞利用
    POST_EXPLOITATION = "post_exploitation"  # 后渗透
    CTF_SOLVE = "ctf_solve"                  # CTF解题
    APT_CAMPAIGN = "apt_campaign"            # APT模拟


@dataclass
class StrategyStep:
    """策略步骤"""
    name: str
    tool: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None  # 执行条件
    parallel: bool = False           # 是否可并行
    timeout: int = 300
    required: bool = True            # 是否必需

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tool": self.tool,
            "parameters": self.parameters,
            "condition": self.condition,
            "parallel": self.parallel,
            "timeout": self.timeout,
            "required": self.required
        }


@dataclass
class Strategy:
    """攻击策略"""
    strategy_id: str
    name: str
    description: str
    strategy_type: StrategyType
    steps: List[StrategyStep] = field(default_factory=list)

    # 适用条件
    target_types: List[str] = field(default_factory=list)  # web, network, binary
    tags: List[str] = field(default_factory=list)

    # 效果评估
    success_count: int = 0
    failure_count: int = 0
    avg_execution_time: float = 0.0

    def get_success_rate(self) -> float:
        """获取成功率"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5  # 默认50%
        return self.success_count / total

    def update_stats(self, success: bool, execution_time: float):
        """更新统计信息"""
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1

        # 滑动平均执行时间
        total = self.success_count + self.failure_count
        self.avg_execution_time = (
            (self.avg_execution_time * (total - 1) + execution_time) / total
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.strategy_id,
            "name": self.name,
            "description": self.description,
            "type": self.strategy_type.value,
            "steps": [s.to_dict() for s in self.steps],
            "target_types": self.target_types,
            "tags": self.tags,
            "success_rate": self.get_success_rate(),
            "avg_time": self.avg_execution_time
        }


class StrategyEngine:
    """策略引擎 - 智能选择和执行攻击策略"""

    def __init__(self):
        """初始化策略引擎"""
        self._strategies: Dict[str, Strategy] = {}
        self._history: List[Dict[str, Any]] = []

        # 注册内置策略
        self._register_builtin_strategies()

        logger.info(f"策略引擎初始化完成, 已注册 {len(self._strategies)} 个策略")

    def _register_builtin_strategies(self):
        """注册内置策略"""

        # 1. Web综合扫描策略
        self.register_strategy(Strategy(
            strategy_id="web_comprehensive",
            name="Web综合安全评估",
            description="全面的Web应用安全测试流程",
            strategy_type=StrategyType.WEB_ATTACK,
            target_types=["web"],
            tags=["comprehensive", "web", "automated"],
            steps=[
                StrategyStep(
                    name="技术识别",
                    tool="whatweb_scan",
                    parameters={"aggression": "1"},
                    timeout=60
                ),
                StrategyStep(
                    name="目录扫描",
                    tool="gobuster_scan",
                    parameters={"mode": "dir"},
                    timeout=180
                ),
                StrategyStep(
                    name="漏洞扫描",
                    tool="nuclei_web_scan",
                    parameters={"scan_type": "comprehensive"},
                    timeout=300
                ),
                StrategyStep(
                    name="SQL注入检测",
                    tool="sqlmap_scan",
                    parameters={"additional_args": "--batch --level=2"},
                    condition="has_forms",
                    timeout=300
                ),
            ]
        ))

        # 2. 网络渗透策略
        self.register_strategy(Strategy(
            strategy_id="network_pentest",
            name="网络渗透测试",
            description="针对网络服务的渗透测试流程",
            strategy_type=StrategyType.NETWORK_ATTACK,
            target_types=["network", "ip"],
            tags=["network", "pentest", "services"],
            steps=[
                StrategyStep(
                    name="端口扫描",
                    tool="nmap_scan",
                    parameters={"scan_type": "-sV", "ports": "1-10000"},
                    timeout=300
                ),
                StrategyStep(
                    name="服务枚举",
                    tool="nmap_scan",
                    parameters={"scan_type": "-sC", "additional_args": "--script=default"},
                    timeout=300
                ),
                StrategyStep(
                    name="漏洞扫描",
                    tool="nuclei_network_scan",
                    parameters={"scan_type": "full"},
                    timeout=300
                ),
            ]
        ))

        # 3. CTF快速解题策略
        self.register_strategy(Strategy(
            strategy_id="ctf_quick_solve",
            name="CTF快速解题",
            description="针对CTF比赛优化的快速攻击流程",
            strategy_type=StrategyType.CTF_SOLVE,
            target_types=["web", "network", "binary"],
            tags=["ctf", "fast", "competition"],
            steps=[
                StrategyStep(
                    name="快速端口扫描",
                    tool="nmap_scan",
                    parameters={"scan_type": "-sS", "ports": "1-10000", "time_constraint": "quick"},
                    timeout=60
                ),
                StrategyStep(
                    name="技术识别",
                    tool="whatweb_scan",
                    parameters={},
                    parallel=True,
                    timeout=30
                ),
                StrategyStep(
                    name="目录扫描",
                    tool="gobuster_scan",
                    parameters={"wordlist": "/usr/share/wordlists/dirb/small.txt"},
                    parallel=True,
                    timeout=60
                ),
                StrategyStep(
                    name="漏洞快扫",
                    tool="nuclei_scan",
                    parameters={"severity": "critical,high"},
                    timeout=120
                ),
            ]
        ))

        # 4. 密码攻击策略
        self.register_strategy(Strategy(
            strategy_id="password_attack",
            name="密码攻击",
            description="针对认证服务的密码攻击",
            strategy_type=StrategyType.PASSWORD_ATTACK,
            target_types=["network"],
            tags=["password", "brute-force", "credential"],
            steps=[
                StrategyStep(
                    name="服务识别",
                    tool="nmap_scan",
                    parameters={"ports": "21,22,23,25,110,143,445,3306,3389,5432"},
                    timeout=60
                ),
                StrategyStep(
                    name="SSH爆破",
                    tool="hydra_attack",
                    parameters={"service": "ssh"},
                    condition="has_ssh",
                    timeout=300
                ),
                StrategyStep(
                    name="FTP爆破",
                    tool="hydra_attack",
                    parameters={"service": "ftp"},
                    condition="has_ftp",
                    timeout=300
                ),
            ]
        ))

        # 5. APT模拟策略
        self.register_strategy(Strategy(
            strategy_id="apt_simulation",
            name="APT攻击模拟",
            description="模拟APT攻击的完整流程",
            strategy_type=StrategyType.APT_CAMPAIGN,
            target_types=["web", "network"],
            tags=["apt", "advanced", "multi-stage"],
            steps=[
                StrategyStep(
                    name="侦察",
                    tool="comprehensive_recon",
                    parameters={"domain_enum": True, "port_scan": True},
                    timeout=600
                ),
                StrategyStep(
                    name="初始访问",
                    tool="adaptive_web_penetration",
                    parameters={},
                    timeout=600
                ),
                StrategyStep(
                    name="权限提升",
                    tool="searchsploit_search",
                    parameters={"term": "privilege escalation"},
                    condition="has_shell",
                    timeout=120
                ),
            ]
        ))

        # 6. 信息收集策略
        self.register_strategy(Strategy(
            strategy_id="recon_comprehensive",
            name="综合信息收集",
            description="全面的信息收集和OSINT",
            strategy_type=StrategyType.RECONNAISSANCE,
            target_types=["domain", "web", "network"],
            tags=["recon", "osint", "enumeration"],
            steps=[
                StrategyStep(
                    name="子域名枚举",
                    tool="subfinder_scan",
                    parameters={},
                    parallel=True,
                    timeout=180
                ),
                StrategyStep(
                    name="DNS枚举",
                    tool="dnsrecon_scan",
                    parameters={},
                    parallel=True,
                    timeout=180
                ),
                StrategyStep(
                    name="OSINT收集",
                    tool="theharvester_osint",
                    parameters={"sources": "google,bing,linkedin"},
                    timeout=180
                ),
                StrategyStep(
                    name="端口扫描",
                    tool="masscan_fast_scan",
                    parameters={"rate": "1000"},
                    timeout=120
                ),
            ]
        ))

    def register_strategy(self, strategy: Strategy):
        """注册策略"""
        self._strategies[strategy.strategy_id] = strategy
        logger.debug(f"注册策略: {strategy.strategy_id}")

    def get_strategy(self, strategy_id: str) -> Optional[Strategy]:
        """获取策略"""
        return self._strategies.get(strategy_id)

    def list_strategies(
        self,
        strategy_type: Optional[StrategyType] = None,
        target_type: Optional[str] = None
    ) -> List[Strategy]:
        """列出策略"""
        strategies = list(self._strategies.values())

        if strategy_type:
            strategies = [s for s in strategies if s.strategy_type == strategy_type]

        if target_type:
            strategies = [s for s in strategies if target_type in s.target_types]

        return strategies

    def recommend_strategy(
        self,
        target: str,
        target_type: str = "unknown",
        context: Optional[Dict[str, Any]] = None
    ) -> List[Strategy]:
        """
        推荐策略

        Args:
            target: 目标
            target_type: 目标类型
            context: 上下文信息

        Returns:
            推荐的策略列表(按优先级排序)
        """
        context = context or {}

        # 获取适用的策略
        candidates = []
        for strategy in self._strategies.values():
            score = self._calculate_strategy_score(strategy, target, target_type, context)
            if score > 0:
                candidates.append((strategy, score))

        # 按分数排序
        candidates.sort(key=lambda x: x[1], reverse=True)

        recommended = [s for s, _ in candidates[:5]]

        logger.info(f"为目标 {target} 推荐 {len(recommended)} 个策略")
        return recommended

    def _calculate_strategy_score(
        self,
        strategy: Strategy,
        target: str,
        target_type: str,
        context: Dict[str, Any]
    ) -> float:
        """计算策略得分"""
        score = 0.0

        # 目标类型匹配
        if target_type in strategy.target_types or "unknown" in strategy.target_types:
            score += 1.0

        # 历史成功率
        success_rate = strategy.get_success_rate()
        score += success_rate * 2.0

        # CTF模式偏好快速策略
        if context.get("mode") == "ctf" and "fast" in strategy.tags:
            score += 1.5

        # 执行时间偏好
        if context.get("time_limit"):
            time_limit = context["time_limit"]
            if strategy.avg_execution_time > 0 and strategy.avg_execution_time < time_limit:
                score += 0.5

        return score

    def select_strategy(
        self,
        target: str,
        target_type: str = "unknown",
        strategy_type: Optional[StrategyType] = None
    ) -> Optional[Strategy]:
        """
        选择最佳策略

        Args:
            target: 目标
            target_type: 目标类型
            strategy_type: 指定策略类型

        Returns:
            最佳策略
        """
        recommended = self.recommend_strategy(target, target_type)

        if strategy_type:
            recommended = [s for s in recommended if s.strategy_type == strategy_type]

        if recommended:
            selected = recommended[0]
            logger.info(f"选择策略: {selected.name}")
            return selected

        return None

    def record_execution(
        self,
        strategy_id: str,
        success: bool,
        execution_time: float,
        details: Optional[Dict[str, Any]] = None
    ):
        """记录策略执行结果"""
        strategy = self._strategies.get(strategy_id)
        if strategy:
            strategy.update_stats(success, execution_time)

        self._history.append({
            "strategy_id": strategy_id,
            "success": success,
            "execution_time": execution_time,
            "timestamp": time.time(),
            "details": details or {}
        })

        logger.debug(f"记录策略执行: {strategy_id} (成功: {success})")

    def get_execution_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取执行历史"""
        return self._history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """获取引擎统计"""
        total_executions = len(self._history)
        successful = sum(1 for h in self._history if h.get("success", False))

        return {
            "registered_strategies": len(self._strategies),
            "total_executions": total_executions,
            "successful_executions": successful,
            "success_rate": f"{(successful / max(1, total_executions)) * 100:.1f}%",
            "strategy_types": list(set(s.strategy_type.value for s in self._strategies.values()))
        }


# 全局策略引擎
_global_strategy_engine: Optional[StrategyEngine] = None


def get_strategy_engine() -> StrategyEngine:
    """获取全局策略引擎"""
    global _global_strategy_engine
    if _global_strategy_engine is None:
        _global_strategy_engine = StrategyEngine()
    return _global_strategy_engine
