#!/usr/bin/env python3
"""
MCP会话管理和策略引擎

从 mcp_server.py 提取的核心类:
- SessionContext: 会话上下文数据类
- StrategyEngine: 策略引擎
"""

import re
import uuid
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class SessionContext:
    """会话上下文数据类"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    attack_mode: str = "pentest"  # pentest, ctf, analysis
    start_time: datetime = field(default_factory=datetime.now)
    conversation_history: List[Dict[str, Any]] = field(default_factory=list)
    discovered_assets: Dict[str, Any] = field(default_factory=dict)
    completed_tasks: List[str] = field(default_factory=list)
    current_strategy: Optional[str] = None
    context_metadata: Dict[str, Any] = field(default_factory=dict)
    last_interaction: datetime = field(default_factory=datetime.now)

    def update_interaction(self):
        """更新最后交互时间"""
        self.last_interaction = datetime.now()

    def add_conversation(self, user_message: str, ai_response: str, tools_used: List[str] = None):
        """添加对话历史"""
        self.conversation_history.append({
            "timestamp": datetime.now().isoformat(),
            "user_message": user_message,
            "ai_response": ai_response,
            "tools_used": tools_used or [],
            "session_context": {
                "target": self.target,
                "strategy": self.current_strategy,
                "discovered_assets": len(self.discovered_assets)
            }
        })
        self.update_interaction()

    def get_context_summary(self) -> Dict[str, Any]:
        """获取会话上下文摘要"""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "attack_mode": self.attack_mode,
            "duration": str(datetime.now() - self.start_time),
            "total_conversations": len(self.conversation_history),
            "discovered_assets": len(self.discovered_assets),
            "completed_tasks": len(self.completed_tasks),
            "current_strategy": self.current_strategy,
            "last_interaction": self.last_interaction.isoformat()
        }

class StrategyEngine:
    """策略引擎 - 根据上下文选择最佳攻击策略"""

    def __init__(self):
        self.strategies = {
            "web_comprehensive": {
                "description": "全面Web应用安全测试",
                "tools": ["nmap_scan", "gobuster_scan", "sqlmap_scan", "nuclei_web_scan", "nikto_scan"],
                "conditions": ["web_service_detected", "http_ports_open"],
                "complexity": "high",
                "estimated_time": "30-60 minutes"
            },
            "ctf_quick_solve": {
                "description": "CTF快速解题策略",
                "tools": ["ctf_quick_scan", "ctf_web_attack", "get_detected_flags"],
                "conditions": ["ctf_mode", "time_limited"],
                "complexity": "medium",
                "estimated_time": "5-15 minutes"
            },
            "network_recon": {
                "description": "网络侦察和服务发现",
                "tools": ["nmap_scan", "masscan_scan", "nuclei_network_scan"],
                "conditions": ["ip_target", "network_range"],
                "complexity": "medium",
                "estimated_time": "15-30 minutes"
            },
            "pwn_exploitation": {
                "description": "二进制漏洞利用",
                "tools": ["pwnpasi_auto_pwn", "auto_reverse_analyze", "quick_pwn_check"],
                "conditions": ["binary_file", "pwn_challenge"],
                "complexity": "high",
                "estimated_time": "20-45 minutes"
            },
            "adaptive_multi": {
                "description": "自适应多向量攻击",
                "tools": ["analyze_target_intelligence", "comprehensive_recon", "intelligent_smart_scan"],
                "conditions": ["unknown_target", "complex_environment"],
                "complexity": "very_high",
                "estimated_time": "45-90 minutes"
            }
        }

    def analyze_context(self, session: SessionContext, user_input: str) -> Dict[str, Any]:
        """分析当前上下文并推荐策略"""
        analysis = {
            "context_indicators": [],
            "recommended_strategies": [],
            "confidence_scores": {},
            "target_analysis": {}
        }

        # 分析目标类型
        target = session.target.lower() if session.target else user_input.lower()

        # Web应用指标
        if any(indicator in target for indicator in ["http", "www", ".com", ".org", "web"]):
            analysis["context_indicators"].append("web_service_detected")
            analysis["confidence_scores"]["web_comprehensive"] = 0.8

        # CTF指标
        if any(indicator in user_input.lower() for indicator in ["ctf", "flag", "challenge", "解题"]):
            analysis["context_indicators"].append("ctf_mode")
            analysis["confidence_scores"]["ctf_quick_solve"] = 0.9

        # 二进制文件指标
        if any(indicator in user_input.lower() for indicator in [".exe", "binary", "pwn", "二进制"]):
            analysis["context_indicators"].append("binary_file")
            analysis["confidence_scores"]["pwn_exploitation"] = 0.8

        # IP地址或网络指标
        import re
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if re.search(ip_pattern, target):
            analysis["context_indicators"].append("ip_target")
            analysis["confidence_scores"]["network_recon"] = 0.7

        # 复杂或未知目标
        if len(analysis["context_indicators"]) == 0 or "不知道" in user_input:
            analysis["context_indicators"].append("unknown_target")
            analysis["confidence_scores"]["adaptive_multi"] = 0.6

        # 基于置信度排序策略
        sorted_strategies = sorted(
            analysis["confidence_scores"].items(),
            key=lambda x: x[1],
            reverse=True
        )

        analysis["recommended_strategies"] = [
            {
                "strategy": strategy,
                "confidence": confidence,
                "details": self.strategies.get(strategy, {})
            }
            for strategy, confidence in sorted_strategies[:3]
        ]

        return analysis

    def get_strategy_tools(self, strategy_name: str) -> List[str]:
        """获取策略对应的工具列表"""
        return self.strategies.get(strategy_name, {}).get("tools", [])

    def update_strategy_effectiveness(self, strategy_name: str, success_rate: float):
        """更新策略有效性（机器学习反馈）"""
        if strategy_name in self.strategies:
            if "effectiveness" not in self.strategies[strategy_name]:
                self.strategies[strategy_name]["effectiveness"] = []
            self.strategies[strategy_name]["effectiveness"].append(success_rate)

