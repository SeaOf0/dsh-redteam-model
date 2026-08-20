#!/usr/bin/env python3
"""
AI上下文管理器

从 mcp_server.py 提取:
- AIContextManager: 管理持续对话状态
"""

import re
import logging
from typing import Dict, Any, Optional, List

from kali_mcp.core.mcp_session import SessionContext, StrategyEngine

logger = logging.getLogger(__name__)

class AIContextManager:
    """AI上下文管理器 - 管理持续对话状态"""

    def __init__(self):
        self.sessions: Dict[str, SessionContext] = {}
        self.current_session: Optional[SessionContext] = None
        self.strategy_engine = StrategyEngine()
        self.global_knowledge_base = {
            "common_ports": {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 3389: "RDP"},
            "ctf_flag_patterns": [r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"FLAG\{[^}]+\}"],
            "vulnerability_signatures": {},
            "successful_payloads": {}
        }

    def create_session(self, target: str = "", attack_mode: str = "pentest") -> SessionContext:
        """创建新的会话"""
        session = SessionContext(target=target, attack_mode=attack_mode)
        self.sessions[session.session_id] = session
        self.current_session = session
        logger.info(f"Created new session {session.session_id} for target {target}")
        return session

    def get_or_create_session(self, session_id: str = None) -> SessionContext:
        """获取或创建会话"""
        if session_id and session_id in self.sessions:
            self.current_session = self.sessions[session_id]
            self.current_session.update_interaction()
            return self.current_session
        elif self.current_session:
            self.current_session.update_interaction()
            return self.current_session
        else:
            return self.create_session()

    def analyze_user_intent(self, user_message: str) -> Dict[str, Any]:
        """分析用户意图和上下文"""
        intent_analysis = {
            "primary_intent": "unknown",
            "target_extraction": "",
            "urgency_level": "normal",
            "context_switches": [],
            "tool_suggestions": []
        }

        message_lower = user_message.lower()

        # 意图分析
        if any(word in message_lower for word in ["扫描", "scan", "测试", "test"]):
            intent_analysis["primary_intent"] = "security_testing"
        elif any(word in message_lower for word in ["ctf", "解题", "flag", "challenge"]):
            intent_analysis["primary_intent"] = "ctf_solving"
        elif any(word in message_lower for word in ["分析", "analyze", "逆向", "reverse"]):
            intent_analysis["primary_intent"] = "analysis"
        elif any(word in message_lower for word in ["攻击", "exploit", "利用", "pwn"]):
            intent_analysis["primary_intent"] = "exploitation"

        # 目标提取
        import re
        # URL提取
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, user_message)
        if urls:
            intent_analysis["target_extraction"] = urls[0]

        # IP地址提取
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, user_message)
        if ips:
            intent_analysis["target_extraction"] = ips[0]

        # 紧急程度
        if any(word in message_lower for word in ["紧急", "urgent", "快速", "fast", "马上"]):
            intent_analysis["urgency_level"] = "high"
        elif any(word in message_lower for word in ["详细", "comprehensive", "深入", "thorough"]):
            intent_analysis["urgency_level"] = "low"

        return intent_analysis

    def generate_contextual_response(self, session: SessionContext, user_message: str) -> Dict[str, Any]:
        """生成基于上下文的响应建议"""
        intent = self.analyze_user_intent(user_message)
        strategy_analysis = self.strategy_engine.analyze_context(session, user_message)

        response = {
            "session_context": session.get_context_summary(),
            "user_intent": intent,
            "strategy_recommendations": strategy_analysis,
            "contextual_suggestions": [],
            "continuation_options": []
        }

        # 基于历史对话生成建议
        if len(session.conversation_history) > 0:
            last_conversation = session.conversation_history[-1]
            tools_used = last_conversation.get("tools_used", [])

            if "nmap_scan" in tools_used:
                response["continuation_options"].append({
                    "action": "深入服务分析",
                    "description": "基于端口扫描结果进行服务版本检测和漏洞扫描",
                    "tools": ["nuclei_scan", "nikto_scan"]
                })

            if any("sql" in tool for tool in tools_used):
                response["continuation_options"].append({
                    "action": "SQL注入深度利用",
                    "description": "扩大SQL注入攻击面，尝试数据提取和权限提升",
                    "tools": ["sqlmap_scan"]
                })

        # 基于发现的资产生成建议
        for asset_type, assets in session.discovered_assets.items():
            if asset_type == "open_ports" and assets:
                response["contextual_suggestions"].append({
                    "type": "port_analysis",
                    "message": f"发现 {len(assets)} 个开放端口，建议进行服务枚举",
                    "priority": "high"
                })

        return response

    def update_knowledge_base(self, category: str, key: str, value: Any):
        """更新全局知识库"""
        if category not in self.global_knowledge_base:
            self.global_knowledge_base[category] = {}
        self.global_knowledge_base[category][key] = value

    def get_session_insights(self, session_id: str = None) -> Dict[str, Any]:
        """获取会话洞察和建议"""
        session = self.get_or_create_session(session_id)

        insights = {
            "session_summary": session.get_context_summary(),
            "progress_analysis": {
                "completed_phases": len(session.completed_tasks),
                "discovered_assets": len(session.discovered_assets),
                "conversation_depth": len(session.conversation_history)
            },
            "next_recommendations": [],
            "knowledge_gaps": []
        }

        # 分析进展并生成建议
        if len(session.completed_tasks) == 0:
            insights["next_recommendations"].append({
                "action": "开始初始侦察",
                "priority": "high",
                "tools": ["nmap_scan", "analyze_target_intelligence"]
            })
        elif session.target and len(session.discovered_assets) > 0:
            insights["next_recommendations"].append({
                "action": "深入漏洞分析",
                "priority": "medium",
                "tools": ["nuclei_scan", "comprehensive_recon"]
            })

        return insights

