#!/usr/bin/env python3
"""
意图识别模块

分析用户输入，识别攻击意图:
- 目标类型识别 (Web/Network/Binary)
- 攻击阶段识别 (侦察/漏洞扫描/利用/后渗透)
- 工具意图映射
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class IntentType(Enum):
    """意图类型"""
    # 侦察阶段
    RECONNAISSANCE = "reconnaissance"
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    SUBDOMAIN_ENUM = "subdomain_enum"
    OSINT = "osint"

    # Web攻击
    WEB_SCAN = "web_scan"
    DIR_SCAN = "directory_scan"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    FILE_UPLOAD = "file_upload"

    # 网络攻击
    NETWORK_ATTACK = "network_attack"
    PASSWORD_ATTACK = "password_attack"
    SMB_ATTACK = "smb_attack"

    # 漏洞利用
    EXPLOIT = "exploit"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # PWN
    BINARY_ANALYSIS = "binary_analysis"
    PWN_EXPLOIT = "pwn_exploit"

    # CTF
    CTF_SOLVE = "ctf_solve"
    FLAG_HUNT = "flag_hunt"

    # 通用
    COMPREHENSIVE = "comprehensive"
    UNKNOWN = "unknown"


class TargetType(Enum):
    """目标类型"""
    WEB = "web"
    NETWORK = "network"
    BINARY = "binary"
    DOMAIN = "domain"
    CTF = "ctf"
    UNKNOWN = "unknown"


@dataclass
class Intent:
    """识别的意图"""
    intent_type: IntentType
    confidence: float
    target_type: TargetType = TargetType.UNKNOWN
    extracted_target: str = ""
    suggested_tools: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent": self.intent_type.value,
            "confidence": self.confidence,
            "target_type": self.target_type.value,
            "target": self.extracted_target,
            "tools": self.suggested_tools,
            "parameters": self.parameters,
            "reasoning": self.reasoning
        }


class IntentAnalyzer:
    """意图分析器"""

    # 关键词到意图的映射
    INTENT_KEYWORDS = {
        IntentType.PORT_SCAN: [
            "端口", "port", "扫描", "scan", "nmap", "开放", "服务"
        ],
        IntentType.DIR_SCAN: [
            "目录", "directory", "路径", "path", "gobuster", "dirsearch",
            "扫描目录", "文件", "备份"
        ],
        IntentType.SQL_INJECTION: [
            "sql", "注入", "injection", "sqlmap", "数据库", "database"
        ],
        IntentType.XSS: [
            "xss", "跨站", "脚本", "script", "弹窗"
        ],
        IntentType.PASSWORD_ATTACK: [
            "密码", "password", "爆破", "brute", "hydra", "弱口令",
            "字典", "wordlist", "登录"
        ],
        IntentType.SUBDOMAIN_ENUM: [
            "子域", "subdomain", "域名", "dns", "枚举"
        ],
        IntentType.EXPLOIT: [
            "漏洞", "exploit", "利用", "cve", "攻击", "getshell", "shell"
        ],
        IntentType.BINARY_ANALYSIS: [
            "二进制", "binary", "逆向", "reverse", "分析", "elf", "pe"
        ],
        IntentType.PWN_EXPLOIT: [
            "pwn", "溢出", "overflow", "rop", "栈", "堆", "shellcode"
        ],
        IntentType.CTF_SOLVE: [
            "ctf", "flag", "解题", "比赛", "靶机", "challenge"
        ],
        IntentType.COMPREHENSIVE: [
            "全面", "综合", "完整", "所有", "全部", "渗透测试"
        ],
        IntentType.OSINT: [
            "信息收集", "osint", "情报", "搜索", "调查"
        ],
    }

    # 意图到工具的映射
    INTENT_TOOLS = {
        IntentType.PORT_SCAN: ["nmap_scan", "masscan_fast_scan"],
        IntentType.DIR_SCAN: ["gobuster_scan", "ffuf_scan", "feroxbuster_scan"],
        IntentType.SQL_INJECTION: ["sqlmap_scan", "intelligent_sql_injection_payloads"],
        IntentType.XSS: ["intelligent_xss_payloads"],
        IntentType.PASSWORD_ATTACK: ["hydra_attack", "john_crack", "hashcat_crack"],
        IntentType.SUBDOMAIN_ENUM: ["subfinder_scan", "amass_enum", "dnsrecon_scan"],
        IntentType.EXPLOIT: ["searchsploit_search", "metasploit_run", "nuclei_scan"],
        IntentType.BINARY_ANALYSIS: ["auto_reverse_analyze", "radare2_analyze_binary"],
        IntentType.PWN_EXPLOIT: ["quick_pwn_check", "pwnpasi_auto_pwn"],
        IntentType.CTF_SOLVE: ["intelligent_ctf_solve", "ctf_quick_scan"],
        IntentType.COMPREHENSIVE: ["comprehensive_recon", "intelligent_vulnerability_assessment"],
        IntentType.OSINT: ["theharvester_osint", "sherlock_search"],
        IntentType.WEB_SCAN: ["whatweb_scan", "nikto_scan", "nuclei_web_scan"],
    }

    # 目标类型识别模式
    TARGET_PATTERNS = {
        TargetType.WEB: [
            r'https?://[^\s]+',
            r'www\.[^\s]+',
        ],
        TargetType.NETWORK: [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}',
        ],
        TargetType.BINARY: [
            r'/[\w/]+\.(elf|exe|bin|so)',
            r'\./[\w]+',
        ],
        TargetType.DOMAIN: [
            r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}',
        ],
        TargetType.CTF: [
            r'ctf[^\s]*',
            r'challenge[^\s]*',
        ],
    }

    def __init__(self):
        """初始化意图分析器"""
        self.history: List[Intent] = []
        logger.info("IntentAnalyzer 初始化完成")

    def analyze(
        self,
        user_input: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Intent:
        """
        分析用户输入，识别意图

        Args:
            user_input: 用户输入文本
            context: 上下文信息

        Returns:
            识别的Intent对象
        """
        context = context or {}
        user_input_lower = user_input.lower()

        # 1. 识别目标类型和提取目标
        target_type, extracted_target = self._extract_target(user_input)

        # 2. 识别意图类型
        intent_type, confidence, reasoning = self._identify_intent(user_input_lower, context)

        # 3. 获取建议工具
        suggested_tools = self._get_suggested_tools(intent_type, target_type)

        # 4. 提取参数
        parameters = self._extract_parameters(user_input, intent_type)

        intent = Intent(
            intent_type=intent_type,
            confidence=confidence,
            target_type=target_type,
            extracted_target=extracted_target,
            suggested_tools=suggested_tools,
            parameters=parameters,
            reasoning=reasoning
        )

        # 记录历史
        self.history.append(intent)

        logger.info(f"识别意图: {intent_type.value} (置信度: {confidence:.2f})")
        return intent

    def _extract_target(self, text: str) -> Tuple[TargetType, str]:
        """提取目标类型和目标"""
        for target_type, patterns in self.TARGET_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return target_type, match.group(0)

        return TargetType.UNKNOWN, ""

    def _identify_intent(
        self,
        text: str,
        context: Dict[str, Any]
    ) -> Tuple[IntentType, float, str]:
        """识别意图类型"""
        scores: Dict[IntentType, float] = {}

        # 基于关键词评分
        for intent_type, keywords in self.INTENT_KEYWORDS.items():
            score = 0
            matched_keywords = []
            for keyword in keywords:
                if keyword in text:
                    score += 1
                    matched_keywords.append(keyword)

            if score > 0:
                scores[intent_type] = score / len(keywords)
                scores[intent_type] = min(scores[intent_type] * 2, 1.0)

        if not scores:
            return IntentType.UNKNOWN, 0.3, "未能识别明确意图"

        # 获取最高分意图
        best_intent = max(scores.items(), key=lambda x: x[1])
        intent_type = best_intent[0]
        confidence = best_intent[1]

        # 生成推理说明
        reasoning = f"基于关键词匹配识别为 {intent_type.value}"

        return intent_type, confidence, reasoning

    def _get_suggested_tools(
        self,
        intent_type: IntentType,
        target_type: TargetType
    ) -> List[str]:
        """获取建议的工具"""
        tools = self.INTENT_TOOLS.get(intent_type, []).copy()

        # 根据目标类型调整
        if target_type == TargetType.WEB:
            if "whatweb_scan" not in tools:
                tools.insert(0, "whatweb_scan")
        elif target_type == TargetType.NETWORK:
            if "nmap_scan" not in tools:
                tools.insert(0, "nmap_scan")
        elif target_type == TargetType.BINARY:
            if "quick_pwn_check" not in tools:
                tools.insert(0, "quick_pwn_check")

        return tools[:5]  # 最多返回5个工具

    def _extract_parameters(
        self,
        text: str,
        intent_type: IntentType
    ) -> Dict[str, Any]:
        """提取参数"""
        params = {}

        # 提取端口
        port_match = re.search(r'端口\s*[:\s]*(\d+(?:,\d+)*)', text)
        if port_match:
            params["ports"] = port_match.group(1)

        # 提取用户名
        user_match = re.search(r'用户[名]?\s*[:\s]*(\w+)', text)
        if user_match:
            params["username"] = user_match.group(1)

        # 提取深度/级别
        if "深度" in text or "全面" in text or "完整" in text:
            params["depth"] = "thorough"
        elif "快速" in text or "简单" in text:
            params["depth"] = "quick"

        return params

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取历史意图"""
        return [i.to_dict() for i in self.history[-limit:]]

    def suggest_next_intent(self, current_intent: Intent) -> List[str]:
        """基于当前意图建议下一步"""
        suggestions = []

        if current_intent.intent_type == IntentType.PORT_SCAN:
            suggestions.append("发现开放端口后，可进行服务枚举或漏洞扫描")
        elif current_intent.intent_type == IntentType.DIR_SCAN:
            suggestions.append("发现敏感目录后，可尝试SQL注入或文件上传测试")
        elif current_intent.intent_type == IntentType.SUBDOMAIN_ENUM:
            suggestions.append("发现子域名后，可对各子域进行端口扫描和Web测试")

        return suggestions


# 全局实例
_global_analyzer: Optional[IntentAnalyzer] = None


def get_intent_analyzer() -> IntentAnalyzer:
    """获取全局意图分析器"""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = IntentAnalyzer()
    return _global_analyzer
