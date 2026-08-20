#!/usr/bin/env python3
"""
意图分析器 (IntentAnalyzer) v2.0

分析用户自然语言输入，提取攻击意图和目标：
- 目标提取（URL、IP、域名等）
- 意图分类（侦察、漏洞扫描、攻击利用等）
- 约束识别（授权、时间限制等）
- 优先级评估
- 上下文推理

作者: SeaOf0
"""

import re
import logging
import json
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class AttackIntent(Enum):
    """攻击意图类型"""
    RECONNAISSANCE = "reconnaissance"        # 信息收集
    VULNERABILITY_SCANNING = "vuln_scan"      # 漏洞扫描
    EXPLOITATION = "exploitation"              # 漏洞利用
    PRIVILEGE_ESCALATION = "privilege_escal"   # 权限提升
    LATERAL_MOVEMENT = "lateral_movement"      # 横向移动
    DATA_EXFILTRATION = "data_exfiltration"    # 数据窃取
    PERSISTENCE = "persistence"                # 持久化
    COVERAGE_ANALYSIS = "coverage_analysis"    # 覆盖分析
    FULL_COMPROMISE = "full_compromise"        # 完全攻陷
    CTF_SOLVING = "ctf_solving"               # CTF解题
    APT_SIMULATION = "apt_simulation"          # APT模拟


class TargetType(Enum):
    """目标类型"""
    URL = "url"                    # URL（Web应用）
    IP_ADDRESS = "ip"              # IP地址
    DOMAIN = "domain"              # 域名
    NETWORK_RANGE = "network"       # 网络段
    FILE = "file"                  # 文件
    BINARY = "binary"              # 二进制文件
    UNKNOWN = "unknown"            # 未知


class ConstraintType(Enum):
    """约束类型"""
    AUTHORIZATION = "authorization"     # 授权要求
    TIME_LIMIT = "time_limit"           # 时间限制
    SCOPE = "scope"                     # 测试范围
    IMPACT_LEVEL = "impact_level"       # 影响级别
    RESOURCE_LIMIT = "resource_limit"    # 资源限制
    LEGAL = "legal"                     # 法律约束


@dataclass
class TargetInfo:
    """目标信息"""
    original: str                  # 原始输入
    type: TargetType               # 目标类型
    value: str                     # 提取的值
    protocol: Optional[str] = None  # 协议（http, https等）
    port: Optional[int] = None      # 端口
    path: Optional[str] = None      # 路径

    # 额外属性
    is_ctf: bool = False            # 是否是CTF目标
    is_internal: bool = False       # 是否是内网目标
    confidence: float = 1.0         # 置信度（0-1）


@dataclass
class IntentAnalysis:
    """意图分析结果"""
    user_input: str                 # 原始用户输入
    intent: AttackIntent            # 主要意图
    targets: List[TargetInfo]       # 目标列表
    constraints: List[Dict]         # 约束列表
    priority: int = 5               # 优先级（1-10）
    confidence: float = 0.0         # 分析置信度

    # 推理结果
    suggested_strategy: Optional[str] = None      # 建议策略
    estimated_duration: Optional[str] = None       # 预估时长
    required_tools: List[str] = field(default_factory=list)  # 需要的工具

    # 元数据
    analysis_time: datetime = field(default_factory=datetime.now)
    reasoning: List[str] = field(default_factory=list)  # 推理过程


@dataclass
class ContextHint:
    """上下文提示"""
    keywords: Set[str]             # 关键词
    patterns: List[str]            # 正则模式
    intent: AttackIntent           # 对应意图
    weight: float = 1.0            # 权重


# ==================== 意图分析器 ====================

class IntentAnalyzer:
    """
    意图分析器

    分析用户自然语言输入，理解攻击意图和目标
    """

    def __init__(self):
        """初始化意图分析器"""
        # 关键词-意图映射
        self._intent_keywords = self._init_intent_keywords()

        # 上下文提示
        self._context_hints = self._init_context_hints()

        # 正则模式
        self._target_patterns = self._init_target_patterns()

        # CTF平台域名
        self._ctf_platforms = {
            "ctf", "hackthebox", "tryhackme", "portswigger",
            "picoctf", "dqctf", "nus", "dasctf"
        }

        logger.info("IntentAnalyzer初始化完成")

    def analyze(self, user_input: str) -> IntentAnalysis:
        """
        分析用户输入

        Args:
            user_input: 用户输入（自然语言）

        Returns:
            意图分析结果
        """
        logger.info(f"分析用户输入: {user_input}")

        reasoning = []

        # 1. 提取目标
        targets = self._extract_targets(user_input)
        reasoning.append(f"提取到{len(targets)}个目标")

        # 2. 识别意图
        intent = self._identify_intent(user_input, targets)
        reasoning.append(f"识别意图: {intent.value}")

        # 3. 检测约束
        constraints = self._detect_constraints(user_input)
        reasoning.append(f"检测到{len(constraints)}个约束")

        # 4. 评估优先级
        priority = self._assess_priority(user_input, intent)
        reasoning.append(f"优先级: {priority}")

        # 5. 生成建议
        strategy = self._suggest_strategy(intent, targets)
        required_tools = self._suggest_tools(intent, targets)

        # 6. 计算置信度
        confidence = self._calculate_confidence(targets, intent)

        return IntentAnalysis(
            user_input=user_input,
            intent=intent,
            targets=targets,
            constraints=constraints,
            priority=priority,
            confidence=confidence,
            suggested_strategy=strategy,
            required_tools=required_tools,
            reasoning=reasoning
        )

    def _extract_targets(self, user_input: str) -> List[TargetInfo]:
        """提取目标"""
        targets = []
        seen = set()

        # 尝试各种模式
        for pattern_name, pattern in self._target_patterns.items():
            matches = pattern.finditer(user_input)

            for match in matches:
                value = match.group(0)

                # 去重（检查是否已处理）
                if value.lower() in seen:
                    continue

                # 分析目标
                target_info = self._analyze_target(value)
                if target_info:
                    seen.add(value.lower())  # 只有成功创建TargetInfo才加入seen
                    targets.append(target_info)

        # 如果没有找到显式目标，尝试提取IP/域名
        if not targets:
            # 提取IP地址
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
            for match in re.finditer(ip_pattern, user_input):
                value = match.group(0)
                if value.lower() not in seen:
                    seen.add(value.lower())
                    targets.append(TargetInfo(
                        original=value,
                        type=TargetType.IP_ADDRESS,
                        value=value,
                        is_internal=self._is_internal_ip(value)
                    ))

            # 提取域名（不使用\b以支持中文环境）
            domain_pattern = r'(?<!\w)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}(?!\w)'
            for match in re.finditer(domain_pattern, user_input):
                value = match.group(0)
                if value.lower() not in seen and '.' in value:
                    seen.add(value.lower())
                    targets.append(TargetInfo(
                        original=value,
                        type=TargetType.DOMAIN,
                        value=value,
                        is_ctf=self._is_ctf_domain(value)
                    ))

        return targets

    def _analyze_target(self, value: str) -> Optional[TargetInfo]:
        """分析单个目标"""
        # 尝试解析为URL
        if value.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(value)
                return TargetInfo(
                    original=value,
                    type=TargetType.URL,
                    value=value,
                    protocol=parsed.scheme,
                    port=None if parsed.port is None else int(parsed.port),
                    path=parsed.path,
                    is_ctf=self._is_ctf_domain(parsed.netloc)
                )
            except Exception:
                pass

        # 尝试解析为IP:PORT
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', value):
            ip, port = value.split(':')
            return TargetInfo(
                original=value,
                type=TargetType.IP_ADDRESS,
                value=ip,
                port=int(port),
                is_internal=self._is_internal_ip(ip)
            )

        return None

    def _identify_intent(self, user_input: str, targets: List[TargetInfo]) -> AttackIntent:
        """识别攻击意图"""
        input_lower = user_input.lower()
        scores = {}

        # 基于关键词评分
        for intent, keywords in self._intent_keywords.items():
            score = 0
            for keyword in keywords:
                if keyword in input_lower:
                    score += 1

            # 检查上下文提示
            for hint in self._context_hints:
                if hint.intent == intent:
                    for pattern in hint.patterns:
                        if re.search(pattern, user_input, re.IGNORECASE):
                            score += hint.weight

            scores[intent] = score

        # 选择得分最高的意图
        if scores:
            best_intent = max(scores.items(), key=lambda x: x[1])[0]
            if scores[best_intent] > 0:
                return best_intent

        # 基于目标类型默认意图
        if targets:
            target = targets[0]
            if target.is_ctf:
                return AttackIntent.CTF_SOLVING
            if target.type == TargetType.BINARY:
                return AttackIntent.EXPLOITATION
            if target.type == TargetType.FILE:
                return AttackIntent.RECONNAISSANCE

        return AttackIntent.RECONNAISSANCE  # 默认意图

    def _detect_constraints(self, user_input: str) -> List[Dict]:
        """检测约束"""
        constraints = []
        input_lower = user_input.lower()

        # 时间约束
        time_keywords = ["分钟", "小时内", "小时内", "小时", "秒内", "快速", "急"]
        if any(kw in input_lower for kw in time_keywords):
            constraints.append({
                "type": ConstraintType.TIME_LIMIT,
                "description": "时间限制",
                "mode": "fast"
            })

        # 授权约束
        auth_keywords = ["授权", "许可", "允许", "合法", "正式"]
        if any(kw in input_lower for kw in auth_keywords):
            constraints.append({
                "type": ConstraintType.AUTHORIZATION,
                "description": "需要授权确认"
            })

        # 范围约束
        scope_keywords = ["只扫描", "仅", "不要", "避免", "限制"]
        if any(kw in input_lower for kw in scope_keywords):
            constraints.append({
                "type": ConstraintType.SCOPE,
                "description": "范围限制"
            })

        # CTF模式
        if "ctf" in input_lower or any(platform in user_input for platform in ["pico", "dq", "das"]):
            constraints.append({
                "type": ConstraintType.TIME_LIMIT,
                "description": "CTF竞赛模式",
                "mode": "aggressive"
            })

        return constraints

    def _assess_priority(self, user_input: str, intent: AttackIntent) -> int:
        """评估优先级（1-10）"""
        priority = 5  # 默认中等优先级
        input_lower = user_input.lower()

        # 高优先级关键词
        high_priority_keywords = ["紧急", "重要", "关键", "立即", "马上", "ctf", "flag"]
        if any(kw in input_lower for kw in high_priority_keywords):
            priority = 8

        # 低优先级关键词
        low_priority_keywords = ["后台", "稍后", "有空", "慢速", "测试"]
        if any(kw in input_lower for kw in low_priority_keywords):
            priority = 3

        # 根据意图调整
        if intent == AttackIntent.CTF_SOLVING:
            priority = max(priority, 7)
        elif intent == AttackIntent.APT_SIMULATION:
            priority = min(priority, 6)

        return min(10, max(1, priority))

    def _suggest_strategy(self, intent: AttackIntent, targets: List[TargetInfo]) -> str:
        """建议策略"""
        if intent == AttackIntent.CTF_SOLVING:
            return "ctf_intensive"
        elif intent == AttackIntent.APT_SIMULATION:
            return "comprehensive_apt"
        elif intent == AttackIntent.RECONNAISSANCE:
            return "fast_recon"
        elif intent == AttackIntent.VULNERABILITY_SCANNING:
            return "vuln_scan"
        elif intent == AttackIntent.EXPLOITATION:
            return "exploit_chain"
        else:
            return "balanced"

    def _suggest_tools(self, intent: AttackIntent, targets: List[TargetInfo]) -> List[str]:
        """建议工具"""
        tools = []

        if intent == AttackIntent.RECONNAISSANCE:
            tools = ["nmap_scan", "subfinder_scan", "whatweb_scan"]
        elif intent == AttackIntent.VULNERABILITY_SCANNING:
            tools = ["nuclei_scan", "nikto_scan", "sqlmap_scan"]
        elif intent == AttackIntent.EXPLOITATION:
            tools = ["metasploit_run", "searchsploit_search"]
        elif intent == AttackIntent.CTF_SOLVING:
            tools = ["intelligent_ctf_solve", "ctf_web_attack"]
        else:
            tools = ["nmap_scan", "nuclei_scan"]

        # 根据目标类型调整
        for target in targets:
            if target.type == TargetType.URL:
                tools.extend(["gobuster_scan", "dirb_scan"])
            elif target.type == TargetType.DOMAIN:
                tools.extend(["amass_enum", "dnsrecon_scan"])

        # 去重
        return list(set(tools))

    def _calculate_confidence(self, targets: List[TargetInfo], intent: AttackIntent) -> float:
        """计算分析置信度"""
        confidence = 0.5  # 基础置信度

        # 有目标 -> 提高置信度
        if targets:
            confidence += 0.2

        # 目标类型明确 -> 提高置信度
        if targets and targets[0].type != TargetType.UNKNOWN:
            confidence += 0.1

        # 意图明确 -> 提高置信度
        if intent != AttackIntent.RECONNAISSANCE:
            confidence += 0.1

        return min(1.0, confidence)

    # ==================== 辅助方法 ====================

    def _is_internal_ip(self, ip: str) -> bool:
        """检查是否是内网IP"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first_octet = int(parts[0])

            # RFC1918私有地址
            if first_octet == 10:
                return True
            if first_octet == 172:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            if first_octet == 192 and int(parts[1]) == 168:
                return True

            return False
        except (ValueError, IndexError):
            return False

    def _is_ctf_domain(self, domain: str) -> bool:
        """检查是否是CTF平台域名"""
        domain_lower = domain.lower()
        return any(platform in domain_lower for platform in self._ctf_platforms)

    @staticmethod
    def _init_intent_keywords() -> Dict[AttackIntent, Set[str]]:
        """初始化意图关键词映射"""
        return {
            AttackIntent.RECONNAISSANCE: {
                "扫描", "侦察", "信息收集", "枚举", "发现", "探测",
                "recon", "scan", "enum", "discover"
            },
            AttackIntent.VULNERABILITY_SCANNING: {
                "漏洞", "vuln", "漏洞扫描", "安全测试", "弱口令",
                "sql注入", "xss", "注入"
            },
            AttackIntent.EXPLOITATION: {
                "利用", "攻击", "exploit", "attack", "getshell",
                "反弹", "shell", "执行命令"
            },
            AttackIntent.PRIVILEGE_ESCALATION: {
                "提权", "权限提升", "privilege", "escalation",
                "root", "administrator", "sudo"
            },
            AttackIntent.LATERAL_MOVEMENT: {
                "横向", "内网", "移动", "lateral", "内网渗透",
                "跳板", "pivot"
            },
            AttackIntent.DATA_EXFILTRATION: {
                "窃取", "数据", "exfil", "下载", "dump",
                "导出", "数据库"
            },
            AttackIntent.CTF_SOLVING: {
                "ctf", "flag", "解题", "题目", "挑战",
                "pico", "hackthebox", "tryhackme"
            },
            AttackIntent.APT_SIMULATION: {
                "apt", "全流程", "完整", "全面", "渗透测试",
                "红队", "攻击链"
            }
        }

    @staticmethod
    def _init_context_hints() -> List[ContextHint]:
        """初始化上下文提示"""
        return [
            ContextHint(
                keywords={"ctf", "flag"},
                patterns=[r'\bctf\b', r'\bflag\b'],
                intent=AttackIntent.CTF_SOLVING,
                weight=2.0
            ),
            ContextHint(
                keywords={"全面", "完整", "apt"},
                patterns=[r'\b全流程\b', r'\bapt\b', r'\b全面'],
                intent=AttackIntent.APT_SIMULATION,
                weight=1.5
            ),
            ContextHint(
                keywords={"漏洞", "扫描"},
                patterns=[r'\bvuln\b', r'\b漏洞'],
                intent=AttackIntent.VULNERABILITY_SCANNING,
                weight=1.0
            )
        ]

    @staticmethod
    def _init_target_patterns() -> Dict[str, re.Pattern]:
        """初始化目标识别正则模式"""
        return {
            "url": re.compile(
                r'https?://(?:[-\w.]|(?:%[0-9a-fA-F]{2}))+[/\w\-\.~:/?#\[\]@!$&\'()*+,;=]*'
            ),
            "ip_with_port": re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b'
            ),
            "cidr": re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'
            ),
            "domain": re.compile(
                r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b'
            )
        }


# ==================== 导出 ====================

__all__ = [
    'IntentAnalyzer',
    'AttackIntent',
    'TargetType',
    'ConstraintType',
    'TargetInfo',
    'IntentAnalysis',
    'ContextHint'
]
