"""
链式推理模块

支持深度推理链和知识图谱的推理引擎。
集成Sequential Thinking MCP工具。
实现自主推理和"灵光一闪"创新能力。
"""

from .knowledge_graph import VulnerabilityKnowledgeGraph, VulnerabilityType, AttackChain
from .chain_engine import ChainReasoningEngine, ReasoningStep
from .sequential_integration import SequentialThinkingIntegrator
from .autonomous_engine import AutonomousReasoningEngine, AutonomousInsight

__all__ = [
    'VulnerabilityKnowledgeGraph',
    'VulnerabilityType',
    'AttackChain',
    'ChainReasoningEngine',
    'ReasoningStep',
    'SequentialThinkingIntegrator',
    'AutonomousReasoningEngine',
    'AutonomousInsight'
]
