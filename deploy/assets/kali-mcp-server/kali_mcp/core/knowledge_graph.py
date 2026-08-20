#!/usr/bin/env python3
"""
攻击知识图谱

从 mcp_server.py 提取:
- KnowledgeNode: 知识节点数据类
- KnowledgeRelation: 知识关系数据类
- AttackKnowledgeGraph: 攻击知识图谱
"""

import uuid
import logging
from typing import Dict, Any, Optional, List, Set
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class KnowledgeNode:
    """知识图谱节点数据类"""
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_type: str = ""  # target, tool, vulnerability, technique, strategy
    node_name: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

@dataclass
class KnowledgeRelation:
    """知识图谱关系数据类"""
    relation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_node_id: str = ""
    target_node_id: str = ""
    relation_type: str = ""  # affects, requires, enables, counters, similar_to
    relation_strength: float = 0.0
    evidence_count: int = 0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

class AttackKnowledgeGraph:
    """攻击智能知识图谱"""

    def __init__(self):
        self.nodes: Dict[str, KnowledgeNode] = {}
        self.relations: Dict[str, KnowledgeRelation] = {}
        self.node_index: Dict[str, List[str]] = {}  # 按类型索引节点
        self.relation_index: Dict[str, List[str]] = {}  # 按类型索引关系

        # 图谱参数
        self.min_relation_strength = 0.3
        self.max_nodes_per_type = 1000

        # 预定义知识
        self._initialize_base_knowledge()

    def _initialize_base_knowledge(self):
        """初始化基础攻击知识"""
        # 常见目标类型
        target_types = [
            {"name": "Web应用", "properties": {"common_ports": [80, 443, 8080], "protocols": ["HTTP", "HTTPS"]}},
            {"name": "数据库", "properties": {"common_ports": [3306, 5432, 1433], "protocols": ["MySQL", "PostgreSQL", "MSSQL"]}},
            {"name": "网络设备", "properties": {"common_ports": [22, 23, 161], "protocols": ["SSH", "Telnet", "SNMP"]}},
        ]

        for target_type in target_types:
            self.add_node("target_type", target_type["name"], target_type["properties"], confidence=0.9)

        # 常见工具和技术
        tools_techniques = [
            {"tool": "nmap", "technique": "端口扫描", "effectiveness": {"web": 0.9, "network": 0.95, "database": 0.8}},
            {"tool": "sqlmap", "technique": "SQL注入", "effectiveness": {"web": 0.9, "database": 0.95, "network": 0.3}},
            {"tool": "dirb", "technique": "目录枚举", "effectiveness": {"web": 0.85, "network": 0.2, "database": 0.1}},
        ]

        for item in tools_techniques:
            tool_node = self.add_node("tool", item["tool"], {"type": "penetration_testing"}, confidence=0.9)
            technique_node = self.add_node("technique", item["technique"], item["effectiveness"], confidence=0.9)
            self.add_relation(tool_node, technique_node, "implements", strength=0.9)

    def add_node(self, node_type: str, node_name: str, properties: Dict[str, Any] = None,
                 confidence: float = 0.5, tags: List[str] = None) -> str:
        """添加知识节点"""
        node = KnowledgeNode(
            node_type=node_type,
            node_name=node_name,
            properties=properties or {},
            confidence_score=confidence,
            tags=tags or []
        )

        self.nodes[node.node_id] = node

        # 更新索引
        if node_type not in self.node_index:
            self.node_index[node_type] = []
        self.node_index[node_type].append(node.node_id)

        return node.node_id

    def add_relation(self, source_node_id: str, target_node_id: str, relation_type: str,
                    strength: float = 0.5, properties: Dict[str, Any] = None) -> str:
        """添加知识关系"""
        if source_node_id not in self.nodes or target_node_id not in self.nodes:
            raise ValueError("源节点或目标节点不存在")

        relation = KnowledgeRelation(
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relation_type=relation_type,
            relation_strength=strength,
            properties=properties or {},
            evidence_count=1
        )

        self.relations[relation.relation_id] = relation

        # 更新索引
        if relation_type not in self.relation_index:
            self.relation_index[relation_type] = []
        self.relation_index[relation_type].append(relation.relation_id)

        return relation.relation_id

    def query_nodes(self, node_type: str = None, name_pattern: str = None,
                   min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        """查询知识节点"""
        results = []

        target_nodes = []
        if node_type:
            target_nodes = [self.nodes[nid] for nid in self.node_index.get(node_type, [])]
        else:
            target_nodes = list(self.nodes.values())

        for node in target_nodes:
            if node.confidence_score >= min_confidence:
                if not name_pattern or name_pattern.lower() in node.node_name.lower():
                    results.append({
                        "node_id": node.node_id,
                        "node_type": node.node_type,
                        "node_name": node.node_name,
                        "properties": node.properties,
                        "confidence_score": node.confidence_score,
                        "tags": node.tags
                    })

        return results

    def recommend_tools_for_target(self, target_properties: Dict[str, Any]) -> List[Dict[str, Any]]:
        """根据目标特征推荐工具"""
        recommendations = []

        # 查找工具节点
        tool_nodes = self.query_nodes(node_type="tool")

        for tool in tool_nodes:
            tool_id = tool["node_id"]

            # 计算匹配度
            effectiveness_score = self._calculate_tool_effectiveness(target_properties, tool["properties"])

            if effectiveness_score > 0.3:  # 最低有效性阈值
                recommendations.append({
                    "tool_name": tool["node_name"],
                    "tool_id": tool_id,
                    "effectiveness_score": effectiveness_score,
                    "confidence": tool["confidence_score"],
                    "reasoning": self._generate_recommendation_reasoning(target_properties, tool["properties"])
                })

        # 按效果评分排序
        recommendations.sort(key=lambda x: x["effectiveness_score"], reverse=True)

        return recommendations[:10]  # 返回前10个推荐

    def _calculate_tool_effectiveness(self, target_props: Dict[str, Any],
                                    tool_props: Dict[str, Any]) -> float:
        """计算工具对目标的有效性"""
        # 根据目标类型计算基础有效性
        target_type = target_props.get("type", "unknown")

        # 默认基础有效性
        effectiveness = 0.5

        # 根据工具类型调整
        if tool_props.get("type") == "penetration_testing":
            effectiveness = 0.7

        return min(effectiveness, 1.0)

    def _generate_recommendation_reasoning(self, target_props: Dict[str, Any],
                                         tool_props: Dict[str, Any]) -> str:
        """生成推荐理由"""
        target_type = target_props.get("type", "未知")
        return f"适用于 {target_type} 类型目标的渗透测试工具"

    def get_knowledge_statistics(self) -> Dict[str, Any]:
        """获取知识图谱统计信息"""
        stats = {
            "total_nodes": len(self.nodes),
            "total_relations": len(self.relations),
            "nodes_by_type": {},
            "relations_by_type": {},
            "average_confidence": 0.0
        }

        # 统计节点类型
        for node_type, node_ids in self.node_index.items():
            stats["nodes_by_type"][node_type] = len(node_ids)

        # 统计关系类型
        for relation_type, relation_ids in self.relation_index.items():
            stats["relations_by_type"][relation_type] = len(relation_ids)

        # 计算平均置信度
        if self.nodes:
            total_confidence = sum(node.confidence_score for node in self.nodes.values())
            stats["average_confidence"] = total_confidence / len(self.nodes)

        return stats

# 全局攻击知识图谱实例
attack_knowledge_graph = AttackKnowledgeGraph()

# ==================== 自适应执行引擎与动态策略切换系统 ====================

