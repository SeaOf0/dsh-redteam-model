#!/usr/bin/env python3
"""
高级内存持久化系统

从 mcp_server.py 提取:
- AdvancedMemoryPersistence: 使用向量存储实现长期记忆
"""

import os
import json
import time
import hashlib
import logging
import random
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from kali_mcp.core.mcp_session import SessionContext

logger = logging.getLogger(__name__)

class AdvancedMemoryPersistence:
    """高级内存持久化系统 - 使用向量存储实现长期记忆"""

    def __init__(self):
        self.vector_storage = {}  # 主向量存储
        self.memory_clusters = {}  # 内存聚类
        self.session_embeddings = {}  # 会话嵌入
        self.knowledge_graph = {}  # 知识图谱

        # 持久化配置
        self.max_memory_entries = 10000
        self.similarity_threshold = 0.7
        self.cluster_update_frequency = 100  # 每100个条目更新一次聚类
        self.entry_counter = 0

        # 记忆类型权重
        self.memory_weights = {
            "vulnerability_discovery": 1.0,
            "successful_exploit": 0.9,
            "tool_effectiveness": 0.8,
            "target_characteristics": 0.7,
            "strategy_outcome": 0.6,
            "conversation_context": 0.5
        }

    def store_memory(self, memory_type: str, content: Dict[str, Any],
                    session_context: SessionContext = None) -> str:
        """存储记忆到向量存储系统"""

        memory_id = f"{memory_type}_{int(time.time())}_{random.randint(1000, 9999)}"

        # 创建记忆条目
        memory_entry = {
            "id": memory_id,
            "type": memory_type,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "session_id": session_context.session_id if session_context else None,
            "importance_score": self._calculate_importance(memory_type, content),
            "access_count": 0,
            "last_accessed": datetime.now().isoformat(),
            "decay_factor": 1.0
        }

        # 生成向量嵌入
        embedding_vector = self._generate_embedding(memory_entry)
        memory_entry["embedding"] = embedding_vector

        # 存储到向量存储
        self.vector_storage[memory_id] = memory_entry

        # 更新知识图谱
        self._update_knowledge_graph(memory_entry, session_context)

        # 检查是否需要聚类更新
        self.entry_counter += 1
        if self.entry_counter % self.cluster_update_frequency == 0:
            self._update_memory_clusters()

        # 清理旧记忆（如果超过限制）
        self._cleanup_old_memories()

        logger.info(f"Stored memory: {memory_id} (type: {memory_type})")
        return memory_id

    def retrieve_similar_memories(self, query_context: Dict[str, Any],
                                memory_types: List[str] = None,
                                limit: int = 10) -> List[Dict[str, Any]]:
        """检索相似记忆"""

        # 生成查询向量
        query_vector = self._generate_query_embedding(query_context)

        # 计算相似度分数
        similarities = []

        for memory_id, memory_entry in self.vector_storage.items():
            # 类型过滤
            if memory_types and memory_entry["type"] not in memory_types:
                continue

            # 计算余弦相似度
            similarity = self._cosine_similarity(query_vector, memory_entry["embedding"])

            # 应用时间衰减
            time_factor = self._calculate_time_decay(memory_entry["timestamp"])

            # 应用重要性权重
            importance_factor = memory_entry["importance_score"]

            # 应用访问频率加权
            access_factor = min(1.0 + memory_entry["access_count"] * 0.1, 2.0)

            final_score = similarity * time_factor * importance_factor * access_factor

            if final_score >= self.similarity_threshold:
                similarities.append({
                    "memory_id": memory_id,
                    "memory": memory_entry,
                    "similarity_score": similarity,
                    "final_score": final_score
                })

        # 排序并返回前N个结果
        similarities.sort(key=lambda x: x["final_score"], reverse=True)
        results = similarities[:limit]

        # 更新访问计数
        for result in results:
            memory_id = result["memory_id"]
            self.vector_storage[memory_id]["access_count"] += 1
            self.vector_storage[memory_id]["last_accessed"] = datetime.now().isoformat()

        return results

    def get_contextual_insights(self, session_context: SessionContext) -> Dict[str, Any]:
        """基于当前上下文获取洞察"""

        insights = {
            "relevant_vulnerabilities": [],
            "successful_techniques": [],
            "similar_targets": [],
            "recommended_approaches": [],
            "risk_indicators": []
        }

        # 构建查询上下文
        query_context = {
            "target": session_context.target,
            "attack_mode": session_context.attack_mode,
            "discovered_assets": session_context.discovered_assets,
            "completed_tasks": session_context.completed_tasks
        }

        # 检索相关漏洞记忆
        vuln_memories = self.retrieve_similar_memories(
            query_context,
            memory_types=["vulnerability_discovery"],
            limit=5
        )

        for memory in vuln_memories:
            insights["relevant_vulnerabilities"].append({
                "vulnerability": memory["memory"]["content"].get("vulnerability_type"),
                "target_similarity": memory["similarity_score"],
                "exploitation_success": memory["memory"]["content"].get("exploitation_success", False),
                "tools_used": memory["memory"]["content"].get("tools_used", [])
            })

        # 检索成功技术
        exploit_memories = self.retrieve_similar_memories(
            query_context,
            memory_types=["successful_exploit"],
            limit=5
        )

        for memory in exploit_memories:
            insights["successful_techniques"].append({
                "technique": memory["memory"]["content"].get("technique"),
                "success_rate": memory["memory"]["content"].get("success_rate", 0),
                "target_type": memory["memory"]["content"].get("target_type"),
                "payload": memory["memory"]["content"].get("payload")
            })

        # 检索相似目标
        target_memories = self.retrieve_similar_memories(
            query_context,
            memory_types=["target_characteristics"],
            limit=3
        )

        for memory in target_memories:
            insights["similar_targets"].append({
                "target": memory["memory"]["content"].get("target"),
                "characteristics": memory["memory"]["content"].get("characteristics"),
                "successful_strategies": memory["memory"]["content"].get("successful_strategies", []),
                "discovery_methods": memory["memory"]["content"].get("discovery_methods", [])
            })

        # 生成推荐方法
        insights["recommended_approaches"] = self._generate_contextual_recommendations(
            session_context, vuln_memories, exploit_memories
        )

        # 识别风险指标
        insights["risk_indicators"] = self._identify_risk_indicators(
            session_context, insights["relevant_vulnerabilities"]
        )

        return insights

    def store_vulnerability_discovery(self, vulnerability_info: Dict[str, Any],
                                   session_context: SessionContext) -> str:
        """存储漏洞发现记忆"""

        content = {
            "vulnerability_type": vulnerability_info.get("type"),
            "severity": vulnerability_info.get("severity"),
            "target": session_context.target,
            "discovery_method": vulnerability_info.get("discovery_method"),
            "tools_used": vulnerability_info.get("tools_used", []),
            "exploitation_success": vulnerability_info.get("exploited", False),
            "mitigation_present": vulnerability_info.get("mitigation_present", False),
            "target_characteristics": {
                "target_type": self._classify_target_type(session_context.target),
                "discovered_services": list(session_context.discovered_assets.keys()),
                "environment_complexity": len(session_context.discovered_assets)
            }
        }

        return self.store_memory("vulnerability_discovery", content, session_context)

    def store_successful_exploit(self, exploit_info: Dict[str, Any],
                               session_context: SessionContext) -> str:
        """存储成功利用记忆"""

        content = {
            "technique": exploit_info.get("technique"),
            "payload": exploit_info.get("payload"),
            "success_rate": exploit_info.get("success_rate", 1.0),
            "target_type": self._classify_target_type(session_context.target),
            "preconditions": exploit_info.get("preconditions", []),
            "side_effects": exploit_info.get("side_effects", []),
            "tools_used": exploit_info.get("tools_used", []),
            "execution_time": exploit_info.get("execution_time"),
            "target_response": exploit_info.get("target_response")
        }

        return self.store_memory("successful_exploit", content, session_context)

    def store_tool_effectiveness(self, tool_name: str, effectiveness_data: Dict[str, Any],
                               session_context: SessionContext) -> str:
        """存储工具有效性记忆"""

        content = {
            "tool_name": tool_name,
            "effectiveness_score": effectiveness_data.get("score", 0.5),
            "execution_time": effectiveness_data.get("execution_time"),
            "resource_usage": effectiveness_data.get("resource_usage"),
            "success_indicators": effectiveness_data.get("success_indicators", []),
            "failure_reasons": effectiveness_data.get("failure_reasons", []),
            "target_characteristics": {
                "target": session_context.target,
                "target_type": self._classify_target_type(session_context.target),
                "complexity": len(session_context.discovered_assets)
            },
            "context_factors": effectiveness_data.get("context_factors", [])
        }

        return self.store_memory("tool_effectiveness", content, session_context)

    def _generate_embedding(self, memory_entry: Dict[str, Any]) -> List[float]:
        """生成记忆条目的向量嵌入"""

        # 初始化50维嵌入向量
        embedding = [0.0] * 50

        content = memory_entry["content"]
        memory_type = memory_entry["type"]

        # 基础特征 (0-9)
        if "target" in content:
            target = content["target"].lower() if content["target"] else ""
            embedding[0] = 1.0 if "http" in target or "www" in target else 0.0  # Web服务
            embedding[1] = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target) else 0.0  # IP
            embedding[2] = len(target) / 100.0  # 目标名称长度标准化

        # 记忆类型编码 (10-14)
        type_encoding = {
            "vulnerability_discovery": [1.0, 0.0, 0.0, 0.0, 0.0],
            "successful_exploit": [0.0, 1.0, 0.0, 0.0, 0.0],
            "tool_effectiveness": [0.0, 0.0, 1.0, 0.0, 0.0],
            "target_characteristics": [0.0, 0.0, 0.0, 1.0, 0.0],
            "strategy_outcome": [0.0, 0.0, 0.0, 0.0, 1.0]
        }
        type_vec = type_encoding.get(memory_type, [0.0, 0.0, 0.0, 0.0, 0.0])
        embedding[10:15] = type_vec

        # 严重性/重要性特征 (15-17)
        if "severity" in content:
            severity_map = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
            embedding[15] = severity_map.get(content["severity"], 0.5)

        if "success_rate" in content:
            embedding[16] = content["success_rate"]

        embedding[17] = memory_entry["importance_score"]

        # 工具特征 (18-27)
        if "tools_used" in content:
            tools = content["tools_used"]
            tool_features = {
                "nmap": 18, "gobuster": 19, "sqlmap": 20, "nuclei": 21, "nikto": 22,
                "metasploit": 23, "burp": 24, "wireshark": 25, "john": 26, "hashcat": 27
            }
            for tool in tools:
                for tool_name, index in tool_features.items():
                    if tool_name in tool.lower():
                        embedding[index] = 1.0

        # 目标特征 (28-37)
        if "target_characteristics" in content:
            char = content["target_characteristics"]
            embedding[28] = char.get("environment_complexity", 0) / 20.0  # 标准化复杂度

            # 目标类型特征
            target_type = char.get("target_type", "unknown")
            type_features = {
                "web_application": 29, "ip_address": 30, "binary_file": 31,
                "complex_endpoint": 32, "network_range": 33
            }
            if target_type in type_features:
                embedding[type_features[target_type]] = 1.0

        # 时间特征 (38-42)
        timestamp = datetime.fromisoformat(memory_entry["timestamp"])
        embedding[38] = timestamp.hour / 24.0  # 小时标准化
        embedding[39] = timestamp.weekday() / 7.0  # 星期标准化
        embedding[40] = timestamp.month / 12.0  # 月份标准化

        # 访问模式特征 (43-47)
        embedding[43] = min(memory_entry["access_count"] / 100.0, 1.0)  # 访问次数标准化
        embedding[44] = memory_entry["decay_factor"]

        # 上下文特征 (45-49)
        if "exploitation_success" in content:
            embedding[45] = 1.0 if content["exploitation_success"] else 0.0

        if "mitigation_present" in content:
            embedding[46] = 1.0 if content["mitigation_present"] else 0.0

        # 向量长度标准化
        vector_magnitude = sum(x*x for x in embedding) ** 0.5
        if vector_magnitude > 0:
            embedding = [x / vector_magnitude for x in embedding]

        return embedding

    def _classify_target_type(self, target: str) -> str:
        """将目标分类为常见类型，供记忆系统使用。"""
        target_text = (target or "").lower()
        if not target_text:
            return "unknown"
        if target_text.startswith(("http://", "https://")):
            return "web"
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", target_text):
            return "ip"
        if any(keyword in target_text for keyword in [".com", ".org", ".net", ".cn"]):
            return "domain"
        if any(keyword in target_text for keyword in ["ctf", "flag", "challenge"]):
            return "ctf"
        return "unknown"

    def _generate_query_embedding(self, query_context: Dict[str, Any]) -> List[float]:
        """生成查询上下文的向量嵌入"""

        # 创建临时记忆条目用于生成嵌入
        temp_memory = {
            "content": query_context,
            "type": "query",
            "timestamp": datetime.now().isoformat(),
            "importance_score": 1.0,
            "access_count": 0,
            "decay_factor": 1.0
        }

        return self._generate_embedding(temp_memory)

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """计算两个向量的余弦相似度"""

        if len(vec1) != len(vec2):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = sum(a * a for a in vec1) ** 0.5
        magnitude2 = sum(b * b for b in vec2) ** 0.5

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)

    def _calculate_importance(self, memory_type: str, content: Dict[str, Any]) -> float:
        """计算记忆重要性分数"""

        base_importance = self.memory_weights.get(memory_type, 0.5)

        # 基于内容调整重要性
        importance_factors = []

        # 成功率因子
        if "success_rate" in content:
            importance_factors.append(content["success_rate"])

        # 严重性因子
        if "severity" in content:
            severity_scores = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}
            importance_factors.append(severity_scores.get(content["severity"], 0.5))

        # 漏洞利用成功因子
        if "exploitation_success" in content and content["exploitation_success"]:
            importance_factors.append(1.0)

        # 工具数量因子
        if "tools_used" in content:
            tool_factor = min(len(content["tools_used"]) / 10.0, 1.0)
            importance_factors.append(tool_factor)

        # 计算最终重要性
        if importance_factors:
            avg_factor = sum(importance_factors) / len(importance_factors)
            final_importance = base_importance * 0.7 + avg_factor * 0.3
        else:
            final_importance = base_importance

        return min(max(final_importance, 0.1), 1.0)

    def _calculate_time_decay(self, timestamp_str: str) -> float:
        """计算时间衰减因子"""

        try:
            timestamp = datetime.fromisoformat(timestamp_str)
            now = datetime.now()
            time_diff = (now - timestamp).total_seconds()

            # 1小时内：无衰减 (1.0)
            # 1天内：轻微衰减 (0.9)
            # 1周内：中等衰减 (0.7)
            # 1月内：明显衰减 (0.5)
            # 更久：强衰减 (0.3)

            if time_diff < 3600:  # 1小时
                return 1.0
            elif time_diff < 86400:  # 1天
                return 0.9
            elif time_diff < 604800:  # 1周
                return 0.7
            elif time_diff < 2592000:  # 1月
                return 0.5
            else:
                return 0.3

        except:
            return 0.5

    def _update_knowledge_graph(self, memory_entry: Dict[str, Any],
                              session_context: SessionContext = None):
        """更新知识图谱"""

        content = memory_entry["content"]
        memory_id = memory_entry["id"]

        # 提取关键实体
        entities = []

        if "target" in content:
            entities.append(("target", content["target"]))

        if "vulnerability_type" in content:
            entities.append(("vulnerability", content["vulnerability_type"]))

        if "technique" in content:
            entities.append(("technique", content["technique"]))

        if "tools_used" in content:
            for tool in content["tools_used"]:
                entities.append(("tool", tool))

        # 更新知识图谱连接
        for entity_type, entity_value in entities:
            entity_key = f"{entity_type}:{entity_value}"

            if entity_key not in self.knowledge_graph:
                self.knowledge_graph[entity_key] = {
                    "type": entity_type,
                    "value": entity_value,
                    "connected_memories": [],
                    "connection_strength": {},
                    "last_updated": datetime.now().isoformat()
                }

            # 添加记忆连接
            if memory_id not in self.knowledge_graph[entity_key]["connected_memories"]:
                self.knowledge_graph[entity_key]["connected_memories"].append(memory_id)

            # 更新连接强度
            for other_entity_type, other_entity_value in entities:
                if entity_type != other_entity_type or entity_value != other_entity_value:
                    other_key = f"{other_entity_type}:{other_entity_value}"

                    if other_key not in self.knowledge_graph[entity_key]["connection_strength"]:
                        self.knowledge_graph[entity_key]["connection_strength"][other_key] = 0

                    self.knowledge_graph[entity_key]["connection_strength"][other_key] += 1

    def _update_memory_clusters(self):
        """更新记忆聚类"""

        logger.info("Updating memory clusters...")

        # 简单的K-means聚类实现
        if len(self.vector_storage) < 10:
            return

        # 提取所有嵌入向量
        embeddings = []
        memory_ids = []

        for memory_id, memory_entry in self.vector_storage.items():
            embeddings.append(memory_entry["embedding"])
            memory_ids.append(memory_id)

        # 确定聚类数量
        num_clusters = min(10, max(3, len(embeddings) // 20))

        # 初始化聚类中心
        import random
        cluster_centers = random.sample(embeddings, num_clusters)

        # 简单聚类分配
        clusters = {i: [] for i in range(num_clusters)}

        for i, embedding in enumerate(embeddings):
            best_cluster = 0
            best_similarity = -1

            for j, center in enumerate(cluster_centers):
                similarity = self._cosine_similarity(embedding, center)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_cluster = j

            clusters[best_cluster].append(memory_ids[i])

        # 更新聚类信息
        self.memory_clusters = {
            f"cluster_{i}": {
                "center": cluster_centers[i],
                "members": members,
                "size": len(members),
                "last_updated": datetime.now().isoformat()
            }
            for i, members in clusters.items() if members
        }

    def _cleanup_old_memories(self):
        """清理旧记忆以保持在限制范围内"""

        if len(self.vector_storage) <= self.max_memory_entries:
            return

        # 计算每个记忆的保留分数
        retention_scores = []

        for memory_id, memory_entry in self.vector_storage.items():
            # 基于重要性、访问频率和时间衰减计算保留分数
            importance = memory_entry["importance_score"]
            access_factor = min(1.0 + memory_entry["access_count"] * 0.1, 2.0)
            time_factor = self._calculate_time_decay(memory_entry["timestamp"])

            retention_score = importance * access_factor * time_factor
            retention_scores.append((memory_id, retention_score))

        # 按保留分数排序
        retention_scores.sort(key=lambda x: x[1], reverse=True)

        # 保留前N个记忆
        memories_to_keep = retention_scores[:self.max_memory_entries]
        keep_ids = set(memory_id for memory_id, _ in memories_to_keep)

        # 删除不需要保留的记忆
        memories_to_delete = [memory_id for memory_id in self.vector_storage.keys()
                            if memory_id not in keep_ids]

        for memory_id in memories_to_delete:
            del self.vector_storage[memory_id]

        logger.info(f"Cleaned up {len(memories_to_delete)} old memories")

    def _generate_contextual_recommendations(self, session_context: SessionContext,
                                          vuln_memories: List[Dict],
                                          exploit_memories: List[Dict]) -> List[Dict[str, Any]]:
        """基于记忆生成上下文推荐"""

        recommendations = []

        # 基于漏洞记忆的推荐
        for memory in vuln_memories[:3]:
            vuln_content = memory["memory"]["content"]
            if vuln_content.get("exploitation_success"):
                recommendations.append({
                    "type": "vulnerability_exploitation",
                    "priority": "high",
                    "description": f"类似目标存在{vuln_content.get('vulnerability_type')}漏洞",
                    "suggested_tools": vuln_content.get("tools_used", []),
                    "confidence": memory["similarity_score"]
                })

        # 基于成功利用记忆的推荐
        for memory in exploit_memories[:3]:
            exploit_content = memory["memory"]["content"]
            recommendations.append({
                "type": "exploitation_technique",
                "priority": "medium",
                "description": f"建议尝试{exploit_content.get('technique')}技术",
                "success_rate": exploit_content.get("success_rate", 0),
                "confidence": memory["similarity_score"]
            })

        return recommendations

    def _identify_risk_indicators(self, session_context: SessionContext,
                                relevant_vulns: List[Dict]) -> List[Dict[str, Any]]:
        """识别风险指标"""

        risk_indicators = []

        # 基于已知漏洞的风险
        high_severity_count = sum(1 for vuln in relevant_vulns
                                if vuln.get("vulnerability", {}).get("severity") in ["high", "critical"])

        if high_severity_count > 0:
            risk_indicators.append({
                "type": "high_severity_vulnerabilities",
                "level": "high",
                "description": f"发现{high_severity_count}个高危漏洞模式",
                "recommendation": "优先进行漏洞验证和利用"
            })

        # 基于目标复杂度的风险
        complexity = len(session_context.discovered_assets)
        if complexity > 10:
            risk_indicators.append({
                "type": "complex_environment",
                "level": "medium",
                "description": "目标环境复杂，可能存在未知风险",
                "recommendation": "采用分阶段深入分析策略"
            })

        return risk_indicators

    def export_memory_analytics(self) -> Dict[str, Any]:
        """导出记忆分析报告"""

        analytics = {
            "memory_statistics": {
                "total_memories": len(self.vector_storage),
                "memory_types": {},
                "cluster_count": len(self.memory_clusters),
                "knowledge_graph_entities": len(self.knowledge_graph)
            },
            "memory_distribution": {},
            "access_patterns": {},
            "retention_analysis": {},
            "knowledge_insights": []
        }

        # 记忆类型分布
        for memory_entry in self.vector_storage.values():
            memory_type = memory_entry["type"]
            if memory_type not in analytics["memory_statistics"]["memory_types"]:
                analytics["memory_statistics"]["memory_types"][memory_type] = 0
            analytics["memory_statistics"]["memory_types"][memory_type] += 1

        # 访问模式分析
        access_counts = [m["access_count"] for m in self.vector_storage.values()]
        if access_counts:
            analytics["access_patterns"] = {
                "average_access": sum(access_counts) / len(access_counts),
                "max_access": max(access_counts),
                "frequently_accessed": len([c for c in access_counts if c > 5])
            }

        # 知识洞察
        if self.knowledge_graph:
            # 找到最连接的实体
            most_connected = max(self.knowledge_graph.items(),
                               key=lambda x: len(x[1]["connected_memories"]))

            analytics["knowledge_insights"].append({
                "type": "most_connected_entity",
                "entity": most_connected[0],
                "connections": len(most_connected[1]["connected_memories"])
            })

        return analytics

# 全局高级内存持久化实例
advanced_memory = AdvancedMemoryPersistence()
