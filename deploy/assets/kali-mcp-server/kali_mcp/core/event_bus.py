#!/usr/bin/env python3
"""
统一事件总线 - Kali MCP 模块间通信核心

所有模块通过事件总线通信，实现：
- 工具执行结果自动广播给分析模块
- 漏洞发现自动触发知识图谱更新
- 决策变更自动通知策略优化器

事件类型:
- tool.result    工具执行完成（成功或失败）
- tool.error     工具执行异常
- vuln.candidate 发现疑似漏洞
- vuln.verified  漏洞已验证
- fragment.new   新信息碎片
- decision.made  决策引擎做出决策
- strategy.update 策略变更
- port.discovered 发现开放端口
- service.identified 识别到服务
- chain.step_complete 工具链步骤完成
"""

import logging
import time
import threading
from typing import Dict, Any, Callable, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)

# 事件处理超时(秒) - 防止慢订阅者阻塞整个链
HANDLER_TIMEOUT = 5.0


@dataclass
class Event:
    """事件对象"""
    event_type: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    source: str = ""  # 发布者标识


@dataclass
class Subscription:
    """订阅记录"""
    handler: Callable
    subscriber_name: str
    event_pattern: str  # 支持通配符: "tool.*" 匹配 "tool.result", "tool.error"
    priority: int = 0   # 越大越优先


class EventBus:
    """
    进程内同步事件总线

    设计原则:
    - 同步处理，避免异步复杂性
    - 单个handler超时5秒自动跳过
    - 支持事件模式匹配 (tool.* 匹配所有tool事件)
    - 线程安全（用锁保护订阅列表）
    """

    def __init__(self):
        self._subscriptions: Dict[str, List[Subscription]] = defaultdict(list)
        self._lock = threading.Lock()
        self._event_history: List[Event] = []
        self._max_history = 500  # 保留最近500个事件
        self._stats = defaultdict(lambda: {"emitted": 0, "handled": 0, "errors": 0, "timeouts": 0})

    def subscribe(self, event_pattern: str, handler: Callable,
                  subscriber_name: str = "", priority: int = 0):
        """
        订阅事件

        Args:
            event_pattern: 事件模式，支持通配符 "tool.*"
            handler: 回调函数 fn(event: Event) -> None
            subscriber_name: 订阅者名称，用于日志
            priority: 优先级，越大越先执行
        """
        sub = Subscription(
            handler=handler,
            subscriber_name=subscriber_name or handler.__name__,
            event_pattern=event_pattern,
            priority=priority
        )
        with self._lock:
            self._subscriptions[event_pattern].append(sub)
            # 按优先级排序
            self._subscriptions[event_pattern].sort(key=lambda s: s.priority, reverse=True)

        logger.debug(f"EventBus: {sub.subscriber_name} subscribed to '{event_pattern}'")

    def unsubscribe(self, event_pattern: str, subscriber_name: str):
        """取消订阅"""
        with self._lock:
            if event_pattern in self._subscriptions:
                self._subscriptions[event_pattern] = [
                    s for s in self._subscriptions[event_pattern]
                    if s.subscriber_name != subscriber_name
                ]

    def emit(self, event_type: str, data: Dict[str, Any], source: str = ""):
        """
        发布事件

        同步执行所有匹配的handler。每个handler有5秒超时。

        Args:
            event_type: 事件类型 (如 "tool.result")
            data: 事件数据
            source: 发布者标识
        """
        event = Event(event_type=event_type, data=data, source=source)

        # 记录历史
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        self._stats[event_type]["emitted"] += 1

        # 找到所有匹配的订阅
        matched_subs = self._match_subscriptions(event_type)

        for sub in matched_subs:
            try:
                self._execute_handler(sub, event)
                self._stats[event_type]["handled"] += 1
            except TimeoutError:
                self._stats[event_type]["timeouts"] += 1
                logger.warning(
                    f"EventBus: handler '{sub.subscriber_name}' timed out "
                    f"for event '{event_type}'"
                )
            except Exception as e:
                self._stats[event_type]["errors"] += 1
                logger.error(
                    f"EventBus: handler '{sub.subscriber_name}' failed "
                    f"for event '{event_type}': {e}"
                )

    def _match_subscriptions(self, event_type: str) -> List[Subscription]:
        """匹配事件模式"""
        matched = []
        with self._lock:
            for pattern, subs in self._subscriptions.items():
                if self._pattern_matches(pattern, event_type):
                    matched.extend(subs)
        # 按优先级排序
        matched.sort(key=lambda s: s.priority, reverse=True)
        return matched

    @staticmethod
    def _pattern_matches(pattern: str, event_type: str) -> bool:
        """
        模式匹配:
        - "tool.result" 精确匹配 "tool.result"
        - "tool.*" 匹配 "tool.result", "tool.error"
        - "*" 匹配所有
        """
        if pattern == "*":
            return True
        if pattern == event_type:
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return event_type.startswith(prefix + ".")
        return False

    def _execute_handler(self, sub: Subscription, event: Event):
        """执行handler，带超时保护"""
        # 使用线程实现超时
        result = {"error": None}

        def run():
            try:
                sub.handler(event)
            except Exception as e:
                result["error"] = e

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=HANDLER_TIMEOUT)

        if thread.is_alive():
            raise TimeoutError(f"Handler {sub.subscriber_name} exceeded {HANDLER_TIMEOUT}s")

        if result["error"]:
            raise result["error"]

    def get_stats(self) -> Dict[str, Any]:
        """获取事件统计"""
        return {
            "total_events": sum(s["emitted"] for s in self._stats.values()),
            "total_handled": sum(s["handled"] for s in self._stats.values()),
            "total_errors": sum(s["errors"] for s in self._stats.values()),
            "total_timeouts": sum(s["timeouts"] for s in self._stats.values()),
            "by_type": dict(self._stats),
            "subscriber_count": sum(len(subs) for subs in self._subscriptions.values()),
            "history_size": len(self._event_history),
        }

    def get_recent_events(self, event_type: str = None, limit: int = 20) -> List[Dict]:
        """获取最近的事件"""
        events = self._event_history
        if event_type:
            events = [e for e in events if self._pattern_matches(event_type, e.event_type)]
        return [
            {
                "event_type": e.event_type,
                "source": e.source,
                "timestamp": e.timestamp,
                "data_keys": list(e.data.keys()),
                "data_preview": {k: str(v)[:200] for k, v in list(e.data.items())[:5]},
            }
            for e in events[-limit:]
        ]

    def get_events_for_target(self, target: str, limit: int = 50) -> List[Event]:
        """获取特定目标相关的所有事件"""
        return [
            e for e in self._event_history
            if target in str(e.data.get("target", ""))
        ][-limit:]


# ============================================================
# 事件总线订阅者 - 将分析模块连接到工具执行结果
# ============================================================

class KnowledgeGraphSubscriber:
    """知识图谱自动更新订阅者"""

    def __init__(self, knowledge_graph):
        self.kg = knowledge_graph

    def on_tool_result(self, event: Event):
        """工具执行完成时，自动记录工具-目标关系"""
        data = event.data
        tool_name = data.get("tool_name", "")
        target = data.get("target", "")
        success = data.get("success", False)

        if not tool_name or not target:
            return

        # 添加目标节点
        target_id = self.kg.add_node(
            node_type="target",
            node_name=target,
            properties={"last_scanned": time.time()},
            confidence=0.9,
            tags=["auto_discovered"]
        )

        # 添加工具节点
        tool_id = self.kg.add_node(
            node_type="tool",
            node_name=tool_name,
            properties={"last_used": time.time(), "success": success},
            confidence=1.0,
            tags=[]
        )

        # 添加关系
        self.kg.add_relation(
            source_node_id=tool_id,
            target_node_id=target_id,
            relation_type="scanned" if success else "failed_on",
            strength=0.8 if success else 0.3,
            properties={"timestamp": time.time()}
        )

    def on_vuln_candidate(self, event: Event):
        """发现漏洞时，记录漏洞节点"""
        data = event.data
        vuln_type = data.get("vuln_type", "unknown")
        target = data.get("target", "")

        vuln_id = self.kg.add_node(
            node_type="vulnerability",
            node_name=f"{vuln_type}@{target}",
            properties={
                "vuln_type": vuln_type,
                "target": target,
                "severity": data.get("severity", "medium"),
                "evidence": data.get("evidence", "")[:500],
            },
            confidence=data.get("confidence", 0.5),
            tags=[vuln_type]
        )

    def register(self, bus: EventBus):
        """注册所有订阅"""
        bus.subscribe("tool.result", self.on_tool_result, "KnowledgeGraph", priority=5)
        bus.subscribe("vuln.candidate", self.on_vuln_candidate, "KnowledgeGraph", priority=5)


class VulnManagerSubscriber:
    """漏洞管理器自动提取订阅者"""

    def __init__(self, vuln_manager):
        self.vm = vuln_manager

    def on_tool_result(self, event: Event):
        """从工具结果中自动提取漏洞候选"""
        data = event.data
        output = data.get("output", "")
        tool_name = data.get("tool_name", "")
        target = data.get("target", "")

        if not output or not target:
            return

        # nuclei 结果直接包含漏洞信息
        if tool_name == "nuclei" and data.get("success"):
            self._extract_nuclei_vulns(output, target)

        # sqlmap 发现注入点
        if tool_name == "sqlmap" and "is vulnerable" in output.lower():
            self._extract_sqlmap_vulns(output, target)

        # nikto 发现问题
        if tool_name == "nikto" and "OSVDB" in output:
            self._extract_nikto_vulns(output, target)

    def _extract_nuclei_vulns(self, output: str, target: str):
        """从nuclei输出提取漏洞"""
        import re
        for line in output.split("\n"):
            # nuclei 输出格式: [severity] [template-id] [protocol] url
            match = re.search(r'\[(\w+)\]\s+\[([^\]]+)\]', line)
            if match:
                severity = match.group(1).lower()
                template_id = match.group(2)
                if severity in ("critical", "high", "medium"):
                    try:
                        from kali_mcp.core.vuln_models import VulnRecord
                        vuln = VulnRecord(
                            title=f"Nuclei: {template_id}",
                            vuln_type="nuclei_finding",
                            target=target,
                            severity=severity,
                            confidence="high",
                            source="blackbox",
                            evidence=line[:500],
                            discovered_by="nuclei"
                        )
                        self.vm.issue_vuln(vuln)
                    except Exception:
                        pass

    def _extract_sqlmap_vulns(self, output: str, target: str):
        """从sqlmap输出提取SQL注入漏洞"""
        try:
            from kali_mcp.core.vuln_models import VulnRecord
            vuln = VulnRecord(
                title=f"SQL Injection on {target}",
                vuln_type="sqli",
                target=target,
                severity="high",
                confidence="high",
                source="blackbox",
                evidence=output[:1000],
                discovered_by="sqlmap"
            )
            self.vm.issue_vuln(vuln)
        except Exception:
            pass

    def _extract_nikto_vulns(self, output: str, target: str):
        """从nikto输出提取漏洞"""
        import re
        for line in output.split("\n"):
            if "OSVDB" in line:
                try:
                    from kali_mcp.core.vuln_models import VulnRecord
                    vuln = VulnRecord(
                        title=f"Nikto: {line.strip()[:100]}",
                        vuln_type="web_misconfiguration",
                        target=target,
                        severity="medium",
                        confidence="medium",
                        source="blackbox",
                        evidence=line[:500],
                        discovered_by="nikto"
                    )
                    self.vm.issue_vuln(vuln)
                except Exception:
                    pass

    def register(self, bus: EventBus):
        bus.subscribe("tool.result", self.on_tool_result, "VulnManager", priority=3)


class MLOptimizerSubscriber:
    """ML优化器学习数据收集订阅者"""

    def __init__(self, ml_optimizer):
        self.ml = ml_optimizer

    def on_tool_result(self, event: Event):
        """记录工具执行效果，用于统计学习"""
        data = event.data
        tool_name = data.get("tool_name", "")
        success = data.get("success", False)
        target = data.get("target", "")
        duration = data.get("duration", 0)

        if not tool_name:
            return

        # 调用ML优化器记录
        if hasattr(self.ml, 'record_tool_outcome'):
            self.ml.record_tool_outcome(
                tool_name=tool_name,
                target=target,
                success=success,
                duration=duration,
                context=data.get("context", {})
            )

    def register(self, bus: EventBus):
        bus.subscribe("tool.result", self.on_tool_result, "MLOptimizer", priority=1)


class DecisionBrainSubscriber:
    """决策引擎上下文更新订阅者"""

    def __init__(self, decision_brain):
        self.db = decision_brain

    def on_tool_result(self, event: Event):
        """工具结果更新决策上下文"""
        data = event.data
        if hasattr(self.db, 'update_context'):
            self.db.update_context({
                "last_tool": data.get("tool_name", ""),
                "last_success": data.get("success", False),
                "last_target": data.get("target", ""),
                "timestamp": event.timestamp,
            })

    def on_vuln_candidate(self, event: Event):
        """漏洞发现触发决策重新评估"""
        if hasattr(self.db, 'trigger_reassessment'):
            self.db.trigger_reassessment(event.data)

    def register(self, bus: EventBus):
        bus.subscribe("tool.result", self.on_tool_result, "DecisionBrain", priority=2)
        bus.subscribe("vuln.candidate", self.on_vuln_candidate, "DecisionBrain", priority=2)
        bus.subscribe("vuln.discovered", self.on_vuln_candidate, "DecisionBrain", priority=2)
        bus.subscribe("digger.completed", self.on_digger_completed, "DecisionBrain", priority=2)

    def on_digger_completed(self, event: Event):
        """Digger完成时更新决策引擎上下文"""
        data = event.data
        if hasattr(self.db, '_decisions'):
            self.db._decisions.append({
                "point": "digger_feedback",
                "digger": data.get("digger", ""),
                "target": data.get("target", ""),
                "success": data.get("success", False),
                "findings_count": data.get("findings_count", 0),
                "flags_count": data.get("flags_count", 0),
                "timestamp": event.timestamp,
            })


class DiggerSubscriber:
    """v5.2: Digger事件统一订阅者 - 将Digger结果路由到MLOptimizer和VulnManager"""

    def __init__(self, ml_optimizer=None, vuln_manager=None):
        self.ml = ml_optimizer
        self.vm = vuln_manager

    def on_vuln_discovered(self, event: Event):
        """Digger发现漏洞  记录到VulnManager"""
        data = event.data
        if self.vm and hasattr(self.vm, 'add_candidate'):
            try:
                self.vm.add_candidate(
                    title=f"{data.get('vuln_type', 'unknown')} in {data.get('target', '')}",
                    vuln_type=data.get("vuln_type", "unknown"),
                    target=data.get("target", ""),
                    severity=data.get("severity", "medium"),
                    confidence="high",
                    source="digger",
                    evidence=data.get("detail", ""),
                    discovered_by=data.get("source", ""),
                )
            except Exception as e:
                logger.debug(f"DiggerSubscriber vuln record failed: {e}")

    def on_digger_completed(self, event: Event):
        """Digger完成  记录到MLOptimizer作为学习数据"""
        data = event.data
        if self.ml and hasattr(self.ml, 'record_tool_outcome'):
            try:
                self.ml.record_tool_outcome(
                    tool_name=f"digger:{data.get('digger', 'unknown')}",
                    target=data.get("target", ""),
                    success=data.get("success", False),
                    duration=data.get("duration", 0),
                    context={
                        "findings": data.get("findings_count", 0),
                        "flags": data.get("flags_count", 0),
                        "mode": data.get("mode", ""),
                    }
                )
            except Exception as e:
                logger.debug(f"DiggerSubscriber ML record failed: {e}")

    def register(self, bus: EventBus):
        bus.subscribe("vuln.discovered", self.on_vuln_discovered, "DiggerSub", priority=1)
        bus.subscribe("digger.completed", self.on_digger_completed, "DiggerSub", priority=1)
