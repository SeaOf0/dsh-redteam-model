"""
深度挖掘器基类

所有深度挖掘器都继承此类，提供：
- 双模式支持（CTF/渗透测试/自动）
- 模式自动识别
- 时间控制（CTF模式60秒限制）
- 工具编排接口
- 结果分析框架
"""

import re
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BaseDeepDigger:
    """
    深度挖掘器基类

    所有深度挖掘器都继承此类，实现统一的接口和行为。
    """

    def __init__(self):
        """初始化深度挖掘器"""
        self.mode = "auto"  # ctf/pentest/auto
        self.time_limit = 60  # CTF模式时间限制（秒）
        self.start_time = None
        self.server_type = "unknown"  # 服务器类型（php/jsp/aspx等）
        self.results = {
            "success": False,
            "mode": None,
            "start_time": None,
            "end_time": None,
            "duration": 0,
            "phases": {},
            "findings": [],
            "flags": [],
            "summary": "",
        }

        # v5.2: 注入EventBus
        self._event_bus = None
        try:
            from kali_mcp.core.local_executor import _event_bus
            self._event_bus = _event_bus
        except (ImportError, AttributeError):
            pass

        # 初始化命令执行器
        try:
            from kali_mcp.core.local_executor import LocalCommandExecutor

            class ExecutorAdapter:
                def __init__(self):
                    self._executor = LocalCommandExecutor(timeout=45)

                def execute_command(self, cmd: str) -> str:
                    result = self._executor.execute_command(cmd, timeout=45)
                    if not isinstance(result, dict):
                        return str(result)
                    stdout = result.get("output", "") or ""
                    stderr = result.get("error", "") or ""
                    merged = f"{stdout}\n{stderr}".strip()
                    return merged

            self.executor = ExecutorAdapter()
        except ImportError:
            # 如果没有导入模块，使用简单的subprocess
            import subprocess
            class SimpleExecutor:
                def execute_command(self, cmd):
                    try:
                        result = subprocess.run(cmd, shell=True, capture_output=True,
                                               text=True, timeout=30)
                        return result.stdout
                    except Exception as e:
                        return str(e)
            self.executor = SimpleExecutor()

        # 初始化payload生成器
        try:
            from kali_mcp.payloads.generator import PayloadGenerator
            self.payload_engine = PayloadGenerator()
        except ImportError:
            # 简单的payload生成器
            self.payload_engine = None

        # 初始化AI决策组件
        self.ai_context = None
        self.strategy_engine = None

        # 初始化链式推理引擎
        self.chain_engine = None
        self.sequential_integrator = None

        try:
            # 尝试导入AI组件（可选）
            from kali_mcp.core.ai_context import AIContextManager
            from kali_mcp.core.strategy import StrategyEngine
            self.ai_context = AIContextManager()
            self.strategy_engine = StrategyEngine()
            logger.info("AI决策组件已加载")
        except ImportError:
            logger.info("AI决策组件未找到，使用默认策略")
            self.ai_context = None
            self.strategy_engine = None

        try:
            # 导入链式推理引擎
            from kali_mcp.reasoning import ChainReasoningEngine, SequentialThinkingIntegrator
            self.chain_engine = ChainReasoningEngine()
            self.sequential_integrator = SequentialThinkingIntegrator()
            logger.info("链式推理引擎已加载")
        except ImportError:
            logger.warning("链式推理引擎未找到，链式推理功能不可用")
            self.chain_engine = None
            self.sequential_integrator = None

    def excavate(self, target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        执行深度挖掘

        Args:
            target: 目标URL或IP
            mode: 工作模式 (ctf/pentest/auto)

        Returns:
            挖掘结果字典
        """
        # 初始化
        self.start_time = datetime.now()
        self.results["start_time"] = self.start_time.isoformat()

        # 识别模式
        if mode == "auto":
            mode = self._detect_mode(target)
        self.mode = mode
        self.results["mode"] = mode

        logger.info(f"开始深度挖掘: {target}, 模式: {mode}")

        try:
            # 根据模式执行不同的挖掘策略
            if mode == "ctf":
                result = self._execute_ctf_mode(target)
            else:  # pentest
                result = self._execute_pentest_mode(target)

            self.results.update(result)
            self.results["success"] = True

        except Exception as e:
            logger.error(f"深度挖掘失败: {str(e)}")
            self.results["success"] = False
            self.results["error"] = str(e)

        finally:
            # 记录结束时间
            end_time = datetime.now()
            self.results["end_time"] = end_time.isoformat()
            self.results["duration"] = (end_time - self.start_time).total_seconds()

            # 生成摘要
            self.results["summary"] = self._generate_summary()

            # v5.2: 通过EventBus广播挖掘结果
            self._emit_digger_results(target)

        return self.results

    def _detect_mode(self, target: str) -> str:
        """
        自动识别目标模式

        Args:
            target: 目标URL或IP

        Returns:
            "ctf" 或 "pentest"
        """
        # CTF特征检测
        ctf_keywords = [
            "ctf", "flag", "challenge", "hack",
            "awd", "jeopardy", "pwnable"
        ]

        # 常见CTF平台域名
        ctf_domains = [
            "ctflearn.org", "ctftime.org", "picoctf.com",
            "hackthebox.eu", "tryhackme.com"
        ]

        target_lower = target.lower()

        # 检查CTF关键词
        for keyword in ctf_keywords:
            if keyword in target_lower:
                logger.info(f"检测到CTF特征: {keyword}")
                return "ctf"

        # 检查CTF平台域名
        for domain in ctf_domains:
            if domain in target_lower:
                logger.info(f"检测到CTF平台: {domain}")
                return "ctf"

        # 检查渗透测试特征（内网IP）
        if re.match(r'^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)', target):
            logger.info("检测到内网IP，判定为渗透测试模式")
            return "pentest"

        # 默认为CTF模式（更激进）
        logger.info("未明确检测到模式，默认使用CTF模式")
        return "ctf"

    def _execute_ctf_mode(self, target: str) -> Dict[str, Any]:
        """
        CTF模式：快速挖掘（60秒内完成）

        子类必须实现此方法。

        Args:
            target: 目标URL或IP

        Returns:
            挖掘结果
        """
        raise NotImplementedError("子类必须实现_execute_ctf_mode方法")

    def _execute_pentest_mode(self, target: str) -> Dict[str, Any]:
        """
        渗透测试模式：深度全面挖掘

        子类必须实现此方法。

        Args:
            target: 目标URL或IP

        Returns:
            挖掘结果
        """
        raise NotImplementedError("子类必须实现_execute_pentest_mode方法")

    def _check_timeout(self) -> bool:
        """
        检查是否超时（仅CTF模式）

        Returns:
            True if 超时
        """
        if self.mode != "ctf":
            return False

        if self.start_time is None:
            return False

        elapsed = (datetime.now() - self.start_time).total_seconds()
        return elapsed >= self.time_limit

    def _get_remaining_time(self) -> float:
        """
        获取剩余时间（仅CTF模式）

        Returns:
            剩余秒数
        """
        if self.mode != "ctf" or self.start_time is None:
            return float('inf')

        elapsed = (datetime.now() - self.start_time).total_seconds()
        remaining = self.time_limit - elapsed
        return max(0, remaining)

    def _extract_flags(self, text: str) -> List[str]:
        """
        从文本中提取Flag

        支持的Flag格式：
        - flag{...}
        - FLAG{...}
        - ctf{...}
        - CTF{...}
        - DASCTF{...}
        - xxx{...}

        Args:
            text: 要搜索的文本

        Returns:
            找到的Flag列表
        """
        flags = []

        # 常见Flag格式的正则表达式
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[^}]+\}',  # 通用格式
            # 哈希格式（32/40/64位十六进制）
            r'\b[a-f0-9]{32}\b',
            r'\b[a-f0-9]{40}\b',
            r'\b[a-f0-9]{64}\b',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)

        # 去重
        return list(set(flags))

    def _extract_flags_from_data(self, data: str) -> Dict[str, str]:
        """
        从数据中提取Flag（返回字典形式）

        Args:
            data: 要搜索的数据

        Returns:
            Flag字典 {flag_path: flag_content}
        """
        flags_dict = {}

        # 使用_extract_flags方法提取所有flag
        flags = self._extract_flags(data)

        # 为每个flag生成key
        for i, flag in enumerate(flags):
            # 尝试识别flag来源
            if '/flag' in data.lower() or 'flag.txt' in data.lower():
                source = "file:/flag"
            elif 'table' in data.lower() or 'database' in data.lower():
                source = "database:flag_table"
            elif 'shell' in data.lower() or 'command' in data.lower():
                source = "command_output"
            else:
                source = f"extracted_{i}"

            flags_dict[source] = flag

        return flags_dict

    def _generate_summary(self) -> str:
        """
        生成挖掘摘要

        Returns:
            摘要字符串
        """
        if not self.results["success"]:
            return "深度挖掘失败"

        mode = self.results["mode"]
        duration = self.results["duration"]

        if mode == "ctf":
            flag_count = len(self.results.get("flags", []))
            return f"CTF模式完成: 发现{flag_count}个Flag, 耗时{duration:.2f}秒"
        else:
            finding_count = len(self.results.get("findings", []))
            return f"渗透测试模式完成: 发现{finding_count}个漏洞, 耗时{duration:.2f}秒"

    def _log_phase(self, phase_name: str, message: str):
        """
        记录阶段日志

        Args:
            phase_name: 阶段名称
            message: 日志消息
        """
        logger.info(f"[{phase_name}] {message}")

        # 检查超时
        if self._check_timeout():
            logger.warning(f"CTF模式超时（{self.time_limit}秒），停止挖掘")
            raise TimeoutError(f"CTF模式超时限制: {self.time_limit}秒")

    def _execute_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """
        执行工具的通用接口

        子类可以重写此方法以支持不同的工具执行方式。

        Args:
            tool_name: 工具名称
            **kwargs: 工具参数

        Returns:
            工具执行结果
        """
        # 这里应该调用实际的工具执行器
        # 目前先返回空字典，子类可以重写
        logger.info(f"执行工具: {tool_name}, 参数: {kwargs}")
        return {}

    def _analyze_result(self, result: Dict[str, Any]) -> bool:
        """
        分析工具结果

        Args:
            result: 工具执行结果

        Returns:
            是否成功
        """
        return result.get("success", False)

    def _merge_findings(self, *results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        合并多个结果的发现

        Args:
            *results: 多个结果字典

        Returns:
            合并后的发现列表
        """
        findings = []

        for result in results:
            if "findings" in result:
                findings.extend(result["findings"])

        return findings

    def _get_ai_strategy(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        获取AI推荐的攻击策略

        Args:
            target: 目标
            context: 上下文信息

        Returns:
            策略建议
        """
        if self.strategy_engine:
            try:
                # 使用StrategyEngine获取策略
                strategy = self.strategy_engine.select_strategy(context)
                return {
                    "recommended_strategy": strategy,
                    "confidence": "high",
                    "source": "ai_strategy_engine"
                }
            except Exception as e:
                logger.warning(f"AI策略获取失败: {str(e)}")

        # 默认策略
        return {
            "recommended_strategy": "standard",
            "confidence": "medium",
            "source": "default"
        }

    def _update_ai_context(self, phase: str, result: Dict[str, Any]):
        """
        更新AI上下文

        Args:
            phase: 当前阶段
            result: 执行结果
        """
        if self.ai_context:
            try:
                # 记录发现
                if "findings" in result:
                    for finding in result["findings"]:
                        self.ai_context.add_asset(finding)

                # 记录Flag
                if "flags" in result:
                    for flag in result["flags"]:
                        self.ai_context.add_conversation("flag_found", flag)

            except Exception as e:
                logger.debug(f"AI上下文更新失败: {str(e)}")

    def _should_continue(self) -> bool:
        """
        AI决策：是否应该继续挖掘

        Returns:
            True if 应该继续
        """
        # CTF模式：检查是否超时
        if self.mode == "ctf" and self._check_timeout():
            return False

        # 如果有AI上下文，咨询AI
        if self.ai_context:
            try:
                # 基于已发现的信息判断
                if len(self.results.get("flags", [])) > 0:
                    # 已找到Flag，CTF模式可以停止
                    if self.mode == "ctf":
                        return False

                # 渗透测试模式继续深入
                return True

            except Exception as e:
                logger.debug(f"AI决策失败: {str(e)}")

        # 默认继续
        return True

    def _optimize_tool_selection(self, available_tools: List[str]) -> List[str]:
        """
        AI优化工具选择

        Args:
            available_tools: 可用工具列表

        Returns:
            优化后的工具执行顺序
        """
        if not available_tools:
            return []

        # 简单优化：优先使用快速工具
        priority_tools = {
            "quick_scan": 1,
            "fast_test": 2,
            "enumerate": 3,
            "exploit": 4,
            "deep_analysis": 5
        }

        try:
            # 按优先级排序
            sorted_tools = sorted(
                available_tools,
                key=lambda x: priority_tools.get(x, 99)
            )
            return sorted_tools

        except Exception as e:
            logger.debug(f"工具优化失败: {str(e)}")
            return available_tools

    def _perform_chain_reasoning(self,
                                  initial_finding: Dict[str, Any],
                                  context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        执行链式推理

        基于初始发现，使用知识图谱和Sequential Thinking进行深度推理。

        Args:
            initial_finding: 初始发现
            context: 上下文信息

        Returns:
            推理步骤列表
        """
        if not self.chain_engine:
            logger.warning("[链式推理] 推理引擎未初始化")
            return []

        try:
            logger.info(f"[链式推理] 开始深度推理，初始发现: {initial_finding.get('vulnerability_type', 'unknown')}")

            # 使用Sequential Thinking集成器增强推理
            if self.sequential_integrator:
                enhanced_steps = self.sequential_integrator.enhance_reasoning(
                    reasoning_engine=self.chain_engine,
                    initial_finding=initial_finding,
                    context=context
                )

                # 保存推理链到结果中
                if "reasoning_chain" not in self.results:
                    self.results["reasoning_chain"] = []

                self.results["reasoning_chain"].extend(enhanced_steps)

                # 生成可视化
                if self.chain_engine.reasoning_chain:
                    visualization = self.chain_engine.visualize_chain()
                    logger.info(f"\n{visualization}\n")

                return enhanced_steps

            else:
                # 只使用基础推理引擎
                reasoning_chain = self.chain_engine.reason_chain(
                    initial_finding=initial_finding,
                    context=context
                )

                return [step.to_dict() for step in reasoning_chain]

        except Exception as e:
            logger.error(f"[链式推理] 推理失败: {str(e)}")
            return []

    def _should_use_chain_reasoning(self, context: Dict[str, Any]) -> bool:
        """
        判断是否应该使用链式推理

        Args:
            context: 上下文

        Returns:
            是否使用链式推理
        """
        # 必须有推理引擎
        if not self.chain_engine:
            return False

        # 确定当前模式（优先使用context中的mode，其次使用self.mode）
        current_mode = context.get("mode", self.mode)

        # CTF模式：时间充足时使用
        if current_mode == "ctf":
            remaining_time = self._get_remaining_time()
            return remaining_time > 30  # 剩余30秒以上才使用

        # 渗透测试模式：总是使用
        if current_mode == "pentest":
            return True

        # auto模式或其他：默认使用
        return True

    def _get_reasoning_summary(self) -> Dict[str, Any]:
        """
        获取推理摘要

        Returns:
            推理摘要字典
        """
        if not self.chain_engine:
            return {
                "enabled": False,
                "message": "链式推理引擎未初始化"
            }

        summary = self.chain_engine.get_summary()
        summary["enabled"] = True

        return summary

    def _visualize_reasoning_results(self, reasoning_chain: List[Dict[str, Any]]) -> str:
        """
        可视化推理链结果（简化版，无ASCII艺术）

        Args:
            reasoning_chain: 推理链步骤列表

        Returns:
            格式化的可视化字符串
        """
        if not reasoning_chain:
            return "推理链为空"

        lines = []
        lines.append("")
        lines.append("=" * 80)
        lines.append("链式推理过程")
        lines.append("=" * 80)
        lines.append("")

        # 绘制推理链
        for i, step in enumerate(reasoning_chain):
            step_num = step.get("step", i + 1)
            action = step.get("action", "unknown")
            reasoning = step.get("reasoning", "")
            confidence = step.get("confidence", 0.0)

            # 步骤标题
            lines.append(f"[步骤 {step_num}] {action}")
            lines.append(f"  置信度: {confidence:.1%}")

            # 推理逻辑
            if reasoning:
                lines.append(f"  推理: {reasoning[:100]}...")

            # 下一步想法
            next_thoughts = step.get("next_thoughts", [])
            if next_thoughts:
                lines.append(f"  下一步: {next_thoughts[0][:80]}...")

            lines.append("")

        # 统计信息
        lines.append("-" * 80)
        lines.append("推理统计")
        lines.append("-" * 80)
        lines.append(f"  总推理步骤: {len(reasoning_chain)}")
        lines.append(f"  平均置信度: {sum(s.get('confidence', 0) for s in reasoning_chain) / len(reasoning_chain):.2%}")

        if reasoning_chain:
            last_step = reasoning_chain[-1]
            next_thoughts = last_step.get("next_thoughts", [])
            if next_thoughts:
                lines.append("")
                lines.append(f"推荐下一步: {next_thoughts[0]}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    def _format_reasoning_for_report(self, reasoning_chain: List[Dict[str, Any]]) -> str:
        """
        为报告格式化推理链（简化版）

        生成适合包含在渗透测试报告或CTF writeup中的格式

        Args:
            reasoning_chain: 推理链步骤列表

        Returns:
            Markdown格式的推理链
        """
        if not reasoning_chain:
            return "## 链式推理分析\n\n未执行推理链分析。\n"

        lines = []
        lines.append("## 链式推理分析\n")
        lines.append("本分析使用AI驱动的链式推理引擎，基于初始发现自动推导攻击路径。\n")

        # 总览
        lines.append("### 推理概览\n")
        lines.append(f"- **总推理步骤**: {len(reasoning_chain)}")
        avg_conf = sum(s.get('confidence', 0) for s in reasoning_chain) / len(reasoning_chain)
        lines.append(f"- **平均置信度**: {avg_conf:.1%}")
        lines.append("")

        # 详细推理链
        lines.append("### 推理过程\n")

        for i, step in enumerate(reasoning_chain):
            step_num = step.get("step", i + 1)
            action = step.get("action", "unknown")
            reasoning = step.get("reasoning", "")
            confidence = step.get("confidence", 0.0)

            lines.append(f"#### 步骤 {step_num}: {action}\n")
            lines.append(f"**置信度**: {confidence:.1%}\n\n")
            lines.append(f"**推理逻辑**: {reasoning}\n\n")

            next_thoughts = step.get("next_thoughts", [])
            if next_thoughts:
                lines.append("**下一步计划**:\n")
                for thought in next_thoughts:
                    lines.append(f"- {thought}")
                lines.append("")

        # 结论
        lines.append("### 推理结论\n")
        last_step = reasoning_chain[-1]
        next_thoughts = last_step.get("next_thoughts", [])
        if next_thoughts:
            lines.append(f"**推荐行动**: {next_thoughts[0]}\n")
        else:
            lines.append("推理链已完成，无进一步建议。\n")

        return "\n".join(lines)

    # ==================== v5.2: EventBus 集成 ====================

    def _emit_event(self, event_type: str, data: Dict[str, Any]):
        """通过EventBus发射事件（安全，失败不影响主流程）"""
        if self._event_bus is None:
            return
        try:
            self._event_bus.emit(event_type, data, source=self.__class__.__name__)
        except Exception as e:
            logger.debug(f"EventBus emit failed (non-fatal): {e}")

    def _emit_digger_results(self, target: str):
        """挖掘完成后广播所有结果"""
        if self._event_bus is None:
            return

        digger_name = self.__class__.__name__

        # 广播发现的漏洞
        for finding in self.results.get("findings", []):
            self._emit_event("vuln.discovered", {
                "target": target,
                "vuln_type": finding.get("type", finding.get("vulnerability_type", "unknown")),
                "severity": finding.get("severity", "medium"),
                "detail": str(finding.get("detail", finding.get("description", "")))[:500],
                "source": digger_name,
                "mode": self.mode,
            })

        # 广播发现的Flag
        for flag in self.results.get("flags", []):
            self._emit_event("flag.found", {
                "target": target,
                "flag": str(flag)[:200],
                "source": digger_name,
                "mode": self.mode,
            })

        # 广播挖掘完成事件（包含摘要统计）
        self._emit_event("digger.completed", {
            "target": target,
            "digger": digger_name,
            "mode": self.mode,
            "success": self.results.get("success", False),
            "duration": self.results.get("duration", 0),
            "findings_count": len(self.results.get("findings", [])),
            "flags_count": len(self.results.get("flags", [])),
        })
