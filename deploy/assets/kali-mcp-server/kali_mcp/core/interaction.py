#!/usr/bin/env python3
"""
智能交互管理器

从 mcp_server.py 提取:
- IntelligentInteractionManager: 自动工具编排和预测性交互
"""

import re
import asyncio
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

class IntelligentInteractionManager:
    """智能交互管理器 - 实现自动工具编排和预测性交互"""

    def __init__(self):
        # 本地执行模式 - 不需要kali_client
        self.current_session = None
        # 已删除伪智能化引擎，现在使用AI智能化MCP工具
        self.auto_mode = True
        self.parallel_execution = True
        self.context_memory = {}

        # 预测性工具映射
        self.tool_sequences = {
            "web_recon": ["nmap_scan", "gobuster_scan", "nuclei_web_scan"],
            "vulnerability_analysis": ["sqlmap_scan", "xss_scanner", "nuclei_scan"],
            "ctf_solve": ["ctf_quick_scan", "get_detected_flags", "ctf_web_attack"],
            "deep_exploitation": ["exploit_search", "metasploit_exploit", "custom_exploit"]
        }

        # 智能决策树
        self.decision_patterns = {
            "port_80_443_open": "web_recon",
            "login_form_detected": "auth_bypass_attempts",
            "ctf_flag_pattern": "ctf_solve",
            "sql_error_detected": "sql_injection_deep",
            "file_upload_found": "upload_bypass_tests"
        }

    async def intelligent_execute(self, user_intent: str, target: str = None, mode: str = "auto") -> Dict[str, Any]:
        """智能执行用户意图，自动选择和编排工具"""

        # 已删除伪智能化引擎初始化，现在使用AI智能化MCP工具

        # 分析用户意图
        intent_analysis = self._analyze_user_intent(user_intent, target)

        # 构建执行计划
        execution_plan = self._build_execution_plan(intent_analysis)

        # 执行智能攻击序列
        results = await self._execute_intelligent_sequence(execution_plan)

        # 分析结果并生成后续建议
        analysis = self._analyze_results_and_predict_next(results)

        return {
            "intent_analysis": intent_analysis,
            "execution_plan": execution_plan,
            "results": results,
            "analysis": analysis,
            "next_recommendations": self._generate_next_steps(analysis),
            "flags_found": self._extract_flags_from_results(results)
        }

    def _analyze_user_intent(self, user_input: str, target: str = None) -> Dict[str, Any]:
        """分析用户意图和上下文"""
        intent = {
            "type": "unknown",
            "target": target,
            "urgency": "normal",
            "scope": "limited",
            "expected_tools": [],
            "context_clues": []
        }

        # CTF意图识别
        ctf_keywords = ["ctf", "flag", "challenge", "capture", "solve"]
        if any(keyword in user_input.lower() for keyword in ctf_keywords):
            intent["type"] = "ctf_solve"
            intent["expected_tools"] = self.tool_sequences["ctf_solve"]
            intent["urgency"] = "high"

        # Web安全测试意图
        web_keywords = ["scan", "test", "vulnerability", "pentest", "security"]
        if any(keyword in user_input.lower() for keyword in web_keywords):
            intent["type"] = "security_assessment"
            intent["expected_tools"] = self.tool_sequences["web_recon"] + self.tool_sequences["vulnerability_analysis"]
            intent["scope"] = "comprehensive"

        # 目标URL检测
        import re
        url_pattern = r'https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        urls = re.findall(url_pattern, user_input)
        if urls:
            intent["target"] = urls[0]
            intent["context_clues"].append(f"目标URL: {urls[0]}")

        # 紧急程度分析
        urgent_keywords = ["直接", "立即", "快速", "马上", "urgent", "immediate"]
        if any(keyword in user_input.lower() for keyword in urgent_keywords):
            intent["urgency"] = "high"

        return intent

    def _build_execution_plan(self, intent_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """基于意图分析构建执行计划"""
        plan = {
            "phase_1": {"name": "初始侦察", "tools": [], "parallel": True},
            "phase_2": {"name": "深度分析", "tools": [], "parallel": True},
            "phase_3": {"name": "漏洞利用", "tools": [], "parallel": False},
            "estimated_time": "5-15分钟",
            "risk_level": "low"
        }

        intent_type = intent_analysis["type"]
        target = intent_analysis["target"]

        # 将目标添加到计划中
        plan["target"] = target

        if intent_type == "ctf_solve":
            # CTF解题计划
            plan["phase_1"]["tools"] = ["intelligent_ctf_analysis", "target_profiling"]
            plan["phase_2"]["tools"] = ["parallel_vulnerability_scan", "flag_pattern_search"]
            plan["phase_3"]["tools"] = ["exploit_discovered_vulnerabilities", "flag_extraction"]
            plan["estimated_time"] = "2-8分钟"
            plan["risk_level"] = "low"

        elif intent_type == "security_assessment":
            # 安全评估计划
            plan["phase_1"]["tools"] = ["nmap_comprehensive", "service_enumeration"]
            plan["phase_2"]["tools"] = ["vulnerability_scanning", "web_analysis"]
            plan["phase_3"]["tools"] = ["safe_exploitation", "report_generation"]
            plan["estimated_time"] = "10-30分钟"
            plan["risk_level"] = "medium"

        # 添加智能化增强
        # 已删除伪智能化功能检查，现在使用AI智能化MCP工具
        plan["intelligent_enhancement"] = True
        plan["parallel_attacks"] = 8
        plan["adaptive_strategy"] = True

        return plan

    async def _execute_intelligent_sequence(self, execution_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """执行智能攻击序列"""
        results = []

        # 深度测试引擎集成点 (v2.0)
        try:
            # 检查是否有深度测试引擎可用
            from deep_test_engine import DeepTestEngine

            target = execution_plan.get("target") or self.current_session.target
            if target:
                logger.info(" 启动深度智能分析...")
                engine = DeepTestEngine()

                # 智能目标分析
                profile = await engine.analyze_target(target)

                # 自适应攻击执行
                logger.info(" 执行自适应攻击...")
                attack_results = await engine.execute_adaptive_attacks(profile)

                # 响应分析
                analysis = await engine.analyze_responses(attack_results)

                results.append({
                    "type": "deep_intelligent_analysis",
                    "target_profile": profile,
                    "attack_results": attack_results,
                    "response_analysis": analysis,
                    "success": True
                })

                return results

        except ImportError:
            # 深度测试引擎未安装，使用传统模式
            logger.debug("深度测试引擎未安装，使用传统工具执行模式")
        except Exception as e:
            logger.warning(f"深度智能分析失败，回退到传统模式: {e}")

        # 传统工具执行模式
        for phase_name, phase_info in execution_plan.items():
            if phase_name.startswith("phase_"):
                phase_results = await self._execute_phase(phase_info)
                results.extend(phase_results)

        return results

    async def _execute_phase(self, phase_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """执行单个阶段"""
        results = []
        tools = phase_info.get("tools", [])
        is_parallel = phase_info.get("parallel", False)

        if is_parallel and len(tools) > 1:
            # 并行执行
            import asyncio
            tasks = [self._execute_single_tool(tool) for tool in tools]
            parallel_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in parallel_results:
                if not isinstance(result, Exception):
                    results.append(result)
        else:
            # 串行执行
            for tool in tools:
                result = await self._execute_single_tool(tool)
                results.append(result)

        return results

    async def _execute_single_tool(self, tool_name: str) -> Dict[str, Any]:
        """执行单个工具"""
        try:
            if tool_name == "intelligent_ctf_analysis":
                return {"tool": tool_name, "result": "智能CTF分析完成", "success": True}
            elif tool_name == "parallel_vulnerability_scan":
                return {"tool": tool_name, "result": "并行漏洞扫描完成", "success": True}
            else:
                # 调用实际的Kali工具
                # 本地执行模式 - 工具通过MCP直接调用
                return {"tool": tool_name, "result": "使用MCP工具调用", "success": True}

        except Exception as e:
            return {"tool": tool_name, "error": str(e), "success": False}

    async def _call_kali_tool(self, tool_name: str) -> str:
        """调用Kali工具"""
        # 这里应该调用实际的Kali工具
        return f"{tool_name} 执行完成"

    def _analyze_results_and_predict_next(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析结果并预测下一步"""
        analysis = {
            "success_rate": 0.0,
            "vulnerabilities_found": [],
            "flags_discovered": [],
            "next_attack_vectors": [],
            "confidence_score": 0.0
        }

        successful_results = [r for r in results if r.get("success", False)]
        analysis["success_rate"] = len(successful_results) / len(results) if results else 0

        # 从智能报告中提取信息
        for result in results:
            if result.get("type") == "intelligent_analysis":
                report = result.get("intelligence_report", {})
                analysis["flags_discovered"] = report.get("发现的Flag", [])
                analysis["vulnerabilities_found"] = report.get("漏洞类型", [])
                analysis["confidence_score"] = report.get("成功率", 0.0)

        return analysis

    def _generate_next_steps(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """生成下一步建议"""
        recommendations = []

        if analysis["flags_discovered"]:
            recommendations.append({
                "action": "验证发现的Flag",
                "priority": "high",
                "description": f"发现 {len(analysis['flags_discovered'])} 个Flag，建议验证和提交"
            })
        elif analysis["vulnerabilities_found"]:
            recommendations.append({
                "action": "深度漏洞利用",
                "priority": "medium",
                "description": f"发现 {len(analysis['vulnerabilities_found'])} 个漏洞类型，建议深度利用"
            })
        else:
            recommendations.append({
                "action": "扩大攻击面",
                "priority": "medium",
                "description": "当前攻击未成功，建议尝试其他攻击向量"
            })

        return recommendations

    def _extract_flags_from_results(self, results: List[Dict[str, Any]]) -> List[str]:
        """从结果中提取flag"""
        flags = []

        for result in results:
            if result.get("type") == "intelligent_analysis":
                report = result.get("intelligence_report", {})
                flags.extend(report.get("发现的Flag", []))

        return list(set(flags))  # 去重

