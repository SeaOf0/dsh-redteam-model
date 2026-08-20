#!/usr/bin/env python3
"""
AI上下文感知和会话管理工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from kali_mcp.core.mcp_session import SessionContext
from kali_mcp.core.ai_context import AIContextManager
from kali_mcp.core.ml_optimizer import MLStrategyOptimizer
from kali_mcp.core.memory_persistence import AdvancedMemoryPersistence
logger = logging.getLogger(__name__)


def register_ai_session_tools(mcp, executor, ai_context_manager, ml_strategy_optimizer):
    """AI上下文感知和会话管理工具注册"""

    # ==================== AI上下文感知工具 ====================

    @mcp.tool()
    def ai_create_session(target: str = "", attack_mode: str = "pentest", session_name: str = "") -> Dict[str, Any]:
        """
        创建新的AI上下文感知会话 - 启用持续对话状态管理

        Args:
            target: 目标IP地址、域名或URL
            attack_mode: 攻击模式 (pentest, ctf, analysis)
            session_name: 自定义会话名称（可选）

        Returns:
            新创建的会话信息和初始建议
        """
        try:
            session = ai_context_manager.create_session(target, attack_mode)
            if session_name:
                session.context_metadata["custom_name"] = session_name

            # 立即分析目标并生成初始策略建议
            if target:
                initial_analysis = ai_context_manager.strategy_engine.analyze_context(session, f"分析目标 {target}")
                session.context_metadata["initial_analysis"] = initial_analysis

            return {
                "success": True,
                "session_id": session.session_id,
                "session_summary": session.get_context_summary(),
                "initial_strategy_recommendations": session.context_metadata.get("initial_analysis", {}),
                "next_steps": ai_context_manager.get_session_insights(session.session_id),
                "message": f"AI会话已创建，会话ID: {session.session_id}"
            }
        except Exception as e:
            logger.error(f"AI session creation error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_analyze_intent(user_message: str, session_id: str = "") -> Dict[str, Any]:
        """
        AI意图分析 - 分析用户输入并提供智能建议

        Args:
            user_message: 用户输入的消息
            session_id: 会话ID（可选）

        Returns:
            意图分析结果和智能建议
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 分析用户意图
            intent = ai_context_manager.analyze_user_intent(user_message)

            # 生成上下文感知的响应
            contextual_response = ai_context_manager.generate_contextual_response(session, user_message)

            # 更新目标（如果从消息中提取到了新目标）
            if intent.get("target_extraction") and not session.target:
                session.target = intent["target_extraction"]
                session.context_metadata["target_auto_extracted"] = True

            return {
                "success": True,
                "session_id": session.session_id,
                "intent_analysis": intent,
                "contextual_response": contextual_response,
                "session_updated": bool(intent.get("target_extraction")),
                "recommended_tools": contextual_response.get("strategy_recommendations", [])
            }
        except Exception as e:
            logger.error(f"AI intent analysis error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_get_strategy_recommendations(session_id: str = "", user_context: str = "") -> Dict[str, Any]:
        """
        获取AI策略建议 - 基于当前会话上下文推荐最佳攻击策略

        Args:
            session_id: 会话ID（可选）
            user_context: 额外的用户上下文信息

        Returns:
            详细的策略建议和执行计划
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 获取策略建议
            strategy_analysis = ai_context_manager.strategy_engine.analyze_context(session, user_context)

            # 获取会话洞察
            insights = ai_context_manager.get_session_insights(session.session_id)

            return {
                "success": True,
                "session_id": session.session_id,
                "strategy_analysis": strategy_analysis,
                "session_insights": insights,
                "execution_plan": {
                    "recommended_strategies": strategy_analysis.get("recommended_strategies", []),
                    "next_actions": insights.get("next_recommendations", []),
                    "estimated_completion_time": "根据策略复杂度而定"
                },
                "context_summary": session.get_context_summary()
            }
        except Exception as e:
            logger.error(f"AI strategy recommendations error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_execute_strategy(strategy_name: str, session_id: str = "", auto_execute: bool = False) -> Dict[str, Any]:
        """
        AI策略执行 - 自动执行推荐的攻击策略

        Args:
            strategy_name: 策略名称 (web_comprehensive, ctf_quick_solve, network_recon, pwn_exploitation, adaptive_multi)
            session_id: 会话ID（可选）
            auto_execute: 是否自动执行所有相关工具

        Returns:
            策略执行结果和进展状态
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)
            strategy_tools = ai_context_manager.strategy_engine.get_strategy_tools(strategy_name)

            if not strategy_tools:
                return {"success": False, "error": f"Unknown strategy: {strategy_name}"}

            execution_results = {
                "strategy_name": strategy_name,
                "session_id": session.session_id,
                "tools_executed": [],
                "tools_failed": [],
                "overall_success": False,
                "execution_summary": {}
            }

            if auto_execute and session.target:
                # 自动执行策略中的工具
                successful_tools = 0
                total_tools = len(strategy_tools)

                for tool_name in strategy_tools:
                    try:
                        # 根据工具类型调用相应的函数
                        if tool_name == "nmap_scan":
                            result = executor.execute_tool_with_data("nmap", {
                                "target": session.target, "scan_type": "-sS",
                                "ports": "80,443,22",
                                "additional_args": "-T5 --open --min-rate 5000 --max-retries 1"
                            })
                        elif tool_name == "gobuster_scan":
                            target_url = session.target if session.target.startswith("http") else f"http://{session.target}"
                            result = executor.execute_tool_with_data("gobuster", {
                                "url": target_url, "mode": "dir",
                                "wordlist": "/usr/share/wordlists/dirb/small.txt",
                                "additional_args": "-t 100 --timeout 3s -q"
                            })
                        elif tool_name == "nuclei_web_scan":
                            target_url = session.target if session.target.startswith("http") else f"http://{session.target}"
                            result = nuclei_web_scan(target_url, "comprehensive")
                        elif tool_name == "analyze_target_intelligence":
                            result = executor.execute_tool_with_data("nmap", {
                                "target": session.target, "scan_type": "-sV -sC",
                                "ports": "80,443,22,21,25,53,8080", "additional_args": "-T4"
                            })
                        elif tool_name == "comprehensive_recon":
                            target_url = session.target if session.target.startswith("http") else f"http://{session.target}"
                            result = executor.execute_command(
                                f"nuclei -u {target_url} -t http/ -s critical,high -silent -rl 100 -timeout 10"
                            )
                        else:
                            result = {"success": False, "error": f"Tool {tool_name} not implemented for auto-execution"}

                        if result.get("success", False):
                            execution_results["tools_executed"].append({
                                "tool": tool_name,
                                "result": result,
                                "timestamp": datetime.now().isoformat()
                            })
                            successful_tools += 1
                        else:
                            execution_results["tools_failed"].append({
                                "tool": tool_name,
                                "error": result.get("error", "Unknown error"),
                                "timestamp": datetime.now().isoformat()
                            })

                    except Exception as e:
                        execution_results["tools_failed"].append({
                            "tool": tool_name,
                            "error": str(e),
                            "timestamp": datetime.now().isoformat()
                        })

                execution_results["overall_success"] = successful_tools > 0
                execution_results["execution_summary"] = {
                    "successful_tools": successful_tools,
                    "total_tools": total_tools,
                    "success_rate": f"{(successful_tools/total_tools)*100:.1f}%"
                }

                # 更新会话状态
                session.completed_tasks.append(f"strategy_{strategy_name}")
                session.current_strategy = strategy_name

            else:
                # 仅返回策略工具列表，不自动执行
                execution_results["tools_to_execute"] = strategy_tools
                execution_results["auto_execution_disabled"] = True
                execution_results["message"] = f"Strategy {strategy_name} prepared. Set auto_execute=True to run automatically."

            return {
                "success": True,
                "execution_results": execution_results,
                "session_updated": True
            }

        except Exception as e:
            logger.error(f"AI strategy execution error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_update_session_context(session_id: str, discovered_info: Dict[str, Any],
                                tools_used: List[str] = None, user_feedback: str = "") -> Dict[str, Any]:
        """
        更新AI会话上下文 - 手动更新会话状态和发现的信息

        Args:
            session_id: 会话ID
            discovered_info: 新发现的信息 (例: {"open_ports": [80, 443], "vulnerabilities": ["SQL injection"]})
            tools_used: 使用的工具列表
            user_feedback: 用户反馈信息

        Returns:
            更新后的会话状态和新建议
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 更新发现的资产
            for key, value in discovered_info.items():
                if key in session.discovered_assets:
                    if isinstance(session.discovered_assets[key], list):
                        session.discovered_assets[key].extend(value if isinstance(value, list) else [value])
                    else:
                        session.discovered_assets[key] = value
                else:
                    session.discovered_assets[key] = value

            # 添加到对话历史
            if user_feedback:
                session.add_conversation(
                    user_message=f"Context update: {user_feedback}",
                    ai_response="Session context updated with new discoveries",
                    tools_used=tools_used or []
                )

            # 更新知识库
            for category, data in discovered_info.items():
                ai_context_manager.update_knowledge_base("session_discoveries", f"{session.session_id}_{category}", data)

            # 获取更新后的洞察
            insights = ai_context_manager.get_session_insights(session.session_id)

            return {
                "success": True,
                "session_id": session.session_id,
                "updated_context": session.get_context_summary(),
                "new_insights": insights,
                "next_recommendations": insights.get("next_recommendations", []),
                "message": "Session context updated successfully"
            }

        except Exception as e:
            logger.error(f"AI session context update error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_get_session_history(session_id: str = "", include_full_details: bool = False) -> Dict[str, Any]:
        """
        获取AI会话历史 - 查看完整的对话历史和分析进展

        Args:
            session_id: 会话ID（可选，默认当前会话）
            include_full_details: 是否包含完整的工具执行详情

        Returns:
            完整的会话历史和分析摘要
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            history = {
                "session_summary": session.get_context_summary(),
                "conversation_history": session.conversation_history,
                "discovered_assets": session.discovered_assets,
                "completed_tasks": session.completed_tasks,
                "timeline": []
            }

            # 生成时间线
            for conv in session.conversation_history:
                history["timeline"].append({
                    "timestamp": conv["timestamp"],
                    "event_type": "conversation",
                    "summary": conv["user_message"][:100] + "..." if len(conv["user_message"]) > 100 else conv["user_message"],
                    "tools_used": conv.get("tools_used", [])
                })

            if not include_full_details:
                # 简化对话历史，只保留摘要
                simplified_history = []
                for conv in session.conversation_history:
                    simplified_history.append({
                        "timestamp": conv["timestamp"],
                        "user_message_summary": conv["user_message"][:50] + "..." if len(conv["user_message"]) > 50 else conv["user_message"],
                        "tools_used": conv.get("tools_used", []),
                        "session_context": conv.get("session_context", {})
                    })
                history["conversation_history"] = simplified_history

            return {
                "success": True,
                "session_id": session.session_id,
                "session_history": history,
                "analysis": {
                    "total_interactions": len(session.conversation_history),
                    "session_duration": str(datetime.now() - session.start_time),
                    "unique_tools_used": len(set(
                        tool for conv in session.conversation_history
                        for tool in conv.get("tools_used", [])
                    )),
                    "discovery_progress": f"{len(session.discovered_assets)} categories discovered"
                }
            }

        except Exception as e:
            logger.error(f"AI session history error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_smart_continuation(session_id: str = "", user_hint: str = "") -> Dict[str, Any]:
        """
        AI智能续接 - 基于当前上下文智能推荐下一步操作

        Args:
            session_id: 会话ID（可选）
            user_hint: 用户提示或偏好（可选）

        Returns:
            智能推荐的下一步操作和执行计划
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 分析当前进展
            insights = ai_context_manager.get_session_insights(session.session_id)

            # 如果有用户提示，结合分析
            combined_context = f"{user_hint} 当前目标: {session.target}" if user_hint else f"继续分析目标: {session.target}"
            contextual_response = ai_context_manager.generate_contextual_response(session, combined_context)

            # 生成智能建议
            smart_recommendations = []

            # 基于已完成任务推荐下一步
            if "nmap_scan" in str(session.completed_tasks):
                smart_recommendations.append({
                    "priority": "high",
                    "action": "深入漏洞扫描",
                    "tools": ["nuclei_scan", "nikto_scan"],
                    "reason": "端口扫描已完成，建议进行漏洞检测"
                })

            if len(session.discovered_assets.get("open_ports", [])) > 0:
                smart_recommendations.append({
                    "priority": "medium",
                    "action": "服务枚举",
                    "tools": ["enum4linux_scan", "dnsrecon_scan"],
                    "reason": f"发现 {len(session.discovered_assets['open_ports'])} 个开放端口，建议枚举服务"
                })

            # 如果是CTF模式，优先Flag检测
            if session.attack_mode == "ctf":
                smart_recommendations.insert(0, {
                    "priority": "urgent",
                    "action": "CTF Flag搜索",
                    "tools": ["get_detected_flags", "ctf_quick_scan"],
                    "reason": "CTF模式下优先搜索Flag"
                })

            # 辅助函数内联定义
            def _determine_next_phase(sess: SessionContext) -> str:
                """确定下一个攻击阶段"""
                completed = len(sess.completed_tasks)
                if completed == 0:
                    return "reconnaissance"
                elif completed < 3:
                    return "vulnerability_discovery"
                elif completed < 5:
                    return "exploitation"
                else:
                    return "post_exploitation"

            def _estimate_completion_time(sess: SessionContext) -> str:
                """估算完成时间"""
                if sess.attack_mode == "ctf":
                    return "5-15 minutes"
                elif len(sess.discovered_assets) > 3:
                    return "20-45 minutes"
                else:
                    return "30-60 minutes"

            def _calculate_confidence(sess: SessionContext) -> str:
                """计算置信度"""
                if len(sess.discovered_assets) > 2 and len(sess.completed_tasks) > 2:
                    return "high"
                elif len(sess.completed_tasks) > 0:
                    return "medium"
                else:
                    return "low"

            return {
                "success": True,
                "session_id": session.session_id,
                "current_progress": insights,
                "smart_recommendations": smart_recommendations,
                "contextual_insights": contextual_response,
                "continuation_strategy": {
                    "next_phase": _determine_next_phase(session),
                    "estimated_time": _estimate_completion_time(session),
                    "confidence_level": _calculate_confidence(session)
                }
            }

        except Exception as e:
            logger.error(f"AI smart continuation error: {str(e)}")
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.

        Args:
            command: The command to execute

        Returns:
            Command execution results
        """
        # 危险命令黑名单检查
        DANGEROUS_PATTERNS = [
            "rm -rf /", "rm -rf /*", "mkfs.", "dd if=",
            ":(){ :|:& };:", "> /dev/sda", "chmod -R 777 /",
            "mv / ", "wget|sh", "curl|sh",
        ]
        cmd_lower = command.lower().strip()
        for pattern in DANGEROUS_PATTERNS:
            if pattern.lower() in cmd_lower:
                logger.warning(f"[AUDIT] 拦截危险命令: {command}")
                return {
                    "success": False,
                    "error": f"命令被安全策略拦截: 包含危险模式 '{pattern}'",
                    "output": "",
                    "return_code": -1,
                    "command": command
                }
        logger.info(f"[AUDIT] 执行命令: {command}")
        return executor.execute_command(command)

    @mcp.tool()
    def nuclei_scan(target: str, templates: str = "", severity: str = "critical,high,medium",
                   tags: str = "", output_format: str = "json") -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner.

        Args:
            target: Target URL, IP, or domain to scan
            templates: Specific templates to use (e.g., 'http/cves/', 'http/misconfiguration/')
                       Note: In nuclei v3+, CVE templates are under 'http/cves/' or 'network/cves/'
            severity: Severity levels to include (critical,high,medium,low,info)
            tags: Tags to filter templates (e.g., 'sqli,xss,rce')
            output_format: Output format (json or text)

        Returns:
            Nuclei scan results
        """
        # 构建nuclei命令
        cmd_parts = ["nuclei", "-u", target]

        # 添加模板过滤 (nuclei v3+ 模板路径变化)
        if templates:
            cmd_parts.extend(["-t", templates])

        # 添加严重程度过滤 (-s 是短格式，兼容新旧版本)
        if severity:
            cmd_parts.extend(["-s", severity])

        # 添加标签过滤
        if tags:
            cmd_parts.extend(["-tags", tags])

        # 设置输出格式
        if output_format == "json":
            cmd_parts.append("-jsonl")  # nuclei v3+ 使用 -jsonl

        # 添加静默模式和其他优化参数
        cmd_parts.extend(["-silent", "-rl", "100", "-timeout", "10"])

        command = " ".join(cmd_parts)
        return executor.execute_command(command)

    @mcp.tool()
    def nuclei_cve_scan(target: str, year: str = "", severity: str = "critical,high") -> Dict[str, Any]:
        """
        Execute Nuclei CVE vulnerability scan.

        Args:
            target: Target URL, IP, or domain to scan
            year: Specific CVE year to scan (e.g., '2023', '2024')
            severity: Severity levels to include

        Returns:
            CVE scan results
        """
        templates = f"cves/{year}/" if year else "cves/"
        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_web_scan(target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Execute Nuclei web application security scan.

        Args:
            target: Target web application URL
            scan_type: Type of scan (quick, comprehensive, deep)

        Returns:
            Web application scan results
        """
        if scan_type == "quick":
            templates = "http/misconfiguration/,http/vulnerabilities/"
            severity = "critical,high"
        elif scan_type == "comprehensive":
            templates = "http/,vulnerabilities/web/"
            severity = "critical,high,medium"
        elif scan_type == "deep":
            templates = "http/,vulnerabilities/,cves/,exposures/"
            severity = "critical,high,medium,low"
        else:
            templates = "http/misconfiguration/"
            severity = "critical,high"

        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_network_scan(target: str, scan_type: str = "basic") -> Dict[str, Any]:
        """
        Execute Nuclei network security scan.

        Args:
            target: Target IP or network range
            scan_type: Type of scan (basic, full)

        Returns:
            Network scan results
        """
        if scan_type == "full":
            templates = "network/,dns/,ssl/,misconfiguration/"
            severity = "critical,high,medium"
        else:
            templates = "network/,dns/"
            severity = "critical,high"

        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_technology_detection(target: str) -> Dict[str, Any]:
        """
        Execute Nuclei technology detection scan.

        Args:
            target: Target URL or IP to analyze

        Returns:
            Technology detection results
        """
        return nuclei_scan(target, "technologies/", "info", "", "json")

    @mcp.tool()
    def dnsrecon_scan(domain: str, scan_type: str = "-t std",
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute DNSrecon for comprehensive DNS enumeration.

        Args:
            domain: Target domain for DNS enumeration
            scan_type: Type of DNS scan (e.g., "-t std", "-t axfr", "-t brt")
            additional_args: Additional DNSrecon arguments

        Returns:
            DNS enumeration results
        """
        data = {
            "domain": domain,
            "scan_type": scan_type,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("dnsrecon", data)

    @mcp.tool()
    def wpscan_scan(target: str, api_token: str = "",
                    additional_args: str = "--enumerate p,t,u") -> Dict[str, Any]:
        """
        Execute WPScan for WordPress security testing.

        Args:
            target: Target WordPress URL
            api_token: WPScan API token for vulnerability data
            additional_args: Additional WPScan arguments

        Returns:
            WordPress security scan results
        """
        data = {
            "target": target,
            "api_token": api_token,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("wpscan", data)

    @mcp.tool()
    def reaver_attack(interface: str, bssid: str,
                      additional_args: str = "-vv") -> Dict[str, Any]:
        """
        Execute Reaver for WPS PIN attacks.

        Args:
            interface: Wireless interface in monitor mode
            bssid: Target AP BSSID
            additional_args: Additional Reaver arguments

        Returns:
            WPS attack results
        """
        data = {
            "interface": interface,
            "bssid": bssid,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("reaver", data)

    @mcp.tool()
    def bettercap_attack(interface: str, caplet: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Bettercap for network attacks and reconnaissance.

        Args:
            interface: Network interface to use
            caplet: Bettercap caplet script to run
            additional_args: Additional Bettercap arguments

        Returns:
            Network attack results
        """
        data = {
            "interface": interface,
            "caplet": caplet,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("bettercap", data)

    @mcp.tool()
    def binwalk_analysis(file_path: str, extract: bool = False,
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Binwalk for firmware analysis and extraction.

        Args:
            file_path: Path to firmware file to analyze
            extract: Whether to extract found filesystems
            additional_args: Additional Binwalk arguments

        Returns:
            Firmware analysis results
        """
        data = {
            "file_path": file_path,
            "extract": extract,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("binwalk", data)

    @mcp.tool()
    def theharvester_osint(domain: str, sources: str = "anubis,crtsh,dnsdumpster,hackertarget,rapiddns,sublist3r,urlscan",
                           limit: str = "500", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute theHarvester for OSINT and information gathering.

        Args:
            domain: Target domain for information gathering
            sources: Data sources (default: free sources without API keys)
                     API-free: anubis,crtsh,dnsdumpster,hackertarget,rapiddns,sublist3r,urlscan
                     Need API: bing,google,hunter,securityTrails,shodan
            limit: Maximum number of results per source
            additional_args: Additional theHarvester arguments

        Returns:
            OSINT gathering results
        """
        data = {
            "domain": domain,
            "sources": sources,
            "limit": limit,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("theharvester", data)

    @mcp.tool()
    def netdiscover_scan(interface: str = "", range_ip: str = "",
                         passive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Netdiscover for network host discovery.

        Args:
            interface: Network interface to use
            range_ip: IP range to scan (e.g., "192.168.1.0/24")
            passive: Use passive mode (ARP sniffing)
            additional_args: Additional Netdiscover arguments

        Returns:
            Network discovery results
        """
        data = {
            "interface": interface,
            "range": range_ip,
            "passive": passive,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("netdiscover", data)

    @mcp.tool()
    def comprehensive_network_scan(target: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Execute comprehensive network reconnaissance workflow.

        Args:
            target: Target network or host
            deep_scan: Whether to perform deep scanning

        Returns:
            Comprehensive network scan results
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "workflow": "comprehensive_network_scan",
            "phases": {}
        }

        try:
            # Phase 1: Fast port discovery with Masscan
            logger.info(f"Phase 1: Fast port discovery on {target}")
            masscan_result = masscan_fast_scan(target, "1-65535", "5000", "--open")
            results["phases"]["1_fast_port_scan"] = masscan_result

            # Phase 2: Detailed service enumeration with Nmap
            if masscan_result.get("success") and deep_scan:
                logger.info(f"Phase 2: Service enumeration on {target}")
                nmap_result = executor.execute_tool_with_data("nmap", {
                    "target": target, "scan_type": "-sV -sC", "additional_args": "-T4"
                })
                results["phases"]["2_service_enum"] = nmap_result

            # Phase 3: Network discovery
            logger.info(f"Phase 3: Network discovery")
            netdiscover_result = netdiscover_scan("", target, False)
            results["phases"]["3_network_discovery"] = netdiscover_result

            # Phase 4: DNS enumeration if target is domain
            if not target.replace(".", "").replace("/", "").isdigit():
                logger.info(f"Phase 4: DNS enumeration for {target}")
                dns_result = dnsrecon_scan(target, "-t std")
                results["phases"]["4_dns_enum"] = dns_result

            results["success"] = True
            results["summary"] = f"Comprehensive network scan completed for {target}"

        except Exception as e:
            logger.error(f"Error in comprehensive network scan: {str(e)}")
            results["success"] = False
            results["error"] = str(e)

        return results

    @mcp.tool()
    def advanced_web_security_assessment(target: str, wordpress_check: bool = True) -> Dict[str, Any]:
        """
        Execute advanced web application security assessment.

        Args:
            target: Target web application URL
            wordpress_check: Whether to perform WordPress-specific checks

        Returns:
            Advanced web security assessment results
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "workflow": "advanced_web_security_assessment",
            "phases": {}
        }

        try:
            # Phase 1: Technology detection
            logger.info(f"Phase 1: Technology detection for {target}")
            nuclei_tech = nuclei_technology_detection(target)
            results["phases"]["1_technology_detection"] = nuclei_tech

            # Phase 2: WAF detection
            logger.info(f"Phase 2: WAF detection for {target}")
            waf_result = executor.execute_command(f"wafw00f {target}")
            results["phases"]["2_waf_detection"] = waf_result

            # Phase 3: Directory enumeration with multiple tools
            logger.info(f"Phase 3: Directory enumeration for {target}")
            gobuster_result = executor.execute_tool_with_data("gobuster", {
                "url": target, "mode": "dir",
                "wordlist": "/usr/share/wordlists/dirb/big.txt"
            })
            results["phases"]["3_directory_enum"] = gobuster_result

            # Phase 4: Web vulnerability scanning
            logger.info(f"Phase 4: Web vulnerability scanning for {target}")
            nuclei_web = nuclei_web_scan(target, "comprehensive")
            results["phases"]["4_web_vuln_scan"] = nuclei_web

            # Phase 5: WordPress specific testing
            if wordpress_check:
                logger.info(f"Phase 5: WordPress security testing for {target}")
                wp_result = wpscan_scan(target)
                results["phases"]["5_wordpress_scan"] = wp_result

            # Phase 6: SQL injection testing
            logger.info(f"Phase 6: SQL injection testing for {target}")
            sql_result = executor.execute_tool_with_data("sqlmap", {
                "url": target, "additional_args": "--batch --level=2 --risk=2"
            })
            results["phases"]["6_sql_injection"] = sql_result

            results["success"] = True
            results["summary"] = f"Advanced web security assessment completed for {target}"

        except Exception as e:
            logger.error(f"Error in advanced web security assessment: {str(e)}")
            results["success"] = False
            results["error"] = str(e)

        return results

    # 工具链组合功能
    @mcp.tool()
    def web_app_security_assessment(target: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Comprehensive web application security assessment workflow.

        Args:
            target: Target web application URL
            deep_scan: Whether to perform deep scanning (takes longer)

        Returns:
            Complete security assessment results
        """
        import time
        from datetime import datetime

        results = {
            "target": target,
            "assessment_type": "web_application_security",
            "start_time": datetime.now().isoformat(),
            "deep_scan": deep_scan,
            "phases": {},
            "summary": {}
        }

        try:
            # Phase 1: Information Gathering
            logger.info(f"Phase 1: Information gathering for {target}")
            results["phases"]["1_info_gathering"] = {
                "description": "Basic information gathering and port scanning",
                "start_time": datetime.now().isoformat()
            }

            # Extract domain/IP from URL for nmap
            import re
            domain_match = re.search(r'https?://([^/]+)', target)
            if domain_match:
                scan_target = domain_match.group(1)
            else:
                scan_target = target

            # Port scan for web services
            nmap_result = executor.execute_tool_with_data("nmap", {
                "target": scan_target, "scan_type": "-sV",
                "ports": "80,443,8080,8443,3000,5000,8000,9000",
                "additional_args": "-T4 --open"
            })
            results["phases"]["1_info_gathering"]["nmap_scan"] = nmap_result

            # Phase 2: Technology Detection
            logger.info(f"Phase 2: Technology detection for {target}")
            results["phases"]["2_tech_detection"] = {
                "description": "Web technology and framework detection",
                "start_time": datetime.now().isoformat()
            }

            tech_result = nuclei_technology_detection(target)
            results["phases"]["2_tech_detection"]["nuclei_tech"] = tech_result

            # Phase 3: Directory Discovery
            logger.info(f"Phase 3: Directory discovery for {target}")
            results["phases"]["3_directory_discovery"] = {
                "description": "Web directory and file discovery",
                "start_time": datetime.now().isoformat()
            }

            gobuster_result = executor.execute_tool_with_data("gobuster", {
                "url": target, "mode": "dir",
                "wordlist": "/usr/share/wordlists/dirb/common.txt",
                "additional_args": "-t 20 -x php,html,txt,js"
            })
            results["phases"]["3_directory_discovery"]["gobuster_scan"] = gobuster_result

            # Phase 4: Vulnerability Scanning
            logger.info(f"Phase 4: Vulnerability scanning for {target}")
            results["phases"]["4_vulnerability_scan"] = {
                "description": "Automated vulnerability detection",
                "start_time": datetime.now().isoformat()
            }

            if deep_scan:
                vuln_result = nuclei_web_scan(target, "deep")
            else:
                vuln_result = nuclei_web_scan(target, "comprehensive")

            results["phases"]["4_vulnerability_scan"]["nuclei_vulns"] = vuln_result

            # Phase 5: Web Server Analysis
            logger.info(f"Phase 5: Web server analysis for {target}")
            results["phases"]["5_webserver_analysis"] = {
                "description": "Web server security analysis",
                "start_time": datetime.now().isoformat()
            }

            nikto_result = executor.execute_tool_with_data("nikto", {
                "target": target, "additional_args": "-C all"
            })
            results["phases"]["5_webserver_analysis"]["nikto_scan"] = nikto_result

            # Generate Summary
            results["end_time"] = datetime.now().isoformat()
            results["success"] = True
            results["summary"] = {
                "phases_completed": len(results["phases"]),
                "total_findings": "Analysis required",
                "recommendation": "Review all phases for security issues"
            }

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            results["end_time"] = datetime.now().isoformat()
            logger.error(f"Web app security assessment failed: {e}")

        return results

    @mcp.tool()
    def network_penetration_test(target: str, scope: str = "single") -> Dict[str, Any]:
        """
        Network penetration testing workflow.

        Args:
            target: Target IP address or network range
            scope: Scope of testing (single, subnet)

        Returns:
            Network penetration test results
        """
        from datetime import datetime

        results = {
            "target": target,
            "assessment_type": "network_penetration_test",
            "scope": scope,
            "start_time": datetime.now().isoformat(),
            "phases": {},
            "summary": {}
        }

        try:
            # Phase 1: Host Discovery
            logger.info(f"Phase 1: Host discovery for {target}")
            results["phases"]["1_host_discovery"] = {
                "description": "Network host discovery and ping sweep",
                "start_time": datetime.now().isoformat()
            }

            if scope == "subnet":
                ping_result = executor.execute_command(f"nmap -sn {target}")
            else:
                ping_result = executor.execute_command(f"ping -c 3 {target}")

            results["phases"]["1_host_discovery"]["ping_scan"] = ping_result

            # Phase 2: Port Discovery
            logger.info(f"Phase 2: Port discovery for {target}")
            results["phases"]["2_port_discovery"] = {
                "description": "Comprehensive port scanning",
                "start_time": datetime.now().isoformat()
            }

            port_result = executor.execute_tool_with_data("nmap", {
                "target": target, "scan_type": "-sS",
                "ports": "80,443,22",
                "additional_args": "-T5 --open --min-rate 5000 --max-retries 1 --host-timeout 3s"
            })
            results["phases"]["2_port_discovery"]["nmap_ports"] = port_result

            # Phase 3: Service Enumeration
            logger.info(f"Phase 3: Service enumeration for {target}")
            results["phases"]["3_service_enum"] = {
                "description": "Service version detection and enumeration",
                "start_time": datetime.now().isoformat()
            }

            service_result = executor.execute_tool_with_data("nmap", {
                "target": target, "scan_type": "-sV -sC", "additional_args": "-T4"
            })
            results["phases"]["3_service_enum"]["nmap_services"] = service_result

            # Phase 4: Vulnerability Assessment
            logger.info(f"Phase 4: Vulnerability assessment for {target}")
            results["phases"]["4_vuln_assessment"] = {
                "description": "Network vulnerability scanning",
                "start_time": datetime.now().isoformat()
            }

            network_vuln_result = nuclei_network_scan(target, "full")
            results["phases"]["4_vuln_assessment"]["nuclei_network"] = network_vuln_result

            # Phase 5: OS Detection
            logger.info(f"Phase 5: OS detection for {target}")
            results["phases"]["5_os_detection"] = {
                "description": "Operating system detection",
                "start_time": datetime.now().isoformat()
            }

            os_result = executor.execute_tool_with_data("nmap", {
                "target": target, "scan_type": "-O", "additional_args": "--osscan-guess"
            })
            results["phases"]["5_os_detection"]["nmap_os"] = os_result

            # Generate Summary
            results["end_time"] = datetime.now().isoformat()
            results["success"] = True
            results["summary"] = {
                "phases_completed": len(results["phases"]),
                "recommendation": "Analyze results for potential attack vectors"
            }

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            results["end_time"] = datetime.now().isoformat()
            logger.error(f"Network penetration test failed: {e}")

        return results

    # 新增现代工具
    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  mode: str = "FUZZ", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute FFUF web fuzzer (faster alternative to wfuzz).

        Args:
            url: Target URL with FUZZ keyword (e.g., 'http://example.com/FUZZ')
            wordlist: Path to wordlist file
            mode: Fuzzing mode (FUZZ for directories, HFUZZ for headers)
            additional_args: Additional FFUF arguments

        Returns:
            FFUF scan results
        """
        cmd = f"ffuf -u {url} -w {wordlist} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def whatweb_scan(target: str, aggression: str = "1", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WhatWeb for web technology identification.

        Args:
            target: Target URL or IP
            aggression: Aggression level (1-4, 1=passive, 4=aggressive)
            additional_args: Additional WhatWeb arguments

        Returns:
            Technology identification results
        """
        cmd = f"whatweb -a {aggression} {target} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def subfinder_scan(domain: str, sources: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for fast subdomain discovery.

        Args:
            domain: Target domain
            sources: Specific sources to use (comma-separated)
            additional_args: Additional Subfinder arguments

        Returns:
            Subdomain discovery results
        """
        cmd = f"subfinder -d {domain}"
        if sources:
            cmd += f" -sources {sources}"
        cmd += f" {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def httpx_probe(targets: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute HTTP probing for target URLs.

        Uses curl as fallback when ProjectDiscovery httpx is not available.

        Args:
            targets: Target URLs, IPs, or file containing targets
            additional_args: Additional arguments

        Returns:
            HTTP probing results
        """
        import shutil

        targets_clean = targets.replace("'", "\\'")

        # 检查是否有ProjectDiscovery的httpx (Go版本)
        httpx_path = shutil.which("httpx")
        if httpx_path:
            # 尝试检测是否是ProjectDiscovery版本
            test_result = executor.execute_command("httpx -version 2>&1 || true")
            if "projectdiscovery" in test_result.get("output", "").lower():
                args = additional_args.replace("-tech-detect", "-td")
                cmd = f"echo '{targets_clean}' | httpx -silent {args}"
                return executor.execute_command(cmd)

        # 使用curl作为备选方案进行HTTP探测
        targets_list = [t.strip() for t in targets_clean.split(",") if t.strip()]
        results = []
        for target in targets_list:
            if not target.startswith("http"):
                target = f"http://{target}"
            # 使用curl进行基本HTTP探测
            cmd = f"curl -sI -o /dev/null -w '%{{http_code}} %{{url_effective}} %{{content_type}}\\n' --connect-timeout 5 '{target}' 2>/dev/null || echo 'FAILED {target}'"
            result = executor.execute_command(cmd)
            results.append(result.get("output", ""))

        return {
            "success": True,
            "output": "\n".join(results),
            "note": "Using curl fallback (ProjectDiscovery httpx not installed)"
        }

    @mcp.tool()
    def masscan_fast_scan(target: str, ports: str = "80,443,22,21,25,53,110,143,993,995,8080,8443",
                          rate: str = "10000", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan for ultra-fast port scanning.

        Args:
            target: Target IP or network range
            ports: Ports to scan (comma-separated or range)
            rate: Scan rate (packets per second)
            additional_args: Additional Masscan arguments

        Returns:
            Fast port scan results
        """
        cmd = f"masscan {target} -p{ports} --rate={rate} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def hashcat_crack(hash_file: str, attack_mode: str = "0",
                      wordlist: str = "/usr/share/wordlists/rockyou.txt",
                      hash_type: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hashcat for GPU-accelerated password cracking.

        Args:
            hash_file: File containing hashes to crack
            attack_mode: Attack mode (0=dictionary, 1=combinator, 3=brute-force)
            wordlist: Wordlist file for dictionary attacks
            hash_type: Hash type (-m parameter)
            additional_args: Additional Hashcat arguments

        Returns:
            Password cracking results
        """
        cmd = f"hashcat -a {attack_mode}"
        if hash_type:
            cmd += f" -m {hash_type}"
        cmd += f" {hash_file} {wordlist} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def searchsploit_search(term: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Search exploit database using searchsploit.

        Args:
            term: Search term (software, version, CVE, etc.)
            additional_args: Additional searchsploit arguments

        Returns:
            Exploit search results
        """
        cmd = f"searchsploit {term} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def aircrack_attack(capture_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                        bssid: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Aircrack-ng for WiFi password cracking.

        Args:
            capture_file: Path to capture file (.cap or .pcap)
            wordlist: Wordlist for dictionary attack
            bssid: Target BSSID (optional)
            additional_args: Additional Aircrack-ng arguments

        Returns:
            WiFi cracking results
        """
        cmd = f"aircrack-ng {capture_file} -w {wordlist}"
        if bssid:
            cmd += f" -b {bssid}"
        cmd += f" {additional_args}"
        return executor.execute_command(cmd)
