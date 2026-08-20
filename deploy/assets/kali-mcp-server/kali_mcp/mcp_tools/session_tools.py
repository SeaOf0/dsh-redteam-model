#!/usr/bin/env python3
"""
PoC生成和攻击会话管理工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# VulnManager集成 (v5.0)
_vuln_manager_integration = None

def _get_vuln_mgr():
    global _vuln_manager_integration
    if _vuln_manager_integration is None:
        try:
            from kali_mcp.core.vuln_manager import VulnManager
            _vuln_manager_integration = VulnManager()
        except Exception:
            pass
    return _vuln_manager_integration


def register_session_tools(mcp, executor, _ATTACK_SESSIONS, _CURRENT_ATTACK_SESSION_ID):
    """PoC生成和攻击会话管理工具注册"""

    # ==================== PoC生成和攻击日志MCP工具 ====================

    @mcp.tool()
    def start_attack_session(target: str, mode: str = "apt", session_name: str = "") -> Dict[str, Any]:
        """
        开始新的攻击会话 - 启动自动日志记录和PoC生成。

        Args:
            target: 目标IP地址、域名或URL
            mode: 攻击模式 ("apt" 或 "ctf")
            session_name: 自定义会话名称（可选）

        Returns:
            会话启动结果，包含会话ID和配置信息
        """
        global _CURRENT_ATTACK_SESSION_ID
        import uuid
        from datetime import datetime, timedelta

        # TTL 懒清理: 删除超过1小时的非活跃会话
        _SESSION_TTL_HOURS = 1
        _MAX_SESSIONS = 50
        now = datetime.now()
        expired = [
            sid for sid, s in list(_ATTACK_SESSIONS.items())
            if s.get("status") != "active" and
            (now - datetime.fromisoformat(s["created_at"])) > timedelta(hours=_SESSION_TTL_HOURS)
        ]
        for sid in expired:
            del _ATTACK_SESSIONS[sid]

        if len(_ATTACK_SESSIONS) >= _MAX_SESSIONS:
            return {"success": False, "error": f"会话数已达上限 ({_MAX_SESSIONS})，请先关闭旧会话"}

        session_id = str(uuid.uuid4())[:8]
        session_name = session_name or f"{mode.upper()}_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        session = {
            "session_id": session_id,
            "session_name": session_name,
            "target": target,
            "mode": mode,
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "steps": [],
            "discovered_vulnerabilities": [],
            "discovered_flags": [],
            "total_tools_used": 0,
            "successful_attacks": 0,
            "failed_attacks": 0
        }

        _ATTACK_SESSIONS[session_id] = session
        _CURRENT_ATTACK_SESSION_ID = session_id

        return {
            "success": True,
            "session_id": session_id,
            "session_name": session_name,
            "target": target,
            "mode": mode,
            "status": "active",
            "message": f"攻击会话已启动: {session_name}"
        }

    @mcp.tool()
    def log_attack_step(tool_name: str, command: str, success: bool, output: str,
                       parameters: Dict[str, Any] = None, error: str = "", payload: str = "") -> Dict[str, Any]:
        """
        记录攻击步骤 - 实时记录每个工具的执行结果。

        Args:
            tool_name: 使用的工具名称
            command: 执行的命令
            success: 是否执行成功
            output: 工具输出结果
            parameters: 工具参数（可选）
            error: 错误信息（可选）
            payload: 使用的Payload（可选）

        Returns:
            步骤记录结果，包含发现的漏洞和Flag信息
        """
        import re
        from datetime import datetime

        if not _CURRENT_ATTACK_SESSION_ID or _CURRENT_ATTACK_SESSION_ID not in _ATTACK_SESSIONS:
            return {"success": False, "error": "没有活跃的攻击会话，请先调用 start_attack_session"}

        session = _ATTACK_SESSIONS[_CURRENT_ATTACK_SESSION_ID]

        # 创建步骤记录
        step = {
            "step_number": len(session["steps"]) + 1,
            "tool_name": tool_name,
            "command": command,
            "success": success,
            "output": output[:5000] if output else "",  # 限制输出长度
            "parameters": parameters or {},
            "error": error,
            "payload": payload,
            "timestamp": datetime.now().isoformat()
        }

        # 检测漏洞指标
        vuln_indicators = []
        output_lower = output.lower() if output else ""

        if ("sql syntax" in output_lower) or ("mysql" in output_lower and "error" in output_lower):
            vuln_indicators.append({"type": "SQL Injection", "confidence": "high"})
        if "<script>" in output_lower or "xss" in output_lower:
            vuln_indicators.append({"type": "XSS", "confidence": "medium"})
        if "command injection" in output_lower or "shell" in output_lower:
            vuln_indicators.append({"type": "Command Injection", "confidence": "medium"})
        if "unauthorized" in output_lower or "bypass" in output_lower:
            vuln_indicators.append({"type": "Auth Bypass", "confidence": "medium"})

        if vuln_indicators:
            step["vulnerabilities"] = vuln_indicators
            session["discovered_vulnerabilities"].extend(vuln_indicators)

            # v5.0: 自动提交到VulnManager
            vuln_mgr = _get_vuln_mgr()
            if vuln_mgr:
                try:
                    from kali_mcp.core.vuln_models import VulnRecord
                    vuln_type_map = {
                        "SQL Injection": "sqli",
                        "XSS": "xss",
                        "Command Injection": "rce",
                        "Auth Bypass": "auth_bypass",
                    }
                    for vi in vuln_indicators:
                        vr = VulnRecord(
                            title=f"{vi['type']} detected by {tool_name}",
                            vuln_type=vuln_type_map.get(vi["type"], vi["type"].lower().replace(" ", "_")),
                            target=session.get("target", ""),
                            severity="high" if vi["confidence"] == "high" else "medium",
                            confidence=vi["confidence"],
                            source="blackbox",
                            payload=payload,
                            evidence=output[:500] if output else "",
                            discovered_by=tool_name,
                        )
                        vuln_mgr.issue_vuln(vr)
                except Exception as e:
                    logger.debug(f"VulnManager集成: {e}")

        # 检测Flag
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}'
        ]

        detected_flags = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, output or "", re.IGNORECASE)
            detected_flags.extend(matches)

        if detected_flags:
            step["flags"] = detected_flags
            session["discovered_flags"].extend(detected_flags)

        # 更新会话统计
        session["steps"].append(step)
        session["total_tools_used"] += 1
        if success:
            session["successful_attacks"] += 1
        else:
            session["failed_attacks"] += 1

        return {
            "success": True,
            "step_number": step["step_number"],
            "tool_name": tool_name,
            "vulnerabilities_detected": vuln_indicators,
            "flags_detected": detected_flags,
            "session_stats": {
                "total_steps": len(session["steps"]),
                "successful": session["successful_attacks"],
                "failed": session["failed_attacks"]
            }
        }

    @mcp.tool()
    def end_attack_session() -> Dict[str, Any]:
        """
        结束当前攻击会话 - 完成日志记录并保存会话数据。

        Returns:
            会话结束结果，包含完整的攻击统计信息
        """
        global _CURRENT_ATTACK_SESSION_ID
        from datetime import datetime

        if not _CURRENT_ATTACK_SESSION_ID or _CURRENT_ATTACK_SESSION_ID not in _ATTACK_SESSIONS:
            return {"success": False, "error": "没有活跃的攻击会话"}

        session = _ATTACK_SESSIONS[_CURRENT_ATTACK_SESSION_ID]
        session["status"] = "completed"
        session["ended_at"] = datetime.now().isoformat()

        # 计算会话持续时间
        created = datetime.fromisoformat(session["created_at"])
        ended = datetime.fromisoformat(session["ended_at"])
        duration = (ended - created).total_seconds()

        result = {
            "success": True,
            "session_id": _CURRENT_ATTACK_SESSION_ID,
            "session_name": session["session_name"],
            "target": session["target"],
            "mode": session["mode"],
            "duration_seconds": duration,
            "statistics": {
                "total_steps": len(session["steps"]),
                "successful_attacks": session["successful_attacks"],
                "failed_attacks": session["failed_attacks"],
                "vulnerabilities_found": len(session["discovered_vulnerabilities"]),
                "flags_found": len(session["discovered_flags"])
            },
            "discovered_vulnerabilities": session["discovered_vulnerabilities"],
            "discovered_flags": session["discovered_flags"],
            "message": "攻击会话已结束"
        }

        _CURRENT_ATTACK_SESSION_ID = None
        return result

    @mcp.tool()
    def generate_poc_from_session(session_id: str) -> Dict[str, Any]:
        """
        从指定攻击会话生成PoC - 自动分析攻击链并生成多种格式的PoC。

        Args:
            session_id: 攻击会话ID

        Returns:
            生成的PoC结果，包含Python、Bash、CTF解题脚本和Markdown报告
        """
        if session_id not in _ATTACK_SESSIONS:
            return {"success": False, "error": f"会话不存在: {session_id}"}

        session = _ATTACK_SESSIONS[session_id]

        # 生成Python PoC
        python_poc = f'''#!/usr/bin/env python3
"""
PoC for {session["session_name"]}
Target: {session["target"]}
Generated from attack session
"""
import requests

TARGET = "{session["target"]}"

'''
        for step in session["steps"]:
            if step.get("success") and step.get("payload"):
                python_poc += f'''
# Step {step["step_number"]}: {step["tool_name"]}
# Command: {step["command"]}
# Payload: {step["payload"]}
'''

        # 生成Bash PoC
        bash_poc = f'''#!/bin/bash
# PoC for {session["session_name"]}
# Target: {session["target"]}

TARGET="{session["target"]}"

'''
        for step in session["steps"]:
            if step.get("success"):
                bash_poc += f'''
# Step {step["step_number"]}: {step["tool_name"]}
{step["command"]}
'''

        # 生成Markdown报告
        markdown_report = f'''# 攻击报告: {session["session_name"]}

## 目标信息
- **目标**: {session["target"]}
- **模式**: {session["mode"]}
- **开始时间**: {session["created_at"]}
- **结束时间**: {session.get("ended_at", "进行中")}

## 攻击统计
- 总步骤数: {len(session["steps"])}
- 成功攻击: {session["successful_attacks"]}
- 失败攻击: {session["failed_attacks"]}

## 发现的漏洞
'''
        for vuln in session["discovered_vulnerabilities"]:
            markdown_report += f'- **{vuln["type"]}** (置信度: {vuln["confidence"]})\n'

        markdown_report += '''
## 发现的Flag
'''
        for flag in session["discovered_flags"]:
            markdown_report += f'- `{flag}`\n'

        markdown_report += '''
## 攻击步骤详情
'''
        for step in session["steps"]:
            status = "" if step["success"] else ""
            markdown_report += f'''
### 步骤 {step["step_number"]}: {step["tool_name"]} {status}
- **命令**: `{step["command"]}`
- **时间**: {step["timestamp"]}
'''
            if step.get("payload"):
                markdown_report += f'- **Payload**: `{step["payload"]}`\n'

        return {
            "success": True,
            "session_id": session_id,
            "poc": {
                "python": python_poc,
                "bash": bash_poc,
                "markdown": markdown_report
            },
            "summary": {
                "total_steps": len(session["steps"]),
                "successful_steps": session["successful_attacks"],
                "vulnerabilities": len(session["discovered_vulnerabilities"]),
                "flags": len(session["discovered_flags"])
            }
        }

    @mcp.tool()
    def generate_poc_from_current_session() -> Dict[str, Any]:
        """
        从当前活跃会话生成PoC - 无需指定会话ID，直接从当前会话生成。

        Returns:
            生成的PoC结果，自动保存到文件
        """
        if not _CURRENT_ATTACK_SESSION_ID:
            return {"success": False, "error": "没有活跃的攻击会话"}

        return generate_poc_from_session(_CURRENT_ATTACK_SESSION_ID)

    @mcp.tool()
    def get_attack_session_details(session_id: str) -> Dict[str, Any]:
        """
        获取攻击会话详情 - 查看指定会话的完整攻击历史。

        Args:
            session_id: 攻击会话ID

        Returns:
            详细的会话信息，包含所有攻击步骤和结果
        """
        if session_id not in _ATTACK_SESSIONS:
            return {"success": False, "error": f"会话不存在: {session_id}"}

        session = _ATTACK_SESSIONS[session_id]

        return {
            "success": True,
            "session": {
                "session_id": session["session_id"],
                "session_name": session["session_name"],
                "target": session["target"],
                "mode": session["mode"],
                "status": session["status"],
                "created_at": session["created_at"],
                "ended_at": session.get("ended_at"),
                "statistics": {
                    "total_steps": len(session["steps"]),
                    "successful_attacks": session["successful_attacks"],
                    "failed_attacks": session["failed_attacks"]
                },
                "discovered_vulnerabilities": session["discovered_vulnerabilities"],
                "discovered_flags": session["discovered_flags"],
                "steps": session["steps"]
            }
        }

    @mcp.tool()
    def list_attack_sessions() -> Dict[str, Any]:
        """
        获取所有攻击会话列表 - 查看历史和当前的所有攻击会话。

        Returns:
            所有攻击会话的摘要信息
        """
        sessions_summary = []

        for session_id, session in _ATTACK_SESSIONS.items():
            sessions_summary.append({
                "session_id": session_id,
                "session_name": session["session_name"],
                "target": session["target"],
                "mode": session["mode"],
                "status": session["status"],
                "created_at": session["created_at"],
                "total_steps": len(session["steps"]),
                "vulnerabilities_found": len(session["discovered_vulnerabilities"]),
                "flags_found": len(session["discovered_flags"]),
                "is_current": session_id == _CURRENT_ATTACK_SESSION_ID
            })

        return {
            "success": True,
            "total_sessions": len(sessions_summary),
            "current_session_id": _CURRENT_ATTACK_SESSION_ID,
            "sessions": sessions_summary
        }

    @mcp.tool()
    def list_poc_templates() -> Dict[str, Any]:
        """
        获取可用的PoC模板 - 查看系统支持的所有PoC生成模板。

        Returns:
            可用的PoC模板列表和描述信息
        """
        templates = [
            {
                "name": "python_exploit",
                "description": "Python漏洞利用脚本模板",
                "language": "python",
                "features": ["HTTP请求", "Payload注入", "响应解析", "自动化利用"]
            },
            {
                "name": "bash_script",
                "description": "Bash命令行PoC脚本",
                "language": "bash",
                "features": ["命令行工具调用", "curl请求", "管道处理"]
            },
            {
                "name": "ctf_solver",
                "description": "CTF自动化解题脚本",
                "language": "python",
                "features": ["Flag提取", "自动化解题", "多步骤攻击"]
            },
            {
                "name": "markdown_report",
                "description": "Markdown格式渗透测试报告",
                "language": "markdown",
                "features": ["漏洞描述", "攻击步骤", "修复建议", "风险评估"]
            },
            {
                "name": "nuclei_template",
                "description": "Nuclei YAML漏洞扫描模板",
                "language": "yaml",
                "features": ["自动化扫描", "漏洞检测", "批量测试"]
            },
            {
                "name": "burp_extension",
                "description": "Burp Suite扩展模板",
                "language": "python",
                "features": ["请求拦截", "响应修改", "自动化测试"]
            }
        ]

        return {
            "success": True,
            "total_templates": len(templates),
            "templates": templates
        }

    @mcp.tool()
    def auto_apt_attack_with_poc(target: str, session_name: str = "") -> Dict[str, Any]:
        """
        自动APT攻击并生成PoC - 完整的APT攻击链，自动记录和生成PoC。

        这个工具将：
        1. 启动APT模式攻击会话
        2. 执行全面的APT攻击链
        3. 自动记录所有攻击步骤
        4. 在攻击完成后生成PoC

        Args:
            target: 目标IP地址或域名
            session_name: 自定义会话名称（可选）

        Returns:
            完整的APT攻击结果和生成的PoC信息
        """
        # 1. 启动攻击会话
        session_result = start_attack_session(target, "apt", session_name or f"APT_Attack_{target}")

        if not session_result.get("success"):
            return {"error": "Failed to start attack session", "details": session_result}

        session_id = session_result.get("session_id")

        # 2. 执行APT攻击链
        try:
            # 阶段1：侦察
            nmap_result = executor.execute_tool_with_data("nmap", {
                "target": target, "scan_type": "-sS", "ports": "80,443,22",
                "additional_args": "-T5 --open --min-rate 5000 --max-retries 1"
            })
            log_attack_step("nmap", f"nmap -sS -p80,443,22 -T5 {target}",
                          nmap_result.get("success", False), str(nmap_result))

            # 阶段2：Web应用攻击（如果发现Web服务）
            if "80" in str(nmap_result) or "443" in str(nmap_result):
                target_url = f"http://{target}"

                # 目录扫描
                gobuster_result = executor.execute_tool_with_data("gobuster", {
                    "url": target_url, "mode": "dir",
                    "wordlist": "/usr/share/wordlists/dirb/common.txt"
                })
                log_attack_step("gobuster", f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/common.txt",
                              gobuster_result.get("success", False), str(gobuster_result))

                # SQL注入测试
                sqlmap_result = executor.execute_tool_with_data("sqlmap", {
                    "url": target_url, "additional_args": "--batch --level=2"
                })
                log_attack_step("sqlmap", f"sqlmap -u {target_url} --batch --level=2",
                              sqlmap_result.get("success", False), str(sqlmap_result))

                # Web漏洞扫描
                nuclei_result = executor.execute_command(
                    f"nuclei -u {target_url} -t http/ -s critical,high,medium -silent -rl 100 -timeout 10"
                )
                log_attack_step("nuclei", f"nuclei -u {target_url} -t http/",
                              nuclei_result.get("success", False), str(nuclei_result))

            # 3. 结束攻击会话
            end_result = end_attack_session()

            # 4. 生成PoC
            poc_result = generate_poc_from_session(session_id)

            return {
                "success": True,
                "session_id": session_id,
                "target": target,
                "attack_completed": True,
                "session_summary": end_result,
                "poc_generated": poc_result,
                "message": f"APT攻击链已完成，PoC已生成并保存"
            }

        except Exception as e:
            # 即使攻击过程中出错，也尝试生成PoC
            try:
                end_attack_session()
                poc_result = generate_poc_from_session(session_id)
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "partial_poc": poc_result,
                    "message": "攻击过程中出现错误，但已生成部分PoC"
                }
            except:
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "message": "攻击失败，无法生成PoC"
                }

    @mcp.tool()
    def auto_ctf_solve_with_poc(target: str, challenge_name: str = "", challenge_category: str = "web") -> Dict[str, Any]:
        """
        自动CTF解题并生成PoC - 完整的CTF解题流程，自动记录和生成解题脚本。

        这个工具将：
        1. 启动CTF模式攻击会话
        2. 执行针对性的CTF解题攻击
        3. 自动提取Flag
        4. 生成CTF解题脚本

        Args:
            target: CTF题目地址或IP
            challenge_name: 题目名称（可选）
            challenge_category: 题目分类 (web, pwn, crypto, misc)

        Returns:
            CTF解题结果和生成的解题脚本
        """
        # 1. 启动CTF会话
        session_name = challenge_name or f"CTF_{challenge_category}_{target}"
        session_result = start_attack_session(target, "ctf", session_name)

        if not session_result.get("success"):
            return {"error": "Failed to start CTF session", "details": session_result}

        session_id = session_result.get("session_id")

        try:
            # 2. 执行CTF解题策略
            if challenge_category == "web":
                # Web题目解题流程

                # 快速端口扫描
                nmap_result = executor.execute_tool_with_data("nmap", {
                    "target": target, "scan_type": "-sV",
                    "ports": "80,443,8080,8000,3000", "additional_args": "-T4"
                })
                log_attack_step("nmap", f"nmap -sV -p80,443,8080,8000,3000 {target}",
                              nmap_result.get("success", False), str(nmap_result))

                target_url = f"http://{target}" if not target.startswith("http") else target

                # 目录暴力破解
                gobuster_result = executor.execute_tool_with_data("gobuster", {
                    "url": target_url, "mode": "dir",
                    "wordlist": "/usr/share/wordlists/dirb/big.txt",
                    "additional_args": "-x php,txt,html,js"
                })
                log_attack_step("gobuster", f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/big.txt -x php,txt,html,js",
                              gobuster_result.get("success", False), str(gobuster_result))

                # SQL注入快速测试
                sqlmap_result = executor.execute_tool_with_data("sqlmap", {
                    "url": target_url, "additional_args": "--batch --level=3 --risk=3"
                })
                log_attack_step("sqlmap", f"sqlmap -u {target_url} --batch --level=3 --risk=3",
                              sqlmap_result.get("success", False), str(sqlmap_result))

                # Web漏洞扫描
                nuclei_result = executor.execute_command(
                    f"nuclei -u {target_url} -t http/ -s critical,high,medium -silent -rl 100 -timeout 10"
                )
                log_attack_step("nuclei", f"nuclei -u {target_url} -t http/",
                              nuclei_result.get("success", False), str(nuclei_result))

            elif challenge_category == "pwn":
                # Pwn题目解题流程
                nmap_result = executor.execute_tool_with_data("nmap", {
                    "target": target, "scan_type": "-sV -sC", "additional_args": "-T4"
                })
                log_attack_step("nmap", f"nmap -sV -sC {target}",
                              nmap_result.get("success", False), str(nmap_result))

            else:
                # 通用解题流程
                nmap_result = executor.execute_tool_with_data("nmap", {
                    "target": target, "scan_type": "-sV", "additional_args": "-T4"
                })
                log_attack_step("nmap", f"nmap -sV {target}",
                              nmap_result.get("success", False), str(nmap_result))

            # 3. 结束CTF会话
            end_result = end_attack_session()

            # 4. 生成CTF解题脚本
            poc_result = generate_poc_from_session(session_id)

            return {
                "success": True,
                "session_id": session_id,
                "target": target,
                "challenge_category": challenge_category,
                "flags_found": end_result.get("flags_found", 0),
                "ctf_completed": True,
                "session_summary": end_result,
                "solver_script": poc_result,
                "message": f"CTF {challenge_category} 题目解题完成，解题脚本已生成"
            }

        except Exception as e:
            # 即使解题过程中出错，也尝试生成脚本
            try:
                end_attack_session()
                poc_result = generate_poc_from_session(session_id)
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "partial_script": poc_result,
                    "message": "CTF解题过程中出现错误，但已生成部分解题脚本"
                }
            except:
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "message": "CTF解题失败，无法生成解题脚本"
                }

    @mcp.tool()
    def intelligent_attack_with_poc(target: str, mode: str = "apt", objectives: List[str] = None) -> Dict[str, Any]:
        """
        智能化攻击并自动生成PoC - 最高级别的自动化渗透测试。

        结合了：
        - 参数优化
        - 结果关联分析
        - 自适应攻击策略
        - 智能Payload生成
        - 自动PoC生成

        Args:
            target: 目标IP地址、域名或URL
            mode: 攻击模式 ("apt" 或 "ctf")
            objectives: 攻击目标列表（可选）

        Returns:
            完整的智能化攻击结果和多格式PoC
        """
        # 1. 启动智能攻击会话
        session_result = start_attack_session(target, mode, f"Intelligent_{mode.upper()}_{target}")

        if not session_result.get("success"):
            return {"error": "Failed to start intelligent attack session", "details": session_result}

        session_id = session_result.get("session_id")

        try:
            # 2. 执行智能化攻击流程
            results = {}

            # 智能参数优化扫描
            if mode == "apt":
                # APT模式：全面渗透测试 - 端口扫描 + Web漏洞 + nuclei
                nmap_r = executor.execute_tool_with_data("nmap", {
                    "target": target, "scan_type": "-sV -sC",
                    "ports": "80,443,22,21,25,53,8080", "additional_args": "-T4"
                })
                results["vulnerability_assessment"] = nmap_r
                target_url = f"http://{target}" if not target.startswith("http") else target
                nuclei_r = executor.execute_command(
                    f"nuclei -u {target_url} -t http/ -s critical,high,medium -silent -rl 100 -timeout 10"
                )
                results["penetration_test"] = nuclei_r
            else:
                # CTF模式：快速解题 - 快速扫描 + 目录枚举 + SQL注入
                nmap_r = executor.execute_tool_with_data("nmap", {
                    "target": target, "scan_type": "-sV",
                    "ports": "80,443,8080,8000,3000", "additional_args": "-T4"
                })
                target_url = f"http://{target}" if not target.startswith("http") else target
                gobuster_r = executor.execute_tool_with_data("gobuster", {
                    "url": target_url, "mode": "dir",
                    "wordlist": "/usr/share/wordlists/dirb/common.txt",
                    "additional_args": "-x php,txt,html"
                })
                sqlmap_r = executor.execute_tool_with_data("sqlmap", {
                    "url": target_url, "additional_args": "--batch --level=3 --risk=3"
                })
                results["ctf_solver"] = {
                    "nmap": nmap_r, "gobuster": gobuster_r, "sqlmap": sqlmap_r
                }

            # 记录智能攻击结果
            for phase, result in results.items():
                log_attack_step("intelligent_system", f"{phase} on {target}",
                              result.get("success", False), str(result))

            # 3. 结束智能攻击会话
            end_result = end_attack_session()

            # 4. 生成高级PoC
            poc_result = generate_poc_from_session(session_id)

            return {
                "success": True,
                "session_id": session_id,
                "target": target,
                "mode": mode,
                "intelligent_results": results,
                "session_summary": end_result,
                "advanced_poc": poc_result,
                "total_vulnerabilities": end_result.get("vulnerabilities_found", 0),
                "flags_found": end_result.get("flags_found", 0),
                "compromise_level": end_result.get("compromise_level", "none"),
                "message": f"智能化{mode.upper()}攻击完成，高级PoC已生成"
            }

        except Exception as e:
            try:
                end_attack_session()
                poc_result = generate_poc_from_session(session_id)
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "partial_results": poc_result,
                    "message": "智能攻击过程中出现错误，但已生成部分结果"
                }
            except:
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "message": "智能攻击失败"
                }

