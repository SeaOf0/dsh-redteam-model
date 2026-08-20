#!/usr/bin/env python3
"""
CTF专用工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_ctf_tools(mcp, executor, _CTF_MODE_ENABLED, _CTF_SESSIONS, _CURRENT_CTF_SESSION, _DETECTED_FLAGS, _CTF_CHALLENGES):
    """CTF专用工具注册"""

    # ==================== CTF专用工具 ====================

    @mcp.tool()
    def enable_ctf_mode() -> Dict[str, Any]:
        """
        启用CTF竞赛模式。

        启用后系统将：
        1. 自动检测和提取所有工具输出中的Flag
        2. 支持多种Flag格式（CTF{}, flag{}, 哈希等）
        3. 提供实时Flag统计和题目管理
        4. 优化攻击策略以适应CTF环境

        Returns:
            CTF模式启用结果
        """
        global _CTF_MODE_ENABLED

        _CTF_MODE_ENABLED = True

        return {
            "success": True,
            "ctf_mode": True,
            "message": "CTF模式已启用",
            "features": [
                "自动Flag检测: 支持 flag{}, FLAG{}, CTF{}, ctf{}, DASCTF{} 等格式",
                "哈希检测: MD5 (32字符), SHA1 (40字符), SHA256 (64字符)",
                "实时统计: 发现的Flag数量和来源",
                "快速攻击: 优化扫描参数以提高速度"
            ],
            "supported_flag_formats": [
                "flag{...}",
                "FLAG{...}",
                "CTF{...}",
                "ctf{...}",
                "DASCTF{...}",
                "[a-f0-9]{32} (MD5)",
                "[a-f0-9]{40} (SHA1)",
                "[a-f0-9]{64} (SHA256)"
            ]
        }

    @mcp.tool()
    def disable_ctf_mode() -> Dict[str, Any]:
        """
        禁用CTF竞赛模式，返回正常渗透测试模式。

        Returns:
            CTF模式禁用结果
        """
        global _CTF_MODE_ENABLED

        was_enabled = _CTF_MODE_ENABLED
        _CTF_MODE_ENABLED = False

        return {
            "success": True,
            "ctf_mode": False,
            "message": "CTF模式已禁用，已切换到正常渗透测试模式",
            "previous_state": "enabled" if was_enabled else "already_disabled"
        }

    @mcp.tool()
    def create_ctf_session(name: str, team_name: str = "") -> Dict[str, Any]:
        """
        创建CTF竞赛会话。

        Args:
            name: 竞赛名称
            team_name: 队伍名称（可选）

        Returns:
            CTF会话创建结果
        """
        import uuid
        from datetime import datetime, timedelta

        # TTL 懒清理: 删除超过1小时的非活跃CTF会话
        _SESSION_TTL_HOURS = 1
        _MAX_CTF_SESSIONS = 20
        now = datetime.now()
        expired = [
            sid for sid, s in list(_CTF_SESSIONS.items())
            if s.get("status") != "active" and
            (now - datetime.fromisoformat(s["created_at"])) > timedelta(hours=_SESSION_TTL_HOURS)
        ]
        for sid in expired:
            del _CTF_SESSIONS[sid]

        if len(_CTF_SESSIONS) >= _MAX_CTF_SESSIONS:
            return {"success": False, "error": f"CTF会话数已达上限 ({_MAX_CTF_SESSIONS})，请先关闭旧会话"}

        session_id = str(uuid.uuid4())[:8]
        session = {
            "session_id": session_id,
            "name": name,
            "team_name": team_name,
            "created_at": datetime.now().isoformat(),
            "challenges": [],
            "flags_found": [],
            "status": "active"
        }

        # 存储到全局CTF会话
        if not hasattr(create_ctf_session, '_sessions'):
            create_ctf_session._sessions = {}
        create_ctf_session._sessions[session_id] = session
        create_ctf_session._current_session = session_id

        return {
            "success": True,
            "session_id": session_id,
            "name": name,
            "team_name": team_name,
            "message": f"CTF会话 '{name}' 已创建"
        }

    @mcp.tool()
    def add_ctf_challenge(name: str, category: str, port: int, service: str = "http") -> Dict[str, Any]:
        """
        添加CTF题目到当前会话。

        Args:
            name: 题目名称
            category: 题目分类（web, pwn, crypto, misc, reverse）
            port: 题目端口
            service: 服务类型（http, ssh, ftp等）

        Returns:
            题目添加结果
        """
        import uuid
        from datetime import datetime

        challenge_id = str(uuid.uuid4())[:8]
        challenge = {
            "challenge_id": challenge_id,
            "name": name,
            "category": category,
            "port": port,
            "service": service,
            "added_at": datetime.now().isoformat(),
            "status": "pending",
            "flags_found": [],
            "attempts": 0
        }

        # 添加到当前会话
        if hasattr(create_ctf_session, '_current_session') and hasattr(create_ctf_session, '_sessions'):
            session_id = create_ctf_session._current_session
            if session_id in create_ctf_session._sessions:
                create_ctf_session._sessions[session_id]["challenges"].append(challenge)

        return {
            "success": True,
            "challenge_id": challenge_id,
            "name": name,
            "category": category,
            "port": port,
            "service": service,
            "message": f"题目 '{name}' ({category}) 已添加到端口 {port}"
        }

    @mcp.tool()
    def get_detected_flags() -> Dict[str, Any]:
        """
        获取所有检测到的Flag。

        Returns:
            包含所有Flag的详细信息，包括：
            - Flag内容
            - 格式类型
            - 发现来源
            - 置信度
            - 发现时间
            - 提交状态
        """
        return {
            "success": True,
            "ctf_mode_enabled": _CTF_MODE_ENABLED,
            "total_flags": len(_DETECTED_FLAGS),
            "flags": _DETECTED_FLAGS,
            "summary": {
                "by_format": _count_flags_by_format(),
                "by_source": _count_flags_by_source(),
                "submitted": sum(1 for f in _DETECTED_FLAGS if f.get("submitted", False)),
                "pending": sum(1 for f in _DETECTED_FLAGS if not f.get("submitted", False))
            }
        }

    def _count_flags_by_format() -> Dict[str, int]:
        """统计各格式Flag数量"""
        counts = {}
        for flag in _DETECTED_FLAGS:
            fmt = flag.get("format", "unknown")
            counts[fmt] = counts.get(fmt, 0) + 1
        return counts

    def _count_flags_by_source() -> Dict[str, int]:
        """统计各来源Flag数量"""
        counts = {}
        for flag in _DETECTED_FLAGS:
            source = flag.get("source", "unknown")
            counts[source] = counts.get(source, 0) + 1
        return counts

    @mcp.tool()
    def get_ctf_challenges_status() -> Dict[str, Any]:
        """
        获取所有CTF题目的状态。

        Returns:
            包含所有题目的状态信息：
            - 题目名称和分类
            - 解题状态
            - 发现的Flag数量
            - 开始和完成时间
        """
        challenges_list = []
        for challenge_id, challenge in _CTF_CHALLENGES.items():
            challenges_list.append({
                "challenge_id": challenge_id,
                "name": challenge.get("name", ""),
                "category": challenge.get("category", ""),
                "port": challenge.get("port", 0),
                "service": challenge.get("service", ""),
                "status": challenge.get("status", "pending"),
                "flags_found": challenge.get("flags_found", 0),
                "started_at": challenge.get("started_at"),
                "completed_at": challenge.get("completed_at")
            })

        # 统计摘要
        total = len(challenges_list)
        solved = sum(1 for c in challenges_list if c["status"] == "solved")
        in_progress = sum(1 for c in challenges_list if c["status"] == "in_progress")
        pending = sum(1 for c in challenges_list if c["status"] == "pending")

        return {
            "success": True,
            "total_challenges": total,
            "solved": solved,
            "in_progress": in_progress,
            "pending": pending,
            "challenges": challenges_list,
            "by_category": _count_challenges_by_category()
        }

    def _count_challenges_by_category() -> Dict[str, Dict[str, int]]:
        """按分类统计题目状态"""
        stats = {}
        for challenge in _CTF_CHALLENGES.values():
            cat = challenge.get("category", "unknown")
            if cat not in stats:
                stats[cat] = {"total": 0, "solved": 0, "in_progress": 0, "pending": 0}
            stats[cat]["total"] += 1
            status = challenge.get("status", "pending")
            if status in stats[cat]:
                stats[cat][status] += 1
        return stats

    @mcp.tool()
    def ctf_quick_scan(target: str, challenge_name: str = "", ports: str = "80,443,22,21,8080") -> Dict[str, Any]:
        """
        CTF快速扫描 - 针对CTF环境优化的快速漏洞发现。

        执行快速端口扫描、服务识别和基础漏洞检测，
        自动提取发现的Flag。

        Args:
            target: 目标IP地址或域名
            challenge_name: 题目名称（用于Flag关联）
            ports: 要扫描的端口列表

        Returns:
            快速扫描结果和发现的Flag
        """
        import re as _re

        results = {
            "target": target,
            "challenge_name": challenge_name,
            "scan_results": {},
            "flags_found": []
        }

        def _detect_flags(text):
            """检测输出中的flag"""
            flags = []
            for pat in [r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'DASCTF\{[^}]+\}']:
                flags.extend(_re.findall(pat, text, _re.IGNORECASE))
            return list(set(flags))

        # 1. 快速端口扫描
        nmap_result = executor.execute_tool_with_data("nmap", {
            "target": target,
            "scan_type": "-sV -sC --open -T4",
            "ports": ports
        })
        results["scan_results"]["nmap"] = nmap_result
        nmap_output = nmap_result.get("output", "") or nmap_result.get("stdout", "")
        results["flags_found"].extend(_detect_flags(nmap_output))

        # 2. Web服务快速扫描（如果有Web端口）
        web_ports = ["80", "443", "8080"]
        if any(p in ports for p in web_ports):
            gobuster_result = executor.execute_tool_with_data("gobuster", {
                "url": f"http://{target}",
                "wordlist": "/usr/share/wordlists/dirb/common.txt",
                "mode": "dir"
            })
            results["scan_results"]["gobuster"] = gobuster_result
            gob_output = gobuster_result.get("output", "") or gobuster_result.get("stdout", "")
            results["flags_found"].extend(_detect_flags(gob_output))

            # Nikto Web漏洞扫描
            nikto_result = executor.execute_tool_with_data("nikto", {
                "target": f"http://{target}"
            })
            results["scan_results"]["nikto"] = nikto_result
            nikto_output = nikto_result.get("output", "") or nikto_result.get("stdout", "")
            results["flags_found"].extend(_detect_flags(nikto_output))

        results["flags_found"] = list(set(results["flags_found"]))
        results["success"] = True
        results["message"] = f"CTF快速扫描完成，目标: {target}，发现Flag: {len(results['flags_found'])}个"
        return results

    @mcp.tool()
    def ctf_web_attack(target: str, challenge_name: str = "") -> Dict[str, Any]:
        """
        CTF Web攻击链 - 专门针对CTF Web题目的攻击。

        执行常见的Web漏洞攻击：
        1. SQL注入检测和利用
        2. XSS漏洞检测
        3. 文件上传漏洞
        4. 目录遍历
        5. 命令注入

        Args:
            target: 目标Web应用URL
            challenge_name: 题目名称

        Returns:
            Web攻击链执行结果
        """
        import re as _re

        results = {
            "target": target,
            "challenge_name": challenge_name,
            "attack_results": {},
            "flags_found": []
        }

        def _detect_flags(text):
            flags = []
            for pat in [r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'DASCTF\{[^}]+\}']:
                flags.extend(_re.findall(pat, text, _re.IGNORECASE))
            return list(set(flags))

        # 1. SQL注入攻击
        sqlmap_result = executor.execute_tool_with_data("sqlmap", {
            "url": target,
            "additional_args": "--crawl=2 --batch --level=3 --risk=3"
        })
        results["attack_results"]["sqlmap"] = sqlmap_result
        sql_output = sqlmap_result.get("output", "") or sqlmap_result.get("stdout", "")
        results["flags_found"].extend(_detect_flags(sql_output))

        # 2. 目录暴力破解
        gobuster_result = executor.execute_tool_with_data("gobuster", {
            "url": target,
            "wordlist": "/usr/share/wordlists/dirb/big.txt",
            "mode": "dir",
            "additional_args": "-x php,html,txt,js,zip,bak"
        })
        results["attack_results"]["gobuster"] = gobuster_result
        gob_output = gobuster_result.get("output", "") or gobuster_result.get("stdout", "")
        results["flags_found"].extend(_detect_flags(gob_output))

        # 3. Web漏洞扫描
        nuclei_result = executor.execute_tool_with_data("nuclei", {
            "target": target,
            "severity": "critical,high,medium"
        })
        results["attack_results"]["nuclei"] = nuclei_result
        nuc_output = nuclei_result.get("output", "") or nuclei_result.get("stdout", "")
        results["flags_found"].extend(_detect_flags(nuc_output))

        results["flags_found"] = list(set(results["flags_found"]))
        results["success"] = True
        results["message"] = f"CTF Web攻击链完成，目标: {target}，发现Flag: {len(results['flags_found'])}个"
        return results

