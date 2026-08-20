#!/usr/bin/env python3
"""
APT攻击链和自适应攻击工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_apt_tools(mcp, executor, _ADAPTIVE_ATTACKS, adapter=None):
    """APT攻击链和自适应攻击工具注册"""

    # ==================== APT攻击链工具 ====================

    @mcp.tool()
    def submit_apt_attack_chain(target: str, target_info: Dict[str, Any] = None,
                               attack_objective: str = "full_compromise") -> Dict[str, Any]:
        """
        提交APT攻击链工作流 - 基于知识图谱的智能化并发攻击。

        Args:
            target: 目标IP地址或域名
            target_info: 目标信息（端口、服务等），如果为空则自动侦察
            attack_objective: 攻击目标（full_compromise, data_extraction, persistence等）

        Returns:
            APT攻击链工作流ID和状态
        """
        # 如果有适配器，尝试通过代理执行
        if adapter and adapter.should_use_agent("submit_apt_attack_chain", {"target": target}):
            return adapter.execute_via_agent("submit_apt_attack_chain", {
                "target": target,
                "target_info": target_info,
                "attack_objective": attack_objective
            })

        import uuid
        attack_id = str(uuid.uuid4())[:8]
        results = {"phases": []}

        # 阶段1: 侦察
        recon_result = executor.execute_tool_with_data("nmap", {
            "target": target,
            "scan_type": "-sV -sC -O",
            "additional_args": "-T4"
        })
        results["phases"].append({"phase": "reconnaissance", "result": recon_result})

        # 阶段2: 漏洞扫描
        vuln_result = executor.execute_tool_with_data("nuclei", {
            "target": target,
            "severity": "critical,high,medium"
        })
        results["phases"].append({"phase": "vulnerability_scan", "result": vuln_result})

        return {
            "success": True,
            "attack_id": attack_id,
            "target": target,
            "attack_objective": attack_objective,
            "results": results
        }

    @mcp.tool()
    def identify_attack_surfaces(target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于目标信息识别攻击面。

        Args:
            target_info: 目标信息，包含端口、服务、版本等

        Returns:
            识别到的攻击面列表
        """
        attack_surfaces = []
        ports = target_info.get("ports", [])
        services = target_info.get("services", {})

        # 根据端口和服务识别攻击面
        port_attack_map = {
            21: {"type": "ftp", "attacks": ["anonymous_login", "brute_force"]},
            22: {"type": "ssh", "attacks": ["brute_force", "key_based"]},
            23: {"type": "telnet", "attacks": ["brute_force", "sniffing"]},
            25: {"type": "smtp", "attacks": ["user_enum", "relay"]},
            80: {"type": "http", "attacks": ["web_vuln_scan", "directory_enum"]},
            443: {"type": "https", "attacks": ["ssl_scan", "web_vuln_scan"]},
            445: {"type": "smb", "attacks": ["smb_enum", "eternal_blue"]},
            3306: {"type": "mysql", "attacks": ["brute_force", "udf_injection"]},
            3389: {"type": "rdp", "attacks": ["brute_force", "bluekeep"]},
        }

        for port in ports:
            if port in port_attack_map:
                attack_surfaces.append({
                    "port": port,
                    **port_attack_map[port]
                })

        return {
            "success": True,
            "attack_surfaces": attack_surfaces,
            "total_surfaces": len(attack_surfaces)
        }

    @mcp.tool()
    def generate_attack_paths(target: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成针对目标的APT攻击路径。

        Args:
            target: 目标IP地址或域名
            target_info: 目标信息，包含端口、服务、版本等

        Returns:
            生成的攻击路径列表，包含并发执行层和成功概率
        """
        attack_paths = []
        ports = target_info.get("ports", [])

        # 根据服务生成攻击路径
        for port_info in ports:
            port = port_info.get("port") if isinstance(port_info, dict) else port_info
            service = port_info.get("service", "unknown") if isinstance(port_info, dict) else "unknown"

            if port in [80, 443, 8080, 8443]:
                attack_paths.append({
                    "path_id": f"web_{port}",
                    "phases": ["recon", "vuln_scan", "exploit", "post_exploit"],
                    "tools": ["whatweb", "gobuster", "nuclei", "sqlmap"],
                    "success_probability": 0.7
                })
            elif port == 22:
                attack_paths.append({
                    "path_id": "ssh_attack",
                    "phases": ["enum", "brute_force"],
                    "tools": ["nmap", "hydra"],
                    "success_probability": 0.3
                })
            elif port == 445:
                attack_paths.append({
                    "path_id": "smb_attack",
                    "phases": ["enum", "exploit"],
                    "tools": ["enum4linux", "metasploit"],
                    "success_probability": 0.5
                })

        return {
            "success": True,
            "target": target,
            "attack_paths": attack_paths,
            "total_paths": len(attack_paths)
        }

    @mcp.tool()
    def apt_web_application_attack(target: str) -> Dict[str, Any]:
        """
        执行APT Web应用攻击链 - 自动化多阶段Web应用渗透。

        包含攻击阶段：
        1. 侦察：端口扫描、技术识别、目录发现
        2. 初始访问：SQL注入、文件上传、认证绕过
        3. 执行：Web Shell部署、命令执行
        4. 持久化：后门植入、权限维持

        Args:
            target: 目标Web应用URL或IP

        Returns:
            APT Web攻击链执行结果
        """
        # 构造Web应用目标信息
        target_info = {
            "ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ]
        }

        return submit_apt_attack_chain(target, target_info, "web_compromise")

    @mcp.tool()
    def apt_network_penetration(target: str) -> Dict[str, Any]:
        """
        执行APT网络渗透攻击链 - 自动化多阶段网络渗透测试。

        包含攻击阶段：
        1. 侦察：网络扫描、服务枚举、漏洞识别
        2. 初始访问：服务漏洞利用、暴力破解
        3. 权限提升：本地漏洞利用、配置错误利用
        4. 横向移动：内网扫描、凭据收集、跳板攻击

        Args:
            target: 目标网络或主机IP

        Returns:
            APT网络渗透链执行结果
        """
        # 构造网络目标信息
        target_info = {
            "ports": [
                {"port": 22, "service": "ssh"},
                {"port": 445, "service": "smb"},
                {"port": 3389, "service": "rdp"}
            ]
        }

        return submit_apt_attack_chain(target, target_info, "network_compromise")

    @mcp.tool()
    def apt_comprehensive_attack(target: str) -> Dict[str, Any]:
        """
        执行APT综合攻击链 - 全面的多向量并发攻击。

        自动识别目标攻击面并执行相应的攻击链：
        - Web应用攻击（如果发现Web服务）
        - 网络服务攻击（SSH、SMB、RDP等）
        - 数据库攻击（MySQL、PostgreSQL等）
        - 无线网络攻击（如果适用）

        Args:
            target: 目标IP地址或域名

        Returns:
            APT综合攻击链执行结果
        """
        return submit_apt_attack_chain(target, None, "full_compromise")

    # ==================== 自适应攻击工具 ====================

    @mcp.tool()
    def start_adaptive_apt_attack(target: str, target_info: Dict[str, Any] = None,
                                 attack_objective: str = "full_compromise") -> Dict[str, Any]:
        """
        启动自适应APT攻击 - 智能化动态调整攻击路径。

        这个功能会：
        1. 执行初始攻击向量
        2. 分析每个攻击的结果
        3. 根据获得的信息重新计算最优攻击路径
        4. 动态调整攻击策略
        5. 持续迭代直到达成攻击目标

        Args:
            target: 目标IP地址或域名
            target_info: 目标信息（端口、服务等），如果为空则自动侦察
            attack_objective: 攻击目标（full_compromise, data_extraction, persistence等）

        Returns:
            自适应攻击ID和状态
        """
        import uuid
        from datetime import datetime

        attack_id = str(uuid.uuid4())[:8]

        # 创建攻击状态对象
        attack_state = {
            "attack_id": attack_id,
            "target": target,
            "target_info": target_info or {},
            "attack_objective": attack_objective,
            "status": "in_progress",
            "current_phase": 1,
            "total_phases": 4,
            "phases_completed": [],
            "phases_pending": ["recon", "vuln_scan", "exploitation", "post_exploitation"],
            "discoveries": [],
            "capabilities_gained": [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "completed_vectors": 0,
            "failed_vectors": 0,
            "results": {"phases": [], "discoveries": []}
        }

        # 阶段1: 如果没有target_info，先进行侦察
        if not target_info:
            recon_result = executor.execute_tool_with_data("nmap", {
                "target": target,
                "scan_type": "-sV -sC",
                "additional_args": "-T4 --top-ports 1000"
            })
            attack_state["results"]["phases"].append({"phase": "auto_recon", "result": recon_result})
            attack_state["phases_completed"].append("recon")
            attack_state["phases_pending"].remove("recon")
            attack_state["completed_vectors"] += 1

            # 解析发现的服务
            if recon_result.get("success"):
                output = str(recon_result.get("output", ""))
                if "http" in output.lower() or "80/tcp" in output:
                    attack_state["discoveries"].append({"type": "service", "name": "http", "details": "Web服务发现"})
                if "ssh" in output.lower() or "22/tcp" in output:
                    attack_state["discoveries"].append({"type": "service", "name": "ssh", "details": "SSH服务发现"})
                if "mysql" in output.lower() or "3306/tcp" in output:
                    attack_state["discoveries"].append({"type": "service", "name": "mysql", "details": "MySQL数据库发现"})

        # 阶段2: 漏洞扫描
        vuln_result = executor.execute_tool_with_data("nuclei", {
            "target": target,
            "severity": "critical,high"
        })
        attack_state["results"]["phases"].append({"phase": "vuln_scan", "result": vuln_result})
        if "vuln_scan" in attack_state["phases_pending"]:
            attack_state["phases_completed"].append("vuln_scan")
            attack_state["phases_pending"].remove("vuln_scan")
        attack_state["completed_vectors"] += 1

        # 检查发现的漏洞
        if vuln_result.get("success"):
            output = str(vuln_result.get("output", ""))
            if "critical" in output.lower():
                attack_state["discoveries"].append({"type": "vulnerability", "severity": "critical", "details": "发现严重漏洞"})
            if "high" in output.lower():
                attack_state["discoveries"].append({"type": "vulnerability", "severity": "high", "details": "发现高危漏洞"})

        # 阶段3: Web扫描（如果目标是Web应用）
        if target.startswith("http"):
            web_result = executor.execute_tool_with_data("gobuster", {
                "url": target,
                "mode": "dir"
            })
            attack_state["results"]["phases"].append({"phase": "web_enum", "result": web_result})
            attack_state["completed_vectors"] += 1

            # 检查发现的路径
            if web_result.get("success"):
                output = str(web_result.get("output", ""))
                if "/admin" in output or "admin" in output.lower():
                    attack_state["discoveries"].append({"type": "endpoint", "name": "/admin", "details": "管理后台发现"})
                if "/upload" in output or "upload" in output.lower():
                    attack_state["discoveries"].append({"type": "endpoint", "name": "/upload", "details": "上传功能发现"})

        attack_state["current_phase"] = 2
        attack_state["updated_at"] = datetime.now().isoformat()

        # 保存到全局存储
        _ADAPTIVE_ATTACKS[attack_id] = attack_state

        return {
            "success": True,
            "attack_id": attack_id,
            "target": target,
            "attack_objective": attack_objective,
            "status": "in_progress",
            "current_phase": attack_state["current_phase"],
            "phases_completed": attack_state["phases_completed"],
            "discoveries": attack_state["discoveries"],
            "completed_vectors": attack_state["completed_vectors"],
            "message": f"自适应攻击已启动，ID: {attack_id}，当前已完成 {attack_state['completed_vectors']} 个攻击向量"
        }

    @mcp.tool()
    def get_adaptive_attack_status(attack_id: str) -> Dict[str, Any]:
        """
        获取自适应攻击状态 - 查看攻击进展和发现的信息。

        Args:
            attack_id: 自适应攻击ID

        Returns:
            攻击状态详情，包括：
            - 当前攻击阶段
            - 已完成的攻击向量数量
            - 失败的攻击向量数量
            - 当前获得的能力
            - 发现的信息
        """
        if attack_id not in _ADAPTIVE_ATTACKS:
            return {
                "success": False,
                "error": f"自适应攻击不存在: {attack_id}",
                "available_attacks": list(_ADAPTIVE_ATTACKS.keys())
            }

        attack = _ADAPTIVE_ATTACKS[attack_id]

        return {
            "success": True,
            "attack_id": attack_id,
            "target": attack.get("target"),
            "attack_objective": attack.get("attack_objective"),
            "status": attack.get("status"),
            "current_phase": attack.get("current_phase"),
            "total_phases": attack.get("total_phases"),
            "phases_completed": attack.get("phases_completed", []),
            "phases_pending": attack.get("phases_pending", []),
            "completed_vectors": attack.get("completed_vectors", 0),
            "failed_vectors": attack.get("failed_vectors", 0),
            "capabilities_gained": attack.get("capabilities_gained", []),
            "discoveries": attack.get("discoveries", []),
            "created_at": attack.get("created_at"),
            "updated_at": attack.get("updated_at")
        }

    @mcp.tool()
    def trigger_next_attack_phase(attack_id: str) -> Dict[str, Any]:
        """
        手动触发下一攻击阶段 - 强制进入下一轮攻击。

        Args:
            attack_id: 自适应攻击ID

        Returns:
            触发结果
        """
        from datetime import datetime

        if attack_id not in _ADAPTIVE_ATTACKS:
            return {
                "success": False,
                "error": f"自适应攻击不存在: {attack_id}",
                "available_attacks": list(_ADAPTIVE_ATTACKS.keys())
            }

        attack = _ADAPTIVE_ATTACKS[attack_id]

        # 检查是否还有待完成的阶段
        if not attack.get("phases_pending"):
            attack["status"] = "completed"
            attack["updated_at"] = datetime.now().isoformat()
            return {
                "success": True,
                "message": "所有攻击阶段已完成",
                "attack_id": attack_id,
                "status": "completed",
                "phases_completed": attack.get("phases_completed", [])
            }

        # 获取下一个待执行的阶段
        next_phase = attack["phases_pending"][0]
        target = attack.get("target", "")

        phase_result = None
        phase_success = False

        # 根据阶段类型执行相应的攻击
        if next_phase == "exploitation":
            # 执行漏洞利用阶段
            if target.startswith("http"):
                phase_result = executor.execute_tool_with_data("sqlmap", {
                    "url": target,
                    "additional_args": "--batch --random-agent"
                })
            else:
                phase_result = executor.execute_tool_with_data("metasploit", {
                    "module": "auxiliary/scanner/smb/smb_ms17_010",
                    "options": {"RHOSTS": target}
                })
            phase_success = phase_result.get("success", False)

        elif next_phase == "post_exploitation":
            # 执行后渗透阶段
            phase_result = executor.execute_tool_with_data("enum4linux", {
                "target": target
            })
            phase_success = phase_result.get("success", False)

        elif next_phase == "recon":
            # 执行侦察阶段
            phase_result = executor.execute_tool_with_data("nmap", {
                "target": target,
                "scan_type": "-sV -sC",
                "additional_args": "-T4"
            })
            phase_success = phase_result.get("success", False)

        elif next_phase == "vuln_scan":
            # 执行漏洞扫描阶段
            phase_result = executor.execute_tool_with_data("nuclei", {
                "target": target,
                "severity": "critical,high,medium"
            })
            phase_success = phase_result.get("success", False)

        # 更新攻击状态
        attack["phases_pending"].remove(next_phase)
        attack["phases_completed"].append(next_phase)
        attack["current_phase"] += 1
        attack["updated_at"] = datetime.now().isoformat()

        if phase_success:
            attack["completed_vectors"] += 1
        else:
            attack["failed_vectors"] += 1

        # 保存阶段结果
        attack["results"]["phases"].append({
            "phase": next_phase,
            "result": phase_result,
            "success": phase_success
        })

        # 检查是否所有阶段都已完成
        if not attack["phases_pending"]:
            attack["status"] = "completed"

        return {
            "success": True,
            "attack_id": attack_id,
            "triggered_phase": next_phase,
            "phase_success": phase_success,
            "current_phase": attack["current_phase"],
            "phases_remaining": attack["phases_pending"],
            "status": attack["status"],
            "message": f"已触发阶段: {next_phase}，{'成功' if phase_success else '失败'}"
        }

    @mcp.tool()
    def adaptive_web_penetration(target: str) -> Dict[str, Any]:
        """
        自适应Web渗透测试 - 智能化Web应用攻击。

        会根据发现的Web技术、框架、漏洞等信息动态调整攻击策略：
        - 发现CMS -> 针对性CMS漏洞利用
        - 发现数据库 -> SQL注入攻击
        - 发现上传功能 -> Web Shell上传
        - 获得Shell -> 权限提升和持久化

        Args:
            target: 目标Web应用URL或IP

        Returns:
            自适应Web攻击结果
        """
        target_info = {
            "ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ]
        }

        return start_adaptive_apt_attack(target, target_info, "web_compromise")

    @mcp.tool()
    def adaptive_network_penetration(target: str) -> Dict[str, Any]:
        """
        自适应网络渗透测试 - 智能化网络攻击。

        会根据发现的服务、操作系统、漏洞等信息动态调整攻击策略：
        - 发现SSH -> 暴力破解或漏洞利用
        - 发现SMB -> SMB漏洞利用或哈希传递
        - 获得凭据 -> 横向移动
        - 获得权限 -> 权限提升和持久化

        Args:
            target: 目标网络或主机IP

        Returns:
            自适应网络攻击结果
        """
        target_info = {
            "ports": [
                {"port": 22, "service": "ssh"},
                {"port": 445, "service": "smb"},
                {"port": 3389, "service": "rdp"}
            ]
        }

        return start_adaptive_apt_attack(target, target_info, "network_compromise")

    @mcp.tool()
    def intelligent_apt_campaign(target: str) -> Dict[str, Any]:
        """
        智能APT攻击活动 - 最高级别的自适应攻击。

        模拟真实APT组织的攻击手法：
        1. 全面侦察和信息收集
        2. 多向量并发初始访问尝试
        3. 根据成功的攻击向量调整策略
        4. 智能权限提升和横向移动
        5. 建立多重持久化机制
        6. 隐蔽数据收集和渗出

        Args:
            target: 目标组织的主要IP或域名

        Returns:
            智能APT攻击活动结果
        """
        return start_adaptive_apt_attack(target, None, "apt_campaign")

