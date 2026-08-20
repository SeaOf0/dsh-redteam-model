#!/usr/bin/env python3
"""
新增工具、并发任务和无线工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_misc_tools(mcp, executor, _TASKS, _WORKFLOWS):
    """新增工具、并发任务和无线工具注册"""

    # ====================  新增工具函数 ====================
    
    # 核心扫描工具
    @mcp.tool()
    def joomscan_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute joomscan for Joomla security testing.
        
        Args:
            target: Target Joomla URL
            additional_args: Additional joomscan arguments
            
        Returns:
            Joomla scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("joomscan", data)

    # 密码攻击工具
    @mcp.tool()
    def patator_attack(module: str = "ssh_login", target: str = "", wordlist: str = "",
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute patator for multi-protocol brute-forcing.
        
        Args:
            module: Patator module to use
            target: Target host
            wordlist: Path to wordlist file
            additional_args: Additional patator arguments
            
        Returns:
            Brute force attack results
        """
        data = {
            "module": module,
            "target": target,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("patator", data)

    @mcp.tool()
    def crowbar_attack(service: str = "ssh", target: str = "", username: str = "",
                      wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute crowbar for brute force attacks.
        
        Args:
            service: Service to attack
            target: Target host
            username: Username to test
            wordlist: Path to wordlist file
            additional_args: Additional crowbar arguments
            
        Returns:
            Brute force attack results
        """
        data = {
            "service": service,
            "target": target,
            "username": username,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("crowbar", data)

    @mcp.tool()
    def brutespray_attack(nmap_file: str, username_file: str = "", password_file: str = "",
                         threads: str = "5", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute brutespray for brute force attacks from nmap output.
        
        Args:
            nmap_file: Path to nmap XML output file
            username_file: Path to username file
            password_file: Path to password file
            threads: Number of threads
            additional_args: Additional brutespray arguments
            
        Returns:
            Brute force attack results
        """
        data = {
            "nmap_file": nmap_file,
            "username_file": username_file,
            "password_file": password_file,
            "threads": threads,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("brutespray", data)

    # 网络发现工具
    @mcp.tool()
    def arp_scan(interface: str = "", network: str = "--local", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute arp-scan for network discovery.
        
        Args:
            interface: Network interface to use
            network: Network to scan
            additional_args: Additional arp-scan arguments
            
        Returns:
            ARP scan results
        """
        data = {
            "interface": interface,
            "network": network,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("arp-scan", data)

    @mcp.tool()
    def fping_scan(targets: str, count: str = "3", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute fping for fast ping sweeps.
        
        Args:
            targets: Target hosts or networks
            count: Number of ping packets
            additional_args: Additional fping arguments
            
        Returns:
            Ping sweep results
        """
        data = {
            "targets": targets,
            "count": count,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("fping", data)

    # 无线安全工具
    @mcp.tool()
    def bully_attack(interface: str, bssid: str, additional_args: str = "-v") -> Dict[str, Any]:
        """
        Execute bully for WPS attacks.
        
        Args:
            interface: Wireless interface
            bssid: Target AP BSSID
            additional_args: Additional bully arguments
            
        Returns:
            WPS attack results
        """
        data = {
            "interface": interface,
            "bssid": bssid,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("bully", data)

    @mcp.tool()
    def pixiewps_attack(pke: str, pkr: str, e_hash1: str, e_hash2: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute pixiewps for WPS PIN recovery.
        
        Args:
            pke: Public Key E
            pkr: Public Key R
            e_hash1: E-Hash1
            e_hash2: E-Hash2
            additional_args: Additional pixiewps arguments
            
        Returns:
            WPS PIN recovery results
        """
        data = {
            "pke": pke,
            "pkr": pkr,
            "e_hash1": e_hash1,
            "e_hash2": e_hash2,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("pixiewps", data)

    @mcp.tool()
    def recon_ng_run(workspace: str = "default", module: str = "", options: Dict[str, str] = None,
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute recon-ng for reconnaissance.

        Args:
            workspace: Recon-ng workspace
            module: Module to execute
            options: Module options
            additional_args: Additional recon-ng arguments

        Returns:
            Reconnaissance results
        """
        if options is None:
            options = {}
        data = {
            "workspace": workspace,
            "module": module,
            "options": options,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("recon-ng", data)

    @mcp.tool()
    def sherlock_search(username: str, sites: str = "", output_format: str = "json",
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute sherlock for username enumeration across social networks.
        
        Args:
            username: Username to search for
            sites: Specific sites to search
            output_format: Output format
            additional_args: Additional sherlock arguments
            
        Returns:
            Username enumeration results
        """
        data = {
            "username": username,
            "sites": sites,
            "output_format": output_format,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("sherlock", data)

    @mcp.tool()
    def yersinia_attack(protocol: str = "stp", interface: str = "", attack_type: str = "",
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute yersinia for network protocol attacks.

        Args:
            protocol: Protocol to attack (stp, cdp, dtp, etc.)
            interface: Network interface
            attack_type: Type of attack
            additional_args: Additional yersinia arguments

        Returns:
            Network protocol attack results
        """
        cmd = f"yersinia -G -d {protocol}"
        if interface:
            cmd += f" -i {interface}"
        if attack_type:
            cmd += f" -a {attack_type}"
        cmd += f" {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def submit_concurrent_task(tool_name: str, parameters: Dict[str, Any],
                             priority: int = 2, timeout: Optional[int] = None,
                             tags: Optional[List[str]] = None,
                             metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        提交并发任务。
        
        Args:
            tool_name: 工具名称
            parameters: 工具参数
            priority: 任务优先级 (1=低, 2=普通, 3=高, 4=紧急)
            timeout: 超时时间(秒)
            tags: 任务标签
            metadata: 元数据
            
        Returns:
            任务提交结果
        """
        # 本地执行模式：直接执行工具
        import uuid
        task_id = str(uuid.uuid4())[:8]
        try:
            result = executor.execute_tool_with_data(tool_name, parameters)
            return {
                "success": True,
                "task_id": task_id,
                "status": "completed",
                "result": result,
                "tool_name": tool_name
            }
        except Exception as e:
            return {
                "success": False,
                "task_id": task_id,
                "status": "failed",
                "error": str(e),
                "tool_name": tool_name
            }

    @mcp.tool()
    def submit_workflow(workflow_name: str, target: str,
                       workflow_type: str = "comprehensive_web_scan") -> Dict[str, Any]:
        """
        提交预定义工作流。

        Args:
            workflow_name: 工作流名称
            target: 目标地址或域名
            workflow_type: 工作流类型
                - "comprehensive_web_scan": 全面Web扫描
                - "network_penetration_test": 网络渗透测试
                - "fast_reconnaissance": 快速侦察

        Returns:
            工作流提交结果
        """
        import uuid
        workflow_id = str(uuid.uuid4())[:8]
        results = []

        # 根据工作流类型执行不同的扫描
        if workflow_type == "comprehensive_web_scan":
            # Web综合扫描工作流
            tools_sequence = [
                ("whatweb", {"target": target}),
                ("gobuster", {"url": target, "mode": "dir"}),
                ("nikto", {"target": target}),
            ]
        elif workflow_type == "network_penetration_test":
            # 网络渗透测试工作流
            tools_sequence = [
                ("nmap", {"target": target, "scan_type": "-sV -sC"}),
            ]
        elif workflow_type == "fast_reconnaissance":
            # 快速侦察工作流
            tools_sequence = [
                ("nmap", {"target": target, "scan_type": "-T4 -F"}),
            ]
        else:
            tools_sequence = []

        for tool_name, params in tools_sequence:
            try:
                result = executor.execute_tool_with_data(tool_name, params)
                results.append({"tool": tool_name, "result": result})
            except Exception as e:
                results.append({"tool": tool_name, "error": str(e)})

        return {
            "success": True,
            "workflow_id": workflow_id,
            "workflow_name": workflow_name,
            "workflow_type": workflow_type,
            "target": target,
            "results": results
        }

    @mcp.tool()
    def get_task_status(task_id: str) -> Dict[str, Any]:
        """
        获取任务状态。

        Args:
            task_id: 任务ID

        Returns:
            任务状态信息
        """
        if task_id not in _TASKS:
            return {"success": False, "error": f"任务不存在: {task_id}"}

        task = _TASKS[task_id]
        return {
            "success": True,
            "task_id": task_id,
            "status": task.get("status", "unknown"),
            "tool_name": task.get("tool_name", ""),
            "created_at": task.get("created_at", ""),
            "completed_at": task.get("completed_at"),
            "result": task.get("result"),
            "error": task.get("error")
        }

    @mcp.tool()
    def get_workflow_status(workflow_id: str) -> Dict[str, Any]:
        """
        获取工作流状态。

        Args:
            workflow_id: 工作流ID

        Returns:
            工作流状态信息，包含所有任务的详细状态
        """
        if workflow_id not in _WORKFLOWS:
            return {"success": False, "error": f"工作流不存在: {workflow_id}"}

        workflow = _WORKFLOWS[workflow_id]
        tasks_status = []

        for task_id in workflow.get("task_ids", []):
            if task_id in _TASKS:
                task = _TASKS[task_id]
                tasks_status.append({
                    "task_id": task_id,
                    "tool_name": task.get("tool_name", ""),
                    "status": task.get("status", "unknown")
                })

        return {
            "success": True,
            "workflow_id": workflow_id,
            "workflow_name": workflow.get("name", ""),
            "status": workflow.get("status", "unknown"),
            "target": workflow.get("target", ""),
            "tasks": tasks_status,
            "created_at": workflow.get("created_at", ""),
            "completed_at": workflow.get("completed_at")
        }

    @mcp.tool()
    def get_concurrent_system_stats() -> Dict[str, Any]:
        """
        获取并发任务系统统计信息。

        Returns:
            系统统计信息，包括任务数量、队列状态等
        """
        pending_tasks = sum(1 for t in _TASKS.values() if t.get("status") == "pending")
        running_tasks = sum(1 for t in _TASKS.values() if t.get("status") == "running")
        completed_tasks = sum(1 for t in _TASKS.values() if t.get("status") == "completed")
        failed_tasks = sum(1 for t in _TASKS.values() if t.get("status") == "failed")

        return {
            "success": True,
            "statistics": {
                "total_tasks": len(_TASKS),
                "pending": pending_tasks,
                "running": running_tasks,
                "completed": completed_tasks,
                "failed": failed_tasks
            },
            "workflows": {
                "total": len(_WORKFLOWS),
                "active": sum(1 for w in _WORKFLOWS.values() if w.get("status") == "running")
            },
            "attack_sessions": {
                "total": len(_ATTACK_SESSIONS),
                "current_session_id": _CURRENT_ATTACK_SESSION_ID
            }
        }
    
    @mcp.tool()
    def fast_reconnaissance(target: str, workflow_name: str = "Fast Reconnaissance") -> Dict[str, Any]:
        """
        执行快速侦察工作流。
        
        该工作流包括：
        1. 快速端口扫描 (masscan)
        2. 子域名枚举 (subfinder)
        
        Args:
            target: 目标域名或IP地址
            workflow_name: 工作流名称
            
        Returns:
            工作流提交结果
        """
        return submit_workflow(
            workflow_name=workflow_name,
            target=target,
            workflow_type="fast_reconnaissance"
        )
    
    @mcp.tool()
    def parallel_port_scanning(targets: List[str], ports: str = "1-1000",
                             scan_type: str = "-sS", priority: int = 3) -> Dict[str, Any]:
        """
        并行执行多个目标的端口扫描。
        
        Args:
            targets: 目标列表
            ports: 端口范围
            scan_type: 扫描类型
            priority: 任务优先级
            
        Returns:
            所有提交的任务ID列表
        """
        task_ids = []
        for target in targets:
            result = submit_concurrent_task(
                tool_name="nmap",
                parameters={
                    "target": target,
                    "scan_type": scan_type,
                    "ports": ports,
                    "additional_args": "-T4 --open"
                },
                priority=priority,
                timeout=600,
                tags=["port_scan", "parallel"],
                metadata={"batch_scan": True, "target_count": len(targets)}
            )
            if result.get("success"):
                task_ids.append(result.get("task_id"))
        
        return {
            "success": True,
            "task_ids": task_ids,
            "total_tasks": len(task_ids),
            "message": f"Submitted {len(task_ids)} parallel port scanning tasks"
        }
    
    @mcp.tool()
    def parallel_directory_scanning(urls: List[str], wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                                  priority: int = 2) -> Dict[str, Any]:
        """
        并行执行多个目标的目录扫描。
        
        Args:
            urls: 目标URL列表
            wordlist: 字典文件路径
            priority: 任务优先级
            
        Returns:
            所有提交的任务ID列表
        """
        task_ids = []
        for url in urls:
            result = submit_concurrent_task(
                tool_name="gobuster",
                parameters={
                    "url": url,
                    "mode": "dir",
                    "wordlist": wordlist,
                    "additional_args": "-t 20 -x php,html,txt,js"
                },
                priority=priority,
                timeout=300,
                tags=["directory_scan", "parallel"],
                metadata={"batch_scan": True, "target_count": len(urls)}
            )
            if result.get("success"):
                task_ids.append(result.get("task_id"))
        
        return {
            "success": True,
            "task_ids": task_ids,
            "total_tasks": len(task_ids),
            "message": f"Submitted {len(task_ids)} parallel directory scanning tasks"
        }
