#!/usr/bin/env python3
"""
信息收集和传统安全工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_recon_tools(mcp, executor):
    """信息收集和传统安全工具注册"""

    # ==================== 传统工具 (增强版) ====================

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "",
                  intelligent_optimization: bool = True, target_type: str = "unknown",
                  time_constraint: str = "quick", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target with intelligent parameter optimization.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            intelligent_optimization: Enable intelligent parameter optimization
            target_type: Target type (web, network, database, windows, linux)
            time_constraint: Time constraint (quick, standard, thorough)
            stealth_mode: Enable stealth mode

        Returns:
            Scan results with intelligent analysis
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args,
            "intelligent_optimization": intelligent_optimization,
            "target_type": target_type,
            "time_constraint": time_constraint,
            "stealth_mode": stealth_mode
        }
        return executor.execute_tool_with_data("nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                     additional_args: str = "", intelligent_optimization: bool = True,
                     target_type: str = "web", time_constraint: str = "quick", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts with intelligent optimization.

        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            intelligent_optimization: Enable intelligent parameter optimization
            target_type: Target type (web, cms, api, etc.)
            time_constraint: Time constraint (quick, standard, thorough)
            stealth_mode: Enable stealth mode

        Returns:
            Scan results with intelligent analysis
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args,
            "intelligent_optimization": intelligent_optimization,
            "target_type": target_type,
            "time_constraint": time_constraint,
            "stealth_mode": stealth_mode
        }
        return executor.execute_tool_with_data("gobuster", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute a Metasploit module.

        Args:
            module: The Metasploit module path
            options: Dictionary of module options

        Returns:
            Module execution results
        """
        if options is None:
            options = {}
        data = {
            "module": module,
            "options": options
        }
        return executor.execute_tool_with_data("metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("john", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("enum4linux", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.

        Returns:
            Server health information
        """
        return {"success": True, "status": "本地执行模式", "message": "无需健康检查"}
