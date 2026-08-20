#!/usr/bin/env python3
"""
PentAGI 能力桥接工具

补齐 PentAGI 常见工具链中在 Web UI ToolBridge 路径下缺失的能力入口。
"""

from typing import Dict, Any


def register_pentagi_bridge_tools(mcp, executor):
    """注册 PentAGI 风格能力桥接工具。"""

    @mcp.tool()
    def amass_scan(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """使用 Amass 执行子域名与资产枚举。"""
        data = {
            "domain": domain,
            "mode": mode,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("amass", data)

    @mcp.tool()
    def sublist3r_scan(domain: str, additional_args: str = "-v") -> Dict[str, Any]:
        """使用 Sublist3r 执行子域名枚举。"""
        data = {
            "domain": domain,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("sublist3r", data)

    @mcp.tool()
    def dnsenum_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """使用 Dnsenum 执行 DNS 枚举。"""
        data = {
            "domain": domain,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("dnsenum", data)

    @mcp.tool()
    def fierce_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """使用 Fierce 执行 DNS 侦察。"""
        data = {
            "domain": domain,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("fierce", data)

    @mcp.tool()
    def dirb_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Dirb 执行目录枚举。"""
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("dirb", data)

    @mcp.tool()
    def feroxbuster_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        threads: str = "50",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Feroxbuster 执行目录与资源爆破。"""
        data = {
            "url": url,
            "wordlist": wordlist,
            "threads": threads,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("feroxbuster", data)

    @mcp.tool()
    def wfuzz_scan(
        target: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "-c",
    ) -> Dict[str, Any]:
        """使用 Wfuzz 执行参数与路径模糊测试。"""
        data = {
            "target": target,
            "wordlist": wordlist,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("wfuzz", data)

    @mcp.tool()
    def medusa_attack(
        target: str,
        service: str = "ssh",
        username: str = "",
        password_list: str = "/usr/share/wordlists/rockyou.txt",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Medusa 执行口令验证测试。"""
        data = {
            "target": target,
            "service": service,
            "username": username,
            "password_list": password_list,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("medusa", data)

    @mcp.tool()
    def ncrack_attack(
        target: str,
        service: str = "ssh",
        username_file: str = "",
        password_file: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Ncrack 执行网络服务凭据验证。"""
        data = {
            "target": target,
            "service": service,
            "username_file": username_file,
            "password_file": password_file,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("ncrack", data)
