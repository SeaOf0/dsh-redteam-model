#!/usr/bin/env python3
"""
代码审计工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_code_audit_tools(mcp, executor):
    """代码审计工具注册"""

    # ==================== 代码审计工具 ====================

    @mcp.tool()
    def semgrep_scan(target_path: str, config: str = "auto", language: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Run Semgrep static analysis on source code.

        Args:
            target_path: Path to source code directory or file
            config: Semgrep config (auto, p/ci, p/security-audit, or custom rule path)
            language: Target language filter (python, javascript, java, etc.)
            additional_args: Additional Semgrep arguments

        Returns:
            Static analysis findings in JSON format
        """
        data = {"target_path": target_path, "config": config, "language": language, "additional_args": additional_args}
        return executor.execute_tool_with_data("semgrep", data)

    @mcp.tool()
    def bandit_scan(target_path: str, severity: str = "", confidence: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Run Bandit security scanner on Python source code.

        Args:
            target_path: Path to Python source code directory or file
            severity: Minimum severity level (low, medium, high)
            confidence: Minimum confidence level (low, medium, high)
            additional_args: Additional Bandit arguments

        Returns:
            Python security scan results in JSON format
        """
        data = {"target_path": target_path, "severity": severity, "confidence": confidence, "additional_args": additional_args}
        return executor.execute_tool_with_data("bandit", data)

    @mcp.tool()
    def flawfinder_scan(target_path: str, min_level: str = "1", additional_args: str = "") -> Dict[str, Any]:
        """
        Run Flawfinder on C/C++ source code to find security vulnerabilities.

        Args:
            target_path: Path to C/C++ source code directory or file
            min_level: Minimum risk level to report (0-5, default 1)
            additional_args: Additional Flawfinder arguments

        Returns:
            C/C++ vulnerability scan results
        """
        data = {"target_path": target_path, "min_level": min_level, "additional_args": additional_args}
        return executor.execute_tool_with_data("flawfinder", data)

    @mcp.tool()
    def shellcheck_scan(target_path: str, severity: str = "warning", additional_args: str = "") -> Dict[str, Any]:
        """
        Run ShellCheck on shell scripts to find bugs and security issues.

        Args:
            target_path: Path to shell script file
            severity: Minimum severity (error, warning, info, style)
            additional_args: Additional ShellCheck arguments

        Returns:
            Shell script analysis results in JSON format
        """
        data = {"target_path": target_path, "severity": severity, "additional_args": additional_args}
        return executor.execute_tool_with_data("shellcheck", data)

    @mcp.tool()
    def code_audit_comprehensive(target_path: str, language: str = "auto") -> Dict[str, Any]:
        """
        Run comprehensive code security audit using multiple tools.

        Automatically selects appropriate scanners based on detected language:
        - Python: Bandit + Semgrep
        - C/C++: Flawfinder + Semgrep
        - Shell: ShellCheck + Semgrep
        - Other: Semgrep with auto config

        Args:
            target_path: Path to source code directory or file
            language: Programming language (auto, python, c, cpp, shell, javascript, java, php)

        Returns:
            Combined audit results from multiple tools
        """
        results = {"target": target_path, "language": language, "tools_used": [], "findings": []}

        # Semgrep (works for all languages)
        semgrep_result = executor.execute_tool_with_data("semgrep", {
            "target_path": target_path, "config": "auto",
            "language": language if language != "auto" else ""
        })
        results["tools_used"].append("semgrep")
        results["findings"].append({"tool": "semgrep", "result": semgrep_result})

        # Language-specific tools
        if language in ("auto", "python"):
            bandit_result = executor.execute_tool_with_data("bandit", {"target_path": target_path})
            results["tools_used"].append("bandit")
            results["findings"].append({"tool": "bandit", "result": bandit_result})

        if language in ("auto", "c", "cpp"):
            flawfinder_result = executor.execute_tool_with_data("flawfinder", {"target_path": target_path})
            results["tools_used"].append("flawfinder")
            results["findings"].append({"tool": "flawfinder", "result": flawfinder_result})

        if language in ("auto", "shell", "bash", "sh"):
            shellcheck_result = executor.execute_tool_with_data("shellcheck", {"target_path": target_path})
            results["tools_used"].append("shellcheck")
            results["findings"].append({"tool": "shellcheck", "result": shellcheck_result})

        # Dangerous pattern search via grep
        pattern_cmd = (
            f"grep -rn -E '(eval\\(|exec\\(|system\\(|os\\.system|pickle\\.load|__import__|"
            f"subprocess\\.call.*shell.*True)' {target_path} "
            f"--include='*.py' --include='*.js' --include='*.php' "
            f"--include='*.rb' --include='*.java' 2>/dev/null | head -50"
        )
        pattern_result = executor.execute_command(pattern_cmd)
        if pattern_result.get("output", "").strip():
            results["tools_used"].append("pattern_search")
            results["findings"].append({"tool": "pattern_search", "result": pattern_result})

        results["summary"] = f"审计完成: 使用 {len(results['tools_used'])} 个工具扫描 {target_path}"
        return results

    @mcp.tool()
    def comprehensive_recon(target: str, domain_enum: bool = True,
                           port_scan: bool = True, web_scan: bool = True) -> Dict[str, Any]:
        """
        Execute comprehensive reconnaissance workflow using multiple tools.

        Args:
            target: Target domain or IP
            domain_enum: Whether to perform subdomain enumeration
            port_scan: Whether to perform port scanning
            web_scan: Whether to perform web application scanning

        Returns:
            Comprehensive reconnaissance results
        """
        from datetime import datetime

        results = {
            "target": target,
            "workflow": "comprehensive_recon",
            "start_time": datetime.now().isoformat(),
            "phases": {}
        }

        try:
            # Phase 1: Subdomain enumeration
            if domain_enum and not target.replace(".", "").replace("/", "").isdigit():
                logger.info(f"Phase 1: Subdomain enumeration for {target}")
                results["phases"]["1_subdomain_enum"] = {
                    "subfinder": executor.execute_command(f"subfinder -d {target} -silent"),
                    "amass": executor.execute_command(f"amass enum -d {target} -passive"),
                    "sublist3r": executor.execute_command(f"sublist3r -d {target}")
                }

            # Phase 2: Port scanning
            if port_scan:
                logger.info(f"Phase 2: Port scanning for {target}")
                results["phases"]["2_port_scan"] = {
                    "masscan": executor.execute_command(f"masscan {target} -p80,443,22,21,25,53,8080 --rate=10000"),
                    "nmap": executor.execute_tool_with_data("nmap", {
                        "target": target, "scan_type": "-sV -sC", "additional_args": "-T4"
                    })
                }

            # Phase 3: Web application scanning
            if web_scan:
                logger.info(f"Phase 3: Web application scanning for {target}")
                target_url = target if target.startswith("http") else f"http://{target}"
                results["phases"]["3_web_scan"] = {
                    "whatweb": executor.execute_command(f"whatweb -a 1 {target_url}"),
                    "httpx": executor.execute_command(f"curl -sI --connect-timeout 5 '{target_url}' 2>/dev/null | head -20"),
                    "nuclei": executor.execute_command(f"nuclei -u {target_url} -t http/ -s critical,high -silent -rl 100 -timeout 10")
                }

            results["success"] = True
            results["end_time"] = datetime.now().isoformat()

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            logger.error(f"Comprehensive recon failed: {e}")

        return results

