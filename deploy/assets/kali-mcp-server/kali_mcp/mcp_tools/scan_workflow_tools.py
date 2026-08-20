#!/usr/bin/env python3
"""
智能分析和扫描工作流工具

从 mcp_server.py setup_mcp_server() 提取
修复: 所有工作流函数现在真正调用 executor 执行 CLI 工具
"""

import logging
import re
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_scan_workflow_tools(mcp, executor, adapter=None):
    """智能分析和扫描工作流工具注册"""

    # ==================== 内部执行辅助函数 ====================

    def _run_tool(tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """内部辅助：通过 executor 实际执行 CLI 工具（支持适配器路由）"""
        try:
            # 如果有适配器且工具应该走代理路径
            if adapter and adapter.should_use_agent(tool_name, data):
                return adapter.execute_via_agent(tool_name, data)
            result = executor.execute_tool_with_data(tool_name, data)
            return result
        except Exception as e:
            logger.error(f"工具执行失败 {tool_name}: {e}")
            return {"success": False, "error": str(e), "tool": tool_name}

    def _detect_flags(text: str) -> List[str]:
        """从工具输出中检测 Flag"""
        flags = []
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
        ]
        for p in patterns:
            flags.extend(re.findall(p, text))
        return flags

    # ==================== 智能分析工具 ====================

    @mcp.tool()
    def optimize_tool_parameters(tool: str, target_type: str = "unknown",
                                time_constraint: str = "quick", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        优化渗透测试工具参数以提高准确性和效率。

        Args:
            tool: 工具名称 (nmap, gobuster, sqlmap, hydra等)
            target_type: 目标类型 (web, network, database, windows, linux)
            time_constraint: 时间约束 (quick, standard, thorough)
            stealth_mode: 是否启用隐蔽模式

        Returns:
            优化后的工具参数配置
        """
        tool_configs = {
            "nmap": {
                "quick": {"args": "-T4 -F --top-ports 100", "timeout": 60},
                "standard": {"args": "-sV -sC -T3", "timeout": 300},
                "thorough": {"args": "-sV -sC -A -T2 -p-", "timeout": 900}
            },
            "gobuster": {
                "quick": {"args": "-t 50 -q --no-error", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
                "standard": {"args": "-t 30 --no-error", "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"},
                "thorough": {"args": "-t 20 -e --no-error", "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"}
            },
            "sqlmap": {
                "quick": {"args": "--batch --level=1 --risk=1", "timeout": 120},
                "standard": {"args": "--batch --level=2 --risk=2", "timeout": 300},
                "thorough": {"args": "--batch --level=5 --risk=3 --all", "timeout": 900}
            },
            "hydra": {
                "quick": {"args": "-t 16 -f", "timeout": 120},
                "standard": {"args": "-t 8 -f", "timeout": 300},
                "thorough": {"args": "-t 4 -f -V", "timeout": 600}
            },
            "nuclei": {
                "quick": {"args": "-s critical,high -rate-limit 150", "timeout": 120},
                "standard": {"args": "-s critical,high,medium -rate-limit 100", "timeout": 300},
                "thorough": {"args": "-rate-limit 50", "timeout": 600}
            }
        }

        stealth_adjustments = {
            "nmap": "-T1 --scan-delay 1s",
            "gobuster": "-t 5 --delay 500ms",
            "sqlmap": "--delay=2 --random-agent",
            "hydra": "-t 1 -W 30",
            "nuclei": "-rate-limit 10 -rl 10"
        }

        config = tool_configs.get(tool, {}).get(time_constraint, {"args": "", "timeout": 300})

        if stealth_mode and tool in stealth_adjustments:
            config["stealth_args"] = stealth_adjustments[tool]

        return {
            "success": True,
            "tool": tool,
            "target_type": target_type,
            "time_constraint": time_constraint,
            "stealth_mode": stealth_mode,
            "optimized_config": config,
            "recommendation": f"使用 {time_constraint} 模式配置 {tool}"
        }

    @mcp.tool()
    def correlate_scan_results(tool_results: Dict[str, Dict]) -> Dict[str, Any]:
        """
        关联和分析多个扫描工具的结果，识别漏洞模式和攻击路径。

        Args:
            tool_results: 多个工具的扫描结果字典
                格式: {"nmap": {...}, "gobuster": {...}, "nuclei": {...}}

        Returns:
            关联分析结果，包含发现的漏洞模式和建议
        """
        vulnerabilities = []
        attack_paths = []
        discovered_services = []

        if "nmap" in tool_results:
            output = str(tool_results["nmap"].get("output", ""))
            ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)
            for port, service in ports:
                discovered_services.append({"port": port, "service": service})

        if "gobuster" in tool_results:
            output = str(tool_results["gobuster"].get("output", ""))
            sensitive_paths = ["/admin", "/backup", "/config", "/upload", "/.git", "/api"]
            for path in sensitive_paths:
                if path in output.lower():
                    vulnerabilities.append({
                        "type": "sensitive_path",
                        "path": path,
                        "severity": "medium",
                        "recommendation": f"检查 {path} 路径的访问控制"
                    })

        if "nuclei" in tool_results:
            output = str(tool_results["nuclei"].get("output", ""))
            if "critical" in output.lower():
                vulnerabilities.append({"type": "nuclei_critical", "severity": "critical"})
            if "high" in output.lower():
                vulnerabilities.append({"type": "nuclei_high", "severity": "high"})

        for svc in discovered_services:
            if svc["service"] in ("http", "https"):
                attack_paths.append(f"Web攻击: 端口{svc['port']} -> gobuster目录扫描 -> nuclei漏洞扫描 -> sqlmap注入测试")
            elif svc["service"] == "ssh":
                attack_paths.append(f"SSH攻击: 端口{svc['port']} -> hydra密码爆破")
            elif svc["service"] == "mysql":
                attack_paths.append(f"数据库攻击: 端口{svc['port']} -> 默认凭据测试 -> SQL注入")

        return {
            "success": True,
            "tools_analyzed": list(tool_results.keys()),
            "discovered_services": discovered_services,
            "vulnerabilities": vulnerabilities,
            "attack_paths": attack_paths,
            "recommendations": [
                "优先处理高危漏洞",
                "验证发现的敏感路径",
                "针对发现的服务进行深度测试"
            ]
        }

    @mcp.tool()
    def generate_adaptive_scan_plan(target: str, initial_results: Dict = None,
                                  time_budget: str = "standard") -> Dict[str, Any]:
        """
        基于目标特征和已有结果生成自适应扫描计划。

        Args:
            target: 目标IP、域名或URL
            initial_results: 初步扫描结果（可选）
            time_budget: 时间预算 (quick, standard, thorough)

        Returns:
            自适应扫描计划，包含优先级排序的扫描步骤
        """
        time_configs = {
            "quick": {"max_steps": 3, "timeout_per_step": 60},
            "standard": {"max_steps": 6, "timeout_per_step": 180},
            "thorough": {"max_steps": 10, "timeout_per_step": 300}
        }

        config = time_configs.get(time_budget, time_configs["standard"])
        scan_steps = []

        scan_steps.append({
            "step": 1, "tool": "nmap", "priority": "high",
            "purpose": "端口和服务发现",
            "args": "-sV -T4 --top-ports 1000" if time_budget == "quick" else "-sV -sC -T3"
        })

        is_web = "http" in target.lower() or ":80" in target or ":443" in target
        if is_web or (initial_results and "web" in str(initial_results).lower()):
            scan_steps.append({"step": 2, "tool": "gobuster", "priority": "high", "purpose": "目录枚举"})
            scan_steps.append({"step": 3, "tool": "nuclei", "priority": "high", "purpose": "Web漏洞扫描"})

        if time_budget in ["standard", "thorough"]:
            scan_steps.append({"step": len(scan_steps) + 1, "tool": "nikto", "priority": "medium", "purpose": "Web服务器漏洞"})

        if time_budget == "thorough":
            scan_steps.append({"step": len(scan_steps) + 1, "tool": "sqlmap", "priority": "medium", "purpose": "SQL注入测试"})

        return {
            "success": True, "target": target, "time_budget": time_budget,
            "scan_plan": scan_steps, "total_steps": len(scan_steps),
            "estimated_time": len(scan_steps) * config["timeout_per_step"],
            "config": config
        }

    @mcp.tool()
    def intelligent_smart_scan(target: str, objectives: List[str] = None,
                             time_budget: str = "standard", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        执行智能扫描 - 实际调用工具并返回结果。

        Args:
            target: 目标IP、域名或URL
            objectives: 扫描目标列表 (默认: ["port_scan", "web_scan"])
            time_budget: 时间预算 (quick, standard, thorough)
            stealth_mode: 是否启用隐蔽模式

        Returns:
            智能扫描实际执行结果
        """
        objectives = objectives or ["port_scan", "web_scan"]
        results = {}
        all_flags = []

        for obj in objectives:
            if obj == "port_scan":
                params = optimize_tool_parameters("nmap", "network", time_budget, stealth_mode)
                args = params.get("optimized_config", {}).get("args", "-sV")
                result = _run_tool("nmap", {"target": target, "scan_type": args})
                results["nmap"] = result
                if result.get("output"):
                    all_flags.extend(_detect_flags(result["output"]))

            elif obj == "web_scan":
                result = _run_tool("gobuster", {"url": target, "mode": "dir"})
                results["gobuster"] = result
                if result.get("output"):
                    all_flags.extend(_detect_flags(result["output"]))

            elif obj == "vuln_scan":
                result = _run_tool("nuclei", {"target": target, "severity": "critical,high,medium"})
                results["nuclei"] = result
                if result.get("output"):
                    all_flags.extend(_detect_flags(result["output"]))

        return {
            "success": True,
            "target": target,
            "objectives": objectives,
            "time_budget": time_budget,
            "stealth_mode": stealth_mode,
            "scan_results": results,
            "total_tools_executed": len(results),
            "flags_detected": all_flags,
            "message": f"智能扫描已完成，执行了 {len(results)} 个工具"
        }

    @mcp.tool()
    def analyze_target_intelligence(target: str, scan_results: Dict = None) -> Dict[str, Any]:
        """
        基于扫描结果分析目标特征和推荐攻击向量。
        如果没有提供扫描结果，会先执行快速扫描获取数据。

        Args:
            target: 目标IP、域名或URL
            scan_results: 扫描结果数据（可选）

        Returns:
            目标分析结果，包含目标类型、推荐攻击向量和安全评估
        """
        target_type = "unknown"
        if "http" in target.lower():
            target_type = "web"
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            target_type = "network"
        elif "." in target and "/" not in target:
            target_type = "domain"

        # 如果没有扫描结果，执行快速nmap扫描获取基础信息
        actual_scan = None
        if not scan_results:
            actual_scan = _run_tool("nmap", {"target": target, "scan_type": "-T4 -F --top-ports 100"})
            scan_results = actual_scan

        attack_vectors = []
        if target_type == "web":
            attack_vectors = [
                {"vector": "SQL注入", "tool": "sqlmap", "priority": "high"},
                {"vector": "目录遍历", "tool": "gobuster", "priority": "high"},
                {"vector": "XSS测试", "tool": "nuclei", "priority": "medium"},
                {"vector": "文件上传", "tool": "manual", "priority": "medium"}
            ]
        elif target_type == "network":
            attack_vectors = [
                {"vector": "端口扫描", "tool": "nmap", "priority": "high"},
                {"vector": "服务漏洞", "tool": "nuclei", "priority": "high"},
                {"vector": "默认凭据", "tool": "hydra", "priority": "medium"}
            ]
        elif target_type == "domain":
            attack_vectors = [
                {"vector": "子域名枚举", "tool": "subfinder", "priority": "high"},
                {"vector": "DNS信息", "tool": "dnsrecon", "priority": "medium"},
                {"vector": "OSINT", "tool": "theharvester", "priority": "medium"}
            ]

        findings = []
        if scan_results:
            output = str(scan_results.get("output", ""))
            if "open" in output.lower():
                findings.append("发现开放端口")
            if "sql" in output.lower() or "error" in output.lower():
                findings.append("可能存在SQL注入")
            if "admin" in output.lower():
                findings.append("发现管理接口")

        result = {
            "success": True,
            "target": target,
            "target_type": target_type,
            "attack_vectors": attack_vectors,
            "findings": findings,
            "risk_level": "medium" if findings else "unknown",
        }
        if actual_scan:
            result["nmap_scan_output"] = actual_scan
        return result

    @mcp.tool()
    def intelligent_ctf_solver(target: str, challenge_category: str = "unknown",
                             time_limit: str = "30min") -> Dict[str, Any]:
        """
        智能CTF题目求解器 - 实际执行扫描和攻击工具。

        Args:
            target: CTF题目地址或IP
            challenge_category: 题目分类 (web, pwn, crypto, misc, reverse)
            time_limit: 时间限制 (15min, 30min, 1hour)

        Returns:
            CTF求解实际执行结果
        """
        results = {}
        all_flags = []

        # 第1步：快速端口扫描
        nmap_result = _run_tool("nmap", {"target": target, "scan_type": "-T4 -F -sV"})
        results["nmap"] = nmap_result
        if nmap_result.get("output"):
            all_flags.extend(_detect_flags(nmap_result["output"]))

        nmap_output = str(nmap_result.get("output", ""))
        has_web = any(p in nmap_output for p in ["80/tcp", "443/tcp", "8080/tcp", "http"])

        if challenge_category == "web" or has_web:
            # Web题：目录扫描
            url = target if target.startswith("http") else f"http://{target}"
            gobuster_result = _run_tool("gobuster", {"url": url, "mode": "dir"})
            results["gobuster"] = gobuster_result
            if gobuster_result.get("output"):
                all_flags.extend(_detect_flags(gobuster_result["output"]))

            # Web题：nuclei漏洞扫描
            nuclei_result = _run_tool("nuclei", {"target": url, "severity": "critical,high,medium"})
            results["nuclei"] = nuclei_result
            if nuclei_result.get("output"):
                all_flags.extend(_detect_flags(nuclei_result["output"]))

            # Web题：nikto扫描
            nikto_result = _run_tool("nikto", {"target": url})
            results["nikto"] = nikto_result
            if nikto_result.get("output"):
                all_flags.extend(_detect_flags(nikto_result["output"]))

        return {
            "success": True,
            "target": target,
            "category": challenge_category,
            "tools_executed": list(results.keys()),
            "scan_results": results,
            "flags_detected": list(set(all_flags)),
            "message": f"CTF求解完成，执行了 {len(results)} 个工具，发现 {len(set(all_flags))} 个Flag"
        }

    @mcp.tool()
    def intelligent_vulnerability_assessment(target: str, assessment_depth: str = "comprehensive") -> Dict[str, Any]:
        """
        智能漏洞评估 - 实际执行多工具扫描。

        Args:
            target: 目标IP、域名或URL
            assessment_depth: 评估深度 (quick, comprehensive, deep)

        Returns:
            实际执行的漏洞评估结果
        """
        results = {}
        all_flags = []

        # 端口扫描
        scan_type = "-T4 -F" if assessment_depth == "quick" else "-sV -sC -T3"
        nmap_result = _run_tool("nmap", {"target": target, "scan_type": scan_type})
        results["nmap"] = nmap_result

        # 漏洞扫描
        url = target if target.startswith("http") else f"http://{target}"
        nuclei_result = _run_tool("nuclei", {"target": url, "severity": "critical,high,medium"})
        results["nuclei"] = nuclei_result

        if assessment_depth in ("comprehensive", "deep"):
            nikto_result = _run_tool("nikto", {"target": url})
            results["nikto"] = nikto_result

        if assessment_depth == "deep":
            whatweb_result = _run_tool("whatweb", {"target": url})
            results["whatweb"] = whatweb_result

        # 收集所有输出中的flag
        for name, res in results.items():
            output = str(res.get("output", ""))
            all_flags.extend(_detect_flags(output))

        return {
            "success": True,
            "target": target,
            "assessment_depth": assessment_depth,
            "tools_executed": list(results.keys()),
            "scan_results": results,
            "flags_detected": list(set(all_flags)),
            "message": f"漏洞评估完成，执行了 {len(results)} 个工具"
        }

    @mcp.tool()
    def intelligent_penetration_testing(target: str, scope: str = "single",
                                       methodology: str = "owasp") -> Dict[str, Any]:
        """
        智能渗透测试 - 遵循标准方法论执行实际渗透测试。

        Args:
            target: 目标IP、域名或URL
            scope: 测试范围 (single, subnet, domain)
            methodology: 测试方法论 (owasp, nist, ptes)

        Returns:
            实际执行的渗透测试结果
        """
        results = {}
        all_flags = []

        # Phase 1: 信息收集
        nmap_result = _run_tool("nmap", {"target": target, "scan_type": "-sV -sC -T3 -A"})
        results["phase1_nmap"] = nmap_result

        url = target if target.startswith("http") else f"http://{target}"

        # Phase 2: 漏洞发现
        nuclei_result = _run_tool("nuclei", {"target": url, "severity": "critical,high,medium"})
        results["phase2_nuclei"] = nuclei_result

        nikto_result = _run_tool("nikto", {"target": url})
        results["phase2_nikto"] = nikto_result

        # Phase 3: 目录发现
        gobuster_result = _run_tool("gobuster", {"url": url, "mode": "dir"})
        results["phase3_gobuster"] = gobuster_result

        # Phase 4: 技术指纹
        whatweb_result = _run_tool("whatweb", {"target": url})
        results["phase4_whatweb"] = whatweb_result

        # 收集flag
        for name, res in results.items():
            output = str(res.get("output", ""))
            all_flags.extend(_detect_flags(output))

        # 关联分析
        correlation = correlate_scan_results({
            k: v for k, v in results.items() if isinstance(v, dict)
        })

        return {
            "success": True,
            "target": target,
            "scope": scope,
            "methodology": methodology,
            "tools_executed": list(results.keys()),
            "scan_results": results,
            "correlation_analysis": correlation,
            "flags_detected": list(set(all_flags)),
            "message": f"渗透测试完成，执行了 {len(results)} 个工具"
        }

    # ==================== 预定义自动化工作流 ====================

    @mcp.tool()
    def auto_web_security_workflow(target: str, depth: str = "comprehensive") -> Dict[str, Any]:
        """
        自动化Web安全评估工作流 - 实际执行完整的Web应用安全测试。

        Args:
            target: 目标Web应用URL
            depth: 评估深度 (quick, comprehensive, deep)

        Returns:
            实际执行的Web安全评估结果
        """
        results = {}
        all_flags = []
        url = target if target.startswith("http") else f"http://{target}"

        # Stage 1: 信息收集
        whatweb_result = _run_tool("whatweb", {"target": url})
        results["whatweb"] = whatweb_result

        # Stage 2: 目录发现
        gobuster_result = _run_tool("gobuster", {"url": url, "mode": "dir"})
        results["gobuster"] = gobuster_result

        # Stage 3: 漏洞扫描
        nuclei_result = _run_tool("nuclei", {"target": url, "severity": "critical,high,medium"})
        results["nuclei"] = nuclei_result

        nikto_result = _run_tool("nikto", {"target": url})
        results["nikto"] = nikto_result

        if depth in ("comprehensive", "deep"):
            # Stage 4: WAF检测
            wafw00f_result = _run_tool("wafw00f", {"target": url})
            results["wafw00f"] = wafw00f_result

        # 收集flag
        for name, res in results.items():
            output = str(res.get("output", ""))
            all_flags.extend(_detect_flags(output))

        return {
            "success": True,
            "workflow_name": "auto_web_security_workflow",
            "target": url,
            "depth": depth,
            "tools_executed": list(results.keys()),
            "scan_results": results,
            "flags_detected": list(set(all_flags)),
            "message": f"Web安全评估完成，执行了 {len(results)} 个工具"
        }

    @mcp.tool()
    def auto_network_discovery_workflow(target_network: str, scan_intensity: str = "standard") -> Dict[str, Any]:
        """
        自动化网络发现工作流 - 实际执行网络侦察和服务发现。

        Args:
            target_network: 目标网络范围 (如 192.168.1.0/24)
            scan_intensity: 扫描强度 (light, standard, aggressive)

        Returns:
            实际执行的网络发现结果
        """
        results = {}

        # Stage 1: 主机发现
        scan_type = "-sn -T4" if scan_intensity == "light" else "-sn -T3"
        nmap_discovery = _run_tool("nmap", {"target": target_network, "scan_type": scan_type})
        results["host_discovery"] = nmap_discovery

        if scan_intensity in ("standard", "aggressive"):
            # Stage 2: 端口扫描
            port_scan_type = "-sV -T4 --top-ports 1000" if scan_intensity == "standard" else "-sV -sC -T3 -p-"
            nmap_ports = _run_tool("nmap", {"target": target_network, "scan_type": port_scan_type})
            results["port_scan"] = nmap_ports

        if scan_intensity == "aggressive":
            # Stage 3: 漏洞扫描
            nuclei_result = _run_tool("nuclei", {"target": target_network, "severity": "critical,high"})
            results["vuln_scan"] = nuclei_result

        return {
            "success": True,
            "workflow_name": "auto_network_discovery_workflow",
            "target_network": target_network,
            "scan_intensity": scan_intensity,
            "tools_executed": list(results.keys()),
            "scan_results": results,
            "message": f"网络发现完成，执行了 {len(results)} 个扫描阶段"
        }

    @mcp.tool()
    def auto_osint_workflow(target_domain: str, scope: str = "comprehensive") -> Dict[str, Any]:
        """
        自动化OSINT情报收集工作流 - 实际执行开源情报收集。

        Args:
            target_domain: 目标域名
            scope: 收集范围 (basic, comprehensive, extensive)

        Returns:
            实际执行的OSINT收集结果
        """
        results = {}

        # Stage 1: 子域名枚举
        subfinder_result = _run_tool("subfinder", {"domain": target_domain})
        results["subfinder"] = subfinder_result

        # Stage 2: DNS枚举
        dnsrecon_result = _run_tool("dnsrecon", {"domain": target_domain})
        results["dnsrecon"] = dnsrecon_result

        if scope in ("comprehensive", "extensive"):
            # Stage 3: OSINT信息收集
            harvester_result = _run_tool("theharvester", {"domain": target_domain})
            results["theharvester"] = harvester_result

        if scope == "extensive":
            # Stage 4: 技术指纹
            whatweb_result = _run_tool("whatweb", {"target": f"http://{target_domain}"})
            results["whatweb"] = whatweb_result

            httpx_result = _run_tool("httpx", {"targets": target_domain})
            results["httpx"] = httpx_result

        return {
            "success": True,
            "workflow_name": "auto_osint_workflow",
            "target_domain": target_domain,
            "scope": scope,
            "tools_executed": list(results.keys()),
            "scan_results": results,
            "message": f"OSINT收集完成，执行了 {len(results)} 个工具"
        }

    # ==================== v5.1: 基于 ToolChain 引擎的智能工作流 ====================

    @mcp.tool()
    def smart_web_recon(target: str, depth: str = "standard") -> Dict[str, Any]:
        """
        智能Web侦察工作流 — 基于结果驱动的自适应工具链。

        与旧版工具链的核心区别：
        - 每个工具的输出被结构化解析
        - 下一个工具的参数基于上一步的发现动态生成
        - 发现WAF时自动调整sqlmap的tamper脚本
        - 发现WordPress时自动启动wpscan
        - 发现可注入URL时自动启动sqlmap

        Args:
            target: 目标URL (如 http://example.com)
            depth: 扫描深度 (quick, standard, thorough)

        Returns:
            包含所有发现的结构化结果
        """
        try:
            from kali_mcp.core.tool_chain import create_web_recon_chain
            from kali_mcp.core.local_executor import _event_bus

            chain = create_web_recon_chain(executor, event_bus=_event_bus)
            result = chain.execute(target)

            return {
                "success": True,
                "workflow": "smart_web_recon",
                "target": target,
                "depth": depth,
                "steps_executed": result.get("steps_executed", 0),
                "steps_skipped": result.get("steps_skipped", 0),
                "open_ports": result.get("context", {}).get("open_ports", []),
                "web_urls": result.get("context", {}).get("web_urls", []),
                "discovered_paths": result.get("context", {}).get("discovered_paths", [])[:50],
                "discovered_vulns": result.get("context", {}).get("discovered_vulns", []),
                "injectable_urls": result.get("context", {}).get("injectable_urls", []),
                "has_waf": result.get("context", {}).get("has_waf", False),
                "waf_type": result.get("context", {}).get("waf_type", ""),
                "cms_type": result.get("context", {}).get("cms_type", ""),
                "flags": result.get("context", {}).get("flags", []),
                "step_results": {
                    name: {
                        "success": r.get("success", False),
                        "output_preview": r.get("output", "")[:300],
                    }
                    for name, r in result.get("results", {}).items()
                },
            }
        except ImportError as e:
            return {"success": False, "error": f"ToolChain engine not available: {e}"}
        except Exception as e:
            logger.error(f"smart_web_recon failed: {e}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def smart_network_recon(target: str, depth: str = "standard") -> Dict[str, Any]:
        """
        智能网络侦察工作流 — 基于结果驱动的自适应网络扫描。

        工具链：masscan快速发现  nmap精确扫描(仅已发现端口)  nuclei漏洞检测  enum4linux(条件触发)

        Args:
            target: 目标IP或网段
            depth: 扫描深度 (quick, standard, thorough)

        Returns:
            结构化网络侦察结果
        """
        try:
            from kali_mcp.core.tool_chain import create_network_recon_chain
            from kali_mcp.core.local_executor import _event_bus

            chain = create_network_recon_chain(executor, event_bus=_event_bus)
            result = chain.execute(target)

            return {
                "success": True,
                "workflow": "smart_network_recon",
                "target": target,
                "depth": depth,
                "steps_executed": result.get("steps_executed", 0),
                "open_ports": result.get("context", {}).get("open_ports", []),
                "discovered_vulns": result.get("context", {}).get("discovered_vulns", []),
                "flags": result.get("context", {}).get("flags", []),
                "step_results": {
                    name: {
                        "success": r.get("success", False),
                        "output_preview": r.get("output", "")[:300],
                    }
                    for name, r in result.get("results", {}).items()
                },
            }
        except ImportError as e:
            return {"success": False, "error": f"ToolChain engine not available: {e}"}
        except Exception as e:
            logger.error(f"smart_network_recon failed: {e}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def smart_ctf_solve(target: str) -> Dict[str, Any]:
        """
        CTF极速解题工作流 — 30-60秒超时的快速自适应攻击链。

        工具链：快速nmap  gobuster目录扫描  nuclei漏洞检测  sqlmap注入(条件触发)
        每步都会自动检测Flag，发现后提前终止。

        Args:
            target: CTF题目URL

        Returns:
            解题结果，包含发现的Flags
        """
        try:
            from kali_mcp.core.tool_chain import create_ctf_speed_chain
            from kali_mcp.core.local_executor import _event_bus

            chain = create_ctf_speed_chain(executor, event_bus=_event_bus)
            result = chain.execute(target)

            flags = result.get("context", {}).get("flags", [])
            return {
                "success": True,
                "workflow": "smart_ctf_solve",
                "target": target,
                "flags_found": flags,
                "flag_count": len(flags),
                "steps_executed": result.get("steps_executed", 0),
                "discovered_vulns": result.get("context", {}).get("discovered_vulns", []),
                "injectable_urls": result.get("context", {}).get("injectable_urls", []),
                "step_results": {
                    name: {
                        "success": r.get("success", False),
                        "output_preview": r.get("output", "")[:200],
                    }
                    for name, r in result.get("results", {}).items()
                },
                "message": f"找到 {len(flags)} 个Flag" if flags else "未找到Flag，建议手动分析",
            }
        except ImportError as e:
            return {"success": False, "error": f"ToolChain engine not available: {e}"}
        except Exception as e:
            logger.error(f"smart_ctf_solve failed: {e}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def smart_full_pentest(target: str) -> Dict[str, Any]:
        """
        完整渗透测试工作流 — 9步全面自适应扫描。

        工具链：nmap  whatweb  wafw00f  gobuster  nuclei CVE  nuclei Web 
        wpscan(CMS条件)  sqlmap(注入条件)  汇总报告

        每步都会解析结果并动态调整后续参数。

        Args:
            target: 目标URL或IP

        Returns:
            完整渗透测试结果
        """
        try:
            from kali_mcp.core.tool_chain import create_full_pentest_chain
            from kali_mcp.core.local_executor import _event_bus

            chain = create_full_pentest_chain(executor, event_bus=_event_bus)
            result = chain.execute(target)

            ctx = result.get("context", {})
            return {
                "success": True,
                "workflow": "smart_full_pentest",
                "target": target,
                "steps_executed": result.get("steps_executed", 0),
                "steps_skipped": result.get("steps_skipped", 0),
                "summary": {
                    "open_ports": ctx.get("open_ports", []),
                    "web_urls": ctx.get("web_urls", []),
                    "has_waf": ctx.get("has_waf", False),
                    "waf_type": ctx.get("waf_type", ""),
                    "cms_type": ctx.get("cms_type", ""),
                    "discovered_paths_count": len(ctx.get("discovered_paths", [])),
                    "discovered_vulns": ctx.get("discovered_vulns", []),
                    "injectable_urls": ctx.get("injectable_urls", []),
                    "flags": ctx.get("flags", []),
                },
                "step_results": {
                    name: {
                        "success": r.get("success", False),
                        "output_preview": r.get("output", "")[:200],
                    }
                    for name, r in result.get("results", {}).items()
                },
            }
        except ImportError as e:
            return {"success": False, "error": f"ToolChain engine not available: {e}"}
        except Exception as e:
            logger.error(f"smart_full_pentest failed: {e}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def auto_pentest(target: str, mode: str = "auto") -> Dict[str, Any]:
        """
        全自动渗透测试 (v5.2) — 一键自动化渗透测试全流程。

        集成所有v5.2引擎:
        1. DecisionBrain.start  分析目标，选择策略，获取ML推荐
        2. ToolChain  执行侦察链（含6个决策钩子动态插入步骤）
        3. DecisionBrain.mid_scan  根据中间结果决定深入/转向/利用
        4. Digger深度挖掘  对高价值漏洞自动启动深度测试
        5. DecisionBrain.final  汇总所有发现，生成结构化报告

        Args:
            target: 目标URL或IP
            mode: 模式 (auto/ctf/pentest/web)

        Returns:
            完整渗透测试报告，含决策过程、漏洞发现、Flag等
        """
        import time as _time
        start_time = _time.time()
        report = {
            "success": True,
            "target": target,
            "mode": mode,
            "phases": {},
            "vulns": [],
            "flags": [],
            "decision_trace": [],
        }

        try:
            from kali_mcp.core.decision_brain import DecisionBrain
            from kali_mcp.core.tool_chain import (
                create_web_recon_chain, create_network_recon_chain,
                create_ctf_speed_chain, create_full_pentest_chain,
            )
            from kali_mcp.core.local_executor import _event_bus
            from kali_mcp.core.ml_optimizer import MLStrategyOptimizer

            # 获取共享数据源
            ml_opt = None
            try:
                ml_opt = MLStrategyOptimizer()
            except Exception:
                pass

            brain = DecisionBrain(ml_optimizer=ml_opt)

            # ===== Phase 1: 决策引擎启动 =====
            start_decision = brain.decide("start", {
                "target": target,
                "mode": mode,
            })
            report["phases"]["start"] = start_decision
            report["decision_trace"].append(start_decision)
            strategy = start_decision.get("strategy", "balanced")

            # ===== Phase 2: 选择并执行工具链 =====
            is_url = "://" in target
            is_ctf = mode == "ctf" or "ctf" in target.lower()

            if is_ctf:
                chain = create_ctf_speed_chain(executor, event_bus=_event_bus)
            elif is_url or strategy == "web_focused":
                chain = create_web_recon_chain(executor, event_bus=_event_bus)
            elif strategy == "methodical":
                chain = create_full_pentest_chain(executor, event_bus=_event_bus)
            else:
                chain = create_network_recon_chain(executor, event_bus=_event_bus)

            chain_result = chain.execute(target)
            report["phases"]["recon"] = {
                "chain_type": type(chain).__name__,
                "duration": chain_result.get("duration", 0),
                "steps": chain_result.get("steps", {}),
                "vulns_found": chain_result.get("vulns_found", 0),
                "paths_found": chain_result.get("paths_found", 0),
            }

            # 收集发现
            ctx_summary = chain_result.get("context_summary", {})
            report["vulns"] = ctx_summary.get("discovered_vulns", [])
            report["flags"] = chain_result.get("flags", [])

            # ===== Phase 3: 中期决策 =====
            elapsed = _time.time() - start_time
            mid_decision = brain.decide("mid_scan", {
                "target": target,
                "vulns_found": chain_result.get("vulns_found", 0),
                "elapsed_minutes": elapsed / 60,
                "scanned": 1,
                "total_targets": 1,
            })
            report["phases"]["mid_scan"] = mid_decision
            report["decision_trace"].append(mid_decision)

            # ===== Phase 4: 根据决策执行深度挖掘 =====
            if mid_decision.get("action") == "shift_to_exploit":
                # 对发现的漏洞使用Digger深度挖掘
                injectable = ctx_summary.get("injectable_urls", [])
                if injectable:
                    try:
                        from kali_mcp.diggers.sqli_digger import SQLInjectionDeepDigger
                        digger = SQLInjectionDeepDigger(executor)
                        dig_result = digger.excavate(injectable[0], mode="ctf" if is_ctf else "pentest")
                        report["phases"]["deep_sqli"] = {
                            "target": injectable[0],
                            "findings": dig_result.get("findings_count", 0),
                            "flags": dig_result.get("flags", []),
                        }
                        report["flags"].extend(dig_result.get("flags", []))
                    except Exception as e:
                        report["phases"]["deep_sqli"] = {"error": str(e)}

            elif mid_decision.get("action") == "expand_scan":
                # 扩大扫描 — 执行全端口nmap
                full_scan = executor.execute_tool_with_data("nmap", {
                    "target": target,
                    "ports": "1-65535",
                    "scan_type": "-sS",
                    "additional_args": "-T4 --open --min-rate 3000",
                })
                report["phases"]["full_port_scan"] = {
                    "success": full_scan.get("success", False),
                    "output_preview": full_scan.get("output", "")[:500],
                }

            # ===== Phase 5: 最终汇总 =====
            final_decision = brain.decide("final", {
                "target": target,
                "total_vulns": len(report["vulns"]),
                "critical_vulns": sum(1 for v in report["vulns"] if v.get("severity") == "critical"),
                "exploited": 0,
                "flags_found": report["flags"],
            })
            report["phases"]["final"] = final_decision
            report["decision_trace"].append(final_decision)

            report["duration"] = round(_time.time() - start_time, 2)
            report["summary"] = {
                "strategy": strategy,
                "total_vulns": len(report["vulns"]),
                "total_flags": len(report["flags"]),
                "phases_executed": len(report["phases"]),
                "decisions_made": len(report["decision_trace"]),
            }

        except ImportError as e:
            report["success"] = False
            report["error"] = f"Required module not available: {e}"
        except Exception as e:
            logger.error(f"auto_pentest failed: {e}")
            report["success"] = False
            report["error"] = str(e)

        return report
