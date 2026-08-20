#!/usr/bin/env python3
"""
增强CTF求解和逆向工程工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
import re as _re
import subprocess
import os
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_advanced_ctf_tools(mcp, executor, adapter=None):
    """增强CTF求解和逆向工程工具注册"""

    def _detect_flags(text):
        """检测输出中的flag"""
        if not text:
            return []
        flags = []
        for pat in [r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'DASCTF\{[^}]+\}']:
            flags.extend(_re.findall(pat, text, _re.IGNORECASE))
        return list(set(flags))

    def _run_tool(tool_name, params):
        """安全执行工具并返回结果（支持适配器路由）"""
        try:
            # 如果有适配器且工具应该走代理路径
            if adapter and adapter.should_use_agent(tool_name, params):
                return adapter.execute_via_agent(tool_name, params)
            return executor.execute_tool_with_data(tool_name, params)
        except Exception as e:
            logger.warning(f"工具 {tool_name} 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _get_output(result):
        """从工具结果提取输出文本"""
        return result.get("output", "") or result.get("stdout", "")

    # ==================== 增强自动化CTF求解功能 ====================

    @mcp.tool()
    def advanced_ctf_solver(target: str, challenge_info: Dict = None, time_limit: str = "30min") -> Dict[str, Any]:
        """
        高级CTF题目自动求解器 - 基于题目特征的智能化攻击策略。

        Args:
            target: CTF题目地址或IP
            challenge_info: 题目信息 (category, description, hints等)
            time_limit: 时间限制

        Returns:
            CTF求解执行计划和结果
        """
        if not challenge_info:
            challenge_info = {}

        category = challenge_info.get("category", "unknown")
        description = challenge_info.get("description", "")

        # 基于题目分类路由到对应求解器
        if category == "web" or "web" in description.lower():
            return ctf_web_comprehensive_solver(target, challenge_info, time_limit)
        elif category == "pwn" or "pwn" in description.lower():
            return _ctf_pwn_network_solver(target, challenge_info, time_limit)
        elif category == "crypto" or "crypto" in description.lower():
            return ctf_crypto_solver(target, challenge_info, time_limit)
        elif category == "misc" or "misc" in description.lower():
            return ctf_misc_solver(target, challenge_info, time_limit)
        else:
            return ctf_auto_detect_solver(target, challenge_info, time_limit)

    @mcp.tool()
    def ctf_web_comprehensive_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Web类CTF题目全面求解器 - 实际执行多阶段Web攻击"""
        results = {
            "solver_type": "ctf_web_comprehensive",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "web",
            "phases": {},
            "flags_found": []
        }
        all_flags = []

        # === 第一阶段：基础信息收集 ===
        logger.info(f"[Web Solver] Phase 1: Recon for {target}")

        # 1.1 技术检测
        whatweb_result = _run_tool("whatweb", {"target": target})
        results["phases"]["1_whatweb"] = whatweb_result
        all_flags.extend(_detect_flags(_get_output(whatweb_result)))

        # 1.2 目录发现
        gobuster_result = _run_tool("gobuster", {
            "url": target,
            "wordlist": "/usr/share/wordlists/dirb/big.txt",
            "mode": "dir"
        })
        results["phases"]["1_gobuster"] = gobuster_result
        all_flags.extend(_detect_flags(_get_output(gobuster_result)))

        # 1.3 漏洞扫描
        nuclei_result = _run_tool("nuclei", {
            "target": target,
            "severity": "critical,high,medium"
        })
        results["phases"]["1_nuclei"] = nuclei_result
        all_flags.extend(_detect_flags(_get_output(nuclei_result)))

        # === 第二阶段：常见Web漏洞检测 ===
        logger.info(f"[Web Solver] Phase 2: Vulnerability detection for {target}")

        # 2.1 SQL注入
        sqlmap_result = _run_tool("sqlmap", {
            "url": target,
            "additional_args": "--crawl=3 --batch --level=3 --risk=3"
        })
        results["phases"]["2_sqlmap"] = sqlmap_result
        all_flags.extend(_detect_flags(_get_output(sqlmap_result)))

        # 2.2 Nikto Web漏洞扫描
        nikto_result = _run_tool("nikto", {"target": target})
        results["phases"]["2_nikto"] = nikto_result
        all_flags.extend(_detect_flags(_get_output(nikto_result)))

        # === 第三阶段：CTF特定攻击 ===
        logger.info(f"[Web Solver] Phase 3: CTF-specific attacks for {target}")

        # 3.1 敏感文件搜索（备份文件、源码泄露等）
        gobuster2_result = _run_tool("gobuster", {
            "url": target,
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "mode": "dir",
            "additional_args": "-x php,txt,bak,old,zip,html,js,flag"
        })
        results["phases"]["3_gobuster_ext"] = gobuster2_result
        all_flags.extend(_detect_flags(_get_output(gobuster2_result)))

        results["flags_found"] = list(set(all_flags))
        results["success"] = True
        results["auto_flag_detection"] = True
        results["message"] = f"CTF Web全面求解完成，目标: {target}，发现Flag: {len(results['flags_found'])}个"
        return results

    def _ctf_pwn_network_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Pwn类CTF题目求解器(内部) - 网络PWN服务识别，不注册为MCP工具(避免与pwn_tools.py中的ctf_pwn_solver重复)"""
        results = {
            "solver_type": "ctf_pwn",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "pwn",
            "phases": {},
            "flags_found": []
        }
        all_flags = []

        # 解析target获取host和port
        host = target
        port = ""
        if ":" in target and not target.startswith("http"):
            parts = target.rsplit(":", 1)
            host = parts[0]
            port = parts[1]

        # Phase 1: 服务识别
        logger.info(f"[PWN Solver] Phase 1: Service identification for {target}")
        nmap_params = {"target": host, "scan_type": "-sV -sC"}
        if port:
            nmap_params["ports"] = port
        nmap_result = _run_tool("nmap", nmap_params)
        results["phases"]["1_nmap"] = nmap_result
        all_flags.extend(_detect_flags(_get_output(nmap_result)))

        # Phase 2: Banner抓取和漏洞探测
        logger.info(f"[PWN Solver] Phase 2: Vulnerability probing for {target}")
        if port:
            # 尝试直接连接获取banner
            nc_result = _run_tool("execute_command", {
                "command": f"echo '' | nc -w 3 {host} {port}"
            })
            results["phases"]["2_banner"] = nc_result
            all_flags.extend(_detect_flags(_get_output(nc_result)))

        # Phase 3: Nuclei网络漏洞扫描
        nuclei_result = _run_tool("nuclei", {
            "target": target,
            "severity": "critical,high"
        })
        results["phases"]["3_nuclei"] = nuclei_result
        all_flags.extend(_detect_flags(_get_output(nuclei_result)))

        results["flags_found"] = list(set(all_flags))
        results["success"] = True
        results["auto_flag_detection"] = True
        results["message"] = f"CTF Pwn求解完成，目标: {target}，发现Flag: {len(results['flags_found'])}个"
        return results

    @mcp.tool()
    def ctf_crypto_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Crypto类CTF题目求解器 - 执行密码学分析工具"""
        results = {
            "solver_type": "ctf_crypto",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "crypto",
            "phases": {},
            "flags_found": []
        }
        all_flags = []

        # Phase 1: 如果target是文件，进行文件分析
        if os.path.exists(target):
            logger.info(f"[Crypto Solver] Phase 1: File analysis for {target}")

            # 1.1 文件类型检测
            file_result = _run_tool("execute_command", {"command": f"file {target}"})
            results["phases"]["1_file_type"] = file_result
            all_flags.extend(_detect_flags(_get_output(file_result)))

            # 1.2 Strings搜索Flag和密钥
            strings_result = _run_tool("execute_command", {"command": f"strings {target}"})
            results["phases"]["1_strings"] = strings_result
            all_flags.extend(_detect_flags(_get_output(strings_result)))

            # 1.3 十六进制分析
            xxd_result = _run_tool("execute_command", {"command": f"xxd {target} | head -100"})
            results["phases"]["1_hex_dump"] = xxd_result
            all_flags.extend(_detect_flags(_get_output(xxd_result)))

        # Phase 2: 如果target是URL，尝试获取加密数据
        elif target.startswith("http"):
            logger.info(f"[Crypto Solver] Phase 2: Web crypto analysis for {target}")
            nmap_result = _run_tool("nmap", {"target": target, "scan_type": "-sV"})
            results["phases"]["2_nmap"] = nmap_result
            all_flags.extend(_detect_flags(_get_output(nmap_result)))

        # Phase 3: 哈希识别（如果target看起来像哈希）
        if _re.match(r'^[a-fA-F0-9]{32,128}$', target.strip()):
            logger.info(f"[Crypto Solver] Phase 3: Hash identification")
            hashid_result = _run_tool("execute_command", {"command": f"echo '{target}' | hashid"})
            results["phases"]["3_hashid"] = hashid_result

            # 尝试用john破解
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
                f.write(target.strip() + "\n")
                hash_file = f.name
            john_result = _run_tool("john", {
                "hash_file": hash_file,
                "wordlist": "/usr/share/wordlists/rockyou.txt"
            })
            results["phases"]["3_john"] = john_result
            all_flags.extend(_detect_flags(_get_output(john_result)))
            try:
                os.unlink(hash_file)
            except:
                pass

        results["flags_found"] = list(set(all_flags))
        results["success"] = True
        results["auto_flag_detection"] = True
        results["message"] = f"CTF Crypto求解完成，目标: {target}，发现Flag: {len(results['flags_found'])}个"
        return results

    @mcp.tool()
    def ctf_misc_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Misc类CTF题目求解器 - 执行文件分析和隐写检测"""
        results = {
            "solver_type": "ctf_misc",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "misc",
            "phases": {},
            "flags_found": []
        }
        all_flags = []

        if os.path.exists(target):
            logger.info(f"[Misc Solver] Phase 1: File analysis for {target}")

            # 1.1 文件类型检测
            file_result = _run_tool("execute_command", {"command": f"file {target}"})
            results["phases"]["1_file_type"] = file_result
            all_flags.extend(_detect_flags(_get_output(file_result)))

            # 1.2 元数据提取
            exiftool_result = _run_tool("execute_command", {"command": f"exiftool {target}"})
            results["phases"]["1_exiftool"] = exiftool_result
            all_flags.extend(_detect_flags(_get_output(exiftool_result)))

            # 1.3 Strings搜索
            strings_result = _run_tool("execute_command", {"command": f"strings {target}"})
            results["phases"]["1_strings"] = strings_result
            all_flags.extend(_detect_flags(_get_output(strings_result)))

            # 1.4 Binwalk固件/嵌入文件分析
            binwalk_result = _run_tool("binwalk", {"file_path": target, "extract": False})
            results["phases"]["1_binwalk"] = binwalk_result
            all_flags.extend(_detect_flags(_get_output(binwalk_result)))

            # Phase 2: 隐写术检测
            logger.info(f"[Misc Solver] Phase 2: Steganography detection for {target}")
            file_output = _get_output(file_result).lower()

            # 2.1 PNG隐写检测
            if "png" in file_output:
                zsteg_result = _run_tool("execute_command", {"command": f"zsteg {target} 2>/dev/null || true"})
                results["phases"]["2_zsteg"] = zsteg_result
                all_flags.extend(_detect_flags(_get_output(zsteg_result)))

                pngcheck_result = _run_tool("execute_command", {"command": f"pngcheck -v {target}"})
                results["phases"]["2_pngcheck"] = pngcheck_result
                all_flags.extend(_detect_flags(_get_output(pngcheck_result)))

            # 2.2 JPEG隐写检测
            elif "jpeg" in file_output or "jpg" in file_output:
                steghide_result = _run_tool("execute_command", {
                    "command": f"steghide extract -sf {target} -p '' -f 2>/dev/null || true"
                })
                results["phases"]["2_steghide"] = steghide_result
                all_flags.extend(_detect_flags(_get_output(steghide_result)))

            # 2.3 ZIP/压缩文件分析
            elif "zip" in file_output or "compress" in file_output:
                unzip_result = _run_tool("execute_command", {"command": f"unzip -l {target}"})
                results["phases"]["2_unzip_list"] = unzip_result
                all_flags.extend(_detect_flags(_get_output(unzip_result)))

            # 2.4 PCAP流量分析
            elif "pcap" in file_output or "capture" in file_output:
                tshark_result = _run_tool("execute_command", {
                    "command": f"tshark -r {target} -Y 'http || ftp || smtp' -T fields -e data 2>/dev/null | head -200"
                })
                results["phases"]["2_tshark"] = tshark_result
                all_flags.extend(_detect_flags(_get_output(tshark_result)))

        elif target.startswith("http"):
            # 网络目标的Misc分析
            logger.info(f"[Misc Solver] Web-based misc analysis for {target}")
            nmap_result = _run_tool("nmap", {"target": target, "scan_type": "-sV -sC"})
            results["phases"]["1_nmap"] = nmap_result
            all_flags.extend(_detect_flags(_get_output(nmap_result)))

        results["flags_found"] = list(set(all_flags))
        results["success"] = True
        results["auto_flag_detection"] = True
        results["message"] = f"CTF Misc求解完成，目标: {target}，发现Flag: {len(results['flags_found'])}个"
        return results

    @mcp.tool()
    def ctf_auto_detect_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """CTF题目自动检测求解器 - 先分析目标类型再选择策略"""
        results = {
            "solver_type": "ctf_auto_detect",
            "target": target,
            "detection_results": {},
            "flags_found": []
        }
        all_flags = []

        # 判断target类型
        is_file = os.path.exists(target)
        is_url = target.startswith("http")
        is_network = not is_file and not is_url

        if is_url:
            # Web目标: 快速探测
            whatweb_result = _run_tool("whatweb", {"target": target})
            results["detection_results"]["whatweb"] = whatweb_result
            all_flags.extend(_detect_flags(_get_output(whatweb_result)))

            results["detected_type"] = "web"
            # 路由到Web求解器
            web_result = ctf_web_comprehensive_solver(target, challenge_info, time_limit)
            results["solver_result"] = web_result
            all_flags.extend(web_result.get("flags_found", []))

        elif is_file:
            # 文件目标: 检测文件类型
            file_result = _run_tool("execute_command", {"command": f"file {target}"})
            file_output = _get_output(file_result).lower()
            results["detection_results"]["file_type"] = file_result

            if "elf" in file_output or "executable" in file_output:
                results["detected_type"] = "binary/pwn"
                # 使用本模块的逆向分析
                rev_result = ctf_reverse_solver(target)
                results["solver_result"] = rev_result
                all_flags.extend(rev_result.get("potential_flags", []))
            elif any(ext in file_output for ext in ["png", "jpeg", "jpg", "gif", "bmp", "pcap", "zip"]):
                results["detected_type"] = "misc"
                misc_result = ctf_misc_solver(target, challenge_info, time_limit)
                results["solver_result"] = misc_result
                all_flags.extend(misc_result.get("flags_found", []))
            else:
                results["detected_type"] = "unknown_file"
                # 尝试strings搜索
                strings_result = _run_tool("execute_command", {"command": f"strings {target}"})
                results["detection_results"]["strings"] = strings_result
                all_flags.extend(_detect_flags(_get_output(strings_result)))

        elif is_network:
            # 网络目标: nmap探测
            nmap_result = _run_tool("nmap", {"target": target, "scan_type": "-sV -sC --open"})
            results["detection_results"]["nmap"] = nmap_result
            nmap_output = _get_output(nmap_result)
            all_flags.extend(_detect_flags(nmap_output))

            if "80/" in nmap_output or "443/" in nmap_output or "8080/" in nmap_output:
                results["detected_type"] = "web"
                web_target = f"http://{target}"
                web_result = ctf_web_comprehensive_solver(web_target, challenge_info, time_limit)
                results["solver_result"] = web_result
                all_flags.extend(web_result.get("flags_found", []))
            else:
                results["detected_type"] = "network"
                pwn_result = _ctf_pwn_network_solver(target, challenge_info, time_limit)
                results["solver_result"] = pwn_result
                all_flags.extend(pwn_result.get("flags_found", []))

        results["flags_found"] = list(set(all_flags))
        results["success"] = True
        results["message"] = f"自动检测求解完成，类型: {results.get('detected_type', 'unknown')}，发现Flag: {len(results['flags_found'])}个"
        return results

    # ==================== 逆向工程工具 ====================

    @mcp.tool()
    def reverse_tool_check() -> Dict[str, Any]:
        """
        检查可用的逆向分析工具 - 检测本机逆向工程工具

        Returns:
            可用的逆向分析工具状态
        """
        available_tools = {}

        # 检查Radare2
        try:
            result = subprocess.run(["r2", "-version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                available_tools["radare2"] = {
                    "available": True,
                    "version": result.stdout.strip()
                }
            else:
                available_tools["radare2"] = {"available": False}
        except:
            available_tools["radare2"] = {"available": False}

        # 检查Ghidra
        try:
            ghidra_paths = [
                "/usr/bin/ghidra",
                "/opt/ghidra/support/analyzeHeadless",
                "/usr/share/ghidra/support/analyzeHeadless"
            ]
            ghidra_available = any(os.path.exists(path) for path in ghidra_paths)
            available_tools["ghidra"] = {"available": ghidra_available}
        except:
            available_tools["ghidra"] = {"available": False}

        # 检查checksec
        try:
            result = subprocess.run(["checksec", "--version"], capture_output=True, text=True, timeout=5)
            available_tools["checksec"] = {"available": result.returncode == 0}
        except:
            available_tools["checksec"] = {"available": False}

        return {
            "success": True,
            "available_tools": available_tools,
            "recommendation": "radare2" if available_tools.get("radare2", {}).get("available")
                           else "ghidra" if available_tools.get("ghidra", {}).get("available")
                           else "请安装逆向分析工具 (apt install radare2)"
        }

    @mcp.tool()
    def radare2_analyze_binary(binary_path: str) -> Dict[str, Any]:
        """
        使用Radare2分析二进制文件 - 开源逆向分析工具

        Args:
            binary_path: 二进制文件路径

        Returns:
            Radare2分析结果，包含函数、字符串、导入导出等信息
        """
        import json

        results = {
            "binary_path": binary_path,
            "functions": [],
            "strings": [],
            "imports": []
        }

        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}

        # 使用executor调用r2（已在_build_tool_command中配置非交互模式）
        # 基础信息分析
        info_result = _run_tool("r2", {"target": binary_path, "additional_args": "ij"})
        info_output = _get_output(info_result)
        try:
            results["binary_info"] = json.loads(info_output)
        except:
            results["binary_info"] = {"raw": info_output[:2000]}

        # 函数列表
        func_result = _run_tool("execute_command", {
            "command": f"r2 -q -A -e scr.color=0 -c 'afl' '{binary_path}'"
        })
        results["functions_raw"] = _get_output(func_result)[:5000]

        # 字符串提取
        str_result = _run_tool("r2", {"target": binary_path, "additional_args": "izz"})
        results["strings_raw"] = _get_output(str_result)[:5000]

        # 导入函数
        imp_result = _run_tool("r2", {"target": binary_path, "additional_args": "ii"})
        results["imports_raw"] = _get_output(imp_result)[:3000]

        results["success"] = True
        results["tool"] = "radare2"
        return results

    @mcp.tool()
    def ghidra_analyze_binary(binary_path: str) -> Dict[str, Any]:
        """
        使用Ghidra分析二进制文件 - NSA开源逆向分析工具

        Args:
            binary_path: 二进制文件路径

        Returns:
            Ghidra分析结果
        """
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}

        try:
            import tempfile

            with tempfile.TemporaryDirectory() as temp_dir:
                project_dir = os.path.join(temp_dir, "ghidra_project")

                ghidra_paths = [
                    "/opt/ghidra/support/analyzeHeadless",
                    "/usr/share/ghidra/support/analyzeHeadless"
                ]

                ghidra_cmd = None
                for path in ghidra_paths:
                    if os.path.exists(path):
                        ghidra_cmd = path
                        break

                if not ghidra_cmd:
                    return {
                        "success": False,
                        "error": "Ghidra未找到",
                        "suggestion": "请安装Ghidra: apt install ghidra"
                    }

                cmd = [
                    ghidra_cmd,
                    project_dir,
                    "temp_project",
                    "-import", binary_path,
                    "-postScript", "ListFunctionsScript.java"
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                return {
                    "success": result.returncode == 0,
                    "tool": "ghidra",
                    "binary_path": binary_path,
                    "output": result.stdout[:10000],
                    "error": result.stderr[:3000] if result.returncode != 0 else None
                }

        except Exception as e:
            return {"success": False, "error": f"Ghidra分析失败: {str(e)}"}

    @mcp.tool()
    def auto_reverse_analyze(binary_path: str) -> Dict[str, Any]:
        """
        自动选择可用工具进行逆向分析 - 智能工具选择

        Args:
            binary_path: 二进制文件路径

        Returns:
            自动分析结果，使用最佳可用工具
        """
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}

        tool_status = reverse_tool_check()
        available = tool_status.get("available_tools", {})

        results = {
            "binary_path": binary_path,
            "attempted_tools": [],
            "successful_analysis": None,
            "all_results": {}
        }

        # 优先级：Radare2 > Ghidra
        if available.get("radare2", {}).get("available"):
            try:
                r2_result = radare2_analyze_binary(binary_path)
                results["attempted_tools"].append("radare2")
                results["all_results"]["radare2"] = r2_result
                if r2_result.get("success"):
                    results["successful_analysis"] = "radare2"
                    results["primary_result"] = r2_result
                    results["success"] = True
                    return results
            except Exception as e:
                logger.warning(f"Radare2 分析失败: {e}")

        if available.get("ghidra", {}).get("available"):
            try:
                ghidra_result = ghidra_analyze_binary(binary_path)
                results["attempted_tools"].append("ghidra")
                results["all_results"]["ghidra"] = ghidra_result
                if ghidra_result.get("success"):
                    results["successful_analysis"] = "ghidra"
                    results["primary_result"] = ghidra_result
                    results["success"] = True
                    return results
            except Exception as e:
                logger.warning(f"Ghidra 分析失败: {e}")

        # 如果专用工具都不可用，使用基础命令
        results["attempted_tools"].append("basic_tools")
        basic_results = {}

        file_result = _run_tool("execute_command", {"command": f"file {binary_path}"})
        basic_results["file_type"] = _get_output(file_result)

        strings_result = _run_tool("execute_command", {"command": f"strings {binary_path} | head -200"})
        basic_results["strings"] = _get_output(strings_result)[:5000]

        objdump_result = _run_tool("execute_command", {"command": f"objdump -d {binary_path} | head -300"})
        basic_results["disassembly"] = _get_output(objdump_result)[:5000]

        results["all_results"]["basic_tools"] = basic_results
        results["successful_analysis"] = "basic_tools"
        results["primary_result"] = basic_results
        results["success"] = True
        return results

    @mcp.tool()
    def ctf_reverse_solver(binary_path: str, challenge_hints: List[str] = None) -> Dict[str, Any]:
        """
        CTF逆向题目自动求解器 - 使用radare2进行综合逆向分析

        Args:
            binary_path: 题目二进制文件路径
            challenge_hints: 题目提示信息列表（可选）

        Returns:
            逆向分析结果和可能的Flag
        """
        if not challenge_hints:
            challenge_hints = []

        results = {
            "binary_path": binary_path,
            "challenge_hints": challenge_hints,
            "analysis_steps": {},
            "findings": [],
            "potential_flags": []
        }

        if not os.path.exists(binary_path):
            results["success"] = False
            results["error"] = f"文件不存在: {binary_path}"
            return results

        all_flags = []

        try:
            # Step 1: 文件类型和保护检测
            logger.info("Step 1: Binary type and protection analysis")
            file_result = _run_tool("execute_command", {"command": f"file {binary_path}"})
            results["analysis_steps"]["1_file_type"] = _get_output(file_result)

            checksec_result = _run_tool("execute_command", {
                "command": f"checksec --file={binary_path} 2>/dev/null || true"
            })
            results["analysis_steps"]["1_checksec"] = _get_output(checksec_result)

            # Step 2: Strings分析（最快找Flag的方式）
            logger.info("Step 2: Strings analysis for flags and keys")
            strings_result = _run_tool("execute_command", {"command": f"strings {binary_path}"})
            strings_output = _get_output(strings_result)
            results["analysis_steps"]["2_strings_count"] = len(strings_output.splitlines())
            all_flags.extend(_detect_flags(strings_output))

            # 搜索关键字符串
            key_strings = []
            for line in strings_output.splitlines():
                line_lower = line.strip().lower()
                if any(kw in line_lower for kw in ["flag", "key", "password", "secret", "correct", "win", "congratul"]):
                    key_strings.append(line.strip())
            results["analysis_steps"]["2_key_strings"] = key_strings[:50]

            # Step 3: Radare2 逆向分析
            logger.info("Step 3: Radare2 reverse analysis")
            r2_result = radare2_analyze_binary(binary_path)
            results["analysis_steps"]["3_radare2"] = r2_result
            # 从radare2输出中提取flag
            for key in ["strings_raw", "functions_raw", "imports_raw"]:
                if key in r2_result:
                    all_flags.extend(_detect_flags(str(r2_result[key])))

            # Step 4: 危险函数检测
            logger.info("Step 4: Dangerous function detection")
            dangerous_funcs = ["gets", "strcpy", "strcat", "sprintf", "scanf", "system", "execve",
                             "popen", "strcmp", "strncmp"]
            found_funcs = []
            for func in dangerous_funcs:
                if func in strings_output:
                    found_funcs.append(func)
            results["analysis_steps"]["4_dangerous_functions"] = found_funcs
            if found_funcs:
                results["findings"].append({
                    "type": "dangerous_functions",
                    "functions": found_funcs,
                    "implication": "可能存在缓冲区溢出或命令注入漏洞"
                })

            # Step 5: 尝试运行（如果是可执行文件且安全）
            logger.info("Step 5: Static analysis complete")

            results["potential_flags"] = list(set(all_flags))
            results["success"] = True
            results["summary"] = {
                "key_strings_found": len(key_strings),
                "dangerous_functions": len(found_funcs),
                "potential_flags_found": len(results["potential_flags"])
            }
            results["message"] = f"逆向分析完成，发现{len(results['potential_flags'])}个潜在Flag"

            return results

        except Exception as e:
            logger.error(f"CTF逆向求解器错误: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            results["potential_flags"] = list(set(all_flags))
            return results

    @mcp.tool()
    def ctf_crypto_reverser(binary_path: str, encrypted_data: str = "") -> Dict[str, Any]:
        """
        CTF密码学逆向专用工具 - 分析二进制中的密码学算法

        Args:
            binary_path: 包含加密算法的二进制文件
            encrypted_data: 加密的数据（可选）

        Returns:
            密码学逆向分析结果，包含算法识别和解密尝试
        """
        results = {
            "binary_path": binary_path,
            "encrypted_data": encrypted_data,
            "crypto_findings": [],
            "decryption_attempts": [],
            "algorithm_analysis": {}
        }

        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}

        all_flags = []

        try:
            # Step 1: 字符串中搜索加密相关关键词
            logger.info("Step 1: Searching for crypto-related strings")
            strings_result = _run_tool("execute_command", {"command": f"strings {binary_path}"})
            strings_output = _get_output(strings_result)

            crypto_keywords = ["aes", "des", "rsa", "md5", "sha", "encrypt", "decrypt", "cipher",
                             "base64", "xor", "key", "iv", "salt", "hmac", "rc4", "blowfish"]
            found_crypto = []
            for line in strings_output.splitlines():
                line_lower = line.strip().lower()
                for kw in crypto_keywords:
                    if kw in line_lower:
                        found_crypto.append({"keyword": kw, "context": line.strip()[:100]})
                        break
            results["crypto_findings"] = found_crypto[:50]
            all_flags.extend(_detect_flags(strings_output))

            # Step 2: Radare2分析 - 搜索XOR和位操作
            logger.info("Step 2: Radare2 crypto pattern analysis")
            r2_result = _run_tool("execute_command", {
                "command": f"r2 -q -A -e scr.color=0 -c 'afl~encrypt,decrypt,cipher,hash,xor,crypt,key' '{binary_path}'"
            })
            results["algorithm_analysis"]["crypto_functions"] = _get_output(r2_result)[:3000]

            # Step 3: 搜索硬编码密钥和常量
            logger.info("Step 3: Searching for hardcoded keys and constants")
            # 搜索可能的AES S-box
            r2_sbox = _run_tool("execute_command", {
                "command": f"r2 -q -e scr.color=0 -c '/x 637c777bf26b6fc5' '{binary_path}'"
            })
            sbox_output = _get_output(r2_sbox)
            if sbox_output.strip():
                results["algorithm_analysis"]["aes_sbox_found"] = True
                results["crypto_findings"].append({"keyword": "AES S-box", "context": "AES加密算法检测到"})

            # Step 4: 如果提供了加密数据，尝试解密
            if encrypted_data:
                logger.info("Step 4: Attempting decryption")
                # Base64解码尝试
                b64_result = _run_tool("execute_command", {
                    "command": f"echo '{encrypted_data}' | base64 -d 2>/dev/null || true"
                })
                b64_output = _get_output(b64_result)
                if b64_output:
                    results["decryption_attempts"].append({
                        "method": "base64_decode",
                        "result": b64_output[:500]
                    })
                    all_flags.extend(_detect_flags(b64_output))

            results["potential_flags"] = list(set(all_flags))
            results["success"] = True
            results["message"] = f"密码学逆向分析完成，发现{len(found_crypto)}个加密相关特征"
            return results

        except Exception as e:
            logger.error(f"密码学逆向分析错误: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            return results
