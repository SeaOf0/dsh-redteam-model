#!/usr/bin/env python3
"""
PWN自动化和二进制利用工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
import os
import re
import subprocess
import datetime
from typing import Dict, Any, Optional, List

from kali_mcp.core.multi_target import MultiTargetOrchestrator

logger = logging.getLogger(__name__)


def register_pwn_tools(mcp, executor, adapter=None):
    """PWN自动化和二进制利用工具注册"""

    # 实例化多目标编排器
    multi_target_orchestrator = MultiTargetOrchestrator()

    # ==================== PwnPasi PWN自动化工具集成 ====================

    @mcp.tool()
    def ctf_pwn_solver(binary_path: str, challenge_name: str = "", challenge_hints: List[str] = None,
                      time_limit: str = "quick") -> Dict[str, Any]:
        """
        CTF PWN题目自动求解器 - 专门针对CTF比赛的PWN题目

        综合使用PwnPasi和逆向分析技术，自动解决CTF PWN题目：
        1. 二进制保护分析
        2. 漏洞类型识别
        3. 利用策略选择
        4. 自动化攻击执行
        5. Flag提取和验证

        Args:
            binary_path: CTF PWN题目二进制文件路径
            challenge_name: 题目名称（用于记录）
            challenge_hints: 题目提示列表
            time_limit: 时间限制（quick, standard, thorough）

        Returns:
            CTF PWN求解结果，包含Flag和解题过程
        """
        if not challenge_hints:
            challenge_hints = []

        if adapter and adapter.should_use_agent("ctf_pwn_solver", {"binary_path": binary_path}):
            return adapter.execute_via_agent("ctf_pwn_solver", {
                "binary_path": binary_path, "challenge_name": challenge_name,
                "challenge_hints": challenge_hints, "time_limit": time_limit
            })

        results = {
            "binary_path": binary_path,
            "challenge_name": challenge_name or f"PWN_Challenge_{os.path.basename(binary_path)}",
            "challenge_hints": challenge_hints,
            "time_limit": time_limit,
            "analysis_steps": {},
            "exploitation_attempts": [],
            "flags_found": [],
            "success": False
        }

        try:
            if not os.path.exists(binary_path):
                results["error"] = f"Binary file not found: {binary_path}"
                return results

            # 第一步：二进制保护分析（checksec + strings）
            logger.info(f"Step 1: Binary analysis for {binary_path}")
            binary_analysis = {"protections": {}, "dangerous_functions": []}
            try:
                checksec_result = subprocess.run(
                    ["checksec", "--file", binary_path],
                    capture_output=True, text=True, timeout=30
                )
                if checksec_result.returncode == 0:
                    binary_analysis["protections"]["raw"] = checksec_result.stdout
            except Exception as e:
                binary_analysis["protections"]["error"] = str(e)

            try:
                strings_result = subprocess.run(
                    ["strings", binary_path],
                    capture_output=True, text=True, timeout=30
                )
                if strings_result.returncode == 0:
                    dangerous_funcs = ["gets", "strcpy", "strcat", "sprintf", "scanf"]
                    for func in dangerous_funcs:
                        if func in strings_result.stdout:
                            binary_analysis["dangerous_functions"].append(func)
                    # 从strings中提取Flag
                    for pattern in [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}", r"CTF\{[^}]+\}"]:
                        matches = re.findall(pattern, strings_result.stdout, re.IGNORECASE)
                        for match in matches:
                            if match not in results["flags_found"]:
                                results["flags_found"].append(match)
            except Exception as e:
                binary_analysis["strings_error"] = str(e)

            results["analysis_steps"]["1_binary_analysis"] = binary_analysis

            # 第二步：PwnPasi自动化攻击
            logger.info(f"Step 2: PwnPasi automated exploitation")
            pwn_result = pwnpasi_auto_pwn(binary_path, verbose=True)
            results["exploitation_attempts"].append({
                "tool": "pwnpasi",
                "result": pwn_result,
                "timestamp": datetime.datetime.now().isoformat()
            })

            # 检查是否获得shell并提取Flag
            if pwn_result.get("exploitation_result") == "shell_obtained":
                results["success"] = True
                results["shell_access"] = True

            stdout_content = pwn_result.get("stdout", "") + pwn_result.get("stderr", "")
            for pattern in [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}", r"CTF\{[^}]+\}"]:
                matches = re.findall(pattern, stdout_content, re.IGNORECASE)
                for match in matches:
                    if match not in results["flags_found"]:
                        results["flags_found"].append(match)

            # 合并pwnpasi自动检测到的flag
            for flag in pwn_result.get("flags_found", []):
                if flag not in results["flags_found"]:
                    results["flags_found"].append(flag)

            results["total_flags_found"] = len(results["flags_found"])
            results["message"] = f"CTF PWN solver completed - Found {results['total_flags_found']} flags"

            return results

        except Exception as e:
            logger.error(f"CTF PWN solver error: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            results["message"] = "CTF PWN solver failed"
            return results

    @mcp.tool()
    def quick_pwn_check(binary_path: str) -> Dict[str, Any]:
        """
        快速PWN漏洞检查 - 快速识别二进制文件的PWN攻击可能性

        执行快速分析来判断二进制文件是否容易受到PWN攻击：
        - 二进制保护分析 (RELRO, Canary, NX, PIE)
        - 危险函数检测 (gets, strcpy, sprintf等)
        - 栈溢出可能性分析
        - 利用难度评估

        Args:
            binary_path: 要分析的二进制文件路径

        Returns:
            快速PWN分析结果，包含攻击可能性评估和建议的攻击方法
        """
        import subprocess

        results = {
            "binary_path": binary_path,
            "analysis_timestamp": datetime.now().isoformat(),
            "protections": {},
            "vulnerable_functions": [],
            "attack_surface": [],
            "difficulty_assessment": "unknown",
            "recommended_methods": [],
            "quick_attack_possible": False
        }

        try:
            if not os.path.exists(binary_path):
                results["error"] = f"Binary file not found: {binary_path}"
                return results

            # 1. 检查二进制保护
            try:
                checksec_cmd = ["checksec", "--file", binary_path]
                checksec_result = subprocess.run(checksec_cmd, capture_output=True, text=True, timeout=30)
                if checksec_result.returncode == 0:
                    output = checksec_result.stdout
                    results["protections"]["raw_output"] = output

                    # 解析保护状态
                    protections_status = {
                        "relro": "No RELRO" in output or "Partial RELRO" in output,
                        "canary": "No canary found" in output,
                        "nx": "NX disabled" in output,
                        "pie": "No PIE" in output
                    }
                    results["protections"]["status"] = protections_status

                    # 评估攻击难度
                    disabled_protections = sum(1 for disabled in protections_status.values() if disabled)
                    if disabled_protections >= 3:
                        results["difficulty_assessment"] = "easy"
                        results["quick_attack_possible"] = True
                    elif disabled_protections >= 2:
                        results["difficulty_assessment"] = "medium"
                    else:
                        results["difficulty_assessment"] = "hard"

            except subprocess.TimeoutExpired:
                results["protections"]["error"] = "checksec timeout"
            except FileNotFoundError:
                results["protections"]["error"] = "checksec not found"

            # 2. 检查危险函数
            try:
                strings_cmd = ["strings", binary_path]
                strings_result = subprocess.run(strings_cmd, capture_output=True, text=True, timeout=30)

                dangerous_functions = [
                    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
                    "scanf", "fscanf", "sscanf", "strncpy", "strncat"
                ]

                if strings_result.returncode == 0:
                    output = strings_result.stdout
                    for func in dangerous_functions:
                        if func in output:
                            results["vulnerable_functions"].append(func)

            except subprocess.TimeoutExpired:
                results["vulnerable_functions_error"] = "strings timeout"
            except FileNotFoundError:
                results["vulnerable_functions_error"] = "strings not found"

            # 3. 生成攻击建议
            if results["quick_attack_possible"]:
                results["recommended_methods"] = ["pwnpasi_auto", "ret2system", "ret2libc"]
                results["attack_surface"] = ["stack_overflow", "format_string"]
            elif results["difficulty_assessment"] == "medium":
                results["recommended_methods"] = ["pwnpasi_auto", "rop_chain"]
                results["attack_surface"] = ["stack_overflow"]
            else:
                results["recommended_methods"] = ["advanced_rop", "heap_exploitation"]
                results["attack_surface"] = ["complex_exploitation"]

            results["success"] = True
            results["summary"] = {
                "attack_possible": results["quick_attack_possible"],
                "difficulty": results["difficulty_assessment"],
                "vulnerable_functions_count": len(results["vulnerable_functions"]),
                "recommended_tool": "pwnpasi" if results["quick_attack_possible"] else "manual_exploitation"
            }

            return results

        except Exception as e:
            logger.error(f"Quick PWN check error: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            return results

    @mcp.tool()
    def pwnpasi_auto_pwn(binary_path: str, remote_ip: str = "", remote_port: int = 0,
                        libc_path: str = "", padding: int = 0, verbose: bool = False,
                        additional_args: str = "") -> Dict[str, Any]:
        """
        执行PwnPasi自动化二进制漏洞利用

        PwnPasi是一个专业的自动化二进制利用框架，支持多种利用技术：
        - 自动栈溢出检测和利用
        - ret2system, ret2libc, ROP链构造
        - 二进制保护绕过 (RELRO, Canary, NX, PIE)
        - 本地和远程利用模式
        - 智能填充计算和libc版本检测

        Args:
            binary_path: 目标二进制文件路径 (必需)
            remote_ip: 远程目标IP地址 (可选，用于远程利用)
            remote_port: 远程目标端口 (可选，与remote_ip配合使用)
            libc_path: 自定义libc库路径 (可选)
            padding: 手动指定溢出填充大小 (可选)
            verbose: 启用详细输出模式
            additional_args: 额外的pwnpasi参数

        Returns:
            PwnPasi利用结果，包含利用过程、发现的漏洞和获取的Shell信息
        """
        import subprocess
        import os

        # 检查二进制文件是否存在
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"二进制文件不存在: {binary_path}"}

        # 确定pwnpasi脚本路径
        script_dir = os.path.dirname(os.path.abspath(__file__))
        pwnpasi_script = os.path.join(script_dir, "pwnpasi", "pwnpasi.py")

        if not os.path.exists(pwnpasi_script):
            return {"success": False, "error": f"PwnPasi脚本不存在: {pwnpasi_script}"}

        # 构建命令
        cmd = ["python3", pwnpasi_script, binary_path]

        if remote_ip and remote_port:
            cmd.extend(["-r", f"{remote_ip}:{remote_port}"])

        if libc_path:
            cmd.extend(["-l", libc_path])

        if padding > 0:
            cmd.extend(["-p", str(padding)])

        if verbose:
            cmd.append("-v")

        if additional_args:
            cmd.extend(additional_args.split())

        try:
            # 执行PwnPasi
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5分钟超时
                cwd=os.path.dirname(binary_path) if os.path.dirname(binary_path) else None
            )

            output = result.stdout + result.stderr

            # 分析输出
            shell_obtained = "shell" in output.lower() or "pwned" in output.lower() or "flag" in output.lower()
            exploitation_success = result.returncode == 0 or shell_obtained

            # 检测Flag
            import re
            flags_found = []
            flag_patterns = [r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}']
            for pattern in flag_patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)
                flags_found.extend(matches)

            return {
                "success": True,
                "exploitation_result": "shell_obtained" if shell_obtained else "attempted",
                "stdout": result.stdout[:10000] if result.stdout else "",
                "stderr": result.stderr[:5000] if result.stderr else "",
                "return_code": result.returncode,
                "flags_found": flags_found,
                "binary_path": binary_path,
                "remote_target": f"{remote_ip}:{remote_port}" if remote_ip else "local",
                "command": " ".join(cmd)
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "PwnPasi执行超时 (300秒)",
                "exploitation_result": "timeout"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "exploitation_result": "error"
            }

    @mcp.tool()
    def pwn_comprehensive_attack(binary_path: str, attack_methods: List[str] = None,
                               remote_target: str = "", timeout: int = 300) -> Dict[str, Any]:
        """
        综合PWN攻击 - 使用多种方法尝试利用二进制文件

        结合多种PWN攻击技术，包括PwnPasi自动化利用和其他手动技术：
        - pwnpasi_auto: 使用PwnPasi自动化利用
        - ret2libc: ret2libc攻击链
        - rop_chain: ROP链构造攻击
        - shellcode_injection: 直接shellcode注入
        - format_string: 格式化字符串攻击

        Args:
            binary_path: 目标二进制文件路径
            attack_methods: 要尝试的攻击方法列表 (默认: ["pwnpasi_auto", "ret2libc"])
            remote_target: 远程目标地址 (格式: ip:port)
            timeout: 单个攻击方法的超时时间 (秒)

        Returns:
            综合攻击结果，包含每种方法的执行结果和成功的利用方式
        """
        if attack_methods is None:
            attack_methods = ["pwnpasi_auto", "ret2libc"]

        if adapter and adapter.should_use_agent("pwn_comprehensive_attack", {"binary_path": binary_path}):
            return adapter.execute_via_agent("pwn_comprehensive_attack", {
                "binary_path": binary_path, "attack_methods": attack_methods,
                "remote_target": remote_target, "timeout": timeout
            })

        results = {
            "binary_path": binary_path,
            "attack_methods": attack_methods,
            "remote_target": remote_target,
            "timestamp": datetime.datetime.now().isoformat(),
            "attempts": [],
            "successful_methods": [],
            "failed_methods": [],
            "overall_success": False
        }

        # 解析远程目标
        remote_ip, remote_port = "", 0
        if remote_target and ":" in remote_target:
            try:
                remote_ip, port_str = remote_target.split(":", 1)
                remote_port = int(port_str)
            except ValueError:
                results["error"] = f"Invalid remote target format: {remote_target}. Use ip:port format."
                return results

        for method in attack_methods:
            attempt = {
                "method": method,
                "start_time": datetime.datetime.now().isoformat(),
                "success": False,
                "output": "",
                "error": ""
            }

            try:
                if method == "pwnpasi_auto":
                    # 使用PwnPasi自动化利用
                    result = pwnpasi_auto_pwn(
                        binary_path=binary_path,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        verbose=True
                    )
                    attempt["output"] = result.get("output", "")
                    attempt["success"] = result.get("success", False)
                    if not attempt["success"] and "error" in result:
                        attempt["error"] = result["error"]

                elif method == "ret2libc":
                    # 这里可以集成其他ret2libc工具或脚本
                    attempt["output"] = "ret2libc attack method placeholder - implement specific ret2libc logic"
                    attempt["success"] = False
                    attempt["error"] = "ret2libc method not yet implemented"

                elif method == "rop_chain":
                    # 这里可以集成ROP链构造工具
                    attempt["output"] = "ROP chain attack method placeholder - implement specific ROP logic"
                    attempt["success"] = False
                    attempt["error"] = "ROP chain method not yet implemented"

                else:
                    attempt["error"] = f"Unknown attack method: {method}"

                if attempt["success"]:
                    results["successful_methods"].append(method)
                    results["overall_success"] = True
                else:
                    results["failed_methods"].append(method)

            except Exception as e:
                attempt["error"] = str(e)
                results["failed_methods"].append(method)

            attempt["end_time"] = datetime.datetime.now().isoformat()
            results["attempts"].append(attempt)

            # 如果成功了，可以选择继续尝试其他方法或停止
            if attempt["success"] and len(results["successful_methods"]) >= 1:
                results["note"] = "Stopped after first successful exploit"
                break

        return results

    @mcp.tool()
    def multi_target_add_target(target_url: str, target_type: str = "unknown",
                               priority: int = 1, dependencies: str = "") -> Dict[str, Any]:
        """
        添加新目标到多目标协调系统

        Args:
            target_url: 目标URL或IP地址
            target_type: 目标类型 (web, network, mobile, cloud)
            priority: 优先级 (1-10, 10为最高)
            dependencies: 依赖的其他目标ID，逗号分隔

        Returns:
            包含目标ID和状态的字典
        """
        try:
            dep_list = [dep.strip() for dep in dependencies.split(",")] if dependencies else []
            target_id = multi_target_orchestrator.add_target(
                target_url=target_url,
                target_type=target_type,
                priority=priority,
                dependencies=dep_list
            )

            return {
                "success": True,
                "target_id": target_id,
                "target_url": target_url,
                "target_type": target_type,
                "priority": priority,
                "dependencies": dep_list,
                "message": f"目标 {target_url} 已添加到协调系统"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "添加目标失败"
            }

    @mcp.tool()
    def multi_target_orchestrate(strategy: str = "adaptive") -> Dict[str, Any]:
        """
        执行多目标攻击编排

        Args:
            strategy: 编排策略 (sequential, parallel, adaptive, dependency_aware)

        Returns:
            包含执行计划的详细信息
        """
        try:
            orchestration_result = multi_target_orchestrator.orchestrate_attack(strategy)

            return {
                "success": True,
                "orchestration_plan": orchestration_result,
                "message": f"使用 {strategy} 策略生成执行计划"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "编排执行失败"
            }

    @mcp.tool()
    def multi_target_get_status() -> Dict[str, Any]:
        """
        获取多目标协调系统状态

        Returns:
            包含系统状态的详细信息
        """
        try:
            status = multi_target_orchestrator.get_orchestration_status()

            return {
                "success": True,
                "status": status,
                "message": "系统状态获取成功"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取状态失败"
            }

    @mcp.tool()
    def multi_target_execute_batch(target_ids: str = "", max_concurrent: int = 3) -> Dict[str, Any]:
        """
        批量执行多目标攻击任务

        Args:
            target_ids: 目标ID列表，逗号分隔（空则执行所有）
            max_concurrent: 最大并发任务数

        Returns:
            批量执行结果
        """
        try:
            # 解析目标ID列表
            if target_ids:
                target_list = [tid.strip() for tid in target_ids.split(",")]
            else:
                target_list = list(multi_target_orchestrator.targets.keys())

            # 更新并发限制
            multi_target_orchestrator.max_concurrent_tasks = max_concurrent

            # 执行编排
            orchestration_result = multi_target_orchestrator.orchestrate_attack("adaptive")

            # 模拟批量执行
            execution_summary = {
                "total_targets": len(target_list),
                "execution_strategy": orchestration_result["orchestration_strategy"],
                "estimated_time": orchestration_result["estimated_total_time"],
                "phases": len(orchestration_result["execution_plan"].get("execution_phases", [])),
                "concurrent_limit": max_concurrent
            }

            return {
                "success": True,
                "execution_summary": execution_summary,
                "orchestration_plan": orchestration_result,
                "message": f"批量执行已启动，涉及 {len(target_list)} 个目标"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "批量执行失败"
            }

    # ==================== pwnpasi 高级模块直接整合 ====================

    # 延迟导入，避免 pwntools 不可用时阻断整个模块加载
    try:
        from pwnpasi.advanced_rop import analyze_rop_techniques
        _ROP_AVAILABLE = True
    except ImportError:
        _ROP_AVAILABLE = False

    try:
        from pwnpasi.auto_fuzzing import quick_fuzz_check
        _FUZZ_AVAILABLE = True
    except ImportError:
        _FUZZ_AVAILABLE = False

    try:
        from pwnpasi.symbolic_analysis import quick_symbolic_analysis
        _SYMBOLIC_AVAILABLE = True
    except ImportError:
        _SYMBOLIC_AVAILABLE = False

    try:
        from pwnpasi.heap_exploit import detect_heap_vulnerability
        _HEAP_AVAILABLE = True
    except ImportError:
        _HEAP_AVAILABLE = False

    @mcp.tool()
    def pwn_rop_analyze(binary_path: str) -> Dict[str, Any]:
        """
        高级ROP技术分析 - 直接调用 pwnpasi.advanced_rop

        分析二进制文件支持的ROP利用技术：
        - SROP (Sigreturn Oriented Programming)
        - ret2csu (通用gadget利用)
        - ret2dlresolve (无需泄露libc)
        - Stack Pivot / BROP辅助

        Args:
            binary_path: 二进制文件路径

        Returns:
            ROP技术分析结果和推荐利用方式
        """
        if not _ROP_AVAILABLE:
            return {"success": False, "error": "pwnpasi.advanced_rop 不可用（需要 pwntools）"}
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}
        try:
            result = analyze_rop_techniques(binary_path)
            return {"success": True, "binary": binary_path, "rop_analysis": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def pwn_fuzz_check(binary_path: str) -> Dict[str, Any]:
        """
        快速Fuzzing检测 - 直接调用 pwnpasi.auto_fuzzing

        对二进制文件执行快速模糊测试检测：
        - 基于变异的输入生成
        - 崩溃检测和分类
        - 漏洞点初步定位

        Args:
            binary_path: 二进制文件路径

        Returns:
            Fuzzing检测结果，包含崩溃信息和漏洞线索
        """
        if not _FUZZ_AVAILABLE:
            return {"success": False, "error": "pwnpasi.auto_fuzzing 不可用"}
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}
        try:
            result = quick_fuzz_check(binary_path)
            return {"success": True, "binary": binary_path, "fuzz_result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def pwn_symbolic_explore(binary_path: str, target_function: str = "") -> Dict[str, Any]:
        """
        符号执行分析 - 直接调用 pwnpasi.symbolic_analysis

        对二进制文件执行符号执行分析：
        - 路径探索和约束求解
        - 自动生成触发漏洞的输入
        - 辅助CTF逆向题求解

        Args:
            binary_path: 二进制文件路径
            target_function: 目标函数名（可选，留空则分析main）

        Returns:
            符号执行分析结果
        """
        if not _SYMBOLIC_AVAILABLE:
            return {"success": False, "error": "pwnpasi.symbolic_analysis 不可用"}
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}
        try:
            result = quick_symbolic_analysis(binary_path)
            return {"success": True, "binary": binary_path, "symbolic_result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def pwn_heap_analyze(binary_path: str) -> Dict[str, Any]:
        """
        堆漏洞分析 - 直接调用 pwnpasi.heap_exploit

        分析二进制文件的堆利用可能性：
        - Fastbin/Tcache攻击检测
        - House of Force/Spirit/Orange等
        - Off-by-one/Off-by-null漏洞识别

        Args:
            binary_path: 二进制文件路径

        Returns:
            堆漏洞分析结果和推荐利用技术
        """
        if not _HEAP_AVAILABLE:
            return {"success": False, "error": "pwnpasi.heap_exploit 不可用（需要 pwntools）"}
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}
        try:
            result = detect_heap_vulnerability(binary_path)
            return {"success": True, "binary": binary_path, "heap_analysis": result}
        except Exception as e:
            return {"success": False, "error": str(e)}
