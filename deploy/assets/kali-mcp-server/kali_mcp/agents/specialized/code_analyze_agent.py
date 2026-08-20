#!/usr/bin/env python3
"""
CodeAnalyzeAgent - 代码分析智能体 (v5.0)

负责源代码安全分析（白盒审计核心）：
- 目录结构扫描
- 危险模式正则搜索 (SQL注入/XSS/RCE/LFI/SSRF等)
- 候选漏洞自动提交到VulnManager
- 与现有CodeAuditAgent的静态分析工具集成

集成工具：4个自有 + 4个CodeAuditAgent工具
"""

import os
import re
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from kali_mcp.agents.base_agent_v2 import BaseAgentV2, AgentCapability
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.core.result_aggregator import (
    AgentResult, Finding, ResultType, ResultSeverity
)

logger = logging.getLogger(__name__)


class CodeAnalyzeAgent(BaseAgentV2):
    """
    代码分析智能体 (白盒审计核心)

    能力：
    - scan_source_tree: 扫描源码目录结构
    - search_dangerous_patterns: 搜索危险代码模式
    - analyze_file: 深度分析单个文件
    - whitebox_audit: 完整白盒审计流程
    """

    # 危险代码模式库 (按漏洞类型分类)
    VULN_PATTERNS = {
        "sqli": [
            (r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*["\']', "SQL字符串拼接"),
            (r'(?:query|execute)\s*\(\s*["\'].*\%s', "SQL格式化字符串"),
            (r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{', "SQL f-string拼接"),
            (r'\.format\(.*(?:SELECT|INSERT|UPDATE|DELETE)', "SQL .format()拼接"),
            (r'cursor\.execute\s*\(\s*["\'].*\+', "cursor.execute SQL拼接"),
            (r'\$_(?:GET|POST|REQUEST)\[.*\].*(?:mysql_query|mysqli_query)', "PHP SQL注入"),
        ],
        "xss": [
            (r'innerHTML\s*=', "innerHTML赋值"),
            (r'document\.write\s*\(', "document.write调用"),
            (r'\.html\s*\(\s*[^)]*\$', "jQuery .html()动态内容"),
            (r'echo\s+\$_(?:GET|POST|REQUEST)', "PHP直接输出用户输入"),
            (r'render_template_string\s*\(', "Flask模板注入"),
            (r'\{\{.*\|safe\}\}', "Jinja2 safe过滤器"),
        ],
        "rce": [
            (r'eval\s*\(', "eval()调用"),
            (r'exec\s*\(', "exec()调用"),
            (r'os\.system\s*\(', "os.system()调用"),
            (r'os\.popen\s*\(', "os.popen()调用"),
            (r'subprocess\.call.*shell\s*=\s*True', "subprocess shell=True"),
            (r'Runtime\.getRuntime\(\)\.exec', "Java Runtime.exec"),
            (r'ProcessBuilder', "Java ProcessBuilder"),
            (r'system\s*\(\s*\$', "PHP system()用户输入"),
            (r'passthru\s*\(', "PHP passthru()"),
            (r'shell_exec\s*\(', "PHP shell_exec()"),
        ],
        "lfi": [
            (r'include\s*\(\s*\$', "PHP include用户输入"),
            (r'require\s*\(\s*\$', "PHP require用户输入"),
            (r'file_get_contents\s*\(\s*\$', "PHP file_get_contents用户输入"),
            (r'open\s*\(.*request\.(args|form|values)', "Python open()用户输入"),
            (r'readFile\s*\(.*req\.(params|query|body)', "Node.js readFile用户输入"),
        ],
        "ssrf": [
            (r'requests\.get\s*\(.*request\.(args|form)', "Python requests用户URL"),
            (r'urllib\.request\.urlopen\s*\(.*request', "Python urllib用户URL"),
            (r'file_get_contents\s*\(\s*\$_(?:GET|POST)', "PHP SSRF"),
            (r'curl_setopt.*CURLOPT_URL.*\$', "PHP curl SSRF"),
            (r'fetch\s*\(.*req\.(params|query|body)', "Node.js fetch SSRF"),
        ],
        "deserialization": [
            (r'pickle\.loads?\s*\(', "Python pickle反序列化"),
            (r'yaml\.load\s*\((?!.*Loader)', "Python yaml.load不安全"),
            (r'unserialize\s*\(\s*\$', "PHP unserialize用户输入"),
            (r'readObject\s*\(', "Java readObject反序列化"),
            (r'ObjectInputStream', "Java ObjectInputStream"),
            (r'JSON\.parse\s*\(.*eval', "JavaScript不安全反序列化"),
        ],
        "auth_bypass": [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', "硬编码密码"),
            (r'(?:api_key|secret|token)\s*=\s*["\'][^"\']+["\']', "硬编码密钥"),
            (r'jwt\.decode\s*\(.*verify\s*=\s*False', "JWT验证禁用"),
            (r'@login_required.*\n.*pass', "空的认证检查"),
            (r'if\s+.*==\s*["\']admin["\']', "硬编码管理员检查"),
        ],
        "info_leak": [
            (r'DEBUG\s*=\s*True', "调试模式开启"),
            (r'app\.debug\s*=\s*True', "Flask调试模式"),
            (r'display_errors\s*=\s*On', "PHP错误显示"),
            (r'console\.log\s*\(.*password', "日志泄露密码"),
            (r'print\s*\(.*(?:password|secret|token)', "打印敏感信息"),
        ],
    }

    # 需要审计的文件扩展名
    AUDIT_EXTENSIONS = {
        ".py", ".php", ".js", ".jsx", ".ts", ".tsx",
        ".java", ".rb", ".go", ".c", ".cpp", ".cs",
        ".asp", ".aspx", ".jsp", ".pl", ".sh",
    }

    def __init__(self, message_bus=None, tool_registry=None, executor=None):
        capabilities = AgentCapability(
            name="code_analysis",
            category="specialized",
            supported_tools={
                "scan_source_tree", "search_dangerous_patterns",
                "analyze_file", "whitebox_audit",
                "semgrep_scan", "bandit_scan",
            },
            max_concurrent_tasks=3,
            specialties=[
                "code_analysis", "whitebox", "sast",
                "vulnerability_detection", "code_audit"
            ]
        )

        super().__init__(
            agent_id="code_analyze_agent",
            name="Code Analyze Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )

        # VulnManager集成
        self._vuln_manager = None
        logger.info("CodeAnalyzeAgent初始化完成")

    def _get_vuln_manager(self):
        if self._vuln_manager is None:
            try:
                from kali_mcp.core.vuln_manager import VulnManager
                self._vuln_manager = VulnManager()
            except Exception:
                pass
        return self._vuln_manager

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        from kali_mcp.core.ctf_agent_framework import MessageType
        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value}")

    async def run(self, context):
        logger.info(f"[{self.agent_id}] 开始代码分析")
        source_path = context.parameters.get("source_path", "") if hasattr(context, 'parameters') else ""
        if not source_path:
            return {"success": False, "error": "未指定源码路径"}
        try:
            result = await self.whitebox_audit(source_path)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _execute_task_impl(self, task_type: str, task_data: Dict, task_id: str):
        source_path = task_data.get("source_path", "")
        if task_type == "scan_source_tree":
            return self.scan_source_tree(source_path)
        elif task_type == "search_dangerous_patterns":
            return self.search_patterns(source_path)
        elif task_type == "analyze_file":
            return self.analyze_single_file(task_data.get("file_path", ""))
        elif task_type == "whitebox_audit":
            return await self.whitebox_audit(source_path)
        else:
            return await self.whitebox_audit(source_path)

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        start_time = datetime.now()
        output = ""
        findings = []
        success = False

        try:
            result = await self._execute_task_impl(
                task.tool_name, task.parameters, task.task_id
            )
            if isinstance(result, dict):
                output = str(result)
                success = result.get("success", True)
                for v in result.get("vulnerabilities", []):
                    sev_map = {"high": ResultSeverity.HIGH, "medium": ResultSeverity.MEDIUM, "low": ResultSeverity.LOW}
                    findings.append(Finding(
                        title=v.get("title", ""),
                        description=v.get("description", ""),
                        severity=sev_map.get(v.get("severity", "medium"), ResultSeverity.MEDIUM),
                        result_type=ResultType.VULNERABILITY,
                        evidence=v.get("evidence", ""),
                    ))
            else:
                output = str(result)
                success = True
        except Exception as e:
            output = str(e)

        return AgentResult(
            agent_id=self.agent_id,
            task_id=task.task_id,
            tool_name=task.tool_name,
            target=task.parameters.get("source_path", ""),
            success=success,
            execution_time=(datetime.now() - start_time).total_seconds(),
            output=output,
            findings=findings,
        )

    # ==================== 核心功能 ====================

    def scan_source_tree(self, source_path: str) -> Dict[str, Any]:
        """扫描源码目录结构"""
        if not os.path.exists(source_path):
            return {"success": False, "error": f"路径不存在: {source_path}"}

        files = []
        for root, dirs, filenames in os.walk(source_path):
            # 跳过常见非源码目录
            dirs[:] = [d for d in dirs if d not in {
                ".git", ".svn", "node_modules", "__pycache__",
                ".venv", "venv", "vendor", ".idea", ".vscode"
            }]
            for f in filenames:
                ext = os.path.splitext(f)[1].lower()
                if ext in self.AUDIT_EXTENSIONS:
                    full_path = os.path.join(root, f)
                    rel_path = os.path.relpath(full_path, source_path)
                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        size = 0
                    files.append({"path": rel_path, "ext": ext, "size": size})

        return {
            "success": True,
            "total_files": len(files),
            "files": files[:200],  # 限制返回数量
        }

    def search_patterns(self, source_path: str) -> Dict[str, Any]:
        """搜索危险代码模式"""
        if not os.path.exists(source_path):
            return {"success": False, "error": f"路径不存在: {source_path}"}

        all_findings = []

        for root, dirs, filenames in os.walk(source_path):
            dirs[:] = [d for d in dirs if d not in {
                ".git", ".svn", "node_modules", "__pycache__", ".venv", "vendor"
            }]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in self.AUDIT_EXTENSIONS:
                    continue

                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, source_path)

                try:
                    with open(full_path, "r", errors="ignore") as f:
                        content = f.read(50000)  # 限制读取大小
                except Exception:
                    continue

                for vuln_type, patterns in self.VULN_PATTERNS.items():
                    for pattern, desc in patterns:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count("\n") + 1
                            line_content = content.split("\n")[line_num - 1].strip()[:200]
                            all_findings.append({
                                "vuln_type": vuln_type,
                                "title": f"{desc} in {rel_path}:{line_num}",
                                "description": desc,
                                "file": rel_path,
                                "line": line_num,
                                "evidence": line_content,
                                "severity": self._vuln_type_severity(vuln_type),
                            })

        return {
            "success": True,
            "total_findings": len(all_findings),
            "vulnerabilities": all_findings[:100],  # 限制返回数量
        }

    def analyze_single_file(self, file_path: str) -> Dict[str, Any]:
        """深度分析单个文件"""
        if not os.path.exists(file_path):
            return {"success": False, "error": f"文件不存在: {file_path}"}

        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read(100000)
        except Exception as e:
            return {"success": False, "error": str(e)}

        findings = []
        for vuln_type, patterns in self.VULN_PATTERNS.items():
            for pattern, desc in patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count("\n") + 1
                    line_content = content.split("\n")[line_num - 1].strip()[:200]
                    findings.append({
                        "vuln_type": vuln_type,
                        "title": f"{desc} at line {line_num}",
                        "description": desc,
                        "line": line_num,
                        "evidence": line_content,
                        "severity": self._vuln_type_severity(vuln_type),
                    })

        return {
            "success": True,
            "file": file_path,
            "total_lines": content.count("\n") + 1,
            "findings_count": len(findings),
            "vulnerabilities": findings,
        }

    async def whitebox_audit(self, source_path: str) -> Dict[str, Any]:
        """完整白盒审计流程"""
        # 1. 扫描目录结构
        tree = self.scan_source_tree(source_path)
        if not tree.get("success"):
            return tree

        # 2. 搜索危险模式
        pattern_results = self.search_patterns(source_path)

        # 3. 自动提交候选漏洞到VulnManager
        submitted_vulns = []
        vuln_mgr = self._get_vuln_manager()
        if vuln_mgr and pattern_results.get("vulnerabilities"):
            from kali_mcp.core.vuln_models import VulnRecord
            for v in pattern_results["vulnerabilities"][:50]:
                try:
                    vr = VulnRecord(
                        title=v["title"],
                        vuln_type=v["vuln_type"],
                        target=source_path,
                        severity=v["severity"],
                        confidence="medium",
                        source="whitebox",
                        endpoint=v.get("file", ""),
                        evidence=v.get("evidence", ""),
                        discovered_by="code_analyze_agent",
                    )
                    vid = vuln_mgr.issue_vuln(vr)
                    submitted_vulns.append(vid)
                except Exception as e:
                    logger.debug(f"VulnManager提交失败: {e}")

        return {
            "success": True,
            "source_path": source_path,
            "total_files": tree.get("total_files", 0),
            "total_findings": pattern_results.get("total_findings", 0),
            "vulnerabilities": pattern_results.get("vulnerabilities", []),
            "submitted_to_vuln_manager": len(submitted_vulns),
            "vuln_ids": submitted_vulns,
        }

    # ==================== 辅助方法 ====================

    @staticmethod
    def _vuln_type_severity(vuln_type: str) -> str:
        severity_map = {
            "sqli": "high", "rce": "critical", "deserialization": "critical",
            "xss": "medium", "lfi": "high", "ssrf": "high",
            "auth_bypass": "high", "info_leak": "low",
        }
        return severity_map.get(vuln_type, "medium")
