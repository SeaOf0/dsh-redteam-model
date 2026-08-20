#!/usr/bin/env python3
"""Vulnerability scanner output parsers: NucleiParser, NiktoParser."""

import re
import json
import logging
from typing import Dict, Any, List, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate

logger = logging.getLogger(__name__)

class NucleiParser(BaseOutputParser):
    """
    Nuclei 输出解析器。

    支持两种格式:
    1. 文本格式: [severity] [template-id] [protocol] url
    2. JSONL 格式: 每行一个 JSON 对象

    structured_data 格式:
    {
        "vulnerabilities": [
            {"id": "CVE-2021-44228", "severity": "critical", "name": "Log4Shell",
             "url": "http://target/path", "matched": "..."}
        ],
        "stats": {"critical": 0, "high": 1, "medium": 3, "low": 0, "info": 5}
    }
    """

    tool_name = "nuclei"

    # 文本格式: [severity] [template-id] [protocol] url [additional info]
    _TEXT_RE = re.compile(
        r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)'
        r'(?:\s+\[([^\]]*)\])?'
    )

    _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        vulns: List[Dict[str, Any]] = []
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        target = data.get("target", "")

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Nuclei 扫描 {target}: 未发现漏洞",
                structured_data={"vulnerabilities": [], "stats": stats},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.7,
            )

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            vuln = None

            # 尝试 JSONL 格式
            if stripped.startswith('{'):
                vuln = self._parse_json_line(stripped)
            else:
                # 文本格式
                vuln = self._parse_text_line(stripped)

            if vuln:
                vulns.append(vuln)
                sev = vuln.get("severity", "info").lower()
                if sev in stats:
                    stats[sev] += 1

        # 确定最高严重性
        max_severity = "info"
        for sev in ("critical", "high", "medium", "low", "info"):
            if stats.get(sev, 0) > 0:
                max_severity = sev
                break

        # next_steps
        next_steps = self._build_next_steps(vulns)

        # 摘要
        if not vulns:
            summary = f"Nuclei 扫描 {target}: 未发现漏洞"
        else:
            parts = []
            for sev in ("critical", "high", "medium", "low", "info"):
                count = stats.get(sev, 0)
                if count > 0:
                    parts.append(f"{count} {sev}")
            summary = f"Nuclei 扫描 {target}: 发现 {len(vulns)} 个漏洞 ({', '.join(parts)})"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "vulnerabilities": vulns,
                "stats": stats,
            },
            raw_output="",
            next_steps=next_steps,
            severity=max_severity,
            confidence=0.95 if vulns else 0.7,
        )

    def _parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """解析 JSONL 格式的一行"""
        try:
            obj = json.loads(line)
            info = obj.get("info", {})
            classification = info.get("classification", {})

            # CVE ID 可能在多处
            cve_id = ""
            cve_ids = classification.get("cve-id", [])
            if isinstance(cve_ids, list) and cve_ids:
                cve_id = cve_ids[0]
            elif isinstance(cve_ids, str):
                cve_id = cve_ids

            return {
                "id": obj.get("template-id", obj.get("templateID", "")),
                "severity": info.get("severity", "info").lower(),
                "name": info.get("name", ""),
                "url": obj.get("matched-at", obj.get("host", "")),
                "matched": obj.get("matcher-name", ""),
                "cve_id": cve_id,
                "description": info.get("description", ""),
                "extracted_results": obj.get("extracted-results", []),
                "curl_command": obj.get("curl-command", ""),
            }
        except (json.JSONDecodeError, TypeError, AttributeError):
            return None

    def _parse_text_line(self, line: str) -> Optional[Dict[str, Any]]:
        """解析文本格式的一行"""
        match = self._TEXT_RE.match(line)
        if not match:
            return None

        severity = match.group(1).lower()
        template_id = match.group(2)
        url = match.group(4)
        extra = match.group(5) or ""

        # 提取 CVE
        cve_match = re.search(r'(CVE-\d{4}-\d+)', template_id, re.IGNORECASE)
        cve_id = cve_match.group(1) if cve_match else ""

        return {
            "id": template_id,
            "severity": severity,
            "name": template_id,
            "url": url,
            "matched": extra,
            "cve_id": cve_id,
            "description": "",
            "extracted_results": [],
            "curl_command": "",
        }

    def _build_next_steps(self, vulns: List[Dict[str, Any]]) -> List[str]:
        """根据漏洞发现生成建议"""
        steps: List[str] = []

        cve_vulns = [v for v in vulns if v.get("cve_id")]
        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
        high_vulns = [v for v in vulns if v.get("severity") == "high"]

        if critical_vulns:
            for v in critical_vulns[:3]:
                steps.append(
                    f" 严重漏洞 {v['id']}  建议使用 searchsploit_search 搜索利用代码, "
                    f"或使用 metasploit_run 尝试利用"
                )

        if high_vulns:
            for v in high_vulns[:3]:
                steps.append(
                    f" 高危漏洞 {v['id']}  建议使用 searchsploit_search 搜索exploit"
                )

        if cve_vulns and not steps:
            cve_list = [v["cve_id"] for v in cve_vulns[:5]]
            steps.append(
                f"发现 {len(cve_vulns)} 个CVE: {', '.join(cve_list)}  "
                f"建议使用 searchsploit_search 搜索利用方法"
            )

        sql_vulns = [v for v in vulns if 'sql' in v.get("id", "").lower()]
        if sql_vulns:
            steps.append("发现SQL注入相关漏洞  建议使用 sqlmap_scan 深入利用")

        xss_vulns = [v for v in vulns if 'xss' in v.get("id", "").lower()]
        if xss_vulns:
            steps.append("发现XSS相关漏洞  建议使用 intelligent_xss_payloads 生成利用载荷")

        if not steps and vulns:
            steps.append(
                f"发现 {len(vulns)} 个问题  建议进一步手动验证高优先级漏洞"
            )

        return steps


class NiktoParser(BaseOutputParser):
    """
    Nikto Web 服务器扫描输出解析器。

    Nikto 输出格式:
        + OSVDB-3092: /admin/: This might be interesting...
        + /login.php: Admin login page/section found.
        + Server: Apache/2.4.41

    structured_data 格式:
    {
        "findings": [{"id": "OSVDB-3092", "url": "/admin/", "description": "..."}],
        "server": "Apache/2.4.41",
        "total_findings": 12,
        "interesting_findings": 3
    }
    """

    tool_name = "nikto"

    # + OSVDB-xxxx: /path: description
    _FINDING_RE = re.compile(
        r'^\+\s+'
        r'(?:(OSVDB-\d+|CVE-[\d-]+):\s+)?'
        r'(/\S*):\s+'
        r'(.+)'
    )
    # + Server: Apache/2.4.41
    _SERVER_RE = re.compile(r'^\+\s+Server:\s+(.+)', re.IGNORECASE)

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        findings: List[Dict[str, str]] = []
        server = ""

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Nikto 扫描 {target}: 无输出",
                structured_data={
                    "findings": [], "server": "",
                    "total_findings": 0, "interesting_findings": 0,
                },
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()

            # 服务器信息
            server_match = self._SERVER_RE.match(stripped)
            if server_match:
                server = server_match.group(1).strip()
                continue

            # 发现
            finding_match = self._FINDING_RE.match(stripped)
            if finding_match:
                findings.append({
                    "id": finding_match.group(1) or "",
                    "url": finding_match.group(2),
                    "description": finding_match.group(3).strip(),
                })

        # 分类
        interesting = [
            f for f in findings
            if any(kw in f["description"].lower() for kw in
                   ('admin', 'login', 'upload', 'backup', 'config',
                    'interesting', 'dangerous', 'vulnerability', 'disclosure'))
        ]

        # 严重性
        severity = "info"
        if any('cve' in f.get("id", "").lower() for f in findings):
            severity = "high"
        elif interesting:
            severity = "medium"

        # next_steps
        next_steps: List[str] = []
        if findings:
            next_steps.append(
                f"Nikto 发现 {len(findings)} 个问题  建议使用 nuclei_web_scan 交叉验证"
            )
        if server:
            next_steps.append(
                f"服务器 {server}  建议使用 searchsploit_search 检查版本漏洞"
            )

        summary = f"Nikto 扫描 {target}: 发现 {len(findings)} 个问题"
        if server:
            summary += f", 服务器: {server}"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "findings": findings,
                "server": server,
                "total_findings": len(findings),
                "interesting_findings": len(interesting),
            },
            raw_output="",
            next_steps=next_steps,
            severity=severity,
            confidence=0.85 if findings else 0.6,
        )

