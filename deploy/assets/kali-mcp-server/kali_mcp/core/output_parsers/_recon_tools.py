#!/usr/bin/env python3
"""Reconnaissance tool output parsers: SubfinderParser."""

import re
import logging
from typing import Dict, Any, List, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate

logger = logging.getLogger(__name__)

class SubfinderParser(BaseOutputParser):
    """
    Subfinder / 子域名枚举输出解析器。

    subfinder 输出格式: 每行一个子域名
        sub1.example.com
        sub2.example.com
        *.example.com  (通配符检测)

    structured_data 格式:
    {
        "subdomains": ["sub1.example.com", "sub2.example.com"],
        "count": 15,
        "wildcard_detected": False,
        "unique_prefixes": ["sub1", "sub2"]
    }
    """

    tool_name = "subfinder"

    _DOMAIN_RE = re.compile(r'^([a-zA-Z0-9*][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$')

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("domain", data.get("target", ""))
        subdomains: List[str] = []
        wildcard_detected = False

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Subfinder 扫描 {target}: 未发现子域名",
                structured_data={
                    "subdomains": [], "count": 0,
                    "wildcard_detected": False, "unique_prefixes": [],
                },
                raw_output="",
                next_steps=["未发现子域名  建议使用 amass_enum 或 dnsrecon_scan 进行更深入枚举"],
                severity="info",
                confidence=0.6,
            )

        seen: set = set()
        for line in output.split('\n'):
            domain = line.strip().lower()
            if not domain or domain in seen:
                continue

            # 跳过非域名行（日志、进度等）
            if not self._DOMAIN_RE.match(domain):
                continue

            seen.add(domain)
            subdomains.append(domain)

            if domain.startswith('*.'):
                wildcard_detected = True

        # 提取唯一前缀
        prefixes: List[str] = []
        if target:
            target_lower = target.lower().lstrip('.')
            for sub in subdomains:
                if sub.endswith('.' + target_lower):
                    prefix = sub[:-(len(target_lower) + 1)]
                    if prefix and prefix not in prefixes:
                        prefixes.append(prefix)

        # next_steps
        next_steps: List[str] = []
        if subdomains:
            next_steps.append(
                f"发现 {len(subdomains)} 个子域名  建议使用 httpx_probe 探测存活主机和Web服务"
            )
            next_steps.append(
                f"对存活子域名  建议使用 nmap_scan 扫描端口, nuclei_web_scan 扫描漏洞"
            )
            if wildcard_detected:
                next_steps.append("检测到通配符DNS记录  注意排除误报")

        # 摘要
        summary = f"Subfinder 扫描 {target}: 发现 {len(subdomains)} 个子域名"
        if wildcard_detected:
            summary += " (检测到通配符DNS)"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "subdomains": subdomains,
                "count": len(subdomains),
                "wildcard_detected": wildcard_detected,
                "unique_prefixes": prefixes[:50],  # 限制大小
            },
            raw_output="",
            next_steps=next_steps,
            severity="info",
            confidence=0.9 if subdomains else 0.5,
        )

