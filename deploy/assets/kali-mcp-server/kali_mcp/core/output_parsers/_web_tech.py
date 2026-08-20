#!/usr/bin/env python3
"""Web technology detection output parsers: WhatwebParser."""

import re
import logging
from typing import Dict, Any, List, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate

logger = logging.getLogger(__name__)

class WhatwebParser(BaseOutputParser):
    """
    WhatWeb 技术栈识别输出解析器。

    structured_data 格式:
    {
        "technologies": [{"name": "Apache", "version": "2.4.41", "category": "server"}],
        "server": "Apache 2.4.41",
        "cms": "WordPress",
        "language": "PHP",
        "framework": ""
    }
    """

    tool_name = "whatweb"

    _TECH_RE = re.compile(r'(\w[\w\s.-]*?)(?:\[([^\]]*)\])?(?:,|$)')

    _SERVER_NAMES = {'apache', 'nginx', 'iis', 'lighttpd', 'litespeed', 'caddy'}
    _CMS_NAMES = {
        'wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'typo3',
        'mediawiki', 'moodle', 'ghost', 'hugo', 'jekyll',
    }
    _LANG_NAMES = {'php', 'python', 'java', 'asp.net', 'ruby', 'perl', 'node.js'}
    _FRAMEWORK_NAMES = {
        'django', 'rails', 'laravel', 'spring', 'flask', 'express',
        'angular', 'react', 'vue', 'symfony', 'codeigniter', 'thinkphp',
    }

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        technologies: List[Dict[str, str]] = []
        server = ""
        cms = ""
        language = ""
        framework = ""

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"WhatWeb 扫描 {target}: 无输出",
                structured_data={
                    "technologies": [], "server": "",
                    "cms": "", "language": "", "framework": "",
                },
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            for match in self._TECH_RE.finditer(stripped):
                name = match.group(1).strip()
                version = match.group(2) or ""

                if not name or name in ('200 OK', '301', '302', '403', '404', 'Country'):
                    continue

                name_lower = name.lower()
                category = "other"

                if name_lower in self._SERVER_NAMES:
                    category = "server"
                    server = f"{name} {version}".strip()
                elif name_lower in self._CMS_NAMES:
                    category = "cms"
                    cms = name
                elif name_lower in self._LANG_NAMES:
                    category = "language"
                    language = name
                elif name_lower in self._FRAMEWORK_NAMES:
                    category = "framework"
                    framework = name
                elif name_lower in ('jquery', 'bootstrap', 'modernizr', 'font-awesome'):
                    category = "js-lib"

                technologies.append({
                    "name": name,
                    "version": version,
                    "category": category,
                })

        # next_steps
        next_steps: List[str] = []
        if cms.lower() == 'wordpress':
            next_steps.append("发现 WordPress  建议使用 wpscan_scan 深度扫描插件/主题漏洞")
        elif cms.lower() == 'joomla':
            next_steps.append("发现 Joomla  建议使用 joomscan_scan 深度扫描")

        if server:
            next_steps.append(f"服务器 {server}  建议使用 searchsploit_search 检查版本漏洞")

        if language.lower() == 'php':
            next_steps.append("PHP 技术栈  注意 LFI/RFI/反序列化等漏洞")
        elif 'java' in language.lower() or 'spring' in framework.lower():
            next_steps.append("Java/Spring 技术栈  注意 OGNL/SpEL 注入、反序列化漏洞")

        if framework.lower() == 'thinkphp':
            next_steps.append("ThinkPHP 框架  建议使用 nuclei_cve_scan 检查已知RCE漏洞")

        summary = f"WhatWeb 扫描 {target}: "
        parts = []
        if server:
            parts.append(f"服务器: {server}")
        if cms:
            parts.append(f"CMS: {cms}")
        if language:
            parts.append(f"语言: {language}")
        if framework:
            parts.append(f"框架: {framework}")
        summary += ", ".join(parts) if parts else f"识别到 {len(technologies)} 项技术"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "technologies": technologies,
                "server": server,
                "cms": cms,
                "language": language,
                "framework": framework,
            },
            raw_output="",
            next_steps=next_steps,
            severity="info",
            confidence=0.85 if technologies else 0.5,
        )

