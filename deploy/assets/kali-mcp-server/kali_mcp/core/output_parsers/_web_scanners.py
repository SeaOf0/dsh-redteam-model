#!/usr/bin/env python3
"""Web directory scanner output parsers: GobusterParser."""

import re
import logging
from typing import Dict, Any, List, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate

logger = logging.getLogger(__name__)

class GobusterParser(BaseOutputParser):
    """
    Gobuster / 目录扫描输出解析器。

    支持 gobuster dir 模式的标准输出格式:
        /admin                (Status: 200) [Size: 1234]
        /login                (Status: 302) [Size: 0] [--> /auth/login]

    也兼容 ffuf/feroxbuster 的类似输出格式。

    structured_data 格式:
    {
        "paths": [{"path": "/admin", "status": 200, "size": 1234}],
        "interesting": ["/admin", "/.git"],
        "total_found": 15
    }
    """

    tool_name = "gobuster"

    # gobuster: /path (Status: 200) [Size: 1234] [--> redirect]
    _GOBUSTER_RE = re.compile(
        r'(/\S*)\s+\(Status:\s*(\d+)\)'
        r'(?:\s+\[Size:\s*(\d+)\])?'
        r'(?:\s+\[-+>\s*(\S+)\])?'
    )

    # feroxbuster: 200 GET 1234l 5678w 9012c http://target/path
    _FEROX_RE = re.compile(
        r'(\d{3})\s+\S+\s+\d+l\s+\d+w\s+(\d+)c\s+(\S+)'
    )

    # 高价值路径关键词
    _INTERESTING_KEYWORDS = {
        'admin', 'login', 'upload', 'api', 'backup', 'config',
        '.git', '.env', '.svn', '.htaccess', '.htpasswd', '.DS_Store',
        'phpmyadmin', 'wp-admin', 'wp-login', 'console', 'dashboard',
        'panel', 'manager', 'shell', 'cmd', 'exec', 'debug',
        'test', 'dev', 'staging', 'internal', 'secret',
        'database', 'db', 'sql', 'dump', 'export',
        'flag', 'key', 'token', 'password', 'credentials',
        'robots.txt', 'sitemap.xml', 'crossdomain.xml',
        'server-status', 'server-info', '.well-known',
    }

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        paths: List[Dict[str, Any]] = []
        target = data.get("url", data.get("target", ""))

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Gobuster 扫描 {target}: 未发现任何路径",
                structured_data={"paths": [], "interesting": [], "total_found": 0},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.6,
            )

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            # gobuster 标准格式
            match = self._GOBUSTER_RE.search(stripped)
            if match:
                paths.append({
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3)) if match.group(3) else 0,
                    "redirect": match.group(4) or "",
                })
                continue

            # feroxbuster 格式
            match2 = self._FEROX_RE.search(stripped)
            if match2:
                url = match2.group(3)
                # 从 URL 中提取路径
                path = "/" + url.split("/", 3)[-1] if "/" in url[8:] else "/"
                paths.append({
                    "path": path,
                    "status": int(match2.group(1)),
                    "size": int(match2.group(2)),
                    "redirect": "",
                })

        # 识别高价值路径
        interesting = self._find_interesting(paths)

        # 构建 next_steps
        next_steps = self._build_next_steps(paths, interesting, target)

        # 摘要
        if not paths:
            summary = f"Gobuster 扫描 {target}: 未发现路径"
        else:
            status_200 = [p for p in paths if p["status"] == 200]
            summary = (
                f"Gobuster 扫描 {target}: 发现 {len(paths)} 个路径 "
                f"(其中 {len(status_200)} 个状态200)"
            )
            if interesting:
                summary += f", {len(interesting)} 个高价值路径: {', '.join(interesting[:5])}"

        # 严重性
        severity = "info"
        for path in interesting:
            pl = path.lower()
            if any(kw in pl for kw in ('.git', '.env', '.htpasswd', 'backup', 'dump', 'database', 'flag')):
                severity = "high"
                break
            if any(kw in pl for kw in ('admin', 'panel', 'console', 'phpmyadmin', 'debug')):
                severity = "medium"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "paths": paths,
                "interesting": interesting,
                "total_found": len(paths),
            },
            raw_output="",
            next_steps=next_steps,
            severity=severity,
            confidence=0.9 if paths else 0.6,
        )

    def _find_interesting(self, paths: List[Dict[str, Any]]) -> List[str]:
        """识别高价值路径"""
        interesting: List[str] = []
        for p in paths:
            path_lower = p["path"].lower()
            # 状态码 200/301/302/403 的路径都可能有价值
            if p["status"] in (200, 301, 302, 403):
                if any(kw in path_lower for kw in self._INTERESTING_KEYWORDS):
                    interesting.append(p["path"])
        return interesting

    def _build_next_steps(
        self,
        paths: List[Dict[str, Any]],
        interesting: List[str],
        target: str,
    ) -> List[str]:
        """根据发现的路径生成建议"""
        steps: List[str] = []

        int_lower = {p.lower() for p in interesting}

        if any('.git' in p for p in int_lower):
            steps.append("发现 .git 目录  尝试 git 信息泄露 (git-dumper)")

        if any('.env' in p for p in int_lower):
            steps.append("发现 .env 文件  直接访问获取敏感配置信息")

        if any(kw in p for p in int_lower for kw in ('admin', 'panel', 'dashboard', 'console')):
            steps.append(
                "发现管理后台  建议使用 hydra_attack 爆破登录, "
                "或使用 intelligent_sql_injection_payloads 测试SQL注入"
            )

        if any(kw in p for p in int_lower for kw in ('login', 'signin', 'auth')):
            steps.append(
                "发现登录页面  建议使用 intelligent_sql_injection_payloads 测试注入, "
                "hydra_attack 爆破凭据"
            )

        if any(kw in p for p in int_lower for kw in ('upload', 'file', 'attach')):
            steps.append("发现文件上传功能  测试文件上传绕过获取 Webshell")

        if any(kw in p for p in int_lower for kw in ('api', 'graphql', 'swagger', 'docs')):
            steps.append("发现 API 端点  建议进一步探测 API 接口和认证绕过")

        if any(kw in p for p in int_lower for kw in ('backup', 'dump', 'export', 'database')):
            steps.append("发现备份/导出路径  直接下载检查敏感数据泄露")

        if any('phpmyadmin' in p for p in int_lower):
            steps.append(
                "发现 phpMyAdmin  建议使用 hydra_attack 爆破, 默认凭据 root/空密码"
            )

        # 通用建议
        php_paths = [p for p in paths if p["status"] == 200 and '.php' in p["path"].lower()]
        if php_paths:
            steps.append(
                f"发现 {len(php_paths)} 个PHP页面  建议使用 sqlmap_scan 测试SQL注入"
            )

        if len(paths) > 0 and not steps:
            steps.append(
                f"发现 {len(paths)} 个路径  建议使用 nuclei_web_scan 对目标进行漏洞扫描"
            )

        return steps

