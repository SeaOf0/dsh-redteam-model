#!/usr/bin/env python3
"""Password attack tool output parsers: HydraParser."""

import re
import logging
from typing import Dict, Any, List, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate

logger = logging.getLogger(__name__)

class HydraParser(BaseOutputParser):
    """
    Hydra 密码爆破输出解析器。

    Hydra 成功格式:
        [22][ssh] host: 10.0.0.1   login: admin   password: password123
        [80][http-get] host: 10.0.0.1   login: admin   password: admin

    structured_data 格式:
    {
        "credentials": [
            {"host": "10.0.0.1", "port": 22, "service": "ssh",
             "login": "admin", "password": "password123"}
        ],
        "found": True,
        "attempts": 1234,
        "target": "10.0.0.1"
    }
    """

    tool_name = "hydra"

    # [port][service] host: x.x.x.x   login: xxx   password: xxx
    _CRED_RE = re.compile(
        r'\[(\d+)\]\[([^\]]+)\]\s+'
        r'host:\s+(\S+)\s+'
        r'login:\s+(\S+)\s+'
        r'password:\s+(\S*)',
        re.IGNORECASE,
    )

    # 尝试次数: 1 of 14344399 [child 0]
    _ATTEMPTS_RE = re.compile(r'(\d+)\s+of\s+(\d+)')

    # 完成摘要: 1 valid password found
    _FOUND_RE = re.compile(r'(\d+)\s+valid\s+password', re.IGNORECASE)

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        service = data.get("service", "")
        credentials: List[Dict[str, Any]] = []
        total_attempts = 0

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Hydra 爆破 {target}: 无输出",
                structured_data={
                    "credentials": [], "found": False,
                    "attempts": 0, "target": target,
                },
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()

            # 凭据匹配
            cred_match = self._CRED_RE.search(stripped)
            if cred_match:
                credentials.append({
                    "host": cred_match.group(3),
                    "port": int(cred_match.group(1)),
                    "service": cred_match.group(2),
                    "login": cred_match.group(4),
                    "password": cred_match.group(5),
                })
                continue

            # 尝试次数
            attempt_match = self._ATTEMPTS_RE.search(stripped)
            if attempt_match:
                total_attempts = max(total_attempts, int(attempt_match.group(2)))

        found = len(credentials) > 0

        # next_steps
        next_steps: List[str] = []
        if found:
            for cred in credentials[:3]:
                svc = cred["service"].lower()
                if 'ssh' in svc:
                    next_steps.append(
                        f"成功爆破 SSH {cred['login']}:{cred['password']}  "
                        f"建议 SSH 登录并检查权限提升"
                    )
                elif 'ftp' in svc:
                    next_steps.append(
                        f"成功爆破 FTP {cred['login']}:{cred['password']}  "
                        f"建议登录检查可上传目录"
                    )
                elif 'http' in svc or 'web' in svc:
                    next_steps.append(
                        f"成功爆破 Web登录 {cred['login']}:{cred['password']}  "
                        f"建议登录后台进一步渗透"
                    )
                elif 'mysql' in svc or 'postgres' in svc:
                    next_steps.append(
                        f"成功爆破 数据库 {cred['login']}:{cred['password']}  "
                        f"建议连接数据库提取数据"
                    )
                else:
                    next_steps.append(
                        f"成功爆破 {svc} {cred['login']}:{cred['password']}  "
                        f"建议登录目标服务"
                    )
        else:
            next_steps.append(
                "未找到有效凭据  建议更换字典或使用更大的密码列表重试"
            )

        # 摘要
        if found:
            cred_desc = "; ".join(
                f"{c['login']}:{c['password']}@{c['service']}" for c in credentials[:3]
            )
            summary = f"Hydra 爆破 {target}: 成功! 发现 {len(credentials)} 个凭据: {cred_desc}"
            severity = "critical"
        else:
            summary = f"Hydra 爆破 {target}/{service}: 未找到有效凭据 ({total_attempts} 次尝试)"
            severity = "info"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "credentials": credentials,
                "found": found,
                "attempts": total_attempts,
                "target": target,
            },
            raw_output="",
            next_steps=next_steps,
            severity=severity,
            confidence=0.99 if found else 0.6,
        )

