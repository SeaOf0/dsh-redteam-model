#!/usr/bin/env python3
"""Generic fallback output parser: GenericParser."""

import re
import logging
from typing import Dict, Any, List, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate

logger = logging.getLogger(__name__)

class GenericParser(BaseOutputParser):
    """
    通用解析器 — 用于所有没有专用解析器的工具。

    特点:
    - 智能截断（保留头部和尾部，优于简单的 output[:5000]）
    - Flag 自动检测
    - 基本错误行识别
    - 输出统计

    structured_data 格式:
    {
        "output_length": 5000,
        "truncated": True,
        "line_count": 150,
        "error_lines": ["ERROR: connection refused"],
        "warning_lines": ["WARNING: timeout on host 10.0.0.1"]
    }
    """

    tool_name = "generic"

    _ERROR_RE = re.compile(
        r'(?:error|fail|fatal|exception|denied|refused|timeout|unreachable)',
        re.IGNORECASE,
    )
    _WARNING_RE = re.compile(
        r'(?:warn|caution|notice|deprecated|skipping)',
        re.IGNORECASE,
    )

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        tool_name = data.get("_tool_name", "unknown")
        target = data.get("target", data.get("url", data.get("domain", "")))
        success = return_code == 0

        if not output.strip():
            return ParsedResult(
                tool_name=tool_name,
                success=success,
                summary=f"{tool_name} {'执行成功' if success else '执行失败'}: 无输出",
                structured_data={
                    "output_length": 0, "truncated": False,
                    "line_count": 0, "error_lines": [], "warning_lines": [],
                },
                raw_output="",
                next_steps=[],
                severity="info" if success else "low",
                confidence=0.3,
            )

        lines = output.split('\n')
        line_count = len(lines)

        # 识别错误和警告行
        error_lines: List[str] = []
        warning_lines: List[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if self._ERROR_RE.search(stripped):
                error_lines.append(stripped[:200])  # 限制单行长度
            elif self._WARNING_RE.search(stripped):
                warning_lines.append(stripped[:200])

        # 限制错误/警告数量
        error_lines = error_lines[:20]
        warning_lines = warning_lines[:10]

        was_truncated = len(output) > 5000

        # 摘要
        if success:
            summary = f"{tool_name} 执行成功: {line_count} 行输出"
            if error_lines:
                summary += f", {len(error_lines)} 个错误/警告"
        else:
            if error_lines:
                summary = f"{tool_name} 执行失败: {error_lines[0][:80]}"
            else:
                summary = f"{tool_name} 执行失败 (退出码: {return_code})"

        severity = "info"
        if not success:
            severity = "low"
        if error_lines:
            severity = "low"

        return ParsedResult(
            tool_name=tool_name,
            success=success,
            summary=summary,
            structured_data={
                "output_length": len(output),
                "truncated": was_truncated,
                "line_count": line_count,
                "error_lines": error_lines,
                "warning_lines": warning_lines,
            },
            raw_output="",
            next_steps=[],
            severity=severity,
            confidence=0.3,  # 通用解析器置信度低
        )

