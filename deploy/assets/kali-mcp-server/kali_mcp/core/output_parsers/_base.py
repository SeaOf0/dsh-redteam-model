#!/usr/bin/env python3
"""
结构化输出解析器 — 替代原始 output[:5000] 截断机制

本模块将工具的原始文本输出转化为统一的 ParsedResult 结构，包含:
- 人类可读摘要 (summary)
- 工具特定的结构化数据 (structured_data)
- CTF Flag 自动检测 (flags_found)
- 基于发现的下一步建议 (next_steps)
- 严重性和解析器置信度 (severity / confidence)

设计原则:
1. 每个解析器对畸形/不完整输出保持鲁棒
2. 空输出优雅处理
3. Flag 检测在所有解析器中统一运行
4. next_steps 引用实际 MCP 工具名
5. 完全自包含，仅依赖标准库

使用方法:
    from kali_mcp.core.output_parsers import parse_output

    result = parse_output("nmap", raw_output, return_code=0, data={"target": "10.0.0.1"})
    print(result.summary)
    print(result.structured_data["ports"])
    print(result.flags_found)
    print(result.next_steps)
"""

import re
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================
# CTF Flag 检测系统
# ============================================================

# 明确的 Flag 格式 — 高置信度，直接匹配
_EXPLICIT_FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'DASCTF\{[^}]+\}'),
    re.compile(r'htb\{[^}]+\}', re.IGNORECASE),
    re.compile(r'picoCTF\{[^}]+\}'),
    re.compile(r'ISCC\{[^}]+\}', re.IGNORECASE),
    re.compile(r'SCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'RCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'GWCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'BUUCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'HCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'CISCN\{[^}]+\}', re.IGNORECASE),
    re.compile(r'VNCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'XYCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'MOECTF\{[^}]+\}', re.IGNORECASE),
    # FLAG-xxxx-xxxx 格式 (HackTheBox 旧格式)
    re.compile(r'FLAG-[a-zA-Z0-9]{4,}(?:-[a-zA-Z0-9]{4,})*'),
]

# MD5-like hash — 低置信度，需要上下文确认
# 仅在 flag/key/secret/answer 等关键词附近出现时才视为 Flag
_MD5_PATTERN = re.compile(r'\b([0-9a-f]{32})\b', re.IGNORECASE)
_FLAG_CONTEXT_KEYWORDS = re.compile(
    r'(?:flag|key|secret|answer|password|token|hash|md5)\s*[:=]\s*',
    re.IGNORECASE,
)


def detect_flags(text: str) -> List[str]:
    """
    在任意文本中检测 CTF Flag。

    对明确格式（flag{...}, ctf{...} 等）直接匹配。
    对 MD5 hash 仅在关键词上下文中匹配，避免海量误报。

    Args:
        text: 待检测文本

    Returns:
        去重后的 Flag 列表
    """
    if not text:
        return []

    found: List[str] = []
    seen: set = set()

    # 1. 明确格式
    for pattern in _EXPLICIT_FLAG_PATTERNS:
        for match in pattern.finditer(text):
            flag = match.group(0)
            flag_lower = flag.lower()
            if flag_lower not in seen:
                seen.add(flag_lower)
                found.append(flag)

    # 2. MD5 hash — 仅在上下文关键词附近
    for line in text.split('\n'):
        if _FLAG_CONTEXT_KEYWORDS.search(line):
            for match in _MD5_PATTERN.finditer(line):
                candidate = match.group(1)
                # 排除全0、全f等明显非 Flag 的 hash
                if candidate not in seen and not _is_trivial_hash(candidate):
                    seen.add(candidate)
                    found.append(candidate)

    return found


def _is_trivial_hash(h: str) -> bool:
    """排除明显非 Flag 的 MD5 hash"""
    h_lower = h.lower()
    return (
        h_lower == '0' * 32
        or h_lower == 'f' * 32
        or h_lower == 'd41d8cd98f00b204e9800998ecf8427e'  # empty string MD5
        or len(set(h_lower)) <= 2  # 只有1-2种字符
    )


# ============================================================
# 统一结果数据类
# ============================================================

@dataclass
class ParsedResult:
    """
    统一的工具输出解析结果。

    所有解析器都返回此类型，提供一致的接口给上层消费者。

    Attributes:
        tool_name: 工具名称
        success: 执行是否成功
        summary: 人类可读的 1-2 句摘要
        structured_data: 工具特定的结构化数据
        raw_output: 原始输出（智能截断后的版本）
        flags_found: 检测到的 CTF Flag 列表
        next_steps: 基于发现建议的下一步操作
        severity: 发现的最高严重性 info/low/medium/high/critical
        confidence: 解析器置信度 0.0-1.0
    """
    tool_name: str
    success: bool
    summary: str
    structured_data: Dict[str, Any]
    raw_output: str
    flags_found: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    severity: str = "info"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典，方便 JSON 传输"""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "summary": self.summary,
            "structured_data": self.structured_data,
            "raw_output": self.raw_output,
            "flags_found": self.flags_found,
            "next_steps": self.next_steps,
            "severity": self.severity,
            "confidence": self.confidence,
        }


# ============================================================
# 智能截断
# ============================================================

def smart_truncate(text: str, max_length: int = 5000) -> Tuple[str, bool]:
    """
    智能截断文本：保留头部和尾部信息。

    与简单的 text[:5000] 不同，此方法保留:
    - 前 3000 字符（通常包含关键发现）
    - 后 1500 字符（通常包含摘要/结论）
    - 中间插入截断标记

    Args:
        text: 原始文本
        max_length: 最大长度

    Returns:
        (截断后文本, 是否发生了截断)
    """
    if not text or len(text) <= max_length:
        return text or "", False

    head_size = int(max_length * 0.6)   # 3000
    tail_size = int(max_length * 0.3)   # 1500
    # 剩余空间给截断标记

    truncation_marker = (
        f"\n\n... [截断: 原始输出 {len(text)} 字符, "
        f"已省略中间 {len(text) - head_size - tail_size} 字符] ...\n\n"
    )

    return text[:head_size] + truncation_marker + text[-tail_size:], True


# ============================================================
# 基础解析器
# ============================================================

class BaseOutputParser(ABC):
    """
    输出解析器基类。

    所有工具特定的解析器继承此类，实现 _parse_output 方法。
    基类负责:
    - Flag 检测（对所有工具统一执行）
    - 智能截断
    - 错误处理
    """

    tool_name: str = "unknown"

    def parse(
        self,
        output: str,
        return_code: int,
        data: Optional[Dict[str, Any]] = None,
    ) -> ParsedResult:
        """
        解析工具输出的主入口。

        Args:
            output: 工具的原始 stdout 输出
            return_code: 进程退出码
            data: 工具调用时的参数字典

        Returns:
            统一的 ParsedResult
        """
        data = data or {}
        output = output or ""
        success = return_code == 0

        # Flag 检测 — 在所有输出上运行
        flags = detect_flags(output)

        # 智能截断
        truncated_output, was_truncated = smart_truncate(output)

        try:
            result = self._parse_output(output, return_code, data)
        except Exception as e:
            logger.warning(f"解析器 {self.tool_name} 解析失败: {e}")
            result = ParsedResult(
                tool_name=self.tool_name,
                success=success,
                summary=f"{self.tool_name} 输出解析失败: {str(e)[:100]}",
                structured_data={"parse_error": str(e)},
                raw_output=truncated_output,
                flags_found=flags,
                next_steps=[],
                severity="info",
                confidence=0.0,
            )
            return result

        # 合并 Flag（解析器可能已发现额外的 Flag）
        all_flags = list(dict.fromkeys(flags + result.flags_found))
        result.flags_found = all_flags
        result.raw_output = truncated_output

        # 如果发现 Flag，提升摘要
        if all_flags and "flag" not in result.summary.lower():
            result.summary += f" |  发现 {len(all_flags)} 个Flag!"

        return result

    @abstractmethod
    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        """子类实现：解析工具特定输出"""
        ...


