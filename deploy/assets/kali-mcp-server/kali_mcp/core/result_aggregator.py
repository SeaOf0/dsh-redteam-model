#!/usr/bin/env python3
"""
结果聚合器 (ResultAggregator)

聚合和分析多个智能体的执行结果：
- 结果去重
- 关联分析
- 报告生成
- Flag提取（CTF模式）
- 证据整理
"""

import logging
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
import re
import json
from pathlib import Path

from kali_mcp.core.intent_analyzer import IntentAnalysis, AttackIntent
from kali_mcp.core.task_decomposer import Task, TaskGraph, TaskCategory
from kali_mcp.core.agent_scheduler import SchedulingDecision

logger = logging.getLogger(__name__)


# ==================== 数据结构 ====================

class ResultSeverity(Enum):
    """结果严重性"""
    CRITICAL = "critical"     # 严重
    HIGH = "high"            # 高
    MEDIUM = "medium"        # 中等
    LOW = "low"              # 低
    INFO = "info"            # 信息


class ResultType(Enum):
    """结果类型"""
    VULNERABILITY = "vulnerability"     # 漏洞
    ASSET = "asset"                   # 资产
    CREDENTIAL = "credential"         # 凭据
    FLAG = "flag"                    # Flag（CTF）
    ERROR = "error"                  # 错误
    INFO = "info"                    # 信息
    METADATA = "metadata"            # 元数据


@dataclass
class AgentResult:
    """单个Agent的执行结果"""
    agent_id: str                          # Agent ID
    task_id: str                           # 任务ID
    tool_name: str                         # 使用的工具
    target: str                            # 目标

    # 执行信息
    success: bool                          # 是否成功
    execution_time: float                  # 执行时长（秒）
    timestamp: datetime = field(default_factory=datetime.now)

    # 结果数据
    output: str = ""                       # 原始输出
    parsed_data: Dict[str, Any] = field(default_factory=dict)  # 解析后的数据
    findings: List["Finding"] = field(default_factory=list)        # 发现列表
    errors: List[str] = field(default_factory=list)               # 错误列表

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """单个发现"""
    finding_type: ResultType               # 发现类型
    severity: ResultSeverity                # 严重性
    title: str                             # 标题
    description: str                        # 描述
    evidence: List[str] = field(default_factory=list)     # 证据
    source: str = ""                        # 来源（哪个Agent/工具）
    confidence: float = 0.5                 # 置信度 (0-1)

    # 额外属性
    cve_id: Optional[str] = None            # CVE编号（如果适用）
    cvss_score: Optional[float] = None       # CVSS评分
    poc_available: bool = False              # 是否有PoC
    flag_content: Optional[str] = None       # Flag内容（CTF模式）


@dataclass
class AggregatedResult:
    """聚合后的结果"""
    intent_analysis: IntentAnalysis         # 意图分析
    agent_results: List[AgentResult]        # 原始Agent结果列表

    # 聚合数据
    all_findings: List[Finding] = field(default_factory=list)      # 所有发现
    unique_findings: List[Finding] = field(default_factory=list)   # 去重后的发现
    correlated_findings: List["CorrelatedFinding"] = field(default_factory=list)  # 关联发现

    # 分类统计
    findings_by_type: Dict[ResultType, List[Finding]] = field(default_factory=dict)
    findings_by_severity: Dict[ResultSeverity, List[Finding]] = field(default_factory=dict)

    # CTF特有
    extracted_flags: List[str] = field(default_factory=list)          # 提取的Flag

    # 元数据
    aggregation_time: datetime = field(default_factory=datetime.now)
    total_execution_time: float = 0
    success_rate: float = 0


@dataclass
class CorrelatedFinding:
    """关联发现"""
    correlation_id: str                     # 关联ID
    title: str                              # 标题
    description: str                        # 描述
    findings: List[Finding]                # 相关的发现列表
    correlation_type: str                   # 关联类型（同一主机、同一漏洞等）
    confidence: float                       # 关联置信度
    severity: ResultSeverity                # 综合严重性


# ==================== 结果聚合器 ====================

class ResultAggregator:
    """
    结果聚合器

    聚合和分析多个Agent的执行结果
    """

    def __init__(self):
        """初始化聚合器"""
        # Flag检测模式
        # 注意：更具体的模式要放在前面
        self.flag_patterns = [
            re.compile(r'DASCTF\{[^}]+\}', re.IGNORECASE),  # DASCTF格式，最具体
            re.compile(r'FLAG\{[^}]+\}', re.IGNORECASE),     # FLAG格式
            re.compile(r'flag\{[^}]+\}'),                    # flag格式（小写，不覆盖FLAG）
            re.compile(r'ctf\{[^}]+\}'),                     # ctf格式（小写，避免匹配DASCTF）
            re.compile(r'[a-f0-9]{32}', re.IGNORECASE),      # MD5-like
            re.compile(r'[a-f0-9]{40}', re.IGNORECASE),      # SHA1-like
            re.compile(r'[a-f0-9]{64}', re.IGNORECASE),      # SHA256-like
        ]

        logger.info("ResultAggregator初始化完成")

    async def aggregate_results(
        self,
        intent_analysis: IntentAnalysis,
        agent_results: List[AgentResult],
        task_graph: Optional[TaskGraph] = None
    ) -> AggregatedResult:
        """
        聚合结果

        Args:
            intent_analysis: 意图分析
            agent_results: Agent结果列表
            task_graph: 任务图（可选）

        Returns:
            聚合结果
        """
        logger.info(f"开始聚合{len(agent_results)}个Agent的结果")

        # 1. 提取所有发现
        all_findings = []
        total_time = 0
        success_count = 0

        for result in agent_results:
            # 解析结果
            parsed = self._parse_agent_result(result)
            all_findings.extend(parsed)

            # 统计
            total_time += result.execution_time
            if result.success:
                success_count += 1

        # 2. 去重
        unique_findings = self._deduplicate_findings(all_findings)

        # 3. 关联分析
        correlated_findings = await self._correlate_findings(unique_findings)

        # 4. 分类
        findings_by_type = self._categorize_by_type(unique_findings)
        findings_by_severity = self._categorize_by_severity(unique_findings)

        # 5. Flag提取（CTF模式）
        extracted_flags = self._extract_flags(agent_results)

        # 6. 创建聚合结果
        aggregated = AggregatedResult(
            intent_analysis=intent_analysis,
            agent_results=agent_results,
            all_findings=all_findings,
            unique_findings=unique_findings,
            correlated_findings=correlated_findings,
            findings_by_type=findings_by_type,
            findings_by_severity=findings_by_severity,
            extracted_flags=extracted_flags,
            total_execution_time=total_time,
            success_rate=success_count / len(agent_results) if agent_results else 0
        )

        logger.info(f"聚合完成: {len(unique_findings)}个唯一发现, "
                   f"{len(correlated_findings)}个关联发现, "
                   f"{len(extracted_flags)}个Flag")

        return aggregated

    def _parse_agent_result(self, result: AgentResult) -> List[Finding]:
        """解析Agent结果"""
        findings = []

        # 如果已经有解析数据，直接使用（不进行auto-discovery）
        if result.parsed_data and result.parsed_data.get("findings"):
            for item in result.parsed_data.get("findings", []):
                finding = Finding(
                    finding_type=ResultType(item.get("type", "info")),
                    severity=ResultSeverity(item.get("severity", "medium")),
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    evidence=item.get("evidence", []),
                    source=result.agent_id,
                    confidence=item.get("confidence", 0.5)
                )
                findings.append(finding)
            return findings

        # 从输出中自动发现
        auto_findings = self._auto_discover_findings(result)
        findings.extend(auto_findings)

        return findings

    def _auto_discover_findings(self, result: AgentResult) -> List[Finding]:
        """从输出中自动发现"""
        findings = []

        output = result.output
        if not output:
            return findings

        # 检测漏洞
        vuln_keywords = {
            "SQL injection": ResultType.VULNERABILITY,
            "XSS": ResultType.VULNERABILITY,
            "RCE": ResultType.VULNERABILITY,
            "LFI": ResultType.VULNERABILITY,
            "CSRF": ResultType.VULNERABILITY
        }

        for keyword, vtype in vuln_keywords.items():
            if keyword.lower() in output.lower():
                findings.append(Finding(
                    finding_type=vtype,
                    severity=ResultSeverity.HIGH,
                    title=f"{keyword} detected",
                    description=f"Tool {result.tool_name} detected {keyword}",
                    evidence=[f"Tool: {result.tool_name}", f"Target: {result.target}"],
                    source=result.agent_id,
                    confidence=0.7
                ))

        # 检测开放端口 - 支持多种格式
        port_patterns = [
            re.compile(r'(\d+)/(tcp|udp)\s+open'),           # nmap格式: 80/tcp open
            re.compile(r'Port\s+(\d+)/(tcp|udp)\s+is\s+open', re.IGNORECASE),  # Port 8080/tcp is open
        ]

        for port_pattern in port_patterns:
            for match in port_pattern.finditer(output):
                findings.append(Finding(
                    finding_type=ResultType.ASSET,
                    severity=ResultSeverity.INFO,
                    title=f"Open port: {match.group(1)}",
                    description=f"Port {match.group(1)}/{match.group(2)} is open",
                    evidence=[match.group(0)],
                    source=result.agent_id,
                    confidence=0.9
                ))

        return findings

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """去重发现"""
        unique = []
        seen = set()

        for finding in findings:
            # 创建唯一键
            key = (
                finding.finding_type,
                finding.title,
                finding.description[:100]  # 前100字符
            )

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        logger.debug(f"去重: {len(findings)} -> {len(unique)}")
        return unique

    async def _correlate_findings(self, findings: List[Finding]) -> List[CorrelatedFinding]:
        """关联发现"""
        correlated = []

        # 按目标分组
        by_target = defaultdict(list)
        for finding in findings:
            if finding.evidence:
                # 尝试从evidence中提取目标
                for evidence in finding.evidence:
                    if "target:" in evidence or "http://" in evidence or "192.168" in evidence:
                        by_target[evidence].append(finding)

        # 为每个目标创建关联发现
        correlation_id = 0
        for target, target_findings in by_target.items():
            if len(target_findings) > 1:
                # 计算综合严重性
                severities = [f.severity for f in target_findings]
                max_severity = self._get_max_severity(severities)

                correlated.append(CorrelatedFinding(
                    correlation_id=f"corr_{correlation_id}",
                    title=f"Multiple findings for {target[:50]}",
                    description=f"{len(target_findings)} findings related to the same target",
                    findings=target_findings,
                    correlation_type="same_target",
                    confidence=0.8,
                    severity=max_severity
                ))
                correlation_id += 1

        return correlated

    def _categorize_by_type(self, findings: List[Finding]) -> Dict[ResultType, List[Finding]]:
        """按类型分类"""
        categorized = defaultdict(list)
        for finding in findings:
            categorized[finding.finding_type].append(finding)
        return dict(categorized)

    def _categorize_by_severity(self, findings: List[Finding]) -> Dict[ResultSeverity, List[Finding]]:
        """按严重性分类"""
        categorized = defaultdict(list)
        for finding in findings:
            categorized[finding.severity].append(finding)
        return dict(categorized)

    def _extract_flags(self, results: List[AgentResult]) -> List[str]:
        """提取Flag"""
        flags = set()

        for result in results:
            output = result.output

            # 尝试所有模式
            for pattern in self.flag_patterns:
                matches = pattern.findall(output)
                for match in matches:
                    flags.add(match)

        return list(flags)

    def _get_max_severity(self, severities: List[ResultSeverity]) -> ResultSeverity:
        """获取最高严重性"""
        severity_order = [
            ResultSeverity.INFO,
            ResultSeverity.LOW,
            ResultSeverity.MEDIUM,
            ResultSeverity.HIGH,
            ResultSeverity.CRITICAL
        ]

        max_sev = ResultSeverity.INFO
        for sev in severities:
            if severity_order.index(sev) > severity_order.index(max_sev):
                max_sev = sev

        return max_sev

    def generate_report(
        self,
        aggregated: AggregatedResult,
        output_format: str = "markdown"
    ) -> str:
        """
        生成报告

        Args:
            aggregated: 聚合结果
            output_format: 输出格式 (markdown, json, html)

        Returns:
            报告内容
        """
        if output_format == "json":
            return self._generate_json_report(aggregated)
        elif output_format == "html":
            return self._generate_html_report(aggregated)
        else:
            return self._generate_markdown_report(aggregated)

    def _generate_markdown_report(self, aggregated: AggregatedResult) -> str:
        """生成Markdown报告"""
        lines = []

        # 标题
        lines.append(f"# 安全测试报告")
        lines.append(f"")
        lines.append(f"**生成时间**: {aggregated.aggregation_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**测试目标**: {', '.join([t.value for t in aggregated.intent_analysis.targets])}")
        lines.append(f"**攻击意图**: {aggregated.intent_analysis.intent.value}")
        lines.append(f"")

        # 执行统计
        lines.append(f"## 执行统计")
        lines.append(f"- **Agent数量**: {len(aggregated.agent_results)}")
        lines.append(f"- **总执行时间**: {aggregated.total_execution_time:.2f}秒")
        lines.append(f"- **成功率**: {aggregated.success_rate*100:.1f}%")
        lines.append(f"- **发现总数**: {len(aggregated.all_findings)}")
        lines.append(f"- **唯一发现**: {len(aggregated.unique_findings)}")
        lines.append(f"- **关联发现**: {len(aggregated.correlated_findings)}")
        lines.append(f"")

        # Flag（CTF模式）
        if aggregated.extracted_flags:
            lines.append(f"##  提取的Flag ({len(aggregated.extracted_flags)})")
            lines.append(f"")
            for i, flag in enumerate(aggregated.extracted_flags, 1):
                lines.append(f"{i}. `{flag}`")
            lines.append(f"")

        # 按严重性分类
        lines.append(f"## 按严重性分类")
        lines.append(f"")

        severity_order = [ResultSeverity.CRITICAL, ResultSeverity.HIGH,
                         ResultSeverity.MEDIUM, ResultSeverity.LOW, ResultSeverity.INFO]

        for severity in severity_order:
            if severity in aggregated.findings_by_severity:
                findings = aggregated.findings_by_severity[severity]
                lines.append(f"### {severity.value.upper()} ({len(findings)})")
                lines.append(f"")

                for finding in findings[:10]:  # 最多显示10个
                    lines.append(f"#### {finding.title}")
                    lines.append(f"- **类型**: {finding.finding_type.value}")
                    lines.append(f"- **来源**: {finding.source}")
                    lines.append(f"- **置信度**: {finding.confidence:.2f}")
                    lines.append(f"- **描述**: {finding.description}")

                    if finding.evidence:
                        lines.append(f"- **证据**:")
                        for evidence in finding.evidence[:3]:
                            lines.append(f"  - `{evidence[:100]}`")

                    lines.append(f"")

                if len(findings) > 10:
                    lines.append(f"*... 还有 {len(findings) - 10} 个{severity.value}发现*")
                    lines.append(f"")

        # 按类型分类
        lines.append(f"## 按类型分类")
        lines.append(f"")

        for ftype, findings in aggregated.findings_by_type.items():
            lines.append(f"- **{ftype.value}**: {len(findings)}")

        lines.append(f"")

        # 关联发现
        if aggregated.correlated_findings:
            lines.append(f"## 关联发现 ({len(aggregated.correlated_findings)})")
            lines.append(f"")

            for corr in aggregated.correlated_findings[:5]:
                lines.append(f"### {corr.title}")
                lines.append(f"- **关联类型**: {corr.correlation_type}")
                lines.append(f"- **发现数量**: {len(corr.findings)}")
                lines.append(f"- **综合严重性**: {corr.severity.value}")
                lines.append(f"- **描述**: {corr.description}")
                lines.append(f"")

        return "\n".join(lines)

    def _generate_json_report(self, aggregated: AggregatedResult) -> str:
        """生成JSON报告"""
        data = {
            "metadata": {
                "generated_at": aggregated.aggregation_time.isoformat(),
                "intent": aggregated.intent_analysis.intent.value,
                "targets": [t.value for t in aggregated.intent_analysis.targets],
                "total_execution_time": aggregated.total_execution_time,
                "success_rate": aggregated.success_rate
            },
            "statistics": {
                "total_agents": len(aggregated.agent_results),
                "total_findings": len(aggregated.all_findings),
                "unique_findings": len(aggregated.unique_findings),
                "correlated_findings": len(aggregated.correlated_findings),
                "extracted_flags": len(aggregated.extracted_flags)
            },
            "flags": aggregated.extracted_flags,
            "findings": [
                {
                    "type": f.finding_type.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "source": f.source,
                    "confidence": f.confidence
                }
                for f in aggregated.unique_findings
            ],
            "correlated_findings": [
                {
                    "id": cf.correlation_id,
                    "title": cf.title,
                    "type": cf.correlation_type,
                    "severity": cf.severity.value,
                    "finding_count": len(cf.findings)
                }
                for cf in aggregated.correlated_findings
            ]
        }

        return json.dumps(data, indent=2, ensure_ascii=False)

    def _generate_html_report(self, aggregated: AggregatedResult) -> str:
        """生成HTML报告"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>安全测试报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        h3 {{ color: #888; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .info {{ color: #1976d2; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ddd; background: #f9f9f9; }}
        .flag {{ background: #fff3e0; padding: 10px; margin: 10px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1> 安全测试报告</h1>
    <p><strong>生成时间</strong>: {aggregated.aggregation_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>测试目标</strong>: {', '.join([t.value for t in aggregated.intent_analysis.targets])}</p>
    <p><strong>攻击意图</strong>: {aggregated.intent_analysis.intent.value}</p>

    <h2> 执行统计</h2>
    <ul>
        <li>Agent数量: {len(aggregated.agent_results)}</li>
        <li>总执行时间: {aggregated.total_execution_time:.2f}秒</li>
        <li>成功率: {aggregated.success_rate*100:.1f}%</li>
        <li>发现总数: {len(aggregated.all_findings)}</li>
        <li>唯一发现: {len(aggregated.unique_findings)}</li>
        <li>关联发现: {len(aggregated.correlated_findings)}</li>
    </ul>

    """

        # Flags
        if aggregated.extracted_flags:
            html += "<h2> 提取的Flag</h2>\n"
            for flag in aggregated.extracted_flags:
                html += f'<div class="flag"><code>{flag}</code></div>\n'

        # Findings by severity
        html += "<h2> 发现列表</h2>\n"

        for finding in aggregated.unique_findings[:20]:
            severity_class = finding.severity.value
            html += f"""
    <div class="finding">
        <h3 class="{severity_class}">{finding.title}</h3>
        <p><strong>类型</strong>: {finding.finding_type.value} |
           <strong>来源</strong>: {finding.source} |
           <strong>置信度</strong>: {finding.confidence:.2f}</p>
        <p>{finding.description}</p>
    </div>
    """

        html += """
</body>
</html>
    """

        return html

    def save_report(self, aggregated: AggregatedResult,
                   filepath: str, format: str = "markdown"):
        """保存报告到文件"""
        report = self.generate_report(aggregated, output_format=format)

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)

        logger.info(f"报告已保存到: {filepath}")


# ==================== 导出 ====================

__all__ = [
    'ResultAggregator',
    'AgentResult',
    'Finding',
    'AggregatedResult',
    'CorrelatedFinding',
    'ResultSeverity',
    'ResultType'
]
