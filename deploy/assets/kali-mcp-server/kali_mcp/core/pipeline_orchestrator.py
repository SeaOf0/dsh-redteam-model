#!/usr/bin/env python3
"""
PipelineOrchestrator - 流水线编排引擎 (v5.0 Phase 4)

三种流水线模式:
1. 渗透测试流水线（完整）: 信息收集源码获取代码审计漏洞扫描交叉验证利用报告
2. CTF快速流水线: 快速扫描源码获取代码审计找漏洞构造payloadflag
3. 代码审计专项流水线: 源码分析多轮审计候选漏洞自动验证报告
"""

import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class PipelineMode(str, Enum):
    PENTEST = "pentest"
    CTF = "ctf"
    AUDIT = "audit"


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class PipelineStage:
    """流水线阶段"""
    name: str
    description: str
    status: StageStatus = StageStatus.PENDING
    result: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    skippable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "result": self.result,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "skippable": self.skippable,
        }


@dataclass
class Pipeline:
    """流水线实例"""
    pipeline_id: str
    mode: PipelineMode
    target: str
    stages: List[PipelineStage] = field(default_factory=list)
    status: str = "created"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    current_stage_idx: int = 0
    config: Dict[str, Any] = field(default_factory=dict)
    findings: Dict[str, Any] = field(default_factory=lambda: {
        "vulns": [], "fragments": [], "chains": [], "flags": [],
    })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "mode": self.mode.value,
            "target": self.target,
            "status": self.status,
            "created_at": self.created_at,
            "current_stage": self.stages[self.current_stage_idx].name
                if self.current_stage_idx < len(self.stages) else "done",
            "progress": f"{self.current_stage_idx}/{len(self.stages)}",
            "stages": [s.to_dict() for s in self.stages],
            "findings_summary": {
                "vulns": len(self.findings["vulns"]),
                "fragments": len(self.findings["fragments"]),
                "chains": len(self.findings["chains"]),
                "flags": len(self.findings["flags"]),
            },
        }


class PipelineOrchestrator:
    """流水线编排引擎 - 管理和执行攻击流水线"""

    # 渗透测试流水线阶段定义
    PENTEST_STAGES = [
        ("recon", "信息收集 - 端口扫描/服务识别/技术栈检测", False),
        ("source_acquisition", "源码获取 - .git泄露/备份文件/LFI", True),
        ("code_audit", "代码审计 - 静态分析/漏洞模式匹配", True),
        ("vuln_scan", "漏洞扫描 - 黑盒扫描/已知CVE检测", False),
        ("cross_validation", "交叉验证 - 黑盒+白盒结果关联", True),
        ("exploitation", "漏洞利用 - PoC验证/自动化利用", False),
        ("privilege_escalation", "权限提升 - 提权检测/利用", True),
        ("chain_building", "攻击链构建 - 多步骤攻击路径", True),
        ("reporting", "报告生成 - 汇总发现/生成报告", False),
    ]

    # CTF快速流水线阶段定义
    CTF_STAGES = [
        ("quick_scan", "快速扫描 - 端口/Web指纹/目录", False),
        ("source_acquisition", "源码获取 - .git泄露/备份/源码泄露", True),
        ("code_audit", "代码审计 - 快速漏洞模式匹配", True),
        ("vuln_discovery", "漏洞发现 - 针对性漏洞检测", False),
        ("payload_craft", "Payload构造 - 生成利用载荷", False),
        ("flag_capture", "Flag获取 - 执行利用/提取Flag", False),
    ]

    # 代码审计专项流水线阶段定义
    AUDIT_STAGES = [
        ("source_analysis", "源码分析 - 语言/框架/结构识别", False),
        ("pattern_scan", "模式扫描 - 50+漏洞模式正则匹配", False),
        ("deep_audit", "深度审计 - 数据流/控制流分析", False),
        ("candidate_vulns", "候选漏洞 - 汇总/去重/评分", False),
        ("auto_verify", "自动验证 - PoC生成/验证(如有环境)", True),
        ("audit_report", "审计报告 - 漏洞详情/修复建议", False),
    ]

    def __init__(self):
        self._pipelines: Dict[str, Pipeline] = {}
        logger.info("PipelineOrchestrator 初始化完成")

    def create_pipeline(self, mode: str, target: str,
                        config: Dict[str, Any] = None) -> Pipeline:
        """创建流水线"""
        try:
            pipeline_mode = PipelineMode(mode)
        except ValueError:
            raise ValueError(f"不支持的流水线模式: {mode}, 可选: pentest/ctf/audit")

        stage_defs = {
            PipelineMode.PENTEST: self.PENTEST_STAGES,
            PipelineMode.CTF: self.CTF_STAGES,
            PipelineMode.AUDIT: self.AUDIT_STAGES,
        }[pipeline_mode]

        stages = [
            PipelineStage(name=name, description=desc, skippable=skip)
            for name, desc, skip in stage_defs
        ]

        pipeline = Pipeline(
            pipeline_id=f"PL-{uuid.uuid4().hex[:8].upper()}",
            mode=pipeline_mode,
            target=target,
            stages=stages,
            config=config or {},
        )
        self._pipelines[pipeline.pipeline_id] = pipeline
        logger.info(f"流水线已创建: {pipeline.pipeline_id} [{mode}]  {target}")
        return pipeline

    def get_pipeline(self, pipeline_id: str) -> Optional[Pipeline]:
        """获取流水线"""
        return self._pipelines.get(pipeline_id)

    def list_pipelines(self) -> List[Dict[str, Any]]:
        """列出所有流水线"""
        return [p.to_dict() for p in self._pipelines.values()]

    def advance_stage(self, pipeline_id: str,
                      result: Dict[str, Any] = None) -> Dict[str, Any]:
        """推进流水线到下一阶段"""
        pipeline = self._pipelines.get(pipeline_id)
        if not pipeline:
            return {"error": f"流水线 {pipeline_id} 不存在"}

        if pipeline.current_stage_idx >= len(pipeline.stages):
            return {"error": "流水线已完成", "status": "completed"}

        # 完成当前阶段
        current = pipeline.stages[pipeline.current_stage_idx]
        current.status = StageStatus.COMPLETED
        current.completed_at = datetime.now().isoformat()
        current.result = result or {}

        # 收集发现
        self._collect_findings(pipeline, current, result or {})

        # 推进到下一阶段
        pipeline.current_stage_idx += 1

        if pipeline.current_stage_idx >= len(pipeline.stages):
            pipeline.status = "completed"
            logger.info(f"流水线 {pipeline_id} 已完成所有阶段")
            return {
                "status": "pipeline_completed",
                "pipeline_id": pipeline_id,
                "findings": pipeline.findings,
            }

        # 启动下一阶段
        next_stage = pipeline.stages[pipeline.current_stage_idx]
        next_stage.status = StageStatus.RUNNING
        next_stage.started_at = datetime.now().isoformat()
        pipeline.status = "running"

        return {
            "status": "stage_advanced",
            "completed_stage": current.name,
            "next_stage": next_stage.name,
            "next_description": next_stage.description,
            "progress": f"{pipeline.current_stage_idx}/{len(pipeline.stages)}",
        }

    def skip_stage(self, pipeline_id: str) -> Dict[str, Any]:
        """跳过当前阶段（仅可跳过标记为skippable的阶段）"""
        pipeline = self._pipelines.get(pipeline_id)
        if not pipeline:
            return {"error": f"流水线 {pipeline_id} 不存在"}

        if pipeline.current_stage_idx >= len(pipeline.stages):
            return {"error": "流水线已完成"}

        current = pipeline.stages[pipeline.current_stage_idx]
        if not current.skippable:
            return {"error": f"阶段 {current.name} 不可跳过"}

        current.status = StageStatus.SKIPPED
        current.completed_at = datetime.now().isoformat()
        pipeline.current_stage_idx += 1

        if pipeline.current_stage_idx >= len(pipeline.stages):
            pipeline.status = "completed"
            return {"status": "pipeline_completed", "skipped": current.name}

        next_stage = pipeline.stages[pipeline.current_stage_idx]
        next_stage.status = StageStatus.RUNNING
        next_stage.started_at = datetime.now().isoformat()

        return {
            "status": "stage_skipped",
            "skipped_stage": current.name,
            "next_stage": next_stage.name,
        }

    def start_pipeline(self, pipeline_id: str) -> Dict[str, Any]:
        """启动流水线（开始第一个阶段）"""
        pipeline = self._pipelines.get(pipeline_id)
        if not pipeline:
            return {"error": f"流水线 {pipeline_id} 不存在"}

        if pipeline.status != "created":
            return {"error": f"流水线状态为 {pipeline.status}，无法启动"}

        first_stage = pipeline.stages[0]
        first_stage.status = StageStatus.RUNNING
        first_stage.started_at = datetime.now().isoformat()
        pipeline.status = "running"

        return {
            "status": "started",
            "pipeline_id": pipeline_id,
            "mode": pipeline.mode.value,
            "target": pipeline.target,
            "first_stage": first_stage.name,
            "total_stages": len(pipeline.stages),
        }

    def get_status(self, pipeline_id: str) -> Dict[str, Any]:
        """获取流水线状态"""
        pipeline = self._pipelines.get(pipeline_id)
        if not pipeline:
            return {"error": f"流水线 {pipeline_id} 不存在"}
        return pipeline.to_dict()

    def get_recommendations(self, pipeline_id: str) -> Dict[str, Any]:
        """根据当前阶段和已有发现，推荐下一步操作"""
        pipeline = self._pipelines.get(pipeline_id)
        if not pipeline:
            return {"error": f"流水线 {pipeline_id} 不存在"}

        if pipeline.current_stage_idx >= len(pipeline.stages):
            return {"recommendations": [], "reason": "流水线已完成"}

        current = pipeline.stages[pipeline.current_stage_idx]
        recs = self._get_stage_recommendations(pipeline, current)
        return {
            "current_stage": current.name,
            "recommendations": recs,
        }

    def _collect_findings(self, pipeline: Pipeline, stage: PipelineStage,
                          result: Dict[str, Any]):
        """从阶段结果中收集发现"""
        if "vulns" in result:
            pipeline.findings["vulns"].extend(result["vulns"])
        if "fragments" in result:
            pipeline.findings["fragments"].extend(result["fragments"])
        if "chains" in result:
            pipeline.findings["chains"].extend(result["chains"])
        if "flags" in result:
            pipeline.findings["flags"].extend(result["flags"])

    def _get_stage_recommendations(self, pipeline: Pipeline,
                                   stage: PipelineStage) -> List[Dict[str, str]]:
        """根据流水线模式和当前阶段生成推荐"""
        recs = []
        mode = pipeline.mode
        name = stage.name
        target = pipeline.target

        # 通用推荐映射
        rec_map = {
            "recon": [
                {"tool": "nmap_scan", "args": f"target={target}",
                 "reason": "端口和服务扫描"},
                {"tool": "whatweb_scan", "args": f"target={target}",
                 "reason": "Web技术栈识别"},
            ],
            "quick_scan": [
                {"tool": "nmap_scan", "args": f"target={target}, scan_type=fast",
                 "reason": "快速端口扫描"},
                {"tool": "gobuster_scan", "args": f"url={target}",
                 "reason": "目录枚举"},
            ],
            "source_acquisition": [
                {"tool": "execute_command", "args": "git-dumper检测.git泄露",
                 "reason": "检测.git源码泄露"},
            ],
            "code_audit": [
                {"tool": "code_audit_comprehensive",
                 "args": "对获取的源码进行全面审计",
                 "reason": "静态代码分析"},
            ],
            "vuln_scan": [
                {"tool": "nuclei_web_scan", "args": f"target={target}",
                 "reason": "已知漏洞模板扫描"},
                {"tool": "sqlmap_scan", "args": f"url={target}",
                 "reason": "SQL注入检测"},
            ],
            "vuln_discovery": [
                {"tool": "nuclei_web_scan", "args": f"target={target}",
                 "reason": "漏洞模板扫描"},
            ],
            "exploitation": [
                {"tool": "searchsploit_search", "args": "搜索可用exploit",
                 "reason": "搜索公开漏洞利用"},
            ],
            "payload_craft": [
                {"tool": "intelligent_sql_injection_payloads",
                 "args": "生成针对性payload",
                 "reason": "智能Payload生成"},
            ],
            "source_analysis": [
                {"tool": "whatweb_scan", "args": f"target={target}",
                 "reason": "技术栈识别"},
            ],
            "pattern_scan": [
                {"tool": "semgrep_scan", "args": "正则模式扫描",
                 "reason": "代码模式匹配"},
            ],
        }

        # 根据已有发现增强推荐
        vulns = pipeline.findings.get("vulns", [])
        if vulns and name == "exploitation":
            for v in vulns[:3]:
                recs.append({
                    "tool": "verify_vulnerability",
                    "args": f"验证漏洞: {v.get('type', 'unknown')}",
                    "reason": f"验证已发现的 {v.get('type', '')} 漏洞",
                })

        recs.extend(rec_map.get(name, []))
        return recs
