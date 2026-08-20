#!/usr/bin/env python3
"""
智能工具链引擎 - 结果驱动的自适应渗透测试工具编排

核心能力:
1. 结果解析: 工具输出自动解析为结构化数据
2. 条件执行: 基于前序结果决定是否执行下一步
3. 参数构建: 前序结果自动构建后续工具的最优参数
4. 失败降级: 工具失败时自动尝试备选方案
5. 分支合并: 多个工具的发现聚合后再决策

与事件总线集成:
- 每个步骤完成后发射 tool.result 事件
- 发现漏洞时发射 vuln.candidate 事件
- 所有分析模块自动接收数据
"""

import logging
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from collections import deque

from kali_mcp.core.result_parser import (
    ResultParser, SmartParamsBuilder,
    NmapResult, GobusterResult, NucleiResult,
    SqlmapResult, WhatwebResult, WafResult,
)

logger = logging.getLogger(__name__)


@dataclass
class ChainContext:
    """
    工具链执行上下文 - 在步骤之间传递结构化数据

    这是整个系统的核心数据结构。每个步骤可以读取前序步骤
    写入的数据，也可以写入新数据供后续步骤使用。
    """
    target: str = ""
    # 结构化解析结果
    nmap_result: Optional[NmapResult] = None
    masscan_result: Optional[NmapResult] = None
    gobuster_result: Optional[GobusterResult] = None
    nuclei_result: Optional[NucleiResult] = None
    sqlmap_result: Optional[SqlmapResult] = None
    whatweb_result: Optional[WhatwebResult] = None
    waf_result: Optional[WafResult] = None

    # 聚合信息
    open_ports: List[int] = field(default_factory=list)
    web_urls: List[str] = field(default_factory=list)
    discovered_paths: List[str] = field(default_factory=list)
    discovered_vulns: List[Dict] = field(default_factory=list)
    discovered_techs: List[str] = field(default_factory=list)
    injectable_urls: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)

    # 元信息
    has_web_service: bool = False
    has_waf: bool = False
    waf_type: str = ""
    cms_type: str = ""
    http_port: int = 80

    # 执行记录
    step_results: Dict[str, Any] = field(default_factory=dict)
    step_durations: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def update_from_nmap(self, nmap_result: NmapResult):
        """从nmap结果更新上下文"""
        self.nmap_result = nmap_result
        self.open_ports = nmap_result.open_ports
        self.has_web_service = nmap_result.has_web_service
        self.web_urls = nmap_result.web_urls
        if nmap_result.http_ports:
            self.http_port = nmap_result.http_ports[0]

    def update_from_gobuster(self, gobuster_result: GobusterResult):
        """从gobuster结果更新上下文"""
        self.gobuster_result = gobuster_result
        self.discovered_paths = gobuster_result.interesting_paths
        # 标记可能有SQL注入的URL
        for p in gobuster_result.paths:
            if p.status_code == 200 and any(
                ext in p.path for ext in (".php", ".asp", ".jsp", ".do", ".action")
            ):
                base = self.web_urls[0] if self.web_urls else f"http://{self.target}"
                self.injectable_urls.append(f"{base.rstrip('/')}{p.path}")

    def update_from_whatweb(self, whatweb_result: WhatwebResult):
        """从whatweb结果更新上下文"""
        self.whatweb_result = whatweb_result
        self.cms_type = whatweb_result.cms
        self.discovered_techs = [t.name for t in whatweb_result.technologies]

    def update_from_waf(self, waf_result: WafResult):
        """从WAF检测结果更新上下文"""
        self.waf_result = waf_result
        self.has_waf = waf_result.has_waf
        self.waf_type = waf_result.waf_name

    def update_from_nuclei(self, nuclei_result: NucleiResult):
        """从nuclei结果更新上下文"""
        self.nuclei_result = nuclei_result
        for f in nuclei_result.findings:
            self.discovered_vulns.append({
                "type": "nuclei",
                "template": f.template_id,
                "severity": f.severity,
                "url": f.url,
                "cve": f.cve_id,
            })

    def update_from_sqlmap(self, sqlmap_result: SqlmapResult):
        """从sqlmap结果更新上下文"""
        self.sqlmap_result = sqlmap_result
        if sqlmap_result.is_vulnerable:
            self.discovered_vulns.append({
                "type": "sqli",
                "injection_type": sqlmap_result.injection_type,
                "dbms": sqlmap_result.dbms,
                "params": sqlmap_result.injectable_params,
            })

    def to_summary(self) -> Dict[str, Any]:
        """生成上下文摘要"""
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "has_web": self.has_web_service,
            "web_urls": self.web_urls[:5],
            "paths_found": len(self.discovered_paths),
            "vulns_found": len(self.discovered_vulns),
            "has_waf": self.has_waf,
            "waf_type": self.waf_type,
            "cms": self.cms_type,
            "techs": self.discovered_techs[:10],
            "flags": self.flags,
            "errors": self.errors[:5],
            "steps_completed": list(self.step_results.keys()),
        }


@dataclass
class ToolChainStep:
    """
    工具链步骤定义

    每个步骤可以:
    - 根据上下文决定是否执行 (condition)
    - 根据上下文构建参数 (params_builder)
    - 解析结果并更新上下文 (result_handler)
    - 失败时使用备选工具 (fallback_tools)
    """
    name: str                    # 步骤名称
    tool_name: str               # 工具名称
    params: Dict[str, Any] = field(default_factory=dict)  # 静态参数
    params_builder: Optional[Callable] = None  # 动态参数构建器 fn(ctx) -> Dict
    condition: Optional[Callable] = None       # 执行条件 fn(ctx) -> bool
    result_handler: Optional[Callable] = None  # 结果处理器 fn(ctx, result) -> None
    fallback_tools: List[str] = field(default_factory=list)  # 失败时的备选工具
    timeout: int = 300           # 单步超时(秒)
    required: bool = False       # 是否必须成功
    priority: int = 50           # 执行优先级(0=最高，100=最低)，用于动态排序


class ToolChain:
    """
    智能工具链执行引擎

    使用方式:
        chain = ToolChain(executor, event_bus)
        chain.add_step(ToolChainStep(...))
        result = chain.execute(target)
    """

    def __init__(self, executor, event_bus=None):
        self.executor = executor
        self.event_bus = event_bus
        self.steps: List[ToolChainStep] = []
        # v5.2: 决策钩子列表 — 每步完成后调用，可动态插入新步骤
        # 签名: fn(ctx: ChainContext, step: ToolChainStep, result: Dict, queue: deque) -> None
        self._decision_hooks: List[Callable] = []

    def add_step(self, step: ToolChainStep):
        """添加步骤"""
        self.steps.append(step)
        return self  # 支持链式调用

    def add_decision_hook(self, hook: Callable):
        """
        添加决策钩子 (v5.2)

        钩子在每步完成后调用，可根据结果动态插入新步骤到队列。
        签名: fn(ctx: ChainContext, step: ToolChainStep, result: Dict, queue: deque) -> None

        示例:
            def on_wordpress(ctx, step, result, queue):
                if ctx.cms_type == 'wordpress':
                    queue.appendleft(ToolChainStep(name='wpscan', tool_name='wpscan', ...))
        """
        self._decision_hooks.append(hook)
        return self

    def execute(self, target: str, initial_context: Dict = None) -> Dict[str, Any]:
        """
        执行工具链

        Args:
            target: 扫描目标
            initial_context: 初始上下文数据

        Returns:
            完整的执行结果，包含每步的结构化数据和聚合分析
        """
        ctx = ChainContext(target=target)
        if initial_context:
            for k, v in initial_context.items():
                if hasattr(ctx, k):
                    setattr(ctx, k, v)

        chain_start = time.time()
        results = {
            "target": target,
            "chain_name": self.__class__.__name__,
            "steps": {},
            "success": True,
        }
        # v5.2: deque 替代固定列表，支持运行时追加步骤
        step_queue = deque(self.steps)
        executed_steps = set()  # 防止重复执行同名步骤
        max_steps = len(self.steps) + 20  # 安全阀：最多追加20个动态步骤
        step_count = 0

        while step_queue and step_count < max_steps:
            step = step_queue.popleft()
            step_count += 1

            # 防止重复执行
            if step.name in executed_steps:
                continue
            executed_steps.add(step.name)
            # 检查条件
            if step.condition and not step.condition(ctx):
                logger.info(f"ToolChain: skipping '{step.name}' (condition not met)")
                results["steps"][step.name] = {"status": "skipped", "reason": "condition_not_met"}
                continue

            # 构建参数
            if step.params_builder:
                try:
                    params = step.params_builder(ctx)
                    if params is None:
                        logger.info(f"ToolChain: skipping '{step.name}' (params_builder returned None)")
                        results["steps"][step.name] = {"status": "skipped", "reason": "no_params"}
                        continue
                except Exception as e:
                    logger.error(f"ToolChain: params_builder failed for '{step.name}': {e}")
                    results["steps"][step.name] = {"status": "error", "error": str(e)}
                    continue
            else:
                params = dict(step.params)
                # 自动注入target
                if "target" not in params and "url" not in params:
                    params["target"] = target

            # 执行工具
            step_start = time.time()
            tool_result = self._execute_step(step, params)
            step_duration = time.time() - step_start
            ctx.step_durations[step.name] = step_duration

            success = self._is_success(tool_result)

            # 失败降级
            if not success and step.fallback_tools:
                for fallback_tool in step.fallback_tools:
                    logger.info(f"ToolChain: trying fallback '{fallback_tool}' for '{step.name}'")
                    fallback_params = dict(params)
                    tool_result = self.executor.execute_tool_with_data(fallback_tool, fallback_params)
                    if self._is_success(tool_result):
                        success = True
                        step.tool_name = fallback_tool  # 记录实际使用的工具
                        break

            # 记录结果
            ctx.step_results[step.name] = tool_result
            results["steps"][step.name] = {
                "tool": step.tool_name,
                "status": "success" if success else "failed",
                "duration": round(step_duration, 2),
            }

            # 解析结果并更新上下文
            output = tool_result.get("output", "")
            parsed = ResultParser.auto_parse(step.tool_name, output, target)
            if parsed:
                self._update_context(ctx, step.tool_name, parsed)
                results["steps"][step.name]["parsed"] = True

            # 自定义结果处理
            if step.result_handler:
                try:
                    step.result_handler(ctx, tool_result)
                except Exception as e:
                    logger.error(f"ToolChain: result_handler failed for '{step.name}': {e}")

            # 发射事件
            if self.event_bus:
                self.event_bus.emit("tool.result", {
                    "tool_name": step.tool_name,
                    "target": target,
                    "success": success,
                    "output": output[:5000],  # 限制事件数据大小
                    "duration": step_duration,
                    "parsed_result": type(parsed).__name__ if parsed else None,
                }, source=f"chain.{step.name}")

                # 发现漏洞时发射专门事件
                if parsed and hasattr(parsed, 'findings'):
                    for finding in getattr(parsed, 'findings', []):
                        if hasattr(finding, 'severity') and finding.severity in ('critical', 'high'):
                            self.event_bus.emit("vuln.candidate", {
                                "vuln_type": getattr(finding, 'template_id', 'unknown'),
                                "target": target,
                                "severity": finding.severity,
                                "evidence": getattr(finding, 'url', ''),
                                "confidence": 0.7,
                            }, source=f"chain.{step.name}")

            # 检测flag
            self._detect_flags(ctx, output)

            # v5.2: 调用决策钩子 — 可根据本步结果动态插入新步骤
            for hook in self._decision_hooks:
                try:
                    hook(ctx, step, tool_result, step_queue)
                except Exception as e:
                    logger.debug(f"ToolChain: decision hook failed: {e}")

            # 必须成功的步骤失败则中止
            if step.required and not success:
                results["success"] = False
                ctx.errors.append(f"Required step '{step.name}' failed")
                break

        # 最终汇总
        results["duration"] = round(time.time() - chain_start, 2)
        results["context_summary"] = ctx.to_summary()
        results["vulns_found"] = len(ctx.discovered_vulns)
        results["paths_found"] = len(ctx.discovered_paths)
        results["flags"] = ctx.flags

        return results

    def _execute_step(self, step: ToolChainStep, params: Dict) -> Dict:
        """执行单个步骤"""
        try:
            return self.executor.execute_tool_with_data(step.tool_name, params)
        except Exception as e:
            logger.error(f"ToolChain: execution failed for '{step.name}': {e}")
            return {"success": False, "error": str(e), "output": ""}

    @staticmethod
    def _is_success(result: Dict) -> bool:
        """判断工具执行是否成功"""
        if result.get("success") is True:
            return True
        if result.get("return_code") == 0:
            return True
        if result.get("output", "").strip():
            return True
        return False

    def _update_context(self, ctx: ChainContext, tool_name: str, parsed):
        """根据解析结果更新上下文"""
        if isinstance(parsed, NmapResult):
            ctx.update_from_nmap(parsed)
        elif isinstance(parsed, GobusterResult):
            ctx.update_from_gobuster(parsed)
        elif isinstance(parsed, WhatwebResult):
            ctx.update_from_whatweb(parsed)
        elif isinstance(parsed, WafResult):
            ctx.update_from_waf(parsed)
        elif isinstance(parsed, NucleiResult):
            ctx.update_from_nuclei(parsed)
        elif isinstance(parsed, SqlmapResult):
            ctx.update_from_sqlmap(parsed)

    @staticmethod
    def _detect_flags(ctx: ChainContext, output: str):
        """从输出中检测flag"""
        import re
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
        ]
        for pattern in flag_patterns:
            for match in re.finditer(pattern, output):
                flag = match.group(0)
                if flag not in ctx.flags:
                    ctx.flags.append(flag)
                    logger.info(f"ToolChain: FLAG DETECTED: {flag}")


# ============================================================
# v5.2: 内置决策钩子 — 基于中间结果动态插入探测步骤
# ============================================================

def _hook_cms_deep_scan(ctx: ChainContext, step: ToolChainStep,
                        result: Dict, queue: deque):
    """发现CMS时自动插入对应扫描器"""
    if step.tool_name not in ("whatweb",):
        return
    cms = ctx.cms_type.lower()
    if cms == "wordpress":
        queue.appendleft(ToolChainStep(
            name="auto_wpscan",
            tool_name="wpscan",
            params_builder=lambda c: {
                "target": c.web_urls[0] if c.web_urls else f"http://{c.target}",
                "additional_args": "--enumerate vp,vt,u --random-user-agent",
            },
            priority=10,
        ))
        logger.info("DecisionHook: WordPress detected  inserting wpscan")
    elif cms == "joomla":
        queue.appendleft(ToolChainStep(
            name="auto_joomscan",
            tool_name="joomscan",
            params_builder=lambda c: {
                "target": c.web_urls[0] if c.web_urls else f"http://{c.target}",
            },
            priority=10,
        ))
        logger.info("DecisionHook: Joomla detected  inserting joomscan")


def _hook_injectable_deep_test(ctx: ChainContext, step: ToolChainStep,
                               result: Dict, queue: deque):
    """发现可注入URL时自动插入sqlmap深度扫描"""
    if step.tool_name not in ("gobuster", "ffuf", "dirb", "feroxbuster"):
        return
    if not ctx.injectable_urls:
        return
    # 只测试第一个可注入URL
    target_url = ctx.injectable_urls[0]
    queue.appendleft(ToolChainStep(
        name="auto_sqlmap",
        tool_name="sqlmap",
        params_builder=lambda c: SmartParamsBuilder.build_sqlmap_params(
            c.gobuster_result, c.waf_result, target_url
        ),
        priority=15,
    ))
    logger.info(f"DecisionHook: injectable URL found  inserting sqlmap for {target_url}")


def _hook_upload_test(ctx: ChainContext, step: ToolChainStep,
                      result: Dict, queue: deque):
    """发现上传路径时自动尝试文件上传漏洞检测"""
    if step.tool_name not in ("gobuster", "ffuf", "dirb", "feroxbuster"):
        return
    if not ctx.gobuster_result:
        return
    upload_paths = ctx.gobuster_result.upload_paths
    if not upload_paths:
        return
    # 使用nuclei的upload模板扫描
    upload_url = f"{ctx.web_urls[0]}{upload_paths[0].path}" if ctx.web_urls else ""
    if upload_url:
        queue.appendleft(ToolChainStep(
            name="auto_upload_scan",
            tool_name="nuclei",
            params_builder=lambda c: {
                "target": upload_url,
                "tags": "fileupload,upload",
                "severity": "critical,high,medium",
            },
            priority=12,
        ))
        logger.info(f"DecisionHook: upload path found  inserting nuclei upload scan")


def _hook_high_vuln_exploit(ctx: ChainContext, step: ToolChainStep,
                            result: Dict, queue: deque):
    """发现高危/严重漏洞时自动搜索exploit"""
    if step.tool_name not in ("nuclei",):
        return
    if not ctx.nuclei_result:
        return
    cves = ctx.nuclei_result.cve_list
    if not cves:
        return
    # 为第一个CVE搜索exploit
    cve = cves[0]
    queue.appendleft(ToolChainStep(
        name="auto_searchsploit",
        tool_name="searchsploit",
        params_builder=lambda c: {
            "term": cve,
            "additional_args": "--json",
        },
        priority=8,
    ))
    logger.info(f"DecisionHook: CVE {cve} found  inserting searchsploit")


def _hook_smb_enumeration(ctx: ChainContext, step: ToolChainStep,
                          result: Dict, queue: deque):
    """发现SMB端口时自动插入enum4linux"""
    if step.tool_name not in ("nmap", "masscan"):
        return
    smb_ports = {445, 139}
    if not smb_ports.intersection(set(ctx.open_ports)):
        return
    queue.append(ToolChainStep(
        name="auto_enum4linux",
        tool_name="enum4linux",
        params_builder=lambda c: {"target": c.target},
        priority=60,
    ))
    logger.info("DecisionHook: SMB ports found  inserting enum4linux")


def _hook_ssh_bruteforce(ctx: ChainContext, step: ToolChainStep,
                         result: Dict, queue: deque):
    """发现SSH端口时自动尝试弱口令(仅CTF模式)"""
    if step.tool_name not in ("nmap",):
        return
    if 22 not in ctx.open_ports:
        return
    queue.append(ToolChainStep(
        name="auto_ssh_bruteforce",
        tool_name="hydra",
        params_builder=lambda c: {
            "target": c.target,
            "service": "ssh",
            "username_file": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "password_file": "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
            "additional_args": "-t 4 -f",
        },
        priority=80,  # 低优先级，排在其他扫描之后
    ))
    logger.info("DecisionHook: SSH found  inserting hydra quick bruteforce")


# 所有内置钩子
BUILTIN_DECISION_HOOKS = [
    _hook_cms_deep_scan,
    _hook_injectable_deep_test,
    _hook_upload_test,
    _hook_high_vuln_exploit,
    _hook_smb_enumeration,
    _hook_ssh_bruteforce,
]


# ============================================================
# 预定义工具链 - 真正的渗透测试流程
# ============================================================

def _apply_decision_hooks(chain: ToolChain) -> ToolChain:
    """为预定义链注册所有内置决策钩子"""
    for hook in BUILTIN_DECISION_HOOKS:
        chain.add_decision_hook(hook)
    return chain

def create_web_recon_chain(executor, event_bus=None) -> ToolChain:
    """
    Web应用侦察链

    流程: nmap  whatweb  wafw00f  gobuster  nuclei
    特点: 每一步的结果都驱动下一步的参数
    """
    chain = ToolChain(executor, event_bus)

    # Step 1: 端口扫描 (必须)
    chain.add_step(ToolChainStep(
        name="port_scan",
        tool_name="nmap",
        params_builder=lambda ctx: {
            "target": ctx.target,
            "scan_type": "-sV -sC",
            "ports": "80,443,8080,8443,8888,3000,5000,9090",
            "additional_args": "-T4 --open",
        },
        required=True,
    ))

    # Step 2: 技术栈识别 (需要web服务)
    chain.add_step(ToolChainStep(
        name="tech_fingerprint",
        tool_name="whatweb",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "aggression": "3",
        },
    ))

    # Step 3: WAF检测 (需要web服务)
    chain.add_step(ToolChainStep(
        name="waf_detection",
        tool_name="wafw00f",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
        },
    ))

    # Step 4: 目录扫描 (需要web服务，使用技术栈信息选择字典)
    chain.add_step(ToolChainStep(
        name="dir_scan",
        tool_name="gobuster",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "url": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "mode": "dir",
            "wordlist": SmartParamsBuilder.choose_wordlist(ctx.whatweb_result),
            "additional_args": "-q --no-error -t 30",
        },
        fallback_tools=["ffuf", "dirb"],
    ))

    # Step 5: 漏洞扫描 (需要web服务，根据发现的技术选择模板)
    chain.add_step(ToolChainStep(
        name="vuln_scan",
        tool_name="nuclei",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: SmartParamsBuilder.build_nuclei_params(
            ctx.nmap_result, ctx.target
        ) if ctx.nmap_result else {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "severity": "critical,high,medium",
        },
    ))

    # Step 6: WordPress专项 (仅当检测到WordPress时)
    chain.add_step(ToolChainStep(
        name="wordpress_scan",
        tool_name="wpscan",
        condition=lambda ctx: ctx.whatweb_result and ctx.whatweb_result.is_wordpress,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "additional_args": "--enumerate vp,vt,u",
        },
    ))

    # Step 7: SQL注入检测 (需要发现动态页面，使用WAF检测结果)
    chain.add_step(ToolChainStep(
        name="sqli_scan",
        tool_name="sqlmap",
        condition=lambda ctx: len(ctx.injectable_urls) > 0,
        params_builder=lambda ctx: SmartParamsBuilder.build_sqlmap_params(
            ctx.gobuster_result, ctx.waf_result, ctx.target
        ) if ctx.gobuster_result else None,
    ))

    _apply_decision_hooks(chain)
    return chain


def create_network_recon_chain(executor, event_bus=None) -> ToolChain:
    """
    网络侦察链

    流程: masscan(快速)  nmap(精确)  nuclei(漏洞)  enum4linux(如果有SMB)
    """
    chain = ToolChain(executor, event_bus)

    # Step 1: 快速端口发现
    chain.add_step(ToolChainStep(
        name="fast_port_scan",
        tool_name="masscan",
        params_builder=lambda ctx: {
            "target": ctx.target,
            "ports": "1-10000",
            "rate": "5000",
        },
        required=True,
    ))

    # Step 2: 精确服务识别 (只扫描masscan发现的端口)
    chain.add_step(ToolChainStep(
        name="service_scan",
        tool_name="nmap",
        condition=lambda ctx: len(ctx.open_ports) > 0,
        params_builder=lambda ctx: {
            "target": ctx.target,
            "scan_type": "-sV -sC",
            "ports": ",".join(str(p) for p in ctx.open_ports[:100]),
            "additional_args": "-T4",
        },
    ))

    # Step 3: 漏洞扫描
    chain.add_step(ToolChainStep(
        name="vuln_scan",
        tool_name="nuclei",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "severity": "critical,high",
        },
    ))

    # Step 4: SMB枚举 (如果发现445端口)
    chain.add_step(ToolChainStep(
        name="smb_enum",
        tool_name="enum4linux",
        condition=lambda ctx: 445 in ctx.open_ports or 139 in ctx.open_ports,
        params_builder=lambda ctx: {
            "target": ctx.target,
            "additional_args": "-a",
        },
    ))

    _apply_decision_hooks(chain)
    return chain


def create_ctf_speed_chain(executor, event_bus=None) -> ToolChain:
    """
    CTF快速解题链

    目标: 最快速度找到flag
    流程: nmap(快速)  gobuster(并行)  nuclei(高危)  sqlmap(如果有注入点)
    """
    chain = ToolChain(executor, event_bus)

    # Step 1: 极速端口扫描
    chain.add_step(ToolChainStep(
        name="fast_scan",
        tool_name="nmap",
        params_builder=lambda ctx: {
            "target": ctx.target,
            "scan_type": "-sV",
            "ports": "80,443,8080,8000,5000,3000,22,21",
            "additional_args": "-T5 --open",
        },
        timeout=30,
        required=True,
    ))

    # Step 2: 快速目录扫描
    chain.add_step(ToolChainStep(
        name="dir_scan",
        tool_name="gobuster",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "url": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "mode": "dir",
            "additional_args": "-q --no-error -t 50 -x php,txt,html,bak,old,zip",
        },
        timeout=60,
        fallback_tools=["ffuf"],
    ))

    # Step 3: 高危漏洞快扫
    chain.add_step(ToolChainStep(
        name="vuln_scan",
        tool_name="nuclei",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "severity": "critical,high",
        },
        timeout=60,
    ))

    # Step 4: SQL注入快速检测
    chain.add_step(ToolChainStep(
        name="sqli_check",
        tool_name="sqlmap",
        condition=lambda ctx: len(ctx.injectable_urls) > 0,
        params_builder=lambda ctx: {
            "url": ctx.injectable_urls[0],
            "additional_args": "--batch --random-agent --level 1 --risk 1",
        },
        timeout=60,
    ))

    _apply_decision_hooks(chain)
    return chain


def create_full_pentest_chain(executor, event_bus=None) -> ToolChain:
    """
    完整渗透测试链 — 最全面的扫描流程

    流程:
    1. nmap全端口扫描
    2. whatweb技术栈
    3. wafw00f WAF检测
    4. gobuster目录扫描
    5. nuclei漏洞扫描
    6. nikto Web服务器扫描
    7. sqlmap SQL注入
    8. 根据CMS选择专项扫描
    """
    chain = ToolChain(executor, event_bus)

    # Step 1: 全面端口扫描
    chain.add_step(ToolChainStep(
        name="full_port_scan",
        tool_name="nmap",
        params_builder=lambda ctx: {
            "target": ctx.target,
            "scan_type": "-sV -sC -O",
            "ports": "1-10000",
            "additional_args": "-T4 --open",
        },
        required=True,
    ))

    # Step 2: 技术栈识别
    chain.add_step(ToolChainStep(
        name="tech_fingerprint",
        tool_name="whatweb",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "aggression": "3",
        },
    ))

    # Step 3: WAF检测
    chain.add_step(ToolChainStep(
        name="waf_detection",
        tool_name="wafw00f",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
        },
    ))

    # Step 4: 目录枚举
    chain.add_step(ToolChainStep(
        name="dir_enum",
        tool_name="gobuster",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "url": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "mode": "dir",
            "wordlist": SmartParamsBuilder.choose_wordlist(ctx.whatweb_result),
            "additional_args": "-q --no-error -t 30 -x php,asp,jsp,html,txt",
        },
        fallback_tools=["ffuf", "dirb"],
    ))

    # Step 5: 漏洞扫描
    chain.add_step(ToolChainStep(
        name="vuln_scan",
        tool_name="nuclei",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "severity": "critical,high,medium",
        },
    ))

    # Step 6: Web服务器深度扫描
    chain.add_step(ToolChainStep(
        name="web_server_scan",
        tool_name="nikto",
        condition=lambda ctx: ctx.has_web_service,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "additional_args": "-maxtime 240",
        },
    ))

    # Step 7: SQL注入检测
    chain.add_step(ToolChainStep(
        name="sqli_scan",
        tool_name="sqlmap",
        condition=lambda ctx: len(ctx.injectable_urls) > 0,
        params_builder=lambda ctx: SmartParamsBuilder.build_sqlmap_params(
            ctx.gobuster_result, ctx.waf_result, ctx.target
        ) if ctx.gobuster_result else None,
    ))

    # Step 8: CMS专项扫描
    chain.add_step(ToolChainStep(
        name="cms_scan",
        tool_name="wpscan",
        condition=lambda ctx: ctx.whatweb_result and ctx.whatweb_result.is_wordpress,
        params_builder=lambda ctx: {
            "target": ctx.web_urls[0] if ctx.web_urls else f"http://{ctx.target}",
            "additional_args": "--enumerate vp,vt,u --detection-mode aggressive",
        },
    ))

    # Step 9: SMB枚举
    chain.add_step(ToolChainStep(
        name="smb_enum",
        tool_name="enum4linux",
        condition=lambda ctx: 445 in ctx.open_ports or 139 in ctx.open_ports,
        params_builder=lambda ctx: {
            "target": ctx.target,
            "additional_args": "-a",
        },
    ))

    _apply_decision_hooks(chain)
    return chain
