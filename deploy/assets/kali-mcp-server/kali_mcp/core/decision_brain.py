#!/usr/bin/env python3
"""
DecisionBrain - 智能决策引擎 (v5.2)

介入点机制:
- start: 任务开始前，分析目标特征，选择策略
- post_recon: 信息收集后，根据发现调整扫描范围
- source_found: 获取到源码后，决定是否启动代码审计
- mid_scan: 扫描中期，评估进度，决定深入或转向
- pre_exploit: 利用前，风险评估
- final: 任务结束，汇总发现，生成报告

v5.2增强:
- 注入MLOptimizer: 基于历史数据推荐工具
- 注入VulnManager: 读取已发现漏洞做决策
- 注入ChainContext: 直接消费结构化解析结果
- update_context(): 接收EventBus推送的实时数据
- trigger_reassessment(): 漏洞发现时触发重新评估
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class DecisionBrain:
    """智能决策引擎 - 攻击流程介入点"""

    # 介入点定义
    INTERVENTION_POINTS = {
        "start": "任务开始前，分析目标特征，选择策略",
        "post_recon": "信息收集后，根据发现调整扫描范围",
        "source_found": "获取到源码后，决定是否启动代码审计",
        "mid_scan": "扫描中期，评估进度，决定深入或转向",
        "pre_exploit": "利用前，风险评估",
        "final": "任务结束，汇总发现，生成报告",
    }

    def __init__(self, ml_optimizer=None, vuln_manager=None):
        self._decisions: List[Dict[str, Any]] = []
        # v5.2: 注入数据源
        self._ml_optimizer = ml_optimizer
        self._vuln_manager = vuln_manager
        # v5.2: EventBus推送的实时上下文
        self._live_context: Dict[str, Any] = {
            "last_tool": "",
            "last_success": False,
            "last_target": "",
            "tools_used": [],
            "vulns_seen": 0,
            "digger_results": [],
        }
        logger.info("DecisionBrain 初始化完成 (v5.2, 数据源注入)")

    def update_context(self, data: Dict[str, Any]):
        """接收EventBus推送的实时数据"""
        self._live_context.update(data)
        tool = data.get("last_tool", "")
        if tool and tool not in self._live_context.get("tools_used", []):
            self._live_context.setdefault("tools_used", []).append(tool)

    def trigger_reassessment(self, vuln_data: Dict[str, Any]):
        """漏洞发现时触发重新评估"""
        self._live_context["vulns_seen"] = self._live_context.get("vulns_seen", 0) + 1
        severity = vuln_data.get("severity", "medium")
        if severity in ("critical", "high"):
            self._live_context["high_value_vuln_found"] = True
            logger.info(f"DecisionBrain: 高价值漏洞触发重评估 ({severity})")

    def _get_ml_recommendations(self, target: str) -> List[str]:
        """从MLOptimizer获取工具推荐"""
        if not self._ml_optimizer:
            return []
        try:
            if hasattr(self._ml_optimizer, 'recommend_tools_for_target'):
                return self._ml_optimizer.recommend_tools_for_target(target)
        except Exception:
            pass
        return []

    def _get_vuln_count(self, target: str = "") -> int:
        """从VulnManager获取已发现漏洞数量"""
        if not self._vuln_manager:
            return self._live_context.get("vulns_seen", 0)
        try:
            if hasattr(self._vuln_manager, 'get_candidates'):
                candidates = self._vuln_manager.get_candidates(target=target)
                return len(candidates) if candidates else 0
        except Exception:
            pass
        return self._live_context.get("vulns_seen", 0)

    def decide(self, point: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """在介入点做出决策"""
        if point not in self.INTERVENTION_POINTS:
            return {"action": "continue", "reason": f"未知介入点: {point}"}

        handler = getattr(self, f"_decide_{point}", None)
        if handler:
            decision = handler(context)
        else:
            decision = {"action": "continue", "reason": "默认继续"}

        decision["point"] = point
        decision["timestamp"] = datetime.now().isoformat()
        self._decisions.append(decision)
        logger.info(f"DecisionBrain [{point}]  {decision.get('action', 'unknown')}: {decision.get('reason', '')}")
        return decision

    def get_decisions(self) -> List[Dict[str, Any]]:
        """获取所有决策记录"""
        return list(self._decisions)

    def clear(self):
        """清空决策记录"""
        self._decisions.clear()

    # ==================== 介入点处理器 ====================

    def _decide_start(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """任务开始前 - 分析目标特征，选择策略"""
        target = ctx.get("target", "")
        mode = ctx.get("mode", "auto")
        prompt = ctx.get("prompt", "")
        recommendations = []
        thinking = []

        thinking.append(f"目标: {target}")
        thinking.append(f"模式: {mode}")
        if prompt:
            thinking.append(f"用户提示: {prompt}")

        # v5.2: 从MLOptimizer获取历史推荐
        ml_recs = self._get_ml_recommendations(target)
        if ml_recs:
            thinking.append(f"ML历史推荐工具: {', '.join(ml_recs[:5])}")

        # 判断目标类型
        is_url = "://" in target
        if any(kw in target.lower() for kw in ["ctf", "challenge", "flag"]):
            recommendations.append("ctf_mode")
            strategy = "aggressive"
            thinking.append("检测到CTF关键词  启用激进策略，优先速度")
        elif any(target.startswith(p) for p in ["10.", "172.16.", "192.168."]):
            recommendations.append("internal_pentest")
            strategy = "methodical"
            thinking.append("目标为内网IP  采用系统化渗透策略")
        elif is_url:
            recommendations.append("web_assessment")
            strategy = "web_focused"
            thinking.append("目标为Web URL  聚焦Web应用安全评估")
        else:
            recommendations.append("general_scan")
            strategy = "balanced"
            thinking.append("通用目标  采用均衡扫描策略")

        plan = [
            f"1. 端口扫描 (nmap) — 识别开放端口和服务",
        ]
        if is_url:
            plan.append("2. Web指纹识别 (whatweb) — 识别技术栈和框架")
            plan.append("3. 目录枚举 (gobuster) — 发现隐藏路径")
            plan.append("4. HTTP头分析 (curl) — 检查安全头和配置")
        else:
            plan.append("2. 服务版本探测 — 识别可利用的服务版本")
            plan.append("3. 根据发现的服务选择针对性扫描")

        plan.append(f" 后续步骤将由 DecisionBrain 根据侦察结果动态决定")

        # v5.2: ML推荐的工具加入计划
        if ml_recs:
            plan.append(f" ML推荐优先使用: {', '.join(ml_recs[:3])}")

        return {
            "action": "proceed",
            "strategy": strategy,
            "recommendations": recommendations,
            "ml_recommendations": ml_recs,
            "thinking": thinking,
            "plan": plan,
            "reason": f"目标分析完成，推荐策略: {strategy}",
        }

    def _decide_post_recon(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """信息收集后 - 根据发现调整扫描范围"""
        open_ports = ctx.get("open_ports", [])
        services = ctx.get("services", [])
        technologies = ctx.get("technologies", [])
        next_actions = []
        thinking = []
        plan = []

        thinking.append(f"侦察结果: {len(open_ports)} 个开放端口")
        if open_ports:
            thinking.append(f"  端口列表: {open_ports}")
        if services:
            thinking.append(f"  服务: {', '.join(str(s) for s in services)}")
        if technologies:
            thinking.append(f"  技术栈: {', '.join(str(t) for t in technologies)}")

        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000, 3000]]
        if web_ports:
            next_actions.append({"tool": "web_scan", "targets": web_ports})
            thinking.append(f"发现Web端口 {web_ports}  规划Web漏洞扫描")
            plan.append(f"Web漏洞扫描 (nuclei + nikto) — 针对端口 {web_ports}")

        db_ports = [p for p in open_ports if p in [3306, 5432, 1433, 27017, 6379]]
        if db_ports:
            next_actions.append({"tool": "db_enum", "targets": db_ports})
            thinking.append(f"发现数据库端口 {db_ports}  规划数据库枚举")
            plan.append(f"数据库枚举 (nmap scripts) — 针对端口 {db_ports}")

        if any(s in str(services).lower() for s in ["ssh", "ftp", "smb"]):
            next_actions.append({"tool": "brute_force", "services": services})
            thinking.append(f"发现可爆破服务  规划弱口令检测")
            plan.append(f"弱口令检测 (hydra) — 针对 {[s for s in services if any(k in str(s).lower() for k in ['ssh','ftp','smb'])]}")

        if not next_actions:
            thinking.append("侦察发现有限，需要扩大扫描范围")
            plan.append("全端口扫描 (nmap -p-) — 发现非标准端口")
            plan.append("更大字典目录扫描 — 发现隐藏路径")
            plan.append("nuclei 全模板扫描 — 广泛漏洞检测")
            return {
                "action": "expand_scan",
                "thinking": thinking,
                "plan": plan,
                "reason": "发现有限，建议扩大扫描范围",
            }

        thinking.append(f"共规划 {len(next_actions)} 个攻击向量")
        plan.append(" 扫描完成后 DecisionBrain 将评估进度并决定下一步")

        return {
            "action": "focus_scan",
            "next_actions": next_actions,
            "thinking": thinking,
            "plan": plan,
            "reason": f"发现 {len(open_ports)} 个端口，规划 {len(next_actions)} 个后续动作",
        }

    def _decide_source_found(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """获取到源码后 - 决定是否启动代码审计"""
        source_type = ctx.get("source_type", "unknown")
        file_count = ctx.get("file_count", 0)
        languages = ctx.get("languages", [])

        if file_count == 0:
            return {"action": "skip_audit", "reason": "未获取到有效源码文件"}

        audit_priority = "high" if file_count > 10 else "medium"
        supported = [l for l in languages if l.lower() in
                     ["python", "php", "java", "javascript", "go", "ruby", "c", "cpp"]]

        if not supported:
            return {"action": "skip_audit", "reason": f"不支持的语言: {languages}"}

        return {
            "action": "start_audit",
            "priority": audit_priority,
            "languages": supported,
            "file_count": file_count,
            "reason": f"发现 {file_count} 个源码文件 ({', '.join(supported)})，启动代码审计",
        }

    def _decide_mid_scan(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """扫描中期 - 评估进度，决定深入或转向"""
        # v5.2: 合并传入上下文与实时上下文
        vulns_found = ctx.get("vulns_found", 0) or self._get_vuln_count(ctx.get("target", ""))
        elapsed_minutes = ctx.get("elapsed_minutes", 0)
        total_targets = ctx.get("total_targets", 1)
        scanned = ctx.get("scanned", 0)
        progress = scanned / max(total_targets, 1)
        thinking = []
        plan = []

        # v5.2: 从实时上下文补充信息
        tools_used = self._live_context.get("tools_used", [])
        high_value = self._live_context.get("high_value_vuln_found", False)

        thinking.append(f"当前进度: {progress:.0%} ({scanned}/{total_targets})")
        thinking.append(f"已发现漏洞: {vulns_found} 个")
        thinking.append(f"已耗时: {elapsed_minutes:.1f} 分钟")
        if tools_used:
            thinking.append(f"已使用工具: {', '.join(tools_used[-5:])}")

        # v5.2: 高价值漏洞触发立即利用
        if high_value:
            thinking.append("检测到高价值漏洞(EventBus推送)  立即转入利用")
            plan.append("对高危/严重漏洞优先验证和利用")
            plan.append("利用成功后继续深度枚举")
            return {
                "action": "shift_to_exploit",
                "thinking": thinking,
                "plan": plan,
                "reason": f"高价值漏洞触发 — 立即转入利用阶段",
            }

        if vulns_found >= 5:
            thinking.append("漏洞数量充足  转入利用阶段以验证可利用性")
            plan.append("对已发现漏洞进行可利用性验证")
            plan.append("尝试利用高危漏洞获取更多信息")
            plan.append("记录利用结果用于最终报告")
            return {
                "action": "shift_to_exploit",
                "thinking": thinking,
                "plan": plan,
                "reason": f"已发现 {vulns_found} 个漏洞，建议转入利用阶段",
            }

        if progress > 0.7 and vulns_found == 0:
            thinking.append("扫描进度较高但无发现  需要更换策略")
            plan.append("切换到深度扫描模式 (SQL注入检测)")
            plan.append("对已发现目录进行逐一漏洞扫描")
            plan.append("尝试不同的扫描参数和字典")
            return {
                "action": "change_strategy",
                "thinking": thinking,
                "plan": plan,
                "reason": f"扫描进度 {progress:.0%} 但无发现，建议更换策略",
            }

        if elapsed_minutes > 30 and vulns_found < 2:
            thinking.append("耗时较长且发现不足  调整扫描范围")
            plan.append("缩小扫描范围，聚焦高价值目标")
            plan.append("使用更激进的扫描参数")
            return {
                "action": "adjust_scope",
                "thinking": thinking,
                "plan": plan,
                "reason": f"已耗时 {elapsed_minutes} 分钟，发现不足，建议调整范围",
            }

        thinking.append("扫描进展正常，继续当前策略")
        plan.append("继续深度扫描 (SQL注入/目录漏洞)")
        plan.append("扫描完成后进行最终评估")
        return {
            "action": "continue",
            "progress": f"{progress:.0%}",
            "thinking": thinking,
            "plan": plan,
            "reason": f"扫描正常进行中 ({progress:.0%})，已发现 {vulns_found} 个漏洞",
        }

    def _decide_pre_exploit(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """利用前 - 风险评估"""
        vuln_type = ctx.get("vuln_type", "unknown")
        confidence = ctx.get("confidence", 0)
        severity = ctx.get("severity", "medium")
        is_ctf = ctx.get("is_ctf", False)
        thinking = []
        plan = []

        thinking.append(f"漏洞类型: {vuln_type}")
        thinking.append(f"置信度: {confidence:.0%}")
        thinking.append(f"严重度: {severity}")
        thinking.append(f"CTF模式: {'是' if is_ctf else '否'}")

        if is_ctf:
            thinking.append("CTF模式下无需风险评估  直接利用")
            plan.append(f"直接利用 {vuln_type} 漏洞")
            plan.append("提取Flag")
            return {
                "action": "exploit",
                "thinking": thinking,
                "plan": plan,
                "reason": "CTF模式，直接利用",
            }

        if confidence < 0.5:
            thinking.append(f"置信度 {confidence:.0%} 偏低  先验证漏洞存在性")
            plan.append(f"使用 nuclei 验证 {vuln_type} 漏洞")
            plan.append("验证通过后再尝试利用")
            return {
                "action": "verify_first",
                "thinking": thinking,
                "plan": plan,
                "reason": f"置信度 {confidence:.0%} 偏低，建议先验证",
            }

        risk_map = {"critical": "high", "high": "medium", "medium": "low", "low": "minimal"}
        risk = risk_map.get(severity, "unknown")
        thinking.append(f"风险评估: {risk}  可以尝试利用")
        plan.append(f"利用 {vuln_type} 漏洞 (风险: {risk})")

        return {
            "action": "exploit",
            "risk_level": risk,
            "thinking": thinking,
            "plan": plan,
            "reason": f"漏洞类型={vuln_type}, 严重度={severity}, 风险={risk}",
        }

    def _decide_final(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """任务结束 - 汇总发现，生成报告"""
        # v5.2: 从VulnManager获取真实漏洞数据
        target = ctx.get("target", "")
        total_vulns = ctx.get("total_vulns", 0) or self._get_vuln_count(target)
        critical = ctx.get("critical_vulns", 0)
        exploited = ctx.get("exploited", 0)
        flags_found = ctx.get("flags_found", [])
        tools_used = self._live_context.get("tools_used", [])
        digger_results = self._live_context.get("digger_results", [])
        thinking = []

        thinking.append(f"总漏洞数: {total_vulns}")
        thinking.append(f"严重漏洞: {critical}")
        thinking.append(f"已利用: {exploited}")
        thinking.append(f"Flag数: {len(flags_found)}")
        if tools_used:
            thinking.append(f"使用工具总数: {len(tools_used)}")
        if digger_results:
            thinking.append(f"Digger执行: {len(digger_results)} 次")

        summary = {
            "total_vulns": total_vulns,
            "critical": critical,
            "exploited": exploited,
            "flags": len(flags_found),
        }

        if flags_found:
            thinking.append(f"成功获取 {len(flags_found)} 个Flag!")
            return {
                "action": "report_with_flags",
                "summary": summary,
                "flags": flags_found,
                "thinking": thinking,
                "reason": f"任务完成，发现 {len(flags_found)} 个Flag",
            }

        if total_vulns > 0:
            thinking.append(f"发现 {total_vulns} 个漏洞，生成完整报告")
        else:
            thinking.append("未发现漏洞，目标可能安全性较好或需要更深入测试")

        report_type = "full_report" if total_vulns > 0 else "no_findings_report"
        return {
            "action": report_type,
            "summary": summary,
            "thinking": thinking,
            "reason": f"任务完成: {total_vulns} 个漏洞, {exploited} 个已利用",
        }
